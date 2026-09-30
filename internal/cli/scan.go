package cli

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/Pixelcity-dev/Iris/internal/cloud"
	"github.com/Pixelcity-dev/Iris/internal/core"
	"github.com/Pixelcity-dev/Iris/internal/reporter"
	"github.com/Pixelcity-dev/Iris/internal/ui"
	"github.com/spf13/cobra"
)

var (
	scanOutput    string
	scanFormats   []string
	scanSeverity  string
	scanScanners  []string
	scanBaseline  string
	scanExitCode  bool
	scanRecursive bool
)

var scanCmd = &cobra.Command{
	Use:   "scan [target]",
	Short: "Run security scan on a target",
	Long: `Scan a filesystem, repository, container image, or URL for security issues.
Supports multiple scan types: SAST, SCA, secrets, IaC, container, DAST, webscan, network, and license.

Examples:
  iris scan ./myapp
  iris scan https://example.com --scanner webscan
  iris scan https://example.com --scanner dast,webscan
  iris webscan https://example.com   # deep website audit (recommended for URLs)`,
	Args: cobra.ExactArgs(1),
	RunE: runScan,
}

func init() {
	scanCmd.Flags().StringVarP(&scanOutput, "output", "o", "", "output file path")
	scanCmd.Flags().StringSliceVarP(&scanFormats, "format", "f", []string{"table"}, "output format (table, json, sarif, cyclonedx, spdx, html, csv, junit)")
	scanCmd.Flags().StringVar(&scanSeverity, "severity", "INFO", "minimum severity level (INFO, LOW, MEDIUM, HIGH, CRITICAL)")
	scanCmd.Flags().StringSliceVar(&scanScanners, "scanner", nil, "specific scanners to use")
	scanCmd.Flags().StringVar(&scanBaseline, "baseline", "", "baseline file for comparing results")
	scanCmd.Flags().BoolVar(&scanExitCode, "exit-code", false, "exit with non-zero code if findings found")
	scanCmd.Flags().BoolVarP(&scanRecursive, "recursive", "r", true, "scan recursively")
	scanCmd.Flags().StringSlice("exclude", nil, "patterns to exclude")
	scanCmd.Flags().StringSlice("include", nil, "patterns to include")

	rootCmd.AddCommand(scanCmd)
}

func runScan(cmd *cobra.Command, args []string) error {
	target := args[0]
	start := time.Now()

	fmt.Fprintf(os.Stderr, "Iris v%s - Scanning %s\n", version, target)

	ruleEngine := core.NewRuleEngine()
	ruleEngine.LoadRulesFromDir("rules")

	pipeline := core.NewPipeline(registry, ruleEngine)

	filter := core.NewFindingFilter()
	filter.MinSeverity = core.ParseSeverity(scanSeverity)
	pipeline.SetFilter(filter)

	// Live spinner: one spinning icon per running scanner (TTY only;
	// degrades to plain lines when output is piped/CI).
	sp := ui.NewSpinner(!rootCmd.PersistentFlags().Changed("no-color"))
	sp.Start()
	pipeline.SetProgress(sp)
	defer sp.Stop()

	var scanTypes []core.ScanType
	if len(scanScanners) > 0 {
		for _, s := range scanScanners {
			// normalize aliases: website -> webscan, audit -> webscan
			norm := s
			if norm == "website" || norm == "audit" || norm == "wscan" {
				norm = string(core.ScanTypeWebScan)
			}
			scanTypes = append(scanTypes, core.ScanType(norm))
		}
	} else {
		// Auto-detect target type and set sensible defaults
		if isURL(target) {
			scanTypes = []core.ScanType{
				core.ScanTypeDAST,
				core.ScanTypeWebScan,
				core.ScanTypeNetwork,
			}
		} else {
			scanTypes = []core.ScanType{
				core.ScanTypeSAST,
				core.ScanTypeSCA,
				core.ScanTypeSecrets,
				core.ScanTypeIAC,
				core.ScanTypeContainer,
				core.ScanTypeLicense,
			}
		}
	}

	// WebScan requires a PixelCity account — same gate as `iris webscan`
	// (URL auto-detection includes webscan, so `iris scan <url>` is gated too).
	// Results are saved to the dashboard scan history.
	needsWebScan := false
	for _, t := range scanTypes {
		if t == core.ScanTypeWebScan {
			needsWebScan = true
		}
	}
	scanCtx := context.Background()
	cloudCfg := cloud.DefaultConfig()
	var cloudToken string
	if needsWebScan {
		var lerr error
		cloudToken, lerr = cloud.EnsureValidToken(scanCtx, cloudCfg)
		if lerr != nil {
			return fmt.Errorf("webscan requires login: %w\n\nRun: iris cloud login", lerr)
		}
	}

	targetObj := core.Target{
		Kind: core.TargetFS,
		URI:  target,
	}

	if isURL(target) {
		targetObj.Kind = core.TargetURL
		// for URL targets, ensure webscan/dast are included even if not requested? already handled
	} else if isContainerImage(target) {
		targetObj.Kind = core.TargetImage
	} else if isGitRepo(target) {
		targetObj.Kind = core.TargetRepo
	}

	results, err := pipeline.Scan(context.Background(), targetObj, scanTypes)
	if err != nil {
		return fmt.Errorf("scan failed: %w", err)
	}
	sp.Stop()

	// Enrich generic fix hints with specific, language-aware remediation steps.
	for i := range results {
		core.EnrichFixes(results[i].Findings)
	}

	duration := time.Since(start).Seconds()

	totalFindings := 0
	for _, r := range results {
		totalFindings += len(r.Findings)
	}

	fmt.Fprintf(os.Stderr, "\nScan completed in %.2f seconds\n", duration)
	fmt.Fprintf(os.Stderr, "Found %d issues\n", totalFindings)

	for _, format := range scanFormats {
		rpt := reporter.GetReporter(format)
		if rpt == nil {
			return fmt.Errorf("unknown format: %s", format)
		}

		output, err := rpt.Generate(results, reporter.ReportOptions{
			Format: format,
			Output: scanOutput,
			Color:  !rootCmd.PersistentFlags().Changed("no-color"),
		})
		if err != nil {
			return fmt.Errorf("failed to generate report: %w", err)
		}

		if scanOutput != "" {
			ext := rpt.Extension()
			filename := scanOutput
			if ext != "" && len(scanFormats) > 1 {
				filename = fmt.Sprintf("%s.%s", scanOutput, ext)
			}
			if err := os.WriteFile(filename, output, 0644); err != nil {
				return fmt.Errorf("failed to write output: %w", err)
			}
			fmt.Fprintf(os.Stderr, "Report written to %s\n", filename)
		} else {
			fmt.Print(string(output))
		}
	}

	// Save full results to dashboard scan history (best-effort).
	if needsWebScan {
		names := make([]string, len(scanTypes))
		for i, t := range scanTypes {
			names[i] = string(t)
		}
		uploadScan(scanCtx, cloudCfg, cloudToken, strings.Join(names, ","),
			target, totalFindings, duration, results, start)
	}

	if scanExitCode && totalFindings > 0 {
		os.Exit(1)
	}

	return nil
}

func isURL(s string) bool {
	return len(s) > 7 && (s[:7] == "http://" || s[:8] == "https://")
}

func isContainerImage(s string) bool {
	return len(s) > 0 && (s[0] == '/' || contains(s, ".") || contains(s, ":"))
}

func isGitRepo(s string) bool {
	return len(s) > 4 && (s[len(s)-4:] == ".git" || s[:4] == "git@" || contains(s, "github.com") || contains(s, "gitlab.com"))
}

func contains(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
