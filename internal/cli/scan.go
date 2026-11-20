package cli

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/Pixelcity-dev/Iris/internal/baseline"
	"github.com/Pixelcity-dev/Iris/internal/cloud"
	"github.com/Pixelcity-dev/Iris/internal/config"
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
	scanExclude   []string
	scanInclude   []string
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
	scanCmd.Flags().BoolVarP(&scanRecursive, "recursive", "r", true, "scan recursively (disable to report top-level files only)")
	scanCmd.Flags().StringSliceVar(&scanExclude, "exclude", nil, "file globs to exclude (e.g. '*.min.js', 'testdata/**')")
	scanCmd.Flags().StringSliceVar(&scanInclude, "include", nil, "only report files matching these globs")

	rootCmd.AddCommand(scanCmd)
}

func runScan(cmd *cobra.Command, args []string) error {
	target := args[0]
	start := time.Now()

	fmt.Fprintf(os.Stderr, "%s - Scanning %s\n",
		ui.Gold(fmt.Sprintf("Iris v%s", version), stderrColor()), target)

	ruleEngine := loadRuleEngine()

	pipeline := core.NewPipeline(registry, ruleEngine)

	minSeverity := scanSeverity
	if !cmd.Flags().Changed("severity") && cfg != nil && cfg.Filter.MinSeverity != "" {
		minSeverity = cfg.Filter.MinSeverity
	}

	// A profile or config file may choose the report format; an explicit
	// --format always wins.
	formats := scanFormats
	if !cmd.Flags().Changed("format") && cfg != nil && cfg.Report.Format != "" {
		formats = []string{cfg.Report.Format}
	}

	filter := core.NewFindingFilter()
	filter.MinSeverity = core.ParseSeverity(minSeverity)
	filter.ExcludedFiles = scanExclude
	filter.IncludedFiles = scanInclude
	pipeline.SetFilter(filter)

	// Live spinner: one spinning icon per running scanner (TTY only;
	// degrades to plain lines when output is piped/CI).
	sp := ui.NewSpinner(!rootCmd.PersistentFlags().Changed("no-color"))
	sp.Start()
	pipeline.SetProgress(sp)
	defer sp.Stop()

	var scanTypes []core.ScanType
	if len(scanScanners) > 0 {
		seen := map[core.ScanType]bool{}
		for _, s := range scanScanners {
			norm := core.ScanType(normalizeScannerName(s))
			if _, ok := registry.Get(norm); !ok {
				return fmt.Errorf("unknown scanner %q (available: %s)", strings.TrimSpace(s), availableScanners())
			}
			if seen[norm] {
				continue
			}
			seen[norm] = true
			scanTypes = append(scanTypes, norm)
		}
	} else {
		// Auto-detect target type and set sensible defaults
		if isURL(target) {
			scanTypes = []core.ScanType{core.ScanTypeDAST, core.ScanTypeNetwork}
			if cfg == nil || cfg.Scanners.WebScan {
				scanTypes = append(scanTypes, core.ScanTypeWebScan)
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

	// Resolve the target before any cloud/session work so a mistyped path
	// fails fast without a token refresh round-trip.
	targetKind, err := classifyTarget(target)
	if err != nil {
		return err
	}
	targetObj := core.Target{Kind: targetKind, URI: target}

	// Scanning never requires an account — webscan included. Results are
	// uploaded to the dashboard scan history only when a session exists;
	// otherwise the upload is skipped (never fails or prompts — CI/air-gapped
	// friendly).
	scanCtx := context.Background()
	cloudCfg := cloud.DefaultConfig()
	cloudToken, tokenErr := cloud.EnsureValidToken(scanCtx, cloudCfg)
	canUpload := tokenErr == nil

	results, err := pipeline.Scan(context.Background(), targetObj, scanTypes)
	if err != nil {
		return fmt.Errorf("scan failed: %w", err)
	}
	sp.Stop()

	// Surface scanner errors instead of reporting a silent, clean-looking scan.
	failed := 0
	for _, r := range results {
		if r.Error != "" {
			failed++
			fmt.Fprintf(os.Stderr, "  warn: %s could not complete: %s\n", r.Scanner, r.Error)
		}
	}
	if failed > 0 && failed == len(results) {
		return fmt.Errorf("all scanners failed for %s", target)
	}

	// --compliance annotates findings with the frameworks that map to their
	// category; it is validation + metadata, not a filter.
	frameworks := complianceFrameworks(cmd)
	if len(frameworks) > 0 {
		if err := applyCompliance(results, frameworks); err != nil {
			return err
		}
	}

	// Non-recursive scans still walk the tree (cheap for rule scanners) but
	// only report findings in top-level files.
	if !scanRecursive {
		results = dropNestedFindings(results)
	}

	// Enrich generic fix hints with specific, language-aware remediation steps.
	for i := range results {
		core.EnrichFixes(results[i].Findings)
	}

	suppressed := 0
	if scanBaseline != "" {
		bl, err := baseline.Load(scanBaseline)
		if err != nil {
			return fmt.Errorf("load baseline: %w", err)
		}
		results, suppressed = bl.Filter(results)
	}

	duration := time.Since(start).Seconds()

	totalFindings := 0
	for _, r := range results {
		totalFindings += len(r.Findings)
	}

	fmt.Fprintf(os.Stderr, "\n%s\n", ui.Gold(fmt.Sprintf("Scan completed in %.2f seconds", duration), stderrColor()))
	fmt.Fprintf(os.Stderr, "%s\n", ui.Gold(fmt.Sprintf("Found %d findings", totalFindings), stderrColor()))
	if scanBaseline != "" {
		fmt.Fprintf(os.Stderr, "Baseline: %d known findings suppressed\n", suppressed)
	}

	for _, format := range formats {
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
			// With several formats and one --output base name, append the
			// extension so files do not overwrite each other. A format with
			// no extension (table) keeps the plain base name.
			if len(formats) > 1 && ext != "" {
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
	if canUpload {
		names := make([]string, len(scanTypes))
		for i, t := range scanTypes {
			names[i] = string(t)
		}
		uploadScan(scanCtx, cloudCfg, cloudToken, strings.Join(names, ","),
			target, totalFindings, duration, results, start)
	} else if isURL(target) && !uploadDisabled() && !quietEnabled() {
		fmt.Fprintln(os.Stderr, "Tip: results not saved to dashboard history — run 'iris cloud login' to sync scans.")
	}

	if scanExitCode && totalFindings > 0 {
		os.Exit(1)
	}

	return nil
}

func isURL(s string) bool {
	return strings.HasPrefix(s, "http://") || strings.HasPrefix(s, "https://")
}

// classifyTarget decides how to treat a scan target. A path that exists on
// disk is always a filesystem target: the old heuristic treated any path
// containing a dot or slash ("-./app") as a container image.
func classifyTarget(target string) (core.TargetKind, error) {
	if isURL(target) {
		return core.TargetURL, nil
	}
	if fi, err := os.Stat(target); err == nil {
		if !fi.IsDir() {
			return core.TargetFS, nil
		}
		if isGitRepoDir(target) {
			return core.TargetRepo, nil
		}
		return core.TargetFS, nil
	}
	if isGitRepoDir(target) || strings.HasPrefix(target, "git@") {
		return core.TargetRepo, nil
	}
	if looksLikeImageRef(target) {
		return core.TargetImage, nil
	}
	return "", fmt.Errorf("target not found: %s", target)
}

func isGitRepoDir(dir string) bool {
	if _, err := os.Stat(filepath.Join(dir, ".git")); err == nil {
		return true
	}
	return strings.HasSuffix(dir, ".git")
}

// looksLikeImageRef recognises registry/image[:tag]@digest references. It is
// deliberately narrow so a mistyped directory is reported as missing rather
// than scanned as an image.
func looksLikeImageRef(s string) bool {
	if s == "" || strings.HasPrefix(s, ".") || strings.HasPrefix(s, "/") {
		return false
	}
	return strings.Contains(s, "/") && (strings.Contains(s, ":") || strings.Contains(s, "@"))
}

func normalizeScannerName(name string) string {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "website", "audit", "wscan":
		return string(core.ScanTypeWebScan)
	case "secret":
		return string(core.ScanTypeSecrets)
	case "deps", "dependency", "dependencies":
		return string(core.ScanTypeSCA)
	case "fmt":
		return string(core.ScanTypeFormat)
	default:
		return strings.ToLower(strings.TrimSpace(name))
	}
}

func availableScanners() string {
	var names []string
	for _, t := range registry.SupportedTypes() {
		names = append(names, string(t))
	}
	sort.Strings(names)
	return strings.Join(names, ", ")
}

// complianceFrameworks resolves --compliance, falling back to the profile or
// configuration value when the flag was not passed.
func complianceFrameworks(cmd *cobra.Command) []string {
	if cmd.Flags().Changed("compliance") {
		v, _ := cmd.Flags().GetString("compliance")
		return splitFrameworks(v)
	}
	if cfg != nil {
		return cfg.Filter.Compliance
	}
	return nil
}

func splitFrameworks(v string) []string {
	var out []string
	for _, part := range strings.Split(v, ",") {
		if part = strings.TrimSpace(strings.ToLower(part)); part != "" {
			out = append(out, part)
		}
	}
	return out
}

// applyCompliance tags findings with the control each framework maps to.
// Frameworks without a mapping for a category are skipped.
func applyCompliance(results []core.ScanResult, frameworks []string) error {
	supported := map[string]bool{"owasp": true, "soc2": true, "iso27001": true, "cwe": true}
	var unknown []string
	for _, fw := range frameworks {
		if !supported[fw] {
			unknown = append(unknown, fw)
		}
	}
	if len(unknown) > 0 {
		return fmt.Errorf("unsupported compliance framework(s): %s (supported: cwe, iso27001, owasp, soc2)", strings.Join(unknown, ", "))
	}

	for ri := range results {
		for fi := range results[ri].Findings {
			f := &results[ri].Findings[fi]
			m, ok := config.ComplianceByCategory[f.Category]
			if !ok {
				continue
			}
			if f.Metadata == nil {
				f.Metadata = map[string]interface{}{}
			}
			mapping := map[string]string{}
			for _, fw := range frameworks {
				var value string
				switch fw {
				case "owasp":
					value = m.OWASP
				case "cwe":
					value = m.CWE
				case "soc2":
					value = m.SOC2
				case "iso27001":
					value = m.ISO27001
				}
				if value == "" {
					continue
				}
				mapping[fw] = value
				f.Tags = appendUnique(f.Tags, fw+":"+value)
			}
			if len(mapping) > 0 {
				f.Metadata["compliance"] = mapping
			}
		}
	}
	return nil
}

func appendUnique(list []string, value string) []string {
	for _, v := range list {
		if v == value {
			return list
		}
	}
	return append(list, value)
}

func dropNestedFindings(results []core.ScanResult) []core.ScanResult {
	for ri := range results {
		kept := results[ri].Findings[:0]
		for _, f := range results[ri].Findings {
			if !strings.Contains(filepath.ToSlash(f.File), "/") {
				kept = append(kept, f)
			}
		}
		results[ri].Findings = kept
	}
	return results
}
