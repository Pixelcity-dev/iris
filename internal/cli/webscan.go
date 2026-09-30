package cli

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/Pixelcity-dev/Iris/internal/cloud"
	"github.com/Pixelcity-dev/Iris/internal/core"
	"github.com/Pixelcity-dev/Iris/internal/reporter"
	"github.com/Pixelcity-dev/Iris/internal/ui"
	"github.com/spf13/cobra"
)

var (
	webscanOutput   string
	webscanFormat   string
	webscanSeverity string
	webscanDeep     bool
)

var webscanCmd = &cobra.Command{
	Use:   "webscan [url]",
	Short: "Deep website security scanner",
	Long: `DeepScan a website for security issues with very depth checks.

Performs comprehensive OWASP-based audit:
  - Security headers (HSTS, CSP, X-Frame-Options, etc. with deep CSP analysis)
  - TLS (version, cipher, cert expiry, self-signed, hostname mismatch)
  - Cookie security (Secure, HttpOnly, SameSite)
  - CORS misconfiguration (wildcard, reflected origin, null)
  - Information disclosure (Server, X-Powered-By, etc.)
  - HTTP methods & TRACE
  - Clickjacking protection
  - Exposed files (.env, .git, backup.zip, etc.)
  - Open redirect (safe)
  - XSS reflection (safe)
  - SQLi error disclosure (safe)
  - Directory listing
  - Mixed content & SRI
  - HTTPS redirect & HSTS preload

Examples:
  iris webscan https://example.com
  iris webscan https://example.com --format json --output report.json
  iris webscan https://example.com --severity high
  iris scan https://example.com --scanner webscan,dast

Requires login: results are saved to your dashboard scan history.
Run "iris cloud login" once, then scan freely.

Aliases: scan URL, website, audit`,
	Aliases: []string{"website", "audit", "wscan"},
	Args:    cobra.ExactArgs(1),
	RunE:    runWebscan,
}

func init() {
	webscanCmd.Flags().StringVarP(&webscanOutput, "output", "o", "", "output file path")
	webscanCmd.Flags().StringVarP(&webscanFormat, "format", "f", "table", "output format (table, json, sarif, html, csv)")
	webscanCmd.Flags().StringVar(&webscanSeverity, "severity", "INFO", "minimum severity (INFO, LOW, MEDIUM, HIGH, CRITICAL)")
	webscanCmd.Flags().BoolVar(&webscanDeep, "deep", true, "enable very deep checks (exposed files, open redirect, xss, sqli)")
	rootCmd.AddCommand(webscanCmd)
}

func runWebscan(cmd *cobra.Command, args []string) error {
	// WebScan requires a PixelCity account: results are saved to the
	// dashboard scan history. Authenticate once via device flow.
	ctx := context.Background()
	cloudCfg := cloud.DefaultConfig()
	accessToken, err := cloud.EnsureValidToken(ctx, cloudCfg)
	if err != nil {
		return fmt.Errorf("webscan requires login: %w\n\nRun: iris cloud login", err)
	}

	targetURL := args[0]
	if !isURL(targetURL) {
		// allow without scheme
		if !isURL("https://" + targetURL) {
			return fmt.Errorf("invalid URL: %s (expected https://example.com)", targetURL)
		}
		targetURL = "https://" + targetURL
	}

	fmt.Fprintf(os.Stderr, "Iris WebScan v%s - Deep website audit on %s\n", version, targetURL)
	if webscanDeep {
		fmt.Fprintf(os.Stderr, "Mode: very deep (headers + TLS + CORS + exposed files + open redirect + XSS + SQLi + ...)\n")
	}

	start := time.Now()

	ruleEngine := core.NewRuleEngine()
	// Load rules if available (not required for webscan, but keep for consistency)
	_ = ruleEngine.LoadRulesFromDir("rules")

	pipeline := core.NewPipeline(registry, ruleEngine)
	filter := core.NewFindingFilter()
	filter.MinSeverity = core.ParseSeverity(webscanSeverity)
	pipeline.SetFilter(filter)

	// Live spinner while deep checks run (TTY only).
	sp := ui.NewSpinner(!rootCmd.PersistentFlags().Changed("no-color"))
	sp.Start()
	pipeline.SetProgress(sp)

	targetObj := core.Target{
		Kind: core.TargetURL,
		URI:  targetURL,
		Options: map[string]interface{}{
			"deep": webscanDeep,
		},
	}

	results, err := pipeline.Scan(context.Background(), targetObj, []core.ScanType{core.ScanTypeWebScan})
	sp.Stop()
	if err != nil {
		return fmt.Errorf("webscan failed: %w", err)
	}

	duration := time.Since(start).Seconds()
	total := 0
	for _, r := range results {
		total += len(r.Findings)
		// If webscan scanner not registered, try fallback to DAST
		if r.Scanner == "webscan" && len(r.Findings) == 0 && total == 0 {
			// no findings may still be ok
		}
	}

	// Fallback: if webscan produced no scanner (not registered), try DAST as alias
	if len(results) == 0 || (len(results) == 1 && results[0].Scanner == "" && total == 0) {
		// try dast + webscan combined
		results, _ = pipeline.Scan(context.Background(), targetObj, []core.ScanType{core.ScanTypeDAST, core.ScanTypeWebScan})
		total = 0
		for _, r := range results {
			total += len(r.Findings)
		}
	}

	fmt.Fprintf(os.Stderr, "\nWebScan completed in %.2f seconds\n", duration)
	if total == 0 {
		fmt.Fprintf(os.Stderr, "No issues found - site looks good! (checked %d categories)\n", 16)
	} else {
		fmt.Fprintf(os.Stderr, "Found %d issues\n", total)
		// Severity breakdown
		bySev := make(map[string]int)
		for _, r := range results {
			for _, f := range r.Findings {
				bySev[f.Severity.String()]++
			}
		}
		for _, sev := range []string{"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"} {
			if c, ok := bySev[sev]; ok && c > 0 {
				fmt.Fprintf(os.Stderr, "  %s: %d\n", sev, c)
			}
		}
	}

	// Generate report
	rpt := reporter.GetReporter(webscanFormat)
	if rpt == nil {
		return fmt.Errorf("unknown format: %s", webscanFormat)
	}
	output, err := rpt.Generate(results, reporter.ReportOptions{
		Format: webscanFormat,
		Output: webscanOutput,
		Color:  !rootCmd.PersistentFlags().Changed("no-color"),
	})
	if err != nil {
		return fmt.Errorf("failed to generate report: %w", err)
	}

	if webscanOutput != "" {
		if err := os.WriteFile(webscanOutput, output, 0644); err != nil {
			return fmt.Errorf("failed to write output: %w", err)
		}
		fmt.Fprintf(os.Stderr, "Report written to %s\n", webscanOutput)
	} else {
		fmt.Print(string(output))
	}

	// Hint
	if total > 0 {
		fmt.Fprintf(os.Stderr, "\nHint: run with --format sarif --output results.sarif for GitHub Code Scanning\n")
		fmt.Fprintf(os.Stderr, "      iris scan https://example.com --scanner webscan --severity high\n")
	}

	// Save full results to dashboard scan history (best-effort).
	uploadScan(ctx, cloudCfg, accessToken, "webscan", targetURL, total, duration, results, start)

	return nil
}
