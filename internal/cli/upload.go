package cli

// Shared helpers for persisting scan results to the dashboard scan history.

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/Pixelcity-dev/Iris/internal/cloud"
	"github.com/Pixelcity-dev/Iris/internal/core"
)

// severityCounts aggregates findings by lowercase severity key
// (critical, high, medium, low, info). Returns nil when empty.
func severityCounts(results []core.ScanResult) map[string]int {
	counts := map[string]int{}
	for _, r := range results {
		for _, f := range r.Findings {
			counts[strings.ToLower(f.Severity.String())]++
		}
	}
	if len(counts) == 0 {
		return nil
	}
	return counts
}

// buildScanReport marshals the full structured scan output (every result
// with all findings) for dashboard persistence. Returns nil on failure.
func buildScanReport(results []core.ScanResult, start time.Time) json.RawMessage {
	payload := map[string]interface{}{
		"iris_version": version,
		"start_time":   start.UTC().Format(time.RFC3339),
		"end_time":     time.Now().UTC().Format(time.RFC3339),
		"results":      results,
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		return nil
	}
	return raw
}

// uploadScan saves one scan (metadata + full report) to the dashboard
// history. Best-effort: failures are printed but never fail the scan.
func uploadScan(ctx context.Context, cfg cloud.Config, token, scanner, target string,
	findings int, duration float64, results []core.ScanResult, start time.Time) {

	err := cloud.ReportUsage(ctx, cfg, token, cloud.UsageEntry{
		Time:           start.UTC(),
		Scanner:        scanner,
		Target:         target,
		Findings:       findings,
		DurationS:      duration,
		SeverityCounts: severityCounts(results),
		Report:         buildScanReport(results, start),
		Version:        version,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "Note: could not save scan to dashboard history: %v\n", err)
		return
	}
	fmt.Fprintf(os.Stderr, "Saved to dashboard scan history.\n")
}
