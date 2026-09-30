package reporter

import (
	"fmt"
	"strings"
	"time"

	"github.com/Pixelcity-dev/Iris/internal/config"
	"github.com/Pixelcity-dev/Iris/internal/core"
)

type TableReporter struct{}

func (r *TableReporter) Name() string      { return "table" }
func (r *TableReporter) Extension() string { return "" }

func (r *TableReporter) Generate(results []core.ScanResult, opts ReportOptions) ([]byte, error) {
	var sb strings.Builder
	totalFindings := 0
	var allFindings []core.Finding
	duration := 0.0
	targets := []string{}
	for _, res := range results {
		totalFindings += len(res.Findings)
		allFindings = append(allFindings, res.Findings...)
		duration += res.Duration
		if res.Target.URI != "" {
			targets = append(targets, res.Target.URI)
		}
	}
	score, level := core.RiskScore(allFindings)

	// Header
	sb.WriteString("\n")
	if opts.Color {
		sb.WriteString("\033[1;34m╔════════════════════════════════════════════════════════════════╗\033[0m\n")
		sb.WriteString("\033[1;34m║\033[0m \033[1;37m⬡ Iris — Cyber Security Enterprise Tool                 \033[0m\033[1;34m║\033[0m\n")
		sb.WriteString("\033[1;34m║\033[0m  \033[2mSAST • SCA • Secrets • IaC • Containers • DAST • WebScan • Network • Format • BuildTest\033[0m  \033[1;34m║\033[0m\n")
		sb.WriteString("\033[1;34m╚════════════════════════════════════════════════════════════════╝\033[0m\n")
	} else {
		sb.WriteString("Iris — Cyber Security Enterprise Tool\n")
		sb.WriteString("SAST • SCA • Secrets • IaC • Containers • DAST • WebScan • Network • Format • BuildTest\n")
	}
	sb.WriteString(fmt.Sprintf("  Target: %s  •  %s  •  %.2fs\n", strings.Join(targets, ", "), time.Now().Format("2006-01-02 15:04 MST"), duration))
	// Risk rating
	riskColor := ""
	reset := ""
	if opts.Color {
		reset = "\033[0m"
		switch level {
		case "Excellent":
			riskColor = "\033[1;32m"
		case "Low":
			riskColor = "\033[32m"
		case "Medium":
			riskColor = "\033[93m"
		case "High":
			riskColor = "\033[31m"
		case "Critical":
			riskColor = "\033[1;31m"
		}
	}
	sb.WriteString(fmt.Sprintf("  Risk Score: %s%d (%s)%s", riskColor, score, level, reset))
	if totalFindings == 0 {
		sb.WriteString("  ✅ Excellent — No actionable findings\n\n")
		return []byte(sb.String()), nil
	}
	sb.WriteString(fmt.Sprintf("  •  %d findings\n\n", totalFindings))

	// Summary by severity
	bySeverity := make(map[string]int)
	byType := make(map[string]int)
	byCategory := make(map[string]int)
	for _, f := range allFindings {
		bySeverity[f.Severity.String()]++
		byType[string(f.ScanType)]++
		byCategory[f.Category]++
	}
	sb.WriteString("Summary by Severity\n")
	sb.WriteString("────────────────────\n")
	order := []string{"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}
	for _, sev := range order {
		if count, ok := bySeverity[sev]; ok {
			bar := strings.Repeat("■", count)
			if count > 10 {
				bar = strings.Repeat("■", 10) + fmt.Sprintf(" +%d", count-10)
			}
			if opts.Color {
				color := ""
				switch sev {
				case "CRITICAL":
					color = "\033[1;31m"
				case "HIGH":
					color = "\033[31m"
				case "MEDIUM":
					color = "\033[93m"
				case "LOW":
					color = "\033[33m"
				default:
					color = "\033[36m"
				}
				sb.WriteString(fmt.Sprintf("  %s%-10s\033[0m %3d  %s\n", color, sev, count, bar))
			} else {
				sb.WriteString(fmt.Sprintf("  %-10s %3d  %s\n", sev, count, bar))
			}
		}
	}
	sb.WriteString("\n")
	sb.WriteString("By Scanner / Category\n")
	sb.WriteString("──────────────────────\n")
	for t, c := range byType {
		sb.WriteString(fmt.Sprintf("  %-15s %d\n", t, c))
	}
	for cat, c := range byCategory {
		if cm, ok := config.ComplianceByCategory[cat]; ok {
			sb.WriteString(fmt.Sprintf("  %-20s %d  \033[2m[OWASP %s CWE-%s]\033[0m\n", cat, c, cm.OWASP, cm.CWE))
		} else {
			sb.WriteString(fmt.Sprintf("  %-20s %d\n", cat, c))
		}
	}
	sb.WriteString("\n")

	// Findings grouped by scanner
	for _, result := range results {
		if len(result.Findings) == 0 {
			continue
		}
		sb.WriteString(fmt.Sprintf("Scanner: %s  (%s)\n", result.Scanner, result.Target.URI))
		sb.WriteString(strings.Repeat("─", 64) + "\n")
		// Sort by severity weight descending
		// simple bubble for small lists
		findings := result.Findings
		for i := 0; i < len(findings); i++ {
			for j := i + 1; j < len(findings); j++ {
				if findings[j].Severity > findings[i].Severity {
					findings[i], findings[j] = findings[j], findings[i]
				}
			}
		}
		for _, f := range findings {
			sev := f.Severity.String()
			if opts.Color {
				switch f.Severity {
				case core.SeverityCritical:
					sev = fmt.Sprintf("\033[1;31m%s\033[0m", sev)
				case core.SeverityHigh:
					sev = fmt.Sprintf("\033[31m%s\033[0m", sev)
				case core.SeverityMedium:
					sev = fmt.Sprintf("\033[93m%s\033[0m", sev)
				case core.SeverityLow:
					sev = fmt.Sprintf("\033[33m%s\033[0m", sev)
				case core.SeverityInfo:
					sev = fmt.Sprintf("\033[36m%s\033[0m", sev)
				}
			}
			sb.WriteString(fmt.Sprintf("  [%s] %s\n", sev, f.Title))
			if f.File != "" {
				sb.WriteString(fmt.Sprintf("       File: %s:%d\n", f.File, f.Line))
			}
			sb.WriteString(fmt.Sprintf("       Rule: %s  •  Category: %s", f.RuleID, f.Category))
			if cm, ok := config.ComplianceByCategory[f.Category]; ok {
				sb.WriteString(fmt.Sprintf("  \033[2m[OWASP %s | CWE %s | SOC2 %s | ISO %s]\033[0m", cm.OWASP, cm.CWE, cm.SOC2, cm.ISO27001))
			}
			sb.WriteString("\n")
			if f.Description != "" {
				sb.WriteString(fmt.Sprintf("       %s\n", f.Description))
			}
			if f.Fix != "" {
				if opts.Color {
					sb.WriteString(fmt.Sprintf("       \033[32mFix:\033[0m %s\n", f.Fix))
				} else {
					sb.WriteString(fmt.Sprintf("       Fix: %s\n", f.Fix))
				}
			}
			if len(f.References) > 0 {
				sb.WriteString(fmt.Sprintf("       Refs: %s\n", strings.Join(f.References, ", ")))
			}
			sb.WriteString("\n")
		}
	}
	sb.WriteString("────────────────────────────────────────────────────────────────\n")
	sb.WriteString("  Next: iris scan --format sarif --output results.sarif  → GitHub Code Scanning\n")
	sb.WriteString("        iris scan --format html --output report.html   → Report\n")
	sb.WriteString("  Docs: https://pixelcity.top/docs/iris  •  https://github.com/Pixelcity-dev/Iris\n")
	return []byte(sb.String()), nil
}
