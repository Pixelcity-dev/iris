package reporter

import (
	"fmt"
	"strings"
	"time"

	"github.com/Pixelcity-dev/Iris/internal/config"
	"github.com/Pixelcity-dev/Iris/internal/core"
)

type HTMLReporter struct{}

func (r *HTMLReporter) Name() string      { return "html" }
func (r *HTMLReporter) Extension() string { return "html" }

func (r *HTMLReporter) Generate(results []core.ScanResult, opts ReportOptions) ([]byte, error) {
	var sb strings.Builder
	total := 0
	duration := 0.0
	var all []core.Finding
	targets := []string{}
	for _, res := range results {
		total += len(res.Findings)
		all = append(all, res.Findings...)
		duration += res.Duration
		if res.Target.URI != "" {
			targets = append(targets, res.Target.URI)
		}
	}
	score, level := core.RiskScore(all)
	bySev := make(map[string]int)
	byCat := make(map[string]int)
	for _, f := range all {
		bySev[f.Severity.String()]++
		byCat[f.Category]++
	}
	// Color for risk level
	riskColor := "#3fb950"
	if level == "Medium" {
		riskColor = "#d29922"
	} else if level == "High" {
		riskColor = "#f0883e"
	} else if level == "Critical" {
		riskColor = "#f85149"
	}
	targetStr := strings.Join(targets, ", ")
	if targetStr == "" {
		targetStr = "Project scan"
	}

	sb.WriteString(`<!DOCTYPE html>
<html lang="en"><head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Iris Report — ` + targetStr + `</title>
<style>
:root{--bg:#0d1117;--card:#161b22;--border:#30363d;--text:#c9d1d9;--muted:#8b949e;--accent:#1f6feb;--radius:12px}
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:Inter,-apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;background:var(--bg);color:var(--text);line-height:1.6}
.topbar{background:#010409;border-bottom:1px solid var(--border);padding:14px 28px;display:flex;justify-content:space-between;align-items:center;position:sticky;top:0;z-index:10}
.topbar .brand{font-weight:800;letter-spacing:.02em;display:flex;gap:10px;align-items:center}
.topbar .brand span{color:#58a6ff}
.topbar a{color:var(--muted);text-decoration:none;font-size:13px;margin-left:16px}
.container{max-width:1180px;margin:0 auto;padding:28px}
.hero{background:linear-gradient(135deg,#0d2a5e,#1f6feb);border-radius:var(--radius);padding:36px;color:white;display:grid;grid-template-columns:1.2fr .8fr;gap:24px}
.hero h1{font-size:28px;margin-bottom:8px}
.hero p{opacity:.85;font-size:14px}
.metrics{display:grid;grid-template-columns:repeat(5,1fr);gap:14px;margin:24px 0}
.metric{background:var(--card);border:1px solid var(--border);border-radius:var(--radius);padding:18px;text-align:center}
.metric .v{font-size:28px;font-weight:800}
.metric .k{color:var(--muted);font-size:12px;text-transform:uppercase;letter-spacing:.08em}
.risk{border-left:4px solid ` + riskColor + `;background:var(--card);border:1px solid var(--border);border-left-color:` + riskColor + `;border-radius:var(--radius);padding:18px;display:flex;justify-content:space-between;align-items:center;margin:20px 0}
.grid2{display:grid;grid-template-columns:1fr 1fr;gap:18px;margin:20px 0}
.card{background:var(--card);border:1px solid var(--border);border-radius:var(--radius);padding:18px}
.card h3{font-size:13px;color:var(--muted);text-transform:uppercase;letter-spacing:.08em;margin-bottom:10px}
.kv{display:flex;justify-content:space-between;padding:8px 0;border-bottom:1px solid #21262d;font-size:14px}
.kv:last-child{border:none}
.badge{padding:2px 8px;border-radius:20px;font-size:11px;font-weight:700;text-transform:uppercase}
.badge-critical{background:#f85149;color:white}
.badge-high{background:#f0883e;color:white}
.badge-medium{background:#d29922;color:#111}
.badge-low{background:#3fb950;color:#111}
.badge-info{background:#58a6ff;color:#111}
.finding{background:var(--card);border:1px solid var(--border);border-radius:var(--radius);padding:18px;margin:12px 0}
.finding .hdr{display:flex;justify-content:space-between;gap:12px;margin-bottom:8px}
.finding .title{font-weight:700}
.meta{color:var(--muted);font-size:12px;margin-bottom:8px}
.code{background:#0d1117;border:1px solid #21262d;border-radius:8px;padding:10px;margin-top:10px;font-family:ui-monospace,monospace;font-size:12px;overflow:auto}
.fix{background:#0d4429;border:1px solid #1b7a4a;border-radius:8px;padding:10px;margin-top:10px;font-size:13px}
.comp{font-size:11px;color:#8b949e;border:1px solid #21262d;border-radius:6px;padding:4px 8px;display:inline-block;margin-top:6px}
.footer{text-align:center;color:#484f58;font-size:12px;margin:40px 0}
.bar{height:8px;background:#21262d;border-radius:8px;overflow:hidden;display:flex}
.bar div{height:100%}
@media(max-width:900px){.hero{grid-template-columns:1fr}.metrics{grid-template-columns:repeat(2,1fr)}.grid2{grid-template-columns:1fr}}
</style>
</head>
<body>
<div class="topbar"><div class="brand">⬢ DEEPSEC</div><div><a href="https://pixelcity.top/docs/iris">Docs</a><a href="https://github.com/Pixelcity-dev/Iris">GitHub</a></div></div>
<div class="container">
<div class="hero">
<div><h1>Security Report</h1><p>Target: ` + templateEscape(targetStr) + ` • ` + time.Now().Format("Jan 2, 2006 15:04 MST") + ` • Duration: ` + fmt.Sprintf("%.2fs", duration) + `</p><p style="margin-top:10px;font-size:12px;opacity:.9">Coverage: SAST 11+ langs • SCA 11+ ecosystems • Secrets 200+ patterns • IaC/K8s/Docker • DAST/WebScan OWASP Top 10 • Network • License • SBOM</p></div>
<div style="background:rgba(255,255,255,.08);border-radius:12px;padding:18px;text-align:center"><div style="font-size:12px;opacity:.8;letter-spacing:.08em;text-transform:uppercase">Risk Rating</div><div style="font-size:42px;font-weight:900;color:` + riskColor + `">` + level + `</div><div style="font-size:13px;opacity:.9">Risk Score: ` + fmt.Sprintf("%d", score) + ` • ` + fmt.Sprintf("%d", total) + ` findings</div><div style="font-size:11px;opacity:.7;margin-top:6px">0 Excellent • &lt;5 Low • &lt;20 Medium • &lt;50 High • 50+ Critical</div></div>
</div>
`)
	// Metrics
	sb.WriteString(fmt.Sprintf(`<div class="metrics">
<div class="metric"><div class="v">%d</div><div class="k">Total</div></div>`, total))
	for _, sev := range []string{"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"} {
		c := bySev[sev]
		cls := strings.ToLower(sev)
		sb.WriteString(fmt.Sprintf(`<div class="metric"><div class="v" style="color:var(--%s, #c9d1d9)">%d</div><div class="k">%s</div></div>`, cls, c, sev))
	}
	sb.WriteString(`</div>`)

	// Risk mitigation priority bar
	sum := total
	if sum == 0 {
		sum = 1
	}
	sb.WriteString(`<div class="card"><h3>Exposure</h3><div class="bar">`)
	for _, sev := range []string{"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"} {
		c := bySev[sev]
		if c == 0 {
			continue
		}
		w := float64(c) / float64(sum) * 100
		color := "#58a6ff"
		switch sev {
		case "CRITICAL":
			color = "#f85149"
		case "HIGH":
			color = "#f0883e"
		case "MEDIUM":
			color = "#d29922"
		case "LOW":
			color = "#3fb950"
		}
		sb.WriteString(fmt.Sprintf(`<div style="width:%.1f%%;background:%s" title="%s %d"></div>`, w, color, sev, c))
	}
	sb.WriteString(`</div><div style="font-size:12px;color:#8b949e;margin-top:8px">Prioritize: Critical → High → Medium. Gate: --fail-on HIGH.</div></div>`)

	// Compliance overview
	sb.WriteString(`<div class="grid2">
<div class="card"><h3>Compliance Mapping</h3>`)
	if total == 0 {
		sb.WriteString(`<div style="color:#3fb950;font-weight:700">✅ No gaps — SOC 2 CC6/CC7, ISO 27001 A.14/A.13, OWASP Top 10 clear</div>`)
	} else {
		for cat, cnt := range byCat {
			m := config.ComplianceByCategory[cat]
			if m.OWASP == "" {
				m = config.ComplianceMapping{OWASP: "A00", CWE: "-", SOC2: "-", ISO27001: "-"}
			}
			sb.WriteString(fmt.Sprintf(`<div class="kv"><span>%s <span style="color:#8b949e">×%d</span></span><span class="comp">OWASP %s · CWE %s · SOC2 %s · ISO %s</span></div>`, templateEscape(cat), cnt, m.OWASP, m.CWE, m.SOC2, m.ISO27001))
		}
	}
	sb.WriteString(`</div><div class="card"><h3>Action Plan</h3>
<div class="kv"><span>1. Immediate (Critical/High)</span><span>24h</span></div>
<div class="kv"><span>2. Scheduled (Medium)</span><span>7 days</span></div>
<div class="kv"><span>3. Hardening (Low/Info)</span><span>30 days</span></div>
<div style="font-size:12px;color:#8b949e;margin-top:8px">Export: <code>--format sarif</code> → Code Scanning • <code>--format cyclonedx</code> → SBOM • <code>iris mcp start</code> → AI agents</div>
</div></div>`)

	// Findings
	sb.WriteString(`<div class="card"><h3>Findings — prioritized by severity</h3></div>`)
	// Sort all findings by severity descending
	var sorted []core.Finding
	for _, res := range results {
		sorted = append(sorted, res.Findings...)
	}
	for i := 0; i < len(sorted); i++ {
		for j := i + 1; j < len(sorted); j++ {
			if sorted[j].Severity > sorted[i].Severity {
				sorted[i], sorted[j] = sorted[j], sorted[i]
			}
		}
	}
	if len(sorted) == 0 {
		sb.WriteString(`<div class="finding" style="border-left:4px solid #3fb950"><div class="title">✅ No actionable findings — Excellent posture</div><div class="meta">Target clean. Keep scanning in CI: <code>iris scan --fail-on high</code></div></div>`)
	}
	for _, f := range sorted {
		cls := strings.ToLower(f.Severity.String())
		sb.WriteString(fmt.Sprintf(`<div class="finding">
<div class="hdr"><span class="title">%s</span><span class="badge badge-%s">%s</span></div>
<div class="meta">Rule <code>%s</code> • Category <code>%s</code> • Scanner <code>%s</code> • File <code>%s:%d</code></div>
<div style="font-size:14px">%s</div>`, templateEscape(f.Title), cls, f.Severity.String(), templateEscape(f.RuleID), templateEscape(f.Category), templateEscape(string(f.ScanType)), templateEscape(f.File), f.Line, templateEscape(f.Description)))
		if m, ok := config.ComplianceByCategory[f.Category]; ok {
			sb.WriteString(fmt.Sprintf(`<div class="comp">OWASP %s · CWE-%s · SOC2 %s · ISO 27001 %s</div>`, m.OWASP, m.CWE, m.SOC2, m.ISO27001))
		}
		if f.Code != "" {
			sb.WriteString(fmt.Sprintf(`<div class="code">%s</div>`, templateEscape(f.Code)))
		}
		if f.Fix != "" {
			sb.WriteString(fmt.Sprintf(`<div class="fix"><strong>Remediation:</strong> %s</div>`, templateEscape(f.Fix)))
		}
		if len(f.References) > 0 {
			sb.WriteString(`<div style="margin-top:8px;font-size:12px">`)
			for _, ref := range f.References {
				sb.WriteString(fmt.Sprintf(`<a href="%s" style="color:#58a6ff;margin-right:12px" target="_blank">%s</a>`, templateEscape(ref), templateEscape(ref)))
			}
			sb.WriteString(`</div>`)
		}
		sb.WriteString(`</div>`)
	}

	sb.WriteString(`<div class="footer">
<p><strong>Iris</strong> v1.1.0 — Cyber Security Enterprise Tool • Generated ` + time.Now().Format(time.RFC3339) + ` • Target: ` + templateEscape(targetStr) + `</p>
<p><a href="https://pixelcity.top/docs/iris" style="color:#58a6ff">Docs</a> • <a href="https://github.com/Pixelcity-dev/Iris" style="color:#58a6ff">GitHub</a></p>
</div></div></body></html>`)
	return []byte(sb.String()), nil
}

func templateEscape(s string) string {
	r := strings.ReplaceAll(s, "&", "&amp;")
	r = strings.ReplaceAll(r, "<", "&lt;")
	r = strings.ReplaceAll(r, ">", "&gt;")
	r = strings.ReplaceAll(r, "\"", "&quot;")
	return r
}
