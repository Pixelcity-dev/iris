package main

// Exporters for stored scan reports: SARIF 2.1.0 (GitHub Code Scanning
// compatible) and a standalone HTML report. Self-contained — the
// dashboard module stays dependency-free.

import (
	"encoding/json"
	"fmt"
	"html"
	"strconv"
	"strings"
	"time"
)

type reportFinding struct {
	RuleID      string   `json:"rule_id"`
	ScanType    string   `json:"scan_type"`
	Severity    string   `json:"severity"`
	Category    string   `json:"category"`
	Title       string   `json:"title"`
	Description string   `json:"description"`
	File        string   `json:"file"`
	Line        int      `json:"line"`
	Code        string   `json:"code"`
	Fix         string   `json:"fix"`
	References  []string `json:"references"`
	Tags        []string `json:"tags"`
	Fingerprint string   `json:"fingerprint"`
	Confidence  float64  `json:"confidence"`
}

type reportResult struct {
	Scanner string `json:"scanner"`
	Target  struct {
		Kind string `json:"kind"`
		URI  string `json:"uri"`
	} `json:"target"`
	Findings []reportFinding `json:"findings"`
	Error    string          `json:"error"`
}

type reportDoc struct {
	IrisVersion string         `json:"iris_version"`
	StartTime   string         `json:"start_time"`
	EndTime     string         `json:"end_time"`
	Results     []reportResult `json:"results"`
}

func parseReport(data []byte) (*reportDoc, error) {
	var d reportDoc
	if err := json.Unmarshal(data, &d); err != nil {
		return nil, err
	}
	return &d, nil
}

// flatFinding is a finding paired with its resolved artifact URI.
type flatFinding struct {
	f   reportFinding
	uri string
}

// flattenFindings returns every finding with its artifact URI resolved
// (falling back to the scan's primary target).
func flattenFindings(e *scanEntry, doc *reportDoc) []flatFinding {
	var out []flatFinding
	for _, r := range doc.Results {
		uri := r.Target.URI
		if uri == "" {
			uri = e.Target
		}
		for _, f := range r.Findings {
			out = append(out, flatFinding{f, uri})
		}
	}
	return out
}

func sarifLevel(sev string) string {
	switch strings.ToUpper(sev) {
	case "CRITICAL", "HIGH":
		return "error"
	case "MEDIUM":
		return "warning"
	default:
		return "note"
	}
}

// sarifFromReport renders a SARIF 2.1.0 document for one stored scan.
func sarifFromReport(e *scanEntry, doc *reportDoc) ([]byte, error) {
	findings := flattenFindings(e, doc)

	type ruleMeta struct {
		ID    string `json:"id"`
		Name  string `json:"name"`
		Short struct {
			Text string `json:"text"`
		} `json:"shortDescription"`
		DefaultConfiguration struct {
			Level string `json:"level"`
		} `json:"defaultConfiguration"`
		Properties struct {
			Category string `json:"category,omitempty"`
		} `json:"properties"`
	}
	ruleIndex := map[string]int{}
	var rules []ruleMeta
	var sarifResults []map[string]interface{}

	for i, item := range findings {
		f, uri := item.f, item.uri
		ruleID := f.RuleID
		if ruleID == "" {
			ruleID = "iris.finding"
		}
		ri, seen := ruleIndex[ruleID]
		if !seen {
			ri = len(rules)
			ruleIndex[ruleID] = ri
			var m ruleMeta
			m.ID = ruleID
			m.Name = ruleID
			short := f.Title
			if short == "" {
				short = ruleID
			}
			m.Short.Text = short
			m.DefaultConfiguration.Level = sarifLevel(f.Severity)
			m.Properties.Category = f.Category
			rules = append(rules, m)
		}

		msg := f.Title
		if f.Description != "" {
			if msg != "" {
				msg += "\n\n"
			}
			msg += f.Description
		}
		if msg == "" {
			msg = ruleID
		}

		loc := map[string]interface{}{
			"physicalLocation": map[string]interface{}{
				"artifactLocation": map[string]interface{}{"uri": uri},
			},
		}
		if f.Line > 0 {
			loc["physicalLocation"].(map[string]interface{})["region"] =
				map[string]interface{}{"startLine": f.Line}
		}

		props := map[string]interface{}{
			"severity":    strings.ToUpper(f.Severity),
			"scan_type":   f.ScanType,
			"fingerprint": f.Fingerprint,
		}
		if f.Category != "" {
			props["category"] = f.Category
		}
		if f.Fix != "" {
			props["fix"] = f.Fix
		}
		if f.Code != "" {
			props["evidence"] = f.Code
		}
		if len(f.References) > 0 {
			props["references"] = f.References
		}
		if len(f.Tags) > 0 {
			props["tags"] = f.Tags
		}
		if f.Confidence > 0 {
			props["confidence"] = f.Confidence
		}

		sarifResults = append(sarifResults, map[string]interface{}{
			"ruleId":    ruleID,
			"ruleIndex": ri,
			"level":     sarifLevel(f.Severity),
			"message":   map[string]interface{}{"text": msg},
			"locations": []interface{}{loc},
			"partialFingerprints": map[string]interface{}{
				"irisFingerprint": f.Fingerprint,
			},
			"properties": props,
			"_index":     i,
		})
	}

	toolVersion := doc.IrisVersion
	if toolVersion == "" {
		toolVersion = e.Version
	}
	run := map[string]interface{}{
		"tool": map[string]interface{}{
			"driver": map[string]interface{}{
				"name":           "Iris",
				"informationUri": "https://pixelcity.top",
				"version":        toolVersion,
				"rules":          rules,
			},
		},
		"results": sarifResults,
		"properties": map[string]interface{}{
			"scanId":         e.ID,
			"target":         e.Target,
			"scanner":        e.Scanner,
			"scanStartTime":  doc.StartTime,
			"scanEndTime":    doc.EndTime,
			"severityCounts": e.SeverityCounts,
		},
	}
	if sarifResults == nil {
		run["results"] = []interface{}{}
	}

	out := map[string]interface{}{
		"$schema": "https://json.schemastore.org/sarif-2.1.0.json",
		"version": "2.1.0",
		"runs":    []interface{}{run},
	}
	return json.MarshalIndent(out, "", "  ")
}

const htmlCSS = `
:root{color-scheme:dark}
*{box-sizing:border-box}
body{margin:0;background:#0b1220;color:#e2e8f0;font:14px/1.5 system-ui,-apple-system,"Segoe UI",sans-serif}
.wrap{max-width:1080px;margin:0 auto;padding:32px 24px 64px}
h1{font-size:22px;margin:0 0 4px}
h2{font-size:16px;margin:28px 0 10px}
.meta{color:#94a3b8;font-size:13px;display:flex;flex-wrap:wrap;gap:14px;margin-bottom:18px}
.meta code{background:#111a2b;padding:2px 6px;border-radius:5px;color:#cbd5e1}
.chip{font-weight:700;font-size:12px;margin-right:10px}
.critical{color:#ef4444}.high{color:#f97316}.medium{color:#eab308}.low{color:#38bdf8}.info{color:#94a3b8}
table{width:100%;border-collapse:collapse;margin-top:8px}
th,td{text-align:left;padding:9px 10px;border-bottom:1px solid rgba(148,163,184,.15);vertical-align:top}
th{color:#94a3b8;font-size:12px;text-transform:uppercase;letter-spacing:.04em}
td.rule{font-family:ui-monospace,monospace;font-size:12px;color:#94a3b8;white-space:nowrap}
.desc{color:#94a3b8;font-size:13px;margin-top:3px}
.fix{color:#6ee7b7;font-size:13px;margin-top:3px}
pre{margin:6px 0 0;padding:8px;background:#0a101c;border:1px solid rgba(148,163,184,.2);border-radius:6px;font-size:12px;overflow-x:auto;max-height:140px;white-space:pre-wrap;word-break:break-word}
.empty{color:#64748b;padding:24px 0}
footer{margin-top:40px;color:#475569;font-size:12px;border-top:1px solid rgba(148,163,184,.15);padding-top:14px}
`

// htmlFromReport renders a standalone HTML report for one stored scan.
// All dynamic text is HTML-escaped.
func htmlFromReport(e *scanEntry, doc *reportDoc) []byte {
	esc := html.EscapeString
	findings := flattenFindings(e, doc)

	var b strings.Builder
	b.WriteString("<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">")
	b.WriteString("<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">")
	b.WriteString("<title>Iris scan report — " + esc(e.Target) + "</title>")
	b.WriteString("<style>" + htmlCSS + "</style></head><body><div class=\"wrap\">")

	b.WriteString("<h1>Iris scan report</h1><div class=\"meta\">")
	b.WriteString("<span><code>" + esc(e.Target) + "</code></span>")
	b.WriteString("<span>scanner: " + esc(e.Scanner) + "</span>")
	if !e.Time.IsZero() {
		b.WriteString("<span>" + esc(e.Time.UTC().Format("2006-01-02 15:04:05 UTC")) + "</span>")
	}
	b.WriteString("<span>" + fmt.Sprintf("%.2fs", e.DurationS) + "</span>")
	ver := doc.IrisVersion
	if ver == "" {
		ver = e.Version
	}
	if ver != "" {
		b.WriteString("<span>iris " + esc(ver) + "</span>")
	}
	b.WriteString("<span>scan " + esc(e.ID) + "</span></div>")

	// Severity summary.
	if len(e.SeverityCounts) > 0 {
		b.WriteString("<div>")
		for _, k := range []string{"critical", "high", "medium", "low", "info"} {
			if v := e.SeverityCounts[k]; v > 0 {
				b.WriteString("<span class=\"chip " + k + "\">" + strings.ToUpper(k) + " " + strconv.Itoa(v) + "</span>")
			}
		}
		b.WriteString("</div>")
	}

	if len(findings) == 0 {
		b.WriteString("<div class=\"empty\">No findings — clean scan.</div></div>")
	} else {
		b.WriteString("<h2>Findings (" + strconv.Itoa(len(findings)) + ")</h2>")
		b.WriteString("<table><thead><tr><th style=\"width:88px\">Severity</th><th style=\"width:230px\">Rule</th><th>Finding</th><th style=\"width:150px\">Category</th></tr></thead><tbody>")
		for _, item := range findings {
			f := item.f
			sev := strings.ToUpper(f.Severity)
			if sev == "" {
				sev = "INFO"
			}
			cls := strings.ToLower(sev)
			b.WriteString("<tr>")
			b.WriteString("<td><span class=\"chip " + esc(cls) + "\" style=\"margin:0\">" + esc(sev) + "</span></td>")
			b.WriteString("<td class=\"rule\">" + esc(f.RuleID) + "</td>")
			b.WriteString("<td>" + esc(f.Title))
			if f.Description != "" {
				b.WriteString("<div class=\"desc\">" + esc(f.Description) + "</div>")
			}
			if f.Fix != "" {
				b.WriteString("<div class=\"fix\">Fix: " + esc(f.Fix) + "</div>")
			}
			if f.Code != "" {
				b.WriteString("<pre>" + esc(f.Code) + "</pre>")
			}
			b.WriteString("</td>")
			b.WriteString("<td class=\"rule\">" + esc(f.Category) + "</td>")
			b.WriteString("</tr>")
		}
		b.WriteString("</tbody></table></div>")
	}

	b.WriteString("<footer>Generated by Iris on " + esc(time.Now().UTC().Format(time.RFC3339)) +
		" · dashboard.pixelcity.dev · scan " + esc(e.ID) + "</footer>")
	b.WriteString("</div></body></html>")
	return []byte(b.String())
}
