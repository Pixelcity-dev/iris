package main

import (
	"encoding/json"
	"html"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const fixtureReport = `{
  "iris_version": "1.2.0",
  "start_time": "2026-09-30T14:11:39Z",
  "end_time": "2026-09-30T14:11:40Z",
  "results": [
    {
      "scanner": "webscan",
      "target": {"kind": "url", "uri": "https://example.com"},
      "findings": [
        {"rule_id": "r-hi", "severity": "HIGH", "title": "Missing HSTS",
         "description": "No strict-transport-security header",
         "category": "transport", "fix": "Add the header"},
        {"rule_id": "r-hi", "severity": "HIGH", "title": "Duplicate rule id",
         "category": "transport"},
        {"rule_id": "r-info", "severity": "INFO", "title": "Server disclosed",
         "category": "info"}
      ]
    }
  ]
}`

func fixtureEntry() *scanEntry {
	return &scanEntry{
		ID: "scan-1", Sub: "u1", Username: "alice",
		Time: time.Now().UTC(), Scanner: "webscan",
		Target: "https://fallback.test", Findings: 3, DurationS: 1,
		SeverityCounts: map[string]int{"high": 2, "info": 1},
		Version:        "1.2.0",
	}
}

func TestSarifFromReport(t *testing.T) {
	doc, err := parseReport([]byte(fixtureReport))
	if err != nil {
		t.Fatal(err)
	}
	out, err := sarifFromReport(fixtureEntry(), doc)
	if err != nil {
		t.Fatal(err)
	}
	var sarif struct {
		Version string `json:"version"`
		Runs    []struct {
			Tool struct {
				Driver struct {
					Name    string `json:"name"`
					Version string `json:"version"`
					Rules   []struct {
						ID                   string `json:"id"`
						DefaultConfiguration struct {
							Level string `json:"level"`
						} `json:"defaultConfiguration"`
					} `json:"rules"`
				} `json:"driver"`
			} `json:"tool"`
			Results []struct {
				RuleID  string `json:"ruleId"`
				Level   string `json:"level"`
				Message struct {
					Text string `json:"text"`
				} `json:"message"`
				Locations []struct {
					PhysicalLocation struct {
						ArtifactLocation struct {
							URI string `json:"uri"`
						} `json:"artifactLocation"`
					} `json:"physicalLocation"`
				} `json:"locations"`
			} `json:"results"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(out, &sarif); err != nil {
		t.Fatalf("sarif not valid JSON: %v", err)
	}
	if sarif.Version != "2.1.0" {
		t.Fatalf("version: %s", sarif.Version)
	}
	if len(sarif.Runs) != 1 || sarif.Runs[0].Tool.Driver.Name != "Iris" {
		t.Fatalf("run/tool wrong: %+v", sarif.Runs)
	}
	if sarif.Runs[0].Tool.Driver.Version != "1.2.0" {
		t.Fatalf("tool version: %s", sarif.Runs[0].Tool.Driver.Version)
	}
	// Duplicate rule ids collapse into one rule entry.
	if len(sarif.Runs[0].Tool.Driver.Rules) != 2 {
		t.Fatalf("want 2 rules, got %d", len(sarif.Runs[0].Tool.Driver.Rules))
	}
	if len(sarif.Runs[0].Results) != 3 {
		t.Fatalf("want 3 results, got %d", len(sarif.Runs[0].Results))
	}
	// Level mapping: HIGH -> error, INFO -> note.
	if sarif.Runs[0].Results[0].Level != "error" || sarif.Runs[0].Results[2].Level != "note" {
		t.Fatalf("levels: %s %s", sarif.Runs[0].Results[0].Level, sarif.Runs[0].Results[2].Level)
	}
	// URI comes from the report's target.
	if sarif.Runs[0].Results[0].Locations[0].PhysicalLocation.ArtifactLocation.URI != "https://example.com" {
		t.Fatalf("uri: %s", sarif.Runs[0].Results[0].Locations[0].PhysicalLocation.ArtifactLocation.URI)
	}
	// Message carries the description.
	if !strings.Contains(sarif.Runs[0].Results[0].Message.Text, "strict-transport-security") {
		t.Fatalf("message: %s", sarif.Runs[0].Results[0].Message.Text)
	}
}

func TestSarifURIFallback(t *testing.T) {
	doc, err := parseReport([]byte(`{"results":[{"findings":[{"rule_id":"x","severity":"LOW","title":"t"}]}]}`))
	if err != nil {
		t.Fatal(err)
	}
	out, _ := sarifFromReport(fixtureEntry(), doc)
	if !strings.Contains(string(out), "https://fallback.test") {
		t.Fatal("target fallback missing from SARIF")
	}
}

func TestHtmlFromReportEscapes(t *testing.T) {
	malicious := `{"iris_version":"1.2.0","results":[{"target":{"uri":"https://evil.test/?a=<x>"},
	  "findings":[{"rule_id":"r1","severity":"CRITICAL","title":"<script>alert(1)</script>",
	  "description":"<img src=x onerror=alert(2)>","fix":"</style><b>bold</b>","code":"if a < b {}"}]}]}`
	doc, err := parseReport([]byte(malicious))
	if err != nil {
		t.Fatal(err)
	}
	out := string(htmlFromReport(fixtureEntry(), doc))

	if strings.Contains(out, "<script>alert(1)</script>") {
		t.Fatal("unescaped script tag in HTML report")
	}
	if strings.Contains(out, "<img src=x onerror=") {
		t.Fatal("unescaped img tag in HTML report")
	}
	if !strings.Contains(out, html.EscapeString("<script>alert(1)</script>")) {
		t.Fatal("escaped title missing")
	}
	if !strings.Contains(out, "CRITICAL") || !strings.Contains(out, "Findings (1)") {
		t.Fatalf("structure missing: %s", out[:200])
	}
	if strings.Contains(out, "</style><b>") || !strings.Contains(out, "&lt;/style&gt;") {
		t.Fatal("fix text not escaped")
	}
}

func TestScanExportHandler(t *testing.T) {
	secret := []byte("test-secret-0123456789abcdef-test")
	srv := &server{
		cfg:   config{SessionSecret: secret},
		scans: newScanStore(filepath.Join(t.TempDir(), "scans.jsonl")),
	}
	seedScan(t, srv, "exp-full", "u-owner", "alice", true)
	seedScan(t, srv, "exp-bare", "u-owner", "alice", false)
	mux := detailMux(t, srv)

	get := func(url, cookie string) *httptest.ResponseRecorder {
		req := httptest.NewRequest("GET", url, nil)
		if cookie != "" {
			req.AddCookie(&http.Cookie{Name: "ds_session", Value: cookie})
		}
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		return rec
	}
	owner := cookieFor(t, srv, "u-owner", "alice", nil)
	other := cookieFor(t, srv, "u-third", "carol", nil)

	// SARIF export: 200, attachment, valid SARIF.
	rec := get("/api/v1/scans/exp-full?format=sarif", owner)
	if rec.Code != 200 {
		t.Fatalf("sarif: %d %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Header().Get("Content-Disposition"), ".sarif") {
		t.Fatalf("disposition: %q", rec.Header().Get("Content-Disposition"))
	}
	var probe map[string]interface{}
	if err := json.Unmarshal(rec.Body.Bytes(), &probe); err != nil || probe["version"] != "2.1.0" {
		t.Fatalf("not sarif: %v %v", err, probe["version"])
	}

	// HTML export: inline, escaped content.
	rec = get("/api/v1/scans/exp-full?format=html", owner)
	if rec.Code != 200 || !strings.Contains(rec.Header().Get("Content-Type"), "text/html") {
		t.Fatalf("html: %d %s", rec.Code, rec.Header().Get("Content-Type"))
	}
	if strings.Contains(rec.Header().Get("Content-Disposition"), "attachment") {
		t.Fatal("html should render inline")
	}

	// JSON export: attachment.
	rec = get("/api/v1/scans/exp-full?format=json", owner)
	if rec.Code != 200 || !strings.Contains(rec.Header().Get("Content-Disposition"), ".json") {
		t.Fatalf("json: %d %q", rec.Code, rec.Header().Get("Content-Disposition"))
	}

	// No stored report → 404 on export, but plain detail still 200.
	if rec := get("/api/v1/scans/exp-bare?format=sarif", owner); rec.Code != 404 {
		t.Fatalf("bare export: %d", rec.Code)
	}
	if rec := get("/api/v1/scans/exp-bare", owner); rec.Code != 200 {
		t.Fatalf("bare detail: %d", rec.Code)
	}

	// Authorization still applies to exports.
	if rec := get("/api/v1/scans/exp-full?format=sarif", other); rec.Code != 403 {
		t.Fatalf("third party: %d", rec.Code)
	}
	if rec := get("/api/v1/scans/exp-full?format=sarif", ""); rec.Code != 401 {
		t.Fatalf("anon: %d", rec.Code)
	}

	// Unknown format → 400.
	if rec := get("/api/v1/scans/exp-full?format=pdf", owner); rec.Code != 400 {
		t.Fatalf("bad format: %d", rec.Code)
	}
}
