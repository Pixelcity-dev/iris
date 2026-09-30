package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"
)

func toolsMux(t *testing.T, srv *server) *http.ServeMux {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/v1/scans/findings", srv.handleFindings)
	mux.HandleFunc("GET /api/v1/scans/compare", srv.handleCompare)
	mux.HandleFunc("DELETE /api/v1/scans/{id}", srv.handleScanDelete)
	mux.HandleFunc("GET /api/v1/tools/search", srv.authEither(srv.handleSearch))
	return mux
}

func toolsServer(t *testing.T) (*server, *http.ServeMux) {
	t.Helper()
	srv := &server{
		cfg:    config{SessionSecret: []byte("test-secret-0123456789abcdef-test")},
		scans:  newScanStore(filepath.Join(t.TempDir(), "scans.jsonl")),
		tokens: newTokenStore(""),
	}
	return srv, toolsMux(t, srv)
}

func seedReportScan(t *testing.T, srv *server, id, sub, user, report string) {
	t.Helper()
	e := scanEntry{
		ID: id, Sub: sub, Username: user, Email: user + "@x.dev",
		Time: time.Now().UTC(), Scanner: "sast", Target: "repo://app",
		Findings: 2, DurationS: 0.4,
		SeverityCounts: map[string]int{"high": 1, "low": 1},
	}
	if err := srv.scans.saveReport(id, []byte(report)); err != nil {
		t.Fatal(err)
	}
	e.ReportBytes = len(report)
	if err := srv.scans.append(e); err != nil {
		t.Fatal(err)
	}
}

func doReq(t *testing.T, mux *http.ServeMux, method, target, cookie string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, target, nil)
	if cookie != "" {
		req.AddCookie(&http.Cookie{Name: "ds_session", Value: cookie})
	}
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	return rec
}

func TestFindingsExplorerFilters(t *testing.T) {
	srv, mux := toolsServer(t)
	report := `{"iris_version":"1.2.0","results":[{"scanner":"sast","target":{"uri":"repo://app"},"findings":[
		{"rule_id":"sql-injection","severity":"high","title":"SQL injection","file":"db.go","line":10,"fingerprint":"fp1"},
		{"rule_id":"weak-hash","severity":"low","title":"MD5 used","file":"crypto.go","line":3,"fingerprint":"fp2"}]}]}`
	seedReportScan(t, srv, "f-scan", "u-owner", "alice", report)

	cookie := cookieFor(t, srv, "u-owner", "alice", nil)

	// All findings.
	rec := doReq(t, mux, "GET", "/api/v1/scans/findings", cookie)
	if rec.Code != 200 {
		t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
	}
	var resp struct {
		Findings []findingsRow `json:"findings"`
		Total    int           `json:"total"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if len(resp.Findings) != 2 {
		t.Fatalf("want 2 findings, got %d", len(resp.Findings))
	}

	// Severity filter.
	rec = doReq(t, mux, "GET", "/api/v1/scans/findings?severity=high", cookie)
	json.Unmarshal(rec.Body.Bytes(), &resp)
	if len(resp.Findings) != 1 || resp.Findings[0].RuleID != "sql-injection" {
		t.Fatalf("severity filter failed: %+v", resp.Findings)
	}

	// Text search over file/title.
	rec = doReq(t, mux, "GET", "/api/v1/scans/findings?q=crypto", cookie)
	json.Unmarshal(rec.Body.Bytes(), &resp)
	if len(resp.Findings) != 1 || resp.Findings[0].RuleID != "weak-hash" {
		t.Fatalf("q filter failed: %+v", resp.Findings)
	}

	// Rule filter.
	rec = doReq(t, mux, "GET", "/api/v1/scans/findings?rule=weak-hash", cookie)
	json.Unmarshal(rec.Body.Bytes(), &resp)
	if len(resp.Findings) != 1 {
		t.Fatalf("rule filter failed: %+v", resp.Findings)
	}

	// Anonymous rejected.
	rec = doReq(t, mux, "GET", "/api/v1/scans/findings", "")
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("anon status %d", rec.Code)
	}
}

func TestCompareFindings(t *testing.T) {
	srv, mux := toolsServer(t)
	shared := `{"rule_id":"shared","severity":"medium","title":"Shared","file":"a.go","fingerprint":"fp-shared"}`
	old := `{"iris_version":"1.0.0","results":[{"scanner":"sast","findings":[` + shared + `,
		{"rule_id":"gone","severity":"high","title":"Fixed later","file":"b.go","fingerprint":"fp-gone"}]}]}`
	newR := `{"iris_version":"1.2.0","results":[{"scanner":"sast","findings":[` + shared + `,
		{"rule_id":"fresh","severity":"critical","title":"New issue","file":"c.go","fingerprint":"fp-fresh"}]}]}`
	seedReportScan(t, srv, "cmp-old", "u-owner", "alice", old)
	seedReportScan(t, srv, "cmp-new", "u-owner", "alice", newR)

	cookie := cookieFor(t, srv, "u-owner", "alice", nil)
	rec := doReq(t, mux, "GET", "/api/v1/scans/compare?a=cmp-old&b=cmp-new", cookie)
	if rec.Code != 200 {
		t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
	}
	var resp struct {
		Added    []findingsRow  `json:"added"`
		Resolved []findingsRow  `json:"resolved"`
		Summary  map[string]int `json:"summary"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.Summary["added"] != 1 || resp.Summary["resolved"] != 1 || resp.Summary["unchanged"] != 1 {
		t.Fatalf("summary %+v (added=%d resolved=%d)", resp.Summary, len(resp.Added), len(resp.Resolved))
	}
	if resp.Added[0].RuleID != "fresh" || resp.Resolved[0].RuleID != "gone" {
		t.Fatalf("diff wrong: added=%s resolved=%s", resp.Added[0].RuleID, resp.Resolved[0].RuleID)
	}

	// Missing params.
	rec = doReq(t, mux, "GET", "/api/v1/scans/compare?a=cmp-old", cookie)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("missing b status %d", rec.Code)
	}
}

func TestScanDeleteOwnership(t *testing.T) {
	srv, mux := toolsServer(t)
	seedReportScan(t, srv, "del-me", "u-owner", "alice", `{"iris_version":"1.0","results":[]}`)
	seedReportScan(t, srv, "del-keep", "u-other", "bob", `{"iris_version":"1.0","results":[]}`)

	owner := cookieFor(t, srv, "u-owner", "alice", nil)
	other := cookieFor(t, srv, "u-other", "bob", nil)
	admin := cookieFor(t, srv, "u-admin", "dave", []string{"iris-admins"})

	// Non-owner cannot delete.
	rec := doReq(t, mux, "DELETE", "/api/v1/scans/del-me", other)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("non-owner status %d", rec.Code)
	}
	// Owner deletes own scan.
	rec = doReq(t, mux, "DELETE", "/api/v1/scans/del-me", owner)
	if rec.Code != 200 {
		t.Fatalf("owner delete status %d: %s", rec.Code, rec.Body.String())
	}
	if _, ok := srv.scans.get("del-me"); ok {
		t.Fatal("scan still present after delete")
	}
	// Admin deletes anyone's scan.
	rec = doReq(t, mux, "DELETE", "/api/v1/scans/del-keep", admin)
	if rec.Code != 200 {
		t.Fatalf("admin delete status %d", rec.Code)
	}
	// Unknown id 404.
	rec = doReq(t, mux, "DELETE", "/api/v1/scans/nope", owner)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("unknown delete status %d", rec.Code)
	}
}

func TestSearchProxyConfigured(t *testing.T) {
	// Unconfigured instance → 503, never SSRF.
	srv, mux := toolsServer(t)
	t.Setenv("SEARXNG_BASE", "")
	cookie := cookieFor(t, srv, "u-owner", "alice", nil)
	rec := doReq(t, mux, "GET", "/api/v1/tools/search?q=test", cookie)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("unconfigured status %d", rec.Code)
	}
	// Missing q → 400 once configured.
	t.Setenv("SEARXNG_BASE", "http://searxng.invalid")
	rec = doReq(t, mux, "GET", "/api/v1/tools/search", cookie)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("missing q status %d", rec.Code)
	}
	// Anonymous → 401.
	rec = doReq(t, mux, "GET", "/api/v1/tools/search?q=x", "")
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("anon status %d", rec.Code)
	}
}

func TestListMatchingIgnoresCorruptLines(t *testing.T) {
	srv, _ := toolsServer(t)
	seedReportScan(t, srv, "lm-1", "u-owner", "alice", `{"results":[]}`)
	entries := srv.scans.listMatching(func(e *scanEntry) bool { return e.Sub == "u-owner" }, 10)
	if len(entries) != 1 || entries[0].ID != "lm-1" {
		t.Fatalf("listMatching got %d", len(entries))
	}
}
