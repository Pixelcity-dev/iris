package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
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

func powerMux(t *testing.T, srv *server) *http.ServeMux {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/v1/stats", srv.handleStats)
	mux.HandleFunc("POST /api/v1/scans/bulk-delete", srv.handleBulkDelete)
	mux.HandleFunc("POST /api/v1/scans/{id}/share", srv.handleShareCreate)
	mux.HandleFunc("DELETE /api/v1/scans/{id}/share", srv.handleShareRevoke)
	mux.HandleFunc("GET /api/v1/scans/findings", srv.handleFindings)
	mux.HandleFunc("GET /api/v1/admin/system", srv.requireAdmin(srv.handleAdminSystem))
	mux.HandleFunc("GET /s/{token}", srv.handleShareView)
	return mux
}

func powerServer(t *testing.T) (*server, *http.ServeMux) {
	t.Helper()
	srv := &server{
		cfg:    config{SessionSecret: []byte("test-secret-0123456789abcdef-test")},
		scans:  newScanStore(filepath.Join(t.TempDir(), "scans.jsonl")),
		tokens: newTokenStore(""),
		shares: newShareStore(""),
	}
	return srv, powerMux(t, srv)
}

const statsReport = `{"iris_version":"1.2.0","results":[{"scanner":"sast","findings":[
	{"rule_id":"sql-injection","severity":"high","title":"SQLi","file":"a.go"},
	{"rule_id":"sql-injection","severity":"high","title":"SQLi","file":"b.go"},
	{"rule_id":"weak-hash","severity":"low","title":"MD5","file":"c.go"}]}]}`

func TestStatsAggregate(t *testing.T) {
	srv, mux := powerServer(t)
	seedReportScan(t, srv, "st-1", "u-owner", "alice", statsReport)
	seedReportScan(t, srv, "st-2", "u-other", "bob", statsReport)

	cookie := cookieFor(t, srv, "u-owner", "alice", nil)
	rec := doReq(t, mux, "GET", "/api/v1/stats", cookie)
	if rec.Code != 200 {
		t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
	}
	var resp struct {
		Scans    int            `json:"scans"`
		Findings int            `json:"findings"`
		Severity map[string]int `json:"severity"`
		TopRules []statsRule    `json:"top_rules"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.Scans != 1 || resp.Findings != 3 {
		t.Fatalf("want 1 scan/3 findings, got %d/%d", resp.Scans, resp.Findings)
	}
	if resp.Severity["high"] != 2 || resp.Severity["low"] != 1 {
		t.Fatalf("severity %+v", resp.Severity)
	}
	if len(resp.TopRules) == 0 || resp.TopRules[0].RuleID != "sql-injection" || resp.TopRules[0].Count != 2 {
		t.Fatalf("top rules %+v", resp.TopRules)
	}

	// Admin "*" sees everyone's scans.
	admin := cookieFor(t, srv, "u-admin", "dave", []string{"iris-admins"})
	rec = doReq(t, mux, "GET", "/api/v1/stats?user=*", admin)
	json.Unmarshal(rec.Body.Bytes(), &resp)
	if resp.Scans != 2 {
		t.Fatalf("admin all users scans=%d", resp.Scans)
	}
	// Non-admin cannot use ?user=.
	rec = doReq(t, mux, "GET", "/api/v1/stats?user=*", cookie)
	json.Unmarshal(rec.Body.Bytes(), &resp)
	if resp.Scans != 1 {
		t.Fatalf("non-admin ?user=* should stay scoped, got %d", resp.Scans)
	}
}

func TestFindingsCSVExport(t *testing.T) {
	srv, mux := powerServer(t)
	seedReportScan(t, srv, "csv-1", "u-owner", "alice", statsReport)
	cookie := cookieFor(t, srv, "u-owner", "alice", nil)
	rec := doReq(t, mux, "GET", "/api/v1/scans/findings?format=csv", cookie)
	if rec.Code != 200 {
		t.Fatalf("status %d", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/csv") {
		t.Fatalf("content-type %q", ct)
	}
	body := rec.Body.String()
	if !strings.HasPrefix(body, "severity,rule_id,") || !strings.Contains(body, "sql-injection") {
		t.Fatalf("csv body %q", body)
	}
	if n := strings.Count(body, "\n"); n != 4 { // header + 3 findings
		t.Fatalf("csv lines %d", n)
	}
}

func TestBulkDeleteOwnership(t *testing.T) {
	srv, mux := powerServer(t)
	seedReportScan(t, srv, "bd-mine", "u-owner", "alice", statsReport)
	seedReportScan(t, srv, "bd-yours", "u-other", "bob", statsReport)

	cookie := cookieFor(t, srv, "u-owner", "alice", nil)
	body := `{"ids":["bd-mine","bd-yours","missing"]}`
	req := httptest.NewRequest("POST", "/api/v1/scans/bulk-delete", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(&http.Cookie{Name: "ds_session", Value: cookie})
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != 200 {
		t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
	}
	var resp struct {
		DeletedCount int      `json:"deleted_count"`
		Failed       []string `json:"failed"`
	}
	json.Unmarshal(rec.Body.Bytes(), &resp)
	if resp.DeletedCount != 1 || len(resp.Failed) != 2 {
		t.Fatalf("resp %+v", resp)
	}
	if _, ok := srv.scans.get("bd-mine"); ok {
		t.Fatal("own scan should be deleted")
	}
	if _, ok := srv.scans.get("bd-yours"); !ok {
		t.Fatal("other user's scan must survive")
	}
	// Bad body.
	req = httptest.NewRequest("POST", "/api/v1/scans/bulk-delete", strings.NewReader(`{}`))
	req.AddCookie(&http.Cookie{Name: "ds_session", Value: cookie})
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("empty ids status %d", rec.Code)
	}
}

func TestShareLifecycle(t *testing.T) {
	srv, mux := powerServer(t)
	seedReportScan(t, srv, "sh-1", "u-owner", "alice", statsReport)
	owner := cookieFor(t, srv, "u-owner", "alice", nil)
	other := cookieFor(t, srv, "u-other", "bob", nil)

	// Create.
	rec := doReq(t, mux, "POST", "/api/v1/scans/sh-1/share", owner)
	if rec.Code != 200 {
		t.Fatalf("create status %d: %s", rec.Code, rec.Body.String())
	}
	var created struct {
		Token string `json:"token"`
		URL   string `json:"url"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &created); err != nil || created.Token == "" {
		t.Fatalf("create resp %s", rec.Body.String())
	}

	// Public view works without auth.
	rec = doReq(t, mux, "GET", "/s/"+created.Token, "")
	if rec.Code != 200 {
		t.Fatalf("public view status %d: %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "sql-injection") {
		t.Fatal("public view missing findings")
	}
	if !strings.Contains(rec.Body.String(), "noindex") {
		t.Fatal("public view should be noindex")
	}

	// Forged token rejected.
	rec = doReq(t, mux, "GET", "/s/"+created.Token+"x", "")
	if rec.Code != http.StatusNotFound {
		t.Fatalf("forged token status %d", rec.Code)
	}

	// Non-owner cannot create/revoke.
	rec = doReq(t, mux, "POST", "/api/v1/scans/sh-1/share", other)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("non-owner create status %d", rec.Code)
	}

	// Revoke kills the public view.
	rec = doReq(t, mux, "DELETE", "/api/v1/scans/sh-1/share", owner)
	if rec.Code != 200 {
		t.Fatalf("revoke status %d", rec.Code)
	}
	rec = doReq(t, mux, "GET", "/s/"+created.Token, "")
	if rec.Code != http.StatusNotFound {
		t.Fatalf("revoked view status %d", rec.Code)
	}
}

func TestAdminSystem(t *testing.T) {
	srv, mux := powerServer(t)
	admin := cookieFor(t, srv, "u-admin", "dave", []string{"iris-admins"})
	plain := cookieFor(t, srv, "u-a", "alice", nil)

	rec := doReq(t, mux, "GET", "/api/v1/admin/system", "")
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("anon %d", rec.Code)
	}
	rec = doReq(t, mux, "GET", "/api/v1/admin/system", plain)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("non-admin %d", rec.Code)
	}
	rec = doReq(t, mux, "GET", "/api/v1/admin/system", admin)
	if rec.Code != 200 {
		t.Fatalf("admin %d", rec.Code)
	}
	var d map[string]interface{}
	if err := json.Unmarshal(rec.Body.Bytes(), &d); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"version", "uptime_seconds", "storage", "scans_total", "searxng_configured"} {
		if _, ok := d[k]; !ok {
			t.Fatalf("missing %s in %+v", k, d)
		}
	}
}
