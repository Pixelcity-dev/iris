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

func detailMux(t *testing.T, srv *server) *http.ServeMux {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/v1/scans/{id}", srv.handleScanGet)
	return mux
}

func seedScan(t *testing.T, srv *server, id, sub, user string, withReport bool) {
	t.Helper()
	e := scanEntry{
		ID: id, Sub: sub, Username: user, Email: user + "@x.dev",
		Time: time.Now().UTC(), Scanner: "webscan",
		Target: "https://example.com", Findings: 3, DurationS: 1.5,
		SeverityCounts: map[string]int{"high": 1, "low": 2},
	}
	if withReport {
		report := []byte(`{"iris_version":"1.2.0","results":[{"scanner":"webscan","findings":[]}]}`)
		if err := srv.scans.saveReport(id, report); err != nil {
			t.Fatal(err)
		}
		e.ReportBytes = len(report)
	}
	if err := srv.scans.append(e); err != nil {
		t.Fatal(err)
	}
}

func cookieFor(t *testing.T, srv *server, sub, user string, groups []string) string {
	t.Helper()
	s := &session{Sub: sub, Username: user, Email: user + "@x.dev",
		Groups: groups, Exp: time.Now().Add(time.Hour).Unix()}
	val, err := signSession(s, srv.cfg.SessionSecret)
	if err != nil {
		t.Fatal(err)
	}
	return val
}

func TestScanDetailOwnerAdminAnon(t *testing.T) {
	secret := []byte("test-secret-0123456789abcdef-test")
	srv := &server{
		cfg:   config{SessionSecret: secret},
		scans: newScanStore(filepath.Join(t.TempDir(), "scans.jsonl")),
	}
	seedScan(t, srv, "scan-owner", "u-owner", "alice", true)
	seedScan(t, srv, "scan-other", "u-other", "bob", false)
	mux := detailMux(t, srv)

	get := func(id, cookie string) *httptest.ResponseRecorder {
		req := httptest.NewRequest("GET", "/api/v1/scans/"+id, nil)
		if cookie != "" {
			req.AddCookie(&http.Cookie{Name: "ds_session", Value: cookie})
		}
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		return rec
	}
	owner := cookieFor(t, srv, "u-owner", "alice", nil)
	other := cookieFor(t, srv, "u-third", "carol", nil)
	admin := cookieFor(t, srv, "u-admin", "dave", []string{"iris-admins"})

	// Owner sees own scan + embedded report.
	rec := get("scan-owner", owner)
	if rec.Code != 200 {
		t.Fatalf("owner: %d %s", rec.Code, rec.Body.String())
	}
	var resp struct {
		Entry  scanEntry       `json:"entry"`
		Report json.RawMessage `json:"report"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.Entry.ID != "scan-owner" || resp.Entry.ReportBytes == 0 {
		t.Fatalf("entry wrong: %+v", resp.Entry)
	}
	if !strings.Contains(string(resp.Report), "webscan") {
		t.Fatalf("report not embedded: %s", string(resp.Report))
	}

	// Admin sees someone else's scan.
	if rec := get("scan-owner", admin); rec.Code != 200 {
		t.Fatalf("admin: %d", rec.Code)
	}

	// Third party forbidden.
	if rec := get("scan-owner", other); rec.Code != 403 {
		t.Fatalf("third party: %d", rec.Code)
	}

	// Anonymous unauthorized.
	if rec := get("scan-owner", ""); rec.Code != 401 {
		t.Fatalf("anon: %d", rec.Code)
	}

	// Unknown id 404.
	if rec := get("nope", owner); rec.Code != 404 {
		t.Fatalf("missing: %d", rec.Code)
	}

	// Scan without stored report → 200 with report null.
	rec = get("scan-other", cookieFor(t, srv, "u-other", "bob", nil))
	if rec.Code != 200 {
		t.Fatalf("no-report owner: %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), `"report":null`) {
		t.Fatalf("want report null, got %s", rec.Body.String())
	}
}

func TestReportRoundTripAndSweep(t *testing.T) {
	s := testStore(t)
	report := []byte(`{"iris_version":"1.2.0","results":[]}`)
	if err := s.saveReport("r1", report); err != nil {
		t.Fatal(err)
	}
	// Metadata for r1 so it survives the sweep.
	e1 := scanEntry{ID: "r1", Sub: "u1", Time: time.Now().UTC(), Scanner: "s", Target: "https://x.test"}
	if err := sanitizeScanInput(&e1); err != nil {
		t.Fatal(err)
	}
	e1.ID = "r1"
	if err := s.append(e1); err != nil {
		t.Fatal(err)
	}
	got, err := s.loadReport("r1")
	if err != nil || string(got) != string(report) {
		t.Fatalf("roundtrip: %v %s", err, got)
	}
	if _, err := s.loadReport("missing"); err != errReportMissing {
		t.Fatalf("want errReportMissing, got %v", err)
	}

	// Orphan report (no metadata) is swept on the next append.
	if err := s.saveReport("orphan-xyz", report); err != nil {
		t.Fatal(err)
	}
	e := scanEntry{Sub: "u1", Time: time.Now().UTC(), Scanner: "s", Target: "https://x.test"}
	if err := sanitizeScanInput(&e); err != nil {
		t.Fatal(err)
	}
	e.ID = "keep-me"
	if err := s.append(e); err != nil {
		t.Fatal(err)
	}
	if _, err := s.loadReport("orphan-xyz"); err != errReportMissing {
		t.Fatalf("orphan not swept: %v", err)
	}
	if _, err := s.loadReport("r1"); err != nil {
		t.Fatalf("metadata-backed report wrongly swept: %v", err)
	}
}

func TestSanitizeScrubsReportMeta(t *testing.T) {
	e := scanEntry{
		Target: "https://x.test", Scanner: "webscan",
		ReportBytes: 999, ReportOmitted: true, Version: strings.Repeat("v", 100),
		SeverityCounts: map[string]int{"high": 1},
	}
	if err := sanitizeScanInput(&e); err != nil {
		t.Fatal(err)
	}
	if e.ReportBytes != 0 || e.ReportOmitted {
		t.Fatalf("report meta not scrubbed: %d %v", e.ReportBytes, e.ReportOmitted)
	}
	if len(e.Version) != maxVersionLen {
		t.Fatalf("version not capped: %q", e.Version)
	}

	e = scanEntry{Target: "https://x.test", SeverityCounts: map[string]int{"high": -1}}
	if err := sanitizeScanInput(&e); err == nil {
		t.Fatal("negative count accepted")
	}
	counts := map[string]int{}
	for i := 0; i < 13; i++ {
		counts[string(rune('a'+i))] = 1
	}
	e = scanEntry{Target: "https://x.test", SeverityCounts: counts}
	if err := sanitizeScanInput(&e); err == nil {
		t.Fatal("excess severity buckets accepted")
	}
}
