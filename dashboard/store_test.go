package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func testStore(t *testing.T) *scanStore {
	t.Helper()
	return newScanStore(filepath.Join(t.TempDir(), "scans.jsonl"))
}

func TestStoreAppendListRoundTrip(t *testing.T) {
	s := testStore(t)
	for i := 0; i < 5; i++ {
		e := scanEntry{Sub: "u1", Username: "alice", Time: time.Now().UTC(),
			Scanner: "webscan", Target: fmt.Sprintf("https://x.test/%d", i), Findings: i}
		if err := sanitizeScanInput(&e); err != nil {
			t.Fatal(err)
		}
		e.ID = fmt.Sprintf("id-%d", i)
		if err := s.append(e); err != nil {
			t.Fatal(err)
		}
	}
	got := s.list("u1", 10)
	if len(got) != 5 {
		t.Fatalf("want 5, got %d", len(got))
	}
	// Newest first.
	if got[0].Target != "https://x.test/4" {
		t.Fatalf("wrong order: %+v", got[0])
	}
	if got[4].Target != "https://x.test/0" {
		t.Fatalf("wrong order tail: %+v", got[4])
	}
	if got := s.list("nobody", 10); len(got) != 0 {
		t.Fatalf("cross-user leak: %d", len(got))
	}
}

func TestStorePerUserCap(t *testing.T) {
	s := testStore(t)
	for i := 0; i < maxScansPerUser+50; i++ {
		e := scanEntry{Sub: "u1", Time: time.Now().UTC(), Scanner: "s",
			Target: fmt.Sprintf("https://x.test/%d", i)}
		if err := sanitizeScanInput(&e); err != nil {
			t.Fatal(err)
		}
		e.ID = fmt.Sprintf("id-%d", i)
		if err := s.append(e); err != nil {
			t.Fatal(err)
		}
	}
	if got := s.list("u1", 500); len(got) != 500 {
		t.Fatalf("want page of 500, got %d", len(got))
	}
	// Bypass the 500 read cap to verify the full per-user store cap.
	lines, err := readLines(s.path)
	if err != nil {
		t.Fatal(err)
	}
	own := 0
	for _, l := range lines {
		var e scanEntry
		if json.Unmarshal([]byte(l), &e) == nil && e.Sub == "u1" {
			own++
		}
	}
	if own != maxScansPerUser {
		t.Fatalf("want stored cap %d, got %d", maxScansPerUser, own)
	}
	// Other users unaffected.
	e := scanEntry{Sub: "u2", Time: time.Now().UTC(), Scanner: "s", Target: "https://y.test"}
	if err := sanitizeScanInput(&e); err != nil {
		t.Fatal(err)
	}
	e.ID = "u2-1"
	if err := s.append(e); err != nil {
		t.Fatal(err)
	}
	if got := s.list("u2", 10); len(got) != 1 {
		t.Fatalf("u2 lost entries: %d", len(got))
	}
}

func TestSanitizeRejects(t *testing.T) {
	cases := []scanEntry{
		{Target: ""},                                                // missing
		{Target: "notaurl"},                                         // no scheme
		{Target: "ftp://x.test"},                                    // bad scheme
		{Target: "https://x.test", Findings: -1},                    // negative
		{Target: "https://x.test", DurationS: 999999},               // too long
		{Target: "https://x.test", Time: time.Now().Add(time.Hour)}, // future
	}
	for i, c := range cases {
		c.Scanner = "webscan"
		if err := sanitizeScanInput(&c); err == nil {
			t.Fatalf("case %d accepted invalid input", i)
		}
	}
	ok := scanEntry{Scanner: "", Target: "https://x.test"}
	if err := sanitizeScanInput(&ok); err != nil {
		t.Fatalf("valid rejected: %v", err)
	}
	if ok.Scanner != "webscan" || ok.Time.IsZero() {
		t.Fatalf("defaults not applied: %+v", ok)
	}
}

func TestIsAdminGate(t *testing.T) {
	t.Setenv("ADMIN_GROUPS", "iris-admins,ops")
	if !isAdmin(&session{Groups: []string{"users", "iris-admins"}}) {
		t.Fatal("group member rejected")
	}
	if !isAdmin(&session{Roles: []string{"ops"}}) {
		t.Fatal("role member rejected")
	}
	if isAdmin(&session{Groups: []string{"users"}}) {
		t.Fatal("non-member accepted")
	}
	if isAdmin(&session{}) {
		t.Fatal("empty session accepted")
	}
}

func TestAdminUsersEmpty(t *testing.T) {
	s := testStore(t)
	if got := s.userStats(); len(got) != 0 {
		t.Fatalf("want empty, got %d", len(got))
	}
}

func TestMain(m *testing.M) {
	os.Exit(m.Run())
}

func TestCountAndRetention(t *testing.T) {
	s := testStore(t)
	for i := 0; i < 3; i++ {
		e := scanEntry{Sub: "u1", Time: time.Now().UTC(), Scanner: "s", Target: "https://x.test"}
		if err := sanitizeScanInput(&e); err != nil {
			t.Fatal(err)
		}
		e.ID = fmt.Sprintf("u-%d", i)
		if err := s.append(e); err != nil {
			t.Fatal(err)
		}
	}
	if got := s.count("u1"); got != 3 {
		t.Fatalf("count: want 3 got %d", got)
	}
	if got := s.count("u2"); got != 0 {
		t.Fatalf("cross-user count: %d", got)
	}

	// A 48h-old scan with a stored report survives until retention bites.
	stale := scanEntry{Sub: "u1", Time: time.Now().Add(-48 * time.Hour).UTC(),
		Scanner: "s", Target: "https://old.test"}
	if err := sanitizeScanInput(&stale); err != nil {
		t.Fatal(err)
	}
	stale.ID = "stale-1"
	if err := s.saveReport("stale-1", []byte(`{"results":[]}`)); err != nil {
		t.Fatal(err)
	}
	if err := s.append(stale); err != nil {
		t.Fatal(err)
	}
	if got := s.count("u1"); got != 4 {
		t.Fatalf("pre-retention count: %d", got)
	}

	// Tighten retention to 24h: next append prunes the stale scan + report.
	s.retention = time.Now().Add(-24 * time.Hour)
	fresh := scanEntry{Sub: "u1", Time: time.Now().UTC(), Scanner: "s", Target: "https://y.test"}
	if err := sanitizeScanInput(&fresh); err != nil {
		t.Fatal(err)
	}
	fresh.ID = "fresh-1"
	if err := s.append(fresh); err != nil {
		t.Fatal(err)
	}
	if got := s.count("u1"); got != 4 { // 3 + fresh, stale dropped
		t.Fatalf("post-retention count: %d", got)
	}
	if _, err := s.loadReport("stale-1"); err != errReportMissing {
		t.Fatalf("stale report not swept: %v", err)
	}
	got := s.list("u1", 50)
	for _, e := range got {
		if e.Target == "https://old.test" {
			t.Fatal("stale scan still listed")
		}
	}
}

func TestTrendAggregation(t *testing.T) {
	s := testStore(t)
	now := time.Now().UTC()
	seed := func(id, sub, target string, age time.Duration, findings int, sev map[string]int) {
		e := scanEntry{ID: id, Sub: sub, Time: now.Add(-age), Scanner: "s",
			Target: target, Findings: findings, SeverityCounts: sev}
		if err := sanitizeScanInput(&e); err != nil {
			t.Fatal(err)
		}
		e.ID = id
		if err := s.append(e); err != nil {
			t.Fatal(err)
		}
	}
	seed("t1", "u1", "https://a.test", 0, 5, map[string]int{"high": 2, "low": 3})
	seed("t2", "u1", "https://b.test", 24*time.Hour, 4, map[string]int{"medium": 4})
	seed("t3", "u2", "https://c.test", 0, 10, map[string]int{"critical": 10})
	seed("t4", "u1", "https://d.test", 40*24*time.Hour, 7, map[string]int{"high": 7})

	since := now.AddDate(0, 0, -30)
	own := s.trend("u1", since, false)
	if len(own) < 31 || len(own) > 32 {
		t.Fatalf("zero-fill points: %d", len(own))
	}
	last := own[len(own)-1]
	if last.Date != now.Format("2006-01-02") {
		t.Fatalf("last date: %s", last.Date)
	}
	if last.Scans != 1 || last.Findings != 5 || last.Severity["high"] != 2 {
		t.Fatalf("today bucket: %+v", last)
	}
	yday := now.AddDate(0, 0, -1).Format("2006-01-02")
	var foundYesterday bool
	sum := 0
	for _, p := range own {
		sum += p.Findings
		if p.Date == yday {
			foundYesterday = true
			if p.Scans != 1 || p.Findings != 4 || p.Severity["medium"] != 4 {
				t.Fatalf("yesterday bucket: %+v", p)
			}
		}
	}
	if !foundYesterday {
		t.Fatal("yesterday missing from zero-fill")
	}
	if sum != 9 { // 40-day-old scan excluded
		t.Fatalf("findings sum: %d", sum)
	}

	// All users: u2 counted today as well.
	all := s.trend("", since, true)
	allLast := all[len(all)-1]
	if allLast.Scans != 2 || allLast.Findings != 15 || allLast.Severity["critical"] != 10 {
		t.Fatalf("admin today bucket: %+v", allLast)
	}
}

func TestTrendRouteBeatsIDWildcard(t *testing.T) {
	secret := []byte("test-secret-0123456789abcdef-test")
	srv := &server{
		cfg:   config{SessionSecret: secret},
		scans: newScanStore(filepath.Join(t.TempDir(), "scans.jsonl")),
	}
	seedScan(t, srv, "tr-1", "u-owner", "alice", true)
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/v1/scans/trend", srv.handleTrend)
	mux.HandleFunc("GET /api/v1/scans/{id}", srv.handleScanGet)

	req := httptest.NewRequest("GET", "/api/v1/scans/trend?days=7", nil)
	req.AddCookie(&http.Cookie{Name: "ds_session", Value: cookieFor(t, srv, "u-owner", "alice", nil)})
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != 200 {
		t.Fatalf("trend: %d %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), `"points"`) {
		t.Fatalf("not a trend response: %s", rec.Body.String())
	}
	// Anonymous rejected.
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest("GET", "/api/v1/scans/trend", nil))
	if rec.Code != 401 {
		t.Fatalf("anon trend: %d", rec.Code)
	}
}
