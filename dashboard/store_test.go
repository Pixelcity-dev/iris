package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
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
