package baseline

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Pixelcity-dev/Iris/internal/core"
)

func finding(rule, file, title string, line int) core.Finding {
	return core.Finding{RuleID: rule, File: file, Title: title, Line: line}
}

func TestKeyIgnoresLineAndColumn(t *testing.T) {
	a := finding("rule-1", "src/main.go", "Unsafe query", 10)
	b := finding("rule-1", "src/main.go", "Unsafe query", 900)
	b.Column = 42
	b.Code = "different code"

	if Key(a) != Key(b) {
		t.Fatalf("expected moved finding to keep its key: %q != %q", Key(a), Key(b))
	}
	if Key(a) == Key(finding("rule-1", "src/main.go", "Different title", 10)) {
		t.Fatal("a different title must produce a different key")
	}
}

func TestFromResultsDeduplicatesAndSorts(t *testing.T) {
	results := []core.ScanResult{
		{Findings: []core.Finding{
			finding("b", "b.go", "Second", 2),
			finding("a", "a.go", "First", 1),
		}},
		{Findings: []core.Finding{
			finding("a", "a.go", "First", 1),
		}},
	}

	b := FromResults(results)
	if len(b.Findings) != 2 {
		t.Fatalf("expected 2 unique entries, got %d", len(b.Findings))
	}
	if b.Findings[0].Key > b.Findings[1].Key {
		t.Fatal("entries should be sorted by key")
	}
}

func TestFilterSuppressesKnownAndKeepsNew(t *testing.T) {
	b := FromResults([]core.ScanResult{{Findings: []core.Finding{
		finding("rule-1", "a.go", "Known", 1),
	}}})

	results := []core.ScanResult{{
		Scanner: "secrets",
		Findings: []core.Finding{
			finding("rule-1", "a.go", "Known", 80),
			finding("rule-1", "a.go", "New", 2),
		},
	}}

	filtered, suppressed := b.Filter(results)
	if suppressed != 1 {
		t.Fatalf("expected 1 suppressed finding, got %d", suppressed)
	}
	if len(filtered) != 1 || len(filtered[0].Findings) != 1 {
		t.Fatalf("expected one result with one finding, got %#v", filtered)
	}
	if filtered[0].Findings[0].Title != "New" {
		t.Fatalf("expected the new finding to remain, got %q", filtered[0].Findings[0].Title)
	}
	if filtered[0].Scanner != "secrets" {
		t.Fatal("filtering should preserve result metadata")
	}
}

func TestSaveLoadRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nested", "baseline.json")
	created := time.Date(2026, 11, 14, 12, 0, 0, 0, time.UTC)
	want := Baseline{
		Version:  "1.2.0",
		Created:  created,
		Findings: []Entry{{Key: "abc", RuleID: "rule", File: "a.go", Line: 3, Title: "Title"}},
	}

	if err := Save(path, want); err != nil {
		t.Fatal(err)
	}
	got, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Findings) != 1 || got.Findings[0].Key != "abc" || !got.Created.Equal(created) {
		t.Fatalf("unexpected round trip: %#v", got)
	}
}

func TestLoadResults(t *testing.T) {
	path := filepath.Join(t.TempDir(), "scan.json")
	data := `{"results":[{"scanner":"secrets","findings":[{"rule_id":"r","file":"a.go","title":"t"}]}]}`
	if err := os.WriteFile(path, []byte(data), 0644); err != nil {
		t.Fatal(err)
	}

	results, err := LoadResults(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 1 || len(results[0].Findings) != 1 {
		t.Fatalf("unexpected results: %#v", results)
	}
}

func TestLoadResultsRawArray(t *testing.T) {
	path := filepath.Join(t.TempDir(), "scan.json")
	if err := os.WriteFile(path, []byte(`[{"scanner":"sast","findings":[]}]`), 0644); err != nil {
		t.Fatal(err)
	}

	results, err := LoadResults(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 1 || results[0].Scanner != "sast" {
		t.Fatalf("unexpected results: %#v", results)
	}
}
