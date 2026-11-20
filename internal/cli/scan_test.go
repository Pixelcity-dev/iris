package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Pixelcity-dev/Iris/internal/core"
)

func TestClassifyTarget(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "app.go")
	if err := os.WriteFile(file, []byte("package main\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	repo := filepath.Join(dir, "repo")
	if err := os.MkdirAll(filepath.Join(repo, ".git"), 0o755); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		target  string
		want    core.TargetKind
		wantErr bool
	}{
		{dir, core.TargetFS, false},
		{file, core.TargetFS, false},
		{repo, core.TargetRepo, false},
		{"https://example.com", core.TargetURL, false},
		{"ghcr.io/org/image:1.0", core.TargetImage, false},
		{"./definitely-missing", "", true},
	}
	for _, tt := range tests {
		got, err := classifyTarget(tt.target)
		if tt.wantErr {
			if err == nil {
				t.Errorf("classifyTarget(%q) expected error", tt.target)
			}
			continue
		}
		if err != nil {
			t.Errorf("classifyTarget(%q): %v", tt.target, err)
			continue
		}
		if got != tt.want {
			t.Errorf("classifyTarget(%q) = %q, want %q", tt.target, got, tt.want)
		}
	}
}

func TestNormalizeScannerName(t *testing.T) {
	tests := map[string]string{
		"website": "webscan",
		"audit":   "webscan",
		"secret":  "secrets",
		"deps":    "sca",
		"fmt":     "format",
		" SAST ":  "sast",
	}
	for in, want := range tests {
		if got := normalizeScannerName(in); got != want {
			t.Errorf("normalizeScannerName(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestUnifiedDiff(t *testing.T) {
	diff := unifiedDiff("a.txt", "one\ntwo  \nthree\n", "one\ntwo\nthree\n")
	if !strings.Contains(diff, "--- a/a.txt") || !strings.Contains(diff, "+++ b/a.txt") {
		t.Fatalf("missing file headers: %q", diff)
	}
	if !strings.Contains(diff, "-two  ") || !strings.Contains(diff, "+two") {
		t.Fatalf("missing changed line: %q", diff)
	}
	if strings.Contains(diff, "-one") {
		t.Errorf("unchanged leading line should be trimmed: %q", diff)
	}
	if got := unifiedDiff("a.txt", "same\n", "same\n"); got != "" {
		t.Errorf("expected empty diff, got %q", got)
	}
}
