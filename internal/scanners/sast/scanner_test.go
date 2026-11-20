package sast

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/Pixelcity-dev/Iris/internal/core"
)

// The tests use a synthetic sink marker rather than a real-looking SQL string:
// a scanner repository that reports its own fixtures is noise for every user
// who runs `iris scan .` on a checkout.
func markerRule() core.Rule {
	return core.Rule{
		ID:          "test-dangerous-call",
		Name:        "Dangerous call",
		Pattern:     `(?i)\bDANGEROUS_CALL\s*\(`,
		Severity:    core.SeverityCritical,
		Category:    "injection",
		Language:    "generic",
		Enabled:     true,
		ScannerType: core.ScanTypeSAST,
	}
}

func TestAnalyzeFileMatchesRegexAndReportsColumn(t *testing.T) {
	findings := analyzeFile("app.go", "x := 1\nDANGEROUS_CALL(x)\n", markerRule(), "go")
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].Line != 2 {
		t.Errorf("expected line 2, got %d", findings[0].Line)
	}
	if findings[0].Column == 0 {
		t.Error("expected a 1-based column")
	}
}

func TestAnalyzeFileReportsOneFindingPerLine(t *testing.T) {
	findings := analyzeFile("app.go", "DANGEROUS_CALL(1); DANGEROUS_CALL(2)\n", markerRule(), "go")
	if len(findings) != 1 {
		t.Fatalf("expected one finding per line, got %d", len(findings))
	}
}

func TestGenericLanguageMatchesEveryFileLanguage(t *testing.T) {
	for _, lang := range []string{"go", "javascript", "python", "unknown"} {
		if !languageMatches("generic", lang) {
			t.Errorf("generic rule should apply to %q", lang)
		}
	}
	if languageMatches("go", "python") {
		t.Error("a Go-specific rule should not apply to Python")
	}
}

func TestMatchRuleFallsBackToLiteralForInvalidRegex(t *testing.T) {
	rule := core.Rule{Pattern: "MARKER(||OTHER("}
	matches := matchRule("x := MARKER(args)", rule)
	if len(matches) != 1 {
		t.Fatalf("expected fallback literal match, got %d", len(matches))
	}
}

func TestScanSkipsVendoredDirectories(t *testing.T) {
	root := t.TempDir()
	mustWrite := func(rel, content string) {
		path := filepath.Join(root, rel)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	mustWrite("main.go", "x := DANGEROUS_CALL(1)")
	mustWrite("node_modules/dep/index.js", "x = DANGEROUS_CALL(1)")
	mustWrite(".git/hooks/pre-commit", "x := DANGEROUS_CALL(1)")

	scanner := NewSASTScanner()
	findings, err := scanner.Scan(context.Background(), core.Target{Kind: core.TargetFS, URI: root}, []core.Rule{markerRule()})
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected only the first-party finding, got %d: %+v", len(findings), findings)
	}
	if findings[0].File != "main.go" {
		t.Errorf("expected main.go, got %s", findings[0].File)
	}
}
