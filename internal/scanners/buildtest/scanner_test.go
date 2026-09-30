package buildtest

import (
	"strings"
	"testing"

	"github.com/Pixelcity-dev/Iris/internal/core"
)

func TestDetectToolchainsGo(t *testing.T) {
	// The repo itself is a Go module.
	tcs := detectToolchains("../../..")
	found := false
	for _, tc := range tcs {
		if tc.Name == "Go" && tc.Manifest == "go.mod" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected Go toolchain detection in repo root, got %+v", tcs)
	}
}

func TestDetectToolchainsNone(t *testing.T) {
	tcs := detectToolchains(t.TempDir())
	if len(tcs) != 0 {
		t.Fatalf("expected no toolchains in empty dir, got %+v", tcs)
	}
}

func TestParseDiagnosticGo(t *testing.T) {
	f := parseDiagnostic("./main.go:4:2: undefined: fmt")
	if f == nil {
		t.Fatal("expected diagnostic to parse")
	}
	if f.File != "./main.go" || f.Line != 4 || f.Column != 2 {
		t.Fatalf("unexpected location: %s:%d:%d", f.File, f.Line, f.Column)
	}
	if !strings.Contains(f.Title, "undefined: fmt") {
		t.Fatalf("unexpected title: %q", f.Title)
	}
}

func TestParseDiagnosticIgnoresWarnings(t *testing.T) {
	if parseDiagnostic("foo.ts:12:5: warning: unused var") != nil {
		t.Fatal("warnings must not be promoted to error findings")
	}
	if parseDiagnostic("random build output line") != nil {
		t.Fatal("plain output must not parse as diagnostic")
	}
}

func TestCompileErrorsToFindings(t *testing.T) {
	base := core.Finding{
		RuleID:   "buildtest-build-failed",
		Metadata: map[string]interface{}{"output": "./a.go:1:1: syntax error: unexpected }\n./b.go:9:5: undefined: X\n"},
	}
	out := compileErrorsToFindings(base)
	if len(out) != 3 {
		t.Fatalf("expected 1 base + 2 compile errors, got %d", len(out))
	}
	if out[1].RuleID != "buildtest-compile-error" || out[1].Line != 1 {
		t.Fatalf("unexpected first compile error: %+v", out[1])
	}
}

func TestWarnFindingsFiltered(t *testing.T) {
	tc := toolchain{Name: "Go", Manifest: "go.mod"}
	findings := warnFindings(tc, "test", "ok  \tpkg  0.01s\n# warnings\n0 warnings\nFAIL")
	for _, f := range findings {
		if strings.Contains(f.Description, "0 warnings") {
			t.Fatalf("summary line leaked as warning: %+v", f)
		}
	}
}
