package core

import (
	"strings"
	"testing"
)

func TestEnrichFixesFormatting(t *testing.T) {
	findings := []Finding{{
		RuleID: "fmt-trailing-whitespace", Category: "formatting",
		File: "src/main.go", Line: 42,
		Fix: "Remove trailing whitespace",
	}}
	EnrichFixes(findings)
	fix := findings[0].Fix
	if !strings.Contains(fix, "sed -i '42s/[ \\t]+$//' src/main.go") {
		t.Fatalf("expected exact sed command in fix, got %q", fix)
	}
	if !strings.Contains(fix, "Location: src/main.go:42") {
		t.Fatalf("expected location line, got %q", fix)
	}
}

func TestEnrichFixesPreservesSpecificFix(t *testing.T) {
	orig := "Add CSP: default-src 'self'; script-src 'self'"
	findings := []Finding{{
		RuleID: "webscan-missing-csp", Category: "security-headers",
		Title: "Content-Security-Policy missing",
		Fix:   orig,
	}}
	EnrichFixes(findings)
	if findings[0].Fix != orig {
		t.Fatalf("specific fix should be preserved, got %q", findings[0].Fix)
	}
}

func TestEnrichFixesSecrets(t *testing.T) {
	findings := []Finding{{
		RuleID: "secrets-aws-key", Category: "secrets",
		File: "config.py", Line: 10,
		Fix: "Remove the secret",
	}}
	EnrichFixes(findings)
	fix := findings[0].Fix
	for _, want := range []string{"Revoke/rotate", "git history", "os.environ"} {
		if !strings.Contains(fix, want) {
			t.Fatalf("expected %q in fix, got %q", want, fix)
		}
	}
}

func TestEnrichFixesHeader(t *testing.T) {
	findings := []Finding{{
		RuleID: "webscan-missing-hsts", Category: "transport-security",
		Title: "HSTS missing",
		Fix:   "Enable HSTS",
	}}
	EnrichFixes(findings)
	if !strings.Contains(findings[0].Fix, "Strict-Transport-Security: max-age=31536000") {
		t.Fatalf("expected HSTS header value, got %q", findings[0].Fix)
	}
}

func TestIsSpecificFix(t *testing.T) {
	cases := map[string]bool{
		"":                         false,
		"Remove trailing spaces":   false,
		"Add header: X-Frame DENY": true,
		"1. Rotate 2. Remove":      true,
		"Run gofmt -w main.go":     true,
	}
	for in, want := range cases {
		if got := isSpecificFix(in); got != want {
			t.Fatalf("isSpecificFix(%q) = %v, want %v", in, got, want)
		}
	}
}
