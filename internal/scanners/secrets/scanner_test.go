package secrets

import (
	"strings"
	"testing"
)

func TestScanFileRedactsMatchedSecret(t *testing.T) {
	scanner := NewSecretsScanner()
	// Built at runtime so this fixture does not itself appear as a leaked
	// credential when someone runs `iris scan .` on a checkout.
	awsKey := "AKIA" + strings.Repeat("Z", 16)
	lines := []string{`aws_access_key = "` + awsKey + `"`}

	findings := scanner.scanFile("config.go", lines)
	if len(findings) == 0 {
		t.Fatal("expected a finding for a real-looking AWS key")
	}
	for _, f := range findings {
		if strings.Contains(f.Code, awsKey) {
			t.Fatalf("secret leaked in Code: %q", f.Code)
		}
	}
}

func TestScanFileRedactsShortLines(t *testing.T) {
	// The old redaction only truncated lines longer than 100 characters, so a
	// short line containing a token was printed verbatim.
	scanner := NewSecretsScanner()
	token := "ghp_" + strings.Repeat("Q", 36)
	findings := scanner.scanFile("token.go", []string{`t := "` + token + `"`})
	if len(findings) == 0 {
		t.Fatal("expected GitHub token finding")
	}
	if strings.Contains(findings[0].Code, token) {
		t.Fatalf("token leaked in Code: %q", findings[0].Code)
	}
	if !strings.Contains(findings[0].Code, "[REDACTED]") {
		t.Fatalf("expected redaction marker, got %q", findings[0].Code)
	}
}

func TestScanFileIgnoresDocumentedPlaceholders(t *testing.T) {
	scanner := NewSecretsScanner()
	lines := []string{
		`Use AKIAIOSFODNN7EXAMPLE in fixtures, never a real key.`,
		`const password = "changeme";`,
		`https://user:pass@example.com/login`,
	}
	if findings := scanner.scanFile("README.md", lines); len(findings) != 0 {
		t.Fatalf("expected placeholder lines to be ignored, got %+v", findings)
	}
}

func TestRedactSecretKeepsContext(t *testing.T) {
	scanner := NewSecretsScanner()
	key := "AIza" + strings.Repeat("B", 35)
	findings := scanner.scanFile("a.go", []string{`const apiKey = "` + key + `"`})
	if len(findings) == 0 {
		t.Fatal("expected Google API key finding")
	}
	if !strings.Contains(findings[0].Code, "apiKey") {
		t.Errorf("expected surrounding context to be kept, got %q", findings[0].Code)
	}
}
