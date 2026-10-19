package webscan

import (
	"context"
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/Pixelcity-dev/Iris/internal/core"
)

func TestWebScanRejectsMalformedAndCredentialURLs(t *testing.T) {
	scanner := NewWebScanScanner()
	for _, raw := range []string{"https:///missing-host", "ftp://example.com", "https://user:pass@example.com"} {
		t.Run(raw, func(t *testing.T) {
			_, err := scanner.Scan(context.Background(), core.Target{Kind: core.TargetURL, URI: raw}, nil)
			if err == nil {
				t.Fatalf("Scan(%q) expected validation error", raw)
			}
		})
	}
}

func TestSameWebOriginIncludesSchemeAndPort(t *testing.T) {
	target, _ := url.Parse("https://example.com/path")
	for _, raw := range []string{"https://example.com:443/other", "https://example.com/other"} {
		next, _ := url.Parse(raw)
		if !sameWebOrigin(target, next) {
			t.Errorf("%s should be same origin", raw)
		}
	}
	for _, raw := range []string{"http://example.com/", "https://example.com:8443/", "https://other.example/"} {
		next, _ := url.Parse(raw)
		if sameWebOrigin(target, next) {
			t.Errorf("%s should be cross-origin", raw)
		}
	}
}

func TestWebScanClientRequiresVerifiedModernTLS(t *testing.T) {
	client := newWebScanClient()
	transport, ok := client.Transport.(*http.Transport)
	if !ok {
		t.Fatal("WebScan client must use an HTTP transport")
	}
	if transport.TLSClientConfig == nil {
		t.Fatal("WebScan client must configure a minimum TLS version")
	}
	if transport.TLSClientConfig.InsecureSkipVerify {
		t.Fatal("WebScan client must verify TLS certificates")
	}
	if transport.TLSClientConfig.MinVersion < tls.VersionTLS12 {
		t.Fatalf("minimum TLS version = %v, want TLS 1.2 or newer", transport.TLSClientConfig.MinVersion)
	}
}

func TestCheckTLSDeepReportsUntrustedCertificate(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer server.Close()
	target, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	findings := checkTLSDeep(target)
	if !hasFinding(findings, "webscan-tls-handshake-fail") {
		t.Fatalf("expected untrusted test certificate to fail verification; findings: %#v", findings)
	}
}

func TestCheckSecurityHeadersDeepReportsCSPWeaknesses(t *testing.T) {
	target, _ := url.Parse("https://example.com")
	resp := &http.Response{Header: http.Header{
		"Content-Security-Policy": []string{"default-src 'self'; script-src 'self' 'unsafe-eval'; object-src 'none'"},
	}}
	findings := checkSecurityHeadersDeep(target, nil, resp)
	for _, ruleID := range []string{
		"webscan-weak-csp-unsafe-eval",
		"webscan-csp-missing-base-uri",
		"webscan-csp-missing-form-action",
	} {
		if !hasFinding(findings, ruleID) {
			t.Errorf("expected finding %q; findings: %#v", ruleID, findings)
		}
	}
}

func TestHasCSPDirectiveMatchesDirectiveNameOnly(t *testing.T) {
	policy := "default-src 'self'; img-src data:"
	if hasCSPDirective(policy, "base-uri") {
		t.Fatal("base-uri must not match a substring inside another directive")
	}
	if !hasCSPDirective(policy+"; BASE-URI 'self'", "base-uri") {
		t.Fatal("directive matching should be case-insensitive")
	}
}

func hasFinding(findings []core.Finding, ruleID string) bool {
	for _, finding := range findings {
		if finding.RuleID == ruleID {
			return true
		}
	}
	return false
}
