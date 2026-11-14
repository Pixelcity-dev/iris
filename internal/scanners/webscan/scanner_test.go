package webscan

import (
	"context"
	"crypto/tls"
	"html"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
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

func TestOriginRootStripsPathQueryAndFragment(t *testing.T) {
	target, err := url.Parse("https://example.test/en-us/services?campaign=x#top")
	if err != nil {
		t.Fatal(err)
	}
	if got, want := originRoot(target).String(), "https://example.test/"; got != want {
		t.Fatalf("originRoot = %q, want %q", got, want)
	}
}

func TestCheckExposedFilesDoesNotReportPublicSitemap(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/sitemap.xml" {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("<urlset></urlset>"))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()
	target, err := url.Parse(server.URL + "/en-us")
	if err != nil {
		t.Fatal(err)
	}
	if findings := checkExposedFiles(target, server.Client()); hasFinding(findings, "webscan-exposed-sitemap") {
		t.Fatalf("a public sitemap is expected and not an exposure finding: %#v", findings)
	}
}

func TestCheckExposedFilesChecksSecurityTxtAtOriginRoot(t *testing.T) {
	var requestedSecurityTxt string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/.well-known/security.txt") {
			requestedSecurityTxt = r.URL.Path
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("Contact: mailto:security@example.test\n"))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()
	target, err := url.Parse(server.URL + "/en-us/services")
	if err != nil {
		t.Fatal(err)
	}
	findings := checkExposedFiles(target, server.Client())
	if requestedSecurityTxt != "/.well-known/security.txt" {
		t.Fatalf("security.txt path = %q, want root well-known path", requestedSecurityTxt)
	}
	if hasFinding(findings, "webscan-missing-security-txt") {
		t.Fatalf("present security.txt must not create a missing-file finding: %#v", findings)
	}
}

func TestCheckHTTPMethodsDoesNotTreatRedirectAsTRACE(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodTrace {
			http.Redirect(w, r, "/canonical", http.StatusMovedPermanently)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()
	target, err := url.Parse(server.URL + "/page")
	if err != nil {
		t.Fatal(err)
	}
	if findings := checkHTTPMethods(target, server.Client()); hasFinding(findings, "webscan-trace-method-active") {
		t.Fatalf("redirect response must not count as accepted TRACE: %#v", findings)
	}
}

func TestCheckOpenRedirectIgnoresCanonicalRedirectContainingPayload(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "https://www.example.test"+r.URL.RequestURI(), http.StatusMovedPermanently)
	}))
	defer server.Close()
	target, err := url.Parse(server.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	if findings := checkOpenRedirect(target, server.Client()); hasFinding(findings, "webscan-open-redirect") {
		t.Fatalf("same-origin canonical redirect with evil.com in query must not be reported: %#v", findings)
	}
}

func TestCheckSRIOnlyCountsExternalScriptTags(t *testing.T) {
	body := `<script>inline()</script><script type="application/json">{"text":"<script>"}</script><script src="/app.js"></script><script src="https://cdn.example.test/a.js"></script><script src="https://cdn.example.test/b.js" integrity="sha384-abc"></script>`
	target, _ := url.Parse("https://example.test/")
	findings := checkSRI(body, target)
	if len(findings) != 1 || findings[0].RuleID != "webscan-partial-sri" || !strings.Contains(findings[0].Title, "1 of 2 third-party scripts") {
		t.Fatalf("checkSRI findings = %#v, want one missing of two third-party scripts", findings)
	}
	if got := checkSRI(`<script>inline()</script><script type="application/json">data</script>`, target); len(got) != 0 {
		t.Fatalf("inline/data scripts should not cause SRI findings: %#v", got)
	}
}

func TestCheckSRIFlagsExternalScriptsWithoutIntegrity(t *testing.T) {
	findings := checkSRI(`<script src="https://cdn.example.test/app.js"></script><script src="https://cdn.example.test/vendor.js"></script>`, &url.URL{Scheme: "https", Host: "example.test"})
	if len(findings) != 1 || findings[0].RuleID != "webscan-missing-sri" {
		t.Fatalf("checkSRI findings = %#v, want missing SRI finding", findings)
	}
}

func TestCheckSRIIgnoresSameOriginScripts(t *testing.T) {
	target, _ := url.Parse("https://example.test/en-us")
	if findings := checkSRI(`<script src="/_next/static/chunks/app.js"></script>`, target); len(findings) != 0 {
		t.Fatalf("same-origin scripts should not cause third-party SRI finding: %#v", findings)
	}
}

func TestCheckXSSReflectionDoesNotReportEscapedInput(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte("<p>" + html.EscapeString(r.URL.Query().Get("q")) + "</p>"))
	}))
	defer server.Close()
	target, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	if findings := checkXSSReflection(target, server.Client()); len(findings) != 0 {
		t.Fatalf("HTML-escaped marker must not be reported as XSS: %#v", findings)
	}
}

func TestCheckOpenRedirectReportsExternalRedirect(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("next") != "" {
			http.Redirect(w, r, r.URL.Query().Get("next"), http.StatusFound)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()
	target, err := url.Parse(server.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	if findings := checkOpenRedirect(target, server.Client()); !hasFinding(findings, "webscan-open-redirect") {
		t.Fatalf("expected real external redirect finding, got %#v", findings)
	}
}

func TestCheckHTTPMethodsReportsSuccessfulTRACE(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodTrace {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()
	target, err := url.Parse(server.URL + "/page")
	if err != nil {
		t.Fatal(err)
	}
	if findings := checkHTTPMethods(target, server.Client()); !hasFinding(findings, "webscan-trace-method-active") {
		t.Fatalf("expected accepted TRACE finding, got %#v", findings)
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
