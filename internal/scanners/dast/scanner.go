package dast

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/Pixelcity-dev/Iris/internal/core"
)

type DASTScanner struct {
	core.BaseScanner
	name string
}

func NewDASTScanner() *DASTScanner {
	return &DASTScanner{
		BaseScanner: core.BaseScanner{Enabled: true},
		name:        "dast",
	}
}

func (s *DASTScanner) Name() string        { return s.name }
func (s *DASTScanner) Type() core.ScanType { return core.ScanTypeDAST }
func (s *DASTScanner) SupportedTargets() []core.TargetKind {
	return []core.TargetKind{core.TargetURL}
}

func (s *DASTScanner) Scan(ctx context.Context, target core.Target, rules []core.Rule) ([]core.Finding, error) {
	var findings []core.Finding
	targetURL, err := url.Parse(target.URI)
	if err != nil {
		return nil, fmt.Errorf("invalid target URL: %w", err)
	}

	client := &http.Client{
		Timeout: 15 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}

	// Fetch once for header checks
	resp, err := client.Get(targetURL.String())
	if err != nil {
		return findings, nil
	}
	defer resp.Body.Close()
	// Drain body for keep-alive but keep headers
	_, _ = io.ReadAll(io.LimitReader(resp.Body, 512*1024))

	findings = append(findings, checkSecurityHeaders(targetURL, resp)...)
	findings = append(findings, checkHSTS(resp)...)
	findings = append(findings, checkTLSDeep(targetURL)...)
	findings = append(findings, checkCookieSecurity(resp)...)
	findings = append(findings, checkCORS(targetURL, client)...)
	findings = append(findings, checkInfoDisclosure(resp)...)
	findings = append(findings, checkClickjacking(resp)...)
	findings = append(findings, checkHTTPSRedirect(targetURL)...)
	findings = append(findings, checkHTTPMethods(targetURL, client)...)

	return findings, nil
}

func checkSecurityHeaders(targetURL *url.URL, resp *http.Response) []core.Finding {
	var findings []core.Finding
	requiredHeaders := map[string]struct {
		Name     string
		Severity core.Severity
		Fix      string
	}{
		"X-Content-Type-Options":       {Name: "X-Content-Type-Options", Severity: core.SeverityMedium, Fix: "Add header: X-Content-Type-Options: nosniff"},
		"X-Frame-Options":              {Name: "X-Frame-Options", Severity: core.SeverityMedium, Fix: "Add header: X-Frame-Options: DENY or SAMEORIGIN"},
		"Strict-Transport-Security":    {Name: "Strict-Transport-Security", Severity: core.SeverityHigh, Fix: "Add header: Strict-Transport-Security: max-age=31536000; includeSubDomains"},
		"Content-Security-Policy":      {Name: "Content-Security-Policy", Severity: core.SeverityHigh, Fix: "Add Content-Security-Policy header with appropriate directives"},
		"Referrer-Policy":              {Name: "Referrer-Policy", Severity: core.SeverityMedium, Fix: "Add header: Referrer-Policy: strict-origin-when-cross-origin"},
		"Permissions-Policy":           {Name: "Permissions-Policy", Severity: core.SeverityMedium, Fix: "Add Permissions-Policy header to restrict browser features"},
		"Cross-Origin-Opener-Policy":   {Name: "Cross-Origin-Opener-Policy", Severity: core.SeverityLow, Fix: "Add Cross-Origin-Opener-Policy: same-origin"},
		"Cross-Origin-Resource-Policy": {Name: "Cross-Origin-Resource-Policy", Severity: core.SeverityLow, Fix: "Add Cross-Origin-Resource-Policy: same-origin"},
	}

	for headerName, info := range requiredHeaders {
		if resp.Header.Get(headerName) == "" {
			if headerName == "X-Frame-Options" && resp.Header.Get("Content-Security-Policy") != "" && strings.Contains(strings.ToLower(resp.Header.Get("Content-Security-Policy")), "frame-ancestors") {
				continue
			}
			findings = append(findings, core.Finding{
				RuleID:      "dast-missing-header-" + strings.ToLower(strings.ReplaceAll(headerName, "-", "-")),
				Severity:    info.Severity,
				Category:    "security-headers",
				Title:       "Missing " + info.Name + " header",
				Description: "Response does not include " + info.Name + " header",
				Fix:         info.Fix,
				References: []string{
					"https://securityheaders.com/",
					"https://owasp.org/www-project-secure-headers/",
				},
				Confidence: 1.0,
			})
		}
	}
	// CSP weak checks
	csp := resp.Header.Get("Content-Security-Policy")
	if csp != "" {
		lower := strings.ToLower(csp)
		if strings.Contains(lower, "unsafe-inline") && !strings.Contains(lower, "nonce-") {
			findings = append(findings, core.Finding{
				RuleID: "dast-weak-csp-unsafe-inline", Severity: core.SeverityMedium, Category: "security-headers",
				Title: "Weak CSP with unsafe-inline", Description: "CSP allows unsafe-inline without nonce",
				Fix: "Remove unsafe-inline or add nonce", Confidence: 0.9,
			})
		}
	}
	if resp.Header.Get("Server") != "" {
		findings = append(findings, core.Finding{
			RuleID: "dast-server-header-disclosure", Severity: core.SeverityLow, Category: "information-disclosure",
			Title: "Server header disclosure", Description: "Server header reveals: " + resp.Header.Get("Server"),
			Fix: "Remove or obfuscate Server header", Confidence: 0.9,
		})
	}
	return findings
}

func checkHSTS(resp *http.Response) []core.Finding {
	var findings []core.Finding
	hsts := resp.Header.Get("Strict-Transport-Security")
	if hsts == "" {
		return findings
	}
	lower := strings.ToLower(hsts)
	maxAge := 0
	if idx := strings.Index(lower, "max-age="); idx != -1 {
		rest := lower[idx+8:]
		numStr := ""
		for _, ch := range rest {
			if ch >= '0' && ch <= '9' {
				numStr += string(ch)
			} else {
				break
			}
		}
		if n, err := strconv.Atoi(numStr); err == nil {
			maxAge = n
		}
	}
	if maxAge > 0 && maxAge < 31536000 {
		findings = append(findings, core.Finding{
			RuleID: "dast-hsts-short-maxage", Severity: core.SeverityMedium, Category: "transport-security",
			Title: fmt.Sprintf("HSTS max-age too short (%d)", maxAge), Description: fmt.Sprintf("HSTS max-age=%d < 31536000", maxAge),
			Fix: "Set max-age=63072000; includeSubDomains; preload", Confidence: 1.0,
		})
	}
	if !strings.Contains(lower, "includesubdomains") {
		findings = append(findings, core.Finding{
			RuleID: "dast-hsts-no-includesubdomains", Severity: core.SeverityLow, Category: "transport-security",
			Title: "HSTS missing includeSubDomains", Description: "HSTS without includeSubDomains",
			Fix: "Add includeSubDomains", Confidence: 1.0,
		})
	}
	return findings
}

func checkTLSDeep(targetURL *url.URL) []core.Finding {
	var findings []core.Finding
	if targetURL.Scheme == "http" {
		findings = append(findings, core.Finding{
			RuleID: "dast-no-tls", Severity: core.SeverityHigh, Category: "transport-security",
			Title: "HTTP instead of HTTPS", Description: "Target uses HTTP",
			Fix: "Use HTTPS and redirect HTTP to HTTPS", References: []string{"https://owasp.org/www-project-transport-layer-security-cheat-sheet/"},
			Confidence: 1.0,
		})
		return findings
	}
	host := targetURL.Host
	if !strings.Contains(host, ":") {
		host += ":443"
	}
	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 5 * time.Second}, "tcp", host, &tls.Config{InsecureSkipVerify: true})
	if err != nil {
		findings = append(findings, core.Finding{
			RuleID: "dast-tls-handshake-fail", Severity: core.SeverityHigh, Category: "transport-security",
			Title: "TLS handshake failed", Description: fmt.Sprintf("%v", err), Fix: "Check TLS config", Confidence: 0.9,
		})
		return findings
	}
	defer conn.Close()
	state := conn.ConnectionState()
	if state.Version < tls.VersionTLS12 {
		findings = append(findings, core.Finding{
			RuleID: "dast-tls-old-version", Severity: core.SeverityHigh, Category: "transport-security",
			Title: fmt.Sprintf("Weak TLS version: %s", tlsVersionToString(state.Version)), Description: fmt.Sprintf("Negotiates %s", tlsVersionToString(state.Version)),
			Fix: "Require TLS 1.2+", Confidence: 1.0,
		})
	}
	if len(state.PeerCertificates) > 0 {
		cert := state.PeerCertificates[0]
		if time.Until(cert.NotAfter) < 30*24*time.Hour {
			sev := core.SeverityMedium
			if time.Now().After(cert.NotAfter) {
				sev = core.SeverityCritical
			} else if time.Until(cert.NotAfter) < 7*24*time.Hour {
				sev = core.SeverityHigh
			}
			findings = append(findings, core.Finding{
				RuleID: "dast-tls-cert-expiry", Severity: sev, Category: "transport-security",
				Title:       fmt.Sprintf("TLS cert expires in %s", time.Until(cert.NotAfter).Truncate(time.Hour).String()),
				Description: fmt.Sprintf("NotAfter: %s Subject: %s", cert.NotAfter.Format(time.RFC3339), cert.Subject.CommonName),
				Fix:         "Renew certificate", Confidence: 1.0,
			})
		}
		if err := cert.VerifyHostname(targetURL.Hostname()); err != nil {
			findings = append(findings, core.Finding{
				RuleID: "dast-tls-hostname-mismatch", Severity: core.SeverityHigh, Category: "transport-security",
				Title: "TLS hostname mismatch", Description: fmt.Sprintf("%v", err), Fix: "Fix SAN", Confidence: 1.0,
			})
		}
	}
	return findings
}

func tlsVersionToString(v uint16) string {
	switch v {
	case tls.VersionTLS10:
		return "TLS 1.0"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS13:
		return "TLS 1.3"
	default:
		return fmt.Sprintf("Unknown(0x%x)", v)
	}
}

func checkCookieSecurity(resp *http.Response) []core.Finding {
	var findings []core.Finding
	for _, c := range resp.Cookies() {
		if !c.Secure {
			findings = append(findings, core.Finding{
				RuleID: "dast-cookie-no-secure", Severity: core.SeverityMedium, Category: "cookie-security",
				Title: "Cookie without Secure flag: " + c.Name, Description: fmt.Sprintf("Cookie '%s' missing Secure", c.Name),
				Fix: "Set Secure flag", Confidence: 1.0,
			})
		}
		if !c.HttpOnly {
			findings = append(findings, core.Finding{
				RuleID: "dast-cookie-no-httponly", Severity: core.SeverityMedium, Category: "cookie-security",
				Title: "Cookie without HttpOnly: " + c.Name, Description: fmt.Sprintf("Cookie '%s' missing HttpOnly", c.Name),
				Fix: "Set HttpOnly", Confidence: 1.0,
			})
		}
		raw := ""
		for _, h := range resp.Header["Set-Cookie"] {
			if strings.HasPrefix(strings.ToLower(h), strings.ToLower(c.Name)+"=") {
				raw = strings.ToLower(h)
				break
			}
		}
		if c.SameSite == http.SameSiteDefaultMode && !strings.Contains(raw, "samesite") {
			findings = append(findings, core.Finding{
				RuleID: "dast-cookie-no-samesite", Severity: core.SeverityLow, Category: "cookie-security",
				Title: "Cookie without SameSite: " + c.Name, Description: fmt.Sprintf("Cookie '%s' missing SameSite", c.Name),
				Fix: "Set SameSite=Lax or Strict", Confidence: 0.9,
			})
		}
	}
	return findings
}

func checkCORS(target *url.URL, client *http.Client) []core.Finding {
	var findings []core.Finding
	origin := "https://evil.com"
	req, _ := http.NewRequest("GET", target.String(), nil)
	req.Header.Set("Origin", origin)
	req.Header.Set("User-Agent", "Iris-DAST/1.0")
	resp, err := client.Do(req)
	if err != nil || resp == nil {
		return findings
	}
	defer resp.Body.Close()
	acao := resp.Header.Get("Access-Control-Allow-Origin")
	acac := resp.Header.Get("Access-Control-Allow-Credentials")
	if acao == "*" {
		sev := core.SeverityMedium
		if acac == "true" {
			sev = core.SeverityHigh
		}
		findings = append(findings, core.Finding{
			RuleID: "dast-cors-wildcard", Severity: sev, Category: "cors",
			Title: "CORS wildcard *", Description: fmt.Sprintf("ACAO: * (Credentials: %s)", acac),
			Fix: "Restrict ACAO to specific origins", Confidence: 1.0,
		})
	} else if acao == origin {
		findings = append(findings, core.Finding{
			RuleID: "dast-cors-reflected-origin", Severity: core.SeverityHigh, Category: "cors",
			Title: "CORS reflected arbitrary Origin", Description: "Server reflects arbitrary Origin",
			Fix: "Whitelist allowed origins", Confidence: 0.95,
		})
	}
	return findings
}

func checkInfoDisclosure(resp *http.Response) []core.Finding {
	var findings []core.Finding
	hdrs := map[string]string{
		"X-Powered-By":     resp.Header.Get("X-Powered-By"),
		"X-AspNet-Version": resp.Header.Get("X-AspNet-Version"),
		"X-Generator":      resp.Header.Get("X-Generator"),
		"Via":              resp.Header.Get("Via"),
	}
	for h, v := range hdrs {
		if v != "" {
			findings = append(findings, core.Finding{
				RuleID: "dast-info-leak-" + strings.ToLower(strings.ReplaceAll(h, "-", "")), Severity: core.SeverityLow, Category: "information-disclosure",
				Title: h + " header disclosure", Description: fmt.Sprintf("%s: %s", h, v),
				Fix: fmt.Sprintf("Remove %s header", h), Confidence: 0.9,
			})
		}
	}
	return findings
}

func checkClickjacking(resp *http.Response) []core.Finding {
	var findings []core.Finding
	xfo := resp.Header.Get("X-Frame-Options")
	csp := resp.Header.Get("Content-Security-Policy")
	hasFrameAncestors := csp != "" && strings.Contains(strings.ToLower(csp), "frame-ancestors")
	if xfo == "" && !hasFrameAncestors {
		findings = append(findings, core.Finding{
			RuleID: "dast-clickjacking-no-protection", Severity: core.SeverityMedium, Category: "clickjacking",
			Title: "No clickjacking protection", Description: "Neither X-Frame-Options nor CSP frame-ancestors present",
			Fix: "Add X-Frame-Options: DENY or CSP frame-ancestors", Confidence: 1.0,
		})
	}
	return findings
}

func checkHTTPSRedirect(target *url.URL) []core.Finding {
	var findings []core.Finding
	if target.Scheme != "https" {
		return findings
	}
	httpURL := "http://" + target.Host + target.Path
	noRedir := &http.Client{
		Timeout:       5 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error { return http.ErrUseLastResponse },
	}
	resp, err := noRedir.Get(httpURL)
	if err != nil || resp == nil {
		return findings
	}
	defer resp.Body.Close()
	if resp.StatusCode < 300 || resp.StatusCode >= 400 {
		findings = append(findings, core.Finding{
			RuleID: "dast-no-https-redirect", Severity: core.SeverityMedium, Category: "transport-security",
			Title: "No HTTP to HTTPS redirect", Description: fmt.Sprintf("http:// does not redirect (status %d)", resp.StatusCode),
			Fix: "Enable 301 redirect http->https", Confidence: 0.9,
		})
	}
	return findings
}

func checkHTTPMethods(target *url.URL, client *http.Client) []core.Finding {
	var findings []core.Finding
	req, _ := http.NewRequest("OPTIONS", target.String(), nil)
	resp, err := client.Do(req)
	if err != nil || resp == nil {
		return findings
	}
	defer resp.Body.Close()
	allow := resp.Header.Get("Allow")
	if strings.Contains(strings.ToUpper(allow), "TRACE") {
		findings = append(findings, core.Finding{
			RuleID: "dast-http-trace-enabled", Severity: core.SeverityMedium, Category: "http-methods",
			Title: "HTTP TRACE enabled", Description: "TRACE can be used for XST",
			Fix: "Disable TRACE", Confidence: 0.9,
		})
	}
	// Direct TRACE
	req2, _ := http.NewRequest("TRACE", target.String(), nil)
	resp2, err := client.Do(req2)
	if err == nil && resp2 != nil {
		defer resp2.Body.Close()
		if resp2.StatusCode < 400 {
			findings = append(findings, core.Finding{
				RuleID: "dast-trace-active", Severity: core.SeverityHigh, Category: "http-methods",
				Title: "TRACE method active", Description: fmt.Sprintf("TRACE returned %d", resp2.StatusCode),
				Fix: "Disable TRACE", Confidence: 1.0,
			})
		}
	}
	return findings
}
