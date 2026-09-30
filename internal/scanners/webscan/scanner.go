package webscan

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

// WebScanScanner performs deep website security audit
// Covers OWASP Top 10, security headers, TLS, cookies, CORS, info disclosure, etc.
type WebScanScanner struct {
	core.BaseScanner
	name string
}

func NewWebScanScanner() *WebScanScanner {
	return &WebScanScanner{
		BaseScanner: core.BaseScanner{Enabled: true},
		name:        "webscan",
	}
}

func (s *WebScanScanner) Name() string        { return s.name }
func (s *WebScanScanner) Type() core.ScanType { return core.ScanTypeWebScan }
func (s *WebScanScanner) SupportedTargets() []core.TargetKind {
	return []core.TargetKind{core.TargetURL, core.TargetFS}
}

func (s *WebScanScanner) Scan(ctx context.Context, target core.Target, rules []core.Rule) ([]core.Finding, error) {
	// Accept both URL and FS where URI looks like URL
	raw := target.URI
	if target.Kind == core.TargetFS && !isURL(raw) {
		// for fs target, try to interpret as URL if user passed --scanner webscan on fs
		// if not URL, return no findings but no error (skip)
		return nil, nil
	}
	if !isURL(raw) {
		return nil, fmt.Errorf("webscan requires URL target (http:// or https://), got: %s", raw)
	}
	u, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("invalid URL: %w", err)
	}

	// Normalize: ensure scheme
	if u.Scheme == "" {
		u.Scheme = "https"
	}

	client := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				d := &net.Dialer{Timeout: 5 * time.Second}
				return d.DialContext(ctx, network, addr)
			},
		},
		// Don't follow redirects automatically for redirect checks, but for general fetch we want to follow
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 3 {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}

	var findings []core.Finding

	// 1. Fetch base URL
	baseResp, baseBody := fetchURL(u.String(), client)
	if baseResp == nil {
		findings = append(findings, core.Finding{
			RuleID:      "webscan-unreachable",
			Severity:    core.SeverityHigh,
			Category:    "availability",
			Title:       "Target unreachable",
			Description: fmt.Sprintf("Failed to fetch %s - target may be down or blocking", u.String()),
			Fix:         "Ensure target is reachable and not blocking scanners",
			Confidence:  0.9,
		})
		return findings, nil
	}
	// Ensure baseBody closed after
	defer func() {
		if baseResp != nil && baseResp.Body != nil {
			// already consumed via fetchURL (body drained), but keep for defer
		}
	}()

	// 2. Security Headers Deep
	findings = append(findings, checkSecurityHeadersDeep(u, client, baseResp)...)
	// 3. TLS Deep
	findings = append(findings, checkTLSDeep(u)...)
	// 4. Cookie Security Deep
	findings = append(findings, checkCookieSecurityDeep(baseResp)...)
	// 5. CORS
	findings = append(findings, checkCORS(u, client)...)
	// 6. Information Disclosure
	findings = append(findings, checkInformationDisclosure(baseResp)...)
	// 7. HTTP Methods & TRACE
	findings = append(findings, checkHTTPMethods(u, client)...)
	// 8. Exposed Files
	findings = append(findings, checkExposedFiles(u, client)...)
	// 9. Clickjacking
	findings = append(findings, checkClickjacking(baseResp)...)
	// 10. Open Redirect (safe)
	findings = append(findings, checkOpenRedirect(u, client)...)
	// 11. XSS Reflection (safe)
	findings = append(findings, checkXSSReflection(u, client)...)
	// 12. SQLi Error Disclosure (safe)
	findings = append(findings, checkSQLiErrorDisclosure(u, client)...)
	// 13. Directory Listing
	findings = append(findings, checkDirectoryListing(u, client)...)
	// 14. Security.txt & Robots
	findings = append(findings, checkSecurityTxt(u, client)...)
	// 15. Mixed Content & SRI
	if baseBody != "" && u.Scheme == "https" {
		findings = append(findings, checkMixedContent(baseBody, u)...)
		findings = append(findings, checkSRI(baseBody)...)
	}
	// 16. HTTP -> HTTPS redirect check
	findings = append(findings, checkHTTPSRedirect(u, client)...)
	// 17. HSTS preload check
	findings = append(findings, checkHSTSDeep(baseResp)...)

	return findings, nil
}

// helpers

func isURL(s string) bool {
	return strings.HasPrefix(s, "http://") || strings.HasPrefix(s, "https://")
}

func fetchURL(raw string, client *http.Client) (*http.Response, string) {
	req, _ := http.NewRequest("GET", raw, nil)
	req.Header.Set("User-Agent", "Iris-WebScan/1.0 (+https://github.com/Pixelcity-dev/Iris)")
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	resp, err := client.Do(req)
	if err != nil {
		return nil, ""
	}
	defer resp.Body.Close()
	bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 2<<20)) // 2MB max
	// clone headers for re-use (resp already closed, but headers retained)
	// we need to keep resp for headers; body already read, so we return copy with body string
	return resp, string(bodyBytes)
}

func fetchWithHeader(raw string, client *http.Client, headers map[string]string) (*http.Response, string) {
	req, _ := http.NewRequest("GET", raw, nil)
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	if req.Header.Get("User-Agent") == "" {
		req.Header.Set("User-Agent", "Iris-WebScan/1.0")
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, ""
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	return resp, string(b)
}

// 1. Security Headers Deep
func checkSecurityHeadersDeep(target *url.URL, client *http.Client, resp *http.Response) []core.Finding {
	var findings []core.Finding
	if resp == nil {
		return findings
	}
	required := map[string]struct {
		severity core.Severity
		fix      string
		refs     []string
	}{
		"Strict-Transport-Security":    {core.SeverityHigh, "Add Strict-Transport-Security: max-age=63072000; includeSubDomains; preload", []string{"https://owasp.org/www-project-secure-headers/", "https://hstspreload.org/"}},
		"Content-Security-Policy":      {core.SeverityHigh, "Add CSP: default-src 'self'; script-src 'self'; object-src 'none'; frame-ancestors 'none'", []string{"https://csp-evaluator.withgoogle.com/", "https://owasp.org/www-project-secure-headers/"}},
		"X-Content-Type-Options":       {core.SeverityMedium, "Add X-Content-Type-Options: nosniff", []string{"https://owasp.org/www-project-secure-headers/"}},
		"X-Frame-Options":              {core.SeverityMedium, "Add X-Frame-Options: DENY or use CSP frame-ancestors", []string{}},
		"Referrer-Policy":              {core.SeverityMedium, "Add Referrer-Policy: strict-origin-when-cross-origin or no-referrer", []string{}},
		"Permissions-Policy":           {core.SeverityLow, "Add Permissions-Policy: camera=(), microphone=(), geolocation=()", []string{}},
		"Cross-Origin-Opener-Policy":   {core.SeverityLow, "Add Cross-Origin-Opener-Policy: same-origin", []string{}},
		"Cross-Origin-Embedder-Policy": {core.SeverityLow, "Add Cross-Origin-Embedder-Policy: require-corp", []string{}},
		"Cross-Origin-Resource-Policy": {core.SeverityLow, "Add Cross-Origin-Resource-Policy: same-origin", []string{}},
	}
	for h, meta := range required {
		if resp.Header.Get(h) == "" {
			// Special case: X-Frame-Options may be satisfied by CSP frame-ancestors
			if h == "X-Frame-Options" && resp.Header.Get("Content-Security-Policy") != "" && strings.Contains(strings.ToLower(resp.Header.Get("Content-Security-Policy")), "frame-ancestors") {
				continue
			}
			findings = append(findings, core.Finding{
				RuleID:      "webscan-missing-header-" + strings.ToLower(strings.ReplaceAll(h, "-", "-")),
				Severity:    meta.severity,
				Category:    "security-headers",
				Title:       "Missing " + h + " header",
				Description: fmt.Sprintf("Response from %s does not include %s header", target.String(), h),
				Fix:         meta.fix,
				References:  meta.refs,
				Confidence:  1.0,
			})
		}
	}
	// Check weak CSP: unsafe-inline without nonce/hash
	csp := resp.Header.Get("Content-Security-Policy")
	if csp != "" {
		lower := strings.ToLower(csp)
		if strings.Contains(lower, "unsafe-inline") && !strings.Contains(lower, "nonce-") && !strings.Contains(lower, "sha256-") {
			findings = append(findings, core.Finding{
				RuleID:      "webscan-weak-csp-unsafe-inline",
				Severity:    core.SeverityMedium,
				Category:    "security-headers",
				Title:       "Weak CSP with unsafe-inline",
				Description: "CSP allows unsafe-inline without nonce/hash - weakens XSS protection",
				Fix:         "Remove unsafe-inline or add nonce/hash for inline scripts",
				Confidence:  0.9,
			})
		}
		if strings.Contains(lower, "*") && strings.Contains(lower, "default-src") {
			// wildcard is risky
			if strings.Contains(lower, "default-src *") || strings.Contains(lower, "default-src 'self' *") {
				findings = append(findings, core.Finding{
					RuleID:      "webscan-weak-csp-wildcard",
					Severity:    core.SeverityMedium,
					Category:    "security-headers",
					Title:       "Overly permissive CSP with wildcard",
					Description: "CSP uses wildcard (*) which allows any origin",
					Fix:         "Restrict CSP to specific origins, avoid *",
					Confidence:  0.85,
				})
			}
		}
		if !strings.Contains(lower, "object-src") {
			findings = append(findings, core.Finding{
				RuleID:      "webscan-csp-missing-object-src",
				Severity:    core.SeverityLow,
				Category:    "security-headers",
				Title:       "CSP missing object-src",
				Description: "CSP should set object-src 'none' to block plugins",
				Fix:         "Add object-src 'none' to CSP",
				Confidence:  0.8,
			})
		}
	}
	// Check X-Content-Type-Options value
	xcto := resp.Header.Get("X-Content-Type-Options")
	if xcto != "" && !strings.EqualFold(strings.TrimSpace(xcto), "nosniff") {
		findings = append(findings, core.Finding{
			RuleID:      "webscan-header-invalid-xcto",
			Severity:    core.SeverityLow,
			Category:    "security-headers",
			Title:       "Invalid X-Content-Type-Options value",
			Description: fmt.Sprintf("X-Content-Type-Options is '%s', expected 'nosniff'", xcto),
			Fix:         "Set X-Content-Type-Options: nosniff",
			Confidence:  1.0,
		})
	}
	return findings
}

func checkHSTSDeep(resp *http.Response) []core.Finding {
	var findings []core.Finding
	hsts := resp.Header.Get("Strict-Transport-Security")
	if hsts == "" {
		return findings // already reported missing
	}
	lower := strings.ToLower(hsts)
	// parse max-age
	maxAge := 0
	if idx := strings.Index(lower, "max-age="); idx != -1 {
		rest := lower[idx+8:]
		// extract number
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
			RuleID:      "webscan-hsts-short-maxage",
			Severity:    core.SeverityMedium,
			Category:    "transport-security",
			Title:       fmt.Sprintf("HSTS max-age too short (%d)", maxAge),
			Description: fmt.Sprintf("HSTS max-age=%d is less than recommended 31536000 (1 year)", maxAge),
			Fix:         "Set Strict-Transport-Security: max-age=63072000; includeSubDomains; preload",
			Confidence:  1.0,
		})
	}
	if !strings.Contains(lower, "includesubdomains") {
		findings = append(findings, core.Finding{
			RuleID:      "webscan-hsts-no-includesubdomains",
			Severity:    core.SeverityLow,
			Category:    "transport-security",
			Title:       "HSTS missing includeSubDomains",
			Description: "HSTS header does not include includeSubDomains",
			Fix:         "Add includeSubDomains to HSTS",
			Confidence:  1.0,
		})
	}
	if !strings.Contains(lower, "preload") {
		findings = append(findings, core.Finding{
			RuleID:      "webscan-hsts-no-preload",
			Severity:    core.SeverityInfo,
			Category:    "transport-security",
			Title:       "HSTS missing preload",
			Description: "Consider adding preload for HSTS preloading",
			Fix:         "Add preload and submit to hstspreload.org",
			Confidence:  0.7,
		})
	}
	return findings
}

// 2. TLS Deep
func checkTLSDeep(target *url.URL) []core.Finding {
	var findings []core.Finding
	if target.Scheme == "http" {
		findings = append(findings, core.Finding{
			RuleID:      "webscan-no-tls",
			Severity:    core.SeverityHigh,
			Category:    "transport-security",
			Title:       "HTTP instead of HTTPS",
			Description: "Target uses plain HTTP",
			Fix:         "Enforce HTTPS and redirect HTTP to HTTPS",
			References:  []string{"https://owasp.org/www-project-transport-layer-security-cheat-sheet/"},
			Confidence:  1.0,
		})
		return findings
	}
	// TLS handshake to inspect cert
	host := target.Host
	if !strings.Contains(host, ":") {
		host = host + ":443"
	}
	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 5 * time.Second}, "tcp", host, &tls.Config{
		InsecureSkipVerify: true,
	})
	if err != nil {
		findings = append(findings, core.Finding{
			RuleID:      "webscan-tls-handshake-fail",
			Severity:    core.SeverityHigh,
			Category:    "transport-security",
			Title:       "TLS handshake failed",
			Description: fmt.Sprintf("TLS handshake error: %v", err),
			Fix:         "Check TLS configuration and certificate",
			Confidence:  0.9,
		})
		return findings
	}
	defer conn.Close()
	state := conn.ConnectionState()
	// TLS version
	if state.Version < tls.VersionTLS12 {
		findings = append(findings, core.Finding{
			RuleID:      "webscan-tls-old-version",
			Severity:    core.SeverityHigh,
			Category:    "transport-security",
			Title:       fmt.Sprintf("Weak TLS version: %s", tlsVersionToString(state.Version)),
			Description: fmt.Sprintf("Server negotiates %s which is deprecated", tlsVersionToString(state.Version)),
			Fix:         "Disable TLS 1.0/1.1, require TLS 1.2+",
			Confidence:  1.0,
		})
	} else if state.Version == tls.VersionTLS12 {
		findings = append(findings, core.Finding{
			RuleID:      "webscan-tls-1.2-only",
			Severity:    core.SeverityInfo,
			Category:    "transport-security",
			Title:       "TLS 1.2 negotiated (TLS 1.3 preferred)",
			Description: "Server supports TLS 1.2 but not TLS 1.3",
			Fix:         "Enable TLS 1.3",
			Confidence:  0.6,
		})
	}
	// Cipher suite check (weak ciphers)
	weakCiphers := map[uint16]bool{
		tls.TLS_RSA_WITH_RC4_128_SHA:            true,
		tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA:       true,
		tls.TLS_RSA_WITH_AES_128_CBC_SHA:        true,
		tls.TLS_RSA_WITH_AES_256_CBC_SHA:        true,
		tls.TLS_ECDHE_RSA_WITH_RC4_128_SHA:      true,
		tls.TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA: true,
		tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA:  true,
	}
	if weakCiphers[state.CipherSuite] {
		findings = append(findings, core.Finding{
			RuleID:      "webscan-tls-weak-cipher",
			Severity:    core.SeverityMedium,
			Category:    "transport-security",
			Title:       fmt.Sprintf("Weak cipher suite: %s", tlsCipherToString(state.CipherSuite)),
			Description: "Server negotiates a weak cipher",
			Fix:         "Disable weak ciphers, prefer ECDHE+AESGCM/ChaCha20",
			Confidence:  0.9,
		})
	}
	// Certificate checks
	if len(state.PeerCertificates) > 0 {
		cert := state.PeerCertificates[0]
		// Expiry
		if time.Until(cert.NotAfter) < 30*24*time.Hour {
			sev := core.SeverityMedium
			if time.Until(cert.NotAfter) < 7*24*time.Hour {
				sev = core.SeverityHigh
			}
			if time.Now().After(cert.NotAfter) {
				sev = core.SeverityCritical
			}
			findings = append(findings, core.Finding{
				RuleID:      "webscan-tls-cert-expiry",
				Severity:    sev,
				Category:    "transport-security",
				Title:       fmt.Sprintf("TLS certificate expires in %s", time.Until(cert.NotAfter).Truncate(time.Hour).String()),
				Description: fmt.Sprintf("Certificate NotAfter: %s, Subject: %s", cert.NotAfter.Format(time.RFC3339), cert.Subject.CommonName),
				Fix:         "Renew TLS certificate",
				Confidence:  1.0,
			})
		}
		// Self-signed?
		if cert.Subject.CommonName == cert.Issuer.CommonName && cert.Subject.String() == cert.Issuer.String() {
			// Could be self-signed, check if issuer is same as subject
			findings = append(findings, core.Finding{
				RuleID:      "webscan-tls-self-signed",
				Severity:    core.SeverityHigh,
				Category:    "transport-security",
				Title:       "Self-signed TLS certificate",
				Description: fmt.Sprintf("Certificate Subject and Issuer identical: %s", cert.Subject.String()),
				Fix:         "Use certificate from trusted CA (Let's Encrypt)",
				Confidence:  0.9,
			})
		}
		// Hostname mismatch
		if err := cert.VerifyHostname(target.Hostname()); err != nil {
			findings = append(findings, core.Finding{
				RuleID:      "webscan-tls-hostname-mismatch",
				Severity:    core.SeverityHigh,
				Category:    "transport-security",
				Title:       "TLS certificate hostname mismatch",
				Description: fmt.Sprintf("Cert verification: %v, CN=%s", err, cert.Subject.CommonName),
				Fix:         "Ensure certificate SAN matches hostname",
				Confidence:  1.0,
			})
		}
		// Key size / signature
		if cert.PublicKeyAlgorithm.String() == "RSA" {
			// check key size via manual? Not easy without parsing, skip
		}
	}
	return findings
}

func tlsVersionToString(v uint16) string {
	switch v {
	case tls.VersionSSL30:
		return "SSL 3.0"
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

func tlsCipherToString(c uint16) string {
	switch c {
	case tls.TLS_RSA_WITH_RC4_128_SHA:
		return "TLS_RSA_WITH_RC4_128_SHA"
	case tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA:
		return "TLS_RSA_WITH_3DES_EDE_CBC_SHA"
	case tls.TLS_AES_128_GCM_SHA256:
		return "TLS_AES_128_GCM_SHA256"
	case tls.TLS_AES_256_GCM_SHA384:
		return "TLS_AES_256_GCM_SHA384"
	case tls.TLS_CHACHA20_POLY1305_SHA256:
		return "TLS_CHACHA20_POLY1305_SHA256"
	default:
		return fmt.Sprintf("0x%x", c)
	}
}

// 3. Cookie Security
func checkCookieSecurityDeep(resp *http.Response) []core.Finding {
	var findings []core.Finding
	if resp == nil {
		return findings
	}
	for _, c := range resp.Cookies() {
		if !c.Secure {
			findings = append(findings, core.Finding{
				RuleID:      "webscan-cookie-no-secure",
				Severity:    core.SeverityMedium,
				Category:    "cookie-security",
				Title:       "Cookie without Secure: " + c.Name,
				Description: fmt.Sprintf("Cookie '%s' missing Secure flag", c.Name),
				Fix:         "Set Secure flag: Set-Cookie: " + c.Name + "=...; Secure",
				Confidence:  1.0,
			})
		}
		if !c.HttpOnly {
			findings = append(findings, core.Finding{
				RuleID:      "webscan-cookie-no-httponly",
				Severity:    core.SeverityMedium,
				Category:    "cookie-security",
				Title:       "Cookie without HttpOnly: " + c.Name,
				Description: fmt.Sprintf("Cookie '%s' missing HttpOnly", c.Name),
				Fix:         "Set HttpOnly flag",
				Confidence:  1.0,
			})
		}
		// SameSite
		sameSite := c.SameSite
		raw := ""
		for _, h := range resp.Header["Set-Cookie"] {
			if strings.HasPrefix(strings.ToLower(h), strings.ToLower(c.Name)+"=") {
				raw = strings.ToLower(h)
				break
			}
		}
		if sameSite == http.SameSiteDefaultMode || (sameSite == 0 && !strings.Contains(raw, "samesite")) {
			findings = append(findings, core.Finding{
				RuleID:      "webscan-cookie-no-samesite",
				Severity:    core.SeverityLow,
				Category:    "cookie-security",
				Title:       "Cookie without SameSite: " + c.Name,
				Description: fmt.Sprintf("Cookie '%s' missing SameSite attribute", c.Name),
				Fix:         "Set SameSite=Lax or Strict",
				Confidence:  0.9,
			})
		} else if sameSite == http.SameSiteNoneMode && !c.Secure {
			findings = append(findings, core.Finding{
				RuleID:      "webscan-cookie-samesite-none-without-secure",
				Severity:    core.SeverityHigh,
				Category:    "cookie-security",
				Title:       "SameSite=None without Secure: " + c.Name,
				Description: "SameSite=None requires Secure",
				Fix:         "Add Secure flag for SameSite=None",
				Confidence:  1.0,
			})
		}
		// Check raw for Partitioned etc? skip
		_ = raw
	}
	return findings
}

// 4. CORS
func checkCORS(target *url.URL, client *http.Client) []core.Finding {
	var findings []core.Finding
	origin := "https://evil.com"
	resp, _ := fetchWithHeader(target.String(), client, map[string]string{"Origin": origin})
	if resp == nil {
		return findings
	}
	acao := resp.Header.Get("Access-Control-Allow-Origin")
	acac := resp.Header.Get("Access-Control-Allow-Credentials")
	if acao == "*" {
		sev := core.SeverityMedium
		if acac == "true" {
			sev = core.SeverityHigh
		}
		findings = append(findings, core.Finding{
			RuleID:      "webscan-cors-wildcard",
			Severity:    sev,
			Category:    "cors",
			Title:       "CORS wildcard *",
			Description: fmt.Sprintf("Access-Control-Allow-Origin: * (Credentials: %s)", acac),
			Fix:         "Restrict ACAO to specific origins, avoid * with credentials",
			Confidence:  1.0,
		})
	} else if acao == origin {
		findings = append(findings, core.Finding{
			RuleID:      "webscan-cors-reflected-origin",
			Severity:    core.SeverityHigh,
			Category:    "cors",
			Title:       "CORS reflected arbitrary Origin",
			Description: "Server reflects arbitrary Origin header - allows any site to read responses",
			Fix:         "Whitelist allowed origins, validate Origin header",
			Confidence:  0.95,
		})
	}
	// Check ACAO with null
	resp2, _ := fetchWithHeader(target.String(), client, map[string]string{"Origin": "null"})
	if resp2 != nil && resp2.Header.Get("Access-Control-Allow-Origin") == "null" {
		findings = append(findings, core.Finding{
			RuleID:      "webscan-cors-null-allowed",
			Severity:    core.SeverityHigh,
			Category:    "cors",
			Title:       "CORS allows null origin",
			Description: "Access-Control-Allow-Origin: null can be exploited via sandboxed iframes",
			Fix:         "Do not allow null origin",
			Confidence:  0.9,
		})
	}
	return findings
}

// 5. Information Disclosure
func checkInformationDisclosure(resp *http.Response) []core.Finding {
	var findings []core.Finding
	if resp == nil {
		return findings
	}
	headers := map[string]string{
		"Server":           resp.Header.Get("Server"),
		"X-Powered-By":     resp.Header.Get("X-Powered-By"),
		"X-AspNet-Version": resp.Header.Get("X-AspNet-Version"),
		"X-Generator":      resp.Header.Get("X-Generator"),
		"X-Drupal-Cache":   resp.Header.Get("X-Drupal-Cache"),
		"X-Pingback":       resp.Header.Get("X-Pingback"),
		"Via":              resp.Header.Get("Via"),
		"X-Backend-Server": resp.Header.Get("X-Backend-Server"),
	}
	for h, v := range headers {
		if v != "" {
			sev := core.SeverityLow
			if h == "Server" || h == "X-Powered-By" {
				sev = core.SeverityInfo
			}
			findings = append(findings, core.Finding{
				RuleID:      "webscan-info-leak-" + strings.ToLower(strings.ReplaceAll(h, "-", "")),
				Severity:    sev,
				Category:    "information-disclosure",
				Title:       h + " header disclosure",
				Description: fmt.Sprintf("%s: %s reveals technology", h, v),
				Fix:         fmt.Sprintf("Remove or obfuscate %s header", h),
				Confidence:  0.9,
			})
		}
	}
	// X-Debug etc?
	return findings
}

// 6. HTTP Methods
func checkHTTPMethods(target *url.URL, client *http.Client) []core.Finding {
	var findings []core.Finding
	req, _ := http.NewRequest("OPTIONS", target.String(), nil)
	req.Header.Set("User-Agent", "Iris-WebScan/1.0")
	resp, err := client.Do(req)
	if err != nil || resp == nil {
		return findings
	}
	defer resp.Body.Close()
	allow := resp.Header.Get("Allow")
	if allow != "" {
		upper := strings.ToUpper(allow)
		if strings.Contains(upper, "TRACE") {
			findings = append(findings, core.Finding{
				RuleID:      "webscan-http-trace-enabled",
				Severity:    core.SeverityMedium,
				Category:    "http-methods",
				Title:       "HTTP TRACE enabled",
				Description: "TRACE method can be used for XST attacks",
				Fix:         "Disable TRACE method",
				Confidence:  0.9,
			})
		}
		if strings.Contains(upper, "DELETE") || strings.Contains(upper, "PUT") {
			findings = append(findings, core.Finding{
				RuleID:      "webscan-http-risky-methods",
				Severity:    core.SeverityLow,
				Category:    "http-methods",
				Title:       "Potentially risky HTTP methods allowed: " + allow,
				Description: "Allow header shows PUT/DELETE",
				Fix:         "Restrict HTTP methods to GET, POST, HEAD",
				Confidence:  0.8,
			})
		}
	}
	// Direct TRACE test
	req2, _ := http.NewRequest("TRACE", target.String(), nil)
	resp2, err := client.Do(req2)
	if err == nil && resp2 != nil {
		defer resp2.Body.Close()
		if resp2.StatusCode < 400 {
			findings = append(findings, core.Finding{
				RuleID:      "webscan-trace-method-active",
				Severity:    core.SeverityHigh,
				Category:    "http-methods",
				Title:       "TRACE method is active",
				Description: fmt.Sprintf("TRACE returned %d", resp2.StatusCode),
				Fix:         "Disable TRACE in web server config",
				Confidence:  1.0,
			})
		}
	}
	return findings
}

// 7. Exposed Files
func checkExposedFiles(target *url.URL, client *http.Client) []core.Finding {
	var findings []core.Finding
	base := strings.TrimRight(target.String(), "/")
	paths := []struct {
		path     string
		severity core.Severity
		title    string
		fix      string
	}{
		{"/.env", core.SeverityCritical, "Exposed .env file", "Block access to .env, ensure not deployed"},
		{"/.git/HEAD", core.SeverityCritical, "Exposed .git directory", "Block .git, ensure not deployed to production"},
		{"/.git/config", core.SeverityCritical, "Exposed .git config", "Block .git"},
		{"/.well-known/security.txt", core.SeverityInfo, "Missing security.txt (optional)", "Add /.well-known/security.txt per RFC 9116"},
		{"/backup.zip", core.SeverityHigh, "Potential backup file exposed", "Remove backup files from web root"},
		{"/config.json", core.SeverityHigh, "Potential config.json exposed", "Block config files"},
		{"/admin/.env", core.SeverityHigh, "Potential admin .env", "Block"},
		{"/phpinfo.php", core.SeverityHigh, "phpinfo.php exposed", "Remove phpinfo.php"},
		{"/.DS_Store", core.SeverityLow, "Potential .DS_Store exposed", "Block .DS_Store"},
		{"/package.json", core.SeverityMedium, "package.json exposed", "Block package.json"},
		{"/sitemap.xml", core.SeverityInfo, "sitemap.xml disclosure", "Ensure sitemap does not expose sensitive URLs"},
		{"/.aws/credentials", core.SeverityCritical, "Potential AWS credentials exposed", "Block"},
	}
	for _, p := range paths {
		// For security.txt we want opposite: missing is info, present is not a finding
		isSecurityTxt := p.path == "/.well-known/security.txt"
		urlStr := base + p.path
		resp, body := fetchURL(urlStr, &http.Client{
			Timeout:   5 * time.Second,
			Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}},
		})
		if resp == nil {
			continue
		}
		// Security.txt special: if 200, it's good, not a finding; if 404, it's info missing
		if isSecurityTxt {
			if resp.StatusCode == 404 {
				findings = append(findings, core.Finding{
					RuleID:      "webscan-missing-security-txt",
					Severity:    core.SeverityInfo,
					Category:    "best-practice",
					Title:       "Missing security.txt",
					Description: "No /.well-known/security.txt found (RFC 9116)",
					Fix:         "Add security.txt with contact info",
					Confidence:  1.0,
				})
			}
			continue
		}
		// sitemap.xml also informational if present? we mark as info but not critical
		if p.path == "/sitemap.xml" && resp.StatusCode == 200 {
			// not a vulnerability, just informational disclosure
			// skip to avoid noise? Keep as info
			findings = append(findings, core.Finding{
				RuleID:      "webscan-exposed-sitemap",
				Severity:    core.SeverityInfo,
				Category:    "information-disclosure",
				Title:       "sitemap.xml accessible",
				Description: "sitemap.xml is publicly accessible",
				Fix:         "Ensure sitemap doesn't list sensitive URLs",
				Confidence:  1.0,
			})
			continue
		}
		if resp.StatusCode == 200 {
			// Heuristic: for .env, check content contains "=" or "APP_" or "DB_"
			if p.path == "/.env" && !(strings.Contains(body, "=") && (strings.Contains(body, "APP") || strings.Contains(body, "DB") || strings.Contains(body, "KEY"))) {
				// maybe false positive, but still 200 is suspicious
			}
			// For .git/HEAD should contain "ref: refs/heads/"
			if strings.Contains(p.path, ".git") && !strings.Contains(body, "ref:") {
				continue // false positive
			}
			if len(body) < 10 && p.severity == core.SeverityCritical {
				continue // too small to be real
			}
			findings = append(findings, core.Finding{
				RuleID:      "webscan-exposed-" + strings.ReplaceAll(strings.Trim(p.path, "/"), "/", "-"),
				Severity:    p.severity,
				Category:    "information-disclosure",
				Title:       p.title + " (" + p.path + ")",
				Description: fmt.Sprintf("GET %s returned %d (size %d)", p.path, resp.StatusCode, len(body)),
				Fix:         p.fix,
				Confidence:  0.85,
			})
		}
	}
	return findings
}

// 8. Clickjacking
func checkClickjacking(resp *http.Response) []core.Finding {
	var findings []core.Finding
	if resp == nil {
		return findings
	}
	xfo := resp.Header.Get("X-Frame-Options")
	csp := resp.Header.Get("Content-Security-Policy")
	hasFrameAncestors := csp != "" && strings.Contains(strings.ToLower(csp), "frame-ancestors")
	if xfo == "" && !hasFrameAncestors {
		findings = append(findings, core.Finding{
			RuleID:      "webscan-clickjacking-no-protection",
			Severity:    core.SeverityMedium,
			Category:    "clickjacking",
			Title:       "No clickjacking protection",
			Description: "Neither X-Frame-Options nor CSP frame-ancestors present",
			Fix:         "Add X-Frame-Options: DENY or CSP: frame-ancestors 'none'",
			Confidence:  1.0,
		})
	} else if xfo != "" {
		val := strings.ToUpper(strings.TrimSpace(xfo))
		if val != "DENY" && val != "SAMEORIGIN" && !strings.HasPrefix(val, "ALLOW-FROM") {
			findings = append(findings, core.Finding{
				RuleID:      "webscan-clickjacking-weak-xfo",
				Severity:    core.SeverityLow,
				Category:    "clickjacking",
				Title:       "Weak X-Frame-Options: " + xfo,
				Description: "X-Frame-Options value is not DENY or SAMEORIGIN",
				Fix:         "Set X-Frame-Options: DENY",
				Confidence:  0.9,
			})
		}
	}
	return findings
}

// 9. Open Redirect
func checkOpenRedirect(target *url.URL, client *http.Client) []core.Finding {
	var findings []core.Finding
	// Do not follow redirects
	noRedir := &http.Client{
		Timeout:   5 * time.Second,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	payloads := []string{
		"https://evil.com",
		"//evil.com",
		"/%09/evil.com",
	}
	// try common param names
	params := []string{"url", "next", "redirect", "return", "dest", "destination", "rurl"}
	for _, param := range params {
		for _, payload := range payloads {
			// Build URL with param
			u2 := *target
			q := u2.Query()
			q.Set(param, payload)
			u2.RawQuery = q.Encode()
			resp, _ := fetchURL(u2.String(), noRedir)
			if resp == nil {
				continue
			}
			loc := resp.Header.Get("Location")
			if (resp.StatusCode == 301 || resp.StatusCode == 302 || resp.StatusCode == 303 || resp.StatusCode == 307 || resp.StatusCode == 308) && strings.Contains(loc, "evil.com") {
				findings = append(findings, core.Finding{
					RuleID:      "webscan-open-redirect",
					Severity:    core.SeverityHigh,
					Category:    "open-redirect",
					Title:       fmt.Sprintf("Potential open redirect via %s param", param),
					Description: fmt.Sprintf("GET %s -> %d Location: %s", u2.String(), resp.StatusCode, loc),
					Fix:         "Validate redirect targets against allowlist, use relative paths",
					Confidence:  0.85,
				})
				goto nextParam // avoid duplicate for same param
			}
		}
	nextParam:
	}
	// Also try path based redirect: /redirect/https://evil.com
	return findings
}

// 10. XSS Reflection (safe)
func checkXSSReflection(target *url.URL, client *http.Client) []core.Finding {
	var findings []core.Finding
	marker := "irisXSS1337"
	payload := "<s>" + marker + "</s>"
	u2 := *target
	q := u2.Query()
	// Use existing param if any, else add q
	if len(q) == 0 {
		q.Set("q", payload)
	} else {
		// append to first param
		for k := range q {
			q.Set(k, q.Get(k)+payload)
			break
		}
	}
	u2.RawQuery = q.Encode()
	_, body := fetchURL(u2.String(), client)
	if body != "" && strings.Contains(body, marker) {
		// Check if payload is escaped or not - look for raw <s>
		if strings.Contains(body, payload) {
			findings = append(findings, core.Finding{
				RuleID:      "webscan-reflected-xss",
				Severity:    core.SeverityHigh,
				Category:    "xss",
				Title:       "Potential reflected XSS",
				Description: fmt.Sprintf("Payload %s reflected unescaped in response of %s", payload, u2.String()),
				Fix:         "Encode output, use CSP, validate input",
				References:  []string{"https://owasp.org/www-community/attacks/xss/"},
				Confidence:  0.75,
			})
		} else if strings.Contains(body, marker) {
			findings = append(findings, core.Finding{
				RuleID:      "webscan-reflected-xss-encoded",
				Severity:    core.SeverityLow,
				Category:    "xss",
				Title:       "Reflected input (potential XSS, but encoded)",
				Description: fmt.Sprintf("Marker %s reflected but HTML encoded", marker),
				Fix:         "Ensure proper output encoding",
				Confidence:  0.5,
			})
		}
	}
	return findings
}

// 11. SQLi error disclosure (safe - just checks error messages with single quote)
func checkSQLiErrorDisclosure(target *url.URL, client *http.Client) []core.Finding {
	var findings []core.Finding
	// Only test if URL has query params, to reduce noise
	if target.RawQuery == "" {
		return findings
	}
	u2 := *target
	q := u2.Query()
	for k := range q {
		orig := q.Get(k)
		q.Set(k, orig+"'")
		u2.RawQuery = q.Encode()
		_, body := fetchURL(u2.String(), client)
		lower := strings.ToLower(body)
		if strings.Contains(lower, "sql syntax") || strings.Contains(lower, "mysql") && strings.Contains(lower, "error") || strings.Contains(lower, "ora-") || strings.Contains(lower, "psql") || strings.Contains(lower, "sqlite") || strings.Contains(lower, "unclosed quotation mark") {
			findings = append(findings, core.Finding{
				RuleID:      "webscan-sqli-error-disclosure",
				Severity:    core.SeverityHigh,
				Category:    "injection",
				Title:       "Potential SQL error disclosure via " + k,
				Description: fmt.Sprintf("Injecting ' into %s shows SQL error message", k),
				Fix:         "Use parameterized queries, hide detailed DB errors",
				Confidence:  0.7,
			})
			break
		}
		// restore
		q.Set(k, orig)
		break // only test one param
	}
	return findings
}

// 12. Directory Listing
func checkDirectoryListing(target *url.URL, client *http.Client) []core.Finding {
	var findings []core.Finding
	// Try common dirs
	paths := []string{"/images/", "/assets/", "/static/", "/uploads/"}
	base := strings.TrimRight(target.String(), "/")
	for _, p := range paths {
		_, body := fetchURL(base+p, client)
		lower := strings.ToLower(body)
		if strings.Contains(lower, "index of") && (strings.Contains(lower, "parent directory") || strings.Contains(lower, "<title>index")) {
			findings = append(findings, core.Finding{
				RuleID:      "webscan-directory-listing",
				Severity:    core.SeverityMedium,
				Category:    "information-disclosure",
				Title:       "Directory listing enabled: " + p,
				Description: fmt.Sprintf("GET %s shows directory listing", p),
				Fix:         "Disable directory listing (autoindex off)",
				Confidence:  0.9,
			})
		}
	}
	return findings
}

// 13. Security.txt & robots.txt
func checkSecurityTxt(target *url.URL, client *http.Client) []core.Finding {
	var findings []core.Finding
	base := strings.TrimRight(target.String(), "/")
	// robots.txt
	resp, body := fetchURL(base+"/robots.txt", client)
	if resp != nil && resp.StatusCode == 200 && body != "" {
		if strings.Contains(strings.ToLower(body), "disallow: /admin") || strings.Contains(strings.ToLower(body), "disallow: /private") {
			findings = append(findings, core.Finding{
				RuleID:      "webscan-robots-sensitive-disallow",
				Severity:    core.SeverityInfo,
				Category:    "information-disclosure",
				Title:       "robots.txt reveals sensitive paths",
				Description: "robots.txt contains Disallow for sensitive areas",
				Fix:         "Avoid listing sensitive paths in robots.txt; use authentication",
				Confidence:  0.8,
			})
		}
	}
	return findings
}

// 14. Mixed Content
func checkMixedContent(body string, u *url.URL) []core.Finding {
	var findings []core.Finding
	lower := strings.ToLower(body)
	if strings.Contains(lower, "http://") {
		// Count http:// references
		count := strings.Count(lower, "http://")
		if count > 0 {
			// Check if any http:// is not just in comments but in src/href
			if strings.Contains(lower, "src=\"http://") || strings.Contains(lower, "href=\"http://") {
				findings = append(findings, core.Finding{
					RuleID:      "webscan-mixed-content",
					Severity:    core.SeverityMedium,
					Category:    "transport-security",
					Title:       fmt.Sprintf("Mixed content: %d http:// resources on https page", count),
					Description: "HTTPS page loads resources over HTTP",
					Fix:         "Use https:// or protocol-relative // for all resources, enable upgrade-insecure-requests",
					Confidence:  0.8,
				})
			}
		}
	}
	return findings
}

// 15. SRI
func checkSRI(body string) []core.Finding {
	var findings []core.Finding
	lower := strings.ToLower(body)
	// Look for script tags without integrity
	if strings.Contains(lower, "<script") {
		// crude: count scripts and integrity
		scripts := strings.Count(lower, "<script")
		integrity := strings.Count(lower, "integrity=")
		if scripts > 0 && integrity == 0 {
			findings = append(findings, core.Finding{
				RuleID:      "webscan-missing-sri",
				Severity:    core.SeverityLow,
				Category:    "integrity",
				Title:       "No Subresource Integrity (SRI) for scripts",
				Description: fmt.Sprintf("%d script tags without integrity attribute", scripts),
				Fix:         "Add integrity hashes to external scripts",
				Confidence:  0.6,
			})
		} else if scripts > integrity {
			findings = append(findings, core.Finding{
				RuleID:      "webscan-partial-sri",
				Severity:    core.SeverityInfo,
				Category:    "integrity",
				Title:       fmt.Sprintf("Partial SRI: %d scripts, %d with integrity", scripts, integrity),
				Description: "Some scripts missing SRI",
				Fix:         "Add integrity to all external scripts",
				Confidence:  0.6,
			})
		}
	}
	return findings
}

// 16. HTTPS redirect
func checkHTTPSRedirect(target *url.URL, client *http.Client) []core.Finding {
	var findings []core.Finding
	if target.Scheme != "https" {
		return findings
	}
	// Try http version
	httpURL := "http://" + target.Host + target.Path
	if target.RawQuery != "" {
		httpURL += "?" + target.RawQuery
	}
	noRedir := &http.Client{
		Timeout: 5 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	resp, err := noRedir.Get(httpURL)
	if err != nil || resp == nil {
		return findings
	}
	defer resp.Body.Close()
	if resp.StatusCode < 300 || resp.StatusCode >= 400 {
		findings = append(findings, core.Finding{
			RuleID:      "webscan-no-https-redirect",
			Severity:    core.SeverityMedium,
			Category:    "transport-security",
			Title:       "No HTTP to HTTPS redirect",
			Description: fmt.Sprintf("http:// version does not redirect to https (status %d)", resp.StatusCode),
			Fix:         "Enable 301 redirect from http to https",
			Confidence:  0.9,
		})
	} else {
		loc := resp.Header.Get("Location")
		if !strings.HasPrefix(loc, "https://") {
			findings = append(findings, core.Finding{
				RuleID:      "webscan-https-redirect-not-https",
				Severity:    core.SeverityMedium,
				Category:    "transport-security",
				Title:       "HTTP redirect not to HTTPS",
				Description: fmt.Sprintf("Redirect Location: %s", loc),
				Fix:         "Redirect http to https",
				Confidence:  1.0,
			})
		}
	}
	_ = client
	return findings
}
