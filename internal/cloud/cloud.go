// Package cloud implements the Iris <-> PixelCity cloud integration:
// Keycloak (id.pixelcity.dev) OIDC login, usage reporting and the
// payments client (payments.pixelcity.dev).
package cloud

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	// DefaultIssuer is the Keycloak realm serving PixelCity identities.
	DefaultIssuer = "https://id.pixelcity.dev/realms/pcid"
	// DefaultAPIBase is the Iris cloud API (dashboard backend).
	DefaultAPIBase = "https://dashboard.pixelcity.dev/api/v1"
	// DefaultPaymentsBase is the payments service.
	DefaultPaymentsBase = "https://payments.pixelcity.dev"
	// ClientID is the public OIDC client for the Iris CLI.
	ClientID = "iris-cli"
)

// ErrNotLoggedIn is returned when a cloud command requires an account.
var ErrNotLoggedIn = errors.New("not logged in — run 'iris cloud login' first")

// Config holds the cloud endpoints (overridable via env for staging).
type Config struct {
	Issuer       string
	APIBase      string
	PaymentsBase string
	HTTPTimeout  time.Duration
}

// DefaultConfig returns the production endpoints.
func DefaultConfig() Config {
	return Config{
		Issuer:       envOr("IRIS_OIDC_ISSUER", DefaultIssuer),
		APIBase:      envOr("IRIS_API_BASE", DefaultAPIBase),
		PaymentsBase: envOr("IRIS_PAYMENTS_BASE", DefaultPaymentsBase),
		HTTPTimeout:  30 * time.Second,
	}
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

// ---------- Token store ----------

// Tokens holds the OIDC token set persisted locally.
type Tokens struct {
	AccessToken      string    `json:"access_token"`
	RefreshToken     string    `json:"refresh_token,omitempty"`
	IDToken          string    `json:"id_token,omitempty"`
	ExpiresAt        time.Time `json:"expires_at"`
	RefreshExpiresAt time.Time `json:"refresh_expires_at,omitempty"`
	Realm            string    `json:"realm,omitempty"`
}

// tokenPath returns ~/.iris/cloud-tokens.json (0600).
func tokenPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".iris", "cloud-tokens.json"), nil
}

// SaveTokens persists tokens with user-only permissions.
func SaveTokens(t Tokens) error {
	p, err := tokenPath()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(p), 0700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(t, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(p, data, 0600)
}

// LoadTokens reads stored tokens.
func LoadTokens() (Tokens, error) {
	p, err := tokenPath()
	if err != nil {
		return Tokens{}, err
	}
	data, err := os.ReadFile(p)
	if err != nil {
		if os.IsNotExist(err) {
			return Tokens{}, ErrNotLoggedIn
		}
		return Tokens{}, err
	}
	var t Tokens
	if err := json.Unmarshal(data, &t); err != nil {
		return Tokens{}, fmt.Errorf("corrupt token store: %w", err)
	}
	return t, nil
}

// ClearTokens removes the local session.
func ClearTokens() error {
	p, err := tokenPath()
	if err != nil {
		return err
	}
	err = os.Remove(p)
	if os.IsNotExist(err) {
		return nil
	}
	return err
}

// ---------- OIDC: device authorization flow ----------

type deviceAuthResp struct {
	DeviceCode              string `json:"device_code"`
	UserCode                string `json:"user_code"`
	VerificationURI         string `json:"verification_uri"`
	VerificationURIComplete string `json:"verification_uri_complete,omitempty"`
	Interval                int    `json:"interval"`
	ExpiresIn               int    `json:"expires_in"`
}

type tokenResp struct {
	AccessToken      string `json:"access_token"`
	RefreshToken     string `json:"refresh_token"`
	IDToken          string `json:"id_token"`
	ExpiresIn        int    `json:"expires_in"`
	RefreshExpiresIn int    `json:"refresh_expires_in"`
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description"`
}

// Login starts the device flow: it prints the verification URL + code and
// polls Keycloak until the user approves in their browser.
func Login(ctx context.Context, cfg Config, out io.Writer) (Tokens, error) {
	if out == nil {
		out = os.Stderr
	}
	hc := &http.Client{Timeout: cfg.HTTPTimeout}

	// RFC 8628 device authorization
	form := url.Values{
		"client_id": {ClientID},
		"scope":     {"openid profile email"},
	}
	req, err := http.NewRequestWithContext(ctx, "POST",
		cfg.Issuer+"/protocol/openid-connect/auth/device", strings.NewReader(form.Encode()))
	if err != nil {
		return Tokens{}, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	var da deviceAuthResp
	if err := postJSON(hc, req, &da); err != nil {
		return Tokens{}, fmt.Errorf("device authorization failed (is id.pixelcity.dev reachable?): %w", err)
	}

	fmt.Fprintf(out, "\nLogin via PixelCity ID (%s):\n", cfg.Issuer)
	fmt.Fprintf(out, "  1. Open:  %s\n", da.VerificationURI)
	if da.VerificationURIComplete != "" {
		fmt.Fprintf(out, "     (or directly: %s)\n", da.VerificationURIComplete)
	}
	fmt.Fprintf(out, "  2. Code:  %s\n\n", da.UserCode)
	fmt.Fprintf(out, "Waiting for approval …\n")

	interval := time.Duration(da.Interval) * time.Second
	if interval <= 0 {
		interval = 5 * time.Second
	}
	deadline := time.Now().Add(time.Duration(da.ExpiresIn) * time.Second)
	if da.ExpiresIn <= 0 {
		deadline = time.Now().Add(10 * time.Minute)
	}

	for time.Now().Before(deadline) {
		select {
		case <-ctx.Done():
			return Tokens{}, ctx.Err()
		case <-time.After(interval):
		}

		tform := url.Values{
			"grant_type":  {"urn:ietf:params:oauth:grant-type:device_code"},
			"device_code": {da.DeviceCode},
			"client_id":   {ClientID},
			"scope":       {"openid profile email"},
		}
		treq, err := http.NewRequestWithContext(ctx, "POST",
			cfg.Issuer+"/protocol/openid-connect/token", strings.NewReader(tform.Encode()))
		if err != nil {
			return Tokens{}, err
		}
		treq.Header.Set("Content-Type", "application/x-www-form-urlencoded")

		var tr tokenResp
		body, err := pollOnce(hc, treq)
		if err != nil {
			return Tokens{}, err
		}
		_ = json.Unmarshal(body, &tr)

		switch tr.Error {
		case "":
			expires := time.Now().Add(time.Duration(tr.ExpiresIn) * time.Second)
			tok := Tokens{
				AccessToken:      tr.AccessToken,
				RefreshToken:     tr.RefreshToken,
				IDToken:          tr.IDToken,
				ExpiresAt:        expires,
				RefreshExpiresAt: time.Now().Add(time.Duration(tr.RefreshExpiresIn) * time.Second),
				Realm:            cfg.Issuer,
			}
			if err := SaveTokens(tok); err != nil {
				return tok, fmt.Errorf("logged in, but could not persist session: %w", err)
			}
			return tok, nil
		case "authorization_pending":
			continue
		case "slow_down":
			interval += 2 * time.Second
			continue
		case "access_denied":
			return Tokens{}, errors.New("login denied by user")
		default:
			if tr.ErrorDescription != "" {
				return Tokens{}, fmt.Errorf("login failed: %s (%s)", tr.Error, tr.ErrorDescription)
			}
			return Tokens{}, fmt.Errorf("login failed: %s", tr.Error)
		}
	}
	return Tokens{}, errors.New("login timed out — start again with 'iris cloud login'")
}

// pollOnce performs one token-endpoint poll. Unlike do(), HTTP 400 is not an
// error: the device flow uses 400 + {error: authorization_pending|slow_down}
// as normal polling responses (RFC 8628 §3.5).
func pollOnce(hc *http.Client, req *http.Request) ([]byte, error) {
	resp, err := hc.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode >= 500 {
		return nil, fmt.Errorf("token endpoint: HTTP %d", resp.StatusCode)
	}
	return body, nil
}

// Logout clears the local session (and best-effort revokes the refresh token).
func Logout(ctx context.Context, cfg Config) error {
	tok, err := LoadTokens()
	if err == nil && tok.RefreshToken != "" {
		form := url.Values{
			"client_id":     {ClientID},
			"refresh_token": {tok.RefreshToken},
		}
		req, _ := http.NewRequestWithContext(ctx, "POST",
			cfg.Issuer+"/protocol/openid-connect/logout", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		hc := &http.Client{Timeout: 10 * time.Second}
		resp, err := hc.Do(req)
		if err == nil {
			_ = resp.Body.Close()
		}
	}
	return ClearTokens()
}

// EnsureValidToken returns a valid access token, refreshing when needed.
func EnsureValidToken(ctx context.Context, cfg Config) (string, error) {
	tok, err := LoadTokens()
	if err != nil {
		return "", err
	}
	if time.Now().Before(tok.ExpiresAt.Add(-30 * time.Second)) {
		return tok.AccessToken, nil
	}
	if tok.RefreshToken == "" {
		return "", ErrNotLoggedIn
	}
	refreshed, err := refresh(ctx, cfg, tok.RefreshToken)
	if err != nil {
		_ = ClearTokens()
		return "", fmt.Errorf("session expired — run 'iris cloud login' again: %w", err)
	}
	if err := SaveTokens(refreshed); err != nil {
		return refreshed.AccessToken, err
	}
	return refreshed.AccessToken, nil
}

func refresh(ctx context.Context, cfg Config, refreshToken string) (Tokens, error) {
	form := url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {refreshToken},
		"client_id":     {ClientID},
	}
	req, err := http.NewRequestWithContext(ctx, "POST",
		cfg.Issuer+"/protocol/openid-connect/token", strings.NewReader(form.Encode()))
	if err != nil {
		return Tokens{}, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	hc := &http.Client{Timeout: cfg.HTTPTimeout}
	body, err := do(hc, req)
	if err != nil {
		return Tokens{}, err
	}
	var tr tokenResp
	if err := json.Unmarshal(body, &tr); err != nil {
		return Tokens{}, err
	}
	if tr.Error != "" {
		return Tokens{}, fmt.Errorf("%s", tr.Error)
	}
	return Tokens{
		AccessToken:      tr.AccessToken,
		RefreshToken:     tr.RefreshToken,
		IDToken:          tr.IDToken,
		ExpiresAt:        time.Now().Add(time.Duration(tr.ExpiresIn) * time.Second),
		RefreshExpiresAt: time.Now().Add(time.Duration(tr.RefreshExpiresIn) * time.Second),
		Realm:            cfg.Issuer,
	}, nil
}

// ---------- Account / claims ----------

// Claims is the subset of the ID token payload the CLI displays.
type Claims struct {
	Sub               string   `json:"sub"`
	PreferredUsername string   `json:"preferred_username"`
	Email             string   `json:"email"`
	EmailVerified     bool     `json:"email_verified"`
	Name              string   `json:"name"`
	Groups            []string `json:"groups"`
}

// Whoami fetches userinfo from Keycloak.
func Whoami(ctx context.Context, cfg Config, accessToken string) (Claims, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", cfg.Issuer+"/protocol/openid-connect/userinfo", nil)
	if err != nil {
		return Claims{}, err
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	hc := &http.Client{Timeout: cfg.HTTPTimeout}
	body, err := do(hc, req)
	if err != nil {
		return Claims{}, err
	}
	var c Claims
	if err := json.Unmarshal(body, &c); err != nil {
		return Claims{}, err
	}
	return c, nil
}

// ---------- Cloud API (dashboard backend) ----------

// Plan describes the account's subscription tier.
type Plan struct {
	Tier         string    `json:"tier"` // free | pro | enterprise
	Name         string    `json:"name"`
	ValidUntil   time.Time `json:"valid_until,omitempty"`
	ScanQuota    int       `json:"scan_quota"`
	ScansUsed    int       `json:"scans_used"`
	AIPagesQuota int       `json:"ai_pages_quota"`
	AIPagesUsed  int       `json:"ai_pages_used"`
	Features     []string  `json:"features,omitempty"`
}

// UsageEntry is a single historical scan record.
type UsageEntry struct {
	Time      time.Time `json:"time"`
	Scanner   string    `json:"scanner"`
	Target    string    `json:"target"`
	Findings  int       `json:"findings"`
	DurationS float64   `json:"duration_seconds"`
	// SeverityCounts breaks findings down by severity (critical..info).
	SeverityCounts map[string]int `json:"severity_counts,omitempty"`
	// Report is the full structured scan output (findings, metadata).
	Report json.RawMessage `json:"report,omitempty"`
	// Version is the CLI version that produced the scan.
	Version string `json:"iris_version,omitempty"`
}

// UsageHistory is the paged usage log.
type UsageHistory struct {
	Entries   []UsageEntry `json:"entries"`
	Total     int          `json:"total"`
	Truncated bool         `json:"truncated"`
}

// GetPlan fetches the current plan + quotas.
func GetPlan(ctx context.Context, cfg Config, accessToken string) (Plan, error) {
	var p Plan
	err := apiGet(ctx, cfg, accessToken, "/plan", &p)
	return p, err
}

// GetUsage fetches the usage history.
func GetUsage(ctx context.Context, cfg Config, accessToken string, limit int) (UsageHistory, error) {
	var u UsageHistory
	if limit <= 0 {
		limit = 50
	}
	err := apiGet(ctx, cfg, accessToken, fmt.Sprintf("/scans?limit=%d", limit), &u)
	return u, err
}

// ReportUsage posts a scan record to the cloud (best-effort; never fatal).
func ReportUsage(ctx context.Context, cfg Config, accessToken string, e UsageEntry) error {
	data, _ := json.Marshal(e)
	req, err := http.NewRequestWithContext(ctx, "POST",
		cfg.APIBase+"/scans", bytes.NewReader(data))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Content-Type", "application/json")
	hc := &http.Client{Timeout: cfg.HTTPTimeout}
	resp, err := hc.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		msg := ""
		var e struct {
			Error string `json:"error"`
		}
		if json.Unmarshal(body, &e) == nil && e.Error != "" {
			msg = e.Error
		} else if m := strings.TrimSpace(string(body)); m != "" {
			msg = m
		} else {
			msg = resp.Status
		}
		return fmt.Errorf("usage report failed: %s: %s", resp.Status, msg)
	}
	return nil
}

// CheckoutSession is a payments.pixelcity.dev checkout URL.
type CheckoutSession struct {
	URL         string `json:"url"`
	SessionID   string `json:"session_id"`
	Plan        string `json:"plan"`
	Currency    string `json:"currency"`
	AmountCents int64  `json:"amount_cents"`
}

// CreateCheckout starts a Pro/Enterprise purchase via the payments service.
func CreateCheckout(ctx context.Context, cfg Config, accessToken, plan, interval string) (CheckoutSession, error) {
	var cs CheckoutSession
	form := url.Values{"plan": {plan}, "interval": {interval}}
	req, err := http.NewRequestWithContext(ctx, "POST",
		cfg.APIBase+"/billing/checkout", strings.NewReader(form.Encode()))
	if err != nil {
		return cs, err
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	hc := &http.Client{Timeout: cfg.HTTPTimeout}
	body, err := do(hc, req)
	if err != nil {
		return cs, err
	}
	err = json.Unmarshal(body, &cs)
	return cs, err
}

// ---------- HTTP helpers ----------

func do(hc *http.Client, req *http.Request) ([]byte, error) {
	resp, err := hc.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, truncate(string(body), 200))
	}
	return body, nil
}

func postJSON(hc *http.Client, req *http.Request, v interface{}) error {
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := hc.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode >= 400 {
		return fmt.Errorf("HTTP %d: %s", resp.StatusCode, truncate(string(body), 200))
	}
	return json.Unmarshal(body, v)
}

func apiGet(ctx context.Context, cfg Config, token, path string, v interface{}) error {
	req, err := http.NewRequestWithContext(ctx, "GET", cfg.APIBase+path, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	hc := &http.Client{Timeout: cfg.HTTPTimeout}
	body, err := do(hc, req)
	if err != nil {
		return err
	}
	return json.Unmarshal(body, v)
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}
