// Iris Dashboard — user portal for the PixelCity cloud.
//
// Serves the SPA (embedded), handles Keycloak (id.pixelcity.dev, realm pcid)
// OIDC login with PKCE and RS256 ID-token verification, proxies account
// management to the Keycloak Account REST API with the user's own token
// (including transparent access-token refresh), and implements plan / usage /
// billing against the Zoneless payments API using a server-side platform key.
//
// Deployed behind Caddy on dashboard.pixelcity.dev.
package main

import (
	"context"
	"crypto"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"embed"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"math/big"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

//go:embed web
var webFS embed.FS

type config struct {
	Listen        string
	Issuer        string // https://id.pixelcity.dev/realms/pcid
	ClientID      string
	ClientSecret  string
	RedirectURL   string // https://dashboard.pixelcity.dev/auth/callback
	PaymentsBase  string // http://zoneless-api:3333 (docker network) or public URL
	PaymentsKey   string // Zoneless platform API key (x-api-key), server-side only
	SessionSecret []byte
	CookieSecure  bool
	// Iris plan price IDs in Zoneless (one-time monthly/annual SKUs).
	PriceProMonthly string
	PriceProYearly  string
	PriceEntMonthly string
	PriceEntYearly  string
}

func loadConfig() config {
	c := config{
		Listen:          envOr("LISTEN", ":8080"),
		Issuer:          envOr("OIDC_ISSUER", "https://id.pixelcity.dev/realms/pcid"),
		ClientID:        envOr("OIDC_CLIENT_ID", "iris-dashboard"),
		ClientSecret:    os.Getenv("OIDC_CLIENT_SECRET"),
		RedirectURL:     envOr("OIDC_REDIRECT_URL", "https://dashboard.pixelcity.dev/auth/callback"),
		PaymentsBase:    envOr("PAYMENTS_BASE", "https://payments.pixelcity.dev"),
		PaymentsKey:     os.Getenv("PAYMENTS_API_KEY"),
		CookieSecure:    envOr("COOKIE_SECURE", "true") == "true",
		PriceProMonthly: os.Getenv("PRICE_PRO_MONTHLY"),
		PriceProYearly:  os.Getenv("PRICE_PRO_YEARLY"),
		PriceEntMonthly: os.Getenv("PRICE_ENT_MONTHLY"),
		PriceEntYearly:  os.Getenv("PRICE_ENT_YEARLY"),
	}
	secret := os.Getenv("SESSION_SECRET")
	if secret == "" {
		log.Fatal("SESSION_SECRET is required (openssl rand -hex 32)")
	}
	c.SessionSecret = []byte(secret)
	return c
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

// ---------- OIDC helpers ----------

type idTokenClaims struct {
	Sub               string   `json:"sub"`
	PreferredUsername string   `json:"preferred_username"`
	Email             string   `json:"email"`
	Name              string   `json:"name"`
	Groups            []string `json:"groups"`
	RealmAccess       struct {
		Roles []string `json:"roles"`
	} `json:"realm_access"`
	Aud any    `json:"aud"`
	Iss string `json:"iss"`
	Exp int64  `json:"exp"`
}

type discovery struct {
	AuthEndpoint  string `json:"authorization_endpoint"`
	TokenEndpoint string `json:"token_endpoint"`
	UserinfoEp    string `json:"userinfo_endpoint"`
	LogoutEp      string `json:"end_session_endpoint"`
	JWKSURI       string `json:"jwks_uri"`
}

func discoveryURL(issuer string) string {
	return strings.TrimSuffix(issuer, "/") + "/.well-known/openid-configuration"
}

func fetchDiscovery(ctx context.Context, issuer string) (*discovery, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", discoveryURL(issuer), nil)
	if err != nil {
		return nil, err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	var d discovery
	if err := json.Unmarshal(body, &d); err != nil {
		return nil, fmt.Errorf("discovery parse failed: %w", err)
	}
	return &d, nil
}

// ---------- JWKS signature verification ----------

type jwkSet struct {
	Keys []struct {
		Kid string `json:"kid"`
		Kty string `json:"kty"`
		Alg string `json:"alg"`
		Use string `json:"use"`
		N   string `json:"n"`
		E   string `json:"e"`
	} `json:"keys"`
}

type jwksCache struct {
	mu      sync.Mutex
	uri     string
	keys    map[string]*rsa.PublicKey
	fetched time.Time
}

func (c *jwksCache) get(ctx context.Context, kid string) (*rsa.PublicKey, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if time.Since(c.fetched) > time.Hour || c.keys == nil {
		if err := c.refreshLocked(ctx); err != nil {
			return nil, err
		}
	}
	if k, ok := c.keys[kid]; ok {
		return k, nil
	}
	// Unknown kid: key rotation — refresh once and retry.
	if err := c.refreshLocked(ctx); err != nil {
		return nil, err
	}
	if k, ok := c.keys[kid]; ok {
		return k, nil
	}
	return nil, fmt.Errorf("unknown signing key %q", kid)
}

func (c *jwksCache) refreshLocked(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, "GET", c.uri, nil)
	if err != nil {
		return err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return err
	}
	var set jwkSet
	if err := json.Unmarshal(body, &set); err != nil {
		return err
	}
	keys := map[string]*rsa.PublicKey{}
	for _, k := range set.Keys {
		if k.Kty != "RSA" || k.N == "" || k.E == "" {
			continue
		}
		nb, err := base64.RawURLEncoding.DecodeString(k.N)
		if err != nil {
			continue
		}
		eb, err := base64.RawURLEncoding.DecodeString(k.E)
		if err != nil {
			continue
		}
		e := 0
		for _, b := range eb {
			e = e<<8 + int(b)
		}
		keys[k.Kid] = &rsa.PublicKey{N: new(big.Int).SetBytes(nb), E: e}
	}
	c.keys = keys
	c.fetched = time.Now()
	return nil
}

// verifyIDToken checks RS256 signature, issuer, audience, and expiry.
// Any of the accepted audiences passes (login needs the dashboard client;
// CLI bearer tokens may carry iris-cli or account).
func verifyIDToken(ctx context.Context, jwks *jwksCache, raw, issuer string, audiences []string) (idTokenClaims, error) {
	var zero idTokenClaims
	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		return zero, errors.New("malformed token")
	}
	var header struct {
		Alg string `json:"alg"`
		Kid string `json:"kid"`
	}
	hb, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return zero, errors.New("malformed token header")
	}
	if err := json.Unmarshal(hb, &header); err != nil {
		return zero, errors.New("malformed token header")
	}
	if header.Alg != "RS256" {
		return zero, fmt.Errorf("unexpected alg %q", header.Alg)
	}
	pub, err := jwks.get(ctx, header.Kid)
	if err != nil {
		return zero, err
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return zero, errors.New("malformed token signature")
	}
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if err := rsa.VerifyPKCS1v15(pub, crypto.SHA256, digest[:], sig); err != nil {
		return zero, errors.New("invalid token signature")
	}
	pb, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return zero, errors.New("malformed token claims")
	}
	var c idTokenClaims
	if err := json.Unmarshal(pb, &c); err != nil {
		return zero, errors.New("malformed token claims")
	}
	if c.Iss != issuer {
		return zero, errors.New("unexpected token issuer")
	}
	want := map[string]bool{}
	for _, a := range audiences {
		want[a] = true
	}
	audOK := false
	switch a := c.Aud.(type) {
	case string:
		audOK = want[a]
	case []interface{}:
		for _, v := range a {
			if s, ok := v.(string); ok && want[s] {
				audOK = true
				break
			}
		}
	}
	if !audOK {
		return zero, errors.New("unexpected token audience")
	}
	if c.Exp != 0 && time.Now().Unix() > c.Exp+60 {
		return zero, errors.New("token expired")
	}
	if c.Sub == "" {
		return zero, errors.New("token has no subject")
	}
	return c, nil
}

// ---------- session cookie (HMAC-signed, minimal) ----------

type session struct {
	Sub          string   `json:"sub"`
	Username     string   `json:"username"`
	Email        string   `json:"email"`
	Groups       []string `json:"groups,omitempty"`
	Roles        []string `json:"roles,omitempty"`
	Exp          int64    `json:"exp"`
	AccessToken  string   `json:"access_token,omitempty"`
	RefreshToken string   `json:"refresh_token,omitempty"`
}

// isAdmin reports dashboard-admin membership (Keycloak group or realm role).
func isAdmin(sess *session) bool {
	want := map[string]bool{}
	for _, g := range strings.Split(os.Getenv("ADMIN_GROUPS"), ",") {
		if g = strings.TrimSpace(g); g != "" {
			want[g] = true
		}
	}
	if len(want) == 0 {
		want["iris-admins"] = true
	}
	for _, g := range sess.Groups {
		if want[g] {
			return true
		}
	}
	for _, r := range sess.Roles {
		if want[r] {
			return true
		}
	}
	return false
}

func signSession(s *session, secret []byte) (string, error) {
	data, err := json.Marshal(s)
	if err != nil {
		return "", err
	}
	payload := base64.RawURLEncoding.EncodeToString(data)
	mac := sha256.Sum256(append(secret, payload...))
	return payload + "." + base64.RawURLEncoding.EncodeToString(mac[:]), nil
}

func verifySession(cookie, secret []byte) (*session, error) {
	parts := strings.Split(string(cookie), ".")
	if len(parts) != 2 {
		return nil, errors.New("malformed session")
	}
	mac := sha256.Sum256(append(secret, []byte(parts[0])...))
	if subtle(parts[1], base64.RawURLEncoding.EncodeToString(mac[:])) {
		var s session
		data, err := base64.RawURLEncoding.DecodeString(parts[0])
		if err != nil {
			return nil, err
		}
		if err := json.Unmarshal(data, &s); err != nil {
			return nil, err
		}
		if time.Now().Unix() > s.Exp {
			return nil, errors.New("session expired")
		}
		return &s, nil
	}
	return nil, errors.New("bad signature")
}

func subtle(a, b string) bool { return hmac.Equal([]byte(a), []byte(b)) } // constant-time compare

// ---------- handlers ----------

type server struct {
	cfg   config
	dsc   *discovery
	jwks  *jwksCache
	scans *scanStore
}

// bearerIdentity validates a CLI Keycloak access token (aud: iris-cli,
// iris-dashboard, or account) and returns the caller's identity.
func (s *server) bearerIdentity(r *http.Request) (*session, error) {
	h := r.Header.Get("Authorization")
	if h == "" || !strings.HasPrefix(strings.ToLower(h), "bearer ") {
		return nil, errors.New("missing bearer token")
	}
	token := strings.TrimSpace(h[len("Bearer "):])
	if token == "" {
		return nil, errors.New("missing bearer token")
	}
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	claims, err := verifyIDToken(ctx, s.jwks, token, s.cfg.Issuer,
		[]string{"iris-cli", s.cfg.ClientID, "account"})
	if err != nil {
		return nil, err
	}
	return &session{
		Sub:      claims.Sub,
		Username: orDefault(claims.PreferredUsername, claims.Email),
		Email:    claims.Email,
		Groups:   claims.Groups,
		Roles:    claims.RealmAccess.Roles,
		Exp:      time.Now().Add(5 * time.Minute).Unix(),
	}, nil
}

func (s *server) handleScansPost(w http.ResponseWriter, r *http.Request) {
	ident, err := s.bearerIdentity(r)
	if err != nil {
		writeErr(w, http.StatusUnauthorized, err)
		return
	}
	// Enforce the plan's scan quota; fail open when billing is not
	// configured (a payments outage must never lose scans).
	if err := s.paymentsConfigured(); err == nil {
		tier := s.planTier(r.Context(), ident)
		quota, _, _ := tierQuotas(tier)
		if qerr := checkScanQuota(s.scans.count(ident.Sub), quota, tier); qerr != nil {
			writeErr(w, http.StatusPaymentRequired, qerr)
			return
		}
	}
	var payload struct {
		scanEntry
		Report json.RawMessage `json:"report,omitempty"`
	}
	// Metadata + up to 8MB report + JSON envelope overhead.
	body, err := io.ReadAll(io.LimitReader(r.Body, maxReportBytes+(1<<20)))
	if err != nil {
		writeErr(w, http.StatusBadRequest, errors.New("unreadable body"))
		return
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		writeErr(w, http.StatusBadRequest, errors.New("invalid JSON"))
		return
	}
	e := payload.scanEntry
	e.Sub = ident.Sub
	e.Username = ident.Username
	e.Email = ident.Email
	if err := sanitizeScanInput(&e); err != nil {
		writeErr(w, http.StatusUnprocessableEntity, err)
		return
	}
	e.ID = fmt.Sprintf("%d-%s", time.Now().UnixNano(), randHex(4))

	// Full report: stored separately; oversized reports are marked omitted.
	if len(payload.Report) > 0 && string(payload.Report) != "null" {
		if len(payload.Report) > maxReportBytes {
			e.ReportOmitted = true
		} else if err := s.scans.saveReport(e.ID, payload.Report); err == nil {
			e.ReportBytes = len(payload.Report)
		} else {
			e.ReportOmitted = true
		}
	}
	if err := s.scans.append(e); err != nil {
		writeErr(w, http.StatusInternalServerError, errors.New("could not store scan"))
		return
	}
	writeJSON(w, map[string]interface{}{
		"ok": true, "id": e.ID,
		"report_bytes": e.ReportBytes, "report_omitted": e.ReportOmitted,
	})
}

// handleScanGet returns one scan with its full report. Owner or admin only.
func (s *server) handleScanGet(w http.ResponseWriter, r *http.Request) {
	ident, err := s.requestIdentity(r)
	if err != nil {
		writeErr(w, http.StatusUnauthorized, err)
		return
	}
	id := r.PathValue("id")
	e, ok := s.scans.get(id)
	if !ok {
		writeErr(w, http.StatusNotFound, errors.New("scan not found"))
		return
	}
	if e.Sub != ident.Sub && !isAdmin(ident) {
		writeErr(w, http.StatusForbidden, errors.New("not your scan"))
		return
	}
	// Export modes: ?format=sarif|html|json downloads/renders the report.
	if format := strings.TrimSpace(r.URL.Query().Get("format")); format != "" {
		s.exportScan(w, &e, format)
		return
	}
	resp := map[string]interface{}{"entry": e, "report": nil}
	if e.ReportBytes > 0 {
		data, err := s.scans.loadReport(e.ID)
		if err == nil {
			resp["report"] = json.RawMessage(data)
		}
	}
	writeJSON(w, resp)
}

// exportScan serves the stored report as SARIF, HTML, or raw JSON.
func (s *server) exportScan(w http.ResponseWriter, e *scanEntry, format string) {
	if e.ReportBytes <= 0 {
		writeErr(w, http.StatusNotFound, errors.New("no stored report for this scan"))
		return
	}
	data, err := s.scans.loadReport(e.ID)
	if err != nil {
		writeErr(w, http.StatusNotFound, err)
		return
	}
	switch format {
	case "json":
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.Header().Set("Content-Disposition",
			fmt.Sprintf("attachment; filename=%q", "iris-scan-"+e.ID+".json"))
		w.Header().Set("Content-Length", strconv.Itoa(len(data)))
		_, _ = w.Write(data)
	case "sarif":
		doc, err := parseReport(data)
		if err != nil {
			writeErr(w, http.StatusInternalServerError, errors.New("stored report is corrupt"))
			return
		}
		out, err := sarifFromReport(e, doc)
		if err != nil {
			writeErr(w, http.StatusInternalServerError, errors.New("could not render SARIF"))
			return
		}
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.Header().Set("Content-Disposition",
			fmt.Sprintf("attachment; filename=%q", "iris-scan-"+e.ID+".sarif"))
		w.Header().Set("Content-Length", strconv.Itoa(len(out)))
		_, _ = w.Write(out)
	case "html":
		doc, err := parseReport(data)
		if err != nil {
			writeErr(w, http.StatusInternalServerError, errors.New("stored report is corrupt"))
			return
		}
		out := htmlFromReport(e, doc)
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Content-Length", strconv.Itoa(len(out)))
		_, _ = w.Write(out)
	default:
		writeErr(w, http.StatusBadRequest, errors.New("unknown format (use sarif, html, or json)"))
	}
}

func (s *server) handleScansGet(w http.ResponseWriter, r *http.Request) {
	ident, err := s.requestIdentity(r)
	if err != nil {
		writeErr(w, http.StatusUnauthorized, err)
		return
	}
	limit := atoiQuery(r, "limit", 50)
	entries := s.scans.list(ident.Sub, limit)
	if entries == nil {
		entries = []scanEntry{}
	}
	writeJSON(w, map[string]interface{}{"entries": entries, "total": s.scans.count(ident.Sub)})
}

// requestIdentity resolves the caller from a bearer token (CLI) or the
// ds_session cookie (browser). Used by read APIs shared by both.
func (s *server) requestIdentity(r *http.Request) (*session, error) {
	if strings.TrimSpace(r.Header.Get("Authorization")) != "" {
		return s.bearerIdentity(r)
	}
	c, err := r.Cookie("ds_session")
	if err != nil {
		return nil, errors.New("not logged in")
	}
	sess, err := verifySession([]byte(c.Value), s.cfg.SessionSecret)
	if err != nil {
		return nil, err
	}
	return sess, nil
}

// authEither accepts a session cookie (browser) or a bearer token (CLI).
func (s *server) authEither(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		sess, err := s.requestIdentity(r)
		if err != nil {
			writeErr(w, http.StatusUnauthorized, err)
			return
		}
		next(w, r.WithContext(context.WithValue(r.Context(), sessKey{}, *sess)))
	}
}

func (s *server) requireAdmin(next http.HandlerFunc) http.HandlerFunc {
	return s.authEither(func(w http.ResponseWriter, r *http.Request) {
		sess := r.Context().Value(sessKey{}).(session)
		if !isAdmin(&sess) {
			writeErr(w, http.StatusForbidden, errors.New("admin only"))
			return
		}
		next(w, r)
	})
}

// handleTrend serves the caller's daily scan/findings activity.
func (s *server) handleTrend(w http.ResponseWriter, r *http.Request) {
	ident, err := s.requestIdentity(r)
	if err != nil {
		writeErr(w, http.StatusUnauthorized, err)
		return
	}
	s.writeTrend(w, r, ident.Sub, false)
}

// handleAdminTrend serves activity across every user (admin only).
func (s *server) handleAdminTrend(w http.ResponseWriter, r *http.Request) {
	sess := r.Context().Value(sessKey{}).(session)
	s.writeTrend(w, r, sess.Sub, true)
}

func (s *server) writeTrend(w http.ResponseWriter, r *http.Request, sub string, allUsers bool) {
	days := atoiQuery(r, "days", 30)
	if days > 365 {
		days = 365
	}
	since := time.Now().UTC().AddDate(0, 0, -days)
	points := s.scans.trend(sub, since, allUsers)
	if points == nil {
		points = []trendPoint{}
	}
	writeJSON(w, map[string]interface{}{"days": days, "points": points})
}

func (s *server) handleAdminScans(w http.ResponseWriter, r *http.Request) {
	limit := atoiQuery(r, "limit", 100)
	user := r.URL.Query().Get("user")
	entries := s.scans.listAll(limit, user)
	if entries == nil {
		entries = []scanEntry{}
	}
	writeJSON(w, map[string]interface{}{"entries": entries, "total": s.scans.countFiltered(user)})
}

func (s *server) handleAdminUsers(w http.ResponseWriter, r *http.Request) {
	users := s.scans.userStats()
	if users == nil {
		users = []map[string]interface{}{}
	}
	writeJSON(w, map[string]interface{}{"users": users, "total": len(users)})
}

func atoiQuery(r *http.Request, key string, def int) int {
	var n int
	if _, err := fmt.Sscanf(r.URL.Query().Get(key), "%d", &n); err != nil || n <= 0 {
		return def
	}
	return n
}

func randHex(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "0000"
	}
	const hexd = "0123456789abcdef"
	out := make([]byte, 0, n*2)
	for _, v := range b {
		out = append(out, hexd[v>>4], hexd[v&15])
	}
	return string(out)
}

// accessLog emits one line per request: method, path, status, duration.
// Paths only (no query strings) so OAuth codes never reach the log.
func accessLog(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		lw := &statusWriter{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(lw, r)
		log.Printf("%s %s -> %d (%s)", r.Method, r.URL.Path, lw.status,
			time.Since(start).Round(time.Millisecond))
	})
}

type statusWriter struct {
	http.ResponseWriter
	status int
}

func (w *statusWriter) WriteHeader(code int) {
	w.status = code
	w.ResponseWriter.WriteHeader(code)
}

func main() {
	ver := flag.Bool("version", false, "print version")
	flag.Parse()
	if *ver {
		fmt.Println("iris-dashboard 1.0.0")
		return
	}

	cfg := loadConfig()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	dsc, err := fetchDiscovery(ctx, cfg.Issuer)
	cancel()
	if err != nil {
		log.Fatalf("OIDC discovery failed for %s: %v (is Keycloak up?)", cfg.Issuer, err)
	}

	srv := &server{
		cfg:   cfg,
		dsc:   dsc,
		jwks:  &jwksCache{uri: dsc.JWKSURI},
		scans: newScanStore(os.Getenv("SCANS_FILE")),
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /auth/login", srv.handleLogin)
	mux.HandleFunc("GET /auth/callback", srv.handleCallback)
	mux.HandleFunc("GET /auth/logout", srv.handleLogout)
	mux.HandleFunc("GET /api/v1/me", srv.authEither(srv.handleMe))
	mux.HandleFunc("GET /api/v1/scans", srv.handleScansGet)
	mux.HandleFunc("GET /api/v1/scans/trend", srv.handleTrend)
	mux.HandleFunc("GET /api/v1/scans/{id}", srv.handleScanGet)
	mux.HandleFunc("POST /api/v1/scans", srv.handleScansPost)
	mux.HandleFunc("GET /api/v1/admin/scans", srv.requireAdmin(srv.handleAdminScans))
	mux.HandleFunc("GET /api/v1/admin/users", srv.requireAdmin(srv.handleAdminUsers))
	mux.HandleFunc("GET /api/v1/admin/trend", srv.requireAdmin(srv.handleAdminTrend))
	mux.HandleFunc("GET /api/v1/account", srv.auth(srv.handleAccountGet))
	mux.HandleFunc("PATCH /api/v1/account", srv.auth(srv.handleAccountPatch))
	mux.HandleFunc("POST /api/v1/account/password", srv.auth(srv.handlePasswordChange))
	mux.HandleFunc("GET /api/v1/account/sessions", srv.auth(srv.handleSessionsList))
	mux.HandleFunc("DELETE /api/v1/account/sessions/{id}", srv.auth(srv.handleSessionRevoke))
	mux.HandleFunc("GET /api/v1/plan", srv.authEither(srv.handlePlan))
	mux.HandleFunc("GET /api/v1/usage", srv.auth(srv.handleUsage))
	mux.HandleFunc("POST /api/v1/billing/checkout", srv.auth(srv.handleCheckout))
	mux.HandleFunc("GET /", srv.handleIndex)

	log.Printf("Iris dashboard listening on %s (issuer=%s, redirect=%s)",
		cfg.Listen, cfg.Issuer, cfg.RedirectURL)
	log.Fatal(http.ListenAndServe(cfg.Listen, accessLog(mux)))
}

func (s *server) handleLogin(w http.ResponseWriter, r *http.Request) {
	state, _ := randBytes(16)
	verifier, _ := randBytes(32)
	challenge := s256Challenge(verifier)

	http.SetCookie(w, &http.Cookie{
		Name: "oauth_state", Value: state, Path: "/",
		MaxAge: 600, HttpOnly: true, Secure: s.cfg.CookieSecure, SameSite: http.SameSiteLaxMode,
	})
	http.SetCookie(w, &http.Cookie{
		Name: "oauth_verifier", Value: verifier, Path: "/",
		MaxAge: 600, HttpOnly: true, Secure: s.cfg.CookieSecure, SameSite: http.SameSiteLaxMode,
	})

	q := url.Values{}
	q.Set("client_id", s.cfg.ClientID)
	q.Set("redirect_uri", s.cfg.RedirectURL)
	q.Set("response_type", "code")
	q.Set("scope", "openid profile email")
	q.Set("state", state)
	q.Set("code_challenge", challenge)
	q.Set("code_challenge_method", "S256")
	http.Redirect(w, r, s.dsc.AuthEndpoint+"?"+q.Encode(), http.StatusFound)
}

func (s *server) handleCallback(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	if q.Get("state") == "" || !sameCookie(r, "oauth_state", q.Get("state")) {
		http.Error(w, "invalid OAuth state", http.StatusBadRequest)
		return
	}
	verifier, err := r.Cookie("oauth_verifier")
	if err != nil {
		http.Error(w, "missing PKCE verifier", http.StatusBadRequest)
		return
	}

	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {q.Get("code")},
		"redirect_uri":  {s.cfg.RedirectURL},
		"client_id":     {s.cfg.ClientID},
		"code_verifier": {verifier.Value},
	}
	if s.cfg.ClientSecret != "" {
		form.Set("client_secret", s.cfg.ClientSecret)
	}

	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()
	tok, err := http.PostForm(s.dsc.TokenEndpoint, form)
	if err != nil {
		http.Error(w, "token exchange failed: "+err.Error(), http.StatusBadGateway)
		return
	}
	defer tok.Body.Close()
	var tr struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		IDToken      string `json:"id_token"`
		ExpiresIn    int    `json:"expires_in"`
	}
	if err := json.NewDecoder(io.LimitReader(tok.Body, 1<<20)).Decode(&tr); err != nil || tr.AccessToken == "" {
		http.Error(w, "token parse failed", http.StatusBadGateway)
		return
	}
	if tr.IDToken == "" {
		http.Error(w, "identity provider did not return an ID token", http.StatusBadGateway)
		return
	}

	// Verify the ID token signature — never trust unverified claims.
	claims, err := verifyIDToken(ctx, s.jwks, tr.IDToken, s.cfg.Issuer, []string{s.cfg.ClientID})
	if err != nil {
		http.Error(w, "identity verification failed", http.StatusBadGateway)
		return
	}

	sess := session{
		Sub:          claims.Sub,
		Username:     orDefault(claims.PreferredUsername, claims.Email),
		Email:        claims.Email,
		Groups:       claims.Groups,
		Roles:        claims.RealmAccess.Roles,
		Exp:          time.Now().Add(12 * time.Hour).Unix(),
		AccessToken:  tr.AccessToken,
		RefreshToken: tr.RefreshToken,
	}
	val, err := signSession(&sess, s.cfg.SessionSecret)
	if err != nil {
		http.Error(w, "session sign failed", http.StatusInternalServerError)
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name: "ds_session", Value: val, Path: "/",
		MaxAge: 12 * 3600, HttpOnly: true, Secure: s.cfg.CookieSecure, SameSite: http.SameSiteLaxMode,
	})
	// clear oauth cookies
	http.SetCookie(w, &http.Cookie{Name: "oauth_state", Value: "", MaxAge: -1, Path: "/"})
	http.SetCookie(w, &http.Cookie{Name: "oauth_verifier", Value: "", MaxAge: -1, Path: "/"})
	http.Redirect(w, r, "/", http.StatusFound)
}

func (s *server) handleLogout(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{Name: "ds_session", Value: "", MaxAge: -1, Path: "/"})
	http.Redirect(w, r, s.dsc.LogoutEp+"?redirect_uri="+url.QueryEscape(s.cfg.RedirectURL), http.StatusFound)
}

func (s *server) handleMe(w http.ResponseWriter, r *http.Request) {
	sess := r.Context().Value(sessKey{}).(session)
	writeJSON(w, map[string]interface{}{
		"username": sess.Username,
		"email":    sess.Email,
		"admin":    isAdmin(&sess),
	})
}

// ---------- Keycloak Account API proxy (user's own token) ----------

func (s *server) accountBase() string {
	return strings.TrimSuffix(s.cfg.Issuer, "/") + "/account/"
}

// accountDo performs an Account API call with the user's access token,
// refreshing once on 401.
func (s *server) accountDo(w http.ResponseWriter, r *http.Request, method, path string, body io.Reader) {
	sess := r.Context().Value(sessKey{}).(session)
	status, respBody := s.accountCall(r.Context(), sess.AccessToken, method, path, body)
	if status == http.StatusUnauthorized && sess.RefreshToken != "" {
		if fresh, err := s.refreshAccessToken(r.Context(), sess.RefreshToken); err == nil {
			sess.AccessToken = fresh.AccessToken
			if c, cerr := r.Cookie("ds_session"); cerr == nil {
				_ = c
			}
			// Persist refreshed tokens back into the session cookie.
			ns := sess
			ns.AccessToken = fresh.AccessToken
			if fresh.RefreshToken != "" {
				ns.RefreshToken = fresh.RefreshToken
			}
			if val, serr := signSession(&ns, s.cfg.SessionSecret); serr == nil {
				http.SetCookie(w, &http.Cookie{
					Name: "ds_session", Value: val, Path: "/",
					MaxAge: 12 * 3600, HttpOnly: true, Secure: s.cfg.CookieSecure, SameSite: http.SameSiteLaxMode,
				})
			}
			status, respBody = s.accountCall(r.Context(), ns.AccessToken, method, path, body)
		}
	}
	if status == 0 {
		writeErr(w, http.StatusBadGateway, errors.New("account service unreachable"))
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write(respBody)
}

func (s *server) accountCall(ctx context.Context, token, method, path string, body io.Reader) (int, []byte) {
	var br io.Reader
	var buf []byte
	if body != nil {
		var err error
		buf, err = io.ReadAll(io.LimitReader(body, 1<<20))
		if err != nil {
			return 0, nil
		}
		br = strings.NewReader(string(buf))
	}
	req, err := http.NewRequestWithContext(ctx, method, s.accountBase()+strings.TrimPrefix(path, "/"), br)
	if err != nil {
		return 0, nil
	}
	req.Header.Set("Authorization", "Bearer "+token)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return 0, nil
	}
	defer resp.Body.Close()
	out, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return 0, nil
	}
	return resp.StatusCode, out
}

func (s *server) refreshAccessToken(ctx context.Context, refreshToken string) (struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
}, error,
) {
	var out struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
	}
	form := url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {refreshToken},
		"client_id":     {s.cfg.ClientID},
	}
	if s.cfg.ClientSecret != "" {
		form.Set("client_secret", s.cfg.ClientSecret)
	}
	req, err := http.NewRequestWithContext(ctx, "POST", s.dsc.TokenEndpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return out, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return out, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return out, fmt.Errorf("refresh rejected (HTTP %d)", resp.StatusCode)
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&out); err != nil {
		return out, err
	}
	if out.AccessToken == "" {
		return out, errors.New("refresh returned no token")
	}
	return out, nil
}

func (s *server) handleAccountGet(w http.ResponseWriter, r *http.Request) {
	s.accountDo(w, r, "GET", "/", nil)
}

func (s *server) handleAccountPatch(w http.ResponseWriter, r *http.Request) {
	s.accountDo(w, r, "POST", "/", r.Body)
}

func (s *server) handlePasswordChange(w http.ResponseWriter, r *http.Request) {
	s.accountDo(w, r, "POST", "/credentials/password", r.Body)
}

func (s *server) handleSessionsList(w http.ResponseWriter, r *http.Request) {
	s.accountDo(w, r, "GET", "/sessions", nil)
}

func (s *server) handleSessionRevoke(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if id == "" {
		writeErr(w, http.StatusBadRequest, errors.New("session id required"))
		return
	}
	s.accountDo(w, r, "DELETE", "/sessions/"+url.PathEscape(id), nil)
}

// ---------- Zoneless billing layer (platform service key) ----------

func (s *server) paymentsConfigured() error {
	if s.cfg.PaymentsKey == "" {
		return errors.New("billing is not configured (PAYMENTS_API_KEY)")
	}
	return nil
}

func (s *server) zapi(ctx context.Context, method, path string, body io.Reader) (int, []byte, error) {
	req, err := http.NewRequestWithContext(ctx, method,
		strings.TrimSuffix(s.cfg.PaymentsBase, "/")+path, body)
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("x-api-key", s.cfg.PaymentsKey)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	out, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return 0, nil, err
	}
	return resp.StatusCode, out, nil
}

func (s *server) zget(ctx context.Context, path string) (int, []byte, error) {
	return s.zapi(ctx, "GET", path, nil)
}

func (s *server) zpostJSON(ctx context.Context, path string, v interface{}) (int, []byte, error) {
	buf, err := json.Marshal(v)
	if err != nil {
		return 0, nil, err
	}
	return s.zapi(ctx, "POST", path, strings.NewReader(string(buf)))
}

type zCustomer struct {
	ID    string `json:"id"`
	Email string `json:"email"`
}

// ensureCustomer finds the Zoneless customer by email or creates one.
func (s *server) ensureCustomer(ctx context.Context, email, name string) (string, error) {
	st, body, err := s.zget(ctx, "/v1/customers?email="+url.QueryEscape(email))
	if err != nil {
		return "", err
	}
	if st == 200 {
		var list struct {
			Data []zCustomer `json:"data"`
		}
		if json.Unmarshal(body, &list) == nil {
			for _, c := range list.Data {
				if strings.EqualFold(c.Email, email) && c.ID != "" {
					return c.ID, nil
				}
			}
		}
	}
	st, body, err = s.zpostJSON(ctx, "/v1/customers", map[string]interface{}{
		"email": email, "name": name,
	})
	if err != nil {
		return "", err
	}
	if st != 200 && st != 201 {
		return "", fmt.Errorf("customer create failed (HTTP %d)", st)
	}
	var c zCustomer
	if err := json.Unmarshal(body, &c); err != nil || c.ID == "" {
		return "", errors.New("customer create returned no id")
	}
	return c.ID, nil
}

type zSession struct {
	ID            string `json:"id"`
	Status        string `json:"status"`
	PaymentStatus string `json:"payment_status"`
	AmountTotal   int    `json:"amount_total"`
	Currency      string `json:"currency"`
	Created       int64  `json:"created"`
	URL           string `json:"url"`
}

type zLineItem struct {
	ID     string `json:"id"`
	Price  string `json:"price"`
	Amount int    `json:"amount_total"`
}

// priceIDSet maps configured Iris price IDs for tier matching.
func (s *server) priceTiers() map[string]string {
	m := map[string]string{}
	if s.cfg.PriceProMonthly != "" {
		m[s.cfg.PriceProMonthly] = "pro"
	}
	if s.cfg.PriceProYearly != "" {
		m[s.cfg.PriceProYearly] = "pro"
	}
	if s.cfg.PriceEntMonthly != "" {
		m[s.cfg.PriceEntMonthly] = "enterprise"
	}
	if s.cfg.PriceEntYearly != "" {
		m[s.cfg.PriceEntYearly] = "enterprise"
	}
	return m
}

// resolveTier finds the highest active tier from paid sessions in window.
func (s *server) resolveTier(ctx context.Context, customerID string) (string, error) {
	tiers := s.priceTiers()
	if len(tiers) == 0 {
		return "free", nil
	}
	st, body, err := s.zget(ctx, "/v1/checkout/sessions?customer="+url.QueryEscape(customerID)+"&limit=50")
	if err != nil || st != 200 {
		if err != nil {
			return "free", err
		}
		return "free", fmt.Errorf("sessions list failed (HTTP %d)", st)
	}
	var list struct {
		Data []zSession `json:"data"`
	}
	if err := json.Unmarshal(body, &list); err != nil {
		return "free", err
	}
	now := time.Now().Unix()
	best := "free"
	rank := map[string]int{"free": 0, "pro": 1, "enterprise": 2}
	for _, sess := range list.Data {
		if sess.PaymentStatus != "paid" {
			continue
		}
		created := sess.Created
		if created == 0 {
			continue
		}
		st2, lb, err := s.zget(ctx, "/v1/checkout/sessions/"+url.PathEscape(sess.ID)+"/line_items")
		if err != nil || st2 != 200 {
			continue
		}
		var lines struct {
			Data []zLineItem `json:"data"`
		}
		if json.Unmarshal(lb, &lines) != nil {
			continue
		}
		for _, li := range lines.Data {
			tier, ok := tiers[li.Price]
			if !ok {
				continue
			}
			window := int64(31 * 86400)
			// Yearly prices grant a 366-day window.
			if isYearlyPrice(s, li.Price) {
				window = int64(366 * 86400)
			}
			if now-created < window && rank[tier] > rank[best] {
				best = tier
			}
		}
	}
	return best, nil
}

func isYearlyPrice(s *server, priceID string) bool {
	return priceID == s.cfg.PriceProYearly || priceID == s.cfg.PriceEntYearly
}

func tierQuotas(tier string) (scans, aiPages int, name string) {
	switch tier {
	case "enterprise":
		return 10000, 5000, "Enterprise"
	case "pro":
		return 1000, 500, "Pro"
	default:
		return 100, 0, "Free"
	}
}

func (s *server) handlePlan(w http.ResponseWriter, r *http.Request) {
	sess := r.Context().Value(sessKey{}).(session)
	ctx := r.Context()
	tier := s.planTier(ctx, &sess)
	scans, aiPages, name := tierQuotas(tier)
	writeJSON(w, map[string]interface{}{
		"tier": tier, "name": name,
		"scan_quota": scans, "scans_used": s.scans.count(sess.Sub),
		"ai_pages_quota": aiPages, "ai_pages_used": 0,
	})
}

// planTier resolves the caller's billing tier, defaulting to free on
// any billing error (never blocks the product on payments outages).
func (s *server) planTier(ctx context.Context, sess *session) string {
	tier := "free"
	if err := s.paymentsConfigured(); err == nil && sess.Email != "" {
		if customerID, err := s.ensureCustomer(ctx, sess.Email, sess.Username); err == nil {
			if t, err := s.resolveTier(ctx, customerID); err == nil {
				tier = t
			}
		}
	}
	return tier
}

// checkScanQuota rejects scans once the plan's scan quota is exhausted.
// quota <= 0 disables enforcement.
func checkScanQuota(used, quota int, tier string) error {
	if quota <= 0 || used < quota {
		return nil
	}
	return fmt.Errorf("scan quota reached (%d/%d) on the %s plan — upgrade with 'iris cloud upgrade'", used, quota, tier)
}

func (s *server) handleUsage(w http.ResponseWriter, r *http.Request) {
	sess := r.Context().Value(sessKey{}).(session)
	ctx := r.Context()
	limit := r.URL.Query().Get("limit")
	if limit == "" {
		limit = "25"
	}
	if err := s.paymentsConfigured(); err != nil {
		writeJSON(w, map[string]interface{}{"entries": []interface{}{}, "total": 0})
		return
	}
	customerID, err := s.ensureCustomer(ctx, sess.Email, sess.Username)
	if err != nil || sess.Email == "" {
		writeJSON(w, map[string]interface{}{"entries": []interface{}{}, "total": 0})
		return
	}
	st, body, err := s.zget(ctx, "/v1/checkout/sessions?customer="+url.QueryEscape(customerID)+"&limit="+url.QueryEscape(limit))
	if err != nil || st != 200 {
		writeJSON(w, map[string]interface{}{"entries": []interface{}{}, "total": 0})
		return
	}
	var list struct {
		Data []zSession `json:"data"`
	}
	if err := json.Unmarshal(body, &list); err != nil {
		writeJSON(w, map[string]interface{}{"entries": []interface{}{}, "total": 0})
		return
	}
	tiers := s.priceTiers()
	entries := []interface{}{}
	for _, sess := range list.Data {
		label := "Wallet top-up"
		for _, pid := range sessionPriceIDs(ctx, s, sess.ID) {
			if t, ok := tiers[pid]; ok {
				label = "Iris " + t + " plan"
				break
			}
		}
		entries = append(entries, map[string]interface{}{
			"id": sess.ID, "date": sess.Created, "amount": sess.AmountTotal,
			"currency": sess.Currency, "status": sess.PaymentStatus, "label": label,
			"url": sess.URL,
		})
	}
	writeJSON(w, map[string]interface{}{"entries": entries, "total": len(entries)})
}

func sessionPriceIDs(ctx context.Context, s *server, sessionID string) []string {
	st, body, err := s.zget(ctx, "/v1/checkout/sessions/"+url.PathEscape(sessionID)+"/line_items")
	if err != nil || st != 200 {
		return nil
	}
	var lines struct {
		Data []zLineItem `json:"data"`
	}
	if json.Unmarshal(body, &lines) != nil {
		return nil
	}
	out := []string{}
	for _, li := range lines.Data {
		if li.Price != "" {
			out = append(out, li.Price)
		}
	}
	return out
}

func (s *server) handleCheckout(w http.ResponseWriter, r *http.Request) {
	sess := r.Context().Value(sessKey{}).(session)
	plan := r.FormValue("plan")
	interval := orDefault(r.FormValue("interval"), "monthly")
	if plan != "pro" && plan != "enterprise" {
		writeErr(w, http.StatusBadRequest, errors.New("plan must be pro or enterprise"))
		return
	}
	if err := s.paymentsConfigured(); err != nil {
		writeErr(w, http.StatusServiceUnavailable, err)
		return
	}
	var priceID string
	if plan == "pro" {
		priceID = s.cfg.PriceProMonthly
		if interval == "yearly" {
			priceID = s.cfg.PriceProYearly
		}
	} else {
		priceID = s.cfg.PriceEntMonthly
		if interval == "yearly" {
			priceID = s.cfg.PriceEntYearly
		}
	}
	if priceID == "" {
		writeErr(w, http.StatusServiceUnavailable, errors.New("plan pricing is not configured"))
		return
	}
	ctx := r.Context()
	customerID, err := s.ensureCustomer(ctx, sess.Email, sess.Username)
	if err != nil {
		writeErr(w, http.StatusBadGateway, err)
		return
	}
	st, body, err := s.zpostJSON(ctx, "/v1/checkout/sessions", map[string]interface{}{
		"mode":           "payment",
		"line_items":     []interface{}{map[string]interface{}{"price": priceID, "quantity": 1}},
		"customer":       customerID,
		"customer_email": sess.Email,
		"success_url":    "https://dashboard.pixelcity.dev/?checkout=success",
		"cancel_url":     "https://dashboard.pixelcity.dev/?checkout=cancelled",
		"metadata":       map[string]string{"plan": plan, "interval": interval, "keycloak_sub": sess.Sub},
	})
	if err != nil {
		writeErr(w, http.StatusBadGateway, err)
		return
	}
	if st != 200 && st != 201 {
		writeErr(w, http.StatusBadGateway, fmt.Errorf("checkout create failed (HTTP %d)", st))
		return
	}
	var created struct {
		ID  string `json:"id"`
		URL string `json:"url"`
	}
	if err := json.Unmarshal(body, &created); err != nil || created.URL == "" {
		writeErr(w, http.StatusBadGateway, errors.New("checkout returned no URL"))
		return
	}
	writeJSON(w, map[string]interface{}{"url": created.URL, "session_id": created.ID})
}

// ---------- middleware & utils ----------

type sessKey struct{}

func (s *server) auth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		c, err := r.Cookie("ds_session")
		if err != nil {
			writeErr(w, http.StatusUnauthorized, errors.New("not logged in"))
			return
		}
		sess, err := verifySession([]byte(c.Value), s.cfg.SessionSecret)
		if err != nil {
			writeErr(w, http.StatusUnauthorized, err)
			return
		}
		next(w, r.WithContext(context.WithValue(r.Context(), sessKey{}, *sess)))
	}
}

func (s *server) handleIndex(w http.ResponseWriter, r *http.Request) {
	if strings.HasPrefix(r.URL.Path, "/api/") || strings.HasPrefix(r.URL.Path, "/auth/") {
		http.NotFound(w, r)
		return
	}
	data, err := webFS.ReadFile("web/index.html")
	if err != nil {
		http.Error(w, "SPA not built — see deploy/web/README", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write(data)
}

func decodeJWTClaims(token string) (idTokenClaims, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return idTokenClaims{}, errors.New("not a JWT")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return idTokenClaims{}, err
	}
	var c idTokenClaims
	err = json.Unmarshal(payload, &c)
	return c, err
}

func s256Challenge(verifier string) string {
	h := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(h[:])
}

func randBytes(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func sameCookie(r *http.Request, name, val string) bool {
	c, err := r.Cookie(name)
	return err == nil && c.Value == val
}

func writeJSON(w http.ResponseWriter, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func writeRaw(w http.ResponseWriter, body []byte) {
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(body)
}

func writeErr(w http.ResponseWriter, code int, err error) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
}

func orDefault(v, def string) string {
	if v == "" {
		return def
	}
	return v
}
