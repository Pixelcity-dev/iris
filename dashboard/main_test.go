package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestSessionRoundTrip(t *testing.T) {
	secret := []byte("test-secret-0123456789abcdef-test")
	s := &session{Sub: "u1", Username: "alice", Email: "a@x.dev", Exp: 9999999999}
	signed, err := signSession(s, secret)
	if err != nil {
		t.Fatal(err)
	}
	got, err := verifySession([]byte(signed), secret)
	if err != nil {
		t.Fatal(err)
	}
	if got.Sub != "u1" || got.Username != "alice" {
		t.Fatalf("round trip mismatch: %+v", got)
	}
	if _, err := verifySession([]byte(signed), []byte("wrong-secret-0123456789abcdef-x")); err == nil {
		t.Fatal("wrong secret must fail")
	}
	if _, err := verifySession([]byte("garbage"), secret); err == nil {
		t.Fatal("malformed must fail")
	}
}

func TestVerifyBrowserRequestRequiresSameOriginForUnsafeMethods(t *testing.T) {
	tests := []struct {
		name       string
		method     string
		origin     string
		authorize  string
		wantReject bool
	}{
		{name: "same-origin post", method: http.MethodPost, origin: "https://dashboard.example.test", wantReject: false},
		{name: "insecure http origin", method: http.MethodPost, origin: "http://dashboard.example.test", wantReject: true},
		{name: "cross-origin post", method: http.MethodPost, origin: "https://attacker.example", wantReject: true},
		{name: "missing origin post", method: http.MethodPost, wantReject: true},
		{name: "malformed origin", method: http.MethodDelete, origin: "https://user@dashboard.example.test", wantReject: true},
		{name: "read request needs no origin", method: http.MethodGet, wantReject: false},
		{name: "bearer API request", method: http.MethodPost, authorize: "Bearer token", wantReject: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(tt.method, "https://dashboard.example.test/api/v1/account", nil)
			req.Host = "dashboard.example.test"
			if tt.origin != "" {
				req.Header.Set("Origin", tt.origin)
			}
			if tt.authorize != "" {
				req.Header.Set("Authorization", tt.authorize)
			}
			err := verifyBrowserRequest(req)
			if tt.wantReject && err == nil {
				t.Fatal("expected request to be rejected")
			}
			if !tt.wantReject && err != nil {
				t.Fatalf("request unexpectedly rejected: %v", err)
			}
		})
	}
}

func TestRequestIdentityRejectsCrossOriginAndMissingOrigin(t *testing.T) {
	srv := &server{cfg: config{SessionSecret: []byte("test-secret-0123456789abcdef-test")}}
	sessionCookie, err := signSession(&session{Sub: "u1", Username: "alice", Exp: 9999999999}, srv.cfg.SessionSecret)
	if err != nil {
		t.Fatal(err)
	}
	for _, origin := range []string{"", "http://dashboard.example.test", "https://attacker.example"} {
		req := httptest.NewRequest(http.MethodPost, "https://dashboard.example.test/api/v1/scans/bulk-delete", nil)
		req.Host = "dashboard.example.test"
		if origin != "" {
			req.Header.Set("Origin", origin)
		}
		req.AddCookie(&http.Cookie{Name: "iris_session", Value: sessionCookie})
		if _, err := srv.requestIdentity(req); err == nil {
			t.Fatalf("origin %q should be rejected", origin)
		}
	}
}

func TestSecurityHeadersMiddleware(t *testing.T) {
	handler := securityHeaders(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/", nil))
	for _, header := range []string{
		"Content-Security-Policy",
		"X-Content-Type-Options",
		"X-Frame-Options",
		"Referrer-Policy",
		"Permissions-Policy",
		"Cross-Origin-Opener-Policy",
		"Cross-Origin-Resource-Policy",
	} {
		if response.Header().Get(header) == "" {
			t.Errorf("missing response header %s", header)
		}
	}
}

func TestHandleLogoutRejectsGETAndCrossOriginPOST(t *testing.T) {
	srv := &server{
		cfg: config{
			SessionSecret: []byte("test-secret-0123456789abcdef-test"),
			RedirectURL:   "https://dashboard.example.test/auth/callback",
		},
		dsc: &discovery{LogoutEp: "https://id.example.test/logout"},
	}
	for _, tc := range []struct {
		name   string
		method string
		origin string
		want   int
	}{
		{name: "get logout", method: http.MethodGet, want: http.StatusMethodNotAllowed},
		{name: "cross-origin post", method: http.MethodPost, origin: "https://attacker.example", want: http.StatusForbidden},
		{name: "same-origin post", method: http.MethodPost, origin: "https://dashboard.example.test", want: http.StatusOK},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(tc.method, "https://dashboard.example.test/auth/logout", nil)
			req.Host = "dashboard.example.test"
			if tc.origin != "" {
				req.Header.Set("Origin", tc.origin)
			}
			response := httptest.NewRecorder()
			srv.handleLogout(response, req)
			if response.Code != tc.want {
				t.Fatalf("status = %d, want %d", response.Code, tc.want)
			}
			if tc.want == http.StatusOK && !strings.Contains(response.Body.String(), "logout_url") {
				t.Fatalf("successful logout response missing identity provider URL: %s", response.Body.String())
			}
		})
	}
}

func TestTierQuotas(t *testing.T) {
	s, a, n := tierQuotas("enterprise")
	if s != 10000 || a != 5000 || n != "Enterprise" {
		t.Fatalf("enterprise: %d %d %s", s, a, n)
	}
	s, a, n = tierQuotas("pro")
	if s != 1000 || a != 500 || n != "Pro" {
		t.Fatalf("pro: %d %d %s", s, a, n)
	}
	s, a, n = tierQuotas("free")
	if s != 100 || a != 0 || n != "Free" {
		t.Fatalf("free: %d %d %s", s, a, n)
	}
}

func TestOrDefault(t *testing.T) {
	if orDefault("", "d") != "d" || orDefault("v", "d") != "v" {
		t.Fatal("orDefault broken")
	}
}

func TestPriceTiersMapping(t *testing.T) {
	s := &server{cfg: config{
		PriceProMonthly: "p_pm", PriceProYearly: "p_py",
		PriceEntMonthly: "p_em", PriceEntYearly: "p_ey",
	}}
	m := s.priceTiers()
	if m["p_pm"] != "pro" || m["p_py"] != "pro" || m["p_em"] != "enterprise" || m["p_ey"] != "enterprise" {
		t.Fatalf("mapping wrong: %v", m)
	}
	if !isYearlyPrice(s, "p_py") || !isYearlyPrice(s, "p_ey") || isYearlyPrice(s, "p_pm") {
		t.Fatal("yearly detection wrong")
	}
}
