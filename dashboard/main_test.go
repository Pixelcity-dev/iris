package main

import (
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
