package ui

import (
	"os"
	"strings"
	"testing"
)

func TestGoldDisabledPassthrough(t *testing.T) {
	if got := Gold("Iris", false); got != "Iris" {
		t.Fatalf("disabled Gold mutated string: %q", got)
	}
	if got := Gold("", true); got != "" {
		t.Fatalf("empty string should stay empty: %q", got)
	}
}

func TestGoldEnabledWraps(t *testing.T) {
	got := Gold("Iris", true)
	if !strings.HasPrefix(got, goldStart) || !strings.HasSuffix(got, goldReset) {
		t.Fatalf("missing ANSI wrap: %q", got)
	}
	if !strings.Contains(got, "Iris") {
		t.Fatalf("payload lost: %q", got)
	}
}

func TestColorOKNoColorEnv(t *testing.T) {
	t.Setenv("NO_COLOR", "1")
	if ColorOK(false, os.Stderr) {
		t.Fatal("NO_COLOR must disable color even on a TTY")
	}
}

func TestColorOKFlagWins(t *testing.T) {
	t.Setenv("NO_COLOR", "")
	os.Unsetenv("NO_COLOR")
	if ColorOK(true, os.Stderr) {
		t.Fatal("--no-color must disable color")
	}
}
