package ui

import (
	"bytes"
	"strings"
	"testing"
)

func newTestSpinner() (*Spinner, *bytes.Buffer) {
	var buf bytes.Buffer
	s := NewSpinner(true)
	s.out = &buf
	s.isTTY = false // force non-TTY path for deterministic output
	return s, &buf
}

func TestSpinnerNonTTYStreams(t *testing.T) {
	s, buf := newTestSpinner()
	s.Add("sast")
	if !strings.Contains(buf.String(), "sast") {
		t.Fatalf("expected task name in output, got %q", buf.String())
	}
	s.Done("sast", "clean")
	if !strings.Contains(buf.String(), "clean") {
		t.Fatalf("expected completion detail in output, got %q", StripANSI(buf.String()))
	}
	s.Stop() // must not hang or panic in non-TTY mode
}

func TestSpinnerTaskLifecycle(t *testing.T) {
	s, _ := newTestSpinner()
	s.Add("sca")
	s.Add("secrets")

	s.mu.Lock()
	if len(s.order) != 2 {
		t.Fatalf("expected 2 tasks, got %d", len(s.order))
	}
	if s.tasks["sca"].status != "running" {
		t.Fatalf("expected sca running, got %s", s.tasks["sca"].status)
	}
	s.mu.Unlock()

	s.Warn("sca", "2 findings")
	s.Fail("secrets", "error: boom")

	s.mu.Lock()
	defer s.mu.Unlock()
	if s.tasks["sca"].status != "warn" || s.tasks["secrets"].status != "fail" {
		t.Fatalf("unexpected statuses: %s %s", s.tasks["sca"].status, s.tasks["secrets"].status)
	}
	if s.tasks["sca"].detail != "2 findings" {
		t.Fatalf("unexpected detail: %q", s.tasks["sca"].detail)
	}
}

func TestSpinnerDoubleAddIgnored(t *testing.T) {
	s, _ := newTestSpinner()
	s.Add("iac")
	s.Add("iac")
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.order) != 1 {
		t.Fatalf("expected 1 task after duplicate Add, got %d", len(s.order))
	}
}

func TestStripANSI(t *testing.T) {
	in := "\033[1;34m╔╗\033[0m plain \033[2K\n"
	want := "╔╗ plain \n"
	if got := StripANSI(in); got != want {
		t.Fatalf("StripANSI = %q, want %q", got, want)
	}
}

func TestProgressInterface(t *testing.T) {
	s, buf := newTestSpinner()
	// Drive via the core.Progress interface exactly as the pipeline does.
	var p interface {
		OnScannerStart(scanType, name string)
		OnScannerDone(scanType, name string, findings int, d interface{})
	}
	_ = p
	s.OnScannerStart("format", "format")
	s.OnScannerDone("format", "format", 3, 0)
	if !strings.Contains(StripANSI(buf.String()), "3 findings") {
		t.Fatalf("expected findings count in non-TTY output, got %q", StripANSI(buf.String()))
	}
}
