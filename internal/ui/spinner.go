// Package ui provides terminal UI helpers (spinner, live task status).
package ui

import (
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"time"
)

// frames are the braille spinner frames.
var frames = []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"}

// ANSI color helpers (disabled automatically when colors are off).
const (
	colorReset  = "\033[0m"
	colorDim    = "\033[2m"
	colorGreen  = "\033[32m"
	colorYellow = "\033[33m"
	colorRed    = "\033[31m"
	colorCyan   = "\033[36m"
)

// Spinner renders live, updating status lines for named tasks
// (e.g. one line per running scanner). It is safe for concurrent use.
// When the output is not usable (pipes, CI, /dev/null) it degrades to
// one line per task printed at start/completion only.
type Spinner struct {
	mu       sync.Mutex
	out      io.Writer
	isTTY    bool
	color    bool
	interval time.Duration
	tasks    map[string]*task
	order    []string
	stop     chan struct{}
	done     chan struct{}
	started  bool
	frame    int
	rendered bool
}

type task struct {
	name     string
	status   string // running | done | warn | fail
	detail   string
	startAt  time.Time
	duration time.Duration
}

// NewSpinner creates a spinner writing to stderr.
// color controls ANSI color output; TTY detection decides between the
// animated live view and the plain CI-friendly output.
func NewSpinner(color bool) *Spinner {
	return &Spinner{
		out:      os.Stderr,
		isTTY:    isTerminal(os.Stderr),
		color:    color,
		interval: 90 * time.Millisecond,
		tasks:    make(map[string]*task),
		stop:     make(chan struct{}),
		done:     make(chan struct{}),
	}
}

// Start begins rendering. Safe to call multiple times.
func (s *Spinner) Start() {
	s.mu.Lock()
	if s.started {
		s.mu.Unlock()
		return
	}
	s.started = true
	s.mu.Unlock()

	if s.isTTY {
		go s.loop()
	}
}

// Stop finishes rendering and waits for the render goroutine to exit.
func (s *Spinner) Stop() {
	s.mu.Lock()
	if !s.started {
		s.mu.Unlock()
		return
	}
	s.started = false
	isTTY := s.isTTY
	if isTTY {
		stopCh := s.stop
		doneCh := s.done
		s.mu.Unlock()
		close(stopCh)
		<-doneCh
		return
	}
	s.mu.Unlock()
}

func (s *Spinner) loop() {
	defer close(s.done)
	ticker := time.NewTicker(s.interval)
	defer ticker.Stop()
	for {
		select {
		case <-s.stop:
			return
		case <-ticker.C:
			s.render()
		}
	}
}

// Add registers a task and marks it running.
func (s *Spinner) Add(name string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.tasks[name]; ok {
		return
	}
	s.tasks[name] = &task{name: name, status: "running", startAt: time.Now()}
	s.order = append(s.order, name)
	if !s.isTTY {
		fmt.Fprintf(s.out, "  %s …\n", name)
	}
}

// Done marks a task successful.
func (s *Spinner) Done(name string, detail string) {
	s.finish(name, "done", detail)
}

// Warn marks a task finished with warnings (e.g. findings).
func (s *Spinner) Warn(name string, detail string) {
	s.finish(name, "warn", detail)
}

// Fail marks a task as failed.
func (s *Spinner) Fail(name string, detail string) {
	s.finish(name, "fail", detail)
}

func (s *Spinner) finish(name, status, detail string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	t, ok := s.tasks[name]
	if !ok {
		return
	}
	t.status = status
	t.detail = detail
	t.duration = time.Since(t.startAt)
	if !s.isTTY && detail != "" {
		fmt.Fprintf(s.out, "  %s → %s\n", name, detail)
	}
}

// SetDetail updates the in-flight detail text of a running task.
func (s *Spinner) SetDetail(name, detail string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if t, ok := s.tasks[name]; ok {
		t.detail = detail
	}
}

func (s *Spinner) render() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.isTTY || len(s.tasks) == 0 {
		return
	}

	out := s.out

	var b strings.Builder
	// Move cursor up to overwrite the previous frame.
	if s.renderedOnce() {
		b.WriteString(fmt.Sprintf("\033[%dA", len(s.order)))
	}
	for _, name := range s.order {
		t := s.tasks[name]
		var icon, col string
		switch t.status {
		case "done":
			icon, col = "✔", colorGreen
		case "warn":
			icon, col = "▲", colorYellow
		case "fail":
			icon, col = "✖", colorRed
		default:
			icon, col = frames[s.frame%len(frames)], colorCyan
		}
		line := fmt.Sprintf("%s %s", icon, name)
		switch {
		case t.status == "running" && t.detail != "":
			line += fmt.Sprintf(" — %s", t.detail)
		case t.status == "running":
			line += fmt.Sprintf(" %s(%s)%s", colorDim, fmtDuration(time.Since(t.startAt)), colorReset)
		case t.detail != "" || t.duration > 0:
			line += fmt.Sprintf(" — %s (%s)", t.detail, fmtDuration(t.duration))
		}
		b.WriteString(fmt.Sprintf("%s%s%s\033[K\n", col, line, colorReset))
	}
	_, _ = fmt.Fprint(out, b.String())
	s.markRendered()
	s.frame++
}

// renderedOnce/markRendered track whether a frame was written, guarded by s.mu.
func (s *Spinner) renderedOnce() bool { return s.rendered }

func (s *Spinner) markRendered() { s.rendered = true }

var _ = fmt.Sprintf

func fmtDuration(d time.Duration) string {
	if d < time.Second {
		return fmt.Sprintf("%dms", d.Milliseconds())
	}
	return fmt.Sprintf("%.1fs", d.Seconds())
}

// isTerminal reports whether f looks like an interactive terminal.
// A char device alone is not enough (/dev/null is a char device too),
// so /dev/null is explicitly excluded via os.SameFile.
func isTerminal(f *os.File) bool {
	if f == nil {
		return false
	}
	fi, err := f.Stat()
	if err != nil {
		return false
	}
	if fi.Mode()&os.ModeCharDevice == 0 {
		return false
	}
	if dn, err := os.Open(os.DevNull); err == nil {
		dsi, _ := dn.Stat()
		same := os.SameFile(fi, dsi)
		_ = dn.Close()
		if same {
			return false
		}
	}
	return true
}

// StripANSI removes ANSI escape sequences (used in tests).
func StripANSI(s string) string {
	var b strings.Builder
	inEscape := false
	for _, r := range s {
		if inEscape {
			if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') {
				inEscape = false
			}
			continue
		}
		if r == '\033' {
			inEscape = true
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}
