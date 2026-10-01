package ui

import "os"

// Brand gold accents for the CLI (#d4a853, the same accent the dashboard,
// marketplace and CLI docs use). Truecolor sequences; terminals without
// 24-bit support degrade to their nearest approximation.
const (
	goldStart = "\033[38;2;212;168;83m"
	goldReset = "\033[0m"
)

// ColorOK reports whether ANSI color should be emitted for f.
// Honors --no-color, the NO_COLOR convention, TERM=dumb and non-TTY output.
func ColorOK(noColorFlag bool, f *os.File) bool {
	if noColorFlag {
		return false
	}
	if _, ok := os.LookupEnv("NO_COLOR"); ok {
		return false
	}
	if os.Getenv("TERM") == "dumb" {
		return false
	}
	return isTerminal(f)
}

// Gold wraps s in the brand gold color when enabled, otherwise returns s.
func Gold(s string, enabled bool) string {
	if !enabled || s == "" {
		return s
	}
	return goldStart + s + goldReset
}
