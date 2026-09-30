package ui

import (
	"time"

	"github.com/Pixelcity-dev/Iris/internal/core"
)

// Compile-time check that Spinner satisfies core.Progress.
var _ core.Progress = (*Spinner)(nil)

// OnScannerStart shows the scanner with a spinning icon.
func (s *Spinner) OnScannerStart(scanType core.ScanType, name string) {
	s.Add(scanTypeLabel(scanType, name))
}

// OnScannerDone marks the scanner green with findings count + duration.
func (s *Spinner) OnScannerDone(scanType core.ScanType, name string, findings int, duration time.Duration) {
	label := scanTypeLabel(scanType, name)
	if findings > 0 {
		s.Warn(label, plural(findings, "finding"))
	} else {
		s.Done(label, "clean")
	}
}

// OnScannerError marks the scanner red.
func (s *Spinner) OnScannerError(scanType core.ScanType, name string, err error, duration time.Duration) {
	s.Fail(scanTypeLabel(scanType, name), "error: "+err.Error())
}

func scanTypeLabel(scanType core.ScanType, name string) string {
	if scanType != "" {
		return string(scanType)
	}
	return name
}

func plural(n int, unit string) string {
	if n == 1 {
		return "1 " + unit
	}
	return itoa(n) + " " + unit + "s"
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}
