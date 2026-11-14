// Package baseline records accepted findings so later scans can report only
// new issues.
package baseline

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/Pixelcity-dev/Iris/internal/core"
)

// Entry is the stable identity of an accepted finding. Line and column are
// kept for display only; moving a finding does not make it new again.
type Entry struct {
	Key      string `json:"key"`
	RuleID   string `json:"rule_id,omitempty"`
	ScanType string `json:"scan_type,omitempty"`
	File     string `json:"file,omitempty"`
	Line     int    `json:"line,omitempty"`
	Title    string `json:"title,omitempty"`
}

type Baseline struct {
	Version  string    `json:"version"`
	Created  time.Time `json:"created"`
	Findings []Entry   `json:"findings"`
}

// Key matches a finding by rule, file, and title. It deliberately ignores
// line and column so edits above a finding do not turn it into a new one.
func Key(f core.Finding) string {
	parts := []string{
		strings.TrimSpace(f.RuleID),
		strings.TrimSpace(filepath.ToSlash(f.File)),
		strings.TrimSpace(f.Title),
	}
	sum := sha256.Sum256([]byte(strings.Join(parts, "\x00")))
	return hex.EncodeToString(sum[:8])
}

// FromResults builds a deduplicated baseline from scan results.
func FromResults(results []core.ScanResult) Baseline {
	b := Baseline{
		Version:  "1.2.0",
		Created:  time.Now().UTC(),
		Findings: []Entry{},
	}

	seen := make(map[string]struct{})
	for _, r := range results {
		for _, f := range r.Findings {
			key := Key(f)
			if _, ok := seen[key]; ok {
				continue
			}
			seen[key] = struct{}{}
			b.Findings = append(b.Findings, Entry{
				Key:      key,
				RuleID:   f.RuleID,
				ScanType: string(f.ScanType),
				File:     filepath.ToSlash(f.File),
				Line:     f.Line,
				Title:    f.Title,
			})
		}
	}

	sort.Slice(b.Findings, func(i, j int) bool { return b.Findings[i].Key < b.Findings[j].Key })
	return b
}

func Load(path string) (*Baseline, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var b Baseline
	if err := json.Unmarshal(data, &b); err != nil {
		return nil, fmt.Errorf("parse baseline %s: %w", path, err)
	}
	return &b, nil
}

func Save(path string, b Baseline) error {
	data, err := json.MarshalIndent(b, "", "  ")
	if err != nil {
		return fmt.Errorf("encode baseline: %w", err)
	}

	if dir := filepath.Dir(path); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return fmt.Errorf("create baseline directory: %w", err)
		}
	}
	if err := os.WriteFile(path, append(data, '\n'), 0644); err != nil {
		return fmt.Errorf("write baseline %s: %w", path, err)
	}
	return nil
}

// LoadResults reads the JSON report written by `iris scan --format json`.
func LoadResults(path string) ([]core.ScanResult, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var report struct {
		Results json.RawMessage `json:"results"`
	}
	if err := json.Unmarshal(data, &report); err == nil && report.Results != nil {
		var results []core.ScanResult
		if err := json.Unmarshal(report.Results, &results); err != nil {
			return nil, fmt.Errorf("parse scan results %s: %w", path, err)
		}
		return results, nil
	}

	var results []core.ScanResult
	if err := json.Unmarshal(data, &results); err != nil {
		return nil, fmt.Errorf("parse scan results %s: %w", path, err)
	}
	return results, nil
}

// Filter removes accepted findings and returns the number suppressed.
func (b *Baseline) Filter(results []core.ScanResult) ([]core.ScanResult, int) {
	known := make(map[string]struct{}, len(b.Findings))
	for _, e := range b.Findings {
		known[e.Key] = struct{}{}
	}

	out := make([]core.ScanResult, 0, len(results))
	suppressed := 0
	for _, r := range results {
		kept := make([]core.Finding, 0, len(r.Findings))
		for _, f := range r.Findings {
			if _, ok := known[Key(f)]; ok {
				suppressed++
				continue
			}
			kept = append(kept, f)
		}
		r.Findings = kept
		out = append(out, r)
	}
	return out, suppressed
}
