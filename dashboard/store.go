package main

// Scan history store: append-only JSONL metadata file, crash-safe via
// tmp+rename, guarded by a mutex (single process). Full scan reports are
// stored as separate JSON files under <dir>/reports/<id>.json and are
// pruned together with their metadata entries. Caps total size and
// per-user entries with oldest-first pruning. Zero dependencies.

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

type scanEntry struct {
	ID        string    `json:"id"`
	Sub       string    `json:"sub"`
	Username  string    `json:"username"`
	Email     string    `json:"email"`
	Time      time.Time `json:"time"`
	Scanner   string    `json:"scanner"`
	Target    string    `json:"target"`
	Findings  int       `json:"findings"`
	DurationS float64   `json:"duration_seconds"`
	// SeverityCounts breaks findings down by severity (critical..info).
	SeverityCounts map[string]int `json:"severity_counts,omitempty"`
	// ReportBytes is the stored report size; 0 = no report stored.
	ReportBytes int `json:"report_bytes,omitempty"`
	// ReportOmitted marks scans whose report exceeded the size cap.
	ReportOmitted bool `json:"report_omitted,omitempty"`
	// Version is the CLI version that produced the scan.
	Version string `json:"iris_version,omitempty"`
}

type scanStore struct {
	mu   sync.Mutex
	path string
}

func newScanStore(path string) *scanStore {
	if path == "" {
		path = "./data/scans.jsonl"
	}
	return &scanStore{path: path}
}

const (
	maxScanFileBytes = 50 << 20 // 50MB total metadata store
	maxReportBytes   = 8 << 20  // 8MB per stored report
	maxScansPerUser  = 1000
	maxTargetLen     = 500
	maxScannerLen    = 64
	maxUsernameLen   = 128
	maxEmailLen      = 254
	maxVersionLen    = 32
)

// errReportMissing means the scan exists but has no stored report
// (older scans, or report exceeded the size cap).
var errReportMissing = errors.New("report not stored")

func (s *scanStore) reportsDir() string {
	return filepath.Join(filepath.Dir(s.path), "reports")
}

func (s *scanStore) reportPath(id string) string {
	return filepath.Join(s.reportsDir(), id+".json")
}

// saveReport writes a full scan report atomically (tmp+rename, 0600).
func (s *scanStore) saveReport(id string, data []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := os.MkdirAll(s.reportsDir(), 0750); err != nil {
		return err
	}
	tmp := s.reportPath(id) + ".tmp"
	if err := os.WriteFile(tmp, data, 0600); err != nil {
		return err
	}
	return os.Rename(tmp, s.reportPath(id))
}

// loadReport reads a stored report. Returns errReportMissing when the
// scan has no stored report.
func (s *scanStore) loadReport(id string) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	data, err := os.ReadFile(s.reportPath(id))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, errReportMissing
		}
		return nil, err
	}
	return data, nil
}

// get returns one scan entry by id (newest match wins).
func (s *scanStore) get(id string) (scanEntry, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	lines, err := readLines(s.path)
	if err != nil {
		return scanEntry{}, false
	}
	for i := len(lines) - 1; i >= 0; i-- {
		var e scanEntry
		if json.Unmarshal([]byte(lines[i]), &e) == nil && e.ID == id {
			return e, true
		}
	}
	return scanEntry{}, false
}

func (s *scanStore) append(e scanEntry) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if err := os.MkdirAll(filepath.Dir(s.path), 0750); err != nil {
		return err
	}
	f, err := os.OpenFile(s.path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	line, err := json.Marshal(e)
	if err != nil {
		f.Close()
		return err
	}
	if _, err := f.Write(append(line, '\n')); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	s.pruneAndSweepLocked()
	return nil
}

// pruneAndSweepLocked applies the byte cap and per-user caps to the
// metadata file, rewrites it when entries were dropped, and deletes
// report files whose metadata no longer exists. Caller must hold s.mu.
func (s *scanStore) pruneAndSweepLocked() {
	lines, err := readLines(s.path)
	if err != nil {
		return
	}
	kept := pruneLines(lines)

	if len(kept) != len(lines) {
		if err := atomicWriteLines(s.path, kept); err != nil {
			return // still sweep what we can
		}
	}
	s.sweepReportsLocked(kept)
}

// pruneLines keeps the newest ~80% of entries under the byte cap, then
// caps entries per user (newest-first), restoring chronological order.
func pruneLines(lines []string) []string {
	// Byte cap: keep newest ~80% by size.
	var total int64
	keepFrom := 0
	for i := len(lines) - 1; i >= 0; i-- {
		total += int64(len(lines[i])) + 1
		if total > maxScanFileBytes*8/10 {
			keepFrom = i + 1
			break
		}
	}
	candidates := lines[keepFrom:]

	// Per-user cap, newest-first.
	kept := make([]string, 0, len(candidates))
	counts := map[string]int{}
	for i := len(candidates) - 1; i >= 0; i-- {
		var e scanEntry
		if json.Unmarshal([]byte(candidates[i]), &e) != nil || e.Sub == "" {
			continue
		}
		if counts[e.Sub] >= maxScansPerUser {
			continue
		}
		counts[e.Sub]++
		kept = append(kept, candidates[i])
	}
	// Restore chronological order.
	for i, j := 0, len(kept)-1; i < j; i, j = i+1, j-1 {
		kept[i], kept[j] = kept[j], kept[i]
	}
	return kept
}

// sweepReportsLocked deletes report files whose id is not present in
// the kept metadata lines. Caller must hold s.mu.
func (s *scanStore) sweepReportsLocked(kept []string) {
	ids := make(map[string]bool, len(kept))
	for _, l := range kept {
		var e scanEntry
		if json.Unmarshal([]byte(l), &e) == nil && e.ID != "" {
			ids[e.ID] = true
		}
	}
	entries, err := os.ReadDir(s.reportsDir())
	if err != nil {
		return
	}
	for _, ent := range entries {
		name := ent.Name()
		if ent.IsDir() || !strings.HasSuffix(name, ".json") {
			continue
		}
		if id := strings.TrimSuffix(name, ".json"); !ids[id] {
			_ = os.Remove(filepath.Join(s.reportsDir(), name))
		}
	}
}

func readLines(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out []string
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1024*1024), 1024*1024)
	for sc.Scan() {
		if line := strings.TrimSpace(sc.Text()); line != "" {
			out = append(out, line)
		}
	}
	return out, sc.Err()
}

func atomicWriteLines(path string, lines []string) error {
	tmp := path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	for _, l := range lines {
		if _, err := f.WriteString(l + "\n"); err != nil {
			f.Close()
			return err
		}
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// list returns newest-first entries for one user, capped by limit.
func (s *scanStore) list(sub string, limit int) []scanEntry {
	s.mu.Lock()
	defer s.mu.Unlock()
	if limit <= 0 || limit > 500 {
		limit = 50
	}
	lines, err := readLines(s.path)
	if err != nil {
		return nil
	}
	var out []scanEntry
	for i := len(lines) - 1; i >= 0 && len(out) < limit; i-- {
		var e scanEntry
		if json.Unmarshal([]byte(lines[i]), &e) != nil {
			continue
		}
		if e.Sub == sub {
			out = append(out, e)
		}
	}
	return out
}

// listAll returns newest-first entries across users for admins.
func (s *scanStore) listAll(limit int, userFilter string) []scanEntry {
	s.mu.Lock()
	defer s.mu.Unlock()
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	lines, err := readLines(s.path)
	if err != nil {
		return nil
	}
	var out []scanEntry
	for i := len(lines) - 1; i >= 0 && len(out) < limit; i-- {
		var e scanEntry
		if json.Unmarshal([]byte(lines[i]), &e) != nil {
			continue
		}
		if userFilter != "" && !strings.Contains(strings.ToLower(e.Username+" "+e.Email), strings.ToLower(userFilter)) {
			continue
		}
		out = append(out, e)
	}
	return out
}

// userStats aggregates per-user counts for the admin overview.
func (s *scanStore) userStats() []map[string]interface{} {
	s.mu.Lock()
	defer s.mu.Unlock()
	type agg struct {
		username string
		email    string
		count    int
		last     time.Time
	}
	bySub := map[string]*agg{}
	order := []string{}
	lines, err := readLines(s.path)
	if err != nil {
		return nil
	}
	for _, line := range lines {
		var e scanEntry
		if json.Unmarshal([]byte(line), &e) != nil || e.Sub == "" {
			continue
		}
		a, ok := bySub[e.Sub]
		if !ok {
			a = &agg{username: e.Username, email: e.Email}
			bySub[e.Sub] = a
			order = append(order, e.Sub)
		}
		a.count++
		if e.Time.After(a.last) {
			a.last = e.Time
		}
	}
	sort.Slice(order, func(i, j int) bool {
		return bySub[order[i]].last.After(bySub[order[j]].last)
	})
	out := []map[string]interface{}{}
	for _, sub := range order {
		a := bySub[sub]
		out = append(out, map[string]interface{}{
			"sub": sub, "username": a.username, "email": a.email,
			"scans": a.count, "last_scan": a.last.Format(time.RFC3339),
		})
	}
	return out
}

func sanitizeScanInput(e *scanEntry) error {
	e.Scanner = strings.TrimSpace(e.Scanner)
	if e.Scanner == "" {
		e.Scanner = "webscan"
	}
	if len(e.Scanner) > maxScannerLen {
		return fmt.Errorf("scanner too long")
	}
	e.Target = strings.TrimSpace(e.Target)
	if e.Target == "" {
		return fmt.Errorf("target is required")
	}
	if len(e.Target) > maxTargetLen {
		return fmt.Errorf("target too long")
	}
	if !(strings.HasPrefix(e.Target, "http://") || strings.HasPrefix(e.Target, "https://")) {
		return fmt.Errorf("target must be an http(s) URL")
	}
	if e.Findings < 0 || e.Findings > 1000000 {
		return fmt.Errorf("findings out of range")
	}
	if e.DurationS < 0 || e.DurationS > 86400 {
		return fmt.Errorf("duration out of range")
	}
	if e.Time.IsZero() {
		e.Time = time.Now().UTC()
	}
	if e.Time.After(time.Now().Add(5 * time.Minute)) {
		return fmt.Errorf("timestamp is in the future")
	}
	e.Username = strings.TrimSpace(e.Username)
	if len(e.Username) > maxUsernameLen {
		e.Username = e.Username[:maxUsernameLen]
	}
	e.Email = strings.TrimSpace(e.Email)
	if len(e.Email) > maxEmailLen {
		e.Email = e.Email[:maxEmailLen]
	}
	// Severity counts: bounded keys, non-negative bounded values.
	if len(e.SeverityCounts) > 12 {
		return fmt.Errorf("too many severity buckets")
	}
	for k, v := range e.SeverityCounts {
		if len(k) > 16 || v < 0 || v > 1000000 {
			return fmt.Errorf("invalid severity counts")
		}
	}
	// Report metadata is server-computed; scrub client-provided values.
	e.ReportBytes = 0
	e.ReportOmitted = false
	e.Version = strings.TrimSpace(e.Version)
	if len(e.Version) > maxVersionLen {
		e.Version = e.Version[:maxVersionLen]
	}
	return nil
}
