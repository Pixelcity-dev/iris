package main

// Scan history store: append-only JSONL file, crash-safe via tmp+rename,
// guarded by a mutex (single process). Caps total size and per-user entries
// with oldest-first pruning. Zero dependencies by design.

import (
	"bufio"
	"encoding/json"
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
	maxScanFileBytes = 50 << 20 // 50MB total store
	maxScansPerUser  = 1000
	maxTargetLen     = 500
	maxScannerLen    = 64
	maxUsernameLen   = 128
	maxEmailLen      = 254
)

func (s *scanStore) append(e scanEntry) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if err := os.MkdirAll(filepath.Dir(s.path), 0750); err != nil {
		return err
	}
	// Prune before append so the file never grows past the cap.
	s.pruneLocked()
	f, err := os.OpenFile(s.path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	defer f.Close()
	line, err := json.Marshal(e)
	if err != nil {
		return err
	}
	if _, err := f.Write(append(line, '\n')); err != nil {
		return err
	}
	// Newest entries for this user beyond the cap are dropped oldest-first.
	s.pruneUserLocked(e.Sub)
	return nil
}

// pruneLocked drops oldest lines while the file exceeds the cap.
// Caller must hold s.mu.
func (s *scanStore) pruneLocked() {
	fi, err := os.Stat(s.path)
	if err != nil || fi.Size() <= maxScanFileBytes {
		return
	}
	lines, err := readLines(s.path)
	if err != nil {
		return
	}
	// Keep newest ~80% by byte size.
	var total int64
	keep := len(lines)
	for i := len(lines) - 1; i >= 0; i-- {
		total += int64(len(lines[i])) + 1
		if total > maxScanFileBytes*8/10 {
			keep = i + 1
			break
		}
		keep = i
	}
	if keep < len(lines) {
		_ = atomicWriteLines(s.path, lines[keep:])
	}
}

// pruneUserLocked keeps only the newest maxScansPerUser entries for a user.
// Caller must hold s.mu.
func (s *scanStore) pruneUserLocked(sub string) {
	lines, err := readLines(s.path)
	if err != nil {
		return
	}
	kept := make([]string, 0, len(lines))
	counts := map[string]int{}
	// Walk newest-first, keep budget per user.
	for i := len(lines) - 1; i >= 0; i-- {
		var e scanEntry
		if json.Unmarshal([]byte(lines[i]), &e) != nil {
			continue
		}
		if e.Sub == "" {
			continue
		}
		if counts[e.Sub] >= maxScansPerUser {
			continue
		}
		counts[e.Sub]++
		kept = append(kept, lines[i])
	}
	// Restore chronological order.
	for i, j := 0, len(kept)-1; i < j; i, j = i+1, j-1 {
		kept[i], kept[j] = kept[j], kept[i]
	}
	_ = atomicWriteLines(s.path, kept)
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
	return nil
}
