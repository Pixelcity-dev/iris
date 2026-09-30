package main

// Power features: aggregate stats over stored reports, bulk scan
// deletion, and admin system diagnostics.

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// statsRule is a rule aggregated across findings.
type statsRule struct {
	RuleID   string `json:"rule_id"`
	Severity string `json:"severity"`
	Title    string `json:"title"`
	Count    int    `json:"count"`
}

// handleStats aggregates findings across the caller's stored reports:
// severity totals, top rules, and scanner breakdown. Admins may pass
// ?user= to aggregate another user's scans.
func (s *server) handleStats(w http.ResponseWriter, r *http.Request) {
	ident, err := s.requestIdentity(r)
	if err != nil {
		writeErr(w, http.StatusUnauthorized, err)
		return
	}
	match := func(e *scanEntry) bool { return e.Sub == ident.Sub }
	if u := strings.TrimSpace(r.URL.Query().Get("user")); u != "" && isAdmin(ident) {
		if u == "*" {
			match = func(*scanEntry) bool { return true }
		} else {
			userFilter := strings.ToLower(u)
			match = func(e *scanEntry) bool {
				return strings.Contains(strings.ToLower(e.Username), userFilter) ||
					strings.Contains(strings.ToLower(e.Email), userFilter)
			}
		}
	}
	entries := s.scans.listMatching(match, 200)

	severity := map[string]int{"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
	ruleCounts := map[string]*statsRule{}
	scanners := map[string]int{}
	scans, withReports, findings := 0, 0, 0

	for _, e := range entries {
		scans++
		scanners[e.Scanner]++
		if e.ReportBytes <= 0 {
			continue
		}
		data, err := s.scans.loadReport(e.ID)
		if err != nil {
			continue
		}
		doc, err := parseReport(data)
		if err != nil {
			continue
		}
		withReports++
		for _, f := range flattenFindings(&e, doc) {
			findings++
			sev := strings.ToLower(f.f.Severity)
			if _, ok := severity[sev]; !ok {
				sev = "info"
			}
			severity[sev]++
			key := f.f.RuleID
			if key == "" {
				key = f.f.Title
			}
			if rc, ok := ruleCounts[key]; ok {
				rc.Count++
			} else {
				ruleCounts[key] = &statsRule{
					RuleID: f.f.RuleID, Severity: strings.ToUpper(f.f.Severity),
					Title: f.f.Title, Count: 1,
				}
			}
		}
	}

	top := make([]statsRule, 0, 15)
	for _, rc := range ruleCounts {
		top = append(top, *rc)
	}
	sort.Slice(top, func(i, j int) bool { return top[i].Count > top[j].Count })
	if len(top) > 15 {
		top = top[:15]
	}

	scannerRows := make([]map[string]interface{}, 0, len(scanners))
	for name, n := range scanners {
		scannerRows = append(scannerRows, map[string]interface{}{"scanner": name, "count": n})
	}

	writeJSON(w, map[string]interface{}{
		"scans": scans, "scans_with_reports": withReports, "findings": findings,
		"severity": severity, "top_rules": top, "scanners": scannerRows,
	})
}

// handleBulkDelete removes many scans (owner or admin) in one request.
// Body: {"ids":["...","..."]}. Caps at 200 ids per call.
func (s *server) handleBulkDelete(w http.ResponseWriter, r *http.Request) {
	ident, err := s.requestIdentity(r)
	if err != nil {
		writeErr(w, http.StatusUnauthorized, err)
		return
	}
	var body struct {
		IDs []string `json:"ids"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&body); err != nil || len(body.IDs) == 0 {
		writeErr(w, http.StatusBadRequest, errors.New("ids array is required"))
		return
	}
	if len(body.IDs) > 200 {
		writeErr(w, http.StatusBadRequest, errors.New("at most 200 ids per request"))
		return
	}
	deleted := []string{}
	failed := []string{}
	for _, id := range body.IDs {
		id = strings.TrimSpace(id)
		if id == "" {
			continue
		}
		e, ok := s.scans.get(id)
		if !ok {
			failed = append(failed, id)
			continue
		}
		if e.Sub != ident.Sub && !isAdmin(ident) {
			failed = append(failed, id)
			continue
		}
		if s.scans.delete(id) {
			deleted = append(deleted, id)
		} else {
			failed = append(failed, id)
		}
	}
	writeJSON(w, map[string]interface{}{
		"deleted": deleted, "failed": failed,
		"deleted_count": len(deleted), "failed_count": len(failed),
	})
}

// handleAdminSystem reports storage, retention, and runtime diagnostics.
func (s *server) handleAdminSystem(w http.ResponseWriter, r *http.Request) {
	storage := map[string]interface{}{}
	if fi, err := os.Stat(s.scans.path); err == nil {
		storage["scans_file_bytes"] = fi.Size()
	}
	reportsBytes, reportsCount := int64(0), 0
	if entries, err := os.ReadDir(s.scans.reportsDir()); err == nil {
		for _, ent := range entries {
			if ent.IsDir() {
				continue
			}
			if fi, err := ent.Info(); err == nil {
				reportsBytes += fi.Size()
				reportsCount++
			}
		}
	}
	storage["reports_bytes"] = reportsBytes
	storage["reports_count"] = reportsCount
	for name, path := range map[string]string{
		"tokens_bytes": os.Getenv("TOKENS_FILE"),
		"shares_bytes": os.Getenv("SHARES_FILE"),
	} {
		storage[name] = 0
		if path != "" {
			if fi, err := os.Stat(path); err == nil {
				storage[name] = fi.Size()
			}
		}
	}

	retentionDays := 0
	if v := strings.TrimSpace(os.Getenv("SCAN_RETENTION_DAYS")); v != "" {
		var n int
		if _, err := fmt.Sscanf(v, "%d", &n); err == nil {
			retentionDays = n
		}
	}

	writeJSON(w, map[string]interface{}{
		"version":            appVersion,
		"started_at":         startedAt.UTC(),
		"uptime_seconds":     int(time.Since(startedAt).Seconds()),
		"scans_total":        s.scans.countAll(),
		"users_total":        len(s.scans.userStats()),
		"storage":            storage,
		"retention_days":     retentionDays,
		"max_report_bytes":   maxReportBytes,
		"max_scan_file_mb":   maxScanFileBytes >> 20,
		"max_scans_per_user": maxScansPerUser,
		"searxng_configured": searxngBase() != "",
		"data_dir":           filepath.Dir(s.scans.path),
	})
}
