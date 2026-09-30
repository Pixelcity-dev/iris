package main

// Interactive dashboard tools: cross-scan findings explorer, scan
// compare, scan deletion, and a SearXNG web-search proxy. Stdlib only.

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

// searxngBase returns the configured SearXNG instance, or "" when unset
// (search tool disabled). Fixed at startup from SEARXNG_BASE — clients
// cannot influence the target, so this is not an SSRF vector.
func searxngBase() string {
	return strings.TrimSuffix(strings.TrimSpace(os.Getenv("SEARXNG_BASE")), "/")
}

// handleFindings aggregates findings across the caller's stored scans
// with server-side filtering: ?q= (text), ?severity=, ?rule=, ?limit=.
// Admins may pass ?user= to search another user's scans.
func (s *server) handleFindings(w http.ResponseWriter, r *http.Request) {
	ident, err := s.requestIdentity(r)
	if err != nil {
		writeErr(w, http.StatusUnauthorized, err)
		return
	}
	q := strings.TrimSpace(strings.ToLower(r.URL.Query().Get("q")))
	severity := strings.ToUpper(strings.TrimSpace(r.URL.Query().Get("severity")))
	rule := strings.TrimSpace(r.URL.Query().Get("rule"))
	limit := atoiQuery(r, "limit", 100)

	if u := strings.TrimSpace(r.URL.Query().Get("user")); u != "" && isAdmin(ident) {
		if u == "*" {
			// Admin: every user's scans.
			s.findingsFor(w, r, func(*scanEntry) bool { return true }, q, severity, rule, limit)
			return
		}
		userFilter := strings.ToLower(u)
		s.findingsFor(w, r, func(e *scanEntry) bool {
			return strings.Contains(strings.ToLower(e.Username), userFilter) ||
				strings.Contains(strings.ToLower(e.Email), userFilter)
		}, q, severity, rule, limit)
		return
	}
	mySub := ident.Sub
	s.findingsFor(w, r, func(e *scanEntry) bool {
		return e.Sub == mySub
	}, q, severity, rule, limit)
}

type findingsRow struct {
	ScanID      string        `json:"scan_id"`
	Scanner     string        `json:"scanner"`
	Target      string        `json:"target"`
	Time        time.Time     `json:"time"`
	Severity    string        `json:"severity"`
	RuleID      string        `json:"rule_id"`
	Title       string        `json:"title"`
	File        string        `json:"file"`
	Line        int           `json:"line"`
	Category    string        `json:"category"`
	Fingerprint string        `json:"fingerprint"`
	Finding     reportFinding `json:"-"`
}

// findingsFor walks matching scans, loads their reports, and returns
// filtered findings (newest scan first), capped at limit rows.
func (s *server) findingsFor(w http.ResponseWriter, r *http.Request,
	match func(*scanEntry) bool, q, severity, rule string, limit int) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	// Gather candidate scans (all matching, capped for cost).
	entries := s.scans.listMatching(match, 200)
	rows := []findingsRow{}
	matchedScans := 0
	for _, e := range entries {
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
		matchedScans++
		for _, f := range flattenFindings(&e, doc) {
			if severity != "" && !strings.EqualFold(f.f.Severity, severity) {
				continue
			}
			if rule != "" && !strings.EqualFold(f.f.RuleID, rule) {
				continue
			}
			if q != "" {
				hay := strings.ToLower(strings.Join([]string{
					f.f.RuleID, f.f.Title, f.f.Description, f.f.File,
					f.f.Category, f.f.Code, f.uri, e.Target, e.Scanner,
				}, " "))
				if !strings.Contains(hay, q) {
					continue
				}
			}
			rows = append(rows, findingsRow{
				ScanID: e.ID, Scanner: e.Scanner, Target: e.Target, Time: e.Time,
				Severity: strings.ToUpper(f.f.Severity), RuleID: f.f.RuleID,
				Title: f.f.Title, File: f.f.File, Line: f.f.Line,
				Category: f.f.Category, Fingerprint: f.f.Fingerprint,
			})
			if len(rows) >= limit {
				s.finishFindings(w, r, rows, true, matchedScans)
				return
			}
		}
	}
	s.finishFindings(w, r, rows, false, matchedScans)
}

// finishFindings renders the findings response as JSON or CSV
// depending on ?format=.
func (s *server) finishFindings(w http.ResponseWriter, r *http.Request, rows []findingsRow, truncated bool, scanned int) {
	if strings.EqualFold(r.URL.Query().Get("format"), "csv") {
		writeFindingsCSV(w, rows)
		return
	}
	if rows == nil {
		rows = []findingsRow{}
	}
	writeJSON(w, map[string]interface{}{
		"findings": rows, "truncated": truncated, "scans_searched": scanned,
	})
}

// handleCompare diffs two of the caller's scans by finding fingerprint:
// new findings (in B, not A), resolved (in A, not B), and unchanged.
func (s *server) handleCompare(w http.ResponseWriter, r *http.Request) {
	ident, err := s.requestIdentity(r)
	if err != nil {
		writeErr(w, http.StatusUnauthorized, err)
		return
	}
	a, b := strings.TrimSpace(r.URL.Query().Get("a")), strings.TrimSpace(r.URL.Query().Get("b"))
	if a == "" || b == "" {
		writeErr(w, http.StatusBadRequest, errors.New("a and b scan ids are required"))
		return
	}
	ea, ok := s.scans.get(a)
	if !ok || (ea.Sub != ident.Sub && !isAdmin(ident)) {
		writeErr(w, http.StatusNotFound, errors.New("scan a not found"))
		return
	}
	eb, ok := s.scans.get(b)
	if !ok || (eb.Sub != ident.Sub && !isAdmin(ident)) {
		writeErr(w, http.StatusNotFound, errors.New("scan b not found"))
		return
	}
	fa, errA := s.findingMap(&ea)
	fb, errB := s.findingMap(&eb)
	if errA != nil || errB != nil {
		writeErr(w, http.StatusNotFound, errors.New("one or both scans have no stored report"))
		return
	}
	added, resolved := []findingsRow{}, []findingsRow{}
	unchanged := 0
	for k, f := range fb {
		if _, ok := fa[k]; !ok {
			added = append(added, rowFor(&eb, f))
		}
	}
	for k, f := range fa {
		if _, ok := fb[k]; !ok {
			resolved = append(resolved, rowFor(&ea, f))
		} else {
			unchanged++
		}
	}
	writeJSON(w, map[string]interface{}{
		"a": ea, "b": eb,
		"added": added, "resolved": resolved, "unchanged": unchanged,
		"summary": map[string]int{
			"added": len(added), "resolved": len(resolved), "unchanged": unchanged,
		},
	})
}

// findingMap indexes a scan's findings by fingerprint (falling back to
// rule+file+line for findings without one).
func (s *server) findingMap(e *scanEntry) (map[string]reportFinding, error) {
	if e.ReportBytes <= 0 {
		return nil, errReportMissing
	}
	data, err := s.scans.loadReport(e.ID)
	if err != nil {
		return nil, err
	}
	doc, err := parseReport(data)
	if err != nil {
		return nil, err
	}
	out := map[string]reportFinding{}
	for _, f := range flattenFindings(e, doc) {
		key := f.f.Fingerprint
		if key == "" {
			key = fmt.Sprintf("%s|%s|%d|%s", f.f.RuleID, f.f.File, f.f.Line, f.f.Title)
		}
		out[key] = f.f
	}
	return out, nil
}

func rowFor(e *scanEntry, f reportFinding) findingsRow {
	return findingsRow{
		ScanID: e.ID, Scanner: e.Scanner, Target: e.Target, Time: e.Time,
		Severity: strings.ToUpper(f.Severity), RuleID: f.RuleID,
		Title: f.Title, File: f.File, Line: f.Line, Category: f.Category,
		Fingerprint: f.Fingerprint,
	}
}

// handleScanDelete removes a scan (owner or admin) including its report.
func (s *server) handleScanDelete(w http.ResponseWriter, r *http.Request) {
	ident, err := s.requestIdentity(r)
	if err != nil {
		writeErr(w, http.StatusUnauthorized, err)
		return
	}
	id := r.PathValue("id")
	e, ok := s.scans.get(id)
	if !ok {
		writeErr(w, http.StatusNotFound, errors.New("scan not found"))
		return
	}
	if e.Sub != ident.Sub && !isAdmin(ident) {
		writeErr(w, http.StatusForbidden, errors.New("not your scan"))
		return
	}
	if !s.scans.delete(id) {
		writeErr(w, http.StatusInternalServerError, errors.New("could not delete scan"))
		return
	}
	writeJSON(w, map[string]interface{}{"deleted": id})
}

// searxResult is the subset of a SearXNG JSON result we expose.
type searxResult struct {
	Title   string `json:"title"`
	URL     string `json:"url"`
	Content string `json:"content"`
	Engine  string `json:"engine"`
}

// handleSearch proxies ?q= to the configured SearXNG instance's JSON
// API. Instance base comes from env only (no client-controlled URL).
func (s *server) handleSearch(w http.ResponseWriter, r *http.Request) {
	if _, err := s.requestIdentity(r); err != nil {
		writeErr(w, http.StatusUnauthorized, err)
		return
	}
	base := searxngBase()
	if base == "" {
		writeErr(w, http.StatusServiceUnavailable, errors.New("web search is not configured (SEARXNG_BASE unset)"))
		return
	}
	q := strings.TrimSpace(r.URL.Query().Get("q"))
	if q == "" {
		writeErr(w, http.StatusBadRequest, errors.New("q is required"))
		return
	}
	if len(q) > 512 {
		q = q[:512]
	}
	u := base + "/search?" + url.Values{
		"q": {q}, "format": {"json"}, "language": {"en"},
	}.Encode()
	ctx, cancel := context.WithTimeout(r.Context(), 12*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, errors.New("bad search request"))
		return
	}
	req.Header.Set("User-Agent", "Iris-Dashboard/1.0")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		writeErr(w, http.StatusBadGateway, errors.New("search engine unreachable"))
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		writeErr(w, http.StatusBadGateway,
			fmt.Errorf("search engine returned status %d (is format=json enabled?)", resp.StatusCode))
		return
	}
	var payload struct {
		Results []struct {
			Title   string `json:"title"`
			URL     string `json:"url"`
			Content string `json:"content"`
			Engine  string `json:"engine"`
		} `json:"results"`
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil || json.Unmarshal(raw, &payload) != nil {
		writeErr(w, http.StatusBadGateway, errors.New("unreadable search response"))
		return
	}
	results := make([]searxResult, 0, len(payload.Results))
	for _, x := range payload.Results {
		if x.URL == "" {
			continue
		}
		if len(results) >= 25 {
			break
		}
		results = append(results, searxResult{Title: x.Title, URL: x.URL, Content: x.Content, Engine: x.Engine})
	}
	writeJSON(w, map[string]interface{}{"query": q, "results": results, "total": len(payload.Results)})
}

// writeFindingsCSV streams findings rows as RFC 4180 CSV.
func writeFindingsCSV(w http.ResponseWriter, rows []findingsRow) {
	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="iris-findings.csv"`)
	cw := csv.NewWriter(w)
	_ = cw.Write([]string{"severity", "rule_id", "title", "category", "file", "line", "scan_id", "scanner", "target", "time", "fingerprint"})
	for _, f := range rows {
		_ = cw.Write([]string{
			f.Severity, f.RuleID, f.Title, f.Category, f.File, strconv.Itoa(f.Line),
			f.ScanID, f.Scanner, f.Target, f.Time.Format(time.RFC3339), f.Fingerprint,
		})
	}
	cw.Flush()
}
