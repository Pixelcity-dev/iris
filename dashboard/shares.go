package main

// Read-only share links for scans. A share is an HMAC-signed,
// expiring token recorded in a persisted store (SHARES_FILE) so owners
// can list and revoke them. Public readers get a self-contained
// HTML view at /s/{token} — no session, no cookies, no other access.

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"net/http"
	"os"
	"sort"
	"strings"
	"sync"
	"time"
)

const shareTTL = 7 * 24 * time.Hour

type shareRecord struct {
	Token     string    `json:"token"`
	ScanID    string    `json:"scan_id"`
	Sub       string    `json:"sub"`
	Username  string    `json:"username"`
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at"`
	Revoked   bool      `json:"revoked"`
}

type shareStore struct {
	mu   sync.Mutex
	path string
	m    map[string]shareRecord
}

func newShareStore(path string) *shareStore {
	ss := &shareStore{path: path, m: map[string]shareRecord{}}
	if path != "" {
		if data, err := os.ReadFile(path); err == nil {
			var m map[string]shareRecord
			if json.Unmarshal(data, &m) == nil && m != nil {
				ss.m = m
			}
		}
	}
	return ss
}

func (ss *shareStore) persistLocked() {
	if ss.path == "" {
		return
	}
	data, err := json.Marshal(ss.m)
	if err != nil {
		return
	}
	tmp := ss.path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err == nil {
		_ = os.Rename(tmp, ss.path)
	}
}

// issue creates a share token for scanID owned by sess.
func (ss *shareStore) issue(scanID string, sess *session, secret []byte) (shareRecord, error) {
	exp := time.Now().Add(shareTTL)
	payload := base64.RawURLEncoding.EncodeToString([]byte(fmt.Sprintf("%s.%d", scanID, exp.Unix())))
	mac := sha256.Sum256(append([]byte("share:"+string(secret)), payload...))
	token := payload + "." + base64.RawURLEncoding.EncodeToString(mac[:])

	rec := shareRecord{
		Token: token, ScanID: scanID, Sub: sess.Sub, Username: sess.Username,
		CreatedAt: time.Now().UTC(), ExpiresAt: exp.UTC(),
	}
	ss.mu.Lock()
	defer ss.mu.Unlock()
	// One active share per scan: revoke previous ones.
	for k, v := range ss.m {
		if v.ScanID == scanID && !v.Revoked {
			v.Revoked = true
			ss.m[k] = v
		}
	}
	ss.m[token] = rec
	ss.persistLocked()
	return rec, nil
}

// verify checks signature, expiry, and store state.
func (ss *shareStore) verify(token string, secret []byte) (shareRecord, bool) {
	token = strings.TrimSpace(token)
	dot := strings.LastIndex(token, ".")
	if dot <= 0 {
		return shareRecord{}, false
	}
	payload := token[:dot]
	mac := sha256.Sum256(append([]byte("share:"+string(secret)), []byte(payload)...))
	want := base64.RawURLEncoding.EncodeToString(mac[:])
	if !hmac.Equal([]byte(want), []byte(token[dot+1:])) {
		return shareRecord{}, false
	}
	rec, ok := ss.get(token)
	if !ok || rec.Revoked || time.Now().After(rec.ExpiresAt) {
		return shareRecord{}, false
	}
	return rec, true
}

func (ss *shareStore) get(token string) (shareRecord, bool) {
	ss.mu.Lock()
	defer ss.mu.Unlock()
	rec, ok := ss.m[token]
	return rec, ok
}

// listForScan returns active (non-revoked, unexpired) shares for a scan.
func (ss *shareStore) listForScan(scanID string) []shareRecord {
	ss.mu.Lock()
	defer ss.mu.Unlock()
	out := []shareRecord{}
	for _, rec := range ss.m {
		if rec.ScanID == scanID && !rec.Revoked && time.Now().Before(rec.ExpiresAt) {
			out = append(out, rec)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.After(out[j].CreatedAt) })
	return out
}

// revokeForScan revokes every active share of a scan.
func (ss *shareStore) revokeForScan(scanID string) int {
	ss.mu.Lock()
	defer ss.mu.Unlock()
	n := 0
	for k, v := range ss.m {
		if v.ScanID == scanID && !v.Revoked {
			v.Revoked = true
			ss.m[k] = v
			n++
		}
	}
	if n > 0 {
		ss.persistLocked()
	}
	return n
}

// revokeForSub revokes every active share owned by a user (account
// revoke / delete paths).
func (ss *shareStore) revokeForSub(sub string) int {
	ss.mu.Lock()
	defer ss.mu.Unlock()
	n := 0
	for k, v := range ss.m {
		if v.Sub == sub && !v.Revoked {
			v.Revoked = true
			ss.m[k] = v
			n++
		}
	}
	if n > 0 {
		ss.persistLocked()
	}
	return n
}

// ---- handlers ----

// handleShareCreate issues (POST) or lists (GET) shares for a scan.
func (s *server) handleShareCreate(w http.ResponseWriter, r *http.Request) {
	ident, err := s.requestIdentity(r)
	if err != nil {
		writeErr(w, http.StatusUnauthorized, err)
		return
	}
	e, ok := s.scans.get(r.PathValue("id"))
	if !ok {
		writeErr(w, http.StatusNotFound, errors.New("scan not found"))
		return
	}
	if e.Sub != ident.Sub && !isAdmin(ident) {
		writeErr(w, http.StatusForbidden, errors.New("not your scan"))
		return
	}
	rec, err := s.shares.issue(e.ID, ident, s.cfg.SessionSecret)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, errors.New("could not create share link"))
		return
	}
	writeJSON(w, map[string]interface{}{
		"token": rec.Token, "url": s.shareURL(r, rec.Token),
		"expires_at": rec.ExpiresAt, "scan_id": e.ID,
	})
}

func (s *server) handleShareList(w http.ResponseWriter, r *http.Request) {
	ident, err := s.requestIdentity(r)
	if err != nil {
		writeErr(w, http.StatusUnauthorized, err)
		return
	}
	e, ok := s.scans.get(r.PathValue("id"))
	if !ok {
		writeErr(w, http.StatusNotFound, errors.New("scan not found"))
		return
	}
	if e.Sub != ident.Sub && !isAdmin(ident) {
		writeErr(w, http.StatusForbidden, errors.New("not your scan"))
		return
	}
	list := s.shares.listForScan(e.ID)
	items := make([]map[string]interface{}, 0, len(list))
	for _, rec := range list {
		items = append(items, map[string]interface{}{
			"token": rec.Token, "url": s.shareURL(r, rec.Token),
			"expires_at": rec.ExpiresAt, "created_at": rec.CreatedAt,
		})
	}
	writeJSON(w, map[string]interface{}{"shares": items})
}

// handleShareRevoke revokes all active shares of a scan.
func (s *server) handleShareRevoke(w http.ResponseWriter, r *http.Request) {
	ident, err := s.requestIdentity(r)
	if err != nil {
		writeErr(w, http.StatusUnauthorized, err)
		return
	}
	e, ok := s.scans.get(r.PathValue("id"))
	if !ok {
		writeErr(w, http.StatusNotFound, errors.New("scan not found"))
		return
	}
	if e.Sub != ident.Sub && !isAdmin(ident) {
		writeErr(w, http.StatusForbidden, errors.New("not your scan"))
		return
	}
	writeJSON(w, map[string]interface{}{"revoked": s.shares.revokeForScan(e.ID)})
}

// shareURL builds the public link from the request host.
func (s *server) shareURL(r *http.Request, token string) string {
	scheme := "https"
	if r.TLS == nil && !s.cfg.CookieSecure {
		scheme = "http"
	}
	if xf := r.Header.Get("X-Forwarded-Proto"); xf != "" {
		scheme = xf
	}
	host := r.Host
	return scheme + "://" + host + "/s/" + token
}

// handleShareView renders the public read-only report page.
func (s *server) handleShareView(w http.ResponseWriter, r *http.Request) {
	token := r.PathValue("token")
	rec, ok := s.shares.verify(token, s.cfg.SessionSecret)
	if !ok {
		writeErr(w, http.StatusNotFound, errors.New("share not found or expired"))
		return
	}
	e, ok := s.scans.get(rec.ScanID)
	if !ok {
		writeErr(w, http.StatusNotFound, errors.New("scan no longer exists"))
		return
	}

	var findingsHTML string
	findingsCount := 0
	if e.ReportBytes > 0 {
		if data, err := s.scans.loadReport(e.ID); err == nil {
			if doc, err := parseReport(data); err == nil {
				findings := flattenFindings(&e, doc)
				findingsCount = len(findings)
				findingsHTML = renderShareFindings(findings)
			}
		}
	}
	if findingsHTML == "" {
		findingsHTML = "<p class='dim'>No stored report for this scan.</p>"
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Robots-Tag", "noindex")
	fmt.Fprintf(w, sharePage, html.EscapeString(e.Target), html.EscapeString(e.Scanner),
		html.EscapeString(e.Time.Format("2006-01-02 15:04 UTC")),
		e.Findings, findingsCount, findingsHTML)
}

func renderShareFindings(findings []flatFinding) string {
	var b strings.Builder
	b.WriteString("<table><thead><tr><th>Severity</th><th>Rule</th><th>Finding</th><th>File</th></tr></thead><tbody>")
	for _, f := range findings {
		sev := strings.ToUpper(f.f.Severity)
		b.WriteString("<tr><td class='sev'>" + html.EscapeString(sev) + "</td>")
		b.WriteString("<td class='mono'>" + html.EscapeString(f.f.RuleID) + "</td>")
		b.WriteString("<td>" + html.EscapeString(f.f.Title))
		if f.f.Description != "" {
			b.WriteString("<div class='desc'>" + html.EscapeString(f.f.Description) + "</div>")
		}
		b.WriteString("</td>")
		file := f.f.File
		if f.f.Line > 0 {
			file = fmt.Sprintf("%s:%d", f.f.File, f.f.Line)
		}
		b.WriteString("<td class='mono'>" + html.EscapeString(file) + "</td></tr>")
	}
	b.WriteString("</tbody></table>")
	return b.String()
}

// sharePage is the self-contained public share view.
const sharePage = `<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex">
<title>Iris shared scan</title>
<style>
  :root { color-scheme: dark; }
  * { box-sizing: border-box; }
  body { margin:0; background:#0a0a0a; color:#e7e7ea; font:15px/1.55 system-ui,-apple-system,sans-serif; padding:40px 20px; }
  .wrap { max-width: 960px; margin: 0 auto; }
  .brand { font-weight:800; letter-spacing:.01em; font-size:1.1rem; }
  .gold { color:transparent; background-image:linear-gradient(115deg,#b08d45,#f0c878 35%%,#ffe9b8 50%%,#d4a853 65%%,#8b6a2a); background-size:200%% 100%%; -webkit-background-clip:text; background-clip:text; animation:8s ease-in-out infinite shift; }
  @keyframes shift { 0%%,100%%{background-position:0%% 50%%} 50%%{background-position:100%% 50%%} }
  .eyebrow { color:#8a8a94; font:600 .65rem/1 ui-monospace,monospace; letter-spacing:.2em; text-transform:uppercase; margin-top:4px; }
  h1 { font-size:1.4rem; margin:22px 0 6px; word-break:break-all; }
  .meta { color:#8a8a94; font-size:.85rem; }
  .badge { display:inline-block; border:1px solid #3f3f46; border-radius:999px; padding:2px 10px; font-size:.72rem; margin:14px 16px 14px 0; }
  table { width:100%%; border-collapse:collapse; margin-top:10px; font-size:.86rem; }
  th, td { text-align:left; padding:9px 10px; border-bottom:1px solid #1f1f24; vertical-align:top; }
  th { color:#8a8a94; font:600 .68rem/1 ui-monospace,monospace; letter-spacing:.14em; text-transform:uppercase; }
  .mono { font-family:ui-monospace,monospace; font-size:.78rem; }
  .sev { font-weight:700; font-size:.75rem; white-space:nowrap; }
  tr:nth-child(1) .sev { color:#ef4444; }
  .desc { color:#9a9aa4; font-size:.8rem; margin-top:3px; }
  .dim { color:#8a8a94; }
  footer { margin-top:34px; color:#6b6b74; font-size:.75rem; border-top:1px solid #1f1f24; padding-top:14px; }
</style></head>
<body><div class="wrap">
  <div><span class="brand">Pixel<span class="gold">City</span></span><div class="eyebrow">Iris · shared scan (read-only)</div></div>
  <h1>%s</h1>
  <div class="meta">Scanner: <span class="mono">%s</span> · Scanned: %s</div>
  <div><span class="badge">findings: %d</span><span class="badge">in report: %d</span></div>
  %s
  <footer>Shared link expires automatically · Powered by Iris · PixelCity</footer>
</div></body></html>`
