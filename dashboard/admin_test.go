package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeKC is an in-memory Keycloak admin API stand-in covering exactly
// the endpoints kcadmin.go uses.
type fakeKC struct {
	mu        sync.Mutex
	users     map[string]kcUser
	nextID    int
	resets    map[string]string // sub → last reset password
	logouts   int
	deleted   []string
	listError bool
}

func newFakeKC() *fakeKC {
	return &fakeKC{users: map[string]kcUser{}, resets: map[string]string{}}
}

func (f *fakeKC) addUser(id, username string) kcUser {
	f.mu.Lock()
	defer f.mu.Unlock()
	u := kcUser{ID: id, Username: username, Email: username + "@x.dev", Enabled: true,
		CreatedTimestamp: time.Now().UnixMilli()}
	f.users[id] = u
	return u
}

// kcTestServer returns a kcAdmin wired to an httptest fake.
func kcTestServer(t *testing.T, f *fakeKC) *kcAdmin {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("POST /realms/pcid/protocol/openid-connect/token",
		func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte(`{"access_token":"fake-sa-token","expires_in":300}`))
		})
	mux.HandleFunc("GET /admin/realms/pcid/users", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		if f.listError {
			http.Error(w, `{"errorMessage":"boom"}`, http.StatusInternalServerError)
			return
		}
		q := r.URL.Query()
		if exact := q.Get("exact"); exact == "true" {
			want := q.Get("username")
			for _, u := range f.users {
				if u.Username == want {
					json.NewEncoder(w).Encode([]kcUser{u})
					return
				}
			}
			json.NewEncoder(w).Encode([]kcUser{})
			return
		}
		out := []kcUser{}
		for _, u := range f.users {
			out = append(out, u)
		}
		json.NewEncoder(w).Encode(out)
	})
	mux.HandleFunc("GET /admin/realms/pcid/users/{id}", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		u, ok := f.users[r.PathValue("id")]
		if !ok {
			http.Error(w, `{"errorMessage":"Could not find user"}`, http.StatusNotFound)
			return
		}
		json.NewEncoder(w).Encode(u)
	})
	mux.HandleFunc("POST /admin/realms/pcid/users", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		var in kcUser
		json.NewDecoder(r.Body).Decode(&in)
		for _, u := range f.users {
			if u.Username == in.Username {
				http.Error(w, `{"errorMessage":"User already exists"}`, http.StatusConflict)
				return
			}
		}
		f.nextID++
		in.ID = "kc-new-" + itoa(f.nextID)
		in.Enabled = true
		in.CreatedTimestamp = time.Now().UnixMilli()
		f.users[in.ID] = in
		w.WriteHeader(http.StatusCreated)
	})
	mux.HandleFunc("PUT /admin/realms/pcid/users/{id}", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		id := r.PathValue("id")
		u, ok := f.users[id]
		if !ok {
			http.Error(w, `{"errorMessage":"not found"}`, http.StatusNotFound)
			return
		}
		var in kcUser
		json.NewDecoder(r.Body).Decode(&in)
		u.Enabled = in.Enabled
		u.Email = in.Email
		f.users[id] = u
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("PUT /admin/realms/pcid/users/{id}/reset-password", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		var in struct {
			Value string `json:"value"`
		}
		json.NewDecoder(r.Body).Decode(&in)
		f.resets[r.PathValue("id")] = in.Value
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("POST /admin/realms/pcid/users/{id}/logout",
		func(w http.ResponseWriter, r *http.Request) {
			f.mu.Lock()
			defer f.mu.Unlock()
			f.logouts++
			w.WriteHeader(http.StatusNoContent)
		})
	mux.HandleFunc("DELETE /admin/realms/pcid/users/{id}", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		id := r.PathValue("id")
		if _, ok := f.users[id]; !ok {
			http.Error(w, `{"errorMessage":"not found"}`, http.StatusNotFound)
			return
		}
		delete(f.users, id)
		f.deleted = append(f.deleted, id)
		w.WriteHeader(http.StatusNoContent)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	k := newKCAdmin(srv.URL+"/realms/pcid", "iris-dashboard", "test-secret")
	if !k.configured() {
		t.Fatal("fake kcAdmin not configured")
	}
	return k
}

func itoa(n int) string {
	b, _ := json.Marshal(n)
	return strings.Trim(string(b), `"`)
}

func adminServer(t *testing.T) (*server, *http.ServeMux, *fakeKC) {
	t.Helper()
	fk := newFakeKC()
	srv := &server{
		cfg:    config{SessionSecret: []byte("test-secret-0123456789abcdef-test")},
		scans:  newScanStore(filepath.Join(t.TempDir(), "scans.jsonl")),
		tokens: newTokenStore(""),
		shares: newShareStore(""),
		meta:   newUserMetaStore(filepath.Join(t.TempDir(), "overrides.json")),
		kc:     kcTestServer(t, fk),
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/v1/admin/users", srv.requireAdmin(srv.handleAdminUsers))
	mux.HandleFunc("POST /api/v1/admin/users", srv.requireAdmin(srv.handleAdminUserCreate))
	mux.HandleFunc("GET /api/v1/admin/users/{sub}", srv.requireAdmin(srv.handleAdminUserGet))
	mux.HandleFunc("PUT /api/v1/admin/users/{sub}", srv.requireAdmin(srv.handleAdminUserPatch))
	mux.HandleFunc("DELETE /api/v1/admin/users/{sub}", srv.requireAdmin(srv.handleAdminUserDelete))
	mux.HandleFunc("POST /api/v1/admin/users/{sub}/reset-password", srv.requireAdmin(srv.handleAdminUserResetPassword))
	mux.HandleFunc("POST /api/v1/admin/users/{sub}/revoke-sessions", srv.requireAdmin(srv.handleAdminUserRevoke))
	mux.HandleFunc("GET /api/v1/plan", srv.authEither(srv.handlePlan))
	mux.HandleFunc("GET /api/v1/stats", srv.handleStats)
	return srv, mux, fk
}

func jsonReq(t *testing.T, mux *http.ServeMux, method, target, cookie, body string) *httptest.ResponseRecorder {
	t.Helper()
	var rdr *strings.Reader
	if body == "" {
		rdr = strings.NewReader("")
	} else {
		rdr = strings.NewReader(body)
	}
	req := httptest.NewRequest(method, target, rdr)
	req.Header.Set("Content-Type", "application/json")
	if cookie != "" {
		req.AddCookie(&http.Cookie{Name: "ds_session", Value: cookie})
	}
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	return rec
}

// ---------- daily limits ----------

func TestDailyQuotaWindow(t *testing.T) {
	// Unit: checkDailyQuota boundaries + message.
	if err := checkDailyQuota(49, 50, "free"); err != nil {
		t.Fatalf("under limit rejected: %v", err)
	}
	err := checkDailyQuota(50, 50, "free")
	if err == nil {
		t.Fatal("at limit accepted")
	}
	if !strings.Contains(err.Error(), "50/50") || !strings.Contains(err.Error(), "00:00 UTC") {
		t.Fatalf("message: %s", err)
	}
	if err := checkDailyQuota(999, 0, "admin"); err != nil {
		t.Fatalf("limit 0 must disable: %v", err)
	}

	// Tier defaults.
	if q := dailyQuota("admin"); q != 0 {
		t.Fatalf("admin daily %d", q)
	}
	if q := dailyQuota("free"); q != 50 {
		t.Fatalf("free daily %d", q)
	}
	if q := dailyQuota("pro"); q != 250 {
		t.Fatalf("pro daily %d", q)
	}
	if q := dailyQuota("enterprise"); q != 2000 {
		t.Fatalf("enterprise daily %d", q)
	}

	// countSince counts only today's scans.
	srv, _ := toolsServer(t)
	now := time.Now().UTC()
	yesterday := now.Add(-26 * time.Hour)
	for i, tm := range []time.Time{now, now.Add(-time.Hour), yesterday} {
		e := scanEntry{ID: "d-" + itoa(i), Sub: "u-day", Username: "day",
			Time: tm, Scanner: "s", Target: "https://x.test"}
		if err := srv.scans.append(e); err != nil {
			t.Fatal(err)
		}
	}
	if got := srv.scans.countSince("u-day", startOfUTCDay()); got != 2 {
		t.Fatalf("today count %d, want 2", got)
	}
	if got := srv.scans.countSince("u-day", startOfUTCDay().Add(-48*time.Hour)); got != 3 {
		t.Fatalf("48h count %d, want 3", got)
	}
	// Reset boundary: next midnight is between 1s and 24h away.
	mid := nextUTCMidnight()
	d := time.Until(mid)
	if d <= 0 || d > 24*time.Hour {
		t.Fatalf("next midnight out of range: %v", d)
	}
	if mid.Hour() != 0 || mid.Minute() != 0 {
		t.Fatalf("midnight not at 00:00: %v", mid)
	}
}

func TestPlanDailyFields(t *testing.T) {
	srv, mux, _ := adminServer(t)
	cookie := cookieFor(t, srv, "u-plan", "alice", nil)

	// Free tier defaults.
	rec := jsonReq(t, mux, "GET", "/api/v1/plan", cookie, "")
	if rec.Code != 200 {
		t.Fatalf("plan status %d: %s", rec.Code, rec.Body.String())
	}
	var p struct {
		Tier            string `json:"tier"`
		DailyQuota      int    `json:"daily_quota"`
		DailyUsed       int    `json:"daily_used"`
		DailyResetsAt   int64  `json:"daily_resets_at"`
		DailyResetSecs  int    `json:"daily_reset_seconds"`
		ScanQuota       int    `json:"scan_quota"`
		DailyResetShort bool   `json:"-"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &p); err != nil {
		t.Fatal(err)
	}
	if p.Tier != "free" || p.DailyQuota != 50 {
		t.Fatalf("plan %+v", p)
	}
	if p.DailyResetsAt <= time.Now().Unix() || p.DailyResetSecs <= 0 {
		t.Fatalf("reset timing %+v", p)
	}

	// Admin override changes tier + daily quota.
	srv.meta.put("u-plan", userOverride{Tier: "pro", DailyLimit: 5})
	rec = jsonReq(t, mux, "GET", "/api/v1/plan", cookie, "")
	json.Unmarshal(rec.Body.Bytes(), &p)
	if p.Tier != "pro" || p.DailyQuota != 5 {
		t.Fatalf("override plan %+v", p)
	}
}

// ---------- overrides & bans ----------

func TestOverrideBanBlocksIdentity(t *testing.T) {
	srv, mux, _ := adminServer(t)
	cookie := cookieFor(t, srv, "u-banned", "mallory", nil)

	// Works before ban.
	if rec := jsonReq(t, mux, "GET", "/api/v1/plan", cookie, ""); rec.Code != 200 {
		t.Fatalf("pre-ban plan %d", rec.Code)
	}
	// Admin bans (via API below in TestAdminUserPatchControls) — do it
	// directly here to isolate identity behaviour.
	srv.meta.put("u-banned", userOverride{Banned: true})

	for _, target := range []string{"/api/v1/plan", "/api/v1/stats"} {
		rec := jsonReq(t, mux, "GET", target, cookie, "")
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("banned %s status %d: %s", target, rec.Code, rec.Body.String())
		}
		if !strings.Contains(rec.Body.String(), "disabled") {
			t.Fatalf("banned message: %s", rec.Body.String())
		}
	}
	// Unban restores access.
	srv.meta.put("u-banned", userOverride{})
	if rec := jsonReq(t, mux, "GET", "/api/v1/plan", cookie, ""); rec.Code != 200 {
		t.Fatalf("post-unban plan %d", rec.Code)
	}
}

func TestUserMetaPersist(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "overrides.json")
	ms := newUserMetaStore(path)
	ms.put("sub-1", userOverride{Tier: "pro", DailyLimit: 10, Note: "vip"})
	// Reload from disk.
	ms2 := newUserMetaStore(path)
	o, ok := ms2.get("sub-1")
	if !ok || o.Tier != "pro" || o.DailyLimit != 10 || o.Note != "vip" {
		t.Fatalf("reloaded %+v ok=%v", o, ok)
	}
	// Clearing removes the record.
	ms2.put("sub-1", userOverride{})
	if _, ok := ms2.get("sub-1"); ok {
		t.Fatal("cleared record still present")
	}
	// Nil store is safe.
	var nilStore *userMetaStore
	if _, ok := nilStore.get("x"); ok {
		t.Fatal("nil store returned entry")
	}
	nilStore.put("x", userOverride{Tier: "pro"})
	nilStore.delete("x")
}

// ---------- admin user management ----------

func TestAdminUsersListMergesSources(t *testing.T) {
	srv, mux, fk := adminServer(t)
	fk.addUser("kc-1", "alice")
	fk.addUser("kc-2", "bob")
	seedScan(t, srv, "ls-1", "kc-1", "alice", false)
	// Scan-only subject with no Keycloak record.
	seedScan(t, srv, "ls-2", "legacy-sub", "olduser", false)
	srv.meta.put("kc-2", userOverride{Tier: "enterprise", DailyLimit: 42, Banned: true, Note: "trial"})

	admin := cookieFor(t, srv, "u-admin", "dave", []string{"iris-admins"})
	plain := cookieFor(t, srv, "u-plain", "eve", nil)

	rec := jsonReq(t, mux, "GET", "/api/v1/admin/users", plain, "")
	if rec.Code != http.StatusForbidden {
		t.Fatalf("non-admin %d", rec.Code)
	}
	rec = jsonReq(t, mux, "GET", "/api/v1/admin/users", "", "")
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("anon %d", rec.Code)
	}
	rec = jsonReq(t, mux, "GET", "/api/v1/admin/users", admin, "")
	if rec.Code != 200 {
		t.Fatalf("admin list %d: %s", rec.Code, rec.Body.String())
	}
	var resp struct {
		Users    []adminUser `json:"users"`
		Total    int         `json:"total"`
		Keycloak bool        `json:"keycloak"`
		KcError  string      `json:"keycloak_error"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if !resp.Keycloak {
		t.Fatalf("keycloak flag: %+v", resp)
	}
	bySub := map[string]adminUser{}
	for _, u := range resp.Users {
		bySub[u.Sub] = u
	}
	if len(bySub) != 3 {
		t.Fatalf("want 3 users (kc-1, kc-2, legacy), got %d: %+v", len(bySub), resp.Users)
	}
	if u := bySub["kc-2"]; u.Tier != "enterprise" || u.DailyLimit != 42 || !u.Banned || u.Note != "trial" {
		t.Fatalf("override row %+v", u)
	}
	if u := bySub["legacy-sub"]; u.Source != "scans" || u.Username != "olduser" || u.Scans != 1 {
		t.Fatalf("legacy row %+v", u)
	}
	if u := bySub["kc-1"]; u.Source != "keycloak" || !u.Enabled || u.Scans != 1 {
		t.Fatalf("kc row %+v", u)
	}
}

func TestAdminUserPatchControls(t *testing.T) {
	srv, mux, fk := adminServer(t)
	fk.addUser("kc-p", "pat")
	admin := cookieFor(t, srv, "u-admin", "dave", []string{"iris-admins"})
	target := cookieFor(t, srv, "kc-p", "pat", nil)

	// Tier override lands in meta and shows on the target's plan.
	rec := jsonReq(t, mux, "PUT", "/api/v1/admin/users/kc-p", admin,
		`{"tier":"pro","daily_limit":7,"note":"beta tester"}`)
	if rec.Code != 200 {
		t.Fatalf("patch %d: %s", rec.Code, rec.Body.String())
	}
	o, _ := srv.meta.get("kc-p")
	if o.Tier != "pro" || o.DailyLimit != 7 || o.Note != "beta tester" {
		t.Fatalf("override %+v", o)
	}
	rec = jsonReq(t, mux, "GET", "/api/v1/plan", target, "")
	var plan struct {
		Tier       string `json:"tier"`
		DailyQuota int    `json:"daily_quota"`
	}
	json.Unmarshal(rec.Body.Bytes(), &plan)
	if plan.Tier != "pro" || plan.DailyQuota != 7 {
		t.Fatalf("target plan %+v", plan)
	}

	// Disable login flips the Keycloak flag.
	rec = jsonReq(t, mux, "PUT", "/api/v1/admin/users/kc-p", admin, `{"enabled":false}`)
	if rec.Code != 200 {
		t.Fatalf("disable %d: %s", rec.Code, rec.Body.String())
	}
	if u, _ := fk.users["kc-p"]; u.Enabled {
		t.Fatal("kc user still enabled")
	}

	// Ban blocks the live session instantly.
	rec = jsonReq(t, mux, "PUT", "/api/v1/admin/users/kc-p", admin, `{"banned":true}`)
	if rec.Code != 200 {
		t.Fatalf("ban %d: %s", rec.Code, rec.Body.String())
	}
	rec = jsonReq(t, mux, "GET", "/api/v1/plan", target, "")
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("banned target plan %d", rec.Code)
	}

	// Guards: cannot disable self; bad tier rejected; anon/outsider out.
	self := cookieFor(t, srv, "u-admin", "dave", []string{"iris-admins"})
	if rec := jsonReq(t, mux, "PUT", "/api/v1/admin/users/u-admin", self, `{"banned":true}`); rec.Code != http.StatusBadRequest {
		t.Fatalf("self ban %d", rec.Code)
	}
	if rec := jsonReq(t, mux, "PUT", "/api/v1/admin/users/kc-p", admin, `{"tier":"gold"}`); rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("bad tier %d", rec.Code)
	}
	if rec := jsonReq(t, mux, "PUT", "/api/v1/admin/users/kc-p", "", `{"tier":"pro"}`); rec.Code != http.StatusUnauthorized {
		t.Fatalf("anon patch %d", rec.Code)
	}
	// Patch without fields → 400.
	if rec := jsonReq(t, mux, "PUT", "/api/v1/admin/users/kc-p", admin, `{}`); rec.Code != http.StatusBadRequest {
		t.Fatalf("empty patch %d", rec.Code)
	}
}

func TestAdminUserCreateAndResetPassword(t *testing.T) {
	srv, mux, fk := adminServer(t)
	admin := cookieFor(t, srv, "u-admin", "dave", []string{"iris-admins"})

	// Create with initial tier override.
	rec := jsonReq(t, mux, "POST", "/api/v1/admin/users", admin,
		`{"username":"newbie","email":"new@x.dev","password":"hunter2222","tier":"pro"}`)
	if rec.Code != 200 {
		t.Fatalf("create %d: %s", rec.Code, rec.Body.String())
	}
	var created struct {
		Sub string `json:"sub"`
	}
	json.Unmarshal(rec.Body.Bytes(), &created)
	if created.Sub == "" {
		t.Fatalf("no sub: %s", rec.Body.String())
	}
	if u, ok := fk.users[created.Sub]; !ok || u.Username != "newbie" || !u.Enabled {
		t.Fatalf("kc user %+v ok=%v", u, ok)
	}
	if o, ok := srv.meta.get(created.Sub); !ok || o.Tier != "pro" {
		t.Fatalf("create override %+v ok=%v", o, ok)
	}

	// Validation: short password, bad username, duplicate.
	if rec := jsonReq(t, mux, "POST", "/api/v1/admin/users", admin,
		`{"username":"valid-name","password":"short"}`); rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("short pw %d", rec.Code)
	}
	if rec := jsonReq(t, mux, "POST", "/api/v1/admin/users", admin,
		`{"username":"x","password":"longenough"}`); rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("bad username %d", rec.Code)
	}
	if rec := jsonReq(t, mux, "POST", "/api/v1/admin/users", admin,
		`{"username":"newbie","password":"longenough"}`); rec.Code != http.StatusConflict {
		t.Fatalf("duplicate %d", rec.Code)
	}

	// Reset password lands in Keycloak.
	rec = jsonReq(t, mux, "POST", "/api/v1/admin/users/"+created.Sub+"/reset-password", admin,
		`{"password":"brandnewpass"}`)
	if rec.Code != 200 {
		t.Fatalf("reset %d: %s", rec.Code, rec.Body.String())
	}
	if fk.resets[created.Sub] != "brandnewpass" {
		t.Fatalf("reset not applied: %+v", fk.resets)
	}
	// Short password rejected; unknown user 404.
	if rec := jsonReq(t, mux, "POST", "/api/v1/admin/users/"+created.Sub+"/reset-password", admin,
		`{"password":"short"}`); rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("short reset %d", rec.Code)
	}
	if rec := jsonReq(t, mux, "POST", "/api/v1/admin/users/ghost/reset-password", admin,
		`{"password":"longenough"}`); rec.Code != http.StatusNotFound {
		t.Fatalf("ghost reset %d", rec.Code)
	}
}

func TestAdminUserRevokeSessions(t *testing.T) {
	srv, mux, fk := adminServer(t)
	fk.addUser("kc-r", "rita")
	seedScan(t, srv, "rv-1", "kc-r", "rita", false)
	srv.tokens.Set("kc-r", tokenPair{AccessToken: "at", RefreshToken: "rt"})
	// Active share for one of the user's scans.
	if _, err := srv.shares.issue("rv-1", &session{Sub: "kc-r", Username: "rita"}, srv.cfg.SessionSecret); err != nil {
		t.Fatal(err)
	}
	admin := cookieFor(t, srv, "u-admin", "dave", []string{"iris-admins"})

	// Self-revoke blocked.
	if rec := jsonReq(t, mux, "POST", "/api/v1/admin/users/u-admin/revoke-sessions", admin, ""); rec.Code != http.StatusBadRequest {
		t.Fatalf("self revoke %d", rec.Code)
	}
	rec := jsonReq(t, mux, "POST", "/api/v1/admin/users/kc-r/revoke-sessions", admin, "")
	if rec.Code != 200 {
		t.Fatalf("revoke %d: %s", rec.Code, rec.Body.String())
	}
	var resp struct {
		TokensCleared bool `json:"tokens_cleared"`
		SharesRevoked int  `json:"shares_revoked"`
	}
	json.Unmarshal(rec.Body.Bytes(), &resp)
	if !resp.TokensCleared || resp.SharesRevoked != 1 {
		t.Fatalf("revoke resp %+v", resp)
	}
	if _, ok := srv.tokens.Get("kc-r"); ok {
		t.Fatal("tokens survived revoke")
	}
	if fk.logouts != 1 {
		t.Fatalf("kc logouts %d", fk.logouts)
	}
}

func TestAdminUserDeletePurgesEverything(t *testing.T) {
	srv, mux, fk := adminServer(t)
	fk.addUser("kc-d", "dan")
	seedScan(t, srv, "del-1", "kc-d", "dan", true)
	seedScan(t, srv, "del-2", "kc-d", "dan", false)
	seedScan(t, srv, "keep-1", "kc-other", "other", false)
	srv.tokens.Set("kc-d", tokenPair{AccessToken: "at"})
	srv.meta.put("kc-d", userOverride{Tier: "pro", Note: "to be removed"})
	admin := cookieFor(t, srv, "u-admin", "dave", []string{"iris-admins"})

	// Self-delete blocked.
	if rec := jsonReq(t, mux, "DELETE", "/api/v1/admin/users/u-admin", admin, ""); rec.Code != http.StatusBadRequest {
		t.Fatalf("self delete %d", rec.Code)
	}
	// Outsider forbidden.
	plain := cookieFor(t, srv, "u-plain", "eve", nil)
	if rec := jsonReq(t, mux, "DELETE", "/api/v1/admin/users/kc-d", plain, ""); rec.Code != http.StatusForbidden {
		t.Fatalf("outsider delete %d", rec.Code)
	}

	rec := jsonReq(t, mux, "DELETE", "/api/v1/admin/users/kc-d", admin, "")
	if rec.Code != 200 {
		t.Fatalf("delete %d: %s", rec.Code, rec.Body.String())
	}
	var resp struct {
		ScansPurged     int  `json:"scans_purged"`
		KeycloakDeleted bool `json:"keycloak_deleted"`
	}
	json.Unmarshal(rec.Body.Bytes(), &resp)
	if resp.ScansPurged != 2 || !resp.KeycloakDeleted {
		t.Fatalf("delete resp %+v", resp)
	}
	if srv.scans.count("kc-d") != 0 {
		t.Fatal("scans survived")
	}
	if srv.scans.count("kc-other") != 1 {
		t.Fatal("other user's scan purged")
	}
	if len(fk.deleted) != 1 || fk.deleted[0] != "kc-d" {
		t.Fatalf("kc deleted %+v", fk.deleted)
	}
	if _, ok := srv.tokens.Get("kc-d"); ok {
		t.Fatal("tokens survived")
	}
	if _, ok := srv.meta.get("kc-d"); ok {
		t.Fatal("override survived")
	}
}

func TestAdminUserDetail(t *testing.T) {
	srv, mux, fk := adminServer(t)
	fk.addUser("kc-i", "iris")
	seedScan(t, srv, "dt-1", "kc-i", "iris", false)
	admin := cookieFor(t, srv, "u-admin", "dave", []string{"iris-admins"})

	rec := jsonReq(t, mux, "GET", "/api/v1/admin/users/kc-i", admin, "")
	if rec.Code != 200 {
		t.Fatalf("detail %d: %s", rec.Code, rec.Body.String())
	}
	var resp struct {
		User   adminUser   `json:"user"`
		Kc     *kcUser     `json:"keycloak"`
		Recent []scanEntry `json:"recent_scans"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.Kc == nil || resp.Kc.Username != "iris" {
		t.Fatalf("kc %+v", resp.Kc)
	}
	if resp.User.Scans != 1 || len(resp.Recent) != 1 {
		t.Fatalf("user %+v recent %d", resp.User, len(resp.Recent))
	}
	// Unknown subject still 200 with empty local profile.
	if rec := jsonReq(t, mux, "GET", "/api/v1/admin/users/ghost", admin, ""); rec.Code != 200 {
		t.Fatalf("ghost detail %d", rec.Code)
	}
}
