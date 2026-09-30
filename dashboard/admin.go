package main

// Admin user management: the Keycloak directory merged with Iris scan
// stats and local overrides, plus full account controls — create, plan
// tier, daily limit, ban, disable login, password reset, session
// revoke, and delete with complete local data purge.
//
// All handlers run behind requireAdmin. Keycloak operations use the
// dashboard's service-account credentials (kcadmin.go); when Keycloak
// is unreachable they fail loudly (502) instead of silently half-
// applying — local-only actions (ban, tier override, purge) work
// regardless.

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"sort"
	"strings"
	"time"
)

// adminUser is one merged record in the admin user list.
type adminUser struct {
	Sub        string `json:"sub"`
	Username   string `json:"username"`
	Email      string `json:"email,omitempty"`
	Enabled    bool   `json:"enabled"`
	Source     string `json:"source"` // "keycloak" | "scans"
	Created    string `json:"created,omitempty"`
	Scans      int    `json:"scans"`
	LastScan   string `json:"last_scan,omitempty"`
	Tier       string `json:"tier"`
	TierSource string `json:"tier_source"` // "override" | "cached" | "default"
	DailyLimit int    `json:"daily_limit"` // effective; 0 = unlimited
	DailyUsed  int    `json:"daily_used"`
	Banned     bool   `json:"banned"`
	Note       string `json:"note,omitempty"`
}

// adminUserRow merges a subject's scan stats, override, and cached
// effective tier into one display record.
func (s *server) adminUserRow(sub, username, email string, enabled bool, created int64, source string) adminUser {
	u := adminUser{
		Sub: sub, Username: username, Email: email,
		Enabled: enabled, Source: source,
	}
	if created > 0 {
		u.Created = time.Unix(created/1000, 0).UTC().Format(time.RFC3339)
	}
	if entries := s.scans.list(sub, 1); len(entries) > 0 {
		u.Scans = s.scans.count(sub)
		u.LastScan = entries[0].Time.UTC().Format(time.RFC3339)
	}
	o, hasOverride := s.meta.get(sub)
	if hasOverride {
		u.Banned = o.Banned
		u.Note = o.Note
	}
	// Effective tier: admin override > cached result of the last plan
	// resolution (billing/admin-role aware) > free.
	u.Tier, u.TierSource = "free", "default"
	if hasOverride && o.Tier != "" {
		u.Tier, u.TierSource = o.Tier, "override"
	} else if hasOverride && o.EffectiveTier != "" {
		u.Tier, u.TierSource = o.EffectiveTier, "cached"
	}
	u.DailyLimit = s.dailyLimitFor(sub, u.Tier)
	u.DailyUsed = s.scans.countSince(sub, startOfUTCDay())
	return u
}

// handleAdminUsers lists every user: Keycloak directory merged with
// scan-only subjects (legacy or deleted accounts that still have data).
func (s *server) handleAdminUsers(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	users := []adminUser{}
	seen := map[string]bool{}

	kcOK := false
	var kcErr string
	if s.kc.configured() {
		list, err := s.kc.listUsers(ctx, 500)
		if err != nil {
			kcErr = err.Error()
		} else {
			kcOK = true
			for _, u := range list {
				seen[u.ID] = true
				users = append(users, s.adminUserRow(
					u.ID,
					orDefault(u.Username, u.ID),
					u.Email, u.Enabled, u.CreatedTimestamp, "keycloak"))
			}
		}
	}
	// Subjects with scans that Keycloak no longer knows about.
	for _, st := range s.scans.userStats() {
		sub, _ := st["sub"].(string)
		if sub == "" || seen[sub] {
			continue
		}
		username, _ := st["username"].(string)
		email, _ := st["email"].(string)
		users = append(users, s.adminUserRow(sub, username, email, true, 0, "scans"))
	}
	sort.SliceStable(users, func(i, j int) bool {
		li, lj := users[i].LastScan, users[j].LastScan
		if li != lj {
			return li > lj
		}
		return users[i].Scans > users[j].Scans
	})
	resp := map[string]interface{}{"users": users, "total": len(users), "keycloak": kcOK}
	if kcErr != "" {
		resp["keycloak_error"] = kcErr
	}
	writeJSON(w, resp)
}

// handleAdminUserGet returns one user's full profile: merged row,
// Keycloak record (when reachable), override, and recent scans.
func (s *server) handleAdminUserGet(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	sub := r.PathValue("sub")

	var kc *kcUser
	if s.kc.configured() {
		u, err := s.kc.getUser(ctx, sub)
		if err != nil {
			writeErr(w, http.StatusBadGateway, fmt.Errorf("keycloak: %v", err))
			return
		}
		kc = u
	}
	o, _ := s.meta.get(sub)
	var username, email string
	enabled, created := true, int64(0)
	source := "scans"
	switch {
	case kc != nil:
		username, email = kc.Username, kc.Email
		enabled, created, source = kc.Enabled, kc.CreatedTimestamp, "keycloak"
	default:
		if entries := s.scans.list(sub, 1); len(entries) > 0 {
			username, email = entries[0].Username, entries[0].Email
		}
		if o.Updated > 0 {
			source = "override"
		}
	}
	row := s.adminUserRow(sub, username, email, enabled, created, source)
	if kc == nil && !s.kc.configured() {
		row.Source = "local"
	}
	// Empty list (not null) for stable JSON consumers.
	recent := s.scans.list(sub, 10)
	if recent == nil {
		recent = []scanEntry{}
	}
	writeJSON(w, map[string]interface{}{
		"user":         row,
		"keycloak":     kc,
		"override":     o,
		"recent_scans": recent,
	})
}

var tierNames = map[string]bool{"": true, "free": true, "pro": true, "enterprise": true, "admin": true}
var usernameRe = regexp.MustCompile(`^[a-zA-Z0-9._@-]{3,64}$`)

// handleAdminUserPatch updates an account: local override fields
// (tier / daily_limit / banned / note) and/or the Keycloak login flag.
func (s *server) handleAdminUserPatch(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	sess := r.Context().Value(sessKey{}).(session)
	sub := r.PathValue("sub")

	var in struct {
		Tier       *string `json:"tier"`
		DailyLimit *int    `json:"daily_limit"`
		Banned     *bool   `json:"banned"`
		Note       *string `json:"note"`
		Enabled    *bool   `json:"enabled"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeErr(w, http.StatusBadRequest, errors.New("invalid JSON"))
		return
	}
	if in.Tier == nil && in.DailyLimit == nil && in.Banned == nil && in.Note == nil && in.Enabled == nil {
		writeErr(w, http.StatusBadRequest, errors.New("no fields to update"))
		return
	}
	if sub == sess.Sub {
		if (in.Banned != nil && *in.Banned) || (in.Enabled != nil && !*in.Enabled) {
			writeErr(w, http.StatusBadRequest, errors.New("you cannot disable your own account"))
			return
		}
	}
	if in.Tier != nil && !tierNames[*in.Tier] {
		writeErr(w, http.StatusUnprocessableEntity, errors.New("tier must be one of free, pro, enterprise, admin"))
		return
	}
	if in.DailyLimit != nil && (*in.DailyLimit < 0 || *in.DailyLimit > 100000) {
		writeErr(w, http.StatusUnprocessableEntity, errors.New("daily_limit must be 0..100000 (0 = tier default)"))
		return
	}

	o, _ := s.meta.get(sub)
	if in.Tier != nil {
		o.Tier = *in.Tier
	}
	if in.DailyLimit != nil {
		o.DailyLimit = *in.DailyLimit
	}
	if in.Banned != nil {
		o.Banned = *in.Banned
	}
	if in.Note != nil {
		o.Note = strings.TrimSpace(*in.Note)
	}
	s.meta.put(sub, o)

	// Keycloak login toggle runs after the local override so a failure
	// there never reverts the ban/tier change.
	if in.Enabled != nil {
		if !s.kc.configured() {
			writeErr(w, http.StatusServiceUnavailable, errors.New("keycloak admin is not configured"))
			return
		}
		u, err := s.kc.getUser(ctx, sub)
		if err != nil {
			writeErr(w, http.StatusBadGateway, fmt.Errorf("keycloak: %v", err))
			return
		}
		if u == nil {
			writeErr(w, http.StatusNotFound, errors.New("user not found in Keycloak"))
			return
		}
		if err := s.kc.updateUser(ctx, sub, kcUser{Enabled: *in.Enabled}); err != nil {
			writeErr(w, http.StatusBadGateway, err)
			return
		}
	}

	// Banned users lose their stored tokens immediately.
	if o.Banned {
		s.tokens.Delete(sub)
	}
	writeJSON(w, map[string]interface{}{"ok": true, "sub": sub})
}

// handleAdminUserCreate provisions a Keycloak user with an initial
// password and returns the new subject id.
func (s *server) handleAdminUserCreate(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Username   string `json:"username"`
		Email      string `json:"email"`
		FirstName  string `json:"first_name"`
		LastName   string `json:"last_name"`
		Password   string `json:"password"`
		Temporary  bool   `json:"temporary"`
		Tier       string `json:"tier"`
		DailyLimit int    `json:"daily_limit"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeErr(w, http.StatusBadRequest, errors.New("invalid JSON"))
		return
	}
	in.Username = strings.TrimSpace(in.Username)
	if !usernameRe.MatchString(in.Username) {
		writeErr(w, http.StatusUnprocessableEntity, errors.New("username must be 3-64 chars (letters, digits, . _ @ -)"))
		return
	}
	if len(in.Password) < 8 {
		writeErr(w, http.StatusUnprocessableEntity, errors.New("password must be at least 8 characters"))
		return
	}
	if in.Tier != "" && !tierNames[in.Tier] {
		writeErr(w, http.StatusUnprocessableEntity, errors.New("tier must be one of free, pro, enterprise, admin"))
		return
	}
	if !s.kc.configured() {
		writeErr(w, http.StatusServiceUnavailable, errors.New("keycloak admin is not configured"))
		return
	}
	id, err := s.kc.createUser(r.Context(), in.Username, strings.TrimSpace(in.Email),
		strings.TrimSpace(in.FirstName), strings.TrimSpace(in.LastName), in.Password, in.Temporary)
	if err != nil {
		if strings.Contains(err.Error(), "already exists") {
			writeErr(w, http.StatusConflict, err)
			return
		}
		writeErr(w, http.StatusBadGateway, err)
		return
	}
	if in.Tier != "" || in.DailyLimit > 0 {
		s.meta.put(id, userOverride{Tier: in.Tier, DailyLimit: in.DailyLimit})
	}
	writeJSON(w, map[string]interface{}{"sub": id, "username": in.Username})
}

// handleAdminUserResetPassword sets a new Keycloak password.
func (s *server) handleAdminUserResetPassword(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Password  string `json:"password"`
		Temporary bool   `json:"temporary"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeErr(w, http.StatusBadRequest, errors.New("invalid JSON"))
		return
	}
	if len(in.Password) < 8 {
		writeErr(w, http.StatusUnprocessableEntity, errors.New("password must be at least 8 characters"))
		return
	}
	if !s.kc.configured() {
		writeErr(w, http.StatusServiceUnavailable, errors.New("keycloak admin is not configured"))
		return
	}
	sub := r.PathValue("sub")
	u, err := s.kc.getUser(r.Context(), sub)
	if err != nil {
		writeErr(w, http.StatusBadGateway, fmt.Errorf("keycloak: %v", err))
		return
	}
	if u == nil {
		writeErr(w, http.StatusNotFound, errors.New("user not found in Keycloak"))
		return
	}
	if err := s.kc.resetPassword(r.Context(), sub, in.Password, in.Temporary); err != nil {
		writeErr(w, http.StatusBadGateway, err)
		return
	}
	writeJSON(w, map[string]interface{}{"ok": true, "sub": sub})
}

// handleAdminUserRevoke ends every Keycloak session and clears local
// credentials for the subject (tokens, active share links).
func (s *server) handleAdminUserRevoke(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	sess := r.Context().Value(sessKey{}).(session)
	sub := r.PathValue("sub")
	if sub == sess.Sub {
		writeErr(w, http.StatusBadRequest, errors.New("you cannot revoke your own session — sign out instead"))
		return
	}
	resp := map[string]interface{}{"ok": true, "sub": sub}
	if s.kc.configured() {
		u, err := s.kc.getUser(ctx, sub)
		if err != nil {
			writeErr(w, http.StatusBadGateway, fmt.Errorf("keycloak: %v", err))
			return
		}
		if u != nil {
			if err := s.kc.revokeSessions(ctx, sub); err != nil {
				writeErr(w, http.StatusBadGateway, err)
				return
			}
		}
		resp["keycloak_sessions_revoked"] = u != nil
	}
	s.tokens.Delete(sub)
	resp["tokens_cleared"] = true
	resp["shares_revoked"] = s.shares.revokeForSub(sub)
	writeJSON(w, resp)
}

// handleAdminUserDelete removes the Keycloak account (when reachable),
// then purges all local data: scans + reports, tokens, shares, and the
// override record. Never self.
func (s *server) handleAdminUserDelete(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	sess := r.Context().Value(sessKey{}).(session)
	sub := r.PathValue("sub")
	if sub == sess.Sub {
		writeErr(w, http.StatusBadRequest, errors.New("you cannot delete your own account"))
		return
	}
	resp := map[string]interface{}{"ok": true, "sub": sub}

	kcDeleted := false
	if s.kc.configured() {
		u, err := s.kc.getUser(ctx, sub)
		if err != nil {
			writeErr(w, http.StatusBadGateway, fmt.Errorf("keycloak: %v", err))
			return
		}
		if u != nil {
			if err := s.kc.deleteUser(ctx, sub); err != nil {
				writeErr(w, http.StatusBadGateway, err)
				return
			}
			kcDeleted = true
		}
		resp["keycloak_deleted"] = kcDeleted
	}
	// Keycloak unreachable: ban locally so a surviving login cannot use
	// the account, instead of pretending the deletion fully succeeded.
	if !s.kc.configured() {
		o, _ := s.meta.get(sub)
		o.Banned = true
		s.meta.put(sub, o)
		resp["banned_locally"] = true
	}

	// Purge local data (loop: listMatching caps per pass).
	purged := 0
	for i := 0; i < 100; i++ {
		entries := s.scans.listMatching(func(e *scanEntry) bool { return e.Sub == sub }, 500)
		if len(entries) == 0 {
			break
		}
		for _, e := range entries {
			if s.scans.delete(e.ID) {
				purged++
			}
		}
	}
	resp["scans_purged"] = purged
	s.tokens.Delete(sub)
	resp["shares_revoked"] = s.shares.revokeForSub(sub)
	s.meta.delete(sub)
	writeJSON(w, resp)
}
