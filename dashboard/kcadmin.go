package main

// Minimal Keycloak admin REST client for user management. Authentication
// uses this app's own OAuth client credentials (the iris-dashboard
// service account, granted realm-management view-users/manage-users) —
// no admin passwords anywhere in the environment. Callers must treat
// errors as "Iris-only mode": every handler degrades to local data or
// returns a clear 502 when Keycloak is unreachable.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// kcUser is the subset of the Keycloak user representation we expose.
type kcUser struct {
	ID               string `json:"id"`
	Username         string `json:"username"`
	Email            string `json:"email,omitempty"`
	FirstName        string `json:"firstName,omitempty"`
	LastName         string `json:"lastName,omitempty"`
	Enabled          bool   `json:"enabled"`
	EmailVerified    bool   `json:"emailVerified"`
	CreatedTimestamp int64  `json:"createdTimestamp"`
}

type kcAdmin struct {
	base         string // e.g. https://id.pixelcity.dev
	realm        string // e.g. pcid
	clientID     string
	clientSecret string
	hc           *http.Client

	mu       sync.Mutex
	token    string
	tokenExp time.Time
}

// newKCAdmin derives base + realm from the OIDC issuer
// (https://host/realms/<realm>). Returns nil when misconfigured; all
// methods are nil-safe and report "not configured".
func newKCAdmin(issuer, clientID, clientSecret string) *kcAdmin {
	issuer = strings.TrimSuffix(strings.TrimSpace(issuer), "/")
	i := strings.LastIndex(issuer, "/realms/")
	if i <= 0 || clientID == "" || clientSecret == "" {
		return nil
	}
	realm := strings.Trim(issuer[i+len("/realms/"):], "/")
	if realm == "" {
		return nil
	}
	return &kcAdmin{
		base:         issuer[:i],
		realm:        realm,
		clientID:     clientID,
		clientSecret: clientSecret,
		hc:           &http.Client{Timeout: 15 * time.Second},
	}
}

func (k *kcAdmin) configured() bool {
	return k != nil && k.base != "" && k.realm != ""
}

// accessToken fetches and caches a service-account token.
func (k *kcAdmin) accessToken(ctx context.Context) (string, error) {
	if !k.configured() {
		return "", errors.New("keycloak admin is not configured")
	}
	k.mu.Lock()
	if k.token != "" && time.Now().Before(k.tokenExp.Add(-30*time.Second)) {
		tok := k.token
		k.mu.Unlock()
		return tok, nil
	}
	k.mu.Unlock()

	form := url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {k.clientID},
		"client_secret": {k.clientSecret},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		k.base+"/realms/"+k.realm+"/protocol/openid-connect/token",
		strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := k.hc.Do(req)
	if err != nil {
		return "", fmt.Errorf("keycloak token endpoint: %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("keycloak token endpoint: status %d", resp.StatusCode)
	}
	var out struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
	}
	if err := json.Unmarshal(body, &out); err != nil || out.AccessToken == "" {
		return "", errors.New("keycloak token endpoint: malformed response")
	}
	if out.ExpiresIn <= 0 {
		out.ExpiresIn = 60
	}
	k.mu.Lock()
	k.token = out.AccessToken
	k.tokenExp = time.Now().Add(time.Duration(out.ExpiresIn) * time.Second)
	k.mu.Unlock()
	return out.AccessToken, nil
}

// do calls an admin REST path (e.g. "/users?max=50") under
// /admin/realms/<realm> and returns status + body.
func (k *kcAdmin) do(ctx context.Context, method, path string, payload interface{}) (int, []byte, error) {
	tok, err := k.accessToken(ctx)
	if err != nil {
		return 0, nil, err
	}
	var body io.Reader
	if payload != nil {
		data, err := json.Marshal(payload)
		if err != nil {
			return 0, nil, err
		}
		body = bytes.NewReader(data)
	}
	req, err := http.NewRequestWithContext(ctx, method,
		k.base+"/admin/realms/"+k.realm+path, body)
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Authorization", "Bearer "+tok)
	if payload != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := k.hc.Do(req)
	if err != nil {
		return 0, nil, fmt.Errorf("keycloak admin: %w", err)
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	return resp.StatusCode, data, nil
}

func (k *kcAdmin) listUsers(ctx context.Context, max int) ([]kcUser, error) {
	if max <= 0 || max > 1000 {
		max = 500
	}
	st, data, err := k.do(ctx, http.MethodGet,
		fmt.Sprintf("/users?first=0&max=%d&briefRepresentation=false", max), nil)
	if err != nil {
		return nil, err
	}
	if st != http.StatusOK {
		return nil, fmt.Errorf("keycloak list users: status %d", st)
	}
	var users []kcUser
	if err := json.Unmarshal(data, &users); err != nil {
		return nil, errors.New("keycloak list users: malformed response")
	}
	return users, nil
}

func (k *kcAdmin) getUser(ctx context.Context, id string) (*kcUser, error) {
	st, data, err := k.do(ctx, http.MethodGet, "/users/"+url.PathEscape(id), nil)
	if err != nil {
		return nil, err
	}
	if st == http.StatusNotFound {
		return nil, nil
	}
	if st != http.StatusOK {
		return nil, fmt.Errorf("keycloak get user: status %d", st)
	}
	var u kcUser
	if err := json.Unmarshal(data, &u); err != nil {
		return nil, errors.New("keycloak get user: malformed response")
	}
	return &u, nil
}

// createUser provisions a Keycloak user with an initial password and
// returns the new user id (the OIDC sub).
func (k *kcAdmin) createUser(ctx context.Context, username, email, first, last, password string, temporary bool) (string, error) {
	payload := map[string]interface{}{
		"username":    username,
		"enabled":     true,
		"credentials": []map[string]interface{}{{"type": "password", "value": password, "temporary": temporary}},
	}
	if email != "" {
		payload["email"] = email
		payload["emailVerified"] = false
	}
	if first != "" {
		payload["firstName"] = first
	}
	if last != "" {
		payload["lastName"] = last
	}
	st, data, err := k.do(ctx, http.MethodPost, "/users", payload)
	if err != nil {
		return "", err
	}
	if st == http.StatusConflict {
		return "", errors.New("username already exists in Keycloak")
	}
	if st != http.StatusCreated && st != http.StatusOK {
		return "", fmt.Errorf("keycloak create user: status %d %s", st, kcErrDetail(data))
	}
	// Keycloak returns the created id in the Location header; recover it
	// via lookup to stay independent of header handling in do().
	looked, err := k.findUserByUsername(ctx, username)
	if err != nil || looked == nil {
		return "", errors.New("keycloak create user: created but not found on lookup")
	}
	return looked.ID, nil
}

func (k *kcAdmin) findUserByUsername(ctx context.Context, username string) (*kcUser, error) {
	st, data, err := k.do(ctx, http.MethodGet,
		"/users?username="+url.QueryEscape(username)+"&exact=true&max=2", nil)
	if err != nil {
		return nil, err
	}
	if st != http.StatusOK {
		return nil, fmt.Errorf("keycloak find user: status %d", st)
	}
	var users []kcUser
	if err := json.Unmarshal(data, &users); err != nil || len(users) == 0 {
		return nil, nil
	}
	return &users[0], nil
}

// updateUser merges the mutable fields onto the current representation
// (Keycloak's PUT replaces the whole user object).
func (k *kcAdmin) updateUser(ctx context.Context, id string, patch kcUser) error {
	cur, err := k.getUser(ctx, id)
	if err != nil {
		return err
	}
	if cur == nil {
		return errors.New("user not found in Keycloak")
	}
	if patch.Email != "" {
		cur.Email = patch.Email
	}
	if patch.FirstName != "" {
		cur.FirstName = patch.FirstName
	}
	if patch.LastName != "" {
		cur.LastName = patch.LastName
	}
	cur.Enabled = patch.Enabled
	st, data, err := k.do(ctx, http.MethodPut, "/users/"+url.PathEscape(id), cur)
	if err != nil {
		return err
	}
	if st != http.StatusNoContent && st != http.StatusOK {
		return fmt.Errorf("keycloak update user: status %d %s", st, kcErrDetail(data))
	}
	return nil
}

func (k *kcAdmin) resetPassword(ctx context.Context, id, password string, temporary bool) error {
	payload := map[string]interface{}{
		"type": "password", "value": password, "temporary": temporary,
	}
	st, data, err := k.do(ctx, http.MethodPut, "/users/"+url.PathEscape(id)+"/reset-password", payload)
	if err != nil {
		return err
	}
	if st != http.StatusNoContent && st != http.StatusOK {
		return fmt.Errorf("keycloak reset password: status %d %s", st, kcErrDetail(data))
	}
	return nil
}

// revokeSessions logs the user out of every Keycloak session.
func (k *kcAdmin) revokeSessions(ctx context.Context, id string) error {
	st, data, err := k.do(ctx, http.MethodPost, "/users/"+url.PathEscape(id)+"/logout", map[string]interface{}{})
	if err != nil {
		return err
	}
	if st != http.StatusNoContent && st != http.StatusOK && st != http.StatusNotFound {
		return fmt.Errorf("keycloak logout: status %d %s", st, kcErrDetail(data))
	}
	return nil
}

func (k *kcAdmin) deleteUser(ctx context.Context, id string) error {
	st, data, err := k.do(ctx, http.MethodDelete, "/users/"+url.PathEscape(id), nil)
	if err != nil {
		return err
	}
	if st == http.StatusNotFound {
		return nil
	}
	if st != http.StatusNoContent && st != http.StatusOK {
		return fmt.Errorf("keycloak delete user: status %d %s", st, kcErrDetail(data))
	}
	return nil
}

// kcErrDetail extracts Keycloak's errorMessage for better API responses.
func kcErrDetail(data []byte) string {
	var e struct {
		ErrorMessage string `json:"errorMessage"`
		Error        string `json:"error"`
		ErrorDesc    string `json:"error_description"`
	}
	if json.Unmarshal(data, &e) == nil {
		if e.ErrorMessage != "" {
			return e.ErrorMessage
		}
		if e.ErrorDesc != "" {
			return e.ErrorDesc
		}
		if e.Error != "" {
			return e.Error
		}
	}
	return ""
}
