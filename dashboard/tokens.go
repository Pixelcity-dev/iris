package main

// Server-side Keycloak token store, keyed by session subject.
// The ds_session cookie carries identity only — browsers silently drop
// cookies over 4096 bytes, and embedding access/refresh tokens pushed
// sessions past that limit (login appeared to succeed but never stuck).
// Tokens persist to TOKENS_FILE (data volume) so restarts keep account
// tools working.

import (
	"encoding/json"
	"os"
	"sync"
	"time"
)

type tokenPair struct {
	AccessToken  string    `json:"access_token"`
	RefreshToken string    `json:"refresh_token"`
	UpdatedAt    time.Time `json:"updated_at"`
}

type tokenStore struct {
	mu   sync.Mutex
	path string // empty = memory only
	m    map[string]tokenPair
}

func newTokenStore(path string) *tokenStore {
	ts := &tokenStore{path: path, m: map[string]tokenPair{}}
	if path != "" {
		if data, err := os.ReadFile(path); err == nil {
			var m map[string]tokenPair
			if json.Unmarshal(data, &m) == nil && m != nil {
				ts.m = m
			}
		}
	}
	return ts
}

func (ts *tokenStore) Set(sub string, p tokenPair) {
	ts.mu.Lock()
	defer ts.mu.Unlock()
	p.UpdatedAt = time.Now().UTC()
	if p.AccessToken == "" && p.RefreshToken == "" {
		delete(ts.m, sub)
	} else {
		ts.m[sub] = p
	}
	ts.persistLocked()
}

func (ts *tokenStore) Get(sub string) (tokenPair, bool) {
	ts.mu.Lock()
	defer ts.mu.Unlock()
	p, ok := ts.m[sub]
	return p, ok
}

func (ts *tokenStore) Delete(sub string) {
	ts.mu.Lock()
	defer ts.mu.Unlock()
	if _, ok := ts.m[sub]; ok {
		delete(ts.m, sub)
		ts.persistLocked()
	}
}

// persistLocked writes the store atomically (tmp + rename), 0600.
func (ts *tokenStore) persistLocked() {
	if ts.path == "" {
		return
	}
	data, err := json.Marshal(ts.m)
	if err != nil {
		return
	}
	tmp := ts.path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err == nil {
		_ = os.Rename(tmp, ts.path)
	}
}
