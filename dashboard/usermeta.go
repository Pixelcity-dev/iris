package main

// Per-user admin overrides, persisted to USER_OVERRIDES_FILE so they
// survive restarts. These sit on top of Keycloak + billing:
//
//	tier        force the plan tier (free|pro|enterprise|admin);
//	            "admin" means unlimited quotas, NOT admin panel access
//	daily_limit replace the tier's per-day scan quota (0 = tier default)
//	banned      block the account at the identity layer — takes effect
//	            immediately, even while a Keycloak session is live
//	note        free-text admin annotation
//
// billing_tier/billing_checked cache the last billing-derived tier for
// display in the admin user list (internal; never set by API patches).
//
// A nil store is valid (nothing ever matches) so tests can omit it.

import (
	"encoding/json"
	"os"
	"sync"
	"time"
)

type userOverride struct {
	Tier       string `json:"tier,omitempty"`
	DailyLimit int    `json:"daily_limit,omitempty"`
	Banned     bool   `json:"banned,omitempty"`
	Note       string `json:"note,omitempty"`
	Updated    int64  `json:"updated,omitempty"`
	// EffectiveTier caches the last resolved plan tier (billing or
	// admin-role based) for display in the admin user list — internal,
	// never set by API patches.
	EffectiveTier    string `json:"effective_tier,omitempty"`
	EffectiveChecked int64  `json:"effective_checked,omitempty"`
}

// empty reports whether the record carries no state worth persisting.
func (o userOverride) empty() bool {
	return o.Tier == "" && o.DailyLimit == 0 && !o.Banned && o.Note == "" &&
		o.EffectiveTier == ""
}

type userMetaStore struct {
	mu    sync.Mutex
	path  string // empty = memory only
	bySub map[string]userOverride
}

func newUserMetaStore(path string) *userMetaStore {
	if path == "" {
		path = "./data/user_overrides.json"
	}
	ms := &userMetaStore{path: path, bySub: map[string]userOverride{}}
	if data, err := os.ReadFile(path); err == nil {
		var m map[string]userOverride
		if json.Unmarshal(data, &m) == nil && m != nil {
			ms.bySub = m
		}
	}
	return ms
}

func (ms *userMetaStore) get(sub string) (userOverride, bool) {
	if ms == nil {
		return userOverride{}, false
	}
	ms.mu.Lock()
	defer ms.mu.Unlock()
	o, ok := ms.bySub[sub]
	return o, ok
}

// put replaces the override record for sub; empty records are removed.
func (ms *userMetaStore) put(sub string, o userOverride) {
	if ms == nil {
		return
	}
	ms.mu.Lock()
	defer ms.mu.Unlock()
	if o.empty() {
		delete(ms.bySub, sub)
	} else {
		o.Updated = time.Now().Unix()
		ms.bySub[sub] = o
	}
	ms.persistLocked()
}

// putEffective caches the last resolved plan tier (billing or admin
// role) for display in the admin user list. Skips redundant writes.
func (ms *userMetaStore) putEffective(sub, tier string) {
	if ms == nil {
		return
	}
	ms.mu.Lock()
	defer ms.mu.Unlock()
	o := ms.bySub[sub]
	if o.EffectiveTier == tier && time.Since(time.Unix(o.EffectiveChecked, 0)) < time.Minute {
		return
	}
	o.EffectiveTier = tier
	o.EffectiveChecked = time.Now().Unix()
	ms.bySub[sub] = o
	ms.persistLocked()
}

// effectiveFresh returns the cached effective tier when checked recently.
func (ms *userMetaStore) effectiveFresh(sub string, maxAge time.Duration) (string, bool) {
	if ms == nil {
		return "", false
	}
	ms.mu.Lock()
	defer ms.mu.Unlock()
	o, ok := ms.bySub[sub]
	if !ok || o.EffectiveTier == "" || o.EffectiveChecked == 0 {
		return "", false
	}
	if time.Since(time.Unix(o.EffectiveChecked, 0)) > maxAge {
		return "", false
	}
	return o.EffectiveTier, true
}

func (ms *userMetaStore) delete(sub string) {
	if ms == nil {
		return
	}
	ms.mu.Lock()
	defer ms.mu.Unlock()
	delete(ms.bySub, sub)
	ms.persistLocked()
}

// all returns a copy keyed by sub (for admin list merges).
func (ms *userMetaStore) all() map[string]userOverride {
	if ms == nil {
		return map[string]userOverride{}
	}
	ms.mu.Lock()
	defer ms.mu.Unlock()
	out := make(map[string]userOverride, len(ms.bySub))
	for k, v := range ms.bySub {
		out[k] = v
	}
	return out
}

func (ms *userMetaStore) persistLocked() {
	if ms.path == "" {
		return
	}
	data, err := json.Marshal(ms.bySub)
	if err != nil {
		return
	}
	tmp := ms.path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err == nil {
		_ = os.Rename(tmp, ms.path)
	}
}
