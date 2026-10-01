// Administration: user directory, per-user editor, platform scans,
// activity trend, system diagnostics.

import { $, esc, shorten } from '../core/dom.js';
import { state } from '../core/state.js';
import { api } from '../core/api.js';
import { toast } from '../ui/toast.js';
import { emptyRow } from '../ui/feedback.js';
import { sevChips, renderTrend } from '../ui/charts.js';
import { onSectionEnter } from '../core/routing.js';
import { hook } from '../core/hooks.js';
import { loadScans, loadTrend, toggleScanDetail } from './scans.js';
import { loadOverview } from './overview.js';
import { loadPlan } from './plan.js';

export async function loadAdmin() {
  try {
    const u = await api('/api/v1/admin/users');
    state.adminUsers = u.users || [];
    const kc = $('admin-kc-status');
    if (kc) kc.textContent = u.keycloak ? 'keycloak connected' : (u.keycloak_error ? 'keycloak unreachable' : 'local only');
    renderAdminUsers();
  } catch (e) {
    $('admin-users-body').innerHTML = emptyRow(7, 'Directory unavailable', 'The user directory did not load — Keycloak or the scan store may be restarting.');
  }
  await loadAdminScans(state.adminUserFilter);
}

export function renderAdminUsers() {
  const q = ($('admin-search') ? $('admin-search').value : '').trim().toLowerCase();
  const rows = state.adminUsers.filter(u => !q ||
    (u.username || '').toLowerCase().includes(q) ||
    (u.email || '').toLowerCase().includes(q));
  $('admin-count').textContent = state.adminUsers.length;
  const status = u => {
    let h = '';
    if (u.banned) h += '<span class="badge badge-bad">banned</span> ';
    if (!u.enabled) h += '<span class="badge badge-warn">login off</span> ';
    if (!h) h = '<span class="badge badge-good">active</span>';
    if (u.source === 'scans') h += ' <span class="badge" title="Known from scan history only">orphan</span>';
    return h;
  };
  $('admin-users-body').innerHTML = rows.map(u => {
    const i = state.adminUsers.indexOf(u);
    const daily = u.daily_limit ? `${u.daily_used} / ${u.daily_limit}` : (u.tier === 'admin' ? `${u.daily_used} · ∞` : String(u.daily_used));
    return `<tr data-action="admin-select" data-idx="${i}">
      <td>
        <div style="font-weight:600">${esc(u.username || '—')}</div>
        <div class="mono" style="font-size:0.7rem;color:var(--color-dim)">${esc(u.email || u.sub || '')}</div>
      </td>
      <td><span class="badge ${u.tier === 'admin' || u.tier === 'enterprise' ? 'badge-gold' : u.tier === 'pro' ? 'badge-accent' : ''}">${esc((u.tier || 'free').toUpperCase())}</span></td>
      <td class="mono" style="font-size:0.78rem;${u.daily_limit && u.daily_used >= u.daily_limit ? 'color:var(--color-warn)' : ''}">${daily}</td>
      <td class="mono">${u.scans ?? 0}</td>
      <td class="mono" style="font-size:0.75rem">${u.last_scan ? new Date(u.last_scan).toLocaleString() : '—'}</td>
      <td style="white-space:nowrap">${status(u)}</td>
      <td style="text-align:right"><button class="btn btn-ghost" data-action="admin-select" data-idx="${i}">Manage</button></td>
    </tr>`;
  }).join('') || emptyRow(7, 'No matching users', 'No account matches that filter. Clear the search to see the full directory.');
}

export function adminSelect(i) {
  const u = state.adminUsers[i];
  if (!u) return;
  const switching = !state.admCur || state.admCur.sub !== u.sub;
  state.admCur = u;
  $('adm-title').textContent = u.username || u.sub;
  $('adm-sub').textContent = u.sub;
  $('adm-src-badge').textContent = u.source === 'keycloak' ? 'Keycloak' : u.source === 'scans' ? 'scan history' : 'local';
  $('adm-banned-badge').style.display = u.banned ? '' : 'none';
  $('adm-disabled-badge').style.display = u.enabled ? 'none' : '';
  $('adm-tier').value = u.tier_source === 'override' ? u.tier : '';
  $('adm-daily').value = (u.tier_source === 'override' || u.daily_limit) ? (u.daily_limit || 0) : 0;
  $('adm-note').value = u.note || '';
  $('adm-pw').value = '';
  if (switching) {
    $('adm-save-note').textContent = '';
    $('adm-save-note').className = 'form-note';
  }
  $('adm-ban-btn').textContent = u.banned ? 'Unban user' : 'Ban user';
  $('adm-enable-btn').textContent = u.enabled ? 'Disable login' : 'Enable login';
  $('adm-detail').style.display = 'block';
  loadAdminUserDetail(u.sub);
  $('adm-detail').scrollIntoView({ behavior: 'smooth', block: 'nearest' });
}

async function loadAdminUserDetail(sub) {
  try {
    const d = await api('/api/v1/admin/users/' + encodeURIComponent(sub));
    if (!state.admCur || state.admCur.sub !== sub) return;
    const kc = d.keycloak;
    const recent = d.recent_scans || [];
    $('adm-scans').innerHTML = recent.length
      ? recent.map(e => `${e.time ? new Date(e.time).toLocaleString() : '—'} · ${esc(e.scanner)} · ${esc(shorten(e.target))}`).join('<br>')
      : 'No scans recorded.';
    if (kc) {
      $('adm-sub').textContent = `${sub} · created ${kc.createdTimestamp ? new Date(kc.createdTimestamp).toLocaleDateString() : '—'} · ${kc.identityProvider || 'password'}`;
    }
  } catch (e) {
    $('adm-scans').innerHTML = 'Could not load detail.';
  }
}

export function adminCloseDetail() {
  $('adm-detail').style.display = 'none';
  state.admCur = null;
}

async function adminPatch(sub, body) {
  return api('/api/v1/admin/users/' + encodeURIComponent(sub), {
    method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body)
  });
}

export async function adminSaveUser() {
  if (!state.admCur) return;
  const note = $('adm-save-note');
  note.className = 'form-note';
  note.textContent = 'Saving…';
  try {
    await adminPatch(state.admCur.sub, {
      tier: $('adm-tier').value,
      daily_limit: Math.max(0, parseInt($('adm-daily').value || '0', 10) || 0),
      note: $('adm-note').value
    });
    note.className = 'form-note ok';
    note.textContent = 'Saved.';
    await loadAdmin();
    adminSelect(state.adminUsers.findIndex(u => u.sub === state.admCur.sub));
  } catch (e) {
    note.className = 'form-note err';
    note.textContent = 'Save failed: ' + e.message;
  }
}

export async function adminToggleBan() {
  if (!state.admCur) return;
  const next = !state.admCur.banned;
  if (next && !confirm(`Ban ${state.admCur.username || state.admCur.sub}? They are signed out of the API immediately.`)) return;
  try {
    await adminPatch(state.admCur.sub, { banned: next });
    toast(next ? 'User banned.' : 'User unbanned.');
    await loadAdmin();
    adminSelect(state.adminUsers.findIndex(u => u.sub === state.admCur.sub));
  } catch (e) {
    toast('Ban update failed: ' + e.message, 'err');
  }
}

export async function adminToggleEnabled() {
  if (!state.admCur) return;
  const next = !state.admCur.enabled;
  if (!next && !confirm(`Disable login for ${state.admCur.username || state.admCur.sub}? They will not be able to sign in.`)) return;
  try {
    await adminPatch(state.admCur.sub, { enabled: next });
    toast(next ? 'Login enabled.' : 'Login disabled.');
    await loadAdmin();
    adminSelect(state.adminUsers.findIndex(u => u.sub === state.admCur.sub));
  } catch (e) {
    toast('Login toggle failed: ' + e.message, 'err');
  }
}

export async function adminResetPw() {
  if (!state.admCur) return;
  const pw = $('adm-pw').value;
  if (!pw || pw.length < 8) { toast('Password must be at least 8 characters.', 'warn'); return; }
  if (!confirm(`Set a new password for ${state.admCur.username || state.admCur.sub}?`)) return;
  try {
    await api(`/api/v1/admin/users/${encodeURIComponent(state.admCur.sub)}/reset-password`, {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ password: pw, temporary: false })
    });
    $('adm-pw').value = '';
    toast('Password reset.');
  } catch (e) {
    toast('Password reset failed: ' + e.message, 'err');
  }
}

export async function adminRevoke() {
  if (!state.admCur) return;
  if (!confirm(`End every session for ${state.admCur.username || state.admCur.sub} and clear stored tokens + share links?`)) return;
  try {
    const r = await api(`/api/v1/admin/users/${encodeURIComponent(state.admCur.sub)}/revoke-sessions`, { method: 'POST' });
    toast(`Sessions revoked (${r.shares_revoked} share link(s) closed).`);
    loadAdminScans(state.adminUserFilter);
  } catch (e) {
    toast('Revoke failed: ' + e.message, 'err');
  }
}

export async function adminDeleteUser() {
  if (!state.admCur) return;
  const who = state.admCur.username || state.admCur.sub;
  if (!confirm(`Delete ${who} permanently? Their account and ALL scans, reports, tokens and share links are purged. This cannot be undone.`)) return;
  try {
    const r = await api('/api/v1/admin/users/' + encodeURIComponent(state.admCur.sub), { method: 'DELETE' });
    toast(`Deleted ${who} · ${r.scans_purged} scan(s) purged.`);
    adminCloseDetail();
    await loadAdmin();
    loadScans();
    loadOverview();
    loadPlan();
    loadTrend();
  } catch (e) {
    toast('Delete failed: ' + e.message, 'err');
  }
}

export function toggleCreateUser() {
  const box = $('admin-create');
  const open = box.style.display === 'none';
  box.style.display = open ? 'grid' : 'none';
  if (open) $('new-username').focus();
}

export async function adminCreate() {
  const note = $('create-note');
  const body = {
    username: $('new-username').value.trim(),
    email: $('new-email').value.trim(),
    first_name: $('new-first').value.trim(),
    last_name: $('new-last').value.trim(),
    password: $('new-password').value,
    tier: $('new-tier').value
  };
  if (!body.username) {
    note.className = 'form-note err';
    note.textContent = 'Username required.';
    return;
  }
  note.className = 'form-note';
  note.textContent = 'Creating…';
  try {
    const r = await api('/api/v1/admin/users', {
      method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body)
    });
    note.className = 'form-note ok';
    note.textContent = 'Created ' + (r.username || body.username) + '.';
    ['new-username', 'new-email', 'new-first', 'new-last', 'new-password'].forEach(id => $(id).value = '');
    await loadAdmin();
    setTimeout(() => { $('admin-create').style.display = 'none'; }, 900);
  } catch (e) {
    note.className = 'form-note err';
    note.textContent = 'Create failed: ' + e.message;
  }
}

export function clearAdminFilter() {
  state.adminUserFilter = '';
  loadAdminScans('');
}

export async function loadAdminScans(userFilter) {
  try {
    const q = '/api/v1/admin/scans?limit=50' + (userFilter ? '&user=' + encodeURIComponent(userFilter) : '');
    const s = await api(q);
    const f = $('admin-scans-filter');
    if (userFilter) {
      f.style.display = 'block';
      f.innerHTML = `Filtered: <strong>${esc(userFilter)}</strong> — ${s.total} scan(s) · <a href="#" data-action="admin-clear-filter">show all</a>`;
    } else {
      f.style.display = 'none';
      f.innerHTML = '';
    }
    $('admin-scans-body').innerHTML = (s.entries || []).map(e => `<tr data-action="scan-detail" data-id="${esc(e.id)}" data-cols="5">
      <td class="mono" style="font-size:0.78rem">${e.time ? new Date(e.time).toLocaleString() : '—'}</td>
      <td class="mono">${esc(e.username || e.email || '—')}</td>
      <td><span class="mono">${esc(e.scanner)}</span></td>
      <td class="mono" style="font-size:0.78rem">${esc(shorten(e.target))}</td>
      <td style="white-space:nowrap">${sevChips(e)}</td>
    </tr>`).join('') || emptyRow(5, 'No scans platform-wide', 'Scans from every account appear here as soon as they run.', 'iris scan ./repo');
  } catch (e) {
    $('admin-scans-body').innerHTML = emptyRow(5, 'Activity unavailable', 'The platform scan feed did not load. Refresh in a moment.');
  }
}

// ---- trend ----
export async function loadAdminTrend() {
  try {
    const t = await api('/api/v1/admin/trend?days=' + state.adminTrendDays);
    renderTrend($('admin-trend'), t, 'All users · last ' + state.adminTrendDays + ' days', 'admin');
  } catch (e) { /* chart is non-critical */ }
}

export function setAdminTrendDays(d) {
  state.adminTrendDays = d;
  loadAdminTrend();
}

// ---- system diagnostics ----
export async function loadSystem() {
  try {
    const d = await api('/api/v1/admin/system');
    const fmtB = n => {
      n = n || 0;
      if (n >= 1 << 30) return (n / (1 << 30)).toFixed(2) + ' GB';
      if (n >= 1 << 20) return (n / (1 << 20)).toFixed(2) + ' MB';
      if (n >= 1 << 10) return (n / (1 << 10)).toFixed(1) + ' KB';
      return n + ' B';
    };
    const up = d.uptime_seconds || 0;
    const uptime = up >= 86400 ? Math.floor(up / 86400) + 'd ' + Math.floor(up % 86400 / 3600) + 'h'
      : up >= 3600 ? Math.floor(up / 3600) + 'h ' + Math.floor(up % 3600 / 60) + 'm'
      : Math.floor(up / 60) + 'm';
    const cells = [
      ['version', d.version], ['uptime', uptime],
      ['scans', d.scans_total], ['users', d.users_total],
      ['scans file', fmtB(d.storage && d.storage.scans_file_bytes)],
      ['reports', `${d.storage ? d.storage.reports_count : 0} · ${fmtB(d.storage && d.storage.reports_bytes)}`],
      ['tokens / shares', `${fmtB(d.storage && d.storage.tokens_bytes)} / ${fmtB(d.storage && d.storage.shares_bytes)}`],
      ['retention', d.retention_days ? d.retention_days + ' days' : 'forever'],
      ['report cap', fmtB(d.max_report_bytes)],
      ['per-user cap', d.max_scans_per_user + ' scans'],
      ['web search', d.searxng_configured ? 'configured' : 'off'],
      ['data dir', d.data_dir],
    ];
    $('admin-system').innerHTML = cells.map(([k, v]) =>
      `<div class="sys-cell"><div class="k">${esc(k)}</div><div class="v">${esc(String(v ?? '—'))}</div></div>`).join('');
  } catch (e) {
    $('admin-system').innerHTML = '<div class="sys-cell"><div class="k">status</div><div class="v">unavailable</div></div>';
  }
}

// Refresh hooks fired from other sections (scans deletes, auto-refresh).
hook('adminScans', () => loadAdminScans(state.adminUserFilter));
hook('adminTrend', () => loadAdminTrend());
hook('system', () => loadSystem());

onSectionEnter('admin', () => {
  if (state.me_admin) {
    loadAdmin();
    loadSystem();
  }
});
