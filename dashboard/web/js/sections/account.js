// Account: profile, password change, active sessions.

import { $, esc } from '../core/dom.js';
import { api } from '../core/api.js';
import { emptyRow, showError } from '../ui/feedback.js';
import { fire } from '../core/hooks.js';

export async function loadAccount() {
  let a = {};
  try {
    a = await api('/api/v1/account');
  } catch (e) { /* fall through to identity fallback */ }
  // Keycloak's account root can respond with its HTML console instead of a
  // profile payload — fall back to /me so username/email still prefill.
  if (!a.username && !a.email) {
    try {
      const me = await api('/api/v1/me');
      a = { username: me.username, email: me.email };
    } catch (e) { /* leave fields empty */ }
  }
  $('acct-username').value = a.username || '';
  $('acct-email').value = a.email || '';
  $('acct-firstname').value = a.firstName || a.first_name || '';
  $('acct-lastname').value = a.lastName || a.last_name || '';
}

export async function saveProfile() {
  const note = $('profile-note');
  note.className = 'form-note';
  note.textContent = 'Saving…';
  try {
    await api('/api/v1/account', {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        username: $('acct-username').value.trim(),
        email: $('acct-email').value.trim(),
        firstName: $('acct-firstname').value.trim(),
        lastName: $('acct-lastname').value.trim()
      })
    });
    note.className = 'form-note ok';
    note.textContent = 'Profile saved.';
    fire('reloadIdentity');
  } catch (e) {
    note.className = 'form-note err';
    note.textContent = 'Save failed: ' + e.message;
  }
}

export async function changePassword() {
  const note = $('pw-note');
  const np = $('pw-new').value, cp = $('pw-confirm').value;
  if (!np || np !== cp) {
    note.className = 'form-note err';
    note.textContent = 'New passwords do not match.';
    return;
  }
  note.className = 'form-note';
  note.textContent = 'Updating…';
  try {
    await api('/api/v1/account/password', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        currentPassword: $('pw-current').value,
        newPassword: np,
        confirmation: cp
      })
    });
    $('pw-current').value = $('pw-new').value = $('pw-confirm').value = '';
    note.className = 'form-note ok';
    note.textContent = 'Password updated.';
  } catch (e) {
    note.className = 'form-note err';
    note.textContent = 'Update failed: ' + e.message;
  }
}

export async function loadSessions() {
  try {
    const s = await api('/api/v1/account/sessions');
    const body = $('sessions-body');
    const list = s.sessions || s || [];
    if (!list.length) {
      body.innerHTML = emptyRow(5, 'No active sessions', 'Only this browser is signed in right now. New sign-ins from other devices will be listed here.');
      return;
    }
    body.innerHTML = list.map(x => `<tr>
      <td class="mono" style="font-size:0.78rem">${x.started ? new Date(x.started * 1000).toLocaleString() : '—'}</td>
      <td class="mono" style="font-size:0.78rem">${x.lastAccess ? new Date(x.lastAccess * 1000).toLocaleString() : '—'}</td>
      <td class="mono">${esc(x.ipAddress || x.ip || '—')}</td>
      <td class="mono" style="font-size:0.78rem">${esc((x.clients || []).join(', ') || '—')}</td>
      <td><button class="btn btn-ghost" data-action="revoke-session" data-id="${esc(x.id)}">Revoke</button></td>
    </tr>`).join('');
  } catch (e) {
    $('sessions-body').innerHTML = '<tr><td colspan="5" style="color:var(--color-dim)">Sessions unavailable.</td></tr>';
  }
}

export async function revokeSession(id) {
  if (!confirm('Revoke this session?')) return;
  try {
    await api(`/api/v1/account/sessions/${encodeURIComponent(id)}`, { method: 'DELETE' });
    loadSessions();
  } catch (e) {
    showError('Revoke failed: ' + e.message);
  }
}
