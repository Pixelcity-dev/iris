// Scan history: table, expandable reports, trend chart, shares, bulk actions,
// auto-refresh. Admin panels refresh through named hooks to stay acyclic.

import { $, esc, shorten } from '../core/dom.js';
import { state } from '../core/state.js';
import { api } from '../core/api.js';
import { toast } from '../ui/toast.js';
import { emptyRow } from '../ui/feedback.js';
import { SEV_COLORS, sevChips, renderTrend } from '../ui/charts.js';
import { onSectionEnter } from '../core/routing.js';
import { fire } from '../core/hooks.js';
import { loadPlan } from './plan.js';
import { loadOverview } from './overview.js';

function refreshAfterMutation() {
  loadScans();
  loadPlan();
  loadTrend();
  if (state.me_admin) {
    fire('adminScans');
    fire('adminTrend');
  }
}

export async function loadScans() {
  try {
    const s = await api('/api/v1/scans?limit=25');
    const body = $('scans-body');
    if (!s.entries || !s.entries.length) {
      body.innerHTML = emptyRow(6, 'No scans yet', 'Every scan you run — CLI, CI or API — lands here with its full report.', 'iris webscan https://example.com');
      updateBulkBtn();
      return;
    }
    fillCompareSelects(s.entries || []);
    body.innerHTML = s.entries.map(e => `<tr data-action="scan-detail" data-id="${esc(e.id)}" data-cols="6">
      <td class="sel-col"><input type="checkbox" class="scan-sel" data-id="${esc(e.id)}"></td>
      <td class="mono" style="font-size:0.78rem;color:var(--color-muted)">${e.time ? new Date(e.time).toLocaleString() : '—'}</td>
      <td><span class="mono">${esc(e.scanner)}</span></td>
      <td class="mono" style="font-size:0.78rem">${esc(shorten(e.target))}</td>
      <td style="white-space:nowrap">${sevChips(e)}</td>
      <td class="mono">${(e.duration_seconds ?? 0).toFixed(2)}s</td>
    </tr>`).join('');
    updateBulkBtn();
  } catch (e) {
    $('scans-body').innerHTML = emptyRow(6, 'Scan history unavailable', 'The scan store did not respond. Refresh in a moment or try again later.');
  }
}

export function fillCompareSelects(entries) {
  const opts = entries.map(e =>
    `<option value="${esc(e.id)}">${esc(new Date(e.time).toLocaleDateString())} · ${esc(e.scanner)} · ${esc(shorten(e.target))}</option>`).join('');
  ['cmp-a', 'cmp-b'].forEach(id => {
    const el = $(id);
    if (!el) return;
    const cur = el.value;
    el.innerHTML = opts || '<option>No scans yet</option>';
    if (cur && entries.some(e => e.id === cur)) el.value = cur;
  });
}

export async function toggleScanDetail(row, id, colspan) {
  const tbody = row.parentElement;
  const open = tbody.querySelector('.scan-detail-row');
  if (open && open.dataset.id === id) {
    open.remove();
    tbody.querySelectorAll('tr[data-action="scan-detail"]').forEach(r => r.classList.remove('is-open'));
    return;
  }
  tbody.querySelectorAll('.scan-detail-row').forEach(n => n.remove());
  tbody.querySelectorAll('tr[data-action="scan-detail"]').forEach(r => r.classList.remove('is-open'));
  row.classList.add('is-open');
  const tr = document.createElement('tr');
  tr.className = 'scan-detail-row';
  tr.dataset.id = id;
  tr.innerHTML = `<td colspan="${colspan}"><span class="spinner"></span></td>`;
  tbody.appendChild(tr);
  try {
    const d = await api(`/api/v1/scans/${encodeURIComponent(id)}`);
    if (!tr.isConnected) return;
    tr.innerHTML = `<td colspan="${colspan}" style="padding:10px 8px 14px">${renderScanDetail(d)}</td>`;
  } catch (e) {
    if (!tr.isConnected) return;
    tr.innerHTML = `<td colspan="${colspan}" style="color:var(--color-dim);padding:10px">Could not load report: ${esc(String((e && e.message) || e))}</td>`;
  }
}

export function renderScanDetail(d) {
  const e = d.entry || {};
  let h = '<div style="display:flex;flex-wrap:wrap;gap:14px;align-items:baseline;padding:2px 0 10px;border-bottom:1px solid rgba(148,163,184,0.18);margin-bottom:8px">';
  h += `<span class="mono" style="font-size:0.82rem">${esc(e.target || '')}</span>`;
  h += `<span class="mono" style="font-size:0.75rem;color:var(--color-muted)">${esc(e.scanner || '')} · ${e.time ? new Date(e.time).toLocaleString() : ''} · ${(e.duration_seconds ?? 0).toFixed(2)}s</span>`;
  if (e.iris_version) h += `<span class="mono" style="font-size:0.75rem;color:var(--color-muted)">iris ${esc(e.iris_version)}</span>`;
  h += `<span style="font-size:0.78rem">${sevChips(e)}</span>`;
  h += `<span style="margin-left:auto;font-size:0.75rem;display:flex;gap:8px;align-items:center">
    <button class="btn btn-ghost" style="border-color:rgba(212,168,83,.45);color:var(--gold)" data-action="share" data-id="${esc(e.id)}">Share</button>
    <button class="btn btn-ghost" style="color:var(--color-dim);border-color:var(--color-line)" data-action="revoke-shares" data-id="${esc(e.id)}">Revoke</button>
    <button class="btn btn-ghost" style="color:var(--color-bad);border-color:rgba(252,165,165,.35)" data-action="delete-scan" data-id="${esc(e.id)}">Delete</button>
  </span>`;
  if (e.report_bytes > 0) {
    const id = encodeURIComponent(e.id);
    const link = f => `<a href="/api/v1/scans/${id}?format=${f}" style="color:var(--gold)">${f.toUpperCase()}</a>`;
    h += `<span style="font-size:0.75rem;color:var(--color-muted)">Export: ${link('sarif')} · ${link('html')} · ${link('json')} · ${link('csv')}</span>`;
  }
  h += `<div id="share-${encodeURIComponent(e.id)}"></div>`;
  h += '</div>';

  const report = d.report;
  if (!report) {
    const note = e.report_omitted
      ? 'Full report exceeded the storage cap — metadata only.'
      : 'No stored report (this scan predates full-output storage).';
    return h + `<div style="color:var(--color-dim);font-size:0.85rem">${note}</div>`;
  }
  const findings = [];
  (report.results || []).forEach(r => (r.findings || []).forEach(f => findings.push(f)));
  if (!findings.length) {
    return h + '<div style="color:var(--color-dim);font-size:0.85rem">Clean scan — no findings recorded.</div>';
  }
  const MAX = 300;
  h += '<div class="table-shell"><table class="data-table"><thead><tr><th style="width:88px">Severity</th><th>Rule</th><th>Finding</th><th style="width:150px">Category</th></tr></thead><tbody>';
  findings.slice(0, MAX).forEach(f => {
    const sev = String(f.severity || 'INFO').toUpperCase();
    h += `<tr>
      <td><span style="color:${SEV_COLORS[sev] || SEV_COLORS.INFO};font-weight:600;font-size:0.78rem">${esc(sev)}</span></td>
      <td class="mono" style="font-size:0.74rem">${esc(f.rule_id || '')}</td>
      <td>${esc(f.title || '')}
        ${f.description ? `<div style="color:var(--color-muted);font-size:0.78rem;margin-top:2px">${esc(f.description)}</div>` : ''}
        ${f.fix ? `<div style="color:var(--color-dim);font-size:0.76rem;margin-top:2px">Fix: ${esc(f.fix)}</div>` : ''}
        ${f.code ? `<pre style="margin:6px 0 0;padding:6px 8px;background:#0b1220;border:1px solid rgba(148,163,184,0.2);border-radius:6px;font-size:0.72rem;overflow-x:auto;max-height:130px">${esc(f.code)}</pre>` : ''}
      </td>
      <td class="mono" style="font-size:0.74rem;color:var(--color-muted)">${esc(f.category || '')}</td>
    </tr>`;
  });
  h += '</tbody></table></div>';
  if (findings.length > MAX) h += `<div style="color:var(--color-dim);font-size:0.78rem;margin-top:6px">Showing first ${MAX} of ${findings.length} findings — full report available via <span class="mono">iris cloud usage</span> or the JSON API.</div>`;
  return h;
}

export async function deleteScan(id) {
  if (!confirm('Delete this scan and its stored report? This cannot be undone.')) return;
  try {
    await api('/api/v1/scans/' + encodeURIComponent(id), { method: 'DELETE' });
    toast('Scan deleted.');
    refreshAfterMutation();
    loadOverview();
  } catch (e) {
    toast('Delete failed: ' + e.message, 'err');
  }
}

// ---- share links ----
export async function createShare(id) {
  try {
    const r = await api(`/api/v1/scans/${encodeURIComponent(id)}/share`, { method: 'POST' });
    try {
      await navigator.clipboard.writeText(r.url);
      toast('Share link copied to clipboard (expires ' + new Date(r.expires_at).toLocaleDateString() + ').');
    } catch (_) {
      toast('Share link: ' + r.url);
    }
    const el = document.getElementById('share-' + encodeURIComponent(id));
    if (el) el.innerHTML = shareBoxHTML(id, r.url);
  } catch (e) {
    toast('Share failed: ' + e.message, 'err');
  }
}

export async function revokeShares(id) {
  try {
    const r = await api(`/api/v1/scans/${encodeURIComponent(id)}/share`, { method: 'DELETE' });
    toast(`Revoked ${r.revoked} share link(s).`);
    const el = document.getElementById('share-' + encodeURIComponent(id));
    if (el) el.innerHTML = '';
  } catch (e) {
    toast('Revoke failed: ' + e.message, 'err');
  }
}

export function shareBoxHTML(id, url) {
  return `<div class="share-box"><input readonly value="${esc(url)}" data-action="select-text"></div>`;
}

// ---- bulk selection / delete ----
export function toggleSelectAll(box) {
  document.querySelectorAll('.scan-sel').forEach(c => { c.checked = box.checked; });
  updateBulkBtn();
}

export function updateBulkBtn() {
  const n = document.querySelectorAll('.scan-sel:checked').length;
  const b = $('bulk-btn');
  if (!b) return;
  b.disabled = n === 0;
  b.textContent = n ? `Delete selected (${n})` : 'Delete selected';
}

export async function bulkDeleteSelected() {
  const ids = [...document.querySelectorAll('.scan-sel:checked')].map(c => c.dataset.id);
  if (!ids.length) return;
  if (!confirm(`Delete ${ids.length} scan(s) and their stored reports? This cannot be undone.`)) return;
  try {
    const r = await api('/api/v1/scans/bulk-delete', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ ids })
    });
    toast(`Deleted ${r.deleted_count} scan(s)${r.failed_count ? `, ${r.failed_count} failed` : ''}.`, r.failed_count ? 'warn' : 'ok');
    refreshAfterMutation();
    loadOverview();
    if (state.me_admin) fire('adminScans');
  } catch (e) {
    toast('Bulk delete failed: ' + e.message, 'err');
  }
}

// ---- auto refresh ----
export function toggleAutoRefresh() {
  const b = $('auto-btn');
  if (state.autoTimer) {
    clearInterval(state.autoTimer);
    state.autoTimer = null;
    b.textContent = 'Auto-refresh: off';
    b.style.color = '';
    toast('Auto-refresh off.');
  } else {
    state.autoTimer = setInterval(() => {
      loadScans();
      loadOverview();
      loadTrend();
      if (state.me_admin) {
        fire('adminScans');
        fire('system');
      }
    }, 20000);
    b.textContent = 'Auto-refresh: 20s';
    b.style.color = 'var(--color-good)';
    toast('Auto-refresh on (20s).');
  }
}

// ---- trend ----
export async function loadTrend() {
  try {
    const t = await api('/api/v1/scans/trend?days=' + state.trendDays);
    renderTrend($('trend-chart'), t, 'Last ' + state.trendDays + ' days', 'own');
  } catch (e) { /* chart is non-critical */ }
}

export function setTrendDays(d) {
  state.trendDays = d;
  loadTrend();
}

onSectionEnter('scans', () => {
  loadScans();
  loadTrend();
});
