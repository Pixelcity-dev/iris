// Workbench: findings explorer (with CSV export), scan comparison,
// privacy-respecting web search.

import { $, esc, shorten } from '../core/dom.js';
import { state } from '../core/state.js';
import { api } from '../core/api.js';
import { toast } from '../ui/toast.js';
import { emptyState } from '../ui/feedback.js';
import { SEV_COLORS } from '../ui/charts.js';
import { showSection } from '../core/routing.js';
import { toggleScanDetail } from './scans.js';

export async function runFindings() {
  const box = $('findings-results');
  box.style.display = 'block';
  box.innerHTML = '<span class="spinner"></span>';
  try {
    const url = findingsURL(false);
    const r = await api(url);
    const rows = r.findings || [];
    if (!rows.length) {
      box.innerHTML = emptyState('No matching findings', 'Nothing in your history matches that filter — broaden the search or scan something new.', 'iris scan ./repo');
      return;
    }
    let h = `<div style="color:var(--color-muted);font-size:0.78rem;margin-bottom:8px">${rows.length} finding(s)${r.truncated ? ' (truncated)' : ''} across ${r.scans_searched} scan(s)</div>`;
    h += '<div class="table-shell"><table class="data-table"><thead><tr><th>Severity</th><th>Rule</th><th>Finding</th><th>File</th><th>Scan</th></tr></thead><tbody>';
    rows.forEach(f => {
      const sev = String(f.severity || 'INFO').toUpperCase();
      h += `<tr>
        <td><span style="color:${SEV_COLORS[sev] || SEV_COLORS.INFO};font-weight:600;font-size:0.78rem">${esc(sev)}</span></td>
        <td class="mono" style="font-size:0.74rem">${esc(f.rule_id || '')}</td>
        <td>${esc(f.title || '')}</td>
        <td class="mono" style="font-size:0.74rem">${esc(f.file || '')}${f.line ? ':' + f.line : ''}</td>
        <td class="mono" style="font-size:0.72rem;color:var(--color-muted);cursor:pointer" data-action="scan-jump" data-id="${esc(f.scan_id)}">${esc(shorten(f.target || f.scan_id))}</td>
      </tr>`;
    });
    box.innerHTML = h + '</tbody></table></div>';
    toast(`${rows.length} finding(s) found.`);
  } catch (e) {
    box.innerHTML = '';
    toast('Findings search failed: ' + e.message, 'err');
  }
}

function findingsURL(csv) {
  const q = $('fx-q').value.trim(), sev = $('fx-sev').value;
  const all = state.me_admin && $('fx-all') && $('fx-all').checked;
  let url = '/api/v1/scans/findings?limit=' + (csv ? 500 : 200) +
    (q ? '&q=' + encodeURIComponent(q) : '') + (sev ? '&severity=' + encodeURIComponent(sev) : '');
  if (all) url += '&user=*';
  if (csv) url += '&format=csv';
  return url;
}

export function exportFindingsCSV() {
  const a = document.createElement('a');
  a.href = findingsURL(true);
  a.download = 'iris-findings.csv';
  document.body.appendChild(a);
  a.click();
  a.remove();
  toast('Findings CSV download started.');
}

export function toggleScanDetailByRow(id) {
  showSection('scans');
  setTimeout(() => {
    const row = document.querySelector(`#scans-body tr[data-action="scan-detail"][data-id="${CSS.escape(id)}"]`);
    if (row) {
      row.scrollIntoView({ behavior: 'smooth', block: 'center' });
      toggleScanDetail(row, id, 6);
    } else {
      toast('Scan not in the recent list — open Scan history.', 'warn');
    }
  }, 120);
}

// ---- compare ----
export async function runCompare() {
  const box = $('compare-results');
  const a = $('cmp-a').value, b = $('cmp-b').value;
  if (!a || !b) { toast('Pick two scans to compare.', 'warn'); return; }
  if (a === b) { toast('Pick two different scans.', 'warn'); return; }
  box.style.display = 'block';
  box.innerHTML = '<span class="spinner"></span>';
  try {
    const r = await api(`/api/v1/scans/compare?a=${encodeURIComponent(a)}&b=${encodeURIComponent(b)}`);
    const s = r.summary || {};
    const chip = (n, color, label) => `<span class="badge" style="border-color:${color};margin-right:8px">${n} ${label}</span>`;
    let h = `<div style="padding:4px 0 10px">${chip(s.added || 0, 'rgba(252,165,165,.5)', 'new')}${chip(s.resolved || 0, 'rgba(134,239,172,.5)', 'resolved')}${chip(s.unchanged || 0, 'rgba(148,163,184,.4)', 'unchanged')}</div>`;
    const renderRows = (rows, label) => {
      if (!rows.length) return '';
      let x = `<h4 style="margin:10px 0 6px">${label}</h4><div class="table-shell"><table class="data-table"><thead><tr><th>Severity</th><th>Rule</th><th>Finding</th><th>File</th></tr></thead><tbody>`;
      rows.forEach(f => {
        const sev = String(f.severity || 'INFO').toUpperCase();
        x += `<tr><td><span style="color:${SEV_COLORS[sev] || SEV_COLORS.INFO};font-weight:600;font-size:0.78rem">${esc(sev)}</span></td>
          <td class="mono" style="font-size:0.74rem">${esc(f.rule_id || '')}</td>
          <td>${esc(f.title || '')}</td>
          <td class="mono" style="font-size:0.74rem">${esc(f.file || '')}${f.line ? ':' + f.line : ''}</td></tr>`;
      });
      return x + '</tbody></table></div>';
    };
    h += renderRows(r.added || [], 'New findings') + renderRows(r.resolved || [], 'Resolved findings');
    if (!(r.added || []).length && !(r.resolved || []).length)
      h += '<div style="color:var(--color-dim);font-size:0.85rem">No differences — the scans are equivalent.</div>';
    box.innerHTML = h;
    toast(`Diff: ${s.added || 0} new, ${s.resolved || 0} resolved.`);
  } catch (e) {
    box.innerHTML = '';
    toast('Compare failed: ' + e.message, 'err');
  }
}

// ---- web search ----
export async function runWebSearch() {
  const box = $('ws-results');
  const q = $('ws-q').value.trim();
  if (!q) { toast('Type something to search.', 'warn'); return; }
  box.innerHTML = '<span class="spinner"></span>';
  try {
    const r = await api('/api/v1/tools/search?q=' + encodeURIComponent(q));
    const rows = r.results || [];
    if (!rows.length) {
      box.innerHTML = '<div style="color:var(--color-dim);font-size:0.85rem">No results.</div>';
      return;
    }
    box.innerHTML = rows.map(x => `<div style="padding:8px 0;border-bottom:1px solid rgba(148,163,184,.14)">
      <a href="${esc(x.url)}" target="_blank" rel="noopener noreferrer" style="color:var(--gold);font-size:0.9rem">${esc(x.title || x.url)}</a>
      <div style="color:var(--color-muted);font-size:0.78rem;word-break:break-all">${esc(x.url)}</div>
      ${x.content ? `<div style="color:var(--color-dim);font-size:0.82rem;margin-top:3px">${esc(x.content.slice(0, 300))}</div>` : ''}
      ${x.engine ? `<span class="mono" style="font-size:0.7rem;color:var(--color-muted)">${esc(x.engine)}</span>` : ''}
    </div>`).join('');
    toast(`${rows.length} result(s).`);
  } catch (e) {
    box.innerHTML = '';
    toast('Search failed: ' + e.message, 'err');
  }
}
