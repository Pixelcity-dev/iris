// Command palette (Ctrl/Cmd+K). Static containers get listeners once;
// the item list re-renders and uses data-attribute delegation.

import { $, esc, scrollToId } from './core/dom.js';
import { state } from './core/state.js';
import { showSection } from './core/routing.js';
import { toast } from './ui/toast.js';
import { loadScans, loadTrend, toggleAutoRefresh } from './sections/scans.js';
import { loadOverview } from './sections/overview.js';
import { loadPlan } from './sections/plan.js';
import { exportFindingsCSV } from './sections/tools.js';
import { loadAdmin, toggleCreateUser } from './sections/admin.js';

const PAL_ITEMS = [
  { t: 'Go to overview', k: 'G O', run: () => showSection('overview') },
  { t: 'Go to scan history', k: 'G S', run: () => showSection('scans') },
  { t: 'Go to tools (findings / compare / search)', k: 'G T', run: () => showSection('tools') },
  { t: 'Go to billing history', k: 'G B', run: () => showSection('billing') },
  { t: 'Go to account', k: 'G A', run: () => showSection('account') },
  { t: 'Go to plans', k: 'G P', run: () => showSection('plans') },
  { t: 'Go to roadmap', k: 'G R', run: () => showSection('roadmap') },
  { t: 'Findings explorer: focus search', k: 'F', run: () => { showSection('tools'); setTimeout(() => $('fx-q').focus(), 120); } },
  { t: 'Findings explorer: export CSV', k: 'C', run: () => exportFindingsCSV() },
  { t: 'Web search: focus', k: 'W', run: () => { showSection('tools'); setTimeout(() => $('ws-q').focus(), 120); } },
  { t: 'Compare scans: pick A/B', k: 'D', run: () => { showSection('tools'); setTimeout(() => $('cmp-a').focus(), 120); } },
  { t: 'Refresh all data', k: 'R', run: () => { loadScans(); loadOverview(); loadTrend(); loadPlan(); if (state.me_admin) loadAdmin(); toast('Refreshed.'); } },
  { t: 'Toggle auto-refresh (20s)', k: 'A', run: () => toggleAutoRefresh() },
  { t: 'Sign out', k: 'Q', run: () => { location.href = '/auth/logout'; } },
  { t: 'Admin: users', k: '', run: () => showSection('admin'), admin: true },
  { t: 'Admin: create user', k: '', run: () => { showSection('admin'); setTimeout(() => { if ($('admin-create').style.display === 'none') toggleCreateUser(); }, 120); }, admin: true },
  { t: 'Admin: all scans', k: '', run: () => { showSection('admin'); setTimeout(() => scrollToId('admin-scans-body'), 120); }, admin: true },
  { t: 'Admin: system diagnostics', k: '', run: () => { showSection('admin'); setTimeout(() => scrollToId('admin-system'), 120); }, admin: true },
];

let palIndex = 0;

export function openPalette() {
  $('palette').classList.add('open');
  $('pal-input').value = '';
  palIndex = 0;
  renderPalette();
  setTimeout(() => $('pal-input').focus(), 30);
}

export function closePalette() {
  $('palette').classList.remove('open');
}

function palFiltered() {
  const q = $('pal-input').value.trim().toLowerCase();
  return PAL_ITEMS.filter(it => (!it.admin || state.me_admin) && (!q || it.t.toLowerCase().includes(q)));
}

function renderPalette() {
  const items = palFiltered();
  if (palIndex >= items.length) palIndex = Math.max(0, items.length - 1);
  $('pal-list').innerHTML = items.length ? items.map((it, i) =>
    `<div class="pal-item${i === palIndex ? ' active' : ''}" role="option" data-pal-index="${i}">
       <span>${esc(it.t)}</span>${it.k ? `<span class="pal-key">${esc(it.k)}</span>` : ''}
     </div>`).join('')
    : '<div class="pal-item">No matches</div>';
}

function paletteKey(e) {
  const items = palFiltered();
  if (e.key === 'Escape') { closePalette(); return; }
  if (e.key === 'ArrowDown') { e.preventDefault(); palIndex = Math.min(items.length - 1, palIndex + 1); renderPalette(); }
  else if (e.key === 'ArrowUp') { e.preventDefault(); palIndex = Math.max(0, palIndex - 1); renderPalette(); }
  else if (e.key === 'Enter') { e.preventDefault(); palRun(palIndex); }
}

function palRun(i) {
  const items = palFiltered();
  const it = items[i];
  if (!it) return;
  closePalette();
  it.run();
}

export function initPalette() {
  const input = $('pal-input');
  input.addEventListener('input', renderPalette);
  input.addEventListener('keydown', paletteKey);

  $('pal-list').addEventListener('click', e => {
    const item = e.target.closest('[data-pal-index]');
    if (item) palRun(+item.dataset.palIndex);
  });
  $('pal-list').addEventListener('mouseover', e => {
    const item = e.target.closest('[data-pal-index]');
    if (item) {
      palIndex = +item.dataset.palIndex;
      renderPalette();
    }
  });

  $('palette').addEventListener('click', e => {
    if (e.target === $('palette')) closePalette();
  });
}
