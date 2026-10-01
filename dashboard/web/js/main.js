// Iris Dashboard bootstrap: event delegation, section wiring, session init.
//
// All interactive markup declares intent via data-section / data-action /
// data-enter attributes; this module is the single place that maps them
// to behavior — no inline handlers anywhere.

import { $ } from './core/dom.js';
import { state } from './core/state.js';
import { api, showLogin } from './core/api.js';
import { showSection } from './core/routing.js';
import { hook } from './core/hooks.js';
import { toast } from './ui/toast.js';
import { copyCmd } from './ui/feedback.js';
import { loadPlan, loadUsage, setBillingInterval, checkout } from './sections/plan.js';
import { loadOverview } from './sections/overview.js';
import {
  loadScans, loadTrend, setTrendDays, toggleAutoRefresh,
  bulkDeleteSelected, toggleSelectAll, updateBulkBtn,
  toggleScanDetail, deleteScan, createShare, revokeShares,
} from './sections/scans.js';
import { runFindings, exportFindingsCSV, runCompare, runWebSearch, toggleScanDetailByRow } from './sections/tools.js';
import { loadAccount, saveProfile, changePassword, loadSessions, revokeSession } from './sections/account.js';
import {
  loadAdmin, renderAdminUsers, toggleCreateUser, adminCreate, adminSaveUser,
  adminResetPw, adminToggleBan, adminToggleEnabled, adminRevoke, adminDeleteUser,
  adminCloseDetail, adminSelect, setAdminTrendDays, loadAdminTrend, loadSystem,
  clearAdminFilter,
} from './sections/admin.js';
import { initPalette, openPalette } from './palette.js';

// ---- action dispatch table ----

const actions = {
  // scans
  'refresh-scans': () => { loadScans(); loadTrend(); toast('Refreshed.'); },
  'toggle-auto': () => toggleAutoRefresh(),
  'bulk-delete': () => bulkDeleteSelected(),
  'scan-detail': (el) => toggleScanDetail(el, el.dataset.id, +(el.dataset.cols || 6)),
  'scan-jump': (el) => toggleScanDetailByRow(el.dataset.id),
  'share': (el) => createShare(el.dataset.id),
  'revoke-shares': (el) => revokeShares(el.dataset.id),
  'delete-scan': (el) => deleteScan(el.dataset.id),
  'trend-days': (el) => {
    const d = +el.dataset.days;
    if (el.dataset.which === 'admin') setAdminTrendDays(d);
    else setTrendDays(d);
  },

  // tools
  'run-findings': () => runFindings(),
  'export-findings': () => exportFindingsCSV(),
  'run-compare': () => runCompare(),
  'run-web-search': () => runWebSearch(),

  // account
  'save-profile': () => saveProfile(),
  'change-password': () => changePassword(),
  'revoke-session': (el) => revokeSession(el.dataset.id),

  // plans / billing
  'checkout': (el) => checkout(el.dataset.plan),
  'set-interval': (el) => setBillingInterval(el.dataset.plan, el.dataset.interval, el),

  // admin
  'toggle-create-user': () => toggleCreateUser(),
  'admin-create': () => adminCreate(),
  'admin-refresh': () => loadAdmin(),
  'admin-select': (el) => adminSelect(+el.dataset.idx),
  'admin-close-detail': () => adminCloseDetail(),
  'admin-save': () => adminSaveUser(),
  'admin-reset-pw': () => adminResetPw(),
  'admin-toggle-ban': () => adminToggleBan(),
  'admin-toggle-enabled': () => adminToggleEnabled(),
  'admin-revoke': () => adminRevoke(),
  'admin-delete': () => adminDeleteUser(),
  'admin-clear-filter': () => clearAdminFilter(),

  // misc
  'copy-cmd': (el) => copyCmd(el),
  'select-text': (el) => el.select(),
};

// ---- global delegation ----

document.addEventListener('click', (e) => {
  const sec = e.target.closest('[data-section]');
  if (sec) {
    if (sec.getAttribute('href') === '#') e.preventDefault();
    showSection(sec.dataset.section);
    return;
  }
  // Row checkboxes manage themselves through the change listener.
  if (e.target.closest('.scan-sel')) return;
  const el = e.target.closest('[data-action]');
  if (!el) return;
  if (el.tagName === 'A' && el.getAttribute('href') === '#') e.preventDefault();
  const fn = actions[el.dataset.action];
  if (fn) fn(el, e);
});

document.addEventListener('change', (e) => {
  if (e.target.id === 'sel-all') toggleSelectAll(e.target);
  else if (e.target.classList.contains('scan-sel')) updateBulkBtn();
});

document.addEventListener('input', (e) => {
  if (e.target.id === 'admin-search') renderAdminUsers();
});

document.addEventListener('keydown', (e) => {
  if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'k') {
    e.preventDefault();
    openPalette();
    return;
  }
  if (e.key === 'Enter' && e.target.dataset && e.target.dataset.enter) {
    const fn = actions[e.target.dataset.enter];
    if (fn) fn(e.target, e);
  }
});

window.addEventListener('hashchange', () => showSection(location.hash.slice(1)));

// ---- boot splash: once per browser session, removed after exit ----

function boot() {
  const el = document.getElementById('boot');
  if (!el) return;
  let seen = false;
  try {
    seen = sessionStorage.getItem('iris_booted') === '1';
    sessionStorage.setItem('iris_booted', '1');
  } catch (e) { /* private mode */ }
  if (seen || matchMedia('(prefers-reduced-motion: reduce)').matches) {
    el.classList.add('gone');
    return;
  }
  setTimeout(() => el.remove(), 1500);
}

// ---- session init ----

async function init() {
  try {
    const me = await api('/api/v1/me');
    $('view-login').style.display = 'none';
    $('view-app').style.display = 'block';
    $('user-chip').style.display = 'flex';
    $('username').textContent = me.username || me.email;
    $('greeting').textContent = `Welcome back, ${me.username || 'user'}`;
    if (me.admin) {
      state.me_admin = true;
      $('nav-admin').style.display = '';
      $('fx-allwrap').style.display = 'block';
      loadAdmin();
      loadAdminTrend();
      loadSystem();
    }
    loadPlan();
    loadUsage();
    loadAccount();
    loadSessions();
    loadScans();
    loadTrend();
    loadOverview();
    showSection(location.hash.slice(1) || 'overview');
  } catch (e) {
    showLogin();
  }
}

// Profile saves re-run init() to refresh identity-dependent chrome.
hook('reloadIdentity', init);

function initIntervalButtons() {
  document.querySelectorAll('.interval-btn[data-interval="monthly"]').forEach(b => b.classList.add('active'));
}
if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', initIntervalButtons);
} else {
  initIntervalButtons();
}

initPalette();
boot();
init();
