// Section routing: one page per dashboard category.
// Sections register per-entry side effects (loaders) via onSectionEnter,
// which keeps the import graph acyclic (routing never imports sections).

import { state } from './state.js';

export const SECTIONS = ['overview', 'scans', 'tools', 'billing', 'account', 'plans', 'roadmap', 'admin'];

const enterHooks = {};

export function onSectionEnter(name, fn) {
  (enterHooks[name] ||= []).push(fn);
}

export function showSection(name) {
  if (SECTIONS.indexOf(name) === -1) name = 'overview';
  if (name === 'admin' && !state.me_admin) name = 'overview';
  state.currentSec = name;

  document.querySelectorAll('.app-sec').forEach(s => s.classList.toggle('active', s.id === 'sec-' + name));
  document.querySelectorAll('.nav-item').forEach(b => {
    const on = b.dataset.section === name;
    b.classList.toggle('active', on);
    if (on) b.setAttribute('aria-current', 'page');
    else b.removeAttribute('aria-current');
  });

  if (location.hash.slice(1) !== name) history.replaceState(null, '', '#' + name);
  (enterHooks[name] || []).forEach(fn => fn());
  window.scrollTo(0, 0);
}
