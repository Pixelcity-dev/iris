// Shared feedback building blocks: empty states, copyable commands, error box.

import { esc } from '../core/dom.js';

export function emptyState(title, copy, cmd, alt) {
  const mark = '<svg class="empty-mark" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M7 10H6a4 4 0 0 1-4-4 1 1 0 0 1 1-1h4"/><path d="M7 5a1 1 0 0 1 1-1h13a1 1 0 0 1 1 1 7 7 0 0 1-7 7H8a1 1 0 0 1-1-1z"/><path d="M9 12v5"/><path d="M15 12v5"/><path d="M5 20a3 3 0 0 1 3-3h8a3 3 0 0 1 3 3 1 1 0 0 1-1 1H6a1 1 0 0 1-1-1"/></svg>';
  const cmdHtml = cmd
    ? `<button class="empty-cmd" type="button" data-action="copy-cmd" data-cmd="${esc(cmd)}">${esc(cmd)}</button>`
    : '';
  return `<div class="empty">${mark}<div class="empty-title">${title}</div>` +
    `<div class="empty-copy">${copy}</div>${cmdHtml}` +
    (alt ? `<div class="empty-alt">${alt}</div>` : '') + '</div>';
}

export function copyCmd(btn) {
  const cmd = btn.dataset.cmd || '';
  const done = () => {
    btn.textContent = 'Copied to clipboard';
    setTimeout(() => { btn.textContent = cmd; }, 1400);
  };
  if (navigator.clipboard && navigator.clipboard.writeText) navigator.clipboard.writeText(cmd).then(done, () => {});
}

export function emptyRow(cols, title, copy, cmd, alt) {
  return `<tr><td colspan="${cols}">${emptyState(title, copy, cmd, alt)}</td></tr>`;
}

export function showError(msg) {
  const el = document.getElementById('error-box');
  el.textContent = msg;
  el.style.display = 'block';
}
