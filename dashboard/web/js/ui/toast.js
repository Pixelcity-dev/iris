// Toast notifications — bottom-right stack, aria-live for screen readers.

export function toast(msg, kind) {
  let el = document.getElementById('toast-box');
  if (!el) {
    el = document.createElement('div');
    el.id = 'toast-box';
    el.setAttribute('role', 'status');
    el.setAttribute('aria-live', 'polite');
    document.body.appendChild(el);
  }
  const t = document.createElement('div');
  t.className = 'toast' + (kind === 'err' ? ' err' : kind === 'warn' ? ' warn' : '');
  t.textContent = msg;
  el.appendChild(t);
  setTimeout(() => {
    t.classList.add('leaving');
    setTimeout(() => t.remove(), 350);
  }, kind === 'err' ? 6000 : 3500);
}
