// DOM + formatting helpers shared by every module.

export const $ = (id) => document.getElementById(id);

export function esc(s) {
  const d = document.createElement('div');
  d.textContent = s ?? '';
  return d.innerHTML;
}

export function shorten(s) {
  s = s ?? '';
  return s.length > 42 ? s.slice(0, 39) + '…' : s;
}

export function scrollToId(id) {
  const el = $(id);
  if (el) el.scrollIntoView({ behavior: 'smooth', block: 'start' });
}

export function money(cents, currency) {
  if (cents == null) return '—';
  try {
    return new Intl.NumberFormat('en-US', { style: 'currency', currency: currency || 'USD' }).format(cents / 100);
  } catch (e) {
    return (cents / 100).toFixed(2);
  }
}
