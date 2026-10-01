// Plan quota cards, daily reset countdown, billing history, checkout.

import { $, esc, money } from '../core/dom.js';
import { state } from '../core/state.js';
import { api } from '../core/api.js';
import { emptyRow, showError } from '../ui/feedback.js';

export async function loadPlan() {
  try {
    const p = await api('/api/v1/plan');
    const tier = p.tier || 'free';
    const badge = tier === 'admin' || tier === 'enterprise' ? 'badge-gold' : tier === 'pro' ? 'badge-accent' : '';
    $('plan-tier').innerHTML = `<span class="badge ${badge}">${tier.toUpperCase()}</span>`;
    $('plan-sub').textContent = p.name ? `${p.name} plan · PixelCity ID` : 'Iris plan · PixelCity ID';
    const unlimited = tier === 'admin';

    // Daily quota (resets 00:00 UTC)
    const dUsed = p.daily_used ?? 0, dQuota = p.daily_quota ?? 0;
    $('today-used').textContent = dQuota ? `${dUsed} / ${dQuota}` : unlimited ? `${dUsed} · unlimited` : String(dUsed);
    setBar('today-bar', dQuota ? dUsed / dQuota : 0);
    state.planDailyResetAt = p.daily_resets_at || 0;
    updateResetNote();

    // Lifetime quota
    const used = p.scans_used ?? 0, quota = p.scan_quota ?? 0;
    $('scans-used').textContent = quota ? `${used} / ${quota}` : unlimited ? `${used} · unlimited` : String(used);
    setBar('scans-bar', quota ? used / quota : 0);
    $('scans-note').textContent = quota ? `${Math.max(0, quota - used)} left all-time` : '';

    const aiUsed = p.ai_pages_used ?? 0, aiQuota = p.ai_pages_quota ?? 0;
    $('ai-used').textContent = aiQuota ? `${aiUsed} / ${aiQuota}` : unlimited ? `${aiUsed} · unlimited` : tier === 'free' ? '—' : String(aiUsed);
    setBar('ai-bar', aiQuota ? aiUsed / aiQuota : 0);
  } catch (e) {
    planFallback();
  }
}

// ---- daily reset countdown (ticks once per second) ----
function updateResetNote() {
  const el = $('today-reset');
  if (!el) return;
  if (!state.planDailyResetAt) { el.className = 'stat-note'; el.textContent = 'resets 00:00 UTC'; return; }
  const secs = Math.max(0, Math.floor(state.planDailyResetAt - Date.now() / 1000));
  const h = Math.floor(secs / 3600), m = Math.floor((secs % 3600) / 60), s = secs % 60;
  const pad = n => String(n).padStart(2, '0');
  el.className = 'stat-note' + (secs < 1800 ? ' warn' : '');
  el.textContent = `resets in ${pad(h)}:${pad(m)}:${pad(s)}`;
}
setInterval(updateResetNote, 1000);

export function planFallback() {
  $('plan-tier').innerHTML = '<span class="badge">FREE</span>';
  $('plan-sub').textContent = 'Plan service unreachable — showing defaults.';
}

export function setBar(id, frac) {
  const el = $(id);
  if (!el) return;
  el.style.width = Math.min(100, frac * 100) + '%';
  el.className = 'bar-fill' + (frac >= 1 ? ' full' : frac > .8 ? ' warn' : '');
}

export async function loadUsage() {
  try {
    const u = await api('/api/v1/usage?limit=25');
    const body = $('usage-body');
    if (!u.entries || !u.entries.length) {
      body.innerHTML = emptyRow(5, 'No payments yet', 'Invoices and receipts appear here after your first payment.', '', 'Pick a plan → <a href="#" data-section="plans">Plans</a>');
      return;
    }
    body.innerHTML = u.entries.map(e => `<tr>
      <td class="mono" style="font-size:0.78rem;color:var(--color-muted)">${e.date ? new Date(e.date * 1000).toLocaleString() : '—'}</td>
      <td>${esc(e.label || 'Payment')}</td>
      <td class="mono">${money(e.amount, e.currency)}</td>
      <td><span class="badge">${esc(e.status || 'unknown')}</span></td>
      <td>${e.url ? `<a class="btn btn-ghost" href="${esc(e.url)}" target="_blank" rel="noopener">Receipt</a>` : ''}</td>
    </tr>`).join('');
  } catch (e) {
    $('usage-body').innerHTML = '<tr><td colspan="5" style="color:var(--color-dim)">Usage service unreachable.</td></tr>';
  }
}

export function setBillingInterval(plan, interval, btn) {
  state.billingInterval[plan] = interval;
  document.querySelectorAll(`.interval-btn[data-plan="${plan}"]`).forEach(b =>
    b.classList.toggle('active', b === btn));
}

export async function checkout(plan) {
  try {
    const cs = await api('/api/v1/billing/checkout', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: `plan=${plan}&interval=${state.billingInterval[plan] || 'monthly'}`
    });
    if (cs.url) location.href = cs.url;
  } catch (e) {
    showError('Checkout failed: ' + e.message);
  }
}
