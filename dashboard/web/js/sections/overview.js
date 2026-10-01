// Security overview: findings donut, top rules, scanner chips.

import { $, esc } from '../core/dom.js';
import { api } from '../core/api.js';
import { SEV_COLORS, SEV_ORDER, renderDonut } from '../ui/charts.js';

export async function loadOverview() {
  try {
    const st = await api('/api/v1/stats');
    const sev = st.severity || {};
    const total = SEV_ORDER.reduce((n, k) => n + (sev[k] || 0), 0);
    $('ov-badge').textContent = total ? `${total} findings` : 'clean';
    $('ov-badge').className = 'badge' + (total ? (sev.critical ? ' badge-bad' : sev.high ? ' badge-warn' : ' badge-good') : ' badge-good');
    renderDonut(sev, total);

    // top rules
    const rules = st.top_rules || [];
    $('ov-top-rules').innerHTML = rules.length ? rules.map(r => {
      const k = String(r.severity || 'INFO').toUpperCase();
      return `<div class="top-rule">
        <span style="color:${SEV_COLORS[k] || SEV_COLORS.INFO};font-weight:700;font-size:0.72rem;width:66px">${esc(k)}</span>
        <span class="mono" style="font-size:0.74rem;color:var(--color-muted)">${esc(r.rule_id || r.title || '')}</span>
        <span class="cnt">×${r.count}</span>
      </div>`;
    }).join('') : '<div style="color:var(--color-dim);font-size:0.85rem">No findings recorded.</div>';

    // scanners
    $('ov-scanners').innerHTML = (st.scanners || []).sort((a, b) => b.count - a.count)
      .map(x => `<span class="scanner-chip">${esc(x.scanner)} <b>${x.count}</b></span>`).join('')
      || '<span style="color:var(--color-dim);font-size:0.85rem">No scans yet.</span>';

    $('ov-note').textContent = `${st.scans || 0} scan(s) · ${st.scans_with_reports || 0} with stored reports`;
  } catch (e) {
    $('ov-badge').textContent = 'unavailable';
    $('ov-top-rules').innerHTML = '<div style="color:var(--color-dim);font-size:0.85rem">Stats unavailable.</div>';
  }
}
