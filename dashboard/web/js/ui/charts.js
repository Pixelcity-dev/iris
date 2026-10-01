// Severity palette + chart renderers: stacked-severity trend bars,
// findings donut, and the compact per-scan severity chips.

import { $, esc } from '../core/dom.js';
import { state } from '../core/state.js';

export const SEV_COLORS = { CRITICAL: '#ef4444', HIGH: '#f97316', MEDIUM: '#eab308', LOW: '#38bdf8', INFO: '#94a3b8' };
export const SEV_ORDER = ['critical', 'high', 'medium', 'low', 'info'];

export function sevChips(e) {
  const total = e.findings ?? 0;
  const c = e.severity_counts;
  if (!c || !Object.keys(c).length) return `<span class="mono">${total}</span>`;
  const chips = ['critical', 'high', 'medium', 'low', 'info'].filter(k => c[k]).map(k =>
    `<span style="color:${SEV_COLORS[k.toUpperCase()]};font-weight:600;font-size:0.72rem;margin-right:6px;white-space:nowrap">${k[0].toUpperCase()}·${c[k]}</span>`).join('');
  return `<span class="mono" style="margin-right:4px">${total}</span>${chips}`;
}

function trendSelector(which) {
  const cur = which === 'admin' ? state.adminTrendDays : state.trendDays;
  const btn = d => `<a href="#" data-action="trend-days" data-which="${which}" data-days="${d}" style="margin-left:7px;${d === cur ? 'color:var(--gold);font-weight:600' : 'color:var(--color-muted)'}">${d}d</a>`;
  return `<span style="float:right">${btn(7)}${btn(30)}${btn(90)}</span>`;
}

// renderTrend draws a stacked-severity SVG bar chart of daily findings.
export function renderTrend(el, t, label, which) {
  if (!el) return;
  const pts = (t && t.points) || [];
  if (!pts.length) return;
  const sel = which ? trendSelector(which) : '';
  const totalScans = pts.reduce((a, p) => a + (p.scans || 0), 0);
  const totalFindings = pts.reduce((a, p) => a + (p.findings || 0), 0);
  const summary = `<div style="font-size:0.78rem;color:var(--color-muted);margin-bottom:6px">${sel}${label} · <strong style="color:var(--color-bright)">${totalScans}</strong> scans · <strong style="color:var(--color-bright)">${totalFindings}</strong> findings</div>`;

  if (!totalFindings) {
    el.innerHTML = summary + '<div style="height:6px;background:rgba(148,163,184,0.15);border-radius:4px"></div>';
    return;
  }
  const W = 720, H = 96, n = pts.length, gap = n > 45 ? 1 : 2;
  const bw = Math.max(1.5, (W - gap * (n - 1)) / n);
  const max = Math.max(1, ...pts.map(p => p.findings));
  const order = ['critical', 'high', 'medium', 'low', 'info', 'unknown'];
  let bars = '';
  pts.forEach((p, i) => {
    const x = i * (bw + gap);
    const buckets = Object.assign({}, p.severity || {});
    const known = Object.keys(buckets).reduce((a, k) => a + buckets[k], 0);
    if (p.findings > known) buckets.unknown = p.findings - known;
    let y = H - 14;
    order.forEach(k => {
      const v = buckets[k] || 0;
      if (!v) return;
      const h = (v / max) * (H - 22);
      y -= h;
      const color = k === 'unknown' ? '#64748b' : (SEV_COLORS[k.toUpperCase()] || '#64748b');
      bars += `<rect x="${x.toFixed(1)}" y="${y.toFixed(1)}" width="${bw.toFixed(1)}" height="${Math.max(1, h).toFixed(1)}" fill="${color}"><title>${p.date} · ${k}: ${v} (${p.scans} scans)</title></rect>`;
    });
    if (!p.findings && p.scans) {
      bars += `<rect x="${x.toFixed(1)}" y="${H - 16}" width="${bw.toFixed(1)}" height="2" fill="#334155"><title>${p.date} · ${p.scans} scans · clean</title></rect>`;
    }
  });
  const first = pts[0].date, mid = pts[Math.floor(n / 2)].date, last = pts[n - 1].date;
  el.innerHTML = summary +
    `<svg viewBox="0 0 ${W} ${H}" preserveAspectRatio="none" style="width:100%;height:96px;display:block">${bars}<line x1="0" y1="${H - 13}" x2="${W}" y2="${H - 13}" stroke="rgba(148,163,184,0.25)" stroke-width="1"/></svg>` +
    `<div style="display:flex;justify-content:space-between;font-size:0.7rem;color:var(--color-muted);margin-top:3px"><span>${first}</span><span>${mid}</span><span>${last}</span></div>`;
}

export function renderDonut(sev, total) {
  const R = 54, C = 2 * Math.PI * R;
  let off = 0, segs = '', legend = '';
  const shown = SEV_ORDER.filter(k => sev[k] > 0);
  shown.forEach(k => {
    const frac = sev[k] / (total || 1);
    const len = frac * C;
    segs += `<circle cx="70" cy="70" r="${R}" fill="none" stroke="${SEV_COLORS[k.toUpperCase()]}" stroke-width="16"
      stroke-dasharray="${len.toFixed(2)} ${(C - len).toFixed(2)}" stroke-dashoffset="${(-off).toFixed(2)}"
      transform="rotate(-90 70 70)"><title>${k}: ${sev[k]}</title></circle>`;
    off += len;
    legend += `<div class="row"><span><span class="dot" style="background:${SEV_COLORS[k.toUpperCase()]}"></span>${k}</span><span class="mono">${sev[k]}</span></div>`;
  });
  if (!shown.length) {
    segs = `<circle cx="70" cy="70" r="${R}" fill="none" stroke="#233" stroke-width="16"/>`;
    legend = '<div class="row"><span>No findings</span></div>';
  }
  $('ov-donut').innerHTML = `<svg width="140" height="140" viewBox="0 0 140 140" role="img" aria-label="Findings by severity">
    <circle cx="70" cy="70" r="${R}" fill="none" stroke="rgba(148,163,184,0.10)" stroke-width="16"/>
    ${segs}
    <text x="70" y="66" text-anchor="middle" fill="#fafafa" font-size="26" font-weight="700" font-family="ui-monospace,monospace">${total}</text>
    <text x="70" y="86" text-anchor="middle" fill="#8a8a94" font-size="9" letter-spacing="2" font-family="ui-monospace,monospace">FINDINGS</text>
  </svg>`;
  $('ov-legend').innerHTML = legend;
}
