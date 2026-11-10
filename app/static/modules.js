'use strict';
/* SignalHarbor v1.1 modules: Vuln Priority, Purple Team, analyst brief, SARIF, audit anchor.
   Relies on helpers from app.js: $, safe, api, requestForm, setupForm, showResult, toast, attachFileLabel. */

const PRIORITY_CLASS = {P1: 'bad', P2: 'warn', P3: 'neutral', P4: 'good'};
const OUTCOME_COLORS = {prevented: '#77e4c0', alerted: '#6c9cff', logged: '#f7ba69', missed: '#ff7585'};

function statTiles(tiles) {
  return `<div class="stat-row">${tiles.map(([label, value, cls]) =>
    `<div class="stat-tile"><span>${safe(label)}</span><strong class="${cls || ''}">${safe(value)}</strong></div>`).join('')}</div>`;
}

function vulnTable(ranked) {
  const rows = ranked.slice(0, 25).map(v => `<tr>
      <td><span class="prio ${PRIORITY_CLASS[v.priority]}">${safe(v.priority)}</span></td>
      <td><span class="mono">${safe(v.cve)}</span><br><span class="finding-meta">${safe(v.title)}</span></td>
      <td>${safe(v.asset)}</td>
      <td>${safe(v.risk)}</td>
      <td class="reason">${safe(v.reason)}</td>
      <td>${v.due ? safe(v.due) : '—'}${v.overdue ? ' <span class="overdue">OVERDUE</span>' : ''}</td></tr>`).join('');
  return `<div class="table-scroll"><table class="data-table compact"><thead><tr><th>PRIORITY</th><th>CVE</th><th>ASSET</th><th>RISK</th><th>WHY</th><th>DUE</th></tr></thead><tbody>${rows}</tbody></table></div>`;
}

function renderVulns(data) {
  const d = data.details, c = d.priority_counts;
  const extra = statTiles([['P1 · 7 days', c.P1, 'bad'], ['P2 · 30 days', c.P2, 'warn'], ['P3 · 90 days', c.P3],
    ['P4 · 180 days', c.P4, 'good'], ['Overdue', d.overdue, d.overdue ? 'bad' : '']]) +
    `<h4 class="sub-head">Risk-ranked queue ${d.enriched ? '' : '<span class="finding-meta">(no EPSS values — run scripts/enrich_vulns.py to add them)</span>'}</h4>` + vulnTable(d.ranked);
  showResult('vulnsResult', data, `Prioritized ${d.rows} vulnerabilities`);
  $('vulnsResult').insertAdjacentHTML('beforeend', extra);
}

function coverageMatrix(matrix) {
  return `<div class="matrix">${matrix.map(r => {
    const seg = ['prevented', 'alerted', 'logged', 'missed'].map(k => r[k] ?
      `<span data-flex="${r[k]}" data-bg="${OUTCOME_COLORS[k]}" title="${k}: ${r[k]}"></span>` : '').join('');
    return `<div class="matrix-row"><span class="matrix-label">${safe(r.tactic.replace(/-/g, ' '))}</span>
      <div class="matrix-bar" role="img" aria-label="${safe(r.tactic)}: ${r.coverage_pct}% prevented or alerted">${seg}</div>
      <span class="matrix-pct">${r.coverage_pct}%</span><span class="finding-meta">${r.tests} test${r.tests === 1 ? '' : 's'}</span></div>`;
  }).join('')}</div>
  <div class="legend-row">${Object.entries(OUTCOME_COLORS).map(([k, c]) => `<span><i data-bg="${c}"></i>${k}</span>`).join('')}</div>`;
}

function renderCoverage(data) {
  const d = data.details, o = d.outcomes;
  const extra = statTiles([['Detection rate', d.detection_rate_pct + '%', d.detection_rate_pct >= 75 ? 'good' : 'warn'],
    ['Visibility', d.visibility_pct + '%'], ['Missed', o.missed, o.missed ? 'bad' : 'good'],
    ['Logged, no alert', o.logged, o.logged ? 'warn' : ''], ['Median TTD', d.median_ttd_min == null ? '—' : d.median_ttd_min + ' min']]) +
    `<h4 class="sub-head">Coverage by ATT&amp;CK tactic · ${safe(d.exercise)} · ${safe(d.tool)}</h4>` + coverageMatrix(d.matrix);
  showResult('coverageResult', data, `${d.tests} tests across ${d.techniques} techniques`);
  $('coverageResult').insertAdjacentHTML('beforeend', extra);
}

async function generateBrief() {
  const btn = $('briefBtn');
  btn.disabled = true;
  $('briefText').textContent = 'Generating… (a CPU-only local model can take a minute)';
  try {
    const data = await api('/api/ai/brief', {method: 'POST'});
    $('briefText').textContent = data.brief;            // textContent: model output is never parsed as HTML
    $('briefMeta').textContent = `Engine: ${data.engine} · ${data.note}`;
  } catch (e) { toast(e.message, true); $('briefText').textContent = 'Brief unavailable.'; }
  finally { btn.disabled = false; }
}

async function anchorAudit() {
  try {
    const a = await api('/api/audit/anchor');
    const text = JSON.stringify(a, null, 2);
    $('auditState').textContent = `Chain head to store outside this machine (ticket, e-mail, git):\n${text}`;
    $('auditState').classList.add('pre');
    try { await navigator.clipboard.writeText(text); toast('Anchor copied to clipboard'); } catch { /* clipboard optional */ }
  } catch (e) { toast(e.message, true); }
}

/* The CSP forbids inline style attributes (style-src 'self'), so colours and sizes travel as
   data-* attributes and are applied through the CSSOM, which CSP permits. */
function applyDataStyles(root) {
  root.querySelectorAll('[data-bg],[data-flex]').forEach(el => {
    if (el.dataset.bg && /^#[0-9a-f]{3,8}$/i.test(el.dataset.bg)) el.style.background = el.dataset.bg;
    if (el.dataset.flex) el.style.flex = String(Number(el.dataset.flex) || 0);
  });
}

document.addEventListener('DOMContentLoaded', () => {
  applyDataStyles(document);
  new MutationObserver(muts => muts.forEach(m => m.addedNodes.forEach(n => { if (n.nodeType === 1) applyDataStyles(n.parentNode || n); })))
    .observe(document.body, {childList: true, subtree: true});
  attachFileLabel('vulnsFile', 'vulnsFileLabel');
  attachFileLabel('coverageFile', 'coverageFileLabel');
  setupForm('vulnsForm', async (form) => renderVulns(await requestForm('/api/vulns', form)));
  setupForm('coverageForm', async (form) => renderCoverage(await requestForm('/api/coverage', form)));
  $('briefBtn').addEventListener('click', generateBrief);
  $('anchorBtn').addEventListener('click', anchorAudit);
  $('exportSarif').addEventListener('click', () => { window.location.href = '/api/report.sarif'; });
  const fromHash = location.hash.replace('#', '');
  if (fromHash && names[fromHash]) navigate(fromHash);
  document.addEventListener('sh:navigate', (e) => { history.replaceState(null, '', '#' + e.detail); });
});
