// ThreatLens console — hunt workspace: facets, relationship graph, ATT&CK overlay, results.

import { state, api, actions, qs, qsa, escapeHtml, severityChip, tlpChip, ago, zTime, showToast, setBanner, stateMarkup, errorMarkup, demoAlerts } from './core.js';

export function renderFacets(kind) {
  const target = qs('#facet-content');
  if (['loading', 'empty', 'error'].includes(kind)) {
    target.innerHTML = stateMarkup(kind);
    window.lucide?.createIcons();
    return;
  }
  if (state.mode === 'live') {
    const fc = state.liveSearch?.facet_counts || { types: {}, sources: {}, tags: {} };
    const groups = [
      ['TYPE', Object.entries(fc.types || {})],
      ['SOURCE', Object.entries(fc.sources || {})],
      ['TAG', Object.entries(fc.tags || {}).slice(0, 10)],
    ];
    const groupKey = { TYPE: 'types', SOURCE: 'sources', TAG: 'tags' };
    target.innerHTML = groups.map(([title, items]) => `<div class="facet-group"><h3>${title}</h3>${items.length ? items.map(([label, count]) => { const key = groupKey[title] || 'types'; const selected = (state['facet' + key.charAt(0).toUpperCase() + key.slice(1)] || []).includes(label); return `<label class="facet-option"><input type="checkbox" data-facet-group="${key}" data-facet-value="${escapeHtml(label)}" ${selected ? 'checked' : ''}><span>${escapeHtml(label)}</span><span>${count}</span></label>`; }).join('') : '<p class="muted">none in results</p>'}</div>`).join('');
    return;
  }
  const groups = [
    ['TYPE', [['IPv4', '122'], ['Domain', '94'], ['SHA-256', '42'], ['URL', '26']]],
    ['SEVERITY', [['Critical', '18'], ['High', '73'], ['Medium', '119'], ['Low', '74']]],
    ['SOURCE', [['OTX', '94'], ['URLhaus', '72'], ['AbuseIPDB', '68'], ['Internal', '50']]],
    ['ATT&CK', [['T1071.001', '63'], ['T1105', '48'], ['T1566.001', '37'], ['T1021.002', '21']]],
  ];
  target.innerHTML = groups.map(([title, items]) => `<div class="facet-group"><h3>${title}</h3>${items.map(([label, count], i) => `<label class="facet-option"><input type="checkbox" ${i === 0 ? 'checked' : ''}><span>${label}</span><span>${count}</span></label>`).join('')}</div>`).join('');
}

export function renderHunt(kind) {
  setBanner('hunt', kind);
  qsa('[data-hunt-tab]').forEach(tab => tab.classList.toggle('active', tab.dataset.huntTab === state.huntTab));
  const target = qs('#hunt-content');
  if (['loading', 'empty', 'error'].includes(kind)) {
    target.innerHTML = stateMarkup(kind);
    window.lucide?.createIcons();
    return;
  }
  target.innerHTML = state.huntTab === 'graph' ? graphMarkup() : state.huntTab === 'attack' ? attackMarkup() : resultsMarkup();
  window.lucide?.createIcons();
}

export async function runLiveHunt() {
  if (state.mode !== 'live') return;
  const query = qs('#hunt-query').value.trim();
  const sp = new URLSearchParams();
  if (query && !/^(type|score|last_seen):/.test(query)) sp.set('q', query);
  const scoreMatch = query.match(/score:>=?(\d+)/);
  const minScore = scoreMatch ? Number(scoreMatch[1]) : 0;
  if (minScore) sp.set('min_score', String(minScore));
  state.huntMinScore = minScore;
  if (state.facetTypes?.length) sp.set('types', state.facetTypes.join(','));
  if (state.facetTags?.length) sp.set('tags', state.facetTags.join(','));
  if (state.facetSources?.length) sp.set('sources', state.facetSources.join(','));
  try {
    state.liveSearch = await api(`/search?${sp.toString()}`);
    renderFacets('populated');
    renderHunt('populated');
  } catch (error) {
    state.lastHuntError = error;
    renderHunt('error');
  }
}

export async function openIndicatorGraph(indicatorId) {
  state.selectedIndicator = indicatorId;
  state.huntTab = 'graph';
  state.liveGraph = null;
  renderHunt('loading');
  try {
    const [detail, relationships] = await Promise.all([
      api(`/indicators/${indicatorId}`),
      api(`/indicators/${indicatorId}/relationships`),
    ]);
    const seen = new Set();
    const neighbors = [];
    for (const row of relationships) {
      const other = row.source_id === indicatorId ? row.target : row.source;
      if (!seen.has(other.id)) {
        seen.add(other.id);
        neighbors.push({ id: other.id, value: other.value, type: other.type, severity_score: other.severity_score, relation: row.relation });
      }
    }
    state.liveGraph = { root: { id: detail.id, value: detail.value, type: detail.type, severity_score: detail.severity_score }, neighbors };
    renderFacets('populated');
    renderHunt('populated');
  } catch (error) {
    showToast(`${error.error_code}: ${error.message}`);
    renderHunt('error');
  }
}

function graphMarkup() {
  if (state.mode === 'live') {
    if (state.liveGraph) return graphSvg(state.liveGraph);
    if (state.graphBusy) return pivotLoading();
    const first = state.liveSearch?.results?.[0];
    if (!first) {
      return '<div class="graph-canvas"><div class="state-message"><strong>NO PIVOT LOADED</strong><span>Run a hunt with matches, then open a result row to grow its graph.</span></div></div>';
    }
    state.graphBusy = true;
    openIndicatorGraph(first.id).finally(() => { state.graphBusy = false; });
    return pivotLoading();
  }
  return graphSvg({
    root: { id: 'demo-root', value: '203.0.113.187', type: 'IP', severity_score: 98 },
    neighbors: [
      { id: 'd1', value: 'cdn-update-check.net', type: 'DOMAIN', severity_score: 91, relation: 'communicates-with' },
      { id: 'd2', value: '6f30cfa90c8a89f7e9abc2630e3955853ff18569', type: 'SHA-256', severity_score: 96, relation: 'drops' },
      { id: 'd3', value: 'auth-sync-service.org', type: 'DOMAIN', severity_score: 84, relation: 'resolves-to' },
      { id: 'd4', value: 'invoice-review-cloud.com', type: 'DOMAIN', severity_score: 68, relation: 'resolves-to' },
      { id: 'd5', value: '198.51.100.91', type: 'IPV4', severity_score: 72, relation: 'communicates-with' },
    ],
  });
}

function pivotLoading() {
  return '<div class="graph-canvas"><div class="state-message"><strong>PIVOTING</strong><span>Resolving typed relationships for the selected indicator…</span></div></div>';
}

function graphSvg(g) {
  const W = 1040, H = 680, cx = W / 2, cy = H / 2;
  const cols = 14;
  const wrap = v => {
    const s = String(v ?? '');
    const out = [];
    for (let i = 0; i < s.length && out.length < 4; i += cols) out.push(s.slice(i, i + cols));
    if (!out.length) out.push('—');
    return out;
  };
  const sevClass = s => s >= 85 ? 'critical' : s >= 70 ? 'high' : s >= 45 ? 'medium' : 'low';
  const shown = g.neighbors.slice(0, 10);
  const extra = g.neighbors.length - shown.length;
  const ringR = shown.length <= 4 ? 200 : shown.length <= 7 ? 250 : 295;
  const positions = shown.map((nb, i) => {
    const angle = (2 * Math.PI * i) / shown.length - Math.PI / 2;
    return { ...nb, x: Math.round(cx + ringR * Math.cos(angle)), y: Math.round(cy + ringR * Math.sin(angle)) };
  });
  const grid = '<g class="graph-grid">'
    + Array.from({ length: Math.ceil(W / 40) }, (_, i) => `<line x1="${i * 40}" y1="0" x2="${i * 40}" y2="${H}"/>`).join('')
    + Array.from({ length: Math.ceil(H / 40) }, (_, i) => `<line x1="0" y1="${i * 40}" x2="${W}" y2="${i * 40}"/>`).join('')
    + '</g>';
  // label block: multi-line value + sub, placed above or below the node anchor
  const labelBlock = (x, nodeY, r, value, sub, place) => {
    const lines = wrap(value);
    const block = lines.length * 13 + 14;
    let firstY;
    if (place === 'above') firstY = nodeY - r - 6 - block + 13;
    else firstY = nodeY + r + 13;
    const spans = lines.map((ln, i) => `<tspan x="${x}" dy="${i === 0 ? 0 : 13}">${escapeHtml(ln)}</tspan>`).join('');
    const subY = firstY + (lines.length - 1) * 13 + 12;
    return `<text class="graph-label" x="${x}" y="${Math.round(firstY)}" text-anchor="middle">${spans}</text>`
      + `<text class="graph-sublabel" x="${x}" y="${Math.round(subY)}" text-anchor="middle">${escapeHtml(sub)}</text>`;
  };
  const edges = positions.map(n => `<path class="graph-edge ${sevClass(n.severity_score)}" d="M${cx} ${cy} L${n.x} ${n.y}"/>`).join('');
  // root: value label + sublabel BELOW the circle (clear of edges and neighbors)
  const rootLabel = labelBlock(cx, cy, 36, g.root.value, `PIVOT · ${g.root.type} · SCORE ${g.root.severity_score} · ${g.neighbors.length} linked`, 'below');
  const rootMark = `<g class="graph-node root" title="${escapeHtml(g.root.value)}"><circle cx="${cx}" cy="${cy}" r="36"/></g>${rootLabel}`;
  // neighbors: label above if in the top half, below if in the bottom half
  const nodeMarks = positions.map(n => {
    const place = n.y < cy ? 'above' : 'below';
    return `<g class="graph-node ${n.severity_score >= 70 ? 'malicious' : ''}" title="${escapeHtml(n.value)}"><circle cx="${n.x}" cy="${n.y}" r="24"/></g>`
      + labelBlock(n.x, n.y, 24, n.value, `${n.type} · ${n.relation}`, place);
  }).join('');
  const legend = `<g class="graph-legend"><span>${shown.length} linked object${shown.length === 1 ? '' : 's'}${extra ? ` · ${extra} more not drawn` : ''}</span><span>edges colored by severity</span></g>`;
  return `<div class="graph-canvas"><svg class="graph-svg" viewBox="0 0 ${W} ${H}" role="img" aria-label="Indicator relationship graph">${grid}<g>${edges}</g>${rootMark}<g>${nodeMarks}</g>${legend}</svg></div>`;
}


function attackMarkup() {
  if (state.mode === 'live') {
    const matrix = state.liveMatrix;
    if (!matrix) return '<div class="attack-matrix"><div class="state-message"><strong>LOADING</strong><span>ATT&amp;CK overlay resolves on first view.</span></div></div>';
    const tactics = new Map();
    for (const t of matrix) tactics.set(t.tactic, [...(tactics.get(t.tactic) || []), t]);
    return `<div class="attack-matrix"><div class="matrix-grid">${[...tactics.entries()].map(([tactic, techs]) => `<div class="matrix-column"><h3>${escapeHtml(tactic.toUpperCase())}</h3>${techs.map(t => `<div class="technique ${t.indicator_count > 0 ? 'covered' : 'gap'}"><strong>${escapeHtml(t.technique_id)}</strong><span>${escapeHtml(t.name)}</span></div>`).join('')}</div>`).join('')}</div></div>`;
  }
  const columns = [
    ['Initial access', [['T1566.001', 'Spearphishing attachment', 'observed'], ['T1190', 'Exploit public app', 'gap']]],
    ['Execution', [['T1059.001', 'PowerShell', 'observed'], ['T1204.002', 'Malicious file', 'covered']]],
    ['Persistence', [['T1053.005', 'Scheduled task', 'gap'], ['T1547.001', 'Registry run keys', 'covered']]],
    ['Lateral movement', [['T1021.002', 'SMB shares', 'observed'], ['T1570', 'Lateral tool transfer', 'gap']]],
    ['C2', [['T1071.001', 'Web protocols', 'observed'], ['T1105', 'Ingress transfer', 'observed']]],
    ['Exfiltration', [['T1041', 'Exfil over C2', 'gap'], ['T1567.002', 'Exfil to cloud', 'covered']]],
  ];
  return `<div class="attack-matrix"><div class="matrix-grid">${columns.map(([tactic, techs]) => `<div class="matrix-column"><h3>${tactic.toUpperCase()}</h3>${techs.map(([id, name, status]) => `<div class="technique ${status}"><strong>${id}</strong><span>${name}</span></div>`).join('')}</div>`).join('')}</div></div>`;
}

function resultsMarkup() {
  if (state.mode === 'live') {
    const results = state.liveSearch?.results || [];
    if (!results.length) return '<div class="state-message"><strong>NO MATCHES</strong><span>Adjust the query or lower the score floor.</span></div>';
    return `<table class="ops-table result-table"><caption class="sr-only">Hunt results, highest severity first</caption><thead><tr><th scope="col">Indicator</th><th scope="col">Type</th><th scope="col">Sources</th><th scope="col">Tags</th><th class="num">Sightings</th><th class="num">Score</th><th>Last seen</th></tr></thead><tbody>${results.map(r => `<tr tabindex="0" data-indicator-id="${escapeHtml(r.id)}" data-severity="${escapeHtml(r.severity)}" title="Open relationship graph"><td class="indicator-cell">${escapeHtml(r.value)}</td><td class="mono">${escapeHtml(r.type)}</td><td>${escapeHtml(r.sources.slice(0, 2).join(', '))}${r.sources.length > 2 ? ` +${r.sources.length - 2}` : ''}</td><td>${r.tags.slice(0, 3).map(t => `<span class="status-inline">#${escapeHtml(t)}</span>`).join(' ')}</td><td class="num mono">${r.internal_sightings}</td><td class="num mono">${r.severity_score}</td><td class="mono">${escapeHtml(zTime(r.last_seen))}</td></tr>`).join('')}</tbody></table>`;
  }
  return `<table class="ops-table result-table"><caption class="sr-only">Hunt results, highest severity first</caption><thead><tr><th scope="col">Indicator</th><th scope="col">Type</th><th scope="col">Sources</th><th scope="col">ATT&amp;CK</th><th class="num">Sightings</th><th class="num">Score</th><th>Last seen</th></tr></thead><tbody>${demoAlerts.slice(0, 7).map(a => `<tr data-severity="${a.severity}"><td class="indicator-cell">${a.indicator}</td><td class="mono">${a.type}</td><td>${a.source}</td><td class="mono">${a.attack}</td><td class="num mono">${a.sightings}</td><td class="num mono ${a.severity}-text">${a.score}</td><td class="mono">${a.absolute}</td></tr>`).join('')}</tbody></table>`;
}

export async function loadMatrix() {
  if (state.mode !== 'live' || state.liveMatrix) return;
  try {
    state.liveMatrix = await api('/attack/matrix');
  } catch {
    state.liveMatrix = [];
  }
}
