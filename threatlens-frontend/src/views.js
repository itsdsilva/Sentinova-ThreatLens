// ThreatLens console — views: executive overview, triage queue, alert drawer, incidents.

import { state, session, api, actions, qs, qsa, icon, escapeHtml, severityChip, tlpChip, ago, zTime, showToast, setBanner, stateMarkup, errorMarkup, spark, demoAlerts, demoIncidents, demoTimeline } from './core.js';

export { state };

// --- executive overview ------------------------------------------------------

export function renderChart() {
  if (state.mode === 'live' && state.liveExec) {
    const exec = state.liveExec;
    const data = exec.throughput || [];
    const alertsSeries = data.map(d => d.alerts);
    const seenSeries = data.map(d => d.indicators_seen);
    const labelEvery = Math.max(1, Math.ceil(data.length / 5));
    renderChartSeries(
      alertsSeries,
      seenSeries,
      data.map((d, i) => (i % labelEvery === 0 || i === data.length - 1 ? d.date.slice(5) : '')),
    );
    const peak = Math.max(...alertsSeries, ...seenSeries);
    const peakIdx = [...alertsSeries, ...seenSeries].indexOf(peak);
    const peakDate = data[Math.min(data.length - 1, peakIdx % Math.max(1, data.length))]?.date || '';
    qs('#chart-note-1').innerHTML = `Peak <strong class="tabular">${peak}</strong> on ${escapeHtml(peakDate)}`;
    const ratio = exec.active_indicators > 0 ? Math.round(exec.indicators_with_internal_sightings * 100 / exec.active_indicators) : 0;
    qs('#chart-note-2').innerHTML = `internal-sighting ratio <strong class="tabular">${ratio}%</strong>`;
    qs('#ov-risk').textContent = exec.risk_score;
    qs('#ov-critical').textContent = exec.critical_count;
    qs('#ov-critical-sub').textContent = `${exec.indicators_with_internal_sightings} with internal sightings`;
    qs('#ov-high').textContent = exec.high_count;
    qs('#ov-high-sub').textContent = `${exec.alerts_new_24h} alerts in 24h`;
    qs('#ov-open-label').textContent = 'OPEN ALERTS';
    qs('#ov-open').textContent = exec.alerts_open;
    qs('#ov-open-sub').textContent = `${exec.open_incidents} incidents open`;
    qs('#ov-extra-label').textContent = 'RESOLVED 30D';
    qs('#ov-extra').textContent = exec.alerts_resolved_30d;
    qs('#ov-extra-sub').textContent = 'SOC clearance';
    const rail = qs('#top-threats-list');
    const families = exec.top_malware_families || [];
    rail.innerHTML = families.length
      ? families.map((f, i) => `<li><span class="rank mono">0${i + 1}</span><div><strong>${escapeHtml(f.family)}</strong><small>${f.count} active indicators</small></div><span class="severity info">${f.count} IOC</span></li>`).join('')
      : '<li><span class="muted">No family clusters yet.</span></li>';
    qs('#asset-mix-head').innerHTML = '<tr><th>IOC type</th><th class="num">Active</th></tr>';
    qs('#asset-mix').innerHTML = (exec.categories || []).map(c => `<tr><td>${escapeHtml(c.type)}</td><td class="num mono">${c.count}</td></tr>`).join('');
    const raised = exec.alerts_new_24h;
    const resolved = exec.alerts_resolved_30d;
    const clearance = raised + resolved > 0 ? Math.round(resolved * 100 / (raised + resolved)) : 0;
    qs('#th-1').textContent = raised;
    qs('#th-2').textContent = resolved;
    qs('#th-3').textContent = `${clearance}%`;
    qs('#th-bar').style.setProperty('--bar', `${clearance}%`);
    qs('#th-note').textContent = `${exec.alerts_open} net open · ${exec.open_incidents} incidents`;
  } else {
    const values = [9,11,8,13,12,14,16,15,18,17,19,21,18,23,22,25,24,20,28,27,30,29,34,39,33,31,35,32,37,36];
    const sightings = [3,4,3,4,5,4,6,5,7,6,8,7,6,9,7,10,8,7,12,9,11,10,14,16,12,11,13,10,14,12];
    renderChartSeries(values, sightings, ['Sep 01','Sep 08','Sep 15','Sep 22','Sep 28']);
  }
}

function renderChartSeries(values, sightings, xLabels) {
  const w = 760, h = 210, p = 28;
  const max = Math.max(10, ...values, ...sightings) * 1.15;
  const points = data => data.map((v, i) => `${p + i * ((w - p * 2) / (data.length - 1))},${h - p - v * ((h - p * 2) / max)}`).join(' ');
  const area = `${p},${h - p} ${points(values)} ${w - p},${h - p}`;
  const labelPositions = xLabels.map((_, i) => Math.round(p + i * ((w - p * 2) / Math.max(1, xLabels.length - 1))));
  qs('#overview-chart').innerHTML = `<svg class="line-chart" viewBox="0 0 ${w} ${h}" preserveAspectRatio="none" aria-hidden="true">${[0, .5, 1].map(t => { const v = Math.round(max * t); const y = h - p - v * ((h - p * 2) / max); return `<line class="chart-grid" x1="${p}" y1="${y}" x2="${w - p}" y2="${y}"/><text class="chart-axis" x="0" y="${y + 4}">${v}</text>`; }).join('')}<polygon class="chart-area" points="${area}"/><polyline class="chart-line" points="${points(values)}"/><polyline class="chart-sightings" points="${points(sightings)}"/>${values.length ? `<circle class="chart-point" cx="${w - p}" cy="${(h - p - values[values.length - 1] * ((h - p * 2) / max)).toFixed(1)}" r="2.5"/>` : ""}${labelPositions.map((x, i) => `<text class="chart-axis" x="${Math.min(w - 60, x)}" y="${h - 3}">${escapeHtml(String(xLabels[i]))}</text>`).join('')}</svg>`;
}

// --- triage queue ------------------------------------------------------------

export function mapAlertRow(item) {
  return {
    id: item.id,
    severity: item.severity,
    score: item.severity_score,
    indicator: item.indicator?.value || '—',
    type: item.indicator?.type || '—',
    status: String(item.state || '').replace(/_/g, ' '),
    tlp: item.indicator?.tlp || 'amber',
    source: state.rules.get(item.rule_id) || (item.rule_id ? `rule ${String(item.rule_id).slice(0, 8)}` : 'direct match'),
    age: ago(item.created_at),
    absolute: zTime(item.created_at),
    sightings: item.indicator?.internal_sightings ?? 0,
    confidence: item.indicator?.confidence ?? 0,
    incident_id: item.incident_id,
    indicator_id: item.indicator?.id,
    title: item.title,
  };
}

function alertActionsHtml(a) {
  if (state.mode !== 'live') {
    return '<span class="row-actions"><button class="mini-action" type="button" tabindex="-1">Acknowledge</button><button class="mini-action" type="button" tabindex="-1">Escalate</button></span>';
  }
  const list = [];
  if (a.status === 'new') list.push(['acknowledge', 'Acknowledge']);
  if (a.status === 'acknowledged') list.push(['in_progress', 'Start work']);
  if (a.status !== 'resolved' && a.status !== 'closed') list.push(['resolve', 'Resolve']);
  list.push(['escalate', 'Escalate']);
  return `<span class="row-actions">${list.map(([act, label]) => `<button class="mini-action" type="button" data-alert-action="${act}" data-alert-id="${escapeHtml(a.id)}">${label}</button>`).join('')}</span>`;
}

export function renderAlerts(kind) {
  setBanner('alerts', kind);
  const container = qs('#alert-table-container');
  if (['loading', 'empty', 'error'].includes(kind)) {
    container.innerHTML = kind === 'error' && state.lastAlertError ? errorMarkup(state.lastAlertError) : stateMarkup(kind);
    window.lucide?.createIcons();
    return;
  }
  let rows = state.mode === 'live' ? state.liveAlerts.map(mapAlertRow) : demoAlerts;
  if (state.mode === 'live') {
    const openStates = new Set(['new', 'acknowledged', 'in_progress']);
    rows = rows.filter(r => openStates.has(r.status));
    if (state.triageSeverity === 'critical') rows = rows.filter(r => r.severity === 'critical');
    if (state.triageSeverity === 'high') rows = rows.filter(r => r.severity === 'high');
  }
  if (state.triageQuery) {
    const q = state.triageQuery.toLowerCase();
    rows = rows.filter(r => `${r.indicator} ${r.title || ''} ${r.source} ${r.type}`.toLowerCase().includes(q));
  }
  if (!rows.length) {
    container.innerHTML = stateMarkup('empty');
    return;
  }
  const foot = state.mode === 'live' && state.alertsTotal > rows.length ? `<div class="table-foot"><span class="muted">showing ${rows.length} of ${state.alertsTotal} by score</span><button class="button ghost" type="button" data-action="alerts-more">Load more</button></div>` : '';
  container.innerHTML = `<table class="ops-table queue-table"><caption class="sr-only">Alert triage queue, highest severity first</caption><thead><tr><th scope="col">Severity</th><th scope="col">Indicator</th><th scope="col">State · TLP · source</th><th scope="col">Type</th><th scope="col" class="num">Sightings</th><th scope="col" class="num">Score</th><th scope="col">Seen</th><th scope="col" aria-label="Actions"></th></tr></thead><tbody>${rows.map((a, index) => `<tr tabindex="0" data-alert-index="${index}" data-severity="${escapeHtml(a.severity)}" class="${index === state.selectedAlert ? 'selected' : ''}"><td>${severityChip(a.severity)}</td><td class="indicator-cell" title="${escapeHtml(a.indicator)}">${escapeHtml(a.indicator)}</td><td><span class="status-inline">${escapeHtml(a.status)}</span> · ${tlpChip(a.tlp)} · <span class="source-cell">${escapeHtml(a.source)}</span></td><td class="mono">${escapeHtml(a.type)}</td><td class="num mono">${a.sightings}</td><td><span class="score-cell">${spark(a.score, index)}${a.score}</span></td><td><time class="mono" title="${escapeHtml(a.absolute)}">${escapeHtml(a.age)}</time></td><td>${alertActionsHtml(a)}</td></tr>`).join('')}</tbody></table>${foot}`;
  window.lucide?.createIcons();
}

export function highlightAlert() {
  qsa('[data-alert-index]').forEach(row => row.classList.toggle('selected', Number(row.dataset.alertIndex) === state.selectedAlert));
  qs(`[data-alert-index="${state.selectedAlert}"]`)?.scrollIntoView({ block: 'nearest' });
}

export async function alertAction(action, alertId) {
  if (state.mode !== 'live') {
    showToast('Triage actions need the live backend — sign in against /api/v1.');
    return;
  }
  const patch = {};
  if (action === 'acknowledge') { patch.state = 'acknowledged'; patch.assignee_id = session.user?.id; }
  if (action === 'in_progress') patch.state = 'in_progress';
  if (action === 'resolve') patch.state = 'resolved';
  if (action === 'escalate') patch.new_incident_title = `Escalation: ${alertId}`;
  try {
    await api(`/alerts/${alertId}`, { method: 'PATCH', body: JSON.stringify(patch) });
    showToast(action === 'escalate' ? `Alert ${alertId} escalated into a new incident.` : `Alert ${alertId} → ${action === 'in_progress' ? 'in progress' : action + 'ed'}.`);
    await actions.refreshLive?.();
  } catch (error) {
    showToast(`${error.error_code}: ${error.message}`);
  }
}

export function startWork() {
  const next = state.mode === 'live'
    ? state.liveAlerts.find(a => a.state === 'new')
    : demoAlerts.find(a => a.status === 'new');
  if (!next) {
    showToast('No unowned alert in the queue.');
    return;
  }
  if (state.mode === 'live') alertAction('acknowledge', next.id);
  else showToast('Assigned the highest-severity unowned alert.');
}

export async function selectAlert(index) {
  state.selectedAlert = index;
  highlightAlert();
  const rows = state.mode === 'live' ? state.liveAlerts.map(mapAlertRow) : demoAlerts;
  const a = rows[index];
  if (!a) return;
  const drawer = qs('#alert-detail');
  qs('.triage-workbench').classList.add('detail-open');
  drawer.setAttribute('aria-hidden', 'false');
  qs('#detail-title').textContent = a.id;
  const liveActions = state.mode === 'live';
  qs('#detail-content').innerHTML = `<div class="detail-indicator"><span class="mono muted">${escapeHtml(a.type)}</span><code>${escapeHtml(a.indicator)}</code><div class="detail-chips">${severityChip(a.severity)}${tlpChip(a.tlp)}<span class="severity info">${escapeHtml(a.status).toUpperCase()}</span></div></div><section class="detail-section"><h3>Enrichment</h3><dl class="key-values"><dt>Score</dt><dd class="mono ${escapeHtml(a.severity)}-text">${a.score}/100</dd><dt>Confidence</dt><dd class="mono">${a.confidence}%</dd><dt>Verdict ratio</dt><dd class="mono">${escapeHtml(a.verdict || 'on demand')}</dd><dt>Family</dt><dd>${escapeHtml(a.family || '—')}</dd><dt>Network</dt><dd class="mono">${escapeHtml(a.asn || '—')}</dd><dt>First seen</dt><dd class="mono">${escapeHtml(a.first || '—')}</dd><dt>ATT&amp;CK</dt><dd class="mono">${escapeHtml(a.attack || '—')}</dd></dl></section><section class="detail-section" id="detail-providers"><h3>Enrichment sources</h3><p class="muted">${liveActions ? 'Run Enrich for the full provider sweep.' : 'demo profile — deterministic reference enrichers'}</p></section><section class="detail-section" id="detail-sightings"><h3>Internal sightings · ${a.sightings}</h3><p class="muted">${liveActions ? 'Loading telemetry…' : 'proxy-edge-02 · edr / PAY-WS-044 · dns-prod-01'}</p></section><section class="detail-section" id="detail-provenance"><h3>Source provenance</h3><p class="muted">${escapeHtml(a.source)} · canonical merge confidence <span class="mono">${a.confidence}%</span></p></section><section class="detail-section" id="detail-tags"><h3>Tags</h3><div class="tag-row" id="detail-tag-row"><span class="muted">${liveActions ? "Loading tags…" : "—"}</span></div><form class="drawer-tag-form" data-indicator-id="${escapeHtml(a.indicator_id || '')}"><input name="tags" placeholder="add, tags, comma-separated" aria-label="Add tags"><button class="mini-action" type="submit">Tag</button></form></section><section class="detail-section" id="detail-notes"><h3>Analyst notes</h3><div id="detail-notes-list"><p class="muted">${liveActions ? "Loading notes…" : "—"}</p></div><form class="drawer-note-form" data-indicator-id="${escapeHtml(a.indicator_id || '')}"><textarea name="body" rows="2" placeholder="Add a triage note for the record…" aria-label="Add note"></textarea><button class="mini-action" type="submit">Save note</button></form></section><div class="drawer-actions"><button class="button secondary" type="button" ${liveActions ? `data-alert-action="acknowledge" data-alert-id="${escapeHtml(a.id)}"` : ''}>Acknowledge</button><button class="button primary" type="button" ${liveActions ? `data-alert-action="escalate" data-alert-id="${escapeHtml(a.id)}"` : ''}>Escalate</button><button class="button ghost" type="button" id="detail-enrich">Enrich</button><button class="button ghost" type="button" id="detail-pipe">Pipe out</button>${liveActions ? `<button class="button ghost" type="button" data-indicator-status="whitelisted" data-indicator-id="${escapeHtml(a.indicator_id || '')}">Whitelist</button><button class="button ghost" type="button" data-indicator-status="under_review" data-indicator-id="${escapeHtml(a.indicator_id || '')}">Review</button>` : ''}</div>`;
  window.lucide?.createIcons();
  qs('#detail-enrich')?.addEventListener('click', async () => {
    if (!liveActions || !a.indicator_id) {
      showToast('Enrichment needs the live backend.');
      return;
    }
    try {
      await api(`/indicators/${a.indicator_id}/enrich`, { method: 'POST' });
      showToast('Enrichment refreshed from reputation services.');
      hydrateDrawer(a.indicator_id);
    } catch (error) {
      showToast(`${error.error_code}: ${error.message}`);
    }
  });
  qs('#detail-pipe')?.addEventListener('click', async () => {
    if (!liveActions) {
      showToast('Exports need the live backend.');
      return;
    }
    try {
      const bundle = await api(`/export/stix?min_score=${a.score}&tlp_max=red`);
      const blob = new Blob([JSON.stringify(bundle, null, 2)], { type: 'application/stix+json' });
      const link = document.createElement('a');
      link.href = URL.createObjectURL(blob);
      link.download = `threatlens_${a.id}.stix.json`;
      link.click();
      URL.revokeObjectURL(link.href);
      showToast(`STIX bundle exported (${bundle.objects.length} objects).`);
    } catch (error) {
      showToast(`${error.error_code}: ${error.message}`);
    }
  });
  if (liveActions && a.indicator_id) hydrateDrawer(a.indicator_id);
}

export async function hydrateDrawer(indicatorId) {
  try {
    const [detail, correlation] = await Promise.all([
      api(`/indicators/${indicatorId}`),
      api(`/indicators/${indicatorId}/correlation`),
    ]);
    const provenance = (detail.sources || []).map(s => `<div class="sighting"><strong>${escapeHtml(s.name)}</strong><span class="mono">conf ${s.confidence} · last ${escapeHtml(zTime(s.last_seen))}</span></div>`).join('');
    const sightings = (correlation.events || []).slice(0, 6).map(e => `<div class="sighting"><strong>${escapeHtml(e.asset || 'internal')}</strong><span class="mono">${escapeHtml(zTime(e.observed_at))} · ${escapeHtml(e.event_type)}</span></div>`).join('');
    const techniques = (detail.techniques || []).map(t => escapeHtml(t.technique_id)).join(', ');
    const sightingsBlock = qs('#detail-sightings');
    if (sightingsBlock) sightingsBlock.innerHTML = `<h3>Internal sightings · ${correlation.sightings}</h3>${sightings || '<p class="muted">No internal sightings in the correlation window.</p>'}`;
    const provenanceBlock = qs('#detail-provenance');
    if (provenanceBlock) provenanceBlock.innerHTML = `<h3>Source provenance</h3>${provenance || '<p class="muted">No provenance recorded.</p>'}<p class="muted" style="margin-top:var(--space-3)">${escapeHtml(detail.description || '')}</p>`;
    const chipsBlock = qs('#detail-content .detail-chips');
    if (chipsBlock) chipsBlock.innerHTML = severityChip(detail.severity) + tlpChip(detail.tlp) + '<span class="severity info">' + escapeHtml(detail.status.toUpperCase()) + '</span>';
    const tagRow = qs('#detail-tag-row');
    if (tagRow) tagRow.innerHTML = (detail.tags || []).length ? (detail.tags || []).map(t => `<span class="tag-chip">#${escapeHtml(t)}</span>`).join('') : '<span class="muted">No tags attached.</span>';
    const tagForm = qs('#detail-tags .drawer-tag-form');
    if (tagForm) tagForm.dataset.indicatorId = detail.id;
    const notesList = qs('#detail-notes-list');
    if (notesList) notesList.innerHTML = (detail.notes || []).length ? (detail.notes || []).map(n => `<div class="sighting"><strong>${escapeHtml(n.author || 'analyst')}</strong><span class="mono">${escapeHtml(zTime(n.created_at))}</span><p style="margin-top:var(--space-1)">${escapeHtml(n.body)}</p></div>`).join('') : '<p class="muted">No analyst notes yet.</p>';
    const noteForm = qs('#detail-notes .drawer-note-form');
    if (noteForm) noteForm.dataset.indicatorId = detail.id;
    renderProviderBlock(detail.enrichment || {});
  } catch {
    // drawer keeps the triage-level detail on lookup failure
  }
}

// Per-provider one-liners for the drawer's "Enrichment sources" section. Each
// provider reports its own field names, so every block formats separately.
const PROVIDER_LABELS = {
  reputation: 'AbuseIPDB',
  noise: 'GreyNoise',
  exposure: 'Shodan',
  otx: 'AlienVault OTX',
  geo: 'Geo / ASN',
  verdicts: 'VirusTotal',
  sample: 'MalwareBazaar',
  domain_analysis: 'Domain analysis',
  urlhaus: 'URLhaus',
  phishtank: 'PhishTank',
  kev: 'CISA KEV',
};

function providerLine(key, data) {
  const mono = v => `<span class="mono">${escapeHtml(String(v))}</span>`;
  if (key === 'reputation') {
    const score = data.abuse_confidence_score ?? '—';
    return `abuse score ${mono(score)} · ${mono(data.total_reports ?? '—')} reports · ${escapeHtml(data.verdict || 'unknown')}`;
  }
  if (key === 'noise') return `${escapeHtml(data.classification || 'unclassified')}${data.actor ? ' · ' + escapeHtml(data.actor) : ''}`;
  if (key === 'exposure') return `${mono((data.ports || []).join(', ') || 'no open ports')} · ${escapeHtml(data.org || 'org unknown')}`;
  if (key === 'otx') return `${mono(data.pulse_count ?? 0)} pulses${(data.malware_families || []).length ? ' · ' + escapeHtml(data.malware_families.join(', ')) : ''}`;
  if (key === 'geo') return `${escapeHtml(data.country || '—')} · ${mono(data.asn || '—')} · ${escapeHtml(data.asn_owner || '')}`;
  if (key === 'verdicts') return `${mono(data.malicious ?? '—')}/${mono(data.engine_total ?? '—')} engines · ratio ${mono(data.ratio ?? '—')}`;
  if (key === 'sample') return data.mb_listed === false ? 'not in MalwareBazaar' : `${escapeHtml(data.signature || 'sample')} · ${escapeHtml(data.file_type || '')}`;
  if (key === 'domain_analysis') return [data.newly_registered ? 'newly registered' : null, data.known_phishing ? 'known phishing' : null, data.dga_like ? 'DGA-like' : null].filter(Boolean).join(' · ') || 'no domain flags';
  if (key === 'urlhaus') return data.urlhaus_listed ? `${mono(data.url_count ?? 0)} payload URLs recorded` : 'not listed on URLhaus';
  if (key === 'phishtank') return data.phishtank_listed ? 'in PhishTank database · verified phish' : 'not in PhishTank database';
  if (key === 'kev') return data.kev_listed ? `known exploited · added ${mono(data.kev_date_added || '—')}` : 'not in CISA KEV';
  return null;
}

function renderProviderBlock(enrichment) {
  const block = qs('#detail-providers');
  if (!block) return;
  const rows = Object.entries(enrichment)
    .filter(([key, data]) => key !== 'scoring' && data && typeof data === 'object')
    .map(([key, data]) => {
      const line = providerLine(key, data);
      if (!line) return '';
      return `<div class="sighting"><strong>${escapeHtml(PROVIDER_LABELS[key] || key)}</strong><span>${line}</span></div>`;
    })
    .join('');
  block.innerHTML = `<h3>Enrichment sources</h3>${rows || '<p class="muted">No cached enrichment yet — run Enrich for the full provider sweep.</p>'}`;
}

// --- incidents ---------------------------------------------------------------

export function renderIncidents(kind) {
  const container = qs('#incident-list-content');
  if (['loading', 'empty', 'error'].includes(kind)) {
    container.innerHTML = stateMarkup(kind);
    window.lucide?.createIcons();
    return;
  }
  if (state.mode === 'live') {
    container.innerHTML = state.liveIncidents.length ? state.liveIncidents.map(item => `
      <button class="incident-row ${item.id === state.selectedIncident ? 'active' : ''}" type="button" data-incident-id="${escapeHtml(item.id)}">
        <span><code>${escapeHtml(item.id)}</code>${severityChip(item.severity)}</span>
        <strong>${escapeHtml(item.title)}</strong>
        <small>${escapeHtml(item.lead?.name || 'unassigned')} · ${escapeHtml(item.status)} · ${ago(item.created_at)}</small>
      </button>`).join('')
      : `<div class="state-message">${icon('inbox')}<strong>No incidents.</strong><span>Escalate an alert to open one.</span></div>`;
    window.lucide?.createIcons();
    return;
  }
  container.innerHTML = demoIncidents.map((item, index) => `<button class="incident-row ${index === 0 ? 'active' : ''}" type="button"><span><code>${item.id}</code>${severityChip(item.severity)}</span><strong>${escapeHtml(item.title)}</strong><small>${item.owner} · ${item.age}</small></button>`).join('');
}

export function renderTimeline() {
  const entries = state.mode === 'live' ? state.liveTimeline : demoTimeline;
  const typeColor = t => ({ detection: 'critical', correlation: 'high', analyst_action: 'info', containment: 'low', note: 'info', report: 'low' })[t] || 'info';
  qs('#timeline-content').innerHTML = entries.length ? entries.map(item => `<li><time class="mono">${state.mode === 'live' ? escapeHtml(zTime(item.occurred_at)) : item.time}</time><span class="timeline-marker ${state.mode === 'live' ? typeColor(item.entry_type) : item.severity}"><i></i></span><div class="timeline-card"><strong>${escapeHtml(item.title)}</strong><p>${escapeHtml(item.body || '')}</p>${state.mode === 'live' && item.actor ? `<p class="mono muted" style="margin-top:var(--space-1)">${escapeHtml(item.entry_type || 'event')} · ${escapeHtml(item.actor || 'system')}</p>` : ''}</div></li>`).join('') : '<li><span class="muted">No timeline entries yet.</span></li>';
}

export async function selectIncident(incidentId) {
  const now = Date.now();
  if (state._lastIncidentSelect === incidentId && now - (state._lastIncidentSelectAt || 0) < 2500) {
    return; // idempotent — overlapping callers must not re-fetch the same incident
  }
  state._lastIncidentSelect = incidentId;
  state._lastIncidentSelectAt = now;
  const ws = state.ws;
  if (state.wsIncidentChannel && state.wsIncidentChannel !== `incidents.${incidentId}` && ws?.readyState === 1) {
    ws.send(JSON.stringify({ action: 'unsubscribe', channel: state.wsIncidentChannel }));
  }
  state.wsIncidentChannel = `incidents.${incidentId}`;
  if (ws?.readyState === 1) ws.send(JSON.stringify({ action: 'subscribe', channel: state.wsIncidentChannel }));
  state.selectedIncident = incidentId;
  renderIncidents('populated');
  if (state.mode === 'live') {
    try {
      const [detail, timelineData] = await Promise.all([
        api(`/incidents/${incidentId}`),
        api(`/incidents/${incidentId}/timeline`),
      ]);
      state.liveTimeline = timelineData.entries || [];
      state.liveIncidentDetail = detail;
      hydrateIncidentHeader(detail);
      renderTimeline();
    } catch (error) {
      qs('#timeline-content').innerHTML = `<li><span class="muted">${escapeHtml(error.error_code)}: ${escapeHtml(error.message)}</span></li>`;
    }
  }
}

function hydrateIncidentHeader(detail) {
  qs('#incident-code').textContent = detail.id;
  qs('#incident-name').textContent = detail.title;
  const opened = detail.created_at ? `${String(detail.created_at).slice(0, 19)}Z` : '';
  qs('#incident-owner').textContent = `Owner ${detail.lead?.name || 'unassigned'} · ${detail.status} · opened ${opened}`;
  qs('#tab-timeline-count').textContent = String(state.liveTimeline.length);
  qs('#tab-indicators-count').textContent = String((detail.indicators || []).length);
  const evidenceTab = qs('#tab-evidence');
  if (evidenceTab) evidenceTab.hidden = true;
  const progress = qs('#checklist-progress');
  const body = qs('#checklist-body');
  const items = detail.containment_checklist || [];
  if (body) {
    body.innerHTML = items.length
      ? items.map((item, i) => `<label><input type="checkbox" data-checklist-index="${i}" ${item.done ? 'checked' : ''}>${escapeHtml(item.text)}</label>`).join('')
      : '<label class="muted">No containment checklist on this incident.</label>';
  }
  if (progress) progress.textContent = `${items.filter(i => i.done).length}/${items.length}`;
  const facts = qs('#incident-facts');
  if (facts) {
    facts.innerHTML = `
      <div><dt>Status</dt><dd class="mono">${escapeHtml(detail.status)}</dd></div>
      <div><dt>Indicators</dt><dd class="mono">${(detail.indicators || []).length}</dd></div>
      <div><dt>Severity</dt><dd>${severityChip(detail.severity)}</dd></div>
      <div><dt>Opened</dt><dd class="mono">${escapeHtml(opened)}</dd></div>`;
  }
  const eyebrow = qs('#incident-open-count');
  if (eyebrow) eyebrow.textContent = `OPEN · ${state.liveIncidents.filter(i => i.status === 'open').length}`;
  renderIncidentTab();
}

export async function toggleChecklist(index, done) {
  if (state.mode !== 'live' || !state.selectedIncident) return;
  try {
    const detail = await api(`/incidents/${state.selectedIncident}/checklist`, {
      method: 'POST',
      body: JSON.stringify({ index, done: !!done }),
    });
    state.liveIncidentDetail = detail;
    hydrateIncidentHeader(detail);
    const entries = await api(`/incidents/${state.selectedIncident}/timeline`);
    state.liveTimeline = entries.entries || [];
    renderTimeline();
    showToast('Containment step recorded on the timeline.');
  } catch (error) {
    showToast(`${error.error_code}: ${error.message}`);
  }
}

export async function refreshSelectedTimeline() {
  // Cheap single-fetch refresh used by WebSocket events — no header re-render,
  // no re-subscribe. Prevents refresh storms when the bus gets chatty.
  if (state.mode !== 'live' || !state.selectedIncident) return;
  try {
    const data = await api(`/incidents/${state.selectedIncident}/timeline`);
    state.liveTimeline = data.entries || [];
    renderTimeline();
  } catch (error) {
    if (error.error_code !== 'unauthenticated') {
      qs('#timeline-content').innerHTML = `<li><span class="muted">${escapeHtml(error.error_code)}: ${escapeHtml(error.message)}</span></li>`;
    }
  }
}

export function visibleAlertRows() {
  return state.mode === 'live' ? state.liveAlerts.length : demoAlerts.length;
}


// --- incident tabs (R2): indicators pane + header hydration from the API ----

export async function hydrateIncidentFromApi(incidentId) {
  if (state.mode !== 'live') return;
  const [detail, timelineData] = await Promise.all([
    api(`/incidents/${incidentId}`),
    api(`/incidents/${incidentId}/timeline`),
  ]);
  state.liveTimeline = timelineData.entries || [];
  state.liveIncidentDetail = detail;
  hydrateIncidentHeader(detail);
}

export function renderIncidentTab() {
  const timelineSection = qs('.timeline-section');
  const indicatorPane = qs('#incident-indicators');
  if (!timelineSection || !indicatorPane) return;
  const showIndicators = state.incidentTab === 'indicators';
  timelineSection.hidden = showIndicators;
  indicatorPane.hidden = !showIndicators;
  qsa('[data-incident-tab]').forEach(tab => tab.classList.toggle('active', tab.dataset.incidentTab === state.incidentTab));
  if (!showIndicators) return;
  const rows = state.mode === 'live'
    ? (state.liveIncidentDetail?.indicators || [])
    : demoAlerts.slice(0, 3).map(a => ({ value: a.indicator, type: a.type, severity_score: a.score, internal_sightings: a.sightings }));
  indicatorPane.innerHTML = `<div class="table-scroll" style="max-height:calc(100dvh - 20rem)"><table class="ops-table"><caption class="sr-only">Indicators linked to this incident</caption><thead><tr><th scope="col">Indicator</th><th scope="col">Type</th><th class="num" scope="col">Sightings</th><th class="num" scope="col">Score</th></tr></thead><tbody>${rows.length ? rows.map(r => `<tr><td class="indicator-cell">${escapeHtml(r.value)}</td><td class="mono">${escapeHtml(r.type)}</td><td class="num mono">${r.internal_sightings}</td><td class="num mono ${r.severity_score >= 70 ? 'high-text' : 'medium-text'}">${r.severity_score}</td></tr>`).join('') : '<tr><td colspan="4" class="muted">No indicators linked yet — escalate an alert into this incident.</td></tr>'}</tbody></table></div>`;
}
