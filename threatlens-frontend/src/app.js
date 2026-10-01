// ThreatLens console — app shell: boot, routing, WebSocket, keyboard, session glue.

import { state, session, api, actions, probeBackend, dropSession, API_BASE, API_ROOT, qs, qsa, escapeHtml, showToast, ago } from './core.js';
import { loadAndRenderHeatmap } from './heatmap.js';
import { applyWidgetLayout, initWidgetPanel } from './widgets.js';
import { renderChart, renderAlerts, renderIncidents, renderTimeline, selectAlert, selectIncident, alertAction, startWork, highlightAlert, visibleAlertRows, toggleChecklist, refreshSelectedTimeline, hydrateIncidentFromApi, hydrateDrawer, renderIncidentTab } from './views.js';
import { renderFacets, renderHunt, runLiveHunt, loadMatrix, openIndicatorGraph } from './hunt.js';
import { renderFeeds, renderUsers, renderAudit, renderHealth, feedActionReal } from './admin.js';

const BASE_CHANNELS = ['alerts.stream', 'indicators.high_severity', 'system.health'];

function renderAll() {
  renderChart();
  renderAlerts('populated');
  renderIncidents('populated');
  renderTimeline();
  renderFacets('populated');
  renderHunt('populated');
  renderFeeds('populated');
  renderUsers('populated');
  renderAudit('populated');
  renderHealth('populated');
}

let refreshPending = false;

async function refreshLive(force = false) {
  if (state.mode !== 'live' || !session.token) return;
  const now = Date.now();
  if (!force && now - (state._lastRefreshAt || 0) < 4000) {
    // Throttle: coalesce bursts of bus events into one trailing refresh.
    if (!refreshPending) {
      refreshPending = true;
      setTimeout(() => { refreshPending = false; refreshLive(true); }, 4200);
    }
    return;
  }
  state._lastRefreshAt = now;
  try {
    const [alerts, exec, incidents] = await Promise.all([
      api('/alerts?sort=-severity_score&page_size=50'),
      api('/dashboard/executive'),
      api('/incidents'),
    ]);
    state.lastAlertError = null;
    state.liveAlerts = alerts.items || [];
    state.alertsTotal = alerts.total || state.liveAlerts.length;
    state.alertsPage = 1;
    state.liveExec = exec;
    state.liveIncidents = incidents.items || [];
    renderAlerts('populated');
    renderChart();
    renderIncidents('populated');
    updateBadge();
    const stamp = new Date().toISOString().slice(11, 19) + 'Z';
    qsa('.freshness time').forEach(t => { t.textContent = stamp; });
    const me = session.user?.id;
    const openStates = new Set(['new', 'acknowledged', 'in_progress']);
    const counters = {
      'qc-new': state.liveAlerts.filter(a => a.state === 'new').length,
      'qc-unassigned': state.liveAlerts.filter(a => !a.assignee && openStates.has(a.state)).length,
      'qc-mine': state.liveAlerts.filter(a => a.assignee?.id === me && openStates.has(a.state)).length,
    };
    for (const [id, count] of Object.entries(counters)) {
      const cell = qs(`#${id} strong`);
      if (cell) cell.textContent = count;
    }
    const chipCounts = { 'chip-open': 0, 'chip-critical': 0, 'chip-high': 0 };
    for (const a of state.liveAlerts) {
      if (!openStates.has(a.state)) continue;
      chipCounts['chip-open'] += 1;
      if (a.severity === 'critical') chipCounts['chip-critical'] += 1;
      if (a.severity === 'high') chipCounts['chip-high'] += 1;
    }
    for (const [id, count] of Object.entries(chipCounts)) {
      const cell = qs(`#${id}`);
      if (cell) cell.textContent = count;
    }
    if (state.route === 'incidents' && !state.selectedIncident && state.liveIncidents.length) {
      await selectIncident(state.liveIncidents[0].id);
    } else if (state.route === 'incidents' && state.selectedIncident && (!state.ws || state.ws.readyState !== 1)) {
      // keep the timeline fresh while the socket is down — never via selectIncident
      await refreshSelectedTimeline();
    }
    const routeName = state.route;
    try {
      if (routeName === 'admin-feeds') { state.liveFeeds = await api('/feeds'); state.lastFeedError = null; renderFeeds('populated'); }
      if (routeName === 'admin-users') { state.liveUsers = await api('/users'); state.lastUserError = null; renderUsers('populated'); }
      if (routeName === 'admin-audit') { const data = await api('/audit?page_size=60'); state.liveAudit = data; state.auditTotal = data.total || (data.items || []).length; state.auditPage = 1; state.lastAuditError = null; renderAudit('populated'); }
      if (routeName === 'admin-health') {
        state.liveHealth = await api('/dashboard/health');
        state.liveSystem = await api('/health/system');
        renderHealth('populated');
      }
      if (routeName === 'hunt') { await loadMatrix(); await runLiveHunt(); state.liveHunts = await api('/hunts').catch(() => []); renderSavedHunts(); }
    } catch (error) {
      if (routeName === 'admin-feeds') { state.lastFeedError = error; renderFeeds('error'); }
      if (routeName === 'admin-users') { state.lastUserError = error; renderUsers('error'); }
      if (routeName === 'admin-audit') { state.lastAuditError = error; renderAudit('error'); }
    }
  } catch (error) {
    if (error?.error_code === 'unauthenticated') return;
    state.lastAlertError = error;
    if (state.route === 'triage') renderAlerts('error');
  }
}
actions.refreshLive = refreshLive;

function route() {
  const requested = location.hash.slice(1) || 'overview';
  const routeName = qs(`[data-view="${requested}"]`) ? requested : 'overview';
  if (state.mode === 'live' && !session.token && routeName !== 'login') {
    location.hash = 'login';
    return;
  }
  state.route = routeName;
  qsa('.view').forEach(view => view.classList.toggle('active', view.dataset.view === routeName));
  qsa('.nav-item').forEach(item => item.classList.toggle('active', item.dataset.route === routeName));
  qs('.sidebar').classList.remove('open');
  qs('#main').scrollTop = 0;
  window.lucide?.createIcons({ attrs: { 'aria-hidden': 'true' } });
  if (routeName === 'incidents' && state.mode === 'live' && !state.selectedIncident && state.liveIncidents.length) {
    selectIncident(state.liveIncidents[0].id);
  }
  if (routeName === 'admin-health' && state.mode === 'live' && session.token) {
    Promise.all([api('/dashboard/health'), api('/health/system')])
      .then(([health, system]) => { state.liveHealth = health; state.liveSystem = system; renderHealth('populated'); })
      .catch(() => {});
  }
  if (routeName === 'hunt' && state.mode === 'live' && session.token) {
    loadMatrix().then(() => runLiveHunt());
  }
  if (state.mode === 'live' && session.token) {
    if (routeName === 'admin-feeds') api('/feeds').then(d => { state.liveFeeds = d; renderFeeds('populated'); }).catch(() => {});
    if (routeName === 'admin-users') api('/users').then(d => { state.liveUsers = d; renderUsers('populated'); }).catch(() => {});
    if (routeName === 'overview') loadAndRenderHeatmap('heatmap-container');
    if (routeName === 'admin-audit') api('/audit?page_size=60').then(d => { state.liveAudit = d; state.auditTotal = d.total || (d.items || []).length; state.auditPage = 1; renderAudit('populated'); }).catch(() => {});
  }
}

function renderSession() {
  const copy = qs('.user-copy');
  if (state.mode === 'live' && session.user) {
    qs('.avatar').textContent = session.user.name.split(' ').map(p => p[0]).slice(0, 2).join('').toUpperCase();
    copy.innerHTML = `<strong>${escapeHtml(session.user.name)}</strong><small>${escapeHtml(session.user.role.replace(/_/g, ' '))}</small>`;
  } else if (state.mode === 'demo') {
    qs('.avatar').textContent = 'PN';
    copy.innerHTML = '<strong>Priya Nair</strong><small>SOC analyst · demo data</small>';
  }
  applyNavRoles();
  const loginView = qs('[data-view="login"]');
  if (loginView) {
    const endpoint = qs('#login-endpoint');
    if (endpoint && !endpoint.value) endpoint.placeholder = state.mode === 'live' ? 'same-origin /api/v1' : 'backend unreachable — demo data active';
  }
  window.lucide?.createIcons({ attrs: { 'aria-hidden': 'true' } });
}

function updateBadge() {
  if (state.mode !== 'live') {
    const badge = qs('.notification-count');
    badge.textContent = 3;
    badge.hidden = false;
    return;
  }
  const count = state.liveAlerts.filter(a => ['new', 'acknowledged', 'in_progress'].includes(a.state) && !state.trayDismissed.has(a.id)).length;
  const badge = qs('.notification-count');
  badge.textContent = count;
  badge.hidden = count === 0;
}

function renderTrayLive() {
  const tray = qs('#notification-tray');
  const items = state.liveAlerts.filter(a => ['new', 'acknowledged', 'in_progress'].includes(a.state) && !state.trayDismissed.has(a.id)).slice(0, 5);
  if (!items.length) {
    clearTrayItems();
    const empty = document.createElement('div');
    empty.className = 'operator-empty';
    empty.style.minHeight = '6rem';
    empty.innerHTML = '<p>Tray clear — new alerts will land here live.</p>';
    tray.append(empty);
    return;
  }
  const edge = severity => severity === 'critical' ? 'critical-edge' : severity === 'high' ? 'high-edge' : 'info-edge';
  tray.querySelectorAll('.notification-item').forEach(node => node.remove());
  const list = document.createElement('div');
  list.innerHTML = items.map(a => `
    <div class="notification-item ${edge(a.severity)}" data-alert-id="${escapeHtml(a.id)}" data-nav="triage" title="Open triage queue">
      <span class="severity ${escapeHtml(a.severity)}">${escapeHtml(a.severity).toUpperCase()}</span>
      <strong>${escapeHtml(String(a.title || '').slice(0, 64))}</strong>
      <p>${escapeHtml(a.indicator?.value || '')}</p>
      <time class="mono">${escapeHtml(String(a.created_at || ''))}</time>
    </div>`).join('');
  tray.append(list);
}

// --- WebSocket (backend protocol: {"action":"subscribe","channel":…}) --------

function connectSocket() {
  if (state.mode !== 'live' || !session.token) return;
  if (location.protocol === 'file:') {
    qs('#connection-state').textContent = 'demo data';
    return;
  }
  const protocol = location.protocol === 'https:' ? 'wss:' : 'ws:';
  const wsUrl = `${API_ROOT.startsWith('http') ? API_ROOT.replace(/^http/, 'ws') : `${protocol}//${location.host}${API_ROOT}`}/ws?token=${encodeURIComponent(session.token)}`;
  let socket;
  try {
    socket = new WebSocket(wsUrl);
  } catch {
    qs('#connection-state').innerHTML = '<span class="status-dot medium-dot"></span>polling only';
    startPolling();
    return;
  }
  state.ws = socket;
  socket.addEventListener('open', () => {
    state.wsAttempts = 0;
    qs('#connection-state').innerHTML = '<span class="live-dot"></span>live';
    [...BASE_CHANNELS, ...(state.wsIncidentChannel ? [state.wsIncidentChannel] : [])]
      .forEach(channel => socket.send(JSON.stringify({ action: 'subscribe', channel })));
  });
  socket.addEventListener('message', handleSocket);
  socket.addEventListener('close', () => {
    state.ws = null;
    state.wsAttempts += 1;
    if (state.wsAttempts > 5) {
      qs('#connection-state').innerHTML = '<span class="status-dot medium-dot"></span>polling only';
      startPolling();
      return;
    }
    qs('#connection-state').innerHTML = '<span class="status-dot medium-dot"></span>reconnecting';
    setTimeout(connectSocket, Math.min(15000, 1500 * state.wsAttempts));
  });
}

function handleSocket(message) {
  let parsed;
  try {
    parsed = JSON.parse(message.data);
  } catch {
    return;
  }
  if (!parsed.channel) return; // hello/subscribed/pong frames
  if (parsed.channel === 'alerts.stream') {
    refreshLive();
    const data = parsed.data || {};
    if (data.state === 'new' && data.severity === 'critical') {
      showToast(`Critical alert: ${String(data.title || '').slice(0, 72)}`);
    }
  }
  if (parsed.channel === 'indicators.high_severity') refreshLive();
  if (parsed.channel === 'system.health' && state.route === 'admin-health') refreshLive();
  if (parsed.channel?.startsWith('incidents.') && parsed.channel === state.wsIncidentChannel) {
    refreshSelectedTimeline();
  }
}

function startPolling() {
  if (state.pollTimer) return;
  state.pollTimer = setInterval(() => refreshLive(), 30000);
}

// --- session -----------------------------------------------------------------

async function doLogin(event) {
  event.preventDefault();
  const errorBox = qs('#login-error');
  errorBox.hidden = true;
  const endpointInput = qs('#login-endpoint').value.trim().replace(/\/+$/, '');
  if (endpointInput && endpointInput !== API_BASE) {
    localStorage.setItem('tl.api', endpointInput);
    location.reload();
    return;
  }
  try {
    const response = await fetch(`${API_ROOT}/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email: qs('#login-email').value.trim(), password: qs('#login-password').value }),
    });
    if (!response.ok) {
      const detail = await response.json().catch(() => ({}));
      throw detail;
    }
    const payload = await response.json();
    session.token = payload.access_token;
    session.user = payload.user;
    localStorage.setItem('tl.token', session.token);
    localStorage.setItem('tl.user', JSON.stringify(session.user));
    state.mode = 'live';
    state.wsAttempts = 0;
    try {
      const rules = await api('/alerts/rules');
      state.rules = new Map(rules.map(r => [r.id, r.name]));
    } catch { /* rule names optional */ }
    renderSession();
    location.hash = 'overview';
    route();
    renderAll();
  loadAndRenderHeatmap('heatmap-container');
  applyWidgetLayout();
    connectSocket();
    await refreshLive();
    showToast(`Signed in as ${session.user.name}.`);
    scheduleTokenRefresh();
  } catch (error) {
    errorBox.textContent = `${error.error_code || 'LOGIN_FAILED'} — ${error.message || 'Invalid credentials.'}`;
    errorBox.hidden = false;
  }
}

function fillPersona(node) {
  qs('#login-email').value = node.dataset.email;
  qs('#login-password').value = node.dataset.password;
  qs('#login-form').dispatchEvent(new Event('submit', { cancelable: true }));
}

function doLogout() {
  dropSession();
  if (state.ws) {
    try { state.ws.close(); } catch { /* closing */ }
    state.ws = null;
  }
  if (state.pollTimer) { clearInterval(state.pollTimer); state.pollTimer = null; }
  state.mode = 'demo';
  renderSession();
  location.hash = 'login';
  route();
  renderAll();
  loadAndRenderHeatmap('heatmap-container');
  applyWidgetLayout();
}

async function generateReport() {
  if (state.mode !== 'live' || !session.token) {
    showToast('Reports are produced by the live backend — sign in first.');
    return;
  }
  try {
    const incident = state.route === 'incidents' && state.selectedIncident ? state.selectedIncident : null;
    const report = await api('/reports', {
      method: 'POST',
      body: JSON.stringify({
        title: incident ? 'Incident Report' : 'Executive Threat Posture Report',
        kind: incident ? 'incident' : 'executive',
        incident_id: incident,
      }),
    });
    await downloadAuth(`/reports/${report.id}/download`, `${incident ? 'threatlens_incident_report' : 'threatlens_executive_report'}.pdf`);
    showToast(`Report ${String(report.id).slice(0, 8)} generated — PDF downloaded.`);
  } catch (error) {
    showToast(`${error.error_code}: ${error.message}`);
  }
}

// --- events / keyboard -------------------------------------------------------

function bindEvents() {
  document.addEventListener('click', event => {
    const actionNode = event.target.closest('[data-action]');
    if (actionNode) {
      const action = actionNode.dataset.action;
      if (action === 'toggle-tray') toggleTray();
      if (action === 'toggle-user') toggleUser();
      if (action === 'toggle-nav') qs('.sidebar').classList.toggle('open');
      if (action === 'close-detail') closeDetail();
      if (action === 'logout') doLogout();
      if (action === 'retry') retryVisibleState(actionNode);
      if (action === 'start-work') startWork();
      if (action === 'save-hunt') saveHuntReal();
      if (action === 'view-all-threats') viewAllThreats();
      if (action === 'login-persona') fillPersona(actionNode);
      if (action === 'generate-report') generateReport();
    }
    const row = event.target.closest('[data-alert-index]');
    if (row && !event.target.closest('button')) selectAlert(Number(row.dataset.alertIndex));
    const incidentRow = event.target.closest('[data-incident-id]');
    if (incidentRow && state.mode === 'live') selectIncident(incidentRow.dataset.incidentId);
    const huntTab = event.target.closest('[data-hunt-tab]');
    if (huntTab) {
      state.huntTab = huntTab.dataset.huntTab;
      renderHunt('populated');
    }
    const huntResult = event.target.closest('[data-indicator-id]');
    if (huntResult && state.mode === 'live') {
      openIndicatorGraph(huntResult.dataset.indicatorId);
    }
    const mini = event.target.closest('[data-alert-action]');
    if (mini) alertAction(mini.dataset.alertAction, mini.dataset.alertId);
    const feedAction = event.target.closest('[data-feed-action]');
    if (feedAction) feedActionReal(feedAction.dataset.feedAction, feedAction.dataset.feedId);
  });
  qsa('[data-state-target]').forEach(select => select.addEventListener('change', () => renderTarget(select.dataset.stateTarget, select.value)));
  document.addEventListener('keydown', onKeydown);
  qs('#global-search').addEventListener('keydown', event => {
    if (event.key === 'Enter' && event.currentTarget.value.trim()) {
      location.hash = 'hunt';
      const value = event.currentTarget.value.trim();
      qs('#hunt-query').value = value;
      if (state.mode === 'live') runLiveHunt();
      else showToast('Global search opened as a hunt.');
    }
  });
  qs('#hunt-query').addEventListener('keydown', event => {
    if (event.key === 'Enter' && state.mode === 'live') runLiveHunt();
  });
  qs('#hunt-run').addEventListener('click', () => {
    if (state.mode === 'live') runLiveHunt();
    else showToast('Hunt execution needs the live backend.');
  });
  qs('#login-form').addEventListener('submit', doLogin);
  document.querySelector('#widget-config-btn')?.addEventListener('click', () => initWidgetPanel(true));
  document.addEventListener('change', event => {
    const box = event.target.closest('[data-checklist-index]');
    if (box && state.mode === 'live') toggleChecklist(Number(box.dataset.checklistIndex), box.checked);
  });
}

function onKeydown(event) {
  const typing = ['INPUT', 'TEXTAREA', 'SELECT'].includes(document.activeElement?.tagName);
  if (event.key === '/' && !typing) {
    event.preventDefault();
    qs('#global-search').focus();
    return;
  }
  if (event.key === 'Escape') {
    if (qs('#notification-tray').classList.contains('open')) toggleTray(false);
    else if (!qs('#user-menu').hidden) {
      qs('#user-menu').hidden = true;
      qs('.user-button').setAttribute('aria-expanded', 'false');
    } else closeDetail();
    return;
  }
  if (state.route !== 'triage' || typing) return;
  if (['j', 'ArrowDown', 'k', 'ArrowUp'].includes(event.key)) {
    event.preventDefault();
    const delta = ['j', 'ArrowDown'].includes(event.key) ? 1 : -1;
    state.selectedAlert = Math.max(0, Math.min(visibleAlertRows() - 1, state.selectedAlert + delta));
    highlightAlert();
  }
  if (event.key === 'Enter' && state.selectedAlert >= 0) {
    event.preventDefault();
    selectAlert(state.selectedAlert);
  }
}

function toggleTray(force) {
  const tray = qs('#notification-tray');
  const open = typeof force === 'boolean' ? force : !tray.classList.contains('open');
  if (open && state.mode === 'live') renderTrayLive();
  tray.classList.toggle('open', open);
  tray.setAttribute('aria-hidden', String(!open));
}

function toggleUser() {
  const menu = qs('#user-menu');
  menu.hidden = !menu.hidden;
  qs('.user-button').setAttribute('aria-expanded', String(!menu.hidden));
}

function closeDetail() {
  qs('.triage-workbench').classList.remove('detail-open');
  qs('#alert-detail').setAttribute('aria-hidden', 'true');
}

function retryVisibleState(node) {
  const parent = node.closest('[data-banner]');
  const target = parent?.dataset.banner || (state.route === 'triage' ? 'alerts' : state.route.replace('admin-', ''));
  renderTarget(target, 'loading');
  setTimeout(() => renderTarget(target, 'populated'), 700);
  if (state.mode === 'live') refreshLive();
}

function renderTarget(target, value) {
  if (target === 'alerts') renderAlerts(value);
  if (target === 'incidents') renderIncidents(value);
  if (target === 'hunt') { renderFacets(value); renderHunt(value); }
  if (target === 'feeds') renderFeeds(value);
  if (target === 'users') renderUsers(value);
  if (target === 'audit') renderAudit(value);
  if (target === 'health') renderHealth(value);
}

// --- boot --------------------------------------------------------------------

async function init() {
  Object.assign(state, { facetTypes: [], facetTags: [], facetSources: [], triageQuery: '', triageSeverity: 'open', auditAction: '', auditActor: '', incidentTab: 'timeline', liveHunts: [], trayDismissed: new Set() });
  bindEvents();
  bindConsoleExtras();
  bindConsoleExtrasR3();
  bindConsoleExtrasR5();
  initWidgetPanel();
  route();
  window.addEventListener('hashchange', route);
  const reachable = await probeBackend();
  if (reachable) {
    state.mode = 'live';
    qs('#connection-state').innerHTML = '<span class="status-dot medium-dot"></span>sign in';
    if (session.token) {
      try {
        const rules = await api('/alerts/rules');
        state.rules = new Map(rules.map(r => [r.id, r.name]));
      } catch {
        dropSession();
      }
    }
    if (!session.token) location.hash = 'login';
  } else {
    qs('#connection-state').innerHTML = '<span class="status-dot info-dot"></span>demo data';
  }
  renderSession();
  renderAll();
  loadAndRenderHeatmap('heatmap-container');
  applyWidgetLayout();
  qsa('.table-scroll').forEach(sc => sc.addEventListener('scroll', () => {
    sc.classList.toggle('is-scrolled', sc.scrollTop > 2);
  }, { passive: true }));
  if (state.mode === 'live' && session.token) {
    connectSocket();
    await refreshLive();
    startPolling();
    scheduleTokenRefresh();
  }
  window.lucide?.createIcons({ attrs: { 'aria-hidden': 'true' } });
}

document.readyState === 'loading' ? document.addEventListener('DOMContentLoaded', init) : init();


// --- console extras: filters, dialogs, saved hunts, incident actions (R2) ----

function bindConsoleExtras() {
  // F01 · triage text filter (live + demo, client-side over rendered rows)
  qs('#triage-filter')?.addEventListener('input', e => {
    state.triageQuery = e.target.value.trim();
    renderAlerts('populated');
  });
  // F02 · severity chips are real single-select filters
  qsa('[data-triage-chip]').forEach(chip => chip.addEventListener('click', () => {
    state.triageSeverity = chip.dataset.triageChip;
    qsa('[data-triage-chip]').forEach(c => {
      const on = c === chip;
      c.classList.toggle('active', on);
      c.setAttribute('aria-pressed', String(on));
    });
    renderAlerts('populated');
  }));
  // F04/F05 · audit filters (live params, demo client-side), debounced
  qs('#audit-action')?.addEventListener('input', e => { state.auditAction = e.target.value.trim(); scheduleAuditRefresh(); });
  qs('#audit-actor')?.addEventListener('input', e => { state.auditActor = e.target.value.trim(); scheduleAuditRefresh(); });
  qsa('[data-audit-chip]').forEach(chip => chip.addEventListener('click', () => {
    state.auditAction = state.auditAction === chip.dataset.auditChip ? '' : chip.dataset.auditChip;
    qsa('[data-audit-chip]').forEach(c => {
      const on = c.dataset.auditChip === state.auditAction;
      c.classList.toggle('active', on);
      c.setAttribute('aria-pressed', String(on));
    });
    scheduleAuditRefresh();
  }));
  // F06 · audit CSV export
  qs('#export-audit')?.addEventListener('click', exportAuditCsv);
  // F07/F08 · admin create dialogs
  qs('#add-feed')?.addEventListener('click', openAddFeed);
  qs('#add-user')?.addEventListener('click', openAddUser);
  qs('#form-add-feed')?.addEventListener('submit', submitAddFeed);
  qs('#form-add-user')?.addEventListener('submit', submitAddUser);
  // F09/F10 · saved hunts
  qs('#saved-hunts-jump')?.addEventListener('click', () => qs('.saved-rail')?.scrollIntoView({ behavior: 'smooth', block: 'start' }));
  // F11 · facets
  qs('#facet-clear')?.addEventListener('click', clearFacets);
  document.addEventListener('change', onFacetChange);
  // F13/F14 · incident header actions
  qs('#incident-escalate')?.addEventListener('click', escalateIncident);
  qs('#incident-pipe')?.addEventListener('click', pipeOutIncident);
  // F15 · incident tabs handled via delegation in bindConsoleExtrasR3
  // session dialogs
  qs('#open-keymap')?.addEventListener('click', () => qs('#dialog-keymap')?.showModal());
  qs('#open-profile')?.addEventListener('click', () => { fillProfile(); qs('#dialog-profile')?.showModal(); });
  // shared: dialog close + saved-hunt clicks (live rail and demo rail)
  document.addEventListener('click', e => {
    const closer = e.target.closest('[data-action="close-dialog"]');
    if (closer) closer.closest('dialog')?.close();
    const savedLive = e.target.closest('.saved-hunt[data-hunt-id]');
    if (savedLive) runSavedHunt(savedLive.dataset.huntId);
    const savedDemo = e.target.closest('.saved-hunt[data-q]');
    if (savedDemo && state.mode !== 'live') {
      qs('#hunt-query').value = savedDemo.dataset.q;
      showToast('Query loaded into the hunt bar — execution needs the live backend.');
    }
  });
}

let auditTimer = null;
function scheduleAuditRefresh() {
  clearTimeout(auditTimer);
  auditTimer = setTimeout(refreshAudit, 350);
}

async function refreshAudit() {
  if (state.mode !== 'live') { renderAudit('populated'); return; }
  try {
    const sp = new URLSearchParams({ page_size: '60' });
    if (state.auditAction) sp.set('action', state.auditAction);
    if (state.auditActor) sp.set('actor', state.auditActor);
    state.liveAudit = await api(`/audit?${sp.toString()}`);
    state.lastAuditError = null;
    renderAudit('populated');
  } catch (error) {
    state.lastAuditError = error;
    renderAudit('error');
  }
}

function downloadCsv(filename, rows) {
  const csv = rows.map(r => r.map(v => `"${String(v ?? '').replace(/"/g, '""')}"`).join(',')).join('\n');
  const blob = new Blob([csv], { type: 'text/csv' });
  const link = document.createElement('a');
  link.href = URL.createObjectURL(blob);
  link.download = filename;
  link.click();
  URL.revokeObjectURL(link.href);
}

async function exportAuditCsv() {
  if (state.mode !== 'live') {
    showToast('Export rendered from the seeded audit rows.');
    return;
  }
  try {
    const sp = new URLSearchParams({ page_size: '200' });
    if (state.auditAction) sp.set('action', state.auditAction);
    if (state.auditActor) sp.set('actor', state.auditActor);
    const data = await api(`/audit?${sp.toString()}`);
    const rows = [
      ['timestamp', 'actor', 'action', 'entity_type', 'entity_id', 'correlation_id'],
      ...data.items.map(a => [a.created_at, a.actor_email || a.actor_id || 'system', a.action, a.entity_type || '', a.entity_id || '', a.correlation_id || '']),
    ];
    downloadCsv(`threatlens_audit_${new Date().toISOString().slice(0, 10)}.csv`, rows);
    showToast(`Exported ${data.items.length} audit rows.`);
  } catch (error) {
    showToast(`${error.error_code}: ${error.message}`);
  }
}

async function openAddFeed() {
  if (state.mode !== 'live') { showToast('Feed management needs the live backend.'); return; }
  try {
    const data = state.liveFeeds || await api('/feeds');
    state.liveFeeds = data;
    const select = qs('#feed-adapter-select');
    if (select) select.innerHTML = (data.known_adapters || []).map(a => `<option value="${escapeHtml(a)}">${escapeHtml(a)}</option>`).join('');
    qs('#dialog-add-feed')?.showModal();
  } catch (error) {
    showToast(`${error.error_code}: ${error.message}`);
  }
}

async function submitAddFeed(event) {
  event.preventDefault();
  const form = event.target;
  const err = form.querySelector('.dialog-error');
  err.hidden = true;
  const fd = new FormData(form);
  try {
    const feed = await api('/feeds', {
      method: 'POST',
      body: JSON.stringify({
        name: fd.get('name'),
        provider: fd.get('provider'),
        adapter_slug: fd.get('adapter'),
        transport: 'internal_sim',
        url: null,
        source_confidence: Number(fd.get('source_confidence')) || 60,
        poll_interval_seconds: Number(fd.get('poll_interval_seconds')) || 900,
        enabled: true,
      }),
    });
    form.reset();
    form.closest('dialog').close();
    state.liveFeeds = await api('/feeds');
    if (state.route === 'admin-feeds') renderFeeds('populated');
    showToast(`Feed "${feed.name}" created — first poll runs on schedule.`);
  } catch (error) {
    err.textContent = `${error.error_code} — ${error.message}`;
    err.hidden = false;
  }
}

function openAddUser() {
  if (state.mode !== 'live') { showToast('User management needs the live backend.'); return; }
  qs('#dialog-add-user')?.showModal();
}

async function submitAddUser(event) {
  event.preventDefault();
  const form = event.target;
  const err = form.querySelector('.dialog-error');
  err.hidden = true;
  const fd = new FormData(form);
  try {
    await api('/users', {
      method: 'POST',
      body: JSON.stringify({
        email: fd.get('email'),
        name: fd.get('name'),
        password: fd.get('password'),
        role: fd.get('role'),
      }),
    });
    form.reset();
    form.closest('dialog').close();
    state.liveUsers = await api('/users');
    if (state.route === 'admin-users') renderUsers('populated');
    showToast(`Account ${fd.get('email')} created.`);
  } catch (error) {
    err.textContent = `${error.error_code} — ${error.message}`;
    err.hidden = false;
  }
}

async function saveHuntReal() {
  if (state.mode !== 'live' || !session.token) {
    showToast('Saving hunts needs the live backend — sign in first.');
    return;
  }
  const query = qs('#hunt-query').value.trim();
  try {
    await api('/hunts', {
      method: 'POST',
      body: JSON.stringify({
        name: query ? `Hunt: ${query.slice(0, 48)}` : `Hunt ${new Date().toISOString().slice(0, 16)}`,
        query: query || null,
        facets: { types: state.facetTypes, tags: state.facetTags, sources: state.facetSources, min_score: state.huntMinScore },
        notes: 'Saved from the hunt workspace.',
      }),
    });
    state.liveHunts = await api('/hunts');
    renderSavedHunts();
    showToast('Hunt saved to your workspace.');
  } catch (error) {
    showToast(`${error.error_code}: ${error.message}`);
  }
}

function renderSavedHunts() {
  const rail = qs('.saved-rail');
  if (!rail || state.mode !== 'live') return;
  const hunts = state.liveHunts || [];
  rail.querySelectorAll('.saved-hunt, .rail-empty').forEach(node => node.remove());
  const body = document.createElement('div');
  body.innerHTML = hunts.length ? hunts.map(h => `
    <button class="saved-hunt" type="button" data-hunt-id="${escapeHtml(h.id)}" title="${escapeHtml(h.query || '')}">
      <strong>${escapeHtml(h.name)}</strong>
      <span class="mono">${escapeHtml(h.query || Object.keys(h.facets || {}).join(', ') || '—')}</span>
      <small>${escapeHtml(h.created_by || 'operator')} · ${ago(h.created_at)}</small>
    </button>`).join('')
    : '<div class="operator-empty rail-empty" style="min-height:8rem"><p>No saved hunts yet — save one from the query bar.</p></div>';
  rail.append(body);
}

async function runSavedHunt(id) {
  const hunt = (state.liveHunts || []).find(h => h.id === id);
  if (!hunt) return;
  state.facetTypes = hunt.facets?.types || [];
  state.facetTags = hunt.facets?.tags || [];
  state.facetSources = hunt.facets?.sources || [];
  state.huntMinScore = hunt.facets?.min_score || 0;
  qs('#hunt-query').value = hunt.query || '';
  state.huntTab = 'results';
  location.hash = 'hunt';
  await runLiveHunt();
  renderHunt('populated');
  showToast(`Hunt "${hunt.name}" loaded.`);
}

function onFacetChange(event) {
  const box = event.target.closest('input[data-facet-group]');
  if (!box) return;
  const group = box.dataset.facetGroup;
  const value = box.dataset.facetValue;
  const set = group === 'types' ? state.facetTypes : group === 'sources' ? state.facetSources : state.facetTags;
  const at = set.indexOf(value);
  if (box.checked && at === -1) set.push(value);
  if (!box.checked && at > -1) set.splice(at, 1);
  if (state.mode === 'live') runLiveHunt();
}

function clearFacets() {
  state.facetTypes = [];
  state.facetTags = [];
  state.facetSources = [];
  qsa('#facet-content input[data-facet-group]').forEach(box => { box.checked = false; });
  if (state.mode === 'live') runLiveHunt();
}

async function escalateIncident() {
  if (state.mode !== 'live' || !state.selectedIncident) {
    showToast('Incident actions need the live backend.');
    return;
  }
  try {
    await api(`/incidents/${state.selectedIncident}`, { method: 'PATCH', body: JSON.stringify({ status: 'contained' }) });
    await hydrateIncidentFromApi(state.selectedIncident);
    const item = state.liveIncidents.find(i => i.id === state.selectedIncident);
    if (item) item.status = 'contained';
    renderIncidents('populated');
    showToast('Incident marked contained — recorded on the timeline.');
  } catch (error) {
    showToast(`${error.error_code}: ${error.message}`);
  }
}

async function pipeOutIncident() {
  if (state.mode !== 'live' || !state.selectedIncident) {
    showToast('Exports need the live backend.');
    return;
  }
  try {
    const detail = state.liveIncidentDetail || await api(`/incidents/${state.selectedIncident}`);
    const ids = new Set(detail.indicator_ids || (detail.indicators || []).map(i => i.id));
    const bundle = await api('/export/stix?min_score=0&tlp_max=red');
    const objects = (bundle.objects || []).filter(o => o.type === 'indicator' && ids.has(String(o.id).replace('indicator--', '')));
    const out = { type: 'bundle', id: `bundle--incident-${state.selectedIncident.slice(0, 8)}`, objects };
    const blob = new Blob([JSON.stringify(out, null, 2)], { type: 'application/stix+json' });
    const link = document.createElement('a');
    link.href = URL.createObjectURL(blob);
    link.download = `threatlens_incident_${state.selectedIncident.slice(0, 8)}.stix.json`;
    link.click();
    URL.revokeObjectURL(link.href);
    showToast(`Piped ${objects.length} incident indicators out as STIX.`);
  } catch (error) {
    showToast(`${error.error_code}: ${error.message}`);
  }
}

function fillProfile() {
  const body = qs('#profile-body');
  if (!body) return;
  if (session.user) {
    body.innerHTML = `<dl class="key-values"><dt>Name</dt><dd>${escapeHtml(session.user.name)}</dd><dt>Email</dt><dd class="mono">${escapeHtml(session.user.email)}</dd><dt>Role</dt><dd>${escapeHtml(session.user.role.replace(/_/g, ' '))}</dd><dt>MFA</dt><dd>${session.user.mfa_enabled ? 'enabled' : 'off'}</dd></dl>`;
  } else {
    body.innerHTML = '<p class="muted">Demo session — sign in against a backend for account details.</p>';
  }
}

function viewAllThreats() {
  location.hash = 'hunt';
  state.huntTab = 'results';
  if (state.mode === 'live') {
    loadMatrix();
    runLiveHunt();
  }
  renderHunt('populated');
}


// --- console extras R3: pagination, inline admin, drawer editors, tray -------

async function downloadAuth(path, filename) {
  const resp = await fetch(`${API_ROOT}${path}`, { headers: session.token ? { Authorization: `Bearer ${session.token}` } : {} });
  if (!resp.ok) throw { error_code: 'download_failed', message: `HTTP ${resp.status}` };
  const blob = await resp.blob();
  const link = document.createElement('a');
  link.href = URL.createObjectURL(blob);
  link.download = filename;
  link.click();
  URL.revokeObjectURL(link.href);
}

async function loadMoreAlerts() {
  if (state.mode !== 'live') return;
  const next = (state.alertsPage || 1) + 1;
  try {
    const data = await api(`/alerts?sort=-severity_score&page_size=50&page=${next}`);
    const known = new Set(state.liveAlerts.map(a => a.id));
    state.liveAlerts = state.liveAlerts.concat((data.items || []).filter(a => !known.has(a.id)));
    state.alertsPage = next;
    renderAlerts('populated');
    showToast(`Loaded page ${next} — ${state.liveAlerts.length} of ${state.alertsTotal} in view.`);
  } catch (error) {
    showToast(`${error.error_code}: ${error.message}`);
  }
}

async function loadMoreAudit() {
  if (state.mode !== 'live') return;
  const next = (state.auditPage || 1) + 1;
  try {
    const sp = new URLSearchParams({ page_size: '60', page: String(next) });
    if (state.auditAction) sp.set('action', state.auditAction);
    if (state.auditActor) sp.set('actor', state.auditActor);
    const data = await api(`/audit?${sp.toString()}`);
    state.liveAudit.items = (state.liveAudit.items || []).concat(data.items || []);
    state.auditPage = next;
    renderAudit('populated');
  } catch (error) {
    showToast(`${error.error_code}: ${error.message}`);
  }
}

async function userRole(userId, role) {
  if (state.mode !== 'live') return;
  try {
    await api(`/users/${userId}`, { method: 'PATCH', body: JSON.stringify({ role }) });
    showToast('Role updated — change recorded in the audit trail.');
  } catch (error) {
    showToast(`${error.error_code}: ${error.message}`);
    state.liveUsers = await api('/users');
    renderUsers('populated');
  }
}

async function userStatus(userId, action) {
  if (state.mode !== 'live') return;
  try {
    await api(`/users/${userId}`, { method: 'PATCH', body: JSON.stringify({ status: action === 'disable' ? 'disabled' : 'active' }) });
    state.liveUsers = await api('/users');
    renderUsers('populated');
    showToast(`Account ${action === 'disable' ? 'disabled' : 're-enabled'}.`);
  } catch (error) {
    showToast(`${error.error_code}: ${error.message}`);
  }
}

function openEditFeed(feedId) {
  if (state.mode !== 'live') { showToast('Feed management needs the live backend.'); return; }
  const feed = (state.liveFeeds?.items || []).find(f => f.id === feedId);
  if (!feed) return;
  const form = qs('#form-edit-feed');
  if (!form) return;
  form.querySelector('input[name="name"]').value = feed.name;
  form.querySelector('input[name="source_confidence"]').value = feed.source_confidence;
  form.querySelector('input[name="poll_interval_seconds"]').value = feed.poll_interval_seconds;
  form.querySelector('select[name="default_tlp"]').value = feed.default_tlp;
  form.dataset.feedId = feed.id;
  qs('#dialog-edit-feed')?.showModal();
}

async function submitEditFeed(event) {
  event.preventDefault();
  const form = event.target;
  const err = form.querySelector('.dialog-error');
  err.hidden = true;
  const fd = new FormData(form);
  try {
    await api(`/feeds/${form.dataset.feedId}`, {
      method: 'PATCH',
      body: JSON.stringify({
        source_confidence: Number(fd.get('source_confidence')),
        poll_interval_seconds: Number(fd.get('poll_interval_seconds')),
        default_tlp: fd.get('default_tlp'),
      }),
    });
    form.closest('dialog').close();
    state.liveFeeds = await api('/feeds');
    renderFeeds('populated');
    showToast('Feed configuration updated.');
  } catch (error) {
    err.textContent = `${error.error_code} — ${error.message}`;
    err.hidden = false;
  }
}

async function indicatorStatus(status, indicatorId) {
  if (state.mode !== 'live' || !indicatorId) return;
  try {
    await api(`/indicators/${indicatorId}`, { method: 'PATCH', body: JSON.stringify({ status }) });
    showToast(`Indicator marked ${status.replace(/_/g, ' ')}.`);
    hydrateDrawer(indicatorId);
  } catch (error) {
    showToast(`${error.error_code}: ${error.message}`);
  }
}

async function addIndicatorTags(indicatorId, form) {
  const input = form.querySelector('input[name="tags"]');
  const tags = String(input.value || '').split(',').map(t => t.trim()).filter(Boolean);
  if (!tags.length) return;
  try {
    await api(`/indicators/${indicatorId}/tags`, { method: 'POST', body: JSON.stringify({ tags }) });
    input.value = '';
    showToast('Tags attached.');
    hydrateDrawer(indicatorId);
  } catch (error) {
    showToast(`${error.error_code}: ${error.message}`);
  }
}

async function addIndicatorNote(indicatorId, form) {
  const body = String(form.querySelector('textarea[name="body"]').value || '').trim();
  if (!body) return;
  try {
    await api(`/indicators/${indicatorId}/notes`, { method: 'POST', body: JSON.stringify({ body }) });
    form.querySelector('textarea[name="body"]').value = '';
    showToast('Note recorded.');
    hydrateDrawer(indicatorId);
  } catch (error) {
    showToast(`${error.error_code}: ${error.message}`);
  }
}

function clearTray() {
  // dismiss every open alert, not just the visible page of five — "Clear"
  // means the tray stays empty until a genuinely new alert arrives
  state.liveAlerts.filter(a => ['new', 'acknowledged', 'in_progress'].includes(a.state)).forEach(a => state.trayDismissed.add(a.id));
  clearTrayItems();
  updateBadge();
  showToast('Tray cleared — new alerts will land here as they arrive.');
}

async function patchIncidentStatus(status) {
  if (state.mode !== 'live' || !state.selectedIncident) {
    showToast('Incident actions need the live backend.');
    return;
  }
  try {
    await api(`/incidents/${state.selectedIncident}`, { method: 'PATCH', body: JSON.stringify({ status }) });
    await hydrateIncidentFromApi(state.selectedIncident);
    const item = state.liveIncidents.find(i => i.id === state.selectedIncident);
    if (item) item.status = status;
    renderIncidents('populated');
    showToast(`Incident → ${status}.`);
  } catch (error) {
    showToast(`${error.error_code}: ${error.message}`);
  }
}

function bindConsoleExtrasR3() {
  document.addEventListener('click', e => {
    const userAction = e.target.closest('[data-user-action]');
    if (userAction) userStatus(userAction.dataset.userId, userAction.dataset.userAction);
    const feedEdit = e.target.closest('[data-feed-edit]');
    if (feedEdit) openEditFeed(feedEdit.dataset.feedEdit);
    if (e.target.closest('[data-action="audit-more"]')) loadMoreAudit();
    if (e.target.closest('[data-action="alerts-more"]')) loadMoreAlerts();
    const drawerStatus = e.target.closest('[data-indicator-status]');
    if (drawerStatus) indicatorStatus(drawerStatus.dataset.indicatorStatus, drawerStatus.dataset.indicatorId);
    if (e.target.closest('#tray-clear')) clearTray();
    const trayItem = e.target.closest('.notification-item[data-nav]');
    if (trayItem) location.hash = trayItem.dataset.nav;
  });
  document.addEventListener('change', e => {
    const roleSelect = e.target.closest('select[data-user-role]');
    if (roleSelect) userRole(roleSelect.dataset.userRole, roleSelect.value);
    if (e.target.id === 'incident-status') patchIncidentStatus(e.target.value);
  });
  document.addEventListener('submit', e => {
    const tagForm = e.target.closest('.drawer-tag-form');
    if (tagForm) { addIndicatorTags(tagForm.dataset.indicatorId, tagForm); return; }
    const noteForm = e.target.closest('.drawer-note-form');
    if (noteForm) { addIndicatorNote(noteForm.dataset.indicatorId, noteForm); return; }
    if (e.target.id === 'form-edit-feed') submitEditFeed(e);
  });
}


// --- console extras R5: delegation-first tab switching, tray rebuild, nav RBAC, theme ---

function bindConsoleExtrasR5() {
  document.addEventListener('click', e => {
    // incident tabs — delegated, immune to re-render timing
    const incTab = e.target.closest('[data-incident-tab]');
    if (incTab) {
      if (incTab.dataset.incidentTab === 'evidence') {
        showToast('Evidence bundles ship with the case export.');
        return;
      }
      state.incidentTab = incTab.dataset.incidentTab;
      renderIncidentTab();
      return;
    }
    // theme toggle
    if (e.target.closest('#theme-toggle')) {
      const next = document.documentElement.dataset.theme === 'light' ? 'dark' : 'light';
      document.documentElement.dataset.theme = next;
      localStorage.setItem('tl.theme', next);
      showToast(next === 'light' ? 'Light shift — high-contrast day palette.' : 'Dark shift — night palette.');
    }
  });
}

// nav items respect the signed-in role (PRD §11 nav gating)
const NAV_ROLES = {
  overview: ['administrator', 'security_engineer', 'incident_responder', 'threat_hunter', 'soc_analyst', 'executive'],
  triage: ['administrator', 'security_engineer', 'incident_responder', 'threat_hunter', 'soc_analyst'],
  incidents: ['administrator', 'incident_responder', 'threat_hunter', 'soc_analyst'],
  hunt: ['administrator', 'security_engineer', 'incident_responder', 'threat_hunter', 'soc_analyst'],
  'admin-feeds': ['administrator', 'security_engineer'],
  'admin-users': ['administrator'],
  'admin-audit': ['administrator', 'security_engineer'],
  'admin-health': ['administrator', 'security_engineer'],
};

function applyNavRoles() {
  if (!session.user) return;
  qsa('.nav-item').forEach(item => {
    const allowed = NAV_ROLES[item.dataset.route] || [];
    item.hidden = !allowed.includes(session.user.role);
  });
}

function clearTrayItems() {
  qsa('#notification-tray .notification-item').forEach(node => node.remove());
}


// --- token refresh: silently renew before the 30-minute expiry ---------------

let tokenRefreshTimer = null;

function scheduleTokenRefresh() {
  clearTimeout(tokenRefreshTimer);
  // refresh at 25 minutes (access token expires at 30)
  tokenRefreshTimer = setTimeout(async () => {
    try {
      const resp = await fetch(`${API_ROOT}/auth/refresh`, { method: 'POST', credentials: 'include' });
      if (resp.ok) {
        const data = await resp.json();
        session.token = data.access_token;
        localStorage.setItem('tl.token', data.access_token);
        // reschedule for the next cycle
        scheduleTokenRefresh();
      } else if (resp.status === 401) {
        // refresh token expired — force re-login
        doLogout();
      }
    } catch {
      // network error — retry in 2 minutes
      tokenRefreshTimer = setTimeout(scheduleTokenRefresh, 120000);
    }
  }, 25 * 60 * 1000);
}
