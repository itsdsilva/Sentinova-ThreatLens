// ThreatLens console — core: configuration, session, transport, demo fixtures.

export const API_BASE = resolveApiBase();
export const API_ROOT = `${API_BASE}/api/v1`;

function resolveApiBase() {
  if (typeof window === 'undefined') return '';
  const override = new URLSearchParams(location.search).get('api')
    || localStorage.getItem('tl.api')
    || window.ThreatLensConfig?.apiBase
    || '';
  return override.trim().replace(/\/+$/, '');
}

export const session = {
  token: localStorage.getItem('tl.token') || null,
  user: JSON.parse(localStorage.getItem('tl.user') || 'null'),
};

export const state = {
  mode: 'demo',            // 'live' | 'demo'
  ws: null,
  wsAttempts: 0,
  route: 'overview',
  selectedAlert: -1,
  selectedIncident: null,
  selectedIndicator: null,
  huntTab: 'graph',
  huntQuery: '',
  huntMinScore: 0,
  wsIncidentChannel: null,
  rules: new Map(),
  pollTimer: null,
  liveAlerts: [],
  liveExec: null,
  liveIncidents: [],
  liveTimeline: [],
  liveSearch: null,
  liveMatrix: null,
  liveGraph: null,
  liveFeeds: null,
  liveUsers: null,
  liveAudit: null,
  liveHealth: null,
  liveSystem: null,
  lastAlertError: null,
  lastFeedError: null,
  lastUserError: null,
  lastAuditError: null,
  lastHuntError: null,
};

// Cross-module action registry — avoids import cycles between views/app.
export const actions = {};

export const qs = (selector, root = document) => root.querySelector(selector);
export const qsa = (selector, root = document) => [...root.querySelectorAll(selector)];
export const icon = name => `<i data-lucide="${name}"></i>`;
export const escapeHtml = value => String(value ?? '').replace(/[&<>'"]/g, char => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', "'": '&#39;', '"': '&quot;' }[char]));
export const severityChip = value => `<span class="severity ${escapeHtml(value)}">${escapeHtml(value).toUpperCase()}</span>`;
export const tlpChip = value => `<span class="tlp ${escapeHtml(value)}">${escapeHtml(value).toUpperCase()}</span>`;

export function ago(iso) {
  const then = Date.parse(iso);
  if (Number.isNaN(then)) return '—';
  const s = Math.max(0, (Date.now() - then) / 1000);
  if (s < 60) return `${Math.floor(s)}s ago`;
  if (s < 3600) return `${Math.floor(s / 60)}m ago`;
  if (s < 86400) return `${Math.floor(s / 3600)}h ago`;
  return `${Math.floor(s / 86400)}d ago`;
}

export function zTime(iso) {
  if (!iso) return '—';
  return `${String(iso).slice(0, 19)}Z`;
}

export function spark(score, index) {
  const heights = [5, 8, 4, 10, 7, 11].map((h, i) => Math.max(2, Math.min(12, h + ((index + i) % 3) - 1)));
  const color = score >= 95 ? 'var(--critical)' : score >= 80 ? 'var(--high)' : score >= 60 ? 'var(--medium)' : 'var(--low)';
  return `<span class="microbar" aria-hidden="true">${heights.map(h => `<i style="height:${h}px;background:${color}"></i>`).join('')}</span>`;
}

export async function api(path, options = {}) {
  const headers = { 'Content-Type': 'application/json', ...(options.headers || {}) };
  if (session.token) headers.Authorization = `Bearer ${session.token}`;
  const response = await fetch(`${API_ROOT}${path}`, { ...options, headers });
  if (response.status === 401) {
    dropSession();
    throw { error_code: 'unauthenticated', message: 'Session expired — sign in again.', correlation_id: 'n/a' };
  }
  if (!response.ok) {
    const body = await response.json().catch(() => null);
    const detail = body && typeof body === 'object' ? body : {};
    throw {
      error_code: detail.error_code || `HTTP_${response.status}`,
      message: detail.message || (typeof detail.detail === 'string' ? detail.detail : 'Request failed.'),
      correlation_id: detail.correlation_id || 'n/a',
    };
  }
  if (response.status === 204) return null;
  return response.json();
}

export function dropSession() {
  session.token = null;
  session.user = null;
  localStorage.removeItem('tl.token');
  localStorage.removeItem('tl.user');
}

export async function probeBackend() {
  try {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 4000);
    const response = await fetch(`${API_ROOT}/health`, { signal: controller.signal });
    clearTimeout(timer);
    return response.ok;
  } catch {
    return false;
  }
}

export function showToast(message) {
  const toast = document.createElement('div');
  toast.className = 'toast';
  toast.textContent = message;
  qs('#toast-stack')?.append(toast);
  setTimeout(() => toast.remove(), 3600);
}

export function setBanner(target, stateName) {
  const banner = qs(`[data-banner="${target}"]`);
  if (banner) banner.hidden = stateName !== 'stale';
}

export function stateMarkup(kind) {
  if (kind === 'loading') return `<div class="skeleton-table" aria-label="Loading"><div class="skeleton-row">${'<i class="skeleton-line"></i>'.repeat(5)}</div>${Array.from({ length: 8 }, () => `<div class="skeleton-row">${'<i class="skeleton-line"></i>'.repeat(5)}</div>`).join('')}</div>`;
  if (kind === 'empty') return `<div class="state-message">${icon('inbox')}<strong>Queue clear.</strong><span>Feeds poll on schedule — new items arrive live.</span></div>`;
  if (kind === 'error') return `<div class="state-message">${icon('triangle-alert')}<strong>FEED_UPSTREAM_TIMEOUT</strong><span>Threat data could not be refreshed.</span><code>corr-5d42a91e</code><button class="button secondary" type="button" data-action="retry">Retry</button></div>`;
  return '';
}

export function errorMarkup(error) {
  return `<div class="state-message">${icon('triangle-alert')}<strong>${escapeHtml(error?.error_code || 'REQUEST_FAILED')}</strong><span>${escapeHtml(error?.message || 'Live backend rejected the request.')}</span><code>${escapeHtml(error?.correlation_id || 'n/a')}</code><button class="button secondary" type="button" data-action="retry">Retry</button></div>`;
}

// --- demo fixtures (offline fallback; deterministic, TEST-NET only) ----------

export const demoAlerts = [
  { id:'ALT-9F2C1', severity:'critical', score:98, indicator:'203.0.113.187', type:'ipv4', status:'new', tlp:'amber', source:'AbuseIPDB + 3', age:'18s ago', absolute:'2026-09-28 14:01:53Z', family:'Qakbot', sightings:14, confidence:96, verdict:'17/19 malicious', asn:'AS64496 TEST-NET-3', first:'2026-09-28 13:58:04Z', attack:'T1071.001, T1105' },
  { id:'ALT-9E81A', severity:'critical', score:96, indicator:'6f30cfa90c8a89f7…c13e7b2a', type:'sha256', status:'new', tlp:'red', source:'MalwareBazaar + 2', age:'1m ago', absolute:'2026-09-28 14:00:47Z', family:'IcedID', sightings:7, confidence:94, verdict:'54/61 malicious', asn:'n/a', first:'2026-09-28 13:43:19Z', attack:'T1059.001, T1105' },
  { id:'ALT-9D44E', severity:'high', score:91, indicator:'cdn-update-check.net', type:'domain', status:'acknowledged', tlp:'amber', source:'URLhaus + 4', age:'3m ago', absolute:'2026-09-28 13:59:08Z', family:'Emotet', sightings:22, confidence:91, verdict:'12/15 malicious', asn:'AS64497', first:'2026-09-28 09:14:33Z', attack:'T1566.001, T1204.002' },
  { id:'ALT-9CD20', severity:'high', score:88, indicator:'203.0.113.44', type:'ipv4', status:'new', tlp:'green', source:'Feodo Tracker + 2', age:'4m ago', absolute:'2026-09-28 13:58:02Z', family:'Qakbot', sightings:5, confidence:89, verdict:'8/10 malicious', asn:'AS64496 TEST-NET-3', first:'2026-09-28 12:05:11Z', attack:'T1095' },
  { id:'ALT-9BA02', severity:'high', score:84, indicator:'auth-sync-service.org', type:'domain', status:'in progress', tlp:'amber', source:'OTX + 2', age:'7m ago', absolute:'2026-09-28 13:55:15Z', family:'Cobalt Strike', sightings:9, confidence:86, verdict:'9/13 malicious', asn:'AS64500', first:'2026-09-27 21:32:09Z', attack:'T1219, T1071.001' },
  { id:'ALT-9984B', severity:'medium', score:72, indicator:'198.51.100.91', type:'ipv4', status:'new', tlp:'clear', source:'GreyNoise + 1', age:'11m ago', absolute:'2026-09-28 13:51:09Z', family:'scanner', sightings:2, confidence:74, verdict:'3/8 malicious', asn:'AS64498 TEST-NET-2', first:'2026-09-28 06:17:51Z', attack:'T1595.002' },
  { id:'ALT-9827C', severity:'medium', score:68, indicator:'invoice-review-cloud.com', type:'domain', status:'acknowledged', tlp:'green', source:'PhishTank + 2', age:'16m ago', absolute:'2026-09-28 13:46:11Z', family:'credential theft', sightings:4, confidence:82, verdict:'7/12 malicious', asn:'AS64501', first:'2026-09-28 08:00:27Z', attack:'T1566.002' },
  { id:'ALT-971F3', severity:'low', score:43, indicator:'203.0.113.8', type:'ipv4', status:'new', tlp:'clear', source:'OTX', age:'21m ago', absolute:'2026-09-28 13:41:42Z', family:'unclassified', sightings:0, confidence:51, verdict:'1/9 malicious', asn:'AS64496 TEST-NET-3', first:'2026-09-26 16:13:09Z', attack:'T1595' },
];
export const demoFeeds = [
  { name:'AbuseIPDB', transport:'REST', status:'nominal', last:'2026-09-28 14:01:39Z', next:'14:06Z', received:'84,210', lag:'12s' },
  { name:'AlienVault OTX', transport:'REST', status:'nominal', last:'2026-09-28 13:59:58Z', next:'14:15Z', received:'231,804', lag:'1m' },
  { name:'URLhaus', transport:'CSV', status:'delayed', last:'2026-09-28 13:42:19Z', next:'14:04Z', received:'19,421', lag:'20m' },
  { name:'MalwareBazaar', transport:'REST', status:'nominal', last:'2026-09-28 14:01:07Z', next:'14:11Z', received:'7,884', lag:'1m' },
  { name:'Feodo Tracker', transport:'CSV', status:'nominal', last:'2026-09-28 13:57:41Z', next:'14:12Z', received:'1,092', lag:'4m' },
  { name:'Partner west', transport:'TAXII 2.1', status:'rate limited', last:'2026-09-28 13:58:12Z', next:'14:06Z', received:'492,337', lag:'4m' },
];
export const demoUsers = [
  { name:'Priya Nair', email:'pnair@sentinova.internal', role:'SOC analyst', status:'active', mfa:'enabled', last:'2026-09-28 14:02:01Z' },
  { name:'Daniel Okafor', email:'dokafor@sentinova.internal', role:'Incident responder', status:'active', mfa:'enabled', last:'2026-09-28 13:58:32Z' },
  { name:'Mei Lin', email:'mlin@sentinova.internal', role:'Threat hunter', status:'active', mfa:'enabled', last:'2026-09-28 13:47:19Z' },
  { name:'Rachel Adeyemi', email:'radeyemi@sentinova.internal', role:'Executive', status:'active', mfa:'enabled', last:'2026-09-28 10:16:44Z' },
  { name:'Arjun Sen', email:'asen@sentinova.internal', role:'Security engineer', status:'review due', mfa:'enabled', last:'2026-09-27 21:03:12Z' },
];
export const demoAudit = [
  { time:'2026-09-28 14:01:58Z', actor:'Priya Nair', action:'alert.acknowledge', object:'ALT-9D44E', result:'allowed', cid:'corr-6a91c0e4' },
  { time:'2026-09-28 14:01:11Z', actor:'worker/scoring-03', action:'indicator.score', object:'ioc-79d2c4', result:'written', cid:'corr-8b4e10d2' },
  { time:'2026-09-28 13:58:30Z', actor:'Daniel Okafor', action:'incident.timeline.append', object:'INC-2026-0941', result:'written', cid:'corr-2975bb81' },
  { time:'2026-09-28 13:57:14Z', actor:'Arjun Sen', action:'feed.repoll', object:'partner-west', result:'rate_limited', cid:'corr-346afdb9' },
  { time:'2026-09-28 13:54:08Z', actor:'Mei Lin', action:'hunt.save', object:'hunt-0228', result:'written', cid:'corr-e4862f11' },
  { time:'2026-09-28 13:42:50Z', actor:'system/auth', action:'token.refresh', object:'usr-1930', result:'allowed', cid:'corr-a09132cd' },
];
export const demoIncidents = [
  { id:'INC-2026-0941', severity:'critical', title:'Qakbot lateral movement — payments', age:'1h 21m', owner:'D. Okafor' },
  { id:'INC-2026-0938', severity:'high', title:'IcedID loader on corp endpoint', age:'3h 48m', owner:'S. Chen' },
  { id:'INC-2026-0934', severity:'high', title:'Credential phishing — finance', age:'6h 02m', owner:'D. Okafor' },
  { id:'INC-2026-0929', severity:'medium', title:'Outbound beacon — dev subnet', age:'1d 3h', owner:'A. Khan' },
];
export const demoTimeline = [
  { time:'2026-09-28 14:01:12Z', severity:'low', title:'Egress block confirmed', body:'Connector siem-prod-01 accepted block set for 3 C2 indicators.' },
  { time:'2026-09-28 13:58:30Z', severity:'high', title:'Endpoint sighting correlated', body:'Host PAY-WS-044 executed a process chain matching T1059.001.' },
  { time:'2026-09-28 13:51:06Z', severity:'info', title:'Incident escalated to IR', body:'Priya Nair attached 7 alerts and assigned Daniel Okafor.' },
  { time:'2026-09-28 13:45:22Z', severity:'critical', title:'Lateral movement detected', body:'SMB authentication from PAY-WS-044 to PAY-DB-02; technique T1021.002.' },
  { time:'2026-09-28 13:42:48Z', severity:'high', title:'Qakbot indicator matched', body:'External indicator 203.0.113.187 matched proxy and EDR telemetry.' },
  { time:'2026-09-28 12:41:07Z', severity:'info', title:'Incident opened', body:'Rule CORR-019 crossed the critical correlation threshold.' },
];
export const demoServices = [
  { name:'api-gateway', status:'nominal', instances:'3/3', p95:'184ms', queue:'—' },
  { name:'ingest-workers', status:'nominal', instances:'8/8', p95:'2.1s', queue:'1,284' },
  { name:'search-cluster', status:'nominal', instances:'3/3', p95:'412ms', queue:'0' },
  { name:'postgres-primary', status:'nominal', instances:'1/1', p95:'28ms', queue:'6' },
  { name:'redis-event-bus', status:'nominal', instances:'3/3', p95:'4ms', queue:'88' },
  { name:'report-worker', status:'degraded', instances:'1/2', p95:'8.4s', queue:'7' },
];
