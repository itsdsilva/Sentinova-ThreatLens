// ThreatLens console — admin views: feeds, users, audit log, system health.

import { state, session, api, qs, escapeHtml, severityChip, ago, zTime, showToast, setBanner, stateMarkup, errorMarkup, demoFeeds, demoUsers, demoAudit, demoServices } from './core.js';

const feedStatus = f => !f.enabled ? 'disabled' : f.last_status === 'ok' ? 'nominal' : f.last_status ? 'impaired' : 'pending';
const statusSev = s => ({ nominal: 'low', delayed: 'medium', 'rate limited': 'high', impaired: 'high', degraded: 'high', pending: 'info' })[s] || 'info';

export function renderFeeds(kind) {
  setBanner('feeds', kind);
  const target = qs('#feed-table-container');
  if (['loading', 'empty', 'error'].includes(kind)) {
    target.innerHTML = kind === 'error' && state.lastFeedError ? errorMarkup(state.lastFeedError) : stateMarkup(kind);
    window.lucide?.createIcons();
    return;
  }
  if (state.mode === 'live') {
    const feeds = state.liveFeeds?.items || [];
    if (!feeds.length) {
      target.innerHTML = stateMarkup('empty');
      return;
    }
    target.innerHTML = `<table class="ops-table"><caption class="sr-only">Configured intelligence feeds</caption><thead><tr><th scope="col">Feed</th><th scope="col">Transport</th><th scope="col">Status</th><th scope="col">Last poll</th><th scope="col">Next poll</th><th scope="col" class="num">Ingested</th><th scope="col" aria-label="Actions"></th></tr></thead><tbody>${feeds.map(f => {
      const status = feedStatus(f);
      const next = f.enabled && f.last_polled_at ? new Date(Date.parse(f.last_polled_at) + f.poll_interval_seconds * 1000).toISOString().slice(11, 16) + 'Z' : '—';
      return `<tr data-severity="${statusSev(status)}"><td><strong>${escapeHtml(f.name)}</strong>${f.last_error ? `<div class="source-cell">${escapeHtml(f.last_error)}</div>` : ''}</td><td class="mono">${escapeHtml(f.transport)}</td><td>${severityChip(statusSev(status))} <span class="status-inline">${status}</span></td><td class="mono">${escapeHtml(zTime(f.last_polled_at))}</td><td class="mono">${next}</td><td class="num mono">${f.items_ingested}</td><td><span class="row-actions"><button class="mini-action" type="button" data-feed-edit="${escapeHtml(f.id)}">Edit</button><button class="mini-action" type="button" data-feed-action="poll" data-feed-id="${escapeHtml(f.id)}">Re-poll</button><button class="mini-action" type="button" data-feed-action="toggle" data-feed-id="${escapeHtml(f.id)}">${f.enabled ? 'Disable' : 'Enable'}</button></span></td></tr>`;
    }).join('')}</tbody></table>`;
    window.lucide?.createIcons();
    return;
  }
  target.innerHTML = `<table class="ops-table"><caption class="sr-only">Configured intelligence feeds</caption><thead><tr><th scope="col">Feed</th><th scope="col">Transport</th><th scope="col">Status</th><th scope="col">Last poll</th><th scope="col">Next</th><th scope="col" class="num">Received 24h</th><th scope="col" class="num">Lag</th><th scope="col" aria-label="Actions"></th></tr></thead><tbody>${demoFeeds.map(f => `<tr data-severity="${statusSev(f.status)}"><td><strong>${f.name}</strong></td><td class="mono">${f.transport}</td><td>${severityChip(statusSev(f.status))} <span class="status-inline">${f.status}</span></td><td class="mono">${f.last}</td><td class="mono">${f.next}</td><td class="num mono">${f.received}</td><td class="num mono">${f.lag}</td><td><span class="row-actions"><button class="mini-action" type="button" tabindex="-1">Re-poll</button></span></td></tr>`).join('')}</tbody></table>`;
}

export async function feedActionReal(action, feedId) {
  if (state.mode !== 'live') {
    showToast('Feed operations need the live backend.');
    return;
  }
  try {
    if (action === 'poll') {
      const feed = await api(`/feeds/${feedId}/poll`, { method: 'POST' });
      const result = feed.poll_result || {};
      showToast(`${feed.name}: ${result.records ?? 0} records → ${result.created ?? 0} new, ${result.merged ?? 0} merged.`);
    }
    if (action === 'toggle') {
      const feed = await api(`/feeds/${feedId}/toggle`, { method: 'POST' });
      showToast(`${feed.name} ${feed.enabled ? 'enabled' : 'disabled'}.`);
    }
    state.liveFeeds = await api('/feeds');
    renderFeeds('populated');
  } catch (error) {
    showToast(`${error.error_code}: ${error.message}`);
  }
}

export function renderUsers(kind) {
  const target = qs('#user-table-container');
  if (['loading', 'empty', 'error'].includes(kind)) {
    target.innerHTML = kind === 'error' && state.lastUserError ? errorMarkup(state.lastUserError) : stateMarkup(kind);
    window.lucide?.createIcons();
    return;
  }
  if (state.mode === 'live') {
    const users = state.liveUsers || [];
    target.innerHTML = `<table class="ops-table"><caption class="sr-only">Workspace users and roles</caption><thead><tr><th scope="col">User</th><th scope="col">Email</th><th scope="col">Role</th><th scope="col">Status</th><th scope="col">MFA</th><th scope="col">Last active</th><th scope="col" aria-label="Actions"></th></tr></thead><tbody>${users.map(u => `<tr><td><strong>${escapeHtml(u.name)}</strong></td><td class="mono">${escapeHtml(u.email)}</td><td><select class="row-select" data-user-role="${escapeHtml(u.id)}" aria-label="Role for ${escapeHtml(u.name)}">${['administrator', 'security_engineer', 'incident_responder', 'threat_hunter', 'soc_analyst', 'executive'].map(r => `<option value="${r}" ${u.role === r ? 'selected' : ''}>${r.replace(/_/g, ' ')}</option>`).join('')}</select></td><td><span class="status-inline">${escapeHtml(u.status)}</span></td><td><span class="status-inline">${u.mfa_enabled ? 'enabled' : 'off'}</span></td><td class="mono">${escapeHtml(zTime(u.last_login_at))}</td><td><span class="row-actions"><button class="mini-action" type="button" data-user-action="${u.status === 'active' ? 'disable' : 'enable'}" data-user-id="${escapeHtml(u.id)}">${u.status === 'active' ? 'Disable' : 'Enable'}</button></span></td></tr>`).join('')}</tbody></table><div class="table-foot"><span class="muted">role and status changes are audited server-side</span></div>`;
    return;
  }
  target.innerHTML = `<table class="ops-table"><caption class="sr-only">Workspace users and roles</caption><thead><tr><th scope="col">User</th><th scope="col">Email</th><th scope="col">Role</th><th scope="col">Status</th><th scope="col">MFA</th><th scope="col">Last active</th><th scope="col" aria-label="Actions"></th></tr></thead><tbody>${demoUsers.map(u => `<tr><td><strong>${u.name}</strong></td><td class="mono">${u.email}</td><td>${u.role}</td><td><span class="status-inline">${u.status}</span></td><td><span class="status-inline">${u.mfa}</span></td><td class="mono">${u.last}</td><td><span class="row-actions"><button class="mini-action" type="button" tabindex="-1">Review</button></span></td></tr>`).join('')}</tbody></table>`;
}

export function renderAudit(kind) {
  const target = qs('#audit-table-container');
  if (['loading', 'empty', 'error'].includes(kind)) {
    target.innerHTML = kind === 'error' && state.lastAuditError ? errorMarkup(state.lastAuditError) : stateMarkup(kind);
    window.lucide?.createIcons();
    return;
  }
  if (state.mode === 'live') {
    const items = state.liveAudit?.items || [];
    const foot = state.auditTotal > items.length ? `<div class="table-foot"><span class="muted">showing ${items.length} of ${state.auditTotal} entries</span><button class="button ghost" type="button" data-action="audit-more">Load more</button></div>` : '';
    target.innerHTML = `<table class="ops-table"><caption class="sr-only">Audit trail, newest first</caption><thead><tr><th scope="col">Timestamp</th><th scope="col">Actor</th><th scope="col">Action</th><th scope="col">Entity</th><th scope="col" class="num">Correlation id</th></tr></thead><tbody>${items.map(a => `<tr><td class="mono">${escapeHtml(zTime(a.created_at))}</td><td>${escapeHtml(a.actor_email || a.actor_id || 'system')}</td><td class="mono">${escapeHtml(a.action)}</td><td class="mono">${escapeHtml(a.entity_type || '')}${a.entity_id ? `/${escapeHtml(String(a.entity_id).slice(0, 8))}` : ''}</td><td class="num mono">${escapeHtml(a.correlation_id || '—')}</td></tr>`).join('')}</tbody></table>${foot}`;
    return;
  }
  target.innerHTML = `<table class="ops-table"><caption class="sr-only">Audit trail, newest first</caption><thead><tr><th scope="col">Timestamp</th><th scope="col">Actor</th><th scope="col">Action</th><th scope="col">Object</th><th scope="col">Result</th><th scope="col">Correlation id</th></tr></thead><tbody>${((state.auditAction || state.auditActor) ? demoAudit.filter(a => (!state.auditAction || a.action.startsWith(state.auditAction)) && (!state.auditActor || (a.actor || '').toLowerCase().includes(state.auditActor.toLowerCase()))) : demoAudit).map(a => `<tr><td class="mono">${a.time}</td><td>${a.actor}</td><td class="mono">${a.action}</td><td class="mono">${a.object}</td><td>${a.result}</td><td class="mono">${a.cid}</td></tr>`).join('')}</tbody></table>`;
}

export function renderHealth(kind) {
  const target = qs('#health-content');
  if (['loading', 'empty', 'error'].includes(kind)) {
    target.innerHTML = stateMarkup(kind);
    window.lucide?.createIcons();
    return;
  }
  if (state.mode === 'live') {
    const health = state.liveHealth;
    const system = state.liveSystem;
    if (!health) return;
    const feeds = health.feeds || [];
    const okFeeds = feeds.filter(f => f.enabled && f.last_status === 'ok').length;
    qs('#hs-1').textContent = system?.status === 'ok' ? 'ok' : system?.status || '—';
    qs('#hs-2').textContent = system?.database || 'connected';
    qs('#hs-3').textContent = `${okFeeds}/${feeds.length}`;
    qs('#hs-4').textContent = Object.keys(system?.bus?.channels || {}).length;
    target.innerHTML = feeds.length ? feeds.map(f => {
      const status = feedStatus(f);
      return `<div class="service-row"><strong class="service-name"><span class="status-dot ${status === 'nominal' ? 'low-dot' : status === 'disabled' ? 'info-dot' : 'medium-dot'}"></span>${escapeHtml(f.name)}</strong><span>${status}</span><span class="mono">${f.enabled ? 'enabled' : 'disabled'}</span><span class="mono">${f.items_ingested} ingested</span></div>`;
    }).join('') : '<div class="service-row"><span class="muted">No feeds configured.</span></div>';
    return;
  }
  target.innerHTML = demoServices.map(s => `<div class="service-row"><strong class="service-name"><span class="status-dot ${s.status === 'nominal' ? 'low-dot' : 'medium-dot'}"></span>${s.name}</strong><span>${s.status}</span><span class="mono">${s.instances}</span><span class="mono">${s.p95}</span><span class="mono">${s.queue}</span></div>`).join('');
}
