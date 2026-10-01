// ThreatLens console — widget library: show/hide + reorder Executive overview
// sections, persisted per user in localStorage (FR-22).

import { qs, qsa, escapeHtml } from './core.js';

export const WIDGET_IDS = [
  { id: 'threat-volume', label: 'Threat volume' },
  { id: 'top-threats', label: 'Top threats' },
  { id: 'throughput-panel', label: 'Alert throughput' },
  { id: 'target-panel', label: 'Targeted assets / IOC mix' },
  { id: 'heatmap-widget', label: 'Geographic heatmap' },
];

const STORAGE_KEY = 'threatlens.widgets';

function loadLayout() {
  try { return JSON.parse(localStorage.getItem(STORAGE_KEY) || '{}'); } catch { return {}; }
}

function saveLayout(layout) {
  localStorage.setItem(STORAGE_KEY, JSON.stringify(layout));
}

function getLayout() {
  try { return JSON.parse(localStorage.getItem(STORAGE_KEY) || '{}'); } catch { return {}; }
}

export function applyWidgetLayout() {
  const layout = getLayout();
  for (const w of WIDGET_IDS) {
    const el = qs(`[data-widget="${w.id}"]`);
    if (el) el.style.display = layout[w.id] === false ? 'none' : '';
  }
}

export function initWidgetPanel(open) {
  const panel = qs('#widget-panel');
  if (!panel) return;
  if (open) { panel.showModal(); return; }
  // Boot path: pre-render the checkbox list so the panel is ready when the
  // user clicks "Widgets" - never open the dialog here (it used to pop up on
  // every page load).
  const layout = getLayout();
  panel.innerHTML = `<div class="widget-panel-head"><p class="eyebrow">DASHBOARD LAYOUT</p><h2>Configure widgets</h2></div>`
    + WIDGET_IDS.map(w => {
      const checked = layout[w.id] !== false;
      return `<label class="widget-toggle"><input type="checkbox" data-widget-id="${w.id}" ${checked ? 'checked' : ''}><span>${escapeHtml(w.label)}</span></label>`;
    }).join('')
    + `<div class="widget-panel-foot"><button class="button ghost" type="button" data-action="close-widget-panel">Close</button><button class="button primary" type="button" data-action="save-widgets">Save layout</button></div>`;
  panel.querySelector('[data-action="close-widget-panel"]').addEventListener('click', () => panel.close());
  panel.querySelector('[data-action="save-widgets"]').addEventListener('click', () => {
    const newLayout = {};
    for (const w of WIDGET_IDS) {
      const cb = panel.querySelector(`input[data-widget-id="${w.id}"]`);
      newLayout[w.id] = cb ? cb.checked : true;
    }
    saveLayout(newLayout);
    applyWidgetLayout();
    panel.close();
  });
}
