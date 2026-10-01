// ThreatLens console — geographic heatmap: dot-density world map (FR-20).
// Uses country centroids projected onto an equirectangular graticule.
// Data source: GET /api/v1/dashboard/threat → country_density.

import { qs, escapeHtml } from './core.js';
import { api } from './core.js';

const W = 720, H = 360;
const CENTROIDS = {
  US:[-98,39],CN:[104,35],RU:[100,60],BR:[-52,-10],IN:[78,22],DE:[10,51],
  NL:[5,52],FR:[2,47],GB:[-2,54],UA:[32,49],VN:[106,16],IR:[53,32],
  RO:[25,46],KR:[127,36],TR:[35,39],ID:[113,-2],JP:[138,36],MX:[-102,23],
  NG:[8,9],ZA:[24,-29],AU:[134,-25],CA:[-106,56],SG:[104,1],TW:[121,24],
  HK:[114,22],PK:[69,30],BD:[90,24],PH:[122,13],TH:[101,15],MY:[102,4],
  EG:[30,27],SA:[45,24],AE:[54,24],IL:[35,31],PL:[19,52],SE:[15,62],
  ES:[-4,40],IT:[12,43],CH:[8,47],CZ:[15,50],BG:[25,43],MD:[28,47],
  BY:[28,53],KZ:[67,48],UZ:[64,41],AR:[-64,-34],CL:[-71,-32],
  CO:[-74,4],PE:[-76,-10],VE:[-66,7],NP:[84,28],LK:[81,7],MM:[96,21],
  KH:[105,12],MN:[103,47],KE:[38,-1],GH:[-1,8],MA:[-7,32],DZ:[3,28],
  LY:[17,27],SD:[30,15],ET:[39,9],TZ:[35,-6],UG:[32,1],CM:[12,6],
  CI:[-5,8],SN:[-14,14],ZA2:[28,-24],ZW:[30,-19],MZ:[35,-18],
  AO:[17,-12],CD:[23,-3],BF:[-2,12],ML:[-4,17],NE:[9,17],TD:[19,15],
  SO:[46,6],RW:[30,-2],BI:[30,-3],MW:[34,-14],ZM:[28,-14],
  BW:[24,-22],NA:[17,-22],GA:[11,-1],CG:[15,-3],CF:[21,7],
  CN2:[104,35],KP:[127,40],MO:[113,22],BN:[114,4],PG:[147,-6],
  FJ:[178,-18],NC:[165,-21],NZ:[172,-42],GL:[-42,72],IS:[-18,65],
  NO:[9,61],FI:[26,64],DK:[9,56],EE:[25,59],LV:[25,57],LT:[24,56],
  BE:[4,51],LU:[6,50],PT:[-8,39],IE:[-8,53],GR:[22,39],AL:[20,41],
  RS:[21,44],HR:[16,46],SI:[14,46],BA:[18,44],MK:[22,41],ME:[19,43],
  XK:[21,43],MD2:[28,47],AM:[45,40],GE:[43,42],AZ:[48,40],
  SY:[38,35],JO:[36,31],IQ:[44,33],KW:[48,29],QA:[51,25],
  BH:[50,26],OM:[57,21],YE:[48,15],AF:[66,34],TM:[59,39],
  TJ:[71,39],KG:[74,41],AF2:[66,34],BT:[90,27],MV:[73,3],
};

const NAMES = {
  US:'United States',CN:'China',RU:'Russia',BR:'Brazil',IN:'India',DE:'Germany',
  NL:'Netherlands',FR:'France',GB:'United Kingdom',UA:'Ukraine',VN:'Vietnam',
  IR:'Iran',RO:'Romania',KR:'South Korea',TR:'Türkiye',ID:'Indonesia',
  JP:'Japan',MX:'Mexico',NG:'Nigeria',ZA:'South Africa',AU:'Australia',
  CA:'Canada',SG:'Singapore',TW:'Taiwan',HK:'Hong Kong',PK:'Pakistan',
  BD:'Bangladesh',PH:'Philippines',TH:'Thailand',MY:'Malaysia',EG:'Egypt',
  SA:'Saudi Arabia',AE:'UAE',IL:'Israel',PL:'Poland',SE:'Sweden',
  ES:'Spain',IT:'Italy',CH:'Switzerland',NL2:'Netherlands',
};

const project = (lon, lat) => ({
  x: ((lon + 180) / 360) * W,
  y: ((90 - lat) / 180) * H,
});

const sizeFor = count => {
  if (count >= 50) return 14;
  if (count >= 20) return 10;
  if (count >= 10) return 7;
  if (count >= 5) return 5;
  return 3;
};

const colorFor = count => {
  if (count >= 50) return 'var(--critical)';
  if (count >= 20) return 'var(--high)';
  if (count >= 5) return 'var(--medium)';
  return 'var(--low)';
};

export function renderHeatmap(containerId, data) {
  const target = document.getElementById(containerId);
  if (!target) return;
  const density = data?.country_density || [];
  const maxCount = Math.max(1, ...density.map(d => d.count));

  const grat = [];
  for (let lon = -180; lon <= 180; lon += 30) {
    const x = ((lon + 180) / 360) * W;
    grat.push(`<line x1="${x}" y1="0" x2="${x}" y2="${H}" class="hm-grid"/>`);
  }
  for (let lat = -90; lat <= 90; lat += 30) {
    const y = ((90 - lat) / 180) * H;
    grat.push(`<line x1="0" y1="${y}" x2="${W}" y2="${y}" class="hm-grid"/>`);
  }
  grat.push(`<line x1="0" y1="${H / 2}" x2="${W}" y2="${H / 2}" class="hm-eq"/>`);

  const dots = density.map(d => {
    const c = CENTROIDS[d.country];
    if (!c) return '';
    const { x, y } = project(c[0], c[1]);
    const r = sizeFor(d.count);
    const fill = colorFor(d.count);
    const name = NAMES[d.country] || d.country;
    return `<circle cx="${x.toFixed(1)}" cy="${y.toFixed(1)}" r="${r}" fill="${fill}" opacity="0.75" class="hm-dot"><title>${escapeHtml(name)}: ${d.count} indicators</title></circle>`;
  }).filter(Boolean).join('');

  const legend = `<g class="hm-legend">
    <circle cx="${W - 130}" cy="${H - 24}" r="3" fill="var(--low)"/><text x="${W - 122}" y="${H - 21}" class="hm-legend-text">1–4</text>
    <circle cx="${W - 96}" cy="${H - 24}" r="5" fill="var(--medium)"/><text x="${W - 88}" y="${H - 21}" class="hm-legend-text">5–9</text>
    <circle cx="${W - 62}" cy="${H - 24}" r="7" fill="var(--high)"/><text x="${W - 52}" y="${H - 21}" class="hm-legend-text">10–19</text>
    <circle cx="${W - 28}" cy="${H - 24}" r="10" fill="var(--critical)"/><text x="${W - 16}" y="${H - 21}" class="hm-legend-text">50+</text>
  </g>`;

  target.innerHTML = `<svg viewBox="0 0 ${W} ${H}" class="heatmap-svg" role="img" aria-label="Geographic threat density heatmap">${grat.join('')}${dots}${legend}</svg>`;
}

export async function loadAndRenderHeatmap(containerId) {
  try {
    const data = await api('/dashboard/threat');
    renderHeatmap(containerId, data);
  } catch {
    const target = document.getElementById(containerId);
    if (target) target.innerHTML = '<div class="state-message"><strong>UNAVAILABLE</strong><span>Geographic data requires the live backend.</span></div>';
  }
}
