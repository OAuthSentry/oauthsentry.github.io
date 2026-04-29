/* OAuthSentry - front-end logic
 *
 * Hash-based routing:
 *   #/search                                 main dashboard (default)
 *   #/search?q=...&cat=...&sev=...&svc=...   pre-filtered dashboard
 *   #/search?id=<appid>                      open detail panel for that app
 *   #/investigation/remediation
 *   #/investigation/forensics
 *   #/investigation/detections
 *   #/feeds
 *   #/methodology
 *
 * No frameworks, no build step. Vanilla JS + Papa Parse for CSVs.
 */

const $  = (sel, root = document) => root.querySelector(sel);
const $$ = (sel, root = document) => Array.from(root.querySelectorAll(sel));

// Map upstream label -> our label
const CATEGORY_MAP = {
  legitimate: 'compliance',
  compliance: 'compliance',
  risky:      'risky',
  malicious:  'malicious',
};

const SEVERITIES = ['critical', 'high', 'medium', 'low', 'info'];

const state = {
  apps: [],
  filtered: [],
  query: '',
  category: 'all',
  service: 'all',
  severity: 'all',
  source: 'all',
  year: 'all',
  hasComment: false,
  sources: [],
  // Lookup of source-domain -> friendly label, populated as data loads
  sourceLabels: new Map(),
  // Suppress hash updates while we are syncing UI from a hash change
  suppressHashUpdate: false,
};

/* ===== Routing ===== */

function parseHash() {
  // hash form: #/path?key=val&key=val
  const raw = (location.hash || '#/search').replace(/^#/, '');
  const [path, queryString] = raw.split('?');
  const params = new URLSearchParams(queryString || '');
  return { path: path || '/search', params };
}

function buildHash(path, params) {
  const qs = new URLSearchParams();
  if (params) {
    for (const [k, v] of Object.entries(params)) {
      if (v !== '' && v !== null && v !== undefined && v !== 'all' && v !== false) {
        qs.set(k, v);
      }
    }
  }
  const s = qs.toString();
  return '#' + path + (s ? '?' + s : '');
}

function pushState(path, params) {
  state.suppressHashUpdate = true;
  const h = buildHash(path, params);
  if (location.hash !== h) {
    history.replaceState(null, '', h);
  }
  state.suppressHashUpdate = false;
}

function setActiveTab(routePrefix) {
  $$('#topnav a[data-route]').forEach(a => {
    a.classList.toggle('active', a.dataset.route === routePrefix);
  });
}

function showPage(pageId) {
  ['page-search', 'page-investigation', 'page-feeds', 'page-triage', 'page-tokens', 'page-submit', 'page-api', 'page-methodology'].forEach(id => {
    const el = document.getElementById(id);
    if (el) el.hidden = (id !== pageId);
  });
  // scroll to top on page switch
  window.scrollTo({ top: 0, behavior: 'instant' });
}

function showInvestigationSub(sub) {
  ['sub-tradecraft', 'sub-remediation', 'sub-forensics', 'sub-detections', 'sub-hunting', 'sub-hardening', 'sub-google', 'sub-github'].forEach(id => {
    const el = document.getElementById(id);
    if (!el) return;
    el.hidden = (id !== `sub-${sub}`);
  });
  $$('#invest-subtabs a').forEach(a => {
    a.classList.toggle('active', a.dataset.route === `/investigation/${sub}`);
  });
}

function applyHash() {
  const { path, params } = parseHash();
  const segments = path.split('/').filter(Boolean);
  const top = segments[0] || 'search';

  if (top === 'investigation') {
    showPage('page-investigation');
    setActiveTab('/investigation');
    const sub = segments[1] || 'tradecraft';
    showInvestigationSub(sub);
    closeDetail();
    return;
  }
  if (top === 'feeds') {
    showPage('page-feeds');
    setActiveTab('/feeds');
    closeDetail();
    return;
  }
  if (top === 'triage') {
    showPage('page-triage');
    setActiveTab('/triage');
    closeDetail();
    return;
  }
  if (top === 'tokens') {
    showPage('page-tokens');
    setActiveTab('/tokens');
    closeDetail();
    return;
  }
  if (top === 'submit') {
    showPage('page-submit');
    setActiveTab('/submit');
    closeDetail();
    return;
  }
  if (top === 'api') {
    showPage('page-api');
    setActiveTab('/api');
    closeDetail();
    return;
  }
  if (top === 'methodology') {
    showPage('page-methodology');
    setActiveTab('/methodology');
    closeDetail();
    return;
  }

  // default: search
  showPage('page-search');
  setActiveTab('/search');

  // Sync filter UI from URL params (suppress hash writes while we do)
  state.suppressHashUpdate = true;
  state.query    = params.get('q')   || '';
  state.category = params.get('cat') || 'all';
  state.severity = params.get('sev') || 'all';
  state.service  = params.get('svc') || 'all';
  state.source   = params.get('src') || 'all';
  state.year     = params.get('yr')  || 'all';
  state.hasComment = params.get('notes') === '1';

  syncFilterUiToState();
  state.suppressHashUpdate = false;

  applyFilters();

  // Open detail panel if id is in URL
  const wantedId = params.get('id');
  if (wantedId) {
    const target = state.apps.find(a => a.appid.toLowerCase() === wantedId.toLowerCase());
    if (target) openDetail(target, /*viaHash*/true);
    else closeDetail();
  } else {
    closeDetail();
  }
}

function syncHashFromState() {
  if (state.suppressHashUpdate) return;
  const params = {
    q:     state.query,
    cat:   state.category,
    sev:   state.severity,
    svc:   state.service,
    src:   state.source,
    yr:    state.year,
    notes: state.hasComment ? '1' : '',
  };
  pushState('/search', params);
}

/* ===== Data loading ===== */

async function loadSources() {
  const res = await fetch('data/sources.json', { cache: 'no-cache' });
  if (!res.ok) throw new Error('failed to load data/sources.json');
  return res.json();
}

async function fetchCsv(url) {
  const res = await fetch(url, { cache: 'no-cache' });
  if (!res.ok) throw new Error(`fetch failed: ${url}`);
  return res.text();
}

function parseCsv(text) {
  const out = Papa.parse(text, { header: true, skipEmptyLines: true });
  return out.data;
}

function extractDomain(url) {
  try { return new URL(url).hostname.replace(/^www\./, ''); }
  catch { return null; }
}

function extractYear(comment) {
  // Look for "LastSeen=YYYY" or "first seen YYYY" or just a 20XX in the text
  if (!comment) return null;
  const m = comment.match(/(?:LastSeen|first\s+seen|first-seen|seen)\s*[=:]?\s*(20\d{2})/i)
         || comment.match(/\b(20\d{2})\b/);
  return m ? m[1] : null;
}

function normalizeRow(row, service) {
  const cat = (row.metadata_category || '').trim().toLowerCase();
  const refsRaw = (row.metadata_reference || '');
  // Split on " | " (mthcht convention) and " - " (mixed legacy entries)
  const refs = refsRaw
    .split(/\s*\|\s*|\s+-\s+/)
    .map(s => s.trim())
    .filter(s => s && /^https?:\/\//i.test(s));
  const domains = Array.from(new Set(refs.map(extractDomain).filter(Boolean)));
  return {
    appname:  (row.appname  || '').trim() || '(unnamed)',
    appid:    (row.appid    || '').trim(),
    category: CATEGORY_MAP[cat] || cat || 'unknown',
    severity: (row.metadata_severity || 'info').trim().toLowerCase(),
    comment:  (row.metadata_comment   || '').trim(),
    refs,
    refDomains: domains,
    year: extractYear(row.metadata_comment),
    service,
  };
}

async function loadService(svcEntry) {
  // svcEntry: { service, label, localMerged }
  // The site reads the MERGED per-service CSV that build_feeds.py produces,
  // not the per-source curator/fill files. The merged file is the source of
  // truth and already has the curated-wins merge applied.
  try {
    const text = await fetchCsv(svcEntry.localMerged);
    const rows = parseCsv(text).map(r => normalizeRow(r, svcEntry.service));
    console.info(`OAuthSentry: loaded ${rows.length} rows for ${svcEntry.service} from ${svcEntry.localMerged}`);
    return rows;
  } catch (e) {
    console.warn(`OAuthSentry: ${svcEntry.service} fetch failed for ${svcEntry.localMerged} - ${e.message}`);
    return [];
  }
}

// Collapse the role-based sources.json into one entry per service for the UI.
// Picks the friendliest service label: prefer a curated-source label stripped of the
// "mthcht/awesome-lists - " prefix, fall back to capitalized service id.
function collapseSourcesToServices(sources) {
  const SERVICE_LABELS = {
    entra:       'Microsoft Entra',
    google:      'Google Workspace',
    slack:       'Slack',
    github:      'GitHub',
    salesforce:  'Salesforce',
    okta:        'Okta',
  };
  const seen = new Map();
  for (const s of sources) {
    if (s.role === 'planned') continue;
    if (!s.service) continue;
    if (seen.has(s.service)) continue;
    seen.set(s.service, {
      service:      s.service,
      label:        SERVICE_LABELS[s.service] || s.service,
      localMerged:  `data/${s.service}/oauth_apps.csv`,
    });
  }
  return Array.from(seen.values());
}

/* ===== Rendering ===== */

function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, c => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'
  }[c]));
}

function highlight(text, query) {
  const safe = escapeHtml(text);
  if (!query) return safe;
  const q = query.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  return safe.replace(new RegExp(q, 'gi'), m => `<mark>${m}</mark>`);
}

function renderResults() {
  const container = $('#results');
  const meta = $('#results-meta');
  const list = state.filtered;
  if (!container || !meta) return;

  meta.innerHTML = `
    <span><strong>${list.length.toLocaleString()}</strong> result${list.length === 1 ? '' : 's'}
          <span style="color: var(--text-faint); margin-left: 6px;">(${describeFilters()})</span></span>
    <span><button class="reset" id="reset-filters" type="button">reset filters</button></span>
  `;
  const resetBtn = $('#reset-filters');
  if (resetBtn) resetBtn.addEventListener('click', resetAllFilters);

  if (!list.length) {
    container.innerHTML = `
      <div class="empty">
        <div class="glyph">&Oslash;</div>
        no matching applications<br>
        <span style="color: var(--text-faint); text-transform: none; letter-spacing: 0;
                     font-family: var(--font-body); font-size: 13px; margin-top: 8px; display: block;">
          try a partial app id, name, or threat-actor reference, or
          <button class="reset" type="button" onclick="resetAllFilters()" style="margin-left:6px;">reset filters</button>
        </span>
      </div>`;
    return;
  }

  const q = state.query.trim();

  container.innerHTML = list.map(app => `
    <div class="row ${app.category}" data-id="${escapeHtml(app.appid)}">
      <span class="badge ${app.category}">${app.category}</span>
      <div class="body">
        <div class="name">${highlight(app.appname, q)}</div>
        <div class="id">${highlight(app.appid, q)}</div>
      </div>
      <div class="right">
        <span class="service-tag">${escapeHtml(app.service)}</span>
        <span class="sev ${app.severity}">${escapeHtml(app.severity)}</span>
      </div>
    </div>
  `).join('');

  $$('#results .row').forEach(el => {
    el.addEventListener('click', () => {
      const id = el.dataset.id;
      const app = state.apps.find(a => a.appid === id);
      if (app) openDetail(app);
    });
  });
}

function describeFilters() {
  const parts = [];
  if (state.category !== 'all') parts.push(state.category);
  if (state.severity !== 'all') parts.push(`sev:${state.severity}`);
  if (state.service !== 'all')  parts.push(`svc:${state.service}`);
  if (state.source !== 'all')   parts.push(`src:${state.source}`);
  if (state.year !== 'all')     parts.push(`yr:${state.year}`);
  if (state.hasComment)         parts.push('notes-only');
  if (parts.length === 0)       parts.push('all');
  return parts.join(' - ');
}

function renderHeroStats() {
  const counts = state.apps.reduce((acc, a) => {
    acc.total++;
    acc[a.category] = (acc[a.category] || 0) + 1;
    return acc;
  }, { total: 0 });

  $('#stat-total').textContent      = counts.total.toLocaleString();
  $('#stat-compliance').textContent = (counts.compliance || 0).toLocaleString();
  $('#stat-risky').textContent      = (counts.risky      || 0).toLocaleString();
  $('#stat-malicious').textContent  = (counts.malicious  || 0).toLocaleString();
}

function renderSourceFilter() {
  const sourceEl = $('#source-filter');
  if (!sourceEl) return;
  const counts = new Map();
  state.apps.forEach(a => {
    a.refDomains.forEach(d => counts.set(d, (counts.get(d) || 0) + 1));
  });
  const sorted = Array.from(counts.entries())
    .sort((a, b) => b[1] - a[1])
    .slice(0, 30);
  const optionsHtml = ['<option value="all">all sources</option>']
    .concat(sorted.map(([d, n]) => `<option value="${escapeHtml(d)}">${escapeHtml(d)} (${n})</option>`));
  sourceEl.innerHTML = optionsHtml.join('');
}

function renderYearFilter() {
  const yearEl = $('#year-filter');
  if (!yearEl) return;
  const years = new Set();
  state.apps.forEach(a => { if (a.year) years.add(a.year); });
  const sorted = Array.from(years).sort().reverse();
  yearEl.innerHTML = ['<option value="all">any year</option>']
    .concat(sorted.map(y => `<option value="${y}">${y}</option>`)).join('');
}

/* ===== Filtering ===== */

function applyFilters() {
  const q = state.query.trim().toLowerCase();
  state.filtered = state.apps.filter(a => {
    if (state.category !== 'all' && a.category !== state.category) return false;
    if (state.severity !== 'all' && a.severity !== state.severity) return false;
    if (state.service  !== 'all' && a.service  !== state.service)  return false;
    if (state.source   !== 'all' && !a.refDomains.includes(state.source)) return false;
    if (state.year     !== 'all' && a.year !== state.year) return false;
    if (state.hasComment && !a.comment) return false;
    if (!q) return true;
    return (
      a.appid.toLowerCase().includes(q) ||
      a.appname.toLowerCase().includes(q) ||
      (a.comment || '').toLowerCase().includes(q)
    );
  });
  const catOrder = { malicious: 0, risky: 1, compliance: 2, unknown: 3 };
  const sevOrder = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
  state.filtered.sort((a, b) => {
    if (catOrder[a.category] !== catOrder[b.category]) return catOrder[a.category] - catOrder[b.category];
    if (sevOrder[a.severity] !== sevOrder[b.severity]) return sevOrder[a.severity] - sevOrder[b.severity];
    return a.appname.localeCompare(b.appname);
  });
  renderResults();
  syncHashFromState();
}

function resetAllFilters() {
  $('#search').value = '';
  state.query = '';
  state.category = 'all';
  state.severity = 'all';
  state.service = 'all';
  state.source = 'all';
  state.year = 'all';
  state.hasComment = false;
  syncFilterUiToState();
  applyFilters();
}
window.resetAllFilters = resetAllFilters;

function syncFilterUiToState() {
  // Search box
  const search = $('#search');
  if (search) search.value = state.query;
  // Category chips
  $$('.chip[data-category]').forEach(c => {
    c.classList.remove('on', 'compliance', 'risky', 'malicious');
    if (c.dataset.category === state.category) {
      c.classList.add('on');
      if (state.category !== 'all') c.classList.add(state.category);
    }
  });
  // Severity chips
  $$('.chip[data-severity]').forEach(c => {
    c.classList.remove('on', 'critical', 'high', 'medium', 'low', 'info');
    if (c.dataset.severity === state.severity) {
      c.classList.add('on');
      if (state.severity !== 'all') c.classList.add(state.severity);
    }
  });
  // Service chips
  $$('.chip[data-service]').forEach(c => {
    c.classList.toggle('on', c.dataset.service === state.service);
  });
  // Source select
  const srcSel = $('#source-filter');
  if (srcSel) srcSel.value = state.source;
  // Year select
  const yrSel = $('#year-filter');
  if (yrSel) yrSel.value = state.year;
  // Has comment toggle
  const hc = $('#has-comment');
  if (hc) {
    hc.dataset.toggle = state.hasComment ? 'on' : 'off';
    hc.classList.toggle('on', state.hasComment);
  }
}

/* ===== Detail panel ===== */

function openDetail(app, viaHash = false) {
  if (!app) return;

  const refs = app.refs.length
    ? app.refs.map(r => `<a class="ref-item" href="${escapeHtml(r)}" target="_blank" rel="noopener noreferrer">${escapeHtml(r)}</a>`).join('')
    : '<div class="ref-item" style="color: var(--text-faint);">no public reference recorded</div>';

  const comment = app.comment
    ? `<div class="comment">${escapeHtml(app.comment)}</div>`
    : '<div class="comment" style="color: var(--text-faint);">(no analyst notes)</div>';

  $('#panel').innerHTML = `
    <div class="panel-actions">
      <button class="copy-link" type="button" onclick="copyDeepLink('${escapeHtml(app.appid)}', this)">copy link</button>
      <button class="close" type="button" onclick="closeDetail()">esc</button>
    </div>
    <span class="cat-banner ${app.category}">${app.category}</span>
    <h2>${escapeHtml(app.appname)}</h2>
    <div class="id-block">
      <span>${escapeHtml(app.appid)}</span>
      <button class="copy-btn" type="button" onclick="copyAppId(this, '${escapeHtml(app.appid)}')">copy</button>
    </div>

    <div class="panel-grid">
      <div><div class="k">category</div><div class="v ${app.category}">${escapeHtml(app.category)}</div></div>
      <div><div class="k">severity</div><div class="v">${escapeHtml(app.severity)}</div></div>
      <div><div class="k">service</div><div class="v">${escapeHtml(app.service)}</div></div>
      <div><div class="k">last seen</div><div class="v">${escapeHtml(app.year || 'unknown')}</div></div>
    </div>

    <h3>Analyst notes</h3>
    ${comment}

    <h3>References</h3>
    <div class="refs">${refs}</div>
  `;
  $('#overlay').classList.add('open');
  document.body.style.overflow = 'hidden';

  // Update URL so the open panel is shareable
  if (!viaHash) {
    const params = {
      q: state.query, cat: state.category, sev: state.severity,
      svc: state.service, src: state.source, yr: state.year,
      notes: state.hasComment ? '1' : '',
      id: app.appid,
    };
    state.suppressHashUpdate = true;
    history.replaceState(null, '', buildHash('/search', params));
    state.suppressHashUpdate = false;
  }
}

function closeDetail() {
  const overlay = $('#overlay');
  if (!overlay || !overlay.classList.contains('open')) return;
  overlay.classList.remove('open');
  document.body.style.overflow = '';
  // Drop the id= param from the URL
  const { params } = parseHash();
  if (params.has('id')) {
    params.delete('id');
    state.suppressHashUpdate = true;
    history.replaceState(null, '', buildHash('/search', Object.fromEntries(params)));
    state.suppressHashUpdate = false;
  }
}

function copyAppId(btn, id) {
  navigator.clipboard.writeText(id).then(() => {
    btn.textContent = 'copied';
    btn.classList.add('copied');
    setTimeout(() => { btn.textContent = 'copy'; btn.classList.remove('copied'); }, 1500);
  });
}

function copyDeepLink(appid, btn) {
  const url = location.origin + location.pathname + buildHash('/search', { id: appid });
  navigator.clipboard.writeText(url).then(() => {
    btn.textContent = 'copied';
    btn.classList.add('copied');
    setTimeout(() => { btn.textContent = 'copy link'; btn.classList.remove('copied'); }, 1800);
  });
}

window.closeDetail   = closeDetail;
window.copyAppId     = copyAppId;
window.copyDeepLink  = copyDeepLink;

/* ===== Wiring ===== */

function wireUi() {
  const search = $('#search');
  const debounce = (fn, ms = 80) => {
    let t;
    return (...args) => { clearTimeout(t); t = setTimeout(() => fn(...args), ms); };
  };
  if (search) {
    search.addEventListener('input', debounce(e => {
      state.query = e.target.value;
      applyFilters();
    }));
  }

  const clearBtn = $('#clear');
  if (clearBtn) {
    clearBtn.addEventListener('click', () => {
      search.value = '';
      state.query = '';
      applyFilters();
      search.focus();
    });
  }

  const shareBtn = $('#share-btn');
  if (shareBtn) {
    shareBtn.addEventListener('click', () => {
      const url = location.origin + location.pathname + location.hash;
      navigator.clipboard.writeText(url).then(() => {
        shareBtn.textContent = 'copied';
        shareBtn.classList.add('copied');
        setTimeout(() => { shareBtn.textContent = 'share'; shareBtn.classList.remove('copied'); }, 1500);
      });
    });
  }

  $$('.chip[data-category]').forEach(chip => {
    chip.addEventListener('click', () => {
      state.category = chip.dataset.category;
      syncFilterUiToState();
      applyFilters();
    });
  });
  $$('.chip[data-severity]').forEach(chip => {
    chip.addEventListener('click', () => {
      state.severity = chip.dataset.severity;
      syncFilterUiToState();
      applyFilters();
    });
  });

  const sourceSel = $('#source-filter');
  if (sourceSel) {
    sourceSel.addEventListener('change', e => {
      state.source = e.target.value;
      applyFilters();
    });
  }
  const yearSel = $('#year-filter');
  if (yearSel) {
    yearSel.addEventListener('change', e => {
      state.year = e.target.value;
      applyFilters();
    });
  }
  const hc = $('#has-comment');
  if (hc) {
    hc.addEventListener('click', () => {
      state.hasComment = !state.hasComment;
      syncFilterUiToState();
      applyFilters();
    });
  }

  // Esc closes panel; '/' focuses search
  document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape') closeDetail();
    if (e.key === '/' && document.activeElement !== search) {
      e.preventDefault();
      if (search) search.focus();
    }
  });

  $('#overlay').addEventListener('click', (e) => {
    if (e.target.id === 'overlay') closeDetail();
  });

  // Hash routing
  window.addEventListener('hashchange', () => {
    if (state.suppressHashUpdate) return;
    applyHash();
  });

  // Copy buttons inside code blocks (Investigation page)
  document.addEventListener('click', (e) => {
    const btn = e.target.closest('.copy-snippet');
    if (!btn) return;
    const block = btn.closest('.code-block');
    const pre = block && block.querySelector('pre');
    if (!pre) return;
    const text = pre.textContent;
    navigator.clipboard.writeText(text).then(() => {
      const orig = btn.textContent;
      btn.textContent = 'copied';
      btn.classList.add('copied');
      setTimeout(() => { btn.textContent = orig; btn.classList.remove('copied'); }, 1500);
    });
  });

  // Top-nav and sub-nav navigation
  document.addEventListener('click', (e) => {
    const a = e.target.closest('a[data-route]');
    if (!a) return;
    // Let GitHub link behave normally
    if (a.target === '_blank') return;
  });
}

/* ===== Init ===== */

async function init() {
  wireUi();
  submitInit();
  tokensInit();

  try {
    const cfg = await loadSources();
    state.sources = cfg.sources || [];

    // Collapse role-based sources into one entry per service for the UI.
    const services = collapseSourcesToServices(state.sources);

    // service chips
    const servicesBar = $('#services-bar');
    if (servicesBar) {
      const html = ['<span class="filter-label">service</span>',
        '<button class="chip on" data-service="all">all</button>'];
      services.forEach(s => {
        html.push(`<button class="chip" data-service="${s.service}">${s.label}</button>`);
      });
      servicesBar.innerHTML = html.join('');
      $$('.chip[data-service]').forEach(chip => {
        chip.addEventListener('click', () => {
          state.service = chip.dataset.service;
          syncFilterUiToState();
          applyFilters();
        });
      });
    }

    const loaded = await Promise.all(services.map(loadService));
    state.apps = loaded.flat();

    // Build appid -> app index for fast lookup. Used by the token decoder
    // to cross-reference appid claims against the catalog without a linear scan.
    state.byId = {};
    for (const a of state.apps) {
      const id = (a.appid || '').trim().toLowerCase();
      if (id) state.byId[id] = a;
    }

    renderHeroStats();
    renderSourceFilter();
    renderYearFilter();

    // Now that data is loaded, sync any URL state that referenced filter values
    applyHash();
  } catch (e) {
    console.error(e);
    const r = $('#results');
    if (r) {
      r.innerHTML = `
        <div class="empty">
          <div class="glyph">!</div>
          failed to load data sources<br>
          <span style="color: var(--text-faint); text-transform: none; letter-spacing: 0;
                       font-family: var(--font-body); font-size: 13px; margin-top: 8px; display: block;">
            ${escapeHtml(e.message)}
          </span>
        </div>`;
    }
  }

  // Triage tool wiring (uses state.apps which is already loaded)
  wireTriage();
}

// =====================================================================
// TRIAGE TOOL
// =====================================================================
//
// Defender pastes raw audit logs or a list of app IDs; the page extracts the
// relevant identifiers, classifies them against state.apps, and renders the
// result grouped by category.

function detectTriageFormat(text) {
  const trimmed = text.trim();
  if (!trimmed) return { format: 'empty', label: 'paste input above' };

  // Try JSON first - structured audit logs in known shapes get the precise extractor
  try {
    const data = JSON.parse(trimmed);

    // M365 unified audit log (array or { value: [] })
    const m365Events = Array.isArray(data) ? data : (data.value || data.records || []);
    if (Array.isArray(m365Events) && m365Events.some(e => e?.OperationName === 'Consent to application')) {
      return { format: 'm365', label: 'M365 unified audit log (precise extract)' };
    }

    // Google Reports API (items[].events[].name == 'authorize')
    const googleItems = data.items || (Array.isArray(data) ? data : []);
    if (googleItems.some?.(i => i?.events?.some?.(e => e?.name === 'authorize' && e?.type === 'auth'))) {
      return { format: 'google', label: 'Google Reports API (precise extract)' };
    }

    // GitHub audit log (array of objects with action starting oauth_)
    if (Array.isArray(data) && data.some(e => typeof e?.action === 'string' && e.action.startsWith('oauth_'))) {
      return { format: 'github', label: 'GitHub audit log (precise extract)' };
    }

    // JSON we don't recognize - fall through to raw scan, which still works on the
    // serialized text. The user might have pasted Graph activity logs, Sentinel
    // alerts, raw Sigma matches, or any other JSON that contains app IDs in fields
    // we don't have a precise extractor for.
  } catch {
    // Not JSON
  }

  // If the input is a single line or contains commas/semicolons/newlines and no
  // surrounding noise, treat it as a deliberate list. Otherwise it's a raw dump.
  const lines = trimmed.split(/\r?\n/).filter(Boolean);
  const looksLikeList = lines.every(l => l.trim().length < 200 && !l.includes('{') && !l.includes(':'));
  if (looksLikeList && lines.length <= 200) {
    return { format: 'list', label: `plain list (${lines.length} line${lines.length === 1 ? '' : 's'})` };
  }
  return { format: 'raw', label: 'raw text - scanning for known app id patterns' };
}

// Patterns that match each service's app id shape. Anchored carefully to avoid
// matching parts of unrelated GUIDs / strings:
//   - Entra: standard 8-4-4-4-12 GUID. Word boundaries on both sides.
//   - Google: ^digits-alphanum.apps.googleusercontent.com$ (the full client_id).
//   - GitHub: app names are not extractable by regex (any string can be an app
//     name); only the JSON precise extractor covers GitHub. The raw scan reports
//     this limitation in the UI.
const RAW_PATTERNS = {
  entra:  /\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b/gi,
  google: /\b\d{6,}-[a-z0-9]+\.apps\.googleusercontent\.com\b/gi,
};

// Field names whose values are likely to actually BE OAuth app ids, not just
// look-alike GUIDs. Used by smart JSON walk to filter out tenantId, userId,
// correlationId, deviceId, wids and other noise GUIDs that share the same shape.
const APP_ID_FIELDS = new Set([
  'appid', 'appId', 'AppId', 'APPID', 'ApplicationId', 'application_id', 'applicationId',
  'clientid', 'clientId', 'client_id', 'ClientAppId',
  'ObjectId',                       // M365 Consent-to-application puts AppId here
  'ServicePrincipalAppId',
  'oauth_application_name',         // GitHub
  'TargetResourceAppId',            // some Sentinel exports
]);

function walkJsonForAppIds(node, out) {
  if (node === null || node === undefined) return;
  if (Array.isArray(node)) {
    for (const v of node) walkJsonForAppIds(v, out);
    return;
  }
  if (typeof node === 'object') {
    for (const [k, v] of Object.entries(node)) {
      if (APP_ID_FIELDS.has(k) && typeof v === 'string' && v) {
        out.add(v);
        continue;
      }
      walkJsonForAppIds(v, out);
    }
    return;
  }
  // primitives ignored
}

function scanRawText(text) {
  // Step 1: if the text is parseable as JSON, walk its tree pulling only values
  // from app-id-like fields. This eliminates false positives like tenantId,
  // userId, correlationId, deviceId, wids on Graph activity logs.
  let parsed = null;
  try { parsed = JSON.parse(text); } catch {}
  if (parsed !== null && typeof parsed === 'object') {
    const out = new Set();
    walkJsonForAppIds(parsed, out);
    if (out.size > 0) return Array.from(out);
    // JSON parsed but no app-id-like fields found - fall through to regex scan
    // so the user still gets something rather than an empty result.
  }

  // Step 2: regex scan over the raw text. Used for non-JSON paste (shell output,
  // chat threads, free-form notes) where the JSON walk doesn't apply.
  const ids = new Set();
  for (const re of Object.values(RAW_PATTERNS)) {
    const matches = text.match(re) || [];
    for (const m of matches) ids.add(m);
  }
  return Array.from(ids);
}

function extractTriageIds(text, format) {
  const trimmed = text.trim();
  if (!trimmed) return [];

  if (format === 'list') {
    return trimmed
      .split(/[\n,;]+/)
      .map(s => s.trim().replace(/^["']|["']$/g, ''))  // strip surrounding quotes
      .filter(Boolean);
  }

  if (format === 'raw') {
    return scanRawText(trimmed);
  }

  let data;
  try { data = JSON.parse(trimmed); } catch { return scanRawText(trimmed); }

  if (format === 'm365') {
    const events = Array.isArray(data) ? data : (data.value || data.records || []);
    return events
      .filter(e => e?.OperationName === 'Consent to application')
      .map(e => e.ObjectId)
      .filter(Boolean);
  }

  if (format === 'google') {
    const items = data.items || (Array.isArray(data) ? data : []);
    const ids = [];
    for (const item of items) {
      for (const ev of item.events || []) {
        if (ev.name !== 'authorize') continue;
        for (const p of ev.parameters || []) {
          if (p.name === 'client_id' && p.value) ids.push(p.value);
        }
      }
    }
    return ids;
  }

  if (format === 'github') {
    return data
      .filter(e => typeof e?.action === 'string' && (e.action.startsWith('oauth_authorization') || e.action.startsWith('oauth_access')))
      .map(e => e.oauth_application_name)
      .filter(Boolean);
  }

  return [];
}

function categorizeTriage(ids, allApps) {
  // Build a fast lookup keyed by lower-case appid
  const byId = new Map();
  for (const a of allApps) byId.set((a.appid || '').toLowerCase(), a);

  const buckets = { malicious: [], risky: [], compliance: [], unknown: [] };
  const seen = new Set();
  for (const raw of ids) {
    const id = String(raw).trim();
    if (!id) continue;
    const key = id.toLowerCase();
    if (seen.has(key)) continue;
    seen.add(key);

    const app = byId.get(key);
    if (app && buckets[app.category]) {
      buckets[app.category].push({ id, ...app });
    } else {
      buckets.unknown.push({ id });
    }
  }
  return buckets;
}

function renderTriageBucket(category, items) {
  if (!items.length) return '';
  const labels = {
    malicious:  'malicious - act now',
    risky:      'risky - investigate',
    unknown:    'unknown - not in catalog (often the most interesting bucket)',
    compliance: 'compliance - known-good',
  };
  const collapsed = (category === 'compliance' && items.length > 5) ? ' triage-collapsed' : '';
  const rows = items.map(it => {
    const refs = (it.references || []).slice(0, 4).map(r => {
      try { const u = new URL(r); return `<a href="${escapeHtml(r)}" target="_blank" rel="noopener">${escapeHtml(u.hostname.replace(/^www\./,''))}</a>`; }
      catch { return ''; }
    }).filter(Boolean).join('');
    const refsBlock = refs ? `<div class="triage-row-refs">${refs}</div>` : '';
    const commentBlock = it.comment ? `<span class="triage-row-comment">${escapeHtml(it.comment)}</span>` : '';
    const meta = it.service ? `${escapeHtml(it.service)}${it.severity ? ' / ' + escapeHtml(it.severity) : ''}` : 'no match';
    return `
      <div class="triage-row">
        <div class="triage-row-name">${escapeHtml(it.appname || it.id)}</div>
        <div>
          <div class="triage-row-id">${escapeHtml(it.id)}</div>
          ${commentBlock}
          ${refsBlock}
        </div>
        <div class="triage-row-meta">${meta}</div>
      </div>`;
  }).join('');
  return `
    <div class="triage-bucket ${category}${collapsed}" data-category="${category}">
      <div class="triage-bucket-header">
        <h4>${labels[category]}</h4>
        <span class="triage-bucket-count">${items.length}</span>
      </div>
      <div class="triage-bucket-body">${rows}</div>
    </div>`;
}

function buildTriageExportRows(buckets) {
  const rows = [];
  for (const cat of ['malicious', 'risky', 'unknown', 'compliance']) {
    for (const it of buckets[cat]) {
      rows.push({
        category: cat,
        appid:    it.id,
        appname:  it.appname || '',
        service:  it.service || '',
        severity: it.severity || '',
        comment:  it.comment || '',
        refs:     (it.references || []).join(' | '),
      });
    }
  }
  return rows;
}

function exportTriageCsv(rows) {
  const head = 'category,appid,appname,service,severity,comment,references';
  const body = rows.map(r =>
    [r.category, r.appid, r.appname, r.service, r.severity, r.comment, r.refs]
      .map(v => `"${String(v).replace(/"/g, '""')}"`).join(',')
  ).join('\n');
  return head + '\n' + body;
}

function exportTriageMd(rows) {
  if (!rows.length) return '_(no rows)_\n';
  let out = '| category | appid | appname | service | severity | comment |\n';
  out += '|---|---|---|---|---|---|\n';
  for (const r of rows) {
    out += `| ${r.category} | \`${r.appid}\` | ${r.appname} | ${r.service} | ${r.severity} | ${r.comment.replace(/\|/g, '\\|').slice(0, 200)} |\n`;
  }
  return out;
}

function copyToClipboard(text) {
  navigator.clipboard.writeText(text).catch(() => {
    // Fallback for older browsers
    const ta = document.createElement('textarea');
    ta.value = text;
    document.body.appendChild(ta);
    ta.select();
    document.execCommand('copy');
    document.body.removeChild(ta);
  });
}

function wireTriage() {
  const input    = document.getElementById('triage-input');
  const hint     = document.getElementById('triage-format-hint');
  const summary  = document.getElementById('triage-summary');
  const results  = document.getElementById('triage-results');
  const exportEl = document.getElementById('triage-export');
  if (!input) return;  // page not present

  let lastBuckets = null;

  function updateHint() {
    const det = detectTriageFormat(input.value);
    hint.textContent = det.label;
    hint.classList.toggle('detected', det.format !== 'empty' && det.format !== 'list');
  }

  function runTriage() {
    const det = detectTriageFormat(input.value);
    const ids = extractTriageIds(input.value, det.format);
    if (!ids.length) {
      results.innerHTML = '';
      summary.textContent = 'No identifiers found in input.';
      exportEl.hidden = true;
      lastBuckets = null;
      return;
    }
    const buckets = categorizeTriage(ids, state.apps || []);
    lastBuckets = buckets;
    const counts = `${buckets.malicious.length} malicious / ${buckets.risky.length} risky / ${buckets.unknown.length} unknown / ${buckets.compliance.length} compliance`;
    summary.innerHTML = `Triaged <strong>${ids.length}</strong> identifier${ids.length === 1 ? '' : 's'} (input: ${escapeHtml(det.label)}). ${counts}.`;
    const order = ['malicious', 'risky', 'unknown', 'compliance'];
    results.innerHTML = order.map(c => renderTriageBucket(c, buckets[c])).join('');
    exportEl.hidden = false;
    // Hook bucket header collapse toggles
    results.querySelectorAll('.triage-bucket-header').forEach(h => {
      h.addEventListener('click', () => h.parentElement.classList.toggle('triage-collapsed'));
    });
  }

  input.addEventListener('input', updateHint);

  document.getElementById('triage-run').addEventListener('click', runTriage);
  document.getElementById('triage-clear').addEventListener('click', () => {
    input.value = '';
    updateHint();
    results.innerHTML = '';
    summary.textContent = 'Paste input and click Triage to begin.';
    exportEl.hidden = true;
    lastBuckets = null;
  });
  document.getElementById('triage-sample').addEventListener('click', () => {
    input.value = [
      '# A mix of real catalog entries (compliance + malicious) and made-up IDs (unknown)',
      '00000003-0000-0000-c000-000000000000',           // Microsoft Graph - compliance
      'c5393580-f805-4401-95e8-94b7a6ef2fc2',           // Office 365 Management APIs - compliance
      '1084253493764-ipb2ntp4jb4rmqc76jp7habdrhfdus3q.apps.googleusercontent.com', // Drift Email - malicious
      'Heroku Dashboard',                                // GitHub - malicious
      '00000000-1111-2222-3333-444455556666',           // unknown - made up GUID
    ].join('\n');
    updateHint();
    runTriage();
  });

  document.getElementById('triage-export-csv').addEventListener('click', () => {
    if (!lastBuckets) return;
    copyToClipboard(exportTriageCsv(buildTriageExportRows(lastBuckets)));
    flashButton(document.getElementById('triage-export-csv'));
  });
  document.getElementById('triage-export-md').addEventListener('click', () => {
    if (!lastBuckets) return;
    copyToClipboard(exportTriageMd(buildTriageExportRows(lastBuckets)));
    flashButton(document.getElementById('triage-export-md'));
  });

  // Add a small CSS rule for collapse via JS - keeps the css file tidy
  const style = document.createElement('style');
  style.textContent = '.triage-bucket.triage-collapsed .triage-bucket-body { display:none; }';
  document.head.appendChild(style);

  updateHint();
}

function flashButton(btn) {
  const original = btn.textContent;
  btn.textContent = 'copied';
  btn.disabled = true;
  setTimeout(() => { btn.textContent = original; btn.disabled = false; }, 1200);
}

// ============================================================
// Submit page - form validation + three-channel submission
// (GitHub issue, CSV download, mailto)
// ============================================================

const SUBMIT_REPO = 'oauthsentry/oauthsentry.github.io';
const SUBMIT_EMAIL = 'submissions@oauthsentry.github.io';

const APPID_PATTERNS = {
  entra:  /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i,
  google: /^\d{6,}-[a-z0-9]+\.apps\.googleusercontent\.com$/i,
  // GitHub OAuth apps are matched by name, not numeric id - any non-empty
  // string up to 100 chars is acceptable as a submission.
  github: /^.{1,100}$/,
};
const APPID_HINTS = {
  entra:  '36-char GUID like c5393580-f805-4401-95e8-94b7a6ef2fc2',
  google: 'Format: digits-alphanum.apps.googleusercontent.com',
  github: 'OAuth Application Name as shown in audit logs (e.g. "Heroku Dashboard")',
};

function submitGetForm() {
  return {
    service:    document.querySelector('#submit-form input[name="service"]:checked')?.value || 'entra',
    appid:      (document.getElementById('submit-appid')?.value || '').trim(),
    appname:    (document.getElementById('submit-appname')?.value || '').trim(),
    category:   document.querySelector('#submit-form input[name="category"]:checked')?.value || '',
    severity:   document.querySelector('#submit-form input[name="severity"]:checked')?.value || 'info',
    comment:    (document.getElementById('submit-comment')?.value || '').trim(),
    references: (document.getElementById('submit-references')?.value || '').trim(),
    source:     document.getElementById('submit-source')?.value || '',
    credit:     (document.getElementById('submit-credit')?.value || '').trim(),
  };
}

function submitValidate(data) {
  const errors = {};

  if (!data.appid) {
    errors.appid = 'App ID is required.';
  } else {
    const re = APPID_PATTERNS[data.service];
    if (re && !re.test(data.appid)) {
      errors.appid = `Doesn\u2019t match the expected ${data.service} format. ${APPID_HINTS[data.service]}`;
    }
  }

  if (!data.appname) {
    errors.appname = 'App name is required.';
  }

  if (!data.category) {
    errors.category = 'Category is required.';
  }

  // Sanity: malicious + info severity is almost always wrong; nudge the user
  if (data.category === 'malicious' && data.severity === 'info') {
    errors.severity = 'Malicious entries should not be info severity. Pick at least medium - critical is most common.';
  }
  if (data.category === 'compliance' && (data.severity === 'high' || data.severity === 'critical')) {
    errors.severity = 'Compliance entries are pre-vetted legitimate apps; severity is almost always info or low.';
  }

  if (!data.comment || data.comment.length < 30) {
    errors.comment = 'Comment must be at least 30 characters and explain why the app is in this category.';
  }

  if (!data.references) {
    errors.references = 'At least one public reference URL is required.';
  } else {
    const lines = data.references.split(/\r?\n/).map(s => s.trim()).filter(Boolean);
    const bad = lines.filter(l => !/^https?:\/\/.+/.test(l));
    if (bad.length > 0) {
      errors.references = `${bad.length} entry${bad.length === 1 ? '' : 'ies'} doesn\u2019t look like a URL. Each line must start with http:// or https://`;
    }
  }

  return errors;
}

function submitShowErrors(errors) {
  for (const field of ['appid', 'appname', 'category', 'severity', 'comment', 'references']) {
    const el = document.getElementById(`submit-${field}-error`);
    if (!el) continue;
    if (errors[field]) {
      el.textContent = errors[field];
      el.hidden = false;
    } else {
      el.textContent = '';
      el.hidden = true;
    }
  }
  // Surface category/severity errors in the comment-error slot since those
  // radio groups don't have their own error placeholder
  if (errors.category || errors.severity) {
    const status = document.getElementById('submit-status');
    if (status) {
      status.className = 'submit-status error';
      status.textContent = errors.category || errors.severity;
      status.hidden = false;
    }
  } else {
    const status = document.getElementById('submit-status');
    if (status && status.classList.contains('error')) {
      status.hidden = true;
    }
  }
}

function submitBuildIssueBody(data) {
  const refs = data.references.split(/\r?\n/).map(s => s.trim()).filter(Boolean);
  const lines = [
    '## OAuth catalog submission',
    '',
    '**Service:** ' + data.service,
    '**App ID:** `' + data.appid + '`',
    '**App name:** ' + data.appname,
    '**Category:** ' + data.category,
    '**Severity:** ' + data.severity,
    '',
    '### Comment',
    data.comment,
    '',
    '### References',
    ...refs.map(r => '- ' + r),
    '',
  ];
  if (data.source)  lines.push('**Source:** ' + data.source);
  if (data.credit)  lines.push('**Credit:** ' + data.credit);
  lines.push('');
  lines.push('---');
  lines.push('Submitted via the OAuthSentry submission form.');
  return lines.join('\n');
}

function submitBuildIssueUrl(data) {
  const title = `[submission] ${data.category}: ${data.appname || data.appid}`;
  const body = submitBuildIssueBody(data);
  const url = `https://github.com/${SUBMIT_REPO}/issues/new?` +
    `title=${encodeURIComponent(title)}` +
    `&body=${encodeURIComponent(body)}` +
    `&labels=${encodeURIComponent('submission')}`;
  return url;
}

function submitBuildCsvRow(data) {
  // CSV-escape: wrap in quotes, double internal quotes
  const esc = (s) => {
    const v = String(s || '');
    if (/[",\n]/.test(v)) return '"' + v.replace(/"/g, '""') + '"';
    return v;
  };
  // Match the catalog schema: appname, appid, metadata_category,
  // metadata_severity, metadata_comment, metadata_reference
  const refs = data.references.split(/\r?\n/).map(s => s.trim()).filter(Boolean).join(' | ');
  return [
    esc(data.appname),
    esc(data.appid),
    esc(data.category),
    esc(data.severity),
    esc(data.comment),
    esc(refs),
  ].join(',');
}

function submitDownloadCsv(data) {
  const header = 'appname,appid,metadata_category,metadata_severity,metadata_comment,metadata_reference';
  const row = submitBuildCsvRow(data);
  const content = header + '\n' + row + '\n';
  const blob = new Blob([content], { type: 'text/csv;charset=utf-8' });
  const url = URL.createObjectURL(blob);
  const safeId = (data.appid || 'submission').replace(/[^a-z0-9-]/gi, '_').slice(0, 40);
  const a = document.createElement('a');
  a.href = url;
  a.download = `oauthsentry-submission-${safeId}.csv`;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

function submitMailto(data) {
  const subject = `[submission] ${data.category}: ${data.appname || data.appid}`;
  const body = submitBuildIssueBody(data);
  // mailto has practical length limits around 2000 chars across browsers/clients;
  // truncate the body if needed and tell the user.
  const MAX = 1800;
  let truncated = body;
  let note = '';
  if (body.length > MAX) {
    truncated = body.slice(0, MAX) + '\n\n[truncated for mailto length limit; please paste the full content into the email]';
    note = ' (body truncated due to mailto length limits - please paste the full submission into the email body manually)';
  }
  const url = `mailto:${SUBMIT_EMAIL}?subject=${encodeURIComponent(subject)}&body=${encodeURIComponent(truncated)}`;
  window.location.href = url;
  return note;
}

function submitStatus(msg, kind) {
  const status = document.getElementById('submit-status');
  if (!status) return;
  status.className = 'submit-status ' + (kind || '');
  status.textContent = msg;
  status.hidden = !msg;
}

function submitInit() {
  // Update the appid hint when service changes
  document.querySelectorAll('#submit-form input[name="service"]').forEach(radio => {
    radio.addEventListener('change', () => {
      const v = document.querySelector('#submit-form input[name="service"]:checked')?.value || 'entra';
      const hint = document.getElementById('submit-appid-hint');
      if (hint) hint.textContent = APPID_HINTS[v] || '';
    });
  });

  const handleSubmit = (channel) => {
    const data = submitGetForm();
    const errors = submitValidate(data);
    submitShowErrors(errors);
    if (Object.keys(errors).length > 0) {
      submitStatus('Please fix the validation errors above.', 'error');
      return;
    }
    submitStatus('', '');

    if (channel === 'issue') {
      const url = submitBuildIssueUrl(data);
      window.open(url, '_blank', 'noopener');
      submitStatus('Opened GitHub in a new tab. Review the prefilled issue and click "Submit new issue" to send.', 'success');
    } else if (channel === 'csv') {
      submitDownloadCsv(data);
      submitStatus('CSV downloaded. Append the row to the appropriate file in data/{entra,google,github}/ and open a pull request.', 'success');
    } else if (channel === 'mailto') {
      const note = submitMailto(data);
      submitStatus('Opening your default email client...' + note, 'success');
    }
  };

  document.getElementById('submit-btn-issue')?.addEventListener('click', () => handleSubmit('issue'));
  document.getElementById('submit-btn-csv')?.addEventListener('click', () => handleSubmit('csv'));
  document.getElementById('submit-btn-mailto')?.addEventListener('click', () => handleSubmit('mailto'));
}

// Hook submit init into the existing init flow - see init() above
document.addEventListener('DOMContentLoaded', init);

// ============================================================
// Token decoder - parse + annotate Microsoft Entra JWTs
// ============================================================

const TOKENS = {
  widsRef: null,        // entra_role_wids.json
  appsRef: null,        // entra_known_apps.json
  claimsRef: null,      // entra_claims_reference.json
  scopesRef: null,      // entra_high_risk_scopes.json
  loaded: false,
};

async function tokensLoadRefs() {
  if (TOKENS.loaded) return;
  try {
    const [wids, apps, claims, scopes] = await Promise.all([
      fetch('assets/data/entra_role_wids.json').then(r => r.json()),
      fetch('assets/data/entra_known_apps.json').then(r => r.json()),
      fetch('assets/data/entra_claims_reference.json').then(r => r.json()),
      fetch('assets/data/entra_high_risk_scopes.json').then(r => r.json()),
    ]);
    TOKENS.widsRef = wids;
    TOKENS.appsRef = apps;
    TOKENS.claimsRef = claims;
    TOKENS.scopesRef = scopes;
    TOKENS.loaded = true;
  } catch (e) {
    console.error('Failed to load decoder reference data:', e);
  }
}

// Base64URL -> string
function tokensB64UrlDecode(seg) {
  // Convert base64url to base64 + pad
  let s = seg.replace(/-/g, '+').replace(/_/g, '/');
  while (s.length % 4) s += '=';
  // Use atob, then handle UTF-8
  try {
    const binary = atob(s);
    // Convert binary string to UTF-8
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
    return new TextDecoder('utf-8').decode(bytes);
  } catch (e) {
    throw new Error('Base64 decode failed: ' + e.message);
  }
}

function tokensParseInput(raw) {
  let s = (raw || '').trim();
  if (!s) throw new Error('Empty input. Paste a JWT in the box above.');
  // Strip 'Authorization: Bearer ' or 'Bearer ' prefix
  s = s.replace(/^(Authorization:\s*)?Bearer\s+/i, '').trim();
  // Strip surrounding quotes (when copied from JSON or .NET output)
  s = s.replace(/^["'`]+|["'`]+$/g, '').trim();
  // Drop trailing semicolons / commas (when copied from a header line)
  s = s.replace(/[;,]+$/g, '').trim();
  // Drop any whitespace inside (some copies wrap across lines)
  s = s.replace(/\s/g, '');
  const parts = s.split('.');
  if (parts.length < 2) {
    throw new Error('Not a JWT. Expected three dot-separated segments (header.payload.signature). Got ' + parts.length + ' segment(s).');
  }
  if (parts.length > 5) {
    throw new Error('Too many segments (' + parts.length + '). A JWT has 3; a JWE (encrypted token) has 5. Either way, this looks malformed.');
  }
  // JWE has 5 segments and uses different header alg/enc. We don't support JWE decryption.
  if (parts.length === 5) {
    throw new Error('This looks like a JWE (encrypted token, 5 segments). The decoder only handles JWS (3 segments). JWEs require the recipient private key to decrypt - decrypt elsewhere then paste the inner JWT.');
  }
  let headerStr, payloadStr;
  try {
    headerStr = tokensB64UrlDecode(parts[0]);
  } catch (e) {
    throw new Error('Header segment (segment 1) is not valid base64url. ' + e.message);
  }
  try {
    payloadStr = tokensB64UrlDecode(parts[1]);
  } catch (e) {
    throw new Error('Payload segment (segment 2) is not valid base64url. ' + e.message);
  }
  let header, payload;
  try { header = JSON.parse(headerStr); }
  catch (e) { throw new Error('Header is not valid JSON: ' + e.message); }
  try { payload = JSON.parse(payloadStr); }
  catch (e) { throw new Error('Payload is not valid JSON: ' + e.message); }
  return { header, payload, raw: s, segments: parts.length };
}

function tokensFmtTs(ts) {
  if (typeof ts !== 'number' || !isFinite(ts)) return String(ts);
  if (ts < 1000000000) return String(ts) + ' (not a unix timestamp?)';
  const d = new Date(ts * 1000);
  return d.toISOString().replace('T', ' ').replace('.000Z', 'Z');
}
function tokensFmtDuration(seconds) {
  const abs = Math.abs(seconds);
  if (abs < 60)         return seconds + 's';
  if (abs < 3600)       return Math.round(seconds / 60) + 'm';
  if (abs < 86400)      return (seconds / 3600).toFixed(1) + 'h';
  return (seconds / 86400).toFixed(1) + 'd';
}

// Returns an annotation object for one claim:
// { value, displayValue, severity: ok|info|warn|critical, note, html (optional) }
function tokensAnnotateClaim(name, value, payload) {
  const ref = TOKENS.claimsRef[name];
  const baseDescription = ref?.description || null;
  const defenderNote    = ref?.defender_note || null;

  const annot = {
    name,
    value,
    displayValue: typeof value === 'object' ? JSON.stringify(value) : String(value),
    severity: 'ok',
    description: baseDescription,
    defenderNote: defenderNote,
    extras: [],   // additional bullets / cross-references
  };

  // Per-claim deep enrichment
  switch (name) {
    case 'appid':
    case 'azp': {
      const v = String(value || '').toLowerCase();
      const known   = TOKENS.appsRef[v];
      const catalog = state.byId && state.byId[v];

      // Priority order:
      //   1. OAuthSentry catalog (curated, daily-refreshed) - if present, this is the
      //      authoritative source. Show its name + category + severity.
      //   2. Well-known first-party reference (FOCI list + adjacent) - shown as
      //      supplementary info even when catalog matches (FOCI flag is useful).
      //   3. Neither - flag as unknown for investigation.
      if (catalog) {
        const cat = catalog.metadata_category || 'unknown';
        const sev = catalog.metadata_severity || 'info';
        const appName = catalog.appname || v;
        if (cat === 'malicious') {
          annot.severity = 'critical';
          annot.extras.push(`<strong style="color: var(--accent, #c44);">OAuthSentry catalog: <em>${escapeHtml(appName)}</em> &mdash; MALICIOUS (${escapeHtml(sev)})</strong>`);
        } else if (cat === 'risky') {
          annot.severity = annot.severity === 'critical' ? 'critical' : 'warn';
          annot.extras.push(`<strong>OAuthSentry catalog: <em>${escapeHtml(appName)}</em> &mdash; risky (${escapeHtml(sev)})</strong>`);
        } else if (cat === 'compliance') {
          annot.extras.push(`OAuthSentry catalog: <em>${escapeHtml(appName)}</em> &mdash; compliance / pre-vetted (${escapeHtml(sev)})`);
        } else {
          annot.extras.push(`OAuthSentry catalog: <em>${escapeHtml(appName)}</em> (${escapeHtml(cat)}, ${escapeHtml(sev)})`);
        }
        if (catalog.metadata_comment) {
          annot.extras.push(escapeHtml(String(catalog.metadata_comment).slice(0, 240)));
        }
        // Add the FOCI flag as supplementary if present in known-apps too
        if (known?.foci) {
          annot.extras.push('<strong>FOCI client</strong> &mdash; refresh tokens are family refresh tokens (FRTs) redeemable across all 11+ FOCI clients. See <a href="#/investigation/tradecraft" data-route="/investigation">Tradecraft tab</a>.');
          if (annot.severity === 'ok') annot.severity = 'warn';
        }
      } else if (known) {
        // Known Microsoft first-party but not in OAuthSentry catalog - typical for
        // resource appids and the few first-party clients we curate explicitly.
        annot.extras.push(`<strong>${escapeHtml(known.name)}</strong> (${escapeHtml(known.publisher)})${known.foci ? ' &mdash; <strong>FOCI client</strong>' : ''}`);
        annot.extras.push(escapeHtml(known.notes));
        if (known.foci) annot.severity = 'warn';
      } else {
        annot.severity = 'info';
        annot.extras.push('Not in OAuthSentry catalog and not a known Microsoft first-party client. If unfamiliar, investigate the consent grant that created it. Search this id at <a href="#/search?q=' + encodeURIComponent(v) + '" data-route="/search">/search</a> or check the <a href="#/submit" data-route="/submit">Submit form</a> if you want to propose adding it to the catalog.');
      }
      break;
    }
    case 'wids': {
      const arr = Array.isArray(value) ? value : (value ? [value] : []);
      const decoded = [];
      let hasPriv = false;
      let hasNonDefault = false;
      for (const w of arr) {
        const wl = String(w).toLowerCase();
        const role = TOKENS.widsRef[wl];
        if (role) {
          if (role.privileged) hasPriv = true;
          if (!role.synthetic) hasNonDefault = true;
          decoded.push(`<code>${escapeHtml(wl.slice(0, 8))}...</code> &rarr; <strong>${escapeHtml(role.name)}</strong>${role.privileged ? ' <em style="color: var(--accent);">[privileged]</em>' : ''}`);
        } else {
          decoded.push(`<code>${escapeHtml(wl)}</code> &rarr; (unknown role - may be custom or new built-in)`);
        }
      }
      if (decoded.length) annot.extras.push(...decoded);
      if (hasPriv) {
        annot.severity = 'critical';
        annot.extras.push('<strong>Token holder has at least one privileged Entra role.</strong> A stolen token from this user is high-impact - revoke immediately and force re-authentication.');
      } else if (hasNonDefault) {
        annot.severity = 'warn';
      }
      break;
    }
    case 'scp': {
      const scopes = String(value || '').split(/\s+/).filter(Boolean);
      let maxRisk = 'low';
      const flagged = [];
      for (const s of scopes) {
        const sl = s.toLowerCase();
        const sref = TOKENS.scopesRef[sl];
        if (sref) {
          flagged.push(`<code>${escapeHtml(s)}</code> &mdash; <strong>${escapeHtml(sref.risk)}</strong>: ${escapeHtml(sref.note)}`);
          const risk = sref.risk;
          if (risk === 'critical') maxRisk = 'critical';
          else if (risk === 'high' && maxRisk !== 'critical') maxRisk = 'high';
          else if (risk === 'medium' && maxRisk !== 'critical' && maxRisk !== 'high') maxRisk = 'medium';
        }
      }
      annot.extras.push(`Scope count: <strong>${scopes.length}</strong>`);
      if (scopes.length > 20) {
        annot.extras.push('<strong>&gt;20 scopes is anomalous</strong> on a delegated FOCI token. See OAuthSentry Detection 10.');
        annot.severity = 'warn';
      }
      if (flagged.length) annot.extras.push(...flagged);
      if (maxRisk === 'critical') annot.severity = 'critical';
      else if (maxRisk === 'high' && annot.severity === 'ok') annot.severity = 'warn';
      annot.extras.push('Cross-reference each scope at <a href="https://graphpermissions.merill.net/" target="_blank" rel="noopener">graphpermissions.merill.net</a> for exact endpoint coverage.');
      break;
    }
    case 'roles': {
      const roles = String(value || '').split(/\s+/).filter(Boolean);
      const flagged = [];
      let maxRisk = 'low';
      for (const r of roles) {
        const rl = r.toLowerCase();
        const sref = TOKENS.scopesRef[rl];
        if (sref) {
          flagged.push(`<code>${escapeHtml(r)}</code> &mdash; <strong>${escapeHtml(sref.risk)}</strong>: ${escapeHtml(sref.note)}`);
          if (sref.risk === 'critical') maxRisk = 'critical';
          else if (sref.risk === 'high' && maxRisk !== 'critical') maxRisk = 'high';
        }
      }
      annot.extras.push(`Application permission count: <strong>${roles.length}</strong>`);
      annot.extras.push('On <strong>app-only tokens</strong>, these are the application permissions the SP can exercise (no user gating). On delegated tokens, these are app-role assignments.');
      if (flagged.length) annot.extras.push(...flagged);
      if (maxRisk === 'critical') annot.severity = 'critical';
      else if (maxRisk === 'high' && annot.severity === 'ok') annot.severity = 'warn';
      break;
    }
    case 'idtyp': {
      const v = String(value).toLowerCase();
      if (v === 'app') {
        annot.extras.push('<strong>App-only token</strong>. The principal is the service principal, not a user. Pivot on <code>servicePrincipalId</code>, not <code>userId</code>.');
      } else if (v === 'user') {
        annot.extras.push('<strong>Delegated token</strong>. Acting on behalf of a user. Pivot on <code>userId</code>.');
      } else if (v === 'device') {
        annot.extras.push('<strong>Device token</strong>. Issued to a registered device.');
      }
      break;
    }
    case 'iat':
    case 'nbf':
    case 'exp': {
      annot.displayValue = `${value} &mdash; ${tokensFmtTs(value)}`;
      if (name === 'exp' && payload.iat) {
        const lifetime = value - payload.iat;
        annot.extras.push(`Token lifetime: <strong>${tokensFmtDuration(lifetime)}</strong>`);
        if (lifetime > 86400 - 3600) {
          annot.severity = 'critical';
          annot.extras.push('<strong>Lifetime &gt; 23h</strong> - at the Configurable Token Lifetime (CTL) maximum. This significantly extends post-compromise exposure. See Hardening Control 6.');
        } else if (lifetime > 7200) {
          annot.severity = 'warn';
          annot.extras.push('<strong>Lifetime &gt; 2h</strong> - indicates a CTL policy. If this is a non-CAE token (no <code>xms_cc:cp1</code>) the long lifetime is worth a documented business reason.');
        } else if (lifetime > 3600 + 1800) {
          annot.extras.push('Lifetime is in the typical CAE-aware range (60-90 min for non-CAE; 24-28h for CAE). Check <code>xms_cc</code> for CAE capability.');
        }
      }
      if (name === 'iat') {
        const ageNow = Math.floor(Date.now()/1000) - value;
        if (ageNow > 0) annot.extras.push(`Issued <strong>${tokensFmtDuration(ageNow)}</strong> ago.`);
      }
      if (name === 'exp') {
        const remaining = value - Math.floor(Date.now()/1000);
        if (remaining > 0) annot.extras.push(`Expires in <strong>${tokensFmtDuration(remaining)}</strong>.`);
        else annot.extras.push(`<strong>EXPIRED</strong> ${tokensFmtDuration(-remaining)} ago.`);
      }
      break;
    }
    case 'amr': {
      const arr = Array.isArray(value) ? value : [value];
      const hasMfa = arr.some(a => a === 'mfa' || a === 'ngcmfa' || a === 'rsa');
      const hasPwd = arr.includes('pwd');
      if (!hasMfa && hasPwd) {
        annot.severity = 'warn';
        annot.extras.push('<strong>Password-only authentication, no MFA factor</strong>. Worth investigating whether the user should have been prompted for MFA.');
      }
      if (arr.includes('fed')) annot.extras.push('Federated authentication assertion - check <code>identityProvider</code> for the source IdP.');
      break;
    }
    case 'acr': {
      if (String(value) === '0') {
        annot.severity = 'warn';
        annot.extras.push('<strong>acr=0</strong> - no MFA-equivalent satisfied.');
      } else if (String(value) === '1') {
        annot.extras.push('acr=1 - MFA satisfied.');
      }
      break;
    }
    case 'iss': {
      const v = String(value);
      if (!/^https:\/\/(sts\.windows\.net|login\.microsoftonline\.com|login\.partner\.microsoftonline\.cn|login\.microsoftonline\.us|.*\.ciamlogin\.com)/i.test(v)) {
        annot.severity = 'warn';
        annot.extras.push('<strong>Unusual issuer</strong> - not a standard Entra STS endpoint. Verify the issuer is expected for this tenant (B2C or external configurations may use ciamlogin.com).');
      }
      break;
    }
    case 'xms_cc': {
      const arr = Array.isArray(value) ? value : [value];
      if (arr.includes('cp1')) {
        annot.extras.push('<strong>CAE-aware client</strong> (cp1). This token gets the extended 24-28h CAE lifetime, but Continuous Access Evaluation can revoke it in near-real-time.');
      }
      break;
    }
    case 'acct': {
      if (String(value) === '1') {
        annot.severity = 'warn';
        annot.extras.push('<strong>Guest account</strong> (acct=1) acting against this tenant. Verify the guest is from an expected B2B partner.');
      }
      break;
    }
    case 'tid': {
      annot.extras.push('Cross-check this tid against your tenant id and your B2B partner list.');
      break;
    }
    case 'oid': {
      annot.extras.push('THE primary IR pivot. Use this to find every Graph call and audit-log event made by this principal.');
      break;
    }
    case 'uti': {
      annot.extras.push(`Pivot SPL: <code>\`oauthsentry_aad_signin\` uniqueTokenIdentifier="${escapeHtml(String(value))}"</code> &mdash; resolves the originating sign-in. Then <code>\`oauthsentry_graph_activity\` 'properties.signInActivityId'="${escapeHtml(String(value))}"</code> for every Graph call by this token.`);
      break;
    }
    default: {
      // No special enrichment - just description + defender_note from the reference
    }
  }

  return annot;
}

function tokensRenderClaim(annot) {
  const sevClass = `claim-sev-${annot.severity}`;
  const extras = annot.extras.length
    ? `<ul class="claim-extras">${annot.extras.map(e => `<li>${e}</li>`).join('')}</ul>`
    : '';
  return `
    <div class="token-claim ${sevClass}">
      <div class="claim-key"><code>${escapeHtml(annot.name)}</code></div>
      <div class="claim-body">
        <div class="claim-value">${annot.displayValue}</div>
        ${annot.description ? `<div class="claim-desc">${escapeHtml(annot.description)}</div>` : ''}
        ${annot.defenderNote ? `<div class="claim-note"><strong>Defender:</strong> ${escapeHtml(annot.defenderNote)}</div>` : ''}
        ${extras}
      </div>
    </div>
  `;
}

function escapeHtml(s) {
  return String(s)
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
}

function tokensRenderSummary(decoded) {
  const { payload } = decoded;
  const flow = (payload.idtyp || '').toLowerCase();
  let flowLabel = flow === 'app' ? 'App-only' : (flow === 'user' ? 'Delegated' : (flow === 'device' ? 'Device' : 'Unknown flow'));
  // App lookup - catalog wins over the FOCI/known list (catalog has up-to-date names + risk)
  const appid = (payload.appid || payload.azp || '').toLowerCase();
  const known = TOKENS.appsRef[appid];
  const catalog = state.byId && state.byId[appid];
  const appLabel = (catalog && catalog.appname) || (known && known.name) || (appid || '(no appid)');
  const isFoci = known?.foci;

  // Detect privileged-role holder by checking wids against the role table
  let hasPriv = false;
  const wids = Array.isArray(payload.wids) ? payload.wids : (payload.wids ? [payload.wids] : []);
  for (const w of wids) {
    const role = TOKENS.widsRef[String(w).toLowerCase()];
    if (role?.privileged) { hasPriv = true; break; }
  }

  // Lifetime + expiry
  let lifetimeLabel = '';
  let isExpired = false;
  let isLongLifetime = false;
  if (payload.iat && payload.exp) {
    const lifetime = payload.exp - payload.iat;
    lifetimeLabel = tokensFmtDuration(lifetime);
    isLongLifetime = lifetime > 86400 - 3600;  // >23h
  }
  if (payload.exp) {
    isExpired = (payload.exp < Math.floor(Date.now()/1000));
  }

  // Severity color
  let badgeClass = 'badge-info';
  if (catalog?.metadata_category === 'malicious') badgeClass = 'badge-critical';
  else if (hasPriv) badgeClass = 'badge-critical';
  else if (catalog?.metadata_category === 'risky') badgeClass = 'badge-warn';
  else if (isFoci || isLongLifetime) badgeClass = 'badge-warn';

  // Trim issuer URL display - cut after the tenant guid for readability
  let issuerDisplay = '';
  if (payload.iss) {
    const issStr = String(payload.iss);
    issuerDisplay = issStr.length > 60 ? issStr.slice(0, 57) + '...' : issStr;
  }

  return `
    <div class="tokens-summary-row">
      <span class="tokens-badge ${badgeClass}">${flowLabel}</span>
      ${hasPriv ? '<span class="tokens-badge badge-critical">Privileged</span>' : ''}
      ${isExpired ? '<span class="tokens-badge badge-info">Expired</span>' : ''}
      <span><strong>App:</strong> ${escapeHtml(appLabel)}${isFoci ? ' <em>(FOCI)</em>' : ''}</span>
      ${payload.upn ? `<span><strong>User:</strong> ${escapeHtml(payload.upn)}</span>` : ''}
      ${lifetimeLabel ? `<span><strong>Lifetime:</strong> ${lifetimeLabel}</span>` : ''}
      ${payload.aud ? `<span><strong>Audience:</strong> ${escapeHtml(String(payload.aud))}</span>` : ''}
      ${issuerDisplay ? `<span><strong>Issuer:</strong> ${escapeHtml(issuerDisplay)}</span>` : ''}
    </div>
  `;
}

function tokensRenderActionPanel(decoded) {
  const { payload } = decoded;
  const items = [];
  if (payload.uti) {
    items.push(`<strong>Find every Graph call by this token (uti pivot)</strong><br><code class="action-spl">\`oauthsentry_graph_activity\` 'properties.signInActivityId'="${escapeHtml(String(payload.uti))}"</code>`);
    items.push(`<strong>Find the originating sign-in</strong><br><code class="action-spl">\`oauthsentry_aad_signin\` uniqueTokenIdentifier="${escapeHtml(String(payload.uti))}"</code>`);
  }
  if (payload.sid) {
    items.push(`<strong>Find every M365 audit event in this session</strong><br><code class="action-spl">\`oauthsentry_o365_audit\` 'AppAccessContext.AADSessionId'="${escapeHtml(String(payload.sid))}"</code>`);
  }
  if (payload.oid) {
    items.push(`<strong>Resolve user/SP via Detection 13 directory lookup</strong><br><code class="action-spl">| lookup oauthsentry_user_directory.csv user_id as "${escapeHtml(String(payload.oid).toLowerCase())}" OUTPUT user_email, user_display_name, user_jobtitle</code>`);
  }
  const appid = (payload.appid || payload.azp || '').toLowerCase();
  if (appid) {
    items.push(`<strong>Investigate this app id</strong><br>Search the OAuthSentry catalog: <a href="#/search?q=${encodeURIComponent(appid)}" data-route="/search">${escapeHtml(appid)}</a>`);
  }
  // FOCI-specific guidance
  if (TOKENS.appsRef[appid]?.foci) {
    items.push(`<strong>FOCI client detected</strong><br>Refresh tokens issued to this app are family refresh tokens (FRTs). See the <a href="#/investigation/tradecraft" data-route="/investigation">Tradecraft tab</a> for the full FOCI list and the post-token-theft attack chain.`);
  }
  if (payload.deviceid) {
    items.push(`<strong>This token came from a registered device</strong><br>Check the registration date - recently-registered devices are a UTA0355 / Storm-2372 PRT-phishing signature. See <a href="#/investigation/forensics" data-route="/investigation">Forensic Traces</a> section on token tracking.`);
  }
  // Privileged role -> escalation playbook
  const wids = Array.isArray(payload.wids) ? payload.wids : (payload.wids ? [payload.wids] : []);
  const hasPriv = wids.some(w => TOKENS.widsRef[String(w).toLowerCase()]?.privileged);
  if (hasPriv) {
    items.push(`<strong>Privileged role on this token</strong><br>Escalate immediately. See <a href="#/investigation/remediation" data-route="/investigation">Remediation</a> for the revoke-and-rotate playbook (revokeSignInSessions on the user, then rotate any client secrets and review consent grants).`);
  }
  if (!items.length) {
    items.push('<em>No pivotable identifiers in this token.</em> The decoded payload above is informational only - check the appid against the catalog and the wids against the role table for context.');
  }
  return `<ol class="tokens-action-list">${items.map(i => `<li>${i}</li>`).join('')}</ol>`;
}

async function tokensDecode() {
  await tokensLoadRefs();
  const errEl = document.getElementById('tokens-error');
  const out   = document.getElementById('tokens-output');
  errEl.hidden = true;
  errEl.textContent = '';

  const raw = document.getElementById('tokens-input')?.value || '';
  let decoded;
  try {
    decoded = tokensParseInput(raw);
  } catch (e) {
    errEl.textContent = e.message;
    errEl.hidden = false;
    out.hidden = true;
    return;
  }

  // Render summary
  document.getElementById('tokens-summary').innerHTML = tokensRenderSummary(decoded);

  // Render header claims
  const headerClaims = Object.entries(decoded.header)
    .map(([k, v]) => tokensAnnotateClaim(k, v, decoded.header))
    .map(tokensRenderClaim).join('');
  document.getElementById('tokens-header-claims').innerHTML = headerClaims || '<em>(empty)</em>';

  // Render payload claims, with a sensible ordering: identification > app > authorization > authn > lifetime > tracking > rest
  const ORDER = ['idtyp', 'aud', 'iss', 'tid', 'oid', 'sub', 'upn', 'preferred_username', 'unique_name', 'name', 'email',
    'appid', 'azp', 'app_displayname', 'appidacr', 'azpacr',
    'scp', 'roles', 'wids', 'groups',
    'amr', 'acr', 'auth_time', 'ipaddr', 'platf', 'deviceid', 'identityProvider',
    'iat', 'nbf', 'exp',
    'uti', 'sid', 'jti',
    'tenant_region_scope', 'tenant_ctry', 'acct', 'ver',
    'xms_cc', 'acrs',
  ];
  const seen = new Set();
  const ordered = [];
  for (const k of ORDER) {
    if (k in decoded.payload) { ordered.push(k); seen.add(k); }
  }
  for (const k of Object.keys(decoded.payload)) {
    if (!seen.has(k)) ordered.push(k);
  }

  const payloadClaims = ordered
    .map(k => tokensAnnotateClaim(k, decoded.payload[k], decoded.payload))
    .map(tokensRenderClaim).join('');
  document.getElementById('tokens-payload-claims').innerHTML = payloadClaims;

  // Action panel
  document.getElementById('tokens-action-panel').innerHTML = tokensRenderActionPanel(decoded);

  // Raw JSON
  document.getElementById('tokens-raw-json').textContent =
    'Header:\n' + JSON.stringify(decoded.header, null, 2) +
    '\n\nPayload:\n' + JSON.stringify(decoded.payload, null, 2);

  out.hidden = false;
}

function tokensInit() {
  document.getElementById('tokens-decode-btn')?.addEventListener('click', tokensDecode);
  document.getElementById('tokens-clear-btn')?.addEventListener('click', () => {
    const el = document.getElementById('tokens-input');
    if (el) el.value = '';
    document.getElementById('tokens-output').hidden = true;
    document.getElementById('tokens-error').hidden = true;
  });
  // Decode on Ctrl/Cmd-Enter when textarea has focus
  document.getElementById('tokens-input')?.addEventListener('keydown', (e) => {
    if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') {
      e.preventDefault();
      tokensDecode();
    }
  });
}
