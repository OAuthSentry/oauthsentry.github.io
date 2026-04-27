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
  ['page-search', 'page-investigation', 'page-feeds', 'page-methodology'].forEach(id => {
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

  const MAX = 300;
  const view = list.slice(0, MAX);
  const q = state.query.trim();

  container.innerHTML = view.map(app => `
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

  if (list.length > MAX) {
    container.insertAdjacentHTML('beforeend', `
      <div class="empty" style="padding: 28px;">
        showing first ${MAX} of ${list.length.toLocaleString()} - refine your query
      </div>
    `);
  }

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
}

document.addEventListener('DOMContentLoaded', init);
