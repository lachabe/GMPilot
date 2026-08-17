const VENDOR_PRODUCTS = JSON.parse(document.getElementById('gmpilot-vulns-data').textContent || '{}');
const STATUS_DEFS = (function () {
  try { return JSON.parse((document.getElementById('gmpilot-status-defs') || {}).textContent || '[]'); }
  catch (e) { return []; }
})();
const STATUS_MAP = {};
STATUS_DEFS.forEach(function (s) { STATUS_MAP[s.id] = s; });

// ══════════════════════════════
// Onglets
// ══════════════════════════════
const TAB_KEY = 'vulns_active_tab';
let resolvedLoaded = false;
let currentTab = 'grouped';
let filtersVisible = localStorage.getItem('vulns_filters_visible') !== 'false';

// ── Faux positifs ──────────────────────────────────────────────
let currentFinding = null;
function canMarkFp() {
  const cfg = document.getElementById('gmpilot-vulns-config');
  return !!cfg && cfg.dataset.canMarkFp === 'true';
}
function csrfToken() { return document.body.dataset.csrfToken || ''; }

function activateTab(tabName) {
  currentTab = tabName;
  if (tabName === 'resolved' && !resolvedLoaded) loadResolved();
  ['grouped','tickets','resolved'].forEach(t => {
    const a = document.getElementById('tab-' + t);
    if (!a) return;
    const active = t === tabName;
    a.style.color = active ? 'var(--tblr-primary)' : 'var(--tblr-secondary)';
    a.style.borderBottomColor = active ? 'var(--tblr-primary)' : 'transparent';
  });
  document.querySelectorAll('.tab-filters').forEach(el =>
    el.style.display = (el.id === 'filters-' + tabName && filtersVisible) ? '' : 'none');
  document.querySelectorAll('.tab-view').forEach(el =>
    el.style.display = el.id === 'view-' + tabName ? '' : 'none');
  ['grouped','tickets','resolved'].forEach(t => {
    const el = document.getElementById('stats-' + t);
    if (el) el.style.display = t === tabName ? '' : 'none';
  });
  // L'export CSV (synthèse) n'est pertinent que sur l'onglet Vulnérabilités
  const exp = document.getElementById('synth-export');
  if (exp) exp.style.display = tabName === 'grouped' ? '' : 'none';
  // Le bouton Filtres n'existe que pour les onglets qui ont une barre de filtres
  const ft = document.getElementById('filters-toggle');
  if (ft) ft.style.display = (tabName === 'grouped' || tabName === 'resolved') ? '' : 'none';
  updateFiltersButton();
  localStorage.setItem(TAB_KEY, tabName);
}

// ── Bouton « Filtres » : bascule l'affichage + indique si un filtre est actif ──
function anyGroupedFilterActive() {
  return !!((synthVendor && synthVendor.value) || (synthProduct && synthProduct.value)
    || (synthScore && synthScore.value) || (synthSevMin && synthSevMin.value)
    || (synthSevMax && synthSevMax.value) || (synthStatus && synthStatus.value)
    || (synthHost && synthHost.value) || (synthSearch && synthSearch.value.trim())
    || (synthExploited && synthExploited.checked));
}
function anyResolvedFilterActive() {
  return ['resolved-search','resolved-type','resolved-min-sev','resolved-since','resolved-min-days','resolved-max-days']
    .some(id => { const el = document.getElementById(id); return el && el.value && String(el.value).trim(); });
}
function updateFiltersButton() {
  const btn = document.getElementById('filters-toggle');
  if (!btn) return;
  let active = false;
  if (currentTab === 'grouped') active = anyGroupedFilterActive();
  else if (currentTab === 'resolved') active = anyResolvedFilterActive();
  btn.classList.toggle('btn-cyan', active);
  btn.classList.toggle('btn-outline-secondary', !active);
  btn.innerHTML = active
    ? '<i class="ti ti-filter-filled me-1"></i>Filtre actif'
    : '<i class="ti ti-filter me-1"></i>Filtre';
}
const _ftBtn = document.getElementById('filters-toggle');
if (_ftBtn) _ftBtn.addEventListener('click', () => {
  filtersVisible = !filtersVisible;
  localStorage.setItem('vulns_filters_visible', filtersVisible);
  const bar = document.getElementById('filters-' + currentTab);
  if (bar) bar.style.display = filtersVisible ? '' : 'none';
});
// Listeners sur les onglets (pas de onclick inline pour éviter les erreurs de parsing)
document.querySelectorAll('[data-tab]').forEach(a => {
  a.addEventListener('click', e => { e.preventDefault(); activateTab(a.dataset.tab); });
});

// ══════════════════════════════
// Accordion Synthèse
// ══════════════════════════════
function toggleVendor(idx) {
  const body = document.getElementById('vendor-body-' + idx);
  const btn  = document.getElementById('toggle-btn-' + idx);
  const row  = body.previousElementSibling;
  const open = body.classList.toggle('is-open');
  btn.classList.toggle('is-open', open);
  row.classList.toggle('is-open', open);
}

function toggleProduct(vIdx, pIdx) {
  const detailRow = document.getElementById('product-body-' + vIdx + '-' + pIdx);
  const btn       = document.getElementById('product-toggle-' + vIdx + '-' + pIdx);
  // Trouver la tr de la ligne product (précédant la tr detail)
  const productRow = detailRow.previousElementSibling;
  const open = detailRow.style.display === 'none' || detailRow.style.display === '';
  detailRow.style.display = open ? 'table-row' : 'none';
  if (btn) btn.classList.toggle('is-open', open);
  if (productRow) productRow.classList.toggle('is-open', open);
}

function toggleTicket(idx) {
  const detailRow = document.getElementById('ticket-body-' + idx);
  const btn       = document.getElementById('ticket-toggle-' + idx);
  if (!detailRow) return;
  const open = detailRow.style.display === 'none' || detailRow.style.display === '';
  detailRow.style.display = open ? 'table-row' : 'none';
  if (btn) btn.classList.toggle('is-open', open);
}

// Clôturer un ticket → résout toutes ses vulnérabilités (réversible via « Rouvrir »)
document.querySelectorAll('.ticket-close-btn').forEach(btn => {
  btn.addEventListener('click', async (e) => {
    e.stopPropagation();
    const ids = (btn.dataset.findingIds || '').split(',').filter(Boolean);
    const ticket = btn.dataset.ticket || '';
    if (!ids.length) return;
    if (!confirm('Clôturer le ticket « ' + ticket + ' » ?\nLes ' + ids.length + ' vulnérabilité(s) associée(s) seront marquées comme RÉSOLUES.')) return;
    try {
      const j = await postTreat(ids, 'resolved', {});
      showToast('Ticket « ' + ticket + ' » clôturé — ' + j.updated + ' vulnérabilité(s) résolue(s).', 'success');
      setTimeout(() => location.reload(), 800);
    } catch (err) { showToast('Erreur : ' + esc(err.message), 'danger'); }
  });
});

// ── Tri des sous-tableaux product ──
document.addEventListener('click', e => {
  const th = e.target.closest('.synth-product-table th[data-col]');
  if (!th) return;
  const table  = th.closest('.synth-product-table');
  const col    = th.dataset.col;
  const isNum  = th.dataset.sort === 'num';
  const isAsc  = th.classList.contains('sort-asc');

  // Réinitialiser les autres headers
  table.querySelectorAll('th[data-col]').forEach(h => {
    h.classList.remove('sort-asc', 'sort-desc');
  });
  th.classList.add(isAsc ? 'sort-desc' : 'sort-asc');

  // Collecter les groupes (paires tr product + tr detail)
  const tbody = table.querySelector('tbody');
  // Les groupes sont des .synth-product-group (divs) — on récupère les paires de tr
  const pairs = [];
  const children = Array.from(tbody.children);
  // Structure : div.synth-product-group contenant tr + tr
  // Mais en HTML réel on a les tr directement dans tbody
  // On groupe par paires : tr.synth-product-row + tr.synth-product-detail
  for (let i = 0; i < children.length; i++) {
    const el = children[i];
    if (el.classList.contains('synth-product-row')) {
      const detail = children[i + 1];
      pairs.push({ row: el, detail: detail || null });
    }
  }

  pairs.sort((a, b) => {
    let va = a.row.dataset[col] || '';
    let vb = b.row.dataset[col] || '';
    if (isNum) { va = parseFloat(va) || 0; vb = parseFloat(vb) || 0; }
    const cmp = isNum ? va - vb : va.localeCompare(vb, 'fr', {sensitivity:'base'});
    return isAsc ? -cmp : cmp;
  });

  pairs.forEach(({ row, detail }) => {
    tbody.appendChild(row);
    if (detail) tbody.appendChild(detail);
  });
});

// ══════════════════════════════
// Filtres Synthèse
// ══════════════════════════════
const synthVendor  = document.getElementById('synth-vendor');
const synthProduct = document.getElementById('synth-product');
const synthScore   = document.getElementById('synth-score');

function populateProducts(vendor) {
  synthProduct.innerHTML = '<option value="">Tous les produits</option>';
  if (!vendor) { synthProduct.disabled = false; return; }
  const products = VENDOR_PRODUCTS[vendor] || [];
  synthProduct.disabled = products.length === 0;
  products.forEach(p => {
    const opt = document.createElement('option');
    opt.value = p; opt.textContent = p;
    synthProduct.appendChild(opt);
  });
}

const synthSearch = document.getElementById('synth-search');
const synthHost   = document.getElementById('synth-host');
const synthStatus = document.getElementById('synth-status');
const synthSevMin = document.getElementById('synth-sevmin');
const synthSevMax = document.getElementById('synth-sevmax');
const synthExploited = document.getElementById('synth-exploited');

// Peupler le dropdown hôtes depuis les data-hosts des lignes produit
(function() {
  if (!synthHost) return;
  var allHosts = new Set();
  document.querySelectorAll('tr.synth-product-group').forEach(function(tr) {
    var hosts = tr.dataset.hosts || '';
    hosts.split(',').forEach(function(h) {
      h = h.trim();
      if (h) {
        var ip = h.split(':')[0];
        if (ip) allHosts.add(ip);
      }
    });
  });
  Array.from(allHosts).sort().forEach(function(h) {
    var opt = document.createElement('option');
    opt.value = h; opt.textContent = h;
    synthHost.appendChild(opt);
  });
})();

function applySynthFilters() {
  const vendor   = synthVendor.value;
  const product  = synthProduct.value;
  const minScore = parseFloat(synthScore.value) || 0;
  const search   = synthSearch ? synthSearch.value.toLowerCase().trim() : '';
  const hostFilter = synthHost ? synthHost.value.trim() : '';
  const statusF  = synthStatus ? synthStatus.value : '';
  const sevMin = synthSevMin && synthSevMin.value !== '' ? parseFloat(synthSevMin.value) : null;
  const sevMax = synthSevMax && synthSevMax.value !== '' ? parseFloat(synthSevMax.value) : null;
  const exploitedOnly = synthExploited ? synthExploited.checked : false;

  let totalProducts = 0, totalVulns = 0, visibleVendors = 0;
  document.querySelectorAll('.synth-vendor-group').forEach(vg => {
    const vendorName = (vg.dataset.vendor || '').toLowerCase();
    // Filtre vendor
    if (vendor && vg.dataset.vendor !== vendor) { vg.style.display = 'none'; return; }
    let vProducts = 0, vVulns = 0;
    vg.querySelectorAll('tr.synth-product-group').forEach(tr => {
      const productName = (tr.dataset.product || '').toLowerCase();
      const hosts = tr.dataset.hosts || '';
      // data-search = vendor + produit + noms de vulns (NVT) + CVE (déjà en minuscules)
      const searchData = tr.dataset.search || (productName + ' ' + vendorName);
      const matchSearch = !search || searchData.includes(search);
      const matchHost = !hostFilter || hosts.split(',').some(function(h) {
        return h.trim().split(':')[0] === hostFilter;
      });
      const totalV = parseInt(tr.dataset.vulns || '0', 10);
      const inProg = parseInt(tr.dataset.inprogress || '0', 10);   // vulns non-active (« traitées »)
      // Un produit correspond si au moins UNE de ses vulns correspond au statut :
      // « en cours » → ≥1 non-active ; « sans traitement » → ≥1 active.
      const matchStatus = !statusF
        || (statusF === 'in_progress' && inProg > 0)
        || (statusF === 'untreated' && (totalV - inProg) > 0);
      const sev = parseFloat(tr.dataset.sev) || 0;
      const matchSev = (sevMin === null || sev >= sevMin) && (sevMax === null || sev <= sevMax);
      const matchExploited = !exploitedOnly || (parseInt(tr.dataset.exploited || '0', 10) > 0);
      const ok = (!product || tr.dataset.product === product)
              && (parseFloat(tr.dataset.maxScore) || 0) >= minScore
              && matchSearch
              && matchHost
              && matchStatus
              && matchSev
              && matchExploited;
      const detail = tr.nextElementSibling;
      tr.style.display = ok ? '' : 'none';
      // Filtrage au niveau des vulns individuelles : un produit mixte (avec/sans
      // ticket) reste visible mais n'affiche que les vulns du statut demandé. Le
      // compteur reflète les vulns effectivement visibles.
      let shownV = totalV;
      if (detail && detail.classList.contains('synth-product-detail')) {
        if (!ok) {
          detail.style.display = 'none';
        } else if (statusF) {
          shownV = 0;
          detail.querySelectorAll('.synth-vuln-row').forEach(function (vr) {
            const vs = vr.dataset.status || 'active';
            const rowOk = (statusF === 'in_progress') ? (vs !== 'active') : (vs === 'active');
            vr.style.display = rowOk ? '' : 'none';
            if (rowOk) shownV++;
          });
        } else {
          detail.querySelectorAll('.synth-vuln-row').forEach(function (vr) { vr.style.display = ''; });
        }
      }
      if (ok) { vProducts++; vVulns += shownV; }
    });
    vg.style.display = vProducts > 0 ? '' : 'none';

    // Compteurs par vendor (en-tête de l'accordéon). Cible la classe si le
    // template la porte, sinon par position (1er col = vulns, 2e = produits) —
    // robuste même si le template en cache Flask n'a pas encore les classes.
    const cols = vg.querySelectorAll('.synth-vendor-col');
    const cVulns = vg.querySelector('.synth-vendor-vulns') || cols[0];
    const cProds = vg.querySelector('.synth-vendor-products') || cols[1];
    if (cVulns) cVulns.textContent = vVulns;
    if (cProds) cProds.textContent = vProducts;

    if (vProducts > 0) { visibleVendors++; totalProducts += vProducts; totalVulns += vVulns; }
  });

  // Compteurs globaux
  var elV  = document.getElementById('synth-stat-vulns');
  var elP  = document.getElementById('synth-stat-products');
  var elVn = document.getElementById('synth-stat-vendors');
  if (elV)  elV.textContent  = totalVulns;
  if (elP)  elP.textContent  = totalProducts;
  if (elVn) elVn.textContent = visibleVendors;
  // Ligne « Aucun résultat » quand des groupes existent mais sont tous masqués par les filtres
  const noRes = document.getElementById('synth-no-results');
  if (noRes) noRes.style.display =
    (document.querySelectorAll('.synth-vendor-group').length > 0 && visibleVendors === 0) ? '' : 'none';
  updateFiltersButton();
}

synthVendor.addEventListener('change', () => { populateProducts(synthVendor.value); applySynthFilters(); });
synthProduct.addEventListener('change', applySynthFilters);
synthScore.addEventListener('input', applySynthFilters);
if (synthSearch) synthSearch.addEventListener('input', applySynthFilters);
if (synthHost) synthHost.addEventListener('change', applySynthFilters);
if (synthStatus) synthStatus.addEventListener('change', applySynthFilters);
if (synthSevMin) synthSevMin.addEventListener('input', applySynthFilters);
if (synthSevMax) synthSevMax.addEventListener('input', applySynthFilters);
if (synthExploited) synthExploited.addEventListener('change', applySynthFilters);
document.getElementById('synth-reset').addEventListener('click', () => {
  synthVendor.value = ''; populateProducts(''); synthScore.value = '';
  if (synthSearch) synthSearch.value = '';
  if (synthHost) synthHost.value = '';
  if (synthStatus) synthStatus.value = '';
  if (synthSevMin) synthSevMin.value = '';
  if (synthSevMax) synthSevMax.value = '';
  if (synthExploited) synthExploited.checked = false;
  applySynthFilters();
});

// Export CSV — reprend les filtres synthèse courants + la sélection de scans de l'URL
const synthExport = document.getElementById('synth-export');
if (synthExport) {
  synthExport.addEventListener('click', () => {
    const params = new URLSearchParams();
    if (synthVendor.value)  params.set('vendor', synthVendor.value);
    if (synthProduct.value) params.set('product', synthProduct.value);
    if (synthScore.value)   params.set('min_score', synthScore.value);
    if (synthSearch && synthSearch.value.trim()) params.set('q', synthSearch.value.trim());
    if (synthHost && synthHost.value.trim())     params.set('host', synthHost.value.trim());
    new URLSearchParams(window.location.search).getAll('task_ids')
      .forEach(t => params.append('task_ids', t));
    window.location = '/vulns/export.csv?' + params.toString();
  });
}

// ══════════════════════════════
// Chargement AJAX des résolues
// ══════════════════════════════
var resolvedState = { items: [], filtered: [], page: 1, perPage: 50, warn: 30, crit: 90 };

function loadResolved() {
  var cfg = document.getElementById('gmpilot-vulns-config');
  var url = cfg ? cfg.dataset.resolvedUrl : '/vulns/api/resolved';
  fetch(url, {headers:{'X-Requested-With':'XMLHttpRequest'}})
    .then(function(r) { return r.json(); })
    .then(function(data) {
      resolvedLoaded = true;
      resolvedState.items = data.resolved || [];
      resolvedState.warn = data.remediation_warn || 30;
      resolvedState.crit = data.remediation_critical || 90;
      resolvedState.filtered = resolvedState.items.slice();
      resolvedState.page = 1;

      // Badge compteur sur l'onglet
      var tabLabel = document.getElementById('tab-resolved');
      if (tabLabel && resolvedState.items.length) {
        var badge = tabLabel.querySelector('.badge');
        if (badge) badge.textContent = resolvedState.items.length;
      }

      renderResolved();
      initResolvedFilters();
    })
    .catch(function() {
      document.getElementById('resolved-content').innerHTML = '<div class="text-center text-danger py-4">Erreur de chargement</div>';
    });
}

// Une ligne du tableau résolues
function resolvedRowHtml(v) {
  var st = resolvedState;
  var sevCls = v.sev_class || 'low';
  var remDays = v.remediation_days;
  var hasDays = remDays !== null && remDays !== undefined;
  var isFp = !!v.is_false_positive;
  var sd = STATUS_MAP[v.status] || { label: v.status || '—', icon: 'ti-circle', color: 'secondary' };
  var tip = [];
  if (v.status_by) tip.push('par ' + v.status_by);
  if (v.status_at) tip.push('le ' + v.status_at.slice(0, 10));
  (sd.fields || []).forEach(function (f) { var val = (v.status_data || {})[f.key]; if (val) tip.push(f.label + ' : ' + val); });
  var typeBadge = '<span class="badge bg-' + esc(sd.color) + '-lt"' + (tip.length ? ' title="' + esc(tip.join(' · ')) + '"' : '') +
    '><i class="ti ' + esc(sd.icon) + ' me-1"></i>' + esc(sd.label) + '</span>';
  var remBadge = '<span class="text-secondary">—</span>';
  if (!isFp && hasDays) {
    var remCls = remDays > st.crit ? 'bg-red-lt' : remDays > st.warn ? 'bg-yellow-lt' : 'bg-green-lt';
    remBadge = '<span class="badge ' + remCls + '">' + remDays + 'j</span>';
  }
  var tasksHtml = (v.task_names || ['—']).map(function(t){ return '<span class="badge bg-secondary-lt me-1">' + t + '</span>'; }).join('');
  var resolvedDate = v.resolved_at ? v.resolved_at.slice(0,10) : '';
  return '<tr class="resolved-row">' +
    '<td class="text-truncate" style="max-width:240px" title="' + esc(v.name) + '">' + v.name + '</td>' +
    '<td class="text-center"><span class="badge badge-' + sevCls + '">' + v.severity.toFixed(1) + '</span></td>' +
    '<td>' + typeBadge + '</td>' +
    '<td class="text-truncate" style="max-width:100px">' + (v.euvd_vendor || '—') + '</td>' +
    '<td class="text-truncate" style="max-width:100px">' + (v.euvd_product || '—') + '</td>' +
    '<td><code class="small"' + (v.hostname ? ' title="' + v.host + '"' : '') + '>' + (v.hostname || v.host) + '</code></td>' +
    '<td class="text-secondary small">' + (v.first_seen ? v.first_seen.slice(0,10) : '—') + '</td>' +
    '<td class="text-secondary small">' + (resolvedDate || '—') + '</td>' +
    '<td class="text-center">' + remBadge + '</td>' +
    '<td class="small">' + tasksHtml + '</td>' +
    '<td class="text-center text-secondary">' + (v.sighting_count || 0) + '</td>' +
    '<td class="text-center"><a class="vuln-detail-btn text-secondary" style="cursor:pointer" data-vuln-id="' + v.id + '" title="Voir le détail"><i class="ti ti-eye fs-3"></i></a></td>' +
    '</tr>';
}

// Rendu de la page courante (pagination côté client → DOM léger)
function renderResolved() {
  var st = resolvedState;
  var total = st.filtered.length;
  var pages = Math.max(1, Math.ceil(total / st.perPage));
  if (st.page > pages) st.page = pages;
  if (st.page < 1) st.page = 1;
  var start = (st.page - 1) * st.perPage;
  var pageItems = st.filtered.slice(start, start + st.perPage);

  var html = '<div class="card"><div class="table-responsive">' +
    '<table class="table table-vcenter card-table" style="font-size:0.8rem"><thead><tr>' +
    '<th>Vulnérabilité</th><th class="text-center" style="width:55px">Sév.</th>' +
    '<th style="width:120px">Type</th><th style="width:100px">Vendor</th>' +
    '<th style="width:100px">Product</th><th style="width:130px">Hôte</th>' +
    '<th style="width:80px">Détecté le</th><th style="width:80px">Résolu le</th>' +
    '<th class="text-center" style="width:70px">Remédiation</th><th style="width:80px">Tâche(s)</th>' +
    '<th class="text-center" style="width:50px">Scans</th>' +
    '<th class="text-center" style="width:44px"></th></tr></thead><tbody>';
  if (total === 0) {
    html += '<tr><td colspan="12" class="text-center text-secondary py-4">Aucune vulnérabilité résolue</td></tr>';
  } else {
    for (var i = 0; i < pageItems.length; i++) html += resolvedRowHtml(pageItems[i]);
  }
  html += '</tbody></table></div>';

  if (pages > 1) {
    var pag = '<li class="page-item' + (st.page <= 1 ? ' disabled' : '') + '">' +
              '<a class="page-link" href="#" data-resolved-page="' + (st.page - 1) + '"><i class="ti ti-chevron-left"></i></a></li>';
    for (var p = 1; p <= pages; p++) {
      if (p === st.page || p === 1 || p === pages || (p >= st.page - 2 && p <= st.page + 2)) {
        pag += '<li class="page-item' + (p === st.page ? ' active' : '') + '">' +
               '<a class="page-link" href="#" data-resolved-page="' + p + '">' + p + '</a></li>';
      } else if (p === st.page - 3 || p === st.page + 3) {
        pag += '<li class="page-item disabled"><span class="page-link">…</span></li>';
      }
    }
    pag += '<li class="page-item' + (st.page >= pages ? ' disabled' : '') + '">' +
           '<a class="page-link" href="#" data-resolved-page="' + (st.page + 1) + '"><i class="ti ti-chevron-right"></i></a></li>';
    html += '<div class="card-footer d-flex align-items-center">' +
      '<p class="m-0 text-secondary small">' + total + ' résultat(s) · page <strong>' + st.page + '</strong>/' + pages + '</p>' +
      '<ul class="pagination m-0 ms-auto">' + pag + '</ul></div>';
  }
  html += '</div>';
  document.getElementById('resolved-content').innerHTML = html;

  // Stats (reflètent le filtrage)
  var statsEl = document.getElementById('resolved-stats-text');
  if (statsEl) {
    var msg = total + ' / ' + st.items.length + ' résolue(s)';
    var days = st.filtered.filter(function(v){ return !v.is_false_positive && v.remediation_days !== null && v.remediation_days !== undefined; })
                          .map(function(v){ return v.remediation_days; });
    if (days.length) { var avg = Math.round(days.reduce(function(a,b){ return a + b; }, 0) / days.length); msg += ' · remédiation moy. ' + avg + 'j'; }
    statsEl.textContent = msg;
  }

  // Liens de pagination
  document.querySelectorAll('#resolved-content [data-resolved-page]').forEach(function(a) {
    a.addEventListener('click', function(e) {
      e.preventDefault();
      var p = parseInt(a.getAttribute('data-resolved-page'));
      if (!isNaN(p)) { resolvedState.page = p; renderResolved(); }
    });
  });
}

// ══════════════════════════════
// Filtres Résolues
// ══════════════════════════════
function initResolvedFilters() {
  var search = document.getElementById('resolved-search');
  var typeSel = document.getElementById('resolved-type');
  var minSev = document.getElementById('resolved-min-sev');
  var since = document.getElementById('resolved-since');
  var minDays = document.getElementById('resolved-min-days');
  var maxDays = document.getElementById('resolved-max-days');
  var resetBtn = document.getElementById('resolved-reset');
  if (!search) return;

  function applyFilters() {
    var q = (search.value || '').toLowerCase();
    var type = typeSel ? typeSel.value : '';
    var ms = parseFloat(minSev.value);
    var dMin = parseInt(minDays.value);
    var dMax = parseInt(maxDays.value);
    var remActive = !isNaN(dMin) || !isNaN(dMax);
    // « Résolu depuis N jours » → borne basse de date
    var sinceCutoff = '';
    var sinceN = since ? parseInt(since.value) : NaN;
    if (!isNaN(sinceN)) {
      var dt = new Date(); dt.setDate(dt.getDate() - sinceN);
      sinceCutoff = dt.toISOString().slice(0, 10);
    }

    resolvedState.filtered = resolvedState.items.filter(function(v) {
      if (q) {
        var hay = [v.name, v.host, v.hostname, v.cve, v.euvd_vendor, v.euvd_product].join(' ').toLowerCase();
        if (hay.indexOf(q) === -1) return false;
      }
      var isFp = !!v.is_false_positive;
      if (type === 'fp' && !isFp) return false;
      if (type === 'patched' && isFp) return false;
      if (!isNaN(ms) && (v.severity || 0) < ms) return false;
      if (sinceCutoff) {
        var rd = v.resolved_at ? v.resolved_at.slice(0, 10) : '';
        if (!rd || rd < sinceCutoff) return false;
      }
      var hasDays = !isFp && v.remediation_days !== null && v.remediation_days !== undefined;
      if (hasDays) {
        if (!isNaN(dMin) && v.remediation_days < dMin) return false;
        if (!isNaN(dMax) && v.remediation_days > dMax) return false;
      } else if (remActive) {
        // Faux positif : pas de délai de remédiation → exclu si un filtre remédiation est actif
        return false;
      }
      return true;
    });
    resolvedState.page = 1;
    renderResolved();
    updateFiltersButton();
  }

  [search, typeSel, minSev, since, minDays, maxDays].forEach(function(el) {
    if (el) { el.addEventListener('input', applyFilters); el.addEventListener('change', applyFilters); }
  });
  if (resetBtn) resetBtn.addEventListener('click', function() {
    search.value = ''; if (typeSel) typeSel.value = ''; minSev.value = '';
    if (since) since.value = ''; minDays.value = ''; maxDays.value = '';
    applyFilters();
  });
}

// ══════════════════════════════
// Toasts
// ══════════════════════════════
function showToast(message, type = 'info') {
  const container = document.getElementById('toast-container');
  const id = 'toast-' + Date.now();
  const icons = { success:'ti-circle-check', danger:'ti-alert-triangle', warning:'ti-exclamation-circle', info:'ti-info-circle' };
  container.insertAdjacentHTML('beforeend', `
    <div id="${id}" class="toast show" role="alert">
      <div class="toast-header">
        <span class="avatar avatar-xs bg-${type} me-2"><i class="ti ${icons[type]||icons.info}"></i></span>
        <strong class="me-auto">${type==='success'?'Succès':type==='danger'?'Erreur':'Info'}</strong>
        <button type="button" class="ms-2 btn-close" onclick="this.closest('.toast').remove()"></button>
      </div>
      <div class="toast-body">${message}</div>
    </div>`);
  setTimeout(() => { const el = document.getElementById(id); if (el) el.remove(); }, 4000);
}

// ══════════════════════════════
// Tri (vue flat)
// ══════════════════════════════
document.querySelectorAll('.sort-th').forEach(th => {
  th.addEventListener('click', () => {
    const url = new URL(location.href);
    const field = th.dataset.field;
    const cur = url.searchParams.get('sort') || 'severity';
    const ord = url.searchParams.get('order') || 'desc';
    url.searchParams.set('sort', field);
    url.searchParams.set('order', cur === field && ord === 'desc' ? 'asc' : 'desc');
    url.searchParams.set('page', '1');
    location = url;
  });
});

// ══════════════════════════════
// Modal détail
// ══════════════════════════════
const modalTrigger = document.getElementById('modalTrigger');
function showModal() { modalTrigger.click(); }

// Fix accessibilité : déplacer le focus hors du modal avant aria-hidden
const vulnModalEl = document.getElementById('vulnModal');
if (vulnModalEl) {
  vulnModalEl.addEventListener('hide.bs.modal', function() {
    if (vulnModalEl.contains(document.activeElement)) {
      document.activeElement.blur();
    }
  });
}
function esc(s) { if (!s) return ''; const d = document.createElement('div'); d.textContent = s; return d.innerHTML; }
function severityLabel(sev) {
  if (sev >= 9.0) return 'Critical'; if (sev >= 7.0) return 'High';
  if (sev >= 4.0) return 'Medium';  if (sev > 0)    return 'Low'; return 'Log';
}

function fillModal(d) {
  currentFinding = d;
  document.getElementById('mTitle').textContent = d.name || '—';
  const sc = d.sev_class || 'log';
  let badges = `<span class="badge badge-${esc(sc)}">${parseFloat(d.severity||0).toFixed(1)}</span>`;
  if (d.euvd_exploited) badges += ` <span class="badge bg-red-lt"><i class="ti ti-alert-triangle me-1"></i>Exploité</span>`;
  if (d.kev_entries && d.kev_entries.length > 0) badges += ` <span class="badge bg-red"><i class="ti ti-flame me-1"></i>KEV</span>`;
  if (d.anssi_entries && d.anssi_entries.length > 0) {
    const hasAlerte = d.anssi_entries.some(e => e.type === 'alerte');
    badges += ` <span class="badge ${hasAlerte?'bg-orange':'bg-yellow'}"><i class="ti ti-building-fortress me-1"></i>ANSSI</span>`;
  }
  document.getElementById('mBadge').innerHTML = badges;

  const score = d.ctx_score || 0;
  const scoreColor = score>=70?'#9e1b1b':score>=50?'#d63939':score>=30?'#f76707':'#e67700';
  const scoreClass = score>=70?'badge-critical':score>=50?'badge-high':score>=30?'badge-medium':'badge-low';
  let scoreHtml = `<div class="d-flex align-items-center gap-2 mb-2">
    <span class="badge ${scoreClass} fs-4">${score.toFixed(0)}</span>
    <div><div class="score-gauge"><div class="score-gauge-fill" style="width:${score}%;background:${scoreColor}"></div></div>
    <small class="text-secondary">Score de priorisation</small></div></div>`;
  if (d.ctx_score_details) {
    scoreHtml += '<div class="d-flex flex-wrap gap-2 mb-2">';
    for (const [k,v] of Object.entries(d.ctx_score_details))
      scoreHtml += `<span class="badge bg-secondary-lt">${esc(k)}: ${(v*100).toFixed(0)}%</span>`;
    scoreHtml += '</div>';
  }

  let hostTagsHtml = '';
  if (d.host_tags && d.host_tags.length > 0)
    hostTagsHtml = d.host_tags.map(t=>`<span class="badge bg-azure-lt me-1">${esc(t)}</span>`).join('');

  let epssHtml = '—';
  if (d.euvd_epss !== null && d.euvd_epss !== undefined) {
    const ev = (d.euvd_epss*100).toFixed(1);
    const ec = d.euvd_epss>=0.5?'badge-critical':d.euvd_epss>=0.1?'badge-high':d.euvd_epss>=0.01?'badge-medium':'badge-low';
    epssHtml = `<span class="badge ${ec}">${ev}%</span>`;
  }

  const allCves = d.all_cves || d.cves || [];
  let cvesHtml = '—';
  if (allCves.length > 0) {
    cvesHtml = allCves.map(c=>`<a href="https://euvd.enisa.europa.eu/vulnerability/${encodeURIComponent(c)}" target="_blank" class="badge bg-cyan-lt text-decoration-none me-1 mb-1">${esc(c)}</a>`).join('');
    cvesHtml += `<button class="btn btn-ghost-secondary btn-sm btn-icon ms-2" onclick="navigator.clipboard.writeText('${allCves.join(', ')}');showToast('CVE copiées !','success');" title="Copier les CVE"><i class="ti ti-copy"></i></button>`;
  }

  let anssiHtml = '';
  if (d.anssi_entries && d.anssi_entries.length > 0) {
    anssiHtml = `<div class="alert alert-warning mb-3"><div class="d-flex align-items-center mb-2"><i class="ti ti-building-fortress me-2"></i><strong>Mentions CERT-FR (ANSSI)</strong></div><ul class="mb-0">`;
    for (const e of d.anssi_entries) {
      const tc = e.type==='alerte'?'text-danger fw-bold':'';
      anssiHtml += `<li><span class="${tc}">${esc(e.type.toUpperCase())}</span> — <a href="${esc(e.url)}" target="_blank" rel="noopener">${esc(e.ref)}</a>: ${esc(e.title)} <small class="text-secondary">(${esc(e.date)})</small></li>`;
    }
    anssiHtml += '</ul></div>';
  }

  let kevHtml = '';
  if (d.kev_entries && d.kev_entries.length > 0) {
    kevHtml = `<div class="alert alert-danger mb-3"><div class="d-flex align-items-center mb-2"><i class="ti ti-flame me-2"></i><strong>Exploitation active connue (KEV)</strong></div><ul class="mb-0">`;
    for (const e of d.kev_entries) {
      const src = e.sources ? e.sources.join(', ') : '';
      kevHtml += `<li>${esc(e.cve)} — ajouté le ${esc(e.date_added)}${src?` (${esc(src)})`:''}</li>`;
    }
    kevHtml += '</ul></div>';
  }

  let refsHtml = '';
  if (d.euvd_references && d.euvd_references.length > 0) {
    const refs = d.euvd_references.filter(r=>r&&r.trim());
    if (refs.length > 0) {
      refsHtml = refs.slice(0,5).map(r=>`<a href="${esc(r)}" target="_blank" rel="noopener" class="d-block small text-truncate" style="max-width:400px">${esc(r)}</a>`).join('');
      if (refs.length > 5) refsHtml += `<span class="text-secondary small">+${refs.length-5} autres</span>`;
    }
  }

  const mainCve = allCves[0] || d.cve;
  let extLinks = '';
  if (mainCve && mainCve !== '—') {
    extLinks = `<div class="d-flex flex-wrap gap-1 mt-2">
      <a href="https://euvd.enisa.europa.eu/vulnerability/${encodeURIComponent(mainCve)}" target="_blank" class="btn btn-sm btn-outline-cyan"><i class="ti ti-external-link me-1"></i>EUVD</a>
      <a href="https://nvd.nist.gov/vuln/detail/${encodeURIComponent(mainCve)}" target="_blank" class="btn btn-sm btn-outline-secondary"><i class="ti ti-external-link me-1"></i>NVD</a>
      <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=${encodeURIComponent(mainCve)}" target="_blank" class="btn btn-sm btn-outline-secondary"><i class="ti ti-external-link me-1"></i>MITRE</a>
    </div>`;
  }

  let fpBanner = '';
  if (d.is_false_positive) {
    const who = esc(d.fp_by) || '?';
    const when = d.fp_at ? esc(d.fp_at.slice(0,10)) : '';
    const why = d.fp_reason ? ` · <em>${esc(d.fp_reason)}</em>` : '';
    fpBanner = `<div class="alert alert-warning mb-3">
      <div class="d-flex align-items-center"><i class="ti ti-eye-off me-2"></i>
        <strong>Faux positif</strong>&nbsp;— déclaré par <strong>${who}</strong>${when?` le ${when}`:''}${why}
      </div></div>`;
  }

  let ipBanner = '';
  const _sdBan = STATUS_MAP[d.status];
  if (_sdBan && d.status !== 'active') {
    const who = esc(d.status_by) || '';
    const when = d.status_at ? esc(d.status_at.slice(0,10)) : '';
    let metaTxt = '';
    if (who || when) metaTxt = `(${who ? 'par ' + who : ''}${who && when ? ' ' : ''}${when ? 'le ' + when : ''})`;
    let fieldsTxt = '';
    (_sdBan.fields || []).forEach(function (f) {
      const v = (d.status_data || {})[f.key];
      if (!v) return;
      const disp = (f.key === 'ticket_number') ? ticketLinkHtml(v) : esc(v);
      fieldsTxt += ' &middot; ' + esc(f.label) + ' : ' + disp;
    });
    ipBanner = `<div class="mb-3 p-2 rounded bg-${esc(_sdBan.color)}-lt">
      <div class="d-flex align-items-center">
        <i class="ti ${esc(_sdBan.icon)} me-2"></i>
        <span><strong>${esc(_sdBan.label)}</strong>${fieldsTxt}${metaTxt ? ' <span class="text-secondary">' + metaTxt + '</span>' : ''}</span>
      </div></div>`;
  }

  // Confiance de correspondance de version (CPE Watch)
  let confBanner = '';
  if (d.match_confidence === 'confirmed') {
    confBanner = `<div class="alert alert-green mb-3">
      <div class="d-flex align-items-center"><i class="ti ti-circle-check me-2"></i>
        <strong>Version confirmée</strong>&nbsp;— la version déclarée est prouvée dans la plage affectée.
      </div></div>`;
  } else if (d.match_confidence === 'unknown') {
    confBanner = `<div class="alert alert-orange mb-3">
      <div class="d-flex align-items-center"><i class="ti ti-help-circle me-2"></i>
        <strong>Impact indéterminé</strong>&nbsp;— le format de la plage de version EUVD n'a pas pu être interprété ; finding conservé par précaution (à vérifier manuellement).
      </div></div>`;
  }

  document.getElementById('mBody').innerHTML = `
    ${fpBanner}
    ${ipBanner}
    ${confBanner}
    ${scoreHtml}
    <div class="row g-2 mb-3">
      <div class="col-6 col-sm-3"><div class="text-secondary small">Hôte</div><code${d.hostname?` title="${esc(d.host)}"`:''}>${esc(d.hostname||d.host)}</code>${d.hostname?`<div class="text-secondary small">${esc(d.host)}</div>`:''}${hostTagsHtml?`<div class="mt-1">${hostTagsHtml}</div>`:''}</div>
      <div class="col-6 col-sm-3"><div class="text-secondary small">Port</div><code>${esc(d.port)}</code>${d.port_service?` <span class="text-muted small">(${esc(d.port_service)})</span>`:''}</div>
      <div class="col-6 col-sm-3"><div class="text-secondary small">CVSS</div><strong class="sev-${esc(sc)}">${parseFloat(d.cvss_base||d.severity||0).toFixed(1)}</strong></div>
      <div class="col-6 col-sm-3"><div class="text-secondary small">QoD</div>${esc(d.qod)||'—'}%</div>
      <div class="col-6 col-sm-3"><div class="text-secondary small">Menace</div>${esc(d.threat)}</div>
      <div class="col-6 col-sm-3"><div class="text-secondary small">NVT</div>${esc(d.nvt_name)||'—'}</div>
      <div class="col-6 col-sm-3"><div class="text-secondary small">Famille</div>${esc(d.family)||'—'}</div>
    </div>
    <div class="mb-3">
      <div class="text-secondary small mb-1">CVE (${allCves.length||(d.cve&&d.cve!=='—'?1:0)})</div>
      <div class="d-flex flex-wrap align-items-center">${cvesHtml}</div>${extLinks}
    </div>
    ${kevHtml}${anssiHtml}
    ${d.euvd_data?`<div class="alert alert-cyan mb-3">
      <div class="d-flex align-items-center mb-2"><i class="ti ti-database me-2"></i><strong>Données EUVD</strong>${d.euvd_id?`<span class="ms-2 badge bg-cyan-lt">${esc(d.euvd_id)}</span>`:''}</div>
      <div class="row g-2">
        <div class="col-6 col-sm-3"><div class="text-secondary small">Vendor</div><strong>${esc(d.euvd_vendor)||'—'}</strong></div>
        <div class="col-6 col-sm-3"><div class="text-secondary small">Product</div><strong>${esc(d.euvd_product)||'—'}</strong></div>
        <div class="col-6 col-sm-3"><div class="text-secondary small">EPSS</div>${epssHtml}</div>
        <div class="col-6 col-sm-3"><div class="text-secondary small">Exploité</div>${d.euvd_exploited?`<span class="badge bg-red-lt">Oui</span> <small class="text-secondary">${esc(d.euvd_exploited_since)}</small>`:'<span class="text-secondary">Non</span>'}</div>
        ${d.euvd_assigner?`<div class="col-6 col-sm-3"><div class="text-secondary small">CNA</div>${esc(d.euvd_assigner)}</div>`:''}
        ${d.euvd_base_score_vector?`<div class="col-12"><div class="text-secondary small">CVSS Vector</div><code class="small">${esc(d.euvd_base_score_vector)}</code></div>`:''}
      </div></div>`:''}
    ${d.euvd_description?`<h4 class="mt-3 mb-1 small text-secondary text-uppercase"><i class="ti ti-file-text me-1"></i>Description EUVD</h4><pre class="p-2 rounded border small" style="white-space:pre-wrap;max-height:150px;overflow-y:auto">${esc(d.euvd_description)}</pre>`:''}
    ${d.description?`<h4 class="mt-3 mb-1 small text-secondary text-uppercase"><i class="ti ti-file-text me-1"></i>Description NVT</h4><pre class="p-2 rounded border small" style="white-space:pre-wrap;max-height:150px;overflow-y:auto">${esc(d.description)}</pre>`:''}
    ${d.solution?`<h4 class="mt-3 mb-1 small text-secondary text-uppercase"><i class="ti ti-tool me-1"></i>Solution</h4><pre class="p-2 rounded border border-green small text-green" style="white-space:pre-wrap;max-height:120px;overflow-y:auto">${esc(d.solution)}</pre>`:''}
    ${refsHtml?`<h4 class="mt-3 mb-1 small text-secondary text-uppercase"><i class="ti ti-link me-1"></i>Références EUVD</h4><div class="p-2 rounded border small">${refsHtml}</div>`:''}
  `;

  renderStatusAction(d);
}

// ── Sélecteur de statut (pied de modale — config dynamique) ─────────
function statusFieldHtml(f, val) {
  val = val || '';
  const lbl = '<label class="form-label small text-secondary mb-1">' + esc(f.label) +
    (f.required ? ' <span class="text-danger">*</span>' : '') + '</label>';
  if (f.type === 'select') {
    const opts = ['<option value=""></option>'].concat((f.options || []).map(function (o) {
      return '<option value="' + esc(o) + '"' + (o === val ? ' selected' : '') + '>' + esc(o) + '</option>';
    })).join('');
    return lbl + '<select class="form-select form-select-sm status-field" data-key="' + esc(f.key) + '">' + opts + '</select>';
  }
  const t = f.type === 'date' ? 'date' : (f.type === 'number' ? 'number' : 'text');
  return lbl + '<input type="' + t + '" class="form-control form-control-sm status-field" data-key="' +
    esc(f.key) + '" value="' + esc(val) + '" placeholder="' + esc(f.label) + '">';
}

function renderStatusAction(d) {
  const el = document.getElementById('mStatusAction');
  if (!el) return;
  if (!canMarkFp() || !STATUS_DEFS.length) { el.innerHTML = ''; return; }

  function statusOptions(sel) {
    return STATUS_DEFS.map(function (s) {
      return '<option value="' + s.id + '"' + (s.id === sel ? ' selected' : '') + '>' + esc(s.label) + '</option>';
    }).join('');
  }
  function fieldCells(statusId) {
    const sd = STATUS_MAP[statusId] || {};
    // Pré-remplissage par clé : une valeur déjà saisie (même statut ou statut précédent)
    // est reprise quand le champ partage la même clé.
    return (sd.fields || []).map(function (f) {
      return '<div class="col-12 col-sm-6 col-lg-4">' +
        statusFieldHtml(f, (d.status_data && d.status_data[f.key]) || '') + '</div>';
    }).join('');
  }
  function paint(statusId) {
    el.innerHTML =
      '<div class="p-3 border-top">' +
        '<div class="row g-2">' +
          '<div class="col-12 col-sm-6 col-lg-4">' +
            '<label class="form-label small text-secondary mb-1">Statut</label>' +
            '<select id="stSel" class="form-select form-select-sm">' + statusOptions(statusId) + '</select>' +
          '</div>' +
          fieldCells(statusId) +
        '</div>' +
        '<div class="text-end mt-2">' +
          '<button type="button" class="btn btn-sm btn-primary" id="stApply"><i class="ti ti-check me-1"></i>Appliquer</button>' +
        '</div>' +
      '</div>';
    const sel = document.getElementById('stSel');
    sel.addEventListener('change', function () { paint(sel.value); });
    document.getElementById('stApply').addEventListener('click', function () { submitStatus(sel.value); });
  }
  paint(d.status || 'active');
}

async function submitStatus(statusId) {
  if (!currentFinding) return;
  const sd = STATUS_MAP[statusId] || {};
  const body = new URLSearchParams({ csrf_token: csrfToken(), status: statusId });
  body.append('finding_ids', currentFinding.id);
  let missing = null;
  document.querySelectorAll('#mStatusAction .status-field').forEach(function (inp) {
    const key = inp.dataset.key;
    const v = (inp.value || '').trim();
    const fdef = (sd.fields || []).find(function (f) { return f.key === key; });
    if (fdef && fdef.required && !v) missing = fdef.label;
    if (v) body.set('field_' + key, v);
  });
  if (missing) { showToast('Champ « ' + missing + ' » obligatoire.', 'danger'); return; }
  try {
    const resp = await fetch('/vulns/treat', {
      method: 'POST',
      headers: { 'X-CSRFToken': csrfToken(), 'Content-Type': 'application/x-www-form-urlencoded' },
      body: body.toString(),
    });
    const json = await resp.json();
    if (json.ok) { showToast('Statut mis à jour.', 'success'); setTimeout(function () { location.reload(); }, 700); }
    else showToast(esc(json.error || 'Échec'), 'danger');
  } catch (err) { showToast('Erreur : ' + esc(err.message), 'danger'); }
}

document.addEventListener('click', async e => {
  const btn = e.target.closest('.vuln-detail-btn');
  if (!btn) return;
  const id = btn.dataset.vulnId;
  if (!id) return;
  document.getElementById('mTitle').textContent = 'Chargement…';
  document.getElementById('mBadge').innerHTML = '';
  document.getElementById('mBody').innerHTML = '<div class="text-center py-4"><div class="spinner-border text-cyan"></div></div>';
  showModal();
  try {
    const resp = await fetch(`/vulns/detail/${encodeURIComponent(id)}`);
    if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
    const json = await resp.json();
    if (json.ok && json.vuln) fillModal(json.vuln);
    else document.getElementById('mBody').innerHTML = `<div class="alert alert-danger mb-0">${esc(json.error||'Introuvable')}</div>`;
  } catch(err) {
    document.getElementById('mBody').innerHTML = `<div class="alert alert-danger mb-0">Erreur : ${esc(err.message)}</div>`;
  }
});

// ══════════════════════════════
// Copier le corps du ticket
// ══════════════════════════════
async function generateTicketBody(btn) {
    const vendor   = btn.dataset.vendor || '—';
    const product  = btn.dataset.product || '—';
    const cves     = btn.dataset.cves ? btn.dataset.cves.split(',').filter(c=>c) : [];
    const severity = parseFloat(btn.dataset.severity) || 0;
    const score    = parseFloat(btn.dataset.score) || 0;
    const exploited= parseInt(btn.dataset.exploited) || 0;
    const anssiRefs= btn.dataset.anssi ? btn.dataset.anssi.split(',').filter(r=>r).map(r => {
      const [type,ref,url] = r.split('|'); return {type:type||'',ref:ref||'',url:url||''};
    }) : [];

    const sevLabel = severityLabel(severity);
    const today = new Date().toLocaleDateString('fr-FR');

    // ── Extraire les données par hôte depuis les lignes du tableau ──
    // Lecture via textContent des td cachées — aucun risque d'injection
    const tbody = btn.closest('tr.synth-product-group')?.nextElementSibling?.querySelector('tbody');
    const hostMap = {};
    if (tbody) {
      tbody.querySelectorAll('tr.synth-vuln-row').forEach(row => {
        const host      = row.dataset.host || '—';
        const hostname  = row.dataset.hostname || '';
        const port      = row.dataset.port || '—';
        const solution  = row.querySelector('.vuln-solution')?.textContent.trim() || '';
        const published = row.querySelector('.vuln-published')?.textContent.trim() || '';
        if (!hostMap[host]) {
          hostMap[host] = { host, hostname, port, solution, published };
        } else {
          if (published && (!hostMap[host].published || published > hostMap[host].published)) {
            hostMap[host].solution  = solution;
            hostMap[host].published = published;
          }
        }
      });
    }
    const hostRows = Object.values(hostMap);
    if (hostRows.length === 0) {
      const hostsRaw = btn.dataset.hosts ? btn.dataset.hosts.split(',').filter(h=>h) : [];
      hostsRaw.forEach(hp => {
        const [h, p] = hp.includes(':') ? hp.split(':') : [hp, '—'];
        hostRows.push({ host: h, hostname: '', port: p || '—', solution: '', published: '' });
      });
    }
    // Libellé hôte : « hostname (ip) » si connu, sinon seulement l'IP
    const hostLabel = (r) => r.hostname ? `${r.hostname} (${r.host})` : r.host;

    let refsHtml = '';
    if (cves.length > 0) {
      refsHtml += cves.map(c=>`<li><a href="https://euvd.enisa.europa.eu/vulnerability/${c}">EUVD - ${c}</a></li>`).join('');
    }
    if (anssiRefs.length > 0) refsHtml += anssiRefs.map(r=>`<li><a href="${r.url}">${r.type} - ${r.ref}</a></li>`).join('');
    if (!refsHtml) refsHtml = '<li><i>Aucune référence</i></li>';

    let refsPlain = cves.map(c=>`• EUVD: https://euvd.enisa.europa.eu/vulnerability/${c}`).join('\n');
    if (anssiRefs.length > 0) { if (refsPlain) refsPlain+='\n'; refsPlain += anssiRefs.map(r=>`• ${r.type} ${r.ref}: ${r.url}`).join('\n'); }
    if (!refsPlain) refsPlain = '• Aucune référence';

    let secImpact = '<span style="color:#d63939"><i>À compléter</i></span>', secPlain = 'À compléter';
    if (exploited > 0) { secImpact = secPlain = 'Exploitation active connue — correction urgente recommandée'; }
    else if (anssiRefs.some(r=>r.type==='ALERTE')) { secImpact = secPlain = 'Mentionné dans une alerte CERT-FR — vigilance accrue'; }
    else if (anssiRefs.some(r=>r.type==='AVIS'))   { secImpact = secPlain = 'Mentionné dans un avis CERT-FR'; }

    // ── Tableau plan d'action HTML ──
    const planRowsHtml = hostRows.map(r => {
      const sol = r.solution ? r.solution.substring(0, 300) + (r.solution.length > 300 ? '…' : '') : '<span style="color:#d63939"><i>À compléter</i></span>';
      return `<tr><td><code>${esc(hostLabel(r))}</code></td><td>${r.port}</td><td>${sol}</td></tr>`;
    }).join('');

    // ── Tableau plan d'action texte ──
    const colW = Math.max(20, ...hostRows.map(r => hostLabel(r).length));
    const planRowsPlain = hostRows.map(r => {
      const sol = r.solution ? r.solution.replace(/\n/g,' ').substring(0, 150) + (r.solution.length > 150 ? '…' : '') : 'À compléter';
      return `  ${hostLabel(r).padEnd(colW)} ${r.port.padEnd(10)} ${sol}`;
    }).join('\n');

    const htmlContent = `<h3>Vulnérabilité</h3><ul>
<li><b>CVE</b> (${cves.length}) : ${cves.length>0?cves.join(', '):'<i>Aucune CVE identifiée</i>'}</li>
<li><b>Produit</b> : ${product}</li><li><b>Éditeur</b> : ${vendor}</li>
<li><b>Gravité max</b> : ${severity.toFixed(1)} (${sevLabel})</li>
<li><b>Score priorisation</b> : ${score.toFixed(0)}/100</li>
${exploited>0?`<li><b>⚠️ Exploitation active</b> : ${exploited} vulnérabilité(s) exploitée(s)</li>`:''}
${anssiRefs.length>0?`<li><b>🏛️ CERT-FR</b> : ${anssiRefs.length} référence(s) ANSSI</li>`:''}
</ul>
<h3>Systèmes impactés</h3>
<table border="1" cellpadding="5" cellspacing="0"><tr><th>Serveur</th><th>Port</th></tr>
${hostRows.map(r=>`<tr><td>${esc(hostLabel(r))}</td><td>${r.port}</td></tr>`).join('')}
</table>
<h3>Impact</h3><ul><li><b>Fonctionnel</b> : <span style="color:#d63939"><i>À compléter</i></span></li><li><b>Sécurité</b> : ${secImpact}</li></ul>
<h3>Plan d'action</h3>
<table border="1" cellpadding="5" cellspacing="0">
<tr><th>Hôte</th><th>Port</th><th>Action corrective</th></tr>
${planRowsHtml}
<tr><td colspan="3"><span style="color:#d63939"><i>À compléter si nécessaire</i></span></td></tr>
</table>
<h3>Dates</h3><ul><li><b>Date du rapport</b> : ${today}</li><li><b>Déploiement prévu</b> : <span style="color:#d63939"><i>À compléter</i></span></li></ul>
<h3>Références</h3><ul>${refsHtml}</ul>`;

    const plainContent = `══════════════════════════════════════
VULNÉRABILITÉ
══════════════════════════════════════
CVE (${cves.length}) : ${cves.length>0?cves.join(', '):'Aucune CVE identifiée'}
Produit     : ${product} / Éditeur : ${vendor}
Gravité max : ${severity.toFixed(1)} (${sevLabel}) / Score : ${score.toFixed(0)}/100
${exploited>0?`⚠️ Exploitation active : ${exploited} vuln(s) exploitée(s)`:''}
${anssiRefs.length>0?`🏛️ CERT-FR : ${anssiRefs.length} référence(s)`:''}

SYSTÈMES IMPACTÉS
${hostRows.map(r=>`• ${hostLabel(r)} : ${r.port}`).join('\n')}

IMPACT : ${secPlain}

PLAN D'ACTION
${'  ' + 'Hôte'.padEnd(colW) + ' ' + 'Port'.padEnd(10) + ' Action corrective'}
${'  ' + '─'.repeat(Math.max(70, colW + 25))}
${planRowsPlain}

DATES : Rapport ${today} / Déploiement : [À compléter]

RÉFÉRENCES
${refsPlain}`;

    try {
      await navigator.clipboard.write([new ClipboardItem({
        'text/html': new Blob([htmlContent], {type:'text/html'}),
        'text/plain': new Blob([plainContent], {type:'text/plain'})
      })]);
      showToast('Corps du ticket copié !', 'success');
    } catch(err) {
      try { await navigator.clipboard.writeText(plainContent); showToast('Copié en texte brut', 'warning'); }
      catch(e2) { showToast('Erreur de copie : ' + e2.message, 'danger'); }
    }
}

// ══════════════════════════════
// Traitement (modale produit — action en masse)
// ══════════════════════════════
let currentTreatBtn = null;

document.querySelectorAll('.treat-btn').forEach(btn => {
  btn.addEventListener('click', (e) => { e.stopPropagation(); openTreatModal(btn); });
});

function renderTreatFields(statusId, presetTicket) {
  const wrap = document.getElementById('treatFields');
  if (!wrap) return;
  const sd = STATUS_MAP[statusId] || {};
  wrap.innerHTML = (sd.fields || []).map(function (f) {
    const val = (f.key === 'ticket_number' && presetTicket) ? presetTicket : '';
    let inner;
    if (f.type === 'select') {
      const opts = ['<option value=""></option>'].concat((f.options || []).map(function (o) {
        return '<option value="' + esc(o) + '">' + esc(o) + '</option>';
      })).join('');
      inner = '<select class="form-select form-select-sm treat-field" data-key="' + esc(f.key) + '">' + opts + '</select>';
    } else {
      const t = f.type === 'date' ? 'date' : (f.type === 'number' ? 'number' : 'text');
      inner = '<input type="' + t + '" class="form-control form-control-sm treat-field" data-key="' + esc(f.key) +
        '" value="' + esc(val) + '" placeholder="' + esc(f.label) + '">';
    }
    return '<div class="col-12 col-sm-6"><label class="form-label small mb-1">' + esc(f.label) +
      (f.required ? ' <span class="text-danger">*</span>' : '') + '</label>' + inner + '</div>';
  }).join('');
}

function openTreatModal(btn) {
  currentTreatBtn = btn;
  const ids = (btn.dataset.findingIds || '').split(',').filter(Boolean);
  const vendor = btn.dataset.vendor && btn.dataset.vendor !== '—' ? btn.dataset.vendor + ' / ' : '';
  document.getElementById('treatProduct').textContent = vendor + (btn.dataset.product || '—');
  document.getElementById('treatCount').textContent = ids.length;
  const sel = document.getElementById('treatStatus');
  if (sel) {
    sel.innerHTML = STATUS_DEFS.map(function (s) { return '<option value="' + s.id + '">' + esc(s.label) + '</option>'; }).join('');
    renderTreatFields(sel.value, btn.dataset.ticket || '');
  }
  const trigger = document.getElementById('treatModalTrigger');
  if (trigger) trigger.click();
}

async function postTreat(ids, status, data) {
  const body = new URLSearchParams({ csrf_token: csrfToken(), status });
  ids.forEach(id => body.append('finding_ids', id));
  Object.keys(data || {}).forEach(function (k) { if (data[k]) body.set('field_' + k, data[k]); });
  const resp = await fetch('/vulns/treat', {
    method: 'POST',
    headers: { 'X-CSRFToken': csrfToken(), 'Content-Type': 'application/x-www-form-urlencoded' },
    body: body.toString(),
  });
  let j = {};
  try { j = await resp.json(); } catch (e) {}
  if (!resp.ok || !j.ok) throw new Error(j.error || ('HTTP ' + resp.status));
  return j;
}

(function bindTreatActions() {
  const sel = document.getElementById('treatStatus');
  const applyBtn = document.getElementById('treatApply');
  const copyBtn = document.getElementById('treatCopyTicket');
  function ids() { return currentTreatBtn ? (currentTreatBtn.dataset.findingIds || '').split(',').filter(Boolean) : []; }
  if (sel) sel.addEventListener('change', function () {
    renderTreatFields(sel.value, currentTreatBtn ? currentTreatBtn.dataset.ticket : '');
  });
  if (applyBtn) applyBtn.addEventListener('click', async function () {
    if (!ids().length) { showToast('Aucune vulnérabilité.', 'danger'); return; }
    const statusId = sel ? sel.value : '';
    const sd = STATUS_MAP[statusId] || {};
    const data = {};
    let missing = null;
    document.querySelectorAll('#treatFields .treat-field').forEach(function (inp) {
      const key = inp.dataset.key; const v = (inp.value || '').trim();
      const fdef = (sd.fields || []).find(function (f) { return f.key === key; });
      if (fdef && fdef.required && !v) missing = fdef.label;
      if (v) data[key] = v;
    });
    if (missing) { showToast('Champ « ' + missing + ' » obligatoire.', 'danger'); return; }
    try {
      const j = await postTreat(ids(), statusId, data);
      showToast(j.updated + ' vulnérabilité(s) mise(s) à jour.', 'success');
      setTimeout(() => location.reload(), 700);
    } catch (err) { showToast('Erreur : ' + esc(err.message), 'danger'); }
  });
  if (copyBtn) copyBtn.addEventListener('click', () => { if (currentTreatBtn) generateTicketBody(currentTreatBtn); });
})();

// Modèle d'URL de ticket configuré (Paramètres) → lien cliquable
function ticketUrlTemplate() {
  const c = document.getElementById('gmpilot-vulns-config');
  return c ? (c.dataset.ticketUrl || '') : '';
}
function ticketLinkHtml(ticket) {
  if (!ticket) return '';
  const tpl = ticketUrlTemplate();
  if (tpl && tpl.indexOf('<id>') !== -1) {
    const href = tpl.replace('<id>', encodeURIComponent(ticket));
    return `<a href="${esc(href)}" target="_blank" rel="noopener">${esc(ticket)}</a>`;
  }
  return esc(ticket);
}

// ── Activation initiale ──────────────────────────────────────────
// Placée en fin de fichier : activateTab() appelle updateFiltersButton() qui lit
// les const synth* déclarées plus haut → il faut qu'elles soient initialisées.
let _savedTab = localStorage.getItem(TAB_KEY);
if (!['grouped','tickets','resolved'].includes(_savedTab)) _savedTab = 'grouped';
activateTab(_savedTab);
setTimeout(applySynthFilters, 0);

