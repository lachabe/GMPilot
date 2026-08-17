/* scoring.js — GMPilot scoring configuration editor */
(function() {
  const cfg = document.getElementById('gmpilot-scoring-config');
  if (!cfg) return;

  // ── Config depuis data-* ──
  const CAN_EDIT       = cfg.dataset.canEdit === 'true';
  const SCORING_NAME   = cfg.dataset.scoringName || 'Score contextualisé';
  const PREVIEW_URL    = cfg.dataset.previewUrl;
  const SAVE_URL       = cfg.dataset.saveUrl;
  const VALIDATE_URL   = cfg.dataset.validateUrl;
  const AUTO_URL       = cfg.dataset.autoFormulaUrl;
  const CSRF_TOKEN     = document.body.dataset.csrfToken || '';

  // Lire criteria et formula depuis <script type="application/json">
  let criteria = JSON.parse(
    (document.getElementById('gmpilot-scoring-criteria') || {textContent:'[]'}).textContent || '[]'
  );
  const formulaEl = document.getElementById('formula-input');
  // Initialiser la valeur du champ formule depuis le JSON
  const initialFormula = JSON.parse(
    (document.getElementById('gmpilot-scoring-formula') || {textContent:'""'}).textContent || '""'
  );
  if (formulaEl && initialFormula) formulaEl.value = initialFormula;

  // ── CSRF fetch helper ──
  function fetchJSON(url, body) {
    return fetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-CSRFToken': CSRF_TOKEN },
      body: JSON.stringify(body)
    });
  }

  // ── Utilitaires ──
  function esc(s) {
    if (!s) return '';
    var d = document.createElement('div');
    d.textContent = s;
    return d.innerHTML;
  }

  // ── Rendu des critères ──
  function renderCriteria() {
    var container = document.getElementById('criteria-container');
    if (!criteria.length) {
      container.innerHTML = '<div class="p-3 text-secondary small text-center">Aucun critère. Cliquez sur Ajouter.</div>';
      return;
    }
    container.innerHTML = criteria.map(function(c, i) {
      return '<div class="criterion-card" data-idx="' + i + '">' +
        '<div class="criterion-header">' +
          '<span class="drag-handle ti ti-grip-vertical"></span>' +
          '<span class="fw-semibold">' + esc(c.label || c.id) + '</span>' +
          '<code class="small text-secondary ms-1">' + esc(c.id) + '</code>' +
          '<span class="badge bg-secondary-lt ms-1">' + esc(c.source) + '</span>' +
          '<span class="badge bg-azure-lt ms-1">poids ' + c.weight + '</span>' +
          '<div class="ms-auto d-flex gap-1">' +
            (CAN_EDIT ?
              '<button class="btn btn-ghost-secondary btn-xs btn-icon" onclick="moveCriterion(' + i + ',-1)" title="Monter"><i class="ti ti-arrow-up"></i></button>' +
              '<button class="btn btn-ghost-secondary btn-xs btn-icon" onclick="moveCriterion(' + i + ',1)" title="Descendre"><i class="ti ti-arrow-down"></i></button>' +
              '<button class="btn btn-ghost-primary btn-xs btn-icon" onclick="editCriterion(' + i + ')" title="Modifier"><i class="ti ti-pencil"></i></button>' +
              '<button class="btn btn-ghost-danger btn-xs btn-icon" onclick="deleteCriterion(' + i + ')" title="Supprimer"><i class="ti ti-trash"></i></button>'
            : '') +
          '</div>' +
        '</div>' +
        '<div class="criterion-body">' + renderValues(c) + '</div>' +
      '</div>';
    }).join('');
  }

  function renderValues(c) {
    var vals = c.values || [];
    if (!vals.length) return '<span class="text-secondary small">Aucune règle</span>';
    return vals.map(function(v) {
      var label = '';
      if ('default' in v)     label = '<span class="badge bg-secondary-lt">défaut</span>';
      else if (v.match === true)  label = '<span class="badge bg-green-lt">présent / vrai</span>';
      else if (v.match === false) label = '<span class="badge bg-red-lt">absent / faux</span>';
      else if (v.match === 'alerte') label = '<span class="badge badge-high">Alerte</span>';
      else if (v.match === 'avis')   label = '<span class="badge badge-medium">Avis</span>';
      else if (v.threshold !== undefined) label = '<span class="badge bg-blue-lt">≥ ' + v.threshold + '</span>';
      else label = '<span class="badge bg-secondary-lt">' + JSON.stringify(v.match) + '</span>';
      var val = 'default' in v ? v.default : v.value;
      return '<span class="me-2 small">' + label + ' → <strong>' + val + '</strong></span>';
    }).join('');
  }

  // ── Actions critères (exposées globalement pour les onclick) ──
  window.moveCriterion = function(idx, dir) {
    var newIdx = idx + dir;
    if (newIdx < 0 || newIdx >= criteria.length) return;
    var tmp = criteria[idx]; criteria[idx] = criteria[newIdx]; criteria[newIdx] = tmp;
    renderCriteria();
  };

  window.deleteCriterion = function(idx) {
    if (!confirm('Supprimer le critère « ' + (criteria[idx].label || criteria[idx].id) + ' » ?')) return;
    criteria.splice(idx, 1);
    renderCriteria();
  };

  window.editCriterion = function(idx) {
    editingIdx = idx;
    var c = criteria[idx];
    document.getElementById('criterionModalTitle').textContent = 'Modifier le critère';
    document.getElementById('btn-save-criterion').textContent = 'Enregistrer';
    document.getElementById('c-id').value = c.id || '';
    document.getElementById('c-id').readOnly = true;
    document.getElementById('c-label').value = c.label || '';
    document.getElementById('c-weight').value = c.weight != null ? c.weight : 1;
    document.getElementById('c-source').value = c.source || 'severity';
    document.getElementById('c-normalize').value = c.normalize || 'scale_0_1';
    document.getElementById('c-tag-name').value = c.tag_name || '';
    document.getElementById('c-description').value = c.description || '';
    updateSourceUI();
    renderValuesEditor(c.values || []);
    document.getElementById('criterionModalTrigger').click();
  };

  // ── Modal ──
  var editingIdx = -1;

  var addBtn = document.getElementById('btn-add-criterion');
  if (addBtn) addBtn.addEventListener('click', function() {
    editingIdx = -1;
    document.getElementById('criterionModalTitle').textContent = 'Nouveau critère';
    document.getElementById('btn-save-criterion').textContent = 'Ajouter';
    document.getElementById('c-id').value = '';
    document.getElementById('c-id').readOnly = false;
    document.getElementById('c-label').value = '';
    document.getElementById('c-weight').value = 1;
    document.getElementById('c-source').value = 'severity';
    document.getElementById('c-normalize').value = 'scale_0_1';
    document.getElementById('c-tag-name').value = '';
    document.getElementById('c-description').value = '';
    updateSourceUI();
    renderValuesEditor([]);
    document.getElementById('criterionModalTrigger').click();
  });

  // ── UI dynamique source ──
  function updateSourceUI() {
    var source = document.getElementById('c-source').value;
    document.getElementById('c-normalize-row').style.display = ['severity','epss','qod'].includes(source) ? '' : 'none';
    document.getElementById('c-tag-row').style.display = source === 'host_tag' ? '' : 'none';
    var helps = {
      severity: 'Scale 0-1 : score/10. Seuils : définir des valeurs par palier CVSS.',
      epss:     'Scale 0-1 : valeur EPSS directe (0-1). Seuils : paliers personnalisés.',
      qod:      'Scale 0-1 : qod/100.',
      kev:      'match: true → CVE dans le KEV. match: false → absente.',
      anssi:    'match: alerte / avis / défaut automatiques.',
      host_tag: "match: true → tag présent sur l'hôte. match: false → absent.",
    };
    document.getElementById('c-values-help').textContent = helps[source] || '';
    var cur = document.getElementById('c-values-container');
    if (!cur.children.length) {
      var defaults = {
        kev:      [{match:true,value:1.0},{default:0.1}],
        anssi:    [{match:'alerte',value:1.0},{match:'avis',value:0.5},{default:0.1}],
        host_tag: [{match:true,value:1.0},{default:0.3}],
      };
      renderValuesEditor(defaults[source] || []);
    }
  }
  window.updateSourceUI = updateSourceUI;

  // ── Éditeur de valeurs ──
  function renderValuesEditor(vals) {
    var source = document.getElementById('c-source').value;
    var container = document.getElementById('c-values-container');

    function sliderRow(id, label, val) {
      return '<div class="value-row">' + label +
        '<input type="range" class="form-range" id="' + id + '" min="0" max="1" step="0.05" value="' + val + '" ' +
        'oninput="document.getElementById(\'' + id + '-n\').textContent=parseFloat(this.value).toFixed(2)"/>' +
        '<span id="' + id + '-n" class="text-center fw-bold">' + parseFloat(val).toFixed(2) + '</span><span></span></div>';
    }

    if (source === 'anssi') {
      var al = vals.find(function(v){return v.match==='alerte';}) || {match:'alerte',value:1.0};
      var av = vals.find(function(v){return v.match==='avis';})   || {match:'avis',value:0.5};
      var df = vals.find(function(v){return 'default' in v;})     || {default:0.1};
      container.innerHTML =
        sliderRow('val-alerte', '<span class="badge badge-high">Alerte</span>', al.value) +
        sliderRow('val-avis',   '<span class="badge badge-medium">Avis</span>', av.value) +
        sliderRow('val-def',    '<span class="badge bg-secondary-lt">Défaut</span>', df.default != null ? df.default : 0.1);
      return;
    }
    if (source === 'kev' || source === 'host_tag') {
      var pr = vals.find(function(v){return v.match===true;}) || {match:true,value:1.0};
      var df = vals.find(function(v){return 'default' in v;}) || {default:0.1};
      container.innerHTML =
        sliderRow('val-true', '<span class="badge bg-green-lt">Présent/Vrai</span>', pr.value) +
        sliderRow('val-def',  '<span class="badge bg-secondary-lt">Défaut</span>', df.default != null ? df.default : 0.1);
      return;
    }
    var normalize = document.getElementById('c-normalize').value;
    if (normalize === 'scale_0_1') {
      container.innerHTML = '<div class="text-secondary small">Normalisation linéaire — aucune règle à définir.</div>';
      return;
    }
    var thresholds = vals.filter(function(v){return v.threshold !== undefined;});
    var df = vals.find(function(v){return 'default' in v;}) || {default:0.0};
    var html = thresholds.map(function(v) {
      return '<div class="value-row threshold-row">' +
        '<span class="small text-secondary">≥</span>' +
        '<input type="number" class="form-control form-control-sm thr-val" value="' + v.threshold + '" min="0" max="10" step="0.1"/>' +
        '<input type="number" class="form-control form-control-sm thr-score" value="' + v.value + '" min="0" max="1" step="0.05"/>' +
        '<button class="btn btn-ghost-danger btn-xs btn-icon" onclick="removeThreshold(this)"><i class="ti ti-x"></i></button>' +
      '</div>';
    }).join('');
    html += '<div class="value-row"><span class="badge bg-secondary-lt">Défaut</span>' +
      '<input type="number" class="form-control form-control-sm" id="val-def-num" value="' + (df.default || 0) + '" min="0" max="1" step="0.05"/>' +
      '<span></span><span></span></div>';
    html += '<button class="btn btn-ghost-secondary btn-sm mt-1" onclick="addThreshold()"><i class="ti ti-plus me-1"></i>Seuil</button>';
    container.innerHTML = html;
  }

  window.addThreshold = function() {
    var container = document.getElementById('c-values-container');
    var btn = container.querySelector('button[onclick="addThreshold()"]');
    var row = document.createElement('div');
    row.className = 'value-row threshold-row';
    row.innerHTML = '<span class="small text-secondary">≥</span>' +
      '<input type="number" class="form-control form-control-sm thr-val" min="0" max="10" step="0.1" placeholder="seuil"/>' +
      '<input type="number" class="form-control form-control-sm thr-score" value="0.5" min="0" max="1" step="0.05"/>' +
      '<button class="btn btn-ghost-danger btn-xs btn-icon" onclick="removeThreshold(this)"><i class="ti ti-x"></i></button>';
    container.insertBefore(row, btn);
  };

  window.removeThreshold = function(btn) { btn.closest('.threshold-row').remove(); };

  function readValues() {
    var source = document.getElementById('c-source').value;
    var normalize = document.getElementById('c-normalize').value;
    if (source === 'anssi') return [
      {match:'alerte', value: parseFloat(document.getElementById('val-alerte').value)},
      {match:'avis',   value: parseFloat(document.getElementById('val-avis').value)},
      {default: parseFloat(document.getElementById('val-def').value)}
    ];
    if (source === 'kev' || source === 'host_tag') return [
      {match:true, value: parseFloat(document.getElementById('val-true').value)},
      {default: parseFloat(document.getElementById('val-def').value)}
    ];
    if (normalize === 'scale_0_1') return [];
    var vals = [];
    document.querySelectorAll('.threshold-row').forEach(function(row) {
      var thr   = parseFloat(row.querySelector('.thr-val').value);
      var score = parseFloat(row.querySelector('.thr-score').value);
      if (!isNaN(thr) && !isNaN(score)) vals.push({threshold:thr, value:score});
    });
    vals.sort(function(a,b){return b.threshold - a.threshold;});
    var defEl = document.getElementById('val-def-num');
    if (defEl) vals.push({default: parseFloat(defEl.value) || 0});
    return vals;
  }

  // ── Save criterion ──
  var saveCriterionBtn = document.getElementById('btn-save-criterion');
  if (saveCriterionBtn) saveCriterionBtn.addEventListener('click', function() {
    var id     = document.getElementById('c-id').value.trim().replace(/\s+/g,'_');
    var label  = document.getElementById('c-label').value.trim();
    var weight = parseInt(document.getElementById('c-weight').value) || 1;
    var source = document.getElementById('c-source').value;
    var normalize = document.getElementById('c-normalize').value;
    var tagName   = document.getElementById('c-tag-name').value.trim();
    var desc      = document.getElementById('c-description').value.trim();
    if (!id || !label) { alert('ID et Label requis.'); return; }
    if (editingIdx === -1 && criteria.find(function(c){return c.id===id;})) {
      alert('Un critère avec l\'ID « ' + id + ' » existe déjà.'); return;
    }
    var criterion = {id:id, label:label, description:desc, source:source, weight:weight, values:readValues()};
    if (['severity','epss','qod'].includes(source)) criterion.normalize = normalize;
    if (source === 'host_tag') criterion.tag_name = tagName;
    if (editingIdx === -1) criteria.push(criterion);
    else criteria[editingIdx] = criterion;
    document.getElementById('criterionModalClose').click();
    renderCriteria();
  });

  var srcEl = document.getElementById('c-source');
  if (srcEl) srcEl.addEventListener('change', function() {
    document.getElementById('c-values-container').innerHTML = '';
    updateSourceUI();
  });
  var normEl = document.getElementById('c-normalize');
  if (normEl) normEl.addEventListener('change', function() {
    document.getElementById('c-values-container').innerHTML = '';
    renderValuesEditor([]);
  });

  // ── Formule ──
  var autoBtn = document.getElementById('btn-auto-formula');
  if (autoBtn) autoBtn.addEventListener('click', function() {
    fetchJSON(AUTO_URL, {criteria:criteria})
      .then(function(r){return r.json();})
      .then(function(data) {
        if (data.ok) {
          formulaEl.value = data.formula;
          var st = document.getElementById('formula-status');
          st.textContent = 'Formule régénérée — poids total : ' + data.total_weight;
          st.className = 'formula-status text-success';
        }
      });
  });

  var validateBtn = document.getElementById('btn-validate-formula');
  if (validateBtn) validateBtn.addEventListener('click', function() {
    fetchJSON(VALIDATE_URL, {formula:formulaEl.value, criteria:criteria})
      .then(function(r){return r.json();})
      .then(function(data) {
        var st = document.getElementById('formula-status');
        st.textContent = data.message;
        st.className = 'formula-status ' + (data.ok ? 'text-success' : 'text-danger');
      });
  });

  // ── Prévisualisation ──
  var previewBtn = document.getElementById('btn-preview');
  if (previewBtn) previewBtn.addEventListener('click', function() {
    var container = document.getElementById('preview-container');
    container.innerHTML = '<div class="p-3 text-center"><div class="spinner-border spinner-border-sm text-cyan"></div></div>';
    fetchJSON(PREVIEW_URL, {criteria:criteria, formula:formulaEl.value})
      .then(function(r){return r.json();})
      .then(function(data) {
        if (!data.ok) { container.innerHTML = '<div class="p-3 text-danger small">' + data.error + '</div>'; return; }
        if (!data.results.length) { container.innerHTML = '<div class="p-3 text-secondary small">Cache vulns vide.</div>'; return; }
        var rows = data.results.map(function(r) {
          var sc = r.score;
          var cls = sc>=70?'badge-critical':sc>=50?'badge-high':sc>=30?'badge-medium':'badge-low';
          var sevCls = r.severity>=9?'badge-critical':r.severity>=7?'badge-high':r.severity>=4?'badge-medium':r.severity>0?'badge-low':'badge-log';
          var details = Object.entries(r.details||{}).map(function(e){
            return '<span class="badge bg-secondary-lt me-1">' + e[0] + ':' + Math.round(e[1]*100) + '%</span>';
          }).join('');
          return '<tr><td class="text-truncate" style="max-width:160px" title="' + esc(r.name) + '">' + esc(r.name) + '</td>' +
            '<td><code class="small">' + esc(r.host) + '</code></td>' +
            '<td><span class="badge ' + sevCls + '">' + r.severity.toFixed(1) + '</span></td>' +
            '<td><span class="score-pill ' + cls + '">' + sc + '</span></td>' +
            '<td class="small">' + details + '</td></tr>';
        }).join('');
        container.innerHTML = '<table class="table table-vcenter table-sm preview-table mb-0">' +
          '<thead><tr><th>Vuln</th><th>Hôte</th><th>CVSS</th><th>Score</th><th>Détails</th></tr></thead>' +
          '<tbody>' + rows + '</tbody></table>';
      })
      .catch(function(e) { container.innerHTML = '<div class="p-3 text-danger small">Erreur : ' + e.message + '</div>'; });
  });

  // ── Sauvegarde globale ──
  var saveBtn = document.getElementById('btn-save');
  if (saveBtn) saveBtn.addEventListener('click', function() {
    var formula = formulaEl.value.trim();
    if (!formula) { alert('La formule est vide.'); return; }
    fetchJSON(VALIDATE_URL, {formula:formula, criteria:criteria})
      .then(function(r){return r.json();})
      .then(function(valData) {
        if (!valData.ok) {
          alert('Formule invalide : ' + valData.message);
          var st = document.getElementById('formula-status');
          st.textContent = valData.message;
          st.className = 'formula-status text-danger';
          return;
        }
        saveBtn.disabled = true;
        saveBtn.innerHTML = '<div class="spinner-border spinner-border-sm me-1"></div>Enregistrement...';
        fetchJSON(SAVE_URL, {name:SCORING_NAME, criteria:criteria, formula:formula})
          .then(function(r){return r.json();})
          .then(function(data) {
            if (data.ok) {
              saveBtn.innerHTML = '<i class="ti ti-circle-check me-1"></i>Enregistré';
              saveBtn.className = 'btn btn-success btn-sm';
              setTimeout(function() {
                saveBtn.innerHTML = '<i class="ti ti-device-floppy me-1"></i>Enregistrer';
                saveBtn.className = 'btn btn-primary btn-sm';
                saveBtn.disabled = false;
              }, 2000);
            } else {
              alert('Erreur : ' + data.error);
              saveBtn.disabled = false;
              saveBtn.innerHTML = '<i class="ti ti-device-floppy me-1"></i>Enregistrer';
            }
          });
      });
  });

  // ── Init ──
  renderCriteria();
})();
