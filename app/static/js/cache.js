/* cache.js — GMPilot cache management polling */
(function() {
  const config = document.getElementById('gmpilot-cache-config');
  if (!config) return;
  const STATUS_URL = config.dataset.statusUrl;
  const META_URL   = config.dataset.metaUrl;
  const CPE_TABLE_URL = config.dataset.cpeTableUrl;

  const pollingIntervals = {};
  const runningTasks = new Set();
  let cpeTableTick = 0;

  // Rafraîchit la table « Surveillance logicielle » (date + statut par produit)
  // sans recharger la page.
  function refreshCpeWatchTable() {
    if (!CPE_TABLE_URL) return;
    fetch(CPE_TABLE_URL)
      .then(function(r) { return r.json(); })
      .then(function(data) {
        (data.items || []).forEach(function(it) {
          var row = document.querySelector('tr[data-sw-id="' + it.id + '"]');
          if (!row) return;
          var lc = row.querySelector('.cpe-last-checked');
          if (lc) lc.textContent = it.last_checked
            ? it.last_checked.slice(0, 16).replace('T', ' ') : '—';
          var st = row.querySelector('.cpe-status');
          if (st) {
            if (!it.last_checked) st.innerHTML = '<span class="badge bg-secondary-lt">jamais</span>';
            else if (it.last_complete) st.innerHTML = '<span class="badge bg-green-lt">complet</span>';
            else st.innerHTML = '<span class="badge bg-orange-lt">partiel</span>';
          }
        });
      })
      .catch(function() {});
  }

  function showToast(message, type) {
    type = type || 'info';
    const container = document.getElementById('toast-container');
    const id = 'toast-' + Date.now();
    const icons = {
      success: 'ti-circle-check',
      danger:  'ti-alert-triangle',
      warning: 'ti-exclamation-circle',
      info:    'ti-info-circle'
    };
    const label = type === 'success' ? 'Succes' : type === 'danger' ? 'Erreur' : 'Info';
    const icon = icons[type] || icons.info;
    container.insertAdjacentHTML('beforeend',
      '<div id="' + id + '" class="toast show" role="alert">' +
        '<div class="toast-header">' +
          '<span class="avatar avatar-xs bg-' + type + ' me-2"><i class="ti ' + icon + '"></i></span>' +
          '<strong class="me-auto">' + label + '</strong>' +
          '<button type="button" class="ms-2 btn-close" onclick="this.closest(\'.toast\').remove()"></button>' +
        '</div>' +
        '<div class="toast-body">' + message + '</div>' +
      '</div>');
    setTimeout(function() { var el = document.getElementById(id); if (el) el.remove(); }, 5000);
  }

  function getStatusUrl(taskType) {
    return STATUS_URL.replace('__TYPE__', taskType);
  }

  function getCard(taskType) {
    var card = document.getElementById(taskType + '-card');
    if (!card) {
      var els = document.querySelectorAll('[data-task="' + taskType + '"]');
      for (var i = 0; i < els.length; i++) {
        if (els[i].classList.contains('card')) { card = els[i]; break; }
      }
    }
    return card;
  }

  function lockCard(taskType) {
    runningTasks.add(taskType);
    var card = getCard(taskType);
    if (card) {
      card.classList.add('task-running');
      card.querySelectorAll('button[type="submit"]').forEach(function(btn) { btn.disabled = true; });
    }
    var statusDiv = document.getElementById(taskType + '-status');
    if (statusDiv) {
      statusDiv.classList.remove('d-none', 'alert-success', 'alert-danger');
      statusDiv.classList.add('alert-info');
    }
  }

  function unlockCard(taskType) {
    // Ne pas supprimer runningTasks ici — géré dans updateTaskStatus après le check finished
    var card = getCard(taskType);
    if (card) {
      card.classList.remove('task-running');
      card.querySelectorAll('button[type="submit"]').forEach(function(btn) { btn.disabled = false; });
    }
  }

  function refreshCardMeta(taskType) {
    if (!META_URL) return;
    fetch(META_URL)
      .then(function(r) { return r.json(); })
      .then(function(cards) {
        Object.keys(cards).forEach(function(key) {
          if (taskType !== 'gmp_all' && key !== taskType) return;
          var data = cards[key];

          function updateBadge(card) {
            if (!card || !data.badge) return;
            var badge = card.querySelector('.cache-badge');
            if (badge) {
              badge.innerHTML = '<span class="badge ' + data.badge.cls + '">' +
                '<i class="ti ' + data.badge.icon + ' me-1"></i>' + data.badge.text + '</span>';
            }
          }

          function upd(sel, val) {
            var el = document.querySelector(sel);
            if (el) el.textContent = val;
          }

          // CVE
          if (key === 'cve') {
            upd('[data-field="cve-count"]', data.count);
            upd('[data-field="cve-in-vulns"]', data.in_vulns);
            upd('[data-field="cve-missing-count"]', data.missing);
            var missingEl = document.querySelector('[data-field="cve-missing"]');
            if (missingEl) {
              missingEl.innerHTML = data.missing > 0
                ? '<span class="badge bg-yellow-lt me-2">' + data.missing + ' CVE manquantes</span>' : '';
            }
            updateBadge(document.getElementById('cve-card'));
            return;
          }

          // KEV
          if (key === 'kev') {
            var kevCard = document.getElementById('kev-card');
            if (kevCard) {
              var cntEl = kevCard.querySelector('.text-red');
              if (cntEl) cntEl.textContent = data.count;
              var dateEl = kevCard.querySelector('[data-field="date"]');
              if (dateEl) dateEl.textContent = data.date;
              updateBadge(kevCard);
            }
            return;
          }

          // ANSSI
          if (key === 'anssi') {
            var anssiCard = document.getElementById('anssi-card');
            if (anssiCard) {
              var cntEl = anssiCard.querySelector('.text-orange');
              if (cntEl) cntEl.textContent = data.count;
              updateBadge(anssiCard);
            }
            return;
          }

          // CPE watch
          if (key === 'cpe_watch') {
            updateBadge(document.getElementById('cpe_watch-card'));
            return;
          }

          // CPE dictionary
          if (key === 'cpe_dict') {
            var cpeCard = document.getElementById('cpe_dict-card');
            if (cpeCard) {
              var cntEl = cpeCard.querySelector('.text-azure');
              if (cntEl) cntEl.textContent = data.count;
              updateBadge(cpeCard);
            }
            return;
          }

          // Cards GMP standard + vulns
          var card = getCard(key);
          if (!card) return;
          var dateEl = card.querySelector('[data-field="date"]');
          if (dateEl) dateEl.textContent = data.date;
          var countEl = card.querySelector('[data-field="count"]');
          if (countEl) countEl.textContent = data.count;
          updateBadge(card);
        });
      })
      .catch(function() {});
  }

  function recentlyStarted(status) {
    // Vrai si la tâche a démarré il y a moins de 60 secondes
    if (!status.started) return false;
    var started = new Date(status.started).getTime();
    return (Date.now() - started) < 60000;
  }

  function updateTaskStatus(taskType, status) {
    // Table de surveillance : rafraîchie ~toutes les 2s pendant le run, et une
    // dernière fois à la fin (pour capter les derniers produits + l'état final).
    if (taskType === 'cpe_watch') {
      if (status.running) {
        cpeTableTick++;
        if (cpeTableTick % 2 === 0) refreshCpeWatchTable();
      } else if (runningTasks.has('cpe_watch')) {
        refreshCpeWatchTable();
      }
    }

    var statusDiv = document.getElementById(taskType + '-status');
    if (!statusDiv) return;
    var messageSpan = statusDiv.querySelector('.task-message');
    var progressSpan = statusDiv.querySelector('.task-progress');

    if (status.running) {
      lockCard(taskType);
      statusDiv.classList.remove('d-none', 'alert-success', 'alert-danger');
      statusDiv.classList.add('alert-info');
      if (messageSpan) messageSpan.textContent = status.message || 'Mise a jour en cours...';
      if (progressSpan) progressSpan.textContent = status.progress || '';
    } else {
      unlockCard(taskType);
      stopPolling(taskType);
      if (status.error) {
        statusDiv.classList.remove('d-none', 'alert-info', 'alert-success');
        statusDiv.classList.add('alert-danger');
        if (messageSpan) messageSpan.textContent = 'Erreur: ' + status.error;
        if (progressSpan) progressSpan.textContent = '';
        showToast('Erreur: ' + status.error, 'danger');
      } else if (status.finished && (runningTasks.has(taskType) || recentlyStarted(status))) {
        statusDiv.classList.remove('d-none', 'alert-info', 'alert-danger');
        statusDiv.classList.add('alert-success');
        if (messageSpan) messageSpan.textContent = 'Terminé !';
        if (progressSpan) progressSpan.textContent = '';
        showToast('Mise à jour terminée', 'success');
        runningTasks.delete(taskType);
        stopPolling(taskType);
        setTimeout(function() {
          statusDiv.classList.add('d-none');
          refreshCardMeta('gmp_all');
          checkForNewTasks();
        }, 1500);
      } else {
        statusDiv.classList.add('d-none');
      }
    }
  }

  function updateDateField(taskType) {
    var card = getCard(taskType);
    if (!card) return;
    var dateField = card.querySelector('[data-field="date"]');
    if (dateField) {
      var now = new Date();
      dateField.innerHTML = now.toLocaleDateString('fr-FR') + ' ' +
        now.toLocaleTimeString('fr-FR', {hour: '2-digit', minute: '2-digit'}) +
        ' <span class="badge bg-green-lt ms-1">Récent</span>';
    }
    var badge = card.querySelector('.cache-badge');
    if (badge) badge.innerHTML = '<span class="badge bg-green-lt"><i class="ti ti-circle-check me-1"></i>Récent</span>';
  }

  function startPolling(taskType) {
    if (pollingIntervals[taskType]) return;
    pollingIntervals[taskType] = setInterval(function() { checkTaskStatus(taskType); }, 1000);
  }

  function stopPolling(taskType) {
    if (pollingIntervals[taskType]) {
      clearInterval(pollingIntervals[taskType]);
      delete pollingIntervals[taskType];
    }
  }

  function checkForNewTasks() {
    ['cve', 'kev', 'anssi', 'gmp_vulns', 'cpe_dict', 'cpe_watch'].forEach(function(t) {
      if (pollingIntervals[t]) return;
      fetch(getStatusUrl(t))
        .then(function(r) { return r.json(); })
        .then(function(status) {
          if (status.running) {
            runningTasks.add(t);
            updateTaskStatus(t, status);
            startPolling(t);
          }
        })
        .catch(function() {});
    });
  }

  function checkTaskStatus(taskType) {
    fetch(getStatusUrl(taskType))
      .then(function(r) { return r.json(); })
      .then(function(status) {
        updateTaskStatus(taskType, status);
        if (status.running && !pollingIntervals[taskType]) startPolling(taskType);
      })
      .catch(function(e) { console.error('[cache] polling error:', e); });
  }

  function submitFormAsync(form) {
    var taskType = form.dataset.task;
    lockCard(taskType);
    var statusDiv = document.getElementById(taskType + '-status');
    if (statusDiv) {
      var messageSpan = statusDiv.querySelector('.task-message');
      if (messageSpan) messageSpan.textContent = 'Demarrage...';
    }
    fetch(form.action, {
      method: 'POST',
      body: new FormData(form),
      headers: { 'X-Requested-With': 'XMLHttpRequest' }
    })
    .then(function(r) { return r.json(); })
    .then(function(data) {
      if (data.success) {
        showToast(data.message, 'info');
        runningTasks.add(taskType);
        startPolling(taskType);
        // Mettre à jour le badge dès la confirmation du serveur
        setTimeout(function() { refreshCardMeta(taskType); }, 500);
      } else {
        showToast(data.error || 'Erreur', 'warning');
        unlockCard(taskType);
        if (statusDiv) statusDiv.classList.add('d-none');
      }
    })
    .catch(function(err) {
      console.error('Erreur:', err);
      showToast('Erreur de connexion', 'danger');
      unlockCard(taskType);
      if (statusDiv) statusDiv.classList.add('d-none');
    });
  }

  document.querySelectorAll('.async-form').forEach(function(form) {
    form.addEventListener('submit', function(e) { e.preventDefault(); submitFormAsync(this); });
  });

  // Bouton "Tout rafraîchir (GMP)" — simule un clic sur chaque form GMP individuel
  var btnRefreshAll = document.getElementById('btn-refresh-all-gmp');
  if (btnRefreshAll) {
    btnRefreshAll.addEventListener('click', function() {
      // Exclure gmp_vulns — il sera déclenché séquentiellement après gmp_tasks
      var gmpForms = Array.from(
        document.querySelectorAll('.async-form[data-task^="gmp_"]')
      ).filter(function(f) { return f.dataset.task !== 'gmp_vulns'; });

      btnRefreshAll.disabled = true;
      var i = 0;
      function clickNext() {
        if (i >= gmpForms.length) {
          // Tous les caches GMP lancés — déclencher vulns en séquence après tasks
          var btnVulns = document.getElementById('btn-refresh-vulns');
          if (btnVulns) btnVulns.click();
          btnRefreshAll.disabled = false;
          return;
        }
        submitFormAsync(gmpForms[i]);
        i++;
        setTimeout(clickNext, 300);
      }
      clickNext();
    });
  }

  // Bouton "Rafraîchir les vulnérabilités" — lance tasks en premier, puis vulns
  var btnRefreshVulns = document.getElementById('btn-refresh-vulns');
  if (btnRefreshVulns) {
    btnRefreshVulns.addEventListener('click', function() {
      btnRefreshVulns.disabled = true;

      // Trouver le form tasks dans les GMP caches génériques
      var tasksForm = document.querySelector('.async-form[data-task="gmp_tasks"]');
      var vulnsForm = document.getElementById('form-refresh-vulns');

      if (!vulnsForm) { btnRefreshVulns.disabled = false; return; }

      if (tasksForm) {
        // Étape 1 : lancer le refresh tasks
        runningTasks.add('gmp_tasks');
        submitFormAsync(tasksForm);

        // Étape 2 : attendre la fin de gmp_tasks puis lancer vulns
        function waitForTasksThenVulns() {
          if (runningTasks.has('gmp_tasks') || pollingIntervals['gmp_tasks']) {
            // Encore en cours, recheck dans 1s
            setTimeout(waitForTasksThenVulns, 1000);
          } else {
            // Tasks terminé — lancer vulns
            runningTasks.add('gmp_vulns');
            submitFormAsync(vulnsForm);
            btnRefreshVulns.disabled = false;
          }
        }
        // Démarrer l'attente après un petit délai pour laisser le polling démarrer
        setTimeout(waitForTasksThenVulns, 1500);
      } else {
        // Pas de form tasks trouvé — lancer vulns directement
        runningTasks.add('gmp_vulns');
        submitFormAsync(vulnsForm);
        btnRefreshVulns.disabled = false;
      }
    });
  }

  // Vérifier les tâches en cours au chargement de la page
  var taskTypes = ['gmp_all', 'gmp_vulns', 'cve', 'kev', 'anssi', 'cpe_dict', 'cpe_watch'];
  document.querySelectorAll('[data-task^="gmp_"]').forEach(function(el) {
    var t = el.dataset.task;
    if (taskTypes.indexOf(t) === -1) taskTypes.push(t);
  });
  taskTypes.forEach(function(taskType) {
    fetch(getStatusUrl(taskType))
      .then(function(r) { return r.json(); })
      .then(function(status) {
        if (status.running) {
          runningTasks.add(taskType);
          updateTaskStatus(taskType, status);
          startPolling(taskType);
        }
      })
      .catch(function() {});
  });
})();
