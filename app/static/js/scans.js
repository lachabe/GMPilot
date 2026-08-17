/* scans.js — GMPilot */
(function() {

const cfg = document.getElementById('gmpilot-scans-config');
const STATUS_ALL_URL = cfg ? cfg.dataset.statusAllUrl : null;
const AUTOREFRESH_KEY = 'scans_autorefresh';

// ── Génération des boutons d'action selon le statut ──
function buildActions(taskId, status, lastReportId, csrfToken) {
  const canStart   = ['New','Done','Stopped','Interrupted'].includes(status);
  const canStop    = status === 'Running';
  const canResume  = status === 'Stopped';
  let html = '';

  if (canStart) html += `
    <form method="POST" action="/scans/${taskId}/start" class="d-inline">
      <input type="hidden" name="csrf_token" value="${csrfToken}"/>
      <button type="submit" class="btn btn-ghost-success btn-icon btn-sm" title="Démarrer">
        <i class="ti ti-player-play"></i>
      </button>
    </form>`;

  if (canStop) html += `
    <form method="POST" action="/scans/${taskId}/stop" class="d-inline">
      <input type="hidden" name="csrf_token" value="${csrfToken}"/>
      <button type="submit" class="btn btn-ghost-warning btn-icon btn-sm" title="Arrêter">
        <i class="ti ti-player-stop"></i>
      </button>
    </form>`;

  if (canResume) html += `
    <form method="POST" action="/scans/${taskId}/resume" class="d-inline">
      <input type="hidden" name="csrf_token" value="${csrfToken}"/>
      <button type="submit" class="btn btn-ghost-secondary btn-icon btn-sm" title="Reprendre">
        <i class="ti ti-rotate-clockwise"></i>
      </button>
    </form>`;

  // Bouton supprimer toujours présent
  html += `
    <form method="POST" action="/scans/${taskId}/delete" class="d-inline"
          onsubmit="return confirm('Supprimer cette tâche ?')">
      <input type="hidden" name="csrf_token" value="${csrfToken}"/>
      <button type="submit" class="btn btn-ghost-danger btn-icon btn-sm" title="Supprimer">
        <i class="ti ti-trash"></i>
      </button>
    </form>`;

  return html;
}

// ── Badge statut ──
function buildStatusBadge(status, progress) {
  if (status === 'Running' || status === 'Requested') {
    return `<span class="status status-green">
      <span class="status-dot status-dot-animated"></span>
      <span>En cours</span>
    </span>`;
  } else if (status === 'Done') {
    return `<span class="status status-cyan">Terminé</span>`;
  } else if (status === 'Stopped') {
    return `<span class="status text-secondary">Arrêté</span>`;
  } else if (status === 'New') {
    return `<span class="status text-secondary">Nouveau</span>`;
  } else if (status === 'Interrupted') {
    return `<span class="status status-red">Interrompu</span>`;
  }
  return `<span class="status status-red">${status}</span>`;
}

// ── Badge sévérité ──
function buildSevBadge(sev) {
  if (!sev || sev <= 0) return '<span class="text-secondary">—</span>';
  const s = parseFloat(sev);
  if (s >= 9.0) return `<span class="badge badge-critical"><i class="ti ti-radiation me-1"></i>${s.toFixed(1)}</span>`;
  if (s >= 7.0) return `<span class="badge badge-high"><i class="ti ti-alert-octagon me-1"></i>${s.toFixed(1)}</span>`;
  if (s >= 4.0) return `<span class="badge badge-medium"><i class="ti ti-alert-triangle me-1"></i>${s.toFixed(1)}</span>`;
  return `<span class="badge badge-low"><i class="ti ti-info-circle me-1"></i>${s.toFixed(1)}</span>`;
}

// ── Mise à jour d'une ligne depuis les données GMP ──
function updateRow(taskId, data) {
  const row = document.getElementById('row-' + taskId);
  if (!row) return;

  const csrfToken = document.body.dataset.csrfToken || '';
  const status    = data.status || 'Unknown';
  const progress  = parseInt(data.progress) || 0;

  // Statut
  const statusCell = row.cells[3];
  if (statusCell) statusCell.innerHTML = buildStatusBadge(status, progress);

  // Progression
  const progCell = row.cells[4];
  if (progCell) {
    if (status === 'Running' || status === 'Requested') {
      progCell.innerHTML = `
        <div class="d-flex align-items-center gap-2" style="min-width:90px">
          <div class="progress progress-sm flex-fill" style="width:65px">
            <div class="progress-bar bg-cyan" style="width:${progress}%"></div>
          </div>
          <span class="small text-secondary">${progress}%</span>
        </div>`;
    } else {
      progCell.innerHTML = '<span class="text-secondary">—</span>';
    }
  }

  // Sévérité
  const sevCell = row.cells[5];
  if (sevCell) sevCell.innerHTML = buildSevBadge(data.severity);

  // Boutons
  const actionsDiv = document.getElementById('actions-' + taskId);
  if (actionsDiv) actionsDiv.innerHTML = buildActions(taskId, status, data.last_report_id, csrfToken);

  row.dataset.taskStatus = status;
}

// ── Refresh de tous les statuts ──
async function refreshAllStatuses() {
  if (!STATUS_ALL_URL) return;
  const indicator = document.getElementById('scans-refresh-indicator');
  if (indicator) indicator.classList.remove('d-none');
  try {
    const resp = await fetch(STATUS_ALL_URL);
    if (!resp.ok) return;
    const data = await resp.json();
    if (data.error) return;
    Object.keys(data).forEach(function(taskId) {
      updateRow(taskId, data[taskId]);
    });
  } catch(e) {
    console.error('[scans] refresh error:', e);
  } finally {
    if (indicator) indicator.classList.add('d-none');
  }
}

// ── Auto-refresh ──
let autoRefreshTimer = null;

function startAutoRefresh(seconds) {
  if (autoRefreshTimer) clearInterval(autoRefreshTimer);
  autoRefreshTimer = null;
  if (seconds > 0) {
    autoRefreshTimer = setInterval(refreshAllStatuses, seconds * 1000);
  }
}

const select = document.getElementById('scans-autorefresh');
if (select) {
  // Restaurer préférence
  const saved = localStorage.getItem(AUTOREFRESH_KEY) || '0';
  select.value = saved;
  startAutoRefresh(parseInt(saved));

  select.addEventListener('change', function() {
    const val = parseInt(this.value);
    localStorage.setItem(AUTOREFRESH_KEY, this.value);
    startAutoRefresh(val);
  });
}

// ── Refresh initial au chargement (statuts frais depuis GMP) ──
refreshAllStatuses();

})();
