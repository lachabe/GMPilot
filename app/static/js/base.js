/* base.js — GMPilot */

// ── Toast global ──
window.showToast = function(message, type) {
  type = type || 'info';
  var container = document.getElementById('toast-container');
  if (!container) return;
  var id = 'toast-' + Date.now();
  var icons = { success:'ti-circle-check', danger:'ti-alert-triangle', warning:'ti-exclamation-circle', info:'ti-info-circle' };
  container.insertAdjacentHTML('beforeend',
    '<div id="' + id + '" class="toast show align-items-center text-bg-' + type + ' border-0 mb-2" role="alert">' +
      '<div class="d-flex">' +
        '<div class="toast-body"><i class="ti ' + (icons[type] || icons.info) + ' me-2"></i>' + message + '</div>' +
        '<button type="button" class="btn-close btn-close-white me-2 m-auto" onclick="this.closest(\'.toast\').remove()"></button>' +
      '</div>' +
    '</div>');
  setTimeout(function() { var el = document.getElementById(id); if (el) el.remove(); }, 4000);
};

// ── Flash messages → toasts ──
var flashEl = document.getElementById('base-flash-data');
if (flashEl) {
  try {
    JSON.parse(flashEl.textContent).forEach(function(m) {
      var type = m[0] === 'error' ? 'danger' : m[0];
      setTimeout(function() { window.showToast(m[1], type); }, 100);
    });
  } catch(e) {}
}

// ── Thème clair/sombre ──
var themeToggle = document.getElementById('themeToggle');
var themeIcon = document.getElementById('themeIcon');
if (themeToggle) {
  var saved = localStorage.getItem('theme');
  if (saved) {
    document.documentElement.setAttribute('data-bs-theme', saved);
    if (themeIcon) themeIcon.className = saved === 'dark' ? 'ti ti-sun' : 'ti ti-moon';
  }
  themeToggle.addEventListener('click', function() {
    var next = document.documentElement.getAttribute('data-bs-theme') === 'dark' ? 'light' : 'dark';
    document.documentElement.setAttribute('data-bs-theme', next);
    localStorage.setItem('theme', next);
    if (themeIcon) themeIcon.className = next === 'dark' ? 'ti ti-sun' : 'ti ti-moon';
  });
}
