/* login.js — GMPilot */

function showToast(message, type) {
  type = type || 'info';
  var container = document.getElementById('toast-container');
  if (!container) return;
  var id = 'toast-' + Date.now();
  var icons = { success:'ti-circle-check', danger:'ti-alert-triangle', warning:'ti-exclamation-circle', info:'ti-info-circle' };
  var label = type === 'success' ? 'Succès' : type === 'danger' ? 'Erreur' : type === 'warning' ? 'Attention' : 'Info';
  container.insertAdjacentHTML('beforeend',
    '<div id="' + id + '" class="toast show align-items-center text-bg-' + type + ' border-0 mb-2" role="alert">' +
      '<div class="d-flex">' +
        '<div class="toast-body"><i class="ti ' + (icons[type] || icons.info) + ' me-2"></i>' + message + '</div>' +
        '<button type="button" class="btn-close btn-close-white me-2 m-auto" onclick="this.closest(\'.toast\').remove()"></button>' +
      '</div>' +
    '</div>');
  setTimeout(function() { var el = document.getElementById(id); if (el) el.remove(); }, 4000);
}

var flashEl = document.getElementById('login-flash-data');
if (flashEl) {
  try {
    var messages = JSON.parse(flashEl.textContent);
    messages.forEach(function(m) {
      var type = m[0] === 'error' ? 'danger' : m[0];
      setTimeout(function() { showToast(m[1], type); }, 100);
    });
  } catch(e) {}
}

var pwdToggle = document.getElementById('pwdToggle');
if (pwdToggle) {
  pwdToggle.addEventListener('click', function() {
    var inp = document.getElementById('pwdInput');
    var ico = document.getElementById('pwdIcon');
    var show = inp.type === 'password';
    inp.type = show ? 'text' : 'password';
    ico.className = show ? 'ti ti-eye-off' : 'ti ti-eye';
  });
}
