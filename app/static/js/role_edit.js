/* role_edit.js — GMPilot */
function setAll(val) {
  document.querySelectorAll('.perm-checkbox').forEach(cb => cb.checked = val);
}
function setSection(section, val) {
  document.querySelectorAll(`.perm-item[data-section="${section}"] .perm-checkbox`)
    .forEach(cb => cb.checked = val);
}
