/* assets_hosts.js — GMPilot */
document.getElementById('hostSearch').addEventListener('input', function(){
  const q = this.value.toLowerCase();
  document.querySelectorAll('#hostsTable tbody tr').forEach(r => r.style.display = !q || r.dataset.name.includes(q) ? '' : 'none');
});
let tagsCache = null;
let tagModalInstance = null;
function getTagModal() {
  if (!tagModalInstance) tagModalInstance = new bootstrap.Modal(document.getElementById('tagModal'));
  return tagModalInstance;
}
async function openTagModal(hostId, hostName) {
  document.getElementById('tagHostId').value = hostId;
  document.getElementById('tagModalSub').textContent = 'Hôte : ' + hostName;
  if (!tagsCache) { try { tagsCache = await (await fetch('/tags/api/list')).json(); } catch(e) { tagsCache = []; } }
  const sel = document.getElementById('tagSelect');
  sel.innerHTML = '<option value="">— Choisir —</option>';
  tagsCache.forEach(t => { const o = document.createElement('option'); o.value = t.id; o.textContent = t.name + (t.value ? ' = '+t.value : ''); sel.appendChild(o); });
  getTagModal().show();
}
document.getElementById('tagAssignForm').addEventListener('submit', function(e) {
  e.preventDefault();
  const tagId = document.getElementById('tagSelect').value;
  if (!tagId) { alert('Sélectionnez un tag.'); return; }
  this.action = '/tags/' + tagId + '/assign';
  this.submit();
});
