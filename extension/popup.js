const $ = id => document.getElementById(id);
chrome.runtime.sendMessage({ type: 'status' }, r => {
  const ok = r && r.connected;
  $('h').className = ok ? 'ok' : '';
  $('s').textContent = ok ? 'Connected to Lockd' : 'Not connected';
  $('d').textContent = ok ? 'Keys you save here go straight to your vault.' : 'Open the Lockd app (menu bar). If it is open, run “lockdctl install-browser” once and restart Chrome.' + (r && r.lastError ? ' (' + r.lastError + ')' : '');
});
chrome.storage.local.get(['shield'], r => { $('shield').checked = r.shield !== false; });
$('shield').addEventListener('change', e => chrome.storage.local.set({ shield: e.target.checked }));
