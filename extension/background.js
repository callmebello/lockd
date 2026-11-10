// Ponte entre as páginas e o app Lockd (mensagens nativas). Não guarda nem mostra valores.
const HOST = 'app.lockd.mac';
let port = null, connected = false, lastError = '';
const captureTabs = new Map();   // cid -> tabId

function setBadge() {
  chrome.action.setBadgeText({ text: connected ? '' : '!' });
  chrome.action.setBadgeBackgroundColor({ color: '#c0792b' });
}

function connect() {
  if (port) return;
  try {
    port = chrome.runtime.connectNative(HOST);
  } catch (e) { lastError = String(e); port = null; setBadge(); return; }
  port.onMessage.addListener(onHost);
  port.onDisconnect.addListener(() => {
    lastError = (chrome.runtime.lastError && chrome.runtime.lastError.message) || lastError;
    port = null; connected = false; setBadge();
  });
}

async function targetTab(host) {
  const tabs = await chrome.tabs.query({ url: `https://${host}/*` });
  if (!tabs.length) return null;
  return tabs.find(t => t.active) || tabs[0];
}

async function onHost(m) {
  if (m.t === 'hello') { connected = true; lastError = ''; setBadge(); return; }
  if (m.t === 'error') { lastError = m.text || 'refused'; connected = false; setBadge(); return; }
  if (m.t === 'captured') {
    const tabId = captureTabs.get(m.cid); captureTabs.delete(m.cid);
    if (tabId != null) chrome.tabs.sendMessage(tabId, { type: 'lockd-toast', text: m.text }).catch(() => {});
    return;
  }
  if (m.t !== 'cmd') return;
  const done = (o) => port && port.postMessage({ t: 'result', id: m.id, ...o });
  try {
    if (m.kind === 'fill') {
      const tab = await targetTab(m.host);
      if (!tab) return done({ ok: false, text: `No open tab on ${m.host}. Open the page first.` });
      const r = await chrome.tabs.sendMessage(tab.id, { type: 'lockd-fill', host: m.host, selector: m.selector, value: m.value, submit: m.submit }, { frameId: 0 });
      return done({ ok: !!(r && r.ok), text: (r && r.text) || 'no answer from the page' });
    }
    if (m.kind === 'harvest') {
      const [tab] = await chrome.tabs.query({ active: true, lastFocusedWindow: true });
      if (!tab || !tab.url || !tab.url.startsWith('https://')) return done({ ok: false, text: 'The active tab isn\'t an https page.' });
      const r = await chrome.tabs.sendMessage(tab.id, { type: 'lockd-harvest' }, { frameId: 0 });
      return done({ ok: true, host: r.host, candidates: r.candidates || [] });
    }
    done({ ok: false, text: 'unknown command' });
  } catch (e) {
    done({ ok: false, text: 'The page did not answer (reload the tab so the Lockd extension can attach).' });
  }
}

chrome.runtime.onMessage.addListener((m, sender, reply) => {
  if (m.type === 'capture' && sender.tab) {
    connect();
    const cid = crypto.randomUUID();
    captureTabs.set(cid, sender.tab.id);
    if (!port) chrome.tabs.sendMessage(sender.tab.id, { type: 'lockd-toast', text: 'Lockd isn\'t running. Open the Lockd app.' }).catch(() => {});
    else port.postMessage({ t: 'capture', cid, host: m.host, candidates: m.candidates });
    reply({ ok: true }); return;
  }
  if (m.type === 'status') { connect(); reply({ connected, lastError }); return; }
});

chrome.runtime.onInstalled.addListener(connect);
chrome.runtime.onStartup.addListener(connect);
chrome.alarms.create('lockd-keepalive', { periodInMinutes: 1 });
chrome.alarms.onAlarm.addListener(connect);
connect(); setBadge();
