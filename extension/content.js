// Lockd na página: esconde chaves na tela (o agente e os prints só veem "sk-ant-••••"), deixa VOCÊ salvar no Lockd com um clique
// e preenche campos a pedido do Lockd. Nada aqui faz rede; o valor só sai por mensagem para a extensão -> app.
(() => {
  if (window.top !== window || !location.protocol.startsWith('http')) return;
  const D = globalThis.LockdDetect;
  const entries = [];                 // chaves originais (só em memória desta aba)
  const byValue = new Map();          // valor -> índice
  const masked = new Map();           // nó de texto -> texto original (para "Revelar")
  let shield = true, mutating = false, revealing = false;
  let host, shadow, pill, msg;


  function register(value) {
    if (byValue.has(value)) return byValue.get(value);
    if (entries.length >= 250) return -1;
    entries.push(value); byValue.set(value, entries.length - 1);
    return entries.length - 1;
  }

  function maskText(text) {
    const hits = D.find(text);
    if (!hits.length) return null;
    let out = '', last = 0;
    for (const h of hits) {
      const i = register(h.value);
      if (i < 0) continue;
      out += text.slice(last, h.index) + D.mask(h.value) + D.tag(i);
      last = h.index + h.value.length;
    }
    return out + text.slice(last);
  }

  function scanTextNode(n) {
    if (revealing || masked.has(n)) return;
    const t = n.nodeValue;
    if (!t || t.length < 16) return;
    const p = n.parentElement;
    if (p && /^(SCRIPT|STYLE|NOSCRIPT|TEXTAREA)$/.test(p.tagName)) return;
    const m = maskText(t);
    if (m === null) return;
    if (shield) { masked.set(n, t); mutating = true; n.nodeValue = m; mutating = false; }
    refresh();
  }

  function scanInput(el) {
    const v = el.value;
    if (!v || v.length < 16) return;
    if (D.find(v).length) {
      for (const h of D.find(v)) register(h.value);
      if (shield) el.style.setProperty('-webkit-text-security', 'disc', 'important');   // o valor continua no campo; só a tela esconde
      refresh();
    }
  }

  function scan(root) {
    if (!root) return;
    if (root.nodeType === 3) { scanTextNode(root); return; }
    if (root.nodeType !== 1) return;
    const w = document.createTreeWalker(root, NodeFilter.SHOW_TEXT);
    let n; let guard = 0;
    while ((n = w.nextNode()) && guard++ < 20000) scanTextNode(n);
    root.querySelectorAll && root.querySelectorAll('input,textarea').forEach(scanInput);
    if (/^(INPUT|TEXTAREA)$/.test(root.tagName)) scanInput(root);
  }

  function unmaskAll() { revealing = true; mutating = true; masked.forEach((orig, n) => { if (n.isConnected) n.nodeValue = orig; }); mutating = false; revealing = false; masked.clear(); document.querySelectorAll('[style*="text-security"]').forEach(e => e.style.removeProperty('-webkit-text-security')); refresh(); }

  // Observa mudanças de página (chaves que aparecem depois de um clique).
  let queue = new Set(), timer = null;
  new MutationObserver(muts => {
    if (mutating) return;
    for (const m of muts) {
      if (m.type === 'characterData') queue.add(m.target);
      else m.addedNodes.forEach(n => queue.add(n));
    }
    clearTimeout(timer); timer = setTimeout(() => { const q = [...queue]; queue = new Set(); q.forEach(scan); }, 120);
  }).observe(document.documentElement, { childList: true, subtree: true, characterData: true });
  document.addEventListener('input', e => { if (e.target && /^(INPUT|TEXTAREA)$/.test(e.target.tagName)) scanInput(e.target); }, true);

  // Copiar: se a seleção tem uma chave escondida, a área de transferência recebe a chave de verdade.
  document.addEventListener('copy', e => {
    const sel = String(window.getSelection());
    if (!sel.includes('••••')) return;
    const fixed = sel.replace(D.TAGGED, (all, tg) => entries[D.untag(tg)] ?? all);
    if (fixed !== sel && e.clipboardData) { e.clipboardData.setData('text/plain', fixed); e.preventDefault(); }
  }, true);

  // ---- botão do Lockd (shadow DOM fechado: a página não lê nem clica) ----
  function ensureUI() {
    if (host) return;
    host = document.createElement('div');
    host.style.cssText = 'all:initial;position:fixed;right:16px;bottom:16px;z-index:2147483647';
    shadow = host.attachShadow({ mode: 'closed' });
    shadow.innerHTML = `<style>
      .p{font:600 12.5px -apple-system,system-ui,sans-serif;display:flex;gap:6px;align-items:center;padding:7px 8px 7px 11px;border-radius:12px;
        background:rgba(34,36,35,.94);color:#f1f3f0;box-shadow:0 8px 28px rgba(0,0,0,.35);border:1px solid rgba(255,255,255,.12);backdrop-filter:blur(14px)}
      .d{width:7px;height:7px;border-radius:50%;background:#7fd1ae}
      button{font:inherit;border:0;border-radius:8px;padding:5px 10px;cursor:pointer;color:#0f1a15;background:#7fd1ae}
      button.g{background:rgba(255,255,255,.1);color:#f1f3f0}
      .m{font-weight:500;opacity:.85;max-width:260px}
    </style><div class="p"><span class="d"></span><span class="m" id="t"></span><button id="s">Save to Lockd</button><button class="g" id="r">Reveal</button></div>`;
    pill = shadow.getElementById('s'); msg = shadow.getElementById('t');
    pill.addEventListener('click', e => { if (!e.isTrusted) return; save(); });
    shadow.getElementById('r').addEventListener('click', e => { if (!e.isTrusted) return; reveal(); });
    (document.body || document.documentElement).appendChild(host);
  }
  function refresh() {
    if (!entries.length) return;
    ensureUI();
    host.style.display = '';
    msg.textContent = (entries.length === 1 ? 'Key' : `${entries.length} keys`) + (shield ? ' hidden on this page' : ' found on this page');
  }
  function say(t, ms = 5000) { ensureUI(); const prev = msg.textContent; msg.textContent = t; setTimeout(() => { if (msg.textContent === t) refresh(); }, ms); }
  function reveal() {
    if (revealing) return; revealing = true; mutating = true;
    masked.forEach((orig, n) => { if (n.isConnected) n.nodeValue = orig; });
    mutating = false;
    say('Visible for 8 seconds', 8000);
    setTimeout(() => { mutating = true; masked.forEach((orig, n) => { if (n.isConnected) n.nodeValue = maskText(orig) ?? orig; }); mutating = false; revealing = false; }, 8000);
  }
  function save() {
    say('Saving…', 15000);
    chrome.runtime.sendMessage({ type: 'capture', host: location.hostname, candidates: entries.slice() }).catch?.(() => say('Lockd is not connected'));
  }

  // ---- pedidos vindos do Lockd (via background) ----
  function visible(el) { const r = el.getBoundingClientRect(); const s = getComputedStyle(el); return r.width > 0 && r.height > 0 && s.visibility !== 'hidden' && s.display !== 'none'; }
  function fill(m) {
    if (location.protocol !== 'https:' || location.hostname !== m.host) return { ok: false, text: `This tab is ${location.hostname}, not ${m.host}.` };
    let el; try { el = document.querySelector(m.selector); } catch (_) { return { ok: false, text: 'Invalid selector.' }; }
    if (!el) return { ok: false, text: 'No element matches that selector.' };
    if (el.disabled || el.readOnly) return { ok: false, text: 'The field is disabled or read-only.' };
    const tag = el.tagName;
    if (tag === 'INPUT' || tag === 'TEXTAREA') {
      if (el.tagName === 'INPUT' && /^(checkbox|radio|file|button|submit|hidden|image)$/i.test(el.type)) return { ok: false, text: 'That input type can\'t take a key.' };
      el.focus();
      const proto = tag === 'INPUT' ? HTMLInputElement.prototype : HTMLTextAreaElement.prototype;
      Object.getOwnPropertyDescriptor(proto, 'value').set.call(el, m.value);
      el.dispatchEvent(new Event('input', { bubbles: true }));
      el.dispatchEvent(new Event('change', { bubbles: true }));
      if (el.type !== 'password') el.style.setProperty('-webkit-text-security', 'disc', 'important');
    } else if (el.isContentEditable) {
      el.focus(); document.execCommand('selectAll', false); document.execCommand('insertText', false, m.value);
    } else return { ok: false, text: 'That element isn\'t a text field.' };
    if (m.submit) {
      let b; try { b = document.querySelector(m.submit); } catch (_) {}
      if (!b) return { ok: true, text: 'Filled, but the submit button was not found.' };
      setTimeout(() => b.click(), 80);
    }
    return { ok: true, text: 'Filled.' };
  }

  try { chrome.storage.local.get(['shield'], r => { if (r && r.shield === false) shield = false; scan(document.body); }); } catch (_) { scan(document.body); }
  try { chrome.storage.onChanged.addListener(c => { if (c.shield) { shield = c.shield.newValue !== false; if (!shield) unmaskAll(); else scan(document.body); } }); } catch (_) {}

  chrome.runtime.onMessage.addListener((m, sender, reply) => {
    if (sender.id !== chrome.runtime.id) return;
    if (m.type === 'lockd-fill') { reply(fill(m)); return; }
    if (m.type === 'lockd-harvest') { scan(document.body); reply({ ok: true, host: location.hostname, candidates: entries.slice() }); return; }
    if (m.type === 'lockd-toast') { say(m.text, 7000); reply({ ok: true }); return; }
  });
})();
