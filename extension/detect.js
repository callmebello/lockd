// Reconhecimento de chaves na página. Espelha as regras do Detector.swift (que é a fonte da verdade no app).
(function (root) {
  const RULES = [
    ['Anthropic', 'sk-ant-[A-Za-z0-9_\\-]{20,}'],
    ['OpenRouter', 'sk-or-v1-[a-f0-9]{40,}'],
    ['OpenAI', 'sk-(?:proj-|svcacct-|admin-)?[A-Za-z0-9_\\-]{32,}'],
    ['Google Gemini', 'AIza[0-9A-Za-z_\\-]{35}'],
    ['Google', 'GOCSPX-[A-Za-z0-9_\\-]{20,}'],
    ['GitHub', '(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{50,})'],
    ['Stripe', '[sr]k_(?:live|test)_[A-Za-z0-9]{16,}'],
    ['Stripe', 'whsec_[A-Za-z0-9]{20,}'],
    ['ElevenLabs', 'sk_[a-f0-9]{40,}'],
    ['AWS', '(?:AKIA|ASIA)[0-9A-Z]{16}'],
    ['Slack', 'xox[baprs]-[A-Za-z0-9\\-]{10,}'],
    ['Supabase', 'sbp_[a-f0-9]{40}'],
    ['Supabase', 'sb_secret_[A-Za-z0-9_\\-]{20,}'],
    ['Resend', 're_[A-Za-z0-9_]{20,}'],
    ['Hugging Face', 'hf_[A-Za-z0-9]{30,}'],
    ['Groq', 'gsk_[A-Za-z0-9]{40,}'],
    ['xAI', 'xai-[A-Za-z0-9]{40,}'],
    ['Perplexity', 'pplx-[A-Za-z0-9]{40,}'],
    ['Replicate', 'r8_[A-Za-z0-9]{30,}'],
    ['SendGrid', 'SG\\.[A-Za-z0-9_\\-]{16,}\\.[A-Za-z0-9_\\-]{16,}'],
    ['npm', 'npm_[A-Za-z0-9]{36}'],
    ['Brevo', 'xkeysib-[a-f0-9]{40,}-[A-Za-z0-9]+'],
    ['Mercado Pago', 'APP_USR-[0-9]{8,}-[0-9]{6}-[a-f0-9]{32}-[0-9]+'],
    ['Database', '(?:postgres(?:ql)?|mysql|mongodb(?:\\+srv)?|rediss?|amqp)://[^\\s:/@]+:[^\\s@]+@[^\\s"\'<>]+'],
  ];
  // Só chaves SECRETAS são mascaradas (publicáveis como pk_live não precisam).
  const LEFT = '(?<![A-Za-z0-9_\\-])', RIGHT = '(?![A-Za-z0-9_\\-])';
  const SCAN = new RegExp(LEFT + '(?:' + RULES.map(r => r[1]).join('|') + ')' + RIGHT, 'g');

  function find(text) {
    const out = [];
    if (!text || text.length < 16 || text.length > 200000) return out;
    SCAN.lastIndex = 0;
    let m;
    while ((m = SCAN.exec(text))) out.push({ value: m[0], index: m.index });
    return out;
  }

  // "sk-ant-api03-…" → "sk-ant-••••": só o prefixo público. Nunca parte do segredo.
  function mask(value) {
    if (/^[a-z]+:\/\//i.test(value)) return value.split('://')[0] + '://••••';
    const m = /^(?:[A-Za-z]{1,7}[_-]){1,2}/.exec(value);
    return (m ? m[0] : value.slice(0, 4)) + '••••';
  }

  // Marca invisível com o índice da chave (para a cópia devolver a chave certa).
  function tag(i) { let s = ''; for (let b = 7; b >= 0; b--) s += (i >> b) & 1 ? '\u200c' : '\u200b'; return s; }
  function untag(s) { let n = 0; for (const ch of s) n = (n << 1) | (ch === '\u200c' ? 1 : 0); return n; }
  const TAGGED = /(?:[A-Za-z]{1,7}[_-]){0,2}[A-Za-z0-9]{0,4}••••([\u200b\u200c]{8})/g;

  const api = { RULES, find, mask, tag, untag, TAGGED };
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
  else root.LockdDetect = api;
})(typeof globalThis !== 'undefined' ? globalThis : this);
