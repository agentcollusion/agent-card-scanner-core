// Registrable-domain approximation. v0 uses a small suffix table; v1 should use the full Public Suffix List.
const MULTI_LABEL_SUFFIXES = new Set([
  'co.jp', 'ne.jp', 'or.jp', 'ac.jp', 'go.jp', 'co.za', 'com.sg', 'com.mx', 'com.tr', 'com.tw', 'com.hk', 'co.il', 'co.id', 'com.ar', 'co.uk', 'org.uk', 'ac.uk', 'com.au', 'net.au', 'co.nz', 'com.br', 'com.cn', 'co.kr', 'co.in',
  // shared hosting platforms: every tenant is a different owner
  'github.io', 'vercel.app', 'pages.dev', 'workers.dev', 'netlify.app', 'herokuapp.com', 'azurewebsites.net',
  'cloudfunctions.net', 'run.app', 'onrender.com', 'fly.dev', 'appspot.com', 'web.app', 'firebaseapp.com', 'replit.app',
  'up.railway.app', 'railway.app', 'mintlify.me', 'mintlify.app', 'hf.space', 'deno.dev', 'lovable.app', 'replit.dev',
  'ngrok.app', 'ngrok-free.app', 'ngrok.io', 'trycloudflare.com', 'modal.run', 'koyeb.app', 'amplifyapp.com',
]);

export function hostOf(url) {
  try {
    return new URL(url).hostname.toLowerCase().replace(/\.$/, '');
  } catch {
    return null;
  }
}

export function registrableDomain(host) {
  if (!host) return null;
  const labels = host.toLowerCase().replace(/\.$/, '').split('.');
  if (labels.length <= 2) return labels.join('.');
  const last2 = labels.slice(-2).join('.');
  const last3 = labels.slice(-3).join('.');
  if (MULTI_LABEL_SUFFIXES.has(last2)) return last3;
  if (MULTI_LABEL_SUFFIXES.has(last3)) return labels.slice(-4).join('.');
  return last2;
}

export function sameRegistrableDomain(a, b) {
  const da = registrableDomain(a);
  return !!da && da === registrableDomain(b);
}
