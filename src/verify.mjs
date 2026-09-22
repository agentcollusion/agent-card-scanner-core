// Explicit verifier policy: same HTTPS origin for remote keys; caller-owned local JWKS.
import { createHash, createPublicKey, verify as cryptoVerify, constants } from 'node:crypto';
import { canonicalize } from './jcs.mjs';
import { cardPayload } from './card-payload.mjs';
import { safeFetch, publicHttpsUrl } from './safe-fetch.mjs';
import { parseJson, isObject, decodeUtf8 } from './input.mjs';

export const POLICY_VERSION = 'same-origin-v1.0.1-2026-09-r2';
export const ALLOWED_ALGS = new Set(['ES256', 'ES384', 'ES512', 'EdDSA', 'Ed25519', 'RS256', 'RS384', 'RS512', 'PS256', 'PS384', 'PS512']);
const b64u = (buf) => Buffer.from(buf).toString('base64url');
const decode = (s) => {
  if (typeof s !== 'string' || !s || !/^[A-Za-z0-9_-]+$/.test(s) || s.length % 4 === 1) throw new Error('Invalid base64url');
  const bytes = Buffer.from(s, 'base64url');
  if (bytes.toString('base64url') !== s) throw new Error('Noncanonical base64url');
  return bytes;
};
export function jwkThumbprint(jwk) {
  const required = { EC: ['crv', 'kty', 'x', 'y'], RSA: ['e', 'kty', 'n'], OKP: ['crv', 'kty', 'x'] }[jwk.kty];
  if (!required || required.some((k) => typeof jwk[k] !== 'string')) return null;
  return b64u(createHash('sha256').update(canonicalize(Object.fromEntries(required.map((k) => [k, jwk[k]])))).digest());
}
export function signingInput(card, protectedB64) {
  return Buffer.from(`${protectedB64}.${b64u(canonicalize(cardPayload(card)))}`);
}
export function keyMatchesAlgorithm(jwk, alg) {
  if (!isObject(jwk) || ['d', 'p', 'q', 'k', 'dp', 'dq', 'qi'].some((k) => k in jwk)) return false;
  if (jwk.alg !== undefined && jwk.alg !== alg) return false;
  if (jwk.use !== undefined && jwk.use !== 'sig') return false;
  if (jwk.key_ops !== undefined && (!Array.isArray(jwk.key_ops) || !jwk.key_ops.includes('verify'))) return false;
  if (alg.startsWith('ES')) {
    const size = { ES256: 32, ES384: 48, ES512: 66 }[alg];
    return jwk.kty === 'EC' && jwk.crv === { ES256: 'P-256', ES384: 'P-384', ES512: 'P-521' }[alg] && decode(jwk.x).length === size && decode(jwk.y).length === size;
  }
  if (alg === 'Ed25519' || alg === 'EdDSA') return jwk.kty === 'OKP' && jwk.crv === 'Ed25519' && decode(jwk.x).length === 32;
  if (/^[RP]S/.test(alg)) return jwk.kty === 'RSA' && decode(jwk.n).length >= 256 && decode(jwk.n).length <= 1024 && decode(jwk.e).length <= 8;
  return false;
}
function verifyWithJwk(alg, jwk, data, sig) {
  if (!keyMatchesAlgorithm(jwk, alg)) return false;
  const key = createPublicKey({ key: jwk, format: 'jwk' });
  if (key.asymmetricKeyType === 'rsa' && key.asymmetricKeyDetails.modulusLength < 2048) return false;
  const hash = { 256: 'sha256', 384: 'sha384', 512: 'sha512' }[alg.slice(2)];
  if (alg === 'EdDSA' || alg === 'Ed25519') return cryptoVerify(null, data, key, sig);
  if (alg.startsWith('ES')) return cryptoVerify(hash, data, { key, dsaEncoding: 'ieee-p1363' }, sig);
  if (alg.startsWith('RS')) return cryptoVerify(hash, data, key, sig);
  return cryptoVerify(hash, data, { key, padding: constants.RSA_PKCS1_PSS_PADDING, saltLength: Number(alg.slice(2)) / 8 }, sig);
}
export function sameKeyOrigin(jku, cardUrl) {
  try { return publicHttpsUrl(jku).origin === publicHttpsUrl(cardUrl).origin; } catch { return false; }
}
export function makeKeyResolver({ fetcher = safeFetch, trustedKeys = [], network = true, localOnly = trustedKeys.length > 0 } = {}) {
  const cache = new Map();
  return async function resolve(header, cardUrl) {
    const matches = (keys, source) => keys.filter((k) => isObject(k) && (!header.kid || k.kid === header.kid)).map((jwk) => ({ jwk, source }));
    if (localOnly || trustedKeys.length) return matches(trustedKeys, 'trusted');
    if (!network || !header.jku || !sameKeyOrigin(header.jku, cardUrl)) return [];
    const origin = publicHttpsUrl(cardUrl).origin;
    if (!cache.has(header.jku)) cache.set(header.jku, (async () => {
      const r = await fetcher(header.jku, { allowedOrigin: origin });
      if (r.status !== 200 || !r.url || !sameKeyOrigin(r.url, cardUrl)) throw new Error('Key response not permitted');
      const jwks = parseJson(r.body);
      if (!isObject(jwks) || !Array.isArray(jwks.keys) || jwks.keys.length > 32) throw new Error('Invalid JWKS');
      return jwks.keys;
    })());
    return matches(await cache.get(header.jku), 'jku');
  };
}
export async function verifyCard(card, cardUrl, { resolveKeys = makeKeyResolver() } = {}) {
  if (!isObject(card)) return [{ status: 'rejected', findings: ['AC-SIG-006'] }];
  if (card.signatures !== undefined && !Array.isArray(card.signatures)) return [{ status: 'rejected', findings: ['AC-SIG-006'] }];
  const sigs = card.signatures || [];
  if (!sigs.length) return [{ status: 'unsigned', findings: ['AC-SIG-000'] }];
  if (sigs.length > 8) return [{ status: 'rejected', findings: ['AC-SIG-007'] }];
  const results = [];
  for (const [index, s] of sigs.entries()) {
    const r = { index, status: 'rejected', findings: [] };
    let header, sig;
    try {
      if (!isObject(s)) throw new Error();
      header = parseJson(decodeUtf8(decode(s.protected)), { maxBytes: 8192 });
      if (!isObject(header) || typeof header.alg !== 'string') throw new Error();
      for (const k of ['kid', 'jku', 'typ']) if (header[k] !== undefined && typeof header[k] !== 'string') throw new Error();
      if (s.header !== undefined && (!isObject(s.header) || Object.keys(s.header).some((k) => k in header) || ['alg', 'jku', 'kid', 'crit', 'b64'].some((k) => k in s.header))) throw new Error();
      // Unknown critical extensions and alternate payload encodings are unsupported, never ignored.
      if ('crit' in header || 'b64' in header || 'jwk' in header || 'x5u' in header || 'x5c' in header) {
        r.findings.push('AC-SIG-007'); results.push(r); continue;
      }
    } catch { r.findings.push('AC-SIG-006'); results.push(r); continue; }
    Object.assign(r, { alg: header.alg, kid: header.kid, jku: header.jku });
    if (!ALLOWED_ALGS.has(header.alg)) { r.findings.push('AC-SIG-002'); results.push(r); continue; }
    try { sig = decode(s.signature); } catch { r.findings.push('AC-SIG-006'); results.push(r); continue; }
    if (!header.kid) r.findings.push('AC-SIG-004');
    if (header.jku && !sameKeyOrigin(header.jku, cardUrl)) { r.findings.push('AC-SIG-003'); results.push(r); continue; }
    let keys;
    try {
      keys = await resolveKeys(header, cardUrl);
      if (!Array.isArray(keys) || keys.length > 32) throw new Error();
      keys = keys.filter(({ jwk }) => { try { return keyMatchesAlgorithm(jwk, header.alg); } catch { return false; } });
    } catch { keys = []; }
    if (!keys.length) { r.status = 'unresolved'; r.findings.push('AC-SIG-005'); results.push(r); continue; }
    let data;
    try { data = signingInput(card, s.protected); }
    catch { r.findings.push('AC-SIG-006'); results.push(r); continue; }
    r.status = 'invalid';
    for (const { jwk, source } of keys) {
      try {
        if (verifyWithJwk(header.alg, jwk, data, sig)) { Object.assign(r, { status: 'valid', keySource: source, thumbprint: jwkThumbprint(jwk) }); break; }
      } catch { /* A bad key cannot crash the inspection. */ }
    }
    if (r.status !== 'valid') {
      r.findings.push('AC-SIG-001');
      // Diagnose a deployed signer's profile mismatch without accepting a second
      // profile, resolving more keys, or changing the current policy decision.
      if (Array.isArray(card.supportedInterfaces)) {
        const { signatures, ...raw } = card;
        const rawData = Buffer.from(`${s.protected}.${b64u(canonicalize(raw))}`);
        if (!rawData.equals(data)) {
          for (const { jwk, source } of keys) {
            try {
              if (verifyWithJwk(header.alg, jwk, rawData, sig)) {
                r.diagnostic = { code: 'RAW_JCS_ONLY', verifiedProfile: 'jcs', expectedProfile: 'a2a-v1.0.1-presence+jcs', keySource: source, thumbprint: jwkThumbprint(jwk) };
                break;
              }
            } catch { /* An unusable key cannot establish a profile mismatch. */ }
          }
        }
      }
    }
    results.push(r);
  }
  return results;
}
