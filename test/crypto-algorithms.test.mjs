import test from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync, sign, constants, webcrypto } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { verifyCard, makeKeyResolver } from '../src/verify.mjs';
import { canonicalize } from '../src/jcs.mjs';

const card = JSON.parse(readFileSync(new URL('../examples/unsigned-card.json', import.meta.url)));
const url = 'https://agent.example.com/card.json';
const b64 = (s) => Buffer.from(s).toString('base64url');
const rsa = generateKeyPairSync('rsa', { modulusLength: 2048 });
for (const alg of ['ES256', 'ES384', 'ES512', 'EdDSA', 'Ed25519', 'RS256', 'RS384', 'RS512', 'PS256', 'PS384', 'PS512']) {
  test(`${alg} verifies matching key and rejects modified card`, async () => {
    const pair = alg.startsWith('ES') ? generateKeyPairSync('ec', { namedCurve: { ES256: 'P-256', ES384: 'P-384', ES512: 'P-521' }[alg] }) : alg.startsWith('Ed') ? generateKeyPairSync('ed25519') : rsa;
    const jwk = { ...pair.publicKey.export({ format: 'jwk' }), kid: 'test', alg, use: 'sig', key_ops: ['verify'] };
    const protectedHeader = b64(JSON.stringify({ alg, kid: 'test' }));
    const data = Buffer.from(`${protectedHeader}.${b64(canonicalize(card))}`);
    const hash = alg.startsWith('Ed') ? null : 'sha' + alg.slice(2);
    const key = alg.startsWith('ES') ? { key: pair.privateKey, dsaEncoding: 'ieee-p1363' } : alg.startsWith('PS') ? { key: pair.privateKey, padding: constants.RSA_PKCS1_PSS_PADDING, saltLength: Number(alg.slice(2)) / 8 } : pair.privateKey;
    const input = { ...card, signatures: [{ protected: protectedHeader, signature: b64(sign(hash, data, key)) }] };
    const opts = { resolveKeys: makeKeyResolver({ trustedKeys: [jwk] }) };
    assert.equal((await verifyCard(input, url, opts))[0].status, 'valid');
    assert.equal((await verifyCard({ ...input, name: 'Tampered' }, url, opts))[0].status, 'invalid');
  });
}
test('WebCrypto ECDSA producer interoperates with the JWS verifier', async () => {
  const pair = await webcrypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
  const jwk = await webcrypto.subtle.exportKey('jwk', pair.publicKey);
  const protectedHeader = b64('{"alg":"ES256"}');
  // Fixed primitive object avoids sharing the production payload-construction function.
  const body = { name: 'Interop' };
  const data = new TextEncoder().encode(`${protectedHeader}.${b64('{"name":"Interop"}')}`);
  const signature = await webcrypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, pair.privateKey, data);
  const result = await verifyCard({ ...body, signatures: [{ protected: protectedHeader, signature: b64(signature) }] }, url, { resolveKeys: makeKeyResolver({ trustedKeys: [jwk] }) });
  assert.equal(result[0].status, 'valid');
});
test('curve/algorithm confusion and short RSA keys cannot verify', async () => {
  const pair = generateKeyPairSync('ec', { namedCurve: 'P-384' });
  const header = b64('{"alg":"ES256"}');
  const data = Buffer.from(`${header}.${b64(canonicalize(card))}`);
  const input = { ...card, signatures: [{ protected: header, signature: b64(sign('sha256', data, { key: pair.privateKey, dsaEncoding: 'ieee-p1363' })) }] };
  assert.notEqual((await verifyCard(input, url, { resolveKeys: makeKeyResolver({ trustedKeys: [pair.publicKey.export({ format: 'jwk' })] }) }))[0].status, 'valid');
  const short = generateKeyPairSync('rsa', { modulusLength: 1024 });
  assert.notEqual((await verifyCard(input, url, { resolveKeys: makeKeyResolver({ trustedKeys: [short.publicKey.export({ format: 'jwk' })] }) }))[0].status, 'valid');
});
