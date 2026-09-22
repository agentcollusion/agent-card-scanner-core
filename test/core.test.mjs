import { test } from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync, sign as cryptoSign } from 'node:crypto';
import { canonicalize } from '../src/jcs.mjs';
import { isPublicAddress } from '../src/safe-fetch.mjs';
import { registrableDomain } from '../src/domain.mjs';
import { verifyCard, makeKeyResolver, jwkThumbprint } from '../src/verify.mjs';
import { normalizeCard } from '../src/normalize.mjs';
import { checkCard } from '../src/checks.mjs';

const b64u = (b) => Buffer.from(b).toString('base64url');

const v1Card = () => ({
  name: 'Parts Quote Agent',
  description: 'Quotes machined parts',
  version: '1.2.0',
  supportedInterfaces: [{ url: 'https://agents.supplier.example/a2a', protocolBinding: 'JSONRPC', protocolVersion: '1.0' }],
  provider: { organization: 'Supplier Example Inc.', url: 'https://supplier.example' },
  capabilities: { streaming: true },
  securitySchemes: {
    oauth: { oauth2SecurityScheme: { flows: { authorizationCode: { authorizationUrl: 'https://auth.supplier.example/authorize', tokenUrl: 'https://auth.supplier.example/token', scopes: { quote: 'q' } } } } },
  },
  skills: [{ id: 'quote', name: 'Quote', tags: ['parts'] }],
});

function signCard(card, { alg, privateKey, kid = 'k1', jku }) {
  const { signatures, ...body } = card;
  const protectedB64 = b64u(JSON.stringify({ alg, typ: 'JOSE', kid, ...(jku ? { jku } : {}) }));
  const input = Buffer.from(`${protectedB64}.${b64u(canonicalize(body))}`);
  const sig = alg === 'EdDSA' ? cryptoSign(null, input, privateKey) : cryptoSign('sha256', input, { key: privateKey, dsaEncoding: 'ieee-p1363' });
  return { ...body, signatures: [{ protected: protectedB64, signature: b64u(sig) }] };
}

test('JCS sorts keys, drops whitespace, serializes numbers per ECMAScript', () => {
  assert.equal(canonicalize({ b: 2, a: [1, 1.5e21, -0, 'x'] }), '{"a":[1,1.5e+21,0,"x"],"b":2}');
});

test('private and special addresses are blocked', () => {
  for (const ip of ['127.0.0.1', '10.1.2.3', '169.254.169.254', '192.168.0.1', '::1', 'fd00::1', '::ffff:127.0.0.1']) assert.equal(isPublicAddress(ip), false, ip);
  for (const ip of ['8.8.8.8', '1.1.1.1', '2606:4700::1111']) assert.equal(isPublicAddress(ip), true, ip);
});

test('registrable domain handles multi-label suffixes and shared hosting', () => {
  assert.equal(registrableDomain('agents.supplier.co.jp'), 'supplier.co.jp');
  assert.equal(registrableDomain('acme.vercel.app'), 'acme.vercel.app');
  assert.equal(registrableDomain('a.b.example.com'), 'example.com');
});

for (const [alg, type, opts] of [['ES256', 'ec', { namedCurve: 'P-256' }], ['EdDSA', 'ed25519', {}]]) {
  test(`${alg}: valid signature verifies; tampering and key-order changes behave correctly`, async () => {
    const { publicKey, privateKey } = generateKeyPairSync(type, opts);
    const jwk = { ...publicKey.export({ format: 'jwk' }), kid: 'k1' };
    const resolveKeys = makeKeyResolver({ trustedKeys: [jwk] });
    const url = 'https://supplier.example/.well-known/agent-card.json';
    const signed = signCard(v1Card(), { alg, privateKey });

    const [ok] = await verifyCard(signed, url, { resolveKeys });
    assert.equal(ok.status, 'valid');
    assert.equal(ok.thumbprint, jwkThumbprint(jwk));

    const reordered = { skills: signed.skills, ...signed };
    assert.equal((await verifyCard(reordered, url, { resolveKeys }))[0].status, 'valid');

    const tampered = { ...signed, provider: { ...signed.provider, url: 'https://evil.example' } };
    const [bad] = await verifyCard(tampered, url, { resolveKeys });
    assert.equal(bad.status, 'invalid');
    assert.ok(bad.findings.includes('AC-SIG-001'));
  });
}

test('alg "none" and HS256 are rejected before any key lookup', async () => {
  let looked = false;
  const resolveKeys = async () => { looked = true; return []; };
  for (const alg of ['none', 'HS256']) {
    const card = { ...v1Card(), signatures: [{ protected: b64u(JSON.stringify({ alg, kid: 'k1' })), signature: '' }] };
    const [r] = await verifyCard(card, 'https://supplier.example/.well-known/agent-card.json', { resolveKeys });
    assert.equal(r.status, 'rejected');
    assert.ok(r.findings.includes('AC-SIG-002'));
  }
  assert.equal(looked, false);
});

test('cross-site jku is rejected without fetching it', async () => {
  let fetched = false;
  const resolveKeys = makeKeyResolver({ fetcher: async () => { fetched = true; return { body: '{"keys":[]}' }; } });
  const { privateKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' });
  const signed = signCard(v1Card(), { alg: 'ES256', privateKey, jku: 'https://attacker.example/jwks.json' });
  const [r] = await verifyCard(signed, 'https://supplier.example/.well-known/agent-card.json', { resolveKeys });
  assert.equal(r.status, 'rejected');
  assert.ok(r.findings.includes('AC-SIG-003'));
  assert.equal(fetched, false);
});

test('v0.x cards normalize and trigger auth and transport checks', () => {
  const legacy = {
    name: 'Old Agent', version: '0.1', protocolVersion: '0.3.0', url: 'http://old.example/a2a',
    securitySchemes: { key: { type: 'apiKey', in: 'query', name: 'api_key' }, o: { type: 'oauth2', flows: { implicit: { authorizationUrl: 'https://old.example/auth', scopes: {} } } } },
    skills: [{ id: 's', name: 'S' }],
  };
  const n = normalizeCard(legacy);
  assert.equal(n.specGeneration, 'v0.x');
  const ids = checkCard(n, { cardUrl: 'https://old.example/.well-known/agent.json', legacyPath: true }).map((f) => f.id);
  for (const id of ['AC-PATH-001', 'AC-TLS-001', 'AC-AUTH-002', 'AC-AUTH-003', 'AC-PROV-001']) assert.ok(ids.includes(id), id);
});
