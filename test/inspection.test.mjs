import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { generateKeyPairSync, sign } from 'node:crypto';
import { inspectCard, inspectPublished, renderInspection } from '../src/inspect.mjs';
import { verifyCard, makeKeyResolver } from '../src/verify.mjs';
import { cardPayload } from '../src/card-payload.mjs';
import { canonicalize } from '../src/jcs.mjs';
import { parseJson, decodeUtf8 } from '../src/input.mjs';

const sample = JSON.parse(readFileSync(new URL('../examples/unsigned-card.json', import.meta.url)));
const url = 'https://agent.example.com/.well-known/agent-card.json';
const b64 = (s) => Buffer.from(s).toString('base64url');
const pair = generateKeyPairSync('ed25519');
const publicJwk = { ...pair.publicKey.export({ format: 'jwk' }), kid: 'demo' };
function signed(card, header = { alg: 'EdDSA', kid: 'demo' }, payload = canonicalize(card)) {
  const protectedHeader = b64(JSON.stringify(header));
  return { ...card, signatures: [{ protected: protectedHeader, signature: b64(sign(null, Buffer.from(`${protectedHeader}.${b64(payload)}`), pair.privateKey)) }] };
}
test('unsigned and auth omission remain advisory even at a low failure threshold', async () => {
  const r = await inspectCard(sample, { cardUrl: url, failOn: 'low' });
  assert.equal(r.decision, 'pass'); assert.equal(r.signatures[0].status, 'unsigned');
  assert.ok(r.findings.every((f) => f.remediation && f.category && f.limitation));
  assert.equal((await inspectCard(sample, { cardUrl: url, requireSignature: true })).decision, 'fail');
});
test('offline verification does not follow an embedded jku', async () => {
  let fetched = 0;
  const card = signed(sample, { alg: 'EdDSA', kid: 'demo', jku: 'https://agent.example.com/keys' });
  const r = await inspectCard(card, { cardUrl: url, fetcher: async () => { fetched++; assert.fail(); } });
  assert.equal(fetched, 0); assert.equal(r.signatures[0].status, 'unresolved');
  assert.equal(r.policy.keySource, 'offline');
});
test('explicit keys are authoritative even when empty or unable to verify', async () => {
  const card = signed(sample, { alg: 'EdDSA', kid: 'demo', jku: 'https://agent.example.com/keys' });
  const fetcher = async () => assert.fail('no network fallback');
  assert.equal((await inspectCard(card, { cardUrl: url, trustedKeys: [], localOnly: true, network: true, fetcher })).signatures[0].status, 'unresolved');
  assert.equal((await inspectCard(card, { cardUrl: url, trustedKeys: [publicJwk], fetcher })).signatures[0].status, 'valid');
});
test('v1 default processing preserves presence, required empties, and extension Struct data', async () => {
  const v1 = { name: 'Example', description: '', version: '', supportedInterfaces: [], defaultInputModes: [], defaultOutputModes: [], capabilities: { streaming: false, pushNotifications: false, extensions: [] }, skills: [], securitySchemes: {}, securityRequirements: [], documentationUrl: '' };
  const expected = '{"capabilities":{"pushNotifications":false,"streaming":false},"defaultInputModes":[],"defaultOutputModes":[],"description":"","documentationUrl":"","name":"Example","skills":[],"supportedInterfaces":[],"version":""}';
  const card = signed(v1, undefined, expected);
  const r = await verifyCard(card, url, { resolveKeys: makeKeyResolver({ trustedKeys: [publicJwk] }) });
  assert.equal(r[0].status, 'valid');
  const withExtension = { ...v1, capabilities: { extensions: [{ uri: 'urn:example', required: false, description: '', params: { flag: false, count: 0, values: [] } }] } };
  assert.deepEqual(cardPayload(withExtension).capabilities.extensions, [{ uri: 'urn:example', params: { flag: false, count: 0, values: [] } }]);
  assert.equal((await verifyCard({ ...card, name: 'Changed' }, url, { resolveKeys: makeKeyResolver({ trustedKeys: [publicJwk] }) }))[0].status, 'invalid');
});
test('v1 OAuth non-optional defaults are omitted while required scopes remain', () => {
  const card = { supportedInterfaces: [], securitySchemes: { auth: { oauth2SecurityScheme: { description: '', oauth2MetadataUrl: '', flows: { authorizationCode: { authorizationUrl: '', tokenUrl: '', refreshUrl: '', scopes: {}, pkceRequired: false } } } } } };
  assert.deepEqual(cardPayload(card).securitySchemes.auth.oauth2SecurityScheme, { flows: { authorizationCode: { authorizationUrl: '', tokenUrl: '', scopes: {} } } });
});

test('raw-JCS-only v1 signatures get a diagnosis without passing or fetching additional keys', async () => {
  const v1 = { name: 'Example', description: 'Example', version: '1', supportedInterfaces: [{ url, protocolBinding: 'JSONRPC', protocolVersion: '1.0' }], capabilities: {}, defaultInputModes: ['text'], defaultOutputModes: ['text'], skills: [], securitySchemes: {}, securityRequirements: [] };
  const rawSigned = signed(v1);
  const options = { cardUrl: url, trustedKeys: [publicJwk], failOn: 'none', requireSignature: true, fetcher: async () => assert.fail('diagnosis must not fetch') };
  const r = await inspectCard(rawSigned, options);
  assert.equal(r.signatures[0].status, 'invalid');
  assert.equal(r.signatures[0].diagnostic.code, 'RAW_JCS_ONLY');
  assert.equal(r.signatures[0].diagnostic.keySource, 'trusted');
  assert.equal(r.signatures[0].keySource, undefined);
  assert.equal(r.signatureRequiredFailed, true); assert.equal(r.decision, 'fail');
  assert.match(renderInspection(r), /verifies with raw JCS but not/);
  const modified = await inspectCard({ ...rawSigned, name: 'Modified' }, options);
  assert.equal(modified.signatures[0].status, 'invalid'); assert.equal(modified.signatures[0].diagnostic, undefined);
  const wrongKey = generateKeyPairSync('ed25519').publicKey.export({ format: 'jwk' });
  assert.equal((await inspectCard(rawSigned, { ...options, trustedKeys: [{ ...wrongKey, kid: 'demo' }] })).signatures[0].diagnostic, undefined);
  const matching = await inspectCard(signed(v1, undefined, canonicalize(cardPayload(v1))), options);
  assert.equal(matching.signatures[0].status, 'valid'); assert.equal(matching.signatures[0].diagnostic, undefined);
});
for (const header of [{ alg: 'EdDSA', crit: ['unknown'] }, { alg: 'EdDSA', b64: false }, { alg: 'EdDSA', jwk: publicJwk }, { alg: 'none' }, { alg: 'HS256' }]) {
  test(`unsupported JOSE profile is rejected: ${JSON.stringify(header).slice(0, 70)}`, async () => {
    const r = await verifyCard(signed(sample, header), url, { resolveKeys: async () => assert.fail('must reject before key lookup') });
    assert.equal(r[0].status, 'rejected');
  });
}
test('malformed signature shapes never crash or become unsigned', async () => {
  for (const signatures of [{}, [null], [{ protected: b64('null'), signature: 'AA' }], [{ protected: b64('{"alg":"EdDSA","jku":3}'), signature: 'AA' }]]) {
    const r = await inspectCard({ ...sample, signatures }, { cardUrl: url });
    assert.equal(r.signatures[0].status, 'rejected'); assert.equal(r.decision, 'fail');
  }
});
test('origin policy includes sibling hosts and non-default ports', async () => {
  for (const jku of ['https://other.example.com/keys', 'https://agent.example.com:8443/keys', 'https://user:secret@agent.example.com/keys']) {
    const r = await verifyCard(signed(sample, { alg: 'EdDSA', jku }), url, { resolveKeys: async () => assert.fail('no cross-origin fetch') });
    assert.equal(r[0].status, 'rejected');
  }
});
test('JWKS validates status, final origin, key count and expected shape', async () => {
  const card = signed(sample, { alg: 'EdDSA', kid: 'demo', jku: 'https://agent.example.com/keys' });
  for (const response of [{ status: 404, url, body: JSON.stringify({ keys: [publicJwk] }) }, { status: 200, url: 'https://other.example/keys', body: JSON.stringify({ keys: [publicJwk] }) }, { status: 200, url, body: '{"keys":{}}' }]) {
    assert.equal((await inspectCard(card, { cardUrl: url, network: true, fetcher: async () => response })).signatures[0].status, 'unresolved');
  }
  let options;
  const r = await inspectCard(card, { cardUrl: url, network: true, fetcher: async (_, o) => { options = o; return { status: 200, url, body: JSON.stringify({ keys: [publicJwk] }) }; } });
  assert.equal(r.signatures[0].status, 'valid'); assert.equal(options.allowedOrigin, 'https://agent.example.com');
});
test('key use, algorithm and private-key mismatch cannot verify', async () => {
  for (const k of [{ ...publicJwk, use: 'enc' }, { ...publicJwk, alg: 'ES256' }, { ...publicJwk, key_ops: ['encrypt'] }, pair.privateKey.export({ format: 'jwk' })]) {
    assert.notEqual((await inspectCard(signed(sample), { cardUrl: url, trustedKeys: [k] })).signatures[0].status, 'valid');
  }
});
test('duplicate members, Unicode surrogates, depth, and nonfinite numbers are rejected', () => {
  for (const input of ['{"a":1,"a":2}', '{"a":1,"\\u0061":2}', '{"x":"\\ud800"}', '{"n":1e999}', '['.repeat(70) + '0' + ']'.repeat(70)]) assert.throws(() => parseJson(input));
  assert.throws(() => canonicalize('\ud800'));
  assert.throws(() => decodeUtf8(Buffer.from([0xc0, 0xaf])), { code: 'INVALID_UTF8' });
  assert.deepEqual(parseJson('{"a":[1,true,null,{"x":"a\\"b"}]}'), { a: [1, true, null, { x: 'a"b' }] });
});
test('signature count, colliding unprotected headers, and invalid base64url are rejected', async () => {
  const valid = signed(sample);
  const candidates = [
    { ...sample, signatures: Array(9).fill(valid.signatures[0]) },
    { ...sample, signatures: [{ ...valid.signatures[0], header: { alg: 'EdDSA' } }] },
    { ...sample, signatures: [{ ...valid.signatures[0], protected: valid.signatures[0].protected + '=' }] },
  ];
  for (const candidate of candidates) assert.equal((await verifyCard(candidate, url))[0].status, 'rejected');
});
test('explicit URLs are inspected exactly; discovery falls back from HTML', async () => {
  const calls = [];
  const fetcher = async (u) => { calls.push(u); return { url: u, status: 200, body: u.endsWith('agent-card.json') ? '<html>Not found</html>' : JSON.stringify(sample) }; };
  assert.equal((await inspectPublished('https://agent.example.com/cards/custom', { fetcher })).discovery.attempts, 1);
  assert.deepEqual(calls, ['https://agent.example.com/cards/custom']);
  calls.length = 0;
  assert.equal((await inspectPublished('agent.example.com', { fetcher })).discovery.attempts, 2);
  assert.equal(calls.length, 2);
});
test('network errors are incomplete operations, not successful card checks', async () => {
  await assert.rejects(inspectPublished('agent.example.com', { fetcher: async () => { throw Object.assign(new Error('private detail'), { code: 'TIMEOUT' }); } }), { code: 'TIMEOUT', exitCode: 3 });
});

test('published reports identify the retrieved snapshot and the final publication origin', async () => {
  const calls = [];
  const before = Date.now();
  const report = await inspectPublished('https://agent.example.com/card', { fetcher: async (u) => {
    calls.push(u);
    return { url: 'https://final.example.com/cards/current', status: 200, body: JSON.stringify(sample) };
  } });
  const retrieved = Date.parse(report.discovery.retrievedAt);
  assert.ok(retrieved >= before && retrieved <= Date.now());
  assert.equal(report.target.url, 'https://final.example.com/cards/current');
  assert.equal(report.target.sha256, (await inspectCard(sample, { cardUrl: report.target.url })).target.sha256);
  assert.deepEqual(calls, ['https://agent.example.com/card']);
  assert.match(renderInspection(report), /Retrieved: .*card snapshot; not continuous monitoring/);
  assert.equal((await inspectCard(sample, { cardUrl: url })).discovery, undefined);
});
test('reports redact URL queries and human output escapes terminal instructions', async () => {
  const r = await inspectCard({ ...sample, url: 'http://agent.example.com/api?secret=hidden\u001b[31m' }, { cardUrl: url + '?token=hidden' });
  assert.ok(!JSON.stringify(r).includes('hidden'));
  r.findings[0].evidence = '\u001b[2J\nFake PASS';
  const text = renderInspection(r); assert.ok(!text.includes('\u001b')); assert.ok(text.includes('\\u001b'));
});
