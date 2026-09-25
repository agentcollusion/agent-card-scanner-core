import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, mkdtempSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';
import { compareCardJson, renderComparison } from '../src/card-comparison.mjs';
const base = () => JSON.parse(readFileSync(new URL('../examples/unsigned-card.json', import.meta.url), 'utf8'));
const compare = (a, b) => compareCardJson(JSON.stringify(a), JSON.stringify(b));
const v1 = () => {
  const c = base(); delete c.url; delete c.protocolVersion;
  c.supportedInterfaces = [{ url: 'https://agent.example.com/a2a', protocolBinding: 'JSONRPC', protocolVersion: '1.0' }];
  return c;
};
const authCard = (modern = false) => {
  const c = modern ? v1() : base();
  c.securitySchemes = modern ? { a: { httpAuthSecurityScheme: { scheme: 'bearer' } }, b: { mtlsSecurityScheme: {} } } : { a: { type: 'http', scheme: 'bearer' }, b: { type: 'mutualTLS' } };
  c[modern ? 'securityRequirements' : 'security'] = modern ? [{ schemes: { a: { list: ['read', 'write'] }, b: { list: [] } } }, { schemes: { a: { list: ['admin'] } } }] : [{ a: ['read', 'write'], b: [] }, { a: ['admin'] }];
  return c;
};
test('unchanged cards and metadata-only changes do not imply safety', () => {
  const a = base(), b = base(); b.version = '2'; b.description = 'new copy';
  const r = compare(a, b);
  assert.equal(r.decision, 'no-covered-changes'); assert.match(r.limitation, /no runtime compatibility/);
  assert.equal(r.context.after.agentVersion, '2');
});
test('release example identifies removals, auth and capability changes', () => {
  const r = compareCardJson(readFileSync(new URL('../examples/compare-before.json', import.meta.url), 'utf8'), readFileSync(new URL('../examples/compare-after.json', import.meta.url), 'utf8'));
  assert.equal(r.decision, 'review-required');
  assert.ok(r.changes.some(x => x.area === 'skill' && x.kind === 'removed' && x.before.id === 'summarize'));
  assert.ok(r.changes.some(x => x.area === 'interface' && x.kind === 'removed'));
  assert.ok(r.changes.some(x => x.area === 'authentication'));
  assert.ok(r.changes.some(x => x.area === 'capability' && x.before === true && x.after === false));
});
test('skill order, mode order, default JSONRPC and duplicate additional primary are neutral', () => {
  const a = base(); a.skills.push({ ...a.skills[0], id: 'two' }); a.defaultInputModes.push('application/json');
  const b = structuredClone(a); b.skills.reverse(); b.defaultInputModes.reverse(); b.preferredTransport = 'JSONRPC';
  b.additionalInterfaces = [{ url: b.url, transport: 'JSONRPC' }];
  assert.equal(compare(a, b).changes.length, 0);
});
for (const modern of [false, true]) test('auth order is neutral; AND/OR and scope changes are reviewed: ' + modern, () => {
  const a = authCard(modern), b = structuredClone(a), key = modern ? 'securityRequirements' : 'security';
  b[key].reverse(); (modern ? b[key][1].schemes.a.list : b[key][1].a).reverse();
  assert.equal(compare(a, b).changes.length, 0);
  b[key] = modern ? [{ schemes: { a: { list: ['read'] } } }, { schemes: { b: {} } }] : [{ a: ['read'] }, { b: [] }];
  assert.ok(compare(a, b).changes.some(x => x.area === 'authentication'));
});
test('inherited and explicit skill modes are compared effectively', () => {
  const a = base(), b = base(); b.skills[0].inputModes = ['text/plain'];
  assert.equal(compare(a, b).changes.length, 0);
  b.skills[0].inputModes = ['application/json'];
  const r = compare(a, b).changes.find(x => x.area === 'skill-modes');
  assert.equal(r.beforePath, '/defaultInputModes'); assert.equal(r.afterPath, '/skills/0/inputModes');
  assert.equal(r.before.skill, 'echo');
});
test('v1 repeated empty modes inherit defaults; v0.3 explicit empty remains a declaration', () => {
  const a = v1(), b = v1(); b.skills[0].inputModes = [];
  assert.equal(compare(a, b).changes.length, 0);
  const c = base(), d = base(); d.skills[0].inputModes = [];
  assert.ok(compare(c, d).changes.some(x => x.area === 'skill-modes'));
});
test('v1 preference, tenant and protocol version changes retain context', () => {
  const a = v1(); a.supportedInterfaces.push({ url: 'https://agent.example.com/rest', protocolBinding: 'HTTP+JSON', protocolVersion: '1.0' });
  const b = structuredClone(a); b.supportedInterfaces.reverse();
  assert.deepEqual(compare(a, b).changes.map(x => x.area), ['interface-preference']);
  b.supportedInterfaces[0].tenant = 'tenant-b'; b.supportedInterfaces[0].protocolVersion = '1.1';
  const r = compare(a, b); assert.ok(r.changes.some(x => x.kind === 'removed'));
  assert.deepEqual(r.context.after.protocolVersions, ['1.0', '1.1']);
});
test('scheme definitions and extension parameters are omitted from exports', () => {
  const a = authCard(), b = authCard(); b.securitySchemes.a.secretExtension = 'TOP-SECRET';
  b.capabilities.extensions = [{ uri: 'urn:example:extension', required: true, params: { token: 'TOP-SECRET' } }];
  const output = JSON.stringify(compare(a, b));
  assert.ok(!output.includes('TOP-SECRET')); assert.match(output, /security-scheme/); assert.match(output, /extensions/);
});
test('URL evidence is redacted after comparison, including changes only in queries', () => {
  const a = base(), b = base();
  a.url = 'https://user:OLD-SECRET@agent.example.com/a2a?token=OLD-SECRET#OLD-SECRET';
  b.url = 'https://user:NEW-SECRET@agent.example.com/a2a?token=NEW-SECRET#NEW-SECRET';
  const r = compare(a, b); assert.equal(r.decision, 'review-required');
  assert.ok(!JSON.stringify(r).includes('SECRET')); assert.match(JSON.stringify(r), /redacted/);
});
test('reserved object-member names never inherit prototype properties', () => {
  const a = base(), b = base(); b.securitySchemes = JSON.parse('{"constructor":{"type":"http","scheme":"bearer"},"__proto__":{"type":"mutualTLS"}}');
  b.security = JSON.parse('[{"constructor":[],"__proto__":[]}]');
  assert.equal(compare(a, b).decision, 'review-required');
});
test('custom fields are reviewed without exporting opaque values; metadata is excluded', () => {
  const a = base(), b = base(); b.custom = { token: 'DO-NOT-EXPORT' };
  const r = compare(a, b); assert.ok(r.changes.some(x => x.area === 'custom-fields'));
  assert.ok(!JSON.stringify(r).includes('DO-NOT-EXPORT'));
});
for (const [label, mutate] of [
  ['skills missing', c => delete c.skills], ['skills null', c => c.skills = null],
  ['duplicate IDs', c => c.skills.push(c.skills[0])], ['wrong modes', c => c.defaultInputModes = 'text/plain'],
  ['wrong skill modes', c => c.skills[0].inputModes = null], ['wrong capability', c => c.capabilities.streaming = 'false'],
  ['wrong auth type', c => c.security = {}], ['undefined scheme', c => c.security = [{ absent: [] }]],
  ['invalid scheme', c => c.securitySchemes = { x: { type: 'http' } }],
  ['wrong scopes', c => { c.securitySchemes = { a: { type: 'http', scheme: 'bearer' } }; c.security = [{ a: 'read' }]; }],
  ['mixed generation', c => c.securityRequirements = []], ['invalid URL', c => c.url = '/relative'],
  ['snake capability', c => c.capabilities.push_notifications = true],
]) test('reject malformed compared fields: ' + label, () => {
  const b = base(); mutate(b);
  assert.throws(() => compare(base(), b), e => e.exitCode === 2 && e.message.startsWith('after '));
});
test('duplicate JSON keys, excessive size/depth and invalid unicode are rejected with side', () => {
  const a = JSON.stringify(base());
  for (const input of ['{"secret":"DO-NOT-ECHO","secret":1}', 'x'.repeat(524289), '['.repeat(66) + '0' + ']'.repeat(66), '{"name":"\\ud800"}']) {
    assert.throws(() => compareCardJson(a, input), e => e.exitCode === 2 && e.message.startsWith('after:') && !e.message.includes('DO-NOT-ECHO'));
  }
});
test('protocol-generation migration and duplicate v1 interfaces are rejected', () => {
  assert.throws(() => compare(base(), v1()), e => e.code === 'UNSUPPORTED_MIGRATION');
  const b = v1(); b.supportedInterfaces.push(b.supportedInterfaces[0]);
  assert.throws(() => compare(v1(), b), /duplicate interface/);
});
test('rendered evidence escapes control and bidi characters', () => {
  const a = base(), b = base(); b.skills[0].id = 'fake\u001b[31m\u202eecho';
  const text = renderComparison(compare(a, b));
  assert.ok(!text.includes('\u001b')); assert.ok(!text.includes('\u202e')); assert.match(text, /Next:/);
});
test('offline CLI has review/override/invalid/I-O exits and rejects flags before I/O', () => {
  const run = (...args) => spawnSync(process.execPath, ['src/cli.mjs', ...args], { encoding: 'utf8', timeout: 10000 });
  const before = 'examples/compare-before.json', after = 'examples/compare-after.json';
  let r = run('compare', before, after); assert.equal(r.status, 1, r.stderr); assert.equal(JSON.parse(r.stdout).decision, 'review-required');
  r = run('compare', before, after, '--fail-on', 'none', '--format', 'text'); assert.equal(r.status, 0); assert.match(r.stdout, /summarize/);
  assert.equal(run('compare', before, before).status, 0);
  for (const args of [['compare', 'missing'], ['compare', 'missing', 'missing', '--network'], ['compare', 'missing', 'missing', '--fail-on', 'high'], ['compare', before, after, after]]) assert.equal(run(...args).status, 2);
  assert.equal(run('compare', 'missing', 'missing').status, 3);
  const dir = mkdtempSync(join(tmpdir(), 'scanner-compare-'));
  try {
    const bad = join(dir, 'bad.json'); writeFileSync(bad, Buffer.from([0xff]));
    r = run('compare', before, bad); assert.equal(r.status, 2); assert.equal(JSON.parse(r.stderr).error.code, 'INVALID_UTF8');
    writeFileSync(bad, '{"private":"DO-NOT-ECHO",'); r = run('compare', before, bad);
    assert.equal(r.status, 2); assert.ok(!r.stderr.includes('DO-NOT-ECHO'));
  } finally { rmSync(dir, { recursive: true, force: true }); }
});
