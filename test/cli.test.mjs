import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, writeFileSync, rmSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = fileURLToPath(new URL('../', import.meta.url));
const run = (...args) => spawnSync(process.execPath, ['src/cli.mjs', ...args], { cwd: root, encoding: 'utf8', timeout: 15000 });
const verify = ['verify', 'examples/unsigned-card.json', '--url', 'https://agent.example.com/.well-known/agent-card.json'];
const pipe = (input, ...options) => spawnSync(process.execPath, ['src/cli.mjs', 'verify', '-', '--url', verify[3], ...options], { cwd: root, input, encoding: 'utf8', timeout: 15000 });

test('stdin and file inspection produce identical offline reports', () => {
  const card = readFileSync(new URL('../examples/unsigned-card.json', import.meta.url));
  const result = pipe(card);
  assert.equal(result.status, 0); assert.equal(result.stderr, '');
  assert.deepEqual(JSON.parse(result.stdout), JSON.parse(run(...verify).stdout));
  const required = pipe(card, '--require-signature', '--format', 'text');
  assert.equal(required.status, 1); assert.match(required.stdout, /Required signature:/);
});

test('stdin rejects empty, malformed, duplicate-member and invalid UTF-8 input without echoing it', () => {
  for (const [input, code] of [['', 'INVALID_JSON'], ['{"secret":"do-not-print",', 'INVALID_JSON'], ['{"a":1,"a":2}', 'DUPLICATE_KEY'], [Buffer.from([0xc0, 0xaf]), 'INVALID_UTF8']]) {
    const result = pipe(input);
    assert.equal(result.status, 2); assert.equal(result.stdout, '');
    assert.equal(JSON.parse(result.stderr).error.code, code);
    assert.ok(!result.stderr.includes('do-not-print'));
  }
});

test('stdin enforces the byte limit and unknown commands fail before input I/O', () => {
  const result = pipe(Buffer.alloc(524289, 32));
  assert.equal(result.status, 2); assert.equal(JSON.parse(result.stderr).error.code, 'INPUT_TOO_LARGE');
  for (const command of ['constructor', '__proto__', 'toString']) {
    const result = run(command, 'missing');
    assert.equal(result.status, 2); assert.equal(JSON.parse(result.stderr).error.code, 'USAGE');
  }
  assert.equal(run('check', '-').status, 2);
});
test('CLI help and version are explicit successful operations', () => {
  assert.match(run('--help').stdout, /Exit codes: 0/); assert.equal(run('--version').status, 0);
});

test('core CLI excludes research commands and research-only options', () => {
  assert.doesNotMatch(run('--help').stdout, /agent-card-scanner (scan|report)|--canary|--concurrency/);
  for (const argv of [['scan', 'seeds.txt'], ['report', 'scan.jsonl'], [...verify, '--canary']]) {
    const result = run(...argv);
    assert.equal(result.status, 2);
    assert.equal(result.stdout, '');
    assert.equal(JSON.parse(result.stderr).error.code, 'USAGE');
  }
});
test('CLI stdout is a single report and stderr stays empty on successful inspection', () => {
  const result = run(...verify);
  assert.equal(result.status, 0); assert.equal(result.stderr, '');
  const report = JSON.parse(result.stdout);
  assert.equal(report.schemaVersion, '1.0'); assert.equal(report.policy.keySource, 'offline'); assert.match(report.target.sha256, /^[a-f0-9]{64}$/);
});
test('CI signature requirement is opt-in and text output explains remediation', () => {
  const failure = run(...verify, '--require-signature');
  assert.equal(failure.status, 1); assert.equal(JSON.parse(failure.stdout).signatureRequiredFailed, true);
  const text = run(...verify, '--format', 'text'); assert.equal(text.status, 0); assert.match(text.stdout, /Next:/);
});
for (const argv of [
  ['check', 'agent.example.com', '--unknown'], ['verify', 'missing.json'], [...verify, '--format', 'xml'], [...verify, '--fail-on', 'critical', '--fail-on', 'none'],
  ['scan', 'missing.txt', '--concurrency', '0'], ['scan', 'missing.txt', '--concurrency', 'NaN'], ['scan', 'missing.txt', '--delay', '-1'], [...verify, '--jwks'], [...verify, '--network=false'],
]) test(`invalid arguments rejected before I/O: ${argv.join(' ')}`, () => {
  const r = run(...argv); assert.equal(r.status, 2); assert.equal(r.stdout, ''); assert.equal(JSON.parse(r.stderr).status, 'error');
});
test('bad input and missing files have distinct exit codes and no stack traces', () => {
  const dir = mkdtempSync(join(tmpdir(), 'scanner-cli-'));
  try {
    const p = join(dir, 'bad.json'); writeFileSync(p, '{"secret":"never print this",');
    const r = run('verify', p, '--url', 'https://example.com/card.json');
    assert.equal(r.status, 2); assert.ok(!r.stderr.includes('never print this')); assert.ok(!r.stderr.includes(' at '));
    assert.equal(run('verify', join(dir, 'missing.json'), '--url', 'https://example.com/card.json').status, 3);
    writeFileSync(p, '[]'); assert.equal(run('verify', p, '--url', 'https://example.com/card.json').status, 2);
    writeFileSync(p, '{"keys":[{"kty":"OKP","d":"sensitive"}]}'); assert.equal(run(...verify, '--jwks', p).status, 2);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});
test('blocked public-check target is an operational failure', () => {
  const r = run('check', 'https://127.0.0.1/card.json');
  assert.equal(r.status, 3); assert.equal(r.stdout, ''); assert.equal(JSON.parse(r.stderr).error.code, 'BLOCKED_ADDRESS');
});
