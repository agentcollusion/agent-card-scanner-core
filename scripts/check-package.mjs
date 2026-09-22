// Verify the actual archive and install without publishing or running package lifecycle scripts.
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = fileURLToPath(new URL('../', import.meta.url));
const tempRoot = resolve(tmpdir());
const destination = mkdtempSync(join(tempRoot, 'scanner-package-'));
assert.ok(resolve(destination).startsWith(tempRoot + (process.platform === 'win32' ? '\\' : '/')));
const npmCli = process.env.npm_execpath;
assert.ok(npmCli, 'Run with npm run check:package');
function execute(command, args, cwd = root) {
  const r = spawnSync(command, args, { cwd, encoding: 'utf8', timeout: 60000 });
  assert.equal(r.status, 0, r.stderr || String(r.error));
  return r.stdout;
}
try {
  const [archive] = JSON.parse(execute(process.execPath, [npmCli, 'pack', '--json', '--ignore-scripts', '--offline', '--pack-destination', destination]));
  const allowed = new Set([
    ...['cli', 'inspect', 'checks', 'rule-guidance', 'normalize', 'verify', 'safe-fetch', 'input', 'jcs', 'card-payload', 'domain'].map((name) => `src/${name}.mjs`),
    'examples/unsigned-card.json', 'docs/cli.md', 'schemas/inspection.schema.json', 'README.md', 'README.ja.md', 'LICENSE', 'NOTICE', 'package.json',
  ]);
  assert.deepEqual(new Set(archive.files.map(({ path }) => path)), allowed, 'Package must contain exactly the reviewed core files');
  execute(process.execPath, [npmCli, 'install', '--prefix', destination, '--ignore-scripts', '--no-audit', '--no-fund', '--offline', join(destination, archive.filename)]);
  const installed = join(destination, 'node_modules', 'agent-card-scanner-core');
  const pkg = JSON.parse(readFileSync(join(installed, 'package.json'), 'utf8'));
  const cli = join(installed, pkg.bin['agent-card-scanner']);
  const report = JSON.parse(execute(process.execPath, [cli, 'verify', join(installed, 'examples', 'unsigned-card.json'), '--url', 'https://agent.example.com/card.json']));
  assert.equal(report.decision, 'pass'); assert.equal(report.policy.keySource, 'offline');
  // Resolve the public export from a consumer, rather than importing a source path.
  const consumer = join(destination, 'consumer.mjs');
  writeFileSync(consumer, `import { inspectCard } from 'agent-card-scanner-core';\nimport { readFileSync } from 'node:fs';\nconst card = JSON.parse(readFileSync(new URL('./node_modules/agent-card-scanner-core/examples/unsigned-card.json', import.meta.url)));\nconsole.log((await inspectCard(card, { cardUrl: 'https://agent.example.com/card.json' })).decision);\n`);
  assert.equal(execute(process.execPath, [consumer]).trim(), 'pass');
  console.log(`Package verified: ${archive.entryCount} files; installed CLI and library work offline.`);
} finally { rmSync(destination, { recursive: true, force: true }); }
