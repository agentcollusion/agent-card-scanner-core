#!/usr/bin/env node
import { readFileSync, statSync } from 'node:fs';
import { parseJson, isObject, InputError, decodeUtf8, MAX_JSON_BYTES, readJsonStream, validatePublicKeys } from './input.mjs';
import { inspectCard, inspectPublished, renderInspection, TOOL_VERSION } from './inspect.mjs';

import { compareCardJson, renderComparison } from './card-comparison.mjs';

const HELP = `Agent Card Scanner ${TOOL_VERSION}
Inspect A2A cards with explicit evidence, remediation, and CI policy.

Usage:
  agent-card-scanner verify <card.json|-> --url <https-url> [options]
  agent-card-scanner compare <before.json> <after.json> [--format json|text] [--fail-on changes|none]
  agent-card-scanner check <host-or-https-url> [options]

Compare is always offline. Exit 1 means declarations need review (default --fail-on changes).

Single-card options:
  -                        Read the card JSON from standard input (verify only)
  --format json|text        Output format (default json)
  --fail-on high|critical|medium|low|none  Non-advisory failure threshold (default high)
  --require-signature       Require at least one verified signature
  --jwks <public-keys.json>  Use only these caller-provided public keys
  --network                 Allow same-origin key lookup for local verify (default offline)

  --help, -h                Show help
  --version                 Show version

Exit codes: 0 policy passed; 1 policy failed; 2 invalid input/usage; 3 incomplete operation.
Unsigned is advisory by default. A valid signature is not a certificate of runtime safety.
No telemetry. Local verify is offline unless --network is supplied.
`;
function args(argv) {
  if (argv.length === 1 && argv[0] === '--version') return { version: true };
  if (argv.length === 0 || argv.some((x) => x === '--help' || x === '-h')) return { help: true };
  const [command, ...rest] = argv;
  const commands = {
    verify: ['url', 'format', 'fail-on', 'require-signature', 'jwks', 'network'],
    check: ['format', 'fail-on', 'require-signature', 'jwks'],
    compare: ['format', 'fail-on'],
  };
  if (!Object.hasOwn(commands, command)) throw new InputError('USAGE', 'Unknown command. Use --help.');
  const allowed = commands[command];
  const boolean = new Set(['require-signature', 'network']);
  const flags = {}; const targets = [];
  for (let i = 0; i < rest.length; i++) {
    const token = rest[i];
    if (!token.startsWith('-') || (token === '-' && command === 'verify')) { targets.push(token); if (targets.length > (command === 'compare' ? 2 : 1)) throw new InputError('USAGE', 'Too many targets.'); continue; }
    const [name, ...inline] = token.slice(2).split('=');
    if (!token.startsWith('--') || !allowed.includes(name) || Object.hasOwn(flags, name)) throw new InputError('USAGE', 'Unknown or repeated option. Use --help.');
    if (boolean.has(name)) {
      if (inline.length) throw new InputError('USAGE', 'Boolean options do not accept a value.');
      flags[name] = true;
    } else {
      const value = inline.length ? inline.join('=') : rest[++i];
      if (!value || value.startsWith('--')) throw new InputError('USAGE', 'Option value is missing.');
      flags[name] = value;
    }
  }
  const [target, after] = targets;
  if (command === 'compare' && targets.length !== 2) throw new InputError('USAGE', 'Compare requires two JSON files.');
  if (!target || (command === 'verify' && !flags.url)) throw new InputError('USAGE', 'Target and required --url are missing. Use --help.');
  if (flags.format && !['text', 'json'].includes(flags.format)) throw new InputError('USAGE', 'Unsupported output format.');
  if (flags['fail-on'] && !(command === 'compare' ? ['changes', 'none'] : ['low', 'medium', 'high', 'critical', 'none']).includes(flags['fail-on'])) throw new InputError('USAGE', 'Unsupported failure threshold.');
  return { command, target, after, flags };
}
function fileText(path) {
  if (statSync(path).size > MAX_JSON_BYTES) throw new InputError('INPUT_TOO_LARGE', 'File exceeds the 512 KiB input limit.');
  return decodeUtf8(readFileSync(path));
}
function fileJson(path) {
  if (statSync(path).size > MAX_JSON_BYTES) throw new InputError('INPUT_TOO_LARGE', 'File exceeds the 512 KiB input limit.');
  return parseJson(decodeUtf8(readFileSync(path)));
}
try {
  const a = args(process.argv.slice(2));
  if (a.help) process.stdout.write(HELP);
  else if (a.version) process.stdout.write(`${TOOL_VERSION}\n`);
  else if (a.command === 'compare') {
    const result = compareCardJson(fileText(a.target), fileText(a.after));
    process.stdout.write((a.flags.format === 'text' ? renderComparison(result) : JSON.stringify(result, null, 2)) + '\n');
    process.exitCode = result.decision === 'review-required' && a.flags['fail-on'] !== 'none' ? 1 : 0;
  }
  else {
    const keys = a.flags.jwks ? fileJson(a.flags.jwks) : { keys: [] };
    validatePublicKeys(isObject(keys) ? keys.keys : undefined);
    const options = { trustedKeys: keys.keys, localOnly: !!a.flags.jwks, failOn: a.flags['fail-on'] || 'high', requireSignature: !!a.flags['require-signature'], network: !!a.flags.network };
    const result = a.command === 'verify'
      ? await inspectCard(a.target === '-' ? await readJsonStream(process.stdin) : fileJson(a.target), { ...options, cardUrl: a.flags.url })
      : await inspectPublished(a.target, options);
    process.stdout.write((a.flags.format === 'text' ? renderInspection(result) : JSON.stringify(result, null, 2)) + '\n');
    process.exitCode = result.decision === 'fail' ? 1 : 0;
  }
} catch (e) {
  const exitCode = e.exitCode || 3;
  // Never echo raw card input, URLs, secrets, or stacks in operational errors.
  const error = { schemaVersion: '1.0', status: 'error', error: { code: e.code || 'OPERATION_FAILED', message: e instanceof InputError || e.exitCode ? e.message : 'Operation failed. Check file paths, permissions, and network connectivity.' } };
  process.stderr.write(JSON.stringify(error) + '\n');
  process.exitCode = exitCode;
}
