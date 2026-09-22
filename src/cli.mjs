#!/usr/bin/env node
import { readFileSync, statSync } from 'node:fs';
import { parseJson, isObject, InputError, decodeUtf8 } from './input.mjs';
import { inspectCard, inspectPublished, renderInspection, TOOL_VERSION } from './inspect.mjs';

const HELP = `Agent Card Scanner ${TOOL_VERSION}
Inspect A2A cards with explicit evidence, remediation, and CI policy.

Usage:
  agent-card-scanner verify <card.json> --url <https-url> [options]
  agent-card-scanner check <host-or-https-url> [options]

Single-card options:
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
  const allowed = {
    verify: ['url', 'format', 'fail-on', 'require-signature', 'jwks', 'network'],
    check: ['format', 'fail-on', 'require-signature', 'jwks'],
  }[command];
  if (!allowed) throw new InputError('USAGE', 'Unknown command. Use --help.');
  const boolean = new Set(['require-signature', 'network']);
  const flags = {}; let target;
  for (let i = 0; i < rest.length; i++) {
    const token = rest[i];
    if (!token.startsWith('-')) { if (target) throw new InputError('USAGE', 'Expected one target.'); target = token; continue; }
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
  if (!target || (command === 'verify' && !flags.url)) throw new InputError('USAGE', 'Target and required --url are missing. Use --help.');
  if (flags.format && !['text', 'json'].includes(flags.format)) throw new InputError('USAGE', 'Unsupported output format.');
  if (flags['fail-on'] && !['low', 'medium', 'high', 'critical', 'none'].includes(flags['fail-on'])) throw new InputError('USAGE', 'Unsupported failure threshold.');
  return { command, target, flags };
}
function fileJson(path) {
  if (statSync(path).size > 524288) throw new InputError('INPUT_TOO_LARGE', 'File exceeds the 512 KiB input limit.');
  return parseJson(decodeUtf8(readFileSync(path)));
}
try {
  const a = args(process.argv.slice(2));
  if (a.help) process.stdout.write(HELP);
  else if (a.version) process.stdout.write(`${TOOL_VERSION}\n`);
  else {
    const keys = a.flags.jwks ? fileJson(a.flags.jwks) : { keys: [] };
    if (!isObject(keys) || !Array.isArray(keys.keys) || keys.keys.length > 32 || keys.keys.some((k) => !isObject(k) || ['d', 'p', 'q', 'k', 'dp', 'dq', 'qi'].some((x) => x in k))) throw new InputError('INVALID_JWKS', 'Use a public JWKS containing at most 32 keys and no private key material.');
    const options = { trustedKeys: keys.keys, localOnly: !!a.flags.jwks, failOn: a.flags['fail-on'] || 'high', requireSignature: !!a.flags['require-signature'], network: !!a.flags.network };
    const result = a.command === 'verify'
      ? await inspectCard(fileJson(a.target), { ...options, cardUrl: a.flags.url })
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
