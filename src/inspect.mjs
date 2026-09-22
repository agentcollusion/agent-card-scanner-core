import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { canonicalize } from './jcs.mjs';
import { normalizeCard } from './normalize.mjs';
import { checkCard, signatureFindings } from './checks.mjs';
import { verifyCard, makeKeyResolver, POLICY_VERSION } from './verify.mjs';
import { parseJson, isObject, InputError, validatePublicKeys } from './input.mjs';
import { publicHttpsUrl, safeFetch } from './safe-fetch.mjs';

export const TOOL_VERSION = JSON.parse(readFileSync(new URL('../package.json', import.meta.url), 'utf8')).version;
export const SEVERITIES = ['info', 'low', 'medium', 'high', 'critical'];
export const LIMITATION = 'Static card inspection only. A valid signature does not establish operator identity, authorization, runtime safety, or absence of collusion.';
export function redactUrl(value) {
  return String(value).replace(/https?:\/\/[^\s<>]+/gi, (s) => {
    try { const u = new URL(s); u.username = ''; u.password = ''; if (u.search) u.search = '?redacted'; u.hash = ''; return u.href; }
    catch { return '[invalid URL]'; }
  });
}
const safeValue = (v) => typeof v === 'string' ? redactUrl(v) : Array.isArray(v) ? v.map(safeValue) : isObject(v) ? Object.fromEntries(Object.entries(v).map(([k, x]) => [k, safeValue(x)])) : v;
export async function inspectCard(card, { cardUrl, trustedKeys = [], localOnly = Array.isArray(trustedKeys) && trustedKeys.length > 0, network = false, fetcher = safeFetch, resolveKeys, failOn = 'high', requireSignature = false, legacyPath = false } = {}) {
  if (![...SEVERITIES.slice(1), 'none'].includes(failOn)) throw new InputError('INVALID_POLICY', 'Unknown failure threshold.');
  if (!isObject(card)) throw new InputError('INVALID_CARD', 'Agent Card must be a JSON object.');
  // The public library entry point has the same bounds as CLI inputs.
  try { canonicalize(card); } catch { throw new InputError('INVALID_CARD', 'Card must contain canonicalizable JSON values.'); }
  card = parseJson(JSON.stringify(card));
  try { publicHttpsUrl(cardUrl); } catch { throw new InputError('INVALID_URL', 'Supply the absolute HTTPS URL from which this card is published.'); }
  validatePublicKeys(trustedKeys);
  const normalized = normalizeCard(card);
  const signatures = await verifyCard(card, cardUrl, { resolveKeys: resolveKeys || makeKeyResolver({ trustedKeys, localOnly, network, fetcher }) });
  const findings = [...checkCard(normalized, { cardUrl, legacyPath }), ...signatureFindings(signatures)]
    .sort((a, b) => SEVERITIES.indexOf(b.severity) - SEVERITIES.indexOf(a.severity) || a.id.localeCompare(b.id) || String(a.evidence).localeCompare(String(b.evidence)));
  const blocking = findings.filter((f) => f.category !== 'advisory' && failOn !== 'none' && SEVERITIES.indexOf(f.severity) >= SEVERITIES.indexOf(failOn));
  const signatureRequiredFailed = requireSignature && !signatures.some((s) => s.status === 'valid');
  return safeValue({
    schemaVersion: '1.0', tool: { name: 'agent-card-scanner', version: TOOL_VERSION },
    policy: { version: POLICY_VERSION, failOn, requireSignature, keySource: localOnly || trustedKeys.length ? 'local-jwks' : network ? 'same-origin-network' : 'offline' },
    target: { url: cardUrl, name: normalized.name || null, specGeneration: normalized.specGeneration, sha256: createHash('sha256').update(canonicalize(card)).digest('hex') },
    status: 'complete', decision: blocking.length || signatureRequiredFailed ? 'fail' : 'pass',
    blockingRuleIds: [...new Set(blocking.map((f) => f.id))], signatureRequiredFailed,
    signatures, findings, limitation: LIMITATION,
    coverage: { coreFields: 'partial', signaturePayload: Array.isArray(card.supportedInterfaces) ? 'a2a-v1.0.1-presence+jcs' : 'jcs', runtimeTested: false, keyRevocationChecked: false },
  });
}

export async function inspectPublished(target, options = {}) {
  validatePublicKeys(options.trustedKeys === undefined ? [] : options.trustedKeys);
  const fetcher = options.fetcher || safeFetch;
  let base;
  try { base = publicHttpsUrl(target.includes('://') ? target : `https://${target}`); }
  catch { throw new InputError('INVALID_URL', 'Use a public HTTPS URL or host.'); }
  if (!target.includes('://') && (base.pathname !== '/' || base.search)) throw new InputError('INVALID_URL', 'Use a bare host or an explicit absolute HTTPS URL.');
  const explicit = target.includes('://') && (base.pathname !== '/' || base.search);
  const urls = explicit ? [base.href] : ['/.well-known/agent-card.json', '/.well-known/agent.json'].map((p) => new URL(p, base.origin).href);
  let lastError = 'NOT_FOUND';
  for (const url of urls) {
    let response;
    try { response = await fetcher(url); }
    catch (e) { lastError = e.code || 'NETWORK'; break; }
    const retrievedAt = new Date().toISOString();
    if (response.status !== 200) { lastError = `HTTP_${response.status}`; continue; }
    let card;
    try { card = parseJson(response.body); if (!isObject(card) || typeof card.name !== 'string') throw new Error(); }
    catch { lastError = 'INVALID_CARD'; continue; }
    const report = await inspectCard(card, { ...options, cardUrl: response.url, network: true, legacyPath: url.endsWith('/.well-known/agent.json'), fetcher });
    report.discovery = { source: explicit ? 'explicit-url' : 'well-known', attempts: urls.indexOf(url) + 1, retrievedAt };
    return report;
  }
  const error = new Error('Card inspection could not be completed. Check the URL, publication path, and network policy.');
  error.code = lastError; error.exitCode = 3; throw error;
}

export function renderInspection(report) {
  const line = (x) => String(x).replace(/[\u0000-\u001f\u007f-\u009f\u202a-\u202e\u2066-\u2069]/g, (c) => `\\u${c.charCodeAt(0).toString(16).padStart(4, '0')}`);
  const out = [`Agent Card Scanner ${TOOL_VERSION}`, `${report.decision.toUpperCase()} under ${report.policy.version}`, `Card: ${line(report.target.url)}`, `Signature: ${report.signatures.map((s) => s.status).join(', ')}`, `Policy: fail on ${report.policy.failOn}; keys ${report.policy.keySource}`, ''];
  if (report.discovery?.retrievedAt) out.splice(3, 0, `Retrieved: ${line(report.discovery.retrievedAt)} (card snapshot; not continuous monitoring)`);
  for (const f of report.findings) out.push(`[${f.severity.toUpperCase()} / ${f.category}] ${f.id}: ${f.message}`, ...(f.path ? [`  At: ${line(f.path)}`] : []), `  Evidence: ${line(f.evidence ?? 'not declared')}`, `  Next: ${f.remediation}`, `  Note: ${f.limitation}`, '');
  if (report.signatureRequiredFailed) out.push('Required signature: no signature verified with an accepted key.', '');
  out.push(report.limitation);
  return out.join('\n');
}
