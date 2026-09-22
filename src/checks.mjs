// Static checks on a normalized card. Each finding: { id, severity, message, evidence }.
import { hostOf, sameRegistrableDomain } from './domain.mjs';
import { GUIDANCE } from './rule-guidance.mjs';

export const RULES = {
  'AC-PATH-001': { severity: 'info', title: 'Served only at the legacy path /.well-known/agent.json' },
  'AC-SCHEMA-001': { severity: 'high', title: 'Core field is missing or has the wrong type' },
  'AC-TLS-001': { severity: 'high', title: 'An interface URL is not HTTPS' },
  'AC-HOST-001': { severity: 'medium', title: 'Interface host is on a different site than the card host' },
  'AC-AUTH-001': { severity: 'medium', title: 'No security scheme declared' },
  'AC-AUTH-002': { severity: 'medium', title: 'API key sent in the query string (leaks into logs and referrers)' },
  'AC-AUTH-003': { severity: 'medium', title: 'Deprecated OAuth flow (implicit or password)' },
  'AC-AUTH-004': { severity: 'low', title: 'Authorization code flow without pkceRequired' },
  'AC-SKILL-001': { severity: 'low', title: 'Very broad skill surface (more than 20 skills)' },
  'AC-PROV-001': { severity: 'low', title: 'Provider organization or URL missing' },
  'AC-EXT-001': { severity: 'info', title: 'Extended (authenticated) card declared' },
  'AC-SIG-000': { severity: 'info', title: 'Card is not signed' },
  'AC-SIG-001': { severity: 'high', title: 'Signature does not verify under the selected payload profile' },
  'AC-SIG-002': { severity: 'critical', title: 'Signature uses a disallowed algorithm (e.g. none, HS256)' },
  'AC-SIG-003': { severity: 'high', title: 'jku is outside the card HTTPS origin' },
  'AC-SIG-004': { severity: 'low', title: 'Signature header has no kid' },
  'AC-SIG-005': { severity: 'medium', title: 'Signing key could not be resolved' },
  'AC-SIG-006': { severity: 'high', title: 'Malformed signature or canonicalization input' },
  'AC-SIG-007': { severity: 'high', title: 'Unsupported signature profile or signature limit exceeded' },
};

const f = (id, evidence) => ({ id, severity: RULES[id].severity, category: GUIDANCE[id][0], message: RULES[id].title, evidence, remediation: GUIDANCE[id][1], limitation: GUIDANCE[id][2] });

export function checkCard(n, { cardUrl, legacyPath = false }) {
  const out = [];
  if (legacyPath) out.push(f('AC-PATH-001', cardUrl));
  const missing = n.schemaIssues || ['name', 'version'].filter((k) => !n[k]);
  if (missing.length) out.push(f('AC-SCHEMA-001', missing.join(',')));

  const cardHost = hostOf(cardUrl);
  for (const i of n.interfaces) {
    if (!String(i.url).startsWith('https://')) out.push(f('AC-TLS-001', i.url));
    else if (!sameRegistrableDomain(hostOf(i.url), cardHost)) out.push(f('AC-HOST-001', `${cardHost} -> ${hostOf(i.url)}`));
  }

  if (!n.securitySchemes.length) out.push(f('AC-AUTH-001', null));
  for (const s of n.securitySchemes) {
    if (s.type === 'apiKey' && s.location === 'query') out.push(f('AC-AUTH-002', s.name));
    for (const fl of s.flows) {
      if (fl.flow === 'implicit' || fl.flow === 'password') out.push(f('AC-AUTH-003', `${s.name}:${fl.flow}`));
      if (fl.flow === 'authorizationCode' && fl.pkceRequired !== true) out.push(f('AC-AUTH-004', s.name));
    }
  }
  if (n.skills.length > 20) out.push(f('AC-SKILL-001', String(n.skills.length)));
  if (!n.provider.organization || !n.provider.url) out.push(f('AC-PROV-001', null));
  if (n.extendedCard) out.push(f('AC-EXT-001', null));
  return out;
}

export function signatureFindings(results) {
  return results.flatMap((r) => r.findings.map((id) => {
    const finding = { ...f(id, [r.alg, r.kid, r.jku].filter(Boolean).join(' ') || null), path: r.index === undefined ? '/signatures' : `/signatures/${r.index}` };
    if (id === 'AC-SIG-001' && r.diagnostic?.code === 'RAW_JCS_ONLY') Object.assign(finding, {
      message: 'Signature verifies with raw JCS but not the selected v1.0.1 presence profile',
      remediation: 'Confirm the intended signing profile with the publisher; compare v1.0.1 default/presence processing with raw JCS before re-signing.',
      limitation: 'This identifies a payload-profile mismatch with the same selected key; it does not pass the current policy or establish operator trust.',
    });
    return finding;
  }));
}
