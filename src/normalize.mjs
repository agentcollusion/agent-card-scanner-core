// Normalize A2A Agent Cards of different spec generations into one shape.
// v1.0: supportedInterfaces[{url, protocolBinding, protocolVersion}], securitySchemes{name: {oauth2SecurityScheme: {...}}}
// v0.3: url, preferredTransport, additionalInterfaces[{url, transport}], protocolVersion,
//       securitySchemes{name: {type: 'oauth2' | 'openIdConnect' | 'apiKey' | 'http' | 'mutualTLS', ...}} (OpenAPI style)
// Cards are untrusted input: every field may be missing or of the wrong type, and nothing here may throw.

const pick = (o, ...names) => {
  if (!isObj(o)) return undefined;
  for (const n of names) if (o[n] !== undefined) return o[n];
  return undefined;
};
const isObj = (v) => !!v && typeof v === 'object' && !Array.isArray(v);
const arr = (v) => (Array.isArray(v) ? v : []);
const str = (v) => (typeof v === 'string' ? v : undefined);

function interfacesOf(card) {
  const list = [];
  for (const i of arr(pick(card, 'supportedInterfaces', 'supported_interfaces'))) {
    list.push({ url: str(pick(i, 'url')), binding: str(pick(i, 'protocolBinding', 'protocol_binding')), protocolVersion: str(pick(i, 'protocolVersion', 'protocol_version')) });
  }
  const protocolVersion = str(card.protocolVersion);
  if (str(card.url)) list.push({ url: card.url, binding: str(card.preferredTransport) || 'JSONRPC', protocolVersion });
  for (const i of arr(card.additionalInterfaces)) list.push({ url: str(pick(i, 'url')), binding: str(pick(i, 'transport')), protocolVersion });
  const seen = new Set();
  return list.filter((i) => i.url && !seen.has(`${i.url}|${i.binding}`) && seen.add(`${i.url}|${i.binding}`));
}

function flowsOf(flows) {
  if (!isObj(flows)) return [];
  const out = [];
  for (const [name, f] of Object.entries(flows)) {
    if (!isObj(f)) continue;
    out.push({
      flow: name.replace(/_([a-z])/g, (_, c) => c.toUpperCase()),
      authorizationUrl: str(pick(f, 'authorizationUrl', 'authorization_url')),
      tokenUrl: str(pick(f, 'tokenUrl', 'token_url')),
      pkceRequired: pick(f, 'pkceRequired', 'pkce_required'),
      scopes: isObj(f.scopes) ? Object.keys(f.scopes) : [],
    });
  }
  return out;
}

function schemesOf(card) {
  const raw = pick(card, 'securitySchemes', 'security_schemes');
  if (!isObj(raw)) return [];
  const out = [];
  for (const [name, s] of Object.entries(raw)) {
    if (!isObj(s)) continue;
    const v1 = [
      ['apiKey', pick(s, 'apiKeySecurityScheme', 'api_key_security_scheme')],
      ['http', pick(s, 'httpAuthSecurityScheme', 'http_auth_security_scheme')],
      ['oauth2', pick(s, 'oauth2SecurityScheme', 'oauth2_security_scheme')],
      ['openIdConnect', pick(s, 'openIdConnectSecurityScheme', 'open_id_connect_security_scheme')],
      ['mutualTLS', pick(s, 'mtlsSecurityScheme', 'mtls_security_scheme')],
    ].find(([, v]) => isObj(v));
    const [type, body] = v1 || [str(s.type), s];
    out.push({
      name,
      type,
      location: str(pick(body, 'location', 'in')),
      scheme: str(body.scheme),
      oauth2MetadataUrl: str(pick(body, 'oauth2MetadataUrl', 'oauth2_metadata_url')),
      openIdConnectUrl: str(pick(body, 'openIdConnectUrl', 'open_id_connect_url')),
      flows: flowsOf(body.flows),
    });
  }
  return out;
}

export function normalizeCard(card) {
  if (!isObj(card)) card = {};
  const provider = isObj(card.provider) ? card.provider : {};
  const capabilities = isObj(card.capabilities) ? card.capabilities : {};
  const hasV1 = Array.isArray(pick(card, 'supportedInterfaces', 'supported_interfaces'));
  const schemaIssues = [];
  for (const k of ['name', 'description', 'version']) if (typeof card[k] !== 'string') schemaIssues.push('/' + k);
  if (!isObj(card.capabilities)) schemaIssues.push('/capabilities');
  for (const k of ['skills', 'defaultInputModes', 'defaultOutputModes']) if (!Array.isArray(card[k])) schemaIssues.push('/' + k);
  if (hasV1) {
    const interfaces = pick(card, 'supportedInterfaces', 'supported_interfaces');
    if (!interfaces.length) schemaIssues.push('/supportedInterfaces');
    interfaces.forEach((x, i) => {
      for (const [camel, snake] of [['url', 'url'], ['protocolBinding', 'protocol_binding'], ['protocolVersion', 'protocol_version']]) {
        if (typeof pick(x, camel, snake) !== 'string') schemaIssues.push(`/supportedInterfaces/${i}/${camel}`);
      }
    });
  } else if (typeof card.url !== 'string') schemaIssues.push('/url');
  arr(card.skills).forEach((x, i) => {
    for (const k of ['id', 'name', 'description']) if (typeof pick(x, k) !== 'string') schemaIssues.push(`/skills/${i}/${k}`);
    if (!Array.isArray(pick(x, 'tags')) || x.tags.some((t) => typeof t !== 'string')) schemaIssues.push(`/skills/${i}/tags`);
  });
  return {
    schemaIssues,
    name: str(card.name),
    version: str(card.version) ?? (typeof card.version === 'number' ? String(card.version) : undefined),
    description: str(card.description),
    provider: { organization: str(provider.organization), url: str(provider.url) },
    interfaces: interfacesOf(card),
    securitySchemes: schemesOf(card),
    skills: arr(card.skills).filter(isObj).map((s) => ({ id: str(s.id), name: str(s.name), tags: arr(s.tags).filter((t) => typeof t === 'string') })),
    extendedCard: !!(pick(capabilities, 'extendedAgentCard', 'extended_agent_card') || card.supportsAuthenticatedExtendedCard),
    documentationUrl: str(pick(card, 'documentationUrl', 'documentation_url')),
    iconUrl: str(pick(card, 'iconUrl', 'icon_url')),
    signatures: arr(card.signatures),
    specGeneration: hasV1 ? 'v1' : str(card.url) ? 'v0.x' : 'unknown',
  };
}
