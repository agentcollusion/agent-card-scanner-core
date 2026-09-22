// Presence/default rules derived from A2A v1.0.1 (3303592588e388e62e0f69f701af531d2f4e3991).
// https://github.com/a2aproject/A2A/blob/v1.0.1/specification/a2a.proto
// Only non-presence defaults are removed. Unknown fields and extension Struct values are retained.
const schemas = {
  card: { supportedInterfaces: ['array', 'iface', true], provider: ['object', 'provider'], capabilities: ['object', 'capabilities'], securitySchemes: ['map', 'scheme'], securityRequirements: ['array', 'requirement'], skills: ['array', 'skill', true] },
  iface: { tenant: ['scalar'] },
  provider: {},
  capabilities: { extensions: ['array', 'extension'] },
  extension: { uri: ['scalar'], description: ['scalar'], required: ['scalar'] },
  skill: { examples: ['array'], inputModes: ['array'], outputModes: ['array'], securityRequirements: ['array', 'requirement'] },
  requirement: { schemes: ['map', 'stringList'] },
  stringList: { list: ['array'] },
  scheme: { apiKeySecurityScheme: ['object', 'apiKey'], httpAuthSecurityScheme: ['object', 'http'], oauth2SecurityScheme: ['object', 'oauth'], openIdConnectSecurityScheme: ['object', 'oidc'], mtlsSecurityScheme: ['object', 'mtls'] },
  apiKey: { description: ['scalar'] },
  http: { description: ['scalar'], bearerFormat: ['scalar'] },
  oauth: { description: ['scalar'], oauth2MetadataUrl: ['scalar'], flows: ['object', 'flows'] },
  oidc: { description: ['scalar'] }, mtls: { description: ['scalar'] },
  flows: { authorizationCode: ['object', 'code'], clientCredentials: ['object', 'client'], implicit: ['object', 'implicit'], password: ['object', 'password'], deviceCode: ['object', 'client'] },
  code: { refreshUrl: ['scalar'], pkceRequired: ['scalar'] },
  client: { refreshUrl: ['scalar'] },
  implicit: { authorizationUrl: ['scalar'], refreshUrl: ['scalar'], scopes: ['map'] },
  password: { tokenUrl: ['scalar'], refreshUrl: ['scalar'], scopes: ['map'] },
};
const isObj = (x) => x !== null && typeof x === 'object' && !Array.isArray(x);
function presence(value, type) {
  if (!isObj(value)) return value;
  return Object.fromEntries(Object.entries(value).flatMap(([key, v]) => {
    const rule = schemas[type]?.[key];
    if (!rule) return [[key, v]];
    const [kind, child, required] = rule;
    if (kind === 'scalar' && (v === '' || v === false || v === 0 || v === null)) return [];
    if (kind === 'array' && Array.isArray(v)) return !required && v.length === 0 ? [] : [[key, child ? v.map((x) => presence(x, child)) : v]];
    if (kind === 'map' && isObj(v)) return Object.keys(v).length === 0 ? [] : [[key, child ? Object.fromEntries(Object.entries(v).map(([k, x]) => [k, presence(x, child)])) : v]];
    return [[key, kind === 'object' ? presence(v, child) : v]];
  }));
}
export function cardPayload(card) {
  const { signatures, ...body } = card;
  return Array.isArray(card.supportedInterfaces) ? presence(body, 'card') : body;
}
