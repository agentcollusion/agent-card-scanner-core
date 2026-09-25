import { parseJson, InputError, isObject } from './input.mjs';
import { canonicalize } from './jcs.mjs';

export const COMPARISON_LIMITATION = 'Compares declared fields only. No agent is contacted, no signature is verified, and no runtime compatibility or safety is established. Metadata and signatures are excluded; extension and custom-field changes need manual review.';
const own = (o, k) => Object.hasOwn(o, k);
const pointer = (s) => String(s).replaceAll('~', '~0').replaceAll('/', '~1');
const same = (a, b) => canonicalize(a) === canonicalize(b);
const set = (values) => [...new Set(values.map(canonicalize))].sort().map(value => JSON.parse(value));
const rest = (o, keys) => Object.fromEntries(Object.entries(o).filter(([k]) => !keys.includes(k)));
const metadata = ['name', 'description', 'version', 'provider', 'documentationUrl', 'iconUrl', 'signatures'];
function safe(value) {
  if (typeof value === 'string') return value.replace(/https?:\/\/[^\s"'<>]+/gi, (text) => {
    try { const u = new URL(text); u.username = ''; u.password = ''; if (u.search) u.search = '?redacted'; u.hash = ''; return u.href; }
    catch { return '[URL omitted]'; }
  });
  if (Array.isArray(value)) return value.map(safe);
  if (isObject(value)) return Object.fromEntries(Object.entries(value).map(([k, v]) => [safe(k), safe(v)]));
  return value;
}
const visible = (s) => s.replace(/[\u0000-\u001f\u007f-\u009f\u202a-\u202e\u2066-\u2069]/g, (ch) => '\\u' + ch.charCodeAt(0).toString(16).padStart(4, '0'));

function project(text, side) {
  const fail = (path, message) => { throw new InputError('INVALID_COMPARISON_CARD', side + ' ' + visible(safe(path)).slice(0, 180) + ': ' + message); };
  let card;
  try {
    if (typeof text !== 'string') throw new InputError('INVALID_JSON', 'Supply JSON text.');
    card = parseJson(text);
  } catch (e) {
    if (e instanceof InputError) throw new InputError(e.code, side + ': ' + e.message);
    throw e;
  }
  const object = (v, p) => { if (!isObject(v)) fail(p, 'Expected an object.'); return v; };
  const array = (v, p) => { if (!Array.isArray(v)) fail(p, 'Expected an array.'); if (v.length > 256) fail(p, 'Comparison arrays are limited to 256 entries.'); return v; };
  const string = (v, p) => { if (typeof v !== 'string' || !v.trim()) fail(p, 'Expected a nonempty string.'); return v; };
  const strings = (v, p) => set(array(v, p).map((x, i) => string(x, p + '/' + i)));
  const bool = (o, k, p) => { if (own(o, k) && typeof o[k] !== 'boolean') fail(p + '/' + k, 'Expected a boolean.'); return o[k] ?? false; };
  const optionalStrings = (o, keys, p) => { for (const k of keys) if (own(o, k) && typeof o[k] !== 'string') fail(p + '/' + k, 'Expected a string.'); };
  const endpoint = (v, p) => {
    string(v, p);
    try { const u = new URL(v); if (!['https:', 'http:'].includes(u.protocol) || !/^https?:\/\//i.test(v) || /[\s\\]/.test(v)) throw new Error(); }
    catch { fail(p, 'Expected an absolute HTTP(S) URL. This comparison never retrieves it.'); }
    return v;
  };
  object(card, '/');
  for (const k of ['name', 'description', 'version']) string(card[k], '/' + k);
  const v1 = own(card, 'supportedInterfaces');
  const generation = v1 ? '1.0' : '0.3';
  if (!v1 && card.protocolVersion !== '0.3.0') fail('/protocolVersion', 'This profile supports v0.3.0 cards or the v1.0 camelCase card shape.');
  const forbidden = v1 ? ['url', 'protocolVersion', 'preferredTransport', 'additionalInterfaces', 'security', 'supportsAuthenticatedExtendedCard'] : ['securityRequirements'];
  for (const k of forbidden) if (own(card, k)) fail('/' + k, 'Mixed protocol generations are not supported.');
  for (const k of ['supported_interfaces', 'default_input_modes', 'default_output_modes', 'security_schemes', 'security_requirements']) {
    if (own(card, k)) fail('/' + k, 'Use camelCase JSON fields for this comparison profile.');
  }
  const modes = { input: strings(card.defaultInputModes, '/defaultInputModes'), output: strings(card.defaultOutputModes, '/defaultOutputModes') };
  for (const values of Object.values(modes)) if (values.length > 64 || values.some(v => v.length > 256)) fail('/defaultInputModes or /defaultOutputModes', 'Mode lists are limited to 64 entries of 256 characters.');
  const schemes = own(card, 'securitySchemes') ? object(card.securitySchemes, '/securitySchemes') : {};
  const wrappers = { apiKeySecurityScheme: 'apiKey', httpAuthSecurityScheme: 'http', oauth2SecurityScheme: 'oauth2', openIdConnectSecurityScheme: 'openIdConnect', mtlsSecurityScheme: 'mutualTLS' };
  for (const [name, value] of Object.entries(schemes)) {
    const p = '/securitySchemes/' + pointer(name);
    string(name, '/securitySchemes');
    object(value, p);
    let type = value.type, s = value, q = p;
    if (v1) {
      const keys = Object.keys(value).filter(k => own(wrappers, k));
      if (keys.length !== 1 || own(value, 'type')) fail(p, 'Expected exactly one v1 security scheme variant.');
      q += '/' + keys[0]; s = object(value[keys[0]], q); type = wrappers[keys[0]];
    }
    if (!['apiKey', 'http', 'oauth2', 'openIdConnect', 'mutualTLS'].includes(type)) fail(p, 'Unsupported security scheme type.');
    optionalStrings(s, ['description', 'bearerFormat'], q);
    if (type === 'apiKey') {
      if (!['header', 'query', 'cookie'].includes(s[v1 ? 'location' : 'in'])) fail(q, 'API key location must be header, query or cookie.');
      string(s.name, q + '/name');
    }
    if (type === 'http') string(s.scheme, q + '/scheme');
    if (type === 'openIdConnect') endpoint(s.openIdConnectUrl, q + '/openIdConnectUrl');
    if (type === 'oauth2') {
      const flows = object(s.flows, q + '/flows');
      const flowFields = { implicit: ['authorizationUrl'], password: ['tokenUrl'], clientCredentials: ['tokenUrl'], authorizationCode: ['authorizationUrl', 'tokenUrl'], deviceCode: ['deviceAuthorizationUrl', 'tokenUrl'] };
      if (!Object.keys(flows).some(k => own(flowFields, k))) fail(q + '/flows', 'Expected at least one supported OAuth flow.');
      for (const [flow, fields] of Object.entries(flowFields)) if (own(flows, flow)) {
        const f = object(flows[flow], q + '/flows/' + flow);
        for (const k of fields) endpoint(f[k], q + '/flows/' + flow + '/' + k);
        if (own(f, 'refreshUrl')) endpoint(f.refreshUrl, q + '/flows/' + flow + '/refreshUrl');
        const scopes = object(f.scopes, q + '/flows/' + flow + '/scopes');
        for (const description of Object.values(scopes)) if (typeof description !== 'string') fail(q + '/flows/' + flow + '/scopes', 'Expected string descriptions.');
      }
      if (own(s, 'oauth2MetadataUrl')) endpoint(s.oauth2MetadataUrl, q + '/oauth2MetadataUrl');
    }
  }
  const authKey = v1 ? 'securityRequirements' : 'security';
  function requirements(o, p) {
    if (!own(o, authKey)) return [];
    return set(array(o[authKey], p).map((requirement, i) => {
      object(requirement, p + '/' + i);
      let map = requirement;
      if (v1) {
        if (Object.keys(requirement).some(k => k !== 'schemes')) fail(p + '/' + i, 'Expected a v1 schemes map.');
        map = own(requirement, 'schemes') ? object(requirement.schemes, p + '/' + i + '/schemes') : {};
      }
      return Object.fromEntries(Object.entries(map).map(([name, value]) => {
        if (!own(schemes, name)) fail(p + '/' + i, 'Requirement references an undefined security scheme.');
        let scopes = value;
        if (v1) {
          object(value, p + '/' + i + '/schemes');
          if (Object.keys(value).some(k => k !== 'list')) fail(p + '/' + i + '/schemes', 'Expected a v1 scope list.');
          scopes = own(value, 'list') ? value.list : [];
        }
        return [name, strings(scopes, p + '/' + i)];
      }));
    }));
  }
  const auth = requirements(card, '/' + authKey);
  const interfaces = [];
  function addInterface(raw, p, primary = false) {
    object(raw, p);
    const item = { url: endpoint(raw.url, p === '/url' ? p : p + '/url'), binding: string(raw[v1 ? 'protocolBinding' : 'transport'], p + '/' + (v1 ? 'protocolBinding' : 'transport')), protocolVersion: v1 ? string(raw.protocolVersion, p + '/protocolVersion') : card.protocolVersion };
    if (v1) { optionalStrings(raw, ['tenant'], p); item.tenant = raw.tenant ?? ''; }
    const extra = rest(raw, v1 ? ['url', 'protocolBinding', 'protocolVersion', 'tenant'] : ['url', 'transport']);
    const id = canonicalize(item);
    if (interfaces.some(x => x.id === id)) {
      if (primary || !same(interfaces.find(x => x.id === id).extra, extra)) fail(p, 'Ambiguous duplicate interface.');
      return;
    }
    interfaces.push({ id, value: item, path: p, extra });
  }
  if (v1) {
    const list = array(card.supportedInterfaces, '/supportedInterfaces');
    if (!list.length) fail('/supportedInterfaces', 'At least one interface is required.');
    list.forEach((v, i) => addInterface(v, '/supportedInterfaces/' + i, true));
  } else {
    if (own(card, 'preferredTransport')) string(card.preferredTransport, '/preferredTransport');
    addInterface({ url: card.url, transport: card.preferredTransport ?? 'JSONRPC' }, '/url', true);
    if (own(card, 'additionalInterfaces')) array(card.additionalInterfaces, '/additionalInterfaces').forEach((v, i) => addInterface(v, '/additionalInterfaces/' + i));
  }
  const skills = new Map();
  array(card.skills, '/skills').forEach((s, i) => {
    const p = '/skills/' + i; object(s, p);
    const id = string(s.id, p + '/id');
    if (skills.has(id)) fail(p + '/id', 'Duplicate skill ID.');
    for (const k of ['name', 'description']) string(s[k], p + '/' + k);
    strings(s.tags, p + '/tags');
    if (own(s, 'examples')) strings(s.examples, p + '/examples');
    for (const k of [v1 ? 'security' : 'securityRequirements', 'input_modes', 'output_modes', 'security_requirements']) if (own(s, k)) fail(p + '/' + k, 'Unsupported or mixed skill field spelling.');
    const skillModes = {};
    for (const [direction, key] of [['input', 'inputModes'], ['output', 'outputModes']]) {
      const declared = own(s, key) ? strings(s[key], p + '/' + key) : undefined;
      if (declared && (declared.length > 64 || declared.some(v => v.length > 256))) fail(p + '/' + key, 'Mode lists are limited to 64 entries of 256 characters.');
      const inherited = declared === undefined || (v1 && declared.length === 0);
      skillModes[direction] = { value: inherited ? modes[direction] : declared, path: inherited ? '/default' + key[0].toUpperCase() + key.slice(1) : p + '/' + key };
    }
    skills.set(id, { id, path: p, modes: skillModes, auth: requirements(s, p + '/' + authKey), extra: rest(s, ['id', 'name', 'description', 'tags', 'examples', 'inputModes', 'outputModes', authKey]) });
  });
  const c = object(card.capabilities, '/capabilities');
  for (const k of ['push_notifications', 'extended_agent_card', 'state_transition_history']) if (own(c, k)) fail('/capabilities/' + k, 'Use camelCase capability fields.');
  const capabilities = {};
  for (const k of ['streaming', 'pushNotifications', ...(v1 ? ['extendedAgentCard'] : ['stateTransitionHistory'])]) capabilities[k] = bool(c, k, '/capabilities');
  if (!v1) capabilities.supportsAuthenticatedExtendedCard = bool(card, 'supportsAuthenticatedExtendedCard', '');
  const extensions = own(c, 'extensions') ? array(c.extensions, '/capabilities/extensions') : [];
  const uris = new Set();
  extensions.forEach((e, i) => {
    const p = '/capabilities/extensions/' + i; object(e, p); string(e.uri, p + '/uri');
    if (uris.has(e.uri)) fail(p + '/uri', 'Duplicate extension URI.');
    uris.add(e.uri); bool(e, 'required', p); optionalStrings(e, ['description'], p);
    if (own(e, 'params')) object(e.params, p + '/params');
  });
  const extras = {
    card: rest(card, [...metadata, 'protocolVersion', 'url', 'preferredTransport', 'additionalInterfaces', 'supportedInterfaces', 'capabilities', 'supportsAuthenticatedExtendedCard', 'securitySchemes', authKey, 'defaultInputModes', 'defaultOutputModes', 'skills']),
    capabilities: rest(c, ['streaming', 'pushNotifications', ...(v1 ? ['extendedAgentCard'] : ['stateTransitionHistory']), 'extensions']),
  };
  return { generation, agentVersion: card.version, modes, schemes, authKey, auth, interfaces, skills, capabilities, extensions: set(extensions), extras };
}

/** Bounded JSON text in, deterministic report out. Browser/Node; no I/O. */
export function compareCardJson(beforeText, afterText) {
  const a = project(beforeText, 'before'), b = project(afterText, 'after');
  if (a.generation !== b.generation) throw new InputError('UNSUPPORTED_MIGRATION', 'Compare cards from the same protocol generation. Review v0.3 to v1.0 migrations separately.');
  const changes = [];
  function add(area, beforePath, afterPath, before, after, action, kind = 'changed') {
    changes.push({ area, kind, beforePath, afterPath, before, after, action });
  }
  function changed(area, ap, bp, av, bv, action, opaque = false) {
    if (!same(av, bv)) add(area, ap, bp, opaque ? '[previous declaration omitted]' : av, opaque ? '[updated declaration omitted]' : bv, action);
  }
  const authAction = 'Check credentials and scopes for every AND group and OR alternative. This change does not establish stronger or weaker authentication.';
  changed('authentication', '/' + a.authKey, '/' + b.authKey, a.auth, b.auth, authAction);
  for (const name of [...new Set([...Object.keys(a.schemes), ...Object.keys(b.schemes)])].sort()) {
    const p = '/securitySchemes/' + pointer(name);
    changed('security-scheme', own(a.schemes, name) ? p : null, own(b.schemes, name) ? p : null, own(a.schemes, name) ? a.schemes[name] : null, own(b.schemes, name) ? b.schemes[name] : null, 'Review this scheme definition in the original cards: credential location, issuer, OAuth flow and token endpoints may have changed. Values are omitted from exports.', true);
  }
  for (const x of a.interfaces) if (!b.interfaces.some(y => y.id === x.id)) add('interface', x.path, null, x.value, null, 'Check clients pinned to this endpoint, binding, protocol version or tenant. Keep the previous interface available during migration if needed.', 'removed');
  for (const x of b.interfaces) if (!a.interfaces.some(y => y.id === x.id)) add('interface', null, x.path, null, x.value, 'Check client support before selecting this interface, protocol version or tenant.', 'added');
  const sameMembers = same(set(a.interfaces.map(x => x.id)), set(b.interfaces.map(x => x.id)));
  if (sameMembers) changed('interface-preference', a.generation === '1.0' ? '/supportedInterfaces' : '/url', b.generation === '1.0' ? '/supportedInterfaces' : '/url', a.generation === '1.0' ? a.interfaces.map(x => x.value) : a.interfaces[0].value, b.generation === '1.0' ? b.interfaces.map(x => x.value) : b.interfaces[0].value, 'Check clients that select interfaces by the advertised preference order.');
  for (const x of a.interfaces) {
    const y = b.interfaces.find(v => v.id === x.id);
    if (y) changed('custom-fields', x.path, y.path, x.extra, y.extra, 'Review changed custom interface fields in the original cards.', true);
  }
  for (const direction of ['input', 'output']) {
    const p = direction === 'input' ? '/defaultInputModes' : '/defaultOutputModes';
    changed('default-modes', p, p, a.modes[direction], b.modes[direction], 'Check media-type handling in clients and skills that inherit these defaults.');
  }
  for (const id of [...new Set([...a.skills.keys(), ...b.skills.keys()])].sort()) {
    const x = a.skills.get(id), y = b.skills.get(id);
    if (!y) { add('skill', x.path, null, { id }, null, 'Check routing and prompts that depend on this skill; migrate those callers before removing it.', 'removed'); continue; }
    if (!x) { add('skill', null, y.path, null, { id }, 'Review the new skill before exposing it to clients.', 'added'); continue; }
    for (const direction of ['input', 'output']) changed('skill-modes', x.modes[direction].path, y.modes[direction].path, { skill: id, modes: x.modes[direction].value }, { skill: id, modes: y.modes[direction].value }, 'Check the effective media types for this skill, including inherited defaults.');
    changed('skill-authentication', x.path + '/' + a.authKey, y.path + '/' + b.authKey, x.auth, y.auth, authAction + ' Review these skill requirements together with the card-level requirements.');
    changed('custom-fields', x.path, y.path, x.extra, y.extra, 'Review changed custom skill fields in the original cards.', true);
  }
  for (const k of Object.keys(a.capabilities)) {
    const p = k === 'supportsAuthenticatedExtendedCard' ? '/' + k : '/capabilities/' + k;
    changed('capability', p, p, a.capabilities[k], b.capabilities[k], 'Check clients that rely on this advertised capability and their fallback behavior.');
  }
  changed('extensions', '/capabilities/extensions', '/capabilities/extensions', a.extensions, b.extensions, 'Review extension URIs, required flags and parameters in the original cards. Extension semantics are not evaluated; values are omitted from exports.', true);
  changed('custom-fields', '/', '/', a.extras, b.extras, 'Review custom card or capability fields in the original cards; this profile does not interpret them.', true);
  const context = (v) => ({ generation: v.generation, agentVersion: v.agentVersion, protocolVersions: set(v.interfaces.map(x => x.value.protocolVersion)) });
  return safe({ schemaVersion: '1.0', kind: 'agent-card-comparison', profile: 'a2a-card-changes-1', status: 'complete', decision: changes.length ? 'review-required' : 'no-covered-changes', context: { before: context(a), after: context(b) }, changes, limitation: COMPARISON_LIMITATION });
}

export function renderComparison(report) {
  const lines = ['Agent Card comparison: ' + report.decision, 'Profile: ' + report.profile, ''];
  for (const change of report.changes) {
    lines.push('- [ ] ' + change.area + ' (' + change.kind + ')', '  Before ' + (change.beforePath ?? '(absent)') + ': ' + JSON.stringify(change.before), '  After  ' + (change.afterPath ?? '(absent)') + ': ' + JSON.stringify(change.after), '  Next: ' + change.action, '');
  }
  if (!report.changes.length) lines.push('No changes found in the covered declarations.', '');
  lines.push(report.limitation);
  return lines.map(visible).join('\n');
}
