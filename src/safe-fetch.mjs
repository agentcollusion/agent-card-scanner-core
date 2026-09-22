// Bounded public HTTPS transport. DNS answers are checked once and pinned at connect time.
import { lookup as dnsLookup } from 'node:dns/promises';
import { request as httpsRequest } from 'node:https';
import net from 'node:net';
import { decodeUtf8 } from './input.mjs';

export const DEFAULTS = {
  timeoutMs: 8000, maxBytes: 512 * 1024, maxRedirects: 3,
  userAgent: 'agent-card-scanner/0.3 (+https://github.com/agentcollusion/agent-card-scanner-core)',
};
const BLOCKED_V4 = [
  ['0.0.0.0', 8], ['10.0.0.0', 8], ['100.64.0.0', 10], ['127.0.0.0', 8], ['169.254.0.0', 16],
  ['172.16.0.0', 12], ['192.0.0.0', 24], ['192.0.2.0', 24], ['192.88.99.0', 24],
  ['192.168.0.0', 16], ['198.18.0.0', 15], ['198.51.100.0', 24], ['203.0.113.0', 24],
  ['224.0.0.0', 4], ['240.0.0.0', 4],
];
const v4ToInt = (ip) => ip.split('.').reduce((a, o) => (a << 8) + Number(o), 0) >>> 0;
function ipv6Value(ip) {
  const normalized = new URL(`https://[${ip}]/`).hostname.slice(1, -1);
  const [left, right] = normalized.split('::');
  const a = left ? left.split(':') : [];
  const b = right ? right.split(':') : [];
  const words = right === undefined ? a : [...a, ...Array(8 - a.length - b.length).fill('0'), ...b];
  return words.reduce((n, w) => (n << 16n) | BigInt(`0x${w}`), 0n);
}
export function isPublicAddress(ip) {
  if (net.isIPv4(ip)) {
    const n = v4ToInt(ip);
    return !BLOCKED_V4.some(([base, bits]) => {
      const mask = (~0 << (32 - bits)) >>> 0;
      return (n & mask) === (v4ToInt(base) & mask);
    });
  }
  if (!net.isIPv6(ip) || ip.includes('%')) return false;
  const n = ipv6Value(ip);
  // Conservative global-unicast policy; also excludes mapped/NAT64/local/multicast forms.
  if ((n >> 125n) !== 1n) return false;
  return ![['2001::', 23], ['2001:db8::', 32], ['2002::', 16], ['3fff::', 20]]
    .some(([base, bits]) => (n >> BigInt(128 - bits)) === (ipv6Value(base) >> BigInt(128 - bits)));
}
export class FetchError extends Error {
  constructor(code, message) { super(message); this.code = code; }
}
export function publicHttpsUrl(input) {
  let url;
  try { url = new URL(input); } catch { throw new FetchError('INVALID_URL', 'Expected a valid absolute HTTPS URL.'); }
  if (url.protocol !== 'https:') throw new FetchError('NOT_HTTPS', 'Only HTTPS URLs are supported.');
  if (url.username || url.password) throw new FetchError('CREDENTIALS_IN_URL', 'Credentials in URLs are not accepted.');
  if (url.hash) throw new FetchError('INVALID_URL', 'URL fragments are not accepted.');
  return url;
}

// Dependency injection is for deterministic transport tests. Production uses native implementations.
export function createSafeFetcher({ lookup = dnsLookup, request = httpsRequest } = {}) {
  return async function fetchPublic(input, opts = {}) {
    const o = { ...DEFAULTS, ...opts };
    for (const [name, min, max] of [['timeoutMs', 1, 60000], ['maxBytes', 1, 524288], ['maxRedirects', 0, 3]]) {
      if (!Number.isInteger(o[name]) || o[name] < min || o[name] > max) throw new FetchError('INVALID_OPTIONS', `Invalid ${name}.`);
    }
    let activeRequest;
    let timedOut = false;
    let timer;
    let onAbort;
    if (o.signal?.aborted) throw new FetchError('ABORTED', 'HTTPS retrieval was cancelled.');
    const deadline = new Promise((_, reject) => {
      onAbort = () => {
        timedOut = true;
        activeRequest?.destroy();
        reject(new FetchError('ABORTED', 'HTTPS retrieval was cancelled.'));
      };
      o.signal?.addEventListener('abort', onAbort, { once: true });
      timer = setTimeout(() => {
        timedOut = true;
        activeRequest?.destroy();
        reject(new FetchError('TIMEOUT', 'HTTPS retrieval exceeded its total time budget.'));
      }, o.timeoutMs);
    });
    const operation = async () => {
      let url = publicHttpsUrl(input);
      for (let hop = 0; hop <= o.maxRedirects; hop++) {
        if (timedOut) throw new FetchError('TIMEOUT', 'HTTPS retrieval timed out.');
        if (o.allowedOrigin && url.origin !== o.allowedOrigin) throw new FetchError('ORIGIN_POLICY', 'Key URL or redirect leaves the permitted origin.');
        const hostname = url.hostname.replace(/^\[|\]$/g, '');
        let answers;
        try { answers = net.isIP(hostname) ? [{ address: hostname, family: net.isIP(hostname) }] : await lookup(hostname, { all: true, verbatim: true }); }
        catch { throw new FetchError('DNS', 'DNS resolution failed.'); }
        if (timedOut) throw new FetchError('TIMEOUT', 'DNS resolution exceeded the retrieval budget.');
        if (!answers.length || answers.some((a) => !isPublicAddress(a.address))) throw new FetchError('BLOCKED_ADDRESS', 'Target resolves to an address outside the public-network policy.');
        const pinned = answers[0];
        const res = await new Promise((resolve, reject) => {
          let settled = false;
          const fail = (e) => {
            if (!settled) { settled = true; reject(e instanceof FetchError ? e : new FetchError('NETWORK', 'HTTPS request failed.')); }
          };
          const req = request(url, {
            method: 'GET', agent: false, rejectUnauthorized: true,
            servername: net.isIP(hostname) ? undefined : hostname,
            lookup: (_host, options, cb) => {
              if (typeof options === 'function') { cb = options; options = {}; }
              if (options?.all) cb(null, [{ address: pinned.address, family: net.isIP(pinned.address) }]);
              else cb(null, pinned.address, net.isIP(pinned.address));
            },
            headers: { 'user-agent': o.userAgent, accept: 'application/json', 'accept-encoding': 'identity' },
          }, (response) => {
            response.on('error', fail);
            const status = response.statusCode;
            const headers = response.headers;
            if ([301, 302, 303, 307, 308].includes(status) && headers.location) {
              settled = true;
              resolve({ status, headers, body: '', addresses: answers.map((a) => a.address) });
              response.destroy();
              return;
            }
            if (headers['content-encoding'] && headers['content-encoding'] !== 'identity') {
              fail(new FetchError('ENCODING', 'Compressed responses are not accepted.'));
              response.destroy();
              return;
            }
            let size = 0;
            const chunks = [];
            response.on('data', (chunk) => {
              size += chunk.length;
              if (size > o.maxBytes) { fail(new FetchError('TOO_LARGE', 'Response exceeds the byte limit.')); response.destroy(); }
              else chunks.push(chunk);
            });
            response.on('aborted', () => fail(new FetchError('NETWORK', 'Response ended before completion.')));
            response.on('end', () => {
              if (!settled) {
                let body;
                try { body = decodeUtf8(Buffer.concat(chunks)); }
                catch { fail(new FetchError('INVALID_UTF8', 'Response is not valid UTF-8.')); return; }
                settled = true; resolve({ status, headers, body, addresses: answers.map((a) => a.address) });
              }
            });
          });
          activeRequest = req;
          req.on('error', fail);
          req.end();
        });
        if ([301, 302, 303, 307, 308].includes(res.status) && res.headers.location) {
          url = publicHttpsUrl(new URL(res.headers.location, url));
          continue;
        }
        return { ...res, url: url.href };
      }
      throw new FetchError('TOO_MANY_REDIRECTS', 'Redirect limit exceeded.');
    };
    try { return await Promise.race([operation(), deadline]); }
    finally { clearTimeout(timer); o.signal?.removeEventListener('abort', onAbort); }
  };
}
export const safeFetch = createSafeFetcher();
