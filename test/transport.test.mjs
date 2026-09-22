import test from 'node:test';
import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';
import { Readable } from 'node:stream';
import { createSafeFetcher, isPublicAddress } from '../src/safe-fetch.mjs';

function harness(responses, lookup = async () => [{ address: '93.184.216.34', family: 4 }]) {
  const calls = [];
  const request = (url, options, callback) => {
    calls.push({ url: String(url), options });
    const req = new EventEmitter();
    req.destroy = () => {};
    req.end = () => queueMicrotask(() => {
      const value = responses.shift() || { status: 200, body: '{}' };
      if (value.hang) return;
      if (value.error) { req.emit('error', new Error('internal connection details')); return; }
      const res = Readable.from(value.chunks || [Buffer.from(value.body || '')]);
      res.statusCode = value.status; res.headers = value.headers || {};
      callback(res);
    });
    return req;
  };
  return { calls, fetcher: createSafeFetcher({ lookup, request }) };
}
test('validated DNS is pinned; original hostname and TLS verification remain in use', async () => {
  let resolutions = 0;
  const { calls, fetcher } = harness([{ status: 200, body: '{}' }], async () => {
    resolutions++; return [{ address: resolutions === 1 ? '93.184.216.34' : '127.0.0.1', family: 4 }];
  });
  const r = await fetcher('https://cards.example/a.json');
  assert.equal(resolutions, 1);
  assert.deepEqual(r.addresses, ['93.184.216.34']);
  const o = calls[0].options;
  assert.equal(o.servername, 'cards.example'); assert.equal(o.rejectUnauthorized, true); assert.equal(o.agent, false);
  assert.deepEqual(await new Promise((resolve, reject) => o.lookup('cards.example', { all: true }, (e, v) => e ? reject(e) : resolve(v))), [{ address: '93.184.216.34', family: 4 }]);
  assert.equal(await new Promise((resolve, reject) => o.lookup('cards.example', {}, (e, v) => e ? reject(e) : resolve(v))), '93.184.216.34');
  assert.equal(resolutions, 1);
});
test('any private DNS answer rejects a mixed public/private set before connection', async () => {
  const { fetcher, calls } = harness([], async () => [{ address: '93.184.216.34' }, { address: '10.0.0.1' }]);
  await assert.rejects(fetcher('https://cards.example/'), { code: 'BLOCKED_ADDRESS' }); assert.equal(calls.length, 0);
});
for (const ip of ['0.0.0.1', '100.64.0.1', '192.0.2.1', '198.51.100.1', '203.0.113.1', '224.0.0.1', '::ffff:7f00:1', '0:0:0:0:0:0:0:1', '64:ff9b::a00:1', 'ff02::1', '2001:db8::1', '2002:7f00:1::', '3fff::1', 'fe80::1%eth0']) {
  test(`public-network policy rejects ${ip}`, () => assert.equal(isPublicAddress(ip), false));
}
test('public IPv6 literal retains correct URL and skips DNS', async () => {
  const { fetcher, calls } = harness([{ status: 200, body: '{}' }], async () => assert.fail('literal address must not resolve'));
  assert.equal((await fetcher('https://[2606:4700::1111]/')).status, 200);
  assert.equal(calls.length, 1);
});
test('redirect to a private address is rejected before the second connection', async () => {
  const { fetcher, calls } = harness([{ status: 302, headers: { location: 'https://127.0.0.1/secret' } }]);
  await assert.rejects(fetcher('https://cards.example/'), { code: 'BLOCKED_ADDRESS' }); assert.equal(calls.length, 1);
});
test('JWKS redirect cannot leave the permitted origin', async () => {
  const { fetcher, calls } = harness([{ status: 302, headers: { location: 'https://other.example/key.json' } }]);
  await assert.rejects(fetcher('https://cards.example/key.json', { allowedOrigin: 'https://cards.example' }), { code: 'ORIGIN_POLICY' }); assert.equal(calls.length, 1);
});
test('same-origin redirects can succeed; cross-origin card discovery is independently rechecked', async () => {
  const { fetcher, calls } = harness([{ status: 302, headers: { location: '/next.json' } }, { status: 200, body: '{}' }]);
  assert.equal((await fetcher('https://cards.example/a.json')).url, 'https://cards.example/next.json'); assert.equal(calls.length, 2);
});
test('body size and compression limits fail closed', async () => {
  await assert.rejects(harness([{ status: 200, chunks: [Buffer.alloc(4), Buffer.alloc(5)] }]).fetcher('https://cards.example/', { maxBytes: 8 }), { code: 'TOO_LARGE' });
  await assert.rejects(harness([{ status: 200, headers: { 'content-encoding': 'gzip' } }]).fetcher('https://cards.example/'), { code: 'ENCODING' });
  await assert.rejects(harness([{ status: 200, chunks: [Buffer.from([0xc0, 0xaf])] }]).fetcher('https://cards.example/'), { code: 'INVALID_UTF8' });
});
test('DNS and response stalls are included in the total timeout', async () => {
  const h = harness([], () => new Promise(() => {}));
  await assert.rejects(h.fetcher('https://cards.example/', { timeoutMs: 20 }), { code: 'TIMEOUT' }); assert.equal(h.calls.length, 0);
  await assert.rejects(harness([{ hang: true }]).fetcher('https://cards.example/', { timeoutMs: 20 }), { code: 'TIMEOUT' });
});
test('credentials, HTTP and invalid options fail without a request', async () => {
  const h = harness([]);
  await assert.rejects(h.fetcher('http://cards.example/'), { code: 'NOT_HTTPS' });
  await assert.rejects(h.fetcher('https://user:secret@cards.example/'), { code: 'CREDENTIALS_IN_URL' });
  await assert.rejects(h.fetcher('https://cards.example/', { timeoutMs: NaN }), { code: 'INVALID_OPTIONS' });
  assert.equal(h.calls.length, 0);
});
test('redirect loops terminate and transport errors do not disclose URLs', async () => {
  const h = harness(Array.from({ length: 5 }, () => ({ status: 302, headers: { location: '/' } })));
  await assert.rejects(h.fetcher('https://cards.example/'), { code: 'TOO_MANY_REDIRECTS' }); assert.equal(h.calls.length, 4);
  await assert.rejects(harness([{ error: true }]).fetcher('https://cards.example/?token=secret'), (e) => e.code === 'NETWORK' && !e.message.includes('secret'));
});
