import test from 'node:test';
import assert from 'node:assert/strict';
import { Readable } from 'node:stream';
import { MAX_JSON_BYTES, readJsonStream } from '../src/input.mjs';

test('stream decoding preserves UTF-8 characters split across chunks', async () => {
  const bytes = Buffer.from('{"name":"雪のエージェント"}');
  assert.deepEqual(await readJsonStream(Readable.from([...bytes].map((b) => Buffer.from([b])))), { name: '雪のエージェント' });
});

test('stream limit is in bytes, accepts the boundary, and stops oversized producers', async () => {
  const json = '{"name":"雪"}';
  const boundary = Buffer.concat([Buffer.from(json), Buffer.alloc(MAX_JSON_BYTES - Buffer.byteLength(json), 32)]);
  assert.deepEqual(await readJsonStream(Readable.from([boundary])), { name: '雪' });
  let consumed = 0;
  let closed = false;
  async function* source() {
    try {
      for (const chunk of [boundary, Buffer.from(' '), Buffer.from('never read')]) { consumed++; yield chunk; }
    } finally { closed = true; }
  }
  await assert.rejects(readJsonStream(source()), { code: 'INPUT_TOO_LARGE', exitCode: 2 });
  assert.equal(consumed, 2); assert.equal(closed, true);
});

test('stream errors and truncated UTF-8 are not treated as successful input', async () => {
  async function* broken() { yield Buffer.from('{'); throw Object.assign(new Error('fixture read failure'), { code: 'EIO' }); }
  await assert.rejects(readJsonStream(broken()), { code: 'EIO' });
  await assert.rejects(readJsonStream(Readable.from([Buffer.from([0xe9, 0x9b])])), { code: 'INVALID_UTF8' });
});
