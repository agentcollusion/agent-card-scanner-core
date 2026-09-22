export class InputError extends Error {
  constructor(code, message) { super(message); this.code = code; this.exitCode = 2; }
}
export function decodeUtf8(bytes) {
  try { return new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(bytes); }
  catch { throw new InputError('INVALID_UTF8', 'Input must be valid UTF-8.'); }
}
export function parseJson(text, { maxBytes = 524288 } = {}) {
  if (Buffer.byteLength(text, 'utf8') > maxBytes) throw new InputError('INPUT_TOO_LARGE', 'JSON exceeds the 512 KiB input limit.');
  let result;
  try { result = JSON.parse(text); } catch { throw new InputError('INVALID_JSON', 'Input must be valid JSON.'); }
  // JSON.parse accepts duplicate keys. Reject them before a signature can be interpreted ambiguously.
  let i = 0;
  const ws = () => { while (/\s/.test(text[i] || '') && i < text.length) i++; };
  const string = () => {
    const start = i++;
    while (i < text.length) { const ch = text[i++]; if (ch === '\\') i++; else if (ch === '"') break; }
    const s = JSON.parse(text.slice(start, i));
    if (!s.isWellFormed()) throw new InputError('INVALID_UNICODE', 'JSON contains an invalid Unicode surrogate.');
    return s;
  };
  const visit = (depth) => {
    if (depth > 64) throw new InputError('INPUT_TOO_DEEP', 'JSON nesting exceeds 64 levels.');
    ws();
    if (text[i] === '"') { string(); return; }
    if (text[i] === '{') {
      i++; ws(); const keys = new Set();
      while (text[i] !== '}') {
        const key = string();
        if (keys.has(key)) throw new InputError('DUPLICATE_KEY', 'JSON contains a duplicate object member.');
        keys.add(key); ws(); i++; visit(depth + 1); ws();
        if (text[i] !== ',') break;
        i++; ws();
      }
      i++; return;
    }
    if (text[i] === '[') {
      i++; ws();
      while (text[i] !== ']') { visit(depth + 1); ws(); if (text[i] !== ',') break; i++; }
      i++; return;
    }
    const start = i;
    while (i < text.length && !/[\s,}\]]/.test(text[i])) i++;
    const scalar = JSON.parse(text.slice(start, i));
    if (typeof scalar === 'number' && !Number.isFinite(scalar)) throw new InputError('INVALID_NUMBER', 'JSON contains a non-finite number.');
  };
  visit(0);
  return result;
}
export const isObject = (x) => x !== null && typeof x === 'object' && !Array.isArray(x);
