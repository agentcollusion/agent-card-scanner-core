// RFC 8785 JSON Canonicalization Scheme (JCS).
// - Object members are sorted by the UTF-16 code units of their names (JS default string sort).
// - Numbers use the ECMAScript Number-to-String algorithm (JSON.stringify of a finite number).
// - Strings use JSON.stringify escaping, which matches RFC 8785 §3.2.2.2.
// - No insignificant whitespace.

export function canonicalize(value) {
  if (value === null) return 'null';
  switch (typeof value) {
    case 'boolean':
      return value ? 'true' : 'false';
    case 'number':
      if (!Number.isFinite(value)) throw new TypeError('JCS: non-finite number');
      return JSON.stringify(value); // -0 serializes as "0", as RFC 8785 requires
    case 'string':
      if (!value.isWellFormed()) throw new TypeError('JCS: invalid Unicode surrogate');
      return JSON.stringify(value);
    case 'object': {
      if (Array.isArray(value)) return `[${value.map(canonicalize).join(',')}]`;
      const keys = Object.keys(value).filter((k) => value[k] !== undefined).sort();
      if (keys.some((k) => !k.isWellFormed())) throw new TypeError('JCS: invalid Unicode key');
      return `{${keys.map((k) => `${JSON.stringify(k)}:${canonicalize(value[k])}`).join(',')}}`;
    }
    default:
      throw new TypeError(`JCS: unsupported type ${typeof value}`);
  }
}
