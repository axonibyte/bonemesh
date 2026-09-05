// BoneMesh restricted-JCS certificate canonicalization (security.md §11.1): the
// exact byte string the mesh root signs. Byte-for-byte identical to the Java,
// Elixir, Rust, and Go canonicalizers over the shared corpus
// (spec/corpus/canon.json).
//
// Keys sort by UTF-16 code unit — which is JavaScript's default string ordering,
// so Array.prototype.sort() is already correct. Values may only be strings,
// non-negative integers, or nested objects; anything else is rejected.

export function canonicalize(cert) {
  const filtered = {};
  for (const k of Object.keys(cert)) {
    if (k !== 'sig') filtered[k] = cert[k];
  }
  return encodeObject(filtered);
}

function encodeObject(obj) {
  const keys = Object.keys(obj).sort();
  let out = '{';
  for (let i = 0; i < keys.length; i++) {
    if (i > 0) out += ',';
    out += encodeString(keys[i]);
    out += ':';
    out += encodeValue(obj[keys[i]]);
  }
  return out + '}';
}

function encodeValue(v) {
  if (typeof v === 'string') return encodeString(v);
  if (typeof v === 'number') {
    if (!Number.isInteger(v)) throw new Error(`canon: ${v} is not an integer`);
    if (v < 0) throw new Error(`canon: negative integer ${v}`);
    return String(v);
  }
  if (v !== null && typeof v === 'object' && !Array.isArray(v)) {
    return encodeObject(v);
  }
  throw new Error(`canon: value type ${Array.isArray(v) ? 'array' : typeof v} not permitted in a certificate`);
}

function encodeString(s) {
  let out = '"';
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    switch (c) {
      case 0x22: out += '\\"'; break;
      case 0x5c: out += '\\\\'; break;
      case 0x08: out += '\\b'; break;
      case 0x09: out += '\\t'; break;
      case 0x0a: out += '\\n'; break;
      case 0x0c: out += '\\f'; break;
      case 0x0d: out += '\\r'; break;
      default:
        if (c < 0x20) {
          out += '\\u' + c.toString(16).padStart(4, '0');
        } else {
          out += s[i];
        }
    }
  }
  return out + '"';
}
