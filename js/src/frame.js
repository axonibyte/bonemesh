// BoneMesh v3 frame reader/writer (protocol.md §2): one newline-terminated
// UTF-8 JSON object per frame within a hard size cap (defect D7). Classification
// verdicts match the shared corpus (spec/corpus/framing.json).
//
// A frame body must be exactly one JSON value with nothing but whitespace after
// it; "{...} X" is trailing-data, not invalid-json. We find the end of the first
// complete value with a small scanner (mirroring a streaming JSON decoder) and
// then check what follows, so the two verdicts stay distinct.

export const HANDSHAKE_CAP = 32768;
export const TRANSPORT_CAP = 65536;

const utf8Strict = new TextDecoder('utf-8', { fatal: true });

// Returns { obj } on success or { reason } on rejection, reading only up to the
// first newline.
export function classify(raw, cap) {
  const nl = raw.indexOf(0x0a);
  if (nl < 0) return { reason: 'no-newline' };
  if (nl + 1 > cap) return { reason: 'oversize' };
  const content = raw.subarray(0, nl);
  if (content.length === 0) return { reason: 'empty' };

  let text;
  try {
    text = utf8Strict.decode(content);
  } catch {
    return { reason: 'invalid-utf8' };
  }

  const end = scanValue(text, skipWs(text, 0));
  if (end < 0) return { reason: 'invalid-json' };
  if (skipWs(text, end) < text.length) return { reason: 'trailing-data' };

  let value;
  try {
    value = JSON.parse(text);
  } catch {
    return { reason: 'invalid-json' };
  }
  if (value === null || typeof value !== 'object' || Array.isArray(value)) {
    return { reason: 'not-an-object' };
  }
  return { obj: value };
}

// Encode an object as a frame body followed by a newline.
export function encode(obj) {
  return Buffer.from(JSON.stringify(obj) + '\n', 'utf8');
}

function skipWs(s, i) {
  while (i < s.length) {
    const c = s[i];
    if (c === ' ' || c === '\t' || c === '\n' || c === '\r') i++;
    else break;
  }
  return i;
}

// Returns the index just past the first complete JSON value starting at i, or
// -1 if the text does not begin with a complete, well-formed value.
function scanValue(s, i) {
  if (i >= s.length) return -1;
  const c = s[i];
  if (c === '{' || c === '[') return scanContainer(s, i);
  if (c === '"') return scanString(s, i);
  if (c === '-' || (c >= '0' && c <= '9')) return scanNumber(s, i);
  if (s.startsWith('true', i)) return i + 4;
  if (s.startsWith('false', i)) return i + 5;
  if (s.startsWith('null', i)) return i + 4;
  return -1;
}

// Depth tracking across both container kinds, skipping over strings.
function scanContainer(s, i) {
  const stack = [];
  for (let j = i; j < s.length; j++) {
    const c = s[j];
    if (c === '"') {
      const end = scanString(s, j);
      if (end < 0) return -1;
      j = end - 1;
    } else if (c === '{' || c === '[') {
      stack.push(c === '{' ? '}' : ']');
    } else if (c === '}' || c === ']') {
      if (stack.length === 0 || stack.pop() !== c) return -1;
      if (stack.length === 0) return j + 1;
    }
  }
  return -1;
}

function scanString(s, i) {
  for (let j = i + 1; j < s.length; j++) {
    const c = s[j];
    if (c === '\\') { j++; continue; }
    if (c === '"') return j + 1;
  }
  return -1;
}

function scanNumber(s, i) {
  let j = i;
  const isNum = (c) => c >= '0' && c <= '9';
  if (s[j] === '-') j++;
  while (j < s.length && (isNum(s[j]) || s[j] === '.' || s[j] === 'e' || s[j] === 'E' || s[j] === '+' || s[j] === '-')) j++;
  return j > i ? j : -1;
}
