// Operational knobs (protocol.md §0): local behavior, never part of the wire
// contract, read once from the environment at node start. Two nodes with
// different values still interoperate.

// An optional sign then decimal digits, and nothing else (protocol.md §0).
const INT = /^-?[0-9]+$/;

function envInt(name, fallback) {
  const v = process.env[name];
  if (v === undefined || !INT.test(v)) return fallback;
  // Number.parseInt stops at the first non-digit, so it read 'BONEMESH_IDLE_MS=12abc'
  // as 12 and '1_000' as 1 -- partially parsing an operator's typo rather than
  // ignoring it. The pattern decides; parseInt only converts what it accepted.
  return Number.parseInt(v, 10);
}

export function loadTunables() {
  return {
    probeTimeoutMs: envInt('BONEMESH_PROBE_TIMEOUT_MS', 15000),
    idleMs: envInt('BONEMESH_IDLE_MS', 0),
    retryBaseMs: envInt('BONEMESH_RETRY_BASE_MS', 500),
    retryCapMs: envInt('BONEMESH_RETRY_CAP_MS', 30000),
    retryMaxMs: envInt('BONEMESH_RETRY_MAX_MS', 60000),
    rekeyMs: envInt('BONEMESH_REKEY_MS', 3600000),
    rekeyFrames: envInt('BONEMESH_REKEY_FRAMES', 65536),
    rekeyTimeoutMs: envInt('BONEMESH_REKEY_TIMEOUT_MS', 10000),
    keylogPath: process.env.BONEMESH_KEYLOG ?? '',
  };
}
