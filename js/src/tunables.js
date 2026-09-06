// Operational knobs (protocol.md §0): local behavior, never part of the wire
// contract, read once from the environment at node start. Two nodes with
// different values still interoperate.

function envInt(name, fallback) {
  const v = process.env[name];
  if (v === undefined || v === '') return fallback;
  const n = Number.parseInt(v, 10);
  return Number.isNaN(n) ? fallback : n;
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
