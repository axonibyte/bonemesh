<?php
namespace Bonemesh;

// Operational knobs (protocol.md §0): local behavior, never part of the wire
// contract, read once from the environment at node start. Two nodes with
// different values still interoperate.
final class Tunables
{
    /** @return array<string,int|string> */
    public static function load(): array
    {
        return [
            'probeTimeoutMs' => self::envInt('BONEMESH_PROBE_TIMEOUT_MS', 15000),
            'idleMs'         => self::envInt('BONEMESH_IDLE_MS', 0),
            'retryBaseMs'    => self::envInt('BONEMESH_RETRY_BASE_MS', 500),
            'retryCapMs'     => self::envInt('BONEMESH_RETRY_CAP_MS', 30000),
            'retryMaxMs'     => self::envInt('BONEMESH_RETRY_MAX_MS', 60000),
            'rekeyMs'        => self::envInt('BONEMESH_REKEY_MS', 3600000),
            'rekeyFrames'    => self::envInt('BONEMESH_REKEY_FRAMES', 65536),
            'rekeyTimeoutMs' => self::envInt('BONEMESH_REKEY_TIMEOUT_MS', 10000),
            'keylogPath'     => (string) (getenv('BONEMESH_KEYLOG') ?: ''),
        ];
    }

    private static function envInt(string $name, int $fallback): int
    {
        $v = getenv($name);
        if ($v === false || $v === '') {
            return $fallback;
        }
        // Accept only a well-formed integer; anything else falls back.
        if (preg_match('/^-?\d+$/', $v) !== 1) {
            return $fallback;
        }
        return (int) $v;
    }
}
