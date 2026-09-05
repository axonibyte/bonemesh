<?php
namespace Bonemesh;

// BoneMesh v3 message schema validation (protocol.md §4) and inner-message
// builders. The validator mirrors the other implementations reason-for-reason
// (shared corpus: spec/corpus/messages.json).
final class Message
{
    public const DEFAULT_TTL = 16;

    // Returns null if valid, else a reason tag. Schemas: bmx1, envelope, data, ack.
    public static function validate(string $schema, array $f): ?string
    {
        return match ($schema) {
            'bmx1' => self::validateBmx1($f),
            'envelope' => self::validateEnvelope($f),
            'data' => self::validateData($f),
            'ack' => self::validateAck($f),
            default => 'unknown-schema',
        };
    }

    private static function validateBmx1(array $f): ?string
    {
        if (($f['t'] ?? null) !== 'bmx1') {
            return 'type';
        }
        if (!isset($f['v']) || !is_int($f['v']) || $f['v'] !== 3) {
            return 'version';
        }
        if (!isset($f['mesh']) || !is_string($f['mesh']) || $f['mesh'] === '') {
            return 'empty-mesh';
        }
        foreach (['e', 'k', 'n'] as $key) {
            if (!array_key_exists($key, $f)) {
                return 'missing-field';
            }
            if ($r = self::base64Reason($f[$key])) {
                return $r;
            }
        }
        return null;
    }

    private static function validateEnvelope(array $f): ?string
    {
        if (!isset($f['seq']) || !is_int($f['seq'])) {
            return 'missing-field';
        }
        if ($f['seq'] < 0) {
            return 'seq-range';
        }
        if (!array_key_exists('ct', $f)) {
            return 'missing-field';
        }
        return self::base64Reason($f['ct']);
    }

    private static function validateData(array $f): ?string
    {
        if (($f['type'] ?? null) !== 'data') {
            return 'type';
        }
        if ($r = self::midReason($f['mid'] ?? null)) {
            return $r;
        }
        if (!isset($f['to']) || !is_string($f['to'])) {
            return 'missing-field';
        }
        if (!isset($f['from']) || !is_string($f['from'])) {
            return 'missing-field';
        }
        if (!isset($f['ttl']) || !is_int($f['ttl'])) {
            return 'missing-field';
        }
        if ($f['ttl'] < 1 || $f['ttl'] > 255) {
            return 'ttl-range';
        }
        if (!array_key_exists('payload', $f)) {
            return 'missing-field';
        }
        return null;
    }

    private static function validateAck(array $f): ?string
    {
        if (($f['type'] ?? null) !== 'ack') {
            return 'type';
        }
        return self::midReason($f['mid'] ?? null);
    }

    // Strict standard-alphabet base64: length a multiple of four, padding only
    // at the end — matching the other implementations' strict decoders.
    private static function base64Reason($v): ?string
    {
        if (!is_string($v)) {
            return 'not-base64';
        }
        if (strlen($v) % 4 !== 0) {
            return 'not-base64';
        }
        if (!preg_match('#^[A-Za-z0-9+/]*={0,2}$#', $v)) {
            return 'not-base64';
        }
        return null;
    }

    private static function midReason($v): ?string
    {
        if (!is_string($v) || strlen($v) !== 32) {
            return 'mid-format';
        }
        return preg_match('#^[0-9a-f]{32}$#', $v) ? null : 'mid-format';
    }

    // A fresh 128-bit message id as 32 lowercase-hex characters.
    public static function newMid(): string
    {
        return bin2hex(random_bytes(16));
    }

    public static function data(string $mid, string $from, string $to, int $ttl, $payload): array
    {
        return ['type' => 'data', 'mid' => $mid, 'from' => $from, 'to' => $to, 'ttl' => $ttl, 'payload' => $payload];
    }

    public static function ack(string $mid): array
    {
        return ['type' => 'ack', 'mid' => $mid];
    }

    public static function echo(int $token): array
    {
        return ['type' => 'echo', 'token' => $token];
    }

    // A liveness probe carrying the sender's send-time timestamp (ms), echoed
    // back so the sender can measure RTT.
    public static function probe(int $token): array
    {
        return ['type' => 'probe', 'token' => $token];
    }

    // A route advertisement: destination label -> path cost in ms. The routes
    // map is cast to an object so it encodes as {} (not []) when empty, which
    // the other implementations parse as an object.
    public static function disco(array $routes): array
    {
        return ['type' => 'disco', 'routes' => (object) $routes];
    }
}
