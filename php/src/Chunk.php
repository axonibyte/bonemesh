<?php
namespace Bonemesh;

// Splitting and reassembly of oversized application payloads (protocol.md §6.1).
//
// A payload too large for one transport frame is serialized, its UTF-8 bytes cut
// into segments of at most MAX_SEGMENT_BYTES on character boundaries, and each
// segment sent as a data message sharing one message id, carrying chunk {i, n} and
// a top-level "seg" string and NO "payload". A payload that fits travels whole,
// with "payload" and no "seg".
//
// Segments are text, not Base64: §0's Base64 rule covers binary fields, a slice of
// JSON text is already UTF-8, and a JSON string carries it directly, so a split
// message stays readable through the key-log inspector (decisions #3, #5, #25).
// Cutting on a byte budget rather than a character count is what keeps the split
// identical across the seven implementations; in this port a PHP string is already
// a byte string, so substr() and strlen() are the right primitives here and the
// mb_* family would be the wrong one.
final class Chunk
{
    // Maximum payload bytes carried by one segment (protocol.md §0).
    public const MAX_SEGMENT_BYTES = 24000;

    // Maximum segments one application message may be split into (§0).
    public const MAX_CHUNKS = 1024;

    // Maximum segment bytes buffered at once, across every in-flight message (§0).
    public const MAX_REASSEMBLY_BUFFER = 16777216;

    // Maximum messages that may be mid-reassembly at once (§0).
    public const MAX_CONCURRENT_REASSEMBLIES = 256;

    // Milliseconds a partially-filled message may sit before being discarded (§0).
    public const REASSEMBLY_TIMEOUT_MILLIS = 30000;

    // Splits a payload into one whole data message or a series of segments. Throws
    // InvalidArgumentException when no conforming destination would reassemble it,
    // so the caller is told locally rather than the mesh carrying a message that
    // cannot arrive (§6.1, Bounds).
    public static function split(string $mid, string $from, string $to, int $ttl, $payload): array
    {
        $src = json_encode($payload, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
        if (strlen($src) <= self::MAX_SEGMENT_BYTES) {
            return [Message::data($mid, $from, $to, $ttl, $payload)];
        }
        if (strlen($src) > self::MAX_REASSEMBLY_BUFFER) {
            throw new \InvalidArgumentException(sprintf(
                'payload of %d bytes exceeds the reassembly buffer maximum of %d',
                strlen($src),
                self::MAX_REASSEMBLY_BUFFER
            ));
        }

        $segs = [];
        for ($pos = 0; $pos < strlen($src);) {
            $end = self::charBoundary($src, $pos, min($pos + self::MAX_SEGMENT_BYTES, strlen($src)));
            $segs[] = substr($src, $pos, $end - $pos);
            $pos = $end;
        }
        if (count($segs) > self::MAX_CHUNKS) {
            throw new \InvalidArgumentException(sprintf(
                'payload needs %d segments, over the maximum of %d',
                count($segs),
                self::MAX_CHUNKS
            ));
        }

        $n = count($segs);
        $out = [];
        foreach ($segs as $i => $seg) {
            $out[] = Message::dataSegment($mid, $from, $to, $ttl, $i, $n, $seg);
        }
        return $out;
    }

    // Walks a proposed cut back to the nearest character boundary at or before it,
    // so a segment never ends mid-character and is itself valid UTF-8.
    private static function charBoundary(string $src, int $start, int $end): int
    {
        if ($end >= strlen($src)) {
            return $end; // the tail is always a boundary
        }
        $e = $end;
        while ($e > $start && (ord($src[$e]) & 0xC0) === 0x80) { // 10xxxxxx is a continuation byte
            $e--;
        }
        // A UTF-8 character is at most 4 bytes and a segment is 24000, so $e cannot
        // reach $start from well-formed input; falling back keeps a malformed
        // serializer from producing a zero-length segment and looping forever.
        return $e > $start ? $e : $end;
    }
}
