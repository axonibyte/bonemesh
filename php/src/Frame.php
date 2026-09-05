<?php
namespace Bonemesh;

// BoneMesh v3 frame reader/writer (protocol.md §2): one newline-terminated
// UTF-8 JSON object per frame within a hard size cap (defect D7). Classification
// verdicts match the shared corpus (spec/corpus/framing.json).
//
// A frame body must be exactly one JSON value with nothing but whitespace after
// it; "{...} X" is trailing-data, not invalid-json. PHP's json_decode cannot
// distinguish the two, so a small one-value scanner finds the end of the first
// complete value and we check what follows.
final class Frame
{
    public const HANDSHAKE_CAP = 32768;
    public const TRANSPORT_CAP = 65536;

    // Returns ['obj' => array] on success or ['reason' => string] on rejection.
    public static function classify(string $raw, int $cap): array
    {
        $nl = strpos($raw, "\n");
        if ($nl === false) {
            return ['reason' => 'no-newline'];
        }
        if ($nl + 1 > $cap) {
            return ['reason' => 'oversize'];
        }
        $content = substr($raw, 0, $nl);
        if ($content === '') {
            return ['reason' => 'empty'];
        }
        if (@preg_match('//u', $content) === false) {
            return ['reason' => 'invalid-utf8'];
        }
        $start = self::skipWs($content, 0);
        $end = self::scanValue($content, $start);
        if ($end < 0) {
            return ['reason' => 'invalid-json'];
        }
        if (self::skipWs($content, $end) < strlen($content)) {
            return ['reason' => 'trailing-data'];
        }
        $val = json_decode($content, true);
        if (json_last_error() !== JSON_ERROR_NONE) {
            return ['reason' => 'invalid-json'];
        }
        if ($content[$start] !== '{') {
            return ['reason' => 'not-an-object'];
        }
        return ['obj' => $val];
    }

    // Encode an object as a frame body followed by a newline. Slashes and
    // Unicode are left unescaped so the bytes match the other implementations'.
    public static function encode(array $obj): string
    {
        return json_encode($obj, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE) . "\n";
    }

    private static function skipWs(string $s, int $i): int
    {
        $len = strlen($s);
        while ($i < $len && ($s[$i] === ' ' || $s[$i] === "\t" || $s[$i] === "\n" || $s[$i] === "\r")) {
            $i++;
        }
        return $i;
    }

    // Index just past the first complete JSON value at $i, or -1 if the text
    // does not begin with a complete, well-formed value.
    private static function scanValue(string $s, int $i): int
    {
        if ($i >= strlen($s)) {
            return -1;
        }
        $c = $s[$i];
        if ($c === '{' || $c === '[') {
            return self::scanContainer($s, $i);
        }
        if ($c === '"') {
            return self::scanString($s, $i);
        }
        if ($c === '-' || ($c >= '0' && $c <= '9')) {
            return self::scanNumber($s, $i);
        }
        if (substr($s, $i, 4) === 'true') {
            return $i + 4;
        }
        if (substr($s, $i, 5) === 'false') {
            return $i + 5;
        }
        if (substr($s, $i, 4) === 'null') {
            return $i + 4;
        }
        return -1;
    }

    private static function scanContainer(string $s, int $i): int
    {
        $stack = [];
        $len = strlen($s);
        for ($j = $i; $j < $len; $j++) {
            $c = $s[$j];
            if ($c === '"') {
                $end = self::scanString($s, $j);
                if ($end < 0) {
                    return -1;
                }
                $j = $end - 1;
            } elseif ($c === '{' || $c === '[') {
                $stack[] = $c === '{' ? '}' : ']';
            } elseif ($c === '}' || $c === ']') {
                if (empty($stack) || array_pop($stack) !== $c) {
                    return -1;
                }
                if (empty($stack)) {
                    return $j + 1;
                }
            }
        }
        return -1;
    }

    private static function scanString(string $s, int $i): int
    {
        $len = strlen($s);
        for ($j = $i + 1; $j < $len; $j++) {
            $c = $s[$j];
            if ($c === '\\') {
                $j++;
                continue;
            }
            if ($c === '"') {
                return $j + 1;
            }
        }
        return -1;
    }

    private static function scanNumber(string $s, int $i): int
    {
        $len = strlen($s);
        $j = $i;
        if ($s[$j] === '-') {
            $j++;
        }
        while ($j < $len) {
            $c = $s[$j];
            if (($c >= '0' && $c <= '9') || $c === '.' || $c === 'e' || $c === 'E' || $c === '+' || $c === '-') {
                $j++;
            } else {
                break;
            }
        }
        return $j > $i ? $j : -1;
    }
}
