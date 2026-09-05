<?php
namespace Bonemesh;

// BoneMesh restricted-JCS certificate canonicalization (security.md §11.1): the
// exact byte string the mesh root signs. Byte-for-byte identical to the Java,
// Elixir, Rust, Go, and JS canonicalizers over the shared corpus
// (spec/corpus/canon.json).
//
// A certificate is a PHP associative array. Keys sort by UTF-16 code unit (the
// spec's rule); values may only be strings, non-negative integers, or nested
// objects (associative arrays). JSON arrays, floats, booleans, and null are
// rejected. Strings are emitted as raw UTF-8 with only the mandated escapes.
final class Canon
{
    public static function canonicalize(array $cert): string
    {
        unset($cert['sig']);
        return self::encodeObject($cert);
    }

    private static function encodeObject(array $obj): string
    {
        uksort($obj, static fn($a, $b) => strcmp(self::utf16($a), self::utf16($b)));
        $parts = [];
        foreach ($obj as $k => $v) {
            $parts[] = self::encodeString((string) $k) . ':' . self::encodeValue($v);
        }
        return '{' . implode(',', $parts) . '}';
    }

    private static function encodeValue($v): string
    {
        if (is_string($v)) {
            return self::encodeString($v);
        }
        if (is_int($v)) {
            if ($v < 0) {
                throw new \RuntimeException("canon: negative integer $v");
            }
            return (string) $v;
        }
        if (is_array($v)) {
            if (self::isList($v)) {
                throw new \RuntimeException('canon: arrays are not permitted in a certificate');
            }
            return self::encodeObject($v);
        }
        $t = is_float($v) ? 'non-integer number' : gettype($v);
        throw new \RuntimeException("canon: $t not permitted in a certificate");
    }

    private static function encodeString(string $s): string
    {
        $out = '"';
        $len = strlen($s);
        for ($i = 0; $i < $len; $i++) {
            $c = ord($s[$i]);
            switch ($c) {
                case 0x22: $out .= '\\"'; break;
                case 0x5c: $out .= '\\\\'; break;
                case 0x08: $out .= '\\b'; break;
                case 0x09: $out .= '\\t'; break;
                case 0x0a: $out .= '\\n'; break;
                case 0x0c: $out .= '\\f'; break;
                case 0x0d: $out .= '\\r'; break;
                default:
                    if ($c < 0x20) {
                        $out .= sprintf('\\u%04x', $c);
                    } else {
                        $out .= $s[$i]; // raw byte: ASCII or UTF-8 continuation
                    }
            }
        }
        return $out . '"';
    }

    // A non-empty array with sequential 0..n-1 integer keys is a JSON array; an
    // empty array is treated as an empty object.
    private static function isList(array $a): bool
    {
        return $a !== [] && array_is_list($a);
    }

    // UTF-8 string to UTF-16BE bytes, so strcmp compares by UTF-16 code unit.
    private static function utf16(string $s): string
    {
        $out = '';
        $len = strlen($s);
        $i = 0;
        while ($i < $len) {
            $c = ord($s[$i]);
            if ($c < 0x80) {
                $cp = $c;
                $i += 1;
            } elseif ($c < 0xE0) {
                $cp = (($c & 0x1F) << 6) | (ord($s[$i + 1]) & 0x3F);
                $i += 2;
            } elseif ($c < 0xF0) {
                $cp = (($c & 0x0F) << 12) | ((ord($s[$i + 1]) & 0x3F) << 6) | (ord($s[$i + 2]) & 0x3F);
                $i += 3;
            } else {
                $cp = (($c & 0x07) << 18) | ((ord($s[$i + 1]) & 0x3F) << 12)
                    | ((ord($s[$i + 2]) & 0x3F) << 6) | (ord($s[$i + 3]) & 0x3F);
                $i += 4;
            }
            if ($cp < 0x10000) {
                $out .= pack('n', $cp);
            } else {
                $cp -= 0x10000;
                $out .= pack('n', 0xD800 + ($cp >> 10)) . pack('n', 0xDC00 + ($cp & 0x3FF));
            }
        }
        return $out;
    }
}
