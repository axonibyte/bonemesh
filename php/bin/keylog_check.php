<?php
// Reads the shared key-log vector (spec/corpus/keylog.json) and confirms this
// implementation can open a key-logged capture.
//
// security.md §8 pins one implementation-neutral key-log format precisely so a
// single inspector reads a log written by a node in any language. That claim needs
// agreement in BOTH directions: emitting lines your own reader accepts is not
// enough. This checks the reading half against a committed capture the Java
// reference produced. The writing half is covered by each port's own key-log tests
// and, live and cross-language, by interop tier 10.
//
// Invoked by interop/check-keylog-php.sh.
require __DIR__ . '/../src/autoload.php';

use Bonemesh\Transport;

// '#' lines are comments; an unknown label shape is ignored rather than fatal, so
// a future label is not a breaking change.
function parse_keylog(array $lines): array
{
    $keys = [];
    foreach ($lines as $raw) {
        $line = trim($raw);
        if ($line === '' || $line[0] === '#') {
            continue;
        }
        $parts = preg_split('/\s+/', $line);
        if (count($parts) !== 3) {
            continue;
        }
        if (!preg_match('/^BMX3_(I2R|R2I)_TRAFFIC_(\d+)$/', $parts[0], $m)) {
            continue;
        }
        $key = @hex2bin($parts[2]);
        if ($key === false || strlen($key) !== 32) {
            continue;
        }
        $keys[strtolower($m[1]) . ':' . (int) $m[2]] = $key;
    }
    return $keys;
}

function canon($v): string
{
    if (is_array($v) && !array_is_list($v)) {
        ksort($v);
        foreach ($v as $k => $x) {
            $v[$k] = json_decode(canon($x), true);
        }
    }
    return json_encode($v, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
}

$path = $argv[1] ?? null;
if ($path === null) {
    fwrite(STDERR, "usage: keylog_check <keylog.json>\n");
    exit(2);
}
$doc = json_decode(file_get_contents($path), true);
$capture = $doc['capture'] ?? [];
$expected = $doc['expected'] ?? [];
if (count($capture) === 0 || count($capture) !== count($expected)) {
    fwrite(STDERR, sprintf("vector malformed: %d capture, %d expected\n", count($capture), count($expected)));
    exit(1);
}
$keys = parse_keylog($doc['keylog'] ?? []);
if (count($keys) === 0) {
    fwrite(STDERR, "no usable key-log entries in the vector\n");
    exit(1);
}

$failures = 0;
foreach ($capture as $i => $frame) {
    $dir = $frame['dir'];
    $seq = (int) $frame['frame']['seq'];
    $ct = base64_decode($frame['frame']['ct'], true);
    $k = $keys[$dir . ':' . (int) $expected[$i]['epoch']] ?? null;
    if ($k === null) {
        echo "FAIL frame $i: no key for $dir epoch {$expected[$i]['epoch']}\n";
        $failures++;
        continue;
    }
    $pt = Transport::openCiphertext($k, $seq, $ct);
    if ($pt === null) {
        echo "FAIL frame $i: the logged $dir key did not open it\n";
        $failures++;
        continue;
    }
    $got = json_decode($pt, true);
    // Compare structurally, not as text: key order is not part of the contract.
    if (canon($got) === canon($expected[$i]['inner'])) {
        echo "PASS frame $i ($dir seq $seq)\n";
    } else {
        echo "FAIL frame $i\n  got:  " . canon($got) . "\n  want: " . canon($expected[$i]['inner']) . "\n";
        $failures++;
    }
}

// Self-test the oracle: a ciphertext no key seals must be refused, or a checker
// that reported success for everything would look identical to this one.
if (Transport::openCiphertext(reset($keys), 0, str_repeat("\0", 32)) !== null) {
    echo "FAIL self-test: an unopenable frame was accepted\n";
    $failures++;
} else {
    echo "PASS self-test: an unopenable frame is refused\n";
}

if ($failures > 0) {
    fwrite(STDERR, "$failures key-log frame(s) failed\n");
    exit(1);
}
echo "every captured frame opens with its logged key and reproduces the vector\n";
