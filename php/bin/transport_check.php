<?php
// Reads the shared transport-frame vector
// (spec/corpus/transcripts/transport-frame.json) and confirms this PHP
// transport both reproduces the sealed ciphertext byte-for-byte and can open it
// again. The vector states both halves ("reproduces ct_hex and can open it"), so
// both are asserted: sealing alone would pass even if opening were broken, and
// opening alone would pass a transport that agreed with itself but not with the
// other implementations. Invoked by interop/check-transport-php.sh.
require __DIR__ . '/../src/autoload.php';

use Bonemesh\Transport;

$path = $argv[1] ?? null;
if ($path === null) {
    fwrite(STDERR, "usage: transport_check <transport-frame.json>\n");
    exit(2);
}
$doc = json_decode(file_get_contents($path), true);
$in = $doc['inputs'];
$out = $doc['outputs'];
$failures = 0;
$check = function (string $name, string $want, string $got) use (&$failures) {
    if ($got === $want) {
        echo "PASS $name\n";
    } else {
        echo "FAIL $name\n  got:  $got\n  want: $want\n";
        $failures++;
    }
};

$key = hex2bin($in['key_hex']);
$seq = (int) $in['seq'];
$inner = hex2bin($in['inner_plaintext_hex']);

$check('ct_hex', $out['ct_hex'], bin2hex(Transport::sealCiphertext($key, $seq, $inner)));

$opened = Transport::openCiphertext($key, $seq, hex2bin($out['ct_hex']));
if ($opened === null) {
    echo "FAIL inner_plaintext_hex\n  got:  <authentication failed>\n";
    $failures++;
} else {
    $check('inner_plaintext_hex', $in['inner_plaintext_hex'], bin2hex($opened));
}

if ($failures > 0) {
    fwrite(STDERR, "$failures output(s) mismatched\n");
    exit(1);
}
echo "transport frame seals and opens to the shared vector\n";
