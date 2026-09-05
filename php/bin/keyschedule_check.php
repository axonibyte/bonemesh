<?php
// Reads the shared key-schedule vector
// (spec/corpus/transcripts/keyschedule.json) and confirms this PHP symmetric
// state reproduces every output. Invoked by interop/check-keyschedule-php.sh.
require __DIR__ . '/../src/autoload.php';

use Bonemesh\KeySchedule;

$path = $argv[1] ?? null;
if ($path === null) {
    fwrite(STDERR, "usage: keyschedule_check <keyschedule.json>\n");
    exit(2);
}
$doc = json_decode(file_get_contents($path), true);
$in = $doc['inputs'];
$out = $doc['outputs'];
$failures = 0;
$check = function (string $name, string $want, string $got) use (&$failures) {
    if (bin2hex($got) === $want) {
        echo "PASS $name\n";
    } else {
        echo "FAIL $name\n  got:  " . bin2hex($got) . "\n  want: $want\n";
        $failures++;
    }
};

$s = new KeySchedule();
$check('h_init', $out['h_init'], $s->h);
$s->mixHash(hex2bin($in['mesh_hex']));
$check('h_after_mesh', $out['h_after_mesh'], $s->h);
$s->mixKey(hex2bin($in['ss_dh_hex']));
$check('ck_after_dh', $out['ck_after_dh'], $s->ck);
$s->mixKey(hex2bin($in['ss_kem_hex']));
$check('ck_after_kem', $out['ck_after_kem'], $s->ck);
$check('ct1', $out['ct1_hex'], $s->encryptAndHash(hex2bin($in['plaintext1_hex'])));
$check('h_after_ct1', $out['h_after_ct1'], $s->h);
$check('ct2', $out['ct2_hex'], $s->encryptAndHash(hex2bin($in['plaintext2_hex'])));
$check('h_after_ct2', $out['h_after_ct2'], $s->h);
[$i2r, $r2i] = $s->split();
$check('transport_key_i2r', $out['transport_key_i2r'], $i2r);
$check('transport_key_r2i', $out['transport_key_r2i'], $r2i);

if ($failures > 0) {
    fwrite(STDERR, "$failures output(s) mismatched\n");
    exit(1);
}
echo "key schedule reproduces every shared output\n";
