<?php
// Reads the shared hybrid key-agreement vector
// (spec/corpus/transcripts/handshake-agreement.json) and confirms this PHP
// implementation reproduces the transcript checkpoints and transport keys.
// Sequence: mixHash(mesh, ei_pub, ki_ek, n); mixHash(er_pub); mixKey(ss_dh);
// mixHash(ct); mixKey(ss_kem); split(). Invoked by interop/check-agreement-php.sh.
require __DIR__ . '/../src/autoload.php';

use Bonemesh\KeySchedule;

$path = $argv[1] ?? null;
if ($path === null) {
    fwrite(STDERR, "usage: agreement_check <handshake-agreement.json>\n");
    exit(2);
}
$doc = json_decode(file_get_contents($path), true);
$in = fn (string $k) => hex2bin($doc['inputs'][$k]);
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
$s->mixHash($in('mesh_hex'));
$s->mixHash($in('ei_pub_hex'));
$s->mixHash($in('ki_ek_hex'));
$s->mixHash($in('n_hex'));
$check('h_after_msg1', $out['h_after_msg1'], $s->h);

$s->mixHash($in('er_pub_hex'));
$s->mixKey($in('ss_dh_hex'));
$check('ck_after_dh', $out['ck_after_dh'], $s->ck);

$s->mixHash($in('kem_ct_hex'));
$s->mixKey($in('ss_kem_hex'));
$check('ck_after_kem', $out['ck_after_kem'], $s->ck);

// The msg-2 checkpoint is taken once both message-2 hash inputs (responder
// ephemeral and KEM ciphertext) are absorbed; mixKey does not alter h.
$check('h_after_msg2_ephemerals', $out['h_after_msg2_ephemerals'], $s->h);

[$i2r, $r2i] = $s->split();
$check('transport_key_i2r', $out['transport_key_i2r'], $i2r);
$check('transport_key_r2i', $out['transport_key_r2i'], $r2i);

if ($failures > 0) {
    fwrite(STDERR, "$failures checkpoint(s) mismatched\n");
    exit(1);
}
echo "hybrid key agreement reproduces every shared checkpoint\n";
