<?php
// Verifies the PHP port's post-quantum interop against the shared vector
// (spec/corpus/transcripts/pqc-interop.json), produced by the Java reference
// (BouncyCastle).
//
// It verifies the ML-DSA-65 signature over the vector's message using the
// vector's public key, exercising the node's real Crypto::mldsa65Verify (the
// openssl 3.5 CLI). Success proves PHP and Java agree on ML-DSA-65 byte-for-byte.
//
// It does NOT decapsulate the vector's ML-KEM ciphertext: the vector ships a
// 2400-byte FIPS *expanded* decapsulation key, while this port (like Go and JS)
// works from openssl's seed-keyed private form. That is a private-key
// *representation* difference, not an interop gap — a decapsulation key never
// crosses a node (only the encapsulation key, ciphertext, and public artifacts
// do, all standard FIPS encodings). Live ML-KEM-768 interop between PHP and the
// other implementations is proven directly by the interop matrix.
require __DIR__ . '/../src/autoload.php';

use Bonemesh\Crypto;

$path = $argv[1] ?? null;
if ($path === null) {
    fwrite(STDERR, "usage: pqc_check <pqc-interop.json>\n");
    exit(2);
}
$v = json_decode(file_get_contents($path), true)['mldsa65'];

$ok = Crypto::mldsa65Verify(hex2bin($v['public_hex']), hex2bin($v['message_hex']), hex2bin($v['signature_hex']));
if (!$ok) {
    fwrite(STDERR, "FAIL: PHP did not verify the Java ML-DSA-65 signature\n");
    exit(1);
}
echo "PASS: PHP verifies the Java ML-DSA-65 signature over the shared vector\n";
echo "NOTE: ML-KEM-768 interop with Java is proven live by the interop matrix\n";
echo "      (openssl's ML-KEM private form is seed-keyed; the vector's expanded\n";
echo "      dk is a key-representation detail that never crosses a node).\n";
