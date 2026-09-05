<?php
// Certificate build/verify tests (security.md §3). The root is a throwaway
// ML-DSA-87 key generated in-test (tests/ca.php), so the suite is self-contained.
use Bonemesh\Cert;
use Bonemesh\Crypto;

const CERT_MESH = 'acme-prod';
const CERT_NBF = 1000;
const CERT_EXP = 2000;
const CERT_NOW = 1500;

function make_signed_cert(array $root, string $label): array
{
    $idk = Crypto::mldsa65Generate()['pub'];
    return ca_sign_cert($root, Cert::build(CERT_MESH, $label, $idk, CERT_NBF, CERT_EXP));
}

test('verifies a valid cert', function () {
    $root = ca_root();
    assertNull(Cert::verify(make_signed_cert($root, 'alpha'), $root['pubRaw'], CERT_MESH, CERT_NOW));
});

test('identity key round-trips', function () {
    $idk = Crypto::mldsa65Generate()['pub'];
    $cert = Cert::build(CERT_MESH, 'alpha', $idk, CERT_NBF, CERT_EXP);
    assertEq($idk, Cert::identityKey($cert));
});

test('rejects a tampered label', function () {
    $root = ca_root();
    $cert = make_signed_cert($root, 'alpha');
    $cert['label'] = 'mallory';
    assertNotNull(Cert::verify($cert, $root['pubRaw'], CERT_MESH, CERT_NOW));
});

test('rejects a swapped identity key', function () {
    $root = ca_root();
    $cert = make_signed_cert($root, 'alpha');
    $cert['idk'] = base64_encode(Crypto::mldsa65Generate()['pub']);
    assertNotNull(Cert::verify($cert, $root['pubRaw'], CERT_MESH, CERT_NOW));
});

test('rejects wrong mesh, expired, not-yet-valid', function () {
    $root = ca_root();
    $cert = make_signed_cert($root, 'alpha');
    assertEq('mesh mismatch', Cert::verify($cert, $root['pubRaw'], 'other', CERT_NOW));
    assertEq('certificate expired', Cert::verify($cert, $root['pubRaw'], CERT_MESH, CERT_EXP + 1));
    assertEq('certificate not yet valid', Cert::verify($cert, $root['pubRaw'], CERT_MESH, CERT_NBF - 1));
});

test('rejects an unsigned cert', function () {
    $cert = Cert::build(CERT_MESH, 'alpha', Crypto::mldsa65Generate()['pub'], CERT_NBF, CERT_EXP);
    assertEq('certificate is unsigned', Cert::verify($cert, str_repeat("\0", 2592), CERT_MESH, CERT_NOW));
});

test('rejects a cert signed by the wrong root', function () {
    $root = ca_root();
    $other = ca_root();
    assertNotNull(Cert::verify(make_signed_cert($root, 'alpha'), $other['pubRaw'], CERT_MESH, CERT_NOW));
});
