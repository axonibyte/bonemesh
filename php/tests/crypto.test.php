<?php
// Primitive round-trip and self-test coverage. Proves each primitive works and
// that the oracle fires on bad input (tampered AEAD, tampered signature). The
// ML-DSA/ML-KEM tests also exercise the raw-key <-> SPKI reconstruction that the
// openssl-CLI bridge depends on. Cross-language agreement is proven by the
// key-schedule KAT, the PQC interop vector, and the live matrix.
use Bonemesh\Crypto;

test('SHA-256 known answer', function () {
    assertEq('ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad', bin2hex(Crypto::sha256('abc')));
});

test('AEAD seal/open round-trip and tamper/AAD rejection', function () {
    $key = Crypto::sha256('k');
    $nonce = str_repeat("\0", 12);
    $ct = Crypto::aeadSeal($key, $nonce, 'aad', 'hello mesh');
    assertEq('hello mesh', Crypto::aeadOpen($key, $nonce, 'aad', $ct));

    $bad = Crypto::aeadSeal($key, $nonce, null, 'hello');
    $bad[3] = chr(ord($bad[3]) ^ 0x01);
    assertNull(Crypto::aeadOpen($key, $nonce, null, $bad));

    $ct2 = Crypto::aeadSeal($key, $nonce, 'aad-1', 'hello');
    assertNull(Crypto::aeadOpen($key, $nonce, 'aad-2', $ct2));
});

test('HKDF is deterministic, length-correct, info-sensitive, and accepts empty IKM', function () {
    $a = Crypto::hkdf('salt', 'ikm', 'info', 64);
    assertEq(64, strlen($a));
    assertEq(bin2hex($a), bin2hex(Crypto::hkdf('salt', 'ikm', 'info', 64)));
    assertTrue(bin2hex($a) !== bin2hex(Crypto::hkdf('salt', 'ikm', 'other', 64)));
    assertEq(64, strlen(Crypto::hkdf('salt', '', '', 64))); // split's empty IKM
});

test('X25519 agreement is symmetric', function () {
    $a = Crypto::x25519Generate();
    $b = Crypto::x25519Generate();
    assertEq(Crypto::x25519Agree($a['priv'], $b['pub']), Crypto::x25519Agree($b['priv'], $a['pub']));
});

test('ML-KEM-768 encapsulate/decapsulate agree', function () {
    $kp = Crypto::mlkem768Keypair();
    assertEq(1184, strlen($kp['ek']));
    $enc = Crypto::mlkem768Encapsulate($kp['ek']);
    assertEq(1088, strlen($enc['ct']));
    assertEq($enc['ss'], Crypto::mlkem768Decapsulate($kp['dk'], $enc['ct']));
});

test('ML-DSA-65 sign/verify (round-trips through raw pub <-> SPKI), rejects tamper', function () {
    $kp = Crypto::mldsa65Generate();
    assertEq(1952, strlen($kp['pub']));
    $sig = Crypto::mldsa65Sign($kp['priv'], 'transcript hash');
    assertEq(3309, strlen($sig));
    assertTrue(Crypto::mldsa65Verify($kp['pub'], 'transcript hash', $sig));
    $sig[10] = chr(ord($sig[10]) ^ 0x01);
    assertTrue(!Crypto::mldsa65Verify($kp['pub'], 'transcript hash', $sig));
    assertTrue(!Crypto::mldsa65Verify($kp['pub'], 'other', Crypto::mldsa65Sign($kp['priv'], 'transcript hash')));
});
