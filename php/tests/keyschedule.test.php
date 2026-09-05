<?php
// Key-schedule known-answer test. Expected values are the shared vector
// (spec/corpus/transcripts/keyschedule.json); reproducing them byte-for-byte
// proves the PHP symmetric state agrees with Java, Elixir, Rust, Go, and JS.
use Bonemesh\KeySchedule;

test('reproduces the shared known-answer vector', function () {
    $meshHex = '61636d652d70726f64';
    $ssDH = '0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20';
    $ssKEM = '2122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f40';
    $pt1 = '726573706f6e6465722d61757468';
    $pt2 = '696e69746961746f722d61757468';

    $s = new KeySchedule();
    assertEq('ca2ab22f811afb5bca159916bd550d879ac5a6f6640d906dc05e2d9ce12c9824', bin2hex($s->h), 'h_init');
    $s->mixHash(hex2bin($meshHex));
    assertEq('f36deae782aa75db659a1d0f27b8edac65913a143bdfefa96fcc401b99c8df88', bin2hex($s->h), 'h_after_mesh');
    $s->mixKey(hex2bin($ssDH));
    assertEq('db8ea3441454c76670fd8ec86c28f1f9231b0fef58723c28a046ae457b0a107c', bin2hex($s->ck), 'ck_after_dh');
    $s->mixKey(hex2bin($ssKEM));
    assertEq('63e4507c23369f55dbf3fbb1d5d887c11f70b156e145db51f3aa92a02050a379', bin2hex($s->ck), 'ck_after_kem');
    assertEq('cd2faeb0160163d5ed9c8cb51f305fb9b257fbd4a06b0c371d92cbab994c', bin2hex($s->encryptAndHash(hex2bin($pt1))), 'ct1');
    assertEq('316b0b3f656dddfada310c4d82595b2a9c179d68df9fe73f025da9739bef6e4c', bin2hex($s->h), 'h_after_ct1');
    assertEq('f56b543d04ce3034e88151cc765c6de343f3039d3f72ee53e16096e3f8d9', bin2hex($s->encryptAndHash(hex2bin($pt2))), 'ct2');
    assertEq('ae83a01e2d5cf41eed8fc2df0eae17c322a920a15790454453df958df16ced76', bin2hex($s->h), 'h_after_ct2');
    [$i2r, $r2i] = $s->split();
    assertEq('b134801d6ec2279d03afb8ed625aaa787c6e06ceb1c11f347bad6f7432c8cb78', bin2hex($i2r), 'i2r');
    assertEq('1b29fa1fa1ef13710241c6750c08d2e3188009cc693cf1e78497ca5d97203aee', bin2hex($r2i), 'r2i');
});

test('decrypt side recovers plaintext and matching transcript hash', function () {
    $mesh = hex2bin('61636d652d70726f64');
    $ssDH = hex2bin('0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20');
    $ssKEM = hex2bin('2122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f40');
    $pt = 'responder-auth';

    $send = new KeySchedule();
    $send->mixHash($mesh); $send->mixKey($ssDH); $send->mixKey($ssKEM);
    $ct = $send->encryptAndHash($pt);

    $recv = new KeySchedule();
    $recv->mixHash($mesh); $recv->mixKey($ssDH); $recv->mixKey($ssKEM);
    assertEq($pt, $recv->decryptAndHash($ct));
    assertEq(bin2hex($send->h), bin2hex($recv->h));
});

test('decrypt rejects a tampered ciphertext', function () {
    $key = hex2bin('0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20');
    $s = new KeySchedule();
    $s->mixKey($key);
    $ct = $s->encryptAndHash('payload');
    $ct[0] = chr(ord($ct[0]) ^ 0x01);
    $r = new KeySchedule();
    $r->mixKey($key);
    assertNull($r->decryptAndHash($ct));
});
