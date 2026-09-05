<?php
// Frame classification tests. Verdicts mirror the shared corpus
// (spec/corpus/framing.json). Byte-for-byte agreement over that corpus is
// checked by bin/interop_checks.php.
use Bonemesh\Frame;

test('accepts a simple object', function () {
    $r = Frame::classify('{"t":"bmx1","v":3}' . "\n", Frame::HANDSHAKE_CAP);
    assertTrue(!isset($r['reason']));
    assertEq('bmx1', $r['obj']['t']);
});

test('verdicts match the corpus shapes', function () {
    $cases = [
        ['no-newline', '{"a":1}', Frame::TRANSPORT_CAP, 'no-newline'],
        ['empty', "\n", Frame::TRANSPORT_CAP, 'empty'],
        ['invalid-json garbage', "not json\n", Frame::TRANSPORT_CAP, 'invalid-json'],
        ['invalid-json interior-newline', '{"a":' . "\n" . '1}' . "\n", Frame::TRANSPORT_CAP, 'invalid-json'],
        ['trailing-data', '{"a":1} X' . "\n", Frame::TRANSPORT_CAP, 'trailing-data'],
        ['not-an-object', '[1,2,3]' . "\n", Frame::TRANSPORT_CAP, 'not-an-object'],
        ['oversize', '{"a":1}' . "\n", 4, 'oversize'],
    ];
    foreach ($cases as [$name, $raw, $cap, $want]) {
        assertEq($want, Frame::classify($raw, $cap)['reason'] ?? '(accept)', $name);
    }
});

test('rejects invalid utf-8', function () {
    $raw = '{"a":"' . chr(0xff) . chr(0xfe) . '"}' . "\n";
    assertEq('invalid-utf8', Frame::classify($raw, Frame::HANDSHAKE_CAP)['reason']);
});

test('nested braces inside strings scan correctly', function () {
    $r = Frame::classify('{"a":{"b":"}]"},"c":[1,{"d":2}]}' . "\n", Frame::TRANSPORT_CAP);
    assertTrue(!isset($r['reason']));
    assertEq([1, ['d' => 2]], $r['obj']['c']);
});

test('encode round-trips through classify', function () {
    $enc = Frame::encode(['t' => 'bmx1', 'mesh' => 'acme']);
    assertEq("\n", substr($enc, -1));
    assertEq('acme', Frame::classify($enc, Frame::HANDSHAKE_CAP)['obj']['mesh']);
});
