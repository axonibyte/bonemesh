<?php
// End-to-end BMX handshake tests (security.md §4). Runs the full three-message
// exchange between two in-process parties holding real root-signed certificates,
// asserts both sides derive matching directional transport keys and each other's
// certificate, exercises a transport round-trip, and self-tests the auth oracle
// by tampering with inputs and pinning a foreign root.
use Bonemesh\Handshake;
use Bonemesh\Transport;
use Bonemesh\Frame;
use Bonemesh\Cert;
use Bonemesh\Crypto;

const HS_MESH = 'acme-prod';
const HS_NOW = 1500;

function hs_issue(array $root, string $label): array
{
    $kp = Crypto::mldsa65Generate();
    $cert = ca_sign_cert($root, Cert::build(HS_MESH, $label, $kp['pub'], 1000, 2000));
    return ['cert' => $cert, 'idPrivate' => $kp['priv']];
}

function hs_dec(string $frame): array
{
    return Frame::classify($frame, Frame::HANDSHAKE_CAP)['obj'];
}

test('full handshake derives matching keys and delivers over transport', function () {
    $root = ca_root();
    $i = hs_issue($root, 'initiator');
    $r = hs_issue($root, 'responder');
    $init = Handshake::initiator(HS_MESH, $root['pubRaw'], HS_NOW, $i['cert'], $i['idPrivate']);
    $resp = Handshake::responder(HS_MESH, $root['pubRaw'], HS_NOW, $r['cert'], $r['idPrivate']);

    $m2 = hs_dec($resp->readMessage1WriteMessage2(hs_dec($init->writeMessage1())));
    $m3 = hs_dec($init->readMessage2WriteMessage3($m2));
    $resp->readMessage3($m3);

    $is = $init->session();
    $rs = $resp->session();
    assertEq($is['sendKey'], $rs['receiveKey']);
    assertEq($is['receiveKey'], $rs['sendKey']);
    assertEq('responder', $is['peerCert']['label']);
    assertEq('initiator', $rs['peerCert']['label']);

    // Each carrier crosses the frame wire so seq behaves as between real nodes.
    $it = new Transport($is);
    $rt = new Transport($rs);
    $wire = fn (array $c) => Frame::classify(Frame::encode($c), Frame::TRANSPORT_CAP)['obj'];
    $got = $rt->open($wire($it->seal(['type' => 'data', 'payload' => ['hi' => 'there']])));
    assertEq('there', $got['payload']['hi']);
    $it->open($wire($rt->seal(['type' => 'ack']))); // throws on failure
});

test('responder pinning a foreign root rejects the initiator at msg3', function () {
    $root = ca_root();
    $foreign = ca_root();
    $i = hs_issue($root, 'initiator');
    $r = hs_issue($root, 'responder');
    $init = Handshake::initiator(HS_MESH, $root['pubRaw'], HS_NOW, $i['cert'], $i['idPrivate']);
    $resp = Handshake::responder(HS_MESH, $foreign['pubRaw'], HS_NOW, $r['cert'], $r['idPrivate']);

    $m2 = hs_dec($resp->readMessage1WriteMessage2(hs_dec($init->writeMessage1())));
    $m3 = hs_dec($init->readMessage2WriteMessage3($m2));
    assertThrows(fn () => $resp->readMessage3($m3));
});

test('foreign mesh is rejected at msg1', function () {
    $root = ca_root();
    $i = hs_issue($root, 'initiator');
    $r = hs_issue($root, 'responder');
    $resp = Handshake::responder(HS_MESH, $root['pubRaw'], HS_NOW, $r['cert'], $r['idPrivate']);
    $bad = hs_dec(Handshake::initiator('other-mesh', $root['pubRaw'], HS_NOW, $i['cert'], $i['idPrivate'])->writeMessage1());
    assertThrows(fn () => $resp->readMessage1WriteMessage2($bad));
});

test('tampered responder auth is rejected by the initiator', function () {
    $root = ca_root();
    $i = hs_issue($root, 'initiator');
    $r = hs_issue($root, 'responder');
    $init = Handshake::initiator(HS_MESH, $root['pubRaw'], HS_NOW, $i['cert'], $i['idPrivate']);
    $resp = Handshake::responder(HS_MESH, $root['pubRaw'], HS_NOW, $r['cert'], $r['idPrivate']);

    $m2 = hs_dec($resp->readMessage1WriteMessage2(hs_dec($init->writeMessage1())));
    $auth = base64_decode($m2['auth'], true);
    $mid = intdiv(strlen($auth), 2);
    $auth[$mid] = chr(ord($auth[$mid]) ^ 0x01);
    $m2['auth'] = base64_encode($auth);
    assertThrows(fn () => $init->readMessage2WriteMessage3($m2));
});

// A bmx1 missing a field must be rejected cleanly, with no PHP warnings —
// interop tier 7's fuzzing showed the responder emitting "Undefined array key"
// and "base64_decode(null)" notices before rejecting. Records any warning via a
// custom handler and asserts none fired.
test('responder rejects a bmx1 with a missing field and emits no warnings', function () {
    $root = ca_root();
    $r = hs_issue($root, 'responder');
    $resp = Handshake::responder(HS_MESH, $root['pubRaw'], HS_NOW, $r['cert'], $r['idPrivate']);

    $warnings = [];
    set_error_handler(function ($no, $str) use (&$warnings) {
        $warnings[] = $str;
        return true;
    });
    $threw = false;
    try {
        // valid e and k, but 'n' is absent
        $resp->readMessage1WriteMessage2([
            't' => 'bmx1', 'v' => 3, 'mesh' => HS_MESH,
            'e' => base64_encode(str_repeat("\0", 32)),
            'k' => base64_encode(str_repeat("\0", 1184)),
        ]);
    } catch (\Throwable $e) {
        $threw = true;
    }
    restore_error_handler();

    assertTrue($threw, 'expected the malformed bmx1 to be rejected');
    assertEq(0, count($warnings), 'expected no PHP warnings, got: ' . implode('; ', $warnings));
});

test('responder rejects a bmx1 with a non-base64 field', function () {
    $root = ca_root();
    $r = hs_issue($root, 'responder');
    $resp = Handshake::responder(HS_MESH, $root['pubRaw'], HS_NOW, $r['cert'], $r['idPrivate']);
    assertThrows(fn () => $resp->readMessage1WriteMessage2([
        't' => 'bmx1', 'v' => 3, 'mesh' => HS_MESH, 'e' => '!!!not-base64!!!', 'k' => 'AA==', 'n' => 'AA==',
    ]));
});
