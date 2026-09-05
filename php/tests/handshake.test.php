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
