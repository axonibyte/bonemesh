<?php
// Key-log emitter tests (security.md §8), component-level: PHP cannot run two
// nodes in one process, so we run a full in-process handshake to get both ends'
// sessions, emit each end's key-log via the node's writeKeylog, and assert the
// two logs agree on the directional keys and transcript-hash label — proof the
// emitted keys are the real shared session keys and the role→direction mapping
// is correct. The cross-node key-log + bonemesh-inspect round-trip is tier 10.
use Bonemesh\Handshake;
use Bonemesh\Frame;
use Bonemesh\Cert;
use Bonemesh\Crypto;
use Bonemesh\Node;

const KL_MESH = 'acme-prod';

function kl_issue(array $root, string $label): array
{
    $kp = Crypto::mldsa65Generate();
    $cert = ca_sign_cert($root, Cert::build(KL_MESH, $label, $kp['pub'], 1000, 2000));
    return ['cert' => $cert, 'idPrivate' => $kp['priv']];
}

function kl_dec(string $frame): array
{
    return Frame::classify($frame, Frame::HANDSHAKE_CAP)['obj'];
}

// A full three-message handshake; returns [initiatorSession, responderSession].
function kl_handshake(): array
{
    $root = ca_root();
    $i = kl_issue($root, 'initiator');
    $r = kl_issue($root, 'responder');
    $init = Handshake::initiator(KL_MESH, $root['pubRaw'], 1500, $i['cert'], $i['idPrivate']);
    $resp = Handshake::responder(KL_MESH, $root['pubRaw'], 1500, $r['cert'], $r['idPrivate']);
    $m2 = kl_dec($resp->readMessage1WriteMessage2(kl_dec($init->writeMessage1())));
    $m3 = kl_dec($init->readMessage2WriteMessage3($m2));
    $resp->readMessage3($m3);
    return [$init->session(), $resp->session()];
}

// Invoke the node's private writeKeylog with an explicit key-log path.
function kl_write(string $path, bool $initiator, array $sess): void
{
    $node = new Node(['label' => 'x', 'mesh' => 'm', 'rootPublic' => '', 'cert' => [], 'idPrivate' => '']);
    $ref = new ReflectionObject($node);
    $tunProp = $ref->getProperty('tun');
    $tunProp->setAccessible(true);
    $tun = $tunProp->getValue($node);
    $tun['keylogPath'] = $path;
    $tunProp->setValue($node, $tun);
    $m = $ref->getMethod('writeKeylog');
    $m->setAccessible(true);
    $m->invoke($node, 0, $initiator, $sess);
}

function kl_parse(string $path): array
{
    $out = [];
    foreach (explode("\n", trim(file_get_contents($path))) as $ln) {
        if ($ln === '' || $ln[0] === '#') {
            continue;
        }
        $f = explode(' ', $ln);
        if (count($f) !== 3) {
            continue;
        }
        $dir = explode('_', $f[0])[1]; // BMX3_<DIR>_TRAFFIC_0 -> DIR
        $out[$dir] = ['th' => $f[1], 'key' => $f[2]];
    }
    return $out;
}

test('keylog emits agreeing directional keys and transcript hash for both ends', function () {
    [$is, $rs] = kl_handshake();
    $fa = tempnam(sys_get_temp_dir(), 'kla');
    $fb = tempnam(sys_get_temp_dir(), 'klb');
    kl_write($fa, true, $is);   // initiator's log
    kl_write($fb, false, $rs);  // responder's log

    $a = kl_parse($fa);
    $b = kl_parse($fb);
    @unlink($fa);
    @unlink($fb);

    assertNotNull($a['I2R'] ?? null, 'initiator wrote an I2R line');
    assertNotNull($b['I2R'] ?? null, 'responder wrote an I2R line');
    assertEq(64, strlen($a['I2R']['key']), 'key is 32 bytes of hex');
    // Both ends must name the same key for each absolute direction — this fails
    // if the responder's role→direction swap is wrong.
    assertEq($a['I2R']['key'], $b['I2R']['key'], 'I2R key disagrees between ends');
    assertEq($a['R2I']['key'], $b['R2I']['key'], 'R2I key disagrees between ends');
    assertEq($a['I2R']['th'], $b['I2R']['th'], 'transcript-hash label disagrees');
    assertTrue($a['I2R']['key'] !== $a['R2I']['key'], 'the two directions must use different keys');
});

test('keylog is silent when BONEMESH_KEYLOG is unset', function () {
    [$is, ] = kl_handshake();
    $node = new Node(['label' => 'x', 'mesh' => 'm', 'rootPublic' => '', 'cert' => [], 'idPrivate' => '']);
    $ref = new ReflectionObject($node);
    // Default tun has keylogPath '' (env unset in tests) — writeKeylog must not throw or write.
    $m = $ref->getMethod('writeKeylog');
    $m->setAccessible(true);
    $m->invoke($node, 0, true, $is); // no path configured -> no-op, no error
    assertTrue(true);
});
