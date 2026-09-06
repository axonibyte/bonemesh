<?php
// M4 node features F2 (retry/backoff) and F5 (rekey), component-level. PHP
// cannot run two serve() loops in one process, so the two-node rekey is driven
// by pumping frames across a socketpair by hand (single-threaded, deterministic)
// rather than by concurrent event loops; full rekey-under-live-traffic is also
// exercised by interop tier 10. What is proven here:
//   - F2 retry queues an unroutable send, delivers it once a route appears, and
//     reports a lifetime-expired send as nak{expired}; disabled queues nothing;
//   - F5 Transport.swapSend/swapReceive reset the per-direction seq and re-key;
//   - F5 two real nodes complete a 4-phase tunneled-BMX rekey and keep
//     delivering on the new keys.
use Bonemesh\Node;
use Bonemesh\Transport;
use Bonemesh\Frame;
use Bonemesh\Handshake;
use Bonemesh\Message;
use Bonemesh\Cert;
use Bonemesh\Crypto;

function m4_bare(string $label): array
{
    $node = new Node(['label' => $label, 'mesh' => 'm', 'rootPublic' => '', 'cert' => [], 'idPrivate' => '']);
    return [$node, new ReflectionClass($node)];
}

function m4_nowms(): int
{
    return (int) (microtime(true) * 1000);
}

function m4_invoke(object $node, ReflectionClass $ref, string $method, array $args)
{
    $m = $ref->getMethod($method);
    $m->setAccessible(true);
    return $m->invoke($node, ...$args);
}

function m4_prop(object $node, ReflectionClass $ref, string $name)
{
    $p = $ref->getProperty($name);
    $p->setAccessible(true);
    return $p->getValue($node);
}

function m4_set_prop(object $node, ReflectionClass $ref, string $name, $value): void
{
    $p = $ref->getProperty($name);
    $p->setAccessible(true);
    $p->setValue($node, $value);
}

function m4_set_tun(object $node, ReflectionClass $ref, array $overrides): void
{
    m4_set_prop($node, $ref, 'tun', array_merge(m4_prop($node, $ref, 'tun'), $overrides));
}

// Inject an established, linked conn with a transport keyed for send, plus a
// route to peer, so drainRetries can actually deliver over it.
function m4_inject_keyed(object $node, ReflectionClass $ref, int $id, $sock, string $peer, string $sendKey): void
{
    $now = m4_nowms();
    $conns = m4_prop($node, $ref, 'conns');
    $conns[$id] = [
        'sock' => $sock, 'buf' => '', 'phase' => 'established',
        'transport' => new Transport(['sendKey' => $sendKey, 'receiveKey' => str_repeat("\x09", 32)]),
        'peer' => $peer, 'initiator' => true,
        'establishedAt' => $now, 'lastInbound' => $now, 'lastData' => $now,
    ];
    m4_set_prop($node, $ref, 'conns', $conns);
    $links = m4_prop($node, $ref, 'links');
    $links[strtolower($peer)] = $id;
    m4_set_prop($node, $ref, 'links', $links);
    m4_prop($node, $ref, 'table')->observeNeighbor($peer, 1);
}

// Inject an already-established conn carrying a completed handshake session.
function m4_inject_session(object $node, ReflectionClass $ref, int $id, $sock, string $peer, Transport $t, bool $initiator): void
{
    $now = m4_nowms();
    $conns = m4_prop($node, $ref, 'conns');
    $conns[$id] = [
        'sock' => $sock, 'buf' => '', 'phase' => 'established', 'transport' => $t,
        'peer' => $peer, 'initiator' => $initiator,
        'establishedAt' => $now, 'lastInbound' => $now, 'lastData' => $now,
    ];
    m4_set_prop($node, $ref, 'conns', $conns);
    $links = m4_prop($node, $ref, 'links');
    $links[strtolower($peer)] = $id;
    m4_set_prop($node, $ref, 'links', $links);
    m4_prop($node, $ref, 'table')->observeNeighbor($peer, 1);
}

function m4_decode(string $framed): array
{
    return json_decode(trim($framed), true);
}

function m4_cfg(array $root, string $label): array
{
    $kp = Crypto::mldsa65Generate();
    $cert = ca_sign_cert($root, Cert::build('m', $label, $kp['pub'], 1000, 1 << 40));
    return ['label' => $label, 'mesh' => 'm', 'rootPublic' => $root['pubRaw'], 'cert' => $cert, 'idPrivate' => $kp['priv']];
}

// Read exactly one frame the node wrote to a peer end, open it with that node's
// conn transport, and feed the inner to handleInner (driving the rekey machine).
function m4_pump($peerSock, object $node, ReflectionClass $ref, int $id, string $peer): void
{
    $line = fgets($peerSock, Frame::TRANSPORT_CAP + 2);
    assertNotNull($line === false ? null : $line, 'expected a frame to pump');
    $res = Frame::classify($line, Frame::TRANSPORT_CAP);
    assertTrue(!isset($res['reason']), 'unparseable pumped frame');
    $conns = m4_prop($node, $ref, 'conns');
    $inner = $conns[$id]['transport']->open($res['obj']);
    m4_invoke($node, $ref, 'handleInner', [$id, $peer, $inner]);
}

test('F2: a queued retry is delivered once a route appears', function () {
    [$node, $ref] = m4_bare('self');
    m4_set_tun($node, $ref, ['retryMaxMs' => 100000]);
    $msg = Message::data(str_repeat('d', 32), 'self', 'peer', 16, []);
    m4_invoke($node, $ref, 'enqueueRetry', [$msg]);
    $pending = m4_prop($node, $ref, 'pending');
    assertTrue(isset($pending['peer']) && count($pending['peer']) === 1, 'not queued');

    // Keep BOTH ends of the pair alive; a write to a socket whose peer has been
    // closed fails, which would wrongly look like an undeliverable retry.
    $pair = stream_socket_pair(STREAM_PF_UNIX, STREAM_SOCK_STREAM, 0);
    m4_inject_keyed($node, $ref, (int) $pair[0], $pair[0], 'peer', str_repeat("\x05", 32));
    m4_invoke($node, $ref, 'drainRetries', [m4_nowms() + 10000]);
    assertEq(0, count(m4_prop($node, $ref, 'pending')), 'deliverable retry not drained');
});

test('F2: an expired retry is dropped and reported as nak{expired}', function () {
    [$node, $ref] = m4_bare('self');
    m4_set_tun($node, $ref, ['retryMaxMs' => 100, 'retryBaseMs' => 10]);
    $got = [];
    $node->onAck(function ($m) use (&$got) {
        $got[] = $m;
    });
    m4_invoke($node, $ref, 'enqueueRetry', [Message::data(str_repeat('b', 32), 'self', 'peer', 16, [])]);
    $pending = m4_prop($node, $ref, 'pending');
    $pending['peer'][0]['enqueuedAt'] = m4_nowms() - 100000;
    $pending['peer'][0]['nextAt'] = 0;
    m4_set_prop($node, $ref, 'pending', $pending);
    m4_invoke($node, $ref, 'drainRetries', [m4_nowms()]);
    assertEq(0, count(m4_prop($node, $ref, 'pending')), 'expired retry not dropped');
    assertTrue(count($got) === 1 && $got[0]['type'] === 'nak' && $got[0]['reason'] === 'expired', 'no expiry report');
});

test('F2: retry disabled queues nothing', function () {
    [$node, $ref] = m4_bare('self');
    m4_set_tun($node, $ref, ['retryMaxMs' => 0]);
    m4_invoke($node, $ref, 'enqueueRetry', [Message::data(str_repeat('c', 32), 'self', 'peer', 16, [])]);
    assertEq(0, count(m4_prop($node, $ref, 'pending')), 'queued even though retry disabled');
});

test('F5: Transport swapSend/swapReceive reset the direction seq and rekey', function () {
    $kA = str_repeat("\x01", 32);
    $kB = str_repeat("\x02", 32);
    $kC = str_repeat("\x03", 32);
    $t = new Transport(['sendKey' => $kA, 'receiveKey' => $kB]);
    $t->seal(['type' => 'probe', 'token' => 1]);
    $t->seal(['type' => 'probe', 'token' => 2]);
    assertEq(2, $t->sendSeq());

    $t->swapSend($kC);
    assertEq(0, $t->sendSeq(), 'swapSend must reset the send seq');
    $c = $t->seal(['type' => 'probe', 'token' => 3]);
    // Opens under the NEW key at seq 0 (proves the key was swapped, not just the seq).
    $dec = new Transport(['sendKey' => str_repeat("\0", 32), 'receiveKey' => $kC]);
    assertEq(3, $dec->open($c)['token']);
    // And must NOT open under the OLD key.
    $decOld = new Transport(['sendKey' => str_repeat("\0", 32), 'receiveKey' => $kA]);
    assertThrows(fn () => $decOld->open(['seq' => 0, 'ct' => $c['ct']]), 'old key still opened the frame');

    $t->swapReceive($kB);
    assertEq(0, $t->receiveSeq(), 'swapReceive must reset the receive seq');
});

test('F5: two nodes rekey over a socketpair and keep delivering', function () {
    $root = ca_root();
    $cfgA = m4_cfg($root, 'alpha');
    $cfgB = m4_cfg($root, 'beta');
    $A = new Node($cfgA);
    $rA = new ReflectionClass($A);
    $B = new Node($cfgB);
    $rB = new ReflectionClass($B);

    // Establish the initial session by pumping a handshake by hand.
    $hsI = Handshake::initiator('m', $root['pubRaw'], time(), $cfgA['cert'], $cfgA['idPrivate']);
    $hsR = Handshake::responder('m', $root['pubRaw'], time(), $cfgB['cert'], $cfgB['idPrivate']);
    $m2 = $hsR->readMessage1WriteMessage2(m4_decode($hsI->writeMessage1()));
    $m3 = $hsI->readMessage2WriteMessage3(m4_decode($m2));
    $hsR->readMessage3(m4_decode($m3));

    [$sA, $sB] = stream_socket_pair(STREAM_PF_UNIX, STREAM_SOCK_STREAM, 0);
    stream_set_blocking($sA, false);
    stream_set_blocking($sB, false);
    $idA = (int) $sA;
    $idB = (int) $sB;
    m4_inject_session($A, $rA, $idA, $sA, 'beta', new Transport($hsI->session()), true);
    m4_inject_session($B, $rB, $idB, $sB, 'alpha', new Transport($hsR->session()), false);
    m4_set_tun($A, $rA, ['rekeyFrames' => 0]); // due immediately

    // A(phase1) -> B(phase2) -> A(phase3, swap send) -> B(phase4, swaps) -> A(swap recv).
    m4_invoke($A, $rA, 'maybeRekey', [$idA, m4_nowms()]);
    m4_pump($sB, $B, $rB, $idB, 'alpha');
    m4_pump($sA, $A, $rA, $idA, 'beta');
    m4_pump($sB, $B, $rB, $idB, 'alpha');
    m4_pump($sA, $A, $rA, $idA, 'beta');

    $connsA = m4_prop($A, $rA, 'conns');
    $connsB = m4_prop($B, $rB, 'conns');
    assertEq(1, $connsA[$idA]['rekeyEpoch'] ?? 0, 'initiator did not complete a rekey');
    assertEq(1, $connsB[$idB]['rekeyEpoch'] ?? 0, 'responder did not complete a rekey');

    // Continuity: A seals a data message on its NEW keys; B opens it on its NEW keys.
    m4_invoke($A, $rA, 'sendToLink', ['beta', Message::data(str_repeat('a', 32), 'alpha', 'beta', 16, ['m' => 'after-rekey'])]);
    $line = fgets($sB, Frame::TRANSPORT_CAP + 2);
    assertNotNull($line === false ? null : $line, 'no post-rekey frame');
    $res = Frame::classify($line, Frame::TRANSPORT_CAP);
    $inner = $connsB[$idB]['transport']->open($res['obj']);
    assertEq('after-rekey', $inner['payload']['m'] ?? null, 'delivery broke across the rekey');
});
