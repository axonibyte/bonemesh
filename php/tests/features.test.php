<?php
// M3 node features at the component level (protocol.md §3, §7). PHP cannot run
// several nodes in one process, so these drive the node's private methods via
// reflection with socketpairs standing in for peers; full cross-node ack/NAK
// relay, probe-death, and idle teardown are exercised end-to-end by interop
// tier 10. What is proven here is the local decision/emission logic:
//   - F1 the simultaneous-dial tiebreak keeps the lower-label-initiated session;
//   - F3 a probe-timed-out link is swept away, a fresh one kept;
//   - F4 idle teardown fires only when enabled;
//   - F6/D4 a TTL-exhausted relay emits a NAK naming ITSELF as the failing hop,
//     and a delivered message is acknowledged back toward the origin.
use Bonemesh\Node;
use Bonemesh\Transport;
use Bonemesh\Frame;

function feat_node(string $label): array
{
    $node = new Node(['label' => $label, 'mesh' => 'm', 'rootPublic' => '', 'cert' => [], 'idPrivate' => '']);
    return [$node, new ReflectionClass($node)];
}

function feat_set_tun(object $node, ReflectionClass $ref, array $overrides): void
{
    $p = $ref->getProperty('tun');
    $p->setAccessible(true);
    $p->setValue($node, array_merge($p->getValue($node), $overrides));
}

function feat_prop(object $node, ReflectionClass $ref, string $name)
{
    $p = $ref->getProperty($name);
    $p->setAccessible(true);
    return $p->getValue($node);
}

function feat_invoke(object $node, ReflectionClass $ref, string $method, array $args)
{
    $m = $ref->getMethod($method);
    $m->setAccessible(true);
    return $m->invoke($node, ...$args);
}

// Register a fake established conn via the real registerLink (so the tiebreak
// runs). Returns the socket id.
function feat_register(object $node, ReflectionClass $ref, int $id, $sock, string $peer, bool $initiator): void
{
    $conns = $ref->getProperty('conns');
    $conns->setAccessible(true);
    $c = $conns->getValue($node);
    $c[$id] = ['sock' => $sock, 'buf' => '', 'phase' => 'established', 'transport' => null, 'peer' => $peer];
    $conns->setValue($node, $c);
    feat_invoke($node, $ref, 'registerLink', [$id, $peer, $initiator]);
}

// Inject an established, linked conn whose transport uses a known send key, so
// a frame the node emits over it can be captured and decrypted from $peerEnd.
function feat_inject_keyed(object $node, ReflectionClass $ref, int $id, $sock, string $peer, string $sendKey): void
{
    $now = (int) (microtime(true) * 1000);
    $conns = $ref->getProperty('conns');
    $conns->setAccessible(true);
    $c = $conns->getValue($node);
    $c[$id] = [
        'sock' => $sock, 'buf' => '', 'phase' => 'established',
        'transport' => new Transport(['sendKey' => $sendKey, 'receiveKey' => str_repeat("\x09", 32)]),
        'peer' => $peer, 'initiator' => true,
        'establishedAt' => $now, 'lastInbound' => $now, 'lastData' => $now,
    ];
    $conns->setValue($node, $c);
    $links = $ref->getProperty('links');
    $links->setAccessible(true);
    $l = $links->getValue($node);
    $l[strtolower($peer)] = $id;
    $links->setValue($node, $l);
    feat_prop($node, $ref, 'table')->observeNeighbor($peer, 1);
}

// Read one frame the node wrote to a captured peer end and decrypt it with a
// transport whose receive key matches the node's send key.
function feat_read_inner($peerEnd, string $nodeSendKey): ?array
{
    stream_set_blocking($peerEnd, false);
    $line = fgets($peerEnd, Frame::TRANSPORT_CAP + 2);
    if ($line === false) {
        return null;
    }
    $res = Frame::classify($line, Frame::TRANSPORT_CAP);
    if (isset($res['reason'])) {
        return null;
    }
    $decoder = new Transport(['sendKey' => str_repeat("\x09", 32), 'receiveKey' => $nodeSendKey]);
    return $decoder->open($res['obj']);
}

test('F1: tiebreak keeps the lower-label-initiated session, order-independent', function () {
    // self="self": against a higher peer keep self-initiated; against a lower
    // peer keep the accepted (peer-initiated) link.
    foreach ([['zzz', true], ['aaa', false]] as [$peer, $wantInitiator]) {
        foreach ([true, false] as $firstInitiator) {
            [$node, $ref] = feat_node('self');
            [$a] = stream_socket_pair(STREAM_PF_UNIX, STREAM_SOCK_STREAM, 0);
            [$b] = stream_socket_pair(STREAM_PF_UNIX, STREAM_SOCK_STREAM, 0);
            feat_register($node, $ref, 1, $a, $peer, $firstInitiator);
            feat_register($node, $ref, 2, $b, $peer, !$firstInitiator);
            $links = feat_prop($node, $ref, 'links');
            $conns = feat_prop($node, $ref, 'conns');
            $survivor = $links[strtolower($peer)] ?? null;
            assertNotNull($survivor, "peer=$peer first=$firstInitiator: no surviving link");
            assertTrue(
                $conns[$survivor]['initiator'] === $wantInitiator,
                "peer=$peer first=" . var_export($firstInitiator, true) .
                    ": survivor initiator=" . var_export($conns[$survivor]['initiator'], true) .
                    " want " . var_export($wantInitiator, true)
            );
            feat_invoke($node, $ref, 'closeConn', [$survivor]);
        }
    }
});

test('F3: a probe-timed-out link is swept away; a fresh one is kept', function () {
    [$node, $ref] = feat_node('self');
    feat_set_tun($node, $ref, ['probeTimeoutMs' => 100, 'idleMs' => 0]);
    [$s] = stream_socket_pair(STREAM_PF_UNIX, STREAM_SOCK_STREAM, 0);
    feat_inject_keyed($node, $ref, 1, $s, 'peer', str_repeat("\x02", 32));

    feat_invoke($node, $ref, 'sweepConn', [1]); // fresh: kept
    $links = feat_prop($node, $ref, 'links');
    assertNotNull($links['peer'] ?? null, 'a fresh link was wrongly swept away');

    $conns = $ref->getProperty('conns');
    $conns->setAccessible(true);
    $c = $conns->getValue($node);
    $c[1]['lastInbound'] = (int) (microtime(true) * 1000) - 5000; // silent past timeout
    $conns->setValue($node, $c);
    feat_invoke($node, $ref, 'sweepConn', [1]);
    assertTrue(!isset(feat_prop($node, $ref, 'conns')[1]), 'probe-timed-out link not swept');
    assertNull(feat_prop($node, $ref, 'table')->nextHop('peer'), 'neighbor not withdrawn on probe death');
});

test('F4: idle teardown fires only when enabled', function () {
    // Enabled: an idle link is torn down.
    [$node, $ref] = feat_node('self');
    feat_set_tun($node, $ref, ['probeTimeoutMs' => 1000000, 'idleMs' => 100]);
    [$s] = stream_socket_pair(STREAM_PF_UNIX, STREAM_SOCK_STREAM, 0);
    feat_inject_keyed($node, $ref, 1, $s, 'peer', str_repeat("\x02", 32));
    $conns = $ref->getProperty('conns');
    $conns->setAccessible(true);
    $c = $conns->getValue($node);
    $c[1]['lastData'] = (int) (microtime(true) * 1000) - 5000;
    $conns->setValue($node, $c);
    feat_invoke($node, $ref, 'sweepConn', [1]);
    assertTrue(!isset(feat_prop($node, $ref, 'conns')[1]), 'idle link not torn down when enabled');

    // Disabled (idleMs=0): the same idle link stays up.
    [$node2, $ref2] = feat_node('self');
    feat_set_tun($node2, $ref2, ['probeTimeoutMs' => 1000000, 'idleMs' => 0]);
    [$s2] = stream_socket_pair(STREAM_PF_UNIX, STREAM_SOCK_STREAM, 0);
    feat_inject_keyed($node2, $ref2, 1, $s2, 'peer', str_repeat("\x02", 32));
    $conns2 = $ref2->getProperty('conns');
    $conns2->setAccessible(true);
    $c2 = $conns2->getValue($node2);
    $c2[1]['lastData'] = (int) (microtime(true) * 1000) - 5000;
    $conns2->setValue($node2, $c2);
    feat_invoke($node2, $ref2, 'sweepConn', [1]);
    assertNotNull(feat_prop($node2, $ref2, 'links')['peer'] ?? null, 'idle teardown fired though disabled');
    feat_invoke($node2, $ref2, 'closeConn', [1]);
});

test('F6/D4: a TTL-exhausted relay NAKs, naming itself as the failing hop', function () {
    // self="relay": a data message alpha->gamma arrives with ttl=1, so the relay
    // exhausts it and must return a NAK to alpha naming "relay" (not "gamma").
    [$node, $ref] = feat_node('relay');
    $sendKey = str_repeat("\x07", 32);
    $pair = stream_socket_pair(STREAM_PF_UNIX, STREAM_SOCK_STREAM, 0);
    feat_inject_keyed($node, $ref, 1, $pair[0], 'alpha', $sendKey); // route to origin

    feat_invoke($node, $ref, 'handleData', [[
        'type' => 'data', 'mid' => '0123456789abcdef0123456789abcdef',
        'to' => 'gamma', 'from' => 'alpha', 'ttl' => 1, 'payload' => ['x' => 1],
    ]]);

    $nak = feat_read_inner($pair[1], $sendKey);
    assertNotNull($nak, 'relay emitted no NAK for the TTL-dropped message');
    assertEq('nak', $nak['type'], 'expected a nak');
    assertEq('relay', $nak['hop'], 'NAK must name the relay as the failing hop, not the destination (D4)');
    assertEq('ttl', $nak['reason'], 'NAK reason should be ttl');
    assertEq('alpha', $nak['to'], 'NAK must route back toward the origin');
    feat_invoke($node, $ref, 'closeConn', [1]);
});

test('F6: a delivered message is acknowledged back toward the origin', function () {
    [$node, $ref] = feat_node('beta');
    $sendKey = str_repeat("\x07", 32);
    $pair = stream_socket_pair(STREAM_PF_UNIX, STREAM_SOCK_STREAM, 0);
    feat_inject_keyed($node, $ref, 1, $pair[0], 'alpha', $sendKey);

    $mid = '0123456789abcdef0123456789abcdef';
    feat_invoke($node, $ref, 'handleData', [[
        'type' => 'data', 'mid' => $mid,
        'to' => 'beta', 'from' => 'alpha', 'ttl' => 16, 'payload' => ['x' => 1],
    ]]);

    $ack = feat_read_inner($pair[1], $sendKey);
    assertNotNull($ack, 'destination emitted no ack on delivery');
    assertEq('ack', $ack['type'], 'expected an ack');
    assertEq($mid, $ack['mid'], 'ack mid must match the delivered message');
    assertEq('alpha', $ack['to'], 'ack must route back toward the origin');
    assertEq('beta', $ack['from'], 'ack must be from the delivering node');
    feat_invoke($node, $ref, 'closeConn', [1]);
});
