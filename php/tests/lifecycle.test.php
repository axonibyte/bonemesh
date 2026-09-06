<?php
// Link registration lifecycle (protocol.md §3), tested at the component level
// (PHP cannot run several nodes in one process, so the socket plumbing is
// driven directly via reflection with a socketpair standing in for a peer):
//   - a reconnect displaces AND closes the old conn;
//   - a stale conn's death must not withdraw the live link's routes;
//   - register stamps who initiated and the liveness/idle clocks;
//   - the env tunables seam reads its knobs with pinned defaults.
use Bonemesh\Node;
use Bonemesh\Tunables;

// Reach the private conns/links/table/registerLink/closeConn of a Node so the
// guard logic can be exercised without a full two-node session.
function lc_node(): array
{
    $node = new Node(['label' => 'self', 'mesh' => 'm', 'rootPublic' => '', 'cert' => [], 'idPrivate' => '']);
    $ref = new ReflectionClass($node);
    return [$node, $ref];
}

function lc_prop(object $node, ReflectionClass $ref, string $name)
{
    $p = $ref->getProperty($name);
    $p->setAccessible(true);
    return $p->getValue($node);
}

// Install a fake established conn (a socketpair end stands in for the peer's
// socket) and register it as the link for $peer with the given initiator flag.
function lc_register(object $node, ReflectionClass $ref, int $id, $sock, string $peer, bool $initiator): void
{
    $conns = $ref->getProperty('conns');
    $conns->setAccessible(true);
    $c = $conns->getValue($node);
    $c[$id] = ['sock' => $sock, 'buf' => '', 'phase' => 'established', 'transport' => null, 'peer' => $peer];
    $conns->setValue($node, $c);
    $m = $ref->getMethod('registerLink');
    $m->setAccessible(true);
    $m->invoke($node, $id, $peer, $initiator);
}

function lc_close(object $node, ReflectionClass $ref, int $id): void
{
    $m = $ref->getMethod('closeConn');
    $m->setAccessible(true);
    $m->invoke($node, $id);
}

// Inject a raw conn entry WITHOUT going through registerLink, so it does not
// displace the current link — this is how we stage a stale conn that still
// exists while links[peer] points elsewhere, the exact state closeConn's
// identity guard protects.
function lc_inject_conn(object $node, ReflectionClass $ref, int $id, $sock, string $peer): void
{
    $conns = $ref->getProperty('conns');
    $conns->setAccessible(true);
    $c = $conns->getValue($node);
    $c[$id] = ['sock' => $sock, 'buf' => '', 'phase' => 'established', 'transport' => null, 'peer' => $peer];
    $conns->setValue($node, $c);
}

test('reconnect displaces and closes the old conn', function () {
    [$node, $ref] = lc_node();
    [$a1] = stream_socket_pair(STREAM_PF_UNIX, STREAM_SOCK_STREAM, 0);
    [$b1] = stream_socket_pair(STREAM_PF_UNIX, STREAM_SOCK_STREAM, 0);

    lc_register($node, $ref, 101, $a1, 'peer', true);
    lc_register($node, $ref, 202, $b1, 'peer', true); // reconnect: displaces 101

    $links = lc_prop($node, $ref, 'links');
    assertEq(202, $links['peer'], 'links must point at the newest conn');
    $conns = lc_prop($node, $ref, 'conns');
    assertTrue(!isset($conns[101]), 'displaced conn was not removed');
    assertTrue(!is_resource($a1), 'displaced socket was not closed (still a live resource)');
    lc_close($node, $ref, 202);
});

test('a stale conn death does not withdraw the live link routes', function () {
    [$node, $ref] = lc_node();
    [$live] = stream_socket_pair(STREAM_PF_UNIX, STREAM_SOCK_STREAM, 0);
    [$stale] = stream_socket_pair(STREAM_PF_UNIX, STREAM_SOCK_STREAM, 0);

    // 202 is the live registered link for peer; 101 is a stale conn for the
    // same peer that still exists but is no longer the current link.
    lc_register($node, $ref, 202, $live, 'peer', true);
    lc_inject_conn($node, $ref, 101, $stale, 'peer');

    // The stale conn's death must NOT withdraw the neighbor that 202 owns.
    lc_close($node, $ref, 101);
    $table = lc_prop($node, $ref, 'table');
    assertNotNull($table->nextHop('peer'), 'stale conn death withdrew the live neighbor');
    $links = lc_prop($node, $ref, 'links');
    assertEq(202, $links['peer'] ?? null, 'live link entry lost after stale close');

    // Control: closing the CURRENT conn does withdraw the neighbor — proves the
    // guard discriminates rather than never withdrawing.
    lc_close($node, $ref, 202);
    $table = lc_prop($node, $ref, 'table');
    assertNull($table->nextHop('peer'), 'current conn death failed to withdraw the neighbor');
});

test('registerLink stamps initiator and the liveness clocks', function () {
    [$node, $ref] = lc_node();
    [$s] = stream_socket_pair(STREAM_PF_UNIX, STREAM_SOCK_STREAM, 0);
    $before = (int) (microtime(true) * 1000);
    lc_register($node, $ref, 303, $s, 'peer', true);
    $conns = lc_prop($node, $ref, 'conns');
    $c = $conns[303];
    assertTrue($c['initiator'] === true, 'initiator flag not recorded');
    assertTrue($c['establishedAt'] >= $before && $c['lastInbound'] >= $before && $c['lastData'] >= $before,
        'timestamps not initialized at register');
    lc_close($node, $ref, 303);
});

test('tunables read env with pinned defaults', function () {
    putenv('BONEMESH_PROBE_TIMEOUT_MS=1234');
    assertEq(1234, Tunables::load()['probeTimeoutMs'], 'env override ignored');
    putenv('BONEMESH_PROBE_TIMEOUT_MS=garbage');
    assertEq(15000, Tunables::load()['probeTimeoutMs'], 'unparseable env did not fall back');
    putenv('BONEMESH_PROBE_TIMEOUT_MS'); // clear
    $t = Tunables::load();
    assertEq(0, $t['idleMs']);
    assertEq(500, $t['retryBaseMs']);
    assertEq(30000, $t['retryCapMs']);
    assertEq(60000, $t['retryMaxMs']);
    assertEq(3600000, $t['rekeyMs']);
    assertEq(65536, $t['rekeyFrames']);
    assertEq(10000, $t['rekeyTimeoutMs']);
});
