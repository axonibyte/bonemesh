<?php
// Broadcast (protocol.md section 6). PHP cannot run several nodes in one process,
// so this drives the node with socketpairs standing in for peers, exactly as
// features.test.php does; cross-node delivery is proven by the interop matrix.
//
// What is proven here is the target selection, which is where D5 lived: the v2
// implementation iterated indirect routes only, so direct session peers were
// missed, and a node could appear among its own routes, so it broadcast to itself.
use Bonemesh\Node;

test('broadcast reaches every live peer and never the sender', function () {
    [$node, $ref] = feat_node('self');
    $key = str_repeat("\x01", 32);

    [$aNode, $aPeer] = stream_socket_pair(STREAM_PF_UNIX, STREAM_SOCK_STREAM, 0);
    [$bNode, $bPeer] = stream_socket_pair(STREAM_PF_UNIX, STREAM_SOCK_STREAM, 0);
    feat_inject_keyed($node, $ref, 1, $aNode, 'alpha', $key);
    feat_inject_keyed($node, $ref, 2, $bNode, 'beta', $key);

    // The D5 condition: the node's own label present among its routes. It must not
    // be targeted even so.
    feat_prop($node, $ref, 'table')->learnRoute('self', 'alpha', 5);

    $handed = $node->broadcast(['m' => 'all']);
    assertEq(2, $handed, 'both live peers should have been handed the message');

    foreach ([[$aPeer, 'alpha'], [$bPeer, 'beta']] as [$peerEnd, $who]) {
        $inner = feat_read_inner($peerEnd, $key);
        assertTrue($inner !== null, "$who received no frame");
        assertEq('data', $inner['type']);
        assertEq(['m' => 'all'], $inner['payload']);
        assertEq($who, $inner['to'], "the frame written to $who was addressed elsewhere");
    }
});

test('broadcast gives each destination its own message id', function () {
    // Forced, not stylistic: dedup keys on (mid, chunk index), so a shared mid would
    // have the first relay suppress every other copy, and an ack names only a mid.
    [$node, $ref] = feat_node('self');
    $key = str_repeat("\x01", 32);
    [$aNode, $aPeer] = stream_socket_pair(STREAM_PF_UNIX, STREAM_SOCK_STREAM, 0);
    [$bNode, $bPeer] = stream_socket_pair(STREAM_PF_UNIX, STREAM_SOCK_STREAM, 0);
    feat_inject_keyed($node, $ref, 1, $aNode, 'alpha', $key);
    feat_inject_keyed($node, $ref, 2, $bNode, 'beta', $key);

    assertEq(2, $node->broadcast(['m' => 'all']));
    $a = feat_read_inner($aPeer, $key);
    $b = feat_read_inner($bPeer, $key);
    assertTrue($a !== null && $b !== null, 'both peers should have received a frame');
    assertTrue($a['mid'] !== $b['mid'], 'both destinations were sent the same mid');
});

test('broadcast with no peers reaches nobody', function () {
    // The boundary: no reachable labels means a count of zero, not a node
    // broadcasting to itself -- which is precisely the D5 failure.
    [$node, $ref] = feat_node('self');
    assertEq(0, $node->broadcast(['m' => 'all']));
});

// Close reasons on the wire (protocol.md section 8). This port's socketpair harness
// can read exactly what the node wrote, which is what makes the reason assertable at
// all: a bye is followed by the link closing, so no port surfaces the peer's reason
// to a listener. The enum itself is pinned by spec/corpus/messages.json; what is
// pinned here is that kill() actually emits one, and names 'shutdown'.
test('kill says goodbye with reason shutdown before closing', function () {
    [$node, $ref] = feat_node('self');
    $key = str_repeat("\x01", 32);
    [$aNode, $aPeer] = stream_socket_pair(STREAM_PF_UNIX, STREAM_SOCK_STREAM, 0);
    feat_inject_keyed($node, $ref, 1, $aNode, 'alpha', $key);

    $node->kill();

    $inner = feat_read_inner($aPeer, $key);
    assertTrue($inner !== null, 'kill() closed the link without saying anything');
    assertEq('bye', $inner['type']);
    assertEq('shutdown', $inner['reason'], 'the close reason was not "shutdown"');
});
