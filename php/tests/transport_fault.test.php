<?php
// A transport-level fault tears the session down and names the reason
// (protocol.md §4 and §8, defects D20 and D21).
//
// PHP cannot run several nodes in one process, so — as in lifecycle.test.php — a
// socketpair end stands in for the peer and onReadable is driven by reflection.
// The injection is a seq gap rather than a flipped ciphertext byte: it is
// deterministic and it exercises the ordering rule §4 actually states.
//
// Two of these cover faults this port previously swallowed: a frame that is not
// one JSON object was `continue`d in the established phase (silently skipped,
// where every other port closed), and the read buffer had no cap at all until a
// newline arrived, so a peer could grow it without limit.
//
// What these tests do NOT prove: that the node re-dials and recovers. That is
// tier 10's job. The claim here is narrower — the session is torn down rather
// than kept, and the reason reaches the far end.
use Bonemesh\Frame;
use Bonemesh\Message;
use Bonemesh\Node;
use Bonemesh\Transport;

// A node with one established conn whose transport has all-zero keys, plus the
// peer-side mirror of it and the peer end of the socketpair.
function tf_setup(): array
{
    $node = new Node(['label' => 'self', 'mesh' => 'm', 'rootPublic' => '', 'cert' => [], 'idPrivate' => '']);
    $ref = new ReflectionClass($node);
    [$nodeSide, $peerSide] = stream_socket_pair(STREAM_PF_UNIX, STREAM_SOCK_STREAM, 0);
    stream_set_blocking($peerSide, false);

    $keys = ['sendKey' => str_repeat("\0", 32), 'receiveKey' => str_repeat("\0", 32)];
    $conns = $ref->getProperty('conns');
    $c = $conns->getValue($node);
    $id = (int) $nodeSide;
    $c[$id] = [
        'sock' => $nodeSide, 'buf' => '', 'phase' => 'established',
        'transport' => new Transport($keys), 'peer' => 'peer',
        'lastInbound' => 0, 'lastData' => 0, 'th' => '',
    ];
    $conns->setValue($node, $c);
    $reg = $ref->getMethod('registerLink');
    $reg->invoke($node, $id, 'peer', true);

    return [$node, $ref, $id, $nodeSide, $peerSide, new Transport($keys)];
}

function tf_readable(object $node, ReflectionClass $ref, $sock): void
{
    $m = $ref->getMethod('onReadable');
    $m->invoke($node, $sock);
}

function tf_conn_present(object $node, ReflectionClass $ref, int $id): bool
{
    $p = $ref->getProperty('conns');
    return isset($p->getValue($node)[$id]);
}

// Reads every frame the node wrote and returns the first bye among them, or null.
// A live node's other traffic must not be mistaken for a close.
function tf_bye($peerSide, Transport $peer): ?array
{
    $buf = '';
    while (($chunk = fread($peerSide, 65536)) !== false && $chunk !== '') {
        $buf .= $chunk;
    }
    foreach (explode("\n", $buf) as $line) {
        if (trim($line) === '') {
            continue;
        }
        $res = Frame::classify($line . "\n", Frame::TRANSPORT_CAP);
        if (isset($res['reason'])) {
            continue;
        }
        $inner = $peer->open($res['obj']);
        if (($inner['type'] ?? null) === 'bye') {
            return $inner;
        }
    }
    return null;
}

test('an out-of-order frame tears the session down, named protocol-error', function () {
    [$node, $ref, $id, $nodeSide, $peerSide, $peer] = tf_setup();
    $peer->seal(['type' => 'probe', 'token' => 1]); // burns seq 0, never written
    $gap = $peer->seal(Message::data('m-gap', 'peer', 'self', 16, ['x' => 1]));
    fwrite($peerSide, json_encode($gap) . "\n");
    tf_readable($node, $ref, $nodeSide);

    $bye = tf_bye($peerSide, $peer);
    assertNotNull($bye, 'the node closed the session without saying why');
    assertEq('protocol-error', $bye['reason'] ?? null, 'wrong close reason');
    assertTrue(!tf_conn_present($node, $ref, $id),
        'the node kept a session whose nonce stream it can never follow again');
});

test('a malformed frame in the established phase tears the session down', function () {
    [$node, $ref, $id, $nodeSide, $peerSide, $peer] = tf_setup();
    fwrite($peerSide, "{ this is not a frame\n");
    tf_readable($node, $ref, $nodeSide);

    $bye = tf_bye($peerSide, $peer);
    assertNotNull($bye, 'a malformed transport frame was silently skipped');
    assertEq('protocol-error', $bye['reason'] ?? null, 'wrong close reason');
    assertTrue(!tf_conn_present($node, $ref, $id),
        'the node kept a session after a frame that is not one JSON object');
});

test('an unterminated oversize frame is refused and named (D21)', function () {
    [$node, $ref, $id, $nodeSide, $peerSide, $peer] = tf_setup();
    // No newline: a peer that never terminates its frame must not be able to make
    // this node buffer unboundedly. The write is interleaved with reads because a
    // socketpair will not accept the whole flood at once and one fread() returns
    // at most 65536 bytes — exactly the cap, so a single pass cannot exceed it.
    // The socketpair will not hold more than the cap at once, and fread() yields
    // one 8 KB stream chunk per call whatever length it is asked for — so the
    // write is resumed between passes of the event loop rather than done up front.
    $flood = str_repeat('x', Frame::TRANSPORT_CAP + 4096);
    for ($i = 0; $i < 64 && tf_conn_present($node, $ref, $id); $i++) {
        if ($flood !== '' && ($wrote = fwrite($peerSide, $flood)) > 0) {
            $flood = substr($flood, $wrote);
        }
        tf_readable($node, $ref, $nodeSide);
    }

    $bye = tf_bye($peerSide, $peer);
    assertNotNull($bye, 'an oversize frame produced no bye at all');
    assertEq('protocol-error', $bye['reason'] ?? null, 'wrong close reason');
    assertTrue(!tf_conn_present($node, $ref, $id),
        'the node kept a session after an oversize frame');
});

// §8 requires ignoring inner types a node does not recognize, so an unknown type
// is NOT a protocol error. This guards the three tests above: making every
// unparseable thing close the link would break forward compatibility.
test('an unrecognized inner type does not close the session', function () {
    [$node, $ref, $id, $nodeSide, $peerSide, $peer] = tf_setup();
    $carrier = $peer->seal(['type' => 'quux-from-the-future', 'mid' => 'm1']);
    fwrite($peerSide, json_encode($carrier) . "\n");
    tf_readable($node, $ref, $nodeSide);

    assertTrue(tf_conn_present($node, $ref, $id),
        'the node closed a session over an inner type it is required to ignore');
    assertNull(tf_bye($peerSide, $peer),
        'the node sent a bye over an inner type it is required to ignore');

    // And the link still carries traffic, rather than merely still being listed.
    $send = $ref->getMethod('sendRaw');
    $send->invoke($node, $id, Message::bye('idle'));
    $echoed = tf_bye($peerSide, $peer);
    assertNotNull($echoed, 'the link survived the unknown type but carried nothing after');
    assertEq('idle', $echoed['reason'] ?? null, 'the peer read a different frame');
});
