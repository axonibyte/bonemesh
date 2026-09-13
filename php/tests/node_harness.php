<?php
// Shared live-node test helpers for the PHP port.
//
// PHP cannot run several nodes in one process, so these drive a node's private
// state through reflection with socketpairs standing in for peers. They used to
// live inside features.test.php, which made them available only to files the
// alphabetical glob in run.php happened to load later -- broadcast.test.php sorts
// first and could not see them. Shared helpers belong in a shared file rather than
// in whichever test happened to need them first.
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
