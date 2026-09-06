<?php
// The PHP driver for the language-agnostic interop harness (interop/).
// Implements the neutral driver contract (keygen / listen / connect) over
// shared, implementation-independent key and certificate files, so the harness
// pairs it with any other driver. The node private key is stored as opaque
// base64(PEM); it never crosses a node boundary, so its format is this driver's.
require __DIR__ . '/../src/autoload.php';

use Bonemesh\Crypto;
use Bonemesh\Node;

$mode = $argv[1] ?? '';

if ($mode === 'caps') {
    // Feature tokens the harness health-probes to gate tier-10 scenarios. PHP
    // cannot capture its own wire stream in-process, so it omits 'capture'.
    echo "ack nak rekey idle probe-death dial-tiebreak keylog sessions acks\n";
    exit(0);
}

$f = parse_flags(array_slice($argv, 2));

switch ($mode) {
    case 'keygen':
        $kp = Crypto::mldsa65Generate();
        file_put_contents($f['id-pub'], base64_encode($kp['pub']));
        file_put_contents($f['id-priv'], base64_encode($kp['priv']));
        break;

    case 'listen':
        $node = Node::start(config($f), (int) $f['port']);
        observe($node, $f);
        $out = $f['out'];
        $node->onMessage(function ($payload) use ($out) {
            file_put_contents($out, json_encode($payload) . "\n", FILE_APPEND);
        });
        $node->serve(seconds($f), function (Node $n) use ($f) {
            dump_sessions($n, $f);
        });
        $node->kill();
        break;

    case 'connect':
        $node = Node::start(config($f), 0);
        observe($node, $f);
        try {
            $node->connect($f['host'], (int) $f['port']);
        } catch (\Throwable $e) {
            fwrite(STDERR, 'connect: ' . $e->getMessage() . "\n");
            exit(1);
        }
        $payload = json_decode(file_get_contents($f['message']), true);
        $deadline = microtime(true) + seconds($f);
        while (microtime(true) < $deadline) {
            if ($node->send($f['to'], $payload)) {
                break;
            }
            usleep(200000);
        }
        // Stay up briefly, pumping the loop so acks/naks and the session dump
        // are observed on this single-threaded node.
        $node->serve(1.5, function (Node $n) use ($f) {
            dump_sessions($n, $f);
        });
        $node->kill();
        break;

    // The multi-link mode for the convergence tier: dial several --peers
    // (host:port,host:port), optionally log delivered payloads (--out), send
    // toward a routed destination (--send-to with --message), and periodically
    // dump the routing table (--routes). Stays up for --seconds.
    case 'mesh':
        $node = Node::start(config($f), (int) ($f['port'] ?? 0));
        observe($node, $f);
        if (isset($f['out'])) {
            $out = $f['out'];
            $node->onMessage(function ($payload) use ($out) {
                file_put_contents($out, json_encode($payload) . "\n", FILE_APPEND);
            });
        }
        foreach (array_filter(explode(',', $f['peers'] ?? '')) as $peer) {
            $c = strrpos($peer, ':');
            $node->connect(substr($peer, 0, $c), (int) substr($peer, $c + 1));
        }
        $payload = isset($f['message']) ? json_decode(file_get_contents($f['message']), true) : null;
        $node->serve(seconds($f), function (Node $n) use ($f, $payload) {
            if (isset($f['send-to']) && $payload !== null) {
                $n->send($f['send-to'], $payload);
            }
            if (isset($f['routes'])) {
                file_put_contents($f['routes'], json_encode($n->routeTable()));
            }
            dump_sessions($n, $f);
        });
        $node->kill();
        break;

    default:
        fwrite(STDERR, "usage: interop_node <keygen|listen|connect|mesh> [--flag value ...]\n");
        exit(2);
}

// observe wires --acks: append each received ack/nak inner as one JSON line.
function observe(Node $node, array $f): void
{
    if (isset($f['acks'])) {
        $acks = $f['acks'];
        $node->onAck(function ($inner) use ($acks) {
            file_put_contents($acks, json_encode($inner) . "\n", FILE_APPEND);
        });
    }
}

// dump_sessions writes the --sessions snapshot (peer => {epoch, th}).
function dump_sessions(Node $node, array $f): void
{
    if (isset($f['sessions'])) {
        file_put_contents($f['sessions'], json_encode($node->sessionInfo()));
    }
}

function config(array $f): array
{
    $cert = json_decode(file_get_contents($f['cert']), true);
    return [
        'label' => $cert['label'],
        'mesh' => $f['mesh'],
        'rootPublic' => base64_decode(trim(file_get_contents($f['root-pub'])), true),
        'cert' => $cert,
        'idPrivate' => base64_decode(trim(file_get_contents($f['id-priv'])), true),
    ];
}

function parse_flags(array $args): array
{
    $m = [];
    for ($i = 0; $i + 1 < count($args); $i += 2) {
        if (str_starts_with($args[$i], '--')) {
            $m[substr($args[$i], 2)] = $args[$i + 1];
        }
    }
    return $m;
}

function seconds(array $f): float
{
    return isset($f['seconds']) ? (float) $f['seconds'] : 10.0;
}
