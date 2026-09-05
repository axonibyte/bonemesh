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
$f = parse_flags(array_slice($argv, 2));

switch ($mode) {
    case 'keygen':
        $kp = Crypto::mldsa65Generate();
        file_put_contents($f['id-pub'], base64_encode($kp['pub']));
        file_put_contents($f['id-priv'], base64_encode($kp['priv']));
        break;

    case 'listen':
        $node = Node::start(config($f), (int) $f['port']);
        $out = $f['out'];
        $node->onMessage(function ($payload) use ($out) {
            file_put_contents($out, json_encode($payload) . "\n", FILE_APPEND);
        });
        $node->serve(seconds($f));
        $node->kill();
        break;

    case 'connect':
        $node = Node::start(config($f), 0);
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
        usleep(1500000);
        $node->kill();
        break;

    default:
        fwrite(STDERR, "usage: interop_node <keygen|listen|connect> [--flag value ...]\n");
        exit(2);
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
