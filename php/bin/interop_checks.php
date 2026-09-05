<?php
// Corpus-driven interop checks for the PHP port: the `framing` subcommand
// confirms the PHP frame classifier reaches the same verdicts as the other
// implementations over spec/corpus/framing.json, and `messages` does the same
// for the message validator over spec/corpus/messages.json. Invoked by
// interop/check-framing-php.sh and interop/check-messages-php.sh.
require __DIR__ . '/../src/autoload.php';

use Bonemesh\Frame;
use Bonemesh\Message;

$mode = $argv[1] ?? '';
$path = $argv[2] ?? '';
if ($mode === '' || $path === '') {
    fwrite(STDERR, "usage: interop_checks <framing|messages> <corpus.json>\n");
    exit(2);
}
$doc = json_decode(file_get_contents($path), true);
$failures = 0;
$report = function (string $name, bool $ok) use (&$failures) {
    echo ($ok ? 'PASS ' : 'FAIL ') . "$name\n";
    if (!$ok) {
        $failures++;
    }
};

if ($mode === 'framing') {
    foreach ($doc['cases'] as $c) {
        $cap = ($c['kind'] ?? '') === 'handshake' ? Frame::HANDSHAKE_CAP : Frame::TRANSPORT_CAP;
        $res = Frame::classify(base64_decode($c['bytes_b64'], true), $cap);
        $ok = $c['expect'] === 'accept'
            ? !isset($res['reason'])
            : (($res['reason'] ?? null) === ($c['reason'] ?? null));
        $report($c['name'], $ok);
    }
    echo 'framing: ' . count($doc['cases']) . " cases checked\n";
} elseif ($mode === 'messages') {
    foreach ($doc['cases'] as $c) {
        $reason = Message::validate($c['schema'], $c['frame']);
        $ok = $c['expect'] === 'valid'
            ? $reason === null
            : $reason === ($c['reason'] ?? null);
        $report($c['name'], $ok);
    }
    echo 'messages: ' . count($doc['cases']) . " cases checked\n";
} else {
    fwrite(STDERR, "unknown mode: $mode\n");
    exit(2);
}

if ($failures > 0) {
    exit(1);
}
