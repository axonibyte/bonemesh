<?php
// Corpus-driven interop checks for the PHP port: the `framing` subcommand
// confirms the PHP frame classifier reaches the same verdicts as the other
// implementations over spec/corpus/framing.json, and `messages` does the same
// for the message validator over spec/corpus/messages.json. Invoked by
// interop/check-framing-php.sh and interop/check-messages-php.sh.
require __DIR__ . '/../src/autoload.php';

use Bonemesh\Chunk;
use Bonemesh\Frame;
use Bonemesh\Message;

$mode = $argv[1] ?? '';
$path = $argv[2] ?? '';
if ($mode === '' || $path === '') {
    fwrite(STDERR, "usage: interop_checks <framing|messages|chunk> <corpus.json>\n");
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
} elseif ($mode === 'chunk') {
    // Two things, and the second is the one nothing else can see. First the pinned
    // section 0 constants must match this implementation's -- including the three
    // (chunk count, in-flight count, timeout) that specsrc deliberately does not
    // check, because a substring search for 1024, 256 or 30000 is satisfied by any
    // buffer size already in the tree. Second, the segments this implementation
    // produces must land on exactly the byte boundaries the corpus pins, which is how
    // all seven are shown to cut in the SAME places rather than merely to cut.
    $mine = [
        'max_segment_bytes' => Chunk::MAX_SEGMENT_BYTES,
        'max_chunks' => Chunk::MAX_CHUNKS,
        'max_reassembly_buffer' => Chunk::MAX_REASSEMBLY_BUFFER,
        'max_concurrent_reassemblies' => Chunk::MAX_CONCURRENT_REASSEMBLIES,
        'reassembly_timeout_millis' => Chunk::REASSEMBLY_TIMEOUT_MILLIS,
    ];
    if (empty($doc['constants'])) {
        fwrite(STDERR, "corpus declares no chunk constants\n");
        exit(1);
    }
    foreach ($doc['constants'] as $name => $want) {
        $got = $mine[$name] ?? null;
        $ok = $got === $want;
        $report($ok ? "constant $name" : "constant $name  (have $got, corpus pins $want)", $ok);
    }
    if (empty($doc['split_cases'])) {
        fwrite(STDERR, "corpus has no split cases\n");
        exit(1);
    }
    foreach ($doc['split_cases'] as $c) {
        $payload = [$c['key'] => str_repeat($c['unit'], $c['times'])];
        $msgs = Chunk::split($doc['mid'], 'a', 'b', 16, $payload);
        $whole = count($msgs) === 1 && array_key_exists('payload', $msgs[0]);
        $lengths = $whole ? [] : array_map(fn ($m) => strlen($m['seg']), $msgs);
        $ok = $whole === $c['expect_whole'] && $lengths === $c['segment_byte_lengths'];
        $detail = $ok ? '' : sprintf(
            '  (whole=%s want %s; lengths=%s want %s)',
            var_export($whole, true),
            var_export($c['expect_whole'], true),
            implode(',', array_slice($lengths, 0, 8)),
            implode(',', array_slice($c['segment_byte_lengths'], 0, 8))
        );
        // A round-trip as the second oracle: matching lengths would not catch segments
        // that are the right size and the wrong bytes.
        if ($ok && !$whole) {
            $rebuilt = json_decode(implode('', array_column($msgs, 'seg')), true);
            if ($rebuilt !== $payload) {
                $ok = false;
                $detail = '  (segments did not rebuild the payload)';
            }
        }
        $report($c['name'] . $detail, $ok);
    }
    if ($failures === 0) {
        echo "splitting agrees with every pinned constant and cut position\n";
    }
} else {
    fwrite(STDERR, "unknown mode: $mode\n");
    exit(2);
}

if ($failures > 0) {
    exit(1);
}
