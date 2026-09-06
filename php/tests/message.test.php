<?php
// Message-schema validation tests. Reason tags mirror the shared corpus
// (spec/corpus/messages.json). Byte-for-byte agreement is checked by
// bin/interop_checks.php.
use Bonemesh\Message;

const MID = '0123456789abcdef0123456789abcdef';

test('schema verdicts', function () {
    $cases = [
        ['bmx1', ['t' => 'bmx1', 'v' => 3, 'mesh' => 'm', 'e' => 'AA==', 'k' => 'AA==', 'n' => 'AA=='], null],
        ['bmx1', ['t' => 'nope', 'v' => 3, 'mesh' => 'm', 'e' => 'AA==', 'k' => 'AA==', 'n' => 'AA=='], 'type'],
        ['bmx1', ['t' => 'bmx1', 'v' => 2, 'mesh' => 'm', 'e' => 'AA==', 'k' => 'AA==', 'n' => 'AA=='], 'version'],
        ['bmx1', ['t' => 'bmx1', 'v' => 3, 'mesh' => '', 'e' => 'AA==', 'k' => 'AA==', 'n' => 'AA=='], 'empty-mesh'],
        ['bmx1', ['t' => 'bmx1', 'v' => 3, 'mesh' => 'm', 'k' => 'AA==', 'n' => 'AA=='], 'missing-field'],
        ['bmx1', ['t' => 'bmx1', 'v' => 3, 'mesh' => 'm', 'e' => '!!!', 'k' => 'AA==', 'n' => 'AA=='], 'not-base64'],

        ['envelope', ['seq' => 0, 'ct' => 'AA=='], null],
        ['envelope', ['ct' => 'AA=='], 'missing-field'],
        ['envelope', ['seq' => -1, 'ct' => 'AA=='], 'seq-range'],
        ['envelope', ['seq' => 0, 'ct' => '@@@@'], 'not-base64'],

        ['data', ['type' => 'data', 'mid' => MID, 'to' => 'b', 'from' => 'a', 'ttl' => 16, 'payload' => []], null],
        ['data', ['type' => 'x', 'mid' => MID, 'to' => 'b', 'from' => 'a', 'ttl' => 16, 'payload' => []], 'type'],
        ['data', ['type' => 'data', 'mid' => 'short', 'to' => 'b', 'from' => 'a', 'ttl' => 16, 'payload' => []], 'mid-format'],
        ['data', ['type' => 'data', 'mid' => MID, 'from' => 'a', 'ttl' => 16, 'payload' => []], 'missing-field'],
        ['data', ['type' => 'data', 'mid' => MID, 'to' => 'b', 'from' => 'a', 'ttl' => 0, 'payload' => []], 'ttl-range'],
        ['data', ['type' => 'data', 'mid' => MID, 'to' => 'b', 'from' => 'a', 'ttl' => 256, 'payload' => []], 'ttl-range'],

        ['ack', ['type' => 'ack', 'mid' => MID], null],
        ['ack', ['type' => 'nack', 'mid' => MID], 'type'],
        ['ack', ['type' => 'ack', 'mid' => 'NOTHEX0000000000000000000000000x'], 'mid-format'],

        ['nak', ['type' => 'nak', 'mid' => MID, 'hop' => 'b', 'reason' => 'ttl', 'to' => 'a', 'from' => 'b', 'ttl' => 16], null],
        ['nak', ['type' => 'nak', 'mid' => MID, 'hop' => 'b', 'reason' => 'anything-new', 'to' => 'a', 'from' => 'b', 'ttl' => 16], null],
        ['nak', ['type' => 'data', 'mid' => MID, 'hop' => 'b', 'reason' => 'ttl', 'to' => 'a', 'from' => 'b', 'ttl' => 16], 'type'],
        ['nak', ['type' => 'nak', 'mid' => 'short', 'hop' => 'b', 'reason' => 'ttl', 'to' => 'a', 'from' => 'b', 'ttl' => 16], 'mid-format'],
        ['nak', ['type' => 'nak', 'mid' => MID, 'reason' => 'ttl', 'to' => 'a', 'from' => 'b', 'ttl' => 16], 'missing-field'],
        ['nak', ['type' => 'nak', 'mid' => MID, 'hop' => 'b', 'to' => 'a', 'from' => 'b', 'ttl' => 16], 'missing-field'],
        ['nak', ['type' => 'nak', 'mid' => MID, 'hop' => 'b', 'reason' => 'ttl', 'to' => 'a', 'from' => 'b', 'ttl' => 0], 'ttl-range'],

        ['bye', ['type' => 'bye', 'reason' => 'idle'], null],
        ['bye', ['type' => 'bye'], null],
        ['bye', ['type' => 'bye', 'reason' => 'anything-new'], null],
        ['bye', ['type' => 'data'], 'type'],

        ['mystery', [], 'unknown-schema'],
    ];
    foreach ($cases as [$schema, $msg, $want]) {
        assertEq($want, Message::validate($schema, $msg), "$schema " . json_encode($msg));
    }
});

test('builders produce valid messages', function () {
    assertNull(Message::validate('data', Message::data(Message::newMid(), 'a', 'b', Message::DEFAULT_TTL, ['k' => 'v'])));
    assertNull(Message::validate('ack', Message::ack(Message::newMid())));
    assertNull(Message::validate('nak', Message::nak(Message::newMid(), 'a', 'b', 'beta', 'ttl', Message::DEFAULT_TTL)));
    assertNull(Message::validate('bye', Message::bye('idle')));
    assertNull(Message::validate('bye', Message::bye()));
});

test('newMid is well-formed and unique', function () {
    $seen = [];
    for ($i = 0; $i < 1000; $i++) {
        $id = Message::newMid();
        assertEq(1, preg_match('#^[0-9a-f]{32}$#', $id));
        assertTrue(!isset($seen[$id]));
        $seen[$id] = true;
    }
});
