<?php
// Splitting and reassembly tests (protocol.md §6.1).
//
// Two groups. The first pins the format: a small payload travels whole, a large
// one splits and rebuilds byte-identically, segments are text rather than Base64,
// and cuts land on character boundaries even when every character is multi-byte.
//
// The second pins the bounds, which is the half that had no coverage anywhere
// before 3.3.0 and where the defect was. Each asserts that a hostile message is
// refused AND that refusing it released whatever it claimed: a reassembler that
// rejects a segment but keeps its partial forever is still a leak, and the
// refusal alone cannot show that.
use Bonemesh\Chunk;
use Bonemesh\Message;
use Bonemesh\Reassembler;

const BM_CHUNK_MID = '0123456789abcdef0123456789abcdef';

function bm_blob(int $n): string
{
    $s = '';
    for ($i = 0; $i < $n; $i++) {
        $s .= chr(97 + ($i % 26));
    }
    return $s;
}

function bm_seg(string $mid, int $i, int $n, string $s): array
{
    return Message::dataSegment($mid, 'a', 'b', 16, $i, $n, $s);
}

// ---- format ----

test('a small payload travels whole', function () {
    $payload = ['line' => 'hello'];
    $msgs = Chunk::split(BM_CHUNK_MID, 'a', 'b', 16, $payload);
    assertEq(1, count($msgs));
    assertTrue(!array_key_exists('chunk', $msgs[0]), 'a whole message must not carry chunk');
    assertTrue(!array_key_exists('seg', $msgs[0]), 'a whole message must not carry seg');
    assertEq($payload, $msgs[0]['payload']);
});

test('a large payload splits and reassembles', function () {
    $payload = ['blob' => bm_blob(120000)];
    $msgs = Chunk::split(BM_CHUNK_MID, 'a', 'b', 16, $payload);
    assertTrue(count($msgs) > 1, 'large payload was not split');
    foreach ($msgs as $i => $m) {
        assertEq(null, Message::validate('data', $m), "segment $i failed the data schema");
        assertTrue(!array_key_exists('payload', $m), "segment $i carries a payload");
        assertTrue(is_string($m['seg']), "segment $i is not a string");
        assertTrue(strlen($m['seg']) <= Chunk::MAX_SEGMENT_BYTES, "segment $i is over the pinned maximum");
    }

    $r = new Reassembler();
    for ($i = 0; $i < count($msgs) - 1; $i++) {
        assertEq(null, $r->offer($msgs[$i], 0), 'completed early');
    }
    $done = $r->offer($msgs[count($msgs) - 1], 0);
    assertTrue($done !== null, 'never completed');
    assertEq($payload, $done[0]);
    assertEq(0, $r->inFlight(), 'a completed message stayed buffered');
    assertEq(0, $r->buffered(), 'a completed message stayed counted');
});

test('segments are text, not base64', function () {
    // decision #25: a segment is a slice of the payload's JSON text, so it stays
    // readable through the key-log inspector. Concatenation must reproduce the
    // serialized payload with no decode step.
    $payload = ['blob' => bm_blob(60000)];
    $msgs = Chunk::split(BM_CHUNK_MID, 'a', 'b', 16, $payload);
    $joined = '';
    foreach ($msgs as $m) {
        $joined .= $m['seg'];
    }
    assertEq(json_encode($payload, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE), $joined);
    assertTrue(str_starts_with($msgs[0]['seg'], '{'), 'the first segment should open the payload JSON');
});

test('cuts land on character boundaries', function () {
    // Every character is 3 UTF-8 bytes, so 24000 divides unevenly and a naive byte
    // cut would split one.
    $payload = ['cjk' => str_repeat('日', 40000)];
    $msgs = Chunk::split(BM_CHUNK_MID, 'a', 'b', 16, $payload);
    assertTrue(count($msgs) > 1);
    foreach ($msgs as $i => $m) {
        assertTrue(strlen($m['seg']) <= Chunk::MAX_SEGMENT_BYTES, "segment $i is over the pinned maximum");
        // preg with the /u modifier fails on invalid UTF-8, and needs no mbstring --
        // which this build does not have, and which Chunk deliberately does not use.
        assertTrue(
            preg_match('//u', $m['seg']) === 1,
            "segment $i is not valid UTF-8, so a cut split a character"
        );
    }
    $r = new Reassembler();
    $done = null;
    foreach ($msgs as $m) {
        $done = $r->offer($m, 0);
    }
    assertTrue($done !== null, 'never completed');
    assertEq($payload, $done[0]);
});

test('out-of-order segments still reassemble', function () {
    $payload = ['blob' => bm_blob(120000)];
    $msgs = Chunk::split(BM_CHUNK_MID, 'a', 'b', 16, $payload);
    $r = new Reassembler();
    $done = null;
    foreach (array_reverse($msgs) as $m) {
        $done = $r->offer($m, 0);
    }
    assertTrue($done !== null, 'reverse order never completed');
    assertEq($payload, $done[0]);
});

// ---- bounds ----

test('an absurd chunk count is refused before allocating', function () {
    // The Java reference sized its buffer on the peer's n before validating it, so
    // one frame claiming two billion segments exhausted the heap. Both oracles
    // matter: the offer is refused, AND nothing was retained.
    $r = new Reassembler();
    foreach ([PHP_INT_MAX, 2000000000, 1000000, Chunk::MAX_CHUNKS + 1] as $n) {
        assertEq(null, $r->offer(bm_seg(BM_CHUNK_MID, 0, $n, 'x'), 0), "accepted n=$n");
        assertEq(0, $r->inFlight(), "n=$n was buffered anyway");
        assertEq(0, $r->buffered(), "n=$n was counted anyway");
    }
    // The boundary itself is legal, so this is a bound and not a blanket ban.
    $r->offer(bm_seg(BM_CHUNK_MID, 0, Chunk::MAX_CHUNKS, 'x'), 0);
    assertEq(1, $r->inFlight(), 'the maximum legal chunk count was refused');
});

test('malformed chunk metadata is refused', function () {
    $r = new Reassembler();
    $bad = [];
    $m = bm_seg(BM_CHUNK_MID, 0, 3, 'x');
    $m['chunk'] = '1/3';
    $bad[] = $m;
    $m = bm_seg(BM_CHUNK_MID, 0, 3, 'x');
    $m['chunk'] = ['i' => 'zero', 'n' => 3];
    $bad[] = $m;
    $m = bm_seg(BM_CHUNK_MID, 0, 3, 'x');
    $m['chunk'] = ['i' => 0];
    $bad[] = $m;
    $m = bm_seg(BM_CHUNK_MID, 0, 3, 'x');
    $m['chunk'] = ['i' => 0.5, 'n' => 3];
    $bad[] = $m;
    $bad[] = bm_seg(BM_CHUNK_MID, 3, 3, 'x');
    $bad[] = bm_seg(BM_CHUNK_MID, -1, 3, 'x');
    $bad[] = bm_seg(BM_CHUNK_MID, 0, 0, 'x');
    foreach ($bad as $k => $msg) {
        assertEq(null, $r->offer($msg, 0), "case $k: accepted malformed chunk");
        assertEq(0, $r->inFlight(), "case $k: malformed chunk was buffered");
    }
});

test('a segment without its slice is refused', function () {
    $r = new Reassembler();
    $m = bm_seg(BM_CHUNK_MID, 0, 3, 'x');
    unset($m['seg']);
    assertEq(null, $r->offer($m, 0));
    assertEq(0, $r->inFlight());
});

test('a whole message claiming to be a segment is not delivered', function () {
    $r = new Reassembler();
    $m = bm_seg(BM_CHUNK_MID, 0, 1, '{"a":1}');
    assertEq(null, $r->offer($m, 0), 'delivered a fragment as a whole payload');
    assertEq('payload-or-seg', Message::validate('data', $m));
});

test('a message carrying both payload and segment is not delivered', function () {
    // Found by mutation in the Rust port, then fixed in all seven: the whole-message
    // path returned the payload whenever one was present, so a message contradicting
    // itself was delivered. The schema rejects it, but the schema is not on the wire
    // path (decision #27), so the reassembler has to refuse it too.
    $r = new Reassembler();
    $both = Message::data(BM_CHUNK_MID, 'a', 'b', 16, ['x' => 1]);
    $both['seg'] = '{';
    assertEq(null, $r->offer($both, 0), 'a self-contradicting message was delivered');
    $withChunk = bm_seg(BM_CHUNK_MID, 0, 1, '{');
    $withChunk['payload'] = ['x' => 1];
    assertEq(null, $r->offer($withChunk, 0), 'a self-contradicting n==1 message was delivered');
});

test('a non-object chunk is refused even with a payload', function () {
    // The distinguishing input: a garbage chunk on a message that DOES carry a
    // payload. Java conflated "chunk absent" with "chunk unparseable" and delivered
    // it; nothing tested the case, which is how that survived.
    $r = new Reassembler();
    foreach (['1/3', 7, true] as $garbage) {
        $m = Message::data(BM_CHUNK_MID, 'a', 'b', 16, ['x' => 1]);
        $m['chunk'] = $garbage;
        assertEq(null, $r->offer($m, 0), 'delivered a message with a garbage chunk');
        assertTrue(Message::validate('data', $m) !== null, 'the schema should reject it too');
    }
});

test('concurrent reassemblies are bounded', function () {
    $r = new Reassembler();
    for ($k = 0; $k < Chunk::MAX_CONCURRENT_REASSEMBLIES; $k++) {
        $r->offer(bm_seg(str_pad(dechex($k), 32, '0', STR_PAD_LEFT), 0, 4, 'x'), 0);
    }
    assertEq(Chunk::MAX_CONCURRENT_REASSEMBLIES, $r->inFlight());
    $r->offer(bm_seg(str_repeat('f', 32), 0, 4, 'x'), 0);
    assertEq(Chunk::MAX_CONCURRENT_REASSEMBLIES, $r->inFlight(), 'the bound was exceeded');
});

test('buffered bytes are bounded', function () {
    // The in-flight bound (256) is reached long before 16 MiB of segments can be
    // spread across separate message ids, so the byte budget is only reachable
    // inside one message: 1024 segments of 24000 bytes is 24.5 MB, over the ceiling.
    $r = new Reassembler();
    $full = str_repeat('y', Chunk::MAX_SEGMENT_BYTES);
    $accepted = 0;
    for ($i = 0; $i < Chunk::MAX_CHUNKS; $i++) {
        $r->offer(bm_seg(BM_CHUNK_MID, $i, Chunk::MAX_CHUNKS, $full), 0);
        if ($r->inFlight() === 0) {
            break; // abandoned: the budget refused it
        }
        $accepted++;
        assertTrue($r->buffered() <= Chunk::MAX_REASSEMBLY_BUFFER, 'the buffer maximum was exceeded');
    }
    assertEq(
        intdiv(Chunk::MAX_REASSEMBLY_BUFFER, Chunk::MAX_SEGMENT_BYTES),
        $accepted,
        'the message should be abandoned on the first segment that would not fit'
    );
    assertEq(0, $r->inFlight(), 'the abandoned message was retained');
    assertEq(0, $r->buffered(), 'abandoning did not return its bytes');
});

test('stale partials are swept', function () {
    $r = new Reassembler();
    $r->offer(bm_seg(BM_CHUNK_MID, 0, 3, 'x'), 1000);
    assertEq(1, $r->inFlight());
    $r->offer(bm_seg(BM_CHUNK_MID, 1, 3, 'y'), 1000 + Chunk::REASSEMBLY_TIMEOUT_MILLIS - 1);
    assertEq(1, $r->inFlight(), 'swept too early');
    $r->offer(bm_seg(str_repeat('1', 32), 0, 3, 'z'), 1000 + Chunk::REASSEMBLY_TIMEOUT_MILLIS);
    assertEq(1, $r->inFlight(), 'the stale partial was not swept');
    assertEq(1, $r->buffered(), 'swept bytes were not returned to the budget');
});

test('an oversized payload fails at the origin', function () {
    // §6.1: an origin whose payload no conforming destination would reassemble is
    // told locally rather than emitting it.
    assertThrows(
        fn () => Chunk::split(BM_CHUNK_MID, 'a', 'b', 16, ['blob' => bm_blob(Chunk::MAX_REASSEMBLY_BUFFER + 1)]),
        'an oversized payload was accepted'
    );
});
