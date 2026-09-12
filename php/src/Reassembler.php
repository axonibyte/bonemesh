<?php
namespace Bonemesh;

// Rebuilds split payloads at the destination, the counterpart to Chunk::split
// (protocol.md §6.1).
//
// Every §0 bound is enforced BEFORE any allocation keyed on a number the peer
// chose. That ordering is the point: the Java reference sized its buffer on the
// peer's n and validated afterwards, so one frame claiming two billion segments
// exhausted the heap -- defect D7 reintroduced by the feature meant to fix it.
//
// Three bounds, none redundant. The byte budget caps one large message; the
// in-flight count caps a flood of distinct ids each carrying an empty segment,
// which costs nothing against a byte budget and still costs memory; the timeout
// stops an abandoned message pinning memory for the session's life.
final class Reassembler
{
    // mid => ['segments' => [?string], 'received' => int, 'bytes' => int, 'started' => int].
    // PHP arrays keep insertion order, which is what lets the sweep stop early.
    private array $partials = [];

    private int $buffered = 0;

    // Feeds one inbound data message. Returns a one-element array holding the
    // payload when a message completes, or null while it is incomplete or refused.
    // A one-element array rather than the payload itself, because a payload may
    // legitimately be null and PHP cannot otherwise tell "nothing yet" from "the
    // payload is null". $nowMillis is passed in rather than read so the timeout is
    // testable without sleeping.
    public function offer(array $msg, int $nowMillis): ?array
    {
        $this->sweep($nowMillis);

        $hasChunk = array_key_exists('chunk', $msg);
        $chunk = $hasChunk && is_array($msg['chunk']) ? $msg['chunk'] : null;
        if ($hasChunk && $chunk === null) {
            return null; // chunk is present but not an object
        }
        $n = $chunk === null ? 1 : (is_int($chunk['n'] ?? null) ? $chunk['n'] : null);
        if ($hasChunk && $n === null) {
            return null;
        }

        if (!$hasChunk || $n === 1) {
            // A whole message carries payload and no seg. One claiming n === 1 while
            // carrying seg instead is malformed, not a one-segment split -- and so is
            // one carrying both.
            if (array_key_exists('seg', $msg)) {
                return null;
            }
            return array_key_exists('payload', $msg) ? [$msg['payload']] : null;
        }

        // Bounds first, allocation second.
        $i = is_int($chunk['i'] ?? null) ? $chunk['i'] : null;
        if ($i === null || $n < 1 || $n > Chunk::MAX_CHUNKS || $i < 0 || $i >= $n) {
            return null;
        }
        if (!isset($msg['seg']) || !is_string($msg['seg'])) {
            return null; // a segment without its slice
        }
        if (!isset($msg['mid']) || !is_string($msg['mid'])) {
            return null;
        }
        $mid = $msg['mid'];

        if (!isset($this->partials[$mid])) {
            if (count($this->partials) >= Chunk::MAX_CONCURRENT_REASSEMBLIES) {
                return null;
            }
            $this->partials[$mid] = [
                'segments' => array_fill(0, $n, null),
                'received' => 0,
                'bytes' => 0,
                'started' => $nowMillis,
            ];
        } elseif (count($this->partials[$mid]['segments']) !== $n) {
            $this->discard($mid); // the peer changed n mid-message
            return null;
        }

        if ($this->partials[$mid]['segments'][$i] === null) {
            $size = strlen($msg['seg']);
            if ($this->buffered + $size > Chunk::MAX_REASSEMBLY_BUFFER) {
                $this->discard($mid);
                return null;
            }
            $this->partials[$mid]['segments'][$i] = $msg['seg'];
            $this->partials[$mid]['bytes'] += $size;
            $this->partials[$mid]['received']++;
            $this->buffered += $size;
        }
        if ($this->partials[$mid]['received'] !== $n) {
            return null;
        }

        $joined = implode('', $this->partials[$mid]['segments']);
        $this->discard($mid);
        $payload = json_decode($joined, true);
        if ($payload === null && json_last_error() !== JSON_ERROR_NONE) {
            return null; // the segments did not rebuild valid JSON
        }
        return [$payload];
    }

    // Messages currently mid-reassembly. Exposed for the tests that assert the
    // bounds release memory rather than merely refusing to add to it -- a
    // reassembler that rejects a segment but keeps its partial forever is still a
    // leak, and the refusal alone cannot show that.
    public function inFlight(): int
    {
        return count($this->partials);
    }

    // Segment bytes held across every in-flight message.
    public function buffered(): int
    {
        return $this->buffered;
    }

    private function discard(string $mid): void
    {
        if (isset($this->partials[$mid])) {
            $this->buffered -= $this->partials[$mid]['bytes'];
            unset($this->partials[$mid]);
        }
    }

    private function sweep(int $nowMillis): void
    {
        foreach ($this->partials as $mid => $p) {
            if ($nowMillis - $p['started'] < Chunk::REASSEMBLY_TIMEOUT_MILLIS) {
                break; // insertion-ordered: the rest are younger
            }
            $this->buffered -= $p['bytes'];
            unset($this->partials[$mid]);
        }
    }
}
