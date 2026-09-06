<?php
namespace Bonemesh;

// A BoneMesh v3 mesh node (protocol.md §3, §5) over TCP: one authenticated,
// encrypted session per neighbor. It routes — distance-vector discovery over a
// 1 s heartbeat (probe/echo for link latency, disco for route advertisement
// with poisoned reverse), relays data toward a next hop with TTL, and delivers
// payloads addressed to itself, deduping by message id. Wire-compatible with
// the Java, Elixir, Rust, Go, and JS implementations.
//
// PHP is synchronous, so incoming connections are driven by a stream_select
// loop (serve); the initiator side completes its handshake with blocking reads
// in connect(). Either way a connection runs one frame at a time, so there is no
// shared-state race to guard.
final class Node
{
    /** @var resource|null */
    private $server = null;
    /** @var array<int, array> keyed by socket resource id */
    private array $conns = [];
    /** @var array<string, int> lowercase label -> socket id */
    private array $links = [];
    /** @var callable[] */
    private array $listeners = [];
    /** @var callable[] invoked with each ack/nak addressed to this node */
    private array $ackListeners = [];
    /** @var array<string, array<int, array>> lowercase dest -> pending retries (F2) */
    private array $pending = [];
    private RoutingTable $table;
    private Dedup $dedup;
    private array $tun;
    private float $lastHeartbeat = 0.0;

    public function __construct(private array $cfg)
    {
        $this->table = new RoutingTable($cfg['label']);
        $this->dedup = new Dedup(4096);
        $this->tun = Tunables::load();
    }

    // A snapshot of learned destinations to their next hop.
    public function routeTable(): array
    {
        return $this->table->routeTable();
    }

    public static function start(array $cfg, int $port): self
    {
        $node = new self($cfg);
        $server = @stream_socket_server("tcp://0.0.0.0:$port", $errno, $errstr);
        if ($server === false) {
            throw new \RuntimeException("listen failed: $errstr ($errno)");
        }
        stream_set_blocking($server, false);
        $node->server = $server;
        return $node;
    }

    public function port(): int
    {
        $name = stream_socket_get_name($this->server, false);
        return (int) substr($name, strrpos($name, ':') + 1);
    }

    public function onMessage(callable $cb): void
    {
        $this->listeners[] = $cb;
    }

    public function connect(string $host, int $port): string
    {
        $sock = @stream_socket_client("tcp://$host:$port", $errno, $errstr, 5.0);
        if ($sock === false) {
            throw new \RuntimeException("connect failed: $errstr ($errno)");
        }
        $hs = Handshake::initiator($this->cfg['mesh'], $this->cfg['rootPublic'], self::now(), $this->cfg['cert'], $this->cfg['idPrivate']);
        fwrite($sock, $hs->writeMessage1());
        $m2 = self::readFrameBlocking($sock, Frame::HANDSHAKE_CAP);
        fwrite($sock, $hs->readMessage2WriteMessage3($m2));
        $sess = $hs->session();
        $peer = $sess['peerCert']['label'];
        stream_set_blocking($sock, false);
        $id = (int) $sock;
        $this->conns[$id] = ['sock' => $sock, 'buf' => '', 'phase' => 'established', 'transport' => new Transport($sess), 'peer' => $peer, 'th' => substr(bin2hex($sess['h']), 0, 16)];
        $this->registerLink($id, $peer, true);
        if (isset($this->conns[$id])) {
            $this->writeKeylog(0, true, $sess);
        }
        return $peer;
    }

    // Records a newly-established link (protocol.md §3): stamps who initiated
    // the connection and the liveness/idle clocks, applies the simultaneous-dial
    // tiebreak, and seeds the neighbor as routable.
    //
    // On a collision with an existing link for the same peer: if both were
    // initiated by the same side it is a reconnect (last writer wins, displacing
    // the old); if by opposite sides it is a genuine dial collision, and both
    // ends deterministically keep the session initiated by the
    // lexicographically-lower label so the pair converges on one session — the
    // loser is closed. Closing the displaced/losing conn is safe because
    // closeConn withdraws routes only when the links entry still points at the
    // closing id, so it cannot clobber the surviving link.
    private function registerLink(int $id, string $peer, bool $initiator): void
    {
        $now = self::nowMs();
        $this->conns[$id]['initiator'] = $initiator;
        $this->conns[$id]['establishedAt'] = $now;
        $this->conns[$id]['lastInbound'] = $now;
        $this->conns[$id]['lastData'] = $now;

        $key = strtolower($peer);
        $prev = $this->links[$key] ?? null;
        $keepNew = true;
        if ($prev !== null && $prev !== $id && isset($this->conns[$prev])
            && ($this->conns[$prev]['initiator'] ?? null) !== $initiator) {
            $selfWins = strtolower($this->cfg['label']) < $key;
            $keepNew = ($initiator === $selfWins);
        }

        if (!$keepNew) {
            // This new link lost the tiebreak; drop it and keep the existing one.
            @fclose($this->conns[$id]['sock']);
            unset($this->conns[$id]);
            return;
        }

        $this->links[$key] = $id;
        if ($prev !== null && $prev !== $id && isset($this->conns[$prev])) {
            @fclose($this->conns[$prev]['sock']);
            unset($this->conns[$prev]);
        }
        $this->table->observeNeighbor($peer, 1); // optimistic seed
    }

    // Routes an application payload toward any reachable destination. Returns
    // true if the message was handed to a next hop this instant; otherwise it is
    // queued for bounded retry (F2) when retry is enabled.
    public function send(string $to, $payload): bool
    {
        [, $ok] = $this->sendInternal($to, $payload);
        return $ok;
    }

    // send that also returns the message id, so a caller can correlate the
    // ack/nak delivered to an onAck listener (protocol.md §7). The mid is always
    // returned, even when there is no route yet (the message is queued for retry).
    public function sendMid(string $to, $payload): ?string
    {
        [$mid, ] = $this->sendInternal($to, $payload);
        return $mid;
    }

    /** @return array{0:string,1:bool} the mid and whether it was handed to a next hop now */
    private function sendInternal(string $to, $payload): array
    {
        $mid = Message::newMid();
        $msg = Message::data($mid, $this->cfg['label'], $to, Message::DEFAULT_TTL, $payload);
        $nh = $this->table->nextHop($to);
        $ok = $nh !== null && $this->sendToLink($nh, $msg);
        if (!$ok) {
            $this->enqueueRetry($msg);
        }
        return [$mid, $ok];
    }

    // Queues an origin data message for later retry, bounded to 64 per
    // destination. A no-op when retry is disabled (retryMaxMs === 0).
    private function enqueueRetry(array $inner): void
    {
        if (($this->tun['retryMaxMs'] ?? 0) <= 0) {
            return;
        }
        $to = strtolower((string) ($inner['to'] ?? ''));
        $now = self::nowMs();
        $q = $this->pending[$to] ?? [];
        if (count($q) >= 64) {
            return; // bounded: one unreachable destination cannot grow without limit
        }
        $q[] = ['inner' => $inner, 'enqueuedAt' => $now, 'nextAt' => $now + $this->tun['retryBaseMs'], 'delay' => $this->tun['retryBaseMs']];
        $this->pending[$to] = $q;
    }

    // Re-attempts due pending sends once per heartbeat: a landed message is
    // dropped, a stuck one backs off (delay doubles to the cap), and one past
    // its lifetime is dropped and reported to the origin's ack listeners as a
    // synthesized nak{reason:"expired"} (never on the wire).
    private function drainRetries(int $nowMs): void
    {
        foreach ($this->pending as $dest => $q) {
            $kept = [];
            foreach ($q as $p) {
                if ($nowMs < $p['nextAt']) {
                    $kept[] = $p;
                    continue;
                }
                $to = (string) ($p['inner']['to'] ?? '');
                $nh = $this->table->nextHop($to);
                $delivered = $nh !== null && $this->sendToLink($nh, $p['inner']);
                $expired = $nowMs - $p['enqueuedAt'] > $this->tun['retryMaxMs'];
                if ($delivered || $expired) {
                    if (!$delivered && $expired) {
                        $mid = (string) ($p['inner']['mid'] ?? '');
                        foreach ($this->ackListeners as $cb) {
                            $cb(['type' => 'nak', 'mid' => $mid, 'hop' => $this->cfg['label'],
                                'reason' => 'expired', 'to' => $this->cfg['label'],
                                'from' => $this->cfg['label'], 'ttl' => Message::DEFAULT_TTL]);
                        }
                    }
                    continue; // drop
                }
                $p['delay'] = min($p['delay'] * 2, $this->tun['retryCapMs']);
                $p['nextAt'] = $nowMs + $p['delay'];
                $kept[] = $p;
            }
            if (empty($kept)) {
                unset($this->pending[$dest]);
            } else {
                $this->pending[$dest] = $kept;
            }
        }
    }

    // Registers a callback invoked with each ack/nak addressed to this node.
    public function onAck(callable $cb): void
    {
        $this->ackListeners[] = $cb;
    }

    // A snapshot of live sessions: peer => {epoch, th}. th is a short transcript-
    // hash prefix both ends agree on; epoch advances on rekey. The interop
    // harness dumps this via --sessions.
    public function sessionInfo(): array
    {
        $out = [];
        foreach ($this->links as $peer => $id) {
            if (!isset($this->conns[$id])) {
                continue;
            }
            $out[$peer] = [
                'epoch' => $this->conns[$id]['rekeyEpoch'] ?? 0,
                'th' => $this->conns[$id]['th'] ?? '',
            ];
        }
        return $out;
    }

    // writeKeylog appends this session's directional transport keys to the file
    // named by BONEMESH_KEYLOG, in the pinned cross-language format (security.md
    // §8): BMX3_I2R_TRAFFIC_<epoch> <hex transcript-hash> <hex key> and the R2I
    // line. A no-op unless the env is set; logs a loud warning per session.
    private function writeKeylog(int $epoch, bool $initiator, array $sess): void
    {
        $path = $this->tun['keylogPath'] ?? '';
        if ($path === '') {
            return;
        }
        $i2r = $sess['sendKey'];
        $r2i = $sess['receiveKey'];
        if (!$initiator) {
            $i2r = $sess['receiveKey'];
            $r2i = $sess['sendKey'];
        }
        $th = bin2hex($sess['h']);
        $line = fn(string $dir, string $key): string =>
            sprintf("BMX3_%s_TRAFFIC_%d %s %s\n", $dir, $epoch, $th, bin2hex($key));
        file_put_contents($path, $line('I2R', $i2r) . $line('R2I', $r2i), FILE_APPEND);
        if ($epoch === 0) {
            fwrite(STDERR, "WARNING: BONEMESH_KEYLOG is on; transport keys written to $path — forward secrecy is defeated for anyone holding that file\n");
        }
    }

    // send with an explicit initial TTL; used by tests to force a relay to
    // exhaust the hop limit and emit a NAK.
    private function sendWithTtl(string $to, $payload, int $ttl): ?string
    {
        $mid = Message::newMid();
        $nh = $this->table->nextHop($to);
        if ($nh !== null) {
            $this->sendToLink($nh, Message::data($mid, $this->cfg['label'], $to, $ttl, $payload));
        }
        return $mid;
    }

    private function sendToLink(string $label, array $inner): bool
    {
        $id = $this->links[strtolower($label)] ?? null;
        if ($id === null || !isset($this->conns[$id])) {
            return false;
        }
        if (($inner['type'] ?? null) === 'data') {
            $this->conns[$id]['lastData'] = self::nowMs();
        }
        $frame = Frame::encode($this->conns[$id]['transport']->seal($inner));
        return @fwrite($this->conns[$id]['sock'], $frame) !== false;
    }

    // Run the accept/read loop for $seconds. Fires a 1 s heartbeat (probe +
    // per-neighbor route advertisement) and, if given, an ~0.5 s $tick callback
    // (used by the mesh mode to send and dump routes) — all on this one loop.
    public function serve(float $seconds, ?callable $tick = null): void
    {
        $deadline = microtime(true) + $seconds;
        $lastTick = 0.0;
        while (microtime(true) < $deadline) {
            $read = [];
            if ($this->server !== null) {
                $read[] = $this->server;
            }
            foreach ($this->conns as $conn) {
                $read[] = $conn['sock'];
            }
            $write = null;
            $except = null;
            $n = @stream_select($read, $write, $except, 0, 200000);
            if ($n !== false) {
                foreach ($read as $r) {
                    if ($this->server !== null && $r === $this->server) {
                        $this->accept();
                    } else {
                        $this->onReadable($r);
                    }
                }
            }
            $now = microtime(true);
            if ($now - $this->lastHeartbeat >= 1.0) {
                $this->heartbeat();
                $this->drainRetries(self::nowMs());
                $this->lastHeartbeat = $now;
            }
            if ($tick !== null && $now - $lastTick >= 0.5) {
                $tick($this);
                $lastTick = $now;
            }
        }
    }

    private function heartbeat(): void
    {
        $nowMs = self::nowMs();
        // Snapshot the ids first: sweepConn may close (unset) a conn mid-sweep.
        foreach (array_keys($this->conns) as $id) {
            if ($this->sweepConn($id)) {
                $this->maybeRekey($id, $nowMs);
            }
        }
    }

    // Once-per-heartbeat maintenance for one established link: tear it down if
    // it is probe-timeout dead (F3) or data-idle past the idle timeout (F4,
    // disabled at idleMs==0), otherwise send it a probe and a route
    // advertisement. Returns true if the link was kept.
    private function sweepConn(int $id): bool
    {
        $conn = $this->conns[$id] ?? null;
        if ($conn === null || ($conn['phase'] ?? '') !== 'established') {
            return false;
        }
        $now = self::nowMs();
        if ($now - ($conn['lastInbound'] ?? $now) > $this->tun['probeTimeoutMs']) {
            $this->closeConn($id);
            return false;
        }
        if ($this->tun['idleMs'] > 0 && $now - ($conn['lastData'] ?? $now) > $this->tun['idleMs']) {
            $this->sendRaw($id, Message::bye('idle'));
            $this->closeConn($id);
            return false;
        }
        $this->sendRaw($id, Message::probe($now));
        $this->sendRaw($id, Message::disco($this->table->advertiseTo($conn['peer'])));
        return true;
    }

    // F5: drives the initiator side of a periodic rekey. Abandons a stalled
    // pre-swap handshake at the rekey timeout (keeping the old keys — the safe
    // degrade against a peer that does not understand rekey), and otherwise, on
    // the session initiator only, starts a fresh BMX when the frame count or
    // session age crosses the threshold. Single-threaded, so seal-then-swap is
    // naturally atomic against other sends.
    private function maybeRekey(int $id, int $nowMs): void
    {
        $conn = $this->conns[$id] ?? null;
        if ($conn === null) {
            return;
        }
        if (($conn['rekeyHs'] ?? null) !== null) {
            if ($nowMs - ($conn['rekeyStartedAt'] ?? 0) > $this->tun['rekeyTimeoutMs']) {
                $this->conns[$id]['rekeyHs'] = null; // no swap yet; old keys stand
            }
            return;
        }
        if (($conn['rekeySession'] ?? null) !== null) {
            return; // swapped send, awaiting phase 4
        }
        if (!($conn['initiator'] ?? false)) {
            return; // only the session initiator drives rekey
        }
        $t = $conn['transport'];
        $due = $t->sendSeq() >= $this->tun['rekeyFrames']
            || $t->receiveSeq() >= $this->tun['rekeyFrames']
            || $nowMs - ($conn['establishedAt'] ?? $nowMs) >= $this->tun['rekeyMs'];
        if (!$due) {
            return;
        }
        $hs = Handshake::initiator($this->cfg['mesh'], $this->cfg['rootPublic'], self::now(), $this->cfg['cert'], $this->cfg['idPrivate']);
        $mid = Message::newMid();
        $this->sendRaw($id, ['type' => 'rekey', 'mid' => $mid, 'phase' => 1, 'body' => base64_encode($hs->writeMessage1())]);
        $this->conns[$id]['rekeyHs'] = $hs;
        $this->conns[$id]['rekeyMid'] = $mid;
        $this->conns[$id]['rekeyStartedAt'] = $nowMs;
    }

    // Advances the tunneled-BMX rekey state machine (protocol.md §5 /
    // security.md §6). BMX messages ride inside transport frames (body is the
    // base64 of the framed bmx line), so they arrive through the normal reader;
    // each side swaps its send key right after sealing its last old-key frame
    // and its receive key right after opening the peer's. A handshake error
    // abandons the rekey and keeps the old keys rather than tearing the link.
    private function handleRekey(int $id, array $msg): void
    {
        if (!isset($this->conns[$id])) {
            return;
        }
        $phase = (int) ($msg['phase'] ?? 0);
        $mid = (string) ($msg['mid'] ?? '');
        $bodyArr = isset($msg['body']) ? json_decode(trim((string) base64_decode($msg['body'], true)), true) : null;
        $t = $this->conns[$id]['transport'];
        try {
            switch ($phase) {
                case 1: // responder: accept the fresh bmx1, reply bmx2
                    $hs = Handshake::responder($this->cfg['mesh'], $this->cfg['rootPublic'], self::now(), $this->cfg['cert'], $this->cfg['idPrivate']);
                    $m2 = $hs->readMessage1WriteMessage2($bodyArr);
                    $this->conns[$id]['rekeyHs'] = $hs;
                    $this->conns[$id]['rekeyMid'] = $mid;
                    $this->conns[$id]['rekeyStartedAt'] = self::nowMs();
                    $this->sendRaw($id, ['type' => 'rekey', 'mid' => $mid, 'phase' => 2, 'body' => base64_encode($m2)]);
                    break;
                case 2: // initiator: finish with bmx3, then swap send
                    $hs = $this->conns[$id]['rekeyHs'] ?? null;
                    if ($hs === null) {
                        return;
                    }
                    $m3 = $hs->readMessage2WriteMessage3($bodyArr);
                    $sess = $hs->session();
                    $this->sendRaw($id, ['type' => 'rekey', 'mid' => $mid, 'phase' => 3, 'body' => base64_encode($m3)]);
                    $t->swapSend($sess['sendKey']); // last old-key frame sent above
                    $this->conns[$id]['rekeySession'] = $sess;
                    $this->conns[$id]['rekeyHs'] = null;
                    break;
                case 3: // responder: verify bmx3, swap receive, send phase 4, swap send
                    $hs = $this->conns[$id]['rekeyHs'] ?? null;
                    if ($hs === null) {
                        return;
                    }
                    $hs->readMessage3($bodyArr);
                    $sess = $hs->session();
                    $t->swapReceive($sess['receiveKey']); // phase-3 frame was the last old-key inbound
                    $this->sendRaw($id, ['type' => 'rekey', 'mid' => $mid, 'phase' => 4]);
                    $t->swapSend($sess['sendKey']);
                    $this->conns[$id]['rekeyHs'] = null;
                    $this->conns[$id]['rekeyEpoch'] = ($this->conns[$id]['rekeyEpoch'] ?? 0) + 1;
                    $this->conns[$id]['th'] = substr(bin2hex($sess['h']), 0, 16);
                    $this->writeKeylog($this->conns[$id]['rekeyEpoch'], $this->conns[$id]['initiator'] ?? false, $sess);
                    break;
                case 4: // initiator: swap receive; rekey complete
                    $sess = $this->conns[$id]['rekeySession'] ?? null;
                    if ($sess === null) {
                        return;
                    }
                    $t->swapReceive($sess['receiveKey']);
                    $this->conns[$id]['rekeySession'] = null;
                    $this->conns[$id]['rekeyEpoch'] = ($this->conns[$id]['rekeyEpoch'] ?? 0) + 1;
                    $this->conns[$id]['th'] = substr(bin2hex($sess['h']), 0, 16);
                    $this->writeKeylog($this->conns[$id]['rekeyEpoch'], $this->conns[$id]['initiator'] ?? false, $sess);
                    break;
            }
        } catch (\Throwable $e) {
            // Abandon a failed rekey, keeping whatever keys are current.
            $this->conns[$id]['rekeyHs'] = null;
            $this->conns[$id]['rekeySession'] = null;
        }
    }

    private function sendRaw(int $id, array $inner): void
    {
        if (isset($this->conns[$id])) {
            @fwrite($this->conns[$id]['sock'], Frame::encode($this->conns[$id]['transport']->seal($inner)));
        }
    }

    public function kill(): void
    {
        if ($this->server !== null) {
            fclose($this->server);
            $this->server = null;
        }
        foreach ($this->conns as $conn) {
            @fclose($conn['sock']);
        }
        $this->conns = [];
    }

    private function accept(): void
    {
        $sock = @stream_socket_accept($this->server, 0);
        if ($sock === false) {
            return;
        }
        stream_set_blocking($sock, false);
        $hs = Handshake::responder($this->cfg['mesh'], $this->cfg['rootPublic'], self::now(), $this->cfg['cert'], $this->cfg['idPrivate']);
        $this->conns[(int) $sock] = ['sock' => $sock, 'buf' => '', 'phase' => 'resp_m1', 'hs' => $hs, 'transport' => null];
    }

    /** @param resource $sock */
    private function onReadable($sock): void
    {
        $id = (int) $sock;
        $data = @fread($sock, 65536);
        if ($data === '' || $data === false) {
            $this->closeConn($id);
            return;
        }
        $this->conns[$id]['buf'] .= $data;
        while (isset($this->conns[$id]) && ($nl = strpos($this->conns[$id]['buf'], "\n")) !== false) {
            $line = substr($this->conns[$id]['buf'], 0, $nl + 1);
            $this->conns[$id]['buf'] = substr($this->conns[$id]['buf'], $nl + 1);
            $cap = $this->conns[$id]['phase'] === 'established' ? Frame::TRANSPORT_CAP : Frame::HANDSHAKE_CAP;
            $res = Frame::classify($line, $cap);
            if (isset($res['reason'])) {
                if ($this->conns[$id]['phase'] !== 'established') {
                    $this->closeConn($id);
                    return;
                }
                continue; // ignore an unparseable transport frame
            }
            try {
                $this->process($sock, $id, $res['obj']);
            } catch (\Throwable $e) {
                $this->closeConn($id);
                return;
            }
        }
    }

    // Closes a connection and withdraws routes through it — but only if this
    // conn is still the current link for its peer. A reconnect may have replaced
    // it, and a stale conn's death must not withdraw the live link's routes.
    private function closeConn(int $id): void
    {
        if (!isset($this->conns[$id])) {
            return;
        }
        $peer = $this->conns[$id]['peer'] ?? null;
        @fclose($this->conns[$id]['sock']);
        unset($this->conns[$id]);
        if ($peer !== null && ($this->links[strtolower($peer)] ?? null) === $id) {
            unset($this->links[strtolower($peer)]);
            $this->table->removeNeighbor($peer);
        }
    }

    /** @param resource $sock */
    private function process($sock, int $id, array $obj): void
    {
        switch ($this->conns[$id]['phase']) {
            case 'resp_m1':
                $m2 = $this->conns[$id]['hs']->readMessage1WriteMessage2($obj);
                fwrite($sock, $m2);
                $this->conns[$id]['phase'] = 'resp_m3';
                break;
            case 'resp_m3':
                $hs = $this->conns[$id]['hs'];
                $hs->readMessage3($obj);
                $sess = $hs->session();
                $peer = $sess['peerCert']['label'];
                $this->conns[$id]['transport'] = new Transport($sess);
                $this->conns[$id]['phase'] = 'established';
                $this->conns[$id]['peer'] = $peer;
                $this->conns[$id]['th'] = substr(bin2hex($sess['h']), 0, 16);
                $this->registerLink($id, $peer, false);
                if (isset($this->conns[$id])) {
                    $this->writeKeylog(0, false, $sess);
                }
                break;
            case 'established':
                $inner = $this->conns[$id]['transport']->open($obj);
                $this->conns[$id]['lastInbound'] = self::nowMs();
                if (($inner['type'] ?? null) === 'data') {
                    $this->conns[$id]['lastData'] = self::nowMs();
                }
                $this->handleInner($id, $this->conns[$id]['peer'], $inner);
                break;
        }
    }

    private function handleInner(int $id, string $peer, array $msg): void
    {
        switch ($msg['type'] ?? null) {
            case 'probe':
                $this->sendRaw($id, Message::echo((int) $msg['token']));
                break;
            case 'echo':
                $this->table->observeNeighbor($peer, max(0, self::nowMs() - (int) $msg['token']));
                break;
            case 'disco':
                foreach (($msg['routes'] ?? []) as $dest => $cost) {
                    $this->table->learnRoute((string) $dest, $peer, (int) $cost);
                }
                break;
            case 'data':
                $this->handleData($msg);
                break;
            case 'ack':
                $this->handleControl($msg, 'a:');
                break;
            case 'nak':
                $this->handleControl($msg, 'n:');
                break;
            case 'bye':
                // Peer is closing this session gracefully; tear it down.
                $this->closeConn($id);
                break;
            case 'rekey':
                $this->handleRekey($id, $msg);
                break;
        }
    }

    private function handleData(array $msg): void
    {
        $mid = (string) ($msg['mid'] ?? '');
        $chunkIdx = isset($msg['chunk']['i']) ? (int) $msg['chunk']['i'] : -1;
        if ($this->dedup->sawBefore('d:' . $mid . ':' . $chunkIdx)) {
            return;
        }
        $to = (string) ($msg['to'] ?? '');
        $from = (string) ($msg['from'] ?? '');
        if (strtolower($to) === strtolower($this->cfg['label'])) {
            foreach ($this->listeners as $cb) {
                $cb($msg['payload'] ?? null);
            }
            // F6: acknowledge receipt back toward the origin.
            if ($from !== '' && strtolower($from) !== strtolower($this->cfg['label'])) {
                $this->routeControl(Message::ackTo($mid, $this->cfg['label'], $from, Message::DEFAULT_TTL));
            }
            return;
        }
        $ttl = (int) ($msg['ttl'] ?? 0) - 1;
        if ($ttl <= 0) {
            // F6/D4: the relay that dropped it names itself as the failing hop.
            $this->emitNak($mid, $from, 'ttl');
            return;
        }
        $nh = $this->table->nextHop($to);
        if ($nh === null) {
            $this->emitNak($mid, $from, 'no-route');
            return;
        }
        $fwd = $msg;
        $fwd['ttl'] = $ttl;
        if (!$this->sendToLink($nh, $fwd)) {
            // The next-hop link died between routing and writing; name it as the
            // failing hop so the origin learns which hop broke (F2/D4).
            $this->emitNakHop($mid, $from, $nh, 'link-dead');
        }
    }

    // Relays or delivers an ack/nak (routed back toward the origin like data). A
    // type-prefixed dedup key keeps a relayed ack from colliding with the data
    // it answers (same mid). ack/nak are never themselves ack'd or nak'd.
    private function handleControl(array $msg, string $prefix): void
    {
        $mid = (string) ($msg['mid'] ?? '');
        if ($this->dedup->sawBefore($prefix . $mid)) {
            return;
        }
        $to = (string) ($msg['to'] ?? '');
        if (strtolower($to) === strtolower($this->cfg['label'])) {
            foreach ($this->ackListeners as $cb) {
                $cb($msg);
            }
            return;
        }
        $ttl = (int) ($msg['ttl'] ?? 0) - 1;
        if ($ttl <= 0) {
            return; // drop silently; no nak-of-nak
        }
        $nh = $this->table->nextHop($to);
        if ($nh === null) {
            return;
        }
        $fwd = $msg;
        $fwd['ttl'] = $ttl;
        $this->sendToLink($nh, $fwd);
    }

    // Sends a NAK back toward the origin naming this node as the failing hop.
    // Best-effort: dropped if it cannot itself be routed (no recursion).
    private function emitNak(string $mid, string $origin, string $reason): void
    {
        $this->emitNakHop($mid, $origin, $this->cfg['label'], $reason);
    }

    // Sends a NAK naming an explicit failing hop (this node for a local drop,
    // the next-hop label for a dead onward link).
    private function emitNakHop(string $mid, string $origin, string $hop, string $reason): void
    {
        if ($origin === '' || strtolower($origin) === strtolower($this->cfg['label'])) {
            return;
        }
        $this->routeControl(Message::nak($mid, $this->cfg['label'], $origin, $hop, $reason, Message::DEFAULT_TTL));
    }

    // Sends a freshly-built ack/nak toward its destination, dropping silently if
    // there is no route (never producing a control-of-control).
    private function routeControl(array $msg): void
    {
        $nh = $this->table->nextHop((string) ($msg['to'] ?? ''));
        if ($nh === null) {
            return;
        }
        $this->sendToLink($nh, $msg);
    }

    /** @param resource $sock */
    private static function readFrameBlocking($sock, int $cap): array
    {
        $line = fgets($sock, $cap + 2);
        if ($line === false) {
            throw new \RuntimeException('connection closed during handshake');
        }
        $res = Frame::classify($line, $cap);
        if (isset($res['reason'])) {
            throw new \RuntimeException('bad handshake frame: ' . $res['reason']);
        }
        return $res['obj'];
    }

    private static function now(): int
    {
        return time();
    }

    private static function nowMs(): int
    {
        return (int) (microtime(true) * 1000);
    }
}
