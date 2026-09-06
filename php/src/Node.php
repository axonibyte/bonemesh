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
        $this->conns[$id] = ['sock' => $sock, 'buf' => '', 'phase' => 'established', 'transport' => new Transport($sess), 'peer' => $peer];
        $this->registerLink($id, $peer, true);
        return $peer;
    }

    // Records a newly-established link (protocol.md §3): stamps who initiated
    // the connection and the liveness/idle clocks, closes any link this one
    // displaces (a reconnect), and seeds the neighbor as routable. Closing the
    // displaced conn is safe because closeConn withdraws routes only when the
    // links entry still points at the closing id, so it cannot clobber this one.
    private function registerLink(int $id, string $peer, bool $initiator): void
    {
        $now = self::nowMs();
        $this->conns[$id]['initiator'] = $initiator;
        $this->conns[$id]['establishedAt'] = $now;
        $this->conns[$id]['lastInbound'] = $now;
        $this->conns[$id]['lastData'] = $now;
        $prev = $this->links[strtolower($peer)] ?? null;
        $this->links[strtolower($peer)] = $id;
        if ($prev !== null && $prev !== $id && isset($this->conns[$prev])) {
            @fclose($this->conns[$prev]['sock']);
            unset($this->conns[$prev]);
        }
        $this->table->observeNeighbor($peer, 1); // optimistic seed
    }

    // Routes an application payload toward any reachable destination.
    public function send(string $to, $payload): bool
    {
        $nh = $this->table->nextHop($to);
        if ($nh === null) {
            return false;
        }
        $msg = Message::data(Message::newMid(), $this->cfg['label'], $to, Message::DEFAULT_TTL, $payload);
        return $this->sendToLink($nh, $msg);
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
        foreach ($this->conns as $id => $conn) {
            if (($conn['phase'] ?? '') !== 'established') {
                continue;
            }
            $this->sendRaw($id, Message::probe(self::nowMs()));
            $this->sendRaw($id, Message::disco($this->table->advertiseTo($conn['peer'])));
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
                $this->registerLink($id, $peer, false);
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
        }
    }

    private function handleData(array $msg): void
    {
        $mid = $msg['mid'] ?? '';
        $chunkIdx = isset($msg['chunk']['i']) ? (int) $msg['chunk']['i'] : -1;
        if ($this->dedup->sawBefore($mid . ':' . $chunkIdx)) {
            return;
        }
        if (strtolower((string) ($msg['to'] ?? '')) === strtolower($this->cfg['label'])) {
            foreach ($this->listeners as $cb) {
                $cb($msg['payload'] ?? null);
            }
            return;
        }
        $ttl = (int) ($msg['ttl'] ?? 0) - 1;
        if ($ttl <= 0) {
            return; // DROP_TTL, silently
        }
        $nh = $this->table->nextHop((string) ($msg['to'] ?? ''));
        if ($nh === null) {
            return; // UNREACHABLE, silently
        }
        $fwd = $msg;
        $fwd['ttl'] = $ttl;
        $this->sendToLink($nh, $fwd);
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
