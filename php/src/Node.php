<?php
namespace Bonemesh;

// A BoneMesh v3 mesh node (protocol.md §3) over TCP: one authenticated,
// encrypted session per neighbor, with application payloads delivered to
// registered listeners. Wire-compatible with the Java, Elixir, Rust, Go, and JS
// implementations. Does direct neighbor delivery, which is what two-party
// interop needs; relay/discovery/heartbeat are shared parity work tracked
// elsewhere.
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

    public function __construct(private array $cfg)
    {
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
        $this->conns[$id] = ['sock' => $sock, 'buf' => '', 'phase' => 'established', 'transport' => new Transport($sess)];
        $this->links[strtolower($peer)] = $id;
        return $peer;
    }

    public function send(string $to, $payload): bool
    {
        $id = $this->links[strtolower($to)] ?? null;
        if ($id === null || !isset($this->conns[$id])) {
            return false;
        }
        $conn = $this->conns[$id];
        $msg = Message::data(Message::newMid(), $this->cfg['label'], $to, Message::DEFAULT_TTL, $payload);
        $frame = Frame::encode($conn['transport']->seal($msg));
        return @fwrite($conn['sock'], $frame) !== false;
    }

    // Run the accept/read loop for $seconds, processing every connection.
    public function serve(float $seconds): void
    {
        $deadline = microtime(true) + $seconds;
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
            if ($n === false) {
                break;
            }
            foreach ($read as $r) {
                if ($this->server !== null && $r === $this->server) {
                    $this->accept();
                } else {
                    $this->onReadable($r);
                }
            }
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
            @fclose($sock);
            unset($this->conns[$id]);
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
                    @fclose($sock);
                    unset($this->conns[$id]);
                    return;
                }
                continue; // ignore an unparseable transport frame
            }
            try {
                $this->process($sock, $id, $res['obj']);
            } catch (\Throwable $e) {
                @fclose($sock);
                unset($this->conns[$id]);
                return;
            }
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
                $this->conns[$id]['transport'] = new Transport($sess);
                $this->conns[$id]['phase'] = 'established';
                $this->links[strtolower($sess['peerCert']['label'])] = $id;
                break;
            case 'established':
                $inner = $this->conns[$id]['transport']->open($obj);
                $this->handleInner($inner);
                break;
        }
    }

    private function handleInner(array $msg): void
    {
        if (($msg['type'] ?? null) !== 'data') {
            return;
        }
        foreach ($this->listeners as $cb) {
            $cb($msg['payload'] ?? null);
        }
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
}
