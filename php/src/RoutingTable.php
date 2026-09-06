<?php
namespace Bonemesh;

// BoneMesh v3 distance-vector routing (protocol.md §5): a table of direct
// neighbors (EWMA-smoothed link latency) and learned routes (destination ->
// next hop, path cost in ms). Wire-compatible with the Java, Elixir, Go, Rust,
// and JS reference routers.
//
// Poison sentinel: routes are advertised unreachable with PHP_INT_MAX (Java's
// Long.MAX_VALUE, which PHP's 64-bit ints hold and encode exactly), and any
// advertised cost at or above POISON_THRESHOLD (1e9, Elixir/JS) is treated as
// unreachable on receipt — so a mixed mesh converges.
final class RoutingTable
{
    public const UNREACHABLE = PHP_INT_MAX;
    public const POISON_THRESHOLD = 1000000000;
    private const ALPHA = 0.2;

    private string $self;
    private array $neighbors = []; // label => ['v' => float, 'has' => bool]
    private array $routes = [];    // dest => ['via' => string, 'cost' => int]

    public function __construct(string $self)
    {
        $this->self = strtolower($self);
    }

    public function observeNeighbor(string $label, int $rttMillis): void
    {
        $k = strtolower($label);
        if (!isset($this->neighbors[$k])) {
            $this->neighbors[$k] = ['v' => 0.0, 'has' => false];
        }
        $e = &$this->neighbors[$k];
        if (!$e['has']) {
            $e['v'] = (float) $rttMillis;
            $e['has'] = true;
        } else {
            $e['v'] = self::ALPHA * $rttMillis + (1 - self::ALPHA) * $e['v'];
        }
    }

    public function removeNeighbor(string $label): void
    {
        $k = strtolower($label);
        unset($this->neighbors[$k]);
        foreach ($this->routes as $dest => $r) {
            if ($r['via'] === $k) {
                unset($this->routes[$dest]);
            }
        }
    }

    public function learnRoute(string $dest, string $via, int $advertisedCost): void
    {
        $d = strtolower($dest);
        $v = strtolower($via);
        if ($d === $this->self || $d === $v) {
            return;
        }
        if (!isset($this->neighbors[$v])) {
            return;
        }
        if (isset($this->neighbors[$d])) {
            return; // dest is a direct neighbor; a routed path would only shadow it
        }
        if ($advertisedCost >= self::POISON_THRESHOLD) {
            if (isset($this->routes[$d]) && $this->routes[$d]['via'] === $v) {
                unset($this->routes[$d]);
            }
            return;
        }
        $cost = self::satSum($advertisedCost, $this->neighborLatency($v));
        if (!isset($this->routes[$d]) || $this->routes[$d]['via'] === $v || $cost < $this->routes[$d]['cost']) {
            $this->routes[$d] = ['via' => $v, 'cost' => $cost];
        }
    }

    public function nextHop(string $dest): ?string
    {
        $d = strtolower($dest);
        if (isset($this->neighbors[$d])) {
            return $d; // a direct neighbor is its own next hop
        }
        return $this->routes[$d]['via'] ?? null;
    }

    public function advertiseTo(string $toNeighbor): array
    {
        $to = strtolower($toNeighbor);
        $m = [];
        foreach ($this->neighbors as $label => $e) {
            if ($label !== $to) {
                $m[$label] = $this->millis($e);
            }
        }
        foreach ($this->routes as $dest => $r) {
            $m[$dest] = $r['via'] === $to ? self::UNREACHABLE : $r['cost'];
        }
        unset($m[$this->self]);
        return $m;
    }

    public function routeTable(): array
    {
        $out = [];
        foreach ($this->routes as $dest => $r) {
            $out[$dest] = $r['via'];
        }
        return $out;
    }

    private function millis(array $e): int
    {
        return $e['has'] ? (int) round($e['v']) : self::UNREACHABLE;
    }

    private function neighborLatency(string $k): int
    {
        return isset($this->neighbors[$k]) ? $this->millis($this->neighbors[$k]) : self::UNREACHABLE;
    }

    private static function satSum(int $a, int $b): int
    {
        if ($a >= self::POISON_THRESHOLD || $b >= self::POISON_THRESHOLD) {
            return self::UNREACHABLE;
        }
        $sum = $a + $b;
        return $sum >= self::POISON_THRESHOLD ? self::UNREACHABLE : $sum;
    }
}
