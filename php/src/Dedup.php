<?php
namespace Bonemesh;

// A bounded set of recently seen keys (message id + chunk index) for dropping
// duplicate and looped relay traffic.
final class Dedup
{
    private int $cap;
    private array $seen = [];
    private array $order = [];

    public function __construct(int $cap)
    {
        $this->cap = $cap;
    }

    // Records $key and reports whether it had been seen before.
    public function sawBefore(string $key): bool
    {
        if (isset($this->seen[$key])) {
            return true;
        }
        $this->seen[$key] = true;
        $this->order[] = $key;
        if (count($this->order) > $this->cap) {
            $oldest = array_shift($this->order);
            unset($this->seen[$oldest]);
        }
        return false;
    }
}
