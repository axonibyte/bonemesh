<?php
// Distance-vector routing tests (protocol.md §5). The algorithm and its
// constants mirror the Java, Elixir, Go, Rust, and JS routers; agreement is
// what lets a PHP node relay in a mixed mesh. (The relay path itself is a
// blocking single-loop concern proven by the interop matrix and tier 8, not an
// in-process test — PHP cannot run several nodes in one process.)
use Bonemesh\RoutingTable;
use Bonemesh\Dedup;

test('neighbor is its own next hop and is advertised', function () {
    $t = new RoutingTable('self');
    $t->observeNeighbor('B', 10);
    assertEq('b', $t->nextHop('b'));
    assertEq(10, $t->advertiseTo('x')['b']);
});

test('learn install, refresh, cheaper', function () {
    $t = new RoutingTable('self');
    $t->observeNeighbor('b', 10);
    $t->observeNeighbor('d', 100);
    $t->learnRoute('c', 'b', 5); // 5 + 10 = 15 via b
    assertEq('b', $t->nextHop('c'));
    $t->learnRoute('c', 'd', 1); // 1 + 100 = 101 — worse, ignored
    assertEq('b', $t->nextHop('c'));
    $t->observeNeighbor('e', 1);
    $t->learnRoute('c', 'e', 2); // 2 + 1 = 3 via e — cheaper
    assertEq('e', $t->nextHop('c'));
    $t->learnRoute('c', 'e', 500); // same via — refresh
    assertEq(501, $t->advertiseTo('x')['c']);
});

test('learn guards', function () {
    $t = new RoutingTable('self');
    $t->observeNeighbor('b', 10);
    $t->learnRoute('self', 'b', 1);
    $t->learnRoute('b', 'b', 1);
    $t->learnRoute('c', 'z', 1);
    assertEq(0, count($t->routeTable()));
});

test('poison from the route\'s own next hop withdraws it', function () {
    $t = new RoutingTable('self');
    $t->observeNeighbor('b', 10);
    $t->learnRoute('c', 'b', 5);
    $t->learnRoute('c', 'b', 1000000000); // Elixir/JS sentinel
    assertNull($t->nextHop('c'));
});

test('poison from another neighbor is a no-op', function () {
    $t = new RoutingTable('self');
    $t->observeNeighbor('b', 10);
    $t->observeNeighbor('d', 10);
    $t->learnRoute('c', 'b', 5);
    $t->learnRoute('c', 'd', RoutingTable::UNREACHABLE);
    assertEq('b', $t->nextHop('c'));
});

test('advertise with split-horizon poisoned reverse', function () {
    $t = new RoutingTable('self');
    $t->observeNeighbor('b', 10);
    $t->learnRoute('c', 'b', 5);
    $toB = $t->advertiseTo('b');
    assertTrue($toB['c'] >= RoutingTable::POISON_THRESHOLD);
    assertTrue(!isset($toB['b']));
    $toX = $t->advertiseTo('x');
    assertEq(15, $toX['c']);
    assertEq(10, $toX['b']);
});

test('remove neighbor withdraws its routes', function () {
    $t = new RoutingTable('self');
    $t->observeNeighbor('b', 10);
    $t->learnRoute('c', 'b', 5);
    $t->removeNeighbor('b');
    assertNull($t->nextHop('c'));
    assertNull($t->nextHop('b'));
});

test('EWMA smoothing (alpha 0.2)', function () {
    $t = new RoutingTable('self');
    $t->observeNeighbor('b', 100);
    $t->observeNeighbor('b', 0); // 0.2*0 + 0.8*100 = 80
    assertEq(80, $t->advertiseTo('x')['b']);
});

test('dedup is bounded', function () {
    $d = new Dedup(2);
    assertTrue(!$d->sawBefore('a'));
    assertTrue($d->sawBefore('a'));
    $d->sawBefore('b');
    $d->sawBefore('c'); // evicts a
    assertTrue(!$d->sawBefore('a'));
});
