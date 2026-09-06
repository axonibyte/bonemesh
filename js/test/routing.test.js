// Distance-vector routing tests (protocol.md §5). The algorithm and its
// constants mirror the Java, Elixir, Go, and Rust routers; agreement is what
// lets a JS node relay in a mixed mesh.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { Table, Dedup, UNREACHABLE, POISON_THRESHOLD } from '../src/routing.js';

test('a neighbor is its own next hop and is advertised', () => {
  const t = new Table('self');
  t.observeNeighbor('B', 10);
  assert.equal(t.nextHop('b'), 'b');
  assert.equal(t.advertiseTo('x').b, 10);
});

test('learn: install, refresh, cheaper', () => {
  const t = new Table('self');
  t.observeNeighbor('b', 10);
  t.observeNeighbor('d', 100);
  t.learnRoute('c', 'b', 5); // 5 + 10 = 15 via b
  assert.equal(t.nextHop('c'), 'b');
  t.learnRoute('c', 'd', 1); // 1 + 100 = 101 — worse, ignored
  assert.equal(t.nextHop('c'), 'b');
  t.observeNeighbor('e', 1);
  t.learnRoute('c', 'e', 2); // 2 + 1 = 3 via e — cheaper
  assert.equal(t.nextHop('c'), 'e');
  t.learnRoute('c', 'e', 500); // same via — refresh
  assert.equal(t.advertiseTo('x').c, 501);
});

test('learn guards (self, via, unknown neighbor)', () => {
  const t = new Table('self');
  t.observeNeighbor('b', 10);
  t.learnRoute('self', 'b', 1);
  t.learnRoute('b', 'b', 1);
  t.learnRoute('c', 'z', 1);
  assert.equal(Object.keys(t.routeTable()).length, 0);
});

test('poison from the route\'s own next hop withdraws it', () => {
  const t = new Table('self');
  t.observeNeighbor('b', 10);
  t.learnRoute('c', 'b', 5);
  t.learnRoute('c', 'b', 1000000000);
  assert.equal(t.nextHop('c'), null);
});

test('poison from another neighbor is a no-op', () => {
  const t = new Table('self');
  t.observeNeighbor('b', 10);
  t.observeNeighbor('d', 10);
  t.learnRoute('c', 'b', 5);
  t.learnRoute('c', 'd', UNREACHABLE);
  assert.equal(t.nextHop('c'), 'b');
});

test('advertise with split-horizon poisoned reverse', () => {
  const t = new Table('self');
  t.observeNeighbor('b', 10);
  t.learnRoute('c', 'b', 5);
  const toB = t.advertiseTo('b');
  assert.ok(toB.c >= POISON_THRESHOLD);
  assert.equal(toB.b, undefined);
  const toX = t.advertiseTo('x');
  assert.equal(toX.c, 15);
  assert.equal(toX.b, 10);
});

test('remove neighbor withdraws its routes', () => {
  const t = new Table('self');
  t.observeNeighbor('b', 10);
  t.learnRoute('c', 'b', 5);
  t.removeNeighbor('b');
  assert.equal(t.nextHop('c'), null);
  assert.equal(t.nextHop('b'), null);
});

test('no route is installed for a direct neighbor', () => {
  const t = new Table('self');
  t.observeNeighbor('b', 10);
  t.observeNeighbor('c', 10);
  t.learnRoute('c', 'b', 1); // c is already a neighbor
  assert.equal(t.routeTable().c, undefined);
  assert.equal(t.nextHop('c'), 'c');
});

test('EWMA smoothing (alpha 0.2)', () => {
  const t = new Table('self');
  t.observeNeighbor('b', 100);
  t.observeNeighbor('b', 0); // 0.2*0 + 0.8*100 = 80
  assert.equal(t.advertiseTo('x').b, 80);
});

test('dedup is bounded', () => {
  const d = new Dedup(2);
  assert.equal(d.sawBefore('a'), false);
  assert.equal(d.sawBefore('a'), true);
  d.sawBefore('b');
  d.sawBefore('c'); // evicts a
  assert.equal(d.sawBefore('a'), false);
});
