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

test('neighbor labels are case-insensitive everywhere', () => {
  // security.md §2: labels compare case-insensitively. The Java port keyed its
  // neighbors map by the label exactly as given while keying routes folded, which made
  // its disco.routes differ on the wire from the other six.
  const t = new Table('self');
  t.observeNeighbor('Beta', 10);
  t.observeNeighbor('beta', 20);
  // isNeighbor is Java-only surface, so the shared property is asserted through
  // nextHop: one neighbor, reachable under any casing, named in folded form.
  assert.equal(t.nextHop('BeTa'), 'beta');
  assert.equal(t.nextHop('beta'), 'beta');
  t.learnRoute('gamma', 'BETA', 5);
  assert.equal(t.nextHop('gamma'), 'beta');
  for (const k of Object.keys(t.advertiseTo('zeta'))) {
    assert.equal(k, k.toLowerCase(), `unfolded key on the wire: ${k}`);
  }
});

test('a summed cost past the threshold is clamped to the poison value', () => {
  // Found by mutation in the Java port, whose saturating sum detected only arithmetic
  // overflow: nothing in any suite summed a cost past the threshold without
  // overflowing. That matters now the emitted value is a pinned wire constant.
  const t = new Table('self');
  t.observeNeighbor('b', 10);
  t.observeNeighbor('d', 10);
  t.learnRoute('c', 'b', 999999999); // + 10ms link = past the threshold
  assert.equal(t.advertiseTo('d').c, 1000000000);
});

test('the advertised poison value is the pinned literal', () => {
  // 1_000_000_000 is written out here rather than referenced as UNREACHABLE, and that
  // is the whole point: every other poison assertion in this suite compares against
  // the constant, which agrees with itself whatever its value. That is how four ports
  // advertised 2^63-1 with green suites. protocol.md §0 pins the number, so the test
  // pins the number.
  const t = new Table('self');
  t.observeNeighbor('b', 10);
  t.learnRoute('c', 'b', 5);
  assert.equal(t.advertiseTo('b').c, 1000000000);
});

test('no route is ever installed to ourselves', () => {
  // The load-bearing half of defect D5: the v2 broadcast could list the node's own
  // label among its routes and send to itself. learnRoute's first guard is what makes
  // that impossible, and until 3.3.0 no suite in any of the seven ports asserted it --
  // which is why broadcast's own self-exclusion cannot be mutation-caught: the
  // condition it guards against cannot be reached from there.
  const t = new Table('self');
  t.observeNeighbor('b', 10);
  t.learnRoute('self', 'b', 1);
  t.learnRoute('SELF', 'b', 1); // labels compare case-insensitively
  assert.deepEqual(t.routeTable(), {}, 'a route to ourselves was installed');
  assert.equal(t.nextHop('self'), null);
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
