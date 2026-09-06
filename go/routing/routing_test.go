// Distance-vector routing tests (protocol.md §5). The algorithm and its wire
// constants (poison sentinel, EWMA) mirror the Java and Elixir reference
// routers; agreement is what lets a Go node relay in a mixed mesh.
package routing

import "testing"

func TestNeighborAndDirectNextHop(t *testing.T) {
	tbl := NewTable("self")
	tbl.ObserveNeighbor("B", 10)
	nh, ok := tbl.NextHop("b")
	if !ok || nh != "b" {
		t.Fatalf("a direct neighbor is its own next hop, got %q ok=%v", nh, ok)
	}
	// Advertising to someone else exposes the neighbor's rounded latency.
	adv := tbl.AdvertiseTo("x")
	if adv["b"] != 10 {
		t.Fatalf("advertised neighbor latency = %d, want 10", adv["b"])
	}
}

func TestLearnRouteInstallRefreshCheaper(t *testing.T) {
	tbl := NewTable("self")
	tbl.ObserveNeighbor("b", 10)
	tbl.ObserveNeighbor("d", 100)

	tbl.LearnRoute("c", "b", 5) // cost = 5 + 10 = 15 via b
	if nh, _ := tbl.NextHop("c"); nh != "b" {
		t.Fatalf("route to c should be via b, got %q", nh)
	}
	tbl.LearnRoute("c", "d", 1) // cost = 1 + 100 = 101 via d — worse, ignored
	if nh, _ := tbl.NextHop("c"); nh != "b" {
		t.Fatalf("worse route should not replace; got %q", nh)
	}
	tbl.ObserveNeighbor("e", 1)
	tbl.LearnRoute("c", "e", 2) // cost = 2 + 1 = 3 via e — cheaper, replaces
	if nh, _ := tbl.NextHop("c"); nh != "e" {
		t.Fatalf("cheaper route should replace; got %q", nh)
	}
	// Same-via refresh always overwrites the stored cost.
	tbl.LearnRoute("c", "e", 500)
	if tbl.AdvertiseTo("x")["c"] != 501 {
		t.Fatalf("same-via refresh should update cost to 501, got %d", tbl.AdvertiseTo("x")["c"])
	}
}

func TestLearnRouteGuards(t *testing.T) {
	tbl := NewTable("self")
	tbl.ObserveNeighbor("b", 10)
	tbl.LearnRoute("self", "b", 1) // dest == self
	tbl.LearnRoute("b", "b", 1)    // dest == via
	tbl.LearnRoute("c", "z", 1)    // via not a neighbor
	if len(tbl.RouteTable()) != 0 {
		t.Fatalf("guards should have installed no routes, got %v", tbl.RouteTable())
	}
}

func TestPoisonWithdrawsRouteViaThatNeighbor(t *testing.T) {
	tbl := NewTable("self")
	tbl.ObserveNeighbor("b", 10)
	tbl.LearnRoute("c", "b", 5)
	// Java's Long.MAX_VALUE and Elixir's 1e9 both count as poison on receipt.
	tbl.LearnRoute("c", "b", 1000000000)
	if _, ok := tbl.NextHop("c"); ok {
		t.Fatal("a poisoned advert from the route's own next hop should withdraw it")
	}
}

func TestPoisonFromOtherNeighborIsNoOp(t *testing.T) {
	tbl := NewTable("self")
	tbl.ObserveNeighbor("b", 10)
	tbl.ObserveNeighbor("d", 10)
	tbl.LearnRoute("c", "b", 5)
	tbl.LearnRoute("c", "d", Unreachable) // poison from a neighbor we don't route through
	if nh, ok := tbl.NextHop("c"); !ok || nh != "b" {
		t.Fatalf("route via b should survive a poison from d; got %q ok=%v", nh, ok)
	}
}

func TestAdvertisePoisonedReverse(t *testing.T) {
	tbl := NewTable("self")
	tbl.ObserveNeighbor("b", 10)
	tbl.LearnRoute("c", "b", 5)
	// Back to b: the route to c (learned via b) is poisoned; b itself is omitted.
	toB := tbl.AdvertiseTo("b")
	if toB["c"] < PoisonThreshold {
		t.Fatalf("route to c should be poisoned back to b, got %d", toB["c"])
	}
	if _, present := toB["b"]; present {
		t.Fatal("split horizon: should not advertise b back to b")
	}
	// To someone else: real cost, and b's latency.
	toX := tbl.AdvertiseTo("x")
	if toX["c"] != 15 || toX["b"] != 10 {
		t.Fatalf("to x: c=%d b=%d, want 15 and 10", toX["c"], toX["b"])
	}
}

func TestRemoveNeighborWithdrawsItsRoutes(t *testing.T) {
	tbl := NewTable("self")
	tbl.ObserveNeighbor("b", 10)
	tbl.LearnRoute("c", "b", 5)
	tbl.RemoveNeighbor("b")
	if _, ok := tbl.NextHop("c"); ok {
		t.Fatal("removing b should withdraw routes via b")
	}
	if _, ok := tbl.NextHop("b"); ok {
		t.Fatal("b should no longer be a neighbor")
	}
}

// A destination that is a direct neighbor must never get a learned route — a
// shadow route would be poison-reversed back to its source, clobbering the
// legitimate neighbor advertisement and breaking multi-relay convergence.
func TestNoRouteInstalledForADirectNeighbor(t *testing.T) {
	tbl := NewTable("self")
	tbl.ObserveNeighbor("b", 10)
	tbl.ObserveNeighbor("c", 10)
	tbl.LearnRoute("c", "b", 1) // c is already a direct neighbor
	if _, ok := tbl.RouteTable()["c"]; ok {
		t.Fatal("must not install a route to a direct neighbor")
	}
	if nh, _ := tbl.NextHop("c"); nh != "c" {
		t.Fatalf("nextHop(c) should be the direct neighbor c, got %q", nh)
	}
}

func TestEwmaSmoothing(t *testing.T) {
	tbl := NewTable("self")
	tbl.ObserveNeighbor("b", 100) // first sample: ewma = 100
	tbl.ObserveNeighbor("b", 0)   // ewma = 0.2*0 + 0.8*100 = 80
	if got := tbl.AdvertiseTo("x")["b"]; got != 80 {
		t.Fatalf("EWMA (alpha 0.2) = %d, want 80", got)
	}
}

func TestDedup(t *testing.T) {
	d := NewDedup(2)
	if d.Seen("a") {
		t.Fatal("first sight of a should be new")
	}
	if !d.Seen("a") {
		t.Fatal("second sight of a should be a duplicate")
	}
	d.Seen("b")
	d.Seen("c") // evicts a (cap 2)
	if d.Seen("a") {
		t.Fatal("a should have been evicted and read as new again")
	}
}
