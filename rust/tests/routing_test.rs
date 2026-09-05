// Distance-vector routing tests (protocol.md §5). The algorithm and its wire
// constants mirror the Java and Elixir reference routers; agreement is what lets
// a Rust node relay in a mixed mesh.
use bonemesh::routing::{Dedup, Table, POISON_THRESHOLD, UNREACHABLE};

#[test]
fn neighbor_is_its_own_next_hop_and_advertised() {
    let mut t = Table::new("self");
    t.observe_neighbor("B", 10);
    assert_eq!(t.next_hop("b").as_deref(), Some("b"));
    assert_eq!(t.advertise_to("x")["b"].as_i64(), Some(10));
}

#[test]
fn learn_install_refresh_cheaper() {
    let mut t = Table::new("self");
    t.observe_neighbor("b", 10);
    t.observe_neighbor("d", 100);
    t.learn_route("c", "b", 5); // 5 + 10 = 15 via b
    assert_eq!(t.next_hop("c").as_deref(), Some("b"));
    t.learn_route("c", "d", 1); // 1 + 100 = 101 via d — worse, ignored
    assert_eq!(t.next_hop("c").as_deref(), Some("b"));
    t.observe_neighbor("e", 1);
    t.learn_route("c", "e", 2); // 2 + 1 = 3 via e — cheaper, replaces
    assert_eq!(t.next_hop("c").as_deref(), Some("e"));
    t.learn_route("c", "e", 500); // same via — refresh cost to 501
    assert_eq!(t.advertise_to("x")["c"].as_i64(), Some(501));
}

#[test]
fn learn_guards() {
    let mut t = Table::new("self");
    t.observe_neighbor("b", 10);
    t.learn_route("self", "b", 1);
    t.learn_route("b", "b", 1);
    t.learn_route("c", "z", 1); // via not a neighbor
    assert!(t.route_table().is_empty());
}

#[test]
fn poison_from_own_next_hop_withdraws() {
    let mut t = Table::new("self");
    t.observe_neighbor("b", 10);
    t.learn_route("c", "b", 5);
    t.learn_route("c", "b", 1_000_000_000); // Elixir's sentinel counts as poison
    assert_eq!(t.next_hop("c"), None);
}

#[test]
fn poison_from_other_neighbor_is_noop() {
    let mut t = Table::new("self");
    t.observe_neighbor("b", 10);
    t.observe_neighbor("d", 10);
    t.learn_route("c", "b", 5);
    t.learn_route("c", "d", UNREACHABLE);
    assert_eq!(t.next_hop("c").as_deref(), Some("b"));
}

#[test]
fn advertise_poisoned_reverse() {
    let mut t = Table::new("self");
    t.observe_neighbor("b", 10);
    t.learn_route("c", "b", 5);
    let to_b = t.advertise_to("b");
    assert!(to_b["c"].as_i64().unwrap() >= POISON_THRESHOLD);
    assert!(to_b.get("b").is_none());
    let to_x = t.advertise_to("x");
    assert_eq!(to_x["c"].as_i64(), Some(15));
    assert_eq!(to_x["b"].as_i64(), Some(10));
}

#[test]
fn remove_neighbor_withdraws_its_routes() {
    let mut t = Table::new("self");
    t.observe_neighbor("b", 10);
    t.learn_route("c", "b", 5);
    t.remove_neighbor("b");
    assert_eq!(t.next_hop("c"), None);
    assert_eq!(t.next_hop("b"), None);
}

#[test]
fn ewma_smoothing() {
    let mut t = Table::new("self");
    t.observe_neighbor("b", 100);
    t.observe_neighbor("b", 0); // 0.2*0 + 0.8*100 = 80
    assert_eq!(t.advertise_to("x")["b"].as_i64(), Some(80));
}

#[test]
fn dedup_bounded() {
    let mut d = Dedup::new(2);
    assert!(!d.seen("a"));
    assert!(d.seen("a"));
    d.seen("b");
    d.seen("c"); // evicts a
    assert!(!d.seen("a"));
}
