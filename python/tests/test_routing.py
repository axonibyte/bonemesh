"""Distance-vector routing (protocol.md §5/§6)."""

from bonemesh.routing import ALPHA, POISON_THRESHOLD, UNREACHABLE, Dedup, Ewma, Table, sat_sum


def test_pinned_constants():
    assert UNREACHABLE == 1_000_000_000
    assert POISON_THRESHOLD == 1_000_000_000
    assert ALPHA == 0.2


def test_ewma_smoothing_follows_alpha_0_2():
    e = Ewma()
    assert e.millis() == UNREACHABLE  # no sample yet
    e.observe(10)
    assert e.millis() == 10           # first sample seeds directly
    e.observe(20)
    assert e.millis() == 12           # 0.2*20 + 0.8*10


def test_labels_are_compared_case_insensitively():
    t = Table("Alpha")
    t.observe_neighbor("BRAVO", 5)
    assert t.next_hop("bravo") == "bravo"
    assert t.next_hop("BrAvO") == "bravo"


def test_a_direct_neighbour_is_its_own_next_hop():
    t = Table("alpha")
    t.observe_neighbor("bravo", 5)
    assert t.next_hop("bravo") == "bravo"


def test_a_learned_route_resolves_to_its_next_hop():
    t = Table("alpha")
    t.observe_neighbor("bravo", 5)
    t.learn_route("charlie", "bravo", 7)
    assert t.next_hop("charlie") == "bravo"
    assert t.route_table() == {"charlie": "bravo"}
    assert t.routes["charlie"]["cost"] == 12  # advertised 7 + link 5


def test_no_route_is_installed_for_a_direct_neighbour():
    # Shadowing a direct neighbour with a learned route was a real convergence
    # defect (docs/architecture.md §4).
    t = Table("alpha")
    t.observe_neighbor("bravo", 5)
    t.observe_neighbor("charlie", 5)
    t.learn_route("charlie", "bravo", 1)
    assert t.route_table() == {}
    assert t.next_hop("charlie") == "charlie"


def test_routes_to_self_and_via_self_are_ignored():
    t = Table("alpha")
    t.observe_neighbor("bravo", 5)
    t.learn_route("alpha", "bravo", 1)
    t.learn_route("bravo", "bravo", 1)
    assert t.route_table() == {}


def test_a_route_from_an_unknown_neighbour_is_ignored():
    t = Table("alpha")
    t.learn_route("charlie", "nobody", 1)
    assert t.route_table() == {}


def test_a_cheaper_path_wins_and_a_dearer_one_does_not():
    t = Table("alpha")
    t.observe_neighbor("bravo", 1)
    t.observe_neighbor("delta", 1)
    t.learn_route("charlie", "bravo", 10)
    t.learn_route("charlie", "delta", 99)
    assert t.next_hop("charlie") == "bravo"
    t.learn_route("charlie", "delta", 2)
    assert t.next_hop("charlie") == "delta"


def test_the_current_next_hop_may_raise_its_own_cost():
    # An incumbent's fresh advertisement always replaces its own entry, or a
    # worsening path would be remembered as cheap forever.
    t = Table("alpha")
    t.observe_neighbor("bravo", 1)
    t.learn_route("charlie", "bravo", 5)
    t.learn_route("charlie", "bravo", 50)
    assert t.routes["charlie"]["cost"] == 51


def test_poison_from_the_routes_own_next_hop_withdraws_it():
    t = Table("alpha")
    t.observe_neighbor("bravo", 1)
    t.learn_route("charlie", "bravo", 5)
    t.learn_route("charlie", "bravo", UNREACHABLE)
    assert t.route_table() == {}


def test_poison_from_another_neighbour_is_a_no_op():
    t = Table("alpha")
    t.observe_neighbor("bravo", 1)
    t.observe_neighbor("delta", 1)
    t.learn_route("charlie", "bravo", 5)
    t.learn_route("charlie", "delta", UNREACHABLE)
    assert t.next_hop("charlie") == "bravo"


def test_any_cost_at_or_above_the_threshold_counts_as_poison():
    # Implementations emit different maxima (Java Long.MAX_VALUE, JS/Elixir 1e9);
    # a receiver must treat anything >= 1e9 as unreachable.
    for advertised in (POISON_THRESHOLD, POISON_THRESHOLD + 1, 2**63 - 1):
        t = Table("alpha")
        t.observe_neighbor("bravo", 1)
        t.learn_route("charlie", "bravo", 5)
        t.learn_route("charlie", "bravo", advertised)
        assert t.route_table() == {}, advertised


def test_advertise_applies_split_horizon_and_poisoned_reverse():
    t = Table("alpha")
    t.observe_neighbor("bravo", 5)
    t.observe_neighbor("delta", 7)
    t.learn_route("charlie", "bravo", 3)
    adv = t.advertise_to("bravo")
    assert "bravo" not in adv                  # split horizon
    assert adv["charlie"] == UNREACHABLE       # poisoned reverse
    assert adv["delta"] == 7
    assert "alpha" not in adv                  # never advertise self


def test_remove_neighbour_withdraws_its_routes():
    t = Table("alpha")
    t.observe_neighbor("bravo", 1)
    t.observe_neighbor("delta", 1)
    t.learn_route("charlie", "bravo", 5)
    t.learn_route("echo", "delta", 5)
    t.remove_neighbor("bravo")
    assert t.route_table() == {"echo": "delta"}
    assert t.next_hop("bravo") is None


def test_sat_sum_saturates_rather_than_wrapping():
    assert sat_sum(1, 2) == 3
    assert sat_sum(UNREACHABLE, 1) == UNREACHABLE
    assert sat_sum(1, UNREACHABLE) == UNREACHABLE
    assert sat_sum(POISON_THRESHOLD - 1, 5) == UNREACHABLE


def test_reachable_lists_neighbours_and_routes_but_never_self():
    t = Table("alpha")
    t.observe_neighbor("bravo", 1)
    t.learn_route("charlie", "bravo", 1)
    assert t.reachable() == ["bravo", "charlie"]


def test_dedup_reports_repeats_and_stays_bounded():
    d = Dedup(3)
    assert [d.saw_before(k) for k in ("a", "b", "a", "c")] == [False, False, True, False]
    d.saw_before("d")            # evicts "a"
    assert d.saw_before("a") is False
    assert len(d.seen) == 3 and len(d.order) == 3
