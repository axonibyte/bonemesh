defmodule Bonemesh.RoutingTest do
  use ExUnit.Case, async: true

  alias Bonemesh.Routing

  # Distance-vector routing (protocol.md §5). Mirrors the Java, Go, Rust, JS, and
  # PHP routers; agreement is what lets an Elixir node relay in a mixed mesh.

  test "a neighbor is its own next hop and is advertised" do
    t = Routing.new("self") |> Routing.observe_neighbor("B", 10)
    assert Routing.next_hop(t, "b") == "b"
    assert Routing.advertise_to(t, "x")["b"] == 10
  end

  test "learn install and poisoned withdrawal" do
    t =
      Routing.new("self")
      |> Routing.observe_neighbor("b", 10)
      |> Routing.learn_route("c", "b", 5)

    assert Routing.next_hop(t, "c") == "b"
    t = Routing.learn_route(t, "c", "b", 1_000_000_000)
    assert Routing.next_hop(t, "c") == nil
  end

  test "advertise with split-horizon poisoned reverse" do
    t =
      Routing.new("self")
      |> Routing.observe_neighbor("b", 10)
      |> Routing.learn_route("c", "b", 5)

    assert Routing.advertise_to(t, "b")["c"] >= 1_000_000_000
    refute Map.has_key?(Routing.advertise_to(t, "b"), "b")
  end

  # No route is ever installed to ourselves.
  #
  # The load-bearing half of defect D5: the v2 broadcast could list the node's own
  # label among its routes and send to itself. learn_route's first guard is what makes
  # that impossible, and until 3.3.0 no suite in any of the seven ports asserted it --
  # which is why broadcast's own self-exclusion cannot be mutation-caught: the
  # condition it guards against cannot be reached from there.
  test "no route is ever installed to ourselves" do
    t =
      Routing.new("self")
      |> Routing.observe_neighbor("b", 10)
      |> Routing.learn_route("self", "b", 1)
      |> Routing.learn_route("SELF", "b", 1)

    assert t.routes == %{}
    assert Routing.next_hop(t, "self") == nil
  end

  # A direct neighbor must never get a learned route: a shadow route would be
  # poison-reversed back to its source, clobbering the legitimate neighbor
  # advertisement and breaking multi-relay convergence.
  test "no route is installed for a direct neighbor" do
    t =
      Routing.new("self")
      |> Routing.observe_neighbor("b", 10)
      |> Routing.observe_neighbor("c", 10)
      |> Routing.learn_route("c", "b", 1)

    assert Routing.next_hop(t, "c") == "c"
    assert Routing.advertise_to(t, "b")["c"] == 10
  end

  test "remove neighbor withdraws its routes" do
    t =
      Routing.new("self")
      |> Routing.observe_neighbor("b", 10)
      |> Routing.learn_route("c", "b", 5)
      |> Routing.remove_neighbor("b")

    assert Routing.next_hop(t, "c") == nil
    assert Routing.next_hop(t, "b") == nil
  end
end
