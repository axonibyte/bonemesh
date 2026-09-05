defmodule Bonemesh.Routing do
  @moduledoc """
  The BoneMesh v3 routing table (protocol.md §6): direct neighbors with EWMA
  round-trip latencies (defect D3) and a distance-vector table of indirect
  destinations. Costs are real latencies; sums saturate; the node's own label is
  never a route; advertisements apply split-horizon with poisoned reverse
  (defect-D4-adjacent loop control). Pure functions over a table map.
  """

  @alpha 0.2
  @unreachable 1_000_000_000

  @doc "Sentinel path cost meaning unreachable."
  def unreachable, do: @unreachable

  @doc "A new routing table for `self_label`."
  def new(self_label), do: %{self: down(self_label), neighbors: %{}, routes: %{}}

  @doc "Records/updates a neighbor, folding in an RTT sample (EWMA)."
  def observe_neighbor(t, label, rtt) do
    key = down(label)
    ewma =
      case t.neighbors[key] do
        nil -> rtt * 1.0
        prev -> @alpha * rtt + (1.0 - @alpha) * prev
      end

    put_in(t.neighbors[key], ewma)
  end

  @doc "Removes a neighbor and withdraws routes that went through it."
  def remove_neighbor(t, label) do
    key = down(label)
    routes = t.routes |> Enum.reject(fn {_d, {via, _c}} -> via == key end) |> Map.new()
    %{t | neighbors: Map.delete(t.neighbors, key), routes: routes}
  end

  @doc "Learns/improves a route to `dest` advertised by `via` at `adv_cost`."
  def learn_route(t, dest, via, adv_cost) do
    d = down(dest)
    v = down(via)

    cond do
      d == t.self -> t
      d == v -> t
      not Map.has_key?(t.neighbors, v) -> t
      adv_cost >= @unreachable -> withdraw_if_via(t, d, v)
      true -> maybe_install(t, d, v, saturating(adv_cost, round(t.neighbors[v])))
    end
  end

  @doc "The next-hop neighbor toward `dest`, or nil."
  def next_hop(t, dest) do
    d = down(dest)

    cond do
      Map.has_key?(t.neighbors, d) -> d
      (r = t.routes[d]) != nil -> elem(r, 0)
      true -> nil
    end
  end

  @doc "The advertisement for `to_neighbor` (split-horizon + poisoned reverse)."
  def advertise_to(t, to_neighbor) do
    n = down(to_neighbor)

    neighbor_ads =
      t.neighbors
      |> Enum.reject(fn {k, _} -> k == n or k == t.self end)
      |> Map.new(fn {k, ewma} -> {k, round(ewma)} end)

    Enum.reduce(t.routes, neighbor_ads, fn {dest, {via, cost}}, acc ->
      Map.put(acc, dest, if(via == n, do: @unreachable, else: cost))
    end)
    |> Map.delete(t.self)
  end

  defp maybe_install(t, d, v, cost) do
    case t.routes[d] do
      nil -> put_in(t.routes[d], {v, cost})
      {^v, _} -> put_in(t.routes[d], {v, cost})
      {_other, old} when cost < old -> put_in(t.routes[d], {v, cost})
      _ -> t
    end
  end

  defp withdraw_if_via(t, d, v) do
    case t.routes[d] do
      {^v, _} -> %{t | routes: Map.delete(t.routes, d)}
      _ -> t
    end
  end

  defp saturating(a, b) do
    sum = a + b
    if sum >= @unreachable, do: @unreachable, else: sum
  end

  defp down(label), do: String.downcase(label)
end
