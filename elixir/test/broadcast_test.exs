defmodule Bonemesh.BroadcastTest do
  use ExUnit.Case, async: false

  @moduledoc """
  Broadcast tests (protocol.md §6).

  Both halves of the D5 fix are asserted, because D5 was two bugs in one line: the v2
  implementation iterated indirect routes only, so direct session peers were missed,
  and a node could appear among its own routes, so it broadcast to itself.
  """

  alias Bonemesh.{Cert, Crypto, Node}

  @mesh "acme-prod"

  setup do
    {root_pub, root_priv} = Crypto.mldsa_generate(:mldsa87)
    %{root_pub: root_pub, root_priv: root_priv}
  end

  defp start_node(ctx, label) do
    {pub, priv} = Crypto.mldsa_generate(:mldsa65)
    now = System.system_time(:second)
    cert = Cert.new(@mesh, label, pub, now - 100, now + 3600) |> Cert.sign(ctx.root_priv)

    {:ok, node} =
      Node.start_link(
        label: label,
        mesh: @mesh,
        root_public: ctx.root_pub,
        cert: cert,
        id_public: pub,
        id_private: priv,
        port: 0
      )

    on_exit(fn -> if Process.alive?(node), do: Node.stop(node) end)
    node
  end

  # Collects n payloads, or fails on timeout. Returns them in arrival order.
  defp collect(0, acc, _timeout), do: Enum.reverse(acc)

  defp collect(n, acc, timeout) do
    receive do
      {:bonemesh_data, payload} -> collect(n - 1, [payload | acc], timeout)
    after
      timeout -> Enum.reverse(acc)
    end
  end

  test "broadcast reaches every peer but never the sender", ctx do
    alpha = start_node(ctx, "alpha")
    beta = start_node(ctx, "beta")
    gamma = start_node(ctx, "gamma")

    # One mailbox receives for all three, so a payload arriving from alpha's own
    # listener would show up here too -- which is what the count assertion below
    # catches.
    Node.add_listener(beta, self())
    Node.add_listener(gamma, self())
    Node.add_listener(alpha, self())

    {:ok, "beta"} = Node.connect(alpha, "127.0.0.1", Node.port(beta))
    {:ok, "gamma"} = Node.connect(alpha, "127.0.0.1", Node.port(gamma))

    assert Node.broadcast(alpha, %{"m" => "all"}) == 2,
           "both peers should have been handed the message"

    # Exactly two deliveries, not three: the sender is not a target. Waiting for a
    # third with time allowed to pass is what proves the absence.
    got = collect(3, [], 1500)
    assert length(got) == 2, "expected 2 deliveries, got #{length(got)}: #{inspect(got)}"
    assert Enum.all?(got, &(&1["m"] == "all"))
  end

  test "broadcast gives each destination its own message id", ctx do
    # Forced, not stylistic: dedup keys on (mid, chunk index), so a shared mid would
    # have the first relay suppress every other copy, and an ack names only a mid.
    alpha = start_node(ctx, "alpha")
    beta = start_node(ctx, "beta")
    gamma = start_node(ctx, "gamma")

    Node.add_ack_listener(alpha, self())
    {:ok, "beta"} = Node.connect(alpha, "127.0.0.1", Node.port(beta))
    {:ok, "gamma"} = Node.connect(alpha, "127.0.0.1", Node.port(gamma))
    assert Node.broadcast(alpha, %{"m" => "all"}) == 2

    mids =
      for _ <- 1..2 do
        receive do
          {:bonemesh_ack, ack} -> ack["mid"]
        after
          5000 -> nil
        end
      end

    assert Enum.all?(mids, &is_binary(&1)), "expected one ack per destination: #{inspect(mids)}"
    assert length(Enum.uniq(mids)) == 2, "both destinations acked the same mid: #{inspect(mids)}"
  end

  test "broadcast with no peers reaches nobody", ctx do
    # The boundary: no reachable labels means a count of zero, not a node
    # broadcasting to itself -- which is precisely the D5 failure.
    alpha = start_node(ctx, "alpha")
    Node.add_listener(alpha, self())
    assert Node.broadcast(alpha, %{"m" => "all"}) == 0
    assert collect(1, [], 1000) == [], "a lone node broadcast to itself"
  end
end
