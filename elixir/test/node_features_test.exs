defmodule Bonemesh.NodeFeaturesTest do
  # M3 node features (protocol.md §3, §7): the simultaneous-dial tiebreak (F1),
  # probe-timeout liveness death (F3), idle teardown (F4), and ack/NAK emission
  # with per-hop failure attribution (F6/D4). F1/F3/F4 are driven at the handler
  # level (casts + :sys state) so they are deterministic; F6 uses real nodes.
  use ExUnit.Case, async: false

  alias Bonemesh.{Cert, Crypto, Node, Routing}

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

  defp fake_link do
    spawn(fn -> loop() end)
  end

  defp loop do
    receive do
      _ -> loop()
    end
  end

  defp inject_link(node, key, entry, neighbor?) do
    :sys.replace_state(node, fn s ->
      routing = if neighbor?, do: Routing.observe_neighbor(s.routing, key, 1), else: s.routing
      %{s | links: Map.put(s.links, key, entry), routing: routing}
    end)
  end

  defp set_tun(node, kv) do
    :sys.replace_state(node, fn s -> %{s | tun: Enum.into(kv, s.tun)} end)
  end

  defp wait_until(fun, timeout) do
    deadline = System.monotonic_time(:millisecond) + timeout
    do_wait = fn do_wait ->
      cond do
        fun.() -> :ok
        System.monotonic_time(:millisecond) >= deadline -> flunk("condition not met in time")
        true -> Process.sleep(20); do_wait.(do_wait)
      end
    end
    do_wait.(do_wait)
  end

  # F1: on a dial collision both ends keep the session initiated by the
  # lower-labelled node. self="self": against a higher peer ("zzz") self keeps
  # its own-initiated link; against a lower peer ("aaa") it keeps the accepted
  # one. Driven by injecting an initiator=true link then casting a link_up
  # (initiator=false) for the same peer — the opposite-initiator collision.
  test "tiebreak keeps the lower-label-initiated session", ctx do
    node = start_node(ctx, "self")
    now = System.system_time(:millisecond)

    p1 = fake_link()
    inject_link(node, "zzz", %{pid: p1, initiator: true, established_at: now, last_inbound: now, last_data: now}, true)
    GenServer.cast(node, {:link_up, "zzz", fake_link()})
    st = :sys.get_state(node)
    assert st.links["zzz"].pid == p1, "self<peer: must keep the self-initiated link"
    assert st.links["zzz"].initiator == true

    p3 = fake_link()
    inject_link(node, "aaa", %{pid: p3, initiator: true, established_at: now, last_inbound: now, last_data: now}, true)
    p4 = fake_link()
    GenServer.cast(node, {:link_up, "aaa", p4})
    st = :sys.get_state(node)
    assert st.links["aaa"].pid == p4, "self>peer: must keep the peer-initiated (accepted) link"
    assert st.links["aaa"].initiator == false
  end

  # F3: a link silent past the probe timeout is torn down on the next heartbeat
  # and its routes withdrawn; a fresh link survives.
  test "probe timeout tears down a silent link", ctx do
    node = start_node(ctx, "self")
    set_tun(node, probe_timeout_ms: 100, idle_ms: 0)
    now = System.system_time(:millisecond)

    fresh = fake_link()
    inject_link(node, "fresh", %{pid: fresh, initiator: true, established_at: now, last_inbound: now, last_data: now}, true)
    silent = fake_link()
    old = now - 1_000_000
    inject_link(node, "silent", %{pid: silent, initiator: true, established_at: old, last_inbound: old, last_data: old}, true)

    send(node, :heartbeat)
    st = :sys.get_state(node)
    refute Map.has_key?(st.links, "silent"), "probe-timed-out link not torn down"
    assert Routing.next_hop(st.routing, "silent") == nil, "silent neighbor not withdrawn"
    assert Map.has_key?(st.links, "fresh"), "fresh link wrongly torn down"
  end

  # F4: idle teardown fires only when enabled (idle_ms > 0).
  test "idle teardown fires only when enabled", ctx do
    now = System.system_time(:millisecond)
    old = now - 1_000_000

    enabled = start_node(ctx, "self")
    set_tun(enabled, probe_timeout_ms: 1_000_000, idle_ms: 100)
    p = fake_link()
    inject_link(enabled, "peer", %{pid: p, initiator: true, established_at: old, last_inbound: now, last_data: old}, true)
    send(enabled, :heartbeat)
    refute Map.has_key?(:sys.get_state(enabled).links, "peer"), "idle link not torn down when enabled"

    disabled = start_node(ctx, "self")
    set_tun(disabled, probe_timeout_ms: 1_000_000, idle_ms: 0)
    q = fake_link()
    inject_link(disabled, "peer", %{pid: q, initiator: true, established_at: old, last_inbound: now, last_data: old}, true)
    send(disabled, :heartbeat)
    assert Map.has_key?(:sys.get_state(disabled).links, "peer"), "idle teardown fired though disabled"
  end

  # F6: the destination's ack reaches the origin's ack listener, correlated by
  # the mid send_mid returned.
  test "ack reaches the origin ack listener", ctx do
    alpha = start_node(ctx, "alpha")
    beta = start_node(ctx, "beta")
    Node.add_ack_listener(alpha, self())
    {:ok, "beta"} = Node.connect(alpha, "127.0.0.1", Node.port(beta))

    mid = send_mid_when_routable(alpha, "beta", %{"m" => "hi"})
    assert_receive {:bonemesh_ack, %{"type" => "ack", "mid" => ^mid}}, 5000
  end

  # F6/D4: when a relay drops a message on TTL exhaustion, the NAK returned to
  # the origin names the RELAY as the failing hop, never the destination.
  test "nak names the failing relay, not the destination", ctx do
    alpha = start_node(ctx, "alpha")
    beta = start_node(ctx, "beta")
    gamma = start_node(ctx, "gamma")
    Node.add_ack_listener(alpha, self())

    {:ok, "beta"} = Node.connect(alpha, "127.0.0.1", Node.port(beta))
    {:ok, "beta"} = Node.connect(gamma, "127.0.0.1", Node.port(beta))
    wait_until(fn -> Node.routes(alpha)["gamma"] == "beta" end, 15_000)

    {:ok, mid} = Node.send_with_ttl(alpha, "gamma", %{"m" => "doomed"}, 1)
    assert_receive {:bonemesh_ack, %{"type" => "nak", "hop" => "beta", "reason" => "ttl", "mid" => ^mid}}, 5000
  end

  defp send_mid_when_routable(node, to, payload) do
    deadline = System.monotonic_time(:millisecond) + 15_000
    do_send = fn do_send ->
      case Node.send_mid(node, to, payload) do
        {:ok, mid} ->
          mid

        :error ->
          if System.monotonic_time(:millisecond) >= deadline do
            flunk("never routable to #{to}")
          else
            Process.sleep(100)
            do_send.(do_send)
          end
      end
    end
    do_send.(do_send)
  end
end
