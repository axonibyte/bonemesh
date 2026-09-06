defmodule Bonemesh.NodeLifecycleTest do
  # Link registration lifecycle (protocol.md §3): register records who initiated
  # each link and stamps its liveness/idle clocks; a stale link's death must
  # never withdraw the live link's routes; and the env tunables seam reads its
  # knobs with pinned defaults. The stale-death case is driven at the handler
  # level with fake link pids and :sys.get_state so it is deterministic (no
  # dependence on the 1 s heartbeat, which would re-seed a wrongly-withdrawn
  # neighbor and mask the bug).
  use ExUnit.Case, async: false

  alias Bonemesh.{Cert, Crypto, Handshake, Node, Routing}

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

  # A throwaway process to stand in for a link owner in handler-level tests.
  defp fake_link do
    spawn(fn ->
      receive do
        _ -> :ok
      end
    end)
  end

  test "register records initiator and timestamps on both ends", ctx do
    before = System.system_time(:millisecond)
    alpha = start_node(ctx, "alpha")
    beta = start_node(ctx, "beta")
    {:ok, "beta"} = Node.connect(alpha, "127.0.0.1", Node.port(beta))

    # Wait for beta's accept-side link_up cast to land.
    wait_until(fn -> Map.has_key?(:sys.get_state(beta).links, "alpha") end, 3000)

    dialed = :sys.get_state(alpha).links["beta"]
    accepted = :sys.get_state(beta).links["alpha"]
    assert dialed.initiator == true, "dialer link must record initiator=true"
    assert accepted.initiator == false, "accepter link must record initiator=false"

    for e <- [dialed, accepted] do
      assert e.established_at >= before and e.last_inbound >= before and e.last_data >= before,
             "timestamps not initialized at register"
    end
  end

  test "a stale link's death does not withdraw the live link's routes", ctx do
    node = start_node(ctx, "self")
    p1 = fake_link()
    p2 = fake_link()

    # p1 registers, then p2 reconnects and displaces it (accept path => not
    # initiator; the flag value is irrelevant to this guard).
    GenServer.cast(node, {:link_up, "peer", p1})
    GenServer.cast(node, {:link_up, "peer", p2})
    st = :sys.get_state(node)
    assert st.links["peer"].pid == p2, "reconnect did not replace the link"
    assert Routing.next_hop(st.routing, "peer") == "peer", "peer must be a live neighbor"

    # p1's death arrives late (its socket finally closes) — it must NOT withdraw
    # the neighbor that p2 now owns.
    GenServer.cast(node, {:link_down, "peer", p1})
    st = :sys.get_state(node)
    assert st.links["peer"].pid == p2, "stale link_down removed the live link"
    assert Routing.next_hop(st.routing, "peer") == "peer",
           "stale link death withdrew the live neighbor"

    # Control: the current link's death does withdraw the neighbor — proves the
    # guard discriminates rather than never withdrawing.
    GenServer.cast(node, {:link_down, "peer", p2})
    st = :sys.get_state(node)
    assert Routing.next_hop(st.routing, "peer") == nil,
           "current link death failed to withdraw the neighbor"
  end

  test "a malformed transport frame tears the link down loudly (not swallowed)", ctx do
    node = start_node(ctx, "self")

    # Act as a real initiator so the node accepts us as a neighbor, then send a
    # frame the transport layer cannot open. P5: that error must close the link
    # (withdrawing the neighbor), not be swallowed and leave a wedged session.
    {pub, priv} = Crypto.mldsa_generate(:mldsa65)
    now = System.system_time(:second)
    cert = Cert.new(@mesh, "faker", pub, now - 100, now + 3600) |> Cert.sign(ctx.root_priv)

    {:ok, sock} =
      :gen_tcp.connect(~c"127.0.0.1", Node.port(node),
        [:binary, {:packet, :line}, {:active, false}, {:packet_size, 200_000}, {:buffer, 200_000}]
      )

    hs = Handshake.initiator(@mesh, ctx.root_pub, now, cert, pub, priv)
    {m1, hs} = Handshake.write_message1(hs)
    :ok = :gen_tcp.send(sock, m1)
    {:ok, m2} = :gen_tcp.recv(sock, 0, 5000)
    {:ok, m3, _hs} = Handshake.read_message2_write_message3(hs, m2)
    :ok = :gen_tcp.send(sock, m3)

    wait_until(fn -> Map.has_key?(:sys.get_state(node).links, "faker") end, 5000)
    assert Routing.next_hop(:sys.get_state(node).routing, "faker") == "faker"

    # A line the transport cannot decrypt (not even valid JSON).
    :ok = :gen_tcp.send(sock, "not-a-valid-transport-frame\n")

    wait_until(fn -> not Map.has_key?(:sys.get_state(node).links, "faker") end, 5000)
    assert Routing.next_hop(:sys.get_state(node).routing, "faker") == nil,
           "a malformed frame was swallowed: the link wedged instead of closing"

    :gen_tcp.close(sock)
  end

  test "tunables read env with pinned defaults", ctx do
    node = start_node(ctx, "self")
    t = :sys.get_state(node).tun
    assert t.probe_timeout_ms == 15_000
    assert t.idle_ms == 0
    assert t.retry_base_ms == 500
    assert t.retry_cap_ms == 30_000
    assert t.retry_max_ms == 60_000
    assert t.rekey_ms == 3_600_000
    assert t.rekey_frames == 65_536
    assert t.rekey_timeout_ms == 10_000

    System.put_env("BONEMESH_PROBE_TIMEOUT_MS", "1234")
    override = start_node(ctx, "self2")
    assert :sys.get_state(override).tun.probe_timeout_ms == 1234, "env override ignored"
    System.delete_env("BONEMESH_PROBE_TIMEOUT_MS")
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
end
