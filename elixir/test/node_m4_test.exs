defmodule Bonemesh.NodeM4Test do
  # M4 node features: F2 retry/backoff (protocol.md §7) and F5 periodic rekey
  # (security.md §6). Real nodes; env knobs are set per test before the node
  # starts (load_tunables reads them once at init).
  use ExUnit.Case, async: false

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

  defp wait_until(fun, timeout \\ 15_000) do
    deadline = System.monotonic_time(:millisecond) + timeout
    do_wait(fun, deadline)
  end

  defp do_wait(fun, deadline) do
    cond do
      fun.() -> :ok
      System.monotonic_time(:millisecond) >= deadline -> :timeout
      true -> Process.sleep(50); do_wait(fun, deadline)
    end
  end

  defp epoch(node, peer) do
    case :sys.get_state(node).links[String.downcase(peer)] do
      %{rekey_epoch: e} -> e
      _ -> -1
    end
  end

  # F2: a message sent before its destination is routable is delivered once a
  # route appears, via a later heartbeat drain.
  test "retry delivers after a route appears", ctx do
    System.put_env("BONEMESH_RETRY_BASE_MS", "100")
    on_exit(fn -> System.delete_env("BONEMESH_RETRY_BASE_MS") end)

    alpha = start_node(ctx, "alpha")
    beta = start_node(ctx, "beta")
    Node.add_listener(beta, self())

    refute Node.send(alpha, "beta", %{"m" => "queued"})
    {:ok, "beta"} = Node.connect(alpha, "127.0.0.1", Node.port(beta))

    assert :ok == await(&(&1["m"] == "queued"), 10_000)
  end

  # F2: a never-routable message is dropped at its lifetime cap and reported to
  # the origin's ack listener as a synthesized nak{reason:"expired"}.
  test "retry reports expired to the ack listener", ctx do
    System.put_env("BONEMESH_RETRY_BASE_MS", "50")
    System.put_env("BONEMESH_RETRY_MAX_MS", "200")
    on_exit(fn ->
      System.delete_env("BONEMESH_RETRY_BASE_MS")
      System.delete_env("BONEMESH_RETRY_MAX_MS")
    end)

    alpha = start_node(ctx, "alpha")
    Node.add_ack_listener(alpha, self())
    refute Node.send(alpha, "ghost", %{"m" => "doomed"})

    assert_receive {:bonemesh_ack, %{"type" => "nak", "reason" => "expired"}}, 5_000
  end

  # F2 disabled: with retry_max_ms==0 nothing is queued.
  test "retry disabled queues nothing", ctx do
    System.put_env("BONEMESH_RETRY_MAX_MS", "0")
    on_exit(fn -> System.delete_env("BONEMESH_RETRY_MAX_MS") end)

    alpha = start_node(ctx, "alpha")
    refute Node.send(alpha, "ghost", %{"m" => "x"})
    assert :sys.get_state(alpha).pending == %{}
  end

  # F5: under a low frame threshold the session initiator rekeys the live link;
  # both ends advance their rekey epoch and delivery continues across the swap.
  test "rekey under traffic advances epoch and keeps delivering", ctx do
    System.put_env("BONEMESH_REKEY_FRAMES", "6")
    on_exit(fn -> System.delete_env("BONEMESH_REKEY_FRAMES") end)

    alpha = start_node(ctx, "alpha")
    beta = start_node(ctx, "beta")
    Node.add_listener(beta, self())
    {:ok, "beta"} = Node.connect(alpha, "127.0.0.1", Node.port(beta))

    assert :ok == wait_until(fn -> epoch(alpha, "beta") >= 1 and epoch(beta, "alpha") >= 1 end)

    # Delivery must still work on the post-rekey keys.
    assert :ok == wait_until(fn -> Node.send(alpha, "beta", %{"m" => "after-rekey"}) end)
    assert :ok == await(&(&1["m"] == "after-rekey"), 5_000)
  end

  defp await(match, timeout) do
    receive do
      {:bonemesh_data, payload} -> if match.(payload), do: :ok, else: await(match, timeout)
    after
      timeout -> :timeout
    end
  end
end
