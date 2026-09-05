defmodule Bonemesh.NodeTest do
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

  defp await_data(match, timeout) do
    receive do
      {:bonemesh_data, payload} -> if match.(payload), do: :ok, else: await_data(match, timeout)
    after
      timeout -> :timeout
    end
  end

  test "two nodes exchange messages both directions", ctx do
    alpha = start_node(ctx, "alpha")
    beta = start_node(ctx, "beta")
    Node.add_listener(alpha, self())
    Node.add_listener(beta, self())

    {:ok, "beta"} = Node.connect(alpha, "127.0.0.1", Node.port(beta))

    assert Node.send(alpha, "beta", %{"m" => "ping"})
    assert :ok == await_data(&(&1["m"] == "ping"), 5000)

    assert Node.send(beta, "alpha", %{"m" => "pong"})
    assert :ok == await_data(&(&1["m"] == "pong"), 5000)
  end

  test "three node line relays across the middle hop", ctx do
    alpha = start_node(ctx, "alpha")
    beta = start_node(ctx, "beta")
    gamma = start_node(ctx, "gamma")
    Node.add_listener(gamma, self())

    {:ok, "beta"} = Node.connect(alpha, "127.0.0.1", Node.port(beta))
    {:ok, "beta"} = Node.connect(gamma, "127.0.0.1", Node.port(beta))

    # Wait for discovery to give alpha a route to gamma via beta.
    deadline = System.monotonic_time(:millisecond) + 15_000
    routed = wait_route(alpha, deadline)
    assert routed, "alpha never learned a route to gamma"
    assert :ok == await_data(&(&1["m"] == "relayed"), 5000)

    # The route to the non-neighbor gamma is via the middle hop beta — the
    # accessor the interop convergence tier reads.
    assert Node.routes(alpha)["gamma"] == "beta"
  end

  defp wait_route(alpha, deadline) do
    if Node.send(alpha, "gamma", %{"m" => "relayed"}) do
      true
    else
      if System.monotonic_time(:millisecond) < deadline do
        Process.sleep(200)
        wait_route(alpha, deadline)
      else
        false
      end
    end
  end

  test "large payload is chunked and reassembled end to end", ctx do
    alpha = start_node(ctx, "alpha")
    beta = start_node(ctx, "beta")
    Node.add_listener(beta, self())

    blob = String.duplicate("abcdefghij", 20_000) # 200 KB, well past the frame cap
    {:ok, "beta"} = Node.connect(alpha, "127.0.0.1", Node.port(beta))
    assert Node.send(alpha, "beta", %{"blob" => blob})
    assert :ok == await_data(&(&1["blob"] == blob), 10_000)
  end
end
