defmodule Bonemesh.TransportFaultTest do
  # A transport-level fault tears the session down and names the reason
  # (protocol.md §4 and §8).
  #
  # Elixir already closed on such a fault (node_lifecycle_test.exs proves the
  # teardown); what is new here is that the peer is told WHY instead of inferring
  # it from a dropped socket. As there, the test acts as a real initiator over a
  # raw socket, because the link process owns the session and there is no seam
  # into it from outside.
  #
  # The injection is a seq gap rather than a flipped ciphertext byte: it is
  # deterministic and it exercises the ordering rule §4 actually states. Both
  # reach the same :error in safe_open.
  #
  # What these tests do NOT prove: that the node re-dials and recovers. That is
  # tier 10's job. The claim here is narrower — the reason reaches the far end,
  # and an inner type the node merely does not recognize produces no close at all.
  use ExUnit.Case, async: false

  alias Bonemesh.{Cert, Crypto, Frame, Handshake, Message, Node, Transport}

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

    # Same teardown contract as node_lifecycle_test.exs: a node linked to the test
    # process may already be gone, and only the "already gone" reasons are treated
    # as success.
    on_exit(fn ->
      try do
        if Process.alive?(node), do: Node.stop(node)
      catch
        :exit, {reason, _} when reason in [:shutdown, :noproc, :normal] -> :ok
        :exit, reason when reason in [:shutdown, :noproc, :normal] -> :ok
      end
    end)

    node
  end

  # Completes a real BMX handshake as the initiator and returns the socket plus
  # the established transport session, so the test can both craft frames the node
  # will read and open the frames it writes.
  defp handshake(ctx, node, label) do
    {pub, priv} = Crypto.mldsa_generate(:mldsa65)
    now = System.system_time(:second)
    cert = Cert.new(@mesh, label, pub, now - 100, now + 3600) |> Cert.sign(ctx.root_priv)

    {:ok, sock} =
      :gen_tcp.connect(
        ~c"127.0.0.1",
        Node.port(node),
        [:binary, {:packet, :line}, {:active, false}, {:packet_size, 200_000}, {:buffer, 200_000}]
      )

    hs = Handshake.initiator(@mesh, ctx.root_pub, now, cert, pub, priv)
    {m1, hs} = Handshake.write_message1(hs)
    :ok = :gen_tcp.send(sock, m1)
    {:ok, m2} = :gen_tcp.recv(sock, 0, 5000)
    {:ok, m3, hs} = Handshake.read_message2_write_message3(hs, m2)
    :ok = :gen_tcp.send(sock, m3)

    wait_until(fn -> Map.has_key?(:sys.get_state(node).links, label) end, 5000)
    {sock, Transport.session(Handshake.session(hs))}
  end

  # Reads inner messages until a bye arrives or the window closes, returning
  # {bye_or_nil, session}. Frames must be opened in arrival order (§4's window is
  # exactly one), and the node's heartbeat interleaves probe and disco traffic
  # with whatever the test waits for — so the oracle cannot be "the next frame is
  # the bye". The window is wall-clock, so a test waiting for "no bye" cannot run
  # long enough for the 15 s probe-timeout sweep to close the link for an
  # unrelated reason.
  defp read_until_bye(sock, session, window_ms) do
    deadline = System.monotonic_time(:millisecond) + window_ms
    do_read_until_bye(sock, session, deadline)
  end

  defp do_read_until_bye(sock, session, deadline) do
    left = deadline - System.monotonic_time(:millisecond)

    if left <= 0 do
      {nil, session}
    else
      case :gen_tcp.recv(sock, 0, min(left, 500)) do
        {:ok, line} ->
          case JSON.decode(String.trim(line)) do
            {:ok, carrier} ->
              case Transport.open(session, carrier) do
                {:ok, %{"type" => "bye"} = bye, session} -> {bye, session}
                {:ok, _other, session} -> do_read_until_bye(sock, session, deadline)
                {:error, _} -> {nil, session}
              end

            {:error, _} ->
              {nil, session}
          end

        {:error, :timeout} ->
          do_read_until_bye(sock, session, deadline)

        {:error, _closed} ->
          {nil, session}
      end
    end
  end

  test "an out-of-order frame tears the session down, named protocol-error", ctx do
    node = start_node(ctx, "self")
    {sock, session} = handshake(ctx, node, "faker")

    # Burn one send seq without writing it, so the next frame arrives as a gap.
    {_unsent, session} = Transport.seal(session, Message.probe(1))

    {carrier, session} =
      Transport.seal(session, Message.data("m-gap", "faker", "self", 16, %{"x" => 1}))

    :ok = :gen_tcp.send(sock, Frame.encode(carrier))

    # Oracle 1: the reason is read off the wire, not inferred from the close.
    {bye, _session} = read_until_bye(sock, session, 5000)
    assert bye != nil, "the node closed the session without saying why"
    assert bye["reason"] == "protocol-error", "wrong close reason: #{inspect(bye)}"

    # Oracle 2: the session is gone, not merely silent.
    wait_until(fn -> not Map.has_key?(:sys.get_state(node).links, "faker") end, 5000)

    refute Map.has_key?(:sys.get_state(node).links, "faker"),
           "the node kept a session whose nonce stream it can never follow again"

    :gen_tcp.close(sock)
  end

  # §8 requires ignoring inner types a node does not recognize, so an unknown type
  # is NOT a protocol error. This guards the test above: making every unparseable
  # thing close the link would break forward compatibility.
  test "an unrecognized inner type does not close the session", ctx do
    node = start_node(ctx, "self")
    {sock, session} = handshake(ctx, node, "faker")

    {carrier, session} =
      Transport.seal(session, %{"type" => "quux-from-the-future", "mid" => "m1"})

    :ok = :gen_tcp.send(sock, Frame.encode(carrier))

    # Assert the absence with time allowed to pass.
    {bye, session} = read_until_bye(sock, session, 2000)
    assert bye == nil, "the node sent a bye over an inner type it must ignore"

    assert Map.has_key?(:sys.get_state(node).links, "faker"),
           "the node closed a session over an inner type it is required to ignore"

    # And the link still carries traffic, rather than merely still being listed:
    # a probe must draw an echo.
    {carrier, session} = Transport.seal(session, Message.probe(42))
    :ok = :gen_tcp.send(sock, Frame.encode(carrier))
    assert await_echo(sock, session, 5000), "the link survived but carried nothing after"

    :gen_tcp.close(sock)
  end

  # D21: a frame over §0's transport cap is refused and named. Nothing on this
  # port's link path enforced that cap -- `Frame.transport_cap/0` was called only
  # by the corpus checker, and the socket's {:packet, :line} `packet_size` bounded
  # a line at 200000 instead.
  test "a frame over the transport cap is refused and named", ctx do
    node = start_node(ctx, "self")
    {sock, session} = handshake(ctx, node, "faker")

    # A syntactically valid carrier that is simply too big. It is sealed properly,
    # so the only thing wrong with it is its size -- which is the point: a cap
    # check that only fires on garbage would not catch this.
    {carrier, session} =
      Transport.seal(session, Message.data("m-big", "faker", "self", 16, %{
        "x" => String.duplicate("y", Frame.transport_cap())
      }))

    :ok = :gen_tcp.send(sock, Frame.encode(carrier))

    {bye, _session} = read_until_bye(sock, session, 5000)
    assert bye != nil, "an oversize frame produced no bye at all"
    assert bye["reason"] == "protocol-error", "wrong close reason: #{inspect(bye)}"

    wait_until(fn -> not Map.has_key?(:sys.get_state(node).links, "faker") end, 5000)

    refute Map.has_key?(:sys.get_state(node).links, "faker"),
           "the node kept a session after a frame over the cap"

    :gen_tcp.close(sock)
  end

  defp await_echo(sock, session, window_ms) do
    deadline = System.monotonic_time(:millisecond) + window_ms
    do_await_echo(sock, session, deadline)
  end

  defp do_await_echo(sock, session, deadline) do
    left = deadline - System.monotonic_time(:millisecond)

    if left <= 0 do
      false
    else
      case :gen_tcp.recv(sock, 0, min(left, 500)) do
        {:ok, line} ->
          with {:ok, carrier} <- JSON.decode(String.trim(line)),
               {:ok, inner, session} <- Transport.open(session, carrier) do
            if inner["type"] == "echo" and inner["token"] == 42,
              do: true,
              else: do_await_echo(sock, session, deadline)
          else
            _ -> false
          end

        {:error, :timeout} ->
          do_await_echo(sock, session, deadline)

        {:error, _} ->
          false
      end
    end
  end

  defp wait_until(fun, timeout) do
    deadline = System.monotonic_time(:millisecond) + timeout

    Stream.repeatedly(fn ->
      if fun.(), do: :done, else: (Process.sleep(20); :again)
    end)
    |> Enum.find(fn r ->
      r == :done or System.monotonic_time(:millisecond) > deadline
    end)
  end
end
