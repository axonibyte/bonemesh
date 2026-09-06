defmodule Bonemesh.Node do
  @moduledoc """
  A BoneMesh v3 mesh node (protocol.md §3): the facade tying the handshake,
  transport, message, and routing layers together over TCP. A node holds one
  authenticated, encrypted session per neighbor (each owned by a link process),
  delivers messages addressed to itself to its listeners, relays the rest toward
  the next hop, and runs a heartbeat that probes neighbors for RTT and advertises
  reachability.

  Wire-compatible with the Java reference: an Elixir node and a Java node
  interoperate.
  """

  use GenServer

  alias Bonemesh.{Frame, Handshake, Message, Routing, Transport}

  @heartbeat_ms 1000
  @dedup_cap 4096

  # --- Public API ---

  @doc """
  Starts a node. `opts` requires :label, :mesh, :root_public, :cert,
  :id_public, :id_private; :port defaults to 0 (ephemeral).
  """
  def start_link(opts), do: GenServer.start_link(__MODULE__, opts)

  @doc "The port the node listens on."
  def port(node), do: GenServer.call(node, :port)

  @doc "Registers a listener pid; it receives `{:bonemesh_data, payload}`."
  def add_listener(node, pid), do: GenServer.cast(node, {:add_listener, pid})

  @doc "Dials a peer and completes the handshake as initiator. Returns `{:ok, label}`."
  def connect(node, host, port), do: GenServer.call(node, {:connect, host, port}, 15_000)

  @doc "Sends an application payload toward `to`. Returns true if routed."
  def send(node, to, payload), do: GenServer.call(node, {:send, to, payload})

  @doc """
  Sends like `send/3` but returns `{:ok, mid}` (the message id, for correlating
  the ack/nak delivered to an ack listener) or `:error` if unroutable.
  """
  def send_mid(node, to, payload), do: GenServer.call(node, {:send_mid, to, payload})

  @doc "Sends with an explicit initial TTL (used by tests to force a relay NAK)."
  def send_with_ttl(node, to, payload, ttl),
    do: GenServer.call(node, {:send_with_ttl, to, payload, ttl})

  @doc "Registers a pid to receive `{:bonemesh_ack, inner}` for ack/nak addressed here."
  def add_ack_listener(node, pid), do: GenServer.cast(node, {:add_ack_listener, pid})

  @doc "A snapshot of the routing table: destination => next-hop label."
  def routes(node), do: GenServer.call(node, :routes)

  @doc "Stops the node."
  def stop(node), do: GenServer.stop(node)

  # --- GenServer ---

  @impl true
  def init(opts) do
    label = Keyword.fetch!(opts, :label)
    {:ok, listen} = :gen_tcp.listen(Keyword.get(opts, :port, 0), tcp_opts())
    {:ok, port} = :inet.port(listen)

    state = %{
      label: label,
      mesh: Keyword.fetch!(opts, :mesh),
      root_public: Keyword.fetch!(opts, :root_public),
      cert: Keyword.fetch!(opts, :cert),
      id_public: Keyword.fetch!(opts, :id_public),
      id_private: Keyword.fetch!(opts, :id_private),
      listen: listen,
      port: port,
      tun: load_tunables(),
      routing: Routing.new(label),
      # links: downcased label => %{pid, initiator, established_at,
      # last_inbound, last_data} (protocol.md §3 — the tiebreak/liveness/idle
      # features need who initiated each link and when it last carried traffic).
      links: %{},
      dedup: {MapSet.new(), :queue.new()},
      reassembler: %{},
      listeners: [],
      ack_listeners: []
    }

    config = Map.take(state, [:mesh, :root_public, :cert, :id_public, :id_private])
    me = self()
    spawn_link(fn -> accept_loop(listen, me, config) end)
    :timer.send_interval(@heartbeat_ms, :heartbeat)
    {:ok, state}
  end

  @impl true
  def handle_call(:port, _from, s), do: {:reply, s.port, s}

  def handle_call(:routes, _from, s) do
    table = for dest <- Map.keys(s.routing.routes), into: %{}, do: {dest, Routing.next_hop(s.routing, dest)}
    {:reply, table, s}
  end

  def handle_call({:connect, host, port}, _from, s) do
    case dial(host, port, s) do
      {:ok, peer, socket, session} ->
        {:reply, {:ok, peer}, register_link(s, peer, socket, session)}

      {:error, reason} ->
        {:reply, {:error, reason}, s}
    end
  end

  def handle_call({:send, to, payload}, _from, s) do
    {ok, _mid, s} = do_send(s, to, payload)
    {:reply, ok, s}
  end

  def handle_call({:send_mid, to, payload}, _from, s) do
    {ok, mid, s} = do_send(s, to, payload)
    {:reply, (if ok, do: {:ok, mid}, else: :error), s}
  end

  def handle_call({:send_with_ttl, to, payload, ttl}, _from, s) do
    mid = Message.new_mid()
    {ok, s} = forward(s, Message.data(mid, s.label, to, ttl, payload))
    {:reply, (if ok, do: {:ok, mid}, else: :error), s}
  end

  @impl true
  def handle_cast({:add_listener, pid}, s), do: {:noreply, %{s | listeners: [pid | s.listeners]}}

  def handle_cast({:add_ack_listener, pid}, s),
    do: {:noreply, %{s | ack_listeners: [pid | s.ack_listeners]}}

  def handle_cast({:link_up, peer, pid}, s), do: {:noreply, register_link_pid(s, peer, pid, false)}

  # An inbound frame proves the peer alive; stamp the link's liveness clock
  # (and its data clock if it was a data frame) — but only if the frame came
  # from the link that is currently registered for this peer.
  def handle_cast({:inbound, peer, pid, inner}, s) do
    key = String.downcase(peer)
    now = System.system_time(:millisecond)

    s =
      case s.links[key] do
        %{pid: ^pid} = e ->
          e = %{e | last_inbound: now}
          e = if inner["type"] == "data", do: %{e | last_data: now}, else: e
          %{s | links: Map.put(s.links, key, e)}

        _ ->
          s
      end

    # F4: a peer's graceful close tears down that link (pid-guarded), no reply.
    if inner["type"] == "bye" do
      {:noreply, teardown(s, key, pid)}
    else
      {:noreply, handle_inner(s, peer, inner)}
    end
  end

  # Withdraw routes on a link's death only if it is still the current link for
  # its peer — a reconnect may have replaced it, and a stale link's death must
  # not withdraw the live link's routes.
  def handle_cast({:link_down, peer, pid}, s) do
    key = String.downcase(peer)

    case s.links[key] do
      %{pid: ^pid} ->
        {:noreply,
         %{s | links: Map.delete(s.links, key), routing: Routing.remove_neighbor(s.routing, peer)}}

      _ ->
        {:noreply, s}
    end
  end

  @impl true
  def handle_info(:heartbeat, s) do
    now = System.system_time(:millisecond)
    s = Enum.reduce(Map.to_list(s.links), s, fn {label, link}, acc -> sweep_link(acc, now, label, link) end)
    {:noreply, s}
  end

  def handle_info(_msg, s), do: {:noreply, s}

  # Once-per-heartbeat maintenance for one link: tear it down if probe-timeout
  # dead (F3) or data-idle past the idle timeout (F4, disabled at idle_ms==0),
  # otherwise send it a probe and a route advertisement.
  defp sweep_link(s, now, label, %{pid: pid} = link) do
    cond do
      now - link.last_inbound > s.tun.probe_timeout_ms ->
        teardown(s, label, pid)

      s.tun.idle_ms > 0 and now - link.last_data > s.tun.idle_ms ->
        Kernel.send(pid, {:send, Message.bye("idle")})
        teardown(s, label, pid)

      true ->
        Kernel.send(pid, {:send, Message.probe(now)})
        Kernel.send(pid, {:send, Message.disco(Routing.advertise_to(s.routing, label))})
        s
    end
  end

  # Tears down a link: closes its process and withdraws its routes, but only if
  # it is still the registered link for its peer (pid-guarded against a
  # concurrent replacement).
  defp teardown(s, key, pid) do
    case s.links[key] do
      %{pid: ^pid} ->
        Kernel.send(pid, :close)
        %{s | links: Map.delete(s.links, key), routing: Routing.remove_neighbor(s.routing, key)}

      _ ->
        s
    end
  end

  # --- Internals ---

  defp handle_inner(s, _peer, %{"type" => "data"} = m) do
    chunk_index = get_in(m, ["chunk", "i"]) || -1
    # Type-prefixed dedup key so a relayed ack/nak carrying the same mid as the
    # data it answers does not collide with it (protocol.md §7).
    key = "d:" <> m["mid"] <> ":" <> Integer.to_string(chunk_index)

    if seen?(s.dedup, key) do
      s
    else
      s = %{s | dedup: remember(s.dedup, key)}
      route_data(s, m)
    end
  end

  defp handle_inner(s, _peer, %{"type" => "ack"} = m), do: handle_control(s, m, "a:")
  defp handle_inner(s, _peer, %{"type" => "nak"} = m), do: handle_control(s, m, "n:")

  defp handle_inner(s, peer, %{"type" => "probe", "token" => token}) do
    send_to_link(s, peer, Message.echo(token))
    s
  end

  defp handle_inner(s, peer, %{"type" => "echo", "token" => token}) do
    rtt = max(0, System.system_time(:millisecond) - token)
    %{s | routing: Routing.observe_neighbor(s.routing, peer, rtt)}
  end

  defp handle_inner(s, peer, %{"type" => "disco", "routes" => routes}) do
    routing =
      Enum.reduce(routes, s.routing, fn {dest, cost}, r -> Routing.learn_route(r, dest, peer, cost) end)

    %{s | routing: routing}
  end

  defp handle_inner(s, _peer, _other), do: s

  defp route_data(s, m) do
    if String.downcase(m["to"]) == String.downcase(s.label) do
      case Message.reassemble(s.reassembler, m) do
        {:complete, payload, acc} ->
          for pid <- s.listeners, do: Kernel.send(pid, {:bonemesh_data, payload})
          s = %{s | reassembler: acc}
          # F6: acknowledge receipt back toward the origin.
          from = m["from"]

          if is_binary(from) and String.downcase(from) != String.downcase(s.label) do
            route_control(s, Message.ack_to(m["mid"], s.label, from, Message.default_ttl()))
          else
            s
          end

        {:incomplete, acc} ->
          %{s | reassembler: acc}
      end
    else
      ttl = m["ttl"] - 1
      origin = m["from"]

      cond do
        # F6/D4: the relay that dropped it names itself as the failing hop.
        ttl <= 0 -> emit_nak(s, m["mid"], origin, "ttl")
        Routing.next_hop(s.routing, m["to"]) == nil -> emit_nak(s, m["mid"], origin, "no-route")
        true -> elem(forward(s, Map.put(m, "ttl", ttl)), 1)
      end
    end
  end

  # Delivers or relays a freshly-arrived payload; builds the mid and threads
  # state. Returns {routed?, mid, state}.
  defp do_send(s, to, payload) do
    mid = Message.new_mid()
    msgs = Message.split(mid, s.label, to, Message.default_ttl(), payload)

    {ok, s} =
      Enum.reduce(msgs, {true, s}, fn m, {acc, st} ->
        {sent, st} = forward(st, m)
        {sent and acc, st}
      end)

    {ok, mid, s}
  end

  # Relays or delivers an ack/nak (routed back toward the origin like data). A
  # type-prefixed dedup key keeps a relayed ack from colliding with the data it
  # answers. ack/nak are never themselves ack'd or nak'd.
  defp handle_control(s, m, prefix) do
    key = prefix <> m["mid"]

    cond do
      seen?(s.dedup, key) ->
        s

      String.downcase(m["to"]) == String.downcase(s.label) ->
        s = %{s | dedup: remember(s.dedup, key)}
        for pid <- s.ack_listeners, do: Kernel.send(pid, {:bonemesh_ack, m})
        s

      true ->
        s = %{s | dedup: remember(s.dedup, key)}
        ttl = m["ttl"] - 1

        if ttl > 0 and Routing.next_hop(s.routing, m["to"]) != nil do
          elem(forward(s, Map.put(m, "ttl", ttl)), 1)
        else
          s
        end
    end
  end

  # emit_nak sends a NAK back toward the origin naming this node as the failing
  # hop; best-effort, dropped if unroutable (no recursion).
  defp emit_nak(s, mid, origin, reason) do
    if is_binary(origin) and String.downcase(origin) != String.downcase(s.label) do
      route_control(s, Message.nak(mid, s.label, origin, s.label, reason, Message.default_ttl()))
    else
      s
    end
  end

  # route_control sends a freshly-built ack/nak toward its destination, dropping
  # silently if there is no route.
  defp route_control(s, m) do
    case Routing.next_hop(s.routing, m["to"]) do
      nil -> s
      next -> elem(send_to_link(s, next, m), 1)
    end
  end

  # Returns {routed?, state}: state may change because sending a data frame
  # stamps the destination link's data-activity clock (for idle teardown).
  defp forward(s, m) do
    case Routing.next_hop(s.routing, m["to"]) do
      nil -> {false, s}
      next -> send_to_link(s, next, m)
    end
  end

  defp send_to_link(s, label, inner) do
    key = String.downcase(label)

    case s.links[key] do
      nil ->
        {false, s}

      %{pid: pid} = e ->
        Kernel.send(pid, {:send, inner})

        s =
          if inner["type"] == "data",
            do: %{s | links: Map.put(s.links, key, %{e | last_data: System.system_time(:millisecond)})},
            else: s

        {true, s}
    end
  end

  defp register_link(s, peer, socket, session) do
    pid = start_link_process(self(), peer, socket, Transport.session(session))
    register_link_pid(s, peer, pid, true)
  end

  # Spawns a link process, transfers socket ownership to it, and releases it.
  # The caller must currently own the socket.
  defp start_link_process(node, peer, socket, session) do
    pid =
      spawn(fn ->
        receive do
          :go ->
            :inet.setopts(socket, active: :once)
            link_loop(node, peer, socket, session)
        end
      end)

    :ok = :gen_tcp.controlling_process(socket, pid)
    Kernel.send(pid, :go)
    pid
  end

  defp register_link_pid(s, peer, pid, initiator) do
    key = String.downcase(peer)
    now = System.system_time(:millisecond)
    existing = s.links[key]

    # F1 simultaneous-dial tiebreak: if the two links were initiated by opposite
    # sides it is a genuine collision, and both ends deterministically keep the
    # session initiated by the lexicographically-lower label, so the pair
    # converges on one session. Same-initiator is a reconnect: last writer wins.
    keep_new =
      case existing do
        %{initiator: prev} when prev != initiator ->
          self_wins = String.downcase(s.label) < key
          initiator == self_wins

        _ ->
          true
      end

    if keep_new do
      # A reconnect (or a collision the new link won) displaces the old link:
      # tell it to close so its socket does not linger. Its {:link_down} is
      # pid-guarded, so its death cannot withdraw this new link's routes.
      case existing do
        %{pid: old} when old != pid -> Kernel.send(old, :close)
        _ -> :ok
      end

      entry = %{
        pid: pid,
        initiator: initiator,
        established_at: now,
        last_inbound: now,
        last_data: now
      }

      %{s | links: Map.put(s.links, key, entry), routing: Routing.observe_neighbor(s.routing, peer, 1)}
    else
      # The new link lost the tiebreak; close it and keep the existing one.
      Kernel.send(pid, :close)
      s
    end
  end

  # A neighbor link: owns the socket + transport session, relays inbound inner
  # messages to the node, and seals outbound ones on request.
  defp link_loop(node, peer, socket, session) do
    receive do
      {:tcp, ^socket, line} ->
        case safe_open(session, line) do
          {:ok, inner, session} ->
            GenServer.cast(node, {:inbound, peer, self(), inner})
            :inet.setopts(socket, active: :once)
            link_loop(node, peer, socket, session)

          :error ->
            # A frame that violates the transport expectation (bad JSON or a
            # seq desync) closes the connection loudly rather than being
            # swallowed — a swallowed error would wedge the link forever
            # (protocol.md §2). The node re-dials on demand.
            :gen_tcp.close(socket)
            GenServer.cast(node, {:link_down, peer, self()})
        end

      {:send, inner} ->
        {carrier, session} = Transport.seal(session, inner)
        :gen_tcp.send(socket, Frame.encode(carrier))
        link_loop(node, peer, socket, session)

      {:tcp_closed, ^socket} ->
        GenServer.cast(node, {:link_down, peer, self()})

      :close ->
        # Displaced by a reconnect: shut down without withdrawing routes (the
        # node has already handed the peer to the new link).
        :gen_tcp.close(socket)

      _ ->
        link_loop(node, peer, socket, session)
    end
  end

  # Opens a transport frame, converting a malformed line or a transport error
  # into a single :error the caller acts on.
  defp safe_open(session, line) do
    case JSON.decode(String.trim(line)) do
      {:ok, carrier} ->
        case Transport.open(session, carrier) do
          {:ok, inner, session} -> {:ok, inner, session}
          {:error, _reason} -> :error
        end

      {:error, _reason} ->
        :error
    end
  end

  defp dial(host, port, s) do
    host = if is_binary(host), do: String.to_charlist(host), else: host

    with {:ok, socket} <- :gen_tcp.connect(host, port, tcp_opts(), 5000) do
      now = System.system_time(:second)
      hs = Handshake.initiator(s.mesh, s.root_public, now, s.cert, s.id_public, s.id_private)
      {m1, hs} = Handshake.write_message1(hs)
      :gen_tcp.send(socket, m1)

      with {:ok, m2} <- :gen_tcp.recv(socket, 0, 5000),
           {:ok, m3, hs} <- Handshake.read_message2_write_message3(hs, m2) do
        :gen_tcp.send(socket, m3)
        session = Handshake.session(hs)
        {:ok, session.peer_cert["label"], socket, session}
      else
        {:error, reason} ->
          :gen_tcp.close(socket)
          {:error, reason}
      end
    end
  end

  defp respond(socket, node, s) do
    now = System.system_time(:second)
    hs = Handshake.responder(s.mesh, s.root_public, now, s.cert, s.id_public, s.id_private)

    with {:ok, m1} <- :gen_tcp.recv(socket, 0, 5000),
         {:ok, m2, hs} <- Handshake.read_message1_write_message2(hs, m1),
         :ok <- :gen_tcp.send(socket, m2),
         {:ok, m3} <- :gen_tcp.recv(socket, 0, 5000),
         {:ok, hs} <- Handshake.read_message3(hs, m3) do
      session = Handshake.session(hs)
      peer = session.peer_cert["label"]
      link = start_link_process(node, peer, socket, Transport.session(session))
      GenServer.cast(node, {:link_up, peer, link})
    else
      _ -> :gen_tcp.close(socket)
    end
  end

  defp accept_loop(listen, node, config) do
    case :gen_tcp.accept(listen) do
      {:ok, socket} ->
        handler = spawn(fn ->
          receive do
            :go -> respond(socket, node, config)
          end
        end)

        :ok = :gen_tcp.controlling_process(socket, handler)
        Kernel.send(handler, :go)
        accept_loop(listen, node, config)

      {:error, :closed} ->
        :ok
    end
  end

  # Dedup: a bounded set with an eviction queue.
  defp seen?({set, _q}, key), do: MapSet.member?(set, key)

  defp remember({set, q}, key) do
    set = MapSet.put(set, key)
    q = :queue.in(key, q)

    if MapSet.size(set) > @dedup_cap do
      {{:value, old}, q} = :queue.out(q)
      {MapSet.delete(set, old), q}
    else
      {set, q}
    end
  end

  # packet: :line frames on newline; buffer/packet_size must exceed the largest
  # frame (post-quantum bmx2 runs ~20 KB, transport frames up to 64 KiB).
  defp tcp_opts,
    do: [:binary, {:packet, :line}, {:active, false}, {:packet_size, 200_000}, {:buffer, 200_000}]

  # Operational knobs (protocol.md §0): local behavior, never part of the wire
  # contract, read once from the environment at node start. Two nodes with
  # different values still interoperate.
  defp load_tunables do
    %{
      probe_timeout_ms: env_int("BONEMESH_PROBE_TIMEOUT_MS", 15_000),
      idle_ms: env_int("BONEMESH_IDLE_MS", 0),
      retry_base_ms: env_int("BONEMESH_RETRY_BASE_MS", 500),
      retry_cap_ms: env_int("BONEMESH_RETRY_CAP_MS", 30_000),
      retry_max_ms: env_int("BONEMESH_RETRY_MAX_MS", 60_000),
      rekey_ms: env_int("BONEMESH_REKEY_MS", 3_600_000),
      rekey_frames: env_int("BONEMESH_REKEY_FRAMES", 65_536),
      rekey_timeout_ms: env_int("BONEMESH_REKEY_TIMEOUT_MS", 10_000),
      keylog_path: System.get_env("BONEMESH_KEYLOG", "")
    }
  end

  defp env_int(name, fallback) do
    case System.get_env(name) do
      nil -> fallback
      "" -> fallback
      v ->
        case Integer.parse(v) do
          {n, ""} -> n
          _ -> fallback
        end
    end
  end
end
