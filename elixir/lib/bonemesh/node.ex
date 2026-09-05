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
      routing: Routing.new(label),
      links: %{},
      dedup: {MapSet.new(), :queue.new()},
      reassembler: %{},
      listeners: []
    }

    config = Map.take(state, [:mesh, :root_public, :cert, :id_public, :id_private])
    me = self()
    spawn_link(fn -> accept_loop(listen, me, config) end)
    :timer.send_interval(@heartbeat_ms, :heartbeat)
    {:ok, state}
  end

  @impl true
  def handle_call(:port, _from, s), do: {:reply, s.port, s}

  def handle_call({:connect, host, port}, _from, s) do
    case dial(host, port, s) do
      {:ok, peer, socket, session} ->
        {:reply, {:ok, peer}, register_link(s, peer, socket, session)}

      {:error, reason} ->
        {:reply, {:error, reason}, s}
    end
  end

  def handle_call({:send, to, payload}, _from, s) do
    mid = Message.new_mid()
    msgs = Message.split(mid, s.label, to, Message.default_ttl(), payload)
    {ok, s} = Enum.reduce(msgs, {true, s}, fn m, {acc, st} -> {forward(st, m) and acc, st} end)
    {:reply, ok, s}
  end

  @impl true
  def handle_cast({:add_listener, pid}, s), do: {:noreply, %{s | listeners: [pid | s.listeners]}}

  def handle_cast({:link_up, peer, pid}, s), do: {:noreply, register_link_pid(s, peer, pid)}

  def handle_cast({:inbound, peer, inner}, s), do: {:noreply, handle_inner(s, peer, inner)}

  def handle_cast({:link_down, peer}, s) do
    {:noreply, %{s | links: Map.delete(s.links, peer), routing: Routing.remove_neighbor(s.routing, peer)}}
  end

  @impl true
  def handle_info(:heartbeat, s) do
    now = System.system_time(:millisecond)

    for {label, pid} <- s.links do
      Kernel.send(pid, {:send, Message.probe(now)})
      Kernel.send(pid, {:send, Message.disco(Routing.advertise_to(s.routing, label))})
    end

    {:noreply, s}
  end

  def handle_info(_msg, s), do: {:noreply, s}

  # --- Internals ---

  defp handle_inner(s, _peer, %{"type" => "data"} = m) do
    chunk_index = get_in(m, ["chunk", "i"]) || -1
    key = m["mid"] <> ":" <> Integer.to_string(chunk_index)

    if seen?(s.dedup, key) do
      s
    else
      s = %{s | dedup: remember(s.dedup, key)}
      route_data(s, m)
    end
  end

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
          %{s | reassembler: acc}

        {:incomplete, acc} ->
          %{s | reassembler: acc}
      end
    else
      ttl = m["ttl"] - 1
      if ttl > 0, do: forward(s, Map.put(m, "ttl", ttl)), else: false
      s
    end
  end

  defp forward(s, m) do
    case Routing.next_hop(s.routing, m["to"]) do
      nil -> false
      next -> send_to_link(s, next, m)
    end
  end

  defp send_to_link(s, label, inner) do
    case s.links[String.downcase(label)] do
      nil -> false
      pid -> Kernel.send(pid, {:send, inner}) && true
    end
  end

  defp register_link(s, peer, socket, session) do
    pid = start_link_process(self(), peer, socket, Transport.session(session))
    register_link_pid(s, peer, pid)
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

  defp register_link_pid(s, peer, pid) do
    key = String.downcase(peer)
    %{s | links: Map.put(s.links, key, pid), routing: Routing.observe_neighbor(s.routing, peer, 1)}
  end

  # A neighbor link: owns the socket + transport session, relays inbound inner
  # messages to the node, and seals outbound ones on request.
  defp link_loop(node, peer, socket, session) do
    receive do
      {:tcp, ^socket, line} ->
        session =
          case Transport.open(session, JSON.decode!(String.trim(line))) do
            {:ok, inner, session} ->
              GenServer.cast(node, {:inbound, peer, inner})
              session

            {:error, _reason} ->
              session
          end

        :inet.setopts(socket, active: :once)
        link_loop(node, peer, socket, session)

      {:send, inner} ->
        {carrier, session} = Transport.seal(session, inner)
        :gen_tcp.send(socket, Frame.encode(carrier))
        link_loop(node, peer, socket, session)

      {:tcp_closed, ^socket} ->
        GenServer.cast(node, {:link_down, peer})

      _ ->
        link_loop(node, peer, socket, session)
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
end
