# The Elixir driver for the language-agnostic interop harness (interop/). It
# implements the same neutral driver contract (interop/README.md) as every
# other implementation's driver: a `listen` mode and a `connect` mode over
# shared, implementation-independent key and certificate files. The harness
# pairs it with any other driver without knowing which is which.

defmodule InteropNode do
  def main(["keygen" | rest]) do
    f = flags(rest)
    {public, private} = :crypto.generate_key(:mldsa65, [])
    File.write!(f["id-pub"], Base.encode64(public))
    File.write!(f["id-priv"], Base.encode64(private))
  end

  def main([mode | rest]) do
    f = flags(rest)

    root_pub = f |> Map.fetch!("root-pub") |> File.read!() |> String.trim() |> Base.decode64!()
    cert = f |> Map.fetch!("cert") |> File.read!() |> JSON.decode!()
    id_pub = f |> Map.fetch!("id-pub") |> File.read!() |> String.trim() |> Base.decode64!()
    id_priv = f |> Map.fetch!("id-priv") |> File.read!() |> String.trim() |> Base.decode64!()
    mesh = Map.fetch!(f, "mesh")
    label = cert["label"]
    seconds = f |> Map.get("seconds", "10") |> String.to_integer()

    opts = [label: label, mesh: mesh, root_public: root_pub, cert: cert, id_public: id_pub, id_private: id_priv]

    case mode do
      "listen" ->
        {:ok, node} = Bonemesh.Node.start_link([{:port, String.to_integer(f["port"])} | opts])
        out = f["out"]
        Bonemesh.Node.add_listener(node, spawn(fn -> collect(out) end))
        Process.sleep(seconds * 1000)

      "connect" ->
        {:ok, node} = Bonemesh.Node.start_link([{:port, 0} | opts])
        {:ok, _peer} = Bonemesh.Node.connect(node, f["host"], String.to_integer(f["port"]))
        payload = f["message"] |> File.read!() |> JSON.decode!()
        send_until(node, f["to"], payload, System.monotonic_time(:millisecond) + seconds * 1000)
        Process.sleep(1500)

      # A multi-link node for the convergence tier: dials several peers
      # (--peers host:port,host:port), optionally records delivered payloads
      # (--out), repeatedly sends toward a routed destination (--send-to with
      # --message), and periodically dumps its routing table (--routes). Stays
      # up for --seconds. Relay nodes need no special mode — a plain listener
      # already forwards.
      "mesh" ->
        {:ok, node} = Bonemesh.Node.start_link([{:port, String.to_integer(Map.get(f, "port", "0"))} | opts])
        if f["out"], do: Bonemesh.Node.add_listener(node, spawn(fn -> collect(f["out"]) end))

        for peer <- String.split(Map.get(f, "peers", ""), ",", trim: true) do
          [host, port] = String.split(peer, ":", parts: 2)
          {:ok, _} = Bonemesh.Node.connect(node, host, String.to_integer(port))
        end

        payload = if f["message"], do: f["message"] |> File.read!() |> JSON.decode!(), else: nil
        mesh_loop(node, f["send-to"], payload, f["routes"], System.monotonic_time(:millisecond) + seconds * 1000)
    end
  end

  defp mesh_loop(node, send_to, payload, routes_file, deadline) do
    if send_to && payload, do: Bonemesh.Node.send(node, send_to, payload)
    if routes_file, do: File.write!(routes_file, JSON.encode!(Bonemesh.Node.routes(node)))

    if System.monotonic_time(:millisecond) < deadline do
      Process.sleep(500)
      mesh_loop(node, send_to, payload, routes_file, deadline)
    end
  end

  # A listener process that appends each received payload as a JSON line.
  defp collect(out) do
    receive do
      {:bonemesh_data, payload} ->
        File.write!(out, JSON.encode!(payload) <> "\n", [:append])
        collect(out)
    end
  end

  defp send_until(node, to, payload, deadline) do
    unless Bonemesh.Node.send(node, to, payload) do
      if System.monotonic_time(:millisecond) < deadline do
        Process.sleep(200)
        send_until(node, to, payload, deadline)
      end
    end
  end

  defp flags(args) do
    args
    |> Enum.chunk_every(2)
    |> Enum.reduce(%{}, fn
      ["--" <> k, v], acc -> Map.put(acc, k, v)
      _, acc -> acc
    end)
  end
end

InteropNode.main(System.argv())
