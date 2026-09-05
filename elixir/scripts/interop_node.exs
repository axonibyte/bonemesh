# The Elixir driver for the language-agnostic interop harness (interop/). It
# implements the same neutral driver contract (interop/README.md) as every
# other implementation's driver: a `listen` mode and a `connect` mode over
# shared, implementation-independent key and certificate files. The harness
# pairs it with any other driver without knowing which is which.

defmodule InteropNode do
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
