defmodule Bonemesh.KeylogTest do
  # M5: with a key-log path set, both ends of a session write the same
  # directional transport keys and transcript-hash label — proof the emitted
  # keys are the real shared session keys and the role→direction mapping is
  # correct. The format is the cross-language pinned one (security.md §8) that
  # Go's bonemesh-inspect reads.
  use ExUnit.Case, async: false

  alias Bonemesh.{Cert, Crypto, Node}

  @mesh "acme-prod"

  defp start_node(root_pub, root_priv, label, keylog) do
    {pub, priv} = Crypto.mldsa_generate(:mldsa65)
    now = System.system_time(:second)
    cert = Cert.new(@mesh, label, pub, now - 100, now + 3600) |> Cert.sign(root_priv)

    {:ok, node} =
      Node.start_link(
        label: label,
        mesh: @mesh,
        root_public: root_pub,
        cert: cert,
        id_public: pub,
        id_private: priv,
        port: 0,
        keylog: keylog
      )

    on_exit(fn -> if Process.alive?(node), do: Node.stop(node) end)
    node
  end

  # dir => {th, key} for the epoch-0 entries.
  defp parse_keylog(path) do
    path
    |> File.read!()
    |> String.split("\n", trim: true)
    |> Enum.reduce(%{}, fn line, acc ->
      case String.split(line, " ") do
        ["BMX3_" <> rest, th, key] ->
          if String.ends_with?(rest, "_TRAFFIC_0") do
            dir = String.replace_suffix(rest, "_TRAFFIC_0", "")
            Map.put(acc, dir, {th, key})
          else
            acc
          end

        _ ->
          acc
      end
    end)
  end

  test "both ends emit agreeing directional keys and transcript hash" do
    {root_pub, root_priv} = Crypto.mldsa_generate(:mldsa87)
    dir = System.tmp_dir!()
    fa = Path.join(dir, "a-#{System.unique_integer([:positive])}.keylog")
    fb = Path.join(dir, "b-#{System.unique_integer([:positive])}.keylog")
    File.rm(fa)
    File.rm(fb)

    alpha = start_node(root_pub, root_priv, "alpha", fa)
    beta = start_node(root_pub, root_priv, "beta", fb)
    {:ok, "beta"} = Node.connect(alpha, "127.0.0.1", Node.port(beta))

    wait_files = fn wait_files ->
      if File.exists?(fa) and File.exists?(fb) and File.stat!(fa).size > 0 and File.stat!(fb).size > 0 do
        :ok
      else
        Process.sleep(50)
        wait_files.(wait_files)
      end
    end

    Task.async(fn -> wait_files.(wait_files) end) |> Task.await(5000)

    a = parse_keylog(fa)
    b = parse_keylog(fb)

    for d <- ["I2R", "R2I"] do
      assert Map.has_key?(a, d) and Map.has_key?(b, d), "missing #{d} (a=#{inspect(a)} b=#{inspect(b)})"
      {th_a, key_a} = a[d]
      {th_b, key_b} = b[d]
      assert String.length(key_a) == 64, "#{d} key not 32-byte hex: #{key_a}"
      assert key_a == key_b, "#{d} key disagrees between ends (role→direction mapping wrong)"
      assert th_a == th_b, "#{d} transcript hash disagrees"
    end

    {_, i2r_key} = a["I2R"]
    {_, r2i_key} = a["R2I"]
    assert i2r_key != r2i_key, "I2R and R2I keys are identical"
  end
end
