defmodule Bonemesh.Message do
  @moduledoc """
  Factory for the BoneMesh v3 inner message types (protocol.md §4) and helpers
  for message ids and payload chunking. Every builder produces a map that passes
  `Bonemesh.MessageSchema`.
  """

  @default_ttl 16
  @max_segment 32000

  @doc "The default hop limit for application data."
  def default_ttl, do: @default_ttl

  @doc "A fresh 128-bit message id as 32 lowercase-hex characters."
  def new_mid, do: :crypto.strong_rand_bytes(16) |> Base.encode16(case: :lower)

  @doc "An application data message."
  def data(mid, from, to, ttl, payload),
    do: %{"type" => "data", "mid" => mid, "from" => from, "to" => to, "ttl" => ttl, "payload" => payload}

  @doc "An acknowledgement for a message id."
  def ack(mid), do: %{"type" => "ack", "mid" => mid}

  @doc """
  A negative acknowledgement naming the hop that failed and why, routed back
  toward the origin like data (to/from/ttl) (protocol.md §7).
  """
  def nak(mid, from, to, hop, reason, ttl),
    do: %{"type" => "nak", "mid" => mid, "hop" => hop, "reason" => reason, "from" => from, "to" => to, "ttl" => ttl}

  @doc "A discovery advertisement (label -> path cost)."
  def disco(costs), do: %{"type" => "disco", "routes" => costs}

  @doc "A latency probe with an opaque token."
  def probe(token), do: %{"type" => "probe", "token" => token}

  @doc "The echo response to a probe."
  def echo(token), do: %{"type" => "echo", "token" => token}

  @doc "A graceful session-close message with no stated reason."
  def bye, do: %{"type" => "bye"}

  @doc "A graceful session-close message stating why (e.g. \"idle\", \"rekey-failed\")."
  def bye(reason) when is_binary(reason) and reason != "", do: Map.put(bye(), "reason", reason)

  @doc """
  Splits a payload across one or more data messages sharing a message id
  (protocol.md §6). A small payload is sent unchunked; a large one is Base64-
  encoded, sliced, and each slice sent as `%{"seg" => ...}` with `chunk`.
  """
  def split(mid, from, to, ttl, payload) do
    b64 = payload |> JSON.encode!() |> Base.encode64()

    if byte_size(b64) <= @max_segment do
      [data(mid, from, to, ttl, payload)]
    else
      segments = chunk_string(b64, @max_segment)
      n = length(segments)

      segments
      |> Enum.with_index()
      |> Enum.map(fn {seg, i} ->
        mid |> data(from, to, ttl, %{"seg" => seg}) |> Map.put("chunk", %{"i" => i, "n" => n})
      end)
    end
  end

  @doc """
  Feeds a data message to the reassembly accumulator. Returns
  `{:complete, payload, acc}` when a message's final segment arrives, or
  `{:incomplete, acc}`.
  """
  def reassemble(acc, %{"chunk" => %{"i" => i, "n" => n}, "mid" => mid, "payload" => %{"seg" => seg}}) do
    partial = acc |> Map.get(mid, %{}) |> Map.put(i, seg)

    if map_size(partial) == n do
      payload =
        0..(n - 1)
        |> Enum.map_join(&Map.fetch!(partial, &1))
        |> Base.decode64!()
        |> JSON.decode!()

      {:complete, payload, Map.delete(acc, mid)}
    else
      {:incomplete, Map.put(acc, mid, partial)}
    end
  end

  # Unchunked message: deliver its payload immediately.
  def reassemble(acc, %{"payload" => payload}), do: {:complete, payload, acc}

  defp chunk_string(<<>>, _size), do: []
  defp chunk_string(s, size) when byte_size(s) <= size, do: [s]

  defp chunk_string(s, size) do
    <<head::binary-size(size), rest::binary>> = s
    [head | chunk_string(rest, size)]
  end
end
