defmodule Bonemesh.Message do
  @moduledoc """
  Factory for the BoneMesh v3 inner message types (protocol.md §4) and helpers
  and message ids. Splitting lives in `Bonemesh.Chunk` and reassembly in
  `Bonemesh.Reassembler`. Every builder produces a map that passes
  `Bonemesh.MessageSchema`.
  """

  @default_ttl 16

  @doc "The default hop limit for application data."
  def default_ttl, do: @default_ttl

  @doc "A fresh 128-bit message id as 32 lowercase-hex characters."
  def new_mid, do: :crypto.strong_rand_bytes(16) |> Base.encode16(case: :lower)

  @doc "An application data message."
  def data(mid, from, to, ttl, payload),
    do: %{"type" => "data", "mid" => mid, "from" => from, "to" => to, "ttl" => ttl, "payload" => payload}

  @doc """
  One segment of a split application message (protocol.md §6.1).

  A segment carries `"seg"` and deliberately carries no `"payload"`: the two are
  mutually exclusive, so a node that does not reassemble sees a data message with no
  payload and rejects it rather than handing a fragment to the application as though
  it were whole.
  """
  def data_segment(mid, from, to, ttl, i, n, seg),
    do: %{
      "type" => "data",
      "mid" => mid,
      "from" => from,
      "to" => to,
      "ttl" => ttl,
      "chunk" => %{"i" => i, "n" => n},
      "seg" => seg
    }

  @doc "An acknowledgement for a message id."
  def ack(mid), do: %{"type" => "ack", "mid" => mid}

  @doc """
  An acknowledgement routed back toward the origin (protocol.md §7): `to` is the
  origin, `from` this node, `ttl` the hop limit.
  """
  def ack_to(mid, from, to, ttl),
    do: %{"type" => "ack", "mid" => mid, "from" => from, "to" => to, "ttl" => ttl}

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

end
