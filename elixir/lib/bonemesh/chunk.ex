defmodule Bonemesh.Chunk do
  @moduledoc """
  Splitting of oversized application payloads (protocol.md §6.1).

  A payload too large for one transport frame is serialized, its UTF-8 bytes cut
  into segments of at most `max_segment_bytes/0` on character boundaries, and each
  segment sent as a data message sharing one message id, carrying `chunk {i, n}`
  and a top-level `"seg"` string and **no** `"payload"`. A payload that fits
  travels whole, with `"payload"` and no `"seg"`.

  Segments are text, not Base64: §0's Base64 rule covers binary fields, a slice of
  JSON text is already UTF-8, and a JSON string carries it directly, so a split
  message stays readable through the key-log inspector (decisions #3, #5, #25).
  Cutting on a byte budget rather than a character count is what keeps the split
  identical across the seven implementations, because UTF-8 has no surrogates: a
  code point is either wholly inside a segment or wholly outside it. An Elixir
  binary is already a byte sequence, so `binary-size` is the right primitive here
  and `String.slice/3`, which counts graphemes, would be the wrong one.

  Reassembly is `Bonemesh.Reassembler`.
  """

  @max_segment_bytes 24000
  @max_chunks 1024
  @max_reassembly_buffer 16_777_216
  @max_concurrent_reassemblies 256
  @reassembly_timeout_millis 30_000

  @doc "Maximum payload bytes carried by one segment (protocol.md §0)."
  def max_segment_bytes, do: @max_segment_bytes

  @doc "Maximum segments one application message may be split into (§0)."
  def max_chunks, do: @max_chunks

  @doc "Maximum segment bytes buffered at once, across every in-flight message (§0)."
  def max_reassembly_buffer, do: @max_reassembly_buffer

  @doc "Maximum messages that may be mid-reassembly at once (§0)."
  def max_concurrent_reassemblies, do: @max_concurrent_reassemblies

  @doc "Milliseconds a partially-filled message may sit before being discarded (§0)."
  def reassembly_timeout_millis, do: @reassembly_timeout_millis

  @doc """
  Splits a payload into one whole data message or a series of segments.

  Raises `ArgumentError` when no conforming destination would reassemble it, so the
  caller is told locally rather than the mesh carrying a message that cannot arrive
  (§6.1, Bounds).
  """
  def split(mid, from, to, ttl, payload) do
    src = JSON.encode!(payload)

    cond do
      byte_size(src) <= @max_segment_bytes ->
        [Bonemesh.Message.data(mid, from, to, ttl, payload)]

      byte_size(src) > @max_reassembly_buffer ->
        raise ArgumentError,
              "payload of #{byte_size(src)} bytes exceeds the reassembly buffer maximum " <>
                "of #{@max_reassembly_buffer}"

      true ->
        segments = cut(src)
        n = length(segments)

        if n > @max_chunks do
          raise ArgumentError, "payload needs #{n} segments, over the maximum of #{@max_chunks}"
        end

        segments
        |> Enum.with_index()
        |> Enum.map(fn {seg, i} ->
          Bonemesh.Message.data_segment(mid, from, to, ttl, i, n, seg)
        end)
    end
  end

  # Cuts a binary into at-most-@max_segment_bytes pieces, every cut landing on a
  # character boundary so each piece is itself valid UTF-8.
  defp cut(<<>>), do: []

  defp cut(s) when byte_size(s) <= @max_segment_bytes, do: [s]

  defp cut(s) do
    at = char_boundary(s, @max_segment_bytes)
    <<head::binary-size(at), rest::binary>> = s
    [head | cut(rest)]
  end

  # Walks a proposed cut back to the nearest character boundary at or before it.
  defp char_boundary(s, at) do
    case :binary.at(s, at) do
      b when Bitwise.band(b, 0xC0) == 0x80 and at > 1 -> char_boundary(s, at - 1)
      _ -> at
    end
  end
end
