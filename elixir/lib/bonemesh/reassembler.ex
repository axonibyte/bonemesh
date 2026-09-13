defmodule Bonemesh.Reassembler do
  @moduledoc """
  Rebuilds split payloads at the destination, the counterpart to
  `Bonemesh.Chunk.split/5` (protocol.md §6.1).

  Every §0 bound is enforced **before** any allocation keyed on a number the peer
  chose. That ordering is the point: the Java reference sized its buffer on the
  peer's `n` and validated afterwards, so one frame claiming two billion segments
  exhausted the heap — defect D7 reintroduced by the feature meant to fix it. This
  port never allocated an array, so it could not reproduce that exact fault, but it
  had no bound of any kind either: its accumulator was a bare map that grew without
  limit and never aged anything out.

  Three bounds, none redundant. The byte budget caps one large message; the
  in-flight count caps a flood of distinct ids each carrying an *empty* segment,
  which costs nothing against a byte budget and still costs memory; the timeout
  stops an abandoned message pinning memory for the session's life.
  """

  alias Bonemesh.Chunk

  defstruct partials: %{}, buffered: 0

  @doc "An empty reassembler."
  def new, do: %__MODULE__{}

  @doc """
  Feeds one inbound data message. Returns `{:complete, payload, reassembler}` when a
  message completes, else `{:incomplete, reassembler}`. `now_millis` is passed in
  rather than read so the timeout is testable without sleeping.
  """
  def offer(%__MODULE__{} = r, msg, now_millis) do
    r = sweep(r, now_millis)
    has_chunk = Map.has_key?(msg, "chunk")
    chunk = Map.get(msg, "chunk")

    cond do
      has_chunk and not is_map(chunk) ->
        {:incomplete, r} # chunk is present but not an object

      has_chunk and not is_integer(chunk["n"]) ->
        {:incomplete, r}

      not has_chunk or chunk["n"] == 1 ->
        whole(r, msg)

      true ->
        segment(r, msg, chunk, chunk["n"], now_millis)
    end
  end

  @doc """
  Messages currently mid-reassembly. Exposed for the tests that assert the bounds
  release memory rather than merely refusing to add to it — a reassembler that
  rejects a segment but keeps its partial forever is still a leak, and the refusal
  alone cannot show that.
  """
  def in_flight(%__MODULE__{partials: p}), do: map_size(p)

  @doc "Segment bytes held across every in-flight message."
  def buffered(%__MODULE__{buffered: b}), do: b

  # A whole message carries payload and no seg. One claiming n == 1 while carrying
  # seg instead is malformed, not a one-segment split -- and so is one carrying both.
  defp whole(r, msg) do
    cond do
      Map.has_key?(msg, "seg") -> {:incomplete, r}
      Map.has_key?(msg, "payload") -> {:complete, msg["payload"], r}
      true -> {:incomplete, r}
    end
  end

  defp segment(r, msg, chunk, n, now_millis) do
    i = chunk["i"]
    seg = Map.get(msg, "seg")
    mid = Map.get(msg, "mid")

    # Bounds first, allocation second.
    if not is_integer(i) or n < 1 or n > Chunk.max_chunks() or i < 0 or i >= n or
         not is_binary(seg) or not is_binary(mid) do
      {:incomplete, r}
    else
      store(r, mid, i, n, seg, now_millis)
    end
  end

  defp store(r, mid, i, n, seg, now_millis) do
    case Map.get(r.partials, mid) do
      nil ->
        if map_size(r.partials) >= Chunk.max_concurrent_reassemblies() do
          {:incomplete, r}
        else
          fresh = %{segments: %{}, bytes: 0, n: n, started: now_millis}
          put(%{r | partials: Map.put(r.partials, mid, fresh)}, mid, i, n, seg)
        end

      %{n: ^n} ->
        put(r, mid, i, n, seg)

      _ ->
        {:incomplete, discard(r, mid)} # the peer changed n mid-message
    end
  end

  defp put(r, mid, i, n, seg) do
    partial = Map.fetch!(r.partials, mid)

    if Map.has_key?(partial.segments, i) do
      complete_if_done(r, mid, partial, n)
    else
      size = byte_size(seg)

      if r.buffered + size > Chunk.max_reassembly_buffer() do
        {:incomplete, discard(r, mid)}
      else
        partial = %{
          partial
          | segments: Map.put(partial.segments, i, seg),
            bytes: partial.bytes + size
        }

        r = %{r | partials: Map.put(r.partials, mid, partial), buffered: r.buffered + size}
        complete_if_done(r, mid, partial, n)
      end
    end
  end

  defp complete_if_done(r, mid, partial, n) do
    if map_size(partial.segments) == n do
      joined = Enum.map_join(0..(n - 1), &Map.fetch!(partial.segments, &1))
      r = discard(r, mid)

      case JSON.decode(joined) do
        {:ok, payload} -> {:complete, payload, r}
        # the segments did not rebuild valid JSON
        _ -> {:incomplete, r}
      end
    else
      {:incomplete, r}
    end
  end

  defp discard(r, mid) do
    case Map.pop(r.partials, mid) do
      {nil, _} -> r
      {partial, rest} -> %{r | partials: rest, buffered: r.buffered - partial.bytes}
    end
  end

  # Elixir maps have no insertion order, so the sweep examines every partial rather
  # than stopping early. At most 256 of them exist, so that is cheaper than
  # maintaining a parallel ordering.
  defp sweep(r, now_millis) do
    stale =
      r.partials
      |> Enum.filter(fn {_mid, p} -> now_millis - p.started >= Chunk.reassembly_timeout_millis() end)
      |> Enum.map(&elem(&1, 0))

    Enum.reduce(stale, r, &discard(&2, &1))
  end
end
