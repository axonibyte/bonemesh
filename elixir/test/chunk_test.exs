defmodule Bonemesh.ChunkTest do
  use ExUnit.Case, async: true

  @moduledoc """
  Splitting and reassembly tests (protocol.md §6.1).

  Two groups. The first pins the format: a small payload travels whole, a large one
  splits and rebuilds byte-identically, segments are text rather than Base64, and
  cuts land on character boundaries even when every character is multi-byte.

  The second pins the bounds, which is the half this port had none of: its
  accumulator was a bare map that grew without limit and never aged anything out.
  Each asserts that a hostile message is refused AND that refusing it released
  whatever it claimed, because a reassembler that rejects a segment but keeps its
  partial forever is still a leak and the refusal alone cannot show that.
  """

  alias Bonemesh.{Chunk, Message, MessageSchema, Reassembler}

  @mid "0123456789abcdef0123456789abcdef"

  defp blob(n), do: String.duplicate("abcdefghij", div(n, 10))

  defp seg(mid, i, n, s), do: Message.data_segment(mid, "a", "b", 16, i, n, s)

  defp feed(r, msgs, now \\ 0) do
    Enum.reduce(msgs, {:incomplete, r}, fn m, {_, acc} -> Reassembler.offer(acc, m, now) end)
  end

  # ---- format ----

  test "a small payload travels whole" do
    payload = %{"line" => "hello"}
    msgs = Chunk.split(@mid, "a", "b", 16, payload)
    assert length(msgs) == 1
    refute Map.has_key?(hd(msgs), "chunk"), "a whole message must not carry chunk"
    refute Map.has_key?(hd(msgs), "seg"), "a whole message must not carry seg"
    assert hd(msgs)["payload"] == payload
  end

  test "a large payload splits and reassembles" do
    payload = %{"blob" => blob(120_000)}
    msgs = Chunk.split(@mid, "a", "b", 16, payload)
    assert length(msgs) > 1, "large payload was not split"

    for {m, i} <- Enum.with_index(msgs) do
      assert MessageSchema.validate("data", m) == nil, "segment #{i} failed the data schema"
      refute Map.has_key?(m, "payload"), "segment #{i} carries a payload"
      assert is_binary(m["seg"])
      assert byte_size(m["seg"]) <= Chunk.max_segment_bytes(), "segment #{i} is over the maximum"
    end

    r = Reassembler.new()
    {before, [last]} = Enum.split(msgs, length(msgs) - 1)
    {:incomplete, r} = feed(r, before)
    assert {:complete, ^payload, r} = Reassembler.offer(r, last, 0)
    assert Reassembler.in_flight(r) == 0, "a completed message stayed buffered"
    assert Reassembler.buffered(r) == 0, "a completed message stayed counted"
  end

  test "segments are text, not base64" do
    # decision #25: a segment is a slice of the payload's JSON text, so it stays
    # readable through the key-log inspector. Concatenation must reproduce the
    # serialized payload with no decode step.
    payload = %{"blob" => blob(60_000)}
    msgs = Chunk.split(@mid, "a", "b", 16, payload)
    assert Enum.map_join(msgs, & &1["seg"]) == JSON.encode!(payload)
    assert String.starts_with?(hd(msgs)["seg"], "{"), "the first segment should open the payload JSON"
  end

  test "cuts land on character boundaries" do
    # Every character is 3 UTF-8 bytes, so 24000 divides unevenly and a naive byte cut
    # would split one. String.valid?/1 on each segment is the oracle.
    payload = %{"cjk" => String.duplicate("日", 40_000)}
    msgs = Chunk.split(@mid, "a", "b", 16, payload)
    assert length(msgs) > 1

    for {m, i} <- Enum.with_index(msgs) do
      assert byte_size(m["seg"]) <= Chunk.max_segment_bytes(), "segment #{i} is over the maximum"
      assert String.valid?(m["seg"]), "segment #{i} is not valid UTF-8: a cut split a character"
    end

    assert {:complete, ^payload, _} = feed(Reassembler.new(), msgs)
  end

  test "out-of-order segments still reassemble" do
    payload = %{"blob" => blob(120_000)}
    msgs = Chunk.split(@mid, "a", "b", 16, payload)
    assert {:complete, ^payload, _} = feed(Reassembler.new(), Enum.reverse(msgs))
  end

  # ---- bounds ----

  test "an absurd chunk count is refused before allocating" do
    # The Java reference sized its buffer on the peer's n before validating it, so one
    # frame claiming two billion segments exhausted the heap. This port allocates no
    # array, so it could not reproduce that exact fault -- but it had no bound either,
    # and an unbounded n is still an unbounded claim on the accumulator.
    r = Reassembler.new()

    for n <- [9_223_372_036_854_775_807, 2_000_000_000, 1_000_000, Chunk.max_chunks() + 1] do
      assert {:incomplete, r2} = Reassembler.offer(r, seg(@mid, 0, n, "x"), 0)
      assert Reassembler.in_flight(r2) == 0, "n=#{n} was buffered anyway"
      assert Reassembler.buffered(r2) == 0, "n=#{n} was counted anyway"
    end

    # The boundary itself is legal, so this is a bound and not a blanket ban.
    {:incomplete, r} = Reassembler.offer(r, seg(@mid, 0, Chunk.max_chunks(), "x"), 0)
    assert Reassembler.in_flight(r) == 1, "the maximum legal chunk count was refused"
  end

  test "malformed chunk metadata is refused" do
    bad = [
      Map.put(seg(@mid, 0, 3, "x"), "chunk", "not-an-object"),
      Map.put(seg(@mid, 0, 3, "x"), "chunk", [0, 3]),
      Map.put(seg(@mid, 0, 3, "x"), "chunk", %{"i" => "zero", "n" => 3}),
      Map.put(seg(@mid, 0, 3, "x"), "chunk", %{"i" => 0}),
      Map.put(seg(@mid, 0, 3, "x"), "chunk", %{"i" => 0.5, "n" => 3}),
      seg(@mid, 3, 3, "x"),
      seg(@mid, -1, 3, "x"),
      seg(@mid, 0, 0, "x")
    ]

    for {m, k} <- Enum.with_index(bad) do
      assert {:incomplete, r} = Reassembler.offer(Reassembler.new(), m, 0),
             "case #{k}: accepted a malformed chunk"
      assert Reassembler.in_flight(r) == 0, "case #{k}: malformed chunk was buffered"
    end
  end

  test "a segment without its slice is refused" do
    m = Map.delete(seg(@mid, 0, 3, "x"), "seg")
    assert {:incomplete, r} = Reassembler.offer(Reassembler.new(), m, 0)
    assert Reassembler.in_flight(r) == 0
  end

  test "a whole message claiming to be a segment is not delivered" do
    m = seg(@mid, 0, 1, ~s({"a":1}))
    assert {:incomplete, _} = Reassembler.offer(Reassembler.new(), m, 0)
    assert MessageSchema.validate("data", m) == "payload-or-seg"
  end

  test "a message carrying both payload and segment is not delivered" do
    # Found by mutation in the Rust port, then fixed in all seven: the whole-message
    # path returned the payload whenever one was present, so a message contradicting
    # itself was delivered. The schema rejects it, but the schema is not on the wire
    # path (decision #27), so the reassembler has to refuse it too.
    both = Map.put(Message.data(@mid, "a", "b", 16, %{"x" => 1}), "seg", "{")
    assert {:incomplete, _} = Reassembler.offer(Reassembler.new(), both, 0)
    with_chunk = Map.put(seg(@mid, 0, 1, "{"), "payload", %{"x" => 1})
    assert {:incomplete, _} = Reassembler.offer(Reassembler.new(), with_chunk, 0)
  end

  test "a non-object chunk is refused even with a payload" do
    # The distinguishing input: a garbage chunk on a message that DOES carry a
    # payload. Java conflated "chunk absent" with "chunk unparseable" and delivered
    # it; nothing tested the case, which is how that survived.
    for garbage <- ["1/3", 7, true, [0, 3]] do
      m = Map.put(Message.data(@mid, "a", "b", 16, %{"x" => 1}), "chunk", garbage)
      assert {:incomplete, _} = Reassembler.offer(Reassembler.new(), m, 0),
             "delivered a message whose chunk was #{inspect(garbage)}"
      assert MessageSchema.validate("data", m) != nil, "the schema should reject it too"
    end
  end

  test "concurrent reassemblies are bounded" do
    r =
      Enum.reduce(0..(Chunk.max_concurrent_reassemblies() - 1), Reassembler.new(), fn k, acc ->
        mid = k |> Integer.to_string(16) |> String.downcase() |> String.pad_leading(32, "0")
        {:incomplete, acc} = Reassembler.offer(acc, seg(mid, 0, 4, "x"), 0)
        acc
      end)

    assert Reassembler.in_flight(r) == Chunk.max_concurrent_reassemblies()
    {:incomplete, r} = Reassembler.offer(r, seg(String.duplicate("f", 32), 0, 4, "x"), 0)
    assert Reassembler.in_flight(r) == Chunk.max_concurrent_reassemblies(), "the bound was exceeded"
  end

  test "buffered bytes are bounded" do
    # The in-flight bound (256) is reached long before 16 MiB of segments can be
    # spread across separate message ids, so the byte budget is only reachable inside
    # one message: 1024 segments of 24000 bytes is 24.5 MB, over the ceiling.
    full = String.duplicate("y", Chunk.max_segment_bytes())

    {r, accepted} =
      Enum.reduce_while(0..(Chunk.max_chunks() - 1), {Reassembler.new(), 0}, fn i, {acc, n} ->
        {:incomplete, acc} = Reassembler.offer(acc, seg(@mid, i, Chunk.max_chunks(), full), 0)

        if Reassembler.in_flight(acc) == 0 do
          {:halt, {acc, n}}
        else
          assert Reassembler.buffered(acc) <= Chunk.max_reassembly_buffer(),
                 "the buffer maximum was exceeded at segment #{i}"

          {:cont, {acc, n + 1}}
        end
      end)

    assert accepted == div(Chunk.max_reassembly_buffer(), Chunk.max_segment_bytes()),
           "the message should be abandoned on the first segment that would not fit"

    assert Reassembler.in_flight(r) == 0, "the abandoned message was retained"
    assert Reassembler.buffered(r) == 0, "abandoning did not return its bytes"
  end

  test "stale partials are swept" do
    r = Reassembler.new()
    {:incomplete, r} = Reassembler.offer(r, seg(@mid, 0, 3, "x"), 1000)
    assert Reassembler.in_flight(r) == 1

    {:incomplete, r} =
      Reassembler.offer(r, seg(@mid, 1, 3, "y"), 1000 + Chunk.reassembly_timeout_millis() - 1)

    assert Reassembler.in_flight(r) == 1, "swept too early"

    {:incomplete, r} =
      Reassembler.offer(
        r,
        seg(String.duplicate("1", 32), 0, 3, "z"),
        1000 + Chunk.reassembly_timeout_millis()
      )

    assert Reassembler.in_flight(r) == 1, "the stale partial was not swept"
    assert Reassembler.buffered(r) == 1, "swept bytes were not returned to the budget"
  end

  test "an oversized payload fails at the origin" do
    # §6.1: an origin whose payload no conforming destination would reassemble is told
    # locally rather than emitting it.
    assert_raise ArgumentError, fn ->
      Chunk.split(@mid, "a", "b", 16, %{"blob" => blob(Chunk.max_reassembly_buffer() + 10)})
    end
  end
end
