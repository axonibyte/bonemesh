# Splitting against the shared corpus (spec/corpus/chunk.json).
#
# Two things, and the second is the one nothing else can see. First the pinned
# section 0 constants must match this implementation's -- including the three (chunk
# count, in-flight count, timeout) that specsrc deliberately does not check, because
# a substring search for 1024, 256 or 30000 is satisfied by any buffer size already
# in the tree. Second, the segments this implementation produces must land on exactly
# the byte boundaries the corpus pins, which is how all seven are shown to cut in the
# SAME places rather than merely to cut.
[path] = System.argv()
doc = path |> File.read!() |> JSON.decode!()
fails = :counters.new(1, [])

report = fn name, ok ->
  if ok do
    IO.puts("PASS #{name}")
  else
    IO.puts("FAIL #{name}")
    :counters.add(fails, 1, 1)
  end
end

mine = %{
  "max_segment_bytes" => Bonemesh.Chunk.max_segment_bytes(),
  "max_chunks" => Bonemesh.Chunk.max_chunks(),
  "max_reassembly_buffer" => Bonemesh.Chunk.max_reassembly_buffer(),
  "max_concurrent_reassemblies" => Bonemesh.Chunk.max_concurrent_reassemblies(),
  "reassembly_timeout_millis" => Bonemesh.Chunk.reassembly_timeout_millis()
}

constants = doc["constants"] || %{}

if map_size(constants) == 0 do
  IO.puts(:stderr, "corpus declares no chunk constants")
  System.halt(1)
end

for {name, want} <- constants do
  got = Map.get(mine, name)

  if got == want do
    report.("constant #{name}", true)
  else
    report.("constant #{name}  (have #{inspect(got)}, corpus pins #{want})", false)
  end
end

cases = doc["split_cases"] || []

if cases == [] do
  IO.puts(:stderr, "corpus has no split cases")
  System.halt(1)
end

for c <- cases do
  payload = %{c["key"] => String.duplicate(c["unit"], c["times"])}
  msgs = Bonemesh.Chunk.split(doc["mid"], "a", "b", 16, payload)
  whole = length(msgs) == 1 and Map.has_key?(hd(msgs), "payload")
  lengths = if whole, do: [], else: Enum.map(msgs, &byte_size(&1["seg"]))
  ok = whole == c["expect_whole"] and lengths == c["segment_byte_lengths"]

  # A round-trip as the second oracle: matching lengths would not catch segments that
  # are the right size and the wrong bytes.
  {ok, detail} =
    cond do
      not ok ->
        {false,
         "  (whole=#{whole} want #{c["expect_whole"]}; lengths=#{inspect(Enum.take(lengths, 8))} " <>
           "want #{inspect(Enum.take(c["segment_byte_lengths"], 8))})"}

      whole ->
        {true, ""}

      true ->
        joined = Enum.map_join(msgs, & &1["seg"])

        case JSON.decode(joined) do
          {:ok, ^payload} -> {true, ""}
          _ -> {false, "  (segments did not rebuild the payload)"}
        end
    end

  report.("#{c["name"]}#{detail}", ok)
end

if :counters.get(fails, 1) > 0 do
  System.halt(1)
else
  IO.puts("splitting agrees with every pinned constant and cut position")
end
