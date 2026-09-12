# Reads the shared key-log vector (spec/corpus/keylog.json) and confirms this
# implementation can open a key-logged capture.
#
# security.md §8 pins one implementation-neutral key-log format precisely so a
# single inspector reads a log written by a node in any language. That claim needs
# agreement in BOTH directions: emitting lines your own reader accepts is not
# enough. This checks the reading half against a committed capture the Java
# reference produced. The writing half is covered by each port's own key-log tests
# and, live and cross-language, by interop tier 10.
#
# Invoked by interop/check-keylog-elixir.sh.

alias Bonemesh.Transport

[path] = System.argv()
doc = path |> File.read!() |> JSON.decode!()

capture = doc["capture"] || []
expected = doc["expected"] || []

if capture == [] or length(capture) != length(expected) do
  IO.puts(:stderr, "vector malformed: #{length(capture)} capture, #{length(expected)} expected")
  System.halt(1)
end

# '#' lines are comments; an unknown label shape is ignored rather than fatal, so a
# future label is not a breaking change.
keys =
  (doc["keylog"] || [])
  |> Enum.reduce(%{}, fn raw, acc ->
    line = String.trim(raw)

    cond do
      line == "" or String.starts_with?(line, "#") ->
        acc

      true ->
        case String.split(line) do
          [label, _th, hex] ->
            case Regex.run(~r/^BMX3_(I2R|R2I)_TRAFFIC_(\d+)$/, label) do
              [_, dir, epoch] ->
                case Base.decode16(hex, case: :lower) do
                  {:ok, key} when byte_size(key) == 32 ->
                    Map.put(acc, {String.downcase(dir), String.to_integer(epoch)}, key)

                  _ ->
                    acc
                end

              _ ->
                acc
            end

          _ ->
            acc
        end
    end
  end)

if map_size(keys) == 0 do
  IO.puts(:stderr, "no usable key-log entries in the vector")
  System.halt(1)
end

failures = :counters.new(1, [])

Enum.zip(capture, expected)
|> Enum.with_index()
|> Enum.each(fn {{frame, want}, i} ->
  dir = frame["dir"]
  seq = frame["frame"]["seq"]
  ct = Base.decode64!(frame["frame"]["ct"])

  case Map.get(keys, {dir, want["epoch"]}) do
    nil ->
      IO.puts("FAIL frame #{i}: no key for #{dir} epoch #{want["epoch"]}")
      :counters.add(failures, 1, 1)

    key ->
      case Transport.open_ciphertext(key, seq, ct) do
        {:ok, pt} ->
          # Decoded maps compare structurally, so key order does not matter --
          # the contract is the structure, not the text.
          got = JSON.decode!(pt)

          if got == want["inner"] do
            IO.puts("PASS frame #{i} (#{dir} seq #{seq})")
          else
            IO.puts("FAIL frame #{i}\n  got:  #{inspect(got)}\n  want: #{inspect(want["inner"])}")
            :counters.add(failures, 1, 1)
          end

        :error ->
          IO.puts("FAIL frame #{i}: the logged #{dir} key did not open it")
          :counters.add(failures, 1, 1)
      end
  end
end)

# Self-test the oracle: a ciphertext no key seals must be refused, or a checker
# that reported success for everything would look identical to this one.
{_k, any_key} = Enum.at(keys, 0)

case Transport.open_ciphertext(any_key, 0, <<0::256>>) do
  :error ->
    IO.puts("PASS self-test: an unopenable frame is refused")

  {:ok, _} ->
    IO.puts("FAIL self-test: an unopenable frame was accepted")
    :counters.add(failures, 1, 1)
end

n = :counters.get(failures, 1)

if n > 0 do
  IO.puts(:stderr, "#{n} key-log frame(s) failed")
  System.halt(1)
end

IO.puts("every captured frame opens with its logged key and reproduces the vector")
