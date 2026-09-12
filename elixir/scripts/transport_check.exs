# Cross-language interop check: reproduces the shared transport-frame vector
# (spec/corpus/transcripts/transport-frame.json) with the Elixir implementation,
# and opens it again.
#
# The vector states both halves ("reproduces ct_hex and can open it"), so both
# are asserted: sealing alone would pass even if opening were broken, and opening
# alone would pass a transport that agreed with itself but not with the other
# implementations. Invoked by interop/check-transport-elixir.sh.

alias Bonemesh.Transport

[path] = System.argv()
doc = path |> File.read!() |> JSON.decode!()
i = doc["inputs"]
o = doc["outputs"]
hx = fn s -> Base.decode16!(s, case: :lower) end
hex = fn b -> Base.encode16(b, case: :lower) end

failures = :counters.new(1, [])

check = fn label, got, want ->
  if got == want do
    IO.puts("PASS #{label}")
  else
    IO.puts("FAIL #{label}\n  got:  #{got}\n  want: #{want}")
    :counters.add(failures, 1, 1)
  end
end

key = hx.(i["key_hex"])
seq = i["seq"]
inner_hex = i["inner_plaintext_hex"]

check.("ct_hex", hex.(Transport.seal_ciphertext(key, seq, hx.(inner_hex))), o["ct_hex"])

case Transport.open_ciphertext(key, seq, hx.(o["ct_hex"])) do
  {:ok, pt} -> check.("inner_plaintext_hex", hex.(pt), inner_hex)
  :error ->
    IO.puts("FAIL inner_plaintext_hex\n  got:  <authentication failed>")
    :counters.add(failures, 1, 1)
end

n = :counters.get(failures, 1)

if n > 0 do
  IO.puts(:stderr, "#{n} output(s) mismatched")
  System.halt(1)
end

IO.puts("transport frame seals and opens to the shared vector")
