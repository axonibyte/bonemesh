# Cross-language interop check: reproduces the shared key-schedule vector
# (spec/corpus/transcripts/keyschedule.json) with the Elixir implementation.
# The Java and Go runners reproduce the same vector, so matching every output
# means all three derive identical transcript hashes, chaining keys, and
# transport keys. Invoked by interop/check-keyschedule-elixir.sh.

alias Bonemesh.KeySchedule, as: KS

[path] = System.argv()
doc = path |> File.read!() |> JSON.decode!()
i = doc["inputs"]
o = doc["outputs"]
hx = fn s -> Base.decode16!(s, case: :lower) end
hex = fn b -> Base.encode16(b, case: :lower) end

failures = :counters.new(1, [])

check = fn label, got, want ->
  if hex.(got) == want do
    IO.puts("PASS #{label}")
  else
    IO.puts("FAIL #{label}\n  got:  #{hex.(got)}\n  want: #{want}")
    :counters.add(failures, 1, 1)
  end
end

s = KS.new()
check.("h_init", s.h, o["h_init"])
s = KS.mix_hash(s, hx.(i["mesh_hex"]))
check.("h_after_mesh", s.h, o["h_after_mesh"])
s = KS.mix_key(s, hx.(i["ss_dh_hex"]))
check.("ck_after_dh", s.ck, o["ck_after_dh"])
s = KS.mix_key(s, hx.(i["ss_kem_hex"]))
check.("ck_after_kem", s.ck, o["ck_after_kem"])
{ct1, s} = KS.encrypt_and_hash(s, hx.(i["plaintext1_hex"]))
check.("ct1", ct1, o["ct1_hex"])
check.("h_after_ct1", s.h, o["h_after_ct1"])
{ct2, s} = KS.encrypt_and_hash(s, hx.(i["plaintext2_hex"]))
check.("ct2", ct2, o["ct2_hex"])
check.("h_after_ct2", s.h, o["h_after_ct2"])
{i2r, r2i} = KS.split(s)
check.("transport_key_i2r", i2r, o["transport_key_i2r"])
check.("transport_key_r2i", r2i, o["transport_key_r2i"])

n = :counters.get(failures, 1)

if n > 0 do
  IO.puts(:stderr, "#{n} key-schedule output(s) mismatched")
  System.halt(1)
else
  IO.puts("all key-schedule outputs match")
end
