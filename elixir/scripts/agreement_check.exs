# Cross-language interop check: reproduces the shared hybrid key-agreement vector
# (spec/corpus/transcripts/handshake-agreement.json) with the Elixir
# implementation. Invoked by interop/check-agreement-elixir.sh.
#
# Sequence (security.md 5): mix_hash(mesh, ei_pub, ki_ek, n); mix_hash(er_pub);
# mix_key(ss_dh); mix_hash(kem_ct); mix_key(ss_kem); split().
#
# The X25519 secret is DERIVED here from ei_priv and er_pub rather than read out
# of the vector, and then compared against the vector's ss_dh_hex. That is a
# second oracle the schedule alone cannot give: feeding the vector's own ss_dh
# straight into mix_key would still pass on an implementation whose X25519
# agreement was broken, because nothing would ever have computed it. Go and Java
# derive it the same way, for the same reason.

alias Bonemesh.Crypto
alias Bonemesh.KeySchedule, as: KS

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

# Oracle 1: the X25519 agreement itself, computed rather than assumed.
ss_dh = Crypto.x25519_agree(hx.(i["er_pub_hex"]), hx.(i["ei_priv_hex"]))
check.("ss_dh (derived)", hex.(ss_dh), i["ss_dh_hex"])

# Oracle 2: the transcript checkpoints and the transport keys.
s = KS.new()
s = KS.mix_hash(s, hx.(i["mesh_hex"]))
s = KS.mix_hash(s, hx.(i["ei_pub_hex"]))
s = KS.mix_hash(s, hx.(i["ki_ek_hex"]))
s = KS.mix_hash(s, hx.(i["n_hex"]))
check.("h_after_msg1", hex.(s.h), o["h_after_msg1"])

s = KS.mix_hash(s, hx.(i["er_pub_hex"]))
s = KS.mix_key(s, ss_dh)
check.("ck_after_dh", hex.(s.ck), o["ck_after_dh"])

s = KS.mix_hash(s, hx.(i["kem_ct_hex"]))
s = KS.mix_key(s, hx.(i["ss_kem_hex"]))
check.("ck_after_kem", hex.(s.ck), o["ck_after_kem"])

# The msg-2 checkpoint is taken once both message-2 hash inputs (responder
# ephemeral and KEM ciphertext) are absorbed; mix_key does not alter h.
check.("h_after_msg2_ephemerals", hex.(s.h), o["h_after_msg2_ephemerals"])

{i2r, r2i} = KS.split(s)
check.("transport_key_i2r", hex.(i2r), o["transport_key_i2r"])
check.("transport_key_r2i", hex.(r2i), o["transport_key_r2i"])

n = :counters.get(failures, 1)

if n > 0 do
  IO.puts(:stderr, "#{n} checkpoint(s) mismatched")
  System.halt(1)
end

IO.puts("hybrid key agreement reproduces every shared checkpoint")
