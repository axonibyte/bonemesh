# Cross-language post-quantum interop check: verifies the Java-produced vector
# (spec/corpus/transcripts/pqc-interop.json) from the Elixir side, using OTP
# 28's native ML-DSA and ML-KEM. Success means Elixir verifies a signature Java
# made and decapsulates a ciphertext Java produced to the identical secret --
# resolving the previously deferred post-quantum interop between the two.

[path] = System.argv()
doc = path |> File.read!() |> JSON.decode!()
hx = fn s -> Base.decode16!(s, case: :lower) end

dsa = doc["mldsa65"]

sig_ok =
  Bonemesh.Crypto.mldsa_verify(
    :mldsa65,
    hx.(dsa["public_hex"]),
    hx.(dsa["message_hex"]),
    hx.(dsa["signature_hex"])
  )

IO.puts("ML-DSA-65: Elixir verifies Java signature: #{sig_ok}")

kem = doc["mlkem768"]
recovered = Bonemesh.Crypto.mlkem_decapsulate(hx.(kem["decapsulation_key_hex"]), hx.(kem["ciphertext_hex"]))
kem_ok = recovered == hx.(kem["shared_secret_hex"])
IO.puts("ML-KEM-768: Elixir decapsulates Java ciphertext to Java secret: #{kem_ok}")

if sig_ok and kem_ok do
  IO.puts("post-quantum interop confirmed (Java -> Elixir)")
else
  IO.puts(:stderr, "post-quantum interop FAILED")
  System.halt(1)
end
