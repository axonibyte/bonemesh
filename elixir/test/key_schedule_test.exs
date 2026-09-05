defmodule Bonemesh.KeyScheduleTest do
  use ExUnit.Case, async: true

  alias Bonemesh.Crypto
  alias Bonemesh.KeySchedule, as: KS

  # Correctness and composition. The exact shared vector is verified against
  # spec/corpus/transcripts/keyschedule.json by interop/check-keyschedule-elixir.sh
  # (and independently by the Java and Go runners); this suite proves the
  # schedule is correct against the SHA-256 formula and stays in lockstep.

  defp ramp(start), do: for(i <- 0..31, into: <<>>, do: <<start + i>>)

  defp driven do
    KS.new()
    |> KS.mix_hash("acme-prod")
    |> KS.mix_key(ramp(1))
    |> KS.mix_key(ramp(0x21))
  end

  test "init seeds the hash from the protocol name" do
    assert KS.new().h == Crypto.sha256(KS.protocol_name())
  end

  test "mix_hash follows the SHA-256 formula" do
    s0 = KS.new()
    s1 = KS.mix_hash(s0, "transcript-bytes")
    assert s1.h == Crypto.sha256(s0.h <> "transcript-bytes")
  end

  test "same inputs yield the same chaining key" do
    assert driven().ck == driven().ck
  end

  test "initiator and responder stay in lockstep" do
    initiator = driven()
    responder = driven()

    {ct1, initiator} = KS.encrypt_and_hash(initiator, "responder sees this")
    {:ok, m1, responder} = KS.decrypt_and_hash(responder, ct1)
    assert m1 == "responder sees this"

    {ct2, initiator} = KS.encrypt_and_hash(initiator, "and this second one")
    {:ok, m2, responder} = KS.decrypt_and_hash(responder, ct2)
    assert m2 == "and this second one"

    assert initiator.h == responder.h
    assert KS.split(initiator) == KS.split(responder)
  end

  test "mix_key resets the nonce counter" do
    s = KS.new() |> KS.mix_key(ramp(1))
    {_ct, s} = KS.encrypt_and_hash(s, "first")
    assert s.nonce == 1
    s = KS.mix_key(s, ramp(0x21))
    assert s.nonce == 0
  end

  test "a tampered ciphertext fails to decrypt" do
    {ct, _} = KS.encrypt_and_hash(driven(), "payload")
    <<first, rest::binary>> = ct
    tampered = <<Bitwise.bxor(first, 1), rest::binary>>
    assert :error == KS.decrypt_and_hash(driven(), tampered)
  end
end
