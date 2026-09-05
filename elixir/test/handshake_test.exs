defmodule Bonemesh.HandshakeTest do
  use ExUnit.Case, async: true

  alias Bonemesh.{Cert, Crypto, Handshake}

  @mesh "acme-prod"
  @now 1_788_600_000

  setup do
    {root_pub, root_priv} = Crypto.mldsa_generate(:mldsa87)
    %{root_pub: root_pub, root_priv: root_priv}
  end

  defp identity(ctx, label) do
    {pub, priv} = Crypto.mldsa_generate(:mldsa65)
    cert = Cert.new(@mesh, label, pub, @now - 100, @now + 100) |> Cert.sign(ctx.root_priv)
    {cert, pub, priv}
  end

  defp run(a0, b0) do
    {m1, a1} = Handshake.write_message1(a0)
    {:ok, m2, b1} = Handshake.read_message1_write_message2(b0, m1)
    {:ok, m3, a2} = Handshake.read_message2_write_message3(a1, m2)
    {:ok, b2} = Handshake.read_message3(b1, m3)
    {a2, b2}
  end

  test "full handshake agrees on keys and identities", ctx do
    {ac, apub, apriv} = identity(ctx, "alpha")
    {bc, bpub, bpriv} = identity(ctx, "beta")
    a0 = Handshake.initiator(@mesh, ctx.root_pub, @now, ac, apub, apriv)
    b0 = Handshake.responder(@mesh, ctx.root_pub, @now, bc, bpub, bpriv)

    {a, b} = run(a0, b0)
    sa = Handshake.session(a)
    sb = Handshake.session(b)

    # Directions line up; keys differ.
    assert sa.send_key == sb.receive_key
    assert sa.receive_key == sb.send_key
    refute sa.send_key == sa.receive_key
    # Each learned the other's authenticated identity.
    assert sa.peer_cert["label"] == "beta"
    assert sb.peer_cert["label"] == "alpha"
  end

  test "responder rejects a foreign mesh", ctx do
    {ac, apub, apriv} = identity(ctx, "alpha")
    {bc, bpub, bpriv} = identity(ctx, "beta")
    a0 = Handshake.initiator(@mesh, ctx.root_pub, @now, ac, apub, apriv)
    b0 = Handshake.responder("other-mesh", ctx.root_pub, @now, bc, bpub, bpriv)
    {m1, _a1} = Handshake.write_message1(a0)
    assert {:error, _} = Handshake.read_message1_write_message2(b0, m1)
  end

  test "initiator rejects a responder signed by another root", ctx do
    {ac, apub, apriv} = identity(ctx, "alpha")
    {bpub, bpriv} = Crypto.mldsa_generate(:mldsa65)
    {other_root_pub, other_root_priv} = Crypto.mldsa_generate(:mldsa87)
    bc = Cert.new(@mesh, "beta", bpub, @now - 100, @now + 100) |> Cert.sign(other_root_priv)
    _ = other_root_pub

    a0 = Handshake.initiator(@mesh, ctx.root_pub, @now, ac, apub, apriv)
    b0 = Handshake.responder(@mesh, ctx.root_pub, @now, bc, bpub, bpriv)
    {m1, a1} = Handshake.write_message1(a0)
    {:ok, m2, _b1} = Handshake.read_message1_write_message2(b0, m1)
    assert {:error, _} = Handshake.read_message2_write_message3(a1, m2)
  end

  test "a party presenting a cert it does not own is rejected", ctx do
    {ac, apub, apriv} = identity(ctx, "alpha")
    {bc, bpub, _bpriv} = identity(ctx, "beta")
    {_wrong_pub, wrong_priv} = Crypto.mldsa_generate(:mldsa65)

    a0 = Handshake.initiator(@mesh, ctx.root_pub, @now, ac, apub, apriv)
    # Responder holds beta's real cert but signs with the wrong identity key.
    b0 = Handshake.responder(@mesh, ctx.root_pub, @now, bc, bpub, wrong_priv)
    {m1, a1} = Handshake.write_message1(a0)
    {:ok, m2, _b1} = Handshake.read_message1_write_message2(b0, m1)
    assert {:error, reason} = Handshake.read_message2_write_message3(a1, m2)
    assert reason =~ "signature"
  end
end
