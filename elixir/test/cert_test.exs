defmodule Bonemesh.CertTest do
  use ExUnit.Case, async: true

  alias Bonemesh.{Cert, Crypto}

  @now 1_788_600_000

  setup do
    {root_pub, root_priv} = Crypto.mldsa_generate(:mldsa87)
    {node_pub, _node_priv} = Crypto.mldsa_generate(:mldsa65)
    %{root_pub: root_pub, root_priv: root_priv, node_pub: node_pub}
  end

  defp cert(ctx, nbf, exp),
    do: Cert.new("acme-prod", "alpha", ctx.node_pub, nbf, exp) |> Cert.sign(ctx.root_priv)

  test "signed certificate verifies", ctx do
    assert :ok == Cert.verify(cert(ctx, @now - 100, @now + 100), ctx.root_pub, "acme-prod", @now)
  end

  test "unsigned certificate is rejected", ctx do
    unsigned = Cert.new("acme-prod", "alpha", ctx.node_pub, @now - 100, @now + 100)
    assert {:error, "certificate is unsigned"} == Cert.verify(unsigned, ctx.root_pub, "acme-prod", @now)
  end

  test "expired certificate is rejected", ctx do
    assert {:error, _} = Cert.verify(cert(ctx, @now - 200, @now - 100), ctx.root_pub, "acme-prod", @now)
  end

  test "mesh mismatch is rejected", ctx do
    assert {:error, "mesh mismatch"} == Cert.verify(cert(ctx, @now - 100, @now + 100), ctx.root_pub, "other", @now)
  end

  test "wrong root key is rejected", ctx do
    {other_root, _} = Crypto.mldsa_generate(:mldsa87)
    assert {:error, _} = Cert.verify(cert(ctx, @now - 100, @now + 100), other_root, "acme-prod", @now)
  end

  test "tampered identity key is rejected", ctx do
    {other_node, _} = Crypto.mldsa_generate(:mldsa65)
    tampered = cert(ctx, @now - 100, @now + 100) |> Map.put("idk", Base.encode64(other_node))
    assert {:error, _} = Cert.verify(tampered, ctx.root_pub, "acme-prod", @now)
  end
end
