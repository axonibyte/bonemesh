defmodule Bonemesh.Cert do
  @moduledoc """
  A BoneMesh v3 membership certificate (security.md §3): a mesh-root-signed
  binding of a display label to a node's ML-DSA-65 identity key, valid within a
  time window. Represented as a plain map with string keys (the JSON form); its
  signed pre-image is the `Bonemesh.Canon` canonicalization of every field
  except `"sig"`. Interoperates with the Java reference (shared corpus and the
  PQC interop vector).
  """

  @version 3

  @doc """
  Builds an unsigned certificate map.

  `identity_key` is the node's raw ML-DSA-65 public key.
  """
  @spec new(String.t(), String.t(), binary(), integer(), integer()) :: map()
  def new(mesh, label, identity_key, not_before, not_after) do
    %{
      "v" => @version,
      "mesh" => mesh,
      "label" => label,
      "idk" => Base.encode64(identity_key),
      "nbf" => not_before,
      "exp" => not_after
    }
  end

  @doc "Signs a certificate with the mesh root's ML-DSA-87 private key."
  @spec sign(map(), binary()) :: map()
  def sign(cert, root_private) do
    sig = Bonemesh.Crypto.mldsa_sign(:mldsa87, root_private, Bonemesh.Canon.canonicalize(cert))
    Map.put(cert, "sig", Base.encode64(sig))
  end

  @doc """
  Verifies a certificate against the pinned root public key, mesh, and time.
  Returns `:ok` or `{:error, reason}`.
  """
  @spec verify(map(), binary(), String.t(), integer()) :: :ok | {:error, String.t()}
  def verify(cert, root_public, expected_mesh, now) do
    cond do
      cert["mesh"] != expected_mesh -> {:error, "mesh mismatch"}
      now < cert["nbf"] -> {:error, "certificate not yet valid"}
      now > cert["exp"] -> {:error, "certificate expired"}
      not Map.has_key?(cert, "sig") -> {:error, "certificate is unsigned"}
      true -> verify_signature(cert, root_public)
    end
  end

  @doc "The node's raw ML-DSA-65 identity public key."
  @spec identity_key(map()) :: binary()
  def identity_key(cert), do: Base.decode64!(cert["idk"])

  defp verify_signature(cert, root_public) do
    sig = Base.decode64!(cert["sig"])
    pre_image = cert |> Map.delete("sig") |> Bonemesh.Canon.canonicalize()

    if Bonemesh.Crypto.mldsa_verify(:mldsa87, root_public, pre_image, sig),
      do: :ok,
      else: {:error, "root signature does not verify"}
  end
end
