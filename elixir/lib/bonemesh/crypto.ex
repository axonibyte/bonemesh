defmodule Bonemesh.Crypto do
  @moduledoc """
  BoneMesh v3 cryptographic primitives (security.md §1), all over OTP 28's
  `:crypto`: HKDF-SHA-256, ChaCha20-Poly1305, SHA-256, X25519, ML-KEM-768, and
  ML-DSA. Encodings are the raw FIPS/RFC byte strings, matching the Java and Go
  implementations.
  """

  @doc "SHA-256 digest."
  @spec sha256(binary()) :: binary()
  def sha256(data), do: :crypto.hash(:sha256, data)

  @doc """
  HKDF-SHA-256 (RFC 5869), full extract-then-expand. Matches the Java reference's
  `Hkdf.derive(salt, ikm, info, length)`.
  """
  @spec hkdf(binary(), binary(), binary(), non_neg_integer()) :: binary()
  def hkdf(salt, ikm, info, length) do
    prk = :crypto.mac(:hmac, :sha256, salt, ikm)
    expand(prk, info, length)
  end

  defp expand(prk, info, length) do
    blocks = div(length + 31, 32)

    {okm, _} =
      Enum.reduce(1..blocks, {<<>>, <<>>}, fn i, {acc, prev} ->
        t = :crypto.mac(:hmac, :sha256, prk, prev <> info <> <<i>>)
        {acc <> t, t}
      end)

    binary_part(okm, 0, length)
  end

  @doc """
  ChaCha20-Poly1305 seal (RFC 8439): returns ciphertext with the 16-byte tag
  appended, matching the Java/Go framing.
  """
  @spec aead_seal(binary(), binary(), binary(), binary()) :: binary()
  def aead_seal(key, nonce, aad, plaintext) do
    {ct, tag} =
      :crypto.crypto_one_time_aead(:chacha20_poly1305, key, nonce, plaintext, aad, true)

    ct <> tag
  end

  @doc """
  ChaCha20-Poly1305 open. Returns `{:ok, plaintext}` or `:error` on tag failure.
  """
  @spec aead_open(binary(), binary(), binary(), binary()) :: {:ok, binary()} | :error
  def aead_open(key, nonce, aad, ct_with_tag) do
    ct_len = byte_size(ct_with_tag) - 16
    <<ct::binary-size(ct_len), tag::binary-size(16)>> = ct_with_tag

    case :crypto.crypto_one_time_aead(:chacha20_poly1305, key, nonce, ct, aad, tag, false) do
      :error -> :error
      plaintext -> {:ok, plaintext}
    end
  end
end
