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

  # --- Asymmetric primitives (raw FIPS/RFC encodings, matching Java/Go) ---

  @doc "Generates an ephemeral X25519 key pair as `{public, private}`."
  @spec x25519_generate() :: {binary(), binary()}
  def x25519_generate, do: :crypto.generate_key(:ecdh, :x25519)

  @doc "Computes the raw X25519 shared secret."
  @spec x25519_agree(binary(), binary()) :: binary()
  def x25519_agree(peer_public, my_private),
    do: :crypto.compute_key(:ecdh, peer_public, my_private, :x25519)

  @doc "Generates an ML-KEM-768 key pair as `{encapsulation_key, decapsulation_key}`."
  @spec mlkem_generate() :: {binary(), binary()}
  def mlkem_generate, do: :crypto.generate_key(:mlkem768, [])

  @doc "Encapsulates to a peer's ML-KEM-768 key, returning `{shared_secret, ciphertext}`."
  @spec mlkem_encapsulate(binary()) :: {binary(), binary()}
  def mlkem_encapsulate(encapsulation_key),
    do: :crypto.encapsulate_key(:mlkem768, encapsulation_key)

  @doc "Recovers the ML-KEM-768 shared secret from a ciphertext."
  @spec mlkem_decapsulate(binary(), binary()) :: binary()
  def mlkem_decapsulate(decapsulation_key, ciphertext),
    do: :crypto.decapsulate_key(:mlkem768, decapsulation_key, ciphertext)

  @doc "Generates an ML-DSA key pair (`:mldsa65` or `:mldsa87`) as `{public, private}`."
  @spec mldsa_generate(:mldsa65 | :mldsa87) :: {binary(), binary()}
  def mldsa_generate(level) when level in [:mldsa65, :mldsa87],
    do: :crypto.generate_key(level, [])

  @doc "Signs a message with an ML-DSA private key."
  @spec mldsa_sign(:mldsa65 | :mldsa87, binary(), binary()) :: binary()
  def mldsa_sign(level, private, message),
    do: :crypto.sign(level, :none, message, private)

  @doc "Verifies an ML-DSA signature."
  @spec mldsa_verify(:mldsa65 | :mldsa87, binary(), binary(), binary()) :: boolean()
  def mldsa_verify(level, public, message, signature),
    do: :crypto.verify(level, :none, message, signature, public)
end
