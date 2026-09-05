defmodule Bonemesh.KeySchedule do
  @moduledoc """
  The BMX key schedule (security.md §5): a Noise-style symmetric state carrying
  a transcript hash `h` and a chaining key `ck`. The pinned constants match the
  Java reference and the Go conformance runner, verified against the shared
  vector (spec/corpus/transcripts/keyschedule.json), so all three languages
  derive identical keys.

  Conventions (pinned): `h`/`ck` seed from SHA-256 of the protocol name;
  `mix_hash` is `h = SHA-256(h || data)`; `mix_key` is HKDF-SHA-256 with the
  chaining key as salt (DH before KEM), resetting the nonce; the AEAD nonce is
  4 zero bytes then the 64-bit little-endian counter; `split` derives the two
  directional transport keys.
  """

  @protocol_name "BoneMesh_BMX_v3_X25519MLKEM768_ChaChaPoly_SHA256"

  defstruct h: nil, ck: nil, key: nil, nonce: 0

  @type t :: %__MODULE__{h: binary(), ck: binary(), key: binary() | nil, nonce: non_neg_integer()}

  @doc "The pinned protocol name."
  def protocol_name, do: @protocol_name

  @doc "Initializes the state from the protocol name."
  @spec new() :: t()
  def new do
    h = Bonemesh.Crypto.sha256(@protocol_name)
    %__MODULE__{h: h, ck: h, key: nil, nonce: 0}
  end

  @doc "Absorbs data into the transcript hash."
  @spec mix_hash(t(), binary()) :: t()
  def mix_hash(%__MODULE__{} = s, data) do
    %{s | h: Bonemesh.Crypto.sha256(s.h <> data)}
  end

  @doc "Mixes input key material, deriving a fresh key and resetting the nonce."
  @spec mix_key(t(), binary()) :: t()
  def mix_key(%__MODULE__{} = s, ikm) do
    okm = Bonemesh.Crypto.hkdf(s.ck, ikm, <<>>, 64)
    <<ck::binary-size(32), key::binary-size(32)>> = okm
    %{s | ck: ck, key: key, nonce: 0}
  end

  @doc """
  Encrypts a plaintext with `h` as associated data, then absorbs the ciphertext.
  Returns `{ciphertext, new_state}`.
  """
  @spec encrypt_and_hash(t(), binary()) :: {binary(), t()}
  def encrypt_and_hash(%__MODULE__{} = s, plaintext) do
    ct = Bonemesh.Crypto.aead_seal(s.key, nonce(s.nonce), s.h, plaintext)
    s = %{s | nonce: s.nonce + 1}
    {ct, mix_hash(s, ct)}
  end

  @doc """
  Decrypts a ciphertext (AAD is the current `h`), then absorbs it. Returns
  `{:ok, plaintext, new_state}` or `:error`.
  """
  @spec decrypt_and_hash(t(), binary()) :: {:ok, binary(), t()} | :error
  def decrypt_and_hash(%__MODULE__{} = s, ciphertext) do
    case Bonemesh.Crypto.aead_open(s.key, nonce(s.nonce), s.h, ciphertext) do
      {:ok, plaintext} ->
        s = %{s | nonce: s.nonce + 1}
        {:ok, plaintext, mix_hash(s, ciphertext)}

      :error ->
        :error
    end
  end

  @doc "Derives the two directional transport keys from the final chaining key."
  @spec split(t()) :: {binary(), binary()}
  def split(%__MODULE__{} = s) do
    okm = Bonemesh.Crypto.hkdf(s.ck, <<>>, <<>>, 64)
    <<i2r::binary-size(32), r2i::binary-size(32)>> = okm
    {i2r, r2i}
  end

  # Nonce = 4 zero bytes || 64-bit little-endian counter.
  defp nonce(counter), do: <<0::32, counter::little-64>>
end
