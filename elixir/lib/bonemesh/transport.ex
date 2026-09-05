defmodule Bonemesh.Transport do
  @moduledoc """
  The encrypted transport channel over a completed handshake (protocol.md §4):
  each frame is a sequence-numbered AEAD carrier `%{"seq" => n, "ct" => ...}`
  whose plaintext is the inner JSON message. The per-direction sequence is the
  ChaCha20-Poly1305 nonce (4 zero bytes then the 64-bit little-endian counter),
  never reused; reordered or replayed frames are rejected. Matches the Java
  reference (shared vector spec/corpus/transcripts/transport-frame.json).

  A session is a map `%{send_key, receive_key, send_seq, receive_seq}`.
  """

  @doc "Builds a transport session from a completed handshake session."
  def session(%{send_key: sk, receive_key: rk}),
    do: %{send_key: sk, receive_key: rk, send_seq: 0, receive_seq: 0}

  @doc "Seals an inner message. Returns `{carrier_map, session}`."
  def seal(session, inner) do
    seq = session.send_seq
    ct = seal_ciphertext(session.send_key, seq, JSON.encode!(inner))
    {%{"seq" => seq, "ct" => Base.encode64(ct)}, %{session | send_seq: seq + 1}}
  end

  @doc """
  Opens a transport carrier, enforcing in-order delivery. Returns
  `{:ok, inner, session}` or `{:error, reason}`.
  """
  def open(session, carrier) do
    seq = carrier["seq"]

    cond do
      seq != session.receive_seq ->
        {:error, "out-of-order frame: expected #{session.receive_seq}, got #{seq}"}

      true ->
        ct = Base.decode64!(carrier["ct"])

        case Bonemesh.Crypto.aead_open(session.receive_key, nonce(seq), <<>>, ct) do
          {:ok, plaintext} -> {:ok, JSON.decode!(plaintext), %{session | receive_seq: seq + 1}}
          :error -> {:error, "frame authentication failed"}
        end
    end
  end

  @doc "Seals a transport-frame ciphertext (the single AEAD implementation)."
  def seal_ciphertext(key, seq, plaintext),
    do: Bonemesh.Crypto.aead_seal(key, nonce(seq), <<>>, plaintext)

  defp nonce(seq), do: <<0::32, seq::little-64>>
end
