defmodule Bonemesh.Handshake do
  @moduledoc """
  The BMX handshake (security.md §4): a three-message, mutually authenticated,
  forward-secret exchange. Hybrid X25519 + ML-KEM-768 forward secrecy mixed
  through `Bonemesh.KeySchedule`; authentication by a root-signed certificate
  plus an ML-DSA signature over the live transcript. Field-for-field identical
  to the Java reference, so an Elixir node and a Java node complete a handshake
  together.

  A handshake value is a struct threaded through the step functions; each step
  returns `{message, state}` or `{:ok, message, state}` / `{:error, reason}`.
  """

  alias Bonemesh.{Cert, Crypto, KeySchedule}

  @version 3

  defstruct [
    :initiator,
    :mesh,
    :root_public,
    :now,
    :cert,
    :id_public,
    :id_private,
    :ks,
    :eph_dh_public,
    :eph_dh_private,
    :eph_kem_public,
    :eph_kem_private,
    :session,
    :peer_cert
  ]

  @doc "Creates the initiating side."
  def initiator(mesh, root_public, now, cert, id_public, id_private),
    do: new(true, mesh, root_public, now, cert, id_public, id_private)

  @doc "Creates the responding side."
  def responder(mesh, root_public, now, cert, id_public, id_private),
    do: new(false, mesh, root_public, now, cert, id_public, id_private)

  defp new(initiator, mesh, root_public, now, cert, id_public, id_private) do
    ks = KeySchedule.new() |> KeySchedule.mix_hash(mesh)

    %__MODULE__{
      initiator: initiator,
      mesh: mesh,
      root_public: root_public,
      now: now,
      cert: cert,
      id_public: id_public,
      id_private: id_private,
      ks: ks
    }
  end

  @doc "Initiator: produces message 1."
  def write_message1(%__MODULE__{initiator: true} = s) do
    {dh_pub, dh_priv} = Crypto.x25519_generate()
    {kem_pub, kem_priv} = Crypto.mlkem_generate()
    n = :crypto.strong_rand_bytes(32)

    ks = s.ks |> KeySchedule.mix_hash(dh_pub) |> KeySchedule.mix_hash(kem_pub) |> KeySchedule.mix_hash(n)

    msg =
      line(%{
        "t" => "bmx1",
        "v" => @version,
        "mesh" => s.mesh,
        "e" => Base.encode64(dh_pub),
        "k" => Base.encode64(kem_pub),
        "n" => Base.encode64(n)
      })

    {msg, %{s | eph_dh_public: dh_pub, eph_dh_private: dh_priv, eph_kem_public: kem_pub, eph_kem_private: kem_priv, ks: ks}}
  end

  @doc "Responder: consumes message 1, produces message 2."
  def read_message1_write_message2(%__MODULE__{initiator: false} = s, msg1) do
    # Malformed peer input (bad JSON, bad base64, wrong shape) is rejected
    # gracefully rather than crashing the connection process.
    try do
      do_read_message1_write_message2(s, msg1)
    rescue
      _ -> {:error, "malformed handshake message"}
    end
  end

  defp do_read_message1_write_message2(s, msg1) do
    m = decode(msg1)

    cond do
      m["t"] != "bmx1" -> {:error, "expected bmx1"}
      m["v"] != @version -> {:error, "unsupported version"}
      m["mesh"] != s.mesh -> {:error, "mesh mismatch"}
      true ->
        ei_pub = Base.decode64!(m["e"])
        ki_ek = Base.decode64!(m["k"])
        n = Base.decode64!(m["n"])

        ks = s.ks |> KeySchedule.mix_hash(ei_pub) |> KeySchedule.mix_hash(ki_ek) |> KeySchedule.mix_hash(n)

        {er_pub, er_priv} = Crypto.x25519_generate()
        ks = KeySchedule.mix_hash(ks, er_pub)
        ss_dh = Crypto.x25519_agree(ei_pub, er_priv)
        ks = KeySchedule.mix_key(ks, ss_dh)

        {ss_kem, ct} = Crypto.mlkem_encapsulate(ki_ek)
        ks = ks |> KeySchedule.mix_hash(ct) |> KeySchedule.mix_key(ss_kem)

        {auth, ks} = seal_identity(ks, s)

        msg =
          line(%{"t" => "bmx2", "e" => Base.encode64(er_pub), "ct" => Base.encode64(ct), "auth" => Base.encode64(auth)})

        {:ok, msg, %{s | ks: ks}}
    end
  end

  @doc "Initiator: consumes message 2 (verifying the responder), produces message 3."
  def read_message2_write_message3(%__MODULE__{initiator: true} = s, msg2) do
    try do
      do_read_message2_write_message3(s, msg2)
    rescue
      _ -> {:error, "malformed handshake message"}
    end
  end

  defp do_read_message2_write_message3(s, msg2) do
    m = decode(msg2)
    er_pub = Base.decode64!(m["e"])
    ct = Base.decode64!(m["ct"])
    auth = Base.decode64!(m["auth"])

    ks = KeySchedule.mix_hash(s.ks, er_pub)
    ss_dh = Crypto.x25519_agree(er_pub, s.eph_dh_private)
    ks = KeySchedule.mix_key(ks, ss_dh)
    ks = KeySchedule.mix_hash(ks, ct)
    ss_kem = Crypto.mlkem_decapsulate(s.eph_kem_private, ct)
    ks = KeySchedule.mix_key(ks, ss_kem)

    case open_identity(ks, auth, s) do
      {:error, reason} ->
        {:error, reason}

      {:ok, peer_cert, ks} ->
        {auth_i, ks} = seal_identity(ks, s)
        msg = line(%{"t" => "bmx3", "auth" => Base.encode64(auth_i)})
        {i2r, r2i} = KeySchedule.split(ks)
        session = %{send_key: i2r, receive_key: r2i, peer_cert: peer_cert}
        {:ok, msg, %{s | ks: ks, session: session, peer_cert: peer_cert}}
    end
  end

  @doc "Responder: consumes message 3, completing the handshake."
  def read_message3(%__MODULE__{initiator: false} = s, msg3) do
    try do
      do_read_message3(s, msg3)
    rescue
      _ -> {:error, "malformed handshake message"}
    end
  end

  defp do_read_message3(s, msg3) do
    m = decode(msg3)
    auth = Base.decode64!(m["auth"])

    case open_identity(s.ks, auth, s) do
      {:error, reason} ->
        {:error, reason}

      {:ok, peer_cert, ks} ->
        {i2r, r2i} = KeySchedule.split(ks)
        session = %{send_key: r2i, receive_key: i2r, peer_cert: peer_cert}
        {:ok, %{s | ks: ks, session: session, peer_cert: peer_cert}}
    end
  end

  @doc "The completed session (`%{send_key, receive_key, peer_cert}`)."
  def session(%__MODULE__{session: session}), do: session

  # Signs the current transcript, packages {cert, sig}, encrypts into the transcript.
  defp seal_identity(ks, s) do
    sig = Crypto.mldsa_sign(:mldsa65, s.id_private, ks.h)
    payload = JSON.encode!(%{"cert" => s.cert, "sig" => Base.encode64(sig)})
    KeySchedule.encrypt_and_hash(ks, payload)
  end

  # Decrypts the peer identity, verifies its certificate and transcript signature.
  defp open_identity(ks, auth, s) do
    h_pre = ks.h

    case KeySchedule.decrypt_and_hash(ks, auth) do
      :error ->
        {:error, "handshake authentication failed"}

      {:ok, plaintext, ks} ->
        payload = JSON.decode!(plaintext)
        peer_cert = payload["cert"]
        sig = Base.decode64!(payload["sig"])

        with :ok <- Cert.verify(peer_cert, s.root_public, s.mesh, s.now),
             true <- Crypto.mldsa_verify(:mldsa65, Cert.identity_key(peer_cert), h_pre, sig) do
          {:ok, peer_cert, ks}
        else
          {:error, reason} -> {:error, "peer certificate invalid: " <> reason}
          false -> {:error, "peer transcript signature does not verify"}
        end
    end
  end

  defp line(map), do: JSON.encode!(map) <> "\n"
  defp decode(bin), do: bin |> String.trim() |> JSON.decode!()
end
