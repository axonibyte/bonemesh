defmodule Bonemesh.MessageSchema do
  @moduledoc """
  Validates BoneMesh v3 message objects against the pinned schemas (protocol.md
  §4, security.md §4), mirroring the Java and Go validators reason-for-reason so
  all three agree on which messages are well formed (shared corpus:
  spec/corpus/messages.json).
  """

  @doc """
  Validates a message map against a named schema. Returns `nil` if valid, or a
  short reason tag. Schemas: `"bmx1"`, `"envelope"`, `"data"`, `"ack"`, `"nak"`,
  `"bye"`.
  """
  @spec validate(String.t(), map()) :: nil | String.t()
  def validate("bmx1", f), do: validate_bmx1(f)
  def validate("bmx2", f), do: validate_bmx2(f)
  def validate("bmx3", f), do: validate_bmx3(f)
  def validate("disco", f), do: validate_disco(f)
  def validate("probe", f), do: validate_token_carrier(f, "probe")
  def validate("echo", f), do: validate_token_carrier(f, "echo")
  def validate("rekey", f), do: validate_rekey(f)
  def validate("envelope", f), do: validate_envelope(f)
  def validate("data", f), do: validate_data(f)
  def validate("ack", f), do: validate_ack(f)
  def validate("nak", f), do: validate_nak(f)
  def validate("bye", f), do: validate_bye(f)
  def validate(_other, _f), do: "unknown-schema"

  defp validate_bmx1(f) do
    cond do
      f["t"] != "bmx1" -> "type"
      f["v"] != 3 -> "version"
      not is_binary(f["mesh"]) or f["mesh"] == "" -> "empty-mesh"
      true -> first_missing_or_base64(f, ["e", "k", "n"])
    end
  end

  # Handshake messages 2 and 3 (security.md §4). Both carry one sealed "auth"
  # member rather than separate cert and sig.
  defp validate_bmx2(f) do
    if f["t"] != "bmx2", do: "type", else: first_missing_or_base64(f, ["e", "ct", "auth"])
  end

  defp validate_bmx3(f) do
    if f["t"] != "bmx3", do: "type", else: first_missing_or_base64(f, ["auth"])
  end

  # Route advertisement (protocol.md §4.2, §6). An empty advertisement is %{}.
  defp validate_disco(f) do
    cond do
      f["type"] != "disco" ->
        "type"

      not Map.has_key?(f, "routes") ->
        "missing-field"

      not is_map(f["routes"]) ->
        "routes-format"

      Enum.any?(f["routes"], fn {_k, c} -> not is_integer(c) or c < 0 end) ->
        "routes-format"

      true ->
        nil
    end
  end

  # Latency measurement pair (§4.2, §5). The token is opaque to the responder,
  # which echoes it back unchanged, so only its type is constrained.
  defp validate_token_carrier(f, want) do
    cond do
      f["type"] != want -> "type"
      not Map.has_key?(f, "token") -> "missing-field"
      not is_integer(f["token"]) -> "token-format"
      true -> nil
    end
  end

  # Tunneled BMX rekey (§4.2, security.md §6). Phases 1-3 carry the BMX bytes in
  # "body"; phase 4 carries no BMX message and must omit it.
  defp validate_rekey(f) do
    cond do
      f["type"] != "rekey" -> "type"
      (r = mid_reason(f["mid"])) != nil -> r
      not Map.has_key?(f, "phase") -> "missing-field"
      not is_integer(f["phase"]) or f["phase"] < 1 or f["phase"] > 4 -> "phase-range"
      f["phase"] == 4 -> if Map.has_key?(f, "body"), do: "body-or-phase", else: nil
      not Map.has_key?(f, "body") -> "body-or-phase"
      true -> base64_reason(f["body"])
    end
  end

  defp validate_envelope(f) do
    cond do
      not is_integer(f["seq"]) -> "missing-field"
      f["seq"] < 0 -> "seq-range"
      not Map.has_key?(f, "ct") -> "missing-field"
      true -> base64_reason(f["ct"])
    end
  end

  defp validate_data(f) do
    cond do
      f["type"] != "data" -> "type"
      (r = mid_reason(f["mid"])) != nil -> r
      not is_binary(f["to"]) -> "missing-field"
      not is_binary(f["from"]) -> "missing-field"
      not is_integer(f["ttl"]) -> "missing-field"
      f["ttl"] < 1 or f["ttl"] > 255 -> "ttl-range"
      true -> check_chunking(f)
    end
  end

  # Validates the splitting half of the data schema (protocol.md §6.1): the shape of
  # "chunk", its bounds, and the rule that exactly one of "payload" and "seg" is
  # present.
  #
  # The exclusion is the load-bearing part. It is what stops a node that does not
  # reassemble from handing a fragment to the application as though it were a whole
  # message -- the silent corruption D11 described. A segment has no payload to
  # deliver, so the mistake is unavailable rather than merely forbidden.
  #
  # Carrying neither stays "missing-field" rather than becoming a splitting error: it
  # is an absent field, the corpus has pinned that reason since 3.0.0, and renaming it
  # here would have rewritten a vector rather than added one.
  defp check_chunking(f) do
    case chunk_reason(f) do
      {:error, reason} ->
        reason

      {:ok, n} ->
        has_payload = Map.has_key?(f, "payload")
        has_seg = Map.has_key?(f, "seg")

        cond do
          not has_payload and not has_seg -> "missing-field"
          # Three clauses, none redundant. An explicit "both present" test was removed:
          # mutation showed it could not reject anything these two do not already
          # reject, since n is always 1 or more, so it read as coverage while
          # asserting nothing.
          n == 1 and has_seg -> "payload-or-seg"
          n > 1 and has_payload -> "payload-or-seg"
          has_seg and not is_binary(f["seg"]) -> "seg-format"
          true -> nil
        end
    end
  end

  defp chunk_reason(f) do
    if Map.has_key?(f, "chunk") do
      chunk = f["chunk"]

      cond do
        not is_map(chunk) ->
          {:error, "chunk-format"}

        not is_integer(chunk["i"]) or not is_integer(chunk["n"]) ->
          {:error, "chunk-format"}

        chunk["n"] < 1 or chunk["n"] > Bonemesh.Chunk.max_chunks() ->
          {:error, "chunk-range"}

        chunk["i"] < 0 or chunk["i"] >= chunk["n"] ->
          {:error, "chunk-range"}

        true ->
          {:ok, chunk["n"]}
      end
    else
      {:ok, 1}
    end
  end

  defp validate_ack(f) do
    if f["type"] != "ack", do: "type", else: mid_reason(f["mid"])
  end

  # A NAK is routed back toward the origin like data (to/from/ttl) and names the
  # failing hop and a reason. The reason string is required but its value is not
  # enum-checked, so a future reason value is not a wire break (protocol.md §8).
  defp validate_nak(f) do
    cond do
      f["type"] != "nak" -> "type"
      (r = mid_reason(f["mid"])) != nil -> r
      not is_binary(f["hop"]) or f["hop"] == "" -> "missing-field"
      not is_binary(f["reason"]) or f["reason"] == "" -> "missing-field"
      not is_binary(f["to"]) -> "missing-field"
      not is_binary(f["from"]) -> "missing-field"
      not is_integer(f["ttl"]) -> "missing-field"
      f["ttl"] < 1 or f["ttl"] > 255 -> "ttl-range"
      true -> nil
    end
  end

  # A graceful session-close control — link-local, so only its type is required;
  # an optional reason string is not validated further.
  defp validate_bye(f) do
    if f["type"] != "bye", do: "type", else: nil
  end

  defp first_missing_or_base64(_f, []), do: nil

  defp first_missing_or_base64(f, [key | rest]) do
    cond do
      not Map.has_key?(f, key) -> "missing-field"
      (r = base64_reason(f[key])) != nil -> r
      true -> first_missing_or_base64(f, rest)
    end
  end

  defp base64_reason(v) when is_binary(v) do
    case Base.decode64(v) do
      {:ok, _} -> nil
      :error -> "not-base64"
    end
  end

  defp base64_reason(_), do: "not-base64"

  # A 32-character lowercase-hex message id (protocol.md §0).
  defp mid_reason(v) when is_binary(v) do
    if byte_size(v) == 32 and String.match?(v, ~r/\A[0-9a-f]{32}\z/), do: nil, else: "mid-format"
  end

  defp mid_reason(_), do: "mid-format"
end
