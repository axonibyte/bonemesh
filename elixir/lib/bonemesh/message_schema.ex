defmodule Bonemesh.MessageSchema do
  @moduledoc """
  Validates BoneMesh v3 message objects against the pinned schemas (protocol.md
  §4, security.md §4), mirroring the Java and Go validators reason-for-reason so
  all three agree on which messages are well formed (shared corpus:
  spec/corpus/messages.json).
  """

  @doc """
  Validates a message map against a named schema. Returns `nil` if valid, or a
  short reason tag. Schemas: `"bmx1"`, `"envelope"`, `"data"`, `"ack"`.
  """
  @spec validate(String.t(), map()) :: nil | String.t()
  def validate("bmx1", f), do: validate_bmx1(f)
  def validate("envelope", f), do: validate_envelope(f)
  def validate("data", f), do: validate_data(f)
  def validate("ack", f), do: validate_ack(f)
  def validate(_other, _f), do: "unknown-schema"

  defp validate_bmx1(f) do
    cond do
      f["t"] != "bmx1" -> "type"
      f["v"] != 3 -> "version"
      not is_binary(f["mesh"]) or f["mesh"] == "" -> "empty-mesh"
      true -> first_missing_or_base64(f, ["e", "k", "n"])
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
      not Map.has_key?(f, "payload") -> "missing-field"
      true -> nil
    end
  end

  defp validate_ack(f) do
    if f["type"] != "ack", do: "type", else: mid_reason(f["mid"])
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
