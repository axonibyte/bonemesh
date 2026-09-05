defmodule Bonemesh.Frame do
  @moduledoc """
  The BoneMesh v3 frame reader/writer (protocol.md §2): one newline-terminated
  UTF-8 JSON object per frame, within a hard size cap — the enforcement point
  for defect D7. Classification verdicts match the shared corpus
  (spec/corpus/framing.json), so a node in any language agrees on which frames
  are well formed.
  """

  @handshake_cap 32768
  @transport_cap 65536

  @doc "Maximum handshake frame size in bytes (including the newline)."
  def handshake_cap, do: @handshake_cap
  @doc "Maximum transport frame size in bytes (including the newline)."
  def transport_cap, do: @transport_cap

  @doc """
  Classifies the first frame in `raw` against `cap`. Returns `{:ok, object}` or
  `{:reject, reason}`, reading only up to the first newline.
  """
  @spec classify(binary(), pos_integer()) :: {:ok, map()} | {:reject, String.t()}
  def classify(raw, cap) do
    case :binary.match(raw, "\n") do
      :nomatch ->
        {:reject, "no-newline"}

      {nl, 1} ->
        cond do
          nl + 1 > cap -> {:reject, "oversize"}
          nl == 0 -> {:reject, "empty"}
          true -> classify_content(binary_part(raw, 0, nl))
        end
    end
  end

  @doc "Encodes an object as a frame body followed by a single newline."
  @spec encode(map()) :: binary()
  def encode(object), do: JSON.encode!(object) <> "\n"

  defp classify_content(content) do
    cond do
      not String.valid?(content) ->
        {:reject, "invalid-utf8"}

      binary_part(content, 0, 1) == "[" ->
        {:reject, "not-an-object"}

      binary_part(content, 0, 1) != "{" ->
        {:reject, "invalid-json"}

      true ->
        decode(content)
    end
  end

  defp decode(content) do
    case JSON.decode(content) do
      {:ok, map} when is_map(map) ->
        {:ok, map}

      {:ok, _other} ->
        {:reject, "not-an-object"}

      {:error, {:invalid_byte, pos, _byte}} ->
        # An invalid byte after a complete object is trailing data; otherwise the
        # object itself is malformed.
        case JSON.decode(binary_part(content, 0, pos)) do
          {:ok, map} when is_map(map) -> {:reject, "trailing-data"}
          _ -> {:reject, "invalid-json"}
        end

      {:error, _} ->
        {:reject, "invalid-json"}
    end
  end
end
