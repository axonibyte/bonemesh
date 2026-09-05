defmodule Bonemesh.Canon do
  @moduledoc """
  The BoneMesh restricted-JCS certificate canonicalization (security.md §11.1):
  the exact byte string the mesh root signs. Byte-for-byte identical to the Java
  reference and the Go conformance runner over the shared corpus
  (spec/corpus/canon.json) — cross-language signature verification depends on it.

  A certificate contains only JSON strings and non-negative integers, so this is
  a small subset of RFC 8785: keys sorted by UTF-16 code unit, minimal string
  escaping, integers in shortest form.
  """

  @doc """
  Canonicalizes a certificate map (string keys; string or non-negative integer
  values), after removing any `"sig"` member. Returns the canonical UTF-8 bytes.
  """
  @spec canonicalize(map()) :: binary()
  def canonicalize(cert) when is_map(cert) do
    cert
    |> Map.delete("sig")
    |> encode_object()
  end

  defp encode_object(map) do
    inner =
      map
      |> Map.keys()
      |> Enum.sort_by(&utf16/1)
      |> Enum.map_join(",", fn key ->
        encode_string(key) <> ":" <> encode_value(Map.fetch!(map, key))
      end)

    "{" <> inner <> "}"
  end

  defp encode_value(v) when is_binary(v), do: encode_string(v)

  defp encode_value(v) when is_integer(v) do
    if v < 0, do: raise(ArgumentError, "certificate integers must be non-negative: #{v}")
    Integer.to_string(v)
  end

  defp encode_value(v) when is_map(v), do: encode_object(v)

  defp encode_value(v),
    do: raise(ArgumentError, "value #{inspect(v)} is not permitted in a certificate")

  # Minimal JSON string escaping (security.md §11.1 step 4).
  defp encode_string(s) do
    escaped =
      s
      |> String.to_charlist()
      |> Enum.map_join(&escape_char/1)

    "\"" <> escaped <> "\""
  end

  defp escape_char(?"), do: "\\\""
  defp escape_char(?\\), do: "\\\\"
  defp escape_char(?\b), do: "\\b"
  defp escape_char(?\t), do: "\\t"
  defp escape_char(?\n), do: "\\n"
  defp escape_char(?\f), do: "\\f"
  defp escape_char(?\r), do: "\\r"

  defp escape_char(c) when c < 0x20 do
    "\\u" <> (c |> Integer.to_string(16) |> String.downcase() |> String.pad_leading(4, "0"))
  end

  defp escape_char(c), do: <<c::utf8>>

  # UTF-16 code-unit byte sequence, the ordering RFC 8785 mandates.
  defp utf16(s), do: :unicode.characters_to_binary(s, :utf8, {:utf16, :big})
end
