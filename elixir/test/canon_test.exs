defmodule Bonemesh.CanonTest do
  use ExUnit.Case, async: true

  # Vectors mirror the shared corpus (spec/corpus/canon.json) and security.md
  # §11.1. Cross-language byte-identity with the Java and Go canonicalizers over
  # that corpus is checked separately by interop/check-canon-elixir.sh.

  defp canon(map), do: Bonemesh.Canon.canonicalize(map)

  test "basic sorted keys" do
    assert canon(%{
             "v" => 3,
             "mesh" => "acme-prod",
             "label" => "alpha",
             "idk" => "YWJj",
             "nbf" => 1_788_500_000,
             "exp" => 1_790_000_000
           }) ==
             ~s({"exp":1790000000,"idk":"YWJj","label":"alpha","mesh":"acme-prod","nbf":1788500000,"v":3})
  end

  test "sig field is stripped" do
    assert canon(%{
             "v" => 3,
             "mesh" => "m",
             "label" => "alpha",
             "idk" => "AA==",
             "nbf" => 0,
             "exp" => 1,
             "sig" => "SHOULD-BE-IGNORED"
           }) == ~s({"exp":1,"idk":"AA==","label":"alpha","mesh":"m","nbf":0,"v":3})
  end

  test "non-ascii emitted raw utf8" do
    assert canon(%{"v" => 3, "mesh" => "m", "label" => "café", "idk" => "AA==", "nbf" => 0, "exp" => 1}) ==
             ~s({"exp":1,"idk":"AA==","label":"café","mesh":"m","nbf":0,"v":3})
  end

  test "string escaping quote and backslash" do
    assert canon(%{"v" => 3, "mesh" => "m", "label" => "a\"b\\c", "idk" => "AA==", "nbf" => 0, "exp" => 1}) ==
             ~s({"exp":1,"idk":"AA==","label":"a\\"b\\\\c","mesh":"m","nbf":0,"v":3})
  end

  test "control chars use short and u forms" do
    # Label bytes: 'a', U+0001, TAB, 'b'. Expected escape bytes built explicitly.
    label = <<?a, 0x01, 0x09, ?b>>
    u0001 = <<0x5C, 0x75, 0x30, 0x30, 0x30, 0x31>>
    tab = <<0x5C, 0x74>>
    want = ~s({"exp":1,"idk":"AA==","label":"a) <> u0001 <> tab <> ~s(b","mesh":"m","nbf":0,"v":3})

    assert canon(%{"v" => 3, "mesh" => "m", "label" => label, "idk" => "AA==", "nbf" => 0, "exp" => 1}) ==
             want
  end

  test "negative integer is rejected" do
    assert_raise ArgumentError, fn ->
      canon(%{"v" => 3, "nbf" => -1})
    end
  end
end
