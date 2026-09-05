defmodule Bonemesh.FrameTest do
  use ExUnit.Case, async: true

  alias Bonemesh.Frame

  # Cases mirror the shared corpus (spec/corpus/framing.json). Byte-for-byte
  # agreement with the Java and Go classifiers over that corpus is checked by
  # interop/check-framing-elixir.sh.

  defp accept?(raw), do: match?({:ok, _}, Frame.classify(raw, Frame.transport_cap()))

  defp reject(raw), do: Frame.classify(raw, Frame.transport_cap())

  test "simple object accepts", do: assert(accept?(~s({"a":1}) <> "\n"))

  test "missing trailing newline", do: assert(reject(~s({"a":1})) == {:reject, "no-newline"})

  test "empty line", do: assert(reject("\n") == {:reject, "empty"})

  test "not json", do: assert(reject("not json\n") == {:reject, "invalid-json"})

  test "json array is not an object",
    do: assert(reject("[1,2,3]\n") == {:reject, "not-an-object"})

  test "interior newline splits frame",
    do: assert(reject(~s({"a":) <> "\n1}\n") == {:reject, "invalid-json"})

  test "invalid utf8" do
    raw = <<?{, ?", ?a, ?", ?:, ?", 0xFF, ?", ?}, ?\n>>
    assert reject(raw) == {:reject, "invalid-utf8"}
  end

  test "trailing garbage after object",
    do: assert(reject(~s({"a":1} X\n)) == {:reject, "trailing-data"})

  test "frame exactly at the cap accepts" do
    assert accept?(line_of_length(Frame.transport_cap()))
  end

  test "frame one byte over the cap is oversize" do
    assert Frame.classify(line_of_length(Frame.transport_cap() + 1), Frame.transport_cap()) ==
             {:reject, "oversize"}
  end

  defp line_of_length(n) do
    fill = n - byte_size(~s({"p":""})) - 1
    ~s({"p":") <> String.duplicate("A", fill) <> ~s("}) <> "\n"
  end
end
