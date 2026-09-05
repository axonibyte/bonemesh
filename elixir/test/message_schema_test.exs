defmodule Bonemesh.MessageSchemaTest do
  use ExUnit.Case, async: true

  alias Bonemesh.MessageSchema, as: MS

  # A representative subset of the shared corpus (spec/corpus/messages.json); the
  # full set is checked cross-language by interop/check-messages-elixir.sh.

  @mid "0123456789abcdef0123456789abcdef"

  test "bmx1 valid" do
    assert MS.validate("bmx1", %{"t" => "bmx1", "v" => 3, "mesh" => "acme", "e" => "AAAA", "k" => "BBBB", "n" => "CCCC"}) == nil
  end

  test "bmx1 wrong version" do
    assert MS.validate("bmx1", %{"t" => "bmx1", "v" => 2, "mesh" => "acme", "e" => "AAAA", "k" => "BBBB", "n" => "CCCC"}) == "version"
  end

  test "bmx1 non-base64 ephemeral" do
    assert MS.validate("bmx1", %{"t" => "bmx1", "v" => 3, "mesh" => "acme", "e" => "not base64!", "k" => "BBBB", "n" => "CCCC"}) == "not-base64"
  end

  test "envelope valid" do
    assert MS.validate("envelope", %{"seq" => 0, "ct" => "3q2+7w=="}) == nil
  end

  test "envelope negative seq" do
    assert MS.validate("envelope", %{"seq" => -1, "ct" => "3q2+7w=="}) == "seq-range"
  end

  test "data valid" do
    assert MS.validate("data", %{"type" => "data", "mid" => @mid, "to" => "g", "from" => "a", "ttl" => 16, "payload" => %{}}) == nil
  end

  test "data ttl out of range" do
    assert MS.validate("data", %{"type" => "data", "mid" => @mid, "to" => "g", "from" => "a", "ttl" => 256, "payload" => %{}}) == "ttl-range"
  end

  test "data malformed mid" do
    assert MS.validate("data", %{"type" => "data", "mid" => "0123", "to" => "g", "from" => "a", "ttl" => 16, "payload" => %{}}) == "mid-format"
    assert MS.validate("data", %{"type" => "data", "mid" => String.upcase(@mid), "to" => "g", "from" => "a", "ttl" => 16, "payload" => %{}}) == "mid-format"
  end

  test "ack valid", do: assert(MS.validate("ack", %{"type" => "ack", "mid" => @mid}) == nil)

  test "ack wrong type",
    do: assert(MS.validate("ack", %{"type" => "data", "mid" => @mid}) == "type")
end
