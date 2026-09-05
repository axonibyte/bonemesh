# Cross-language interop check: reads the shared corpus (spec/corpus/canon.json)
# and confirms this Elixir canonicalizer reproduces each vector's expected bytes.
# Because the Java and Go implementations already validate the same file,
# agreement here means a certificate signed by any implementation verifies under
# the others. Invoked by interop/check-canon-elixir.sh; exits non-zero on any
# mismatch.

[path] = System.argv()
doc = path |> File.read!() |> JSON.decode!()

failures =
  Enum.reduce(doc["vectors"], 0, fn v, acc ->
    got = Bonemesh.Canon.canonicalize(v["cert"])

    if got == v["canonical"] do
      IO.puts("PASS #{v["name"]}")
      acc
    else
      IO.puts("FAIL #{v["name"]}\n  got:  #{got}\n  want: #{v["canonical"]}")
      acc + 1
    end
  end)

if failures > 0 do
  IO.puts(:stderr, "#{failures} vector(s) mismatched")
  System.halt(1)
else
  IO.puts("all #{length(doc["vectors"])} canon vectors match")
end
