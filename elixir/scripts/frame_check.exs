[path] = System.argv()
doc = path |> File.read!() |> JSON.decode!()
cap = fn "handshake" -> Bonemesh.Frame.handshake_cap(); _ -> Bonemesh.Frame.transport_cap() end
fails = :counters.new(1, [])
for c <- doc["cases"] do
  raw = Base.decode64!(c["bytes_b64"])
  v = Bonemesh.Frame.classify(raw, cap.(c["kind"]))
  ok = case {c["expect"], v} do
    {"accept", {:ok, _}} -> true
    {"reject", {:reject, r}} -> r == c["reason"]
    _ -> false
  end
  if ok, do: IO.puts("PASS #{c["name"]}"), else: (IO.puts("FAIL #{c["name"]}: got #{inspect(v)} want #{c["expect"]}/#{c["reason"]}"); :counters.add(fails,1,1))
end
if :counters.get(fails,1) > 0, do: System.halt(1), else: IO.puts("all #{length(doc["cases"])} frame cases match")
