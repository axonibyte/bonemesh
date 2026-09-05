[path] = System.argv()
doc = path |> File.read!() |> JSON.decode!()
fails = :counters.new(1, [])
for c <- doc["cases"] do
  r = Bonemesh.MessageSchema.validate(c["schema"], c["frame"])
  ok = case c["expect"] do
    "valid" -> r == nil
    "invalid" -> r == c["reason"]
  end
  if ok, do: IO.puts("PASS #{c["name"]}"), else: (IO.puts("FAIL #{c["name"]}: got #{inspect(r)} want #{c["expect"]}/#{c["reason"]}"); :counters.add(fails,1,1))
end
if :counters.get(fails,1) > 0, do: System.halt(1), else: IO.puts("all #{length(doc["cases"])} message cases match")
