#!/bin/sh
# Prints the PUBLIC API surface of one implementation's node, one name per line.
#
# "Public" means what a consumer of the library can call. Each language says that
# differently, and each also has a way to say "reachable, but not API" -- the
# convention a port uses to keep a test seam out of its surface without making it
# unreachable from a separate test crate or module. Honouring those markers is the
# whole difficulty: a naive grep for `pub fn` reports Rust's send_with_ttl and
# rekey_epoch, which carry #[doc(hidden)] and an explicit "Not API" rationale
# citing decision #23, and would make this check cry wolf on its first run.
#
#   go      unexported = lowercase; methods on *Node plus package-level funcs
#   java    package-private is the marker; javap -public reports the rest
#   rust    #[doc(hidden)] immediately above the item
#   js      a leading underscore, by convention (a # private field is unreachable
#           from a test file, so the convention carries what the language cannot)
#   python  a leading underscore, by convention
#   php     a docblock @internal tag
#   elixir  @doc false, which Code.fetch_docs reports as :hidden; GenServer
#           callbacks are a behaviour the language requires, not API
#
# Usage: sh interop/api-surface.sh <impl>
set -eu
here=$(cd "$(dirname "$0")" && pwd)
repo=$(cd "$here/.." && pwd)
impl=${1:?usage: api-surface.sh <impl>}

case "$impl" in
  go)
    # Exported methods on *Node, plus exported package-level constructors.
    {
      grep -hoE '^func \(n \*Node\) [A-Z][A-Za-z0-9]*' "$repo"/go/node/*.go | sed 's/.*Node) //'
      grep -hoE '^func (Start|NewNode)[A-Za-z0-9]*' "$repo"/go/node/*.go | sed 's/^func //'
    } | sort -u
    ;;
  java)
    sh "$here/ensure-jar.sh" >/dev/null 2>&1 || true
    cls=$(find "$repo/java/build" -name 'Node.class' -path '*v3*' 2>/dev/null | head -1)
    [ -n "$cls" ] || { echo "api-surface: java classes not built" >&2; exit 1; }
    javap -public "$cls" | grep -E '^  public' | sed -E 's/\(.*//' | awk '{print $NF}' | sort -u
    ;;
  rust)
    # A pub fn whose immediately preceding attribute is #[doc(hidden)] is not API.
    awk '
      /^[[:space:]]*#\[doc\(hidden\)\]/ { hidden = 1; next }
      /^[[:space:]]*pub fn [a-z_0-9]+/ {
        if (hidden) { hidden = 0; next }
        match($0, /pub fn [a-z_0-9]+/); print substr($0, RSTART + 7, RLENGTH - 7); next
      }
      /^[[:space:]]*(\/\/|\/\*)/ { next }        # comments do not break the pairing
      { hidden = 0 }
    ' "$repo/rust/src/node.rs" | sort -u
    ;;
  js)
    (cd "$repo/js" && node -e '
      import("./src/node.js").then((m) => {
        const proto = Object.getOwnPropertyNames(m.Node.prototype);
        const statics = Object.getOwnPropertyNames(m.Node)
          .filter((x) => !["length", "name", "prototype"].includes(x));
        const all = [...proto, ...statics]
          .filter((x) => x !== "constructor" && !x.startsWith("_"));
        console.log([...new Set(all)].sort().join("\n"));
      });
    ')
    ;;
  python)
    (cd "$repo/python" && uv run python -c '
from bonemesh.node import Node
print("\n".join(sorted(m for m in dir(Node) if not m.startswith("_"))))
')
    ;;
  php)
    (cd "$repo/php" && php -r '
require "src/autoload.php";
$r = new ReflectionClass("Bonemesh\\Node");
$out = [];
foreach ($r->getMethods(ReflectionMethod::IS_PUBLIC) as $m) {
    if ($m->name === "__construct") { continue; }
    $doc = $m->getDocComment();
    if ($doc !== false && strpos($doc, "@internal") !== false) { continue; }
    $out[] = $m->name;
}
sort($out);
echo implode("\n", $out), "\n";
')
    ;;
  elixir)
    (cd "$repo/elixir" && mix compile >/dev/null 2>&1 || true
     elixir -e '
Code.append_path("_build/dev/lib/bonemesh/ebin")
{:module, _} = Code.ensure_loaded(Bonemesh.Node)
callbacks = [:child_spec, :code_change, :handle_call, :handle_cast, :handle_info,
             :init, :terminate]
hidden =
  case Code.fetch_docs(Bonemesh.Node) do
    {:docs_v1, _, _, _, _, _, docs} ->
      for {{:function, name, _}, _, _, :hidden, _} <- docs, do: name
    _ -> []
  end
Bonemesh.Node.__info__(:functions)
|> Enum.map(fn {f, _a} -> f end)
|> Enum.reject(&(&1 in callbacks or &1 in hidden))
|> Enum.uniq()
|> Enum.sort()
|> Enum.each(&IO.puts/1)')
    ;;
  *)
    echo "api-surface: unknown implementation $impl" >&2; exit 2 ;;
esac
