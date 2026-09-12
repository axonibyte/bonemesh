#!/usr/bin/env python3
"""Gate every installed dependency's licence against BoneMesh's own.

Deliberately NOT a PEP 723 script, unlike everything under bin/. `uv run` treats
any file carrying inline script metadata as an ISOLATED script and gives it a fresh
environment containing only its declared dependencies -- so with a `/// script`
block and `dependencies = []` this audited an empty environment and passed
trivially, in CI and in the reaper tenant both. A licence gate that inspects
nothing is worse than no gate, because it reports success.

Run it inside the project environment:

    uv run --no-project python tools/check_licenses.py   # explicit
    .venv/bin/python tools/check_licenses.py             # equivalent

and the assertion below refuses to pass if it cannot see the dependency it exists
to audit.

BoneMesh is Apache-2.0, which is one-way incompatible with GPL-2.0, so a single
copyleft dependency anywhere in the transitive set is disqualifying. Checking once
by hand and hoping is not a gate: this runs in CI and in the bonemesh-python
reaper tenant, so a future `uv lock` that drags in a copyleft transitive
dependency FAILS THE BUILD instead of shipping quietly.

Reads installed distribution metadata rather than the lock file, because the lock
records versions and not licences, and because what ships is what is installed.

    uv run tools/check_licenses.py              check this environment
    uv run tools/check_licenses.py --self-test  prove the gate can reject

Stdlib only, so the gate itself never adds a dependency to audit.
"""

from __future__ import annotations

import importlib.metadata as md
import sys

# Permissive licences compatible with redistributing under Apache-2.0. Deliberately
# an allowlist: a new licence must be considered, not silently accepted.
ALLOWED = {
    "apache-2.0", "apache 2.0", "apache software license",
    "bsd-2-clause", "bsd-3-clause", "bsd license", "bsd",
    "mit", "mit-0", "mit license", "mit no attribution",
    "isc", "isc license",
    "psf-2.0", "python software foundation license",
    "unlicense", "0bsd",
}

# Substrings that disqualify outright, checked before the allowlist so that a
# dual-licence expression naming a copyleft option is still examined by a human
# rather than matched on its permissive half.
FORBIDDEN_HINTS = ("gpl", "agpl", "lgpl", "mpl", "eupl", "cddl", "copyleft", "sspl")

# This project itself. It IS Apache-2.0, but it is installed from the local path
# and its metadata carries no licence field, so exempt it by name rather than
# weakening the rule for everything.
SELF = {"bonemesh"}


def normalize(text: str) -> str:
    return " ".join(text.lower().replace("(", " ").replace(")", " ").split())


def licences_of(dist: md.Distribution) -> list[str]:
    """Every licence string a distribution declares, newest metadata field first."""
    meta = dist.metadata
    out: list[str] = []
    expr = meta.get("License-Expression")
    if expr:
        # An SPDX expression: split on OR/AND and take each operand.
        for part in expr.replace(" AND ", " OR ").split(" OR "):
            out.append(part.strip())
    if not out:
        classifiers = [c for c in (meta.get_all("Classifier") or []) if c.startswith("License ::")]
        for c in classifiers:
            out.append(c.split("::")[-1].strip())
    if not out and meta.get("License"):
        out.append(meta["License"].strip())
    return out


def verdict(name: str, declared: list[str]) -> tuple[bool, str]:
    """(ok, detail). Any one permissive operand of a dual licence is enough."""
    if name.lower() in SELF:
        return True, "this project (Apache-2.0, installed from path)"
    if not declared:
        return False, "declares no licence at all"
    permissive = [d for d in declared if normalize(d) in ALLOWED]
    if permissive:
        return True, " OR ".join(declared)
    copyleft = [d for d in declared if any(h in normalize(d) for h in FORBIDDEN_HINTS)]
    if copyleft:
        return False, f"copyleft: {' OR '.join(declared)}"
    return False, f"unrecognized: {' OR '.join(declared)}"


# The gate exists to audit the runtime dependency; if it cannot see it, it is
# looking at the wrong environment and must not report success.
REQUIRED_PRESENT = {"cryptography"}


def check(dists, *, require_present=True) -> int:
    failures = 0
    dists = list(dists)
    names = {(d.metadata["Name"] or "").lower() for d in dists}
    if require_present:
        absent = {n for n in REQUIRED_PRESENT if n not in names}
        if absent or not dists:
            print(f"FAIL  this environment has no {', '.join(sorted(absent)) or 'packages'} in it,",
                  file=sys.stderr)
            print("      so there is nothing to audit and this is not a pass. Run the gate",
                  file=sys.stderr)
            print("      inside the project environment (uv run --no-project python ...,",
                  file=sys.stderr)
            print("      or .venv/bin/python ...), not as an isolated PEP 723 script.",
                  file=sys.stderr)
            return 1
    for dist in sorted(dists, key=lambda d: (d.metadata["Name"] or "").lower()):
        name = dist.metadata["Name"] or "<unnamed>"
        ok, detail = verdict(name, licences_of(dist))
        print(f"{'PASS' if ok else 'FAIL'}  {name:<16} {dist.version:<10} {detail}")
        failures += 0 if ok else 1
    if failures:
        print(f"\n{failures} dependency licence(s) are not compatible with Apache-2.0",
              file=sys.stderr)
        print("Do not add to ALLOWED to make this pass: replace the dependency, or",
              file=sys.stderr)
        print("raise it as a deliberate licensing decision.", file=sys.stderr)
        return 1
    print("\nevery dependency licence is compatible with Apache-2.0")
    return 0


class _Fake:
    """A stand-in distribution for the self-test."""

    def __init__(self, name, version, metadata):
        self.version = version
        self.metadata = metadata
        self._name = name


class _Meta(dict):
    def get_all(self, key):
        value = self.get(key)
        if value is None:
            return None
        return value if isinstance(value, list) else [value]


def self_test() -> int:
    """An allowlist that never rejects anything is indistinguishable from none."""
    cases = [
        ("permissive-apache", "Apache-2.0", True),
        ("permissive-dual", "Apache-2.0 OR BSD-3-Clause", True),
        ("permissive-mit0", "MIT-0", True),
        ("copyleft-gpl3", "GPL-3.0-or-later", False),
        ("copyleft-agpl", "AGPL-3.0", False),
        ("copyleft-lgpl", "LGPL-2.1", False),
        ("weak-copyleft-mpl", "MPL-2.0", False),
        ("dual-naming-gpl", "MIT OR GPL-2.0", True),
        ("unknown", "Weird Custom Licence 1.0", False),
        ("absent", None, False),
    ]
    failures = 0
    for name, expr, want_ok in cases:
        meta = _Meta({"Name": name})
        if expr is not None:
            meta["License-Expression"] = expr
        ok, detail = verdict(name, licences_of(_Fake(name, "0", meta)))
        mark = "ok" if ok == want_ok else "SELF-TEST FAIL"
        print(f"  {mark}: {name:<18} {str(expr):<28} -> {'accept' if ok else 'reject'}")
        if ok != want_ok:
            failures += 1
    # A gate that cannot reject is no gate; prove the whole run fails too. Its
    # output is captured so the self-test's own report stays readable.
    import contextlib
    import io

    bad = _Meta({"Name": "gpl-thing", "License-Expression": "GPL-3.0-only"})
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(buf):
        rc = check([_Fake("gpl-thing", "1.0", bad)], require_present=False)
    if rc == 0:
        print("SELF-TEST FAIL: a GPL dependency did not fail the whole run")
        print(buf.getvalue())
        failures += 1
    else:
        print("  ok: a GPL dependency fails the whole run (exit 1)")
    # And the guard that stops the whole gate being vacuous: an environment with
    # nothing in it must FAIL, not pass. This is the bug this self-test exists to
    # prevent recurring -- the gate shipped once with a PEP 723 block, ran in an
    # isolated env, audited zero packages and reported success.
    buf2 = io.StringIO()
    with contextlib.redirect_stdout(buf2), contextlib.redirect_stderr(buf2):
        rc_empty = check([])
    if rc_empty == 0:
        print("SELF-TEST FAIL: an empty environment passed the gate")
        failures += 1
    else:
        print("  ok: an empty environment fails (the gate cannot be vacuous)")

    if failures:
        print(f"\n{failures} self-test case(s) wrong", file=sys.stderr)
        return 1
    print("\nSELF-TEST PASS: permissive accepted, copyleft and unknown rejected,")
    print("                and an environment with nothing in it is not a pass")
    return 0


def main() -> int:
    if "--self-test" in sys.argv[1:]:
        return self_test()
    return check(list(md.distributions()))


if __name__ == "__main__":
    raise SystemExit(main())
