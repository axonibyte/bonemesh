"""BoneMesh v3 — Python implementation.

A full routing mesh node, wire-compatible with the Java, Go, Rust, PHP, Elixir
and JavaScript implementations. See ``docs/user-guide.md`` §5 for the embedding
example and ``spec/protocol.md`` / ``spec/security.md`` for the normative wire.
"""

from bonemesh.node import Node

__all__ = ["Node"]
__version__ = "3.2.0"
