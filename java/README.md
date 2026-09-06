# BoneMesh — Java

The Java implementation of BoneMesh v3: a full routing mesh node
(`com.axonibyte.bonemesh.v3.Node`), wire-compatible with the Go, Rust, JS, PHP,
and Elixir implementations. The post-quantum primitives (ML-KEM-768,
ML-DSA-65/87) and the classical set (X25519, HKDF-SHA-256, ChaCha20-Poly1305)
come from the JDK's own providers.

Requires **JDK 25**. The Gradle wrapper (`./gradlew`) is checked in, so no local
Gradle install is needed.

## Build

```sh
cd java
./gradlew --no-daemon shadowJar
```

The shadow jar bundles the node and the `InteropNode` driver entry point that
`interop/drivers/java.sh` invokes.

## Test

```sh
./gradlew --no-daemon test
```

This is what the `bonemesh-java` reaper tenant (`java/.reaper.toml`) runs.
`--no-daemon` keeps the ephemeral build hermetic.

## Interop

The neutral driver is [`../interop/drivers/java.sh`](../interop/drivers/java.sh)
(`keygen` / `listen` / `connect` / `mesh`, plus `caps` and `--acks` /
`--sessions`); it drives `InteropNode` from the shadow jar. See
[`../interop/README.md`](../interop/README.md) and
[`../docs/testing.md`](../docs/testing.md).

## Embedding

`Node.start(…)`, then `connect`, `send` / `sendMid`, and the `addDataListener` /
`addAckListener` callbacks. The worked example, alongside the other five
languages, is in [`../docs/user-guide.md`](../docs/user-guide.md) §5.
