"""The BONEMESH_KEYLOG debug hook (security.md §8).

Its own module because BONEMESH_KEYLOG is read once at node start and must not
leak into the other suites.

Both ends write their directional transport keys; because the role-to-direction
mapping is correct, the two ends agree on the I2R key, the R2I key and the
transcript-hash label -- which is the proof that the emitted keys really are the
shared session keys, not just self-consistent bytes.
"""

import asyncio

from bonemesh.node import Node
from bonemesh.transport import open_ciphertext
from tests.conftest import until


def parse(path) -> dict:
    """direction -> [(transcript_hash, key_hex)] for epoch 0."""
    out: dict[str, list] = {}
    try:
        text = path.read_text()
    except OSError:
        return out
    for line in text.splitlines():
        parts = line.split()
        if len(parts) != 3 or not parts[0].endswith("_TRAFFIC_0"):
            continue
        direction = parts[0].removeprefix("BMX3_").removesuffix("_TRAFFIC_0")
        out.setdefault(direction, []).append((parts[1], parts[2]))
    return out


def test_no_keylog_is_written_unless_the_variable_is_set(run_async, spawn, issue, tmp_path):
    async def body():
        beta = await spawn(issue("beta"))
        alpha = await spawn(issue("alpha"))
        await alpha.connect("127.0.0.1", beta.port())
        assert await until(lambda: "beta" in alpha.links)
        assert alpha.tun.keylog_path == ""
        assert list(tmp_path.iterdir()) == []
    run_async(body())


def test_both_ends_emit_agreeing_directional_keys(run_async, issue, monkeypatch, tmp_path, capsys):
    async def body():
        path = tmp_path / "keys.log"
        monkeypatch.setenv("BONEMESH_KEYLOG", str(path))
        beta = await Node.start(issue("beta"), 0)
        alpha = await Node.start(issue("alpha"), 0)
        try:
            await alpha.connect("127.0.0.1", beta.port())
            # Four lines: two directions from each end.
            assert await until(
                lambda: path.exists() and len(path.read_text().splitlines()) >= 4
            ), f"expected 4 key-log lines, got {path.read_text() if path.exists() else '<no file>'}"

            by_dir = parse(path)
            assert set(by_dir) == {"I2R", "R2I"}
            for direction, entries in by_dir.items():
                assert len(entries) >= 2, f"{direction}: only one end wrote it"
                ths = {th for th, _ in entries}
                keys = {key for _, key in entries}
                # One transcript hash and one key per direction across both ends:
                # this is what a swapped role-to-direction mapping breaks.
                assert len(ths) == 1, f"{direction}: ends disagree on the transcript hash"
                assert len(keys) == 1, f"{direction}: ends disagree on the key"
            # The two directions must not share a key.
            assert by_dir["I2R"][0][1] != by_dir["R2I"][0][1]
        finally:
            alpha.kill()
            beta.kill()
    run_async(body())
    # The forward-secrecy warning is mandatory and goes to stderr.
    assert "forward secrecy is defeated" in capsys.readouterr().err


def test_the_logged_key_actually_opens_the_traffic_it_describes(run_async, issue, monkeypatch, tmp_path):
    """The second oracle: the bytes in the log decrypt a real frame.

    Agreement between the two ends proves they derived the same key; only
    decrypting with it proves that key is the one the channel uses -- which is what
    bonemesh-inspect relies on, and what interop tier 10 checks cross-language.
    """
    async def body():
        path = tmp_path / "keys.log"
        monkeypatch.setenv("BONEMESH_KEYLOG", str(path))
        beta = await Node.start(issue("beta"), 0)
        alpha = await Node.start(issue("alpha"), 0)
        try:
            await alpha.connect("127.0.0.1", beta.port())
            assert await until(
                lambda: path.exists() and len(path.read_text().splitlines()) >= 4)
            by_dir = parse(path)
            i2r_key = bytes.fromhex(by_dir["I2R"][0][1])

            # Seal a frame as the initiator would, then open it with the key the
            # log claims is the I2R key.
            link = alpha.links["beta"]
            seq = link.transport.send_seq
            carrier = link.transport.seal({"type": "data", "probe": "keylog"})
            import base64
            opened = open_ciphertext(i2r_key, seq, base64.b64decode(carrier["ct"]))
            assert opened is not None, "the logged I2R key did not open an initiator frame"
            assert b'"probe":"keylog"' in opened
        finally:
            alpha.kill()
            beta.kill()
    run_async(body())


def test_the_line_format_is_the_pinned_one(run_async, issue, monkeypatch, tmp_path):
    async def body():
        import re
        path = tmp_path / "keys.log"
        monkeypatch.setenv("BONEMESH_KEYLOG", str(path))
        beta = await Node.start(issue("beta"), 0)
        alpha = await Node.start(issue("alpha"), 0)
        try:
            await alpha.connect("127.0.0.1", beta.port())
            assert await until(
                lambda: path.exists() and len(path.read_text().splitlines()) >= 4)
            pattern = re.compile(r"^BMX3_(I2R|R2I)_TRAFFIC_\d+ [0-9a-f]{64} [0-9a-f]{64}$")
            lines = path.read_text().splitlines()
            assert lines, "no key-log lines"
            for line in lines:
                assert pattern.match(line), f"malformed key-log line: {line!r}"
        finally:
            alpha.kill()
            beta.kill()
    run_async(body())


def test_a_rekey_appends_a_higher_epoch(run_async, issue, monkeypatch, tmp_path):
    async def body():
        path = tmp_path / "keys.log"
        monkeypatch.setenv("BONEMESH_KEYLOG", str(path))
        monkeypatch.setenv("BONEMESH_REKEY_FRAMES", "4")
        beta = await Node.start(issue("beta"), 0)
        alpha = await Node.start(issue("alpha"), 0)
        try:
            await alpha.connect("127.0.0.1", beta.port())
            assert await until(lambda: "beta" in alpha.links and "alpha" in beta.links)
            for i in range(8):
                alpha.send("beta", {"n": i})
                await asyncio.sleep(0.05)
            assert await until(
                lambda: path.exists()
                and any("_TRAFFIC_1 " in ln for ln in path.read_text().splitlines()),
                timeout=15.0,
            ), f"no epoch-1 key-log lines:\n{path.read_text() if path.exists() else ''}"
        finally:
            alpha.kill()
            beta.kill()
    run_async(body())
