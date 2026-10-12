"""Unit tests for the SCCP v1 TON toolchain, vector and StateInit tooling.

Covers `scripts/ton_sccp_builder.py` (Acton pinning and resolution,
Keccak-256, TON cells and the BoC parser and serializer, §3.7 committee roots
and key chunks, §5.3.1 canonical minter data, the renderers of the two
generated Tolk vector files, the gas report and its 1.1 x comparison, the v1
contract source set and its SECURITY.md) and
`scripts/generate_ton_sccp_stateinit_golden.py` (fixture consistency from
code hashes and depths alone, the bag of cells of the initial data,
script-output parsing and cross-checking).
None of these tests needs Acton or network access.
"""

from __future__ import annotations

import hashlib
import io
import json
import os
import stat
import subprocess
import sys
import tarfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
SCRIPTS = ROOT / "scripts"
sys.path.insert(0, str(SCRIPTS))

import generate_ton_sccp_stateinit_golden as golden  # noqa: E402
import ton_sccp_builder as builder  # noqa: E402


class OpaqueCell:
    """A child cell known only by its representation hash and depth."""

    def __init__(self, hash_hex: str, depth: int) -> None:
        self.hash = bytes.fromhex(hash_hex)
        self.depth = depth


# ---------------------------------------------------------------------------
# Toolchain pinning.


def test_acton_pins_cover_native_hosts_and_are_sha256() -> None:
    assert builder.ACTON_VERSION == "1.2.0"
    assert builder.TOLK_VERSION == "1.4.2"
    assert builder.ACTON_REPORTED_VERSION.startswith("acton 1.2.0 ")
    assert builder.ACTON_RELEASE_URL.startswith("https://github.com/ton-blockchain/acton/releases/download/v1.2.0/")
    for host in (("Darwin", "arm64"), ("Darwin", "x86_64"), ("Linux", "aarch64"), ("Linux", "x86_64")):
        name, digest = builder.ACTON_ARCHIVES[host]
        assert name.startswith("acton-") and name.endswith(".tar.gz")
        assert len(digest) == 64 and int(digest, 16) >= 0
    assert builder.ACTON_ARCHIVES[("Darwin", "arm64")][0] == "acton-aarch64-apple-darwin.tar.gz"


def test_host_archive_rejects_unknown_hosts(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(builder.platform, "system", lambda: "Plan9")
    monkeypatch.setattr(builder.platform, "machine", lambda: "mips")
    with pytest.raises(builder.TonBuilderError, match="no pinned Acton"):
        builder.host_archive()


def _tar(members: dict) -> bytes:
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz") as archive:
        for name, data in members.items():
            info = tarfile.TarInfo(name)
            info.size = len(data)
            archive.addfile(info, io.BytesIO(data))
    return buffer.getvalue()


def test_extract_acton_takes_only_the_single_executable(tmp_path: Path) -> None:
    destination = tmp_path / "bin" / "acton"
    builder.extract_acton(_tar({"./acton": b"#!/bin/sh\necho hi\n"}), destination)
    assert destination.read_bytes() == b"#!/bin/sh\necho hi\n"
    assert destination.stat().st_mode & stat.S_IXUSR
    with pytest.raises(builder.TonBuilderError, match="unexpected Acton archive layout"):
        builder.extract_acton(_tar({"./acton": b"x", "./evil": b"y"}), tmp_path / "other")
    with pytest.raises(builder.TonBuilderError, match="unexpected Acton archive layout"):
        builder.extract_acton(_tar({"../acton": b"x"}), tmp_path / "third")


def _fake_acton(path: Path, version: str) -> Path:
    path.write_text(f"#!/bin/sh\necho '{version}'\n")
    path.chmod(0o755)
    return path


def test_explicit_acton_must_report_the_pinned_version(tmp_path: Path) -> None:
    good = _fake_acton(tmp_path / "good", builder.ACTON_REPORTED_VERSION)
    assert builder.resolve_acton(str(good)) == good
    bad = _fake_acton(tmp_path / "bad", "acton 1.1.0 (9cf4d1f 2026-05-22)")
    with pytest.raises(builder.TonBuilderError, match="expected"):
        builder.resolve_acton(str(bad))
    with pytest.raises(builder.TonBuilderError, match="absolute executable"):
        builder.resolve_acton("relative/acton")


def test_offline_resolution_never_downloads(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(builder, "TOOLCHAIN_DIR", tmp_path / "empty")

    def refuse(*_args, **_kwargs):  # pragma: no cover - must not be called
        raise AssertionError("network used")

    monkeypatch.setattr(builder.urllib.request, "urlopen", refuse)
    with pytest.raises(builder.TonBuilderError, match="--offline"):
        builder.resolve_acton(None, offline=True)


def test_download_verifies_the_archive_digest(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(builder, "TOOLCHAIN_DIR", tmp_path / "cache")
    archive = _tar({"./acton": b"#!/bin/sh\necho wrong\n"})

    class Response(io.BytesIO):
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

    monkeypatch.setattr(builder.urllib.request, "urlopen", lambda *_a, **_k: Response(archive))
    with pytest.raises(builder.TonBuilderError, match="SHA-256 mismatch"):
        builder.resolve_acton(None)
    # a digest-correct archive that reports the wrong version is refused too
    name, _ = builder.host_archive()
    monkeypatch.setitem(
        builder.ACTON_ARCHIVES,
        (builder.platform.system(), builder.platform.machine()),
        (name, hashlib.sha256(archive).hexdigest()),
    )
    with pytest.raises(builder.TonBuilderError, match="downloaded Acton reports"):
        builder.resolve_acton(None)


def test_tolk_stdlib_check(tmp_path: Path) -> None:
    acton_dir = tmp_path / ".acton" / "tolk-stdlib"
    acton_dir.mkdir(parents=True)
    (tmp_path / ".acton" / ".version").write_text("1.2.0")
    (acton_dir / "common.tolk").write_text("// Standard library\n// x\n// y\ntolk 1.4.2\n")
    builder.check_tolk_stdlib(tmp_path)
    (acton_dir / "common.tolk").write_text("tolk 1.4.1\n")
    with pytest.raises(builder.TonBuilderError, match="tolk 1.4.2"):
        builder.check_tolk_stdlib(tmp_path)
    (tmp_path / ".acton" / ".version").write_text("1.1.0")
    with pytest.raises(builder.TonBuilderError, match="Acton 1.2.0"):
        builder.check_tolk_stdlib(tmp_path)


def test_no_docker_or_environment_toggles() -> None:
    python_source = (SCRIPTS / "ton_sccp_builder.py").read_text(encoding="utf-8")
    golden_source = (SCRIPTS / "generate_ton_sccp_stateinit_golden.py").read_text(encoding="utf-8")
    wrapper = (SCRIPTS / "sccp_ton_contract_build.sh").read_text(encoding="utf-8")
    for source in (python_source, golden_source, wrapper):
        for forbidden in ("docker run", '"docker"'):
            assert forbidden not in source
        assert "os.environ" not in source
    assert 'exec python3 "$script_dir/ton_sccp_builder.py" "$@"' in wrapper
    assert os.stat(SCRIPTS / "ton_sccp_builder.py").st_mode & 0o111


def test_acton_project_pins_the_toolchain_and_pascal_case_contracts() -> None:
    manifest = (builder.PROJECT / "Acton.toml").read_text(encoding="utf-8")
    assert 'acton = "1.2.0"' in manifest
    for name in builder.CONTRACTS:
        assert f"[contracts.{name}]" in manifest
        assert (builder.PROJECT / "contracts" / f"{name}.tolk").is_file()
        assert (builder.PROJECT / "wrappers" / f"{name}.gen.tolk").is_file()
    assert ".toolchain/" in (builder.PROJECT / ".gitignore").read_text(encoding="utf-8")


def test_contract_sources_are_exactly_the_v1_set() -> None:
    contracts = builder.PROJECT / "contracts"
    present = sorted(path.name for path in contracts.glob("*.tolk"))
    expected = sorted(Path(path).name for path in builder.SOURCE_FILES if path.startswith("contracts/"))
    assert present == expected


def test_security_notes_describe_the_v1_design() -> None:
    text = (builder.PROJECT / "SECURITY.md").read_text(encoding="utf-8")
    # TODO: WP-TON (map step T9): SECURITY.md still describes the revision 4
    # attestation design. When it is rewritten, also require the revision 5
    # terms here (`sccp_checkpoint`, `BLS_FASTAGGREGATEVERIFY`, `sccp_latched`).
    for current in (
        "sccp_apply_control",
        "control_nonce",
        "raw_reserve",
        "MINTER_FLOOR",
        "BUCKET_FLOOR",
        "library",
        "fixtures/sccp/ton_stateinit_v1.json",
        "Acton 1.2.0",
        "Tolk 1.4.2",
    ):
        assert current in text


def test_cli_rejects_unknown_arguments() -> None:
    result = subprocess.run(
        [sys.executable, str(SCRIPTS / "ton_sccp_builder.py"), "--unknown"],
        cwd=ROOT,
        check=False,
        text=True,
        capture_output=True,
    )
    assert result.returncode == 2


# ---------------------------------------------------------------------------
# Keccak-256.


def test_keccak256_known_answers() -> None:
    assert builder.keccak256(b"").hex() == "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"
    assert builder.keccak256(b"SCCP").hex() == "d7bacbdfe367013f66397ff7242325c31126ab14c95620817c994f22f1d123ba"
    assert builder.keccak256(b"1").hex() == "c89efdaa54c0f20c7adf612882df0950f5a951637e0307cdcb4c672f298b8bc6"
    # rate boundary (135, 136, 137 bytes) agrees with pycryptodome when present
    try:
        from Crypto.Hash import keccak  # type: ignore
    except ImportError:
        keccak = None
    if keccak is not None:
        for size in (135, 136, 137, 272, 1000):
            data = bytes(range(256)) * 4
            reference = keccak.new(digest_bits=256)
            reference.update(data[:size])
            assert builder.keccak256(data[:size]) == reference.digest()


def test_retired_attestation_primitives_are_gone() -> None:
    # revision 5 verifies one BLS aggregate: no secp256k1, EIP-712 or roster code remains
    for retired in (
        "point_mul", "ecdsa_sign", "ecdsa_recover", "eth_address", "SECP_N", "eip712_domain",
        "attestation_digest", "roster_digest", "roster_threshold", "member_chunks", "control_leaf",
        "test_keys", "merkle_levels", "inbound_payload",
    ):
        assert not hasattr(builder, retired)
    source = (SCRIPTS / "ton_sccp_builder.py").read_text(encoding="utf-8")
    for word in ("secp256k1", "ECRECOVER", "EIP712", "SCCP/ROSTER"):
        assert word not in source


# ---------------------------------------------------------------------------
# TON cells and BoCs.


def test_cell_hashes_match_ton_reference_values() -> None:
    assert builder.Cell("").hash.hex() == "96a296d224f285c67bee93c30f8a309157f0daa35dc5b87e410b78630a09cfc7"
    child = builder.Builder().uint(1, 8).end()
    parent = builder.Builder().uint(0b101, 3).ref(child).end()
    assert parent.depth == 1 and child.depth == 0
    material = bytes([1, 1]) + bytes([0b10110000]) + (0).to_bytes(2, "big") + child.hash
    assert parent.hash == hashlib.sha256(material).digest()


def test_builder_serialization_rules() -> None:
    assert builder.Builder().coins(0).bits == "0000"
    assert builder.Builder().coins(256).bits == "0010" + format(256, "016b")
    assert builder.Builder().address(0, 5).bits == "100" + "0" * 8 + format(5, "0256b")
    assert builder.Builder().int(-1, 8).bits == "11111111"
    assert builder.Builder().maybe_ref(None).bits == "0"
    assert builder.Builder().raw(b"\xa5\x01").bits == "1010010100000001"
    assert builder.Builder().raw(b"").bits == ""
    with pytest.raises(builder.TonBuilderError):
        builder.Builder().uint(256, 8)
    with pytest.raises(builder.TonBuilderError):
        builder.Cell("1" * 1024)


def test_serialize_boc_is_the_canonical_form() -> None:
    leaf = builder.Builder().uint(0xABC, 12).end()
    mid = builder.Builder().uint(1, 1).ref(leaf).end()
    root = builder.Builder().uint(0x55, 8).ref(mid).ref(leaf).end()
    boc = builder.serialize_boc(root)
    # magic, flags (no index, no CRC, 1-byte cell indices), 1-byte offsets,
    # 3 cells, 1 root, 0 absent, body length, root index 0
    body = (
        bytes([2, 2, 0x55, 1, 2])  # root: 2 refs, 1 full byte; references mid and leaf
        + bytes([1, 1, 0b11000000, 2])  # mid: 1 ref, 1 bit with the completion tag
        + bytes([0, 3, 0xAB, 0xC8])  # leaf: 12 bits with the completion tag
    )
    assert boc == bytes.fromhex("b5ee9c72") + bytes([1, 1, 3, 1, 0, len(body), 0]) + body
    # one entry per distinct cell although the leaf is referenced twice
    assert boc[6] == 3
    # a single cell
    assert builder.serialize_boc(builder.Cell("")) == bytes.fromhex("b5ee9c72010101010002000000")


def test_serialize_boc_orders_parents_before_children_like_the_rust_builder() -> None:
    # the reversed post-order of a walk that visits references last to first:
    # root, a, b, shared (`iroha_sccp::v1::ton_cell::Cell::to_boc`)
    shared = builder.Builder().uint(7, 8).end()
    a = builder.Builder().uint(0xA, 8).ref(shared).end()
    b = builder.Builder().uint(0xB, 8).ref(shared).end()
    root = builder.Builder().ref(a).ref(b).end()
    boc = builder.serialize_boc(root)
    body = boc[11:]
    assert body == (
        bytes([2, 0, 1, 2])  # root → a (1), b (2)
        + bytes([1, 2, 0x0A, 3])  # a → shared (3)
        + bytes([1, 2, 0x0B, 3])  # b → shared (3)
        + bytes([0, 2, 0x07])  # shared
    )
    assert builder.parse_boc(boc).hash == root.hash


def test_serialize_boc_round_trips_and_uses_minimal_widths() -> None:
    # 300 distinct cells in a chain need 2-byte cell indices
    cell = builder.Builder().uint(0, 16).end()
    for value in range(1, 300):
        cell = builder.Builder().uint(value, 16).ref(cell).end()
    boc = builder.serialize_boc(cell)
    assert boc[4:6] == bytes([2, 2])
    parsed = builder.parse_boc(boc)
    assert parsed.hash == cell.hash and parsed.depth == 299
    assert builder.cell_tree_size(parsed) == (300, 300 * 16)
    assert builder.serialize_boc(parsed) == boc
    # a child known only by its hash and depth cannot be serialized
    opaque = builder.Builder().ref(OpaqueCell("aa" * 32, 3)).end()
    with pytest.raises(builder.TonBuilderError, match="hash and depth"):
        builder.serialize_boc(opaque)


def test_parse_boc_round_trips_a_cell_tree() -> None:
    leaf = builder.Builder().uint(0xABC, 12).end()
    mid = builder.Builder().uint(1, 1).ref(leaf).end()
    root = builder.Builder().uint(0x55, 8).ref(mid).ref(leaf).end()
    parsed = builder.parse_boc(builder.serialize_boc(root))
    assert parsed.hash == root.hash
    assert parsed.depth == 2
    assert builder.cell_tree_size(parsed) == (3, 8 + 1 + 12)
    with pytest.raises(builder.TonBuilderError, match="serialized_boc"):
        builder.parse_boc(b"\x00" * 16)


def test_serialized_code_matches_the_bag_acton_recorded() -> None:
    # the cell tree of a compiled contract survives the serializer unchanged
    build_dir = builder.PROJECT / "build"
    if not (build_dir / "SccpTairaXorWallet.json").is_file():
        pytest.skip("contracts are not built")
    code = builder.load_compiled_code("SccpTairaXorWallet")
    assert builder.parse_boc(builder.serialize_boc(code)).hash == code.hash


# ---------------------------------------------------------------------------
# Committees and canonical minter data.


def _finality() -> dict:
    return builder.load_fixture("finality_v1.json")


def _committee_keys(name: str) -> list:
    return [bytes.fromhex(key[2:]) for key in _finality()["committees"][name]["keys"]]


def test_committee_size_and_quorum() -> None:
    assert [n for n in range(0, 40) if builder.is_committee_size(n)] == list(range(4, 32, 3))
    assert [builder.committee_quorum(n) for n in (4, 7, 10, 31)] == [3, 5, 7, 21]
    for name, committee in _finality()["committees"].items():
        assert builder.committee_quorum(committee["n"]) == committee["q"], name


def test_committee_root_matches_the_fixtures_and_the_spec_example() -> None:
    finality = _finality()
    for name, committee in finality["committees"].items():
        assert builder.committee_root(_committee_keys(name)) == int(committee["root"], 16), name
    # the §3.7 example over four synthetic keys
    synthetic = finality["worked_examples"]["synthetic_committee_root"]
    keys = [bytes.fromhex(key[2:]) for key in synthetic["keys"]]
    assert builder.committee_root(keys) == int(synthetic["root"], 16)
    assert builder.committee_root(keys) == builder.keccak_int(b"SCCP/COMMITTEE/V1" + bytes([4]) + b"".join(keys))


def test_committee_root_rejects_bad_committees() -> None:
    keys = _committee_keys("n4")
    for bad in (
        keys[:3],  # n = 3
        keys + [bytes([0xFF]) * 48],  # n = 5
        [keys[1], keys[0]] + keys[2:],  # not ascending
        [keys[0], keys[0]] + keys[2:],  # duplicate
        keys[:3] + [keys[3][:47]],  # short key
        [bytes([i]) * 48 for i in range(1, 33)],  # n = 32
    ):
        with pytest.raises(builder.TonBuilderError):
            builder.committee_root(bad)


def _chunk_sizes(chunk: builder.Cell) -> list:
    sizes = []
    while True:
        sizes.append((len(chunk.bits) - 1) // 384)
        assert (len(chunk.bits) - 1) % 384 == 0
        if not chunk.refs:
            assert chunk.bits[-1] == "0"
            return sizes
        assert chunk.bits[-1] == "1" and len(chunk.refs) == 1
        chunk = chunk.refs[0]


def test_key_chunks_hold_two_keys_except_the_last() -> None:
    keys = _committee_keys("n31")
    assert _chunk_sizes(builder.key_chunks(keys)) == [2] * 15 + [1]
    assert _chunk_sizes(builder.key_chunks(keys[:4])) == [2, 2]
    assert _chunk_sizes(builder.key_chunks(keys[:7])) == [2, 2, 2, 1]
    first = builder.key_chunks(keys[:4])
    assert len(first.bits) == 769 and first.depth == 1
    assert first.data_bytes()[:96] == keys[0] + keys[1]
    assert first.refs[0].data_bytes()[:96] == keys[2] + keys[3]
    for bad in ([], [keys[0][:47]]):
        with pytest.raises(builder.TonBuilderError):
            builder.key_chunks(bad)


def test_minter_initial_data_layout() -> None:
    wallet = OpaqueCell("aa" * 32, 3)
    bucket = OpaqueCell("bb" * 32, 5)
    keys = _committee_keys("n4")
    network, instance = int("11" * 32, 16), int("77" * 32, 16)
    cells = builder.minter_initial_data(network, instance, 1, 10**18, 7, 7000, 1234, keys, wallet, bucket)
    root = cells["root"]
    # minter_data: 331 zero bits and the empty `retries` dictionary bit
    assert len(root.bits) == 332 and set(root.bits) == {"0"}
    assert root.refs == [cells["config"], cells["committee"], cells["checkpoints"]]
    config = cells["config"]
    assert config.refs == [cells["initial_pin"], wallet, bucket]
    assert config.bits[:256] == format(network, "0256b") and config.bits[256:512] == format(instance, "0256b")
    assert config.bits[512:544] == format(1, "032b")
    assert len(config.bits) == 544 + 4 + 8 * 8  # Coins of 10^18: 4-bit length and 8 bytes
    pin = cells["initial_pin"]
    committee_root = builder.committee_root(keys)
    assert len(pin.bits) == 448 and not pin.refs
    assert pin.bits == (
        format(7, "064b") + format(committee_root, "0256b") + format(7000, "064b") + format(1234, "064b")
    )
    committee = cells["committee"]
    assert len(committee.bits) == 520 and committee.refs == [cells["keys"]]
    assert committee.bits == (
        format(committee_root, "0256b") + format(1234, "064b") + format(7000, "064b")
        + format(6999, "064b") + format(7, "064b") + format(4, "08b")
    )
    assert cells["checkpoints"].bits == "00" and not cells["checkpoints"].refs
    assert cells["keys"].hash == builder.key_chunks(keys).hash
    si = builder.state_init(OpaqueCell("cc" * 32, 9), root)
    assert si.bits == "00110"
    for generation, start in ((0, 7000), (7, 0)):
        with pytest.raises(builder.TonBuilderError):
            builder.minter_initial_data(network, instance, 1, 1, generation, start, 1234, keys, wallet, bucket)
    with pytest.raises(builder.TonBuilderError):
        builder.minter_initial_data(network, instance, 1, 1, 7, 7000, 1234, keys[:3], wallet, bucket)


def test_bucket_initial_data_layout() -> None:
    data = golden.bucket_initial_data(int("cd" * 32, 16), 5)
    # addr_std (267) ‖ index:uint64 ‖ activated:Bool ‖ bits:uint512
    assert len(data.bits) == 267 + 64 + 1 + 512 and not data.refs
    assert data.bits[267:331] == format(5, "064b")
    assert data.bits[331] == "0"
    assert set(data.bits[332:]) == {"0"}
    assert golden.bucket_address(int("cd" * 32, 16), 5, OpaqueCell("bb" * 32, 5)) != golden.bucket_address(
        int("cd" * 32, 16), 6, OpaqueCell("bb" * 32, 5)
    )


def test_state_init_hash_matches_tvm_formula() -> None:
    code = OpaqueCell("01" * 32, 2)
    data = builder.Builder().uint(1, 1).end()
    si = builder.state_init(code, data)
    material = bytes([2, 1]) + bytes([0b00110100]) + (2).to_bytes(2, "big") + data.depth.to_bytes(2, "big")
    material += code.hash + data.hash
    assert si.hash == hashlib.sha256(material).digest()


# ---------------------------------------------------------------------------
# Tolk test vectors.


def test_fixture_value_renderers() -> None:
    assert builder._hex_body("0xab01") == "ab01" and builder._hex_body("0x") == ""
    for bad in ("ab", "0xabc", "0xAB", "0xzz", 7, None):
        with pytest.raises(builder.TonBuilderError):
            builder._hex_body(bad)
    assert builder._slice("0xab01") == '"ab01".hexToSlice()'
    assert builder._slice("0x") == "createEmptySlice()"
    assert builder._slice("0x" + "11" * 127).count("11") == 127
    with pytest.raises(builder.TonBuilderError, match="127 bytes"):
        builder._slice("0x" + "11" * 128)
    pieces = builder._pieces("0x" + "22" * 300)
    assert [len(piece) for piece in pieces] == [2 * 127 + 15, 2 * 127 + 15, 2 * 46 + 15]
    assert builder._pieces("0x") == []
    assert builder._word(7) == "7" and builder._word("42") == "42"
    assert builder._word("0x0000ff") == "0xff" and builder._word("0x00") == "0x0"
    for bad in (True, "0x", "1.5", "-1", None):
        with pytest.raises(builder.TonBuilderError):
            builder._word(bad)
    assert builder._bool(True) == builder._bool(1) == "true"
    assert builder._bool(False) == builder._bool(0) == "false"
    with pytest.raises(builder.TonBuilderError):
        builder._bool(2)
    assert builder._padded("0x1ff", 4) == "0x000001ff"


def test_identifier_and_literal_renderers() -> None:
    assert builder._camel("n4_lowest_q") == "N4LowestQ"
    assert builder._camel("key_flag_infinity_0xc0") == "KeyFlagInfinity0xc0"
    assert builder._upper("n4_lowest_q") == "N4_LOWEST_Q"
    assert builder._upper("BadHeader") == "BAD_HEADER"
    assert builder._upper("NothingToDo") == "NOTHING_TO_DO"
    assert builder._array("int", []) == "([] as array<int>)"
    assert builder._array("int", ["1", "2"]) == "[\n        1,\n        2,\n    ]"
    assert builder._call("f", ["1", "x"]) == "f(\n        1,\n        x,\n    )"
    assert builder._call("f", ["1"], "") == "f(\n    1,\n)"
    assert builder._keys_expr(["0xab", "0xcd"], "") == '[\n    "ab".hexToSlice(),\n    "cd".hexToSlice(),\n]'
    assert builder._path_expr([], "") == "([] as array<int>)"
    assert builder._path_expr(["0x01", "0xff"], "") == "[\n    0x1,\n    0xff,\n]"
    cert = builder._cert_expr(
        {"signature": "0xaa", "signers": 7, "qc_fixed_cell": "0xbb", "x_head": "0xcc", "x_tail": "0xdd"}, ""
    )
    assert cert == (
        'certCell(\n    "aa".hexToSlice(),\n    7,\n    "bb".hexToSlice(),\n    "cc".hexToSlice(),\n'
        '    "dd".hexToSlice(),\n)'
    )
    block = {"height": 5, "sccpRoot": "0x09", "messageCount": 1, "historyIndex": 0, "historyPath": []}
    assert builder._block_expr(block, "") == (
        "blockRefCell(\n    5,\n    0x9,\n    1,\n    0,\n    ([] as array<int>),\n)"
    )
    assert builder._array_fun("vecX", "int", ["1"], "Doc.") == (
        "/// Doc.\nfun vecX(): array<int> {\n    return [\n        1,\n    ];\n}\n\n"
    )
    assert builder._struct([("a", "1"), ("b", "true")], "") == "{\n    a: 1,\n    b: true,\n}"
    table = builder._lookup("vecRow", "int", [("first", "10"), ("second", "20")], "Rows.")
    assert table.startswith("/// Rows.\nfun vecRow(index: int): int {\n    // first\n    if (index == 0) {\n")
    assert "    if (index == 1) {\n        return 20;\n    }\n    throw VecErrors.BadIndex;\n}\n" in table
    assert "enum VecErrors {" in builder.render_test_vectors()
    head, tail = builder._split_x("0x" + "aa" * 109 + "bb" * 112)
    assert head == "0x" + "aa" * 109 and tail == "0x" + "bb" * 112


def test_exit_codes_are_the_shared_table() -> None:
    transitions = builder.load_fixture("committee_transitions_v1.json")
    codes = builder.exit_codes(transitions)
    assert codes["ok"] == 0
    assert (codes["BadSignature"], codes["Equivocated"], codes["LatchRequired"]) == (405, 433, 434)
    assert (codes["BadSnake"], codes["BadRange"], codes["NothingToRetry"]) == (421, 426, 431)
    # EVM-only errors have no TON exit code
    for evm_only in ("AlreadyConsumed", "NonCanonicalCalldata", "TooManyCertificates"):
        assert evm_only not in codes
        with pytest.raises(builder.TonBuilderError):
            builder._exit(codes, evm_only)
    assert builder._exit(codes, "BadHeader") == 406
    # the contract declares exactly these codes under the same names
    errors = (builder.PROJECT / "contracts" / "sccp-errors.tolk").read_text(encoding="utf-8")
    for name, code in codes.items():
        if name != "ok":
            assert f"{name} = {code}" in errors, name


def test_replay_deployment_time_and_init_mode() -> None:
    constants = {"max_validity_ms": 2_592_000_000, "max_init_slack_ms": 3_600_000}
    # an acceptable pin deploys at the first step
    assert builder._replay_init_seconds(1_800_000_000_000, 1_801_209_600_000, constants) == 1_800_000_000
    assert builder._replay_init_seconds(1_800_000_000_000, 1_802_595_600_000, constants) == 1_800_000_000
    # a row that starts expired deploys one second before the expiry
    assert builder._replay_init_seconds(1_801_209_601_000, 1_801_209_600_000, constants) == 1_801_209_599
    assert builder._replay_init_seconds(1_800_000_000_000, 1_800_000_000_000, constants) == 1_799_999_999
    with pytest.raises(builder.TonBuilderError, match="whole second"):
        builder._replay_init_seconds(1_800_000_000_500, 1_801_209_600_000, constants)
    with pytest.raises(builder.TonBuilderError, match="no deployment time"):
        builder._replay_init_seconds(1_800_000_000_000, 1_802_595_600_001, constants)
    finality = _finality()
    committee = finality["committees"]["n4"]
    assert builder._passes_init(committee["keys"], committee["root"])
    assert not builder._passes_init(committee["keys"], "0x" + "00" * 32)
    assert not builder._passes_init(list(reversed(committee["keys"])), committee["root"])
    assert builder._keys_of_root(finality["committees"], committee["root"]) == committee["keys"]
    with pytest.raises(builder.TonBuilderError, match="no fixture committee"):
        builder._keys_of_root(finality["committees"], "0x" + "00" * 32)


def test_committed_tolk_vectors_are_current() -> None:
    generated = builder.generated_vectors()
    assert list(generated) == [builder.VECTORS_FILE, builder.CERT_VECTORS_FILE]
    for path, rendered in generated.items():
        assert path.read_text(encoding="utf-8") == rendered, path.name
        assert rendered.endswith("\n") and not rendered.endswith("\n\n")


def test_vectors_command_detects_stale_files(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys) -> None:
    vectors = tmp_path / "sccp-test-vectors.gen.tolk"
    certs = tmp_path / "sccp-cert-vectors.gen.tolk"
    monkeypatch.setattr(builder, "ROOT", tmp_path)
    monkeypatch.setattr(builder, "generated_vectors", lambda: {vectors: "a\n", certs: "b\n"})
    with pytest.raises(builder.TonBuilderError, match="sccp-test-vectors.gen.tolk is stale"):
        builder.command_vectors(check=True)
    builder.command_vectors(check=False)
    assert vectors.read_text() == "a\n" and certs.read_text() == "b\n"
    builder.command_vectors(check=True)
    certs.write_text("edited\n")
    with pytest.raises(builder.TonBuilderError, match="sccp-cert-vectors.gen.tolk is stale"):
        builder.command_vectors(check=True)
    assert "test vectors are current" in capsys.readouterr().out


def test_test_vectors_render_the_fixture_rows() -> None:
    text = builder.render_test_vectors()
    finality = _finality()
    context = finality["verification_context"]
    word = builder._word
    assert f"const VEC_NETWORK_ID = {word(context['taira_network_id'])}\n" in text
    assert f"const VEC_MINTER_ACCOUNT_ID = 0x{'35' * 32}\n" in text
    assert "const VEC_EXIT_BAD_SIGNATURE = 405\n" in text and "const VEC_EXIT_LATCH_REQUIRED = 434\n" in text
    assert f"const VEC_KEY_COUNT = {len(finality['test_keys'])}\n" in text
    for key in finality["test_keys"]:
        assert f'"{key["pk"][2:]}".hexToSlice()' in text
        assert word(key["sk"]) in text
    for name, committee in finality["committees"].items():
        assert f"const VEC_COMMITTEE_{builder._upper(name)}_ROOT = {word(committee['root'])}\n" in text
    worked = finality["worked_examples"]
    assert f"const VEC_COMMIT_M = {word(worked['commit']['m'])}\n" in text
    assert f"const VEC_X_ROTATION_ID = {word(worked['cases']['rotation']['checkpoint_id'])}\n" in text
    assert "VEC_X_INACTIVE_ID" not in text  # the inactive form has no checkpoint id
    assert f"const VEC_VALID_HEADER_COUNT = {len(finality['headers']['valid'])}\n" in text
    assert f"const VEC_INVALID_HEADER_COUNT = {len(finality['headers']['invalid'])}\n" in text
    # only the control leaves of the TON lane, each with its two HASHEXT builders
    control = builder.load_fixture("control_v1.json")
    ton = [row for row in control["controls"] if row["target"] == "ton-mainnet"]
    assert f"const VEC_CONTROL_LEAF_COUNT = {len(ton)}\n" in text and len(ton) == 12
    for row in ton:
        assert f'b1: "{row["ton_b1"][2:]}".hexToSlice()' in text
        assert f'b2: "{row["ton_b2"][2:]}".hexToSlice()' in text
        assert f"leaf: {word(row['leaf'])}," in text
    foreign = control["controls"][0]
    assert foreign["target"] != "ton-mainnet" and word(foreign["leaf"]) not in text
    payloads = {row["label"]: row for row in builder.load_fixture("payload_v1.json")["directions"]}
    inbound, outbound = payloads["sora-taira->ton-mainnet"], payloads["ton-mainnet->sora-taira"]
    assert f"const VEC_INBOUND_MESSAGE_ID = {word(inbound['message_id'])}\n" in text
    assert f"const VEC_OUTBOUND_MESSAGE_ID = {word(outbound['message_id'])}\n" in text
    # nothing of the retired attestation design is rendered
    for retired in ("ECDSA", "ROSTER", "DOMAIN_SEPARATOR", "vecKeyAddresses"):
        assert retired not in text
    # every hex literal fits one slice
    for literal in __import__("re").findall(r'"([0-9a-f]*)"\.hexToSlice\(\)', text):
        assert len(literal) <= 254 and len(literal) % 2 == 0


def test_cert_vectors_render_certificates_and_scenarios() -> None:
    text = builder.render_cert_vectors()
    finality = _finality()
    transitions = builder.load_fixture("committee_transitions_v1.json")
    assert f"const VEC_CERTIFICATE_COUNT = {len(finality['certificates'])}\n" in text
    negatives = finality["negative_certificates"] + finality["flavor_specific_certificates"]
    assert f"const VEC_NEGATIVE_CERTIFICATE_COUNT = {len(negatives)}\n" in text
    assert "const VEC_CERT_N4_LOWEST_Q = 0\n" in text and "const VEC_NEG_PREPARE_KIND = 0\n" in text
    for row in finality["certificates"] + negatives:
        assert f'signature: "{row["ton"]["signature"][2:]}".hexToSlice()' in text, row["label"]
    # a row without a pinned TON outcome carries the placeholder, never a guess
    unpinned = sum(1 for row in negatives if row["expected"]["ton"] is None)
    assert unpinned > 0 and text.count("exit: VEC_EXIT_UNPINNED,") == unpinned
    assert text.count("exit: 405,") == sum(1 for row in negatives if row["expected"]["ton"] == "BadSignature")
    # every TON scenario and every replayable EVM scenario has its replay function
    replayed = [
        scenario["name"] for scenario in transitions["scenarios"]
        if scenario.get("flavor") == "ton" or scenario.get("ton_replayable")
    ]
    assert len(replayed) == text.count("\nfun vecScenario") and len(replayed) >= 20
    for name in replayed:
        assert f"fun vecScenario{builder._camel(name)}() {{\n" in text
    skipped = [s["name"] for s in transitions["scenarios"] if s["name"] not in replayed]
    for name in skipped:
        assert f"fun vecScenario{builder._camel(name)}()" not in text
    # outcomes are exit codes of the shared table and events are full bodies
    assert "expectOutcome(res0, 403);" in text  # BadCommittee: key change without next_keys
    for call in ("eventCertificate(", "eventCheckpointed(", "eventRotated(", "eventLatched(", "eventControlApplied("):
        assert call in text
    for literal in __import__("re").findall(r'"([0-9a-f]*)"\.hexToSlice\(\)', text):
        assert len(literal) <= 254 and len(literal) % 2 == 0


def test_scenario_renderer_refuses_rows_it_cannot_replay() -> None:
    transitions = builder.load_fixture("committee_transitions_v1.json")
    context = _finality()["verification_context"]
    codes = builder.exit_codes(transitions)
    by_name = {scenario["name"]: scenario for scenario in transitions["scenarios"]}
    # a batch of certificates has no TON message
    with pytest.raises(builder.TonBuilderError, match="batches certificates"):
        builder._scenario_function(by_name["sixteen_batched_rotations"], transitions, codes, context)
    # a scenario of another verification context is not replayed on the pinned minter
    foreign = dict(by_name["ton_rotation_next_keys"])
    foreign["deployment"] = dict(foreign["deployment"], consensus_instance="0x" + "78" * 32)
    with pytest.raises(builder.TonBuilderError, match="another verification context"):
        builder._scenario_function(foreign, transitions, codes, context)
    # an event that TON does not emit in a replayed step is refused, not dropped
    with pytest.raises(builder.TonBuilderError, match="no TON replay form"):
        builder._event_expr({"event": "SccpFinalized"}, {}, {"checkpoints": []})


# ---------------------------------------------------------------------------
# StateInit golden.


def _fixture() -> dict:
    return json.loads(golden.FIXTURE.read_text(encoding="utf-8"))


def test_fixture_is_canonical_json() -> None:
    fixture = _fixture()
    assert golden.render(fixture) == golden.FIXTURE.read_text(encoding="utf-8")
    assert fixture["schema"] == golden.SCHEMA
    assert fixture["toolchain"] == {"acton": "1.2.0", "tolk": "1.4.2"}
    assert [vector["label"] for vector in fixture["vectors"]] == ["n4", "n31"]


def test_golden_context_is_the_finality_fixture() -> None:
    context = golden.golden_context()
    finality = _finality()
    assert context["network_id"] == int(finality["verification_context"]["taira_network_id"], 16)
    assert context["consensus_instance"] == int("77" * 32, 16)
    assert sorted(context["committees"]) == sorted(spec["committee"] for spec in golden.VECTORS)
    for name, (keys, root) in context["committees"].items():
        assert keys == _committee_keys(name)
        assert root == int(finality["committees"][name]["root"], 16)


def test_fixture_reproduces_from_code_hashes_and_depths_alone() -> None:
    fixture = _fixture()
    assert fixture["spec"] == "specs/sccp.md §5.3.1 (revision 5)"
    code = {name: OpaqueCell(record["hash"], record["depth"]) for name, record in fixture["code"].items()}
    for vector, spec in zip(fixture["vectors"], golden.VECTORS):
        keys = [bytes.fromhex(key) for key in vector["keys"]]
        assert keys == _committee_keys(spec["committee"]) and vector["committee"] == spec["committee"]
        pin = vector["pin"]
        assert (pin["generation"], pin["start_height"], pin["until_ms"]) == (
            spec["generation"], spec["start_height"], spec["until_ms"]
        )
        assert f"{builder.committee_root(keys):064x}" == pin["committee_root"]
        cells = builder.minter_initial_data(
            int(vector["taira_network_id"], 16),
            int(vector["consensus_instance"], 16),
            vector["route_revision"],
            int(vector["max_supply"]),
            pin["generation"],
            pin["start_height"],
            pin["until_ms"],
            keys,
            code["wallet"],
            code["bucket"],
        )
        data = vector["initial_data"]
        assert cells["root"].hash.hex() == data["hash"]
        assert cells["root"].depth == data["depth"]
        for name in ("root", "config", "initial_pin", "committee", "checkpoints"):
            assert cells[name].hash.hex() == data[name]["hash"], name
            assert cells[name].data_hex() == data[name]["data"], name
            assert len(cells[name].bits) == data[name]["bit_len"], name
        assert data["root"]["bit_len"] == 332 and data["root"]["refs"] == ["config", "committee", "checkpoints"]
        assert data["checkpoints"]["bit_len"] == 2 and data["checkpoints"]["data"] == "00"
        state_init = builder.state_init(code["minter"], cells["root"])
        assert state_init.hash.hex() == vector["state_init_hash"] == vector["address"]["account_id"]
        account = int(vector["address"]["account_id"], 16)
        children = vector["children"]
        assert f"{golden.wallet_address(golden.WALLET_OWNER, account, code['wallet']):064x}" == children["wallet_account_id"]
        assert f"{golden.bucket_address(account, 0, code['bucket']):064x}" == children["bucket_0_account_id"]
        assert f"{golden.bucket_address(account, 1, code['bucket']):064x}" == children["bucket_1_account_id"]
        assert vector["q"] == builder.committee_quorum(vector["n"]) and vector["n"] == len(keys)
    n4, n31 = fixture["vectors"]
    assert [cell["bit_len"] for cell in n4["initial_data"]["keys"]] == [769, 769]
    assert [cell["bit_len"] for cell in n31["initial_data"]["keys"]] == [769] * 15 + [385]
    assert n31["initial_data"]["keys"][-1]["refs"] == [] and n31["initial_data"]["depth"] == 17


def test_fixture_bag_of_cells_is_the_initial_data() -> None:
    fixture = _fixture()
    for vector in fixture["vectors"]:
        data = vector["initial_data"]
        root = builder.parse_boc(bytes.fromhex(data["boc"]))
        assert root.hash.hex() == data["hash"] and root.depth == data["depth"]
        assert builder.serialize_boc(root).hex() == data["boc"]
        config, committee, checkpoints = root.refs
        assert config.hash.hex() == data["config"]["hash"]
        assert committee.hash.hex() == data["committee"]["hash"]
        assert checkpoints.hash.hex() == data["checkpoints"]["hash"]
        pin, wallet, bucket = config.refs
        assert pin.hash.hex() == data["initial_pin"]["hash"]
        # the bag carries the complete wallet and bucket code
        assert wallet.hash.hex() == fixture["code"]["wallet"]["hash"]
        assert bucket.hash.hex() == fixture["code"]["bucket"]["hash"]
        assert builder.cell_tree_size(wallet) == (fixture["code"]["wallet"]["cells"], fixture["code"]["wallet"]["bits"])
        chunk, chunks = committee.refs[0], []
        while True:
            chunks.append(chunk.hash.hex())
            if not chunk.refs:
                break
            chunk = chunk.refs[0]
        assert chunks == [cell["hash"] for cell in data["keys"]]


def test_script_output_parser_and_cross_check() -> None:
    fixture = _fixture()
    lines = []
    for name, record in fixture["code"].items():
        lines.append(f"sccp-stateinit code {name}_code_hash={record['hash']}")
        lines.append(f"sccp-stateinit code {name}_code_depth={record['depth']}")
    for vector in fixture["vectors"]:
        label = vector["label"]
        data = vector["initial_data"]
        lines += [
            f"sccp-stateinit {label} committee_root={vector['pin']['committee_root']}",
            f"sccp-stateinit {label} pin_hash={data['initial_pin']['hash']}",
            f"sccp-stateinit {label} config_hash={data['config']['hash']}",
            f"sccp-stateinit {label} committee_hash={data['committee']['hash']}",
            f"sccp-stateinit {label} keys_hash={data['keys'][0]['hash']}",
            f"sccp-stateinit {label} checkpoints_hash={data['checkpoints']['hash']}",
            f"sccp-stateinit {label} data_hash={vector['initial_data']['hash']}",
            f"sccp-stateinit {label} data_depth={vector['initial_data']['depth']}",
            f"sccp-stateinit {label} state_init_hash={vector['state_init_hash']}",
            f"sccp-stateinit {label} workchain=0",
            f"sccp-stateinit {label} account_id={vector['address']['account_id']}",
            f"sccp-stateinit {label} wallet_of_abab={vector['children']['wallet_account_id']}",
            f"sccp-stateinit {label} bucket_0={vector['children']['bucket_0_account_id']}",
            f"sccp-stateinit {label} bucket_1={vector['children']['bucket_1_account_id']}",
        ]
    output = "noise line\n" + "\n".join(lines) + "\n"
    golden.cross_check(fixture, golden.parse_script_output(output))
    tampered = output.replace(fixture["vectors"][0]["address"]["account_id"], "00" * 32, 1)
    with pytest.raises(golden.GoldenError):
        golden.cross_check(fixture, golden.parse_script_output(tampered))
    with pytest.raises(golden.GoldenError, match="duplicate"):
        golden.parse_script_output(output + lines[0] + "\n")
    with pytest.raises(golden.GoldenError, match="keys differ"):
        golden.cross_check(fixture, golden.parse_script_output("\n".join(lines[1:])))
    # a cell of the initial data that differs is caught by its own hash
    tampered = output.replace(fixture["vectors"][1]["initial_data"]["committee"]["hash"], "11" * 32, 1)
    with pytest.raises(golden.GoldenError, match="n31.committee_hash"):
        golden.cross_check(fixture, golden.parse_script_output(tampered))


def test_golden_script_reads_the_committees_from_the_generated_vectors() -> None:
    script = (builder.PROJECT / "scripts" / "stateinit-golden.tolk").read_text(encoding="utf-8")
    assert 'import "@tests/unit/sccp-test-vectors.gen"' in script
    for current in ("committeeKeys(vecCommitteeN4())", "committeeKeys(vecCommitteeN31())", "sccpCommitteeRoot("):
        assert current in script
    for retired in ("sccpRosterDigest", "sccpBuildMembers", "prevRoster", "mintingPaused"):
        assert retired not in script
    # the script and the generator pin the same two deployments
    for spec in golden.VECTORS:
        assert f'"{spec["label"]}",' in script
        assert f"{spec['generation']},\n        {spec['start_height']},\n        {spec['until_ms']}," in script


# ---------------------------------------------------------------------------
# Gas report.

GAS_OUTPUT = """
 > tests/unit/sccp-fees.test.tolk (2 tests)
  ✓ gas of a checkpoint 11ms
    └─ Test output:
       gas checkpoint n=4: 97564 (limit 250000)
       gas rotation n=4 -> n=4: 107467 (limit 250000)
       finalize required value (existing bucket): 123
  ✓ gas of a checkpoint at the largest committee 20ms
    └─ Test output:
       gas checkpoint n=31: 164189 (limit 250000)
       gas checkpoint n=4: 97580 (limit 250000)
       gas of an underfunded n=31 finalize: 5000
"""


def test_parse_gas_lines_reads_only_the_gas_format() -> None:
    rows = builder.parse_gas_lines(GAS_OUTPUT)
    assert rows == {
        # a label measured twice keeps its largest value
        "checkpoint n=4": {"gas": 97580, "limit": 250000},
        "rotation n=4 -> n=4": {"gas": 107467, "limit": 250000},
        "checkpoint n=31": {"gas": 164189, "limit": 250000},
    }
    assert builder.parse_gas_lines("no measurement\n") == {}
    with pytest.raises(builder.TonBuilderError, match="two limits"):
        builder.parse_gas_lines("gas a: 1 (limit 5)\ngas a: 1 (limit 6)\n")


def test_gas_report_round_trips_and_rejects_other_layouts(tmp_path: Path) -> None:
    rows = builder.parse_gas_lines(GAS_OUTPUT)
    text = builder.render_gas_report(rows)
    assert json.loads(text) == {"schema": "iroha.sccp.ton-gas.v1", "rows": rows}
    assert text == json.dumps(json.loads(text), indent=2, sort_keys=True) + "\n"
    path = tmp_path / "gas-baseline.json"
    path.write_text(text)
    assert builder.load_gas_report(path) == rows
    for bad in (
        "[]",
        json.dumps({"schema": "other", "rows": {}}),
        json.dumps({"schema": builder.GAS_SCHEMA, "rows": []}),
        json.dumps({"schema": builder.GAS_SCHEMA, "rows": {"a": {"gas": 1}}}),
        json.dumps({"schema": builder.GAS_SCHEMA, "rows": {"a": {"gas": "1", "limit": 2}}}),
        json.dumps({"schema": builder.GAS_SCHEMA, "rows": {"a": {"gas": -1, "limit": 2}}}),
    ):
        path.write_text(bad)
        with pytest.raises(builder.TonBuilderError):
            builder.load_gas_report(path)


def test_compare_gas_fails_above_one_point_one_times_the_baseline() -> None:
    baseline = {"a": {"gas": 1000, "limit": 5000}, "b": {"gas": 10, "limit": 50}}
    row = lambda gas: {"gas": gas, "limit": 5000}  # noqa: E731
    same = {"a": row(1000), "b": {"gas": 10, "limit": 50}}
    assert builder.compare_gas(same, baseline, complete=True) == []
    # exactly 1.1 x passes, one more gas unit fails; a cheaper step passes
    assert builder.compare_gas({"a": row(1100)}, baseline, complete=False) == []
    assert builder.compare_gas({"a": row(1)}, baseline, complete=False) == []
    assert builder.compare_gas({"a": row(1101)}, baseline, complete=False) == [
        "a: 1101 gas is above 1.1 x the baseline 1000"
    ]
    # 1.1 x of 10 is 11: integer arithmetic, no rounding in favour of the run
    assert builder.compare_gas({"b": {"gas": 11, "limit": 50}}, baseline, complete=False) == []
    assert builder.compare_gas({"b": {"gas": 12, "limit": 50}}, baseline, complete=False) != []
    # a step the baseline does not know, and a step over its own limit
    assert builder.compare_gas({"c": row(1)}, baseline, complete=False) == ["c: no baseline row"]
    assert builder.compare_gas({"a": {"gas": 900, "limit": 800}}, baseline, complete=False) == [
        "a: 900 gas exceeds the step limit 800"
    ]
    # only a complete run fails for a baseline row that was not measured
    assert builder.compare_gas({"a": row(1000)}, baseline, complete=False) == []
    assert builder.compare_gas({"a": row(1000)}, baseline, complete=True) == ["b: baseline row was not measured"]


def test_test_command_records_gas_and_applies_the_baseline(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys
) -> None:
    current, baseline = tmp_path / "gas-current.json", tmp_path / "gas-baseline.json"
    monkeypatch.setattr(builder, "GAS_CURRENT_FILE", current)
    monkeypatch.setattr(builder, "GAS_BASELINE_FILE", baseline)
    calls = []

    def fake_acton(_acton, arguments, cwd=builder.PROJECT):
        calls.append(list(arguments))
        return GAS_OUTPUT

    monkeypatch.setattr(builder, "run_acton", fake_acton)
    # A missing baseline refuses qualification while preserving the measured run.
    with pytest.raises(builder.TonBuilderError, match="gas-baseline.json is missing"):
        builder.command_test(Path("/acton"), [])
    assert calls == [["test", "tests/unit"]]
    rows = builder.load_gas_report(current)
    assert rows["checkpoint n=31"] == {"gas": 164189, "limit": 250000}
    assert "gas is within" not in capsys.readouterr().out
    # the recorded run is its own baseline
    baseline.write_text(current.read_text())
    builder.command_test(Path("/acton"), [])
    assert "gas is within 1.1 x gas-baseline.json" in capsys.readouterr().out
    # a regression above 1.1 x fails the command after the report is written
    cheaper = dict(rows, **{"checkpoint n=31": {"gas": 100000, "limit": 250000}})
    baseline.write_text(builder.render_gas_report(cheaper))
    current.unlink()
    with pytest.raises(builder.TonBuilderError, match="checkpoint n=31: 164189 gas is above 1.1 x the baseline 100000"):
        builder.command_test(Path("/acton"), [])
    assert builder.load_gas_report(current) == rows
    # a filtered run passes its extra arguments on and is not held to unmeasured rows
    extra = dict(rows, **{"void frozen": {"gas": 9000, "limit": 30000}})
    baseline.write_text(builder.render_gas_report(extra))
    builder.command_test(Path("/acton"), ["--filter", "checkpoint"])
    assert calls[-1] == ["test", "tests/unit", "--filter", "checkpoint"]
    with pytest.raises(builder.TonBuilderError, match="void frozen: baseline row was not measured"):
        builder.command_test(Path("/acton"), [])


def test_gas_files_are_project_files_and_the_current_one_is_ignored() -> None:
    assert builder.GAS_CURRENT_FILE == builder.PROJECT / "gas-current.json"
    assert builder.GAS_BASELINE_FILE == builder.PROJECT / "gas-baseline.json"
    ignored = (builder.PROJECT / ".gitignore").read_text(encoding="utf-8").split()
    assert "gas-current.json" in ignored and "gas-baseline.json" not in ignored


def test_load_fixture_reads_the_committed_json() -> None:
    assert builder.load_fixture("finality_v1.json")["schema"] == "iroha.sccp.finality.v1"
    assert builder.load_fixture("control_v1.json")["schema"] == "iroha.sccp.control.v1"
    with pytest.raises(FileNotFoundError):
        builder.load_fixture("no_such_fixture.json")
