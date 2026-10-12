"""Exercise the first-release history and cutover guard on the real tree and on mutated copies."""

from __future__ import annotations

import base64
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import sys

import pytest


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "check_first_release_history.py"
SPEC = importlib.util.spec_from_file_location("check_first_release_history", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
GUARD = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = GUARD
SPEC.loader.exec_module(GUARD)

BLOCK_RS = "crates/model/src/block.rs"
LOADER_RS = "crates/core/src/loader.rs"
NODE_RS = "crates/core/src/node.rs"
KURA_RS = "crates/core/src/kura/retired.rs"
PROOF_RS = "crates/model/src/proof.rs"
BROKEN_RS = "crates/model/src/broken_tests.rs"
CONTRACT_MD = "specs/first_release_history_cutover.md"
PINNED_DIR = "fixtures/core/history"

BLOCK = """\
//! Block wire.
pub struct SignedBlock;
impl iroha_version::Version for SignedBlock {
    fn version(&self) -> u8 {
        1
    }
    fn supported_versions() -> std::ops::Range<u8> {
        1..2
    }
}
/// Frames a headerless block; only tests call it.
pub fn frame_headerless(bytes: &[u8]) -> Vec<u8> {
    bytes.to_vec()
}
#[cfg(test)]
mod tests {
    struct Probe(u8);
    impl iroha_version::Version for Probe {
        fn version(&self) -> u8 {
            self.0
        }
        fn supported_versions() -> std::ops::Range<u8> {
            1..10
        }
    }
    #[test]
    fn block_rejects_pre_release_layout() {
        struct PreReleaseBlock;
        let _ = super::frame_headerless(&[]);
    }
}
"""
LOADER = """\
//! State loader: an old shape is "decoded" nowhere, e.g. not by `fn decode_legacy_state`.
fn reject_legacy_state(path: &str) -> Result<(), String> {
    Err(format!("legacy state `{path}` is unsupported"))
}
/// The index image a crash-safe rewrite recorded before it started.
fn prepend_old_layout() {}
/* fn migrate_state() {} /* nested */ struct LegacyState; */
#[cfg(test)]
mod tests {
    #[test]
    fn legacy_state_is_rejected() {
        struct LegacyState;
    }
}
"""
NODE = """\
//! Startup replay.
// Restoring a snapshot is not implemented (TODO(S9)); startup replays from genesis.
#[cfg(test)]
mod tests {
    /// Cold restart.
    #[test]
    fn history_replays_from_storage() {}
    /// Replay across builds.
    #[test]
    fn pinned_history_replays() {}
    /// Explicit exporter.
    #[test]
    #[ignore = "explicit capture"]
    fn capture_pinned_history() {}
}
"""
KURA = """\
const TAIL: &str = "verified_snapshot_tail.norito";
impl Kura {
    // Refused by name, never opened.
    fn reject_retired_snapshot_tail(root: &Path) -> Result<(), Error> {
        for name in names(root) {
            if name == TAIL || name.starts_with(".verified-snapshot-tail-") {
                return Err(Error::RetiredKuraArtifact);
            }
        }
        Ok(())
    }
    fn new_inner(root: &Path) -> Result<(), Error> {
        Self::reject_retired_snapshot_tail(root)?;
        let blocks_root = root.join("blocks");
        for retired in ["v2_finality", "wsv_checkpoints"] {
            let path = blocks_root.join(retired);
            if path.exists() {
                return Err(invalid(path, "retired pre-release storage owner"));
            }
        }
        Ok(())
    }
}
"""
OPEN = "pub enum ProofKind {\n    LegacyReplay,\n    Compact,\n}\n"
BROKEN = "use crate::private::{Hidden};\n#[test]\nfn header_rejects_old_bytes() {}\n"
CONTRACT = """\
# contract

| Id | Surface | Cutover | Regenerate |
| --- | --- | --- | --- |
| `wire` | Block wire | `fresh_genesis` | the pinned history |
| `proof` | Proof relation | `fresh_genesis_when_stored`: only when stored | proof fixtures |
| `abi` | ABI hash | `contract_redeployment`, and a fresh genesis when stored | goldens |

## Snapshots and checkpoints

Restart is full replay. A future checkpoint states the suffix it
verifies. It cannot retroactively validate discarded history.

## Halted chain

Operators repair it.
"""
CHECKPOINT_SECTION = (
    "Restart is full replay. A future checkpoint states the suffix it verifies. "
    "It cannot retroactively validate discarded history."
)
NETWORK_RS = "crates/network/src/lib.rs"
NETWORK = 'const PROGRAM_ENV: &str = "TEST_BIN_NODE";\n'
GENERATOR = "#!/bin/sh\n# Regenerates fixtures/proof/vectors.json.\n"
EVIDENCE_TOOL = 'SCHEMA = "iroha.obsolete_history_evidence.v1"\n'
PROBE = "pub fn run_check_storage() {}\n"
FRAMES = (b"\x01genesis frame", b"\x01block two frame")
ABI_HASH = hashlib.sha256(b"synthetic abi surface").hexdigest()
ABI_RAW = bytes.fromhex(ABI_HASH)
OTHER_ABI_HASH = hashlib.sha256(b"another abi surface").hexdigest()
OTHER_ABI_RAW = bytes.fromhex(OTHER_ABI_HASH)
ABI_GOLDEN_RS = "crates/vm/tests/abi_golden.rs"
ABI_GOLDEN_PREFIX = 'const ABI_GOLDEN: &str = "'
ABI_GOLDEN = f'//! ABI golden.\n{ABI_GOLDEN_PREFIX}{ABI_HASH}";\n'
ABI_DOC_MD = "specs/abi.md"
ABI_DOC = f"| ABI v1 | {ABI_HASH} |\n"
ABI_MANIFEST_JSON = "demo/sample.manifest.json"
ABI_MANIFEST = json.dumps({"abi_hash": f"hash:{ABI_HASH.upper()}#0000"}) + "\n"
ABI_WRAPPED_RS = "crates/model/tests/fixtures/handle_golden.rs"
ABI_WRAPPED = (
    "pub const HANDLE: &[u8] = &hex!(\n"
    f'    "0102{ABI_HASH[:30]}"\n'
    f'    "{ABI_HASH[30:]}0304"\n'
    ");\n"
)
ABI_EXECUTOR_TO = "defaults/executor.to"
ABI_SAMPLE_TO = "demo/sample.to"
ABI_MAP_TSV = "scripts/artifacts.tsv"
ABI_MAP = (
    "# owner\tsource-or-tag\tartifact\n"
    f"contract\tdemo/sample.ko\t{ABI_SAMPLE_TO}\n"
    f"default\tv1\t{ABI_EXECUTOR_TO}\n"
)
ABI_GENERATOR_SH = "scripts/regen_abi.sh"
ABI_GENERATOR = (
    "#!/bin/sh\n# Regenerates abi_golden.rs, specs/abi.md, sample.manifest.json,\n"
    "# handle_golden.rs, defaults/executor.to and every row of artifacts.tsv,\n"
    "# the capture native_v1.tsv and the fixture artifact.json.\n"
)
ABI_CAPTURE_TSV = "fixtures/compiler/native_v1.tsv"
ABI_FIXTURE_JSON = "sdk/test/fixtures/artifact.json"


def ivm_program(abi_hash: bytes, body: bytes = b"\x00" * 8) -> bytes:
    """An IVM program image: the fixed 49-byte header ending in the ABI hash, then `body`."""
    header = b"IVM\0" + bytes([1, 1, 0, 0]) + (1_000_000).to_bytes(8, "little") + b"\x01"
    return header + abi_hash + body


def capture_row(case: str, before: bytes, after: bytes) -> str:
    """One row of a compiler capture: case, source hash, two program hashes, two programs."""
    return "\t".join(
        (
            case,
            hashlib.sha256(case.encode()).hexdigest(),
            hashlib.sha256(before).hexdigest(),
            hashlib.sha256(after).hexdigest(),
            before.hex(),
            after.hex(),
        )
    ) + "\n"


def abi_capture(abi_hash: bytes = ABI_RAW) -> str:
    """A two-row compiler capture whose four programs carry `abi_hash` in their headers.

    Each program states the hash a second time in its body, as a compiled contract does.
    """
    return capture_row(
        "first", ivm_program(abi_hash, b"CNTR" + abi_hash), ivm_program(abi_hash, b"\x01")
    ) + capture_row(
        "second", ivm_program(abi_hash, b"\x02"), ivm_program(abi_hash, b"CNTR" + abi_hash)
    )


def abi_fixture(abi_hash: bytes = ABI_RAW) -> str:
    """A fixture stating `abi_hash` three ways: base64 program, upper-case and lower-case hex."""
    return (
        json.dumps(
            {
                "artifact_base64": base64.b64encode(ivm_program(abi_hash, b"CNTR")).decode(),
                "manifest": {"abi_hash": f"hash:{abi_hash.hex().upper()}#0000"},
                "artifact_semantics": {"abi_hash_hex": abi_hash.hex()},
            },
            indent=2,
        )
        + "\n"
    )


def pinned_manifest(frames: tuple[bytes, ...] = FRAMES) -> dict:
    """The manifest of a pinned history holding `frames`."""
    history = hashlib.sha256()
    blocks = []
    for index, frame in enumerate(frames):
        history.update(frame)
        blocks.append(
            {
                "height": index + 1,
                "file": f"block-{index + 1}.wire",
                "bytes": len(frame),
                "sha256": hashlib.sha256(frame).hexdigest(),
                "block_hash": f"{index + 1:064x}",
            }
        )
    return {
        "format": "iroha.first_release_history.pinned.v1",
        "blocks": blocks,
        "history_sha256": history.hexdigest(),
    }


def inventory() -> dict:
    """A minimal inventory describing the tree written by `tree`."""
    lib = {"package": "core", "target": "lib"}
    return {
        "schema": GUARD.SCHEMA,
        "contract": CONTRACT_MD,
        "history_wire": [{"type": "SignedBlock", "path": BLOCK_RS, "version": 1, "kind": "versioned-payload"}],
        "test_only_version_impls": [{"type": "Probe", "path": BLOCK_RS}],
        "replay_tests": [
            {"path": NODE_RS, "test": "history_replays_from_storage", "covers": "", **lib},
            {"path": NODE_RS, "test": "pinned_history_replays", "covers": "", **lib},
        ],
        "obsolete_layout_rejection_tests": [
            {"path": BLOCK_RS, "test": "block_rejects_pre_release_layout", **lib},
            {
                "path": BROKEN_RS,
                "test": "header_rejects_old_bytes",
                "package": "model",
                "target": "lib",
            },
        ],
        "blocked_test_targets": [
            {
                "package": "model",
                "target": "lib",
                "owner": "outside-zk-plan:data-model",
                "reason": "the lib-test target does not compile",
                "anchors": [{"path": BROKEN_RS, "contains": "use crate::private::{Hidden};"}],
            }
        ],
        "pinned_history": {
            "manifest": f"{PINNED_DIR}/manifest.json",
            "format": "iroha.first_release_history.pinned.v1",
            "history_sha256": pinned_manifest()["history_sha256"],
            "generator": {"path": NODE_RS, "test": "capture_pinned_history"},
            "replay_test": {"path": NODE_RS, "test": "pinned_history_replays"},
        },
        "loader_paths": [BLOCK_RS, "crates/core/src/load*.rs", "crates/core/src/kura"],
        "loader_rejection_helpers": [
            {"path": LOADER_RS, "name": "reject_legacy_state", "reason": ""}
        ],
        "loader_classified_definitions": [
            {"path": LOADER_RS, "name": "prepend_old_layout", "classification": ""}
        ],
        "test_only_references": [
            {"needle": "frame_headerless", "finding": "T1-A01", "reason": ""},
            {"needle": "SignedBlock::decode_headerless", "finding": "T1-A01", "reason": ""},
        ],
        "retired_identifier_roots": ["crates", "integration_tests"],
        "retired_identifiers": [
            {"identifier": "LegacyBlockHeader", "retired": ""},
            {"identifier": "legacy_snapshot_missing_section", "retired": ""},
        ],
        "retired_impls": [
            {"trait": "DecodeHeaderless", "type": "SignedBlock", "retired": "headerless decode"}
        ],
        "retired_store_artifacts": [
            {
                "refusal": "reject_retired_snapshot_tail",
                "kind": "function",
                "path": KURA_RS,
                "called_from": [{"path": KURA_RS, "function": "new_inner"}],
                "location": "blocks_root",
                "error": "RetiredKuraArtifact",
                "constants": [
                    {"name": "TAIL", "value": "verified_snapshot_tail.norito", "path": KURA_RS}
                ],
                "literals": [".verified-snapshot-tail-"],
                "messages": [],
                "artifacts": [
                    {
                        "name": "verified_snapshot_tail.norito",
                        "plant": "verified_snapshot_tail.norito",
                        "kind": "file",
                    },
                    {
                        "name": ".verified-snapshot-tail-*",
                        "plant": ".verified-snapshot-tail-x",
                        "kind": "file",
                    },
                ],
            },
            {
                "refusal": "new_inner",
                "kind": "inline_array",
                "index": 0,
                "path": KURA_RS,
                "called_from": [],
                "location": "blocks_root",
                "error": "retired pre-release storage owner",
                "constants": [],
                "literals": ["v2_finality", "wsv_checkpoints"],
                "messages": [],
                "artifacts": [
                    {"name": "v2_finality", "plant": "v2_finality", "kind": "directory"},
                    {"name": "wsv_checkpoints", "plant": "wsv_checkpoints", "kind": "directory"},
                ],
            },
        ],
        "incompatible_change_surfaces": [
            {
                "id": "wire",
                "surface": "block wire",
                "cutover": "fresh_genesis",
                "anchors": [{"path": BLOCK_RS, "contains": "pub struct SignedBlock"}],
                "regenerate": [
                    {
                        "artifact": PINNED_DIR,
                        "generator": NODE_RS,
                        "mention": "capture_pinned_history",
                    },
                    {"artifact": "norito.md", "document": True},
                ],
            },
            {
                "id": "proof",
                "surface": "proof relation",
                "cutover": "fresh_genesis_when_stored",
                "anchors": [{"path": PROOF_RS, "contains": "pub enum ProofKind"}],
                "regenerate": [
                    {
                        "artifact": "fixtures/proof/vectors.json",
                        "generator": "scripts/regen_proof.sh",
                        "checked_by": "scripts/regen_proof.sh",
                        "mention": "fixtures/proof/vectors.json",
                    }
                ],
            },
            {
                "id": "abi",
                "surface": "ABI hash",
                "cutover": "contract_redeployment",
                "anchors": [{"path": ABI_GOLDEN_RS, "contains": "const ABI_GOLDEN"}],
                "regenerate": [
                    abi_carrier(ABI_GOLDEN_RS, "abi_golden.rs", "hex"),
                    abi_carrier(ABI_DOC_MD, "specs/abi.md", "hex"),
                    abi_carrier(ABI_MANIFEST_JSON, "sample.manifest.json", "HEX"),
                    abi_carrier(ABI_WRAPPED_RS, "handle_golden.rs", "hex_wrapped"),
                    abi_carrier(ABI_EXECUTOR_TO, "defaults/executor.to", "ivm_header"),
                    abi_carrier(ABI_MAP_TSV, "artifacts.tsv", "artifact_map"),
                    abi_carrier(ABI_CAPTURE_TSV, "native_v1.tsv", "ivm_hex_rows"),
                    abi_carrier(ABI_FIXTURE_JSON, "artifact.json", ["hex", "HEX", "ivm_base64"]),
                    {"artifact": "norito.md", "document": True},
                ],
            },
        ],
        "declared_abi_cutover": {
            "surface": "abi",
            "cutover": "contract_redeployment",
            "abi_hash": ABI_HASH,
            "golden": {"path": ABI_GOLDEN_RS, "prefix": ABI_GOLDEN_PREFIX},
            "change": "the callable schema body changed",
            "fresh_genesis": False,
            "fresh_genesis_reason": "the pinned history holds no contract",
        },
        "obsolete_history_evidence": {
            "tool": "scripts/first_release_history_evidence.py",
            "tool_test": "pytests/scripts/first_release_history_evidence_test.py",
            "manifest_schema": "iroha.obsolete_history_evidence.v1",
            "anchors": [{"path": "crates/node/src/probe.rs", "contains": "pub fn run_check_storage"}],
        },
        "future_checkpoint_rule": {
            "section": "Snapshots and checkpoints",
            "statements": [
                "A future checkpoint states the suffix it verifies.",
                "It cannot retroactively validate discarded history.",
            ],
            "section_sha256": hashlib.sha256(CHECKPOINT_SECTION.encode("utf-8")).hexdigest(),
            "anchors": [{"path": NODE_RS, "contains": "is not implemented (TODO(S9))"}],
            "owner": "outside-zk-plan:consensus",
            "summary": "no checkpoint exists",
        },
        "test_prerequisites": [],
        "open_findings": [
            {
                "id": "T1-A01",
                "owner": "A.4",
                "path": PROOF_RS,
                "anchor": "LegacyReplay,",
                "summary": "replay proof kind",
            }
        ],
    }


def abi_carrier(artifact: str, mention: str, form: str | list[str]) -> dict:
    """A regeneration target of the `abi` surface that carries the ABI hash in `form`."""
    return {
        "artifact": artifact,
        "generator": ABI_GENERATOR_SH,
        "mention": mention,
        "carries": form,
    }


def real_peer_prerequisite() -> dict:
    """The prerequisite of a package whose tests start a daemon of the tree under test."""
    return {
        "package": "it",
        "build": "cargo build -p node --bin noded",
        "environment": {"TEST_BIN_NODE": "${CARGO_TARGET_DIR:-$PWD/target}/debug/noded"},
        "reason": "the tests start the daemon",
        "anchors": [{"path": NETWORK_RS, "contains": 'const PROGRAM_ENV: &str = "TEST_BIN_NODE";'}],
    }


def write(root: Path, relative: str, contents: str | bytes) -> None:
    """Write one file of the synthetic tree."""
    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    if isinstance(contents, bytes):
        path.write_bytes(contents)
    else:
        path.write_text(contents, encoding="utf-8")


@pytest.fixture
def tree(tmp_path: Path) -> Path:
    """A synthetic checkout that satisfies `inventory`."""
    write(tmp_path, GUARD.INVENTORY, json.dumps(inventory()))
    write(tmp_path, CONTRACT_MD, CONTRACT)
    write(tmp_path, "specs/zk_delivery_graph.json", json.dumps({"tasks": [{"id": "A.4"}]}))
    write(tmp_path, BLOCK_RS, BLOCK)
    write(tmp_path, PROOF_RS, OPEN)
    write(tmp_path, BROKEN_RS, BROKEN)
    write(tmp_path, LOADER_RS, LOADER)
    write(tmp_path, NODE_RS, NODE)
    write(tmp_path, KURA_RS, KURA)
    write(tmp_path, "crates/node/src/probe.rs", PROBE)
    write(tmp_path, NETWORK_RS, NETWORK)
    write(tmp_path, "integration_tests/tests/restart.rs", "//! Restart.\n")
    write(tmp_path, f"{PINNED_DIR}/manifest.json", json.dumps(pinned_manifest()))
    for index, frame in enumerate(FRAMES):
        write(tmp_path, f"{PINNED_DIR}/block-{index + 1}.wire", frame)
    write(tmp_path, "fixtures/proof/vectors.json", "{}\n")
    write(tmp_path, "norito.md", "# Norito\n")
    write(tmp_path, "scripts/regen_proof.sh", GENERATOR)
    write(tmp_path, ABI_GOLDEN_RS, ABI_GOLDEN)
    write(tmp_path, ABI_DOC_MD, ABI_DOC)
    write(tmp_path, ABI_MANIFEST_JSON, ABI_MANIFEST)
    write(tmp_path, ABI_WRAPPED_RS, ABI_WRAPPED)
    write(tmp_path, ABI_EXECUTOR_TO, ivm_program(ABI_RAW))
    write(tmp_path, ABI_SAMPLE_TO, ivm_program(ABI_RAW, b"CNTR" + ABI_RAW))
    write(tmp_path, ABI_MAP_TSV, ABI_MAP)
    write(tmp_path, ABI_CAPTURE_TSV, abi_capture())
    write(tmp_path, ABI_FIXTURE_JSON, abi_fixture())
    write(tmp_path, ABI_GENERATOR_SH, ABI_GENERATOR)
    write(tmp_path, "scripts/first_release_history_evidence.py", EVIDENCE_TOOL)
    write(tmp_path, "pytests/scripts/first_release_history_evidence_test.py", "\n")
    return tmp_path


def edit(root: Path, relative: str, old: str, new: str) -> None:
    """Replace one exact occurrence in a synthetic source file."""
    path = root / relative
    text = path.read_text(encoding="utf-8")
    assert text.count(old) == 1, (relative, old)
    path.write_text(text.replace(old, new), encoding="utf-8")


def edit_inventory(root: Path, change) -> None:
    """Apply `change` to the synthetic inventory."""
    data = inventory()
    change(data)
    write(root, GUARD.INVENTORY, json.dumps(data))


def assert_single(errors: tuple[str, ...], *fragments: str) -> None:
    """Exactly one violation, mentioning every fragment."""
    assert len(errors) == 1, errors
    for fragment in fragments:
        assert fragment in errors[0], errors


def assert_any(errors: tuple[str, ...], *fragments: str) -> None:
    """Some violation mentions every fragment."""
    assert any(all(fragment in error for fragment in fragments) for error in errors), errors


def test_current_tree_matches_its_inventory() -> None:
    assert GUARD.check(ROOT) == ()


def test_current_inventory_lists_the_history_types_and_the_new_replay_tests() -> None:
    data, errors = GUARD.load_inventory(ROOT)
    assert errors == []
    assert {entry["type"] for entry in data["history_wire"]} == {
        "SignedBlock",
        "SignedTransaction",
        "TransactionEntrypoint",
        "SignedQuery",
    }
    assert all(entry["version"] == 1 for entry in data["history_wire"])
    tests = {entry["test"] for entry in data["replay_tests"]}
    assert "current_genesis_history_replays_from_reopened_stores_to_the_identical_state" in tests
    assert "pinned_history_of_an_earlier_build_replays_to_its_pinned_state" in tests
    assert "a_store_never_replays_under_another_genesis" in tests
    assert len(data["retired_identifiers"]) >= 10


def test_current_inventory_lists_every_kura_refusal_and_every_contract_surface() -> None:
    data, _ = GUARD.load_inventory(ROOT)
    refusals = {entry["refusal"] for entry in data["retired_store_artifacts"]}
    assert refusals == {
        "reject_retired_snapshot_tail",
        "reject_retired_commit_roster_artifacts",
        "reject_retired_merge_storage",
        "reject_retired_pipeline_artifacts",
        "reject_retired_rollback_intents",
        "new_inner",
    }
    artifacts = [
        artifact["name"]
        for entry in data["retired_store_artifacts"]
        for artifact in entry["artifacts"]
    ]
    assert len(artifacts) == len(set(artifacts)) == 28
    assert {entry["id"]: entry["cutover"] for entry in data["incompatible_change_surfaces"]} == {
        "wire": "fresh_genesis",
        "state_layout": "fresh_genesis",
        "execution_root": "fresh_genesis",
        "genesis": "fresh_genesis",
        "execution_semantics": "fresh_genesis",
        "abi": "contract_redeployment",
        "proof": "fresh_genesis_when_stored",
    }
    for entry in data["incompatible_change_surfaces"]:
        assert all("/" in target["artifact"] or target.get("document") for target in entry["regenerate"])


def test_current_inventory_declares_the_abi_cutover_and_every_carrier() -> None:
    data, errors = GUARD.load_inventory(ROOT)
    assert errors == []
    declaration = data["declared_abi_cutover"]
    assert (declaration["surface"], declaration["cutover"]) == ("abi", "contract_redeployment")
    assert declaration["fresh_genesis"] is False
    golden = (ROOT / declaration["golden"]["path"]).read_text(encoding="utf-8")
    assert f'{declaration["golden"]["prefix"]}{declaration["abi_hash"]}"' in golden
    surface = next(
        entry for entry in data["incompatible_change_surfaces"] if entry["id"] == "abi"
    )
    forms = {
        target["artifact"]: target["carries"]
        for target in surface["regenerate"]
        if "carries" in target
    }
    assert forms["crates/iroha_data_model/tests/fixtures/abi_v1_hash.rs"] == "hex"
    assert forms["scripts/ivm_artifacts.tsv"] == "artifact_map"
    assert forms["defaults/executor.to"] == "ivm_header"
    assert forms["crates/ivm_abi/tests/fixtures/axt_golden.rs"] == "hex_wrapped"
    assert {path for path, form in forms.items() if form == "HEX"} == {
        f"demo/{name}.manifest.json"
        for name in ("authority_probe", "irohaswap", "ivm_smoke", "prediction_market")
    } | {"crates/iroha/tests/fixtures/contract_code_readback/code_readback.manifest.json"}
    # A compiler capture is read row by row, both programs of every row.
    captures = {
        f"fixtures/kotodama/{name}/native_v1.tsv"
        for name in (
            "compact_emission",
            "frame_emission",
            "local_emission",
            "numeric_zero",
            "private_single_use",
        )
    }
    assert {path for path, form in forms.items() if form == "ivm_hex_rows"} == captures
    assert {path for path in forms if path.startswith("fixtures/kotodama/")} == captures
    rows = 0
    for capture in sorted(captures):
        for line in (ROOT / capture).read_text(encoding="utf-8").splitlines():
            programs = [field for field in line.split("\t") if field.startswith("49564d00")]
            assert len(programs) == 2, (capture, line[:40])
            rows += 1
    assert rows == 42
    # The JS fixture states the hash as a base64 program, in its manifest and in its semantics.
    assert forms["javascript/iroha_js/test/fixtures/current_rust_contract_artifact.json"] == [
        "hex",
        "HEX",
        "ivm_base64",
    ]
    # The generated readback manifest replaced the retired hand-maintained carrier.
    retired_readback = "crates/iroha/tests/fixtures/contract_code_readback/provenance.json"
    assert retired_readback not in forms
    assert not (ROOT / retired_readback).exists()
    # Every program of the artifact map carries the declared hash in its header.
    raw = bytes.fromhex(declaration["abi_hash"])
    rows = [
        line.split("\t")
        for line in (ROOT / "scripts/ivm_artifacts.tsv").read_text(encoding="utf-8").splitlines()
        if line and not line.startswith("#")
    ]
    assert len(rows) >= 60
    assert all(GUARD.ivm_program_abi_hash((ROOT / row[2]).read_bytes()) == raw for row in rows)


def test_current_inventory_retired_the_headerless_block_decoder() -> None:
    data, _ = GUARD.load_inventory(ROOT)
    assert not any(entry["id"] == "T1-A15" for entry in data["open_findings"])
    # The generic codec cannot infer a block because its Version trait is retired.
    assert data["test_only_references"] == []
    findings = {entry["id"]: entry for entry in data["open_findings"]}
    assert "T1-A16" not in findings
    block_wire = next(entry for entry in data["history_wire"] if entry["type"] == "SignedBlock")
    assert block_wire["kind"] == "canonical-frame"
    # Both the generic leaf and complete frame reject the retired packed array form.
    assert "T1-A17" not in findings
    assert {
        "path": "crates/norito/src/core/borrowed_field_framing_tests.rs",
        "test": "generic_byte_arrays_reject_length_n_truncation_inside_and_outside_options",
        "package": "norito",
        "target": "lib",
    } in data["obsolete_layout_rejection_tests"]
    assert any(
        entry["test"] == "framed_block_rejects_packed_confidential_digest_hash_arrays"
        and entry["path"] == "crates/iroha_data_model/src/block/tests.rs"
        for entry in data["obsolete_layout_rejection_tests"]
    )
    retired = {entry["identifier"] for entry in data["retired_identifiers"]}
    assert {
        "frame_versioned_signed_block_bytes",
        "decode_bare_versioned_signed_block_inner",
        "deframe_versioned_signed_block_bytes",
        "DeframedSignedBlockBytes",
    } <= retired
    assert {(entry["trait"], entry["type"]) for entry in data["retired_impls"]} == {
        ("DecodeVersioned", "SignedBlock"),
        ("EncodeVersioned", "SignedBlock"),
        ("Version", "SignedBlock"),
    }
    block = (ROOT / "crates/iroha_data_model/src/block/mod.rs").read_text(encoding="utf-8")
    assert "pub fn decode_framed_signed_block(" in block
    assert "DecodeVersioned for SignedBlock" not in block


def test_synthetic_tree_passes(tree: Path) -> None:
    assert GUARD.check(tree) == ()


@pytest.mark.parametrize(
    "source,valid",
    [
        ("impl Framed { pub const WIRE_VERSION: u8 = 1; }", True),
        ("impl Framed { pub const WIRE_VERSION: u8 = 2; }", False),
        ("impl Framed { pub const WIRE_VERSION: u8 = CURRENT; }", False),
        ("impl Other { pub const WIRE_VERSION: u8 = 1; }", False),
        ("// impl Framed { pub const WIRE_VERSION: u8 = 1; }", False),
        ("impl Framed { const WIRE_VERSION: u8 = 1; }", False),
        ("#[cfg(test)] impl Framed { pub const WIRE_VERSION: u8 = 1; }", False),
        ("#![cfg(test)] impl Framed { pub const WIRE_VERSION: u8 = 1; }", False),
        ("impl Framed { #[cfg(test)] pub const WIRE_VERSION: u8 = 1; }", False),
        ('#[cfg(feature = "enabled")] impl Framed { pub const WIRE_VERSION: u8 = 1; }', False),
        ('impl Framed { #[cfg_attr(test, cfg(any()))] pub const WIRE_VERSION: u8 = 1; }', False),
        ("mod foreign { struct Framed; impl Framed { pub const WIRE_VERSION: u8 = 1; } }", False),
        ("impl Framed { fn nested() { pub const WIRE_VERSION: u8 = 1; } }", False),
        ("impl Framed { pub const WIRE_VERSION: u8 = 1; } "
         "impl Framed { pub const WIRE_VERSION: u8 = 1; }", False),
    ],
)
def test_framed_wire_version_is_owned_and_pinned(tmp_path: Path, source: str, valid: bool) -> None:
    write(tmp_path, "frame.rs", source)
    entries = [{"type": "Framed", "path": "frame.rs", "version": 1, "kind": "canonical-frame"}]
    errors = GUARD.framed_wire_errors(tmp_path, entries)
    assert (errors == []) is valid
    if not valid:
        assert_single(errors, "Framed::WIRE_VERSION must be the single literal 1")
    (tmp_path / "frame.rs").unlink()
    assert_single(GUARD.framed_wire_errors(tmp_path, entries), "canonical frame source is missing")


def test_report_prints_open_findings_with_current_lines(tree: Path) -> None:
    result = subprocess.run(
        [sys.executable, str(SCRIPT), "--root", str(tree), "--report"],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    assert f"{PROOF_RS}:2: T1-A01 [A.4] replay proof kind" in result.stdout
    edit(tree, PROOF_RS, "pub enum", "/// Kinds.\npub enum")
    result = subprocess.run(
        [sys.executable, str(SCRIPT), "--root", str(tree), "--report"],
        capture_output=True,
        text=True,
        check=False,
    )
    assert f"{PROOF_RS}:3: T1-A01" in result.stdout


def test_test_commands_run_exactly_the_listed_tests_and_comment_blocked_targets(tree: Path) -> None:
    result = subprocess.run(
        [sys.executable, str(SCRIPT), "--root", str(tree), "--test-commands"],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout.splitlines() == [
        "cargo test -p core --lib -- block_rejects_pre_release_layout "
        "history_replays_from_storage pinned_history_replays",
        "# blocked: the lib-test target does not compile",
        "# cargo test -p model --lib -- header_rejects_old_bytes",
    ]
    data = inventory()
    data["replay_tests"][0].update(package="it", target="test:restart")
    assert GUARD.test_commands(data)[1] == (
        "cargo test -p it --test restart -- history_replays_from_storage"
    )


def test_test_commands_of_a_real_peer_package_build_the_daemon_and_name_it(tree: Path) -> None:
    def real_peers(data: dict) -> None:
        data["replay_tests"][0].update(package="it", target="test:restart")
        data["replay_tests"].append(
            {
                "path": NODE_RS,
                "test": "pinned_history_replays",
                "covers": "",
                "package": "it",
                "target": "test:lanes",
            }
        )
        data["test_prerequisites"] = [real_peer_prerequisite()]

    edit_inventory(tree, real_peers)
    assert GUARD.check(tree) == ()
    result = subprocess.run(
        [sys.executable, str(SCRIPT), "--root", str(tree), "--test-commands"],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    variable = 'TEST_BIN_NODE="${CARGO_TARGET_DIR:-$PWD/target}/debug/noded"'
    # The daemon is built once, before the first command that needs it, and every
    # command of the package names it: each printed line runs as printed.
    assert result.stdout.splitlines()[:5] == [
        "cargo test -p core --lib -- block_rejects_pre_release_layout pinned_history_replays",
        "cargo build -p node --bin noded",
        f"{variable} cargo test -p it --test lanes -- pinned_history_replays",
        f"{variable} cargo test -p it --test restart -- history_replays_from_storage",
        "# blocked: the lib-test target does not compile",
    ]
    # A blocked target of such a package stays a comment, prerequisite included.
    data = inventory()
    real_peers(data)
    data["blocked_test_targets"][0].update(package="it", target="test:lanes")
    lines = GUARD.test_commands(data)
    assert lines[1:4] == [
        "# blocked: the lib-test target does not compile",
        "# cargo build -p node --bin noded",
        f"# {variable} cargo test -p it --test lanes -- pinned_history_replays",
    ]


def test_current_test_commands_make_the_real_peer_lines_runnable_as_printed() -> None:
    data, errors = GUARD.load_inventory(ROOT)
    assert errors == []
    lines = GUARD.test_commands(data)
    build = lines.index("cargo build -p irohad --bin iroha3d")
    variable = 'TEST_NETWORK_BIN_IROHAD="${CARGO_TARGET_DIR:-$PWD/target}/debug/iroha3d"'
    real_peer = [line for line in lines if "-p integration_tests" in line]
    assert len(real_peer) == 2
    assert all(line.startswith(f"{variable} cargo test -p integration_tests --test ") for line in real_peer)
    assert all(lines.index(line) > build for line in real_peer)
    assert not [line for line in lines if "TEST_NETWORK_BIN_IROHAD" in line and line not in real_peer]


@pytest.mark.parametrize(
    "change,fragment",
    [
        (lambda entry: entry.update(package="absent"), "names one package with a listed test"),
        (lambda entry: entry.update(build="make daemon"), "needs `build` as `cargo build -p"),
        (lambda entry: entry.update(build="cargo build -p node --bin noded; rm -rf x"), "needs `build` as"),
        (lambda entry: entry.update(environment={}), "needs a non-empty `environment`"),
        (lambda entry: entry.update(environment={"bin": "x"}), "a shell cannot take as printed"),
        (lambda entry: entry.update(environment={"TEST_BIN_NODE": "$(id)"}), "a shell cannot take as printed"),
        (lambda entry: entry.update(reason=""), "states its `reason`"),
        (lambda entry: entry.update(anchors=[]), "has no source anchor"),
    ],
)
def test_malformed_test_prerequisite_fails(tree: Path, change, fragment: str) -> None:
    def malformed(data: dict) -> None:
        data["replay_tests"][0].update(package="it", target="test:restart")
        entry = real_peer_prerequisite()
        change(entry)
        data["test_prerequisites"] = [entry]

    edit_inventory(tree, malformed)
    errors = GUARD.check(tree)
    assert any(fragment in error for error in errors), errors


def test_test_prerequisite_goes_stale_when_the_daemon_variable_changes(tree: Path) -> None:
    def real_peers(data: dict) -> None:
        data["replay_tests"][0].update(package="it", target="test:restart")
        data["test_prerequisites"] = [real_peer_prerequisite(), real_peer_prerequisite()]

    edit_inventory(tree, real_peers)
    assert_single(GUARD.check(tree), "names one package with a listed test, once")
    edit_inventory(
        tree,
        lambda data: (
            data["replay_tests"][0].update(package="it", target="test:restart"),
            data.update(test_prerequisites=[real_peer_prerequisite()]),
        ),
    )
    assert GUARD.check(tree) == ()
    edit(tree, NETWORK_RS, "TEST_BIN_NODE", "TEST_BIN_DAEMON")
    assert_single(GUARD.check(tree), NETWORK_RS, "test prerequisite anchor", "is missing")


def test_current_inventory_pins_the_future_checkpoint_rule() -> None:
    data, errors = GUARD.load_inventory(ROOT)
    assert errors == []
    rule = data["future_checkpoint_rule"]
    assert rule["section"] == "Snapshots and checkpoints"
    assert any(
        "the suffix it verifies" in statement for statement in rule["statements"]
    )
    assert any(
        "cannot retroactively validate discarded history" in statement
        for statement in rule["statements"]
    )
    assert [anchor["path"] for anchor in rule["anchors"]] == [
        "crates/iroha_core/src/sumeragi/node.rs"
    ]
    assert all("TODO(S9)" in anchor["contains"] for anchor in rule["anchors"])
    contract = (ROOT / data["contract"]).read_text(encoding="utf-8")
    section = GUARD.contract_section(contract, rule["section"])
    assert section is not None
    assert hashlib.sha256(section.encode("utf-8")).hexdigest() == rule["section_sha256"]


@pytest.mark.parametrize(
    "old,new,fragments",
    [
        # The rule itself is removed or weakened.
        (
            " It cannot retroactively validate discarded history.",
            "",
            ("no longer states `It cannot retroactively validate discarded history.`",),
        ),
        (
            "states the suffix it\nverifies",
            "may state a suffix",
            ("no longer states `A future checkpoint states the suffix it verifies.`",),
        ),
        # Any other edit of the section is a reviewed change of the inventory too.
        (
            "Restart is full replay.",
            "Restart is full replay or a snapshot.",
            ("differs from the text", "record the new `section_sha256`"),
        ),
        # The section disappears, or a second one makes the rule ambiguous.
        ("## Snapshots and checkpoints", "## Snapshots", ("exactly one `## Snapshots and checkpoints` section",)),
        (
            "## Halted chain",
            "## Snapshots and checkpoints",
            ("exactly one `## Snapshots and checkpoints` section",),
        ),
    ],
)
def test_changing_the_future_checkpoint_rule_without_the_inventory_fails(
    tree: Path, old: str, new: str, fragments: tuple[str, ...]
) -> None:
    edit(tree, CONTRACT_MD, old, new)
    errors = GUARD.check(tree)
    assert errors, "the guard must fail when the checkpoint section changes"
    assert_any(errors, CONTRACT_MD, *fragments)


def test_reflowing_the_checkpoint_section_is_not_a_change(tree: Path) -> None:
    edit(tree, CONTRACT_MD, "states the suffix it\nverifies", "states the\nsuffix it verifies")
    assert GUARD.check(tree) == ()


def test_the_unimplemented_restore_marker_is_part_of_the_checkpoint_rule(tree: Path) -> None:
    edit(tree, NODE_RS, "is not implemented (TODO(S9))", "is implemented")
    assert_single(GUARD.check(tree), NODE_RS, "future-checkpoint anchor", "is missing")


@pytest.mark.parametrize(
    "change,fragment",
    [
        (lambda rule: rule.update(statements=[]), "names its section and statements"),
        (lambda rule: rule.update(section=""), "names its section and statements"),
        (lambda rule: rule.update(section_sha256="abc"), "records `section_sha256`"),
        (lambda rule: rule.update(anchors=[]), "has no source anchor"),
        (lambda rule: rule.update(owner=""), "states its owner and summary"),
    ],
)
def test_malformed_future_checkpoint_rule_fails(tree: Path, change, fragment: str) -> None:
    edit_inventory(tree, lambda data: change(data["future_checkpoint_rule"]))
    errors = GUARD.check(tree)
    assert any(fragment in error for error in errors), errors


def test_failure_exits_nonzero_and_names_the_site(tree: Path) -> None:
    write(tree, "crates/core/src/lib.rs", "struct LegacyBlockHeader;\n")
    result = subprocess.run(
        [sys.executable, str(SCRIPT), "--root", str(tree)],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 1
    assert "crates/core/src/lib.rs:1: retired first-release identifier" in result.stderr


@pytest.mark.parametrize(
    "relative,contents",
    [
        ("crates/core/src/lib.rs", "//! Docs.\nstruct LegacyBlockHeader {\n    height: u64,\n}\n"),
        ("crates/core/tests/decode.rs", "#[test]\nfn legacy_snapshot_missing_section_loads() {}\n"),
        ("integration_tests/tests/old.rs", "use model::LegacyBlockHeader;\n"),
        ("crates/core/src/deep/nested/mod.rs", "type Old = LegacyBlockHeaderV2;\n"),
    ],
)
def test_retired_identifier_reappearing_anywhere_fails(
    tree: Path, relative: str, contents: str
) -> None:
    write(tree, relative, contents)
    errors = GUARD.check(tree)
    assert_single(errors, relative, "retired first-release identifier", "reappeared")


def test_retired_identifier_is_not_matched_inside_a_longer_word(tree: Path) -> None:
    write(tree, "crates/core/src/lib.rs", "struct NotLegacyBlockHeader;\n")
    write(tree, "crates/core/target/debug/build.rs", "struct LegacyBlockHeader;\n")
    assert GUARD.check(tree) == ()


@pytest.mark.parametrize(
    "old,new,fragment",
    [
        ("        1..2\n", "        1..3\n", "supported_versions must be exactly 1..2"),
        ("        1..2\n", "        0..2\n", "supported_versions must be exactly 1..2"),
        ("        1\n    }", "        2\n    }", "version must be the literal 1"),
        ("        1..2\n", "        Self::RANGE\n", "supported_versions must be exactly 1..2"),
    ],
)
def test_history_type_admitting_another_version_fails(
    tree: Path, old: str, new: str, fragment: str
) -> None:
    edit(tree, BLOCK_RS, old, new)
    errors = GUARD.check(tree)
    assert any(fragment in error and f"{BLOCK_RS}:3" in error for error in errors)
    assert all("SignedBlock" in error for error in errors), errors


@pytest.mark.parametrize(
    "header,name",
    [
        ("impl Version for LaneBlock", "LaneBlock"),
        ("impl<T> Version for Wrapper<T>", "Wrapper"),
        ("impl<T: Codec<U>, U> iroha_version::Version for Nested<T, U>\nwhere\n    U: Copy,", "Nested"),
        ("impl<'a> Version for Borrowed<'a>", "Borrowed"),
    ],
)
def test_unlisted_version_implementation_fails_whatever_its_generics(
    tree: Path, header: str, name: str
) -> None:
    write(
        tree,
        "crates/model/src/lane.rs",
        f"{header} {{\n    fn version(&self) -> u8 {{ 1 }}\n"
        "    fn supported_versions() -> Range<u8> { 0..9 }\n}\n",
    )
    assert_single(GUARD.check(tree), "crates/model/src/lane.rs:1", f"{name} is not listed")


def test_vanished_version_implementation_and_other_traits(tree: Path) -> None:
    write(tree, "crates/model/src/other.rs", "impl SchemaVersion for Block {\n}\nimpl Display for Version {\n}\n")
    assert GUARD.check(tree) == ()
    edit(tree, BLOCK_RS, "Version for SignedBlock", "Display for SignedBlock")
    assert_single(GUARD.check(tree), "SignedBlock does not exist")


@pytest.mark.parametrize(
    "addition",
    [
        "fn decode_legacy_state(bytes: &[u8]) -> State { todo!() }\n",
        "pub(crate) struct StateCompatV0;\n",
        "fn migrate_state_layout() {}\n",
        "mod pre_release_layout {}\n",
        "const DEPRECATED_TAG: u8 = 0;\n",
        "fn decode_block_fallback() {}\n",
        "fn load_state_v0() {}\n",
        "fn compatibility_decoder() {}\n",
        "#[cfg(not(test))]\nfn state_shim() {}\n",
        "fn decode_old_layout() {}\n",
        "fn decode_previous_header() {}\n",
        "struct PriorFormat;\n",
        "struct OldBlockHeader;\n",
        "const OLD_LAYOUT_TAG: u8 = 0;\n",
        "const PREVIOUS_WIRE: u8 = 0;\n",
        "type WireAlias = Block;\n",
        "fn alias_layout() {}\n",
        "fn state_layout_alias() {}\n",
        "fn read_prior_version() {}\n",
    ],
)
def test_history_loader_gaining_a_compatibility_definition_fails(
    tree: Path, addition: str
) -> None:
    edit(tree, LOADER_RS, "#[cfg(test)]", addition + "#[cfg(test)]")
    assert_single(GUARD.check(tree), f"{LOADER_RS}:", "history loader defines")


@pytest.mark.parametrize(
    "addition,name",
    [
        ("pub use crate::state::State as LegacyState;\n", "LegacyState"),
        ("use crate::wire::{Header, Block as BlockCompat};\n", "BlockCompat"),
        ("use crate::wire::Header as OldHeader;\n", "OldHeader"),
        ("pub(crate) use wire::v1 as wire_alias;\n", "wire_alias"),
    ],
)
def test_history_loader_importing_under_a_compatibility_alias_fails(
    tree: Path, addition: str, name: str
) -> None:
    edit(tree, LOADER_RS, "#[cfg(test)]", addition + "#[cfg(test)]")
    assert_single(GUARD.check(tree), f"{LOADER_RS}:", f"imports an item as `{name}`")


@pytest.mark.parametrize(
    "relative,contents",
    [
        ("crates/core/src/kura/tests/shapes.rs", "struct LegacyShape;\nfn legacy_shape() {}\n"),
        ("crates/core/src/kura/geometry_tests/startup.rs", "struct PreReleaseJournal;\n"),
        ("crates/core/src/kura/store.rs", "#[cfg(test)]\nmod tests {\n    struct LegacyStore;\n}\n"),
        ("crates/core/src/kura/store.rs", "#[cfg(test)]\nconst LEGACY_FIXTURE: [u8; 2] = [0; 2];\n"),
        ("crates/core/src/kura/store.rs", "#[test]\nfn legacy_store_is_rejected() {}\n"),
        (
            "crates/core/src/kura/store.rs",
            "#![cfg(test)]\nstruct LegacyStore;\nfn legacy_fixture() {}\n",
        ),
        ("crates/core/src/kura/store.rs", 'const NOTE: &str = "fn decode_legacy_block";\n'),
        (
            "crates/core/src/kura/store.rs",
            "fn crc64_fallback() {}\nfn is_compatible_with() {}\nfn incompatible() {}\n",
        ),
        ("crates/core/src/other.rs", "fn decode_legacy_state() {}\n"),
        (
            "crates/core/src/kura/store.rs",
            "fn threshold_layout() {}\nfn hold_wire() {}\nfn fold_format() {}\n"
            "fn previous_block_hash() {}\nfn rebuild_with_previous() {}\nfn priority_version() {}\n"
            "fn bind_account_alias() {}\nstruct AccountAliasRecord;\nstruct ThresholdHeader;\n"
            "fn validate_against_previous_receipt() {}\nconst THRESHOLD_VERSION: u8 = 1;\n",
        ),
        (
            "crates/core/src/kura/store.rs",
            "use std::io::Error as IoError;\nuse crate::kura::{Config as KuraConfig, Old};\n"
            "#[cfg(test)]\nuse crate::wire::Header as LegacyHeader;\n",
        ),
    ],
)
def test_tests_literals_and_other_modules_are_not_loader_definitions(
    tree: Path, relative: str, contents: str
) -> None:
    write(tree, relative, contents)
    assert GUARD.check(tree) == ()


def test_code_after_a_test_item_is_production_again(tree: Path) -> None:
    write(
        tree,
        "crates/core/src/kura/store.rs",
        "#[cfg(test)]\nmod tests;\n#[cfg(test)]\nfn fixture(seed: [u8; 32]) -> u8 {\n    seed[0]\n}\n"
        "fn read_legacy_index() {}\n",
    )
    assert_single(GUARD.check(tree), "crates/core/src/kura/store.rs:7", "read_legacy_index")


def test_stale_rejection_helper_and_classified_definition_fail(tree: Path) -> None:
    edit(tree, LOADER_RS, "fn reject_legacy_state", "fn refuse_old_state")
    assert_single(GUARD.check(tree), "listed rejection helper `reject_legacy_state`")
    edit(tree, LOADER_RS, "fn refuse_old_state", "fn reject_legacy_state")
    edit(tree, LOADER_RS, "fn prepend_old_layout() {}\n", "")
    assert_single(GUARD.check(tree), "classified definition `prepend_old_layout` no longer exists")


@pytest.mark.parametrize(
    "old,new,fragment",
    [
        ("fn history_replays_from_storage", "fn history_replays", "no longer exists"),
        ("    /// Cold restart.\n    #[test]\n", "    /// Cold restart.\n", "no longer exists"),
        ("    /// Cold restart.\n    #[test]\n", "    #[test]\n    #[ignore]\n", "is ignored"),
        ("    /// Cold restart.\n    #[test]\n", "    #[ignore]\n    #[test]\n", "is ignored"),
        (
            "    /// Cold restart.\n    #[test]\n",
            '    #[ignore = "slow"]\n    /// Cold restart.\n    #[test]\n',
            "is ignored",
        ),
        (
            "    /// Cold restart.\n    #[test]\n",
            '    #[test]\n    #[cfg_attr(target_os = "macos", ignore)]\n',
            "is ignored",
        ),
        (
            "    /// Cold restart.\n    #[test]\n",
            "    #[cfg(any())]\n    #[test]\n",
            "is conditionally compiled",
        ),
        (
            "    /// Cold restart.\n    #[test]\n",
            '    #[test]\n    #[cfg(feature = "slow-tests")]\n',
            "is conditionally compiled",
        ),
    ],
)
def test_replay_test_removed_ignored_or_conditional_fails(
    tree: Path, old: str, new: str, fragment: str
) -> None:
    edit(tree, NODE_RS, old, new)
    assert_single(GUARD.check(tree), "replay test `history_replays_from_storage`", fragment)


@pytest.mark.parametrize(
    "attributes",
    [
        "    #[cfg(test)]\n    #[test]\n",
        "    #[tokio::test(flavor = \"multi_thread\")]\n",
        "    #[test]\n    #[allow(clippy::too_many_lines)]\n",
        "    #[test]\n    #[should_panic(expected = \"x [y]\")]\n",
    ],
)
def test_harmless_test_attributes_pass(tree: Path, attributes: str) -> None:
    edit(tree, NODE_RS, "    /// Cold restart.\n    #[test]\n", attributes)
    edit(tree, NODE_RS, "fn history_replays_from_storage", "pub(crate) async fn history_replays_from_storage")
    assert GUARD.check(tree) == ()


def test_rejection_test_removed_fails(tree: Path) -> None:
    edit(tree, BLOCK_RS, "fn block_rejects_pre_release_layout", "fn block_ok")
    assert_single(GUARD.check(tree), "obsolete-layout rejection test", "no longer exists")


def test_listed_test_without_package_and_target_fails(tree: Path) -> None:
    edit_inventory(tree, lambda data: data["replay_tests"][0].pop("target"))
    assert_single(GUARD.check(tree), "must name its `package` and its `target`")
    edit_inventory(tree, lambda data: data["replay_tests"][0].update(target="bin:node"))
    assert_single(GUARD.check(tree), "must name its `package` and its `target`")


def test_blocked_test_target_goes_stale_when_its_cause_is_fixed(tree: Path) -> None:
    edit(tree, BROKEN_RS, "use crate::private::{Hidden};\n", "")
    assert_single(GUARD.check(tree), "blocked test target model (lib) no longer matches")
    edit_inventory(tree, lambda data: data["blocked_test_targets"][0].update(package="absent"))
    assert_any(GUARD.check(tree), "blocked test target absent (lib) has no listed test")


@pytest.mark.parametrize(
    "relative,contents",
    [
        ("crates/core/src/lib.rs", "fn store(b: &[u8]) -> Vec<u8> {\n    model::frame_headerless(b)\n}\n"),
        ("crates/core/src/lib.rs", "pub use model::block::frame_headerless;\n"),
        ("crates/node/src/sync.rs", "fn read(b: &[u8]) {\n    let _ = SignedBlock :: decode_headerless(b);\n}\n"),
        (
            "crates/node/src/sync.rs",
            "fn read(b: &[u8]) {\n    let _ = model::block::SignedBlock::decode_headerless(b);\n}\n",
        ),
        (
            "crates/core/src/kura/store.rs",
            "#[cfg(test)]\nmod tests {}\nfn store(b: &[u8]) -> Vec<u8> {\n    frame_headerless(b)\n}\n",
        ),
    ],
)
def test_production_reference_to_a_test_only_helper_fails(
    tree: Path, relative: str, contents: str
) -> None:
    write(tree, relative, contents)
    assert_single(GUARD.check(tree), relative, "production source references", "T1-A01")


@pytest.mark.parametrize(
    "relative,contents",
    [
        ("crates/core/tests/frames.rs", "fn frame(b: &[u8]) -> Vec<u8> {\n    model::frame_headerless(b)\n}\n"),
        ("crates/model/benches/wire.rs", "fn bench(b: &[u8]) {\n    SignedBlock::decode_headerless(b);\n}\n"),
        ("integration_tests/tests/genesis.rs", "use model::block::frame_headerless;\n"),
        ("crates/core/src/lib.rs", "#[cfg(test)]\nmod tests {\n    use model::frame_headerless;\n}\n"),
        ("crates/core/src/lib.rs", "// frame_headerless(bytes) is test-only\nfn deframe_headerless() {}\n"),
        ("crates/core/src/lib.rs", 'const NAME: &str = "frame_headerless";\nfn frame_headerless_len() {}\n'),
    ],
)
def test_test_and_bench_references_to_a_test_only_helper_pass(
    tree: Path, relative: str, contents: str
) -> None:
    write(tree, relative, contents)
    assert GUARD.check(tree) == ()


def test_test_only_reference_needs_its_open_finding(tree: Path) -> None:
    edit_inventory(tree, lambda data: data["test_only_references"][0].update(finding="T1-A99"))
    assert_single(GUARD.check(tree), "names the unknown finding T1-A99")


def test_a_generic_call_named_with_its_type_is_a_test_only_reference(tree: Path) -> None:
    def generic(data: dict) -> None:
        data["test_only_references"].append(
            {"needle": "decode_exact::<SignedBlock>", "finding": "T1-A01", "reason": ""}
        )

    edit_inventory(tree, generic)
    relative = "crates/core/src/sync.rs"
    write(tree, relative, "fn read(b: &[u8]) {\n    let _ = codec :: decode_exact :: <SignedBlock>(b);\n}\n")
    assert_single(
        GUARD.check(tree),
        f"{relative}:2",
        "production source references `decode_exact::<SignedBlock>`",
        "T1-A01",
    )
    # The match is textual: another type is another call, and a call whose type is inferred
    # is not seen at all.
    write(
        tree,
        relative,
        "fn read(b: &[u8]) {\n    let _ = decode_exact::<SignedTransaction>(b);\n"
        "    let _: SignedBlock = decode_exact(b);\n}\n",
    )
    assert GUARD.check(tree) == ()
    write(tree, relative, "//! Sync.\n")
    write(
        tree,
        "crates/core/tests/frames.rs",
        "fn read(b: &[u8]) {\n    let _ = decode_exact::<SignedBlock>(b);\n}\n",
    )
    assert GUARD.check(tree) == ()


@pytest.mark.parametrize(
    "old,new,fragment",
    [
        (' || name.starts_with(".verified-snapshot-tail-")', "", "no longer names `.verified-snapshot-tail-`"),
        ("name == TAIL ||", 'name == TAIL || name == "new_marker" ||', "names `new_marker`, which"),
        ('"verified_snapshot_tail.norito";', '"snapshot_tail.norito";', "is no longer the constant `TAIL`"),
        ("if name == TAIL ||", "if", "no longer uses `TAIL`"),
        ("Err(Error::RetiredKuraArtifact)", "Ok(())", "no longer fails with `RetiredKuraArtifact`"),
        ("        Self::reject_retired_snapshot_tail(root)?;\n", "", "`new_inner` no longer calls"),
        (
            "        Self::reject_retired_snapshot_tail(root)?;\n",
            "        // Self::reject_retired_snapshot_tail(root)?;\n",
            "`new_inner` no longer calls",
        ),
        ("fn reject_retired_snapshot_tail", "fn check_snapshot_tail", "`reject_retired_snapshot_tail` no longer exists"),
        ('["v2_finality", "wsv_checkpoints"]', '["v2_finality"]', "refuses ['v2_finality']"),
        (
            '["v2_finality", "wsv_checkpoints"]',
            '["v2_finality", "wsv_checkpoints", "lane_artifacts"]',
            "refuses ['lane_artifacts', 'v2_finality', 'wsv_checkpoints']",
        ),
        ("blocks_root.join(retired)", "root.join(retired)", "no longer refuses under blocks_root"),
        ('"retired pre-release storage owner"', '"unexpected entry"', "no longer refuses under blocks_root"),
        ("for retired in [", "for name in [", "no longer holds retired-artifact array 0"),
    ],
)
def test_retired_store_artifact_refusal_drift_fails(
    tree: Path, old: str, new: str, fragment: str
) -> None:
    edit(tree, KURA_RS, old, new)
    assert_any(GUARD.check(tree), KURA_RS, fragment)


@pytest.mark.parametrize(
    "addition,fragment",
    [
        (
            "fn reject_retired_merge_storage() {}\n",
            "retired-artifact refusal `reject_retired_merge_storage` is not listed",
        ),
        (
            "fn ensure_no_retired_intents() {}\n",
            "retired-artifact refusal `ensure_no_retired_intents` is not listed",
        ),
        (
            'fn other(store_root: &Path) {\n    for retired in ["merge_carriers"] {\n'
            "        let _ = store_root.join(retired);\n    }\n}\n",
            "2 inline retired-artifact arrays",
        ),
    ],
)
def test_unlisted_retired_artifact_refusal_fails(tree: Path, addition: str, fragment: str) -> None:
    write(tree, KURA_RS, KURA + addition)
    assert_single(GUARD.check(tree), KURA_RS, fragment)


@pytest.mark.parametrize(
    "change,fragment",
    [
        (lambda entry: entry.update(location="lane_root"), "has an unknown location"),
        (lambda entry: entry.update(artifacts=[]), "lists no artifact"),
        (lambda entry: entry["artifacts"][0].update(plant="../outside"), "relative `plant` path"),
        (lambda entry: entry["artifacts"][0].update(kind="socket"), "relative `plant` path"),
        (lambda entry: entry.update(called_from=[]), "lists no call site"),
        (lambda entry: entry.update(kind="pattern"), "has an unknown kind"),
        (lambda entry: entry.update(path="crates/core/src/kura/gone.rs"), "refusal source is missing"),
    ],
)
def test_malformed_retired_store_artifact_entry_fails(tree: Path, change, fragment: str) -> None:
    edit_inventory(tree, lambda data: change(data["retired_store_artifacts"][0]))
    assert_any(GUARD.check(tree), fragment)


def test_pinned_history_is_bound_to_its_manifest_and_to_the_inventory(tree: Path) -> None:
    write(tree, f"{PINNED_DIR}/block-2.wire", b"\x01another block two")
    assert_single(GUARD.check(tree), f"{PINNED_DIR}/block-2.wire", "differs from the digest")
    # A coherent regeneration is still not the recorded history until the inventory says so.
    regenerated = (FRAMES[0], b"\x01another block two")
    write(tree, f"{PINNED_DIR}/manifest.json", json.dumps(pinned_manifest(regenerated)))
    assert_single(GUARD.check(tree), "is not the one", "declared cutover")
    edit_inventory(
        tree,
        lambda data: data["pinned_history"].update(
            history_sha256=pinned_manifest(regenerated)["history_sha256"]
        ),
    )
    assert GUARD.check(tree) == ()


@pytest.mark.parametrize(
    "change,fragment",
    [
        (lambda manifest: manifest.update(history_sha256="00" * 32), "`history_sha256` differs"),
        (lambda manifest: manifest.update(format="other"), "format must be"),
        (lambda manifest: manifest.update(blocks=manifest["blocks"][:1]), "at least one block"),
        (lambda manifest: manifest["blocks"][1].update(height=3), "out of order or misnamed"),
        (lambda manifest: manifest["blocks"][1].update(file="../block-2.wire"), "out of order or misnamed"),
        (lambda manifest: manifest["blocks"][1].update(file="block-9.wire"), "pinned frame is missing"),
        (lambda manifest: manifest["blocks"][0].update(bytes=1), "differs from the digest"),
        (lambda manifest: manifest.pop("blocks"), "unreadable pinned history manifest"),
    ],
)
def test_inconsistent_pinned_history_manifest_fails(tree: Path, change, fragment: str) -> None:
    manifest = pinned_manifest()
    change(manifest)
    write(tree, f"{PINNED_DIR}/manifest.json", json.dumps(manifest))
    assert_any(GUARD.check(tree), fragment)


def test_pinned_history_needs_its_generator_and_listed_replay_test(tree: Path) -> None:
    edit(tree, NODE_RS, "fn capture_pinned_history", "fn capture_nothing")
    assert_any(GUARD.check(tree), "pinned history generator `capture_pinned_history` is gone")
    edit(tree, NODE_RS, "fn capture_nothing", "fn capture_pinned_history")
    edit_inventory(tree, lambda data: data["replay_tests"].pop(1))
    assert_single(GUARD.check(tree), "replay test `pinned_history_replays` is not a listed replay test")


@pytest.mark.parametrize(
    "old,new,fragment",
    [
        ("| `proof` | Proof relation | `fresh_genesis_when_stored`: only when stored | proof fixtures |\n", "",
         "surface `proof` of specs/first_release_history_cutover.json is missing from the contract table"),
        ("| `wire` |", "| `gas` | Gas | `fresh_genesis` | goldens |\n| `wire` |",
         "contract table surface `gas` is not in"),
        ("| `wire` | Block wire | `fresh_genesis` |", "| `wire` | Block wire | `contract_redeployment` |",
         "surface `wire` cutover is `contract_redeployment` in the contract and `fresh_genesis` in"),
    ],
)
def test_contract_table_and_inventory_must_list_the_same_surfaces(
    tree: Path, old: str, new: str, fragment: str
) -> None:
    edit(tree, CONTRACT_MD, old, new)
    assert_single(GUARD.check(tree), CONTRACT_MD, fragment)


@pytest.mark.parametrize(
    "change,fragment",
    [
        (lambda surface: surface.update(cutover="activation"), "unknown cutover"),
        (lambda surface: surface.update(id="Wire"), "needs a unique lower-case `id`"),
        (lambda surface: surface.update(anchors=[]), "has no source anchor"),
        (lambda surface: surface.update(regenerate=[]), "lists nothing to regenerate"),
        (lambda surface: surface["regenerate"][0].update(artifact="fixtures"), "whole top-level directory"),
        (lambda surface: surface["regenerate"][0].update(artifact="fixtures/absent"), "regeneration target of `block wire` is missing"),
        (lambda surface: surface["regenerate"][0].pop("mention"), "needs a `generator` or `checked_by`"),
        (lambda surface: surface["regenerate"][0].pop("generator"), "needs a `generator` or `checked_by`"),
        (lambda surface: surface["regenerate"][0].update(generator="scripts/absent.sh"), "generator or check of"),
        (lambda surface: surface["regenerate"][0].update(mention="capture_other"), "no longer mentions `capture_other`"),
        (lambda surface: surface["regenerate"][1].update(artifact=PINNED_DIR), "must be a file"),
        (lambda surface: surface["anchors"][0].update(contains="pub struct Block;"), "is missing; update the inventory"),
    ],
)
def test_vague_or_stale_incompatible_change_surface_fails(tree: Path, change, fragment: str) -> None:
    edit_inventory(tree, lambda data: change(data["incompatible_change_surfaces"][0]))
    assert_any(GUARD.check(tree), fragment)


def test_duplicate_surface_identifier_fails(tree: Path) -> None:
    edit_inventory(tree, lambda data: data["incompatible_change_surfaces"][1].update(id="wire"))
    assert_any(GUARD.check(tree), "needs a unique lower-case `id`")


def test_generator_that_stops_covering_its_artifact_fails(tree: Path) -> None:
    write(tree, "scripts/regen_proof.sh", "#!/bin/sh\n")
    assert_single(GUARD.check(tree), "scripts/regen_proof.sh", "no longer mentions")


def test_a_check_is_tied_to_its_artifact_by_its_own_mention(tree: Path) -> None:
    # The exporter and the test that fails on a stale artifact live in one file: the entry
    # names both, so removing the test is seen although the exporter still mentions itself.
    checked = lambda data: data["incompatible_change_surfaces"][0]["regenerate"][0].update(
        checked_by=NODE_RS, check_mention="pinned_frames_are_the_current_capture"
    )
    edit_inventory(tree, checked)
    assert_single(
        GUARD.check(tree), NODE_RS, "no longer mentions `pinned_frames_are_the_current_capture`"
    )
    edit(
        tree,
        NODE_RS,
        "fn capture_pinned_history() {}",
        "fn capture_pinned_history() {}\n#[test]\nfn pinned_frames_are_the_current_capture() {}",
    )
    assert GUARD.check(tree) == ()
    # Without `check_mention` the check is tied by `mention`, as before.
    plain = lambda data: data["incompatible_change_surfaces"][0]["regenerate"][0].update(
        checked_by=NODE_RS
    )
    edit_inventory(tree, plain)
    assert GUARD.check(tree) == ()
    orphan = lambda data: data["incompatible_change_surfaces"][0]["regenerate"][0].update(
        check_mention="pinned_frames_are_the_current_capture"
    )
    edit_inventory(tree, orphan)
    assert_single(GUARD.check(tree), PINNED_DIR, "`check_mention` names what its `checked_by`")


def test_current_inventory_checks_the_native_finality_frames_with_a_live_test() -> None:
    data, _ = GUARD.load_inventory(ROOT)
    surface = next(
        entry for entry in data["incompatible_change_surfaces"] if entry["id"] == "execution_root"
    )
    target = next(
        entry
        for entry in surface["regenerate"]
        if entry["artifact"] == "fixtures/sumeragi/native-finality"
    )
    assert target["mention"] == "capture_native_checkpoint_fixtures"
    check = "tracked_native_checkpoint_fixtures_are_the_current_exporter_output"
    assert target["check_mention"] == check
    source = GUARD.Sources(ROOT).get(target["checked_by"])
    assert source is not None
    # The exporter is an explicit, ignored capture; the check beside it runs with the lib tests.
    position = source.blanked.index(f"fn {check}(")
    attributes = GUARD.function_attributes(source.blanked, position)
    assert any(GUARD.IS_TEST_ATTRIBUTE.match(attribute) for attribute in attributes)
    assert not any(GUARD.IGNORE_ATTRIBUTE.match(attribute) for attribute in attributes)
    exporter = source.blanked.index(f"fn {target['mention']}(")
    assert any(
        GUARD.IGNORE_ATTRIBUTE.match(attribute)
        for attribute in GUARD.function_attributes(source.blanked, exporter)
    )


@pytest.mark.parametrize(
    "relative,contents,fragment",
    [
        ("crates/node/src/probe.rs", "pub fn other() {}\n", "obsolete-history evidence anchor"),
        ("scripts/first_release_history_evidence.py", "SCHEMA = 'other'\n", "no longer writes"),
    ],
)
def test_obsolete_history_evidence_drift_fails(
    tree: Path, relative: str, contents: str, fragment: str
) -> None:
    write(tree, relative, contents)
    assert_single(GUARD.check(tree), relative, fragment)


def test_missing_obsolete_history_evidence_tool_or_test_fails(tree: Path) -> None:
    (tree / "scripts/first_release_history_evidence.py").unlink()
    assert_single(GUARD.check(tree), "evidence tool is missing")
    write(tree, "scripts/first_release_history_evidence.py", EVIDENCE_TOOL)
    (tree / "pytests/scripts/first_release_history_evidence_test.py").unlink()
    assert_single(GUARD.check(tree), "evidence test is missing")


def test_regenerated_abi_golden_is_a_declared_cutover_with_every_carrier(tree: Path) -> None:
    edit(tree, ABI_GOLDEN_RS, ABI_HASH, OTHER_ABI_HASH)
    assert_single(GUARD.check(tree), ABI_GOLDEN_RS, "is not the hash", "declared cutover")
    # Declaring the new hash is not enough: every listed carrier must be regenerated with it.
    declare = lambda data: data["declared_abi_cutover"].update(abi_hash=OTHER_ABI_HASH)
    edit_inventory(tree, declare)
    errors = GUARD.check(tree)
    assert len(errors) == 10, errors
    for carrier in (ABI_DOC_MD, ABI_MANIFEST_JSON, ABI_WRAPPED_RS, ABI_FIXTURE_JSON):
        assert_any(errors, f"{carrier}: does not carry the declared ABI hash {OTHER_ABI_HASH}")
    assert_any(errors, f"{ABI_EXECUTOR_TO}: does not carry the declared ABI hash")
    assert_any(errors, f"{ABI_EXECUTOR_TO}: IVM program header does not carry")
    assert_any(errors, f"{ABI_SAMPLE_TO}: IVM program header does not carry", ABI_GENERATOR_SH)
    for row in (1, 2):
        assert_any(errors, f"{ABI_CAPTURE_TSV}:{row}: IVM program header does not carry")
    assert_any(errors, f"{ABI_FIXTURE_JSON}: base64 IVM program header does not carry")
    other = bytes.fromhex(OTHER_ABI_HASH)
    write(tree, ABI_DOC_MD, ABI_DOC.replace(ABI_HASH, OTHER_ABI_HASH))
    write(tree, ABI_MANIFEST_JSON, ABI_MANIFEST.replace(ABI_HASH.upper(), OTHER_ABI_HASH.upper()))
    write(
        tree,
        ABI_WRAPPED_RS,
        f'pub const HANDLE: &[u8] = &hex!(\n    "{OTHER_ABI_HASH[:7]}"\n    "{OTHER_ABI_HASH[7:]}"\n);\n',
    )
    write(tree, ABI_EXECUTOR_TO, ivm_program(other))
    write(tree, ABI_SAMPLE_TO, ivm_program(other))
    write(tree, ABI_CAPTURE_TSV, abi_capture(other))
    write(tree, ABI_FIXTURE_JSON, abi_fixture(other))
    assert GUARD.check(tree) == ()


@pytest.mark.parametrize(
    "relative,contents,fragments",
    [
        (ABI_DOC_MD, f"| ABI v1 | {OTHER_ABI_HASH} |\n", (ABI_DOC_MD, "does not carry")),
        # The text forms are exact: a manifest literal is upper case, a golden lower case.
        (ABI_MANIFEST_JSON, ABI_MANIFEST.lower(), (ABI_MANIFEST_JSON, "does not carry")),
        (ABI_DOC_MD, ABI_DOC.upper(), (ABI_DOC_MD, "does not carry")),
        (
            ABI_WRAPPED_RS,
            ABI_WRAPPED.replace(ABI_HASH[30:], OTHER_ABI_HASH[30:]),
            (ABI_WRAPPED_RS, "does not carry"),
        ),
        # A program is read at its header: the hash elsewhere in the image does not count.
        (
            ABI_SAMPLE_TO,
            ivm_program(bytes.fromhex(OTHER_ABI_HASH), b"CNTR" + ABI_RAW),
            (ABI_SAMPLE_TO, "IVM program header does not carry"),
        ),
        (ABI_SAMPLE_TO, b"NOPE" + ivm_program(ABI_RAW)[4:], (ABI_SAMPLE_TO, "IVM program header")),
        (ABI_SAMPLE_TO, ivm_program(ABI_RAW)[:40], (ABI_SAMPLE_TO, "IVM program header")),
        (
            ABI_MAP_TSV,
            ABI_MAP + "contract\tdemo/absent.ko\tdemo/absent.to\n",
            ("demo/absent.to", f"listed in {ABI_MAP_TSV} is missing"),
        ),
        (ABI_MAP_TSV, ABI_MAP + "contract demo/sample.to\n", (ABI_MAP_TSV, "is not owner, source")),
        (ABI_MAP_TSV, "# owner\tsource-or-tag\tartifact\n", (ABI_MAP_TSV, "lists no IVM program")),
        # A capture is read row by row: one stale program of one row is enough, wherever the
        # row stands and whichever of its two programs it is.
        (
            ABI_CAPTURE_TSV,
            abi_capture(OTHER_ABI_RAW).splitlines(keepends=True)[0]
            + abi_capture().splitlines(keepends=True)[1],
            (f"{ABI_CAPTURE_TSV}:1:", "IVM program header does not carry"),
        ),
        (
            ABI_CAPTURE_TSV,
            abi_capture()
            + capture_row("third", ivm_program(ABI_RAW), ivm_program(OTHER_ABI_RAW, b"CNTR" + ABI_RAW)),
            (f"{ABI_CAPTURE_TSV}:3:", "IVM program header does not carry"),
        ),
        (
            ABI_CAPTURE_TSV,
            abi_capture()
            + capture_row("third", ivm_program(OTHER_ABI_RAW, b"CNTR" + ABI_RAW), ivm_program(ABI_RAW)),
            (f"{ABI_CAPTURE_TSV}:3:", "IVM program header does not carry"),
        ),
        # Program text is canonical lower-case hexadecimal of a complete header.
        (
            ABI_CAPTURE_TSV,
            abi_capture() + f"odd\t{ivm_program(ABI_RAW).hex()}0\n",
            (f"{ABI_CAPTURE_TSV}:3:", "IVM program header does not carry"),
        ),
        (
            ABI_CAPTURE_TSV,
            abi_capture() + f"short\t{ivm_program(ABI_RAW)[:40].hex()}\n",
            (f"{ABI_CAPTURE_TSV}:3:", "IVM program header does not carry"),
        ),
        (
            ABI_CAPTURE_TSV,
            abi_capture() + f"mixed\t49564d00{ivm_program(ABI_RAW)[4:].hex().upper()}\n",
            (f"{ABI_CAPTURE_TSV}:3:", "IVM program header does not carry"),
        ),
        # The hash as bare text in a row is no program.
        (
            ABI_CAPTURE_TSV,
            abi_capture() + f"bare\t{ABI_HASH}\t{ABI_HASH}\n",
            (f"{ABI_CAPTURE_TSV}:3:", "capture row holds no IVM program"),
        ),
        (ABI_CAPTURE_TSV, "", (ABI_CAPTURE_TSV, "capture holds no row")),
        (ABI_CAPTURE_TSV, "\n\n", (ABI_CAPTURE_TSV, "capture holds no row")),
        # A fixture states the hash three ways; each is checked on its own.
        (
            ABI_FIXTURE_JSON,
            abi_fixture().replace(
                base64.b64encode(ivm_program(ABI_RAW, b"CNTR")).decode(),
                base64.b64encode(ivm_program(OTHER_ABI_RAW, b"CNTR")).decode(),
            ),
            (ABI_FIXTURE_JSON, "base64 IVM program header does not carry"),
        ),
        (
            ABI_FIXTURE_JSON,
            abi_fixture().replace(f'"{ABI_HASH}"', f'"{OTHER_ABI_HASH}"'),
            (f"{ABI_FIXTURE_JSON}: does not carry",),
        ),
        (
            ABI_FIXTURE_JSON,
            abi_fixture().replace(ABI_HASH.upper(), OTHER_ABI_HASH.upper()),
            (f"{ABI_FIXTURE_JSON}: does not carry",),
        ),
        (
            ABI_FIXTURE_JSON,
            abi_fixture().replace(
                base64.b64encode(ivm_program(ABI_RAW, b"CNTR")).decode(), "bm90IGEgcHJvZ3JhbQ=="
            ),
            (ABI_FIXTURE_JSON, "holds no base64 IVM program"),
        ),
        # A base64 image cut inside its header is still found and still refused.
        (
            ABI_FIXTURE_JSON,
            abi_fixture().replace(
                base64.b64encode(ivm_program(ABI_RAW, b"CNTR")).decode(),
                base64.b64encode(ivm_program(ABI_RAW)[:30]).decode(),
            ),
            (ABI_FIXTURE_JSON, "base64 IVM program header does not carry"),
        ),
        (
            ABI_FIXTURE_JSON,
            abi_fixture().replace(
                base64.b64encode(ivm_program(ABI_RAW, b"CNTR")).decode(),
                base64.b64encode(ivm_program(ABI_RAW, b"CNTR")).decode()[:-3],
            ),
            (ABI_FIXTURE_JSON, "base64 IVM program header does not carry"),
        ),
        # A text carrier holds the hash exactly as often as its entry states.
        (ABI_DOC_MD, ABI_DOC + ABI_DOC, (ABI_DOC_MD, "holds the declared ABI hash 2 times as `hex`", "states 1")),
        (
            ABI_MANIFEST_JSON,
            ABI_MANIFEST + ABI_MANIFEST,
            (ABI_MANIFEST_JSON, "holds the declared ABI hash 2 times as `HEX`", "states 1"),
        ),
        (
            ABI_WRAPPED_RS,
            ABI_WRAPPED + ABI_WRAPPED.replace("HANDLE", "OTHER"),
            (ABI_WRAPPED_RS, "holds the declared ABI hash 2 times as `hex_wrapped`", "states 1"),
        ),
    ],
)
def test_stale_or_malformed_abi_hash_carrier_fails(
    tree: Path, relative: str, contents: str | bytes, fragments: tuple[str, ...]
) -> None:
    write(tree, relative, contents)
    assert_single(GUARD.check(tree), *fragments)


def test_a_text_carrier_cannot_keep_a_stale_statement_beside_a_regenerated_one(tree: Path) -> None:
    # A document that states the hash twice says so in its entry.
    twice = lambda data: data["incompatible_change_surfaces"][2]["regenerate"][1].update(
        occurrences=2
    )
    edit_inventory(tree, twice)
    assert_single(GUARD.check(tree), ABI_DOC_MD, "holds the declared ABI hash 1 times", "states 2")
    write(tree, ABI_DOC_MD, ABI_DOC + f"| runtime | {ABI_HASH} |\n")
    assert GUARD.check(tree) == ()
    # Regenerating one of the two statements leaves the other stale: the count fails.
    write(tree, ABI_DOC_MD, ABI_DOC + f"| runtime | {OTHER_ABI_HASH} |\n")
    assert_single(GUARD.check(tree), ABI_DOC_MD, "holds the declared ABI hash 1 times", "states 2")
    write(tree, ABI_DOC_MD, ABI_DOC.replace(ABI_HASH, OTHER_ABI_HASH) + f"| runtime | {OTHER_ABI_HASH} |\n")
    assert_single(GUARD.check(tree), f"{ABI_DOC_MD}: does not carry the declared ABI hash")


def test_a_capture_with_extra_columns_or_one_program_per_row_is_read_by_program(tree: Path) -> None:
    program = ivm_program(ABI_RAW, b"CNTR" + ABI_RAW).hex()
    write(tree, ABI_CAPTURE_TSV, f"solo\t{program}\n\nwide\tnote\t{program}\t{program}\t{program}\n")
    assert GUARD.check(tree) == ()
    stale = ivm_program(OTHER_ABI_RAW, b"CNTR" + ABI_RAW).hex()
    write(tree, ABI_CAPTURE_TSV, f"solo\t{program}\n\nwide\tnote\t{program}\t{program}\t{stale}\n")
    assert_single(GUARD.check(tree), f"{ABI_CAPTURE_TSV}:3:", "IVM program header does not carry")


def test_every_base64_program_of_a_fixture_is_read(tree: Path) -> None:
    fresh = base64.b64encode(ivm_program(ABI_RAW, b"\x07")).decode()
    stale = base64.b64encode(ivm_program(OTHER_ABI_RAW, b"\x07")).decode()
    with_second = lambda image: abi_fixture().replace(
        '"manifest"', f'"second_base64": "{image}",\n  "manifest"'
    )
    write(tree, ABI_FIXTURE_JSON, with_second(fresh))
    assert GUARD.check(tree) == ()
    write(tree, ABI_FIXTURE_JSON, with_second(stale))
    assert_single(GUARD.check(tree), ABI_FIXTURE_JSON, "base64 IVM program header does not carry")


def test_carrier_forms_accept_one_form_or_a_list_of_distinct_forms() -> None:
    assert GUARD.carrier_forms({}) == ()
    assert GUARD.carrier_forms({"carries": "hex"}) == ("hex",)
    assert GUARD.carrier_forms({"carries": ["HEX", "ivm_base64"]}) == ("HEX", "ivm_base64")
    for malformed in ("base64", "", [], ["hex", "hex"], ["hex", "sha"], ["hex", 3], {"hex": 1}, 7, True):
        assert GUARD.carrier_forms({"carries": malformed}) is None, malformed
    assert set(GUARD.ABI_TEXT_FORMS) < set(GUARD.ABI_HASH_FORMS)


def test_wrapped_hex_carrier_ignores_only_quotes_and_whitespace(tree: Path) -> None:
    write(tree, ABI_WRAPPED_RS, f'const H: &[u8] = &hex!("{ABI_HASH[:1]}"\n\t "{ABI_HASH[1:]}");\n')
    assert GUARD.check(tree) == ()
    write(tree, ABI_WRAPPED_RS, f'const H: &[u8] = &hex!("{ABI_HASH[:32]}", "{ABI_HASH[32:]}");\n')
    assert_single(GUARD.check(tree), ABI_WRAPPED_RS, "does not carry")


@pytest.mark.parametrize(
    "change,fragment",
    [
        (lambda data: data.pop("declared_abi_cutover"), "`declared_abi_cutover` must be a dict"),
        (
            lambda data: data["declared_abi_cutover"].update(abi_hash="c728"),
            "records `abi_hash` as 64 hex digits",
        ),
        (
            lambda data: data["declared_abi_cutover"].update(abi_hash=ABI_HASH.upper()),
            "records `abi_hash` as 64 hex digits",
        ),
        (lambda data: data["declared_abi_cutover"].pop("golden"), "names the `golden` path"),
        (
            lambda data: data["declared_abi_cutover"]["golden"].update(prefix="const OTHER: &str ="),
            "the ABI golden must hold `const OTHER: &str =` exactly once",
        ),
        (
            lambda data: data["declared_abi_cutover"]["golden"].update(prefix="const "),
            "the ABI golden is not 64 hex digits",
        ),
        (
            lambda data: data["declared_abi_cutover"]["golden"].update(path=ABI_DOC_MD),
            "the ABI golden must hold",
        ),
        (lambda data: data["declared_abi_cutover"].update(change=""), "states the `change`"),
        (lambda data: data["declared_abi_cutover"].pop("fresh_genesis"), "states `fresh_genesis`"),
        (
            lambda data: data["declared_abi_cutover"].update(fresh_genesis="no"),
            "states `fresh_genesis`",
        ),
        (
            lambda data: data["declared_abi_cutover"].update(fresh_genesis_reason=""),
            "states `fresh_genesis`",
        ),
        (lambda data: data["declared_abi_cutover"].update(surface="gas"), "names a listed surface"),
        (
            lambda data: data["declared_abi_cutover"].update(cutover="fresh_genesis"),
            "declares `fresh_genesis`, but the cutover of surface `abi` is `contract_redeployment`",
        ),
        (
            lambda data: data["declared_abi_cutover"].update(surface="wire"),
            "but the cutover of surface `wire` is `fresh_genesis`",
        ),
        (
            lambda data: data["incompatible_change_surfaces"][0]["regenerate"][0].update(
                carries="hex"
            ),
            "only targets of the declared surface carry the ABI hash, not those of `wire`",
        ),
        (
            lambda data: data["incompatible_change_surfaces"][2]["regenerate"][0].pop("carries"),
            f"the ABI golden {ABI_GOLDEN_RS} must be a regeneration target of `abi`",
        ),
        (
            lambda data: data["incompatible_change_surfaces"][2]["regenerate"][1].update(
                carries="base64"
            ),
            "carries the ABI hash in the unknown form `base64`",
        ),
        (
            lambda data: data["incompatible_change_surfaces"][2]["regenerate"][1].update(carries=[]),
            "carries the ABI hash in the unknown form `[]`",
        ),
        (
            lambda data: data["incompatible_change_surfaces"][2]["regenerate"][1].update(
                carries=["hex", "hex"]
            ),
            "or a list of distinct ones",
        ),
        (
            lambda data: data["incompatible_change_surfaces"][2]["regenerate"][1].update(
                carries=["hex", "sha256"]
            ),
            "carries the ABI hash in the unknown form",
        ),
        (
            lambda data: data["incompatible_change_surfaces"][2]["regenerate"][1].update(
                occurrences=0
            ),
            "`occurrences` is the positive number of times a text carrier",
        ),
        (
            lambda data: data["incompatible_change_surfaces"][2]["regenerate"][1].update(
                occurrences=True
            ),
            "`occurrences` is the positive number of times a text carrier",
        ),
        (
            lambda data: data["incompatible_change_surfaces"][2]["regenerate"][1].update(
                occurrences="2"
            ),
            "`occurrences` is the positive number of times a text carrier",
        ),
        (
            # A program carrier has no text count.
            lambda data: data["incompatible_change_surfaces"][2]["regenerate"][4].update(
                occurrences=1
            ),
            f"{ABI_EXECUTOR_TO}: `occurrences` is the positive number of times a text carrier",
        ),
        (
            # Nor has a target that carries nothing.
            lambda data: data["incompatible_change_surfaces"][0]["regenerate"][0].update(
                occurrences=1
            ),
            f"{PINNED_DIR}: `occurrences` is the positive number of times a text carrier",
        ),
        (
            lambda data: data["incompatible_change_surfaces"][2]["regenerate"][1].update(
                document=True
            ),
            "a carrier of the ABI hash names its `generator` or `checked_by` source",
        ),
        (
            lambda data: data["incompatible_change_surfaces"][2]["regenerate"][1].update(
                mention="other.md"
            ),
            "no longer mentions `other.md`",
        ),
    ],
)
def test_malformed_abi_cutover_declaration_fails(tree: Path, change, fragment: str) -> None:
    edit_inventory(tree, change)
    assert_any(GUARD.check(tree), fragment)


def test_pinned_history_holding_the_abi_hash_needs_a_fresh_genesis(tree: Path) -> None:
    frames = (FRAMES[0], b"\x01deployment under " + ABI_RAW)
    write(tree, f"{PINNED_DIR}/block-2.wire", frames[1])
    write(tree, f"{PINNED_DIR}/manifest.json", json.dumps(pinned_manifest(frames)))

    def regenerated(data: dict) -> None:
        data["pinned_history"].update(history_sha256=pinned_manifest(frames)["history_sha256"])

    edit_inventory(tree, regenerated)
    assert_single(
        GUARD.check(tree),
        f"{PINNED_DIR}/manifest.json",
        "the pinned history holds the declared ABI hash",
        "fresh genesis",
    )

    def declared(data: dict) -> None:
        regenerated(data)
        data["declared_abi_cutover"].update(fresh_genesis=True)

    edit_inventory(tree, declared)
    assert GUARD.check(tree) == ()


@pytest.mark.parametrize(
    "relative,contents",
    [
        ("crates/model/src/codec.rs", "impl DecodeHeaderless for SignedBlock {\n    fn d() {}\n}\n"),
        ("crates/model/src/codec.rs", "impl v::codec::DecodeHeaderless for crate::b::SignedBlock {}\n"),
        ("crates/model/src/codec.rs", "impl<'a> DecodeHeaderless<'a>\n    for SignedBlock\n{\n}\n"),
        ("crates/model/src/codec.rs", "#[cfg(test)]\nimpl DecodeHeaderless for SignedBlock {}\n"),
        ("crates/model/src/block_tests.rs", "impl DecodeHeaderless for SignedBlock {}\n"),
        ("integration_tests/tests/decode.rs", "impl DecodeHeaderless for SignedBlock {}\n"),
    ],
)
def test_retired_implementation_written_again_fails(tree: Path, relative: str, contents: str) -> None:
    write(tree, relative, contents)
    assert_single(
        GUARD.check(tree),
        relative,
        "retired implementation `DecodeHeaderless for SignedBlock` reappeared",
    )


@pytest.mark.parametrize(
    "contents",
    [
        "impl DecodeHeaderless for SignedTransaction {}\n",
        "impl EncodeHeaderless for SignedBlock {}\n",
        "impl DecodeHeaderless for SignedBlockWire {}\n",
        "impl DecodeHeaderlessProbe for SignedBlock {}\n",
        "impl<T: DecodeHeaderless> Frame<T> for SignedBlock {}\n",
        "// impl DecodeHeaderless for SignedBlock {}\n",
        'const NOTE: &str = "impl DecodeHeaderless for SignedBlock";\n',
        "fn decode<T: DecodeHeaderless>(bytes: &[u8]) -> SignedBlock {\n    todo(bytes)\n}\n",
    ],
)
def test_other_implementations_and_mentions_are_not_the_retired_one(
    tree: Path, contents: str
) -> None:
    write(tree, "crates/model/src/codec.rs", contents)
    assert GUARD.check(tree) == ()


@pytest.mark.parametrize(
    "change,fragment",
    [
        (lambda data: data.pop("retired_impls"), "`retired_impls` must be a list"),
        (
            lambda data: data["retired_impls"][0].update(trait="codec::DecodeHeaderless"),
            "names a plain trait and a plain type",
        ),
        (lambda data: data["retired_impls"][0].pop("type"), "names a plain trait and a plain type"),
        (lambda data: data["retired_impls"][0].update(retired=""), "states what was retired"),
    ],
)
def test_malformed_retired_implementation_entry_fails(tree: Path, change, fragment: str) -> None:
    edit_inventory(tree, change)
    assert_any(GUARD.check(tree), fragment)


def test_resolved_or_misowned_open_finding_fails(tree: Path) -> None:
    edit(tree, PROOF_RS, "    LegacyReplay,\n", "")
    assert_single(GUARD.check(tree), "open finding T1-A01 no longer matches the source")
    edit_inventory(tree, lambda data: data["open_findings"][0].update(owner="Z.9"))
    errors = GUARD.check(tree)
    assert any("unknown task Z.9" in error for error in errors), errors
    edit_inventory(
        tree, lambda data: data["open_findings"][0].update(owner="outside-zk-plan:consensus")
    )
    assert_single(GUARD.check(tree), "open finding T1-A01 no longer matches the source")


@pytest.mark.parametrize(
    "change,fragment",
    [
        (lambda data: data.update(schema="other"), "schema must be"),
        (lambda data: data.pop("replay_tests"), "`replay_tests` must be a list"),
        (lambda data: data.pop("pinned_history"), "`pinned_history` must be a dict"),
        (
            lambda data: data.pop("future_checkpoint_rule"),
            "`future_checkpoint_rule` must be a dict",
        ),
        (lambda data: data.pop("test_prerequisites"), "`test_prerequisites` must be a list"),
        (lambda data: data.update(retired_identifiers=[]), "`retired_identifiers` must not be empty"),
        (lambda data: data.update(retired_store_artifacts=[]), "`retired_store_artifacts` must not be empty"),
        (lambda data: data.update(contract="specs/missing.md"), "contract specs/missing.md is missing"),
        (
            lambda data: data["retired_identifiers"].append({"identifier": "a|b", "retired": ""}),
            "is not a plain identifier",
        ),
        (lambda data: data["loader_paths"].append("crates/absent"), "has no Rust source"),
    ],
)
def test_malformed_inventory_fails(tree: Path, change, fragment: str) -> None:
    edit_inventory(tree, change)
    errors = GUARD.check(tree)
    assert any(fragment in error for error in errors), errors


def test_missing_inventory_fails(tmp_path: Path) -> None:
    assert_single(GUARD.check(tmp_path), "unreadable inventory")


def test_blanking_keeps_layout_and_removes_only_literals_and_comments() -> None:
    source = (
        'fn a<\'x>(s: &\'x str) -> char { let _ = "} fn legacy() {"; \'{\' }\n'
        "// fn legacy_line() {\n"
        "/* fn outer() { /* fn inner() { */ } */ fn kept() {}\n"
        'const RAW: &str = r#"fn "legacy_raw"() {"#; const B: &[u8] = b"}";\n'
        "let escaped = \"\\\"}\\\\\"; let unit = '\\n'; let quote = '\\'';\n"
    )
    blanked = GUARD.blank_rust_literals(source)
    assert len(blanked) == len(source)
    assert blanked.count("\n") == source.count("\n")
    assert "legacy" not in blanked
    assert "fn kept() {}" in blanked
    assert "fn a<'x>(s: &'x str) -> char {" in blanked
    assert blanked.count("{") == blanked.count("}") == 2


def test_string_literals_are_read_from_code_only() -> None:
    text = (
        'fn refuse(name: &str) -> bool {\n    // "commented_out"\n'
        '    name == "exact" || name.starts_with(r#"raw"prefix"#) || name == "a\\"b" /* "blocked" */\n}\n'
        'const AFTER: &str = "outside";\n'
    )
    source = GUARD.Source(text)
    span = source.function("refuse")
    assert span is not None
    assert source.strings(*span) == ["exact", 'raw"prefix', 'a\\"b']
    assert source.function("absent") is None
    assert GUARD.Source("#[cfg(test)]\nfn refuse() {}\n").function("refuse") is None


def test_function_attributes_are_read_on_both_sides_of_the_test_attribute() -> None:
    blanked = GUARD.blank_rust_literals(
        '#[ignore = "why [x]"]\n/// Doc.\n#[test]\n#[cfg(unix)]\npub(crate) async fn runs() {}\n'
        "struct Unrelated;\n#[derive(Debug)]\nfn plain() {}\n"
    )
    attributes = GUARD.function_attributes(blanked, blanked.index("fn runs"))
    assert [" ".join(attribute.split())[:8] for attribute in attributes] == [
        "#[cfg(un",
        "#[test]",
        "#[ignore",
    ]
    assert len(GUARD.function_attributes(blanked, blanked.index("fn plain"))) == 1


def test_test_spans_cover_exactly_the_test_only_items() -> None:
    source = (
        "#[cfg(test)]\nuse helper::fixture;\n"
        "fn production(seed: [u8; 32]) {}\n"
        "#[cfg(all(test, feature = \"x\"))]\n#[allow(dead_code)]\nfn probe(seed: [u8; 32]) -> u8 {\n    seed[0]\n}\n"
        "fn also_production() {}\n"
        "#[tokio::test(flavor = \"multi_thread\")]\nasync fn runs() {}\n"
        "#[cfg(not(test))]\nfn shipping() {}\n"
        "#[cfg(test)] mod inline_tests { fn inner() {} }\n"
        "fn tail() {}\n"
    )
    blanked = GUARD.blank_rust_literals(source)
    spans = GUARD.test_spans(blanked)

    def covered(name: str) -> bool:
        return GUARD.in_spans(blanked.index(name), spans)

    assert [covered(name) for name in ("fixture", "probe", "runs", "inner")] == [True] * 4
    assert [
        covered(name) for name in ("production", "also_production", "shipping", "tail")
    ] == [False] * 4


def test_test_paths_are_recognized() -> None:
    for relative in (
        "crates/a/tests/replay.rs",
        "crates/a/src/kura/tests/01_support.rs",
        "crates/a/src/kura/lane_geometry_tests/03_gc.rs",
        "crates/a/src/block/consensus_model_tests.rs",
        "crates/a/src/block/tests.rs",
        "crates/a/benches/wire.rs",
    ):
        assert GUARD.is_test_path(relative), relative
    for relative in (
        "crates/a/src/kura.rs",
        "crates/a/src/attests.rs",
        "crates/a/src/latests/mod.rs",
        "crates/a/src/contests.rs",
    ):
        assert not GUARD.is_test_path(relative), relative
