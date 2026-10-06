"""Tests of scripts/check_zk_feature_parity.py: record parsing and comparison.

The comparison is exercised on captured outputs; no cargo build runs here.
"""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import sys

import pytest

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "check_zk_feature_parity.py"
RECORD_TEST = ROOT / "crates" / "iroha_core" / "src" / "zk_validity_policy_feature_parity_tests.rs"

_spec = importlib.util.spec_from_file_location("check_zk_feature_parity", SCRIPT)
assert _spec and _spec.loader
parity = importlib.util.module_from_spec(_spec)
sys.modules["check_zk_feature_parity"] = parity
_spec.loader.exec_module(parity)

DIGEST_A = "a" * 64
DIGEST_B = "b" * 64


def output(features: str, must_equal: dict, gated: dict, noise: bool = True) -> str:
    lines = ["running 1 test"] if noise else []
    # The harness prints the test name before the first output line.
    prefix = "test zk_validity_policy::parity_tests::feature_parity::feature_parity_record ... " if noise else ""
    lines.append(f"{prefix}ZK_FEATURE_PARITY features={features}")
    lines += [f"ZK_FEATURE_PARITY must_equal.{k}={v}" for k, v in must_equal.items()]
    lines += [f"ZK_FEATURE_PARITY gated.{k}={v}" for k, v in gated.items()]
    if noise:
        lines.append("ok")
        lines.append("test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 11839 filtered out")
    return "\n".join(lines) + "\n"


def census(status: str = "open", feature_class: str = "validity_gate") -> dict:
    return {
        "entries": [{"id": "feature.zk_stark", "status": status}],
        "features": {
            "iroha_core": {
                "zk-stark": {"class": feature_class, "entry": "feature.zk_stark"},
                "simd": {"class": "acceleration", "reason": "scalar fallback"},
            }
        },
    }


def records(with_stark: str, without_stark: str, **overrides) -> dict:
    full = parity.parse_record(
        "node",
        output(
            "zk-stark,sm",
            overrides.get("full_must", {"certified_history": DIGEST_A, "verification_gas": DIGEST_B}),
            {"zk-stark.real_proof": with_stark},
        ),
    )
    reduced = parity.parse_record(
        "node-without-stark",
        output(
            "sm",
            overrides.get("reduced_must", {"certified_history": DIGEST_A, "verification_gas": DIGEST_B}),
            {"zk-stark.real_proof": without_stark},
        ),
    )
    return {"node": full, "node-without-stark": reduced}


def test_identical_must_equal_and_an_open_gate_pass() -> None:
    gates = parity.load_gates(census())
    assert gates == {"zk-stark": {"entry": "feature.zk_stark", "status": "open"}}
    assert parity.compare(records("registered=[true] verified=[true]", "not-compiled"), gates) == []


def test_a_feature_that_changes_a_root_or_gas_fails() -> None:
    gates = parity.load_gates(census())
    problems = parity.compare(
        records(
            "accepted",
            "not-compiled",
            reduced_must={"certified_history": DIGEST_B, "verification_gas": DIGEST_B},
        ),
        gates,
    )
    assert len(problems) == 1
    assert problems[0].startswith("must_equal.certified_history: a Cargo feature changes this record")
    problems = parity.compare(
        records(
            "accepted",
            "not-compiled",
            reduced_must={"certified_history": DIGEST_A, "verification_gas": DIGEST_A},
        ),
        gates,
    )
    assert [p.split(":")[0] for p in problems] == ["must_equal.verification_gas"]


def test_a_missing_must_equal_record_fails() -> None:
    problems = parity.compare(
        records("accepted", "not-compiled", reduced_must={"certified_history": DIGEST_A}),
        parity.load_gates(census()),
    )
    assert problems == ["must_equal.verification_gas: not printed by ['node-without-stark']"]


def test_a_gated_difference_needs_an_open_census_gate() -> None:
    differing = records("accepted", "not-compiled")
    # The census says the gate is removed, yet the builds still differ.
    problems = parity.compare(differing, parity.load_gates(census(status="done")))
    assert len(problems) == 1 and "has status `done`" in problems[0]
    # The census does not classify the feature as a gate at all.
    problems = parity.compare(differing, parity.load_gates(census(feature_class="acceleration")))
    assert len(problems) == 1 and "does not classify `iroha_core/zk-stark`" in problems[0]


def test_an_open_gate_that_no_longer_differs_is_stale() -> None:
    agreeing = records("accepted", "accepted")
    problems = parity.compare(agreeing, parity.load_gates(census()))
    assert len(problems) == 1 and "update the census" in problems[0]
    # With the gate closed in the census the same records pass.
    assert parity.compare(agreeing, parity.load_gates(census(status="done"))) == []
    # Two selections that both compile the feature say nothing about the gate.
    both = {
        "node": agreeing["node"],
        "node-again": parity.parse_record(
            "node-again",
            output("zk-stark,sm", {"certified_history": DIGEST_A, "verification_gas": DIGEST_B}, {"zk-stark.real_proof": "accepted"}),
        ),
    }
    assert parity.compare(both, parity.load_gates(census())) == []


def test_the_harness_prefix_on_the_first_line_is_tolerated() -> None:
    record = parity.parse_record(
        "node", output("zk-stark,sm", {"certified_history": DIGEST_A}, {"zk-stark.real_proof": "accepted"})
    )
    assert record["features"] == {"compiled": "zk-stark,sm"}
    assert record["must_equal"] == {"certified_history": DIGEST_A}
    assert record["gated"] == {"zk-stark.real_proof": "accepted"}
    plain = parity.parse_record(
        "node",
        output("zk-stark,sm", {"certified_history": DIGEST_A}, {"zk-stark.real_proof": "accepted"}, noise=False),
    )
    assert plain == record


def test_one_selection_is_not_a_comparison() -> None:
    single = {"node": records("accepted", "not-compiled")["node"]}
    assert parity.compare(single, {}) == ["need at least two feature selections to compare, got ['node']"]


@pytest.mark.parametrize(
    "text, message",
    [
        ("running 1 test\n", "printed no `ZK_FEATURE_PARITY` line"),
        ("ZK_FEATURE_PARITY features=sm\n", "no `must_equal` record"),
        ("ZK_FEATURE_PARITY must_equal.history\n", "malformed record line"),
        ("ZK_FEATURE_PARITY other.history=aa\n", "unknown record `other.history`"),
        ("ZK_FEATURE_PARITY must_equal.history=\n", "record `must_equal.history` is empty"),
        (
            "ZK_FEATURE_PARITY must_equal.history=aa\nZK_FEATURE_PARITY must_equal.history=aa\n",
            "printed twice",
        ),
    ],
)
def test_malformed_output_is_rejected(text: str, message: str) -> None:
    with pytest.raises(parity.ParityError, match=message.replace("`", "`")):
        parity.parse_record("node", text)


def test_cli_compares_captured_outputs(tmp_path: Path, capsys: pytest.CaptureFixture) -> None:
    census_path = tmp_path / "census.json"
    census_path.write_text(json.dumps(census()), encoding="utf-8")
    full = tmp_path / "node.txt"
    reduced = tmp_path / "reduced.txt"
    full.write_text(output("zk-stark", {"certified_history": DIGEST_A}, {"zk-stark.real_proof": "accepted"}))
    reduced.write_text(output("", {"certified_history": DIGEST_A}, {"zk-stark.real_proof": "not-compiled"}))
    arguments = [
        "--census",
        str(census_path),
        "--from-output",
        f"node={full}",
        "--from-output",
        f"node-without-stark={reduced}",
    ]
    assert parity.main(arguments) == 0
    assert "OK (1 must-equal records identical" in capsys.readouterr().out
    reduced.write_text(output("", {"certified_history": DIGEST_B}, {"zk-stark.real_proof": "not-compiled"}))
    assert parity.main(arguments) == 1
    assert "a Cargo feature changes this record" in capsys.readouterr().err
    assert parity.main(["--census", str(census_path), "--from-output", "node"]) == 2
    assert parity.main(["--census", str(tmp_path / "absent.json"), "--from-output", f"node={full}"]) == 2


def test_selections_and_the_record_test_agree_with_the_source() -> None:
    # The default selection is the crate's default feature set; the others are
    # explicit lists that drop exactly one gate family.
    assert parity.SELECTIONS["node"] is None
    assert "proofs-stark" not in parity.SELECTIONS["node-without-stark"]
    assert set(parity.NODE_FEATURES) - set(parity.SELECTIONS["node-without-stark"]) == {"proofs-stark"}
    assert set(parity.NODE_FEATURES) - set(parity.SELECTIONS["node-without-sm-gost"]) == {"sm", "gost"}
    command = parity.cargo_command("node-without-stark", "/tmp/target")
    assert command[:5] == ["cargo", "test", "-p", "iroha_core", "--lib"]
    assert "--no-default-features" in command and "--target-dir" in command
    assert parity.TEST_FILTER in command
    assert "--no-default-features" not in parity.cargo_command("node", None)
    # `node` of crates/iroha_core/Cargo.toml plus `simd` is the list compared here.
    manifest = (ROOT / "crates" / "iroha_core" / "Cargo.toml").read_text(encoding="utf-8")
    node_block = manifest.split("\nnode = [", 1)[1].split("]", 1)[0]
    declared = {part.strip().strip('"') for part in node_block.split(",") if part.strip()}
    assert declared | {"simd"} == set(parity.NODE_FEATURES)
    assert 'default = ["node", "simd"]' in manifest
    # The Rust test prints the prefix and the record names this script reads.
    source = RECORD_TEST.read_text(encoding="utf-8")
    assert 'const LINE_PREFIX: &str = "ZK_FEATURE_PARITY";' in source
    assert "fn feature_parity_record()" in source
    assert '"zk-stark.real_proof"' in source
    # Every gated record names a feature the real census classifies as a gate.
    gates = parity.load_gates(json.loads((ROOT / parity.CENSUS).read_text(encoding="utf-8")))
    assert gates["zk-stark"]["entry"] == "feature.zk_stark"
    assert gates["zk-stark"]["status"] == "open"
