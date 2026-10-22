"""Check separate receipt preparation, without claiming native admission."""

import hashlib
import importlib.util
import json
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "apple_consumer", ROOT / "scripts/mobile_sdk_apple_device_demo_consumer.py"
)
consumer = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(consumer)


@pytest.fixture
def artifact(tmp_path, monkeypatch):
    """Synthetic receipt inputs only; no valid native framework is produced."""
    directory = tmp_path / "artifact"
    root = directory / "NoritoBridge.xcframework"
    archive = root / "ios-arm64/libNoritoBridge.a"
    archive.parent.mkdir(parents=True)
    archive.write_bytes(b"receipt unit fixture, not a native archive")
    evidence = root / "evidence"
    evidence.mkdir()
    names = ("producer-launch.json", "producer-record.json", "cargo-messages.jsonl",
             "pqcrypto-normalization.json", "consumer", "source-observation.json")
    for name in names:
        (evidence / name).write_text("receipt-only fixture")
    manifest = {
        "schema": "iroha.norito-bridge-device-demo-artifact.v1",
        "artifact_scope": "physical-device-demo", "purpose": "physical-ios-debug",
        "source_root": str(ROOT), "source_commit": "a" * 40,
        "target_triple": "aarch64-apple-ios", "native_bridge_abi_version": 31,
        "hashes": {"ios-arm64": hashlib.sha256(archive.read_bytes()).hexdigest()},
        "evidence": {name: hashlib.sha256((evidence / name).read_bytes()).hexdigest() for name in names},
    }
    (root / "NoritoBridge.artifacts.json").write_text(json.dumps(manifest))
    monkeypatch.setattr(consumer.subprocess, "check_output", lambda *args, **kwargs: "b" * 40 + "\n")
    return directory


def test_prepare_retains_original_and_observes_current_separately(artifact):
    original = (artifact / "NoritoBridge.xcframework/NoritoBridge.artifacts.json").read_bytes()
    with pytest.raises(ValueError, match="source commit differs"):
        consumer.prepare_record(artifact, allow_source_head_drift=False)
    record = consumer.prepare_record(artifact, allow_source_head_drift=True)
    assert record["artifact_source_commit"] == "a" * 40
    assert record["current_source_commit"] == "b" * 40
    assert record["source_head_drifted"] is True
    assert (artifact / "NoritoBridge.xcframework/NoritoBridge.artifacts.json").read_bytes() == original


@pytest.mark.parametrize("relative", ("ios-arm64/libNoritoBridge.a", "evidence/producer-record.json"))
def test_prepare_refuses_changed_native_or_evidence_inputs(artifact, relative):
    (artifact / "NoritoBridge.xcframework" / relative).write_bytes(b"changed")
    with pytest.raises(ValueError, match="hash differs|evidence changed"):
        consumer.prepare_record(artifact, allow_source_head_drift=True)


def test_prepare_refuses_head_change_during_observation(artifact, monkeypatch):
    observations = iter(("b" * 40, "c" * 40))
    monkeypatch.setattr(consumer.subprocess, "check_output", lambda *args, **kwargs: next(observations))
    with pytest.raises(ValueError, match="changed during"):
        consumer.prepare_record(artifact, allow_source_head_drift=True)


def test_receipt_retention_is_idempotent_and_never_overwrites(artifact, tmp_path):
    record = consumer.prepare_record(artifact, allow_source_head_drift=True)
    destination = tmp_path / "consumer.json"
    consumer.retain_record(destination, record)
    original = destination.read_bytes()
    assert destination.stat().st_mode & 0o777 == 0o600
    consumer.retain_record(destination, record)
    with pytest.raises(ValueError, match="differs"):
        consumer.retain_record(destination, {**record, "current_source_commit": "c" * 40})
    assert destination.read_bytes() == original


def test_receipt_cannot_enter_artifact_or_follow_link(artifact, tmp_path):
    record = consumer.prepare_record(artifact, allow_source_head_drift=True)
    with pytest.raises(ValueError, match="outside"):
        consumer.retain_record(artifact / "consumer.json", record)
    original = tmp_path / "original.json"
    original.write_text("untouched")
    link = tmp_path / "link.json"
    link.symlink_to(original)
    with pytest.raises(ValueError, match="symbolic link"):
        consumer.retain_record(link, record)
    assert original.read_text() == "untouched"
