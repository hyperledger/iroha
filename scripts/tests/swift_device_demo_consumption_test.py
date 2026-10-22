"""Exercise the original Swift manifest and its separate consumer receipt owner.

These checks do not build or qualify a native bridge. Artifact admission remains
with the manifest; receipt helper tests exercise only local evidence custody.
"""

import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

import pytest


ROOT = Path(__file__).resolve().parents[2]
MANIFEST = ROOT / "IrohaSwift/Package.swift"
SELECTOR = "MOBILE_SDK_APPLE_DEVICE_DEMO_ARTIFACT_DIR"
FLAG = "MOBILE_SDK_APPLE_DEVICE_DEMO_ALLOW_SOURCE_HEAD_DRIFT"
RECEIPT = "MOBILE_SDK_APPLE_DEVICE_DEMO_CONSUMPTION_RECEIPT"
pytestmark = pytest.mark.skipif(
    sys.platform != "darwin" or shutil.which("swift") is None,
    reason="requires the original macOS Swift manifest owner",
)


@pytest.fixture(scope="module")
def workspace():
    parent = ROOT / "target/qualification"
    parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="swift-device-consumption-", dir=parent) as directory:
        yield Path(directory)


def evaluate(workspace, settings):
    environment = {key: value for key, value in os.environ.items()
                   if not key.startswith("MOBILE_SDK_")}
    environment.update(settings)
    command = ["swift", "package", "--package-path", str(ROOT / "IrohaSwift")]
    for role in ("scratch", "cache", "config", "security"):
        command.extend([f"--{role}-path", str(workspace / role)])
    result = subprocess.run([*command, "dump-package"], env=environment,
                            cwd=ROOT, text=True, capture_output=True, timeout=90)
    assert result.returncode != 0, "empty fixtures must never admit a bridge"
    return result.stdout + result.stderr


@pytest.mark.parametrize("value", ("", "true", "2"))
def test_drift_flag_requires_exact_boolean(workspace, value):
    assert "must be exactly 0 or 1" in evaluate(workspace, {FLAG: value})


@pytest.mark.parametrize("settings", ({FLAG: "1"}, {RECEIPT: "/unused/receipt.json"}))
def test_drift_and_receipt_cannot_select_another_artifact_corridor(workspace, settings):
    assert "require the physical-device demo selector" in evaluate(workspace, settings)


def test_explicit_drift_requires_separate_receipt(workspace):
    assert "requires a separate physical-device demo consumption receipt" in evaluate(
        workspace, {SELECTOR: str(workspace), FLAG: "1"})


def test_drift_does_not_enter_release_corridor(workspace):
    assert "cannot enter an external/release or local-unit corridor" in evaluate(workspace, {
        SELECTOR: str(workspace), FLAG: "1", RECEIPT: str(workspace / "receipt.json"),
        "MOBILE_SDK_REQUIRE_EXTERNAL_APPLE_ARTIFACT": "1",
    })


def original_function(source, name):
    """Retain the complete original function between top-level declarations."""
    start = source.index(f"func {name}(")
    end = source.index("\n}\n", start) + len("\n}\n")
    return source[start:end]


@pytest.fixture(scope="module")
def receipt_helper(workspace):
    source = MANIFEST.read_text()
    test_source = workspace / "receipt-helper.swift"
    test_source.write_text(
        "import Foundation\nimport Darwin\n"
        f'let repositoryDirectory = URL(fileURLWithPath: {json.dumps(str(ROOT))})\n'
        "let deviceDemoConsumptionReceipt: String? = CommandLine.arguments[1] == \"-\" ? nil : CommandLine.arguments[1]\n"
        + original_function(source, "canonicalExistingFilesystemPath")
        + original_function(source, "deviceDemoSourceCommit")
        + original_function(source, "validateDeviceDemoConsumption")
        + "\nlet record = try JSONSerialization.jsonObject(with: Data(CommandLine.arguments[3].utf8)) as! [String: Any]\n"
        + "let result = validateDeviceDemoConsumption(record, outside: URL(fileURLWithPath: CommandLine.arguments[2]))\n"
        + "print(String(data: try JSONSerialization.data(withJSONObject: [\"error\": result as Any? ?? NSNull(), \"head\": deviceDemoSourceCommit() as Any? ?? NSNull()]), encoding: .utf8)!)\n"
    )
    binary = workspace / "receipt-helper"
    result = subprocess.run(["swiftc", str(test_source), "-o", str(binary)],
                            text=True, capture_output=True, timeout=90)
    assert result.returncode == 0, result.stderr
    return binary


def consume(helper, destination, artifact, record):
    result = subprocess.run([str(helper), str(destination), str(artifact), json.dumps(record)],
                            text=True, capture_output=True, timeout=30)
    assert result.returncode == 0, result.stderr
    return json.loads(result.stdout)


def test_receipt_is_separate_idempotent_and_never_relabels_original(receipt_helper, tmp_path):
    artifact = tmp_path / "original" / "NoritoBridge.xcframework"
    artifact.mkdir(parents=True)
    original = artifact / "original.txt"
    original.write_text("unchanged producer evidence")
    destination = tmp_path / "consumption.json"
    record = {"artifact_source_commit": "a" * 40, "current_source_commit": "b" * 40}
    destination.write_text(json.dumps(record))
    before_head = subprocess.check_output(["git", "-C", str(ROOT), "rev-parse", "HEAD"], text=True).strip()
    result = consume(receipt_helper, destination, artifact, record)
    assert result == {"error": None, "head": before_head}
    original_receipt = destination.read_bytes()
    assert json.loads(original_receipt) == record
    assert consume(receipt_helper, destination, artifact, record)["error"] is None
    changed = {**record, "current_source_commit": "c" * 40}
    assert "differs" in consume(receipt_helper, destination, artifact, changed)["error"]
    assert destination.read_bytes() == original_receipt
    assert original.read_text() == "unchanged producer evidence"


def test_receipt_refuses_artifact_paths_missing_parent_and_symlinks(receipt_helper, tmp_path):
    artifact = tmp_path / "original" / "NoritoBridge.xcframework"
    artifact.mkdir(parents=True)
    for destination in (artifact / "receipt.json", artifact.parent / "receipt.json",
                        tmp_path / "missing" / "receipt.json"):
        assert "canonical path outside" in consume(receipt_helper, destination, artifact, {})["error"]
        assert not destination.exists()
    retained = tmp_path / "retained.json"
    retained.write_text("retained")
    link = tmp_path / "linked.json"
    link.symlink_to(retained)
    assert "differs" in consume(receipt_helper, link, artifact, {})["error"]
    assert retained.read_text() == "retained"


def test_default_consumer_writes_no_receipt(receipt_helper, tmp_path):
    assert consume(receipt_helper, "-", tmp_path / "artifact", {})["error"] is None
    assert list(tmp_path.iterdir()) == []


def test_manifest_requires_prepared_receipt_and_never_writes_it(receipt_helper, tmp_path):
    destination = tmp_path / "missing.json"
    assert "requires a prepared receipt" in consume(
        receipt_helper, destination, tmp_path / "artifact" / "NoritoBridge.xcframework", {}
    )["error"]
    assert not destination.exists()
