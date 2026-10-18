"""Evidence-copy and test-inventory controls; synthetic files confer no native authority."""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import shutil
from pathlib import Path
import xml.etree.ElementTree as ET

import pytest

DRAFT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("guard_evidence", DRAFT / "ci/python_native_guard_evidence.py")
OWNER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(OWNER)


def xml(names=None, *, skip=False):
    root = ET.Element("testsuites")
    suite = ET.SubElement(root, "testsuite")
    for name in sorted(OWNER.EXPECTED if names is None else names):
        case = ET.SubElement(suite, "testcase", classname="test.InstalledConfidentialWalletTests", name=name)
        if skip:
            ET.SubElement(case, "skipped")
    return ET.tostring(root)


def seal(path):
    row = path.stat()
    return ":".join(map(str, (hashlib.sha256(path.read_bytes()).hexdigest(), row.st_dev, row.st_ino,
                              row.st_size, row.st_mtime_ns, row.st_ctime_ns))) + ":" + oct(row.st_mode & 0o7777)


@pytest.fixture
def arguments(tmp_path):
    root = tmp_path / "root"
    for name in ("target/qualification", "ci", "python/iroha_python/tests"):
        (root / name).mkdir(parents=True, mode=0o700, exist_ok=True)
    private = root / "target/qualification/private"
    venv = private / "venv"
    venv.mkdir(parents=True, mode=0o700)
    native = venv / "native.so"
    native.write_bytes(b"synthetic file-copy fixture, not an extension")
    wheel = private / "native.whl"; wheel.write_bytes(b"synthetic wheel control")
    sdk = private / "sdk.whl"; sdk.write_bytes(b"synthetic SDK control")
    manifest = private / "abi.json"
    source_pin = {"head_commit": "fixture", "workspace_source_manifest_sha256": "source-fixture"}
    manifest.write_text(json.dumps({"sdk": "python", "artifact_sha256": hashlib.sha256(native.read_bytes()).hexdigest(), "source_commit": "fixture", "workspace_source_manifest_sha256": "source-fixture"}))
    tests = private / "tests.xml"; tests.write_bytes(xml())
    audit = private / "invocations"; audit.write_bytes(b"synthetic command audit")
    (root / OWNER.TEST_SOURCE).write_text("# synthetic inventory fixture\n")
    (root / "ci/check_privacy_python_sdk.sh").write_text("# synthetic guard fixture\n")
    return argparse.Namespace(root=root, output=root / "target/qualification/receipt", private_dir=private,
                              venv=venv, native=native, native_wheel=wheel, sdk_wheel=sdk,
                              native_wheel_seal=seal(wheel), sdk_wheel_seal=seal(sdk), manifest=manifest,
                              tests=tests, cargo_audit=audit, source_pin=json.dumps(source_pin), test_exit=0)


def test_exact_five_inventory_and_bytes_survive_private_cleanup(arguments):
    record = OWNER.retain(arguments)
    assert record["passed"] and record["guard_cleanup_exit_not_observed"]
    assert record["tests"]["native_cases"] == dict.fromkeys(OWNER.EXPECTED, 1)
    with pytest.raises(FileExistsError):
        OWNER.retain(arguments)
    shutil.rmtree(arguments.private_dir)
    for item in record["files"].values():
        retained = arguments.output / item["file"]
        assert hashlib.sha256(retained.read_bytes()).hexdigest() == item["sha256"]
        assert retained.stat().st_mode & 0o777 == 0o400


@pytest.mark.parametrize("mutation", ["missing", "duplicate", "skip", "exit", "unrelated"])
def test_incomplete_or_failed_native_inventory_is_never_passing(arguments, mutation):
    names = list(OWNER.EXPECTED)
    if mutation == "missing": names.pop()
    if mutation == "duplicate": names.append(names[0])
    if mutation == "unrelated": names = ["unrelated"] * 5
    arguments.tests.write_bytes(xml(names, skip=mutation == "skip"))
    if mutation == "exit": arguments.test_exit = 1
    assert OWNER.retain(arguments)["passed"] is False
    assert (arguments.output / "receipt.json").exists()


@pytest.mark.parametrize("mutation", ["changed-wheel", "wrong-manifest", "native-outside", "cleanup-child", "outside-output", "symlink-input"])
def test_foreign_or_changed_originals_refuse_without_passing_receipt(arguments, mutation):
    if mutation == "changed-wheel": arguments.native_wheel.write_bytes(b"substitute")
    elif mutation == "wrong-manifest": arguments.manifest.write_text('{"sdk":"python","artifact_sha256":"foreign"}')
    elif mutation == "native-outside": arguments.native = arguments.native_wheel
    elif mutation == "cleanup-child": arguments.output = arguments.private_dir / "deleted-with-cleanup"
    elif mutation == "outside-output": arguments.output = arguments.root / "outside"
    else:
        link = arguments.private_dir / "link.xml"
        link.symlink_to(arguments.tests)
        arguments.tests = link
    with pytest.raises(ValueError): OWNER.retain(arguments)
    assert not (arguments.output / "receipt.json").exists()


def test_same_inode_mutation_during_copy_refuses(tmp_path, monkeypatch):
    source = tmp_path / "source"
    source.write_bytes(b"original")
    original_sync = OWNER.os.fsync
    def modify(descriptor):
        source.write_bytes(b"replaced")
        original_sync(descriptor)
    monkeypatch.setattr(OWNER.os, "fsync", modify)
    with pytest.raises(ValueError, match="changed during copy"):
        OWNER.copy_original(source, tmp_path / "copy", 1024)


@pytest.mark.parametrize("raw", [b'<!DOCTYPE x><testsuites/>', b'<!ENTITY x "a"><testsuites/>'])
def test_xml_entity_controls_refuse(raw):
    with pytest.raises(ValueError): OWNER.inspect_tests(raw, 0)


def test_guard_keeps_clean_source_and_places_original_tests_before_final_verification():
    text = (DRAFT / "ci/check_privacy_python_sdk.sh").read_text()
    tests = text.index('tests/confidential_wallet_native_test.py')
    final_verify = text.rindex('"${ABI30_CHECKER}" verify')
    retain = text.index('"${SCRIPT_DIR}/python_native_guard_evidence.py"')
    assert tests < final_verify < retain
    assert '"${SCRIPT_DIR}/python_native_source_delivery.py" pin --root "${ROOT_DIR}"' in text
    assert '|| PYTEST_STATUS=$?' in text and text.rstrip().endswith('exit "${PYTEST_STATUS}"')
