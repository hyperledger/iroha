"""Adversarial coverage for mandatory SoraFS mobile JUnit evidence."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path

import pytest

from scripts import check_sorafs_mobile_parity_reports as checker

PASSING = (
    b'<testsuite tests="1" failures="0" errors="0" skipped="0">'
    b'<testcase classname="CanonicalNativeTest" name="runs" time="0.01"/>'
    b'</testsuite>'
)
ENCODED_REPORT = "__TEST-or-9Q1NPHA28VGNQ.hyperledger.EncodedSuite.xml"


def reports(root: Path, name: str = "TEST-canonical.xml") -> list[Path]:
    """Seed one genuinely shaped JUnit report per required task."""

    paths = []
    for module, task in checker.TASKS:
        path = root / module / "test-results" / task / name
        path.parent.mkdir(parents=True)
        path.write_bytes(PASSING)
        paths.append(path)
    return paths


def test_all_five_tasks_require_actual_execution_and_bind_report_bytes(tmp_path: Path) -> None:
    reports(tmp_path)
    result = checker.validate_reports(tmp_path)
    assert result["status"] == "verified"
    assert [row["task"] for row in result["tasks"]] == [
        f":{module}:{task}" for module, task in checker.TASKS
    ]
    assert all(row["executed"] == 1 and row["reports"] == 1 for row in result["tasks"])
    assert checker.validate_reports(tmp_path) == result


@pytest.mark.parametrize("alongside_standard", [False, True])
def test_encoded_gradle_reports_are_counted_and_bound_for_every_task(
    tmp_path: Path, alongside_standard: bool
) -> None:
    paths = reports(tmp_path)
    encoded = PASSING.replace(b"CanonicalNativeTest", b"EncodedNativeTest")
    for path in paths:
        if not alongside_standard:
            path.unlink()
        path.with_name(ENCODED_REPORT).write_bytes(encoded)
    result = checker.validate_reports(tmp_path)
    assert result["status"] == "verified"
    expected_hashes = [hashlib.sha256(encoded).hexdigest()]
    if alongside_standard:
        expected_hashes.insert(0, hashlib.sha256(PASSING).hexdigest())
    for row in result["tasks"]:
        assert row["executed"] == row["reports"] == 1 + int(alongside_standard)
        assert row["sha256"] == expected_hashes


@pytest.mark.parametrize("name", ["metadata.xml", "TEST-.xml", "__TEST-.xml"])
def test_unknown_xml_cannot_be_silently_ignored_or_counted(tmp_path: Path, name: str) -> None:
    paths = reports(tmp_path)
    paths[0].with_name(name).write_bytes(PASSING)
    with pytest.raises(ValueError, match="lacks complete passing"):
        checker.validate_reports(tmp_path)


def test_non_xml_metadata_is_not_test_execution(tmp_path: Path) -> None:
    paths = reports(tmp_path)
    directory = paths[0].parent
    (directory / "binary").mkdir()
    (directory / "binary" / "results.bin").write_bytes(PASSING)
    (directory / "TEST-canonical.xml.bak").write_bytes(PASSING)
    result = checker.validate_reports(tmp_path)
    assert result["tasks"][0]["executed"] == result["tasks"][0]["reports"] == 1
    paths[0].unlink()
    with pytest.raises(ValueError, match="lacks complete passing"):
        checker.validate_reports(tmp_path)


@pytest.mark.parametrize("index", range(5))
def test_manifest_or_other_tasks_cannot_substitute_for_a_missing_report(
    tmp_path: Path, index: int
) -> None:
    paths = reports(tmp_path)
    paths[index].unlink()
    (tmp_path / "native-sdk-abi29.json").write_text('{"status":"verified"}')
    with pytest.raises(ValueError, match="lacks complete passing"):
        checker.validate_reports(tmp_path)


@pytest.mark.parametrize("name", ["TEST-canonical.xml", ENCODED_REPORT])
@pytest.mark.parametrize(
    "payload",
    [
        PASSING.replace(b'tests="1"', b'tests="0"'),
        PASSING.replace(b'tests="1"', b'tests="01"'),
        PASSING.replace(b'tests="1"', b'tests="-1"'),
        PASSING.replace(b'failures="0"', b'failures="1"'),
        PASSING.replace(b'errors="0"', b'errors="1"'),
        PASSING.replace(b'skipped="0"', b'skipped="1"'),
        PASSING.replace(b'/></testsuite>', b'><failure/></testcase></testsuite>'),
        PASSING.replace(b'/></testsuite>', b'><error/></testcase></testsuite>'),
        PASSING.replace(b'/></testsuite>', b'><skipped/></testcase></testsuite>'),
        b'<testsuite tests="0" failures="0" errors="0" skipped="0"/>',
        b'<testsuites>' + PASSING + b'</testsuites>',
        PASSING[:-1],
        b'<!DOCTYPE testsuite [<!ENTITY secret SYSTEM "file:///private/secret">]>' + PASSING,
        ('<!DOCTYPE testsuite><testsuite tests="0"/>').encode("utf-16"),
        PASSING.replace(b'<testcase', b'<nested><testcase').replace(
            b'</testsuite>', b'</nested></testsuite>'
        ),
    ],
)
def test_rejects_nonpassing_forged_empty_malformed_or_entity_reports(
    tmp_path: Path, payload: bytes, name: str
) -> None:
    paths = reports(tmp_path, name=name)
    paths[0].write_bytes(payload)
    with pytest.raises(ValueError, match="lacks complete passing"):
        checker.validate_reports(tmp_path)


@pytest.mark.parametrize(
    "payload",
    [
        PASSING.replace(b'failures="0"', b'failures="1"'),
        PASSING.replace(b'errors="0"', b'errors="1"'),
        PASSING.replace(b'skipped="0"', b'skipped="1"'),
        PASSING[:-1],
    ],
)
def test_passing_standard_report_cannot_hide_nonpassing_encoded_report(
    tmp_path: Path, payload: bytes
) -> None:
    paths = reports(tmp_path)
    paths[0].with_name(ENCODED_REPORT).write_bytes(payload)
    with pytest.raises(ValueError, match="lacks complete passing"):
        checker.validate_reports(tmp_path)


@pytest.mark.parametrize("name", ["TEST-canonical.xml", ENCODED_REPORT])
@pytest.mark.parametrize("kind", ["symlink", "hardlink", "parent_symlink"])
def test_rejects_linked_reports(tmp_path: Path, kind: str, name: str) -> None:
    paths = reports(tmp_path)
    path = paths[0].with_name(name)
    path.write_bytes(PASSING)
    if kind == "parent_symlink":
        moved = path.parent.with_name("moved")
        path.parent.rename(moved)
        path.parent.symlink_to(moved, target_is_directory=True)
    else:
        source = tmp_path / "outside.xml"
        path.rename(source)
        if kind == "symlink":
            path.symlink_to(source)
        else:
            os.link(source, path)
    with pytest.raises(ValueError, match="lacks complete passing"):
        checker.validate_reports(tmp_path)


def test_report_age_never_hides_a_failed_encoded_suite(tmp_path: Path) -> None:
    paths = reports(tmp_path)
    encoded = paths[0].with_name(ENCODED_REPORT)
    encoded.write_bytes(PASSING.replace(b'failures="0"', b'failures="1"'))
    os.utime(encoded, (1, 1))
    # Fresh-tree custody belongs to the caller; a timestamp is no filtering authority.
    with pytest.raises(ValueError, match="lacks complete passing"):
        checker.validate_reports(tmp_path)


@pytest.mark.parametrize("name", ["TEST-canonical.xml", ENCODED_REPORT])
@pytest.mark.parametrize(
    "limit,value", [("MAX_REPORT_BYTES", 8), ("MAX_TOTAL_BYTES", 200),
                    ("MAX_DIRECTORY_ENTRIES", 0), ("MAX_XML_ELEMENTS", 1),
                    ("MAX_XML_DEPTH", 1)]
)
def test_report_resources_are_bounded(
    tmp_path: Path, monkeypatch, limit: str, value: int, name: str
) -> None:
    reports(tmp_path, name=name)
    monkeypatch.setattr(checker, limit, value)
    with pytest.raises(ValueError, match="lacks complete passing"):
        checker.validate_reports(tmp_path)


@pytest.mark.parametrize("name", ["TEST-canonical.xml", ENCODED_REPORT])
def test_directory_replacement_during_read_is_rejected(tmp_path: Path, monkeypatch, name: str) -> None:
    paths = reports(tmp_path, name=name)
    original = checker.read_evidence_bytes

    def replace_after_read(path: Path, maximum: int) -> bytes:
        raw = original(path, maximum)
        path.parent.rename(path.parent.with_name("detached"))
        path.parent.mkdir()
        path.write_bytes(raw)
        return raw

    monkeypatch.setattr(checker, "read_evidence_bytes", replace_after_read)
    with pytest.raises(ValueError, match="lacks complete passing"):
        checker.validate_reports(tmp_path)
    assert paths[0].exists()


def test_cli_is_payload_free_on_success_and_failure(tmp_path: Path, capsys) -> None:
    paths = reports(tmp_path)
    assert checker.main(["--report-root", str(tmp_path)]) == 0
    assert json.loads(capsys.readouterr().out)["status"] == "verified"
    paths[0].write_bytes(b'<private-secret-value>')
    assert checker.main(["--report-root", str(tmp_path)]) == 1
    output = capsys.readouterr().out
    assert json.loads(output)["status"] == "blocked"
    assert "private-secret-value" not in output
    assert str(tmp_path) not in output
    with pytest.raises(ValueError, match="absolute canonical"):
        checker.validate_reports(Path("relative"))
