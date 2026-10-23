"""Offline regressions for independently pinned ACVP fixture provenance."""

from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path
from runpy import run_path

import pytest


CHECKER = run_path(str(Path(__file__).resolve().parents[1] / "check_soranet_pq_acvp.py"))


def test_offline_check_accepts_the_pinned_fixture(capsys):
    assert CHECKER["main"]([]) == 0
    assert "50 cases, 24 groups" in capsys.readouterr().out


def test_fixture_pin_rejects_a_changed_expected_output():
    raw = CHECKER["FIXTURE"].read_bytes()
    data = json.loads(raw)
    case = data["vector_sets"][0]["testGroups"][0]["tests"][0]
    case["ek"] = ("0" if case["ek"][0] != "0" else "1") + case["ek"][1:]
    with pytest.raises(ValueError, match="subset SHA-256 mismatch"):
        CHECKER["check_fixture"]((json.dumps(data, indent=2) + "\n").encode())


def test_projection_preserves_original_metadata_and_negative_disposition():
    document = {
        "algorithm": "test",
        "testGroups": [
            {"tgId": 7, "parameterSet": "test", "tests": [
                {"tcId": 1, "testPassed": True, "signature": "01"},
                {"tcId": 2, "testPassed": False, "reason": "modified hint", "signature": "02"},
            ]},
            {"tgId": 8, "tests": [{"tcId": 3}]},
        ],
    }
    before = copy.deepcopy(document)
    projected = CHECKER["project"](document, {7: [2]})
    assert document == before
    assert projected == {
        "algorithm": "test",
        "testGroups": [{"tgId": 7, "parameterSet": "test", "tests": [
            {"tcId": 2, "testPassed": False, "reason": "modified hint", "signature": "02"},
        ]}],
    }


@pytest.mark.parametrize("groups", [
    [],
    [{"tgId": 7, "tests": []}],
    [{"tgId": 7, "tests": [{"tcId": 2}, {"tcId": 2}]}],
    [{"tgId": 7, "tests": [{"tcId": 2}]}] * 2,
])
def test_projection_rejects_missing_or_duplicate_selected_objects(groups):
    with pytest.raises(ValueError, match="missing, duplicate or reordered"):
        CHECKER["project"]({"testGroups": groups}, {7: [2]})


def test_extract_authenticates_every_source_before_accepting_projection():
    with pytest.raises(ValueError, match="exactly the five"):
        CHECKER["extract"]({})
    sources = dict.fromkeys(CHECKER["SOURCE_SHA256"], b"{}")
    with pytest.raises(ValueError, match="upstream SHA-256 mismatch"):
        CHECKER["extract"](sources)


def test_download_verifies_bytes_before_writing_cache(tmp_path, monkeypatch):
    class BadResponse:
        def __enter__(self):
            return self

        def __exit__(self, *_):
            return False

        def read(self):
            return b"{}"

    requests = []

    def open_url(url, timeout):
        requests.append((url, timeout))
        return BadResponse()

    monkeypatch.setattr(CHECKER["urllib"].request, "urlopen", open_url)
    with pytest.raises(ValueError, match="downloaded SHA-256 mismatch"):
        CHECKER["load_sources"](tmp_path, True)
    assert len(requests) == 1
    assert f"/{CHECKER['REVISION']}/gen-val/json-files/" in requests[0][0]
    assert list(tmp_path.iterdir()) == []


@pytest.mark.parametrize("flag", ["--download", "--write"])
def test_network_or_fixture_writes_require_explicit_source_directory(flag):
    with pytest.raises(SystemExit) as error:
        CHECKER["main"]([flag])
    assert error.value.code == 2


def test_fixture_has_explicit_source_pins_and_exact_selected_cases():
    data = json.loads(CHECKER["FIXTURE"].read_bytes())
    assert data["upstream_revision"] == CHECKER["REVISION"]
    assert [v["source"] for v in data["vector_sets"]] == list(CHECKER["SOURCE_SHA256"])
    for vector_set in data["vector_sets"]:
        name = vector_set["source"]
        assert vector_set["source_sha256"] == CHECKER["SOURCE_SHA256"][name]
        selection = {
            group["tgId"]: [case["tcId"] for case in group["tests"]]
            for group in vector_set["testGroups"]
        }
        assert selection == CHECKER["SELECTED_CASES"][name]
    assert hashlib.sha256(CHECKER["FIXTURE"].read_bytes()).hexdigest() == CHECKER["FIXTURE_SHA256"]
