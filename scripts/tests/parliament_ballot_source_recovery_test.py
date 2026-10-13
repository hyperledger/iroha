"""Fault controls for the frozen historical-source recovery recipe.

Synthetic inputs exercise refusal and drift handling. They neither recover new
historical content nor qualify the current checkout or the retained binaries.
"""
import hashlib
import importlib.machinery
import importlib.util
import json
from pathlib import Path
import sys

import pytest


RECIPE = Path(__file__).resolve().parents[2] / "docs/validation/parliament_ballot_b6/recover-adapter-sources.py.template"
REPORT_SHA = "90b67fba04a4c7f1c73ed067eb4a8c8d5478707e05f4b4d51ddc27235da7a471"


@pytest.fixture
def recipe():
    loader = importlib.machinery.SourceFileLoader("source_recovery_controls", str(RECIPE))
    spec = importlib.util.spec_from_loader(loader.name, loader)
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    return module


@pytest.fixture
def fixture(recipe, tmp_path, monkeypatch):
    """Create a synthetic report; only its fixed report hash is substituted."""
    root, output = tmp_path / "root", tmp_path / "new-output"
    root.mkdir()
    expected, git_bytes = {}, {}
    for relative, revision in recipe.REVISIONS.items():
        original = root / relative
        original.parent.mkdir(parents=True, exist_ok=True)
        original.write_bytes(b"later live source")
        value = ("historical:" + relative).encode()
        expected[str(original)] = hashlib.sha256(value).hexdigest()
        git_bytes[revision + ":" + relative] = value
    sentinel = root / "unchanged-input"
    sentinel.write_bytes(b"retained input")
    expected[str(sentinel)] = recipe.sha(sentinel)
    report = root / "docs/validation/parliament_ballot_adapter_bound/report.json"
    report.parent.mkdir(parents=True)
    report.write_text(json.dumps({"input_changes": {}, "verdict": "PASS_UNDER_STATED_PREMISES", "input_sha256": expected}))
    raw_sha = recipe.sha

    def guarded_sha(path):
        return REPORT_SHA if Path(path) == report else raw_sha(path)

    commands = []

    def git(command, *, cwd):
        assert command[:2] == ["git", "show"] and cwd == root
        commands.append(command)
        return git_bytes[command[2]]

    monkeypatch.setattr(recipe, "sha", guarded_sha)
    monkeypatch.setattr(recipe.subprocess, "check_output", git)
    monkeypatch.setattr(sys, "argv", [str(RECIPE), "--root", str(root), "--output", str(output)])
    return root, output, sentinel, report, git_bytes, commands, guarded_sha


def test_sha_exact_bytes_and_missing(recipe, tmp_path):
    path = tmp_path / "input"
    path.write_bytes(b"abc")
    assert recipe.sha(path) == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    path.unlink()
    with pytest.raises(FileNotFoundError):
        recipe.sha(path)


def test_success_preserves_live_sources_and_records_each_git_identity(recipe, fixture):
    root, out, sentinel, report, git_bytes, commands, _ = fixture
    before = {p: p.read_bytes() for p in root.rglob("*") if p.is_file()}
    assert recipe.main() == 0
    result = json.loads((out / "receipt.json").read_text())
    assert result["historical_source_identities_resolved"] is True
    assert len(result["resolved_inputs"]) == 5 and len(commands) == 4
    assert set(result["current_source_changes"]) == {str(root / p) for p in recipe.REVISIONS}
    assert result["resolution_failures"] == result["during_resolution_changes"] == {}
    assert result["pins_refreshed"] is result["profile_qualified"] is False
    assert before == {p: p.read_bytes() for p in root.rglob("*") if p.is_file()}
    assert (out / "executed-recipe.py.template").read_bytes() == RECIPE.read_bytes()
    for original, recovered in result["recovered"].items():
        assert Path(recovered["path"]).read_bytes() == git_bytes[recovered["command"][2]]


def test_existing_output_refused_before_git(recipe, fixture):
    _, out, _, _, _, commands, _ = fixture
    out.mkdir()
    with pytest.raises(FileExistsError):
        recipe.main()
    assert not commands and not list(out.iterdir())


def test_bad_report_identity_refused_before_git(recipe, fixture, monkeypatch):
    _, out, _, report, _, commands, sha = fixture
    monkeypatch.setattr(recipe, "sha", lambda p: "0" * 64 if Path(p) == report else sha(p))
    with pytest.raises(RuntimeError, match="report identity changed"):
        recipe.main()
    assert not commands and not (out / "receipt.json").exists()


@pytest.mark.parametrize("field,value", [("input_changes", {"changed": True}), ("verdict", "UNKNOWN")])
def test_unstable_historical_capture_refused(recipe, fixture, field, value):
    _, out, _, report, _, commands, _ = fixture
    data = json.loads(report.read_text())
    data[field] = value
    report.write_text(json.dumps(data))
    with pytest.raises(RuntimeError, match="stable inputs"):
        recipe.main()
    assert not commands and not (out / "receipt.json").exists()


def test_git_byte_mismatch_refused(recipe, fixture):
    root, out, _, _, git_bytes, _, _ = fixture
    git_bytes[next(iter(git_bytes))] = b"wrong Git revision content"
    with pytest.raises(RuntimeError, match="Git source does not match"):
        recipe.main()
    assert not (out / "receipt.json").exists()
    assert all((root / p).read_bytes() == b"later live source" for p in recipe.REVISIONS)


@pytest.mark.parametrize("missing", [False, True])
def test_initial_missing_or_mutated_input_cannot_resolve(recipe, fixture, missing):
    _, out, sentinel, _, _, _, _ = fixture
    sentinel.unlink() if missing else sentinel.write_bytes(b"new source")
    assert recipe.main() == 1
    result = json.loads((out / "receipt.json").read_text())
    assert set(result["resolution_failures"]) == {str(sentinel)}
    assert result["historical_source_identities_resolved"] is False


@pytest.mark.parametrize("missing", [False, True])
def test_second_pass_missing_or_mutated_input_cannot_resolve(recipe, fixture, monkeypatch, missing):
    _, out, sentinel, _, _, _, sha = fixture
    seen = False

    def change_after_first_read(path):
        nonlocal seen
        value = sha(path)
        if Path(path) == sentinel and not seen:
            seen = True
            sentinel.unlink() if missing else sentinel.write_bytes(b"changed between passes")
        return value

    monkeypatch.setattr(recipe, "sha", change_after_first_read)
    assert recipe.main() == 1
    result = json.loads((out / "receipt.json").read_text())
    assert result["resolution_failures"] == {}
    assert set(result["during_resolution_changes"]) == {str(sentinel)}
    assert result["historical_source_identities_resolved"] is False


def test_recipe_identity_change_cannot_resolve(recipe, fixture, monkeypatch):
    _, out, _, _, _, _, sha = fixture
    reads = 0

    def changed_recipe_hash(path):
        nonlocal reads
        if Path(path) == RECIPE:
            reads += 1
            if reads > 1:
                return "1" * 64
        return sha(path)

    monkeypatch.setattr(recipe, "sha", changed_recipe_hash)
    assert recipe.main() == 1
    result = json.loads((out / "receipt.json").read_text())
    assert set(result["during_resolution_changes"]) == {str(RECIPE)}
    assert result["historical_source_identities_resolved"] is False
