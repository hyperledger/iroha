"""Allocation diagnostics preserve frozen sources and explicit build derivation."""
import json
from pathlib import Path
import sys
import tomllib
from unittest.mock import patch

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import prepare_parliament_ballot_allocation_trace as prepare


def test_derivation_exact_anchors_and_no_original_edit():
    path = prepare.ROOT / prepare.RESOURCE / "workspace.rs"
    before = prepare.digest(path)
    source = path.read_text()
    derived = prepare.derive_workspace(source, Path("/tmp/controls.rs"))
    for name in ("record_alloc", "record_free", "set_base", "begin", "end", "read_record"):
        assert derived.count(f"crate::trace::{name}(") == 1
    assert "    ACTIVE.store(true" in derived
    assert "file.read_exact" not in derived
    assert prepare.digest(path) == before
    with pytest.raises(ValueError, match="anchor"):
        prepare.derive_workspace(source.replace("ACTIVE.store(true", "ACTIVE.store(false"), Path("/tmp/x"))


def test_manifest_retains_root_overrides_and_acceleration():
    result = tomllib.loads(prepare.manifest(prepare.ROOT))
    original = tomllib.loads((prepare.ROOT / "Cargo.toml").read_text())
    assert result["features"]["accel"] == ["iroha_parliament_ballot_proof/accel"]
    assert result["dependencies"]["norito"]["default-features"] is False
    assert result["dependencies"]["iroha_parliament_ballot_proof"]["features"] == ["diagnostics"]
    assert result["workspace"] == {}
    for name, entry in original["patch"]["crates-io"].items():
        assert result["patch"]["crates-io"][name]["path"] == str((prepare.ROOT / entry["path"]).resolve())


def test_preparation_new_directory_and_source_scope(tmp_path):
    target = tmp_path / "prepared"
    before = prepare.digest(prepare.ROOT / "Cargo.lock")
    result = prepare.prepare(target)
    assert not result["source_changes"] and not result["profile_qualified"]
    assert prepare.digest(prepare.ROOT / "Cargo.lock") == before
    assert (target / "workspace.diff").is_file()
    assert f"{prepare.RESOURCE}/workspace.rs" in result["source_files"]
    assert json.loads((target / "preparation.json").read_text()) == result
    with pytest.raises(ValueError, match="new directory"):
        prepare.prepare(target)


def test_lock_identity_membership_not_edges(tmp_path):
    old = tmp_path / "old.lock"; new = tmp_path / "new.lock"
    body = '[[package]]\nname="x"\nversion="1.0.0"\nsource="registry+https://invalid.example"\nchecksum="abc"\n'
    extra = f'\n[[package]]\nname="{prepare.PACKAGE}"\nversion="0.0.0"\n'
    old.write_text(body); new.write_text(body + extra)
    report = prepare.compare_locks(old, new)
    assert report["diagnostic_packages"] == 2
    assert "not dependency-edge" in report["comparison_scope"]
    for wrong in (body, (body + extra).replace('checksum="abc"', 'checksum="def"'),
                  (body + extra).replace('version="0.0.0"', 'version="0.1.0"')):
        new.write_text(wrong)
        with pytest.raises(ValueError, match="identity drift"):
            prepare.compare_locks(old, new)


def test_cli_refuses_existing_target(tmp_path, capsys):
    with patch.object(sys, "argv", ["prepare", "--output", str(tmp_path)]):
        assert prepare.main() == 1
        assert json.loads(capsys.readouterr().out)["profile_qualified"] is False
