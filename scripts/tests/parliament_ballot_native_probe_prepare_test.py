"""Derived native probe sources and lock identities remain explicit and fail closed."""
import importlib.util
import json
from pathlib import Path
import sys
from unittest.mock import patch
import pytest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import prepare_parliament_ballot_native_probe as prepare


def test_exact_marker_derivation_and_anchor_drift():
    source=(prepare.ROOT/prepare.RESOURCE/'workspace.rs').read_text()
    result=prepare.derive_workspace(source,Path('/tmp/control.rs'))
    assert result.count('crate::observer::begin();')==1
    assert result.count('crate::observer::end();')==1
    assert result.count('crate::observer::terminal();')==1
    assert 'crate::observer::begin();\n    ACTIVE.store(true' in result
    with pytest.raises(ValueError,match='anchor'):
        prepare.derive_workspace(source.replace('ACTIVE.store(true','ACTIVE.store(false'),Path('/tmp/control.rs'))


def test_prepare_keeps_original_sources_and_copies_all_patches(tmp_path):
    path=tmp_path/'probe'
    original=prepare.digest(prepare.ROOT/'Cargo.lock')
    report=prepare.prepare(path)
    assert prepare.digest(prepare.ROOT/'Cargo.lock')==original
    assert report['frozen_sources_unchanged'] and not report['profile_qualified']
    import tomllib
    derived=tomllib.loads((path/'Cargo.toml').read_text())
    root=tomllib.loads((prepare.ROOT/'Cargo.toml').read_text())
    for name,entry in root['patch']['crates-io'].items():
        assert derived['patch']['crates-io'][name]['path']==str((prepare.ROOT/entry['path']).resolve())
    assert 'crate::observer::terminal();' in (path/'generated_workspace.rs').read_text()
    with pytest.raises(ValueError,match='new directory'):prepare.prepare(path)


def test_lock_membership_rejects_new_version_or_package(tmp_path):
    reference=tmp_path/'old.lock';new=tmp_path/'new.lock'
    old='[[package]]\nname="x"\nversion="1.0.0"\nsource="registry+https://example.invalid"\nchecksum="abc"\n'
    probe='\n[[package]]\nname="parliament-native-probe"\nversion="0.0.0"\n'
    reference.write_text(old);new.write_text(old+probe)
    report=prepare.compare_locks(reference,new)
    assert report['diagnostic_packages']==2 and not report['unexpected_dependency_identities']
    assert 'not dependency-edge' in report['comparison_scope']
    new.write_text(old.replace('1.0.0','2.0.0')+probe)
    with pytest.raises(ValueError,match='drift'):prepare.compare_locks(reference,new)
    new.write_text(old)
    with pytest.raises(ValueError,match='missing'):prepare.compare_locks(reference,new)


def test_main_reports_failure_instead_of_preparing_over_existing_output(tmp_path,capsys):
    with patch.object(sys,'argv',['prepare','--output',str(tmp_path)]):assert prepare.main()==1
    assert json.loads(capsys.readouterr().out)['profile_qualified'] is False
