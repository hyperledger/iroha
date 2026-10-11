"""Local native hash projection controls for the fixed canonical Kura namespace."""
from __future__ import annotations

import importlib.util
from pathlib import Path
import subprocess
import shutil

import pytest

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location("taira_kura_storage_guest", ROOT / "scripts/taira_update_guest.py")
guest = importlib.util.module_from_spec(spec)
spec.loader.exec_module(guest)


@pytest.fixture
def journals(tmp_path, monkeypatch):
    monkeypatch.setattr(guest, "STATE_ROOT", tmp_path, raising=False)
    monkeypatch.setattr(guest, "ROLES", ("validator",), raising=False)
    monkeypatch.setattr(guest, "KURA_HASH_JOURNAL",
                        "storage/kura/blocks/canonical/blocks.hashes", raising=False)
    # These disposable files belong to the test user. Deployment owner/mode
    # authorization remains separately enforced by the unmodified guest stamp.
    def local_stamp(path, directory=False):
        info = Path(path).lstat()
        return [info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid,
                info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns]
    monkeypatch.setattr(guest, "stamp", local_stamp)
    native_popen = subprocess.Popen
    def portable_popen(args, **kwargs):
        # BSD dd lacks GNU's status=none; stderr is already discarded here.
        portable = [arg for arg in args if arg != "status=none"]
        portable[0] = shutil.which(Path(portable[0]).name) or portable[0]
        return native_popen(portable, **kwargs)
    monkeypatch.setattr(guest.subprocess, "Popen", portable_popen)
    canonical = tmp_path / "validator/storage/kura/blocks/canonical/blocks.hashes"
    alias = tmp_path / "validator/storage/kura/blocks/lane_000_core/blocks.hashes"
    for path in (canonical, alias):
        path.parent.mkdir(parents=True)
    alias.write_bytes(bytes([0xFF]) * 32)
    return canonical


def test_tip_and_retained_hash_read_the_same_canonical_chain(journals):
    first, second = bytes([0x11]) * 32, bytes([0x22]) * 32
    journals.write_bytes(first + second)
    assert guest.native_kura_tip("validator") == {"height": 2, "hash": second.hex()}
    assert guest.native_kura_hash("validator", 1) == first.hex()
    assert guest.native_kura_hash("validator", 2) == second.hex()


def test_missing_canonical_chain_never_falls_back_to_lane_alias(journals):
    with pytest.raises(FileNotFoundError):
        guest.native_kura_tip("validator")
    with pytest.raises(FileNotFoundError):
        guest.native_kura_hash("validator", 1)


def test_truncated_canonical_hash_journal_is_rejected(journals):
    journals.write_bytes(bytes(31))
    with pytest.raises(RuntimeError, match="hash journal size differs"):
        guest.native_kura_tip("validator")
    with pytest.raises(RuntimeError, match="retained Kura height is missing"):
        guest.native_kura_hash("validator", 1)
