"""Exact public vendor-role admission; public synthetic originals, no Cargo or private material."""
from __future__ import annotations

import hashlib
import importlib.util
from pathlib import Path
from unittest import mock

import pytest

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("norito_reviewed_vendor", ROOT / "scripts/norito_bridge_source_seal.py")
assert SPEC is not None and SPEC.loader is not None
seal = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(seal)

REVIEWED_VENDOR_FILES = (
    "vendor/concread/.codespell_ignore",
    "vendor/concread/Cargo.toml.orig",
    "vendor/wayland-scanner-0.31.10/Cargo.toml.orig",
    "vendor/bytes/Cargo.toml.orig",
    "vendor/http-body-util/Cargo.toml.orig",
    "vendor/axum-core/Cargo.toml.orig",
)
ROLE_EXAMPLES = REVIEWED_VENDOR_FILES


def public_original(relative: str) -> bytes:
    if relative.endswith("Cargo.toml.orig"):
        return b'[package]\nname = "public-synthetic-source"\nversion = "0.0.0"\n'
    if relative.endswith(".codespell_ignore"):
        return b"crate\nser\n"
    # Public patterned bytes exercise binary preservation; these are not curve
    # attestations or key material and confer no cryptographic qualification.
    return bytes(range(256)) * 3 + b"PUBLIC SYNTHETIC VECTOR\x00\xff\n"


def write_public(root: Path, relative: str) -> bytes:
    source = root / relative
    source.parent.mkdir(parents=True, exist_ok=True)
    original = public_original(relative)
    source.write_bytes(original)
    return original


def test_reviewed_vendor_inventory_is_exactly_the_established_roles() -> None:
    assert seal._REVIEWED_PUBLIC_VENDOR_INPUTS == frozenset(REVIEWED_VENDOR_FILES)
    assert len(seal._REVIEWED_PUBLIC_VENDOR_INPUTS) == 6


@pytest.mark.parametrize("relative", [
    "vendor/bytes/Cargo.toml.orig",
    "vendor/http-body-util/Cargo.toml.orig",
    "vendor/axum-core/Cargo.toml.orig",
])
def test_actual_patched_manifest_remains_an_exact_public_source_input(relative: str) -> None:
    original = (ROOT / relative).read_bytes()
    assert original.startswith(b"[package]\n")
    assert seal._read_public_source_bytes(ROOT, relative) == original


@pytest.mark.parametrize("relative", REVIEWED_VENDOR_FILES)
def test_each_reviewed_vendor_original_is_read_without_byte_changes(tmp_path: Path, relative: str) -> None:
    root = tmp_path.resolve()
    original = write_public(root, relative)
    assert seal._read_public_source_bytes(root, relative) == original


def test_actual_listed_file_admission_keeps_every_reviewed_vendor_input(tmp_path: Path) -> None:
    root = tmp_path.resolve()
    for relative in REVIEWED_VENDOR_FILES:
        write_public(root, relative)
    lock = root / "Cargo.lock"
    lock.write_bytes(b"public synthetic lock original\n")
    filename_inventory = b"\0".join(name.encode() for name in REVIEWED_VENDOR_FILES) + b"\0"
    # Only the filename-only Git boundary is mocked; real lexical/ancestor/file
    # admission runs for all six. No repository script, Cargo or Git is invoked.
    with mock.patch.object(seal, "source_seal_tools", return_value=(None, None, None, None)), \
            mock.patch.object(seal, "source_seal_environment", return_value={}), \
            mock.patch.object(seal, "run", return_value=filename_inventory):
        assert seal.listed_files(root, ["vendor"], lock) == sorted(REVIEWED_VENDOR_FILES)


def test_reviewed_vendor_fingerprint_preserves_names_original_bytes_and_lock_domain(tmp_path: Path) -> None:
    root = tmp_path.resolve()
    originals = {relative: write_public(root, relative) for relative in REVIEWED_VENDOR_FILES}
    lock = root / "Cargo.lock"
    lock_original = b"public synthetic lock original\n"
    lock.write_bytes(lock_original)

    def manual_original_fingerprint() -> str:
        digest = hashlib.sha256()
        for relative in sorted(originals):
            digest.update(relative.encode() + b"\0" + originals[relative] + b"\0")
        digest.update(b"\0selected-cargo-lock-sha256\0")
        digest.update(hashlib.sha256(lock_original).digest())
        return digest.hexdigest()

    with mock.patch.object(seal, "listed_files", return_value=sorted(REVIEWED_VENDOR_FILES)):
        before = seal.fingerprint(root, ["vendor"], lock)
        assert before == manual_original_fingerprint()
        changed = REVIEWED_VENDOR_FILES[0]
        originals[changed] = b"crate\nser\npublic-synthetic-new-word\n"
        (root / changed).write_bytes(originals[changed])
        after = seal.fingerprint(root, ["vendor"], lock)
        assert after == manual_original_fingerprint()
        assert after != before


@pytest.mark.parametrize("relative", [
    "vendor/example/Cargo.toml.orig",
    "vendor/bytes/Cargo.toml.orig.backup",
    "vendor/bytes/src/Cargo.toml.orig",
    "vendor/bytes/credentials.orig",
    "vendor/http-body-util/Cargo.toml.orig.backup",
    "vendor/http-body-util/src/Cargo.toml.orig",
    "vendor/http-body-util/credentials.orig",
    "vendor/axum-core/Cargo.toml.orig.backup",
    "vendor/axum-core/src/Cargo.toml.orig",
    "vendor/axum-core/credentials.orig",
    "vendor/concread/Cargo.toml.orig.backup",
    "vendor/concread/not.codespell_ignore",
    "vendor/concread/.codespell_ignore/words",
    "vendor/halo2curves-axiom/src/bls12_381/tests/g1_changed_valid_test_vectors.dat",
    "vendor/halo2curves-axiom/src/bls12_381/tests/g1_compressed_valid_test_vectors.dat.extra",
    "vendor/example/private/public-sentinel.dat",
    "vendor/example/operations/public-sentinel.orig",
    "vendor/concread/public-sentinel.der",
    "vendor/concread/public-sentinel.pem",
    "vendor/concread/credentials.orig",
])
def test_neighbor_or_material_role_is_refused_before_any_open(tmp_path: Path, relative: str) -> None:
    root = tmp_path.resolve()
    source = root / relative
    source.parent.mkdir(parents=True, exist_ok=True)
    source.write_bytes(b"PUBLIC SYNTHETIC REFUSAL SENTINEL; NOT A CREDENTIAL\n")
    with mock.patch.object(seal.os, "open", side_effect=AssertionError("no source descriptor permitted")) as opened:
        with pytest.raises(RuntimeError, match="prohibited|admitted public filename"):
            seal._read_public_source_bytes(root, relative)
    opened.assert_not_called()


@pytest.mark.parametrize("relative", [
    "vendor/example/credentials.orig",
    "vendor/example/public-sentinel.pem",
    "vendor/example/vultr-public-sentinel.dat",
])
def test_material_and_provider_refusal_precedes_even_an_expanded_exact_allowlist(tmp_path: Path, relative: str) -> None:
    root = tmp_path.resolve()
    source = root / relative
    source.parent.mkdir(parents=True, exist_ok=True)
    source.write_bytes(b"PUBLIC SYNTHETIC REFUSAL SENTINEL; NO PROVIDER OPERATION\n")
    with mock.patch.object(seal, "_REVIEWED_PUBLIC_VENDOR_INPUTS", seal._REVIEWED_PUBLIC_VENDOR_INPUTS | {relative}), \
            mock.patch.object(seal.os, "open", side_effect=AssertionError("no source descriptor permitted")) as opened:
        with pytest.raises(RuntimeError, match="prohibited"):
            seal._read_public_source_bytes(root, relative)
    opened.assert_not_called()


@pytest.mark.parametrize("relative", ROLE_EXAMPLES)
def test_reviewed_vendor_leaf_alias_is_refused_before_any_open(tmp_path: Path, relative: str) -> None:
    root = tmp_path.resolve()
    public = root / "public-sentinel.rs"
    public.write_bytes(b"pub fn public_sentinel() {}\n")
    alias = root / relative
    alias.parent.mkdir(parents=True, exist_ok=True)
    alias.symlink_to(public)
    with mock.patch.object(seal.os, "open", side_effect=AssertionError("no source descriptor permitted")) as opened:
        with pytest.raises(RuntimeError, match="symlinked"):
            seal._read_public_source_bytes(root, relative)
    opened.assert_not_called()


@pytest.mark.parametrize("relative", ROLE_EXAMPLES)
def test_reviewed_vendor_ancestor_alias_is_refused_before_any_open(tmp_path: Path, relative: str) -> None:
    root = tmp_path.resolve()
    actual = root / "public-vendor"
    suffix = Path(relative).relative_to("vendor")
    write_public(actual, str(suffix))
    (root / "vendor").symlink_to(actual, target_is_directory=True)
    with mock.patch.object(seal.os, "open", side_effect=AssertionError("no source descriptor permitted")) as opened:
        with pytest.raises(RuntimeError, match="symlinked"):
            seal._read_public_source_bytes(root, relative)
    opened.assert_not_called()
