"""Pure tests for the proposed Kagami profile generated-output owner."""

from __future__ import annotations

import hashlib
import importlib.util
import os
from pathlib import Path
import stat
import sys

import pytest

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - Python 3.10
    import tomli as tomllib


CACHE_DIR = Path(__file__).resolve().parent
DEFAULT_HELPER = CACHE_DIR / "kagami_profile_owner.py"
if not DEFAULT_HELPER.exists():
    DEFAULT_HELPER = CACHE_DIR.parent / "kagami_profile_owner.py"
HELPER = Path(os.environ.get("KAGAMI_PROFILE_OWNER_UNDER_TEST", DEFAULT_HELPER))
DEFAULT_REPO_ROOT = Path(__file__).resolve().parents[2]
REPO_ROOT = Path(
    os.environ.get("IROHA_REPO_ROOT_UNDER_TEST", DEFAULT_REPO_ROOT)
).resolve()
DEFAULT_POST_MANIFEST = CACHE_DIR / "generated-files.post.toml"
if not DEFAULT_POST_MANIFEST.exists():
    DEFAULT_POST_MANIFEST = REPO_ROOT / "generated-files.toml"
POST_MANIFEST = Path(
    os.environ.get("GENERATED_FILES_UNDER_TEST", DEFAULT_POST_MANIFEST)
)

SPEC = importlib.util.spec_from_file_location("kagami_profile_owner", HELPER)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)
MODULE.REPO_ROOT = REPO_ROOT
MODULE.ROOT_CARGO_LOCK = REPO_ROOT / "Cargo.lock"


DEV_FILES = {
    "README.md",
    "docker-compose.yml",
    "genesis.expected_hash",
    "genesis.json",
    "genesis.public_key",
    "genesis.signed.nrt",
    "peer0.toml",
    "peer1.toml",
    "peer2.toml",
    "peer3.toml",
    "verify.txt",
}
def _write_dummy_stage(root: Path, profile: str) -> None:
    for relative in MODULE._expected_paths(profile):
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(f"{relative}\n".encode())


def _valid_cli_tail(tmp_path: Path) -> list[str]:
    cargo = tmp_path / "cargo"
    cargo.write_text("cargo fixture\n", encoding="utf-8")
    cargo.chmod(0o700)
    target = tmp_path / "target"
    target.mkdir(mode=0o700)
    allocations = tmp_path / "allocations"
    allocations.mkdir(mode=0o700)
    return [
        "--cargo",
        str(cargo),
        "--cargo-target-dir",
        str(target),
        "--xor-allocations-dir",
        str(allocations),
        "--genesis-creation-time-ms",
        "1700000000000",
        "--cargo-lock-size",
        "311234",
        "--cargo-lock-sha256",
        "d5b8bf5efbdc3ce2a8b1c0d2d75e1c5d1a343a072f836cfb76205bc6ea4cf15f",
    ]


def test_profile_allowlist_describes_external_complete_bundles() -> None:
    assert set(MODULE.PROFILE_FILES) == {"iroha3-dev"}
    assert set(MODULE.PROFILE_FILES["iroha3-dev"]) == DEV_FILES
    assert len(DEV_FILES) == 11
    present = {
        path.name
        for path in (REPO_ROOT / "defaults" / "kagami" / "iroha3-dev").iterdir()
        if path.is_file()
    }
    assert present != DEV_FILES
    assert "genesis.template.json" in present
    assert "genesis.signed.nrt" not in present


def test_profile_command_always_pins_one_profile_output_and_kagami() -> None:
    tools = MODULE.BuiltTools(Path("/external/target/debug/xtask"), Path("/external/target/debug/kagami"))
    command = MODULE._profile_command(
        tools,
        "iroha3-dev",
        Path("/external/stage"),
        Path("/external/allocations"),
        1_700_000_000_000,
    )
    expected = [
        "/external/target/debug/xtask",
        "kagami-profiles",
        "--profile",
        "iroha3-dev",
        "--xor-allocations-dir",
        "/external/allocations",
        "--genesis-creation-time-ms",
        "1700000000000",
        "--out",
        "/external/stage/defaults/kagami",
        "--kagami",
        "/external/target/debug/kagami",
    ]
    assert command == expected
    assert "iroha3-nexus" not in command
    assert "all" not in command

def test_cli_requires_current_xor_allocations_and_refuses_retired_mint_arguments(tmp_path: Path) -> None:
    tail = _valid_cli_tail(tmp_path)
    args = ["--write", "--profile", "iroha3-dev", "--output-root", str(tmp_path / "out"), *tail]
    parsed = MODULE._parse_args(args)
    assert parsed.xor_allocations_dir == str(tmp_path / "allocations")
    assert parsed.genesis_creation_time_ms == 1_700_000_000_000
    assert not hasattr(parsed, "kagemusha_mint_finality_parameters_dir")
    missing = args.copy()
    index = missing.index("--xor-allocations-dir")
    del missing[index:index + 2]
    with pytest.raises(SystemExit):
        MODULE._parse_args(missing)
    with pytest.raises(SystemExit):
        MODULE._parse_args([*args, "--kagemusha-mint-finality-parameters-dir", str(tmp_path / "retired")])


def test_creation_time_is_required_canonical_nonzero_and_bounded(tmp_path: Path) -> None:
    args = ["--write", "--profile", "iroha3-dev", "--output-root", str(tmp_path / "out"), *_valid_cli_tail(tmp_path)]
    index = args.index("--genesis-creation-time-ms")
    missing = args.copy()
    del missing[index:index + 2]
    with pytest.raises(SystemExit):
        MODULE._parse_args(missing)
    for record in ("0", "01", "+1", " 1", "18446744073709551616", "１２"):
        invalid = args.copy()
        invalid[index + 1] = record
        with pytest.raises(SystemExit):
            MODULE._parse_args(invalid)


@pytest.mark.parametrize("record", ["1700000000001", "1700000000000"])
def test_cli_rejects_repeated_creation_time(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], record: str,
) -> None:
    args = ["--write", "--profile", "iroha3-dev", "--output-root", str(tmp_path / "out"), *_valid_cli_tail(tmp_path)]
    with pytest.raises(SystemExit):
        MODULE._parse_args([*args, "--genesis-creation-time-ms", record])
    assert "--genesis-creation-time-ms may be supplied only once" in capsys.readouterr().err


@pytest.mark.parametrize("mode", ["write", "check"])
def test_run_passes_exact_creation_time_to_each_stage(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, mode: str,
) -> None:
    tmp_path = tmp_path.resolve()
    args = [f"--{mode}", "--profile", "iroha3-dev", *_valid_cli_tail(tmp_path)]
    if mode == "write":
        args.extend(["--output-root", str(tmp_path / "out")])
    else:
        candidate = tmp_path / "candidate"
        candidate.mkdir()
        args.extend([
            "--root", str(candidate),
            "--stage-a", str(tmp_path / "stage-a"),
            "--stage-b", str(tmp_path / "stage-b"),
        ])
    stages = []
    monkeypatch.setattr(MODULE, "_authenticate_lock", lambda *args: b"lock")
    monkeypatch.setattr(MODULE, "_build_tools", lambda *args: (None, {}))
    monkeypatch.setattr(MODULE, "_generate_stage", lambda *args: stages.append(args) or {})
    monkeypatch.setattr(MODULE, "_snapshot", lambda *args, **kwargs: {})
    MODULE.run(MODULE._parse_args(args))
    assert len(stages) == (1 if mode == "write" else 2)
    assert all(stage[-1] == 1_700_000_000_000 for stage in stages)


def test_cargo_build_command_is_locked_offline_and_uses_exact_root_lock() -> None:
    expectation = MODULE.LockExpectation(321032, "ab" * 32)
    command = MODULE._cargo_command(Path("/toolchain/cargo"), "xtask", "xtask", expectation)
    for item in ("--locked", "--offline", "--jobs", "1", "--lockfile-path"):
        assert item in command
    assert str(MODULE.ROOT_CARGO_LOCK) in command
    assert command[-6:] == ["-p", "xtask", "--features", "dev-tools", "--bin", "xtask"]


def test_stage_snapshot_rejects_missing_extra_symlink_and_hardlink(tmp_path: Path) -> None:
    root = tmp_path / "stage"
    root.mkdir(mode=0o700)
    _write_dummy_stage(root, "iroha3-dev")
    baseline = MODULE._snapshot(root, "iroha3-dev", closed_stage=True)
    assert len(baseline) == 11

    extra = root / "defaults" / "kagami" / "iroha3-dev" / "extra"
    extra.write_bytes(b"extra")
    with pytest.raises(MODULE.OwnerError, match="topology mismatch"):
        MODULE._snapshot(root, "iroha3-dev", closed_stage=True)
    extra.unlink()

    victim = root / next(iter(MODULE._expected_paths("iroha3-dev")))
    original = victim.read_bytes()
    victim.unlink()
    victim.symlink_to("README.md")
    with pytest.raises(MODULE.OwnerError, match="single-link regular"):
        MODULE._snapshot(root, "iroha3-dev", closed_stage=True)
    victim.unlink()
    victim.write_bytes(original)

    peer = root / "defaults" / "kagami" / "iroha3-dev" / "peer0.toml"
    peer.unlink()
    os.link(root / "defaults" / "kagami" / "iroha3-dev" / "README.md", peer)
    with pytest.raises(MODULE.OwnerError, match="single-link regular"):
        MODULE._snapshot(root, "iroha3-dev", closed_stage=True)


def test_snapshot_comparison_is_byte_exact() -> None:
    first = {"x": MODULE.ManagedFile(1, hashlib.sha256(b"a").hexdigest(), b"a")}
    same = {"x": MODULE.ManagedFile(1, hashlib.sha256(b"a").hexdigest(), b"a")}
    drift = {"x": MODULE.ManagedFile(1, hashlib.sha256(b"b").hexdigest(), b"b")}
    MODULE._compare_snapshots(first, same, "same")
    with pytest.raises(MODULE.OwnerError, match="byte drift"):
        MODULE._compare_snapshots(first, drift, "drift")


def test_lock_authentication_checks_identity_size_digest_and_permissions(tmp_path: Path) -> None:
    lock = tmp_path / "Cargo.lock"
    lock.write_bytes(b"sealed lock bytes")
    lock.chmod(0o600)
    expected = MODULE.LockExpectation(len(b"sealed lock bytes"), hashlib.sha256(b"sealed lock bytes").hexdigest())
    assert MODULE._authenticate_lock(lock, expected) == b"sealed lock bytes"
    with pytest.raises(MODULE.OwnerError, match="byte length drifted"):
        MODULE._authenticate_lock(lock, MODULE.LockExpectation(1, expected.sha256))
    with pytest.raises(MODULE.OwnerError, match="SHA-256 drifted"):
        MODULE._authenticate_lock(lock, MODULE.LockExpectation(expected.byte_length, "00" * 32))
    lock.chmod(0o620)
    with pytest.raises(MODULE.OwnerError, match="group- or world-writable"):
        MODULE._authenticate_lock(lock, expected)


def test_absent_root_is_external_private_normalized_and_nonoverlapping(tmp_path: Path) -> None:
    tmp_path.chmod(0o700)
    if MODULE._is_relative_to(tmp_path.resolve(), REPO_ROOT):
        with pytest.raises(MODULE.OwnerError, match="source repository|Git checkout"):
            MODULE._absent_external_root(str(tmp_path / "stage"), "stage")
    else:
        assert MODULE._absent_external_root(str(tmp_path / "stage"), "stage") == tmp_path / "stage"
        (tmp_path / "stage").mkdir()
        with pytest.raises(MODULE.OwnerError, match="must be absent"):
            MODULE._absent_external_root(str(tmp_path / "stage"), "stage")
    with pytest.raises(MODULE.OwnerError, match="source repository|group or world permissions"):
        MODULE._absent_external_root(str(REPO_ROOT / "stage"), "stage")
    with pytest.raises(MODULE.OwnerError, match="normalized absolute"):
        MODULE._absent_external_root("relative/stage", "stage")

def test_private_virtual_external_owner_admits_absent_root_and_refuses_overlap(monkeypatch: pytest.MonkeyPatch) -> None:
    # Model separate private source/output roots without writing outside the repository.
    # The actual source-overlap and Git-ancestor policy executes unchanged below.
    virtual = Path(REPO_ROOT.anchor) / "virtual-profile-owner"
    repository = virtual / "source"
    owner = virtual / "output"
    destination = owner / "stage"
    metadata = os.stat_result((stat.S_IFDIR | 0o700, 1, 1, 1, 0, 0, 0, 0, 0, 0))
    occupied: set[Path] = set()
    git_checkout = False

    def virtual_lstat(path: Path) -> os.stat_result:
        if path.name == ".git":
            if git_checkout and path == owner / ".git":
                return metadata
            raise FileNotFoundError(path)
        if path in {repository, owner, virtual}:
            return metadata
        raise FileNotFoundError(path)

    def virtual_resolve(path: Path, strict: bool = False) -> Path:
        if strict and path not in {repository, owner, virtual}:
            raise FileNotFoundError(path)
        return path

    monkeypatch.setattr(MODULE, "REPO_ROOT", repository)
    with monkeypatch.context() as filesystem:
        filesystem.setattr(Path, "lstat", virtual_lstat)
        filesystem.setattr(Path, "resolve", virtual_resolve)
        filesystem.setattr(MODULE.os.path, "lexists", lambda path: Path(path) in occupied)
        assert MODULE._absent_external_root(str(destination), "stage") == destination
        occupied.add(destination)
        with pytest.raises(MODULE.OwnerError, match="must be absent"):
            MODULE._absent_external_root(str(destination), "stage")
        with pytest.raises(MODULE.OwnerError, match="source repository"):
            MODULE._absent_external_root(str(repository / "stage"), "stage")
        git_checkout = True
        with pytest.raises(MODULE.OwnerError, match="Git checkout"):
            MODULE._absent_external_root(str(owner / "fresh"), "stage")


@pytest.mark.skipif(
    not (sys.platform == "darwin" or sys.platform.startswith("linux")),
    reason="atomic no-replace primitive is intentionally fail-closed elsewhere",
)
def test_atomic_directory_publish_never_replaces_existing_destination(tmp_path: Path) -> None:
    tmp_path.chmod(0o700)
    source = tmp_path / "source"
    source.mkdir()
    (source / "sentinel").write_bytes(b"first")
    destination = tmp_path / "destination"
    MODULE._rename_no_replace(source, destination)
    assert (destination / "sentinel").read_bytes() == b"first"

    second = tmp_path / "second"
    second.mkdir()
    (second / "sentinel").write_bytes(b"second")
    with pytest.raises(MODULE.OwnerError, match="destination appeared"):
        MODULE._rename_no_replace(second, destination)
    assert (destination / "sentinel").read_bytes() == b"first"


def test_cli_rejects_public_profiles_all_and_ambiguous_modes(tmp_path: Path) -> None:
    tail = _valid_cli_tail(tmp_path)
    for profile in ("iroha3-taira", "iroha3-nexus", "all"):
        with pytest.raises(SystemExit):
            MODULE._parse_args(["--write", "--profile", profile, "--output-root", str(tmp_path / "out"), *tail])
    with pytest.raises(SystemExit):
        MODULE._parse_args(
            [
                "--write",
                "--check",
                "--profile",
                "iroha3-dev",
                "--output-root",
                str(tmp_path / "out"),
                *tail,
            ]
        )


def test_post_manifest_does_not_claim_operator_bundles_are_checked_in() -> None:
    if POST_MANIFEST.exists():
        manifest_text = POST_MANIFEST.read_text(encoding="utf-8")
    else:
        manifest_text = (REPO_ROOT / "generated-files.toml").read_text(encoding="utf-8")
        manifest_text += (CACHE_DIR / "generated-files.append.toml").read_text(encoding="utf-8")
    manifest = tomllib.loads(manifest_text)
    owners = {
        entry["name"]: entry
        for entry in manifest["generated"]
        if entry["name"] == "kagami-iroha3-dev-profile-bundle"
    }
    assert owners == {}
