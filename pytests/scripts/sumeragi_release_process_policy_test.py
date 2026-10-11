from __future__ import annotations

import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile


REPO_ROOT = Path(__file__).resolve().parents[2]
POLICY = REPO_ROOT / "scripts" / "sumeragi_release_process_policy.sh"


def _authenticated_temporary_base() -> Path:
    configured = os.environ.get("IROHA_RELEASE_TEMP_BASE")
    candidates = (
        (Path(configured),)
        if configured
        else (Path("/private/tmp"), Path("/tmp"))
    )
    for candidate in candidates:
        try:
            metadata = candidate.lstat()
            if (
                candidate.is_absolute()
                and Path(os.path.abspath(candidate)) == candidate
                and candidate.resolve(strict=True) == candidate
                and not candidate.is_symlink()
                and candidate.is_dir()
                and os.access(candidate, os.W_OK | os.X_OK)
                and (
                    (metadata.st_uid == 0 and metadata.st_mode & 0o1000)
                    or (
                        metadata.st_uid == os.geteuid()
                        and not metadata.st_mode & 0o077
                    )
                )
            ):
                return candidate
        except (OSError, RuntimeError):
            continue
    raise RuntimeError("tests require an authenticated release temporary base")


AUTHENTICATED_TEMP_BASE = _authenticated_temporary_base()


def _write_executable(path: Path, source: str) -> None:
    path.write_text(source, encoding="utf-8")
    path.chmod(0o700)


def _policy_environment(fake_bin: Path, **extra: str) -> dict[str, str]:
    environment = os.environ.copy()
    environment.update(
        {
            "PATH": f"{fake_bin}{os.pathsep}{environment['PATH']}",
            "IROHA_RELEASE_POLICY_PYTHON": sys.executable,
            "IROHA_RELEASE_CARGO_BIN": str(fake_bin / "cargo"),
            "IROHA_RELEASE_TEMP_BASE": str(AUTHENTICATED_TEMP_BASE),
        }
    )
    environment.update(extra)
    return environment


def _run_policy(
    command: str,
    *,
    fake_bin: Path,
    environment: dict[str, str] | None = None,
    shell: str = "bash",
) -> subprocess.CompletedProcess[str]:
    merged = _policy_environment(fake_bin)
    if environment:
        merged.update(environment)
    temporary_root = None
    if "IROHA_RELEASE_ARTIFACT_ROOT" not in merged:
        temporary_root = tempfile.TemporaryDirectory(
            prefix="iroha-policy-artifacts-", dir=AUTHENTICATED_TEMP_BASE
        )
        artifact_root = Path(temporary_root.name)
        artifact_root.chmod(0o700)
        merged["IROHA_RELEASE_ARTIFACT_ROOT"] = str(artifact_root)
    try:
        return subprocess.run(
            [shell, "-c", f'source "{POLICY}"\n{command}'],
            cwd=REPO_ROOT,
            env=merged,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
    finally:
        if temporary_root is not None:
            temporary_root.cleanup()


def test_invocation_cargo_lock_is_private_fail_closed_and_reusable(
    tmp_path: Path,
) -> None:
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    with tempfile.TemporaryDirectory(
        prefix="iroha-policy-lock-", dir=AUTHENTICATED_TEMP_BASE
    ) as temporary_root:
        artifact_root = Path(temporary_root)
        artifact_root.chmod(0o700)
        lock = artifact_root / ".sumeragi-cargo.lock"

        first = _run_policy(
            "acquire_invocation_cargo_lock",
            fake_bin=fake_bin,
            environment={"IROHA_RELEASE_ARTIFACT_ROOT": str(artifact_root)},
        )
        held = _run_policy(
            "acquire_invocation_cargo_lock",
            fake_bin=fake_bin,
            environment={"IROHA_RELEASE_ARTIFACT_ROOT": str(artifact_root)},
        )
        released = _run_policy(
            "release_invocation_cargo_lock",
            fake_bin=fake_bin,
            environment={"IROHA_RELEASE_ARTIFACT_ROOT": str(artifact_root)},
        )
        token = lock / "owner-token"
        token_bytes = token.read_bytes()
        token_mode = token.stat().st_mode & 0o777
        shutil.rmtree(lock)
        replaced_lock = artifact_root / ".sumeragi-cargo.replaced"
        inode_tampered = _run_policy(
            'acquire_invocation_cargo_lock && '
            'mv "$IROHA_RELEASE_ARTIFACT_ROOT/.sumeragi-cargo.lock" '
            '"$IROHA_RELEASE_ARTIFACT_ROOT/.sumeragi-cargo.replaced" && '
            'mkdir -m 0700 "$IROHA_RELEASE_ARTIFACT_ROOT/.sumeragi-cargo.lock" && '
            "release_invocation_cargo_lock",
            fake_bin=fake_bin,
            environment={"IROHA_RELEASE_ARTIFACT_ROOT": str(artifact_root)},
        )
        shutil.rmtree(lock)
        shutil.rmtree(replaced_lock)
        token_tampered = _run_policy(
            'acquire_invocation_cargo_lock && '
            'chmod 0600 "$IROHA_RELEASE_ARTIFACT_ROOT/.sumeragi-cargo.lock/owner-token" && '
            'printf "%064d\\n" 0 > '
            '"$IROHA_RELEASE_ARTIFACT_ROOT/.sumeragi-cargo.lock/owner-token" && '
            'chmod 0400 "$IROHA_RELEASE_ARTIFACT_ROOT/.sumeragi-cargo.lock/owner-token" && '
            "release_invocation_cargo_lock",
            fake_bin=fake_bin,
            environment={"IROHA_RELEASE_ARTIFACT_ROOT": str(artifact_root)},
        )
        shutil.rmtree(lock)
        reacquired = _run_policy(
            "acquire_invocation_cargo_lock && release_invocation_cargo_lock",
            fake_bin=fake_bin,
            environment={"IROHA_RELEASE_ARTIFACT_ROOT": str(artifact_root)},
        )
        artifact_root.chmod(0o755)
        unsafe_root = _run_policy(
            "acquire_invocation_cargo_lock",
            fake_bin=fake_bin,
            environment={"IROHA_RELEASE_ARTIFACT_ROOT": str(artifact_root)},
        )
        artifact_root.chmod(0o700)

        assert first.returncode == 0, first.stderr
        assert held.returncode == 2
        assert "already held" in held.stderr
        assert released.returncode == 2
        assert "not owned by this shell" in released.stderr
        assert len(token_bytes) == 65 and token_bytes.endswith(b"\n")
        assert token_mode == 0o400
        assert inode_tampered.returncode == 2
        assert "unsafe invocation-local Cargo lock" in inode_tampered.stderr
        assert token_tampered.returncode == 2
        assert "token changed" in token_tampered.stderr
        assert reacquired.returncode == 0, reacquired.stderr
        assert unsafe_root.returncode == 2
        assert "private artifact root" in unsafe_root.stderr
        assert not lock.exists()


def test_run_cargo_pins_toolchain_jobs_and_locked_offline_flags(tmp_path: Path) -> None:
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    argv_path = tmp_path / "cargo-argv"
    rustup_policy_path = tmp_path / "rustup-auto-install"
    ambient_observation_path = tmp_path / "ambient-observation"
    _write_executable(
        fake_bin / "cargo",
        "#!/bin/sh\n"
        'if [ -n "${MUTATE_CARGO_CONFIG:-}" ]; then printf "[net]\\noffline = false\\n" > "$CARGO_HOME/config.toml"; fi\n'
        "printf '%s\\n' \"$@\" > \"$CARGO_ARGV_FILE\"\n"
        "printf '%s\\n' \"$RUSTUP_AUTO_INSTALL\" > \"$RUSTUP_POLICY_FILE\"\n",
    )
    for command in ("ps", "pgrep", "sleep"):
        _write_executable(
            fake_bin / command,
            "#!/bin/sh\nprintf observed > \"$AMBIENT_OBSERVATION_FILE\"\nexit 91\n",
        )

    result = _run_policy(
        "run_cargo test --locked --offline -p iroha_core --lib",
        fake_bin=fake_bin,
        environment={
            "CARGO_ARGV_FILE": str(argv_path),
            "RUSTUP_POLICY_FILE": str(rustup_policy_path),
            "AMBIENT_OBSERVATION_FILE": str(ambient_observation_path),
        },
    )
    result_argv = argv_path.read_text(encoding="utf-8").splitlines()
    unsupported_verus = _run_policy(
        "run_cargo verus verify --locked --offline --package iroha_core",
        fake_bin=fake_bin,
        environment={
            "CARGO_ARGV_FILE": str(argv_path),
            "RUSTUP_POLICY_FILE": str(rustup_policy_path),
            "AMBIENT_OBSERVATION_FILE": str(ambient_observation_path),
        },
    )
    cargo_home = tmp_path / "cargo-home"
    cargo_home.mkdir(mode=0o700)
    config_mutation = _run_policy(
        "run_cargo test --locked --offline -p iroha_core --lib",
        fake_bin=fake_bin,
        environment={
            "CARGO_ARGV_FILE": str(argv_path),
            "RUSTUP_POLICY_FILE": str(rustup_policy_path),
            "CARGO_HOME": str(cargo_home),
            "MUTATE_CARGO_CONFIG": "1",
        },
    )

    assert result.returncode == 0, result.stderr
    assert result_argv == [
        "test",
        "-j1",
        "--locked",
        "--offline",
        "-p",
        "iroha_core",
        "--lib",
    ]
    assert unsupported_verus.returncode == 2
    assert (
        "run_cargo rejects unsupported Cargo subcommand: verus"
        in unsupported_verus.stderr
    )
    assert rustup_policy_path.read_text(encoding="utf-8") == "0\n"
    assert not ambient_observation_path.exists()
    assert config_mutation.returncode == 2
    assert "configuration roots changed" in config_mutation.stderr


def test_run_cargo_preserves_nonzero_status_when_sourced_by_zsh(tmp_path: Path) -> None:
    zsh = shutil.which("zsh")
    if zsh is None:
        return

    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    argv_path = tmp_path / "cargo-argv"
    _write_executable(
        fake_bin / "cargo",
        "#!/bin/sh\nprintf '%s\\n' \"$@\" > \"$CARGO_ARGV_FILE\"\nexit 7\n",
    )

    with tempfile.TemporaryDirectory(
        prefix="iroha-policy-nonzero-", dir=AUTHENTICATED_TEMP_BASE
    ) as temporary_root:
        artifact_root = Path(temporary_root)
        artifact_root.chmod(0o700)
        result = _run_policy(
            "run_cargo test --locked --offline -p iroha_core --lib",
            fake_bin=fake_bin,
            environment={
                "CARGO_ARGV_FILE": str(argv_path),
                "IROHA_RELEASE_ARTIFACT_ROOT": str(artifact_root),
            },
            shell=zsh,
        )
        assert not (artifact_root / ".sumeragi-cargo.lock").exists()

    assert result.returncode == 7, result.stderr
    assert "read-only variable: status" not in result.stderr
    assert argv_path.read_text(encoding="utf-8").splitlines()[:2] == [
        "test",
        "-j1",
    ]


def test_run_cargo_rejects_missing_or_caller_owned_policy_flags(tmp_path: Path) -> None:
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    _write_executable(fake_bin / "cargo", "#!/bin/sh\nexit 99\n")

    missing = _run_policy(
        "run_cargo test --locked -p iroha_core",
        fake_bin=fake_bin,
    )
    caller_jobs = _run_policy(
        "run_cargo test --locked --offline -j2 -p iroha_core",
        fake_bin=fake_bin,
    )
    fetch = _run_policy(
        "run_cargo fetch --locked --offline",
        fake_bin=fake_bin,
    )
    rustup_override = _run_policy(
        "run_cargo test --locked --offline -p iroha_core",
        fake_bin=fake_bin,
        environment={"RUSTUP_AUTO_INSTALL": "1"},
    )

    assert missing.returncode == 2
    assert "exactly one --locked and one --offline" in missing.stderr
    assert caller_jobs.returncode == 2
    assert "caller job flags are forbidden" in caller_jobs.stderr
    assert fetch.returncode == 2
    assert "rejects unsupported Cargo subcommand: fetch" in fetch.stderr
    assert rustup_override.returncode == 2
    assert "caller-owned rustup auto-install policy" in rustup_override.stderr


def test_run_cargo_uses_only_the_authenticated_absolute_binary(tmp_path: Path) -> None:
    fake_bin = tmp_path / "bin"
    authenticated_bin = tmp_path / "authenticated-bin"
    fake_bin.mkdir()
    authenticated_bin.mkdir()
    decoy_path = tmp_path / "decoy-called"
    authenticated_path = tmp_path / "authenticated-called"
    _write_executable(
        fake_bin / "cargo",
        f"#!/bin/sh\nprintf called > {decoy_path}\nexit 97\n",
    )
    authenticated_cargo = authenticated_bin / "cargo"
    _write_executable(
        authenticated_cargo,
        f"#!/bin/sh\nprintf called > {authenticated_path}\n",
    )

    result = _run_policy(
        "run_cargo test --locked --offline -p iroha_core",
        fake_bin=fake_bin,
        environment={"IROHA_RELEASE_CARGO_BIN": str(authenticated_cargo)},
    )

    assert result.returncode == 0, result.stderr
    assert authenticated_path.read_text(encoding="utf-8") == "called"
    assert not decoy_path.exists()


def test_run_cargo_rejects_unbound_or_noncanonical_binary(tmp_path: Path) -> None:
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    cargo = fake_bin / "cargo"
    _write_executable(cargo, "#!/bin/sh\nexit 99\n")
    cargo_symlink = tmp_path / "cargo-symlink"
    cargo_symlink.symlink_to(cargo)

    results = (
        _run_policy(
            "run_cargo --version",
            fake_bin=fake_bin,
            environment={"IROHA_RELEASE_CARGO_BIN": ""},
        ),
        _run_policy(
            "run_cargo --version",
            fake_bin=fake_bin,
            environment={"IROHA_RELEASE_CARGO_BIN": "cargo"},
        ),
        _run_policy(
            "run_cargo --version",
            fake_bin=fake_bin,
            environment={"IROHA_RELEASE_CARGO_BIN": str(cargo_symlink)},
        ),
    )

    assert all(result.returncode == 2 for result in results)
    assert "requires IROHA_RELEASE_CARGO_BIN" in results[0].stderr
    assert "absolute and normalized" in results[1].stderr
    assert "canonical executable regular file" in results[2].stderr


def test_run_cargo_policy_flags_stop_at_literal_separator(tmp_path: Path) -> None:
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    argv_path = tmp_path / "cargo-argv"
    _write_executable(
        fake_bin / "cargo",
        "#!/bin/sh\nprintf '%s\\n' \"$@\" > \"$CARGO_ARGV_FILE\"\n",
    )

    suffix_only = _run_policy(
        "run_cargo test -p iroha_core -- --locked --offline",
        fake_bin=fake_bin,
        environment={"CARGO_ARGV_FILE": str(argv_path)},
    )
    accepted = _run_policy(
        "run_cargo test --locked --offline -p iroha_core -- "
        "--locked --offline -j2 --target-dir=harness-output --config fixture",
        fake_bin=fake_bin,
        environment={"CARGO_ARGV_FILE": str(argv_path)},
    )

    assert suffix_only.returncode == 2
    assert "before --" in suffix_only.stderr
    assert accepted.returncode == 0, accepted.stderr
    assert argv_path.read_text(encoding="utf-8").splitlines() == [
        "test",
        "-j1",
        "--locked",
        "--offline",
        "-p",
        "iroha_core",
        "--",
        "--locked",
        "--offline",
        "-j2",
        "--target-dir=harness-output",
        "--config",
        "fixture",
    ]


def test_run_cargo_rejects_output_manifest_and_config_overrides(
    tmp_path: Path,
) -> None:
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    called = tmp_path / "cargo-called"
    _write_executable(
        fake_bin / "cargo",
        f"#!/bin/sh\nprintf called > {called}\n",
    )
    commands = (
        "run_cargo test --locked --offline --target-dir /private/tmp/escape",
        "run_cargo test --locked --offline --target-dir=/private/tmp/escape",
        "run_cargo test --locked --offline --manifest-path /private/tmp/Cargo.toml",
        "run_cargo test --locked --offline --manifest-path=/private/tmp/Cargo.toml",
        "run_cargo test --locked --offline --config net.offline=false",
        "run_cargo test --locked --offline --config=net.offline=false",
        "run_cargo fmt --manifest-path /private/tmp/Cargo.toml -- --check",
    )

    results = tuple(
        _run_policy(command, fake_bin=fake_bin) for command in commands
    )

    assert all(result.returncode == 2 for result in results)
    assert all(
        "owns Cargo target, manifest, and configuration selection" in result.stderr
        for result in results
    )
    assert not called.exists()


def test_cooperative_marker_is_checked_only_between_commands(tmp_path: Path) -> None:
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    marker = tmp_path / "cancel.json"
    marker.write_bytes(b'{"reason":"operator-request","schema_version":1}\n')
    marker.chmod(0o600)

    result = _run_policy(
        "release_gate_boundary focused-tests",
        fake_bin=fake_bin,
        environment={"IROHA_RELEASE_CANCEL_REQUEST_PATH": str(marker)},
        shell=shutil.which("zsh") or "bash",
    )

    assert result.returncode == 125
    assert "cooperative cancellation requested" in result.stderr


def test_malformed_or_non_private_marker_fails_closed(tmp_path: Path) -> None:
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    marker = tmp_path / "cancel.json"
    marker.write_text('{"schema_version":1}\n', encoding="utf-8")
    marker.chmod(0o600)
    malformed = _run_policy(
        "release_gate_boundary focused-tests",
        fake_bin=fake_bin,
        environment={"IROHA_RELEASE_CANCEL_REQUEST_PATH": str(marker)},
    )

    marker.write_bytes(b'{"reason":"operator-request","schema_version":1}\n')
    marker.chmod(0o644)
    public = _run_policy(
        "release_gate_boundary focused-tests",
        fake_bin=fake_bin,
        environment={"IROHA_RELEASE_CANCEL_REQUEST_PATH": str(marker)},
    )

    assert malformed.returncode == 2
    assert public.returncode == 2


def test_marker_parent_must_be_private(tmp_path: Path) -> None:
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    marker_parent = tmp_path / "public"
    marker_parent.mkdir(mode=0o700)
    marker = marker_parent / "cancel.json"
    marker.write_bytes(b'{"reason":"operator-request","schema_version":1}\n')
    marker.chmod(0o600)
    marker_parent.chmod(0o755)

    result = _run_policy(
        "release_gate_boundary focused-tests",
        fake_bin=fake_bin,
        environment={"IROHA_RELEASE_CANCEL_REQUEST_PATH": str(marker)},
    )

    assert result.returncode == 2
    assert "parent is not one canonical private owner directory" in result.stderr


def test_cargo_target_accepts_authenticated_linux_tmp_and_rejects_aliases(
    tmp_path: Path,
) -> None:
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    # Authenticate disjoint fixture roots independently of pytest's base directory.
    source_root = tmp_path / "candidate-source"
    source_root.mkdir(mode=0o700)
    (source_root / "target").mkdir(mode=0o700)
    with tempfile.TemporaryDirectory(
        prefix="iroha-policy-target-", dir=AUTHENTICATED_TEMP_BASE
    ) as temporary_root:
        target = Path(temporary_root) / "target"
        target.mkdir(mode=0o700)
        accepted = _run_policy(
            f'require_external_cargo_target_dir "{source_root}"',
            fake_bin=fake_bin,
            environment={"CARGO_TARGET_DIR": str(target)},
        )
        default_accepted = None
        if AUTHENTICATED_TEMP_BASE in (Path("/private/tmp"), Path("/tmp")):
            default_accepted = _run_policy(
                f'require_external_cargo_target_dir "{source_root}"',
                fake_bin=fake_bin,
                environment={
                    "CARGO_TARGET_DIR": str(target),
                    "IROHA_RELEASE_TEMP_BASE": "",
                },
            )
    rejected = _run_policy(
        f'require_external_cargo_target_dir "{source_root}"',
        fake_bin=fake_bin,
        environment={"CARGO_TARGET_DIR": str(source_root / "target")},
    )
    linux_tmp = tmp_path / "tmp"
    linux_tmp.mkdir(mode=0o700)
    linux_target = linux_tmp / "invocation" / "target"
    linux_target.mkdir(parents=True, mode=0o700)
    linux_target.parent.chmod(0o700)
    linux_accepted = _run_policy(
        f'require_external_cargo_target_dir "{source_root}"',
        fake_bin=fake_bin,
        environment={
            "CARGO_TARGET_DIR": str(linux_target),
            "IROHA_RELEASE_TEMP_BASE": str(linux_tmp),
        },
    )
    linux_alias = tmp_path / "tmp-alias"
    linux_alias.symlink_to(linux_tmp, target_is_directory=True)
    alias_rejected = _run_policy(
        f'require_external_cargo_target_dir "{source_root}"',
        fake_bin=fake_bin,
        environment={
            "CARGO_TARGET_DIR": str(linux_target),
            "IROHA_RELEASE_TEMP_BASE": str(linux_alias),
        },
    )
    real_target = linux_tmp / "real-target"
    real_target.mkdir(mode=0o700)
    target_alias = linux_tmp / "target-alias"
    target_alias.symlink_to(real_target, target_is_directory=True)
    target_alias_rejected = _run_policy(
        f'require_external_cargo_target_dir "{source_root}"',
        fake_bin=fake_bin,
        environment={
            "CARGO_TARGET_DIR": str(target_alias),
            "IROHA_RELEASE_TEMP_BASE": str(linux_tmp),
        },
    )
    unsafe_mode_base = tmp_path / "unsafe-mode-base"
    unsafe_mode_base.mkdir(mode=0o700)
    unsafe_mode_target = unsafe_mode_base / "target"
    unsafe_mode_target.mkdir(mode=0o700)
    unsafe_mode_base.chmod(0o755)
    mode_rejected = _run_policy(
        f'require_external_cargo_target_dir "{source_root}"',
        fake_bin=fake_bin,
        environment={
            "CARGO_TARGET_DIR": str(unsafe_mode_target),
            "IROHA_RELEASE_TEMP_BASE": str(unsafe_mode_base),
        },
    )
    unsafe_mode_base.chmod(0o700)

    ownership_base = tmp_path / "wrong-owner-base"
    ownership_base.mkdir(mode=0o700)
    ownership_target = ownership_base / "target"
    ownership_target.mkdir(mode=0o700)
    if os.geteuid() == 0:
        os.chown(ownership_base, 65534, -1)
        wrong_owner_base = ownership_base
    else:
        wrong_owner_base = Path("/")
    owner_rejected = _run_policy(
        f'require_external_cargo_target_dir "{source_root}"',
        fake_bin=fake_bin,
        environment={
            "CARGO_TARGET_DIR": str(ownership_target),
            "IROHA_RELEASE_TEMP_BASE": str(wrong_owner_base),
        },
    )
    if os.geteuid() == 0:
        os.chown(ownership_base, 0, -1)

    source = linux_tmp / "source"
    source.mkdir(mode=0o700)
    source_target = source / "target"
    source_target.mkdir(mode=0o700)
    source_overlap = _run_policy(
        f'require_external_cargo_target_dir "{source}"',
        fake_bin=fake_bin,
        environment={
            "CARGO_TARGET_DIR": str(source_target),
            "IROHA_RELEASE_TEMP_BASE": str(linux_tmp),
        },
    )

    protected_cache = linux_tmp / "caller-cache"
    protected_cache.mkdir(mode=0o700)
    cache_target = protected_cache / "target"
    cache_target.mkdir(mode=0o700)
    cache_overlap = _run_policy(
        f'require_external_cargo_target_dir "{source_root}" "{protected_cache}"',
        fake_bin=fake_bin,
        environment={
            "CARGO_TARGET_DIR": str(cache_target),
            "IROHA_RELEASE_TEMP_BASE": str(linux_tmp),
        },
    )

    assert accepted.returncode == 0, accepted.stderr
    if default_accepted is not None:
        assert default_accepted.returncode == 0, default_accepted.stderr
    assert linux_accepted.returncode == 0, linux_accepted.stderr
    assert rejected.returncode == 2
    assert alias_rejected.returncode == 2
    assert "temporary base" in alias_rejected.stderr
    assert target_alias_rejected.returncode == 2
    assert "Cargo target root" in target_alias_rejected.stderr
    assert mode_rejected.returncode == 2
    assert "temporary base" in mode_rejected.stderr
    assert owner_rejected.returncode == 2
    assert "temporary base" in owner_rejected.stderr
    assert source_overlap.returncode == 2
    assert "outside source" in source_overlap.stderr
    assert cache_overlap.returncode == 2
    assert "protected cache roots" in cache_overlap.stderr


def test_artifact_root_must_be_private_external_and_under_private_tmp(
    tmp_path: Path,
) -> None:
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    with tempfile.TemporaryDirectory(
        prefix="iroha-policy-artifacts-", dir=AUTHENTICATED_TEMP_BASE
    ) as temporary_root:
        invocation_root = Path(temporary_root)
        artifacts = invocation_root / "artifacts"
        target = invocation_root / "target"
        fixture_source = invocation_root / "source"
        artifacts.mkdir(mode=0o700)
        target.mkdir(mode=0o700)
        fixture_source.mkdir(mode=0o700)
        cancel_root = invocation_root / "cancel"
        cancel_root.mkdir(mode=0o700)
        cancel = cancel_root / "cancel-request.json"
        cancel.write_bytes(b'{"reason":"operator-request","schema_version":1}\n')
        cancel.chmod(0o600)
        accepted = _run_policy(
            f'require_external_release_artifact_root "{fixture_source}"',
            fake_bin=fake_bin,
            environment={"IROHA_RELEASE_ARTIFACT_ROOT": str(artifacts)},
        )
        disjoint = _run_policy(
            f'require_disjoint_release_roots "{fixture_source}"',
            fake_bin=fake_bin,
            environment={
                "CARGO_TARGET_DIR": str(target),
                "IROHA_RELEASE_ARTIFACT_ROOT": str(artifacts),
                "IROHA_RELEASE_CANCEL_REQUEST_PATH": str(cancel),
            },
        )
        nested_artifacts = target / "nested-artifacts"
        nested_artifacts.mkdir(mode=0o700)
        nested = _run_policy(
            f'require_disjoint_release_roots "{fixture_source}"',
            fake_bin=fake_bin,
            environment={
                "CARGO_TARGET_DIR": str(target),
                "IROHA_RELEASE_ARTIFACT_ROOT": str(nested_artifacts),
                "IROHA_RELEASE_CANCEL_REQUEST_PATH": str(cancel),
            },
        )
        nested_target_cancel = _run_policy(
            f'require_disjoint_release_roots "{fixture_source}"',
            fake_bin=fake_bin,
            environment={
                "CARGO_TARGET_DIR": str(target),
                "IROHA_RELEASE_ARTIFACT_ROOT": str(artifacts),
                "IROHA_RELEASE_CANCEL_REQUEST_PATH": str(
                    target / "cancel-request.json"
                ),
            },
        )
        nested_artifact_cancel = _run_policy(
            f'require_disjoint_release_roots "{fixture_source}"',
            fake_bin=fake_bin,
            environment={
                "CARGO_TARGET_DIR": str(target),
                "IROHA_RELEASE_ARTIFACT_ROOT": str(artifacts),
                "IROHA_RELEASE_CANCEL_REQUEST_PATH": str(
                    artifacts / "cancel-request.json"
                ),
            },
        )
        nested_source_cancel = _run_policy(
            f'require_disjoint_release_roots "{fixture_source}"',
            fake_bin=fake_bin,
            environment={
                "CARGO_TARGET_DIR": str(target),
                "IROHA_RELEASE_ARTIFACT_ROOT": str(artifacts),
                "IROHA_RELEASE_CANCEL_REQUEST_PATH": str(
                    fixture_source / "cancel-request.json"
                ),
            },
        )
        noncanonical_parent = invocation_root / "nested"
        noncanonical_parent.mkdir(mode=0o700)
        noncanonical_cancel = _run_policy(
            f'require_disjoint_release_roots "{fixture_source}"',
            fake_bin=fake_bin,
            environment={
                "CARGO_TARGET_DIR": str(target),
                "IROHA_RELEASE_ARTIFACT_ROOT": str(artifacts),
                "IROHA_RELEASE_CANCEL_REQUEST_PATH": str(
                    noncanonical_parent / ".." / "cancel-request.json"
                ),
            },
        )
        relative_cancel = _run_policy(
            f'require_disjoint_release_roots "{fixture_source}"',
            fake_bin=fake_bin,
            environment={
                "CARGO_TARGET_DIR": str(target),
                "IROHA_RELEASE_ARTIFACT_ROOT": str(artifacts),
                "IROHA_RELEASE_CANCEL_REQUEST_PATH": "cancel-request.json",
            },
        )
        inside_source_artifacts = fixture_source / "artifacts"
        inside_source_artifacts.mkdir(mode=0o700)
        source_overlap = _run_policy(
            f'require_external_release_artifact_root "{fixture_source}"',
            fake_bin=fake_bin,
            environment={"IROHA_RELEASE_ARTIFACT_ROOT": str(inside_source_artifacts)},
        )
        preserved_cancel = cancel.read_bytes()
    rejected = _run_policy(
        f'require_external_release_artifact_root "{REPO_ROOT}"',
        fake_bin=fake_bin,
        environment={"IROHA_RELEASE_ARTIFACT_ROOT": str(REPO_ROOT / "target")},
    )

    assert accepted.returncode == 0, accepted.stderr
    assert disjoint.returncode == 0, disjoint.stderr
    assert preserved_cancel == b'{"reason":"operator-request","schema_version":1}\n'
    assert nested.returncode == 2
    assert "must be disjoint" in nested.stderr
    for rejected_cancel in (
        nested_target_cancel,
        nested_artifact_cancel,
        nested_source_cancel,
    ):
        assert rejected_cancel.returncode == 2
        assert "outside source" in rejected_cancel.stderr
    assert noncanonical_cancel.returncode == 2
    assert "canonical private owner directory" in noncanonical_cancel.stderr
    assert relative_cancel.returncode == 2
    assert "must be absolute" in relative_cancel.stderr
    assert rejected.returncode == 2
    assert source_overlap.returncode == 2
    assert "outside source" in source_overlap.stderr


def test_artifact_directory_must_remain_below_authenticated_root() -> None:
    with tempfile.TemporaryDirectory(
        prefix="iroha-policy-artifact-tree-", dir=AUTHENTICATED_TEMP_BASE
    ) as temporary_root:
        root = Path(temporary_root) / "artifacts"
        root.mkdir(mode=0o700)
        nested = root / "run"
        nested.mkdir()
        fake_bin = root / "fake-bin"
        fake_bin.mkdir()
        future = root / "future" / "invocation"
        accepted_future = _run_policy(
            f'require_release_artifact_path "{future}"',
            fake_bin=fake_bin,
            environment={"IROHA_RELEASE_ARTIFACT_ROOT": str(root)},
        )
        accepted = _run_policy(
            f'require_release_artifact_directory "{nested}"',
            fake_bin=fake_bin,
            environment={"IROHA_RELEASE_ARTIFACT_ROOT": str(root)},
        )
        rejected = _run_policy(
            f'require_release_artifact_directory "{REPO_ROOT}"',
            fake_bin=fake_bin,
            environment={"IROHA_RELEASE_ARTIFACT_ROOT": str(root)},
        )
        escaped_future = REPO_ROOT / "future"
        rejected_future = _run_policy(
            f'require_release_artifact_path "{escaped_future}"',
            fake_bin=fake_bin,
            environment={"IROHA_RELEASE_ARTIFACT_ROOT": str(root)},
        )

    assert accepted_future.returncode == 0, accepted_future.stderr
    assert accepted.returncode == 0, accepted.stderr
    assert rejected.returncode == 2
    assert rejected_future.returncode == 2


def test_policy_source_contains_no_process_control_or_observation_escape_hatch() -> None:
    source = POLICY.read_text(encoding="utf-8")
    forbidden = (
        "SIGSTOP",
        "SIGTERM",
        "SIGKILL",
        "killpg",
        "pkill",
        "renice",
        "start_new_session",
        ".terminate(",
        ".kill(",
        "wait_for_external_cargo",
        "ps -",
        "pgrep",
        "/proc/",
        "process_snapshot",
        "sleep ",
    )
    assert all(token not in source for token in forbidden)
    assert source.count("acquire_invocation_cargo_lock() {") == 1
    assert source.count("release_invocation_cargo_lock() {") == 1
    assert source.count(
        'lock_path="${artifact_root}/.sumeragi-cargo.lock"'
    ) == 2
    assert source.count("lock.mkdir(mode=0o700)") == 1
    assert source.count("lock.rmdir()") == 1
    assert source.count("os.rmdir(lock.name, dir_fd=root_fd)") == 1
    assert source.count("acquire_invocation_cargo_lock || return $?") == 1
    assert source.count("release_invocation_cargo_lock || return $?") == 1
    assert source.count("trap _release_scoped_invocation_cargo_lock RETURN EXIT") == 1
    assert source.count('if "$IROHA_RELEASE_CARGO_BIN" "$@"; then') == 1
    assert 'for candidate in ("/private/tmp", "/tmp"):' in source
    assert "authenticate_temp_base(configured_base)" in source
    assert "protected_cache_roots" in source
    assert "metadata.st_uid != os.geteuid()" in source
    assert "metadata.st_mode & 0o077" in source
    assert "command cargo +1.93.1" not in source
    assert 'if ((cargo_prefix)) && [[ "$argument" == "--" ]]; then' in source
    assert "--target-dir|--target-dir=*|--manifest-path|--manifest-path=*|--config|--config=*" in source
    assert 'pinned_arguments=("$subcommand" -j1)' in source
    assert 'pinned_arguments+=("$@")' in source
    assert "local status" not in source
    assert "build|test|run|clippy)" in source
    assert "verus" not in source
