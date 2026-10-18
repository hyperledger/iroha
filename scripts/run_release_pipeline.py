#!/usr/bin/env -S python3 -I -S
"""
Orchestrate the canonical Iroha 3 release pipeline.

This helper generates release notes via git-cliff, invokes the bundle and image
builders for the canonical Iroha 3 profile, aggregates checksums,
produces the canonical manifest, and optionally stages publication commands
for release targets (SoraFS/SoraNet gateways or other URIs).

Example:
    ./scripts/run_release_pipeline.py \\
        --version <release-version> \\
        --previous-tag <previous-release-tag> \\
        --output-dir artifacts/releases/<release-version> \\
        --external-signer /opt/iroha/bin/authenticated-external-software-ed25519-sign \\
        --signing-public-key /run/iroha-release/ed25519-public.raw \\
        --trusted-signing-fingerprint <reviewed-lowercase-sha256> \\
        --release-manifest-verifier /opt/iroha/bin/iroha \\
        --trusted-release-manifest-verifier-sha256 <reviewed-lowercase-sha256> \\
        --publish-target iroha3=sorafs://releases/iroha3/v<release-version>
"""
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
import re
import shlex
import shutil
import stat
import subprocess
import sys
import types
from pathlib import Path
from typing import Callable, Dict, Iterable, List, Tuple, TypeVar
from urllib import error as urllib_error
from urllib import request as urllib_request


_SCRIPT_DIRECTORY = Path(os.path.abspath(__file__)).parent
_MAX_BOOTSTRAP_MODULE_BYTES = 2 * 1024 * 1024
_BOOTSTRAP_RELEASE_MODULE_SHA256 = {
    "release_artifact_contract": "66945051159d644f9507c5e6c4c264e2ece83cbcd4a4c8c1d21ef4115d380a0e",
    "release_manifest_signing": "4966d0b408f7d67d154b578875a1b0cb77584de77b4b1561e8704043b99b60fd",
    "publish_plan": "a9d15abb6eaea794f4c8fa27283667b5d75165fee60cd081a1373dab00257d70",
    # This source owns the reviewed surface seal. Its one literal digest is
    # normalized before hashing so resealing does not create a hash cycle with
    # this pipeline's bootstrap trust anchor.
    "check_release_feature_graph": "a0a5e6d559f60026bbd62a15564b93a7b43c58145cd8d95fe04e01362d2876ec",
}


def _bootstrap_identity(info: os.stat_result) -> tuple[int, ...]:
    return (
        info.st_dev,
        info.st_ino,
        info.st_mode,
        info.st_nlink,
        info.st_size,
        info.st_mtime_ns,
        info.st_ctime_ns,
    )


def _normalized_bootstrap_payload(name: str, payload: bytes) -> bytes:
    """Normalize only the review seal literal which intentionally changes."""

    if name != "check_release_feature_graph":
        return payload
    pattern = re.compile(
        rb'TRUSTED_RELEASE_SURFACE_SHA256\s*=\s*\(\s*"(?P<digest>[0-9a-f]{64})"\s*\)'
    )
    matches = tuple(pattern.finditer(payload))
    if len(matches) != 1:
        raise RuntimeError(
            "release pipeline bootstrap checker seal declaration is ambiguous"
        )
    match = matches[0]
    return (
        payload[: match.start("digest")]
        + b"0" * 64
        + payload[match.end("digest") :]
    )


def _stable_bootstrap_sources() -> dict[str, tuple[Path, bytes]]:
    """Capture every bootstrap helper before any of its bytes execute."""

    directory_flags = os.O_RDONLY | os.O_CLOEXEC | os.O_DIRECTORY | os.O_NOFOLLOW
    file_flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW
    repository = _SCRIPT_DIRECTORY.parent
    repository_before_path = repository.lstat()
    repository_fd = os.open(repository, directory_flags)
    scripts_fd = -1
    try:
        repository_before = os.fstat(repository_fd)
        if (
            not stat.S_ISDIR(repository_before.st_mode)
            or _bootstrap_identity(repository_before_path)
            != _bootstrap_identity(repository_before)
            or repository_before.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
        ):
            raise RuntimeError(
                "release pipeline repository must be one non-shared-writable directory"
            )
        scripts_before_path = os.stat(
            _SCRIPT_DIRECTORY.name,
            dir_fd=repository_fd,
            follow_symlinks=False,
        )
        scripts_fd = os.open(
            _SCRIPT_DIRECTORY.name, directory_flags, dir_fd=repository_fd
        )
        scripts_before = os.fstat(scripts_fd)
        if (
            not stat.S_ISDIR(scripts_before.st_mode)
            or _bootstrap_identity(scripts_before_path)
            != _bootstrap_identity(scripts_before)
            or scripts_before.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
        ):
            raise RuntimeError(
                "release pipeline scripts must be one non-shared-writable directory"
            )

        captured: dict[str, tuple[Path, bytes]] = {}
        for name, expected_sha256 in _BOOTSTRAP_RELEASE_MODULE_SHA256.items():
            filename = f"{name}.py"
            before_path = os.stat(filename, dir_fd=scripts_fd, follow_symlinks=False)
            descriptor = os.open(filename, file_flags, dir_fd=scripts_fd)
            try:
                before = os.fstat(descriptor)
                if (
                    not stat.S_ISREG(before.st_mode)
                    or _bootstrap_identity(before_path) != _bootstrap_identity(before)
                    or before.st_nlink != 1
                    or before.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
                    or before.st_size <= 0
                    or before.st_size > _MAX_BOOTSTRAP_MODULE_BYTES
                ):
                    raise RuntimeError(
                        "release pipeline bootstrap helper must be one singly linked, "
                        f"non-shared-writable regular file: {filename}"
                    )
                payload = bytearray()
                while True:
                    chunk = os.read(descriptor, 1024 * 1024)
                    if not chunk:
                        break
                    payload.extend(chunk)
                after = os.fstat(descriptor)
                after_path = os.stat(
                    filename, dir_fd=scripts_fd, follow_symlinks=False
                )
            finally:
                os.close(descriptor)
            if (
                len(payload) != before.st_size
                or _bootstrap_identity(before) != _bootstrap_identity(after)
                or _bootstrap_identity(before) != _bootstrap_identity(after_path)
            ):
                raise RuntimeError(
                    f"release pipeline bootstrap helper changed while read: {filename}"
                )
            normalized = _normalized_bootstrap_payload(name, bytes(payload))
            if hashlib.sha256(normalized).hexdigest() != expected_sha256:
                raise RuntimeError(
                    f"release pipeline bootstrap helper differs from review: {filename}"
                )
            captured[name] = (_SCRIPT_DIRECTORY / filename, bytes(payload))

        repository_after = os.fstat(repository_fd)
        repository_after_path = repository.lstat()
        scripts_after = os.fstat(scripts_fd)
        scripts_after_path = os.stat(
            _SCRIPT_DIRECTORY.name,
            dir_fd=repository_fd,
            follow_symlinks=False,
        )
        if (
            _bootstrap_identity(repository_before)
            != _bootstrap_identity(repository_after)
            or _bootstrap_identity(repository_before)
            != _bootstrap_identity(repository_after_path)
            or _bootstrap_identity(scripts_before) != _bootstrap_identity(scripts_after)
            or _bootstrap_identity(scripts_before)
            != _bootstrap_identity(scripts_after_path)
        ):
            raise RuntimeError(
                "release pipeline bootstrap directories changed while read"
            )
        return captured
    finally:
        if scripts_fd >= 0:
            os.close(scripts_fd)
        os.close(repository_fd)


def _load_release_modules() -> None:
    """Execute only the complete, previously captured bootstrap source set."""

    captured = _stable_bootstrap_sources()
    for name in _BOOTSTRAP_RELEASE_MODULE_SHA256:
        if name in sys.modules:
            continue
        path, payload = captured[name]
        module = types.ModuleType(name)
        module.__file__ = str(path)
        module.__package__ = ""
        sys.modules[name] = module
        exec(compile(payload, str(path), "exec"), module.__dict__)


_load_release_modules()

from publish_plan import (
    PublishPlanError,
    build_publish_plan,
    parse_target_map,
    validate_publish_plan,
    write_plan_files,
)
from release_artifact_contract import (
    ReleaseArtifactError,
    canonical_json_bytes,
    create_fresh_directory,
    exclusive_write_bytes,
    format_artifact_spec,
    format_source_date_epoch,
    parse_source_date_epoch,
    scan_inventory_paths,
    stable_hash_relative,
    require_release_cuda_source_inputs,
)
from release_manifest_signing import (
    ReleaseManifestSignatureError,
    sign_release_manifest,
)
from check_release_feature_graph import validate_trusted_release_surface_commit

REPO_ROOT = Path(__file__).resolve().parent.parent
RELEASE_PROFILE = "iroha3"
RELEASE_CONFIG = "nexus"
RELEASE_PROFILES = ((RELEASE_PROFILE, RELEASE_CONFIG),)
RELEASE_TARGETS = {
    "x86_64-unknown-linux-gnu": ("linux", "x86_64"),
    "aarch64-unknown-linux-gnu": ("linux", "aarch64"),
    "x86_64-apple-darwin": ("mac", "x86_64"),
    "aarch64-apple-darwin": ("mac", "aarch64"),
    "x86_64-pc-windows-msvc": ("win", "x86_64"),
}
IMAGE_PLATFORM_TARGETS = {
    "linux/amd64": ("linux", "amd64", "x86_64-unknown-linux-gnu"),
    "linux/arm64": ("linux", "arm64", "aarch64-unknown-linux-gnu"),
}
REQUIRED_IMAGE_PLATFORMS = tuple(IMAGE_PLATFORM_TARGETS)
AGGREGATE_TARGET = "multi-target"
RELEASE_SIGNING_PROVIDER = "authenticated_external_signer"
_FASTPQ_ROLLOUT_STAMP_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._+-]{0,127}")


class PipelineError(RuntimeError):
    """Fatal error raised during the release pipeline."""


_ACTION_RESULT = TypeVar("_ACTION_RESULT")
_HOSTILE_CHILD_ENVIRONMENT = frozenset(
    {
        "BASH_ENV",
        "BASHOPTS",
        "BASH_XTRACEFD",
        "CDPATH",
        "ENV",
        "GLOBIGNORE",
        "PS4",
        "PYTHONHOME",
        "PYTHONPATH",
        "CARGO_ENCODED_RUSTFLAGS",
        "CARGO_ENCODED_RUSTDOCFLAGS",
        "CARGO_HOME",
        "RUSTC",
        "RUSTC_WRAPPER",
        "RUSTC_WORKSPACE_WRAPPER",
        "RUSTDOC",
        "RUSTDOCFLAGS",
        "RUSTFLAGS",
        "SHELLOPTS",
    }
)


def _hostile_child_environment_name(name: str) -> bool:
    """Return whether one inherited name can inject release child behavior."""

    if name in _HOSTILE_CHILD_ENVIRONMENT or name.startswith(
        ("BASH_FUNC_", "CARGO_BUILD_")
    ):
        return True
    return name.startswith("CARGO_TARGET_") and name.endswith(
        ("_LINKER", "_RUNNER", "_RUSTFLAGS", "_RUSTDOCFLAGS")
    )


def _scrubbed_child_environment(
    overrides: Dict[str, str] | None = None,
) -> Dict[str, str]:
    """Return inherited release state without interpreter or shell hooks."""

    environment = os.environ.copy()
    if overrides is not None:
        environment.update(overrides)
    for name in tuple(environment):
        if _hostile_child_environment_name(name):
            environment.pop(name, None)
    environment["PYTHONNOUSERSITE"] = "1"
    return environment


def ensure_tool(name: str) -> None:
    if shutil.which(name) is None:
        raise PipelineError(f"Required tool '{name}' not found in PATH")


def render_command(cmd: Iterable[str]) -> str:
    """Render one payload-free, one-line command for release logs."""

    rendered: List[str] = []
    redact_next = False
    for raw in cmd:
        value = str(raw)
        if redact_next:
            value = "<redacted>"
            redact_next = False
        elif value.startswith("--") and "=" in value:
            option, option_value = value.split("=", 1)
            if any(
                marker in option.casefold()
                for marker in ("password", "token", "secret", "credential")
            ):
                value = f"{option}=<redacted>"
        elif value.startswith("--") and any(
            marker in value.casefold()
            for marker in ("password", "token", "secret", "credential")
        ):
            redact_next = True
        safe = "".join(
            character
            if ord(character) >= 0x20 and ord(character) != 0x7F
            else f"\\x{ord(character):02x}"
            for character in value
        )
        rendered.append(shlex.quote(safe))
    return " ".join(rendered)


def run(cmd: List[str], *, cwd: Path | None = None, env: Dict[str, str] | None = None) -> None:
    command = [str(argument) for argument in cmd]
    executable = Path(command[0])
    if (
        executable.suffix == ".py"
        and executable.resolve().is_relative_to(_SCRIPT_DIRECTORY)
    ):
        command = [
            sys.executable,
            "-I",
            "-S",
            str(_SCRIPT_DIRECTORY / "run_isolated_release_tool.py"),
            str(executable),
            *command[1:],
        ]
    display = render_command(command)
    print(f"[release-pipeline] $ {display}", flush=True)
    subprocess.run(
        command,
        check=True,
        cwd=cwd or REPO_ROOT,
        env=_scrubbed_child_environment(env),
    )


def release_subprocess_environment(source_date_epoch: int) -> Dict[str, str]:
    """Return the inherited release environment without interpreter/shell hooks."""

    environment = _scrubbed_child_environment()
    environment["SOURCE_DATE_EPOCH"] = str(source_date_epoch)
    return environment


def validate_release_source(commit: str, action: str) -> None:
    """Require the exact reviewed source immediately before a trusted action."""

    try:
        validate_trusted_release_surface_commit(REPO_ROOT, commit)
    except RuntimeError as exc:
        raise PipelineError(f"{action}: {exc}") from exc


def run_trusted_release_action(
    commit: str,
    action: str,
    operation: Callable[[], _ACTION_RESULT],
) -> _ACTION_RESULT:
    """Validate sealed source before starting one irreversible action."""

    validate_release_source(commit, action)
    return operation()


def repo_version() -> str:
    cargo_toml = REPO_ROOT / "Cargo.toml"
    for line in cargo_toml.read_text(encoding="utf-8").splitlines():
        if line.strip().startswith("version"):
            return line.split('"')[1]
    raise PipelineError("Unable to read version from Cargo.toml")


def _parse_prebuilt_matrix(
    specs: Iterable[str] | None,
    *,
    option: str,
    dimensions: set[str],
) -> Dict[str, Tuple[str, str]]:
    result: Dict[str, Tuple[str, str]] = {}
    for spec in specs or ():
        if "=" not in spec:
            raise PipelineError(
                f"Invalid {option} value; expected dimension=path@sha256:digest"
            )
        dimension, authenticated_path = spec.split("=", 1)
        path, separator, provenance_sha256 = authenticated_path.rpartition(
            "@sha256:"
        )
        if (
            dimension not in dimensions
            or not separator
            or not path
            or re.fullmatch(r"[0-9a-f]{64}", provenance_sha256) is None
        ):
            raise PipelineError(f"Invalid {option} release dimension")
        if dimension in result:
            raise PipelineError(f"Duplicate {option} identity '{dimension}'")
        if any(ord(character) < 0x20 or ord(character) == 0x7F for character in path):
            raise PipelineError(f"{option} paths must not contain controls")
        result[dimension] = (path, provenance_sha256)
    return result


def parse_bundle_prebuilt_dirs(
    specs: Iterable[str] | None,
) -> Dict[str, Tuple[str, str]]:
    return _parse_prebuilt_matrix(
        specs,
        option="--bundle-prebuilt-bin-dir",
        dimensions=set(RELEASE_TARGETS),
    )


def parse_image_prebuilt_dirs(
    specs: Iterable[str] | None,
) -> Dict[str, Tuple[str, str]]:
    return _parse_prebuilt_matrix(
        specs,
        option="--image-prebuilt-bin-dir",
        dimensions=set(IMAGE_PLATFORM_TARGETS),
    )


def release_signing_cli_args(
    external_signer: str | None,
    signing_public_key: str | None,
    trusted_signing_fingerprint: str | None,
) -> List[str]:
    """Return the complete private-key-free Ed25519 signer argument set."""

    values = (external_signer, signing_public_key, trusted_signing_fingerprint)
    supplied = sum(value is not None for value in values)
    if supplied not in (0, len(values)):
        raise PipelineError(
            "--external-signer, --signing-public-key, and "
            "--trusted-signing-fingerprint must be supplied together"
        )
    if supplied == 0:
        return []
    assert external_signer is not None
    assert signing_public_key is not None
    assert trusted_signing_fingerprint is not None
    if re.fullmatch(r"[0-9a-f]{64}", trusted_signing_fingerprint) is None:
        raise PipelineError(
            "--trusted-signing-fingerprint must be exactly 64 lowercase "
            "hexadecimal characters"
        )
    return [
        "--external-signer",
        external_signer,
        "--signing-public-key",
        signing_public_key,
        "--trusted-signing-fingerprint",
        trusted_signing_fingerprint,
    ]


def artifact_spec(
    profile: str,
    target: str,
    kind: str,
    artifact_format: str,
    path: str,
) -> str:
    try:
        return format_artifact_spec(
            {
                "profile": profile,
                "target": target,
                "kind": kind,
                "format": artifact_format,
                "path": path,
            }
        )
    except ReleaseArtifactError as exc:
        raise PipelineError(f"Invalid release artifact contract: {exc}") from exc


def copy_closed_tree(
    source: Path,
    output_root: Path,
    destination_prefix: str,
    *,
    dry_run: bool,
) -> None:
    """Copy one explicit evidence tree through the shared closed-tree contract."""

    command = [
        str(REPO_ROOT / "scripts" / "copy_release_tree.py"),
        "--source-root",
        str(source),
        "--output-root",
        str(output_root),
        "--destination-prefix",
        destination_prefix,
    ]
    if dry_run:
        print(f"[release-pipeline] (dry-run) {render_command(command)}")
    else:
        run(command)


def build_evidence_artifacts(
    *,
    evidence_stage: Path,
    release_root: Path,
    artifact_dir: Path,
    version: str,
    commit: str,
    source_date_epoch: int,
    zstd_path: str,
    trusted_zstd_sha256: str,
    dry_run: bool,
) -> list[str]:
    """Normalize and archive all generated evidence before aggregate closure."""

    archive_name = f"release-evidence-{version}.tar.zst"
    inventory_name = f"release-evidence-{version}.json"
    normalized_root = release_root / ".evidence-normalized"
    archive_path = artifact_dir / archive_name
    checksum_path = artifact_dir / f"{archive_name}.sha256"
    inventory_path = artifact_dir / inventory_name
    specs = [
        artifact_spec(
            "shared",
            AGGREGATE_TARGET,
            "release-evidence",
            "tar.zst",
            archive_name,
        ),
        artifact_spec(
            "shared",
            AGGREGATE_TARGET,
            "checksum",
            "sha256",
            f"{archive_name}.sha256",
        ),
        artifact_spec(
            "shared",
            AGGREGATE_TARGET,
            "release-evidence",
            "json",
            inventory_name,
        ),
    ]
    if dry_run:
        print(
            "[release-pipeline] (dry-run) normalize the exact evidence staging "
            f"inventory, build {archive_name}, and write {inventory_name}"
        )
        return specs

    source_paths = scan_inventory_paths(evidence_stage)
    if not source_paths:
        raise PipelineError("release evidence staging inventory is empty")
    create_fresh_directory(normalized_root, mode=0o700)
    copy_closed_tree(
        evidence_stage,
        normalized_root,
        "evidence",
        dry_run=False,
    )
    normalized_paths = scan_inventory_paths(normalized_root)
    rows = []
    for relative in normalized_paths:
        info = stable_hash_relative(normalized_root, relative)
        rows.append(
            {
                "path": relative,
                "sha256": info.sha256,
                "size": info.size,
            }
        )
    inventory = {
        "schema": "iroha.release_evidence_inventory",
        "schema_version": 1,
        "version": version,
        "commit": commit,
        "source_date_epoch": source_date_epoch,
        "built_at": format_source_date_epoch(source_date_epoch),
        "file_count": len(rows),
        "files": rows,
    }
    exclusive_write_bytes(
        inventory_path,
        canonical_json_bytes(inventory),
        mode=0o644,
    )
    archive_command = [
        str(REPO_ROOT / "scripts" / "build_release_tar_zst.py"),
        "--stage-root",
        str(normalized_root),
        "--output",
        str(archive_path),
        "--prefix",
        f"release-evidence-{version}",
        "--source-date-epoch",
        str(source_date_epoch),
        "--zstd",
        zstd_path,
        "--trusted-zstd-sha256",
        trusted_zstd_sha256,
    ]
    for relative in normalized_paths:
        archive_command.extend(["--file", relative])
    run(archive_command)
    run(
        [
            str(REPO_ROOT / "scripts" / "write_release_checksum.py"),
            "--artifact",
            str(archive_path),
            "--output",
            str(checksum_path),
            "--listed-name",
            archive_name,
        ]
    )
    shutil.rmtree(normalized_root)
    shutil.rmtree(evidence_stage)
    return specs


def export_fastpq_dashboard(grafana_url: str, token: str, destination: Path) -> None:
    api_url = grafana_url.rstrip("/") + "/api/dashboards/uid/fastpq-acceleration"
    req = urllib_request.Request(
        api_url,
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/json",
        },
    )
    try:
        with urllib_request.urlopen(req) as resp:
            payload = json.load(resp)
    except urllib_error.HTTPError as exc:
        raise PipelineError(f"Grafana export failed ({exc.code}): {exc.reason}") from exc
    except urllib_error.URLError as exc:
        raise PipelineError(f"Grafana export failed: {exc.reason}") from exc
    except json.JSONDecodeError as exc:
        raise PipelineError(f"Grafana response was not valid JSON: {exc}") from exc

    dashboard = payload.get("dashboard", payload)
    destination.write_text(json.dumps(dashboard, indent=2) + "\n", encoding="utf-8")


def summarize_fastpq_rollout_bundle(bundle_dir: Path, *, dry_run: bool) -> List[Dict[str, str]]:
    """Write reviewer-facing FASTPQ rollout summaries for each archived manifest."""

    manifests = sorted(bundle_dir.rglob("fastpq_bench_manifest.json"))
    summaries: List[Dict[str, str]] = []
    helper = REPO_ROOT / "scripts" / "fastpq" / "rollout_manifest_summary.py"
    for manifest in manifests:
        json_out = manifest.parent / "fastpq_rollout_summary.json"
        markdown_out = manifest.parent / "fastpq_rollout_summary.md"
        if dry_run:
            print(
                "[release-pipeline] (dry-run) summarize FASTPQ rollout manifest "
                f"{manifest} -> {json_out}, {markdown_out}"
            )
            continue
        run(
            [
                str(helper),
                "--manifest",
                str(manifest),
                "--bundle-dir",
                str(manifest.parent),
                "--repo-root",
                str(REPO_ROOT),
                "--json-out",
                str(json_out),
                "--markdown-out",
                str(markdown_out),
            ]
        )
        summary_entry: Dict[str, str] = {}
        try:
            summary_entry["manifest"] = str(manifest.relative_to(REPO_ROOT))
        except ValueError:
            summary_entry["manifest"] = str(manifest)
        try:
            summary_entry["json"] = str(json_out.relative_to(REPO_ROOT))
        except ValueError:
            summary_entry["json"] = str(json_out)
        try:
            summary_entry["markdown"] = str(markdown_out.relative_to(REPO_ROOT))
        except ValueError:
            summary_entry["markdown"] = str(markdown_out)
        summaries.append(summary_entry)
    return summaries


def evidence_inventory_label(path: Path, evidence_stage: Path) -> str:
    """Return the stable inventory path for an item in the closed evidence archive."""

    if ".." in path.parts or ".." in evidence_stage.parts:
        raise PipelineError(
            f"release evidence path contains lexical traversal: {path}"
        )
    absolute_path = path if path.is_absolute() else REPO_ROOT / path
    absolute_stage = (
        evidence_stage if evidence_stage.is_absolute() else REPO_ROOT / evidence_stage
    )
    try:
        resolved_path = absolute_path.resolve(strict=False)
        resolved_stage = absolute_stage.resolve(strict=False)
        relative = resolved_path.relative_to(resolved_stage)
    except (OSError, RuntimeError, ValueError) as exc:
        raise PipelineError(
            f"release evidence path is outside the staging tree: {path}"
        ) from exc
    return (Path("evidence") / relative).as_posix()


def validate_fastpq_rollout_stamp(stamp: str | None) -> str | None:
    """Require an optional FASTPQ rollout stamp to be one safe path component."""

    if stamp is None:
        return None
    if _FASTPQ_ROLLOUT_STAMP_RE.fullmatch(stamp) is None:
        raise PipelineError(
            "--fastpq-rollout-stamp must be exactly one bounded safe path component"
        )
    return stamp


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--version", required=True, help="Target release version (e.g., 2.0.0-rc.3 or v2.0.0-rc.3)")
    parser.add_argument(
        "--source-commit",
        help="Reviewed full 40- or 64-hex source commit.",
    )
    parser.add_argument(
        "--source-date-epoch",
        help="Canonical shared SOURCE_DATE_EPOCH for every release builder.",
    )
    parser.add_argument(
        "--previous-tag",
        help="Previous release tag for changelog generation (optional; should match the release line being prepared).",
    )
    parser.add_argument(
        "--output-dir",
        default="artifacts/releases",
        help="Base directory for release artifacts (default: artifacts/releases)",
    )
    parser.add_argument(
        "--git-cliff",
        help="Absolute path to the reviewed git-cliff executable.",
    )
    parser.add_argument(
        "--trusted-git-cliff-sha256",
        help="Reviewed lowercase SHA256 of the exact git-cliff executable.",
    )
    parser.add_argument(
        "--external-signer",
        help=(
            "Reviewed adapter for the authenticated external Ed25519 "
            "signer, invoked only with the final canonical aggregate-manifest "
            "path and a new raw-signature output path."
        ),
    )
    parser.add_argument(
        "--signing-public-key",
        help="Raw 32-byte Ed25519 public key used to verify external signatures.",
    )
    parser.add_argument(
        "--trusted-signing-fingerprint",
        help="Reviewed lowercase SHA256 of the exact raw Ed25519 public key.",
    )
    parser.add_argument(
        "--release-manifest-verifier",
        help="Direct path to the reviewed iroha native verifier.",
    )
    parser.add_argument(
        "--trusted-release-manifest-verifier-sha256",
        help="Reviewed lowercase SHA256 of the exact native verifier executable.",
    )
    parser.add_argument("--skip-bundles", action="store_true", help="Skip building tar.zst bundles.")
    parser.add_argument("--skip-images", action="store_true", help="Skip building Docker images.")
    parser.add_argument(
        "--bundle-prebuilt-bin-dir",
        action="append",
        help=(
            "Reviewed bundle binary directory as target=path@sha256:manifest; "
            "required exactly once for each mandatory target."
        ),
    )
    parser.add_argument(
        "--zstd",
        help="Absolute path to the reviewed zstd executable.",
    )
    parser.add_argument(
        "--trusted-zstd-sha256",
        help=(
            "Reviewed SHA256 of the exact zstd executable used by bundle "
            "and evidence builders."
        ),
    )
    parser.add_argument(
        "--image-platform",
        action="append",
        choices=tuple(IMAGE_PLATFORM_TARGETS),
        dest="image_platforms",
        help=(
            "Exact OCI image platform; both linux/amd64 and linux/arm64 are "
            "required unless images are skipped."
        ),
    )
    parser.add_argument(
        "--image-builder-base-image",
        help="Reviewed preprovisioned builder image ref@sha256 digest.",
    )
    parser.add_argument(
        "--image-runtime-base-image",
        help="Reviewed preprovisioned runtime image ref@sha256 digest.",
    )
    parser.add_argument(
        "--image-docker",
        help="Absolute path to the reviewed Docker CLI executable.",
    )
    parser.add_argument(
        "--trusted-docker-sha256",
        help="Reviewed lowercase SHA256 of the exact Docker CLI.",
    )
    parser.add_argument(
        "--image-buildx-plugin",
        help="Absolute path to the reviewed docker-buildx plugin.",
    )
    parser.add_argument(
        "--trusted-buildx-sha256",
        help="Reviewed lowercase SHA256 of the exact docker-buildx plugin.",
    )
    parser.add_argument(
        "--trusted-buildx-version",
        help="Exact reviewed one-line `docker buildx version` output.",
    )
    parser.add_argument(
        "--image-buildx-builder",
        help="Reviewed bounded buildx builder instance name.",
    )
    parser.add_argument(
        "--trusted-buildx-builder-inspect-sha256",
        help="Reviewed SHA256 of the exact buildx builder inspection output.",
    )
    parser.add_argument(
        "--image-prebuilt-bin-dir",
        action="append",
        help=(
            "Reviewed image binary directory as platform=path@sha256:manifest; "
            "required once for every required Linux image platform."
        ),
    )
    parser.add_argument(
        "--skip-privacy-dp",
        action="store_true",
        help="Skip regenerating the SoraNet privacy differential privacy artefacts.",
    )
    parser.add_argument(
        "--skip-nexus-lane-smoke",
        action="store_true",
        help="Skip ci/check_nexus_lane_smoke.sh + NX-18 evidence bundling.",
    )
    parser.add_argument(
        "--publish-target",
        action="append",
        help=(
            "Publish target URI for publication plan (optional). "
            "Use iroha3=uri or shared=uri for exact artifact classes; a single URI applies to both."
        ),
    )
    parser.add_argument(
        "--development-allow-unsigned-publish-plan",
        action="store_true",
        help=(
            "TEST/DEVELOPMENT ONLY: permit publish-plan generation from an "
            "unsigned aggregate manifest; never use this mode for promotion."
        ),
    )
    parser.add_argument(
        "--previous-publish-plan",
        help="Optional previous publish_plan.json used for diffing during validation.",
    )
    parser.add_argument(
        "--publish-probe-remote",
        action="store_true",
        help="Issue HTTP(S) HEAD requests during publish_plan validation for destinations with http/https scheme.",
    )
    parser.add_argument(
        "--publish-probe-command",
        help="Optional external probe command (use {destination} placeholder) to validate non-HTTP publish targets.",
    )
    parser.add_argument("--dry-run", action="store_true", help="Print commands without executing.")
    parser.add_argument(
        "--export-fastpq-grafana",
        action="store_true",
        help="Capture the fastpq-acceleration Grafana dashboard into the rollout bundle.",
    )
    parser.add_argument(
        "--fastpq-rollout-dir",
        default="artifacts/fastpq_rollouts",
        help="Base directory for FASTPQ rollout artefacts (default: artifacts/fastpq_rollouts).",
    )
    parser.add_argument(
        "--fastpq-rollout-stamp",
        help="Override timestamp folder for FASTPQ rollout artefacts (default combines timestamp + version).",
    )
    parser.add_argument(
        "--grafana-url",
        help="Grafana base URL used when exporting FASTPQ dashboards (required with --export-fastpq-grafana unless GRAFANA_URL is set).",
    )
    parser.add_argument(
        "--grafana-token-env",
        default="GRAFANA_TOKEN",
        help="Environment variable holding the Grafana API token (default: GRAFANA_TOKEN).",
    )
    parser.add_argument(
        "--fastpq-rollout-bundle",
        action="append",
        dest="fastpq_bundles",
        help="Path to a FASTPQ rollout bundle directory to archive alongside the release output (can be repeated).",
    )
    parser.add_argument(
        "--skip-fastpq-rollout-check",
        action="store_true",
        help="Skip validating FASTPQ rollout bundles even if provided.",
    )
    parser.add_argument(
        "--cbdc-rollout-dir",
        help=(
            "Explicit reviewed CBDC rollout directory validated and archived "
            "via ci/check_cbdc_rollout.sh."
        ),
    )
    parser.add_argument(
        "--skip-cbdc-rollout-check",
        action="store_true",
        help="Skip validating CBDC rollout bundles even if present.",
    )
    parser.add_argument(
        "--publish-android-sdk",
        action="store_true",
        help="Run scripts/publish_android_sdk.sh to include the Android Maven artifacts in the release bundle.",
    )
    parser.add_argument(
        "--android-sdk-repo-url",
        help="Remote Maven repository URL passed to scripts/publish_android_sdk.sh when publishing the Android SDK.",
    )
    parser.add_argument(
        "--android-sdk-username",
        help="Runtime repository username used with --android-sdk-repo-url.",
    )
    parser.add_argument(
        "--android-sdk-password",
        help="Repository password used with --android-sdk-repo-url.",
    )


    args = parser.parse_args()
    fastpq_rollout_stamp = validate_fastpq_rollout_stamp(
        args.fastpq_rollout_stamp
    )
    profiles = RELEASE_PROFILES
    signing_cli_args = release_signing_cli_args(
        args.external_signer,
        args.signing_public_key,
        args.trusted_signing_fingerprint,
    )
    verifier_values = (
        args.release_manifest_verifier,
        args.trusted_release_manifest_verifier_sha256,
    )
    verifier_value_count = sum(value is not None for value in verifier_values)
    if verifier_value_count not in (0, len(verifier_values)):
        raise PipelineError(
            "--release-manifest-verifier and "
            "--trusted-release-manifest-verifier-sha256 must be supplied together"
        )
    if (
        args.trusted_release_manifest_verifier_sha256 is not None
        and re.fullmatch(
            r"[0-9a-f]{64}",
            args.trusted_release_manifest_verifier_sha256,
        )
        is None
    ):
        raise PipelineError(
            "--trusted-release-manifest-verifier-sha256 must be exactly "
            "64 lowercase hexadecimal characters"
        )
    if bool(signing_cli_args) != bool(verifier_value_count):
        raise PipelineError(
            "aggregate signing requires both the complete external signer "
            "contract and the pinned native release-manifest verifier contract"
        )
    if args.development_allow_unsigned_publish_plan and not args.publish_target:
        raise PipelineError(
            "--development-allow-unsigned-publish-plan requires --publish-target"
        )
    if args.publish_target and signing_cli_args and args.development_allow_unsigned_publish_plan:
        raise PipelineError(
            "signed release inputs cannot be combined with "
            "--development-allow-unsigned-publish-plan"
        )
    if (
        args.publish_target
        and not signing_cli_args
        and not args.development_allow_unsigned_publish_plan
    ):
        raise PipelineError(
            "production publish plans require --external-signer, "
            "--signing-public-key, and --trusted-signing-fingerprint; use "
            "--development-allow-unsigned-publish-plan only for tests/development"
        )
    # TODO(parliament anonymous ballot, P6): production publish plans must require the
    # complete independent audit input set for the anonymous-ballot relations (registration
    # and vote proofs; design section 12.2) once its audit-manifest format and native
    # verifier exist; see the matching TODO in release_manifest_signing.sign_release_manifest.
    if not args.skip_cbdc_rollout_check and args.cbdc_rollout_dir is None:
        raise PipelineError(
            "--cbdc-rollout-dir is required unless "
            "--skip-cbdc-rollout-check is supplied"
        )
    evidence_requested = any(
        (
            not args.skip_privacy_dp,
            not args.skip_nexus_lane_smoke,
            args.publish_android_sdk,
            args.export_fastpq_grafana,
            bool(args.fastpq_bundles),
            not args.skip_cbdc_rollout_check,
        )
    )
    if (
        (not args.skip_bundles or evidence_requested)
        and (
            args.zstd is None
            or not Path(args.zstd).is_absolute()
            or args.trusted_zstd_sha256 is None
            or re.fullmatch(r"[0-9a-f]{64}", args.trusted_zstd_sha256) is None
        )
    ):
        raise PipelineError(
            "bundle/evidence lanes require absolute --zstd and "
            "--trusted-zstd-sha256 as 64 lowercase hex"
        )
    bundle_prebuilt_dirs: Dict[str, Tuple[str, str]] = {}
    if not args.skip_bundles:
        bundle_prebuilt_dirs = parse_bundle_prebuilt_dirs(
            args.bundle_prebuilt_bin_dir
        )
        expected_bundle_inputs = set(RELEASE_TARGETS)
        if set(bundle_prebuilt_dirs) != expected_bundle_inputs:
            raise PipelineError(
                "--bundle-prebuilt-bin-dir identities must be exactly the "
                "mandatory Linux/macOS/Windows target matrix"
            )
    elif args.bundle_prebuilt_bin_dir:
        raise PipelineError(
            "--bundle-prebuilt-bin-dir cannot be supplied with --skip-bundles"
        )
    if args.skip_bundles and args.skip_images:
        raise PipelineError(
            "at least one bundle or image release lane must be enabled"
        )
    image_prebuilt_dirs: Dict[str, Tuple[str, str]] = {}
    image_platforms = tuple(args.image_platforms or ())
    if not args.skip_images:
        image_required = {
            "--image-platform": image_platforms,
            "--image-builder-base-image": args.image_builder_base_image,
            "--image-runtime-base-image": args.image_runtime_base_image,
            "--image-docker": args.image_docker,
            "--trusted-docker-sha256": args.trusted_docker_sha256,
            "--image-buildx-plugin": args.image_buildx_plugin,
            "--trusted-buildx-sha256": args.trusted_buildx_sha256,
            "--trusted-buildx-version": args.trusted_buildx_version,
            "--image-buildx-builder": args.image_buildx_builder,
            "--trusted-buildx-builder-inspect-sha256": (
                args.trusted_buildx_builder_inspect_sha256
            ),
        }
        missing_image_controls = [
            option for option, value in image_required.items() if value is None
        ]
        if missing_image_controls:
            raise PipelineError(
                "image lanes require explicit reviewed controls: "
                + ", ".join(missing_image_controls)
            )
        if (
            len(image_platforms) != len(REQUIRED_IMAGE_PLATFORMS)
            or set(image_platforms) != set(REQUIRED_IMAGE_PLATFORMS)
        ):
            raise PipelineError(
                "image lanes require each of linux/amd64 and linux/arm64 "
                "exactly once"
            )
        for option, value in (
            ("--trusted-docker-sha256", args.trusted_docker_sha256),
            ("--trusted-buildx-sha256", args.trusted_buildx_sha256),
            (
                "--trusted-buildx-builder-inspect-sha256",
                args.trusted_buildx_builder_inspect_sha256,
            ),
        ):
            assert value is not None
            if re.fullmatch(r"[0-9a-f]{64}", value) is None:
                raise PipelineError(
                    f"{option} must be exactly 64 lowercase hexadecimal characters"
                )
        digest_reference = re.compile(
            r"[a-z0-9][a-z0-9._:/-]{0,200}@sha256:[0-9a-f]{64}"
        )
        for option, value in (
            ("--image-builder-base-image", args.image_builder_base_image),
            ("--image-runtime-base-image", args.image_runtime_base_image),
        ):
            assert value is not None
            if digest_reference.fullmatch(value) is None:
                raise PipelineError(
                    f"{option} must be a bounded lowercase ref@sha256 digest"
                )
        for option, value in (
            ("--image-docker", args.image_docker),
            ("--image-buildx-plugin", args.image_buildx_plugin),
        ):
            assert value is not None
            if not Path(value).is_absolute():
                raise PipelineError(f"{option} must be an absolute path")
        assert args.trusted_buildx_version is not None
        if (
            not args.trusted_buildx_version
            or len(args.trusted_buildx_version.encode("utf-8")) > 512
            or any(
                ord(character) < 0x20 or ord(character) == 0x7F
                for character in args.trusted_buildx_version
            )
        ):
            raise PipelineError(
                "--trusted-buildx-version must be one bounded control-free line"
            )
        assert args.image_buildx_builder is not None
        if re.fullmatch(
            r"[A-Za-z0-9][A-Za-z0-9._+-]{0,127}",
            args.image_buildx_builder,
        ) is None:
            raise PipelineError(
                "--image-buildx-builder must be a bounded safe token"
            )
        image_prebuilt_dirs = parse_image_prebuilt_dirs(
            args.image_prebuilt_bin_dir
        )
        expected_prebuilt_profiles = set(REQUIRED_IMAGE_PLATFORMS)
        if set(image_prebuilt_dirs) != expected_prebuilt_profiles:
            raise PipelineError(
                "--image-prebuilt-bin-dir identities must be exactly the "
                "required Linux image-platform matrix"
            )
    elif args.image_platforms or args.image_prebuilt_bin_dir:
        raise PipelineError(
            "image platform/prebuilt controls cannot be supplied with --skip-images"
        )
    if args.git_cliff is None or args.trusted_git_cliff_sha256 is None:
        raise PipelineError(
            "release changelog generation requires --git-cliff and "
            "--trusted-git-cliff-sha256"
        )
    if not Path(args.git_cliff).is_absolute():
        raise PipelineError("--git-cliff must be an absolute path")
    if re.fullmatch(r"[0-9a-f]{64}", args.trusted_git_cliff_sha256) is None:
        raise PipelineError(
            "--trusted-git-cliff-sha256 must be exactly 64 lowercase "
            "hexadecimal characters"
        )
    if args.source_commit is None or re.fullmatch(
        r"(?:[0-9a-f]{40}|[0-9a-f]{64})",
        args.source_commit,
    ) is None:
        raise PipelineError(
            "--source-commit is required as a full 40- or 64-hex identifier"
        )
    if args.source_date_epoch is None:
        raise PipelineError("--source-date-epoch is required")
    try:
        source_date_epoch = parse_source_date_epoch(args.source_date_epoch)
    except ReleaseArtifactError as exc:
        raise PipelineError(f"Invalid --source-date-epoch: {exc}") from exc
    try:
        publish_target_map = (
            parse_target_map(args.publish_target) if args.publish_target else None
        )
    except PublishPlanError as exc:
        raise PipelineError(f"Invalid publish target configuration: {exc}") from exc

    provided_version = args.version.lstrip("v")
    repo_ver = repo_version()
    if repo_ver != provided_version:
        raise PipelineError(
            f"Version mismatch: repository declares {repo_ver} but --version {provided_version} was provided."
        )
    ensure_tool("git")
    actual_commit = subprocess.check_output(
        ["git", "rev-parse", "HEAD"],
        cwd=REPO_ROOT,
        text=True,
    ).strip()
    commit = args.source_commit
    assert commit is not None
    if actual_commit != commit:
        raise PipelineError(
            "--source-commit does not match the repository HEAD"
        )
    if not args.dry_run:
        validate_release_source(commit, "Release source preflight failed")

    for target in RELEASE_TARGETS:
        require_release_cuda_source_inputs(REPO_ROOT, target)

    release_root = (
        Path(os.path.abspath(Path(args.output_dir).expanduser()))
        / provided_version
    )
    artifact_dir = release_root / "artifacts"
    evidence_stage = release_root / ".evidence-staging"
    if release_root.exists() or release_root.is_symlink():
        raise PipelineError(
            f"Release output must be a fresh path; refusing stale reuse: {release_root}"
        )
    if not args.dry_run:
        try:
            create_fresh_directory(release_root, mode=0o755)
            create_fresh_directory(artifact_dir, mode=0o755)
            if evidence_requested:
                create_fresh_directory(evidence_stage, mode=0o700)
        except ReleaseArtifactError as exc:
            raise PipelineError(
                f"Failed to create fresh release output: {exc}"
            ) from exc
    release_env = release_subprocess_environment(source_date_epoch)

    dp_script = REPO_ROOT / "scripts" / "telemetry" / "run_privacy_dp_notebook.sh"
    if not args.skip_privacy_dp:
        if not dp_script.is_file():
            raise PipelineError(f"Privacy DP script missing: {dp_script}")
        dp_cmd = [str(dp_script)]
        privacy_source = evidence_stage / "privacy_dp"
        dp_env = release_env.copy()
        dp_env["SORANET_PRIVACY_DP_ARTIFACT_DIR"] = str(privacy_source)
        if args.dry_run:
            print(f"[release-pipeline] (dry-run) {render_command(dp_cmd)}")
        else:
            run(dp_cmd, env=dp_env)
        if not args.dry_run and not privacy_source.is_dir():
            raise PipelineError(
                "privacy DP evidence directory was not created"
            )

    if args.skip_nexus_lane_smoke:
        print("[release-pipeline] skipping Nexus lane smoke evidence step")
    else:
        smoke_cmd = ["bash", str(REPO_ROOT / "ci" / "check_nexus_lane_smoke.sh")]
        nx_source = evidence_stage / "nx18"
        smoke_env = release_env.copy()
        smoke_env["NEXUS_LANE_SMOKE_EVIDENCE_DIR"] = str(nx_source)
        if args.dry_run:
            print(f"[release-pipeline] (dry-run) {render_command(smoke_cmd)}")
        else:
            run(smoke_cmd, env=smoke_env)
        if not args.dry_run and not nx_source.is_dir():
            raise PipelineError("NX-18 evidence directory was not created")

    built_at = format_source_date_epoch(source_date_epoch)

    changelog_path = artifact_dir / f"CHANGELOG-{provided_version}.md"
    cliff_args = [
        "-c",
        str(REPO_ROOT / "cliff.toml"),
        "--tag",
        f"v{provided_version}",
    ]
    if args.previous_tag:
        cliff_args.extend(["--previous-tag", args.previous_tag])
    cliff_cmd = [
        str(REPO_ROOT / "scripts" / "capture_release_command.py"),
        "--output",
        str(changelog_path),
        "--executable-root",
        str(Path(args.git_cliff).parent),
        "--executable-relative",
        Path(args.git_cliff).name,
        "--trusted-executable-sha256",
        args.trusted_git_cliff_sha256,
        "--",
        *cliff_args,
    ]

    if args.dry_run:
        print(f"[release-pipeline] (dry-run) {render_command(cliff_cmd)}")
    else:
        run(cliff_cmd)

    aggregate_specs: List[str] = [
        artifact_spec(
            "shared",
            AGGREGATE_TARGET,
            "changelog",
            "markdown",
            changelog_path.name,
        )
    ]
    bundle_paths: Dict[str, Dict[str, Path]] = {
        target: {} for target in RELEASE_TARGETS
    }
    for profile, config in profiles:
        if not args.skip_bundles:
            for target_triple, (os_tag, target_arch) in RELEASE_TARGETS.items():
                bundle_cmd = [
                    str(REPO_ROOT / "scripts" / "build_release_bundle.sh"),
                    "--artifacts-dir",
                    str(artifact_dir),
                    "--target",
                    target_triple,
                    "--source-commit",
                    commit,
                    "--source-date-epoch",
                    str(source_date_epoch),
                    "--trusted-zstd-sha256",
                    str(args.trusted_zstd_sha256),
                    "--zstd",
                    str(args.zstd),
                    "--prebuilt-bin-dir",
                    bundle_prebuilt_dirs[target_triple][0],
                    "--trusted-prebuilt-provenance-sha256",
                    bundle_prebuilt_dirs[target_triple][1],
                ]
                if args.dry_run:
                    print(
                        f"[release-pipeline] (dry-run) "
                        f"{render_command(bundle_cmd)}"
                    )
                else:
                    run(bundle_cmd, env=release_env)
                bundle_name = (
                    f"{profile}-{provided_version}-{os_tag}-{target_arch}.tar.zst"
                )
                builder_manifest_name = (
                    f"{profile}-{provided_version}-{os_tag}-{target_arch}"
                    "-manifest.json"
                )
                bundle_paths[target_triple][profile] = artifact_dir / bundle_name
                aggregate_specs.extend(
                    [
                        artifact_spec(
                            profile,
                            target_triple,
                            "bundle",
                            "tar.zst",
                            bundle_name,
                        ),
                        artifact_spec(
                            profile,
                            target_triple,
                            "checksum",
                            "sha256",
                            f"{bundle_name}.sha256",
                        ),
                        artifact_spec(
                            profile,
                            target_triple,
                            "builder-manifest",
                            "json",
                            builder_manifest_name,
                        ),
                    ]
                )

        if not args.skip_images:
            assert args.image_builder_base_image is not None
            assert args.image_runtime_base_image is not None
            assert args.image_docker is not None
            assert args.trusted_docker_sha256 is not None
            assert args.image_buildx_plugin is not None
            assert args.trusted_buildx_sha256 is not None
            assert args.trusted_buildx_version is not None
            assert args.image_buildx_builder is not None
            assert args.trusted_buildx_builder_inspect_sha256 is not None
            for image_platform in REQUIRED_IMAGE_PLATFORMS:
                image_os_tag, image_arch, image_target_triple = (
                    IMAGE_PLATFORM_TARGETS[image_platform]
                )
                image_cmd = [
                    str(REPO_ROOT / "scripts" / "build_release_image.sh"),
                    "--source-commit",
                    commit,
                    "--source-date-epoch",
                    str(source_date_epoch),
                    "--platform",
                    image_platform,
                    "--builder-base-image",
                    args.image_builder_base_image,
                    "--runtime-base-image",
                    args.image_runtime_base_image,
                    "--docker",
                    args.image_docker,
                    "--trusted-docker-sha256",
                    args.trusted_docker_sha256,
                    "--buildx-plugin",
                    args.image_buildx_plugin,
                    "--trusted-buildx-sha256",
                    args.trusted_buildx_sha256,
                    "--trusted-buildx-version",
                    args.trusted_buildx_version,
                    "--buildx-builder",
                    args.image_buildx_builder,
                    "--trusted-buildx-builder-inspect-sha256",
                    args.trusted_buildx_builder_inspect_sha256,
                    "--artifacts-dir",
                    str(artifact_dir),
                    "--prebuilt-bin-dir",
                    image_prebuilt_dirs[image_platform][0],
                    "--trusted-prebuilt-provenance-sha256",
                    image_prebuilt_dirs[image_platform][1],
                ]
                if args.dry_run:
                    print(
                        f"[release-pipeline] (dry-run) "
                        f"{render_command(image_cmd)}"
                    )
                else:
                    run(image_cmd, env=release_env)
                image_name = (
                    f"{profile}-{provided_version}-{image_os_tag}-{image_arch}"
                    "-image.oci.tar"
                )
                aggregate_specs.extend(
                    [
                        artifact_spec(
                            profile,
                            image_target_triple,
                            "image",
                            "oci-archive",
                            image_name,
                        ),
                        artifact_spec(
                            profile,
                            image_target_triple,
                            "checksum",
                            "sha256",
                            f"{image_name}.sha256",
                        ),
                        artifact_spec(
                            profile,
                            image_target_triple,
                            "builder-manifest",
                            "json",
                            (
                                f"{profile}-{provided_version}-{image_os_tag}-"
                                f"{image_arch}-image.json"
                            ),
                        ),
                    ]
                )

    if not args.skip_bundles:
        for target_triple, (os_tag, target_arch) in RELEASE_TARGETS.items():
            matrix_name = f"release_bundle_inventory-{os_tag}-{target_arch}.json"
            matrix_output = artifact_dir / matrix_name
            matrix_cmd = [
                str(REPO_ROOT / "ci" / "release_bundle_inventory.sh"),
                "--output",
                str(matrix_output),
                "--expect-version",
                provided_version,
                *[
                    str(bundle_paths[target_triple][profile])
                    for profile, _config in profiles
                ],
            ]
            if args.dry_run:
                print(
                    f"[release-pipeline] (dry-run) {render_command(matrix_cmd)}"
                )
            else:
                run(matrix_cmd)
            aggregate_specs.append(
                artifact_spec(
                    "shared",
                    target_triple,
                    "bundle-inventory",
                    "json",
                    matrix_name,
                )
            )

    if args.publish_android_sdk:
        android_dir = evidence_stage / "android"
        android_repo_dir = android_dir / "maven"
        android_sbom_dir = android_dir / "sbom"
        android_report_dir = android_dir / "publication"
        if not args.dry_run:
            android_dir.mkdir(mode=0o700, exist_ok=False)
        publish_cmd = [
            str(REPO_ROOT / "scripts" / "publish_android_sdk.sh"),
            "--version",
            provided_version,
            "--repo-dir",
            str(android_repo_dir),
            "--report-dir", str(android_report_dir),
            "--sbom-dir", str(android_sbom_dir),
        ]
        if args.android_sdk_repo_url:
            publish_cmd.extend(["--repo-url", args.android_sdk_repo_url])
        publisher_env = release_env.copy()
        if args.android_sdk_username:
            publisher_env["ANDROID_PUBLISH_REPO_USERNAME"] = args.android_sdk_username
        if args.android_sdk_password:
            publisher_env["ANDROID_PUBLISH_REPO_PASSWORD"] = args.android_sdk_password
        if args.dry_run:
            print(f"[release-pipeline] (dry-run) {render_command(publish_cmd)}")
        else:
            run_trusted_release_action(
                commit,
                "Android Maven publication refused changed release source",
                lambda: run(publish_cmd, env=publisher_env),
            )

        if args.dry_run:
            print(f"[release-pipeline] (dry-run) retain signed Android SBOM bundle {android_sbom_dir}")
        elif not android_sbom_dir.is_dir():
            raise PipelineError(f"Android SBOM bundle not found at {android_sbom_dir}")

        readme_path = android_dir / "README.txt"
        summary_path = android_report_dir / "publish_summary.json"
        checksum_path = android_report_dir / "checksums.txt"
        if not args.dry_run:
            lines = [
                "Android SDK release bundle",
                f"Version: {provided_version}",
                f"Generated: {built_at}",
                "Local Maven repo: maven",
                "SBOM bundle: sbom",
            ]
            if args.android_sdk_repo_url:
                lines.append("Remote Maven publication: completed")
            if summary_path.is_file():
                lines.append("Summary: publication/publish_summary.json")
            if checksum_path.is_file():
                lines.append("Checksums: publication/checksums.txt")
            exclusive_write_bytes(
                readme_path,
                ("\n".join(lines) + "\n").encode("utf-8"),
                mode=0o644,
            )
        else:
            print(f"[release-pipeline] (dry-run) write Android README to {readme_path}")

    fastpq_grafana_rel: str | None = None
    fastpq_rollout_base = Path(
        os.path.abspath(Path(args.fastpq_rollout_dir).expanduser())
    )
    if args.export_fastpq_grafana:
        grafana_url = args.grafana_url or os.environ.get("GRAFANA_URL")
        if not grafana_url:
            raise PipelineError("Grafana URL not provided (use --grafana-url or set GRAFANA_URL).")
        token = os.environ.get(args.grafana_token_env)
        if not token:
            raise PipelineError(
                f"Grafana token not found in environment variable {args.grafana_token_env}."
            )
        stamp = fastpq_rollout_stamp or (
            f"{dt.datetime.fromtimestamp(source_date_epoch, tz=dt.timezone.utc):%Y%m%dT%H%MZ}_"
            f"{provided_version}"
        )
        rollout_dir = evidence_stage / "fastpq_grafana" / stamp
        dashboard_path = rollout_dir / "grafana_fastpq_acceleration.json"
        alerts_dst = rollout_dir / "alerts"
        tests_dst = alerts_dst / "tests"
        repo_alert = REPO_ROOT / "dashboards" / "alerts" / "fastpq_acceleration_rules.yml"
        repo_test = (
            REPO_ROOT
            / "dashboards"
            / "alerts"
            / "tests"
            / "fastpq_acceleration_rules.test.yml"
        )
        if args.dry_run:
            print(
                f"[release-pipeline] (dry-run) export Grafana dashboard to {dashboard_path} "
                f"and copy alert pack into {alerts_dst}"
            )
        else:
            rollout_dir.mkdir(parents=True, exist_ok=False)
            export_fastpq_dashboard(grafana_url, token, dashboard_path)
            alerts_dst.mkdir(parents=True, exist_ok=True)
            run(
                [
                    str(REPO_ROOT / "scripts" / "copy_release_file.py"),
                    "--source",
                    str(repo_alert),
                    "--output",
                    str(alerts_dst / "fastpq_acceleration_rules.yml"),
                    "--mode",
                    "0644",
                ]
            )
            tests_dst.mkdir(parents=True, exist_ok=True)
            run(
                [
                    str(REPO_ROOT / "scripts" / "copy_release_file.py"),
                    "--source",
                    str(repo_test),
                    "--output",
                    str(tests_dst / "fastpq_acceleration_rules.test.yml"),
                    "--mode",
                    "0644",
                ]
            )
        fastpq_grafana_rel = evidence_inventory_label(rollout_dir, evidence_stage)

    archived_fastpq: List[Dict[str, object]] = []
    if args.fastpq_bundles:
        script = REPO_ROOT / "ci" / "check_fastpq_rollout.sh"
        release_rollout_root = evidence_stage / "fastpq_rollouts"
        for bundle in args.fastpq_bundles:
            bundle_path = Path(os.path.abspath(Path(bundle).expanduser()))
            if not bundle_path.exists():
                raise PipelineError(f"FASTPQ rollout bundle not found: {bundle_path}")
            if not args.dry_run:
                scan_inventory_paths(bundle_path)
            if not args.skip_fastpq_rollout_check and not args.dry_run:
                env = os.environ.copy()
                env["FASTPQ_ROLLOUT_BUNDLE"] = str(bundle_path)
                run([str(script)], env=env)
            try:
                rel_bundle = bundle_path.relative_to(fastpq_rollout_base)
            except ValueError:
                rel_bundle = Path(bundle_path.name)
            dest_dir = release_rollout_root / rel_bundle
            if args.dry_run:
                print(
                    f"[release-pipeline] (dry-run) archive FASTPQ rollout bundle {bundle_path} -> {dest_dir}"
                )
            else:
                copy_closed_tree(
                    bundle_path,
                    evidence_stage,
                    (Path("fastpq_rollouts") / rel_bundle).as_posix(),
                    dry_run=False,
                )
            summary_paths = summarize_fastpq_rollout_bundle(dest_dir, dry_run=args.dry_run)
            summary_paths = [
                {
                    kind: evidence_inventory_label(Path(path), evidence_stage)
                    for kind, path in summary_paths_for_manifest.items()
                }
                for summary_paths_for_manifest in summary_paths
            ]
            bundle_label = evidence_inventory_label(dest_dir, evidence_stage)
            archived_fastpq.append(
                {
                    "bundle": bundle_label,
                    "summaries": summary_paths,
                }
            )

    cbdc_validation_rel: str | None = None
    if not args.skip_cbdc_rollout_check:
        assert args.cbdc_rollout_dir is not None
        cbdc_dir = Path(
            os.path.abspath(Path(args.cbdc_rollout_dir).expanduser())
        )
        cbdc_inventory = (
            scan_inventory_paths(cbdc_dir) if not args.dry_run else []
        )
        manifests = [
            relative
            for relative in cbdc_inventory
            if Path(relative).name == "cbdc.manifest.json"
        ]
        if args.dry_run:
            manifests = ["<reviewed-cbdc-manifest>"]
        if manifests:
            script = REPO_ROOT / "ci" / "check_cbdc_rollout.sh"
            if args.dry_run:
                print(
                    f"[release-pipeline] (dry-run) CBDC_ROLLOUT_BUNDLE={cbdc_dir} {script}"
                )
            else:
                env = os.environ.copy()
                env["CBDC_ROLLOUT_BUNDLE"] = str(cbdc_dir)
                run([str(script)], env=env)
                copy_closed_tree(
                    cbdc_dir,
                    evidence_stage,
                    "cbdc_rollouts",
                    dry_run=False,
                )
            cbdc_validation_rel = evidence_inventory_label(
                evidence_stage / "cbdc_rollouts", evidence_stage
            )
        else:
            raise PipelineError(
                f"CBDC rollout directory has no cbdc.manifest.json: {cbdc_dir}"
            )

    if evidence_requested:
        assert args.trusted_zstd_sha256 is not None
        aggregate_specs.extend(
            build_evidence_artifacts(
                evidence_stage=evidence_stage,
                release_root=release_root,
                artifact_dir=artifact_dir,
                version=provided_version,
                commit=commit,
                source_date_epoch=source_date_epoch,
                zstd_path=str(args.zstd),
                trusted_zstd_sha256=args.trusted_zstd_sha256,
                dry_run=args.dry_run,
            )
        )

    aggregate_paths = [spec.split(":", 4)[4] for spec in aggregate_specs]
    sha_path = artifact_dir / "SHA256SUMS"
    checksum_args = [
        str(REPO_ROOT / "scripts" / "write_release_sha256sums.py"),
        "--artifacts-dir",
        str(artifact_dir),
        "--output",
        str(sha_path),
    ]
    for relative_path in aggregate_paths:
        checksum_args.extend(["--file", relative_path])
    if args.dry_run:
        print(f"[release-pipeline] (dry-run) {render_command(checksum_args)}")
    else:
        run(checksum_args)

    manifest_args = [
        str(REPO_ROOT / "scripts" / "generate_release_manifest.py"),
        "--artifacts-dir",
        str(artifact_dir),
        "--version",
        provided_version,
        "--commit",
        commit,
        "--source-date-epoch",
        str(source_date_epoch),
        "--os-tag",
        "multi",
        "--arch",
        "multi",
        "--output",
        str(release_root / "release_manifest.json"),
    ]
    for spec in aggregate_specs:
        manifest_args.extend(["--artifact", spec])

    if args.dry_run:
        print(f"[release-pipeline] (dry-run) {render_command(manifest_args)}")
    else:
        run(manifest_args)

    manifest_path = release_root / "release_manifest.json"
    aggregate_signature_path = release_root / "release_manifest.json.sig"
    aggregate_public_key_path = release_root / "release_manifest.json.pub"
    aggregate_signing_result: Dict[str, object] | None = None
    if signing_cli_args:
        if args.dry_run:
            print(
                "[release-pipeline] (dry-run) sign final aggregate manifest "
                f"{manifest_path} via {args.external_signer}; verify against "
                f"{args.trusted_signing_fingerprint}; write "
                f"{aggregate_signature_path} and raw key "
                f"{aggregate_public_key_path}; verify with "
                f"{args.release_manifest_verifier} pinned to "
                f"{args.trusted_release_manifest_verifier_sha256}"
            )
        else:
            assert args.external_signer is not None
            assert args.signing_public_key is not None
            assert args.trusted_signing_fingerprint is not None
            assert args.release_manifest_verifier is not None
            assert args.trusted_release_manifest_verifier_sha256 is not None
            validate_release_source(
                commit,
                "Aggregate manifest signing refused changed release source",
            )
            try:
                aggregate_signing_result = sign_release_manifest(
                    manifest_path,
                    Path(args.external_signer),
                    Path(args.signing_public_key),
                    args.trusted_signing_fingerprint,
                    aggregate_signature_path,
                    aggregate_public_key_path,
                    Path(args.release_manifest_verifier),
                    args.trusted_release_manifest_verifier_sha256,
                )
                aggregate_signing_result.update(
                    {
                        "signing_provider": RELEASE_SIGNING_PROVIDER,
                    }
                )
            except ReleaseManifestSignatureError as exc:
                raise PipelineError(
                    f"Aggregate release-manifest signing failed: {exc}"
                ) from exc

    if publish_target_map:
        if args.dry_run:
            mode = (
                "verified aggregate Ed25519 manifest"
                if signing_cli_args
                else "explicit development-only unsigned manifest"
            )
            print(
                f"[release-pipeline] (dry-run) publish plan for targets "
                f"{publish_target_map} using {mode} would be written to {release_root}"
            )
        else:
            try:
                plan = build_publish_plan(
                    manifest_path=manifest_path,
                    artifacts_dir=artifact_dir,
                    target_map=publish_target_map,
                    manifest_signature_path=aggregate_signature_path
                    if signing_cli_args
                    else None,
                    manifest_public_key_path=aggregate_public_key_path
                    if signing_cli_args
                    else None,
                    trusted_signing_fingerprint=args.trusted_signing_fingerprint
                    if signing_cli_args
                    else None,
                    release_manifest_verifier_path=Path(
                        args.release_manifest_verifier
                    )
                    if signing_cli_args
                    else None,
                    trusted_release_manifest_verifier_sha256=(
                        args.trusted_release_manifest_verifier_sha256
                        if signing_cli_args
                        else None
                    ),
                    development_allow_unsigned_manifest=(
                        args.development_allow_unsigned_publish_plan
                    ),
                )
                plan_paths = write_plan_files(plan, release_root)
                report = validate_publish_plan(
                    plan_path=plan_paths["json"],
                    previous_plan_path=Path(args.previous_publish_plan)
                    if args.previous_publish_plan
                    else None,
                    probe_remote=args.publish_probe_remote,
                    probe_command=args.publish_probe_command,
                    manifest_path=manifest_path,
                    artifacts_dir=artifact_dir,
                    target_map=publish_target_map,
                    manifest_signature_path=aggregate_signature_path
                    if signing_cli_args
                    else None,
                    manifest_public_key_path=aggregate_public_key_path
                    if signing_cli_args
                    else None,
                    trusted_signing_fingerprint=(
                        args.trusted_signing_fingerprint
                        if signing_cli_args
                        else None
                    ),
                    release_manifest_verifier_path=Path(
                        args.release_manifest_verifier
                    )
                    if signing_cli_args
                    else None,
                    trusted_release_manifest_verifier_sha256=(
                        args.trusted_release_manifest_verifier_sha256
                        if signing_cli_args
                        else None
                    ),
                    development_allow_unsigned_manifest=(
                        args.development_allow_unsigned_publish_plan
                    ),
                )
            except (PublishPlanError, OSError, json.JSONDecodeError) as exc:
                raise PipelineError(f"Publish plan generation failed: {exc}") from exc
            report_path = release_root / "publish_plan_report.json"
            try:
                exclusive_write_bytes(
                    report_path,
                    canonical_json_bytes(report),
                    mode=0o644,
                )
            except ReleaseArtifactError as exc:
                raise PipelineError(
                    f"Publish plan report write failed: {exc}"
                ) from exc
            report_txt = release_root / "publish_plan_report.txt"
            report_lines = [
                f"status: {report.get('status')}",
                f"local failures: {len(report.get('local_failures', []))}",
                f"remote failures: {len(report.get('remote_failures', []))}",
                f"diff: {report.get('diff') or {}}",
            ]
            try:
                exclusive_write_bytes(
                    report_txt,
                    ("\n".join(report_lines) + "\n").encode("utf-8"),
                    mode=0o644,
                )
            except ReleaseArtifactError as exc:
                raise PipelineError(
                    f"Publish plan text report write failed: {exc}"
                ) from exc
            if report.get("status") != "ok":
                raise PipelineError(
                    "Publish plan validation failed; see publish_plan_report.json"
                )

    if not args.dry_run:
        validate_release_source(
            commit, "Release source changed during pipeline execution"
        )

    summary = release_root / "SUMMARY.txt"
    lines = [
        f"Version: {provided_version}",
        f"Commit: {commit}",
        f"Built at: {built_at}",
        f"Artifacts dir: {artifact_dir}",
        f"Changelog: {changelog_path.name}",
        f"Manifest: release_manifest.json",
        f"Profiles: {', '.join(f'{p}={c}' for p, c in profiles)}",
    ]
    if signing_cli_args:
        lines.append(
            "Release signatures: externally produced and locally verified as "
            f"Ed25519 ({args.trusted_signing_fingerprint})"
        )
        lines.append(
            "Aggregate manifest signature: "
            + (
                "release_manifest.json.sig (verified)"
                if aggregate_signing_result is not None
                else "planned in dry-run"
            )
        )
        lines.append("Aggregate manifest public key: release_manifest.json.pub")
        lines.append(
            "Aggregate manifest signing provider: " + RELEASE_SIGNING_PROVIDER
        )
        lines.append(
            "Aggregate manifest native verifier: "
            f"{args.release_manifest_verifier} "
            f"({args.trusted_release_manifest_verifier_sha256})"
        )
    else:
        lines.append("Release signatures: absent (artifact set is not promotable)")
        if args.development_allow_unsigned_publish_plan:
            lines.append(
                "Aggregate manifest verification: development-unsigned "
                "(not promotable)"
            )
    if args.skip_privacy_dp:
        lines.append("Privacy DP notebook: skipped (--skip-privacy-dp)")
    else:
        lines.append("Privacy DP notebook: refreshed")
    if publish_target_map:
        lines.append("Publish targets:")
        for profile, target in sorted(publish_target_map.items()):
            lines.append(f"  - {profile}: {target}")
        lines.append("Publish plan: publish_plan.{json,sh,txt}")
        lines.append("Publish plan report: publish_plan_report.json")
        lines.append("Publish plan report (text): publish_plan_report.txt")
    if fastpq_grafana_rel:
        lines.append(f"FASTPQ Grafana release-evidence path: {fastpq_grafana_rel}")
    if archived_fastpq:
        lines.append("FASTPQ rollout bundles in release evidence:")
        for entry in archived_fastpq:
            bundle = entry.get("bundle", "")
            lines.append(f"  - {bundle}")
            for summary_path in entry.get("summaries", []):
                if isinstance(summary_path, dict):
                    markdown_path = summary_path.get("markdown")
                    if markdown_path:
                        lines.append(f"    Summary: {markdown_path}")
    if cbdc_validation_rel:
        lines.append(f"CBDC rollout release-evidence path: {cbdc_validation_rel}")
    if args.dry_run:
        print(f"[release-pipeline] (dry-run) write release summary {summary}")
    else:
        try:
            exclusive_write_bytes(
                summary,
                ("\n".join(lines) + "\n").encode("utf-8"),
                mode=0o644,
            )
        except ReleaseArtifactError as exc:
            raise PipelineError(f"Release summary write failed: {exc}") from exc

    print("[release-pipeline] Completed. Artifacts staged under", release_root)
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except ReleaseArtifactError as exc:
        print(f"[release-pipeline] release artifact error: {exc}", file=sys.stderr)
        sys.exit(1)
    except PipelineError as exc:
        print(f"[release-pipeline] error: {exc}", file=sys.stderr)
        sys.exit(1)
    except subprocess.CalledProcessError as exc:
        print(f"[release-pipeline] command failed with exit code {exc.returncode}", file=sys.stderr)
        sys.exit(exc.returncode)
