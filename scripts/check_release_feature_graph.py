#!/usr/bin/env python3
"""Reject development-only Iroha features from shipping dependency graphs."""

from __future__ import annotations

import argparse
import ast
import hashlib
import itertools
import json
import os
import re
import shlex
import stat
import subprocess
import sys
from pathlib import Path
from typing import NamedTuple

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - Python 3.10 CI
    import tomli as tomllib


BASELINE_PACKAGES = (
    "iroha_genesis",
    "ivm",
)
DOCKERFILE = Path("Dockerfile")
SORAFS_RELEASE_WORKFLOW = Path(".github/workflows/sorafs-cli-release.yml")
SORAFS_CLI_VERBATIM_PAYLOADS = (
    Path("release/version-map.toml"),
    Path("specs/sorafs/runbooks/release_rollback_yank.md"),
    Path("CHANGELOG.md"),
    Path("LICENSE"),
)
SORAFS_REFERENCE_VALIDATOR_VERBATIM_PAYLOADS = (
    Path("crates/sorafs_manifest/include/sorafs_reference.h"),
)
RELEASE_PIPELINE_SEMANTIC_INPUTS = (Path("cliff.toml"),)
OPTIONAL_SIGNED_RELEASE_EVIDENCE_INPUTS = (
    Path("dashboards/alerts/fastpq_acceleration_rules.yml"),
    Path("dashboards/alerts/tests/fastpq_acceleration_rules.test.yml"),
)
DOCKER_PUBLISH_WORKFLOWS = (
    Path(".github/workflows/publish.yml"),
    Path(".github/workflows/publish_custom.yml"),
    Path(".github/workflows/publish_dev.yml"),
    Path(".github/workflows/publish_xx.yml"),
)
NONSHIPPING_DOCKER_PUBLISH_WORKFLOWS = {
    Path(".github/workflows/ci_image.yml"): (
        "CI builder image only; it does not compile or package Iroha runtime artifacts"
    ),
}
NATIVE_ARTIFACT_WORKFLOWS = (
    SORAFS_RELEASE_WORKFLOW,
    Path(".github/workflows/pr_csharp.yml"),
    Path(".github/workflows/mobile_sdk_artifacts.yml"),
    Path(".github/workflows/sorafs-orchestrator-sdk.yml"),
)
# These exact builds produce test subprocesses used by core-jvm's
# FixtureGeneratorRunner through IROHA_KOTLIN_FIXTURE_GEN_BIN. The reviewed
# workflows upload SDK artifacts, ABI manifests and test reports, not these binaries.
# Keep this classification scoped to the sealed consumer declaration and exact
# Cargo command; selecting the same package anywhere else remains shipping and
# therefore fails the positive shipping policy below.
NONSHIPPING_WORKFLOW_BUILD_COMMANDS = {
    Path(".github/workflows/mobile_sdk_artifacts.yml"): frozenset({
        (
            "cargo", "build", "--locked", "-p", "kotlin-fixture-gen",
            "--features", "dev-tools", "--bin", "kotlin-fixture-gen",
        ),
    }),
    Path(".github/workflows/sorafs-orchestrator-sdk.yml"): frozenset({
        (
            "cargo", "build", "--locked", "--offline", "--release",
            "-p", "kotlin-fixture-gen", "--features", "dev-tools",
            "--bin", "kotlin-fixture-gen", "--target", "$target",
            "--target-dir", "$native_root/cargo-target",
        ),
    }),
}
NATIVE_BRIDGE_BUILD_SCRIPT = Path("scripts/build_norito_xcframework.sh")
NATIVE_BRIDGE_CALLER_WORKFLOWS = (
    Path(".github/workflows/mobile_sdk_artifacts.yml"),
    Path(".github/workflows/sorafs-orchestrator-sdk.yml"),
)
ANDROID_NATIVE_BUILD_OWNER = Path("kotlin/client-android/build.gradle.kts")
ANDROID_HERMETIC_RUNNER = Path("scripts/run_mobile_hermetic_command.py")
APPLE_DEVELOPMENT_BRIDGE_LINK = Path("IrohaSwift/NoritoBridge.xcframework")
APPLE_DEVELOPMENT_BRIDGE_TARGET = "../dist/NoritoBridge.xcframework"
RELEASE_BUNDLE_SCRIPT = Path("scripts/build_release_bundle.sh")
RELEASE_IMAGE_SCRIPT = Path("scripts/build_release_image.sh")
ISOLATED_RELEASE_RUNNER = Path("scripts/run_isolated_release_tool.py")
CANONICAL_RELEASE_PIPELINE = Path("scripts/run_release_pipeline.py")
NIX_RELEASE_OWNER = Path("flake.nix")
NIX_RELEASE_OWNER_PATHS = (NIX_RELEASE_OWNER, Path("flake.lock"))
NIX_APPIMAGE_OWNER_ROOT = Path("nix-appimage")
DOTNET_REPOSITORY_ANCESTOR_OWNER_PATHS = tuple(
    Path(name)
    for name in (
        "Directory.Build.props",
        "Directory.Build.targets",
        "Directory.Build.rsp",
        "Directory.Packages.props",
        "Directory.Solution.props",
        "Directory.Solution.targets",
        "global.json",
    )
)
DOTNET_NUGET_CONFIG_PATHSPEC = ":(top,icase)NuGet.Config"
# Git's ordinary untracked-file inventory intentionally honors ignore rules.
# Build tools do not: these names are auto-loaded even when they are ignored.
# Enumerate them separately without excludes so a local override cannot sit
# outside the reviewed release-source seal.
AUTOLOADED_BUILD_CONTROL_PATHSPECS = (
    # Python places a launched script's directory on sys.path before the
    # standard library unless isolated safe-path mode is used. Seal ignored
    # top-level modules too so legacy helper invocations cannot hide a stdlib
    # or site-customization shadow outside the reviewed inventory.
    ":(top,glob)scripts/*.py",
    ":(top,glob)scripts/**/*.py",
    ":(top,literal).cargo/config",
    ":(top,literal).cargo/config.toml",
    # Release validation loads this profile before executing its selected tests.
    ":(top,literal).config/nextest.toml",
    ":(top,glob,icase)csharp/**/Directory.Build.props",
    ":(top,glob,icase)csharp/**/Directory.Build.targets",
    ":(top,glob,icase)csharp/**/Directory.Build.rsp",
    ":(top,glob,icase)csharp/**/Directory.Packages.props",
    *(f":(top,literal){path.as_posix()}" for path in DOTNET_REPOSITORY_ANCESTOR_OWNER_PATHS),
    *(f":(top,icase)csharp/{path.as_posix()}" for path in DOTNET_REPOSITORY_ANCESTOR_OWNER_PATHS),
    DOTNET_NUGET_CONFIG_PATHSPEC,
    ":(top,icase)csharp/NuGet.Config",
)
TRUSTED_RELEASE_SURFACE_SHA256 = (
    "764493ca996861079788bfe15607311c250a6890c3226ac28626b5d8b5beba2a"
)
HOSTILE_CARGO_ENVIRONMENT = frozenset(
    {
        "CARGO_ENCODED_RUSTFLAGS",
        "CARGO_ENCODED_RUSTDOCFLAGS",
        "CARGO_HOME",
        "RUSTC",
        "RUSTC_WRAPPER",
        "RUSTC_WORKSPACE_WRAPPER",
        "RUSTDOC",
        "RUSTDOCFLAGS",
        "RUSTFLAGS",
    }
)
FORBIDDEN_FEATURES = (
    'irohad_lib feature "mutation-testing"',
    'iroha feature "test-fixtures"',
    'iroha_core feature "iroha-core-tests"',
    'iroha_core_zk feature "test-utils"',
    'iroha_core_privacy feature "test-utils"',
    'iroha_core_timed_ovn feature "test-utils"',
    'iroha_crypto feature "bfv-test-fixtures"',
    'iroha_data_model feature "test-fixtures"',
    'iroha_p2p feature "test-fixtures"',
    'iroha_sccp feature "test-fixtures"',
)
# Positive policy for every package that an official shipping declaration may
# select. Values include the complete, reviewed root-package feature closure
# visible in `cargo tree --edges features`; any new package or root feature
# therefore requires an explicit policy review instead of relying on its name
# matching a short fixture denylist.
SHIPPING_ROOT_FEATURE_ALLOWLIST = {
    "connect_norito_bridge": frozenset({"cuda", "privacy-production-enabled"}),
    "iroha_cli": frozenset(
        {"bridge", "cli", "default", "offline-visual-codecs"}
    ),
    "iroha_core": frozenset(
        {
            "app_api",
            "bls",
            "default",
            "gost",
            "json",
            "node",
            "profiling",
            "proofs-stark",
            "runtime",
            "simd",
            "sm",
            "telemetry",
            "zk-ipa-native",
            "zk-preverify",
            "zk-stark",
        }
    ),
    "iroha_genesis": frozenset({"default", "sm"}),
    "iroha_kagami": frozenset({"default", "gost", "sm"}),
    "iroha_torii": frozenset(
        {
            "app_api",
            "app_api_https",
            "app_api_wss",
            "connect",
            "default",
            "gost",
            "ipa-commitment",
            "node-api",
            "profiling",
            "proofs-full",
            "proofs-stark",
            "push",
            "schema",
            "sm",
            "telemetry",
            "transparent_api",
            "zk-stark",
            "zk-verify-batch",
        }
    ),
    "irohad": frozenset(
        {
            "daemon",
            "dag-recovery-verify",
            "default",
            "expensive-telemetry",
            "external-software-signer-bin",
            "gost",
            "schema-endpoint",
            "sm",
            "telemetry",
        }
    ),
    # Production IVM backends retain their build-time signed-artifact admission.
    # This permits their normal graph; physical-test gates and toolkit-coupled
    # aggregate helper features remain outside the shipping root policy.
    "ivm": frozenset({"cuda", "default", "metal"}),
    "sorafs_car": frozenset({"cli", "default", "manifest"}),
    "sorafs_orchestrator": frozenset(
        {"cli-orchestrator", "default", "moderation-grpc"}
    ),
}
REQUIRED_FEATURES = {
    "irohad": (
        'iroha_zkp_halo2 feature "full"',
        'iroha_zkp_halo2 feature "parallel"',
    ),
    "iroha_cli": (
        'iroha_zkp_halo2 feature "full"',
        'iroha_zkp_halo2 feature "parallel"',
    ),
}
FORBIDDEN_DOCKER_CARGO_SCOPE_FLAGS = frozenset(
    {
        "--workspace",
        "--all",
        "--exclude",
        "--package",
        "-p",
        "--bin",
        "--bins",
        "--all-targets",
        "--features",
        "-F",
        "--all-features",
        "--no-default-features",
    }
)
FORBIDDEN_DOCKER_CARGO_SCOPE_PREFIXES = (
    "--workspace=",
    "--exclude=",
    "--package=",
    "--bin=",
    "--features=",
)


class CargoBinary(NamedTuple):
    """Workspace binary ownership and its Cargo-required features."""

    package: str
    name: str
    required_features: tuple[str, ...]


class WorkspaceCatalog(NamedTuple):
    """Cargo package features and binary targets used by release discovery."""

    package_features: dict[str, frozenset[str]]
    binaries: dict[str, tuple[CargoBinary, ...]]
    native_libraries: dict[str, tuple[str, ...]]
    workspace_docker_bins: tuple[str, ...]


class DockerInvocation(NamedTuple):
    """One Docker publication step and its build-time Cargo feature override."""

    workflow: str
    dockerfile: str
    features: tuple[str, ...] | None
    cargo_flags: tuple[str, ...]


class ShippingTarget(NamedTuple):
    """One binary named by a repository shipping declaration."""

    package: str
    binary: str
    features: tuple[str, ...]
    default_features: bool
    source: str


class ShippingProfile(NamedTuple):
    """One distinct Cargo package/feature profile shipped by the repository."""

    package: str
    features: tuple[str, ...] = ()
    default_features: bool = True

    def label(self) -> str:
        """Return a concise diagnostic label for this profile."""

        feature_label = ",".join(self.features) or "defaults-only"
        defaults = "defaults" if self.default_features else "no-defaults"
        return f"{self.package}[{defaults};{feature_label}]"


def _git_release_paths(
    repo: Path, pathspecs: tuple[str, ...], *, include_ignored: bool = False
) -> set[Path]:
    """Return cached and untracked paths matching ``pathspecs``.

    Ordinary release inputs honor repository ignore rules. Exact auto-loaded
    build controls opt into ``include_ignored`` because Cargo, MSBuild, and
    NuGet still consume those files when Git ignores them.
    """

    command = ["git", "ls-files", "--cached", "--others"]
    if not include_ignored:
        command.append("--exclude-standard")
    command.extend(("-z", "--", *pathspecs))
    completed = subprocess.run(
        command,
        cwd=repo,
        check=False,
        capture_output=True,
    )
    if completed.returncode != 0:
        detail = completed.stderr.decode("utf-8", errors="replace").strip()
        raise RuntimeError(f"unable to enumerate trusted release sources: {detail}")
    candidates = {
        Path(raw.decode("utf-8")) for raw in completed.stdout.split(b"\0") if raw
    }
    # ``git ls-files --cached`` also reports tracked files deleted by the
    # current first-release hard cut. Model the source tree that a clean commit
    # will actually ship; commit validation separately rejects dirty trees.
    # ``lexists`` intentionally retains broken links so the stable-reader path
    # can reject them instead of silently excluding them from the seal.
    return {path for path in candidates if os.path.lexists(repo / path)}


def _custom_build_package_paths(repo: Path, manifests: set[Path]) -> set[Path]:
    """Close every repository Cargo custom-build target over its package tree."""

    repo_root = repo.resolve()
    paths: set[Path] = set()
    for manifest in sorted(manifests):
        manifest_path = repo / manifest
        if manifest_path.is_symlink() or not manifest_path.is_file():
            raise RuntimeError(
                "trusted release source surface drifted: Cargo manifest is not a "
                f"regular file: {manifest}"
            )
        try:
            document = tomllib.loads(manifest_path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, tomllib.TOMLDecodeError) as error:
            raise RuntimeError(f"unable to parse Cargo manifest {manifest}: {error}") from error
        package = document.get("package")
        if not isinstance(package, dict):
            continue
        configured = package.get("build")
        if configured is False:
            continue
        if configured is None:
            source_lexical = manifest.parent / "build.rs"
            if not (repo / source_lexical).exists():
                continue
        elif isinstance(configured, str) and configured:
            source_lexical = manifest.parent / configured
        else:
            raise RuntimeError(
                f"{manifest}: package.build must be false or a non-empty path"
            )

        source_path = repo / source_lexical
        if source_path.is_symlink() or not source_path.is_file():
            raise RuntimeError(
                f"{manifest}: custom build target is not a regular file: {source_lexical}"
            )
        try:
            source = source_path.resolve(strict=True).relative_to(repo_root)
        except (OSError, ValueError) as error:
            raise RuntimeError(
                f"{manifest}: custom build target escapes the repository: {source_lexical}"
            ) from error
        indexed_source = _git_release_paths(
            repo, (f":(top,literal){source.as_posix()}",)
        )
        if source not in indexed_source:
            raise RuntimeError(
                f"{manifest}: custom build target is ignored or absent from the source inventory: "
                f"{source}"
            )

        package_paths = _git_release_paths(
            repo, (f":(top,literal){manifest.parent.as_posix()}",)
        )
        source_parent_paths = _git_release_paths(
            repo, (f":(top,literal){source.parent.as_posix()}",)
        )
        paths.update(package_paths)
        paths.update(source_parent_paths)
    return paths


def trusted_release_surface_paths(repo: Path) -> tuple[Path, ...]:
    """Return every repository source that can define or support release jobs.

    Cargo project configuration, manifests, custom-build package trees, and
    Gradle launch/settings/buildSrc inputs are included because those tools
    load or execute them before the reviewed build task runs.
    """

    paths = _git_release_paths(
        repo,
        (
            ":(top,glob)**/.cargo/**",
            ":(top,glob)**/Cargo.lock",
            ":(top,glob)**/Cargo.toml",
            ":(top,glob)**/rust-toolchain",
            ":(top,glob)**/rust-toolchain.toml",
            ":(top).dockerignore",
            ":(top,glob)Dockerfile*",
            ":(top,glob).github/actions/**",
            ":(top,glob).github/workflows/**",
            ":(top,glob)IrohaSwift/**",
            ":(top,glob)ci/**",
            ":(top,glob)codec/rans/tables/**",
            ":(top,glob)configs/soranexus/taira/**",
            ":(top,glob)configs/sorafs/external_software_signer/**",
            ":(top,glob)configs/sorafs/runtime_provider_broker/**",
            ":(top,glob)csharp/**",
            ":(top,glob)defaults/**",
            ":(top,glob)gradle/**",
            ":(top,glob)java/**",
            ":(top,glob)kotlin/**",
            f":(top,glob){NIX_APPIMAGE_OWNER_ROOT.as_posix()}/**",
            ":(top,glob)scripts/**",
            ":(top,glob)**/*.podspec*",
            *(f":(top,literal){path.as_posix()}" for path in SORAFS_CLI_VERBATIM_PAYLOADS),
            *(
                f":(top,literal){path.as_posix()}"
                for path in SORAFS_REFERENCE_VALIDATOR_VERBATIM_PAYLOADS
            ),
            *(f":(top,literal){path.as_posix()}" for path in RELEASE_PIPELINE_SEMANTIC_INPUTS),
            *(
                f":(top,literal){path.as_posix()}"
                for path in OPTIONAL_SIGNED_RELEASE_EVIDENCE_INPUTS
            ),
            *(
                f":(top,literal){path.as_posix()}"
                for path in NIX_RELEASE_OWNER_PATHS
            ),
            *(
                f":(top,literal){path.as_posix()}"
                for path in DOTNET_REPOSITORY_ANCESTOR_OWNER_PATHS
            ),
            DOTNET_NUGET_CONFIG_PATHSPEC,
            f":(top){ANDROID_NATIVE_BUILD_OWNER}",
        ),
    )
    paths.update(
        _git_release_paths(
            repo, AUTOLOADED_BUILD_CONTROL_PATHSPECS, include_ignored=True
        )
    )
    cargo_control_root = repo / ".cargo"
    if cargo_control_root.is_symlink():
        raise RuntimeError(
            "trusted release source surface drifted: .cargo may not be a symbolic link"
        )
    manifests = {path for path in paths if path.name == "Cargo.toml"}
    paths.update(_custom_build_package_paths(repo, manifests))
    ordered = tuple(sorted(paths))
    if not ordered:
        raise RuntimeError("trusted release source inventory is empty")
    return ordered


def _normalize_swift_native_bridge_hash_pins(contents: bytes) -> bytes:
    """Normalize only the three canonical generated Swift fallback digests.

    Keep this byte grammar aligned with the native source-seal owner. Importing
    that candidate-owned module here would execute it before release admission.
    Native artifact validation independently authenticates all three pin values;
    every other loader byte remains part of the reviewed source digest.
    """

    block_pattern = re.compile(
        rb'^    private static let expectedHashes: \[String: String\] = \[\n'
        rb'(?P<body>(?:[ \t]+"(?:macos-arm64_x86_64|ios-arm64|ios-arm64_x86_64-simulator)"'
        rb': "[0-9a-f]{64}",\n){2}'
        rb'[ \t]+"(?:macos-arm64_x86_64|ios-arm64|ios-arm64_x86_64-simulator)"'
        rb': "[0-9a-f]{64}"\n)'
        rb'^    \]$',
        re.MULTILINE,
    )
    pin_pattern = re.compile(
        rb'^(?P<prefix>[ \t]+)"(?P<key>macos-arm64_x86_64|ios-arm64|ios-arm64_x86_64-simulator)"'
        rb': "(?P<digest>[0-9a-f]{64})"(?P<suffix>,?)$',
        re.MULTILINE,
    )
    blocks = list(block_pattern.finditer(contents))
    if len(blocks) != 1:
        raise RuntimeError(
            "trusted release source surface drifted: NativeBridge.swift must "
            "contain exactly one canonical expectedHashes block"
        )
    block = blocks[0]
    body = block.group("body")
    matches = list(pin_pattern.finditer(body))
    if (
        len(matches) != 3
        or {match.group("key") for match in matches}
        != {b"macos-arm64_x86_64", b"ios-arm64", b"ios-arm64_x86_64-simulator"}
        or [match.group("suffix") for match in matches] != [b",", b",", b""]
    ):
        raise RuntimeError(
            "trusted release source surface drifted: NativeBridge.swift must "
            "contain exactly one canonical fallback hash for every Apple artifact slice"
        )
    for match in reversed(matches):
        start, end = match.span("digest")
        body = body[:start] + (b"0" * 64) + body[end:]
    start, end = block.span("body")
    return contents[:start] + body + contents[end:]


def _release_surface_contents(relative: Path, contents: bytes) -> bytes:
    """Normalize exact generated pins and this guard's own embedded seal."""

    if relative == Path("IrohaSwift/Sources/IrohaSwift/NativeBridge.swift"):
        return _normalize_swift_native_bridge_hash_pins(contents)

    if relative != Path("scripts/check_release_feature_graph.py"):
        return contents
    try:
        source = contents.decode("utf-8")
        tree = ast.parse(source, filename=relative.as_posix())
    except (UnicodeDecodeError, SyntaxError) as error:
        raise RuntimeError(
            "trusted release source surface drifted: release guard must be "
            f"valid UTF-8 Python: {error}"
        ) from error

    stored_names = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Name)
        and isinstance(node.ctx, ast.Store)
        and node.id == "TRUSTED_RELEASE_SURFACE_SHA256"
    ]
    imported_names = [
        alias
        for node in ast.walk(tree)
        if isinstance(node, (ast.Import, ast.ImportFrom))
        for alias in node.names
        if (alias.asname or alias.name.rsplit(".", 1)[-1])
        == "TRUSTED_RELEASE_SURFACE_SHA256"
    ]
    named_definitions = [
        node
        for node in ast.walk(tree)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))
        and node.name == "TRUSTED_RELEASE_SURFACE_SHA256"
    ]

    def module_namespace(call: ast.AST) -> bool:
        return (
            isinstance(call, ast.Call)
            and isinstance(call.func, ast.Name)
            and call.func.id in {"globals", "vars"}
            and not call.args
            and not call.keywords
        )

    namespace_mutations: list[ast.AST] = []
    for node in ast.walk(tree):
        if (
            isinstance(node, ast.Subscript)
            and isinstance(node.ctx, ast.Store)
            and module_namespace(node.value)
            and isinstance(node.slice, ast.Constant)
            and node.slice.value == "TRUSTED_RELEASE_SURFACE_SHA256"
        ):
            namespace_mutations.append(node)
        if not isinstance(node, ast.Call):
            continue
        if (
            isinstance(node.func, ast.Attribute)
            and module_namespace(node.func.value)
            and node.func.attr in {"__setitem__", "setdefault", "update"}
            and any(
                isinstance(argument, ast.Constant)
                and argument.value == "TRUSTED_RELEASE_SURFACE_SHA256"
                for argument in node.args
            )
        ):
            namespace_mutations.append(node)
        if (
            isinstance(node.func, ast.Name)
            and node.func.id == "setattr"
            and len(node.args) >= 2
            and isinstance(node.args[1], ast.Constant)
            and node.args[1].value == "TRUSTED_RELEASE_SURFACE_SHA256"
        ):
            namespace_mutations.append(node)
    literal_declarations = [
        statement
        for statement in tree.body
        if isinstance(statement, ast.Assign)
        and len(statement.targets) == 1
        and isinstance(statement.targets[0], ast.Name)
        and statement.targets[0].id == "TRUSTED_RELEASE_SURFACE_SHA256"
        and isinstance(statement.value, ast.Constant)
        and isinstance(statement.value.value, str)
        and re.fullmatch(r"[0-9a-f]{64}", statement.value.value) is not None
    ]
    if (
        len(stored_names) != 1
        or len(literal_declarations) != 1
        or imported_names
        or named_definitions
        or namespace_mutations
    ):
        raise RuntimeError(
            "trusted release source surface drifted: embedded seal must have "
            "exactly one top-level literal assignment"
        )
    pattern = re.compile(
        rb'(?P<prefix>TRUSTED_RELEASE_SURFACE_SHA256\s*=\s*\(\s*")'
        rb"(?P<digest>[0-9a-f]{64})"
        rb'(?P<suffix>"\s*\))'
    )
    matches = list(pattern.finditer(contents))
    declaration = literal_declarations[0]
    encoded_lines = source.encode("utf-8").splitlines(keepends=True)
    start = sum(len(line) for line in encoded_lines[: declaration.lineno - 1])
    start += declaration.col_offset
    end = sum(len(line) for line in encoded_lines[: declaration.end_lineno - 1])
    end += declaration.end_col_offset
    if (
        len(matches) != 1
        or matches[0].start() != start
        or matches[0].end() != end
        or pattern.fullmatch(contents[start:end]) is None
    ):
        raise RuntimeError(
            "trusted release source surface drifted: embedded seal declaration "
            "must occur exactly once"
        )
    match = matches[0]
    return (
        contents[: match.start("digest")]
        + (b"0" * 64)
        + contents[match.end("digest") :]
    )


def _embedded_release_surface_sha256() -> str:
    """Read the reviewed literal from this source, independent of global rebinding."""

    relative = Path("scripts/check_release_feature_graph.py")
    contents = Path(__file__).read_bytes()
    _release_surface_contents(relative, contents)
    match = re.search(
        rb'TRUSTED_RELEASE_SURFACE_SHA256\s*=\s*\(\s*"(?P<digest>[0-9a-f]{64})"\s*\)',
        contents,
    )
    if match is None:  # pragma: no cover - validated above
        raise RuntimeError("trusted release source surface seal literal is missing")
    return match.group("digest").decode("ascii")


def _stable_release_surface_read(path: Path) -> bytes:
    """Read one unchanged, singly linked, non-shared-writable regular file."""

    flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW
    before_path = path.lstat()
    descriptor = os.open(path, flags)
    try:
        before = os.fstat(descriptor)
        stable_fields = (
            "st_dev",
            "st_ino",
            "st_mode",
            "st_nlink",
            "st_size",
            "st_mtime_ns",
            "st_ctime_ns",
        )
        if not stat.S_ISREG(before.st_mode) or any(
            getattr(before, field) != getattr(before_path, field)
            for field in stable_fields
        ):
            raise RuntimeError(
                f"trusted release source is not one pinned regular file: {path}"
            )
        if before.st_nlink != 1:
            raise RuntimeError(
                f"trusted release source must have exactly one hard link: {path}"
            )
        if before.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
            raise RuntimeError(
                "trusted release source must not be group- or world-writable: "
                f"{path}"
            )
        payload = bytearray()
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            payload.extend(chunk)
        after = os.fstat(descriptor)
        after_path = path.lstat()
    finally:
        os.close(descriptor)
    if len(payload) != before.st_size or any(
        getattr(before, field) != getattr(after, field)
        or getattr(before, field) != getattr(after_path, field)
        for field in stable_fields
    ):
        raise RuntimeError(f"trusted release source changed while being read: {path}")
    return bytes(payload)


def _release_surface_directory_identities(
    repo: Path, paths: tuple[Path, ...]
) -> dict[Path, tuple[int, int, int]]:
    """Pin every in-repository parent directory for the reviewed surface."""

    directories = {repo}
    for relative in paths:
        parent = relative.parent
        while parent != Path("."):
            directories.add(repo / parent)
            parent = parent.parent
    flags = os.O_RDONLY | os.O_CLOEXEC | os.O_DIRECTORY | os.O_NOFOLLOW
    identities: dict[Path, tuple[int, int, int]] = {}
    for directory in sorted(directories, key=lambda path: (len(path.parts), path)):
        before_path = directory.lstat()
        descriptor = os.open(directory, flags)
        try:
            opened = os.fstat(descriptor)
            after_path = directory.lstat()
        finally:
            os.close(descriptor)
        identity = lambda info: (info.st_dev, info.st_ino, info.st_mode)
        if (
            not stat.S_ISDIR(opened.st_mode)
            or identity(before_path) != identity(opened)
            or identity(opened) != identity(after_path)
        ):
            raise RuntimeError(
                "trusted release source parent is not one pinned directory: "
                f"{directory}"
            )
        if opened.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
            raise RuntimeError(
                "trusted release source parent must not be group- or "
                f"world-writable: {directory}"
            )
        identities[directory] = identity(opened)
    return identities


def trusted_release_surface_digest(repo: Path) -> str:
    """Hash paths and bytes for the closed release-analysis source surface."""

    paths = trusted_release_surface_paths(repo)
    directory_identities = _release_surface_directory_identities(repo, paths)
    digest = hashlib.sha256()
    for relative in paths:
        path = repo / relative
        if path.is_symlink():
            if relative != APPLE_DEVELOPMENT_BRIDGE_LINK:
                raise RuntimeError(
                    "trusted release source surface drifted: tracked path is a "
                    f"symbolic link: {relative}"
                )
            target = os.readlink(path)
            if target != APPLE_DEVELOPMENT_BRIDGE_TARGET:
                raise RuntimeError(
                    "trusted release source surface drifted: Apple development "
                    f"bridge link must target {APPLE_DEVELOPMENT_BRIDGE_TARGET}: {target}"
                )
            contents = b"symbolic-link\0" + os.fsencode(target)
        elif not path.is_file():
            raise RuntimeError(
                "trusted release source surface drifted: tracked path is not a "
                f"regular file: {relative}"
            )
        else:
            contents = _stable_release_surface_read(path)
        relative_bytes = relative.as_posix().encode("utf-8")
        contents = _release_surface_contents(relative, contents)
        digest.update(len(relative_bytes).to_bytes(8, "big"))
        digest.update(relative_bytes)
        digest.update(len(contents).to_bytes(8, "big"))
        digest.update(contents)
    if _release_surface_directory_identities(repo, paths) != directory_identities:
        raise RuntimeError(
            "trusted release source parent directories changed while hashing"
        )
    return digest.hexdigest()


def validate_trusted_release_surface(
    repo: Path, expected_digest: str | None = None
) -> None:
    """Reject unreviewed workflow, Dockerfile, or release-support drift."""

    if expected_digest is None:
        expected_digest = _embedded_release_surface_sha256()
    observed = trusted_release_surface_digest(repo)
    if observed != expected_digest:
        raise RuntimeError(
            "trusted release source surface drifted; review the semantic changes and "
            "update TRUSTED_RELEASE_SURFACE_SHA256 "
            f"(expected {expected_digest}, observed {observed})"
        )


def validate_trusted_release_surface_commit(
    repo: Path, source_commit: str, expected_digest: str | None = None
) -> str:
    """Bind the reviewed release surface to one clean checked-out Git commit."""

    if re.fullmatch(r"(?:[0-9a-f]{40}|[0-9a-f]{64})", source_commit) is None:
        raise RuntimeError("trusted release source commit must be one full lowercase id")
    reviewed_digest = (
        _embedded_release_surface_sha256()
        if expected_digest is None
        else expected_digest
    )
    validate_trusted_release_surface(repo, reviewed_digest)
    head = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=repo,
        check=False,
        capture_output=True,
        text=True,
    )
    if head.returncode != 0 or head.stdout.strip() != source_commit:
        raise RuntimeError("trusted release source commit does not match repository HEAD")
    dirty = subprocess.run(
        ["git", "diff", "--quiet", "--no-ext-diff", source_commit, "--"],
        cwd=repo,
        check=False,
    )
    if dirty.returncode == 1:
        raise RuntimeError("trusted release source commit has tracked working-tree drift")
    if dirty.returncode != 0:
        raise RuntimeError("unable to compare trusted release source commit")
    tracked_result = subprocess.run(
        ["git", "ls-files", "--cached", "-z"],
        cwd=repo,
        check=False,
        capture_output=True,
    )
    if tracked_result.returncode != 0:
        raise RuntimeError("unable to enumerate tracked release sources")
    tracked = {
        Path(raw.decode("utf-8"))
        for raw in tracked_result.stdout.split(b"\0")
        if raw
    }
    uncommitted = set(trusted_release_surface_paths(repo)).difference(tracked)
    if uncommitted:
        rendered = ", ".join(path.as_posix() for path in sorted(uncommitted)[:8])
        raise RuntimeError(
            "trusted release surface contains uncommitted or ignored inputs: "
            + rendered
        )
    final_digest = trusted_release_surface_digest(repo)
    if final_digest != reviewed_digest:
        raise RuntimeError(
            "trusted release source surface changed during commit validation "
            f"(expected {reviewed_digest}, observed {final_digest})"
        )
    return final_digest


def _hostile_cargo_environment_name(name: str) -> bool:
    """Return whether one inherited variable can alter Cargo compilation."""

    if name in HOSTILE_CARGO_ENVIRONMENT or name.startswith("CARGO_BUILD_"):
        return True
    return name.startswith("CARGO_TARGET_") and name.endswith(
        ("_LINKER", "_RUNNER", "_RUSTFLAGS", "_RUSTDOCFLAGS")
    )


def _cargo_subprocess_environment() -> dict[str, str]:
    """Return a Cargo graph-query environment without caller compile hooks."""

    environment = os.environ.copy()
    for name in tuple(environment):
        if _hostile_cargo_environment_name(name):
            environment.pop(name, None)
    return environment


def validate_daemon_cuda_target_dependency(repo: Path) -> None:
    """Require the sole mandatory Linux/Windows IVM CUDA target dependency."""
    runtime = tomllib.loads((repo / "crates/irohad/Cargo.toml").read_text(encoding="utf-8"))
    binary = tomllib.loads((repo / "crates/irohad/bins/Cargo.toml").read_text(encoding="utf-8"))
    scope = 'cfg(any(target_os = "linux", target_os = "windows"))'
    expected = {"workspace": True, "features": ["cuda"]}
    targets = runtime.get("target", {})
    if (runtime.get("dependencies", {}).get("ivm") != {"workspace": True}
            or targets.get(scope, {}).get("dependencies", {}).get("ivm") != expected
            or any("ivm" in value.get("dependencies", {}) for key, value in targets.items() if key != scope)
            or any("ivm-cuda" in document.get("features", {}) for document in (runtime, binary))):
        raise RuntimeError("daemon CUDA must use the exact mandatory Linux/Windows target dependency; aliases are retired")


def workspace_catalog(repo: Path) -> WorkspaceCatalog:
    """Return workspace package and binary metadata from the locked graph."""

    completed = subprocess.run(
        [
            "cargo",
            "metadata",
            "--locked",
            "--no-deps",
            "--format-version",
            "1",
        ],
        cwd=repo,
        check=False,
        capture_output=True,
        text=True,
        env=_cargo_subprocess_environment(),
    )
    if completed.returncode != 0:
        raise RuntimeError(
            f"cargo metadata failed:\n{completed.stdout}{completed.stderr}"
        )

    metadata = json.loads(completed.stdout)
    package_features: dict[str, frozenset[str]] = {}
    binaries: dict[str, list[CargoBinary]] = {}
    native_libraries: dict[str, tuple[str, ...]] = {}
    for package in metadata["packages"]:
        package_name = package["name"]
        if package_name in package_features:
            raise RuntimeError(f"duplicate workspace package name: {package_name}")
        package_features[package_name] = frozenset(package.get("features", {}))
        for target in package.get("targets", ()):
            crate_types = tuple(sorted(target.get("crate_types", ())))
            if {"cdylib", "staticlib"}.intersection(crate_types):
                native_libraries[package_name] = crate_types
            if "bin" not in target.get("kind", ()):
                continue
            binary = CargoBinary(
                package=package_name,
                name=target["name"],
                required_features=tuple(sorted(target.get("required-features", ()))),
            )
            binaries.setdefault(binary.name, []).append(binary)

    return WorkspaceCatalog(
        package_features=package_features,
        binaries={name: tuple(sorted(targets)) for name, targets in binaries.items()},
        native_libraries=native_libraries,
        workspace_docker_bins=tuple(
            sorted(metadata.get("metadata", {}).get("docker_bins", ()))
        ),
    )


def _resolve_binary(
    catalog: WorkspaceCatalog, binary: str, package: str | None = None
) -> CargoBinary:
    candidates = catalog.binaries.get(binary, ())
    if package is not None:
        candidates = tuple(target for target in candidates if target.package == package)
    if len(candidates) != 1:
        owner = f" in package {package}" if package is not None else ""
        packages = ", ".join(target.package for target in candidates) or "none"
        raise RuntimeError(
            f"shipping binary {binary!r}{owner} must resolve uniquely; owners: {packages}"
        )
    return candidates[0]


def _quoted_arg_words(
    source: str, name: str, path: Path, *, required: bool = True
) -> tuple[str, ...] | None:
    declarations = re.findall(
        rf"(?im)^\s*ARG\s+{re.escape(name)}(?:\s*=.*)?\s*$", source
    )
    if len(declarations) > 1:
        raise RuntimeError(f"{path}: ARG {name} must be declared exactly once")
    match = re.search(
        rf'^\s*ARG\s+{re.escape(name)}="([^"]*)"\s*$',
        source,
        re.IGNORECASE | re.MULTILINE,
    )
    if match is None:
        if declarations:
            raise RuntimeError(
                f"{path}: ARG {name} must use a static quoted default for review"
            )
        if required:
            raise RuntimeError(f"{path}: missing quoted ARG {name}")
        return None
    if name == "FEATURES":
        return _split_features(match.group(1))
    return tuple(word for word in match.group(1).split() if word)


def _dockerfile_binary_names(
    source: str, path: Path, catalog: WorkspaceCatalog
) -> tuple[str, ...]:
    declared = _quoted_arg_words(source, "BINARIES", path, required=False)
    if declared:
        return declared
    if declared == () and "workspace_metadata.docker_bins" in source:
        if not catalog.workspace_docker_bins:
            raise RuntimeError(f"{path}: workspace docker_bins metadata is empty")
        return catalog.workspace_docker_bins
    binaries = tuple(
        dict.fromkeys(
            re.findall(r"--bin\s+(?:\"|')?([A-Za-z0-9_.-]+)", source)
        )
    )
    if not binaries:
        raise RuntimeError(f"{path}: no shipping binaries could be derived")
    return binaries


def _dockerfile_arg_names(source: str) -> frozenset[str]:
    """Return build arguments declared by one Dockerfile."""

    return frozenset(
        re.findall(
            r"(?im)^\s*ARG\s+([A-Za-z_][A-Za-z0-9_]*)(?:=|\s|$)", source
        )
    )


def _cargo_scope_flags_are_forbidden(flags: tuple[str, ...]) -> bool:
    return bool(FORBIDDEN_DOCKER_CARGO_SCOPE_FLAGS.intersection(flags)) or any(
        token.startswith(FORBIDDEN_DOCKER_CARGO_SCOPE_PREFIXES)
        or (token.startswith("-p") and token != "-p")
        or (token.startswith("-F") and token != "-F")
        for token in flags
    )


def _dockerfile_cargo_build_commands(source: str, path: Path) -> tuple[str, ...]:
    """Extract literal Cargo build clauses from a Dockerfile shell surface."""

    uncommented = "\n".join(
        line for line in source.splitlines() if not line.lstrip().startswith("#")
    )
    logical = re.sub(r"\\\s*\n", " ", uncommented)
    commands: list[str] = []
    for line in logical.splitlines():
        for clause in re.split(r"\s*(?:;|&&|\|\|)\s*", line):
            match = re.search(
                r"(?<![A-Za-z0-9_-])(?:xx-)?cargo\s+.*?\bbuild\b.*$", clause
            )
            if match is not None:
                commands.append(match.group(0).strip())
    if not commands:
        raise RuntimeError(f"{path}: no literal Cargo build invocation was derived")
    return tuple(commands)


def _dockerfile_run_instructions(source: str) -> tuple[str, ...]:
    """Return Dockerfile RUN instruction bodies, including continuation lines."""

    lines = source.splitlines()
    starts = [
        index
        for index, line in enumerate(lines)
        if re.match(r"(?i)^\s*RUN(?:\s|$)", line)
    ]
    instruction = re.compile(
        r"(?i)^\s*(?:ADD|ARG|CMD|COPY|ENTRYPOINT|ENV|EXPOSE|FROM|HEALTHCHECK|"
        r"LABEL|ONBUILD|RUN|SHELL|STOPSIGNAL|USER|VOLUME|WORKDIR)\s"
    )
    instructions: list[str] = []
    for start in starts:
        end = len(lines)
        for index in range(start + 1, len(lines)):
            if instruction.match(lines[index]):
                end = index
                break
        instructions.append("\n".join(lines[start:end]))
    return tuple(instructions)


def _validate_dockerfile_output_provenance(source: str, path: Path) -> None:
    """Bind runtime executable copies to reviewed Cargo output stages."""

    logical = re.sub(r"\\\s*\n", " ", source)
    binary_names = set(
        re.findall(r"--bin\s+(?:\"|')?([A-Za-z0-9_.-]+)", logical)
    )
    allowed_copies = {
        ("COPY", "--from=builder", "/outbin/", "$BIN_PATH"),
        (
            "COPY",
            "--from=builder",
            "/app/scripts/docker_entrypoint.sh",
            "$BIN_PATH",
        ),
        ("COPY", "--from=xx-build", "/app/bins/*", "/usr/local/bin/"),
    }
    if "TARGET_DIR" in _dockerfile_arg_names(source):
        allowed_copies.update(
            ("COPY", "--from=builder", f"$TARGET_DIR/{binary}", "$BIN_PATH")
            for binary in binary_names
        )

    protected_destinations = ("/outbin", "/app/bins", "./bins")
    for line in logical.splitlines():
        if not re.match(r"(?i)^\s*(?:COPY|ADD)\s", line):
            continue
        try:
            parsed = tuple(shlex.split(line))
            tokens = (parsed[0].upper(), *parsed[1:])
        except ValueError as error:
            raise RuntimeError(f"{path}: unreviewable Docker copy: {line}") from error
        destination = tokens[-1] if len(tokens) >= 3 else ""
        runtime_destination = destination in {"$BIN_PATH", "${BIN_PATH}"} or any(
            destination == root or destination.startswith(f"{root}/")
            for root in ("/usr/local/bin", "/usr/local/sbin")
        )
        protected_builder_destination = any(
            destination == root or destination.startswith(f"{root}/")
            for root in protected_destinations
        )
        if runtime_destination and tokens not in allowed_copies:
            raise RuntimeError(
                f"{path}: runtime executable COPY is not bound to reviewed Cargo "
                f"output: {line}"
            )
        if protected_builder_destination:
            raise RuntimeError(
                f"{path}: Docker COPY may not overwrite the reviewed builder output: "
                f"{line}"
            )

    allowed_outbin_operations = {
        ("mkdir", "-p", "/outbin"),
        ("cp", "/app/dist/docker-bin/${bin}", "/outbin/${bin}"),
        (
            "cp",
            "/cargo-target/${cargo_target_profile_dir}/${bin}",
            "/outbin/${bin}",
        ),
        (
            "cp",
            "/cargo-target/${cargo_target_profile_dir}/kagami",
            "/outbin/kagami",
        ),
        ("chmod", "755", "/outbin/*"),
    }
    allowed_cross_bin_operations = {
        ("mkdir", "-p", "./bins"),
        ("mv", "${bin_path}", "./bins/"),
    }
    seen_builder_operations: set[tuple[str, ...]] = set()

    def runtime_bin_path(value: str) -> bool:
        value = value.strip('"\'')
        return value.startswith(("$BIN_PATH", "${BIN_PATH}", "/usr/local/bin"))

    write_commands = {"cp", "mv", "install", "ln", "rm", "truncate", "tee"}
    for instruction in _dockerfile_run_instructions(source):
        logical_instruction = re.sub(r"\\\s*\n", " ", instruction)
        if re.search(
            r">+\s*[\"']?(?:\$\{?BIN_PATH\}?|/usr/local/bin|/outbin|\./bins)"
            r"(?:/|\s|$)",
            logical_instruction,
        ):
            raise RuntimeError(
                f"{path}: RUN redirection may not overwrite runtime executables"
            )
        for clause in re.split(r"\s*(?:;|&&|\|\||\n)\s*", logical_instruction):
            try:
                tokens = tuple(shlex.split(clause))
            except ValueError as error:
                raise RuntimeError(
                    f"{path}: unreviewable runtime output command: {clause}"
                ) from error
            if "/outbin" in clause or "./bins" in clause:
                operation_index = next(
                    (
                        index
                        for index, token in enumerate(tokens)
                        if token in {"mkdir", "cp", "mv", "chmod"}
                    ),
                    None,
                )
                operation = tokens[operation_index:] if operation_index is not None else ()
                allowed = (
                    operation in allowed_outbin_operations
                    or operation in allowed_cross_bin_operations
                )
                if not allowed or operation in seen_builder_operations:
                    raise RuntimeError(
                        f"{path}: builder output write is not bound to reviewed "
                        f"Cargo output: {clause.strip()}"
                    )
                seen_builder_operations.add(operation)
            command_index = next(
                (index for index, token in enumerate(tokens) if token in write_commands),
                None,
            )
            if command_index is None:
                continue
            command = tokens[command_index]
            arguments = tokens[command_index + 1 :]
            destinations = arguments if command in {"rm", "truncate", "tee"} else arguments[-1:]
            if any(
                value.strip('"\'').startswith(("./target/", "target/", "/cargo-target/"))
                for value in destinations
            ):
                raise RuntimeError(
                    f"{path}: RUN may not overwrite Cargo's authenticated target output: "
                    f"{clause.strip()}"
                )
            if any(runtime_bin_path(value) for value in destinations):
                raise RuntimeError(
                    f"{path}: RUN may not overwrite the final runtime executable "
                    f"directory: {clause.strip()}"
                )

    prebuilt_copy = 'cp "/app/dist/docker-bin/${bin}" "/outbin/${bin}"'
    if prebuilt_copy in logical:
        prebuilt_gate = re.search(
            r'if\s+\[\s+"\$\{USE_PREBUILT\}"\s+=\s+"1"\s+\];\s+then',
            logical,
        )
        copy_index = logical.index(prebuilt_copy)
        following_else = re.search(r"\belse\b", logical[copy_index:])
        if (
            prebuilt_gate is None
            or prebuilt_gate.start() >= copy_index
            or following_else is None
        ):
            raise RuntimeError(
                f"{path}: prebuilt output copy is not confined to the disabled gate"
            )


def _validate_dockerfile_cargo_scope(source: str, path: Path) -> None:
    """Authenticate Docker Cargo feature selection and controlling arguments."""

    default_cargo_flags = _quoted_arg_words(
        source, "CARGOFLAGS", path, required=False
    )
    if default_cargo_flags and _cargo_scope_flags_are_forbidden(default_cargo_flags):
        raise RuntimeError(f"{path}: default CARGOFLAGS expands Cargo target scope")
    reassigned_scope = tuple(
        line
        for line in source.splitlines()
        if not re.match(r"(?i)^\s*ARG\s+", line)
        and re.search(r"\b(?:CARGOFLAGS|FEATURES|USE_PREBUILT)\s*=", line)
    )
    if reassigned_scope:
        raise RuntimeError(
            f"{path}: Cargo/output scope arguments may not be reassigned"
        )
    if "USE_PREBUILT" in _dockerfile_arg_names(source):
        prebuilt_default = _quoted_arg_words(
            source, "USE_PREBUILT", path, required=True
        )
        if prebuilt_default != ("0",):
            raise RuntimeError(f"{path}: USE_PREBUILT must default to disabled")

    for instruction in _dockerfile_run_instructions(source):
        indirect_builders = {
            match.group(1) or match.group(2)
            for match in re.finditer(
                r"(?:\$\{([A-Za-z_][A-Za-z0-9_]*)\}|\$([A-Za-z_][A-Za-z0-9_]*))"
                r"\s+build(?:\s|$)",
                instruction,
            )
        }.difference({"CARGOFLAGS"})
        if indirect_builders:
            raise RuntimeError(
                f"{path}: unreviewed ARG controls Cargo scope: "
                f"{', '.join(sorted(indirect_builders))}"
            )
        relative_scripts = re.findall(
            r"(?<![A-Za-z0-9_./-])(?:\./|/app/|scripts/)"
            r"[^\s;\"']+\.(?:sh|py)\b",
            instruction,
        )
        interpreter_scripts = set(
            re.findall(
            r"\b(?:bash|sh|python3?)\s+[^\s;\"']+\.(?:sh|py)\b",
            instruction,
            )
        ).difference(
            {"python3 /usr/local/libexec/package_inrou_runtime_v1.py"}
        )
        if relative_scripts or interpreter_scripts:
            raise RuntimeError(
                f"{path}: indirect build or output script is not reviewable"
            )

    uncommented = "\n".join(
        line for line in source.splitlines() if not line.lstrip().startswith("#")
    )
    logical = re.sub(r"\\\s*\n", " ", uncommented)
    if re.search(r"(?<![A-Za-z0-9_-])--all-features(?![A-Za-z0-9_-])", logical):
        raise RuntimeError(f"{path}: hardcoded --all-features is not reviewable")
    for line in logical.splitlines():
        for clause in re.split(r"\s*(?:;|&&|\|\|)\s*", line):
            if not re.search(r"\bset\s+--(?:\s|$)", clause) or "$@" not in clause:
                continue
            try:
                mutation = tuple(shlex.split(clause))
            except ValueError as error:
                raise RuntimeError(
                    f"{path}: unreviewable Cargo command mutation: {clause}"
                ) from error
            try:
                set_index = mutation.index("set")
            except ValueError as error:
                raise RuntimeError(
                    f"{path}: unreviewable Cargo command mutation: {clause}"
                ) from error
            mutation = mutation[set_index:]
            if mutation not in {
                ("set", "--", "$@", "--bin", "$bin"),
                ("set", "--", "$@", "--bin", "${bin}"),
            }:
                raise RuntimeError(
                    f"{path}: unreviewed mutation of the Cargo invocation: {clause}"
                )

    for command in _dockerfile_cargo_build_commands(source, path):
        try:
            tokens = tuple(shlex.split(command))
        except ValueError as error:
            raise RuntimeError(f"{path}: unreviewable Cargo invocation: {command}") from error
        build_index = tokens.index("build")
        prefix = tokens[1:build_index]
        arguments = tokens[build_index + 1 :]
        variables = {
            match.group(1) or match.group(2)
            for token in (*prefix, *arguments)
            for match in re.finditer(
                r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}|\$([A-Za-z_][A-Za-z0-9_]*)",
                token,
            )
        }
        unexpected_variables = variables.difference({"CARGOFLAGS", "FEATURES", "PROFILE"})
        if unexpected_variables:
            raise RuntimeError(
                f"{path}: unreviewed ARG controls Cargo scope: "
                f"{', '.join(sorted(unexpected_variables))}"
            )
        if prefix not in {(), ("${CARGOFLAGS}",), ("$CARGOFLAGS",)}:
            raise RuntimeError(
                f"{path}: unreviewed arguments precede Cargo build: {' '.join(prefix)}"
            )
        index = 0
        while index < len(arguments):
            token = arguments[index]
            if token in {"--features", "-F"}:
                if index + 1 >= len(arguments):
                    raise RuntimeError(f"{path}: {token} is missing its feature value")
                value = arguments[index + 1]
                if value not in {"${FEATURES}", "$FEATURES"}:
                    raise RuntimeError(
                        f"{path}: hardcoded or indirect Cargo features are not reviewable: "
                        f"{value}"
                    )
                index += 2
                continue
            if token.startswith("--features=") or (
                token.startswith("-F") and token != "-F"
            ):
                value = token.split("=", 1)[1] if "=" in token else token[2:]
                if value not in {"${FEATURES}", "$FEATURES"}:
                    raise RuntimeError(
                        f"{path}: hardcoded or indirect Cargo features are not reviewable: "
                        f"{value}"
                    )
            index += 1
    _validate_dockerfile_output_provenance(source, path)


def _workflow_steps(source: str) -> tuple[str, ...]:
    """Return GitHub workflow step blocks without requiring a YAML dependency."""

    lines = source.splitlines(keepends=True)
    starts: list[tuple[int, int]] = []
    for index, line in enumerate(lines):
        match = re.match(
            r"^(?P<indent> *)-\s+[A-Za-z_][A-Za-z0-9_-]*\s*:\s*", line
        )
        if match is not None:
            starts.append((index, len(match.group("indent"))))

    blocks: list[str] = []
    for start, indentation in starts:
        end = len(lines)
        for index in range(start + 1, len(lines)):
            line = lines[index]
            if not line.strip() or line.lstrip().startswith("#"):
                continue
            current = len(line) - len(line.lstrip(" "))
            if current < indentation or (
                current == indentation and re.match(r"^ *-\s+", line)
            ):
                end = index
                break
        blocks.append("".join(lines[start:end]))
    return tuple(blocks)


def _docker_action_steps(source: str, path: Path) -> tuple[str, ...]:
    """Return every Docker build action step or reject unparsed YAML syntax."""

    uncommented = "\n".join(
        line for line in source.splitlines() if not line.lstrip().startswith("#")
    )
    if "docker/bake-action@" in uncommented:
        raise RuntimeError(
            f"{path}: Docker bake action publication requires explicit guard support"
        )
    occurrences = len(re.findall(r"docker/build-push-action@", uncommented))
    if not occurrences:
        return ()
    if re.search(
        r"(?m)^[^#\n]*:\s*[&*][A-Za-z_][A-Za-z0-9_-]*(?:\s|$|[\[{])",
        uncommented,
    ) or re.search(r"(?m)^\s*-\s*\*[A-Za-z_][A-Za-z0-9_-]*(?:\s|$)", uncommented):
        raise RuntimeError(
            f"{path}: YAML anchors and aliases are not reviewable for Docker actions"
        )
    steps = tuple(
        step
        for step in _workflow_steps(uncommented)
        if "docker/build-push-action@" in step
    )
    if len(steps) != occurrences:
        raise RuntimeError(
            f"{path}: Docker build action uses unsupported or ambiguous YAML syntax"
        )
    return steps


def _docker_action_push_value(step: str, path: Path) -> str | None:
    matches = re.findall(r"(?m)^\s+push:\s*([^#\n]+?)\s*$", step)
    if len(matches) > 1:
        raise RuntimeError(f"{path}: Docker action declares push more than once")
    if not matches:
        if re.search(r"\bpush\s*:", step):
            raise RuntimeError(f"{path}: Docker action push uses unsupported YAML syntax")
        return None
    return matches[0].strip().strip('"\'').lower()


def _docker_action_has_registry_output(step: str, path: Path) -> bool:
    """Return whether a Docker action exports an image to a registry."""

    lines = step.splitlines()
    entries: list[str] = []
    found = False
    for index, line in enumerate(lines):
        match = re.match(r"^(?P<indent>\s*)outputs:\s*(?P<value>.*?)\s*$", line)
        if match is None:
            continue
        if found:
            raise RuntimeError(f"{path}: Docker action declares outputs more than once")
        found = True
        inline = match.group("value").strip()
        if inline and inline not in {"|", "|-"}:
            entries.append(inline.strip('"\''))
            continue
        field_indent = len(match.group("indent"))
        for candidate in lines[index + 1 :]:
            if not candidate.strip():
                continue
            indentation = len(candidate) - len(candidate.lstrip(" "))
            if indentation <= field_indent:
                break
            entry = candidate.strip()
            if not entry.startswith("#"):
                entries.append(entry.removeprefix("- ").strip().strip('"\''))

    if any("${{" in entry or "$" in entry for entry in entries):
        raise RuntimeError(f"{path}: dynamic Docker action outputs are not reviewable")
    return any(
        re.search(r"(?:^|,)\s*type\s*=\s*registry(?:,|$)", entry)
        or re.search(r"(?:^|,)\s*push\s*=\s*true(?:,|$)", entry)
        for entry in entries
    )


def _workflow_has_direct_docker_publish(source: str) -> bool:
    """Detect direct Docker CLI publication paths unsupported by this guard."""

    uncommented = "\n".join(
        line for line in source.splitlines() if not line.lstrip().startswith("#")
    )
    logical = re.sub(r"\\\s*\n", " ", uncommented)
    if re.search(
        r"(?m)(?<![A-Za-z0-9_-])docker\s+(?:(?:image|compose)\s+)?push(?:\s|$)",
        logical,
    ):
        return True
    registry_output = (
        r"(?:--output(?:=|\s+)|-o(?:=|\s+))[\"']?[^\s\"']*"
        r"(?:type\s*=\s*registry|push\s*=\s*true)"
    )
    bake_registry_output = r"\.output\s*=\s*type\s*=\s*registry"
    return bool(
        re.search(
            r"(?m)(?<![A-Za-z0-9_-])docker\s+(?:buildx\s+)?(?:build|bake)\b"
            rf"[^\n]*(?:(?<![A-Za-z0-9_-])--push(?:[=\s]|$)|"
            rf"{registry_output}|{bake_registry_output})",
            logical,
        )
    )


def docker_image_publish_workflows(repo: Path) -> tuple[Path, ...]:
    """Discover workflows whose Docker build step can push an image."""

    workflow_dir = repo / ".github" / "workflows"
    paths = sorted({*workflow_dir.glob("*.yml"), *workflow_dir.glob("*.yaml")})
    published: list[Path] = []
    for path in paths:
        source = path.read_text(encoding="utf-8")
        if _workflow_has_direct_docker_publish(source):
            published.append(path.relative_to(repo))
            continue
        for step in _docker_action_steps(source, path.relative_to(repo)):
            value = _docker_action_push_value(step, path.relative_to(repo))
            registry_output = _docker_action_has_registry_output(
                step, path.relative_to(repo)
            )
            if (value is not None and value != "false") or registry_output:
                published.append(path.relative_to(repo))
                break
    return tuple(sorted(set(published)))


def validate_docker_publish_workflow_classification(repo: Path) -> None:
    """Fail closed when an image-publishing workflow lacks review coverage."""

    runtime = set(DOCKER_PUBLISH_WORKFLOWS)
    nonshipping = set(NONSHIPPING_DOCKER_PUBLISH_WORKFLOWS)
    overlap = runtime.intersection(nonshipping)
    if overlap:
        raise RuntimeError(
            "Docker publish workflows have conflicting classifications: "
            f"{', '.join(map(str, sorted(overlap)))}"
        )

    discovered = set(docker_image_publish_workflows(repo))
    unclassified = discovered.difference(runtime, nonshipping)
    if unclassified:
        raise RuntimeError(
            "unclassified Docker image-publishing workflows: "
            f"{', '.join(map(str, sorted(unclassified)))}"
        )
    stale_exceptions = nonshipping.difference(discovered)
    if stale_exceptions:
        raise RuntimeError(
            "nonshipping Docker publish exceptions no longer push images: "
            f"{', '.join(map(str, sorted(stale_exceptions)))}"
        )

    direct_publishers = tuple(
        relative
        for relative in sorted(discovered)
        if _workflow_has_direct_docker_publish(
            (repo / relative).read_text(encoding="utf-8")
        )
    )
    if direct_publishers:
        raise RuntimeError(
            "direct Docker CLI publication requires explicit release-graph support: "
            f"{', '.join(map(str, direct_publishers))}"
        )


def _workflow_top_level_env(source: str) -> dict[str, str]:
    match = re.search(r"(?ms)^env:\s*\n(?P<body>(?:^  [^\n]+\n?)*)", source)
    if match is None:
        return {}
    values: dict[str, str] = {}
    for key, value in re.findall(
        r"(?m)^  ([A-Z][A-Z0-9_]*)\s*:\s*([^#\n]+?)\s*$", match.group("body")
    ):
        values[key] = value.strip().strip('"\'')
    return values


def _resolve_workflow_value(value: str, env: dict[str, str], path: Path) -> str:
    value = value.strip().strip('"\'')
    match = re.fullmatch(r"\$\{\{\s*env\.([A-Z][A-Z0-9_]*)\s*\}\}", value)
    if match is not None:
        key = match.group(1)
        if key not in env:
            raise RuntimeError(f"{path}: unresolved workflow environment value {key}")
        value = env[key]
    if "${{" in value or "$" in value:
        raise RuntimeError(f"{path}: dynamic workflow value is not reviewable: {value}")
    return value


def _split_features(value: str) -> tuple[str, ...]:
    return tuple(sorted({part for part in re.split(r"[,\s]+", value) if part}))


def _docker_build_arguments(
    step: str, env: dict[str, str], path: Path
) -> dict[str, str]:
    """Parse a Docker action's build-args field, rejecting opaque expansion."""

    lines = step.splitlines()
    entries: list[str] = []
    found = False
    for index, line in enumerate(lines):
        match = re.match(r"^(?P<indent>\s*)build-args:\s*(?P<value>.*?)\s*$", line)
        if match is None:
            continue
        if found:
            raise RuntimeError(f"{path}: Docker step declares build-args more than once")
        found = True
        inline = match.group("value").strip()
        if inline and inline not in {"|", "|-"}:
            entries.append(inline)
            continue
        field_indent = len(match.group("indent"))
        for candidate in lines[index + 1 :]:
            if not candidate.strip():
                continue
            indentation = len(candidate) - len(candidate.lstrip(" "))
            if indentation <= field_indent:
                break
            entry = candidate.strip()
            if entry.startswith("#"):
                continue
            entries.append(entry)

    arguments: dict[str, str] = {}
    for entry in entries:
        entry = entry.removeprefix("- ").strip().strip('"\'')
        match = re.fullmatch(r"([A-Z][A-Z0-9_]*)=(.*)", entry)
        if match is None:
            raise RuntimeError(
                f"{path}: Docker build-args must declare one reviewable KEY=value "
                f"per entry: {entry}"
            )
        key, value = match.groups()
        if key in arguments:
            raise RuntimeError(f"{path}: duplicate Docker build argument {key}")
        arguments[key] = (
            _resolve_workflow_value(value, env, path)
            if key in {"FEATURES", "CARGOFLAGS", "BINARIES"}
            else value
        )
    return arguments


def docker_publish_invocations(repo: Path) -> tuple[DockerInvocation, ...]:
    """Derive published Dockerfiles and their Cargo feature overrides."""

    validate_docker_publish_workflow_classification(repo)
    invocations: list[DockerInvocation] = []
    for relative in DOCKER_PUBLISH_WORKFLOWS:
        path = repo / relative
        source = path.read_text(encoding="utf-8")
        env = _workflow_top_level_env(source)
        for step in _docker_action_steps(source, relative):
            context_matches = re.findall(
                r"(?m)^\s+context:\s*([^#\n]+?)\s*$", step
            )
            if len(context_matches) != 1:
                raise RuntimeError(
                    f"{relative}: Docker publication must declare exactly one context"
                )
            context = _resolve_workflow_value(context_matches[0], env, relative)
            if context != ".":
                raise RuntimeError(
                    f"{relative}: Docker publication context must be the repository root '.'"
                )
            file_match = re.search(r"(?m)^\s+file:\s*([^#\n]+?)\s*$", step)
            dockerfile = (
                _resolve_workflow_value(file_match.group(1), env, relative)
                if file_match is not None
                else str(DOCKERFILE)
            )
            dockerfile_relative = Path(dockerfile)
            if dockerfile_relative.is_absolute() or ".." in dockerfile_relative.parts:
                raise RuntimeError(
                    f"{relative}: Dockerfile must be inside the repository context"
                )
            dockerfile_path = repo / dockerfile_relative
            if not dockerfile_path.resolve().is_relative_to(repo.resolve()):
                raise RuntimeError(
                    f"{relative}: Dockerfile must resolve inside the repository context"
                )
            dockerfile_source = dockerfile_path.read_text(encoding="utf-8")
            _validate_dockerfile_cargo_scope(dockerfile_source, dockerfile_relative)
            args = _docker_build_arguments(step, env, relative)
            undeclared_args = set(args).difference(
                _dockerfile_arg_names(dockerfile_source)
            )
            if undeclared_args:
                raise RuntimeError(
                    f"{relative}: Docker build arguments are not declared by "
                    f"{dockerfile_relative}: {', '.join(sorted(undeclared_args))}"
                )
            if "USE_PREBUILT" in args:
                raise RuntimeError(
                    f"{relative}: official workflow may not override USE_PREBUILT"
                )
            features = (
                _split_features(args["FEATURES"]) if "FEATURES" in args else None
            )
            cargo_flags = tuple(shlex.split(args.get("CARGOFLAGS", "")))
            if _cargo_scope_flags_are_forbidden(cargo_flags):
                raise RuntimeError(
                    f"{relative}: CARGOFLAGS may not expand the reviewed Docker target scope"
                )
            if "BINARIES" in args:
                raise RuntimeError(
                    f"{relative}: workflow BINARIES overrides require explicit guard support"
                )
            invocations.append(
                DockerInvocation(
                    workflow=str(relative),
                    dockerfile=dockerfile,
                    features=features,
                    cargo_flags=cargo_flags,
                )
            )
    if not invocations:
        raise RuntimeError("no published Docker invocations were derived")
    return tuple(
        sorted(
            set(invocations),
            key=lambda item: (
                item.workflow,
                item.dockerfile,
                item.features or (),
                item.features is None,
                item.cargo_flags,
            ),
        )
    )


def _validate_docker_acceleration_inputs(source: str, path: Path) -> None:
    """Keep every Linux image build bound to its signed bundled CUDA input."""

    markers = (
        "for input in aes.ptx bitonic_sort.ptx bn254.ptx poseidon.ptx sha256.ptx sha256_leaves.ptx sha256_pairs_reduce.ptx sha3.ptx signature.ptx vector.ptx provenance.v1 provenance.v1.pub provenance.v1.sig; do",
        'test -f "crates/ivm/cuda/${input}" && test ! -L "crates/ivm/cuda/${input}" || exit 1;',
    )
    if (any(source.count(marker) != 1 for marker in markers)
            or any(token in source for token in ("ivm-cuda", "IVM_CUDA_TRUSTED_KEY_SHA256", "IVM_CUDA_PTX_MODE"))):
        raise RuntimeError(f"{path}: fixed CUDA inventory preflight or retired input changed")


def docker_shipping_targets(
    repo: Path,
    catalog: WorkspaceCatalog | None = None,
    dockerfile: Path = DOCKERFILE,
    features: tuple[str, ...] | None = None,
    source_label: str | None = None,
) -> tuple[ShippingTarget, ...]:
    """Resolve one Docker publication profile to Cargo binary roots."""

    catalog = catalog or workspace_catalog(repo)
    path = repo / dockerfile
    source = path.read_text(encoding="utf-8")
    _validate_dockerfile_cargo_scope(source, dockerfile)
    binary_names = _dockerfile_binary_names(source, dockerfile, catalog)
    default_features = _quoted_arg_words(
        source, "FEATURES", dockerfile, required=False
    )
    global_features = frozenset(
        features if features is not None else default_features or ()
    )
    resolved = tuple(_resolve_binary(catalog, binary) for binary in binary_names)

    owned_features = {
        pair for value in global_features for pair in declared_feature_owners(value, catalog)
    }
    if any(target.package == "irohad" for target in resolved):
        _validate_docker_acceleration_inputs(source, dockerfile)

    targets: list[ShippingTarget] = []
    for target in resolved:
        features = set(target.required_features)
        features.update(
            feature for owner, feature in owned_features if owner == target.package
        )
        targets.append(
            ShippingTarget(
                package=target.package,
                binary=target.name,
                features=tuple(sorted(features)),
                default_features=True,
                source=source_label or str(dockerfile),
            )
        )
    return tuple(sorted(targets))


def _workflow_build_commands(source: str) -> tuple[tuple[str, ...], ...]:
    """Return logical Cargo build/rustc commands from workflow or shell text."""

    logical_lines: list[str] = []
    pending = ""
    for raw_line in source.splitlines():
        stripped = raw_line.strip()
        if pending:
            stripped = f"{pending}{stripped}"
        if stripped.endswith("\\"):
            pending = f"{stripped[:-1].rstrip()} "
            continue
        pending = ""
        if re.search(r"\bcargo(?:\s+\+\S+)?\s+(?:build|b|rustc)\b", stripped):
            logical_lines.append(stripped.removeprefix("run: "))
    if pending:
        raise RuntimeError("unterminated shell continuation in release workflow")

    commands: list[tuple[str, ...]] = []
    for line in logical_lines:
        tokens = shlex.split(line)
        try:
            cargo_index = next(
                index
                for index in range(len(tokens) - 1)
                if tokens[index] == "cargo"
                and (
                    tokens[index + 1] in {"build", "b", "rustc"}
                    or (
                        tokens[index + 1].startswith("+")
                        and index + 2 < len(tokens)
                        and tokens[index + 2] in {"build", "b", "rustc"}
                    )
                )
            )
        except StopIteration as error:
            raise RuntimeError(f"unable to parse Cargo build command: {line}") from error
        commands.append(tuple(tokens[cargo_index:]))
    return tuple(commands)


def _option_values(tokens: tuple[str, ...], *names: str) -> tuple[str, ...]:
    values: list[str] = []
    index = 0
    while index < len(tokens):
        token = tokens[index]
        if token in names:
            if index + 1 >= len(tokens):
                raise RuntimeError(f"missing value after {token}")
            values.append(tokens[index + 1])
            index += 2
            continue
        matched = next((name for name in names if token.startswith(f"{name}=")), None)
        if matched is not None:
            values.append(token.split("=", 1)[1])
        index += 1
    return tuple(values)


def _package_features(
    catalog: WorkspaceCatalog, package: str, values: tuple[str, ...], source: Path
) -> set[str]:
    features: set[str] = set()
    for value in values:
        for feature in _split_features(value):
            if "/" in feature:
                feature_package, feature_name = feature.split("/", 1)
                if feature_package != package:
                    continue
                feature = feature_name
            if feature not in catalog.package_features[package]:
                raise RuntimeError(f"{source}: {package} has no feature {feature!r}")
            features.add(feature)
    return features


def _nix_balanced_body(
    source: str,
    opening_index: int,
    opener: str,
    closer: str,
    relative: Path,
    label: str,
) -> tuple[str, int]:
    """Return one balanced Nix block while ignoring strings and comments."""

    if opening_index >= len(source) or source[opening_index] != opener:
        raise RuntimeError(f"{relative}: malformed Nix {label} block")
    depth = 0
    index = opening_index
    while index < len(source):
        if source.startswith("/*", index):
            comment_end = source.find("*/", index + 2)
            if comment_end < 0:
                raise RuntimeError(f"{relative}: unterminated comment in Nix {label}")
            index = comment_end + 2
            continue
        if source.startswith("''", index):
            string_end = source.find("''", index + 2)
            if string_end < 0:
                raise RuntimeError(
                    f"{relative}: unterminated indented string in Nix {label}"
                )
            index = string_end + 2
            continue
        character = source[index]
        if character == "#":
            newline = source.find("\n", index + 1)
            index = len(source) if newline < 0 else newline + 1
            continue
        if character == '"':
            index += 1
            while index < len(source):
                if source[index] == "\\":
                    index += 2
                    continue
                if source[index] == '"':
                    index += 1
                    break
                index += 1
            else:
                raise RuntimeError(f"{relative}: unterminated string in Nix {label}")
            continue
        if character == opener:
            depth += 1
        elif character == closer:
            depth -= 1
            if depth == 0:
                return source[opening_index + 1 : index], index + 1
            if depth < 0:
                break
        index += 1
    raise RuntimeError(f"{relative}: unterminated Nix {label} block")


def _nix_unique_balanced_assignment(
    source: str,
    pattern: str,
    opener: str,
    closer: str,
    relative: Path,
    label: str,
) -> str:
    """Return a uniquely named, semicolon-terminated Nix block."""

    matches = tuple(re.finditer(pattern, source, re.MULTILINE))
    if len(matches) != 1:
        raise RuntimeError(
            f"{relative}: Nix {label} must occur exactly once, found {len(matches)}"
        )
    opening_index = matches[0].end() - 1
    body, end = _nix_balanced_body(
        source, opening_index, opener, closer, relative, label
    )
    if re.match(r"\s*;", source[end:]) is None:
        raise RuntimeError(f"{relative}: Nix {label} must end with a semicolon")
    return body


def _nix_literal_feature_list(
    source: str, field: str, relative: Path, label: str
) -> tuple[str, ...]:
    """Parse a literal Nix string list used as a Cargo feature profile."""

    body = _nix_unique_balanced_assignment(
        source,
        rf"^\s*{re.escape(field)}\s*=\s*\[",
        "[",
        "]",
        relative,
        label,
    )
    literal = re.compile(r'"(?P<value>[^"\\]*)"')
    values: list[str] = []
    cursor = 0
    for match in literal.finditer(body):
        if body[cursor : match.start()].strip():
            raise RuntimeError(f"{relative}: Nix {label} must be a literal string list")
        value = match.group("value")
        split = _split_features(value)
        if not split:
            raise RuntimeError(f"{relative}: Nix {label} contains an empty feature")
        for feature in split:
            if re.fullmatch(
                r"[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)?", feature
            ) is None:
                raise RuntimeError(
                    f"{relative}: Nix {label} contains invalid feature {feature!r}"
                )
            values.append(feature)
        cursor = match.end()
    if body[cursor:].strip():
        raise RuntimeError(f"{relative}: Nix {label} must be a literal string list")
    if len(values) != len(set(values)):
        raise RuntimeError(f"{relative}: Nix {label} contains duplicate features")
    return tuple(values)


def _nix_literal_target_list(
    source: str, pattern: str, relative: Path, label: str
) -> tuple[tuple[str, str], ...]:
    """Parse literal ``package``/``binary`` attrsets from one Nix list."""

    body = _nix_unique_balanced_assignment(
        source, pattern, "[", "]", relative, label
    )
    assignment = re.compile(
        r'\b(?P<key>package|binary)\s*=\s*"(?P<value>[A-Za-z0-9_.-]+)"\s*;'
    )
    targets: list[tuple[str, str]] = []
    cursor = 0
    while cursor < len(body):
        whitespace = re.match(r"\s*", body[cursor:])
        assert whitespace is not None
        cursor += whitespace.end()
        if cursor == len(body):
            break
        if body[cursor] != "{":
            raise RuntimeError(
                f"{relative}: Nix {label} must contain only literal attrsets"
            )
        target_body, cursor = _nix_balanced_body(
            body, cursor, "{", "}", relative, label
        )
        fields: dict[str, str] = {}
        for match in assignment.finditer(target_body):
            key = match.group("key")
            if key in fields:
                raise RuntimeError(
                    f"{relative}: Nix {label} repeats target field {key}"
                )
            fields[key] = match.group("value")
        if assignment.sub("", target_body).strip():
            raise RuntimeError(
                f"{relative}: Nix {label} target must contain only package and binary"
            )
        if set(fields) != {"package", "binary"}:
            raise RuntimeError(
                f"{relative}: Nix {label} target needs package and binary"
            )
        targets.append((fields["package"], fields["binary"]))
    if not targets:
        raise RuntimeError(f"{relative}: Nix {label} may not be empty")
    if len(targets) != len(set(targets)):
        raise RuntimeError(f"{relative}: Nix {label} contains duplicate targets")
    return tuple(targets)


def _nix_mk_targets_region(source: str, relative: Path) -> str:
    """Return the bounded ``mkTargets`` definition before named outputs."""

    starts = tuple(re.finditer(r"^\s*mkTargets\s*=", source, re.MULTILINE))
    if len(starts) != 1:
        raise RuntimeError(
            f"{relative}: Nix mkTargets must occur exactly once, found {len(starts)}"
        )
    end = re.search(r"^\s*in\s+rec\s*\{", source[starts[0].end() :], re.MULTILINE)
    if end is None:
        raise RuntimeError(f"{relative}: Nix mkTargets has no bounded output region")
    return source[starts[0].start() : starts[0].end() + end.start()]


def _nix_output_body(source: str, relative: Path) -> str:
    """Return the complete unmerged top-level output attrset."""

    matches = tuple(re.finditer(r"^\s*in\s+rec\s*\{", source, re.MULTILINE))
    if len(matches) != 1:
        raise RuntimeError(
            f"{relative}: Nix output attrset must occur exactly once, found {len(matches)}"
        )
    opening_index = matches[0].end() - 1
    body, end = _nix_balanced_body(
        source, opening_index, "{", "}", relative, "release outputs"
    )
    if re.fullmatch(r"\s*\)\s*;\s*\}\s*", source[end:]) is None:
        raise RuntimeError(
            f"{relative}: Nix release outputs may not be merged or replaced"
        )
    return body


def _nix_named_package_outputs(source: str, relative: Path) -> tuple[str, ...]:
    """Return exact literal package-output names and reject opaque attributes."""

    body = _nix_output_body(source, relative)
    if re.search(r"(?m)^\s*inherit\b[^;\n]*\bpackages\b", body):
        raise RuntimeError(
            f"{relative}: inherited Nix package outputs require explicit guard support"
        )

    outputs: list[str] = []
    assignment = re.compile(r"(?m)^\s*(?P<lhs>[^#\n=]+?)\s*=")
    for match in assignment.finditer(body):
        lhs = match.group("lhs").strip()
        literal = re.fullmatch(r"packages\.([A-Za-z0-9_.-]+)", lhs)
        if literal is not None:
            outputs.append(literal.group(1))
            continue
        if (
            re.search(r"(?:^|[^A-Za-z0-9_-])packages(?:[^A-Za-z0-9_-]|$)", lhs)
            or lhs.startswith(('"', "''", "${"))
        ):
            raise RuntimeError(
                f"{relative}: quoted or dynamic Nix package output is not reviewable: "
                f"{lhs}"
            )
    return tuple(outputs)


def _validate_nix_cargo_envelope(source: str, relative: Path) -> None:
    """Authenticate the only Cargo option construction used by ``mkIroha``."""

    matches = tuple(
        re.finditer(
            r"(?ms)^\s*cargoBuildOptions\s*=\s*default:\s*(?P<body>.*?);\s*$",
            source,
        )
    )
    if len(matches) != 1:
        raise RuntimeError(
            f"{relative}: Nix cargoBuildOptions must occur exactly once, found "
            f"{len(matches)}"
        )
    observed = re.sub(r"\s+", " ", matches[0].group("body")).strip()
    expected = (
        'default ++ ["--target" targetTriple] '
        '++ builtins.concatMap (target: ["-p" target.package "--bin" '
        'target.binary]) binaries ++ (if releaseFeatures == [] then [] else '
        '["--features" (builtins.concatStringsSep "," releaseFeatures)])'
    )
    if observed != expected:
        raise RuntimeError(
            f"{relative}: Nix cargoBuildOptions is not the reviewed target/feature envelope"
        )

    capability_markers = (
        'includesDaemon = builtins.any (binary: binary.package == "irohad") binaries;',
        'needsCuda = includesDaemon && (lib.hasInfix "-linux-" targetTriple || lib.hasInfix "-windows-" targetTriple);',
        'releaseFeatures = lib.unique features;',
        "preBuild = lib.optionalString needsCuda ''",
        "test -f \"crates/ivm/cuda/''${input}\" && test ! -L \"crates/ivm/cuda/''${input}\" || exit 1",
        'for input in aes.ptx bitonic_sort.ptx bn254.ptx poseidon.ptx sha256.ptx sha256_leaves.ptx sha256_pairs_reduce.ptx sha3.ptx signature.ptx vector.ptx provenance.v1 provenance.v1.pub provenance.v1.sig; do',
    )
    if (any(source.count(marker) != 1 for marker in capability_markers)
            or any(token in source for token in ("ivm-cuda", "IVM_CUDA_PTX_MODE", "IVM_CUDA_TRUSTED_KEY_SHA256", "cudaTrustedKeySha256"))):
        raise RuntimeError(f"{relative}: target-qualified acceleration inventory preflight changed")

    rustflag_assignments = tuple(
        re.findall(
            r'(?m)^\s*((?:[A-Za-z_][A-Za-z0-9_]*)?RUSTFLAGS)\s*=\s*"([^"]*)"\s*;\s*$',
            source,
        )
    )
    if rustflag_assignments != (("RUSTFLAGS", "-C linker=${CC}"),):
        raise RuntimeError(
            f"{relative}: Nix Rust feature/cfg flags are not the reviewed linker-only value"
        )


def _validate_nix_appimage_helper(repo: Path) -> None:
    """Bind the AppImage payload to the derivation supplied as ``drv``."""

    relative = NIX_APPIMAGE_OWNER_ROOT / "flake.nix"
    source = (repo / relative).read_text(encoding="utf-8")
    required = (
        r"^\s*mkappimage\s*=\s*\{\s*drv\s*,\s*name\s*\}\s*:\s*$",
        r"^\s*closure\s*=\s*pkgs\.writeReferencesToFile\s+drv\s*;\s*$",
        r'^\s*entrypoint\s*=\s*"\$\{drv\}/bin/\$\{name\}"\s*;\s*$',
        r"^\s*mksquashfs\s+\$\(cat\s+\$\{closure\}\)\s+\$out\s+\\\s*$",
    )
    for pattern in required:
        if len(re.findall(pattern, source, re.MULTILINE)) != 1:
            raise RuntimeError(
                f"{relative}: AppImage derivation provenance contract changed"
            )
    if re.search(
        r"(?<![A-Za-z0-9_-])(?:cargo|rustc)(?:\s|$)|"
        r"(?<![A-Za-z0-9_-])(?:--features|-F|--all-features)(?:[=\s]|$)",
        source,
        re.MULTILINE,
    ):
        raise RuntimeError(
            f"{relative}: AppImage helper may not compile or select Cargo features"
        )


def _nix_shipping_feature_sets(
    catalog: WorkspaceCatalog,
    selected_packages: tuple[str, ...],
    values: tuple[str, ...],
    relative: Path,
    label: str,
) -> dict[str, tuple[str, ...]]:
    """Resolve one Nix Cargo feature list without discarding foreign owners."""

    selected = set(selected_packages)
    unknown = selected.difference(catalog.package_features)
    if unknown:
        raise RuntimeError(f"{relative}: unknown Nix shipping packages: {sorted(unknown)}")
    features: dict[str, set[str]] = {package: set() for package in selected}
    for value in values:
        if "/" in value:
            owner, feature = value.split("/", 1)
            if owner not in selected:
                raise RuntimeError(
                    f"{relative}: Nix {label} feature owner {owner!r} is not a "
                    "selected shipping package"
                )
            if feature not in catalog.package_features[owner]:
                raise RuntimeError(
                    f"{relative}: Nix {label} package {owner} has no feature {feature!r}"
                )
            features[owner].add(feature)
            continue
        owners = tuple(
            package
            for package in sorted(selected)
            if value in catalog.package_features[package]
        )
        if len(owners) != 1:
            raise RuntimeError(
                f"{relative}: Nix {label} feature {value!r} must have exactly one "
                f"selected owner, found {len(owners)}"
            )
        features[owners[0]].add(value)
    return {package: tuple(sorted(active)) for package, active in features.items()}


def nix_shipping_targets(
    repo: Path, catalog: WorkspaceCatalog | None = None
) -> tuple[ShippingTarget, ...]:
    """Resolve Cargo profiles behind the repository's named Nix outputs."""

    catalog = catalog or workspace_catalog(repo)
    relative = NIX_RELEASE_OWNER
    source = (repo / relative).read_text(encoding="utf-8")
    _validate_nix_cargo_envelope(source, relative)
    _validate_nix_appimage_helper(repo)
    named_outputs = _nix_named_package_outputs(source, relative)
    if len(named_outputs) != 4 or set(named_outputs) != {
        "iroha3",
        "default",
        "appimage",
        "targets",
    }:
        raise RuntimeError(
            f"{relative}: Nix named package outputs require explicit guard support"
        )
    required_exact_lines = (
        r'^\s*nix-appimage\.url\s*=\s*"path:nix-appimage"\s*;\s*$',
        r"^\s*packages\.default\s*=\s*packages\.iroha3\s*;\s*$",
    )
    for pattern in required_exact_lines:
        if len(re.findall(pattern, source, re.MULTILINE)) != 1:
            raise RuntimeError(f"{relative}: Nix named release aliases changed")

    all_binaries = _nix_literal_target_list(
        source,
        r"^\s*allBinaries\s*=\s*\[",
        relative,
        "allBinaries",
    )
    if len(re.findall(r"\bbinaries\s*\?\s*allBinaries\b", source)) != 1:
        raise RuntimeError(f"{relative}: mkIroha must default to allBinaries")

    iroha3 = _nix_unique_balanced_assignment(
        source,
        r"^\s*packages\.iroha3\s*=\s*mkIroha\s*\{",
        "{",
        "}",
        relative,
        "packages.iroha3",
    )
    if re.search(r"^\s*binaries\s*=", iroha3, re.MULTILINE):
        raise RuntimeError(f"{relative}: packages.iroha3 may not override allBinaries")
    iroha3_features = _nix_literal_feature_list(
        iroha3, "features", relative, "packages.iroha3 features"
    )

    appimage = _nix_unique_balanced_assignment(
        source,
        r"^\s*packages\.appimage\s*=\s*nix-appimage\.mkappimage\.\$\{system\}\s*\{",
        "{",
        "}",
        relative,
        "packages.appimage",
    )
    canonical_appimage = re.sub(r"\s+", " ", appimage).strip()
    if canonical_appimage != 'drv = packages.iroha3; name = "iroha3";':
        raise RuntimeError(
            f"{relative}: packages.appimage must wrap packages.iroha3 exactly "
            "with the reviewed entrypoint"
        )

    mk_targets = _nix_mk_targets_region(source, relative)
    if len(
        re.findall(r"^\s*features\s*=\s*features\s*;\s*$", mk_targets, re.MULTILINE)
    ) != 1:
        raise RuntimeError(f"{relative}: mkTargets must forward its feature profile")
    target_binaries = _nix_literal_target_list(
        mk_targets,
        r"^\s*binaries\s*=\s*\[",
        relative,
        "mkTargets binaries",
    )
    targets_output = _nix_unique_balanced_assignment(
        source,
        r"^\s*packages\.targets\s*=\s*mkTargets\s*\{",
        "{",
        "}",
        relative,
        "packages.targets",
    )
    target_features = _nix_literal_feature_list(
        targets_output, "features", relative, "packages.targets features"
    )

    targets: list[ShippingTarget] = []
    for pairs, values, label in (
        (all_binaries, iroha3_features, "packages.iroha3"),
        (target_binaries, target_features, "packages.targets"),
    ):
        feature_sets = _nix_shipping_feature_sets(
            catalog,
            tuple(package for package, _ in pairs),
            values,
            relative,
            label,
        )
        for package, binary in pairs:
            resolved = _resolve_binary(catalog, binary, package)
            features = set(feature_sets[package])
            features.update(resolved.required_features)
            targets.append(
                ShippingTarget(
                    package=package,
                    binary=binary,
                    features=tuple(sorted(features)),
                    default_features=True,
                    source=f"{relative}:{label}",
                )
            )
    return tuple(sorted(set(targets)))


def cargo_shipping_targets(
    repo: Path, relative: Path, catalog: WorkspaceCatalog | None = None
) -> tuple[ShippingTarget, ...]:
    """Resolve explicit Cargo binary/native-library roots in one declaration."""

    catalog = catalog or workspace_catalog(repo)
    source = (repo / relative).read_text(encoding="utf-8")
    targets: list[ShippingTarget] = []
    for command in _workflow_build_commands(source):
        if command in NONSHIPPING_WORKFLOW_BUILD_COMMANDS.get(relative, ()):
            continue
        packages = _option_values(command, "-p", "--package")
        binaries = _option_values(command, "--bin")
        if len(packages) != 1:
            raise RuntimeError(
                f"{relative}: shipping Cargo commands must select exactly one package"
            )
        package = packages[0]
        if package not in catalog.package_features:
            raise RuntimeError(f"{relative}: unknown shipping package {package!r}")
        feature_values = _option_values(command, "-F", "--features")
        foreign_features = tuple(
            feature
            for value in feature_values
            for feature in _split_features(value)
            if "/" in feature and feature.split("/", 1)[0] != package
        )
        if foreign_features:
            raise RuntimeError(
                f"{relative}: cross-package shipping features require explicit "
                f"profiles: {', '.join(foreign_features)}"
            )
        if "--bins" in command or "--all-targets" in command:
            raise RuntimeError(
                f"{relative}: broad Cargo target selectors require explicit guard support"
            )
        features = _package_features(
            catalog,
            package,
            feature_values,
            relative,
        )
        if "--all-features" in command:
            features.update(catalog.package_features[package])
        default_features = "--no-default-features" not in command
        if not binaries and package in catalog.native_libraries:
            targets.append(
                ShippingTarget(
                    package=package,
                    binary="<native-library>",
                    features=tuple(sorted(features)),
                    default_features=default_features,
                    source=str(relative),
                )
            )
        elif not binaries:
            raise RuntimeError(
                f"{relative}: shipping package {package!r} must name its binary target"
            )
        for binary in binaries:
            target = _resolve_binary(catalog, binary, package)
            target_features = features.union(target.required_features)
            targets.append(
                ShippingTarget(
                    package=package,
                    binary=binary,
                    features=tuple(sorted(target_features)),
                    default_features=default_features,
                    source=str(relative),
                )
            )
    return tuple(sorted(set(targets)))


def workflow_shipping_targets(
    repo: Path, catalog: WorkspaceCatalog | None = None
) -> tuple[ShippingTarget, ...]:
    """Resolve SoraFS CLI release workflow Cargo builds."""

    return cargo_shipping_targets(repo, SORAFS_RELEASE_WORKFLOW, catalog)


def native_artifact_targets(
    repo: Path, catalog: WorkspaceCatalog | None = None
) -> tuple[ShippingTarget, ...]:
    """Resolve published native libraries and their declared feature profiles."""

    catalog = catalog or workspace_catalog(repo)
    targets = list(
        itertools.chain.from_iterable(
            cargo_shipping_targets(repo, relative, catalog)
            for relative in NATIVE_ARTIFACT_WORKFLOWS
        )
    )
    script = (repo / NATIVE_BRIDGE_BUILD_SCRIPT).read_text(encoding="utf-8")
    package_match = re.search(r'^LIB_CRATE_NAME="([^"]+)"$', script, re.MULTILINE)
    if package_match is None:
        raise RuntimeError(f"{NATIVE_BRIDGE_BUILD_SCRIPT}: missing library package")
    package = package_match.group(1)
    if package not in catalog.native_libraries:
        raise RuntimeError(
            f"{NATIVE_BRIDGE_BUILD_SCRIPT}: {package} is not a native library package"
        )
    if 'CARGO_FEATURE_ARGS=(--features privacy-production-enabled)' not in script:
        raise RuntimeError(f"{NATIVE_BRIDGE_BUILD_SCRIPT}: mandatory native recipe changed")
    if 'PRIVACY_PRODUCTION_ENABLED' in script:
        raise RuntimeError(f"{NATIVE_BRIDGE_BUILD_SCRIPT}: retired privacy mode selector")
    if "privacy-production-enabled" not in catalog.package_features[package]:
        raise RuntimeError(f"{NATIVE_BRIDGE_BUILD_SCRIPT}: missing native provenance feature")
    for caller in NATIVE_BRIDGE_CALLER_WORKFLOWS:
        caller_source = (repo / caller).read_text(encoding="utf-8")
        if str(NATIVE_BRIDGE_BUILD_SCRIPT) not in caller_source:
            raise RuntimeError(f"{caller}: native bridge build script is not invoked")
    for feature_set in (("privacy-production-enabled",),):
        targets.append(
            ShippingTarget(
                package=package,
                binary="<native-library>",
                features=feature_set,
                default_features=True,
                source=str(NATIVE_BRIDGE_BUILD_SCRIPT),
            )
        )
    targets.extend(android_native_artifact_targets(repo, catalog))
    return tuple(sorted(set(targets)))


def android_native_artifact_targets(
    repo: Path, catalog: WorkspaceCatalog | None = None
) -> tuple[ShippingTarget, ...]:
    """Authenticate the Gradle-owned Cargo graph shipped in Android artifacts."""

    catalog = catalog or workspace_catalog(repo)
    workflow = (repo / Path(".github/workflows/mobile_sdk_artifacts.yml")).read_text(
        encoding="utf-8"
    )
    if workflow.count(":client-android:buildNativeLibs") != 1:
        raise RuntimeError(
            "mobile SDK workflow must invoke :client-android:buildNativeLibs once"
        )
    if "-PprivacyProductionEnabled" in workflow:
        raise RuntimeError(
            "mobile SDK workflow must use the sole default Android native profile"
        )

    source = (repo / ANDROID_NATIVE_BUILD_OWNER).read_text(encoding="utf-8")
    command_marker = "val command = buildList {"
    if source.count(command_marker) != 1:
        raise RuntimeError(
            f"{ANDROID_NATIVE_BUILD_OWNER}: Android Cargo command owner is ambiguous"
        )
    command_start = source.index(command_marker)
    command_end = source.index("execOperations.exec {", command_start)
    command = source[command_start:command_end]
    packages = tuple(re.findall(r'"-p",\s*"([A-Za-z0-9_.-]+)"', command))
    if packages != ("connect_norito_bridge",):
        raise RuntimeError(
            f"{ANDROID_NATIVE_BUILD_OWNER}: Android Cargo package must be exactly "
            "connect_norito_bridge"
        )
    feature_values = tuple(
        re.findall(
            r'addAll\(listOf\("--features",\s*"([A-Za-z0-9_.-]+)"\)\)',
            command,
        )
    )
    if feature_values != ("privacy-production-enabled",):
        raise RuntimeError(
            f"{ANDROID_NATIVE_BUILD_OWNER}: Android Cargo feature profile changed"
        )
    if command.count('"--features"') != 1 or "--all-features" in command:
        raise RuntimeError(
            f"{ANDROID_NATIVE_BUILD_OWNER}: Android Cargo feature scope is not exact"
        )
    # Cargo uses the authenticated workspace root lock through the canonical
    # root manifest. --lockfile-path belongs to the source-seal helper only;
    # the hermetic Cargo owner deliberately rejects alternate lock authorities.
    required_markers = (
        'tools.hermeticRunner.toString()',
        '"--profile",\n                        "android-cargo"',
    )
    cargo_envelope = (
        r'"build",\s*"--locked",\s*"--offline",\s*'
        r'"--jobs",\s*"1",\s*"--manifest-path",\s*'
        r'irohaRoot\.resolve\("Cargo\.toml"\)\.absolutePath'
    )
    if (
        any(marker not in command for marker in required_markers)
        or len(re.findall(cargo_envelope, command)) != 1
    ):
        raise RuntimeError(
            f"{ANDROID_NATIVE_BUILD_OWNER}: Android Cargo envelope is incomplete"
        )
    command_literals = re.findall(r'"([^"\n]*)"', command)
    if (
        any(command_literals.count(value) != 1 for value in (
            "build", "--locked", "--offline", "--jobs", "--manifest-path",
        ))
        or any(
            value.startswith(("-j", "-Z", "--jobs=", "--manifest-path=",
                              "--lockfile-path", "--config"))
            for value in command_literals
        )
    ):
        raise RuntimeError(
            f"{ANDROID_NATIVE_BUILD_OWNER}: Android Cargo envelope is not exact"
        )
    root_lock_markers = (
        'val cargoLock = canonicalIrohaRoot.resolve("Cargo.lock")',
        "Files.isRegularFile(cargoLock, LinkOption.NOFOLLOW_LINKS)",
        "!Files.isSymbolicLink(cargoLock)",
        "cargoLock.toRealPath(LinkOption.NOFOLLOW_LINKS) == cargoLock",
    )
    if any(marker not in source for marker in root_lock_markers):
        raise RuntimeError(
            f"{ANDROID_NATIVE_BUILD_OWNER}: Android root Cargo.lock custody changed"
        )
    packaging_markers = (
        "inputDirectory.set(compileNativeLibs.flatMap { it.outputDirectory })",
        'tasks.register("buildNativeLibs")',
        "dependsOn(stripNativeLibs)",
    )
    if any(marker not in source for marker in packaging_markers):
        raise RuntimeError(
            f"{ANDROID_NATIVE_BUILD_OWNER}: Android native packaging chain changed"
        )

    runner = (repo / ANDROID_HERMETIC_RUNNER).read_text(encoding="utf-8")
    runner_markers = (
        'if args.profile == "android-cargo":',
        'root_lock, lock_identity = authenticate_regular_file(\n'
        '        "Android root Cargo.lock",\n'
        '        canonical_workspace / "Cargo.lock",',
        'manifest_position = exact_pair("--manifest-path", '
        'str(canonical_workspace / "Cargo.toml"))',
        'value == "--lockfile-path"',
        'for name, (path, expected_identity) in authenticated_files.items():',
        '_, current_identity = authenticate_regular_file(name, path)',
        'if current_identity != expected_identity:',
        'resolved != authenticated_tools["CARGO"][0]',
    )
    tracked_lock_call = (
        r'authenticated_files\["Android root Cargo\.lock"\]\s*=\s*'
        r'authenticate_android_cargo_arguments\(\s*args\.command\s*\)'
    )
    if (
        any(marker not in runner for marker in runner_markers)
        or len(re.findall(tracked_lock_call, runner)) != 1
    ):
        raise RuntimeError(
            f"{ANDROID_HERMETIC_RUNNER}: Android Cargo authentication changed"
        )

    package = packages[0]
    if package not in catalog.native_libraries:
        raise RuntimeError(
            f"{ANDROID_NATIVE_BUILD_OWNER}: {package} is not a native library"
        )
    feature = feature_values[0]
    if feature not in catalog.package_features[package]:
        raise RuntimeError(
            f"{ANDROID_NATIVE_BUILD_OWNER}: unknown {package} feature {feature}"
        )
    return (
        ShippingTarget(
            package=package,
            binary="<native-library>",
            features=("privacy-production-enabled",),
            default_features=True,
            source=str(ANDROID_NATIVE_BUILD_OWNER),
        ),
    )


def canonical_release_bundle_policy(repo: Path) -> str:
    """Require authenticated provenance for the mandatory prebuilt corridor."""

    bundle_source = (repo / RELEASE_BUNDLE_SCRIPT).read_text(encoding="utf-8")
    if 'case "$1" in' not in bundle_source or "--features)" not in bundle_source:
        raise RuntimeError(
            f"{RELEASE_BUNDLE_SCRIPT}: standalone feature input contract changed"
        )
    image_source = (repo / RELEASE_IMAGE_SCRIPT).read_text(encoding="utf-8")
    runner_source = (repo / ISOLATED_RELEASE_RUNNER).read_text(encoding="utf-8")
    runner_markers = (
        "ALLOWED_TOOLS = frozenset(",
        '"generate_release_manifest.py"',
        '"write_release_sha256sums.py"',
        '"fastpq/rollout_manifest_summary.py"',
        '"verify_release_prebuilt_provenance.py"',
        "RELEASE_ARTIFACT_CONTRACT_SHA256",
        "REVIEWED_TOOL_SHA256",
        "hashlib.sha256(payload).hexdigest()",
        "os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW",
        "directory_flags = file_flags | os.O_DIRECTORY",
        "before.st_nlink != 1",
        "stat.S_IWGRP | stat.S_IWOTH",
        'os.open(name, file_flags, dir_fd=directory_descriptor)',
        "identity(before) != identity(after)",
        'exec(compile(payload, str(path), "exec"), module.__dict__)',
        'exec(compile(payload, str(path), "exec"), namespace)',
        "contract.stable_read_relative(",
        "_load_fastpq_summary_dependencies()",
    )
    if any(marker not in runner_source for marker in runner_markers) or any(
        marker in runner_source
        for marker in ("sys.path.insert", "runpy.run_path", "exec_module")
    ):
        raise RuntimeError(
            f"{ISOLATED_RELEASE_RUNNER}: isolated release helper trust boundary changed"
        )
    provenance_marker = "verify_release_prebuilt_provenance.py"
    required_provenance_controls = (
        "--trusted-manifest-sha256",
        "--source-commit",
        "--cargo-lock",
        "--target",
        "--cargo-profile",
        "--features",
        '"${provenance_binaries[@]}"',
        "--output-directory",
    )
    for script, source in (
        (RELEASE_BUNDLE_SCRIPT, bundle_source),
        (RELEASE_IMAGE_SCRIPT, image_source),
    ):
        capability_markers = (
            "from release_artifact_contract import release_acceleration_features",
            'release_acceleration_features(sys.argv[2], filter(None, sys.argv[3].split(",")))',
            'require_release_cuda_source_inputs(Path(sys.argv[1]).parent, sys.argv[2])',
        )
        if any(source.count(marker) != 1 for marker in capability_markers):
            raise RuntimeError(f"{script}: target acceleration or independent CUDA trust handoff changed")
        environment_markers = (
            "#!/usr/bin/env -S -u BASH_ENV -u ENV -u SHELLOPTS -u BASHOPTS "
            "-u PS4 -u BASH_XTRACEFD -u CDPATH -u GLOBIGNORE bash -p\n",
            "set -euo pipefail\n",
            "CARGO_ENCODED_RUSTFLAGS CARGO_ENCODED_RUSTDOCFLAGS CARGO_HOME",
            "RUSTC RUSTC_WRAPPER RUSTC_WORKSPACE_WRAPPER RUSTDOC RUSTDOCFLAGS RUSTFLAGS",
            "for release_environment_name in ${!CARGO_BUILD_@}; do",
            "for release_environment_name in ${!CARGO_TARGET_@}; do",
            "*_LINKER|*_RUNNER|*_RUSTFLAGS|*_RUSTDOCFLAGS)",
        )
        if any(marker not in source for marker in environment_markers):
            raise RuntimeError(
                f"{script}: hostile shell/Python/Rust environment scrub changed"
            )
        if source.count(
            'release_python=(python3 -I -S "$repo_root/scripts/'
            'run_isolated_release_tool.py")'
        ) != 1:
            raise RuntimeError(
                f"{script}: isolated release helper launcher changed"
            )
        if len(re.findall(r"(?m)^validate_release_source$", source)) != 2:
            raise RuntimeError(
                f"{script}: clean source-commit preflight/recheck changed"
            )
        if re.search(r'python3[ \t]+"\$repo_root/scripts/', source):
            raise RuntimeError(
                f"{script}: release Python helper bypasses isolated launcher"
            )
        if source.count(provenance_marker) != 1:
            raise RuntimeError(
                f"{script}: prebuilt provenance verifier contract changed"
            )
        if source.count(
            '"${release_python[@]}" "$repo_root/scripts/'
            'verify_release_prebuilt_provenance.py"'
        ) != 1:
            raise RuntimeError(
                f"{script}: prebuilt provenance verifier must run through the "
                "reviewed isolated loader"
            )
        provenance_start = source.index(provenance_marker)
        provenance_end = source.find("--output-directory", provenance_start)
        if provenance_end < 0:
            raise RuntimeError(
                f"{script}: prebuilt provenance verifier invocation is unbounded"
            )
        provenance_invocation = source[
            provenance_start : provenance_end + len("--output-directory") + 128
        ]
        if any(
            provenance_invocation.count(control) != 1
            for control in required_provenance_controls
        ):
            raise RuntimeError(
                f"{script}: prebuilt provenance verifier contract changed"
            )

    bundle_binary_root_assignments = tuple(
        match.group(1).strip()
        for match in re.finditer(r"(?m)^\s*binary_root=(.+)$", bundle_source)
    )
    if (
        bundle_binary_root_assignments
        != ('""', '"$stage_parent/prebuilt-bin"')
        or bundle_source.count(
        'stage_release_file "$binary_root/'
        )
        != 7
        or bundle_source.count(
            "--prebuilt-bin-dir is required for deterministic release bundles"
        )
        != 1
        or re.search(r"(?m)^\s*cargo(?:_command)?=.*\bbuild\b", bundle_source)
    ):
        raise RuntimeError(
            f"{RELEASE_BUNDLE_SCRIPT}: verified private prebuilt snapshot consumption changed"
        )
    image_prebuilt_assignments = tuple(
        match.group(1).strip()
        for match in re.finditer(r"(?m)^\s*prebuilt_bin_dir=(.+)$", image_source)
    )
    if image_prebuilt_assignments != (
        '""',
        '"$2"',
        '"$prebuilt_snapshot"',
    ) or image_source.count(
        '--source "$prebuilt_bin_dir/$binary"'
    ) != 1:
        raise RuntimeError(
            f"{RELEASE_IMAGE_SCRIPT}: verified private prebuilt snapshot consumption changed"
        )
    pipeline = (repo / CANONICAL_RELEASE_PIPELINE).read_text(encoding="utf-8")
    bootstrap_markers = (
        "_BOOTSTRAP_RELEASE_MODULE_SHA256",
        "_stable_bootstrap_sources()",
        "os.O_RDONLY | os.O_CLOEXEC | os.O_DIRECTORY | os.O_NOFOLLOW",
        "before.st_nlink != 1",
        "stat.S_IWGRP | stat.S_IWOTH",
        "_normalized_bootstrap_payload(name, bytes(payload))",
        "hashlib.sha256(normalized).hexdigest()",
        'exec(compile(payload, str(path), "exec"), module.__dict__)',
    )
    if any(marker not in pipeline for marker in bootstrap_markers) or any(
        marker in pipeline for marker in ("importlib.util", "exec_module")
    ):
        raise RuntimeError(
            f"{CANONICAL_RELEASE_PIPELINE}: bootstrap helper authentication changed"
        )
    release_source_markers = (
        "def validate_release_source(commit: str, action: str) -> None:",
        "validate_trusted_release_surface_commit(REPO_ROOT, commit)",
        'validate_release_source(commit, "Release source preflight failed")',
        "Android Maven publication refused changed release source",
        "lambda: run(publish_cmd, env=publisher_env)",
        "Aggregate manifest signing refused changed release source",
        "Release source changed during pipeline execution",
    )
    if any(marker not in pipeline for marker in release_source_markers):
        raise RuntimeError(
            f"{CANONICAL_RELEASE_PIPELINE}: reviewed source-commit preflight/recheck changed"
        )
    for hostile_environment in (
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
    ):
        if f'"{hostile_environment}"' not in pipeline:
            raise RuntimeError(
                f"{CANONICAL_RELEASE_PIPELINE}: hostile subprocess environment scrub changed"
            )
    if (
        '"BASH_FUNC_", "CARGO_BUILD_"' not in pipeline
        or 'name.startswith("CARGO_TARGET_")' not in pipeline
        or '"_LINKER", "_RUNNER", "_RUSTFLAGS", "_RUSTDOCFLAGS"' not in pipeline
        or 'run_isolated_release_tool.py"),' not in pipeline
        or "executable.resolve().is_relative_to(_SCRIPT_DIRECTORY)" not in pipeline
    ):
        raise RuntimeError(
            f"{CANONICAL_RELEASE_PIPELINE}: child execution isolation changed"
        )
    if pipeline.count('rpartition(\n            "@sha256:"\n        )') != 1:
        raise RuntimeError(
            f"{CANONICAL_RELEASE_PIPELINE}: prebuilt path and reviewed provenance "
            "digest are not parsed as one authenticated identity"
        )
    invocations: dict[str, str] = {}
    for label, marker in (
        ("bundle", 'REPO_ROOT / "scripts" / "build_release_bundle.sh"'),
        ("image", 'REPO_ROOT / "scripts" / "build_release_image.sh"'),
    ):
        if pipeline.count(marker) != 1:
            raise RuntimeError(
                f"{CANONICAL_RELEASE_PIPELINE}: canonical {label} invocation is ambiguous"
            )
        start = pipeline.index(marker)
        invocation_tail = pipeline[start:]
        invocation_end = invocation_tail.find("\n                ]")
        if invocation_end < 0:
            raise RuntimeError(
                f"{CANONICAL_RELEASE_PIPELINE}: canonical {label} invocation is unbounded"
            )
        invocation = invocation_tail[:invocation_end]
        if invocation.count('"--prebuilt-bin-dir"') != 1 or invocation.count(
            '"--trusted-prebuilt-provenance-sha256"'
        ) != 1:
            raise RuntimeError(
                f"{CANONICAL_RELEASE_PIPELINE}: canonical {label} prebuilt "
                "provenance handoff changed"
            )
        invocations[label] = invocation
    for label, invocation in invocations.items():
        if '"--features"' in invocation:
            raise RuntimeError(
                f"{CANONICAL_RELEASE_PIPELINE}: official {label} may not accept a "
                "dynamic feature override"
            )
    return "authenticated-prebuilt-reviewed-profile"


def release_bundle_targets(
    repo: Path, catalog: WorkspaceCatalog | None = None
) -> tuple[ShippingTarget, ...]:
    """Resolve the standalone bundle's authenticated prebuilt package roots."""

    catalog = catalog or workspace_catalog(repo)
    source = (repo / RELEASE_BUNDLE_SCRIPT).read_text(encoding="utf-8")
    output_binaries = tuple(
        dict.fromkeys(
            re.findall(
                r'(?m)^(?:daemon|governance_dag|cli|utility|sanitizer|signer)_bin="([^"]+)"$',
                source,
            )
        )
    )
    if not output_binaries:
        raise RuntimeError(f"{RELEASE_BUNDLE_SCRIPT}: no bundle binaries derived")
    fixed_features = tuple(
        re.findall(r"--features\s+([A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+)", source)
    )
    targets: list[ShippingTarget] = []
    for binary in output_binaries:
        target = _resolve_binary(catalog, binary)
        features = _package_features(
            catalog, target.package, fixed_features, RELEASE_BUNDLE_SCRIPT
        )
        features.update(target.required_features)
        # Mandatory platform dependencies carry the canonical target union.
        targets.append(
            ShippingTarget(
                package=target.package,
                binary=binary,
                features=tuple(sorted(features)),
                default_features=True,
                source=str(RELEASE_BUNDLE_SCRIPT),
            )
        )

    canonical_release_bundle_policy(repo)
    return tuple(sorted(set(targets)))


def declared_shipping_targets(repo: Path) -> tuple[ShippingTarget, ...]:
    """Return targets derived from every repository shipping declaration."""

    validate_trusted_release_surface(repo)
    catalog = workspace_catalog(repo)
    return _declared_shipping_targets_from_catalog(repo, catalog)



def _declared_shipping_targets_from_catalog(
    repo: Path, catalog: WorkspaceCatalog
) -> tuple[ShippingTarget, ...]:
    """Analyze declarations using an explicit catalog, without release admission or Cargo."""

    docker_targets: list[ShippingTarget] = []
    for invocation in docker_publish_invocations(repo):
        relative = Path(invocation.dockerfile)
        docker_targets.extend(
            docker_shipping_targets(
                repo,
                catalog,
                relative,
                invocation.features,
                f"{invocation.workflow}->{invocation.dockerfile}",
            )
        )
    return tuple(
        sorted(
            set(
                (
                    *docker_targets,
                    *workflow_shipping_targets(repo, catalog),
                    *native_artifact_targets(repo, catalog),
                    *nix_shipping_targets(repo, catalog),
                    *release_bundle_targets(repo, catalog),
                )
            )
        )
    )


def declared_feature_owners(value: str, catalog: WorkspaceCatalog) -> tuple[tuple[str, str], ...]:
    """Bind qualified Cargo feature names to exactly their declared package."""

    if "/" in value:
        owner, feature = value.split("/", 1)
        if feature not in catalog.package_features.get(owner, ()):
            raise RuntimeError(f"no workspace package declares qualified feature {value!r}")
        return ((owner, feature),)
    owners = tuple((package, value) for package, features in catalog.package_features.items() if value in features)
    if not owners:
        raise RuntimeError(f"no workspace package declares feature {value!r}")
    return owners


def shipping_profiles(repo: Path) -> tuple[ShippingProfile, ...]:
    """Return distinct baseline and declaration-derived shipping profiles."""

    # Validate the reviewed source surface before Cargo reads repository-owned
    # manifests or configuration, including during baseline package discovery.
    targets = declared_shipping_targets(repo)
    catalog = workspace_catalog(repo)
    return _shipping_profiles_from_catalog(repo, catalog, targets)



def _shipping_profiles_from_catalog(
    repo: Path,
    catalog: WorkspaceCatalog,
    targets: tuple[ShippingTarget, ...],
) -> tuple[ShippingProfile, ...]:
    """Aggregate explicit declaration results without claiming release qualification."""

    missing = set(BASELINE_PACKAGES).difference(catalog.package_features)
    if missing:
        raise RuntimeError(f"missing baseline shipping packages: {sorted(missing)}")
    profiles = {
        ShippingProfile(package=package) for package in BASELINE_PACKAGES
    }
    profiles.update(
        ShippingProfile(
            package=target.package,
            features=target.features,
            default_features=target.default_features,
        )
        for target in targets
    )
    for invocation in docker_publish_invocations(repo):
        source = (repo / invocation.dockerfile).read_text(encoding="utf-8")
        declared_features = invocation.features
        if declared_features is None:
            declared_features = _quoted_arg_words(
                source, "FEATURES", Path(invocation.dockerfile), required=False
            ) or ()
        for feature in declared_features:
            profiles.update(
                ShippingProfile(package=package, features=(local_feature,))
                for package, local_feature in declared_feature_owners(feature, catalog)
            )
    ordered = tuple(sorted(profiles))
    validate_shipping_profile_policy(ordered)
    return ordered


def validate_shipping_profile_policy(
    profiles: tuple[ShippingProfile, ...],
) -> None:
    """Reject unknown shipping packages and non-reviewed root features."""

    failures: list[str] = []
    for profile in profiles:
        allowed = SHIPPING_ROOT_FEATURE_ALLOWLIST.get(profile.package)
        if allowed is None:
            failures.append(f"{profile.label()}: package has no shipping feature policy")
            continue
        unexpected = sorted(set(profile.features).difference(allowed))
        if unexpected:
            failures.append(
                f"{profile.label()}: unreviewed root features "
                f"{', '.join(unexpected)}"
            )
    if failures:
        raise RuntimeError("shipping feature policy violations:\n- " + "\n- ".join(failures))


def feature_graph(
    repo: Path,
    package: str,
    features: tuple[str, ...] = (),
    default_features: bool = True,
) -> str:
    """Return Cargo's normal/build feature graph for one shipping profile."""

    command = [
        "cargo",
        "tree",
        "--locked",
        "--target",
        "all",
        "--package",
        package,
        "--edges",
        "normal,build,features",
        "--prefix",
        "none",
    ]
    if not default_features:
        command.append("--no-default-features")
    if features:
        command.extend(("--features", ",".join(features)))

    completed = subprocess.run(
        command,
        cwd=repo,
        check=False,
        capture_output=True,
        text=True,
        env=_cargo_subprocess_environment(),
    )
    if completed.returncode != 0:
        raise RuntimeError(
            f"cargo tree failed for {package}:\n{completed.stdout}{completed.stderr}"
        )
    return completed.stdout


def forbidden_features_in_graph(graph: str) -> tuple[str, ...]:
    """Return development-only feature markers present in a Cargo graph."""

    return tuple(feature for feature in FORBIDDEN_FEATURES if feature in graph)


def unauthorized_root_features_in_graph(
    graph: str, package: str
) -> tuple[str, ...]:
    """Return active root-package features outside the positive shipping policy."""

    allowed = SHIPPING_ROOT_FEATURE_ALLOWLIST.get(package)
    if allowed is None:
        return (f"{package} has no shipping feature policy",)
    active = {
        match.group("feature")
        for match in re.finditer(
            rf'(?m)^{re.escape(package)} feature "(?P<feature>[^"]+)"(?: \(\*\))?$',
            graph,
        )
    }
    return tuple(sorted(active.difference(allowed)))


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--package",
        action="append",
        dest="packages",
        help="shipping package to inspect (repeatable)",
    )
    parser.add_argument(
        "--validate-source-commit",
        help="validate only the sealed clean release surface at this full commit",
    )
    args = parser.parse_args()
    repo = Path(__file__).resolve().parents[1]
    if args.validate_source_commit:
        validate_trusted_release_surface_commit(
            repo, args.validate_source_commit
        )
        print("trusted release source commit and surface passed")
        return 0
    validate_daemon_cuda_target_dependency(repo)
    profiles = shipping_profiles(repo)
    if args.packages:
        selected: list[ShippingProfile] = []
        for package in args.packages:
            matches = tuple(profile for profile in profiles if profile.package == package)
            selected.extend(matches or (ShippingProfile(package=package),))
        profiles = tuple(sorted(set(selected)))
    failures: list[str] = []
    for profile in profiles:
        graph = feature_graph(
            repo,
            profile.package,
            profile.features,
            profile.default_features,
        )
        for forbidden in forbidden_features_in_graph(graph):
            failures.append(f"{profile.label()}: enabled {forbidden}")
        for unauthorized in unauthorized_root_features_in_graph(
            graph, profile.package
        ):
            failures.append(
                f"{profile.label()}: enabled unreviewed root feature {unauthorized}"
            )
        for required in REQUIRED_FEATURES.get(profile.package, ()):
            if required not in graph:
                failures.append(f"{profile.label()}: missing {required}")
    if failures:
        print("shipping feature graph violations:", file=sys.stderr)
        for failure in failures:
            print(f"- {failure}", file=sys.stderr)
        return 1
    print(
        "declared shipping feature graphs preserve proof engines and exclude test fixtures"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
