#!/usr/bin/env python3
"""Run one mobile native-build command with an exact environment.

This launcher is shared by the Apple, Android, and host-JNI build gates.  Its
profiles are deliberately closed inventories: a caller must provide every
declared variable and cannot add undeclared variables.  In particular, ambient
Cargo/Rust compiler flags and wrapper variables never reach the child process.
The launcher creates no runtime, hardware or financial authority.
"""

from __future__ import annotations

import argparse
import stat
import os
import pathlib
import re
import subprocess
import sys


COMMON_CARGO_ENVIRONMENT = frozenset(
    {
        "CARGO",
        "CARGO_HOME",
        "CARGO_INCREMENTAL",
        "CARGO_NET_OFFLINE",
        "CARGO_TARGET_DIR",
        "HOME",
        "LANG",
        "LC_ALL",
        "NORITO_SKIP_BINDINGS_SYNC",
        "PATH",
        "RUSTC",
        "RUSTUP_HOME",
        "TMPDIR",
    }
)
SERIALIZED_CARGO_ENVIRONMENT = COMMON_CARGO_ENVIRONMENT | {
    "CARGO_BUILD_JOBS",
    "RUSTDOC",
}
APPLE_CARGO_ENVIRONMENT = SERIALIZED_CARGO_ENVIRONMENT | {
    "CONNECT_NORITO_SOURCE_REVISION",
    "IROHA_GIT_COMMIT_HASH",
    "VERGEN_GIT_SHA",
}
ANDROID_CARGO_ENVIRONMENT = SERIALIZED_CARGO_ENVIRONMENT | {
    "ANDROID_NDK_HOME",
    "ANDROID_NDK_ROOT",
}
WALLET_RUNTIME_TRUST_INPUT = "MOBILE_SDK_WALLET_RUNTIME_TRUST_ED25519_HEX"
WALLET_RUNTIME_AUTHORITY_INPUT = "MOBILE_SDK_WALLET_RUNTIME_AUTHORITY"
WALLET_RUNTIME_AUTHORITIES = frozenset({"bpng-taira-v7", "cbsi-release-v1"})


def wallet_runtime_authority(value: str) -> str:
    """Validate the immutable application parser selected by the genuine build owner."""
    if value not in WALLET_RUNTIME_AUTHORITIES:
        raise RuntimeError("native wallet runtime authority must be bpng-taira-v7 or cbsi-release-v1")
    return value


def wallet_runtime_trust(value: str) -> str:
    """Validate public build DATA; it grants no runtime or monetary authority."""
    if re.fullmatch(r"[0-9a-f]{64}", value) is None or value == "0" * 64:
        raise RuntimeError("native wallet runtime trust must be nonzero lowercase 32-byte hex")
    return value


GRADLE_JVM_ENVIRONMENT = frozenset(
    {
        "ANDROID_HOME",
        "ANDROID_SDK_ROOT",
        "DYLD_LIBRARY_PATH",
        "GRADLE_USER_HOME",
        "HOME",
        "IROHA_NATIVE_LIBRARY_PATH",
        "IROHA_REQUIRE_SORAFS_NATIVE_VALIDATION",
        "JAVA_HOME",
        "LANG",
        "LC_ALL",
        "LD_LIBRARY_PATH",
        "PATH",
        "TMPDIR",
    }
)
AUTHENTICATED_CARGO_PROFILES = frozenset(
    {
        "android-cargo",
        "android-armv7-diagnostic-cargo",
        "apple-ios-device",
        "apple-ios-simulator",
        "apple-macos",
    }
)
PROFILES = {
    "apple-ios-device": APPLE_CARGO_ENVIRONMENT
    | {
        "DEVELOPER_DIR",
        "IPHONEOS_DEPLOYMENT_TARGET",
        "SDKROOT",
    },
    "apple-ios-simulator": APPLE_CARGO_ENVIRONMENT
    | {
        "DEVELOPER_DIR",
        "IPHONEOS_DEPLOYMENT_TARGET",
        "IPHONESIMULATOR_DEPLOYMENT_TARGET",
        "SDKROOT",
    },
    "apple-macos": APPLE_CARGO_ENVIRONMENT
    | {
        "DEVELOPER_DIR",
        "MACOSX_DEPLOYMENT_TARGET",
        "SDKROOT",
    },
    "android-cargo": ANDROID_CARGO_ENVIRONMENT,
    "android-armv7-diagnostic-cargo": ANDROID_CARGO_ENVIRONMENT,
    "host-cargo": COMMON_CARGO_ENVIRONMENT,
    "gradle-jvm": GRADLE_JVM_ENVIRONMENT,
    "gradle-jvm-localnet": GRADLE_JVM_ENVIRONMENT
    | {
        "IROHA_LOCALNET_DIR",
        "IROHA_LOCALNET_TEST",
    },
}


for _profile in AUTHENTICATED_CARGO_PROFILES:
    PROFILES[_profile] = PROFILES[_profile] | {WALLET_RUNTIME_TRUST_INPUT, WALLET_RUNTIME_AUTHORITY_INPUT}


def validate_profile_environment(profile: str, environment: dict[str, str]) -> None:
    """Enforce an exact profile and mandatory immutable public Native signer root."""
    expected = PROFILES[profile]
    actual = set(environment)
    if actual != expected:
        raise RuntimeError(
            f"{profile} environment inventory is not exact "
            f"(missing={sorted(expected - actual)}, unexpected={sorted(actual - expected)})"
        )
    if profile in AUTHENTICATED_CARGO_PROFILES:
        wallet_runtime_trust(environment[WALLET_RUNTIME_TRUST_INPUT])
        wallet_runtime_authority(environment[WALLET_RUNTIME_AUTHORITY_INPUT])


def parse_assignment(raw: str) -> tuple[str, str]:
    if "=" not in raw:
        raise argparse.ArgumentTypeError("--set requires NAME=VALUE")
    name, value = raw.split("=", 1)
    if not name or any(character not in "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_" for character in name):
        raise argparse.ArgumentTypeError(f"invalid environment variable name: {name!r}")
    if "\0" in value:
        raise argparse.ArgumentTypeError(f"{name} contains a NUL byte")
    return name, value


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--profile", choices=sorted(PROFILES), required=True)
    parser.add_argument("--working-directory", type=pathlib.Path)
    parser.add_argument(
        "--set",
        dest="assignments",
        action="append",
        default=[],
        type=parse_assignment,
        metavar="NAME=VALUE",
    )
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    if args.command[:1] == ["--"]:
        args.command = args.command[1:]
    if not args.command:
        parser.error("an executable and command arguments are required after --")
    return args


def authenticate_regular_executable(name: str, raw: str) -> tuple[pathlib.Path, tuple[int, ...]]:
    candidate = pathlib.Path(raw)
    if not candidate.is_absolute() or candidate != pathlib.Path(os.path.abspath(candidate)):
        raise RuntimeError(f"{name} must name an absolute canonical executable")
    try:
        metadata = candidate.lstat()
        resolved = candidate.resolve(strict=True)
        resolved_metadata = resolved.stat()
    except OSError as error:
        raise RuntimeError(f"{name} executable is unavailable: {candidate}") from error
    if (
        resolved != candidate
        or not candidate.is_file()
        or not os.access(candidate, os.X_OK)
        or metadata.st_mode != resolved_metadata.st_mode
    ):
        raise RuntimeError(f"{name} must name a non-symbolic regular executable: {candidate}")
    identity = (
        resolved_metadata.st_dev,
        resolved_metadata.st_ino,
        resolved_metadata.st_mode,
        resolved_metadata.st_size,
        resolved_metadata.st_mtime_ns,
    )
    return resolved, identity


def authenticate_regular_file(name: str, candidate: pathlib.Path) -> tuple[pathlib.Path, tuple[int, ...]]:
    if not candidate.is_absolute() or candidate != pathlib.Path(os.path.abspath(candidate)):
        raise RuntimeError(f"{name} must name an absolute canonical regular file")
    try:
        metadata = candidate.lstat()
        resolved = candidate.resolve(strict=True)
        resolved_metadata = resolved.stat()
    except OSError as error:
        raise RuntimeError(f"{name} is unavailable: {candidate}") from error
    if (
        resolved != candidate
        or not candidate.is_file()
        or metadata.st_mode != resolved_metadata.st_mode
    ):
        raise RuntimeError(f"{name} must name a non-symbolic regular file: {candidate}")
    identity = (
        resolved_metadata.st_dev,
        resolved_metadata.st_ino,
        resolved_metadata.st_mode,
        resolved_metadata.st_size,
        resolved_metadata.st_mtime_ns,
    )
    return resolved, identity


def authenticate_cargo_environment(
    environment: dict[str, str],
) -> dict[str, tuple[pathlib.Path, tuple[int, ...]]]:
    exact_values = {
        "CARGO_BUILD_JOBS": "1",
        "CARGO_INCREMENTAL": "0",
        "CARGO_NET_OFFLINE": "true",
        "NORITO_SKIP_BINDINGS_SYNC": "1",
    }
    for name, expected in exact_values.items():
        if environment[name] != expected:
            raise RuntimeError(f"{name} must be exactly {expected!r}")

    source_revision_names = (
        "CONNECT_NORITO_SOURCE_REVISION",
        "IROHA_GIT_COMMIT_HASH",
        "VERGEN_GIT_SHA",
    )
    if source_revision_names[0] in environment:
        revisions = [environment[name] for name in source_revision_names]
        if (
            len(set(revisions)) != 1
            or re.fullmatch(r"[0-9a-f]{40}", revisions[0]) is None
        ):
            raise RuntimeError(
                "Apple source revision variables must be identical canonical commits"
            )

    target = pathlib.Path(environment["CARGO_TARGET_DIR"])
    if not target.is_absolute() or target != pathlib.Path(os.path.abspath(target)):
        raise RuntimeError("CARGO_TARGET_DIR must be an absolute canonical directory")
    try:
        metadata = target.lstat()
        resolved = target.resolve(strict=True)
    except OSError as error:
        raise RuntimeError(f"CARGO_TARGET_DIR is unavailable: {target}") from error
    if resolved != target or not target.is_dir() or metadata.st_mode != target.stat().st_mode:
        raise RuntimeError(
            f"CARGO_TARGET_DIR must be a non-symbolic canonical directory: {target}"
        )

    return {
        name: authenticate_regular_executable(name, environment[name])
        for name in ("CARGO", "RUSTC", "RUSTDOC")
    }


def authenticate_android_cargo_arguments(
    command: list[str],
) -> tuple[pathlib.Path, tuple[int, ...]]:
    workspace = pathlib.Path.cwd()
    canonical_workspace = workspace.resolve(strict=True)
    if workspace != canonical_workspace:
        raise RuntimeError("Android Cargo working directory must be absolute and canonical")
    root_lock, lock_identity = authenticate_regular_file(
        "Android root Cargo.lock",
        canonical_workspace / "Cargo.lock",
    )
    arguments = command[1:]

    def exact_token(name: str) -> int:
        positions = [index for index, value in enumerate(arguments) if value == name]
        if len(positions) != 1:
            raise RuntimeError(f"Android Cargo command requires exactly one {name}")
        return positions[0]

    def exact_pair(name: str, expected: str) -> int:
        position = exact_token(name)
        if position + 1 >= len(arguments) or arguments[position + 1] != expected:
            raise RuntimeError(
                f"Android Cargo command requires the exact sequence {name} {expected}"
            )
        return position

    build_position = exact_token("build")
    locked_position = exact_token("--locked")
    offline_position = exact_token("--offline")
    jobs_position = exact_pair("--jobs", "1")
    manifest_position = exact_pair("--manifest-path", str(canonical_workspace / "Cargo.toml"))
    if not (
        build_position
        < locked_position
        < offline_position
        < jobs_position
        < manifest_position
    ):
        raise RuntimeError(
            "Android Cargo command must use build --locked --offline --jobs 1 "
            "--manifest-path <root Cargo.toml> in that order"
        )
    if any(
        value == "-j"
        or (value.startswith("-j") and value != "-Z")
        or value.startswith("--jobs=")
        or value.startswith("--manifest-path=")
        or value == "--lockfile-path"
        or value.startswith("--lockfile-path=")
        or value == "--config"
        or value.startswith("--config=")
        or value.startswith("-Z")
        for value in arguments
    ):
        raise RuntimeError("Android Cargo command contains an alternate Cargo envelope form")
    return root_lock, lock_identity


def android_cargo_configuration(
    root: pathlib.Path, cache: pathlib.Path, invocation: pathlib.Path,
    *, diagnostic: bool = False,
) -> dict[str, object]:
    import importlib.util
    policy = pathlib.Path(__file__).with_name("norito_bridge_local_integration.py")
    specification = importlib.util.spec_from_file_location("android_diagnostic_configuration_policy", policy)
    if specification is None or specification.loader is None:
        raise RuntimeError("Android diagnostic configuration policy is unavailable")
    owner = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(owner)
    if diagnostic:
        return owner.android_armv7_diagnostic_configuration(
            root, cache, invocation, local_integration=True,
        )
    return owner.android_cargo_configuration(root, cache, invocation)


def android_armv7_diagnostic_configuration(
    root: pathlib.Path, cache: pathlib.Path, invocation: pathlib.Path,
) -> dict[str, object]:
    return android_cargo_configuration(root, cache, invocation, diagnostic=True)


def authenticate_android_armv7_diagnostic_arguments(command: list[str]) -> None:
    """Require the entire single-ABI diagnostic recipe, not a release selector."""
    root = pathlib.Path.cwd()
    arguments = command[1:]
    if len(arguments) != 17 or arguments[:3] != ["ndk", "-t", "armeabi-v7a"]:
        raise RuntimeError("Android armv7 diagnostic requires the exact single-ABI recipe")
    output = pathlib.Path(arguments[4])
    if (arguments[3] != "-o" or not output.is_absolute()
            or output != pathlib.Path(os.path.abspath(output))
            or output.resolve(strict=True) != output
            or not output.is_dir()
            or output != root / "dist/norito-bridge-android-local/gradle-build/iroha_kotlin_sdk/client-android/native/cargo-ndk-staging/armv7-diagnostic/armeabi-v7a"
            or arguments[5:] != [
                "build", "--locked", "--offline", "--jobs", "1",
                "--manifest-path", str(root / "Cargo.toml"), "--release",
                "-p", "connect_norito_bridge", "--features", "privacy-production-enabled",
            ]):
        raise RuntimeError("Android armv7 diagnostic requires the exact single-ABI recipe")


# Cargo reads configuration from the invocation directory, every ancestor and
# CARGO_HOME even when the child environment is closed. Keep network/registry
# configuration usable, while refusing a second compiler/profile authority.
_BUILD_CARGO_CONFIG_MAX_BYTES = 1024 * 1024
_CARGO_BUILTIN_ALIASES = frozenset({
    "add", "b", "bench", "build", "c", "check", "clean", "clippy", "doc", "d",
    "fetch", "fix", "fmt", "generate-lockfile", "help", "init", "install",
    "locate-project", "login", "logout", "metadata", "new", "owner", "package",
    "pkgid", "publish", "r", "read-manifest", "remove", "report", "run", "rustc",
    "rustdoc", "search", "t", "test", "tree", "uninstall", "update", "vendor",
    "verify-project", "version", "yank",
})


def _build_cargo_config_observation(candidate: pathlib.Path) -> tuple[object, ...] | None:
    import hashlib
    import stat

    if candidate.resolve(strict=False) != candidate:
        raise RuntimeError(f"Native Cargo configuration path is not canonical: {candidate}")
    try:
        descriptor = os.open(candidate, os.O_RDONLY | os.O_NONBLOCK | getattr(os, "O_NOFOLLOW", 0))
    except FileNotFoundError:
        return None
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or before.st_size > _BUILD_CARGO_CONFIG_MAX_BYTES:
            raise RuntimeError(f"Native Cargo configuration is not a bounded regular file: {candidate}")
        chunks: list[bytes] = []
        length = 0
        while True:
            chunk = os.read(descriptor, min(64 * 1024, _BUILD_CARGO_CONFIG_MAX_BYTES + 1 - length))
            if not chunk:
                break
            chunks.append(chunk)
            length += len(chunk)
            if length > _BUILD_CARGO_CONFIG_MAX_BYTES:
                raise RuntimeError(f"Native Cargo configuration exceeds its byte limit: {candidate}")
        after = os.fstat(descriptor)
        linked = candidate.lstat()
        identity = lambda value: (value.st_dev, value.st_ino, value.st_mode, value.st_size, value.st_mtime_ns, value.st_ctime_ns)
        if (identity(before) != identity(after) or identity(after) != identity(linked)
                or length != after.st_size or candidate.resolve(strict=True) != candidate):
            raise RuntimeError(f"Native Cargo configuration changed during inspection: {candidate}")
        contents = b"".join(chunks)
    finally:
        os.close(descriptor)
    try:
        import tomllib
        config = tomllib.loads(contents.decode("utf-8"))
    except (ImportError, UnicodeError, ValueError) as error:
        raise RuntimeError(f"Native Cargo configuration cannot be parsed with Python 3.11+ TOML: {candidate}") from error
    # [env] can override any declared compiler variable using force=true and
    # defeats a closed child inventory even when its key is otherwise unknown.
    for table in ("profile", "unstable", "env", "paths", "patch", "include"):
        if table in config:
            raise RuntimeError(f"Native Cargo configuration forbids {table}: {candidate}")
    build = config.get("build", {})
    if not isinstance(build, dict):
        raise RuntimeError(f"Native Cargo build configuration is not a table: {candidate}")
    compile_keys = {
        "rustc", "rustc-wrapper", "rustc-workspace-wrapper", "rustdoc", "rustflags",
        "rustdocflags", "target", "target-dir", "build-dir", "jobs", "incremental",
    }
    if compile_keys.intersection(build):
        raise RuntimeError(f"Native Cargo configuration overrides the compiler envelope: {candidate}")
    # Every target-specific table can select a linker/runner, add flags or
    # override build-script outputs through a links-name subtable.
    if config.get("target"):
        raise RuntimeError(f"Native Cargo configuration overrides a target: {candidate}")
    aliases = config.get("alias", {})
    if not isinstance(aliases, dict) or _CARGO_BUILTIN_ALIASES.intersection(aliases):
        raise RuntimeError(f"Native Cargo configuration overrides a built-in command: {candidate}")
    return (*identity(after), hashlib.sha256(contents).hexdigest())


def authenticate_build_cargo_configuration(
    directory: pathlib.Path, cargo_home: pathlib.Path,
) -> dict[pathlib.Path, tuple[object, ...] | None]:
    """Authenticate every effective Cargo config, including absent candidates.

    Apple Cargo and Android cargo-ndk use the same configuration authority.
    The caller must recheck the returned observations after its Cargo command.
    """
    for name, value in (("invocation directory", directory), ("CARGO_HOME", cargo_home)):
        if not value.is_absolute() or value.resolve(strict=False) != value:
            raise RuntimeError(f"Native Cargo {name} must be absolute and canonical")
    candidates: dict[pathlib.Path, None] = {}
    for parent in (directory, *directory.parents):
        for filename in ("config", "config.toml"):
            candidates[parent / ".cargo" / filename] = None
    for filename in ("config", "config.toml"):
        candidates[cargo_home / filename] = None
    return {candidate: _build_cargo_config_observation(candidate) for candidate in candidates}


def recheck_build_cargo_configuration(
    observations: dict[pathlib.Path, tuple[object, ...] | None],
) -> None:
    """Refuse changed, replaced, newly created or removed Cargo config files."""
    for candidate, expected in observations.items():
        if _build_cargo_config_observation(candidate) != expected:
            raise RuntimeError(f"Native Cargo configuration changed during invocation: {candidate}")


def authenticate_cargo_invocation_directory(
    root: pathlib.Path, directory: pathlib.Path,
) -> tuple[pathlib.Path, tuple[int, ...]]:
    """Pin an explicit private Cargo cwd outside the authenticated source tree."""
    if not directory.is_absolute() or directory != pathlib.Path(os.path.abspath(directory)):
        raise RuntimeError("MOBILE_SDK_CARGO_INVOCATION_DIR must be an absolute canonical directory")
    try:
        metadata = directory.lstat()
        resolved = directory.resolve(strict=True)
    except OSError as error:
        raise RuntimeError("MOBILE_SDK_CARGO_INVOCATION_DIR must already exist") from error
    if (resolved != directory or not stat.S_ISDIR(metadata.st_mode)
            or stat.S_ISLNK(metadata.st_mode) or metadata.st_uid != os.geteuid()
            or stat.S_IMODE(metadata.st_mode) != 0o700
            or not os.access(directory, os.R_OK | os.W_OK | os.X_OK)
            or directory == root or root in directory.parents or directory in root.parents):
        raise RuntimeError("MOBILE_SDK_CARGO_INVOCATION_DIR must be an owned writable non-symbolic canonical mode-0700 directory disjoint from source")
    return directory, (
        metadata.st_dev, metadata.st_ino, metadata.st_mode, metadata.st_uid, metadata.st_gid,
    )


def recheck_cargo_invocation_directory(
    root: pathlib.Path, observation: tuple[pathlib.Path, tuple[int, ...]],
) -> None:
    """Refuse replacement or custody changes to the actual Cargo working directory."""
    if authenticate_cargo_invocation_directory(root, observation[0]) != observation:
        raise RuntimeError("Native Cargo invocation directory changed during invocation")


def main() -> int:
    args = parse_args()
    environment: dict[str, str] = {}
    for name, value in args.assignments:
        if name in environment:
            raise RuntimeError(f"duplicate environment assignment: {name}")
        environment[name] = value
    validate_profile_environment(args.profile, environment)
    source_root = pathlib.Path.cwd()
    invocation_directory = source_root
    invocation_observation = None
    if args.working_directory is not None:
        if not args.profile.startswith("apple-") and args.profile not in {"android-cargo", "android-armv7-diagnostic-cargo"}:
            raise RuntimeError("an explicit Cargo working directory requires an authenticated Apple or Android Cargo profile")
        invocation_observation = authenticate_cargo_invocation_directory(
            source_root, args.working_directory
        )
        invocation_directory = invocation_observation[0]

    if args.profile == "android-armv7-diagnostic-cargo":
        if invocation_observation is None:
            raise RuntimeError("Android armv7 diagnostics require an authenticated external working directory")
        expected_target = source_root / "dist/norito-bridge-android-local/gradle-build/iroha_kotlin_sdk/client-android/native/cargo-target/armv7-diagnostic"
        if environment["CARGO_TARGET_DIR"] != str(expected_target):
            raise RuntimeError("Android armv7 diagnostics require the fixed warm Cargo target")
        diagnostic_configuration = android_armv7_diagnostic_configuration(
            source_root, pathlib.Path(environment["CARGO_HOME"]), invocation_directory,
        )
        authenticate_android_armv7_diagnostic_arguments(args.command)
    else:
        diagnostic_configuration = None
    cargo_configuration = (
        android_cargo_configuration(
            source_root, pathlib.Path(environment["CARGO_HOME"]), invocation_directory,
        ) if args.profile == "android-cargo" and invocation_observation is not None else None
    )

    authenticated_tools: dict[str, tuple[pathlib.Path, tuple[int, ...]]] = {}
    authenticated_files: dict[str, tuple[pathlib.Path, tuple[int, ...]]] = {}
    build_configuration = {}
    if args.profile in AUTHENTICATED_CARGO_PROFILES:
        build_configuration = authenticate_build_cargo_configuration(
            invocation_directory, pathlib.Path(environment["CARGO_HOME"])
        )
    if args.profile in AUTHENTICATED_CARGO_PROFILES:
        authenticated_tools = authenticate_cargo_environment(environment)
    if args.profile in {"android-cargo", "android-armv7-diagnostic-cargo"}:
        authenticated_files["Android root Cargo.lock"] = authenticate_android_cargo_arguments(
            args.command
        )

    executable = pathlib.Path(args.command[0])
    if not executable.is_absolute():
        raise RuntimeError(f"hermetic command executable must be absolute: {executable}")
    resolved = executable.resolve(strict=True)
    if not resolved.is_file() or not os.access(resolved, os.X_OK):
        raise RuntimeError(f"hermetic command executable is not a regular executable: {resolved}")
    if (
        args.profile in AUTHENTICATED_CARGO_PROFILES
        and resolved != authenticated_tools["CARGO"][0]
    ):
        raise RuntimeError(
            "Cargo command does not match the authenticated CARGO executable"
        )

    if invocation_observation is not None:
        recheck_cargo_invocation_directory(source_root, invocation_observation)

    completed = subprocess.run(
        [str(resolved), *args.command[1:]],
        env=environment,
        close_fds=True,
        check=False,
        cwd=invocation_directory,
    )
    if invocation_observation is not None:
        recheck_cargo_invocation_directory(source_root, invocation_observation)
    recheck_build_cargo_configuration(build_configuration)
    if (diagnostic_configuration is not None
            and android_armv7_diagnostic_configuration(
                source_root, pathlib.Path(environment["CARGO_HOME"]), invocation_directory,
            ) != diagnostic_configuration):
        raise RuntimeError("Android diagnostic configuration or custody changed during invocation")
    if (cargo_configuration is not None
            and android_cargo_configuration(
                source_root, pathlib.Path(environment["CARGO_HOME"]), invocation_directory,
            ) != cargo_configuration):
        raise RuntimeError("Android Cargo configuration or custody changed during invocation")
    for name, (path, expected_identity) in authenticated_tools.items():
        _, current_identity = authenticate_regular_executable(name, str(path))
        if current_identity != expected_identity:
            raise RuntimeError(f"{name} changed during the hermetic Cargo invocation")
    for name, (path, expected_identity) in authenticated_files.items():
        _, current_identity = authenticate_regular_file(name, path)
        if current_identity != expected_identity:
            raise RuntimeError(f"{name} changed during the hermetic Cargo invocation")
    return completed.returncode


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, RuntimeError) as error:
        print(f"mobile hermetic command failed: {error}", file=sys.stderr)
        raise SystemExit(1) from error
