#!/usr/bin/env python3
"""Check and prepare local Taira binaries without deployment authority.

Requires Python 3.11+, Git, the repository Rust toolchain, a warm Cargo target,
and explicitly hash-pinned Zig/cargo-zigbuild executables. Optional `check` runs
development diagnostics in the existing sibling .taira-testnet-build-targets/routine
lane (override with --target-dir or TAIRA_TESTNET_CARGO_TARGET_DIR; both must agree).
`prepare` keeps repo target/ by default, ignoring the development-only environment
selector, and builds the four Linux release binaries
from one fixed Git-object source capture with six jobs and captures read-only
copies. Explicit --source-mode canonical-checkout instead compiles the selected
checkout; its HEAD, index and tracked bytes must match the signed selection before
and after work. The immutable capture remains authority evidence only. This mode
is available for prepare, prepare-client and prepare-native-runtime. Rerun the same prepare command to reuse completed captures or retry an
incomplete local build in the same warm Cargo lane. Failed attempt directories
and logs remain intact. Preparation records native_check_scope=build-only
and checks.passed=false, without running native regression checks. Its signed
source, pinned tools and captured release artifacts retain the same custody;
it is unqualified build evidence, never a Basic or Full pass. Native deployment
preflight, finality, readiness and custody checks remain mandatory. Write-canary,
restart and broad public-doctor diagnostics never gate signing, transfer or deployment.
The persistent compiler cache starts through a descriptor-isolated version probe
before Cargo inherits the build locks; existing cache contents are preserved.
For a mutable-source prequalification diagnostic, check accepts repeatable
--focus-regression HARNESS=EXACT_TEST: run selected portable ownership tests first,
then mandatory configuration and remaining selected harnesses in the same warm
lane. Both phases must pass. Optional --session-dir creates a fresh private
background diagnostic with durable request/log/result records; check-status reads
its inherited flock and completion record after the launching terminal exits.
Status includes the immutable request path and explicit focus count, not the selector list.
No session is resumed or restarted automatically. It writes no qualification checkpoint and cannot
be selected by prepare.
Development checks default to LLVM 18 on Linux, requiring /usr/bin/clang-18 and
/usr/bin/ld.lld-18 before compilation; missing tools fail without fallback.
Install clang-18 and lld-18 with the platform package manager, or explicitly select
--native-linker system for diagnosis. macOS keeps the system Apple linker. Changing this
selection invalidates Cargo fingerprints and can rebuild dependencies once in the
same warm lane; repeating the selection reuses them. Authenticated prepare pins
--native-linker, platform, and the native Rust linker driver's compiler/linker paths,
SHA256 digests and sizes in its request and revalidates them before and after work
and on resume. Linux defaults to LLVM 18; explicit system uses the same clang-18
driver with /usr/bin/ld. macOS system uses the selected Xcode Apple clang and ld.
Missing tools fail without fallback. These generated native flags never enter the
separate shipping Zig environment; inherited compiler flags remain excluded.
Changing selection or tools requires a fresh output, and can rebuild native Cargo
fingerprints in the existing lane. Both platforms still run only host-native gates;
Mac preparation does not establish Linux-specific supervisor behavior.
New owned preparation directories are created 0700 component by component,
independent of the parent umask. Unsafe existing directories are refused without
changing their modes. No keys, runtime configuration, SSH, signing, activation or publishing inputs
are accepted. Output is a local build observation, not release qualification.
Successful source refreshes retire their verified previous materialization only
after durable publication. Failed captures, outputs and Cargo caches remain intact.
The explicit --expected-commit selects immutable Git objects on both fresh
preparation and resume; unrelated HEAD advancement and worktree edits are excluded.
Preparation records the sanitized environment in a separate owner-private file.
Resume restores those exact inputs before resolving tools, so session PATH changes
do not invalidate successful checks. An explicit incremental-policy change still
requires a fresh preparation; old records without an environment are not resumed.
The active repository must remain on optimizations, and the executing
bootstrap sources must match the selected signed commit. Native qualification
loads its gate only from the authenticated source capture; it does not import
the mutable checkout gate.
`prepare-client --bin iroha|musubi` builds exactly the selected ordinary
host-native client on macOS from the same
signed capture owner, in a separate fixed target/taira-macos-client lane. It
uses Apple's linker and Cargo's native jobserver, and retains a source/tool/
artifact receipt. It does not run qualification or add a validator artifact.
`prepare-native-runtime` uses the same authenticated owner to build the standard
iroha CLI, Kagami and iroha3d together for the native Mac in one locked/offline
release invocation. It safely creates and then reuses target/taira-macos-runtime,
retains failed requests/logs, and atomically publishes only a complete read-only
three-executable package. This is signed-source build evidence, not deployment
authority or qualification; it accepts no runtime credentials or private keys.
"""

from __future__ import annotations

from collections.abc import Callable
import argparse
import contextlib
import fcntl
import json
import hashlib
import types
import os
from pathlib import Path
import re
import shutil
import stat
import struct
import subprocess
import sys
import threading
import time
import tomllib
import uuid

sys.dont_write_bytecode = True
from release_artifact_contract import (
    ReleaseArtifactError, canonical_json_bytes, create_fresh_directory, ensure_private_directory,
    exclusive_output_fd, exclusive_write_bytes, publish_directory_noreplace, stable_hash_path,
    stable_open_relative,
)
from taira_cargo_cache import (admit_source_fingerprints, local_package_names,
                               local_package_roots, source_fingerprints)
from taira_cargo_artifact import cargo_hash_path, cargo_open_relative


TARGET = "aarch64-unknown-linux-gnu"
BINARIES = (("iroha3d_taira", "irohad"), ("iroha", "iroha_cli"),
            ("sorafs-node", "sorafs_node"), ("kagami", "iroha_kagami"))
NATIVE_RUNTIME_BINARIES = (
    ("iroha", "iroha_cli", "crates/iroha_cli/bins/Cargo.toml", "crates/iroha_cli/bins/src/bin/iroha.rs"),
    ("kagami", "iroha_kagami", "crates/iroha_kagami/Cargo.toml", "crates/iroha_kagami/src/main.rs"),
    ("iroha3d", "irohad", "crates/irohad/bins/Cargo.toml", "crates/irohad/bins/src/bin/iroha3d.rs"),
)
CLIENT_BINARIES = {
    "iroha": NATIVE_RUNTIME_BINARIES[0],
    "musubi": ("musubi", "musubi", "crates/musubi/Cargo.toml", "crates/musubi/src/main.rs"),
}
MAX_CARGO_RECORD_BYTES = 16 * 1024**2
LINUX_NATIVE_LLVM_TOOL_PATHS = (
    ("compiler", Path("/usr/bin/clang-18"), Path("/usr/lib/llvm-18/bin/clang")),
    ("linker", Path("/usr/bin/ld.lld-18"), Path("/usr/lib/llvm-18/bin/lld")),
)
MAX_BINARY_BYTES = 4 * 1024**3
BUILD_FREE_FLOOR_BYTES = 8 * 1024**3
CAPTURE_HEADROOM_BYTES = 256 * 1024**2
PROGRESS_SECONDS = 30
SESSION_SCHEMA = "taira.local-preparation.v1"
CAPTURED_GATE_SOURCES = ("scripts/taira_release_check.py", "scripts/taira_native_test_inventory.py",
                         "scripts/formal/rust_text.py")
BUILD_SOURCES = ("scripts/taira_release.py", *CAPTURED_GATE_SOURCES,
                 "scripts/taira_cargo_cache.py", "scripts/taira_cargo_artifact.py",
                 "scripts/release_artifact_contract.py", "scripts/cargo_fast.sh",
                 "scripts/cargo_zigbuild_linux.sh", "scripts/zig_linux_gnu.py")
# The native gate is authenticated with every captured build input, then loaded
# from that capture. Only these controller files execute from the live checkout.
BOOTSTRAP_SOURCES = tuple(path for path in BUILD_SOURCES
                          if path not in CAPTURED_GATE_SOURCES)


class PrepareError(RuntimeError):
    """Local preparation stopped before publishing a successful result."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise PrepareError(message)


def real_path(path: Path, *, exists: bool = True) -> Path:
    require(path.is_absolute() and Path(os.path.abspath(path)) == path,
            "paths must be absolute and normalized")
    require(path.resolve(strict=exists) == path, "paths must not contain symlinks")
    return path


def child_environment(inherited: dict[str, str], target_dir: Path) -> dict[str, str]:
    # Do not forward runtime secrets, compiler overrides or interpreter hooks.
    allowed = {"PATH", "HOME", "CARGO_HOME", "RUSTUP_HOME", "TMPDIR", "TMP", "TEMP",
               "SCCACHE_DIR", "SCCACHE_CACHE_SIZE"}
    env = {key: value for key, value in inherited.items() if key in allowed}
    env.update(LC_ALL="C", PYTHONNOUSERSITE="1", PYTHONDONTWRITEBYTECODE="1",
               CARGO_TARGET_DIR=str(target_dir))
    return env



def preflight_preparation_tmpdir(inherited: dict[str, str], *,
                                 scoped_parent: Path = Path("/tmp")) -> None:
    """Restore the disposable Taira temp directory before Git invokes GPG.

    Other configured temporary directories must already exist. Never repair an
    existing directory's ownership or permissions, or follow a final symlink.
    """
    raw = inherited.get("TMPDIR")
    if raw is None:
        return
    path = Path(raw)
    require(bool(raw) and path.is_absolute() and Path(os.path.abspath(raw)) == path,
            "TMPDIR must be an absolute normalized directory path")
    try:
        info = path.lstat()
    except FileNotFoundError:
        require(path.parent == scoped_parent
                and re.fullmatch(r"iroha-taira-native-[0-9]+", path.name) is not None,
                f"TMPDIR does not exist in this build environment: {path}; "
                "create an owner-only directory or select the scoped Taira temp path")
        try:
            parent_fd = os.open(scoped_parent, os.O_RDONLY | os.O_DIRECTORY |
                                os.O_NOFOLLOW | os.O_CLOEXEC)
        except OSError as error:
            raise PrepareError(f"TMPDIR parent is not a direct usable directory: {scoped_parent}: {error}") from error
        try:
            parent = os.fstat(parent_fd)
            require(stat.S_ISDIR(parent.st_mode) and parent.st_uid in (0, os.geteuid())
                    and stat.S_IMODE(parent.st_mode) == 0o1777,
                    "scoped TMPDIR parent must be an owner-held 01777 directory")
            try:
                os.mkdir(path.name, mode=0o700, dir_fd=parent_fd)
            except FileExistsError:
                # A concurrent invocation can create the same scoped directory.
                # Its identity and permissions must still pass below.
                pass
            except OSError as error:
                raise PrepareError(f"cannot recreate scoped TMPDIR {path}: {error}") from error
        finally:
            os.close(parent_fd)
        try:
            info = path.lstat()
        except OSError as error:
            raise PrepareError(f"cannot inspect recreated TMPDIR {path}: {error}") from error
    except OSError as error:
        raise PrepareError(f"cannot inspect TMPDIR {path}: {error}") from error
    require(stat.S_ISDIR(info.st_mode) and info.st_uid == os.geteuid()
            and stat.S_IMODE(info.st_mode) == 0o700,
            f"TMPDIR must be a direct owner-held 0700 directory: {path}")
    try:
        fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    except OSError as error:
        raise PrepareError(f"cannot open TMPDIR {path}: {error}") from error
    try:
        opened = os.fstat(fd)
        require((opened.st_dev, opened.st_ino) == (info.st_dev, info.st_ino),
                f"TMPDIR changed during admission: {path}")
        probe = ".taira-preparation-probe-" + uuid.uuid4().hex
        try:
            os.mkdir(probe, mode=0o700, dir_fd=fd)
        except OSError as error:
            raise PrepareError(f"TMPDIR is not writable in this build environment: {path}: {error}") from error
        os.rmdir(probe, dir_fd=fd)
    finally:
        os.close(fd)


def native_check_environment(environment: dict[str, str], inherited: dict[str, str]) -> dict[str, str]:
    """Align native dependency metadata without changing the release environment."""
    incremental = inherited.get("CARGO_INCREMENTAL", "1")
    require(incremental in ("0", "1"), "native CARGO_INCREMENTAL must be 0 or 1")
    # Both native profiles have debug=0. Keep their split setting identical so
    # building the daemon between test harnesses does not create a second
    # dependency graph solely for packed versus unpacked debug metadata.
    # Keep deliberate per-package test optimization (notably FASTPQ) intact.
    native = environment | {
        "CARGO_INCREMENTAL": incremental,
        "CARGO_PROFILE_DEV_SPLIT_DEBUGINFO": "unpacked",
        "CARGO_PROFILE_TEST_SPLIT_DEBUGINFO": "unpacked",
    }
    # sccache rejects CARGO_INCREMENTAL=1 before invoking rustc. Cargo's warm
    # incremental artifacts own this lane; retain sccache for nonincremental
    # native checks and the separate sanitized Linux release environment.
    if incremental == "1" and Path(native.get("RUSTC_WRAPPER", "")).name == "sccache":
        native.pop("RUSTC_WRAPPER")
    return native


def default_development_linker() -> str:
    """Use LLVM for Linux development checks and preserve the macOS system linker."""
    return "llvm" if sys.platform == "linux" else "system"


def development_linker_environment(environment: dict[str, str], preference: str) -> dict[str, str]:
    """Apply the Linux development choice after environment sanitization."""
    require(preference in {"system", "llvm"}, "native linker must be system or llvm")
    if preference == "system":
        return dict(environment)
    require(sys.platform == "linux", "--native-linker llvm is supported only for Linux development checks")
    require(not any(name in environment for name in ("RUSTFLAGS", "CARGO_ENCODED_RUSTFLAGS"))
            and not any(name.startswith("CARGO_TARGET_") and name.endswith("_LINKER")
                        for name in environment),
            "development linker selection requires the sanitized native environment")
    tools = llvm_native_linker_tools()
    # The ld.lld basename selects ELF mode; invoking its canonical target `lld`
    # directly would select the generic driver instead. Validate and report both.
    flags = (f"-Clinker={tools['compiler']['path']} "
             f"-Clink-arg=-fuse-ld={tools['linker']['invocation']}")
    print("[taira-check] development native linker llvm: "
          + json.dumps(tools, sort_keys=True), flush=True)
    print("[taira-check] changing native linker selection invalidates Cargo fingerprints; "
          "expect a one-time dependency rebuild in this existing warm lane. "
          "Repeating the same selection reuses its cache; switching back invalidates it again.", flush=True)
    return environment | {"RUSTFLAGS": flags}


def llvm_native_linker_tools() -> dict[str, dict[str, object]]:
    """Inspect the one fixed LLVM installation shared by both native workflows."""
    tools = {}
    for role, invocation, expected in LINUX_NATIVE_LLVM_TOOL_PATHS:
        remedy = ("install executable clang-18" if role == "compiler" else
                  "install executable lld-18 or select --native-linker system")
        try:
            path = real_path(invocation.resolve(strict=True))
        except OSError as error:
            raise PrepareError(
                f"--native-linker llvm requires installed LLVM 18 tools: missing {invocation}; {remedy}"
            ) from error
        require(path == expected, f"LLVM {role} must resolve to the fixed installed path {expected}")
        info = stable_hash_path(path)
        require(bool(info.mode & stat.S_IXUSR) and os.access(path, os.X_OK),
                f"LLVM {role} is not executable: {invocation}; {remedy}")
        require(invocation.resolve(strict=True) == path, f"LLVM {role} changed during inspection")
        tools[role] = {"invocation": str(invocation), "path": str(path),
                       "sha256": info.sha256, "size": info.size}
    return tools


def system_native_linker_paths() -> tuple[tuple[str, Path, Path], ...]:
    """Resolve the system linker with a Clang driver that can name its exact path."""
    require(sys.platform in {"darwin", "linux"}, "native linker requires macOS or Linux")
    if sys.platform == "darwin":
        paths = []
        for name in ("clang", "ld"):
            selected = subprocess.check_output(
                ["/usr/bin/xcrun", "--find", name], cwd="/",
                env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"},
                stdin=subprocess.DEVNULL, text=True, timeout=15).strip()
            paths.append(Path(selected))
    else:
        linker = Path("/usr/bin/ld")
        return (LINUX_NATIVE_LLVM_TOOL_PATHS[0],
                ("linker", linker, linker.resolve(strict=True)))
    return tuple((role, path, path.resolve(strict=True))
                 for role, path in zip(("compiler", "linker"), paths))


def preparation_native_linker(preference: str) -> dict[str, object]:
    """Bind the native driver and linker; shipping Zig remains a separate owner."""
    require(preference in {"system", "llvm"}, "native linker must be system or llvm")
    if preference == "llvm":
        require(sys.platform == "linux", "--native-linker llvm is supported only on Linux")
        tools = llvm_native_linker_tools()
    else:
        tools = {}
        for role, invocation, expected in system_native_linker_paths():
            path = real_path(invocation.resolve(strict=True))
            require(path == expected, f"system native {role} changed during resolution")
            info = stable_hash_path(path)
            require(bool(info.mode & stat.S_IXUSR) and os.access(path, os.X_OK),
                    f"system native {role} is not executable: {invocation}")
            require(invocation.resolve(strict=True) == path,
                    f"system native {role} changed during inspection")
            tools[role] = {"invocation": str(invocation), "path": str(path),
                           "sha256": info.sha256, "size": info.size}
    return {"preference": preference, "platform": sys.platform, "tools": tools}


def preparation_native_environment(environment: dict[str, str], linker: dict[str, object]) -> dict[str, str]:
    """Generate exact native flags without admitting inherited compiler hooks."""
    require(not any(name in environment for name in ("RUSTFLAGS", "CARGO_ENCODED_RUSTFLAGS"))
            and not any(name.startswith("CARGO_TARGET_") and name.endswith("_LINKER")
                        for name in environment),
            "preparation linker selection requires the sanitized native environment")
    tools = linker["tools"]
    # Use the invocation alias for LLVM: ld.lld selects ELF mode, unlike lld.
    # Encoded flags also preserve spaces in the selected Apple toolchain path.
    flags = (f"-Clinker={tools['compiler']['path']}",
             f"-Clink-arg=-fuse-ld={tools['linker']['invocation']}")
    return environment | {"CARGO_ENCODED_RUSTFLAGS": "\x1f".join(flags)}


def recorded_preparation_environment(output: Path, target_dir: Path,
                                     request: dict[str, object]) -> dict[str, object]:
    """Authenticate only the saved allowlist; never deserialize arbitrary hooks."""
    path = output / "environment.json"
    require(path.is_file() and not path.is_symlink() and path.lstat().st_nlink == 1,
            "preparation requires its direct single-link environment checkpoint; select a fresh output")
    record = read_record(path)
    require(hashlib.sha256(canonical_json_bytes(record)).hexdigest()
            == request.get("environment_sha256"), "preparation environment checkpoint changed")
    require(set(record) == {"schema", "child_environment"}
            and record["schema"] == "taira.preparation-environment.v1",
            "invalid preparation environment checkpoint")
    environment = record["child_environment"]
    require(isinstance(environment, dict)
            and all(isinstance(key, str) and isinstance(value, str)
                    and "\0" not in key and "\0" not in value
                    for key, value in environment.items()),
            "invalid preparation environment values")
    require(child_environment(environment, target_dir) == environment,
            "preparation environment contains noncanonical or unapproved inputs")
    return record


def preparation_environment(output: Path, target_dir: Path,
                            inherited: dict[str, str], *, fresh: bool
                            ) -> tuple[dict[str, str], dict[str, object], str]:
    """Keep actual tool resolution and execution on one recorded environment."""
    if fresh:
        incremental = native_check_environment({}, inherited)["CARGO_INCREMENTAL"]
        record = {"schema": "taira.preparation-environment.v1",
                  "child_environment": child_environment(inherited, target_dir)}
    else:
        request = read_record(output / "request.json")
        require(request.get("schema") == SESSION_SCHEMA,
                "unsupported preparation checkpoint; select a fresh output")
        require(type(request.get("native_incremental")) is bool,
                "invalid recorded native incremental policy")
        incremental = "1" if request["native_incremental"] else "0"
        if "CARGO_INCREMENTAL" in inherited:
            requested = native_check_environment({}, inherited)["CARGO_INCREMENTAL"]
            require(requested == incremental,
                    "preparation checkpoint belongs to different inputs: native incremental policy")
        record = recorded_preparation_environment(output, target_dir, request)
    return dict(record["child_environment"]), record, incremental

def git(root: Path, *args: str) -> bytes:
    result = subprocess.run(["git", "--no-replace-objects", *args], cwd=root, stdin=subprocess.DEVNULL,
                            capture_output=True, check=False, timeout=60,
                            env=child_environment(dict(os.environ), root / "target"))
    require(result.returncode == 0, "git " + args[0] + " failed")
    return result.stdout.strip()


def file_identity(info: os.stat_result) -> tuple[int, ...]:
    return (info.st_dev, info.st_ino, info.st_mode, info.st_nlink, info.st_uid,
            info.st_gid, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def source_snapshot(root: Path, entries: bytes | None = None, *, frozen: bool = False) -> list[dict[str, object]]:
    rows = []
    for raw in (git(root, "ls-files", "--stage", "-z") if entries is None else entries).split(b"\0"):
        if not raw:
            continue
        entry = re.fullmatch(rb"(100644|100755|120000|160000) ([0-9a-f]{40}) 0\t(.+)", raw, re.DOTALL)
        require(entry is not None, "tracked index entry has unsupported mode, object or merge stage")
        mode, oid, relative_raw = entry.groups()
        relative = os.fsdecode(relative_raw)
        require(not Path(relative).is_absolute() and ".." not in Path(relative).parts,
                "tracked index path must stay inside the checkout")
        path = root / relative
        if mode == b"160000":
            # No submodule source is imported by this release corridor. Bind the
            # indexed commit and prove its local path contributes no build input.
            try:
                before = path.lstat()
            except FileNotFoundError:
                require(not os.path.lexists(path), "gitlink path appeared during inspection")
                checkout = "absent"
            else:
                require(stat.S_ISDIR(before.st_mode) and not any(path.iterdir()),
                        "gitlinks must be uninitialized empty directories or absent")
                require(file_identity(path.lstat()) == file_identity(before),
                        "gitlink changed during inspection")
                checkout = "empty"
            rows.append({"path": relative, "kind": "gitlink", "index_mode": mode.decode(),
                         "object": oid.decode(), "uninitialized": True, "checkout": checkout})
            continue
        before = path.lstat()
        if stat.S_ISLNK(before.st_mode):
            require(mode == b"120000", "tracked source kind differs from the index: " + relative)
            if frozen:
                require(path.resolve(strict=False).is_relative_to(root), "source symlink escapes capture")
            payload = os.fsencode(os.readlink(path))
            blob = hashlib.sha1(f"blob {len(payload)}\0".encode() + payload).hexdigest()
            digest, size, kind = hashlib.sha256(payload).hexdigest(), len(payload), "symlink"
        else:
            require(stat.S_ISREG(before.st_mode), "tracked source must be regular files or symlinks")
            require(mode in (b"100644", b"100755")
                    and bool(before.st_mode & stat.S_IXUSR) == (mode == b"100755"),
                    "tracked source mode differs from the index: " + relative)
            if frozen:
                require(before.st_uid == os.geteuid() and before.st_nlink == 1
                        and stat.S_IMODE(before.st_mode) == (0o500 if mode == b"100755" else 0o400),
                        "captured source file is not owner-held and read-only")
            fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
            with os.fdopen(fd, "rb") as stream:
                require(file_identity(os.fstat(stream.fileno())) == file_identity(before),
                        "source changed before hashing")
                sha256 = hashlib.sha256()
                git_blob = hashlib.sha1(f"blob {before.st_size}\0".encode())
                while block := stream.read(1024 * 1024):
                    sha256.update(block)
                    git_blob.update(block)
                digest, blob = sha256.hexdigest(), git_blob.hexdigest()
                require(file_identity(os.fstat(stream.fileno())) == file_identity(before),
                        "source changed while hashing")
            size, kind = before.st_size, "regular"
        require(file_identity(path.lstat()) == file_identity(before), "source path changed while hashing")
        # Git status can conceal edits marked assume-unchanged/skip-worktree.
        # Compare raw bytes to the indexed Git blob during the same bounded read.
        require(blob == oid.decode(), "tracked source bytes differ from the index: " + relative)
        rows.append({"path": relative, "kind": kind, "size": size,
                     "index_mode": mode.decode(), "object": oid.decode(),
                     "mode": stat.S_IMODE(before.st_mode), "sha256": digest})
    return rows


def commit_entries(root: Path, commit: str) -> bytes:
    rows = []
    for row in git(root, "ls-tree", "-r", "-z", "--full-tree", commit).split(b"\0"):
        if not row:
            continue
        metadata, path = row.split(b"\t", 1)
        mode, kind, oid = metadata.split(b" ")
        require((mode == b"160000" and kind == b"commit")
                or (mode in (b"100644", b"100755", b"120000") and kind == b"blob"),
                "unsupported signed source entry")
        require(b".git" not in path.split(b"/") and not path.startswith(b"target/"),
                "signed source includes a repository or build-output path")
        rows.append(mode + b" " + oid + b" 0\t" + path)
    return b"\0".join(sorted(rows, key=lambda row: row.split(b"\t", 1)[1])) + b"\0"


def verify_controller_module_origins(root: Path) -> None:
    """Keep unrelated checkout modules outside the admitted live controller."""
    modules = {
        "release_artifact_contract": "scripts/release_artifact_contract.py",
        "taira_cargo_cache": "scripts/taira_cargo_cache.py",
        "taira_cargo_artifact": "scripts/taira_cargo_artifact.py",
    }
    allowed = {root / "scripts/taira_release.py", *(root / path for path in modules.values())}
    for name, relative in modules.items():
        module = sys.modules.get(name)
        origin = getattr(module, "__file__", None)
        expected = root / relative
        require(isinstance(origin, str) and Path(origin).resolve() == expected,
                "build controller module has an unbound origin: " + name)
        spec_origin = getattr(getattr(module, "__spec__", None), "origin", None)
        require(isinstance(spec_origin, str) and Path(spec_origin).resolve() == expected,
                "build controller module has an unbound import origin: " + name)
    for name, module in tuple(sys.modules.items()):
        origin = getattr(module, "__file__", None)
        if isinstance(origin, str):
            resolved = Path(origin).resolve()
            require(not resolved.is_relative_to(root) or resolved in allowed,
                    "loaded checkout module is outside the build controller: " + name)


def verify_controller_sources(root: Path, commit: str) -> None:
    """Compare the live controller with signed blobs, independently of index flags."""
    selected = []
    required = {os.fsencode(path) for path in BUILD_SOURCES}
    for row in commit_entries(root, commit).split(b"\0"):
        if not row:
            continue
        metadata, path = row.split(b"\t", 1)
        if path in required:
            require(metadata.split()[0] in (b"100644", b"100755"),
                    "signed build controller must be a regular file: " + os.fsdecode(path))
            selected.append(row)
    require({row.split(b"\t", 1)[1] for row in selected} == required,
            "signed commit is missing a required build controller source")
    bootstrap = {os.fsencode(path) for path in BOOTSTRAP_SOURCES}
    live = [row for row in selected if row.split(b"\t", 1)[1] in bootstrap]
    try:
        source_snapshot(root, b"\0".join(live) + b"\0")
    except (PrepareError, OSError) as error:
        raise PrepareError("build controller differs from signed commit: " + str(error)) from error
    verify_controller_module_origins(root)


def signed_source_size(root: Path, commit: str, entries: bytes) -> int:
    """Count captured blob bytes from the selected Git tree, never the worktree."""
    expected = {}
    for row in entries.split(b"\0"):
        if row:
            metadata, path = row.split(b"\t", 1)
            mode, oid, stage = metadata.split()
            require(path not in expected and stage == b"0",
                    "source size inventory has duplicate paths or merge stages")
            expected[path] = (mode, oid)
    total, seen = 0, set()
    for row in git(root, "ls-tree", "-r", "-l", "-z", "--full-tree", commit).split(b"\0"):
        if not row:
            continue
        metadata, path = row.split(b"\t", 1)
        mode, kind, oid, size = metadata.split()
        require(path not in seen and expected.get(path) == (mode, oid),
                "source size inventory differs from the signed capture")
        seen.add(path)
        if mode == b"160000":
            require(kind == b"commit" and size == b"-", "invalid signed gitlink size")
        else:
            require(kind == b"blob" and size.isdigit(), "invalid signed source blob size")
            total += int(size)
    require(seen == set(expected), "source size inventory is incomplete")
    return total


def verify_signed_source(root: Path, commit: str, signer: str) -> str:
    """Authenticate the explicitly selected Git source for fresh and resumed builds."""
    require(re.fullmatch(r"[0-9a-f]{40}", commit) is not None,
            "expected commit must be a full lowercase Git object ID")
    require(re.fullmatch(r"(?:[0-9A-F]{40}|[0-9A-F]{64}|SHA256:[A-Za-z0-9+/]{43})", signer) is not None,
            "expected signer must be a full signing-key fingerprint")
    require(git(root, "rev-parse", "--show-toplevel") == os.fsencode(root),
            "repository root does not match the checkout")
    require(git(root, "branch", "--show-current") == b"optimizations",
            "Taira preparation requires optimizations")
    git(root, "verify-commit", commit)
    require(git(root, "show", "--no-patch", "--format=%GF", commit).decode() == signer,
            "commit signature does not match the expected signer")
    verify_controller_sources(root, commit)
    return git(root, "rev-parse", commit + "^{tree}").decode()


def canonical_source_snapshot(root: Path, commit: str, entries: bytes) -> list[dict[str, object]]:
    """Bind a canonical compiler checkout to the admitted signed Git selection."""
    real_path(root)

    def identity():
        require(git(root, "rev-parse", "HEAD").decode() == commit,
                "canonical compiler HEAD differs from the selected signed commit")
        require(git(root, "branch", "--show-current") == b"optimizations",
                "canonical compiler checkout requires optimizations")
        require(git(root, "ls-files", "--stage", "-z") == entries,
                "canonical compiler index differs from the selected signed tree")
        require(not git(root, "ls-files", "--others", "--exclude-standard", "-z"),
                "canonical compiler checkout has untracked source files")

    identity()
    for entry in entries.split(b"\0"):
        if entry:
            path = root / os.fsdecode(entry.split(b"\t", 1)[1])
            require(path.resolve(strict=False).is_relative_to(root),
                    "canonical compiler source symlink escapes the checkout")
    snapshot = source_snapshot(root, entries)
    identity()
    return snapshot


def frozen_snapshot(source: Path, entries: bytes, target_dir: Path, *,
                    unpublished_root_fd: int | None = None) -> list[dict[str, object]]:
    def check_unpublished_root():
        if unpublished_root_fd is not None:
            opened, named = os.fstat(unpublished_root_fd), source.lstat()
            require(stat.S_ISDIR(opened.st_mode) and opened.st_uid == os.geteuid()
                    and stat.S_IMODE(opened.st_mode) == 0o700
                    and file_identity(opened) == file_identity(named),
                    "unpublished source root custody changed")
    check_unpublished_root()
    rows = source_snapshot(source, entries, frozen=True)
    binding = source / "target"
    require(binding.is_symlink() and binding.lstat().st_uid == os.geteuid()
            and os.readlink(binding) == str(target_dir) and binding.resolve(strict=True) == target_dir,
            "captured source output binding differs from the selected Cargo target")
    expected = {Path(row["path"]) for row in rows} | {Path("target")}
    for path in list(expected):
        expected.update(parent for parent in path.parents if parent != Path("."))
    actual = set()
    for parent, directories, files in os.walk(source, followlinks=False):
        info = Path(parent).lstat()
        mode = 0o700 if unpublished_root_fd is not None and Path(parent) == source else 0o500
        require(stat.S_IMODE(info.st_mode) == mode and info.st_uid == os.geteuid(),
                "captured source directory is not owner-held and read-only")
        actual.update((Path(parent) / name).relative_to(source) for name in directories + files)
    require(actual == expected, "captured source has missing or extra inputs")
    check_unpublished_root()
    return rows


def retire_source_capture(source: Path, entries: bytes, target_dir: Path) -> None:
    """Remove only one authenticated, superseded capture under the source-lane lock."""
    require(re.fullmatch(r"source\.retained-[0-9a-f]{32}", source.name) is not None,
            "only a superseded source capture may be retired")
    real_path(source)
    before = source.lstat()
    rows = frozen_snapshot(source, entries, target_dir)
    # Build an exact deletion plan from authenticated entries. Never follow the
    # target symlink into the warm Cargo lane or recurse through unknown inputs.
    tree: dict = {"target": None}
    for row in rows:
        parts = Path(row["path"]).parts
        node = tree
        for part in parts[:-1]:
            node = node.setdefault(part, {})
        node[parts[-1]] = {} if row["kind"] == "gitlink" else None

    def remove_contents(fd: int, expected: dict) -> None:
        info = os.fstat(fd)
        require(info.st_uid == os.geteuid() and stat.S_IMODE(info.st_mode) == 0o500,
                "retired source directory custody changed")
        require(set(os.listdir(fd)) == set(expected), "retired source has unknown inputs")
        os.fchmod(fd, 0o700)
        for name, children in expected.items():
            if children is None:
                os.unlink(name, dir_fd=fd)
            else:
                child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                                dir_fd=fd)
                try:
                    remove_contents(child, children)
                finally:
                    os.close(child)
                os.rmdir(name, dir_fd=fd)
        os.fsync(fd)

    parent = os.open(source.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        fd = os.open(source.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                     dir_fd=parent)
        try:
            require(file_identity(os.fstat(fd)) == file_identity(before),
                    "retired source changed before removal")
            remove_contents(fd, tree)
        finally:
            os.close(fd)
        os.rmdir(source.name, dir_fd=parent)
        os.fsync(parent)
    finally:
        os.close(parent)


def unchanged_source_directories(previous_entries: bytes, entries: bytes) -> set[Path]:
    """Find directories whose complete Git-authenticated subtrees are unchanged."""
    def subtrees(records: bytes) -> dict[Path, str]:
        digests = {}
        for row in records.split(b"\0"):
            if not row:
                continue
            metadata, relative = row.split(b"\t", 1)
            path = Path(os.fsdecode(relative))
            directories = list(path.parents)
            if metadata.startswith(b"160000 "):
                directories.append(path)
            for directory in directories:
                digests.setdefault(directory, hashlib.sha256()).update(row + b"\0")
        return {directory: digest.hexdigest() for directory, digest in digests.items()}
    previous, current = subtrees(previous_entries), subtrees(entries)
    return {directory for directory, digest in current.items() if previous.get(directory) == digest}


def source_capture_heartbeat(stop: threading.Event, started: float,
                             completed: list[int], total: int) -> None:
    """Report bounded capture progress without publishing source paths or contents."""
    while not stop.wait(15):
        print(f"[taira-release] signed source capture {completed[0]}/{total} entries "
              f"in {time.monotonic() - started:.0f}s", flush=True)


class PrivateSourceTree:
    """Hold one unpublished capture and defer directory durability to its seal.

    Only a capture-private tree uses this writer. Files receive their final
    metadata before their sole fsync; child directories are frozen and synced
    bottom-up. The original root stays private and writable until Darwin's
    exclusive rename completes, then freezes through its retained descriptor.
    At most two custody and two traversal descriptors are open, independent of size.
    """

    def __init__(self, root: Path):
        self.root = root
        self.fd = -1
        self.parent_fd = -1
        self.parent_identity: tuple[int, ...] | None = None
        self.published_identity: tuple[int, ...] | None = None
        self.directories: dict[Path, tuple[int, ...]] = {}
        self.frozen: set[Path] = set()

    @staticmethod
    def identity(info: os.stat_result) -> tuple[int, ...]:
        return info.st_dev, info.st_ino, info.st_uid, info.st_gid

    def __enter__(self):
        real_path(self.root)
        before = self.root.lstat()
        fd = os.open(self.root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            info = os.fstat(fd)
            require(file_identity(before) == file_identity(info)
                    and info.st_uid == os.geteuid() and stat.S_IMODE(info.st_mode) == 0o700,
                    "private source root custody changed")
            self.directories[Path('.')] = self.identity(info)
            self.parent_fd = os.open(self.root.parent, os.O_RDONLY | os.O_DIRECTORY
                                     | os.O_NOFOLLOW | os.O_CLOEXEC)
            parent = os.fstat(self.parent_fd)
            require(stat.S_ISDIR(parent.st_mode) and parent.st_uid == os.geteuid()
                    and not parent.st_mode & 0o022
                    and file_identity(parent) == file_identity(self.root.parent.lstat()),
                    "private source publication parent custody changed")
            self.parent_identity = (*self.identity(parent), parent.st_mode)
            self.fd = fd
        except BaseException:
            if self.parent_fd != -1:
                os.close(self.parent_fd)
                self.parent_fd = -1
            os.close(fd)
            raise
        return self

    def __exit__(self, *_exc):
        os.close(self.fd)
        os.close(self.parent_fd)
        self.fd = -1
        self.parent_fd = -1

    def check_root(self) -> None:
        parent, named_parent = os.fstat(self.parent_fd), self.root.parent.lstat()
        require(all((*self.identity(info), info.st_mode) == self.parent_identity
                    for info in (parent, named_parent)),
                "private source publication parent custody changed")
        named, held = self.root.lstat(), os.fstat(self.fd)
        mode = 0o500 if Path('.') in self.frozen else 0o700
        require(all(stat.S_ISDIR(info.st_mode)
                    and self.identity(info) == self.directories[Path('.')]
                    and stat.S_IMODE(info.st_mode) == mode for info in (named, held)),
                "private source root was replaced or its custody changed")
        if self.published_identity is not None:
            require(all(file_identity(info) == self.published_identity for info in (named, held)),
                    "published source root metadata changed")

    @contextlib.contextmanager
    def directory(self, relative: Path, *, create: bool = False):
        require(not relative.is_absolute() and '..' not in relative.parts,
                "private source directory escapes capture")
        self.check_root()
        fd = os.dup(self.fd)
        traversed = Path('.')
        try:
            for component in relative.parts:
                traversed /= component
                fresh = traversed not in self.directories
                if fresh:
                    require(create, "private source contains an unrecorded directory")
                    # No existing directory, link or substituted entry is adopted.
                    os.mkdir(component, mode=0o700, dir_fd=fd)
                named = os.stat(component, dir_fd=fd, follow_symlinks=False)
                child = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
                                | os.O_CLOEXEC, dir_fd=fd)
                os.close(fd)
                fd = child
                info = os.fstat(fd)
                require(self.identity(info) == self.identity(named)
                        and info.st_uid == os.geteuid(), "private source directory changed")
                if fresh:
                    os.fchmod(fd, 0o700)
                    self.directories[traversed] = self.identity(info)
                require(self.identity(info) == self.directories[traversed]
                        and stat.S_IMODE(os.fstat(fd).st_mode)
                        == (0o500 if traversed in self.frozen else 0o700),
                        "private source directory custody changed")
            require(self.identity(os.fstat(fd)) == self.directories[relative],
                    "private source directory owner differs")
            yield fd
        finally:
            os.close(fd)

    def write(self, relative: Path, payload: bytes, *, executable: bool,
              timestamps: tuple[int, int] | None = None) -> None:
        require(relative.name and relative != Path('.'), "source file needs a name")
        with self.directory(relative.parent, create=True) as parent:
            fd = os.open(relative.name, os.O_WRONLY | os.O_CREAT | os.O_EXCL
                         | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=parent)
            identity = None
            complete = False
            try:
                info = os.fstat(fd)
                identity = self.identity(info)
                require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1
                        and info.st_uid == os.geteuid(), "private source file custody differs")
                view = memoryview(payload)
                while view:
                    size = os.write(fd, view)
                    require(size > 0, "short private source write")
                    view = view[size:]
                mode = 0o500 if executable else 0o400
                os.fchmod(fd, mode)
                if timestamps is not None:
                    os.utime(fd, ns=timestamps)
                os.fsync(fd)
                info = os.fstat(fd)
                named = os.stat(relative.name, dir_fd=parent, follow_symlinks=False)
                require(self.identity(info) == identity and info.st_nlink == 1
                        and stat.S_ISREG(info.st_mode) and stat.S_IMODE(info.st_mode) == mode
                        and info.st_size == len(payload) and file_identity(info) == file_identity(named),
                        "private source file changed before sealing")
                complete = True
            finally:
                if not complete:
                    # Match the exclusive output contract: scrub only our held new
                    # inode, and never unlink a substituted name or an older source.
                    try:
                        os.ftruncate(fd, 0)
                        os.fsync(fd)
                        named = os.stat(relative.name, dir_fd=parent, follow_symlinks=False)
                        if self.identity(named) == identity:
                            os.unlink(relative.name, dir_fd=parent)
                            os.fsync(parent)
                    except OSError:
                        pass
                os.close(fd)

    def symlink(self, relative: Path, destination: str) -> None:
        with self.directory(relative.parent, create=True) as parent:
            os.symlink(destination, relative.name, dir_fd=parent)

    def seal(self, previous: Path, unchanged: set[Path]) -> None:
        real_path(self.root)
        self.check_root()
        for relative in sorted(self.directories, key=lambda path: len(path.parts), reverse=True):
            if relative == Path('.'):
                continue
            with self.directory(relative) as fd:
                os.fchmod(fd, 0o500)
                if relative in unchanged:
                    info = (previous / relative).stat(follow_symlinks=False)
                    require(stat.S_ISDIR(info.st_mode), "unchanged captured directory changed type")
                    os.utime(fd, ns=(info.st_atime_ns, info.st_mtime_ns))
                os.fsync(fd)
                self.frozen.add(relative)
                info = os.fstat(fd)
                require(self.identity(info) == self.directories[relative]
                        and stat.S_IMODE(info.st_mode) == 0o500,
                        "sealed source directory custody changed")
                named = (self.root / relative).lstat()
                require(self.identity(named) == self.directories[relative]
                        and stat.S_IMODE(named.st_mode) == 0o500,
                        "sealed source directory path changed")
        self.check_root()
        os.fsync(self.fd)
        real_path(self.root)

    def publish(self, destination: Path) -> None:
        """Publish only this original sealed tree, then durably freeze its root."""
        self.check_root()
        require(Path('.') not in self.frozen
                and self.frozen == set(self.directories) - {Path('.')},
                "private source children must be sealed before publication")
        publish_directory_noreplace(self.root, destination, parent_fd=self.parent_fd,
                                    stage_fd=self.fd)
        self.root = destination
        self.check_root()
        os.fchmod(self.fd, 0o500)
        os.fsync(self.fd)
        self.frozen.add(Path('.'))
        self.published_identity = file_identity(os.fstat(self.fd))
        self.check_root()
        require(file_identity(os.fstat(self.fd)) == file_identity(destination.lstat()),
                "published source root custody changed")
        os.fsync(self.parent_fd)
        self.check_root()


def retain_previous_source(source: Path, destination: Path, entries: bytes,
                           target_dir: Path, parent_fd: int) -> None:
    """Move one authenticated prior capture through its retained original inode."""
    before = source.lstat()
    fd = os.open(source, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        require(file_identity(os.fstat(fd)) == file_identity(before),
                "previous source root changed before retention")
        frozen_snapshot(source, entries, target_dir)
        require(file_identity(os.fstat(fd)) == file_identity(before)
                and file_identity(source.lstat()) == file_identity(before),
                "previous source root custody changed")
        # This is an intentional lifecycle transition of the verified old inode,
        # not repair or admission of an existing writable/foreign directory.
        os.fchmod(fd, 0o700)
        try:
            require(file_identity(os.fstat(fd)) == file_identity(source.lstat()),
                    "previous source root changed during retention")
            publish_directory_noreplace(source, destination, parent_fd=parent_fd, stage_fd=fd)
        finally:
            os.fchmod(fd, 0o500)
            os.fsync(fd)
        require(file_identity(os.fstat(fd)) == file_identity(destination.lstat()),
                "retained previous source root custody changed")
        frozen_snapshot(destination, entries, target_dir)
    finally:
        os.close(fd)


def capture_source(root: Path, source: Path, target_dir: Path, commit: str, entries: bytes,
                   *, on_entry: Callable[[int], None] | None = None) -> Path:
    """Publish one fixed Git-object capture; never copy the mutable worktree."""
    parent = source.parent
    state_path = parent / "source-state.json"
    state = read_record(state_path) if state_path.exists() else None
    require(state is None or set(state) == {"commit"}, "invalid captured source checkpoint")
    previous_entries = None
    if os.path.lexists(source):
        real_path(source)
        if state == {"commit": commit}:
            frozen_snapshot(source, entries, target_dir)
            return source
        try:
            frozen_snapshot(source, entries, target_dir)
        except (PrepareError, FileNotFoundError, NotADirectoryError):
            require(state is not None, "unexpected unrecorded source capture")
            # Added paths and file/directory replacements need not exist in the
            # previous tree. Other I/O failures still retain their diagnostic.
            # Preserve timestamps only from a complete, unchanged previous tree.
            previous_entries = commit_entries(root, state["commit"])
            frozen_snapshot(source, previous_entries, target_dir)
        else:
            # Publication may have completed before its small pointer checkpoint.
            checkpoint = parent / ("source-state.pending-" + uuid.uuid4().hex)
            write_record(checkpoint, {"commit": commit})
            os.replace(checkpoint, state_path)
            return source
    # The lane lock covers refresh, native checks, Linux compilation and capture.
    # No running Cargo process may observe the source-directory replacement.
    pending = create_fresh_directory(parent / ("source.pending-" + uuid.uuid4().hex), mode=0o700)
    with PrivateSourceTree(pending) as writer:
        unchanged_directories = (unchanged_source_directories(previous_entries, entries)
                                 if previous_entries is not None else set())
        # Batch mode reads exact committed blobs without archive export filters.
        captured_entries = 0
        with subprocess.Popen(["git", "--no-replace-objects", "cat-file", "--batch"], cwd=root,
                              env=child_environment(dict(os.environ), root / "target"),
                              stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE) as child:
            assert child.stdin is not None and child.stdout is not None
            try:
                for row in entries.split(b"\0"):
                    if not row:
                        continue
                    metadata, relative = row.split(b"\t", 1)
                    mode, oid, _ = metadata.split(b" ")
                    path = pending / os.fsdecode(relative)
                    require(not Path(os.fsdecode(relative)).is_absolute()
                            and ".." not in Path(os.fsdecode(relative)).parts, "source path escapes capture")
                    if mode == b"160000":
                        with writer.directory(path.relative_to(pending), create=True):
                            pass
                        captured_entries += 1
                        if on_entry is not None:
                            on_entry(captured_entries)
                        continue
                    child.stdin.write(oid + b"\n")
                    child.stdin.flush()
                    header = child.stdout.readline().split()
                    require(len(header) == 3 and header[:2] == [oid, b"blob"], "missing signed source blob")
                    size = int(header[2])
                    payload = child.stdout.read(size)
                    require(len(payload) == size and child.stdout.read(1) == b"\n", "truncated source blob")
                    require(hashlib.sha1(f"blob {size}\0".encode() + payload).hexdigest() == oid.decode(),
                            "source blob differs from the signed tree")
                    if mode == b"120000":
                        writer.symlink(path.relative_to(pending), os.fsdecode(payload))
                        require(path.resolve(strict=False).is_relative_to(pending), "source symlink escapes capture")
                    else:
                        timestamps = None
                        previous = source / os.fsdecode(relative)
                        if state is not None and previous.is_file() and not previous.is_symlink():
                            try:
                                old = stable_hash_path(previous)
                            except (ReleaseArtifactError, OSError):
                                old = None
                            if old is not None and old.sha256 == hashlib.sha256(payload).hexdigest():
                                info = previous.stat()
                                timestamps = (info.st_atime_ns, info.st_mtime_ns)
                        writer.write(path.relative_to(pending), payload,
                                     executable=mode == b"100755", timestamps=timestamps)
                    captured_entries += 1
                    if on_entry is not None:
                        on_entry(captured_entries)
                child.stdin.close()
                require(child.wait() == 0, "Git source capture failed")
            finally:
                child.stdin.close()
                child.stdout.close()
                if child.stderr is not None:
                    child.stderr.close()
        # Some native fixtures use CARGO_MANIFEST_DIR/../../target. Admit only this
        # exact output binding; inventories never follow it into generated files.
        writer.symlink(Path("target"), str(target_dir))
        writer.seal(source, unchanged_directories)
        frozen_snapshot(pending, entries, target_dir, unpublished_root_fd=writer.fd)
        retained = None
        if os.path.lexists(source):
            real_path(source)
            require(previous_entries is not None, "previous source lacks an authenticated binding")
            retained = parent / ("source.retained-" + uuid.uuid4().hex)
            retain_previous_source(source, retained, previous_entries, target_dir, writer.parent_fd)
        writer.publish(source)
        frozen_snapshot(source, entries, target_dir)
        writer.check_root()
        checkpoint = parent / ("source-state.pending-" + uuid.uuid4().hex)
        write_record(checkpoint, {"commit": commit})
        writer.check_root()
        os.replace(checkpoint, state_path)
        os.fsync(writer.parent_fd)
        writer.check_root()
    if retained is not None:
        # Keep rollback input through every capture/checkpoint publication failure.
        # Older retained/pending directories belong to interrupted attempts and
        # are deliberately not discovered or deleted by a successful refresh.
        retire_source_capture(retained, previous_entries, target_dir)
    return source


def captured_gate(source: Path, before: list[dict[str, object]]):
    """Execute the gate and its census from the same retained, verified code bytes."""
    rows = {row["path"]: row for row in before}
    captured = {}
    for relative in CAPTURED_GATE_SOURCES:
        row = rows.get(relative)
        require(row is not None, "captured native gate dependency is absent: " + relative)
        path = source / relative
        expected = stable_hash_path(path)
        require(expected.sha256 == row["sha256"],
                "captured native gate changed: " + relative)
        with stable_open_relative(path.parent, path.name, expected=expected) as fd:
            with os.fdopen(os.dup(fd), "rb") as stream:
                code = stream.read()
        require(hashlib.sha256(code).hexdigest() == row["sha256"],
                "captured native gate changed: " + relative)
        captured[relative] = code

    helper_path = source / "scripts/formal/rust_text.py"
    helper = {"__name__": "taira_captured_rust_text", "__file__": str(helper_path)}
    exec(compile(captured["scripts/formal/rust_text.py"], str(helper_path), "exec"), helper)
    inventory_path = source / "scripts/taira_native_test_inventory.py"
    inventory = {"__name__": "taira_captured_native_inventory", "__file__": str(inventory_path),
                 "_captured_mask_rust_comments": helper["mask_rust_comments"]}
    exec(compile(captured["scripts/taira_native_test_inventory.py"],
                 str(inventory_path), "exec"), inventory)
    path = source / "scripts/taira_release_check.py"
    module = types.ModuleType("taira_captured_release_check")
    module.__file__ = str(path)
    module.__dict__["_captured_native_inventory"] = inventory
    exec(compile(captured["scripts/taira_release_check.py"], str(path), "exec"), module.__dict__)
    return module



def initialize_compiler_cache(env: dict[str, str]) -> None:
    """Start/reuse the persistent cache before a compiler can inherit build locks."""
    if "RUSTC_WRAPPER" not in env:
        return
    # A compiler version request uses sccache's connect-or-start path. Unlike
    # --start-server it also succeeds for an existing server; --show-stats can
    # report empty statistics without starting one. Do not reset or stop caches.
    env["SCCACHE_IDLE_TIMEOUT"] = "0"
    try:
        result = subprocess.run(
            [env["RUSTC_WRAPPER"], env["RUSTC"], "--version"],
            cwd="/", env=env, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE, close_fds=True, check=False, timeout=30,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise PrepareError("compiler cache initialization failed before Cargo; cache retained") from error
    require(result.returncode == 0,
            "compiler cache initialization failed before Cargo; cache retained")


def isolated_cargo_environment(root: Path, source: Path, env: dict[str, str]) -> tuple[dict[str, str], list[dict[str, object]]]:
    """Select the captured toolchain, sharing cache bytes but no ambient config."""
    channel = tomllib.loads((source / "rust-toolchain.toml").read_text())["toolchain"]["channel"]
    require(isinstance(channel, str) and re.fullmatch(r"[A-Za-z0-9_.-]+", channel) is not None,
            "invalid captured Rust toolchain")
    tools = []
    for name in ("cargo", "rustc", "rustdoc"):
        selected = subprocess.check_output(["rustup", "which", "--toolchain", channel, name],
                                          cwd="/", env=env, stdin=subprocess.DEVNULL, text=True).strip()
        path = real_path(Path(selected).resolve(strict=True))
        info = stable_hash_path(path)
        require(info.mode & stat.S_IXUSR, "selected Rust tool is not executable")
        tools.append({"name": name, "path": str(path), "sha256": info.sha256, "size": info.size})
    original = Path(env.get("CARGO_HOME", str(Path(env["HOME"]) / ".cargo")))
    home = root / "target/taira-release-cargo-home"
    home.mkdir(mode=0o700, exist_ok=True)
    real_path(home)
    require(home.stat().st_uid == os.geteuid() and stat.S_IMODE(home.stat().st_mode) == 0o700,
            "isolated Cargo home must remain owner-private")
    cache_files = {".package-cache", ".package-cache-mutate", ".global-cache", ".global-cache-shm", ".global-cache-wal"}
    for path in home.iterdir():
        if path.name in ("registry", "git"):
            continue
        info = path.lstat()
        require(path.name in cache_files and stat.S_ISREG(info.st_mode) and info.st_nlink == 1
                and info.st_uid == os.geteuid() and not info.st_mode & 0o022,
                "unexpected isolated Cargo home entry: " + path.name)
    for name in ("registry", "git"):
        path, cache = home / name, original / name
        if not os.path.lexists(path):
            if cache.exists():
                path.symlink_to(real_path(cache), target_is_directory=True)
            else:
                path.mkdir(mode=0o700)
        require((path.is_symlink() and os.readlink(path) == str(cache) and cache.is_dir())
                or (not path.is_symlink() and path.is_dir() and path.stat().st_uid == os.geteuid()),
                "Cargo cache location changed")
    require(not any(os.path.lexists(path) for path in ("/.cargo/config", "/.cargo/config.toml")),
            "root-level Cargo config prevents isolated preparation")
    result = dict(env)
    result.update(CARGO_HOME=str(home), CARGO=tools[0]["path"], RUSTC=tools[1]["path"], RUSTDOC=tools[2]["path"],
                  RUSTUP_TOOLCHAIN=channel, CARGO_BUILD_JOBS="6", CARGO_NET_OFFLINE="true",
                  CARGO_ZIGBUILD_ZIG_PATH=str(source / "scripts/zig_linux_gnu.py"),
                  CARGO_ZIGBUILD_PYTHON_PATH="/usr/bin/false", CC_ENABLE_DEBUG_OUTPUT="1")
    sccache = shutil.which("sccache", path=env.get("PATH", ""))
    if sccache:
        result["RUSTC_WRAPPER"] = str(Path(sccache).resolve(strict=True))
        initialize_compiler_cache(result)
    return result, tools


def verify_tool(path: Path, expected: str) -> dict[str, object]:
    real_path(path)
    require(re.fullmatch(r"[0-9a-f]{64}", expected) is not None, "tool digest must be lowercase SHA256")
    info = stable_hash_path(path)
    require(info.sha256 == expected and bool(info.mode & stat.S_IXUSR),
            "tool is not the exact reviewed executable: " + path.name)
    return {"path": str(path), "sha256": info.sha256, "size": info.size}


def build_command(root: Path, target_dir: Path, cargo: str) -> list[str]:
    # cwd=/ plus this explicit config excludes the mutable checkout's ancestors.
    command = [cargo, "zigbuild", "--config", str(root / ".cargo/config.toml"),
               "--manifest-path", str(root / "Cargo.toml"), "--target-dir", str(target_dir), "--locked", "--offline",
               "--profile", "release", "--target", TARGET]
    for name, package in BINARIES:
        command.extend(("-p", package, "--bin", name))
    return command


def first_build_error(log: Path) -> str | None:
    """Project one bounded compiler error from a completed private Cargo log."""
    try:
        fd = os.open(log, os.O_RDONLY | os.O_NOFOLLOW)
    except OSError:
        return None
    with os.fdopen(fd, "rb") as source:
        while raw := source.readline(256 * 1024):
            # A malformed or enormous child line must not consume unbounded memory.
            if not raw.endswith(b"\n"):
                while tail := source.readline(256 * 1024):
                    if tail.endswith(b"\n"):
                        break
            line = re.sub(r"\x1b\[[0-?]*[ -/]*[@-~]", "", raw.decode("utf-8", "replace")).strip()
            if line.startswith("{"):
                try:
                    value = json.loads(line)
                except (ValueError, TypeError):
                    continue
                message = value.get("message") if isinstance(value, dict) else None
                if (isinstance(value, dict)
                        and value.get("reason") == "compiler-message"
                        and isinstance(message, dict)
                        and message.get("level") == "error"):
                    line = message.get("message", "")
                else:
                    continue
            elif not re.match(
                r"^(?:error(?:\[[^]]+\])?:|(?:ld(?:\.lld)?|rust-lld|collect2|clang(?:-\d+)?|cc|gcc): error:)",
                line,
            ):
                continue
            if not isinstance(line, str):
                continue
            # Keep diagnostics useful without relaying control sequences or a full
            # compiler transcript into the operator-facing failure message.
            line = re.sub(r"\x1b\[[0-?]*[ -/]*[@-~]", "", line)
            line = " ".join("".join(char if char.isprintable() else " " for char in line).split())
            if line:
                return line[:240] + ("..." if len(line) > 240 else "")
    return None


def run_build(root: Path, command: list[str], env: dict[str, str], log: Path,
              *, lock_fd: int | None = None, lane_lock_fd: int | None = None,
              mode_lock_fd: int | None = None, label: str = "Linux build") -> None:
    failure = None
    code = None
    started = time.monotonic()
    # Commit diagnostic output even on compiler failure; the result is published
    # only after a successful build and independent source/tool revalidation.
    with exclusive_output_fd(log, mode=0o600) as output:
        try:
            # Cargo's locks and outputs must satisfy capture custody even when
            # the invoking Linux account has a group-writable default umask.
            child = subprocess.Popen(command, cwd="/", env=env, stdin=subprocess.DEVNULL,
                                     stdout=output, stderr=subprocess.STDOUT, start_new_session=True, umask=0o077,
                                     pass_fds=tuple(fd for fd in (lock_fd, lane_lock_fd, mode_lock_fd) if fd is not None))
            try:
                while True:
                    try:
                        code = child.wait(timeout=PROGRESS_SECONDS)
                        break
                    except subprocess.TimeoutExpired:
                        print(f"[taira-release] {label} running {time.monotonic() - started:.0f}s; "
                              f"compiler output {os.fstat(output).st_size} bytes; log {log}", flush=True)
                require(code == 0, label + " failed; inspect " + str(log)
                        + "; retain the log and reuse the warm Cargo lane for the next attempt")
            except BaseException:
                # The inherited preparation lock remains held by any active child.
                # A launcher interruption does not authorize killing Cargo.
                if child.poll() is None:
                    print(f"[taira-release] build process {child.pid} retained; log {log}",
                          file=sys.stderr, flush=True)
                raise
        except BaseException as error:
            failure = error
    if failure is not None:
        if code is not None and code != 0 and isinstance(failure, PrepareError):
            try:
                diagnostic = first_build_error(log)
            except Exception:
                # Diagnostics must never replace the original build failure.
                diagnostic = None
            if diagnostic:
                raise PrepareError(str(failure) + "; first error: " + diagnostic) from failure
        raise failure


def valid_elf(header: bytes) -> bool:
    return (len(header) >= 20 and header[:7] == b"\x7fELF\x02\x01\x01"
            and struct.unpack("<H", header[16:18])[0] in (2, 3)
            and struct.unpack("<H", header[18:20])[0] == 183)


def freeze(path: Path, *, directory: bool = False) -> None:
    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC
    if directory:
        flags |= os.O_DIRECTORY
    fd = os.open(path, flags)
    try:
        info = os.fstat(fd)
        require(info.st_uid == os.geteuid() and
                (info.st_dev, info.st_ino) == (path.lstat().st_dev, path.lstat().st_ino),
                "capture ownership or path changed")
        os.fchmod(fd, 0o500 if directory or info.st_mode & stat.S_IXUSR else 0o400)
        os.fsync(fd)
    finally:
        os.close(fd)


def capture_artifacts(target_dir: Path, output_dir: Path) -> list[dict[str, object]]:
    sources = [(name, package, cargo_hash_path(target_dir / TARGET / "release" / name,
                                                max_size=MAX_BINARY_BYTES))
               for name, package in BINARIES]
    capacity_preflight([(output_dir, sum(info.size for _, _, info in sources)
                        + CAPTURE_HEADROOM_BYTES, "artifact capture")])
    capture = create_fresh_directory(output_dir / "bin", mode=0o700)
    rows = []
    for name, package, expected in sources:
        relative = f"{TARGET}/release/{name}"
        original = target_dir / relative
        require(expected.size >= 20 and bool(expected.mode & stat.S_IXUSR),
                "release artifact must be an executable ELF")
        require(original.stat().st_uid == os.geteuid(), "release artifact must be owner-held")
        destination = capture / name
        with cargo_open_relative(target_dir, relative, expected=expected) as source:
            require(valid_elf(os.read(source, 20)), "release artifact is not AArch64 Linux ELF: " + name)
            os.lseek(source, 0, os.SEEK_SET)
            with exclusive_output_fd(destination, mode=0o755) as output:
                digest, size = hashlib.sha256(), 0
                while block := os.read(source, 1024 * 1024):
                    size += len(block)
                    require(size <= expected.size, "artifact grew during capture")
                    digest.update(block)
                    view = memoryview(block)
                    while view:
                        written = os.write(output, view)
                        require(written > 0, "artifact capture made no write progress")
                        view = view[written:]
                require(size == expected.size and digest.hexdigest() == expected.sha256,
                        "artifact changed during capture")
        freeze(destination)
        actual = stable_hash_path(destination, max_size=MAX_BINARY_BYTES)
        require(actual.sha256 == expected.sha256 and actual.mode == 0o500,
                "read-only artifact capture differs from the build")
        rows.append({"name": name, "package": package, "path": str(destination),
                     "sha256": actual.sha256, "size": actual.size})
    freeze(capture, directory=True)
    return rows


def capacity_preflight(requirements: list[tuple[Path, int, str]]) -> list[dict[str, object]]:
    """Sum additional bytes on each actual filesystem, using descriptor-based free space."""
    devices: dict[int, dict[str, object]] = {}
    for path, required, label in requirements:
        require(type(required) is int and required >= 0, "invalid capacity requirement")
        anchor = real_path(path, exists=False)
        while not anchor.exists():
            anchor = anchor.parent
        fd = os.open(anchor, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            info, space = os.fstat(fd), os.fstatvfs(fd)
            require((info.st_dev, info.st_ino) == (anchor.stat().st_dev, anchor.stat().st_ino),
                    "capacity filesystem changed during inspection")
            available = space.f_bavail * space.f_frsize
            require(available >= 0, "filesystem reported invalid available space")
            row = devices.setdefault(info.st_dev, {"path": str(anchor), "required_bytes": 0,
                                                   "available_bytes": available, "uses": []})
            row["required_bytes"] += required
            row["available_bytes"] = min(row["available_bytes"], available)
            row["uses"].append(label)
        finally:
            os.close(fd)
    for row in devices.values():
        require(row["available_bytes"] >= row["required_bytes"],
                f"insufficient free space at {row['path']}: need {row['required_bytes']} additional bytes "
                f"for {', '.join(row['uses'])}, available {row['available_bytes']}; "
                "free obsolete output copies, retain the warm Cargo lane, then rerun the same command")
    return list(devices.values())


def read_record(path: Path) -> dict[str, object]:
    require(path.lstat().st_uid == os.geteuid() and stat.S_IMODE(path.lstat().st_mode) == 0o400,
            "preparation checkpoint must remain owner-held and read-only: " + str(path))
    expected = stable_hash_path(path, max_size=16 * 1024**2)
    with stable_open_relative(path.parent, path.name, expected=expected) as fd:
        raw = bytearray()
        while block := os.read(fd, 1024 * 1024):
            raw.extend(block)
    try:
        value = json.loads(raw)
    except (ValueError, UnicodeError) as error:
        raise PrepareError("invalid preparation checkpoint: " + str(path)) from error
    require(isinstance(value, dict) and canonical_json_bytes(value) == raw,
            "noncanonical preparation checkpoint: " + str(path))
    return value


def write_record(path: Path, value: dict[str, object]) -> None:
    # The session flock serializes all checkpoint writers. A crash leaves either the
    # complete read-only checkpoint or an unreferenced private temporary file.
    temporary = path.with_name(path.name + ".pending-" + uuid.uuid4().hex)
    exclusive_write_bytes(temporary, canonical_json_bytes(value), mode=0o600)
    freeze(temporary)
    require(not os.path.lexists(path), "checkpoint already exists: " + str(path))
    os.rename(temporary, path)
    directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


@contextlib.contextmanager
def preparation_lock(output: Path, *, purpose: str | None = None):
    info = output.lstat()
    require(stat.S_ISDIR(info.st_mode) and info.st_uid == os.geteuid()
            and stat.S_IMODE(info.st_mode) in (0o700, 0o500),
            "preparation output must remain an owner-private directory")
    path = output / "session.lock"
    fd = os.open(path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    try:
        opened = os.fstat(fd)
        require(stat.S_ISREG(opened.st_mode) and opened.st_uid == os.geteuid()
                and opened.st_nlink == 1 and stat.S_IMODE(opened.st_mode) == 0o600
                and (opened.st_dev, opened.st_ino) == (path.lstat().st_dev, path.lstat().st_ino),
                "preparation lock custody changed")
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as error:
            if purpose is not None:
                raise PrepareError(f"{purpose} is still running; lane coordination is {output}") from error
            raise PrepareError("preparation is still running; inspect retained attempt logs at "
                               + str(output / "attempts")) from error
        yield fd
    finally:
        os.close(fd)


def verify_capture(result: dict[str, object], base: dict[str, object], output: Path) -> None:
    require(all(result.get(key) == value for key, value in base.items())
            and set(result) == set(base) | {"artifacts", "timings_seconds", "attempt"},
            "completed preparation identity differs from this command")
    attempt = result["attempt"]
    require(isinstance(attempt, str) and re.fullmatch(r"attempts/[0-9]{6}", attempt),
            "invalid completed attempt path")
    capture = real_path(output / attempt / "bin")
    require(stat.S_IMODE(capture.stat().st_mode) == 0o500, "capture directory is not read-only")
    rows = result["artifacts"]
    require(isinstance(rows, list) and len(rows) == len(BINARIES), "incomplete captured binaries")
    for row, (name, package) in zip(rows, BINARIES):
        path = capture / name
        require(isinstance(row, dict) and set(row) == {"name", "package", "path", "sha256", "size"}
                and row["name"] == name and row["package"] == package and row["path"] == str(path),
                "captured artifact path or role differs")
        actual = stable_hash_path(path, max_size=MAX_BINARY_BYTES)
        require(actual.sha256 == row["sha256"] and actual.size == row["size"]
                and actual.mode == 0o500 and path.stat().st_uid == os.geteuid(),
                "captured artifact changed; retained output must be inspected: " + str(path))


def routine_target(root: Path) -> Path:
    return root.parent / ".taira-testnet-build-targets" / "routine"


def development_target(root: Path, requested: Path | None, inherited: dict[str, str]) -> Path:
    """Select an existing lane; ambient CARGO_TARGET_DIR never selects authority."""
    configured = inherited.get("TAIRA_TESTNET_CARGO_TARGET_DIR")
    require(configured is None or bool(configured), "TAIRA_TESTNET_CARGO_TARGET_DIR must not be empty")
    explicit = real_path(requested) if requested is not None else None
    environment = real_path(Path(configured)) if configured is not None else None
    require(explicit is None or environment is None or explicit == environment,
            "--target-dir conflicts with TAIRA_TESTNET_CARGO_TARGET_DIR")
    return explicit or environment or real_path(routine_target(root))


@contextlib.contextmanager
def cargo_lane(root: Path, target_dir: Path, role: str):
    """Keep diagnostic and authenticated modes separate for the whole native run."""
    require(role in {"development", "release"}, "invalid Cargo lane role")
    root = real_path(root)
    real_path(target_dir)
    info = target_dir.stat()
    require(stat.S_ISDIR(info.st_mode) and info.st_uid == os.geteuid()
            and not info.st_mode & 0o022, "target-dir must be an existing owner-held warm Cargo lane")
    if role == "development":
        require(target_dir != root / "target"
                and "taira-release-sources" not in target_dir.parts
                and not os.path.lexists(target_dir / "taira-release-sources"),
                "development checks cannot use the authenticated release lane")
    else:
        require(not target_dir.is_relative_to(routine_target(root)),
                "authenticated preparation cannot use the routine development lane")
    coordination = target_dir / ".taira-build-lane"
    coordination.mkdir(mode=0o700, exist_ok=True)
    real_path(coordination)
    with preparation_lock(coordination, purpose=f"{role} Cargo lane") as lock_fd:
        marker = coordination / "role.json"
        expected = canonical_json_bytes({"schema": "taira.cargo-lane.v1", "repo_root": str(root), "role": role})
        require(len(expected) <= 16 * 1024, "Cargo lane ownership record is too large")
        if not os.path.lexists(marker):
            exclusive_write_bytes(marker, expected, mode=0o600)
        fd = os.open(marker, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            info = os.fstat(fd)
            require(stat.S_ISREG(info.st_mode) and info.st_uid == os.geteuid()
                    and info.st_nlink == 1 and stat.S_IMODE(info.st_mode) == 0o600,
                    "Cargo lane role must remain owner-held")
            require(info.st_size == len(expected) and os.read(fd, len(expected) + 1) == expected,
                    "Cargo lane is assigned to a different build mode or repository")
        finally:
            os.close(fd)
        yield lock_fd


def development_check(root: Path, target: Path | None, inherited: dict[str, str],
                      *, native_check_scope: str = "basic", focused_regressions=None,
                      native_linker: str | None = None,
                      lock_fds: tuple[int, ...] = ()) -> None:
    # Mutable-source diagnostics intentionally use the checkout gate. Preparation
    # never imports this module and authenticates its captured gate separately.
    import taira_release_check as gate

    try:
        if focused_regressions is not None:
            gate.focused_regression_stages(native_check_scope, focused_regressions)
        root = real_path(root)
        target_dir = development_target(root, target, inherited)
        with cargo_lane(root, target_dir, "development") as lock_fd:
            env = child_environment(inherited, target_dir)
            env, _ = isolated_cargo_environment(root, root, env)
            print(f"[taira-check] development lane {target_dir}; mutable source; not release-qualified", flush=True)
            native = native_check_environment(env, inherited)
            native = development_linker_environment(
                native, default_development_linker() if native_linker is None else native_linker)
            if focused_regressions is None:
                gate.run_checks(root, environment=native, lock_fds=(*lock_fds, lock_fd),
                                qualification_scope=native_check_scope)
            else:
                gate.run_prequalification(root, focused_regressions=focused_regressions,
                                          environment=native, lock_fds=(*lock_fds, lock_fd),
                                          qualification_scope=native_check_scope)
    except gate.CheckError as error:
        raise PrepareError(str(error)) from error


CHECK_SESSION_SCHEMA = "taira.development-check.v1"


def check_session_directory(path: Path) -> Path:
    path = real_path(path)
    info = path.stat()
    require(stat.S_ISDIR(info.st_mode) and info.st_uid == os.geteuid()
            and stat.S_IMODE(info.st_mode) == 0o700,
            "check session must remain an owner-private 0700 directory")
    return path


def check_session_lock_identity(session: Path, fd: int) -> None:
    opened, named = os.fstat(fd), (session / "session.lock").lstat()
    require(stat.S_ISREG(opened.st_mode) and opened.st_uid == os.geteuid()
            and opened.st_nlink == 1 and stat.S_IMODE(opened.st_mode) == 0o600
            and (opened.st_dev, opened.st_ino) == (named.st_dev, named.st_ino),
            "check session lock custody changed")


def check_request(session: Path) -> dict[str, object]:
    request = read_record(session / "request.json")
    require(set(request) == {"schema", "session_id", "repo_root", "target_dir",
                            "native_check_scope", "native_linker", "focused_regressions",
                            "incremental", "created_ns"}
            and request["schema"] == CHECK_SESSION_SCHEMA
            and isinstance(request["session_id"], str)
            and re.fullmatch(r"[0-9a-f]{32}", request["session_id"])
            and request["native_check_scope"] in ("basic", "full")
            and request["native_linker"] in ("system", "llvm")
            and request["incremental"] in ("0", "1")
            and type(request["created_ns"]) is int,
            "invalid development check request")
    for field in ("repo_root", "target_dir"):
        require(isinstance(request[field], str), "invalid check request path")
        real_path(Path(request[field]))
    focused = request["focused_regressions"]
    require(focused is None or (isinstance(focused, list) and focused
                               and all(isinstance(item, str) for item in focused)),
            "invalid focused development check request")
    return request


def development_check_status(session: Path) -> dict[str, object]:
    """Observe durable completion and inherited flock custody without trusting PIDs."""
    session = check_session_directory(session)
    request = check_request(session)
    fd = os.open(session / "session.lock", os.O_RDWR | os.O_NONBLOCK | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        check_session_lock_identity(session, fd)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            active = False
        except BlockingIOError:
            active = True
        result = None
        if os.path.lexists(session / "result.json"):
            result = read_record(session / "result.json")
            require(result.get("schema") == CHECK_SESSION_SCHEMA
                    and result.get("session_id") == request["session_id"]
                    and type(result.get("exit_code")) is int
                    and result["exit_code"] in (0, 1), "invalid development check result")
        # A held descriptor can belong to the worker or its still-running Cargo
        # descendant. Neither a stale PID nor a result published before final
        # descriptor cleanup can authorize a terminal status.
        state = "running" if active else (
            "incomplete" if result is None else "passed" if result["exit_code"] == 0 else "failed")
        return {"schema": CHECK_SESSION_SCHEMA, "session_id": request["session_id"],
                "state": state, "request_path": str(session / "request.json"),
                "focused_regression_count": len(request["focused_regressions"] or []),
                "result": result, "log": str(session / "check.log"),
                "release_qualified": False}
    finally:
        os.close(fd)


def start_development_check(args: argparse.Namespace, inherited: dict[str, str]) -> Path:
    """Detach one diagnostic; retain records and never restart an incomplete run."""
    import taira_release_check as gate

    root = real_path(args.repo_root)
    target = development_target(root, args.target_dir, inherited)
    focused = args.focus_regression
    if focused is not None:
        try:
            gate.focused_regression_stages(args.native_check_scope, focused)
        except gate.CheckError as error:
            raise PrepareError(str(error)) from error
    incremental = inherited.get("CARGO_INCREMENTAL", "1")
    require(incremental in ("0", "1"), "native CARGO_INCREMENTAL must be 0 or 1")
    session = create_fresh_directory(real_path(args.session_dir, exists=False), mode=0o700)
    with preparation_lock(session) as session_fd:
        request = {"schema": CHECK_SESSION_SCHEMA, "session_id": uuid.uuid4().hex,
                   "repo_root": str(root), "target_dir": str(target),
                   "native_check_scope": args.native_check_scope,
                   "native_linker": args.native_linker,
                   "focused_regressions": focused, "incremental": incremental,
                   "created_ns": time.time_ns()}
        write_record(session / "request.json", request)
        with exclusive_output_fd(session / "check.log", mode=0o600) as log_fd:
            # Only the standard sanitized build environment crosses this process
            # boundary. No inherited environment record or credentials are saved.
            environment = child_environment(inherited, target)
            environment["CARGO_INCREMENTAL"] = incremental
            try:
                subprocess.Popen(
                    [sys.executable, str(Path(__file__).resolve()), "_check-runner",
                     "--session-dir", str(session), "--session-fd", str(session_fd)],
                    cwd=root, env=environment, stdin=subprocess.DEVNULL,
                    stdout=log_fd, stderr=log_fd, start_new_session=True,
                    pass_fds=(session_fd,), umask=0o077,
                )
            except OSError as error:
                os.write(log_fd, f"[taira-check] launch failed: {error}\n".encode("utf-8"))
                os.fsync(log_fd)
                write_record(session / "result.json", {
                    "schema": CHECK_SESSION_SCHEMA, "session_id": request["session_id"],
                    "exit_code": 1, "finished_ns": time.time_ns(),
                    "error_type": type(error).__name__, "stage": "launch",
                })
                raise
    return session


def run_development_check_session(session: Path, session_fd: int) -> int:
    """The sole detached child retains session custody through durable completion."""
    session = check_session_directory(session)
    check_session_lock_identity(session, session_fd)
    # A fresh independent open must contend with the inherited open description.
    # Do not re-lock an arbitrary supplied descriptor or trust a recorded PID.
    require(development_check_status(session)["state"] == "running",
            "check runner requires its inherited session lock")
    try:
        fcntl.flock(session_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError as error:
        raise PrepareError("check runner descriptor does not own its inherited lock") from error
    request = check_request(session)
    write_record(session / "started.json", {
        "schema": CHECK_SESSION_SCHEMA, "session_id": request["session_id"],
        "pid": os.getpid(), "started_ns": time.time_ns(),
    })
    result = {"schema": CHECK_SESSION_SCHEMA, "session_id": request["session_id"],
              "exit_code": 0, "error_type": None, "stage": "check"}
    try:
        development_check(
            Path(request["repo_root"]), Path(request["target_dir"]),
            dict(os.environ, CARGO_INCREMENTAL=request["incremental"]),
            native_check_scope=request["native_check_scope"],
            native_linker=request["native_linker"],
            focused_regressions=request["focused_regressions"], lock_fds=(session_fd,),
        )
    except Exception as error:
        result.update(exit_code=1, error_type=type(error).__name__)
        print(f"[taira-check] FAIL: {error}", file=sys.stderr, flush=True)
    result["finished_ns"] = time.time_ns()
    sys.stdout.flush()
    sys.stderr.flush()
    os.fsync(sys.stdout.fileno())
    write_record(session / "result.json", result)
    return result["exit_code"]


@contextlib.contextmanager
def source_lane(root: Path, target_dir: Path):
    # Preserve the fixed-source custody lock even across preparer upgrades.
    key = hashlib.sha256(os.fsencode(target_dir)).hexdigest()[:24]
    parent = target_dir / "taira-release-sources" / key
    ensure_private_directory(parent, anchor=target_dir)
    real_path(parent)
    with preparation_lock(parent) as lock_fd:
        yield parent / "source", lock_fd


def prepare(args: argparse.Namespace) -> dict[str, object]:
    root, target_dir = real_path(args.repo_root), real_path(args.target_dir)
    require(target_dir.is_dir(), "target-dir must be an existing warm Cargo lane")
    with cargo_lane(root, target_dir, "release") as mode_lock_fd:
        with source_lane(root, target_dir) as (source, lock_fd):
            return prepare_in_lane(args, source, lock_fd, mode_lock_fd)


def prepare_in_lane(args: argparse.Namespace, source: Path, lane_lock_fd: int, mode_lock_fd: int) -> dict[str, object]:
    root, target_dir = real_path(args.repo_root), real_path(args.target_dir)
    require(args.native_check_scope == "build-only", "preparation is build-only; use check for regression tests")
    source_mode = getattr(args, "source_mode", "captured")
    require(source_mode in {"captured", "canonical-checkout"}, "unsupported compiler source mode")
    output = real_path(args.output_dir, exists=False)
    preflight_preparation_tmpdir(dict(os.environ))
    require(Path(__file__).resolve() == root / "scripts/taira_release.py",
            "prepare must use the maintained script from the selected checkout")
    require(target_dir.is_dir(), "target-dir must be an existing warm Cargo lane")
    fresh = not os.path.lexists(output)
    require(fresh or (output / "request.json").is_file(),
            "existing output has no preparation checkpoint; retain it and choose a fresh output directory")
    if output.is_relative_to(root):
        require(output.is_relative_to(root / "target"), "repository outputs must stay under target/")
    require(output != target_dir and not target_dir.is_relative_to(output),
            "output-dir must not contain the Cargo lane")
    tree = verify_signed_source(root, args.expected_commit, args.expected_signer)
    entries = commit_entries(root, args.expected_commit)
    canonical_before = (canonical_source_snapshot(root, args.expected_commit, entries)
                        if source_mode == "canonical-checkout" else None)
    if fresh:
        capacity_preflight([(target_dir, signed_source_size(root, args.expected_commit, entries),
                             "fixed source capture"),
                            (target_dir, BUILD_FREE_FLOOR_BYTES, "Cargo working space floor"),
                            (output, CAPTURE_HEADROOM_BYTES, "capture headroom")])
    capture_started = time.monotonic()
    capture_total = entries.count(b"\0")
    capture_completed = [0]

    def count_captured_entry(count: int) -> None:
        capture_completed[0] = count

    capture_stop = threading.Event()
    capture_thread = threading.Thread(
        target=source_capture_heartbeat,
        args=(capture_stop, capture_started, capture_completed, capture_total),
        daemon=True,
    )
    print(f"[taira-release] signed source capture started ({capture_total} entries)", flush=True)
    capture_thread.start()
    try:
        source = capture_source(root, source, target_dir, args.expected_commit, entries,
                                on_entry=count_captured_entry)
        capture_completed[0] = capture_total
        before = frozen_snapshot(source, entries, target_dir)
    finally:
        capture_stop.set()
        capture_thread.join()
    print(f"[taira-release] signed source capture ready ({capture_total} entries "
          f"in {time.monotonic() - capture_started:.1f}s)", flush=True)
    authority_source, authority_before = source, before
    if canonical_before is not None:
        source, before = root, canonical_before
        require(canonical_source_snapshot(root, args.expected_commit, entries) == before,
                "canonical compiler source changed during authority capture")
    inherited = dict(os.environ)
    env, environment_record, incremental = preparation_environment(output, target_dir, inherited, fresh=fresh)
    tools = [verify_tool(args.zig, args.zig_sha256),
             verify_tool(args.cargo_zigbuild, args.cargo_zigbuild_sha256)]
    selected = shutil.which("cargo-zigbuild", path=env.get("PATH", ""))
    require(selected is not None and Path(selected).resolve() == args.cargo_zigbuild,
            "PATH must select the explicitly pinned cargo-zigbuild")
    env.update(IROHA_ZIG_BINARY=str(args.zig), IROHA_GIT_COMMIT_HASH=args.expected_commit,
               VERGEN_GIT_SHA=args.expected_commit)
    env, compiler_tools = isolated_cargo_environment(root, source, env)
    native_linker = preparation_native_linker(args.native_linker)
    native_env = preparation_native_environment(
        native_check_environment(env, {"CARGO_INCREMENTAL": incremental}), native_linker)
    print("[taira-release] pinned native linker " + json.dumps(native_linker, sort_keys=True), flush=True)
    command = build_command(source, target_dir, env["CARGO"])
    base = {"commit": args.expected_commit, "signer_fingerprint": args.expected_signer,
            "native_check_scope": "build-only",
            "native_incremental": native_env["CARGO_INCREMENTAL"] == "1",
            "native_linker": native_linker,
            "environment_sha256": hashlib.sha256(canonical_json_bytes(environment_record)).hexdigest(),
            # This is the effective gate environment: child_environment excludes
            # CARGO_BUILD_TARGET, and both commit variables are normalized above.
            # Bind path-dependent tests without publishing environment values.
            "native_environment_sha256": hashlib.sha256(canonical_json_bytes(native_env)).hexdigest(),
            "tree": tree, "target": TARGET, "profile": "release", "jobs": 6,
            "source_unchanged": True, "toolchain_unchanged": True,
            "source_snapshot_sha256": hashlib.sha256(canonical_json_bytes(authority_before)).hexdigest(),
            # Source root names immutable authority; command binds the actual compiler root.
            "source_root": str(authority_source), "source_output_target": str(target_dir), "compiler_tools": compiler_tools,
            "tools": tools, "command": command, "release_qualified": False, "deployed": False}
    request = {"schema": SESSION_SCHEMA, "repo_root": str(root), "target_dir": str(target_dir), **base}
    if fresh:
        capacity_preflight([(target_dir, BUILD_FREE_FLOOR_BYTES, "Cargo working space floor"),
                            (output, CAPTURE_HEADROOM_BYTES, "capture headroom")])
        output = create_fresh_directory(output, mode=0o700)

    def revalidate():
        require(preparation_native_linker(args.native_linker) == native_linker,
                "native linker choice or tool identity changed during preparation")
        require(recorded_preparation_environment(output, target_dir, request) == environment_record,
                "preparation environment checkpoint changed during preparation")
        require(frozen_snapshot(authority_source, entries, target_dir) == authority_before,
                "captured source changed during preparation")
        if canonical_before is not None:
            require(canonical_source_snapshot(root, args.expected_commit, entries) == before,
                    "canonical compiler source changed during preparation")
        require([{"name": row["name"], **verify_tool(Path(row["path"]), row["sha256"])}
                 for row in compiler_tools] == compiler_tools, "Rust toolchain changed during preparation")
        require([verify_tool(args.zig, args.zig_sha256),
                 verify_tool(args.cargo_zigbuild, args.cargo_zigbuild_sha256)] == tools,
                "toolchain changed during preparation")

    with preparation_lock(output) as lock_fd:
        if fresh:
            write_record(output / "environment.json", environment_record)
            write_record(output / "request.json", request)
            create_fresh_directory(output / "attempts", mode=0o700)
        else:
            require(read_record(output / "request.json") == request,
                    "preparation checkpoint belongs to different inputs; retain it and select a new output")
        # request.json is the durable initialization checkpoint. If its publication
        # survived but the following mkdir did not, complete that empty namespace
        # under the same lock after the exact request has been revalidated.
        if not os.path.lexists(output / "attempts"):
            create_fresh_directory(output / "attempts", mode=0o700)
        if (output / "result.json").exists():
            result = read_record(output / "result.json")
            verify_capture(result, base, output)
            revalidate()
            freeze(output / result["attempt"], directory=True)
            freeze(output, directory=True)
            print("[taira-release] reused completed captured binaries; no checks or build needed", flush=True)
            return result
        attempts = output / "attempts"
        names = sorted(path.name for path in attempts.iterdir())
        require(all(re.fullmatch(r"[0-9]{6}", name) for name in names), "unexpected preparation attempt entry")
        # Only an immutable completed capture can bypass Cargo. Partial builds/captures are
        # retained, then Cargo reuses its own warm cache in a fresh attempt directory.
        for name in reversed(names):
            candidate = attempts / name / "capture.json"
            if candidate.exists():
                result = read_record(candidate)
                require(result.get("attempt") == "attempts/" + name, "capture attempt differs")
                verify_capture(result, base, output)
                revalidate()
                freeze(attempts / name, directory=True)
                write_record(output / "result.json", result)
                freeze(output, directory=True)
                print("[taira-release] recovered completed capture; no rebuild needed", flush=True)
                return result
        capacity_preflight([(target_dir, BUILD_FREE_FLOOR_BYTES, "Cargo working space floor"),
                            (output, CAPTURE_HEADROOM_BYTES, "capture headroom")])
        # Resolve the complete signed package graph before allocating an attempt
        # or running the release build.
        print("[taira-release] verify offline Cargo package closure", flush=True)
        source_paths = ({root / row["path"] for row in before if row["kind"] == "regular"}
                        if canonical_before is not None else None)
        package_roots = (local_package_roots(source, env, source_paths=source_paths)
                         if source_paths is not None else None)
        packages = set(package_roots) if package_roots is not None else local_package_names(source, env)
        fingerprint_options = ({"package_roots": package_roots, "source_paths": source_paths}
                               if package_roots is not None else {})
        attempt_number = 1 if not names else int(names[-1]) + 1
        require(attempt_number <= 999999, "preparation attempt namespace exhausted")
        attempt = create_fresh_directory(attempts / f"{attempt_number:06d}", mode=0o700)
        timings: dict[str, float] = {}

        def stage(label, operation):
            print(f"[taira-release] start {label}", flush=True)
            started = time.monotonic()
            try:
                return operation()
            finally:
                timings[label] = round(time.monotonic() - started, 3)
                print(f"[taira-release] {label} elapsed {timings[label]:.3f}s", flush=True)

        checks = output / "checks.json"
        if checks.exists():
            record = read_record(checks)
            require(record == {"request": request, "passed": False}
                    and type(record.get("passed")) is bool, "native check checkpoint differs")

        def retire_checkpoint(checkpoint):
            # Remove the resumable success checkpoint before retiring any cache
            # metadata. A crash or a failed rerun must never revive an old pass.
            if checkpoint.exists():
                os.rename(checkpoint, attempt / ("retired-" + checkpoint.name))
                for directory in (attempt, output):
                    fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
                    try:
                        os.fsync(fd)
                    finally:
                        os.close(fd)

        def retire_checks():
            retire_checkpoint(checks)

        admit_source_fingerprints(source, target_dir, TARGET, packages, before_retire=retire_checks,
                                  **fingerprint_options)
        revalidate()
        if checks.exists():
            print("[taira-release] reused build-only observation; native checks were not run", flush=True)
        else:
            write_record(checks, {"request": request, "passed": False})
            print("[taira-release] build-only: native checks not run; artifacts remain unqualified", flush=True)
        revalidate()
        stage("Linux release build", lambda: run_build(source, command, env, attempt / "cargo.log", lock_fd=lock_fd, lane_lock_fd=lane_lock_fd, mode_lock_fd=mode_lock_fd))
        with source_fingerprints(source, target_dir, TARGET, packages, repair=False, **fingerprint_options):
            revalidate()
            artifacts = stage("read-only artifact capture", lambda: capture_artifacts(target_dir, attempt))
            revalidate()
        result = {**base, "artifacts": artifacts, "timings_seconds": timings,
                  "attempt": "attempts/" + attempt.name}
        freeze(attempt / "cargo.log")
        write_record(attempt / "capture.json", result)
        freeze(attempt, directory=True)
        write_record(output / "result.json", result)
        freeze(output, directory=True)
        return result


def client_build_command(source: Path, target: Path, cargo: str, host: str,
                         binary: str) -> list[str]:
    """Build exactly the ordinary client with explicit captured configuration."""
    require(host in {"aarch64-apple-darwin", "x86_64-apple-darwin"},
            "ordinary client preparation requires a native macOS Rust toolchain")
    require(binary in CLIENT_BINARIES, "select exactly one maintained native client")
    name, package, _, _ = CLIENT_BINARIES[binary]
    return [cargo, "--config", str(source / ".cargo/config.toml"), "build",
            "--manifest-path", str(source / "Cargo.toml"), "--target-dir", str(target),
            "--locked", "--offline", "--profile", "dev", "--target", host,
            "--message-format=json-render-diagnostics", "-p", package, "--bin", name]


def client_artifact_emission(log: Path, source: Path, target: Path, host: str,
                            binary: str) -> dict[str, object]:
    """Require the successful Cargo run to emit the exact normal client artifact."""
    require(binary in CLIENT_BINARIES, "select exactly one maintained native client")
    return native_artifact_emissions(log, source, target, host,
                                     binaries=(CLIENT_BINARIES[binary],), profile="debug")[0]


def capture_client_artifact(target: Path, output: Path, host: str,
                            binary: str, *, revalidate: Callable[[], None]) -> dict[str, object]:
    """Publish the selected client under its original source and created-copy custody."""
    require(binary in CLIENT_BINARIES, "select exactly one maintained native client")
    return capture_native_binaries(target, output, host,
                                    binaries=(CLIENT_BINARIES[binary],), profile="debug",
                                    revalidate=revalidate)[0]


def native_runtime_build_command(source: Path, target: Path, cargo: str, host: str) -> list[str]:
    """Build the exact standard native runtime once, with default package features."""
    require(host in {"aarch64-apple-darwin", "x86_64-apple-darwin"},
            "native runtime preparation requires a native macOS Rust toolchain")
    command = [cargo, "--config", str(source / ".cargo/config.toml"), "build",
               "--manifest-path", str(source / "Cargo.toml"), "--target-dir", str(target),
               "--locked", "--offline", "--profile", "release", "--target", host,
               "--message-format=json-render-diagnostics"]
    for name, package, _, _ in NATIVE_RUNTIME_BINARIES:
        command.extend(("-p", package, "--bin", name))
    return command


def native_artifact_emissions(log: Path, source: Path, target: Path,
                             host: str, *, binaries: tuple, profile: str) -> list[dict[str, object]]:
    """Bind one successful Cargo run to the exact selected package/bin/source roles."""
    roles = {name: (package, manifest, entry) for name, package, manifest, entry
             in binaries}
    selected, finished = {}, []
    with log.open("rb") as stream:
        while raw := stream.readline(MAX_CARGO_RECORD_BYTES + 1):
            require(len(raw) <= MAX_CARGO_RECORD_BYTES, "Cargo native record exceeds its bound")
            if not raw.startswith(b"{"):
                continue
            try:
                value = json.loads(raw)
            except (ValueError, UnicodeError):
                continue
            if not isinstance(value, dict):
                continue
            if value.get("reason") == "build-finished":
                finished.append(value.get("success"))
                require(len(finished) == 1, "Cargo native build completion is duplicated")
            elif value.get("reason") == "compiler-artifact":
                item = value.get("target")
                require(isinstance(item, dict), "Cargo native target is malformed")
                name = item.get("name")
                require(isinstance(name, str), "Cargo native target name is malformed")
                if name not in roles:
                    continue
                # The SDK dependency also has a target named iroha. Its exact
                # non-executable library record cannot replace the CLI binary.
                if item.get("kind") == ["lib"] and "executable" in value and value["executable"] is None:
                    continue
                package, manifest, entry = roles[name]
                manifest_path = source / manifest
                declaration = tomllib.loads(manifest_path.read_text())["package"]
                require(declaration.get("name") == package,
                        "captured native package declaration differs")
                package_id = value.get("package_id")
                prefix = "path+" + manifest_path.parent.as_uri() + "#"
                require(isinstance(package_id, str) and package_id.startswith(prefix),
                        "Cargo native package identity differs from captured source")
                suffix = package_id[len(prefix):]
                version = declaration.get("version")
                if version == {"workspace": True}:
                    version = tomllib.loads((source / "Cargo.toml").read_text())["workspace"]["package"]["version"]
                require(isinstance(version, str) and suffix ==
                        (version if manifest_path.parent.name == package else package + "@" + version),
                        "Cargo native package/version differs from captured source")
                executable = str(target / host / profile / name)
                emitted_profile, filenames = value.get("profile"), value.get("filenames")
                require(item.get("kind") == ["bin"] and item.get("src_path") == str(source / entry)
                        and value.get("manifest_path") == str(manifest_path)
                        and isinstance(emitted_profile, dict) and emitted_profile.get("test") is False
                        and value.get("executable") == executable
                        and isinstance(filenames, list) and executable in filenames
                        and isinstance(value.get("features"), list) and type(value.get("fresh")) is bool
                        and name not in selected,
                        "Cargo native artifact differs from the captured runtime binary")
                selected[name] = {key: value[key] for key in (
                    "package_id", "manifest_path", "target", "profile", "features", "filenames", "executable", "fresh")}
    require(finished == [True] and set(selected) == set(roles),
            "Cargo did not emit one successful complete selected native build")
    return [selected[name] for name, *_ in binaries]


def native_runtime_artifact_emissions(log: Path, source: Path, target: Path,
                                     host: str) -> list[dict[str, object]]:
    """Bind successful Cargo outputs to all three captured package/bin/source roles."""
    return native_artifact_emissions(log, source, target, host,
                                     binaries=NATIVE_RUNTIME_BINARIES, profile="release")


def native_file_identity(info: os.stat_result) -> dict[str, int]:
    """Record the full public native identity, without rounding integer fields."""
    return {"device": info.st_dev, "inode": info.st_ino, "uid": info.st_uid, "gid": info.st_gid,
            "mode": stat.S_IMODE(info.st_mode), "links": info.st_nlink, "size": info.st_size,
            "mtime_ns": info.st_mtime_ns, "ctime_ns": info.st_ctime_ns}


def capture_native_binaries(target: Path, output: Path, host: str, *, binaries: tuple,
                            profile: str, revalidate: Callable[[], None]) -> list[dict[str, object]]:
    """Retain every selected native executable, then publish their complete directory."""
    expected = [cargo_hash_path(target / host / profile / name, max_size=MAX_BINARY_BYTES)
                for name, *_ in binaries]
    capacity_preflight([(output, sum(row.size for row in expected) + CAPTURE_HEADROOM_BYTES,
                         "complete native artifact capture")])
    stage = create_fresh_directory(output / (".native-bin.pending-" + uuid.uuid4().hex), mode=0o700)
    destination = output / "bin"
    cpu = {"aarch64-apple-darwin": 0x100000c, "x86_64-apple-darwin": 0x1000007}[host]
    with contextlib.ExitStack() as retained:
        parent_fd = os.open(output, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        retained.callback(os.close, parent_fd)
        parent_identity = os.fstat(parent_fd)
        def revalidate_parent():
            real_path(output)
            opened, named = os.fstat(parent_fd), output.lstat()
            require(stat.S_ISDIR(opened.st_mode) and opened.st_uid == os.geteuid()
                    and stat.S_IMODE(opened.st_mode) == 0o700
                    and all(getattr(opened, field) == getattr(parent_identity, field)
                            for field in ("st_dev", "st_ino", "st_mode", "st_uid", "st_gid"))
                    and file_identity(opened) == file_identity(named),
                    "native artifact output parent custody changed")
        revalidate_parent()
        stage_fd = os.open(stage, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        retained.callback(os.close, stage_fd)
        rows, copies, sources = [], [], []
        for (name, package, _, _), pin in zip(binaries, expected):
            relative = host + "/" + profile + "/" + name
            source = retained.enter_context(cargo_open_relative(target, relative, expected=pin))
            original = os.fstat(source)
            require(pin.size >= 32 and original.st_uid == os.geteuid()
                    and bool(original.st_mode & stat.S_IXUSR),
                    "native artifact artifact is not an owner-held executable")
            header = os.read(source, 16)
            require(len(header) == 16 and struct.unpack("<IIII", header)[0:2] == (0xfeedfacf, cpu)
                    and struct.unpack("<IIII", header)[3] == 2,
                    "artifact is not a native macOS executable")
            os.lseek(source, 0, os.SEEK_SET)
            path = stage / name
            with exclusive_output_fd(path, mode=0o755) as result:
                # Preserve the actual create-only origin; reopening a pathname
                # after this context must never become a new custody baseline.
                copy = os.dup(result)
                retained.callback(os.close, copy)
                digest, size = hashlib.sha256(), 0
                while block := os.read(source, 1024 * 1024):
                    size += len(block)
                    require(size <= pin.size, "native artifact artifact grew during capture")
                    digest.update(block)
                    view = memoryview(block)
                    while view:
                        written = os.write(result, view)
                        require(written > 0, "native artifact capture made no write progress")
                        view = view[written:]
                require(size == pin.size and digest.hexdigest() == pin.sha256,
                        "native artifact artifact changed during capture")
            os.fchmod(copy, 0o500)
            os.fsync(copy)
            identity = os.fstat(copy)
            require(stat.S_ISREG(identity.st_mode) and identity.st_nlink == 1
                    and identity.st_uid == os.geteuid() and identity.st_size == pin.size
                    and file_identity(path.lstat()) == file_identity(identity),
                    "native artifact created copy custody changed")
            captured = stable_hash_path(path, max_size=MAX_BINARY_BYTES)
            require(file_identity(os.fstat(copy)) == file_identity(identity)
                    and file_identity(path.lstat()) == file_identity(identity)
                    and captured.sha256 == pin.sha256 and captured.mode == 0o500,
                    "retained native artifact differs from the build")
            sources.append((source, original, relative, pin))
            copies.append((copy, identity, name, captured))
            rows.append({"name": name, "package": package, "path": str(destination / name),
                         "sha256": captured.sha256, "size": captured.size,
                         "identity": native_file_identity(identity),
                         "source_identity": native_file_identity(original)})
        revalidate()
        for source, original, relative, pin in sources:
            require(file_identity(os.fstat(source)) == file_identity(original)
                    and file_identity((target / relative).lstat()) == file_identity(original)
                    and cargo_hash_path(target / relative, max_size=MAX_BINARY_BYTES) == pin,
                    "native artifact source changed before package publication")
        for copy, identity, name, pin in copies:
            require(file_identity(os.fstat(copy)) == file_identity(identity)
                    and file_identity((stage / name).lstat()) == file_identity(identity)
                    and stable_hash_path(stage / name, max_size=MAX_BINARY_BYTES) == pin,
                    "native artifact copy changed before package publication")
        staged_names = set()
        with os.scandir(stage_fd) as names:
            for entry in names:
                require(len(staged_names) < len(binaries),
                        "native artifact staging directory contains foreign output")
                staged_names.add(entry.name)
        require(staged_names == {name for name, *_ in binaries},
                "native artifact staging directory contains foreign output")
        revalidate_parent()
        publish_directory_noreplace(stage, destination, parent_fd=parent_fd, stage_fd=stage_fd)
        published = os.fstat(stage_fd)
        require(stat.S_ISDIR(published.st_mode) and published.st_uid == os.geteuid()
                and stat.S_IMODE(published.st_mode) == 0o700
                and file_identity(destination.lstat()) == file_identity(published),
                "native artifact published directory custody changed")
        # Original file descriptors survive the directory rename. Join every
        # copied inode to its final name before releasing those descriptors.
        for copy, identity, name, pin in copies:
            require(file_identity(os.fstat(copy)) == file_identity(identity)
                    and file_identity((destination / name).lstat()) == file_identity(identity)
                    and stable_hash_path(destination / name, max_size=MAX_BINARY_BYTES) == pin,
                    "native artifact publication changed a retained executable")
        revalidate_parent()
        require(file_identity(destination.lstat()) == file_identity(os.fstat(stage_fd)),
                "native artifact published directory custody changed before finalization")
        os.fchmod(stage_fd, 0o500)
        os.fsync(stage_fd)
        os.fsync(parent_fd)
        require(file_identity(destination.lstat()) == file_identity(os.fstat(stage_fd))
                and stat.S_IMODE(os.fstat(stage_fd).st_mode) == 0o500,
                "native artifact published directory custody changed during finalization")
        revalidate_parent()
    return rows


def capture_native_runtime(target: Path, output: Path, host: str,
                           *, revalidate: Callable[[], None]) -> list[dict[str, object]]:
    """Retain and publish the exact complete three-executable runtime."""
    return capture_native_binaries(target, output, host, binaries=NATIVE_RUNTIME_BINARIES,
                                    profile="release", revalidate=revalidate)


def prepare_native_build(args: argparse.Namespace, *, runtime: bool) -> dict[str, object]:
    """Use one authenticated preparation pipeline for client and native runtime builds."""
    action = "prepare-native-runtime" if runtime else "prepare-client"
    binary = None if runtime else args.bin
    require(runtime or binary in CLIENT_BINARIES, "select exactly one maintained native client")
    subject = "native runtime" if runtime else binary + " client"
    require(sys.platform == "darwin", action + " currently supports macOS only")
    root = real_path(args.repo_root)
    source_mode = getattr(args, "source_mode", "captured")
    require(source_mode in {"captured", "canonical-checkout"}, "unsupported compiler source mode")
    require(Path(__file__).resolve() == root / "scripts/taira_release.py",
            action + " must use the maintained script from the selected checkout")
    target = real_path(root / ("target/taira-macos-runtime" if runtime else "target/taira-macos-client"),
                       exists=False)
    output = real_path(args.output_dir, exists=False)
    require(output.is_relative_to(root / "target")
            and not any(output.is_relative_to(root / "target" / name)
                        for name in ("taira-macos-runtime", "taira-macos-client"))
            and not target.is_relative_to(output) and not os.path.lexists(output),
            subject + " output must be a fresh directory under target/ outside the " + subject + " Cargo lane")
    require(not any(output.is_relative_to(root / "target" / name)
                    for name in ("taira-release-sources", "taira-release-cargo-home")),
            "native output cannot enter the retained signed source or Cargo home")
    preflight_preparation_tmpdir(dict(os.environ))
    tree = verify_signed_source(root, args.expected_commit, args.expected_signer)
    entries = commit_entries(root, args.expected_commit)
    canonical_before = (canonical_source_snapshot(root, args.expected_commit, entries)
                        if source_mode == "canonical-checkout" else None)
    # Only authenticated controller/source admission may create the single
    # fixed native lane. Existing cache custody is admitted, never repaired.
    anchor = root / "target"
    if not os.path.lexists(anchor):
        create_fresh_directory(anchor, mode=0o700)
    anchor = real_path(anchor)
    anchor_info = anchor.stat()
    require(stat.S_ISDIR(anchor_info.st_mode) and anchor_info.st_uid == os.geteuid()
            and not anchor_info.st_mode & 0o022,
            "native target parent must remain owner-held")
    ensure_private_directory(target, anchor=anchor)
    with cargo_lane(root, target, "release") as mode_fd, source_lane(root, target) as (source, source_fd), \
            retained_native_target(target) as revalidate_target:
        capacity_preflight([(target, signed_source_size(root, args.expected_commit, entries)
                             + BUILD_FREE_FLOOR_BYTES, "signed " + subject + " source and Cargo working space")])
        capture_source(root, source, target, args.expected_commit, entries)
        before = frozen_snapshot(source, entries, target)
        authority_source, authority_before = source, before
        if canonical_before is not None:
            source, before = root, canonical_before
            require(canonical_source_snapshot(root, args.expected_commit, entries) == before,
                    "canonical compiler source changed during authority capture")
        env = child_environment(dict(os.environ), target)
        env.update(IROHA_GIT_COMMIT_HASH=args.expected_commit, VERGEN_GIT_SHA=args.expected_commit)
        env, tools = isolated_cargo_environment(root, source, env)
        # The shared shipping helper selects six jobs. Host-native builds use
        # Cargo's native jobserver; ambient job/flags overrides were sanitized.
        env.pop("CARGO_BUILD_JOBS", None)
        env.pop("CARGO_ZIGBUILD_ZIG_PATH", None)
        env.pop("CARGO_ZIGBUILD_PYTHON_PATH", None)
        linker = preparation_native_linker("system")
        env = preparation_native_environment(native_check_environment(env, {"CARGO_INCREMENTAL": "0"}), linker)
        version = subprocess.check_output([env["RUSTC"], "-vV"], cwd="/", env=env,
                                          stdin=subprocess.DEVNULL, text=True, timeout=30)
        hosts = re.findall(r"^host: (\S+)$", version, re.MULTILINE)
        require(len(hosts) == 1, "Rust toolchain did not report one native host")
        host = hosts[0]
        command = (native_runtime_build_command(source, target, env["CARGO"], host) if runtime
                   else client_build_command(source, target, env["CARGO"], host, binary))
        source_paths = ({root / row["path"] for row in before if row["kind"] == "regular"}
                        if canonical_before is not None else None)
        package_roots = (local_package_roots(source, env, source_paths=source_paths)
                         if source_paths is not None else None)
        packages = set(package_roots) if package_roots is not None else local_package_names(source, env)
        fingerprint_options = ({"package_roots": package_roots, "source_paths": source_paths}
                               if package_roots is not None else {})
        output = create_fresh_directory(output, mode=0o700)
        request = {"schema": "taira.native-runtime-build.v1" if runtime else "taira.local-client-build.v2", "commit": args.expected_commit,
                   "tree": tree, "signer_fingerprint": args.expected_signer, "source_root": str(authority_source),
                   "source_mode": source_mode, "compiler_source_root": str(source),
                   "target_dir": str(target), "host": host, "profile": "release" if runtime else "dev", "jobs": "cargo-default",
                   "source_snapshot_sha256": hashlib.sha256(canonical_json_bytes(authority_before)).hexdigest(),
                   "compiler_tools": tools, "native_linker": linker, "command": command,
                   "environment_sha256": hashlib.sha256(canonical_json_bytes(env)).hexdigest(),
                   "release_qualified": False, "deployed": False}
        if runtime:
            request["qualified"] = False
        else:
            request["binary"] = binary
            request["package"] = CLIENT_BINARIES[binary][1]
        write_record(output / "request.json", request)

        def revalidate():
            revalidate_target()
            require(frozen_snapshot(authority_source, entries, target) == authority_before,
                    "captured source changed during " + subject + " build")
            if canonical_before is not None:
                require(canonical_source_snapshot(root, args.expected_commit, entries) == before,
                        "canonical compiler source changed during " + subject + " build")
            require(preparation_native_linker("system") == linker,
                    "native linker changed during " + subject + " build")
            require([{"name": row["name"], **verify_tool(Path(row["path"]), row["sha256"])}
                     for row in tools] == tools, "Rust toolchain changed during " + subject + " build")

        with preparation_lock(output) as output_fd:
            admit_source_fingerprints(source, target, host, packages, **fingerprint_options)
            revalidate()
            log = output / "cargo.jsonl"
            run_build(source, command, env, log, lock_fd=output_fd, lane_lock_fd=source_fd,
                      mode_lock_fd=mode_fd, label="native runtime build" if runtime else "native " + binary + " build")
            with source_fingerprints(source, target, host, packages, repair=False, **fingerprint_options):
                revalidate()
                if runtime:
                    emission = native_runtime_artifact_emissions(log, source, target, host)
                    artifact = capture_native_runtime(target, output, host, revalidate=revalidate)
                else:
                    emission = client_artifact_emission(log, source, target, host, binary)
                    artifact = capture_client_artifact(target, output, host, binary, revalidate=revalidate)
                revalidate()
            result = {**request, "source_unchanged": True, "toolchain_unchanged": True,
                      "cargo_emissions" if runtime else "cargo_emission": emission,
                      "artifacts" if runtime else "artifact": artifact}
            freeze(log)
            write_record(output / "result.json", result)
            freeze(output, directory=True)
            return result


@contextlib.contextmanager
def retained_native_target(target: Path):
    """Hold the original warm native lane while its legitimate contents change."""
    descriptor = os.open(target, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        original = os.fstat(descriptor)
        fields = ("st_dev", "st_ino", "st_mode", "st_uid", "st_gid")
        def revalidate():
            real_path(target)
            opened, named = os.fstat(descriptor), target.lstat()
            require(stat.S_ISDIR(original.st_mode) and original.st_uid == os.geteuid()
                    and not original.st_mode & 0o022
                    and all(getattr(info, field) == getattr(original, field)
                            for info in (opened, named) for field in fields),
                    "native Cargo lane custody changed")
        revalidate()
        yield revalidate
        revalidate()
    finally:
        os.close(descriptor)


def prepare_client(args: argparse.Namespace) -> dict[str, object]:
    """Build an ordinary public client from signed source, without release authority."""
    return prepare_native_build(args, runtime=False)


def prepare_native_runtime(args: argparse.Namespace) -> dict[str, object]:
    """Build one same-source native runtime package, without deploying or qualifying it."""
    return prepare_native_build(args, runtime=True)


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    commands = result.add_subparsers(dest="command", required=True)
    for name in ("check", "prepare"):
        command = commands.add_parser(name)
        command.add_argument("--repo-root", type=Path, default=Path(__file__).resolve().parents[1])
        command.add_argument("--target-dir", type=Path, help="existing warm Cargo lane (check: sibling routine lane; prepare: repo target/)")
        if name == "check":
            command.add_argument("--native-check-scope", choices=("basic", "full"), default="basic",
                                 help="optional development diagnostics: basic regressions (default) or full census; neither is a preparation or deployment prerequisite")
            command.add_argument("--session-dir", type=Path,
                                 help="fresh private directory for a detached diagnostic; use check-status for its durable result")
            command.add_argument("--native-linker", choices=("system", "llvm"), default=default_development_linker(),
                                 help="development only: LLVM 18 by default on Linux (clang-18/lld-18 required), system on macOS; explicit system selects the diagnostic fallback; changing selection rebuilds Cargo dependencies")
            command.add_argument("--focus-regression", action="append", metavar="HARNESS=EXACT_TEST",
                                 help="development diagnostic: run selected portable ownership targets first, then mandatory configuration and remaining explicit harnesses; not qualification")
        if name == "prepare":
            command.set_defaults(native_check_scope="build-only")
            command.add_argument("--source-mode", choices=("captured", "canonical-checkout"), default="captured",
                                 help="compiler input: immutable capture (default), or the exact clean signed HEAD in repo-root; capture remains authority evidence")
            command.add_argument("--native-linker", choices=("system", "llvm"), default=default_development_linker(),
                                 help="pinned native build linker: LLVM 18 by default on Linux; system Apple ld on macOS; separate from shipping Zig")
            command.add_argument("--expected-commit", required=True)
            command.add_argument("--expected-signer", required=True, help="independently reviewed signing-key fingerprint")
            command.add_argument("--output-dir", type=Path, required=True)
            command.add_argument("--zig", type=Path, required=True, help="absolute real Zig executable")
            command.add_argument("--zig-sha256", required=True)
            command.add_argument("--cargo-zigbuild", type=Path, required=True, help="absolute real cargo-zigbuild executable")
            command.add_argument("--cargo-zigbuild-sha256", required=True)
    client = commands.add_parser("prepare-client", help="build exactly one ordinary macOS client from signed source")
    client.add_argument("--repo-root", type=Path, default=Path(__file__).resolve().parents[1])
    client.add_argument("--source-mode", choices=("captured", "canonical-checkout"), default="captured",
                        help="compiler input: immutable capture (default), or the exact clean signed optimizations HEAD in repo-root; capture remains authority evidence")
    client.add_argument("--expected-commit", required=True)
    client.add_argument("--expected-signer", required=True)
    client.add_argument("--bin", required=True, choices=tuple(CLIENT_BINARIES),
                        help="select only iroha CLI or Musubi; validator binaries are never selected")
    client.add_argument("--output-dir", type=Path, required=True,
                        help="fresh retained observation directory; retries reuse the fixed client Cargo lane")
    runtime = commands.add_parser("prepare-native-runtime", help="build same-source native macOS iroha, Kagami and iroha3d")
    runtime.add_argument("--repo-root", type=Path, default=Path(__file__).resolve().parents[1])
    runtime.add_argument("--source-mode", choices=("captured", "canonical-checkout"), default="captured",
                         help="compiler input: immutable capture (default), or the exact clean signed optimizations HEAD in repo-root; capture remains authority evidence")
    runtime.add_argument("--expected-commit", required=True)
    runtime.add_argument("--expected-signer", required=True, help="independently reviewed signing-key fingerprint")
    runtime.add_argument("--output-dir", type=Path, required=True,
                         help="fresh retained observation directory; safely create/reuse the fixed native runtime Cargo lane")
    status = commands.add_parser("check-status", help="read a background diagnostic without starting work")
    status.add_argument("--session-dir", type=Path, required=True)
    worker = commands.add_parser("_check-runner", help=argparse.SUPPRESS)
    worker.add_argument("--session-dir", type=Path, required=True)
    worker.add_argument("--session-fd", type=int, required=True)
    return result


def main() -> int:
    args = parser().parse_args()
    try:
        require(sys.platform in {"darwin", "linux"}, "Taira preparation requires macOS or Linux")
        if args.command == "_check-runner":
            return run_development_check_session(args.session_dir, args.session_fd)
        if args.command == "check-status":
            status = development_check_status(args.session_dir)
            print(canonical_json_bytes(status).decode("utf-8"), flush=True)
            return {"passed": 0, "running": 2, "failed": 1, "incomplete": 1}[status["state"]]
        if args.command == "prepare-client":
            result = prepare_client(args)
            print(f"[taira-client] built {result['commit']}: {args.output_dir / 'result.json'}", flush=True)
            return 0
        if args.command == "prepare-native-runtime":
            result = prepare_native_runtime(args)
            print(f"[taira-native-runtime] built {result['commit']}: {args.output_dir / 'result.json'}; unqualified, undeployed", flush=True)
            return 0
        if args.command == "check" and args.session_dir is not None:
            session = start_development_check(args, dict(os.environ))
            print(f"[taira-check] started diagnostic: {session}; inspect with check-status; not release-qualified", flush=True)
        elif args.command == "check":
            options = {"native_check_scope": args.native_check_scope, "native_linker": args.native_linker}
            if args.focus_regression is not None:
                options["focused_regressions"] = tuple(args.focus_regression)
            development_check(args.repo_root, args.target_dir, dict(os.environ), **options)
        else:
            args.target_dir = args.target_dir or args.repo_root / "target"
            prepared = prepare(args)
            print(f"[taira-release] prepared {prepared['commit']}: {args.output_dir / 'result.json'}", flush=True)
    except (PrepareError, ReleaseArtifactError, OSError, ValueError, subprocess.SubprocessError) as error:
        print(f"[taira-release] FAIL: {error}", file=sys.stderr, flush=True)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
