#!/usr/bin/env python3
"""Freeze the authenticated, no-skip ABI-31 Swift privacy lane."""

from __future__ import annotations

import hashlib
import os
import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]


def read(relative: str) -> str:
    """Read one UTF-8 repository file."""

    return (REPO_ROOT / relative).read_text(encoding="utf-8")


def isolated_python312() -> str:
    """Find the canonical Python required by Apple release consumers."""

    candidates = (
        sys.executable,
        "/opt/homebrew/opt/python@3.12/bin/python3.12",
        "/opt/homebrew/bin/python3.12",
        "/usr/local/opt/python@3.12/bin/python3.12",
        "/usr/local/bin/python3.12",
        "/usr/bin/python3.12",
    )
    for candidate in candidates:
        try:
            executable = Path(candidate).resolve(strict=True)
        except (OSError, RuntimeError):
            continue
        if not executable.is_file() or not os.access(executable, os.X_OK):
            continue
        result = subprocess.run(
            [str(executable), "-I", "-S", "-B", "-c",
             "import sys; raise SystemExit(sys.version_info[:2] != (3, 12) "
             "or not sys.flags.isolated)"],
            capture_output=True, text=True, check=False,
        )
        if result.returncode == 0:
            return str(executable)
    raise AssertionError("isolated Python 3.12 is required for Apple release checks")


def workflow_job(source: str, name: str) -> str:
    """Return one top-level workflow job block."""

    match = re.search(
        rf"(?ms)^  {re.escape(name)}:\n.*?(?=^  [A-Za-z0-9_-]+:\n|\Z)",
        source,
    )
    if match is None:
        raise AssertionError(f"missing workflow job: {name}")
    return match.group(0)


def make_bridge_fixture(base: Path) -> tuple[Path, dict[str, str], Path, Path]:
    """Run the real Make target with inert builder and checksum executables."""

    root, tools = base / "repo with spaces", base / "tools"
    (root / "scripts").mkdir(parents=True)
    tools.mkdir()
    (root / "Makefile").write_text(read("Makefile"), encoding="utf-8")
    (root / "Cargo.lock").write_text("source graph must not be selected implicitly\n")
    (root / "scripts/build_norito_xcframework.sh").write_text(
        'printf \'%s\\0\' "$@" > "$BRIDGE_TEST_BUILDER_LOG"\n'
        'exit "${BRIDGE_TEST_BUILDER_STATUS:-0}"\n',
        encoding="utf-8",
    )
    swift = tools / "swift"
    swift.write_text(
        '#!/bin/sh\n'
        'printf \'%s\\0\' "$@" > "$BRIDGE_TEST_CHECKSUM_LOG"\n',
        encoding="utf-8",
    )
    swift.chmod(0o755)
    selected_lock = base / "external selected graph.lock"
    selected_lock.write_bytes(b"reviewed external graph\n")
    selected_lock.chmod(0o400)
    builder_log, checksum_log = base / "builder-call", base / "checksum-call"
    environment = {
        "PATH": f"{tools}:/usr/bin:/bin",
        "SOURCE_DATE_EPOCH": "1730000000",
        "NORITO_BRIDGE_OUT_DIR": str(base / "external artifact"),
        "NORITO_BRIDGE_BUILD_DIR": str(base / "external build"),
        "NORITO_BRIDGE_ARCHIVE_OUTPUT": str(base / "release output.zip"),
        "MOBILE_SDK_CARGO_LOCKFILE": str(selected_lock),
        "BRIDGE_TEST_BUILDER_LOG": str(builder_log),
        "BRIDGE_TEST_CHECKSUM_LOG": str(checksum_log),
    }
    return root, environment, builder_log, checksum_log


class PrivacySwiftNativeContractTests(unittest.TestCase):
    """Guard the release Swift tests against native capability skips."""

    def test_native_archive_frameworks_reach_every_apple_consumer(self) -> None:
        builder = read("scripts/build_norito_xcframework.sh")
        swift_package = read("IrohaSwift/Package.swift")
        archive_manifest = read("scripts/fixtures/swift_release_consumers/archive/Package.swift")
        frameworks = ("Foundation", "Security", "Metal", "CoreGraphics", "Accelerate")
        for framework in frameworks:
            with self.subTest(framework=framework):
                self.assertIn(f"-framework {framework}", builder)
                self.assertIn(
                    f'.linkedFramework("{framework}", .when(platforms: [.iOS, .macOS]))',
                    swift_package,
                )
                self.assertIn(
                    f'.linkedFramework("{framework}", .when(platforms: [.iOS, .macOS]))',
                    archive_manifest,
                )

    def test_swift_release_test_inventory_has_no_runtime_skip(self) -> None:
        test_roots = (
            REPO_ROOT / "IrohaSwift" / "Tests",
            REPO_ROOT / "examples" / "ios" / "NoritoDemo" / "Tests",
        )
        test_sources = [
            path
            for root in test_roots
            for path in sorted(root.rglob("*.swift"))
        ]
        self.assertTrue(test_sources, "Swift release test inventory is empty")
        for path in test_sources:
            relative = path.relative_to(REPO_ROOT)
            self.assertNotIn("XCTSkip", path.read_text(encoding="utf-8"), relative)
        parity = read(
            "IrohaSwift/Tests/IrohaSwiftTests/SorafsOrchestratorParityTests.swift"
        )
        self.assertIn(
            'guard NoritoNativeBridge.shared.isAvailable else {',
            parity,
        )
        self.assertIn(
            'XCTFail("ABI-31 NoritoBridge is required on this platform")',
            parity,
        )
        for retired in (
            "SorafsBridgeBootstrap",
            "dlopen(",
            "dlsym(",
            '"cargo", "build"',
            "unzipArchive",
            "NoritoBridge.xcframework.zip",
            "libconnect_norito_bridge.dylib",
            "swift-sorafs-bridge",
        ):
            self.assertNotIn(retired, parity)

    def test_swift_runner_reauthenticates_external_apple_artifact(self) -> None:
        source = read("ci/check_privacy_swift_sdk.sh")
        for marker in (
            '"$(uname -s)" != "Darwin"',
            '"${MOBILE_SDK_REQUIRE_EXTERNAL_APPLE_ARTIFACT:-}" != "1"',
            "MOBILE_SDK_APPLE_ARTIFACT_DIR",
            "MOBILE_SDK_SWIFT_SCRATCH_DIR",
            "MOBILE_SDK_PYTHON_BINARY",
            "scripts/check_mobile_sdk_artifacts.sh",
            '--apple-only',
            "SorafsOrchestratorParityTests.swift",
            "--disable-automatic-resolution",
            '--scratch-path "${SWIFT_SCRATCH_DIRECTORY}"',
        ):
            self.assertIn(marker, source)
        self.assertLess(
            source.index('bash "${APPLE_ARTIFACT_CHECKER}" --apple-only'),
            source.index('"${SWIFT_BIN}" test'),
        )
        self.assertNotIn("external-lock requalification", source)
        for invocation in (
            'DEVELOPER_DIR="$(xcode-select -p)"',
            "xcodebuild -version",
            'bash "${APPLE_ARTIFACT_CHECKER}" --apple-only',
            '"${SWIFTC_BIN}" --version',
            '"${SWIFT_BIN}" test',
        ):
            self.assertIn(invocation, source)

    def test_swift_builder_binds_the_canonical_external_graph_snapshot(self) -> None:
        source = read("scripts/build_norito_xcframework.sh")
        for marker in (
            'CARGO_LOCKFILE=""',
            '--lockfile-path is required; no implicit Cargo.lock selection',
            '"$CARGO_LOCKFILE" != "$ROOT_DIR/Cargo.lock"',
            'source "$CARGO_GRAPH_OWNER"',
            '"$PRIVACY_SDK_CANONICAL_CARGO_LOCK_SHA256"',
            'Privacy production builds require an explicit external canonical graph snapshot',
            '--manifest-path "$ROOT_DIR/Cargo.toml"',
        ):
            self.assertIn(marker, source)
        # This name is a release-corridor sentinel for the local-integration
        # rejection only; it must never select the builder's Cargo graph.
        release_lock_name = "IROHA_PRIVACY_RELEASE_CARGO_LOCKFILE_PATH"
        self.assertEqual(source.count(release_lock_name), 1)
        self.assertIn(
            '|| -n "${IROHA_PRIVACY_RELEASE_CARGO_LOCKFILE_PATH+x}"',
            source,
        )
        lock_selection = source[
            source.index('CARGO_LOCKFILE=""'):source.index('CI_HANDOFF_DIR=')
        ]
        self.assertNotIn(release_lock_name, lock_selection)
        fixture = read("scripts/tests/mobile_sdk_build_source_seal_test.sh")
        self.assertIn('"$root/ci/privacy_sdk_cargo_lockfile.sh"', fixture)
        self.assertIn("external Cargo lock does not match the canonical reviewed graph", fixture)
        readme = read("IrohaSwift/README.md")
        self.assertNotIn('--lockfile-path "$PWD/Cargo.lock" --privacy-production-enabled', readme)
        self.assertIn("/absolute/non-symlink/path/to/reviewed-release-lock/Cargo.lock", readme)
        self.assertNotIn("export RUSTC_BOOTSTRAP=", readme)
        self.assertNotIn("build\nan opt-in Apple artifact", readme)
        self.assertIn("Every bridge build includes mandatory privacy support", readme)
        self.assertIn("stock Rust 1.93.1", readme)
        self.assertIn("unset RUSTC_BOOTSTRAP", readme)
        self.assertIn('bridge_local="$PWD/target/norito-bridge-local"', readme)
        self.assertIn('--lockfile-path "$PWD/Cargo.lock" --local-integration --allow-dirty-source', readme)

    def test_privacy_builder_rejects_root_selection_with_equal_graph_digest(self) -> None:
        source = read("scripts/build_norito_xcframework.sh")
        fragment = source[source.index('source "$CARGO_GRAPH_OWNER"'):source.index('assert_selected_cargo_lock()')]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            owner = root / "owner.sh"
            owner.write_text('readonly PRIVACY_SDK_CANONICAL_CARGO_LOCK_SHA256="' + ("a" * 64) + '"\n')
            # Privacy is mandatory. Only the explicit local integration corridor
            # admits the source-root lock; a retired feature value cannot do so.
            for privacy, local, selected, digest, error in (
                ("1", "0", root / "Cargo.lock", "a" * 64, "explicit external canonical graph snapshot"),
                ("1", "0", root.parent / "snapshot/Cargo.lock", "a" * 64, None),
                ("0", "0", root / "Cargo.lock", "a" * 64, "explicit external canonical graph snapshot"),
                ("1", "1", root / "Cargo.lock", "a" * 64, None),
                ("0", "1", root / "Cargo.lock", "a" * 64, None),
                ("1", "0", root.parent / "snapshot/Cargo.lock", "b" * 64, "External Cargo.lock must match the canonical reviewed graph"),
            ):
                with self.subTest(privacy=privacy, local=local, selected=selected, digest=digest):
                    environment = dict(os.environ, ROOT_DIR=str(root), CARGO_GRAPH_OWNER=str(owner), PRIVACY_PRODUCTION_ENABLED=privacy, LOCAL_INTEGRATION=local, CARGO_LOCKFILE=str(selected), CARGO_LOCK_SHA256_START=digest)
                    result = subprocess.run(["bash", "-c", "set -euo pipefail\n" + fragment], env=environment, text=True, capture_output=True)
                    self.assertEqual(result.returncode == 0, error is None, result.stderr)
                    if error is not None:
                        self.assertIn(error, result.stderr)

    def test_privacy_shell_lock_reader_requires_readonly_equal_bytes(self) -> None:
        source = read("scripts/build_norito_xcframework.sh")
        fragment = source[source.index("selected_cargo_lock_sha256() {"):source.index("CARGO_LOCK_SHA256_START=")]
        command = 'run_isolated_python() { "$TEST_PYTHON_BINARY" -I -S -B "$@"; }\n' + fragment + "\nselected_cargo_lock_sha256\n"
        with tempfile.TemporaryDirectory() as directory:
            fixture = Path(directory).resolve()
            root = fixture / "source"
            (root / "ci").mkdir(parents=True)
            lock_bytes = (REPO_ROOT / "Cargo.lock").read_bytes()
            digest = hashlib.sha256(lock_bytes).hexdigest()
            root_lock = root / "Cargo.lock"
            root_lock.write_bytes(lock_bytes)
            (root / "ci/privacy_sdk_cargo_lockfile.sh").write_text(
                'readonly PRIVACY_SDK_CANONICAL_CARGO_LOCK_SHA256=\\\n'
                f'"{digest}"\n',
                encoding="utf-8",
            )
            selected = fixture / "Cargo.lock"
            selected.write_bytes(lock_bytes)
            for privacy, local, path, mode, error in (
                ("1", "0", selected, 0o600, "must be read-only"),
                ("0", "0", selected, 0o600, "must be read-only"),
                ("1", "0", selected, 0o400, None),
                ("0", "0", selected, 0o400, None),
                ("1", "1", root_lock, 0o600, None),
                ("0", "1", root_lock, 0o600, None),
                ("1", "1", root_lock, 0o400, None),
                ("1", "1", selected, 0o400, "local integration requires the explicitly selected root Cargo.lock"),
            ):
                with self.subTest(privacy=privacy, local=local, path=path, mode=oct(mode)):
                    path.chmod(mode)
                    environment = dict(os.environ, TEST_PYTHON_BINARY=sys.executable, SOURCE_SEAL_SCRIPT=str(REPO_ROOT / "scripts/norito_bridge_source_seal.py"), CARGO_LOCKFILE=str(path), PRIVACY_PRODUCTION_ENABLED=privacy, LOCAL_INTEGRATION=local, ROOT_DIR=str(root))
                    result = subprocess.run(["bash", "-c", "set -euo pipefail\n" + command], env=environment, text=True, capture_output=True)
                    self.assertEqual(result.returncode == 0, error is None, result.stderr)
                    if error is None:
                        self.assertEqual(result.stdout.strip(), digest)
                    else:
                        self.assertIn(error, result.stderr)
            for mutated, error in (
                (selected, "external Cargo lock does not match the canonical reviewed graph"),
                (root_lock, "root source Cargo lock does not match the canonical reviewed graph"),
            ):
                with self.subTest(mutated=mutated):
                    mutated.chmod(0o600)
                    mutated.write_bytes(lock_bytes + b"\n# unreviewed graph\n")
                    mutated.chmod(0o400)
                    environment = dict(os.environ, TEST_PYTHON_BINARY=sys.executable, SOURCE_SEAL_SCRIPT=str(REPO_ROOT / "scripts/norito_bridge_source_seal.py"), CARGO_LOCKFILE=str(selected), LOCAL_INTEGRATION="0", ROOT_DIR=str(root))
                    result = subprocess.run(["bash", "-c", "set -euo pipefail\n" + command], env=environment, text=True, capture_output=True)
                    self.assertNotEqual(result.returncode, 0, result.stdout)
                    self.assertIn(error, result.stderr)
                    mutated.chmod(0o600)
                    mutated.write_bytes(lock_bytes)
                    mutated.chmod(0o400)
            self.assertEqual(selected.read_bytes(), lock_bytes)
            self.assertEqual(root_lock.read_bytes(), lock_bytes)

    def test_builder_requires_one_explicit_lock_argument_without_environment_alias(self) -> None:
        source = read("scripts/build_norito_xcframework.sh")
        fragment = source[source.index('BRIDGE_VERSION=""'):source.index('CI_HANDOFF_DIR=')]
        fragment += '\nprintf "%s" "$CARGO_LOCKFILE"\n'
        for arguments, valid in (
            ([], False),
            (["--lockfile-path"], False),
            (["--lockfile-path", ""], False),
            (["--lockfile-path", "/explicit root/Cargo.lock"], True),
            (["--lockfile-path", "/reviewed external/Cargo.lock"], True),
            (["--lockfile-path", "/one/Cargo.lock", "--lockfile-path", "/two/Cargo.lock"], False),
        ):
            with self.subTest(arguments=arguments):
                result = subprocess.run(
                    ["/bin/bash", "-euc", fragment, "build-lock-parser", *arguments],
                    env={"PATH": "/usr/bin:/bin", "IROHA_PRIVACY_RELEASE_CARGO_LOCKFILE_PATH": "/ignored/alias.lock"},
                    capture_output=True, text=True, check=False,
                )
                self.assertEqual(result.returncode == 0, valid, result.stderr)
                if valid:
                    self.assertEqual(result.stdout.strip(), arguments[1])
                else:
                    self.assertIn("--lockfile-path", result.stderr)

    def test_all_apple_consumers_reject_missing_selected_lock_before_artifact_access(self) -> None:
        python = isolated_python312()
        commands = [
            [python, "-I", "-S", "-B", "scripts/validate_norito_bridge_xcframework.py",
             "--root", str(REPO_ROOT), "--xcframework", "/absent/framework", "--manifest", "/absent/manifest",
             "--manifest-link", "/absent/link", "--expected-link-target", "NoritoBridge.xcframework/NoritoBridge.artifacts.json"],
            [python, "-I", "-S", "-B", "scripts/update_norito_bridge_swift_pins.py",
             "--root", str(REPO_ROOT), "--artifact-dir", "/absent/artifacts", "--check"],
            [python, "-I", "-S", "-B", "scripts/archive_norito_xcframework.py",
             "--xcframework", "/absent/framework", "--output", "/absent/output", "--scratch-dir", "/absent/scratch"],
            ["/bin/bash", "scripts/check_mobile_sdk_artifacts.sh", "--root", str(REPO_ROOT), "--apple-only"],
            ["/bin/bash", "scripts/package_mobile_sdk_artifacts.sh", "--root", str(REPO_ROOT), "--apple"],
        ]
        for command in commands:
            with self.subTest(command=command):
                result = subprocess.run(
                    command, cwd=REPO_ROOT,
                    env={"PATH": "/usr/bin:/bin", "MOBILE_SDK_PYTHON_BINARY": python},
                    capture_output=True, text=True, check=False,
                )
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("--lockfile-path", result.stderr)
                self.assertNotIn("Traceback", result.stderr)

    def test_all_shipped_apple_callers_forward_their_explicit_lock(self) -> None:
        ordinary = {
            ".github/workflows/mobile_sdk_artifacts.yml": "$IROHA_PRIVACY_RELEASE_CARGO_LOCKFILE_PATH",
            ".github/workflows/sorafs-orchestrator-sdk.yml": "$IROHA_PRIVACY_RELEASE_CARGO_LOCKFILE_PATH",
            ".github/workflows/numeric_v1_sdk.yml": "$IROHA_PRIVACY_RELEASE_CARGO_LOCKFILE_PATH",
        }
        for path, selected_lock in ordinary.items():
            for line in read(path).splitlines():
                if ("run: scripts/build_norito_xcframework.sh" in line or
                    "scripts/check_mobile_sdk_artifacts.sh --apple-only" in line or
                    "run: bash scripts/package_mobile_sdk_artifacts.sh --apple " in line):
                    self.assertIn(f'--lockfile-path "{selected_lock}"', line, path)
        makefile = read("Makefile")
        self.assertIn('--lockfile-path "$$MOBILE_SDK_CARGO_LOCKFILE"', makefile)
        self.assertNotIn('--lockfile-path "$(CURDIR)/Cargo.lock"', makefile)
        self.assertIn('bash "${APPLE_ARTIFACT_CHECKER}" --apple-only --lockfile-path "${PRIVACY_RELEASE_CARGO_LOCK}"', read("ci/check_privacy_swift_sdk.sh"))
        android = read("kotlin/client-android/build.gradle.kts")
        self.assertEqual(android.count('"--lockfile-path",\n                tools.cargoLock.toString(),'), 2)

    def test_make_bridge_requires_selected_external_lock_before_builder(self) -> None:
        for selector in (None, ""):
            with self.subTest(selector=selector), tempfile.TemporaryDirectory() as temporary:
                root, environment, builder_log, checksum_log = make_bridge_fixture(
                    Path(temporary).resolve()
                )
                if selector is None:
                    environment.pop("MOBILE_SDK_CARGO_LOCKFILE")
                else:
                    environment["MOBILE_SDK_CARGO_LOCKFILE"] = selector
                result = subprocess.run(
                    ["/usr/bin/make", "bridge-xcframework"], cwd=root,
                    env=environment, capture_output=True, text=True, check=False,
                )
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("MOBILE_SDK_CARGO_LOCKFILE is required", result.stderr)
                self.assertFalse(builder_log.exists())
                self.assertFalse(checksum_log.exists())

    def test_make_bridge_forwards_selected_lock_and_archive_without_rewriting(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root, environment, builder_log, checksum_log = make_bridge_fixture(
                Path(temporary).resolve()
            )
            result = subprocess.run(
                ["/usr/bin/make", "bridge-xcframework"], cwd=root,
                env=environment, capture_output=True, text=True, check=False,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(
                builder_log.read_bytes().split(b"\0"),
                [b"--lockfile-path", os.fsencode(environment["MOBILE_SDK_CARGO_LOCKFILE"]),
                 b"--archive-output", os.fsencode(environment["NORITO_BRIDGE_ARCHIVE_OUTPUT"]), b""],
            )
            self.assertEqual(
                checksum_log.read_bytes().split(b"\0"),
                [b"package", b"compute-checksum",
                 os.fsencode(environment["NORITO_BRIDGE_ARCHIVE_OUTPUT"]), b""],
            )
            selected_lock = Path(environment["MOBILE_SDK_CARGO_LOCKFILE"])
            self.assertEqual(selected_lock.read_bytes(), b"reviewed external graph\n")
            self.assertEqual(selected_lock.stat().st_mode & 0o777, 0o400)

    def test_make_bridge_preserves_builder_lock_refusal_before_checksum(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root, environment, builder_log, checksum_log = make_bridge_fixture(
                Path(temporary).resolve()
            )
            environment["BRIDGE_TEST_BUILDER_STATUS"] = "19"
            result = subprocess.run(
                ["/usr/bin/make", "bridge-xcframework"], cwd=root,
                env=environment, capture_output=True, text=True, check=False,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertTrue(builder_log.exists())
            self.assertIn("Error 19", result.stderr)
            self.assertFalse(checksum_log.exists())

    def test_swift_authenticated_external_lock_allows_execution(self) -> None:
        source = read("ci/check_privacy_swift_sdk.sh")
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary).resolve()
            root, artifact, scratch, tools = (
                base / name for name in ("repo", "artifact", "scratch", "bin")
            )
            for directory in (root / "scripts", root / "ci", artifact, scratch, tools):
                directory.mkdir(parents=True)
            (artifact / "NoritoBridge.xcframework").mkdir()
            tracked, release, log = root / "Cargo.lock", base / "Cargo.lock", base / "calls"
            (root / "ci/privacy_sdk_cargo_lockfile.sh").write_text(
                'readonly PRIVACY_SDK_CANONICAL_CARGO_LOCK_SHA256=\\\n"' + ("a" * 64) + '"\n', encoding="utf-8",
            )
            tracked.write_text("tracked\n", encoding="utf-8")
            release.write_text("release\n", encoding="utf-8")
            fake_python = tools / "python"
            fake_python.write_text(
                "#!/usr/bin/env bash\n"
                'echo "' + ("a" * 64) + '"\n',
                encoding="utf-8",
            )
            (tools / "uname").write_text("#!/usr/bin/env bash\necho Darwin\n", encoding="utf-8")
            tool_stub = (
                '#!/usr/bin/env bash\necho "${0##*/}" >>"$PRIVACY_TEST_LOG"\n'
                '[[ "${0##*/}" == xcode-select ]] && echo /Applications/Xcode.app/Contents/Developer\n'
                'exit 0\n'
            )
            for name in ("xcode-select", "xcodebuild", "swiftc", "swift"):
                (tools / name).write_text(tool_stub, encoding="utf-8")
            (root / "scripts/check_mobile_sdk_artifacts.sh").write_text(
                '#!/usr/bin/env bash\necho artifact-checker >>"$PRIVACY_TEST_LOG"\n',
                encoding="utf-8",
            )
            for executable in (*tools.iterdir(), root / "scripts/check_mobile_sdk_artifacts.sh"):
                executable.chmod(0o700)
            environment = {
                **os.environ,
                "PATH": f"{tools}:{os.environ['PATH']}",
                "PRIVACY_TEST_LOG": str(log),
                "PRIVACY_SWIFT_SDK_ROOT": str(root),
                "PRIVACY_SWIFT_SDK_SWIFTC_BIN": str(tools / "swiftc"),
                "PRIVACY_SWIFT_SDK_SWIFT_BIN": str(tools / "swift"),
                "MOBILE_SDK_REQUIRE_EXTERNAL_APPLE_ARTIFACT": "1",
                "MOBILE_SDK_APPLE_ARTIFACT_DIR": str(artifact),
                "MOBILE_SDK_SWIFT_SCRATCH_DIR": str(scratch),
                "MOBILE_SDK_PYTHON_BINARY": str(fake_python),
                "IROHA_PRIVACY_RELEASE_CARGO_LOCKFILE_PATH": str(release),
            }
            gate = base / "gate.sh"
            gate.write_text(source, encoding="utf-8")
            result = subprocess.run(
                ["bash", str(gate)], env=environment, text=True, capture_output=True
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            calls = log.read_text(encoding="utf-8")
            self.assertIn("xcode-select", calls)
            self.assertIn("artifact-checker", calls)
            self.assertIn("swiftc", calls)
            self.assertIn("swift", calls)

            release.write_text("wrong release\n", encoding="utf-8")
            fake_python.write_text(
                "#!/usr/bin/env bash\n"
                f'[[ "${{!#}}" == "{tracked}" ]] && echo "' + ("a" * 64) + '" || echo "'
                + ("0" * 64)
                + '"\n',
                encoding="utf-8",
            )
            fake_python.chmod(0o700)
            log.unlink()
            result = subprocess.run(
                ["bash", str(gate)], env=environment, text=True, capture_output=True
            )
            self.assertEqual(result.returncode, 1)
            self.assertIn("external Cargo.lock does not match the canonical reviewed graph", result.stderr)
            self.assertFalse(log.exists(), "invalid lock allowed artifact/Xcode execution")

    def test_package_manifest_requires_the_external_artifact(self) -> None:
        source = read("IrohaSwift/Package.swift")
        for marker in (
            '"MOBILE_SDK_APPLE_ARTIFACT_DIR"',
            '"MOBILE_SDK_REQUIRE_EXTERNAL_APPLE_ARTIFACT"',
            "configuredArtifactDirectory == nil",
            "must be outside the reviewed Iroha source tree",
            "requiredBridgeAbiVersion = 31",
            '"NoritoBridge.artifacts.json"',
            'manifest["native_bridge_abi_version"]',
            "validateBridgeArtifact(at: bridgeAbsolutePath)",
        ):
            self.assertIn(marker, source)

    def test_retired_cocoapods_delivery_cannot_reenter_the_release_workflows(self) -> None:
        retired = (
            "IrohaSwift/IrohaSwift.podspec",
            "crates/connect_norito_bridge/NoritoBridge.podspec.template",
            "scripts/render_norito_bridge_podspec.py",
            "scripts/check_swift_pod_bridge.sh",
            "ci/check_swift_pod_bridge.sh",
        )
        for relative in retired:
            self.assertFalse((REPO_ROOT / relative).exists(), relative)
        for relative in (
            ".github/workflows/mobile_sdk_artifacts.yml",
            ".github/workflows/pr_privacy_sdk_guard.yml",
            ".github/workflows/sorafs-cli-release.yml",
        ):
            workflow = read(relative)
            for path in retired:
                self.assertNotIn(path, workflow, relative)
            self.assertNotIn("CocoaPods", workflow, relative)

    def test_swiftpm_archive_consumer_authenticates_before_compilation(self) -> None:
        workflow = read(".github/workflows/mobile_sdk_artifacts.yml")
        checker = workflow_job(workflow, "checker-self-test")
        apple = workflow_job(workflow, "apple-mobile-sdk")
        for trigger in (
            "scripts/validate_norito_bridge_archive.py",
            "scripts/tests/validate_norito_bridge_archive_test.py",
        ):
            self.assertIn(f'      - "{trigger}"', workflow)
            self.assertIn(trigger, checker)
        self.assertIn("scripts/validate_norito_bridge_archive.py", read("scripts/package_mobile_sdk_artifacts.sh"))
        for marker in (
            're.fullmatch(rb"(0|[1-9][0-9]*)\\.(0|[1-9][0-9]*)\\.(0|[1-9][0-9]*)\\n", raw)',
            'archive="$MOBILE_SDK_PACKAGE_OUT_DIR/NoritoBridge-v${bridge_version}.xcframework.zip"',
            '"$MOBILE_SDK_PYTHON_BINARY" -I -S -B scripts/validate_norito_bridge_archive.py',
            '--root "$GITHUB_WORKSPACE"',
            '--archive "$archive"',
            '--lockfile-path "$IROHA_PRIVACY_RELEASE_CARGO_LOCKFILE_PATH"',
            'NORITO_BRIDGE_SEAL_CARGO_HOME="${MOBILE_SDK_CARGO_HOME:-$HOME/.cargo}"',
            'NORITO_BRIDGE_SEAL_CARGO_INVOCATION_DIR="${MOBILE_SDK_CARGO_INVOCATION_DIR:-$GITHUB_WORKSPACE}"',
            'NORITO_BRIDGE_SEAL_CARGO_TARGET_DIR="$CARGO_TARGET_DIR"',
            'scripts/check_swift_release_consumers.py',
            '--archive-sha256 "$archive_sha256"',
            '--sdk-path "$GITHUB_WORKSPACE/IrohaSwift"',
            '--archive-scratch "$RUNNER_TEMP/norito-bridge-archive-consumer-build"',
            '--sdk-scratch "$RUNNER_TEMP/iroha-swift-sdk-release-consumer-build"',
        ):
            self.assertIn(marker, apple)
        self.assertLess(
            apple.index("name: Package Apple mobile SDK artifact"),
            apple.index('"$MOBILE_SDK_PYTHON_BINARY" -I -S -B scripts/validate_norito_bridge_archive.py'),
        )
        self.assertLess(
            apple.index('"$MOBILE_SDK_PYTHON_BINARY" -I -S -B scripts/validate_norito_bridge_archive.py'),
            apple.index('scripts/check_swift_release_consumers.py'),
        )
        for forbidden in ("--allow-dirty-source", "--local-integration", "--skip", "--clobber"):
            self.assertNotIn(forbidden, apple)

    def test_release_guidance_distinguishes_source_wiring_from_publication(self) -> None:
        guide = read("docs/norito_bridge_release.md")
        sources = (
            guide,
            read("IrohaSwift/README.md"),
            read("specs/sorafs_reference_sdk_plan.md"),
            read("specs/sdk/swift/index.md"),
            read("ci/README.md"),
        )
        for source in sources:
            self.assertRegex(source, r"SwiftPM|Swift Package Manager")
            for retired in (".podspec", "pod lib lint", "pod spec lint"):
                self.assertNotIn(retired, source)
            self.assertNotIn("offline consumer compilation", source.lower())
        self.assertIn("MOBILE_SDK_APPLE_ARTIFACT_DIR", guide)
        self.assertIn("Generated `dist/*`", guide)
        self.assertIn("only `dist/.gitkeep` belongs in Git", guide)
        self.assertNotIn("Commit the generated artifacts", guide)

    def test_workflow_builds_authenticates_and_tests_exact_apple_artifact(self) -> None:
        source = read(".github/workflows/pr_privacy_sdk_guard.yml")
        job = workflow_job(source, "privacy_swift_sdk_parse")
        for trigger in (
            ".github/workflows/mobile_sdk_artifacts.yml",
            "ci/README.md",
            "IrohaSwift/Package.swift",
            "IrohaSwift/VERSION",
            "IrohaSwift/Sources/IrohaSwift/NativeBridge.swift",
            "IrohaSwift/Tests/IrohaSwiftTests/NativeBridgeLoaderTests.swift",
            "scripts/tests/check_privacy_swift_native_contract_test.py",
            "scripts/archive_norito_xcframework.py",
            "scripts/build_norito_xcframework.sh",
            "scripts/check_mobile_sdk_artifact_pin_commit.py",
            "scripts/exec_with_file_lock.py",
            "scripts/norito_bridge_apple_slice_handoff.py",
            "scripts/norito_bridge_source_seal.py",
            "scripts/package_mobile_sdk_artifacts.sh",
            "scripts/run_mobile_hermetic_command.py",
            "scripts/validate_norito_bridge_archive.py",
            "scripts/tests/package_mobile_sdk_artifacts_test.py",
            "scripts/tests/validate_norito_bridge_archive_test.py",
            "scripts/tests/norito_bridge_apple_slice_handoff_test.py",
            "scripts/tests/norito_bridge_source_seal_test.py",
            "scripts/update_norito_bridge_swift_pins.py",
            "scripts/validate_norito_bridge_xcframework.py",
            "crates/connect_norito_bridge/RELEASE_NOTES.md",
            "docs/norito_bridge_release.md",
            "specs/sdk/swift/index.md",
            "specs/sorafs_reference_sdk_plan.md",
        ):
            self.assertIn(f'      - "{trigger}"', source)
        for marker in (
            "runs-on: macos-14",
            "actions/setup-python@a26af69be951a213d495a4c3e4e4022e16d87065",
            'python-version: "3.12"',
            "update-environment: false",
            "MOBILE_SDK_PYTHON_BINARY",
            '"${HOME}/.cargo/bin/rustup" toolchain install',
            '"1.93.1-aarch64-apple-darwin"',
            "aarch64-apple-ios-sim",
            "x86_64-apple-darwin",
            'cargo_path="$(rustup which --toolchain 1.93.1-aarch64-apple-darwin cargo)"',
            'env -u RUSTC_BOOTSTRAP "$cargo_path" fetch --locked --manifest-path "$GITHUB_WORKSPACE/Cargo.toml"',
            "MOBILE_SDK_APPLE_ARTIFACT_DIR",
            "MOBILE_SDK_REQUIRE_EXTERNAL_APPLE_ARTIFACT=1",
            "MOBILE_SDK_SWIFT_SCRATCH_DIR",
            "NORITO_BRIDGE_OUT_DIR",
            "NORITO_BRIDGE_BUILD_DIR",
            'chmod -R a-w "$GITHUB_WORKSPACE"',
            'scripts/build_norito_xcframework.sh --lockfile-path "$IROHA_PRIVACY_RELEASE_CARGO_LOCKFILE_PATH"',
            'scripts/check_mobile_sdk_artifacts.sh --apple-only --lockfile-path "$IROHA_PRIVACY_RELEASE_CARGO_LOCKFILE_PATH"',
            "python3 -I -B scripts/tests/check_privacy_swift_native_contract_test.py",
            "run: ci/check_privacy_swift_sdk.sh",
        ):
            self.assertIn(marker, job)
        for forbidden in (
            "--allow-dirty-source",
            "NORITO_BRIDGE_TEST_PREBUILT_SLICES",
            "MOBILE_SDK_SKIP_BINARY_INSPECTION",
            "NORITO_BRIDGE_PRESERVE_CARGO_TARGETS",
        ):
            self.assertNotIn(forbidden, job)


if __name__ == "__main__":
    unittest.main()
