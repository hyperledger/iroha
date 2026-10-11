#!/usr/bin/env python3
"""Race and failure-safety tests for the mobile SDK package publisher."""

from __future__ import annotations

import fcntl
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import textwrap
import unittest
from unittest import mock
import zipfile


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
PACKAGE_OWNER = REPOSITORY_ROOT / "scripts/package_mobile_sdk_artifacts.sh"
LOCK_RUNNER = REPOSITORY_ROOT / "scripts/exec_with_file_lock.py"
ARCHIVE_VALIDATOR = REPOSITORY_ROOT / "scripts/validate_norito_bridge_archive.py"
VERSION = "1.0.0"


def run_isolated_package_case(
    case: unittest.TestCase, result: unittest.TestResult | None = None
) -> unittest.TestResult:
    """Execute one real isolated case and report its outcome to the parent runner."""
    owns_result = result is None
    if result is None:
        result = case.defaultTestResult()
        result.startTestRun()
    result.startTest(case)
    try:
        selected = f"{type(case).__name__}.{case._testMethodName}"
        command = [sys.executable, "-I", "-S", "-B", str(Path(__file__).resolve()), selected]
        child = subprocess.run(
            command,
            cwd=REPOSITORY_ROOT,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )
        if child.returncode != 0 or "Ran 1 test" not in child.stdout:
            raise AssertionError(
                f"isolated mobile package case {selected} failed (exit {child.returncode}):\n"
                f"{child.stdout}"
            )
    except AssertionError:
        result.addFailure(case, sys.exc_info())
    except Exception:
        result.addError(case, sys.exc_info())
    else:
        result.addSuccess(case)
    finally:
        result.stopTest(case)
        if owns_result:
            result.stopTestRun()
    return result


class MobileSdkPackagePublisherTests(unittest.TestCase):
    def run(self, result: unittest.TestResult | None = None) -> unittest.TestResult:
        # Preserve each original case in a genuine isolated interpreter rather
        # than requiring the normally collected parent runner to be isolated.
        if sys.flags.isolated:
            return super().run(result)
        return run_isolated_package_case(self, result)

    def _assert_real_isolated_runtime(self) -> None:
        self.assertEqual(sys.version_info[:2], (3, 12))
        self.assertTrue(sys.flags.isolated)
        self.assertTrue(sys.flags.no_site)

    def _deliberate_isolated_failure(self) -> None:
        self.fail("isolated child assertion propagation probe")

    def setUp(self) -> None:
        if sys.version_info[:2] != (3, 12) or not sys.flags.isolated:
            self.fail("tests require isolated Python 3.12")
        self.temporary = tempfile.TemporaryDirectory(
            prefix="mobile-sdk-package-owner-test."
        )
        self.temporary_root = Path(self.temporary.name).resolve(strict=True)
        self.repository = self.temporary_root / "repo"
        self.artifacts = self.temporary_root / "android-artifacts"
        self.output = self.temporary_root / "package-output/mobile-sdk"
        self.output.parent.mkdir()
        self._write_fixture()
        graph_directory = self.temporary_root / "graph"
        graph_directory.mkdir()
        self.lockfile = graph_directory / "Cargo.lock"
        self.lockfile.write_bytes(b'version = 4\n\n[[package]]\nname = "mobile-package-fixture"\nversion = "0.0.0"\n')
        self.lockfile.chmod(0o400)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _write_fixture(self) -> None:
        scripts = self.repository / "scripts"
        scripts.mkdir(parents=True)
        package_owner = scripts / PACKAGE_OWNER.name
        shutil.copy2(PACKAGE_OWNER, package_owner)
        shutil.copy2(REPOSITORY_ROOT / "scripts/mobile_sdk_android_artifacts.py", scripts / "mobile_sdk_android_artifacts.py")
        shutil.copy2(REPOSITORY_ROOT / "scripts/mobile_sdk_android_package_inputs.py", scripts / "mobile_sdk_android_package_inputs.py")
        owner_source = package_owner.read_text(encoding="utf-8")
        publication = (
            'no_replace_flag = 0x4 if sys.platform == "darwin" else 0x1\n'
            "rename_with_flag(stage, final, no_replace_flag)"
        )
        fixture_publication = (
            'no_replace_flag = 0x4 if sys.platform == "darwin" else 0x1\n'
            'destination_race = final.parent / ".package-test-destination-race"\n'
            'stage_race = final.parent / ".package-test-stage-race"\n'
            "if destination_race.exists():\n"
            "    final.mkdir()\n"
            '    (final / "competitor.txt").write_bytes(b"late competitor\\n")\n'
            "elif stage_race.exists():\n"
            '    retained = stage.with_name(f"{stage.name}.owner-retained")\n'
            "    stage.rename(retained)\n"
            "    stage.mkdir()\n"
            '    (stage / "competitor.txt").write_bytes(b"late competitor\\n")\n'
            "rename_with_flag(stage, final, no_replace_flag)"
        )
        self.assertEqual(owner_source.count(publication), 1)
        package_owner.write_text(
            owner_source.replace(publication, fixture_publication),
            encoding="utf-8",
        )
        shutil.copy2(LOCK_RUNNER, scripts / LOCK_RUNNER.name)
        shutil.copy2(ARCHIVE_VALIDATOR, scripts / ARCHIVE_VALIDATOR.name)
        swift_root = self.repository / "IrohaSwift"
        swift_root.mkdir()
        (swift_root / "VERSION").write_text(f"{VERSION}\n", encoding="ascii")
        checker = scripts / "check_mobile_sdk_artifacts.sh"
        checker.write_text(
            textwrap.dedent(
                """\
                #!/usr/bin/env bash
                set -euo pipefail
                if [[ "${PACKAGE_TEST_MUTATE_AND_RESTORE_SOURCE:-0}" == "1" ]]; then
                  fixture_source="$MOBILE_SDK_ANDROID_ARTIFACT_DIR/gradle-build/iroha_kotlin_sdk/core-jvm/libs/core-jvm-1.0.0.jar"
                  fixture_original="$(cat "$fixture_source")"
                  printf 'temporary substituted source' > "$fixture_source"
                  printf '%s\\n' "$fixture_original" > "$fixture_source"
                fi
                if [[ "${PACKAGE_TEST_MUTATE_SOURCE_AFTER_VALIDATION:-0}" == "1" ]]; then
                  printf 'changed after validation' > "$MOBILE_SDK_ANDROID_ARTIFACT_DIR/gradle-build/iroha_kotlin_sdk/core-jvm/libs/core-jvm-1.0.0.jar"
                fi
                if [[ "${PACKAGE_TEST_CHECK_FAIL:-0}" == "1" ]]; then
                  echo "forced late package validation failure" >&2
                  exit 91
                fi
                """
            ),
            encoding="utf-8",
        )
        checker.chmod(0o755)

        gradle = self.artifacts / "gradle-build/iroha_kotlin_sdk"
        core_jar = gradle / f"core-jvm/libs/core-jvm-{VERSION}.jar"
        client = gradle / "client-android"
        aar = client / "outputs/aar/client-android-release.aar"
        native_root = client / "generated/jniLibs/production"
        provenance = (
            client
            / "generated/nativeProvenance/production/iroha/native-build-provenance-v1.json"
        )
        core_jar.parent.mkdir(parents=True)
        aar.parent.mkdir(parents=True)
        provenance.parent.mkdir(parents=True)
        core_jar.write_bytes(b"canonical core fixture\n")
        provenance_payload = json.dumps(
            {"privacy_production_enabled": True, "libraries": {
                abi: {"aar_path": f"jni/{abi}/libconnect_norito_bridge.so",
                      "bytes": len(f"canonical {abi} fixture\n".encode("ascii")),
                      "sha256": hashlib.sha256(f"canonical {abi} fixture\n".encode("ascii")).hexdigest()}
                for abi in ("arm64-v8a", "armeabi-v7a", "x86_64")}},
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8") + b"\n"
        provenance.write_bytes(provenance_payload)
        for abi in ("arm64-v8a", "armeabi-v7a", "x86_64"):
            library = native_root / abi / "libconnect_norito_bridge.so"
            library.parent.mkdir(parents=True)
            library.write_bytes(f"canonical {abi} fixture\n".encode("ascii"))
        with zipfile.ZipFile(aar, "w", compression=zipfile.ZIP_STORED) as archive:
            archive.writestr(
                "assets/iroha/native-build-provenance-v1.json",
                provenance_payload,
            )
            archive.writestr("AndroidManifest.xml", "<manifest />")
            archive.writestr("classes.jar", b"managed client fixture")
            for abi in ("arm64-v8a", "armeabi-v7a", "x86_64"):
                archive.writestr(f"jni/{abi}/libconnect_norito_bridge.so", (native_root / abi / "libconnect_norito_bridge.so").read_bytes())

        self._write_android_publications(VERSION)

    def _write_android_publications(self, version):
        gradle = self.artifacts / "gradle-build/iroha_kotlin_sdk"
        jar = next((gradle / "core-jvm/libs").glob("core-jvm-*.jar"))
        if jar.name != f"core-jvm-{version}.jar":
            jar.rename(jar.with_name(f"core-jvm-{version}.jar"))
        for module, dependency in [("core-jvm", ""), ("client-android", "core-jvm"),
                                   ("kagemusha-wallet-android", "client-android")]:
            packaging = "jar" if module == "core-jvm" else "aar"
            deps = (f"<dependencies><dependency><groupId>org.hyperledger.iroha.sdk</groupId>"
                    f"<artifactId>{dependency}</artifactId><version>{version}</version>"
                    "</dependency></dependencies>") if dependency else ""
            pom_text = (f'<project xmlns="http://maven.apache.org/POM/4.0.0"><modelVersion>4.0.0</modelVersion>'
                        f'<groupId>org.hyperledger.iroha.sdk</groupId><artifactId>{module}</artifactId>'
                        f'<version>{version}</version><packaging>{packaging}</packaging>{deps}</project>')
            pom = gradle / module / "publications/release/pom-default.xml"
            pom.parent.mkdir(parents=True, exist_ok=True)
            pom.write_text(pom_text)
            original = gradle / module / (f"libs/core-jvm-{version}.jar" if module == "core-jvm"
                                         else f"outputs/aar/{module}-release.aar")
            if module == "kagemusha-wallet-android":
                original.parent.mkdir(parents=True, exist_ok=True)
                with zipfile.ZipFile(original, "w") as archive:
                    archive.writestr("AndroidManifest.xml", "<manifest />")
                    archive.writestr("classes.jar", b"managed wallet fixture")
            directory = self.artifacts / "maven/org/hyperledger/iroha/sdk" / module / version
            directory.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(original, directory / f"{module}-{version}.{packaging}")
            (directory / f"{module}-{version}.pom").write_text(pom_text)
            variants = []
            for usage in ("java-api", "java-runtime"):
                attributes = {"org.gradle.category": "library", "org.gradle.dependency.bundling": "external",
                              "org.gradle.libraryelements": packaging, "org.gradle.usage": usage}
                if module == "core-jvm":
                    attributes["org.gradle.jvm.version"] = 8
                dependencies = ([{"group": "org.hyperledger.iroha.sdk", "module": dependency,
                                  "version": {"requires": version}}] if dependency else [])
                variants.append({"name": "apiElements" if usage == "java-api" else "runtimeElements",
                    "attributes": attributes, "dependencies": dependencies,
                    "files": [{"name": f"{module}-{version}.{packaging}", "url": f"{module}-{version}.{packaging}",
                               "size": original.stat().st_size, "sha256": hashlib.sha256(original.read_bytes()).hexdigest()}]})
            (directory / f"{module}-{version}.module").write_text(json.dumps({
                "formatVersion": "1.1", "component": {"group": "org.hyperledger.iroha.sdk", "module": module, "version": version},
                "variants": variants}))


    def _environment(self, **updates: str) -> dict[str, str]:
        environment = os.environ.copy()
        environment.pop("MOBILE_SDK_PACKAGE_LOCK_FDS", None)
        environment.pop("NORITO_BRIDGE_OUTPUT_LOCK_FD", None)
        environment.update(
            {
                "MOBILE_SDK_PYTHON_BINARY": str(
                    Path(sys.executable).resolve(strict=True)
                ),
                "MOBILE_SDK_ANDROID_ARTIFACT_DIR": str(self.artifacts),
                "MOBILE_SDK_PACKAGE_OUT_DIR": str(self.output),
            }
        )
        environment.update(updates)
        return environment

    def _package(
        self,
        *,
        mode: str = "android",
        version: str = VERSION,
        **updates: str,
    ) -> subprocess.CompletedProcess[str]:
        platform_arguments = [] if mode == "all" else [f"--{mode}"]
        return subprocess.run(
            [
                "/bin/bash",
                str(self.repository / "scripts/package_mobile_sdk_artifacts.sh"),
                "--lockfile-path", str(self.lockfile),
                "--root",
                str(self.repository),
                *platform_arguments,
                "--version",
                version,
            ],
            env=self._environment(**updates),
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )

    def _write_fake_apple_owner(self) -> dict[str, str]:
        artifact_root = self.temporary_root / "apple-artifacts"
        xcframework = artifact_root / "NoritoBridge.xcframework"
        xcframework.mkdir(parents=True)
        (xcframework / "Info.plist").write_bytes(b"canonical plist fixture\n")
        bridge_manifest = (
            json.dumps(
                {"schema_version": 1, "version": VERSION},
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
            + b"\n"
        )
        (artifact_root / "NoritoBridge.artifacts.json").write_bytes(bridge_manifest)
        (xcframework / "NoritoBridge.artifacts.json").write_bytes(bridge_manifest)
        owner = self.repository / "scripts/archive_norito_xcframework.py"
        owner.write_text(
            textwrap.dedent(
                """\
                import argparse
                import fcntl
                import os
                from pathlib import Path
                import stat
                import zipfile

                parser = argparse.ArgumentParser()
                parser.add_argument("--lockfile-path", required=True)
                parser.add_argument("--xcframework", required=True)
                parser.add_argument("--output", required=True)
                parser.add_argument("--scratch-dir", required=True)
                arguments = parser.parse_args()
                if Path(arguments.lockfile_path) != Path(__file__).resolve().parents[2] / "graph/Cargo.lock":
                    raise SystemExit("selected lock was not forwarded to the archive owner")
                source = Path(arguments.xcframework)
                output = Path(arguments.output)
                scratch = Path(arguments.scratch_dir)
                if scratch != output.parent.parent:
                    raise SystemExit("Apple archive scratch directory was not external")
                required_seal_environment = {
                    "NORITO_BRIDGE_SEAL_HOME",
                    "NORITO_BRIDGE_SEAL_CARGO_HOME",
                    "NORITO_BRIDGE_SEAL_RUSTUP_HOME",
                    "NORITO_BRIDGE_SEAL_TMPDIR",
                    "NORITO_BRIDGE_SEAL_CARGO_TARGET_DIR",
                    "NORITO_BRIDGE_SEAL_CARGO",
                    "NORITO_BRIDGE_SEAL_RUSTC",
                    "NORITO_BRIDGE_SEAL_RUSTDOC",
                    "NORITO_BRIDGE_SEAL_RUSTUP",
                    "NORITO_BRIDGE_SEAL_DEVELOPER_DIR",
                }
                missing = sorted(required_seal_environment - os.environ.keys())
                if missing:
                    raise SystemExit(f"Apple seal environment was not forwarded: {missing}")
                for name in required_seal_environment:
                    value = Path(os.environ[name])
                    if not value.is_absolute() or not value.exists():
                        raise SystemExit(f"Apple seal environment is invalid: {name}")
                raw_descriptor = os.environ.get("NORITO_BRIDGE_OUTPUT_LOCK_FD", "")
                if not raw_descriptor.isdecimal():
                    raise SystemExit("Apple source lock descriptor was not forwarded")
                descriptor = int(raw_descriptor, 10)
                descriptor_metadata = os.fstat(descriptor)
                path_metadata = (source.parent / ".NoritoBridge.publish.lockfile").lstat()
                if (
                    not stat.S_ISREG(descriptor_metadata.st_mode)
                    or (descriptor_metadata.st_dev, descriptor_metadata.st_ino)
                    != (path_metadata.st_dev, path_metadata.st_ino)
                ):
                    raise SystemExit("Apple source lock descriptor does not match its path")
                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
                if os.environ.get("SOURCE_DATE_EPOCH") != "1700000000":
                    raise SystemExit("SOURCE_DATE_EPOCH was not forwarded")
                output.parent.mkdir(parents=True, exist_ok=True)
                payload = (source.parent / "NoritoBridge.artifacts.json").read_bytes()
                with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_STORED) as archive:
                    archive.writestr(
                        "NoritoBridge.xcframework/NoritoBridge.artifacts.json",
                        payload,
                    )
                """
            ),
            encoding="utf-8",
        )
        # Package-publisher fixtures isolate native provenance/physical-tool
        # ownership; the generic ZIP bounds/extraction remain the real code.
        archive_fixture = owner.read_text(encoding="utf-8")
        owner.write_text(
            "def _validate_native_binaries(snapshot, validator):\n"
            "    assert snapshot.name == 'NoritoBridge.xcframework'\n"
            "    assert (snapshot / 'NoritoBridge.artifacts.json').is_file()\n\n"
            "if __name__ == '__main__':\n" + textwrap.indent(archive_fixture, "    "),
            encoding="utf-8",
        )
        (self.repository / "scripts/validate_norito_bridge_xcframework.py").write_text(
            textwrap.dedent(
                """\
                import json
                import os
                from pathlib import Path

                def validate(**arguments):
                    root = arguments['root']
                    assert arguments['verify_repository_provenance'] is True
                    assert arguments['swift_loader'] == root / 'IrohaSwift/Sources/IrohaSwift/NativeBridge.swift'
                    assert arguments['lockfile_path'] == root.parent / 'graph/Cargo.lock'
                    assert arguments['expected_link_target'] == 'NoritoBridge.xcframework/NoritoBridge.artifacts.json'
                    assert os.readlink(arguments['manifest_link']) == arguments['expected_link_target']
                    return json.loads(arguments['manifest_path'].read_bytes())
                """
            ),
            encoding="utf-8",
        )
        seal_root = self.temporary_root / "apple-seal"
        directories = {
            "NORITO_BRIDGE_SEAL_HOME": seal_root / "home",
            "NORITO_BRIDGE_SEAL_CARGO_HOME": seal_root / "cargo-home",
            "NORITO_BRIDGE_SEAL_RUSTUP_HOME": seal_root / "rustup-home",
            "NORITO_BRIDGE_SEAL_TMPDIR": seal_root / "tmp",
            "NORITO_BRIDGE_SEAL_CARGO_TARGET_DIR": seal_root / "cargo-target",
            "NORITO_BRIDGE_SEAL_DEVELOPER_DIR": seal_root / "developer",
        }
        for directory in directories.values():
            directory.mkdir(parents=True)
        tools = {}
        tool_root = seal_root / "tools"
        tool_root.mkdir()
        for environment_name, filename in (
            ("NORITO_BRIDGE_SEAL_CARGO", "cargo"),
            ("NORITO_BRIDGE_SEAL_RUSTC", "rustc"),
            ("NORITO_BRIDGE_SEAL_RUSTDOC", "rustdoc"),
            ("NORITO_BRIDGE_SEAL_RUSTUP", "rustup"),
        ):
            tool = tool_root / filename
            tool.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
            tool.chmod(0o755)
            tools[environment_name] = tool
        return {
            name: str(path.resolve(strict=True))
            for name, path in {**directories, **tools}.items()
        } | {"MOBILE_SDK_APPLE_ARTIFACT_DIR": str(artifact_root)}

    def test_disabled_native_provenance_cannot_publish_a_package(self) -> None:
        client = self.artifacts / "gradle-build/iroha_kotlin_sdk/client-android"
        provenance = client / "generated/nativeProvenance/production/iroha/native-build-provenance-v1.json"
        provenance.write_text('{"privacy_production_enabled":false}\n')
        aar = client / "outputs/aar/client-android-release.aar"
        with zipfile.ZipFile(aar) as archive:
            originals = [(item, archive.read(item.filename)) for item in archive.infolist()]
        with zipfile.ZipFile(aar, "w") as archive:
            for item, original in originals:
                archive.writestr(item, provenance.read_bytes() if item.filename ==
                    "assets/iroha/native-build-provenance-v1.json" else original)
        self._write_android_publications(VERSION)
        result = self._package()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("mandatory privacy support", result.stderr)
        self.assertFalse(self.output.exists())
        # Startup rejection retains the failed stage as diagnostic DATA only.
        self.assertTrue(self._publish_stages())

    def _seed_previous_release(self) -> Path:
        self.output.mkdir(parents=True, exist_ok=True)
        sentinel = self.output / "last-good-release.txt"
        sentinel.write_text("keep the last good package\n", encoding="utf-8")
        return sentinel

    def _publish_stages(self) -> list[Path]:
        return [
            path
            for path in self.output.parent.glob(".mobile-sdk.publish.*")
            if path.is_dir()
        ]

    def _assert_no_publish_stage(self) -> None:
        self.assertEqual(self._publish_stages(), [])

    def _inject_extra_package_file(self) -> None:
        owner = self.repository / "scripts/package_mobile_sdk_artifacts.sh"
        source = owner.read_text(encoding="utf-8")
        marker = "# PACKAGE_TEST_BEFORE_STAGE_INVENTORY\n"
        self.assertEqual(source.count(marker), 1)
        owner.write_text(
            source.replace(
                marker,
                marker
                + '(stage / "unexpected.txt").write_text('
                + '"unexpected\\n", encoding="utf-8")\n',
                1,
            ),
            encoding="utf-8",
        )

    def test_held_parent_lock_rejects_before_creating_output(self) -> None:
        lock_path = self.output.parent / ".mobile-sdk.publish.lockfile"
        lock_path.parent.mkdir(parents=True, exist_ok=True)
        descriptor = os.open(lock_path, os.O_RDWR | os.O_CREAT, 0o600)
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            result = self._package()
        finally:
            os.close(descriptor)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("another process holds", result.stderr)
        self.assertFalse(self.output.exists())
        self._assert_no_publish_stage()

    def test_preexisting_destination_is_rejected_without_replacement(self) -> None:
        sentinel = self._seed_previous_release()
        result = self._package()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("must not already exist", result.stderr)
        self.assertEqual(sentinel.read_text(encoding="utf-8"), "keep the last good package\n")
        self._assert_no_publish_stage()

    def test_late_validation_failure_retains_stage_and_leaves_output_absent(self) -> None:
        result = self._package(PACKAGE_TEST_CHECK_FAIL="1")
        self.assertEqual(result.returncode, 91, result.stderr)
        self.assertIn("forced late package validation failure", result.stderr)
        self.assertFalse(self.output.exists())
        self.assertEqual(len(self._publish_stages()), 1)
        self.assertIn("retained failed package stage", result.stderr)

    def test_extra_package_file_is_rejected_before_publication(self) -> None:
        self._inject_extra_package_file()
        result = self._package()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(
            "package stage does not contain the exact android file set",
            result.stderr,
        )
        self.assertFalse(self.output.exists())

    def test_combined_package_extra_file_is_rejected_before_publication(self) -> None:
        self._inject_extra_package_file()
        seal_environment = self._write_fake_apple_owner()
        shutil.rmtree(self.artifacts / "maven")
        self._write_android_publications("pr-9-deadbeef")
        result = self._package(
            mode="all",
            version="pr-9-deadbeef",
            SOURCE_DATE_EPOCH="1700000000",
            **seal_environment,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(
            "package stage does not contain the exact all file set",
            result.stderr,
        )
        self.assertFalse(self.output.exists())

    def test_local_integration_provenance_is_rejected_after_external_copy(self) -> None:
        client = self.artifacts / "gradle-build/iroha_kotlin_sdk/client-android"
        provenance = client / "generated/nativeProvenance/production/iroha/native-build-provenance-v1.json"
        document = json.loads(provenance.read_text())
        document["artifact_scope"] = "local-integration"
        document["source_tree_dirty"] = False
        payload = (json.dumps(document) + "\n").encode()
        provenance.write_bytes(payload)
        aar = client / "outputs/aar/client-android-release.aar"
        with zipfile.ZipFile(aar) as archive:
            contents = {name: archive.read(name) for name in archive.namelist()}
        contents["assets/iroha/native-build-provenance-v1.json"] = payload
        with zipfile.ZipFile(aar, "w", compression=zipfile.ZIP_STORED) as archive:
            for name, value in contents.items():
                archive.writestr(name, value)
        shutil.copyfile(aar, self.artifacts / f"maven/org/hyperledger/iroha/sdk/client-android/{VERSION}/client-android-{VERSION}.aar")
        metadata = self.artifacts / f"maven/org/hyperledger/iroha/sdk/client-android/{VERSION}/client-android-{VERSION}.module"
        document = json.loads(metadata.read_text())
        for variant in document["variants"]:
            variant["files"][0].update(size=aar.stat().st_size, sha256=hashlib.sha256(aar.read_bytes()).hexdigest())
        metadata.write_text(json.dumps(document))
        result = self._package()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("diagnostic Android artifact scope", result.stderr)
        self.assertFalse(self.output.exists())

    def test_missing_wallet_maven_member_prevents_publication(self):
        (self.artifacts / f"maven/org/hyperledger/iroha/sdk/kagemusha-wallet-android/{VERSION}/kagemusha-wallet-android-{VERSION}.aar").unlink()
        result = self._package()
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(self.output.exists())

    def test_maven_client_substitution_prevents_publication(self):
        path = self.artifacts / f"maven/org/hyperledger/iroha/sdk/client-android/{VERSION}/client-android-{VERSION}.aar"
        path.write_bytes(b"foreign Maven client")
        result = self._package()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("differs from the selected canonical build", result.stderr)
        self.assertFalse(self.output.exists())

    def test_source_changed_after_native_validation_refuses_publication(self):
        result = self._package(PACKAGE_TEST_MUTATE_SOURCE_AFTER_VALIDATION="1")
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(self.output.exists())

    def test_source_mutation_and_restoration_refuses_original_identity_snapshot(self):
        result = self._package(PACKAGE_TEST_MUTATE_AND_RESTORE_SOURCE="1")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("package source identity differs", result.stderr)
        self.assertFalse(self.output.exists())

    def test_missing_armv7_generated_original_refuses_package(self):
        native = self.artifacts / "gradle-build/iroha_kotlin_sdk/client-android/generated/jniLibs/production/armeabi-v7a/libconnect_norito_bridge.so"
        native.unlink()
        result = self._package()
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(self.output.exists())

    def test_generated_native_original_mismatch_refuses_client_correlation(self):
        native = self.artifacts / "gradle-build/iroha_kotlin_sdk/client-android/generated/jniLibs/production/arm64-v8a/libconnect_norito_bridge.so"
        native.write_bytes(b"unrelated generated bridge")
        result = self._package()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("client AAR native payload", result.stderr)
        self.assertFalse(self.output.exists())

    def _inject_copied_payload_mutation(self, restore):
        owner = self.repository / "scripts/package_mobile_sdk_artifacts.sh"
        source = owner.read_text()
        original = '(cd "$stage_container" && zip -qr "$android_zip" "$(basename "$stage")")'
        replacement = ('saved_original="$stage_container/original-core.jar"\n'
                       '  cp "$stage/core-jvm/core-jvm-${VERSION#v}.jar" "$saved_original"\n'
                       '  printf "substituted copied payload" > "$stage/core-jvm/core-jvm-${VERSION#v}.jar"\n'
                       '  ' + original)
        if restore:
            replacement += '\n  cp "$saved_original" "$stage/core-jvm/core-jvm-${VERSION#v}.jar"'
        self.assertEqual(source.count(original), 1)
        owner.write_text(source.replace(original, replacement))

    def test_substituted_copied_payload_refuses_publication(self):
        self._inject_copied_payload_mutation(False)
        result = self._package()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("copied Android payload differs", result.stderr)
        self.assertFalse(self.output.exists())

    def test_copied_payload_mutation_then_restoration_cannot_hide_wrong_zip(self):
        self._inject_copied_payload_mutation(True)
        result = self._package()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Android ZIP payload", result.stderr)
        self.assertFalse(self.output.exists())

    def test_success_publishes_only_to_absent_destination(self) -> None:
        result = self._package()
        self.assertEqual(result.returncode, 0, result.stderr)
        archive = self.output / f"iroha-mobile-sdk-android-{VERSION}.zip"
        manifest = self.output / f"mobile-sdk-android-{VERSION}.artifacts.json"
        checksums = self.output / f"SHA256SUMS-android-{VERSION}.txt"
        self.assertTrue(archive.is_file())
        with zipfile.ZipFile(archive) as bundle:
            names = bundle.namelist()
            prefix = f"iroha-mobile-sdk-android-{VERSION}/"
            self.assertIn(prefix + "kagemusha-wallet-android/kagemusha-wallet-android-release.aar", names)
            for module, extension in [("core-jvm", "jar"), ("client-android", "aar"), ("kagemusha-wallet-android", "aar")]:
                self.assertIn(prefix + f"maven/org/hyperledger/iroha/sdk/{module}/{VERSION}/{module}-{VERSION}.{extension}", names)
        self.assertTrue(manifest.is_file())
        self.assertTrue(checksums.is_file())
        self.assertFalse((self.output / ".NoritoBridge.archive.lockfile").exists())
        self._assert_no_publish_stage()
        self.assertEqual(
            len(list(self.output.parent.glob(".iroha-mobile-sdk-android-*.stage.*"))),
            1,
        )
        self.assertIn("retained Android package stage", result.stderr)

        payload = json.loads(manifest.read_text(encoding="utf-8"))
        self.assertEqual(payload["version"], VERSION)
        self.assertEqual(payload["mode"], "android")
        self.assertEqual(
            [entry["kind"] for entry in payload["artifacts"]],
            ["android-sdk"],
        )
        for line in checksums.read_text(encoding="utf-8").splitlines():
            expected, relative = line.split("  ", 1)
            artifact = self.output / relative
            self.assertTrue(artifact.is_file(), relative)
            self.assertEqual(hashlib.sha256(artifact.read_bytes()).hexdigest(), expected)

    def test_late_destination_competitor_is_preserved(self) -> None:
        (self.output.parent / ".package-test-destination-race").write_bytes(b"")
        result = self._package()
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(
            (self.output / "competitor.txt").read_bytes(),
            b"late competitor\n",
        )
        self.assertEqual(len(self._publish_stages()), 1)

    def test_late_stage_swap_is_detected_without_removing_foreign_output(self) -> None:
        (self.output.parent / ".package-test-stage-race").write_bytes(b"")
        result = self._package()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("does not match the authenticated stage inode", result.stderr)
        self.assertEqual(
            (self.output / "competitor.txt").read_bytes(),
            b"late competitor\n",
        )
        retained = list(
            self.output.parent.glob(".mobile-sdk.publish.*.owner-retained")
        )
        self.assertEqual(len(retained), 1)
        self.assertTrue(
            (retained[0] / f"mobile-sdk-android-{VERSION}.artifacts.json").is_file()
        )

    def test_apple_checker_and_archiver_share_authenticated_source_lock(self) -> None:
        diagnostic_version = "pr-7-deadbeef"
        seal_environment = self._write_fake_apple_owner()
        result = self._package(
            mode="apple",
            version=diagnostic_version,
            SOURCE_DATE_EPOCH="1700000000",
            **seal_environment,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        archive = self.output / f"NoritoBridge-v{VERSION}.xcframework.zip"
        versioned_manifest = self.output / f"NoritoBridge-v{VERSION}.artifacts.json"
        self.assertTrue(
            archive.is_file()
        )
        self.assertTrue(versioned_manifest.is_file())
        self.assertEqual(len(list(self.output.iterdir())), 4)
        self.assertFalse((self.output / ".NoritoBridge.archive.lockfile").exists())
        self._assert_no_publish_stage()

        package_manifest = (
            self.output / f"mobile-sdk-apple-{diagnostic_version}.artifacts.json"
        )
        package_payload = json.loads(package_manifest.read_text(encoding="utf-8"))
        self.assertEqual(package_payload["version"], diagnostic_version)
        self.assertEqual(package_payload["apple_sdk_semver"], VERSION)
        self.assertEqual(
            [entry["kind"] for entry in package_payload["artifacts"]],
            [
                "apple-xcframework",
                "apple-manifest",
            ],
        )
        self.assertEqual(
            {entry["name"] for entry in package_payload["artifacts"]},
            {archive.name, versioned_manifest.name},
        )
        checksums = self.output / f"SHA256SUMS-apple-{diagnostic_version}.txt"
        checksum_paths = {
            line.split("  ", 1)[1]
            for line in checksums.read_text(encoding="utf-8").splitlines()
        }
        self.assertEqual(
            checksum_paths,
            {archive.name, versioned_manifest.name, package_manifest.name},
        )

    def test_apple_package_accepts_canonical_mobile_rustup_fallback(self) -> None:
        seal_environment = self._write_fake_apple_owner()
        rustup = seal_environment.pop("NORITO_BRIDGE_SEAL_RUSTUP")
        result = self._package(
            mode="apple",
            version="pr-7-rustup",
            SOURCE_DATE_EPOCH="1700000000",
            MOBILE_SDK_RUSTUP_BINARY=rustup,
            **seal_environment,
        )
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_apple_package_rejects_empty_mobile_rustup_override(self) -> None:
        self._assert_invalid_mobile_rustup("")

    def test_apple_package_rejects_relative_mobile_rustup_override(self) -> None:
        self._assert_invalid_mobile_rustup("rustup")

    def test_apple_package_rejects_symlinked_mobile_rustup_override(self) -> None:
        seal_environment = self._write_fake_apple_owner()
        rustup = Path(seal_environment.pop("NORITO_BRIDGE_SEAL_RUSTUP"))
        rustup_link = rustup.with_name("rustup-link")
        rustup_link.symlink_to(rustup)
        self._assert_invalid_mobile_rustup(str(rustup_link), seal_environment)

    def test_apple_package_rejects_noncanonical_mobile_rustup_override(self) -> None:
        seal_environment = self._write_fake_apple_owner()
        rustup = Path(seal_environment.pop("NORITO_BRIDGE_SEAL_RUSTUP"))
        noncanonical = rustup.parent / ".." / rustup.parent.name / rustup.name
        self._assert_invalid_mobile_rustup(str(noncanonical), seal_environment)

    def _assert_invalid_mobile_rustup(
        self,
        rustup: str,
        seal_environment: dict[str, str] | None = None,
    ) -> None:
        if seal_environment is None:
            seal_environment = self._write_fake_apple_owner()
            seal_environment.pop("NORITO_BRIDGE_SEAL_RUSTUP")
        result = self._package(
            mode="apple",
            version="pr-7-invalid-rustup",
            SOURCE_DATE_EPOCH="1700000000",
            MOBILE_SDK_RUSTUP_BINARY=rustup,
            **seal_environment,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(
            "MOBILE_SDK_RUSTUP_BINARY must be an absolute canonical "
            "non-symbolic executable",
            result.stderr,
        )
        self.assertFalse(self.output.exists())

    def test_missing_apple_archive_validator_fails_without_publication(self) -> None:
        seal_environment = self._write_fake_apple_owner()
        missing_validator = self.repository / "scripts/validate_norito_bridge_archive.py"
        missing_validator.unlink()
        result = self._package(
            mode="apple", version="pr-8-missing-validator",
            SOURCE_DATE_EPOCH="1700000000", **seal_environment,
        )
        self.assertEqual(result.returncode, 66, result.stderr)
        self.assertIn("Apple archive validator is unavailable", result.stderr)
        self.assertIn(str(missing_validator), result.stderr)
        self.assertNotIn("unbound variable", result.stderr)
        self.assertFalse(self.output.exists())
        artifact_root = Path(seal_environment["MOBILE_SDK_APPLE_ARTIFACT_DIR"])
        self.assertEqual(
            (artifact_root / "NoritoBridge.xcframework/Info.plist").read_bytes(),
            b"canonical plist fixture\n",
        )

    def test_apple_manifest_version_must_match_sdk_version(self) -> None:
        seal_environment = self._write_fake_apple_owner()
        artifact_root = Path(seal_environment["MOBILE_SDK_APPLE_ARTIFACT_DIR"])
        drifted = b'{"schema_version":1,"version":"9.9.9"}\n'
        (artifact_root / "NoritoBridge.artifacts.json").write_bytes(drifted)
        (artifact_root / "NoritoBridge.xcframework/NoritoBridge.artifacts.json").write_bytes(
            drifted
        )
        result = self._package(
            mode="apple",
            version="pr-8-deadbeef",
            SOURCE_DATE_EPOCH="1700000000",
            **seal_environment,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(
            "embedded NoritoBridge manifest version must equal IrohaSwift/VERSION",
            result.stderr,
        )
        self.assertFalse(self.output.exists())

    def test_repository_local_and_implicit_outputs_are_rejected(self) -> None:
        implicit_environment = self._environment()
        implicit_environment.pop("MOBILE_SDK_PACKAGE_OUT_DIR")
        implicit = subprocess.run(
            [
                "/bin/bash",
                str(self.repository / "scripts/package_mobile_sdk_artifacts.sh"),
                "--lockfile-path", str(self.lockfile),
                "--root",
                str(self.repository),
                "--android",
                "--version",
                VERSION,
            ],
            env=implicit_environment,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        self.assertNotEqual(implicit.returncode, 0)
        self.assertIn("MOBILE_SDK_PACKAGE_OUT_DIR is required", implicit.stderr)

        repository_output = self.repository / "dist/mobile-sdk"
        repository_output.parent.mkdir(parents=True, exist_ok=True)
        confined = self._package(MOBILE_SDK_PACKAGE_OUT_DIR=str(repository_output))
        self.assertNotEqual(confined.returncode, 0)
        self.assertIn("outside the Iroha source tree", confined.stderr)
        self.assertFalse(repository_output.exists())

        real_parent = self.temporary_root / "canonical-package-parent/nested"
        real_parent.mkdir(parents=True)
        linked_ancestor = self.temporary_root / "linked-package-parent"
        linked_ancestor.symlink_to(real_parent.parent, target_is_directory=True)
        linked_output = linked_ancestor / "nested/mobile-sdk"
        no_follow = self._package(MOBILE_SDK_PACKAGE_OUT_DIR=str(linked_output))
        self.assertNotEqual(no_follow.returncode, 0)
        self.assertIn("must not traverse symbolic links", no_follow.stderr)
        self.assertFalse((real_parent / "mobile-sdk").exists())


class PackageIsolationLauncherTests(unittest.TestCase):
    def test_parent_executes_one_genuinely_isolated_case(self) -> None:
        case = MobileSdkPackagePublisherTests("_assert_real_isolated_runtime")
        result = unittest.TestResult()
        with mock.patch.object(subprocess, "run", wraps=subprocess.run) as executed:
            run_isolated_package_case(case, result)
        self.assertEqual(result.testsRun, 1)
        self.assertTrue(result.wasSuccessful(), result.errors + result.failures)
        self.assertEqual(executed.call_args.args[0][1:4], ["-I", "-S", "-B"])
        self.assertEqual(
            executed.call_args.args[0][-1],
            "MobileSdkPackagePublisherTests._assert_real_isolated_runtime",
        )

    def test_child_assertion_failure_is_reported_to_parent(self) -> None:
        case = MobileSdkPackagePublisherTests("_deliberate_isolated_failure")
        result = unittest.TestResult()
        run_isolated_package_case(case, result)
        self.assertEqual(result.testsRun, 1)
        self.assertFalse(result.wasSuccessful())
        self.assertEqual(result.errors, [])
        self.assertEqual(len(result.failures), 1)
        self.assertIs(result.failures[0][0], case)
        self.assertIn("isolated child assertion propagation probe", result.failures[0][1])


if __name__ == "__main__":
    unittest.main()
