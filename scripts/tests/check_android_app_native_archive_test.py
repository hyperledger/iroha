#!/usr/bin/env python3
"""Tests for exact ABI-30 byte authentication in Android app archives."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
import warnings
import zipfile


SCRIPT = Path(__file__).resolve().parents[1] / "check_android_app_native_archive.py"
ABIS = ("arm64-v8a", "armeabi-v7a", "x86_64")
LIBRARY_NAME = "libconnect_norito_bridge.so"
PROVENANCE_ENTRY = "assets/iroha/native-build-provenance-v1.json"
ANDROID_NDK_BASE_REVISION = "28.0.12674087"
ANDROID_NDK_SOURCE_PROPERTIES_SHA256 = (
    "55368a3554d27b8413b75a4b2e83ea7f6b66fef4068f7a7f71cf2910c6e3357b"
)


class AndroidAppNativeArchiveTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary_directory.name).resolve()
        self.iroha_root = self.root / "iroha-source"
        self.artifact_root = self.root / "android-artifacts"
        self.client_root = (
            self.artifact_root
            / "gradle-build"
            / "iroha_kotlin_sdk"
            / "client-android"
        )
        self.iroha_root.mkdir()
        self.client_root.mkdir(parents=True)
        self.cargo_lock = self.iroha_root / "Cargo.lock"
        self.cargo_lock.write_bytes(b"# fixture Cargo.lock\n")
        self.native_target = self.client_root / "native/cargo-target/production"
        self.native_target.mkdir(parents=True)
        self.source_seal = {
            "schema": "iroha.norito-bridge-source-seal.v1",
            "platform": "android",
            "targets": ["aarch64-linux-android", "armv7-linux-androideabi", "x86_64-linux-android"],
            "source_commit": "1" * 40,
            "source_tree_dirty": False,
            "source_status": "",
            "source_fingerprint_sha256": "2" * 64,
        }
        self.source_seal_path = (
            self.client_root / "native/sourceSeal/production/source-seal-v1.json"
        )
        self.source_seal_path.parent.mkdir(parents=True)
        self.source_seal_path.write_bytes(self.seal_bytes())
        verifier = self.iroha_root / "scripts/norito_bridge_source_seal.py"
        verifier.parent.mkdir()
        verifier.write_text(
            "from pathlib import Path\n"
            "import sys\n"
            "if len(sys.argv) < 2 or sys.argv[1] != 'verify':\n"
            "    raise SystemExit(1)\n"
            "snapshot = Path(sys.argv[sys.argv.index('--snapshot') + 1])\n"
            "expected = Path(__file__).with_name('expected-source-seal.json')\n"
            "raise SystemExit(0 if snapshot.read_bytes() == expected.read_bytes() else 1)\n",
            encoding="utf-8",
        )
        verifier.with_name("expected-source-seal.json").write_bytes(self.seal_bytes())
        self.libraries = {
            abi: f"\x7fELF-authenticated-{abi}\n".encode("ascii")
            for abi in ABIS
        }
        for abi, payload in self.libraries.items():
            path = (
                self.client_root
                / "generated"
                / "jniLibs"
                / "production"
                / abi
                / LIBRARY_NAME
            )
            path.parent.mkdir(parents=True)
            path.write_bytes(payload)

        provenance = {
            "schema": "iroha.android-native-build-provenance.v1",
            "native_bridge_abi_version": 30,
            "build_profile": "release",
            "cargo_locked": True,
            "privacy_production_enabled": True,
            "cargo_features": ["privacy-production-enabled"],
            "build_environment": {
                "schema": "iroha.mobile-native-build-environment.v1",
                "android_ndk_revision": ANDROID_NDK_BASE_REVISION,
                "android_ndk_source_properties_sha256":
                    ANDROID_NDK_SOURCE_PROPERTIES_SHA256,
            },
            "source_commit": "1" * 40,
            "source_tree_dirty": False,
            "source_fingerprint_sha256": "2" * 64,
            "cargo_lock_sha256": hashlib.sha256(self.cargo_lock.read_bytes()).hexdigest(),
            "android_ndk_revision": ANDROID_NDK_BASE_REVISION,
            "strip_tool_sha256": "4" * 64,
            "libraries": {
                abi: {
                    "aar_path": f"jni/{abi}/{LIBRARY_NAME}",
                    "bytes": len(payload),
                    "raw_bytes": len(payload) + 1,
                    "raw_sha256": "5" * 64,
                    "sha256": hashlib.sha256(payload).hexdigest(),
                }
                for abi, payload in self.libraries.items()
            },
        }
        self.provenance_bytes = (
            json.dumps(provenance, sort_keys=True, separators=(",", ":")) + "\n"
        ).encode("utf-8")
        self.provenance = provenance
        self.provenance_path = (
            self.client_root
            / "generated"
            / "nativeProvenance"
            / "production"
            / "iroha"
            / "native-build-provenance-v1.json"
        )
        self.provenance_path.parent.mkdir(parents=True)
        self.provenance_path.write_bytes(self.provenance_bytes)

        self.aar_path = (
            self.client_root / "outputs" / "aar" / "client-android-release.aar"
        )
        self.aar_path.parent.mkdir(parents=True)
        self.write_aar()

    def tearDown(self) -> None:
        self.temporary_directory.cleanup()

    def seal_bytes(self) -> bytes:
        return (
            json.dumps(self.source_seal, sort_keys=True, separators=(",", ":")) + "\n"
        ).encode("utf-8")

    @staticmethod
    def write_zip(
        path: Path,
        entries: list[tuple[str, bytes]],
    ) -> None:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", UserWarning)
            with zipfile.ZipFile(path, "w") as archive:
                for name, payload in entries:
                    archive.writestr(name, payload)

    def write_aar(
        self,
        *,
        extra_entries: dict[str, bytes] | None = None,
        duplicate_entries: list[tuple[str, bytes]] | None = None,
    ) -> None:
        entries = [
            ("AndroidManifest.xml", b"<manifest />\n"),
            (PROVENANCE_ENTRY, self.provenance_bytes),
            *[
                (f"jni/{abi}/{LIBRARY_NAME}", payload)
                for abi, payload in self.libraries.items()
            ],
            *(extra_entries or {}).items(),
            *(duplicate_entries or []),
        ]
        self.write_zip(self.aar_path, entries)

    def replace_provenance(self, provenance: dict[str, object]) -> None:
        self.provenance_bytes = (
            json.dumps(provenance, sort_keys=True, separators=(",", ":")) + "\n"
        ).encode("utf-8")
        self.provenance_path.write_bytes(self.provenance_bytes)
        self.write_aar()

    def write_app_archive(
        self,
        kind: str,
        *,
        overrides: dict[str, bytes] | None = None,
        extra_entries: dict[str, bytes] | None = None,
        duplicate_entries: list[tuple[str, bytes]] | None = None,
    ) -> Path:
        prefix = "base/" if kind == "aab" else ""
        entries = {
            f"{prefix}assets/iroha/native-build-provenance-v1.json":
                self.provenance_bytes,
            **{
                f"{prefix}lib/{abi}/{LIBRARY_NAME}": payload
                for abi, payload in self.libraries.items()
            },
        }
        entries.update(overrides or {})
        entries.update(extra_entries or {})
        path = self.root / f"wallet-release.{kind}"
        self.write_zip(path, [*entries.items(), *(duplicate_entries or [])])
        return path

    def verify(self, archive: Path, kind: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [
                sys.executable,
                "-I",
                str(SCRIPT),
                "--archive",
                str(archive.resolve(strict=True)),
                "--kind",
                kind,
                "--artifact-dir",
                str(self.artifact_root.resolve(strict=True)),
                "--iroha-root",
                str(self.iroha_root.resolve(strict=True)),
            ],
            check=False,
            capture_output=True,
            text=True,
        )

    def test_accepts_exact_aab_and_apk_bytes(self) -> None:
        for kind in ("aab", "apk"):
            with self.subTest(kind=kind):
                result = self.verify(self.write_app_archive(kind), kind)
                self.assertEqual(0, result.returncode, result.stderr)

    def test_accepts_canonical_native_directory_entries(self) -> None:
        self.write_aar(
            extra_entries={
                "jni/": b"",
                **{f"jni/{abi}/": b"" for abi in ABIS},
            },
        )
        for kind in ("aab", "apk"):
            with self.subTest(kind=kind):
                prefix = "base/" if kind == "aab" else ""
                result = self.verify(
                    self.write_app_archive(
                        kind,
                        extra_entries={
                            f"{prefix}lib/": b"",
                            **{f"{prefix}lib/{abi}/": b"" for abi in ABIS},
                        },
                    ),
                    kind,
                )
                self.assertEqual(0, result.returncode, result.stderr)

    def test_rejects_tampered_app_bridge(self) -> None:
        archive = self.write_app_archive(
            "aab",
            overrides={
                f"base/lib/{ABIS[0]}/{LIBRARY_NAME}": b"\x7fELF-tampered\n",
            },
        )
        result = self.verify(archive, "aab")
        self.assertNotEqual(0, result.returncode)
        self.assertIn("differs from the authenticated generated/AAR bytes", result.stderr)

    def test_rejects_extra_bridge_abi(self) -> None:
        archive = self.write_app_archive(
            "apk",
            extra_entries={
                f"lib/x86/{LIBRARY_NAME}": b"\x7fELF-extra\n",
            },
        )
        result = self.verify(archive, "apk")
        self.assertNotEqual(0, result.returncode)
        self.assertIn("native ABI directory inventory is not exact", result.stderr)

    def test_rejects_unrelated_library_under_unsupported_abi(self) -> None:
        for kind in ("aab", "apk"):
            with self.subTest(archive=kind):
                prefix = "base/" if kind == "aab" else ""
                archive = self.write_app_archive(
                    kind,
                    extra_entries={
                        f"{prefix}lib/x86/libunrelated.so": b"\x7fELF\n",
                    },
                )
                result = self.verify(archive, kind)
                self.assertNotEqual(0, result.returncode)
                self.assertIn("native ABI directory inventory is not exact", result.stderr)

        with self.subTest(archive="aar"):
            self.write_aar(
                extra_entries={
                    "jni/x86/libunrelated.so": b"\x7fELF\n",
                },
            )
            result = self.verify(self.write_app_archive("aab"), "aab")
            self.assertNotEqual(0, result.returncode)
            self.assertIn("native ABI directory inventory is not exact", result.stderr)

    def test_rejects_unrelated_library_under_supported_abi(self) -> None:
        for kind in ("aab", "apk"):
            with self.subTest(archive=kind):
                prefix = "base/" if kind == "aab" else ""
                archive = self.write_app_archive(
                    kind,
                    extra_entries={
                        f"{prefix}lib/{ABIS[0]}/libunrelated.so": b"\x7fELF\n",
                    },
                )
                result = self.verify(archive, kind)
                self.assertNotEqual(0, result.returncode)
                self.assertIn("native library inventory is not exact", result.stderr)

        with self.subTest(archive="aar"):
            self.write_aar(
                extra_entries={
                    f"jni/{ABIS[0]}/libunrelated.so": b"\x7fELF\n",
                },
            )
            result = self.verify(self.write_app_archive("aab"), "aab")
            self.assertNotEqual(0, result.returncode)
            self.assertIn("native library inventory is not exact", result.stderr)

    def test_rejects_nested_native_library_paths(self) -> None:
        for kind in ("aab", "apk"):
            with self.subTest(archive=kind):
                prefix = "base/" if kind == "aab" else ""
                archive = self.write_app_archive(
                    kind,
                    extra_entries={
                        f"{prefix}lib/{ABIS[0]}/nested/libunrelated.so":
                            b"\x7fELF\n",
                    },
                )
                result = self.verify(archive, kind)
                self.assertNotEqual(0, result.returncode)
                self.assertIn("malformed or nested native-library entry", result.stderr)

        with self.subTest(archive="aar"):
            self.write_aar(
                extra_entries={
                    f"jni/{ABIS[0]}/nested/libunrelated.so": b"\x7fELF\n",
                },
            )
            result = self.verify(self.write_app_archive("aab"), "aab")
            self.assertNotEqual(0, result.returncode)
            self.assertIn("malformed or nested native-library entry", result.stderr)

    def test_rejects_noncanonical_native_library_paths(self) -> None:
        for kind in ("aab", "apk"):
            with self.subTest(archive=kind):
                prefix = "base/" if kind == "aab" else ""
                archive = self.write_app_archive(
                    kind,
                    extra_entries={
                        f"{prefix}lib//{ABIS[0]}/libunrelated.so": b"\x7fELF\n",
                    },
                )
                result = self.verify(archive, kind)
                self.assertNotEqual(0, result.returncode)
                self.assertIn("non-canonical ZIP path", result.stderr)

        with self.subTest(archive="aar"):
            self.write_aar(
                extra_entries={
                    f"jni//{ABIS[0]}/libunrelated.so": b"\x7fELF\n",
                },
            )
            result = self.verify(self.write_app_archive("aab"), "aab")
            self.assertNotEqual(0, result.returncode)
            self.assertIn("non-canonical ZIP path", result.stderr)

    def test_rejects_native_library_path_traversal(self) -> None:
        for kind in ("aab", "apk"):
            with self.subTest(archive=kind):
                prefix = "base/" if kind == "aab" else ""
                archive = self.write_app_archive(
                    kind,
                    extra_entries={
                        f"{prefix}lib/{ABIS[0]}/../armeabi-v7a/libunrelated.so":
                            b"\x7fELF\n",
                    },
                )
                result = self.verify(archive, kind)
                self.assertNotEqual(0, result.returncode)
                self.assertIn("non-canonical ZIP path", result.stderr)

        with self.subTest(archive="aar"):
            self.write_aar(
                extra_entries={
                    f"jni/{ABIS[0]}/../armeabi-v7a/libunrelated.so": b"\x7fELF\n",
                },
            )
            result = self.verify(self.write_app_archive("aab"), "aab")
            self.assertNotEqual(0, result.returncode)
            self.assertIn("non-canonical ZIP path", result.stderr)

    def test_rejects_duplicate_native_library_entries(self) -> None:
        for kind in ("aab", "apk"):
            with self.subTest(archive=kind):
                prefix = "base/" if kind == "aab" else ""
                duplicate_name = f"{prefix}lib/{ABIS[0]}/{LIBRARY_NAME}"
                archive = self.write_app_archive(
                    kind,
                    duplicate_entries=[(duplicate_name, self.libraries[ABIS[0]])],
                )
                result = self.verify(archive, kind)
                self.assertNotEqual(0, result.returncode)
                self.assertIn("duplicate ZIP entries", result.stderr)

        with self.subTest(archive="aar"):
            duplicate_name = f"jni/{ABIS[0]}/{LIBRARY_NAME}"
            self.write_aar(
                duplicate_entries=[(duplicate_name, self.libraries[ABIS[0]])],
            )
            result = self.verify(self.write_app_archive("aab"), "aab")
            self.assertNotEqual(0, result.returncode)
            self.assertIn("duplicate ZIP entries", result.stderr)

    def test_rejects_aar_provenance_that_differs_from_generated_bytes(self) -> None:
        with zipfile.ZipFile(self.aar_path) as source:
            entries = {
                info.filename: source.read(info)
                for info in source.infolist()
            }
        entries[PROVENANCE_ENTRY] += b" "
        with zipfile.ZipFile(self.aar_path, "w") as output:
            for name, payload in entries.items():
                output.writestr(name, payload)

        result = self.verify(self.write_app_archive("aab"), "aab")
        self.assertNotEqual(0, result.returncode)
        self.assertIn("AAR provenance differs from generated provenance", result.stderr)

    def test_rejects_nonexact_top_level_ndk_base_revision(self) -> None:
        provenance = json.loads(json.dumps(self.provenance))
        provenance["android_ndk_revision"] = "28.0.12674087-beta2"
        self.replace_provenance(provenance)

        result = self.verify(self.write_app_archive("aab"), "aab")
        self.assertNotEqual(0, result.returncode)
        self.assertIn("Android NDK base revision is not exact", result.stderr)

    def test_rejects_nonexact_nested_ndk_base_revision(self) -> None:
        for replacement in ("28.0.12674087-beta2", None):
            with self.subTest(replacement=replacement):
                provenance = json.loads(json.dumps(self.provenance))
                build_environment = provenance["build_environment"]
                self.assertIsInstance(build_environment, dict)
                if replacement is None:
                    del build_environment["android_ndk_revision"]
                else:
                    build_environment["android_ndk_revision"] = replacement
                self.replace_provenance(provenance)

                result = self.verify(self.write_app_archive("apk"), "apk")
                self.assertNotEqual(0, result.returncode)
                self.assertIn(
                    "build environment Android NDK base revision is not exact",
                    result.stderr,
                )

    def test_rejects_nonexact_or_missing_ndk_source_properties_digest(self) -> None:
        for replacement in ("0" * 64, None):
            with self.subTest(replacement=replacement):
                provenance = json.loads(json.dumps(self.provenance))
                build_environment = provenance["build_environment"]
                self.assertIsInstance(build_environment, dict)
                if replacement is None:
                    del build_environment[
                        "android_ndk_source_properties_sha256"
                    ]
                else:
                    build_environment[
                        "android_ndk_source_properties_sha256"
                    ] = replacement
                self.replace_provenance(provenance)

                result = self.verify(self.write_app_archive("aab"), "aab")
                self.assertNotEqual(0, result.returncode)
                self.assertIn(
                    "Android NDK source.properties digest is not exact",
                    result.stderr,
                )

    def test_rejects_nonobject_or_wrong_schema_build_environment(self) -> None:
        for replacement in (
            [],
            {
                "schema": "iroha.mobile-native-build-environment.v2",
                "android_ndk_revision": ANDROID_NDK_BASE_REVISION,
                "android_ndk_source_properties_sha256":
                    ANDROID_NDK_SOURCE_PROPERTIES_SHA256,
            },
        ):
            with self.subTest(replacement=replacement):
                provenance = json.loads(json.dumps(self.provenance))
                provenance["build_environment"] = replacement
                self.replace_provenance(provenance)

                result = self.verify(self.write_app_archive("apk"), "apk")
                self.assertNotEqual(0, result.returncode)
                if isinstance(replacement, list):
                    self.assertIn(
                        "build environment must be an object",
                        result.stderr,
                    )
                else:
                    self.assertIn(
                        "build environment schema is not exact",
                        result.stderr,
                    )

    def test_local_integration_scope_is_rejected_even_for_clean_source(self) -> None:
        for dirty in (False, True):
            with self.subTest(source_tree_dirty=dirty):
                provenance = json.loads(json.dumps(self.provenance))
                provenance["artifact_scope"] = "local-integration"
                provenance["source_tree_dirty"] = dirty
                self.replace_provenance(provenance)
                result = self.verify(self.write_app_archive("apk"), "apk")
                self.assertNotEqual(0, result.returncode)
                self.assertIn("field inventory is not exact", result.stderr)

    def test_rejects_dirty_or_mismatched_source_provenance(self) -> None:
        for field, replacement in (
            ("source_tree_dirty", True),
            ("source_commit", "3" * 40),
            ("source_fingerprint_sha256", "4" * 64),
        ):
            with self.subTest(field=field):
                provenance = json.loads(json.dumps(self.provenance))
                provenance[field] = replacement
                self.replace_provenance(provenance)
                result = self.verify(self.write_app_archive("apk"), "apk")
                self.assertNotEqual(0, result.returncode)
                self.assertIn("source", result.stderr)

    def test_rejects_stale_or_missing_source_seal(self) -> None:
        self.source_seal["source_fingerprint_sha256"] = "4" * 64
        self.source_seal_path.write_bytes(self.seal_bytes())
        result = self.verify(self.write_app_archive("apk"), "apk")
        self.assertNotEqual(0, result.returncode)
        self.assertIn("source seal disagrees", result.stderr)

        self.source_seal_path.unlink()
        result = self.verify(self.write_app_archive("apk"), "apk")
        self.assertNotEqual(0, result.returncode)
        self.assertIn("source seal is missing", result.stderr)

    def test_armv7_diagnostic_source_seal_is_not_an_admitted_android_release(self) -> None:
        self.source_seal["platform"] = "android-armv7-diagnostic"
        self.source_seal["targets"] = ["armv7-linux-androideabi"]
        self.source_seal_path.write_bytes(self.seal_bytes())
        result = self.verify(self.write_app_archive("apk"), "apk")
        self.assertNotEqual(0, result.returncode)
        self.assertIn("source seal disagrees", result.stderr)

    def test_armv7_diagnostic_bytes_cannot_replace_production_original(self) -> None:
        archive = self.write_app_archive("apk")
        with zipfile.ZipFile(archive) as source:
            entries = {entry.filename: source.read(entry) for entry in source.infolist()}
        entries["lib/armeabi-v7a/" + LIBRARY_NAME] = b"TEST ONLY diagnostic ELF32"
        with zipfile.ZipFile(archive, "w") as output:
            for name, data in entries.items():
                output.writestr(name, data)
        result = self.verify(archive, "apk")
        self.assertNotEqual(0, result.returncode)
        self.assertIn("differs", result.stderr)

    def test_prior_two_abi_source_seal_is_not_an_admitted_release(self) -> None:
        self.source_seal["targets"] = ["aarch64-linux-android", "x86_64-linux-android"]
        self.source_seal_path.write_bytes(self.seal_bytes())
        result = self.verify(self.write_app_archive("apk"), "apk")
        self.assertNotEqual(0, result.returncode)
        self.assertIn("source seal disagrees", result.stderr)

    def test_prior_two_abi_native_manifest_is_not_an_admitted_release(self) -> None:
        provenance = json.loads(json.dumps(self.provenance))
        del provenance["libraries"]["armeabi-v7a"]
        self.replace_provenance(provenance)
        result = self.verify(self.write_app_archive("apk"), "apk")
        self.assertNotEqual(0, result.returncode)
        self.assertIn("native provenance ABI inventory is not exact", result.stderr)

    def test_rejects_stale_cargo_lock_or_live_source_verification(self) -> None:
        self.cargo_lock.write_bytes(b"# changed Cargo.lock\n")
        result = self.verify(self.write_app_archive("aab"), "aab")
        self.assertNotEqual(0, result.returncode)
        self.assertIn("canonical Cargo.lock", result.stderr)

        self.cargo_lock.write_bytes(b"# fixture Cargo.lock\n")
        expected = self.iroha_root / "scripts/expected-source-seal.json"
        expected.write_bytes(b"stale\n")
        result = self.verify(self.write_app_archive("aab"), "aab")
        self.assertNotEqual(0, result.returncode)
        self.assertIn("live Iroha source tree", result.stderr)


if __name__ == "__main__":
    unittest.main()
