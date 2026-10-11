from __future__ import annotations

import importlib.util
from pathlib import Path
import os
import struct
import subprocess
import tempfile
import unittest
from unittest import mock


SCRIPT = Path(__file__).parents[1] / "inspect_android_armv7_diagnostic.py"
SPEC = importlib.util.spec_from_file_location("armv7_inspection", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
inspection = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(inspection)


def elf32(*, machine: int = 40, alignment: int = 4096, address: int = 0) -> bytes:
    header = b"\x7fELF\x01\x01\x01" + bytes(9)
    header += struct.pack("<HHIIIIIHHHHHH", 3, machine, 1, 0, 52, 0,
                          0x05000000, 52, 32, 1, 0, 0, 0)
    segment = struct.pack("<IIIIIIII", 1, 0, address, 0, 84, 84, 5, alignment)
    return header + segment


class Armv7DiagnosticInspectionTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name).resolve()
        self.library = self.root / "libconnect_norito_bridge.so"
        self.library.write_bytes(elf32())
        self.inspector = self.root / "llvm-nm"
        self.inspector.write_bytes(b"explicit synthetic symbol inspector\n")
        self.inspector.chmod(0o700)
        self.stdout = (b"connect_norito_bridge_abi_version\nconnect_norito_free\n"
                       b"Java_org_hyperledger_iroha_sdk_fixture\n")

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def result(self, **changes) -> subprocess.CompletedProcess:
        values = {"args": [], "returncode": 0, "stdout": self.stdout, "stderr": b""}
        values.update(changes)
        return subprocess.CompletedProcess(**values)

    def test_elf32_arm_load_alignment_is_observed_without_release_admission(self) -> None:
        for alignment in (4096, 16384):
            self.library.write_bytes(elf32(alignment=alignment))
            with mock.patch.object(inspection.subprocess, "run", return_value=self.result()) as run:
                report = inspection.inspect(self.library, self.inspector)
            self.assertEqual(report["library"]["elf"]["machine"], 40)
            self.assertEqual(report["library"]["elf"]["allLoadsAligned16KiB"], alignment == 16384)
            self.assertEqual(report["jniExportCount"], 1)
            self.assertFalse(report["release_admitted"])
            self.assertEqual(set(report), {
                "schema", "artifact_scope", "abi", "target", "release_admitted",
                "library", "symbolInspector", "nativeExports", "jniExportCount", "limits",
            })
            self.assertEqual(report["artifact_scope"], "android-local-diagnostic")
            self.assertEqual(run.call_args.args[0], [str(self.inspector), "--dynamic",
                "--defined-only", "--extern-only", "--format=just-symbols", str(self.library)])
            self.assertEqual(run.call_args.kwargs["env"],
                             {"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C"})

    def test_wrong_elf_class_machine_and_program_headers_fail(self) -> None:
        cases = [bytes(elf32())[:20], elf32(machine=183),
                 b"\x7fELF\x02" + elf32()[5:], elf32(alignment=1024),
                 elf32(address=1), elf32()[:70]]
        for payload in cases:
            with self.subTest(payload=payload[:24]):
                with self.assertRaises(ValueError):
                    inspection.check_elf32_arm(payload)

    def test_no_load_segment_fails(self) -> None:
        payload = bytearray(elf32())
        struct.pack_into("<I", payload, 52, 0)
        with self.assertRaisesRegex(ValueError, "no LOAD"):
            inspection.check_elf32_arm(bytes(payload))

    def test_segment_file_range_cannot_escape_original(self) -> None:
        payload = bytearray(elf32())
        struct.pack_into("<I", payload, 52 + 16, 85)
        struct.pack_into("<I", payload, 52 + 20, 85)
        with self.assertRaisesRegex(ValueError, "LOAD"):
            inspection.check_elf32_arm(bytes(payload))

    def test_missing_baseline_exports_and_malformed_output_fail(self) -> None:
        for stdout in [b"connect_norito_free\n", self.stdout[:-1],
                       self.stdout + b"bad symbol\n", self.stdout + b"connect_norito_free\n"]:
            with mock.patch.object(inspection.subprocess, "run", return_value=self.result(stdout=stdout)):
                with self.assertRaises(ValueError):
                    inspection.inspect(self.library, self.inspector)

    def test_failed_or_noisy_inspector_fails(self) -> None:
        for changes in [{"returncode": 1}, {"stderr": b"warning"}, {"stdout": b""}]:
            with mock.patch.object(inspection.subprocess, "run", return_value=self.result(**changes)):
                with self.assertRaisesRegex(ValueError, "did not complete"):
                    inspection.inspect(self.library, self.inspector)

    def test_original_substitution_during_inspection_fails(self) -> None:
        def substitute(*args, **kwargs):
            self.library.write_bytes(elf32(alignment=16384))
            return self.result()
        with mock.patch.object(inspection.subprocess, "run", side_effect=substitute):
            with self.assertRaisesRegex(ValueError, "changed during"):
                inspection.inspect(self.library, self.inspector)

    def test_symbol_inspector_substitution_fails(self) -> None:
        def substitute(*args, **kwargs):
            self.inspector.write_bytes(b"different tool\n")
            return self.result()
        with mock.patch.object(inspection.subprocess, "run", side_effect=substitute):
            with self.assertRaisesRegex(ValueError, "changed during"):
                inspection.inspect(self.library, self.inspector)

    def test_symlink_hardlink_and_relative_originals_fail(self) -> None:
        symlink = self.root / "linked-library"
        symlink.symlink_to(self.library)
        for path in [symlink, Path("libconnect_norito_bridge.so")]:
            with self.assertRaises(ValueError):
                inspection.original(path)
        hardlink = self.root / "hardlinked-library"
        os.link(self.library, hardlink)
        with self.assertRaisesRegex(ValueError, "single-link"):
            inspection.original(self.library)


if __name__ == "__main__":
    unittest.main()
