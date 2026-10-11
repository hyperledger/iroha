#!/usr/bin/env python3
"""Verify ordinary C references retain the Swift SDK's dynamic native exports.

The isolated link fixture exercises archive extraction and dead stripping only;
real native ABI behavior remains covered by the full Swift/native consumer suite.
"""

from __future__ import annotations

import importlib.util
import json
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
TARGET = ROOT / "IrohaSwift/Sources/NoritoBridgeRetention"
SOURCE = TARGET / "NoritoBridgeRetention.c"
EXPORT_PATTERN = r"(?:connect_norito_|iroha_privacy_|soranet_mldsa_)[A-Za-z0-9_]+"


def retained_exports() -> list[str]:
    """Read the concrete function references from the maintained C table."""
    return re.findall(
        rf"\(NoritoBridgeExportReference\)({EXPORT_PATTERN}),",
        SOURCE.read_text(encoding="utf-8"),
    )


class SwiftNativeExportRetentionTests(unittest.TestCase):
    """Check the real retention source and its package dependency wiring."""

    def test_every_current_dynamic_export_has_a_direct_c_reference(self) -> None:
        swift = "\n".join(
            path.read_text(encoding="utf-8")
            for path in sorted((ROOT / "IrohaSwift/Sources").rglob("*.swift"))
        )
        named = set(re.findall(rf'"({EXPORT_PATTERN})"', swift))
        declared = set(re.findall(
            rf"\b({EXPORT_PATTERN})\s*\(",
            (ROOT / "crates/connect_norito_bridge/include/connect_norito_bridge.h")
            .read_text(encoding="utf-8") + SOURCE.read_text(encoding="utf-8"),
        ))
        exports = retained_exports()
        self.assertEqual(exports, sorted(set(exports)))
        self.assertEqual(set(exports), named & declared)
        loader = (ROOT / "IrohaSwift/Sources/IrohaSwift/NativeBridge.swift").read_text()
        required = loader.split("static let parliamentTimedOvnWalletRequiredSymbols", 1)[1]
        required = required.split("private typealias BridgeAbiVersionFn", 1)[0]
        self.assertTrue(set(re.findall(rf'"({EXPORT_PATTERN})"', required)) <= set(exports))

    def test_retention_and_admission_omit_retired_native_exports(self) -> None:
        policy_path = ROOT / "scripts/check_native_sdk_artifact.py"
        spec = importlib.util.spec_from_file_location("swift_retention_native_policy", policy_path)
        self.assertIsNotNone(spec)
        self.assertIsNotNone(spec.loader)
        policy = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(policy)
        loader = (ROOT / "IrohaSwift/Sources/IrohaSwift/NativeBridge.swift").read_text()
        inventory = set(retained_exports()) | set(re.findall(rf'"({EXPORT_PATTERN})"', loader))
        self.assertFalse(inventory & set(policy.RETIRED_PROTOCOL_SYMBOLS["c-jni"]))
        self.assertFalse({
            symbol for symbol in inventory
            if policy.is_retired_kagemusha_export(symbol)
        })

    def test_mldsa_declarations_match_the_canonical_owner(self) -> None:
        owner = (ROOT / "crates/soranet_pq/include/soranet_pq.h").read_text()
        retention = SOURCE.read_text()
        for symbol in retained_exports():
            if not symbol.startswith("soranet_mldsa_"):
                continue
            pattern = rf"int\s+{re.escape(symbol)}\s*\([^;]+\);"
            expected = re.search(pattern, owner)
            actual = re.search(pattern, retention)
            self.assertIsNotNone(expected, symbol)
            self.assertIsNotNone(actual, symbol)
            self.assertEqual(re.sub(r"\s+", "", actual.group()), re.sub(r"\s+", "", expected.group()))

    def test_safe_dependency_and_called_root_are_source_sealed(self) -> None:
        package = (ROOT / "IrohaSwift/Package.swift").read_text()
        self.assertNotIn(".unsafeFlags(", package)
        self.assertIn('name: "NoritoBridgeRetention"', package)
        self.assertIn('dependencies: [bridgeDependency]', package)
        loader = (ROOT / "IrohaSwift/Sources/IrohaSwift/NativeBridge.swift").read_text()
        self.assertIn("#if SWIFT_PACKAGE\nimport NoritoBridgeRetention\n#endif", loader)
        self.assertIn("_ = iroha_norito_bridge_retain_exports()", loader)
        seal = (ROOT / "scripts/norito_bridge_source_seal.py").read_text()
        self.assertIn('"IrohaSwift/Sources/NoritoBridgeRetention",', seal)

    def test_archive_extraction_retains_dynamic_exports_under_dead_stripping(self) -> None:
        compiler = shutil.which("clang") or shutil.which("cc")
        archiver = shutil.which("ar")
        self.assertIsNotNone(compiler, "a C compiler is required for the retention link fixture")
        self.assertIsNotNone(archiver, "an archive tool is required for the retention link fixture")
        exports = retained_exports()
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary).resolve()
            # These never-called definitions stand only for independent archive
            # entries. This fixture does not create an SDK artifact or fake ABI.
            stubs = base / "exports.c"
            stubs.write_text("\n".join(f"void {name}(void) {{}}" for name in exports) + "\n")
            subprocess.run([compiler, "-c", str(stubs), "-o", str(base / "exports.o")], check=True)
            archive = base / "libfixture.a"
            subprocess.run([archiver, "rcs", str(archive), str(base / "exports.o")], check=True)
            probe = base / "probe.c"
            probe.write_text(
                '#include "NoritoBridgeRetention.h"\n#include <dlfcn.h>\n'
                '#include <stdio.h>\n'
                'int main(void) {\n'
                f'  if (iroha_norito_bridge_retain_exports() != {len(exports)}) return 1;\n'
                + "".join(
                    f'  if (!dlsym(RTLD_DEFAULT, {json.dumps(name)})) return 2;\n'
                    for name in exports
                )
                + '  return 0;\n}\n'
            )
            linker = ["-Wl,-dead_strip"] if sys.platform == "darwin" else ["-Wl,--gc-sections", "-rdynamic", "-ldl"]
            command = [
                compiler, "-O2", "-Wall", "-Wextra", "-Werror",
                "-I", str(TARGET / "include"),
                "-I", str(ROOT / "crates/connect_norito_bridge/include"),
                str(SOURCE), str(probe), str(archive), *linker, "-o", str(base / "probe"),
            ]
            subprocess.run(command, check=True)
            subprocess.run([str(base / "probe")], check=True)
            # A count-only implementation has no native symbol references, so
            # the linker cannot extract the same dynamically queried archive.
            control = base / "without-retention.c"
            control.write_text(
                '#include "NoritoBridgeRetention.h"\n'
                f'size_t iroha_norito_bridge_retain_exports(void) {{ return {len(exports)}; }}\n'
            )
            subprocess.run([
                compiler, "-O2", "-I", str(TARGET / "include"),
                str(control), str(probe), str(archive), *linker, "-o", str(base / "without-retention"),
            ], check=True)
            result = subprocess.run([str(base / "without-retention")], check=False)
            self.assertEqual(result.returncode, 2)


if __name__ == "__main__":
    unittest.main()
