#!/usr/bin/env python3
"""Check declared Apple profiles; actual five-slice compilation remains mandatory."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
import unittest

try:
    import tomllib
except ModuleNotFoundError:  # Python 3.10 uses the scripts dependency.
    import tomli as tomllib

ROOT = Path(__file__).resolve().parents[2]


class AppleNativeReleaseProfileTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.manifest = tomllib.loads((ROOT / "Cargo.toml").read_text())
        cls.bridge_manifest = tomllib.loads(
            (ROOT / "crates/connect_norito_bridge/Cargo.toml").read_text()
        )
        cls.release = cls.manifest["profile"]["release"]
        cls.apple = cls.manifest["profile"]["apple-release"]

    def test_final_c_abi_target_can_perform_full_graph_thin_lto(self) -> None:
        # These are source-profile controls, not fabricated Cargo unit-graph
        # evidence. The maintained builder compiles every actual staticlib slice.
        self.assertEqual(self.bridge_manifest["package"]["name"], "connect_norito_bridge")
        self.assertIn("privacy-production-enabled", self.bridge_manifest["features"])
        self.assertEqual(self.apple["inherits"], "release")
        self.assertEqual(self.apple["lto"], "thin")
        self.assertEqual(self.apple["package"]["connect_norito_bridge"]["opt-level"], 3)
        self.assertEqual(self.apple.get("panic", self.release.get("panic", "unwind")), "unwind")
        self.assertFalse(self.apple.get("incremental", self.release.get("incremental", False)))
        self.assertEqual(self.apple["strip"], "none")
        self.assertEqual(self.apple["package"]["connect_norito_bridge"]["strip"], "none")

    def test_dependency_optimization_and_host_loadability_are_retained(self) -> None:
        for name, level in (("iroha_data_model", 1), ("iroha_model_base", 1),
                            ("iroha_crypto", 3), ("iroha_core_zk", 3)):
            inherited = self.release.get("package", {}).get(name, {}).get(
                "opt-level", self.release.get("opt-level", 3)
            )
            actual = self.apple.get("package", {}).get(name, {}).get("opt-level", inherited)
            self.assertEqual(actual, level, name)
        self.assertEqual(self.release["build-override"]["strip"], "none")
        self.assertNotIn("build-override", self.apple)
        self.assertEqual(set(self.bridge_manifest["lib"]["crate-type"]),
                         {"staticlib", "cdylib", "rlib"})

    def test_packaging_limits_remain_the_existing_release_limits(self) -> None:
        specification = importlib.util.spec_from_file_location(
            "norito_archive_budget", ROOT / "scripts/validate_norito_bridge_archive.py"
        )
        self.assertIsNotNone(specification)
        self.assertIsNotNone(specification.loader)
        archive = importlib.util.module_from_spec(specification)
        sys.modules[specification.name] = archive
        specification.loader.exec_module(archive)
        self.assertEqual(archive.MAX_ENTRY_BYTES, 512 * 1024 * 1024)
        self.assertEqual(archive.MAX_ARCHIVE_BYTES, 1024 * 1024 * 1024)
        self.assertEqual(archive.MAX_TOTAL_UNCOMPRESSED_BYTES, 1024 * 1024 * 1024)

    def test_all_five_slice_commands_and_provenance_paths_use_the_same_profile(self) -> None:
        builder = (ROOT / "scripts/build_norito_xcframework.sh").read_text()
        self.assertEqual(builder.count("--crate-type staticlib --profile apple-release"), 5)
        self.assertIn('$CARGO_TARGET_DIR/$target_triple/apple-release/lib${LIB_CRATE_NAME}.a', builder)
        self.assertIn('--cargo-build-dir "$CARGO_TARGET_DIR/$target_triple/apple-release/build"', builder)
        self.assertNotIn('build --locked --offline --jobs 1 -p "$LIB_CRATE_NAME" --lib --release', builder)
        self.assertIn('-Wl,-all_load "$library"', builder)
        self.assertIn('"$PQCRYPTO_ARCHIVE_NORMALIZER"', builder)


if __name__ == "__main__":
    unittest.main()
