#!/usr/bin/env python3
"""Prevent retired generic proof engines from returning to first-release consumers.

This replaces guards that pinned the deleted Halo2 test shards. Mathematical
and admission behavior is covered by the native Rust proof/mutation suites;
these checks cover source and shipping dependency retirement only. The
external oracle is deleted. The separate Orchard dependency keeps its own
package identity and remains outside the retired Axiom stack.
"""

from __future__ import annotations

import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
RETIRED_SOURCES = (
    "halo2_backend.rs",
    "halo2_backend_tests.rs",
    "halo2_backend_01_tests.rs",
    "halo2_backend_02_tests.rs",
    "halo2_backend_03_tests.rs",
    "zk1_test_helpers.rs",
    "zkparse.rs",
    "zkparse",
)
MIGRATED_CONSUMERS = (
    "iroha_core_zk",
    "iroha_core",
    "iroha_js_host",
    "kaigi_zk",
    "sorafs_manifest",
)

class NativeProverRetirementSourceTest(unittest.TestCase):
    """Require one native consumer path without resurrecting retired dispatch."""

    def test_external_oracle_and_vendor_owners_are_absent(self) -> None:
        for relative in (
            "crates/iroha_plonk_oracle", "crates/iroha_plonk/build.rs",
            "vendor/halo2-axiom", "vendor/halo2-base", "vendor/halo2curves-axiom",
            "ci/native_prover_oracle.py", "scripts/tests/native_prover_oracle_test.py",
        ):
            self.assertFalse((ROOT / relative).exists(), relative)

    def test_native_library_has_no_external_oracle_configuration(self) -> None:
        source_dir = ROOT / "crates/iroha_plonk/src"
        sources = sorted(source_dir.rglob("*.rs"))
        self.assertTrue(sources)
        for path in sources:
            source = path.read_text(encoding="utf-8")
            self.assertNotRegex(source, r"\b(?:iroha_plonk_oracle|ORACLE_BUILD)\b", str(path))
        manifest = (ROOT / "crates/iroha_plonk/Cargo.toml").read_text(encoding="utf-8")
        self.assertNotRegex(manifest, r"(?m)^\s*build\s*=")

    def test_retired_sources_and_module_declarations_are_absent(self) -> None:
        source_dir = ROOT / "crates/iroha_core_zk/src"
        for name in RETIRED_SOURCES:
            self.assertFalse((source_dir / name).exists(), name)
        source = (source_dir / "lib.rs").read_text(encoding="utf-8")
        self.assertNotRegex(source, r"\bmod\s+(?:halo2_backend|zkparse|zk1_test_helpers)\s*;")

    def test_migrated_consumers_do_not_link_vendored_runtime_engines(self) -> None:
        retired = re.compile(r"\b(?:halo2[-_]axiom|halo2[-_]base|halo2[-_]ecc|snark[-_]verifier|halo2_proofs)\b")
        for consumer in MIGRATED_CONSUMERS:
            path = ROOT / "crates" / consumer / "Cargo.toml"
            runtime = False
            for line in path.read_text(encoding="utf-8").splitlines():
                stripped = line.split("#", 1)[0].strip()
                if stripped.startswith("["):
                    runtime = stripped == "[dependencies]" or (
                        stripped.startswith("[target.") and stripped.endswith(".dependencies]")
                    )
                if runtime:
                    self.assertNotRegex(stripped, retired, f"{consumer}: {line}")

    def test_native_engine_wire_discriminants_stay_closed(self) -> None:
        source = (ROOT / "crates/iroha_data_model/src/zk.rs").read_text(encoding="utf-8")
        match = re.search(r"pub enum BackendTag\s*\{([^}]+)\}", source)
        self.assertIsNotNone(match)
        variants = re.findall(r"^\s*([A-Za-z_]\w*)\s*,\s*$", match.group(1), re.MULTILINE)
        self.assertEqual(variants, ["NativePipaRPasta", "Stark"])


if __name__ == "__main__":
    unittest.main()
