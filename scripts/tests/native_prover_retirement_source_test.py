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
import tempfile
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

def has_retired_source(path: Path) -> bool:
    """Reject retired owners while permitting only retained build-output directories.

    A package cannot be rebuilt from a lockfile and target directory alone.
    Never follow symbolic links or traverse the warm target cache. Any other
    entry, including a manifest or source directory, restores a retired owner.
    """
    if path.is_symlink():
        return True
    if not path.exists():
        return False
    if not path.is_dir():
        return True
    for entry in path.iterdir():
        if entry.is_symlink():
            return True
        if entry.name == "target" and entry.is_dir():
            continue
        if entry.name == "Cargo.lock" and entry.is_file():
            continue
        return True
    return False


class NativeProverRetirementSourceTest(unittest.TestCase):
    """Require one native consumer path without resurrecting retired dispatch."""

    def test_external_oracle_and_vendor_owners_are_absent(self) -> None:
        for relative in (
            "crates/iroha_plonk_oracle",
            "ci/native_prover_oracle.py", "scripts/tests/native_prover_oracle_test.py",
        ):
            path = ROOT / relative
            self.assertFalse(path.exists() or path.is_symlink(), relative)
        for relative in (
            "vendor/halo2-axiom", "vendor/halo2-base", "vendor/halo2curves-axiom",
        ):
            self.assertFalse(has_retired_source(ROOT / relative), relative)

    def test_retired_source_detection_preserves_only_build_outputs(self) -> None:
        """Cache retention never permits a manifest, source owner or path redirect."""
        with tempfile.TemporaryDirectory(prefix="native-retirement-source-") as temporary:
            parent = Path(temporary)
            retired = parent / "retired"
            self.assertFalse(has_retired_source(retired))
            retired.mkdir()
            self.assertFalse(has_retired_source(retired))
            (retired / "target").mkdir()
            (retired / "Cargo.lock").write_text("# Retained build artifact.\n")
            self.assertFalse(has_retired_source(retired))
            for name, directory in (
                ("Cargo.toml", False), ("src", True), ("README.md", False), (".git", True),
            ):
                with self.subTest(unexpected=name):
                    entry = retired / name
                    entry.mkdir() if directory else entry.write_text("retired source\n")
                    self.assertTrue(has_retired_source(retired))
                    entry.rmdir() if directory else entry.unlink()
            for name in ("target", "Cargo.lock"):
                with self.subTest(wrong_type=name):
                    entry = retired / name
                    entry.rmdir() if entry.is_dir() else entry.unlink()
                    entry.write_text("not a directory\n") if name == "target" else entry.mkdir()
                    self.assertTrue(has_retired_source(retired))
                    entry.rmdir() if entry.is_dir() else entry.unlink()
                with self.subTest(symlink=name):
                    entry.symlink_to(parent / "missing")
                    self.assertTrue(has_retired_source(retired))
                    entry.unlink()
            linked = parent / "linked"
            linked.symlink_to(retired, target_is_directory=True)
            self.assertTrue(has_retired_source(linked))
            linked.unlink()
            linked.symlink_to(parent / "missing")
            self.assertTrue(has_retired_source(linked))
            regular = parent / "regular"
            regular.write_text("retired source\n")
            self.assertTrue(has_retired_source(regular))

    def test_native_library_has_no_external_oracle_configuration(self) -> None:
        source_dir = ROOT / "crates/iroha_plonk/src"
        sources = sorted(source_dir.rglob("*.rs"))
        self.assertTrue(sources)
        # The native source-identity build owner is required; it must not delegate
        # to a retired engine through either its entry or a helper.
        native_root = source_dir.parent
        sources.append(native_root / "build.rs")
        sources.extend(sorted((native_root / "build_support").rglob("*.rs")))
        for path in sources:
            source = path.read_text(encoding="utf-8")
            self.assertNotRegex(source, r"\b(?:iroha_plonk_oracle|ORACLE_BUILD)\b", str(path))
        manifest = (ROOT / "crates/iroha_plonk/Cargo.toml").read_text(encoding="utf-8")
        self.assertNotRegex(manifest, r"(?m)^\s*build\s*=")

    def test_retired_transcript_override_entrypoints_are_absent(self) -> None:
        """Proof admission and tests must use the descriptor-bound first-release API."""
        retired = re.compile(
            r"\b(?:create_proof_oracle|verify_full_oracle|accumulate_succinct_oracle|"
            r"with_transcript_repr_for_oracle)\b"
        )
        sources = sorted((ROOT / "crates/iroha_plonk/src").rglob("*.rs"))
        self.assertTrue(sources)
        for path in sources:
            self.assertNotRegex(path.read_text(encoding="utf-8"), retired, str(path))

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

    def test_retired_native_finality_circuits_are_absent(self) -> None:
        """Native finality must not retain unused recursive source circuits."""
        for module in ("bls12_381", "blake2b", "merkle"):
            source = ROOT / "crates/iroha_plonk_gadgets/src" / module
            self.assertFalse(source.exists(), str(source))
            self.assertFalse(source.with_suffix(".rs").exists(), str(source))
        library = (ROOT / "crates/iroha_plonk_gadgets/src/lib.rs").read_text(encoding="utf-8")
        verifier = (ROOT / "crates/iroha_plonk_recursion/src/verifier/mod.rs").read_text(encoding="utf-8")
        self.assertNotRegex(library, r"\b(?:mod|use)\s+(?:bls12_381|blake2b|merkle)\b")
        self.assertNotRegex(verifier, r"\b(?:bls381|Bls381Chip|bls12_381)\b")
        manifest = (ROOT / "crates/iroha_plonk_gadgets/Cargo.toml").read_text(encoding="utf-8")
        self.assertNotRegex(manifest, r"(?m)^\s*(?:ark-(?:bls12-381|ff|ec|serialize)|iroha_crypto)\s*=")

    def test_native_engine_wire_discriminants_stay_closed(self) -> None:
        source = (ROOT / "crates/iroha_data_model/src/zk.rs").read_text(encoding="utf-8")
        match = re.search(r"pub enum BackendTag\s*\{([^}]+)\}", source)
        self.assertIsNotNone(match)
        variants = re.findall(r"^\s*([A-Za-z_]\w*)\s*,\s*$", match.group(1), re.MULTILINE)
        self.assertEqual(variants, ["NativePipaRPasta", "Stark"])


if __name__ == "__main__":
    unittest.main()
