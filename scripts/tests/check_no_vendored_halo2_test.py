"""Dependency-path mutations for the first-release proof-stack retirement guard."""
from copy import deepcopy
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("no_vendored_halo2", ROOT / "scripts/check_no_vendored_halo2.py")
GUARD = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(GUARD)


def graph():
    names = ["wallet", "native", "halo2_proofs", "halo2curves", "iroha_plonk_oracle", "halo2-axiom"]
    return {
        "packages": [{"id": name, "name": name, "manifest_path": str(ROOT / "crates" / name / "Cargo.toml"), "publish": []} for name in names],
        "workspace_members": ["wallet", "native"],
        "resolve": {"nodes": [{"id": name, "deps": []} for name in names]},
    }


def edge(data, owner, dependency, kind=None, target=None):
    node = next(node for node in data["resolve"]["nodes"] if node["id"] == owner)
    node["deps"].append({"name": "renamed_alias", "pkg": dependency, "dep_kinds": [{"kind": kind, "target": target}]})


class RetirementGraphTests(unittest.TestCase):
    def test_native_and_separate_orchard_primitives_are_allowed(self):
        data = graph()
        edge(data, "wallet", "native")
        edge(data, "native", "halo2_proofs")
        edge(data, "native", "halo2curves")
        self.assertEqual(GUARD.violations(data, ROOT), [])

    def test_direct_transitive_build_and_foreign_target_dependencies_fail(self):
        for kind, target in [(None, None), ("build", None), (None, 'cfg(target_os = "android")')]:
            with self.subTest(kind=kind, target=target):
                data = graph()
                edge(data, "wallet", "native")
                edge(data, "native", "halo2-axiom", kind, target)
                self.assertIn("wallet -> native -> halo2-axiom", GUARD.violations(data, ROOT))

    def test_development_only_retired_edges_are_rejected(self):
        data = graph()
        edge(data, "native", "halo2-axiom", "dev")
        edge(data, "wallet", "iroha_plonk_oracle", "dev")
        self.assertIn("native -> halo2-axiom", GUARD.violations(data, ROOT))
        self.assertIn("wallet -> iroha_plonk_oracle", GUARD.violations(data, ROOT))

    def test_consumer_cannot_reach_the_retired_oracle_owner(self):
        data = graph()
        edge(data, "wallet", "iroha_plonk_oracle")
        self.assertIn("wallet -> iroha_plonk_oracle", GUARD.violations(data, ROOT))

    def test_all_retired_package_identities_fail_even_with_dependency_aliases(self):
        for name in GUARD.RETIRED:
            with self.subTest(name=name):
                data = graph()
                package = next(p for p in data["packages"] if p["id"] == "halo2-axiom")
                package["name"] = name
                edge(data, "wallet", "halo2-axiom")
                self.assertIn(f"wallet -> {name}", GUARD.violations(data, ROOT))

    def test_exact_nonpublishable_oracle_root_is_also_rejected(self):
        data = graph()
        data["workspace_members"].append("iroha_plonk_oracle")
        self.assertIn("iroha_plonk_oracle", GUARD.violations(data, ROOT))

    def test_missing_or_unknown_resolve_evidence_fails_closed(self):
        baseline = graph()
        edge(baseline, "wallet", "native")
        for mutation in ["node", "package", "kind", "empty"]:
            with self.subTest(mutation=mutation):
                data = deepcopy(baseline)
                if mutation == "node":
                    data["resolve"]["nodes"] = [n for n in data["resolve"]["nodes"] if n["id"] != "native"]
                elif mutation == "package":
                    data["packages"] = [p for p in data["packages"] if p["id"] != "native"]
                elif mutation == "kind":
                    data["resolve"]["nodes"][0]["deps"][0]["dep_kinds"][0]["kind"] = "unknown"
                else:
                    data["workspace_members"] = []
                with self.assertRaises(ValueError):
                    GUARD.violations(data, ROOT)

    def test_cycles_and_shared_dependencies_are_visited_once(self):
        data = graph()
        edge(data, "wallet", "native")
        edge(data, "native", "wallet")
        self.assertEqual(GUARD.violations(data, ROOT), [])

    def test_command_line_preserves_pass_and_failure_exit_status(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "metadata.json"
            for forbidden in [False, True]:
                data = graph()
                if forbidden:
                    edge(data, "wallet", "halo2-axiom")
                path.write_text(json.dumps(data))
                result = subprocess.run(
                    [sys.executable, str(ROOT / "scripts/check_no_vendored_halo2.py"), "--metadata", str(path)],
                    capture_output=True, text=True, check=False,
                )
                self.assertEqual(result.returncode, int(forbidden), result.stderr)
                self.assertIn("forbidden dependency path" if forbidden else "PASS", result.stderr if forbidden else result.stdout)


if __name__ == "__main__":
    unittest.main()
