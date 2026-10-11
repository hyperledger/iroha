"""Exercise locked fuzz Cargo forwarding without a retired prover dependency."""

from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts/cargo_fuzz_locked_cargo.sh"


class LockedFuzzCargoTests(unittest.TestCase):
    """The fake child records arguments; these tests do not qualify fuzz execution."""

    def test_locked_offline_arguments_precede_preserved_rustc_arguments(self) -> None:
        """No Halo2 checkout or environment variable is needed by the proxy."""
        with tempfile.TemporaryDirectory(prefix="fuzz proxy ") as temporary:
            directory = Path(temporary)
            cargo = directory / "cargo"
            output = directory / "arguments.json"
            cargo.write_text(
                "#!/usr/bin/env python3\n"
                "import json, os, sys\n"
                "open(os.environ['FUZZ_PROXY_TEST_OUTPUT'], 'w').write(json.dumps(sys.argv[1:]))\n"
            )
            cargo.chmod(0o755)
            environment = os.environ.copy()
            environment.update(
                IROHA_FUZZ_REAL_CARGO=str(cargo),
                IROHA_FUZZ_NIGHTLY="nightly-test",
                IROHA_FUZZ_LOCKFILE=str(directory / "fuzz lock.toml"),
                FUZZ_PROXY_TEST_OUTPUT=str(output),
            )
            for name in ["IROHA_FUZZ_HALO2_AXIOM", "IROHA_FUZZ_HALO2CURVES_AXIOM"]:
                environment.pop(name, None)
            for command in ["build", "rustc"]:
                result = subprocess.run(
                    ["bash", str(SCRIPT), command, "--bin", "a target", "--", "-C", "panic=abort"],
                    env=environment,
                    capture_output=True,
                    text=True,
                    check=False,
                )
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(
                    json.loads(output.read_text()),
                    [
                        "+nightly-test", command, "--bin", "a target",
                        "-Zunstable-options", "--lockfile-path", str(directory / "fuzz lock.toml"),
                        "--locked", "--offline", "--jobs", "1", "--", "-C", "panic=abort",
                    ],
                )
            result = subprocess.run(
                ["bash", str(SCRIPT), "metadata"],
                env=environment,
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(result.returncode, 2)
            self.assertIn("unsupported cargo-fuzz child command", result.stderr)

    def test_nested_manifests_do_not_mount_retired_oracle_engines(self) -> None:
        """Native migrated consumers have no reason to patch the test-only oracle."""
        for relative in ["fuzz/Cargo.toml", "crates/fastpq_prover/fuzz/Cargo.toml"]:
            text = (ROOT / relative).read_text()
            for retired in ["halo2-axiom", "halo2curves-axiom", "halo2-base"]:
                self.assertNotIn(retired, text)


if __name__ == "__main__":
    unittest.main()
