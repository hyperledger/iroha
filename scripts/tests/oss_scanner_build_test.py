"""Exercise the OSS scanner's build budget without Docker, Cargo or process signals.

Run with ``python3 -m unittest discover -s scripts/tests -p oss_scanner_build_test.py``.
Only the Python standard library and a POSIX shell are required.
"""

from __future__ import annotations

import os
from pathlib import Path
import re
import shlex
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
DOCKERFILE = ROOT / ".oss-scanner" / "Dockerfile"


class OssScannerBuildTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.state = self.root / "scanner state"
        self.state.mkdir()
        self.bin = self.root / "bin"
        self.bin.mkdir()
        self.environment = {
            **os.environ,
            "PATH": str(self.bin) + os.pathsep + os.environ.get("PATH", ""),
            "OSS_SCANNER_BUDGET_MINUTES": "30",
        }
        self.source = DOCKERFILE.read_text(encoding="utf-8")
        self.executable("date", "#!/bin/sh\necho 10000\n")

    def executable(self, name: str, source: str) -> Path:
        path = self.bin / name
        path.write_text(source, encoding="utf-8")
        path.chmod(0o755)
        return path

    def relocate(self, source: str) -> str:
        return source.replace("/opt/oss-scanner", shlex.quote(str(self.state)))

    def run_shell(self, source: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            ["sh", "-c", source],
            env=self.environment,
            text=True,
            capture_output=True,
            check=False,
            timeout=10,
        )

    def wrapper(self) -> Path:
        marker = "COPY --chmod=0755 <<'EOF' /usr/local/bin/within-budget\n"
        program = self.source.split(marker, 1)[1].split("\nEOF", 1)[0]
        # Simulate timeout's exit statuses without actually timing out or killing anything.
        self.executable("timeout", '#!/bin/sh\nshift 2\nexec "$@"\n')
        return self.executable("within-budget", self.relocate(program) + "\n")

    def compile_instruction(self) -> str:
        instructions = re.findall(r"^RUN (?:[^\n]*\\\n)*[^\n]*", self.source, re.MULTILINE)
        builds = [instruction for instruction in instructions if 'within-budget "' in instruction]
        self.assertEqual(len(builds), 1, "all compile steps must share one Docker RUN")
        self.assertLess(
            self.source.index("RUN cargo fetch --locked"),
            self.source.index(builds[0]),
        )
        return self.relocate(builds[0][4:])

    def test_timeout_status_is_distinct_from_compile_failure_and_sigkill(self) -> None:
        wrapper = self.wrapper()
        (self.state / "deadline").write_text("11800\n", encoding="utf-8")
        for command_status, expected_status, description in (
            (0, 0, "done in 0s"),
            (124, 0, "stopped at the deadline"),
            (42, 42, "failed with exit status 42"),
            (137, 137, "failed with exit status 137"),
        ):
            with self.subTest(command_status=command_status):
                result = self.run_shell(
                    f"{shlex.quote(str(wrapper))} compile sh -c 'exit {command_status}'"
                )
                self.assertEqual(result.returncode, expected_status, result.stderr)
                self.assertIn(description, result.stdout)
                self.assertIn(description, (self.state / "build.log").read_text())

    def test_exhausted_budget_skips_command_without_failure(self) -> None:
        wrapper = self.wrapper()
        (self.state / "deadline").write_text("9999\n", encoding="utf-8")
        result = self.run_shell(f"{shlex.quote(str(wrapper))} compile command-must-not-run")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("skipped", result.stdout)

    def test_compilation_resets_stale_cached_deadline_and_shares_budget(self) -> None:
        (self.state / "deadline").write_text("1\n", encoding="utf-8")
        self.executable(
            "within-budget",
            "#!/bin/sh\n"
            + self.relocate(
                'printf "%s:%s\\n" "$1" "$(cat /opt/oss-scanner/deadline)" '
                ">> /opt/oss-scanner/observed\n"
            ),
        )
        result = self.run_shell(self.compile_instruction())
        self.assertEqual(result.returncode, 0, result.stderr)
        observed = (self.state / "observed").read_text().splitlines()
        self.assertEqual(
            observed,
            [
                name + ":11800"
                for name in (
                    "release binaries",
                    "kagami",
                    "norito tests",
                    "iroha_sumeragi simulator tests",
                    "iroha_crypto tests",
                    "ivm tests",
                    "iroha_p2p tests",
                )
            ],
        )

    def test_compile_failure_prevents_later_prebuild_steps(self) -> None:
        self.executable(
            "within-budget",
            "#!/bin/sh\n"
            + self.relocate('echo "$1" >> /opt/oss-scanner/observed\n')
            + "exit 23\n",
        )
        result = self.run_shell(self.compile_instruction())
        self.assertEqual(result.returncode, 23, result.stderr)
        self.assertEqual((self.state / "observed").read_text(), "release binaries\n")

    def test_final_probe_checks_release_clis_without_launching_internal_subprocess(self) -> None:
        debug = self.root / "target" / "debug"
        debug.mkdir(parents=True)
        names = (
            "iroha3d",
            "iroha3d_taira",
            "sorafs_governance_dag",
            "sorafs_external_software_signer",
            "iroha",
            "kagami",
            "koto",
            "attachment_sanitizer",
        )
        for name in names:
            binary = debug / name
            binary.write_text(
                "#!/bin/sh\n"
                + self.relocate(
                    f'printf "%s:%s\\n" {shlex.quote(name)} "$*" >> /opt/oss-scanner/invoked\n'
                )
                + ("exit 1\n" if name == "attachment_sanitizer" else '[ "$*" = "--help" ]\n'),
                encoding="utf-8",
            )
            binary.chmod(0o755)
        probe = re.search(
            r"^RUN for bin (?:[^\n]*\\\n)*[^\n]*", self.source, re.MULTILINE
        )
        self.assertIsNotNone(probe)
        program = f"cd {shlex.quote(str(self.root))}\n" + self.relocate(probe.group()[4:])
        result = self.run_shell(program)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(
            (self.state / "invoked").read_text().splitlines(),
            [name + ":--help" for name in names if name != "attachment_sanitizer"],
        )
        for name in names[:-1]:
            self.assertIn(f"{name}: built, --help works", result.stdout)
        self.assertIn(
            "attachment_sanitizer: built, internal subprocess (no --help CLI)", result.stdout
        )
        self.assertNotIn("--help failed", result.stdout)

        # Missing internal tools and genuine CLI failures must remain visible in the report.
        (debug / "attachment_sanitizer").unlink()
        (debug / "koto").write_text("#!/bin/sh\nexit 1\n", encoding="utf-8")
        (self.state / "build.log").unlink()
        result = self.run_shell(program)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("attachment_sanitizer: not built", result.stdout)
        self.assertIn("koto: built, but --help failed", result.stdout)


if __name__ == "__main__":
    unittest.main()
