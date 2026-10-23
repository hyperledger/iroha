"""Exercise the OSS scanner's prebuild contract without Docker, Cargo or signals.

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
BINARIES = (
    "iroha3d",
    "iroha3d_taira",
    "sorafs_governance_dag",
    "sorafs_external_software_signer",
    "iroha",
    "kagami",
    "koto",
    "attachment_sanitizer",
)
STAGES = (
    "release binaries and kagami",
    "codec crypto VM and P2P tests",
    "iroha_sumeragi simulator tests",
)


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
            "OSS_SCANNER_BUDGET_MINUTES": "28",
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
            cwd=self.root,
            env=self.environment,
            text=True,
            capture_output=True,
            check=False,
            timeout=10,
        )

    def instructions(self) -> list[str]:
        return re.findall(r"^RUN (?:[^\n]*\\\n)*[^\n]*", self.source, re.MULTILINE)

    def wrapper(self) -> Path:
        marker = "COPY --chmod=0755 <<'EOF' /usr/local/bin/within-budget\n"
        program = self.source.split(marker, 1)[1].split("\nEOF", 1)[0]
        # Simulate timeout's exit statuses without timing out or killing anything.
        self.executable("timeout", '#!/bin/sh\nshift 2\nexec "$@"\n')
        return self.executable("within-budget", self.relocate(program) + "\n")

    def compile_instruction(self) -> str:
        builds = [line for line in self.instructions() if 'within-budget "' in line]
        self.assertEqual(len(builds), 1, "all compile steps must share one Docker RUN")
        self.assertLess(
            self.source.index("RUN cargo fetch --locked"),
            self.source.index(builds[0]),
        )
        return self.relocate(builds[0][4:])

    def fake_build_tools(self) -> None:
        self.executable(
            "cargo",
            "#!/bin/sh\n"
            + self.relocate(
                '{ printf "cargo"; printf " %s" "$@"; printf "\\n"; } '
                '>> /opt/oss-scanner/events\n'
                'if [ -e /opt/oss-scanner/unpinned ]; then exit 92; fi\n'
                'count=0\n'
                'if [ -f /opt/oss-scanner/count ]; then count=$(cat /opt/oss-scanner/count); fi\n'
                'count=$((count + 1))\n'
                'echo "$count" > /opt/oss-scanner/count\n'
                'if [ "$count" = "${FAIL_STAGE:-0}" ]; then exit "${CARGO_STATUS:-42}"; fi\n'
                'touch /opt/oss-scanner/unpinned\n'
            ),
        )
        self.executable(
            "pin-iroha-plonk",
            "#!/bin/sh\n"
            + self.relocate(
                'echo pin >> /opt/oss-scanner/events\n'
                'rm -f /opt/oss-scanner/unpinned\n'
            ),
        )
        self.executable(
            "du",
            "#!/bin/sh\n"
            + self.relocate('echo "du $*" >> /opt/oss-scanner/events\n'),
        )
        self.executable(
            "sha256sum",
            "#!/bin/sh\n"
            + self.relocate(
                'printf "%s\\n" "$*" >> /opt/oss-scanner/checksums\n'
                'if [ "$1" = --check ]; then exit "${CHECKSUM_STATUS:-0}"; fi\n'
            ),
        )

    def test_timeout_status_is_distinct_from_compile_failure_and_sigkill(self) -> None:
        wrapper = self.wrapper()
        (self.state / "deadline").write_text("11800\n", encoding="utf-8")
        for command_status, description in (
            (0, "done in 0s"),
            (124, "deadline"),
            (42, "failed with exit status 42"),
            (137, "failed with exit status 137"),
        ):
            with self.subTest(command_status=command_status):
                result = self.run_shell(
                    f"{shlex.quote(str(wrapper))} compile sh -c 'exit {command_status}'"
                )
                self.assertEqual(result.returncode, command_status, result.stderr)
                self.assertIn(description, result.stdout)
                self.assertIn(description, (self.state / "build.log").read_text())

    def test_less_than_one_minute_remaining_fails_without_launching_command(self) -> None:
        wrapper = self.wrapper()
        self.executable(
            "must-not-run",
            "#!/bin/sh\n" + self.relocate('touch /opt/oss-scanner/invoked\n'),
        )
        for remaining in (-1, 0, 59):
            with self.subTest(remaining=remaining):
                (self.state / "deadline").write_text(f"{10000 + remaining}\n", encoding="utf-8")
                result = self.run_shell(f"{shlex.quote(str(wrapper))} compile must-not-run")
                self.assertEqual(result.returncode, 124, result.stderr)
                self.assertIn("deadline", result.stdout)
                self.assertFalse((self.state / "invoked").exists())

        (self.state / "deadline").write_text("10060\n", encoding="utf-8")
        result = self.run_shell(f"{shlex.quote(str(wrapper))} compile must-not-run")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue((self.state / "invoked").exists())

    def test_compilation_resets_stale_cached_deadline_and_shares_budget(self) -> None:
        (self.state / "deadline").write_text("1\n", encoding="utf-8")
        budget = re.search(r"^ARG OSS_SCANNER_BUDGET_MINUTES=(\d+)$", self.source, re.MULTILINE)
        self.assertIsNotNone(budget)
        self.environment["OSS_SCANNER_BUDGET_MINUTES"] = budget.group(1)
        self.fake_build_tools()
        self.executable(
            "within-budget",
            "#!/bin/sh\n"
            + self.relocate(
                'printf "%s:%s\\n" "$1" "$(cat /opt/oss-scanner/deadline)" '
                '>> /opt/oss-scanner/observed\n'
                'shift\nexec "$@"\n'
            ),
        )
        result = self.run_shell(self.compile_instruction())
        self.assertEqual(result.returncode, 0, result.stderr)
        expected_deadline = 10000 + int(budget.group(1)) * 60
        self.assertEqual(
            (self.state / "observed").read_text().splitlines(),
            [f"{name}:{expected_deadline}" for name in STAGES],
        )

    def test_prebuild_graphs_preserve_all_binaries_and_test_suites(self) -> None:
        self.wrapper()
        self.fake_build_tools()
        result = self.run_shell(self.compile_instruction())
        self.assertEqual(result.returncode, 0, result.stderr)
        events = (self.state / "events").read_text().splitlines()
        self.assertEqual(len(events), 9)
        self.assertEqual(events[1::3], ["pin"] * 3)
        self.assertEqual(events[2::3], ["du -sh target"] * 3)
        commands = [shlex.split(event) for event in events[::3]]

        def values(arguments: list[str], flag: str) -> set[str]:
            return {arguments[index + 1] for index, value in enumerate(arguments) if value == flag}

        release, tests, simulator = commands
        self.assertEqual(release[:2], ["cargo", "build"])
        self.assertEqual(values(release, "-p"), {
            "irohad", "iroha_cli", "iroha_torii", "kotodama_toolchain", "iroha_kagami"
        })
        self.assertEqual(values(release, "--bin"), set(BINARIES))
        self.assertEqual(values(release, "--features"), {"irohad/external-software-signer-bin"})
        self.assertEqual(values(tests, "-p"), {"norito", "iroha_crypto", "ivm", "iroha_p2p"})
        self.assertEqual(values(tests, "--features"), set())
        self.assertEqual(values(simulator, "-p"), {"iroha_sumeragi"})
        self.assertEqual(values(simulator, "--features"), {"sim"})
        for command in commands:
            self.assertIn("--locked", command)
            self.assertIn("--timings", command)
            self.assertNotIn("--release", command)
        for command in (tests, simulator):
            self.assertEqual(command[:2], ["cargo", "test"])
            self.assertIn("--no-run", command)
            # Only build flags and package/feature selection may follow `cargo test`.
            # This rejects test-name filters, target narrowing and excluded packages.
            remaining = command[2:]
            while remaining:
                flag = remaining.pop(0)
                if flag in {"-p", "--features"}:
                    remaining.pop(0)
                else:
                    self.assertIn(flag, {"--locked", "--no-run", "--timings"})
        checksums = (self.state / "checksums").read_text().splitlines()
        self.assertEqual(len(checksums), 2)
        self.assertEqual(set(checksums[0].split()), {f"target/debug/{name}" for name in BINARIES})
        self.assertEqual(checksums[1], f"--check {self.state}/binaries.sha256")

    def test_error_or_timeout_stops_remaining_prebuilds(self) -> None:
        self.wrapper()
        self.fake_build_tools()
        for stage in (1, 2, 3):
            for status in (42, 124, 137):
                with self.subTest(stage=stage, status=status):
                    for name in ("events", "count", "unpinned"):
                        (self.state / name).unlink(missing_ok=True)
                    self.environment.update(FAIL_STAGE=str(stage), CARGO_STATUS=str(status))
                    result = self.run_shell(self.compile_instruction())
                    self.assertEqual(result.returncode, status, result.stderr)
                    events = (self.state / "events").read_text().splitlines()
                    self.assertEqual(sum(event.startswith("cargo ") for event in events), stage)
                    self.assertEqual(events.count("pin"), stage - 1)
                    self.assertEqual(events.count("du -sh target"), stage - 1)

    def test_shipping_binary_checksum_failure_fails_prebuild(self) -> None:
        self.wrapper()
        self.fake_build_tools()
        self.environment["CHECKSUM_STATUS"] = "1"
        result = self.run_shell(self.compile_instruction())
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertEqual((self.state / "count").read_text().strip(), "3")

    def prepare_probe(self) -> str:
        debug = self.root / "target" / "debug"
        debug.mkdir(parents=True)
        for name in BINARIES:
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
        probes = [line for line in self.instructions() if "for bin in " in line]
        self.assertEqual(len(probes), 1)
        return self.relocate(probes[0][4:])

    def test_final_probe_checks_every_cli_without_launching_internal_subprocess(self) -> None:
        result = self.run_shell(self.prepare_probe())
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertCountEqual(
            (self.state / "invoked").read_text().splitlines(),
            [name + ":--help" for name in BINARIES if name != "attachment_sanitizer"],
        )
        for name in BINARIES[:-1]:
            self.assertIn(f"{name}: built, --help works", result.stdout)
        self.assertIn(
            "attachment_sanitizer: built, internal subprocess (no --help CLI)", result.stdout
        )

    def test_final_probe_fails_when_any_binary_is_missing(self) -> None:
        program = self.prepare_probe()
        for name in BINARIES:
            with self.subTest(name=name):
                binary = self.root / "target" / "debug" / name
                saved = binary.read_text()
                binary.unlink()
                (self.state / "build.log").unlink(missing_ok=True)
                result = self.run_shell(program)
                self.assertNotEqual(result.returncode, 0, result.stderr)
                self.assertIn(f"{name}: not built", result.stdout)
                binary.write_text(saved, encoding="utf-8")
                binary.chmod(0o755)

    def test_final_probe_fails_when_any_cli_help_fails(self) -> None:
        program = self.prepare_probe()
        for name in BINARIES[:-1]:
            with self.subTest(name=name):
                binary = self.root / "target" / "debug" / name
                saved = binary.read_text()
                binary.write_text("#!/bin/sh\nexit 42\n", encoding="utf-8")
                (self.state / "build.log").unlink(missing_ok=True)
                result = self.run_shell(program)
                self.assertNotEqual(result.returncode, 0, result.stderr)
                self.assertIn(f"{name}: built, but --help failed", result.stdout)
                binary.write_text(saved, encoding="utf-8")


if __name__ == "__main__":
    unittest.main()
