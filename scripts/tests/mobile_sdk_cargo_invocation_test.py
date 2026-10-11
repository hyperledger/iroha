"""Test genuine Cargo cwd/config admission through command mocks, without builds."""

from __future__ import annotations

import argparse
import importlib.util
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[2]


def module(name: str):
    specification = importlib.util.spec_from_file_location(name, ROOT / "scripts" / (name + ".py"))
    value = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(value)
    return value


runner = module("run_mobile_hermetic_command")
seal = module("norito_bridge_source_seal")


class CargoInvocationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.base = Path(self.temporary.name).resolve()
        self.home = self.base / "home"
        self.root = self.home / "project"
        self.cache = self.base / "cargo-cache"
        self.invocation = self.base / "invocation"
        for path in (self.root, self.cache, self.invocation):
            path.mkdir(parents=True, mode=0o700)
        (self.root / "Cargo.lock").write_text("version = 4\n", encoding="utf-8")
        (self.root / "Cargo.toml").write_text("[workspace]\n", encoding="utf-8")
        self.cargo = mock.Mock()
        self.rustc = mock.Mock()
        self.rustdoc = mock.Mock()

    def metadata(self, invocation: str | None, effect=None):
        environment = {} if invocation is None else {"NORITO_BRIDGE_SEAL_CARGO_INVOCATION_DIR": invocation}
        with (
            mock.patch.dict(os.environ, environment, clear=True),
            mock.patch.object(seal, "source_seal_tools", return_value=(self.cargo, self.rustc, self.rustdoc, Path("/usr/bin/git"))),
            mock.patch.object(seal, "source_seal_environment", return_value={"CARGO_HOME": str(self.cache)}),
            mock.patch.object(seal, "run", return_value=b"{}", side_effect=effect) as command,
        ):
            seal.metadata(self.root, "aarch64-apple-darwin", self.root / "Cargo.lock")
        return command

    def test_metadata_uses_isolated_cwd_and_original_root_manifest(self) -> None:
        # A rejected config is a real ancestor of the source cwd, but is not an
        # ancestor of the explicitly selected actual Cargo invocation directory.
        config = self.home / ".cargo/config.toml"
        config.parent.mkdir()
        config.write_text('[build]\nrustc-wrapper = "/untrusted/wrapper"\n', encoding="utf-8")
        with self.assertRaisesRegex(RuntimeError, "overrides the compiler envelope"):
            self.metadata(None)
        command = self.metadata(str(self.invocation))
        self.assertEqual(command.call_args.args[0], self.invocation)
        arguments = command.call_args.args[2]
        self.assertEqual(arguments[arguments.index("--manifest-path") + 1], str(self.root / "Cargo.toml"))
        self.assertIn("--locked", arguments)
        self.assertIn("--offline", arguments)

    def test_actual_invocation_and_cache_configs_remain_strictly_checked(self) -> None:
        for config in (self.invocation / ".cargo/config.toml", self.cache / "config.toml"):
            with self.subTest(config=config):
                config.parent.mkdir(exist_ok=True)
                config.write_text('[env]\nSCCACHE_CLIENT_SIDE = "1"\n', encoding="utf-8")
                with self.assertRaisesRegex(RuntimeError, "forbids env"):
                    self.metadata(str(self.invocation))
                config.unlink()

    def test_metadata_refuses_new_effective_config_after_command(self) -> None:
        def create_config(*_args):
            config = self.invocation / ".cargo/config.toml"
            config.parent.mkdir()
            config.write_text("[net]\noffline = true\n", encoding="utf-8")
            return b"{}"
        with self.assertRaisesRegex(RuntimeError, "changed during invocation"):
            self.metadata(str(self.invocation), create_config)

    def test_private_canonical_cwd_and_ownership_are_required(self) -> None:
        accepted = runner.authenticate_cargo_invocation_directory(self.root, self.invocation)
        runner.recheck_cargo_invocation_directory(self.root, accepted)
        for path in (Path("relative"), self.base / "missing", self.root, self.home, self.root / "child"):
            with self.subTest(path=path):
                with self.assertRaises(RuntimeError):
                    runner.authenticate_cargo_invocation_directory(self.root, path)
        symbolic = self.base / "symbolic"
        symbolic.symlink_to(self.invocation, target_is_directory=True)
        with self.assertRaisesRegex(RuntimeError, "non-symbolic"):
            runner.authenticate_cargo_invocation_directory(self.root, symbolic)
        with mock.patch.object(runner.os, "geteuid", return_value=os.geteuid() + 1):
            with self.assertRaisesRegex(RuntimeError, "owned writable"):
                runner.authenticate_cargo_invocation_directory(self.root, self.invocation)
        self.invocation.chmod(0o755)
        with self.assertRaisesRegex(RuntimeError, "mode-0700"):
            runner.authenticate_cargo_invocation_directory(self.root, self.invocation)

    def test_replaced_invocation_directory_is_refused(self) -> None:
        observation = runner.authenticate_cargo_invocation_directory(self.root, self.invocation)
        self.invocation.rename(self.base / "retained-invocation")
        self.invocation.mkdir(mode=0o700)
        with self.assertRaisesRegex(RuntimeError, "invocation directory changed"):
            runner.recheck_cargo_invocation_directory(self.root, observation)

    def test_hermetic_runner_executes_command_in_authenticated_cwd(self) -> None:
        executable = Path(sys.executable).resolve(strict=True)
        environment = {key: "fixture" for key in runner.PROFILES["apple-macos"]}
        environment["CARGO_HOME"] = str(self.cache)
        environment[runner.WALLET_RUNTIME_AUTHORITY_INPUT] = "cbsi-release-v1"
        environment[runner.WALLET_RUNTIME_TRUST_INPUT] = "3" * 64
        tools = {name: runner.authenticate_regular_executable(name, str(executable)) for name in ("CARGO", "RUSTC", "RUSTDOC")}
        args = argparse.Namespace(profile="apple-macos", working_directory=self.invocation,
                                  assignments=list(environment.items()), command=[str(executable)])
        before = Path.cwd()
        os.chdir(self.root)
        try:
            with (
                mock.patch.object(runner, "parse_args", return_value=args),
                mock.patch.object(runner, "authenticate_cargo_environment", return_value=tools),
                mock.patch.object(runner.subprocess, "run", return_value=subprocess.CompletedProcess([], 0)) as command,
            ):
                self.assertEqual(runner.main(), 0)
            self.assertEqual(command.call_args.kwargs["cwd"], self.invocation)
            self.assertEqual(command.call_args.kwargs["env"], environment)
        finally:
            os.chdir(before)

    def test_parser_accepts_explicit_cwd_without_changing_environment_contract(self) -> None:
        with mock.patch.object(sys, "argv", ["runner", "--profile", "apple-macos", "--working-directory", str(self.invocation), "--", "/fixture/cargo", "build"]):
            args = runner.parse_args()
        self.assertEqual(args.working_directory, self.invocation)
        self.assertEqual(args.command, ["/fixture/cargo", "build"])
        self.assertEqual(args.assignments, [])


if __name__ == "__main__":
    unittest.main()
