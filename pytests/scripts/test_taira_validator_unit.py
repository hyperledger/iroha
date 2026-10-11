"""Exercise rendered native signer-descriptor custody and the one-shot first boot with disposable fixtures."""
import ast
import importlib.util
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts/taira_validator_unit.py"
SPEC = importlib.util.spec_from_file_location("taira_validator_unit_under_test", SCRIPT)
unit = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(unit)

FRESH_KEY = "--sumeragi-assert-fresh-key"


class ValidatorUnitTests(unittest.TestCase):
    def amendment_fixture(self, directory):
        root = Path(directory).resolve()
        source_dir, output_dir = root / "installed", root / "next"
        source_dir.mkdir(mode=0o700)
        output_dir.mkdir(mode=0o700)
        source = source_dir / "iroha3d-taira-validator-1.service"
        output = output_dir / source.name
        # Disposable configs stand in for native-owned files. The helper may
        # inspect metadata, but must never open either body or any signer.
        config, amended = root / "beacon.toml", root / "beacon.next.toml"
        for path in (config, amended):
            path.write_bytes(b"fixture-private-config")
            path.chmod(0o600)
        old_hash, new_hash = "a" * 64, "b" * 64
        code = unit.launcher("taira-validator-1", "/absent/runtime", "/absent/beacon")
        code = code.replace("cmd = ['/srv/taira/taira-validator-1/current/bin/iroha3d_taira', '--config', '/srv/taira/taira-validator-1/current/config/config.toml', '--sora']",
                            f"cmd = {['/private/runtime/current/bin/iroha3d_taira', '--sora', '--config', str(config), '--config-blake3', old_hash]!r}")
        text = unit.render("taira-validator-1", "/absent/runtime", "/absent/beacon")
        lines = ["ExecStart=/usr/bin/python3 -c " + unit.systemd_argument(code) if line.startswith("ExecStart=") else line for line in text.splitlines()]
        source.write_text("\n".join(lines) + "\n")
        source.chmod(0o644)
        info = amended.stat()
        receipt = {
            "schema": "iroha.taira.torii-rate-config-amend.v1", "source_path": str(config),
            "source_config_blake3": old_hash, "output_path": str(amended),
            "output_config_blake3": new_hash,
            "request_budgets": {"torii.query_rate_per_authority_per_sec": 1000000,
                                "torii.query_burst_per_authority": 10000000},
            "unchanged_optional_sections": ["recipient-lookup"],
            "output_metadata": {"device": info.st_dev, "inode": info.st_ino, "uid": info.st_uid,
                                "mode": 0o600, "links": 1, "bytes": info.st_size},
        }
        receipt_path = root / "native-receipt.json"
        receipt_path.write_text(json.dumps(receipt))
        receipt_path.chmod(0o600)
        return source, receipt_path, output, receipt, config, amended

    def test_rate_amendment_changes_only_bound_hash_without_opening_private_files(self):
        with tempfile.TemporaryDirectory() as directory:
            source, receipt_path, output, receipt, config, amended = self.amendment_fixture(directory)
            before = source.read_bytes()
            opened = []
            actual_open = os.open
            def public_only(path, flags, *arguments, **keywords):
                opened.append(Path(path))
                self.assertNotIn(Path(path), (config, amended))
                self.assertFalse(str(path).startswith("/absent/"))
                return actual_open(path, flags, *arguments, **keywords)
            with patch.object(unit.os, "open", side_effect=public_only):
                self.assertEqual(unit.amend_unit("taira-validator-1", source, receipt_path, output), output)
            self.assertEqual(source.read_bytes(), before)
            self.assertEqual(output.read_bytes(), before.replace(b"a" * 64, b"b" * 64, 1))
            self.assertEqual(stat.S_IMODE(output.stat().st_mode), 0o644)
            self.assertEqual(unit.unit_config_binding(output.read_bytes()), (str(config), "b" * 64))
            self.assertEqual(set(opened), {source, receipt_path, output, output.parent})
            with self.assertRaises(FileExistsError):
                unit.amend_unit("taira-validator-1", source, receipt_path, output)
            self.assertEqual(output.read_bytes(), before.replace(b"a" * 64, b"b" * 64, 1))

    def test_rate_amendment_rejects_invalid_receipts_before_creating_output(self):
        for mutation in ("schema", "unknown", "source", "hash", "uppercase", "zero", "boolean", "field",
                         "optional", "metadata", "duplicate", "oversized", "second-hash", "second-cmd"):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as directory:
                source, receipt_path, output, receipt, _, _ = self.amendment_fixture(directory)
                if mutation == "schema": receipt["schema"] = "retired"
                elif mutation == "unknown": receipt["private_config"] = "forbidden"
                elif mutation == "source": receipt["source_path"] = "/absent/config.toml"
                elif mutation == "hash": receipt["source_config_blake3"] = "c" * 64
                elif mutation == "uppercase": receipt["output_config_blake3"] = "B" * 64
                elif mutation in ("zero", "boolean"): receipt["request_budgets"]["torii.query_burst_per_authority"] = 0 if mutation == "zero" else True
                elif mutation == "field": receipt["request_budgets"]["torii.enabled"] = 1
                elif mutation == "optional": receipt["unchanged_optional_sections"] = ["mcp"]
                elif mutation == "metadata": receipt["output_metadata"]["inode"] += 1
                elif mutation == "second-hash": source.write_text(source.read_text() + "# " + "a" * 64 + "\n")
                elif mutation == "second-cmd":
                    prefix = "ExecStart=/usr/bin/python3 -c "
                    lines = source.read_text().splitlines()
                    index = next(index for index, line in enumerate(lines) if line.startswith(prefix))
                    code = json.loads(lines[index][len(prefix):]).replace("cmd = [", "cmd = []\ncmd = [", 1)
                    lines[index] = prefix + unit.systemd_argument(code)
                    source.write_text("\n".join(lines) + "\n")
                receipt_path.write_text(json.dumps(receipt))
                if mutation == "duplicate": receipt_path.write_text(receipt_path.read_text().replace('"schema":', '"schema": "duplicate", "schema":', 1))
                if mutation == "oversized": receipt_path.write_bytes(b" " * (64 * 1024 + 1))
                expected = "one literal daemon argv" if mutation == "second-cmd" else ".*"
                with self.assertRaisesRegex(ValueError, expected):
                    unit.amend_unit("taira-validator-1", source, receipt_path, output)
                self.assertFalse(output.exists())

    def test_rate_amendment_rejects_untrusted_public_inputs_and_config_metadata(self):
        for target in ("unit", "receipt", "config", "amended"):
            for mutation in ("mode", "link", "symlink", "fifo"):
                with self.subTest(target=target, mutation=mutation), tempfile.TemporaryDirectory() as directory:
                    source, receipt_path, output, _, config, amended = self.amendment_fixture(directory)
                    path = {"unit": source, "receipt": receipt_path, "config": config, "amended": amended}[target]
                    if mutation == "mode": path.chmod(0o666)
                    elif mutation == "link": os.link(path, str(path) + ".linked")
                    elif mutation == "symlink":
                        retained = Path(str(path) + ".retained")
                        path.rename(retained)
                        path.symlink_to(retained)
                    else:
                        path.unlink()
                        os.mkfifo(path, 0o600)
                    with self.assertRaises((ValueError, OSError)):
                        unit.amend_unit("taira-validator-1", source, receipt_path, output)
                    self.assertFalse(output.exists())

    def test_rate_amendment_removes_owned_output_when_source_changes_during_write(self):
        with tempfile.TemporaryDirectory() as directory:
            source, receipt_path, output, _, _, _ = self.amendment_fixture(directory)
            actual_open = os.open
            def mutate_before_publish(path, flags, *arguments, **keywords):
                if Path(path) == output:
                    with source.open("ab") as file:
                        file.write(b"# concurrent change\n")
                return actual_open(path, flags, *arguments, **keywords)
            with patch.object(unit.os, "open", side_effect=mutate_before_publish), self.assertRaisesRegex(ValueError, "input changed"):
                unit.amend_unit("taira-validator-1", source, receipt_path, output)
            self.assertFalse(output.exists())

    def test_rate_amendment_cli_is_exclusive_and_emits_only_fresh_output_path(self):
        with tempfile.TemporaryDirectory() as directory:
            source, receipt_path, output, _, _, _ = self.amendment_fixture(directory)
            base = [sys.executable, str(SCRIPT), "--role", "taira-validator-1", "--amend-unit", str(source),
                    "--rate-config-receipt", str(receipt_path), "--output", str(output)]
            for extra in (["--runtime-key", "/absent/key"], ["--config-file", "beacon.toml"], ["--arm-first-boot"]):
                result = subprocess.run(base + extra, capture_output=True, text=True, timeout=10)
                self.assertEqual(result.returncode, 2, result.stderr)
                self.assertFalse(output.exists())
            result = subprocess.run(base, capture_output=True, text=True, timeout=10)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stdout, str(output) + "\n")
            self.assertEqual(result.stderr, "")

    def fixture(self, directory, name, size):
        path = Path(directory) / name
        path.write_bytes(bytes((index % 251 for index in range(size))))
        path.chmod(0o600)
        return path

    def inputs(self, directory):
        return (
            self.fixture(directory, "runtime", 71),
            self.fixture(directory, "beacon.norito", 257),
        )

    def state(self, paths):
        # Disposable stand-in for /var/lib/taira/ROLE beside the fixture signers.
        root = Path(paths[0]).parent / "state"
        if not root.exists():
            root.mkdir(mode=0o700)
        return root

    def arm(self, paths):
        return Path(unit.arm_first_boot("taira-validator-1", state_root=str(self.state(paths))))

    def place_token(self, path):
        path.touch(mode=0o600)
        path.chmod(0o600)
        return path

    def execute(self, paths, *, beacon=True, reached_exec=True, occupy=False, config_file="config.toml",
                fresh_key=False, exec_outcome="fail", during_staging=None):
        runtime, credential = paths
        state_root = self.state(paths)
        code = unit.launcher(
            "taira-validator-1", str(runtime),
            str(credential) if beacon else None, config_file=config_file, state_root=str(state_root),
        )
        # Execute the actual generated custody body in an isolated process.
        # The exec boundary observes inherited files, then either raises to
        # exercise production cleanup or ends the process like a real exec,
        # which never returns to the launcher. Fixture bytes never enter output.
        # `during_staging` changes the state root at the first signer read,
        # after the launcher's initial first-boot check and before its exec.
        driver = r'''
import json, os, sys
request = json.load(sys.stdin)
seen = False
owned = None
if request["occupy"]:
    owned = os.open(request["paths"][0], os.O_RDONLY)
    os.dup2(owned, 200, inheritable=True)
if request["during_staging"] is not None:
    signer_read = os.readv
    mutated = []
    def mutate_then_read(descriptor, buffers):
        if not mutated:
            mutated.append(request["during_staging"])
            if request["during_staging"] == "replace-token":
                # A new inode created beside the old one, then renamed over it.
                replacement = request["token"] + ".replacement"
                os.close(os.open(replacement, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600))
                os.rename(replacement, request["token"])
            else:
                os.mkdir(os.path.join(request["state_root"], "sumeragi-records"), 0o700)
        return signer_read(descriptor, buffers)
    os.readv = mutate_then_read
def observe_exec(executable, argv):
    global seen
    seen = True
    assert executable == argv[0]
    expected_argv = ["/srv/taira/taira-validator-1/current/bin/iroha3d_taira",
                     "--config", "/srv/taira/taira-validator-1/current/config/" + request["config_file"],
                     "--sora"]
    if request["fresh_key"]:
        expected_argv.append("--sumeragi-assert-fresh-key")
    assert argv == expected_argv, argv
    # A first-boot token never survives into the daemon's lifetime.
    assert not os.path.lexists(request["token"])
    expected = [(198, request["paths"][0])]
    if request["beacon"]:
        expected.append((200, request["paths"][1]))
    else:
        try: os.fstat(200)
        except OSError: pass
        else: raise AssertionError("bootstrap must not invent a beacon descriptor")
    for descriptor, source in expected:
        info = os.fstat(descriptor)
        assert info.st_mode & 0o7777 == 0o600 and info.st_nlink == 1
        assert os.get_inheritable(descriptor)
        with open(source, "rb") as file:
            assert os.read(descriptor, info.st_size + 1) == file.read()
        assert info.st_ino != os.stat(source).st_ino
    if request["exec_outcome"] == "replace":
        sys.stdout.write(json.dumps({"exec": argv}))
        sys.stdout.flush()
        os._exit(0)
    raise RuntimeError("simulated exec failure")
os.execv = observe_exec
failure = None
try:
    exec(compile(request["code"], "<rendered-unit>", "exec"), {})
except (OSError, RuntimeError) as error:
    failure = str(error)
assert seen == request["reached_exec"], failure
if owned is not None:
    assert os.fstat(200).st_ino == os.stat(request["paths"][0]).st_ino
    os.close(200)
    os.close(owned)
sys.stdout.write(json.dumps({"failure": failure}))
'''
        result = subprocess.run(
            [sys.executable, "-c", driver],
            input=json.dumps({"code": code, "paths": list(map(str, paths)),
                              "beacon": beacon, "reached_exec": reached_exec,
                              "occupy": occupy, "config_file": config_file,
                              "fresh_key": fresh_key, "exec_outcome": exec_outcome,
                              "during_staging": during_staging, "state_root": str(state_root),
                              "token": str(state_root / "sumeragi-first-boot")}),
            text=True, capture_output=True, timeout=10, check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        return json.loads(result.stdout)

    def assert_no_launch_copies(self, paths):
        for descriptor, path in zip((198, 200), paths):
            self.assertFalse(Path(str(path) + f".fd{descriptor}").exists())

    def assert_token(self, token):
        info = token.lstat()
        self.assertTrue(stat.S_ISREG(info.st_mode))
        self.assertEqual((stat.S_IMODE(info.st_mode), info.st_nlink, info.st_size, info.st_uid),
                         (0o600, 1, 0, os.geteuid()))

    def test_beacon_stage_uses_independent_inherited_copy_and_cleans_failed_exec(self):
        with tempfile.TemporaryDirectory() as directory:
            paths = self.inputs(directory)
            originals = [path.read_bytes() for path in paths]
            for config_file in unit.CONFIG_FILES:
                with self.subTest(config_file=config_file):
                    self.execute(paths, config_file=config_file)
                    self.assert_no_launch_copies(paths)
                    self.assertEqual([path.read_bytes() for path in paths], originals)

    def test_initial_bootstrap_never_opens_or_fabricates_a_beacon_credential(self):
        with tempfile.TemporaryDirectory() as directory:
            paths = self.inputs(directory)
            paths[1].unlink()
            self.execute(paths, beacon=False)
            self.assert_no_launch_copies(paths)

    def test_missing_or_untrusted_beacon_cleans_prior_descriptors(self):
        for mutation in ("missing", "mode", "hardlink", "symlink", "empty", "oversized"):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as directory:
                paths = self.inputs(directory)
                credential = paths[1]
                originals = [path.read_bytes() for path in paths[:1]]
                if mutation == "missing":
                    credential.unlink()
                elif mutation == "mode":
                    credential.chmod(0o644)
                elif mutation == "hardlink":
                    os.link(credential, Path(directory) / "second-link")
                elif mutation == "symlink":
                    target = Path(directory) / "retained-beacon"
                    credential.rename(target)
                    credential.symlink_to(target)
                elif mutation == "empty":
                    credential.write_bytes(b"")
                elif mutation == "oversized":
                    with credential.open("r+b") as file:
                        file.truncate(16 * 1024 * 1024 + 1)
                self.execute(paths, reached_exec=False)
                self.assert_no_launch_copies(paths)
                self.assertEqual([path.read_bytes() for path in paths[:1]], originals)

    def test_occupied_beacon_descriptor_is_never_replaced_or_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            paths = self.inputs(directory)
            self.execute(paths, reached_exec=False, occupy=True)
            self.assert_no_launch_copies(paths)

    def test_stale_untrusted_beacon_launch_copy_is_never_followed(self):
        with tempfile.TemporaryDirectory() as directory:
            paths = self.inputs(directory)
            target = self.fixture(directory, "other-owner-file", 19)
            original = target.read_bytes()
            launch = Path(str(paths[1]) + ".fd200")
            launch.symlink_to(target)
            self.execute(paths, reached_exec=False)
            self.assertTrue(launch.is_symlink())
            self.assertEqual(target.read_bytes(), original)
            for descriptor, path in zip((198,), paths):
                self.assertFalse(Path(str(path) + f".fd{descriptor}").exists())

    def test_render_only_uses_paths_and_rejects_cross_role_collisions(self):
        with patch.object(os, "open", side_effect=AssertionError("render must not read keys")):
            rendered = unit.render("taira-validator-2", "/private/runtime/a", "/private/runtime/c")
        self.assertIn("Type=exec", rendered)
        self.assertIn(".fd", unit.CUSTODY)
        for credential in ("relative", "/private/runtime/a", "/private/runtime/a.fd198",
                           "/var/lib/taira/taira-validator-2/sumeragi-first-boot"):
            with self.subTest(credential=credential), self.assertRaises(ValueError):
                unit.render("taira-validator-2", "/private/runtime/a", credential)
        for config_file in ("", "/etc/other.toml", "../beacon.toml", "config.toml/../beacon.toml",
                            "beacon.toml\nExecStart=/bin/false", "$(touch nope)", "%n.toml", "other.toml"):
            with self.subTest(config_file=config_file), self.assertRaises(ValueError):
                unit.render("taira-validator-2", "/private/runtime/a",
                            "/private/runtime/c", config_file=config_file)
        self.assertEqual(
            unit.render("taira-validator-2", "/private/runtime/a"),
            unit.render("taira-validator-2", "/private/runtime/a", config_file="config.toml"),
        )

    def test_cli_publishes_exact_public_unit_without_opening_credentials(self):
        for config_file in (None, *unit.CONFIG_FILES):
            with self.subTest(config_file=config_file), tempfile.TemporaryDirectory() as directory:
                output = Path(directory) / "iroha3d-taira-validator-3.service"
                command = [sys.executable, str(SCRIPT), "--role", "taira-validator-3",
                           "--runtime-key", "/absent/runtime",
                           "--global-beacon-credential", "/absent/beacon", "--output", str(output)]
                if config_file is not None:
                    command += ["--config-file", config_file]
                first = subprocess.run(command, capture_output=True, text=True, timeout=10)
                self.assertEqual(first.returncode, 0, first.stderr)
                self.assertEqual(output.stat().st_mode & 0o777, 0o644)
                original = output.read_bytes()
                self.assertEqual(original.decode(), unit.render(
                    "taira-validator-3", "/absent/runtime", "/absent/beacon",
                    config_file=config_file or "config.toml"))
                second = subprocess.run(command, capture_output=True, text=True, timeout=10)
                self.assertNotEqual(second.returncode, 0)
                self.assertEqual(output.read_bytes(), original)
                for invalid in ("../beacon.toml", "beacon.toml\nExecStart=/bin/false", "other.toml"):
                    rejected = subprocess.run(command + ["--config-file", invalid], capture_output=True, text=True, timeout=10)
                    self.assertEqual(rejected.returncode, 2)
                    self.assertEqual(output.read_bytes(), original)

    def test_first_boot_asserts_the_fresh_key_once_and_no_restart_repeats_it(self):
        # Initial and beacon units carry the same one-shot first boot.
        for config_file in unit.CONFIG_FILES:
            beacon = config_file == "beacon.toml"
            with self.subTest(config_file=config_file), tempfile.TemporaryDirectory() as directory:
                paths = self.inputs(directory)
                originals = [path.read_bytes() for path in paths]
                token = self.arm(paths)
                self.assert_token(token)
                root = token.parent
                first = self.execute(paths, beacon=beacon, config_file=config_file,
                                     fresh_key=True, exec_outcome="replace")
                self.assertEqual(first["exec"][-1], FRESH_KEY)
                self.assertFalse(os.path.lexists(token))
                # The daemon's installation event writes the configured safety history.
                (root / "sumeragi-records").mkdir(mode=0o700)
                (root / "sumeragi-installation.log").write_bytes(b"installation entries")
                restart = self.execute(paths, beacon=beacon, config_file=config_file, exec_outcome="replace")
                self.assertNotIn(FRESH_KEY, restart["exec"])
                # A lost record store and log look fresh but never renew the assertion.
                shutil.rmtree(root / "sumeragi-records")
                (root / "sumeragi-installation.log").unlink()
                after_loss = self.execute(paths, beacon=beacon, config_file=config_file, exec_outcome="replace")
                self.assertNotIn(FRESH_KEY, after_loss["exec"])
                self.execute(paths, beacon=beacon, config_file=config_file)
                self.assert_no_launch_copies(paths)
                self.assertFalse(os.path.lexists(token))
                self.assertEqual([path.read_bytes() for path in paths], originals)

    def test_first_boot_is_refused_while_safety_history_exists(self):
        for history in ("records", "log", "both", "dangling-records-link"):
            with self.subTest(history=history), tempfile.TemporaryDirectory() as directory:
                paths = self.inputs(directory)
                originals = [path.read_bytes() for path in paths]
                root = self.state(paths)
                records, log = root / "sumeragi-records", root / "sumeragi-installation.log"
                if history in ("records", "both"):
                    records.mkdir(mode=0o700)
                if history in ("log", "both"):
                    log.write_bytes(b"installation entries")
                if history == "dangling-records-link":
                    records.symlink_to(root / "absent")
                token = root / "sumeragi-first-boot"
                with self.assertRaisesRegex(RuntimeError, "safety history already exists"):
                    unit.arm_first_boot("taira-validator-1", state_root=str(root))
                self.assertFalse(os.path.lexists(token))
                # A token beside existing history (placed by hand, or restored
                # with a key store) never starts the daemon and is never consumed.
                self.place_token(token)
                for _ in range(2):
                    refused = self.execute(paths, reached_exec=False)
                    self.assertIn("safety history already exists", refused["failure"])
                    self.assert_token(token)
                    self.assert_no_launch_copies(paths)
                self.assertEqual([path.read_bytes() for path in paths], originals)

    def test_untrusted_first_boot_token_or_state_root_never_starts_the_daemon(self):
        for mutation in ("mode", "hardlink", "symlink", "nonempty", "directory", "writable-state-root"):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as directory:
                paths = self.inputs(directory)
                root = self.state(paths)
                token = root / "sumeragi-first-boot"
                if mutation == "symlink":
                    token.symlink_to(self.place_token(root / "retained-token"))
                elif mutation == "directory":
                    token.mkdir(mode=0o700)
                else:
                    self.place_token(token)
                if mutation == "mode":
                    token.chmod(0o640)
                elif mutation == "hardlink":
                    os.link(token, root / "second-link")
                elif mutation == "nonempty":
                    token.write_bytes(b"x")
                elif mutation == "writable-state-root":
                    root.chmod(0o730)
                refused = self.execute(paths, reached_exec=False)
                self.assertRegex(refused["failure"], "untrusted Taira (first-boot token|validator state root)")
                self.assertTrue(os.path.lexists(token))
                self.assert_no_launch_copies(paths)

    def test_failed_first_boot_exec_restores_the_unused_token(self):
        with tempfile.TemporaryDirectory() as directory:
            paths = self.inputs(directory)
            token = self.arm(paths)
            # The driver checks that the token is gone when exec is attempted.
            self.execute(paths, fresh_key=True)
            self.assert_token(token)
            self.assert_no_launch_copies(paths)
            retried = self.execute(paths, fresh_key=True, exec_outcome="replace")
            self.assertEqual(retried["exec"][-1], FRESH_KEY)
            self.assertFalse(os.path.lexists(token))

    def test_first_boot_changed_during_staging_never_asserts_or_consumes_the_token(self):
        for change, failure in (("replace-token", "first-boot token changed while staging"),
                                ("create-records", "safety history already exists")):
            with self.subTest(change=change), tempfile.TemporaryDirectory() as directory:
                paths = self.inputs(directory)
                originals = [path.read_bytes() for path in paths]
                token = self.arm(paths)
                armed = token.lstat()
                refused = self.execute(paths, reached_exec=False, during_staging=change)
                self.assertIn(failure, refused["failure"])
                # The launcher never removes a token it did not use.
                self.assert_token(token)
                if change == "replace-token":
                    self.assertNotEqual(token.lstat().st_ino, armed.st_ino)
                else:
                    self.assertEqual(token.lstat().st_ino, armed.st_ino)
                self.assert_no_launch_copies(paths)
                self.assertEqual([path.read_bytes() for path in paths], originals)

    def test_first_boot_refusal_precedes_any_signer_access(self):
        for mutation, failure in (("records", "safety history already exists"),
                                  ("log", "safety history already exists"),
                                  ("mode", "untrusted Taira first-boot token")):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as directory:
                paths = self.inputs(directory)
                root = self.state(paths)
                token = self.place_token(root / "sumeragi-first-boot")
                if mutation == "records":
                    (root / "sumeragi-records").mkdir(mode=0o700)
                elif mutation == "log":
                    (root / "sumeragi-installation.log").write_bytes(b"installation entries")
                else:
                    token.chmod(0o640)
                # Without signers, only a check that runs before staging can report the token.
                for path in paths:
                    path.unlink()
                refused = self.execute(paths, reached_exec=False)
                self.assertIn(failure, refused["failure"])
                self.assertTrue(os.path.lexists(token))
                self.assert_no_launch_copies(paths)

    def test_arming_requires_a_private_state_root_and_never_replaces_a_token(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "state"
            with self.assertRaises(FileNotFoundError):
                unit.arm_first_boot("taira-validator-2", state_root=str(root))
            target = Path(directory) / "real-state"
            target.mkdir(mode=0o700)
            root.symlink_to(target)
            with self.assertRaisesRegex(RuntimeError, "state root"):
                unit.arm_first_boot("taira-validator-2", state_root=str(root))
            self.assertEqual(list(target.iterdir()), [])
            root.unlink()
            root.mkdir(mode=0o700)
            root.chmod(0o770)
            with self.assertRaisesRegex(RuntimeError, "state root"):
                unit.arm_first_boot("taira-validator-2", state_root=str(root))
            root.chmod(0o700)
            token = Path(unit.arm_first_boot("taira-validator-2", state_root=str(root)))
            self.assertEqual(token, root / "sumeragi-first-boot")
            self.assert_token(token)
            before = token.lstat()
            with self.assertRaisesRegex(RuntimeError, "already exists"):
                unit.arm_first_boot("taira-validator-2", state_root=str(root))
            after = token.lstat()
            self.assertEqual((before.st_ino, before.st_mtime_ns), (after.st_ino, after.st_mtime_ns))
            token.unlink()
            token.symlink_to(target / "absent")
            with self.assertRaisesRegex(RuntimeError, "already exists"):
                unit.arm_first_boot("taira-validator-2", state_root=str(root))
            self.assertEqual(list(target.iterdir()), [])
            for invalid in ("relative", "/private/../state", "//state", "/state/"):
                with self.subTest(state_root=invalid), self.assertRaises(ValueError):
                    unit.arm_first_boot("taira-validator-2", state_root=invalid)
            with self.assertRaises(ValueError):
                unit.arm_first_boot("taira-validator-5", state_root=str(root))

    def test_cli_arming_takes_only_a_role(self):
        base = [sys.executable, str(SCRIPT), "--arm-first-boot"]
        self.assertEqual(subprocess.run(base, capture_output=True, text=True, timeout=10).returncode, 2)
        for extra in (["--output", "/absent/iroha3d-taira-validator-1.service"], ["--runtime-key", "/absent/runtime"],
                      ["--global-beacon-credential", "/absent/beacon"],
                      ["--config-file", "config.toml"]):
            with self.subTest(extra=extra):
                rejected = subprocess.run(base + ["--role", "taira-validator-1", *extra],
                                          capture_output=True, text=True, timeout=10)
                self.assertEqual(rejected.returncode, 2)
                self.assertIn("--arm-first-boot takes only --role", rejected.stderr)
        render_without_inputs = subprocess.run(
            [sys.executable, str(SCRIPT), "--role", "taira-validator-1", "--output", "/absent/iroha3d-taira-validator-1.service"],
            capture_output=True, text=True, timeout=10)
        self.assertEqual(render_without_inputs.returncode, 2)
        self.assertIn("--runtime-key", render_without_inputs.stderr)

    @unittest.skipIf(os.path.lexists("/var/lib/taira/taira-validator-4"), "host has a real Taira validator state root")
    def test_cli_arming_refuses_without_the_canonical_state_root(self):
        result = subprocess.run([sys.executable, str(SCRIPT), "--arm-first-boot", "--role", "taira-validator-4"],
                                capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 1)
        self.assertIn("first boot not armed", result.stderr)
        self.assertEqual(result.stdout, "")
        self.assertFalse(os.path.lexists("/var/lib/taira/taira-validator-4"))

    def test_rendered_launcher_keeps_one_daemon_argv_and_the_role_first_boot_paths(self):
        for role in unit.ROLES:
            for config_file in unit.CONFIG_FILES:
                with self.subTest(role=role, config_file=config_file):
                    arguments = (role, "/private/runtime/a", "/private/runtime/c")
                    code = unit.launcher(*arguments, config_file=config_file)
                    rendered = unit.render(*arguments, config_file=config_file)
                    bindings = {}
                    for node in ast.parse(code).body:
                        if (isinstance(node, ast.Assign) and len(node.targets) == 1
                                and isinstance(node.targets[0], ast.Name)):
                            bindings.setdefault(node.targets[0].id, []).append(node.value)
                    literal = {name: [ast.literal_eval(value) for value in bindings[name]]
                               for name in ("runtime_key", "cmd", "state_root",
                                            "first_boot_token", "sumeragi_history")}
                    root = "/var/lib/taira/" + role
                    current = "/srv/taira/" + role + "/current"
                    # Unit capture and daemon updates parse exactly one literal daemon argv.
                    self.assertEqual(literal["cmd"], [[current + "/bin/iroha3d_taira", "--config",
                                                       current + "/config/" + config_file, "--sora"]])
                    self.assertEqual(literal["runtime_key"], ["/private/runtime/a"])
                    self.assertEqual(literal["state_root"], [root])
                    self.assertEqual(literal["first_boot_token"], [root + "/sumeragi-first-boot"])
                    self.assertEqual(literal["sumeragi_history"],
                                     [(root + "/sumeragi-records", root + "/sumeragi-installation.log")])
                    self.assertIn("WorkingDirectory=" + root + "\n", rendered)
                    self.assertEqual(len([line for line in rendered.split("\\n") if line.startswith("cmd = ['")]), 1)
                    self.assertEqual(code.count(FRESH_KEY), 1)
                    self.assertIn("launch_argv = cmd + ['" + FRESH_KEY + "']", code)


if __name__ == "__main__":
    unittest.main()
