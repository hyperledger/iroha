"""Exercise the generated launcher with disposable signer inputs and no daemon."""

import importlib.util
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch


SOURCE = Path(__file__).resolve().parents[1] / "taira_validator_unit.py"
SPEC = importlib.util.spec_from_file_location("taira_validator_unit", SOURCE)
UNIT = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(UNIT)


class ValidatorUnitTests(unittest.TestCase):
    def test_cli_output_matches_public_artifact_mode_under_private_umask(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            role = UNIT.ROLES[0]
            output = root / f"iroha3d-{role}.service"
            command = [sys.executable, "-I", str(SOURCE), "--role", role,
                       "--runtime-key", str(root / "absent-key"),
                       "--output", str(output)]
            result = subprocess.run(command, capture_output=True, timeout=10, umask=0o077)
            self.assertEqual(result.returncode, 0, result.stderr.decode())
            self.assertEqual(output.stat().st_mode & 0o7777, 0o644)
            expected = UNIT.render(role, str(root / "absent-key"))
            self.assertEqual(output.read_text(), expected)
            self.assertEqual(set(root.iterdir()), {output})
            before = output.stat()
            repeated = subprocess.run(command, capture_output=True, timeout=10, umask=0o077)
            self.assertNotEqual(repeated.returncode, 0)
            self.assertEqual(output.read_text(), expected)
            after = output.stat()
            for field in ("st_ino", "st_mode", "st_size", "st_mtime_ns", "st_ctime_ns"):
                self.assertEqual(getattr(before, field), getattr(after, field))

    def test_render_does_not_open_signers_and_waits_for_launcher_exec(self):
        with patch("os.open", side_effect=AssertionError("renderer read an input")):
            for role in UNIT.ROLES:
                text = UNIT.render(role, "/runtime/key", "/runtime/credential")
                self.assertIn("[Service]\nType=exec\n", text)
                self.assertEqual(text.count("ExecStart="), 1)
                self.assertIn("ExecStart=/usr/bin/python3 -c ", text)
                self.assertIn("UMask=0077\n", text)

    def test_generated_launcher_passes_independent_fds_and_cleans_failed_exec(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            key, credential = root / "key", root / "credential"
            for path, size in ((key, 71), (credential, 257)):
                path.write_bytes(os.urandom(size))
                path.chmod(0o600)
            before = {path: path.read_bytes() for path in (key, credential)}
            code = UNIT.launcher(UNIT.ROLES[0], str(key), str(credential))
            # Run descriptor manipulation in a child. Intercept only the final
            # exec: the generated custody code does the real opens and copies.
            child = """
import os
from pathlib import Path
key, credential, code = __import__('sys').argv[1:]
expected = [Path(key).read_bytes(), Path(credential).read_bytes()]
class StopExec(Exception): pass
def observe_exec(path, argv):
    assert argv == ['/srv/taira/taira-validator-1/current/bin/iroha3d_taira',
                    '--config', '/srv/taira/taira-validator-1/current/config/config.toml', '--sora']
    assert path == argv[0]
    for fd, value in zip((198, 200), expected):
        assert os.get_inheritable(fd)
        assert os.read(fd, len(value) + 1) == value
    raise StopExec()
os.execv = observe_exec
try:
    exec(compile(code, '<generated-launcher>', 'exec'))
except StopExec:
    pass
else:
    raise AssertionError('launcher did not reach foreground exec')
for fd in (198, 200):
    try: os.fstat(fd)
    except OSError: pass
    else: raise AssertionError('launch descriptor leaked')
assert not Path(key + '.fd198').exists()
assert not Path(credential + '.fd200').exists()
assert Path(key).read_bytes() == expected[0]
assert Path(credential).read_bytes() == expected[1]
"""
            result = subprocess.run(
                [sys.executable, "-I", "-c", child, str(key), str(credential), code],
                capture_output=True, timeout=10, check=False,
            )
            self.assertEqual(result.returncode, 0, result.stderr.decode())
            self.assertEqual(result.stdout, b"")
            self.assertEqual({path: path.read_bytes() for path in (key, credential)}, before)

    def test_rejects_ambiguous_roles_paths_and_overlapping_launch_copies(self):
        for path in ("relative", "//runtime/key", "/runtime/../key", "/runtime/key\n"):
            with self.subTest(path=path), self.assertRaises(ValueError):
                UNIT.render(UNIT.ROLES[0], path, "/runtime/credential")
        for role, key, credential in (("unknown", "/runtime/key", "/runtime/credential"),
                                (UNIT.ROLES[0], "/runtime/key", "/runtime/key.fd198")):
            with self.assertRaises(ValueError):
                UNIT.render(role, key, credential)


if __name__ == "__main__":
    unittest.main()
