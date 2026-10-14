#!/usr/bin/env python3
"""Linux syscall component tests for the exact C helper; Android SELinux needs device tests."""
from concurrent.futures import ThreadPoolExecutor
import ctypes
import errno
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import tempfile
import threading
import unittest


@unittest.skipUnless(sys.platform == "linux", "requires the actual Linux renameat2 syscall")
class RenameTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.build = tempfile.TemporaryDirectory(prefix="probe-rename-build-")
        cls.addClassCleanup(cls.build.cleanup)
        output = Path(cls.build.name)
        source = Path(__file__).with_name("enrollment_probe_rename.c").resolve(strict=True)
        wrapper = output / "wrapper.c"
        wrapper.write_text('#define ENROLLMENT_PROBE_HOST_TEST 1\n#include "' + str(source) +
                           '"\nint test_publish(const char *p, const char *s, const char *t) { '
                           'return publish_in_directory(p, s, t); }\n')
        compiler = shutil.which("cc")
        if compiler is None:
            raise RuntimeError("A C compiler is required; an unexecuted test is not success")
        subprocess.run([compiler, "-std=c11", "-shared", "-fPIC", "-Wall", "-Wextra", "-Werror",
                        str(wrapper), "-o", str(output / "probe.so")], check=True)
        cls.library = ctypes.CDLL(str(output / "probe.so"))
        cls.library.test_publish.argtypes = [ctypes.c_char_p] * 3
        cls.library.test_publish.restype = ctypes.c_int

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="probe-rename-test-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.stage = ".kagemusha-publication-selected.stage"

    def write(self, name, body=b"original"):
        fd = os.open(self.root / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        try:
            self.assertEqual(len(body), os.write(fd, body))
            os.fsync(fd)
        finally:
            os.close(fd)
        return (self.root / name).stat()

    def publish(self, stage=None, target="target", parent=None):
        return self.library.test_publish(os.fsencode(parent or self.root),
                                         os.fsencode(stage or self.stage), os.fsencode(target))

    def test_atomic_move_consumes_stage_and_preserves_selected_inode(self):
        before = self.write(self.stage)
        self.assertEqual(0, self.publish())
        self.assertFalse((self.root / self.stage).exists())
        after = (self.root / "target").stat()
        self.assertEqual((before.st_dev, before.st_ino), (after.st_dev, after.st_ino))
        self.assertEqual((1, 0o600), (after.st_nlink, stat.S_IMODE(after.st_mode)))
        self.assertEqual(b"original", (self.root / "target").read_bytes())

    def test_existing_targets_never_replaced_even_for_identical_bytes(self):
        self.write(self.stage)
        for target, body in [("same", b"original"), ("different", b"other")]:
            selected = self.write(target, body)
            self.assertEqual(errno.EEXIST, self.publish(target=target))
            self.assertEqual(selected.st_ino, (self.root / target).stat().st_ino)
            self.assertEqual(body, (self.root / target).read_bytes())
            self.assertEqual(b"original", (self.root / self.stage).read_bytes())

    def test_target_symlink_and_directory_are_existing_targets(self):
        self.write(self.stage)
        (self.root / "link").symlink_to(self.stage)
        self.assertEqual(errno.EEXIST, self.publish(target="link"))
        self.assertTrue((self.root / "link").is_symlink())
        (self.root / "directory").mkdir(mode=0o700)
        self.assertEqual(errno.EEXIST, self.publish(target="directory"))
        self.assertTrue((self.root / "directory").is_dir())

    def test_unsafe_leaf_and_parent_components_are_refused(self):
        self.write(self.stage)
        for target in ["../outside", "a/b", ".", "..", "", "é", self.stage, "a" * 129]:
            self.assertEqual(errno.EINVAL, self.publish(target=target), target)
        for parent in [str(self.root) + "/.", str(self.root) + "//child", "relative"]:
            self.assertEqual(errno.EINVAL, self.publish(parent=parent), parent)
        self.assertFalse((self.root / "target").exists())

    def test_symlink_source_and_parent_and_nonregular_source_fail_closed(self):
        self.write("original")
        (self.root / self.stage).symlink_to("original")
        self.assertEqual(errno.ELOOP, self.publish())
        (self.root / self.stage).unlink()
        (self.root / self.stage).mkdir(mode=0o700)
        self.assertEqual(errno.EPERM, self.publish())
        (self.root / self.stage).rmdir()
        os.mkfifo(self.root / self.stage, 0o600)
        self.assertEqual(errno.EPERM, self.publish())
        (self.root / self.stage).unlink()
        self.write(self.stage)
        (self.root / "parent-link").symlink_to(self.root, target_is_directory=True)
        self.assertIn(self.publish(parent=self.root / "parent-link"), [errno.ELOOP, errno.ENOTDIR])
        self.assertFalse((self.root / "target").exists())

    def test_mode_and_multiple_links_cannot_be_repaired(self):
        self.write(self.stage)
        for mode in [0o644, 0o1600]:
            (self.root / self.stage).chmod(mode)
            self.assertEqual(errno.EPERM, self.publish())
            self.assertEqual(mode, stat.S_IMODE((self.root / self.stage).stat().st_mode))
        (self.root / self.stage).chmod(0o600)
        os.link(self.root / self.stage, self.root / "alias")
        self.assertEqual(errno.EPERM, self.publish())
        (self.root / "alias").unlink()
        for mode in [0o755, 0o1700]:
            self.root.chmod(mode)
            self.assertEqual(errno.EPERM, self.publish())
        self.root.chmod(0o700)
        self.assertFalse((self.root / "target").exists())

    def test_syscall_concurrency_has_one_winner_without_advisory_lock(self):
        with ThreadPoolExecutor(max_workers=2) as executor:
            for round_index in range(50):
                stages = [f".kagemusha-publication-{round_index}-{i}.stage" for i in range(2)]
                for i, stage in enumerate(stages):
                    self.write(stage, bytes([i]))
                gate = threading.Barrier(2)
                target = f"winner-{round_index}"
                def attempt(stage):
                    gate.wait(timeout=10)
                    return self.publish(stage, target)
                futures = [executor.submit(attempt, stage) for stage in stages]
                results = [future.result(timeout=10) for future in futures]
                self.assertEqual([0, errno.EEXIST], sorted(results))
                winner = results.index(0)
                loser = 1 - winner
                self.assertEqual(bytes([winner]), (self.root / target).read_bytes())
                self.assertFalse((self.root / stages[winner]).exists())
                self.assertEqual(bytes([loser]), (self.root / stages[loser]).read_bytes())


if __name__ == "__main__":
    unittest.main(verbosity=2)
