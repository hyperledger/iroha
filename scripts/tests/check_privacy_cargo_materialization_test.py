"""Exercise canonical graph materialization with real filesystem boundaries."""
from __future__ import annotations

import hashlib
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import types
import unittest

ROOT = Path(__file__).resolve().parents[2]
HELPER = ROOT / "ci/privacy_sdk_cargo_lockfile.sh"
OWNER = re.findall(
    r'^readonly PRIVACY_SDK_CANONICAL_CARGO_LOCK_SHA256=\\\n"([0-9a-f]{64})"$',
    HELPER.read_text(), re.MULTILINE,
)
assert len(OWNER) == 1


class CanonicalCargoMaterializationTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="privacy-graph-boundary-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        self.source = self.root / "source"
        self.source.mkdir()
        self.lock = self.source / "Cargo.lock"
        self.lock.write_bytes((ROOT / "Cargo.lock").read_bytes())
        self.assertEqual(hashlib.sha256(self.lock.read_bytes()).hexdigest(), OWNER[0])
        self.destination = self.root / "external/Cargo.lock"
        self.destination.parent.mkdir()

    def invoke(self, destination=None, state=None):
        command = '''set -euo pipefail
source "$1"
state="${5:-$(privacy_sdk_capture_optional_file_state "$2/Cargo.lock" graph "$4")}"
privacy_sdk_materialize_canonical_cargo_lock "$2" "$3" "$state" "$4"
'''
        return subprocess.run(
            ["/bin/bash", "-c", command, "snapshot-test", str(HELPER),
             str(self.source), str(destination or self.destination), sys.executable,
             state or ""], capture_output=True, text=True, check=False,
        )

    def assert_rejected(self, result):
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertFalse(self.destination.exists())

    def manifest(self, selected=None):
        return subprocess.run(
            ["/bin/bash", "-c", 'source "$1"; privacy_sdk_assert_stock_cargo_manifest "$2" "$3" "$4"',
             "manifest-test", str(HELPER), str(self.source),
             str(selected or self.source / "Cargo.toml"), sys.executable],
            capture_output=True, text=True, check=False,
        )

    def write_manifest_fixture(self):
        (self.source / "Cargo.toml").write_text(
            '[workspace]\nmembers = ["members/*"]\nexclude = ["members/excluded"]\n'
        )
        member = self.source / "members/allowed/Cargo.toml"
        member.parent.mkdir(parents=True)
        member.write_text('[package]\nname = "allowed"\nversion = "0.1.0"\n')
        return member

    def test_stock_manifest_accepts_root_and_explicit_member(self):
        member = self.write_manifest_fixture()
        for candidate in (self.source / "Cargo.toml", member):
            result = self.manifest(candidate)
            self.assertEqual(result.returncode, 0, result.stderr)

    def test_stock_manifest_rejects_graph_redirects(self):
        member = self.write_manifest_fixture()
        outside = self.root / "outside/Cargo.toml"
        outside.parent.mkdir()
        outside.write_text('[workspace]\n')
        excluded = self.source / "members/excluded/Cargo.toml"
        excluded.parent.mkdir()
        excluded.write_text('[package]\nname="excluded"\n')
        unlisted = self.source / "other/Cargo.toml"
        unlisted.parent.mkdir()
        unlisted.write_text('[package]\nname="other"\n')
        linked = self.source / "members/linked/Cargo.toml"
        linked.parent.mkdir()
        linked.symlink_to(member)
        for candidate in (outside, excluded, unlisted, linked, Path("Cargo.toml"),
                          member.parent / "missing.toml"):
            with self.subTest(candidate=candidate):
                result = self.manifest(candidate)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("not bound to the authenticated root", result.stderr)

    def test_stock_manifest_rejects_nested_and_redirected_workspaces(self):
        member = self.write_manifest_fixture()
        for contents in ('[workspace]\n', '[package]\nworkspace="../../../"\n'):
            with self.subTest(contents=contents):
                member.write_text(contents)
                result = self.manifest(member)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("not bound to the authenticated root", result.stderr)
        member.write_text('[package]\nname="allowed"\n')
        (member.parent.parent / "Cargo.toml").write_text('[workspace]\n')
        result = self.manifest(member)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("intermediate workspace", result.stderr)

    def test_stock_manifest_accepts_explicit_original_workspace(self):
        member = self.write_manifest_fixture()
        member.write_text('[package]\nworkspace="../.."\n')
        result = self.manifest(member)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_stock_cargo_policy_rejects_every_bootstrap_assignment(self):
        for value in ("", "0", "1"):
            with self.subTest(value=value):
                result = subprocess.run(
                    ["/bin/bash", "-c", 'source "$1"; privacy_sdk_reject_cargo_policy_environment "$2"',
                     "policy-test", str(HELPER), sys.executable],
                    env=dict(os.environ, RUSTC_BOOTSTRAP=value), capture_output=True, text=True,
                )
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("RUSTC_BOOTSTRAP", result.stderr)

    def test_snapshot_preserves_bytes_with_independent_readonly_inode(self):
        before = self.lock.stat()
        result = self.invoke()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.destination.read_bytes(), self.lock.read_bytes())
        self.assertNotEqual(self.destination.stat().st_ino, before.st_ino)
        self.assertEqual(self.destination.stat().st_nlink, 1)
        self.assertEqual(self.destination.stat().st_mode & 0o777, 0o400)
        self.assertEqual(self.lock.stat(), before)

    def test_real_selected_root_graph_matches_owner_and_materializes_independently(self):
        source = ROOT / "Cargo.lock"
        before = source.stat(), source.read_bytes()
        self.assertEqual(hashlib.sha256(before[1]).hexdigest(), OWNER[0])
        for selector in ("HEAD:Cargo.lock", ":Cargo.lock"):
            committed = subprocess.run(
                ["/usr/bin/git", "-C", str(ROOT), "show", selector],
                capture_output=True, check=True,
            ).stdout
            if committed == before[1]:
                self.assertEqual(committed, before[1], selector)
            else:
                # A development checkout can hold a reviewed graph newer than
                # HEAD/index. Those bytes must fail current physical-owner
                # authentication; release tracked-state guards remain separate.
                self.assertNotEqual(hashlib.sha256(committed).hexdigest(), OWNER[0], selector)
                try:
                    self.lock.write_bytes(committed)
                    self.assert_rejected(self.invoke())
                finally:
                    self.lock.write_bytes(before[1])
        command = '''set -euo pipefail
source "$1"
state="$(privacy_sdk_capture_optional_file_state "$2/Cargo.lock" graph "$4")"
privacy_sdk_materialize_canonical_cargo_lock "$2" "$3" "$state" "$4"
IROHA_PRIVACY_CARGO_LOCKFILE_PATH="$3" privacy_sdk_resolve_cargo_lockfile "$2" "$4"
'''
        result = subprocess.run(
            ["/bin/bash", "-c", command, "real-graph-test", str(HELPER),
             str(ROOT), str(self.destination), sys.executable],
            capture_output=True, text=True, check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), str(self.destination))
        self.assertEqual(self.destination.read_bytes(), before[1])
        self.assertEqual(hashlib.sha256(self.destination.read_bytes()).hexdigest(), OWNER[0])
        self.assertNotEqual((self.destination.stat().st_dev, self.destination.stat().st_ino),
                            (before[0].st_dev, before[0].st_ino))
        self.assertEqual(self.destination.stat().st_nlink, 1)
        self.assertEqual(self.destination.stat().st_mode & 0o777, 0o400)
        self.assertEqual((source.stat(), source.read_bytes()), before)

    def test_stale_graph_owner_rejects_current_authenticated_source(self):
        # Preceding reviewed digests are rejected fixtures, never alternate
        # selectors. Even a correct current physical seal cannot authorize them.
        stale_digests = (
            "f63ef61b2abd60f5dc71ec5cfffa5652c49b01ce1789be3ab9240ebe06d04698",
            "1c67e27eee71508ca7822f52851ec110ce1f78e74a50ec985f342f5baa91fb62",
            "c766e96ceedbad8f0a457746590ec5e5795934793bfc507aa3a5c3f2effee631",
            "6db7b8e403d3f0ceda056552ede710d5f57b2c423290640f368b51e7f4c91ddd",
            "398cd15f1b51bc25d673acc766f98c8910446246a2ba33b0e97f17332bf57d40",
            "4ac28ef33c97060d246652c755e2cfb7780351e8cf1741c4e58c7712e82b9fdd",
            "4c038f2fa5625ac018c5e8b0cb96f0af6390025dab943b27896e37cb405254b4",
            "5947516819f9e3a9a391ec61e432f9de98ef3614c384c0483c179a46ac1930f9",
            "e25b69246098fb3f1454c4e20975d0752d4ea6e2319cbd8970f6e32f02c9354f",
        )
        for stale_digest in stale_digests:
            with self.subTest(stale_digest=stale_digest):
                self.assertNotEqual(stale_digest, OWNER[0])
                state = self.run_python_owner("privacy_sdk_file_seal", [self.lock])
                self.assertEqual(state.returncode, 0, state.stderr)
                before = self.lock.stat(), self.lock.read_bytes()
                result = self.run_python_owner(
                    "privacy_sdk_materialize_canonical_cargo_lock",
                    [self.source, self.destination, "present:" + state.stdout.strip(), stale_digest],
                )
                self.assert_rejected(result)
                self.assertIn("authenticated reviewed state", result.stderr)
                self.assertEqual((self.lock.stat(), self.lock.read_bytes()), before)

    def test_current_owner_rejects_stale_authenticated_state(self):
        state = self.run_python_owner("privacy_sdk_file_seal", [self.lock])
        self.assertEqual(state.returncode, 0, state.stderr)
        digest, separator, physical_state = state.stdout.strip().partition(":")
        self.assertEqual(digest, OWNER[0])
        self.assertEqual(separator, ":")
        before = self.lock.stat(), self.lock.read_bytes()
        stale_state = "present:" + ("0" * 64) + ":" + physical_state
        result = self.run_python_owner(
            "privacy_sdk_materialize_canonical_cargo_lock",
            [self.source, self.destination, stale_state, OWNER[0]],
        )
        self.assert_rejected(result)
        self.assertIn("authenticated reviewed state", result.stderr)
        self.assertEqual((self.lock.stat(), self.lock.read_bytes()), before)

    def test_unreviewed_graph_bytes_are_rejected(self):
        self.lock.write_bytes(self.lock.read_bytes() + b"\n# unreviewed bytes\n")
        self.assert_rejected(self.invoke())

    def test_empty_source_is_rejected(self):
        self.lock.write_bytes(b"")
        self.assert_rejected(self.invoke())

    def test_executable_source_is_rejected(self):
        self.lock.chmod(0o700)
        self.assert_rejected(self.invoke())

    def test_symlink_source_is_rejected(self):
        other = self.source / "other"
        self.lock.rename(other)
        self.lock.symlink_to(other)
        self.assert_rejected(self.invoke())

    def test_hardlinked_source_is_rejected(self):
        os.link(self.lock, self.source / "other")
        self.assert_rejected(self.invoke())

    def run_python_owner(self, function, arguments, *, environment=None, prelude=""):
        # Execute the exact production body directly so a timeout terminates the
        # sole test child, including on the blocking-open regression.
        function_source = HELPER.read_text().split(function + "() {\n", 1)[1]
        body = function_source.split("<<'PY'\n", 1)[1].split("\nPY\n", 1)[0]
        driver = prelude + "\nexec(compile(" + repr(body) + ", " + repr(str(HELPER)) + ", 'exec'))\n"
        return subprocess.run(
            [sys.executable, "-I", "-", *map(str, arguments)], input=driver,
            env=environment, capture_output=True, text=True, check=False, timeout=5,
        )

    def test_materializer_fifo_source_rejects_without_blocking(self):
        self.lock.unlink()
        os.mkfifo(self.lock)
        result = self.run_python_owner(
            "privacy_sdk_materialize_canonical_cargo_lock",
            [self.source, self.destination, "present:unused", OWNER[0]],
        )
        self.assert_rejected(result)
        self.assertIn("regular file", result.stderr)

    def test_resolver_fifo_selection_rejects_without_blocking(self):
        os.mkfifo(self.destination)
        environment = dict(os.environ, IROHA_PRIVACY_CARGO_LOCKFILE_PATH=str(self.destination))
        result = self.run_python_owner(
            "privacy_sdk_resolve_cargo_lockfile", [self.source], environment=environment,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("regular file", result.stderr)

    def test_file_seal_fifo_rejects_without_blocking(self):
        os.mkfifo(self.destination)
        result = self.run_python_owner("privacy_sdk_file_seal", [self.destination])
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("regular file", result.stderr)

    def test_executable_seal_fifo_rejects_without_blocking(self):
        os.mkfifo(self.destination, 0o700)
        result = self.run_python_owner("privacy_sdk_executable_seal", [self.destination])
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("regular file", result.stderr)

    def test_source_parent_symlink_swap_after_write_is_rejected(self):
        state = self.run_python_owner("privacy_sdk_file_seal", [self.lock])
        self.assertEqual(state.returncode, 0, state.stderr)
        # Swap an ancestor while retaining the original source inode. The final
        # descriptor identity alone cannot distinguish this path mutation.
        prelude = '''import os
from pathlib import Path
original_fsync = os.fsync
def swap_source_parent(descriptor):
    original_fsync(descriptor)
    source = Path(__import__('sys').argv[1])
    moved = source.with_name('moved-source')
    source.rename(moved)
    source.symlink_to(moved, target_is_directory=True)
os.fsync = swap_source_parent
'''
        result = self.run_python_owner(
            "privacy_sdk_materialize_canonical_cargo_lock",
            [self.source, self.destination, "present:" + state.stdout.strip(), OWNER[0]],
            prelude=prelude,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("source changed after materialization", result.stderr)

    def test_resolver_parent_symlink_swap_during_read_is_rejected(self):
        self.destination.write_bytes(self.lock.read_bytes())
        prelude = '''import os
from pathlib import Path
original_read = os.read
swapped = False
def swap_selected_parent(descriptor, count):
    global swapped
    payload = original_read(descriptor, count)
    if not swapped:
        parent = Path(os.environ['IROHA_PRIVACY_CARGO_LOCKFILE_PATH']).parent
        moved = parent.with_name('moved-external')
        parent.rename(moved)
        parent.symlink_to(moved, target_is_directory=True)
        swapped = True
    return payload
os.read = swap_selected_parent
'''
        environment = dict(os.environ, IROHA_PRIVACY_CARGO_LOCKFILE_PATH=str(self.destination))
        result = self.run_python_owner(
            "privacy_sdk_resolve_cargo_lockfile", [self.source],
            environment=environment, prelude=prelude,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("path became noncanonical", result.stderr)

    def test_root_selection_is_rejected_without_mutation(self):
        before = self.lock.stat(), self.lock.read_bytes()
        result = self.invoke(self.lock)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual((self.lock.stat(), self.lock.read_bytes()), before)

    def test_in_tree_selection_is_rejected(self):
        destination = self.source / "private/Cargo.lock"
        destination.parent.mkdir()
        self.assert_rejected(self.invoke(destination))
        self.assertFalse(destination.exists())

    def test_relative_selection_is_rejected(self):
        self.assert_rejected(self.invoke(Path("relative/Cargo.lock")))

    def test_parent_symlink_is_rejected(self):
        alias = self.root / "alias"
        alias.symlink_to(self.destination.parent, target_is_directory=True)
        self.assert_rejected(self.invoke(alias / "Cargo.lock"))

    def test_wrong_basename_is_rejected(self):
        self.assert_rejected(self.invoke(self.destination.with_name("other.lock")))

    def assert_existing_destination_untouched(self, kind):
        other = self.destination.parent / "sentinel"
        other.write_bytes(b"must remain unchanged")
        if kind == "regular":
            self.destination.write_bytes(b"must remain unchanged")
        elif kind == "symlink":
            self.destination.symlink_to(other)
        else:
            os.link(other, self.destination)
        before = self.destination.lstat()
        result = self.invoke()
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.destination.lstat(), before)
        self.assertEqual(self.destination.read_bytes(), b"must remain unchanged")
        self.assertEqual(other.read_bytes(), b"must remain unchanged")

    def test_existing_regular_destination_is_never_overwritten(self):
        self.assert_existing_destination_untouched("regular")

    def test_existing_symlink_destination_is_never_overwritten(self):
        self.assert_existing_destination_untouched("symlink")

    def test_existing_hardlink_destination_is_never_overwritten(self):
        self.assert_existing_destination_untouched("hardlink")

    def test_digest_cannot_replace_full_authenticated_source_state(self):
        result = self.invoke(state="present:" + OWNER[0])
        self.assert_rejected(result)
        self.assertIn("authenticated reviewed state", result.stderr)

    def test_historical_external_authority_is_not_a_second_graph(self):
        self.assert_rejected(self.invoke(state="present:cd9e829e454171f17540abeb7fd1aa14129252082bd8b076a0199b0ffa4e3f79:0:0:0:0:0:0o400"))
        text = HELPER.read_text()
        self.assertNotIn("PRIVACY_SDK_FROZEN_RELEASE_CARGO_LOCK_SHA256", text)
        self.assertNotIn("PRIVACY_SDK_TRACKED_ROOT_CARGO_LOCK_SHA256", text)
        self.assertNotIn("generate-lockfile", text)


class CanonicalGraphWorkflowOrderTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        guard = ROOT / "ci/check_privacy_sdk_guard.sh"
        body = guard.read_text().split("<<'PY'\n", 1)[1].split("\nPY\n", 1)[0]
        module = types.ModuleType("canonical_graph_workflow_order_test")
        previous_argv = sys.argv
        sys.modules[module.__name__] = module
        try:
            sys.argv = [str(guard), str(ROOT), ""]
            exec(compile(body[:body.index("def check(overrides:")], str(guard), "exec"), module.__dict__)
        finally:
            sys.argv = previous_argv
            del sys.modules[module.__name__]
        cls.check_workflow = staticmethod(module._check_cargo_workflow)
        cls.workflow = (ROOT / ".github/workflows/pr_privacy_sdk_guard.yml").read_text()

    def test_reviewed_workflow_initializes_every_graph_comparison(self):
        errors = []
        self.check_workflow(self.workflow, errors)
        self.assertEqual(errors, [])

    def test_each_fresh_shell_rejects_graph_use_before_owner_import(self):
        checks = 0
        for step in re.split(r"(?m)(?=^      - )", self.workflow):
            owner = "          source ci/privacy_sdk_cargo_lockfile.sh\n"
            if owner not in step:
                continue
            lines = step.splitlines(keepends=True)
            lines.remove(owner)
            first_use = next(i for i, line in enumerate(lines) if "${PRIVACY_SDK_CANONICAL_CARGO_LOCK_SHA256}" in line)
            lines.insert(first_use + 1, owner)
            with self.subTest(step=lines[0].strip()):
                errors = []
                self.check_workflow(self.workflow.replace(step, "".join(lines), 1), errors)
                # Require the semantic order rejection independently of the
                # complete job digest, whose check also rejects these bytes.
                self.assertTrue(any("must source the sole graph owner before every pin use" in error for error in errors), errors)
            checks += 1
        self.assertEqual(checks, 4)


class CanonicalSourceLockAssertionTests(unittest.TestCase):
    """Execute the actual self-test footer, including on macOS's Bash 3.2."""

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="privacy-source-lock-")
        self.addCleanup(self.temporary.cleanup)
        self.source = Path(self.temporary.name).resolve()
        (self.source / "Cargo.lock").write_bytes((ROOT / "Cargo.lock").read_bytes())
        (self.source / ".gitignore").write_text("**/Cargo.lock\n!/Cargo.lock\n")
        self.workflow = self.source / "workflow.yml"
        self.workflow.write_text("# No root-lock copy operation.\n")
        script = (ROOT / "ci/privacy_sdk_cargo_lockfile_test.sh").read_text()
        begin = "# BEGIN canonical source lock assertion."
        end = "# END canonical source lock assertion."
        self.assertEqual(script.count(begin), 1)
        self.assertEqual(script.count(end), 1)
        self.assertion = script.split(begin, 1)[1].split(end, 1)[0]

    def invoke(self, **changes):
        oid = "1" * 40
        environment = dict(os.environ)
        environment.update(
            SOURCE_ROOT=str(self.source),
            WORKFLOW_PATH=str(self.workflow),
            PRIVACY_SDK_CANONICAL_CARGO_LOCK_SHA256=OWNER[0],
            FIXTURE_INDEX_ENTRY=f"100644 {oid} 0\tCargo.lock",
            FIXTURE_HEAD_ENTRY=f"100644 blob {oid}\tCargo.lock",
            FIXTURE_WORK_OID=oid,
            FIXTURE_GIT_FAIL="",
        )
        environment.update(changes)
        # Only Git's three read results are fixtures. The real footer reads the
        # actual lock bytes, pin and tracking policy; no candidate is fabricated.
        command = '''set -euo pipefail
CANONICAL_SOURCE_LOCK_EXPECTED_SHA256="$PRIVACY_SDK_CANONICAL_CARGO_LOCK_SHA256"
git() {
  if [[ "$3" == "$FIXTURE_GIT_FAIL" ]]; then return 91; fi
  case "$3" in
    ls-files) printf '%s\\n' "$FIXTURE_INDEX_ENTRY" ;;
    ls-tree) printf '%s\\n' "$FIXTURE_HEAD_ENTRY" ;;
    hash-object) printf '%s\\n' "$FIXTURE_WORK_OID" ;;
    *) return 92 ;;
  esac
}
''' + self.assertion + "\nprintf '%s\\n' 'fixture success'\n"
        return subprocess.run(
            ["/bin/bash", "-c", command], env=environment,
            capture_output=True, text=True, check=False,
        )

    def assert_rejected(self, result, diagnostic):
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertNotIn("fixture success", result.stdout)
        self.assertIn(diagnostic, result.stderr)

    def test_exact_committed_graph_passes(self):
        result = self.invoke()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, "fixture success\n")

    def test_each_graph_conjunct_rejects_before_success(self):
        cases = [
            {"FIXTURE_HEAD_ENTRY": f"100644 blob {'2' * 40}\tCargo.lock"},
            {"FIXTURE_WORK_OID": "2" * 40},
            {"PRIVACY_SDK_CANONICAL_CARGO_LOCK_SHA256": "0" * 64},
        ]
        for change in cases:
            with self.subTest(change=change):
                self.assert_rejected(self.invoke(**change), "must match HEAD, index, worktree")

    def test_unreviewed_physical_lock_bytes_reject(self):
        with (self.source / "Cargo.lock").open("ab") as output:
            output.write(b"\n# unreviewed change\n")
        self.assert_rejected(self.invoke(), "must match HEAD, index, worktree")

    def test_missing_or_nonregular_index_entry_rejects(self):
        for entry in ("", f"120000 {'1' * 40} 0\tCargo.lock", f"100644 {'1' * 40} 1\tCargo.lock"):
            with self.subTest(entry=entry):
                self.assert_rejected(
                    self.invoke(FIXTURE_INDEX_ENTRY=entry), "one regular tracked index entry",
                )

    def test_missing_or_nonregular_committed_entry_rejects(self):
        for entry in ("", f"120000 blob {'1' * 40}\tCargo.lock"):
            with self.subTest(entry=entry):
                self.assert_rejected(
                    self.invoke(FIXTURE_HEAD_ENTRY=entry), "one committed regular file",
                )

    def test_each_tracking_policy_conjunct_rejects(self):
        for policy in ("!/Cargo.lock\n", "**/Cargo.lock\n"):
            with self.subTest(policy=policy):
                (self.source / ".gitignore").write_text(policy)
                self.assert_rejected(self.invoke(), "root lock tracking policy changed")
        (self.source / ".gitignore").write_text("**/Cargo.lock\n!/Cargo.lock\n")
        self.workflow.write_text("install -m 600 incoming/Cargo.lock source/Cargo.lock\n")
        self.assert_rejected(self.invoke(), "root lock tracking policy changed")

    def test_git_read_failure_cannot_report_success(self):
        for operation in ("ls-files", "ls-tree", "hash-object"):
            with self.subTest(operation=operation):
                result = self.invoke(FIXTURE_GIT_FAIL=operation)
                self.assertNotEqual(result.returncode, 0)
                self.assertNotIn("fixture success", result.stdout)

    def test_real_git_fixture_preserves_objects_and_rejects_dirty_states(self):
        script = (ROOT / "ci/privacy_sdk_cargo_lockfile_test.sh").read_text()
        begin = "# BEGIN canonical source lock Git fixtures."
        end = "# END canonical source lock Git fixtures."
        self.assertEqual(script.count(begin), 1)
        self.assertEqual(script.count(end), 1)
        fixture_body = script.split(begin, 1)[1].split(end, 1)[0]
        # Reuse the real shell fixture owner. Every production conjunction and
        # dirty-state control executes under Bash 3.2 with genuine Git objects.
        command = '''set -euo pipefail
readonly PRIVACY_SDK_CANONICAL_CARGO_LOCK_SHA256="$4"
expect_failure() {
  local expected="$1" output
  shift
  if output="$("$@" 2>&1)"; then
    echo "expected command to fail: $*" >&2
    exit 1
  fi
  case "$output" in
    *"$expected"*) ;;
    *) echo "missing rejection: $expected: $output" >&2; exit 1 ;;
  esac
}
assert_canonical_source_lock() (
  local SOURCE_ROOT="$1" WORKFLOW_PATH="$2"
  local CANONICAL_SOURCE_LOCK_EXPECTED_SHA256="$3"
''' + self.assertion + "\n)\n" + fixture_body + '''
exercise_canonical_source_lock_git_fixture "$1" "$2" "$3"
printf '%s\\n' 'fixture success'
'''
        fixture = self.source / "real-git-fixture"
        # Poisoned routing must not select or modify an inherited repository.
        poison = self.source / "inherited-git-context"
        environment = dict(os.environ, GIT_DIR=str(poison / "git"),
                           GIT_WORK_TREE=str(poison / "tree"),
                           GIT_INDEX_FILE=str(poison / "index"))
        result = subprocess.run(
            ["/bin/bash", "-c", command, "source-lock-fixture", str(ROOT),
             str(self.workflow), str(fixture), OWNER[0]], env=environment,
            capture_output=True, text=True, check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, "fixture success\n")
        self.assertEqual(result.stderr, "")
        self.assertFalse(poison.exists())
        # The copied signed commit is byte-identical; no fixture commit is made.
        git_environment = {key: value for key, value in os.environ.items()
                           if not key.startswith("GIT_")}
        git_environment.update(GIT_CONFIG_GLOBAL=os.devnull,
                               GIT_CONFIG_NOSYSTEM="1")

        def git(root, *arguments):
            return subprocess.check_output(
                ["/usr/bin/git", "--no-replace-objects", "-C", str(root), *arguments],
                env=git_environment,
            )

        head = git(fixture, "rev-parse", "HEAD").decode().strip()
        self.assertEqual(git(fixture, "cat-file", "commit", head),
                         git(ROOT, "cat-file", "commit", head))
        self.assertEqual(git(fixture, "ls-files", "--stage", "--", "Cargo.lock"),
                         b"100644 " + git(fixture, "rev-parse", "HEAD:Cargo.lock").strip()
                         + b" 0\tCargo.lock\n")
        self.assertEqual((fixture / "Cargo.lock").read_bytes(),
                         git(fixture, "show", "HEAD:Cargo.lock"))
        # An uncommitted candidate in the source fixture must not prevent unit
        # execution or be staged/committed by it. Its committed graph remains
        # the immutable positive owner for the independent child fixture.
        (fixture / "Cargo.lock").write_bytes(b"uncommitted candidate\n")
        lock_oid = git(fixture, "rev-parse", "HEAD:Cargo.lock").decode().strip()
        git(fixture, "update-index", "--cacheinfo", f"100755,{lock_oid},Cargo.lock")
        source_index = (fixture / ".git/index").read_bytes()
        source_lock = (fixture / "Cargo.lock").read_bytes()
        result = subprocess.run(
            ["/bin/bash", "-c", command, "dirty-source-lock-fixture", str(fixture),
             str(self.workflow), str(self.source / "dirty-source-child"), OWNER[0]],
            env=environment, capture_output=True, text=True, check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, "fixture success\n")
        self.assertEqual(result.stderr, "")
        self.assertEqual((fixture / ".git/index").read_bytes(), source_index)
        self.assertEqual((fixture / "Cargo.lock").read_bytes(), source_lock)
        self.assertEqual(git(fixture, "rev-parse", "HEAD").decode().strip(), head)

    def test_absence_assertion_distinguishes_match_absence_and_read_failure(self):
        script = (ROOT / "ci/privacy_sdk_cargo_lockfile_test.sh").read_text()
        begin = "# BEGIN explicit absence assertion."
        end = "# END explicit absence assertion."
        self.assertEqual(script.count(begin), 1)
        self.assertEqual(script.count(end), 1)
        function = script.split(begin, 1)[1].split(end, 1)[0]
        source = self.source / "pattern-input"
        source.write_text("current-policy\n")
        for pattern, path, expected in [
            ("retired-policy", source, 0),
            ("current-policy", source, 1),
            ("current-policy", self.source / "missing", 2),
        ]:
            with self.subTest(pattern=pattern, path=path):
                result = subprocess.run(
                    ["/bin/bash", "-c", "set -euo pipefail\n" + function +
                     '\nexpect_no_match -Fq "$1" "$2"\necho fixture-success\n',
                     "absence-test", pattern, str(path)],
                    capture_output=True, text=True, check=False,
                )
                self.assertEqual(result.returncode, expected, result.stderr)
                self.assertEqual("fixture-success" in result.stdout, expected == 0)


if __name__ == "__main__":
    unittest.main()
