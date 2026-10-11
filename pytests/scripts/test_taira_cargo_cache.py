"""Cargo source relocation regressions, including an actual dependency-free build."""

import importlib.util
import json
import fcntl
import os
from pathlib import Path
import struct
import subprocess
import stat
import sys
import tempfile
import unittest
from unittest.mock import patch


SCRIPT = Path(__file__).resolve().parents[2] / "scripts/taira_cargo_cache.py"
sys.path.insert(0, str(SCRIPT.parent))
SPEC = importlib.util.spec_from_file_location("taira_cargo_cache", SCRIPT)
cache = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(cache)


def record(paths):
    raw = b"\x01\x00\x00\x00\xff\x01" + struct.pack("<I", len(paths))
    for kind, path in paths:
        value = os.fsencode(path)
        raw += bytes([kind]) + struct.pack("<I", len(value)) + value + b"\0"
    return raw + b"\0\0\0\0"


class CargoSourceAdmissionTests(unittest.TestCase):
    def test_missing_offline_package_reports_bounded_sanitized_cargo_error(self):
        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary).resolve()
            stderr = (b"\x1b[31merror: no matching package named `missing-crate` found\x1b[0m\n"
                      b"required by package at /private/workspace TOKEN=private-value "
                      b"https://private.example.invalid/registry\n" + b"x" * 10000)
            result = subprocess.CompletedProcess([], 101, b"", stderr)
            with patch.object(cache.subprocess, "run", return_value=result) as run:
                with self.assertRaisesRegex(ValueError, "missing-crate") as failure:
                    cache.local_package_names(source, {"CARGO": "/fixture/cargo"})
            command = run.call_args.args[0]
            self.assertIn("--locked", command)
            self.assertIn("--offline", command)
            self.assertFalse(run.call_args.kwargs["check"])
            message = str(failure.exception)
            self.assertLessEqual(len(message), 610)
            for unsafe in ("\x1b", "/private/workspace", "private-value", "private.example.invalid"):
                self.assertNotIn(unsafe, message)
            self.assertIn("<path>", message)
            self.assertIn("<credential>", message)
            self.assertIn("<url>", message)

    def test_offline_metadata_timeout_has_no_command_or_stderr_dump(self):
        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary).resolve()
            with patch.object(cache.subprocess, "run", side_effect=subprocess.TimeoutExpired(
                    ["/private/cargo"], 60, stderr=b"private stderr")):
                with self.assertRaisesRegex(ValueError, "timed out after 60s") as failure:
                    cache.local_package_names(source, {"CARGO": "/private/cargo"})
            self.assertNotIn("/private/cargo", str(failure.exception))
            self.assertNotIn("private stderr", str(failure.exception))

    def test_metadata_child_creates_private_cache_without_changing_parent_umask(self):
        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary).resolve()
            cargo = source / "cargo-fixture"
            cache_file = source / "package-cache"
            cargo.write_text("#!" + sys.executable + "\nimport os\n"
                             f"os.close(os.open({str(cache_file)!r}, os.O_CREAT|os.O_WRONLY, 0o666))\n"
                             "print('{\"packages\": []}')\n")
            cargo.chmod(0o700)
            original_umask = os.umask(0o002)
            try:
                self.assertEqual(cache.local_package_names(source, {"CARGO": str(cargo)}), set())
                self.assertEqual(os.umask(0o002), 0o002)
            finally:
                os.umask(original_umask)
            self.assertEqual(stat.S_IMODE(cache_file.stat().st_mode), 0o600)

    def test_foreign_source_retires_only_its_host_and_cross_profile_family(self):
        triple = "aarch64-unknown-linux-gnu"
        for stale_family, preserved_family in (("debug", "release"), ("release", "debug")):
            with self.subTest(stale_family=stale_family), tempfile.TemporaryDirectory() as temporary:
                target = Path(temporary).resolve()
                source = target / "source"
                source.mkdir()
                paths = {}
                for family in ("debug", "release"):
                    for cross in (False, True):
                        profile = target / triple / family if cross else target / family
                        directory = profile / ".fingerprint/ivm-1111111111111111"
                        directory.mkdir(parents=True)
                        dependency = ("old-source/crates/ivm/build.rs"
                                      if family == stale_family and not cross
                                      else "source/crates/ivm/src/lib.rs")
                        (directory / "dep-fixture").write_bytes(record([(1, dependency)]))
                        artifact = profile / "retained-compiled-output"
                        artifact.write_bytes(b"compiled output")
                        paths[family, cross] = directory
                self.assertEqual(cache.admit_source_fingerprints(source, target, triple, {"ivm"}), ["ivm"])
                for cross in (False, True):
                    self.assertFalse(paths[stale_family, cross].exists())
                    self.assertTrue(paths[preserved_family, cross].exists())
                    self.assertEqual((paths[stale_family, cross].parent.parent / "retained-compiled-output").read_bytes(),
                                     b"compiled output")
                self.assertEqual(len(list((target / "taira-release-cache-retired").glob("**/ivm-*"))), 2)
                self.assertEqual(cache.admit_source_fingerprints(source, target, triple, {"ivm"}, repair=False), [])

    def test_retirement_creates_private_host_and_cross_parents_under_permissive_umask(self):
        with tempfile.TemporaryDirectory() as temporary:
            target = Path(temporary).resolve()
            source = target / "source"
            source.mkdir(mode=0o700)
            triple = "aarch64-unknown-linux-gnu"
            stale = []
            for profile in (target / "release", target / triple / "release"):
                directory = profile / ".fingerprint/ivm-1111111111111111"
                directory.mkdir(parents=True)
                (directory / "dep-fixture").write_bytes(record([(1, "old-source/crates/ivm/build.rs")]))
                stale.append(directory)
            original_umask = os.umask(0o002)
            try:
                self.assertEqual(cache.admit_source_fingerprints(source, target, triple, {"ivm"}), ["ivm"])
                self.assertEqual(os.umask(0o002), 0o002)
            finally:
                os.umask(original_umask)
            parent = target / "taira-release-cache-retired"
            archive, = parent.iterdir()
            for path in (parent, archive, archive / "release", archive / "release/.fingerprint",
                         archive / triple, archive / triple / "release", archive / triple / "release/.fingerprint"):
                self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o700)
            for path in stale:
                self.assertFalse(path.exists())
                self.assertTrue((archive / path.relative_to(target) / "dep-fixture").is_file())

    def test_generated_build_script_paths_are_bound_to_the_same_profile_family(self):
        with tempfile.TemporaryDirectory() as temporary:
            target = Path(temporary).resolve()
            source = target / "source"
            source.mkdir()
            for family, generated in (("debug", "release/build/ivm/out/generated.rs"),
                                      ("release", "release/build/ivm/out/generated.rs")):
                directory = target / family / ".fingerprint/ivm-1111111111111111"
                directory.mkdir(parents=True)
                (directory / "dep-fixture").write_bytes(record([(1, generated)]))
            self.assertEqual(cache.admit_source_fingerprints(source, target, "aarch64-unknown-linux-gnu", {"ivm"}),
                             ["ivm"])
            self.assertFalse((target / "debug/.fingerprint/ivm-1111111111111111").exists())
            self.assertTrue((target / "release/.fingerprint/ivm-1111111111111111").exists())

    def test_parser_rejects_unknown_truncated_and_trailing_records(self):
        expected = [(1, Path("source/build.rs")), (0, Path("src/lib.rs"))]
        raw = record(expected)
        self.assertEqual(cache.dependency_paths(raw), expected)
        for invalid in (raw[:-1], raw + b"x", b"old format", raw[:5] + b"\2" + raw[6:]):
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                cache.dependency_paths(invalid)

    def test_only_foreign_local_package_metadata_is_retired(self):
        with tempfile.TemporaryDirectory() as temporary:
            target = Path(temporary).resolve()
            source = target / "source"
            source.mkdir()
            parent = target / "release/.fingerprint"
            for name, paths in {
                "ivm-1111111111111111": [(1, "old-source/crates/ivm/build.rs")],
                "ivm-2222222222222222": [(1, "source/crates/ivm/src/lib.rs")],
                "local-3333333333333333": [(0, "src/lib.rs")],
                "safe-4444444444444444": [(1, "source/crates/safe/lib.rs"),
                                          (1, "release/build/safe/out/generated.rs")],
                "registry-5555555555555555": [(0, "src/lib.rs")],
            }.items():
                directory = parent / name
                directory.mkdir(parents=True)
                (directory / "dep-lib-fixture").write_bytes(record(paths))
            artifact = target / "release/retained-binary"
            artifact.write_bytes(b"compiled output")
            packages = {"ivm", "local", "safe"}
            with self.assertRaisesRegex(ValueError, "foreign Cargo"):
                cache.admit_source_fingerprints(source, target, "aarch64-unknown-linux-gnu", packages, repair=False)
            def interrupted_checkpoint():
                self.assertEqual(len(list(parent.iterdir())), 5)
                raise OSError("fixture checkpoint interruption")
            with self.assertRaisesRegex(OSError, "checkpoint interruption"):
                cache.admit_source_fingerprints(source, target, "aarch64-unknown-linux-gnu", packages,
                                                 before_retire=interrupted_checkpoint)
            self.assertEqual(len(list(parent.iterdir())), 5)
            self.assertEqual(cache.admit_source_fingerprints(source, target, "aarch64-unknown-linux-gnu", packages),
                             ["ivm", "local"])
            self.assertEqual(sorted(p.name for p in parent.iterdir()),
                             ["registry-5555555555555555", "safe-4444444444444444"])
            self.assertEqual(len(list((target / "taira-release-cache-retired").glob("*/release/.fingerprint/*"))), 3)
            self.assertEqual(artifact.read_bytes(), b"compiled output")
            self.assertEqual(cache.admit_source_fingerprints(source, target, "aarch64-unknown-linux-gnu", packages), [])
            with cache.source_fingerprints(source, target, "aarch64-unknown-linux-gnu", packages, repair=False):
                with (target / "release/.cargo-lock").open("rb") as lock:
                    with self.assertRaises(BlockingIOError):
                        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)

    def test_real_cargo_rebuilds_relocated_host_build_script(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            target = root / "target"
            target.mkdir()
            environment = {key: value for key, value in os.environ.items()
                           if key in {"PATH", "HOME", "RUSTUP_HOME", "TMPDIR"}}
            environment.update(CARGO_TARGET_DIR=str(target), CARGO_HOME=str(root / "cargo-home"),
                               CARGO_NET_OFFLINE="true", RUSTUP_TOOLCHAIN="1.93.1")
            for name, value in (("old-source", "14"), ("source", "15")):
                source = target / name
                (source / "src").mkdir(parents=True)
                (source / "Cargo.toml").write_text(
                    '[package]\nname="taira-cache-fixture"\nversion="0.1.0"\nedition="2024"\n[workspace]\n')
                (source / "build.rs").write_text(
                    'fn main() { println!("cargo:rustc-env=SOURCE_VALUE=' + value + '"); }\n')
                (source / "src/main.rs").write_text(
                    'fn main() { println!("{}", env!("SOURCE_VALUE")); }\n')
                subprocess.run(["cargo", "build", "--offline", "--release", "--manifest-path",
                                str(source / "Cargo.toml")], cwd=root, env=environment,
                               check=True, capture_output=True, timeout=60)
            binary = target / "release/taira-cache-fixture"
            # This reproduces Cargo 1.93's real stale build-root-relative record.
            self.assertEqual(subprocess.check_output([str(binary)]).strip(), b"14")
            self.assertEqual(cache.admit_source_fingerprints(source, target, "aarch64-unknown-linux-gnu",
                                                             {"taira-cache-fixture"}), ["taira-cache-fixture"])
            subprocess.run(["cargo", "build", "--offline", "--release", "--manifest-path",
                            str(source / "Cargo.toml")], cwd=root, env=environment,
                           check=True, capture_output=True, timeout=60)
            self.assertEqual(subprocess.check_output([str(binary)]).strip(), b"15")
            self.assertEqual(cache.admit_source_fingerprints(source, target, "aarch64-unknown-linux-gnu",
                                                             {"taira-cache-fixture"}, repair=False), [])



class CanonicalCargoSourceAdmissionTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.source = Path(self.directory.name).resolve() / "repo"
        self.target = self.source / "target/linux-release"
        self.package = self.source / "crates/ivm"
        self.target.mkdir(parents=True)
        self.package.mkdir(parents=True)
        (self.package / "Cargo.toml").write_text('[package]\nname="ivm"\n')
        self.triple = "aarch64-unknown-linux-gnu"
        self.roots = {"ivm": self.package}
        (self.package / "src").mkdir()
        (self.package / "src/lib.rs").write_text("// signed source fixture\n")
        self.source_paths = {self.package / "src/lib.rs", self.package / "Cargo.toml"}

    def tearDown(self):
        self.directory.cleanup()

    def fingerprint(self, paths, *, family="release", cross=False):
        profile = self.target / self.triple / family if cross else self.target / family
        directory = profile / ".fingerprint/ivm-1111111111111111"
        directory.mkdir(parents=True, exist_ok=True)
        (directory / "dep-fixture").write_bytes(record(paths))
        return directory

    def admit(self, **options):
        return cache.admit_source_fingerprints(
            self.source, self.target, self.triple, {"ivm"},
            package_roots=self.roots, source_paths=self.source_paths, **options)

    def test_metadata_binds_exact_canonical_manifest_roots(self):
        local = {"name": "ivm", "source": None,
                 "manifest_path": str(self.package / "Cargo.toml")}
        registry = {"name": "external", "source": "registry+fixture"}
        result = subprocess.CompletedProcess([], 0,
            json.dumps({"packages": [local, registry]}).encode(), b"")
        with patch.object(cache.subprocess, "run", return_value=result) as run:
            self.assertEqual(cache.local_package_roots(self.source, {"CARGO": "/cargo"}, source_paths=self.source_paths), self.roots)
        self.assertIn(str(self.source / "Cargo.toml"), run.call_args.args[0])
        self.assertEqual(run.call_args.kwargs["cwd"], "/")
        self.assertIn("--offline", run.call_args.args[0])
        self.assertEqual(run.call_args.kwargs["umask"], 0o077)

    def test_metadata_rejects_duplicate_foreign_and_symlinked_roots(self):
        foreign = self.source.parent / "outside/Cargo.toml"
        foreign.parent.mkdir()
        foreign.write_text("fixture")
        captured = self.target / "old/source/Cargo.toml"
        captured.parent.mkdir(parents=True)
        captured.write_text("fixture")
        link = self.source / "linked"
        link.symlink_to(self.package, target_is_directory=True)
        selected = {"name": "ivm", "source": None,
                    "manifest_path": str(self.package / "Cargo.toml")}
        cases = [[selected, selected]] + [
            [dict(selected, manifest_path=str(path))]
            for path in (foreign, captured, link / "Cargo.toml")]
        for packages in cases:
            with self.subTest(packages=packages):
                result = subprocess.CompletedProcess([], 0,
                    json.dumps({"packages": packages}).encode(), b"")
                with patch.object(cache.subprocess, "run", return_value=result):
                    with self.assertRaisesRegex(ValueError, "ambiguous or foreign"):
                        cache.local_package_roots(self.source, {"CARGO": "/cargo"}, source_paths=self.source_paths)

    def test_package_root_mapping_requires_exact_names_and_canonical_source_paths(self):
        outside = self.source.parent
        captured = self.target / "old/source"
        captured.mkdir(parents=True)
        link = self.source / "linked"
        link.symlink_to(self.package, target_is_directory=True)
        cases = ({}, {"other": self.package}, {"ivm": outside},
                 {"ivm": captured}, {"ivm": link}, {"ivm": Path("relative")})
        for roots in cases:
            with self.subTest(roots=roots), self.assertRaises(ValueError):
                cache.admit_source_fingerprints(self.source, self.target, self.triple,
                                               {"ivm"}, package_roots=roots)
        self.assertFalse((self.target / ".taira-source-fingerprint-binding.json").exists())

    def test_first_adoption_retires_ambiguous_kind_zero_in_every_selected_family(self):
        directories = [self.fingerprint([(0, "src/lib.rs")], family=family, cross=cross)
                       for family in ("debug", "release") for cross in (False, True)]
        artifact = self.target / "release/retained-binary"
        artifact.write_bytes(b"compiled output")
        called = []
        self.assertEqual(self.admit(before_retire=lambda: called.append(True)), ["ivm"])
        self.assertEqual(called, [True])
        self.assertTrue(all(not path.exists() for path in directories))
        self.assertEqual(artifact.read_bytes(), b"compiled output")
        marker = self.target / ".taira-source-fingerprint-binding.json"
        self.assertEqual(stat.S_IMODE(marker.stat().st_mode), 0o600)
        bound = json.loads(marker.read_bytes())
        self.assertEqual(bound["source_root"], str(self.source))
        self.assertEqual(bound["package_roots"], {"ivm": str(self.package)})
        current = self.fingerprint([(0, "src/lib.rs"), (1, "release/build/ivm/out/generated.rs")])
        self.assertEqual(self.admit(repair=False), [])
        self.assertTrue(current.exists())

    def test_missing_binding_refuses_postbuild_even_without_existing_fingerprints(self):
        with self.assertRaisesRegex(ValueError, "binding is absent or changed"):
            self.admit(repair=False)
        self.assertFalse((self.target / ".taira-source-fingerprint-binding.json").exists())

    def test_changed_package_root_retires_ambiguous_records_again(self):
        self.admit()
        original = self.fingerprint([(0, "src/lib.rs")])
        replacement = self.source / "replacement/ivm"
        replacement.mkdir(parents=True)
        self.roots = {"ivm": replacement}
        (replacement / "src").mkdir()
        (replacement / "src/lib.rs").write_text("// replacement source fixture\n")
        (replacement / "Cargo.toml").write_text("# signed replacement manifest\n")
        self.source_paths = {replacement / "src/lib.rs", replacement / "Cargo.toml"}
        with self.assertRaisesRegex(ValueError, "binding is absent or changed"):
            self.admit(repair=False)
        self.assertTrue(original.exists())
        self.assertEqual(self.admit(), ["ivm"])
        self.assertFalse(original.exists())
        self.fingerprint([(0, "src/lib.rs")])
        self.assertEqual(self.admit(repair=False), [])

    def test_kind_zero_escape_and_captured_kind_one_never_become_canonical_source(self):
        self.admit()
        invalid = [(0, "../../../../outside.rs"), (0, "/outside.rs"),
                   (0, "../../target/linux-release/old/source/lib.rs"),
                   (1, "old/source/crates/ivm/src/lib.rs"),
                   (1, "../another-lane/old/source/crates/ivm/src/lib.rs")]
        for dependency in invalid:
            with self.subTest(dependency=dependency):
                directory = self.fingerprint([dependency])
                with self.assertRaisesRegex(ValueError, "foreign Cargo source"):
                    self.admit(repair=False)
                self.assertTrue(directory.exists())
                self.assertEqual(self.admit(), ["ivm"])

    def test_generated_paths_stay_profile_bound_with_canonical_roots(self):
        self.admit()
        debug = self.fingerprint([(1, "release/build/ivm/out/generated.rs")], family="debug")
        release = self.fingerprint([(1, "release/build/ivm/out/generated.rs")])
        self.assertEqual(self.admit(), ["ivm"])
        self.assertFalse(debug.exists())
        self.assertTrue(release.exists())

    def test_binding_publication_and_capture_keep_real_profile_locks_held(self):
        self.fingerprint([(0, "src/lib.rs")])
        self.fingerprint([(0, "src/lib.rs")], cross=True)
        paths = [self.target / "release/.cargo-lock",
                 self.target / self.triple / "release/.cargo-lock"]
        with cache.source_fingerprints(self.source, self.target, self.triple, {"ivm"},
                                       package_roots=self.roots, source_paths=self.source_paths):
            self.assertTrue((self.target / ".taira-source-fingerprint-binding.json").is_file())
            for path in paths:
                fd = os.open(path, os.O_RDWR)
                try:
                    with self.assertRaises(BlockingIOError):
                        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                finally:
                    os.close(fd)
        for path in paths:
            fd = os.open(path, os.O_RDWR)
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            finally:
                os.close(fd)

    def test_failed_retirement_callback_cannot_publish_binding(self):
        directory = self.fingerprint([(0, "src/lib.rs")])
        with self.assertRaisesRegex(ValueError, "stop"):
            self.admit(before_retire=lambda: (_ for _ in ()).throw(ValueError("stop")))
        self.assertTrue(directory.exists())
        self.assertFalse((self.target / ".taira-source-fingerprint-binding.json").exists())

    def test_source_mapping_is_opt_in(self):
        with self.assertRaisesRegex(ValueError, "maintained capture"):
            cache.admit_source_fingerprints(self.source, self.target, self.triple, {"ivm"})


    def test_canonical_mapping_requires_selected_regular_source_paths(self):
        with self.assertRaisesRegex(ValueError, "requires signed regular-file paths"):
            cache.admit_source_fingerprints(self.source, self.target, self.triple,
                                           {"ivm"}, package_roots=self.roots)
        self.assertFalse((self.target / ".taira-source-fingerprint-binding.json").exists())
        link = self.package / "selected-link.rs"
        link.symlink_to(self.package / "src/lib.rs")
        for paths in ({Path("relative.rs")}, {self.source.parent / "outside.rs"}, {link}):
            with self.subTest(paths=paths), self.assertRaises((ValueError, FileNotFoundError)):
                cache.admit_source_fingerprints(self.source, self.target, self.triple,
                    {"ivm"}, package_roots=self.roots, source_paths=paths)

    def test_ignored_include_is_foreign_but_signed_sibling_and_generated_are_admitted(self):
        shared = self.source / "crates/shared/shared.rs"
        shared.parent.mkdir()
        shared.write_text("// selected signed sibling fixture\n")
        self.source_paths.add(shared)
        self.admit()
        ignored = self.package / "ignored.rs"
        ignored.write_text("// ignored include fixture\n")
        directory = self.fingerprint([(0, "ignored.rs")])
        with self.assertRaisesRegex(ValueError, "foreign Cargo source"):
            self.admit(repair=False)
        self.assertTrue(directory.exists())
        self.assertEqual(self.admit(), ["ivm"])
        current = self.fingerprint([(0, "../shared/shared.rs"), (0, "src/lib.rs"),
                                    (1, "release/build/ivm/out/generated.rs")])
        self.assertEqual(self.admit(repair=False), [])
        self.assertTrue(current.exists())

    def test_source_path_selection_is_part_of_durable_binding(self):
        self.admit()
        directory = self.fingerprint([(0, "src/lib.rs")])
        extra = self.package / "selected-extra.rs"
        extra.write_text("// another signed regular source\n")
        self.source_paths.add(extra)
        with self.assertRaisesRegex(ValueError, "binding is absent or changed"):
            self.admit(repair=False)
        self.assertTrue(directory.exists())
        self.assertEqual(self.admit(), ["ivm"])
        marker = json.loads((self.target / ".taira-source-fingerprint-binding.json").read_bytes())
        self.assertEqual(marker["source_paths"], sorted(str(path) for path in self.source_paths))
        self.fingerprint([(0, "selected-extra.rs")])
        self.assertEqual(self.admit(repair=False), [])


    def test_ignored_package_manifest_cannot_enter_metadata_or_fingerprint_admission(self):
        self.source_paths.remove(self.package / "Cargo.toml")
        metadata = {"packages": [{"name": "ivm", "source": None,
                                  "manifest_path": str(self.package / "Cargo.toml")}]}
        result = subprocess.CompletedProcess([], 0, json.dumps(metadata).encode(), b"")
        with patch.object(cache.subprocess, "run", return_value=result):
            with self.assertRaisesRegex(ValueError, "ambiguous or foreign"):
                cache.local_package_roots(self.source, {"CARGO": "/cargo"}, source_paths=self.source_paths)
        with self.assertRaisesRegex(ValueError, "manifest is not a selected signed"):
            self.admit()
        self.assertFalse((self.target / ".taira-source-fingerprint-binding.json").exists())

    def test_retirement_parents_are_durable_before_new_binding_publication(self):
        directories = [self.fingerprint([(0, "src/lib.rs")], cross=cross) for cross in (False, True)]
        events, opened = [], {}
        original_open, original_fsync = cache.os.open, cache.os.fsync
        original_rename, original_replace = cache.os.rename, cache.os.replace
        marker = self.target / ".taira-source-fingerprint-binding.json"
        def observe_open(path, *args, **kwargs):
            fd = original_open(path, *args, **kwargs)
            opened[fd] = Path(path)
            return fd
        def observe_fsync(fd):
            events.append(("fsync", opened.get(fd)))
            return original_fsync(fd)
        def observe_rename(source, destination, *args, **kwargs):
            events.append(("retire", Path(source), Path(destination)))
            return original_rename(source, destination, *args, **kwargs)
        def observe_replace(source, destination, *args, **kwargs):
            if Path(destination) == marker:
                events.append(("publish-binding",))
            return original_replace(source, destination, *args, **kwargs)
        with patch.object(cache.os, "open", side_effect=observe_open), \
             patch.object(cache.os, "fsync", side_effect=observe_fsync), \
             patch.object(cache.os, "rename", side_effect=observe_rename), \
             patch.object(cache.os, "replace", side_effect=observe_replace):
            self.assertEqual(self.admit(), ["ivm"])
        published = events.index(("publish-binding",))
        retirements = [(index, event) for index, event in enumerate(events) if event[0] == "retire"]
        self.assertEqual(len(retirements), 2)
        self.assertEqual({event[1] for _, event in retirements}, set(directories))
        for retired, event in retirements:
            for directory in (event[1].parent, event[2].parent):
                while True:
                    self.assertTrue(any(retired < index < published and item == ("fsync", directory)
                                        for index, item in enumerate(events)), directory)
                    if directory == self.target:
                        break
                    directory = directory.parent

if __name__ == "__main__":
    unittest.main()
