#!/usr/bin/env python3
"""Focused tests for two-pass Kotodama golden ownership and publication."""

from __future__ import annotations

import contextlib
import hashlib
import importlib.util
import io
import re
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - Python 3.10 compatibility
    import tomli as tomllib


SCRIPT = Path(__file__).resolve().parents[1] / "regenerate_kotodama_goldens.py"
SPEC = importlib.util.spec_from_file_location("regenerate_kotodama_goldens", SCRIPT)
if SPEC is None or SPEC.loader is None:  # pragma: no cover - import machinery guard
    raise RuntimeError(f"could not import {SCRIPT}")
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)


class RegistryOwnershipTests(unittest.TestCase):
    def test_repository_registry_owns_every_current_compiler_output(self) -> None:
        root = SCRIPT.parent.parent
        manifest = tomllib.loads(
            (root / "generated-files.toml").read_text(encoding="utf-8")
        )
        rows = MODULE.read_map(root / MODULE.MAP_PATH)
        expected = {row.destination.as_posix() for row in rows}
        expected.update(path.as_posix() for path in MODULE.COMPILER_MANIFESTS.values())
        self.assertIn(
            "crates/iroha/tests/fixtures/contract_code_readback/code_readback.to",
            expected,
        )
        self.assertIn("crates/ivm/docs/examples/20_commit_reveal.to", expected)
        self.assertIn(
            "crates/iroha/tests/fixtures/contract_code_readback/code_readback.manifest.json",
            expected,
        )
        owners = [
            entry
            for entry in manifest["generated"]
            if expected.intersection(entry["outputs"])
        ]
        self.assertEqual(len(owners), 1)
        owner = owners[0]
        self.assertEqual(owner["name"], "kotodama-v1-artifacts-and-manifests")
        self.assertEqual(owner["kind"], "file")
        self.assertEqual(set(owner["outputs"]), expected)
        self.assertEqual(len(owner["outputs"]), len(expected))
        self.assertIn(MODULE.MAP_PATH.as_posix(), owner["inputs"])
        self.assertEqual(
            owner["generator_sources"], ["scripts/regenerate_kotodama_goldens.py"]
        )


class CommandLineTests(unittest.TestCase):
    def test_explicit_output_and_staging_roots_are_parsed(self) -> None:
        defaults = MODULE.parse_args(())
        self.assertFalse(defaults.write)
        self.assertFalse(defaults.check)
        self.assertEqual(defaults.koto, Path("target/debug/koto"))
        self.assertEqual(defaults.admission_tool, Path("target/debug/ivm_artifact_admit"))
        self.assertIsNone(defaults.output_root)
        self.assertIsNone(defaults.staging_root)

        options = MODULE.parse_args(
            (
                "--write",
                "--output-root",
                "/cache/output",
                "--staging-root",
                "/cache/work",
            )
        )
        self.assertTrue(options.write)
        self.assertEqual(options.output_root, Path("/cache/output"))
        self.assertEqual(options.staging_root, Path("/cache/work"))

        for arguments in (
            ("--write",),
            ("--write", "--check"),
            ("--write", "--write"),
            ("--check", "--check"),
            ("--output-root",),
            ("--staging-root",),
            ("--write", "--output-root", ""),
            ("--write", "--staging-root", ""),
            ("--write", "--output-root", "."),
            ("--write", "--output-root", "cache/output"),
            ("--check", "--output-root", "cache/output"),
            ("--write", "--staging-root", ".."),
            ("--write", "--output-root", "/"),
            ("--output-root", "first", "--output-root", "second"),
            ("--staging-root", "first", "--staging-root", "second"),
            ("--koto", ""),
            ("--admission-tool", ""),
            ("--koto", "first", "--koto", "second"),
            ("--admission-tool", "first", "--admission-tool", "second"),
            ("--koto=-h",),
            ("--admission-tool=--write",),
            ("--output-root=-h",),
            ("--staging-root=--write",),
            ("--skip-runtime-manifest-check",),
            ("--skip-contract-tests",),
            ("--iroha", "retired-producer"),
            ("--unknown",),
        ):
            with self.subTest(arguments=arguments):
                with contextlib.redirect_stderr(io.StringIO()):
                    with self.assertRaises(SystemExit):
                        MODULE.parse_args(arguments)

    def test_relative_locations_are_rooted_at_the_live_repository(self) -> None:
        root = Path("/live/repository")
        self.assertEqual(
            MODULE._rooted_path(root, Path("cache/output"), root),
            root / "cache/output",
        )
        self.assertEqual(
            MODULE._rooted_path(root, Path("/cache/output"), root),
            Path("/cache/output"),
        )
        self.assertEqual(MODULE._rooted_path(root, None, root), root)


class DirectorySafetyTests(unittest.TestCase):
    def test_output_root_cannot_be_a_source_directory(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            parent = Path(temporary).resolve(strict=True)
            source = parent / "source"
            source.mkdir()
            with self.assertRaisesRegex(MODULE.GoldenError, "below ignored target"):
                MODULE._require_output_path(
                    source,
                    source / "publication",
                )
            publication = parent / "publication"
            self.assertEqual(
                MODULE._require_output_path(source, publication),
                publication,
            )

    def test_checkout_target_requires_exact_ignored_untracked_path(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary).resolve(strict=True)
            (source / "target").mkdir()
            publication = source / "target" / "publication"
            with mock.patch.object(MODULE, "run", side_effect=["", "target/publication\0"]) as run:
                self.assertEqual(MODULE._require_output_path(source, publication), publication)
            self.assertEqual(run.call_args_list, [
                mock.call(["git", "ls-files", "--cached", "-z", "--", "target/publication"], source),
                mock.call(["git", "check-ignore", "--no-index", "-z", "--stdin"], source, input="target/publication\0"),
            ])
            self.assertFalse(publication.exists())
            with mock.patch.object(MODULE, "run", return_value="target/publication/tracked\0"):
                with self.assertRaisesRegex(MODULE.GoldenError, "tracked paths"):
                    MODULE._require_output_path(source, publication)
            for ignored in ("", "target/other\0", "target/publication\0target/other\0"):
                with mock.patch.object(MODULE, "run", side_effect=["", ignored]):
                    with self.assertRaisesRegex(MODULE.GoldenError, "Git-ignored"):
                        MODULE._require_output_path(source, publication)
            with self.assertRaisesRegex(MODULE.GoldenError, "below ignored target"):
                MODULE._require_scratch_path(source, source / "target")

    def test_target_symlink_and_parent_traversal_cannot_select_scratch(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve(strict=True)
            source = root / "source"
            source.mkdir()
            destination = root / "other"
            destination.mkdir()
            (source / "target").symlink_to(destination, target_is_directory=True)
            for path in (source / "target" / "publication", source / ".." / "other" / "publication"):
                with self.assertRaisesRegex(MODULE.GoldenError, "canonical non-symlink"):
                    MODULE._require_scratch_path(source, path)

    def test_staging_preparation_preserves_requested_path_and_rechecks_policy(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary).resolve(strict=True)
            requested = source / "target" / "scratch"
            with mock.patch.object(MODULE, "run", side_effect=[
                "", "target/scratch\0", "", "target/scratch\0"
            ]) as run:
                self.assertEqual(MODULE._prepare_staging_directory(source, requested), requested)
            self.assertTrue(requested.is_dir())
            self.assertEqual(run.call_count, 4)

    def test_staging_ancestor_exchange_cannot_gain_external_authority(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            parent = Path(temporary).resolve(strict=True)
            source = parent / "source"
            source.mkdir()
            target = source / "target"
            target.mkdir()
            external = parent / "external"
            external.mkdir()
            requested = target / "scratch"
            original_prepare = MODULE._prepare_real_directory

            def exchange(path: Path, *, context: str, create: bool) -> Path:
                target.rename(source / "original-target")
                target.symlink_to(external, target_is_directory=True)
                return original_prepare(path, context=context, create=create)

            with (
                mock.patch.object(MODULE, "run", side_effect=["", "target/scratch\0"]),
                mock.patch.object(MODULE, "_prepare_real_directory", side_effect=exchange),
                self.assertRaisesRegex(MODULE.GoldenError, "path changed during preparation"),
            ):
                MODULE._prepare_staging_directory(source, requested)

    def test_external_publication_path_is_not_reserved_during_preflight(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            parent = Path(temporary).resolve(strict=True)
            publication = parent / "publication"
            selected = MODULE._preflight_create_only_output_path(publication)
            self.assertEqual(selected, publication)
            self.assertFalse(selected.exists())

            selected.mkdir()
            with self.assertRaisesRegex(MODULE.GoldenError, "create-only"):
                MODULE._preflight_create_only_output_path(publication)

    def test_check_does_not_create_a_missing_output_root(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            missing = Path(temporary) / "missing"
            with self.assertRaises(MODULE.GoldenError):
                MODULE._prepare_real_directory(
                    missing,
                    context="output root",
                    create=False,
                )
            self.assertFalse(missing.exists())

            MODULE._prepare_real_directory(
                missing,
                context="output root",
                create=True,
            )
            self.assertTrue(missing.is_dir())

    def test_symlink_root_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve(strict=True)
            target = root / "target"
            link = root / "link"
            target.mkdir()
            try:
                link.symlink_to(target, target_is_directory=True)
            except (NotImplementedError, OSError):
                self.skipTest("symlinks are unavailable on this platform")
            with self.assertRaises(MODULE.GoldenError):
                MODULE._prepare_real_directory(
                    link,
                    context="output root",
                    create=False,
                )

    def test_symlink_above_the_selected_root_is_canonicalized(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            target = root / "target"
            link = root / "link"
            target.mkdir()
            try:
                link.symlink_to(target, target_is_directory=True)
            except (NotImplementedError, OSError):
                self.skipTest("symlinks are unavailable on this platform")
            selected = MODULE._prepare_real_directory(
                link / "nested",
                context="output root",
                create=True,
            )
            self.assertEqual(selected, (target / "nested").resolve())
            self.assertTrue(selected.is_dir())


class SourcePolicyTests(unittest.TestCase):
    @staticmethod
    def _attribute_result(payload: bytes, returncode: int = 0) -> object:
        return MODULE.subprocess.CompletedProcess(
            args=("git", "check-attr"),
            returncode=returncode,
            stdout=payload,
            stderr=b"classification failed" if returncode else b"",
        )

    def test_unset_and_unspecified_sources_are_partitioned_exactly(self) -> None:
        sources = (Path("contracts/live.ko"), Path("fixtures/extracted.ko"))
        output = (
            b"contracts/live.ko\0whitespace\0unspecified\0"
            b"fixtures/extracted.ko\0whitespace\0unset\0"
        )
        with mock.patch.object(
            MODULE.subprocess,
            "run",
            return_value=self._attribute_result(output),
        ) as run:
            checked, byte_exact = MODULE.partition_source_policy(
                Path("/repository"), sources
            )
        self.assertEqual(checked, (sources[0],))
        self.assertEqual(byte_exact, (sources[1],))
        self.assertEqual(
            run.call_args.args[0],
            [
                "git",
                "-C",
                "/repository",
                "check-attr",
                "-z",
                "whitespace",
                "--",
                "contracts/live.ko",
                "fixtures/extracted.ko",
            ],
        )

    def test_malformed_attribute_framing_fails_closed(self) -> None:
        sources = (Path("contracts/live.ko"),)
        malformed = (
            b"contracts/live.ko\0whitespace\0unspecified",
            b"contracts/live.ko\0whitespace\0",
            b"other.ko\0whitespace\0unspecified\0",
            b"contracts/live.ko\0other\0unspecified\0",
            b"contracts/live.ko\0whitespace\0\xff\0",
        )
        for output in malformed:
            with self.subTest(output=output):
                with (
                    mock.patch.object(
                        MODULE.subprocess,
                        "run",
                        return_value=self._attribute_result(output),
                    ),
                    self.assertRaises(MODULE.GoldenError),
                ):
                    MODULE.partition_source_policy(Path("/repository"), sources)

    def test_attributes_file_is_sealed_as_a_generation_input(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "scripts").mkdir()
            (root / MODULE.ATTRIBUTES_PATH).write_text(
                "fixtures/** -whitespace\n", encoding="utf-8"
            )
            (root / MODULE.MAP_PATH).write_text("map\n", encoding="utf-8")
            source = root / "contract.ko"
            koto = root / "koto"
            admission_tool = root / "ivm_artifact_admit"
            for path, payload in (
                (source, b"contract"),
                (koto, b"koto"),
                (admission_tool, b"ivm_artifact_admit"),
            ):
                path.write_bytes(payload)

            before = MODULE.generation_input_seals(
                root, (Path("contract.ko"),), koto, admission_tool
            )
            attribute_seal = next(
                seal for seal in before if seal.path == root / MODULE.ATTRIBUTES_PATH
            )
            self.assertEqual(
                attribute_seal.sha256,
                hashlib.sha256(b"fixtures/** -whitespace\n").hexdigest(),
            )

            (root / MODULE.ATTRIBUTES_PATH).write_text(
                "fixtures/** whitespace\n", encoding="utf-8"
            )
            after = MODULE.generation_input_seals(
                root, (Path("contract.ko"),), koto, admission_tool
            )
            self.assertNotEqual(before, after)

    def test_attribute_value_tamper_fails_closed(self) -> None:
        source = Path("contracts/live.ko")
        for value in (b"set", b"trailing-space", b"whitespace"):
            with self.subTest(value=value):
                output = b"contracts/live.ko\0whitespace\0" + value + b"\0"
                with (
                    mock.patch.object(
                        MODULE.subprocess,
                        "run",
                        return_value=self._attribute_result(output),
                    ),
                    self.assertRaisesRegex(
                        MODULE.GoldenError, "unsupported whitespace attribute"
                    ),
                ):
                    MODULE.partition_source_policy(Path("/repository"), (source,))


class StagingModeTests(unittest.TestCase):
    def test_private_compiler_output_is_rendered_publicly_without_source_mutation(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            stage = Path(temporary)
            source = stage / "release/example.to"
            source.parent.mkdir()
            source.write_bytes(b"canonical artifact")
            source.chmod(0o600)
            before = source.stat()
            rows = [MODULE.Golden("standard", Path("example.ko"), Path("example.to"))]
            with mock.patch.object(MODULE, "COMPILER_MANIFESTS", {}):
                rendered = MODULE.rendered_files(stage, rows)
            self.assertEqual(rendered, (MODULE.RenderedFile(Path("example.to"), 0o644, b"canonical artifact"),))
            self.assertEqual(MODULE._metadata_identity(source.stat()), MODULE._metadata_identity(before))
            self.assertEqual(source.read_bytes(), b"canonical artifact")

    def test_compiler_staging_refuses_nonprivate_modes(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary) / "output.to"
            source.write_bytes(b"artifact")
            for mode in (0o400, 0o620, 0o644, 0o666, 0o700):
                with self.subTest(mode=oct(mode)):
                    source.chmod(mode)
                    with self.assertRaisesRegex(MODULE.GoldenError, "mode 0600"):
                        MODULE.read_compiler_output(source)

    def test_runtime_manifest_accepts_exact_bytes_under_private_staging_mode(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary) / "compiler.json"
            destination = Path(temporary) / "runtime.json"
            source.write_bytes(b'{"artifact":"same"}')
            source.chmod(0o600)
            destination.write_bytes(source.read_bytes())
            for mode in (0o600,):
                with self.subTest(mode=oct(mode)):
                    destination.chmod(mode)
                    MODULE.compare_runtime_manifest(source, destination)
                    self.assertEqual(destination.stat().st_mode & 0o7777, mode)

    def test_runtime_manifest_rejects_changed_bytes_or_unsafe_modes(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary) / "compiler.json"
            destination = Path(temporary) / "runtime.json"
            source.write_bytes(b"canonical")
            source.chmod(0o600)
            destination.write_bytes(source.read_bytes())
            for mode in (0o400, 0o620, 0o644, 0o666, 0o700):
                with self.subTest(mode=oct(mode)):
                    destination.chmod(mode)
                    with self.assertRaisesRegex(MODULE.GoldenError, "runtime manifest must use mode"):
                        MODULE.compare_runtime_manifest(source, destination)
            destination.chmod(0o600)
            destination.write_bytes(b"changed")
            with self.assertRaisesRegex(MODULE.GoldenError, "differs from compiler"):
                MODULE.compare_runtime_manifest(source, destination)

    def test_checked_publication_still_requires_exact_public_mode(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            destination = Path(temporary) / "artifact.to"
            destination.write_bytes(b"canonical")
            destination.chmod(0o600)
            with self.assertRaisesRegex(MODULE.GoldenError, "expected 0644, got 0600"):
                MODULE.compare_payload(b"canonical", destination)
            destination.chmod(0o644)
            MODULE.compare_payload(b"canonical", destination)


class StagedPublicationTests(unittest.TestCase):
    def test_private_staging_is_required_before_explicit_public_publication(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            stage = Path(temporary).resolve(strict=True)
            (stage / "release").mkdir()
            artifact = stage / "release/example.to"
            artifact.write_bytes(b"compiler output")
            artifact.chmod(0o644)
            rows = [MODULE.Golden("standard", Path("example.ko"), Path("example.to"))]
            with mock.patch.object(MODULE, "COMPILER_MANIFESTS", {}):
                with self.assertRaisesRegex(MODULE.GoldenError, "mode 0600"):
                    MODULE.rendered_files(stage, rows)
                artifact.chmod(0o600)
                rendered = MODULE.rendered_files(stage, rows)
            self.assertEqual(rendered[0].mode, 0o644)
            self.assertEqual(artifact.stat().st_mode & 0o777, 0o600)
            self.assertEqual(artifact.read_bytes(), b"compiler output")

    def test_publish_and_check_touch_only_the_distinct_output_root(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve(strict=True)
            source_root = root / "source"
            output_root = root / "output"
            stage = root / "stage"
            source_root.mkdir()
            (stage / "release").mkdir(parents=True)
            sentinel = source_root / "sentinel"
            sentinel.write_bytes(b"source remains untouched")
            (stage / "release/example.to").write_bytes(b"canonical artifact")
            (stage / "release/example.to").chmod(0o600)
            rows = [
                MODULE.Golden(
                    mode="standard",
                    source=Path("contracts/example.ko"),
                    destination=Path("artifacts/example.to"),
                )
            ]
            with (
                mock.patch.object(MODULE, "COMPILER_MANIFESTS", {}),
                mock.patch.object(MODULE, "FORBIDDEN_LEGACY_OUTPUTS", ()),
            ):
                rendered = MODULE.rendered_files(stage, rows)
                self.assertEqual(
                    MODULE.publish_create_only(output_root, rendered),
                    1,
                )
                with self.assertRaisesRegex(MODULE.GoldenError, "create-only"):
                    MODULE.publish_create_only(output_root, rendered)
                self.assertEqual(
                    MODULE.verify_rendered_tree(output_root, rendered),
                    0,
                )

                destination = output_root / "artifacts/example.to"
                before = b"stale artifact"
                destination.write_bytes(before)
                with self.assertRaises(MODULE.GoldenError):
                    MODULE.verify_rendered_tree(output_root, rendered)
                self.assertEqual(destination.read_bytes(), before)

            self.assertEqual(sentinel.read_bytes(), b"source remains untouched")
            self.assertEqual([entry.name for entry in source_root.iterdir()], ["sentinel"])

    def test_nested_output_symlink_cannot_escape_the_selected_root(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve(strict=True)
            output_root = root / "output"
            outside = root / "below ignored target"
            stage = root / "stage"
            output_root.mkdir()
            outside.mkdir()
            (stage / "release").mkdir(parents=True)
            (stage / "release/example.to").write_bytes(b"canonical artifact")
            (stage / "release/example.to").chmod(0o600)
            try:
                (output_root / "artifacts").symlink_to(
                    outside,
                    target_is_directory=True,
                )
            except (NotImplementedError, OSError):
                self.skipTest("symlinks are unavailable on this platform")
            rows = [
                MODULE.Golden(
                    mode="standard",
                    source=Path("contracts/example.ko"),
                    destination=Path("artifacts/example.to"),
                )
            ]
            with (
                mock.patch.object(MODULE, "COMPILER_MANIFESTS", {}),
                mock.patch.object(MODULE, "FORBIDDEN_LEGACY_OUTPUTS", ()),
                self.assertRaises(MODULE.GoldenError),
            ):
                rendered = MODULE.rendered_files(stage, rows)
                MODULE.publish_create_only(output_root, rendered)
            self.assertEqual(list(outside.iterdir()), [])

    def test_forbidden_legacy_output_is_rejected_without_removal(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            output_root = Path(temporary)
            legacy = Path("legacy/retired.to")
            legacy_path = output_root / legacy
            legacy_path.parent.mkdir()
            legacy_path.write_bytes(b"retired")

            with (
                mock.patch.object(MODULE, "FORBIDDEN_LEGACY_OUTPUTS", (legacy,)),
                mock.patch.object(MODULE, "repository_root", return_value=output_root),
                self.assertRaisesRegex(MODULE.GoldenError, "retired Kotodama"),
            ):
                MODULE.verify_rendered_tree(output_root, ())
            self.assertEqual(legacy_path.read_bytes(), b"retired")

    def test_unsealed_or_unexpected_external_tree_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve(strict=True)
            publication = root / "publication"
            rendered = (
                MODULE.RenderedFile(Path("artifacts/example.to"), 0o644, b"artifact"),
            )
            publication.mkdir(mode=0o700)
            (publication / "artifacts").mkdir(mode=0o755)
            (publication / "artifacts/example.to").write_bytes(b"artifact")
            with self.assertRaisesRegex(MODULE.GoldenError, "complete"):
                MODULE.verify_rendered_tree(publication, rendered)

            manifest = publication / MODULE.PUBLICATION_MANIFEST_PATH
            manifest.write_bytes(MODULE.owner_manifest(rendered))
            (publication / "unexpected").mkdir(mode=0o755)
            with self.assertRaisesRegex(MODULE.GoldenError, "unexpected"):
                MODULE.verify_rendered_tree(publication, rendered)

    def test_failed_preseal_leaves_rejected_residue_without_completion(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            publication = Path(temporary).resolve(strict=True) / "publication"
            rendered = (
                MODULE.RenderedFile(Path("artifacts/example.to"), 0o644, b"artifact"),
            )

            def reject() -> None:
                raise MODULE.GoldenError("source drift")

            with self.assertRaisesRegex(MODULE.GoldenError, "source drift"):
                MODULE.publish_create_only(
                    publication,
                    rendered,
                    preseal=reject,
                )
            self.assertTrue((publication / "artifacts/example.to").is_file())
            self.assertFalse((publication / MODULE.PUBLICATION_MANIFEST_PATH).exists())
            with self.assertRaisesRegex(MODULE.GoldenError, "complete"):
                MODULE.verify_rendered_tree(publication, rendered)


class TestModuleValidationTests(unittest.TestCase):
    def test_scaffold_pair_and_ordinary_tests_use_the_real_test_runner(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            template = Path("crates/musubi/templates/contract.test.ko")
            template_bytes = (MODULE.repository_root() / template).read_bytes()
            (root / template).parent.mkdir(parents=True)
            (root / template).write_bytes(template_bytes)
            contract = root / "crates/musubi/templates/contract.ko"
            contract.write_bytes(b"contract-source")
            ordinary = Path("examples/coffee-club/tests/coffee-club.test.ko")
            observed = []

            def execute(command, cwd):
                self.assertEqual(command[1:3], ["test", "run"])
                self.assertEqual(command[-3:-1], ["--source-root", cwd])
                if Path(command[-1]).is_absolute():
                    staged = Path(command[-1])
                    self.assertEqual(staged.read_bytes(), template_bytes)
                    target = re.search(rb'koto_test\s*\{\s*target:\s*"([^"]+)"', template_bytes)
                    self.assertIsNotNone(target)
                    self.assertEqual(
                        (staged.parent / target.group(1).decode("utf-8")).read_bytes(),
                        contract.read_bytes(),
                    )
                    self.assertEqual(cwd, staged.parent.parent)
                observed.append(command[-1])
                return "{}"

            with mock.patch.object(MODULE, "run", side_effect=execute):
                MODULE.validate_additional_test_sources(
                    Path("koto"), root, [MODULE.TEST_SOURCE, template, ordinary], root
                )
            self.assertEqual(len(observed), 2)
            self.assertIn(ordinary, observed)
            self.assertEqual((root / template).read_bytes(), template_bytes)

    def test_test_runner_failure_is_not_reclassified_as_a_deployable_source(self) -> None:
        with mock.patch.object(MODULE, "run", side_effect=MODULE.GoldenError("test failed")):
            with self.assertRaisesRegex(MODULE.GoldenError, "test failed"):
                MODULE.validate_additional_test_sources(
                    Path("koto"), Path("root"), [Path("contract.test.ko")], Path("stage")
                )


class TwoPassTests(unittest.TestCase):
    def test_renderings_bind_sorted_paths_modes_bytes_and_manifest(self) -> None:
        first = (
            MODULE.RenderedFile(Path("a/one.to"), 0o644, b"one"),
            MODULE.RenderedFile(Path("b/two.to"), 0o644, b"two"),
        )
        MODULE.compare_renderings(first, tuple(first))
        self.assertEqual(
            MODULE.owner_manifest(first),
            MODULE.owner_manifest(tuple(first)),
        )
        manifest = MODULE.json.loads(MODULE.owner_manifest(first))
        self.assertEqual(manifest["root_mode"], "0700")
        self.assertEqual(
            manifest["directories"],
            [
                {"path": "a", "mode": "0755"},
                {"path": "b", "mode": "0755"},
            ],
        )

        for changed in (
            first[::-1],
            (first[0], MODULE.RenderedFile(first[1].relative_path, 0o600, b"two")),
            (first[0], MODULE.RenderedFile(first[1].relative_path, 0o644, b"drift")),
        ):
            with self.subTest(changed=changed):
                with self.assertRaises(MODULE.GoldenError):
                    MODULE.compare_renderings(first, changed)


if __name__ == "__main__":
    unittest.main()
