"""Offline custody/stream tests; no SSH, deployment, build or runtime input access."""
from __future__ import annotations

import copy
import errno
import importlib.util
import io
import json
import os
from pathlib import Path
import platform
import stat
import shutil
import subprocess
import sys
import tempfile
import types
import unittest
from unittest.mock import patch

SCRIPTS = Path(__file__).resolve().parents[2] / "scripts"
sys.path.insert(0, str(SCRIPTS))
import taira_release_transfer as transfer
import taira_disk_capacity as capacity


class SourceOwner:
    """Explicit source-owner seam: production cryptography has its own signed Git tests."""
    def __init__(self):
        self.imports = 0
        self.verifications = 0
        self.reject = False

    def import_source(self, pack, manifest, commit, tree, signer, root):
        self.imports += 1
        if self.reject:
            raise ValueError("signed object inventory rejected")
        root.mkdir(mode=0o700)
        transfer.write_new(root / "public.txt", b"exact signed source\n")
        return self.verify_import(root, manifest, commit, tree, signer)

    def verify_import(self, root, manifest, commit, tree, signer):
        self.verifications += 1
        if self.reject or transfer.read(root / "public.txt") != b"exact signed source\n":
            raise ValueError("source signature/tree rejection")
        return {"commit": commit, "tree": tree, "signer_fingerprint": signer,
                "clean": True, "signature_verified": True, "object_inventory_verified": True,
                "source_root": str(root), "activated": False,
                "runtime_files_included": False,
                "history_included": False, "runtime_files_transferred": False}


class TransferTests(unittest.TestCase):
    def setUp(self):
        # Native private ancestry; /tmp's sticky writable parent is deliberately
        # not accepted for root-owned deployment custody.
        self.directory = tempfile.TemporaryDirectory(prefix=".taira-transfer-test-", dir=Path.home())
        self.root = Path(self.directory.name).resolve()
        os.chmod(self.root, 0o700)
        self.runtime = self.root / "runtime"
        self.runtime.mkdir(mode=0o700)
        result = b'{"public":"prepared result"}\n'
        self.data = [b"\x7fELF" + bytes([index]) * 64 for index in range(4)] + [
            b"public git packet", b'{"public":"manifest"}\n', result,
            b'{"public":"prepared request"}\n', b'{"public":"native checks"}\n', result]
        rows = [{"name": name, "size": len(raw), "sha256": transfer.sha(raw)}
                for name, raw in zip(transfer.PAYLOAD_NAMES, self.data)]
        self.request = {"schema": transfer.SCHEMA, "commit": "a" * 40, "tree": "b" * 40,
            "signer_fingerprint": "C" * 40, "result_sha256": transfer.sha(result),
            "runtime_root": str(self.runtime), "rows": rows,
            "allocation": {"bytes": 1024**2, "files": 100, "directories": 100}}
        self.owner = SourceOwner()
        self.capacity = types.SimpleNamespace(PLAN_SCHEMA=capacity.PLAN_SCHEMA,
            inspect_filesystem=lambda path: {"fragment_bytes": 4096},
            allocation_bound=capacity.allocation_bound,
            evaluate=lambda plan: {"schema": capacity.RESULT_SCHEMA, "passed": True, "errors": []})

    def tearDown(self):
        self.directory.cleanup()

    @property
    def destination(self):
        return self.runtime / transfer.import_name(self.request)

    def receive(self, data=None):
        return transfer.receive(self.request, io.BytesIO(b"".join(self.data) if data is None else data),
                                self.owner, self.capacity)

    def test_round_trip_publishes_exact_receipts_and_reuses_without_writes(self):
        result = self.receive()
        self.assertFalse(result["activated"])
        self.assertEqual(result["binary"]["artifacts"], self.request["rows"][:4])
        self.assertEqual(result["source"]["result_sha256"], self.request["result_sha256"])
        self.assertTrue(result["source"]["signature_verified"])
        self.assertFalse(result["source"]["history_included"])
        before = {str(path): transfer.identity(path.lstat()) for path in self.destination.rglob("*")}
        self.assertEqual(self.receive(), result)
        after = {str(path): transfer.identity(path.lstat()) for path in self.destination.rglob("*")}
        self.assertEqual(before, after)
        self.assertEqual(self.owner.imports, 1)
        for name in transfer.NAMES:
            self.assertEqual(stat.S_IMODE((self.destination / "artifacts/bin" / name).stat().st_mode), 0o755)
        pack = self.destination / "source/source.pack"
        self.assertEqual(stat.S_IMODE(pack.stat().st_mode), 0o600)
        self.assertEqual(stat.S_IMODE((self.destination / "source/source-capture.json").stat().st_mode), 0o400)
        for index, name in enumerate(transfer.PROOF_NAMES, start=6):
            path = self.destination / name
            self.assertEqual(path.read_bytes(), self.data[index])
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o400)
        pack.chmod(0o400)
        with self.assertRaisesRegex(transfer.TransferError, "input mode differs"):
            self.receive()

    def test_mutated_truncated_and_extra_streams_never_publish_success(self):
        for label, payload in (("changed", b"X" + b"".join(self.data)[1:]),
                               ("short", b"".join(self.data)[:-1]),
                               ("extra", b"".join(self.data) + b"X")):
            with self.subTest(label=label):
                self.runtime = self.root / ("runtime-" + label)
                self.runtime.mkdir(mode=0o700)
                self.request["runtime_root"] = str(self.runtime)
                with self.assertRaises(transfer.TransferError):
                    self.receive(payload)
                self.assertTrue(self.destination.is_dir())
                self.assertFalse((self.destination / "completed.json").exists())
                with self.assertRaises(transfer.TransferError):
                    self.receive()

    def test_source_verification_failure_preserves_partial_without_receipts(self):
        self.owner.reject = True
        with self.assertRaises(ValueError):
            self.receive()
        self.assertFalse((self.destination / "completed.json").exists())
        self.assertFalse((self.destination / "artifacts/verified-manifest.json").exists())
        self.assertTrue((self.destination / "source/source.pack").exists())

    def test_completed_reuse_rejects_every_payload_mutation_and_unsafe_link(self):
        self.receive()
        for row in self.request["rows"]:
            path = transfer.payload_path(self.destination, row["name"])
            original = path.read_bytes()
            path.chmod(0o600)
            path.write_bytes(b"x" * len(original))
            path.chmod(transfer.payload_mode(row["name"]))
            with self.subTest(name=row["name"]):
                with self.assertRaisesRegex(transfer.TransferError, "digest differs"):
                    self.receive()
            path.chmod(0o600)
            path.write_bytes(original)
            path.chmod(transfer.payload_mode(row["name"]))
        path = self.destination / "artifacts/bin/iroha"
        os.link(path, self.root / "alias")
        with self.assertRaisesRegex(transfer.TransferError, "custody"):
            self.receive()

    def test_completed_extra_or_missing_entry_and_source_drift_reject(self):
        self.receive()
        extra = self.destination / "extra"
        extra.write_bytes(b"unexpected")
        with self.assertRaisesRegex(transfer.TransferError, "unexpected entries"):
            self.receive()
        extra.unlink()
        source = self.destination / "source/source/public.txt"
        source.chmod(0o600)
        source.write_bytes(b"wrong signed source")
        with self.assertRaisesRegex(ValueError, "source signature/tree"):
            self.receive()

    def test_completed_receipt_and_repeated_stream_drift_reject(self):
        self.receive()
        with self.assertRaisesRegex(transfer.TransferError, "repeated transfer digest"):
            self.receive(b"X" + b"".join(self.data)[1:])
        receipt = self.destination / "artifacts/verified-manifest.json"
        receipt.chmod(0o600)
        receipt.write_bytes(b'{}\n')
        receipt.chmod(0o400)
        with self.assertRaisesRegex(transfer.TransferError, "receipt differs"):
            self.receive()

    def test_completed_capacity_charges_only_headroom_and_partial_is_not_adopted(self):
        fresh = transfer.capacity_probe(self.request, self.capacity)
        self.assertFalse(fresh["reuse"])
        self.assertEqual(len(fresh["plan"]["allocations"]), 2)
        self.receive()
        completed = transfer.capacity_probe(self.request, self.capacity)
        self.assertTrue(completed["reuse"])
        self.assertEqual(completed["plan"]["allocations"], [{"path": str(self.runtime),
            "label": "filesystem operating headroom", "bytes": transfer.HEADROOM, "inodes": 1024}])
        (self.destination / "completed.json").unlink()
        with self.assertRaises(FileNotFoundError):
            transfer.capacity_probe(self.request, self.capacity)

    def test_capacity_failure_precedes_destination_creation(self):
        self.capacity.evaluate = lambda plan: {"passed": False}
        with self.assertRaisesRegex(transfer.TransferError, "capacity"):
            self.receive()
        self.assertFalse(self.destination.exists())
        self.assertEqual(self.owner.imports, 0)

    def test_closed_payload_schema_rejects_traversal_duplicates_sizes_and_missing(self):
        for mutate in (
            lambda value: value["rows"].pop(),
            lambda value: value["rows"][0].update(name="../outside"),
            lambda value: value["rows"][1].update(name=value["rows"][0]["name"]),
            lambda value: value["rows"][0].update(size=True),
            lambda value: value["rows"][0].update(size=transfer.MAX_BINARY + 1),
            lambda value: value["rows"][6].update(size=transfer.MAX_PROOF + 1),
            lambda value: value["rows"][9].update(sha256="e" * 64),
            lambda value: value.update(result_sha256="e" * 64),
            lambda value: value.update(rows=value["rows"][:6]),
            lambda value: value.update(extra=True),
        ):
            value = copy.deepcopy(self.request)
            mutate(value)
            with self.subTest(value=value):
                with self.assertRaises(transfer.TransferError):
                    transfer.validate_request(value)

    def test_same_tick_mutation_is_detected_by_descriptor_content_reread(self):
        path = self.root / "public"
        transfer.write_new(path, b"original", mode=0o600)
        with patch.object(transfer, "identity", return_value=(1,)):
            with self.assertRaisesRegex(transfer.TransferError, "changed during use"):
                with transfer.pinned(path) as (fd, _, _):
                    path.write_bytes(b"modified")

    def test_private_parent_and_symlink_roots_reject_before_payload(self):
        self.runtime.chmod(0o777)
        with self.assertRaisesRegex(transfer.TransferError, "unsafe directory"):
            self.receive()
        self.runtime.chmod(0o700)
        alias = self.root / "alias"
        alias.symlink_to(self.runtime, target_is_directory=True)
        self.request["runtime_root"] = str(alias)
        with self.assertRaisesRegex(transfer.TransferError, "direct path"):
            self.receive()

    def test_receiver_stream_deadline_is_enforced_without_sender_eof(self):
        incoming, outgoing = os.pipe()
        try:
            with os.fdopen(incoming, "rb", buffering=0) as stream:
                reader = transfer.DeadlineReader(stream, 0.01)
                with self.assertRaisesRegex(transfer.TransferError, "receiver stream deadline"):
                    reader.read(1)
        finally:
            os.close(outgoing)

    def test_sender_streams_fixed_code_and_exact_bytes_through_real_pipe(self):
        modules = {name: b"" for name in transfer.MODULES}
        # Real subprocess executes the fixed framing bootstrap locally, without
        # SSH. The authenticated receiver seam only reads and reports exact bytes.
        modules["taira_release_transfer"] = b'''import hashlib
def remote_entry(e, stream):
 b=stream.read();return {"size":len(b),"sha256":hashlib.sha256(b).hexdigest()}
'''
        path = self.root / "payload"
        raw = b"bounded payload\x00" * 100000
        transfer.write_new(path, raw, mode=0o600)
        row = {"size": len(raw), "sha256": transfer.sha(raw)}
        retry = types.SimpleNamespace(validate_ssh=lambda route: [sys.executable, "-c", "unused"])
        # Existing strict SSH validation is reused in production; replace only
        # command construction for this no-network real-child transport test.
        with patch.object(transfer, "REMOTE_COMMAND", transfer.BOOTSTRAP):
            result = transfer.remote_call({}, {"operation": "import"}, modules,
                self.root / "transport", retry, [(row, path)])
        self.assertEqual(result, {"size": len(raw), "sha256": transfer.sha(raw)})

    def test_signed_module_loader_ignores_poisoned_cached_objects(self):
        poisoned = types.ModuleType("release_artifact_contract")
        poisoned.marker = "untrusted cached code"
        source = {name: b"marker = 'signed bytes'\n" for name in transfer.CONTROLLERS}
        source["taira_source_capture"] = b"import release_artifact_contract\nmarker = release_artifact_contract.marker\n"
        with patch.dict(sys.modules, {"release_artifact_contract": poisoned}):
            loaded = transfer.load_signed_modules(source, self.root)
            self.assertIsNot(loaded["release_artifact_contract"], poisoned)
            self.assertEqual(loaded["taira_source_capture"].marker, "signed bytes")
            self.assertEqual(loaded["taira_release_transfer"].marker, "signed bytes")
        with self.assertRaisesRegex(transfer.TransferError, "byte closure"):
            transfer.load_signed_modules({"taira_retry": b""}, self.root)

    def preparation_fixture(self, scope="basic", target="aarch64-unknown-linux-gnu", machine=183):
        import taira_release as release
        output = self.root / "preparation"
        output.mkdir(mode=0o700)
        (output / "attempts").mkdir(mode=0o700)
        attempt = output / "attempts/000001"
        attempt.mkdir(mode=0o700)
        (attempt / "bin").mkdir(mode=0o700)
        header = b"\x7fELF\x02\x01\x01" + b"\x00" * 9 + b"\x02\x00" + machine.to_bytes(2, "little")
        rows = []
        for name, package in zip(transfer.NAMES, transfer.PACKAGES):
            path = attempt / "bin" / name
            transfer.write_new(path, header, mode=0o500)
            rows.append({"name": name, "package": package, "path": str(path),
                         "size": len(header), "sha256": transfer.sha(header)})
        (attempt / "bin").chmod(0o500)
        base = dict.fromkeys(transfer.BASE_FIELDS, "fixture")
        base.update(commit="a" * 40, tree="b" * 40, signer_fingerprint="C" * 40,
            target=target, profile="release", jobs=6, native_check_scope=scope,
            source_unchanged=True, toolchain_unchanged=True, release_qualified=False, deployed=False,
            source_snapshot_sha256=transfer.sha(release.canonical_json_bytes([])),
            source_root=str(self.root / "source"))
        request = dict(base, schema=release.SESSION_SCHEMA,
                       repo_root=str(SCRIPTS.parent), target_dir=str(self.root))
        result = dict(base, artifacts=rows, timings_seconds={}, attempt="attempts/000001")
        raw = release.canonical_json_bytes(result)
        for path, value in ((output / "request.json", request),
                            (output / "checks.json", {"request": request, "passed": scope != "build-only"}),
                            (attempt / "capture.json", result), (output / "result.json", result)):
            transfer.write_new(path, release.canonical_json_bytes(value))
        attempt.chmod(0o500)
        output.chmod(0o500)
        plan = {"expected_commit": "a" * 40, "expected_signer": "C" * 40,
                "preparation": {"path": str(output / "result.json"), "sha256": transfer.sha(raw)}}
        return release, plan, result, output

    def test_preparation_admits_exact_x86_receipt_and_refuses_crossed_elf(self):
        release, plan, expected, output = self.preparation_fixture(target="x86_64-unknown-linux-gnu", machine=62)
        with patch.object(release, "commit_entries", return_value=b""), patch.object(release, "frozen_snapshot", return_value=[]):
            self.assertEqual(transfer.admit_preparation(plan, {"taira_release": release}, "b" * 40), expected)
            # Substitute the target in all locally consistent records and rebind
            # their digest, leaving the real x86 bytes unchanged. ELF must still refuse.
            expected["target"] = "aarch64-unknown-linux-gnu"
            request = release.read_record(output / "request.json")
            request["target"] = expected["target"]
            for path, value in [(output / "request.json", request),
                    (output / "checks.json", {"request": request, "passed": True}),
                    (output / "result.json", expected), (output / expected["attempt"] / "capture.json", expected)]:
                path.chmod(0o600)
                path.write_bytes(release.canonical_json_bytes(value))
                path.chmod(0o400)
            plan["preparation"]["sha256"] = transfer.sha(release.canonical_json_bytes(expected))
            with self.assertRaisesRegex(release.PrepareError, "ELF differs from receipt target"):
                transfer.admit_preparation(plan, {"taira_release": release}, "b" * 40)

    def test_x86_artifact_support_does_not_widen_native_host_authority(self):
        request = {"build": {"target": "x86_64-unknown-linux-gnu"}}
        with open(os.devnull, "rb") as stream, patch.object(transfer.sys, "platform", "linux"), patch.object(transfer.platform, "machine", return_value="aarch64"), patch.object(transfer.os, "geteuid", return_value=0), patch.object(transfer, "native_guest") as execute:
            with self.assertRaisesRegex(transfer.TransferError, "target differs from the admitted AArch64 host"):
                transfer.remote_entry({"operation": "native-exec", "request": request, "modules": {}}, stream)
            execute.assert_not_called()
        with open(os.devnull, "rb") as stream, patch.object(transfer.sys, "platform", "linux"), patch.object(transfer.platform, "machine", return_value="x86_64"), patch.object(transfer.os, "geteuid", return_value=0), patch.object(transfer, "native_guest") as execute:
            with self.assertRaisesRegex(transfer.TransferError, "requires AArch64 Linux root"):
                transfer.remote_entry({"operation": "native-exec", "request": request, "modules": {}}, stream)
            execute.assert_not_called()
        # Provider rejection remains independent of artifact architecture.
        plan = {"schema": transfer.SCHEMA, "provider": "macstadium-dublin",
                "preparation": {"path": "/private/result.json", "sha256": "a" * 64},
                "expected_commit": "b" * 40, "expected_signer": "C" * 40,
                "guest_ssh": [], "backing_ssh": [], "backing_path": "/private/backing",
                "runtime_root": "/private/runtime"}
        transfer.validate_plan(plan)
        plan["provider"] = "ovh"
        with self.assertRaisesRegex(transfer.TransferError, "exact MacStadium transfer plan required"):
            transfer.validate_plan(plan)

    def test_preparation_admits_exact_capture_and_refuses_changed_binary_or_native_checkpoint(self):
        release, plan, expected, output = self.preparation_fixture()
        with patch.object(release, "commit_entries", return_value=b""), \
             patch.object(release, "frozen_snapshot", return_value=[]):
            self.assertEqual(transfer.admit_preparation(plan, {"taira_release": release}, "b" * 40), expected)
            binary = Path(expected["artifacts"][0]["path"])
            binary.chmod(0o700)
            binary.write_bytes(b"x" * expected["artifacts"][0]["size"])
            binary.chmod(0o500)
            with self.assertRaisesRegex(release.PrepareError, "captured artifact changed"):
                transfer.admit_preparation(plan, {"taira_release": release}, "b" * 40)
            checkpoint = output / "checks.json"
            checkpoint.chmod(0o600)
            checkpoint.write_bytes(release.canonical_json_bytes({"passed": False}))
            checkpoint.chmod(0o400)
            with self.assertRaisesRegex(transfer.TransferError, "qualification checkpoint"):
                transfer.admit_preparation(plan, {"taira_release": release}, "b" * 40)

    def test_checks_require_exact_scope_boolean_and_request(self):
        for scope in ("basic", "full", "build-only"):
            request = {"native_check_scope": scope, "commit": "a" * 40}
            passed = scope != "build-only"
            self.assertTrue(transfer.preparation_checks_match(request,
                            {"request": request, "passed": passed}))
            self.assertTrue(transfer.preparation_checks_match(request,
                            {"request": request, "passed": not passed}))
            for invalid in (0, 1, None, "false"):
                self.assertFalse(transfer.preparation_checks_match(request,
                                 {"request": request, "passed": invalid}))
            self.assertFalse(transfer.preparation_checks_match(request,
                             {"request": dict(request, commit="b" * 40), "passed": passed}))
            self.assertFalse(transfer.preparation_checks_match(request,
                             {"request": request, "passed": passed, "extra": True}))
        request = {"native_check_scope": "unknown"}
        self.assertFalse(transfer.preparation_checks_match(request,
                         {"request": request, "passed": False}))

    def test_build_only_transfer_preserves_boolean_evidence_without_a_pass_gate(self):
        release, plan, expected, output = self.preparation_fixture("build-only")
        with patch.object(release, "commit_entries", return_value=b""), \
             patch.object(release, "frozen_snapshot", return_value=[]):
            self.assertEqual(transfer.admit_preparation(plan, {"taira_release": release}, "b" * 40), expected)
            payloads = transfer.preparation_payloads(plan, expected)
            checkpoint = output / "checks.json"
            self.assertEqual(payloads[2][1], checkpoint)
            self.assertIs(release.read_record(checkpoint)["passed"], False)
            checkpoint.chmod(0o600)
            checkpoint.write_bytes(release.canonical_json_bytes(
                {"request": release.read_record(output / "request.json"), "passed": True}))
            checkpoint.chmod(0o400)
            self.assertEqual(transfer.admit_preparation(plan, {"taira_release": release}, "b" * 40), expected)
            transfer.preparation_payloads(plan, expected)
            checkpoint.chmod(0o600)
            checkpoint.write_bytes(release.canonical_json_bytes(
                {"request": release.read_record(output / "request.json"), "passed": 0}))
            checkpoint.chmod(0o400)
            with self.assertRaisesRegex(transfer.TransferError, "qualification checkpoint"):
                transfer.admit_preparation(plan, {"taira_release": release}, "b" * 40)
            with self.assertRaisesRegex(transfer.TransferError, "checkpoint changed"):
                transfer.preparation_payloads(plan, expected)
    def test_preparation_refuses_foreign_identity_capture_record_and_frozen_source(self):
        release, plan, expected, output = self.preparation_fixture()
        with patch.object(release, "commit_entries", return_value=b""), \
             patch.object(release, "frozen_snapshot", return_value=[]):
            for key, value in (("expected_commit", "e" * 40), ("expected_signer", "F" * 40)):
                wrong = dict(plan, **{key: value})
                with self.assertRaisesRegex(transfer.TransferError, "matching maintained preparation"):
                    transfer.admit_preparation(wrong, {"taira_release": release}, "b" * 40)
            with patch.object(release, "frozen_snapshot", return_value=[{"changed": True}]):
                with self.assertRaisesRegex(transfer.TransferError, "source snapshot differs"):
                    transfer.admit_preparation(plan, {"taira_release": release}, "b" * 40)
            capture = output / expected["attempt"] / "capture.json"
            capture.chmod(0o600)
            capture.write_bytes(b"{}\n")
            capture.chmod(0o400)
            with self.assertRaisesRegex(transfer.TransferError, "capture differs"):
                transfer.admit_preparation(plan, {"taira_release": release}, "b" * 40)

    def test_preparation_payloads_bind_actual_proofs_and_refuse_changed_checkpoint(self):
        release, plan, build, output = self.preparation_fixture()
        payloads = transfer.preparation_payloads(plan, build)
        self.assertEqual(tuple(row["name"] for row, _ in payloads), transfer.PROOF_NAMES)
        self.assertEqual(payloads[0][0]["sha256"], plan["preparation"]["sha256"])
        self.assertEqual(payloads[0][1].read_bytes(), payloads[3][1].read_bytes())
        for row, path in payloads:
            self.assertEqual((row["size"], row["sha256"]), (path.stat().st_size, transfer.sha(path.read_bytes())))
        checkpoint = output / "checks.json"
        checkpoint.chmod(0o600)
        checkpoint.write_bytes(release.canonical_json_bytes({"request": release.read_record(output / "request.json"), "passed": 0}))
        checkpoint.chmod(0o400)
        with self.assertRaisesRegex(transfer.TransferError, "checkpoint changed"):
            transfer.preparation_payloads(plan, build)

    def test_cli_help_has_no_activation_runtime_or_shell_options(self):
        result = subprocess.run([sys.executable, "-B", str(SCRIPTS / "taira_release_transfer.py"), "--help"],
                                capture_output=True, text=True, check=True)
        self.assertIn("--plan", result.stdout)
        self.assertIn("--native-plan", result.stdout)
        for flag in ("--activate", "--command", "--private-key", "--reset", "--service"):
            self.assertNotIn(flag, result.stdout)


class NativeInvocationTests(unittest.TestCase):
    """Receipt admission everywhere; actual descriptor execution on Linux only."""

    def setUp(self):
        self.fixture = TransferTests(methodName="runTest")
        self.fixture.setUp()
        self.addCleanup(self.fixture.tearDown)
        self.root, self.runtime = self.fixture.root, self.fixture.runtime
        self.addCleanup(patch.stopall)
        patch.object(transfer, "NATIVE_RUNTIME", str(self.runtime)).start()
        release, preparation, self.build, output = self.fixture.preparation_fixture(
            getattr(self, "preparation_scope", "basic"),
            target=getattr(self, "preparation_target", "aarch64-unknown-linux-gnu"))
        self.preparation = preparation
        if sys.platform == "linux" or hasattr(self, "native_image"):
            image = (self.native_image if hasattr(self, "native_image")
                     else Path(sys.executable).resolve().read_bytes())
            for row in self.build["artifacts"]:
                path = Path(row["path"])
                path.chmod(0o600)
                path.write_bytes(image)
                path.chmod(0o500)
                row.update(size=len(image), sha256=transfer.sha(image))
            for path in (output / "result.json", output / self.build["attempt"] / "capture.json"):
                path.chmod(0o600)
                path.write_bytes(release.canonical_json_bytes(self.build))
                path.chmod(0o400)
            preparation["preparation"]["sha256"] = transfer.sha(release.canonical_json_bytes(self.build))
        proof_paths = (output / "result.json", output / "request.json", output / "checks.json",
                       output / self.build["attempt"] / "capture.json")
        self.fixture.data = [Path(row["path"]).read_bytes() for row in self.build["artifacts"]] + [
            b"public git packet", b'{"public":"manifest"}\n', *(path.read_bytes() for path in proof_paths)]
        self.fixture.request["rows"] = [{"name": name, "size": len(raw), "sha256": transfer.sha(raw)}
                                       for name, raw in zip(transfer.PAYLOAD_NAMES, self.fixture.data)]
        self.fixture.request["result_sha256"] = preparation["preparation"]["sha256"]
        self.fixture.request["allocation"]["bytes"] = sum(map(len, self.fixture.data)) + 1024**2
        self.request = self.fixture.request
        self.completed = self.fixture.receive()
        def reference(name, value, mode=0o400):
            raw = transfer.canonical(value)
            path = self.root / name
            transfer.write_new(path, raw, mode=mode)
            return {"path": str(path), "sha256": transfer.sha(raw)}
        self.plan = {"schema": transfer.NATIVE_SCHEMA, "provider": "macstadium-dublin",
            "invocation_id": "d" * 32, "expected_commit": "a" * 40, "expected_signer": "C" * 40,
            "descriptor": reference("descriptor.json", {"schema": "taira.runtime-deployment.v1", "runtime_root": str(self.runtime),
                "public_origin": "https://taira.sora.org", "guest_ssh": {"test": "pinned route"}}, 0o600),
            "preparation": preparation["preparation"],
            "import_request": reference("request.json", self.request),
            "import_completed": reference("completed.json", self.completed),
            "program": "iroha", "argv": ["--help"], "files": [], "stdout_file": None,
            "timeout_seconds": 5}
        self.value = {"plan": self.plan, "tree": "b" * 40, "build": self.build,
                      "import_request": self.request, "completed": self.completed}

    def test_closed_plan_rejects_shell_programs_paths_fd_aliases_and_unbounded_inputs(self):
        self.assertIs(transfer.validate_native_plan(self.plan), self.plan)
        changes = [dict(program="iroha3d_taira"), dict(program="/bin/sh"), dict(argv=["bad\narg"]),
                   dict(argv=["x" * 8193]), dict(timeout_seconds=True), dict(timeout_seconds=86401),
                   dict(invocation_id=""), dict(extra="ignored"), dict(stdout_file="/tmp/output"),
                   dict(files=[{"fd": 0, "path": str(self.runtime / "key")}]),
                   dict(files=[{"fd": 3, "path": "/etc/key"}]),
                   dict(files=[{"fd": 3, "path": str(self.runtime / "key")}] * 2)]
        for changed in changes:
            with self.subTest(changed=changed), self.assertRaises(transfer.TransferError):
                transfer.validate_native_plan({**self.plan, **changed})
        result = subprocess.run([sys.executable, "-B", str(SCRIPTS / "taira_release_transfer.py"),
            "--plan", "a", "--native-plan", "b", "--output-dir", "c"], capture_output=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(b"not allowed with argument", result.stderr)

    def test_native_selected_image_header_must_match_bound_target_before_execution(self):
        # Exercise actual files, hashes and import/preparation receipts through
        # native_guest. Only the child execution is substituted: this portable
        # header control grants no host authority and executes no fixture image.
        for target, machine in [("aarch64-unknown-linux-gnu", 183),
                                ("x86_64-unknown-linux-gnu", 62)]:
            for offset, byte in [(None, None), (4, 1), (5, 2), (6, 0), (16, 1),
                                 (17, 1), (18, 0), (19, 1)]:
                header = bytearray(64)
                header[:7] = b"\x7fELF\x02\x01\x01"
                header[16] = 3
                header[18:20] = machine.to_bytes(2, "little")
                if offset is not None:
                    header[offset] = byte
                case = NativeInvocationTests(methodName="runTest")
                case.preparation_target, case.native_image = target, bytes(header)
                try:
                    case.setUp()
                    with self.subTest(target=target, offset=offset), \
                         patch.object(transfer.os, "supports_fd", {os.execve}), \
                         patch.object(transfer, "native_child", return_value={"state": "fixture-header-admitted"}) as child:
                        if offset is None:
                            result = transfer.native_guest(case.value)
                            self.assertEqual(result["executable_sha256"], transfer.sha(header))
                            child.assert_called_once()
                        else:
                            with self.assertRaisesRegex(transfer.TransferError, "ELF differs from exact receipt target"):
                                transfer.native_guest(case.value)
                            child.assert_not_called()
                            attempt = case.runtime / "native-invocations" / case.plan["invocation_id"]
                            self.assertEqual((attempt / "request.json").read_bytes(), transfer.canonical(case.value))
                            self.assertFalse((attempt / "result.json").exists())
                finally:
                    case.doCleanups()

    def test_native_preparation_target_substitution_breaks_original_digest_binding(self):
        build = copy.deepcopy(self.build)
        build["target"] = "x86_64-unknown-linux-gnu"
        with self.assertRaisesRegex(transfer.TransferError, "native preparation identity differs"):
            transfer.admit_native_records(self.plan, "b" * 40, build, self.request, self.completed)
        build["target"] = "x86_64-unknown-linux-musl"
        with self.assertRaisesRegex(transfer.TransferError, "native preparation identity differs"):
            transfer.admit_native_records(self.plan, "b" * 40, build, self.request, self.completed)

    def test_receipts_bind_preparation_exact_roles_and_completed_import(self):
        self.assertEqual(transfer.admit_native_records(self.plan, "b" * 40, self.build,
                         self.request, self.completed), self.fixture.destination)
        for part in ("build", "request", "completed"):
            build, request, completed = copy.deepcopy((self.build, self.request, self.completed))
            if part == "build":
                build["artifacts"][1]["sha256"] = "0" * 64
            elif part == "request":
                request["rows"][1]["sha256"] = "0" * 64
            else:
                completed["binary"]["destination"] = str(self.runtime / "foreign/bin")
            with self.subTest(part=part), self.assertRaises(transfer.TransferError):
                transfer.admit_native_records(self.plan, "b" * 40, build, request, completed)

    def test_build_only_native_invocation_still_binds_actual_import_and_roles(self):
        case = NativeInvocationTests(methodName="runTest")
        case.preparation_scope = "build-only"
        try:
            case.setUp()
            self.assertEqual(case.build["native_check_scope"], "build-only")
            case.test_receipts_bind_preparation_exact_roles_and_completed_import()
        finally:
            case.doCleanups()

    def test_runtime_descriptors_reject_links_permissions_and_unsafe_ancestry_without_reading(self):
        path = self.runtime / "key"
        transfer.write_new(path, b"fake-secret", mode=0o600)
        with patch.object(os, "pread", side_effect=AssertionError("secret bytes read")):
            with transfer.native_file(path) as fd:
                self.assertEqual(os.fstat(fd).st_size, 11)
        path.chmod(0o644)
        with self.assertRaisesRegex(transfer.TransferError, "custody"):
            with transfer.native_file(path):
                pass
        path.chmod(0o600)
        alias = self.runtime / "alias"
        os.link(path, alias)
        with self.assertRaisesRegex(transfer.TransferError, "custody"):
            with transfer.native_file(path):
                pass
        alias.unlink()
        alias.symlink_to(path)
        with self.assertRaises(OSError):
            with transfer.native_file(alias):
                pass
        directory = self.runtime / "unsafe"
        directory.mkdir(mode=0o777)
        directory.chmod(0o777)
        with self.assertRaisesRegex(transfer.TransferError, "ancestry"):
            with transfer.native_file(directory / "new", output=True):
                pass
        self.assertFalse((directory / "new").exists())
        with self.assertRaises(FileExistsError):
            with transfer.native_file(path, output=True):
                pass

    def test_local_transport_loss_retains_durable_attempt_and_never_replays(self):
        route = types.SimpleNamespace(validate_ssh=lambda value: value)
        calls = []
        output = self.root / "attempt"
        def loss(*args, **kwargs):
            self.assertTrue((output / "started.json").exists())
            calls.append(args)
            raise OSError("transport interrupted")
        with patch.object(transfer, "remote_call", side_effect=loss):
            with self.assertRaisesRegex(transfer.TransferError, "do not replay"):
                transfer.invoke_native_admitted(self.plan, output, "b" * 40, {}, {"taira_retry": route})
            with self.assertRaises(FileExistsError):
                transfer.invoke_native_admitted(self.plan, output, "b" * 40, {}, {"taira_retry": route})
        self.assertEqual(len(calls), 1)
        result = transfer.decode((output / "result.json").read_bytes())
        self.assertEqual((result["state"], result["exit_code"]), ("indeterminate", None))

    def test_descriptor_digest_and_guest_receipt_drift_stop_before_execution(self):
        descriptor = Path(self.plan["descriptor"]["path"])
        descriptor.write_bytes(b"{}\n")
        with patch.object(transfer, "remote_call") as remote:
            with self.assertRaisesRegex(transfer.TransferError, "digest"):
                transfer.invoke_native_admitted(self.plan, self.root / "attempt", "b" * 40, {}, {})
            remote.assert_not_called()
        receipt = self.fixture.destination / "artifacts/verified-manifest.json"
        receipt.chmod(0o600)
        receipt.write_bytes(b"{}\n")
        receipt.chmod(0o400)
        with patch.object(transfer, "native_child") as child:
            with self.assertRaisesRegex(transfer.TransferError, "digest"):
                transfer.native_guest(self.value)
            child.assert_not_called()

    def test_partial_pipe_setup_failure_closes_every_opened_descriptor(self):
        def descriptors():
            live = set()
            for name in os.listdir("/dev/fd"):
                try:
                    os.fstat(int(name))
                    live.add(int(name))
                except OSError:
                    pass
            return live
        path = self.fixture.destination / "artifacts/bin/iroha"
        with path.open("rb") as executable:
            for failure in (3, 4):
                before = descriptors()
                original, calls = transfer.fcntl.fcntl, []
                def fail_protect(*args):
                    calls.append(args)
                    if len(calls) == failure:
                        raise OSError(errno.EMFILE, "fixture descriptor limit")
                    return original(*args)
                with self.subTest(protect=failure), patch.object(transfer.fcntl, "fcntl", side_effect=fail_protect):
                    with self.assertRaises(OSError):
                        transfer.native_child(executable.fileno(), path, self.plan, [], None, self.runtime)
                self.assertEqual(descriptors(), before)

    @unittest.skipUnless(sys.platform == "linux" and platform.machine() in ("aarch64", "arm64")
                         and os.execve in os.supports_fd, "AArch64 Linux descriptor exec required")
    def test_linux_held_executable_fd_mapping_collision_and_private_stdout(self):
        first, second = self.runtime / "first", self.runtime / "second"
        transfer.write_new(first, b"secret-three", mode=0o600)
        transfer.write_new(second, b"secret-198", mode=0o400)
        self.plan["files"] = [{"fd": 3, "path": str(first)}, {"fd": 198, "path": str(second)}]
        self.plan["stdout_file"] = str(self.runtime / "private-output")
        # The fixture image is a copied harmless system Python ELF, authenticated
        # by fixture receipts only. Production still permits only signed iroha/kagami.
        self.plan["argv"] = ["-I", "-c", "import os; os.write(1,os.read(3,64)+os.read(198,64)); os.write(2,b'secret-stderr'); "
                            "assert not any(os.path.exists('/proc/self/fd/'+str(n)) for n in (4,5,6,7,8,9))"]
        result = transfer.native_guest(self.value)
        self.assertEqual((result["state"], result["exit_code"]), ("process-exited", 0))
        self.assertEqual(result["stdout_base64"], "")
        self.assertEqual(result["stderr_base64"], "")
        self.assertEqual(Path(self.plan["stdout_file"]).read_bytes(), b"secret-threesecret-198")
        self.assertEqual((Path(result["guest_attempt"]) / "stderr").read_bytes(), b"secret-stderr")
        self.assertNotIn(b"secret-three", transfer.canonical(result))
        self.assertNotIn(b"secret-198", transfer.canonical(result))
        with self.assertRaises(FileExistsError):
            transfer.native_guest(self.value)

    @unittest.skipUnless(sys.platform == "linux" and os.execve in os.supports_fd, "Linux descriptor exec required")
    def test_linux_exec_uses_held_inode_and_closes_unmapped_descriptors(self):
        program = self.runtime / "test-image"
        transfer.write_new(program, Path(sys.executable).resolve().read_bytes(), mode=0o755)
        fd = os.open(program, os.O_RDONLY | os.O_CLOEXEC)
        self.addCleanup(os.close, fd)
        os.unlink(program)
        transfer.write_new(program, b"not the admitted executable", mode=0o755)
        leaked = os.open(self.runtime / "leak", os.O_WRONLY | os.O_CREAT, 0o600)
        self.addCleanup(os.close, leaked)
        os.set_inheritable(leaked, True)
        self.plan["argv"] = ["-I", "-c", "import os; assert not os.path.exists('/proc/self/fd/" + str(leaked) + "'); print('held inode')"]
        attempt = transfer.fresh_directory(self.runtime / "inode-attempt")
        result = transfer.native_child(fd, program, self.plan, [], None, attempt)
        self.assertEqual(result["exit_code"], 0)
        self.assertEqual(transfer.base64.b64decode(result["stdout_base64"]), b"held inode\n")

    @unittest.skipUnless(sys.platform == "linux" and platform.machine() in ("aarch64", "arm64")
                         and os.execve in os.supports_fd, "AArch64 Linux descriptor exec required")
    def test_linux_public_output_is_bounded_nonzero_exit_and_timeout_stay_distinct(self):
        for nonce, code, expected in (("1", "import os; os.write(1,b'x'*1000000); os.write(2,b'y'*1000000); raise SystemExit(7)", 7),
                                      ("2", "import time; time.sleep(10)", -9)):
            self.plan["invocation_id"] = nonce * 32
            self.plan["argv"] = ["-I", "-c", code]
            self.plan["timeout_seconds"] = 1
            result = transfer.native_guest(self.value)
            self.assertEqual(result["exit_code"], expected)
            self.assertEqual(result["state"], "indeterminate" if nonce == "2" else "process-exited")
            if nonce == "1":
                self.assertEqual(result["output_truncated"], {"stdout": True, "stderr": True})
                for key in ("stdout_base64", "stderr_base64"):
                    self.assertEqual(len(transfer.base64.b64decode(result[key])), transfer.NATIVE_OUTPUT_LIMIT)


@unittest.skipUnless(shutil.which("git") and shutil.which("gpg"), "Git/GnuPG required")
class SignedTransferIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Reuse the adjacent maintained source owner's isolated genuine signing
        # fixture. No operator key or real repository index is accessed.
        spec = importlib.util.spec_from_file_location("transfer_source_fixture", Path(__file__).with_name("test_taira_source_capture.py"))
        cls.fixture_module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.fixture_module)
        cls.fixture_type = cls.fixture_module.SignedSourceCaptureTests
        cls.fixture_type.setUpClass()

    @classmethod
    def tearDownClass(cls):
        cls.fixture_type.tearDownClass()

    def setUp(self):
        self.fixture = self.fixture_type(methodName="runTest")
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)

    def test_actual_signed_source_and_four_binary_receiver_completion_and_reuse(self):
        source = self.fixture_module.source
        exported = self.fixture.export()
        runtime = self.fixture.case / "runtime"
        runtime.mkdir(mode=0o700)
        binary_rows = []
        for index, (name, package) in enumerate(zip(transfer.NAMES, transfer.PACKAGES)):
            path = self.fixture.case / name
            raw = b"ELF fixture payload" + bytes([index]) * 64
            transfer.write_new(path, raw, mode=0o500)
            binary_rows.append({"name": name, "package": package, "path": str(path),
                                "size": len(raw), "sha256": transfer.sha(raw)})
        from release_artifact_contract import canonical_json_bytes
        base = dict.fromkeys(transfer.BASE_FIELDS, "fixture")
        base.update(commit=self.fixture.commit, tree=self.fixture.tree, signer_fingerprint=self.fixture.fingerprint,
                    native_check_scope="build-only")
        build = dict(base, artifacts=binary_rows, timings_seconds={}, attempt="attempts/000001")
        preparation = self.fixture.case / "preparation"
        attempt = preparation / "attempts/000001"
        attempt.mkdir(parents=True, mode=0o700)
        preparation.chmod(0o700)
        attempt.parent.chmod(0o700)
        prepared_request = dict(base, schema="taira.local-preparation.v1", repo_root=str(SCRIPTS.parent), target_dir=str(self.fixture.case))
        for path, record in ((preparation / "result.json", build), (attempt / "capture.json", build),
                             (preparation / "request.json", prepared_request),
                             (preparation / "checks.json", {"request": prepared_request, "passed": True})):
            transfer.write_new(path, canonical_json_bytes(record))
        attempt.chmod(0o500)
        preparation.chmod(0o500)
        plan = {"expected_signer": self.fixture.fingerprint, "preparation": {
                    "path": str(preparation / "result.json"), "sha256": transfer.sha(canonical_json_bytes(build))},
                "runtime_root": str(runtime)}
        request, payloads = transfer.make_request(plan, build, exported)
        raw = b"".join(path.read_bytes() for _, path in payloads)
        checker = types.SimpleNamespace(PLAN_SCHEMA=capacity.PLAN_SCHEMA,
            inspect_filesystem=lambda path: {"fragment_bytes": 4096},
            allocation_bound=capacity.allocation_bound,
            evaluate=lambda plan: {"schema": capacity.RESULT_SCHEMA, "passed": True, "errors": []})
        result = transfer.receive(request, io.BytesIO(raw), source, checker)
        self.assertEqual(result["source"]["signer_fingerprint"], self.fixture.fingerprint)
        self.assertTrue(result["source"]["object_inventory_verified"])
        self.assertFalse(result["source"]["history_included"])
        self.assertEqual(result, transfer.receive(request, io.BytesIO(raw), source, checker))
        imported = Path(result["source"]["source_root"])
        self.assertEqual((imported / "nested/data").read_bytes(), b"signed source\0with bytes\n")
        self.assertFalse((imported / "old-only").exists())
        source.verify_import(imported, imported.parent / "source-capture.json", self.fixture.commit,
                             self.fixture.tree, self.fixture.fingerprint)

    def test_actual_signed_controller_bytes_ignore_cached_module_and_reject_drift(self):
        scripts = self.fixture.repo / "scripts"
        scripts.mkdir(mode=0o755)
        for name in transfer.CONTROLLERS:
            transfer.write_new(scripts / (name + ".py"),
                (SCRIPTS / (name + ".py")).read_bytes(), mode=0o644)
        self.fixture.git("add", "scripts")
        self.fixture.git("commit", "-m", "signed transfer controller closure")
        commit = self.fixture.git("rev-parse", "HEAD").decode().strip()
        poisoned = types.ModuleType("taira_retry")
        poisoned.__file__ = str(scripts / "taira_retry.py")
        poisoned.validate_ssh = lambda value: (_ for _ in ()).throw(AssertionError("cached code executed"))
        with patch.dict(sys.modules, {"taira_retry": poisoned}):
            tree, modules, loaded = transfer.authenticated_modules(self.fixture.repo, commit, self.fixture.fingerprint)
            self.assertEqual(tree, self.fixture.git("rev-parse", "HEAD^{tree}").decode().strip())
            self.assertIsNot(loaded["taira_retry"], poisoned)
            self.assertEqual(set(modules), set(transfer.CONTROLLERS))
            self.assertEqual(loaded["taira_release_transfer"].SCHEMA, transfer.SCHEMA)
        with self.assertRaisesRegex(transfer.TransferError, "actual commit signer"):
            transfer.authenticated_modules(self.fixture.repo, commit, "F" * 40)
        (scripts / "taira_retry.py").write_bytes(b"raise AssertionError('modified controller')\n")
        with self.assertRaisesRegex(transfer.TransferError, "controller differs"):
            transfer.authenticated_modules(self.fixture.repo, commit, self.fixture.fingerprint)


if __name__ == "__main__":
    unittest.main()
