#!/usr/bin/env python3
"""Complete native Taira edge custody as a direct authenticated Rust child.

Requires Darwin, Python 3.11+, the four embedded owner helpers, and inherited
public descriptors retained by the independently guarded native dispatcher.
There are no environment overrides, SSH routes or private configuration reads.
Rust verifies signatures and the ordered cross-host proof before admitting a
child. This helper rechecks its actual parent, held lock, exact public inputs,
irreversible proof fence and native publication before every owned effect.
--inspect-request-fd performs the maintained read-only owner observation only.
"""
from __future__ import annotations

import argparse
import base64
import fcntl
import hashlib
import json
import os
from pathlib import Path
import pwd
import re
import stat
import struct
import subprocess
import sys
import types

ADMISSION_SCHEMA = "iroha.taira.public-reset.native-edge-completion-admission.v1"
RECEIPT_SCHEMA = "iroha.taira.public-reset.native-edge-completion-receipt.v1"
JOURNAL_SCHEMA = "iroha.taira.public-reset.native-edge-completion-journal.v1"
PROGRESS_SCHEMA = "iroha.taira.public-reset.native-edge-progress.v1"
FENCE_SCHEMA = "iroha.taira.public-reset.native-edge-global-proof.v1"
SOURCE_NAMES = ("taira_native_nginx_check.py", "taira_native_nginx_apply.py",
                "taira_native_validator_forwarding.py", "taira_native_edge_completion.py")
IDENTITY_KEYS = {"device", "inode", "uid", "gid", "mode", "links", "size", "mtime_ns", "ctime_ns"}
BINDING_KEYS = {"operation_id", "inventory_sha256", "authorization_sha256", "authorization_nonce",
                "host_pair_sha256", "host_identity_sha256", "custody_root"}
MAX_PUBLIC_BYTES = 1024 * 1024
ADOPTION_PREFIX = "iroha.taira.public-reset.native-owner-adoption-"
ADOPTION_BINDING_KEYS = {"operation_id", "request_sha256", "authorization_sha256", "authorization_nonce",
    "host_pair_sha256", "host_identity_sha256", "custody_root", "helper_source_closure_sha256"}


def need(condition, code):
    """Refuse using a bounded code, never a rendered input or native diagnostic."""
    if not condition:
        raise RuntimeError(code)


def fields(value, expected, code):
    need(isinstance(value, dict) and set(value) == set(expected), code)


def hex_value(value, length, code):
    need(isinstance(value, str) and re.fullmatch(r"[0-9a-f]{" + str(length) + "}", value)
         is not None, code)


def path_value(value):
    need(isinstance(value, str) and re.fullmatch(r"/[A-Za-z0-9_./-]+", value) is not None
         and str(Path(value)) == value and os.path.normpath(value) == value, "noncanonical_path")
    return Path(value)


def identity(info):
    """Preserve exact native integers, including nanosecond values above 2**53."""
    return dict(device=info.st_dev, inode=info.st_ino, uid=info.st_uid, gid=info.st_gid,
                mode=stat.S_IMODE(info.st_mode), links=info.st_nlink, size=info.st_size,
                mtime_ns=info.st_mtime_ns, ctime_ns=info.st_ctime_ns)


def unique_members(entries):
    result = {}
    for name, value in entries:
        need(name not in result, "duplicate_json_member")
        result[name] = value
    return result


def public_json(body, limit=MAX_PUBLIC_BYTES):
    need(0 < len(body) <= limit, "public_json_size_bound")
    return json.loads(body, object_pairs_hook=unique_members)


def descriptor_value(fd):
    need(type(fd) is int and 2 < fd <= 2147483647, "inherited_descriptor_required")
    os.fstat(fd)
    return fd


def open_anchored(target, *, directory=False):
    """Never follow any ancestor symlink or a writable foreign parent."""
    target = path_value(str(target))
    parent = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        for component in target.parts[1:-1]:
            child = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                            dir_fd=parent)
            info = os.fstat(child)
            try:
                need(info.st_uid in {0, os.geteuid()} and not info.st_mode & 0o022,
                     "untrusted_native_parent")
            except BaseException:
                os.close(child)
                raise
            os.close(parent)
            parent = child
        flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK
        if directory:
            flags |= os.O_DIRECTORY
        return os.open(target.name, flags, dir_fd=parent)
    finally:
        os.close(parent)


def validate_observed(reference, *, directory=False):
    fields(reference, {"path", "identity"}, "observed_file_fields")
    path_value(reference["path"])
    observed = reference["identity"]
    fields(observed, IDENTITY_KEYS, "native_identity_fields")
    need(all(type(value) is int and 0 <= value <= 2**64 - 1 for value in observed.values()),
         "native_identity_numbers")
    # Owner-private files may inherit their publisher directory's group. The
    # group remains part of the exact retained identity; mode 0600 grants it no
    # access. Match the maintained nginx publisher's owner-private contract.
    need(observed["uid"] == os.geteuid() and (not directory or observed["gid"] == os.getegid())
         and observed["mode"] == (0o700 if directory else 0o600)
         and (directory or observed["links"] == 1), "unsafe_retained_owner")


def recheck_observed(reference, fd, *, directory=False, executable=False):
    """Join the inherited descriptor to a newly anchored pathname observation."""
    expected = reference["identity"]
    current = open_anchored(reference["path"], directory=directory)
    try:
        info = os.fstat(fd)
        need((stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode))
             and identity(info) == expected == identity(os.fstat(current)), "retained_identity_changed")
        if executable:
            need(info.st_uid == os.geteuid() and info.st_nlink == 1
                 and not info.st_mode & 0o022 and info.st_mode & 0o111,
                 "unsafe_parent_executable")
    finally:
        os.close(current)


def retained_public(value, *, limit=MAX_PUBLIC_BYTES, executable=False):
    fields(value, {"fd", "reference"}, "retained_public_fields")
    descriptor_value(value["fd"])
    reference = value["reference"]
    fields(reference, {"file", "sha256"}, "public_reference_fields")
    if executable:
        fields(reference["file"], {"path", "identity"}, "observed_file_fields")
        path_value(reference["file"]["path"])
        fields(reference["file"]["identity"], IDENTITY_KEYS, "native_identity_fields")
        need(all(type(item) is int and 0 <= item <= 2**64 - 1
                 for item in reference["file"]["identity"].values()), "native_identity_numbers")
    else:
        validate_observed(reference["file"])
    hex_value(reference["sha256"], 64, "public_digest")
    recheck_observed(reference["file"], value["fd"], executable=executable)
    size = reference["file"]["identity"]["size"]
    need(0 < size <= limit, "retained_public_size_bound")
    digest = hashlib.sha256()
    offset = 0
    body = bytearray() if not executable else None
    while offset < size:
        chunk = os.pread(value["fd"], min(65536, size - offset), offset)
        need(bool(chunk), "retained_public_truncated")
        digest.update(chunk)
        if body is not None:
            body.extend(chunk)
        offset += len(chunk)
    need(not os.pread(value["fd"], 1, size) and digest.hexdigest() == reference["sha256"],
         "retained_public_digest_changed")
    recheck_observed(reference["file"], value["fd"], executable=executable)
    return bytes(body) if body is not None else None


def native_custodian_anchor(packet):
    """Resolve the independently provisioned guard from the actual OS account.

    Incoming inventory, environment variables and public packet paths cannot
    select this authority. Only the independently pinned Rust dispatcher may
    hand signature-verified inventory/checkpoint custody to its direct child.
    """
    home = path_value(pwd.getpwuid(os.geteuid()).pw_dir)
    custody = home / ".local/share/iroha/taira/public-reset-v1"
    guard_path = custody / "taira-edge/guard.json"
    dispatcher = custody / "dispatcher/iroha"
    need(packet["custody_root"] == str(custody)
         and packet["guard"]["reference"]["file"]["path"] == str(guard_path)
         and packet["parent"]["executable"]["reference"]["file"]["path"] == str(dispatcher),
         "independent_native_anchor_required")
    opened = open_anchored(guard_path)
    try:
        observed = identity(os.fstat(opened))
        reference = dict(file=dict(path=str(guard_path), identity=observed), sha256="")
        validate_observed(reference["file"])
        need(0 < observed["size"] <= 16 * 1024, "native_guard_size_bound")
        body = os.pread(opened, 16 * 1024+1, 0)
        recheck_observed(reference["file"], opened)
        need(len(body) == observed["size"], "native_guard_changed")
        reference["sha256"] = hashlib.sha256(body).hexdigest()
        guard = public_json(body, 16 * 1024)
        fields(guard, {"schema", "host_slug", "service_root", "state_root", "trusted_key_sha256",
                       "dispatcher_path", "dispatcher_sha256", "upload_parent"}, "host_guard_fields")
        need(guard["schema"] == "iroha.taira.public-reset.host-guard.v1"
             and guard["dispatcher_path"] == str(dispatcher), "independent_native_guard_binding")
        hex_value(guard["dispatcher_sha256"], 64, "native_dispatcher_digest")
        hex_value(guard["trusted_key_sha256"], 64, "native_trusted_key_digest")
        need(packet["guard"]["reference"] == reference, "independent_native_guard_changed")
        retained_public(packet["guard"], limit=16 * 1024)
        return dict(custody_root=str(custody), dispatcher_path=str(dispatcher),
                    guard=guard, retained=dict(fd=opened, reference=reference))
    except BaseException:
        os.close(opened)
        raise


def kernel_executable_path(pid):
    """Observe the actual Darwin executable, rather than any mapped text file."""
    import ctypes
    need(sys.platform == "darwin", "native_darwin_parent_required")
    library = ctypes.CDLL("/usr/lib/libproc.dylib", use_errno=True)
    function = library.proc_pidpath
    function.argtypes = [ctypes.c_int, ctypes.c_void_p, ctypes.c_uint32]
    function.restype = ctypes.c_int
    buffer = ctypes.create_string_buffer(4096)
    result = function(pid, buffer, len(buffer))
    need(0 < result < len(buffer), "native_parent_executable_unavailable")
    return os.fsdecode(buffer.value)


def source_closure():
    """Read only public embedded helpers; compile imports from these exact bytes."""
    source_root = Path(__file__).resolve().parent
    digest = hashlib.sha256(b"iroha:taira:public-reset:native-helper-source:v1\0")
    sources = {}
    for name in SOURCE_NAMES:
        fd = open_anchored(source_root / name)
        try:
            before = identity(os.fstat(fd))
            need(stat.S_ISREG(os.fstat(fd).st_mode) and before["uid"] in {0, os.geteuid()}
                 and before["links"] == 1 and not before["mode"] & 0o022
                 and 0 < before["size"] <= MAX_PUBLIC_BYTES, "unsafe_helper_source")
            source = os.pread(fd, MAX_PUBLIC_BYTES + 1, 0)
            need(len(source) == before["size"], "helper_source_changed")
            recheck_observed(dict(path=str(source_root / name), identity=before), fd)
            digest.update(name.encode() + b"\0" + struct.pack(">Q", len(source)) + source)
            sources[name] = source
        finally:
            os.close(fd)
    return digest.hexdigest(), sources


def owner_modules(sources):
    """Load the exact maintained owner bytes without an import-search fallback."""
    check = types.ModuleType("taira_native_nginx_check")
    check.__file__ = str(Path(__file__).parent / SOURCE_NAMES[0])
    exec(compile(sources[SOURCE_NAMES[0]], check.__file__, "exec"), check.__dict__)
    previous = sys.modules.get(check.__name__)
    sys.modules[check.__name__] = check
    try:
        apply = types.ModuleType("taira_native_nginx_apply")
        apply.__file__ = str(Path(__file__).parent / SOURCE_NAMES[1])
        exec(compile(sources[SOURCE_NAMES[1]], apply.__file__, "exec"), apply.__dict__)
    finally:
        if previous is None:
            del sys.modules[check.__name__]
        else:
            sys.modules[check.__name__] = previous
    return apply


def inspect_owned_publication(request):
    """Return only the maintained owner's closed read-only numeric observation."""
    _, sources = source_closure()
    return owner_modules(sources).inspect_owned_publication(request)


def verify_native_custody(custody):
    """Recheck independently fixed OS custody shared by closed native actions."""
    self = custody
    packet = self.packet
    recheck_observed(self.anchor["retained"]["reference"]["file"], self.anchor["retained"]["fd"])
    need(packet["guard"]["reference"] == self.anchor["retained"]["reference"],
         "independent_native_guard_changed")
    recheck_observed(packet["guard"]["reference"]["file"], packet["guard"]["fd"])
    current = open_anchored(self.path, directory=True)
    try:
        need(identity(os.fstat(current)) == self.directory_identity == identity(os.fstat(self.directory)),
             "operation_directory_changed")
    finally:
        os.close(current)
    fields(packet["parent"], {"pid", "uid", "started", "executable"}, "native_parent_fields")
    parent = packet["parent"]
    need(type(parent["pid"]) is int and parent["pid"] == os.getppid() and parent["pid"] > 1
         and type(parent["uid"]) is int and parent["uid"] == os.geteuid()
         and isinstance(parent["started"], str)
         and re.fullmatch(r"[A-Za-z0-9: ]{20,32}", parent["started"]) is not None,
         "native_parent_changed")
    need(parent["executable"]["reference"]["file"]["path"] == self.anchor["dispatcher_path"]
         and parent["executable"]["reference"]["sha256"] == self.anchor["guard"]["dispatcher_sha256"]
         and kernel_executable_path(parent["pid"]) == self.anchor["dispatcher_path"],
         "independent_native_parent_required")
    if not self.parent_digest_verified:
        retained_public(parent["executable"], limit=512 * 1024 * 1024, executable=True)
        self.parent_digest_verified = True
    else:
        recheck_observed(parent["executable"]["reference"]["file"], parent["executable"]["fd"], executable=True)
    closure, sources = source_closure()
    need(closure == packet["helper_source_closure_sha256"], "helper_closure_changed")
    self.sources = sources
    owner = owner_modules(sources)
    expected = dict(pid=parent["pid"], uid=parent["uid"], started=parent["started"],
                    executable=parent["executable"]["reference"]["file"]["path"])
    need(owner.observe_master(expected) == expected, "native_parent_changed")
    for name, expected_path in (
            ("lock", self.path / "operation.lock"),
            ("host_lock", Path(self.anchor["custody_root"]) / "taira-edge/host-operation.lock")):
        lock = packet[name]
        fields(lock, {"fd", "file"}, "native_lock_fields")
        descriptor_value(lock["fd"])
        validate_observed(lock["file"])
        need(lock["file"]["path"] == str(expected_path), "native_lock_path")
        need(lock["file"]["identity"]["size"] == 0, "native_lock_size")
        recheck_observed(lock["file"], lock["fd"])
        competing = open_anchored(lock["file"]["path"])
        try:
            try:
                fcntl.flock(competing, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                pass
            else:
                fcntl.flock(competing, fcntl.LOCK_UN)
                raise RuntimeError("native_lock_not_held")
        finally:
            os.close(competing)
    return owner, parent, expected


class Admission:
    """Retain public child custody and revalidate it before each owned effect."""

    def __init__(self, packet):
        fields(packet, BINDING_KEYS | {"schema", "action", "helper_source_closure_sha256", "parent", "lock", "host_lock",
            "guard", "inventory", "authorization", "progress", "checkpoints", "fence", "plan"},
            "completion_admission_fields")
        need(packet["schema"] == ADMISSION_SCHEMA and packet["action"] in {"rollback", "seal", "cleanup"}
             and sys.platform == "darwin", "native_completion_admission")
        for key in ("operation_id", "authorization_nonce"):
            hex_value(packet[key], 32, "completion_operation_identity")
        for key in BINDING_KEYS - {"operation_id", "authorization_nonce", "custody_root"}:
            hex_value(packet[key], 64, "completion_binding_digest")
        hex_value(packet["helper_source_closure_sha256"], 64, "helper_closure_digest")
        self.packet = packet
        self.bindings = {key: packet[key] for key in BINDING_KEYS}
        # Resolve independent authority before any caller-selected operation,
        # inventory, executable or guard file is opened.
        self.anchor = native_custodian_anchor(packet)
        self.directory = None
        self.predecessor = None
        self.parent_digest_verified = False
        self.path = path_value(packet["custody_root"]) / "taira-edge/operations" / packet["authorization_sha256"]
        self.plan = None
        self.progress = None
        self.fence_body = None
        self.sources = None
        try:
            self.directory = open_anchored(self.path, directory=True)
            self.directory_identity = identity(os.fstat(self.directory))
            self.directory_owned_change = False
            need(self.directory_identity["uid"] == os.geteuid()
                 and self.directory_identity["gid"] == os.getegid()
                 and self.directory_identity["mode"] == 0o700, "unsafe_operation_directory")
            self.verify()
        except BaseException:
            self.close()
            raise

    def close(self):
        if self.predecessor is not None:
            os.close(self.predecessor["fd"])
        if self.directory is not None:
            os.close(self.directory)
        os.close(self.anchor["retained"]["fd"])

    def verify(self):
        packet = self.packet
        owner, parent, expected = verify_native_custody(self)
        for key, name in (("inventory", "inventory.json"), ("authorization", "authorization.json"),
                          ("progress", "progress.json"), ("plan", "completion-plan.json")):
            need(packet[key]["reference"]["file"]["path"] == str(self.path / name), "operation_public_path")
        inventory = public_json(retained_public(packet["inventory"]))
        authorization = public_json(retained_public(packet["authorization"]))
        guard = self.anchor["guard"]
        fields(guard, {"schema", "host_slug", "service_root", "state_root", "trusted_key_sha256",
                       "dispatcher_path", "dispatcher_sha256", "upload_parent"}, "host_guard_fields")
        native = inventory["hosts"]["native_edge"]
        need(inventory["hosts"]["provider"] == "macstadium-dublin"
             and inventory["authorization_nonce"] == packet["authorization_nonce"]
             and packet["inventory"]["reference"]["sha256"] == packet["inventory_sha256"]
             and native["owner_uid"] == os.geteuid() and native["owner_gid"] == os.getegid()
             and native["custody_root"] == packet["custody_root"]
             and native["endpoint"]["host_identity_sha256"] == packet["host_identity_sha256"]
             and packet["guard"]["reference"]["sha256"] == native["guard_sha256"]
             and guard["schema"] == "iroha.taira.public-reset.host-guard.v1"
             and guard["dispatcher_path"] == native["dispatcher_path"] == expected["executable"]
             and guard["dispatcher_sha256"] == native["dispatcher_sha256"]
             == parent["executable"]["reference"]["sha256"], "native_guard_binding")
        claims = authorization["claims"]
        need(claims["inventory_sha256"] == packet["inventory_sha256"]
             and claims["authorization_nonce"] == packet["authorization_nonce"]
             and claims["deployment_id"] == inventory["deployment_id"], "authorization_binding")
        # The envelope's raw file hash intentionally differs from the semantic
        # authorization digest verified by the guarded Rust parent.
        self.progress = public_json(retained_public(packet["progress"], limit=16 * 1024))
        fields(self.progress, BINDING_KEYS | {"schema", "sequence", "predecessor_sha256", "request_sha256",
            "publication_operation_id", "status", "checkpoint_sha256", "completion_receipt_sha256"},
            "native_progress_fields")
        need(self.progress["schema"] == PROGRESS_SCHEMA
             and all(self.progress[key] == value for key, value in self.bindings.items())
             and type(self.progress["sequence"]) is int and 0 < self.progress["sequence"] <= 2**64 - 1,
             "native_progress_binding")
        need((self.progress["sequence"] == 1) == (self.progress["predecessor_sha256"] is None),
             "native_progress_sequence")
        for key in ("predecessor_sha256", "checkpoint_sha256", "completion_receipt_sha256"):
            if self.progress[key] is not None:
                hex_value(self.progress[key], 64, "native_progress_digest")
        hex_value(self.progress["request_sha256"], 64, "native_progress_request")
        hex_value(self.progress["publication_operation_id"], 32, "native_progress_publication")
        allowed_status = {"rollback": {"admitted", "staged", "cutover_requested", "awaiting_readiness",
            "edge_ready_unqualified", "rollback_requested", "rolled_back", "recovery_pending"},
            "seal": {"edge_ready_unqualified", "sealing", "sealed", "recovery_pending"},
            "cleanup": {"sealed", "cleanup_requested", "cleaned", "recovery_pending"}}
        need(self.progress["status"] in allowed_status[packet["action"]], "completion_progress_phase")
        self.plan = public_json(retained_public(packet["plan"]))
        fields(self.plan, {"schema", "nginx", "completion_journal_basename", "publication_effect"}, "completion_plan_fields")
        need(self.plan["schema"] == "iroha.taira.public-reset.native-nginx-completion-plan.v1"
             and self.plan["completion_journal_basename"] == "native-completion.ndjson",
             "completion_plan_schema")
        owner.validate_plan(self.plan["nginx"])
        plan = self.plan["nginx"]
        need(plan["host_kind"] == "macos", "completion_publication_binding")
        effect = self.plan["publication_effect"]
        fields(effect, {"kind", "value"}, "publication_effect_fields")
        if effect["kind"] == "publisher_rolled_back":
            need(packet["action"] == "rollback" and self.progress["status"] in {
                "rollback_requested", "rolled_back", "recovery_pending"}
                and plan["publication"]["kind"] in {"create", "replace"}
                and plan["operation_id"] == self.progress["publication_operation_id"],
                "publisher_rollback_effect")
            fields(effect["value"], {"journal", "restored_owned_publication"}, "publisher_rollback_fields")
            reference = numeric_owner_journal(effect["value"]["journal"])
            need(owner.validate_public_journal_reference(reference, plan["native"]) == plan["operation_id"],
                 "publisher_rollback_operation")
            restored = effect["value"]["restored_owned_publication"]
            need((restored is None) == (plan["publication"]["kind"] == "create"),
                 "publisher_rollback_predecessor")
            if restored is not None:
                need(restored["publication"]["file"]["path"] == str(
                    Path(plan["destination"]["directory"]["path"]) / plan["destination"]["basename"]),
                    "publisher_rollback_destination")
                restored = numeric_owner_publication(restored)
                owner.validate_public_prior_reference(restored, plan["native"])
                prior = plan["publication"]["prior"]
                need(restored["operation_id"] == prior["operation_id"]
                     and restored["publication"]["sha256"] == prior["publication"]["sha256"]
                     and all(restored["publication"]["identity"][key] == prior["publication"]["identity"][key]
                             for key in IDENTITY_KEYS - {"ctime_ns"}), "publisher_rollback_predecessor")
        else:
            need(plan["publication"]["kind"] == "reconcile"
                 and plan["operation_id"] == plan["publication"]["prior"]["operation_id"],
                 "completion_publication_binding")
        if effect["kind"] == "owned":
            need(effect["value"] is None and plan["operation_id"] == self.progress["publication_operation_id"],
                 "owned_publication_effect")
        elif effect["kind"] == "not_requested":
            need(effect["kind"] == "not_requested" and packet["action"] == "rollback"
                 and self.progress["status"] in {"admitted", "staged", "rollback_requested", "rolled_back", "recovery_pending"},
                 "publication_effect_not_requested")
            fields(effect["value"], {"intended_operation_id", "incumbent"}, "not_requested_effect_fields")
            hex_value(effect["value"]["intended_operation_id"], 32, "intended_publication_identity")
            incumbent = effect["value"]["incumbent"]
            fields(incumbent, {"operation_id", "journal", "publication"}, "incumbent_owner_fields")
            for name in ("journal", "publication"):
                fields(incumbent[name], {"file", "sha256"}, "incumbent_public_fields")
                validate_observed(incumbent[name]["file"])
                hex_value(incumbent[name]["sha256"], 64, "incumbent_public_digest")
            need(effect["value"]["intended_operation_id"] == self.progress["publication_operation_id"]
                 and effect["value"]["intended_operation_id"] != plan["operation_id"]
                 and incumbent == numeric_owned_publication(plan), "incumbent_owner_binding")
        else:
            need(effect["kind"] == "publisher_rolled_back", "publication_effect_kind")
        checkpoints = packet["checkpoints"]
        need(isinstance(checkpoints, list) and len(checkpoints) <= 3, "checkpoint_count")
        hashes = []
        for index, reference in enumerate(checkpoints):
            need(reference["reference"]["file"]["path"] == str(self.path / f"checkpoint-{index+1}.json"),
                 "checkpoint_path")
            checkpoint = public_json(retained_public(reference, limit=16 * 1024))
            fields(checkpoint, {"claims", "signature_hex"}, "signed_checkpoint_fields")
            claim = checkpoint["claims"]
            phase = {"kind": ("candidate_frontier", "native_edge_ready", "deployment_proven")[index],
                     "value": None}
            fields(claim, {"schema", "phase", "deployment_id", "inventory_sha256", "authorization_sha256",
                "authorization_nonce", "host_pair_sha256", "guest_host_identity_sha256",
                "native_edge_host_identity_sha256", "guest_custody_root", "native_edge_custody_root",
                "source_commit", "next_genesis_hash", "evidence_sha256", "predecessor_sha256",
                "execution_expires_at_unix_ms"}, "checkpoint_claims_fields")
            hex_value(checkpoint["signature_hex"], 128, "checkpoint_signature")
            hex_value(claim["evidence_sha256"], 64, "checkpoint_evidence")
            need(claim["schema"] == "iroha.taira.public-reset.host-phase-checkpoint.v1"
                 and claim["phase"] == phase
                 and claim["deployment_id"] == inventory["deployment_id"]
                 and claim["source_commit"] == inventory["revision"]["commit"]
                 and claim["next_genesis_hash"] == inventory["next_genesis_hash"]
                 and claim["guest_host_identity_sha256"] == inventory["hosts"]["validator_guest"]["endpoint"]["host_identity_sha256"]
                 and claim["guest_custody_root"] == inventory["hosts"]["validator_guest"]["custody_root"]
                 and claim["execution_expires_at_unix_ms"] == claims["execution_expires_at_unix_ms"]
                 and claim["inventory_sha256"] == packet["inventory_sha256"]
                 and claim["authorization_sha256"] == packet["authorization_sha256"]
                 and claim["authorization_nonce"] == packet["authorization_nonce"]
                 and claim["host_pair_sha256"] == packet["host_pair_sha256"]
                 and claim["native_edge_host_identity_sha256"] == packet["host_identity_sha256"]
                 and claim["native_edge_custody_root"] == packet["custody_root"]
                 and claim["predecessor_sha256"] == (hashes[-1] if hashes else None),
                 "checkpoint_binding")
            hashes.append(reference["reference"]["sha256"])
        fields(packet["fence"], {"kind", "value"}, "proof_fence_fields")
        fence = packet["fence"]
        if packet["action"] == "rollback":
            need(fence["kind"] == "absent" and len(hashes) < 3, "rollback_after_global_proof")
            fields(fence["value"], {"directory_fd", "directory", "basename"}, "absent_fence_fields")
            absent = fence["value"]
            descriptor_value(absent["directory_fd"])
            need(absent["directory"]["path"] == str(self.path) and absent["basename"] == "global-proof.json",
                 "absent_fence_path")
            validate_observed(absent["directory"], directory=True)
            # Only this helper's own controlled directory effects may refresh
            # the volatile directory metadata, never its inode/owner/mode.
            stable = {"device", "inode", "uid", "gid", "mode", "links"}
            need(all(absent["directory"]["identity"][key] == self.directory_identity[key] for key in stable)
                 and (self.directory_owned_change
                      or absent["directory"]["identity"] == self.directory_identity)
                 and identity(os.fstat(absent["directory_fd"])) == self.directory_identity,
                 "absent_fence_directory_changed")
            try:
                os.stat(absent["basename"], dir_fd=absent["directory_fd"], follow_symlinks=False)
            except FileNotFoundError:
                pass
            else:
                raise RuntimeError("rollback_after_global_proof")
            self.fence_body = None
        else:
            need(fence["kind"] == "present" and len(hashes) == 3, "global_proof_required")
            fields(fence["value"], {"reference"}, "present_fence_fields")
            retained = fence["value"]["reference"]
            need(retained["reference"]["file"]["path"] == str(self.path / "global-proof.json"),
                 "global_proof_path")
            self.fence_body = public_json(retained_public(retained, limit=16 * 1024))
            fields(self.fence_body, BINDING_KEYS | {"schema", "checkpoint_sha256", "final_checkpoint_sha256",
                "progress_predecessor_sha256", "publication_operation_id"}, "global_proof_fields")
            need(self.fence_body["schema"] == FENCE_SCHEMA
                 and all(self.fence_body[key] == value for key, value in self.bindings.items())
                 and self.fence_body["checkpoint_sha256"] == hashes
                 and self.fence_body["final_checkpoint_sha256"] == hashes[-1]
                 and self.fence_body["publication_operation_id"] == plan["operation_id"], "global_proof_binding")
            if self.progress["status"] == "edge_ready_unqualified":
                need(self.fence_body["progress_predecessor_sha256"] == packet["progress"]["reference"]["sha256"],
                     "global_proof_progress_binding")
            hex_value(self.fence_body["progress_predecessor_sha256"], 64, "global_proof_progress_digest")
            if self.predecessor is None:
                opened = open_anchored(self.path / "global-proof-predecessor.json")
                self.predecessor = dict(fd=opened, reference=dict(file=dict(
                    path=str(self.path / "global-proof-predecessor.json"), identity=identity(os.fstat(opened))),
                    sha256=self.fence_body["progress_predecessor_sha256"]))
            predecessor = public_json(retained_public(self.predecessor, limit=16 * 1024))
            fields(predecessor, set(self.progress), "proof_predecessor_fields")
            need(predecessor["schema"] == PROGRESS_SCHEMA
                 and all(predecessor[key] == value for key, value in self.bindings.items())
                 and predecessor["status"] == "edge_ready_unqualified"
                 and predecessor["publication_operation_id"] == plan["operation_id"]
                 and predecessor["checkpoint_sha256"] == hashes[1], "proof_predecessor_binding")
        return owner

    def refresh_directory(self):
        self.directory_identity = identity(os.fstat(self.directory))
        self.directory_owned_change = True


class AdoptionAdmission:
    """Admit a separately signed exact ownership transition, never old phases."""

    def __init__(self, packet):
        fields(packet, ADOPTION_BINDING_KEYS | {"schema", "parent", "host_lock", "lock", "guard", "request",
            "authorization", "trusted_key", "progress", "plan", "source_plan", "lease", "publication", "opaque_journals"},
            "adoption_admission_fields")
        need(packet["schema"] == ADOPTION_PREFIX + "admission.v1" and sys.platform == "darwin",
             "native_adoption_admission")
        for key in ("operation_id", "authorization_nonce"):
            hex_value(packet[key], 32, "adoption_operation_identity")
        for key in ADOPTION_BINDING_KEYS - {"operation_id", "authorization_nonce", "custody_root"}:
            hex_value(packet[key], 64, "adoption_binding_digest")
        self.packet = packet
        self.bindings = {key: packet[key] for key in ADOPTION_BINDING_KEYS}
        self.anchor = native_custodian_anchor(packet)
        self.directory = None
        self.parent_digest_verified = False
        self.path = path_value(packet["custody_root"]) / "taira-edge/operations" / packet["authorization_sha256"]
        self.incident_refs = None
        try:
            self.directory = open_anchored(self.path, directory=True)
            self.directory_identity = identity(os.fstat(self.directory))
            validate_observed(dict(path=str(self.path), identity=self.directory_identity), directory=True)
            self.verify()
        except BaseException:
            self.close()
            raise

    def close(self):
        if self.directory is not None:
            os.close(self.directory)
        os.close(self.anchor["retained"]["fd"])

    def refresh_directory(self):
        self.directory_identity = identity(os.fstat(self.directory))

    def verify(self):
        packet = self.packet
        owner, parent, expected = verify_native_custody(self)
        for key, name in (("request", "request.json"), ("authorization", "authorization.json"),
                ("trusted_key", "trusted-key.json"), ("progress", "progress.json"), ("plan", "adoption-plan.json")):
            need(packet[key]["reference"]["file"]["path"] == str(self.path / name), "adoption_public_path")
        need(packet["lease"]["reference"]["file"]["path"] == str(
            Path(self.anchor["custody_root"]) / "taira-edge/active-adoption.json"), "adoption_lease_path")
        request = public_json(retained_public(packet["request"], limit=128 * 1024))
        fields(request, {"schema", "hosts", "operation_id", "authorization_nonce", "helper_source_closure_sha256",
                        "adoption_plan", "not_before_unix_ms", "expires_at_unix_ms"}, "adoption_request_fields")
        need(request["schema"] == ADOPTION_PREFIX + "request.v1"
             and packet["request"]["reference"]["sha256"] == packet["request_sha256"]
             and all(request[key] == packet[key] for key in
                     ("operation_id", "authorization_nonce", "helper_source_closure_sha256")),
             "adoption_request_binding")
        fields(request["hosts"], {"schema", "provider", "validator_guest", "native_edge"}, "adoption_host_pair_fields")
        native, guard = request["hosts"]["native_edge"], self.anchor["guard"]
        need(request["hosts"]["provider"] == "macstadium-dublin"
             and native["owner_uid"] == os.geteuid() and native["owner_gid"] == os.getegid()
             and native["custody_root"] == packet["custody_root"]
             and native["endpoint"]["host_identity_sha256"] == packet["host_identity_sha256"]
             and native["guard_sha256"] == packet["guard"]["reference"]["sha256"]
             and native["dispatcher_path"] == expected["executable"]
             and native["dispatcher_sha256"] == parent["executable"]["reference"]["sha256"],
             "adoption_native_guard_binding")
        trusted = public_json(retained_public(packet["trusted_key"], limit=16 * 1024))
        fields(trusted, {"schema", "algorithm", "public_key"}, "adoption_trusted_key_fields")
        need(trusted["schema"] == "iroha.taira.public-reset.trusted-key.v1" and trusted["algorithm"] == "ed25519"
             and packet["trusted_key"]["reference"]["sha256"] == guard["trusted_key_sha256"],
             "adoption_trusted_key_binding")
        authorization = public_json(retained_public(packet["authorization"], limit=16 * 1024))
        fields(authorization, {"schema", "claims", "signature_hex"}, "adoption_authorization_fields")
        claims = authorization["claims"]
        fields(claims, {"schema", "request_sha256", "operation_id", "authorization_nonce", "host_pair_sha256",
            "helper_source_closure_sha256", "not_before_unix_ms", "expires_at_unix_ms"}, "adoption_claims_fields")
        hex_value(authorization["signature_hex"], 128, "adoption_signature")
        need(authorization["schema"] == ADOPTION_PREFIX + "authorization.v1"
             and claims["schema"] == ADOPTION_PREFIX + "claims.v1"
             and packet["authorization"]["reference"]["sha256"] == packet["authorization_sha256"]
             and all(claims[key] == packet[key] for key in ("request_sha256", "operation_id", "authorization_nonce",
                     "host_pair_sha256", "helper_source_closure_sha256"))
             and all(type(request[key]) is int and 0 <= request[key] <= 2**64-1
                     and claims[key] == request[key] for key in ("not_before_unix_ms", "expires_at_unix_ms"))
             and request["expires_at_unix_ms"] > request["not_before_unix_ms"], "adoption_authorization_binding")
        # The actual guarded Rust parent verifies the exact domain-separated
        # signature. Python cannot reinterpret expiry or supply another signer.
        self.progress = public_json(retained_public(packet["progress"], limit=16 * 1024))
        fields(self.progress, ADOPTION_BINDING_KEYS | {"schema", "status", "receipt_sha256"}, "adoption_progress_fields")
        need(self.progress["schema"] == ADOPTION_PREFIX + "progress.v1"
             and all(self.progress[key] == value for key, value in self.bindings.items())
             and self.progress["status"] in {"adoption_requested", "recovery_pending", "adopted_unqualified"},
             "adoption_progress_binding")
        if self.progress["receipt_sha256"] is not None:
            hex_value(self.progress["receipt_sha256"], 64, "adoption_progress_receipt")
        lease = public_json(retained_public(packet["lease"], limit=16 * 1024))
        lease_keys = {"operation_id", "request_sha256", "authorization_sha256", "authorization_nonce", "host_pair_sha256"}
        fields(lease, lease_keys | {"schema"}, "adoption_lease_fields")
        need(lease["schema"] == ADOPTION_PREFIX + "lease.v1"
             and all(lease[key] == packet[key] for key in lease_keys), "adoption_lease_binding")
        try:
            os.stat(Path(self.anchor["custody_root"]) / "taira-edge/active-lease.json", follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            raise RuntimeError("adoption_reset_lease_present")
        self.plan = public_json(retained_public(packet["plan"]))
        fields(self.plan, {"schema", "nginx", "publication", "opaque_journals"}, "adoption_plan_fields")
        source_plan = retained_public(packet["source_plan"])
        need(self.plan["schema"] == ADOPTION_PREFIX + "plan.v1"
             and request["adoption_plan"] == packet["source_plan"]["reference"]
             and source_plan == retained_public(packet["plan"])
             and self.plan["publication"] == packet["publication"]["reference"], "adoption_plan_binding")
        owner.validate_plan(self.plan["nginx"])
        plan = self.plan["nginx"]
        need(plan["operation_id"] == packet["operation_id"] and plan["host_kind"] == "macos"
             and plan["publication"] == {"kind": "create"}
             and plan["candidate"]["sha256"] == self.plan["publication"]["sha256"]
             and self.plan["publication"]["file"]["path"] == str(
                 Path(plan["destination"]["directory"]["path"]) / plan["destination"]["basename"]),
             "adoption_publication_binding")
        retained_public(packet["publication"])
        originals, retained = self.plan["opaque_journals"], packet["opaque_journals"]
        need(isinstance(originals, list) and isinstance(retained, list) and 0 < len(originals) == len(retained) <= 32,
             "adoption_incident_bound")
        paths = set()
        for ordinal, (original, pin) in enumerate(zip(originals, retained)):
            observed = original["file"]
            validate_observed(observed)
            hex_value(original["sha256"], 64, "adoption_incident_digest")
            name = Path(observed["path"]).name
            match = re.fullmatch(r"\.taira-native-nginx-apply-([0-9a-f]{32})\.receipt\.ndjson", name)
            need(match is not None and match[1] != packet["operation_id"]
                 and observed["path"] == str(Path(plan["native"]["directory"]["path"]) / name)
                 and observed["path"] not in paths, "adoption_incident_path")
            paths.add(observed["path"])
            actual = pin["reference"]
            validate_observed(actual["file"])
            need(actual["sha256"] == original["sha256"]
                 and actual["file"]["path"] in {observed["path"], adoption_archive_path(self, ordinal)}
                 and all(actual["file"]["identity"][key] == observed["identity"][key]
                         for key in IDENTITY_KEYS - {"ctime_ns"}), "adoption_incident_lineage")
        if self.incident_refs is not None:
            for pin in self.incident_refs:
                retained_public(pin)
        return owner


def adoption_archive_path(admission, ordinal):
    return str(Path(admission.plan["nginx"]["native"]["directory"]["path"]) /
        (".taira-native-nginx-adoption-" + admission.packet["operation_id"] + "-opaque-" + str(ordinal) + ".ndjson"))


class CompletionJournal:
    """One finite append-only effect chain, retained under the inherited lock."""

    def __init__(self, admission, *, name="native-completion.ndjson"):
        need(name in {"native-completion.ndjson", "native-adoption.ndjson"}, "native_effect_journal_name")
        self.admission = admission
        self.name = name
        flags = os.O_RDWR | os.O_APPEND | os.O_NOFOLLOW | os.O_CLOEXEC
        self.fd = None
        try:
            try:
                self.fd = os.open(self.name, flags | os.O_CREAT | os.O_EXCL, 0o600, dir_fd=admission.directory)
                os.fsync(admission.directory)
                admission.refresh_directory()
            except FileExistsError:
                self.fd = os.open(self.name, flags, dir_fd=admission.directory)
        except BaseException:
            if self.fd is not None:
                os.close(self.fd)
            raise
        self.observed = identity(os.fstat(self.fd))
        self.records = []
        try:
            self.load()
        except BaseException:
            self.close()
            raise

    def load(self):
        admission = self.admission
        owner = admission.verify()
        self.check()
        body = os.pread(self.fd, MAX_PUBLIC_BYTES + 1, 0)
        need(len(body) <= MAX_PUBLIC_BYTES and (not body or body.endswith(b"\n")), "completion_journal_bound")
        for ordinal, line in enumerate(body.splitlines(), 1):
            record = public_json(line, 65536)
            fields(record, BINDING_KEYS | {"schema", "sequence", "plan_sha256", "phase", "action",
                "publication_operation_id", "publication_identity", "backup_identity", "publisher_journal",
                "progress_before_sha256", "global_proof_sha256", "error_code", "publisher_terminal_record",
                "restored_owner", "publisher_write_intent"}, "completion_journal_fields")
            need(record["schema"] == JOURNAL_SCHEMA and type(record["sequence"]) is int
                 and record["sequence"] == ordinal
                 and all(record[key] == value for key, value in admission.bindings.items())
                 and record["plan_sha256"] == admission.packet["plan"]["reference"]["sha256"]
                 and record["publication_operation_id"] == intended_publication_operation(admission.plan)
                 and record["phase"] in {"admitted", "rollback_requested", "source_restored",
                     "reload_requested", "publisher_terminal_requested", "publisher_terminal", "rolled_back",
                     "seal_requested", "sealed", "cleanup_requested", "cleaned", "recovery_pending"}
                 and record["action"] in {"rollback", "seal", "cleanup"}, "completion_journal_binding")
            witness = record["publisher_write_intent"]
            if witness is not None:
                fields(witness, {"intent", "stage", "record"}, "publisher_write_intent_fields")
                reference = witness["intent"]
                fields(reference, {"path", "identity", "sha256"}, "publisher_write_intent_reference")
                native = admission.plan["nginx"]["native"]
                owner.validate_public_owner_identity(reference["identity"], native)
                owner.validate_public_owner_identity(witness["stage"], native)
                hex_value(reference["sha256"], 64, "publisher_write_intent_digest")
                projection = witness["record"]
                need(isinstance(projection, dict)
                     and "journal_publication_identity" not in projection
                     and "journal_write_intent" not in projection
                     and type(projection.get("sequence")) is int
                     and 0 < projection["sequence"] <= 128, "publisher_write_intent_record")
                hex_value(projection.get("operation_id"), 32, "publisher_write_intent_operation")
                name = Path(reference["path"]).name
                need(re.fullmatch(r"\.taira-native-nginx-write-" + projection["operation_id"]
                     + "-" + str(projection["sequence"]) + r"-[0-9a-f]{32}\.intent\.json", name)
                     is not None and reference["path"] == str(Path(native["directory"]["path"]) / name)
                     and record["phase"] == "publisher_terminal_requested", "publisher_write_intent_path")
            self.records.append(record)
        need(len(self.records) <= 128, "completion_journal_record_bound")
        self.check()

    def close(self):
        os.close(self.fd)

    def check(self):
        info = os.fstat(self.fd)
        need(stat.S_ISREG(info.st_mode) and identity(info) == self.observed
             == identity(os.stat(self.name, dir_fd=self.admission.directory, follow_symlinks=False))
             and info.st_uid == os.geteuid() and info.st_gid == os.getegid() and info.st_nlink == 1
             and stat.S_IMODE(info.st_mode) == 0o600, "completion_journal_changed")

    def append(self, phase, *, publication_identity, backup_identity, publisher_journal, error_code=None,
               publisher_terminal_record=None, restored_owner=None, publisher_write_intent=None):
        import uuid
        owner = self.admission.verify()
        self.check()
        packet = self.admission.packet
        fence_sha = (packet["fence"]["value"]["reference"]["reference"]["sha256"]
                     if packet["fence"]["kind"] == "present" else None)
        record = dict(self.admission.bindings, schema=JOURNAL_SCHEMA, sequence=len(self.records)+1,
            plan_sha256=packet["plan"]["reference"]["sha256"], phase=phase, action=packet["action"],
            publication_operation_id=intended_publication_operation(self.admission.plan),
            publication_identity=publication_identity, backup_identity=backup_identity,
            publisher_journal=publisher_journal,
            progress_before_sha256=packet["progress"]["reference"]["sha256"],
            global_proof_sha256=fence_sha, error_code=error_code,
            publisher_terminal_record=publisher_terminal_record,
            restored_owner=restored_owner, publisher_write_intent=publisher_write_intent)
        self.append_record(record)

    def append_record(self, record):
        """Publish one complete private authority chain under exact native custody."""
        import uuid
        owner = self.admission.verify()
        self.check()
        body = (json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n").encode()
        need(len(self.records) < 128 and len(body) <= 65536
             and os.fstat(self.fd).st_size + len(body) <= MAX_PUBLIC_BYTES, "completion_journal_bound")
        prefix = os.pread(self.fd, MAX_PUBLIC_BYTES + 1, 0)
        self.check()
        need(len(prefix) == self.observed["size"] and (not prefix or prefix.endswith(b"\n")),
             "completion_journal_changed")
        complete = prefix + body
        stage_name = ".native-completion-" + uuid.uuid4().hex + ".journal"
        stage_fd = os.open(stage_name, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                           0o600, dir_fd=self.admission.directory)
        stage_created = identity(os.fstat(stage_fd))
        old_fd, old_observed = self.fd, self.observed
        stage_observed = None
        installed = False
        self.admission.refresh_directory()

        def paired(observed, expected):
            # Only our atomic rename may refresh ctime; bytes, ownership and
            # the two original inodes must retain their admitted lineage.
            return all(observed[key] == expected[key] for key in IDENTITY_KEYS - {"ctime_ns"})

        def staged(expected, content):
            before = identity(os.fstat(stage_fd))
            need(stat.S_ISREG(os.fstat(stage_fd).st_mode) and before == expected
                 == identity(os.stat(stage_name, dir_fd=self.admission.directory, follow_symlinks=False))
                 and before["uid"] == os.geteuid() and before["gid"] == os.getegid()
                 and before["mode"] == 0o600 and before["links"] == 1,
                 "completion_journal_stage_changed")
            need(os.pread(stage_fd, MAX_PUBLIC_BYTES + 1, 0) == content
                 and identity(os.fstat(stage_fd)) == before
                 == identity(os.stat(stage_name, dir_fd=self.admission.directory, follow_symlinks=False)),
                 "completion_journal_stage_changed")

        def adopt_exchange():
            nonlocal stage_fd, installed
            new_observed, displaced = identity(os.fstat(stage_fd)), identity(os.fstat(old_fd))
            need(paired(new_observed, stage_observed) and paired(displaced, old_observed)
                 and new_observed == identity(os.stat(self.name, dir_fd=self.admission.directory, follow_symlinks=False))
                 and displaced == identity(os.stat(stage_name, dir_fd=self.admission.directory, follow_symlinks=False))
                 and os.pread(stage_fd, MAX_PUBLIC_BYTES + 1, 0) == complete
                 and os.pread(old_fd, MAX_PUBLIC_BYTES + 1, 0) == prefix,
                 "completion_journal_exchange_ambiguous")
            need(new_observed == identity(os.fstat(stage_fd))
                 == identity(os.stat(self.name, dir_fd=self.admission.directory, follow_symlinks=False))
                 and displaced == identity(os.fstat(old_fd))
                 == identity(os.stat(stage_name, dir_fd=self.admission.directory, follow_symlinks=False)),
                 "completion_journal_exchange_ambiguous")
            self.fd, self.observed = stage_fd, new_observed
            stage_fd, installed = None, True
            # Retain no aliases to mutable caller metadata, including on an
            # exception immediately after the complete chain became visible.
            self.records.append(public_json(body, 65536))
            return displaced

        try:
            need(stat.S_ISREG(os.fstat(stage_fd).st_mode) and stage_created["uid"] == os.geteuid()
                 and stage_created["gid"] == os.getegid() and stage_created["mode"] == 0o600
                 and stage_created["links"] == 1, "completion_journal_stage_changed")
            offset = 0
            while offset < len(complete):
                self.admission.verify()
                self.check()
                try:
                    written = os.write(stage_fd, complete[offset:])
                except InterruptedError:
                    continue
                need(0 < written <= len(complete) - offset, "completion_journal_write_incomplete")
                offset += written
            os.fsync(stage_fd)
            stage_observed = identity(os.fstat(stage_fd))
            staged(stage_observed, complete)
            self.admission.verify()
            self.check()
            need(os.pread(old_fd, MAX_PUBLIC_BYTES + 1, 0) == prefix, "completion_journal_changed")
            self.check()
            try:
                owner.native_exchange(self.admission.directory, self.name, stage_name)
            except BaseException:
                # A native effect can precede an interrupted acknowledgement.
                # Adopt only the two exact exchanged inodes; unknown paths are
                # preserved and cannot authorize a later append or cleanup.
                self.admission.refresh_directory()
                if identity(os.fstat(stage_fd)) == identity(os.stat(
                        self.name, dir_fd=self.admission.directory, follow_symlinks=False)):
                    adopt_exchange()
                raise
            self.admission.refresh_directory()
            displaced = adopt_exchange()
            os.fsync(self.admission.directory)
            self.admission.verify()
            self.check()
            need(displaced == identity(os.fstat(old_fd))
                 == identity(os.stat(stage_name, dir_fd=self.admission.directory, follow_symlinks=False))
                 and os.pread(old_fd, MAX_PUBLIC_BYTES + 1, 0) == prefix,
                 "completion_journal_cleanup_ambiguous")
            need(displaced == identity(os.fstat(old_fd))
                 == identity(os.stat(stage_name, dir_fd=self.admission.directory, follow_symlinks=False)),
                 "completion_journal_cleanup_ambiguous")
            os.unlink(stage_name, dir_fd=self.admission.directory)
            self.admission.refresh_directory()
            os.fsync(self.admission.directory)
            self.check()
        finally:
            if installed:
                os.close(old_fd)
            else:
                # Failed/partial or substituted stages remain evidence. Only
                # an exact fully written unexchanged public stage may be removed.
                if stage_observed is not None:
                    try:
                        self.admission.verify()
                        self.check()
                        staged(stage_observed, complete)
                        os.unlink(stage_name, dir_fd=self.admission.directory)
                        self.admission.refresh_directory()
                        os.fsync(self.admission.directory)
                    except Exception:
                        pass
            if stage_fd is not None:
                os.close(stage_fd)

    def reference(self):
        self.check()
        body = os.pread(self.fd, MAX_PUBLIC_BYTES+1, 0)
        need(0 < len(body) <= MAX_PUBLIC_BYTES, "completion_journal_empty_or_oversized")
        self.check()
        return dict(file=dict(path=str(self.admission.path / self.name), identity=self.observed),
                    sha256=hashlib.sha256(body).hexdigest())


class AdoptionJournal(CompletionJournal):
    """Keep the signed incident set and publisher intent in native authority."""

    def __init__(self, admission):
        super().__init__(admission, name="native-adoption.ndjson")

    def load(self):
        self.check()
        body = os.pread(self.fd, MAX_PUBLIC_BYTES + 1, 0)
        need(len(body) <= MAX_PUBLIC_BYTES and (not body or body.endswith(b"\n")), "adoption_journal_bound")
        for sequence, line in enumerate(body.splitlines(), 1):
            row = public_json(line, 65536)
            fields(row, ADOPTION_BINDING_KEYS | {"schema", "sequence", "phase", "archive_ordinal",
                "archived_journals", "owner_journal", "write_intent"}, "adoption_journal_fields")
            need(row["schema"] == ADOPTION_PREFIX + "journal.v1" and type(row["sequence"]) is int
                 and row["sequence"] == sequence and all(row[key] == value for key, value in self.admission.bindings.items())
                 and row["phase"] in {"admitted", "archive_requested", "archived", "owner_write_requested", "adopted_unqualified"}
                 and isinstance(row["archived_journals"], list) and len(row["archived_journals"]) <= 32,
                 "adoption_journal_binding")
            for ordinal, reference in enumerate(row["archived_journals"]):
                need(ordinal < len(self.admission.plan["opaque_journals"]), "adoption_archives_bound")
                fields(reference, {"file", "sha256"}, "adoption_archive_reference")
                validate_observed(reference["file"])
                original = self.admission.plan["opaque_journals"][ordinal]
                need(reference["file"]["path"] == adoption_archive_path(self.admission, ordinal)
                     and reference["sha256"] == original["sha256"]
                     and all(reference["file"]["identity"][key] == original["file"]["identity"][key]
                             for key in IDENTITY_KEYS - {"ctime_ns"}), "adoption_archive_lineage")
            ordinal = row["archive_ordinal"]
            need((row["phase"] == "archive_requested") == (ordinal is not None)
                 and (ordinal is None or type(ordinal) is int and 0 <= ordinal < len(self.admission.plan["opaque_journals"])),
                 "adoption_archive_intent")
            witness = row["write_intent"]
            if witness is not None:
                fields(witness, {"intent", "stage", "record"}, "adoption_write_intent_fields")
                need(row["phase"] == "owner_write_requested" and isinstance(witness["record"], dict)
                     and witness["record"].get("operation_id") == self.admission.packet["operation_id"],
                     "adoption_write_intent_binding")
                fields(witness["intent"], {"path", "identity", "sha256"}, "adoption_write_intent_reference")
                native = self.admission.plan["nginx"]["native"]
                owner = self.admission.verify()
                owner.validate_public_owner_identity(witness["intent"]["identity"], native)
                owner.validate_public_owner_identity(witness["stage"], native)
                hex_value(witness["intent"]["sha256"], 64, "adoption_write_intent_digest")
                name = Path(witness["intent"]["path"]).name
                need(witness["record"].get("sequence") == 1
                     and re.fullmatch(r"\.taira-native-nginx-write-" + self.admission.packet["operation_id"]
                         + r"-1-[0-9a-f]{32}\.intent\.json", name) is not None
                     and witness["intent"]["path"] == str(Path(native["directory"]["path"]) / name),
                     "adoption_write_intent_path")
            if row["owner_journal"] is not None:
                need(row["phase"] == "adopted_unqualified", "adoption_owner_phase")
                owner = self.admission.verify()
                need(owner.validate_public_journal_reference(row["owner_journal"], self.admission.plan["nginx"]["native"])
                     == self.admission.packet["operation_id"], "adoption_owner_operation")
            self.records.append(row)
        need(len(self.records) <= 128, "adoption_journal_bound")
        self.check()

    def phase(self, phase, archives, *, archive_ordinal=None, owner_journal=None, write_intent=None):
        self.append_record(dict(self.admission.bindings, schema=ADOPTION_PREFIX + "journal.v1",
            sequence=len(self.records)+1, phase=phase, archive_ordinal=archive_ordinal,
            archived_journals=archives, owner_journal=owner_journal, write_intent=write_intent))


def adopt(packet):
    admission = AdoptionAdmission(packet)
    journal = None
    try:
        journal = AdoptionJournal(admission)
        return adopt_owned(admission, journal)
    finally:
        if journal is not None:
            journal.close()
        admission.close()


def adopt_owned(admission, journal):
    owner = admission.verify()
    result = owner.adopt_owned_publication(admission.plan["nginx"], lambda receipt, request, context:
        adopt_in_context(receipt, request, context, admission, journal, owner))
    status, code = "adopted_unqualified", None
    if result.get("exit_code") != 0 or result.get("validation_files_removed") is not True:
        status = "recovery_pending"
        code = result.get("error_code", "native_adoption_refused")
    need(code is None or isinstance(code, str) and re.fullmatch(r"[a-z_]{1,128}", code), "adoption_error_code")
    bindings = {key: value for key, value in admission.bindings.items() if key != "host_identity_sha256"}
    return dict(bindings, schema=ADOPTION_PREFIX + "receipt.v1",
        progress_before_sha256=admission.packet["progress"]["reference"]["sha256"], status=status,
        archived_journals=result.get("archived_journals", []),
        owned_publication=result.get("owned_publication") if status == "adopted_unqualified" else None,
        error_code=code)


def adopt_in_context(receipt, request, context, admission, journal, owner):
    """Archive only pinned opaque inodes, then own the unchanged public include."""
    import copy
    directory = context["directory"]
    destination = str(Path(request["destination"]["directory"]["path"]) / request["destination"]["basename"])
    originals = admission.plan["opaque_journals"]
    journal_name = ".taira-native-nginx-apply-" + request["operation_id"] + ".receipt.ndjson"
    journal_path = str(Path(request["native"]["directory"]["path"]) / journal_name)
    incident_refs = copy.deepcopy(admission.packet["opaque_journals"])
    archives = []
    current_journal = None

    def public_pin(reference, fd):
        return dict(fd=fd, reference=reference)

    def current_public():
        retained_public(admission.packet["publication"])
        need(admission.packet["publication"]["reference"] == admission.plan["publication"], "adoption_include_changed")

    def census():
        permitted = {Path(reference["reference"]["file"]["path"]).name for ordinal, reference in enumerate(incident_refs)
                     if reference["reference"]["file"]["path"] == originals[ordinal]["file"]["path"]}
        if any(row["write_intent"] is not None for row in journal.records):
            permitted.add(journal_name)
        observed = set()
        with os.scandir(directory) as entries:
            for count, entry in enumerate(entries, 1):
                need(count <= 4096, "adoption_directory_entry_bound")
                if re.fullmatch(r"\.taira-native-nginx-apply-[0-9a-f]{32}\.receipt\.ndjson", entry.name):
                    observed.add(entry.name)
        need(observed <= permitted, "adoption_unadmitted_journal")

    def guard():
        admission.verify()
        journal.check()
        current_public()
        for key, fd in context["bound"].items():
            context["revalidate"](request["native"][key], fd)
        context["revalidate"](request["native"]["directory"], directory, True)
        need(context["identity"](os.fstat(context["lock"])) == context["lock_identity"]
             == context["identity"](os.stat(".taira-native-nginx-check.lock", dir_fd=directory, follow_symlinks=False)),
             "check_lock_identity_changed")
        need(owner.observe_master(request["master"]) == request["master"], "master_identity_changed")
        for reference in incident_refs:
            retained_public(reference)
        if current_journal is not None:
            reference, fd = current_journal
            context["revalidate"]({key: reference[key] for key in ("path", "identity")}, fd)
        census()

    # Before an inherited archive may supply custody, our independently durable
    # authority must already name that exact original and target arrangement.
    for ordinal, pin in enumerate(incident_refs):
        original = originals[ordinal]
        retained_public(pin)
        need(pin["reference"]["sha256"] == original["sha256"]
             and all(pin["reference"]["file"]["identity"][key] == original["file"]["identity"][key]
                     for key in IDENTITY_KEYS - {"ctime_ns"}), "adoption_incident_lineage")
        archive_path = adoption_archive_path(admission, ordinal)
        if pin["reference"]["file"]["path"] == archive_path:
            need(any(row["phase"] == "archive_requested" and row["archive_ordinal"] == ordinal
                     for row in journal.records), "adoption_archive_without_intent")
            try:
                os.stat(original["file"]["path"], follow_symlinks=False)
            except FileNotFoundError:
                pass
            else:
                raise RuntimeError("adoption_archive_ambiguous")
        else:
            need(pin["reference"] == original, "adoption_incident_changed")
            try:
                os.stat(archive_path, follow_symlinks=False)
            except FileNotFoundError:
                pass
            else:
                raise RuntimeError("adoption_archive_ambiguous")
    admission.incident_refs = incident_refs
    guard()
    native_context_check(context, request, owner, includes=True)
    guard()
    if not journal.records:
        journal.phase("admitted", archives)
    for ordinal, pin in enumerate(incident_refs):
        original = originals[ordinal]
        target = adoption_archive_path(admission, ordinal)
        if pin["reference"]["file"]["path"] != target:
            if not any(row["phase"] == "archive_requested" and row["archive_ordinal"] == ordinal
                       for row in journal.records):
                journal.phase("archive_requested", archives, archive_ordinal=ordinal)
            else:
                journal.check()
                os.fsync(journal.fd)
                os.fsync(admission.directory)
            guard()
            owner.native_publish_no_replace(directory, Path(original["file"]["path"]).name, Path(target).name)
            observed = identity(os.fstat(pin["fd"]))
            need(all(observed[key] == original["file"]["identity"][key] for key in IDENTITY_KEYS - {"ctime_ns"})
                 and observed == identity(os.stat(target, follow_symlinks=False)), "adoption_archive_changed")
            pin["reference"] = dict(file=dict(path=target, identity=observed), sha256=original["sha256"])
        receipt["archived_journals"] = copy.deepcopy(archives + [pin["reference"]])
        os.fsync(directory)
        guard()
        archives.append(copy.deepcopy(pin["reference"]))
        receipt["archived_journals"] = copy.deepcopy(archives)
        if not any(row["phase"] == "archived" and row["archived_journals"] == archives for row in journal.records):
            journal.phase("archived", archives)
    guard()
    native_context_check(context, request, owner, includes=True)
    guard()
    publication_identity = {key: str(value) for key, value in admission.plan["publication"]["file"]["identity"].items()}
    record = dict(schema="iroha.taira.native-nginx-apply.journal.v1", sequence=1,
        operation_id=request["operation_id"], phase="awaiting_readiness", qualified=False,
        candidate_sha256=request["candidate_sha256"], renderer_source_sha256=request["renderer_source_sha256"],
        host_kind=request["host_kind"], native_executable=request["native"]["nginx"],
        main_configuration=request["native"]["main"], master=request["master"], destination_path=destination,
        destination_directory=request["destination"]["directory"], publication_identity=publication_identity,
        cause="explicit_native_owner_adoption:" + admission.packet["authorization_sha256"])
    prepared = next((row["write_intent"] for row in reversed(journal.records) if row["write_intent"] is not None), None)
    projection = owner.public_journal_record_projection

    def persist_intent(intent, stage, semantic):
        need(semantic == projection(record), "adoption_owner_record_changed")
        witness = dict(intent=intent, stage=stage, record=semantic)
        if not any(row["write_intent"] == witness for row in journal.records):
            journal.phase("owner_write_requested", archives, write_intent=witness)
        else:
            journal.check()
            os.fsync(journal.fd)
            os.fsync(admission.directory)
        guard()

    try:
        observed = context["identity"](os.stat(journal_name, dir_fd=directory, follow_symlinks=False))
    except FileNotFoundError:
        reference, fd, committed = owner.append_owned_publication_record(
            context, request, None, None, [], record, persist_intent, prepared)
    else:
        need(prepared is not None and all(observed[key] == prepared["stage"][key]
             for key in IDENTITY_KEYS - {"ctime_ns"}), "adoption_owner_without_intent")
        fd = context["open_bound"](dict(path=journal_path, identity=observed))
        body = os.pread(fd, MAX_PUBLIC_BYTES+1, 0)
        reference = dict(path=journal_path, identity=observed, sha256=hashlib.sha256(body).hexdigest())
        retained, rows = owner.read_owned_publication_journal(reference, request, context, destination)
        need(len(rows) == 1 and rows[0]["journal_write_intent"] == prepared["intent"]
             and projection(rows[0]) == projection(record), "adoption_owner_record_changed")
        fd, committed = retained, rows[0]
        os.fsync(directory)
    current_journal = reference, fd
    guard()
    need(projection(committed) == projection(record), "adoption_owner_record_changed")
    if not any(row["phase"] == "adopted_unqualified" and row["owner_journal"] == reference for row in journal.records):
        journal.phase("adopted_unqualified", archives, owner_journal=reference)
    guard()
    receipt.update(exit_code=0, owned_publication=dict(operation_id=request["operation_id"],
        journal=dict(file=dict(path=reference["path"], identity={key: int(value) for key, value in reference["identity"].items()}),
                     sha256=reference["sha256"]), publication=admission.plan["publication"]))


def complete(packet):
    """Run one authenticated, exact-owner native terminal action locally."""
    admission = Admission(packet)
    journal = None
    try:
        journal = CompletionJournal(admission)
        return complete_owned(admission, journal)
    finally:
        if journal is not None:
            journal.close()
        admission.close()


def complete_owned(admission, journal):
    """Dispatch effects under the maintained nginx owner lock and decoder."""
    owner = admission.verify()
    plan = admission.plan["nginx"]
    # The public candidate is already declared by the canonical owner plan.
    # Read its exact inode natively, never the private main/TLS configuration.
    fd = open_anchored(plan["candidate"]["path"])
    try:
        observed = identity(os.fstat(fd))
        need(stat.S_ISREG(os.fstat(fd).st_mode) and observed["uid"] == plan["candidate"]["owner_uid"]
             and observed["links"] == 1 and not observed["mode"] & 0o022
             and 0 < observed["size"] <= MAX_PUBLIC_BYTES, "unsafe_public_candidate")
        candidate = os.pread(fd, MAX_PUBLIC_BYTES + 1, 0)
        recheck_observed(dict(path=plan["candidate"]["path"], identity=observed), fd)
        need(hashlib.sha256(candidate).hexdigest() == plan["candidate"]["sha256"], "candidate_digest_changed")
    finally:
        os.close(fd)
    request = dict(host_kind=plan["host_kind"], native=plan["native"], master=plan["master"],
        destination=plan["destination"], operation_id=plan["operation_id"], publication=plan["publication"],
        candidate_sha256=plan["candidate"]["sha256"], candidate_base64=base64.b64encode(candidate).decode(),
        renderer_source_sha256=plan["renderer_source"]["sha256"])
    result = owner.checked.remote_check(request, lambda receipt, request, context:
        finish_in_context(receipt, request, context, admission, journal, owner))
    status = result.get("completion_status", "recovery_pending")
    need(status in {"rolled_back", "sealed", "cleaned", "recovery_pending"}, "completion_status")
    code = result.get("error_code")
    if result.get("exit_code") != 0 or result.get("validation_files_removed") is not True:
        status = "recovery_pending"
        code = code or "native_completion_refused"
    need(code is None or isinstance(code, str) and re.fullmatch(r"[a-z_]{1,128}", code) is not None,
         "completion_error_code")
    fence_sha = (admission.packet["fence"]["value"]["reference"]["reference"]["sha256"]
                 if admission.packet["fence"]["kind"] == "present" else None)
    return dict(admission.bindings, schema=RECEIPT_SCHEMA, action=packet_action(admission),
        progress_before_sha256=admission.packet["progress"]["reference"]["sha256"],
        global_proof_sha256=fence_sha, publication_operation_id=intended_publication_operation(admission.plan),
        completion_journal=journal.reference(), status=status, error_code=code,
        restored_owned_publication=(result.get("restored_owned_publication") if status == "rolled_back" else None))


def packet_action(admission):
    return admission.packet["action"]


def intended_publication_operation(plan):
    effect = plan["publication_effect"]
    return (effect["value"]["intended_operation_id"] if effect["kind"] == "not_requested"
            else plan["nginx"]["operation_id"])


def numeric_owned_publication(plan):
    """Project the sole maintained owner wire into exact native numeric refs."""
    prior = plan["publication"]["prior"]
    destination = str(Path(plan["destination"]["directory"]["path"]) / plan["destination"]["basename"])
    def public(path, observed, digest):
        return dict(file=dict(path=path, identity={key: int(value) for key, value in observed.items()}), sha256=digest)
    return dict(operation_id=prior["operation_id"],
        journal=public(prior["journal"]["path"], prior["journal"]["identity"], prior["journal"]["sha256"]),
        publication=public(destination, prior["publication"]["identity"], prior["publication"]["sha256"]))


def numeric_owner_journal(reference):
    """Project one closed numeric public journal reference to the owner's wire."""
    fields(reference, {"file", "sha256"}, "publisher_public_fields")
    validate_observed(reference["file"])
    hex_value(reference["sha256"], 64, "publisher_public_digest")
    return dict(path=reference["file"]["path"],
                identity={key: str(value) for key, value in reference["file"]["identity"].items()},
                sha256=reference["sha256"])


def numeric_owner_publication(value):
    """Project only an actual typed owner, without accepting legacy string identities."""
    fields(value, {"operation_id", "journal", "publication"}, "publisher_restored_owner_fields")
    hex_value(value["operation_id"], 32, "publisher_restored_identity")
    journal = numeric_owner_journal(value["journal"])
    publication = numeric_owner_journal(value["publication"])
    return dict(operation_id=value["operation_id"], journal=journal,
                publication={key: publication[key] for key in ("identity", "sha256")})


def finish_in_context(receipt, request, context, admission, journal, owner):
    """Only the owner-proven public include and retained backup can be changed."""
    action = packet_action(admission)
    directory = context["open_bound"](request["destination"]["directory"], True)
    destination = str(Path(request["destination"]["directory"]["path"]) / request["destination"]["basename"])
    basename = request["destination"]["basename"]
    backup_name = ".taira-nginx-backup-" + request["operation_id"] + ".public"
    prior = request["publication"].get("prior")
    publisher = (numeric_owner_journal(admission.plan["publication_effect"]["value"]["journal"])
                 if admission.plan["publication_effect"]["kind"] == "publisher_rolled_back"
                 else prior["journal"])
    active = prior["publication"]["identity"] if prior is not None else None
    backup = None
    restored = None
    terminal_record = None
    master_handle = None
    retained_journals = {}

    def retain_journal(reference, opened):
        retained_journals[reference["path"]] = (reference, opened)

    def journal_effect(phase, **details):
        journal.append(phase, publication_identity=active, backup_identity=backup,
            publisher_journal=publisher, publisher_terminal_record=terminal_record,
            restored_owner=restored, **details)

    def owned(name, expected, digest, renamed=False):
        return owner.verify_owned_public_file(context, directory, name, expected, digest, renamed=renamed)

    def native_guard():
        admission.verify()
        journal.check()
        for name, fd in context["bound"].items():
            context["revalidate"](context["native"][name], fd)
        for reference, fd in retained_journals.values():
            context["revalidate"]({key: reference[key] for key in ("path", "identity")}, fd)
        context["revalidate"](context["native"]["directory"], context["directory"], True)
        context["revalidate"](request["destination"]["directory"], directory, True)
        need(context["identity"](os.fstat(context["lock"])) == context.get("lock_identity")
             == context["identity"](os.stat(".taira-native-nginx-check.lock", dir_fd=context["directory"],
                                            follow_symlinks=False)), "check_lock_identity_changed")
        need(owner.observe_master(request["master"]) == request["master"], "master_identity_changed")

    def immutable_publisher(reference, template):
        # An atomic publisher append exposes either the complete pinned prefix
        # or that prefix plus exactly one independently witnessed terminal row.
        # Its pre-publication intent is also retained in our own authority chain.
        owner.validate_public_journal_reference(reference, context["native"])
        opened = open_anchored(reference["path"])
        context["handles"].append(opened)
        observed = context["identity"](os.fstat(opened))
        owner.validate_public_owner_identity(observed, context["native"])
        need(stat.S_ISREG(os.fstat(opened).st_mode)
             and observed == context["identity"](os.stat(reference["path"], follow_symlinks=False)),
             "publisher_journal_changed")
        body = os.pread(opened, MAX_PUBLIC_BYTES + 1, 0)
        prefix_size = int(reference["identity"]["size"])
        need(len(body) <= MAX_PUBLIC_BYTES and len(body) >= prefix_size
             and hashlib.sha256(body[:prefix_size]).hexdigest() == reference["sha256"],
             "publisher_journal_prefix_changed")
        need(observed == context["identity"](os.fstat(opened))
             == context["identity"](os.stat(reference["path"], follow_symlinks=False)),
             "publisher_journal_changed")
        actual = dict(path=reference["path"], identity=observed, sha256=hashlib.sha256(body).hexdigest())
        retained, records = owner.read_owned_publication_journal(actual, request, context, destination)
        projection = owner.public_journal_record_projection
        if len(body) == prefix_size:
            need(observed == reference["identity"] and actual["sha256"] == reference["sha256"],
                 "publisher_journal_changed")
            retain_journal(actual, retained)
            if template is None or projection(records[-1]) == projection(template):
                return actual, records, False
            need(type(template["sequence"]) is int and template["sequence"] == len(records) + 1,
                 "publisher_terminal_sequence")
            return actual, records, False
        need(template is not None and records[-1]["sequence"] == template["sequence"]
             and projection(records[-1]) == projection(template)
             and len(body[prefix_size:].splitlines()) == 1, "publisher_journal_suffix_changed")
        recorded = [row["publisher_write_intent"] for row in journal.records
                    if row["publisher_write_intent"] is not None]
        witness = next((item for item in recorded
                        if item["intent"] == records[-1]["journal_write_intent"]
                        and item["record"] == projection(template)), None)
        need(witness is not None
             and all(observed[key] == witness["stage"][key]
                     for key in IDENTITY_KEYS - {"ctime_ns"}), "publisher_terminal_not_recorded")
        retain_journal(actual, retained)
        native_guard()
        return actual, records, True

    def append_publisher(reference, template):
        native_guard()
        actual, records, appended = immutable_publisher(reference, template)
        projection = owner.public_journal_record_projection
        if projection(records[-1]) == projection(template):
            return actual
        need(not appended and any(row["publisher_terminal_record"] is not None
                 and projection(row["publisher_terminal_record"]) == projection(template)
                 or row["restored_owner"] is not None
                 and row["restored_owner"]["terminal_record"] is not None
                 and projection(row["restored_owner"]["terminal_record"]) == projection(template)
                 for row in journal.records), "publisher_terminal_not_recorded")
        retained = retained_journals[actual["path"]][1]
        def persist_intent(intent, stage_identity, record_projection):
            need(record_projection == projection(template), "publisher_terminal_changed")
            witness = dict(intent=intent, stage=stage_identity, record=record_projection)
            if not any(row["publisher_write_intent"] == witness for row in journal.records):
                journal_effect("publisher_terminal_requested", publisher_write_intent=witness)
            else:
                journal.check()
                os.fsync(journal.fd)
                os.fsync(admission.directory)
            native_guard()
        prepared = next((row["publisher_write_intent"] for row in reversed(journal.records)
                         if row["publisher_write_intent"] is not None
                         and row["publisher_write_intent"]["record"] == projection(template)), None)
        updated, successor, committed = owner.append_owned_publication_record(
            context, request, actual, retained, records, template, persist_intent, prepared)
        need(projection(committed) == projection(template), "publisher_terminal_changed")
        retain_journal(updated, successor)
        native_guard()
        return updated

    try:
        native_guard()
        if admission.plan["publication_effect"]["kind"] == "publisher_rolled_back":
            # The original publisher has already restored its journal-proven
            # predecessor. A historical rollback lease cannot complete forward
            # publication just to manufacture a terminal boundary.
            need(action == "rollback", "publisher_rollback_terminal_action")
            effect = admission.plan["publication_effect"]["value"]
            need(owner.validate_public_journal_reference(publisher, context["native"])
                 == request["operation_id"], "publisher_rollback_operation")
            retained, rows = owner.read_owned_publication_journal(publisher, request, context, destination)
            retain_journal(publisher, retained)
            need(rows[-1]["phase"] == "rolled_back_unqualified"
                 and rows[-1]["qualified"] is False
                 and rows[-1]["master"] == request["master"]
                 and rows[-1]["candidate_sha256"] == request["candidate_sha256"]
                 and rows[-1]["renderer_source_sha256"] == request["renderer_source_sha256"]
                 and rows[0].get("prior") == prior, "publisher_rollback_terminal_binding")
            restored_publication = effect["restored_owned_publication"]
            need((restored_publication is None) == (prior is None), "publisher_rollback_predecessor")
            if restored_publication is not None:
                predecessor = numeric_owner_publication(restored_publication)
                owner.validate_public_prior_reference(predecessor, context["native"])
                need(restored_publication["publication"]["file"]["path"] == destination
                     and predecessor["operation_id"] == prior["operation_id"]
                     and predecessor["publication"]["sha256"] == prior["publication"]["sha256"]
                     and all(predecessor["publication"]["identity"][key] == prior["publication"]["identity"][key]
                             for key in IDENTITY_KEYS - {"ctime_ns"}), "publisher_rollback_predecessor")
                retained, previous = owner.read_owned_publication_journal(
                    predecessor["journal"], request, context, destination)
                retain_journal(predecessor["journal"], retained)
                need(previous[-1]["phase"] == "awaiting_readiness"
                     and previous[-1]["master"] == request["master"]
                     and previous[-1]["publication_identity"] == predecessor["publication"]["identity"]
                     and previous[-1]["candidate_sha256"] == predecessor["publication"]["sha256"],
                     "publisher_rollback_restored_binding")
                # The restored public journal may contain the exact owner's
                # controlled ctime refresh. Its signed original prefix remains
                # the immutable authority for this predecessor.
                old_size = int(prior["journal"]["identity"]["size"])
                need(0 < old_size <= MAX_PUBLIC_BYTES
                     and hashlib.sha256(os.pread(retained, old_size, 0)).hexdigest()
                         == prior["journal"]["sha256"], "publisher_rollback_restored_prefix")
                active = predecessor["publication"]["identity"]
                owned(basename, active, predecessor["publication"]["sha256"])
                restored = dict(owner=predecessor, terminal_record=None)
            else:
                active = None

            def restored_guard():
                native_guard()
                if restored_publication is not None:
                    owned(basename, active, predecessor["publication"]["sha256"])
                else:
                    try:
                        os.stat(basename, dir_fd=directory, follow_symlinks=False)
                    except FileNotFoundError:
                        pass
                    else:
                        raise RuntimeError("publisher_rollback_absence_changed")
                try:
                    os.stat(backup_name, dir_fd=directory, follow_symlinks=False)
                except FileNotFoundError:
                    pass
                else:
                    raise RuntimeError("publisher_rollback_backup_remaining")

            restored_guard()
            native_context_check(context, request, owner, includes=restored_publication is not None)
            restored_guard()
            if not journal.records:
                journal_effect("admitted")
            need(all(row["action"] == "rollback" and row["phase"] in {
                "admitted", "rollback_requested", "rolled_back", "recovery_pending"} for row in journal.records),
                "publisher_rollback_journal_phase")
            if journal.records[-1]["phase"] != "rolled_back":
                journal_effect("rollback_requested")
                restored_guard()
                journal_effect("rolled_back")
            restored_guard()
            receipt.update(exit_code=0, completion_status="rolled_back",
                           restored_owned_publication=restored_publication)
            return
        if admission.plan["publication_effect"]["kind"] == "not_requested":
            # Stage-only rollback proves the incumbent without changing it.
            # It cannot borrow the successor's nonexistent journal or undo a
            # healthy current network to manufacture a rollback receipt.
            need(action == "rollback", "not_requested_terminal_action")
            incumbent = admission.plan["publication_effect"]["value"]["incumbent"]
            intended = admission.plan["publication_effect"]["value"]["intended_operation_id"]
            need(intended != request["operation_id"], "intended_operation_is_incumbent")
            intended_journal = ".taira-native-nginx-apply-" + intended + ".receipt.ndjson"
            def verify_unrequested():
                try:
                    os.stat(intended_journal, dir_fd=context["directory"], follow_symlinks=False)
                except FileNotFoundError:
                    pass
                else:
                    raise RuntimeError("publication_effect_already_requested")
            verify_unrequested()
            observed = {}
            owner.inspect_owned_publication_in_context(observed, request, context)
            exact = dict(operation_id=observed["operation_id"], journal=observed["journal"],
                         publication=observed["publication"])
            need(exact == incumbent, "incumbent_owner_changed")
            if not journal.records:
                journal_effect("admitted")
            need(all(row["action"] == "rollback" and row["phase"] in {
                "admitted", "rollback_requested", "rolled_back", "recovery_pending"} for row in journal.records),
                "not_requested_journal_phase")
            if journal.records[-1]["phase"] != "rolled_back":
                journal_effect("rollback_requested")
                native_guard()
                verify_unrequested()
                observed = {}
                owner.inspect_owned_publication_in_context(observed, request, context)
                need(dict(operation_id=observed["operation_id"], journal=observed["journal"],
                          publication=observed["publication"]) == incumbent, "incumbent_owner_changed")
                journal_effect("rolled_back")
            native_guard()
            verify_unrequested()
            receipt.update(exit_code=0, completion_status="rolled_back", restored_owned_publication=incumbent)
            return
        last = journal.records[-1] if journal.records else None
        if last is not None:
            need(last["global_proof_sha256"] == (admission.packet["fence"]["value"]["reference"]["reference"]["sha256"]
                 if admission.packet["fence"]["kind"] == "present" else None), "completion_fence_changed")
            need(not (action == "rollback" and any(row["action"] != "rollback" for row in journal.records))
                 and not (action != "rollback" and any(row["action"] == "rollback" for row in journal.records)),
                 "completion_action_order")
            need(not (action == "seal" and any(row["action"] == "cleanup" for row in journal.records)),
                 "completion_action_order")
            publisher = last["publisher_journal"]
            active, backup = last["publication_identity"], last["backup_identity"]
            restored = last["restored_owner"]
            terminal_record = last["publisher_terminal_record"]
            if restored is not None:
                fields(restored, {"owner", "terminal_record"}, "restored_owner_fields")
                owner.validate_public_prior_reference(restored["owner"], context["native"])
        # Terminal owner acknowledgement can be resumed from its exact suffix.
        if action == "rollback" and terminal_record is not None:
            publisher, records, _ = immutable_publisher(prior["journal"], terminal_record)
        else:
            retained, records = owner.read_owned_publication_journal(publisher, request, context, destination)
            retain_journal(publisher, retained)
        original = records[0].get("prior")
        if restored is not None and restored["terminal_record"] is not None:
            restored_reference, _, _ = immutable_publisher(restored["owner"]["journal"],
                                                          restored["terminal_record"])
            restored["owner"]["journal"] = restored_reference
        if last is None or not any(row["phase"] == "admitted" for row in journal.records):
            active = prior["publication"]["identity"]
            need(records[-1]["phase"] == "awaiting_readiness" and records[-1]["qualified"] is False
                 and records[-1]["candidate_sha256"] == request["candidate_sha256"]
                 and records[-1]["renderer_source_sha256"] == request["renderer_source_sha256"]
                 and records[-1]["master"] == request["master"]
                 and records[-1]["publication_identity"] == active, "completion_owner_binding")
            owned(basename, active, request["candidate_sha256"])
            if original is not None:
                # The maintained owner decoder admits the full public ancestor
                # contract before any ancestor file can be opened.
                retained, previous = owner.read_owned_publication_journal(original["journal"], request, context, destination)
                retain_journal(original["journal"], retained)
                need(previous[-1]["phase"] == "awaiting_readiness"
                     and previous[-1]["master"] == request["master"], "restored_owner_binding")
                _, backup = owned(backup_name, records[-1]["backup_identity"], original["publication"]["sha256"])
                restored = dict(owner=original, terminal_record=None)
            journal_effect("admitted")
            last = journal.records[-1]
        if action == "seal":
            need(last["phase"] in {"admitted", "seal_requested", "sealed", "recovery_pending"}, "seal_phase")
            owned(basename, active, request["candidate_sha256"])
            if backup is not None:
                owned(backup_name, backup, original["publication"]["sha256"])
            native_guard()
            if last["phase"] != "sealed":
                journal_effect("seal_requested")
                native_context_check(context, request, owner, includes=True)
                owned(basename, active, request["candidate_sha256"])
                native_guard()
                journal_effect("sealed")
            receipt.update(exit_code=0, completion_status="sealed")
            return
        if action == "cleanup":
            need(any(row["phase"] == "sealed" for row in journal.records)
                 and last["phase"] in {"sealed", "cleanup_requested", "cleaned", "recovery_pending"}, "cleanup_before_seal")
            owned(basename, active, request["candidate_sha256"])
            native_guard()
            if last["phase"] != "cleaned":
                cleanup_was_requested = any(row["phase"] == "cleanup_requested" for row in journal.records)
                if not cleanup_was_requested and backup is not None:
                    owned(backup_name, backup, original["publication"]["sha256"])
                if last["phase"] not in {"cleanup_requested", "recovery_pending"}:
                    journal_effect("cleanup_requested")
                if backup is not None:
                    try:
                        owned(backup_name, backup, original["publication"]["sha256"])
                    except FileNotFoundError:
                        need(cleanup_was_requested, "cleanup_backup_missing")
                    else:
                        native_guard()
                        owned(backup_name, backup, original["publication"]["sha256"])
                        os.unlink(backup_name, dir_fd=directory)
                        os.fsync(directory)
                owned(basename, active, request["candidate_sha256"])
                native_guard()
                journal_effect("cleaned")
            receipt.update(exit_code=0, completion_status="cleaned")
            return

        need(last["phase"] in {"admitted", "rollback_requested", "source_restored", "reload_requested",
             "publisher_terminal_requested", "publisher_terminal", "rolled_back", "recovery_pending"}, "rollback_phase")
        master_handle = owner.open_master_handle(request["master"])
        # Ignore only our own uncertain marker when recovering an interrupted
        # action. The last durable intent remains the authority for effects.
        effective = next(row for row in reversed(journal.records) if row["phase"] != "recovery_pending")
        phase = effective["phase"]
        if phase == "admitted":
            owned(basename, active, request["candidate_sha256"])
            if backup is not None:
                owned(backup_name, backup, original["publication"]["sha256"])
            native_guard()
            journal_effect("rollback_requested")
            phase = "rollback_requested"
        if phase == "rollback_requested":
            if original is not None:
                # A retained intent admits both exact inode arrangements. The
                # exchange can be observed after a crash without doing it twice.
                try:
                    owned(basename, active, request["candidate_sha256"])
                    owned(backup_name, backup, original["publication"]["sha256"])
                    was_active = True
                except RuntimeError:
                    owned(basename, backup, original["publication"]["sha256"], renamed=True)
                    owned(backup_name, active, request["candidate_sha256"], renamed=True)
                    was_active = False
                if was_active:
                    native_guard()
                    owned(basename, active, request["candidate_sha256"])
                    owned(backup_name, backup, original["publication"]["sha256"])
                    owner.native_exchange(directory, basename, backup_name)
                    os.fsync(directory)
                _, restored_identity = owned(basename, backup, original["publication"]["sha256"], renamed=True)
                _, removed_identity = owned(backup_name, active, request["candidate_sha256"], renamed=True)
                active, backup = restored_identity, removed_identity
                retained, previous = owner.read_owned_publication_journal(original["journal"], request, context, destination)
                retain_journal(original["journal"], retained)
                restored["terminal_record"] = dict(previous[-1], sequence=len(previous)+1,
                    phase="awaiting_readiness", publication_identity=active, cause="native_completion_restored")
            else:
                try:
                    owned(basename, active, request["candidate_sha256"])
                except FileNotFoundError:
                    pass
                else:
                    native_guard()
                    owned(basename, active, request["candidate_sha256"])
                    os.unlink(basename, dir_fd=directory)
                    os.fsync(directory)
                active = None
            native_guard()
            journal_effect("source_restored")
            phase = "source_restored"
        if phase in {"source_restored", "reload_requested"}:
            if active is not None:
                owned(basename, active, original["publication"]["sha256"])
            native_guard()
            native_context_check(context, request, owner, includes=active is not None)
            native_guard()
            if phase != "reload_requested":
                journal_effect("reload_requested")
            owner.signal_master(request["master"], master_handle)
            native_guard()
            # The original publisher remains public, unqualified provenance;
            # its terminal annotation prevents future blind unresolved-owner
            # refusal after a controlled rollback.
            terminal_record = dict(records[-1], sequence=len(records)+1,
                phase="rolled_back_unqualified", cause="native_completion_rollback")
            journal_effect("publisher_terminal_requested")
            phase = "publisher_terminal_requested"
        if phase == "publisher_terminal_requested":
            publisher = append_publisher(prior["journal"], terminal_record)
            if restored is not None:
                restored_journal = append_publisher(restored["owner"]["journal"], restored["terminal_record"])
                restored["owner"]["journal"] = restored_journal
                restored["owner"]["publication"]["identity"] = active
                original["journal"] = restored_journal
                original["publication"]["identity"] = active
            journal_effect("publisher_terminal")
            phase = "publisher_terminal"
        if phase == "publisher_terminal":
            if backup is not None:
                try:
                    owned(backup_name, backup, request["candidate_sha256"])
                except FileNotFoundError:
                    pass
                else:
                    native_guard()
                    owned(backup_name, backup, request["candidate_sha256"])
                    os.unlink(backup_name, dir_fd=directory)
                    os.fsync(directory)
            journal_effect("rolled_back")
        if active is not None:
            owned(basename, active, original["publication"]["sha256"])
        native_guard()
        observed_restored = None
        if restored is not None:
            restored_owner = restored["owner"]
            retained, previous = owner.read_owned_publication_journal(
                restored_owner["journal"], request, context, destination)
            retain_journal(restored_owner["journal"], retained)
            need(owner.public_journal_record_projection(previous[-1])
                 == owner.public_journal_record_projection(restored["terminal_record"])
                 and previous[-1]["publication_identity"] == active, "restored_terminal_binding")
            def numeric_public(path, observed, digest):
                return dict(file=dict(path=path, identity={key: int(value) for key, value in observed.items()}),
                            sha256=digest)
            observed_restored = dict(operation_id=restored_owner["operation_id"],
                journal=numeric_public(restored_owner["journal"]["path"], restored_owner["journal"]["identity"],
                                       restored_owner["journal"]["sha256"]),
                publication=numeric_public(destination, active, original["publication"]["sha256"]))
            native_guard()
        receipt.update(exit_code=0, completion_status="rolled_back", restored_owned_publication=observed_restored)
    except Exception as error:
        code = error.args[0] if type(error) is RuntimeError and error.args else "native_completion_refused"
        code = code if isinstance(code, str) and re.fullmatch(r"[a-z_]{1,128}", code) else "native_completion_refused"
        try:
            journal_effect("recovery_pending", error_code=code)
        except Exception:
            pass
        receipt.update(exit_code=1, completion_status="recovery_pending", error_code=code)
    finally:
        if master_handle is not None:
            os.close(master_handle)


def native_context_check(context, request, owner, *, includes):
    """Private nginx streams pass directly through bounded native consumers."""
    native = context["native"]
    environment = {"PATH": "/usr/bin:/bin", "LC_ALL": "C"}
    inherited = (context["lock"], context["directory"], *context["bound"].values())
    status = subprocess.run([native["nginx"]["path"], "-t", "-q", "-c", native["main"]["path"]],
        stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        pass_fds=inherited, env=environment, timeout=45).returncode
    need(status == 0, "completion_native_context_rejected")
    destination = str(Path(request["destination"]["directory"]["path"]) / request["destination"]["basename"])
    # The maintained source guard's sole expected-count predicate is made
    # explicit for a first-publication rollback that restores absence.
    source_guard = owner.SOURCE_GUARD.replace("count!=1", "count!=expected_count")
    child = subprocess.Popen([native["nginx"]["path"], "-T", "-q", "-c", native["main"]["path"]],
        stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
        pass_fds=inherited, env=environment)
    guard = None
    try:
        guard = subprocess.Popen([native["awk"]["path"], "-v", "expected=" + destination,
            "-v", "expected_count=" + str(int(includes)), source_guard], stdin=child.stdout,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, pass_fds=inherited, env=environment)
        child.stdout.close()
        guard_status = guard.wait(timeout=45)
        child_status = child.wait(timeout=45)
        need(guard_status == child_status == 0, "completion_native_source_rejected")
    finally:
        for owned in (guard, child):
            if owned is not None and owned.poll() is None:
                owned.kill()
                owned.wait()


def read_request_fd(fd, limit):
    descriptor_value(fd)
    info = os.fstat(fd)
    need(stat.S_ISREG(info.st_mode) and 0 < info.st_size <= limit
         and info.st_uid == os.geteuid() and info.st_nlink == 1 and not info.st_mode & 0o077,
         "request_descriptor_custody")
    observed = identity(info)
    body = os.pread(fd, limit+1, 0)
    need(identity(os.fstat(fd)) == observed, "request_descriptor_changed")
    return public_json(body, limit)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    entry = parser.add_mutually_exclusive_group(required=True)
    entry.add_argument("--admission-fd", type=int, help="Direct native Rust parent's retained admission descriptor")
    entry.add_argument("--inspect-request-fd", type=int, help="Retained public request for a read-only owner observation")
    entry.add_argument("--adoption-admission-fd", type=int, help="Direct native Rust parent's independently authorized owner adoption")
    args = parser.parse_args(argv)
    try:
        if args.adoption_admission_fd is not None:
            result = adopt(read_request_fd(args.adoption_admission_fd, 128 * 1024))
        elif args.admission_fd is not None:
            result = complete(read_request_fd(args.admission_fd, 64 * 1024))
        else:
            result = inspect_owned_publication(read_request_fd(args.inspect_request_fd, 64 * 1024))
        print(json.dumps(result, sort_keys=True, separators=(",", ":")))
        return int(result.get("status") == "recovery_pending")
    except Exception as error:
        code = error.args[0] if type(error) is RuntimeError and error.args else "native_completion_failed"
        code = code if isinstance(code, str) and re.fullmatch(r"[a-z_]{1,128}", code) else "native_completion_failed"
        print(json.dumps(dict(error_code=code), separators=(",", ":")))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
