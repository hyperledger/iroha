#!/usr/bin/env python3
"""Retry a fully rolled-back four-validator Taira deployment with identical artifacts.

The build identity is immutable; each attempt gets a fresh inventory and nonce.
Native assemble/authorize/apply remain the authentication and execution authority.
Native preparation derives public genesis and authenticated beacon inputs from
a closed topology intent and actual retained input paths.
Only the pinned renderer creates final FD200 units; native code admits credentials.
Static retained path arguments and per-attempt derived assembly arguments have
separate records. No prior four-file public bundle is accepted as the new closure.
Runtime signing keys and peer configs are passed only to native code. This module
also retains the locked operator-custody retirement, signer metadata continuity and
boot publication checks used by the deployed corridor.
The guest plan explicitly lists retired_public_imports (possibly empty). Each
closed import names digest-pinned inventory, retirement, binary_manifest and
source_manifest public records plus the exact completed source.pack path. Only
superseded public payloads are reclaimed; current inputs and records remain.
"""

from __future__ import annotations
import argparse
import ast
import base64
import copy
import ctypes
import errno
import fcntl
import hashlib
import gzip
import io
import json
import os
import platform
import re
import resource
import secrets
import shlex
import shutil
import stat
import subprocess
import sys
import tarfile
import time
from contextlib import contextmanager
from pathlib import Path
from types import SimpleNamespace

PLAN_SCHEMA = "taira.same-artifact-retry.v1"
PROGRESS_SCHEMA = "taira.retry-progress.v1"
RESULT_SCHEMA = "taira.retry-result.v1"
PROGRESS_SECONDS = 30
PHASES = (
    "retire",
    "prepare-public-inputs",
    "prepare-beacon-inputs",
    "assemble",
    "signer-pre",
    "authorize",
    "apply",
    "signer-post",
    "persistence",
    "public-validation",
)


class RetryError(RuntimeError):
    """The exact retry stopped; its private evidence must be preserved."""


def require(value, message):
    if not value:
        raise RetryError(message)


def identity(info):
    return tuple(
        getattr(info, name)
        for name in (
            "st_dev",
            "st_ino",
            "st_mode",
            "st_uid",
            "st_gid",
            "st_nlink",
            "st_size",
            "st_mtime_ns",
            "st_ctime_ns",
        )
    )


def direct(path):
    path = Path(path)
    require(
        path.is_absolute()
        and path == Path(os.path.normpath(path))
        and path.resolve() == path,
        "input path must be direct and absolute",
    )
    return path


def public_record(
    path, expected=None, *, owner=None, private=False, limit=8 * 1024 * 1024
):
    """Read bounded public evidence through a stable descriptor; never key/config bytes."""
    path = direct(path)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
    try:
        before = os.fstat(fd)
        require(
            stat.S_ISREG(before.st_mode)
            and before.st_nlink == 1
            and before.st_size <= limit
            and before.st_uid == (os.getuid() if owner is None else owner)
            and not before.st_mode & 0o022,
            "unsafe public record metadata",
        )
        if private:
            require(
                stat.S_IMODE(before.st_mode) in (0o400, 0o600),
                "owner-only public plan required",
            )
        raw = os.pread(fd, before.st_size + 1, 0)
        require(
            len(raw) == before.st_size
            and identity(before) == identity(os.fstat(fd)) == identity(path.lstat()),
            "public record changed while reading",
        )
    finally:
        os.close(fd)
    if expected is not None:
        require(
            hashlib.sha256(raw).hexdigest() == expected, "public record digest differs"
        )
    return raw


def decode(raw):
    def unique(pairs):
        value = {}
        for key, item in pairs:
            require(key not in value, "duplicate JSON field")
            value[key] = item
        return value

    return json.loads(raw, object_pairs_hook=unique)


def write_public(path, value):
    """Publish one new private evidence record; previous attempts are never overwritten."""
    raw = (json.dumps(value, sort_keys=True) + "\n").encode()
    return write_public_bytes(path, raw)


def write_public_bytes(path, raw, *, mode=0o600):
    """Publish exact public bytes; only rendered public units use mode0644."""
    require(mode in (0o600, 0o644), "public output mode must be0600 or0644")
    fd = os.open(
        path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600
    )
    with os.fdopen(fd, "wb") as output:
        output.write(raw)
        output.flush()
        if mode != 0o600:
            os.fchmod(output.fileno(), mode)
        os.fsync(output.fileno())
    sync_directory(Path(path).parent)
    return hashlib.sha256(raw).hexdigest()


def sync_directory(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def emit(phase, started, **fields):
    """Only allowlisted public progress is printed; native streams remain private."""
    value = {
        "schema": PROGRESS_SCHEMA,
        "phase": phase,
        "elapsed_seconds": round(time.monotonic() - started, 3),
        **fields,
    }
    try:
        print(json.dumps(value, sort_keys=True), flush=True)
    except (BrokenPipeError, OSError):
        # A disconnected observer must not abort a native operation already in flight.
        pass


def safe_native_error(raw):
    """Project fixed operation names and numeric errno, never arbitrary stderr lines."""
    text = raw.decode("utf-8", "replace")
    value = {}
    match = re.search(r"\bos error (\d{1,4})\b", text)
    if match:
        number = int(match.group(1))
        value["errno"] = number
        value["errno_name"] = errno.errorcode.get(number, "UNKNOWN")
    elif "No space left on device" in text:
        value.update(errno=errno.ENOSPC, errno_name="ENOSPC")
    for phase in (
        "upload",
        "stage",
        "stop",
        "install",
        "reset",
        "preseed",
        "start",
        "convergence",
        "canary",
        "restart",
        "edge",
        "rollback",
    ):
        if re.search(r"\bphase=" + phase + r"\b", text, flags=re.I):
            value["native_phase"] = phase
            break
    for operation in (
        "write staged chunk",
        "read staged chunk",
        "preseed Inrou",
        "snapshot artifact",
        "copy artifact",
        "sync directory",
    ):
        if operation.lower() in text.lower():
            value["operation"] = operation
            break
    match = re.search(r"\bstaged chunk\s*(\d{1,10})\b", text, flags=re.I)
    if match:
        value["chunk"] = int(match.group(1))
    return value


def native_error(path):
    """Read a bounded diagnostic tail without exposing arbitrary diagnostic text."""
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
    try:
        before = os.fstat(fd)
        require(
            stat.S_ISREG(before.st_mode)
            and before.st_uid == os.getuid()
            and before.st_nlink == 1
            and stat.S_IMODE(before.st_mode) == 0o600,
            "unsafe private native diagnostic",
        )
        raw = os.pread(fd, 65536, max(0, before.st_size - 65536))
        require(
            identity(before) == identity(os.fstat(fd)) == identity(Path(path).lstat()),
            "native diagnostic changed after child exit",
        )
        return safe_native_error(raw)
    finally:
        os.close(fd)


def native_journal_progress(path):
    """Project only phase/cursor/counts; never emit nonce, signatures or failure text."""
    if path is None:
        return {}
    try:
        value = decode(public_record(path, owner=0, private=True, limit=1024 * 1024))
        phases = {
            "admitted",
            "preflight",
            "stage",
            "stop",
            "install",
            "reset",
            "preseed",
            "start",
            "edge_stage",
            "edge_cutover",
            "convergence",
            "canary",
            "restart_proof",
            "edge_verify",
            "seal",
            "cleanup",
            "cleanup_pending",
            "rolling_back",
            "rolled_back",
            "finishing",
            "completed",
        }
        require(
            value.get("schema") == "iroha.taira.public-reset.journal.v1"
            and value.get("phase") in phases
            and type(value.get("next_step")) is int
            and 0 <= value["next_step"] <= len(qualification_steps(value.get("qualification_scope")))
            and (value["phase"] != "preseed" or value["qualification_scope"] == "full_inrou")
            and isinstance(value.get("touched_validators"), list)
            and len(value["touched_validators"]) <= 4
            and type(value.get("edge_touched")) is bool,
            "unexpected native progress shape",
        )
        return {
            "native_phase": value["phase"],
            "next_step": value["next_step"],
            "touched_validator_count": len(value["touched_validators"]),
            "edge_touched": value["edge_touched"],
        }
    except (OSError, RetryError, ValueError, KeyError, TypeError):
        return {}


def run_native(argv, directory, *, phase, pass_fds=(), env=None, journal_path=None):
    """Submit one native command, preserve output, and report elapsed time every30s."""
    directory.mkdir(mode=0o700)
    started = time.monotonic()
    emit(phase, started, status="started", private_log=str(directory))
    with (
        (directory / "stdout").open("xb") as stdout,
        (directory / "stderr").open("xb") as stderr,
    ):
        os.fchmod(stdout.fileno(), 0o600)
        os.fchmod(stderr.fileno(), 0o600)
        process = subprocess.Popen(
            list(map(str, argv)),
            stdin=subprocess.DEVNULL,
            stdout=stdout,
            stderr=stderr,
            pass_fds=pass_fds,
            env=env,
        )
        while True:
            try:
                code = process.wait(timeout=PROGRESS_SECONDS)
                break
            except subprocess.TimeoutExpired:
                emit(
                    phase,
                    started,
                    status="running",
                    private_log=str(directory),
                    **native_journal_progress(
                        journal_path if phase == "apply" else None
                    ),
                )
        stdout.flush()
        os.fsync(stdout.fileno())
        stderr.flush()
        os.fsync(stderr.fileno())
    result = {
        "phase": phase,
        "exit_code": code,
        "elapsed_seconds": round(time.monotonic() - started, 3),
        "private_log": str(directory),
        "automatic_replay": False,
    }
    if code:
        result.update(native_error(directory / "stderr"))
    write_public(directory / "result.json", result)
    emit(
        phase,
        started,
        status="passed" if code == 0 else "failed",
        **{key: value for key, value in result.items() if key != "phase"},
    )
    require(
        code == 0, "native " + phase + " failed; inspect " + str(directory / "stderr")
    )
    return result


def qualification_steps(scope):
    """Exact first-release native journal sequence; never reinterpret old indices."""
    require(scope in ("core_testnet", "full_inrou"), "one explicit canonical qualification scope is required")
    return ("preflight", "stage", "stop", "install", "reset") + (("preseed",) if scope == "full_inrou" else ()) + ("start", "canary", "convergence", "edge_stage", "edge_cutover", "edge_verify", "seal", "cleanup")


def require_candidate_probe_inventory(inventory):
    """Reject obsolete or ambiguous public drafts before any retirement mutation."""
    require(inventory.get("qualification_scope") in ("core_testnet", "full_inrou"),
            "one explicit qualification scope is required")
    require("inrou_canary" in inventory and "inrou_stage_tree_sha256" in inventory,
            "explicit nullable Inrou scope fields are required")
    canary, stage_hash = inventory["inrou_canary"], inventory["inrou_stage_tree_sha256"]
    if inventory["qualification_scope"] == "core_testnet":
        require(canary is None and stage_hash is None, "core_testnet forbids Inrou inputs")
    else:
        require(isinstance(canary, dict) and isinstance(stage_hash, str)
                and re.fullmatch(r"[0-9a-f]{64}", stage_hash) is not None
                and canary.get("stage_tree_sha256") == stage_hash,
                "full_inrou requires its exact Inrou stage identity")
    operator_key = inventory.get("operator_public_key")
    # PublicKey Display uses a lowercase multihash prefix and uppercase payload.
    # Native admission performs the cryptographic key/config/custody joins.
    require(isinstance(operator_key, str)
            and re.fullmatch(r"ed0120[0-9A-F]{64}", operator_key) is not None,
            "one explicit canonical Ed25519 operator public key is required")
    clients = inventory.get("validator_clients")
    require(isinstance(clients, list) and len(clients) == 4,
            "four explicit validator candidate probe origins are required")
    origins = set()
    for index, client in enumerate(clients, 1):
        require(isinstance(client, dict)
                and client.get("slug") == f"taira-validator-{index}",
                "candidate probe clients must use the exact validator order")
        origin = client.get("probe_origin")
        match = (re.fullmatch(r"http://127\.0\.0\.1:([1-9][0-9]{0,4})/", origin)
                 if isinstance(origin, str) else None)
        # The native Url parser omits HTTP's default port; candidate inventory
        # requires the port to remain explicit in its canonical URL.
        require(match is not None and int(match[1]) <= 65535 and int(match[1]) != 80,
                "candidate probe origin requires an explicit IPv4 loopback socket")
        require(origin not in origins, "candidate probe sockets must be distinct")
        origins.add(origin)


def fresh_inventory(previous, attempt_id, nonce):
    """Project explicit topology intent only; native code derives every release pin."""
    require_candidate_probe_inventory(previous)
    require(re.fullmatch(r"retry-[0-9]{16,24}-[0-9a-f]{8}", attempt_id) is not None,
            "fresh generated attempt identity required")
    require(re.fullmatch("[0-9a-f]{32}", nonce) is not None
            and nonce != previous["authorization_nonce"], "fresh authorization nonce required")
    def project(value, fields):
        return {field: copy.deepcopy(value[field]) for field in fields}
    def host(value, fields):
        result = project(value, fields)
        result["artifacts"] = [project(row, ("role", "local_path", "remote_path"))
                               for row in value["artifacts"]]
        return result
    value = project(previous, ("qualification_scope", "previous_genesis_hash",
        "validator_clients", "canary_onboarding_request", "faucet_policy", "fee_intent",
        "cleanup", "timeouts"))
    value.update(schema="iroha.taira.public-reset.topology-intent.v1",
        deployment_id="taira-" + attempt_id, authorization_nonce=nonce,
        revision=project(previous["revision"], ("source_root", "source_manifest_path")),
        validators=[host(row, ("slug", "endpoint", "platform", "service_root", "state_root",
            "reset_guard", "systemd_unit", "initial_state")) for row in previous["validators"]],
        edge=host(previous["edge"], ("slug", "endpoint", "platform", "service_root", "state_root",
            "reset_guard", "nginx_config", "initial_state")))
    require(value["deployment_id"] != previous["deployment_id"], "deployment identity reused")
    return value






def validate_artifact_receipts(build, binary, source):
    """Admit already completed immutable preparation/transfer records, without rebuilding."""
    commit = build["commit"]
    require(
        re.fullmatch("[0-9a-f]{40}", commit) is not None
        and "exit_code" not in build
        and build["source_unchanged"] is True
        and build["toolchain_unchanged"] is True
        and build["target"] == "aarch64-unknown-linux-gnu"
        and build["profile"] == "release"
        and build["deployed"] is False
        and build["release_qualified"] is False,
        "successful maintained preparation required",
    )
    names = {"iroha", "iroha3d_taira", "sorafs-node", "kagami"}
    rows = {row["name"]: row for row in build["artifacts"]}
    require(
        len(build["artifacts"]) == len(binary["artifacts"]) == 4
        and set(rows) == names
        and {row["name"] for row in binary["artifacts"]} == names
        and binary["commit"] == commit
        and binary["all_hashes_verified"] is True
        and binary["activated"] is False,
        "completed exact binary transfer required",
    )
    for row in binary["artifacts"]:
        require(
            row["size"] == rows[row["name"]]["size"]
            and row["sha256"] == rows[row["name"]]["sha256"],
            "artifact transfer differs from preparation",
        )
    require(
        source["commit"] == commit
        and source["tree"] == build["tree"]
        and source["clean"] is True
        and source["signature_verified"] is True
        and source["object_inventory_verified"] is True
        and source["activated"] is False
        and source["runtime_files_transferred"] is False
        and source["history_included"] is False,
        "completed exact source transfer required",
    )
    return commit


def ssh_host_key_paths(argv, *, proxy=False):
    """Parse one fixed SSH route; no ambient config or arbitrary local command."""
    require(
        isinstance(argv, list)
        and len(argv) >= 4
        and argv[0] == "/usr/bin/ssh"
        and all(
            isinstance(arg, str) and not re.search(r"[\x00-\x1f\x7f]", arg)
            for arg in argv
        ),
        "invalid approved SSH invocation",
    )
    if not proxy:
        require(
            argv[-1] == "/usr/bin/python3 -I -", "fixed remote Python command required"
        )
        argv = argv[:-1]
    options, flags = {}, {}
    index = 1
    while index < len(argv) - 1:
        flag = argv[index]
        if flag == "-T":
            require(flag not in flags, "duplicate SSH route flag")
            flags[flag] = True
            index += 1
            continue
        require(
            flag in {"-F", "-i", "-o", "-W"} and index + 1 < len(argv) - 1,
            "unsupported SSH route argument",
        )
        argument = argv[index + 1]
        if flag == "-o":
            key, separator, value = argument.partition("=")
            key = key.lower()
            require(separator and key not in options, "duplicate or invalid SSH option")
            options[key] = value
        else:
            require(flag not in flags, "duplicate SSH route flag")
            flags[flag] = argument
        index += 2
    host = argv[-1]
    require(
        re.fullmatch(r"(?:[a-zA-Z0-9._-]+@)?[a-zA-Z0-9][a-zA-Z0-9.-]*", host),
        "invalid fixed SSH destination",
    )
    require(flags.get("-F") == "/dev/null", "ambient SSH config is forbidden")
    identity_path = flags.get("-i", "")
    require(
        identity_path.startswith("/") and not re.search(r"[\s%$`~]", identity_path),
        "explicit fixed SSH identity path required",
    )
    required = {
        "batchmode": "yes",
        "identitiesonly": "yes",
        "stricthostkeychecking": "yes",
        "forwardagent": "no",
        "clearallforwardings": "yes",
        "globalknownhostsfile": "/dev/null",
        "updatehostkeys": "no",
        "verifyhostkeydns": "no",
    }
    if not proxy:
        required["identityagent"] = "none"
    optional = {
        "identityagent": "none",
        "preferredauthentications": "publickey",
        "passwordauthentication": "no",
        "kbdinteractiveauthentication": "no",
        "checkhostip": "no",
        "connectionattempts": "1",
        "numberofpasswordprompts": "0",
        # Compress the byte stream before SSH encryption; payload pins stay exact.
        "compression": "yes",
    }
    require(
        set(options)
        <= set(required)
        | set(optional)
        | {"userknownhostsfile", "hostkeyalias", "connecttimeout", "proxycommand"},
        "unsupported SSH option",
    )
    for key, expected in required.items():
        require(options.get(key) == expected, "strict SSH option missing: " + key)
    for key, expected in optional.items():
        require(
            key not in options or options[key] == expected, "unsafe SSH option: " + key
        )
    if "connecttimeout" in options:
        require(
            re.fullmatch(r"[0-9]{1,2}", options["connecttimeout"])
            and 1 <= int(options["connecttimeout"]) <= 60,
            "bounded SSH connect timeout required",
        )
    if "hostkeyalias" in options:
        require(
            re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9._-]*", options["hostkeyalias"]),
            "invalid fixed SSH host-key alias",
        )
    host_keys = options.get("userknownhostsfile", "")
    require(
        host_keys.startswith("/")
        and not re.search(r"[\s%$`~]", host_keys)
        and str(Path(os.path.normpath(host_keys))) == host_keys
        and host_keys != identity_path,
        "one explicit public host-key file required",
    )
    paths = {host_keys}
    if proxy:
        require(
            "proxycommand" not in options
            and re.fullmatch(r"[a-zA-Z0-9.-]+:[0-9]{1,5}", flags.get("-W", "")),
            "proxy must be one fixed SSH forwarding hop",
        )
    else:
        require("-W" not in flags, "outer SSH forwarding is forbidden")
        if "proxycommand" in options:
            command = options["proxycommand"]
            require(
                not re.search(r"[;&|<>$`\\%]", command),
                "shell proxy commands are forbidden",
            )
            try:
                hop = shlex.split(command)
            except ValueError:
                raise RetryError("invalid fixed SSH proxy") from None
            paths |= ssh_host_key_paths(hop, proxy=True)
            require(
                hop[hop.index("-W") + 1] == host.rsplit("@", 1)[-1] + ":22",
                "proxy forwarding destination differs from the admitted guest",
            )
    require(
        "vultr" not in " ".join(argv).lower(),
        "banned infrastructure is not an operational input",
    )
    return paths


def validate_ssh(value):
    """Pin precisely the public host-key files used by the fixed SSH route."""
    require(
        set(value) == {"argv", "pins"}, "exact approved SSH route and pins required"
    )
    paths = ssh_host_key_paths(value["argv"])
    pins = value["pins"]
    require(isinstance(pins, list) and pins, "approved host-key evidence pins required")
    for pin in pins:
        require(
            isinstance(pin, dict)
            and set(pin) == {"path", "sha256"}
            and isinstance(pin["path"], str)
            and isinstance(pin["sha256"], str)
            and re.fullmatch("[0-9a-f]{64}", pin["sha256"]),
            "invalid SSH public evidence pin",
        )
    require(
        len(pins) == len(paths) and {pin["path"] for pin in pins} == paths,
        "SSH pins must match exactly the route's public host-key files",
    )
    for pin in pins:
        public_record(pin["path"], pin["sha256"])
    return value["argv"]


def validate_plan(plan):
    """The private operator plan contains public paths/receipts, never signing values."""
    require(
        set(plan)
        == {
            "schema",
            "preparation",
            "binary_transfer",
            "source_transfer",
            "guest_ssh",
            "backing_ssh",
            "backing_path",
            "guest",
        },
        "unexpected retry plan fields",
    )
    require(plan["schema"] == PLAN_SCHEMA, "unsupported retry plan schema")
    require(
        isinstance(plan["backing_path"], str)
        and plan["backing_path"].startswith("/")
        and str(Path(os.path.normpath(plan["backing_path"]))) == plan["backing_path"],
        "explicit approved backing directory required",
    )
    guest_keys = {
        "runtime_root",
        "previous_inventory",
        "source_manifest",
        "trusted_public_key",
        "signing_key",
        "ssh_identity",
        "guard_support",
        "unit_renderer",
        "local_node",
        "expected_mac",
        "retired_public_imports",
    }
    require(set(plan["guest"]) == guest_keys,
            "unexpected guest runtime plan fields")
    validate_retired_public_imports(plan["guest"]["retired_public_imports"])
    for key in guest_keys - {
        "guard_support",
        "unit_renderer",
        "local_node",
        "capacity_plan",
        "expected_mac",
        "retired_public_imports",
    }:
        value = plan["guest"][key]
        require(
            isinstance(value, str)
            and value.startswith("/")
            and Path(value) == Path(os.path.normpath(value)),
            "absolute guest path required: " + key,
        )
    for key in ("guard_support", "unit_renderer", "local_node"):
        reference = plan["guest"][key]
        require(
            set(reference) == {"path", "sha256"}
            and reference["path"].startswith("/")
            and re.fullmatch("[0-9a-f]{64}", reference["sha256"]),
            "pinned public helper required",
        )
    require(
        re.fullmatch(r"(?:[0-9a-f]{2}:){5}[0-9a-f]{2}", plan["guest"]["expected_mac"]),
        "exact approved guest MAC required",
    )
    records = {}
    for name in ("preparation", "binary_transfer", "source_transfer"):
        reference = plan[name]
        require(
            set(reference) == {"path", "sha256"}
            and re.fullmatch("[0-9a-f]{64}", reference["sha256"]),
            "actual receipt path and digest required",
        )
        records[name] = decode(public_record(reference["path"], reference["sha256"]))
    require(
        records["source_transfer"]["result_sha256"] == plan["preparation"]["sha256"],
        "source transfer preparation binding differs",
    )
    commit = validate_artifact_receipts(
        records["preparation"], records["binary_transfer"], records["source_transfer"]
    )
    validate_ssh(plan["guest_ssh"])
    validate_ssh(plan["backing_ssh"])
    return commit, records


# Retire custody and evidence
RETIRE_WORK = None
RETIRE_UNIT_PATHS = None
RETIRE_TRUST_HASH = None
RETIRE_TERMINAL = None
RETIRE_SUPPORT_SHA = None
RETIRE_SUPPORT = None
RETIRE_RUNTIME = None
RETIRE_RETAINED_UNITS = None
RETIRE_RETAINED_DEPLOYMENT = None
RETIRE_NGINX_UNIT_HASH = None
RETIRE_INVENTORY_PATH = None
RETIRE_DISPATCHER = None
RETIRE_CONTROL = None
RETIRE_COMMIT = None
RETIRE_CLI_SHA = None
RETIRE_BINS = None
RETIRE_BINARY_MANIFEST = None
RETIRE_PUBLIC_IMPORTS = ()
RETIRE_PROTECTED_INPUTS = ()
RETIRE_DEPLOYMENT_STATE = Path('/var/lib/taira-deployment')
RETIRE_WORKER_STATE = Path('/var/lib/taira-epoch-supervisor')
RETIRE_WORKER_UNIT = Path('/etc/systemd/system/iroha-taira-epoch-supervisor.service')


class _retire_RebindError(Exception):
    pass


def _retire_need(ok, label):
    if not ok:
        raise _retire_RebindError(label)


def _retire_digest(data):
    return hashlib.sha256(data).hexdigest()


def _retire_canonical(value):
    return (json.dumps(value, indent=2, ensure_ascii=True) + "\n").encode("ascii")


def _retire_load_support():
    before = RETIRE_SUPPORT.lstat()
    _retire_need(
        stat.S_ISREG(before.st_mode)
        and before.st_uid == 0
        and (before.st_nlink == 1)
        and (stat.S_IMODE(before.st_mode) == 0o600),
        "support helper custody mismatch",
    )
    for ancestor in RETIRE_SUPPORT.parents:
        m = ancestor.lstat()
        _retire_need(
            stat.S_ISDIR(m.st_mode) and m.st_uid == 0 and (not m.st_mode & 18),
            "support helper ancestor mismatch",
        )
    with os.fdopen(
        os.open(RETIRE_SUPPORT, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC), "rb"
    ) as f:
        data = f.read(65537)
        _retire_need(
            len(data) <= 65536 and _retire_digest(data) == RETIRE_SUPPORT_SHA,
            "support helper hash mismatch",
        )
        fields = (
            "st_dev",
            "st_ino",
            "st_mode",
            "st_uid",
            "st_gid",
            "st_nlink",
            "st_size",
            "st_mtime_ns",
            "st_ctime_ns",
        )
        _retire_need(
            all(
                (
                    getattr(os.fstat(f.fileno()), x) == getattr(before, x)
                    and getattr(RETIRE_SUPPORT.lstat(), x) == getattr(before, x)
                    for x in fields
                )
            ),
            "support helper changed",
        )
    module = {"__name__": "owner_guard_support", "__file__": str(RETIRE_SUPPORT)}
    exec(compile(data, str(RETIRE_SUPPORT), "exec"), module)
    return module


def _retire_rename_atomic(source, target, exchange=False):
    libc = ctypes.CDLL(None, use_errno=True)
    call = libc.renameat2
    call.argtypes = [
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_uint,
    ]
    call.restype = ctypes.c_int
    if call(-100, os.fsencode(source), -100, os.fsencode(target), 2 if exchange else 1):
        err = ctypes.get_errno()
        raise OSError(err, os.strerror(err))


def _retire_read_public(g, path, expected=None, limit=65536):
    pinned = g["PinnedFile"](path, private=True)
    try:
        _retire_need(
            os.fstat(pinned.fd).st_size <= limit, "public record exceeds bound"
        )
        data = os.pread(pinned.fd, limit + 1, 0)
        pinned.verify()
        if expected is not None:
            _retire_need(
                _retire_digest(data) == expected,
                "public record hash mismatch: " + str(path),
            )
        return data
    finally:
        pinned.close()


def _retire_binary(g, path, expected):
    pinned = g["PinnedFile"](path, executable=True)
    try:
        _retire_need(
            stat.S_IMODE(os.fstat(pinned.fd).st_mode) == 0o755, "CLI mode is not 0755"
        )
        _retire_need(pinned.digest() == expected, "CLI hash mismatch")
        g["arm64_elf"](os.pread(pinned.fd, 64, 0))
        return pinned
    except BaseException:
        pinned.close()
        raise


def _retire_systemd_empty(g):
    names = [f"iroha3d-taira-validator-{i}.service" for i in range(1, 5)] + [
        "nginx.service"
    ]
    fields = (
        "LoadState",
        "ActiveState",
        "SubState",
        "MainPID",
        "ControlPID",
        "FragmentPath",
        "DropInPaths",
        "Job",
    )
    for name in names:
        r = subprocess.run(
            [
                "/usr/bin/systemctl",
                "show",
                "--all",
                *[f"--property={x}" for x in fields],
                name,
            ],
            capture_output=True,
            timeout=15,
            env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"},
        )
        _retire_need(
            r.returncode in (0, 4) and len(r.stdout) <= 16384,
            "cannot attest inactive unit",
        )
        lines = r.stdout.decode("utf-8").splitlines()
        pairs = [line.split("=", 1) for line in lines]
        _retire_need(
            all((len(p) == 2 for p in pairs)) and len(pairs) == len(fields),
            "unit evidence malformed",
        )
        values = dict(pairs)
        _retire_need(set(values) == set(fields), "unit evidence fields drifted")
        _retire_need(
            values["ActiveState"] == "inactive"
            and values["SubState"] == "dead"
            and (values["MainPID"] == "0")
            and (values["ControlPID"] == "0")
            and (values["DropInPaths"] == "")
            and (values["Job"] == ""),
            "unit is active or has pending work",
        )
        if name == "nginx.service":
            _retire_need(
                values["LoadState"] == "loaded"
                and values["FragmentPath"] == "/etc/systemd/system/nginx.service",
                "nginx unit differs",
            )
            unit = g["PinnedFile"](Path(values["FragmentPath"]))
            try:
                _retire_need(
                    unit.digest() == RETIRE_NGINX_UNIT_HASH, "nginx unit hash differs"
                )
            finally:
                unit.close()
        else:
            expected = Path("/etc/systemd/system") / name
            _retire_need(
                values["LoadState"] == "loaded"
                and values["FragmentPath"] == str(expected),
                "retained inactive validator unit is not exactly installed",
            )
            installed = g["PinnedFile"](expected)
            prepared = g["PinnedFile"](RETIRE_UNIT_PATHS[name], private=True)
            try:
                _retire_need(
                    installed.digest() == RETIRE_RETAINED_UNITS[name]
                    and prepared.digest() == RETIRE_RETAINED_UNITS[name],
                    "retained validator unit bytes differ from the retained native signer paths",
                )
            finally:
                installed.close()
                prepared.close()
            for directory in (
                "/etc/systemd/system",
                "/run/systemd/system",
                "/usr/lib/systemd/system",
            ):
                if directory != "/etc/systemd/system":
                    g["absent"](Path(directory) / name)
                g["absent"](Path(directory) / (name + ".d"))


def _retire_no_running_inode(inode):
    examined = 0
    with os.scandir("/proc") as entries:
        for entry in entries:
            if not entry.name.isascii() or not entry.name.isdigit():
                continue
            examined += 1
            _retire_need(examined <= 65536, "process census exceeds bound")
            try:
                m = os.stat(Path(entry.path) / "exe")
            except FileNotFoundError:
                continue
            _retire_need(
                (m.st_dev, m.st_ino) != inode,
                "an old/new fixed dispatcher process is still running",
            )


def _retire_mount_rows(raw):
    """Decode only bounded public mount identity/path fields, never mounted bytes."""
    _retire_need(0 < len(raw) <= 4 * 1024 * 1024, "namespace evidence exceeds bound")
    rows = []
    for line in raw.decode().splitlines():
        fields = line.split()
        _retire_need(len(fields) >= 10 and "-" in fields[6:]
                     and re.fullmatch(r"[0-9]+:[0-9]+", fields[2]),
                     "mount identity evidence malformed")
        major, minor = map(int, fields[2].split(":"))
        paths = [Path(re.sub(r"\\([0-7]{3})", lambda match: chr(int(match[1], 8)), value))
                 for value in fields[3:5]]
        _retire_need(all(path.is_absolute() and str(path) == os.path.normpath(path)
                         for path in paths), "mount path evidence malformed")
        rows.append((os.makedev(major, minor), *paths))
        _retire_need(len(rows) <= 65536, "mount census exceeds bound")
    return rows


def _retire_live_references(roots, *, file_identities=(), own_fds=None, proc_root=Path("/proc")):
    """Observe paths, admitted inodes and mount aliases; never argv/env or payloads.

    Directory roots are checked for path references and mount aliases. Callers
    with a closed file census also pass its identities to catch aliases after
    rename/unlink. Explicit own_fds includes the observer in the census and
    admits only those custody descriptors; native callers may exclude self.
    """
    roots = tuple(Path(root) for root in roots)
    _retire_need(len(roots) <= 65536 and all(root.is_absolute() for root in roots),
                 "live reference roots exceed bounds or are not absolute")
    _retire_need(len(file_identities) <= 65536, "live inode census exceeds bound")
    selected, devices = {}, {}
    for row in file_identities:
        stamp, path = row["identity"], Path(row["path"])
        _retire_need(path.is_absolute() and len(stamp) == 9
                     and all(type(stamp[i]) is int and stamp[i] >= 0 for i in (0, 1))
                     and stat.S_ISREG(stamp[2]), "selected file identity malformed")
        _retire_need(any(path.is_relative_to(root) for root in roots),
                     "selected file identity escaped observed roots")
        selected[(stamp[0], stamp[1])] = str(path)
        if path in roots:
            devices[path] = stamp[0]
    for root in roots:
        try:
            info = root.lstat()
        except FileNotFoundError:
            # Missing original/quarantine names still have a filesystem scope.
            parent = root.parent
            while not parent.exists():
                _retire_need(parent != parent.parent, "live reference filesystem unavailable")
                parent = parent.parent
            devices.setdefault(root, parent.stat().st_dev)
        else:
            devices[root] = info.st_dev
            selected[(info.st_dev, info.st_ino)] = str(root)
    if own_fds is not None:
        _retire_need(len(own_fds) <= 65536 and all(type(fd) is int and fd >= 0 for fd in own_fds),
                     "own custody descriptor census malformed")
    admitted_fds = set(own_fds or ())
    examined = fds_examined = 0
    namespaces, views, references = set(), set(), []
    full_namespaces, empty_views = set(), []

    def match(target):
        target = target.removesuffix(" (deleted)")
        if not target.startswith("/"):
            return None
        path = Path(target)
        return next((str(root) for root in roots if path.is_relative_to(root)), None)

    def observe(pid, kind, target=None, inode=None, fd=None):
        root = selected.get(inode) or (match(target) if target is not None else None)
        if root is not None and not (pid == os.getpid() and kind == "fd" and fd in admitted_fds):
            _retire_need(len(references) < 256, "live reference report bound exceeded")
            references.append({"pid": pid, "kind": kind, "target_root": root})

    def read_bounded(path):
        with path.open("rb") as stream:
            raw = stream.read(4 * 1024 * 1024 + 1)
        _retire_need(len(raw) <= 4 * 1024 * 1024, "namespace evidence exceeds bound")
        return raw

    local_mounts = _retire_mount_rows(read_bounded(proc_root / "self/mountinfo"))
    if os.readlink(proc_root / "self/root") == "/":
        full_namespaces.add(os.readlink(proc_root / "self/ns/mnt"))
    scopes = []
    for path, device in devices.items():
        candidates = [row for row in local_mounts if row[0] == device and path.is_relative_to(row[2])]
        _retire_need(candidates, "selected filesystem missing from mount census")
        _, mount_root, mountpoint = max(candidates, key=lambda row: len(row[2].parts))
        scopes.append((device, mount_root / path.relative_to(mountpoint), path))

    def observe_mounts(pid, rows):
        for device, mount_root, mountpoint in rows:
            for selected_device, selected_root, path in scopes:
                if device != selected_device:
                    continue
                if selected_root.is_relative_to(mount_root):
                    alias = mountpoint / selected_root.relative_to(mount_root)
                    expected = path
                elif mount_root.is_relative_to(selected_root):
                    alias = mountpoint
                    expected = path / mount_root.relative_to(selected_root)
                else:
                    continue
                if alias != expected:
                    _retire_need(len(references) < 256, "live reference report bound exceeded")
                    references.append({"pid": pid, "kind": "mount_alias", "target_root": str(path)})

    observe_mounts(os.getpid(), local_mounts)
    with os.scandir(proc_root) as entries:
        processes = sorted((e.name for e in entries if e.name.isascii() and e.name.isdigit()), key=int)
    for name in processes:
        pid = int(name)
        if pid == os.getpid() and own_fds is None:
            continue
        examined += 1
        _retire_need(examined <= 65536, "process census exceeds bound")
        proc = proc_root / name
        process_root = None
        for leaf in ("exe", "cwd", "root"):
            try:
                target = os.readlink(proc / leaf)
                info = os.stat(proc / leaf)
                observe(pid, leaf, target, (info.st_dev, info.st_ino))
                if leaf == "root":
                    process_root = target
            except FileNotFoundError:
                pass
        try:
            with os.scandir(proc / "fd") as entries:
                for index, entry in enumerate(entries):
                    _retire_need(index < 65536, "descriptor census exceeds bound")
                    fds_examined += 1
                    _retire_need(fds_examined <= 1048576, "aggregate descriptor census exceeds bound")
                    try:
                        target = os.readlink(entry.path)
                        info = os.stat(entry.path)
                        observe(pid, "fd", target, (info.st_dev, info.st_ino), int(entry.name))
                    except FileNotFoundError:
                        pass
        except FileNotFoundError:
            continue
        try:
            raw = read_bounded(proc / "maps")
        except FileNotFoundError:
            continue
        for line in raw.decode().splitlines():
            fields = line.split(None, 5)
            _retire_need(len(fields) >= 5 and re.fullmatch(r"[0-9a-fA-F]+:[0-9a-fA-F]+", fields[3])
                         and fields[4].isascii() and fields[4].isdigit(), "mapping identity evidence malformed")
            major, minor = (int(part, 16) for part in fields[3].split(":"))
            target = re.sub(r"\\([0-7]{3})", lambda match: chr(int(match[1], 8)), fields[5]) if len(fields) == 6 else None
            observe(pid, "maps", target, (os.makedev(major, minor), int(fields[4])))
        try:
            namespace = os.readlink(proc / "ns/mnt")
            view = (namespace, process_root)
            if view in views:
                continue
            raw_mounts = read_bounded(proc / "mountinfo")
            if not raw_mounts:
                # A chroot with no mountpoints below its root has an empty
                # view. Require the same namespace's full-root view elsewhere;
                # kernel threads or tasks that exited retain no such view.
                if process_root is not None and os.path.lexists(proc / "root"):
                    empty_views.append((namespace, proc))
                continue
            rows = _retire_mount_rows(raw_mounts)
            if process_root == "/":
                full_namespaces.add(namespace)
        except FileNotFoundError:
            continue
        observe_mounts(pid, rows)
        namespaces.add(namespace)
        views.add(view)
    _retire_need(all(namespace in full_namespaces or not os.path.lexists(proc / "root")
                     for namespace, proc in empty_views),
                 "empty chroot mount view has no observed full namespace")
    return {"passed": not references, "processes_examined": examined,
            "descriptors_examined": fds_examined, "mount_namespaces_examined": len(namespaces),
            "mount_views_examined": len(views), "references": references,
            "argv_or_environment_read": False}


RETIRE_SLUGS = tuple((f"taira-validator-{i}" for i in range(1, 5))) + ("taira-edge",)


def _retire_root_identity(path):
    m = path.lstat()
    _retire_need(
        stat.S_ISDIR(m.st_mode)
        and m.st_uid == 0
        and (stat.S_IMODE(m.st_mode) == 0o700),
        "private directory custody differs: " + str(path),
    )
    return {
        "device": m.st_dev,
        "inode": m.st_ino,
        "mode": stat.S_IMODE(m.st_mode),
        "uid": m.st_uid,
        "gid": m.st_gid,
    }


def _retire_validate_terminal(inventory, value, *, expected_commit=None, expected_deployment=None):
    # Native rollback failures are append-only history. A successful resume
    # retains them; the terminal state and completed counters prove recovery.
    history = value.get("rollback_failures")
    history_valid = isinstance(history, list) and len(history) <= 5 and all(
        isinstance(entry, str) and re.fullmatch(
            r"phase=rollback;target=(?:edge|taira-validator-[1-4]);"
            r"class=operation_failed;sha256=[0-9a-f]{64}", entry
        ) is not None for entry in history
    )
    _retire_need(
        inventory["revision"]["commit"] == (RETIRE_COMMIT if expected_commit is None else expected_commit)
        and inventory["deployment_id"] == (RETIRE_RETAINED_DEPLOYMENT if expected_deployment is None else expected_deployment)
        and value.get("deployment_id") == inventory["deployment_id"]
        and value.get("status") == value.get("phase") == "rolled_back"
        and type(value.get("next_step")) is int
        and value.get("qualification_scope") == inventory.get("qualification_scope")
        and qualification_steps(inventory.get("qualification_scope")).index("reset") + 1 <= value["next_step"] <= len(qualification_steps(inventory.get("qualification_scope"))) - 3
        and value.get("recovery_intent") is None
        and value.get("touched_validators") == list(RETIRE_SLUGS[:-1])
        and type(value.get("edge_touched")) is bool
        and value.get("edge_rollback_complete") is value["edge_touched"]
        and value.get("rollback_next_validator") == 4
        and history_valid,
        "requires complete native rollback of all touched validators and edge",
    )


def _retire_validate_progress(value, context):
    expected = list(RETIRE_SLUGS if context["edge_touched"] else RETIRE_SLUGS[:-1])
    _retire_need(
        value.get("schema") == "iroha.taira.public-reset.host-progress.v1"
        and value.get("inventory_sha256") == context["inventory_sha256"]
        and value.get("authorization_sha256") == context["authorization_sha256"]
        and value.get("authorization_nonce") == context["nonce"]
        and value.get("prepared_action") is None
        and value.get("rolling_back") is True
        and value.get("sealed") is False
        and sorted(value.get("touched_hosts", [])) == sorted(expected)
        and sorted(value.get("rolled_back_hosts", [])) == sorted(expected),
        "physical host progress is not this complete rollback",
    )


def _retire_retained_context(g):
    raw = _retire_read_public(g, RETIRE_INVENTORY_PATH, limit=8 * 1024 * 1024)
    inventory = json.loads(raw)
    hosts = inventory["validators"] + [inventory["edge"]]
    _retire_need(
        [host["slug"] for host in hosts] == list(RETIRE_SLUGS),
        "retained host topology differs",
    )
    _retire_need(
        all(
            (
                host["initial_state"] == {"state": "vacant", "value": None}
                for host in hosts
            )
        ),
        "retained topology was not vacant",
    )
    terminal_raw = _retire_read_public(g, RETIRE_TERMINAL)
    value = json.loads(terminal_raw)
    _retire_validate_terminal(inventory, value)
    _retire_need(
        value["inventory_sha256"] == _retire_digest(raw),
        "terminal inventory binding differs",
    )
    nonce = inventory["authorization_nonce"]
    _retire_need(re.fullmatch("[0-9a-f]{32}", nonce), "retained nonce invalid")
    _retire_need(
        value["authorization_nonce"] == nonce, "terminal nonce binding differs"
    )
    _retire_need(
        re.fullmatch("[0-9a-f]{64}", value["authorization_sha256"])
        and RETIRE_TERMINAL.name == value["authorization_sha256"] + ".json",
        "terminal authorization binding differs",
    )
    identity = {host["endpoint"]["host_identity_sha256"] for host in hosts}
    _retire_need(
        len(identity) == 1 and re.fullmatch("[0-9a-f]{64}", next(iter(identity))),
        "retirement requires the existing single physical guest",
    )
    if RETIRE_WORK.exists():
        g["check_directory"](RETIRE_WORK, 0o700)
    control = (
        RETIRE_WORK / "retired-control"
        if (RETIRE_WORK / "retired-control").exists()
        else RETIRE_CONTROL
    )
    context = {
        "commit": RETIRE_COMMIT,
        "dispatcher_sha256": RETIRE_CLI_SHA,
        "nonce": nonce,
        "authorization_sha256": value["authorization_sha256"],
        "retained_deployment_id": inventory["deployment_id"],
        "inventory_sha256": _retire_digest(raw),
        "terminal_path": str(RETIRE_TERMINAL),
        "terminal_sha256": _retire_digest(terminal_raw),
        "coordination_relative": str(Path("hosts") / next(iter(identity))),
        "old_dispatcher_sha256": RETIRE_CLI_SHA,
        "states": {},
        "uploads": [],
        "guards": [],
    }
    context["edge_touched"] = value["edge_touched"]
    for host in hosts:
        slug = host["slug"]
        service, state, _ = g["role_paths"](slug)
        _retire_need(
            host["service_root"] == str(service)
            and host["state_root"] == str(state)
            and (host["reset_guard"] == str(RETIRE_CONTROL / slug)),
            "retained role paths escaped fixed target",
        )
        guard_raw = _retire_read_public(g, control / slug / "guard.json")
        _retire_need(
            _retire_digest(guard_raw) == host["endpoint"]["upload_guard_sha256"]
            and guard_raw
            == _retire_canonical(
                g["guard_record"](slug, RETIRE_TRUST_HASH, RETIRE_CLI_SHA)
            ),
            "retained host guard differs from admitted inventory",
        )
        context["guards"].append(
            {"slug": slug, "upload_guard_sha256": _retire_digest(guard_raw)}
        )
        state_meta = _retire_root_identity(state)
        if slug != "taira-edge":
            intent = json.loads(
                _retire_read_public(
                    g, control / slug / "rollback" / nonce / "state-move.intent.json"
                )
            )
            _retire_need(
                intent.get("host_slug") == slug
                and intent.get("inventory_sha256") == context["inventory_sha256"]
                and (intent.get("authorization_nonce") == nonce)
                and (intent.get("state_root") == str(state))
                and (intent.get("prior_device") == state_meta["device"])
                and (intent.get("prior_inode") == state_meta["inode"]),
                "restored state root differs from the native pre-mutation intent",
            )
        context["states"][slug] = state_meta
        source = service / ".public-reset-upload-v1" / nonce
        archive = RETIRE_WORK / "uploads" / slug
        if source.exists() or archive.exists():
            _retire_need(
                (slug != "taira-edge" or context["edge_touched"])
                and source.exists() != archive.exists(),
                "upload location is ambiguous or unexpected",
            )
            location = source if source.exists() else archive
            marker = json.loads(
                _retire_read_public(g, location / ".public-reset-generated-v1.json")
            )
            _retire_need(
                marker.get("host_slug") == slug
                and marker.get("inventory_sha256") == context["inventory_sha256"]
                and (marker.get("authorization_nonce") == nonce)
                and (marker.get("revision") == RETIRE_COMMIT),
                "upload archive is not generated by this failed attempt",
            )
            context["uploads"].append(
                {
                    "slug": slug,
                    "source": str(source),
                    "archive": str(archive),
                    "identity": _retire_root_identity(location),
                }
            )
    expected_uploads = list(
        RETIRE_SLUGS if context["edge_touched"] else RETIRE_SLUGS[:-1]
    )
    _retire_need(
        [row["slug"] for row in context["uploads"]] == expected_uploads,
        "all staged validator and touched edge uploads must be retained",
    )
    return context


def _retire_check_guards(g, root, expected_cli_sha):
    g["check_directory"](root, 0o700)
    _retire_need(
        {p.name for p in root.iterdir()} == set(RETIRE_SLUGS),
        "new guard root must contain only five roles",
    )
    for slug in RETIRE_SLUGS:
        g["check_directory"](root / slug, 0o700)
        _retire_need(
            {p.name for p in (root / slug).iterdir()} == {"guard.json"},
            "new guard has unexpected control state",
        )
        _retire_need(
            _retire_read_public(g, root / slug / "guard.json")
            == _retire_canonical(
                g["guard_record"](slug, RETIRE_TRUST_HASH, expected_cli_sha)
            ),
            "new guard binding differs",
        )


def _retire_deployment_lock():
    """Join the existing native lifecycle lock; never recreate lost authority."""
    root = direct(RETIRE_DEPLOYMENT_STATE)
    root_info = root.lstat()
    _retire_need(stat.S_ISDIR(root_info.st_mode) and root_info.st_uid == 0
                 and root_info.st_gid == 0 and stat.S_IMODE(root_info.st_mode) == 0o700,
                 "deployment state root custody differs")
    for parent in root.parents:
        info = parent.lstat()
        _retire_need(stat.S_ISDIR(info.st_mode) and info.st_uid == 0
                     and not info.st_mode & 0o022, "deployment lock ancestor custody differs")
    path = root / ".deployment.lock"
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
    try:
        before = os.fstat(fd)
        _retire_need(stat.S_ISREG(before.st_mode) and before.st_uid == 0
                     and before.st_gid == 0 and before.st_nlink == 1
                     and stat.S_IMODE(before.st_mode) == 0o600 and before.st_size == 0,
                     "deployment lock custody differs")
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        _retire_need(identity(path.lstat()) == identity(before)
                     and identity(os.fstat(fd)) == identity(before)
                     and identity(root.lstat()) == identity(root_info),
                     "deployment lock changed during acquisition")
        _retire_need(not os.path.lexists(RETIRE_WORKER_STATE)
                     and not os.path.lexists(RETIRE_WORKER_UNIT),
                     "retired epoch worker must be removed before retirement")
        _retire_need(not os.path.lexists(root / ".reset-owner.json"),
                     "active reset owner forbids retirement")
        return fd
    except BaseException:
        os.close(fd)
        raise


@contextmanager
def _retire_locks(g, context):
    opened = []
    try:
        control = (
            RETIRE_WORK / "retired-control"
            if (RETIRE_WORK / "retired-control").exists()
            else RETIRE_CONTROL
        )
        for path in (
            RETIRE_RUNTIME / "journal-v1/public-reset.lock",
            control / context["coordination_relative"] / "action.lock",
        ):
            fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
            opened.append(fd)
            g["inspect_file"](os.fstat(fd), private=True, size=0)
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        # Native reset order is coordinator -> host action -> deployment.
        # Rollback already released its durable owner; an updater can otherwise
        # enter while retirement archives control and prunes failed artifacts.
        opened.append(_retire_deployment_lock())
        yield
    finally:
        for fd in reversed(opened):
            os.close(fd)


def _retire_retained_state(g, context):
    _retire_need(
        _retire_digest(_retire_read_public(g, RETIRE_TERMINAL))
        == context["terminal_sha256"],
        "immutable terminal changed",
    )
    g["absent"](
        RETIRE_RUNTIME
        / "journal-v1"
        / (context["retained_deployment_id"] + ".journal.json")
    )
    _retire_systemd_empty(g)
    control = (
        RETIRE_WORK / "retired-control"
        if (RETIRE_WORK / "retired-control").exists()
        else RETIRE_CONTROL
    )
    coordination = control / context["coordination_relative"]
    lease = json.loads(_retire_read_public(g, coordination / "lease.json"))
    _retire_need(
        lease.get("schema") == "iroha.taira.public-reset.host-lease.v1"
        and lease.get("inventory_sha256") == context["inventory_sha256"]
        and (
            lease.get("authorization_semantic_sha256")
            == context["authorization_sha256"]
        )
        and (lease.get("authorization_nonce") == context["nonce"]),
        "native lease identity differs",
    )
    _retire_validate_progress(
        json.loads(_retire_read_public(g, coordination / "progress.json")), context
    )
    for name in (
        "progress.successor.json",
        ".progress.json.next",
        ".progress.successor.json.next",
    ):
        g["absent"](coordination / name)
    if control == RETIRE_WORK / "retired-control":
        admission = json.loads(
            _retire_read_public(g, RETIRE_WORK / "03-archive-control.json")
        )
        _retire_need(
            _retire_root_identity(control) == admission["identity"],
            "retained control archive inode changed",
        )
    roots = [
        RETIRE_CONTROL,
        RETIRE_WORK / "retired-control",
        RETIRE_WORK / "candidate-control",
        RETIRE_WORK / "uploads",
        RETIRE_BINS.parent,
        RETIRE_INVENTORY_PATH.parent,
    ]
    for slug in RETIRE_SLUGS:
        service, state, _ = g["role_paths"](slug)
        g["check_directory"](service)
        _retire_need(
            {p.name for p in service.iterdir()}
            == {"releases", ".public-reset-upload-v1"},
            "service root is not vacant",
        )
        g["check_directory"](service / "releases", empty=True)
        g["check_directory"](state, 0o700, empty=True)
        _retire_need(
            _retire_root_identity(state) == context["states"][slug],
            "restored state root identity changed",
        )
        roots.extend((service, state))
    for name in (
        "taira.conf",
        ".taira.conf.public-reset.next",
        ".taira.conf.public-reset-rollback.next",
    ):
        g["absent"](g["NGINX"] / name)
    _retire_need(
        _retire_live_references(roots)["passed"],
        "target/control/archive has live process references",
    )
    for row in context["uploads"]:
        source = Path(row["source"])
        archive = Path(row["archive"])
        _retire_need(
            source.exists() != archive.exists(),
            "retained upload is missing or duplicated",
        )
        _retire_need(
            _retire_root_identity(source if source.exists() else archive)
            == row["identity"],
            "retained upload inode changed",
        )
        _retire_need(
            {p.name for p in source.parent.iterdir()}
            == ({context["nonce"]} if source.exists() else set()),
            "unknown upload occupant",
        )
    service, _, _ = g["role_paths"]("taira-edge")
    if not context["edge_touched"]:
        g["check_directory"](service / ".public-reset-upload-v1", 0o700, empty=True)


def _retire_event(g, name, value):
    path = RETIRE_WORK / (name + ".json")
    data = _retire_canonical(value)
    if path.exists():
        _retire_need(
            _retire_read_public(g, path, limit=8 * 1024 * 1024) == data,
            "existing retirement event differs",
        )
    else:
        g["fresh_write"](path, data, 0o600)
    g["sync_directory"](RETIRE_WORK)


def _retire_move(g, source, target):
    _retire_need(
        source.parent.stat().st_dev == target.parent.stat().st_dev,
        "archive must stay on same filesystem",
    )
    _retire_rename_atomic(source, target)
    g["sync_directory"](source.parent)
    g["sync_directory"](target.parent)


def _retire_context_from_retained(g, args):
    _retire_need(
        isinstance(args.expected_commit, str)
        and re.fullmatch("[0-9a-f]{40}", args.expected_commit),
        "explicit admitted admitted artifact commit required",
    )
    _retire_need(
        isinstance(args.new_cli_sha256, str)
        and re.fullmatch("[0-9a-f]{64}", args.new_cli_sha256),
        "explicit admitted admitted artifact CLI digest required",
    )
    manifest = json.loads(_retire_read_public(g, RETIRE_BINARY_MANIFEST))
    _retire_need(
        set(manifest)
        == {"commit", "destination", "artifacts", "all_hashes_verified", "activated"}
        and manifest["commit"] == args.expected_commit
        and (manifest["destination"] == str(RETIRE_BINS))
        and (manifest["all_hashes_verified"] is True)
        and (manifest["activated"] is False),
        "actual inactive admitted artifact transfer differs",
    )
    artifacts = manifest["artifacts"]
    _retire_need(
        len(artifacts) == 4
        and {row["name"] for row in artifacts}
        == {"iroha", "iroha3d_taira", "sorafs-node", "kagami"},
        "actual admitted artifact must contain all four binaries",
    )
    row = next((row for row in artifacts if row["name"] == "iroha"))
    _retire_need(
        row["sha256"] == args.new_cli_sha256
        and type(row["size"]) is int
        and (row["size"] > 0),
        "admitted artifact CLI manifest binding differs",
    )
    new = _retire_binary(g, RETIRE_BINS / "iroha", args.new_cli_sha256)
    try:
        _retire_need(
            os.fstat(new.fd).st_size == row["size"],
            "admitted artifact CLI size differs",
        )
    finally:
        new.close()
    context = _retire_retained_context(g)
    context.update(
        expected_commit=args.expected_commit, new_dispatcher_sha256=args.new_cli_sha256
    )
    return context


# Closed-attempt public payload reclamation. These helpers run only while the
# existing native retirement locks are held, after result.json is published.
RETIRE_PRUNE_MAX_FILES = 65536
RETIRE_PRUNE_MAX_RECEIPT_BYTES = 32 * 1024 * 1024


def _retire_prune_info(path, *, directory=False):
    path = direct(path)
    for parent in path.parents:
        info = parent.lstat()
        _retire_need(stat.S_ISDIR(info.st_mode) and info.st_uid in (0, os.geteuid())
                     and not info.st_mode & 0o022, "prune ancestor custody differs")
    info = path.lstat()
    _retire_need(info.st_uid == os.geteuid() and info.st_gid == os.getegid()
                 and not info.st_mode & 0o022, "prune path custody differs")
    _retire_need(stat.S_ISDIR(info.st_mode) if directory else
                 stat.S_ISREG(info.st_mode) and info.st_nlink == 1,
                 "prune path type or links differ")
    return info


def _retire_prune_marker(g, path, context, slug, kind):
    value = json.loads(_retire_read_public(g, path / ".public-reset-generated-v1.json"))
    _retire_need(value.get("schema") == "iroha.taira.public-reset.generated-path.v1"
                 and value.get("kind") == kind and value.get("host_slug") == slug
                 and value.get("inventory_sha256") == context["inventory_sha256"]
                 and value.get("authorization_nonce") == context["nonce"]
                 and value.get("revision") == context["commit"],
                 "prune generated scope is not this closed attempt")


def _retire_prune_scopes(g, context, inventory):
    """Derive closed exact file slots and three public manifest chunk scopes."""
    qualification_steps(inventory.get("qualification_scope"))
    full_inrou = inventory["qualification_scope"] == "full_inrou"
    exact, chunk_dirs, protected, stores = {}, set(), {}, []
    staged = RETIRE_RUNTIME / "journal-v1/staged-artifacts-v1" / context["inventory_sha256"]
    runtime_stage = RETIRE_RUNTIME / "journal-v1/runtime-stage-v1" / context["authorization_sha256"]
    archives = {row["slug"]: Path(row["archive"]) for row in context["uploads"]}
    physical_hosts = {host["endpoint"]["host_identity_sha256"]
                      for host in inventory["validators"] + [inventory["edge"]]}
    _retire_need(len(physical_hosts) == 1
                 and re.fullmatch("[0-9a-f]{64}", next(iter(physical_hosts)))
                 and context["coordination_relative"] == str(Path("hosts") / next(iter(physical_hosts))),
                 "archived host stage coordination differs from the physical host")
    host_stage = (RETIRE_WORK / "retired-control" / context["coordination_relative"]
                  / "inrou-stage-v1" / context["nonce"])
    if full_inrou and os.path.lexists(host_stage):
        _retire_need(stat.S_IMODE(_retire_prune_info(host_stage, directory=True).st_mode) == 0o700,
                     "archived host stage must remain owner-private")
        carrier = next(host for host in inventory["validators"]
                       if host["endpoint"]["host_identity_sha256"] == next(iter(physical_hosts)))
        _retire_prune_marker(g, host_stage, context, carrier["slug"], "inrou_stage")
        marker = host_stage / ".public-reset-generated-v1.json"
        protected[str(marker)] = list(identity(_retire_prune_info(marker)))
    names = {"iroha_cli": ("iroha", "iroha"),
             "iroha3d": ("artifact-iroha3d", "iroha3d_taira"),
             "sorafs_node": ("artifact-sorafs_node", "sorafs-node"),
             "kagami": ("artifact-kagami", "kagami")}
    for host in inventory["validators"] + [inventory["edge"]]:
        slug = host["slug"]
        for artifact in host["artifacts"]:
            if artifact["role"] not in names:
                continue
            source = direct(artifact["local_path"])
            info = _retire_prune_info(source)
            _retire_need(info.st_size == artifact["size"] > 0,
                         "canonical public artifact metadata changed")
            protected[str(source)] = list(identity(info))
            upload_name, release_name = names[artifact["role"]]
            mode = 0o500 if artifact["role"] in ("iroha_cli", "iroha3d") else 0o400
            exact[staged / slug / context["nonce"] / upload_name] = (artifact["size"], mode)
            if slug in archives:
                exact[archives[slug] / upload_name] = (artifact["size"], 0o755)
            if slug != "taira-edge":
                release = RETIRE_WORK / "retired-control" / slug / "rollback" / context["nonce"] / "first-release.after"
                if release.exists():
                    _retire_prune_marker(g, release, context, slug, "release")
                    exact[release / "bin" / release_name] = (artifact["size"], 0o755)
        if full_inrou and slug != "taira-edge":
            fresh = RETIRE_WORK / "retired-control" / slug / "rollback" / context["nonce"] / "fresh-state.after"
            if fresh.exists():
                _retire_prune_marker(g, fresh, context, slug, "fresh_state")
                store = fresh / "sorafs-data"
                _retire_prune_marker(g, store, context, slug, "fresh_state_entry")
                _retire_prune_info(store, directory=True)
                stores.append(store)
    for name in (("rootfs.ext4", "vmlinux", "initrd.img") if full_inrou else ()):
        source = CONTINUITY_PREP / "inrou-stage/payloads/guest/aarch64" / name
        info = _retire_prune_info(source)
        _retire_need(info.st_size > 0, "canonical guest image is empty")
        protected[str(source)] = list(identity(info))
        exact[runtime_stage / "payloads/guest/aarch64" / name] = (info.st_size, 0o400)
        if os.path.lexists(host_stage):
            exact[host_stage / "payloads/guest/aarch64" / name] = (info.st_size, 0o400)
    for store in stores:
        for role in ("bundle", "guest", "discovery"):
            manifest_id = inventory["inrou_canary"][role + "_manifest_digest_hex"]
            manifest_sha = inventory["inrou_canary"][role + "_manifest_sha256"]
            _retire_need(re.fullmatch("[0-9a-f]{64}", manifest_id)
                         and re.fullmatch("[0-9a-f]{64}", manifest_sha),
                         "public store manifest identity is invalid")
            manifest = store / "manifests" / manifest_id
            chunks = manifest / "chunks"
            if not chunks.exists():
                continue
            _retire_prune_info(chunks, directory=True)
            # The directory's BLAKE3 identity and SHA256-bound small manifest
            # both come from native public SF1 admission. Never decode private
            # storage metadata or select other manifests/ingest staging.
            # SF1 manifests are public records; authority receipts still use
            # the distinct private-custody reader above.
            manifest_path = manifest / "manifest.to"
            manifest_identity = identity(_retire_prune_info(manifest_path))
            public_record(manifest_path, manifest_sha,
                          owner=os.geteuid(), limit=1024 * 1024)
            _retire_need(identity(_retire_prune_info(manifest_path)) == manifest_identity,
                         "public manifest changed during prune admission")
            protected[str(manifest_path)] = list(manifest_identity)
            chunk_dirs.add(chunks)
    for path in exact:
        _retire_need(str(path) not in protected and not path.is_relative_to(RETIRE_BINS)
                     and not path.is_relative_to(CONTINUITY_PREP),
                     "prune candidate overlaps canonical input")
    return exact, chunk_dirs, protected, stores


def _retire_prune_census(exact, chunk_dirs):
    paths = set(exact)
    for directory in sorted(chunk_dirs):
        with os.scandir(directory) as entries:
            for entry in entries:
                _retire_need(len(paths) < RETIRE_PRUNE_MAX_FILES,
                             "public prune file bound exceeded")
                _retire_need(re.fullmatch(r"chunk_[0-9]{5,}\.bin", entry.name),
                             "public chunk scope contains an unexpected entry")
                paths.add(Path(entry.path))
    rows = []
    for path in sorted(paths):
        if not os.path.lexists(path):
            continue
        info = _retire_prune_info(path)
        _retire_need(info.st_size > 0, "public prune payload is empty")
        if path in exact:
            _retire_need((info.st_size, stat.S_IMODE(info.st_mode)) == exact[path],
                         "public disposable copy size or mode differs")
        rows.append({"path": str(path), "identity": list(identity(info)),
                     "allocated_bytes": info.st_blocks * 512})
    _retire_need(len(rows) <= RETIRE_PRUNE_MAX_FILES
                 and len({tuple(row["identity"][:2]) for row in rows}) == len(rows),
                 "public prune candidates are duplicated or exceed bound")
    return rows


def _retire_prune_directories(rows):
    selected = {Path(row["path"]) for row in rows}
    directories = []
    for directory in sorted({path.parent for path in selected}):
        info = _retire_prune_info(directory, directory=True)
        retained = []
        with os.scandir(directory) as entries:
            for entry in entries:
                _retire_need(len(retained) < 4096, "retained sibling census exceeds bound")
                if Path(entry.path) not in selected:
                    retained.append({"name": entry.name,
                                     "identity": list(identity(entry.stat(follow_symlinks=False)))})
        directories.append({"path": str(directory), "identity": list(identity(info)[:5]),
                            "retained": sorted(retained, key=lambda row: row["name"])})
    _retire_need(len(directories) <= 128, "public prune directory bound exceeded")
    return directories


def _retire_prune_revalidate(g, context, intent, exact, chunk_dirs, protected):
    _retire_need(intent.get("schema") == "taira.closed-public-prune-intent.v1"
                 and intent.get("inventory_sha256") == context["inventory_sha256"]
                 and intent.get("terminal_sha256") == context["terminal_sha256"]
                 and intent.get("authorization_sha256") == context["authorization_sha256"]
                 and intent.get("protected") == protected,
                 "public prune intent binding changed")
    rows = intent["files"]
    _retire_need(isinstance(rows, list) and len(rows) <= RETIRE_PRUNE_MAX_FILES,
                 "public prune intent file bound exceeded")
    recorded = {}
    for row in rows:
        path = direct(row["path"])
        _retire_need(path not in recorded and (path in exact or
                     path.parent in chunk_dirs and re.fullmatch(r"chunk_[0-9]{5,}\.bin", path.name)),
                     "public prune intent escaped admitted scopes")
        recorded[path] = row
    present = _retire_prune_census(exact, chunk_dirs)
    _retire_need(all(Path(row["path"]) in recorded and
                     row == recorded[Path(row["path"])] for row in present),
                 "public prune payload appeared or changed after admission")
    expected_directories = {path.parent for path in recorded}
    _retire_need(len(intent["directories"]) <= 128
                 and {Path(row["path"]) for row in intent["directories"]} == expected_directories,
                 "public prune parent census differs")
    for row in intent["directories"]:
        directory = direct(row["path"])
        info = _retire_prune_info(directory, directory=True)
        _retire_need(list(identity(info)[:5]) == row["identity"],
                     "public prune parent identity changed")
        retained = {entry["name"]: entry["identity"] for entry in row["retained"]}
        selected = {path.name for path in recorded if path.parent == directory}
        names = {entry.name for entry in directory.iterdir()}
        _retire_need(names - selected == set(retained), "public prune sibling set changed")
        for name, stamp in retained.items():
            _retire_need(list(identity((directory / name).lstat())) == stamp,
                         "public prune retained sibling changed")
    for path, stamp in protected.items():
        _retire_need(list(identity(_retire_prune_info(path))) == stamp,
                     "canonical public input changed during prune")
    _retire_retained_state(g, context)
    _retire_need(_retire_live_references(list(expected_directories), file_identities=present)["passed"],
                 "public disposable payload has a live reference")
    return present


def _retire_prune_public(g, context, result):
    """Finish disposable-copy reclamation after publication, including crash resume."""
    _retire_need(result.get("published") is True and result.get("control_archived") is True
                 and result.get("native_rollback_completed") is True
                 and result.get("inventory_sha256") == context["inventory_sha256"]
                 and result.get("terminal_sha256") == context["terminal_sha256"]
                 and result.get("retired_control_path") == str(RETIRE_WORK / "retired-control"),
                 "public pruning requires this published retirement")
    inventory_raw = _retire_read_public(g, RETIRE_INVENTORY_PATH, limit=8 * 1024 * 1024)
    inventory = json.loads(inventory_raw)
    _retire_need(_retire_digest(inventory_raw) == context["inventory_sha256"],
                 "public prune inventory binding changed")
    opened = []
    try:
        for slug in RETIRE_SLUGS[:-1]:
            store = RETIRE_WORK / "retired-control" / slug / "rollback" / context["nonce"] / "fresh-state.after/sorafs-data"
            if not store.exists():
                continue
            lock = store / ".storage.lock"
            if not lock.exists():
                _retire_need(not (store / "manifests").exists(), "retired store lacks its lock")
                continue
            before = _retire_prune_info(lock)
            fd = os.open(lock, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
            opened.append(fd)
            _retire_need(identity(os.fstat(fd)) == identity(before), "retired store lock changed")
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        exact, chunk_dirs, protected, _ = _retire_prune_scopes(g, context, inventory)
        path = RETIRE_WORK / "public-prune-intent.json"
        if path.exists():
            intent = json.loads(_retire_read_public(g, path, limit=RETIRE_PRUNE_MAX_RECEIPT_BYTES))
        else:
            rows = _retire_prune_census(exact, chunk_dirs)
            intent = {"schema": "taira.closed-public-prune-intent.v1",
                      "inventory_sha256": context["inventory_sha256"],
                      "terminal_sha256": context["terminal_sha256"],
                      "authorization_sha256": context["authorization_sha256"],
                      "files": rows, "directories": _retire_prune_directories(rows),
                      "protected": protected}
            data = _retire_canonical(intent)
            _retire_need(len(data) <= RETIRE_PRUNE_MAX_RECEIPT_BYTES,
                         "public prune intent byte bound exceeded")
            _retire_prune_revalidate(g, context, intent, exact, chunk_dirs, protected)
            g["fresh_write"](path, data, 0o600)
            g["sync_directory"](RETIRE_WORK)
        present = _retire_prune_revalidate(g, context, intent, exact, chunk_dirs, protected)
        for row in present:
            payload = Path(row["path"])
            _retire_need(list(identity(_retire_prune_info(payload))) == row["identity"],
                         "public disposable payload changed before removal")
            payload.unlink()
        for directory in intent["directories"]:
            g["sync_directory"](Path(directory["path"]))
        _retire_need(not _retire_prune_revalidate(g, context, intent, exact, chunk_dirs, protected),
                     "public disposable payload remained after pruning")
        completed = {"schema": "taira.closed-public-prune.v1",
                     "inventory_sha256": context["inventory_sha256"],
                     "terminal_sha256": context["terminal_sha256"],
                     "file_count": len(intent["files"]),
                     "allocated_bytes_removed": sum(row["allocated_bytes"] for row in intent["files"]),
                     "directories_inputs_metadata_and_private_state_preserved": True}
        _retire_event(g, "public-prune-completed", completed)
        # Flush and trim are repeated on resume because a crash may follow unlink
        # but precede discard. Directory fsync alone does not settle filesystem
        # block reclamation before FITRIM, which can otherwise discard zero bytes.
        # The next guest and backing capacity observations remain decisive.
        mount = RETIRE_RUNTIME
        while not os.path.ismount(mount):
            _retire_need(mount != mount.parent, "retired runtime mountpoint is unavailable")
            mount = mount.parent
        flush = subprocess.run(["/usr/bin/sync", "-f", str(mount)],
                               capture_output=True, timeout=60, check=False)
        _retire_need(flush.returncode == 0, "retired public payload filesystem flush failed")
        trim = subprocess.run(["/usr/sbin/fstrim", str(mount)],
                              capture_output=True, timeout=60, check=False)
        _retire_need(trim.returncode == 0, "retired public payload trim failed")
        return completed
    finally:
        for fd in reversed(opened):
            os.close(fd)



_RETIRE_SOURCE_MAX_ENTRIES = 65536
_RETIRE_SOURCE_MAX_DEPTH = 64


def _retire_source_no_mounts(root):
    if sys.platform != "linux":
        return
    with open("/proc/self/mountinfo", "rb") as stream:
        raw = stream.read(1024 * 1024 + 1)
    require(0 < len(raw) <= 1024 * 1024, "source mount census exceeds bound")
    for line in raw.splitlines():
        fields = line.split()
        require(len(fields) >= 10 and b"-" in fields, "source mount census malformed")
        name = re.sub(rb"\\([0-7]{3})", lambda m: bytes([int(m[1], 8)]), fields[4])
        mount = Path(os.fsdecode(name))
        require(mount != root and not mount.is_relative_to(root), "source contains a mount")


def _retire_source_walk(root):
    root = direct(root)
    for path in (root, *root.parents):
        info = path.lstat()
        require(stat.S_ISDIR(info.st_mode) and info.st_uid in (0, os.geteuid())
                and not info.st_mode & 0o022, "source ancestor custody differs")
    _retire_source_no_mounts(root)
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    records = []
    root_fd = os.open(root, flags)
    root_info = os.fstat(root_fd)

    def walk(fd, relative, depth):
        require(depth <= _RETIRE_SOURCE_MAX_DEPTH, "source directory depth exceeds bound")
        before = os.fstat(fd)
        add(relative, before)
        with os.scandir(fd) as entries:
            for entry in entries:
                path = str(Path(relative) / entry.name) if relative != "." else entry.name
                info = os.stat(entry.name, dir_fd=fd, follow_symlinks=False)
                if stat.S_ISDIR(info.st_mode):
                    child = os.open(entry.name, flags, dir_fd=fd)
                    try:
                        require(identity(info) == identity(os.fstat(child)), "source directory changed")
                        walk(child, path, depth + 1)
                        require(identity(info) == identity(os.stat(entry.name, dir_fd=fd,
                                                                  follow_symlinks=False)),
                                "source directory replaced during census")
                    finally:
                        os.close(child)
                else:
                    add(path, info)
        require(identity(before) == identity(os.fstat(fd)), "source directory changed during census")

    def add(path, info):
        require(len(records) < _RETIRE_SOURCE_MAX_ENTRIES, "source entry count exceeds bound")
        kind = ("directory" if stat.S_ISDIR(info.st_mode) else
                "file" if stat.S_ISREG(info.st_mode) else
                "symlink" if stat.S_ISLNK(info.st_mode) else None)
        require(kind is not None and info.st_dev == root_info.st_dev,
                "source type or filesystem differs")
        require(info.st_uid == os.geteuid() and info.st_gid == os.getegid()
                and (kind == "symlink" or not info.st_mode & 0o022)
                and (kind == "directory" or info.st_nlink == 1), "source entry custody differs")
        records.append({"path": path, "kind": kind, "identity": list(identity(info)),
                        "allocated_bytes": info.st_blocks * 512})

    try:
        require(identity(root_info) == identity(root.lstat()), "source root changed during open")
        walk(root_fd, ".", 0)
        require(identity(root_info) == identity(root.lstat()), "source root changed during census")
        _retire_source_no_mounts(root)
    finally:
        os.close(root_fd)
    return sorted(records, key=lambda row: row["path"])


def _retire_source_validate_records(records, tracked_files, *, pack_size):
    """Bind retained source metadata to the native tracked closure and import layout."""
    require(isinstance(tracked_files, list) and 0 < len(tracked_files) < _RETIRE_SOURCE_MAX_ENTRIES
            and type(pack_size) is int and pack_size > 0, "source manifest bounds differ")
    expected = {".": ("directory", {0o755}, None)}
    gitlinks = []

    def add(path, kind, modes, size=None):
        item = (kind, modes, size)
        require(path not in expected or expected[path] == item, "source manifest path collision")
        expected[path] = item
        for parent in Path(path).parents:
            name = str(parent)
            require(name not in expected or expected[name] == ("directory", {0o755}, None),
                    "source manifest parent collision")
            expected[name] = ("directory", {0o755}, None)

    seen = set()
    for row in tracked_files:
        path, mode, size = row["path"], row["mode"], row["size"]
        require(isinstance(path, str) and path not in seen and path != "."
                and not Path(path).is_absolute() and str(Path(path)) == path
                and ".." not in Path(path).parts and "\x00" not in path
                and len(os.fsencode(path)) <= 4096 and Path(path).parts[0] != ".git"
                and type(mode) is int and type(size) is int and size >= 0,
                "source manifest path or mode differs")
        seen.add(path)
        if mode in (0o644, 0o755):
            add(path, "file", {mode}, size)
        elif mode == 0o120000:
            add(path, "symlink", {0o777}, size)
        elif mode == 0o160000:
            add(path, "directory", {0o755})
            gitlinks.append(path)
        else:
            require(False, "unsupported source manifest mode")
    require(not any(other.startswith(link + "/") for link in gitlinks for other in seen),
            "initialized source gitlink is not allowed")
    for path in ("HEAD", "ORIG_HEAD", "config", "shallow", "refs/heads/optimizations",
                 "logs/HEAD", "logs/refs/heads/optimizations"):
        add(".git/" + path, "file", {0o644})
    add(".git/index", "file", {0o600, 0o644})
    for path in (".git/objects/info", ".git/objects/pack", ".git/refs/tags"):
        add(path, "directory", {0o755})
    packs = [row["path"] for row in records if
             re.fullmatch(r"\.git/objects/pack/pack-[0-9a-f]{40}\.pack", row["path"])]
    require(len(packs) == 1, "exactly one source Git pack required")
    stem = packs[0][:-5]
    for suffix in (".pack", ".idx", ".rev"):
        add(stem + suffix, "file", {0o444}, pack_size if suffix == ".pack" else None)
    require({row["path"] for row in records} == set(expected), "source has missing or extra paths")
    for row in records:
        kind, modes, size = expected[row["path"]]
        info = row["identity"]
        require(row["kind"] == kind and stat.S_IMODE(info[2]) in modes
                and (size is None or info[6] == size), "source manifest metadata differs")
    return records


def _retire_source_census(root, tracked_files, *, pack_size):
    """Admit the entire exact public tree and return durable metadata identities."""
    return _retire_source_validate_records(_retire_source_walk(root), tracked_files,
                                           pack_size=pack_size)


def _retire_source_revalidate(root, records, *, allow_absent=False):
    """Allow only deletion progress, including a renamed quarantine root."""
    require(isinstance(records, list) and 0 < len(records) <= _RETIRE_SOURCE_MAX_ENTRIES,
            "source intent bounds differ")
    expected = {row["path"]: row for row in records}
    require(len(expected) == len(records) and "." in expected, "source intent path set differs")
    if allow_absent and not os.path.lexists(root):
        return []
    remaining = _retire_source_walk(root)
    for row in remaining:
        old = expected.get(row["path"])
        require(old is not None and row["kind"] == old["kind"], "source gained an unadmitted path")
        count = 5 if row["kind"] == "directory" else 9
        require(row["identity"][:count] == old["identity"][:count],
                "source identity changed after admission")
    return remaining


# Superseded public import ownership stays with the coordinator, not validators.
RETIRE_IMPORT_MAX_COUNT = 4
RETIRE_IMPORT_MAX_INTENT_BYTES = 16 * 1024 * 1024


def validate_retired_public_imports(value):
    """Require explicitly named closed imports; never discover targets by a glob."""
    require(isinstance(value, list) and len(value) <= RETIRE_IMPORT_MAX_COUNT,
            "retired public import count exceeds its bound")
    seen = set()
    for row in value:
        require(isinstance(row, dict) and set(row) == {
            "inventory", "retirement", "binary_manifest", "source_manifest", "source_pack"},
            "retired import requires exact inventory/retirement/import references and pack path")
        for name in ("inventory", "retirement", "binary_manifest", "source_manifest"):
            ref = row[name]
            require(isinstance(ref, dict) and set(ref) == {"path", "sha256"}
                    and isinstance(ref["path"], str) and "\x00" not in ref["path"]
                    and Path(ref["path"]).is_absolute()
                    and str(Path(ref["path"])) == ref["path"]
                    and ".." not in Path(ref["path"]).parts
                    and isinstance(ref["sha256"], str)
                    and re.fullmatch("[0-9a-f]{64}", ref["sha256"]) is not None,
                    "retired import public reference is invalid")
        pack = row["source_pack"]
        require(isinstance(pack, str) and "\x00" not in pack and Path(pack).is_absolute()
                and str(Path(pack)) == pack and ".." not in Path(pack).parts
                and Path(pack) == Path(row["source_manifest"]["path"]).parent / "source.pack",
                "transport pack must be the exact completed import's source.pack")
        key = row["inventory"]["sha256"]
        require(key not in seen, "retired import inventory is duplicated")
        seen.add(key)
    return value


def _retire_import_overlaps(path, protected):
    path = Path(path)
    return any(path == other or path.is_relative_to(other) or other.is_relative_to(path)
               for other in map(Path, protected))


def _retire_import_admission(g, descriptor, current_inventory):
    """Join existing native closure authority to completed public transfer receipts."""
    guards, records = {}, {}
    for name in ("inventory", "retirement", "binary_manifest", "source_manifest"):
        ref = descriptor[name]
        path = direct(ref["path"])
        require(path.is_relative_to(RETIRE_RUNTIME), "retired public receipt escaped runtime authority")
        raw = public_record(path, ref["sha256"], owner=os.geteuid(), limit=8 * 1024 * 1024)
        guards[str(path)] = ref["sha256"]
        records[name] = decode(raw)
    inventory, retired = records["inventory"], records["retirement"]
    revision = inventory["revision"]
    require(retired.get("schema") == "taira.terminal-custody-retirement.v1"
            and all(retired.get(k) is True for k in
                    ("published", "control_archived", "native_rollback_completed"))
            and retired.get("inventory_sha256") == descriptor["inventory"]["sha256"]
            and retired.get("retained_commit") == revision["commit"]
            and retired.get("retained_deployment_id") == inventory["deployment_id"],
            "superseded inputs require their completed custody retirement")
    terminal_path = direct(retired["terminal_path"])
    require(terminal_path.parent == RETIRE_RUNTIME / "journal-v1/rolled-back"
            and re.fullmatch("[0-9a-f]{64}\\.json", terminal_path.name),
            "superseded native terminal is outside closed rollback authority")
    raw = public_record(terminal_path, retired["terminal_sha256"], owner=os.geteuid())
    terminal = decode(raw)
    _retire_validate_terminal(inventory, terminal, expected_commit=revision["commit"],
                             expected_deployment=inventory["deployment_id"])
    require(terminal.get("inventory_sha256") == descriptor["inventory"]["sha256"]
            and terminal_path.stem == terminal.get("authorization_sha256")
            and terminal.get("authorization_nonce") == inventory["authorization_nonce"],
            "superseded native terminal differs from the imported inventory")
    deployment = inventory["deployment_id"]
    require(isinstance(deployment, str) and re.fullmatch(r"[a-zA-Z0-9_.-]{1,128}", deployment)
            and not os.path.lexists(RETIRE_RUNTIME / "journal-v1" / (deployment + ".journal.json")),
            "superseded import still has a live native journal")
    guards[str(terminal_path)] = retired["terminal_sha256"]
    binary, source = records["binary_manifest"], records["source_manifest"]
    names = {"iroha", "iroha3d_taira", "sorafs-node", "kagami"}
    require(binary.get("commit") == source.get("commit") == revision["commit"]
            and binary.get("all_hashes_verified") is True and binary.get("activated") is False
            and source.get("tree") == revision["tree"]
            and source.get("source_root") == revision["source_root"]
            and all(source.get(k) is True for k in ("clean", "signature_verified", "object_inventory_verified"))
            and all(source.get(k) is False for k in
                    ("activated", "runtime_files_transferred", "runtime_files_included", "history_included"))
            and len(binary.get("artifacts", [])) == 4
            and {row["name"] for row in binary["artifacts"]} == names,
            "superseded public import provenance differs")
    artifacts = {row["name"]: row for row in binary["artifacts"]}
    for row in [*artifacts.values(), {"size": source.get("size"), "sha256": source.get("sha256")}]:
        require(type(row["size"]) is int and 0 < row["size"] < 1 << 63
                and isinstance(row["sha256"], str) and re.fullmatch("[0-9a-f]{64}", row["sha256"]),
                "superseded public payload size or digest is invalid")
    bins, source_root = direct(binary["destination"]), direct(source["source_root"])
    require(bins.is_relative_to(RETIRE_RUNTIME)
            and Path(descriptor["binary_manifest"]["path"]) == bins.parent / "verified-manifest.json",
            "superseded binary namespace differs from its completed transfer")
    roles = {"iroha_cli": "iroha", "iroha3d": "iroha3d_taira",
             "sorafs_node": "sorafs-node", "kagami": "kagami"}
    admitted_names = set()
    for host in inventory["validators"] + [inventory["edge"]]:
        for artifact in host["artifacts"]:
            if artifact["role"] in roles:
                name = roles[artifact["role"]]
                require(artifact["local_path"] == str(bins / name)
                        and artifact["size"] == artifacts[name]["size"]
                        and artifact["sha256"] == artifacts[name]["sha256"],
                        "superseded canonical binary differs from native inventory")
                admitted_names.add(name)
    require(admitted_names == set(roles.values()), "superseded inventory omits deployed public binaries")
    closure_path = direct(revision["source_manifest_path"])
    require(closure_path.is_relative_to(RETIRE_RUNTIME), "source closure escaped runtime authority")
    closure_raw = public_record(closure_path, revision["source_manifest_sha256"], owner=os.geteuid())
    closure = decode(closure_raw)
    require(closure.get("schema") == "iroha.taira.public-reset.signed-source-closure.v1"
            and closure.get("branch") == revision["branch"] == "optimizations"
            and closure.get("head_commit_sha1") == revision["commit"]
            and closure.get("head_tree_sha1") == revision["tree"]
            and closure.get("closure_sha256") == revision["source_closure_sha256"]
            and closure.get("cargo_lock_sha256") == revision["cargo_lock_sha256"]
            and closure.get("untracked_files") == [], "superseded source closure binding differs")
    guards[str(closure_path)] = revision["source_manifest_sha256"]
    protected = {str(RETIRE_RUNTIME / "journal-v1"), str(RETIRE_RUNTIME / "retry-v1"),
                 str(RETIRE_WORK), str(RETIRE_CONTROL), str(RETIRE_DISPATCHER),
                 str(CONTINUITY_PREP), str(RETIRE_BINS), *map(str, RETIRE_PROTECTED_INPUTS), *guards,
                 *(entry[key]["path"] for entry in RETIRE_PUBLIC_IMPORTS
                   for key in ("inventory", "retirement", "binary_manifest", "source_manifest"))}
    protected.add(current_inventory["revision"]["source_root"])
    for host in current_inventory["validators"] + [current_inventory["edge"]]:
        protected.update(host[k] for k in ("service_root", "state_root", "reset_guard") if k in host)
        protected.update(artifact["local_path"] for artifact in host["artifacts"])
    files = [{"path": str(bins / name), "size": row["size"], "mode": 0o755}
             for name, row in sorted(artifacts.items())]
    files.append({"path": descriptor["source_pack"], "size": source["size"], "mode": 0o600})
    files = [row for row in files if not _retire_import_overlaps(row["path"], protected)]
    tree = None if _retire_import_overlaps(source_root, protected) else str(source_root)
    require(not tree or not any(_retire_import_overlaps(tree, [row["path"]]) for row in files),
            "superseded source and public-file scopes overlap")
    return {"inventory_sha256": descriptor["inventory"]["sha256"],
            "terminal_sha256": retired["terminal_sha256"], "guards": guards,
            "files": files, "source_root": tree, "tracked_files": closure["tracked_files"],
            "pack_size": source["size"], "protected": sorted(protected)}


def _retire_import_admissions(g, current):
    admissions = [_retire_import_admission(g, row, current) for row in
                  validate_retired_public_imports(list(RETIRE_PUBLIC_IMPORTS))]
    scopes = []
    guards = {path for row in admissions for path in row["guards"]}
    for row in admissions:
        for path in [item["path"] for item in row["files"]] + ([row["source_root"]] if row["source_root"] else []):
            require(not _retire_import_overlaps(path, guards)
                    and not _retire_import_overlaps(path, scopes),
                    "retired import scopes overlap another payload or retained authority")
            scopes.append(path)
    return admissions


def _retire_import_file_records(files):
    records = []
    for expected in files:
        path = direct(expected["path"])
        if not os.path.lexists(path):
            continue
        info = _retire_prune_info(path)
        require(info.st_size == expected["size"] and stat.S_IMODE(info.st_mode) == expected["mode"],
                "superseded public file metadata differs")
        records.append({"path": str(path), "identity": list(identity(info)),
                        "allocated_bytes": info.st_blocks * 512})
    return records


def _retire_import_revalidate(g, context, admission, intent):
    require(intent.get("schema") == "taira.superseded-public-import-intent.v1"
            and intent.get("admission") == admission, "superseded import intent binding changed")
    for path, expected in admission["guards"].items():
        public_record(path, expected, owner=os.geteuid())
    tree = admission["source_root"]
    expected_quarantine = str(Path(tree).with_name(".taira-retired-source-" + admission["inventory_sha256"])) if tree else None
    require(intent.get("quarantine") == expected_quarantine,
            "superseded source quarantine escaped its admitted parent")
    recorded = {row["path"]: row for row in intent["files"]}
    require(len(recorded) == len(intent["files"])
            and set(recorded) <= {row["path"] for row in admission["files"]},
            "superseded public file intent escaped admitted inputs")
    require({row["path"] for row in intent["directories"]}
            == {str(Path(path).parent) for path in recorded}
            and len(intent["directories"]) == len({row["path"] for row in intent["directories"]}),
            "superseded public parent intent escaped admitted inputs")
    files = _retire_import_file_records(admission["files"])
    require(all(row == recorded.get(row["path"]) for row in files),
            "superseded public file changed or appeared after intent")
    for row in intent["directories"]:
        path = direct(row["path"])
        require(list(identity(_retire_prune_info(path, directory=True))[:5]) == row["identity"],
                "superseded public parent changed")
        selected = {Path(name).name for name in recorded if Path(name).parent == path}
        retained = {entry["name"]: entry["identity"] for entry in row["retained"]}
        require({entry.name for entry in path.iterdir()} - selected == set(retained),
                "superseded public siblings changed")
        for name, stamp in retained.items():
            require(list(identity((path / name).lstat())) == stamp, "superseded public sibling replaced")
    quarantine = intent["quarantine"]
    remaining = []
    require(tree is not None or intent["source_records"] == [],
            "protected current source gained a retirement intent")
    if intent["source_records"]:
        _retire_source_validate_records(intent["source_records"], admission["tracked_files"],
                                        pack_size=admission["pack_size"])
    if tree:
        require(not (os.path.lexists(tree) and os.path.lexists(quarantine)),
                "superseded source has two owners")
        if os.path.lexists(tree):
            remaining = _retire_source_revalidate(tree, intent["source_records"])
            require(remaining == intent["source_records"], "source changed before quarantine")
        elif os.path.lexists(quarantine):
            remaining = _retire_source_revalidate(quarantine, intent["source_records"])
    _retire_retained_state(g, context)
    roots = [row["path"] for row in admission["files"]]
    roots += [row["path"] for row in intent["directories"]]
    roots += [tree, quarantine] if tree else []
    source_files = []
    if tree:
        source_base = Path(quarantine if os.path.lexists(quarantine) else tree)
        source_files = [{"path": str(source_base / row["path"]), "identity": row["identity"]}
                        for row in remaining if row["kind"] == "file"]
    require(_retire_live_references(roots, file_identities=files + source_files)["passed"],
            "superseded import has a live process or mount reference")
    return files, remaining


def _retire_completed_public_imports(g, context, result):
    """Retire explicitly superseded public imports under the existing native locks."""
    descriptors = validate_retired_public_imports(list(RETIRE_PUBLIC_IMPORTS))
    if not descriptors:
        return []
    require(result.get("published") is True and result.get("control_archived") is True
            and result.get("native_rollback_completed") is True
            and result.get("inventory_sha256") == context["inventory_sha256"]
            and result.get("terminal_sha256") == context["terminal_sha256"],
            "superseded import cleanup requires this published retirement")
    current = decode(_retire_read_public(g, RETIRE_INVENTORY_PATH, context["inventory_sha256"],
                                       limit=8 * 1024 * 1024))
    admissions = _retire_import_admissions(g, current)
    output = RETIRE_WORK / "public-import-retirement"
    output.mkdir(mode=0o700, exist_ok=True)
    _retire_prune_info(output, directory=True)
    completed = []
    for admission in admissions:
        label = admission["inventory_sha256"]
        path = output / (label + ".intent.json")
        if path.exists():
            intent = decode(public_record(path, owner=os.geteuid(), private=True,
                                          limit=RETIRE_IMPORT_MAX_INTENT_BYTES))
        else:
            tree = admission["source_root"]
            records = (_retire_source_census(tree, admission["tracked_files"], pack_size=admission["pack_size"])
                       if tree and os.path.lexists(tree) else [])
            quarantine = str(Path(tree).with_name(".taira-retired-source-" + label)) if tree else None
            require(not quarantine or not os.path.lexists(quarantine), "unowned source quarantine exists")
            files = _retire_import_file_records(admission["files"])
            intent = {"schema": "taira.superseded-public-import-intent.v1", "admission": admission,
                      "files": files, "directories": _retire_prune_directories(files),
                      "source_records": records, "quarantine": quarantine}
            raw = _retire_canonical(intent)
            require(len(raw) <= RETIRE_IMPORT_MAX_INTENT_BYTES, "superseded import intent exceeds bound")
            _retire_import_revalidate(g, context, admission, intent)
            g["fresh_write"](path, raw, 0o600)
            g["sync_directory"](output)
        files, remaining = _retire_import_revalidate(g, context, admission, intent)
        tree = admission["source_root"]
        if tree and os.path.lexists(tree):
            _retire_rename_atomic(Path(tree), Path(intent["quarantine"]))
            g["sync_directory"](Path(tree).parent)
        if remaining:
            _retire_import_revalidate(g, context, admission, intent)
            require(shutil.rmtree.avoids_symlink_attacks, "descriptor-safe source removal required")
            shutil.rmtree(intent["quarantine"])
            g["sync_directory"](Path(tree).parent)
        files, _ = _retire_import_revalidate(g, context, admission, intent)
        for row in files:
            payload = Path(row["path"])
            require(list(identity(_retire_prune_info(payload))) == row["identity"],
                    "superseded public file changed before unlink")
            payload.unlink()
        for directory in intent["directories"]:
            g["sync_directory"](Path(directory["path"]))
        files, remaining = _retire_import_revalidate(g, context, admission, intent)
        require(not files and not remaining, "superseded public payload remains")
        record = {"schema": "taira.superseded-public-import-retired.v1", "inventory_sha256": label,
                  "terminal_sha256": admission["terminal_sha256"],
                  "allocated_bytes_removed": sum(row["allocated_bytes"] for row in intent["files"] + intent["source_records"]),
                  "private_inputs_manifests_and_current_artifacts_preserved": True}
        done = output / (label + ".completed.json")
        if done.exists():
            require(decode(public_record(done, owner=os.geteuid(), private=True)) == record,
                    "superseded import completion changed")
        else:
            g["fresh_write"](done, _retire_canonical(record), 0o600)
            g["sync_directory"](output)
        completed.append(record)
    mounts = set()
    for descriptor in descriptors:
        for path in (Path(descriptor["source_pack"]).parent,
                     Path(decode(_retire_read_public(g, Path(descriptor["source_manifest"]["path"])))['source_root']).parent):
            while not os.path.ismount(path):
                require(path != path.parent, "superseded import filesystem unavailable")
                path = path.parent
            mounts.add(path)
    for mount in sorted(mounts):
        flush = subprocess.run(["/usr/bin/sync", "-f", str(mount)], capture_output=True, timeout=60, check=False)
        require(flush.returncode == 0, "superseded import filesystem flush failed")
        trim = subprocess.run(["/usr/sbin/fstrim", str(mount)], capture_output=True, timeout=60, check=False)
        require(trim.returncode == 0, "superseded import filesystem trim failed")
    return completed


def _retire_apply(g, context, check_only=False):
    with _retire_locks(g, context):
        _retire_retained_state(g, context)
        old_location = (
            RETIRE_WORK / "old-dispatcher"
            if (RETIRE_WORK / "old-dispatcher").exists()
            else RETIRE_DISPATCHER
        )
        old = _retire_binary(g, old_location, context["old_dispatcher_sha256"])
        try:
            _retire_no_running_inode((os.fstat(old.fd).st_dev, os.fstat(old.fd).st_ino))
        finally:
            old.close()
        if RETIRE_PUBLIC_IMPORTS:
            current = decode(_retire_read_public(g, RETIRE_INVENTORY_PATH, context["inventory_sha256"],
                                               limit=8 * 1024 * 1024))
            _retire_import_admissions(g, current)
        if check_only:
            return {
                "schema": "taira.terminal-custody-retirement-precheck.v1",
                "check_only": True,
                "preconditions_passed": True,
                "mutation_performed": False,
                "commit": context["expected_commit"],
                "terminal_status": "rolled_back",
                "native_rollback_completed": True,
            }
        manifest = RETIRE_WORK / "manifest.json"
        if not RETIRE_WORK.exists():
            RETIRE_WORK.mkdir(mode=0o700)
            g["sync_directory"](RETIRE_WORK.parent)
        if manifest.exists():
            _retire_need(
                json.loads(_retire_read_public(g, manifest, limit=8 * 1024 * 1024))
                == context,
                "operator reset context changed",
            )
        else:
            _retire_event(g, "manifest", context)
        if (RETIRE_WORK / "result.json").exists():
            _retire_check_guards(g, RETIRE_CONTROL, context["new_dispatcher_sha256"])
            current = _retire_binary(
                g, RETIRE_DISPATCHER, context["new_dispatcher_sha256"]
            )
            current.close()
            result = json.loads(_retire_read_public(g, RETIRE_WORK / "result.json"))
            _retire_prune_public(g, context, result)
            _retire_completed_public_imports(g, context, result)
            return result
        candidate = RETIRE_WORK / "candidate-control"
        staged = RETIRE_WORK / "new-dispatcher"
        old_path = RETIRE_WORK / "old-dispatcher"
        archived = RETIRE_WORK / "retired-control"
        if not archived.exists():
            if not candidate.exists():
                candidate.mkdir(mode=0o700)
            g["check_directory"](candidate, 0o700)
            _retire_need(
                {p.name for p in candidate.iterdir()} <= set(RETIRE_SLUGS),
                "partial candidate has unknown roles",
            )
            for slug in RETIRE_SLUGS:
                role = candidate / slug
                if not role.exists():
                    role.mkdir(mode=0o700)
                g["check_directory"](role, 0o700)
                _retire_need(
                    {p.name for p in role.iterdir()} <= {"guard.json"},
                    "partial candidate has unknown files",
                )
                expected = _retire_canonical(
                    g["guard_record"](
                        slug, RETIRE_TRUST_HASH, context["new_dispatcher_sha256"]
                    )
                )
                if (role / "guard.json").exists():
                    _retire_need(
                        _retire_read_public(g, role / "guard.json") == expected,
                        "partial candidate guard differs",
                    )
                else:
                    g["fresh_write"](role / "guard.json", expected, 0o600)
                g["sync_directory"](role)
            g["sync_directory"](candidate)
            g["sync_directory"](RETIRE_WORK)
            _retire_check_guards(g, candidate, context["new_dispatcher_sha256"])
        if staged.exists() and (not old_path.exists()):
            try:
                ready = _retire_binary(g, staged, context["new_dispatcher_sha256"])
                ready.close()
            except _retire_RebindError:
                failed = RETIRE_WORK / (
                    "failed-new-dispatcher-" + str(staged.lstat().st_ino)
                )
                _retire_move(g, staged, failed)
        if not staged.exists() and (not old_path.exists()):
            source = _retire_binary(
                g, RETIRE_BINS / "iroha", context["new_dispatcher_sha256"]
            )
            try:
                fd = os.open(
                    staged, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o755
                )
                with os.fdopen(fd, "wb") as out:
                    os.lseek(source.fd, 0, os.SEEK_SET)
                    os.fchmod(out.fileno(), 0o755)
                    while block := os.read(source.fd, 1024 * 1024):
                        out.write(block)
                    out.flush()
                    os.fsync(out.fileno())
                    source.verify()
                g["sync_directory"](RETIRE_WORK)
            finally:
                source.close()
        if not old_path.exists():
            ready = _retire_binary(g, staged, context["new_dispatcher_sha256"])
            ready.close()
            _retire_event(
                g,
                "01-dispatcher-barrier",
                {
                    "scope": "completed-native-terminal-retirement",
                    "native_rollback_completed": True,
                },
            )
            _retire_move(g, RETIRE_DISPATCHER, old_path)
        old = _retire_binary(g, old_path, context["old_dispatcher_sha256"])
        try:
            _retire_no_running_inode((os.fstat(old.fd).st_dev, os.fstat(old.fd).st_ino))
        finally:
            old.close()
        _retire_retained_state(g, context)
        archive_parent = RETIRE_WORK / "uploads"
        if not archive_parent.exists():
            archive_parent.mkdir(mode=0o700)
            g["sync_directory"](RETIRE_WORK)
        g["check_directory"](archive_parent, 0o700)
        for row in context["uploads"]:
            source = Path(row["source"])
            target = Path(row["archive"])
            if source.exists():
                _retire_event(g, "02-archive-" + row["slug"], row)
                _retire_move(g, source, target)
                _retire_need(
                    _retire_root_identity(target) == row["identity"],
                    "upload root inode changed during rename",
                )
        if not archived.exists():
            identity = _retire_root_identity(RETIRE_CONTROL)
            _retire_event(g, "03-archive-control", {"identity": identity})
            _retire_move(g, RETIRE_CONTROL, archived)
            _retire_need(
                _retire_root_identity(archived) == identity,
                "control root inode changed during rename",
            )
        if not RETIRE_CONTROL.exists():
            _retire_move(g, candidate, RETIRE_CONTROL)
        _retire_check_guards(g, RETIRE_CONTROL, context["new_dispatcher_sha256"])
        _retire_retained_state(g, context)
        if not RETIRE_DISPATCHER.exists():
            ready = _retire_binary(g, staged, context["new_dispatcher_sha256"])
            ready.close()
            _retire_event(
                g,
                "04-publish-corrected-dispatcher",
                {"commit": context["expected_commit"]},
            )
            _retire_move(g, staged, RETIRE_DISPATCHER)
        current = _retire_binary(g, RETIRE_DISPATCHER, context["new_dispatcher_sha256"])
        current.close()
        result = {
            "schema": "taira.terminal-custody-retirement.v1",
            "commit": context["expected_commit"],
            "dispatcher_sha256": context["new_dispatcher_sha256"],
            "retained_commit": RETIRE_COMMIT,
            "terminal_path": str(RETIRE_TERMINAL),
            "terminal_sha256": context["terminal_sha256"],
            "terminal_status": "rolled_back",
            "retained_deployment_id": context["retained_deployment_id"],
            "inventory_sha256": context["inventory_sha256"],
            "native_rollback_completed": True,
            "control_archived": True,
            "retired_control_path": str(archived),
            "upload_archives": context["uploads"],
            "published": True,
            "dispatcher_inode_preserved": False,
            "guard_bytes_unchanged": context["new_dispatcher_sha256"] == RETIRE_CLI_SHA,
            "runtime_secret_contents_read_hashed_or_copied": False,
            "native_journal_modified": False,
            "guards": [
                {
                    "slug": slug,
                    "upload_guard_sha256": _retire_digest(
                        _retire_canonical(
                            g["guard_record"](
                                slug,
                                RETIRE_TRUST_HASH,
                                context["new_dispatcher_sha256"],
                            )
                        )
                    ),
                }
                for slug in RETIRE_SLUGS
            ],
        }
        _retire_event(g, "result", result)
        _retire_prune_public(g, context, result)
        _retire_completed_public_imports(g, context, result)
        return result


# Continuity custody and evidence
CONTINUITY_UNIT_RENDERER = None
CONTINUITY_RUNTIME = None
CONTINUITY_RENDERER_SHA = None
CONTINUITY_PREP = None
CONTINUITY_OUT = None
CONTINUITY_COMMIT = None
CONTINUITY_ASSEMBLY = None
CONTINUITY_SCHEMA = "iroha.taira.fixed4.signer-authority.v1"


def _continuity_need(ok, message):
    if not ok:
        raise RuntimeError(message)


def _continuity_open_direct(path, metadata_only=False):
    path = Path(path)
    _continuity_need(
        path.is_absolute() and path == Path(os.path.normpath(path)),
        "Canonical absolute path required",
    )
    directory = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        for part in path.parts[1:-1]:
            child = os.open(
                part,
                os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                dir_fd=directory,
            )
            info = os.fstat(child)
            _continuity_need(
                info.st_uid == 0 and (not info.st_mode & 18),
                "Unsafe authority directory",
            )
            os.close(directory)
            directory = child
        flags = os.O_PATH if metadata_only else os.O_RDONLY
        return os.open(
            path.name, flags | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=directory
        )
    finally:
        os.close(directory)


def _continuity_stamp(info):
    return {
        key: getattr(info, source)
        for key, source in (
            ("device", "st_dev"),
            ("inode", "st_ino"),
            ("size", "st_size"),
            ("mtime_ns", "st_mtime_ns"),
            ("ctime_ns", "st_ctime_ns"),
            ("uid", "st_uid"),
            ("mode", "st_mode"),
            ("nlink", "st_nlink"),
        )
    }


def _continuity_signer_metadata(path):
    fd = _continuity_open_direct(path, metadata_only=True)
    try:
        info = os.fstat(fd)
        _continuity_need(
            stat.S_ISREG(info.st_mode)
            and info.st_mode == stat.S_IFREG | 0o600
            and (info.st_uid == 0)
            and (info.st_nlink == 1)
            and (info.st_size == 71),
            "Retained FD198 source must be root0600, single-link, 71-byte regular file",
        )
        return _continuity_stamp(info)
    finally:
        os.close(fd)


def _continuity_read(path, limit=1024 * 1024, expected=None):
    fd = _continuity_open_direct(path)
    try:
        before = os.fstat(fd)
        _continuity_need(
            stat.S_ISREG(before.st_mode)
            and before.st_uid == 0
            and (before.st_nlink == 1)
            and (not before.st_mode & 18)
            and (before.st_size <= limit),
            "Unsafe public/custody record",
        )
        with os.fdopen(fd, "rb", closefd=False) as source:
            data = source.read(limit + 1)
        _continuity_need(
            len(data) <= limit
            and _continuity_stamp(before) == _continuity_stamp(os.fstat(fd)),
            "Record changed while reading",
        )
        if expected is not None:
            _continuity_need(
                hashlib.sha256(data).hexdigest() == expected,
                "Pinned public record changed",
            )
        return data
    finally:
        os.close(fd)


def _continuity_parse(path, **kwargs):

    def unique(pairs):
        value = {}
        for key, item in pairs:
            _continuity_need(key not in value, "Duplicate JSON key")
            value[key] = item
        return value

    return json.loads(_continuity_read(path, **kwargs), object_pairs_hook=unique)


def _continuity_write(path, value):
    _continuity_need(
        path.parent == CONTINUITY_OUT and CONTINUITY_OUT.resolve() == CONTINUITY_OUT,
        "Output outside private capture directory",
    )
    info = CONTINUITY_OUT.stat()
    _continuity_need(
        info.st_uid == 0 and stat.S_IMODE(info.st_mode) == 0o700,
        "Output directory must be root0700",
    )
    data = (json.dumps(value, sort_keys=True) + "\n").encode()
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as output:
        output.write(data)
        output.flush()
        os.fsync(output.fileno())
    return hashlib.sha256(data).hexdigest()


def _continuity_systemd(unit):
    names = (
        "LoadState",
        "ActiveState",
        "SubState",
        "MainPID",
        "ControlPID",
        "FragmentPath",
        "DropInPaths",
        "NeedDaemonReload",
        "Job",
    )
    value = subprocess.run(
        [
            "/usr/bin/systemctl",
            "show",
            "--all",
            *["--property=" + name for name in names],
            unit,
        ],
        capture_output=True,
        timeout=15,
        check=False,
    )
    _continuity_need(
        value.returncode == 0 and len(value.stdout) <= 16384,
        "Cannot attest systemd unit",
    )
    pairs = [line.split("=", 1) for line in value.stdout.decode().splitlines()]
    _continuity_need(
        all((len(row) == 2 for row in pairs)) and len(pairs) == len(names),
        "Malformed systemd fields",
    )
    result = dict(pairs)
    _continuity_need(
        set(result) == set(names)
        and result["LoadState"] == "loaded"
        and (result["FragmentPath"] == "/etc/systemd/system/" + unit)
        and (result["DropInPaths"] == "")
        and (result["NeedDaemonReload"] == "no")
        and (result["Job"] == ""),
        "Loaded unit differs from approved standalone fragment",
    )
    return result


def _continuity_unit_sources(data, role, renderer):
    lines = [
        line for line in data.decode().splitlines() if line.startswith("ExecStart=")
    ]
    prefix = "ExecStart=/usr/bin/python3 -c "
    _continuity_need(
        len(lines) == 1 and lines[0].startswith(prefix),
        "Unexpected generated unit executable",
    )
    code = json.loads(lines[0][len(prefix) :]).replace("%%", "%").replace("$$", "$")
    fields = {}
    for node in ast.parse(code).body:
        if (
            isinstance(node, ast.Assign)
            and len(node.targets) == 1
            and isinstance(node.targets[0], ast.Name)
        ):
            key = node.targets[0].id
            if key in ("runtime_key", "global_beacon_credential", "cmd"):
                _continuity_need(
                    key not in fields, "Duplicate generated launcher binding"
                )
                fields[key] = ast.literal_eval(node.value)
    _continuity_need(
        set(fields) == {"runtime_key", "global_beacon_credential", "cmd"}
        and fields["global_beacon_credential"] is None,
        "Generated signer bindings incomplete",
    )
    _continuity_need(
        renderer["render"](
            role, fields["runtime_key"]
        ).encode()
        == data,
        "Unit is not exact reviewed FD198 renderer output",
    )
    return fields


def _continuity_load_public_module(path, expected):
    data = _continuity_read(path, limit=256 * 1024, expected=expected)
    namespace = {"__name__": "reviewed_public_helper", "__file__": str(path)}
    exec(compile(data, str(path), "exec"), namespace)
    return namespace


def _continuity_checked_hash_body(value):
    _continuity_need(
        isinstance(value, str) and re.fullmatch("hash:[0-9A-F]{64}#[0-9A-F]{4}", value),
        "Native hash JSON must be an exact checked literal",
    )
    return value[5:69].lower()


def _continuity_topology_peers(manifest):
    """Read the exact four validator identities from the signed genesis topology."""
    _continuity_need(
        isinstance(manifest, dict) and isinstance(manifest.get("transactions"), list),
        "Genesis must contain native transactions and topology",
    )
    peers = []
    for transaction in manifest["transactions"]:
        _continuity_need(
            isinstance(transaction, dict)
            and isinstance(transaction.get("topology", []), list),
            "Genesis transaction topology is malformed",
        )
        for row in transaction.get("topology", []):
            _continuity_need(
                isinstance(row, dict)
                and isinstance(row.get("peer"), str)
                and bool(row["peer"]),
                "Genesis topology peer identity is missing",
            )
            peers.append(row["peer"])
    _continuity_need(
        len(peers) == len(set(peers)) == 4,
        "Exact four distinct native topology peers required",
    )
    return peers


def _continuity_capture(args):
    _continuity_need(
        not os.path.lexists(CONTINUITY_OUT),
        "Pre-start capture already exists; preserve existing evidence",
    )
    inventory_bytes = _continuity_read(CONTINUITY_ASSEMBLY / "inventory.json")
    inventory = json.loads(inventory_bytes)
    _continuity_need(
        inventory["revision"]["commit"] == CONTINUITY_COMMIT
        and inventory["next_genesis_hash"] == args.genesis_hash,
        "Capture must use exact assembled artifact revision and retained public genesis",
    )
    network_id = (
        _continuity_read(CONTINUITY_PREP / "network/genesis.expected_hash")
        .decode()
        .strip()
    )
    _continuity_need(
        re.fullmatch("hash:[0-9A-F]{64}#[0-9A-F]{4}", network_id)
        and network_id[5:69].lower() == args.genesis_hash,
        "Checked native genesis record differs",
    )
    manifest = _continuity_parse(
        CONTINUITY_PREP / "network/genesis.json", limit=32 * 1024 * 1024
    )
    peers = _continuity_topology_peers(manifest)
    renderer = _continuity_load_public_module(
        CONTINUITY_UNIT_RENDERER, CONTINUITY_RENDERER_SHA
    )
    clients = {row["slug"]: row for row in inventory["validator_clients"]}
    _continuity_need(
        len(inventory["validators"]) == len(inventory["validator_clients"]) == len(clients) == 4,
        "Capture requires exactly four distinct validator clients",
    )
    rows = []
    for index, validator in enumerate(inventory["validators"]):
        role = validator["slug"]
        unit = validator["systemd_unit"]
        _continuity_need(
            role == "taira-validator-" + str(index + 1)
            and unit == "iroha3d-" + role + ".service",
            "Validator unit order differs",
        )
        state = _continuity_systemd(unit)
        _continuity_need(
            state["ActiveState"] == "inactive"
            and state["SubState"] == "dead"
            and (state["MainPID"] == state["ControlPID"] == "0"),
            "Capture must precede validator startup",
        )
        data = _continuity_read(
            Path(state["FragmentPath"]), expected=validator["systemd_unit_sha256"]
        )
        fields = _continuity_unit_sources(data, role, renderer)
        artifacts = {row["role"]: row for row in validator["artifacts"]}
        exe = artifacts["iroha3d"]
        config = artifacts["config"]
        expected_cmd = [
            f"/srv/taira/{role}/current/bin/iroha3d_taira",
            "--config",
            f"/srv/taira/{role}/current/config/config.toml",
            "--sora",
        ]
        _continuity_need(
            fields["cmd"] == expected_cmd, "Actual native unit launch argv differs"
        )
        rows.append(
            {
                "peer_id": clients[role]["peer_id"],
                "systemd_unit": unit,
                "signer_path": fields["runtime_key"],
                "signer_fd": 198,
                "signer_file": _continuity_signer_metadata(fields["runtime_key"]),
                "exe_sha256": exe["sha256"],
                "config_sha256": config["sha256"],
                "binding": {
                    "pid_file": None,
                    "systemd_unit": unit,
                    "exe_path": exe["remote_path"],
                    "exe_sha256": exe["sha256"],
                    "config_path": config["remote_path"],
                    "config_sha256": config["sha256"],
                    "config_files": [
                        {"path": config["remote_path"], "sha256": config["sha256"]}
                    ],
                    "uid": 0,
                    "port": 8080 + index,
                    "argv": expected_cmd,
                    "launch_selector": {
                        "path": f"/srv/taira/{role}/current",
                        "target": f"/srv/taira/{role}/releases/{CONTINUITY_COMMIT}",
                    },
                },
                "unit_sha256": validator["systemd_unit_sha256"],
                "node_fingerprint": validator["node_fingerprint"],
                "build_fingerprint": validator["build_fingerprint"],
                "config_fingerprint": validator["config_fingerprint"],
            }
        )
    by_peer = {row["peer_id"]: row for row in rows}
    _continuity_need(
        set(by_peer) == set(peers)
        and len({(r["signer_file"]["device"], r["signer_file"]["inode"]) for r in rows})
        == 4,
        "Runtime signer mapping must cover four distinct native peers/source inodes",
    )
    rows = [by_peer[peer] for peer in peers]
    CONTINUITY_OUT.mkdir(mode=0o700)
    value = {
        "schema": "iroha.taira.fixed4.signer-prestart.v1",
        "commit": CONTINUITY_COMMIT,
        "network_id": network_id,
        "genesis_hash": args.genesis_hash,
        "boot_id": Path("/proc/sys/kernel/random/boot_id").read_text().strip(),
        "earliest_start_ticks": int(
            float(Path("/proc/uptime").read_text().split()[0])
            * os.sysconf("SC_CLK_TCK")
        ),
        "inventory_sha256": hashlib.sha256(inventory_bytes).hexdigest(),
        "nodes": rows,
    }
    digest = _continuity_write(CONTINUITY_OUT / "prestart.json", value)
    print(
        json.dumps(
            {
                "prestart_path": str(CONTINUITY_OUT / "prestart.json"),
                "sha256": digest,
                "signers_read": False,
            }
        )
    )


def beacon_completed_rows(runtime, assembly, before):
    """Bind final process paths to completed native authorization and activation.

    The native controller verifies the bundle, installation inclusion and exact
    private config projection before recording completion. Python consumes only
    its public hashes, after proving that exact completed deployment; an isolated
    activation marker never authorizes a process or a config.
    """
    proof = completed_attempt({"runtime_root": str(runtime)}, assembly.parent, required=True)
    inventory = proof["inventory"]
    frontier = decode(public_record(assembly.parent / "apply-started.json", owner=0, private=True))
    require(before["inventory_sha256"] == frontier["inventory_sha256"],
            "beacon completion belongs to another pre-start inventory")
    plan = inventory["beacon_bootstrap"]
    units = plan["final_units"]
    validators = inventory["validators"]
    clients = inventory["validator_clients"]
    require(len(units) == len(validators) == len(clients) == len(before["nodes"]) == 4,
            "completed beacon projection requires the exact four validators")
    prior = {row["peer_id"]: row for row in before["nodes"]}
    require(len(prior) == 4, "pre-start beacon identities repeat")
    rows = {}
    bundle_sha = None
    for validator, client, unit in zip(validators, clients, units):
        role = validator["slug"]
        require(client["slug"] == unit["validator"] == role and client["peer_id"] in prior,
                "signed final beacon unit or peer order differs")
        row = copy.deepcopy(prior[client["peer_id"]])
        require(row["systemd_unit"] == validator["systemd_unit"],
                "pre-start unit differs from completed validator")
        marker_path = (Path("/var/lib/taira/.public-reset-control-v1/beacon")
                       / inventory["authorization_nonce"] / (role + ".active.json"))
        marker = decode(public_record(marker_path, owner=0, private=True, limit=65536))
        require(isinstance(marker, dict) and set(marker) == {
                    "schema", "authorization_sha256", "bundle_sha256", "validator",
                    "session_id", "config_sha256", "unit_sha256"}
                and marker["schema"] == "iroha.taira.public-reset.beacon-provider-active.v1"
                and marker["authorization_sha256"] == frontier["authorization_sha256"]
                and marker["validator"] == role
                and marker["session_id"] == plan["request"]["dkg_session"]["session_id"]
                and marker["unit_sha256"] == unit["sha256"]
                and all(isinstance(marker[name], str)
                        and re.fullmatch("[0-9a-f]{64}", marker[name])
                        for name in ("bundle_sha256", "config_sha256", "unit_sha256")),
                "native beacon activation differs from exact completed authorization")
        if bundle_sha is None:
            bundle_sha = marker["bundle_sha256"]
        require(marker["bundle_sha256"] == bundle_sha,
                "native beacon activations disagree on the verified bundle")
        config = next((item for item in validator["artifacts"] if item["role"] == "config"), None)
        require(config is not None and row["binding"]["config_path"] == config["remote_path"]
                and row["config_sha256"] == config["sha256"],
                "pre-start config differs from the signed original artifact")
        final_config = str(Path(config["remote_path"]).with_name("beacon.toml"))
        row["unit_sha256"] = marker["unit_sha256"]
        row["config_sha256"] = marker["config_sha256"]
        binding = row["binding"]
        require(binding["argv"].count("--config") == 1
                and binding["argv"][binding["argv"].index("--config") + 1]
                    == f"/srv/taira/{role}/current/config/config.toml",
                "pre-start config argument differs from exact initial renderer")
        binding["argv"][binding["argv"].index("--config") + 1] = f"/srv/taira/{role}/current/config/beacon.toml"
        binding["config_path"] = final_config
        binding["config_sha256"] = marker["config_sha256"]
        binding["config_files"] = [{"path": final_config, "sha256": marker["config_sha256"]}]
        rows[row["peer_id"]] = row
    require(set(rows) == set(prior), "completed beacon projection omitted a peer")
    return [rows[row["peer_id"]] for row in before["nodes"]]


def _continuity_reconcile(args):
    _continuity_need(
        args.prestart_sha256 and args.local_node_module and args.local_node_sha256,
        "Post-start requires exact prestart and reviewed LocalNode pins",
    )
    before = _continuity_parse(
        CONTINUITY_OUT / "prestart.json", expected=args.prestart_sha256
    )
    _continuity_need(
        before["schema"] == "iroha.taira.fixed4.signer-prestart.v1"
        and before["commit"] == CONTINUITY_COMMIT
        and before["genesis_hash"] == args.genesis_hash
        and (
            before["boot_id"]
            == Path("/proc/sys/kernel/random/boot_id").read_text().strip()
        ),
        "Pre-start deployment/boot differs",
    )
    _continuity_read(
        CONTINUITY_ASSEMBLY / "inventory.json", expected=before["inventory_sha256"]
    )
    before["nodes"] = beacon_completed_rows(CONTINUITY_RUNTIME, CONTINUITY_ASSEMBLY, before)
    node_class = _continuity_load_public_module(
        Path(args.local_node_module), args.local_node_sha256
    )["LocalNode"]
    _continuity_need(
        isinstance(getattr(args, "signer_observation_source", None), str)
        and len(args.signer_observation_source) <= 350 * 1024
        and isinstance(getattr(args, "signer_observation_sha256", None), str)
        and re.fullmatch("[0-9a-f]{64}", args.signer_observation_sha256),
        "Explicit maintained signer observation helper required",
    )
    observation_raw = base64.b64decode(args.signer_observation_source, validate=True)
    _continuity_need(
        len(observation_raw) <= 256 * 1024
        and hashlib.sha256(observation_raw).hexdigest() == args.signer_observation_sha256,
        "Exact maintained signer observation helper required",
    )
    observation = {"__name__": "reviewed_signer_observation"}
    exec(compile(observation_raw, "<maintained-signer-observation>", "exec"), observation)
    receipt_rows = []
    observations = []
    genesis_block_hash = None
    for row in before["nodes"]:
        _continuity_need(
            _continuity_signer_metadata(row["signer_path"]) == row["signer_file"],
            "Retained signer changed after pre-start capture",
        )
        state = _continuity_systemd(row["systemd_unit"])
        _continuity_need(
            state["ActiveState"] == "active"
            and state["SubState"] == "running"
            and (int(state["MainPID"]) > 0)
            and (state["ControlPID"] == "0"),
            "Native validator is not running",
        )
        _continuity_read(Path(state["FragmentPath"]), expected=row["unit_sha256"])
        pid = int(state["MainPID"])
        fields = Path(f"/proc/{pid}/stat").read_bytes().rpartition(b") ")[2].split()
        _continuity_need(
            len(fields) >= 20 and int(fields[19]) >= before["earliest_start_ticks"],
            "Running daemon predates continuity capture",
        )
        node, status, attestation = observation["observe_attested_status"](
            node_class, row["binding"], row, before["network_id"], args.genesis_hash
        )
        native_hash = attestation["body"]["genesis_block_hash"]
        if genesis_block_hash is None:
            genesis_block_hash = native_hash
        _continuity_need(
            genesis_block_hash == native_hash,
            "Validators disagree on native genesis identity",
        )
        node.assert_identity()
        _continuity_need(
            _continuity_systemd(row["systemd_unit"]) == state
            and _continuity_signer_metadata(row["signer_path"]) == row["signer_file"],
            "Process/unit/retained signer changed during successful startup observation",
        )
        keys = (
            "peer_id",
            "systemd_unit",
            "signer_path",
            "signer_fd",
            "signer_file",
            "exe_sha256",
            "config_sha256",
        )
        receipt_rows.append({key: row[key] for key in keys})
        observations.append(
            {
                "peer_id": row["peer_id"],
                "binding": row["binding"],
                "main_pid": pid,
                "start_ticks": int(fields[19]),
                "status": status,
                "attestation": attestation,
            }
        )
    _continuity_write(
        CONTINUITY_OUT / "startup-evidence.json",
        {"prestart_sha256": args.prestart_sha256, "nodes": observations},
    )
    _continuity_write(
        CONTINUITY_OUT / "public-process-bindings.json",
        {
            "nodes": [
                {"peer_id": r["peer_id"], "binding": r["binding"]}
                for r in before["nodes"]
            ]
        },
    )
    receipt = {
        "schema": CONTINUITY_SCHEMA,
        "network_id": before["network_id"],
        "genesis_block_hash": genesis_block_hash,
        "nodes": receipt_rows,
    }
    digest = _continuity_write(CONTINUITY_OUT / "signer-authority-receipt.json", receipt)
    print(
        json.dumps(
            {
                "signer_authority_receipt": {
                    "path": str(CONTINUITY_OUT / "signer-authority-receipt.json"),
                    "sha256": digest,
                },
                "public_process_bindings": str(
                    CONTINUITY_OUT / "public-process-bindings.json"
                ),
                "signers_read": False,
            }
        )
    )


# Boot custody and evidence
BOOT_SOURCE_MANIFEST = None
BOOT_SIGNER = None
BOOT_ROOT = None
BOOT_OUT = None
BOOT_NGINX_SHA = None
BOOT_GENESIS = None
BOOT_EXPECTED_MAC = None
BOOT_COMMIT = None
BOOT_BINARY_MANIFEST = None
BOOT_ASSEMBLY = None
BOOT_UNITS = tuple((f"iroha3d-taira-validator-{i}.service" for i in range(1, 5))) + (
    "nginx.service",
)
BOOT_PROPERTIES = (
    "FragmentPath",
    "DropInPaths",
    "NeedDaemonReload",
    "LoadState",
    "ActiveState",
    "SubState",
    "MainPID",
    "ControlPID",
    "InvocationID",
    "ActiveEnterTimestampMonotonic",
    "UnitFileState",
)


def _boot_need(ok, label):
    if not ok:
        raise RuntimeError(label)


def _boot_stamp(m):
    return {
        k: getattr(m, k)
        for k in (
            "st_dev",
            "st_ino",
            "st_uid",
            "st_gid",
            "st_mode",
            "st_nlink",
            "st_size",
            "st_mtime_ns",
            "st_ctime_ns",
        )
    }


def _boot_direct(path):
    for p in (path, *path.parents):
        m = p.lstat()
        _boot_need(
            not stat.S_ISLNK(m.st_mode) and m.st_uid == 0 and (not m.st_mode & 3602),
            "unsafe admitted input path",
        )


def _boot_read(path, sha=None, mode=0o600, limit=1024 * 1024):
    _boot_direct(path)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        before = os.fstat(fd)
        _boot_need(
            stat.S_ISREG(before.st_mode)
            and before.st_nlink == 1
            and (stat.S_IMODE(before.st_mode) == mode)
            and (before.st_size <= limit),
            "unsafe admitted public record",
        )
        data = os.pread(fd, limit + 1, 0)
        _boot_need(
            len(data) == before.st_size
            and _boot_stamp(before)
            == _boot_stamp(os.fstat(fd))
            == _boot_stamp(path.lstat()),
            "admitted record changed",
        )
        if sha:
            _boot_need(
                hashlib.sha256(data).hexdigest() == sha,
                "admitted public record hash differs",
            )
        return data
    finally:
        os.close(fd)


def _boot_write(name, value):
    path = BOOT_OUT / name
    fd = os.open(
        path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600
    )
    with os.fdopen(fd, "w") as out:
        json.dump(value, out, sort_keys=True)
        out.write("\n")
        out.flush()
        os.fsync(out.fileno())
    directory = os.open(BOOT_OUT, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


def _boot_state(unit):
    done = subprocess.run(
        [
            "/usr/bin/systemctl",
            "show",
            "--no-pager",
            "--property=" + ",".join(BOOT_PROPERTIES),
            unit,
        ],
        stdin=subprocess.DEVNULL,
        capture_output=True,
        timeout=15,
        env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"},
    )
    _boot_need(
        done.returncode == 0 and len(done.stdout) <= 8192, "systemd state query failed"
    )
    rows = [line.split("=", 1) for line in done.stdout.decode("ascii").splitlines()]
    _boot_need(all((len(row) == 2 for row in rows)), "invalid systemd state shape")
    result = dict(rows)
    _boot_need(
        len(rows) == len(result) and set(result) == set(BOOT_PROPERTIES),
        "systemd state property mismatch",
    )
    _boot_need(
        result["LoadState"] == "loaded"
        and result["ActiveState"] == "active"
        and (result["SubState"] == "running")
        and result["MainPID"].isdigit()
        and (int(result["MainPID"]) > 0)
        and (result["ControlPID"] == "0"),
        "admitted unit is not currently running",
    )
    _boot_need(
        result["FragmentPath"] == str(Path("/etc/systemd/system") / unit)
        and result["DropInPaths"] == ""
        and (result["NeedDaemonReload"] == "no"),
        "loaded signed unit identity differs",
    )
    _boot_need(
        result["UnitFileState"] in ("enabled", "disabled"),
        "unexpected unit boot registration state",
    )
    return result


def _boot_fragment(unit, sha):
    path = Path("/etc/systemd/system") / unit
    _boot_direct(path)
    m = path.lstat()
    _boot_need(
        stat.S_IMODE(m.st_mode) in (0o600, 0o644), "signed fragment mode differs"
    )
    data = _boot_read(path, sha, stat.S_IMODE(m.st_mode), 128 * 1024)
    _boot_need(
        b"[Install]\n" in data and b"WantedBy=multi-user.target\n" in data,
        "unit lacks reviewed multi-user boot registration",
    )
    return _boot_stamp(path.lstat())


def _boot_link(unit):
    parent = Path("/etc/systemd/system/multi-user.target.wants")
    _boot_direct(parent)
    path = parent / unit
    m = path.lstat()
    _boot_need(
        stat.S_ISLNK(m.st_mode) and m.st_uid == 0 and (m.st_nlink == 1),
        "enabled unit link custody differs",
    )
    target = os.readlink(path)
    _boot_need(_boot_stamp(path.lstat()) == _boot_stamp(m), "enabled unit link changed")
    return {
        "path": str(path),
        "target": target,
        "uid": m.st_uid,
        "metadata": _boot_stamp(m),
    }


def _boot_enabled_link(unit):
    link = _boot_link(unit)
    _boot_need(
        link["target"] in ("../" + unit, str(Path("/etc/systemd/system") / unit)),
        "enabled unit link points elsewhere",
    )
    return {key: link[key] for key in ("path", "target", "uid")}


def _boot_reenable_nginx(prior_link, before, fragment_sha, fragment_metadata):
    unit = "nginx.service"
    fragment_path = "/etc/systemd/system/nginx.service"
    _boot_need(
        prior_link["path"] == "/etc/systemd/system/multi-user.target.wants/nginx.service"
        and prior_link["target"] == "/usr/lib/systemd/system/nginx.service"
        and before["UnitFileState"] == "enabled"
        and before["FragmentPath"] == fragment_path,
        "unexpected nginx boot link repair",
    )
    _boot_write(
        "reenable-intent.json",
        {
            "unit": unit,
            "fragment_path": fragment_path,
            "fragment_sha256": fragment_sha,
            "prior_link": prior_link,
            "used_now": False,
        },
    )
    _boot_need(
        _boot_link(unit) == prior_link
        and _boot_state(unit) == before
        and _boot_fragment(unit, fragment_sha) == fragment_metadata,
        "nginx boot repair identity changed",
    )
    done = subprocess.run(
        ["/usr/bin/systemctl", "reenable", fragment_path],
        stdin=subprocess.DEVNULL,
        capture_output=True,
        timeout=45,
        env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"},
    )
    _boot_write(
        "reenable-result.json",
        {"exit_code": done.returncode, "units": [unit], "used_now": False},
    )
    _boot_need(
        done.returncode == 0, "systemctl reenable failed; preserve private evidence"
    )
    _boot_invariants(before, _boot_state(unit))
    _boot_need(
        _boot_fragment(unit, fragment_sha) == fragment_metadata,
        "signed fragment bytes or metadata changed",
    )
    _boot_enabled_link(unit)


def _boot_process_start_ticks(pid):
    _boot_need(type(pid) is int and pid > 0, "invalid observed process id")
    fd = os.open(f"/proc/{pid}/stat", os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        data = os.read(fd, 4097)
    finally:
        os.close(fd)
    _boot_need(len(data) <= 4096, "unexpected process identity size")
    fields = data.rpartition(b") ")[2].split()
    _boot_need(
        len(fields) >= 20 and fields[19].isdigit(), "process identity is unavailable"
    )
    return int(fields[19])


def _boot_selector(row):
    unit = row["systemd_unit"]
    _boot_need(unit in BOOT_UNITS[:4], "unexpected selector unit")
    role = unit.removeprefix("iroha3d-").removesuffix(".service")
    expected = {
        "path": f"/srv/taira/{role}/current",
        "target": f"/srv/taira/{role}/releases/{BOOT_COMMIT}",
    }
    _boot_need(
        row["binding"]["launch_selector"] == expected,
        "retained selector binding differs",
    )
    path = Path(expected["path"])
    _boot_direct(path.parent)
    m = path.lstat()
    _boot_need(
        stat.S_ISLNK(m.st_mode)
        and m.st_uid == 0
        and (m.st_nlink == 1)
        and (os.readlink(path) == expected["target"]),
        "deployed selector points elsewhere",
    )
    return _boot_stamp(m)


def _boot_invariants(before, after):
    _boot_need(
        {k: v for k, v in before.items() if k != "UnitFileState"}
        == {k: v for k, v in after.items() if k != "UnitFileState"},
        "live unit process or loaded fragment changed while enabling",
    )
    _boot_need(
        after["UnitFileState"] == "enabled", "unit boot registration not enabled"
    )


def _boot_main(request):
    global BOOT_COMMIT
    BOOT_COMMIT = request["commit"]
    _boot_need(
        isinstance(BOOT_COMMIT, str) and re.fullmatch("[0-9a-f]{40}", BOOT_COMMIT),
        "exact signed artifact revision commit required",
    )
    _boot_need(
        os.geteuid() == 0
        and platform.system() == "Linux"
        and (platform.machine() == "aarch64"),
        "approved root ARM64 guest required",
    )
    _boot_need(
        BOOT_EXPECTED_MAC
        in {
            p.read_text().strip().lower()
            for p in Path("/sys/class/net").glob("*/address")
        },
        "approved guest identity differs",
    )
    os.umask(63)
    _boot_direct(BOOT_ROOT)
    _boot_need(
        not os.path.lexists(BOOT_OUT),
        "persistence evidence already exists; preserve it",
    )
    release = json.loads(_boot_read(BOOT_BINARY_MANIFEST, request["transfer_sha256"]))
    _boot_read(BOOT_SOURCE_MANIFEST, request["source_sha256"])
    _boot_need(
        release["commit"] == BOOT_COMMIT and release["all_hashes_verified"] is True,
        "actual transfer differs",
    )
    pre = json.loads(
        _boot_read(BOOT_SIGNER / "prestart.json", request["prestart_sha256"])
    )
    authority = json.loads(
        _boot_read(
            BOOT_SIGNER / "signer-authority-receipt.json", request["authority_sha256"]
        )
    )
    startup = json.loads(_boot_read(BOOT_SIGNER / "startup-evidence.json"))
    _boot_need(
        pre["schema"] == "iroha.taira.fixed4.signer-prestart.v1"
        and pre["commit"] == BOOT_COMMIT
        and pre["genesis_hash"] == BOOT_GENESIS
        and (
            pre["boot_id"]
            == Path("/proc/sys/kernel/random/boot_id").read_text().strip()
        ),
        "pre/post boot identity differs",
    )
    _boot_need(
        authority["schema"] == "iroha.taira.fixed4.signer-authority.v1"
        and authority["network_id"]
        == authority["genesis_block_hash"]
        == pre["network_id"]
        and (len(authority["nodes"]) == 4),
        "actual signer authority proof differs",
    )
    _boot_need(
        startup["prestart_sha256"] == request["prestart_sha256"]
        and len(startup["nodes"]) == 4,
        "post-start process evidence differs",
    )
    inventory = json.loads(
        _boot_read(BOOT_ASSEMBLY / "inventory.json", pre["inventory_sha256"])
    )
    _boot_need(
        inventory["revision"]["commit"] == BOOT_COMMIT
        and inventory["next_genesis_hash"] == BOOT_GENESIS,
        "assembled signed deployment differs",
    )
    pre["nodes"] = beacon_completed_rows(BOOT_ROOT, BOOT_ASSEMBLY, pre)
    validators = inventory["validators"]
    _boot_need(
        len(validators) == 4
        and tuple((v["systemd_unit"] for v in validators)) == BOOT_UNITS[:4],
        "exact four signed units required",
    )
    hashes = {row["systemd_unit"]: row["unit_sha256"] for row in pre["nodes"]}
    hashes["nginx.service"] = BOOT_NGINX_SHA
    _boot_need(
        inventory["edge"]["systemd_unit_sha256"] == BOOT_NGINX_SHA,
        "approved edge fragment differs",
    )
    peers = {row["peer_id"]: row for row in pre["nodes"]}
    _boot_need(
        len(peers) == 4
        and {row["peer_id"] for row in authority["nodes"]} == set(peers),
        "signer authority peer binding differs",
    )
    pids = {
        peers[row["peer_id"]]["systemd_unit"]: row["main_pid"]
        for row in startup["nodes"]
    }
    starts = {
        peers[row["peer_id"]]["systemd_unit"]: row["start_ticks"]
        for row in startup["nodes"]
    }
    _boot_need(
        set(pids) == set(BOOT_UNITS[:4]), "startup evidence does not cover four units"
    )
    before = {unit: _boot_state(unit) for unit in BOOT_UNITS}
    metadata = {unit: _boot_fragment(unit, hashes[unit]) for unit in BOOT_UNITS}
    _boot_need(
        all(
            (
                int(before[unit]["MainPID"]) == pids[unit]
                and _boot_process_start_ticks(pids[unit]) == starts[unit]
                for unit in BOOT_UNITS[:4]
            )
        ),
        "validator restarted since actual post-start proof",
    )
    selectors = {row["systemd_unit"]: _boot_selector(row) for row in pre["nodes"]}
    repairs = {}
    for unit in BOOT_UNITS:
        if before[unit]["UnitFileState"] == "enabled":
            link = _boot_link(unit)
            if (
                unit == "nginx.service"
                and link["target"] == "/usr/lib/systemd/system/nginx.service"
            ):
                repairs[unit] = link
            else:
                _boot_enabled_link(unit)
    BOOT_OUT.mkdir(mode=0o700)
    _boot_write(
        "before.json",
        {
            "commit": BOOT_COMMIT,
            "units": before,
            "fragment_metadata": metadata,
            "fragment_sha256": hashes,
        },
    )
    disabled = [
        unit for unit in BOOT_UNITS if before[unit]["UnitFileState"] == "disabled"
    ]
    if repairs:
        _boot_reenable_nginx(
            repairs["nginx.service"],
            before["nginx.service"],
            hashes["nginx.service"],
            metadata["nginx.service"],
        )
    if disabled:
        done = subprocess.run(
            ["/usr/bin/systemctl", "enable", *disabled],
            stdin=subprocess.DEVNULL,
            capture_output=True,
            timeout=45,
            env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"},
        )
        _boot_write(
            "enable-result.json",
            {"exit_code": done.returncode, "units": disabled, "used_now": False},
        )
        _boot_need(
            done.returncode == 0, "systemctl enable failed; preserve private evidence"
        )
    after = {unit: _boot_state(unit) for unit in BOOT_UNITS}
    for unit in BOOT_UNITS:
        _boot_invariants(before[unit], after[unit])
        _boot_need(
            _boot_fragment(unit, hashes[unit]) == metadata[unit],
            "signed fragment bytes or metadata changed",
        )
    _boot_need(
        all(
            (
                _boot_process_start_ticks(pids[unit]) == starts[unit]
                for unit in BOOT_UNITS[:4]
            )
        ),
        "validator process identity changed during enable",
    )
    _boot_need(
        {row["systemd_unit"]: _boot_selector(row) for row in pre["nodes"]} == selectors,
        "retained selector metadata changed during enable",
    )
    links = {unit: _boot_enabled_link(unit) for unit in BOOT_UNITS}
    result = {
        "schema": "taira.guest-boot-persistence.v1",
        "commit": BOOT_COMMIT,
        "genesis_hash": BOOT_GENESIS,
        "passed": True,
        "enabled_units": list(BOOT_UNITS),
        "changed_units": [
            unit for unit in BOOT_UNITS if unit in disabled or unit in repairs
        ],
        "signed_fragments_unchanged": True,
        "main_pids_unchanged": True,
        "process_start_ticks_unchanged": True,
        "retained_selectors_unchanged": True,
        "services_restarted": False,
        "runtime_secrets_read": False,
        "links": links,
    }
    _boot_write("result.json", result)
    print(json.dumps(result, sort_keys=True))


def local_arguments(raw, qualification_scope):
    """Admit the exact recorded native input argument shape, containing paths only."""
    value = decode(raw)
    qualification_steps(qualification_scope)
    shape = (
        ("--public-inputs", 1),
        ("--runtime-client-config", 1),
        ("--validator-client-config", 4),
        ("--validator-operator-key", 1),
        ("--onboarding-token", 1),
    ) + ((("--inrou-stage-dir", 1),) if qualification_scope == "full_inrou" else ()) + (
        ("--validator-unit", 4),
        ("--native-edge-capability", 1),
        ("--known-hosts", 1),
    )
    require(
        isinstance(value, list) and len(value) == sum(count + 1 for _, count in shape),
        "exact native local argument closure required",
    )
    result = {}
    offset = 0
    for flag, count in shape:
        require(value[offset] == flag, "native local argument order differs")
        paths = value[offset + 1 : offset + count + 1]
        require(
            all(
                isinstance(path, str)
                and path.startswith("/")
                and "\x00" not in path
                and "\n" not in path
                and Path(path) == Path(os.path.normpath(path))
                for path in paths
            ),
            "native local arguments must be canonical paths",
        )
        result[flag] = paths
        offset += count + 1
    return value, result


def apply_arguments(arguments, qualification_scope):
    """Apply receives runtime paths only, never public assembly or unit inputs."""
    qualification_steps(qualification_scope)
    flags = ["--runtime-client-config", "--validator-client-config",
             "--validator-operator-key", "--onboarding-token"]
    if qualification_scope == "full_inrou":
        flags.append("--inrou-stage-dir")
    return [item for flag in flags for item in [flag, *arguments[flag]]]


def prepare_beacon_arguments(cli, assembly, plan, static_args, arguments, draft, previous, logs):
    """Use native public derivation and the pinned renderer; never load a key/config."""
    bundle = assembly / "public-inputs"
    inputs = assembly / "beacon-inputs.json"
    run_native([
        *cli, "prepare-beacon-inputs", "--intent", assembly / "topology-intent.json",
        "--public-inputs", bundle, "--output", inputs,
    ], logs / "prepare-beacon-inputs", phase="prepare-beacon-inputs")
    value = decode(public_record(inputs, owner=0, private=True))
    require(isinstance(value, dict)
            and set(value) == {"schema", "authorization_nonce", "request", "final_units"}
            and value["schema"] == "iroha.taira.public-reset.beacon-inputs.v1"
            and value["authorization_nonce"] == draft["authorization_nonce"]
            and isinstance(value["request"], dict)
            and isinstance(value["final_units"], list) and len(value["final_units"]) == 4,
            "native beacon inputs differ from this exact fresh attempt")
    validators = draft["validators"]
    require(len(validators) == 4 and len(arguments["--validator-unit"]) == 4,
            "beacon preparation requires four exact validator units")
    seen = set()
    # Admit all public descriptors before executing even the authenticated renderer.
    for index, (validator, row) in enumerate(zip(validators, value["final_units"]), 1):
        require(isinstance(row, dict)
                and set(row) == {"validator", "signer_index", "credential_path", "config_file"}
                and row["validator"] == validator["slug"] == f"taira-validator-{index}"
                and type(row["signer_index"]) is int and 1 <= row["signer_index"] <= 4
                and row["signer_index"] not in seen and row["config_file"] == "beacon.toml",
                "native beacon unit descriptors omit, repeat or reorder a validator seat")
        seat = row["signer_index"]
        expected = (Path("/var/lib/taira/.public-reset-control-v1/beacon")
                    / draft["authorization_nonce"] / "ceremony" / f"seat-{seat}"
                    / "iroha-global-beacon-partial-signer-v1.norito")
        require(row["credential_path"] == str(expected),
                "native beacon credential path differs from its nonce and signer seat")
        seen.add(seat)
    renderer = _continuity_load_public_module(
        Path(plan["unit_renderer"]["path"]), plan["unit_renderer"]["sha256"])
    units = assembly / "beacon-units"
    units.mkdir(mode=0o700)
    paths = []
    for validator, retained, row, initial in zip(validators, previous["validators"], value["final_units"], arguments["--validator-unit"]):
        require(validator["slug"] == retained["slug"], "retained unit validator order differs")
        data = public_record(initial, retained["systemd_unit_sha256"], owner=0)
        fields = _continuity_unit_sources(data, validator["slug"], renderer)
        rendered = renderer["render"](
            validator["slug"], fields["runtime_key"],
            row["credential_path"], config_file=row["config_file"])
        require(isinstance(rendered, str), "authenticated renderer omitted exact unit text")
        path = units / validator["systemd_unit"]
        require(path.parent == units and path.name == f"iroha3d-{validator['slug']}.service",
                "signed validator unit filename differs")
        write_public_bytes(path, rendered.encode(), mode=0o644)
        paths.append(str(path))
    # Keep the static retained closure intact; derived arguments have distinct custody.
    derived = list(static_args)
    derived[derived.index("--public-inputs") + 1] = str(bundle)
    derived.extend(["--beacon-inputs", str(inputs), "--beacon-validator-unit", *paths])
    write_public(assembly / "native-local-args.json", list(static_args))
    write_public(assembly / "native-assembly-args.json", derived)
    return derived




def find_terminal(journal_root, deployment_id):
    """Read only bounded public terminal records; never infer rollback from process exit."""
    matches = []
    paths = sorted((journal_root / "rolled-back").glob("*.json"))
    require(len(paths) <= 4096, "terminal inventory exceeds bounded lookup")
    for path in paths:
        require(
            re.fullmatch(r"[0-9a-f]{64}\.json", path.name),
            "noncanonical terminal filename",
        )
        value = decode(public_record(path, owner=0, private=True, limit=1024 * 1024))
        if value.get("deployment_id") == deployment_id:
            matches.append(path)
    require(
        len(matches) == 1,
        "no unique completed rollback; pending mutation must not be replayed",
    )
    return matches[0]


def preflight_identity(attempt, inventory):
    """Bind the durable apply frontier to the native signed-input admission report."""
    assembly = attempt / "assembly"
    raw_inventory = public_record(assembly / "inventory.json", owner=0, private=True)
    raw_authorization = public_record(
        assembly / "authorization.json", owner=0, private=True
    )
    report = decode(
        public_record(attempt / "native/preflight/stdout", owner=0, private=True)
    )
    inventory_sha = hashlib.sha256(raw_inventory).hexdigest()
    require(
        report["schema"] == "iroha.taira.public-reset.report.v1"
        and report["command"] == "preflight"
        and report["status"] == "ok"
        and inventory.get("qualification_scope") in ("core_testnet", "full_inrou")
        and report.get("qualification_scope") == inventory["qualification_scope"]
        and report["deployment_id"] == inventory["deployment_id"]
        and report["revision"] == inventory["revision"]["commit"]
        and report["inventory_sha256"] == inventory_sha
        and re.fullmatch("[0-9a-f]{64}", report["authorization_sha256"]),
        "native preflight identity differs from exact apply inputs",
    )
    return {
        "deployment_id": inventory["deployment_id"],
        "qualification_scope": inventory["qualification_scope"],
        "authorization_nonce": inventory["authorization_nonce"],
        "inventory_sha256": inventory_sha,
        "authorization_sha256": report["authorization_sha256"],
        "authorization_file_sha256": hashlib.sha256(raw_authorization).hexdigest(),
        "automatic_replay": False,
    }


def completed_attempt(plan, attempt, *, required=False):
    """Authenticate exact native completed and deployment-proven receipts; never infer success."""
    inventory = decode(
        public_record(attempt / "assembly/inventory.json", owner=0, private=True)
    )
    frontier = decode(
        public_record(attempt / "apply-started.json", owner=0, private=True)
    )
    require(
        frontier == preflight_identity(attempt, inventory),
        "durable apply identity differs",
    )
    journal = Path(plan["runtime_root"]) / "journal-v1"
    name = frontier["authorization_sha256"] + ".json"
    path = journal / "completed" / name
    if not path.exists():
        require(not required, "exact native completed receipt is missing")
        return None
    raw = public_record(path, owner=0, private=True)
    value = decode(raw)
    expected = {
        "schema": "iroha.taira.public-reset.journal.v1",
        "deployment_id": inventory["deployment_id"],
        "qualification_scope": inventory["qualification_scope"],
        "inventory_sha256": frontier["inventory_sha256"],
        "authorization_sha256": frontier["authorization_sha256"],
        "authorization_nonce": inventory["authorization_nonce"],
        "status": "completed",
        "phase": "completed",
        "next_step": len(qualification_steps(inventory["qualification_scope"])),
        "recovery_intent": None,
        "touched_validators": [row["slug"] for row in inventory["validators"]],
        "edge_touched": True,
        "edge_rollback_complete": False,
        "rollback_next_validator": 0,
        "failure_summary": "",
        "rollback_failures": [],
    }
    require(value == expected, "native receipt is not this exact completed deployment")
    require(
        not (journal / (inventory["deployment_id"] + ".journal.json")).exists()
        and not (journal / "rolled-back" / name).exists()
        and not (journal / "aborted-before-mutation" / name).exists(),
        "completed receipt conflicts with retained native execution state",
    )
    proven = decode(
        public_record(journal / "deployment-proven" / name, owner=0, private=True)
    )
    require(
        proven == dict(expected, status="sealing", phase="seal", next_step=len(qualification_steps(inventory["qualification_scope"])) - 2),
        "native completed receipt lacks its exact deployment proof",
    )
    return {
        "path": str(path),
        "sha256": hashlib.sha256(raw).hexdigest(),
        "inventory": inventory,
    }


def previous_attempt(plan):
    """Resume before the durable apply frontier; afterward require real native rollback."""
    root = Path(plan["attempts_root"])
    pointer = root / "latest.json"
    if not pointer.exists():
        return (
            Path(plan["previous_inventory"]),
            Path(plan["previous_terminal"]),
            Path(plan["local_args_path"]),
            None,
        )
    latest = decode(public_record(pointer, owner=0, private=True))
    require(
        set(latest)
        == {
            "schema",
            "attempt_id",
            "deployment_id",
            "inventory_path",
            "local_args_path",
            "retained_inventory",
            "retained_terminal",
            "retained_local_args",
            "custody_plan_sha256",
        }
        and latest["schema"] == "taira.retry-latest.v1",
        "invalid retained attempt pointer",
    )
    attempt = root / latest["attempt_id"]
    require(
        re.fullmatch(r"retry-[0-9]{16,24}-[0-9a-f]{8}", latest["attempt_id"])
        and latest["deployment_id"] == "taira-" + latest["attempt_id"]
        and Path(latest["inventory_path"]) == attempt / "assembly/inventory.json"
        and Path(latest["local_args_path"])
        == attempt / "assembly/native-local-args.json",
        "retained attempt pointer escaped its generated scope",
    )
    require(
        latest["custody_plan_sha256"] == custody_plan_digest(plan),
        "pending attempt custody plan changed",
    )
    if not (attempt / "apply-started.json").exists():
        require(
            not (attempt / "result.json").exists()
            and not (attempt / "boot-persistence").exists(),
            "post-apply evidence exists without its durable apply frontier",
        )
        return (
            Path(latest["retained_inventory"]),
            Path(latest["retained_terminal"]),
            Path(latest["retained_local_args"]),
            latest["attempt_id"],
        )
    completed = completed_attempt(plan, attempt)
    if completed is not None:
        return (
            Path(latest["inventory_path"]),
            Path(completed["path"]),
            Path(latest["local_args_path"]),
            latest["attempt_id"],
        )
    terminal = find_terminal(
        Path(plan["runtime_root"]) / "journal-v1", latest["deployment_id"]
    )
    return (
        Path(latest["inventory_path"]),
        terminal,
        Path(latest["local_args_path"]),
        None,
    )


def custody_plan_digest(plan):
    """Capacity can be increased after a deficiency; runtime authority stays identical."""
    value = {key: item for key, item in plan.items() if key != "capacity_plan"}
    return hashlib.sha256(json.dumps(value, sort_keys=True).encode()).hexdigest()


def preserve_preapply_outputs(attempt):
    """Retain incomplete preparation evidence before an authorized preapply resume."""
    require(
        not (attempt / "apply-started.json").exists(),
        "native apply frontier forbids preapply replay",
    )
    names = {"assembly", "signer-continuity", "native", "failure.json"}
    names.update(path.name for path in attempt.glob("*-phase.json"))
    names.update(path.name for path in attempt.glob("capacity-*.json"))
    existing = [attempt / name for name in sorted(names) if (attempt / name).exists()]
    if not existing:
        return
    archive = attempt / ("preapply-evidence-" + str(time.time_ns()))
    archive.mkdir(mode=0o700)
    for source in existing:
        require(
            source.resolve() == source and not source.is_symlink(),
            "preapply evidence escaped attempt",
        )
        os.rename(source, archive / source.name)
    sync_directory(archive)
    sync_directory(attempt)


def configure_protocols(
    plan, inventory, inventory_path, terminal_path, attempt, binary, arguments
):
    """Bind the existing custody/evidence algorithms to this attempt, without text rewrites."""
    commit = inventory["revision"]["commit"]
    cli_sha = next(
        row["sha256"] for row in binary["artifacts"] if row["name"] == "iroha"
    )
    runtime = Path(plan["runtime_root"])
    require(
        terminal_path.parent
        in (runtime / "journal-v1/rolled-back", runtime / "journal-v1/completed")
        and terminal_path.name.endswith(".json"),
        "terminal is outside native authority",
    )
    values = {
        "RETIRE_SUPPORT": Path(plan["guard_support"]["path"]),
        "RETIRE_SUPPORT_SHA": plan["guard_support"]["sha256"],
        "RETIRE_TRUST_HASH": hashlib.sha256(
            public_record(plan["trusted_public_key"], owner=0, private=True)
        ).hexdigest(),
        "RETIRE_NGINX_UNIT_HASH": inventory["edge"]["systemd_unit_sha256"],
        "RETIRE_RETAINED_UNITS": {
            row["systemd_unit"]: row["systemd_unit_sha256"]
            for row in inventory["validators"]
        },
        "RETIRE_UNIT_PATHS": {
            Path(path).name: Path(path) for path in arguments["--validator-unit"]
        },
        "RETIRE_RUNTIME": runtime,
        "RETIRE_CONTROL": Path("/var/lib/taira/.public-reset-control-v1"),
        "RETIRE_DISPATCHER": Path("/usr/local/libexec/iroha-taira-public-reset-v1"),
        "RETIRE_WORK": attempt / "retirement",
        "RETIRE_COMMIT": commit,
        "RETIRE_CLI_SHA": cli_sha,
        "RETIRE_TERMINAL": terminal_path,
        "RETIRE_RETAINED_DEPLOYMENT": inventory["deployment_id"],
        "RETIRE_INVENTORY_PATH": inventory_path,
        "RETIRE_BINARY_MANIFEST": Path(plan["binary_manifest"]),
        "RETIRE_BINS": Path(binary["destination"]),
        "RETIRE_PUBLIC_IMPORTS": copy.deepcopy(plan["retired_public_imports"]),
        "RETIRE_PROTECTED_INPUTS": [str(path) for path in (
            Path(inventory["revision"]["source_root"]), Path(binary["destination"]),
            *(Path(plan[key]) for key in ("source_manifest", "binary_manifest", "signing_key",
                "trusted_public_key", "ssh_identity", "known_hosts")),
            *(Path(path) for key in ("--runtime-client-config", "--validator-client-config",
                "--validator-operator-key", "--onboarding-token") for path in arguments[key]),
        )],
        "CONTINUITY_RUNTIME": runtime,
        "CONTINUITY_PREP": Path(plan["prep_root"]),
        "CONTINUITY_ASSEMBLY": attempt / "assembly",
        "CONTINUITY_OUT": attempt / "signer-continuity",
        "CONTINUITY_UNIT_RENDERER": Path(plan["unit_renderer"]["path"]),
        "CONTINUITY_RENDERER_SHA": plan["unit_renderer"]["sha256"],
        "CONTINUITY_COMMIT": commit,
        "BOOT_ROOT": runtime,
        "BOOT_OUT": attempt / "boot-persistence",
        "BOOT_COMMIT": commit,
        "BOOT_GENESIS": inventory["next_genesis_hash"],
        "BOOT_NGINX_SHA": inventory["edge"]["systemd_unit_sha256"],
        "BOOT_BINARY_MANIFEST": Path(plan["binary_manifest"]),
        "BOOT_SOURCE_MANIFEST": Path(plan["source_manifest"]),
        "BOOT_SIGNER": attempt / "signer-continuity",
        "BOOT_ASSEMBLY": attempt / "assembly",
        "BOOT_EXPECTED_MAC": plan["expected_mac"],
    }
    globals().update(values)


def require_same_inventory_artifacts(inventory, binary, source):
    """Config and release paths stay unchanged only for exactly identical built artifacts."""
    commit = binary["commit"]
    require(
        inventory["revision"]["commit"] == commit
        and inventory["revision"]["source_root"] == source["source_root"],
        "changed-artifact rollout requires the preparation/transfer workflow",
    )
    expected = {row["name"]: row["sha256"] for row in binary["artifacts"]}
    roles = {
        "iroha_cli": "iroha",
        "iroha3d": "iroha3d_taira",
        "sorafs_node": "sorafs-node",
        "kagami": "kagami",
    }
    for host in inventory["validators"] + [inventory["edge"]]:
        for artifact in host["artifacts"]:
            if artifact["role"] in roles:
                name = roles[artifact["role"]]
                require(
                    artifact["sha256"] == expected[name]
                    and artifact["local_path"]
                    == str(Path(binary["destination"]) / name),
                    "previous inventory does not use the exact retained artifact set",
                )


def capacity_module(source):
    namespace = {"__name__": "retry_capacity"}
    exec(
        compile(
            base64.b64decode(source, validate=True), "<maintained-capacity>", "exec"
        ),
        namespace,
    )
    return namespace


def validate_full_capacity(module, plan, qualification_scope):
    """Require every allocation for the signed native scope."""
    qualification_steps(qualification_scope)
    rows = module["validate_plan"](plan)
    if qualification_scope == "core_testnet":
        expected = {"coordinator artifact snapshot", "per-role artifact uploads", "per-role installed artifacts", "guest filesystem headroom"}
        require(len(rows) == 4 and {row["label"] for row in rows} == expected,
                "core capacity requires exactly 3A plus headroom, without Inrou allocations")
        require(all(row["bytes"] > 0 and row["inodes"] > 0 for row in rows), "core allocation bounds must be positive")
        require(next(row for row in rows if row["label"] == "guest filesystem headroom")["bytes"] >= 2 * 1024**3, "core capacity requires explicit 2 GiB headroom")
        return
    expected = {
        "coordinator artifact snapshot",
        "per-role artifact uploads",
        "per-role installed artifacts",
        "coordinator Inrou stage snapshot",
        "host-scoped Inrou stage upload",
    }
    expected.update("preseed store " + str(index) for index in range(1, 5))
    expected.update("runtime replica " + str(index) for index in range(1, 5))
    by_label = {row["label"]: row for row in rows}
    require(
        len(by_label) == len(rows) and expected <= set(by_label),
        "capacity plan must include complete3A+2S+4P+4R and explicit headroom",
    )
    require(
        all(
            by_label[label]["bytes"] > 0 and by_label[label]["inodes"] > 0
            for label in expected
        ),
        "native allocation bounds must be positive",
    )
    for prefix in ("preseed store ", "runtime replica "):
        require(
            len({by_label[prefix + str(index)]["path"] for index in range(1, 5)}) == 4,
            "four distinct per-validator allocation paths required",
        )
    headroom = [row for row in rows if row["label"] not in expected]
    require(
        headroom and sum(row["bytes"] for row in headroom) >= 2 * 1024**3,
        "at least2GiB explicit filesystem headroom required",
    )


def check_capacity(module, plan, phase, directory=None):
    result = module["evaluate"](plan)
    if directory is not None:
        write_public(directory / ("capacity-" + phase + ".json"), result)
    require(
        result["passed"] is True,
        "insufficient capacity before " + phase + ": " + "; ".join(result["errors"]),
    )
    return result


def authorize_native(cli, assembly, args, plan, log):
    """Open the owner key read-only and let the native strict FD reader consume it."""
    signer = os.open(
        plan["signing_key"], os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK
    )
    try:
        info = os.fstat(signer)
        require(
            3 <= signer <= 65535
            and stat.S_ISREG(info.st_mode)
            and info.st_uid == 0
            and info.st_nlink == 1
            and stat.S_IMODE(info.st_mode) in (0o400, 0o600),
            "unsafe native signing descriptor",
        )
        return run_native(
            [
                *cli,
                "authorize",
                "--inventory",
                assembly / "inventory.json",
                *args,
                "--trusted-public-key",
                plan["trusted_public_key"],
                "--signing-key-fd",
                signer,
                "--output",
                assembly / "authorization.json",
            ],
            log,
            phase="authorize",
            pass_fds=(signer,),
        )
    finally:
        os.close(signer)


def call_phase(name, callback, attempt):
    started = time.monotonic()
    emit(name, started, status="started", private_attempt=str(attempt))
    try:
        result = callback()
    except BaseException as error:
        write_public(
            attempt / (name + "-phase.json"),
            {
                "phase": name,
                "passed": False,
                "error_type": type(error).__name__,
                "elapsed_seconds": round(time.monotonic() - started, 3),
            },
        )
        raise
    write_public(
        attempt / (name + "-phase.json"),
        {
            "phase": name,
            "passed": True,
            "elapsed_seconds": round(time.monotonic() - started, 3),
        },
    )
    emit(name, started, status="passed", private_attempt=str(attempt))
    return result


def derive_runtime_paths(plan, binary, inventory, arguments):
    """Derive deployment-independent paths from the admitted previous assembly."""
    qualification_steps(inventory.get("qualification_scope"))
    value = copy.deepcopy(plan)
    runtime = Path(value["runtime_root"])
    previous = Path(value["previous_inventory"])
    require(
        previous.is_relative_to(runtime), "previous inventory escaped private runtime"
    )
    prep = Path(arguments["--runtime-client-config"][0]).parent
    require(
        arguments["--runtime-client-config"] == [str(prep / "runtime-client.toml")]
        and arguments["--validator-client-config"]
        == [str(prep / f"validator-{index}-client.toml") for index in range(1, 5)]
        and arguments["--public-inputs"] == [str(prep / "public-inputs")]
        and ((arguments.get("--inrou-stage-dir") == [str(prep / "inrou-stage")])
             if inventory["qualification_scope"] == "full_inrou" else "--inrou-stage-dir" not in arguments)
        and arguments["--onboarding-token"]
        == [str(prep / "network/runtime/onboarding.token")],
        "retained native arguments do not identify one canonical preparation",
    )
    value.update(
        qualification_scope=inventory["qualification_scope"],
        attempts_root=str(runtime / "retry-v1"),
        binary_manifest=str(
            Path(binary["destination"]).parent / "verified-manifest.json"
        ),
        local_args_path=str(previous.parent / "native-local-args.json"),
        prep_root=str(prep),
        known_hosts=arguments["--known-hosts"][0],
    )
    require(
        inventory["revision"]["commit"] == binary["commit"],
        "retained source differs from actual artifacts",
    )
    return value


def public_file_metadata(path):
    """Inspect file metadata only, including when the native artifact is a config."""
    path = direct(path)
    before = path.lstat()
    require(
        stat.S_ISREG(before.st_mode)
        and before.st_uid == 0
        and before.st_nlink == 1
        and not before.st_mode & 0o022,
        "unsafe capacity input metadata",
    )
    require(
        identity(before) == identity(path.lstat()),
        "capacity input changed during metadata inspection",
    )
    return {
        "path": str(path),
        "bytes": before.st_size,
        "allocated_bytes": before.st_blocks * 512,
        "device": before.st_dev,
        "inode": before.st_ino,
        "mtime_ns": before.st_mtime_ns,
        "ctime_ns": before.st_ctime_ns,
    }


def measured_capacity_inputs(inventory, stage):
    """Measure native artifact metadata and, only for full_inrou, its public SF1 stage."""
    scope = inventory.get("qualification_scope")
    qualification_steps(scope)
    require((scope == "core_testnet" and stage is None) or (scope == "full_inrou" and stage is not None), "stage argument does not match signed capacity scope")
    rows = []
    for host in inventory["validators"] + [inventory["edge"]]:
        for artifact in host["artifacts"]:
            metadata = public_file_metadata(artifact["local_path"])
            require(
                metadata["bytes"] == artifact["size"],
                "retained artifact metadata differs from native inventory",
            )
            rows.append(
                {
                    "slug": host["slug"],
                    "role": artifact["role"],
                    "bytes": metadata["bytes"],
                    "local_metadata": metadata,
                }
            )
    if scope == "core_testnet":
        require("inrou_canary" in inventory and inventory["inrou_canary"] is None
                and "inrou_stage_tree_sha256" in inventory and inventory["inrou_stage_tree_sha256"] is None,
                "core_testnet must not carry Inrou capacity inputs")
        require(rows, "core artifact metadata is empty")
        space = os.statvfs(rows[0]["local_metadata"]["path"])
        return {"schema": "taira.public-capacity-inputs.v1", "qualification_scope": scope,
                "secret_contents_read": False, "commit": inventory["revision"]["commit"], "artifacts": rows,
                "inventory_inrou_stage_bytes": None, "stage_files": [], "stage_directories": [],
                "native_sf1_manifest_bindings": None,
                "filesystem": {"fragment_bytes": space.f_frsize or space.f_bsize}}, None
    stage = direct(stage)
    directories, files = [], []
    for parent, children, names in os.walk(stage, followlinks=False):
        require(
            len(directories) < 64 and len(files) + len(names) <= 1024,
            "public stage metadata exceeds bound",
        )
        for name in [parent, *(str(Path(parent) / child) for child in children)]:
            path = direct(name)
            info = path.lstat()
            require(
                stat.S_ISDIR(info.st_mode)
                and info.st_uid == 0
                and not info.st_mode & 0o022,
                "unsafe public stage directory",
            )
        directories.append(parent)
        files.extend(
            public_file_metadata(Path(parent) / name) for name in sorted(names)
        )
    space = os.statvfs(stage)
    inputs = {
        "schema": "taira.public-capacity-inputs.v1",
        "qualification_scope": scope,
        "secret_contents_read": False,
        "commit": inventory["revision"]["commit"],
        "artifacts": rows,
        "inventory_inrou_stage_bytes": inventory["inrou_canary"]["stage_bytes"],
        "stage_files": files,
        "stage_directories": directories,
        "filesystem": {"fragment_bytes": space.f_frsize or space.f_bsize},
    }
    # Native assembly admitted each canonical manifest against the default SF1
    # chunker. Bind that existing proof to the tiny manifest bytes observed now;
    # a same-sized custom profile must not reuse the 64 KiB capacity bound.
    bindings = {}
    for role, name in (
        ("bundle", "bundle.to"),
        ("guest", "aarch64.to"),
        ("discovery", "discovery.to"),
    ):
        digest = hashlib.sha256(
            public_record(stage / "manifests" / name, owner=0, limit=1024 * 1024)
        ).hexdigest()
        require(
            digest == inventory["inrou_canary"][role + "_manifest_sha256"],
            "public chunk manifest differs from native SF1 admission",
        )
        bindings[role] = digest
    inputs["native_sf1_manifest_bindings"] = bindings
    container = decode(
        public_record(stage / "container.json", owner=0, limit=1024 * 1024)
    )
    service = decode(public_record(stage / "service.json", owner=0, limit=1024 * 1024))
    compressed = public_record(
        stage / "payloads/bundle.bin", owner=0, limit=8 * 1024 * 1024
    )
    try:
        with gzip.GzipFile(fileobj=io.BytesIO(compressed)) as source:
            decoded = source.read(64 * 1024 * 1024 + 1)
        require(
            len(decoded) <= 64 * 1024 * 1024,
            "public bundle decoded metadata exceeds bound",
        )
        members = []
        with tarfile.open(fileobj=io.BytesIO(decoded), mode="r:") as archive:
            for member in archive:
                require(
                    len(members) < 1024 and (member.isfile() or member.isdir()),
                    "public bundle has unsupported member geometry",
                )
                members.append(
                    {
                        "path": member.name,
                        "kind": "file" if member.isfile() else "directory",
                        "bytes": member.size,
                    }
                )
    except (OSError, EOFError, tarfile.TarError):
        raise RetryError("public bundle metadata could not be decoded") from None
    runtime = {
        "schema": "taira.public-runtime-capacity-inputs.v1",
        "secret_contents_read": False,
        "payload_contents_printed": False,
        "source_stage": str(stage),
        "container_resources": container["resources"],
        "lease_volumes": service["lease_volumes"],
        "service_artifacts": service["artifacts"],
        "bundle_members": members,
        "bundle_compressed_bytes": len(compressed),
        "bundle_archive_decoded_bytes": len(decoded),
    }
    # The public JSON/archive reads and the metadata observation must describe the same files.
    require(
        all(public_file_metadata(row["path"]) == row for row in files),
        "public stage changed while deriving runtime capacity",
    )
    return inputs, runtime


def execution_intent(request):
    intent = request.get("intent")
    require(intent in ("retirement", "deployment"), "explicit retry execution intent required")
    return intent


def retirement_capacity_plans(runtime_root, backing_path, binary, retired_import_count=0):
    """Bound dispatcher/custody records plus each declared import retirement intent."""
    require(type(retired_import_count) is int and 0 <= retired_import_count <= RETIRE_IMPORT_MAX_COUNT,
            "retired public import count exceeds capacity bounds")
    rows = [row for row in binary["artifacts"] if row["name"] == "iroha"]
    require(len(rows) == 1 and type(rows[0]["size"]) is int and rows[0]["size"] > 0,
            "actual dispatcher size required for retirement capacity")
    guest = {
        "schema": "taira.disk-capacity.plan.v1",
        "allocations": [
            {"path": runtime_root, "label": "retirement publication and prune metadata",
             "bytes": rows[0]["size"] + 64 * 1024**2
                      + retired_import_count * (RETIRE_IMPORT_MAX_INTENT_BYTES + 1024**2),
             "inodes": 4096 + 4 * retired_import_count},
            {"path": runtime_root, "label": "guest filesystem headroom",
             "bytes": 2 * 1024**3, "inodes": 1024},
        ],
    }
    total = sum(row["bytes"] for row in guest["allocations"])
    return {
        "guest_plan": guest,
        "backing_plan": {
            "schema": guest["schema"],
            "allocations": [
                {"path": backing_path, "label": "retirement guest allocation including reserve",
                 "bytes": total, "inodes": 1},
                {"path": backing_path, "label": "Mac physical backing headroom",
                 "bytes": 2 * 1024**3, "inodes": 1024},
            ],
        },
        "derivation": {"retirement_only": True, "new_apply": False,
                       "required_bytes": total, "backing_required_bytes": total + 2 * 1024**3},
    }


def validate_execution_capacity(request, capacity, postconditions, resume_id):
    intent = execution_intent(request)
    plan = request["plan"]
    if intent == "retirement":
        require(not postconditions, "completed native execution cannot be retired")
        expected = retirement_capacity_plans(plan["runtime_root"], request["backing_path"], request["binary"],
                                             len(plan["retired_public_imports"]))
        require(plan["capacity_plan"] == expected["guest_plan"], "exact bounded retirement capacity required")
    else:
        validate_retry_capacity(capacity, plan["capacity_plan"], postconditions, plan["qualification_scope"])
        if not postconditions:
            expected = request.get("retirement_attempt_id")
            require(isinstance(expected, str) and re.fullmatch(r"retry-[0-9]{16,24}-[0-9a-f]{8}", expected)
                    and resume_id == expected, "deployment must resume its exact retired attempt")


def require_public_probe_curl():
    require(
        Path("/usr/bin/curl").is_file() and os.access("/usr/bin/curl", os.X_OK),
        "required public-probe executable /usr/bin/curl is unavailable",
    )


def guest_admit(request):
    """Read-only admission selects retirement or deployment capacity explicitly."""
    intent = execution_intent(request)
    plan = request["plan"]
    require(
        os.geteuid() == 0
        and sys.platform == "linux"
        and platform.machine() == "aarch64",
        "capacity admission requires the approved root AArch64 guest",
    )
    require(
        plan["expected_mac"]
        in {
            path.read_text().strip().lower()
            for path in Path("/sys/class/net").glob("*/address")
        },
        "guest identity differs from approved runtime",
    )
    require_public_probe_curl()
    inventory_path = direct(plan["previous_inventory"])
    inventory = decode(public_record(inventory_path, owner=0, private=True))
    require_same_inventory_artifacts(inventory, request["binary"], request["source"])
    _, arguments = local_arguments(
        public_record(
            inventory_path.parent / "native-local-args.json", owner=0, private=True
        ), inventory["qualification_scope"]
    )
    require("epoch_supervisor" not in plan and "epoch_supervisor" not in inventory,
            "retired epoch worker input is unsupported")
    plan = derive_runtime_paths(plan, request["binary"], inventory, arguments)
    plan["previous_terminal"] = str(
        find_terminal(
            Path(plan["runtime_root"]) / "journal-v1", inventory["deployment_id"]
        )
    )
    for key, expected, digest in (
        ("binary_manifest", request["binary"], request["binary_sha256"]),
        ("source_manifest", request["source"], request["source_sha256"]),
    ):
        require(
            decode(public_record(plan[key], digest, owner=0, private=True)) == expected,
            "retained transfer receipt differs",
        )
    prior_inventory, terminal, prior_args, resume_id = previous_attempt(plan)
    postconditions = resume_id is not None and terminal.parent.name == "completed"
    if not postconditions and plan["retired_public_imports"]:
        configure_protocols(plan, inventory, inventory_path, Path(plan["previous_terminal"]),
                            Path(plan["attempts_root"]) / (resume_id or "admission"),
                            request["binary"], arguments)
        _retire_import_admissions(None, inventory)
    capacity = capacity_module(request["capacity_source"])
    if postconditions:
        result = postcondition_capacity_plans(
            plan["runtime_root"], request["backing_path"]
        )
    elif intent == "retirement":
        result = retirement_capacity_plans(plan["runtime_root"], request["backing_path"], request["binary"],
                                           len(plan["retired_public_imports"]))
    else:
        inputs, runtime = measured_capacity_inputs(
            inventory, arguments["--inrou-stage-dir"][0] if inventory["qualification_scope"] == "full_inrou" else None
        )
        capacity = capacity_module(request["capacity_source"])
        services = [
            Path(host["service_root"])
            for host in inventory["validators"] + [inventory["edge"]]
        ]
        require(
            len({path.parent for path in services}) == 1,
            "cohost service roots must share their native parent",
        )
        result = capacity["derive_capacity"](
            inputs,
            runtime,
            request["build"],
            expected_commit=request["commit"],
            coordinator_path=str(Path(plan["runtime_root"]) / "journal-v1"),
            upload_path=str(services[0].parent),
            service_path=str(services[0].parent),
            store_paths=[
                str(Path(host["state_root"]) / "sorafs-data")
                for host in inventory["validators"]
            ] if inventory["qualification_scope"] == "full_inrou" else [],
            runtime_paths=[
                str(Path(host["state_root"]) / "inrou-data")
                for host in inventory["validators"]
            ] if inventory["qualification_scope"] == "full_inrou" else [],
            guest_headroom_path=plan["runtime_root"],
            backing_path=request["backing_path"],
        )
    plan["capacity_plan"] = result["guest_plan"]
    if intent == "deployment" or postconditions:
        validate_retry_capacity(capacity, plan["capacity_plan"], postconditions, plan["qualification_scope"])
    observed = check_capacity(capacity, plan["capacity_plan"], intent + "-admission")
    result.update(
        schema="taira.retry-admission.v1",
        commit=request["commit"],
        plan=plan,
        guest_capacity=observed,
        runtime_secret_contents_read=False,
        postconditions_only=postconditions,
        intent=intent,
        pending_attempt_id=resume_id,
    )
    print(json.dumps(result, sort_keys=True), flush=True)
    return result


def postcondition_capacity_plans(runtime_root, backing_path):
    """Charge remaining evidence only after exact native completion is authenticated."""
    guest = {
        "schema": "taira.disk-capacity.plan.v1",
        "allocations": [
            {
                "path": runtime_root,
                "label": "remaining postcondition evidence",
                "bytes": 64 * 1024**2,
                "inodes": 1024,
            },
            {
                "path": runtime_root,
                "label": "guest filesystem headroom",
                "bytes": 2 * 1024**3,
                "inodes": 1024,
            },
        ],
    }
    total = sum(row["bytes"] for row in guest["allocations"])
    backing = {
        "schema": guest["schema"],
        "allocations": [
            {
                "path": backing_path,
                "label": "remaining guest postcondition allocation including reserve",
                "bytes": total,
                "inodes": 1,
            },
            {
                "path": backing_path,
                "label": "Mac physical backing headroom",
                "bytes": 2 * 1024**3,
                "inodes": 1024,
            },
        ],
    }
    return {
        "guest_plan": guest,
        "backing_plan": backing,
        "derivation": {
            "native_completion_required": True,
            "new_apply": False,
            "required_bytes": total,
            "backing_required_bytes": total + 2 * 1024**3,
        },
    }


def validate_retry_capacity(capacity, plan, postconditions, qualification_scope):
    if not postconditions:
        return validate_full_capacity(capacity, plan, qualification_scope)
    rows = capacity["validate_plan"](plan)
    require(
        len(rows) == 2
        and {row["label"] for row in rows}
        == {"remaining postcondition evidence", "guest filesystem headroom"}
        and sum(row["bytes"] for row in rows) >= 2 * 1024**3 + 64 * 1024**2,
        "completed attempt requires its remaining evidence capacity and reserve",
    )


def guest_run(request):
    """One concrete native retry, with original custody locks and no automatic replay."""
    plan = request["plan"]
    require(
        os.geteuid() == 0
        and sys.platform == "linux"
        and platform.machine() == "aarch64",
        "native retry requires the approved root AArch64 guest",
    )
    require(
        plan["expected_mac"]
        in {
            path.read_text().strip().lower()
            for path in Path("/sys/class/net").glob("*/address")
        },
        "guest identity differs from the approved runtime plan",
    )
    require_public_probe_curl()
    os.umask(0o077)
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    capacity = capacity_module(request["capacity_source"])
    _, terminal, _, resume_id = previous_attempt(plan)
    postconditions = resume_id is not None and terminal.parent.name == "completed"
    validate_execution_capacity(request, capacity, postconditions, resume_id)
    check_capacity(capacity, plan["capacity_plan"], execution_intent(request))
    runtime = direct(plan["runtime_root"])
    root = direct(plan["attempts_root"])
    require(
        root.is_relative_to(runtime) and root != runtime,
        "attempts must remain inside private runtime",
    )
    for name in (
        "binary_manifest",
        "source_manifest",
        "trusted_public_key",
        "signing_key",
        "ssh_identity",
        "known_hosts",
        "prep_root",
    ):
        require(
            Path(plan[name]).is_relative_to(runtime),
            "runtime input escaped private authority",
        )
    if not root.exists():
        root.mkdir(mode=0o700)
        sync_directory(root.parent)
    _retire_root_identity(root)
    lock = os.open(
        root / "retry.lock",
        os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC,
        0o600,
    )
    try:
        info = os.fstat(lock)
        require(
            stat.S_ISREG(info.st_mode)
            and info.st_uid == 0
            and info.st_nlink == 1
            and stat.S_IMODE(info.st_mode) == 0o600
            and info.st_size == 0,
            "unsafe retry lock",
        )
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        return guest_locked(request, capacity, root)
    finally:
        os.close(lock)


def guest_locked(request, capacity, root):
    intent = execution_intent(request)
    plan = request["plan"]
    binary = decode(
        public_record(
            plan["binary_manifest"], request["binary_sha256"], owner=0, private=True
        )
    )
    source = decode(
        public_record(
            plan["source_manifest"], request["source_sha256"], owner=0, private=True
        )
    )
    require(
        binary == request["binary"] and source == request["source"],
        "retained transfer receipts differ",
    )
    inventory_path, terminal_path, args_path, resume_id = previous_attempt(plan)
    if resume_id is not None and terminal_path.parent.name == "completed":
        require(intent == "deployment", "completed native execution cannot be retired")
        return resume_postconditions(request, root / resume_id, terminal_path)
    if "retirement_attempt_id" in request:
        require(intent == "deployment" and resume_id == request["retirement_attempt_id"],
                "retired attempt changed before deployment lock")
    inventory = decode(public_record(inventory_path, owner=0, private=True))
    require_candidate_probe_inventory(inventory)
    require(inventory["qualification_scope"] == plan["qualification_scope"], "capacity scope differs from exact native inventory")
    require_same_inventory_artifacts(inventory, binary, source)
    args, arguments = local_arguments(public_record(args_path, owner=0, private=True), inventory["qualification_scope"])
    require(
        arguments["--known-hosts"] == [plan["known_hosts"]],
        "native SSH authority differs",
    )
    require("epoch_supervisor" not in plan and "epoch_supervisor" not in inventory,
            "retired epoch worker input is unsupported")
    attempt_id = resume_id or (
        "retry-" + str(time.time_ns()) + "-" + secrets.token_hex(4)
    )
    attempt = root / attempt_id
    configure_protocols(
        plan, inventory, inventory_path, terminal_path, attempt, binary, arguments
    )
    guard = _retire_load_support()
    retained = _retire_context_from_retained(
        guard,
        SimpleNamespace(
            expected_commit=binary["commit"], new_cli_sha256=RETIRE_CLI_SHA
        ),
    )
    with _retire_locks(guard, retained):
        _retire_retained_state(guard, retained)
    if resume_id is None:
        attempt.mkdir(mode=0o700)
    else:
        _retire_root_identity(attempt)
    phase = "retire"
    completed = []
    started = time.monotonic()
    try:
        admission = {
            "schema": PLAN_SCHEMA,
            "attempt_id": attempt_id,
            "commit": binary["commit"],
            "retained_inventory": str(inventory_path),
            "retained_terminal": str(terminal_path),
            "binary_manifest_sha256": request["binary_sha256"],
            "source_manifest_sha256": request["source_sha256"],
            "private_inputs_read_by_python": False,
        }
        if resume_id is None:
            write_public(attempt / "request.json", admission)
            nonce = secrets.token_hex(16)
            write_public(
                attempt / "operation.json",
                {"deployment_id": "taira-" + attempt_id, "nonce": nonce},
            )
        else:
            require(
                decode(public_record(attempt / "request.json", owner=0, private=True))
                == admission,
                "preapply artifact admission changed",
            )
            operation = decode(
                public_record(attempt / "operation.json", owner=0, private=True)
            )
            require(
                set(operation) == {"deployment_id", "nonce"}
                and operation["deployment_id"] == "taira-" + attempt_id,
                "preapply operation identity differs",
            )
            nonce = operation["nonce"]
            preserve_preapply_outputs(attempt)
        draft = fresh_inventory(inventory, attempt_id, nonce)
        assembly = attempt / "assembly"
        assembly.mkdir(mode=0o700)
        write_public(assembly / "topology-intent.json", draft)
        write_public(assembly / "native-retained-args.json", args)
        cli = [Path(binary["destination"]) / "iroha", "taira", "public-reset"]
        logs = attempt / "native"
        logs.mkdir(mode=0o700)
        pointer = {
            "schema": "taira.retry-latest.v1",
            "attempt_id": attempt_id,
            "deployment_id": draft["deployment_id"],
            "inventory_path": str(assembly / "inventory.json"),
            "local_args_path": str(assembly / "native-local-args.json"),
            "retained_inventory": str(inventory_path),
            "retained_terminal": str(terminal_path),
            "retained_local_args": str(args_path),
            "custody_plan_sha256": custody_plan_digest(plan),
        }
        if resume_id is None:
            temporary = root / (".latest-" + attempt_id + ".json")
            write_public(temporary, pointer)
            os.replace(temporary, root / "latest.json")
            sync_directory(root)
        retired = call_phase(phase, lambda: _retire_apply(guard, retained), attempt)
        require(
            retired["guard_bytes_unchanged"] is True,
            "same-artifact retry must preserve guard bytes",
        )
        completed.append(phase)
        if intent == "retirement":
            result = {
                "schema": "taira.retry-retirement.v1", "intent": "retirement",
                "attempt_id": attempt_id, "passed": True, "commit": binary["commit"],
                "binary_manifest_sha256": request["binary_sha256"],
                "source_manifest_sha256": request["source_sha256"],
                "custody_plan_sha256": custody_plan_digest(plan),
                "native_apply_started": False, "next_step": "deployment-capacity-admission",
            }
            ready = attempt / "retirement-ready.json"
            if ready.exists():
                require(decode(public_record(ready, owner=0, private=True)) == result,
                        "retirement resume identity differs")
            else:
                write_public(ready, result)
            print(json.dumps(result, sort_keys=True), flush=True)
            return result
        phase = "prepare-public-inputs"
        check_capacity(capacity, plan["capacity_plan"], phase, attempt)
        run_native([
            *cli, "prepare-public-inputs", "--localnet-dir", Path(plan["prep_root"]) / "network",
            "--intent", assembly / "topology-intent.json",
            "--output-dir", assembly / "public-inputs",
        ], logs / phase, phase=phase)
        completed.append(phase)
        phase = "prepare-beacon-inputs"
        derived_args = prepare_beacon_arguments(
            cli, assembly, plan, args, arguments, draft, inventory, logs)
        completed.append(phase)
        phase = "assemble"
        check_capacity(capacity, plan["capacity_plan"], phase, attempt)
        run_native(
            [
                *cli,
                "assemble",
                "--intent",
                assembly / "topology-intent.json",
                *derived_args,
                "--output",
                assembly / "inventory.json",
            ],
            logs / phase,
            phase=phase,
        )
        assembled = decode(
            public_record(assembly / "inventory.json", owner=0, private=True)
        )
        require(
            assembled["deployment_id"] == draft["deployment_id"]
            and assembled["authorization_nonce"] == draft["authorization_nonce"],
            "fresh native identity differs",
        )
        completed.append(phase)
        phase = "signer-pre"
        signer_args = SimpleNamespace(
            commit=binary["commit"],
            genesis_hash=inventory["next_genesis_hash"],
            prestart_sha256=None,
            local_node_module=plan["local_node"]["path"],
            local_node_sha256=plan["local_node"]["sha256"],
            signer_observation_source=request.get("signer_observation_source"),
            signer_observation_sha256=request.get("signer_observation_sha256"),
        )
        call_phase(phase, lambda: _continuity_capture(signer_args), attempt)
        signer_args.prestart_sha256 = hashlib.sha256(
            public_record(CONTINUITY_OUT / "prestart.json", owner=0, private=True)
        ).hexdigest()
        completed.append(phase)
        phase = "authorize"
        check_capacity(capacity, plan["capacity_plan"], phase, attempt)
        authorize_native(cli, assembly, derived_args, plan, logs / phase)
        authentication = [
            "--inventory",
            assembly / "inventory.json",
            "--authorization",
            assembly / "authorization.json",
            "--trusted-public-key",
            plan["trusted_public_key"],
            "--ssh-identity",
            plan["ssh_identity"],
            "--known-hosts",
            plan["known_hosts"],
        ]
        run_native(
            [*cli, "preflight", *authentication], logs / "preflight", phase="preflight"
        )
        completed.append(phase)
        phase = "apply"
        check_capacity(capacity, plan["capacity_plan"], phase, attempt)
        write_public(
            attempt / "apply-started.json", preflight_identity(attempt, assembled)
        )
        run_native(
            [*cli, "apply", *authentication, *apply_arguments(arguments, inventory["qualification_scope"])],
            logs / phase,
            phase=phase,
            journal_path=Path(plan["runtime_root"])
            / "journal-v1"
            / (assembled["deployment_id"] + ".journal.json"),
        )
        completed.append(phase)
        phase = "signer-post"
        call_phase(phase, lambda: _continuity_reconcile(signer_args), attempt)
        completed.append(phase)
        authority_sha = hashlib.sha256(
            public_record(
                CONTINUITY_OUT / "signer-authority-receipt.json", owner=0, private=True
            )
        ).hexdigest()
        phase = "persistence"
        call_phase(
            phase,
            lambda: _boot_main(
                {
                    "commit": binary["commit"],
                    "transfer_sha256": request["binary_sha256"],
                    "source_sha256": request["source_sha256"],
                    "prestart_sha256": signer_args.prestart_sha256,
                    "authority_sha256": authority_sha,
                }
            ),
            attempt,
        )
        completed.append(phase)
        phase = "public-validation"
        call_phase(
            phase,
            lambda: public_validation(
                binary, assembled, attempt / "native/public-validation"
            ),
            attempt,
        )
        completed.append(phase)
    except BaseException as error:
        result = {
            "schema": RESULT_SCHEMA,
            "attempt_id": attempt_id,
            "passed": False,
            "phase": phase,
            "completed": completed,
            "error_type": type(error).__name__,
            "automatic_replay": False,
            "private_attempt": str(attempt),
            "elapsed_seconds": round(time.monotonic() - started, 3),
        }
        write_public(attempt / "failure.json", result)
        emit(
            phase,
            started,
            status="failed",
            error_type=type(error).__name__,
            private_attempt=str(attempt),
        )
        raise
    result = {
        "schema": RESULT_SCHEMA,
        "attempt_id": attempt_id,
        "passed": True,
        "commit": binary["commit"],
        "deployment_id": draft["deployment_id"],
        "qualification_scope": draft["qualification_scope"],
        "completed": completed,
        "private_attempt": str(attempt),
        "native_apply_passed": True,
        "signer_continuity_passed": True,
        "boot_persistence_passed": True,
        "public_endpoints_verified": True,
        "public_application_validation_completed": False,
        "elapsed_seconds": round(time.monotonic() - started, 3),
    }
    write_public(attempt / "result.json", result)
    print(json.dumps(result, sort_keys=True), flush=True)
    return result


@contextmanager
def completed_execution_lock(plan):
    """Reuse native coordinator exclusion while checking a running deployment."""
    path = direct(Path(plan["runtime_root"]) / "journal-v1/public-reset.lock")
    fd = os.open(path, os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
    try:
        info = os.fstat(fd)
        require(
            stat.S_ISREG(info.st_mode)
            and info.st_uid == 0
            and info.st_nlink == 1
            and stat.S_IMODE(info.st_mode) == 0o600
            and info.st_size == 0,
            "native completed-execution lock custody differs",
        )
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        yield
    finally:
        os.close(fd)


def preserve_postcondition_outputs(attempt):
    """Keep every prior postcondition observation and preserve the prestart authority."""
    relative = [
        "failure.json",
        "result.json",
        "boot-persistence",
        "native/public-validation",
        "signer-post-phase.json",
        "persistence-phase.json",
        "public-validation-phase.json",
        "signer-continuity/startup-evidence.json",
        "signer-continuity/public-process-bindings.json",
        "signer-continuity/signer-authority-receipt.json",
    ]
    existing = [name for name in relative if (attempt / name).exists()]
    if not existing:
        return
    archive = attempt / ("postcondition-evidence-" + str(time.time_ns()))
    archive.mkdir(mode=0o700)
    for name in existing:
        source = direct(attempt / name)
        destination = archive / name
        destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        os.rename(source, destination)
        sync_directory(source.parent)
        sync_directory(destination.parent)
    sync_directory(archive)
    sync_directory(attempt)


def public_validation(binary, inventory, directory):
    """Observe actual public readiness and identity without running diagnostics."""
    qualification_scope = inventory.get("qualification_scope")
    require(
        qualification_scope in ("core_testnet", "full_inrou"),
        "public validation requires the signed qualification scope",
    )
    directory.mkdir(mode=0o700)
    observed = {}
    for name, path in (
        ("readiness", "/readyz"),
        ("status", "/status"),
        ("tip", "/status/blocks"),
        ("network", "/v1/accounts/faucet/puzzle"),
        ("mcp", "/v1/mcp"),
    ):
        log = directory / name
        command = [
            "/usr/bin/curl",
            "-q",
            "--silent",
            "--show-error",
            "--fail-with-body",
            "--max-time",
            "30",
            "--proto",
            "=https",
            "--max-filesize",
            "1048576",
            "--noproxy",
            "*",
            "--output",
            str(log / "body.json"),
            "--write-out",
            "%{http_code}",
            "-H",
            "Accept: text/plain" if name == "readiness" else
            "Accept: application/json, text/event-stream"
            if name == "mcp"
            else "Accept: application/json",
        ]
        if name == "mcp":
            body = {
                "jsonrpc": "2.0",
                "id": 3,
                "method": "tools/call",
                "params": {
                    "name": "iroha.health",
                    "arguments": {},
                    "_meta": {
                        "io.modelcontextprotocol/protocolVersion": "2026-07-28",
                        "io.modelcontextprotocol/clientCapabilities": {},
                        "io.modelcontextprotocol/clientInfo": {
                            "name": "iroha-taira-public-observation",
                            "version": "1",
                        },
                    },
                },
            }
            command += [
                "-H",
                "Content-Type: application/json",
                "-H",
                "MCP-Protocol-Version: 2026-07-28",
                "-H",
                "Mcp-Method: tools/call",
                "-H",
                "Mcp-Name: iroha.health",
                "--data-binary",
                json.dumps(body, separators=(",", ":")),
            ]
        command.append("https://taira.sora.org" + path)
        run_native(
            command,
            log,
            phase="public-validation",
            env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"},
        )
        require(
            public_record(log / "stdout", owner=0, private=True, limit=16) == b"200",
            "anonymous public validation did not return HTTP 200",
        )
        if name != "readiness":
            observed[name] = decode(
                public_record(log / "body.json", owner=0, private=True, limit=1024 * 1024)
            )
    signer = decode(
        public_record(
            CONTINUITY_OUT / "signer-authority-receipt.json", owner=0, private=True
        )
    )
    status, rpc = observed["status"], observed["mcp"]
    require(
        status.get("build", {}).get("git_commit_sha") == binary["commit"]
        and status["build"].get("target_triple") == "aarch64-unknown-linux-gnu"
        and type(observed["tip"]) is int
        and observed["tip"] > 0
        and observed["network"].get("network_id") == signer["network_id"]
        and observed["network"].get("chain_discriminant") == 369,
        "public source, committed tip or NetworkId differs from the completed deployment",
    )
    require(
        rpc.get("jsonrpc") == "2.0"
        and type(rpc.get("id")) is int
        and rpc["id"] == 3
        and "error" not in rpc
        and rpc.get("result", {}).get("isError") is False
        and rpc["result"].get("structuredContent", {}).get("status") == 200,
        "anonymous curated MCP health did not pass",
    )
    result = {
        "public_readiness_passed": True,
        "public_source_passed": True,
        "public_mcp_health_passed": True,
        "public_network_id": signer["network_id"],
        "public_tip": observed["tip"],
        "application_validation_completed": False,
    }
    write_public(directory / "public-result.json", result)
    return result


def resume_postconditions(request, attempt, terminal_path):
    """After proven native completion, repeat only observations and idempotent boot enable."""
    plan, binary, source = request["plan"], request["binary"], request["source"]
    started = time.monotonic()
    phase = "signer-post"
    with completed_execution_lock(plan):
        proof = completed_attempt(plan, attempt, required=True)
        require(
            Path(proof["path"]) == terminal_path, "completed native authority changed"
        )
        inventory = proof["inventory"]
        require_same_inventory_artifacts(inventory, binary, source)
        admission = decode(
            public_record(attempt / "request.json", owner=0, private=True)
        )
        require(
            admission["commit"] == binary["commit"]
            and admission["attempt_id"] == attempt.name
            and admission["binary_manifest_sha256"] == request["binary_sha256"]
            and admission["source_manifest_sha256"] == request["source_sha256"],
            "completed attempt artifact custody changed",
        )
        _, arguments = local_arguments(
            public_record(
                attempt / "assembly/native-local-args.json", owner=0, private=True
            ), inventory["qualification_scope"]
        )
        configure_protocols(
            plan,
            inventory,
            attempt / "assembly/inventory.json",
            terminal_path,
            attempt,
            binary,
            arguments,
        )
        signer_args = SimpleNamespace(
            commit=binary["commit"],
            genesis_hash=inventory["next_genesis_hash"],
            prestart_sha256=hashlib.sha256(
                public_record(CONTINUITY_OUT / "prestart.json", owner=0, private=True)
            ).hexdigest(),
            local_node_module=plan["local_node"]["path"],
            local_node_sha256=plan["local_node"]["sha256"],
            signer_observation_source=request.get("signer_observation_source"),
            signer_observation_sha256=request.get("signer_observation_sha256"),
        )
        preserve_postcondition_outputs(attempt)
        completed = list(PHASES[: PHASES.index("signer-post")])
        try:
            call_phase(phase, lambda: _continuity_reconcile(signer_args), attempt)
            completed.append(phase)
            phase = "persistence"
            authority_sha = hashlib.sha256(
                public_record(
                    CONTINUITY_OUT / "signer-authority-receipt.json",
                    owner=0,
                    private=True,
                )
            ).hexdigest()
            call_phase(
                phase,
                lambda: _boot_main(
                    {
                        "commit": binary["commit"],
                        "transfer_sha256": request["binary_sha256"],
                        "source_sha256": request["source_sha256"],
                        "prestart_sha256": signer_args.prestart_sha256,
                        "authority_sha256": authority_sha,
                    }
                ),
                attempt,
            )
            completed.append(phase)
            phase = "public-validation"
            call_phase(
                phase,
                lambda: public_validation(
                    binary, inventory, attempt / "native/public-validation"
                ),
                attempt,
            )
            completed.append(phase)
            require(
                completed_attempt(plan, attempt, required=True)["sha256"]
                == proof["sha256"],
                "native completed receipt changed during postconditions",
            )
        except BaseException as error:
            write_public(
                attempt / "failure.json",
                {
                    "schema": RESULT_SCHEMA,
                    "attempt_id": attempt.name,
                    "passed": False,
                    "phase": phase,
                    "completed": completed,
                    "error_type": type(error).__name__,
                    "postconditions_only": True,
                    "automatic_replay": False,
                    "private_attempt": str(attempt),
                },
            )
            raise
    result = {
        "schema": RESULT_SCHEMA,
        "attempt_id": attempt.name,
        "passed": True,
        "commit": binary["commit"],
        "deployment_id": inventory["deployment_id"],
        "completed": completed,
        "qualification_scope": inventory["qualification_scope"],
        "private_attempt": str(attempt),
        "native_apply_passed": True,
        "signer_continuity_passed": True,
        "boot_persistence_passed": True,
        "public_endpoints_verified": True,
        "public_application_validation_completed": False,
        "postconditions_only": True,
        "native_completed_receipt": proof["path"],
        "elapsed_seconds": round(time.monotonic() - started, 3),
    }
    write_public(attempt / "result.json", result)
    print(json.dumps(result, sort_keys=True), flush=True)
    return result


def relay_progress(path, cursor, pending, current_phase):
    """Relay only structured public phase/error fields; never arbitrary remote output."""
    with path.open("rb") as stream:
        stream.seek(cursor)
        raw = stream.read(1024 * 1024)
    cursor += len(raw)
    lines = (pending + raw).split(b"\n")
    pending = lines.pop()
    require(len(pending) <= 1024 * 1024, "remote public record exceeds progress bound")
    allowed = {
        "schema",
        "phase",
        "elapsed_seconds",
        "status",
        "private_log",
        "exit_code",
        "automatic_replay",
        "errno",
        "errno_name",
        "operation",
        "chunk",
        "native_phase",
        "next_step",
        "touched_validator_count",
        "edge_touched",
        "attempt_id",
        "private_attempt",
        "error_type",
    }
    for line in lines:
        try:
            value = decode(line)
        except (RetryError, ValueError, UnicodeError):
            continue
        if (
            not isinstance(value, dict)
            or value.get("schema") != PROGRESS_SCHEMA
            or value.get("phase") not in (*PHASES, "preflight")
        ):
            continue
        current_phase = value["phase"]
        print(
            json.dumps(
                {key: item for key, item in value.items() if key in allowed},
                sort_keys=True,
            ),
            flush=True,
        )
    return cursor, pending, current_phase


def remote_command(argv, source, output, phase):
    """One SSH submission with periodic time reporting and private output retention."""
    output.mkdir(mode=0o700)
    started = time.monotonic()
    emit(phase, started, status="started", private_log=str(output))
    cursor, pending, current_phase = 0, b"", phase
    with (
        (output / "stdout").open("xb") as stdout,
        (output / "stderr").open("xb") as stderr,
    ):
        os.fchmod(stdout.fileno(), 0o600)
        os.fchmod(stderr.fileno(), 0o600)
        process = subprocess.Popen(
            argv, stdin=subprocess.PIPE, stdout=stdout, stderr=stderr
        )
        process.stdin.write(source)
        process.stdin.close()
        while True:
            try:
                code = process.wait(timeout=PROGRESS_SECONDS)
                break
            except subprocess.TimeoutExpired:
                cursor, pending, current_phase = relay_progress(
                    output / "stdout", cursor, pending, current_phase
                )
                emit(current_phase, started, status="running", private_log=str(output))
        stdout.flush()
        os.fsync(stdout.fileno())
        stderr.flush()
        os.fsync(stderr.fileno())
    relay_progress(output / "stdout", cursor, pending, current_phase)
    write_public(
        output / "result.json",
        {
            "exit_code": code,
            "elapsed_seconds": round(time.monotonic() - started, 3),
            "automatic_replay": False,
        },
    )
    if code != 0:
        emit(phase, started, status="failed", exit_code=code,
             private_log=str(output), automatic_replay=False)
    require(code == 0, phase + " stopped; inspect private evidence " + str(output))
    return decode(public_record(output / "stdout").splitlines()[-1])


def remote_payload(source, function, argument, *, print_result=False):
    """Execute maintained source as a module, preserving its future-import placement."""
    require(
        function in ("evaluate", "guest_run", "guest_admit"),
        "unknown maintained remote entry point",
    )
    encoded = base64.b64encode(source).decode()
    code = (
        'import base64,json\nnamespace={"__name__":"taira_retry_remote"}\n'
        "exec(compile(base64.b64decode("
        + repr(encoded)
        + '),"<maintained-taira-retry>","exec"),namespace)\n'
        "result=namespace[" + repr(function) + "](" + repr(argument) + ")\n"
    )
    if print_result:
        code += "print(json.dumps(result,sort_keys=True))\n"
    return code.encode()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--plan", required=True, type=Path, help="owner-only public runtime plan"
    )
    parser.add_argument(
        "--output-root",
        required=True,
        type=Path,
        help="existing owner-only local evidence directory",
    )
    args = parser.parse_args()
    os.umask(0o077)
    plan = decode(public_record(args.plan, private=True, limit=1024 * 1024))
    commit, records = validate_plan(plan)
    directory = direct(args.output_root)
    info = directory.stat()
    require(
        stat.S_ISDIR(info.st_mode)
        and info.st_uid == os.getuid()
        and stat.S_IMODE(info.st_mode) == 0o700,
        "existing owner-only output root required",
    )
    output = directory / ("run-" + str(time.time_ns()) + "-" + secrets.token_hex(4))
    output.mkdir(mode=0o700)
    source = public_record(Path(__file__).resolve(), limit=1024 * 1024)
    capacity_source = public_record(
        Path(__file__).resolve().with_name("taira_disk_capacity.py"), limit=1024 * 1024
    )
    signer_observation_source = public_record(
        Path(__file__).resolve().with_name("taira_signer_observation.py"), limit=256 * 1024
    )
    request = {
        "signer_observation_source": base64.b64encode(signer_observation_source).decode(),
        "signer_observation_sha256": hashlib.sha256(signer_observation_source).hexdigest(),
        "plan": plan["guest"],
        "commit": commit,
        "build": records["preparation"],
        "binary": records["binary_transfer"],
        "source": records["source_transfer"],
        "binary_sha256": plan["binary_transfer"]["sha256"],
        "source_sha256": plan["source_transfer"]["sha256"],
        "capacity_source": base64.b64encode(capacity_source).decode(),
        "backing_path": plan["backing_path"],
    }
    def admit(intent, label):
        request["intent"] = intent
        admission = remote_command(
            plan["guest_ssh"]["argv"], remote_payload(source, "guest_admit", request),
            output / label, label,
        )
        require(admission["schema"] == "taira.retry-admission.v1"
                and admission["commit"] == commit and admission["intent"] == intent
                and all(admission["plan"][key] == value for key, value in plan["guest"].items()),
                "derived runtime admission changed explicit owner inputs or execution intent")
        request["plan"] = admission["plan"]
        return admission

    def check_backing(admission, label):
        backing_code = remote_payload(capacity_source, "evaluate", admission["backing_plan"], print_result=True)
        backing = remote_command(plan["backing_ssh"]["argv"], backing_code, output / label, label)
        require(backing["passed"] is True, "physical backing capacity is insufficient")

    # Retirement allocates only its bounded publication/evidence footprint, then
    # reclaims the previous failed attempt before charging the next fresh peak.
    admission = admit("retirement", "retirement-admission")
    retired = None
    if not admission["postconditions_only"]:
        check_backing(admission, "retirement-backing-capacity")
        retired = remote_command(
            plan["guest_ssh"]["argv"], remote_payload(source, "guest_run", request),
            output / "retirement", "retirement",
        )
        require(retired["schema"] == "taira.retry-retirement.v1"
                and retired["intent"] == "retirement" and retired["passed"] is True
                and retired["commit"] == commit and retired["native_apply_started"] is False
                and retired["binary_manifest_sha256"] == request["binary_sha256"]
                and retired["source_manifest_sha256"] == request["source_sha256"]
                and retired["custody_plan_sha256"] == custody_plan_digest(request["plan"])
                and re.fullmatch(r"retry-[0-9]{16,24}-[0-9a-f]{8}", retired["attempt_id"]),
                "retirement did not return its exact non-executing resume identity")
        request["retirement_attempt_id"] = retired["attempt_id"]
    admission = admit("deployment", "admission")
    if retired is not None:
        require(not admission["postconditions_only"]
                and admission["pending_attempt_id"] == retired["attempt_id"],
                "retired attempt changed before fresh deployment admission")
    check_backing(admission, "backing-capacity")
    payload = remote_payload(source, "guest_run", request)
    result = remote_command(
        plan["guest_ssh"]["argv"], payload, output / "guest", "native-retry"
    )
    require(
        result["schema"] == RESULT_SCHEMA
        and result["passed"] is True
        and result["commit"] == commit,
        "native retry did not return exact completion",
    )
    write_public(output / "result.json", result)
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    try:
        main()
    except (RetryError, OSError, ValueError) as error:
        print(
            json.dumps(
                {
                    "schema": RESULT_SCHEMA,
                    "passed": False,
                    "error_type": type(error).__name__,
                    "automatic_replay": False,
                }
            ),
            file=sys.stderr,
        )
        raise SystemExit(1)
