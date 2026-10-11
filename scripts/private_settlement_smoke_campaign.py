#!/usr/bin/env python3
"""Run and validate the ten fresh N=3 AtomicPrivateSettlementV1 positive gates.

Prerequisites: a clean, signed exact Git commit, an installed Rust toolchain,
the locked offline Cargo dependency cache, and permission to start 16 local
validator processes. ``run`` builds once and invokes the exact ignored Rust
smoke test ten times serially. It never retries a failed run. Output must name
a new absolute directory outside the repository; evidence is retained with
owner-only permissions, including failures. No inherited APS/Iroha test knobs
are accepted. ``validate`` and :func:`validate_campaign` are read-only.

The Rust harness verifies canonical SumeragiFinalityProof carriers through
CertifiedPrefix from the configured signed genesis. Python checks their inventory,
retained transport log replay, and cross-record bindings; it does not implement or claim independent BLS verification. This
campaign is correctness evidence, not an independent cryptographic audit.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import os
from pathlib import Path
import re
import secrets
import stat
import struct
import subprocess
import sys
import time
from types import ModuleType
from typing import Any

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))
import private_settlement_release_runner as release_runner
import sumeragi_mutation_gate as native_accounting


def _load_source_manifest_tools() -> ModuleType:
    """Load the canonical release-source checker from this exact checkout."""
    path = SCRIPT_DIR / "compute_workspace_source_manifest.py"
    spec = importlib.util.spec_from_file_location("_smoke_workspace_source_manifest", path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load workspace source-manifest tools: {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


_SOURCE_TOOLS = _load_source_manifest_tools()

PROTOCOL = "AtomicPrivateSettlementV1"
# Hash::prehashed sets the final byte's low marker bit, including empty input.
EMPTY_PROTOCOL_HASH = "0" * 63 + "1"
TEST_NAME = (
    "nexus::atomic_private_settlement_localnet::"
    "atomic_private_settlement_n3_real_process_smoke"
)
HAPPY_DAY_TEST_NAME = (
    "nexus::atomic_private_settlement_localnet::"
    "atomic_private_settlement_n3_happy_day"
)
RUN_COUNT = 10
PEER_COUNT = 16
RAYON_WORKER_THREADS = 8
WORKER_ENVIRONMENT_KEYS = ("RAYON_NUM_THREADS", "RUST_TEST_THREADS", "CARGO_BUILD_JOBS", "CARGO_INCREMENTAL")
MAX_JSON_BYTES = 16 * 1024 * 1024
MAX_TRANSPORT_LOG_BYTES = 64 * 1024 * 1024
TRANSPORT_PROVENANCE = "retained process binary and local authenticated-ingress observations"
REQUEST_FIELDS = {
    "version", "protocol", "kind", "request_id", "invocation_nonce", "commit", "seed", "run"
}
STATE_PHASES = (
    "before", "collecting", "audited", "prepared", "registered", "commit-certified",
    "finalized", "replay",
)
EVIDENCE_NAMES = frozenset(
    {"request.json", "processes-before.json", "processes-after.json", "authorities.json",
     "prepare-barrier.json", "commit-certificates.json", "receipt.json", "restarts.json"}
    | {f"state-{phase}.json" for phase in STATE_PHASES}
    | {f"{prefix}-{peer:02}.json" for prefix in (
        "continuous", "state-restarted", "finality-before", "finality-after"
    ) for peer in range(PEER_COUNT)}
    | {f"finality-before-transport-{peer:02}.{extension}"
       for peer in range(PEER_COUNT) for extension in ("json", "log")}
)
HAPPY_DAY_EVIDENCE_NAMES = frozenset(
    EVIDENCE_NAMES - {"restarts.json"}
    - {f"{prefix}-{peer:02}.json" for prefix in ("state-restarted", "finality-after")
       for peer in range(PEER_COUNT)}
)
CRYPTOGRAPHIC_SCOPE = (
    "Rust CertifiedPrefix verifies contiguous native finality from the configured signed genesis, "
    "including exact-quorum BLS and original signed RS16 availability. Python validates retained "
    "proof bindings and replays source-bound local authenticated-ingress logs; it does not verify "
    "BLS signatures or establish Byzantine remote-transport provenance. "
    "Independent cryptographic review remains a separate requirement."
)


class CampaignError(release_runner.RunnerError):
    """A failed or incomplete positive gate; never a qualification result."""


def require(condition: bool, message: str) -> None:
    """Reject a violated evidence invariant."""
    if not condition:
        raise CampaignError(message)


def fields(value: Any, names: set[str], label: str) -> dict[str, Any]:
    """Require one exact current-schema JSON object."""
    return release_runner.exact_fields(value, names, label)


def integer(value: Any, minimum: int, maximum: int, label: str) -> int:
    """Validate a bounded integer without accepting JSON booleans."""
    return release_runner.bounded_integer(value, minimum, maximum, label)


def digest(value: Any, label: str, widths: tuple[int, ...] = (64,)) -> str:
    """Require a nonzero lowercase SHA/Git digest with an exact width."""
    require(isinstance(value, str) and len(value) in widths
            and re.fullmatch(r"[0-9a-f]+", value) is not None
            and any(character != "0" for character in value), f"invalid {label}")
    return value


def canonical(value: Any) -> bytes:
    """Use the release runner's canonical JSON encoding for evidence bindings."""
    return release_runner.canonical_bytes(value)


def protocol_hash(value: Any, label: str, *, allow_empty: bool = False) -> str:
    """Decode the current marked Iroha hash spelling and its checksum.

    Hash::prehashed sets the low bit; the reserved empty value is therefore
    00...01. Raw all-zero bytes are not a valid current Hash wire value.
    """
    body = release_runner.canonical_iroha_hash_body(value, label)
    require(int(body[-2:], 16) & 1 == 1, f"{label} lacks the canonical Iroha hash marker")
    require(allow_empty or body != EMPTY_PROTOCOL_HASH, f"{label} is the reserved empty Iroha hash")
    return body


def sha(data: bytes) -> str:
    """Return a raw SHA-256 evidence digest."""
    return hashlib.sha256(data).hexdigest()


def owner_path(path: Path, *, directory: bool) -> None:
    """Reject symlinks, foreign ownership, and non-owner permission bits."""
    info = path.lstat()
    require((stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode))
            and info.st_uid == os.getuid()
            and stat.S_IMODE(info.st_mode) == (0o700 if directory else 0o600),
            f"{path} must be an owner-only {'directory' if directory else 'regular file'}")
    require(path.is_absolute() and path.resolve(strict=True) == path,
            f"{path} must be canonical and must not traverse a symlink")


def read_bytes(path: Path, *, limit: int = MAX_JSON_BYTES, private: bool = True) -> bytes:
    """Read stable regular bytes without following a final-component symlink."""
    if private:
        owner_path(path, directory=False)
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        before = os.fstat(descriptor)
        require(stat.S_ISREG(before.st_mode) and before.st_size <= limit,
                f"{path} is not a bounded regular file")
        with os.fdopen(descriptor, "rb", closefd=False) as stream:
            data = stream.read(limit + 1)
        after = os.fstat(descriptor)
        require(len(data) <= limit and all(getattr(before, name) == getattr(after, name)
                for name in ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns")),
                f"{path} changed during its read")
        return data
    finally:
        os.close(descriptor)


def file_digest(path: Path) -> str:
    """Hash a stable executable or source file without allocating it in memory."""
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        before = os.fstat(descriptor)
        require(stat.S_ISREG(before.st_mode), f"{path} must be a regular file")
        result = hashlib.sha256()
        with os.fdopen(descriptor, "rb", closefd=False) as stream:
            for block in iter(lambda: stream.read(1024 * 1024), b""):
                result.update(block)
        after = os.fstat(descriptor)
        require(all(getattr(before, name) == getattr(after, name) for name in
                    ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns")),
                f"{path} changed during hashing")
        return result.hexdigest()
    finally:
        os.close(descriptor)


def read_json(path: Path) -> Any:
    """Read strict, bounded, owner-only JSON, rejecting duplicate keys."""
    return release_runner.strict_json_loads(read_bytes(path).decode("utf-8"), str(path))


def write_new(path: Path, data: bytes) -> None:
    """Durably retain a new private file; never replace existing evidence."""
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(descriptor, "wb", closefd=False) as stream:
            stream.write(data)
            stream.flush()
            os.fsync(descriptor)
    finally:
        os.close(descriptor)
    parent = os.open(path.parent, os.O_RDONLY)
    try:
        os.fsync(parent)
    finally:
        os.close(parent)


def write_json(path: Path, value: Any) -> None:
    """Retain one immutable canonical JSON record."""
    write_new(path, canonical(value) + b"\n")


def outside_repo(path: Path, repo: Path) -> None:
    """Require an absolute canonical path outside the complete source checkout."""
    require(path.is_absolute() and path == path.resolve(), "output must be absolute and canonical")
    require(path != repo and repo not in path.parents, "campaign evidence must be outside the repository")


def validate_request(value: Any, commit: str, run: int, *, kind: str = "smoke") -> dict[str, Any]:
    """Bind a request to its explicitly selected experiment and exact intent."""
    require(kind in ("smoke", "happy_day"), "unknown experiment kind")
    request = fields(value, REQUEST_FIELDS, "request")
    require(type(request["version"]) is int and request["version"] == 1
            and request["protocol"] == PROTOCOL and request["kind"] == kind, "wrong experiment protocol/kind")
    digest(request["invocation_nonce"], "invocation nonce")
    digest(request["commit"], "commit", (40, 64))
    require(request["commit"] == commit and integer(request["run"], 0, 9, "run") == run,
            "request commit/run substitution")
    integer(request["seed"], 0, 2**64 - 1, "seed")
    material = {key: value for key, value in request.items() if key != "request_id"}
    require(request["request_id"] == sha(canonical(material)), "request ID does not bind its exact intent")
    return request


def new_request(commit: str, run: int, *, kind: str = "smoke") -> dict[str, Any]:
    """Create fresh per-run network entropy before any process starts."""
    require(kind in ("smoke", "happy_day"), "unknown experiment kind")
    request = {"version": 1, "protocol": PROTOCOL, "kind": kind, "commit": commit,
               "seed": secrets.randbits(64), "run": run, "invocation_nonce": secrets.token_hex(32)}
    request["request_id"] = sha(canonical(request))
    return validate_request(request, commit, run, kind=kind)


def terminal_success(output: str, *, kind: str = "smoke") -> None:
    """Require an executed exact test, excluding zero-test/ignored/skip successes."""
    require(kind in ("smoke", "happy_day"), "unknown experiment kind")
    selected = TEST_NAME if kind == "smoke" else HAPPY_DAY_TEST_NAME
    terminals, owners_valid = native_accounting.serial_test_terminals(output)
    headers = list(native_accounting.TEST_RUNNING.finditer(output))
    summaries = list(native_accounting.TEST_COMPLETION.finditer(output))
    require(owners_valid and len(terminals) == 1
            and terminals[0][:2] == (selected, "ok"),
            "experiment lacks its exact successful native test terminal")
    require(len(headers) == len(summaries) == 1
            and len(re.findall(r"^test result:.*$", output, re.MULTILINE)) == 1
            and headers[0].group(1) == "1"
            and summaries[0].group(1) == "ok"
            and tuple(map(int, summaries[0].group(2, 3, 4, 5))) == (1, 0, 0, 0)
            and headers[0].end() < terminals[0][2]
            and terminals[0][3] < summaries[0].start(),
            "experiment lacks one ordered exact native header and success summary")
    require(re.search(r"\bskip(?:ped|ping)?\b|\bretrying\b|fresh startup attempt [2-9]", output,
                      re.IGNORECASE) is None, "smoke reported a skip or retry")
    require(output.count(f"APS {kind} completed:") == 1, "missing unique Rust experiment completion")
    other = "happy_day" if kind == "smoke" else "smoke"
    require(f"APS {other} completed:" not in output, "another experiment completion was mixed into the stream")


def validate_process_closure(output: str) -> None:
    """Require all restart and final-shutdown exits from the standalone smoke run.

    PeerExit prints the pinned Rust ExitStatus Debug value: Unix wait status or
    the nested Windows ExitStatus. Every one of the 16 original and 16 replacement
    validator processes must report successful termination; unrelated log lines
    do not replace missing records. Native/source/PID custody remains separately
    authenticated by the campaign and its Rust producer.
    """
    prefix = "TEST_NETWORK peer exited"
    records = [line for line in output.splitlines() if prefix in line]
    require(len(records) == 2 * PEER_COUNT, "smoke requires exactly 32 validator process exit records")
    successful = {
        "TEST_NETWORK peer exited with status ExitStatus(unix_wait_status(0))",
        "TEST_NETWORK peer exited with status ExitStatus(ExitStatus(0))",
    }
    require(records[0] in successful and all(record == records[0] for record in records),
            "smoke requires successful validator process exits with one exact platform grammar")


def validate_inventory(before: Any, after: Any, restarts: Any, validator_sha: str,
                       *, kind: str = "smoke") -> list[Any]:
    """Check identity/configuration and the process lifecycle selected by the experiment."""
    require(kind in ("smoke", "happy_day"), "unknown experiment kind")
    require(isinstance(before, list) and isinstance(after, list)
            and len(before) == len(after) == PEER_COUNT, "incomplete process inventory")
    require((kind == "smoke" and isinstance(restarts, list) and len(restarts) == PEER_COUNT)
            or (kind == "happy_day" and restarts is None), "wrong experiment restart inventory")
    names = {"peer_index", "peer_id", "committee_index", "validator_index", "pid",
             "executable_sha256", "configuration_sha256"}
    identities = []
    for rows in (before, after):
        pids = []
        for index, item in enumerate(rows):
            row = fields(item, names, "process")
            require(integer(row["peer_index"], 0, 15, "peer index") == index
                    and integer(row["committee_index"], 0, 3, "committee") == index // 4
                    and integer(row["validator_index"], 0, 3, "validator") == index % 4,
                    "process committee/index substitution")
            pids.append(integer(row["pid"], 1, 2**32 - 1, "process PID"))
            digest(row["configuration_sha256"], "configuration digest")
            require(row["executable_sha256"] == validator_sha and row["peer_id"] is not None,
                    "process executable/identity substitution")
        require(len(set(pids)) == 16, "process inventory repeats a PID")
    for index, (old, new) in enumerate(zip(before, after, strict=True)):
        if kind == "smoke":
            record = fields(restarts[index], {"peer_index", "before_pid", "after_pid"}, "restart")
            require(integer(record["peer_index"], 0, 15, "restart peer index") == index
                    and integer(record["before_pid"], 1, 2**32 - 1, "restart before PID") == old["pid"]
                    and integer(record["after_pid"], 1, 2**32 - 1, "restart after PID") == new["pid"]
                    and record == {"peer_index": index, "before_pid": old["pid"], "after_pid": new["pid"]}
                    and old["pid"] != new["pid"], "restart did not replace the exact process")
        else:
            require(old["pid"] == new["pid"], "happy-day validator process changed")
        require(all(old[name] == new[name] for name in names - {"pid"}),
                "restart changed validator identity, configuration, or executable")
        identities.append(old["peer_id"])
    require(len({canonical(identity) for identity in identities}) == 16, "validator identities overlap")
    # These digests bind ordered shared input layers. Node identities and PIDs
    # are checked independently above; identical validator layers are valid.
    return identities


def state_identity(observation: Any, peer: int, label: str) -> Any:
    """Validate raw response bytes and the exact N=3 staged-lock geometry."""
    result = release_runner._validate_fault_state_response(
        observation, label=label, expected_peer_index=peer)
    for name in ("commitment", "ledger_commitment", "replicated_staged_lock_commitment", "staged_lock_commitment"):
        protocol_hash(observation[name], f"{label}.{name}", allow_empty=True)
    counts = dict(result[3])
    require(counts["staged_pool_heads"] <= 3 and counts["replicated_staged_locks"] in (0, 28),
            f"{label} has wrong N=3 lock geometry")
    return result


def validate_states(evidence: dict[str, Any], finalized_height: int,
                    *, kind: str = "smoke") -> tuple[Any, Any]:
    """Require baseline financial state at every preparation stage and exact atomic deltas."""
    require(kind in ("smoke", "happy_day"), "unknown experiment kind")
    phases = STATE_PHASES + (tuple(f"restarted-{index:02}" for index in range(16)) if kind == "smoke" else ())
    vectors = {}
    for phase in phases:
        name = f"state-{phase}.json"
        snapshot = fields(evidence[name], {"label", "validators"}, name)
        # The shared exact-carrier retry observer retains this label when its
        # immutable snapshot is written as state-replay.json by either campaign.
        expected_label = ("smoke-restarted" if phase.startswith("restarted-")
                          else "after-finalized-retry" if phase == "replay"
                          else f"smoke-{phase}")
        require(snapshot["label"] == expected_label and isinstance(snapshot["validators"], list)
                and len(snapshot["validators"]) == 16, f"{name} omits/relabels validators")
        vectors[phase] = [state_identity(row, peer, name) for peer, row in enumerate(snapshot["validators"])]
        if phase in ("finalized", "replay") or phase.startswith("restarted-"):
            require(all(row["height"] >= finalized_height for row in snapshot["validators"]),
                    f"{name} predates finality")
    before, after = vectors["before"][0], vectors["finalized"][0]
    require(len(set(vectors["before"])) == len(set(vectors["finalized"])) == 1,
            "validators lack coherent before/finalized states")
    before_counts, after_counts = dict(before[3]), dict(after[3])
    deltas = {"roots": 3, "nullifiers": 6, "commitments": 9, "encrypted_outputs": 9,
              "replay_markers": 1, "receipts": 1}
    require(before[0] != after[0] and before[1:3] == after[1:3], "atomic finality commitment mismatch")
    require(before_counts["governance"] == before_counts["pools"] == 3, "smoke lacks three governed pools")
    for name in release_runner.FAULT_STATE_COUNT_FIELDS:
        require(after_counts[name] == before_counts[name] + deltas.get(name, 0),
                f"wrong final financial delta for {name}")
    require(all(before_counts[name] == after_counts[name] == 0
                for name in release_runner.FAULT_STAGED_COUNT_FIELDS), "terminal locks were not released")
    baseline = release_runner._fault_ledger_attempt_identity(before)
    for phase in STATE_PHASES[1:6]:
        require(all(release_runner._fault_ledger_attempt_identity(row) == baseline for row in vectors[phase]),
                f"partial financial application during {phase}")
    for phase, vector in vectors.items():
        if phase == "replay" or phase.startswith("restarted-"):
            require(all(row == after for row in vector), f"replay/restart changed financial state: {phase}")
    return before, after


def validate_continuous(record: Any, peer: int, bundle: bytes, before: Any, after: Any) -> int:
    """Recompute phase/response chains and bind every attempt to retained raw bytes."""
    row = fields(record, {"summary", "observations"}, "continuous evidence")
    summary = fields(row["summary"], {"peer_index", "check_count", "poll_failure_count",
        "first_response_sha256", "last_response_sha256", "response_chain_sha256",
        "baseline_observations", "finalized_observations", "phase_coverage"}, "continuous summary")
    observations = row["observations"]
    require(integer(summary["peer_index"], 0, 15, "continuous peer index") == peer and isinstance(observations, list)
            and 3 <= len(observations) <= 10_000, "incomplete continuous observations")
    require(integer(summary["check_count"], 3, 10_000, "check count") == len(observations)
            and integer(summary["poll_failure_count"], 0, 0, "poll failures") == 0,
            "continuous count/failure mismatch")
    classes = []
    seen_finalized = False
    previous_final_local = None
    baseline = release_runner._fault_ledger_attempt_identity(before)
    finalized_ledger = release_runner._fault_ledger_attempt_identity(after)
    for observation in observations:
        identity = state_identity(observation, peer, "continuous observation")
        if release_runner._fault_ledger_attempt_identity(identity) == finalized_ledger:
            previous_final_local = release_runner._validate_finalized_local_reconciliation(
                identity, after, previous_final_local)
            seen_finalized = True
            classes.append("finalized")
        else:
            require(not seen_finalized and release_runner._fault_ledger_attempt_identity(identity) == baseline,
                    "continuous partial application or rollback")
            classes.append("baseline")
    require(classes[0] == "baseline" and classes[-1] == "finalized", "continuous stream lacks both endpoints")
    require(state_identity(observations[-1], peer, "continuous terminal") == after,
            "continuous terminal state retains unreconciled local staging")
    chain = hashlib.sha256(release_runner.FAULT_CONTINUOUS_OBSERVATION_DOMAIN_V1 + bundle + struct.pack("<Q", peer))
    for observation in observations:
        chain.update(bytes.fromhex(observation["response_sha256"]))
    require(summary["response_chain_sha256"] == chain.hexdigest()
            and summary["first_response_sha256"] == observations[0]["response_sha256"]
            and summary["last_response_sha256"] == observations[-1]["response_sha256"]
            and integer(summary["baseline_observations"], 1, 10_000, "baseline count") == classes.count("baseline")
            and integer(summary["finalized_observations"], 1, 10_000, "finalized count") == classes.count("finalized"),
            "continuous response chain or class count mismatch")
    phases = summary["phase_coverage"]
    require(isinstance(phases, list) and len(phases) == 3, "missing preflight/finalization/terminal coverage")
    position = 0
    for index, (value, name, allowed) in enumerate(zip(phases, ("preflight", "finalization", "terminal"),
                                                    (False, True, True), strict=True)):
        phase = fields(value, {"phase", "expected_unavailable", "finalization_allowed", "successful_observations",
            "poll_failures", "baseline_observations", "finalized_observations", "checkpoint_attempt",
            "checkpoint_control_bindings", "attempt_chain_sha256", "attempts"}, "continuous phase")
        require(phase["phase"] == name and phase["expected_unavailable"] is False
                and phase["finalization_allowed"] is allowed and phase["checkpoint_control_bindings"] == [],
                "wrong smoke observation phase contract")
        success = integer(phase["successful_observations"], 1, 10_000, "phase success count")
        checkpoint = integer(phase["checkpoint_attempt"], 0, success - 1, "phase checkpoint")
        require(integer(phase["poll_failures"], 0, 0, "phase failures") == 0, "phase poll failed")
        encoded_name = name.encode("ascii")
        phase_chain = hashlib.sha256(release_runner.FAULT_CONTINUOUS_OBSERVATION_PHASE_DOMAIN_V1 + bundle
            + struct.pack("<QQQ", peer, index, len(encoded_name)) + encoded_name + bytes((0, allowed)))
        counts = {"baseline": 0, "finalized": 0}
        require(isinstance(phase["attempts"], list) and 0 < len(phase["attempts"]) <= 10_000,
                "missing/bloated phase attempts")
        previous = None
        for value in phase["attempts"]:
            attempt = fields(value, {"class", "evidence", "repetitions"}, "phase attempt")
            kind = attempt["class"]
            require(kind in counts and (allowed or kind == "baseline"), "invalid/early finalization attempt")
            repetitions = integer(attempt["repetitions"], 1, success, "attempt repetitions")
            require(previous != (kind, attempt["evidence"]), "phase attempt RLE is not canonical")
            previous = (kind, attempt["evidence"])
            require(position + repetitions <= len(observations), "phase attempts exceed retained responses")
            for _ in range(repetitions):
                observation = observations[position]
                if name == "terminal":
                    require(state_identity(observation, peer, "continuous terminal phase") == after,
                            "terminal phase observation retains unreconciled local staging")
                require(classes[position] == kind and observation["response_hex"] == attempt["evidence"],
                        "phase attempt does not match the corresponding retained raw response")
                phase_chain.update(bytes((1 if kind == "baseline" else 2,)))
                phase_chain.update(bytes.fromhex(observation["response_sha256"]))
                counts[kind] += 1
                position += 1
        require(sum(counts.values()) == success
                and integer(phase["baseline_observations"], 0, success, "phase baseline") == counts["baseline"]
                and integer(phase["finalized_observations"], 0, success, "phase finalized") == counts["finalized"],
                "phase class count mismatch")
        phase_chain.update(b"checkpoint\0" + struct.pack("<Q", checkpoint)
                           + b"checkpoint-controls\0" + struct.pack("<Q", 0))
        require(phase["attempt_chain_sha256"] == phase_chain.hexdigest(), "phase attempt chain mismatch")
    require(position == len(observations), "retained raw observations lack phase coverage")
    return len(observations)


def byte_vector(value: Any, label: str, *, minimum: int = 1, maximum: int = 1024 * 1024) -> None:
    """Require actual bounded signature/PoP bytes, not a digest-only assertion."""
    require(isinstance(value, list) and minimum <= len(value) <= maximum
            and all(type(byte) is int and 0 <= byte <= 255 for byte in value)
            and any(value), f"missing or invalid {label} bytes")


def consensus_key(peer: Any) -> str:
    """Extract the current canonical BLS-normal PeerId's 48-byte consensus key.

    PublicKey Display/JSON uses lowercase multihash varints ea0130 and uppercase
    payload hex. This binds identities, not BLS key validity or signatures.
    """
    require(isinstance(peer, str) and re.fullmatch(r"ea0130[0-9A-F]{96}", peer) is not None,
            "invalid canonical BLS-normal peer identity")
    return peer[6:].lower()


def validate_finality(proof: Any, result: dict[str, Any], identities: list[Any]) -> bytes:
    """Check the current native proof schema; Rust authenticates its opaque carrier.

    CertifiedPrefix is a verification capability, not another JSON proof format.
    Do not guess Norito layouts here or equate different valid QC subsets with
    different decisions. Rust compares the before/recovery block and context.
    """
    proof = fields(proof, {"block_header", "block_wire", "committee"}, "finality proof")
    header = fields(proof["block_header"], {"height", "prev_block_hash", "merkle_root",
        "da_proof_policies_hash", "da_commitments_hash", "da_pin_intents_hash", "npos_effects_hash",
        "creation_time_ms", "view_change_index", "confidential_features", "execution_context_hash",
        "global_beacon_pulse_hash"}, "block header")
    require(integer(header["height"], 2, 2**64 - 1, "finality height") == result["finalized_height"],
            "finality height substitution")
    integer(header["creation_time_ms"], 0, 2**64 - 1, "block creation time")
    integer(header["view_change_index"], 0, 2**64 - 1, "block view")
    protocol_hash(header["prev_block_hash"], "previous block")
    for name in ("merkle_root", "da_proof_policies_hash", "da_commitments_hash", "da_pin_intents_hash",
                 "npos_effects_hash", "execution_context_hash", "global_beacon_pulse_hash"):
        if header[name] is not None:
            protocol_hash(header[name], name)
    byte_vector(proof["block_wire"], "canonical SignedBlockWire", maximum=32 * 1024 * 1024)
    require(isinstance(proof["committee"], list) and len(proof["committee"]) == 4,
            "wrong global finality committee")
    members = [fields(member, {"public_key", "proof_of_possession"}, "finality validator")
               for member in proof["committee"]]
    keys = [consensus_key(member["public_key"]) for member in members]
    require(keys == sorted(set(keys))
            and set(keys) == {consensus_key(peer) for peer in identities[:4]},
            "finality substituted, reordered or duplicated a global validator")
    for member in members:
        byte_vector(member["proof_of_possession"], "validator PoP", minimum=96, maximum=96)
    return canonical({"header": header, "committee": members})


def validate_transport(record: Any, raw_log: bytes, proof_raw: bytes, proof: dict[str, Any],
                       result: dict[str, Any], processes: list[Any], peer: int) -> bytes:
    """Replay actual retained log bytes and bind one live process to its verified source.

    The producer derives the source from CertifiedPrefix, not from these logs.
    This validator establishes consistent source-bound observations, never remote
    receipt attestation or an independent verification of the embedded Norito QC.
    """
    record = fields(record, {"peer_index", "peer", "pid", "run_id", "stdout_path", "log_artifact",
        "log_sha256", "log_bytes", "network_id", "proof_sha256", "instance", "height", "block", "result",
        "availability_digest", "payload_hash", "payload_bytes", "epoch", "context", "proposer",
        "local_key", "peer_keys", "data_shards", "parity_shards", "stripes", "admitted_rows",
        "local_author", "provenance", "audit_lines"}, "transport evidence")
    process = processes[peer]
    require(integer(record["peer_index"], 0, 15, "transport peer") == peer
            and record["peer"] == process["peer_id"]
            and integer(record["pid"], 1, 2**32 - 1, "transport PID") == process["pid"],
            "transport substituted its process")
    run_id = integer(record["run_id"], 1, 2**64 - 1, "transport run")
    require(isinstance(record["stdout_path"], str)
            and re.fullmatch(r"[a-z][a-z0-9_]*?/run-" + str(run_id) + r"-stdout\.log",
                             record["stdout_path"]) is not None,
            "transport stdout path/run mismatch")
    require(record["log_artifact"] == f"finality-before-transport-{peer:02}.log"
            and integer(record["log_bytes"], 1, MAX_TRANSPORT_LOG_BYTES, "transport log length") == len(raw_log)
            and record["log_sha256"] == sha(raw_log), "transport retained log binding differs")
    digest(record["log_sha256"], "transport log hash")
    require(record["network_id"] == result["network_id"]
            and record["proof_sha256"] == sha(proof_raw), "transport native proof/network binding differs")
    digest(record["proof_sha256"], "transport proof hash")
    require(record["provenance"] == TRANSPORT_PROVENANCE, "transport provenance claim differs")
    require(integer(record["height"], 2, 2**64 - 1, "transport height") == result["finalized_height"],
            "transport finality height differs")
    for name in ("instance", "block", "result", "availability_digest", "payload_hash", "context"):
        digest(record[name], f"transport {name}")
    integer(record["epoch"], 0, 2**64 - 1, "transport epoch")
    proposer = integer(record["proposer"], 0, 3, "transport proposer")
    require(record["local_key"] == consensus_key(process["peer_id"])
            and record["peer_keys"] == sorted(consensus_key(row["peer_id"]) for row in processes),
            "transport consensus-key population differs")
    author = proof["committee"][proposer]["public_key"] == process["peer_id"]
    require(type(record["local_author"]) is bool and record["local_author"] == author,
            "transport author does not match the certified proposer")
    size = integer(record["payload_bytes"], 1, 16 * 1024 * 1024, "transport payload length")
    require(type(record["data_shards"]) is int and record["data_shards"] == 4
            and type(record["parity_shards"]) is int and record["parity_shards"] == 2,
            "mandatory signed RS16 layout mismatch")
    stripes = integer(record["stripes"], 1, 16, "transport stripes")
    require(stripes == (size + 4 * 256 * 1024 - 1) // (4 * 256 * 1024),
            "transport geometry differs from the payload")
    accepted = integer(record["admitted_rows"], 0, stripes * 6, "transport admitted rows")
    require(isinstance(record["audit_lines"], list) and 2 <= len(record["audit_lines"]) <= 65536,
            "missing or excessive transport audit lines")
    # Scan the complete retained prefix, rather than trusting a producer-selected
    # subset. Matching observations cannot be omitted to hide a duplicate or PID.
    observations = []
    selected = []
    offset = 0
    require(raw_log.endswith(b"\n"), "transport log prefix contains an incomplete line")
    try:
        raw_log.decode("utf-8")
    except UnicodeDecodeError as error:
        raise CampaignError("transport log is not UTF-8") from error
    for content in raw_log.split(b"\n")[:-1]:
        raw_line = content + b"\n"
        if b"sumeragi payload" in raw_line or b"sumeragi block applied" in raw_line:
            require(len(content) <= 1024 * 1024, "transport observation exceeds line bound")
            line = raw_line.decode("utf-8")
            value = release_runner.strict_json_loads(line, "transport audit log")
            require(isinstance(value, dict) and isinstance(value.get("fields"), dict),
                    "transport audit log lacks fields")
            event = value["fields"]
            require(isinstance(event.get("message"), str), "transport audit log lacks message")
            if event["message"] in {"sumeragi payload row admitted", "sumeragi payload custody verified",
                                    "sumeragi block applied"}:
                require(isinstance(event.get("instance"), str) and isinstance(event.get("block"), str),
                        "transport audit source is not text")
                integer(event.get("height"), 0, 2**64 - 1, "audit height")
            if (event.get("message") in {"sumeragi payload row admitted", "sumeragi payload custody verified",
                                         "sumeragi block applied"}
                    and event.get("instance") == record["instance"]
                    and event.get("height") == record["height"] and event.get("block") == record["block"]):
                selected.append({"offset": offset, "line": line})
                observations.append(event)
        offset += len(raw_line)
    for item in record["audit_lines"]:
        item = fields(item, {"offset", "line"}, "transport audit line")
        integer(item["offset"], 0, MAX_TRANSPORT_LOG_BYTES - 1, "transport line offset")
        require(isinstance(item["line"], str), "transport audit line is not text")
    require(record["audit_lines"] == selected, "transport audit lines omit or substitute raw observations")
    rows: dict[int, set[int]] = {}
    custody = False
    applied = 0
    counted = 0
    for event in observations:
        require(integer(event.get("process_id"), 1, 2**32 - 1, "audit PID") == process["pid"],
                "transport audit came from another process")
        integer(event.get("height"), 2, 2**64 - 1, "audit height")
        message = event["message"]
        if message == "sumeragi block applied":
            require(custody and event.get("result") == record["result"],
                    "application differs from certified result or lacks transport custody")
            applied += 1
            continue
        require(applied == 0, "transport custody appeared after application")
        require(event.get("availability_digest") == record["availability_digest"], "transport table substituted")
        acquisition = integer(event.get("acquisition"), 0, 2**64 - 1, "transport acquisition")
        if message == "sumeragi payload row admitted":
            require(acquisition != 0 and (acquisition in rows or len(rows) < 4096),
                    "invalid or excessive transport acquisition identities")
            index = integer(event.get("index"), 0, stripes * 6 - 1, "transport row index")
            sender = event.get("from")
            require(sender in record["peer_keys"] and sender != record["local_key"],
                    "transport row sender is not a remote configured peer")
            admitted = rows.setdefault(acquisition, set())
            require(index not in admitted, "transport repeats an admitted row")
            admitted.add(index)
            continue
        require(not custody, "duplicate transport custody completion")
        for name, maximum in (("epoch", 2**64 - 1), ("proposer", 3), ("payload_bytes", 16 * 1024 * 1024)):
            require(integer(event.get(name), 0, maximum, f"audit {name}") == record[name],
                    "transport custody differs from certified original source")
        require(event.get("context") == record["context"] and event.get("payload_hash") == record["payload_hash"],
                "transport custody differs from certified original source")
        count = integer(event.get("accepted_rows"), 0, stripes * 6, "audit accepted rows")
        if event.get("origin") == "author":
            require(author and acquisition == 0 and count == 0, "non-author substituted authored custody")
        elif event.get("origin") == "network_rows":
            admitted = rows.pop(acquisition, set())
            require(acquisition != 0 and len(admitted) == count
                    and all(sum(stripe * 6 <= row < (stripe + 1) * 6 for row in admitted) >= 4
                            for stripe in range(stripes)), "network custody lacks actual distinct stripe rows")
            counted = count
        else:
            raise CampaignError("storage or unknown custody cannot qualify network transport")
        custody = True
    require(custody and applied == 1 and counted == accepted,
            "transport custody/application count differs")
    return canonical({name: record[name] for name in ("network_id", "instance", "height", "block", "result",
        "availability_digest", "payload_hash", "payload_bytes", "epoch", "context", "proposer",
        "data_shards", "parity_shards", "stripes")})


def validate_smoke_result_heights(result: dict[str, Any]) -> tuple[int, int, int]:
    """Bind nonzero genesis readiness and subsequent authority/finality observations.

    The experimental result's ``activation_height`` is the committed height of
    the first successful exact Active-genesis capability observation, not a
    scheduled lifecycle transition. Pool authority must be observed afterward.
    """
    activation = integer(result["activation_height"], 1, 2**64 - 2, "genesis readiness height")
    authority = integer(result["authority_context_height"], activation + 1, 2**64 - 1, "authority height")
    finalized = integer(result["finalized_height"], authority, 2**64 - 1, "finalized height")
    return activation, authority, finalized


def validate_certificates(evidence: dict[str, Any], result: dict[str, Any], identities: list[Any]) -> bytes:
    """Check the retained three participant authorities and full Prepare/Commit/receipt bindings."""
    receipt = fields(evidence["receipt.json"], {"version", "manifest", "authority_catalog", "legs",
                                               "finalized_height"}, "receipt")
    barrier = fields(evidence["prepare-barrier.json"], {"version", "manifest", "authority_catalog", "deltas",
                        "prepare_certificates", "prepared_bundle_digest"}, "Prepare barrier")
    manifest = receipt["manifest"]
    activation, authority, finalized = validate_smoke_result_heights(result)
    manifest_authority = integer(manifest["authority_context_height"], activation + 1, 2**64 - 1,
                                 "manifest authority height")
    # The authority context precedes expiry; the final admissible height is inclusive.
    expiry = integer(manifest["expiry_height"], authority + 1, 2**64 - 1, "manifest expiry height")
    require(manifest_authority == authority and finalized <= expiry,
            "receipt/Prepare authority or expiry window substitution")
    require(all(type(row["version"]) is int and row["version"] == 1 for row in (receipt, barrier, manifest))
            and receipt["finalized_height"] == result["finalized_height"]
            and receipt["manifest"] == barrier["manifest"]
            and receipt["authority_catalog"] == barrier["authority_catalog"]
            and manifest["network_id"] == result["network_id"]
            and manifest["authority_context_height"] == result["authority_context_height"]
            and manifest["expiry_height"] >= result["finalized_height"], "receipt/Prepare manifest substitution")
    bundle = bytes.fromhex(protocol_hash(manifest["bundle_id"], "bundle ID"))
    authorities, commits = evidence["authorities.json"], evidence["commit-certificates.json"]
    vectors = (manifest["legs"], receipt["legs"], barrier["deltas"], barrier["prepare_certificates"], authorities, commits)
    require(all(isinstance(vector, list) and len(vector) == 3 for vector in vectors), "incomplete three-leg certificates")
    catalog = fields(barrier["authority_catalog"], {"rosters", "leg_roster_indices"}, "authority catalog")
    require(catalog["leg_roster_indices"] == [0, 1, 2]
            and all(type(index) is int for index in catalog["leg_roster_indices"])
            and len(catalog["rosters"]) == 3,
            "smoke requires three disjoint participant rosters")
    routes = set()
    for ordinal in range(3):
        authority = fields(authorities[ordinal], {"route", "validator_set_hash", "validators", "validator_pops"}, "authority")
        route = authority["route"]
        routes.add(canonical(route))
        peers = authority["validators"]
        require(isinstance(peers, list) and len(peers) == 4
                and len({canonical(peer) for peer in peers}) == 4
                and {canonical(peer) for peer in peers} == {canonical(peer) for peer in identities[(ordinal + 1)*4:(ordinal + 2)*4]},
                "participant authority does not bind its configured disjoint committee")
        roster = {name: authority[name] for name in ("validator_set_hash", "validators", "validator_pops")}
        require(catalog["rosters"][ordinal] == roster and len(authority["validator_pops"]) == 4,
                "catalog authority substitution")
        for pop in authority["validator_pops"]:
            byte_vector(pop, "participant PoP", minimum=96, maximum=96)
        leg = fields(receipt["legs"][ordinal], {"delta", "prepare", "commit"}, "receipt leg")
        commitment = manifest["legs"][ordinal]
        require(integer(commitment["ordinal"], 0, 2, "manifest leg ordinal") == ordinal and commitment["route"] == route
                and leg["delta"] == barrier["deltas"][ordinal]
                and integer(leg["delta"]["leg_ordinal"], 0, 2, "delta leg ordinal") == ordinal and leg["delta"]["route"] == route
                and leg["prepare"] == barrier["prepare_certificates"][ordinal]
                and leg["commit"] == commits[ordinal], "leg certificate/delta/route substitution")
        for phase in ("prepare", "commit"):
            cert = fields(leg[phase], {"body", "authority_catalog_index", "signers_bitmap", "aggregate_signature"}, "phase certificate")
            body = cert["body"]
            bitmap = integer(cert["signers_bitmap"], 1, 15, "signer bitmap")
            require(bitmap.bit_count() == 3
                    and integer(cert["authority_catalog_index"], 0, 2, "certificate leg slot") == ordinal,
                    "participant QC lacks exact three-of-four signers")
            byte_vector(cert["aggregate_signature"], "participant aggregate", minimum=96, maximum=96)
            require(body["network_id"] == manifest["network_id"] and body["bundle_id"] == manifest["bundle_id"]
                    and integer(body["leg_ordinal"], 0, 2, "certificate leg ordinal") == ordinal and body["route"] == route
                    and body["authority_context_height"] == manifest["authority_context_height"]
                    and body["expiry_height"] == manifest["expiry_height"]
                    and body["delta_digest"] == commitment["delta_digest"]
                    and body["phase"] == {"phase": phase, "value": None}, "phase signed-body substitution")
            prepared = protocol_hash(body["prepared_bundle_digest"], "prepared bundle digest", allow_empty=True)
            require((phase == "prepare" and prepared == EMPTY_PROTOCOL_HASH) or
                    (phase == "commit" and prepared not in ("0" * 64, EMPTY_PROTOCOL_HASH)
                     and body["prepared_bundle_digest"] == barrier["prepared_bundle_digest"]), "Commit bypasses all-Prepare barrier")
        require(all(leg["prepare"]["body"][name] == leg["commit"]["body"][name]
                    for name in ("manifest_digest", "authority_digest")), "Prepare/Commit binding changed")
    require(len(routes) == 3, "participant routes overlap")
    return bundle


def validate_run(path: Path, request: dict[str, Any], validator_sha: str,
                 *, kind: str = "smoke") -> dict[str, Any]:
    """Validate the exact financial evidence population of the selected experiment."""
    require(kind in ("smoke", "happy_day"), "unknown experiment kind")
    evidence_names = EVIDENCE_NAMES if kind == "smoke" else HAPPY_DAY_EVIDENCE_NAMES
    owner_path(path, directory=True)
    evidence_path = path / "evidence"
    owner_path(evidence_path, directory=True)
    result = fields(read_json(path / "rust-result.json"), {"version", "protocol", "kind", "request",
        "request_sha256", "network_id", "participants", "processes", "restarted", "activation_height",
        "authority_context_height", "finalized_height", "signed_rs16_observations", "continuous_checks",
        "passed", "artifacts"}, "Rust smoke result")
    validate_request(result["request"], request["commit"], request["run"], kind=kind)
    require(result["request"] == request and result["request_sha256"] == sha(read_bytes(path / "request.json"))
            and type(result["version"]) is int and result["version"] == 1
            and result["protocol"] == PROTOCOL and result["kind"] == kind
            and result["passed"] is True, "unbound Rust result")
    for name, expected in (("participants", 3), ("processes", 16),
                           ("restarted", 16 if kind == "smoke" else 0), ("signed_rs16_observations", 16)):
        require(type(result[name]) is int and result[name] == expected, f"wrong {name}")
    _activation, _authority, height = validate_smoke_result_heights(result)
    require({item.name for item in evidence_path.iterdir()} == evidence_names, "incomplete or extra experiment evidence files")
    inventory = result["artifacts"]
    require(isinstance(inventory, list) and len(inventory) == len(evidence_names), "incomplete artifact manifest")
    evidence = {}
    evidence_raw = {}
    for item in inventory:
        entry = fields(item, {"name", "bytes", "sha256"}, "evidence entry")
        name = entry["name"]
        require(isinstance(name, str) and name in evidence_names and name not in evidence,
                "duplicate or unsafe evidence entry")
        limit = MAX_TRANSPORT_LOG_BYTES if name.endswith(".log") else MAX_JSON_BYTES
        raw = read_bytes(evidence_path / name, limit=limit)
        require(integer(entry["bytes"], 1, limit, "evidence size") == len(raw)
                and entry["sha256"] == sha(raw), "evidence byte/digest mismatch")
        evidence_raw[name] = raw
        evidence[name] = raw if name.endswith(".log") else release_runner.strict_json_loads(raw.decode("utf-8"), name)
    validate_request(evidence["request.json"], request["commit"], request["run"], kind=kind)
    require(evidence["request.json"] == request, "Rust evidence replays another request")
    identities = validate_inventory(evidence["processes-before.json"], evidence["processes-after.json"],
                                    evidence["restarts.json"] if kind == "smoke" else None,
                                    validator_sha, kind=kind)
    bundle = validate_certificates(evidence, result, identities)
    before, after = validate_states(evidence, height, kind=kind)
    checks = sum(validate_continuous(evidence[f"continuous-{peer:02}.json"], peer, bundle, before, after)
                 for peer in range(16))
    require(integer(result["continuous_checks"], 48, 160_000, "total continuous checks") == checks,
            "aggregate continuous coverage mismatch")
    anchors = {validate_finality(evidence[f"finality-{phase}-{peer:02}.json"], result, identities)
               for phase in (("before", "after") if kind == "smoke" else ("before",)) for peer in range(16)}
    require(len(anchors) == 1, "peers/restarts disagree on finalized block header or committee")
    sources = {validate_transport(evidence[f"finality-before-transport-{peer:02}.json"],
        evidence_raw[f"finality-before-transport-{peer:02}.log"],
        evidence_raw[f"finality-before-{peer:02}.json"], evidence[f"finality-before-{peer:02}.json"],
        result, evidence["processes-before.json"], peer) for peer in range(16)}
    require(len(sources) == 1, "peers disagree on certified original transport source")
    require(len({evidence[f"finality-before-transport-{peer:02}.json"]["stdout_path"]
                 for peer in range(16)}) == 16, "transport process log paths overlap")
    return {"network_id": result["network_id"], "bundle_id": bundle.hex(),
            "validator_identities": identities, "finalized_height": height, "continuous_checks": checks,
            "result_sha256": sha(read_bytes(path / "rust-result.json"))}


def sanitized_environment() -> dict[str, str]:
    """Allow only toolchain/user paths; do not inherit test, compiler, or loader overrides."""
    allowed = {"PATH", "HOME", "USER", "LOGNAME", "TMPDIR", "TEMP", "TMP", "CARGO_HOME", "RUSTUP_HOME",
               "SYSTEMROOT", "GNUPGHOME", "GPG_TTY"}
    environment = {name: value for name, value in os.environ.items() if name in allowed}
    environment.update({"LC_ALL": "C", "LANG": "C", "CARGO_BUILD_JOBS": "4", "CARGO_INCREMENTAL": "0",
                        "SCCACHE_DISABLE": "1",
                        "RUST_BACKTRACE": "1", "GIT_CONFIG_NOSYSTEM": "1", "GIT_NO_REPLACE_OBJECTS": "1"})
    return environment


def git_bytes(repo: Path, arguments: list[str]) -> bytes:
    """Execute one read-only Git operation without inherited Git overrides."""
    result = subprocess.run(["git", "-C", str(repo), *arguments], env=sanitized_environment(),
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
    require(result.returncode == 0, f"Git {' '.join(arguments)} failed: {result.stderr.decode(errors='replace')}")
    return result.stdout


def source_seal(repo: Path, commit: str) -> dict[str, Any]:
    """Bind the signed commit to the canonical clean release-source identity.

    The shared checker verifies raw tracked bytes and accepts gitlinks only as
    empty directories. Populated documentation checkouts remain unqualified.
    """
    digest(commit, "signed commit", (40, 64))
    require(repo.is_absolute() and repo.resolve(strict=True) == repo, "repository must be canonical")
    require(git_bytes(repo, ["rev-parse", "--show-toplevel"]).decode().strip() == str(repo), "not a repository root")
    require(git_bytes(repo, ["rev-parse", "HEAD"]).decode().strip() == commit, "HEAD differs from exact requested commit")
    git_bytes(repo, ["verify-commit", commit])
    try:
        identity = _SOURCE_TOOLS.release_source_identity(repo)
        require(identity["head_commit"] == commit
                and identity["head_tree"] == identity["index_tree"], "canonical source commit/tree differs")
        signed_paths = set()
        for entry in git_bytes(repo, ["ls-tree", "-rz", commit]).split(b"\0"):
            if not entry:
                continue
            metadata, encoded_path = entry.split(b"\t", 1)
            mode, kind, _ = metadata.decode("ascii").split()
            require((kind == "blob" and mode in {"100644", "100755", "120000"})
                    or (kind == "commit" and mode == "160000"), "unsupported source inventory mode")
            signed_paths.add(os.fsdecode(encoded_path))
        reject_unsigned_cargo_configuration(repo, signed_paths)
        repeated = _SOURCE_TOOLS.release_source_identity(repo)
    except (RuntimeError, subprocess.SubprocessError) as error:
        raise CampaignError(f"canonical release source refused: {error}") from error
    require(signed_paths and repeated == identity, "source changed during sealing")
    return {"commit": commit, "tree": identity["head_tree"], "tracked_files": len(signed_paths),
            "source_sha256": identity["workspace_source_manifest_sha256"]}


def reject_unsigned_cargo_configuration(repo: Path, signed_paths: set[str]) -> None:
    """Reject ignored or external Cargo configuration that could change the build.

    Cargo searches the invocation directory, its ancestors and Cargo home.
    Only configurations inside this checkout and present in the signed tree
    are admissible. The compiler/toolchain, dependency cache and system linker
    remain host prerequisites; their version receipts are retained separately.
    """
    roots = {directory / ".cargo" for directory in (repo, *repo.parents)}
    cargo_home = Path(os.environ.get("CARGO_HOME", str(Path.home() / ".cargo")))
    require(cargo_home.is_absolute() and cargo_home.resolve() == cargo_home,
            "Cargo home must be absolute and canonical so caller/build directories agree")
    roots.add(cargo_home)
    for root in roots:
        for name in ("config", "config.toml"):
            path = root / name
            if not path.exists() and not path.is_symlink():
                continue
            require(repo in path.parents and str(path.relative_to(repo)) in signed_paths,
                    f"unsigned Cargo build configuration: {path}")
            require(not path.is_symlink() and path.resolve(strict=True) == path,
                    f"Cargo configuration must not traverse a symlink: {path}")


def toolchain_commands() -> dict[str, list[str]]:
    """Retain compiler/Cargo version provenance without claiming a hermetic system toolchain."""
    return {"toolchain-rustc": ["rustc", "--version", "--verbose"],
            "toolchain-cargo": ["cargo", "--version", "--verbose"]}


def command(arguments: list[str], repo: Path, environment: dict[str, str], directory: Path, name: str,
            *, check: bool = True) -> dict[str, Any]:
    """Run once without timeouts/retries/signals and retain terminal output even on failure."""
    output = directory / f"{name}.log"
    descriptor = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    started = time.time_ns()
    try:
        with os.fdopen(descriptor, "wb", closefd=False) as stream:
            # umask is explicit for every Rust-created result/config/evidence file.
            completed = subprocess.run(arguments, cwd=repo, env=environment, stdout=stream,
                                       stderr=subprocess.STDOUT, check=False, umask=0o077)
            stream.flush()
            os.fsync(descriptor)
        record = {"version": 1, "command": arguments, "exit_code": completed.returncode,
                  "started_ns": started, "finished_ns": time.time_ns(), "log": output.name,
                  "log_sha256": file_digest(output),
                  "worker_environment": {key: environment.get(key) for key in WORKER_ENVIRONMENT_KEYS}}
    finally:
        os.close(descriptor)
    write_json(directory / f"{name}.json", record)
    require(not check or completed.returncode == 0, f"command failed ({completed.returncode}); retained {output}")
    return record


def build_commands(repo: Path, target: Path) -> dict[str, list[str]]:
    """Request the Metal smoke capability and its declared native dependencies."""
    prefix = [str(repo / "scripts/cargo_fast.sh"), "--no-sccache", "--no-incremental", "--jobs", "4", "--"]
    common = ["--locked", "--offline", "--release"]
    return {
        "build-validator": prefix + ["build", *common, "-p", "irohad", "--bin", "iroha3d",
                                      "--features", "test-network-private-settlement-route-control", "--target-dir", str(target)],
        "build-integration": prefix + ["test", *common, "-p", "integration_tests", "--test", "nexus_and_streaming",
            "--features", "atomic-private-settlement-smoke", "--no-run", "--message-format=json",
            "--target-dir", str(target)],
    }


def artifact_bindings(validator: Path, integration: Path) -> dict[str, Any]:
    """Capture the exact executable paths and bytes used by every run."""
    result = {}
    for name, path in (("validator", validator), ("integration", integration)):
        require(path.is_absolute() and path.resolve(strict=True) == path
                and os.access(path, os.X_OK), f"{name} artifact is not a canonical executable")
        result[name] = {"path": str(path), "sha256": file_digest(path)}
    return result


def discover_artifact(log: Path, target: Path) -> Path:
    """Select the unique test executable reported by Cargo's compiler-artifact records."""
    matches = set()
    for line in read_bytes(log, limit=256 * 1024 * 1024).decode("utf-8").splitlines():
        if not line.startswith("{"):
            continue
        row = release_runner.strict_json_loads(line, "Cargo build output")
        if (row.get("reason") == "compiler-artifact" and row.get("target", {}).get("name") == "nexus_and_streaming"
                and row.get("target", {}).get("kind") == ["test"] and row.get("executable")):
            matches.add(row["executable"])
    require(len(matches) == 1, "Cargo did not report exactly one integration test executable")
    result = Path(matches.pop())
    require(result.is_absolute() and result.resolve(strict=True) == result
            and result.parent == target / "release" / "deps", "Cargo test artifact is outside the bound target")
    return result


def validate_discovery(output: str) -> None:
    """Require exact ignored-test discovery rather than relying on a substring filter."""
    require(output.strip().splitlines() == [f"{TEST_NAME}: test", "", "1 test, 0 benchmarks"],
            "exact ignored smoke test discovery failed")


def invocation_environment(request_path: Path, evidence: Path, result_path: Path, validator: dict[str, str]) -> dict[str, str]:
    """Construct the strict network/request environment from retained bytes only."""
    environment = sanitized_environment()
    environment.update({"RAYON_NUM_THREADS": str(RAYON_WORKER_THREADS),
        "IROHA_TEST_REQUIRE_NETWORK": "1", "IROHA_TEST_NETWORK_START_ATTEMPTS": "1",
        "IROHA_TEST_SKIP_BUILD": "1", "IROHA_TEST_BUILD_PROFILE": "release",
        "TEST_NETWORK_BIN_IROHAD_PRIVATE_SETTLEMENT_ROUTES": validator["path"],
        "APS_REAL_PROCESS_REQUEST": str(request_path), "APS_REAL_PROCESS_RESULT": str(result_path),
        "APS_REAL_PROCESS_REQUEST_SHA256": sha(read_bytes(request_path)),
        "APS_REAL_PROCESS_VALIDATOR_SHA256": validator["sha256"], "APS_REAL_PROCESS_EVIDENCE_DIR": str(evidence)})
    return environment


def run_campaign(repo: Path, output: Path, target: Path, commit: str) -> dict[str, Any]:
    """Build once and run ten fresh serialized positive gates, stopping at the first failure."""
    repo = repo.resolve(strict=True)
    outside_repo(output, repo)
    require(target.is_absolute() and target.resolve() == target, "target directory must be canonical")
    require(not target.exists() and not target.is_symlink(), "smoke requires a fresh build target directory")
    require(output not in target.parents and target not in output.parents and target != output,
            "build and evidence directories must be disjoint")
    output.mkdir(mode=0o700)
    owner_path(output, directory=True)
    try:
        environment = sanitized_environment()
        signature = command(["git", "verify-commit", commit], repo, environment, output, "verify-commit")
        seal = source_seal(repo, commit)
        require((repo / "scripts/private_settlement_smoke_campaign.py").resolve() == Path(__file__).resolve(),
                "run this driver from the exact signed source checkout")
        write_json(output / "source.json", seal)
        toolchain = {name: command(arguments, repo, environment, output, name)
                     for name, arguments in toolchain_commands().items()}
        builds = {}
        for name, arguments in build_commands(repo, target).items():
            require(source_seal(repo, commit) == seal, "source drift before build")
            builds[name] = command(arguments, repo, environment, output, name)
            require(source_seal(repo, commit) == seal, "source drift during build")
        validator = target / "release" / "iroha3d"
        integration = discover_artifact(output / "build-integration.log", target)
        binaries = artifact_bindings(validator, integration)
        write_json(output / "artifacts.json", binaries)
        discovery = command([str(integration), TEST_NAME, "--exact", "--ignored", "--list"],
                            repo, environment, output, "discovery")
        validate_discovery(read_bytes(output / "discovery.log").decode())
        runs = []
        fresh = {name: set() for name in ("request_id", "seed", "invocation_nonce", "network_id", "bundle_id", "identity")}
        for index in range(RUN_COUNT):
            directory = output / f"run-{index:02}"
            directory.mkdir(mode=0o700)
            evidence = directory / "evidence"
            evidence.mkdir(mode=0o700)
            request = new_request(commit, index)
            for name in ("request_id", "seed", "invocation_nonce"):
                require(request[name] not in fresh[name], f"fresh request collision: {name}")
                fresh[name].add(request[name])
            write_json(directory / "request.json", request)
            require(source_seal(repo, commit) == seal and artifact_bindings(validator, integration) == binaries,
                    "source or executable drift before smoke")
            write_json(directory / "before.json", {"source": seal, "artifacts": binaries})
            run_environment = invocation_environment(directory / "request.json", evidence,
                                                     directory / "rust-result.json", binaries["validator"])
            receipt = command([str(integration), TEST_NAME, "--exact", "--ignored", "--nocapture", "--test-threads=1"],
                              repo, run_environment, directory, "stdout", check=False)
            post_source, post_binaries = source_seal(repo, commit), artifact_bindings(validator, integration)
            write_json(directory / "after.json", {"source": post_source, "artifacts": post_binaries})
            require(post_source == seal and post_binaries == binaries, "source or executable drift during smoke")
            require(receipt["exit_code"] == 0, f"smoke run {index} failed; all output retained in {directory}")
            output_text = read_bytes(directory / "stdout.log", limit=256 * 1024 * 1024).decode("utf-8")
            terminal_success(output_text)
            validate_process_closure(output_text)
            summary = validate_run(directory, request, binaries["validator"]["sha256"])
            for name in ("network_id", "bundle_id"):
                identity = canonical(summary[name])
                require(identity not in fresh[name], f"smoke reused a {name}")
                fresh[name].add(identity)
            for peer in summary["validator_identities"]:
                identity = canonical(peer)
                require(identity not in fresh["identity"], "smoke reused validator identities across runs")
                fresh["identity"].add(identity)
            runs.append({"run": index, "request_id": request["request_id"], "result_sha256": summary["result_sha256"],
                         "command_sha256": sha(canonical(receipt)), "summary": summary})
        campaign = {"version": 1, "protocol": PROTOCOL, "kind": "smoke_campaign", "runs": runs,
                    "repo": str(repo), "target": str(target), "source": seal, "artifacts": binaries,
                    "builds": builds, "toolchain": toolchain, "signature_verification": signature, "discovery": discovery,
                    "passed": True, "cryptographic_scope": CRYPTOGRAPHIC_SCOPE}
        write_json(output / "campaign.json", campaign)
        return validate_campaign(output, expected_commit=commit)
    except Exception as error:
        write_json(output / "failure.json", {"version": 1, "passed": False, "error": str(error),
                                             "time_ns": time.time_ns()})
        raise


def validate_command_record(path: Path, arguments: list[str], *, proving: bool = False) -> dict[str, Any]:
    """Validate a successful terminal command, its worker environment, and retained log."""
    record = fields(read_json(path), {"version", "command", "exit_code", "started_ns", "finished_ns", "log",
                                     "log_sha256", "worker_environment"}, "command receipt")
    require(type(record["version"]) is int and record["version"] == 1
            and type(record["exit_code"]) is int and record["exit_code"] == 0
            and record["command"] == arguments and record["log"] == path.with_suffix(".log").name,
            "failed/substituted command receipt")
    require(record["worker_environment"] == {
        "RAYON_NUM_THREADS": str(RAYON_WORKER_THREADS) if proving else None,
        "RUST_TEST_THREADS": None, "CARGO_BUILD_JOBS": "4", "CARGO_INCREMENTAL": "0",
    }, "command worker environment differs from the pinned invocation")
    start = integer(record["started_ns"], 1, 2**64 - 1, "command start")
    integer(record["finished_ns"], start, 2**64 - 1, "command finish")
    raw = read_bytes(path.with_suffix(".log"), limit=256 * 1024 * 1024)
    require(record["log_sha256"] == sha(raw), "retained command output changed")
    return record


def validate_campaign(path: Path | str, *, expected_commit: str | None = None) -> dict[str, Any]:
    """Read-only positive-gate prerequisite API; reject incomplete, stale, or changed campaigns.

    Revalidates the signed checkout and both executable files as well as every
    retained record. It performs no build, network startup, repair, or write.
    Callers must retain the checkout and artifacts until qualification ends.
    """
    path = Path(path)
    owner_path(path, directory=True)
    require(not (path / "failure.json").exists(), "campaign retains a failure; it is not qualifying evidence")
    campaign = fields(read_json(path / "campaign.json"), {"version", "protocol", "kind", "runs", "repo", "target",
        "source", "artifacts", "builds", "toolchain", "signature_verification", "discovery", "passed", "cryptographic_scope"}, "campaign")
    require(type(campaign["version"]) is int and campaign["version"] == 1
            and campaign["protocol"] == PROTOCOL and campaign["kind"] == "smoke_campaign"
            and campaign["passed"] is True and campaign["cryptographic_scope"] == CRYPTOGRAPHIC_SCOPE,
            "campaign is not a current completed smoke gate")
    repo, target = Path(campaign["repo"]), Path(campaign["target"])
    outside_repo(path, repo)
    seal = campaign["source"]
    commit = digest(seal["commit"], "campaign commit", (40, 64))
    require(expected_commit is None or commit == expected_commit, "campaign uses another source commit")
    require(read_json(path / "source.json") == seal and source_seal(repo, commit) == seal, "campaign signed source changed")
    binaries = campaign["artifacts"]
    require(read_json(path / "artifacts.json") == binaries
            and artifact_bindings(Path(binaries["validator"]["path"]), Path(binaries["integration"]["path"])) == binaries,
            "campaign executable bytes changed")
    require(Path(binaries["validator"]["path"]) == target / "release" / "iroha3d"
            and discover_artifact(path / "build-integration.log", target) == Path(binaries["integration"]["path"]),
            "build artifact path binding changed")
    signature = validate_command_record(path / "verify-commit.json", ["git", "verify-commit", commit])
    require(campaign["signature_verification"] == signature, "signature command substituted")
    previous_end = signature["finished_ns"]
    require(set(campaign["toolchain"]) == set(toolchain_commands()), "incomplete compiler/Cargo provenance")
    for name, arguments in toolchain_commands().items():
        record = validate_command_record(path / f"{name}.json", arguments)
        require(campaign["toolchain"][name] == record and record["started_ns"] >= previous_end,
                "toolchain provenance command changed/overlapping")
        previous_end = record["finished_ns"]
    require(set(campaign["builds"]) == set(build_commands(repo, target)), "unexpected or missing build commands")
    for name, arguments in build_commands(repo, target).items():
        record = validate_command_record(path / f"{name}.json", arguments)
        require(campaign["builds"].get(name) == record and record["started_ns"] >= previous_end,
                "builds overlap or differ from retained commands")
        previous_end = record["finished_ns"]
    integration = binaries["integration"]["path"]
    discovery = validate_command_record(path / "discovery.json", [integration, TEST_NAME, "--exact", "--ignored", "--list"])
    require(campaign["discovery"] == discovery and discovery["started_ns"] >= previous_end, "discovery command substituted/overlapping")
    validate_discovery(read_bytes(path / "discovery.log").decode())
    previous_end = discovery["finished_ns"]
    require(isinstance(campaign["runs"], list) and len(campaign["runs"]) == RUN_COUNT, "campaign requires ten complete runs")
    expected_root = {"campaign.json", "source.json", "artifacts.json"}
    expected_root |= {f"{name}.{suffix}" for name in ("verify-commit", "toolchain-rustc", "toolchain-cargo",
                                                    "build-validator", "build-integration", "discovery")
                      for suffix in ("json", "log")}
    expected_root |= {f"run-{index:02}" for index in range(10)}
    require({entry.name for entry in path.iterdir()} == expected_root, "extra or missing campaign artifacts")
    seen = {name: set() for name in ("request_id", "invocation_nonce", "seed", "network_id", "bundle_id", "identity")}
    for index, item in enumerate(campaign["runs"]):
        row = fields(item, {"run", "request_id", "result_sha256", "command_sha256", "summary"}, "campaign run")
        directory = path / f"run-{index:02}"
        owner_path(directory, directory=True)
        require({entry.name for entry in directory.iterdir()} == {"request.json", "rust-result.json", "stdout.log",
            "stdout.json", "before.json", "after.json", "evidence"}, "extra or missing run artifacts")
        request = validate_request(read_json(directory / "request.json"), commit, index)
        require(integer(row["run"], 0, 9, "campaign run") == index
                and row["request_id"] == request["request_id"], "run order/request substitution")
        for name in ("request_id", "invocation_nonce", "seed"):
            require(request[name] not in seen[name], f"reused {name}")
            seen[name].add(request[name])
        for phase in ("before", "after"):
            require(read_json(directory / f"{phase}.json") == {"source": seal, "artifacts": binaries},
                    "per-run source/executable seal changed")
        record = validate_command_record(directory / "stdout.json", [integration, TEST_NAME, "--exact", "--ignored",
                                        "--nocapture", "--test-threads=1"], proving=True)
        require(record["started_ns"] >= previous_end and row["command_sha256"] == sha(canonical(record)),
                "smoke runs overlap or command receipt changed")
        previous_end = record["finished_ns"]
        output_text = read_bytes(directory / "stdout.log", limit=256 * 1024 * 1024).decode()
        terminal_success(output_text)
        validate_process_closure(output_text)
        summary = validate_run(directory, request, binaries["validator"]["sha256"])
        require(row["summary"] == summary and row["result_sha256"] == summary["result_sha256"], "run summary changed")
        for name in ("network_id", "bundle_id"):
            key = canonical(summary[name])
            require(key not in seen[name], f"reused {name}")
            seen[name].add(key)
        for peer in summary["validator_identities"]:
            key = canonical(peer)
            require(key not in seen["identity"], "validator identity reused across runs")
            seen["identity"].add(key)
    require(source_seal(repo, commit) == seal
            and artifact_bindings(Path(binaries["validator"]["path"]), Path(integration)) == binaries,
            "source/executable changed during campaign validation")
    return campaign


def main(argv: list[str] | None = None) -> int:
    """Expose explicit run and read-only validate entrypoints."""
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="action", required=True)
    execute = commands.add_parser("run", help="build once and execute ten fresh real networks serially")
    execute.add_argument("--repo", type=Path, default=SCRIPT_DIR.parent)
    execute.add_argument("--output", type=Path, required=True, help="fresh canonical owner-only directory OUTSIDE the repository")
    execute.add_argument("--target-dir", type=Path, required=True, help="fresh canonical build directory; prebuilt targets are rejected")
    execute.add_argument("--commit", required=True, help="exact signed clean HEAD (full 40/64 lowercase hex)")
    validate = commands.add_parser("validate", help="read and revalidate all retained evidence without executing a network")
    validate.add_argument("campaign", type=Path)
    validate.add_argument("--commit", help="required source commit for a later campaign prerequisite")
    arguments = parser.parse_args(argv)
    try:
        if arguments.action == "run":
            result = run_campaign(arguments.repo, arguments.output, arguments.target_dir, arguments.commit)
        else:
            result = validate_campaign(arguments.campaign, expected_commit=arguments.commit)
        print(f"Validated {len(result['runs'])} fresh N=3 smoke runs at signed commit {result['source']['commit']}")
        return 0
    except (OSError, ValueError, KeyError, TypeError, release_runner.RunnerError) as error:
        print(f"Smoke campaign failed: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
