#!/usr/bin/env python3
"""Synthetic adversarial tests for the smoke evidence validator and serial driver.

These fixtures are explicitly unmeasured and contain no valid BLS proof. Tests
never run Cargo, Git signing, validator binaries, or a network. All files live
in disposable owner-only temporary directories; none are release evidence.
"""

from __future__ import annotations

from contextlib import ExitStack, contextmanager
import copy
import hashlib
import importlib.util
import os
from pathlib import Path
import struct
import tempfile
import unittest
from unittest import mock

SCRIPT = Path(__file__).resolve().parents[1] / "private_settlement_smoke_campaign.py"
SPEC = importlib.util.spec_from_file_location("smoke_campaign_under_test", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
M = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(M)
COMMIT = "a" * 40


@contextmanager
def canonical_source_fixture(*, gitlink: bool = False):
    """Use real canonical byte checks with synthetic read-only Git metadata."""
    with tempfile.TemporaryDirectory(prefix="synthetic-canonical-source-") as temporary:
        base = Path(temporary).resolve()
        root = base / "repo"
        root.mkdir()
        cargo_home = base / "cargo-home"
        cargo_home.mkdir()
        entries = []
        for relative, contents in (("Cargo.lock", b"# synthetic locked input\n"),
                                   ("source.rs", b"// synthetic signed blob fixture\n")):
            path = root / relative
            path.write_bytes(contents)
            path.chmod(0o644)
            blob = hashlib.sha1(f"blob {len(contents)}\0".encode() + contents).hexdigest()
            entries.append((relative.encode(), "100644", blob))
        if gitlink:
            (root / "docs").mkdir()
            entries.append((b"docs", "160000", "d" * 40))
        entries.sort()
        paths = [os.fsdecode(path) for path, _, _ in entries]
        listing = b"".join(
            f"{mode} {'commit' if mode == '160000' else 'blob'} {oid}\t".encode() + path + b"\0"
            for path, mode, oid in entries
        )
        responses = {
            ("rev-parse", "--show-toplevel"): str(root).encode() + b"\n",
            ("rev-parse", "HEAD"): COMMIT.encode() + b"\n",
            ("verify-commit", COMMIT): b"",
            ("ls-tree", "-rz", COMMIT): listing,
        }
        canonical_responses = {
            ("rev-parse", "--verify", "HEAD^{commit}"): COMMIT,
            ("rev-parse", "--verify", f"{COMMIT}^{{tree}}"): "b" * 40,
            ("rev-parse", "--show-object-format"): "sha1",
        }
        with ExitStack() as stack:
            stack.enter_context(mock.patch.dict(os.environ, {"CARGO_HOME": str(cargo_home)}))
            git = stack.enter_context(mock.patch.object(
                M, "git_bytes", side_effect=lambda _root, args: responses[tuple(args)]))
            stack.enter_context(mock.patch.object(M._SOURCE_TOOLS, "_reject_active_git_operations"))
            stack.enter_context(mock.patch.object(M._SOURCE_TOOLS, "_git_unmerged_paths", return_value=[]))
            stack.enter_context(mock.patch.object(M._SOURCE_TOOLS, "_git_paths", return_value=[]))
            stack.enter_context(mock.patch.object(M._SOURCE_TOOLS, "_git_index_entries", return_value=entries))
            stack.enter_context(mock.patch.object(M._SOURCE_TOOLS, "_git_source_paths", return_value=paths))
            stack.enter_context(mock.patch.object(M._SOURCE_TOOLS, "_git_stdout",
                side_effect=lambda _root, *args: canonical_responses[args]))
            yield root, git


def hash_literal(number: int, *, mark: bool = True) -> str:
    """Mirror Hash::prehashed's low marker bit and JSON checksum for synthetic data."""
    body = f"{number | 1 if mark else number:064X}"
    crc = 0xFFFF
    for byte in f"hash:{body}".encode("ascii"):
        crc ^= byte << 8
        for _ in range(8):
            crc = ((crc << 1) ^ 0x1021) & 0xFFFF if crc & 0x8000 else (crc << 1) & 0xFFFF
    return f"hash:{body}#{crc:04X}"


def observation(peer: int, finalized: bool, *, staged: bool = False, local_only: bool = False, baseline_height: int = 302,
                finalized_height: int = 306) -> dict:
    """Build bound synthetic raw state bytes with the current two-input/three-output counts."""
    counts = {name: 0 for name in M.release_runner.FAULT_STATE_COUNT_FIELDS}
    counts.update(governance=3, pools=3, roots=3, commitments=6)
    if finalized:
        for name, delta in {"roots": 3, "nullifiers": 6, "commitments": 9, "encrypted_outputs": 9,
                            "replay_markers": 1, "receipts": 1}.items():
            counts[name] += delta
    if staged:
        counts.update(staged_pool_heads=1, staged_nullifiers=2, staged_output_commitments=3,
                      staged_locks=6, replicated_staged_locks=0 if local_only else 28)
    response = {"format_version": 1, "height": finalized_height if finalized else baseline_height,
                "commitment": hash_literal(24 if finalized else 23),
                "ledger_commitment": hash_literal(12 if finalized else 11),
                "replicated_staged_lock_commitment": hash_literal(14 if staged and not local_only else 13),
                "staged_lock_commitment": hash_literal(16 if staged else 15), "counts": counts}
    raw = M.canonical(response)
    return {"peer_index": peer, "response_sha256": M.sha(raw), "response_hex": raw.hex(),
            **{name: value for name, value in response.items() if name != "format_version"}}


def continuous(peer: int, bundle: bytes, *, baseline_height: int = 302,
               finalized_height: int = 306, reconciling: bool = False,
               terminal_staged: bool = False) -> dict:
    """Build an independent response/phase hash-chain fixture with one live baseline poll."""
    observations = [observation(peer, False, baseline_height=baseline_height),
                    observation(peer, False, staged=True, baseline_height=baseline_height),
                    observation(peer, True, finalized_height=finalized_height, staged=reconciling, local_only=True),
                    observation(peer, True, finalized_height=finalized_height, staged=terminal_staged, local_only=True)]
    classes = ["baseline", "baseline", "finalized", "finalized"]
    response_chain = hashlib.sha256(b"iroha:aps-fault-continuous-observation:v1\0" + bundle + struct.pack("<Q", peer))
    for row in observations:
        response_chain.update(bytes.fromhex(row["response_sha256"]))
    phases = []
    for index, (name, allowed, positions, checkpoint) in enumerate((
        ("preflight", False, (0, 1), 1), ("finalization", True, (2,), 0), ("terminal", True, (3,), 0)
    )):
        phase_chain = hashlib.sha256(b"iroha:aps-fault-continuous-observation-phase:v1\0" + bundle
            + struct.pack("<QQQ", peer, index, len(name)) + name.encode() + bytes((0, allowed)))
        attempts = []
        for position in positions:
            kind = classes[position]
            attempts.append({"class": kind, "evidence": observations[position]["response_hex"], "repetitions": 1})
            phase_chain.update(bytes((1 if kind == "baseline" else 2,)))
            phase_chain.update(bytes.fromhex(observations[position]["response_sha256"]))
        phase_chain.update(b"checkpoint\0" + struct.pack("<Q", checkpoint)
                           + b"checkpoint-controls\0" + struct.pack("<Q", 0))
        phases.append({"phase": name, "expected_unavailable": False, "finalization_allowed": allowed,
            "successful_observations": len(positions), "poll_failures": 0,
            "baseline_observations": sum(classes[position] == "baseline" for position in positions),
            "finalized_observations": sum(classes[position] == "finalized" for position in positions),
            "checkpoint_attempt": checkpoint, "checkpoint_control_bindings": [],
            "attempt_chain_sha256": phase_chain.hexdigest(), "attempts": attempts})
    return {"summary": {"peer_index": peer, "check_count": 4, "poll_failure_count": 0,
        "first_response_sha256": observations[0]["response_sha256"], "last_response_sha256": observations[-1]["response_sha256"],
        "response_chain_sha256": response_chain.hexdigest(), "baseline_observations": 2,
        "finalized_observations": 2, "phase_coverage": phases}, "observations": observations}


def finality(network: object, identities: list[str], *, height: int = 306) -> dict:
    """Current native schema; the synthetic wire and PoPs have no cryptographic validity."""
    header = {name: None for name in ("merkle_root", "da_proof_policies_hash", "da_commitments_hash",
        "da_pin_intents_hash", "npos_effects_hash", "confidential_features", "execution_context_hash",
        "global_beacon_pulse_hash")}
    header.update(height=height, prev_block_hash=hash_literal(777), creation_time_ms=123456, view_change_index=0)
    return {"block_header": header, "block_wire": [1, 2, 3], "committee": [
        {"public_key": peer, "proof_of_possession": [1] * 96} for peer in identities[:4]]}


def transport(peer: int, proof: dict, network: object, inventory: list[dict]) -> tuple[dict, bytes]:
    """Build explicitly synthetic complete prefixes with actual offset/count/PID bindings."""
    process = inventory[peer]
    source = {"instance": "1" * 64, "height": proof["block_header"]["height"], "block": "2" * 64}
    body = {"availability_digest": "3" * 64, "payload_hash": "4" * 64, "payload_bytes": 16,
            "epoch": 1, "context": "5" * 64, "proposer": 0}
    author = peer == 0
    log = b'{"unrelated":"prefix with UTF-8: \xc3\xa9"}\n'
    selected = []
    def append(extra):
        nonlocal log
        line = M.canonical({"fields": {**source, "process_id": process["pid"], **extra}}) + b"\n"
        selected.append({"offset": len(log), "line": line.decode()})
        log += line
    if not author:
        for index in range(4):
            append({"message": "sumeragi payload row admitted", "availability_digest": body["availability_digest"],
                    "acquisition": 1, "index": index, "from": M.consensus_key(inventory[0]["peer_id"])})
    append({"message": "sumeragi payload custody verified", **body,
            "acquisition": 0 if author else 1, "accepted_rows": 0 if author else 4,
            "origin": "author" if author else "network_rows"})
    append({"message": "sumeragi block applied", "result": "6" * 64})
    record = {"peer_index": peer, "peer": process["peer_id"], "pid": process["pid"], "run_id": 1,
        "stdout_path": f"peer_{peer:02}/run-1-stdout.log", "log_artifact": f"finality-before-transport-{peer:02}.log",
        "log_sha256": M.sha(log), "log_bytes": len(log), "network_id": network,
        "proof_sha256": M.sha(M.canonical(proof)), "result": "6" * 64, **source, **body,
        "local_key": M.consensus_key(process["peer_id"]),
        "peer_keys": sorted(M.consensus_key(row["peer_id"]) for row in inventory),
        "data_shards": 4, "parity_shards": 2, "stripes": 1,
        "admitted_rows": 0 if author else 4, "local_author": author,
        "provenance": M.TRANSPORT_PROVENANCE, "audit_lines": selected}
    return record, log


def request(index: int) -> dict:
    """Generate deterministic distinct test-only requests."""
    value = {"version": 1, "protocol": M.PROTOCOL, "kind": "smoke", "commit": COMMIT,
             "seed": index + 1, "run": index, "invocation_nonce": f"{index + 1:064x}"}
    value["request_id"] = M.sha(M.canonical(value))
    return value


def evidence_fixture(index: int, validator_sha: str, *, authority_height: int = 302,
                     expiry_height: int = 1000, readiness_height: int = 301,
                     finalized_height: int = 306) -> tuple[dict, dict]:
    """Build the 112-file contract entirely from explicitly synthetic test values."""
    req = request(index)
    identities = [f"ea0130{index * 16 + peer + 1:096X}" for peer in range(16)]
    network = [hash_literal(900 + 2 * index)]
    manifest = {"version": 1, "bundle_id": hash_literal(1000 + 2 * index), "network_id": network,
                "authority_context_height": authority_height, "expiry_height": expiry_height, "legs": []}
    authorities, rosters, deltas, prepares, commits, legs = [], [], [], [], [], []
    prepared_digest = hash_literal(3000 + index)
    for ordinal in range(3):
        route = {"lane_id": ordinal + 1, "dataspace_id": ordinal + 1, "lane_incarnation": hash_literal(3100 + ordinal)}
        delta = {"leg_ordinal": ordinal, "route": route}
        authority = {"route": route, "validator_set_hash": hash_literal(3200 + ordinal),
            "validators": identities[(ordinal+1)*4:(ordinal+2)*4], "validator_pops": [[1]*96 for _ in range(4)]}
        body = {"network_id": network, "bundle_id": manifest["bundle_id"], "manifest_digest": hash_literal(3300),
            "leg_ordinal": ordinal, "route": route, "delta_digest": hash_literal(3400 + ordinal),
            "authority_digest": hash_literal(3500 + ordinal), "authority_context_height": authority_height, "expiry_height": expiry_height}
        certificates = []
        for phase in ("prepare", "commit"):
            certificates.append({"body": {**body, "phase": {"phase": phase, "value": None},
                "prepared_bundle_digest": hash_literal(0) if phase == "prepare" else prepared_digest},
                "authority_catalog_index": ordinal, "signers_bitmap": 7, "aggregate_signature": [1]*96})
        authorities.append(authority)
        rosters.append({key: value for key, value in authority.items() if key != "route"})
        deltas.append(delta)
        prepares.append(certificates[0])
        commits.append(certificates[1])
        legs.append({"delta": delta, "prepare": certificates[0], "commit": certificates[1]})
        manifest["legs"].append({"ordinal": ordinal, "route": route, "delta_digest": body["delta_digest"]})
    catalog = {"rosters": rosters, "leg_roster_indices": [0, 1, 2]}
    inventory = [{"peer_index": peer, "peer_id": identity, "committee_index": peer // 4,
        "validator_index": peer % 4, "pid": 100 + peer, "executable_sha256": validator_sha,
        "configuration_sha256": M.sha(identity.encode())} for peer, identity in enumerate(identities)]
    after = [{**row, "pid": row["pid"] + 100} for row in inventory]
    evidence = {"request.json": req, "processes-before.json": inventory, "processes-after.json": after,
        "authorities.json": authorities, "prepare-barrier.json": {"version": 1, "manifest": manifest,
            "authority_catalog": catalog, "deltas": deltas, "prepare_certificates": prepares,
            "prepared_bundle_digest": prepared_digest}, "commit-certificates.json": commits,
        "receipt.json": {"version": 1, "manifest": manifest, "authority_catalog": catalog,
                         "legs": legs, "finalized_height": finalized_height},
        "restarts.json": [{"peer_index": peer, "before_pid": 100+peer, "after_pid": 200+peer} for peer in range(16)]}
    for phase in M.STATE_PHASES:
        evidence[f"state-{phase}.json"] = {"label": "after-finalized-retry" if phase == "replay" else f"smoke-{phase}",
            "validators": [observation(peer, phase in ("finalized", "replay"), baseline_height=authority_height, finalized_height=finalized_height)
                           for peer in range(16)]}
    for peer in range(16):
        evidence[f"state-restarted-{peer:02}.json"] = {"label": "smoke-restarted",
            "validators": [observation(other, True, finalized_height=finalized_height) for other in range(16)]}
        evidence[f"continuous-{peer:02}.json"] = continuous(peer, ((1000+2*index) | 1).to_bytes(32, "big"),
                                                               baseline_height=authority_height, finalized_height=finalized_height)
        for phase in ("before", "after"):
            evidence[f"finality-{phase}-{peer:02}.json"] = finality(network, identities, height=finalized_height)
        record, log = transport(peer, evidence[f"finality-before-{peer:02}.json"], network, inventory)
        evidence[f"finality-before-transport-{peer:02}.json"] = record
        evidence[f"finality-before-transport-{peer:02}.log"] = log
    result = {"version": 1, "protocol": M.PROTOCOL, "kind": "smoke", "request": req,
        "request_sha256": M.sha(M.canonical(req)+b"\n"), "network_id": network, "participants": 3,
        "processes": 16, "restarted": 16, "activation_height": readiness_height, "authority_context_height": authority_height,
        "finalized_height": finalized_height, "signed_rs16_observations": 16, "continuous_checks": 64, "passed": True,
        "artifacts": []}
    return evidence, result


def put(path: Path, value: object) -> None:
    """Write or mutate only disposable test fixture bytes."""
    path.write_bytes(M.canonical(value)+b"\n")
    path.chmod(0o600)


def store_evidence(directory: Path, evidence: dict, result: dict) -> None:
    """Retain a synthetic fixture with fresh artifact digest bindings."""
    (directory / "evidence").mkdir(mode=0o700, exist_ok=True)
    result["artifacts"] = []
    for name, value in sorted(evidence.items()):
        target = directory / "evidence" / name
        target.write_bytes(value if isinstance(value, bytes) else M.canonical(value))
        target.chmod(0o600)
        raw = (directory / "evidence" / name).read_bytes()
        result["artifacts"].append({"name": name, "bytes": len(raw), "sha256": M.sha(raw)})
    put(directory / "request.json", result["request"])
    put(directory / "rust-result.json", result)


class SmokeEvidenceTests(unittest.TestCase):
    """Mutate bound evidence adversarially, including recomputed outer file hashes."""

    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="synthetic-smoke-validator-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        self.root.chmod(0o700)
        self.sha = "b" * 64
        self.evidence, self.result = evidence_fixture(0, self.sha)

    def validate(self) -> dict:
        store_evidence(self.root, self.evidence, self.result)
        return M.validate_run(self.root, request(0), self.sha)

    def test_complete_synthetic_contract_and_live_staged_observation(self) -> None:
        self.assertEqual(self.validate()["continuous_checks"], 64)
        self.assertEqual(len(M.EVIDENCE_NAMES), 112)

    def test_exact_retry_snapshot_requires_its_original_phase_and_all_validators(self) -> None:
        self.assertEqual(self.evidence["state-replay.json"]["label"], "after-finalized-retry")
        self.validate()
        for label in ("smoke-replay", "before-finalized-retry", "smoke-finalized"):
            with self.subTest(label=label):
                self.evidence["state-replay.json"]["label"] = label
                with self.assertRaisesRegex(M.CampaignError, "state-replay.json omits/relabels validators"):
                    self.validate()
        self.evidence["state-replay.json"]["label"] = "after-finalized-retry"
        self.evidence["state-replay.json"]["validators"].pop()
        with self.assertRaisesRegex(M.CampaignError, "state-replay.json omits/relabels validators"):
            self.validate()

    def test_local_reconciliation_preserves_atomic_ledger_and_requires_terminal_cleanup(self) -> None:
        bundle = bytes(32)
        before = M.state_identity(observation(0, False), 0, "before")
        after = M.state_identity(observation(0, True), 0, "after")
        self.assertEqual(M.validate_continuous(continuous(0, bundle, reconciling=True),
                                             0, bundle, before, after), 4)
        for reconciling in (False, True):
            with self.assertRaises(M.release_runner.RunnerError):
                M.validate_continuous(continuous(0, bundle, reconciling=reconciling,
                                                terminal_staged=True),
                                      0, bundle, before, after)
        pending = M.state_identity(observation(0, True, staged=True, local_only=True), 0, "pending")
        local = M.release_runner._validate_finalized_local_reconciliation(pending, after, None)
        self.assertEqual(local[0], 6)
        M.release_runner._validate_finalized_local_reconciliation(after, after, local)
        for invalid in (
                M.state_identity(observation(0, True, staged=True), 0, "replicated"),
                (pending[0], pending[1], hash_literal(81), pending[3])):
            with self.assertRaises(M.release_runner.RunnerError):
                M.release_runner._validate_finalized_local_reconciliation(invalid, after, local)

    def test_shared_validator_input_layers_retain_unique_process_identity(self) -> None:
        for name in ("processes-before.json", "processes-after.json"):
            for row in self.evidence[name]:
                row["configuration_sha256"] = "9" * 64
        self.assertEqual(self.validate()["continuous_checks"], 64)

    def test_genesis_readiness_height_one_keeps_all_112_artifacts_bound(self) -> None:
        self.evidence, self.result = evidence_fixture(
            0, self.sha, readiness_height=1, authority_height=4, finalized_height=8)
        summary = self.validate()
        self.assertEqual(M.validate_smoke_result_heights(self.result), (1, 4, 8))
        self.assertEqual(summary["finalized_height"], 8)
        self.assertEqual(summary["continuous_checks"], 64)
        self.assertEqual(len(self.result["artifacts"]), 112)
        self.assertEqual({row["name"] for row in self.result["artifacts"]}, M.EVIDENCE_NAMES)

    def test_low_height_readiness_type_and_strict_authority_order_fail_closed(self) -> None:
        for field, values in (("activation_height", (0, True, 1.0, "1", 4)),
                              ("authority_context_height", (0, True, 4.0, "4", 1)),
                              ("finalized_height", (0, True, 8.0, "8", 3))):
            for value in values:
                with self.subTest(field=field, value=value):
                    self.evidence, self.result = evidence_fixture(
                        0, self.sha, readiness_height=1, authority_height=4, finalized_height=8)
                    self.result[field] = value
                    with self.assertRaises(M.release_runner.RunnerError):
                        self.validate()

    def test_low_height_manifest_substitution_fails_after_rehash(self) -> None:
        self.evidence, self.result = evidence_fixture(
            0, self.sha, readiness_height=1, authority_height=4, finalized_height=8)
        self.evidence["receipt.json"]["manifest"]["authority_context_height"] = 5
        with self.assertRaisesRegex(M.CampaignError, "authority or expiry"):
            self.validate()

    def test_low_height_changed_artifact_bytes_fail_the_retained_hash(self) -> None:
        self.evidence, self.result = evidence_fixture(
            0, self.sha, readiness_height=1, authority_height=4, finalized_height=8)
        store_evidence(self.root, self.evidence, self.result)
        artifact = self.root / "evidence" / "state-before.json"
        artifact.write_bytes(artifact.read_bytes() + b" ")
        with self.assertRaisesRegex(M.CampaignError, "byte/digest mismatch"):
            M.validate_run(self.root, request(0), self.sha)

    def test_observed_later_authority_height_keeps_complete_evidence_binding(self) -> None:
        for authority in (303, 305, 306):
            with self.subTest(authority=authority):
                self.evidence, self.result = evidence_fixture(0, self.sha, authority_height=authority)
                summary = self.validate()
                self.assertEqual(summary["finalized_height"], 306)
                self.assertEqual(self.evidence["state-before.json"]["validators"][0]["height"], authority)

    def test_result_height_window_rejects_order_type_and_u64_substitution(self) -> None:
        maximum = 2**64 - 1
        self.assertEqual(M.validate_smoke_result_heights({"activation_height": maximum - 2,
            "authority_context_height": maximum - 1, "finalized_height": maximum}),
            (maximum - 2, maximum - 1, maximum))
        for field, values in (
            ("activation_height", (True, 0, 301.0, maximum - 1, maximum + 1)),
            ("authority_context_height", (True, 0, 300, 301, 302.0, maximum + 1)),
            ("finalized_height", (True, 0, 301, 306.0, maximum + 1)),
        ):
            for value in values:
                with self.subTest(field=field, value=value):
                    result = dict(self.result, **{field: value})
                    with self.assertRaises(M.release_runner.RunnerError):
                        M.validate_smoke_result_heights(result)

    def test_manifest_authority_substitution_is_rejected_after_rehash(self) -> None:
        self.evidence, self.result = evidence_fixture(0, self.sha, authority_height=303)
        # Receipt and barrier share the manifest; keep both coherently changed.
        self.evidence["receipt.json"]["manifest"]["authority_context_height"] = 304
        with self.assertRaisesRegex(M.CampaignError, "authority or expiry"):
            self.validate()

    def test_expiry_is_strict_for_authority_and_inclusive_for_finalization(self) -> None:
        self.evidence, self.result = evidence_fixture(0, self.sha, authority_height=305, expiry_height=306)
        self.assertEqual(self.validate()["finalized_height"], 306)
        for expiry in (True, 0, 304, 305, 306.0, 2**64):
            with self.subTest(expiry=expiry):
                self.evidence, self.result = evidence_fixture(0, self.sha, authority_height=305,
                                                             expiry_height=expiry)
                with self.assertRaises(M.release_runner.RunnerError):
                    self.validate()
        # Valid authority < expiry does not permit finalization after expiry.
        self.evidence, self.result = evidence_fixture(0, self.sha, authority_height=303, expiry_height=305)
        with self.assertRaisesRegex(M.CampaignError, "authority or expiry"):
            self.validate()

    def test_later_authority_does_not_relax_phase_height_or_expiry_binding(self) -> None:
        for phase in ("prepare", "commit"):
            for field in ("authority_context_height", "expiry_height"):
                with self.subTest(phase=phase, field=field):
                    self.evidence, self.result = evidence_fixture(0, self.sha, authority_height=303)
                    self.evidence["receipt.json"]["legs"][1][phase]["body"][field] += 1
                    with self.assertRaisesRegex(M.CampaignError, "phase signed-body substitution"):
                        self.validate()

    def test_financial_stage_mutations_rejected_even_with_rehashed_artifacts(self) -> None:
        for phase in ("collecting", "audited", "prepared", "registered", "commit-certified"):
            with self.subTest(phase=phase):
                self.evidence, self.result = evidence_fixture(0, self.sha)
                self.evidence[f"state-{phase}.json"]["validators"][9] = observation(9, True)
                with self.assertRaisesRegex(M.CampaignError, "partial financial"):
                    self.validate()

    def test_every_restart_snapshot_is_checked(self) -> None:
        self.evidence["state-restarted-15.json"]["validators"][15] = observation(15, False)
        with self.assertRaisesRegex(M.CampaignError, "predates finality|restart changed"):
            self.validate()

    def test_process_identity_pid_config_and_executable_substitutions(self) -> None:
        mutations = (
            lambda e: e["processes-before.json"][8].update(peer_id=e["processes-before.json"][0]["peer_id"]),
            lambda e: e["processes-after.json"][15].update(pid=115),
            lambda e: e["processes-after.json"][3].update(configuration_sha256="c"*64),
            lambda e: e["processes-after.json"][0].update(executable_sha256="c"*64),
            lambda e: e["processes-before.json"][2].update(pid=100),
        )
        for mutate in mutations:
            self.evidence, self.result = evidence_fixture(0, self.sha)
            mutate(self.evidence)
            with self.assertRaises(M.CampaignError):
                self.validate()

    def test_continuous_rollback_partial_counts_retention_race_and_chain_tampering(self) -> None:
        mutations = (
            lambda row: row["observations"].__setitem__(3, observation(0, False)),
            lambda row: row["observations"].append(observation(0, True)),
            lambda row: row["summary"].update(response_chain_sha256="c"*64),
            lambda row: row["summary"]["phase_coverage"][0].update(finalization_allowed=True),
            lambda row: row["summary"]["phase_coverage"][1].update(checkpoint_attempt=1),
            lambda row: row["summary"]["phase_coverage"][1]["attempts"][0].update(evidence=observation(0, False)["response_hex"]),
        )
        for mutate in mutations:
            self.evidence, self.result = evidence_fixture(0, self.sha)
            mutate(self.evidence["continuous-00.json"])
            with self.assertRaises(M.release_runner.RunnerError):
                self.validate()

    def test_finality_wire_pop_height_roster_and_consistency(self) -> None:
        mutations = (
            lambda p: p["committee"][0].update(proof_of_possession=[]),
            lambda p: p["committee"][0].update(public_key=f"ea0130{999:096X}"),
            lambda p: p.update(block_wire=[]),
            lambda p: p["block_header"].update(height=307),
            lambda p: p["block_header"].update(creation_time_ms=123457),
            lambda p: p["committee"].__setitem__(1, copy.deepcopy(p["committee"][0])),
            lambda p: p.update(block_wire=[True]),
        )
        for mutate in mutations:
            self.evidence, self.result = evidence_fixture(0, self.sha)
            mutate(self.evidence["finality-after-15.json"])
            with self.assertRaises(M.CampaignError):
                self.validate()

    def test_finality_retains_only_the_bare_native_proof_schema(self) -> None:
        # SumeragiFinalityBundle and SumeragiFinalityAttestation wrap this proof; neither
        # wrapper nor any extra field is the retained SumeragiFinalityProof carrier.
        proof = copy.deepcopy(self.evidence["finality-after-15.json"])
        network = copy.deepcopy(self.result["network_id"])
        variants = {
            "bundle network field": {**proof, "network_id": network},
            "bundle wrapper": {"network_id": network, "finality_proof": proof},
            "attestation wrapper": {"body": {"finality_proof": proof}, "signature": [1] * 64},
        }
        for name, value in variants.items():
            with self.subTest(variant=name):
                self.evidence, self.result = evidence_fixture(0, self.sha)
                self.evidence["finality-after-15.json"] = copy.deepcopy(value)
                with self.assertRaisesRegex(M.release_runner.RunnerError, "finality proof fields mismatch"):
                    self.validate()
        self.evidence, self.result = evidence_fixture(0, self.sha)
        self.evidence["finality-after-15.json"]["block_header"]["result_merkle_root"] = None
        with self.assertRaisesRegex(M.release_runner.RunnerError, "block header fields mismatch"):
            self.validate()

    def test_equivalent_verified_carriers_do_not_require_identical_qc_bytes(self) -> None:
        # Python deliberately does not interpret or verify the opaque Norito QC.
        # Rust CertifiedPrefix must authenticate this equivalence before retention.
        alternate = self.evidence["finality-after-15.json"]
        alternate["block_wire"] = [2, 3, 4]
        self.validate()
        alternate["block_header"]["prev_block_hash"] = hash_literal(999)
        with self.assertRaisesRegex(M.CampaignError, "disagree"):
            self.validate()

    def test_transport_metadata_and_source_binding_fail_after_outer_rehash(self) -> None:
        mutations = {
            "peer": lambda r: r.update(peer=f"ea0130{999:096X}"),
            "peer_index": lambda r: r.update(peer_index=14),
            "pid": lambda r: r.update(pid=999),
            "run": lambda r: r.update(run_id=2),
            "path": lambda r: r.update(stdout_path="../peer/run-1-stdout.log"),
            "log artifact": lambda r: r.update(log_artifact="finality-before-transport-14.log"),
            "log hash": lambda r: r.update(log_sha256="9" * 64),
            "log size": lambda r: r.update(log_bytes=r["log_bytes"] + 1),
            "proof hash": lambda r: r.update(proof_sha256="9" * 64),
            "network": lambda r: r.update(network_id=[hash_literal(99)]),
            "local key": lambda r: r.update(local_key="9" * 96),
            "peers": lambda r: r["peer_keys"].reverse(),
            "author": lambda r: r.update(local_author=True),
            "provenance": lambda r: r.update(provenance="cryptographic remote transport proof"),
            "count": lambda r: r.update(admitted_rows=3),
            "geometry": lambda r: r.update(data_shards=3),
            "stripe": lambda r: r.update(stripes=2),
            "epoch": lambda r: r.update(epoch=2),
            "context": lambda r: r.update(context="9" * 64),
            "result": lambda r: r.update(result="9" * 64),
            "proposer": lambda r: r.update(proposer=1),
            "payload": lambda r: r.update(payload_hash="9" * 64),
            "payload bytes": lambda r: r.update(payload_bytes=17),
            "offset": lambda r: r["audit_lines"][0].update(offset=0),
            "omission": lambda r: r["audit_lines"].pop(0),
            "reorder": lambda r: r["audit_lines"].reverse(),
        }
        for label, mutate in mutations.items():
            with self.subTest(mutation=label):
                self.evidence, self.result = evidence_fixture(0, self.sha)
                mutate(self.evidence["finality-before-transport-15.json"])
                with self.assertRaises((M.CampaignError, M.release_runner.RunnerError)):
                    self.validate()

    def test_transport_replays_every_raw_line_not_just_selected_claims(self) -> None:
        def change_raw(transform, *, update_lines=True):
            record = self.evidence["finality-before-transport-15.json"]
            old = self.evidence["finality-before-transport-15.log"]
            changed = transform(old)
            self.assertNotEqual(changed, old)
            self.evidence["finality-before-transport-15.log"] = changed
            record.update(log_sha256=M.sha(changed), log_bytes=len(changed))
            if update_lines:
                offset = 0
                selected = []
                for line in changed.splitlines(keepends=True):
                    if b"sumeragi" in line:
                        selected.append({"offset": offset, "line": line.decode()})
                    offset += len(line)
                record["audit_lines"] = selected
        mutations = (
            lambda b: b.replace(b'"process_id":115', b'"process_id":999'),
            lambda b: b.replace(b'"index":1', b'"index":0'),
            lambda b: b.replace(b'"from":"' + b'0' * 95 + b'1"', b'"from":"' + b'0' * 94 + b'10"'),
            lambda b: b.replace(b'"network_rows"', b'"stored"'),
            lambda b: b.replace(b'"network_rows"', b'"author"'),
            lambda b: b.replace(b'"accepted_rows":4', b'"accepted_rows":3'),
            lambda b: b.replace(b'"acquisition":1', b'"acquisition":0'),
            lambda b: b.replace(b'"index":3', b'"index":6'),
            lambda b: b + b.splitlines(keepends=True)[-1],
            lambda b: b''.join(reversed(b.splitlines(keepends=True))),
            lambda b: b''.join(b.splitlines(keepends=True)[:-1]),
            lambda b: b[:-1],
        )
        for index, mutate in enumerate(mutations):
            with self.subTest(mutation=index):
                self.evidence, self.result = evidence_fixture(0, self.sha)
                change_raw(mutate)
                with self.assertRaises((M.CampaignError, M.release_runner.RunnerError)):
                    self.validate()
        # Appending a duplicate observation but omitting it from audit_lines also fails.
        self.evidence, self.result = evidence_fixture(0, self.sha)
        change_raw(lambda b: b + b.splitlines(keepends=True)[-1], update_lines=False)
        with self.assertRaisesRegex(M.CampaignError, "omit or substitute"):
            self.validate()

    def test_transport_rejects_consistently_substituted_one_peer_source(self) -> None:
        record = self.evidence["finality-before-transport-15.json"]
        raw = self.evidence["finality-before-transport-15.log"]
        changed = raw.replace(b'2' * 64, b'9' * 64)
        self.evidence["finality-before-transport-15.log"] = changed
        record.update(block="9" * 64, log_sha256=M.sha(changed))
        for line in record["audit_lines"]:
            line["line"] = line["line"].replace("2" * 64, "9" * 64)
        with self.assertRaisesRegex(M.CampaignError, "original transport source"):
            self.validate()

    def test_transport_refuses_missing_raw_log_and_unbounded_read(self) -> None:
        del self.evidence["finality-before-transport-15.log"]
        with self.assertRaises(M.CampaignError):
            self.validate()
        self.evidence, self.result = evidence_fixture(0, self.sha)
        store_evidence(self.root, self.evidence, self.result)
        log = self.root / "evidence/finality-before-transport-15.log"
        with log.open("r+b") as stream:
            stream.truncate(M.MAX_TRANSPORT_LOG_BYTES + 1)
        with self.assertRaisesRegex(M.CampaignError, "bounded regular"):
            M.validate_run(self.root, request(0), self.sha)

    def test_readiness_authority_and_missing_artifact_failures(self) -> None:
        self.result["activation_height"] = 0
        with self.assertRaises(M.release_runner.RunnerError):
            self.validate()
        self.evidence, self.result = evidence_fixture(0, self.sha)
        self.evidence["commit-certificates.json"][2]["body"]["prepared_bundle_digest"] = hash_literal(0)
        with self.assertRaisesRegex(M.CampaignError, "bypasses"):
            self.validate()
        self.evidence, self.result = evidence_fixture(0, self.sha)
        del self.evidence["finality-before-15.json"]
        # Previous subcases left the file on disk; both inventory count and extras are rejected.
        with self.assertRaises(M.CampaignError):
            self.validate()

    def test_prepare_empty_hash_is_canonical_marker_and_commit_never_empty(self) -> None:
        self.assertEqual(M.release_runner.canonical_iroha_hash_body(hash_literal(0), "test hash"), "0"*63+"1")
        self.validate()
        self.evidence["prepare-barrier.json"]["prepare_certificates"][0]["body"]["prepared_bundle_digest"] = hash_literal(0, mark=False)
        with self.assertRaisesRegex(M.CampaignError, "marker"):
            self.validate()
        for empty in (hash_literal(0), hash_literal(0, mark=False)):
            self.evidence, self.result = evidence_fixture(0, self.sha)
            self.evidence["prepare-barrier.json"]["prepared_bundle_digest"] = empty
            for cert in self.evidence["commit-certificates.json"]:
                cert["body"]["prepared_bundle_digest"] = empty
            with self.assertRaisesRegex(M.CampaignError, "bypasses|marker"):
                self.validate()

    def test_protocol_hash_marker_empty_and_boolean_versions_are_rejected(self) -> None:
        for number in (0, 2, 1000):
            with self.assertRaisesRegex(M.CampaignError, "marker"):
                M.protocol_hash(hash_literal(number, mark=False), "synthetic")
        with self.assertRaisesRegex(M.CampaignError, "reserved empty"):
            M.protocol_hash(hash_literal(0), "synthetic")
        self.assertEqual(M.protocol_hash(hash_literal(0), "synthetic", allow_empty=True), M.EMPTY_PROTOCOL_HASH)
        self.assertEqual(M.protocol_hash(hash_literal(1000), "synthetic"), f"{1001:064x}")
        for artifact in ("result", "receipt.json", "prepare-barrier.json"):
            self.evidence, self.result = evidence_fixture(0, self.sha)
            value = self.result if artifact == "result" else self.evidence[artifact]
            value["version"] = True
            with self.assertRaises(M.CampaignError):
                self.validate()

    def test_raw_response_binding_and_owner_only_files(self) -> None:
        store_evidence(self.root, self.evidence, self.result)
        target = self.root / "evidence" / "state-before.json"
        target.chmod(0o644)
        with self.assertRaisesRegex(M.CampaignError, "owner-only"):
            M.validate_run(self.root, request(0), self.sha)
        target.chmod(0o600)
        raw = target.read_bytes()
        target.unlink()
        alternate = self.root / "substitution.json"
        alternate.write_bytes(raw)
        alternate.chmod(0o600)
        target.symlink_to(alternate)
        with self.assertRaises(M.CampaignError):
            M.validate_run(self.root, request(0), self.sha)

    def test_boolean_indices_and_embedded_request_are_not_integer_evidence(self) -> None:
        cases = [
            ("restarts.json", (0, "peer_index")),
            ("continuous-00.json", ("summary", "peer_index")),
            ("receipt.json", ("manifest", "legs", 0, "ordinal")),
            ("prepare-barrier.json", ("deltas", 0, "leg_ordinal")),
            ("commit-certificates.json", (0, "authority_catalog_index")),
            ("commit-certificates.json", (0, "body", "leg_ordinal")),
        ]
        for artifact, path in cases:
            with self.subTest(artifact=artifact, path=path):
                self.evidence, self.result = evidence_fixture(0, self.sha)
                row = self.evidence[artifact]
                for component in path[:-1]:
                    row = row[component]
                row[path[-1]] = False
                with self.assertRaises(M.release_runner.RunnerError):
                    self.validate()
        self.evidence, self.result = evidence_fixture(0, self.sha)
        store_evidence(self.root, self.evidence, self.result)
        for location in ("rust-result.json", "evidence/request.json"):
            with self.subTest(location=location):
                self.evidence, self.result = evidence_fixture(0, self.sha)
                store_evidence(self.root, self.evidence, self.result)
                path = self.root / location
                value = M.read_json(path)
                embedded = value["request"] if location == "rust-result.json" else value
                embedded["version"] = True
                path.write_bytes(M.canonical(value) + b"\n")
                if location == "evidence/request.json":
                    result_path = self.root / "rust-result.json"
                    result = M.read_json(result_path)
                    raw = path.read_bytes()
                    for artifact in result["artifacts"]:
                        if artifact["name"] == "request.json":
                            artifact.update(bytes=len(raw), sha256=M.sha(raw))
                    put(result_path, result)
                with self.assertRaisesRegex(M.CampaignError, "wrong experiment protocol/kind"):
                    M.validate_run(self.root, request(0), self.sha)

    def test_restart_pid_one_is_integer_and_boolean_aliases_are_rejected(self) -> None:
        for phase, field in (("before", "before_pid"), ("after", "after_pid")):
            with self.subTest(phase=phase):
                self.evidence, self.result = evidence_fixture(0, self.sha)
                self.evidence[f"processes-{phase}.json"][0]["pid"] = 1
                self.evidence["restarts.json"][0][field] = 1
                if phase == "before":
                    record, log = transport(0, self.evidence["finality-before-00.json"],
                                            self.result["network_id"], self.evidence["processes-before.json"])
                    self.evidence["finality-before-transport-00.json"] = record
                    self.evidence["finality-before-transport-00.log"] = log
                self.validate()
                self.evidence["restarts.json"][0][field] = True
                with self.assertRaisesRegex(M.release_runner.RunnerError, "integer"):
                    self.validate()


class DriverBoundaryTests(unittest.TestCase):
    """Verify strict invocation controls without spawning Git, Cargo, or networks."""

    def test_smoke_build_requests_the_privacy_entrypoint_feature(self) -> None:
        commands = M.build_commands(Path("/synthetic/repo"), Path("/synthetic/target"))
        integration = commands["build-integration"]
        self.assertEqual(integration.count("--features"), 1)
        self.assertEqual(integration[integration.index("--features") + 1],
                         "atomic-private-settlement-smoke")
        self.assertEqual(integration[integration.index("--test") + 1], "nexus_and_streaming")
        for flag in ("--locked", "--offline", "--release", "--no-run"):
            self.assertIn(flag, integration)
        validator = commands["build-validator"]
        self.assertEqual(validator[validator.index("--features") + 1], "test-network-private-settlement-route-control")

    def test_exact_terminal_and_discovery_reject_zero_ignored_skipped_or_duplicate(self) -> None:
        good = f"running 1 test\ntest {M.TEST_NAME} ... APS smoke completed: synthetic fixture only\nok\n" + (
            "test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 5 filtered out; finished in 1.0s\n")
        M.terminal_success(good)
        for bad in (good.replace("1 passed", "0 passed"), good.replace("0 ignored", "1 ignored"),
                    good + "network skipped\n", good + good, good.replace("running 1", "running 0")):
            with self.assertRaises(M.CampaignError):
                M.terminal_success(bad)
        listing = f"{M.TEST_NAME}: test\n\n1 test, 0 benchmarks\n"
        M.validate_discovery(listing)
        with self.assertRaises(M.CampaignError):
            M.validate_discovery(listing.replace(M.TEST_NAME, M.TEST_NAME + "_wrong"))

    def test_terminal_accounting_keeps_exact_owners_with_interleaved_logs(self) -> None:
        for kind, name in (("smoke", M.TEST_NAME), ("happy_day", M.HAPPY_DAY_TEST_NAME)):
            marker = f"APS {kind} completed: synthetic fixture only"
            summary = "test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 5 filtered out; finished in 1.0s\n"
            for terminal in (f"test {name} ... ok\n{marker}\n",
                             f"test {name} ... {{\"logger\":\"interleaved\"}}\n{marker}\nok\n"):
                with self.subTest(kind=kind, terminal=terminal):
                    M.terminal_success("running 1 test\n" + terminal + summary, kind=kind)

    def test_terminal_accounting_rejects_missing_foreign_duplicate_and_contradictory_owners(self) -> None:
        for kind, name in (("smoke", M.TEST_NAME), ("happy_day", M.HAPPY_DAY_TEST_NAME)):
            marker = f"APS {kind} completed: synthetic fixture only\n"
            summary = "test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 5 filtered out; finished in 1.0s\n"
            good = f"running 1 test\ntest {name} ... " + marker + "ok\n" + summary
            attacks = {
                "missing owner and terminal": "running 1 test\n" + marker + summary,
                "missing terminal": good.replace("ok\n", "", 1),
                "foreign owner": good.replace(name, name + "_foreign"),
                "duplicate header": "running 1 test\n" + good,
                "contradictory failed terminal": good.replace("ok\n", "FAILED\n", 1),
                "duplicate owner": good.replace(summary, f"test {name} ... ok\n" + summary),
                "foreign additional owner": good.replace(summary, "test foreign::test ... ok\n" + summary),
                "orphan terminal": good + "ok\n",
                "duplicate terminal": good.replace(summary, "ok\n" + summary),
                "missing header": good.replace("running 1 test\n", ""),
                "duplicate summary": good + summary,
                "malformed summary": good.replace("finished in 1.0s", "finished in invalid"),
                "misordered summary": summary + good.removesuffix(summary),
            }
            for label, output in attacks.items():
                with self.subTest(kind=kind, attack=label), self.assertRaises(M.CampaignError):
                    M.terminal_success(output, kind=kind)

    def test_request_nonce_content_id_commit_range_and_bool_boundaries(self) -> None:
        M.validate_request(request(0), COMMIT, 0)
        for key, value in (("run", True), ("run", 10), ("seed", -1), ("seed", 2**64),
                           ("invocation_nonce", "0"*64), ("commit", "B"*40), ("request_id", "b"*64)):
            candidate = request(0)
            candidate[key] = value
            with self.assertRaises(M.release_runner.RunnerError):
                M.validate_request(candidate, COMMIT, 0)

    def test_environment_drops_network_compiler_loader_and_git_injection(self) -> None:
        injected = {"PATH": "/test/toolchain", "HOME": "/test/home", "IROHA_TEST_REQUIRE_NETWORK": "0",
            "APS_REAL_PROCESS_REQUEST": "/stale", "RUSTFLAGS": "bad", "RUSTC_WRAPPER": "bad",
            "DYLD_INSERT_LIBRARIES": "bad", "LD_PRELOAD": "bad", "GIT_INDEX_FILE": "/stale",
            "IROHA_RELEASE_SOURCE_MANIFEST_SHA256": "stale", "TEST_NETWORK_BIN_IROHAD": "/wrong",
            "RAYON_NUM_THREADS": "128", "RUST_TEST_THREADS": "128",
            "CARGO_PROFILE_RELEASE_CODEGEN_UNITS": "128"}
        with mock.patch.dict(os.environ, injected, clear=True):
            environment = M.sanitized_environment()
        self.assertEqual(environment["PATH"], "/test/toolchain")
        self.assertTrue((set(injected) - {"PATH", "HOME"}).isdisjoint(environment))

    def test_proving_child_receives_pinned_workers_and_receipt_records_effective_environment(self) -> None:
        with tempfile.TemporaryDirectory(prefix="synthetic-smoke-workers-") as temporary:
            root = Path(temporary).resolve()
            request_path = root / "request.json"
            M.write_json(request_path, request(0))
            injected = {"RAYON_NUM_THREADS": "128", "RUST_TEST_THREADS": "128",
                        "CARGO_BUILD_JOBS": "128", "CARGO_INCREMENTAL": "1"}
            with mock.patch.dict(os.environ, injected):
                environment = M.invocation_environment(request_path, root / "evidence", root / "result.json",
                                                       {"path": "/synthetic/validator", "sha256": "a" * 64})
                arguments = [M.sys.executable, "-c", "import os; "
                    "print(os.environ.get('RAYON_NUM_THREADS')); print(os.environ.get('RUST_TEST_THREADS')); "
                    "print(os.environ.get('CARGO_BUILD_JOBS')); print(os.environ.get('CARGO_INCREMENTAL'))"]
                receipt = M.command(arguments, root, environment, root, "workers")
            self.assertEqual(M.read_bytes(root / "workers.log"), b"8\nNone\n4\n0\n")
            expected = {"RAYON_NUM_THREADS": "8", "RUST_TEST_THREADS": None,
                        "CARGO_BUILD_JOBS": "4", "CARGO_INCREMENTAL": "0"}
            self.assertEqual(receipt["worker_environment"], expected)
            self.assertEqual(M.read_json(root / "workers.json"), receipt)
            self.assertEqual(M.validate_command_record(root / "workers.json", arguments, proving=True), receipt)
            for key, value in (("RAYON_NUM_THREADS", "1"), ("RUST_TEST_THREADS", "8"),
                               ("CARGO_BUILD_JOBS", "128"), ("CARGO_INCREMENTAL", "1")):
                with self.subTest(key=key):
                    changed = copy.deepcopy(receipt)
                    changed["worker_environment"][key] = value
                    put(root / "workers.json", changed)
                    with self.assertRaisesRegex(M.CampaignError, "worker environment"):
                        M.validate_command_record(root / "workers.json", arguments, proving=True)
            changed = copy.deepcopy(receipt)
            del changed["worker_environment"]
            put(root / "workers.json", changed)
            with self.assertRaises(M.release_runner.RunnerError):
                M.validate_command_record(root / "workers.json", arguments, proving=True)

    def test_source_checker_loads_from_checkout_not_ambient_module(self) -> None:
        with mock.patch.dict(M.sys.modules, {"compute_workspace_source_manifest": mock.Mock()}):
            loaded = M._load_source_manifest_tools()
        self.assertEqual(Path(loaded.__file__).resolve(), SCRIPT.parent / "compute_workspace_source_manifest.py")
        self.assertTrue(callable(loaded.release_source_identity))

    def test_signed_blob_seal_detects_edits_hidden_by_git_status(self) -> None:
        with canonical_source_fixture() as (root, git):
            seal = M.source_seal(root, COMMIT)
            identity = M._SOURCE_TOOLS.release_source_identity(root)
            self.assertEqual(seal["tracked_files"], 2)
            self.assertEqual(seal["source_sha256"], identity["workspace_source_manifest_sha256"])
            self.assertIn(mock.call(root, ["verify-commit", COMMIT]), git.call_args_list)
            (root / "source.rs").write_bytes(b"// substituted despite clean Git metadata\n")
            with self.assertRaisesRegex(M.CampaignError, "canonical release source refused.*tracked changes"):
                M.source_seal(root, COMMIT)

    def test_canonical_source_accepts_empty_gitlink_and_rejects_materialization(self) -> None:
        for mutation in ("populated", "missing", "symlink"):
            with self.subTest(mutation=mutation), canonical_source_fixture(gitlink=True) as (root, _):
                seal = M.source_seal(root, COMMIT)
                self.assertEqual(seal["tracked_files"], 3)
                self.assertEqual(seal["tree"], "b" * 40)
                docs = root / "docs"
                if mutation == "populated":
                    (docs / "unsealed.md").write_text("not in parent source closure\n")
                else:
                    docs.rmdir()
                    if mutation == "symlink":
                        docs.symlink_to(root.parent / "missing-docs", target_is_directory=True)
                with self.assertRaisesRegex(M.CampaignError, "canonical release source refused.*docs"):
                    M.source_seal(root, COMMIT)

    def test_canonical_source_refusals_are_never_accepted(self) -> None:
        failures = [error("synthetic refusal") for error in (
            M._SOURCE_TOOLS.ActiveGitOperationError, M._SOURCE_TOOLS.UnmergedSourceError,
            M._SOURCE_TOOLS.DirtyReleaseSourceError, M._SOURCE_TOOLS.SourceSealError)]
        failures.append(M.subprocess.CalledProcessError(1, ["git", "synthetic-read-only-check"]))
        for failure in failures:
            with self.subTest(failure=type(failure).__name__), canonical_source_fixture() as (root, _):
                with mock.patch.object(M._SOURCE_TOOLS, "release_source_identity", side_effect=failure):
                    with self.assertRaisesRegex(M.CampaignError, "canonical release source refused") as raised:
                        M.source_seal(root, COMMIT)
                    self.assertIs(raised.exception.__cause__, failure)

    def test_canonical_source_rejects_wrong_commit_index_and_capture_substitution(self) -> None:
        with canonical_source_fixture() as (root, _):
            identity = M._SOURCE_TOOLS.release_source_identity(root)
            for field in ("head_commit", "index_tree"):
                altered = {**identity, field: "c" * 40}
                with self.subTest(field=field), mock.patch.object(
                        M._SOURCE_TOOLS, "release_source_identity", return_value=altered):
                    with self.assertRaisesRegex(M.CampaignError, "canonical source commit/tree differs"):
                        M.source_seal(root, COMMIT)
            for field in ("workspace_source_manifest_sha256", "cargo_lock_sha256"):
                altered = {**identity, field: "c" * 64}
                with self.subTest(field=field), mock.patch.object(
                        M._SOURCE_TOOLS, "release_source_identity", side_effect=[identity, altered]):
                    with self.assertRaisesRegex(M.CampaignError, "source changed during sealing"):
                        M.source_seal(root, COMMIT)

    def test_canonical_source_still_requires_signature_root_and_requested_commit(self) -> None:
        cases = [("root", ["rev-parse", "--show-toplevel"]),
                 ("commit", ["rev-parse", "HEAD"]),
                 ("signature", ["verify-commit", COMMIT])]
        for name, rejected in cases:
            with self.subTest(check=name), canonical_source_fixture() as (root, git):
                original = git.side_effect
                def altered(candidate, arguments):
                    if arguments == rejected:
                        if name == "signature":
                            raise M.CampaignError("signature refused")
                        return b"not-the-requested-root-or-commit\n"
                    return original(candidate, arguments)
                git.side_effect = altered
                with mock.patch.object(M._SOURCE_TOOLS, "release_source_identity") as identity:
                    with self.assertRaises(M.CampaignError):
                        M.source_seal(root, COMMIT)
                    identity.assert_not_called()

    def test_canonical_source_still_rejects_unsigned_cargo_configuration(self) -> None:
        with canonical_source_fixture() as (root, _):
            M.source_seal(root, COMMIT)
            (root.parent / "cargo-home" / "config.toml").write_text("# unsigned build override\n")
            with self.assertRaisesRegex(M.CampaignError, "unsigned Cargo"):
                M.source_seal(root, COMMIT)

    def test_unsigned_cargo_configuration_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory(prefix="synthetic-cargo-configuration-") as temporary:
            root = Path(temporary).resolve()
            repo = root / "repo"
            (repo / ".cargo").mkdir(parents=True)
            cargo_home = root / "cargo-home"
            cargo_home.mkdir()
            config = repo / ".cargo" / "config.toml"
            config.write_text("# Synthetic configuration fixture only\n")
            with mock.patch.dict(os.environ, {"CARGO_HOME": str(cargo_home)}):
                with self.assertRaisesRegex(M.CampaignError, "unsigned Cargo"):
                    M.reject_unsigned_cargo_configuration(repo, set())
                M.reject_unsigned_cargo_configuration(repo, {".cargo/config.toml"})
                (cargo_home / "config").write_text("# External unsigned configuration\n")
                with self.assertRaisesRegex(M.CampaignError, "unsigned Cargo"):
                    M.reject_unsigned_cargo_configuration(repo, {".cargo/config.toml"})

    def test_signed_config_symlink_cannot_load_unsigned_target_bytes(self) -> None:
        with tempfile.TemporaryDirectory(prefix="synthetic-cargo-symlink-") as temporary:
            root = Path(temporary).resolve()
            repo = root / "repo"
            (repo / ".cargo").mkdir(parents=True)
            outside = root / "unsigned-config.toml"
            outside.write_text("# Unsigned bytes behind a signed link fixture\n")
            config = repo / ".cargo" / "config.toml"
            config.symlink_to(outside)
            with mock.patch.dict(os.environ, {"CARGO_HOME": str(root / "cargo-home")}), self.assertRaisesRegex(
                M.CampaignError, "symlink"
            ):
                M.reject_unsigned_cargo_configuration(repo, {".cargo/config.toml"})

    def test_relative_cargo_home_cannot_hide_configuration_in_build_directory(self) -> None:
        with tempfile.TemporaryDirectory(prefix="synthetic-relative-cargo-home-") as temporary:
            root = Path(temporary).resolve()
            repo = root / "repo"
            cargo_home = repo / "relative-cargo-home"
            cargo_home.mkdir(parents=True)
            (cargo_home / "config.toml").write_text("# Unsigned build-directory configuration\n")
            with mock.patch.dict(os.environ, {"CARGO_HOME": "relative-cargo-home"}), self.assertRaisesRegex(
                M.CampaignError, "absolute and canonical"
            ):
                M.reject_unsigned_cargo_configuration(repo, set())


class ProcessClosureTests(unittest.TestCase):
    """Pure exact Unix/Windows exit grammar and standalone smoke population checks."""

    def test_all_original_and_replacement_exits_use_exact_success_grammar(self) -> None:
        for value in ("unix_wait_status", "ExitStatus"):
            for newline in ("\n", "\r\n"):
                with self.subTest(platform=value, newline=newline):
                    rows = [f"TEST_NETWORK peer exited with status ExitStatus({value}(0))"] * (2 * M.PEER_COUNT)
                    M.validate_process_closure(newline.join(rows) + newline)

    def test_missing_extra_malformed_nonzero_and_foreign_records_refuse(self) -> None:
        good = "TEST_NETWORK peer exited with status ExitStatus(unix_wait_status(0))\n"
        cases = ["", good * (2 * M.PEER_COUNT - 1), good * (2 * M.PEER_COUNT + 1)]
        for bad in (
            good.replace("(0)", "(9)"), good.replace("(0)", "(256)"),
            good.replace("(0)", "(-1)"), good.replace("(0)", "(00)"),
            good.replace("(0)", "(invalid)"), good.replace("(0)", "(0) suffix"),
            good.replace("unix_wait_status(0)", "ExitStatus(1)"),
            good.replace("unix_wait_status(0)", "ExitStatus(4294967295)"),
            good.replace("ExitStatus(unix_wait_status(0))", "exit code: 0"),
            good.replace("TEST_NETWORK", "foreign TEST_NETWORK"),
            good.replace("with status", "with status:"),
            good.removesuffix("\n") + good,
        ):
            cases.append(good * (2 * M.PEER_COUNT - 1) + bad)
        for output in cases:
            with self.subTest(output=output), self.assertRaisesRegex(M.CampaignError, "validator process exit"):
                M.validate_process_closure(output)


class SerialCampaignTests(unittest.TestCase):
    """Exercise the real orchestration/reader with mocked commands and synthetic evidence only."""

    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="synthetic-smoke-campaign-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        self.repo = self.root / "repo"
        self.repo.mkdir()
        (self.repo / "scripts").mkdir()
        self.driver = self.repo / "scripts" / SCRIPT.name
        self.driver.write_text("# Synthetic signed source path; never executed.\n")
        self.target = self.repo / "target" / "synthetic"
        self.validator = self.target / "release" / "iroha3d"
        self.integration = self.target / "release" / "deps" / "nexus_and_streaming-synthetic"
        self.output = self.root / "campaign"
        self.seal = {"commit": COMMIT, "tree": "b"*40, "tracked_files": 1, "source_sha256": "c"*64}
        self.invocations = []
        self.clock = 100
        self.fail_run = None
        self.bad_exit_run = None
        self.drift_run = None
        self.source_drift_run = None
        self.patchers = [mock.patch.object(M, "source_seal", side_effect=lambda *_: self.seal.copy()),
                         mock.patch.object(M, "__file__", str(self.driver)),
                         mock.patch.object(M, "new_request", side_effect=lambda _commit, run: request(run)),
                         mock.patch.object(M, "command", side_effect=self.fake_command)]
        for patcher in self.patchers:
            patcher.start()
            self.addCleanup(patcher.stop)

    def fake_command(self, arguments: list[str], _repo: Path, environment: dict, directory: Path,
                     name: str, *, check: bool = True) -> dict:
        """Simulate a command receipt, never spawning the supplied executable."""
        self.invocations.append((name, arguments))
        output = "Synthetic unit-test command output; not release evidence.\n"
        exit_code = 0
        if name == "build-validator":
            (self.target / "release" / "deps").mkdir(parents=True)
            for path in (self.validator, self.integration):
                path.write_text("Synthetic test executable bytes: NEVER EXECUTED.\n")
                path.chmod(0o700)
        elif name == "build-integration":
            output += M.canonical({"reason": "compiler-artifact", "target": {"name": "nexus_and_streaming", "kind": ["test"]},
                                  "executable": str(self.integration)}).decode()+"\n"
        elif name == "discovery":
            output = f"{M.TEST_NAME}: test\n\n1 test, 0 benchmarks\n"
        elif name == "stdout":
            req = M.read_json(directory / "request.json")
            self.assertEqual(environment["IROHA_TEST_REQUIRE_NETWORK"], "1")
            self.assertEqual(environment["IROHA_TEST_NETWORK_START_ATTEMPTS"], "1")
            self.assertEqual(environment["IROHA_TEST_SKIP_BUILD"], "1")
            self.assertEqual(environment["RAYON_NUM_THREADS"], "8")
            self.assertNotIn("RUST_TEST_THREADS", environment)
            self.assertIn("--test-threads=1", arguments)
            self.assertEqual(environment["APS_REAL_PROCESS_REQUEST_SHA256"], M.sha((directory/"request.json").read_bytes()))
            self.assertEqual(list((directory/"evidence").iterdir()), [])
            M.owner_path(directory/"evidence", directory=True)
            evidence, result = evidence_fixture(req["run"], M.file_digest(self.validator))
            store_evidence(directory, evidence, result)
            if req["run"] == self.fail_run:
                exit_code = 101
                output = "running 1 test\ntest result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 5 filtered out; finished in 1.0s\n"
            else:
                output = f"running 1 test\ntest {M.TEST_NAME} ... APS smoke completed: synthetic test only\nok\n"
                output += "".join(
                    "TEST_NETWORK peer exited with status ExitStatus(unix_wait_status(" +
                    ("9" if req["run"] == self.bad_exit_run and index == 0 else "0") + "))\n"
                    for index in range(2 * M.PEER_COUNT))
                output += "test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 5 filtered out; finished in 1.0s\n"
            if req["run"] == self.drift_run:
                self.validator.write_text("Synthetic mid-run substituted binary.\n")
            if req["run"] == self.source_drift_run:
                self.seal = {**self.seal, "source_sha256": "d"*64}
        M.write_new(directory / f"{name}.log", output.encode())
        self.clock += 10
        record = {"version": 1, "command": arguments, "exit_code": exit_code, "started_ns": self.clock,
                  "finished_ns": self.clock + 1, "log": f"{name}.log", "log_sha256": M.sha(output.encode()),
                  "worker_environment": {key: environment.get(key) for key in M.WORKER_ENVIRONMENT_KEYS}}
        M.write_json(directory / f"{name}.json", record)
        if check:
            M.require(exit_code == 0, "synthetic failed command")
        return record

    def run_driver(self) -> dict:
        return M.run_campaign(self.repo, self.output, self.target, COMMIT)

    def test_ten_serial_fresh_runs_one_build_and_readonly_validation(self) -> None:
        campaign = self.run_driver()
        self.assertEqual(len(campaign["runs"]), 10)
        self.assertEqual([name for name, _ in self.invocations[:6]],
                         ["verify-commit", "toolchain-rustc", "toolchain-cargo", "build-validator", "build-integration", "discovery"])
        self.assertEqual([name for name, _ in self.invocations[6:]], ["stdout"]*10)
        self.assertEqual(len(self.invocations), 16)
        before = {str(path.relative_to(self.output)): (path.stat().st_mtime_ns, M.file_digest(path))
                  for path in self.output.rglob("*") if path.is_file()}
        self.assertEqual(M.validate_campaign(self.output, expected_commit=COMMIT), campaign)
        after = {str(path.relative_to(self.output)): (path.stat().st_mtime_ns, M.file_digest(path))
                 for path in self.output.rglob("*") if path.is_file()}
        self.assertEqual(before, after)
        self.assertEqual(len(self.invocations), 16, "read-only validation must never invoke the build/network command helper")
        with self.assertRaisesRegex(M.CampaignError, "another source"):
            M.validate_campaign(self.output, expected_commit="d"*40)

    def test_failure_is_retained_without_retry_and_after_seal_is_recorded(self) -> None:
        self.fail_run = 1
        with self.assertRaisesRegex(M.CampaignError, "run 1 failed"):
            self.run_driver()
        self.assertEqual(sum(name == "stdout" for name, _ in self.invocations), 2)
        self.assertTrue((self.output / "failure.json").is_file())
        self.assertTrue((self.output / "run-01" / "after.json").is_file())
        self.assertFalse((self.output / "run-02").exists())
        self.assertFalse((self.output / "campaign.json").exists())
        with self.assertRaisesRegex(M.CampaignError, "retains a failure"):
            M.validate_campaign(self.output)

    def test_binary_drift_during_first_run_stops_campaign(self) -> None:
        self.drift_run = 0
        with self.assertRaisesRegex(M.CampaignError, "drift during smoke"):
            self.run_driver()
        self.assertEqual(sum(name == "stdout" for name, _ in self.invocations), 1)
        self.assertNotEqual(M.read_json(self.output/"run-00"/"before.json"), M.read_json(self.output/"run-00"/"after.json"))

    def test_source_drift_during_first_run_stops_campaign(self) -> None:
        self.source_drift_run = 0
        with self.assertRaisesRegex(M.CampaignError, "drift during smoke"):
            self.run_driver()
        self.assertEqual(sum(name == "stdout" for name, _ in self.invocations), 1)

    def test_reused_request_nonce_prevents_second_network(self) -> None:
        def reused(_commit: str, run: int) -> dict:
            value = request(run)
            value["invocation_nonce"] = request(0)["invocation_nonce"]
            value["request_id"] = M.sha(M.canonical({key: item for key, item in value.items() if key != "request_id"}))
            return value
        with mock.patch.object(M, "new_request", side_effect=reused):
            with self.assertRaisesRegex(M.CampaignError, "fresh request collision"):
                self.run_driver()
        self.assertEqual(sum(name == "stdout" for name, _ in self.invocations), 1)

    def test_nonzero_validator_exit_stops_live_campaign_without_retry(self) -> None:
        self.bad_exit_run = 0
        with self.assertRaisesRegex(M.CampaignError, "successful validator process exits"):
            self.run_driver()
        self.assertEqual(sum(name == "stdout" for name, _ in self.invocations), 1)
        self.assertTrue((self.output / "failure.json").is_file())
        self.assertTrue((self.output / "run-00" / "after.json").is_file())
        self.assertFalse((self.output / "run-01").exists())
        self.assertFalse((self.output / "campaign.json").exists())

    def test_readonly_campaign_refuses_bad_closure_after_outer_log_rehash(self) -> None:
        campaign = self.run_driver()
        directory = self.output / "run-00"
        original_log = M.read_bytes(directory / "stdout.log").decode()
        original_record = M.read_json(directory / "stdout.json")
        original_exit = "TEST_NETWORK peer exited with status ExitStatus(unix_wait_status(0))\n"
        attacks = {
            "missing": original_log.replace(original_exit, "", 1),
            "extra": original_log + original_exit,
            "malformed": original_log.replace(original_exit, original_exit.replace("(0)", "(invalid)"), 1),
            "nonzero": original_log.replace(original_exit, original_exit.replace("(0)", "(9)"), 1),
            "mixed platform": original_log.replace(original_exit, original_exit.replace("unix_wait_status", "ExitStatus"), 1),
        }
        for label, output in attacks.items():
            with self.subTest(attack=label):
                record = copy.deepcopy(original_record)
                record["log_sha256"] = M.sha(output.encode())
                modified = copy.deepcopy(campaign)
                modified["runs"][0]["command_sha256"] = M.sha(M.canonical(record))
                (directory / "stdout.log").write_bytes(output.encode())
                (directory / "stdout.json").write_bytes(M.canonical(record) + b"\n")
                (self.output / "campaign.json").write_bytes(M.canonical(modified) + b"\n")
                with self.assertRaisesRegex(M.CampaignError, "validator process exit"):
                    M.validate_campaign(self.output, expected_commit=COMMIT)
        self.assertEqual(len(self.invocations), 16, "retained validation must never launch a native child")

    def test_output_inside_repository_and_existing_output_are_rejected(self) -> None:
        with self.assertRaisesRegex(M.CampaignError, "outside the repository"):
            M.run_campaign(self.repo, self.repo/"evidence", self.target, COMMIT)
        self.output.mkdir(mode=0o700)
        with self.assertRaises(FileExistsError):
            self.run_driver()
        self.assertEqual(self.invocations, [])

    def test_existing_build_target_is_rejected_before_any_build(self) -> None:
        self.target.mkdir(parents=True)
        with self.assertRaisesRegex(M.CampaignError, "fresh build target"):
            self.run_driver()
        self.assertEqual(self.invocations, [])


if __name__ == "__main__":
    unittest.main()
