#!/usr/bin/env python3
"""Replay public four-peer SCCP certificates through the pinned native TON VM.

The input is an original export from ``integration_tests/tests/sccp_lanes``.
This adapter never signs certificates or changes their committee. It copies the
contract project into a new target directory, renders the original bytes into
one Acton test, and preserves its inputs, output and source identities. A pass
qualifies checkpoint interoperability only, not a deployed route or monetary
authority. Ordinary exports and the named normal/heartbeat/successor or
normal/key_change/successor sequences are supported. The input's signed genesis
is retained, not decoded here; its
authentication remains the native producer's recorded prerequisite.
"""

from __future__ import annotations

import argparse
import dataclasses
import datetime
import hashlib
import json
import re
import shutil
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

import ton_sccp_builder as ton
from sccp_reference.finality import (
    FinalityHeader,
    checkpoint_id,
    parse_header,
    parse_qc_fixed,
)

ROOT = Path(__file__).resolve().parents[1]
ROLES = ("normal", "heartbeat", "successor")
KEY_CHANGE_ROLES = ("normal", "key_change", "successor")
TEST_NAME = "live native certificates retain checkpoint and rotation custody"
LATCH_TEST_NAME = "explicit native test quorum conflict permanently latches destination"
LATCH_PROVENANCE = "runtime_test_quorum_not_chain_output"


def require(condition: bool, message: str) -> None:
    """Reject malformed replay input even when Python assertions are disabled."""
    if not condition:
        raise ValueError(message)


def raw_bytes(value: Any, length: int | None, name: str) -> bytes:
    """Read a strict hex string or JSON byte array without numeric coercion."""
    if isinstance(value, str):
        digits = value[2:] if value.startswith("0x") else value
        require(bool(re.fullmatch(r"(?:[0-9a-fA-F]{2})+", digits)), f"{name}: canonical hex required")
        result = bytes.fromhex(digits)
    else:
        require(isinstance(value, list), f"{name}: byte array or hex required")
        require(all(type(item) is int and 0 <= item <= 255 for item in value), f"{name}: invalid byte")
        result = bytes(value)
    require(length is None or len(result) == length, f"{name}: expected {length} bytes")
    return result


def uint(value: Any, name: str) -> int:
    """Read an exact JSON u64, without accepting bool or float aliases."""
    require(type(value) is int and 0 <= value < 1 << 64, f"{name}: u64 required")
    return value


@dataclasses.dataclass(frozen=True)
class Certificate:
    """Original certificate bytes and the independently parsed public header."""

    role: str
    signature: bytes
    qc: bytes
    header: bytes
    parsed: FinalityHeader
    committee: tuple[bytes, ...]
    next_keys: tuple[bytes, ...] = ()


@dataclasses.dataclass(frozen=True)
class Bundle:
    """Structurally checked original pin and ordered certificate sequence."""

    network: bytes
    instance: bytes
    keys: tuple[bytes, ...]
    generation: int
    start: int
    until_ms: int
    certificates: tuple[Certificate, ...]
    latch: Certificate | None = None


def decode_bundle(source: dict[str, Any]) -> Bundle:
    """Check scope, exact quorum and an original-key heartbeat or 4→7 handoff.

    BLS verification is performed by the compiled destination in Acton. This
    decoder is not a signature verifier or a SignedBlockWire genesis decoder.
    """
    require(isinstance(source, dict) and type(source.get("version")) is int and source["version"] == 1, "export version must be 1")
    require(isinstance(source.get("chain_id"), str) and bool(source["chain_id"]), "chain id required")
    require(bool(raw_bytes(source.get("signed_genesis_wire"), None, "original signed genesis")), "signed genesis required")
    network = raw_bytes(source.get("network_id"), 32, "network id")
    instance = raw_bytes(source.get("consensus_instance"), 32, "consensus instance")
    pin = source["initial_generation"]
    keys = tuple(raw_bytes(key, 48, "original generation key") for key in pin["keys"])
    require(len(keys) == 4, "this replay requires the actual four-peer committee")
    root = ton.committee_root(keys).to_bytes(32, "big")
    require(root == raw_bytes(pin["committee_root"], 32, "original root"), "initial committee root mismatch")
    generation = uint(pin["generation"], "initial generation")
    start = uint(pin["start_height"], "initial start")
    until_ms = uint(pin["deadline_ms"], "initial deadline")
    require(generation > 0 and start > 0, "generation and start must be positive")
    if "certificate" in source:
        require("certificates" not in source, "ambiguous certificate sequences")
        rows, roles = [source["certificate"]], ("normal",)
    else:
        rows, roles = source.get("certificates"), tuple(source.get("certificate_roles", ()))
        require(isinstance(rows, list) and len(rows) == 3 and roles in (ROLES, KEY_CHANGE_ROLES), "named normal/heartbeat/successor or normal/key_change/successor sequence required")
    successor_keys = ()
    transition = None
    if roles == KEY_CHANGE_ROLES:
        transition = source.get("transition")
        require(isinstance(transition, dict), "key-change transition metadata required")
        old_keys = tuple(raw_bytes(key, 48, "ordered old key") for key in transition["ordered_old_committee"])
        require(old_keys == keys, "transition old committee must equal original pin")
        successor_keys = tuple(raw_bytes(key, 48, "ordered new key") for key in transition["ordered_new_committee"])
        require(len(successor_keys) == 7, "key-change successor must contain seven original keys")
        require(ton.committee_root(successor_keys).to_bytes(32, "big") != root, "key change must install a different root")
        for name in ("original_boundary_wire", "original_successor_wire"):
            require(bool(raw_bytes(transition[name], None, name)), f"{name}: original block wire required")
    certificates = []
    previous_height = start - 1
    previous_time = 0
    current_generation = generation
    current_deadline = until_ms
    current_keys = keys
    for role, row in zip(roles, rows):
        require(isinstance(row, dict), "certificate must be an object")
        require(tuple(raw_bytes(key, 48, "certificate key") for key in row["committee"]) == current_keys, "certificate must retain original committee keys for its generation")
        qc = raw_bytes(row["qc"], 116, "original QC")
        parsed_qc = parse_qc_fixed(qc)
        require(parsed_qc.signers >> len(current_keys) == 0 and parsed_qc.signers.bit_count() == ton.committee_quorum(len(current_keys)), "original QC must contain the exact quorum of current committee signers")
        header = raw_bytes(row["header"], 221, "original X")
        parsed = parse_header(header)
        require(parsed.network_id == network and parsed.active, "certificate network/active mismatch")
        require(parsed.height == uint(row["height"], "certificate height"), "certificate height mismatch")
        require(parsed.height > previous_height and parsed.timestamp_ms >= previous_time, "certificates must be ordered by increasing height and nondecreasing time")
        require(parsed.generation == current_generation and parsed.committee_root == root, "certificate does not name the current original-key generation")
        require(((parsed.timestamp_ms + 999) // 1000) * 1000 <= current_deadline, "generation must be live at replay time")
        require(parsed.rotation == (role in ("heartbeat", "key_change")), "only the named heartbeat or key change may rotate")
        next_keys = ()
        certificate_keys = current_keys
        if role == "heartbeat":
            require(parsed.next_committee_root == root, "heartbeat must retain the original key root")
        if role == "key_change":
            next_keys = successor_keys
            root = ton.committee_root(next_keys).to_bytes(32, "big")
            require(parsed.next_committee_root == root, "key-change next root must match original seven successor keys")
            require(parsed.height == uint(transition["boundary_height"], "transition boundary height"), "transition boundary height mismatch")
            current_keys = next_keys
        if parsed.rotation:
            current_generation += 1
            current_deadline = min((1 << 64) - 1, parsed.timestamp_ms + parsed.validity_ms)
        if role == "successor":
            require(parsed.height == previous_height + 1, "successor must be the first height after the rotation")
            if transition is not None:
                require(parsed.height == uint(transition["successor_height"], "transition successor height"), "transition successor height mismatch")
        certificates.append(Certificate(role, raw_bytes(row["aggregate_signature"], 96, "original signature"), qc, header, parsed, certificate_keys, next_keys))
        previous_height, previous_time = parsed.height, parsed.timestamp_ms
    if transition is not None:
        records = source.get("generations")
        require(isinstance(records, list) and len(records) == 2, "original ended and successor generation records required")
        ended, successor = records
        boundary = certificates[1].parsed
        require(uint(ended["generation"], "ended generation") == generation, "ended generation mismatch")
        require(tuple(raw_bytes(key, 48, "ended key") for key in ended["keys"]) == keys and raw_bytes(ended["committee_root"], 32, "ended root") == ton.committee_root(keys).to_bytes(32, "big"), "ended generation keys/root mismatch")
        require(uint(successor["generation"], "successor generation") == current_generation, "successor generation mismatch")
        require(tuple(raw_bytes(key, 48, "successor key") for key in successor["keys"]) == current_keys and raw_bytes(successor["committee_root"], 32, "successor root") == root, "successor generation keys/root mismatch")
        require(uint(successor["start_height"], "successor start") == boundary.height + 1 and uint(successor["deadline_ms"], "successor deadline") == current_deadline, "successor generation start/deadline mismatch")
    latch = None
    if roles == ROLES:
        require("destination_latch" in source, "heartbeat export requires explicit destination latch certificate")
    if "destination_latch" in source:
        item = source["destination_latch"]
        require(roles == ROLES, "native V1 latch export requires unchanged heartbeat keys")
        require(isinstance(item, dict) and type(item.get("version")) is int and item["version"] == 1, "latch version must be 1")
        require(item.get("provenance") == LATCH_PROVENANCE and item.get("rule") == "V1", "explicit malicious test quorum provenance and V1 rule required")
        row = item["certificate"]
        normal = certificates[0]
        committee = tuple(raw_bytes(key, 48, "malicious test certificate key") for key in row["committee"])
        require(committee == keys, "malicious test certificate must retain original ordered committee")
        qc = raw_bytes(row["qc"], 116, "malicious test QC")
        require(qc == normal.qc, "malicious test certificate must retain original QC and signers")
        header = raw_bytes(row["header"], 221, "malicious test X")
        parsed = parse_header(header)
        require(parsed.height == uint(row["height"], "malicious test height"), "malicious test certificate height mismatch")
        require(normal.parsed.timestamp_ms < (1 << 64) - 1, "conflicting timestamp must fit u64")
        require(header == dataclasses.replace(normal.parsed, timestamp_ms=normal.parsed.timestamp_ms + 1).encode(), "only the deliberately conflicting timestamp may change")
        require(parsed.timestamp_ms < certificates[1].parsed.timestamp_ms, "conflict must precede authentic handoff")
        require(((parsed.timestamp_ms + 999) // 1000) * 1000 <= until_ms, "conflict replay must remain within original deadline")
        require(checkpoint_id(header) != checkpoint_id(normal.header), "conflicting checkpoint id must differ")
        latch = Certificate("malicious_test_v1", raw_bytes(row["aggregate_signature"], 96, "malicious test signature"), qc, header, parsed, committee)
    return Bundle(network, instance, keys, generation, start, until_ms, tuple(certificates), latch)


def slice_literal(data: bytes) -> str:
    """Render fixed public bytes without interpolation of untrusted Tolk text."""
    return f'"{data.hex()}".hexToSlice()'


def certificate_expression(cert: Certificate, *, forged: bool = False, foreign: bool = False) -> str:
    """Render the canonical TON certificate graph, or one explicit negative."""
    qc, header = bytearray(cert.qc), bytearray(cert.header)
    if forged:
        qc[80] ^= 1  # result_body, leaving the original signature untouched
    if foreign:
        header[16] ^= 1  # network id, leaving the original signature untouched
    return "certCell({}, {}, {}, {}, {})".format(
        slice_literal(cert.signature), int.from_bytes(qc[112:], "big"),
        slice_literal(bytes(qc[:112])), slice_literal(bytes(header[:109])), slice_literal(bytes(header[109:])),
    )


def render_test(bundle: Bundle, source_sha256: str) -> str:
    """Render a real-address replay with exact events and state-preserving refusals."""
    require(bool(re.fullmatch(r"[0-9a-f]{64}", source_sha256)), "source SHA-256 required")
    key_values = ",\n        ".join(slice_literal(key) for key in bundle.keys)
    root = ton.committee_root(bundle.keys)
    first = bundle.certificates[0].parsed
    lines = [f'''// Runtime-only public native export SHA-256: {source_sha256}
// Generated by scripts/sccp_ton_live_replay.py; no signatures are generated here.
import "@acton/emulation/network"
import "@acton/emulation/testing"
import "@acton/testing/expect"
import "@acton/io"
import "@contracts/sccp-cells"
import "@contracts/sccp-errors"
import "@contracts/sccp-messages"
import "@contracts/sccp-storage"
import "@wrappers/SccpTairaXorMinter.gen"
import "sccp-test-helpers"

/// No wrapped value, outbound nonce, governance action or bucket is created.
fun liveNoMonetaryEffect(env: Env, expectedLatched: bool) {{
    val st = env.minter.getSccpState();
    expect(st.initialized).toBeTrue();
    expect(st.equivocated).toEqual(expectedLatched);
    expect(st.totalSupply).toEqual(0);
    expect(st.pendingSupply).toEqual(0);
    expect(st.outboundNonce).toEqual(0);
    expect(st.opCount).toEqual(0);
    expect(st.controlNonce).toEqual(0);
    expect(st.deployedBuckets).toEqual(0);
    expect(st.parliamentPaused).toBeFalse();
    expect(st.fastPauseUntilMs).toEqual(0);
}}

/// A refused message emits no SCCP event and preserves all minter data.
fun liveRefusal(env: Env, cert: cell, expected: int, nextKeys: cell?) {{
    val before = minterStorage(env).toCell().hash();
    val result = sendCheckpoint(env, env.deployer, cert, nextKeys, REPLAY_VALUE);
    expectOutcome(result, expected);
    expectEvents(result, []);
    expect(minterStorage(env).toCell().hash()).toEqual(before);
    liveNoMonetaryEffect(env, false);
}}

get fun `test {TEST_NAME}`() {{
    testing.setNow({(first.timestamp_ms + 999) // 1000});
    val deployer = testing.treasury("native-replay-relayer").address;
    val keys: array<slice> = [
        {key_values}
    ];
    val pin: InitialPin = {{ generation: {bundle.generation}, root: {root}, start: {bundle.start}, untilMs: {bundle.until_ms} }};
    val storage = canonicalStorage({int.from_bytes(bundle.network, 'big')}, {int.from_bytes(bundle.instance, 'big')}, 1, TEST_MAX_SUPPLY, pin, keys);
    val (minter, deployed) = deployWithInit(storage, deployer, REPLAY_VALUE);
    expect(deployed).toHaveSuccessfulDeploy({{ to: minter.address }});
    val env: Env = {{ minter, deployer, networkId: {int.from_bytes(bundle.network, 'big')}, instance: {int.from_bytes(bundle.instance, 'big')}, generation: {bundle.generation}, committee: {{ keys, secrets: [] }} }};
    expect(minter.address).toEqual(SccpTairaXorMinter.fromStorage(storage).address);
    liveNoMonetaryEffect(env, false);
    expect(minter.getSccpState().initialRoot).toEqual({root});
    expect(minter.getSccpState().initialUntilMs).toEqual({bundle.until_ms});
    expect(minter.getSccpCheckpoints().count).toEqual(0);
    println("native-replay source {source_sha256}");
    println("native-replay address {{}}", minter.address);
''']
    generation, start, until = bundle.generation, bundle.start, bundle.until_ms
    current_keys_expression = "env.committee.keysCell()"
    current_n = len(bundle.keys)
    for index, cert in enumerate(bundle.certificates):
        x = cert.parsed
        now = (x.timestamp_ms + 999) // 1000
        ident = int.from_bytes(checkpoint_id(cert.header), "big")
        lines.extend([
            f"    // {cert.role}: original QC, X and compressed signature; full path first.",
            f"    testing.setNow({now});",
            f"    liveRefusal(env, {certificate_expression(cert, forged=True)}, SccpErrors.BadSignature, null);",
            f"    liveRefusal(env, {certificate_expression(cert, foreign=True)}, SccpErrors.BadHeader, null);",
            f"    val cert{index} = {certificate_expression(cert)};",
        ])
        next_keys_argument = "null"
        if cert.next_keys:
            successor_literals = ", ".join(slice_literal(key) for key in cert.next_keys)
            next_keys_argument = f"nextKeys{index}"
            lines.extend([
                f"    val {next_keys_argument} = sccpBuildKeys([{successor_literals}]);",
                f"    liveRefusal(env, cert{index}, SccpErrors.BadCommittee, null);",
                f"    liveRefusal(env, cert{index}, SccpErrors.BadCommittee, {current_keys_expression});",
                '    println("native-replay successor-data key_change missing BadCommittee wrong-root BadCommittee");',
            ])
            current_keys_expression = next_keys_argument
            current_n = len(cert.next_keys)
        lines.extend([
            f"    val result{index} = sendCheckpoint(env, deployer, cert{index}, {next_keys_argument}, REPLAY_VALUE);",
            f"    expectOutcome(result{index}, 0);",
        ])
        events = [f"eventCertificate({x.height}, {x.generation}, cert{index})", f"eventCheckpointed({x.height}, {ident})"]
        if x.rotation:
            generation += 1
            start = x.height + 1
            until = min((1 << 64) - 1, x.timestamp_ms + x.validity_ms)
            root = int.from_bytes(x.next_committee_root, "big")
            events.append(f"eventRotated({generation}, {root}, {until}, {start})")
        lines.extend([
            f"    expectEvents(result{index}, [{', '.join(events)}]);",
            f"    val state{index} = minter.getSccpState();",
            f"    expect(state{index}.generation).toEqual({generation});",
            f"    expect(state{index}.root).toEqual({root});",
            f"    expect(state{index}.start).toEqual({start});",
            f"    expect(state{index}.high).toEqual({x.height});",
            f"    expect(state{index}.untilMs).toEqual({until});",
            f"    expect(minter.getSccpCommittee().keys.hash()).toEqual({current_keys_expression}.hash());",
            f"    expect(minter.getSccpCommittee().n).toEqual({current_n});",
            f"    expect(minter.getSccpCheckpoints().count).toEqual({index + 1});",
        ])
        for slot, past in enumerate(bundle.certificates[:index + 1]):
            lines.extend([
                f"    expect(minter.getSccpCheckpoints().height{slot}).toEqual({past.parsed.height});",
                f"    expect(minter.getSccpCheckpoints().id{slot}).toEqual({int.from_bytes(checkpoint_id(past.header), 'big')});",
            ])
        duplicate = "CommitteeNotAccepted" if x.rotation else "NothingToDo"
        lines.extend([
            "    liveNoMonetaryEffect(env, false);",
            f"    liveRefusal(env, cert{index}, SccpErrors.{duplicate}, null);",
            f'    println("native-replay accepted {cert.role} height {x.height} checkpoint {checkpoint_id(cert.header).hex()}");',
            f'    println("native-replay refusals {cert.role} BadSignature BadHeader {duplicate}");',
        ])
    lines.extend([
        f"    testing.setNow({until // 1000 + 1});",
        f"    liveRefusal(env, cert{len(bundle.certificates) - 1}, SccpErrors.CommitteeNotAccepted, null);",
        '    println("native-replay refusal expired CommitteeNotAccepted");',
        '    println("native-replay complete no-monetary-effect");',
        "}", "",
    ])
    if bundle.latch is not None:
        lines.append(render_latch_test(bundle))
    return "\n".join(lines)


def render_latch_test(bundle: Bundle) -> str:
    """Replay the labeled malicious runtime quorum certificate without signing."""
    require(bundle.latch is not None, "labeled native test conflict required")
    normal, heartbeat = bundle.certificates[:2]
    conflict = bundle.latch
    keys = ", ".join(slice_literal(key) for key in bundle.keys)
    root = ton.committee_root(bundle.keys)
    original_id = int.from_bytes(checkpoint_id(normal.header), "big")
    conflicting_id = int.from_bytes(checkpoint_id(conflict.header), "big")
    return f'''
// This certificate is an explicitly malicious runtime test-quorum signature,
// not an original committed-chain output. Neither adapter signs anything.
get fun `test {LATCH_TEST_NAME}`() {{
    testing.setNow({(conflict.parsed.timestamp_ms + 999) // 1000});
    val deployer = testing.treasury("native-latch-relayer").address;
    val keys: array<slice> = [{keys}];
    val pin: InitialPin = {{ generation: {bundle.generation}, root: {root}, start: {bundle.start}, untilMs: {bundle.until_ms} }};
    val storage = canonicalStorage({int.from_bytes(bundle.network, 'big')}, {int.from_bytes(bundle.instance, 'big')}, 1, TEST_MAX_SUPPLY, pin, keys);
    val (minter, deployed) = deployWithInit(storage, deployer, REPLAY_VALUE);
    expect(deployed).toHaveSuccessfulDeploy({{ to: minter.address }});
    val env: Env = {{ minter, deployer, networkId: {int.from_bytes(bundle.network, 'big')}, instance: {int.from_bytes(bundle.instance, 'big')}, generation: {bundle.generation}, committee: {{ keys, secrets: [] }} }};
    expect(minter.address).toEqual(SccpTairaXorMinter.fromStorage(storage).address);
    val original = {certificate_expression(normal)};
    val accepted = sendCheckpoint(env, deployer, original, null, REPLAY_VALUE);
    expectOutcome(accepted, 0);
    expectEvents(accepted, [eventCertificate({normal.parsed.height}, {normal.parsed.generation}, original), eventCheckpointed({normal.parsed.height}, {original_id})]);
    liveNoMonetaryEffect(env, false);
    liveRefusal(env, {certificate_expression(conflict, forged=True)}, SccpErrors.BadSignature, null);
    var expected = minterStorage(env);
    expected.equivocated = true;
    var expectedCommittee = expected.committee.load();
    expectedCommittee.untilMs = 0;
    expected.committee = expectedCommittee.toCell();
    val malicious = {certificate_expression(conflict)};
    val latched = sendCheckpoint(env, deployer, malicious, null, REPLAY_VALUE);
    expectOutcome(latched, 0);
    expectEvents(latched, [eventCertificate({normal.parsed.height}, {normal.parsed.generation}, malicious), eventLatched(1, {normal.parsed.generation}, {normal.parsed.height}, {original_id}, {conflicting_id})]);
    expect(latched).toHaveSuccessfulTx<ReturnExcessesBack>({{ to: deployer }});
    expect(minterStorage(env).toCell().hash()).toEqual(expected.toCell().hash());
    expect(minter.getSccpCheckpoints().count).toEqual(1);
    expect(minter.getSccpCheckpoints().height0).toEqual({normal.parsed.height});
    expect(minter.getSccpCheckpoints().id0).toEqual({original_id});
    liveNoMonetaryEffect(env, true);
    val later = sendCheckpoint(env, deployer, {certificate_expression(heartbeat)}, null, REPLAY_VALUE);
    expectOutcome(later, SccpErrors.Equivocated);
    expectEvents(later, []);
    expect(minterStorage(env).toCell().hash()).toEqual(expected.toCell().hash());
    liveNoMonetaryEffect(env, true);
    println("native-replay latch V1 {checkpoint_id(normal.header).hex()} {checkpoint_id(conflict.header).hex()} untilMs 0");
    println("native-replay latch refusals BadSignature Equivocated no-monetary-effect");
}}
'''


def sha256(path: Path) -> str:
    """Hash one retained input or output."""
    return hashlib.sha256(path.read_bytes()).hexdigest()


def source_snapshot() -> dict[str, str]:
    """Capture copied source plus the adapter, reference and native Acton library."""
    paths = []
    for directory in (ton.PROJECT / "contracts", ton.PROJECT / "wrappers", ton.PROJECT / "tests", ton.PROJECT / ".acton", ROOT / "scripts/sccp_reference"):
        paths.extend(path for path in directory.rglob("*") if path.is_file() and "__pycache__" not in path.parts and path.suffix != ".pyc")
    paths.extend([ton.PROJECT / "Acton.toml", Path(__file__), ROOT / "scripts/ton_sccp_builder.py", ROOT / "scripts/tests/sccp_ton_live_replay_test.py"])
    return {str(path.relative_to(ROOT)): sha256(path) for path in sorted(set(paths))}


def project_snapshot(project: Path) -> dict[str, str]:
    """Hash the sources and native libraries actually read in the copied project."""
    paths = [project / "Acton.toml"]
    for relative in ("contracts", "wrappers", "tests", ".acton"):
        paths.extend(path for path in (project / relative).rglob("*") if path.is_file())
    return {str(path.relative_to(project)): sha256(path) for path in sorted(paths)}


def replay(source_path: Path, output: Path, acton: Path) -> dict[str, Any]:
    """Run original replay and any labeled V1 latch test in a retained project."""
    source_path, output = source_path.resolve(), output.resolve()
    require(output.is_relative_to(ROOT / "target"), "output must stay under repository target")
    require(not output.exists(), "use a new output directory; prior receipts are immutable")
    raw = source_path.read_bytes()
    source = json.loads(raw)
    bundle = decode_bundle(source)
    output.mkdir(parents=True)
    before = source_snapshot()
    tool_before = sha256(acton)
    export_hash = hashlib.sha256(raw).hexdigest()
    (output / "export.json").write_bytes(raw)
    (output / "source-before.json").write_text(json.dumps(before, indent=2) + "\n")
    project = output / "project"
    project.mkdir()
    for relative in ("Acton.toml", "contracts", "wrappers", "tests", ".acton"):
        source_item = ton.PROJECT / relative
        if source_item.is_dir():
            shutil.copytree(source_item, project / relative)
        else:
            shutil.copy2(source_item, project / relative)
    copied = project_snapshot(project)
    require(all(before.get(f"contracts/ton/sccp/{path}") == digest for path, digest in copied.items()), "copied project differs from captured source")
    test_path = project / "tests/unit/sccp-live-native.test.tolk"
    test_path.write_text(render_test(bundle, export_hash))
    copied_before = project_snapshot(project)
    (output / "project-source-before.json").write_text(json.dumps(copied_before, indent=2) + "\n")
    command = [str(acton), "--color", "never", "test", "tests/unit/sccp-live-native.test.tolk"]
    started = datetime.datetime.now(datetime.timezone.utc).isoformat()
    command_record = {"command": command, "cwd": str(project), "started_utc": started, "export_sha256": export_hash, "acton_sha256": tool_before, "acton_version": ton.ACTON_REPORTED_VERSION, "rendered_test_sha256": sha256(test_path), "python": {"executable": sys.executable, "version": sys.version, "sha256": sha256(Path(sys.executable))}}
    (output / "command.json").write_text(json.dumps(command_record, indent=2) + "\n")
    start_time = time.monotonic()
    with (output / "acton.log").open("w") as log:
        completed = subprocess.run(command, cwd=project, stdout=log, stderr=subprocess.STDOUT, check=False)
    after = source_snapshot()
    (output / "source-after.json").write_text(json.dumps(after, indent=2) + "\n")
    copied_after = project_snapshot(project)
    (output / "project-source-after.json").write_text(json.dumps(copied_after, indent=2) + "\n")
    log_text = (output / "acton.log").read_text()
    counts = re.findall(r"(\d+) passed in (\d+) files?", log_text)
    expected_markers = [f"native-replay source {export_hash}", "native-replay refusal expired CommitteeNotAccepted", "native-replay complete no-monetary-effect"]
    for cert in bundle.certificates:
        duplicate = "CommitteeNotAccepted" if cert.parsed.rotation else "NothingToDo"
        expected_markers.extend([
            f"native-replay accepted {cert.role} height {cert.parsed.height} checkpoint {checkpoint_id(cert.header).hex()}",
            f"native-replay refusals {cert.role} BadSignature BadHeader {duplicate}",
        ])
        if cert.next_keys:
            expected_markers.append("native-replay successor-data key_change missing BadCommittee wrong-root BadCommittee")
    if bundle.latch is not None:
        expected_markers.extend([
            f"native-replay latch V1 {checkpoint_id(bundle.certificates[0].header).hex()} {checkpoint_id(bundle.latch.header).hex()} untilMs 0",
            "native-replay latch refusals BadSignature Equivocated no-monetary-effect",
        ])
    expected_test_count = 2 if bundle.latch is not None else 1
    stable = before == after and copied_before == copied_after and tool_before == sha256(acton) and export_hash == sha256(source_path) and export_hash == sha256(output / "export.json") and command_record["rendered_test_sha256"] == sha256(test_path) and command_record["python"]["sha256"] == sha256(Path(sys.executable))
    qualified = completed.returncode == 0 and counts == [(str(expected_test_count), "1")] and all(log_text.count(marker) == 1 for marker in expected_markers) and stable
    result = {
        **command_record, "ended_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "elapsed_seconds": round(time.monotonic() - start_time, 3), "exit_code": completed.returncode,
        "qualified": qualified, "source_and_tool_stable": stable,
        "scope": "original native certificate checkpoint/heartbeat/key-change interoperability in pinned Acton; no route deployment or monetary authority",
        "genesis_authentication": "retained original SignedBlockWire; authentication is the native producer's prerequisite, not repeated by this adapter",
        "certificates": [{"role": cert.role, "height": cert.parsed.height, "generation": cert.parsed.generation, "committee_size": len(cert.committee), "next_committee_size": len(cert.next_keys), "checkpoint": checkpoint_id(cert.header).hex()} for cert in bundle.certificates],
        "test_counts": counts, "expected_test_count": expected_test_count, "expected_markers": expected_markers,
        "destination_latch": None if bundle.latch is None else {"provenance": LATCH_PROVENANCE, "rule": "V1", "original_checkpoint": checkpoint_id(bundle.certificates[0].header).hex(), "conflicting_checkpoint": checkpoint_id(bundle.latch.header).hex(), "qualified": qualified},
        "source_drift": [path for path in sorted(before.keys() | after.keys()) if before.get(path) != after.get(path)],
        "copied_source_drift": [path for path in sorted(copied_before.keys() | copied_after.keys()) if copied_before.get(path) != copied_after.get(path)],
        "compiled_outputs": {str(path.relative_to(project)): sha256(path) for path in sorted((project / "build").rglob("*")) if path.is_file()},
        "log_sha256": sha256(output / "acton.log"), "launch_qualified": False,
    }
    (output / "result.json").write_text(json.dumps(result, indent=2) + "\n")
    return result


def main() -> int:
    """CLI for a retained ordinary or heartbeat export and a fresh target output."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--acton", help="absolute pinned native Acton executable")
    args = parser.parse_args()
    result = replay(args.source, args.output, ton.resolve_acton(args.acton, offline=True))
    print(json.dumps(result, indent=2))
    return 0 if result["qualified"] else 1


if __name__ == "__main__":
    sys.exit(main())
