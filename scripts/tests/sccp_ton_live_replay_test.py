"""Input and rendering checks for original-certificate TON replay tooling.

Synthetic sequence edits here test the adapter's structure only. They are never
submitted to Acton or reported as native cryptographic qualification.
"""

from __future__ import annotations

import copy
import dataclasses
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))

import sccp_ton_live_replay as replay  # noqa: E402


@pytest.fixture
def ordinary() -> dict:
    """Use public independent fixture bytes for decoder tests, not live claims."""
    vectors = json.loads((ROOT / "fixtures/sccp/finality_v1.json").read_text())
    row = next(row for row in vectors["certificates"] if row["label"] == "n4_lowest_q")
    keys = bytes.fromhex(row["evm"]["committee"][2:])
    committee = [keys[offset:offset + 48].hex() for offset in range(0, len(keys), 48)]
    return {
        "version": 1,
        "chain_id": "unit-test-structural-input",
        "network_id": row["header_fields"]["network_id"],
        "consensus_instance": vectors["verification_context"]["consensus_instance"],
        "signed_genesis_wire": [1],  # presence only; the adapter does not authenticate it
        "initial_generation": {
            **row["pin"], "keys": committee, "deadline_ms": row["pin"]["until_ms"],
        },
        "certificate": {
            "height": row["header_fields"]["height"],
            "committee": committee,
            "qc": row["evm"]["qc"],
            "header": row["evm"]["header"],
            "aggregate_signature": row["aggregate_signature"]["compressed"],
        },
    }


@pytest.fixture
def heartbeat(ordinary: dict) -> dict:
    """Structurally valid but deliberately unsigned header edits for decoder tests."""
    first = replay.decode_bundle(ordinary).certificates[0].parsed
    beat = dataclasses.replace(first, height=first.height + 1, timestamp_ms=first.timestamp_ms + 3_600_000,
                               flags=3, next_committee_root=first.committee_root, validity_ms=1_209_600_000)
    successor = dataclasses.replace(first, height=first.height + 2, timestamp_ms=beat.timestamp_ms + 1_000,
                                    generation=first.generation + 1)
    result = copy.deepcopy(ordinary)
    base = result.pop("certificate")
    result["certificate_roles"] = list(replay.ROLES)
    result["certificates"] = [base, {**base, "height": beat.height, "header": beat.encode().hex()},
                              {**base, "height": successor.height, "header": successor.encode().hex()}]
    result["destination_latch"] = {
        "version": 1, "provenance": replay.LATCH_PROVENANCE, "rule": "V1",
        "certificate": {**base, "header": dataclasses.replace(first, timestamp_ms=first.timestamp_ms + 1).encode().hex()},
    }
    return result


@pytest.fixture
def key_change(heartbeat: dict) -> dict:
    """Unsigned structural 4→7 transition; never a native or Acton receipt."""
    result = copy.deepcopy(heartbeat)
    vectors = json.loads((ROOT / "fixtures/sccp/finality_v1.json").read_text())
    row = next(row for row in vectors["certificates"] if row["label"] == "n7_lowest_q")
    key_bytes = bytes.fromhex(row["evm"]["committee"][2:])
    keys = [key_bytes[offset:offset + 48].hex() for offset in range(0, len(key_bytes), 48)]
    decoded = replay.decode_bundle(heartbeat)
    root = replay.ton.committee_root(tuple(bytes.fromhex(key) for key in keys)).to_bytes(32, "big")
    boundary = dataclasses.replace(decoded.certificates[1].parsed, next_committee_root=root)
    successor = dataclasses.replace(decoded.certificates[2].parsed, committee_root=root)
    del result["destination_latch"]
    result["certificate_roles"] = list(replay.KEY_CHANGE_ROLES)
    result["certificates"][1]["header"] = boundary.encode().hex()
    result["certificates"][2].update({"header": successor.encode().hex(), "committee": keys,
                                      "qc": (decoded.certificates[2].qc[:112] + (31).to_bytes(4, "big")).hex()})
    result["transition"] = {
        "ordered_old_committee": result["initial_generation"]["keys"],
        "ordered_new_committee": keys,
        "boundary_height": boundary.height,
        "successor_height": successor.height,
        "original_boundary_wire": [1], "original_successor_wire": [1],
    }
    result["generations"] = [copy.deepcopy(result["initial_generation"]), {
        "keys": keys, "committee_root": root.hex(), "generation": successor.generation,
        "start_height": successor.height, "deadline_ms": boundary.timestamp_ms + boundary.validity_ms,
    }]
    return result


@pytest.mark.parametrize("value", [[True], [256], [-1], [1.0], "0x0", "0xgg", "aa bb", None])
def test_bytes_reject_noncanonical_inputs(value: object) -> None:
    with pytest.raises(ValueError):
        replay.raw_bytes(value, 1, "test")


def test_original_bytes_remain_exact(ordinary: dict) -> None:
    bundle = replay.decode_bundle(ordinary)
    cert = bundle.certificates[0]
    assert cert.qc.hex() == ordinary["certificate"]["qc"][2:]
    assert cert.header.hex() == ordinary["certificate"]["header"][2:]
    assert cert.signature.hex() == ordinary["certificate"]["aggregate_signature"][2:]
    assert replay.raw_bytes([0, 255], 2, "test") == b"\x00\xff"
    with pytest.raises(ValueError, match="expected 3"):
        replay.raw_bytes("0x00ff", 3, "test")


@pytest.mark.parametrize("value", [True, 1.0, -1, 1 << 64, "1"])
def test_u64_rejects_aliases(value: object) -> None:
    with pytest.raises(ValueError, match="u64"):
        replay.uint(value, "test")


def test_decoder_requires_original_keys_and_exact_quorum(ordinary: dict) -> None:
    wrong_keys = copy.deepcopy(ordinary)
    wrong_keys["certificate"]["committee"] = wrong_keys["certificate"]["committee"][::-1]
    with pytest.raises(ValueError, match="retain original"):
        replay.decode_bundle(wrong_keys)
    for signers in (0b0011, 0b1111, 0b10101):
        bad = copy.deepcopy(ordinary)
        qc = bytes.fromhex(bad["certificate"]["qc"][2:])
        bad["certificate"]["qc"] = (qc[:112] + signers.to_bytes(4, "big")).hex()
        with pytest.raises(ValueError, match="exact quorum"):
            replay.decode_bundle(bad)


def test_decoder_rejects_foreign_scope_and_missing_genesis(ordinary: dict) -> None:
    foreign = copy.deepcopy(ordinary)
    foreign["network_id"] = bytes(32).hex()
    with pytest.raises(ValueError, match="network/active"):
        replay.decode_bundle(foreign)
    ordinary["signed_genesis_wire"] = []
    with pytest.raises(ValueError, match="signed genesis required"):
        replay.decode_bundle(ordinary)


def test_decoder_rejects_ambiguous_sequences_and_version_alias(ordinary: dict) -> None:
    bad = copy.deepcopy(ordinary)
    bad["certificates"] = [bad["certificate"]]
    with pytest.raises(ValueError, match="ambiguous"):
        replay.decode_bundle(bad)
    ordinary["version"] = True
    with pytest.raises(ValueError, match="version"):
        replay.decode_bundle(ordinary)


def test_named_heartbeat_sequence_and_generation_are_checked(heartbeat: dict) -> None:
    bundle = replay.decode_bundle(heartbeat)
    assert tuple(cert.role for cert in bundle.certificates) == replay.ROLES
    bad = copy.deepcopy(heartbeat)
    bad["certificate_roles"][1] = "rotation"
    with pytest.raises(ValueError, match="named"):
        replay.decode_bundle(bad)
    bad = copy.deepcopy(heartbeat)
    successor = bundle.certificates[2].parsed
    bad["certificates"][2]["header"] = dataclasses.replace(successor, generation=successor.generation - 1).encode().hex()
    with pytest.raises(ValueError, match="current original-key generation"):
        replay.decode_bundle(bad)


def test_successor_must_be_first_height_and_deadline_live(heartbeat: dict) -> None:
    bad = copy.deepcopy(heartbeat)
    successor = replay.decode_bundle(bad).certificates[2].parsed
    bad["certificates"][2]["header"] = dataclasses.replace(successor, height=successor.height + 1).encode().hex()
    bad["certificates"][2]["height"] += 1
    with pytest.raises(ValueError, match="first height"):
        replay.decode_bundle(bad)
    bad = copy.deepcopy(heartbeat)
    bad["initial_generation"]["deadline_ms"] = 1
    with pytest.raises(ValueError, match="live at replay"):
        replay.decode_bundle(bad)


def test_render_forces_full_verification_before_acceptance(heartbeat: dict) -> None:
    bundle = replay.decode_bundle(heartbeat)
    rendered = replay.render_test(bundle, "a" * 64)
    assert rendered.index("SccpErrors.BadSignature") < rendered.index("val result0")
    assert "liveRefusal(env, cert0, SccpErrors.NothingToDo, null)" in rendered
    assert "liveRefusal(env, cert1, SccpErrors.CommitteeNotAccepted, null)" in rendered
    assert "liveRefusal(env, cert2, SccpErrors.NothingToDo, null)" in rendered
    assert "deployWithInit(storage, deployer, REPLAY_VALUE)" in rendered
    assert "secrets: []" in rendered
    for forbidden in ("deployPinned(", "installPinned(", "setMinterStorage(", "seedCheckpoint(", "signCertificate("):
        assert forbidden not in rendered
    for cert in bundle.certificates:
        assert cert.signature.hex() in rendered
        assert cert.qc[:112].hex() in rendered
        assert cert.header[:109].hex() in rendered
    assert "minterStorage(env).toCell().hash()).toEqual(before)" in rendered
    assert rendered.count("eventRotated(") == 1


def test_key_change_checks_new_keys_quorum_and_retained_generations(key_change: dict) -> None:
    decoded = replay.decode_bundle(key_change)
    assert tuple(len(cert.committee) for cert in decoded.certificates) == (4, 4, 7)
    assert decoded.certificates[1].next_keys == decoded.certificates[2].committee
    assert not decoded.certificates[0].next_keys and not decoded.certificates[2].next_keys
    for signers in (7, 15, 63, 0x8F):
        bad = copy.deepcopy(key_change)
        bad["certificates"][2]["qc"] = (decoded.certificates[2].qc[:112] + signers.to_bytes(4, "big")).hex()
        with pytest.raises(ValueError, match="exact quorum"):
            replay.decode_bundle(bad)
    bad = copy.deepcopy(key_change)
    bad["generations"][1]["deadline_ms"] += 1
    with pytest.raises(ValueError, match="start/deadline"):
        replay.decode_bundle(bad)


def test_key_change_cannot_replace_boundary_signers_or_successor_root(key_change: dict) -> None:
    bad = copy.deepcopy(key_change)
    bad["certificates"][1]["committee"] = bad["transition"]["ordered_new_committee"]
    with pytest.raises(ValueError, match="retain original"):
        replay.decode_bundle(bad)
    bad = copy.deepcopy(key_change)
    boundary = replay.decode_bundle(bad).certificates[1].parsed
    bad["certificates"][1]["header"] = dataclasses.replace(boundary, next_committee_root=boundary.committee_root).encode().hex()
    with pytest.raises(ValueError, match="next root"):
        replay.decode_bundle(bad)
    bad = copy.deepcopy(key_change)
    bad["transition"]["original_boundary_wire"] = []
    with pytest.raises(ValueError, match="original block wire"):
        replay.decode_bundle(bad)


def test_key_change_renders_original_next_keys_and_required_data_refusals(key_change: dict) -> None:
    bundle = replay.decode_bundle(key_change)
    rendered = replay.render_test(bundle, "b" * 64)
    assert "sendCheckpoint(env, deployer, cert1, nextKeys1, REPLAY_VALUE)" in rendered
    assert "liveRefusal(env, cert1, SccpErrors.BadCommittee, null)" in rendered
    assert "liveRefusal(env, cert1, SccpErrors.BadCommittee, env.committee.keysCell())" in rendered
    assert "expect(minter.getSccpCommittee().keys.hash()).toEqual(nextKeys1.hash())" in rendered
    assert rendered.count("expect(minter.getSccpCommittee().n).toEqual(7)") == 2
    assert "SccpErrors.CommitteeNotAccepted, null" in rendered
    for key in bundle.certificates[1].next_keys:
        assert key.hex() in rendered
    for cert in bundle.certificates:
        assert cert.signature.hex() in rendered
    assert rendered.count("eventRotated(") == 1


def test_negative_encodings_only_change_designated_unsigned_input(ordinary: dict) -> None:
    cert = replay.decode_bundle(ordinary).certificates[0]
    forged = replay.certificate_expression(cert, forged=True)
    foreign = replay.certificate_expression(cert, foreign=True)
    assert cert.signature.hex() in forged and cert.signature.hex() in foreign
    assert cert.qc[:112].hex() not in forged
    assert cert.qc[:112].hex() in foreign
    assert cert.header[:109].hex() in forged
    assert cert.header[:109].hex() not in foreign


def test_output_cannot_replace_prior_receipts(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="repository target"):
        # ROOT stays outside target regardless of the pytest TMPDIR location.
        replay.replay(tmp_path / "missing.json", ROOT, tmp_path / "acton")
    with pytest.raises(ValueError, match="new output"):
        replay.replay(tmp_path / "missing.json", ROOT / "target", tmp_path / "acton")


@pytest.fixture
def latch_bundle(heartbeat: dict) -> dict:
    """Unsigned malicious-header structure only; never native BLS evidence."""
    result = copy.deepcopy(heartbeat)
    normal = replay.decode_bundle(result).certificates[0]
    result["destination_latch"] = {
        "version": 1, "provenance": replay.LATCH_PROVENANCE, "rule": "V1",
        "certificate": {**result["certificates"][0], "header": dataclasses.replace(normal.parsed, timestamp_ms=normal.parsed.timestamp_ms + 1).encode().hex()},
    }
    return result


def test_latch_retains_original_and_explicit_malicious_bytes(latch_bundle: dict) -> None:
    before = copy.deepcopy(latch_bundle)
    decoded = replay.decode_bundle(latch_bundle)
    assert latch_bundle == before
    assert decoded.latch.qc == decoded.certificates[0].qc
    assert decoded.latch.signature == decoded.certificates[0].signature
    assert decoded.latch.header.hex() == latch_bundle["destination_latch"]["certificate"]["header"]
    assert decoded.latch.committee == decoded.keys
    assert replay.checkpoint_id(decoded.latch.header) != replay.checkpoint_id(decoded.certificates[0].header)


@pytest.mark.parametrize("key,value", [("version", True), ("version", 2), ("provenance", "chain_output"), ("rule", "V2")])
def test_latch_rejects_provenance_and_rule_aliases(latch_bundle: dict, key: str, value: object) -> None:
    latch_bundle["destination_latch"][key] = value
    with pytest.raises(ValueError):
        replay.decode_bundle(latch_bundle)


@pytest.mark.parametrize("field,value", [("generation", 8), ("height", 7), ("timestamp_ms", 1)])
def test_latch_rejects_other_header_changes(latch_bundle: dict, field: str, value: int) -> None:
    cert = replay.decode_bundle(latch_bundle).latch
    changed = dataclasses.replace(cert.parsed, **{field: getattr(cert.parsed, field) + value})
    latch_bundle["destination_latch"]["certificate"].update(header=changed.encode().hex(), height=changed.height)
    with pytest.raises(ValueError, match="only the deliberately"):
        replay.decode_bundle(latch_bundle)


def test_latch_rejects_qc_and_committee_changes(latch_bundle: dict) -> None:
    bad = copy.deepcopy(latch_bundle)
    row = bad["destination_latch"]["certificate"]
    row["committee"] = row["committee"][::-1]
    with pytest.raises(ValueError, match="ordered committee"):
        replay.decode_bundle(bad)
    cert = replay.decode_bundle(latch_bundle).latch
    bad = copy.deepcopy(latch_bundle)
    qc = bytearray(cert.qc); qc[80] ^= 1
    bad["destination_latch"]["certificate"]["qc"] = qc.hex()
    with pytest.raises(ValueError, match="original QC"):
        replay.decode_bundle(bad)


def test_latch_rejects_key_change_or_conflict_at_handoff(latch_bundle: dict, key_change: dict) -> None:
    key_change["destination_latch"] = latch_bundle["destination_latch"]
    with pytest.raises(ValueError, match="heartbeat keys"):
        replay.decode_bundle(key_change)
    decoded = replay.decode_bundle(latch_bundle)
    latch_bundle["certificates"][1]["header"] = dataclasses.replace(decoded.certificates[1].parsed, timestamp_ms=decoded.latch.parsed.timestamp_ms).encode().hex()
    with pytest.raises(ValueError, match="precede authentic handoff"):
        replay.decode_bundle(latch_bundle)


def test_latch_render_requires_persistent_exact_state_and_refusal(latch_bundle: dict) -> None:
    decoded = replay.decode_bundle(latch_bundle)
    rendered = replay.render_test(decoded, "c" * 64)
    assert rendered.count("get fun `test ") == 2
    assert decoded.latch.signature.hex() in rendered and decoded.latch.header[:109].hex() in rendered
    assert rendered.count("eventLatched(1,") == 1
    assert "expected.equivocated = true;" in rendered and "expectedCommittee.untilMs = 0;" in rendered
    assert rendered.count("minterStorage(env).toCell().hash()).toEqual(expected.toCell().hash())") == 2
    assert "expectOutcome(later, SccpErrors.Equivocated)" in rendered
    assert "toHaveSuccessfulTx<ReturnExcessesBack>" in rendered
    assert "liveNoMonetaryEffect(env, true)" in rendered
    assert "signCertificate(" not in rendered and "setMinterStorage(" not in rendered
    with pytest.raises(ValueError, match="labeled native test conflict"):
        replay.render_latch_test(dataclasses.replace(decoded, latch=None))


def test_heartbeat_requires_explicit_latch_certificate(heartbeat: dict) -> None:
    del heartbeat["destination_latch"]
    with pytest.raises(ValueError, match="heartbeat export requires"):
        replay.decode_bundle(heartbeat)
