"""Independent SCCP governance frames and compare-and-set heads (§4.14.3, §11.1).

The small encoder below implements the advertised Norito v1 layout from norito.md;
it does not call Rust or read a fixture. FastHold is automatic state, never a
Parliament action: it appears in head snapshots and in a refused extra base.
"""

from __future__ import annotations

import hashlib

from .common import U64_MAX, rep

GENERATOR = "scripts/sccp_reference/vectors_governance.py and crates/iroha_core/src/smartcontracts/isi/sccp/governance/reference_fixtures.rs"
NETWORK = rep(0x11)
SUBJECTS = {"route": 0, "route_control": 1, "light_client": 2, "parameters": 3,
            "forgery_hold": 5, "fast_hold": 6, "fast_pause_control": 7}
NETWORKS = {"ethereum-mainnet": 65, "bsc-mainnet": 66, "ton-mainnet": 68}
ACTION_TAGS = {"set_taira_paused": 7, "set_destination_paused": 8,
               "freeze_light_client": 11, "quarantine_revision": 16,
               "set_fast_pause_suspended": 18}
ACTION_SUBJECTS = dict(zip(ACTION_TAGS, ("route", "route_control", "light_client", "forgery_hold", "fast_pause_control")))


def le(value: int, width: int = 8) -> bytes:
    """Fixed little-endian unsigned integer."""
    return value.to_bytes(width, "little")


def fields(*values: bytes) -> bytes:
    """Norito record/tuple fields, each with its COMPACT_LEN byte length."""
    def length(n: int) -> bytes:
        out = bytearray()
        while n >= 128:
            out.append((n & 127) | 128)
            n >>= 7
        return bytes(out) + bytes([n])
    return b"".join(length(len(v)) + v for v in values)


def sequence(values: list[bytes]) -> bytes:
    """Norito sequence count followed by length-delimited elements."""
    return le(len(values)) + fields(*values)


def subject(kind: str, network: str | None = None) -> dict:
    """Labelled subject input, ordered by declaration and network tag."""
    return {"kind": kind, "network": network}


def subject_key(value: dict) -> tuple[int, int]:
    return SUBJECTS[value["kind"]], NETWORKS.get(value["network"], 0)


def subject_bytes(value: dict) -> bytes:
    tag = le(SUBJECTS[value["kind"]], 4)
    return tag if value["kind"] == "parameters" else tag + fields(le(NETWORKS[value["network"]], 4))


def fingerprint(domain: str, payload: bytes) -> bytes:
    domain = domain.encode("ascii")
    return hashlib.blake2b(le(len(domain)) + domain + payload, digest_size=32).digest()


def frame(payload: bytes) -> bytes:
    """Uncompressed, flags=2 Norito SccpGovernanceProposalV1 frame with CRC64-XZ."""
    crc = U64_MAX
    for byte in payload:
        crc ^= byte
        for _ in range(8):
            crc = (crc >> 1) ^ (0xC96C5795D7870F42 if crc & 1 else 0)
    schema = hashlib.sha256(b"norito:v1:type-name\0iroha_data_model::sccp::governance::SccpGovernanceProposalV1").digest()[:16]
    return b"NRT0\0\0" + schema + b"\0" + le(len(payload)) + le(crc ^ U64_MAX) + b"\x02" + payload


def action_bytes(action: dict) -> bytes:
    values = [le(NETWORKS[action["network"]], 4)]
    kind = action["kind"]
    if kind in ("quarantine_revision", "set_destination_paused"):
        values.append(le(action["revision"], 4))
    if kind in ("set_taira_paused", "set_destination_paused"):
        values.append(bytes([action["paused"]]))
    if kind == "set_fast_pause_suspended":
        values.append(le(action["duration_ms"]))
    return le(ACTION_TAGS[kind], 4) + fields(fields(*values))


def expected_head(subjects: list[dict], revisions: list[dict]) -> dict:
    current = {subject_key(row["subject"]): row["revision"] for row in revisions}
    heads = [{"subject": s, "revision": current.get(subject_key(s), 0)} for s in subjects]
    version = 1 + sum(row["revision"] for row in heads)
    if version > U64_MAX:
        return {"outcome": "VersionOverflow"}
    subject_preimage = le(2, 4) + fields(sequence([subject_bytes(s) for s in subjects]))
    head_preimage = sequence([fields(subject_bytes(row["subject"]), le(row["revision"])) for row in heads])
    return {"outcome": "Present", "subject_id": hx(fingerprint("iroha.governance.subject.id.v1", subject_preimage)),
            "version": version, "head_root": hx(fingerprint("iroha.governance.parliament.expected_head.root.v1", head_preimage)),
            "heads": heads}


def hx(value: bytes) -> str:
    return "0x" + value.hex()


def proposal_row(label: str, actions: list[dict], revisions: list[dict], *, stale=False, extra_fast_hold=False) -> dict:
    subjects = sorted({subject_key(subject(ACTION_SUBJECTS[a["kind"]], a["network"])):
                       subject(ACTION_SUBJECTS[a["kind"]], a["network"]) for a in actions}.values(), key=subject_key)
    current = {subject_key(row["subject"]): row["revision"] for row in revisions}
    base = [{"subject": s, "revision": current.get(subject_key(s), 0)} for s in subjects]
    if stale:
        base[0] = {**base[0], "revision": base[0]["revision"] + 1}
    if extra_fast_hold:
        base.append({"subject": subject("fast_hold", "ethereum-mainnet"), "revision": 0})
        base.sort(key=lambda r: subject_key(r["subject"]))
    payload = fields(NETWORK, sequence([fields(subject_bytes(r["subject"]), le(r["revision"])) for r in base]),
                     sequence([action_bytes(a) for a in actions]))
    # The variant field, wrapper struct field, and owned Box each prefix their payload.
    proposal_kind = le(2, 4) + fields(fields(fields(payload)))
    static = "BaseRevisionsMismatch" if extra_fast_hold else ("ExceedsJsonSafeInteger" if any(r["revision"] > 2**53 - 1 for r in base) else "Accepted")
    return {"label": label, "input": {"network_id": hx(NETWORK), "actions": actions, "base_revisions": base,
                                       "revision_map": revisions},
            "expected": {"frame": hx(frame(payload)), "proposal_id": hx(fingerprint("iroha.governance.proposal.sccp_route_governance.v1", proposal_kind)),
                         "effect_hash": hx(fingerprint("iroha.governance.effect_preimage.v1", proposal_kind)),
                         "subjects": subjects, "head": expected_head(subjects, revisions),
                         "static_outcome": static,
                         "attempt_outcome": "NotAttempted" if static != "Accepted" else ("Stale" if stale else "Accepted")}}


def build() -> dict:
    all_subjects = [subject(kind, network) for kind in SUBJECTS for network in
                    ([None] if kind == "parameters" else NETWORKS)]
    revisions = [{"subject": s, "revision": i + 1} for i, s in enumerate(all_subjects)]
    pause = {"kind": "set_taira_paused", "network": "ethereum-mainnet", "paused": True}
    control = {"kind": "set_destination_paused", "network": "ethereum-mainnet", "revision": 1, "paused": False}
    hold = {"kind": "quarantine_revision", "network": "bsc-mainnet", "revision": 2}
    suspend = {"kind": "set_fast_pause_suspended", "network": "ton-mainnet", "duration_ms": 60000}
    freeze = {"kind": "freeze_light_client", "network": "bsc-mainnet"}
    rows = [proposal_row("absent_route_head", [pause], []),
            proposal_row("fixed_route_head", [pause], revisions),
            proposal_row("different_effect_same_subject", [{**pause, "paused": False}], revisions),
            proposal_row("control_head", [control], revisions),
            proposal_row("forgery_hold_head", [hold], revisions),
            proposal_row("fast_pause_control_head", [suspend], revisions),
            proposal_row("sorted_deduplicated_subjects", [suspend, control, hold, pause, freeze, pause], revisions),
            proposal_row("stale_base_revision", [pause], revisions, stale=True),
            proposal_row("fast_hold_is_not_a_parliament_action", [pause], revisions, extra_fast_hold=True),
            proposal_row("head_version_overflow", [pause], [{"subject": subject("route", "ethereum-mainnet"), "revision": U64_MAX}])]
    snapshot = expected_head(all_subjects, revisions)
    del snapshot["subject_id"]  # No Parliament action can own the automatic FastHold subject.
    return {"schema": "iroha.sccp.governance.v1", "generator": GENERATOR,
            "conventions": {"encoding": "Norito v1, uncompressed, COMPACT_LEN field lengths, flags 2; hex is 0x-prefixed.",
                            "authority": "Proposal/head computation does not authenticate a ballot or enact an effect. Both launch gates remain false.",
                            "fast_hold": "FastHold is automatic state; it has head snapshots but no Parliament action. An extra FastHold base revision is refused."},
            "constants": {"network_id": hx(NETWORK), "revision_map": revisions},
            "subject_encodings": [{"subject": s, "bytes": hx(subject_bytes(s))} for s in all_subjects],
            "head_snapshots": [{"label": "all_subjects_including_automatic_fast_hold", "subjects": all_subjects,
                                "expected": snapshot}], "rows": rows}
