"""Two-generator fast-pause fixture: Core consumers and independent Python state machine."""
from __future__ import annotations

from .common import MAX_FAST_PAUSE_MS, hx, rep
from .fast_pause import HOLD_MS, RENEW_LEAD_MS, Machine, recheck, seats
from .destination import clamped_fast_pause
from .merkle import control_leaf, control_leaf_preimage
from .payload import ETHEREUM, TON

T0 = 8_000
DESTINATION_T0 = 1_800_000_000_000
ALL = (1 << 27) - 1
GENERATOR = "Independent Python scripts/sccp_reference/vectors_fast_pause.py and Rust iroha_core fast_pause::certification::reference_fixtures write this file byte for byte."
BOUNDARY = "Component inputs only: Parliament authenticates certificate_id, effect_hash and casting-open s0; panel draw order and eligibility masks are supplied DATA. No genuine ballot, citizen draw or eligibility capability is fabricated; production launch gates remain false."


def anchor(height: int, position: int) -> dict:
    return {"height": height, "position": position, "timestamp_ms": 1_000}


def op(kind: str, time: int = T0, **kw) -> dict:
    result = {"kind": kind, "time_ms": time, **kw}
    if kind.startswith("parliament_") or kind == "suspend":
        result.update(certificate_id=hx(rep(0x43)), effect_hash=hx(rep(0x45)))
        result.setdefault("s0", anchor(1, 0))
    return result


def fast(time: int = T0, height: int = 2, position: int = 5, role: str = "Primary") -> dict:
    return op("fast_enact", time, height=height, position=position, role=role, round_opened_at_ms=time, round_closes_at_ms=time + 1_800_000)


def state_rows() -> list[dict]:
    until = T0 + HOLD_MS
    renewal = until - RENEW_LEAD_MS
    cases = [
        ("parliament_pause_fast_pause_lapse", "A Parliament pause survives a later fast pause and its blockless expiry.", "Bidirectional", [op("parliament_pause"), fast(), op("observe", until)]),
        ("certify_before_parliament_pause", "A round certified against the unchanged FastHold head before Parliament pauses is enacted afterward; lapse preserves Parliament's pause.", "Bidirectional", [op("seed_rounds"), op("parliament_pause"), fast(), op("observe", until)]),
        ("lift_after_enactment", "Authenticated s0 after the fast enactment clears both parts; timestamp is not an ordering substitute.", "Bidirectional", [fast(), op("parliament_resume", s0=anchor(2, 6))]),
        ("lift_before_enactment", "Authenticated s0 before the fast enactment retains both parts.", "Bidirectional", [fast(), op("parliament_resume", s0=anchor(1, 99))]),
        ("same_block_open_2_enact_5", "A ballot opened at position 2 cannot lift a pause enacted at position 5 of that same block.", "Bidirectional", [fast(), op("parliament_resume", s0=anchor(2, 2))]),
        ("older_resume_keeps_settlement_held", "Parliament pauses, a resume ballot opens, fast pause enacts, and that older resume leaves the Taira part holding settlement.", "Bidirectional", [op("parliament_pause"), fast(), op("parliament_resume", s0=anchor(2, 2))]),
        ("inbound_only_settlement_and_refunds_held", "The common Taira hold predicate holds settlement and refunds even for InboundOnly.", "InboundOnly", [fast()]),
        ("renew_at_lead_then_old_lift", "A renewal opens exactly at until minus renew lead and enacts before lapse; an s0 between enactments cannot lift the renewed hold.", "Bidirectional", [fast(), fast(renewal, 3, 5), op("parliament_resume", renewal, s0=anchor(2, 6))]),
        ("backup_decides_deletes_both_rounds", "Three primary members remain silent; a quorate backup effect deletes both panel rounds.", "Bidirectional", [op("seed_rounds"), fast(role="Backup")]),
        ("suspension_counts_from_enactment", "Authenticated suspension duration starts at its own enactment and preserves existing pause parts.", "Bidirectional", [fast(), op("suspend", T0 + 1_000, duration_ms=30_000)]),
    ]
    rows = []
    for name, description, activation, operations in cases:
        model = Machine(activation=activation)
        for operation in operations:
            model.run(operation)
        rows.append({"id": name, "category": "state", "description": description,
                     "inputs": {"activation": activation, "panel_seats": 5 if name == "backup_decides_deletes_both_rounds" else 9, "operations": operations},
                     "expected": {"snapshots": model.snapshots}})
    return rows


def build() -> dict:
    rows = state_rows()
    certification = [
        ("quorum_next_block_after_close", "Quorum is insufficient once the first post-halt block is at or after closes_at_ms.", {"time": 9_001}),
        ("endorser_suspended_earlier_same_pass", "An eligibility observation after an earlier Parliament suspension no longer counts that citizen.", {"eligible": ALL & ~1}),
        ("fast_pause_suspended_earlier_same_pass", "An earlier authenticated SetFastPauseSuspended enactment makes this round NoResult.", {"suspended_until": 38_000}),
        ("new_draw_between_quorum_and_certification", "A replacement draw invalidates the original panel sequence.", {"panel_seq": 2}),
        ("stale_fast_hold_head", "An endorsement of the previous FastHold head cannot certify after another enactment.", {"head": 1}),
        ("primary_three_silent", "Three silent primary members of a five-seat panel leave fewer than the four required endorsements.", {"panel_seats": 5, "endorsers": [0, 1]}),
        ("backup_quorum", "Four backup members of a five-seat panel independently reach quorum while three primaries are silent.", {"panel_seats": 5, "endorsers": [5, 6, 7, 8], "role": "Backup"}),
    ]
    for name, description, overrides in certification:
        inputs = dict(time=8_000, closes=9_000, eligible=ALL, endorsers=list(range(6)), role="Primary", panel_seq=1, round_seq=1, head=0, round_head=0, suspended_until=0, panel_seats=9)
        inputs.update(overrides)
        outcome, count = recheck(**inputs)
        rows.append({"id": name, "category": "certification", "description": description, "inputs": inputs,
                     "expected": {"outcome": outcome, "endorsement_count": count}})
    for name, time, accepted, eligible, member in [
        ("seat_replacement_at_deadline", 2_000, [1, 9, 18, 19, 20, 21, 22, 23, 24, 25, 26], ALL & ~(1 << 19), 18),
        ("reserve_exhaustion", 2_000, [18], ALL, 18),
        ("reserve_premature_endorsement", 1_999, [18], ALL, 18),
    ]:
        owners = seats(27, accepted, time, 2_000, eligible)
        rows.append({"id": name, "category": "seats", "description": "Original draw indices are identities; replacement consumes accepted eligible reserves once, primary then backup.",
                     "inputs": {"drawn_count": 27, "accepted": accepted, "time_ms": time, "accept_until_ms": 2_000, "eligible": eligible, "member": member},
                     "expected": {"owners": owners, "primary_member_counts": member in owners[:9] and bool(eligible & (1 << member))}})
    for name, member, existing, expected in [
        ("non_member_endorsement", 27, [], "NotEligibleSeat"),
        ("duplicate_endorsement", 0, [0], "DuplicateEndorsement"),
        ("member_first_endorsement", 0, [], "Accepted"),
    ]:
        outcome = "NotEligibleSeat" if member >= 9 else "DuplicateEndorsement" if member in existing else "Accepted"
        assert outcome == expected
        rows.append({"id": name, "category": "endorsement", "description": "Member and duplicate checks consume a previously authenticated eligibility observation; no observation is synthesized in production.",
                     "inputs": {"member": member, "existing_endorsers": existing}, "expected": {"outcome": outcome}})
    for offset in (-1, 0):
        time = T0 + HOLD_MS - RENEW_LEAD_MS + offset
        outcome = "RenewalWindowClosed" if time < T0 + HOLD_MS - RENEW_LEAD_MS else "Ready"
        rows.append({"id": "renewal_boundary_before" if offset < 0 else "renewal_boundary_at", "category": "renewal", "description": "Renewal opens at the exact lead boundary, with no empty block required.",
                     "inputs": {"time_ms": time, "until_ms": T0 + HOLD_MS}, "expected": {"outcome": outcome}})
    rows.append({"id": "parliament_authority_unavailable", "category": "boundary", "description": "Current public draw and eligibility producers refuse; seeded component facts confer no authority.", "inputs": {"panel_seq": 1}, "expected": {"draw_available": False, "eligibility_available": False, "binding_ballot_available": False}})
    controls = []
    for target, destination in [(ETHEREUM, bytes(12) + bytes([0x22]) * 20), (TON, rep(0x35))]:
        for name, paused, until, previous in [("late_track2", 0, DESTINATION_T0 - 1_000, 0), ("max_fast_pause_clamp", 0, DESTINATION_T0 + MAX_FAST_PAUSE_MS + 1_000, 0), ("parliament_survives_expiry", 1, DESTINATION_T0 - 1_000, 0), ("stale_control_nonce", 0, DESTINATION_T0 + 30_000, 1)]:
            fields = dict(route_revision=1, control_nonce=1, track=2, parliament_paused=paused, fast_pause_until_ms=until, certificate_id=rep(0x55), effect_hash=rep(0x66))
            args = (rep(0x11), target, destination, fields["route_revision"], fields["control_nonce"], fields["track"], fields["parliament_paused"], fields["fast_pause_until_ms"], fields["certificate_id"], fields["effect_hash"])
            expiry = clamped_fast_pause(until, DESTINATION_T0)
            controls.append({"id": target.name + "_" + name, "network": target.name, "network_id": hx(rep(0x11)), "destination_word": hx(destination), "now_ms": DESTINATION_T0, "previous_control_nonce": previous,
                             "fields": {k: hx(v) if isinstance(v, bytes) else v for k, v in fields.items()},
                             "leaf": hx(control_leaf(*args)), "preimage": hx(control_leaf_preimage(*args)),
                             "expected": {"outcome": "StaleControl" if previous else "Applied", "applied_until_ms": expiry, "minting_paused": bool(paused) or DESTINATION_T0 < expiry}})
    return {"schema": "iroha.sccp.fast_pause.v1", "generator": GENERATOR, "conventions": {"authority_boundary": BOUNDARY, "indices": "Zero-based original draw indices; panel_seats is 5 or 9, with equally sized primary, backup and reserve partitions.", "clock": "Taira inputs are milliseconds; destination now_ms is a whole second times 1000."},
            "constants": {"t0_ms": T0, "destination_t0_ms": DESTINATION_T0, "hold_ms": HOLD_MS, "renew_lead_ms": RENEW_LEAD_MS, "panel_seats": 9, "panel_quorum": 6, "max_fast_pause_ms": MAX_FAST_PAUSE_MS}, "rows": rows, "controls": controls}
