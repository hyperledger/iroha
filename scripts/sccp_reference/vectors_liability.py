"""Independent SCCP liability-clock, L3/L5, pruning and P2 fixture models.

Python 3.11+, no dependencies, downloads or environment variables. ``build()``
is consumed by ``generate.py`` and models committed inputs, not authority.
"""
from __future__ import annotations
from .common import U64_MAX

GENERATOR = "two independent generators: python3.11 scripts/sccp_reference/generate.py --write; cargo test -p iroha_core --lib sccp -- --ignored regenerate_liability_v1"
CONVENTION = "Times are integer milliseconds; every liability boundary is inclusive. DATA fixtures call production clock, L3, L5, pruning and P2 predicates without opening either route launch gate or manufacturing Parliament authority."
HEARTBEAT = 86_400_000
SLACK = 3_600_000
VALIDITY = 1_209_600_000
GRACE = 604_800_000
CAP = 2_592_000_000
START = 1_000
UNTIL = START + VALIDITY + GRACE


def next_clock(parent_lc: int, parent_time: int, time: int, heartbeat_ms: int) -> int:
    """S0 limits elapsed time consumed by a resumed block and saturates u64."""
    return min(U64_MAX, parent_lc + min(max(0, time - parent_time), min(U64_MAX, heartbeat_ms + SLACK)))


def liable(generation: int, current_generation: int, lc: int, liable_until_lc: int,
           grace_ms: int, progress_cap_ms: int, dest_cleared_lc: int | None) -> bool:
    """The exact inclusive time, destination-progress and current-generation legs."""
    progress_end = min(U64_MAX, liable_until_lc + progress_cap_ms) if dest_cleared_lc is None else min(U64_MAX, dest_cleared_lc + grace_ms)
    return generation == current_generation or lc <= liable_until_lc or lc <= progress_end


def build() -> dict:
    """Generate every required liability row from the independent predicates."""
    clock = []
    lc, parent = 1_000, 1_000
    for label, now in (("ordinary_step", 2_000), ("halt_no_committed_block", 2_000),
                       ("first_block_after_halt", 2_000 + 30 * 86_400_000),
                       ("second_resumed_block", 3_000 + 30 * 86_400_000)):
        out = next_clock(lc, parent, now, HEARTBEAT)
        clock.append(dict(label=label, input=dict(parent_lc=lc, parent_time=parent, time=now, heartbeat_ms=HEARTBEAT), expected=dict(lc=out)))
        lc, parent = out, now
    clock.append(dict(label="saturating_clock", input=dict(parent_lc=U64_MAX-2, parent_time=0, time=100, heartbeat_ms=HEARTBEAT), expected=dict(lc=U64_MAX)))
    liability = []
    for label, current, at, cleared in (
        ("time_leg_before", 8, UNTIL-1, START), ("time_leg_inclusive", 8, UNTIL, START),
        ("time_leg_ended", 8, UNTIL+1, START), ("progress_leg", 8, UNTIL+1, None),
        ("progress_clearance_inclusive", 8, UNTIL+GRACE, UNTIL),
        ("progress_clearance_ended", 8, UNTIL+GRACE+1, UNTIL),
        ("cap_inclusive", 8, UNTIL+CAP, None), ("cap_ended", 8, UNTIL+CAP+1, None),
        ("current_generation_never_expires", 7, U64_MAX, None),
    ):
        inp=dict(generation=7, current_generation=current, lc=at, liable_until_lc=UNTIL,
                 grace_ms=GRACE, progress_cap_ms=CAP, dest_cleared_lc=cleared)
        liability.append(dict(label=label, input=inp, expected=dict(liable=liable(**inp))))
    clearance=[]
    deadline=START+VALIDITY
    for label, present, frozen, source in (
        ("l5_missing_light_client",False,False,0), ("l5_stalled_light_client",True,False,deadline-1),
        ("l5_at_deadline",True,False,deadline), ("l5_past_deadline",True,False,deadline+1),
        ("l5_frozen_light_client",True,True,deadline+1),
    ):
        clear=present and not frozen and source>deadline
        clearance.append(dict(label=label,input=dict(deadline_ms=deadline,lc=UNTIL,light_client_present=present,
                                                    light_client_frozen=frozen,source_time_ms=source),
                              expected=dict(dest_cleared_lc=UNTIL if clear else None)))
    orders=[]
    for label, steps in (("evidence_then_unbond",("evidence","unbond")), ("unbond_then_evidence",("unbond","evidence"))):
        pending=False
        outcomes=[]
        for step in steps:
            if step=="evidence":
                pending=True
                outcomes.append("Pending")
            else:
                outcomes.append("LiabilityActive")
        orders.append(dict(label=label,input=dict(lc=UNTIL,liable_until_lc=UNTIL,steps=list(steps)),expected=dict(outcomes=outcomes,stake_released=False,penalty_pending=pending)))
    pruning=[]
    for label,pending in (("pending_generation_is_skipped",True),("applied_generation_can_retire",False)):
        pruning.append(dict(label=label,input=dict(current_generation=20,lc=U64_MAX,retained_generations=[7,9,20],pending_generation=7 if pending else None),
                            expected=dict(retained_generations=[7,20] if pending else [20],pruned_generations=[9] if pending else [7,9])))
    pins=[]
    threshold=200_000_000+HEARTBEAT+86_400_000
    for label, successor in (("p2_validity_reduction_refused",threshold-1),("p2_intervening_boundary",threshold),("p2_all_generations_live",threshold+1)):
        deadlines=[START+VALIDITY,successor]
        pins.append(dict(label=label,input=dict(now_ms=200_000_000,heartbeat_ms=HEARTBEAT,pin_margin_ms=86_400_000,deadlines_ms=deadlines),
                         expected=dict(required_until_ms=threshold,outcome="Accepted" if min(deadlines)>=threshold else "InterveningGenerationExpired")))
    return dict(schema="iroha.sccp.liability.v1",generator=GENERATOR,conventions=CONVENTION,
                constants=dict(heartbeat_ms=HEARTBEAT,lc_slack_ms=SLACK,start_lc=START,validity_ms=VALIDITY,
                               grace_ms=GRACE,progress_cap_ms=CAP,liable_until_lc=UNTIL),
                clock=clock,liability=liability,destination_clearance=clearance,same_block_orders=orders,pruning=pruning,pin_margin=pins)
