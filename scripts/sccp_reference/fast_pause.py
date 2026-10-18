"""Independent SCCP fast-pause component model, with opaque Parliament authority inputs.

Draw order and eligibility are explicitly supplied facts, never a fabricated ballot.
The production producer remains unavailable until Parliament supplies those capabilities.
"""
from __future__ import annotations

from dataclasses import dataclass, field

HOLD_MS = 864_000_000
RENEW_LEAD_MS = 86_400_000


def seats(drawn: int, accepted: list[int], time: int, deadline: int, eligible: int, k: int = 9) -> list[int]:
    """Keep accepted originals; replace unaccepted seats primary-first at the deadline."""
    assert k in (5, 7, 9) and 2 * k <= drawn <= 3 * k
    owners, reserve = list(range(2 * k)), 2 * k
    for index in range(2 * k):
        if time < deadline or index in accepted:
            continue
        while reserve < drawn:
            candidate, reserve = reserve, reserve + 1
            if eligible & (1 << candidate) and candidate in accepted:
                owners[index] = candidate
                break
    return owners


def recheck(*, time: int = 8_000, closes: int = 9_000, eligible: int = (1 << 27) - 1,
            endorsers: list[int] | None = None, role: str = "Primary", panel_seq: int = 1,
            round_seq: int = 1, head: int = 0, round_head: int = 0,
            suspended_until: int = 0, panel_seats: int = 9) -> tuple[str, int]:
    """Re-evaluate current-state quorum after all earlier positioned enactments."""
    if head != round_head:
        return "HeadChanged", 0
    if time < suspended_until:
        return "Suspended", 0
    if time >= closes:
        return "Expired", 0
    if panel_seq != round_seq:
        return "PanelChanged", 0
    start = 0 if role == "Primary" else panel_seats
    count = sum(start <= index < start + panel_seats and eligible & (1 << index) != 0
                for index in (endorsers if endorsers is not None else list(range(6))))
    return ("Certified", count) if count >= (2 * panel_seats + 2) // 3 else ("InsufficientEligibleEndorsements", 0)


@dataclass
class Machine:
    """Effect-consumer state; synthetic inputs never authenticate a production operation."""
    activation: str = "Bidirectional"
    destination_parliament_paused: bool = False
    until: int = 0
    enacted_at: tuple[int, int] = (0, 0)
    taira_part: bool = False
    destination_part: bool = False
    head: int = 0
    rounds: int = 0
    nonce: int = 1
    suspended_until: int = 0
    snapshots: list[dict] = field(default_factory=list)

    def run(self, operation: dict) -> None:
        """Apply one explicit component input and retain its complete hold observation."""
        kind, time = operation["kind"], operation["time_ms"]
        if kind in ("parliament_pause", "parliament_resume"):
            pause = kind == "parliament_pause"
            if not pause and time < self.until:
                s0 = operation["s0"]
                if self.enacted_at < (s0["height"], s0["position"]):
                    for part in ("taira_part", "destination_part"):
                        if getattr(self, part):
                            setattr(self, part, False)
                            self.head += 1
                    if not self.taira_part and not self.destination_part:
                        self.until = 0
            if self.activation in ("Bidirectional", "Paused"):
                self.activation = "Paused" if pause else "Bidirectional"
            self.destination_parliament_paused = pause
            self.nonce += 1
        elif kind == "fast_enact":
            assert operation["round_opened_at_ms"] <= time < operation["round_closes_at_ms"]
            assert time >= self.suspended_until
            assert not self.until or time >= self.until - RENEW_LEAD_MS
            self.until = time + HOLD_MS
            self.enacted_at = operation["height"], operation["position"]
            self.taira_part = self.destination_part = True
            self.head += 1
            self.rounds = 0
            self.nonce += 1
        elif kind == "seed_rounds":
            self.rounds = 2
        elif kind == "suspend":
            self.suspended_until = time + operation["duration_ms"]
        elif kind != "observe":
            raise ValueError(kind)
        active_taira = self.taira_part and time < self.until
        active_destination = self.destination_part and time < self.until
        self.snapshots.append({
            "activation": self.activation,
            "destination_parliament_paused": self.destination_parliament_paused,
            "fast_until_ms": self.until,
            "fast_taira_held": active_taira,
            "fast_destination_held": active_destination,
            "taira_held": self.activation == "Paused" or active_taira,
            "destination_held": self.destination_parliament_paused or active_destination,
            "fast_hold_head": self.head,
            "rounds": self.rounds,
            "next_control_nonce": self.nonce,
            "suspended_until_ms": self.suspended_until,
        })
