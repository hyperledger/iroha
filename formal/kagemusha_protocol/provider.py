"""Finite Advance publication model; no cryptography or native execution authority.

Two competing opaque capsules target one old head. Capsule and receipt numbers
are names of exact byte strings, not data from which missing originals may be
reconstructed. ``winner``, ``sealed`` and ``observed`` include ghost history used
by the assertions; only retained copies may satisfy a retry.
"""
from collections import deque
from dataclasses import dataclass, replace
from enum import Enum
import sys

if sys.flags.optimize:
    raise RuntimeError("provider model requires unoptimized Python; assertions are gates")


class Fault(Enum):
    """Deliberately incorrect rules, each requiring a reachable counterexample."""

    NONE = "none"
    RESELECT = "reselect"
    EARLY_RELEASE = "early_release"
    UNAVAILABLE_AS_ABSENT = "unavailable_as_absent"
    FRESH_RETRY = "fresh_retry"
    REGENERATE_LOST = "regenerate_lost"
    FOREIGN_RECEIPT = "foreign_receipt"
    SELECTED_AS_NOT_PERFORMED = "selected_as_not_performed"


@dataclass(frozen=True, slots=True)
class State:
    """Durable marker/copies, temporary signing state and observer history."""

    marker: str = "old"
    staged: int | None = None
    winner: int | None = None
    capsule_copies: int = 0
    temporary_receipt: tuple[int, int] | None = None
    retained_receipt: tuple[int, int] | None = None
    completion_copies: int = 0
    sealed: tuple[int, int] | None = None
    observed: tuple[int, int] | None = None
    storage_available: bool = True
    signer_available: bool = True


@dataclass(frozen=True, slots=True)
class Edge:
    """One atomic abstract action and its optional API observation."""

    name: str
    after: State
    reply: str | tuple[int, int] | None = None


def status(state: State, fault: Fault = Fault.NONE):
    """Read without inventing custody from an unavailable or absent original."""
    if not state.storage_available:
        return "old_head_usable" if fault == Fault.UNAVAILABLE_AS_ABSENT else "unavailable"
    if state.marker == "old":
        return "old_head_usable"
    if state.marker == "selected":
        if fault == Fault.SELECTED_AS_NOT_PERFORMED:
            return "not_performed"
        return "pending" if state.capsule_copies else "custody_loss"
    if not state.completion_copies:
        return state.sealed if fault == Fault.REGENERATE_LOST else "delivery_data_loss"
    if fault == Fault.FRESH_RETRY:
        return (state.winner, 1 - state.retained_receipt[1])
    return state.retained_receipt


def edges(state: State, fault: Fault = Fault.NONE):
    """Enumerate crashes, uncertainty, custody loss, retries and both contenders.

    Publication is atomic at the model boundary: an uncertain acknowledgement
    can accompany either an unchanged old marker or the exact Selected marker.
    It never grants a capability to assume the old outcome.
    """
    yield Edge("storage_availability", replace(state, storage_available=not state.storage_available))
    yield Edge("signer_availability", replace(state, signer_available=not state.signer_available))
    # Power loss drops temporary work, never rolls back an authoritative marker.
    yield Edge("crash", replace(state, staged=None, temporary_receipt=None,
                                capsule_copies=0 if state.marker == "old" else state.capsule_copies))
    reply = status(state, fault)
    observed = reply if isinstance(reply, tuple) else state.observed
    yield Edge("observe", replace(state, observed=observed), reply)

    # Explicit total-erasure controls are outside ordinary crash durability.
    # They must remain losses, not replacement-wallet or package authorities.
    if state.capsule_copies:
        yield Edge("lose_capsule_copy", replace(state, capsule_copies=state.capsule_copies - 1))
    if state.completion_copies:
        left = state.completion_copies - 1
        yield Edge("lose_completion_copy", replace(state, completion_copies=left,
                                                   retained_receipt=state.retained_receipt if left else None))
    if not state.storage_available:
        return
    if state.marker == "old":
        for capsule in (0, 1):
            yield Edge(f"stage_{capsule}", replace(state, staged=capsule, capsule_copies=2))
        if state.staged is not None:
            # The native owner revalidates staged durable originals before selection.
            yield Edge("discard", replace(state, staged=None, capsule_copies=0), "not_performed")
            yield Edge("publication_not_selected", replace(state, staged=None, capsule_copies=0), "not_performed")
            if state.capsule_copies == 2:
                selected = replace(state, marker="selected", winner=state.staged, staged=None)
                yield Edge("select", selected, "pending")
                yield Edge("select_uncertain", selected, "pending")
        return

    if fault == Fault.RESELECT and state.marker == "selected":
        yield Edge("fault_reselect", replace(state, winner=1 - state.winner, capsule_copies=2))
    if state.capsule_copies == 1:
        yield Edge("repair_capsule", replace(state, capsule_copies=2))
    if state.completion_copies == 1:
        yield Edge("repair_completion", replace(state, completion_copies=2))
    if state.marker != "selected" or not state.capsule_copies:
        return
    if state.signer_available and state.completion_copies == 0 and state.temporary_receipt is None:
        for nonce in (0, 1):
            capsule = 1 - state.winner if fault == Fault.FOREIGN_RECEIPT else state.winner
            yield Edge(f"sign_{nonce}", replace(state, temporary_receipt=(capsule, nonce)))
    if state.temporary_receipt is not None and state.completion_copies == 0:
        yield Edge("persist_completion", replace(state, retained_receipt=state.temporary_receipt,
                                                  temporary_receipt=None, completion_copies=1))
    if state.completion_copies == 2 or (fault == Fault.EARLY_RELEASE and state.completion_copies == 1):
        yield Edge("publish_released", replace(state, marker="released", sealed=state.retained_receipt))


def invariant(state: State):
    """Check exact-byte ownership and publication shape in one abstract state."""
    assert state.marker in ("old", "selected", "released"), "marker kind"
    assert state.capsule_copies in (0, 1, 2), "capsule copy bound"
    assert state.completion_copies in (0, 1, 2), "completion copy bound"
    assert (state.retained_receipt is not None) == bool(state.completion_copies), "retained original extent"
    if state.marker == "old":
        assert state.winner is None and state.sealed is None, "old head after selection"
        assert not state.completion_copies and state.temporary_receipt is None, "receipt before selection"
    else:
        assert state.winner in (0, 1) and state.staged is None, "one selected capsule"
    for receipt in (state.temporary_receipt, state.retained_receipt, state.sealed, state.observed):
        if receipt is not None:
            assert receipt[0] == state.winner and receipt[1] in (0, 1), "foreign receipt"
    if state.marker == "released":
        assert state.sealed is not None and state.temporary_receipt is None, "released receipt authority"
        if state.completion_copies:
            assert state.retained_receipt == state.sealed, "changed released original"
    else:
        assert state.sealed is None and state.observed is None, "output before release"
    if state.observed is not None:
        assert state.observed == state.sealed, "changed delivered bytes"


def transition_invariant(before: State, edge: Edge):
    """History-sensitive assertions: irreversibility, release durability and replay."""
    after = edge.after
    invariant(before)
    invariant(after)
    if before.winner is not None:
        assert after.winner == before.winner and after.marker != "old", "selected head replaced"
    if before.sealed is not None:
        assert after.sealed == before.sealed and after.marker == "released", "released head replaced"
    if before.observed is not None:
        assert after.observed == before.observed, "retry changed delivered bytes"
    if edge.name == "publish_released":
        assert before.completion_copies == 2 and before.capsule_copies > 0, "release before redundant durability"
    if edge.name == "observe":
        assert edge.reply == status(before), "invalid custody observation"
    if edge.reply == "not_performed":
        assert before.winner is None and after.winner is None, "selected operation reported not performed"
    if isinstance(edge.reply, tuple):
        assert before.storage_available and before.marker == "released", "release before marker"
        assert before.completion_copies > 0, "regenerated missing output"
        assert edge.reply == before.retained_receipt == before.sealed, "retry not exact retained bytes"


def explore(fault: Fault = Fault.NONE, *, state_limit: int = 10000):
    """Exhaust the finite graph, retaining a shortest violating trace for mutants.

    A limit hit is an error, never a successful bounded result. Returns the
    actual state/edge counts and maximum shortest-path depth, or a violation.
    """
    if not isinstance(fault, Fault):
        raise ValueError("explicit model fault required")
    if type(state_limit) is not int or state_limit <= 0:
        raise ValueError("positive finite state limit required")
    initial = State()
    queue = deque([initial])
    traces = {initial: ()}
    transitions = 0
    depth = 0
    while queue:
        before = queue.popleft()
        trace = traces[before]
        depth = max(depth, len(trace))
        for edge in edges(before, fault):
            transitions += 1
            try:
                transition_invariant(before, edge)
            except AssertionError as error:
                return {"exhausted": False, "states": len(traces), "edges": transitions,
                        "violation": str(error), "trace": trace + (edge.name,)}
            if edge.after not in traces:
                if len(traces) >= state_limit:
                    raise RuntimeError("state limit reached before graph exhaustion")
                traces[edge.after] = trace + (edge.name,)
                queue.append(edge.after)
    return {"exhausted": True, "states": len(traces), "edges": transitions,
            "maximum_shortest_path": depth, "violation": None, "trace": ()}


if __name__ == "__main__":
    import json
    results = {fault.value: explore(fault) for fault in Fault}
    if not results[Fault.NONE.value]["exhausted"] or any(
            results[fault.value]["violation"] is None for fault in Fault if fault != Fault.NONE):
        raise SystemExit("baseline violation or surviving mutation")
    print(json.dumps({"scope": "one-head provider abstraction; not protocol/phone qualification",
                      "results": results}, indent=2, sort_keys=True))
