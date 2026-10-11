"""Bounded composition of one Send publication and conditional accounting.

Two already validated Send capsules compete for one funded, folded payer head.
Selection creates an irreversible liability projection, even before its signature
is available. That projection is not a delivered Payment or spend capability.
Only the provider's released original can populate delivery custody. Receive and
its fold use the accounting model's durable-operation premises; their own provider
instances, cryptography, filesystem refinement and arbitrary histories are TODOs.
"""
from collections import deque
from dataclasses import dataclass, replace
from enum import Enum
import sys

import accounting as money
import provider

if sys.flags.optimize:
    raise RuntimeError("publication accounting requires unoptimized Python; assertions are gates")


class Fault(Enum):
    """Incorrect composition rules, distinct from the provider's own mutations."""

    NONE = "none"
    REFUND_UNCERTAIN = "refund_uncertain"
    EARLY_PAYMENT = "early_payment"
    RETRY_DEBIT = "retry_debit"
    RESTORE_FROM_GHOST = "restore_from_ghost"


def funded_world():
    """Start after an authentic three-unit Load and its completed local fold."""
    world = money.issue_load(money.initial(3, 0), 0, 3)
    return money.fold(money.absorb_load(world, 0), 0)


@dataclass(frozen=True, slots=True)
class State:
    """Provider state, projected liabilities, exact carrier and first-credit names."""

    publication: provider.State
    world: money.World
    carrier: tuple[int, int] | None = None
    received: tuple[int, int] | None = None


@dataclass(frozen=True, slots=True)
class Edge:
    """One provider, carrier, Receive or fold transition."""

    name: str
    after: State
    publication: provider.Edge | None = None


def initial():
    """Create the exact finite composition initial state."""
    return State(provider.State(), funded_world())


def retained_payment(world, retained):
    """Reflect payer original custody without changing value or carrier custody."""
    if not world.payments:
        return world
    return replace(world, payments=money.changed(
        world.payments, 0, replace(world.payments[0], retained=retained)))


def edges(state, fault=Fault.NONE):
    """Compose every provider transition with one selected Send liability.

The provider's ``sealed`` and this model's ``received`` are ghost identities:
neither can restore lost bytes. Receiver replay uses its permanent first credit;
it does not require rereading a lost payer or carrier original.
"""
    if not isinstance(fault, Fault):
        raise ValueError("explicit composition fault required")
    before = state.publication
    for event in provider.edges(before):
        after = event.after
        world = state.world
        if before.winner is None and after.winner is not None:
            world = money.send(world, 0, 1, after.winner + 1)
            if fault == Fault.REFUND_UNCERTAIN and event.name == "select_uncertain":
                world = state.world
        available = after.marker == "released" and after.completion_copies > 0
        if fault == Fault.EARLY_PAYMENT and after.temporary_receipt is not None:
            available = True
        if (fault == Fault.RESTORE_FROM_GHOST and after.sealed is not None
                and not after.completion_copies):
            available = True
        world = retained_payment(world, available)
        if fault == Fault.RETRY_DEBIT and isinstance(event.reply, tuple):
            try:
                world = money.send(money.fold(world, 0), 0, 1, after.winner + 1)
            except money.Rejected:
                pass
        yield Edge("provider/" + event.name,
                   replace(state, publication=after, world=world), event)

    reply = provider.status(before)
    if isinstance(reply, tuple):
        # Reading the original, rather than knowing its ghost name, authorizes
        # copying. In particular unavailable storage cannot satisfy this branch.
        world = money.copy_for_delivery(state.world, 0)
        yield Edge("deliver", replace(state, world=world, carrier=reply))
    if state.carrier is not None:
        payment = replace(state.world.payments[0], carrier_copy=False)
        world = replace(state.world, payments=money.changed(state.world.payments, 0, payment))
        yield Edge("lose_carrier", replace(state, world=world, carrier=None))
    if state.carrier is not None or state.received is not None:
        for variant in (0, 1):
            try:
                world = money.receive(state.world, 1, 0, variant=variant)
            except money.Rejected:
                continue
            original = state.received if state.received is not None else state.carrier
            yield Edge("receive_" + str(variant), replace(state, world=world, received=original))
    yield Edge("fold_receiver", replace(state, world=money.fold(state.world, 1)))


def invariant(state):
    """Check conservation and the exact link from selected Send to delivered credit."""
    p, world = state.publication, state.world
    provider.invariant(p)
    money.invariant(world)
    if p.winner is None:
        assert world == funded_world(), "unselected monetary effect"
        assert state.carrier is None and state.received is None, "unselected delivery"
        return
    assert len(world.payments) == 1, "one selected Send must have exactly one debit"
    payment, = world.payments
    assert (payment.sender, payment.receiver, payment.ordinal, payment.amount, payment.fee) == (
        0, 1, 0, p.winner + 1, 0), "selected capsule terms"
    assert world.wallets[0].balance == 3 - payment.amount, "selected debit refunded"
    assert world.wallets[0].sequence == 2 and world.wallets[0].next_send == 1, "selected head advanced again"
    assert payment.retained == (p.marker == "released" and p.completion_copies > 0), "payer original custody"
    assert payment.carrier_copy == (state.carrier is not None), "carrier original custody"
    for original in (state.carrier, state.received):
        if original is not None:
            assert p.marker == "released" and original == p.sealed, "foreign or early delivered original"
    assert bool(world.wallets[1].credits) == (state.received is not None), "first-credit original"
    assert len(world.wallets[1].credits) <= 1, "duplicate credit"
    assert not world.claims and world.reserve == 3, "composition vocabulary"


def transition_invariant(before, edge):
    """Check provider safety and cross-component custody/history implications."""
    invariant(before)
    after = edge.after
    if edge.publication is not None:
        provider.transition_invariant(before.publication, edge.publication)
        assert edge.publication.after == after.publication, "provider transition mismatch"
    else:
        assert before.publication == after.publication, "monetary action changed provider"
    invariant(after)
    if before.publication.winner is not None:
        assert after.world.wallets[0] == before.world.wallets[0], "retry changed payer debit"
    if before.received is not None:
        assert after.received == before.received, "retry changed first original"
        assert after.world.wallets[1].credits == before.world.wallets[1].credits, "retry credited twice"
    if edge.name == "deliver":
        assert isinstance(provider.status(before.publication), tuple), "delivery without readable original"
    if edge.name.startswith("receive_") and before.received is None:
        assert before.carrier is not None, "new credit without delivery bytes"


def explore(fault=Fault.NONE, *, state_limit=100000):
    """Exhaust this bounded product or return a shortest invariant counterexample."""
    if not isinstance(fault, Fault):
        raise ValueError("explicit composition fault required")
    if type(state_limit) is not int or state_limit <= 0:
        raise ValueError("positive finite state limit required")
    start = initial()
    traces = {start: ()}
    queue = deque([start])
    transitions, depth = 0, 0
    while queue:
        before = queue.popleft()
        trace = traces[before]
        depth = max(depth, len(trace))
        for event in edges(before, fault):
            transitions += 1
            try:
                transition_invariant(before, event)
            except AssertionError as error:
                return dict(exhausted=False, states=len(traces), edges=transitions,
                            violation=str(error), trace=trace + (event.name,))
            if event.after not in traces:
                if len(traces) >= state_limit:
                    raise RuntimeError("state limit reached before graph exhaustion")
                traces[event.after] = trace + (event.name,)
                queue.append(event.after)
    return dict(exhausted=True, states=len(traces), edges=transitions,
                maximum_shortest_path=depth, violation=None, trace=())


if __name__ == "__main__":
    import json
    results = {fault.value: explore(fault) for fault in Fault}
    assert results[Fault.NONE.value]["exhausted"]
    assert all(value["violation"] for name, value in results.items() if name != Fault.NONE.value)
    print(json.dumps(results, indent=2, sort_keys=True))
