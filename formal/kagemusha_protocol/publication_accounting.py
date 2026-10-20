"""Bounded composition of one Send publication and conditional accounting.

Two already validated Send capsules compete for one funded, folded payer head.
Selection creates an irreversible liability projection, even before its signature
is available. That projection is not a delivered Payment or spend capability.
Only the provider's released original can populate delivery custody. The first
graph treats Receive as an already durable operation. A separate receiver graph
starts at that graph's exact released/delivered seam and composes a second provider
with first-credit accounting, retries and fold refusal. Neither graph proves
cryptography, filesystem refinement or arbitrary multi-head histories.
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


class ReceiveFault(Enum):
    """Incorrect joins between receiver custody, API completion and accounting."""

    NONE = "none"
    EARLY_COMPLETION = "early_completion"
    RETRY_CREDIT = "retry_credit"
    FOLD_PENDING = "fold_pending"
    FOLD_AFTER_REFUSAL = "fold_after_refusal"
    REPLAY_LOST_OUTPUT = "replay_lost_output"


# Fixed released payer: 3 capsule-copy counts, 3 output-copy counts, two storage,
# signer and observed-output states. Receiver: 28 Old + 168 Selected + 288 Released
# states from provider.py's finite fields. Only carrier presence and folded_sequence
# add independent binary choices; retained intake and accounting are then determined.
# This is a structural upper bound, not a count copied from a successful traversal.
RECEIVER_STATE_BOUND = 72 * (28 + 168 + 288) * 2 * 2


@dataclass(frozen=True, slots=True)
class ReceiveState:
    """One delivered payer original and the receiver's distinct provider.

    ``payer.received`` is the permanent first-original ghost at selection, not
    an API completion or an assertion that the native index was already written.
    ``input_original`` instead denotes actual bytes in the receiver's retained
    capsule. It cannot be recovered from that ghost after all capsule copies die.
    """

    payer: State
    publication: provider.State
    input_original: tuple[int, int] | None = None


@dataclass(frozen=True, slots=True)
class ReceiveEdge:
    """A payer-custody, receiver-provider, duplicate-input or local-fold action."""

    name: str
    after: ReceiveState
    payer: Edge | None = None
    publication: provider.Edge | None = None
    reply: str | tuple[int, int] | None = None


def receiver_initial(capsule=0, nonce=0):
    """Reach the seam through legal payer transitions, never a ghost byte copy."""
    if type(capsule) is not int or capsule not in (0, 1):
        raise ValueError("payer capsule")
    if type(nonce) is not int or nonce not in (0, 1):
        raise ValueError("payer receipt nonce")
    state = initial()
    for name in (f"provider/stage_{capsule}", "provider/select",
                 f"provider/sign_{nonce}", "provider/persist_completion",
                 "provider/repair_completion", "provider/publish_released", "deliver"):
        event, = [event for event in edges(state) if event.name == name]
        transition_invariant(state, event)
        state = event.after
    return ReceiveState(state, provider.State())


def receiver_status(state, fault=ReceiveFault.NONE):
    """Only the receiver's released readable output can report completion."""
    if not isinstance(fault, ReceiveFault):
        raise ValueError("explicit receiver fault required")
    selected = state.publication
    reply = provider.status(selected)
    if selected.storage_available:
        if fault == ReceiveFault.EARLY_COMPLETION and selected.marker == "selected":
            # A signature in memory or a lone completion is not released credit.
            return selected.temporary_receipt or selected.retained_receipt or reply
        if fault == ReceiveFault.REPLAY_LOST_OUTPUT and reply == "delivery_data_loss":
            return selected.sealed
    return reply


def select_received_credit(state, variant):
    """Project one irreversible selection using actual retained intake bytes.

    The accounting model's carrier flag stands for available delivery bytes.
    Here a checked retained receiver capsule can supply them even after carrier
    and payer loss. Restore the real carrier flag immediately after that call.
    No exported byte string is reconstructed from the accounting ghost.
    """
    assert state.input_original is not None, "selection without retained Payment"
    payment, = state.payer.world.payments
    readable = replace(state.payer.world, payments=(replace(payment, carrier_copy=True),))
    world = money.receive(readable, 1, 0, variant=variant)
    world = replace(world, payments=(replace(world.payments[0],
                                            carrier_copy=payment.carrier_copy),))
    return replace(state.payer, world=world, received=state.input_original)


def receiver_edges(state, fault=ReceiveFault.NONE):
    """Explore the receiver after a genuine payer release.

    Payer loss/availability/delivery may still interleave. Only the second
    provider selects Receive; the first graph's atomic Receive/fold transitions
    are deliberately not part of this second vocabulary.
    """
    if not isinstance(fault, ReceiveFault):
        raise ValueError("explicit receiver fault required")
    for event in edges(state.payer):
        if event.name.startswith("provider/") or event.name in ("deliver", "lose_carrier"):
            yield ReceiveEdge("payer/" + event.name,
                              replace(state, payer=event.after), payer=event)

    before = state.publication
    for event in provider.edges(before):
        if event.name.startswith("stage_") and state.payer.carrier is None:
            continue
        original = state.input_original
        if event.name.startswith("stage_"):
            original = state.payer.carrier
        if not event.after.capsule_copies:
            original = None
        payer = state.payer
        if before.winner is None and event.after.winner is not None:
            payer = select_received_credit(state, event.after.winner)
        reply = event.reply
        if event.name == "observe":
            reply = receiver_status(state, fault)
            if fault == ReceiveFault.RETRY_CREDIT and isinstance(reply, tuple):
                # Preserve aggregate conservation: the extra optimistic credit
                # is matched by a burn, but it is still a forbidden retry effect.
                wallet = payer.world.wallets[1]
                world = money.contain_duplicate_receive(
                    payer.world, 1, 0, payer.world.payments[0].amount,
                    digest=0, sequence=wallet.sequence + 1)
                payer = replace(payer, world=world)
        yield ReceiveEdge("receiver/" + event.name,
                          replace(state, payer=payer, publication=event.after,
                                  input_original=original),
                          publication=event, reply=reply)

    if before.winner is not None:
        # Same-request recovery does not require the sender or carrier again.
        yield ReceiveEdge("retry_receive", state, reply=receiver_status(state, fault))
        if state.payer.carrier is not None:
            yield ReceiveEdge("duplicate_receive", state, reply=receiver_status(state, fault))
            if (before.marker == "released" and before.storage_available
                    and before.completion_copies):
                # Native duplicate-original comparison follows sync_manifest:
                # a projected selected credit cannot override Pending/unavailable.
                yield ReceiveEdge("conflicting_receive", state, reply="credit_conflict")
    if before.marker == "selected" and before.storage_available:
        after = state
        if fault == ReceiveFault.FOLD_PENDING:
            after = replace(state, payer=replace(
                state.payer, world=money.fold(state.payer.world, 1)))
        yield ReceiveEdge("fold_pending", after, reply="idle")
    # Sufficient readable custody for this bounded fold vocabulary. The native
    # archive has more independently retained sources than this finite model.
    if (before.marker == "released" and before.storage_available
            and before.completion_copies and state.input_original is not None):
        folded = replace(state, payer=replace(
            state.payer, world=money.fold(state.payer.world, 1)))
        yield ReceiveEdge("fold_receiver", folded)
        yield ReceiveEdge("fold_refused",
                          folded if fault == ReceiveFault.FOLD_AFTER_REFUSAL else state,
                          reply="proof_refused")
        yield ReceiveEdge("fold_cancelled", state, reply="cancelled")


def receiver_invariant(state):
    """Keep payer assertions, reserve conservation and one receiver selection."""
    invariant(state.payer)
    provider.invariant(state.publication)
    selected = state.publication
    wallet = state.payer.world.wallets[1]
    assert state.payer.publication.marker == "released", "unreleased payer seam"
    if state.input_original is not None:
        assert selected.capsule_copies > 0, "intake bytes without retained capsule"
        assert state.input_original == state.payer.publication.sealed, "foreign retained Payment"
    if selected.winner is None:
        assert state.payer.received is None and not wallet.credits, "credit before receiver selection"
        assert wallet.sequence == 0 and wallet.balance == 0, "unselected receiver effect"
    else:
        assert state.payer.received == state.payer.publication.sealed, "first Payment identity"
        assert len(wallet.credits) == 1, "one receiver first credit"
        assert wallet.credits[0].variant == selected.winner, "selected Receive verdict"
        assert wallet.sequence == 1 and not wallet.duplicate_receives, "receiver selected operation advanced twice"
        if wallet.folded():
            assert selected.marker == "released", "fold before receiver release"


def receiver_transition_invariant(before, edge):
    """Check exact completion/replay and that refusals never publish a fold."""
    receiver_invariant(before)
    after = edge.after
    if edge.payer is not None:
        transition_invariant(before.payer, edge.payer)
        assert edge.payer.after == after.payer, "payer transition mismatch"
        assert before.publication == after.publication, "payer changed receiver custody"
        assert before.input_original == after.input_original, "payer erased receiver intake"
    elif edge.publication is not None:
        provider.transition_invariant(before.publication, edge.publication)
        assert edge.publication.after == after.publication, "receiver transition mismatch"
    else:
        assert before.publication == after.publication, "fold or retry changed receiver custody"
        assert before.input_original == after.input_original, "fold or retry changed intake"
    receiver_invariant(after)
    if before.publication.winner is not None:
        assert after.payer.received == before.payer.received, "retry changed first Payment"
        assert after.payer.world.wallets[1].credits == before.payer.world.wallets[1].credits, "retry changed first credit"
        assert after.payer.world.wallets[1].balance == before.payer.world.wallets[1].balance, "retry changed receiver balance"
    if edge.name in ("receiver/observe", "retry_receive", "duplicate_receive"):
        assert edge.reply == provider.status(before.publication), "receiver completion without exact released output"
    if isinstance(edge.reply, tuple):
        selected = before.publication
        assert selected.marker == "released" and selected.storage_available, "receiver completion before release"
        assert selected.completion_copies > 0, "receiver output regenerated from ghost"
        assert edge.reply == selected.retained_receipt == selected.sealed, "receiver retry changed bytes"
    if edge.name in ("fold_pending", "fold_refused", "fold_cancelled",
                     "retry_receive", "duplicate_receive", "conflicting_receive"):
        assert after == before, "refusal or retry changed receiver state"
    if edge.name == "fold_receiver":
        assert before.publication.marker == "released", "fold without released Receive"
        assert after.payer.world.wallets[1].folded(), "successful fold not published"
        assert before.payer.world.wallets[1].normalized_balance() == after.payer.world.wallets[1].normalized_balance(), "fold changed reserve liability"


def explore_receiver(fault=ReceiveFault.NONE, *, capsule=0, nonce=0,
                     state_limit=RECEIVER_STATE_BOUND):
    """Exhaust one exact payer-output/receiver-provider frontier, or fail closed."""
    if not isinstance(fault, ReceiveFault):
        raise ValueError("explicit receiver fault required")
    if type(state_limit) is not int or state_limit <= 0:
        raise ValueError("positive finite state limit required")
    start = receiver_initial(capsule, nonce)
    traces = {start: ()}
    queue = deque([start])
    transitions, depth = 0, 0
    while queue:
        before = queue.popleft()
        trace = traces[before]
        depth = max(depth, len(trace))
        for event in receiver_edges(before, fault):
            transitions += 1
            try:
                receiver_transition_invariant(before, event)
            except AssertionError as error:
                return dict(exhausted=False, states=len(traces), edges=transitions,
                            violation=str(error), trace=trace + (event.name,))
            if event.after not in traces:
                if len(traces) >= state_limit:
                    raise RuntimeError("receiver state limit reached before graph exhaustion")
                traces[event.after] = trace + (event.name,)
                queue.append(event.after)
    return dict(exhausted=True, states=len(traces), edges=transitions,
                maximum_shortest_path=depth, violation=None, trace=())


if __name__ == "__main__":
    import json
    results = {fault.value: explore(fault) for fault in Fault}
    assert results[Fault.NONE.value]["exhausted"]
    assert all(value["violation"] for name, value in results.items() if name != Fault.NONE.value)
    receivers = {f"capsule_{capsule}_nonce_{nonce}": explore_receiver(capsule=capsule, nonce=nonce)
                 for capsule in (0, 1) for nonce in (0, 1)}
    mutations = {fault.value: explore_receiver(fault) for fault in ReceiveFault
                 if fault != ReceiveFault.NONE}
    assert all(value["exhausted"] and value["violation"] is None for value in receivers.values())
    assert all(value["violation"] for value in mutations.values())
    print(json.dumps({"payer": results, "receiver": receivers, "receiver_mutations": mutations,
                      "scope": "separate finite payer and receiver frontiers; not native, C12 or phone qualification"},
                     indent=2, sort_keys=True))
