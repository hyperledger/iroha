"""Exhaust finite monetary schedules without treating a search cutoff as success.

Record bounds delimit the explored vocabulary, not production wallet capacity.
Accounting transitions already assume authenticated inputs and an atomic durable
Advance. This graph does not compose provider crashes or prove native refinement.
"""
from collections import deque
from dataclasses import dataclass, replace
from enum import Enum
from functools import lru_cache
import sys

import accounting as a

if sys.flags.optimize:
    raise RuntimeError("schedule model requires unoptimized Python; assertions are gates")


class Fault(Enum):
    """Incorrect monetary transition rules requiring reachable counterexamples."""

    NONE = "none"
    REFUND_SEND = "refund_send"
    OMIT_BURN = "omit_burn"
    DUPLICATE_CREDIT = "duplicate_credit"
    REDIRECT_UNLOAD = "redirect_unload"


@dataclass(frozen=True, slots=True)
class Bounds:
    """Finite identities and initial supply; all amounts within supply are tried."""

    balances: tuple[int, ...] = (1, 0)
    loads: int = 1
    payments: int = 1
    claims: int = 1
    unbacked: bool = False

    def validate(self):
        """Refuse ambiguous or unbounded exploration parameters."""
        if type(self.balances) is not tuple:
            raise ValueError("initial balances must be an immutable tuple")
        a.initial(*self.balances)
        if len(self.balances) < 2 or sum(self.balances) > 3:
            raise ValueError("schedule vocabulary requires at least two wallets and supply at most three")
        if any(type(n) is not int or not 0 <= n <= 3 for n in (self.loads, self.payments, self.claims)):
            raise ValueError("record bounds must be integers in 0..3")
        if type(self.unbacked) is not bool:
            raise ValueError("explicit unbacked-input selection required")


@dataclass(frozen=True, slots=True)
class Action:
    """One exact operation name and positional/keyword arguments for replay."""

    operation: str
    args: tuple = ()
    keywords: tuple = ()

    def label(self):
        """Stable, unique label within one state's operation inventory."""
        fields = [str(v) for v in self.args] + [f"{k}={v}" for k, v in self.keywords]
        return f"{self.operation}({','.join(fields)})"

    def apply(self, world, fault=Fault.NONE):
        """Apply a genuine accounting transition, then its explicit fault rule."""
        if not isinstance(fault, Fault):
            raise ValueError("explicit model fault required")
        after = OPERATIONS[self.operation](world, *self.args, **dict(self.keywords))
        if fault == Fault.REFUND_SEND and self.operation == "send":
            sender = self.args[0]
            previous, current = world.wallets[sender], after.wallets[sender]
            after = replace(after, wallets=a.changed(after.wallets, sender, replace(current, balance=previous.balance)))
        if fault == Fault.OMIT_BURN and self.operation == "receive" and after != world:
            receiver = self.args[0]
            previous, current = world.wallets[receiver], after.wallets[receiver]
            after = replace(after, wallets=a.changed(after.wallets, receiver,
                            replace(current, deferred_burn=previous.deferred_burn)))
        if fault == Fault.DUPLICATE_CREDIT and self.operation == "receive" and after == world:
            receiver, key = self.args
            current = after.wallets[receiver]
            original = next(c for c in current.credits if c.key == key)
            after = replace(after, wallets=a.changed(after.wallets, receiver,
                            replace(current, balance=current.balance + original.amount,
                                    credits=current.credits + (original,))))
        if fault == Fault.REDIRECT_UNLOAD and self.operation == "pay_unload" and after != world:
            claim = after.claims[self.args[0]]
            value = claim.amount - claim.charge
            if value:
                recipient = (claim.wallet + 1) % len(after.wallets)
                online = a.changed(after.online, claim.wallet, after.online[claim.wallet] - value)
                after = replace(after, online=a.changed(online, recipient, online[recipient] + value))
        return after


OPERATIONS = {name: getattr(a, name) for name in (
    "issue_load", "absorb_load", "send", "receive", "fold", "archive",
    "collect_payment", "copy_for_delivery", "lose_delivery_bytes", "unload",
    "pay_unload", "pay_fee", "retire", "close_loads",
)}


def actions(world, bounds):
    """Enumerate every configured action, including exact retries and rejected ones."""
    return action_inventory(bounds, len(world.vouchers),
                            tuple(payment.receiver for payment in world.payments), len(world.claims))


@lru_cache(maxsize=512)
def action_inventory(bounds, vouchers, receivers, claims):
    """Share immutable action lists; only record identities affect the vocabulary."""
    return tuple(generate_actions(bounds, vouchers, receivers, claims))


def generate_actions(bounds, vouchers, receivers, claims):
    """Construct the exact inventory without consulting any monetary verdict."""
    supply = sum(bounds.balances)
    for wallet in range(len(bounds.balances)):
        for operation in ("fold", "retire", "close_loads"):
            yield Action(operation, (wallet,))
        if bounds.unbacked:
            yield Action("receive", (wallet, -1), (("variant", 1),))
        for amount in range(1, supply + 1):
            for charge in range(supply + 1):
                if vouchers < bounds.loads:
                    yield Action("issue_load", (wallet, amount), (("charge", charge),))
                if claims < bounds.claims:
                    yield Action("unload", (wallet, amount), (("charge", charge),))
                if len(receivers) < bounds.payments:
                    for receiver in range(len(bounds.balances)):
                        yield Action("send", (wallet, receiver, amount), (("fee", charge),))
    for key in range(vouchers):
        yield Action("absorb_load", (key,))
    for key, receiver in enumerate(receivers):
        for variant in (0, 1):
            yield Action("receive", (receiver, key), (("variant", variant),))
        for valid in (False, True):
            yield Action("archive", (key,), (("evidence_valid", valid),))
        for operation in ("collect_payment", "copy_for_delivery", "lose_delivery_bytes", "pay_fee"):
            yield Action(operation, (key,))
    for key in range(claims):
        yield Action("pay_unload", (key,))


def explore(bounds=Bounds(), fault=Fault.NONE, state_limit=200_000):
    """Exhaust reachable worlds or return a shortest violating trace; never truncate."""
    bounds.validate()
    if not isinstance(fault, Fault) or type(state_limit) is not int or state_limit <= 0:
        raise ValueError("explicit fault and positive finite state limit required")
    start = a.initial(*bounds.balances)
    a.invariant(start)
    queue, parents = deque([start]), {start: None}
    depths = {start: 0}
    edges = rejected = retries = maximum_depth = 0
    coverage = set()

    def trace(world, final):
        steps = [final]
        while parents[world] is not None:
            world, label = parents[world]
            steps.append(label)
        return tuple(reversed(steps))

    while queue:
        before = queue.popleft()
        maximum_depth = max(maximum_depth, depths[before])
        for action in actions(before, bounds):
            try:
                after = action.apply(before, fault)
            except a.Rejected:
                rejected += 1
                continue
            edges += 1
            retries += after == before
            coverage.add(action.operation)
            # Every retained World is immutable and already passed this same
            # state-only invariant. Rechecking a previously visited World adds
            # no path property; all transitions and self-loops still count.
            if after in parents:
                continue
            try:
                a.invariant(after)
            except AssertionError as error:
                return {"exhausted": False, "states": len(parents), "edges": edges,
                        "violation": str(error), "trace": trace(before, action.label())}
            if len(parents) >= state_limit:
                raise RuntimeError(f"state limit reached before monetary graph exhaustion: "
                                   f"{len(parents)} states, {edges} edges, depth {maximum_depth}")
            parents[after] = (before, action.label())
            depths[after] = depths[before] + 1
            queue.append(after)
    return {"exhausted": True, "states": len(parents), "edges": edges, "rejected": rejected,
            "retries": retries, "maximum_shortest_path": maximum_depth,
            "operations": sorted(coverage), "violation": None, "trace": ()}


def replay(bounds, labels, fault=Fault.NONE):
    """Reconstruct a reported path without skipping rejection or intermediate checks."""
    bounds.validate()
    if not isinstance(fault, Fault):
        raise ValueError("explicit model fault required")
    world = a.initial(*bounds.balances)
    for label in labels:
        matches = [action for action in actions(world, bounds) if action.label() == label]
        if len(matches) != 1:
            raise ValueError(f"unavailable or ambiguous action: {label}")
        world = matches[0].apply(world, fault)
        a.invariant(world)
    return world


# Each graph is separate. Their state counts are not added or presented as one
# exhaustive graph spanning the union of these record/supply vocabularies.
PROFILES = {
    "single_unit": Bounds(),
    "fees": Bounds(balances=(2, 0)),
    "unbacked": Bounds(balances=(0, 0), loads=0, payments=0, claims=0, unbacked=True),
    "onward": Bounds(balances=(1, 0, 0), payments=2),
}


if __name__ == "__main__":
    import json
    from dataclasses import asdict

    baseline = {}
    for name, bounds in PROFILES.items():
        baseline[name] = {"bounds": asdict(bounds), "state_limit": 5_000_000,
                          "result": explore(bounds, state_limit=5_000_000)}
        # Preserve completed profiles if a later profile reaches its search
        # limit. Only the final all-profile record can report overall success.
        print(json.dumps({"completed_profile": name, **baseline[name]}, sort_keys=True),
              file=sys.stderr, flush=True)
    mutations = {fault.value: explore(Bounds(), fault) for fault in Fault if fault != Fault.NONE}
    if any(not value["result"]["exhausted"] for value in baseline.values()) or any(
            value["violation"] is None for value in mutations.values()):
        raise SystemExit("monetary baseline violation or surviving mutation")
    print(json.dumps({"scope": "bounded accounting only; no provider/native/phone qualification",
                      "profiles": baseline, "mutation_bounds": asdict(Bounds()),
                      "mutations": mutations}, indent=2, sort_keys=True))
