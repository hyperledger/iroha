"""Conditional accounting model for committed operations and a completed local fold.

This is a specification model, not a proof verifier or wallet. ``deferred_burn``
and ``adjusted_pending`` describe the eventual deterministic lineage result of
committed inputs. They are ghost values until fold completion. Monetary release
must use a folded head; an optimistic core balance alone grants no authority.
"""
from dataclasses import dataclass, replace
import sys

if sys.flags.optimize:
    raise RuntimeError("accounting model requires unoptimized Python; assertions are gates")

MAX = (1 << 128) - 1


class Rejected(ValueError):
    """The selected abstract operation has no valid transition."""


def require(condition, reason):
    """Reject a transition without changing its immutable input world."""
    if not condition:
        raise Rejected(reason)


@dataclass(frozen=True, slots=True)
class Credit:
    """Permanent first received identity; variant 1 denotes a failing input."""

    key: int
    variant: int
    amount: int


@dataclass(frozen=True, slots=True)
class Wallet:
    """Core state plus folded and deferred lineage accounting projections."""

    balance: int = 0
    core_burned: int = 0
    burned: int = 0
    deferred_burn: int = 0
    sequence: int = 0
    folded_sequence: int = 0
    next_load: int = 0
    next_send: int = 0
    next_redeem: int = 0
    retiring: bool = False
    core_pending: frozenset[int] = frozenset()
    adjusted_pending: frozenset[int] = frozenset()
    credits: tuple[Credit, ...] = ()

    def folded(self):
        """Whether the current head, rather than an older head, has durable Ω."""
        return self.sequence == self.folded_sequence

    def normalized_balance(self):
        """Accounting value; this ghost expression is not an unfurled spend API."""
        return self.balance - self.burned - self.deferred_burn


@dataclass(frozen=True, slots=True)
class Voucher:
    """Already finalized native-authorized Load terms; proof checks are assumed."""

    wallet: int
    ordinal: int
    amount: int
    charge: int
    absorbed: bool = False


@dataclass(frozen=True, slots=True)
class Payment:
    """One irreversible Send, with independent delivery and fee original custody."""

    sender: int
    receiver: int
    ordinal: int
    amount: int
    fee: int
    received_variant: int | None = None
    fee_paid: bool = False
    retained: bool = True
    fee_retained: bool = False
    carrier_copy: bool = False
    archived_sequence: int | None = None


@dataclass(frozen=True, slots=True)
class Claim:
    """Unload face amount with its disclosed online charge withheld from payout."""

    wallet: int
    ordinal: int
    amount: int
    charge: int
    paid: bool = False


@dataclass(frozen=True, slots=True)
class World:
    """One scheme/asset, active enrolled wallets and a fixed fee beneficiary."""

    initial_online: tuple[int, ...]
    online: tuple[int, ...]
    wallets: tuple[Wallet, ...]
    reserve: int = 0
    fee_online: int = 0
    vouchers: tuple[Voucher, ...] = ()
    payments: tuple[Payment, ...] = ()
    claims: tuple[Claim, ...] = ()
    closed_loads: frozenset[int] = frozenset()


def initial(*balances):
    """Begin after enrollment/activation; enrollment itself is not modeled here."""
    require(bool(balances) and all(type(n) is int and 0 <= n <= MAX for n in balances), "initial balances")
    require(sum(balances) <= MAX, "bounded initial supply")
    return World(tuple(balances), tuple(balances), tuple(Wallet() for _ in balances))


def changed(items, index, value):
    """Replace one bounded immutable vector entry."""
    require(type(index) is int and 0 <= index < len(items), "record index")
    return items[:index] + (value,) + items[index + 1:]


def owner(world, wallet):
    """Select the exact enrolled wallet/account binding in this model."""
    require(type(wallet) is int and 0 <= wallet < len(world.wallets), "wallet identity")
    return world.wallets[wallet]


def advance(world, wallet, **fields):
    """Abstract one successfully committed Advance, whose proof is already durable."""
    previous = owner(world, wallet)
    require(previous.sequence < MAX, "sequence overflow")
    current = replace(previous, sequence=previous.sequence + 1, **fields)
    require(0 <= current.balance <= MAX, "balance overflow or underflow")
    return replace(world, wallets=changed(world.wallets, wallet, current))


def spend_head(world, wallet, amount):
    """Use only current folded lineage and its adjusted burned amount."""
    current = owner(world, wallet)
    require(current.folded(), "current head must be folded")
    require(type(amount) is int and 0 < amount <= current.balance - current.burned, "unavailable value")
    return current


def issue_load(world, wallet, amount, *, charge=0, ordinal=None):
    """Atomic ledger debit and reserve deposit; a lost response never refunds it."""
    owner(world, wallet)
    require(wallet not in world.closed_loads, "loads closed")
    next_ordinal = sum(v.wallet == wallet for v in world.vouchers)
    require(next_ordinal < MAX, "load ordinal overflow")
    require(ordinal is None or (type(ordinal) is int and ordinal == next_ordinal), "stale load ordinal")
    require(type(amount) is int and type(charge) is int and 0 < amount <= MAX and 0 <= charge <= MAX, "load terms")
    require(amount + charge <= world.online[wallet], "online balance")
    return replace(world, online=changed(world.online, wallet, world.online[wallet] - amount - charge),
                   reserve=world.reserve + amount, fee_online=world.fee_online + charge,
                   vouchers=world.vouchers + (Voucher(wallet, next_ordinal, amount, charge),))


def absorb_load(world, voucher):
    """Absorb the exact next finalized receipt once, including after retirement."""
    require(type(voucher) is int and 0 <= voucher < len(world.vouchers), "voucher identity")
    value = world.vouchers[voucher]
    wallet = owner(world, value.wallet)
    if value.absorbed:
        return world
    require(value.ordinal == wallet.next_load, "load receipt order")
    result = advance(world, value.wallet, balance=wallet.balance + value.amount, next_load=wallet.next_load + 1)
    return replace(result, vouchers=changed(world.vouchers, voucher, replace(value, absorbed=True)))


def send(world, sender, receiver, amount, *, fee=0):
    """Commit a preauthenticated Request; recipient retirement cannot revoke it.

    Quote issuance and historical policy verification are premises of this
    transition. Sender and receiver identities and terms are already bound.
    """
    owner(world, receiver)
    require(sender != receiver, "self payment")
    require(type(amount) is int and type(fee) is int and amount > 0 and 0 <= fee <= MAX, "send terms")
    wallet = spend_head(world, sender, amount + fee)
    require(not wallet.retiring, "sender retiring")
    require(wallet.next_send < MAX, "send ordinal overflow")
    key = len(world.payments)
    pending = wallet.adjusted_pending | {key}
    result = advance(world, sender, balance=wallet.balance - amount - fee, core_burned=wallet.burned,
                     core_pending=pending, adjusted_pending=pending, next_send=wallet.next_send + 1)
    payment = Payment(sender, receiver, wallet.next_send, amount, fee, fee_retained=fee > 0)
    return replace(result, payments=world.payments + (payment,))


def receive(world, receiver, key, *, variant=0):
    """Commit first-credit intake or return its exact original without another credit.

    Variant 0 is the authenticated retained Payment. Variant 1 abstracts a
    post-commit lineage rejection; any negative key names an unbacked failing
    input. This permits the specified burn-containment branch without claiming
    a correct native verifier admits malformed proofs in normal execution.
    """
    wallet = owner(world, receiver)
    require(type(key) is int and type(variant) is int and variant in (0, 1), "incoming identity")
    previous = next((credit for credit in wallet.credits if credit.key == key), None)
    if previous is not None:
        require(previous.variant == variant, "conflicting original for consumed credit")
        return world
    if key < 0:
        require(variant == 1, "unbacked input cannot be valid")
        amount, payment = 1, None
    else:
        require(key < len(world.payments), "payment identity")
        payment = world.payments[key]
        require(payment.receiver == receiver and payment.received_variant is None, "payment recipient or replay")
        require(payment.retained or payment.carrier_copy, "missing delivery bytes")
        amount = payment.amount
    result = advance(world, receiver, balance=wallet.balance + amount,
                     deferred_burn=wallet.deferred_burn + (amount if variant else 0),
                     credits=wallet.credits + (Credit(key, variant, amount),))
    if payment is not None:
        result = replace(result, payments=changed(world.payments, key, replace(payment, received_variant=variant)))
    return result


def fold(world, wallet):
    """Complete and durably record the full current lineage; no core state changes."""
    current = owner(world, wallet)
    if current.folded():
        return world
    folded = replace(current, burned=current.burned + current.deferred_burn,
                     deferred_burn=0, folded_sequence=current.sequence)
    return replace(world, wallets=changed(world.wallets, wallet, folded))


def archive(world, key, *, evidence_valid=True):
    """Core removes its descriptor; a failing lineage verdict keeps adjusted pending."""
    require(type(key) is int and 0 <= key < len(world.payments), "payment identity")
    require(type(evidence_valid) is bool, "evidence verdict")
    payment = world.payments[key]
    wallet = owner(world, payment.sender)
    require(key in wallet.core_pending and payment.retained, "retained pending payment")
    if evidence_valid:
        require(payment.received_variant == 0, "delivery evidence does not bind retained Payment")
    adjusted = wallet.adjusted_pending - {key} if evidence_valid else wallet.adjusted_pending
    result = advance(world, payment.sender, core_pending=wallet.core_pending - {key}, adjusted_pending=adjusted)
    if evidence_valid:
        payment = replace(payment, archived_sequence=wallet.sequence + 1)
        result = replace(result, payments=changed(world.payments, key, payment))
    return result


def collect_payment(world, key):
    """Collect delivery originals only after successful Archive is durably folded."""
    require(type(key) is int and 0 <= key < len(world.payments), "payment identity")
    payment = world.payments[key]
    wallet = owner(world, payment.sender)
    require(payment.archived_sequence is not None and wallet.folded_sequence >= payment.archived_sequence,
            "Archive not durably covered")
    require(key not in wallet.adjusted_pending, "adjusted pending remains")
    return replace(world, payments=changed(world.payments, key, replace(payment, retained=False)))


def copy_for_delivery(world, key):
    """Retain a carrier's exact bytes; this does not debit or credit value."""
    require(type(key) is int and 0 <= key < len(world.payments), "payment identity")
    payment = world.payments[key]
    require(payment.retained, "missing payer Payment bytes")
    return replace(world, payments=changed(world.payments, key, replace(payment, carrier_copy=True)))


def lose_delivery_bytes(world, key):
    """Explicit erasure strands an undelivered credit and never refunds Send."""
    require(type(key) is int and 0 <= key < len(world.payments), "payment identity")
    payment = world.payments[key]
    return replace(world, payments=changed(world.payments, key, replace(payment, retained=False, carrier_copy=False)))


def unload(world, wallet, amount, *, charge=0):
    """Commit a face-value redemption; the ledger later withholds its quoted charge."""
    current = spend_head(world, wallet, amount)
    require(type(charge) is int and 0 <= charge <= amount, "unload charge")
    require(current.next_redeem < MAX, "unload ordinal overflow")
    result = advance(world, wallet, balance=current.balance - amount, core_burned=current.burned,
                     core_pending=current.adjusted_pending, next_redeem=current.next_redeem + 1)
    return replace(result, claims=world.claims + (Claim(wallet, current.next_redeem, amount, charge),))


def pay_unload(world, claim):
    """Atomic exactly-once payout to the claim's already authenticated account."""
    require(type(claim) is int and 0 <= claim < len(world.claims), "claim identity")
    value = world.claims[claim]
    if value.paid:
        return world
    require(world.reserve >= value.amount, "reserve underflow")
    return replace(world, reserve=world.reserve - value.amount,
                   online=changed(world.online, value.wallet, world.online[value.wallet] + value.amount - value.charge),
                   fee_online=world.fee_online + value.charge,
                   claims=changed(world.claims, claim, replace(value, paid=True)))


def pay_fee(world, key):
    """The committed Send earns its fee, whether or not Receive ever happens."""
    require(type(key) is int and 0 <= key < len(world.payments), "payment identity")
    payment = world.payments[key]
    require(payment.fee > 0, "no earned fee")
    if payment.fee_paid:
        return world
    require(payment.retained or payment.fee_retained or payment.carrier_copy, "missing fee-claim bytes")
    require(world.reserve >= payment.fee, "reserve underflow")
    return replace(world, reserve=world.reserve - payment.fee, fee_online=world.fee_online + payment.fee,
                   payments=changed(world.payments, key, replace(payment, fee_paid=True, fee_retained=False)))


def retire(world, wallet):
    """Retiring consumes folded lineage, resynchronizes core roots and releases no value."""
    current = owner(world, wallet)
    require(current.folded() and not current.retiring, "retirement head")
    return advance(world, wallet, retiring=True, core_burned=current.burned, core_pending=current.adjusted_pending)


def close_loads(world, wallet):
    """Ledger closure races safely with IssueLoad; old funded receipts remain owed."""
    require(owner(world, wallet).retiring, "retirement evidence")
    return replace(world, closed_loads=world.closed_loads | {wallet})


def categories(world):
    """Disjoint normalized reserve liabilities; unbacked burned inputs add zero."""
    return {
        "wallets": sum(wallet.normalized_balance() for wallet in world.wallets),
        "unabsorbed_loads": sum(value.amount for value in world.vouchers if not value.absorbed),
        "in_flight": sum(value.amount for value in world.payments if value.received_variant is None),
        "burned_backing": sum(value.amount for value in world.payments if value.received_variant == 1),
        "earned_fees": sum(value.fee for value in world.payments if not value.fee_paid),
        "unpaid_unloads": sum(value.amount for value in world.claims if not value.paid),
    }


def invariant(world):
    """Independently recompute ledger movements, first identities and reserve liabilities."""
    assert sum(world.online) + world.fee_online + world.reserve == sum(world.initial_online), "online supply"
    assert all(0 <= value <= MAX for value in (*world.online, world.fee_online, world.reserve)), "ledger value"
    assert all(value >= 0 for value in categories(world).values()), "negative liability category"
    assert sum(categories(world).values()) == world.reserve, "reserve conservation"
    assert world.fee_online == sum(v.charge for v in world.vouchers) + sum(
        c.charge for c in world.claims if c.paid) + sum(p.fee for p in world.payments if p.fee_paid), "fee beneficiary"
    for index, wallet in enumerate(world.wallets):
        assert world.online[index] == world.initial_online[index] - sum(
            v.amount + v.charge for v in world.vouchers if v.wallet == index) + sum(
            c.amount - c.charge for c in world.claims if c.wallet == index and c.paid), "bound account payout"
        assert 0 <= wallet.balance <= MAX and 0 <= wallet.normalized_balance(), "wallet value"
        assert wallet.balance == sum(v.amount for v in world.vouchers if v.wallet == index and v.absorbed) + sum(
            credit.amount for credit in wallet.credits) - sum(p.amount + p.fee for p in world.payments if p.sender == index) - sum(
            claim.amount for claim in world.claims if claim.wallet == index), "wallet effect ownership"
        assert 0 <= wallet.core_burned <= wallet.burned and 0 <= wallet.folded_sequence <= wallet.sequence, "lineage order"
        assert wallet.deferred_burn >= 0, "negative deferred burn"
        assert wallet.burned + wallet.deferred_burn == sum(c.amount for c in wallet.credits if c.variant), "burn accounting"
        assert len({c.key for c in wallet.credits}) == len(wallet.credits), "permanent first credit"
        assert wallet.next_load == sum(v.wallet == index and v.absorbed for v in world.vouchers), "load replay"
        assert wallet.next_send == sum(p.sender == index for p in world.payments), "send ordinal"
        assert wallet.next_redeem == sum(c.wallet == index for c in world.claims), "unload ordinal"
        assert [v.ordinal for v in world.vouchers if v.wallet == index] == list(range(sum(v.wallet == index for v in world.vouchers))), "load ordinal sequence"
        assert [p.ordinal for p in world.payments if p.sender == index] == list(range(wallet.next_send)), "send ordinal sequence"
        assert [c.ordinal for c in world.claims if c.wallet == index] == list(range(wallet.next_redeem)), "unload ordinal sequence"
        assert wallet.adjusted_pending == frozenset(key for key, payment in enumerate(world.payments)
            if payment.sender == index and payment.archived_sequence is None), "adjusted pending retention"
        assert wallet.core_pending <= wallet.adjusted_pending, "pending no-op containment"
        for key in wallet.adjusted_pending:
            assert 0 <= key < len(world.payments) and world.payments[key].sender == index, "pending owner"
        if wallet.folded():
            assert wallet.deferred_burn == 0, "fold missed burn"
    for key, payment in enumerate(world.payments):
        credits = [c for c in world.wallets[payment.receiver].credits if c.key == key]
        assert len(credits) == int(payment.received_variant is not None), "recipient first credit"
        if credits:
            assert credits[0].amount == payment.amount and credits[0].variant == payment.received_variant, "received original"
        assert payment.sender != payment.receiver and payment.amount > 0 and payment.fee >= 0, "payment terms"
        if payment.archived_sequence is not None:
            assert payment.received_variant == 0, "Archive original mismatch"
        if payment.fee and not payment.fee_paid:
            assert payment.fee_retained, "lost independent unpaid fee original"
