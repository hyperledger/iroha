"""Builder of `fixtures/sccp/committee_transitions_v1.json` (`specs/sccp.md` §5.1.2–§5.1.8, §11.1).

Every required row of §11.1 is a scenario: a fresh destination deployed with a
pin, then calls with `now_ms`, each with the expected outcome, events and the
state afterwards. Scenarios are EVM-flavored (`submitCheckpoints` batches,
calldata committees) unless marked `ton` (one certificate per `sccp_checkpoint`
message, keys in storage, three checkpoint slots, `next_keys`).

A TON-flavored scenario runs on the TON route: Taira's leaves target
`ton-mainnet`, the destination word is the minter account id (a placeholder,
`TON_DESTINATION_WORD`) and recipients are 36-byte TON accounts. A real minter
computes its lane and its word from its own chain and address, so a row on any
other route could not be replayed against it.

`now_ms` is the destination clock (`block.timestamp × 1000`, §0): every step
uses a whole second and no step is earlier than the one before it, which the
scenario recorder asserts. A time boundary (`Live ⇔ now_ms ≤ untilMs`, a
payload deadline) is therefore probed at the boundary value and at the next
clock value, one second later; `rotation_sub_second_deadline` probes a
sub-second `untilMs` from both sides, and `transfer_deadline_boundaries` a
whole-second and a sub-second payload deadline.
"""

from __future__ import annotations

import dataclasses

from .bls12_381 import P
from .common import (
    DESTINATION_CLOCK_CONVENTION,
    MAX_CERTIFICATES_PER_CALL,
    MAX_INIT_SLACK_MS,
    MAX_VALIDITY_MS,
    REFERENCE_GENERATORS,
    SCENARIO_CLOCK_CONVENTION,
    U64_MAX,
    hx,
    rep,
)
from .destination import IDENTITY_SIGNATURE_COMPRESSED, BlockRef, Deployment, MessageProof, init_until_ms_ok
from .finality import FLAG_ACTIVE, FLAG_ROTATION
from .keccak import event_topic, selector
from .payload import ETHEREUM, TON, outbound_payload
from .scenario import CALL_NAMES, CertificatePool, Scenario
from .taira import Committee, TairaSim

NETWORK_ID = rep(0x11)
INSTANCE = rep(0x77)
T0 = 1_800_000_000_000
SECOND = 1_000
MINUTE = 60_000
HOUR = 3_600_000
DAY = 86_400_000
VALIDITY = 1_209_600_000
PIN_GENERATION = 5
PIN_START = 1000
EVM_DESTINATION_WORD = bytes(12) + rep(0x22, 20)
RECIPIENT = rep(0x44, 20)
# The TON route of the TON-flavored scenarios. The destination word of a minter is its account id, which its
# StateInit fixes; this one is a placeholder (`control_v1.json` lists the same value under `destination_words`).
TON_DESTINATION_WORD = rep(0x35)
# A TON recipient: `addr_std` in workchain 0 (`be32(0) ‖ account_id`).
TON_RECIPIENT = bytes(4) + rep(0x44, 32)

EVENT_SIGNATURES = {
    "SccpCommitteeRotated": ("SccpCommitteeRotated(uint64,bytes32,uint64,uint64)", "6244ff84b5945581521adb818f0b307122dfde790299fb252046603a974d3d3d"),
    "SccpCheckpointed": ("SccpCheckpointed(uint64,bytes32)", "fe0aa9a242fa773b609fa05dac2bc7034ac693373de95b042f61db6c8d218853"),
    "SccpLatched": ("SccpLatched(uint8,uint64,uint64,bytes32,bytes32)", "0567b58957c8b229342697465e6c4c3c6f0f63efb05b97d09469929c47a331f7"),
    "SccpControlApplied": ("SccpControlApplied(uint64,uint8,bool,uint64,bytes32)", "b069397cc6f8fa22bf7c0216c554253ab0fc92a3178d10969760b028dd174238"),
    "SccpCertificate": ("SccpCertificate(uint64,uint64,bytes,bytes,bytes)", "a89e234faf229fd8a8a7add0e9aec37a1986183e842549427a65eb2fb88c116e"),
    "SccpFinalized": ("SccpFinalized(bytes32,uint64,address,uint256)", "8ab0eb669cb9abcdf0e37e9ce8443162d317d10c2b059296e40aebbd3fa23748"),
    "SccpVoided": ("SccpVoided(bytes32,uint64)", "fc0fe8523e61c1e6bcbb957a8b692dd0b08e1774c4c4bd897fbc68c047c82fcf"),
    "SccpTransferToTaira": (
        "SccpTransferToTaira(bytes32,address,uint64,bytes)",
        "79ac1cc63262b80bfbf96e55b2d49d96bd82f018ce0192f7002168724c7d264b",
    ),
}


_CERT = "(bytes,bytes,bytes,bytes,bytes)"
_CHECKPOINT_REF = "(bytes)"
_BLOCK_REF = "(uint64,bytes32,uint32,uint64,bytes32[])"
_MESSAGE_PROOF = f"(bytes,uint32,bytes32[],{_BLOCK_REF})"
_CONTROL_PROOF = f"(uint64,uint8,bool,uint64,bytes32,bytes32,uint32,bytes32[],{_BLOCK_REF})"

# §5.2.2 entry points and views: (name, canonical signature with tuples expanded, specification selector).
SELECTORS = (
    ("submitCheckpoints", f"submitCheckpoints({_CERT}[])", "07a5e706"),
    ("finalizeFromTaira", f"finalizeFromTaira({_CERT},{_MESSAGE_PROOF})", "10efea88"),
    ("finalizeFromCheckpoint", f"finalizeFromCheckpoint({_CHECKPOINT_REF},{_MESSAGE_PROOF})", "55c39595"),
    ("applyControl", f"applyControl({_CERT},{_CONTROL_PROOF})", "32118e92"),
    ("applyControlFromCheckpoint", f"applyControlFromCheckpoint({_CHECKPOINT_REF},{_CONTROL_PROOF})", "53899b1e"),
    ("voidExpired", f"voidExpired(uint64,{_CERT},{_MESSAGE_PROOF})", "997fcd99"),
    ("voidExpiredFromCheckpoint", f"voidExpiredFromCheckpoint(uint64,{_CHECKPOINT_REF},{_MESSAGE_PROOF})", "fbeb670e"),
    ("voidFrozen", "voidFrozen(uint64,uint64)", "5b094c00"),
    ("transferToTaira", "transferToTaira(bytes,uint256,uint64)", "ebfc6ca8"),
    ("committeeState", "committeeState()", "620ae238"),
    ("checkpointHeader", "checkpointHeader(uint64)", "405cf530"),
    ("pauseState", "pauseState()", "d7118351"),
    ("mintingPaused", "mintingPaused()", "e1a283d6"),
    ("consensusInstance", "consensusInstance()", "1682dae6"),
    ("initialCommittee", "initialCommittee()", "86645f61"),
    ("equivocated", "equivocated()", "78048149"),
    ("maxValidityMs", "maxValidityMs()", "5cffa161"),
    ("isConsumed", "isConsumed(uint64)", "95b67034"),
    ("controlNonce", "controlNonce()", "4faac8ca"),
    ("opCount", "opCount()", "cb58065f"),
    ("transferNonces", "transferNonces(address)", "f6f0e8a6"),
    ("tairaNetworkId", "tairaNetworkId()", "6b91d731"),
    ("routeRevision", "routeRevision()", "1818891a"),
    ("maxWrappedSupply", "maxWrappedSupply()", "d8bc4dcd"),
)

# §5.2.2 error table: EVM error name → TON exit code (None: EVM only).
ERROR_CODES = {
    "WrongChain": 400,
    "MintingIsPaused": 401,
    "CommitteeNotAccepted": 402,
    "BadCommittee": 403,
    "BadCertificate": 404,
    "BadSignature": 405,
    "BadHeader": 406,
    "BadProof": 407,
    "BadPayload": 408,
    "SupplyCapExceeded": 410,
    "UnknownCheckpoint": 411,
    "BadRecipient": 412,
    "BadAmount": 413,
    "DeadlinePassed": 414,
    "DeadlineNotReached": 415,
    "NotFrozen": 416,
    "StaleControl": 417,
    "NotInitialized": 418,
    "AlreadyInitialized": 419,
    "BadControl": 420,
    "BadNonce": 425,
    "NothingToDo": 428,
    "BadConfig": 429,
    "Equivocated": 433,
    "LatchRequired": 434,
    "TooManyCertificates": None,
    "NonCanonicalCalldata": None,
    "AlreadyConsumed": None,
}
TON_ONLY_ERROR_CODES = {
    "BadSnake": 421,
    "BucketNotDeployed": 422,
    "NotMinter": 423,
    "NotBucket": 424,
    "BadRange": 426,
    "BadBurnPayload": 427,
    "BucketNotActive": 430,
    "NothingToRetry": 431,
}


def selectors_json() -> dict:
    """§5.2.2 selectors recomputed with the independent Keccak and asserted against the specification."""
    out = {}
    for name, signature, expected in SELECTORS:
        computed = selector(signature).hex()
        if computed != expected:
            raise AssertionError(f"{name}: selector {computed} differs from the specification value {expected}")
        out[name] = {"signature": signature, "selector": "0x" + computed}
    return out


def committee(j: int) -> Committee:
    """`K<j>`: test keys 40 + 4j … 43 + 4j (n = 4)."""
    return Committee(f"K{j}", tuple(range(40 + 4 * j, 44 + 4 * j)))


class _Env:
    """A Taira route with generation 5 (`K0`) pinned at height 1000, time `T0`.

    `ton_route` is the route Taira's leaves are built for: the TON route for a scenario its author wrote for
    TON, the Ethereum route otherwise. `flavor` is the flavor of the destination. The two differ only in the
    replay pass, which runs an EVM-authored scenario on a TON destination to decide `ton_replayable`: the
    certificates stay those of the Ethereum route, and the destination is a TON minter.
    """

    def __init__(self, pool: CertificatePool, flavor: str = "evm", validity: int = VALIDITY, ton_route: bool | None = None):
        self.flavor = flavor
        self.ton_route = flavor == "ton" if ton_route is None else ton_route
        self.k = [committee(0)]
        self.recipient = TON_RECIPIENT if self.ton_route else RECIPIENT
        if self.ton_route:
            self.sim = TairaSim(NETWORK_ID, INSTANCE, TON, TON_DESTINATION_WORD)
        else:
            self.sim = TairaSim(NETWORK_ID, INSTANCE, ETHEREUM, EVM_DESTINATION_WORD)
        self.sim.start(PIN_GENERATION, self.k[0], PIN_START, T0, validity)
        self.pool = pool
        self.pin_until = T0 + validity

    def k_(self, j: int) -> Committee:
        while len(self.k) <= j:
            self.k.append(committee(len(self.k)))
        return self.k[j]

    def deployment(self) -> Deployment:
        return Deployment(
            flavor=self.flavor,
            taira_network_id=NETWORK_ID,
            consensus_instance=INSTANCE,
            network=TON if self.flavor == "ton" else ETHEREUM,
            destination_word=TON_DESTINATION_WORD if self.flavor == "ton" else EVM_DESTINATION_WORD,
            route_revision=1,
            max_wrapped_supply=10 * 10**9,
            pin_generation=PIN_GENERATION,
            pin_root=self.k[0].root,
            pin_start_height=PIN_START,
            pin_until_ms=self.pin_until,
            pin_keys=self.k[0].keys,
        )

    def scenario(self, name: str, description: str) -> Scenario:
        return Scenario(name, description, self.deployment(), self.pool, getattr(self, "strict", True))

    def block(self, height: int, ts: int, leaves=None, **kw):
        return self.sim.block(height, ts, leaves, **kw)

    def transfer(self, nonce: int, amount: int, deadline_ms: int):
        """A transfer of the route to its recipient."""
        return self.sim.transfer(nonce, amount, deadline_ms, self.recipient)

    def cert(self, block_or_header, signer: Committee | None = None, label: str | None = None, next_committee=None, **kw):
        header = getattr(block_or_header, "header", block_or_header)
        signer = signer or getattr(block_or_header, "generation").committee
        cert = self.sim.certify(header, signer, **kw)
        return (cert, label or f"X_{header.height}", signer.name, next_committee)

    def forged(self, height: int, ts: int, generation: int, signer: Committee, flags: int = FLAG_ACTIVE, **fields):
        """An `X` Taira never certified, signed by `signer` (an attacker holding that quorum)."""
        from .finality import FinalityHeader

        header = FinalityHeader(
            network_id=NETWORK_ID,
            height=height,
            timestamp_ms=ts,
            flags=flags,
            generation=generation,
            committee_root=signer.root,
            **fields,
        )
        return self.cert(header, signer, label=f"forged_X_{height}")


def _inline(c):
    cert, label, signer, _ = c
    return ("inline", (cert, label, signer))


def build_scenarios(pool: CertificatePool, default_flavor: str = "evm") -> tuple[list[Scenario], dict]:
    """Build every scenario; `default_flavor` re-runs the EVM rows under the TON model for `ton_replayable`."""
    out: list[Scenario] = []
    committees: dict[str, Committee] = {}

    class Env(_Env):  # noqa: N801 - local default flavor
        def __init__(self, pool_, flavor=None, validity=VALIDITY):
            # The route follows the flavor the author chose; the replay pass changes the destination only.
            super().__init__(pool_, flavor or default_flavor, validity, ton_route=flavor == "ton")
            self.strict = default_flavor == "evm"

    def remember(env: Env):
        for k in env.k:
            committees[k.name] = k

    # 1. Initial pin.
    env = Env(pool)
    sc = env.scenario(
        "initial_pin",
        "the state a constructor (EVM) or sccp_init (TON) leaves: cur from the pin, high = start − 1"
    )
    sc.views(T0 + MINUTE)
    out.append(sc)

    # 2. A checkpoint raises high and leaves untilMs unchanged; a CUR certificate at or below high.
    env = Env(pool)
    b1 = env.block(1005, T0 + 5 * SECOND)
    b2 = env.block(1020, T0 + 20 * SECOND)
    sc = env.scenario(
        "checkpoint_raises_high",
        "a non-rotation CUR certificate records its checkpoint and raises high; untilMs is unchanged;"
        " a CUR certificate below high records a checkpoint without moving high; a replay changes "
        "nothing"
    )
    sc.submit([env.cert(b2)], T0 + MINUTE, "ok")
    sc.submit([env.cert(b1)], T0 + MINUTE, "ok")
    sc.submit([env.cert(b1)], T0 + 2 * MINUTE, "NothingToDo")
    out.append(sc)

    # 3. Rotation at a key change; 4. heartbeat; 5. lowered validity.
    env = Env(pool)
    k1 = env.k_(1)
    rot = env.block(1100, T0 + HOUR, rotate="key", next_committee=k1)
    after = env.block(1101, T0 + HOUR + SECOND)
    sc = env.scenario(
        "rotation_key_change",
        "a ROTATION certificate of the current generation installs generation 6 with untilMs = "
        "t_eff(X) + validity_ms; the successor's certificates are then CUR"
    )
    sc.submit([env.cert(rot, next_committee=k1)], T0 + HOUR + MINUTE, "ok")
    sc.submit([env.cert(after)], T0 + HOUR + 2 * MINUTE, "ok")
    out.append(sc)
    remember(env)

    env = Env(pool)
    hb = env.block(1100, T0 + DAY, rotate="heartbeat")
    sc = env.scenario(
        "heartbeat_rotation",
        "a heartbeat (next_committee_root = committee_root) installs generation 6 with the same keys "
        "and a fresh deadline"
    )
    sc.submit([env.cert(hb)], T0 + DAY + MINUTE, "ok")
    out.append(sc)

    env = Env(pool)
    k1 = env.k_(1)
    low = env.block(1100, T0 + HOUR, rotate="key", next_committee=k1, validity_ms=3 * DAY)
    sc = env.scenario(
        "rotation_lowered_validity",
        "a rotation with validity_ms = 3 d gives the successor a deadline earlier than its "
        "predecessor's"
    )
    sc.submit([env.cert(low, next_committee=k1)], T0 + HOUR + MINUTE, "ok")
    assert sc.dest.state.until_ms == T0 + HOUR + 3 * DAY
    sc.views(T0 + HOUR + 3 * DAY)  # now_ms = untilMs: still Live
    sc.views(T0 + HOUR + 3 * DAY + SECOND)  # the next clock value: Frozen
    out.append(sc)
    remember(env)

    # 6. A rotation whose successor deadline already passed.
    env = Env(pool)
    k1 = env.k_(1)
    late = env.block(1100, T0 + HOUR, rotate="key", next_committee=k1, validity_ms=DAY)
    later = env.block(1101, T0 + HOUR + SECOND)
    sc = env.scenario(
        "rotation_successor_already_expired",
        "a destination lagging past the successor's deadline applies the rotation, becomes Frozen and"
        " stops processing; then voids drain it"
    )
    sc.submit([env.cert(late, next_committee=k1), env.cert(later)], T0 + 3 * DAY, "ok")
    sc.submit([env.cert(later)], T0 + 3 * DAY, "CommitteeNotAccepted")
    sc.void_frozen(0, 3, T0 + 3 * DAY, "ok")
    out.append(sc)
    remember(env)

    # 7. Sixteen batched rotations, then seventeen certificates.
    env = Env(pool)
    certs = []
    for j in range(16):
        nxt = env.k_(j + 1)
        blk = env.block(1100 + 100 * j, T0 + (j + 1) * HOUR, rotate="key", next_committee=nxt)
        certs.append(env.cert(blk, next_committee=nxt))
    sc = env.scenario(
        "sixteen_batched_rotations",
        "16 rotations K0 → K16 in one submitCheckpoints call; 17 certificates revert "
        "TooManyCertificates"
    )
    sc.submit(certs, T0 + 17 * HOUR, "ok")
    extra = env.block(2700, T0 + 17 * HOUR)
    sc.submit(certs + [env.cert(extra)], T0 + 17 * HOUR, "TooManyCertificates")
    assert len(certs) == MAX_CERTIFICATES_PER_CALL
    out.append(sc)
    remember(env)

    # 8. K → K′ → K, then an old generation with the same root.
    env = Env(pool)
    k0, k1 = env.k_(0), env.k_(1)
    old = env.block(1050, T0 + MINUTE)
    r1 = env.block(1100, T0 + HOUR, rotate="key", next_committee=k1)
    r2 = env.block(1200, T0 + 2 * HOUR, rotate="key", next_committee=k0)
    sc = env.scenario(
        "k_kprime_k",
        "K → K′ → K: generation 7 has K's root again; a genuine certificate of generation 5 (same "
        "root) is refused"
    )
    sc.submit([env.cert(r1, next_committee=k1), env.cert(r2, next_committee=k0)], T0 + 2 * HOUR + MINUTE, "ok")
    sc.submit([env.cert(old)], T0 + 2 * HOUR + MINUTE, "CommitteeNotAccepted")
    out.append(sc)
    remember(env)

    # 9. A future-dated certificate replayed across several validity periods.
    env = Env(pool)
    future = env.forged(1010, T0 + 30 * DAY, PIN_GENERATION, env.k[0], message_count=0)
    sc = env.scenario(
        "future_dated_replay_no_extension",
        "a future-dated non-rotation certificate is accepted but never extends untilMs; replays "
        "change nothing; after the pin's deadline it is refused and voidFrozen opens"
    )
    sc.submit([future], T0 + HOUR, "ok")
    sc.submit([future], T0 + 7 * DAY, "NothingToDo")
    sc.submit([future], T0 + VALIDITY, "NothingToDo")  # now_ms = untilMs: still Live
    sc.submit([future], T0 + VALIDITY + SECOND, "CommitteeNotAccepted")  # the next clock value
    sc.void_frozen(0, 1, T0 + VALIDITY + SECOND, "ok")
    out.append(sc)

    # 10. Forged in-generation heights after the genuine end, then the genuine handoff (V3).
    env = Env(pool)
    k1 = env.k_(1)
    handoff = env.block(1100, T0 + HOUR, rotate="key", next_committee=k1)
    f1 = env.forged(1101, T0 + HOUR + SECOND, PIN_GENERATION, env.k[0])
    f2 = env.forged(1102, T0 + HOUR + 2 * SECOND, PIN_GENERATION, env.k[0])
    sc = env.scenario(
        "forged_heights_then_genuine_handoff_latches",
        "a departed quorum of generation 5 signs heights above its genuine end: accepted (bounded); "
        "the genuine handoff then trips V3 and latches; voidFrozen opens"
    )
    sc.submit([f1, f2], T0 + HOUR + MINUTE, "ok")
    sc.submit([env.cert(handoff, next_committee=k1)], T0 + HOUR + 2 * MINUTE, "ok")
    sc.void_frozen(5, 2, T0 + HOUR + 3 * MINUTE, "ok")
    sc.submit([env.cert(env.block(1110, T0 + HOUR + 10 * SECOND))], T0 + HOUR + 4 * MINUTE, "Equivocated")
    out.append(sc)
    remember(env)

    # 11. Old generations refused after every genuine rotation is applied.
    env = Env(pool)
    k1, k2 = env.k_(1), env.k_(2)
    g5 = env.block(1050, T0 + MINUTE)
    rot5 = env.block(1100, T0 + HOUR, rotate="key", next_committee=k1)
    g6 = env.block(1150, T0 + HOUR + MINUTE)
    rot6 = env.block(1200, T0 + 2 * HOUR, rotate="key", next_committee=k2)
    forged_old = env.forged(1300, T0 + 3 * HOUR, PIN_GENERATION, env.k[0], flags=FLAG_ACTIVE | FLAG_ROTATION,
                            validity_ms=VALIDITY, next_committee_root=env.k[0].root)
    sc = env.scenario(
        "old_generations_refused",
        "after generations 6 and 7 are installed, genuine and forged certificates of generations 5 "
        "and 6 (any height, ROTATION or not) are refused with no state change"
    )
    sc.submit([env.cert(rot5, next_committee=k1), env.cert(rot6, next_committee=k2)], T0 + 2 * HOUR + MINUTE, "ok")
    sc.submit([env.cert(g5)], T0 + 2 * HOUR + MINUTE, "CommitteeNotAccepted")
    sc.submit([env.cert(g6)], T0 + 2 * HOUR + MINUTE, "CommitteeNotAccepted")
    sc.submit([env.cert(rot5, next_committee=k1)], T0 + 2 * HOUR + MINUTE, "CommitteeNotAccepted")
    sc.submit([forged_old], T0 + 2 * HOUR + MINUTE, "CommitteeNotAccepted")
    out.append(sc)
    remember(env)

    # 12. V1 positive and neighbour.
    env = Env(pool)
    genuine = env.block(1030, T0 + 30 * SECOND)
    conflicting = env.forged(1030, T0 + 30 * SECOND, PIN_GENERATION, env.k[0], message_count=1, sccp_root=rep(0xEE))
    sc = env.scenario(
        "v1_two_x_at_one_height",
        "V1: a second, different X at a recorded height signed by cur latches with reason 1"
    )
    sc.submit([env.cert(genuine)], T0 + MINUTE, "ok")
    sc.submit([conflicting], T0 + 2 * MINUTE, "ok")
    sc.void_frozen(0, 1, T0 + 3 * MINUTE, "ok")
    out.append(sc)

    env = Env(pool)
    genuine = env.block(1030, T0 + 30 * SECOND)
    sc = env.scenario(
        "v1_neighbour_same_x_other_result_body",
        "the same X with a different result_body (signed) records nothing and does not latch"
    )
    sc.submit([env.cert(genuine)], T0 + MINUTE, "ok")
    sc.submit([env.cert(genuine, body_tag=b"/other")], T0 + 2 * MINUTE, "NothingToDo")
    out.append(sc)

    # 13. V2 positive and neighbour.
    env = Env(pool)
    sc = env.scenario("v2_below_start", "V2: a CUR certificate below cur.start latches with reason 2")
    sc.submit([env.forged(999, T0 - SECOND, PIN_GENERATION, env.k[0])], T0 + MINUTE, "ok")
    out.append(sc)

    env = Env(pool)
    sc = env.scenario("v2_neighbour_at_start", "a CUR certificate at exactly cur.start is accepted")
    sc.submit([env.cert(env.block(1000, T0))], T0 + MINUTE, "ok")
    out.append(sc)

    # 14. V3 positive and neighbour.
    env = Env(pool)
    k1 = env.k_(1)
    high = env.block(1060, T0 + MINUTE)
    sc = env.scenario(
        "v3_rotation_below_high",
        "V3: a ROTATION certificate below cur.high latches with reason 3"
    )
    sc.submit([env.cert(high)], T0 + 2 * MINUTE, "ok")
    sc.submit([env.forged(1050, T0 + 50 * SECOND, PIN_GENERATION, env.k[0], flags=FLAG_ACTIVE | FLAG_ROTATION,
                          validity_ms=VALIDITY, next_committee_root=k1.root)], T0 + 3 * MINUTE, "ok")
    out.append(sc)
    remember(env)

    env = Env(pool)
    k1 = env.k_(1)
    recipient = RECIPIENT
    rot = env.block(1060, T0 + MINUTE, [env.sim.transfer(0, 10**9, T0 + DAY, recipient)], rotate="key", next_committee=k1)
    rot_cert = env.cert(rot, next_committee=k1)
    sc = env.scenario(
        "v3_neighbour_rotation_at_high",
        "the handoff used inline first (finalizeFromTaira records it and raises high to its height "
        "without installing), then submitted: ROTATION at height = high installs"
    )
    sc.finalize(_inline(rot_cert), env.sim.message_proof(1060, 0, rot.header), T0 + 2 * MINUTE, "ok")
    sc.submit([rot_cert], T0 + 3 * MINUTE, "ok")
    out.append(sc)
    remember(env)

    # 15. Expiry, then refusal, then voidFrozen.
    env = Env(pool)
    blk = env.block(1010, T0 + 10 * SECOND, [env.sim.transfer(0, 10**9, T0 + 20 * DAY, RECIPIENT)])
    sc = env.scenario(
        "expiry_then_refusal_then_void_frozen",
        "at untilMs the destination is still Live; at the next clock value (one second later) "
        "submitCheckpoints and finalize are refused, voidFrozen voids, a second voidFrozen of the same "
        "nonce reverts"
    )
    sc.void_frozen(0, 1, T0 + VALIDITY, "NotFrozen")
    sc.submit([env.cert(blk)], T0 + VALIDITY, "ok")
    sc.submit([env.cert(env.block(1011, T0 + 11 * SECOND))], T0 + VALIDITY + SECOND, "CommitteeNotAccepted")
    sc.finalize(("checkpoint", blk.x), env.sim.message_proof(1010, 0, blk.header), T0 + VALIDITY + SECOND, "CommitteeNotAccepted")
    sc.void_frozen(0, 2, T0 + VALIDITY + SECOND, "ok")
    sc.void_frozen(1, 1, T0 + VALIDITY + 2 * SECOND, "AlreadyConsumed")
    sc.void_frozen(10, 0, T0 + VALIDITY + 2 * SECOND, "BadAmount")
    sc.void_frozen(10, 257, T0 + VALIDITY + 2 * SECOND, "BadAmount")
    sc.void_frozen(U64_MAX, 2, T0 + VALIDITY + 2 * SECOND, "BadAmount")
    out.append(sc)

    # 16. A latch inside a batch.
    env = Env(pool)
    a = env.block(1010, T0 + 10 * SECOND)
    c = env.block(1020, T0 + 20 * SECOND)
    sc = env.scenario(
        "latch_inside_batch",
        "[ok, V2 violation, ok]: the first is applied, the latch persists and the third is not "
        "processed"
    )
    sc.submit([env.cert(a), env.forged(990, T0 - 10 * SECOND, PIN_GENERATION, env.k[0]), env.cert(c)], T0 + MINUTE, "ok")
    out.append(sc)

    # 17. Inline V3 gives LatchRequired, then submitCheckpoints latches.
    env = Env(pool)
    k1 = env.k_(1)
    handoff = env.block(1100, T0 + HOUR, [env.sim.transfer(0, 10**9, T0 + DAY, RECIPIENT)], rotate="key", next_committee=k1)
    forged = env.forged(1102, T0 + HOUR + 2 * SECOND, PIN_GENERATION, env.k[0])
    handoff_cert = env.cert(handoff, next_committee=k1)
    sc = env.scenario(
        "inline_v3_latch_required_then_submit_latches",
        "an inline use of a violating certificate reverts LatchRequired; the relayer resubmits it "
        "through submitCheckpoints, which latches"
    )
    sc.submit([forged], T0 + HOUR + MINUTE, "ok")
    sc.finalize(_inline(handoff_cert), env.sim.message_proof(1100, 0, handoff.header), T0 + HOUR + 2 * MINUTE, "LatchRequired")
    sc.submit([handoff_cert], T0 + HOUR + 3 * MINUTE, "ok")
    out.append(sc)
    remember(env)

    # 18. A future-dated rotation: t_eff caps the successor's start at now.
    env = Env(pool)
    k1 = env.k_(1)
    fut = env.block(1100, T0 + 10 * DAY, rotate="key", next_committee=k1)
    sc = env.scenario(
        "future_dated_rotation_t_eff",
        "a rotation X timed 10 d ahead installs untilMs = now + validity_ms (t_eff = "
        "min(X.timestamp_ms, now))"
    )
    sc.submit([env.cert(fut, next_committee=k1)], T0 + HOUR, "ok")
    assert sc.dest.state.until_ms == T0 + HOUR + VALIDITY
    out.append(sc)
    remember(env)

    # 19. Finalization, history proofs, supply cap and voids.
    env = Env(pool)
    sim = env.sim
    b10 = env.block(
        1010,
        T0 + 10 * SECOND,
        [
            sim.transfer(0, 2 * 10**9, T0 + DAY, RECIPIENT),
            sim.transfer(1, 3 * 10**9, T0 + DAY, RECIPIENT),
            sim.transfer(2, 10**9, T0 + HOUR, RECIPIENT),
        ],
    )
    env.block(
        1020,
        T0 + 20 * SECOND,
        [sim.transfer(3, 4 * 10**9, T0 + DAY, RECIPIENT), sim.transfer(4, 2 * 10**9, T0 + DAY, RECIPIENT)],
    )
    b50 = env.block(1050, T0 + 50 * SECOND)
    bad_recipient = env.block(1060, T0 + 60 * SECOND, [sim.transfer(5, 10**9, T0 + DAY, EVM_DESTINATION_WORD[12:])])
    sc = env.scenario(
        "finalize_proofs_cap_and_voids",
        "inline and checkpoint finalization, a history proof, replay, deadline, recipient, supply-cap"
        " and proof failures, and voidExpired"
    )
    sc.finalize(_inline(env.cert(b10)), sim.message_proof(1010, 0, b10.header), T0 + MINUTE, "ok")
    sc.finalize(("checkpoint", b10.x), sim.message_proof(1010, 1, b10.header), T0 + MINUTE, "ok")
    sc.finalize(("checkpoint", b10.x), sim.message_proof(1010, 0, b10.header), T0 + MINUTE, "AlreadyConsumed")
    sc.finalize(_inline(env.cert(b50)), sim.message_proof(1020, 0, b50.header), T0 + 2 * MINUTE, "ok")
    sc.finalize(("checkpoint", b50.x), sim.message_proof(1020, 1, b50.header), T0 + 2 * MINUTE, "SupplyCapExceeded")
    wrong_path = sim.message_proof(1010, 2, b10.header)
    wrong_path.path = [rep(0xAB)] + wrong_path.path[1:]
    sc.finalize(("checkpoint", b10.x), wrong_path, T0 + 2 * MINUTE, "BadProof")
    # Transfer 2 has deadline_ms = T0 + HOUR: at that clock value a void is early, at the next one a finalization is late.
    sc.void_expired(2, ("checkpoint", b10.x), sim.message_proof(1010, 2, b10.header), T0 + HOUR, "DeadlineNotReached")
    sc.finalize(("checkpoint", b10.x), sim.message_proof(1010, 2, b10.header), T0 + HOUR + SECOND, "DeadlinePassed")
    sc.void_expired(1, ("checkpoint", b10.x), sim.message_proof(1010, 2, b10.header), T0 + HOUR + SECOND, "BadNonce")
    sc.void_expired(2, ("checkpoint", b10.x), sim.message_proof(1010, 2, b10.header), T0 + HOUR + SECOND, "ok")
    sc.void_expired(2, ("checkpoint", b10.x), sim.message_proof(1010, 2, b10.header), T0 + HOUR + 2 * SECOND, "AlreadyConsumed")
    late = T0 + HOUR + 2 * SECOND
    sc.finalize(("checkpoint", bad_recipient.x), sim.message_proof(1060, 0, bad_recipient.header), late, "UnknownCheckpoint")
    sc.finalize(_inline(env.cert(bad_recipient)), sim.message_proof(1060, 0, bad_recipient.header), late, "BadRecipient")
    sc.void_frozen(10, 1, late, "NotFrozen")
    out.append(sc)

    # TON-flavored rows: next_keys, heartbeat without next_keys, checkpoint eviction ordering.
    env = Env(pool, flavor="ton")
    k1 = env.k_(1)
    rot = env.block(1100, T0 + HOUR, rotate="key", next_committee=k1)
    hb = env.block(1200, T0 + DAY + HOUR, rotate="heartbeat")
    rc = env.cert(rot, next_committee=k1)
    sc = env.scenario(
        "ton_rotation_next_keys",
        "TON: a key-changing rotation needs next_keys hashing to X.next_committee_root (missing or "
        "wrong → BadCommittee); a heartbeat keeps the stored keys without next_keys"
    )
    sc.submit([(rc[0], rc[1], rc[2], None)], T0 + HOUR + MINUTE, "BadCommittee")
    sc.submit([(rc[0], rc[1], rc[2], env.k_(2))], T0 + HOUR + MINUTE, "BadCommittee")
    sc.submit([rc], T0 + HOUR + MINUTE, "ok")
    sc.submit([env.cert(hb)], T0 + DAY + HOUR + MINUTE, "ok")
    out.append(sc)
    remember(env)

    env = Env(pool, flavor="ton")
    blocks = {h: env.block(h, T0 + (h - 1000) * SECOND) for h in (1010, 1015, 1020, 1030, 1040)}
    stray = env.block(1005, T0 + 5 * SECOND)
    sc = env.scenario(
        "ton_checkpoint_eviction",
        "TON keeps three checkpoints: a higher height evicts the lowest, a height at or below the "
        "lowest is not stored, conflicts are detected only for retained entries, an evicted "
        "checkpoint is unknown"
    )
    for h in (1010, 1020, 1030):
        sc.submit([env.cert(blocks[h])], T0 + 2 * MINUTE, "ok")
    sc.submit([env.cert(blocks[1015])], T0 + 2 * MINUTE, "ok")
    sc.submit([env.cert(stray)], T0 + 2 * MINUTE, "NothingToDo")
    sc.submit([env.cert(blocks[1040])], T0 + 2 * MINUTE, "ok")
    sc.submit([env.forged(1010, T0 + 10 * SECOND, PIN_GENERATION, env.k[0], message_count=1, sccp_root=rep(0xEE))], T0 + 3 * MINUTE, "NothingToDo")
    sc.finalize(("checkpoint", blocks[1015].x), _dummy_proof(env, blocks[1015]), T0 + 3 * MINUTE, "UnknownCheckpoint")
    sc.submit([env.forged(1030, T0 + 30 * SECOND, PIN_GENERATION, env.k[0], message_count=1, sccp_root=rep(0xEE))], T0 + 4 * MINUTE, "ok")
    out.append(sc)

    # A sub-second Taira timestamp against the whole-second destination clock. The row is EVM-flavored; it comes
    # after the TON rows so that the pool ids of the certificates above do not move.
    env = Env(pool)
    k1 = env.k_(1)
    rot = env.block(1100, T0 + HOUR + 999, rotate="key", next_committee=k1)
    after = env.block(1101, T0 + HOUR + 2 * SECOND)
    later = env.block(1102, T0 + HOUR + 3 * SECOND)
    until = T0 + HOUR + 999 + VALIDITY
    sc = env.scenario(
        "rotation_sub_second_deadline",
        "a rotation X with a sub-second timestamp_ms installs the sub-second untilMs = t_eff(X) + "
        "validity_ms; the whole-second destination clock is Live at the last second at or below untilMs "
        "and Frozen at the next one, which is untilMs + 1 ms"
    )
    sc.submit([env.cert(rot, next_committee=k1)], T0 + HOUR + MINUTE, "ok")
    assert sc.dest.state.until_ms == until and until % SECOND == 999
    sc.submit([env.cert(after)], until - 999, "ok")
    sc.submit([env.cert(later)], until + 1, "CommitteeNotAccepted")
    out.append(sc)
    remember(env)

    # The scenarios below were added after the rows above; they come last so that no pool id above moves.

    # The mandatory cheap path (§5.1.3 step 8), and the identity signature that step 6 refuses before it. The
    # second row is TON-flavored: the two flavors must agree on a certificate whose X is already stored.
    for flavor, name in ((None, "cheap_path_identity_signature"), ("ton", "ton_cheap_path_identity_signature")):
        env = Env(pool, flavor=flavor)
        blk = env.block(1010, T0 + 10 * SECOND)
        genuine = env.cert(blk)
        other_instance = env.cert(blk, label="X_1010_other_instance_signature", signed_instance=rep(0x78))
        identity = (
            dataclasses.replace(genuine[0], signature_evm=bytes(192), signature_ton=IDENTITY_SIGNATURE_COMPRESSED),
            "X_1010_identity_signature",
            genuine[2],
            None,
        )
        sc = env.scenario(
            name,
            "the cheap path is mandatory and observable: a certificate of X whose signature covers another "
            "instance is refused while X is not stored and accepted without a signature check once it is "
            "(nothing changes, so NothingToDo); the identity signature is refused before the cheap path"
        )
        sc.submit([other_instance], T0 + MINUTE, "BadSignature")
        sc.submit([genuine], T0 + MINUTE, "ok")
        sc.submit([other_instance], T0 + 2 * MINUTE, "NothingToDo")
        sc.submit([identity], T0 + 2 * MINUTE, "BadSignature")
        out.append(sc)

    # Payload deadlines: a finalization needs now_ms ≤ deadline_ms and a void now_ms > deadline_ms.
    env = Env(pool)
    sim = env.sim
    whole = T0 + HOUR
    sub_second = T0 + 2 * HOUR + 999
    blk = env.block(
        1010,
        T0 + 10 * SECOND,
        [
            sim.transfer(0, 10**9, whole, RECIPIENT),
            sim.transfer(1, 10**9, whole, RECIPIENT),
            sim.transfer(2, 10**9, sub_second, RECIPIENT),
            sim.transfer(3, 10**9, sub_second, RECIPIENT),
        ],
    )
    stored = ("checkpoint", blk.x)
    sc = env.scenario(
        "transfer_deadline_boundaries",
        "a whole-second deadline_ms: at it a finalization is accepted and a void is early, one second later the "
        "finalization is late and the void is accepted; a deadline_ms ending in 999 ms: the same pairs at the last "
        "clock value below it (999 ms earlier) and at the next one (1 ms later)"
    )
    sc.submit([env.cert(blk)], T0 + MINUTE, "ok")
    sc.finalize(stored, sim.message_proof(1010, 0, blk.header), whole, "ok")
    sc.void_expired(1, stored, sim.message_proof(1010, 1, blk.header), whole, "DeadlineNotReached")
    sc.finalize(stored, sim.message_proof(1010, 1, blk.header), whole + SECOND, "DeadlinePassed")
    sc.void_expired(1, stored, sim.message_proof(1010, 1, blk.header), whole + SECOND, "ok")
    assert sub_second % SECOND == 999
    sc.finalize(stored, sim.message_proof(1010, 2, blk.header), sub_second - 999, "ok")
    sc.void_expired(3, stored, sim.message_proof(1010, 3, blk.header), sub_second - 999, "DeadlineNotReached")
    sc.finalize(stored, sim.message_proof(1010, 3, blk.header), sub_second + 1, "DeadlinePassed")
    sc.void_expired(3, stored, sim.message_proof(1010, 3, blk.header), sub_second + 1, "ok")
    out.append(sc)

    # Checkpoint use after a rotation (§5.1.3): U1 (a header of the current generation) or U2 (the handoff that
    # installed it). Messages and controls of a retired generation are proven under the handoff, with a history proof.
    env = Env(pool)
    sim = env.sim
    k1, k2 = env.k_(1), env.k_(2)
    b10 = env.block(
        1010,
        T0 + 10 * SECOND,
        [
            sim.control(1, 1, 0, 0, rep(0xC1), rep(0xE1)),
            sim.transfer(0, 10**9, T0 + DAY, RECIPIENT),
            sim.transfer(1, 10**9, T0 + DAY, RECIPIENT),
            sim.transfer(2, 10**9, T0 + 90 * MINUTE, RECIPIENT),
            sim.transfer(3, 10**9, T0 + DAY, RECIPIENT),
        ],
    )
    rot5 = env.block(1100, T0 + HOUR, rotate="key", next_committee=k1)
    b1150 = env.block(1150, T0 + HOUR + MINUTE, [sim.transfer(4, 10**9, T0 + DAY, RECIPIENT)])
    rot6 = env.block(1200, T0 + 2 * HOUR, rotate="key", next_committee=k2)
    sc = env.scenario(
        "checkpoint_use_after_rotation",
        "a stored checkpoint is usable while its header is of the current generation (U1) or is the handoff "
        "that installed it (U2): after the handoff of generation 5 is installed, a non-handoff checkpoint of "
        "generation 5 is refused for finalize, control and void while the handoff checkpoint proves the same "
        "leaves through its history root; after generation 7 is installed the handoff of generation 5 and every "
        "non-handoff checkpoint of generations 5 and 6 are refused, and the handoff of generation 6 is usable"
    )
    now = T0 + MINUTE
    sc.submit([env.cert(b10)], now, "ok")
    sc.finalize(("checkpoint", b10.x), sim.message_proof(1010, 1, b10.header), now, "ok")
    now = T0 + HOUR + MINUTE
    sc.submit([env.cert(rot5, next_committee=k1)], now, "ok")
    sc.finalize(("checkpoint", b10.x), sim.message_proof(1010, 2, b10.header), now, "CommitteeNotAccepted")
    sc.apply_control(("checkpoint", b10.x), sim.control_proof(1010, 0, b10.header), now, "CommitteeNotAccepted")
    sc.finalize(("checkpoint", rot5.x), sim.message_proof(1010, 2, rot5.header), now, "ok")
    sc.apply_control(("checkpoint", rot5.x), sim.control_proof(1010, 0, rot5.header), now, "ok")
    now = T0 + 2 * HOUR
    sc.void_expired(2, ("checkpoint", b10.x), sim.message_proof(1010, 3, b10.header), now, "CommitteeNotAccepted")
    sc.void_expired(2, ("checkpoint", rot5.x), sim.message_proof(1010, 3, rot5.header), now, "ok")
    now = T0 + 2 * HOUR + MINUTE
    sc.submit([env.cert(b1150), env.cert(rot6, next_committee=k2)], now, "ok")
    sc.finalize(("checkpoint", rot5.x), sim.message_proof(1010, 4, rot5.header), now, "CommitteeNotAccepted")
    sc.finalize(("checkpoint", b10.x), sim.message_proof(1010, 4, b10.header), now, "CommitteeNotAccepted")
    sc.finalize(("checkpoint", b1150.x), sim.message_proof(1010, 4, b1150.header), now, "CommitteeNotAccepted")
    sc.finalize(("checkpoint", rot6.x), sim.message_proof(1010, 4, rot6.header), now, "ok")
    out.append(sc)
    remember(env)

    # The same rule on TON, with the calls its minter decides alone: the checks of a finalization that precede
    # the bucket, and controls.
    env = Env(pool, flavor="ton")
    sim = env.sim
    k1, k2 = env.k_(1), env.k_(2)
    b10 = env.block(
        1010,
        T0 + 10 * SECOND,
        [
            sim.control(1, 1, 0, 0, rep(0xC1), rep(0xE1)),
            sim.control(2, 1, 0, 0, rep(0xC2), rep(0xE2)),
            env.transfer(0, 10**9, T0 + DAY),
        ],
    )
    rot5 = env.block(1100, T0 + HOUR, rotate="key", next_committee=k1)
    rot6 = env.block(1200, T0 + 2 * HOUR, rotate="key", next_committee=k2)
    sc = env.scenario(
        "ton_checkpoint_use_after_rotation",
        "TON: after the handoff of generation 5 is installed its non-handoff checkpoint is refused and the "
        "handoff checkpoint applies the control through its history root; after generation 7 is installed the "
        "handoff of generation 5 is refused and the handoff of generation 6 is usable"
    )
    now = T0 + HOUR + MINUTE
    sc.submit([env.cert(b10)], now, "ok")
    sc.submit([env.cert(rot5, next_committee=k1)], now, "ok")
    sc.apply_control(("checkpoint", b10.x), sim.control_proof(1010, 0, b10.header), now, "CommitteeNotAccepted")
    sc.finalize(("checkpoint", b10.x), sim.message_proof(1010, 2, b10.header), now, "CommitteeNotAccepted")
    sc.apply_control(("checkpoint", rot5.x), sim.control_proof(1010, 0, rot5.header), now, "ok")
    now = T0 + 2 * HOUR + MINUTE
    sc.submit([env.cert(rot6, next_committee=k2)], now, "ok")
    sc.apply_control(("checkpoint", rot5.x), sim.control_proof(1010, 1, rot5.header), now, "CommitteeNotAccepted")
    sc.finalize(("checkpoint", rot5.x), sim.message_proof(1010, 2, rot5.header), now, "CommitteeNotAccepted")
    sc.apply_control(("checkpoint", rot6.x), sim.control_proof(1010, 1, rot6.header), now, "ok")
    out.append(sc)
    remember(env)

    # voidFrozen checks its range before Frozen (§5.1.8): every range failure on a Live destination, then a valid
    # range, which is NotFrozen. No certificate is involved.
    for flavor, name in ((None, "void_frozen_range_before_frozen"), ("ton", "ton_void_frozen_range_before_frozen")):
        env = Env(pool, flavor=flavor)
        sc = env.scenario(
            name,
            "voidFrozen on a Live destination: a range failure is reported before NotFrozen (count 0, a count above "
            "the bound, a range past 2^64 and, on TON, a range that crosses a 512-nonce bucket); a valid range is "
            "NotFrozen"
        )
        now = T0 + MINUTE
        if env.flavor == "evm":
            ranges = ((10, 0), (10, 257), (U64_MAX, 2))
        else:
            ranges = ((10, 0), (10, 513), (510, 4), (U64_MAX, 2))
        for first, count in ranges:
            sc.void_frozen(first, count, now, "BadAmount" if env.flavor == "evm" else "BadRange")
        sc.void_frozen(10, 1, now, "NotFrozen")
        out.append(sc)

    # Two faults in one call, which the check order decides. EVM obtains X first; the TON minter checks the payload
    # and its recipient before X (§5.3.4), because its required value depends on the payload nonce. On both
    # flavors the deadline is checked before the leaf path.
    for flavor, name in ((None, "finalize_two_faults"), ("ton", "ton_finalize_two_faults")):
        env = Env(pool, flavor=flavor)
        sim = env.sim
        evm = env.flavor == "evm"
        own_word = sim.destination_word
        to_contract = bytes(4) + own_word if env.ton_route else own_word[12:]
        blk = env.block(1010, T0 + 10 * SECOND, [env.transfer(0, 10**9, T0 + HOUR)])
        never_stored = env.block(1020, T0 + 20 * SECOND)
        other_revision = outbound_payload(sim.target, 0, 2, T0 + DAY, 10**9, b"\x01" + rep(0x5A, 33), env.recipient)
        own_recipient = outbound_payload(sim.target, 0, 1, T0 + DAY, 10**9, b"\x01" + rep(0x5A, 33), to_contract)
        unknown = ("checkpoint", never_stored.x)
        reference = BlockRef(never_stored.height, rep(0x01), 1)
        sc = env.scenario(
            name,
            "two faults in one call: a payload of another revision, or one that pays the contract itself, under a "
            "checkpoint that is not stored (EVM reports the checkpoint, the TON minter the payload); a finalization "
            "after the deadline with a wrong leaf path (the deadline is reported); a void with a wrong nonce "
            "argument under a checkpoint that is not stored"
        )
        sc.finalize(unknown, MessageProof(other_revision, 0, [], reference), T0 + MINUTE,
                    "UnknownCheckpoint" if evm else "BadPayload")
        sc.finalize(unknown, MessageProof(own_recipient, 0, [], reference), T0 + MINUTE,
                    "UnknownCheckpoint" if evm else "BadRecipient")
        sc.void_expired(7, unknown, MessageProof(other_revision, 0, [], reference), T0 + MINUTE,
                        "UnknownCheckpoint" if evm else "BadPayload")
        sc.submit([env.cert(blk)], T0 + MINUTE, "ok")
        late = sim.message_proof(1010, 0, blk.header)
        late.path = [rep(0xAB)]  # one sibling too many for a block of one leaf
        sc.finalize(("checkpoint", blk.x), late, T0 + HOUR + SECOND, "DeadlinePassed")
        out.append(sc)

    # Check orders that a single fault cannot show (EVM): the §3.4 constraints before the control nonce, a
    # consumed nonce before the supply cap, and the nonce argument of voidExpired before the consumed set.
    env = Env(pool)
    sim = env.sim
    blk = env.block(
        1010,
        T0 + 10 * SECOND,
        [
            sim.control(5, 1, 0, 0, rep(0xC5), rep(0xE5)),
            sim.control(3, 3, 0, 0, rep(0xC3), rep(0xE3), check=False),
            env.transfer(0, 10 * 10**9, T0 + HOUR),
        ],
    )
    stored = ("checkpoint", blk.x)
    sc = env.scenario(
        "check_order_two_faults",
        "a control leaf with track 3 and a nonce below the stored one is BadControl, not StaleControl; a "
        "finalization of a consumed nonce at a full supply cap is AlreadyConsumed, not SupplyCapExceeded; a "
        "voidExpired of a consumed payload with a wrong nonce argument is BadNonce, not AlreadyConsumed"
    )
    sc.submit([env.cert(blk)], T0 + MINUTE, "ok")
    sc.apply_control(stored, sim.control_proof(1010, 0, blk.header), T0 + MINUTE, "ok")
    sc.apply_control(stored, sim.control_proof(1010, 1, blk.header), T0 + MINUTE, "BadControl")
    sc.finalize(stored, sim.message_proof(1010, 2, blk.header), T0 + MINUTE, "ok")
    assert not env.strict or sc.dest.state.total_supply == sc.deployment.max_wrapped_supply  # the cap is full
    sc.finalize(stored, sim.message_proof(1010, 2, blk.header), T0 + MINUTE, "AlreadyConsumed")
    sc.void_expired(1, stored, sim.message_proof(1010, 2, blk.header), T0 + HOUR + SECOND, "BadNonce")
    sc.void_expired(0, stored, sim.message_proof(1010, 2, blk.header), T0 + HOUR + SECOND, "AlreadyConsumed")
    out.append(sc)

    # The encodings of step 6 are enforced on the cheap path too (EVM): the same stored X under a signer y that is
    # not reduced, a signer y of the other sign, and a σ limb that is not reduced.
    env = Env(pool)
    blk = env.block(1010, T0 + 10 * SECOND)
    genuine = env.cert(blk)
    cert = genuine[0]
    y0 = int.from_bytes(cert.signer_ys[:48], "big")
    limb0 = int.from_bytes(cert.signature_evm[:48], "big")

    def variant(label: str, **changes):
        return (dataclasses.replace(cert, **changes), f"X_1010_{label}", genuine[2], None)

    sc = env.scenario(
        "cheap_path_checks_encodings",
        "the encodings of step 6 are checked before the cheap path: once X is stored, the same certificate with "
        "signerYs[0] + p, with signerYs[0] = p − y (the other sign) or with the first σ limb + p is refused, and "
        "the unchanged certificate is accepted without a signature check (NothingToDo)"
    )
    sc.submit([genuine], T0 + MINUTE, "ok")
    sc.submit([variant("signer_y_ge_p", signer_ys=(y0 + P).to_bytes(48, "big") + cert.signer_ys[48:])],
              T0 + 2 * MINUTE, "BadCommittee")
    sc.submit([variant("signer_y_wrong_sign", signer_ys=(P - y0).to_bytes(48, "big") + cert.signer_ys[48:])],
              T0 + 2 * MINUTE, "BadCommittee")
    sc.submit([variant("sigma_limb_ge_p", signature_evm=(limb0 + P).to_bytes(48, "big") + cert.signature_evm[48:])],
              T0 + 2 * MINUTE, "BadSignature")
    sc.submit([genuine], T0 + 2 * MINUTE, "NothingToDo")
    out.append(sc)

    # A reference to the certified block itself carries no history proof (§5.1.5): historyIndex = 0 and an empty
    # historyPath. Each refused proof differs from an accepted one in that one field only. The TON row keeps to
    # what its minter decides alone: the refusals, and the control.
    for flavor, name in ((None, "same_height_block_ref_with_history"), ("ton", "ton_same_height_block_ref_with_history")):
        env = Env(pool, flavor=flavor)
        sim = env.sim
        blk = env.block(
            1010,
            T0 + 10 * SECOND,
            [
                sim.control(1, 1, 0, 0, rep(0xC1), rep(0xE1)),
                env.transfer(0, 10**9, T0 + DAY),
                env.transfer(1, 10**9, T0 + HOUR),
            ],
        )
        genuine = env.cert(blk)
        stored = ("checkpoint", blk.x)
        control = sim.control_proof(1010, 0, blk.header)
        mint = sim.message_proof(1010, 1, blk.header)
        void = sim.message_proof(1010, 2, blk.header)
        changes = ({"history_index": 1}, {"history_path": [rep(0xAB)]})

        def with_history(proof, change):
            return dataclasses.replace(proof, block=dataclasses.replace(proof.block, **change))

        sc = env.scenario(
            name,
            "a reference to the certified block itself carries no history proof: with historyIndex 1, or with a "
            "historyPath of one sibling, it is BadProof for an inline finalization and, under the stored checkpoint, "
            "for a control, a finalization and a void; the unchanged proofs are accepted (in the TON row the control "
            "only: a mint and a void end in the bucket)"
        )
        now = T0 + MINUTE
        sc.finalize(_inline(genuine), with_history(mint, changes[0]), now, "BadProof")
        sc.submit([genuine], now, "ok")
        for change in changes:
            sc.apply_control(stored, with_history(control, change), now, "BadProof")
        for change in changes:
            sc.finalize(stored, with_history(mint, change), now, "BadProof")
        late = T0 + HOUR + SECOND  # the first clock value after the deadline of transfer 1
        for change in changes:
            sc.void_expired(1, stored, with_history(void, change), late, "BadProof")
        sc.apply_control(stored, control, late, "ok")
        if env.flavor == "evm":
            sc.finalize(stored, mint, late, "ok")
            sc.void_expired(1, stored, void, late, "ok")
        out.append(sc)

    # An inline entry point obtains X before it checks Live (§5.1.2 "Check order and errors"). After the deadline of
    # the pinned generation no certificate was stored, so each call verifies its certificate in full first.
    for flavor, name in ((None, "inline_calls_after_expiry"), ("ton", "ton_inline_calls_after_expiry")):
        env = Env(pool, flavor=flavor)
        sim = env.sim
        expired = T0 + VALIDITY + SECOND  # the first clock value after the pin's deadline
        blk = env.block(
            1010,
            T0 + 10 * SECOND,
            [
                sim.control(1, 1, 0, 0, rep(0xC1), rep(0xE1)),
                env.transfer(0, 10**9, expired + DAY),
                env.transfer(1, 10**9, T0 + HOUR),
            ],
        )
        genuine = env.cert(blk)
        other_instance = env.cert(blk, label="X_1010_other_instance_signature", signed_instance=rep(0x78))
        control = sim.control_proof(1010, 0, blk.header)
        mint = sim.message_proof(1010, 1, blk.header)
        void = sim.message_proof(1010, 2, blk.header)
        sc = env.scenario(
            name,
            "an inline entry point obtains X before it checks Live: on a destination whose generation has expired, a "
            "certificate whose signature covers another instance is BadSignature for a finalization, a control and a "
            "void, and the genuine certificate of the current generation is CommitteeNotAccepted; neither stores a "
            "checkpoint"
        )
        for cert, outcome in ((other_instance, "BadSignature"), (genuine, "CommitteeNotAccepted")):
            sc.finalize(_inline(cert), mint, expired, outcome)
            sc.apply_control(_inline(cert), control, expired, outcome)
            sc.void_expired(1, _inline(cert), void, expired, outcome)
        out.append(sc)
    return out, committees


def _strip_keys(state: dict) -> dict:
    state = {**state, "committee": {k: v for k, v in state["committee"].items() if k != "keys"}}
    return state


def _ton_replayable(evm_doc: dict, ton_doc: dict) -> bool:
    """Whether a TON harness replays the EVM rows unchanged: single-certificate checkpoint calls only, and the TON
    model (keys in storage, three checkpoint slots) gives the same outcomes, events and state."""
    for evm_step, ton_step in zip(evm_doc["steps"], ton_doc["steps"]):
        if evm_step["call"] not in ("submitCheckpoints", "views"):
            return False
        if evm_step["call"] == "submitCheckpoints" and len(evm_step["certificates"]) != 1:
            return False
        if evm_step["expected"] != ton_step["expected"] and evm_step["call"] != "views":
            return False
        if _strip_keys(evm_step["state_after"]) != _strip_keys(ton_step["state_after"]):
            return False
    return len(evm_doc["steps"]) == len(ton_doc["steps"])


def _dummy_proof(env: _Env, block):
    """A syntactically complete message proof for a call that fails before the proof is read."""
    payload = env.transfer(0, 10**9, T0 + DAY).payload
    return MessageProof(payload, 0, [], BlockRef(block.height, rep(0x01), 1))


def _flavor_reports(flavor: str, outcome: str) -> bool:
    """Whether a destination of `flavor` can report `outcome`: an EVM custom error, or a TON exit code."""
    if outcome == "ok":
        return True
    if flavor == "evm":
        return outcome in ERROR_CODES
    return ERROR_CODES.get(outcome) is not None or outcome in TON_ONLY_ERROR_CODES


def _check_successor_keys(doc: dict, pool: CertificatePool, committees: dict) -> None:
    """A `ton_replayable` row tells a TON harness to send each certificate with its `ton_next_keys`: every
    key-changing rotation the row installs must therefore be pooled with the successor committee."""
    for step in doc["steps"]:
        if not any(ev["event"] == "SccpCommitteeRotated" for ev in step["expected"].get("events", [])):
            continue
        for cid in step["certificates"]:
            entry = pool.entries[cid]
            fields = entry["header_fields"]
            if fields["flags"] & FLAG_ROTATION and fields["next_committee_root"] != fields["committee_root"]:
                named = entry["ton_next_keys"]
                if named is None or hx(committees[named].root) != fields["next_committee_root"]:
                    raise AssertionError(f"{doc['name']}: {cid} is pooled without the successor keys it installs")


def init_bound_rows() -> list[dict]:
    """The deployment bound on `initialUntilMs` (§5.2.1 constructor, §5.3.1 `sccp_init`), around both ends."""
    now = T0
    span = MAX_VALIDITY_MS + MAX_INIT_SLACK_MS
    rows = []
    for label, until, expected in (
        ("until_before_now", now - SECOND, "BadConfig"),
        ("until_equals_now", now, "BadConfig"),
        ("until_one_ms_after_now", now + 1, "ok"),
        ("until_at_the_bound", now + span, "ok"),
        ("until_one_ms_above_the_bound", now + span + 1, "BadConfig"),
    ):
        assert init_until_ms_ok(now, until) == (expected == "ok"), label
        rows.append({"label": label, "now_ms": now, "until_ms": until, "expected": expected})
    return rows


def build() -> dict:
    """The complete `committee_transitions_v1.json` document."""
    topics = {}
    for name, (signature, expected) in EVENT_SIGNATURES.items():
        topic = event_topic(signature)
        if topic.hex() != expected:
            raise AssertionError(f"{name} topic differs from the specification")
        topics[name] = {"signature": signature, "topic0": hx(topic)}
    pool = CertificatePool()
    scenarios, committees = build_scenarios(pool)
    names = [s.name for s in scenarios]
    assert len(names) == len(set(names))
    ton_runs = {s.name: s for s in build_scenarios(CertificatePool(), "ton")[0]}
    rendered = []
    for sc in scenarios:
        doc = sc.as_json()
        flavor = sc.deployment.flavor
        if (flavor == "ton") != (sc.deployment.network is TON):
            raise AssertionError(f"{sc.name}: the flavor and the profile disagree")
        if flavor == "evm":
            doc["ton_replayable"] = _ton_replayable(doc, ton_runs[sc.name].as_json())
            if doc["ton_replayable"]:
                _check_successor_keys(doc, pool, committees)
        for step in doc["steps"]:
            outcome = step["expected"].get("outcome", "ok")
            if not _flavor_reports(flavor, outcome):
                raise AssertionError(f"{sc.name}: {outcome} is not a §5.2.2 error of the {flavor} flavor")
        rendered.append(doc)
    return {
        "schema": "iroha.sccp.committee-transitions.v1",
        "spec": "specs/sccp.md §5.1.2–§5.1.8, §11.1 (revision 5)",
        "generator": REFERENCE_GENERATORS,
        "conventions": "each scenario deploys a fresh destination from `deployment` (its `initial_state`), then runs `steps` "
        "in order; a step is (state, call, now_ms) → (state_after, expected.outcome, expected.events). "
        + DESTINATION_CLOCK_CONVENTION
        + "; "
        + SCENARIO_CLOCK_CONVENTION
        + ". `ok` is success "
        "(a latch or a lost Live inside submitCheckpoints is success with `stopped`); any other outcome is the §5.2.2 "
        "error and the call changes nothing. Certificates are pooled under `certificates` and referenced by id; an "
        "SccpCertificate event names the pooled certificate whose QC_FIXED, header and signature it publishes; "
        "`committees` resolve `signed_by` and TON `next_keys`. A step names its call as its flavor does: the EVM entry "
        "point, or the TON message of §5.3.2 (`ton_call_names`). An EVM scenario runs on ethereum-mainnet with the "
        "destination word word(0x22…22) and 20-byte recipients. A TON scenario runs on ton-mainnet: Taira's leaves "
        "use lane_bytes(sora-taira, ton-mainnet), recipients are 36-byte accounts of workchain 0, and the destination "
        "word is the placeholder minter account id 0x35…35. Events list "
        "the SCCP events only (the ERC-20 Transfer of a mint is implied). "
        "`state_after.checkpoints` is a set (sorted by height for readability). `ton_replayable` marks EVM scenarios "
        "that a TON harness replays as one sccp_checkpoint message per step (using each certificate's `ton` form and "
        "`ton_next_keys`) with identical outcomes and state; such a row contains checkpoint submissions only, which "
        "do not depend on the profile. `init_bounds` lists the deployment bound on the pinned untilMs: the "
        "constructor (EVM) or sccp_init (TON) at `now_ms` accepts `until_ms` iff now_ms < until_ms ≤ now_ms + "
        "max_validity_ms + max_init_slack_ms, and answers BadConfig otherwise",
        "error_choices": {
            "not_live_latched": "Equivocated",
            "not_live_expired": "CommitteeNotAccepted",
            "length_qc_or_signature_or_signer_ys": "BadCertificate",
            "length_x": "BadHeader",
            "length_committee": "BadCommittee",
            "signer_key_flags_sign_y_or_off_curve": "BadCommittee",
            "signer_key_x_not_reduced_or_zero_coordinates": "BadCommittee",
            "signature_identity": "BadSignature",
            "signature_encoding_subgroup_or_pairing": "BadSignature",
            "aggregate_key_identity": {"evm": "BadCommittee", "ton": "BadSignature"},
            "aggregate_key_outside_g1": "BadSignature",
            "ton_signer_key_refused_by_the_opcode": "BadSignature",
            "checkpoint_not_current_or_installing_handoff": "CommitteeNotAccepted",
            "void_frozen_range": {"evm": "BadAmount", "ton": "BadRange"},
            "check_order": "submitCheckpoints checks TooManyCertificates, then an empty batch (NothingToDo), then Live, "
            "then each certificate; the inline entry points obtain X first (VerifyCertificate with V1–V3 → "
            "LatchRequired) and check Live after it, in the §5.1.5 step order; the checkpoint entry points check the "
            "X length (BadHeader), the stored id (UnknownCheckpoint), X1–X7 with ACTIVE (BadHeader), Live, and then "
            "that X is of the current generation or the handoff that installed it (CommitteeNotAccepted); "
            "VerifyCertificate checks the key and signature encodings of step 6, including the identity signature on "
            "both flavors, before the cheap path of step 8; on EVM step 10 reports apk = O (BadCommittee) before step "
            "11 reads σ as a point; a TON finalize or void checks the payload and its recipient (BadPayload, "
            "BadRecipient) before it obtains X (§5.3.4), while EVM checks them after X, Live, the pause and the block "
            "reference; on both flavors the deadline is checked before the leaf path, a consumed nonce "
            "(AlreadyConsumed) before the supply cap, the §3.4 constraints (BadControl) before the control nonce "
            "(StaleControl), and the nonce argument of voidExpired (BadNonce) before the consumed set; voidFrozen "
            "checks the range before Frozen",
            "note": "these are the error names and the check order of specs/sccp.md §5.1.2, §5.1.3 and §5.1.8, repeated "
            "here so that every harness keys on one table",
        },
        "constants": {
            "max_certificates_per_call": MAX_CERTIFICATES_PER_CALL,
            "ton_checkpoint_slots": 3,
            "max_void_frozen_range_evm": 256,
            "max_void_frozen_range_ton": 512,
            "max_validity_ms": MAX_VALIDITY_MS,
            "max_init_slack_ms": MAX_INIT_SLACK_MS,
            "cheap_path": "mandatory: taken when checkpoint[X.height] = keccak256(X), after the checks of steps 1–6; "
            "steps 9–12 (the signature check and the SccpCertificate event) are skipped",
        },
        "event_topics": topics,
        "selectors": selectors_json(),
        "ton_call_names": dict(CALL_NAMES),
        "init_bounds": init_bound_rows(),
        "error_codes": {
            "note": "§5.2.2: the EVM error name and its TON exit code (null: EVM only); scenario outcomes use the names",
            "shared": ERROR_CODES,
            "ton_only": TON_ONLY_ERROR_CODES,
        },
        "committees": {name: committees[name].as_json() for name in sorted(committees, key=lambda n: int(n[1:]))},
        "certificates": pool.entries,
        "scenarios": rendered,
        "todo": [
            "TODO(TON contract work package): TON finalize and void rows through the bucket round trip (§5.3.4) are not "
            "modelled. The ton_* scenarios contain only steps the minter decides alone: checkpoints, controls, and "
            "finalize, void and voidFrozen steps that it refuses before any bucket message",
            "TODO(TON contract work package): the TON destination word 0x35…35 is a placeholder account id. The "
            "refusals of the ton_* scenarios do not depend on it; the applied controls of "
            "ton_checkpoint_use_after_rotation and ton_same_height_block_ref_with_history do (their leaves commit to "
            "the word), so the Acton harness either installs the minter at that account id or the rows are "
            "regenerated with the address its StateInit gives",
            "TODO(TON contract work package): the Acton harness confirms that BLS_FASTAGGREGATEVERIFY refuses a signer "
            "key that is no canonical point, is the identity or lies outside G1 (error_choices."
            "ton_signer_key_refused_by_the_opcode); until then no TON row pins those inputs",
        ],
    }
