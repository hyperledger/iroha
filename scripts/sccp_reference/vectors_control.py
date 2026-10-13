"""Builder of `fixtures/sccp/control_v1.json` (`specs/sccp.md` §3.4, §4.14.6, §5.1.6)."""

from __future__ import annotations

from .common import (
    DESTINATION_CLOCK_CONVENTION,
    MAX_FAST_PAUSE_MS,
    REFERENCE_GENERATORS,
    SCENARIO_CLOCK_CONVENTION,
    SccpError,
    hx,
    rep,
    word,
)
from .destination import ControlProof, Deployment
from .keccak import event_topic, keccak256
from .merkle import control_leaf, control_leaf_preimage, control_leaf_ton_builders, tree_path
from .payload import BSC, ETHEREUM, TAIRA, TON, lane_bytes
from .scenario import CertificatePool, Scenario
from .taira import Committee, TairaSim

NETWORK_ID = rep(0x11)
INSTANCE = rep(0x77)
T0 = 1_800_000_000_000
SECOND = 1_000
MINUTE = 60_000
HOUR = 3_600_000
DAY = 86_400_000
VALIDITY = 1_209_600_000
EVENT_SIGNATURE = "SccpControlApplied(uint64,uint8,bool,uint64,bytes32)"
SPEC_TOPIC = "b069397cc6f8fa22bf7c0216c554253ab0fc92a3178d10969760b028dd174238"
SPEC_EXAMPLES = (
    (1, 1, 1, 0, 0x33, 0x44, "d9be284f6412d8e310b35afa921f8244f8d56cc64fbfc795d58701c11dce4d77"),
    (2, 2, 0, 1_700_604_800_000, 0x55, 0x66, "fbdf5c5743292897ecf43c3d74fe0a3d3946aa73219bdab2f0a3e33bc0b988e0"),
    (3, 1, 1, 1_700_604_800_000, 0x77, 0x88, "8afcebc533342cb86836b0195edc6a55e8e998d8e52d85f1fbf2c2707193c518"),
    (4, 1, 0, 0, 0x99, 0xAA, "b52aafb5bd2fcc77db32e1dfb8a92890b97adc2b9e81dd30f63dba3c059c8df3"),
)
SPEC_NONCE2_PREIMAGE = (
    "534343502f434f4e54524f4c2f5631" + "40" + "11" * 32 + "41" + "00" * 31 + "01" + "00" * 12 + "22" * 20
    + "00000001" + "0000000000000002" + "02" + "00" + "0000018bf3f1ec00" + "55" * 32 + "66" * 32
)
DESTINATION_WORDS = {
    ETHEREUM.name: bytes(12) + rep(0x22, 20),
    BSC.name: bytes(12) + rep(0x24, 20),
    TON.name: rep(0x35),
}


def _row(target, revision, nonce, track, pp, until, cert_id, effect) -> dict:
    dw = DESTINATION_WORDS[target.name]
    preimage = control_leaf_preimage(NETWORK_ID, target, dw, revision, nonce, track, pp, until, cert_id, effect)
    b1, b2 = control_leaf_ton_builders(preimage)
    leaf = control_leaf(NETWORK_ID, target, dw, revision, nonce, track, pp, until, cert_id, effect)
    assert leaf == keccak256(preimage) == keccak256(b1, b2)
    return {
        "target": target.name,
        "destination_word": hx(dw),
        "route_revision": revision,
        "control_nonce": nonce,
        "track": track,
        "parliament_paused": pp,
        "fast_pause_until_ms": until,
        "certificate_id": hx(cert_id),
        "effect_hash": hx(effect),
        "lane_bytes": hx(lane_bytes(TAIRA, target, NETWORK_ID)),
        "preimage": hx(preimage),
        "ton_b1": hx(b1),
        "ton_b2": hx(b2),
        "leaf": hx(leaf),
    }


def spec_examples() -> list[dict]:
    rows = []
    for nonce, track, pp, until, cid, eff, leaf in SPEC_EXAMPLES:
        row = _row(ETHEREUM, 1, nonce, track, pp, until, rep(cid), rep(eff))
        if row["leaf"][2:] != leaf:
            raise AssertionError(f"control leaf nonce {nonce}: {row['leaf']} differs from the specification value {leaf}")
        if nonce == 2 and row["preimage"][2:] != SPEC_NONCE2_PREIMAGE:
            raise AssertionError("nonce 2 preimage differs from the specification")
        rows.append(row)
    return rows


def matrix() -> list[dict]:
    rows = []
    until = T0 + 10 * DAY
    for target in (ETHEREUM, BSC, TON):
        for revision, nonce in ((1, 1), (7, (1 << 32) + 5)):
            for track, pp, fp in ((1, 1, 0), (1, 0, 0), (1, 1, until), (1, 0, until), (2, 0, until), (2, 1, until)):
                tag = bytes([target.tag, revision & 0xFF, track, pp]) + nonce.to_bytes(8, "big")
                cert_id = keccak256(b"sccp-reference/control/certificate", tag)
                effect = keccak256(b"sccp-reference/control/effect", tag)
                rows.append(_row(target, revision, nonce, track, pp, fp, cert_id, effect))
    return rows


def rejected() -> list[dict]:
    dw = DESTINATION_WORDS[ETHEREUM.name]
    good = dict(target=ETHEREUM, revision=1, nonce=1, track=1, pp=1, until=0, cid=rep(0x33), eff=rep(0x44))
    # (label, change, Taira-side error, destination outcome when such a leaf is somehow certified)
    cases = [
        ("track_0", dict(track=0), "BadControl", "BadControl"),
        ("track_3", dict(track=3), "BadControl", "BadControl"),
        ("parliament_paused_2", dict(pp=2), "BadControl", "BadControl"),
        ("fast_pause_track_zero_expiry", dict(track=2, pp=0, until=0), "BadControl", "BadControl"),
        ("zero_certificate_id", dict(cid=bytes(32)), "BadControl", "BadControl"),
        ("zero_effect_hash", dict(eff=bytes(32)), "BadControl", "BadControl"),
        ("taira_target", dict(target=TAIRA), "TargetNotExternal", None),
        ("zero_revision", dict(revision=0), "ZeroRevision", "BadProof"),
        ("zero_control_nonce", dict(nonce=0), "ZeroControlNonce", "StaleControl"),
    ]
    rows = []
    for label, change, error, destination in cases:
        f = {**good, **change}
        try:
            control_leaf(NETWORK_ID, f["target"], dw, f["revision"], f["nonce"], f["track"], f["pp"], f["until"], f["cid"], f["eff"])
        except SccpError as err:
            assert err.name == error, (label, err.name)
        else:
            raise AssertionError(label)
        row = {
            "label": label,
            "target": f["target"].name,
            "route_revision": f["revision"],
            "control_nonce": f["nonce"],
            "track": f["track"],
            "parliament_paused": f["pp"],
            "fast_pause_until_ms": f["until"],
            "certificate_id": hx(f["cid"]),
            "effect_hash": hx(f["eff"]),
            "error": error,
        }
        if f["target"] is not TAIRA:
            row["unchecked_leaf"] = hx(
                control_leaf(
                    NETWORK_ID, f["target"], dw, f["revision"], f["nonce"], f["track"], f["pp"], f["until"], f["cid"], f["eff"], check=False
                )
            )
        row["destination"] = destination
        rows.append(row)
    return rows


class _Env:
    """One Taira route producing control blocks for the EVM destination at 0x22…22."""

    def __init__(self):
        self.k0 = Committee("K0", (40, 41, 42, 43))
        self.sim = TairaSim(NETWORK_ID, INSTANCE, ETHEREUM, DESTINATION_WORDS[ETHEREUM.name])
        self.gen = self.sim.start(5, self.k0, 1000, T0, VALIDITY)
        self.pool = CertificatePool()

    def deployment(self) -> Deployment:
        return Deployment(
            flavor="evm",
            taira_network_id=NETWORK_ID,
            consensus_instance=INSTANCE,
            network=ETHEREUM,
            destination_word=DESTINATION_WORDS[ETHEREUM.name],
            route_revision=1,
            max_wrapped_supply=10**18,
            pin_generation=5,
            pin_root=self.k0.root,
            pin_start_height=1000,
            pin_until_ms=T0 + VALIDITY,
            pin_keys=self.k0.keys,
        )

    def cert(self, height: int, label: str):
        block = self.sim.blocks[height]
        return (self.sim.certify(block.header, self.k0), label, "K0")

    def ids(self, nonce: int) -> tuple[bytes, bytes]:
        return keccak256(b"sccp-reference/certificate", word(nonce)), keccak256(b"sccp-reference/effect", word(nonce))


def destination_effects() -> tuple[list[dict], dict, dict]:
    env = _Env()
    sim = env.sim
    recipient = rep(0x44, 20)
    c = env.ids
    # Blocks (heights and times strictly increasing).
    sim.block(1010, T0 + 1 * MINUTE, [sim.control(1, 1, 1, 0, *c(1))])
    sim.block(1020, T0 + 2 * MINUTE, [sim.control(2, 2, 1, T0 + 2 * HOUR, *c(2)), sim.transfer(0, 10**9, T0 + DAY, recipient)])
    sim.block(1030, T0 + 3 * MINUTE, [sim.control(1, 2, 0, T0 + 2 * HOUR, *c(11)), sim.control(2, 1, 1, T0 + 2 * HOUR, *c(12))])
    sim.block(1040, T0 + 4 * MINUTE, [sim.control(1, 2, 0, T0 + HOUR, *c(21)), sim.transfer(1, 2 * 10**9, T0 + DAY, recipient)])
    sim.block(
        1050,
        T0 + 5 * MINUTE,
        [sim.control(3, 1, 1, 0, *c(31)), sim.control(2, 1, 0, 0, *c(32)), sim.control(5, 1, 0, 0, *c(35))],
    )
    sim.block(1060, T0 + 6 * MINUTE, [sim.control(1, 2, 0, T0 + 6 * MINUTE + 40 * DAY, *c(41))])
    sim.block(
        1070,
        T0 + 7 * MINUTE,
        [
            sim.control(1, 2, 0, T0 + 2 * HOUR, *c(51)),
            sim.transfer(2, 3 * 10**9, T0 + DAY, recipient),
            sim.transfer(3, 10**9, T0 + 30 * MINUTE, recipient),
        ],
    )
    sim.block(1080, T0 + 8 * MINUTE, [sim.control(1, 1, 1, 0, *c(61)), sim.control(2, 1, 0, 0, *c(62))])
    bsc = TairaSim(NETWORK_ID, INSTANCE, BSC, DESTINATION_WORDS[ETHEREUM.name])
    other_net = TairaSim(rep(0x12), INSTANCE, ETHEREUM, DESTINATION_WORDS[ETHEREUM.name])
    other_rev = TairaSim(NETWORK_ID, INSTANCE, ETHEREUM, DESTINATION_WORDS[ETHEREUM.name], route_revision=2)
    other_dest = TairaSim(NETWORK_ID, INSTANCE, ETHEREUM, bytes(12) + rep(0x23, 20))
    sim.block(
        1090,
        T0 + 9 * MINUTE,
        [
            bsc.control(1, 1, 1, 0, *c(71)),
            other_net.control(1, 1, 1, 0, *c(72)),
            other_rev.control(1, 1, 1, 0, *c(73)),
            other_dest.control(1, 1, 1, 0, *c(75)),
            sim.control(1, 3, 0, 0, *c(74), check=False),
            sim.transfer(4, 10**9, T0 + DAY, recipient),
        ],
    )
    sim.block(1100, T0 + 10 * MINUTE)
    sub_second_expiry = T0 + 2 * HOUR + 1
    sim.block(
        1110,
        T0 + 11 * MINUTE,
        [sim.control(1, 2, 0, sub_second_expiry, *c(81)), sim.transfer(5, 10**9, T0 + DAY, recipient)],
    )
    scenarios = []

    def scenario(name, description):
        sc = Scenario(name, description, env.deployment(), env.pool)
        scenarios.append(sc)
        return sc

    def inline(h):
        return ("inline", env.cert(h, f"X_{h}"))

    def proof(h, i, certified_h=None):
        return sim.control_proof(h, i, sim.blocks[certified_h or h].header)

    sc = scenario(
        "parliament_pause_then_fast_pause_then_lapse",
        "CX-3: a Parliament pause, then a fast pause, then the lapse; the Parliament pause stays in "
        "force"
    )
    sc.apply_control(inline(1010), proof(1010, 0), T0 + 10 * MINUTE, "ok")
    sc.apply_control(inline(1020), proof(1020, 0), T0 + 20 * MINUTE, "ok")
    sc.views(T0 + HOUR)
    sc.views(T0 + 3 * HOUR)
    sc.finalize(("checkpoint", sim.blocks[1020].x), sim.message_proof(1020, 1, sim.blocks[1020].header), T0 + 3 * HOUR, "MintingIsPaused")

    sc = scenario(
        "fast_pause_then_parliament_pause_then_lapse",
        "CX-3: the fast pause, then a Parliament pause whose leaf carries the live fast pause; after "
        "the lapse the Parliament pause remains"
    )
    sc.apply_control(inline(1030), proof(1030, 0), T0 + 10 * MINUTE, "ok")
    sc.apply_control(("checkpoint", sim.blocks[1030].x), proof(1030, 1), T0 + 20 * MINUTE, "ok")
    sc.views(T0 + 3 * HOUR)

    sc = scenario(
        "track2_leaf_after_expiry",
        "CX-4: a fast-pause leaf delivered after its expiry consumes its nonce and does not pause"
    )
    sc.apply_control(inline(1040), proof(1040, 0), T0 + 2 * HOUR, "ok")
    sc.views(T0 + 2 * HOUR)
    sc.finalize(("checkpoint", sim.blocks[1040].x), sim.message_proof(1040, 1, sim.blocks[1040].header), T0 + 2 * HOUR, "ok")

    sc = scenario(
        "stale_equal_and_gap_nonces",
        "newest nonce wins: 3 applied, 2 and 3 stale, 5 accepted across the gap"
    )
    sc.apply_control(inline(1050), proof(1050, 0), T0 + 10 * MINUTE, "ok")
    sc.apply_control(("checkpoint", sim.blocks[1050].x), proof(1050, 1), T0 + 11 * MINUTE, "StaleControl")
    sc.apply_control(("checkpoint", sim.blocks[1050].x), proof(1050, 0), T0 + 12 * MINUTE, "StaleControl")
    sc.apply_control(("checkpoint", sim.blocks[1050].x), proof(1050, 2), T0 + 13 * MINUTE, "ok")

    sc = scenario(
        "max_fast_pause_clamp",
        "fast_pause_until_ms 40 days ahead is clamped to now + MAX_FAST_PAUSE_MS"
    )
    now = T0 + 10 * MINUTE
    sc.apply_control(inline(1060), proof(1060, 0), now, "ok")
    assert sc.dest.state.fast_pause_until_ms == now + MAX_FAST_PAUSE_MS
    sc.views(now + MAX_FAST_PAUSE_MS - SECOND)  # the last clock value before the expiry: paused
    sc.views(now + MAX_FAST_PAUSE_MS)  # now_ms = fastPauseUntilMs: not paused

    sc = scenario(
        "fast_pause_local_expiry",
        "minting is paused while now < fastPauseUntilMs and resumes at the expiry with no relay; "
        "voids and checkpoints work while paused"
    )
    sc.apply_control(inline(1070), proof(1070, 0), T0 + 10 * MINUTE, "ok")
    sc.finalize(("checkpoint", sim.blocks[1070].x), sim.message_proof(1070, 1, sim.blocks[1070].header), T0 + 20 * MINUTE, "MintingIsPaused")
    sc.submit([env.cert(1080, "X_1080") + (None,)], T0 + 20 * MINUTE, "ok")
    # Transfer 3 has deadline_ms = T0 + 30 min: at that clock value a void is still early.
    sc.void_expired(3, ("checkpoint", sim.blocks[1070].x), sim.message_proof(1070, 2, sim.blocks[1070].header), T0 + 30 * MINUTE, "DeadlineNotReached")
    sc.void_expired(3, ("checkpoint", sim.blocks[1070].x), sim.message_proof(1070, 2, sim.blocks[1070].header), T0 + HOUR, "ok")
    # fastPauseUntilMs = T0 + 2 h: paused at the last clock value before it, minting again at it.
    sc.finalize(("checkpoint", sim.blocks[1070].x), sim.message_proof(1070, 1, sim.blocks[1070].header), T0 + 2 * HOUR - SECOND, "MintingIsPaused")
    sc.finalize(("checkpoint", sim.blocks[1070].x), sim.message_proof(1070, 1, sim.blocks[1070].header), T0 + 2 * HOUR, "ok")

    sc = scenario("pause_then_resume", "a Parliament pause (nonce 1) then a resume (nonce 2) in one block")
    sc.apply_control(inline(1080), proof(1080, 0), T0 + 10 * MINUTE, "ok")
    sc.apply_control(("checkpoint", sim.blocks[1080].x), proof(1080, 1), T0 + 11 * MINUTE, "ok")
    sc.views(T0 + 11 * MINUTE)

    sc = scenario(
        "historical_control_proof",
        "a control of block 1010 proven through the history path of X_1100"
    )
    sc.apply_control(inline(1100), proof(1010, 0, 1100), T0 + 15 * MINUTE, "ok")

    sc = scenario(
        "foreign_and_malformed_controls",
        "leaves of another network, Taira network, revision or destination, a transfer leaf offered as "
        "a control, and a recorded leaf violating a constraint"
    )
    now = T0 + 15 * MINUTE
    sc.apply_control(inline(1090), proof(1090, 0), now, "BadProof")
    sc.apply_control(inline(1090), proof(1090, 1), now, "BadProof")
    sc.apply_control(inline(1090), proof(1090, 2), now, "BadProof")
    sc.apply_control(inline(1090), proof(1090, 3), now, "BadProof")
    block = sim.blocks[1090]
    t = block.leaves[5]
    assert t.kind == "transfer"
    as_control = ControlProof(
        1, 1, 1, 0, t.leaf, t.leaf, 5, tree_path([i.leaf for i in block.leaves], 5), sim.block_ref(1090, block.header)
    )
    sc.apply_control(inline(1090), as_control, now, "BadProof")
    sc.apply_control(inline(1090), proof(1090, 4), now, "BadControl")
    sc.apply_control(("checkpoint", sim.blocks[1080].x), proof(1080, 0), now, "UnknownCheckpoint")
    sc.apply_control(inline(1010), proof(1010, 0), T0 + VALIDITY + SECOND, "CommitteeNotAccepted")

    # Added after the rows above (the certificate of block 1110 takes the next pool id).
    sc = scenario(
        "fast_pause_sub_second_expiry",
        "a fast pause whose expiry ends in 001 ms: the whole-second destination clock is paused at the last "
        "clock value below fastPauseUntilMs (1 ms earlier) and mints at the next one (999 ms later)"
    )
    block = sim.blocks[1110]
    sc.apply_control(inline(1110), proof(1110, 0), T0 + 20 * MINUTE, "ok")
    assert sc.dest.state.fast_pause_until_ms == sub_second_expiry and sub_second_expiry % SECOND == 1
    sc.views(sub_second_expiry - 1)
    sc.finalize(("checkpoint", block.x), sim.message_proof(1110, 1, block.header), sub_second_expiry - 1, "MintingIsPaused")
    sc.views(sub_second_expiry + 999)
    sc.finalize(("checkpoint", block.x), sim.message_proof(1110, 1, block.header), sub_second_expiry + 999, "ok")
    return [s.as_json() for s in scenarios], env.pool.entries, {"K0": env.k0.as_json()}


def build() -> dict:
    """The complete `control_v1.json` document."""
    topic = event_topic(EVENT_SIGNATURE)
    if topic.hex() != SPEC_TOPIC:
        raise AssertionError("SccpControlApplied topic differs from the specification")
    scenarios, certificates, committees = destination_effects()
    return {
        "schema": "iroha.sccp.control.v1",
        "spec": "specs/sccp.md §3.4, §4.14.6, §5.1.6 (revision 5)",
        "generator": REFERENCE_GENERATORS,
        "conventions": "byte strings are 0x-prefixed lowercase hex; `preimage` is the 199-byte control-leaf preimage and "
        "`ton_b1`/`ton_b2` its two TON HASHEXT builders (125 + 74 bytes); scenario rows follow "
        "committee_transitions_v1.json. "
        + DESTINATION_CLOCK_CONVENTION
        + "; "
        + SCENARIO_CLOCK_CONVENTION
        + ". The Taira blocks of `destination_effects` are synthetic destination "
        "inputs: every scenario starts from a fresh destination, and the control nonces of a block are chosen for "
        "that scenario, so they need not follow Taira's dense per-revision sequence (§4.14.6 step 1). "
        "`rejected[].error` is the refusal of the Rust and Python reference when Taira records a control: BadControl "
        "is the §3.4 constraint error, and TargetNotExternal, ZeroRevision and ZeroControlNonce are reference labels "
        "for the recording rules of §4.14.6 (a route targets an external network, revisions and control nonces start "
        "at 1), which no contract reports. `rejected[].destination` is what the destination model answers when such a "
        "leaf is certified anyway (null: the leaf does not exist). Row parliament_paused_2 cannot reach a contract "
        "through its typed interface (`bool parliamentPaused` on EVM, where the ABI decoder refuses a dirty word, and "
        "`Bool` on TON), so no contract harness replays it",
        "taira_network_id": hx(NETWORK_ID),
        "consensus_instance": hx(INSTANCE),
        "destination_words": {name: hx(w) for name, w in DESTINATION_WORDS.items()},
        "event_signature": EVENT_SIGNATURE,
        "topic_control_applied": hx(topic),
        "max_fast_pause_ms": MAX_FAST_PAUSE_MS,
        "spec_examples": spec_examples(),
        "controls": matrix(),
        "rejected": rejected(),
        "committees": committees,
        "certificates": certificates,
        "destination_effects": scenarios,
        "todo": [
            "TODO(reference generators): add TON destination-effect rows to this file. The Acton harness installs its "
            "minter at 0:35…35, and committee_transitions_v1.json already carries TON control rows for that destination word",
        ],
    }
