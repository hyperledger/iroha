"""Tests for the independent SCCP Python reference (`scripts/sccp_reference/`, `specs/sccp.md` revision 5).

They pin the primitives against published vectors (RFC 9380, Ethereum
bls12-381-tests inputs, a captured Ethereum mainnet sync-committee aggregate,
values cross-checked against `blst`), against the Rust-generated fixtures
whose layouts revision 5 keeps (payloads, transfer leaves, the commitment tree
and the history accumulator), exercise the destination model directly
(including the values no fixture row can carry: the saturating time sums, the
`voidFrozen` range and the supply cap at the ends of their widths, and the
checkpoint-use rule under forged headers), check the destination clock rule of
the scenario files (`now_ms` in whole, non-decreasing seconds) and that every
time boundary keeps a probe on both sides, verify the rows of the Rust-only
files (`bls_consensus_rust_v1.json`,
`finality_rust_v1.json`) with the Python reference, and regenerate every
fixture the reference writes to fail on drift.
"""

from __future__ import annotations

import copy
import dataclasses
import hashlib
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))

from sccp_reference import bls12_381 as bls  # noqa: E402
from sccp_reference import generate  # noqa: E402
from sccp_reference.bls_sig import (  # noqa: E402
    aggregate,
    aggregate_verify,
    consensus_digest,
    fast_aggregate_verify,
    key_validate,
    keygen,
    sign,
    signature_validate,
    sk_to_pk,
    verify,
)
from sccp_reference.common import (  # noqa: E402
    MAX_FAST_PAUSE_MS,
    MAX_INIT_SLACK_MS,
    MAX_VALIDITY_MS,
    U64_MAX,
    SccpError,
    check_destination_clock,
    h_iroha,
    rep,
    saturating_u64_sum,
    unhex,
)
from sccp_reference.destination import (  # noqa: E402
    IDENTITY_SIGNATURE_COMPRESSED,
    BlockRef,
    Deployment,
    Destination,
    MessageProof,
    bumped_op_count,
    check_ton_burn_payload,
    clamped_fast_pause,
    init_until_ms_ok,
    next_source_nonce,
    rotation_until_ms,
    void_frozen_range_ok,
)
from sccp_reference.finality import (  # noqa: E402
    FLAG_ACTIVE,
    FLAG_ROTATION,
    FinalityHeader,
    anchor_chunk_levels,
    anchor_chunk_path,
    anchor_chunk_position,
    anchor_leaf,
    anchor_node,
    bitmap_from_indices,
    build_certificate,
    commit_preimage,
    committee_n_valid,
    committee_root,
    inactive_header,
    parse_header,
    parse_qc_fixed,
    quorum,
    result_of_preimage,
    signers_from_indices,
)
from sccp_reference.hash_to_curve import (  # noqa: E402
    DST_SIG,
    SSWU_Z,
    expand_message_xmd,
    hash_to_g2,
    hash_to_g2_trace,
)
from sccp_reference.imported_vectors import (  # noqa: E402
    EXPAND_MESSAGE_XMD_DST,
    EXPAND_MESSAGE_XMD_SHA256,
    HASH_TO_G2_RO,
    HASH_TO_G2_RO_DST,
)
from sccp_reference.keccak import event_topic, keccak256, keccak_f1600, selector  # noqa: E402
from sccp_reference.merkle import (  # noqa: E402
    bag_peaks,
    check_block_ref,
    check_leaf,
    control_leaf,
    control_leaf_preimage,
    history_leaf,
    history_peaks,
    history_root,
    merkle_root,
    transfer_leaf,
    tree_levels,
    tree_path,
    tree_root,
)
from sccp_reference.payload import (  # noqa: E402
    BSC,
    BY_DOMAIN,
    ETHEREUM,
    TAIRA,
    TON,
    decode_payload,
    identity_word,
    message_id,
    outbound_payload,
    payload_hash,
)
from sccp_reference.taira import Committee, TairaSim  # noqa: E402
from sccp_reference.ton_cell import (  # noqa: E402
    TON_BURN_TO_TAIRA_OP,
    TonCell,
    burn_to_taira_payload,
    parse_taira_recipient,
    snake_bytes,
)

FIXTURES = ROOT / "fixtures" / "sccp"


# -- Keccak ---------------------------------------------------------------------


def _sha3_256_with(permutation, data: bytes) -> bytes:
    padded = bytearray(data) + b"\x06"
    while len(padded) % 136:
        padded.append(0)
    padded[-1] |= 0x80
    state = [0] * 25
    for off in range(0, len(padded), 136):
        for i in range(17):
            state[i] ^= int.from_bytes(padded[off + 8 * i : off + 8 * i + 8], "little")
        permutation(state)
    return b"".join(state[i].to_bytes(8, "little") for i in range(4))


def test_keccak256_known_values():
    assert keccak256(b"").hex() == "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"
    assert keccak256(b"abc").hex() == "4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45"
    assert keccak256(b"ab", b"c") == keccak256(b"abc")


@pytest.mark.parametrize("length", [0, 1, 55, 135, 136, 137, 271, 272, 300])
def test_keccak_permutation_matches_fips202(length):
    data = bytes((7 * i + 1) % 256 for i in range(length))
    assert _sha3_256_with(keccak_f1600, data) == hashlib.sha3_256(data).digest()


def test_selector_and_event_topic():
    assert selector("submitCheckpoints((bytes,bytes,bytes,bytes,bytes)[])").hex() == "07a5e706"
    assert event_topic("SccpTransferToTaira(bytes32,address,uint64,bytes)").hex() == (
        "79ac1cc63262b80bfbf96e55b2d49d96bd82f018ce0192f7002168724c7d264b"
    )


# -- BLS12-381 arithmetic ----------------------------------------------------------


def test_generators_constants_and_order():
    assert bls.g1_is_on_curve(bls.G1_GENERATOR) and bls.g2_is_on_curve(bls.G2_GENERATOR)
    assert bls.g1_in_subgroup(bls.G1_GENERATOR) and bls.g2_in_subgroup(bls.G2_GENERATOR)
    assert bls.g1_compress(bls.G1_GENERATOR).hex().startswith("97f1d3a73197d794")
    assert bls.g2_compress(bls.G2_GENERATOR).hex().startswith("93e02b6052719f60")
    assert bls.HALF_P == 0x0D0088F51CBFF34D258DD3DB21A5D66BB23BA5C279C2895FB39869507B587B120F55FFFF58A9FFFFDCFF7FFFFFFFD555


def test_field_sqrt_and_inverses():
    for a in (2, 3, 5, 12345678901234567890):
        sq = a * a % bls.P
        assert bls.fp_sqrt(sq) in (a % bls.P, -a % bls.P)
        assert bls.fp_inv(a) * a % bls.P == 1
        x = (a, a + 1)
        assert bls.f2_sqrt(bls.f2_sqr(x)) in (x, bls.f2_neg(x))
        assert bls.f2_mul(x, bls.f2_inv(x)) == bls.F2_ONE
    assert bls.f2_sqrt(SSWU_Z) is None and not bls.f2_is_square(SSWU_Z)  # Z = −(2 + u) is a non-square
    f = bls.miller_loop(bls.G1_GENERATOR, bls.G2_GENERATOR)
    assert bls.f12_mul(f, bls.f12_inv(f)) == bls.F12_ONE


def test_scalar_multiplication_matches_repeated_addition():
    acc1, acc2 = None, None
    for k in range(1, 12):
        acc1 = bls.g1_add(acc1, bls.G1_GENERATOR)
        acc2 = bls.g2_add(acc2, bls.G2_GENERATOR)
        assert bls.g1_mul(bls.G1_GENERATOR, k) == acc1
        assert bls.g2_mul(bls.G2_GENERATOR, k) == acc2
    assert bls.g1_mul(bls.G1_GENERATOR, bls.R) is None
    assert bls.g2_mul(bls.G2_GENERATOR, -1) == bls.g2_neg(bls.G2_GENERATOR)


def test_pairing_is_bilinear_and_non_degenerate():
    e = bls.pairing(bls.G1_GENERATOR, bls.G2_GENERATOR)
    assert e != bls.F12_ONE
    assert bls.pairing(bls.g1_mul(bls.G1_GENERATOR, 3), bls.G2_GENERATOR) == bls.pairing(
        bls.G1_GENERATOR, bls.g2_mul(bls.G2_GENERATOR, 3)
    )
    assert bls.pairing_product_is_one(
        [(bls.g1_mul(bls.G1_GENERATOR, 6), bls.G2_GENERATOR), (bls.g1_neg(bls.G1_GENERATOR), bls.g2_mul(bls.G2_GENERATOR, 6))]
    )


def test_point_encodings_roundtrip_and_reject_non_canonical():
    for k in (1, 2, 7, 1 << 70):
        p1 = bls.g1_mul(bls.G1_GENERATOR, k)
        p2 = bls.g2_mul(bls.G2_GENERATOR, k)
        assert bls.g1_decompress(bls.g1_compress(p1)) == p1
        assert bls.g2_decompress(bls.g2_compress(p2)) == p2
        assert bls.g2_from_evm192(bls.g2_to_evm192(p2)) == p2
        assert len(bls.g1_to_eip2537(p1)) == 128 and len(bls.g2_to_eip2537(p2)) == 256
    assert bls.g1_decompress(bytes([0xC0]) + bytes(47)) is None
    for bad in (bytes([0xE0]) + bytes(47), bytes([0xC0]) + bytes(46) + b"\x01", bytes(48), bytes([0x9F]) + b"\xff" * 47):
        with pytest.raises(bls.PointEncodingError):
            bls.g1_decompress(bad)
    with pytest.raises(bls.PointEncodingError):
        bls.g2_from_evm192(bls.g2_to_evm192(bls.G2_GENERATOR)[:191] + b"\x00")


# -- hash to curve -----------------------------------------------------------------


def test_expand_message_xmd_rfc9380():
    for msg, length, uniform in EXPAND_MESSAGE_XMD_SHA256:
        assert expand_message_xmd(msg.encode(), EXPAND_MESSAGE_XMD_DST, length).hex() == uniform


def test_hash_to_g2_rfc9380():
    for vector in HASH_TO_G2_RO:
        trace = hash_to_g2_trace(vector["msg"].encode(), HASH_TO_G2_RO_DST)
        fp2 = lambda pair: (int(pair[0], 16), int(pair[1], 16))  # noqa: E731
        assert trace["u0"] == fp2(vector["u0"]) and trace["u1"] == fp2(vector["u1"])
        assert trace["q0"] == (fp2(vector["q0"][0]), fp2(vector["q0"][1]))
        assert trace["point"] == (fp2(vector["p"][0]), fp2(vector["p"][1]))
        assert bls.g2_add(trace["map_u0"], trace["map_u1"]) == trace["point"]


def test_sgn0():
    assert bls.f2_sgn0((0, 0)) == 0 and bls.f2_sgn0((1, 0)) == 1
    assert bls.f2_sgn0((0, 1)) == 1 and bls.f2_sgn0((2, 1)) == 0


# -- BLS signatures ----------------------------------------------------------------

# Values produced by `blst` 0.3.16 (`SecretKey::key_gen`, `sign` with DST_SIG) for the §11.3 test keys.
BLST_SK0 = "165e9e0625d23c83f6a34e786966cd88ae130231cf749c809c92d9437b6ee5d7"
BLST_PK0 = "98deef4a5d6468f0725ea03a677415de205c1c90ad01044187029cb9ad00cc7285e9b1d7ebd7ff6b2e3bddc7fe110d90"
BLST_PK2 = "b2d3a715d3fa2670e31baeecd4210431a8f09f5210e4a2e68c67083e38f7ac6f61134a4a0d9eaecf3bdd465d4533e470"
BLST_AGG21 = (
    "b0aca45f918a9ce7a8f15bc105b2adefd78b1b026dc92de440c2c90efbdce56fe9b5f748bf4b4e666234f6b54b179e9b"
    "17dea1cd9e2627b99e8bd8e9b544698e636f87b430754ff23a373e46b98a99f9e6f92553419c86b8796314502fef6181"
)


def _test_sk(i: int) -> int:
    return keygen(hashlib.sha256(b"sccp-finality-test-ikm" + bytes([i])).digest())


def test_keygen_and_aggregate_match_blst():
    assert _test_sk(0).to_bytes(32, "big").hex() == BLST_SK0
    assert sk_to_pk(_test_sk(0)).hex() == BLST_PK0 and sk_to_pk(_test_sk(2)).hex() == BLST_PK2
    msg = hashlib.sha256(b"sccp-reference-crosscheck").digest()
    sigs = [sign(_test_sk(i), msg) for i in range(21)]
    assert aggregate(sigs).hex() == BLST_AGG21
    assert fast_aggregate_verify([sk_to_pk(_test_sk(i)) for i in range(21)], msg, aggregate(sigs))


def test_sign_verify_and_validation():
    sk = _test_sk(1)
    msg = bytes(32)
    sig = sign(sk, msg)
    assert verify(sk_to_pk(sk), msg, sig)
    assert not verify(sk_to_pk(sk), b"\x01" * 32, sig)
    assert not verify(sk_to_pk(sk), msg, sign(sk, msg, b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_"))
    assert key_validate(bytes([0xC0]) + bytes(47)) is None
    assert signature_validate(bytes([0xC0]) + bytes(95)) is None
    assert signature_validate(sig) is not None


def test_aggregates():
    msgs = [bytes([i]) * 32 for i in range(3)]
    pks = [sk_to_pk(_test_sk(i)) for i in range(3)]
    agg = aggregate([sign(_test_sk(i), msgs[0]) for i in range(3)])
    assert fast_aggregate_verify(pks, msgs[0], agg)
    assert not fast_aggregate_verify(pks[:2], msgs[0], agg)
    assert not fast_aggregate_verify([], msgs[0], agg)
    distinct = aggregate([sign(_test_sk(i), msgs[i]) for i in range(3)])
    assert aggregate_verify(pks, msgs, distinct)
    assert not aggregate_verify(pks, [msgs[0], msgs[0], msgs[2]], distinct)


def test_consensus_digest_allowlist():
    commit = b"sumeragi/sig" + b"\x03" + bytes(152)
    assert consensus_digest(commit) == hashlib.sha256(commit).digest()
    assert consensus_digest(commit[:-1]) is None
    assert consensus_digest(b"sumeragi/sig" + b"\x06" + bytes(152)) is None
    assert consensus_digest(b"sumeragi/sig" + b"\x04" + bytes(88) + b"\x00") is not None
    assert consensus_digest(b"sumeragi/sig" + b"\x04" + bytes(88) + b"\x01") is None
    assert consensus_digest(b"sumeragi/availability/sign" + b"\x01" + bytes(192)) is not None


def test_ethereum_mainnet_sync_committee_aggregate():
    from sccp_reference.vectors_bls import ethereum_mainnet_vector

    vector = ethereum_mainnet_vector()
    assert vector["fast_aggregate_verify"] is True and vector["participants"] == 502


# Rows of `bls_consensus_rust_v1.json` whose verdict needs the w3f transcript of `iroha_crypto`.
RUST_ONLY_BLS_NEGATIVES = ("dst_sig_signature_presented_to_generic_api",)


def test_rust_bls_consensus_fixture_agrees():
    """Rows of the Rust-generated `bls_consensus_rust_v1.json` (iroha_crypto) verify identically in Python."""
    path = FIXTURES / "bls_consensus_rust_v1.json"
    assert path.exists(), "fixtures/sccp/bls_consensus_rust_v1.json is missing: regenerate it with iroha_crypto"
    d = json.loads(path.read_text())
    sks = [int(k["secret_key_be"], 16) for k in d["keys"]]
    pks = [unhex(k["public_key"]) for k in d["keys"]]
    assert [sk_to_pk(sk) for sk in sks] == pks
    sv = d["standard_vectors"]
    for row in sv["sign"]:
        assert sign(sks[row["key"]], unhex(row["message"])) == unhex(row["signature"])
    for row in sv["verify"]:
        assert verify(pks[row["key"]], unhex(row["message"]), unhex(row["signature"])) == row["valid"]
    assert sv["aggregate"]
    for row in sv["aggregate"]:
        assert aggregate([unhex(share) for share in row["signatures"]]) == unhex(row["output"])
    for row in sv["fast_aggregate_verify"]:
        keys = [pks[k] if isinstance(k, int) else unhex(k) for k in row["keys"]]
        assert fast_aggregate_verify(keys, unhex(row["message"]), unhex(row["signature"])) == row["valid"]
    for row in sv["aggregate_verify"]:
        keys = [pks[k] for k in row["keys"]]
        assert aggregate_verify(keys, [unhex(m) for m in row["messages"]], unhex(row["signature"])) == row["valid"]
    for row in d["allowlist"]:
        digest = consensus_digest(unhex(row["preimage"]))
        assert digest == unhex(row["digest"])
        assert [sign(sk, digest) for sk in sks] == [unhex(s) for s in row["signatures"]]
    for row in d["allowlist_rejections"]:
        assert consensus_digest(unhex(row["preimage"])) is None, row["case"]
    for row in d["negatives"]:
        if "key_validate" in row:
            assert key_validate(unhex(row["public_key"])) is None, row["case"]
        elif "consensus_valid" in row:
            digest = consensus_digest(unhex(row["preimage"])) if "preimage" in row else unhex(row["message"])
            keys = [unhex(k) for k in row.get("public_keys", [])] or [pks[row["key"]]]
            assert digest is None or not fast_aggregate_verify(keys, digest, unhex(row["signature"])), row["case"]
        elif "generic_valid_over_digest" in row:
            # Rust-only verdict: the generic w3f API refuses a consensus signature. Python has no w3f transcript,
            # so it checks the half it can: the signature is a genuine consensus signature of the preimage.
            assert row["case"] in RUST_ONLY_BLS_NEGATIVES, row["case"]
            assert (row["generic_valid_over_digest"], row["generic_valid_over_preimage"]) == (False, False)
            digest = consensus_digest(unhex(row["preimage"]))
            assert digest is not None and verify(pks[row["key"]], digest, unhex(row["signature"])), row["case"]
        else:
            pytest.fail(f"negative row {row['case']} has a shape this test does not check: {sorted(row)}")
    # `keys[].w3f_pop` is the other Rust-only field: a proof of possession under the w3f transcript.
    assert all(len(unhex(k["w3f_pop"])) == 96 for k in d["keys"])


# -- payloads, leaves, trees, history -------------------------------------------------


def test_identity_words():
    assert identity_word(ETHEREUM, rep(0x11)) == bytes(31) + b"\x01"
    assert identity_word(TON, rep(0x11)).hex() == "ff" * 31 + "11"
    assert identity_word(TAIRA, rep(0x11)) == rep(0x11)


def test_payloads_and_message_ids_match_rust_payload_fixture():
    data = json.loads((FIXTURES / "payload_v1.json").read_text())
    network_id = unhex(data["taira_network_id"])
    assert len(data["networks"]) == 4 and len(data["directions"]) == 6
    for direction in data["directions"]:
        payload = unhex(direction["payload"])
        decoded = decode_payload(payload)
        assert payload_hash(payload) == unhex(direction["payload_hash"])
        source, dest = BY_DOMAIN[decoded.source_domain], BY_DOMAIN[decoded.dest_domain]
        assert message_id(source, dest, network_id, payload) == unhex(direction["message_id"])
    # Every payload the Rust codec refuses is refused here too, the retired domain 5 and codec 5 included.
    rejected = {row["label"]: row for row in data["rejected_payloads"]}
    assert {
        "retired_tron_domain_5_outbound",
        "retired_tron_domain_5_inbound",
        "recipient_codec_5_on_eth",
        "sender_codec_5_on_bsc",
    } <= set(rejected)
    for label, row in rejected.items():
        with pytest.raises(SccpError):
            decode_payload(unhex(row["payload"]))
        assert row["error"], label


def test_payload_rejections():
    sim = TairaSim(rep(0x11), rep(0x77), ETHEREUM, bytes(12) + rep(0x22, 20))
    payload = sim.transfer(0, 10**9, 1, rep(0x44, 20)).payload
    decode_payload(payload)
    for bad in (payload + b"\x00", payload[:-1], payload.replace(b"taira_eth_xor", b"taira_bsc_xor")):
        with pytest.raises(SccpError):
            decode_payload(bad)
    retired = bytearray(payload)
    retired[6:10] = (5).to_bytes(4, "big")  # domain 5 of the removed TRON profile
    with pytest.raises(SccpError):
        decode_payload(bytes(retired))


def test_commitment_tree_matches_rust_fixture():
    data = json.loads((FIXTURES / "commitment_tree_v1.json").read_text())
    leaves = [unhex(x) for x in data["leaves"]]
    for tree in data["trees"]:
        count = tree["count"]
        subset = leaves[:count]
        levels = tree_levels(subset)
        assert levels[-1][0] == unhex(tree["root"])
        for index, path in enumerate(tree["paths"]):
            assert [x.hex() for x in tree_path(subset, index, levels)] == [p[2:] for p in path]
            if index % 16 == 0 or index == count - 1:
                assert merkle_root(subset[index], index, count, [unhex(p) for p in path]) == unhex(tree["root"])
    example = data["examples"]["transfer"]
    assert transfer_leaf(unhex(example["message_id"]), unhex(example["destination_word"])) == unhex(example["leaf"])
    control = data["examples"]["control"]
    assert control["target"] == "ethereum-mainnet"
    fields = (
        unhex(data["taira_network_id"]), ETHEREUM, unhex(control["destination_word"]),
        control["route_revision"], control["control_nonce"], control["track"],
        control["parliament_paused"], control["fast_pause_until_ms"],
        unhex(control["certificate_id"]), unhex(control["effect_hash"]),
    )
    preimage = control_leaf_preimage(*fields)
    assert len(preimage) == 199
    assert preimage == unhex(control["preimage"])
    assert control_leaf(*fields) == unhex(control["leaf"])
    assert leaves[2] == unhex(control["leaf"])



def test_history_matches_rust_fixture_and_bagging():
    data = json.loads((FIXTURES / "history_v1.json").read_text())
    leaves = []
    for entry in data["leaves"]:
        leaf = history_leaf(entry["height"], unhex(entry["sccp_root"]), entry["message_count"])
        assert leaf == unhex(entry["leaf"])
        leaves.append(leaf)
    assert history_root([]) == bytes(32)
    for size in data["sizes"]:
        subset = leaves[: size["size"]]
        assert history_root(subset) == unhex(size["root"])
        assert [p.hex() for p in history_peaks(subset)] == [p[2:] for p in size["peaks"]]
        assert bag_peaks(history_peaks(subset)) == history_root(subset)


def test_merkle_root_rejects_malformed_paths():
    leaves = [rep(i) for i in range(1, 6)]
    path = tree_path(leaves, 1)
    assert merkle_root(leaves[1], 1, 5, path) == tree_root(leaves)
    for args in ((leaves[1], 1, 5, path[:-1]), (leaves[1], 1, 5, path + [rep(9)]), (leaves[1], 5, 5, path), (leaves[1], 0, 0, [])):
        with pytest.raises(SccpError):
            merkle_root(*args)
    assert tree_path(leaves, 4) == [tree_root(leaves[:4])]


def test_control_leaf_constraints():
    dw = bytes(12) + rep(0x22, 20)
    leaf = control_leaf(rep(0x11), ETHEREUM, dw, 1, 1, 1, 1, 0, rep(0x33), rep(0x44))
    assert leaf.hex() == "d9be284f6412d8e310b35afa921f8244f8d56cc64fbfc795d58701c11dce4d77"
    for args, error in (
        ((1, 1, 0, 1, 0, rep(0x33), rep(0x44)), "BadControl"),
        ((1, 1, 2, 0, 0, rep(0x33), rep(0x44)), "BadControl"),
        ((1, 1, 1, 2, 0, rep(0x33), rep(0x44)), "BadControl"),
        ((1, 1, 1, 1, 0, bytes(32), rep(0x44)), "BadControl"),
        ((0, 1, 1, 1, 0, rep(0x33), rep(0x44)), "ZeroRevision"),
        ((1, 0, 1, 1, 0, rep(0x33), rep(0x44)), "ZeroControlNonce"),
    ):
        with pytest.raises(SccpError) as err:
            control_leaf(rep(0x11), ETHEREUM, dw, *args)
        assert err.value.name == error


# -- finality header, R, P, anchors ---------------------------------------------------


def test_spec_worked_examples():
    from sccp_reference.vectors_finality import worked_examples

    examples = worked_examples()
    assert examples["commit"]["m"] == "0x85c684fac5aab78b197a5e2d40329ec518bc038abd99974a37064ea26e4943e0"


def test_header_parse_invariants():
    from sccp_reference.vectors_finality import header_vectors

    asked = []

    def outcomes(x, generation, root):
        asked.append(x)
        return {"evm": "BadHeader", "ton": "BadHeader"} if _header_violations(x) or not x[64] & FLAG_ACTIVE else {"evm": "BadCommittee", "ton": "BadSignature"}

    vectors = header_vectors(outcomes)
    committed = json.loads((FIXTURES / "finality_v1.json").read_text())["headers"]
    assert vectors == committed and len(asked) == len(vectors["valid"]) + len(vectors["invalid"])
    assert {v["error"] for v in vectors["invalid"]} == {"X1", "X2", "X3", "X4", "X5", "X6", "X7", "Length"}
    for v in vectors["valid"]:
        assert parse_header(unhex(v["x"])).encode() == unhex(v["x"]) and not _header_violations(unhex(v["x"]))
    for v in vectors["invalid"]:
        with pytest.raises(SccpError) as err:
            parse_header(unhex(v["x"]))
        assert err.value.name == v["error"] and v["destination"] == "BadHeader", v["label"]
    errors = {v["label"]: v["error"] for v in vectors["invalid"]}
    assert errors["rotation_at_max_height"] == "X6" and errors["rotation_at_max_generation"] == "X6"


HEADER_CHECK_ORDER = ("Length", "X1", "X2", "X3", "X4", "X5", "X6", "X7")


def _header_violations(x: bytes) -> list[str]:
    """Every check of §3.6 that `x` violates, each evaluated on its own (not the first one only)."""
    if len(x) != 221:
        return ["Length"]
    u = lambda lo, hi: int.from_bytes(x[lo:hi], "big")  # noqa: E731
    flags, height = x[64], u(48, 56)
    count, root, hsize, hroot = u(65, 69), x[69:101], u(101, 109), x[109:141]
    generation, croot, validity, nroot = u(141, 149), x[149:181], u(181, 189), x[189:221]
    active, rotation = bool(flags & FLAG_ACTIVE), bool(flags & FLAG_ROTATION)
    out = []
    if x[:16] != b"SCCP/FINALITY/V1" or flags & 0xFC:
        out.append("X1")
    if not active and (any(x[65:]) or rotation):
        out.append("X2")
    if active and (generation < 1 or not any(croot)):
        out.append("X3")
    if (count == 0) != (not any(root)) or count > 512:
        out.append("X4")
    if (hsize == 0) != (not any(hroot)) or hsize > 1 << 32:
        out.append("X5")
    if rotation:
        if not any(nroot) or not 1 <= validity <= MAX_VALIDITY_MS or height > U64_MAX - 1 or generation > U64_MAX - 1:
            out.append("X6")
    elif validity or any(nroot):
        out.append("X6")
    if height < 1:
        out.append("X7")
    return out


def test_header_vectors_pin_the_check_order():
    """`headers.invalid` pins the order Length, X1, X2 | X3, X4, X5, X6, X7: every row reports the first check it
    violates, and for each adjacent pair of the order some row violates both."""
    rows = json.loads((FIXTURES / "finality_v1.json").read_text())["headers"]["invalid"]
    pairs = set()
    for row in rows:
        violated = _header_violations(unhex(row["x"]))
        assert violated and row["error"] == min(violated, key=HEADER_CHECK_ORDER.index), (row["label"], violated)
        pairs |= {(a, b) for a in violated for b in violated if a != b}
    # X2 needs an inactive header and X3 an active one, so each follows X1 and X7 closes both chains.
    adjacent = {("X1", "X2"), ("X1", "X3"), ("X3", "X4"), ("X4", "X5"), ("X5", "X6"), ("X6", "X7"), ("X2", "X7")}
    assert not adjacent - pairs, sorted(adjacent - pairs)
    # An evaluator that swapped two adjacent checks would report the later one on the row of that pair.
    for first, second in sorted(adjacent):
        both = [row for row in rows if {first, second} <= set(_header_violations(unhex(row["x"])))]
        assert both and all(row["error"] != second for row in both), (first, second)


def _header_error(header: FinalityHeader) -> str | None:
    try:
        parse_header(header.encode())
    except SccpError as err:
        return err.name
    return None


def test_rotation_at_the_last_height_violates_x6():
    """A rotation at `2^64 − 1` would start its successor at `2^64`: X6, reported after X1–X5 and as `BadHeader`."""
    sim, k0, dest = _destination()
    rotation = _x(k0, U64_MAX, flags=FLAG_ACTIVE | FLAG_ROTATION, validity_ms=1, next_committee_root=k0.root)
    assert _header_error(rotation) == "X6"
    row = {v["label"]: v for v in json.loads((FIXTURES / "finality_v1.json").read_text())["headers"]["invalid"]}["rotation_at_max_height"]
    assert (row["error"], row["destination"]) == ("X6", "BadHeader")
    assert unhex(row["x"])[48:56] == b"\xff" * 8 and unhex(row["x"])[64] == FLAG_ACTIVE | FLAG_ROTATION
    assert _header_error(rotation.with_(height=U64_MAX - 1)) is None
    assert _header_error(rotation.with_(flags=FLAG_ACTIVE, validity_ms=0, next_committee_root=bytes(32))) is None
    assert parse_header(inactive_header(rep(0x11), U64_MAX, 5).encode()).height == U64_MAX
    # The first violated check is reported: X1, X3, X4 and X5 precede X6.
    assert _header_error(rotation.with_(flags=0x07)) == "X1"
    assert _header_error(rotation.with_(generation=0)) == "X3"
    assert _header_error(rotation.with_(message_count=1)) == "X4"
    assert _header_error(rotation.with_(history_size=1)) == "X5"
    # Destinations answer BadHeader although the certificate is validly signed, and nothing changes.
    cert = sim.certify(rotation, k0)
    assert dest.verify_certificate(cert, T0) == {"outcome": "BadHeader", "detail": "X6"}
    assert dest.submit_checkpoints([cert], T0)["outcome"] == "BadHeader"
    assert (dest.state.generation, dest.state.start, dest.state.checkpoints) == (5, 1000, {})
    # Its neighbour at 2^64 − 2 installs a successor whose start is the last u64 height.
    neighbour = sim.certify(rotation.with_(height=U64_MAX - 1), k0)
    assert dest.submit_checkpoints([neighbour], T0)["outcome"] == "ok"
    assert (dest.state.generation, dest.state.start, dest.state.high) == (6, U64_MAX, U64_MAX - 1)


def test_rotation_of_the_last_generation_violates_x6():
    """A rotation of generation `2^64 − 1` would install generation `2^64`: X6, reported as `BadHeader`."""
    sim, k0, dest = _destination()
    rotation = _x(k0, 1100, flags=FLAG_ACTIVE | FLAG_ROTATION, validity_ms=1, next_committee_root=k0.root)
    assert _header_error(rotation.with_(generation=U64_MAX)) == "X6"
    row = {v["label"]: v for v in json.loads((FIXTURES / "finality_v1.json").read_text())["headers"]["invalid"]}["rotation_at_max_generation"]
    assert (row["error"], row["destination"]) == ("X6", "BadHeader")
    assert unhex(row["x"])[141:149] == b"\xff" * 8 and unhex(row["x"])[64] == FLAG_ACTIVE | FLAG_ROTATION
    # The neighbours parse: the last generation that can rotate, and a non-rotation of the last generation.
    assert _header_error(rotation.with_(generation=U64_MAX - 1)) is None
    assert _header_error(_x(k0, 1100).with_(generation=U64_MAX)) is None
    # The first violated check is reported: X3, X4 and X5 precede X6, and a rotation at the last height is X6 too.
    assert _header_error(rotation.with_(generation=U64_MAX, committee_root=bytes(32))) == "X3"
    assert _header_error(rotation.with_(generation=U64_MAX, message_count=1)) == "X4"
    assert _header_error(rotation.with_(generation=U64_MAX, history_size=1)) == "X5"
    assert _header_error(rotation.with_(generation=U64_MAX, height=U64_MAX)) == "X6"
    # A destination pinned at the last generation answers BadHeader to its rotation and keeps its state;
    # one pinned at 2^64 − 2 installs the last generation, which then accepts non-rotation certificates only.
    last = Destination(dataclasses.replace(dest.d, pin_generation=U64_MAX))
    cert = sim.certify(rotation.with_(generation=U64_MAX), k0)
    assert last.verify_certificate(cert, T0) == {"outcome": "BadHeader", "detail": "X6"}
    assert last.submit_checkpoints([cert], T0)["outcome"] == "BadHeader"
    assert (last.state.generation, last.state.start, last.state.checkpoints, last.events) == (U64_MAX, 1000, {}, [])
    penultimate = Destination(dataclasses.replace(dest.d, pin_generation=U64_MAX - 1))
    assert penultimate.submit_checkpoints([sim.certify(rotation.with_(generation=U64_MAX - 1), k0)], T0)["outcome"] == "ok"
    assert (penultimate.state.generation, penultimate.state.start) == (U64_MAX, 1101)
    assert penultimate.submit_checkpoints([sim.certify(_x(k0, 1200).with_(generation=U64_MAX), k0)], T0)["outcome"] == "ok"
    assert penultimate.submit_checkpoints([sim.certify(rotation.with_(generation=U64_MAX, height=1300), k0)], T0)["outcome"] == "BadHeader"
    assert (penultimate.state.generation, penultimate.state.high) == (U64_MAX, 1200)


def test_inactive_header_and_result_of_preimage():
    x = inactive_header(rep(0x11), 9, 5).encode()
    assert x[65:] == bytes(156) and x[64] == 0
    assert result_of_preimage(x) is None
    assert result_of_preimage(x + b"\x00") is not None
    assert result_of_preimage(bytes(221) + b"\x00") is None


def test_qc_fixed_signers_and_quorum():
    assert signers_from_indices([0, 9, 30]) == 0x40000201
    assert bitmap_from_indices([0, 9, 30], 31).hex() == "01020040"
    assert [quorum(n) for n in (4, 7, 31)] == [3, 5, 21]
    assert not committee_n_valid(5) and committee_n_valid(31) and not committee_n_valid(34)
    p = commit_preimage(rep(0x77), 1, rep(0x88), 2, 3, rep(0x99), rep(0x66))
    assert len(p) == 165 and p[12] == 3
    qc = parse_qc_fixed(bytes(112) + (0x40000201).to_bytes(4, "big"))
    assert qc.signers == 0x40000201
    assert len(qc.encode()) == 116
    assert parse_qc_fixed(qc.encode()) == qc
    assert consensus_digest(p) == hashlib.sha256(p).digest()
    assert consensus_digest(p + b"\x01") is None
    for invalid in (qc.encode()[:-1], qc.encode()[:80] + b"\x01" + qc.encode()[80:]):
        with pytest.raises(SccpError, match="QC_FIXED must be 116 bytes"):
            parse_qc_fixed(invalid)


def test_anchor_chunk_paths_verify():
    leaves = [anchor_leaf(h, rep(0x99), rep(0x66)) for h in range(1, 4097)]
    levels = anchor_chunk_levels(leaves)
    path = anchor_chunk_path(levels, 3102)
    assert len(path) == 12
    h, pos = leaves[3102], 3102
    for sibling in path:
        h = anchor_node(sibling, h) if pos & 1 else anchor_node(h, sibling)
        pos >>= 1
    assert h == levels[-1][0]
    assert h_iroha(b"x")[-1] & 1 == 1


def test_certificate_aggregate_equals_sum_of_signatures():
    committee = Committee("t", (0, 1, 2, 3))
    header = FinalityHeader(network_id=rep(0x11), height=5, timestamp_ms=1, generation=1, committee_root=committee.root)
    cert = build_certificate(
        keys=committee.keys,
        secret_of=committee.secret_of,
        signer_indices=[0, 2, 3],
        header=header.encode(),
        instance=rep(0x77),
        epoch=0,
        epoch_context=rep(0x88),
        view=0,
        block_hash=rep(0x99),
        result_body=rep(0x66),
    )
    m = cert.meta["m"]
    individual = aggregate([sign(committee.secret_of[committee.keys[i]], m) for i in (0, 2, 3)])
    assert individual == cert.signature_ton
    assert fast_aggregate_verify([committee.keys[i] for i in (0, 2, 3)], m, cert.signature_ton)
    assert hash_to_g2(m, DST_SIG) == cert.meta["hash_point"]


# -- destination model ------------------------------------------------------------------

T0 = 1_800_000_000_000


def _route(flavor: str):
    """The profile and the destination word of a destination of `flavor` (the TON word is a placeholder)."""
    return (TON, rep(0x35)) if flavor == "ton" else (ETHEREUM, bytes(12) + rep(0x22, 20))


def _recipient(flavor: str) -> bytes:
    return bytes(4) + rep(0x44, 32) if flavor == "ton" else rep(0x44, 20)


def _destination(flavor: str = "evm"):
    k0 = Committee("K0", (40, 41, 42, 43))
    network, word = _route(flavor)
    sim = TairaSim(rep(0x11), rep(0x77), network, word)
    sim.start(5, k0, 1000, T0, 1_209_600_000)
    deployment = Deployment(
        flavor, rep(0x11), rep(0x77), network, word, 1, 10**18, 5, k0.root, 1000, T0 + 1_209_600_000, k0.keys
    )
    return sim, k0, Destination(deployment)


def _x(k0, height, flags=FLAG_ACTIVE, **fields):
    return FinalityHeader(network_id=rep(0x11), height=height, timestamp_ms=T0, flags=flags, generation=5, committee_root=k0.root, **fields)


@pytest.mark.parametrize(
    "first,second,reason",
    [
        (1010, ("conflict", 1010), 1),
        (None, ("plain", 999), 2),
        (1060, ("rotation", 1050), 3),
    ],
)
def test_violation_predicates_latch(first, second, reason):
    sim, k0, dest = _destination()
    if first is not None:
        assert dest.submit_checkpoints([sim.certify(_x(k0, first), k0)], T0)["outcome"] == "ok"
    kind, height = second
    if kind == "conflict":
        x = _x(k0, height, message_count=1, sccp_root=rep(0xEE))
    elif kind == "rotation":
        x = _x(k0, height, flags=FLAG_ACTIVE | FLAG_ROTATION, validity_ms=1, next_committee_root=k0.root)
    else:
        x = _x(k0, height)
    out = dest.submit_checkpoints([sim.certify(x, k0)], T0)
    assert out["outcome"] == "ok" and out["stopped"] == "latch"
    assert [e["reason"] for e in out["events"] if e["event"] == "SccpLatched"] == [reason]
    assert dest.state.equivocated and dest.state.until_ms == 0
    assert dest.void_frozen(0, 1, T0)["outcome"] == "ok"


def test_batch_is_atomic_and_nothing_to_do():
    sim, k0, dest = _destination()
    good = sim.certify(_x(k0, 1010), k0)
    bad = sim.certify(_x(k0, 1011), k0, signed_instance=rep(0x78))
    assert dest.submit_checkpoints([good, bad], T0)["outcome"] == "BadSignature"
    assert dest.state.checkpoints == {}
    assert dest.submit_checkpoints([good], T0)["outcome"] == "ok"
    assert dest.submit_checkpoints([good], T0)["outcome"] == "NothingToDo"
    assert dest.submit_checkpoints([good] * 17, T0)["outcome"] == "TooManyCertificates"


def test_rotation_deadline_is_anchored_at_t_eff():
    sim, k0, dest = _destination()
    k1 = Committee("K1", (44, 45, 46, 47))
    x = _x(k0, 1100, flags=FLAG_ACTIVE | FLAG_ROTATION, validity_ms=1000, next_committee_root=k1.root).with_(timestamp_ms=T0 + 50)
    assert dest.submit_checkpoints([sim.certify(x, k0)], T0 + 10)["outcome"] == "ok"
    assert (dest.state.generation, dest.state.start, dest.state.until_ms) == (6, 1101, T0 + 10 + 1000)


def test_ton_rotation_needs_next_keys():
    sim, k0, dest = _destination("ton")
    k1 = Committee("K1", (44, 45, 46, 47))
    x = _x(k0, 1100, flags=FLAG_ACTIVE | FLAG_ROTATION, validity_ms=1000, next_committee_root=k1.root)
    cert = sim.certify(x, k0)
    for invalid in (None, [], k1.keys[:3], list(reversed(k1.keys)), [key[:-1] for key in k1.keys], k0.keys):
        before = copy.deepcopy(dest.state)
        assert dest.submit_checkpoints([cert], T0, [invalid])["outcome"] == "BadCommittee"
        assert dest.state == before
    assert dest.submit_checkpoints([cert], T0, [k1.keys])["outcome"] == "ok"
    assert dest.state.keys == k1.keys


def test_check_block_ref_and_leaf():
    x = _x(Committee("K0", (40, 41, 42, 43)), 50, message_count=1, sccp_root=rep(0x21), history_size=3, history_root=rep(0x31))
    check_block_ref(50, rep(0x21), 1, 0, [], x)
    for args in ((50, rep(0x22), 1, 0, []), (51, rep(0x21), 1, 0, []), (40, rep(0x21), 0, 0, [])):
        with pytest.raises(SccpError):
            check_block_ref(*args, x)
    leaves = [rep(1), rep(2), rep(3)]
    check_leaf(leaves[2], 2, 3, tree_path(leaves, 2), tree_root(leaves))
    with pytest.raises(SccpError):
        check_leaf(leaves[2], 1, 3, tree_path(leaves, 2), tree_root(leaves))


def test_helper_functions():
    from sccp_reference.finality import (
        anchor_chunk_position,
        body_digest,
        canonical_order,
        checkpoint_id,
        forgery_evidence_id,
        indices_from_signers,
        y_sign_flag_matches,
    )
    from sccp_reference.merkle import control_leaf_preimage, control_leaf_ton_builders
    from sccp_reference.payload import lane_bytes, network_bytes

    f = bls.miller_loop(bls.G1_GENERATOR, bls.G2_GENERATOR)
    assert bls.f12_frobenius_p2(f) == bls.f12_pow(f, bls.P * bls.P)
    assert bls.fp_to_bytes64(5) == bytes(63) + b"\x05"
    rfc = HASH_TO_G2_RO[0]["p"]
    point = ((int(rfc[0][0], 16), int(rfc[0][1], 16)), (int(rfc[1][0], 16), int(rfc[1][1], 16)))
    assert bls.g2_uncompressed_zcash(point).hex().startswith(rfc[0][1][2:])
    assert len(network_bytes(TON, rep(0x11))) == 33 and len(lane_bytes(TAIRA, TON, rep(0x11))) == 66
    with pytest.raises(ValueError):
        lane_bytes(ETHEREUM, TON, rep(0x11))
    preimage = control_leaf_preimage(rep(0x11), ETHEREUM, bytes(32), 1, 1, 1, 0, 0, rep(1), rep(2))
    b1, b2 = control_leaf_ton_builders(preimage)
    assert (len(b1), len(b2)) == (125, 74) and keccak256(b1, b2) == keccak256(preimage)
    assert indices_from_signers(0x40000201) == [0, 9, 30]
    with pytest.raises(ValueError):
        canonical_order([rep(1, 48), rep(1, 48)])
    assert anchor_chunk_position(4096) == (0, 4095) and anchor_chunk_position(4097) == (1, 0)
    assert len(body_digest(b"")) == 32 and body_digest(b"")[-1] & 1
    assert checkpoint_id(bytes(221)) == keccak256(bytes(221))
    assert len(forgery_evidence_id(1, bytes(32), 7)) == 32
    pk = bls.g1_compress(bls.G1_GENERATOR)
    assert y_sign_flag_matches(pk, bls.G1_GENERATOR[1]) and not y_sign_flag_matches(pk, bls.P - bls.G1_GENERATOR[1])
    with pytest.raises(ValueError):
        keygen(bytes(31))


def test_destination_finalize_control_and_views():
    sim, k0, dest = _destination()
    recipient = rep(0x44, 20)
    block = sim.block(1010, T0, [sim.control(1, 2, 0, T0 + 500, rep(1), rep(2)), sim.transfer(0, 10**9, T0 + 1000, recipient)])
    cert = sim.certify(block.header, k0)
    assert dest.apply_control(("inline", cert), sim.control_proof(1010, 0, block.header), T0)["outcome"] == "ok"
    assert dest.pause_state(T0)["effective"] and not dest.pause_state(T0 + 500)["effective"]
    proof = sim.message_proof(1010, 1, block.header)
    assert dest.finalize(("checkpoint", block.x), proof, T0 + 100)["outcome"] == "MintingIsPaused"
    assert dest.finalize(("checkpoint", block.x), proof, T0 + 500)["outcome"] == "ok"
    assert dest.void_expired(0, ("checkpoint", block.x), proof, T0 + 1001)["outcome"] == "AlreadyConsumed"
    assert dest.verify_certificate(cert, T0)["outcome"] == "ok"
    assert dest.state.op_count == 2 and dest.state.total_supply == 10**9


# -- VerifyCertificate step 6 and the cheap path ---------------------------------------------


def test_committee_root_is_defined_for_1_to_255_keys():
    key = rep(0x07, 48)
    assert len(committee_root([key])) == 32 and len(committee_root([key] * 255)) == 32
    assert committee_root([key]) != committee_root([key] * 2)
    for keys in ([], [key] * 256, [key[:-1]]):
        with pytest.raises(ValueError):
            committee_root(keys)


@pytest.mark.parametrize("flavor", ["evm", "ton"])
def test_identity_signature_is_refused_before_the_cheap_path(flavor):
    """§5.1.3 step 6 refuses `σ = O` on both flavors, so they agree on a certificate whose `X` is stored."""
    sim, k0, dest = _destination(flavor)
    genuine = sim.certify(_x(k0, 1010), k0)
    assert IDENTITY_SIGNATURE_COMPRESSED == bytes([0xC0]) + bytes(95) and bls.g2_decompress(IDENTITY_SIGNATURE_COMPRESSED) is None
    identity = dataclasses.replace(genuine, signature_evm=bytes(192), signature_ton=IDENTITY_SIGNATURE_COMPRESSED)
    other_instance = sim.certify(_x(k0, 1010), k0, signed_instance=rep(0x78))
    refused = {"outcome": "BadSignature", "detail": "identity signature"}
    # X is not stored: the full path refuses both, the identity at step 6 and the other one at the pairing.
    assert dest.verify_certificate(identity, T0) == refused
    assert dest.verify_certificate(other_instance, T0) == {"outcome": "BadSignature", "detail": "pairing"}
    out = dest.submit_checkpoints([genuine], T0)
    assert out["outcome"] == "ok" and [e["event"] for e in out["events"]] == ["SccpCertificate", "SccpCheckpointed"]
    # X is stored: the cheap path skips the signature check and the publication, but not step 6.
    assert dest.verify_certificate(other_instance, T0) == {"outcome": "ok"}
    assert dest.submit_checkpoints([other_instance], T0)["outcome"] == "NothingToDo"
    assert dest.verify_certificate(identity, T0) == refused
    assert dest.submit_checkpoints([identity], T0) == refused
    assert dest.state.checkpoints == {1010: keccak256(_x(k0, 1010).encode())} and len(dest.events) == 2


def test_step_6_checks_run_in_their_stated_order_on_evm():
    """§5.1.3 step 6: `σ = O`, then every signer `y < p`, then every `σ` limb `< p`, then the signer keys."""
    sim, k0, dest = _destination()
    cert = sim.certify(_x(k0, 1010), k0)
    y0 = int.from_bytes(cert.signer_ys[:48], "big")
    y_ge_p = (y0 + bls.P).to_bytes(48, "big") + cert.signer_ys[48:]
    wrong_sign = (bls.P - y0).to_bytes(48, "big") + cert.signer_ys[48:]
    limb = int.from_bytes(cert.signature_evm[:48], "big")
    limb_ge_p = (limb + bls.P).to_bytes(48, "big") + cert.signature_evm[48:]
    detail = lambda **changes: dest.verify_certificate(dataclasses.replace(cert, **changes), T0).get("detail")  # noqa: E731
    assert dest.verify_certificate(cert, T0) == {"outcome": "ok"}
    assert detail(signature_evm=bytes(192), signer_ys=y_ge_p) == "identity signature"
    assert detail(signer_ys=y_ge_p, signature_evm=limb_ge_p) == "signer y not reduced"
    assert detail(signature_evm=limb_ge_p, signer_ys=wrong_sign) == "signature limb not reduced"
    assert detail(signer_ys=wrong_sign) == "key sign bit"
    # Step 5 precedes all of them: a spare signer bit with an identity signature is BadCertificate.
    spare = cert.qc[:112] + (int.from_bytes(cert.qc[112:], "big") | 1 << 4).to_bytes(4, "big")
    assert dest.verify_certificate(dataclasses.replace(cert, qc=spare, signature_evm=bytes(192)), T0)["outcome"] == "BadCertificate"


def test_cheap_path_is_not_a_deployment_option():
    """The cheap path is mandatory (§5.1.3 step 8): neither the model nor a fixture deployment carries a switch."""
    assert "cheap_path" not in {f.name for f in dataclasses.fields(Deployment)}
    _, _, dest = _destination()
    assert "cheap_path" not in dest.d.as_json()
    scenarios = _fixture_scenarios()
    assert scenarios and all("cheap_path" not in scenario["deployment"] for _, scenario in scenarios)


def _zero_key_destination():
    """An EVM destination whose pinned root commits to a key 0 with `x = 0`, and a header of that committee."""
    k0 = Committee("K0", (40, 41, 42, 43))
    bad_keys = [bytes([0x80]) + bytes(47)] + k0.keys[1:]
    root = committee_root(bad_keys)
    sim = TairaSim(rep(0x11), rep(0x77), ETHEREUM, bytes(12) + rep(0x22, 20))
    deployment = Deployment(
        "evm", rep(0x11), rep(0x77), ETHEREUM, bytes(12) + rep(0x22, 20), 1, 10**18, 5, root, 1000, T0 + 1_209_600_000, bad_keys
    )
    header = FinalityHeader(network_id=rep(0x11), height=1010, timestamp_ms=T0, generation=5, committee_root=root)
    return sim, k0, bad_keys, Destination(deployment), header


def test_signer_coordinate_checks_precede_the_cheap_path():
    """EVM step 6: a signer with `x ≥ p` or the coordinates `(0, 0)` is `BadCommittee` even when `X` is stored."""
    sim, k0, bad_keys, dest, header = _zero_key_destination()
    committee = b"".join(bad_keys)
    # Signers 1, 2 and 3 never read key 0, so their certificate verifies and stores X.
    genuine = dataclasses.replace(sim.certify(header, k0, signer_indices=[1, 2, 3]), committee=committee)
    assert dest.submit_checkpoints([genuine], T0)["outcome"] == "ok"
    with_zero = sim.certify(header, k0, signer_indices=[0, 1, 2])
    with_zero = dataclasses.replace(with_zero, committee=committee, signer_ys=bytes(48) + with_zero.signer_ys[48:])
    assert dest.verify_certificate(with_zero, T0) == {"outcome": "BadCommittee", "detail": "signer coordinates (0, 0)"}
    # Only the pair (0, 0) is refused here: x = 0 with a nonzero y passes step 6 and takes the cheap path.
    nonzero_y = dataclasses.replace(with_zero, signer_ys=(1).to_bytes(48, "big") + with_zero.signer_ys[48:])
    assert dest.verify_certificate(nonzero_y, T0) == {"outcome": "ok"}


def test_evm_key_negatives_fail_at_the_check_they_name():
    """Each EVM key negative of `finality_v1.json` fails at its own check (step 6, or step 10 for the off-curve
    `y`), and the `x ≥ p` and `(0, 0)` rows are pinned under a root that commits to their key."""
    doc = json.loads((FIXTURES / "finality_v1.json").read_text())
    rows = {entry["label"]: entry for entry in doc["negative_certificates"]}
    expected = {
        "signer_y_wrong_sign": "key sign bit",
        "signer_y_ge_p": "signer y not reduced",
        "signer_y_off_curve": "signer key off curve",
        "key_flag_infinity_0xc0": "key flags",
        "key_flag_uncompressed": "key flags",
        "signer_x_ge_p": "signer x not reduced",
        "signer_zero_coordinates": "signer coordinates (0, 0)",
    }
    for label, detail in expected.items():
        entry = rows[label]
        ton_outcome = None if label.startswith("signer_y_") else "BadSignature"
        assert entry["expected"] == {"evm": "BadCommittee", "ton": ton_outcome}, label
        out = _fixture_destination(doc, entry, "evm").verify_certificate(_fixture_certificate(entry), entry["now_ms"])
        assert (out["outcome"], out.get("detail")) == ("BadCommittee", detail), (label, out)
    for label in ("key_flag_infinity_0xc0", "key_flag_uncompressed", "signer_x_ge_p", "signer_zero_coordinates"):
        entry = rows[label]
        assert [unhex(key) for key in entry["pin"]["keys"]] == sorted(unhex(key) for key in entry["pin"]["keys"])
    for label in ("signer_x_ge_p", "signer_zero_coordinates"):
        entry = rows[label]
        keys = [unhex(k) for k in entry["pin"]["keys"]]
        assert unhex(entry["evm"]["committee"]) == b"".join(keys)
        assert committee_root(keys) == unhex(entry["pin"]["committee_root"]) == unhex(entry["evm"]["header"])[149:181]
        assert keys[0][0] & 0xC0 == 0x80
    x_row = rows["signer_x_ge_p"]
    x_keys = [unhex(key) for key in x_row["pin"]["keys"]]
    seat = next(index for index, key in enumerate(x_keys) if int.from_bytes(bytes([key[0] & 0x1F]) + key[1:], "big") >= bls.P)
    signer_position = x_row["signer_indices"].index(seat)
    encoded_ys = unhex(x_row["evm"]["signerYs"])
    assert int.from_bytes(encoded_ys[48 * signer_position : 48 * (signer_position + 1)], "big") < bls.P
    zero = rows["signer_zero_coordinates"]
    assert unhex(zero["pin"]["keys"][0]) == bytes([0x80]) + bytes(47) and unhex(zero["evm"]["signerYs"])[:48] == bytes(48)


# -- checkpoint use (§5.1.3) ------------------------------------------------------------------


def test_checkpoint_eligibility_is_the_current_generation_or_its_installing_handoff():
    """U1: `X` is CUR. U2: `X` is the rotation of `cur.generation − 1` at `cur.start − 1` whose successor is `cur.root`."""
    sim, k0, dest = _destination()
    k1 = Committee("K1", (44, 45, 46, 47))
    rotation = FLAG_ACTIVE | FLAG_ROTATION
    handoff = _x(k0, 1100, flags=rotation, validity_ms=1_209_600_000, next_committee_root=k1.root)
    # At the pin (generation 5 from height 1000): only headers of generation 5 under the pinned root.
    assert dest.checkpoint_eligible(_x(k0, 1010)) and dest.checkpoint_eligible(handoff)
    assert not dest.checkpoint_eligible(_x(k0, 1010).with_(generation=4))
    assert not dest.checkpoint_eligible(_x(k0, 1010).with_(committee_root=k1.root))
    pin_handoff = _x(k1, 999, flags=rotation, validity_ms=1, next_committee_root=k0.root).with_(generation=4)
    assert dest.checkpoint_eligible(pin_handoff)  # U2 as a predicate; no destination stores a header it did not verify
    assert dest.submit_checkpoints([sim.certify(_x(k0, 1010), k0), sim.certify(handoff, k0)], T0)["outcome"] == "ok"
    assert (dest.state.generation, dest.state.start, dest.state.root) == (6, 1101, k1.root)
    # Generation 6: its own headers (U1) and the handoff that installed it (U2); nothing else of generation 5.
    own = FinalityHeader(network_id=rep(0x11), height=1150, timestamp_ms=T0, generation=6, committee_root=k1.root)
    assert dest.checkpoint_eligible(own) and dest.checkpoint_eligible(handoff)
    assert not dest.checkpoint_eligible(_x(k0, 1010))
    for changed in (
        handoff.with_(flags=FLAG_ACTIVE, validity_ms=0, next_committee_root=bytes(32)),  # not a rotation
        handoff.with_(height=1099),  # not at cur.start − 1
        handoff.with_(height=1101),
        handoff.with_(next_committee_root=k0.root),  # another successor
        handoff.with_(generation=4),  # two generations old
        handoff.with_(generation=6),  # not CUR either: its committee root is the old one
    ):
        assert not dest.checkpoint_eligible(changed), changed
    # A heartbeat keeps the root: the non-handoff headers of the old generation are still refused.
    sim, k0, dest = _destination()
    heartbeat = _x(k0, 1100, flags=rotation, validity_ms=1_209_600_000, next_committee_root=k0.root)
    assert dest.submit_checkpoints([sim.certify(_x(k0, 1010), k0), sim.certify(heartbeat, k0)], T0)["outcome"] == "ok"
    assert (dest.state.generation, dest.state.root) == (6, k0.root)
    assert dest.checkpoint_eligible(heartbeat) and not dest.checkpoint_eligible(_x(k0, 1010))
    assert dest.checkpoint_eligible(_x(k0, 1150).with_(generation=6))


def _forger(k0):
    """A second producer under the same identity and keys: the headers Taira never certified."""
    forger = TairaSim(rep(0x11), rep(0x77), ETHEREUM, bytes(12) + rep(0x22, 20))
    forger.start(5, k0, 1000, T0, 1_209_600_000)
    return forger


def test_checkpoint_use_check_order():
    """Stored id (`UnknownCheckpoint`), X1–X7 with `ACTIVE`, `Live`, then eligibility (`CommitteeNotAccepted`)."""
    sim, k0, dest = _destination()
    k1 = Committee("K1", (44, 45, 46, 47))
    recipient = rep(0x44, 20)
    block = sim.block(1010, T0, [sim.transfer(0, 10**9, T0 + 10**9, recipient), sim.transfer(1, 10**9, T0 + 10**9, recipient)])
    handoff = sim.block(1100, T0 + 1000, rotate="key", next_committee=k1)
    proof = sim.message_proof(1010, 0, block.header)
    use = lambda x, now: dest.finalize(("checkpoint", x), proof, now)  # noqa: E731
    assert use(block.x[:-1], T0) == {"outcome": "BadHeader", "detail": "X length"}
    assert use(block.x, T0)["outcome"] == "UnknownCheckpoint"
    assert dest.submit_checkpoints([sim.certify(block.header, k0), sim.certify(handoff.header, k0)], T0 + 1000)["outcome"] == "ok"
    # Stored but no longer eligible; an unknown header of the old generation is still UnknownCheckpoint.
    assert use(block.x, T0 + 1000) == {"outcome": "CommitteeNotAccepted", "detail": "checkpoint of a retired generation"}
    assert use(_x(k0, 1020).encode(), T0 + 1000)["outcome"] == "UnknownCheckpoint"
    # Live is checked before eligibility: an expired destination answers for the expiry, a latched one Equivocated.
    expired = dest.state.until_ms + 1000
    assert use(block.x, expired) == {"outcome": "CommitteeNotAccepted", "detail": "destination expired"}
    dest.state.equivocated = True
    assert use(block.x, T0 + 1000)["outcome"] == "Equivocated"
    assert use(handoff.x, T0 + 1000)["outcome"] == "Equivocated"
    dest.state.equivocated = False
    # The installing handoff proves the old block through its history root.
    out = dest.finalize(("checkpoint", handoff.x), sim.message_proof(1010, 0, handoff.header), T0 + 1000)
    assert out["outcome"] == "ok" and dest.state.consumed == {0}


def test_forged_in_tenure_checkpoint_stops_at_the_genuine_handoff():
    """A forged non-handoff checkpoint of `g` is usable while `g` is current and not after its genuine handoff."""
    sim, k0, dest = _destination()
    k1 = Committee("K1", (44, 45, 46, 47))
    recipient = rep(0x44, 20)
    forger = _forger(k0)
    forged = forger.block(1030, T0, [forger.transfer(7, 10**9, T0 + 10**9, recipient), forger.transfer(8, 10**9, T0 + 10**9, recipient)])
    handoff = sim.block(1100, T0 + 1000, rotate="key", next_committee=k1)
    assert dest.submit_checkpoints([forger.certify(forged.header, k0)], T0)["outcome"] == "ok"
    assert dest.finalize(("checkpoint", forged.x), forger.message_proof(1030, 0, forged.header), T0)["outcome"] == "ok"
    assert dest.submit_checkpoints([sim.certify(handoff.header, k0)], T0 + 1000)["outcome"] == "ok"
    out = dest.finalize(("checkpoint", forged.x), forger.message_proof(1030, 1, forged.header), T0 + 1000)
    assert out["outcome"] == "CommitteeNotAccepted"
    # No new authorization comes from the retired generation; the mint already made survives the rotation.
    assert dest.state.consumed == {7} and dest.state.total_supply == 10**9 and not dest.state.equivocated


def test_forged_handoff_captures_and_stays_usable():
    """A forged handoff naming the genuine successor root installs `cur`; the genuine handoff is then not CUR."""
    sim, k0, dest = _destination()
    k1 = Committee("K1", (44, 45, 46, 47))
    recipient = rep(0x44, 20)
    genuine = sim.block(1100, T0 + 1000, rotate="key", next_committee=k1)
    forger = _forger(k0)
    forged = forger.block(1100, T0 + 1000, [forger.transfer(9, 10**9, T0 + 10**9, recipient)], rotate="key", next_committee=k1)
    assert forged.header.next_committee_root == genuine.header.next_committee_root and forged.x != genuine.x
    assert dest.submit_checkpoints([forger.certify(forged.header, k0)], T0 + 1000)["outcome"] == "ok"
    assert (dest.state.generation, dest.state.root, dest.state.start) == (6, k1.root, 1101)
    # The forged handoff stays eligible under U2, and the genuine one is refused without latching.
    assert dest.finalize(("checkpoint", forged.x), forger.message_proof(1100, 0, forged.header), T0 + 1000)["outcome"] == "ok"
    before = copy.deepcopy(dest.state)
    assert dest.submit_checkpoints([sim.certify(genuine.header, k0)], T0 + 1000)["outcome"] == "CommitteeNotAccepted"
    assert dest.state == before and not dest.state.equivocated
    assert dest.finalize(("checkpoint", genuine.x), _fixture_free_proof(sim, recipient), T0 + 1000)["outcome"] == "UnknownCheckpoint"
    # The next rotation, by the genuine successor committee, retires it.
    sim6 = TairaSim(rep(0x11), rep(0x77), ETHEREUM, bytes(12) + rep(0x22, 20))
    sim6.start(6, k1, 1101, T0 + 1000, 1_209_600_000)
    heartbeat = sim6.block(1200, T0 + 2000, rotate="heartbeat")
    assert dest.submit_checkpoints([sim6.certify(heartbeat.header, k1)], T0 + 2000)["outcome"] == "ok"
    out = dest.finalize(("checkpoint", forged.x), forger.message_proof(1100, 0, forged.header), T0 + 2000)
    assert out["outcome"] == "CommitteeNotAccepted" and dest.state.generation == 7


def _fixture_free_proof(sim, recipient):
    """A syntactically complete message proof for a call that fails before the proof is read."""
    from sccp_reference.destination import BlockRef, MessageProof

    return MessageProof(sim.transfer(0, 10**9, T0 + 10**9, recipient).payload, 0, [], BlockRef(1100, rep(0x01), 1))


# -- fixed-width arithmetic ---------------------------------------------------------------

FROZEN = T0 + 1_209_600_000 + 1000  # the first clock value after the pin's deadline


def test_saturating_u64_sum():
    assert saturating_u64_sum(0, 0) == 0 and saturating_u64_sum(T0, MAX_VALIDITY_MS) == T0 + MAX_VALIDITY_MS
    assert saturating_u64_sum(U64_MAX - 5, 5) == U64_MAX
    assert saturating_u64_sum(U64_MAX - 5, 6) == U64_MAX
    assert saturating_u64_sum(U64_MAX, U64_MAX) == U64_MAX
    for a, b in ((-1, 0), (0, -1), (U64_MAX + 1, 0), (0, U64_MAX + 1)):
        with pytest.raises(ValueError, match="u64 operands"):
            saturating_u64_sum(a, b)


def test_void_frozen_range_at_the_u64_end():
    """`firstNonce + count ≤ 2^64` is decided without the sum, and the last nonce `2^64 − 1` can be voided."""
    firsts = (0, 1, U64_MAX - 512, U64_MAX - 256, U64_MAX - 255, U64_MAX - 1, U64_MAX)
    for limit in (256, 512):
        for first in firsts:
            for count in (0, 1, 2, 255, 256, 257, 512, 513):
                assert void_frozen_range_ok(first, count, limit) == (1 <= count <= limit and first + count <= 1 << 64)
    assert not void_frozen_range_ok(U64_MAX + 1, 1, 256) and not void_frozen_range_ok(-1, 1, 256)
    _, _, dest = _destination()
    assert dest.void_frozen(U64_MAX, 2, FROZEN)["outcome"] == "BadAmount"
    assert dest.void_frozen(U64_MAX - 255, 257, FROZEN)["outcome"] == "BadAmount"
    assert dest.void_frozen(U64_MAX, 0, FROZEN)["outcome"] == "BadAmount"
    out = dest.void_frozen(U64_MAX, 1, FROZEN)
    assert out["outcome"] == "ok" and [e["nonce"] for e in out["events"]] == [U64_MAX]
    out = dest.void_frozen(U64_MAX - 255, 256, FROZEN)
    assert (out["outcome"], out["error_args"]) == ("AlreadyConsumed", {"nonce": U64_MAX})
    out = dest.void_frozen(U64_MAX - 255, 255, FROZEN)
    assert out["outcome"] == "ok" and len(out["events"]) == 255 and max(dest.state.consumed) == U64_MAX
    _, _, ton = _destination("ton")
    assert ton.void_frozen(U64_MAX, 2, FROZEN)["outcome"] == "BadRange"
    assert ton.void_frozen(U64_MAX - 512, 512, FROZEN)["outcome"] == "BadRange"  # crosses a bucket of 512 nonces
    out = ton.void_frozen(U64_MAX - 511, 512, FROZEN)
    assert out["outcome"] == "ok" and out["events"][0]["firstNonce"] == U64_MAX - 511 and out["events"][0]["count"] == 512
    # The range is checked before Frozen: on a Live destination a range failure wins, and a valid range is NotFrozen.
    _, _, live = _destination()
    for first, count in ((10, 0), (10, 257), (U64_MAX, 2)):
        assert live.void_frozen(first, count, T0)["outcome"] == "BadAmount", (first, count)
    assert live.void_frozen(10, 1, T0)["outcome"] == "NotFrozen"
    _, _, live_ton = _destination("ton")
    for first, count in ((10, 0), (10, 513), (510, 4), (U64_MAX, 2)):
        assert live_ton.void_frozen(first, count, T0)["outcome"] == "BadRange", (first, count)
    assert live_ton.void_frozen(10, 1, T0)["outcome"] == "NotFrozen"
    assert not live.state.consumed and not live_ton.state.consumed


def test_fast_pause_clamp_saturates_its_bound():
    """`min(leaf, min(now + MAX_FAST_PAUSE_MS, 2^64 − 1))`: the bound saturates, so the clamp never aborts."""
    times = (0, 1, T0, U64_MAX - MAX_FAST_PAUSE_MS - 1, U64_MAX - MAX_FAST_PAUSE_MS, U64_MAX - 1000, U64_MAX)
    untils = (0, 1, T0, T0 + MAX_FAST_PAUSE_MS, T0 + MAX_FAST_PAUSE_MS + 1, U64_MAX - 1, U64_MAX)
    for now in times:
        for until in untils:
            clamped = clamped_fast_pause(until, now)
            assert clamped == min(until, min(now + MAX_FAST_PAUSE_MS, U64_MAX))
            assert clamped == min(until, now + MAX_FAST_PAUSE_MS) and clamped <= U64_MAX
    assert clamped_fast_pause(U64_MAX, U64_MAX - MAX_FAST_PAUSE_MS - 1) == U64_MAX - 1
    assert clamped_fast_pause(U64_MAX, U64_MAX - MAX_FAST_PAUSE_MS) == U64_MAX
    assert clamped_fast_pause(U64_MAX, U64_MAX) == U64_MAX
    sim, k0, dest = _destination()
    block = sim.block(1010, T0, [sim.control(1, 2, 0, U64_MAX, rep(1), rep(2))])
    assert dest.apply_control(("inline", sim.certify(block.header, k0)), sim.control_proof(1010, 0, block.header), T0)["outcome"] == "ok"
    assert dest.state.fast_pause_until_ms == T0 + MAX_FAST_PAUSE_MS
    # A destination clock within MAX_FAST_PAUSE_MS of 2^64 ms: the control is applied with the saturated bound.
    sim, k0, dest = _destination()
    late = Destination(dataclasses.replace(dest.d, pin_until_ms=U64_MAX))
    now = U64_MAX // 1000 * 1000
    block = sim.block(1010, T0, [sim.control(1, 2, 0, U64_MAX, rep(1), rep(2)), sim.control(2, 2, 0, U64_MAX - 1, rep(3), rep(4))])
    cert = sim.certify(block.header, k0)
    out = late.apply_control(("inline", cert), sim.control_proof(1010, 0, block.header), now)
    assert out["outcome"] == "ok" and out["events"][-1]["fastPauseUntilMs"] == U64_MAX
    assert late.state.fast_pause_until_ms == U64_MAX and late.effective_pause(now)
    assert late.apply_control(("checkpoint", block.x), sim.control_proof(1010, 1, block.header), now)["outcome"] == "ok"
    assert late.state.fast_pause_until_ms == U64_MAX - 1


def test_supply_cap_check_never_needs_a_wide_sum():
    """With a cap of `2^128 − 1` the sum `totalSupply + amount` exceeds `u128`; the outcome is `SupplyCapExceeded`."""
    sim, k0, dest = _destination()
    cap = (1 << 128) - 1
    dest = Destination(dataclasses.replace(dest.d, max_wrapped_supply=cap))
    recipient = rep(0x44, 20)
    transfers = [sim.transfer(0, cap - 1, T0 + 1000, recipient), sim.transfer(1, cap, T0 + 1000, recipient), sim.transfer(2, 1, T0 + 1000, recipient)]
    block = sim.block(1010, T0, transfers)
    cert = sim.certify(block.header, k0)
    assert dest.finalize(("inline", cert), sim.message_proof(1010, 0, block.header), T0)["outcome"] == "ok"
    assert dest.finalize(("checkpoint", block.x), sim.message_proof(1010, 1, block.header), T0)["outcome"] == "SupplyCapExceeded"
    assert dest.state.consumed == {0} and dest.state.total_supply == cap - 1
    assert dest.finalize(("checkpoint", block.x), sim.message_proof(1010, 2, block.header), T0)["outcome"] == "ok"
    assert dest.state.total_supply == cap


def test_op_count_saturates_at_the_u64_end():
    """`opCount` never wraps (§5.1.1): the operation that reaches `2^64 − 1` succeeds, and so does every later one."""
    assert [bumped_op_count(count) for count in (0, 1, U64_MAX - 2, U64_MAX - 1, U64_MAX)] == [1, 2, U64_MAX - 1, U64_MAX, U64_MAX]
    for count in (-1, U64_MAX + 1):
        with pytest.raises(ValueError, match="u64"):
            bumped_op_count(count)
    # The four counted operations of the model at the bound: a mint, a control, a void by proof and a frozen range.
    sim, k0, dest = _destination()
    recipient = rep(0x44, 20)
    leaves = [
        sim.control(1, 1, 0, 0, rep(1), rep(2)),
        sim.transfer(0, 10**9, T0 + 10**9, recipient),
        sim.transfer(1, 10**9, T0, recipient),
        sim.transfer(2, 10**9, T0 + 10**9, recipient),
    ]
    block = sim.block(1010, T0, leaves)
    stored = ("checkpoint", block.x)
    assert dest.submit_checkpoints([sim.certify(block.header, k0)], T0)["outcome"] == "ok"
    assert dest.state.op_count == 0  # a checkpoint is not counted
    dest.state.op_count = U64_MAX - 1
    assert dest.finalize(stored, sim.message_proof(1010, 1, block.header), T0)["outcome"] == "ok"
    assert dest.state.op_count == U64_MAX
    assert dest.apply_control(stored, sim.control_proof(1010, 0, block.header), T0)["outcome"] == "ok"
    assert dest.void_expired(1, stored, sim.message_proof(1010, 2, block.header), T0 + 1000)["outcome"] == "ok"
    assert dest.finalize(stored, sim.message_proof(1010, 3, block.header), T0 + 1000)["outcome"] == "ok"
    assert dest.void_frozen(7, 3, FROZEN)["outcome"] == "ok"
    assert dest.state.op_count == U64_MAX
    assert (dest.state.consumed, dest.state.control_nonce, dest.state.total_supply) == ({0, 1, 2, 7, 8, 9}, 1, 2 * 10**9)
    # A refused call at the bound changes nothing, the counter included.
    assert dest.void_frozen(7, 1, FROZEN)["outcome"] == "AlreadyConsumed" and dest.state.op_count == U64_MAX


@pytest.mark.parametrize("length", [1, 126, 127, 128, 1024])
def test_ton_burn_recipient_bound_and_canonical_wrapper(length):
    recipient = bytes(i % 251 for i in range(length))
    wrapper = burn_to_taira_payload(recipient)
    assert wrapper.bits == f"{TON_BURN_TO_TAIRA_OP:032b}"
    assert not wrapper.exotic and len(wrapper.refs) == 1
    assert check_ton_burn_payload(wrapper) == recipient
    assert parse_taira_recipient(wrapper.refs[0]) == recipient


def test_ton_burn_refuses_every_malformed_wrapper_and_recipient():
    """Wallet admission walks the entire snake before a debit or value-bearing send."""
    good = burn_to_taira_payload(b"x")
    tail = good.refs[0]
    oversized = dataclasses.replace(good, refs=(snake_bytes(bytes(12700)),))
    cases = {
        "missing wrapper": (None, "BadBurnPayload"),
        "wrong opcode": (dataclasses.replace(good, bits="0" * 32), "BadBurnPayload"),
        "exotic wrapper": (dataclasses.replace(good, exotic=True), "BadSnake"),
        "extra wrapper bit": (dataclasses.replace(good, bits=good.bits + "0"), "BadSnake"),
        "extra wrapper ref": (dataclasses.replace(good, refs=(tail, tail)), "BadSnake"),
        "missing wrapper ref": (dataclasses.replace(good, refs=()), "BadSnake"),
        "empty recipient": (dataclasses.replace(good, refs=(TonCell(""),)), "BadSnake"),
        "short nonfinal chunk": (dataclasses.replace(good, refs=(TonCell("0" * 1008, (tail,)),)), "BadSnake"),
        "extra recipient bit": (dataclasses.replace(good, refs=(TonCell("0" * 9),)), "BadSnake"),
        "extra recipient ref": (dataclasses.replace(good, refs=(TonCell("0" * 1016, (tail, tail)),)), "BadSnake"),
        "exotic recipient": (dataclasses.replace(good, refs=(dataclasses.replace(tail, exotic=True),)), "BadSnake"),
        "exotic continuation": (dataclasses.replace(good, refs=(TonCell("0" * 1016, (dataclasses.replace(tail, exotic=True),)),)), "BadSnake"),
        "1025 bytes": (dataclasses.replace(good, refs=(snake_bytes(bytes(1025)),)), "BadRecipient"),
        "100 full chunks": (oversized, "BadRecipient"),
    }
    for label, (wrapper, expected) in cases.items():
        with pytest.raises(SccpError) as refusal:
            check_ton_burn_payload(wrapper)
        assert refusal.value.name == expected, label


@pytest.mark.parametrize("recipient,expected", [(b"", "BadSnake"), (bytes(1025), "BadRecipient")])
def test_ton_burn_builder_refuses_unadmitted_recipients(recipient, expected):
    with pytest.raises(SccpError) as refusal:
        burn_to_taira_payload(recipient)
    assert refusal.value.name == expected


def test_source_nonces_end_at_the_u64_end_without_wrapping():
    """Source nonces are `0 ..= 2^64 − 2` (§5.1.7): a stored next nonce of `2^64 − 1` refuses every burn."""
    assert next_source_nonce(0, 0) == 1 and next_source_nonce(7, 7) == 8
    # The last nonce is used like any other, and leaves the exhausted value behind.
    assert next_source_nonce(U64_MAX - 1, U64_MAX - 1) == U64_MAX
    # A wrong expectation names the stored nonce.
    for stored, expected in ((0, 1), (7, 6), (7, 8), (U64_MAX - 1, U64_MAX), (U64_MAX - 1, 0)):
        with pytest.raises(SccpError) as refusal:
            next_source_nonce(stored, expected)
        assert (refusal.value.name, refusal.value.args_map) == ("BadNonce", {"expected": stored})
    # Exhausted: whatever the call expects, the equal value included, the answer is BadNonce(2^64 − 1).
    for expected in (U64_MAX, 0, 1, U64_MAX - 1):
        with pytest.raises(SccpError) as refusal:
            next_source_nonce(U64_MAX, expected)
        assert (refusal.value.name, refusal.value.args_map) == ("BadNonce", {"expected": U64_MAX})
    # No sequence of burns reaches a nonce twice: from any stored value the next one is larger, up to the bound.
    stored = U64_MAX - 3
    used = []
    while True:
        try:
            following = next_source_nonce(stored, stored)
        except SccpError:
            break
        used.append(stored)
        assert following == stored + 1 <= U64_MAX
        stored = following
    assert used == [U64_MAX - 3, U64_MAX - 2, U64_MAX - 1] and stored == U64_MAX
    for stored, expected in ((-1, 0), (0, -1), (U64_MAX + 1, 0), (0, U64_MAX + 1)):
        with pytest.raises(ValueError, match="u64"):
            next_source_nonce(stored, expected)


def test_rotation_deadline_saturates_and_no_call_aborts():
    """No destination call aborts for arithmetic (§5.1.2): `t_eff(X) + X.validity_ms` saturates at `2^64 − 1`."""
    for timestamp_ms, validity_ms, now_ms in (
        (T0, 1, T0),
        (T0 + 50, MAX_VALIDITY_MS, T0),
        (U64_MAX, MAX_VALIDITY_MS, U64_MAX - MAX_VALIDITY_MS),
        (U64_MAX, MAX_VALIDITY_MS, U64_MAX - MAX_VALIDITY_MS + 1),
        (U64_MAX - 1, 1, U64_MAX),
        (U64_MAX, 1, U64_MAX),
        (U64_MAX, MAX_VALIDITY_MS, U64_MAX),
    ):
        until = rotation_until_ms(timestamp_ms, validity_ms, now_ms)
        assert until == min(min(timestamp_ms, now_ms) + validity_ms, U64_MAX)
    assert rotation_until_ms(U64_MAX, MAX_VALIDITY_MS, U64_MAX - MAX_VALIDITY_MS) == U64_MAX
    assert rotation_until_ms(U64_MAX, MAX_VALIDITY_MS, U64_MAX - MAX_VALIDITY_MS - 1) == U64_MAX - 1
    assert rotation_until_ms(U64_MAX, MAX_VALIDITY_MS, U64_MAX) == U64_MAX
    # A deadline beyond the last millisecond: the clock is within the validity of 2^64 ms. The rotation is applied
    # with untilMs = 2^64 − 1, and the destination stays Live at that clock value.
    sim, k0, dest = _destination()
    now = U64_MAX // 1000 * 1000
    late = Destination(dataclasses.replace(dest.d, pin_until_ms=U64_MAX))
    x = _x(k0, 1100, flags=FLAG_ACTIVE | FLAG_ROTATION, validity_ms=1000, next_committee_root=k0.root).with_(timestamp_ms=now)
    assert now + 1000 > U64_MAX
    out = late.submit_checkpoints([sim.certify(x, k0)], now)
    assert out["outcome"] == "ok" and "stopped" not in out
    rotated = [e for e in out["events"] if e["event"] == "SccpCommitteeRotated"]
    assert rotated == [{"event": "SccpCommitteeRotated", "generation": 6, "root": "0x" + k0.root.hex(), "untilMs": U64_MAX, "startHeight": 1101}]
    assert (late.state.generation, late.state.start, late.state.until_ms) == (6, 1101, U64_MAX) and late.live(now)
    # The sum that fits exactly is not changed by the saturation, and neither is one below it.
    for validity_ms, until in ((U64_MAX - now, U64_MAX), (U64_MAX - now - 1, U64_MAX - 1)):
        exact = Destination(dataclasses.replace(dest.d, pin_until_ms=U64_MAX))
        assert exact.submit_checkpoints([sim.certify(x.with_(validity_ms=validity_ms), k0)], now)["outcome"] == "ok"
        assert exact.state.until_ms == until
    # `high = pin.start_height − 1` has no value for a pin at height 0, which no constructor accepts.
    with pytest.raises(ValueError, match="start_height"):
        Destination(dataclasses.replace(dest.d, pin_start_height=0))


# -- the destination clock ------------------------------------------------------------------


def test_destination_clock_is_whole_seconds_and_monotone():
    check_destination_clock(T0)
    check_destination_clock(T0, T0)
    check_destination_clock(T0 + 1000, T0)
    for now, previous in ((T0 + 1, None), (T0 + 999, T0), (T0 - 1000, T0), (-1000, None)):
        with pytest.raises(AssertionError):
            check_destination_clock(now, previous)


def test_scenario_recorder_enforces_the_destination_clock():
    """Generation fails on a step that an EVM or TON harness could not replay with block times."""
    from sccp_reference.scenario import CertificatePool, Scenario

    _, _, dest = _destination()
    sc = Scenario("clock", "recorder clock rule", dest.d, CertificatePool())
    sc.views(T0)
    sc.void_frozen(0, 1, T0, "NotFrozen")  # the same block
    sc.views(T0 + 1000)
    with pytest.raises(AssertionError, match="whole-second"):
        sc.views(T0 + 1001)
    with pytest.raises(AssertionError, match="whole-second"):
        sc.void_frozen(0, 1, T0 + 1999, "NotFrozen")
    with pytest.raises(AssertionError, match="earlier than the previous step"):
        sc.views(T0)
    with pytest.raises(AssertionError, match="earlier than the previous step"):
        sc.void_frozen(0, 1, T0, "NotFrozen")
    assert [step["now_ms"] for step in sc.steps] == [T0, T0, T0 + 1000]


def _fixture_scenarios() -> list[tuple[dict, dict]]:
    """Every scenario of the two scenario files, each with the certificate pool of its file."""
    transitions = json.loads((FIXTURES / "committee_transitions_v1.json").read_text())
    control = json.loads((FIXTURES / "control_v1.json").read_text())
    return [(transitions["certificates"], scenario) for scenario in transitions["scenarios"]] + [
        (control["certificates"], scenario) for scenario in control["destination_effects"]
    ]


def test_fixture_steps_follow_the_destination_clock():
    """`now_ms = block.timestamp × 1000`: every step is a whole second and no step precedes the one before it."""
    steps = 0
    for _, scenario in _fixture_scenarios():
        previous = None
        for index, step in enumerate(scenario["steps"]):
            check_destination_clock(step["now_ms"], previous, f"{scenario['name']} step {index}")
            previous = step["now_ms"]
            steps += 1
    assert steps >= 123
    finality = json.loads((FIXTURES / "finality_v1.json").read_text())
    for row in finality["certificates"] + finality["negative_certificates"]:
        check_destination_clock(row["now_ms"], where=row["label"])


# §11.1 "Required committee_transitions_v1.json rows", each by the scenario that carries it.
REQUIRED_TRANSITION_ROWS = (
    "initial_pin",
    "checkpoint_raises_high",
    "rotation_key_change",
    "heartbeat_rotation",
    "ton_rotation_next_keys",
    "rotation_lowered_validity",
    "rotation_successor_already_expired",
    "sixteen_batched_rotations",
    "k_kprime_k",
    "future_dated_replay_no_extension",
    "forged_heights_then_genuine_handoff_latches",
    "old_generations_refused",
    "v1_two_x_at_one_height",
    "v1_neighbour_same_x_other_result_body",
    "v2_below_start",
    "v2_neighbour_at_start",
    "v3_rotation_below_high",
    "v3_neighbour_rotation_at_high",
    "expiry_then_refusal_then_void_frozen",
    "latch_inside_batch",
    "inline_v3_latch_required_then_submit_latches",
    "future_dated_rotation_t_eff",
    "finalize_proofs_cap_and_voids",
    "ton_checkpoint_eviction",
    "rotation_sub_second_deadline",
    "cheap_path_identity_signature",
    "ton_cheap_path_identity_signature",
    "transfer_deadline_boundaries",
    "checkpoint_use_after_rotation",
    "ton_checkpoint_use_after_rotation",
    "void_frozen_range_before_frozen",
    "ton_void_frozen_range_before_frozen",
    "finalize_two_faults",
    "ton_finalize_two_faults",
    "check_order_two_faults",
    "cheap_path_checks_encodings",
)
REQUIRED_CONTROL_ROWS = (
    "parliament_pause_then_fast_pause_then_lapse",
    "fast_pause_then_parliament_pause_then_lapse",
    "track2_leaf_after_expiry",
    "stale_equal_and_gap_nonces",
    "max_fast_pause_clamp",
    "fast_pause_local_expiry",
    "pause_then_resume",
    "historical_control_proof",
    "foreign_and_malformed_controls",
    "fast_pause_sub_second_expiry",
)


def test_required_scenarios_are_present():
    """No required row disappears when scenarios are reworked (new scenarios may be added)."""
    transitions = json.loads((FIXTURES / "committee_transitions_v1.json").read_text())
    control = json.loads((FIXTURES / "control_v1.json").read_text())
    names = [s["name"] for s in transitions["scenarios"]]
    assert len(names) == len(set(names)) and not set(REQUIRED_TRANSITION_ROWS) - set(names)
    effects = [s["name"] for s in control["destination_effects"]]
    assert len(effects) == len(set(effects)) and not set(REQUIRED_CONTROL_ROWS) - set(effects)


def test_fixture_rows_of_the_cheap_path_and_the_identity_signature():
    """One row per flavor: the same stored `X` under a foreign signature (cheap path) and under `σ = O` (refused)."""
    transitions = json.loads((FIXTURES / "committee_transitions_v1.json").read_text())
    scenarios = {s["name"]: s for s in transitions["scenarios"]}
    pool = transitions["certificates"]
    for name, flavor, call in (
        ("cheap_path_identity_signature", "evm", "submitCheckpoints"),
        ("ton_cheap_path_identity_signature", "ton", "sccp_checkpoint"),
    ):
        scenario = scenarios[name]
        steps = scenario["steps"]
        assert scenario["flavor"] == flavor and [s["call"] for s in steps] == [call] * 4
        assert [s["expected"]["outcome"] for s in steps] == ["BadSignature", "ok", "NothingToDo", "BadSignature"]
        ids = [s["certificates"] for s in steps]
        assert all(len(batch) == 1 for batch in ids) and ids[0] == ids[2] and len({batch[0] for batch in ids}) == 3
        other, genuine, identity = (pool[batch[0]] for batch in (ids[0], ids[1], ids[3]))
        assert other["evm"]["header"] == genuine["evm"]["header"] == identity["evm"]["header"]
        assert other["evm"]["qc"] == genuine["evm"]["qc"] == identity["evm"]["qc"]
        assert unhex(identity["evm"]["signature"]) == bytes(192)
        assert unhex(identity["ton"]["signature"]) == IDENTITY_SIGNATURE_COMPRESSED
        assert other["evm"]["signature"] not in (genuine["evm"]["signature"], identity["evm"]["signature"])
        # Only the full-path verification publishes, and the cheap path changes nothing.
        assert [e["event"] for e in steps[1]["expected"]["events"]] == ["SccpCertificate", "SccpCheckpointed"]
        assert steps[1]["expected"]["events"][0]["certificate"] == ids[1][0]
        assert all(s["expected"]["events"] == [] for s in (steps[0], steps[2], steps[3]))
        stored = steps[1]["state_after"]["checkpoints"]
        assert len(stored) == 1 and all(s["state_after"]["checkpoints"] == stored for s in steps[2:])
    assert scenarios["cheap_path_identity_signature"]["ton_replayable"] is True


def _evm_call_name(call: str) -> str:
    """The EVM entry point of a step's call (a TON row names the message of §5.3.2)."""
    from sccp_reference.scenario import CALL_NAMES

    return {ton: evm for evm, ton in CALL_NAMES.items()}.get(call, call)


def _call_name(flavor: str, evm_name: str) -> str:
    from sccp_reference.scenario import call_name

    return call_name(flavor, evm_name)


def test_fixture_rows_of_checkpoint_use_after_rotation():
    """Each `*FromCheckpoint` step is `ok` iff its header is of the current generation (U1) or the handoff that
    installed it (U2), re-derived here from the recorded state before the step."""
    transitions = json.loads((FIXTURES / "committee_transitions_v1.json").read_text())
    scenarios = {s["name"]: s for s in transitions["scenarios"]}
    required = {
        "checkpoint_use_after_rotation": {
            ("finalize", "current"),
            ("finalize", "non-handoff 1 back"),
            ("finalize", "installing handoff"),
            ("finalize", "handoff 2 back"),
            ("finalize", "non-handoff 2 back"),
            ("applyControl", "non-handoff 1 back"),
            ("applyControl", "installing handoff"),
            ("voidExpired", "non-handoff 1 back"),
            ("voidExpired", "installing handoff"),
        },
        "ton_checkpoint_use_after_rotation": {
            ("finalize", "non-handoff 1 back"),
            ("finalize", "handoff 2 back"),
            ("applyControl", "non-handoff 1 back"),
            ("applyControl", "installing handoff"),
            ("applyControl", "handoff 2 back"),
        },
    }
    for name, rows in required.items():
        scenario = scenarios[name]
        assert scenario["flavor"] == ("ton" if name.startswith("ton_") else "evm")
        cur = scenario["initial_state"]["committee"]
        seen = set()
        for step in scenario["steps"]:
            if "checkpoint" in step:
                x = parse_header(unhex(step["checkpoint"]["header"]))
                root = unhex(cur["root"])
                current = x.generation == cur["generation"] and x.committee_root == root
                installing = (
                    x.rotation
                    and x.generation + 1 == cur["generation"]
                    and x.height + 1 == cur["start"]
                    and x.next_committee_root == root
                )
                usable = current or installing
                assert step["expected"]["outcome"] == ("ok" if usable else "CommitteeNotAccepted"), (name, step["call"], x)
                assert step["state_after"]["live"] is True
                kind = "handoff" if x.rotation else "non-handoff"
                age = cur["generation"] - x.generation
                label = "current" if current else "installing handoff" if installing else f"{kind} {age} back"
                assert step["call"] == _call_name(scenario["flavor"], _evm_call_name(step["call"]))
                seen.add((_evm_call_name(step["call"]).removesuffix("FromCheckpoint"), label))
            cur = step["state_after"]["committee"]
        assert not rows - seen, (name, sorted(rows - seen))
    # Every other checkpoint use of the two scenario files is a header of the current generation.
    control = json.loads((FIXTURES / "control_v1.json").read_text())
    for scenario in transitions["scenarios"] + control["destination_effects"]:
        if scenario["name"] in required:
            continue
        cur = scenario["initial_state"]["committee"]
        for step in scenario["steps"]:
            if "checkpoint" in step and step["expected"]["outcome"] not in ("UnknownCheckpoint", "BadHeader"):
                x = parse_header(unhex(step["checkpoint"]["header"]))
                assert (x.generation, x.committee_root) == (cur["generation"], unhex(cur["root"])), scenario["name"]
            cur = step["state_after"]["committee"]


def test_bls_consensus_fixture_names_its_single_generator():
    """`bls_consensus_v1.json` is written by Python alone; no entry asks the Rust reference to add rows to it."""
    doc = json.loads((FIXTURES / "bls_consensus_v1.json").read_text())
    assert "Python reference" in doc["generator"] and "reproduces every row" in doc["generator"]
    assert "bls_consensus_rust_v1.json" in doc["rust_only_vectors"]
    assert doc["todo"] and all("Rust" not in item and "iroha_crypto" not in item for item in doc["todo"])
    assert (FIXTURES / "bls_consensus_rust_v1.json").exists()


CHECKPOINT_CALLS = ("submitCheckpoints", "sccp_checkpoint")


def test_time_boundaries_are_probed_on_both_sides():
    """Each time rule keeps a probe at its boundary value and at the nearest clock value beyond it.

    `Live ⇔ now_ms ≤ untilMs`; a void needs `now_ms > deadline_ms` and a finalization
    `now_ms ≤ deadline_ms`; the fast pause holds while `now_ms < fastPauseUntilMs`;
    `t_eff(X) = min(X.timestamp_ms, now_ms)`. With a whole-second clock the nearest
    value beyond a whole-second boundary is 1000 ms away; a sub-second `untilMs`,
    a `deadline_ms` ending in 999 and a `fastPauseUntilMs` ending in 001 are each
    probed at the whole seconds on both sides of them.
    """
    seen = set()
    for pool, scenario in _fixture_scenarios():
        for step in scenario["steps"]:
            now, state, call = step["now_ms"], step["state_after"], step["call"]
            outcome = step["expected"].get("outcome")
            until = state["committee"]["until_ms"]
            fast = state["pause"]["fast_pause_until_ms"]
            # Live.
            if not state["equivocated"]:
                assert state["live"] == (now <= until)
                if call in CHECKPOINT_CALLS and outcome in ("ok", "NothingToDo") and now == until:
                    seen.add("live: checkpoint call accepted at untilMs")
                if call == "voidFrozen" and outcome == "NotFrozen" and now == until:
                    seen.add("live: voidFrozen refused at untilMs")
                if now - until == 1000 and until % 1000 == 0:
                    if outcome == "CommitteeNotAccepted":
                        seen.add(f"live: {call} refused one clock value after untilMs")
                    if call == "voidFrozen" and outcome == "ok":
                        seen.add("live: voidFrozen accepted one clock value after untilMs")
                    if call == "views":
                        seen.add("live: views one clock value after untilMs")
                if until % 1000 and call in CHECKPOINT_CALLS:
                    if outcome == "ok" and 0 < until - now < 1000:
                        seen.add("live: accepted in the second that holds a sub-second untilMs")
                    if outcome == "CommitteeNotAccepted" and now - until == 1:
                        seen.add("live: refused 1 ms after a sub-second untilMs")
            # Deadlines.
            if "proof" in step and "payload" in step["proof"]:
                deadline = decode_payload(unhex(step["proof"]["payload"]), check_recipient=False).deadline_ms
                if call.startswith("voidExpired") and outcome == "DeadlineNotReached" and now == deadline:
                    seen.add("deadline: void refused at deadline_ms")
                if call.startswith("voidExpired") and outcome == "ok" and now - deadline == 1000:
                    seen.add("deadline: void accepted one clock value after deadline_ms")
                if call.startswith("finalize") and outcome == "DeadlinePassed" and now - deadline == 1000:
                    seen.add("deadline: finalization refused one clock value after deadline_ms")
                if call.startswith("finalize") and outcome == "ok" and now == deadline:
                    seen.add("deadline: finalization accepted at deadline_ms")
                if deadline % 1000 == 999:
                    side = "below" if deadline - now == 999 else "after" if now - deadline == 1 else None
                    kind = "finalization" if call.startswith("finalize") else "void"
                    verdicts = {
                        ("finalization", "below"): "ok",
                        ("void", "below"): "DeadlineNotReached",
                        ("finalization", "after"): "DeadlinePassed",
                        ("void", "after"): "ok",
                    }
                    if side is not None and outcome == verdicts[(kind, side)]:
                        seen.add(f"deadline: {kind} {outcome} at the clock value {side} a deadline_ms ending in 999")
            # Fast pause (with no Parliament pause in force).
            if not state["pause"]["parliament_paused"] and fast:
                assert state["pause"]["effective"] == (now < fast)
                if call.startswith("finalize") and outcome == "MintingIsPaused" and fast - now == 1000:
                    seen.add("pause: finalization refused one clock value before fastPauseUntilMs")
                if call.startswith("finalize") and outcome == "ok" and now == fast:
                    seen.add("pause: finalization accepted at fastPauseUntilMs")
                if call == "views" and fast - now == 1000:
                    assert step["expected"]["mintingPaused"] is True
                    seen.add("pause: views one clock value before fastPauseUntilMs")
                if call == "views" and now == fast:
                    assert step["expected"]["mintingPaused"] is False
                    seen.add("pause: views at fastPauseUntilMs")
                if fast % 1000 == 1 and (fast - now == 1 or now - fast == 999):
                    side = "below" if fast - now == 1 else "after"
                    if call == "views":
                        assert step["expected"]["mintingPaused"] is (side == "below")
                        seen.add(f"pause: views at the clock value {side} a fastPauseUntilMs ending in 001")
                    if call.startswith("finalize") and outcome == ("MintingIsPaused" if side == "below" else "ok"):
                        seen.add(f"pause: finalization {outcome} at the clock value {side} a fastPauseUntilMs ending in 001")
            # t_eff of a single rotation.
            rotated = [e for e in step["expected"].get("events", []) if e["event"] == "SccpCommitteeRotated"]
            if call in CHECKPOINT_CALLS and len(step["certificates"]) == 1 and len(rotated) == 1:
                fields = pool[step["certificates"][0]]["header_fields"]
                assert rotated[0]["untilMs"] == min(fields["timestamp_ms"], now) + fields["validity_ms"]
                seen.add("t_eff: X.timestamp_ms above now_ms" if fields["timestamp_ms"] > now else "t_eff: X.timestamp_ms at or below now_ms")
                if fields["timestamp_ms"] % 1000 and rotated[0]["untilMs"] % 1000:
                    seen.add("t_eff: sub-second X.timestamp_ms and untilMs")
    required = {
        "live: checkpoint call accepted at untilMs",
        "live: voidFrozen refused at untilMs",
        "live: submitCheckpoints refused one clock value after untilMs",
        "live: finalizeFromCheckpoint refused one clock value after untilMs",
        "live: applyControl refused one clock value after untilMs",
        "live: voidFrozen accepted one clock value after untilMs",
        "live: views one clock value after untilMs",
        "live: accepted in the second that holds a sub-second untilMs",
        "live: refused 1 ms after a sub-second untilMs",
        "deadline: void refused at deadline_ms",
        "deadline: void accepted one clock value after deadline_ms",
        "deadline: finalization refused one clock value after deadline_ms",
        "deadline: finalization accepted at deadline_ms",
        "deadline: finalization ok at the clock value below a deadline_ms ending in 999",
        "deadline: void DeadlineNotReached at the clock value below a deadline_ms ending in 999",
        "deadline: finalization DeadlinePassed at the clock value after a deadline_ms ending in 999",
        "deadline: void ok at the clock value after a deadline_ms ending in 999",
        "pause: finalization refused one clock value before fastPauseUntilMs",
        "pause: finalization accepted at fastPauseUntilMs",
        "pause: views one clock value before fastPauseUntilMs",
        "pause: views at fastPauseUntilMs",
        "pause: views at the clock value below a fastPauseUntilMs ending in 001",
        "pause: views at the clock value after a fastPauseUntilMs ending in 001",
        "pause: finalization MintingIsPaused at the clock value below a fastPauseUntilMs ending in 001",
        "pause: finalization ok at the clock value after a fastPauseUntilMs ending in 001",
        "t_eff: X.timestamp_ms above now_ms",
        "t_eff: X.timestamp_ms at or below now_ms",
        "t_eff: sub-second X.timestamp_ms and untilMs",
    }
    assert not required - seen, sorted(required - seen)


def _fixture_certificate(entry: dict):
    from sccp_reference.finality import Certificate

    evm, ton = entry["evm"], entry["ton"]
    return Certificate(
        qc=unhex(evm["qc"]),
        header=unhex(evm["header"]),
        signature_evm=unhex(evm["signature"]),
        signature_ton=unhex(ton["signature"]),
        committee=unhex(evm["committee"]),
        signer_ys=unhex(evm["signerYs"]),
        meta={},
    )


def _fixture_destination(doc: dict, entry: dict, flavor: str) -> Destination:
    context, pin = doc["verification_context"], entry["pin"]
    pinned_keys = pin.get("keys")
    if pinned_keys is None:
        pinned_keys = next(committee["keys"] for committee in doc["committees"].values() if committee["root"] == pin["committee_root"])
    keys = [unhex(key) for key in pinned_keys]
    network, word = ETHEREUM, unhex(context["destination_word"])
    if flavor == "ton":
        assert context["ton"]["network"] == TON.name
        network, word = TON, unhex(context["ton"]["destination_word"])
    return Destination(
        Deployment(
            flavor,
            unhex(context["taira_network_id"]),
            unhex(context["consensus_instance"]),
            network,
            word,
            1,
            10**18,
            pin["generation"],
            unhex(pin["committee_root"]),
            pin["start_height"],
            pin["until_ms"],
            keys,
        )
    )


def test_signer_set_negatives_reach_the_bitmap_check():
    """The popcount and spare-bit rows fail at §5.1.3 step 5 on EVM, not at the step 1 signerYs length."""
    doc = json.loads((FIXTURES / "finality_v1.json").read_text())
    rows = {entry["label"]: entry for entry in doc["negative_certificates"]}
    expected = {
        "popcount_q_minus_1": "popcount",
        "popcount_q_plus_1_extra_signer": "popcount",
        "spare_bits": "spare signer bits",
        "msb_first_bitmap": "spare signer bits",
    }
    for label, detail in expected.items():
        entry = rows[label]
        n = doc["committees"][entry["committee"]]["n"]
        assert len(unhex(entry["evm"]["signerYs"])) == 48 * quorum(n), label
        for flavor in ("evm", "ton"):
            out = _fixture_destination(doc, entry, flavor).verify_certificate(_fixture_certificate(entry), entry["now_ms"])
            assert (out["outcome"], out.get("detail")) == ("BadCertificate", detail), (label, flavor, out)


def test_shared_certificate_outcomes_match_each_flavor():
    """Every pinned certificate verdict is derived from the model, including TON's single BLS verdict."""
    doc = json.loads((FIXTURES / "finality_v1.json").read_text())
    expected_counts = {
        "certificates": {"evm": 13, "ton": 13},
        "negative_certificates": {"evm": 51, "ton": 40},
        "flavor_specific_certificates": {"evm": 1, "ton": 1},
    }
    for group, expected in expected_counts.items():
        counts = {"evm": 0, "ton": 0}
        for entry in doc[group]:
            for flavor in counts:
                verdict = entry["expected"][flavor]
                if verdict is None:
                    continue
                destination = _fixture_destination(doc, entry, flavor)
                out = destination.verify_certificate(_fixture_certificate(entry), entry["now_ms"])
                assert out["outcome"] == verdict, (entry["label"], flavor, out)
                counts[flavor] += 1
        assert counts == expected, group


def test_ton_length_negatives_are_malformed_cells():
    doc = json.loads((FIXTURES / "finality_v1.json").read_text())
    rows = {entry["label"]: entry for entry in doc["negative_certificates"]}
    assert len(unhex(rows["qc_length_115"]["ton"]["qc_fixed_cell"])) == 111
    assert len(unhex(rows["header_length_220"]["ton"]["x_tail"])) == 111
    assert len(unhex(rows["ton_signature_length_95"]["ton"]["signature"])) == 95
    for entry in doc["certificates"]:
        ton = entry["ton"]
        assert len(unhex(ton["qc_fixed_cell"])) == 112 and len(unhex(ton["x_head"])) + len(unhex(ton["x_tail"])) == 221
        assert unhex(ton["qc_fixed_cell"]) + ton["signers"].to_bytes(4, "big") == unhex(entry["evm"]["qc"])


RUST_ONLY_FINALITY_SCHEMA = "iroha.sccp.finality.rust.v1"
# The w3f transcript of `iroha_crypto::Signature::new` for BLS-normal keys
# (crates/iroha_crypto/src/signature/bls/uncached.rs): hash_to_curve(prefix ‖ payload, dst).
W3F_SIGNING_PREFIX = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_for signing messages"
W3F_SIGNING_DST = b"\x01"


def _check_rust_only_finality(doc: dict, base: dict) -> int:
    """Check the Rust-only finality rows with the Python model; returns the number of rows.

    `finality_rust_v1.json` carries the §11.3 negatives that need `iroha_crypto`
    (the w3f-transcript signature). Its `negative_certificates` rows have the shape
    of the `finality_v1.json` rows: `label`, `committee`, `pin`, `now_ms`, `evm`,
    `ton` and `expected`. `verification_context` and `committees` come from the
    file itself when it carries them and from `finality_v1.json` (`base`) otherwise.
    Every row must be rejected with the outcome it records; a row labelled `w3f`
    must be well formed up to the pairing check, the only step a foreign
    transcript can fail.
    """
    assert doc["schema"] == RUST_ONLY_FINALITY_SCHEMA
    rows = doc["negative_certificates"]
    assert rows, "the Rust-only finality file has no rows"
    context = {key: doc.get(key, base[key]) for key in ("verification_context", "committees")}
    for entry in rows:
        check_destination_clock(entry["now_ms"], where=entry["label"])
        cert = _fixture_certificate(entry)
        flavors = [flavor for flavor in ("evm", "ton") if entry["expected"][flavor] is not None]
        assert flavors, entry["label"]
        for flavor in flavors:
            out = _fixture_destination(context, entry, flavor).verify_certificate(cert, entry["now_ms"])
            assert out["outcome"] == entry["expected"][flavor] != "ok", (entry["label"], flavor, out)
            if "w3f" in entry["label"]:
                assert (out["outcome"], out.get("detail")) == ("BadSignature", "pairing"), (entry["label"], flavor, out)
    return len(rows)


def test_rust_only_finality_fixture_is_rejected():
    """The w3f-transcript negative of `finality_rust_v1.json` (Rust-generated) is rejected by the Python reference.

    Only `crates/iroha_sccp/tests/v1_reference_finality.rs` writes the file. A missing
    file fails, so the check never passes vacuously. Its text is the canonical rendering
    of both references, and the committee and verification context it repeats are those
    of `finality_v1.json`.
    """
    path = FIXTURES / "finality_rust_v1.json"
    assert path.exists(), "fixtures/sccp/finality_rust_v1.json is missing: regenerate it with the Rust reference"
    text = path.read_text()
    doc = json.loads(text)
    assert generate.render(doc) == text
    base = json.loads((FIXTURES / "finality_v1.json").read_text())
    assert doc["verification_context"] == base["verification_context"]
    assert doc["committees"] and all(base["committees"][name] == value for name, value in doc["committees"].items())
    assert _check_rust_only_finality(doc, base) >= 1
    labels = [entry["label"] for entry in doc["negative_certificates"]]
    assert len(set(labels)) == len(labels) and any("w3f" in label for label in labels)


def test_rust_only_w3f_row_differs_from_a_genuine_certificate_in_the_signature_only():
    """Each w3f row is the certificate the Python reference builds for the same `X`, under another signature.

    The Python reference re-derives the row from its header and signer set: `QC_FIXED`,
    the committee, `signerYs`, `R`, `P`, `m`, the checkpoint id and the forgery-evidence
    id are equal, and its own aggregate under `DST_SIG` is accepted where the row's
    signature is refused. So the transcript is the only thing the row gets wrong.
    """
    from sccp_reference.common import hx
    from sccp_reference.finality import checkpoint_id, forgery_evidence_id

    doc = json.loads((FIXTURES / "finality_rust_v1.json").read_text())
    context = doc["verification_context"]
    rows = [entry for entry in doc["negative_certificates"] if "w3f" in entry["label"]]
    assert rows
    for entry in rows:
        committee = Committee(entry["committee"], tuple(doc["committees"][entry["committee"]]["test_key_indices"]))
        assert committee.as_json() == doc["committees"][entry["committee"]]
        sim = TairaSim(unhex(context["taira_network_id"]), unhex(context["consensus_instance"]), ETHEREUM, unhex(context["destination_word"]))
        header = unhex(entry["evm"]["header"])
        assert parse_header(header).as_json() == entry["header_fields"]
        genuine = sim.certify(header, committee, signer_indices=entry["signer_indices"])
        meta = genuine.meta
        # The row's signature is the w3f-transcript aggregate of its signers over `m`: the generic API of
        # iroha_crypto hashes `"…_NUL_for signing messages" ‖ payload` to G2 under the augmentation tag 0x01.
        secrets = [committee.secret_of[committee.keys[i]] for i in entry["signer_indices"]]
        w3f_point = hash_to_g2(W3F_SIGNING_PREFIX + meta["m"], W3F_SIGNING_DST)
        assert bls.g2_compress(bls.g2_mul(w3f_point, sum(secrets) % bls.R)) == unhex(entry["ton"]["signature"])
        assert genuine.evm_json() | {"signature": None} == entry["evm"] | {"signature": None}
        assert genuine.ton_json() | {"signature": None} == entry["ton"] | {"signature": None}
        assert genuine.signature_evm != unhex(entry["evm"]["signature"])
        assert genuine.signature_ton != unhex(entry["ton"]["signature"])
        assert bls.g2_to_evm192(bls.g2_decompress(unhex(entry["ton"]["signature"]))) == unhex(entry["evm"]["signature"])
        assert (meta["kind"], meta["qc"].as_json()) == (entry["commit_kind"], entry["qc_fixed_fields"])
        assert (hx(meta["r"]), hx(meta["p"]), hx(meta["m"])) == (entry["r"], entry["commit_preimage"], entry["m"])
        assert hx(meta["bitmap"]) == entry["bitmap"]
        assert hx(checkpoint_id(header)) == entry["checkpoint_id"]
        assert hx(forgery_evidence_id(entry["header_fields"]["generation"], meta["m"], meta["signers"])) == entry["forgery_evidence_id"]
        for flavor in ("evm", "ton"):
            destination = _fixture_destination(doc, entry, flavor)
            assert destination.verify_certificate(genuine, entry["now_ms"]) == {"outcome": "ok"}, (entry["label"], flavor)
            refused = destination.verify_certificate(_fixture_certificate(entry), entry["now_ms"])
            assert refused == {"outcome": "BadSignature", "detail": "pairing"}, (entry["label"], flavor)


def test_rust_only_finality_checker_accepts_rejections_only():
    """The checker passes on a signature under a foreign domain and fails on a valid certificate or a wrong outcome."""
    base = json.loads((FIXTURES / "finality_v1.json").read_text())
    negatives = {entry["label"]: entry for entry in base["negative_certificates"]}
    # The NUL-ciphersuite signature stands in for the w3f one: well formed, and only the pairing rejects it.
    stand_in = {**negatives["wrong_dst"], "label": "w3f_transcript_stand_in"}
    doc = {"schema": RUST_ONLY_FINALITY_SCHEMA, "negative_certificates": [stand_in]}
    assert _check_rust_only_finality(doc, base) == 1
    assert _check_rust_only_finality({**doc, "committees": base["committees"], "verification_context": base["verification_context"]}, base) == 1
    valid = {**base["certificates"][0], "label": "w3f_transcript_but_valid", "expected": {"evm": "BadSignature", "ton": "BadSignature"}}
    wrong_outcome = {**stand_in, "expected": {"evm": "BadCertificate", "ton": "BadCertificate"}}
    malformed = {**negatives["qc_length_115"], "label": "w3f_transcript_malformed"}
    unchecked = {**stand_in, "expected": {"evm": None, "ton": None}}
    sub_second = {**stand_in, "now_ms": stand_in["now_ms"] + 1}
    for bad in (valid, wrong_outcome, malformed, unchecked, sub_second):
        with pytest.raises(AssertionError):
            _check_rust_only_finality({**doc, "negative_certificates": [bad]}, base)
    with pytest.raises(AssertionError):
        _check_rust_only_finality({**doc, "negative_certificates": []}, base)
    with pytest.raises(AssertionError):
        _check_rust_only_finality({**doc, "schema": "iroha.sccp.finality.v1"}, base)


def test_every_fixture_outcome_is_a_named_error():
    doc = json.loads((FIXTURES / "committee_transitions_v1.json").read_text())
    known = {"ok", *doc["error_codes"]["shared"], *doc["error_codes"]["ton_only"]}
    control = json.loads((FIXTURES / "control_v1.json").read_text())
    for scenario in doc["scenarios"] + control["destination_effects"]:
        for step in scenario["steps"]:
            assert step["expected"].get("outcome", "ok") in known, (scenario["name"], step)
    assert doc["selectors"]["submitCheckpoints"]["selector"] == "0x07a5e706"
    assert doc["selectors"]["applyControl"]["selector"] == "0x32118e92"


def test_allowlist_rows_have_both_off_by_one_neighbours():
    doc = json.loads((FIXTURES / "bls_consensus_v1.json").read_text())
    rows = {row["label"]: row for row in doc["consensus_allowlist"]}
    positives = [label for label, row in rows.items() if row["allowed"]]
    assert len(positives) == 8
    for label in positives:
        for suffix, delta in (("_minus_1", -1), ("_plus_1", 1)):
            neighbour = rows[label + suffix]
            assert not neighbour["allowed"] and neighbour["len"] == rows[label]["len"] + delta
            assert consensus_digest(unhex(neighbour["preimage"])) is None


def test_taira_sim_orders_controls_first():
    sim, _, _ = _destination()
    with pytest.raises(ValueError):
        sim.block(1010, T0, [sim.transfer(0, 10**9, T0 + 1, rep(0x44, 20)), sim.control(1, 1, 1, 0, rep(1), rep(2))])


# -- review fixes: profiles, keys outside G1, check order, recorder, bounds ----------------


def test_ton_deployment_authenticates_the_canonical_pinned_keys():
    """A TON pin needs the exact, strictly ordered committee, without performing signature-time KeyValidate."""
    _, _, destination = _destination("ton")
    keys = destination.d.pin_keys
    reordered = [keys[1], keys[0], *keys[2:]]
    repeated = [keys[0], keys[0], *keys[2:]]
    for pinned_keys, root in (
        (None, destination.d.pin_root),
        ([], destination.d.pin_root),
        (keys[:3], committee_root(keys[:3])),
        ([*keys, keys[0]], committee_root([*keys, keys[0]])),
        (reordered, committee_root(reordered)),
        (repeated, committee_root(repeated)),
        (keys, rep(0x99)),
        ([key[:-1] for key in keys], destination.d.pin_root),
    ):
        with pytest.raises(ValueError, match="canonical keys"):
            Destination(dataclasses.replace(destination.d, pin_keys=pinned_keys, pin_root=root))
    # Malformed keys remain representable under a canonical root so the opcode verdict can be tested.
    malformed = sorted([bytes([0xC0]) + bytes(47), *keys[1:]])
    pinned = Destination(dataclasses.replace(destination.d, pin_keys=malformed, pin_root=committee_root(malformed)))
    assert pinned.state.keys == malformed


def test_flavor_is_bound_to_the_profile():
    """An EVM destination is deployed on Ethereum or BSC and a TON destination on TON; any other pair is refused."""
    _, _, evm = _destination()
    _, _, ton = _destination("ton")
    assert Destination(dataclasses.replace(evm.d, network=BSC)).d.network is BSC
    for deployment in (
        dataclasses.replace(evm.d, network=TON),
        dataclasses.replace(evm.d, flavor="ton"),
        dataclasses.replace(ton.d, network=ETHEREUM),
        dataclasses.replace(ton.d, flavor="evm"),
        dataclasses.replace(evm.d, network=TAIRA),
        dataclasses.replace(evm.d, flavor="tron"),
    ):
        with pytest.raises(ValueError):
            Destination(deployment)
    transitions = json.loads((FIXTURES / "committee_transitions_v1.json").read_text())
    control = json.loads((FIXTURES / "control_v1.json").read_text())
    rows = transitions["scenarios"] + control["destination_effects"]
    assert any(row["flavor"] == "ton" for row in rows)
    for row in rows:
        deployment = row["deployment"]
        assert (row["flavor"] == "ton") == (deployment["network"] == "ton-mainnet"), row["name"]
        assert deployment["flavor"] == row["flavor"]
        if row["flavor"] == "ton":
            assert deployment["destination_word"] == "0x" + "35" * 32, row["name"]
            assert all(step["call"].startswith("sccp_") or step["call"] == "views" for step in row["steps"]), row["name"]
            assert all(len(step.get("certificates", [])) <= 1 for step in row["steps"]), row["name"]
        else:
            assert not any(step["call"].startswith("sccp_") for step in row["steps"]), row["name"]


def _odd_committee(flavor: str, replaced: dict, signers=(0, 1, 2), height: int = 1010):
    """A destination pinned under `K0` with the members of `replaced` listed under other key bytes, and the
    certificate of `signers` (members, signing with their genuine secrets) at their seats of that committee."""
    sim, k0, dest = _destination(flavor)
    listed = {member: replaced.get(member, k0.keys[member]) for member in range(4)}
    custom = sorted(listed.values())
    root = committee_root(custom)
    x = FinalityHeader(network_id=rep(0x11), height=height, timestamp_ms=T0, generation=5, committee_root=root).encode()
    cert = build_certificate(
        keys=custom,
        secret_of={listed[member]: k0.secret_of[k0.keys[member]] for member in range(4)},
        signer_indices=sorted(custom.index(listed[member]) for member in signers),
        header=x,
        instance=rep(0x77),
        **sim.qc_fields(height, x),
    )
    pinned = Destination(dataclasses.replace(dest.d, pin_root=root, pin_keys=custom))
    return pinned, cert, k0


def test_signer_keys_outside_g1_follow_what_each_destination_observes():
    """A signer key that is a point of the curve outside G1: EVM sees the aggregate (`PAIRING_CHECK` refuses one
    outside G1 and accepts keys whose odd components cancel), TON's opcode refuses the key itself."""
    from sccp_reference.vectors_finality import g1_shift_outside_subgroup

    shift = g1_shift_outside_subgroup()
    assert bls.g1_is_on_curve(shift) and not bls.g1_in_subgroup(shift)
    _, k0, _ = _destination()
    points = [bls.g1_decompress(key) for key in k0.keys]
    plus = bls.g1_compress(bls.g1_add(points[0], shift))
    minus = bls.g1_compress(bls.g1_add(points[1], bls.g1_neg(shift)))
    assert key_validate(plus) is None and key_validate(minus) is None
    for flavor in ("evm", "ton"):
        dest, cert, _ = _odd_committee(flavor, {0: plus})
        # The pairing equation holds for the genuine signature; the key, and the aggregate, are outside G1.
        apk = None
        for index in cert.meta["signer_indices"]:
            apk = bls.g1_add(apk, bls.g1_decompress(dest.d.pin_keys[index]))
        assert not bls.g1_in_subgroup(apk)
        assert bls.pairing_product_is_one(
            [(apk, hash_to_g2(cert.meta["m"])), (bls.g1_neg(bls.G1_GENERATOR), cert.meta["sigma"])]
        )
        out = dest.verify_certificate(cert, T0)
        detail = "aggregate key not in G1" if flavor == "evm" else "signer key not in G1"
        assert out == {"outcome": "BadSignature", "detail": detail}, flavor
        assert dest.submit_checkpoints([cert], T0)["outcome"] == "BadSignature" and not dest.state.checkpoints
    evm, cert, _ = _odd_committee("evm", {0: plus, 1: minus})
    assert evm.verify_certificate(cert, T0) == {"outcome": "ok"}
    ton, cert, _ = _odd_committee("ton", {0: plus, 1: minus})
    assert ton.verify_certificate(cert, T0) == {"outcome": "BadSignature", "detail": "signer key not in G1"}


def test_ton_stored_keys_the_opcode_refuses_are_bad_signature():
    """A stored TON signer key that is the identity or no point has an outcome (`BadSignature`), never an exception,
    and an identity key does not let `q − 1` members certify."""
    identity = bytes([0xC0]) + bytes(47)
    sim, k0, dest = _destination("ton")
    for odd, detail in ((identity, "signer key is the identity"), (bytes([0x80]) + b"\xff" * 47, "signer key encoding")):
        custom = sorted([odd] + k0.keys[1:])
        root = committee_root(custom)
        x = FinalityHeader(network_id=rep(0x11), height=1010, timestamp_ms=T0, generation=5, committee_root=root).encode()
        # Members 1 and 2 sign; the bitmap also names the odd seat, so that `q = 3` bits are set.
        base = sim.certify(x, k0, signer_indices=[1, 2])
        seats = [custom.index(k0.keys[1]), custom.index(k0.keys[2]), custom.index(odd)]
        cert = dataclasses.replace(base, qc=base.qc[:112] + signers_from_indices(seats).to_bytes(4, "big"))
        pinned = Destination(dataclasses.replace(dest.d, pin_root=root, pin_keys=custom))
        assert pinned.verify_certificate(cert, T0) == {"outcome": "BadSignature", "detail": detail}
        assert pinned.submit_checkpoints([cert], T0)["outcome"] == "BadSignature"
        assert not pinned.state.checkpoints and not pinned.events


def test_identity_aggregate_is_bad_committee_on_evm_and_bad_signature_on_ton():
    """`apk = O`: EVM reports `BadCommittee` at step 10, before `σ` is read as a point; TON's opcode answers
    `false`, so the minter reports `BadSignature`."""
    _, k0, _ = _destination()
    points = [bls.g1_decompress(key) for key in k0.keys]
    rogue = bls.g1_compress(bls.g1_neg(bls.g1_add(points[0], points[1])))
    evm, cert, _ = _odd_committee("evm", {2: rogue})
    assert evm.verify_certificate(cert, T0) == {"outcome": "BadCommittee", "detail": "aggregate key is the identity"}
    off_curve = bytearray(cert.signature_evm)
    off_curve[191] ^= 0x01
    first = evm.verify_certificate(dataclasses.replace(cert, signature_evm=bytes(off_curve)), T0)
    assert first == {"outcome": "BadCommittee", "detail": "aggregate key is the identity"}
    ton, cert, _ = _odd_committee("ton", {2: rogue})
    assert ton.verify_certificate(cert, T0) == {"outcome": "BadSignature", "detail": "aggregate key is the identity"}
    doc = json.loads((FIXTURES / "finality_v1.json").read_text())
    rows = {entry["label"]: entry["expected"] for entry in doc["negative_certificates"]}
    assert rows["signer_key_outside_g1"] == {"evm": "BadSignature", "ton": "BadSignature"}
    specific = {entry["label"]: entry["expected"] for entry in doc["flavor_specific_certificates"]}
    assert specific == {"signer_keys_outside_g1_cancelling": {"evm": "ok", "ton": "BadSignature"}}
    assert all("ok" not in entry["expected"].values() for entry in doc["negative_certificates"])
    assert rows["aggregate_key_identity"] == {"evm": "BadCommittee", "ton": "BadSignature"}
    assert rows["aggregate_key_identity_sigma_off_curve"] == {"evm": "BadCommittee", "ton": "BadSignature"}
    choices = json.loads((FIXTURES / "committee_transitions_v1.json").read_text())["error_choices"]
    assert choices["aggregate_key_identity"] == {"evm": "BadCommittee", "ton": "BadSignature"}
    assert choices["aggregate_key_outside_g1"] == choices["ton_signer_key_refused_by_the_opcode"] == "BadSignature"


def test_ton_checks_the_payload_before_x_and_evm_after():
    """Two faults in one call: a payload of another revision under a checkpoint that is not stored."""
    for flavor, expected in (("evm", "UnknownCheckpoint"), ("ton", "BadPayload")):
        sim, k0, dest = _destination(flavor)
        block = sim.block(1010, T0)
        other = outbound_payload(sim.target, 0, 2, T0 + 1000, 10**9, b"\x01" + rep(0x5A, 33), _recipient(flavor))
        proof = MessageProof(other, 0, [], BlockRef(1010, rep(0x01), 1))
        assert dest.finalize(("checkpoint", block.x), proof, T0)["outcome"] == expected, flavor
        assert dest.void_expired(0, ("checkpoint", block.x), proof, T0)["outcome"] == expected, flavor
        # With a payload of this revision both flavors report the checkpoint.
        own = sim.transfer(0, 10**9, T0 + 1000, _recipient(flavor)).payload
        proof = MessageProof(own, 0, [], BlockRef(1010, rep(0x01), 1))
        assert dest.finalize(("checkpoint", block.x), proof, T0)["outcome"] == "UnknownCheckpoint", flavor
    # The deadline precedes the leaf path on both flavors.
    for flavor in ("evm", "ton"):
        sim, k0, dest = _destination(flavor)
        block = sim.block(1010, T0, [sim.transfer(0, 10**9, T0 + 1000, _recipient(flavor))])
        assert dest.submit_checkpoints([sim.certify(block.header, k0)], T0)["outcome"] == "ok"
        proof = sim.message_proof(1010, 0, block.header)
        proof.path = [rep(0xAB)]
        assert dest.finalize(("checkpoint", block.x), proof, T0 + 2000)["outcome"] == "DeadlinePassed", flavor
        assert dest.finalize(("checkpoint", block.x), proof, T0 + 1000)["outcome"] == "BadProof", flavor


def test_anchor_helpers_refuse_undefined_inputs():
    """§4.2.1 defines anchors for heights `a ≥ 1` and a chunk root for a completed chunk of 4 096 anchors only."""
    assert anchor_chunk_position(1) == (0, 0)
    for height in (0, -1):
        with pytest.raises(ValueError):
            anchor_chunk_position(height)
    leaf = anchor_leaf(1, rep(0x99), rep(0x66))
    for count in (0, 1, 2, 2048, 4095, 4097, 8192):
        with pytest.raises(ValueError):
            anchor_chunk_levels([leaf] * count)


def _scenario_rows():
    transitions = json.loads((FIXTURES / "committee_transitions_v1.json").read_text())
    control = json.loads((FIXTURES / "control_v1.json").read_text())
    return [(transitions, row) for row in transitions["scenarios"]] + [(control, row) for row in control["destination_effects"]]


def test_certificate_events_name_a_certificate_the_step_submitted():
    """Every `SccpCertificate` event names a certificate of its own step, and the pool never holds two entries with
    one `QC_FIXED`, header and signature, so the name identifies the published bytes."""
    events = 0
    for doc, row in _scenario_rows():
        for index, step in enumerate(row["steps"]):
            submitted = list(step.get("certificates", [])) + ([step["certificate"]] if "certificate" in step else [])
            for event in step["expected"].get("events", []):
                if event["event"] == "SccpCertificate":
                    events += 1
                    assert event["certificate"] in submitted, (row["name"], index)
                    # Among the certificates of the step, the event's bytes belong to this one alone.
                    form = "ton" if row["flavor"] == "ton" else "evm"
                    wire = lambda cid: (  # noqa: E731
                        doc["certificates"][cid]["evm"]["qc"],
                        doc["certificates"][cid]["evm"]["header"],
                        doc["certificates"][cid][form]["signature"],
                    )
                    assert [wire(cid) for cid in submitted].count(wire(event["certificate"])) == 1, (row["name"], index)
    assert events > 60


def test_recorder_names_the_published_certificate_by_its_signature():
    """A twin of the genuine certificate (same `QC_FIXED` and `X`, another signature) pooled first does not take
    the name of the certificate a destination publishes."""
    from sccp_reference.scenario import CertificatePool, Scenario

    for flavor in ("evm", "ton"):
        sim, k0, dest = _destination(flavor)
        block = sim.block(1010, T0)
        genuine = sim.certify(block.header, k0)
        twin = sim.certify(block.header, k0, signed_instance=rep(0x78))
        assert (twin.qc, twin.header) == (genuine.qc, genuine.header) and twin.signature_ton != genuine.signature_ton
        pool = CertificatePool()
        scenario = Scenario("twin_first", "", dest.d, pool)
        assert scenario.submit([(twin, "twin", "K0", None)], T0)["outcome"] == "BadSignature"
        assert scenario.submit([(genuine, "genuine", "K0", None)], T0)["outcome"] == "ok"
        step = scenario.steps[1]
        assert step["certificates"] == ["c002"] and step["expected"]["events"][0]["certificate"] == "c002", flavor
        ids = list(pool.entries)
        assert pool.id_of("0x" + genuine.qc.hex(), "0x" + genuine.header.hex(), "0x" + genuine.signature_ton.hex(), ids) == "c002"
        assert pool.id_of("0x" + genuine.qc.hex(), "0x" + genuine.header.hex(), "0x" + twin.signature_evm.hex(), ids) == "c001"
        assert pool.id_of("0x" + genuine.qc.hex(), "0x" + genuine.header.hex(), "0x" + bytes(96).hex(), ids) is None
        assert pool.id_of("0x" + genuine.qc.hex(), "0x" + genuine.header.hex(), "0x" + genuine.signature_ton.hex(), ["c001"]) is None


def test_scenario_outcomes_exist_on_their_flavor():
    """A row reports only errors its flavor has: an EVM custom error on `evm`, a TON exit code on `ton`."""
    from sccp_reference.vectors_transitions import ERROR_CODES, TON_ONLY_ERROR_CODES, _flavor_reports

    assert _flavor_reports("evm", "ok") and _flavor_reports("ton", "ok")
    assert _flavor_reports("evm", "AlreadyConsumed") and not _flavor_reports("ton", "AlreadyConsumed")
    assert _flavor_reports("ton", "BadRange") and not _flavor_reports("evm", "BadRange")
    assert not _flavor_reports("ton", "TooManyCertificates") and not _flavor_reports("evm", "NoSuchError")
    seen = {"evm": set(), "ton": set()}
    for _, row in _scenario_rows():
        for step in row["steps"]:
            outcome = step["expected"].get("outcome", "ok")
            assert _flavor_reports(row["flavor"], outcome), (row["name"], outcome)
            seen[row["flavor"]].add(outcome)
    assert "BadRange" in seen["ton"] and "BadAmount" in seen["evm"] and "BadPayload" in seen["ton"]
    assert set(ERROR_CODES) & set(TON_ONLY_ERROR_CODES) == set()


def test_init_bound_rows():
    """`now < initialUntilMs ≤ now + MAX_VALIDITY_MS + MAX_INIT_SLACK_MS`, compared without a sum above `u64`."""
    assert MAX_INIT_SLACK_MS == 3_600_000
    doc = json.loads((FIXTURES / "committee_transitions_v1.json").read_text())
    assert doc["constants"]["max_init_slack_ms"] == MAX_INIT_SLACK_MS
    assert doc["constants"]["max_validity_ms"] == MAX_VALIDITY_MS
    rows = doc["init_bounds"]
    assert {row["expected"] for row in rows} == {"ok", "BadConfig"} and len(rows) == 5
    for row in rows:
        check_destination_clock(row["now_ms"], where=row["label"])
        assert init_until_ms_ok(row["now_ms"], row["until_ms"]) == (row["expected"] == "ok"), row["label"]
    span = MAX_VALIDITY_MS + MAX_INIT_SLACK_MS
    top = U64_MAX // 1000 * 1000
    assert init_until_ms_ok(top, U64_MAX) and not init_until_ms_ok(U64_MAX, U64_MAX)
    assert init_until_ms_ok(U64_MAX - span, U64_MAX) and not init_until_ms_ok(U64_MAX - span - 1, U64_MAX)


def test_forgery_evidence_id_rows_use_the_message_of_the_wire():
    """A certificate row carries `forgery_evidence_id` iff its `m` is the `m` a verifier derives from its wire
    fields, and then the id is over that `m` (§4.9)."""
    from sccp_reference.common import hx
    from sccp_reference.finality import commit_message, forgery_evidence_id, result_r

    doc = json.loads((FIXTURES / "finality_v1.json").read_text())
    instance = unhex(doc["verification_context"]["consensus_instance"])
    without = set()
    for entry in doc["certificates"] + doc["negative_certificates"] + doc["flavor_specific_certificates"]:
        qc, x = unhex(entry["evm"]["qc"]), unhex(entry["evm"]["header"])
        if len(qc) != 116 or len(x) != 221:
            assert "forgery_evidence_id" not in entry, entry["label"]
            continue
        derived = commit_message(
            commit_preimage(
                instance, int.from_bytes(qc[0:8], "big"), qc[8:40], int.from_bytes(x[48:56], "big"),
                int.from_bytes(qc[40:48], "big"), qc[48:80], result_r(x, qc[80:112]),
            )
        )
        if hx(derived) == entry["m"]:
            generation, signers = int.from_bytes(x[141:149], "big"), int.from_bytes(qc[112:116], "big")
            assert entry["forgery_evidence_id"] == hx(forgery_evidence_id(generation, derived, signers)), entry["label"]
        else:
            assert "forgery_evidence_id" not in entry, entry["label"]
            without.add(entry["label"])
    assert without == {"prepare_kind", "wrong_instance", "signed_height_mismatch", "tampered_x"}


def test_fixture_rows_of_the_check_orders():
    """The rows that two simultaneous faults decide (`*_two_faults`, `check_order_two_faults`), the voidFrozen
    range on a Live destination, and the step 6 encodings on the cheap path."""
    rows = {row["name"]: row for _, row in _scenario_rows()}
    outcomes = lambda name: [(_evm_call_name(s["call"]), s["expected"]["outcome"]) for s in rows[name]["steps"]]  # noqa: E731
    assert outcomes("finalize_two_faults")[:3] == [
        ("finalizeFromCheckpoint", "UnknownCheckpoint"),
        ("finalizeFromCheckpoint", "UnknownCheckpoint"),
        ("voidExpiredFromCheckpoint", "UnknownCheckpoint"),
    ]
    assert outcomes("ton_finalize_two_faults")[:3] == [
        ("finalizeFromCheckpoint", "BadPayload"),
        ("finalizeFromCheckpoint", "BadRecipient"),
        ("voidExpiredFromCheckpoint", "BadPayload"),
    ]
    for name in ("finalize_two_faults", "ton_finalize_two_faults"):
        assert outcomes(name)[-1] == ("finalizeFromCheckpoint", "DeadlinePassed")
        payloads = [decode_payload(unhex(s["proof"]["payload"]), check_recipient=False) for s in rows[name]["steps"] if "proof" in s]
        assert [p.route_revision for p in payloads] == [2, 1, 2, 1]
        assert all(p.dest_domain == (TON.domain if name.startswith("ton_") else ETHEREUM.domain) for p in payloads)
    assert [o for _, o in outcomes("check_order_two_faults")] == [
        "ok", "ok", "BadControl", "ok", "AlreadyConsumed", "BadNonce", "AlreadyConsumed",
    ]
    steps = rows["check_order_two_faults"]["steps"]
    assert steps[2]["proof"]["track"] == 3 and steps[2]["proof"]["controlNonce"] < steps[1]["state_after"]["pause"]["control_nonce"]
    assert steps[3]["state_after"]["total_supply"] == rows["check_order_two_faults"]["deployment"]["max_wrapped_supply"]
    assert steps[5]["nonce"] != steps[6]["nonce"] and steps[5]["proof"] == steps[6]["proof"]
    assert [o for _, o in outcomes("void_frozen_range_before_frozen")] == ["BadAmount"] * 3 + ["NotFrozen"]
    assert [o for _, o in outcomes("ton_void_frozen_range_before_frozen")] == ["BadRange"] * 4 + ["NotFrozen"]
    for name in ("void_frozen_range_before_frozen", "ton_void_frozen_range_before_frozen"):
        assert all(step["state_after"]["live"] for step in rows[name]["steps"])
    assert [o for _, o in outcomes("cheap_path_checks_encodings")] == [
        "ok", "BadCommittee", "BadCommittee", "BadSignature", "NothingToDo",
    ]
    stored = rows["cheap_path_checks_encodings"]["steps"]
    assert all(step["state_after"]["checkpoints"] == stored[0]["state_after"]["checkpoints"] for step in stored)


def test_ton_control_rows_commit_to_the_ton_lane_and_the_placeholder_word():
    """The applied controls of `ton_checkpoint_use_after_rotation` are leaves of `lane_bytes(sora-taira, ton-mainnet)`
    under the placeholder minter word, which is what a TON minter hashes; under the Ethereum lane they do not verify."""
    doc = json.loads((FIXTURES / "committee_transitions_v1.json").read_text())
    row = {r["name"]: r for r in doc["scenarios"]}["ton_checkpoint_use_after_rotation"]
    deployment = row["deployment"]
    applied = [s for s in row["steps"] if s["call"] == "sccp_apply_control_checkpoint" and s["expected"]["outcome"] == "ok"]
    assert len(applied) == 2
    for step in applied:
        proof = step["proof"]
        fields = (
            deployment["route_revision"], proof["controlNonce"], proof["track"], int(proof["parliamentPaused"]),
            proof["fastPauseUntilMs"], unhex(proof["certificateId"]), unhex(proof["effectHash"]),
        )
        block = proof["block"]
        path = [unhex(h) for h in proof["path"]]
        ton_leaf = control_leaf(unhex(deployment["taira_network_id"]), TON, unhex(deployment["destination_word"]), *fields)
        check_leaf(ton_leaf, proof["leafIndex"], block["messageCount"], path, unhex(block["sccpRoot"]))
        eth_leaf = control_leaf(unhex(deployment["taira_network_id"]), ETHEREUM, bytes(12) + rep(0x22, 20), *fields)
        with pytest.raises(SccpError):
            check_leaf(eth_leaf, proof["leafIndex"], block["messageCount"], path, unhex(block["sccpRoot"]))


# -- fixtures ---------------------------------------------------------------------------


def test_render_is_canonical():
    assert generate.render({"b": 1, "a": [2]}) == '{\n  "a": [\n    2\n  ],\n  "b": 1\n}\n'


@pytest.mark.parametrize("name", sorted(generate.BUILDERS))
def test_fixture_has_no_drift(name):
    """Regenerate each fixture the reference owns; any difference is drift (rerun generate.py --write after review)."""
    diff = generate.check(name)
    assert not diff, "\n".join(diff)
