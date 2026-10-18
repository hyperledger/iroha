"""Builder of `fixtures/sccp/bls_consensus_v1.json`.

Consensus-suite vectors (`specs/sccp.md` §3.8, `specs/sumeragi.md` §1 item 6):
imported RFC 9380 and Ethereum bls12-381-tests v0.1.2 vectors, hash-to-G2 traces under `DST_SIG` with the EIP-2537
`MAP_FP2_TO_G2` inputs and outputs, `KeyGen`/`Sign`/`Verify`,
`FastAggregateVerify`, `AggregateVerify`, the consensus preimage allowlist, and
a real Ethereum mainnet sync-committee aggregate verified under the same IETF
proof-of-possession ciphersuite.
"""

from __future__ import annotations

import json
from pathlib import Path

from .bls12_381 import (
    fp_sqrt,
    fp_to_bytes64,
    g1_add,
    g1_compress,
    g1_decompress,
    g1_in_subgroup,
    g1_neg,
    g2_compress,
    g2_decompress,
    g2_to_eip2537,
    g2_uncompressed_zcash,
)
from .bls_sig import (
    AVAILABILITY_TAG,
    aggregate,
    aggregate_verify,
    consensus_digest,
    core_verify_point,
    fast_aggregate_verify,
    key_validate,
    keygen,
    sign,
    signature_validate,
    sk_to_pk,
    verify,
)
from .common import hx, rep, sha256
from .finality import TAG_SIG
from .hash_to_curve import DST_SIG, expand_message_xmd, hash_to_g2_trace, iso_map_g2, map_to_curve_sswu
from .imported_vectors import (
    EXPAND_MESSAGE_XMD_DST,
    EXPAND_MESSAGE_XMD_SHA256,
    HASH_TO_G2_RO,
    HASH_TO_G2_RO_DST,
)
from .taira import test_public, test_secret
from .vectors_finality import SPEC_M, g1_json, g2_json
from .vectors_bls_malformed import build as malformed_inputs
from .vectors_bls_ethereum import build as ethereum_vectors

ROOT = Path(__file__).resolve().parents[2]
ETH_CAPTURE = ROOT / "fixtures" / "sccp" / "rpc" / "eth"
ETH_GENESIS_VALIDATORS_ROOT = bytes.fromhex("4b363db94e286120d76eb905340fdd4e54bfe9f06bf33ff6cf5ad27f511bfe95")
ETH_FULU_FORK_VERSION = bytes([6, 0, 0, 0])
ETH_DOMAIN_SYNC_COMMITTEE = bytes([7, 0, 0, 0])


def _fp2_hex(value) -> list[str]:
    return [hex(value[0]), hex(value[1])]


def _fp2_eip2537(value) -> str:
    return hx(fp_to_bytes64(value[0]) + fp_to_bytes64(value[1]))


def imported_rfc9380() -> dict:
    """RFC 9380 K.1 and J.10.1 vectors, each reproduced before it is written."""
    expand = []
    for msg, length, uniform in EXPAND_MESSAGE_XMD_SHA256:
        out = expand_message_xmd(msg.encode(), EXPAND_MESSAGE_XMD_DST, length)
        assert out.hex() == uniform, ("expand_message_xmd", msg[:8], length)
        expand.append({"msg": msg, "len_in_bytes": length, "uniform_bytes": hx(out)})
    h2c = []
    for vector in HASH_TO_G2_RO:
        trace = hash_to_g2_trace(vector["msg"].encode(), HASH_TO_G2_RO_DST)

        def fp2(pair):
            return (int(pair[0], 16), int(pair[1], 16))

        def point(pt):
            return (fp2(pt[0]), fp2(pt[1]))

        assert trace["u0"] == fp2(vector["u0"]) and trace["u1"] == fp2(vector["u1"])
        assert trace["q0"] == point(vector["q0"]) and trace["q1"] == point(vector["q1"])
        assert trace["point"] == point(vector["p"]), vector["msg"][:8]
        h2c.append(
            {
                "msg": vector["msg"],
                "u0": list(vector["u0"]),
                "u1": list(vector["u1"]),
                "q0": [list(vector["q0"][0]), list(vector["q0"][1])],
                "q1": [list(vector["q1"][0]), list(vector["q1"][1])],
                "p": [list(vector["p"][0]), list(vector["p"][1])],
                "p_compressed": hx(g2_compress(trace["point"])),
                "p_eip2537": hx(g2_to_eip2537(trace["point"])),
                "p_zcash_uncompressed": hx(g2_uncompressed_zcash(trace["point"])),
            }
        )
    return {
        "source": "RFC 9380 Appendix K.1 (expand_message_xmd SHA-256) and Appendix J.10.1 (BLS12381G2_XMD:SHA-256_SSWU_RO_)",
        "expand_message_xmd": {"dst": EXPAND_MESSAGE_XMD_DST.decode(), "vectors": expand},
        "hash_to_g2": {"dst": HASH_TO_G2_RO_DST.decode(), "vectors": h2c},
    }


def dst_sig_traces() -> list[dict]:
    """Hash-to-G2 under `DST_SIG` for SCCP-shaped 32-byte messages, with every intermediate value."""
    messages = [
        ("spec_11_2_m", bytes.fromhex(SPEC_M)),
        ("zero_digest", bytes(32)),
        ("sha256_empty", sha256(b"")),
        ("sha256_sccp", sha256(b"SCCP")),
    ]
    out = []
    for label, msg in messages:
        t = hash_to_g2_trace(msg, DST_SIG)
        out.append(
            {
                "label": label,
                "msg": hx(msg),
                "uniform_bytes": hx(t["uniform_bytes"]),
                "u0": _fp2_hex(t["u0"]),
                "u1": _fp2_hex(t["u1"]),
                "map_fp2_to_g2_input_u0": _fp2_eip2537(t["u0"]),
                "map_fp2_to_g2_input_u1": _fp2_eip2537(t["u1"]),
                "map_fp2_to_g2_output_u0": hx(g2_to_eip2537(t["map_u0"])),
                "map_fp2_to_g2_output_u1": hx(g2_to_eip2537(t["map_u1"])),
                "q": g2_json(t["point"]),
            }
        )
    return out


def _non_subgroup_g1():
    """The first x ≥ 1 whose curve point is not in G1."""
    x = 1
    while True:
        y = fp_sqrt(x * x * x + 4)
        if y is not None and not g1_in_subgroup((x, y)):
            return (x, y)
        x += 1


def sign_verify_vectors() -> dict:
    msgs = [bytes.fromhex(SPEC_M), sha256(b"sccp-reference/sign/1")]
    keys = []
    for i in range(3):
        ikm = sha256(b"sccp-finality-test-ikm", bytes([i]))
        sk = keygen(ikm)
        assert sk == test_secret(i)
        keys.append({"ikm": hx(ikm), "sk": hx(sk.to_bytes(32, "big")), "pk": hx(sk_to_pk(sk))})
    signatures = []
    for i in range(3):
        for msg in msgs:
            sig = sign(test_secret(i), msg)
            assert verify(test_public(i), msg, sig)
            signatures.append({"key": i, "msg": hx(msg), "signature": hx(sig), "verify": True})
    sig0 = sign(test_secret(0), msgs[0])
    pk0 = test_public(0)
    bad_g1 = _non_subgroup_g1()
    q_bad = iso_map_g2(map_to_curve_sswu((5, 7)))
    infinity_g1 = bytes([0xC0]) + bytes(47)
    infinity_g2 = bytes([0xC0]) + bytes(95)
    x_ge_p = bytearray(pk0)
    x_ge_p[0] = 0x80 | 0x1F
    x_ge_p[1:] = b"\xff" * 47
    off_curve_x = 0
    while fp_sqrt(off_curve_x**3 + 4) is not None:
        off_curve_x += 1
    off_curve = bytearray(off_curve_x.to_bytes(48, "big"))
    off_curve[0] |= 0x80
    no_flag = bytearray(sig0)
    no_flag[0] &= 0x7F
    infinity_dirty = bytearray(infinity_g2)
    infinity_dirty[95] = 1
    infinity_g1_sign = bytes([0xE0]) + bytes(47)
    sig_x_c1_ge_p = bytes([0x80 | (sig0[0] & 0x20) | 0x1F]) + b"\xff" * 47 + sig0[48:]
    sig_x_c0_ge_p = sig0[:48] + b"\xff" * 48
    negatives = [
        ("wrong_message", pk0, msgs[1], sig0, DST_SIG),
        ("wrong_key", test_public(1), msgs[0], sig0, DST_SIG),
        ("nul_dst_signature", pk0, msgs[0], sign(test_secret(0), msgs[0], b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_"), DST_SIG),
        ("pk_identity", infinity_g1, msgs[0], sig0, DST_SIG),
        ("pk_identity_with_sign_flag", infinity_g1_sign, msgs[0], sig0, DST_SIG),
        ("pk_not_in_subgroup", g1_compress(bad_g1), msgs[0], sig0, DST_SIG),
        ("pk_x_ge_p", bytes(x_ge_p), msgs[0], sig0, DST_SIG),
        ("pk_off_curve", bytes(off_curve), msgs[0], sig0, DST_SIG),
        ("pk_missing_compression_flag", bytes([pk0[0] & 0x7F]) + pk0[1:], msgs[0], sig0, DST_SIG),
        ("sig_identity", pk0, msgs[0], infinity_g2, DST_SIG),
        ("sig_identity_dirty", pk0, msgs[0], bytes(infinity_dirty), DST_SIG),
        ("sig_not_in_subgroup", pk0, msgs[0], g2_compress(q_bad), DST_SIG),
        ("sig_x_c1_ge_p", pk0, msgs[0], sig_x_c1_ge_p, DST_SIG),
        ("sig_x_c0_ge_p", pk0, msgs[0], sig_x_c0_ge_p, DST_SIG),
        ("sig_missing_compression_flag", pk0, msgs[0], bytes(no_flag), DST_SIG),
    ]
    rows = []
    for label, pk, msg, sig, dst in negatives:
        assert not verify(pk, msg, sig, dst), label
        # Encoding rows fail at KeyValidate or the signature check, not only at the pairing.
        if label.startswith("pk_"):
            assert key_validate(pk) is None, label
        if label.startswith("sig_"):
            assert signature_validate(sig) is None, label
        rows.append({"label": label, "pk": hx(pk), "msg": hx(msg), "signature": hx(sig), "verify": False})
    return {"dst": DST_SIG.decode(), "keys": keys, "signatures": signatures, "negatives": rows}


def aggregate_vectors() -> dict:
    msg = bytes.fromhex(SPEC_M)
    fav = []
    for label, indices in (("k1", [0]), ("k3", [0, 1, 2]), ("k5", [0, 1, 2, 3, 4]), ("k21", list(range(21)))):
        sigs = [sign(test_secret(i), msg) for i in indices]
        agg = aggregate(sigs)
        pks = [test_public(i) for i in indices]
        assert fast_aggregate_verify(pks, msg, agg)
        fav.append(
            {
                "label": label,
                "pks": [hx(pk) for pk in pks],
                "msg": hx(msg),
                "signature": hx(agg),
                "aggregate_public_key": g1_json(_sum_keys(pks)),
                "result": True,
            }
        )
    agg3 = aggregate([sign(test_secret(i), msg) for i in (0, 1, 2)])
    pks3 = [test_public(i) for i in (0, 1, 2)]
    fav_neg = [
        ("empty_key_list", [], msg, agg3),
        ("missing_signer_key", pks3[:2], msg, agg3),
        ("extra_key", pks3 + [test_public(3)], msg, agg3),
        ("identity_key_in_list", pks3 + [bytes([0xC0]) + bytes(47)], msg, agg3),
        ("other_message", pks3, sha256(b"other"), agg3),
        ("identity_signature", pks3, msg, bytes([0xC0]) + bytes(95)),
    ]
    for label, pks, m, sig in fav_neg:
        assert not fast_aggregate_verify(pks, m, sig), label
        fav.append({"label": label, "pks": [hx(pk) for pk in pks], "msg": hx(m), "signature": hx(sig), "result": False})
    msgs = [sha256(b"sccp-reference/aggregate-verify", bytes([i])) for i in range(3)]
    agg_distinct = aggregate([sign(test_secret(i), msgs[i]) for i in range(3)])
    av = [
        {
            "label": "distinct_messages",
            "pks": [hx(test_public(i)) for i in range(3)],
            "msgs": [hx(m) for m in msgs],
            "signature": hx(agg_distinct),
            "result": aggregate_verify([test_public(i) for i in range(3)], msgs, agg_distinct),
        }
    ]
    assert av[0]["result"] is True
    dup_msgs = [msgs[0], msgs[0], msgs[2]]
    agg_dup = aggregate([sign(test_secret(i), dup_msgs[i]) for i in range(3)])
    swapped = [msgs[1], msgs[0], msgs[2]]
    for label, pks, ms, sig in (
        ("duplicate_message", [test_public(i) for i in range(3)], dup_msgs, agg_dup),
        ("messages_swapped", [test_public(i) for i in range(3)], swapped, agg_distinct),
    ):
        result = aggregate_verify(pks, ms, sig)
        assert result is False, label
        av.append({"label": label, "pks": [hx(p) for p in pks], "msgs": [hx(m) for m in ms], "signature": hx(sig), "result": False})
    return {"fast_aggregate_verify": fav, "aggregate_verify": av}


def _sum_keys(pks: list[bytes]):
    apk = None
    for pk in pks:
        apk = g1_add(apk, g1_decompress(pk))
    return apk


def allowlist_vectors() -> list[dict]:
    """`ConsensusDigest::from_preimage` rows: exact-length allowlisted preimages and neighbours."""
    instance = rep(0x77)
    epoch = (2).to_bytes(8, "big") + rep(0x88)
    prefix = lambda kind: TAG_SIG + bytes([kind]) + instance + epoch  # noqa: E731
    rows = []

    def row(label, preimage, allowed):
        digest = consensus_digest(preimage)
        assert (digest is not None) == allowed, label
        rows.append(
            {
                "label": label,
                "preimage": hx(preimage),
                "len": len(preimage),
                "allowed": allowed,
                "digest": None if digest is None else hx(digest),
            }
        )

    body = lambda n: bytes((i * 7 + 3) % 256 for i in range(n))  # noqa: E731
    allowed = (
        ("proposal_165", prefix(0x01) + body(80)),
        ("prepare_165", prefix(0x02) + body(80)),
        ("commit_165", prefix(0x03) + body(80)),
        ("timeout_102_no_hq", prefix(0x04) + body(16) + b"\x00"),
        ("timeout_110_with_hq", prefix(0x04) + body(16) + b"\x01" + body(8)),
        ("echo_101", prefix(0x05) + body(16)),
        ("rs16_manifest_179", AVAILABILITY_TAG + b"\x00" + body(179 - len(AVAILABILITY_TAG) - 1)),
        ("rs16_row_219", AVAILABILITY_TAG + b"\x01" + body(219 - len(AVAILABILITY_TAG) - 1)),
    )
    for label, preimage in allowed:
        row(label, preimage, True)
    # Every allowlisted row one byte short and one byte long.
    for label, preimage in allowed:
        row(f"{label}_minus_1", preimage[:-1], False)
        row(f"{label}_plus_1", preimage + b"\x00", False)
    row("timeout_102_flag_1", prefix(0x04) + body(16) + b"\x01", False)
    row("timeout_110_flag_0", prefix(0x04) + body(16) + b"\x00" + body(8), False)
    row("kind_0x06_165", prefix(0x06) + body(80), False)
    row("kind_0x00_165", prefix(0x00) + body(80), False)
    row("kind_0x07_165", prefix(0x07) + body(80), False)
    row("rs16_kind_0x02_219", AVAILABILITY_TAG + b"\x02" + body(219 - len(AVAILABILITY_TAG) - 1), False)
    row("rs16_manifest_180", AVAILABILITY_TAG + b"\x00" + body(180 - len(AVAILABILITY_TAG) - 1), False)
    row("wrong_tag_165", b"sumeragi/sih" + prefix(0x03)[12:] + body(80), False)
    return rows


def ethereum_mainnet_vector() -> dict:
    """A captured Ethereum mainnet sync-committee aggregate: FastAggregateVerify under the same DST."""
    update = json.loads((ETH_CAPTURE / "finality_update.json").read_text())["data"]
    committee = json.loads((ETH_CAPTURE / "updates.json").read_text())[0]["data"]["next_sync_committee"]["pubkeys"]
    beacon = update["attested_header"]["beacon"]

    def u64(value) -> bytes:
        return int(value).to_bytes(8, "little") + bytes(24)

    def h(text: str) -> bytes:
        return bytes.fromhex(text[2:])

    def merkleize(chunks: list[bytes]) -> bytes:
        width = 1
        while width < len(chunks):
            width *= 2
        level = chunks + [bytes(32)] * (width - len(chunks))
        while len(level) > 1:
            level = [sha256(level[i], level[i + 1]) for i in range(0, len(level), 2)]
        return level[0]

    header_root = merkleize(
        [u64(beacon["slot"]), u64(beacon["proposer_index"]), h(beacon["parent_root"]), h(beacon["state_root"]), h(beacon["body_root"])]
    )
    fork_data_root = sha256(ETH_FULU_FORK_VERSION + bytes(28), ETH_GENESIS_VALIDATORS_ROOT)
    domain = ETH_DOMAIN_SYNC_COMMITTEE + fork_data_root[:28]
    signing_root = sha256(header_root, domain)
    bits = h(update["sync_aggregate"]["sync_committee_bits"])
    participants = [committee[i] for i in range(512) if bits[i // 8] >> (i % 8) & 1]
    apk = None
    for pk in participants:
        apk = g1_add(apk, g1_decompress(h(pk)))
    signature = h(update["sync_aggregate"]["sync_committee_signature"])
    sig_point = g2_decompress(signature)
    assert core_verify_point(apk, signing_root, sig_point), "captured Ethereum aggregate must verify"
    dropped = g1_add(apk, g1_neg(g1_decompress(h(participants[0]))))
    assert not core_verify_point(dropped, signing_root, sig_point)
    return {
        "source": "fixtures/sccp/rpc/eth/finality_update.json (sync_aggregate, attested_header.beacon) with the period-1868 "
        "committee from fixtures/sccp/rpc/eth/updates.json[0].next_sync_committee; Fulu fork version, mainnet genesis "
        "validators root, DOMAIN_SYNC_COMMITTEE",
        "dst": DST_SIG.decode(),
        "signature_slot": int(update["signature_slot"]),
        "attested_header_root": hx(header_root),
        "domain": hx(domain),
        "signing_root": hx(signing_root),
        "participants": len(participants),
        "aggregate_public_key": g1_json(apk),
        "signature": hx(signature),
        "fast_aggregate_verify": True,
        "negative_first_participant_dropped": {"aggregate_public_key": g1_json(dropped), "fast_aggregate_verify": False},
    }


def build() -> dict:
    """The complete `bls_consensus_v1.json` document."""
    return {
        "schema": "iroha.sccp.bls-consensus.v1",
        "spec": "specs/sccp.md §3.8; specs/sumeragi.md §1 item 6 (revision 5)",
        "generator": "scripts/sccp_reference/generate.py (independent Python reference) writes this file alone; "
        "iroha_crypto::bls::consensus reproduces every row "
        "(crates/iroha_crypto/src/signature/bls/consensus/tests/python_reference.rs)",
        "conventions": "upstream input/output values retain their original JSON conventions; other byte strings are 0x-prefixed lowercase hex; field elements are 0x-prefixed hex integers; G1 points are "
        "{compressed (ZCash 48 B), eip2537 (128 B)} and G2 points {compressed (ZCash 96 B), evm192 (x.c0‖x.c1‖y.c0‖y.c1, "
        "48 B limbs), eip2537 (256 B)}",
        "imported_rfc9380": imported_rfc9380(),
        "hash_to_g2_dst_sig": dst_sig_traces(),
        "sign_verify": sign_verify_vectors(),
        "aggregates": aggregate_vectors(),
        "consensus_allowlist": allowlist_vectors(),
        "ethereum_bls12_381_tests": ethereum_vectors(),
        "sccp_extra_malformed_inputs": malformed_inputs(),
        "ethereum_mainnet_sync_committee": ethereum_mainnet_vector(),
        "rust_only_vectors": "the vectors that need the w3f transcript of iroha_crypto (pinned w3f proofs of "
        "possession, a w3f-transcript signature over a consensus digest, a DST_SIG signature presented to the generic "
        "API and a proof of possession used as a signature) are not rows of this file. They live in "
        "fixtures/sccp/bls_consensus_rust_v1.json (schema iroha.bls_consensus.rust.v1), generated and drift-checked "
        "by iroha_crypto. The Python reference checks in pytests/scripts/test_sccp_reference.py every row of that "
        "file it can decide without the w3f transcript: the standard sign, verify and aggregate vectors, the "
        "allowlist rows and rejections, and the key and consensus-API negatives; the proofs of possession and the "
        "verdict of the generic-API negative stay Rust-only",
    }
