"""Builder of `fixtures/sccp/finality_v1.json` (`specs/sccp.md` §3.6–§3.8, §11.2, §11.3)."""

from __future__ import annotations

import dataclasses

from .bls12_381 import (
    G1_GENERATOR,
    G2_GENERATOR,
    HALF_P,
    P,
    R,
    fp_to_bytes48,
    PointEncodingError,
    g1_add,
    g1_compress,
    g1_decompress,
    g1_in_subgroup,
    g1_is_on_curve,
    g1_mul,
    g1_neg,
    g1_to_eip2537,
    g2_compress,
    g2_to_eip2537,
    g2_to_evm192,
)
from .common import (
    DESTINATION_CLOCK_CONVENTION,
    MAX_HISTORY_SIZE,
    MAX_VALIDITY_MS,
    REFERENCE_GENERATORS,
    U64_MAX,
    SccpError,
    check_destination_clock,
    hx,
    rep,
    sha256,
)
from .destination import Deployment, Destination
from .finality import (
    COMMIT_PREIMAGE_LEN,
    FLAG_ACTIVE,
    FLAG_ROTATION,
    KIND_PREPARE,
    MAX_ROTATION_GENERATION,
    MAX_ROTATION_HEIGHT,
    QC_FIXED_LEN,
    RESULT_BODY_TAG,
    RESULT_TAG,
    TAG_SIG,
    X_HEAD_LEN,
    X_LEN,
    X_MAGIC,
    FinalityHeader,
    QcFixed,
    anchor_chunk_levels,
    anchor_chunk_path,
    anchor_chunk_position,
    anchor_leaf,
    anchor_node,
    bitmap_from_indices,
    body_digest,
    build_certificate,
    checkpoint_id,
    commit_message,
    commit_preimage,
    committee_root,
    forgery_evidence_id,
    inactive_header,
    pairing_input,
    parse_header,
    quorum,
    result_of_preimage,
    result_r,
    signers_from_indices,
)
from .hash_to_curve import DST_SIG, iso_map_g2, map_to_curve_sswu
from .payload import ETHEREUM, TON
from .taira import Committee, TairaSim, test_public, test_secret

NETWORK_ID = rep(0x11)
INSTANCE = rep(0x77)
T0 = 1_790_000_000_000
HOUR = 3_600_000
DAY = 86_400_000
VALIDITY = 1_209_600_000
GENERATION = 7
START_HEIGHT = 7000
DST_NUL = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_"
# The destination words of the two verification contexts. A TON minter's word is its account id; this one is a
# placeholder (`control_v1.json` lists the same value under `destination_words`).
EVM_DESTINATION_WORD = bytes(12) + rep(0x22, 20)
TON_DESTINATION_WORD = rep(0x35)
# The effective cofactor of G1 (RFC 9380 §8.8.1): `H_EFF_G1 · P` is in G1 for every point `P` of the curve.
H_EFF_G1 = 0xD201000000010001

# §11.2 pinned values (asserted on every build).
SPEC_R = {
    "rotation": "3fcdcdfce761808f1a1f633fd209c197738d93032a0c5496ff20fb9bbcd783d7",
    "heartbeat": "ec15d2c034f21de8f6a6192bd246d5ee7acf99ae452c7a70f7c6003b567b1ed4",
    "non_rotation": "93d642e5cd5e489a395a937a88c63834fceaa8db9ef267e600f70ba58027c9ac",
    "inactive": "541b29c5e6058adb34edef96855cb321fdcdc635fc92e4ac25777d1b3ea07b1a",
}
SPEC_CHECKPOINT_ID = {
    "rotation": "b0a93737e03cec3ff52c920efa7db18859883ecb598ff7bdd2bf19f67c1086f6",
    "heartbeat": "0ae4bff13d50fc7129b3fcd5926df55d5da6afc8a33445abed1a1a7e650537a4",
    "non_rotation": "2d519a8ba8b000583ee3d0e6ec06843d95c3f7de32bf5ff9a76e6fad0fbbda6c",
}
SPEC_X_HEX = {
    "rotation": "534343502f46494e414c4954592f5631" + "11" * 32 + "0000000000001c20000001a0c4506c0003"
    "00000002" + "22" * 32 + "0000000000000005" + "33" * 32 + "0000000000000003" + "44" * 32
    + "0000000048190800" + "55" * 32,
    "non_rotation": "534343502f46494e414c4954592f5631" + "11" * 32 + "0000000000001c1f000001a0c450681801"
    "00000002" + "22" * 32 + "0000000000000005" + "33" * 32 + "0000000000000003" + "44" * 32
    + "0000000000000000" + "00" * 32,
}
SPEC_QC_FIXED_HEX = "0000000000000002" + "88" * 32 + "0000000000000001" + "99" * 32 + "66" * 32 + "40000201"
SPEC_M = "85c684fac5aab78b197a5e2d40329ec518bc038abd99974a37064ea26e4943e0"
SPEC_FORGERY_ID = "5fe24c413eba8a5e1d7727f630f9bf0c005286c75662061a8216b0292a454f35"
SPEC_ANCHOR_7199 = "a22346dda5d3ec12cd1308908cbbcb509f68f3b860377153ca4bae4a5f13df65"
SPEC_ANCHOR_7200 = "0422761979d4e89d78edd5dcfbd719b1f6e10f339603a53da14e4b1587202ed7"
SPEC_ANCHOR_NODE = "1d1e5d3ee82efa64b0c2703e18202b34c29bed398a688bb1626f873c2d36d1a3"
SPEC_CHUNK0_ROOT = "2367ae00d979ce576c55f1be87c6971c22921aae16c939eb9ff85b820d2e235f"
SPEC_SYNTHETIC_COMMITTEE_ROOT = "fe8902a93a6592a748b8528a9f49312e9cbc5d1abcccb1ff7431b0acba92b2b9"
NEG_G1_Y = 0x114D1D6855D545A8AA7D76C8CF2E21F267816AEF1DB507C96655B9D5CAAC42364E6F38BA0ECB751BAD54DCD6B939C2CA
HALF_P_SPEC = 0x0D0088F51CBFF34D258DD3DB21A5D66BB23BA5C279C2895FB39869507B587B120F55FFFF58A9FFFFDCFF7FFFFFFFD555


def _check(actual: bytes, expected_hex: str, what: str) -> None:
    if actual.hex() != expected_hex:
        raise AssertionError(f"{what}: computed {actual.hex()} differs from the specification value {expected_hex}")


def g1_json(pt) -> dict:
    return {"compressed": hx(g1_compress(pt)), "eip2537": hx(g1_to_eip2537(pt))}


def g2_json(pt) -> dict:
    return {"compressed": hx(g2_compress(pt)), "evm192": hx(g2_to_evm192(pt)), "eip2537": hx(g2_to_eip2537(pt))}


def constants_json() -> dict:
    neg_g1 = g1_neg(G1_GENERATOR)
    assert neg_g1[1] == NEG_G1_Y and HALF_P == HALF_P_SPEC
    return {
        "x_magic": {"ascii": X_MAGIC.decode(), "hex": hx(X_MAGIC)},
        "x_len": X_LEN,
        "x_head_len": X_HEAD_LEN,
        "x_tail_len": X_LEN - X_HEAD_LEN,
        "result_tag": {"ascii": RESULT_TAG.decode(), "hex": hx(RESULT_TAG)},
        "result_body_tag": {"ascii": RESULT_BODY_TAG.decode(), "hex": hx(RESULT_BODY_TAG)},
        "tag_sig": {"ascii": TAG_SIG.decode(), "hex": hx(TAG_SIG)},
        "dst_sig": {"ascii": DST_SIG.decode(), "hex": hx(DST_SIG), "len": len(DST_SIG)},
        "qc_fixed_len": QC_FIXED_LEN,
        "commit_preimage_len": COMMIT_PREIMAGE_LEN,
        "committee_tag": "SCCP/COMMITTEE/V1",
        "max_validity_ms": MAX_VALIDITY_MS,
        "max_history_size": str(MAX_HISTORY_SIZE),
        "bls12_381": {
            "p": hex(P),
            "half_p": hex(HALF_P),
            "r": hex(R),
            "g1": g1_json(G1_GENERATOR),
            "neg_g1": g1_json(neg_g1),
            "neg_g1_y": hex(NEG_G1_Y),
            "g2": g2_json(G2_GENERATOR),
        },
    }


def worked_examples() -> dict:
    """§11.2, every value asserted against the specification."""
    common = dict(
        network_id=rep(0x11),
        message_count=2,
        sccp_root=rep(0x22),
        history_size=5,
        history_root=rep(0x33),
        generation=3,
        committee_root=rep(0x44),
    )
    d_body = rep(0x66)
    rotation = FinalityHeader(
        height=7200, timestamp_ms=1_790_000_000_000, flags=3, validity_ms=1_209_600_000, next_committee_root=rep(0x55), **common
    )
    heartbeat = rotation.with_(next_committee_root=rep(0x44))
    non_rotation = FinalityHeader(height=7199, timestamp_ms=1_789_999_999_000, flags=1, **common)
    inactive = inactive_header(rep(0x11), 9, 1_790_000_000_000)
    cases = {}
    for name, header in (
        ("rotation", rotation),
        ("heartbeat", heartbeat),
        ("non_rotation", non_rotation),
        ("inactive", inactive),
    ):
        x = header.encode()
        parse_header(x)
        r = result_r(x, d_body)
        _check(r, SPEC_R[name], f"R({name})")
        entry = {"fields": header.as_json(), "x": hx(x), "d_body": hx(d_body), "r": hx(r)}
        if name in SPEC_CHECKPOINT_ID:
            _check(checkpoint_id(x), SPEC_CHECKPOINT_ID[name], f"checkpoint_id({name})")
            entry["checkpoint_id"] = hx(checkpoint_id(x))
        if name in SPEC_X_HEX:
            _check(x, SPEC_X_HEX[name], f"X({name})")
        cases[name] = entry
    qc = QcFixed(2, rep(0x88), 1, rep(0x99), rep(0x66), signers_from_indices([0, 9, 30]))
    _check(qc.encode(), SPEC_QC_FIXED_HEX, "QC_FIXED")
    r_rot = result_r(rotation.encode(), d_body)
    preimage = commit_preimage(INSTANCE, 2, rep(0x88), 7200, 1, rep(0x99), r_rot)
    m = commit_message(preimage)
    _check(m, SPEC_M, "m")
    fid = forgery_evidence_id(3, m, 0x40000201)
    _check(fid, SPEC_FORGERY_ID, "forgery evidence id")
    r_non = result_r(non_rotation.encode(), d_body)
    a7199 = anchor_leaf(7199, rep(0x99), r_non)
    a7200 = anchor_leaf(7200, rep(0x99), r_rot)
    _check(a7199, SPEC_ANCHOR_7199, "anchor_leaf(7199)")
    _check(a7200, SPEC_ANCHOR_7200, "anchor_leaf(7200)")
    pair = anchor_node(a7199, a7200)
    _check(pair, SPEC_ANCHOR_NODE, "anchor node")
    assert anchor_chunk_position(7199) == (1, 3102) and anchor_chunk_position(7200) == (1, 3103)
    chunk0 = anchor_chunk_levels([anchor_leaf(h, rep(0x99), rep(0x66)) for h in range(1, 4097)])
    _check(chunk0[-1][0], SPEC_CHUNK0_ROOT, "chunk 0 root")
    synthetic = committee_root([rep(1, 48), rep(2, 48), rep(3, 48), rep(4, 48)])
    _check(synthetic, SPEC_SYNTHETIC_COMMITTEE_ROOT, "synthetic committee root")
    return {
        "cases": cases,
        "qc_fixed": {
            "fields": qc.as_json(),
            "signer_indices": [0, 9, 30],
            "bitmap": hx(bitmap_from_indices([0, 9, 30], 31)),
            "encoded": hx(qc.encode()),
            "raw_bitmap_signers_negative": hex(int.from_bytes(bitmap_from_indices([0, 9, 30], 31), "big")),
        },
        "commit": {
            "instance": hx(INSTANCE),
            "epoch": 2,
            "epoch_context": hx(rep(0x88)),
            "height": 7200,
            "view": 1,
            "block_hash": hx(rep(0x99)),
            "r": hx(r_rot),
            "preimage": hx(preimage),
            "m": hx(m),
        },
        "forgery_evidence_id": {"generation": 3, "m": hx(m), "signers": 0x40000201, "id": hx(fid)},
        "anchors": {
            "core_hash": hx(rep(0x99)),
            "leaf_7199": {"chunk": 1, "position": 3102, "r": hx(r_non), "leaf": hx(a7199)},
            "leaf_7200": {"chunk": 1, "position": 3103, "r": hx(r_rot), "leaf": hx(a7200)},
            "node_7199_7200": hx(pair),
            "chunk0_all_99_66": {
                "root": hx(chunk0[-1][0]),
                "path_height_1": [hx(h) for h in anchor_chunk_path(chunk0, 0)],
                "path_height_4096": [hx(h) for h in anchor_chunk_path(chunk0, 4095)],
                "leaf_height_1": hx(chunk0[0][0]),
                "leaf_height_4096": hx(chunk0[0][4095]),
            },
        },
        "synthetic_committee_root": {
            "keys": ["0x" + "01" * 48, "0x" + "02" * 48, "0x" + "03" * 48, "0x" + "04" * 48],
            "root": hx(synthetic),
        },
    }


def curve_point_outside_g1():
    """The curve point with the smallest `x ≥ 1` (and the smaller `y`) that lies outside the G1 subgroup."""
    for low in range(1, 256):
        try:
            point = g1_decompress(bytes([0x80]) + bytes(46) + bytes([low]))
        except PointEncodingError:
            continue
        if point is not None and not g1_in_subgroup(point):
            return point
    raise AssertionError("no small curve point outside G1")


def g1_shift_outside_subgroup():
    """A nonzero point `T` of the curve with `H_EFF_G1 · T = O`: adding it to a key leaves every pairing value
    unchanged and takes the key out of G1.

    `T = W − (H_EFF_G1⁻¹ mod r) · (H_EFF_G1 · W)` for `W = curve_point_outside_g1()`: the component of `W`
    outside the `r`-torsion.
    """
    w = curve_point_outside_g1()
    in_subgroup = g1_mul(w, H_EFF_G1)
    assert g1_in_subgroup(in_subgroup)
    shift = g1_add(w, g1_neg(g1_mul(in_subgroup, pow(H_EFF_G1, -1, R))))
    assert shift is not None and g1_is_on_curve(shift) and not g1_in_subgroup(shift)
    assert g1_mul(shift, H_EFF_G1) is None
    return shift


def header_vectors(destination_outcomes) -> dict:
    """`headers.valid` and `headers.invalid`.

    `destination_outcomes(x, generation, committee_root)` gives the outcome of both destination flavors for a
    certificate that carries `x`, on a destination pinned at that generation and root: the `destination` column
    is what the model answers, not a literal.
    """
    base = FinalityHeader(
        network_id=NETWORK_ID,
        height=7100,
        timestamp_ms=T0,
        flags=FLAG_ACTIVE,
        message_count=3,
        sccp_root=rep(0x21),
        history_size=12,
        history_root=rep(0x31),
        generation=GENERATION,
        committee_root=rep(0x41),
    )
    rotation = base.with_(flags=3, validity_ms=VALIDITY, next_committee_root=rep(0x51))
    valid = {
        "non_rotation": base,
        "rotation": rotation,
        "heartbeat": rotation.with_(next_committee_root=base.committee_root),
        "empty_block": base.with_(message_count=0, sccp_root=bytes(32)),
        "empty_history": base.with_(message_count=0, sccp_root=bytes(32), history_size=0, history_root=bytes(32)),
        "maximal": rotation.with_(
            message_count=512,
            history_size=MAX_HISTORY_SIZE,
            validity_ms=MAX_VALIDITY_MS,
            height=(1 << 53) - 1,
            timestamp_ms=(1 << 53) - 1,
        ),
        "inactive": inactive_header(NETWORK_ID, 7100, T0),
        "inactive_height_1": inactive_header(NETWORK_ID, 1, 0),
    }
    out_valid = []
    for label, header in valid.items():
        x = header.encode()
        parsed = parse_header(x)
        out_valid.append(
            {
                "label": label,
                "fields": header.as_json(),
                "x": hx(x),
                "x_head": hx(x[:X_HEAD_LEN]),
                "x_tail": hx(x[X_HEAD_LEN:]),
                "checkpoint_id": hx(checkpoint_id(x)),
                "active": parsed.active,
                "rotation": parsed.rotation,
                "destination": "accept" if parsed.active else "BadHeader",
            }
        )
        # An active header passes step 2 on a destination pinned at its generation and root (it is then refused
        # for the calldata committee, which is not the one the synthetic root names); an inactive one does not.
        root = header.committee_root if any(header.committee_root) else rep(0x41)
        evm_outcome = destination_outcomes(x, header.generation or GENERATION, root)["evm"]
        assert (evm_outcome != "BadHeader") == parsed.active, (label, evm_outcome)
    bad_magic = bytearray(base.encode())
    bad_magic[0] ^= 0x01
    invalid = {
        "magic": ("X1", bytes(bad_magic)),
        "flag_bit_2": ("X1", base.with_(flags=0x05).encode()),
        "flag_bit_7": ("X1", base.with_(flags=0x81).encode()),
        "flags_0xc0": ("X1", base.with_(flags=0xC1).encode()),
        "inactive_with_message_count": ("X2", inactive_header(NETWORK_ID, 7100, T0).with_(message_count=1, sccp_root=rep(0x21)).encode()),
        "inactive_with_generation": ("X2", inactive_header(NETWORK_ID, 7100, T0).with_(generation=1).encode()),
        "inactive_with_rotation": ("X2", inactive_header(NETWORK_ID, 7100, T0).with_(flags=FLAG_ROTATION).encode()),
        "generation_zero": ("X3", base.with_(generation=0).encode()),
        "committee_root_zero": ("X3", base.with_(committee_root=bytes(32)).encode()),
        "count_without_root": ("X4", base.with_(sccp_root=bytes(32)).encode()),
        "root_without_count": ("X4", base.with_(message_count=0).encode()),
        "count_513": ("X4", base.with_(message_count=513).encode()),
        "history_size_without_root": ("X5", base.with_(history_root=bytes(32)).encode()),
        "history_root_without_size": ("X5", base.with_(history_size=0).encode()),
        "history_size_2_32_plus_1": ("X5", base.with_(history_size=MAX_HISTORY_SIZE + 1).encode()),
        "rotation_validity_zero": ("X6", rotation.with_(validity_ms=0).encode()),
        "rotation_validity_above_max": ("X6", rotation.with_(validity_ms=MAX_VALIDITY_MS + 1).encode()),
        "rotation_next_root_zero": ("X6", rotation.with_(next_committee_root=bytes(32)).encode()),
        # The successor would start at height 2^64, which no u64 holds.
        "rotation_at_max_height": ("X6", rotation.with_(height=U64_MAX).encode()),
        # The successor would be generation 2^64.
        "rotation_at_max_generation": ("X6", rotation.with_(generation=U64_MAX).encode()),
        "non_rotation_with_validity": ("X6", base.with_(validity_ms=1).encode()),
        "non_rotation_with_next_root": ("X6", base.with_(next_committee_root=rep(0x51)).encode()),
        "height_zero": ("X7", base.with_(height=0).encode()),
        "inactive_height_zero": ("X7", inactive_header(NETWORK_ID, 0, T0).encode()),
        "length_220": ("Length", base.encode()[:-1]),
        "length_222": ("Length", base.encode() + b"\x00"),
        # Two violations each, one row per adjacent pair of the order Length, X1, X2 | X3, X4, X5, X6, X7: the
        # reported error is the earlier one.
        "magic_and_inactive_with_generation": (
            "X1", bytes([bad_magic[0]]) + inactive_header(NETWORK_ID, 7100, T0).with_(generation=1).encode()[1:]),
        "flag_bit_2_and_generation_zero": ("X1", base.with_(flags=0x05, generation=0).encode()),
        "generation_zero_and_count_513": ("X3", base.with_(generation=0, message_count=513).encode()),
        "count_513_and_history_root_without_size": ("X4", base.with_(message_count=513, history_size=0).encode()),
        "history_size_without_root_and_rotation_validity_zero": (
            "X5", rotation.with_(history_root=bytes(32), validity_ms=0).encode()),
        "rotation_validity_zero_and_height_zero": ("X6", rotation.with_(validity_ms=0, height=0).encode()),
        "inactive_with_generation_and_height_zero": ("X2", inactive_header(NETWORK_ID, 0, T0).with_(generation=1).encode()),
    }
    out_invalid = []
    for label, (error, data) in invalid.items():
        try:
            parse_header(data)
        except SccpError as err:
            assert err.name == error, (label, err.name, error)
        else:
            raise AssertionError(f"{label} parsed")
        outcomes = destination_outcomes(data, GENERATION, base.committee_root)
        assert outcomes == {"evm": "BadHeader", "ton": "BadHeader"}, (label, outcomes)
        out_invalid.append({"label": label, "x": hx(data), "error": error, "destination": outcomes["evm"]})
    # The nearest neighbours of `rotation_at_max_height` and `rotation_at_max_generation` parse (their values
    # exceed 2^53, so they are not rows).
    parse_header(rotation.with_(height=MAX_ROTATION_HEIGHT).encode())
    parse_header(base.with_(height=U64_MAX).encode())
    parse_header(rotation.with_(generation=MAX_ROTATION_GENERATION).encode())
    parse_header(base.with_(generation=U64_MAX).encode())
    return {"valid": out_valid, "invalid": out_invalid}


def result_of_preimage_vectors() -> list[dict]:
    x = FinalityHeader(
        network_id=NETWORK_ID, height=7100, timestamp_ms=T0, generation=GENERATION, committee_root=rep(0x41)
    ).encode()
    inactive = inactive_header(NETWORK_ID, 7100, T0).encode()
    rows = []
    for label, body in (("one_byte_body", b"\x00"), ("short_body", b"sccp-reference body"), ("inactive_x", None)):
        preimage = (inactive if body is None else x) + (b"\x01\x02\x03" if body is None else body)
        result = result_of_preimage(preimage)
        rows.append(
            {
                "label": label,
                "preimage": hx(preimage),
                "d_body": hx(body_digest(preimage[X_LEN:])),
                "r": hx(result),
            }
        )
    max_body = bytes(65_315)
    max_r = result_of_preimage(x + max_body)
    assert max_r is not None and result_of_preimage(x + max_body + b"\x00") is None
    rows.append(
        {
            "label": "maximal_body",
            "construction": "the X of row one_byte_body followed by 65315 zero bytes (65536 bytes in total)",
            "preimage_len": X_LEN + 65_315,
            "d_body": hx(body_digest(max_body)),
            "r": hx(max_r),
        }
    )
    rows.append(
        {
            "label": "body_too_long",
            "construction": "the X of row one_byte_body followed by 65316 zero bytes (65537 bytes)",
            "preimage_len": X_LEN + 65_316,
            "r": None,
        }
    )
    for label, preimage in (("x_only", x), ("truncated_x", x[:200]), ("unparseable_x", bytes(X_LEN) + b"\x00")):
        assert result_of_preimage(preimage) is None
        rows.append({"label": label, "preimage": hx(preimage), "r": None})
    return rows


def signer_encoding_vectors() -> list[dict]:
    rows = []
    for label, n, indices in (
        ("n4_lowest", 4, [0, 1, 2]),
        ("n4_highest", 4, [1, 2, 3]),
        ("n7_lowest", 7, [0, 1, 2, 3, 4]),
        ("n7_highest", 7, [2, 3, 4, 5, 6]),
        ("n31_example", 31, [0, 9, 30]),
        ("n31_lowest", 31, list(range(21))),
        ("n31_highest", 31, list(range(10, 31))),
    ):
        bitmap = bitmap_from_indices(indices, n)
        signers = signers_from_indices(indices)
        rows.append(
            {
                "label": label,
                "n": n,
                "indices": indices,
                "bitmap": hx(bitmap),
                "signers": signers,
                "signers_be32": hx(signers.to_bytes(4, "big")),
                "raw_bitmap_misreading": hex(int.from_bytes(bitmap.ljust(4, b"\x00")[:4], "big")) if n > 8 else None,
            }
        )
    return rows


def signer_ys_exactly_q(cert, keys: list[bytes]):
    """`cert` with `signerYs` of exactly `48q` bytes, so that EVM passes the step 1 length check.

    The `y` values of the encoded in-range signers come first (ascending index); a short list
    is padded with the `y` of the lowest keys outside the encoded set, a long one truncated.
    """
    q = quorum(len(keys))
    signers = int.from_bytes(cert.qc[112:116], "big")
    ys = cert.signer_ys
    for i in range(len(keys)):
        if len(ys) >= 48 * q:
            break
        if not signers >> i & 1:
            ys += fp_to_bytes48(g1_decompress(keys[i])[1])
    return dataclasses.replace(cert, signer_ys=ys[: 48 * q])


def _pin(committee: Committee, generation: int = GENERATION) -> dict:
    return {
        "generation": generation,
        "committee_root": committee.root,
        "start_height": START_HEIGHT,
        "until_ms": T0 + VALIDITY,
        "keys": committee.keys,
    }


def _deployment(flavor: str, pin: dict) -> Deployment:
    return Deployment(
        flavor=flavor,
        taira_network_id=NETWORK_ID,
        consensus_instance=INSTANCE,
        network=TON if flavor == "ton" else ETHEREUM,
        destination_word=TON_DESTINATION_WORD if flavor == "ton" else EVM_DESTINATION_WORD,
        route_revision=1,
        max_wrapped_supply=10**18,
        pin_generation=pin["generation"],
        pin_root=pin["committee_root"],
        pin_start_height=pin["start_height"],
        pin_until_ms=pin["until_ms"],
        pin_keys=pin["keys"],
    )


def _outcome(flavor: str, pin: dict, cert, now_ms: int) -> str:
    return Destination(_deployment(flavor, pin)).verify_certificate(cert, now_ms)["outcome"]


def wire_commit_message(cert) -> bytes:
    """`m` as a verifier derives it from the wire: `SHA-256(P)` with the pinned instance, kind `0x03`, the
    `QC_FIXED` fields and `X.height` and `R` of the header bytes as they are."""
    qc, x = cert.qc, cert.header
    return commit_message(
        commit_preimage(
            INSTANCE,
            int.from_bytes(qc[0:8], "big"),
            qc[8:40],
            int.from_bytes(x[48:56], "big"),
            int.from_bytes(qc[40:48], "big"),
            qc[48:80],
            result_r(x, qc[80:112]),
        )
    )


def _certificate_json(label, description, committee_name, cert, pin, now_ms, *, evm=True, ton=True, detail=True) -> dict:
    check_destination_clock(now_ms, where=f"certificate {label}")
    meta = cert.meta
    expected = {
        "evm": _outcome("evm", pin, cert, now_ms) if evm else None,
        "ton": _outcome("ton", pin, cert, now_ms) if ton else None,
    }
    try:
        header_fields = parse_header(cert.header).as_json()
    except SccpError:
        header_fields = None
    entry = {
        "label": label,
        "description": description,
        "committee": committee_name,
        "pin": {
            "generation": pin["generation"],
            "committee_root": hx(pin["committee_root"]),
            "start_height": pin["start_height"],
            "until_ms": pin["until_ms"],
        },
        "now_ms": now_ms,
        "header_fields": header_fields,
        "signer_indices": meta["signer_indices"],
        "bitmap": hx(meta["bitmap"]),
        "qc_fixed_fields": meta["qc"].as_json(),
        "commit_kind": meta["kind"],
        "dst": meta["dst"].decode(),
        "r": hx(meta["r"]),
        "commit_preimage": hx(meta["p"]),
        "m": hx(meta["m"]),
        "checkpoint_id": hx(checkpoint_id(cert.header)) if len(cert.header) == X_LEN else None,
        "evm": cert.evm_json(),
        "ton": cert.ton_json(),
        "expected": expected,
    }
    if detail:
        entry["hash_to_g2_m"] = g2_json(meta["hash_point"])
        entry["aggregate_public_key"] = g1_json(meta["apk"])
        entry["aggregate_signature"] = g2_json(meta["sigma"])
        entry["pairing_input"] = hx(pairing_input(meta["apk"], meta["hash_point"], meta["sigma"]))
    # The forgery-evidence identity is over the `m` a verifier derives from the wire (§4.9), so a row carries
    # it only when its `m`, the message that was signed, is that value.
    if len(cert.header) == X_LEN and len(cert.qc) == QC_FIXED_LEN and wire_commit_message(cert) == meta["m"]:
        x_gen = int.from_bytes(cert.header[141:149], "big")
        entry["forgery_evidence_id"] = hx(forgery_evidence_id(x_gen, meta["m"], int.from_bytes(cert.qc[112:116], "big")))
    if pin.get("custom_keys"):
        entry["pin"]["keys"] = [hx(k) for k in pin["keys"]]
    return entry


def build() -> dict:
    """The complete `finality_v1.json` document."""
    committees = {
        "n4": Committee("n4", tuple(range(4))),
        "n7": Committee("n7", tuple(range(7))),
        "n31": Committee("n31", tuple(range(31))),
    }
    other4 = Committee("n4_other", tuple(range(31, 35)))
    sim = TairaSim(NETWORK_ID, INSTANCE, ETHEREUM, EVM_DESTINATION_WORD)
    now = T0 + HOUR

    def header(committee: Committee, height: int, **changes) -> FinalityHeader:
        return FinalityHeader(
            network_id=NETWORK_ID,
            height=height,
            timestamp_ms=T0 + (height - START_HEIGHT) * 1000,
            flags=FLAG_ACTIVE,
            message_count=2,
            sccp_root=sha256(b"sccp-reference/block-root", height.to_bytes(8, "big")),
            history_size=40,
            history_root=sha256(b"sccp-reference/history-root", height.to_bytes(8, "big")),
            generation=GENERATION,
            committee_root=committee.root,
        ).with_(**changes)

    positives = []
    scattered = {
        "n4": [0, 1, 3],
        "n7": [0, 2, 3, 5, 6],
        "n31": [i for i in range(31) if i % 3 != 1],
    }
    for name, committee in committees.items():
        q = quorum(committee.n)
        pin = _pin(committee)
        for set_label, indices in (
            ("lowest", list(range(q))),
            ("highest", list(range(committee.n - q, committee.n))),
            ("scattered", scattered[name]),
        ):
            x = header(committee, 7100 + len(positives))
            cert = sim.certify(x, committee, signer_indices=indices)
            positives.append(
                _certificate_json(
                    f"{name}_{set_label}_q", f"non-rotation certificate, {set_label} {q} signers of n = {committee.n}", name, cert, pin, now
                )
            )
    assert 0 in scattered["n31"] and 9 in scattered["n31"] and 30 in scattered["n31"]
    n4 = committees["n4"]
    pin4 = _pin(n4)
    kinds = (
        ("key_change_rotation", header(n4, 7200, flags=3, validity_ms=VALIDITY, next_committee_root=other4.root)),
        ("heartbeat_rotation", header(n4, 7201, flags=3, validity_ms=VALIDITY, next_committee_root=n4.root)),
        ("non_rotation", header(n4, 7203)),
        ("empty_block_non_rotation", header(n4, 7205, message_count=0, sccp_root=bytes(32))),
    )
    for label, x in kinds:
        cert = sim.certify(x, n4)
        positives.append(_certificate_json(label, f"{label.replace('_', ' ')} (n = 4)", "n4", cert, pin4, now))
    for entry in positives:
        assert entry["expected"] == {"evm": "ok", "ton": "ok"}, entry["label"]

    negatives, flavor_specific = _negatives(sim, committees, other4, header, now)

    # Any well-formed certificate: the header checks precede everything that reads its other fields.
    probe = sim.certify(header(n4, 7099), n4)

    def destination_outcomes(x: bytes, generation: int, root: bytes) -> dict:
        pin = {**pin4, "generation": generation, "committee_root": root}
        carried = dataclasses.replace(probe, header=x)
        return {"evm": _outcome("evm", pin, carried, now), "ton": _outcome("ton", {**pin4, "generation": generation}, carried, now)}

    return {
        "schema": "iroha.sccp.finality.v1",
        "spec": "specs/sccp.md §3.6–§3.8, §5.1.3, §11.2, §11.3 (revision 5)",
        "generator": REFERENCE_GENERATORS,
        "conventions": "byte strings are 0x-prefixed lowercase hex; field elements and scalars that exceed 2^53 are hex strings; "
        "`expected.evm`/`expected.ton` name the §5.2.2 outcome of VerifyCertificate steps 1–12 on a fresh destination "
        "deployed with `pin` at `now_ms` (null where that flavor cannot express the vector). "
        + DESTINATION_CLOCK_CONVENTION
        + ". `headers.invalid[].error` is the first violated check in the order Length, X1, X2 (inactive) or X3 (active), "
        "X4, X5, X6, X7; X6 includes the rule that a ROTATION header has height and generation at most 2^64 - 2, so "
        "that the successor's start height + 1 and its generation + 1 fit u64 (rows rotation_at_max_height and "
        "rotation_at_max_generation); the rows named `<a>_and_<b>` violate two checks and report the earlier one, one "
        "row per adjacent pair of that order. `headers.*[].destination` is what the destination model answers for a "
        "certificate that carries the header. A certificate row carries `forgery_evidence_id` only when its `m` (the "
        "message that was signed) is the `m` a verifier derives from its wire fields. The TON verification context is "
        "ton-mainnet with the placeholder minter account id 0x35…35. `flavor_specific_certificates` are certificates "
        "that one flavor accepts and the other does not pin (rows of the same shape, without the pairing details)",
        "constants": constants_json(),
        "worked_examples": worked_examples(),
        "headers": header_vectors(destination_outcomes),
        "result_of_preimage": result_of_preimage_vectors(),
        "signer_encodings": signer_encoding_vectors(),
        "test_keys": [
            {
                "index": i,
                "ikm": hx(sha256(b"sccp-finality-test-ikm", bytes([i]))),
                "sk": hx(test_secret(i).to_bytes(32, "big")),
                "pk": hx(test_public(i)),
                "pk_eip2537": hx(g1_to_eip2537(g1_decompress(test_public(i)))),
                "pk_y": hx(fp_to_bytes48(g1_decompress(test_public(i))[1])),
            }
            for i in range(35)
        ],
        "committees": {name: c.as_json() for name, c in {**committees, "n4_other": other4}.items()},
        "verification_context": {
            "taira_network_id": hx(NETWORK_ID),
            "consensus_instance": hx(INSTANCE),
            "network": ETHEREUM.name,
            "destination_word": hx(EVM_DESTINATION_WORD),
            "ton": {"network": TON.name, "destination_word": hx(TON_DESTINATION_WORD)},
        },
        "certificates": positives,
        "negative_certificates": negatives,
        "flavor_specific_certificates": flavor_specific,
        "rust_only_vectors": "the w3f-transcript negative of §11.3 (a signature made under the generic w3f transcript "
        "over a consensus digest) needs the iroha_crypto w3f transcript, which the dependency-free Python reference does "
        "not carry. It lives in fixtures/sccp/finality_rust_v1.json (schema iroha.sccp.finality.rust.v1), generated and "
        "drift-checked by crates/iroha_sccp/tests/v1_reference_finality.rs and verified as rejected by the Python "
        "reference in pytests/scripts/test_sccp_reference.py",
    }


def _negatives(sim: TairaSim, committees: dict, other4: Committee, header, now: int) -> tuple[list[dict], list[dict]]:
    """The rows of `negative_certificates`, and the rows of `flavor_specific_certificates`: certificates that one
    flavor accepts and the other does not pin."""
    n4, n7, n31 = committees["n4"], committees["n7"], committees["n31"]
    pin4 = _pin(n4)
    out = []

    def add(label, description, cert, pin=pin4, committee="n4", *, evm=True, ton=True, expect=None):
        entry = _certificate_json(label, description, committee, cert, pin, now, evm=evm, ton=ton, detail=False)
        if expect is not None:
            for flavor, outcome in expect.items():
                if entry["expected"][flavor] != outcome:
                    raise AssertionError(f"{label}/{flavor}: model gave {entry['expected'][flavor]}, expected {outcome}")
        out.append(entry)

    base_x = header(n4, 7300)
    good = sim.certify(base_x, n4)

    add("prepare_kind", "PrepareQC (kind 0x02) instead of CommitQC", sim.certify(header(n4, 7301), n4, kind=KIND_PREPARE),
        expect={"evm": "BadSignature", "ton": "BadSignature"})
    # The signer-set rows carry exactly 48q bytes of signerYs, so EVM passes the step 1 length
    # check and reaches the step 5 bitmap check they exist for (`signer_ys_short` pins step 1).
    add("popcount_q_minus_1", "q − 1 signers (signerYs padded to 48q with a non-signer's y)",
        signer_ys_exactly_q(sim.certify(header(n4, 7302), n4, signer_indices=[0, 1]), n4.keys),
        expect={"evm": "BadCertificate", "ton": "BadCertificate"})
    add("popcount_q_plus_1_extra_signer", "q + 1 signers, an extra signer (signerYs truncated to 48q)",
        signer_ys_exactly_q(sim.certify(header(n4, 7303), n4, signer_indices=[0, 1, 2, 3]), n4.keys),
        expect={"evm": "BadCertificate", "ton": "BadCertificate"})
    spare = sim.certify(header(n4, 7304), n4, signer_indices=[0, 1, 2], signers_field=0b10011)
    add("spare_bits", "a signer bit at index n (spare bit) with popcount q (signerYs of 48q bytes)",
        signer_ys_exactly_q(spare, n4.keys), expect={"evm": "BadCertificate", "ton": "BadCertificate"})
    add("retired_qc_extension", "retired attestation field in QC_FIXED",
        dataclasses.replace(good, qc=good.qc[:80] + b"\x01" + good.qc[80:]),
        expect={"evm": "BadCertificate", "ton": "BadCertificate"})
    add("wrong_instance", "signed over a Commit preimage with another instance I",
        sim.certify(header(n4, 7306), n4, signed_instance=rep(0x78)), expect={"evm": "BadSignature", "ton": "BadSignature"})
    add("wrong_network", "X.network_id differs from the destination's Taira NetworkId",
        sim.certify(header(n4, 7307, network_id=rep(0x12)), n4), expect={"evm": "BadHeader", "ton": "BadHeader"})
    add("wrong_dst", "signed with the NUL ciphersuite DST instead of DST_SIG",
        sim.certify(header(n4, 7308), n4, dst=DST_NUL), expect={"evm": "BadSignature", "ton": "BadSignature"})
    add("signed_height_mismatch", "the Commit preimage names X.height + 1",
        sim.certify(header(n4, 7309), n4, signed_height=7310), expect={"evm": "BadSignature", "ton": "BadSignature"})
    x_signed = header(n4, 7310)
    tampered = sim.certify(x_signed, n4)
    tampered = dataclasses.replace(tampered, header=x_signed.with_(sccp_root=rep(0xEE)).encode())
    add("tampered_x", "a valid-layout X changed after signing (different sccp_root)", tampered,
        expect={"evm": "BadSignature", "ton": "BadSignature"})
    wrong_subset = sim.certify(header(n4, 7311), n4, signer_indices=[0, 1, 2], signing_keys=[n4.keys[1], n4.keys[2], n4.keys[3]])
    add("signature_of_other_subset", "the bitmap names {0,1,2} but {1,2,3} signed", wrong_subset,
        expect={"evm": "BadSignature", "ton": "BadSignature"})

    # Dirty X (each signed by the committee, so only the header check rejects it).
    dirty = {
        "x1_magic": None,
        "x1_flags_0x04": header(n4, 7320, flags=0x05),
        "x2_inactive_with_fields": inactive_header(NETWORK_ID, 7321, T0).with_(generation=GENERATION),
        "inactive_x": inactive_header(NETWORK_ID, 7322, T0),
        "x3_generation_zero": header(n4, 7323, generation=0),
        "x4_count_without_root": header(n4, 7324, sccp_root=bytes(32)),
        "x4_count_513": header(n4, 7325, message_count=513),
        "x5_history_size_without_root": header(n4, 7326, history_root=bytes(32)),
        "x6_rotation_validity_zero": header(n4, 7327, flags=3, validity_ms=0, next_committee_root=other4.root),
        "x6_non_rotation_with_validity": header(n4, 7328, validity_ms=VALIDITY),
        "x6_non_rotation_with_next_root": header(n4, 7329, next_committee_root=other4.root),
        "x7_height_zero": header(n4, 0),
    }
    for label, x in dirty.items():
        if x is None:
            raw = bytearray(header(n4, 7330).encode())
            raw[3] ^= 0x20
            raw = bytes(raw)
        else:
            raw = x.encode()
        cert = sim.certify(raw, n4)
        add(f"dirty_{label}", f"dirty X ({label.replace('_', ' ')}), validly signed", cert,
            expect={"evm": "BadHeader", "ton": "BadHeader"})

    # Classification.
    add("past_generation", "a genuine-looking certificate of generation g − 1 (same keys)",
        sim.certify(header(n4, 7340, generation=GENERATION - 1), n4), expect={"evm": "CommitteeNotAccepted", "ton": "CommitteeNotAccepted"})
    add("foreign_committee_root", "X.committee_root names another committee",
        sim.certify(header(other4, 7341), other4), committee="n4_other",
        expect={"evm": "CommitteeNotAccepted", "ton": "CommitteeNotAccepted"})

    # EVM committee and signerYs inputs.
    root_mismatch = dataclasses.replace(good, committee=b"".join(other4.keys))
    add("committee_root_mismatch", "calldata committee whose keccak root differs from cur.root", root_mismatch, ton=False,
        expect={"evm": "BadCommittee"})
    keys = n4.keys
    ys = [g1_decompress(k)[1] for k in keys]

    def with_y(cert, index_in_signers, y_value):
        sy = bytearray(cert.signer_ys)
        sy[48 * index_in_signers : 48 * index_in_signers + 48] = y_value.to_bytes(48, "big")
        return dataclasses.replace(cert, signer_ys=bytes(sy))

    add("signer_y_wrong_sign", "signerYs[0] = p − y, inconsistent with the key's sign bit", with_y(good, 0, P - ys[0]), ton=False,
        expect={"evm": "BadCommittee"})
    add("signer_y_ge_p", "signerYs[1] = y + p", with_y(good, 1, ys[1] + P), ton=False, expect={"evm": "BadCommittee"})
    off = ys[2]
    for delta in range(1, 64):
        candidate = (off + delta) % P
        if (candidate > HALF_P) == (ys[2] > HALF_P) and not g1_is_on_curve((g1_decompress(keys[2])[0], candidate)):
            off = candidate
            break
    add("signer_y_off_curve", "signerYs[2] has the right sign class but is not on the curve", with_y(good, 2, off), ton=False,
        expect={"evm": "BadCommittee"})
    for label, flag_fn in (("key_flag_infinity_0xc0", lambda b: b | 0x40), ("key_flag_uncompressed", lambda b: b & 0x7F)):
        bad_keys = list(keys)
        bad_keys[0] = bytes([flag_fn(bad_keys[0][0])]) + bad_keys[0][1:]
        bad_root = committee_root(bad_keys)
        pin = {**pin4, "committee_root": bad_root, "keys": bad_keys, "custom_keys": True}
        x = header(n4, 7350 if "infinity" in label else 7351, committee_root=bad_root)
        cert = sim.certify(x, n4)
        cert = dataclasses.replace(cert, committee=b"".join(bad_keys))
        add(label, "committee key 0 with a bad flag byte, pinned under the root of those exact bytes", cert, pin=pin, ton=False,
            expect={"evm": "BadCommittee"})
    # Signer coordinates that are no precompile input for a finite point (step 6): x ≥ p, and (0, 0), which
    # EIP-2537 reads as the point at infinity. Each key keeps valid flags, so only its own check refuses it.
    x_ge_p = bytes([(keys[0][0] & 0xE0) | 0x1F]) + b"\xff" * 47
    assert int.from_bytes(bytes([x_ge_p[0] & 0x1F]) + x_ge_p[1:], "big") >= P
    for label, description, bad_key, y_value, height in (
        ("signer_x_ge_p", "committee key 0 whose x (every coordinate bit set) is not below p, with its genuine y",
         x_ge_p, ys[0], 7352),
        ("signer_zero_coordinates", "committee key 0 with x = 0 and signerYs[0] = 0: the coordinates (0, 0)",
         bytes([0x80]) + bytes(47), 0, 7353),
    ):
        bad_keys = [bad_key] + list(keys[1:])
        bad_root = committee_root(bad_keys)
        pin = {**pin4, "committee_root": bad_root, "keys": bad_keys, "custom_keys": True}
        cert = sim.certify(header(n4, height, committee_root=bad_root), n4)
        cert = with_y(dataclasses.replace(cert, committee=b"".join(bad_keys)), 0, y_value)
        add(label, f"{description}, pinned under the root of those exact bytes", cert, pin=pin, ton=False,
            expect={"evm": "BadCommittee"})

    # Signature encodings.
    sigma = good.meta["sigma"]
    q0 = iso_map_g2(map_to_curve_sswu((5, 7)))
    from .bls12_381 import g2_in_subgroup  # local: only needed here

    assert q0 is not None and not g2_in_subgroup(q0)
    add("sigma_not_in_subgroup", "σ on the curve but outside G2",
        dataclasses.replace(good, signature_evm=g2_to_evm192(q0), signature_ton=g2_compress(q0)),
        expect={"evm": "BadSignature", "ton": "BadSignature"})
    add("sigma_zero", "σ = 0^192 (EVM) / the compressed identity (TON)",
        dataclasses.replace(good, signature_evm=bytes(192), signature_ton=bytes([0xC0]) + bytes(95)),
        expect={"evm": "BadSignature", "ton": "BadSignature"})
    evm = g2_to_evm192(sigma)
    for position, limb_name in enumerate(("x_c0", "x_c1", "y_c0", "y_c1")):
        limb = bytearray(evm)
        value = int.from_bytes(evm[48 * position : 48 * position + 48], "big") + P
        limb[48 * position : 48 * position + 48] = value.to_bytes(48, "big")
        add(f"sigma_limb_{limb_name}_ge_p", f"σ.{limb_name.replace('_', '.')} + p in the EVM form",
            dataclasses.replace(good, signature_evm=bytes(limb)), ton=False, expect={"evm": "BadSignature"})
    swapped = evm[48:96] + evm[0:48] + evm[144:192] + evm[96:144]
    add("sigma_c0_c1_swapped", "EVM σ with c1 ‖ c0 limb order (ZCash order mistaken for EIP-2537)",
        dataclasses.replace(good, signature_evm=swapped), ton=False, expect={"evm": "BadSignature"})
    off_curve = bytearray(evm)
    off_curve[191] ^= 0x01
    add("sigma_off_curve", "EVM σ with y.c1 changed by one bit", dataclasses.replace(good, signature_evm=bytes(off_curve)), ton=False,
        expect={"evm": "BadSignature"})
    ton_bad = bytearray(g2_compress(sigma))
    ton_bad[0] &= 0x7F
    add("sigma_ton_uncompressed_flag", "TON σ without the compression flag", dataclasses.replace(good, signature_ton=bytes(ton_bad)),
        evm=False, expect={"ton": "BadSignature"})

    # Bitmap order (n = 31 scattered set, and n = 7).
    idx31 = [i for i in range(31) if i % 3 != 1]
    raw_misread = int.from_bytes(bitmap_from_indices(idx31, 31), "big")
    pin31 = _pin(n31)
    add("raw_bitmap_signers", "signers = the Sumeragi bitmap bytes read big-endian (n = 31)",
        sim.certify(header(n31, 7360), n31, signer_indices=idx31, signers_field=raw_misread), pin=pin31, committee="n31",
        expect={"evm": "BadSignature", "ton": "BadSignature"})
    idx7 = [0, 1, 2, 3, 4]
    msb = 0
    for i in idx7:
        msb |= 1 << (8 * (i // 8) + 7 - i % 8)
    add("msb_first_bitmap", "signers with MSB-first bit order inside the byte (n = 7; signerYs of 48q bytes)",
        signer_ys_exactly_q(sim.certify(header(n7, 7361), n7, signer_indices=idx7, signers_field=msb), n7.keys),
        pin=_pin(n7), committee="n7", expect={"evm": "BadCertificate", "ton": "BadCertificate"})

    # Exact lengths.
    add("qc_length_115", "QC_FIXED of 115 bytes", dataclasses.replace(good, qc=good.qc[:-1]),
        expect={"evm": "BadCertificate", "ton": "BadCertificate"})
    add("header_length_220", "X of 220 bytes", dataclasses.replace(good, header=good.header[:-1]),
        expect={"evm": "BadHeader", "ton": "BadHeader"})
    add("evm_signature_length_191", "EVM signature of 191 bytes", dataclasses.replace(good, signature_evm=good.signature_evm[:-1]),
        ton=False, expect={"evm": "BadCertificate"})
    add("ton_signature_length_95", "TON signature of 95 bytes", dataclasses.replace(good, signature_ton=good.signature_ton[:-1]),
        evm=False, expect={"ton": "BadCertificate"})
    add("committee_n_5", "calldata committee of 5 keys", dataclasses.replace(good, committee=good.committee + keys[0]),
        ton=False, expect={"evm": "BadCommittee"})
    add("signer_ys_short", "signerYs of 48(q − 1) bytes", dataclasses.replace(good, signer_ys=good.signer_ys[:-48]),
        ton=False, expect={"evm": "BadCertificate"})

    # Signer keys that are points of the curve but fail KeyValidate, and an identity aggregate (§5.1.3 steps 10–11).
    # Each committee is pinned under the root of its exact key bytes, in canonical order. The first three members
    # of n4 sign with their genuine secrets; the fourth member does not sign.
    shift = g1_shift_outside_subgroup()
    points = [g1_decompress(k) for k in keys]
    secrets = [n4.secret_of[k] for k in keys]

    def odd_committee(replaced: dict[int, bytes], height: int):
        """A certificate of the committee `keys` with the members of `replaced` listed under other key bytes."""
        listed = {member: replaced.get(member, keys[member]) for member in range(4)}
        custom = sorted(listed.values())
        assert len(set(custom)) == 4
        seats = sorted(custom.index(listed[member]) for member in range(3))
        root = committee_root(custom)
        x = header(n4, height, committee_root=root).encode()
        cert = build_certificate(
            keys=custom,
            secret_of={listed[member]: secrets[member] for member in range(4)},
            signer_indices=seats,
            header=x,
            instance=INSTANCE,
            **sim.qc_fields(height, x),
        )
        return cert, {**pin4, "committee_root": root, "keys": custom, "custom_keys": True}

    shifted = g1_compress(g1_add(points[0], shift))
    cert, pin = odd_committee({0: shifted}, 7370)
    add("signer_key_outside_g1",
        "member 0 listed under its key shifted by a point outside G1, with the genuine signature: the pairing equation "
        "holds, the aggregate key is outside G1",
        cert, pin=pin, expect={"evm": "BadSignature", "ton": "BadSignature"})
    cancelling = {0: shifted, 1: g1_compress(g1_add(points[1], g1_neg(shift)))}
    cert, pin = odd_committee(cancelling, 7371)
    flavor_specific = [
        _certificate_json(
            "signer_keys_outside_g1_cancelling",
            "members 0 and 1 listed under keys shifted by T and −T outside G1, with the genuine signature: neither key "
            "is in G1, the aggregate key is, and the pairing holds. EVM sees the aggregate only and accepts; the TON "
            "outcome rests on the per-key checks of BLS_FASTAGGREGATEVERIFY (null until the Acton harness pins them)",
            "n4", cert, pin, now, ton=False, detail=False,
        )
    ]
    assert flavor_specific[0]["expected"]["evm"] == "ok" and _outcome("ton", pin, cert, now) == "BadSignature"
    # `apk = O`: member 2 listed under −(PK_0 + PK_1). The signature is the one members 0, 1 and 2 make.
    rogue = g1_compress(g1_neg(g1_add(points[0], points[1])))
    cert, pin = odd_committee({2: rogue}, 7372)
    add("aggregate_key_identity",
        "the three signer keys sum to the identity (member 2 listed under −(PK_0 + PK_1)); σ is a point of G2",
        cert, pin=pin, expect={"evm": "BadCommittee", "ton": "BadSignature"})
    off_curve_sigma = bytearray(cert.signature_evm)
    off_curve_sigma[191] ^= 0x01
    add("aggregate_key_identity_sigma_off_curve",
        "the same identity aggregate with an EVM σ that is no point of the curve: apk = O is reported first",
        dataclasses.replace(cert, signature_evm=bytes(off_curve_sigma)), pin=pin, ton=False, expect={"evm": "BadCommittee"})
    return out, flavor_specific
