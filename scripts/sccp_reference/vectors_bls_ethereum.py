"""Import and independently reproduce every pinned Ethereum BLS12-381 vector."""

from __future__ import annotations

from . import bls12_381 as curve
from .bls_sig import aggregate, aggregate_verify, core_verify_point, fast_aggregate_verify, key_validate, sign, signature_validate, sk_to_pk, verify
from .common import hx
from .hash_to_curve import DST_SIG, hash_to_g2_trace
from .imported_vectors import ETHEREUM_MANIFEST_SHA256, ETHEREUM_VECTOR_COUNTS, HASH_TO_G2_RO_DST, load_ethereum_vectors
from .vectors_bls_malformed import _affine
from .vectors_finality import g2_json


def raw(value: str) -> bytes:
    """Decode either upstream hex convention without changing imported JSON values."""
    return bytes.fromhex(value.removeprefix("0x"))


def decoded(group: int, encoding: bytes) -> bool:
    """Generic upstream deserialization includes subgroup membership and permits infinity."""
    decode = curve.g1_decompress if group == 1 else curve.g2_decompress
    subgroup = curve.g1_in_subgroup if group == 1 else curve.g2_in_subgroup
    try:
        return subgroup(decode(encoding))
    except curve.PointEncodingError:
        return False


def reproduce(group: str, vector: dict):
    """Compute the upstream result, retaining null for invalid Sign/Aggregate input.

    BatchVerify is checked as the conjunction of independently verified signatures,
    which rejects the upstream cancelling-forgery set without probabilistic batching.
    No generic upstream operation is substituted for SCCP key admission.
    """
    value = vector["input"]
    if group in ("deserialization_G1", "deserialization_G2"):
        return decoded(1 if group.endswith("G1") else 2, raw(next(iter(value.values()))))
    if group == "sign":
        secret = int(value["privkey"], 16)
        return hx(sign(secret, raw(value["message"]))) if 0 < secret < curve.R else None
    if group == "verify":
        return verify(raw(value["pubkey"]), raw(value["message"]), raw(value["signature"]))
    if group == "aggregate":
        try:
            return hx(aggregate([raw(signature) for signature in value]))
        except (ValueError, curve.PointEncodingError):
            return None
    if group == "fast_aggregate_verify":
        return fast_aggregate_verify([raw(key) for key in value["pubkeys"]], raw(value["message"]), raw(value["signature"]))
    if group == "aggregate_verify":
        return aggregate_verify([raw(key) for key in value["pubkeys"]], [raw(message) for message in value["messages"]], raw(value["signature"]))
    if group == "batch_verify":
        keys, messages, signatures = value["pubkeys"], value["messages"], value["signatures"]
        return bool(keys) and len(keys) == len(messages) == len(signatures) and all(
            verify(raw(key), raw(message), raw(signature)) for key, message, signature in zip(keys, messages, signatures)
        )
    if group == "hash_to_G2":
        point = hash_to_g2_trace(value["msg"].encode(), HASH_TO_G2_RO_DST)["point"]
        return {axis: ",".join(f"0x{limb:096x}" for limb in limbs) for axis, limbs in zip(("x", "y"), point)}
    raise ValueError(f"unknown Ethereum BLS group: {group}")


def ton_verify(keys: list[bytes], message: bytes, signature: bytes, *, aggregate_keys: bool = False) -> int:
    """Model the opcode's fixed-prefix reads separately from SCCP exact-length admission."""
    if len(signature) < 96 or any(len(key) < 48 for key in keys):
        return -9
    if aggregate_keys:
        return int(fast_aggregate_verify([key[:48] for key in keys], message, signature[:96]))
    return int(verify(keys[0][:48], message, signature[:96]))


def _deserialization_metadata(group: int, encoding: bytes, baseline: dict) -> dict:
    """Give each destination an explicit outcome for the representation it consumes."""
    key = encoding if group == 1 else raw(baseline["pk"])
    signature = encoding if group == 2 else raw(baseline["signature"])
    message = raw(baseline["msg"])
    sized = len(encoding) == (48 if group == 1 else 96)
    affine_valid, point = _affine(encoding, group) if sized else (False, None)
    affine_key = point if group == 1 else curve.g1_decompress(key)
    affine_signature = point if group == 2 else curve.g2_decompress(signature)
    validate = key_validate if group == 1 else signature_validate
    return {
        "encoding": hx(encoding),
        "deserialize": decoded(group, encoding),
        "validate": validate(encoding) is not None,
        "verify": verify(key, message, signature),
        "ton_verify": ton_verify([key], message, signature),
        "evm_affine_pairing": affine_valid if sized else None,
        "evm_affine_verify": (affine_valid and core_verify_point(affine_key, message, affine_signature)) if sized else None,
    }


def build() -> dict:
    """Import all 98 upstream rows and abort generation on any unexpected model result."""
    groups = load_ethereum_vectors()
    baseline_sign = next(row for row in groups["sign"] if row["label"] == "sign_case_c82df61aa3ee60fb")
    baseline = {
        "pk": hx(sk_to_pk(int(baseline_sign["input"]["privkey"], 16))),
        "msg": baseline_sign["input"]["message"],
        "signature": baseline_sign["output"],
    }
    for group, rows in groups.items():
        for row in rows:
            actual = reproduce(group, row)
            if actual != row["output"]:
                raise AssertionError((group, row["label"], "upstream expectation", row["output"], "model", actual))
            value = row["input"]
            if group.startswith("deserialization_"):
                row.update(_deserialization_metadata(1 if group.endswith("G1") else 2, raw(next(iter(value.values()))), baseline))
            elif group == "sign":
                row["pubkey"] = hx(sk_to_pk(int(value["privkey"], 16))) if row["output"] is not None else None
            elif group in ("verify", "fast_aggregate_verify", "aggregate_verify"):
                row["consensus_output"] = actual
                if group != "aggregate_verify":
                    keys = [raw(value["pubkey"])] if group == "verify" else [raw(key) for key in value["pubkeys"]]
                    row["ton_verify"] = ton_verify(keys, raw(value["message"]), raw(value["signature"]), aggregate_keys=group == "fast_aggregate_verify")
            elif group == "hash_to_G2":
                trace = hash_to_g2_trace(value["msg"].encode(), HASH_TO_G2_RO_DST)
                row["dst"] = HASH_TO_G2_RO_DST.decode()
                row["trace"] = {"uniform_bytes": hx(trace["uniform_bytes"])}
                for index in (0, 1):
                    u = trace[f"u{index}"]
                    row["trace"][f"u{index}"] = [hex(limb) for limb in u]
                    row["trace"][f"map_fp2_to_g2_input_u{index}"] = hx(b"".join(curve.fp_to_bytes64(limb) for limb in u))
                    row["trace"][f"map_fp2_to_g2_output_u{index}"] = hx(curve.g2_to_eip2537(trace[f"map_u{index}"]))
                row["point"] = {**g2_json(trace["point"]), "zcash_uncompressed": hx(curve.g2_uncompressed_zcash(trace["point"]))}
    return {
        "source_kind": "upstream_release_import",
        "source": "https://github.com/ethereum/bls12-381-tests/releases/tag/v0.1.2",
        "release": "v0.1.2",
        "tag_commit": "89ff3a86f1a9b89a555495f7535c853cda589320",
        "asset": "bls_tests_json.tar.gz",
        "archive_sha256": "0dc1dfabfa7b3e0f8e8029f9cb2bb8733597526fa085b18f160d2c4eb0b448bc",
        "manifest_sha256": ETHEREUM_MANIFEST_SHA256,
        "vendor_directory": "fixtures/sccp/ethereum-bls12-381-tests/v0.1.2",
        "license": "CC0-1.0",
        "dst_signature": DST_SIG.decode(),
        "dst_hash_to_G2": HASH_TO_G2_RO_DST.decode(),
        "conventions": "input and output are unchanged upstream JSON values; label is the upstream filename stem. "
        "Generic deserialization accepts canonical infinity; SCCP validate rejects identity keys and signatures. "
        "BatchVerify is reproduced by individual verification, not unweighted signature aggregation. "
        "EVM affine outcomes describe the translated ABI, which does not carry compressed flags; wrong compressed lengths have no translation (null). "
        "TON outcomes describe opcode fixed-prefix reads (-9 for short slices), independently of SCCP's exact-size admission. "
        "The hash_to_G2 group uses RFC 9380 QUUX DST and UTF-8 text, unlike the POP signature groups.",
        "counts": ETHEREUM_VECTOR_COUNTS,
        "baseline": baseline,
        "groups": groups,
    }
