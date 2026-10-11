"""Finality header `X`, certified result `R`, `QC_FIXED`, Commit preimage and anchors.

`specs/sccp.md` §3.6–§3.8, §4.2.1 and §11.2. Everything here is a fixed byte
layout; nothing depends on Norito.
"""

from __future__ import annotations

from dataclasses import dataclass, replace

from .bls12_381 import (
    G1_GENERATOR,
    HALF_P,
    R as GROUP_ORDER,
    G1Point,
    G2Point,
    fp_to_bytes48,
    g1_add,
    g1_decompress,
    g1_neg,
    g1_to_eip2537,
    g2_compress,
    g2_mul,
    g2_to_eip2537,
    g2_to_evm192,
)
from .common import (
    MAX_HISTORY_SIZE,
    MAX_VALIDITY_MS,
    SCCP_ANCHOR_CHUNK,
    U64_MAX,
    SccpError,
    be32,
    be64,
    h_iroha,
    sha256,
)
from .hash_to_curve import DST_SIG, hash_to_g2
from .keccak import keccak256

X_MAGIC = b"SCCP/FINALITY/V1"
X_LEN = 221
X_HEAD_LEN = 109
RESULT_TAG = b"iroha/sumeragi/result/v1"
RESULT_BODY_TAG = b"iroha/sumeragi/result-body/v1"
MAX_RESULT_PREIMAGE_BYTES = 65_536
MAX_RESULT_BODY_BYTES = 65_315
QC_FIXED_LEN = 116
COMMIT_PREIMAGE_LEN = 165
TAG_SIG = b"sumeragi/sig"
KIND_PREPARE = 0x02
KIND_COMMIT = 0x03
COMMITTEE_TAG = b"SCCP/COMMITTEE/V1"
ANCHOR_LEAF_TAG = b"sccp/anchor-leaf/v1"
ANCHOR_NODE_TAG = b"sccp/anchor-node/v1"
FORGERY_EVIDENCE_TAG = b"sccp/forgery-evidence/v1"
FLAG_ACTIVE = 0x01
FLAG_ROTATION = 0x02
# X6: a rotation at height `h` of generation `g` installs generation `g + 1` starting at `h + 1`,
# and both successor values must fit `u64`.
MAX_ROTATION_HEIGHT = U64_MAX - 1
MAX_ROTATION_GENERATION = U64_MAX - 1
ZERO32 = bytes(32)


def committee_n_valid(n: int) -> bool:
    """`n ∈ {4, 7, …, 31}`."""
    return 4 <= n <= 31 and (n - 1) % 3 == 0


def quorum(n: int) -> int:
    """`q = n − f` with `f = (n − 1) / 3`."""
    if not committee_n_valid(n):
        raise ValueError(f"invalid committee size {n}")
    return n - (n - 1) // 3


@dataclass(frozen=True)
class FinalityHeader:
    """`SccpFinalityHeaderV1` fields (§3.6)."""

    network_id: bytes
    height: int
    timestamp_ms: int
    flags: int = FLAG_ACTIVE
    message_count: int = 0
    sccp_root: bytes = ZERO32
    history_size: int = 0
    history_root: bytes = ZERO32
    generation: int = 0
    committee_root: bytes = ZERO32
    validity_ms: int = 0
    next_committee_root: bytes = ZERO32

    @property
    def active(self) -> bool:
        return bool(self.flags & FLAG_ACTIVE)

    @property
    def rotation(self) -> bool:
        return bool(self.flags & FLAG_ROTATION)

    def encode(self) -> bytes:
        """The 221 raw bytes, without checking the invariants (use `parse` to check)."""
        out = (
            X_MAGIC
            + self.network_id
            + be64(self.height)
            + be64(self.timestamp_ms)
            + bytes([self.flags])
            + be32(self.message_count)
            + self.sccp_root
            + be64(self.history_size)
            + self.history_root
            + be64(self.generation)
            + self.committee_root
            + be64(self.validity_ms)
            + self.next_committee_root
        )
        assert len(out) == X_LEN
        return out

    def with_(self, **changes) -> "FinalityHeader":
        return replace(self, **changes)

    def as_json(self) -> dict:
        return {
            "network_id": "0x" + self.network_id.hex(),
            "height": self.height,
            "timestamp_ms": self.timestamp_ms,
            "flags": self.flags,
            "message_count": self.message_count,
            "sccp_root": "0x" + self.sccp_root.hex(),
            "history_size": self.history_size,
            "history_root": "0x" + self.history_root.hex(),
            "generation": self.generation,
            "committee_root": "0x" + self.committee_root.hex(),
            "validity_ms": self.validity_ms,
            "next_committee_root": "0x" + self.next_committee_root.hex(),
        }


def inactive_header(network_id: bytes, height: int, timestamp_ms: int) -> FinalityHeader:
    """The inactive form `magic ‖ network_id ‖ be64(h) ‖ be64(t) ‖ 0x00 ‖ 0^156`."""
    return FinalityHeader(network_id=network_id, height=height, timestamp_ms=timestamp_ms, flags=0)


def parse_header(data: bytes) -> FinalityHeader:
    """`SccpFinalityHeaderV1::parse`: exact length, then X1–X7 (`SccpError(name="X<k>")`).

    The checks run in the order Length, X1, X2 (inactive) or X3 (active), X4, X5,
    X6, X7 and the first violated one is reported. X6 also bounds a rotation's
    height and generation by `2^64 − 2`, so that the successor's start
    `height + 1` and its generation `generation + 1` fit `u64`.
    """
    if len(data) != X_LEN:
        raise SccpError("Length", f"X must be {X_LEN} bytes")

    def u(offset: int, width: int) -> int:
        return int.from_bytes(data[offset : offset + width], "big")

    x = FinalityHeader(
        network_id=data[16:48],
        height=u(48, 8),
        timestamp_ms=u(56, 8),
        flags=data[64],
        message_count=u(65, 4),
        sccp_root=data[69:101],
        history_size=u(101, 8),
        history_root=data[109:141],
        generation=u(141, 8),
        committee_root=data[149:181],
        validity_ms=u(181, 8),
        next_committee_root=data[189:221],
    )
    if data[:16] != X_MAGIC or x.flags & 0xFC:
        raise SccpError("X1", "magic or reserved flag bits")
    if not x.active:
        if any(data[65:]) or x.rotation:
            raise SccpError("X2", "inactive X must be zero after the flags and not rotate")
    else:
        if x.generation < 1 or x.committee_root == ZERO32:
            raise SccpError("X3", "active X needs a generation and a committee root")
    if (x.message_count == 0) != (x.sccp_root == ZERO32) or x.message_count > 512:
        raise SccpError("X4", "message count and root disagree")
    if (x.history_size == 0) != (x.history_root == ZERO32) or x.history_size > MAX_HISTORY_SIZE:
        raise SccpError("X5", "history size and root disagree")
    if x.rotation:
        if x.next_committee_root == ZERO32 or not 1 <= x.validity_ms <= MAX_VALIDITY_MS:
            raise SccpError("X6", "rotation needs a successor root and a validity")
        if x.height > MAX_ROTATION_HEIGHT:
            raise SccpError("X6", "rotation at the last height leaves no successor start")
        if x.generation > MAX_ROTATION_GENERATION:
            raise SccpError("X6", "rotation of the last generation leaves no successor generation")
    elif x.next_committee_root != ZERO32 or x.validity_ms != 0:
        raise SccpError("X6", "non-rotation X carries successor fields")
    if x.height < 1:
        raise SccpError("X7", "height must be at least 1")
    return x


def result_r(x: bytes, d_body: bytes) -> bytes:
    """`R = SHA-256(RESULT_TAG ‖ X ‖ D_body)` (277-byte input)."""
    if len(x) != X_LEN or len(d_body) != 32:
        raise ValueError("R takes a 221-byte X and a 32-byte D_body")
    return sha256(RESULT_TAG, x, d_body)


def body_digest(body: bytes) -> bytes:
    """`D_body = H_iroha(RESULT_BODY_TAG ‖ body)`."""
    return h_iroha(RESULT_BODY_TAG, body)


def result_of_preimage(preimage: bytes) -> bytes | None:
    """The only `R` function (§3.6): `None` for a bad length or an unparseable `X`."""
    if len(preimage) < X_LEN + 1 or len(preimage) > MAX_RESULT_PREIMAGE_BYTES:
        return None
    try:
        parse_header(preimage[:X_LEN])
    except SccpError:
        return None
    return sha256(RESULT_TAG, preimage[:X_LEN], body_digest(preimage[X_LEN:]))


def checkpoint_id(x: bytes) -> bytes:
    """`keccak256(X)`."""
    return keccak256(x)


def committee_root(keys: list[bytes]) -> bytes:
    """`keccak256("SCCP/COMMITTEE/V1" ‖ u8 n ‖ PK_0 ‖ … ‖ PK_{n−1})` (18 + 48n bytes).

    The root is defined for `1 ≤ n ≤ 255` keys only, the counts the `u8` can
    name without ambiguity; any other list has no root and raises `ValueError`.
    """
    if not 1 <= len(keys) <= 255:
        raise ValueError("a committee root is defined for 1 to 255 keys")
    if any(len(k) != 48 for k in keys):
        raise ValueError("committee keys are 48-byte compressed points")
    return keccak256(COMMITTEE_TAG, bytes([len(keys)]), *keys)


def canonical_order(keys: list[bytes]) -> list[bytes]:
    """Strictly ascending by `kb(pk) = be16(48) ‖ pk`, i.e. by the key bytes."""
    ordered = sorted(keys)
    if len(set(ordered)) != len(ordered):
        raise ValueError("duplicate committee key")
    return ordered


def signers_from_indices(indices: list[int]) -> int:
    """`Σ_j bitmap[j] << 8j` = the bitset of canonical indices."""
    value = 0
    for i in indices:
        value |= 1 << i
    return value


def bitmap_from_indices(indices: list[int], n: int) -> bytes:
    """The Sumeragi bitmap: `ceil(n/8)` bytes, bit `i` = index `i`, LSB-first in each byte."""
    out = bytearray((n + 7) // 8)
    for i in indices:
        out[i // 8] |= 1 << (i % 8)
    return bytes(out)


def indices_from_signers(signers: int) -> list[int]:
    return [i for i in range(32) if signers >> i & 1]


@dataclass(frozen=True)
class QcFixed:
    """The 116-byte `QC_FIXED` (§3.7)."""

    epoch: int
    epoch_context: bytes
    view: int
    block_hash: bytes
    result_body: bytes
    signers: int

    def encode(self) -> bytes:
        out = (
            be64(self.epoch)
            + self.epoch_context
            + be64(self.view)
            + self.block_hash
            + self.result_body
            + be32(self.signers)
        )
        assert len(out) == QC_FIXED_LEN
        return out

    def as_json(self) -> dict:
        return {
            "epoch": self.epoch,
            "epoch_context": "0x" + self.epoch_context.hex(),
            "view": self.view,
            "block_hash": "0x" + self.block_hash.hex(),
            "result_body": "0x" + self.result_body.hex(),
            "signers": self.signers,
        }


def parse_qc_fixed(data: bytes) -> QcFixed:
    if len(data) != QC_FIXED_LEN:
        raise SccpError("BadCertificate", "QC_FIXED must be 116 bytes")
    return QcFixed(
        epoch=int.from_bytes(data[0:8], "big"),
        epoch_context=data[8:40],
        view=int.from_bytes(data[40:48], "big"),
        block_hash=data[48:80],
        result_body=data[80:112],
        signers=int.from_bytes(data[112:116], "big"),
    )


def commit_preimage(
    instance: bytes,
    epoch: int,
    epoch_context: bytes,
    height: int,
    view: int,
    block_hash: bytes,
    result: bytes,
    kind: int = KIND_COMMIT,
) -> bytes:
    """`vote_preimage(kind, h, v, bh, R)`; the Commit kind gives the 165-byte `P` of §3.7."""
    out = (
        TAG_SIG
        + bytes([kind])
        + instance
        + be64(epoch)
        + epoch_context
        + be64(height)
        + be64(view)
        + block_hash
        + result
    )
    assert len(out) == COMMIT_PREIMAGE_LEN
    return out


def commit_message(preimage: bytes) -> bytes:
    """`m = SHA-256(P)`."""
    return sha256(preimage)


def anchor_leaf(height: int, core_hash: bytes, result: bytes) -> bytes:
    """`H_iroha("sccp/anchor-leaf/v1" ‖ be64(h) ‖ core_hash ‖ R)`."""
    return h_iroha(ANCHOR_LEAF_TAG, be64(height), core_hash, result)


def anchor_node(left: bytes, right: bytes) -> bytes:
    """`H_iroha("sccp/anchor-node/v1" ‖ left ‖ right)`."""
    return h_iroha(ANCHOR_NODE_TAG, left, right)


def anchor_chunk_levels(leaves: list[bytes]) -> list[list[bytes]]:
    """The complete binary tree over one full chunk: exactly 4 096 anchors (§4.2.1). An open chunk has no root."""
    if len(leaves) != SCCP_ANCHOR_CHUNK:
        raise ValueError(f"a chunk tree needs exactly {SCCP_ANCHOR_CHUNK} leaves")
    levels = [list(leaves)]
    while len(levels[-1]) > 1:
        level = levels[-1]
        levels.append([anchor_node(level[i], level[i + 1]) for i in range(0, len(level), 2)])
    return levels


def anchor_chunk_path(levels: list[list[bytes]], position: int) -> list[bytes]:
    """Bottom-up siblings (12 hashes for a full chunk)."""
    path = []
    for level in levels[:-1]:
        path.append(level[position ^ 1])
        position >>= 1
    return path


def anchor_chunk_position(height: int) -> tuple[int, int]:
    """`(chunk, position) = (⌊(a − 1) / 4096⌋, (a − 1) mod 4096)` for an anchor height `a ≥ 1`."""
    if height < 1:
        raise ValueError("anchor heights start at 1")
    return (height - 1) // SCCP_ANCHOR_CHUNK, (height - 1) % SCCP_ANCHOR_CHUNK


def forgery_evidence_id(generation: int, message: bytes, signers: int) -> bytes:
    """`H_iroha("sccp/forgery-evidence/v1" ‖ be64(g) ‖ m ‖ be32(signers))`."""
    return h_iroha(FORGERY_EVIDENCE_TAG, be64(generation), message, be32(signers))


# ---------------------------------------------------------------------------
# Certificates
# ---------------------------------------------------------------------------


@dataclass
class Certificate:
    """A full SCCP certificate in wire form, with the values it was built from.

    `qc`, `header`, `signature_evm`, `committee` and `signer_ys` are exactly the
    EVM `TairaCertificateV1` fields; `signature_ton` is the 96-byte compressed
    aggregate the TON `TairaCert` cell carries. Negative vectors mutate these
    bytes directly.
    """

    qc: bytes
    header: bytes
    signature_evm: bytes
    signature_ton: bytes
    committee: bytes
    signer_ys: bytes
    meta: dict

    def evm_json(self) -> dict:
        return {
            "qc": "0x" + self.qc.hex(),
            "header": "0x" + self.header.hex(),
            "signature": "0x" + self.signature_evm.hex(),
            "committee": "0x" + self.committee.hex(),
            "signerYs": "0x" + self.signer_ys.hex(),
        }

    def ton_json(self) -> dict:
        """The TON `TairaCert` contents: `signers` is the last 4 bytes of `QC_FIXED` and
        `qc_fixed_cell` everything before them, so a `QC_FIXED` of the wrong length gives a
        `QcFixed` cell of the wrong length (a TON length negative), never a well-formed one."""
        return {
            "signature": "0x" + self.signature_ton.hex(),
            "signers": int.from_bytes(self.qc[-4:], "big"),
            "qc_fixed_cell": "0x" + self.qc[:-4].hex(),
            "x_head": "0x" + self.header[:X_HEAD_LEN].hex(),
            "x_tail": "0x" + self.header[X_HEAD_LEN:].hex(),
        }


def signer_y_bytes(keys: list[bytes], indices: list[int]) -> bytes:
    """`signerYs`: each signer's `y` (48 bytes) in ascending index order."""
    out = b""
    for i in sorted(indices):
        point = g1_decompress(keys[i])
        assert point is not None
        out += fp_to_bytes48(point[1])
    return out


def aggregate_public_key(keys: list[bytes], indices: list[int]) -> G1Point:
    apk: G1Point = None
    for i in sorted(indices):
        apk = g1_add(apk, g1_decompress(keys[i]))
    return apk


def build_certificate(
    *,
    keys: list[bytes],
    secret_of: dict[bytes, int],
    signer_indices: list[int],
    header: bytes,
    instance: bytes,
    epoch: int,
    epoch_context: bytes,
    view: int,
    block_hash: bytes,
    result_body: bytes,
    kind: int = KIND_COMMIT,
    dst: bytes = DST_SIG,
    signed_height: int | None = None,
    signed_instance: bytes | None = None,
    signed_header: bytes | None = None,
    signing_keys: list[bytes] | None = None,
    signers_field: int | None = None,
) -> Certificate:
    """Sign a certificate with the secret keys of `signer_indices` of `keys`.

    The aggregate is `(Σ sk_i) · hash_to_G2(m, dst)`, which equals the sum of the
    individual signatures. The keyword overrides build negative vectors whose
    signature covers something other than what the wire carries. `signerYs`
    always follows the `signers` field actually encoded, as a relayer that
    misreads the bitmap would build it.
    """
    n = len(keys)
    signers = signers_from_indices(signer_indices) if signers_field is None else signers_field
    qc = QcFixed(epoch, epoch_context, view, block_hash, result_body, signers)
    signed_x = header if signed_header is None else signed_header
    height = int.from_bytes(signed_x[48:56], "big") if signed_height is None else signed_height
    result = sha256(RESULT_TAG, signed_x, result_body)
    preimage = commit_preimage(
        instance if signed_instance is None else signed_instance,
        epoch,
        epoch_context,
        height,
        view,
        block_hash,
        result,
        kind,
    )
    message = commit_message(preimage)
    signer_set = signing_keys if signing_keys is not None else [keys[i] for i in signer_indices]
    scalar = sum(secret_of[k] for k in signer_set) % GROUP_ORDER
    q_point = hash_to_g2(message, dst)
    sigma = g2_mul(q_point, scalar)
    apk = aggregate_public_key(keys, signer_indices)
    meta = {
        "n": n,
        "q": quorum(n) if committee_n_valid(n) else None,
        "signer_indices": sorted(signer_indices),
        "signers": signers,
        "bitmap": bitmap_from_indices(signer_indices, n),
        "qc": qc,
        "r": result,
        "p": preimage,
        "m": message,
        "kind": kind,
        "dst": dst,
        "hash_point": q_point,
        "sigma": sigma,
        "apk": apk,
    }
    return Certificate(
        qc=qc.encode(),
        header=header,
        signature_evm=g2_to_evm192(sigma),
        signature_ton=g2_compress(sigma),
        committee=b"".join(keys),
        signer_ys=signer_y_bytes(keys, [i for i in indices_from_signers(signers) if i < n]),
        meta=meta,
    )


def pairing_input(apk: G1Point, q_point: G2Point, sigma: G2Point) -> bytes:
    """The 768-byte EIP-2537 `PAIRING_CHECK` input `apk ‖ Q ‖ (−g1) ‖ σ` (§5.2.4)."""
    return g1_to_eip2537(apk) + g2_to_eip2537(q_point) + g1_to_eip2537(g1_neg(G1_GENERATOR)) + g2_to_eip2537(sigma)


def y_sign_flag_matches(key: bytes, y: int) -> bool:
    """EVM step 6: `(byte0 & 0x20 ≠ 0) = (y > HALF_P)`."""
    return bool(key[0] & 0x20) == (y > HALF_P)
