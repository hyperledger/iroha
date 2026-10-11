"""Leaves, the promote-odd commitment tree and the history accumulator (`specs/sccp.md` §3.4, §3.5)."""

from __future__ import annotations

from .common import (
    MAX_BLOCK_LEAVES,
    MAX_BLOCK_PATH,
    MAX_HISTORY_PATH,
    MAX_HISTORY_SIZE,
    SccpError,
    be32,
    be64,
)
from .keccak import keccak256
from .payload import TAIRA, Profile, lane_bytes

LEAF_TAG = b"SCCP/LEAF/V1"
CONTROL_TAG = b"SCCP/CONTROL/V1"
NODE_TAG = b"SCCP/NODE/V1"
HISTORY_TAG = b"SCCP/HISTORY/V1"
CONTROL_PREIMAGE_BYTES = 199
TRACK_PARLIAMENT = 1
TRACK_FAST_PAUSE = 2
ZERO32 = bytes(32)


def transfer_leaf(message_id: bytes, destination_word: bytes) -> bytes:
    """`keccak256("SCCP/LEAF/V1" ‖ message_id ‖ destination_word)` (76-byte preimage)."""
    if len(message_id) != 32 or len(destination_word) != 32:
        raise ValueError("transfer leaf inputs are 32 bytes")
    return keccak256(LEAF_TAG, message_id, destination_word)


def check_control_constraints(
    track: int, parliament_paused: int, fast_pause_until_ms: int, certificate_id: bytes, effect_hash: bytes
) -> None:
    """The §3.4 control constraints that Taira and destinations check (`BadControl`)."""
    if track not in (TRACK_PARLIAMENT, TRACK_FAST_PAUSE):
        raise SccpError("BadControl", "track must be 1 or 2")
    if parliament_paused not in (0, 1):
        raise SccpError("BadControl", "parliament_paused must be 0 or 1")
    if track == TRACK_FAST_PAUSE and fast_pause_until_ms == 0:
        raise SccpError("BadControl", "a fast-pause control carries a nonzero expiry")
    if certificate_id == ZERO32:
        raise SccpError("BadControl", "zero certificate id")
    if effect_hash == ZERO32:
        raise SccpError("BadControl", "zero effect hash")


def control_leaf_preimage(
    taira_network_id: bytes,
    target: Profile,
    destination_word: bytes,
    route_revision: int,
    control_nonce: int,
    track: int,
    parliament_paused: int,
    fast_pause_until_ms: int,
    certificate_id: bytes,
    effect_hash: bytes,
) -> bytes:
    """The 199-byte control-leaf preimage, laid out field by field (no validity checks)."""
    out = (
        CONTROL_TAG
        + lane_bytes(TAIRA, target, taira_network_id)
        + destination_word
        + be32(route_revision)
        + be64(control_nonce)
        + bytes([track])
        + bytes([parliament_paused])
        + be64(fast_pause_until_ms)
        + certificate_id
        + effect_hash
    )
    assert len(out) == CONTROL_PREIMAGE_BYTES
    return out


def control_leaf(
    taira_network_id: bytes,
    target: Profile,
    destination_word: bytes,
    route_revision: int,
    control_nonce: int,
    track: int,
    parliament_paused: int,
    fast_pause_until_ms: int,
    certificate_id: bytes,
    effect_hash: bytes,
    *,
    check: bool = True,
) -> bytes:
    """The §3.4 control leaf; with `check`, Taira's recording rules are enforced first."""
    if check:
        if target is TAIRA:
            raise SccpError("TargetNotExternal")
        if route_revision == 0:
            raise SccpError("ZeroRevision")
        if control_nonce == 0:
            raise SccpError("ZeroControlNonce")
        check_control_constraints(track, parliament_paused, fast_pause_until_ms, certificate_id, effect_hash)
    return keccak256(
        control_leaf_preimage(
            taira_network_id,
            target,
            destination_word,
            route_revision,
            control_nonce,
            track,
            parliament_paused,
            fast_pause_until_ms,
            certificate_id,
            effect_hash,
        )
    )


def control_leaf_ton_builders(preimage: bytes) -> tuple[bytes, bytes]:
    """TON's two `HASHEXT` builders (§3.4): 125 + 74 bytes."""
    assert len(preimage) == CONTROL_PREIMAGE_BYTES
    return preimage[:125], preimage[125:]


def node(left: bytes, right: bytes) -> bytes:
    """`keccak256("SCCP/NODE/V1" ‖ l ‖ r)`."""
    return keccak256(NODE_TAG, left, right)


def tree_levels(leaves: list[bytes]) -> list[list[bytes]]:
    """All levels of the promote-odd tree, leaves first."""
    if not leaves:
        raise ValueError("a tree has at least one leaf")
    levels = [list(leaves)]
    while len(levels[-1]) > 1:
        level = levels[-1]
        nxt = [node(level[i], level[i + 1]) for i in range(0, len(level) - 1, 2)]
        if len(level) % 2:
            nxt.append(level[-1])
        levels.append(nxt)
    return levels


def tree_root(leaves: list[bytes]) -> bytes:
    """Promote-odd root; the root of one leaf is that leaf."""
    return tree_levels(leaves)[-1][0]


def tree_path(leaves: list[bytes], index: int, levels: list[list[bytes]] | None = None) -> list[bytes]:
    """Bottom-up siblings of leaf `index` (promoted levels contribute none); `levels` may be precomputed."""
    if not 0 <= index < len(leaves):
        raise ValueError("index out of range")
    path = []
    for level in (levels or tree_levels(leaves))[:-1]:
        if index % 2:
            path.append(level[index - 1])
        elif index + 1 < len(level):
            path.append(level[index + 1])
        index >>= 1
    return path


def merkle_root(leaf: bytes, index: int, count: int, siblings: list[bytes]) -> bytes:
    """The §3.4 positional verifier; raises `BadProof` on a malformed path."""
    if count < 1 or index >= count or index < 0:
        raise SccpError("BadProof", "index out of range")
    h, k = leaf, 0
    while count > 1:
        if index % 2:
            if k >= len(siblings):
                raise SccpError("BadProof", "path too short")
            h = node(siblings[k], h)
            k += 1
        elif index + 1 < count:
            if k >= len(siblings):
                raise SccpError("BadProof", "path too short")
            h = node(h, siblings[k])
            k += 1
        index >>= 1
        count = (count + 1) >> 1
    if k != len(siblings):
        raise SccpError("BadProof", "path too long")
    return h


def history_leaf(height: int, sccp_root: bytes, message_count: int) -> bytes:
    """`keccak256("SCCP/HISTORY/V1" ‖ u64 height ‖ sccp_root ‖ u32 message_count)`."""
    return keccak256(HISTORY_TAG, be64(height), sccp_root, be32(message_count))


def history_root(leaves: list[bytes]) -> bytes:
    """`history_root(size)` over the given leaves; zero for size 0."""
    return ZERO32 if not leaves else tree_root(leaves)


def history_peaks(leaves: list[bytes]) -> list[bytes]:
    """Perfect-subtree roots of the binary decomposition of `len(leaves)`, largest first."""
    peaks = []
    offset = 0
    size = len(leaves)
    for bit in reversed(range(size.bit_length())):
        width = 1 << bit
        if size & width:
            peaks.append(tree_root(leaves[offset : offset + width]))
            offset += width
    return peaks


def bag_peaks(peaks: list[bytes]) -> bytes:
    """Right-bagging `node(P_a, node(P_b, … node(P_y, P_z)))` (§3.5)."""
    if not peaks:
        return ZERO32
    acc = peaks[-1]
    for peak in reversed(peaks[:-1]):
        acc = node(peak, acc)
    return acc


def check_block_ref(
    ref_height: int,
    ref_sccp_root: bytes,
    ref_message_count: int,
    ref_history_index: int,
    ref_history_path: list[bytes],
    x,
) -> None:
    """§5.1.5 `BlockRefV1` check against a verified header (`BadProof`)."""
    if ref_height == x.height:
        if ref_sccp_root != x.sccp_root or x.sccp_root == ZERO32:
            raise SccpError("BadProof", "block root differs from X")
        if ref_message_count != x.message_count:
            raise SccpError("BadProof", "message count differs from X")
        if ref_history_index != 0 or ref_history_path:
            raise SccpError("BadProof", "same-height reference carries a history path")
        return
    if ref_height > x.height:
        raise SccpError("BadProof", "reference above the certified height")
    if not 1 <= ref_message_count <= MAX_BLOCK_LEAVES or ref_sccp_root == ZERO32:
        raise SccpError("BadProof", "invalid historical block")
    if len(ref_history_path) > MAX_HISTORY_PATH or x.history_size > MAX_HISTORY_SIZE:
        raise SccpError("BadProof", "history path too long")
    root = merkle_root(
        history_leaf(ref_height, ref_sccp_root, ref_message_count), ref_history_index, x.history_size, ref_history_path
    )
    if root != x.history_root:
        raise SccpError("BadProof", "history root mismatch")


def check_leaf(leaf: bytes, leaf_index: int, message_count: int, path: list[bytes], sccp_root: bytes) -> None:
    """Leaf inclusion in a block (path ≤ 9 siblings), `BadProof` otherwise."""
    if len(path) > MAX_BLOCK_PATH:
        raise SccpError("BadProof", "block path too long")
    if merkle_root(leaf, leaf_index, message_count, path) != sccp_root:
        raise SccpError("BadProof", "leaf root mismatch")
