"""A deterministic Taira-side producer of finality headers and certificates for fixtures.

This is not a Taira implementation: it only produces the contract-visible
artefacts a destination consumes (§3.4–§3.8) with the generation bookkeeping of
§4.2.2 (G2: a rotation at `h` starts generation `g + 1` at `h + 1` with
`deadline_ms = t(h) + validity_ms`), so that the destination model can be
driven through realistic sequences. Test keys follow §11.3:
`sk_i = KeyGen(IKM = SHA-256("sccp-finality-test-ikm" ‖ u8 i))`.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from functools import lru_cache

from .bls_sig import keygen, sk_to_pk
from .common import be64, h_iroha, rep, sha256
from .destination import BlockRef, ControlProof, MessageProof
from .finality import (
    FLAG_ACTIVE,
    FLAG_ROTATION,
    ZERO32,
    Certificate,
    FinalityHeader,
    body_digest,
    build_certificate,
    canonical_order,
    committee_root,
    quorum,
)
from .merkle import control_leaf, history_leaf, history_root, transfer_leaf, tree_path, tree_root
from .payload import TAIRA, Profile, message_id, outbound_payload

TEST_IKM_TAG = b"sccp-finality-test-ikm"


@lru_cache(maxsize=None)
def test_secret(index: int) -> int:
    """§11.3 test key `sk_i`."""
    return keygen(sha256(TEST_IKM_TAG, bytes([index])))


@lru_cache(maxsize=None)
def test_public(index: int) -> bytes:
    return sk_to_pk(test_secret(index))


@dataclass
class Committee:
    """A canonical committee built from test key indices."""

    name: str
    indices: tuple[int, ...]

    @property
    def keys(self) -> list[bytes]:
        return canonical_order([test_public(i) for i in self.indices])

    @property
    def root(self) -> bytes:
        return committee_root(self.keys)

    @property
    def secret_of(self) -> dict[bytes, int]:
        return {test_public(i): test_secret(i) for i in self.indices}

    @property
    def n(self) -> int:
        return len(self.indices)

    def key_index_map(self) -> list[int]:
        """Test key index at each canonical position."""
        by_pk = {test_public(i): i for i in self.indices}
        return [by_pk[k] for k in self.keys]

    def as_json(self) -> dict:
        return {
            "n": self.n,
            "q": quorum(self.n),
            "test_key_indices": self.key_index_map(),
            "keys": ["0x" + k.hex() for k in self.keys],
            "root": "0x" + self.root.hex(),
        }


@dataclass
class Generation:
    generation: int
    committee: Committee
    start_height: int
    start_timestamp_ms: int
    validity_ms: int

    @property
    def deadline_ms(self) -> int:
        return self.start_timestamp_ms + self.validity_ms


@dataclass
class LeafItem:
    """One SCCP message of a block: a transfer payload or a control."""

    kind: str
    leaf: bytes
    payload: bytes | None = None
    nonce: int | None = None
    control: dict | None = None


@dataclass
class Block:
    height: int
    timestamp_ms: int
    header: FinalityHeader
    generation: Generation
    leaves: list[LeafItem] = field(default_factory=list)
    history_index: int | None = None

    @property
    def x(self) -> bytes:
        return self.header.encode()


class TairaSim:
    """Produces headers, certificates and proofs for one destination route."""

    def __init__(
        self,
        network_id: bytes,
        instance: bytes,
        target: Profile,
        destination_word: bytes,
        route_revision: int = 1,
    ):
        self.network_id = network_id
        self.instance = instance
        self.target = target
        self.destination_word = destination_word
        self.route_revision = route_revision
        self.generations: dict[int, Generation] = {}
        self.current: Generation | None = None
        self.history: list[bytes] = []
        self.blocks: dict[int, Block] = {}

    def start(self, generation: int, committee: Committee, start_height: int, start_ts: int, validity_ms: int) -> Generation:
        gen = Generation(generation, committee, start_height, start_ts, validity_ms)
        self.generations[generation] = gen
        self.current = gen
        return gen

    # -- leaves ----------------------------------------------------------------

    def transfer(
        self, nonce: int, amount: int, deadline_ms: int, recipient: bytes, sender: bytes = b"\x01" + rep(0x5A, 33)
    ) -> LeafItem:
        payload = outbound_payload(self.target, nonce, self.route_revision, deadline_ms, amount, sender, recipient)
        mid = message_id(TAIRA, self.target, self.network_id, payload)
        return LeafItem("transfer", transfer_leaf(mid, self.destination_word), payload=payload, nonce=nonce)

    def control(
        self,
        control_nonce: int,
        track: int,
        parliament_paused: int,
        fast_pause_until_ms: int,
        certificate_id: bytes,
        effect_hash: bytes,
        *,
        check: bool = True,
    ) -> LeafItem:
        fields = {
            "control_nonce": control_nonce,
            "track": track,
            "parliament_paused": parliament_paused,
            "fast_pause_until_ms": fast_pause_until_ms,
            "certificate_id": certificate_id,
            "effect_hash": effect_hash,
        }
        leaf = control_leaf(
            self.network_id,
            self.target,
            self.destination_word,
            self.route_revision,
            control_nonce,
            track,
            parliament_paused,
            fast_pause_until_ms,
            certificate_id,
            effect_hash,
            check=check,
        )
        return LeafItem("control", leaf, control=fields)

    # -- blocks --------------------------------------------------------------

    def block(
        self,
        height: int,
        timestamp_ms: int,
        leaves: list[LeafItem] | None = None,
        *,
        rotate: str | None = None,
        next_committee: Committee | None = None,
        validity_ms: int | None = None,
    ) -> Block:
        """Produce `X_h`; `rotate` is `"key"` or `"heartbeat"` (rule G2).

        Controls precede transfers, as the block-start pass runs before the
        block's transactions (§4.5).
        """
        gen = self.current
        leaves = leaves or []
        kinds = [item.kind for item in leaves]
        if "transfer" in kinds and "control" in kinds[kinds.index("transfer") :]:
            raise ValueError("control leaves precede transfer leaves in a block")
        count = len(leaves)
        root = tree_root([item.leaf for item in leaves]) if count else ZERO32
        history_index = None
        if count:
            history_index = len(self.history)
            self.history.append(history_leaf(height, root, count))
        flags = FLAG_ACTIVE
        validity = 0
        next_root = ZERO32
        if rotate:
            flags |= FLAG_ROTATION
            successor = gen.committee if rotate == "heartbeat" else next_committee
            validity = gen.validity_ms if validity_ms is None else validity_ms
            next_root = successor.root
        header = FinalityHeader(
            network_id=self.network_id,
            height=height,
            timestamp_ms=timestamp_ms,
            flags=flags,
            message_count=count,
            sccp_root=root,
            history_size=len(self.history),
            history_root=history_root(self.history),
            generation=gen.generation,
            committee_root=gen.committee.root,
            validity_ms=validity,
            next_committee_root=next_root,
        )
        block = Block(height, timestamp_ms, header, gen, leaves, history_index)
        self.blocks[height] = block
        if rotate:
            self.start(gen.generation + 1, successor, height + 1, timestamp_ms, validity)
        return block

    # -- certificates --------------------------------------------------------

    def qc_fields(self, height: int, header: bytes, body_tag: bytes = b"") -> dict:
        """Deterministic `QC_FIXED` inputs that destinations take unverified."""
        epoch = height // 100
        return {
            "epoch": epoch,
            "epoch_context": h_iroha(b"sccp-reference/epoch-context", be64(epoch)),
            "view": 0,
            "block_hash": h_iroha(b"sccp-reference/block", be64(height), header),
            "result_body": body_digest(b"sccp-reference/result-body" + be64(height) + body_tag),
        }

    def certify(
        self,
        header: FinalityHeader | bytes,
        committee: Committee,
        *,
        signer_indices: list[int] | None = None,
        body_tag: bytes = b"",
        **overrides,
    ) -> Certificate:
        """Sign `header` with the lowest `q` (or the given) canonical indices of `committee`."""
        x = header if isinstance(header, bytes) else header.encode()
        height = int.from_bytes(x[48:56], "big")
        fields = self.qc_fields(height, x, body_tag)
        fields.update({k: overrides.pop(k) for k in list(overrides) if k in fields})
        indices = list(range(quorum(committee.n))) if signer_indices is None else signer_indices
        return build_certificate(
            keys=committee.keys,
            secret_of=committee.secret_of,
            signer_indices=indices,
            header=x,
            instance=self.instance,
            **fields,
            **overrides,
        )

    # -- proofs --------------------------------------------------------------

    def block_ref(self, target_height: int, certified: FinalityHeader) -> BlockRef:
        block = self.blocks[target_height]
        if target_height == certified.height:
            return BlockRef(target_height, block.header.sccp_root, block.header.message_count)
        leaves = self.history[: certified.history_size]
        return BlockRef(
            target_height,
            block.header.sccp_root,
            block.header.message_count,
            block.history_index,
            tree_path(leaves, block.history_index),
        )

    def message_proof(self, target_height: int, leaf_index: int, certified: FinalityHeader) -> MessageProof:
        block = self.blocks[target_height]
        item = block.leaves[leaf_index]
        assert item.kind == "transfer"
        return MessageProof(
            item.payload,
            leaf_index,
            tree_path([i.leaf for i in block.leaves], leaf_index),
            self.block_ref(target_height, certified),
        )

    def control_proof(self, target_height: int, leaf_index: int, certified: FinalityHeader) -> ControlProof:
        block = self.blocks[target_height]
        item = block.leaves[leaf_index]
        assert item.kind == "control"
        c = item.control
        return ControlProof(
            c["control_nonce"],
            c["track"],
            c["parliament_paused"],
            c["fast_pause_until_ms"],
            c["certificate_id"],
            c["effect_hash"],
            leaf_index,
            tree_path([i.leaf for i in block.leaves], leaf_index),
            self.block_ref(target_height, certified),
        )
