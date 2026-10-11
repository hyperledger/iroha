//! Synthetic TON chain for TON light-client tests (`specs/sccp.md` §4.13.3, §11).
//!
//! [`CellArenaV1`] builds deduplicated TON cells and serializes canonical bags of cells with the
//! verifier's own hashing, [`BitsV1`] writes TL-B bit strings and [`hashmap_edge`] builds
//! `Hashmap`/`HashmapAug` trees. [`SyntheticTonChainV1`] derives Ed25519 validator epochs from a
//! seed and produces masterchain key blocks (with the state proof of configs 34, 28 and 15),
//! signed masterchain blocks registering a basechain shard block, shard blocks linked by
//! predecessor references, and minter transactions emitting `sccp_transfer_to_taira` or
//! `sccp_voided`, so tests drive the production light client end to end.

use std::collections::BTreeMap;

use iroha_crypto::{Algorithm, KeyPair, Signature};
use iroha_data_model::sccp::light_client::SccpLcBootstrapV1;

use crate::{
    light_client::{
        proof::SccpLcBootstrapDataV1,
        ton::{TonKeyBlockHopV1, TonLcBootstrapV1, TonShardLinkV1, TonSignedBlockV1},
    },
    ton_native::{
        TonBlockIdExtV1, TonBlockSignaturesV1, TonBoc, TonBocCell, TonOrdinaryBlockSignaturesV1,
        TonValidatorSignatureV1, TonValidatorV1, encode_canonical_ton_boc, ton_block_id_tl_bytes,
        ton_boc_cell_hashes, ton_validator_list_hash_short_v1, ton_validator_node_id_short_v1,
    },
    v1::hashes::keccak256,
};

/// Masterchain shard id.
pub const MASTER_SHARD: u64 = 0x8000_0000_0000_0000;
/// Catchain session every synthetic block uses.
pub const SYNTHETIC_CATCHAIN_SEQNO: u32 = 7;
/// Validators per synthetic epoch.
pub const SYNTHETIC_VALIDATORS: usize = 5;
/// Config 15 `stake_held_for` of every synthetic epoch (seconds).
pub const SYNTHETIC_STAKE_HELD_FOR: u32 = 32_768;

/// A TL-B bit string under construction.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct BitsV1 {
    bits: Vec<bool>,
}

impl BitsV1 {
    /// Empty bits.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Append one bit.
    pub fn bit(&mut self, bit: bool) -> &mut Self {
        self.bits.push(bit);
        self
    }

    /// Append `value` as `n` big-endian bits.
    pub fn uint(&mut self, value: u128, n: usize) -> &mut Self {
        for index in (0..n).rev() {
            self.bits.push(index < 128 && (value >> index) & 1 == 1);
        }
        self
    }

    /// Append a two's-complement `value` as `n` bits.
    pub fn int(&mut self, value: i64, n: usize) -> &mut Self {
        let raw = u128::from(value.cast_unsigned()) & ((1_u128 << n) - 1);
        self.uint(raw, n)
    }

    /// Append bytes.
    pub fn bytes(&mut self, bytes: &[u8]) -> &mut Self {
        for byte in bytes {
            self.uint(u128::from(*byte), 8);
        }
        self
    }

    /// Append other bits.
    pub fn append(&mut self, other: &Self) -> &mut Self {
        self.bits.extend_from_slice(&other.bits);
        self
    }

    /// Append `Coins` (`VarUInteger 16`).
    pub fn coins(&mut self, value: u128) -> &mut Self {
        let len = usize::try_from((128 - value.leading_zeros()).div_ceil(8)).expect("len");
        self.uint(u128::try_from(len).expect("len"), 4);
        self.uint(value, len * 8)
    }

    /// Append an empty `CurrencyCollection` (zero grams, no extra currencies).
    pub fn zero_currency(&mut self) -> &mut Self {
        self.coins(0).bit(false)
    }

    /// Append `addr_std$10` without anycast.
    pub fn std_address(&mut self, workchain: i8, account: &[u8; 32]) -> &mut Self {
        self.uint(0b10, 2)
            .bit(false)
            .int(i64::from(workchain), 8)
            .bytes(account)
    }

    /// Append a `ShardIdent` of the whole workchain.
    pub fn shard_ident(&mut self, workchain: i32) -> &mut Self {
        self.uint(0, 2)
            .uint(0, 6)
            .int(i64::from(workchain), 32)
            .uint(0, 64)
    }

    /// Number of bits.
    #[must_use]
    pub fn len(&self) -> usize {
        self.bits.len()
    }

    /// Whether no bit was written.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.bits.is_empty()
    }
}

/// Deduplicated TON cells; children are created before their parents.
#[derive(Clone, Debug, Default)]
pub struct CellArenaV1 {
    cells: Vec<TonBocCell>,
    interned: BTreeMap<(u8, u8, Vec<u8>, Vec<usize>), usize>,
}

impl CellArenaV1 {
    /// An empty arena.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    fn insert(&mut self, cell: TonBocCell) -> usize {
        let key = (
            cell.descriptor,
            cell.data_descriptor,
            cell.data.clone(),
            cell.refs.clone(),
        );
        if let Some(index) = self.interned.get(&key) {
            return *index;
        }
        self.cells.push(cell);
        let index = self.cells.len() - 1;
        self.interned.insert(key, index);
        index
    }

    /// An ordinary cell of `bits` and `refs`.
    pub fn cell(&mut self, bits: &BitsV1, refs: &[usize]) -> usize {
        assert!(bits.len() <= 1023 && refs.len() <= 4, "cell too large");
        let full = bits.len() / 8;
        let mut data = vec![0_u8; bits.len().div_ceil(8)];
        for (index, bit) in bits.bits.iter().enumerate() {
            if *bit {
                data[index / 8] |= 0x80 >> (index % 8);
            }
        }
        if !bits.len().is_multiple_of(8) {
            data[full] |= 0x80 >> (bits.len() % 8);
        }
        self.insert(TonBocCell {
            descriptor: u8::try_from(refs.len()).expect("refs"),
            data_descriptor: u8::try_from(full + bits.len().div_ceil(8)).expect("data"),
            data,
            refs: refs.to_vec(),
            exotic: false,
        })
    }

    /// The arena as a `BoC` whose parents precede their children.
    fn reversed(&self) -> (TonBoc, usize) {
        let last = self.cells.len() - 1;
        let cells = self
            .cells
            .iter()
            .rev()
            .map(|cell| TonBocCell {
                refs: cell.refs.iter().map(|child| last - child).collect(),
                ..cell.clone()
            })
            .collect();
        (
            TonBoc {
                roots: vec![0],
                cells,
            },
            last,
        )
    }

    /// Representation hash and depth of cell `index`.
    #[must_use]
    pub fn hash_depth(&self, index: usize) -> ([u8; 32], u16) {
        let (boc, last) = self.reversed();
        let computed = ton_boc_cell_hashes(&boc).expect("valid synthetic cells");
        let cell = &computed[last - index];
        (cell.hashes[0], cell.depths[0])
    }

    /// Representation hash of cell `index`.
    #[must_use]
    pub fn hash(&self, index: usize) -> [u8; 32] {
        self.hash_depth(index).0
    }

    /// A `MERKLE_UPDATE` cell from `old` to `new`.
    pub fn merkle_update(&mut self, old: usize, new: usize) -> usize {
        let (old_hash, old_depth) = self.hash_depth(old);
        let (new_hash, new_depth) = self.hash_depth(new);
        let mut data = vec![4];
        data.extend_from_slice(&old_hash);
        data.extend_from_slice(&new_hash);
        data.extend_from_slice(&old_depth.to_be_bytes());
        data.extend_from_slice(&new_depth.to_be_bytes());
        self.insert(TonBocCell {
            descriptor: 0x0a,
            data_descriptor: u8::try_from(data.len() * 2).expect("data"),
            data,
            refs: vec![old, new],
            exotic: true,
        })
    }

    /// The arena of the cells reachable from `root` (children still before parents) and the
    /// root's index in it.
    fn subgraph(&self, root: usize) -> (Self, usize) {
        fn visit(
            arena: &CellArenaV1,
            index: usize,
            map: &mut BTreeMap<usize, usize>,
            out: &mut CellArenaV1,
        ) -> usize {
            if let Some(mapped) = map.get(&index) {
                return *mapped;
            }
            let cell = arena.cells[index].clone();
            let refs = cell
                .refs
                .iter()
                .map(|child| visit(arena, *child, map, out))
                .collect();
            let mapped = out.insert(TonBocCell { refs, ..cell });
            map.insert(index, mapped);
            mapped
        }
        let mut out = Self::new();
        let root = visit(self, root, &mut BTreeMap::new(), &mut out);
        (out, root)
    }

    /// The canonical `BoC` rooted at `root`.
    #[must_use]
    pub fn boc(&self, root: usize) -> Vec<u8> {
        let (sub, root) = self.subgraph(root);
        let (boc, last) = sub.reversed();
        encode_canonical_ton_boc(&boc, last - root).expect("canonical synthetic BoC")
    }
}

/// A leaf of a synthetic hashmap: inline bits and refs.
#[derive(Clone, Debug, Default)]
pub struct LeafV1 {
    /// Inline bits.
    pub bits: BitsV1,
    /// References.
    pub refs: Vec<usize>,
}

fn label(out: &mut BitsV1, label: &[bool], max: usize) {
    let len_bits = usize::try_from(usize::BITS - max.leading_zeros()).expect("width");
    let short = 2 + 2 * label.len();
    let long = 2 + len_bits + label.len();
    let same = if label
        .iter()
        .all(|bit| *bit == label.first().copied().unwrap_or(false))
    {
        3 + len_bits
    } else {
        usize::MAX
    };
    if short <= long && short <= same {
        out.bit(false);
        for _ in label {
            out.bit(true);
        }
        out.bit(false);
        for bit in label {
            out.bit(*bit);
        }
    } else if long <= same {
        out.uint(0b10, 2)
            .uint(u128::try_from(label.len()).expect("len"), len_bits);
        for bit in label {
            out.bit(*bit);
        }
    } else {
        out.uint(0b11, 2)
            .bit(label.first().copied().unwrap_or(false))
            .uint(u128::try_from(label.len()).expect("len"), len_bits);
    }
}

/// The root edge (inline bits and refs) of a `Hashmap n` (or `HashmapAug n` with fork extra
/// `fork_extra`) over `entries` (keys of `n` bits, ascending), its forks stored as cells.
pub fn hashmap_edge(
    arena: &mut CellArenaV1,
    entries: &[(Vec<bool>, LeafV1)],
    n: usize,
    fork_extra: Option<&BitsV1>,
) -> LeafV1 {
    assert!(!entries.is_empty(), "hashmap edges have entries");
    let first = &entries[0].0;
    let common = (0..n)
        .take_while(|index| entries.iter().all(|(key, _)| key[*index] == first[*index]))
        .count();
    let mut bits = BitsV1::new();
    label(&mut bits, &first[..common], n);
    if common == n {
        let leaf = &entries[0].1;
        bits.append(&leaf.bits);
        return LeafV1 {
            bits,
            refs: leaf.refs.clone(),
        };
    }
    let mut children = Vec::new();
    for side in [false, true] {
        let subset: Vec<(Vec<bool>, LeafV1)> = entries
            .iter()
            .filter(|(key, _)| key[common] == side)
            .map(|(key, leaf)| (key[common + 1..].to_vec(), leaf.clone()))
            .collect();
        let edge = hashmap_edge(arena, &subset, n - common - 1, fork_extra);
        children.push(arena.cell(&edge.bits, &edge.refs));
    }
    if let Some(extra) = fork_extra {
        bits.append(extra);
    }
    LeafV1 {
        bits,
        refs: children,
    }
}

/// Key bits of `value` in `n` bits.
#[must_use]
pub fn key_bits(value: &[u8], n: usize) -> Vec<bool> {
    (0..n)
        .map(|index| value[index / 8] & (0x80 >> (index % 8)) != 0)
        .collect()
}

/// A synthetic validator epoch.
#[derive(Clone)]
pub struct SyntheticEpochV1 {
    keys: Vec<KeyPair>,
    validators: Vec<TonValidatorV1>,
}

impl SyntheticEpochV1 {
    fn new(seed: &[u8; 32], index: u32) -> Self {
        let mut keys = Vec::new();
        let mut validators = Vec::new();
        for position in 0..SYNTHETIC_VALIDATORS {
            let position_byte = u8::try_from(position).expect("small");
            let secret = keccak256(&[
                seed,
                b"ton-validator",
                &index.to_be_bytes(),
                &[position_byte],
            ]);
            let pair = KeyPair::try_from_seed(secret.to_vec(), Algorithm::Ed25519).expect("key");
            let (_, raw) = pair.public_key().try_to_bytes().expect("public key");
            validators.push(TonValidatorV1 {
                public_key: raw.try_into().expect("32 bytes"),
                weight: 10 + u64::from(position_byte),
                adnl_address: [0; 32],
            });
            keys.push(pair);
        }
        Self { keys, validators }
    }

    /// `validator_list_hash_short` of the whole epoch as the masterchain subset.
    #[must_use]
    pub fn list_hash(&self) -> u32 {
        ton_validator_list_hash_short_v1(SYNTHETIC_CATCHAIN_SEQNO, &self.validators).expect("hash")
    }

    /// Ordinary signatures of `block` by the first `signers` validators, in node-id order.
    #[must_use]
    pub fn sign(&self, block: TonBlockIdExtV1, signers: usize) -> TonBlockSignaturesV1 {
        let message = ton_block_id_tl_bytes(block);
        let mut signatures: Vec<TonValidatorSignatureV1> = self
            .keys
            .iter()
            .zip(&self.validators)
            .take(signers)
            .map(|(pair, validator)| TonValidatorSignatureV1 {
                node_id_short: ton_validator_node_id_short_v1(&validator.public_key)
                    .expect("node id"),
                signature: Signature::try_new(pair.private_key(), &message)
                    .expect("signature")
                    .payload()
                    .to_vec(),
            })
            .collect();
        signatures.sort_by_key(|signature| signature.node_id_short);
        TonBlockSignaturesV1::Ordinary(TonOrdinaryBlockSignaturesV1 {
            catchain_seqno: SYNTHETIC_CATCHAIN_SEQNO,
            validator_list_hash_short: self.list_hash(),
            signatures,
        })
    }

    fn config_34(&self, arena: &mut CellArenaV1, since: u32, until: u32) -> usize {
        let entries: Vec<(Vec<bool>, LeafV1)> = self
            .validators
            .iter()
            .enumerate()
            .map(|(index, validator)| {
                let mut bits = BitsV1::new();
                bits.uint(0x53, 8)
                    .uint(0x8e81_278a, 32)
                    .bytes(&validator.public_key)
                    .uint(u128::from(validator.weight), 64);
                (
                    key_bits(&u16::try_from(index).expect("small").to_be_bytes(), 16),
                    LeafV1 {
                        bits,
                        refs: Vec::new(),
                    },
                )
            })
            .collect();
        let list = hashmap_edge(arena, &entries, 16, None);
        let mut bits = BitsV1::new();
        bits.uint(0x11, 8)
            .uint(u128::from(since), 32)
            .uint(u128::from(until), 32)
            .uint(u128::try_from(SYNTHETIC_VALIDATORS).expect("small"), 16)
            .uint(u128::try_from(SYNTHETIC_VALIDATORS).expect("small"), 16)
            .append(&list.bits);
        arena.cell(&bits, &list.refs)
    }
}

/// One synthetic key block: the signed block and its config proof.
pub struct SyntheticKeyBlockV1 {
    /// Hop frame.
    pub hop: TonKeyBlockHopV1,
    /// Generation time (seconds).
    pub gen_utime: u32,
}

/// What a synthetic minter transaction emits.
#[derive(Clone, Debug)]
pub enum SyntheticTonEventV1 {
    /// `sccp_transfer_to_taira`.
    Transfer {
        /// Message id.
        message_id: [u8; 32],
        /// Nonce.
        nonce: u64,
        /// Burning owner.
        sender: [u8; 32],
        /// Amount.
        amount: u128,
        /// Payload bytes.
        payload: Vec<u8>,
    },
    /// `sccp_voided`.
    Voided {
        /// Message id (zero for frozen).
        message_id: [u8; 32],
        /// First nonce.
        first_nonce: u64,
        /// Count.
        count: u16,
    },
}

/// A synthetic shard block with its header proof and, when it carries the minter transaction,
/// the transaction `BoC`.
pub struct SyntheticShardBlockV1 {
    /// Link frame (id and header proof).
    pub link: TonShardLinkV1,
    /// Transaction `BoC`, when the block carries one.
    pub transaction: Option<Vec<u8>>,
}

/// Deterministic synthetic TON chain.
#[derive(Clone, Copy)]
pub struct SyntheticTonChainV1 {
    seed: [u8; 32],
}

fn ext_blk_ref(arena: &mut CellArenaV1, block: &TonBlockIdExtV1) -> usize {
    let mut bits = BitsV1::new();
    bits.uint(u128::from(block.seqno) * 1_000 + 1, 64)
        .uint(u128::from(block.seqno), 32)
        .bytes(&block.root_hash)
        .bytes(&block.file_hash);
    arena.cell(&bits, &[])
}

impl SyntheticTonChainV1 {
    /// A chain derived from `seed`.
    #[must_use]
    pub fn new(seed: [u8; 32]) -> Self {
        Self { seed }
    }

    /// Validator epoch `index`.
    #[must_use]
    pub fn epoch(&self, index: u32) -> SyntheticEpochV1 {
        SyntheticEpochV1::new(&self.seed, index)
    }

    fn file_hash(&self, root: &[u8; 32]) -> [u8; 32] {
        keccak256(&[&self.seed, b"file", root])
    }

    #[expect(clippy::too_many_arguments, reason = "block info fields")]
    fn block_info(
        arena: &mut CellArenaV1,
        master: bool,
        key_block: bool,
        seqno: u32,
        gen_utime: u32,
        prev_key_block_seqno: u32,
        list_hash: u32,
        previous: &TonBlockIdExtV1,
        master_ref: Option<&TonBlockIdExtV1>,
    ) -> usize {
        let previous = ext_blk_ref(arena, previous);
        let mut refs = Vec::new();
        if let Some(master_ref) = master_ref {
            refs.push(ext_blk_ref(arena, master_ref));
        }
        refs.push(previous);
        let mut bits = BitsV1::new();
        bits.uint(0x9bc7_a987, 32)
            .uint(0, 32)
            .bit(!master)
            .bit(false)
            .bit(false)
            .bit(false)
            .bit(false)
            .bit(false)
            .bit(key_block)
            .bit(false)
            .uint(0, 8)
            .uint(u128::from(seqno), 32)
            .uint(0, 32)
            .shard_ident(if master { -1 } else { 0 })
            .uint(u128::from(gen_utime), 32)
            .uint(u128::from(seqno) * 1_000, 64)
            .uint(u128::from(seqno) * 1_000 + 1, 64)
            .uint(u128::from(list_hash), 32)
            .uint(u128::from(SYNTHETIC_CATCHAIN_SEQNO), 32)
            .uint(1, 32)
            .uint(u128::from(prev_key_block_seqno), 32);
        arena.cell(&bits, &refs)
    }

    fn block(arena: &mut CellArenaV1, info: usize, new_state: usize, extra: usize) -> usize {
        let empty = arena.cell(&BitsV1::new(), &[]);
        let update = arena.merkle_update(empty, new_state);
        let mut bits = BitsV1::new();
        bits.uint(0x11ef_55aa, 32).int(-239, 32);
        arena.cell(&bits, &[info, empty, update, extra])
    }

    fn block_extra(arena: &mut CellArenaV1, account_blocks: usize, custom: Option<usize>) -> usize {
        let empty = arena.cell(&BitsV1::new(), &[]);
        let mut bits = BitsV1::new();
        bits.uint(0x4a33_f6fd, 32).uint(0, 256).uint(0, 256);
        let mut refs = vec![empty, empty, account_blocks];
        match custom {
            Some(custom) => {
                bits.bit(true);
                refs.push(custom);
            }
            None => {
                bits.bit(false);
            }
        }
        arena.cell(&bits, &refs)
    }

    fn empty_account_blocks(arena: &mut CellArenaV1) -> usize {
        let mut bits = BitsV1::new();
        bits.bit(false).zero_currency();
        arena.cell(&bits, &[])
    }

    /// Masterchain state whose config holds epoch `epoch`'s validators (valid `since..until`)
    /// and, when given, `prev_blocks` entries `(seqno, root, file)`.
    fn masterchain_state(
        &self,
        arena: &mut CellArenaV1,
        epoch: u32,
        since: u32,
        until: u32,
        prev_blocks: &[TonBlockIdExtV1],
    ) -> usize {
        let validators = self.epoch(epoch).config_34(arena, since, until);
        let mut catchain = BitsV1::new();
        catchain
            .uint(0xc1, 8)
            .uint(1_000, 32)
            .uint(1_000, 32)
            .uint(1_000, 32)
            .uint(7, 32);
        let catchain = arena.cell(&catchain, &[]);
        let mut timings = BitsV1::new();
        timings
            .uint(65_536, 32)
            .uint(32_768, 32)
            .uint(8_192, 32)
            .uint(u128::from(SYNTHETIC_STAKE_HELD_FOR), 32);
        let timings = arena.cell(&timings, &[]);
        let entries: Vec<(Vec<bool>, LeafV1)> =
            [(15_u32, timings), (28, catchain), (34, validators)]
                .into_iter()
                .map(|(key, value)| {
                    (
                        key_bits(&key.to_be_bytes(), 32),
                        LeafV1 {
                            bits: BitsV1::new(),
                            refs: vec![value],
                        },
                    )
                })
                .collect();
        let config = hashmap_edge(arena, &entries, 32, None);
        let config = arena.cell(&config.bits, &config.refs);
        let mut auxiliary = BitsV1::new();
        auxiliary.uint(0, 16).uint(0, 65);
        let mut auxiliary_refs = Vec::new();
        if prev_blocks.is_empty() {
            auxiliary.bit(false);
        } else {
            let entries: Vec<(Vec<bool>, LeafV1)> = prev_blocks
                .iter()
                .map(|block| {
                    let mut bits = BitsV1::new();
                    bits.bit(false)
                        .uint(u128::from(block.seqno) * 1_000 + 1, 64)
                        .bit(false)
                        .uint(u128::from(block.seqno) * 1_000 + 1, 64)
                        .uint(u128::from(block.seqno), 32)
                        .bytes(&block.root_hash)
                        .bytes(&block.file_hash);
                    (
                        key_bits(&block.seqno.to_be_bytes(), 32),
                        LeafV1 {
                            bits,
                            refs: Vec::new(),
                        },
                    )
                })
                .collect();
            let mut fork_extra = BitsV1::new();
            fork_extra.bit(false).uint(1, 64);
            let root = hashmap_edge(arena, &entries, 32, Some(&fork_extra));
            let root = arena.cell(&root.bits, &root.refs);
            auxiliary.bit(true).bit(false).uint(1, 64);
            auxiliary_refs.push(root);
        }
        auxiliary.bit(false).bit(false);
        let auxiliary = arena.cell(&auxiliary, &auxiliary_refs);
        let mut custom = BitsV1::new();
        custom.uint(0xcc26, 16).bit(false).uint(0, 256);
        custom.zero_currency();
        let custom = arena.cell(&custom, &[config, auxiliary]);
        let empty = arena.cell(&BitsV1::new(), &[]);
        let mut state = BitsV1::new();
        state
            .uint(0x9023_afe2, 32)
            .int(-239, 32)
            .shard_ident(-1)
            .uint(1, 32)
            .uint(0, 32)
            .uint(u128::from(since), 32)
            .uint(1, 64)
            .uint(1, 32)
            .bit(false)
            .bit(true);
        arena.cell(&state, &[empty, empty, empty, custom])
    }

    /// Masterchain block id of `root` with the synthetic file hash.
    fn master_id(&self, seqno: u32, root: [u8; 32]) -> TonBlockIdExtV1 {
        TonBlockIdExtV1 {
            workchain: -1,
            shard: MASTER_SHARD,
            seqno,
            root_hash: root,
            file_hash: self.file_hash(&root),
        }
    }

    fn previous_master(&self, seqno: u32) -> TonBlockIdExtV1 {
        self.master_id(
            seqno - 1,
            keccak256(&[&self.seed, b"prev-master", &seqno.to_be_bytes()]),
        )
    }

    /// Key block `seqno` whose validators are epoch `new_epoch` (valid `since..until`),
    /// following key block `prev_key` and signed by the first `signers` validators of epoch
    /// `signing_epoch`.
    #[must_use]
    #[expect(clippy::too_many_arguments, reason = "synthetic key-block knobs")]
    pub fn key_block(
        &self,
        seqno: u32,
        prev_key: u32,
        signing_epoch: u32,
        new_epoch: u32,
        gen_utime: u32,
        until: u32,
        signers: usize,
    ) -> SyntheticKeyBlockV1 {
        let mut arena = CellArenaV1::new();
        let state = self.masterchain_state(&mut arena, new_epoch, gen_utime, until, &[]);
        let list_hash = self.epoch(signing_epoch).list_hash();
        let info = Self::block_info(
            &mut arena,
            true,
            true,
            seqno,
            gen_utime,
            prev_key,
            list_hash,
            &self.previous_master(seqno),
            None,
        );
        let account_blocks = Self::empty_account_blocks(&mut arena);
        let extra = Self::block_extra(&mut arena, account_blocks, None);
        let root = Self::block(&mut arena, info, state, extra);
        let block_id = self.master_id(seqno, arena.hash(root));
        SyntheticKeyBlockV1 {
            hop: TonKeyBlockHopV1 {
                block: TonSignedBlockV1 {
                    block_id,
                    header_proof: arena.boc(root),
                    signatures: self.epoch(signing_epoch).sign(block_id, signers),
                },
                config_proof: arena.boc(state),
            },
            gen_utime,
        }
    }

    /// The bootstrap of key block `seqno` with epoch `epoch`.
    #[must_use]
    pub fn bootstrap(
        &self,
        seqno: u32,
        epoch: u32,
        gen_utime: u32,
        until: u32,
    ) -> SccpLcBootstrapV1 {
        let key = self.key_block(seqno, seqno - 10, epoch, epoch, gen_utime, until, 0);
        SccpLcBootstrapDataV1::Ton(TonLcBootstrapV1 {
            block_id: key.hop.block.block_id,
            header_proof: key.hop.block.header_proof,
            config_proof: key.hop.config_proof,
        })
        .to_bootstrap()
        .expect("synthetic bootstrap")
    }

    /// A masterchain block `seqno` naming key block `prev_key`, signed by the first `signers`
    /// of epoch `signing_epoch`, whose shard hashes register `shard` for workchain 0 and whose
    /// state lists `prev_blocks`. Returns the signed block and its state proof.
    #[must_use]
    #[expect(clippy::too_many_arguments, reason = "synthetic block knobs")]
    pub fn master_block(
        &self,
        seqno: u32,
        prev_key: u32,
        signing_epoch: u32,
        gen_utime: u32,
        shard: &TonBlockIdExtV1,
        prev_blocks: &[TonBlockIdExtV1],
        signers: usize,
    ) -> (TonSignedBlockV1, Vec<u8>) {
        let mut arena = CellArenaV1::new();
        let state = self.masterchain_state(
            &mut arena,
            signing_epoch,
            gen_utime,
            gen_utime + 1,
            prev_blocks,
        );
        let mut descriptor = BitsV1::new();
        descriptor
            .bit(false)
            .uint(0xb, 4)
            .uint(u128::from(shard.seqno), 32)
            .uint(u128::from(seqno), 32)
            .uint(u128::from(shard.seqno) * 1_000, 64)
            .uint(u128::from(shard.seqno) * 1_000 + 1, 64)
            .bytes(&shard.root_hash)
            .bytes(&shard.file_hash);
        let descriptor = arena.cell(&descriptor, &[]);
        let shards = hashmap_edge(
            &mut arena,
            &[(
                key_bits(&0_i32.to_be_bytes(), 32),
                LeafV1 {
                    bits: BitsV1::new(),
                    refs: vec![descriptor],
                },
            )],
            32,
            None,
        );
        let shards = arena.cell(&shards.bits, &shards.refs);
        let empty = arena.cell(&BitsV1::new(), &[]);
        let mut custom = BitsV1::new();
        custom.uint(0xcca5, 16).bit(false).bit(true).bit(false);
        custom.zero_currency().zero_currency();
        let custom = arena.cell(&custom, &[shards, empty]);
        let list_hash = self.epoch(signing_epoch).list_hash();
        let info = Self::block_info(
            &mut arena,
            true,
            false,
            seqno,
            gen_utime,
            prev_key,
            list_hash,
            &self.previous_master(seqno),
            None,
        );
        let account_blocks = Self::empty_account_blocks(&mut arena);
        let extra = Self::block_extra(&mut arena, account_blocks, Some(custom));
        let root = Self::block(&mut arena, info, state, extra);
        let block_id = self.master_id(seqno, arena.hash(root));
        (
            TonSignedBlockV1 {
                block_id,
                header_proof: arena.boc(root),
                signatures: self.epoch(signing_epoch).sign(block_id, signers),
            },
            arena.boc(state),
        )
    }

    /// The external-out message body of `event`; a transfer's payload rides in a chain of
    /// 127-byte cells referenced from the body.
    fn event_body(arena: &mut CellArenaV1, event: &SyntheticTonEventV1) -> usize {
        let mut body = BitsV1::new();
        let mut body_refs = Vec::new();
        match event {
            SyntheticTonEventV1::Transfer {
                message_id,
                nonce,
                sender,
                amount,
                payload,
            } => {
                let mut chunks: Vec<&[u8]> = payload.chunks(127).collect();
                let mut next: Option<usize> = None;
                while let Some(chunk) = chunks.pop() {
                    let mut bits = BitsV1::new();
                    bits.bytes(chunk);
                    let refs: Vec<usize> = next.into_iter().collect();
                    next = Some(arena.cell(&bits, &refs));
                }
                body.uint(0x5343_5454, 32)
                    .bytes(message_id)
                    .uint(u128::from(*nonce), 64)
                    .std_address(0, sender)
                    .coins(*amount);
                body_refs.push(next.expect("nonempty payload"));
            }
            SyntheticTonEventV1::Voided {
                message_id,
                first_nonce,
                count,
            } => {
                body.uint(0x5343_564f, 32)
                    .bytes(message_id)
                    .uint(u128::from(*first_nonce), 64)
                    .uint(u128::from(*count), 16);
            }
        }
        arena.cell(&body, &body_refs)
    }

    /// The canonical `BoC` of `event`'s external-out message body.
    #[must_use]
    pub fn event_body_boc(event: &SyntheticTonEventV1) -> Vec<u8> {
        let mut arena = CellArenaV1::new();
        let body = Self::event_body(&mut arena, event);
        arena.boc(body)
    }

    fn transaction(
        arena: &mut CellArenaV1,
        minter: &[u8; 32],
        lt: u64,
        event: &SyntheticTonEventV1,
        succeed: bool,
    ) -> usize {
        let body = Self::event_body(arena, event);
        let mut message = BitsV1::new();
        message
            .uint(0b11, 2)
            .std_address(0, minter)
            .uint(0, 2)
            .uint(u128::from(lt), 64)
            .uint(1, 32)
            .bit(false)
            .bit(true);
        let message = arena.cell(&message, &[body]);
        let out_messages = hashmap_edge(
            arena,
            &[(
                key_bits(&0_u16.to_be_bytes(), 15),
                LeafV1 {
                    bits: BitsV1::new(),
                    refs: vec![message],
                },
            )],
            15,
            None,
        );
        let out_messages = arena.cell(&out_messages.bits, &out_messages.refs);
        let mut auxiliary = BitsV1::new();
        auxiliary.bit(false).bit(true);
        let auxiliary = arena.cell(&auxiliary, &[out_messages]);
        let mut update = BitsV1::new();
        update.uint(0x72, 8).uint(1, 256).uint(2, 256);
        let update = arena.cell(&update, &[]);
        let mut details = BitsV1::new();
        details
            .uint(1, 3)
            .uint(100, 8)
            .uint(1, 3)
            .uint(200, 8)
            .bit(false)
            .int(0, 8)
            .int(if succeed { 0 } else { 35 }, 32)
            .bit(false)
            .uint(10, 32)
            .uint(0, 256)
            .uint(0, 256);
        let details = arena.cell(&details, &[]);
        let mut action = BitsV1::new();
        action
            .bit(true)
            .bit(true)
            .bit(false)
            .bit(false)
            .bit(false)
            .bit(false)
            .int(0, 32)
            .bit(false)
            .uint(1, 16)
            .uint(0, 16)
            .uint(0, 16)
            .uint(1, 16)
            .uint(0, 256)
            .uint(0, 3)
            .uint(0, 3);
        let action = arena.cell(&action, &[]);
        let mut description = BitsV1::new();
        description
            .uint(0, 4)
            .bit(false)
            .bit(false)
            .bit(false)
            .bit(true)
            .bit(succeed)
            .bit(false)
            .bit(false)
            .coins(0)
            .bit(true)
            .bit(false)
            .bit(false)
            .bit(false);
        let description = arena.cell(&description, &[details, action]);
        let mut transaction = BitsV1::new();
        transaction
            .uint(7, 4)
            .bytes(minter)
            .uint(u128::from(lt), 64)
            .uint(0, 256)
            .uint(u128::from(lt - 1), 64)
            .uint(1, 32)
            .uint(1, 15)
            .uint(2, 2)
            .uint(2, 2)
            .zero_currency();
        arena.cell(&transaction, &[auxiliary, update, description])
    }

    /// Basechain shard block `seqno` preceded by `previous`, referencing masterchain block
    /// `master_ref`; with `event`, it carries the minter's transaction at `lt`.
    #[must_use]
    pub fn shard_block(
        &self,
        seqno: u32,
        previous: &TonBlockIdExtV1,
        master_ref: &TonBlockIdExtV1,
        minter: &[u8; 32],
        event: Option<&(u64, SyntheticTonEventV1, bool)>,
    ) -> SyntheticShardBlockV1 {
        let mut arena = CellArenaV1::new();
        let mut transaction_boc = None;
        let account_blocks = match event {
            None => Self::empty_account_blocks(&mut arena),
            Some((lt, event, succeed)) => {
                let transaction = Self::transaction(&mut arena, minter, *lt, event, *succeed);
                transaction_boc = Some(arena.boc(transaction));
                let mut tx_leaf = BitsV1::new();
                tx_leaf.zero_currency();
                let transactions = hashmap_edge(
                    &mut arena,
                    &[(
                        key_bits(&lt.to_be_bytes(), 64),
                        LeafV1 {
                            bits: tx_leaf,
                            refs: vec![transaction],
                        },
                    )],
                    64,
                    None,
                );
                let empty = arena.cell(&BitsV1::new(), &[]);
                let mut account_block = BitsV1::new();
                account_block
                    .zero_currency()
                    .uint(5, 4)
                    .bytes(minter)
                    .append(&transactions.bits);
                let mut refs = transactions.refs.clone();
                refs.push(empty);
                let root = hashmap_edge(
                    &mut arena,
                    &[(
                        key_bits(minter, 256),
                        LeafV1 {
                            bits: account_block,
                            refs,
                        },
                    )],
                    256,
                    None,
                );
                let root = arena.cell(&root.bits, &root.refs);
                let mut wrapper = BitsV1::new();
                wrapper.bit(true).zero_currency();
                arena.cell(&wrapper, &[root])
            }
        };
        let info = Self::block_info(
            &mut arena,
            false,
            false,
            seqno,
            1,
            0,
            0,
            previous,
            Some(master_ref),
        );
        let extra = Self::block_extra(&mut arena, account_blocks, None);
        let empty = arena.cell(&BitsV1::new(), &[]);
        let root = Self::block(&mut arena, info, empty, extra);
        let root_hash = arena.hash(root);
        SyntheticShardBlockV1 {
            link: TonShardLinkV1 {
                block_id: TonBlockIdExtV1 {
                    workchain: 0,
                    shard: MASTER_SHARD,
                    seqno,
                    root_hash,
                    file_hash: self.file_hash(&root_hash),
                },
                header_proof: arena.boc(root),
            },
            transaction: transaction_boc,
        }
    }

    /// A shard block id not present in any synthetic chain (a walk's end).
    #[must_use]
    pub fn genesis_shard(&self) -> TonBlockIdExtV1 {
        let root = keccak256(&[&self.seed, b"genesis-shard"]);
        TonBlockIdExtV1 {
            workchain: 0,
            shard: MASTER_SHARD,
            seqno: 1,
            root_hash: root,
            file_hash: self.file_hash(&root),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn labels_pick_a_valid_shortest_form() {
        let mut short = BitsV1::new();
        label(&mut short, &[true, false], 32);
        assert_eq!(short.len(), 6);
        let mut long = BitsV1::new();
        label(
            &mut long,
            &[true, false, true, true, false, false, true, false, true],
            32,
        );
        assert_eq!(long.len(), 2 + 6 + 9);
        let mut same = BitsV1::new();
        label(&mut same, &[false; 20], 32);
        assert_eq!(same.len(), 3 + 6);
    }

    #[test]
    fn arenas_deduplicate_and_serialize_canonically() {
        let mut arena = CellArenaV1::new();
        let mut bits = BitsV1::new();
        bits.uint(0xabc, 12);
        let a = arena.cell(&bits, &[]);
        let b = arena.cell(&bits, &[]);
        assert_eq!(a, b);
        let parent = arena.cell(&BitsV1::new(), &[a, a]);
        let boc = arena.boc(parent);
        assert_eq!(
            crate::ton_native::ton_canonical_boc_single_root_hash_v1(&boc),
            Some(arena.hash(parent))
        );
    }
}
