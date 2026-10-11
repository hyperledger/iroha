//! SCCP v1 TON cells (spec §5.3.1, §5.3.2).
//!
//! A minimal ordinary-cell builder with TON representation hashes and depths, the standard
//! `SnakeBytes` format, the chunked `MemberChunk` and `HashChunk` lists, the canonical initial
//! data of the SCCP Jetton master (minter) and the workchain-0 `StateInit` addresses of the
//! minter, its wallets and its consumption buckets.
//!
//! A cell's representation hash depends on its children only through their hashes and depths,
//! so contract code is referenced by `(hash, depth)` alone ([`CellRef::opaque`]) and Taira can
//! recompute a deployment address from the registered code references (§4.14.3).
//!
//! [`Cell::to_boc`] serializes a complete cell tree as a single-root bag of cells (message
//! bodies, `StateInit`s and external messages) and [`cell_from_boc`] reads one back (contract
//! code artifacts).
//!
//! The storage-rent constants mirror `contracts/ton/sccp/contracts/sccp-fees.tolk` (§5.3.5; a
//! unit test compares them), so tooling can fund a minter deployment before the minter's own
//! `minter_floor()` get method exists.
//!
//! TODO(ws3A): deduplicate the cell hashing with the `BoC` cell hashing of `crate::ton_native`.

use std::sync::Arc;

use iroha_data_model::sccp::deployment::SccpTonCodeRefV1;
use sha2::{Digest as _, Sha256};

use super::{
    constants::{TON_HASH_CHUNK_HASHES, TON_MEMBER_CHUNK_ADDRESSES, TON_SNAKE_CHUNK_BYTES},
    roster::RosterV1,
};

/// Maximum data bits of one cell.
pub const MAX_CELL_BITS: usize = 1023;
/// Maximum references of one cell.
pub const MAX_CELL_REFS: usize = 4;
/// Exclusive bound of a TON `Coins` value (`VarUInteger 16`: at most 15 value bytes).
pub const COINS_BOUND: u128 = 1 << 120;

unit_error! {
    /// TON cell construction and parsing errors.
    pub enum TonCellError {
        /// The cell would exceed 1023 data bits.
        BitOverflow => "a TON cell holds at most 1023 data bits",
        /// The cell would exceed 4 references.
        RefOverflow => "a TON cell holds at most 4 references",
        /// An unsigned value does not fit its bit width, or the width exceeds 128.
        ValueTooWide => "value does not fit the requested bit width",
        /// A `Coins` value is `2^120` or more.
        CoinsTooLarge => "TON Coins values must be below 2^120",
        /// A snake or chunk list would be empty.
        Empty => "snake bytes and chunk lists must not be empty",
        /// A snake cell has a shape other than the canonical one.
        BadSnake => "cell is not canonical SnakeBytes",
        /// Snake content exceeds the caller's bound.
        SnakeTooLong => "snake content exceeds the length bound",
        /// A child cell is known only by its hash and depth.
        OpaqueChild => "cell child is known only by hash and depth",
        /// The roster fields violate §3.7.
        BadRoster => "minter roster violates the roster rules",
    }
}

/// A reference to a child cell: its representation hash and depth, plus the cell when known.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CellRef {
    hash: [u8; 32],
    depth: u16,
    cell: Option<Arc<Cell>>,
}

impl CellRef {
    /// A child known only by representation hash and depth (for example, contract code).
    #[must_use]
    pub const fn opaque(hash: [u8; 32], depth: u16) -> Self {
        Self {
            hash,
            depth,
            cell: None,
        }
    }

    /// Representation hash of the child.
    #[must_use]
    pub const fn hash(&self) -> &[u8; 32] {
        &self.hash
    }

    /// Depth of the child.
    #[must_use]
    pub const fn depth(&self) -> u16 {
        self.depth
    }

    /// The child cell, unless it is opaque.
    #[must_use]
    pub fn cell(&self) -> Option<&Cell> {
        self.cell.as_deref()
    }
}

impl From<Cell> for CellRef {
    fn from(cell: Cell) -> Self {
        Self {
            hash: cell.hash,
            depth: cell.depth,
            cell: Some(Arc::new(cell)),
        }
    }
}

impl From<SccpTonCodeRefV1> for CellRef {
    fn from(code: SccpTonCodeRefV1) -> Self {
        Self::opaque(code.hash, code.depth)
    }
}

/// An ordinary (level-0) TON cell.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Cell {
    data: Vec<u8>,
    bit_len: usize,
    refs: Vec<CellRef>,
    hash: [u8; 32],
    depth: u16,
}

impl Cell {
    /// Representation hash.
    #[must_use]
    pub const fn hash(&self) -> &[u8; 32] {
        &self.hash
    }

    /// Depth (0 without references, else one more than the deepest child).
    #[must_use]
    pub const fn depth(&self) -> u16 {
        self.depth
    }

    /// Number of data bits.
    #[must_use]
    pub const fn bit_len(&self) -> usize {
        self.bit_len
    }

    /// Data bits, left-aligned and zero-padded to whole bytes (no completion tag).
    #[must_use]
    pub fn data(&self) -> &[u8] {
        &self.data
    }

    /// Child references.
    #[must_use]
    pub fn refs(&self) -> &[CellRef] {
        &self.refs
    }

    /// The standard representation `d1 ‖ d2 ‖ augmented data ‖ child depths ‖ child hashes`.
    #[must_use]
    pub fn representation(&self) -> Vec<u8> {
        representation(&self.data, self.bit_len, &self.refs)
    }

    /// Serialize the complete tree as a single-root bag of cells: no index, no CRC, minimal
    /// widths, one entry per distinct cell, parents before children.
    ///
    /// # Errors
    ///
    /// Returns [`TonCellError::OpaqueChild`] when a child is known only by hash and depth.
    pub fn to_boc(&self) -> Result<Vec<u8>, TonCellError> {
        fn visit<'a>(
            cell: &'a Cell,
            seen: &mut std::collections::BTreeSet<[u8; 32]>,
            post: &mut Vec<&'a Cell>,
        ) -> Result<(), TonCellError> {
            if !seen.insert(cell.hash) {
                return Ok(());
            }
            // Children in reverse, then the reversed post-order: the canonical proof order.
            for child in cell.refs.iter().rev() {
                visit(child.cell().ok_or(TonCellError::OpaqueChild)?, seen, post)?;
            }
            post.push(cell);
            Ok(())
        }
        let mut post = Vec::new();
        visit(self, &mut std::collections::BTreeSet::new(), &mut post)?;
        post.reverse();
        let index: std::collections::BTreeMap<[u8; 32], usize> = post
            .iter()
            .enumerate()
            .map(|(position, cell)| (cell.hash, position))
            .collect();
        let width = |value: usize| {
            usize::try_from((usize::BITS - value.leading_zeros()).div_ceil(8).max(1)).unwrap_or(8)
        };
        let be = |value: usize, bytes: usize| {
            u64::try_from(value).unwrap_or(u64::MAX).to_be_bytes()[8 - bytes..].to_vec()
        };
        let size_bytes = width(post.len());
        let mut body = Vec::new();
        for cell in &post {
            let representation = cell.representation();
            body.extend_from_slice(&representation[..2 + cell.bit_len.div_ceil(8)]);
            for child in &cell.refs {
                body.extend_from_slice(&be(index[child.hash()], size_bytes));
            }
        }
        let offset_bytes = width(body.len());
        let mut out = vec![0xb5, 0xee, 0x9c, 0x72];
        out.push(u8::try_from(size_bytes).map_err(|_| TonCellError::BitOverflow)?);
        out.push(u8::try_from(offset_bytes).map_err(|_| TonCellError::BitOverflow)?);
        out.extend_from_slice(&be(post.len(), size_bytes));
        out.extend_from_slice(&be(1, size_bytes));
        out.extend_from_slice(&be(0, size_bytes));
        out.extend_from_slice(&be(body.len(), offset_bytes));
        out.extend_from_slice(&be(0, size_bytes));
        out.extend_from_slice(&body);
        Ok(out)
    }
}

/// Read a single-root bag of ordinary cells (for example a contract code artifact) as a
/// complete cell tree.
///
/// # Errors
///
/// Returns [`TonCellError::BadSnake`] for a malformed bag, an exotic cell or a cell that does
/// not fit the builder.
pub fn cell_from_boc(bytes: &[u8]) -> Result<Cell, TonCellError> {
    fn build(
        boc: &crate::ton_native::TonBoc,
        index: usize,
        memo: &mut std::collections::BTreeMap<usize, Cell>,
    ) -> Result<Cell, TonCellError> {
        if let Some(cell) = memo.get(&index) {
            return Ok(cell.clone());
        }
        let raw = boc.cells.get(index).ok_or(TonCellError::BadSnake)?;
        if raw.exotic {
            return Err(TonCellError::BadSnake);
        }
        let bits = crate::ton_native::ton_cell_serialized_bit_len(raw.data_descriptor, &raw.data)
            .ok_or(TonCellError::BadSnake)?;
        let mut builder = CellBuilder::new();
        for bit in 0..bits {
            builder.store_bit(raw.data[bit / 8] & (0x80 >> (bit % 8)) != 0)?;
        }
        for child in &raw.refs {
            builder.store_ref(build(boc, *child, memo)?)?;
        }
        let cell = builder.build();
        memo.insert(index, cell.clone());
        Ok(cell)
    }
    let boc = crate::ton_native::parse_ton_boc(bytes).ok_or(TonCellError::BadSnake)?;
    let [root] = boc.roots.as_slice() else {
        return Err(TonCellError::BadSnake);
    };
    build(&boc, *root, &mut std::collections::BTreeMap::new())
}

fn representation(data: &[u8], bit_len: usize, refs: &[CellRef]) -> Vec<u8> {
    let full_bytes = bit_len / 8;
    let data_bytes = bit_len.div_ceil(8);
    let mut out = Vec::with_capacity(2 + data_bytes + refs.len() * 34);
    out.push(u8::try_from(refs.len()).expect("at most 4 references"));
    out.push(u8::try_from(full_bytes + data_bytes).expect("at most 256 data bytes"));
    out.extend_from_slice(&data[..data_bytes]);
    if !bit_len.is_multiple_of(8) {
        let last = out.len() - 1;
        out[last] |= 0x80 >> (bit_len % 8);
    }
    for child in refs {
        out.extend_from_slice(&child.depth.to_be_bytes());
    }
    for child in refs {
        out.extend_from_slice(&child.hash);
    }
    out
}

/// Builder of one ordinary cell.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CellBuilder {
    data: Vec<u8>,
    bit_len: usize,
    refs: Vec<CellRef>,
}

impl CellBuilder {
    /// An empty builder.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Data bits stored so far.
    #[must_use]
    pub fn bit_len(&self) -> usize {
        self.bit_len
    }

    /// Append one bit.
    ///
    /// # Errors
    ///
    /// Returns [`TonCellError::BitOverflow`] past 1023 bits.
    pub fn store_bit(&mut self, bit: bool) -> Result<&mut Self, TonCellError> {
        if self.bit_len >= MAX_CELL_BITS {
            return Err(TonCellError::BitOverflow);
        }
        if self.bit_len.is_multiple_of(8) {
            self.data.push(0);
        }
        if bit {
            let last = self.data.len() - 1;
            self.data[last] |= 0x80 >> (self.bit_len % 8);
        }
        self.bit_len += 1;
        Ok(self)
    }

    /// Append `value` as a big-endian unsigned integer of `bits` bits (at most 128).
    ///
    /// # Errors
    ///
    /// Returns [`TonCellError::ValueTooWide`] or [`TonCellError::BitOverflow`].
    pub fn store_uint(&mut self, value: u128, bits: u32) -> Result<&mut Self, TonCellError> {
        if bits > 128 || (bits < 128 && value >> bits != 0) {
            return Err(TonCellError::ValueTooWide);
        }
        self.ensure_room(bits as usize)?;
        for position in (0..bits).rev() {
            self.store_bit((value >> position) & 1 == 1)?;
        }
        Ok(self)
    }

    /// Append whole bytes (for example a `uint256` or `uint160` in big-endian form).
    ///
    /// # Errors
    ///
    /// Returns [`TonCellError::BitOverflow`].
    pub fn store_bytes(&mut self, bytes: &[u8]) -> Result<&mut Self, TonCellError> {
        self.ensure_room(bytes.len() * 8)?;
        for byte in bytes {
            self.store_uint(u128::from(*byte), 8)?;
        }
        Ok(self)
    }

    /// Append a `Coins` (`VarUInteger 16`) value: a 4-bit byte length, then the minimal
    /// big-endian bytes.
    ///
    /// # Errors
    ///
    /// Returns [`TonCellError::CoinsTooLarge`] or [`TonCellError::BitOverflow`].
    pub fn store_coins(&mut self, value: u128) -> Result<&mut Self, TonCellError> {
        if value >= COINS_BOUND {
            return Err(TonCellError::CoinsTooLarge);
        }
        let len = (128 - value.leading_zeros()).div_ceil(8);
        self.store_uint(u128::from(len), 4)?;
        self.store_uint(value, len * 8)
    }

    /// Append an `addr_std` without anycast: `10 ‖ 0 ‖ int8 workchain ‖ bits256 account`.
    ///
    /// # Errors
    ///
    /// Returns [`TonCellError::BitOverflow`].
    pub fn store_address_std(
        &mut self,
        workchain: i8,
        account: &[u8; 32],
    ) -> Result<&mut Self, TonCellError> {
        self.ensure_room(267)?;
        self.store_uint(0b100, 3)?;
        self.store_bytes(&workchain.to_be_bytes())?;
        self.store_bytes(account)
    }

    /// Append a reference.
    ///
    /// # Errors
    ///
    /// Returns [`TonCellError::RefOverflow`] past 4 references.
    pub fn store_ref(&mut self, child: impl Into<CellRef>) -> Result<&mut Self, TonCellError> {
        if self.refs.len() >= MAX_CELL_REFS {
            return Err(TonCellError::RefOverflow);
        }
        self.refs.push(child.into());
        Ok(self)
    }

    /// Append a `Maybe ^Cell`: bit 1 and the reference, or bit 0.
    ///
    /// # Errors
    ///
    /// Returns [`TonCellError::BitOverflow`] or [`TonCellError::RefOverflow`].
    pub fn store_maybe_ref(
        &mut self,
        child: Option<impl Into<CellRef>>,
    ) -> Result<&mut Self, TonCellError> {
        match child {
            Some(child) => {
                if self.refs.len() >= MAX_CELL_REFS {
                    return Err(TonCellError::RefOverflow);
                }
                self.store_bit(true)?;
                self.store_ref(child)
            }
            None => self.store_bit(false),
        }
    }

    /// Finish the cell and compute its representation hash and depth.
    #[must_use]
    pub fn build(&self) -> Cell {
        let representation = representation(&self.data, self.bit_len, &self.refs);
        let hash: [u8; 32] = Sha256::digest(&representation).into();
        let depth = self
            .refs
            .iter()
            .map(|child| child.depth.saturating_add(1))
            .max()
            .unwrap_or(0);
        Cell {
            data: self.data.clone(),
            bit_len: self.bit_len,
            refs: self.refs.clone(),
            hash,
            depth,
        }
    }

    fn ensure_room(&self, bits: usize) -> Result<(), TonCellError> {
        if self.bit_len + bits > MAX_CELL_BITS {
            Err(TonCellError::BitOverflow)
        } else {
            Ok(())
        }
    }
}

// ---------------------------------------------------------------------------------------------
// SnakeBytes and chunked lists (§5.3.2)
// ---------------------------------------------------------------------------------------------

/// Canonical `SnakeBytes`: 127-byte chunks linked by the single reference, the last chunk
/// holding 1..=127 bytes.
///
/// # Errors
///
/// Returns [`TonCellError::Empty`] for no bytes.
pub fn snake_bytes(bytes: &[u8]) -> Result<Cell, TonCellError> {
    if bytes.is_empty() {
        return Err(TonCellError::Empty);
    }
    let mut chunks = bytes.chunks(TON_SNAKE_CHUNK_BYTES).rev();
    let last = chunks.next().expect("non-empty input has a chunk");
    let mut tail = CellBuilder::new().store_bytes(last)?.build();
    for chunk in chunks {
        let mut builder = CellBuilder::new();
        builder.store_bytes(chunk)?.store_ref(tail)?;
        tail = builder.build();
    }
    Ok(tail)
}

/// Parse canonical `SnakeBytes` of at most `max_bytes` bytes. Every chunk holds whole bytes; a
/// chunk with a continuation holds exactly 127 bytes and one reference; the last chunk holds
/// 1..=127 bytes and no reference.
///
/// # Errors
///
/// Returns [`TonCellError::BadSnake`], [`TonCellError::SnakeTooLong`] or
/// [`TonCellError::OpaqueChild`].
pub fn parse_snake_bytes(cell: &Cell, max_bytes: usize) -> Result<Vec<u8>, TonCellError> {
    let mut out = Vec::new();
    let mut current = cell;
    loop {
        if !current.bit_len.is_multiple_of(8) || current.refs.len() > 1 {
            return Err(TonCellError::BadSnake);
        }
        let len = current.bit_len / 8;
        let has_next = current.refs.len() == 1;
        if (has_next && len != TON_SNAKE_CHUNK_BYTES) || !(1..=TON_SNAKE_CHUNK_BYTES).contains(&len)
        {
            return Err(TonCellError::BadSnake);
        }
        if out.len() + len > max_bytes {
            return Err(TonCellError::SnakeTooLong);
        }
        out.extend_from_slice(&current.data[..len]);
        if !has_next {
            return Ok(out);
        }
        current = current.refs[0].cell().ok_or(TonCellError::OpaqueChild)?;
    }
}

fn chunk_list<T>(
    items: &[T],
    per_chunk: usize,
    store: impl Fn(&mut CellBuilder, &T) -> Result<(), TonCellError>,
) -> Result<Cell, TonCellError> {
    if items.is_empty() {
        return Err(TonCellError::Empty);
    }
    let mut next: Option<Cell> = None;
    for chunk in items.chunks(per_chunk).rev() {
        let mut builder = CellBuilder::new();
        for item in chunk {
            store(&mut builder, item)?;
        }
        builder.store_maybe_ref(next.take())?;
        next = Some(builder.build());
    }
    Ok(next.expect("non-empty input has a chunk"))
}

/// `MemberChunk`: maximal 6-address chunks of `uint160` members with a `Maybe ^MemberChunk`
/// continuation.
///
/// # Errors
///
/// Returns [`TonCellError::Empty`] for no members.
pub fn member_chunks(members: &[[u8; 20]]) -> Result<Cell, TonCellError> {
    chunk_list(members, TON_MEMBER_CHUNK_ADDRESSES, |builder, member| {
        builder.store_bytes(member).map(|_| ())
    })
}

/// `HashChunk`: maximal 3-hash chunks of `uint256` with a `Maybe ^HashChunk` continuation;
/// `None` for an empty path (`path:(Maybe ^HashChunk)`).
///
/// # Errors
///
/// Returns [`TonCellError::BitOverflow`] only on internal misuse.
pub fn hash_chunks(hashes: &[[u8; 32]]) -> Result<Option<Cell>, TonCellError> {
    if hashes.is_empty() {
        return Ok(None);
    }
    chunk_list(hashes, TON_HASH_CHUNK_HASHES, |builder, hash| {
        builder.store_bytes(hash).map(|_| ())
    })
    .map(Some)
}

// ---------------------------------------------------------------------------------------------
// Minter initial data and StateInit addresses (§5.3.1)
// ---------------------------------------------------------------------------------------------

/// Inputs of the canonical minter initial data for a deployment pinned to one generation.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct TonMinterInitV1 {
    /// Live Taira `NetworkId` bytes.
    pub taira_network_id: [u8; 32],
    /// Route revision.
    pub route_revision: u32,
    /// Supply cap in token units (`Coins`, below `2^120`).
    pub max_supply: u128,
    /// The pinned Taira roster generation.
    pub roster: RosterV1,
    /// Jetton wallet code.
    pub wallet_code: SccpTonCodeRefV1,
    /// Consumption bucket code.
    pub bucket_code: SccpTonCodeRefV1,
}

/// The three cells under the minter data root, exposed for golden comparisons.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct TonMinterDataV1 {
    /// `minter_data` root cell.
    pub root: Cell,
    /// `minter_config` cell.
    pub config: Cell,
    /// `roster_state` cell.
    pub roster: Cell,
    /// First `MemberChunk` cell.
    pub members: Cell,
    /// The pinned roster digest.
    pub roster_digest: [u8; 32],
}

/// Build the canonical initial minter data (§5.3.1): uninitialized, zero counters and supply,
/// not paused, no deployed buckets, no previous roster, no recorded retries; the config holds
/// the network id,
/// revision, cap, pinned generation and digest and both code references; the roster holds the
/// digest, generation, validity window, `n`, `t` and the members in maximal 6-address chunks.
///
/// # Errors
///
/// Returns [`TonCellError::BadRoster`] or [`TonCellError::CoinsTooLarge`].
pub fn minter_initial_data(init: &TonMinterInitV1) -> Result<TonMinterDataV1, TonCellError> {
    minter_initial_data_with_code(init, init.wallet_code.into(), init.bucket_code.into())
}

/// [`minter_initial_data`] with the complete wallet and bucket code cells, so the data can be
/// serialized in a deployment `StateInit`; the codes must match `init`'s references.
///
/// # Errors
///
/// Returns [`TonCellError::OpaqueChild`] when a code cell does not match its reference, or the
/// errors of [`minter_initial_data`].
pub fn minter_deployment_data(
    init: &TonMinterInitV1,
    wallet_code: Cell,
    bucket_code: Cell,
) -> Result<TonMinterDataV1, TonCellError> {
    for (cell, reference) in [
        (&wallet_code, init.wallet_code),
        (&bucket_code, init.bucket_code),
    ] {
        if *cell.hash() != reference.hash || cell.depth() != reference.depth {
            return Err(TonCellError::OpaqueChild);
        }
    }
    minter_initial_data_with_code(init, wallet_code.into(), bucket_code.into())
}

fn minter_initial_data_with_code(
    init: &TonMinterInitV1,
    wallet_code: CellRef,
    bucket_code: CellRef,
) -> Result<TonMinterDataV1, TonCellError> {
    let roster_digest = init
        .roster
        .digest(&init.taira_network_id)
        .map_err(|_| TonCellError::BadRoster)?;
    let n = u8::try_from(init.roster.n()).map_err(|_| TonCellError::BadRoster)?;
    let t = u8::try_from(init.roster.threshold()).map_err(|_| TonCellError::BadRoster)?;

    let mut config = CellBuilder::new();
    config
        .store_bytes(&init.taira_network_id)?
        .store_uint(u128::from(init.route_revision), 32)?
        .store_coins(init.max_supply)?
        .store_uint(u128::from(init.roster.generation), 64)?
        .store_bytes(&roster_digest)?
        .store_ref(wallet_code)?
        .store_ref(bucket_code)?;
    let config = config.build();

    let members = member_chunks(&init.roster.members)?;
    let mut roster = CellBuilder::new();
    roster
        .store_bytes(&roster_digest)?
        .store_uint(u128::from(init.roster.generation), 64)?
        .store_uint(u128::from(init.roster.valid_from_ms), 64)?
        .store_uint(u128::from(init.roster.valid_until_ms), 64)?
        .store_uint(u128::from(n), 8)?
        .store_uint(u128::from(t), 8)?
        .store_ref(members.clone())?;
    let roster = roster.build();

    let mut root = CellBuilder::new();
    root.store_bit(false)? // initialized
        .store_coins(0)? // total_supply
        .store_coins(0)? // pending_supply
        .store_uint(0, 64)? // outbound_nonce
        .store_uint(0, 64)? // op_count
        .store_uint(0, 64)? // control_nonce
        .store_bit(false)? // minting_paused
        .store_uint(0, 64)? // deployed_buckets
        .store_ref(config.clone())?
        .store_ref(roster.clone())?
        .store_maybe_ref(None::<Cell>)? // prev_roster
        .store_bit(false)?; // retries: empty HashmapE 64
    Ok(TonMinterDataV1 {
        root: root.build(),
        config,
        roster,
        members,
        roster_digest,
    })
}

/// `StateInit` with code and data and no split depth, special flags or libraries.
///
/// # Errors
///
/// Never fails for the fixed 5-bit layout; the `Result` mirrors the builder.
pub fn state_init(
    code: impl Into<CellRef>,
    data: impl Into<CellRef>,
) -> Result<Cell, TonCellError> {
    let mut builder = CellBuilder::new();
    builder
        .store_bit(false)? // split_depth
        .store_bit(false)? // special
        .store_maybe_ref(Some(code))?
        .store_maybe_ref(Some(data))?
        .store_bit(false)?; // library
    Ok(builder.build())
}

/// Workchain-0 account id (`StateInit` hash) of the minter for `init` and its code.
///
/// # Errors
///
/// See [`minter_initial_data`].
pub fn minter_account_id(
    init: &TonMinterInitV1,
    minter_code: SccpTonCodeRefV1,
) -> Result<[u8; 32], TonCellError> {
    let data = minter_initial_data(init)?;
    Ok(*state_init(minter_code, data.root)?.hash())
}

/// Account id of the Jetton wallet of `owner` (zero balance) under the minter.
///
/// # Errors
///
/// Never fails for well-formed inputs; the `Result` mirrors the builder.
pub fn wallet_account_id(
    owner_workchain: i8,
    owner: &[u8; 32],
    minter_account: &[u8; 32],
    wallet_code: SccpTonCodeRefV1,
) -> Result<[u8; 32], TonCellError> {
    let mut data = CellBuilder::new();
    data.store_coins(0)?
        .store_address_std(owner_workchain, owner)?
        .store_address_std(0, minter_account)?;
    Ok(*state_init(wallet_code, data.build())?.hash())
}

/// Account id of consumption bucket `index` under the minter: the hash of its canonical
/// `StateInit`, `bucket_data` with `activated = false` and all 512 flags clear (§5.3.3). Anyone
/// can deploy that state, but only the minter's `sccp_activate_bucket` makes it accept flags.
///
/// # Errors
///
/// Never fails for well-formed inputs; the `Result` mirrors the builder.
pub fn bucket_account_id(
    minter_account: &[u8; 32],
    index: u64,
    bucket_code: SccpTonCodeRefV1,
) -> Result<[u8; 32], TonCellError> {
    let mut data = CellBuilder::new();
    data.store_address_std(0, minter_account)?
        .store_uint(u128::from(index), 64)?
        .store_bit(false)? // activated
        .store_bytes(&[0; 64])?;
    Ok(*state_init(bucket_code, data.build())?.hash())
}

// ---------------------------------------------------------------------------------------------
// Storage rent (§5.3.5)
// ---------------------------------------------------------------------------------------------

/// Upper bound of the minter's account state in bits (code and maximal data), the size
/// `MINTER_FLOOR` is computed for (`SCCP_MINTER_STATE_BITS`).
pub const TON_MINTER_STATE_BITS: u64 = 102_000;
/// Upper bound of the minter's account state in cells (`SCCP_MINTER_STATE_CELLS`).
pub const TON_MINTER_STATE_CELLS: u64 = 205;
/// Storage period of `MINTER_FLOOR` and `BUCKET_FLOOR`: 100 years (`SCCP_FLOOR_SECONDS`).
pub const TON_FLOOR_SECONDS: u64 = 3_153_600_000;
/// TON mainnet basechain storage price per bit and 2^16 seconds (`ConfigParam 18`).
pub const TON_MAINNET_BIT_PRICE_PS: u64 = 1;
/// TON mainnet basechain storage price per cell and 2^16 seconds (`ConfigParam 18`).
pub const TON_MAINNET_CELL_PRICE_PS: u64 = 500;

/// `GETSTORAGEFEE`: nanotons for storing `bits` and `cells` for `seconds` at the given
/// per-2^16-second prices, rounded up as the TON storage phase rounds.
#[must_use]
pub fn ton_storage_fee(
    seconds: u64,
    bits: u64,
    cells: u64,
    bit_price_ps: u64,
    cell_price_ps: u64,
) -> u128 {
    let per_period =
        u128::from(bits) * u128::from(bit_price_ps) + u128::from(cells) * u128::from(cell_price_ps);
    (per_period * u128::from(seconds)).div_ceil(1 << 16)
}

/// `MINTER_FLOOR` at TON mainnet storage prices. The minter computes its floor from the live
/// `ConfigParam 18` (get method `minter_floor()`); this is the same value at the prices pinned
/// above, for funding a deployment before the minter exists.
#[must_use]
pub fn ton_minter_floor_at_mainnet_prices() -> u128 {
    ton_storage_fee(
        TON_FLOOR_SECONDS,
        TON_MINTER_STATE_BITS,
        TON_MINTER_STATE_CELLS,
        TON_MAINNET_BIT_PRICE_PS,
        TON_MAINNET_CELL_PRICE_PS,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(bytes: &[u8]) -> String {
        crate::v1::hashes::to_hex(bytes)
    }

    fn from_hex(text: &str) -> [u8; 32] {
        let mut out = [0_u8; 32];
        for (index, slot) in out.iter_mut().enumerate() {
            *slot = u8::from_str_radix(&text[2 * index..2 * index + 2], 16).unwrap();
        }
        out
    }

    #[test]
    fn empty_cell_hash_is_the_known_constant() {
        let empty = CellBuilder::new().build();
        assert_eq!(
            hex(empty.hash()),
            "96a296d224f285c67bee93c30f8a309157f0daa35dc5b87e410b78630a09cfc7"
        );
        assert_eq!(empty.depth(), 0);
    }

    #[test]
    fn representation_uses_the_completion_tag() {
        let mut builder = CellBuilder::new();
        builder.store_uint(0b101, 3).unwrap();
        let cell = builder.build();
        assert_eq!(cell.representation(), vec![0, 1, 0b1011_0000]);
        assert_eq!(cell.data(), &[0b1010_0000]);
        let mut builder = CellBuilder::new();
        builder.store_uint(0xab, 8).unwrap();
        builder.store_ref(cell.clone()).unwrap();
        let parent = builder.build();
        let mut expected = vec![1, 2, 0xab, 0, 0];
        expected.extend_from_slice(cell.hash());
        assert_eq!(parent.representation(), expected);
        assert_eq!(parent.depth(), 1);
    }

    #[test]
    fn builder_limits() {
        let mut builder = CellBuilder::new();
        builder.store_bytes(&[0; 127]).unwrap();
        builder.store_uint(0, 7).unwrap();
        assert_eq!(builder.bit_len(), 1023);
        assert_eq!(
            builder.store_bit(true).unwrap_err(),
            TonCellError::BitOverflow
        );
        let mut builder = CellBuilder::new();
        assert_eq!(
            builder.store_uint(4, 2).unwrap_err(),
            TonCellError::ValueTooWide
        );
        assert_eq!(
            builder.store_uint(0, 129).unwrap_err(),
            TonCellError::ValueTooWide
        );
        assert!(builder.store_uint(u128::MAX, 128).is_ok());
        for _ in 0..4 {
            builder.store_ref(CellRef::opaque([0; 32], 0)).unwrap();
        }
        assert_eq!(
            builder.store_ref(CellRef::opaque([0; 32], 0)).unwrap_err(),
            TonCellError::RefOverflow
        );
        assert_eq!(
            CellBuilder::new().store_coins(COINS_BOUND).unwrap_err(),
            TonCellError::CoinsTooLarge
        );
    }

    #[test]
    fn coins_and_addresses() {
        let mut builder = CellBuilder::new();
        builder.store_coins(0).unwrap();
        assert_eq!(builder.bit_len(), 4);
        let mut builder = CellBuilder::new();
        builder.store_coins(1_000_000_000_000_000_000).unwrap();
        assert_eq!(builder.bit_len(), 4 + 64);
        assert_eq!(builder.build().data()[0], 0x80);
        let mut builder = CellBuilder::new();
        builder.store_address_std(-1, &[0xff; 32]).unwrap();
        assert_eq!(builder.bit_len(), 267);
        let cell = builder.build();
        assert_eq!(cell.data()[0], 0b1001_1111);
    }

    #[test]
    fn snake_bytes_shapes() {
        for len in [1_usize, 126, 127, 128, 254, 255, 1024] {
            let bytes: Vec<u8> = (0..len)
                .map(|index| u8::try_from(index % 251).unwrap())
                .collect();
            let cell = snake_bytes(&bytes).unwrap();
            assert_eq!(parse_snake_bytes(&cell, 4096).unwrap(), bytes, "len {len}");
            let expected_depth = u16::try_from(len.div_ceil(127) - 1).unwrap();
            assert_eq!(cell.depth(), expected_depth);
        }
        assert_eq!(snake_bytes(&[]).unwrap_err(), TonCellError::Empty);
        let long = snake_bytes(&[1; 300]).unwrap();
        assert_eq!(
            parse_snake_bytes(&long, 299).unwrap_err(),
            TonCellError::SnakeTooLong
        );
        // Empty cell, short non-final chunk, non-byte bits, two refs and opaque continuations.
        assert_eq!(
            parse_snake_bytes(&CellBuilder::new().build(), 10).unwrap_err(),
            TonCellError::BadSnake
        );
        let tail = CellBuilder::new().store_bytes(&[1]).unwrap().build();
        let mut short = CellBuilder::new();
        short
            .store_bytes(&[1; 126])
            .unwrap()
            .store_ref(tail.clone())
            .unwrap();
        assert_eq!(
            parse_snake_bytes(&short.build(), 4096).unwrap_err(),
            TonCellError::BadSnake
        );
        let mut odd_bits = CellBuilder::new();
        odd_bits.store_uint(1, 9).unwrap();
        assert_eq!(
            parse_snake_bytes(&odd_bits.build(), 4096).unwrap_err(),
            TonCellError::BadSnake
        );
        let mut two_refs = CellBuilder::new();
        two_refs
            .store_bytes(&[1; 127])
            .unwrap()
            .store_ref(tail.clone())
            .unwrap()
            .store_ref(tail)
            .unwrap();
        assert_eq!(
            parse_snake_bytes(&two_refs.build(), 4096).unwrap_err(),
            TonCellError::BadSnake
        );
        let mut opaque = CellBuilder::new();
        opaque
            .store_bytes(&[1; 127])
            .unwrap()
            .store_ref(CellRef::opaque([1; 32], 0))
            .unwrap();
        assert_eq!(
            parse_snake_bytes(&opaque.build(), 4096).unwrap_err(),
            TonCellError::OpaqueChild
        );
        let mut empty_tail = CellBuilder::new();
        empty_tail
            .store_bytes(&[1; 127])
            .unwrap()
            .store_ref(CellBuilder::new().build())
            .unwrap();
        assert_eq!(
            parse_snake_bytes(&empty_tail.build(), 4096).unwrap_err(),
            TonCellError::BadSnake
        );
    }

    #[test]
    fn chunk_lists() {
        let members: Vec<[u8; 20]> = (1..=13).map(|byte| [byte; 20]).collect();
        let head = member_chunks(&members).unwrap();
        assert_eq!(head.bit_len(), 6 * 160 + 1);
        assert_eq!(head.depth(), 2);
        let last = head.refs()[0].cell().unwrap().refs()[0].cell().unwrap();
        assert_eq!(last.bit_len(), 160 + 1);
        assert!(last.refs().is_empty());
        assert_eq!(member_chunks(&[]).unwrap_err(), TonCellError::Empty);
        assert_eq!(hash_chunks(&[]).unwrap(), None);
        let path = hash_chunks(&[[1; 32]; 4]).unwrap().unwrap();
        assert_eq!(path.bit_len(), 3 * 256 + 1);
        assert_eq!(path.refs()[0].cell().unwrap().bit_len(), 256 + 1);
    }

    fn fixture_n4() -> (TonMinterInitV1, SccpTonCodeRefV1) {
        let init = TonMinterInitV1 {
            taira_network_id: [0x11; 32],
            route_revision: 1,
            max_supply: 1_000_000_000_000_000_000,
            roster: RosterV1 {
                generation: 7,
                valid_from_ms: 1_800_000_000_000,
                valid_until_ms: 1_801_209_600_000,
                members: (1..=4).map(|byte| [byte; 20]).collect(),
            },
            wallet_code: SccpTonCodeRefV1 {
                hash: from_hex("ee3cf858ffdc0e230e9b97914a75c0d7d4ecd317881ecec0873d2abd875aaa90"),
                depth: 4,
            },
            bucket_code: SccpTonCodeRefV1 {
                hash: from_hex("636f93d7b6d9fbf1c4756453654eea4d8fa9a474b461e642d501299737cd0450"),
                depth: 6,
            },
        };
        let minter_code = SccpTonCodeRefV1 {
            hash: from_hex("4557a9b6df6a72104fcb8ef3337106f4d6a43ba7f0a825990641552e0d6554e4"),
            depth: 15,
        };
        (init, minter_code)
    }

    #[test]
    fn minter_data_and_addresses_match_the_contract_fixture() {
        // fixtures/sccp/ton_stateinit_v1.json, label "n4" (emitted by the Tolk contracts).
        let (init, minter_code) = fixture_n4();
        let data = minter_initial_data(&init).unwrap();
        assert_eq!(data.config.bit_len(), 676);
        assert_eq!(
            hex(data.config.hash()),
            "97abb649f4e1e5e72c64a5fd6d5d300cb4278e149c761aa0bad02515ae45882c"
        );
        assert_eq!(data.config.depth(), 7);
        assert_eq!(data.members.bit_len(), 641);
        assert_eq!(
            hex(data.members.hash()),
            "efdb0f63b51fe0addd82eb234ccb1c4fda247dd2bbe0f845258aa353a56d2a28"
        );
        assert_eq!(data.roster.bit_len(), 464);
        assert_eq!(
            hex(data.roster.hash()),
            "f0e8dc1f221010d8407e023420ce004d6259cc632652f397993a418e83b05ab1"
        );
        // 267 bits of counters and flags, the `prev_roster` Maybe bit and the empty `retries`
        assert_eq!(data.root.bit_len(), 268);
        assert_eq!(data.root.depth(), 8);
        assert_eq!(
            hex(data.root.hash()),
            "6a26fb09952d20b8623ffc1625be3a0de55f575bbfb3e0068a7dbdf75820389d"
        );
        let minter = minter_account_id(&init, minter_code).unwrap();
        assert_eq!(
            hex(&minter),
            "2df158214cff298e678f9b15f50dd20aa4f30bbed5e570cfdf0524c6209a10a7"
        );
        assert_eq!(
            hex(&bucket_account_id(&minter, 0, init.bucket_code).unwrap()),
            "99be6871b79cb5cd7fdde27c8b11bc6b4314a179f5db7146894259b751a0da7a"
        );
        assert_eq!(
            hex(&bucket_account_id(&minter, 1, init.bucket_code).unwrap()),
            "921d14d62f1496963af0a3c3e5a7ca9344b5342badaad02d5dc877db7d1dbb32"
        );
        assert_eq!(
            hex(&wallet_account_id(0, &[0xab; 32], &minter, init.wallet_code).unwrap()),
            "a961afd4c4a4491cbcf46cbd80976bb4b62dd4e103c156f0cd0cdc01dc0c9aae"
        );
    }

    fn fixture_text(value: &norito::json::Value, key: &str) -> String {
        value
            .get(key)
            .and_then(norito::json::Value::as_str)
            .unwrap_or_else(|| panic!("fixture field `{key}`"))
            .to_owned()
    }

    fn fixture_u64(value: &norito::json::Value, key: &str) -> u64 {
        value
            .get(key)
            .and_then(norito::json::Value::as_u64)
            .unwrap_or_else(|| panic!("fixture field `{key}`"))
    }

    fn fixture_code(fixture: &norito::json::Value, name: &str) -> SccpTonCodeRefV1 {
        let record = &fixture["code"][name];
        SccpTonCodeRefV1 {
            hash: from_hex(&fixture_text(record, "hash")),
            depth: u16::try_from(fixture_u64(record, "depth")).unwrap(),
        }
    }

    #[test]
    fn every_stateinit_fixture_vector_reproduces_from_code_references() {
        // Taira's `RegisterRoute` recomputes the minter address from these inputs alone; the
        // fixture is emitted by the Tolk contracts and recomputed in Python.
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../fixtures/sccp/ton_stateinit_v1.json");
        let text = std::fs::read_to_string(path).expect("fixture");
        let fixture: norito::json::Value = norito::json::from_str(&text).expect("fixture parses");
        let minter_code = fixture_code(&fixture, "minter");
        let wallet_code = fixture_code(&fixture, "wallet");
        let bucket_code = fixture_code(&fixture, "bucket");
        let vectors = fixture["vectors"].as_array().expect("vectors");
        assert_eq!(vectors.len(), 2);
        for vector in vectors {
            let members: Vec<[u8; 20]> = vector["members"]
                .as_array()
                .expect("members")
                .iter()
                .map(|member| {
                    let mut out = [0_u8; 20];
                    let text = member.as_str().expect("member");
                    for (index, slot) in out.iter_mut().enumerate() {
                        *slot = u8::from_str_radix(&text[2 * index..2 * index + 2], 16).unwrap();
                    }
                    out
                })
                .collect();
            let init = TonMinterInitV1 {
                taira_network_id: from_hex(&fixture_text(vector, "taira_network_id")),
                route_revision: u32::try_from(fixture_u64(vector, "route_revision")).unwrap(),
                max_supply: fixture_text(vector, "max_supply").parse().unwrap(),
                roster: RosterV1 {
                    generation: fixture_u64(vector, "generation"),
                    valid_from_ms: fixture_u64(vector, "valid_from_ms"),
                    valid_until_ms: fixture_u64(vector, "valid_until_ms"),
                    members,
                },
                wallet_code,
                bucket_code,
            };
            let label = fixture_text(vector, "label");
            let data = minter_initial_data(&init).unwrap();
            assert_eq!(
                hex(&data.roster_digest),
                fixture_text(vector, "roster_digest"),
                "{label}"
            );
            let initial = &vector["initial_data"];
            assert_eq!(
                hex(data.root.hash()),
                fixture_text(initial, "hash"),
                "{label}"
            );
            assert_eq!(
                u64::from(data.root.depth()),
                fixture_u64(initial, "depth"),
                "{label}"
            );
            assert_eq!(
                data.root.bit_len() as u64,
                fixture_u64(&initial["root"], "bit_len"),
                "{label}"
            );
            let minter = minter_account_id(&init, minter_code).unwrap();
            assert_eq!(
                hex(&minter),
                fixture_text(&vector["address"], "account_id"),
                "{label}"
            );
            let children = &vector["children"];
            assert_eq!(
                hex(&bucket_account_id(&minter, 0, bucket_code).unwrap()),
                fixture_text(children, "bucket_0_account_id"),
                "{label}"
            );
            assert_eq!(
                hex(&bucket_account_id(&minter, 1, bucket_code).unwrap()),
                fixture_text(children, "bucket_1_account_id"),
                "{label}"
            );
            assert_eq!(
                hex(&wallet_account_id(0, &[0xab; 32], &minter, wallet_code).unwrap()),
                fixture_text(children, "wallet_account_id"),
                "{label}"
            );
        }
    }

    #[test]
    fn storage_fees_follow_the_tvm_formula() {
        // (bits · 1 + cells · 500) · seconds / 2^16, rounded up
        assert_eq!(ton_storage_fee(65_536, 1, 0, 1, 500), 1);
        assert_eq!(ton_storage_fee(1, 1, 0, 1, 500), 1);
        assert_eq!(ton_storage_fee(0, 1, 1, 1, 500), 0);
        assert_eq!(ton_storage_fee(65_536, 2, 3, 1, 500), 1_502);
        // MINTER_FLOOR at mainnet prices: 204 500 units per 2^16 s over 100 years
        assert_eq!(
            ton_minter_floor_at_mainnet_prices(),
            (204_500_u128 * 3_153_600_000).div_ceil(65_536)
        );
        assert_eq!(ton_minter_floor_at_mainnet_prices(), 9_840_563_965);
    }

    /// The value of `const <name> = <integer>` in a Tolk source.
    fn tolk_const(source: &str, name: &str) -> u64 {
        let prefix = format!("const {name} = ");
        source
            .lines()
            .find_map(|line| line.trim().strip_prefix(prefix.as_str()))
            .unwrap_or_else(|| panic!("`{name}` is not declared"))
            .trim()
            .parse()
            .unwrap_or_else(|_| panic!("`{name}` is not an integer literal"))
    }

    #[test]
    fn rent_constants_match_the_tolk_fee_module() {
        // `ton_minter_floor_at_mainnet_prices` funds a deployment before the minter's own
        // `minter_floor()` exists, so its inputs must be the contract's.
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../contracts/ton/sccp/contracts/sccp-fees.tolk");
        let source = std::fs::read_to_string(path).expect("sccp-fees.tolk");
        assert_eq!(
            tolk_const(&source, "SCCP_MINTER_STATE_BITS"),
            TON_MINTER_STATE_BITS
        );
        assert_eq!(
            tolk_const(&source, "SCCP_MINTER_STATE_CELLS"),
            TON_MINTER_STATE_CELLS
        );
        assert_eq!(tolk_const(&source, "SCCP_FLOOR_SECONDS"), TON_FLOOR_SECONDS);
    }

    #[test]
    fn minter_data_rejects_bad_inputs() {
        let (mut init, _) = fixture_n4();
        init.roster.members.swap(0, 1);
        assert_eq!(
            minter_initial_data(&init).unwrap_err(),
            TonCellError::BadRoster
        );
        let (mut init, _) = fixture_n4();
        init.max_supply = COINS_BOUND;
        assert_eq!(
            minter_initial_data(&init).unwrap_err(),
            TonCellError::CoinsTooLarge
        );
    }

    #[test]
    fn deployment_data_embeds_the_complete_code_cells() {
        let (mut init, _) = fixture_n4();
        let wallet = CellBuilder::new().store_uint(1, 8).unwrap().build();
        let bucket = CellBuilder::new().store_uint(2, 8).unwrap().build();
        init.wallet_code = SccpTonCodeRefV1 {
            hash: *wallet.hash(),
            depth: wallet.depth(),
        };
        init.bucket_code = SccpTonCodeRefV1 {
            hash: *bucket.hash(),
            depth: bucket.depth(),
        };
        let full = minter_deployment_data(&init, wallet.clone(), bucket.clone()).unwrap();
        assert_eq!(
            full.root.hash(),
            minter_initial_data(&init).unwrap().root.hash()
        );
        assert!(full.root.to_boc().is_ok());
        assert_eq!(
            minter_initial_data(&init).unwrap().root.to_boc(),
            Err(TonCellError::OpaqueChild)
        );
        assert_eq!(
            minter_deployment_data(&init, bucket, wallet).unwrap_err(),
            TonCellError::OpaqueChild
        );
    }

    #[test]
    fn bags_of_cells_round_trip_through_the_proof_parser() {
        let mut leaf = CellBuilder::new();
        leaf.store_uint(0x5a, 7).expect("bits");
        let leaf = leaf.build();
        let mut root = CellBuilder::new();
        root.store_bytes(&[1, 2, 3])
            .expect("bytes")
            .store_ref(leaf.clone())
            .expect("ref")
            .store_ref(leaf)
            .expect("ref");
        let root = root.build();
        let boc = root.to_boc().expect("complete tree");
        assert_eq!(
            crate::ton_native::ton_canonical_boc_single_root_hash_v1(&boc),
            Some(*root.hash())
        );
        assert_eq!(cell_from_boc(&boc).expect("parses"), root);
        let opaque = CellBuilder::new()
            .store_ref(CellRef::opaque([1; 32], 3))
            .expect("ref")
            .build();
        assert_eq!(opaque.to_boc(), Err(TonCellError::OpaqueChild));
        assert!(cell_from_boc(&[1, 2, 3]).is_err());
    }

    #[test]
    fn cell_refs() {
        let code = SccpTonCodeRefV1 {
            hash: [3; 32],
            depth: 9,
        };
        let reference = CellRef::from(code);
        assert_eq!(reference.hash(), &[3; 32]);
        assert_eq!(reference.depth(), 9);
        assert!(reference.cell().is_none());
        let cell = CellBuilder::new().build();
        let reference = CellRef::from(cell.clone());
        assert_eq!(reference.cell(), Some(&cell));
        let state = state_init(code, cell).unwrap();
        assert_eq!(state.bit_len(), 5);
        assert_eq!(state.depth(), 10);
    }
}
