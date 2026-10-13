//! Exact locked SCCP minter storage projections from authenticated native Account cells.

use super::{wallet_state::TonAccountCells, *};
use crate::v1::{
    committee::{CommitteeStateV1, committee_root, is_canonical_order, is_valid_committee_size},
    ton_cell::{CellBuilder, CellRef, locked_code_refs},
};
use iroha_data_model::sccp::deployment::{SccpCommitteePinV1, SccpTonCodeRefV1};

/// One immutable operation cause and its current bounded recovery coordinates.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TonRecoveryStateV1 {
    /// Never-reused key of the retained recovery operation.
    pub operation_id: u64,
    /// Commitment to the original nonce, amount, count, chain, query and tail.
    pub identity: H256,
    /// Activation, consumption, mint, unconsume or range (1..=5).
    pub stage: u8,
    /// Wait, drop, failed or queued (0..=3).
    pub phase: u8,
    /// Dispatch attempt within the current stage; zero only for failed first unconsume.
    pub attempt: u64,
    /// Canonical original row and tail bytes retained before a retry is signed.
    pub row_boc: Vec<u8>,
}

/// Exact persistent fields of the locked first-release minter.
///
/// Parsing alone is not native finality: callers obtain this projection through
/// `light_client::ton::wallet_state::verify_minter_state` before authorizing an outcome.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TonMinterStateV1 {
    /// Whether the one-time initial acceptance completed.
    pub initialized: bool,
    /// Native network bound into every certificate.
    pub network: H256,
    /// Native Sumeragi instance bound into every certificate.
    pub instance: H256,
    /// Immutable route revision.
    pub revision: u32,
    /// Immutable original generation pin.
    pub initial: SccpCommitteePinV1,
    /// Current committee and permanent equivocation latch.
    pub committee: CommitteeStateV1,
    /// At most three retained certified checkpoint commitments, in height order.
    pub checkpoints: Vec<(u64, H256)>,
    /// Completed circulating supply.
    pub total_supply: u128,
    /// Reserved supply awaiting asynchronous completion.
    pub pending_supply: u128,
    /// Immutable maximum combined supply.
    pub max_supply: u128,
    /// Next outbound burn nonce.
    pub outbound_nonce: u64,
    /// Saturating monetary/control operation counter.
    pub op_count: u64,
    /// Latest applied native control nonce.
    pub control_nonce: u64,
    /// Latest native Parliament pause state.
    pub parliament_paused: bool,
    /// Latest native fast-pause expiry.
    pub fast_pause_until_ms: u64,
    /// Number of deployed consumption buckets.
    pub deployed_buckets: u64,
    /// Contiguous prefix of fully acknowledged bucket activations.
    pub activated_buckets: u64,
    /// Next never-reused recovery identifier; earlier absent rows have completed.
    pub next_operation_id: u64,
    /// Complete capacity-bounded recovery dictionary in operation-id order.
    pub recovery: Vec<TonRecoveryStateV1>,
}

fn reader(boc: &TonBoc, index: usize) -> Option<TonBitReader<'_>> {
    let cell = boc.cells.get(index)?;
    if ton_cell_type(cell)? != TonCellType::Ordinary {
        return None;
    }
    TonBitReader::new(cell)
}

fn code_ref(cells: &TonAccountCells, index: usize) -> Option<SccpTonCodeRefV1> {
    let cell = cells.computed.get(index)?;
    Some(SccpTonCodeRefV1 {
        hash: cell.hashes[0],
        depth: cell.depths[0],
    })
}

fn initial(boc: &TonBoc, index: usize) -> Option<SccpCommitteePinV1> {
    let mut bits = reader(boc, index)?;
    let pin = SccpCommitteePinV1 {
        generation: bits.read_u64(64)?,
        committee_root: bits.read_h256()?,
        start_height: bits.read_u64(64)?,
        until_ms: bits.read_u64(64)?,
    };
    (bits.exhausted() && pin.is_well_formed()).then_some(pin)
}

fn committee(boc: &TonBoc, index: usize, equivocated: bool) -> Option<CommitteeStateV1> {
    let mut bits = reader(boc, index)?;
    let state = CommitteeStateV1 {
        root: bits.read_h256()?,
        until_ms: bits.read_u64(64)?,
        start: bits.read_u64(64)?,
        high: bits.read_u64(64)?,
        generation: bits.read_u64(64)?,
        equivocated,
    };
    let n = bits.read_usize(8)?;
    let mut chunk = bits.read_ref()?;
    if !bits.exhausted()
        || !is_valid_committee_size(n)
        || state.start == 0
        || state.generation == 0
        || state.high < state.start - 1
        || (equivocated && state.until_ms != 0)
        || (!equivocated && state.until_ms == 0)
    {
        return None;
    }
    let mut keys = Vec::with_capacity(n);
    while keys.len() < n {
        let mut bits = reader(boc, chunk)?;
        for _ in 0..(n - keys.len()).min(2) {
            let mut key = [0; 48];
            for byte in &mut key {
                *byte = u8::try_from(bits.read_u64(8)?).ok()?;
            }
            keys.push(key);
        }
        let continued = bits.read_bit()?;
        if continued != (keys.len() < n) {
            return None;
        }
        if continued {
            chunk = bits.read_ref()?;
        }
        if !bits.exhausted() {
            return None;
        }
    }
    (is_canonical_order(&keys) && committee_root(&keys) == Some(state.root)).then_some(state)
}

fn checkpoints(boc: &TonBoc, index: usize) -> Option<Vec<(u64, H256)>> {
    let mut bits = reader(boc, index)?;
    let count = bits.read_usize(2)?;
    let mut checkpoints = Vec::with_capacity(count);
    let mut previous = 0;
    for _ in 0..count {
        let height = bits.read_u64(64)?;
        let hash = bits.read_h256()?;
        if height <= previous || hash == [0; 32] {
            return None;
        }
        checkpoints.push((height, hash));
        previous = height;
    }
    bits.exhausted().then_some(checkpoints)
}

fn recovery_row(
    cells: &TonAccountCells,
    index: usize,
    operation_id: u64,
) -> Option<TonRecoveryStateV1> {
    let mut bits = reader(&cells.boc, index)?;
    let stage = u8::try_from(bits.read_u64(3)?).ok()?;
    let phase = u8::try_from(bits.read_u64(2)?).ok()?;
    let attempt = bits.read_u64(64)?;
    // A bounced mint enters failed unconsume at attempt zero, before its first paid retry.
    if !(1..=5).contains(&stage) || (attempt == 0 && (stage, phase) != (4, 2)) {
        return None;
    }
    let mut identity = CellBuilder::new();
    // Exactly nonce64 + amount96 + count10 + nextId64 + queryId64.
    for _ in 0..298 {
        identity.store_bit(bits.read_bit()?).ok()?;
    }
    bits.read_u64(2)?; // Mutable result is not part of the immutable cause.
    let tail_index = bits.read_ref()?;
    let tail = code_ref(cells, tail_index)?;
    if !bits.exhausted() {
        return None;
    }
    let mut tail_bits = reader(&cells.boc, tail_index)?;
    let tail_length = tail_bits.remaining_bits()?;
    let is_void = tail_bits.read_bit()?;
    if tail_length != if is_void { 526 } else { 791 } || tail_bits.remaining_refs()? != 0 {
        return None;
    }
    // ConsumeTail commits the exact recipient/response bytes. The locked contract admits
    // a standard response address in any workchain; do not impose the minter's workchain.
    let mut tail_bits = reader(&cells.boc, tail_index)?;
    let mut tail_cell = CellBuilder::new();
    while tail_bits.remaining_bits()? > 0 {
        tail_cell.store_bit(tail_bits.read_bit()?).ok()?;
    }
    let tail_cell = tail_cell.build();
    if *tail_cell.hash() != tail.hash || tail_cell.depth() != tail.depth {
        return None;
    }
    identity
        .store_ref(CellRef::opaque(tail.hash, tail.depth))
        .ok()?;
    let mut row_bits = reader(&cells.boc, index)?;
    let mut row = CellBuilder::new();
    for _ in 0..369 {
        row.store_bit(row_bits.read_bit()?).ok()?;
    }
    row.store_ref(tail_cell).ok()?;
    let row_boc = row.build().to_boc().ok()?;
    Some(TonRecoveryStateV1 {
        operation_id,
        identity: *identity.build().hash(),
        stage,
        phase,
        attempt,
        row_boc,
    })
}

fn label(bits: &mut TonBitReader<'_>, maximum: usize) -> Option<(u64, usize)> {
    let length;
    let long_or_same = bits.read_bit()?;
    let same = if long_or_same {
        bits.read_bit()?
    } else {
        false
    };
    if !long_or_same {
        let mut unary = 0;
        while bits.read_bit()? {
            unary += 1;
            if unary > maximum {
                return None;
            }
        }
        length = unary;
    } else if !same {
        length = bits.read_usize(ton_hashmap_uint_len_bits(maximum))?;
    } else {
        let value = bits.read_bit()?;
        length = bits.read_usize(ton_hashmap_uint_len_bits(maximum))?;
        if length > maximum {
            return None;
        }
        return Some((
            if value {
                if length == 0 {
                    0
                } else {
                    u64::MAX >> (64 - length)
                }
            } else {
                0
            },
            length,
        ));
    }
    if length > maximum {
        return None;
    }
    Some((bits.read_u64(length)?, length))
}

fn recovery_dictionary(
    cells: &TonAccountCells,
    index: usize,
    prefix: u64,
    remaining: usize,
    next_id: u64,
    rows: &mut Vec<TonRecoveryStateV1>,
) -> Option<()> {
    let mut bits = reader(&cells.boc, index)?;
    let (suffix, length) = label(&mut bits, remaining)?;
    let prefix = if length == 64 {
        suffix
    } else {
        (prefix << length) | suffix
    };
    let remaining = remaining.checked_sub(length)?;
    if remaining == 0 {
        if rows.len() >= 512 || prefix == 0 || prefix >= next_id {
            return None;
        }
        let row = recovery_row(cells, bits.read_ref()?, prefix)?;
        if !bits.exhausted() {
            return None;
        }
        rows.push(row);
    } else {
        let left = bits.read_ref()?;
        let right = bits.read_ref()?;
        if !bits.exhausted() {
            return None;
        }
        recovery_dictionary(cells, left, prefix << 1, remaining - 1, next_id, rows)?;
        recovery_dictionary(
            cells,
            right,
            (prefix << 1) | 1,
            remaining - 1,
            next_id,
            rows,
        )?;
    }
    Some(())
}

fn parse(cells: &TonAccountCells) -> Option<TonMinterStateV1> {
    let locked = locked_code_refs();
    if code_ref(cells, cells.code)? != locked[0] {
        return None;
    }
    let mut bits = reader(&cells.boc, cells.data)?;
    let initialized = bits.read_bit()?;
    let equivocated = bits.read_bit()?;
    let total_supply = ton_read_canonical_coins(&mut bits)?;
    let pending_supply = ton_read_canonical_coins(&mut bits)?;
    let outbound_nonce = bits.read_u64(64)?;
    let op_count = bits.read_u64(64)?;
    let control_nonce = bits.read_u64(64)?;
    let parliament_paused = bits.read_bit()?;
    let fast_pause_until_ms = bits.read_u64(64)?;
    let deployed_buckets = bits.read_u64(64)?;
    let config = bits.read_ref()?;
    let committee_index = bits.read_ref()?;
    let checkpoint_index = bits.read_ref()?;
    let recovery_index = bits.read_ref()?;
    if !bits.exhausted() {
        return None;
    }
    let mut config = reader(&cells.boc, config)?;
    let network = config.read_h256()?;
    let instance = config.read_h256()?;
    let revision = u32::try_from(config.read_u64(32)?).ok()?;
    let max_supply = ton_read_canonical_coins(&mut config)?;
    let initial = initial(&cells.boc, config.read_ref()?)?;
    if code_ref(cells, config.read_ref()?)? != locked[1]
        || code_ref(cells, config.read_ref()?)? != locked[2]
        || !config.exhausted()
        || network == [0; 32]
        || instance == [0; 32]
        || revision == 0
        || max_supply == 0
        || max_supply >= (1_u128 << 96)
        || total_supply.checked_add(pending_supply)? > max_supply
    {
        return None;
    }
    let committee = committee(&cells.boc, committee_index, equivocated)?;
    if committee.generation < initial.generation {
        return None;
    }
    if committee.generation == initial.generation
        && (committee.root != initial.committee_root
            || committee.start != initial.start_height
            || (!equivocated && committee.until_ms != initial.until_ms))
    {
        return None;
    }
    let checkpoints = checkpoints(&cells.boc, checkpoint_index)?;
    let mut book = reader(&cells.boc, recovery_index)?;
    let next_operation_id = book.read_u64(64)?;
    let count = book.read_usize(10)?;
    let activated_buckets = book.read_u64(64)?;
    if next_operation_id == 0 || count > 512 || activated_buckets > deployed_buckets {
        return None;
    }
    let mut recovery = Vec::with_capacity(count);
    if book.read_bit()? {
        recovery_dictionary(
            cells,
            book.read_ref()?,
            0,
            64,
            next_operation_id,
            &mut recovery,
        )?;
    }
    if recovery.len() != count || !book.exhausted() {
        return None;
    }
    Some(TonMinterStateV1 {
        initialized,
        network,
        instance,
        revision,
        initial,
        committee,
        checkpoints,
        total_supply,
        pending_supply,
        max_supply,
        outbound_nonce,
        op_count,
        control_nonce,
        parliament_paused,
        fast_pause_until_ms,
        deployed_buckets,
        activated_buckets,
        next_operation_id,
        recovery,
    })
}

/// Open an exact Account root and project only the locked SCCP minter's persistent schema.
///
/// # Errors
/// Refuses substituted code/depth, malformed or partial data and over-capacity recovery books.
pub fn parse_minter_state(
    account_state: &[u8],
    expected_account_hash: &H256,
    account: &H256,
    memory: &Memory<'_>,
) -> Result<TonMinterStateV1, TonNativeSourceError> {
    let cells =
        wallet_state::open_account_state(account_state, expected_account_hash, account, memory)?;
    parse(&cells).ok_or(TonNativeSourceError::InvalidBoc)
}

#[cfg(test)]
mod tests;
