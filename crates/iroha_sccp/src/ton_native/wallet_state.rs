//! Bounded wallet v5r1 account-state authentication; no getter execution or VM.

use super::*;

/// Hash of the immutable standard wallet v5r1 code (wallet-contract-v5 release).
pub const CODE_HASH: H256 = [
    0x20, 0x83, 0x4b, 0x7b, 0x72, 0xb1, 0x12, 0x14, 0x7e, 0x1b, 0x2f, 0xb4, 0x57, 0xb8, 0x4e, 0x74,
    0xd1, 0xa3, 0x0f, 0x04, 0xf7, 0x37, 0xd4, 0xf6, 0x2a, 0x66, 0x8e, 0x95, 0x52, 0xd2, 0xb7, 0x2f,
];

fn skip_balance(reader: &mut TonBitReader<'_>) -> Option<()> {
    reader.skip_bits(5)?;
    ton_skip_currency_collection(reader)
}

fn account_cells(
    bytes: &[u8],
    expected: &H256,
    account: &H256,
    memory: &Memory<'_>,
) -> Option<TonAccountCells> {
    let (boc, computed, root) = ton_open_canonical_with(bytes, expected, memory).ok()?;
    let root = ton_virtual_root_index(&boc, root)?;
    let mut reader = TonBitReader::new(boc.cells.get(root)?)?;
    if !reader.read_bit()? || ton_read_canonical_std_address(&mut reader)?.account != *account {
        return None;
    }
    ton_skip_storage_used(&mut reader)?;
    match reader.read_u64(3)? {
        0 => (),
        1 => {
            reader.read_h256()?;
        }
        _ => return None,
    }
    reader.skip_bits(32)?;
    if reader.read_bit()? {
        ton_skip_grams(&mut reader)?;
    }
    reader.skip_bits(64)?;
    ton_skip_currency_collection(&mut reader)?;
    if !reader.read_bit()? {
        return None;
    } // account_active$1
    // Standard wallet and locked minter accounts have no split depth or TickTock handlers.
    if reader.read_bit()? || reader.read_bit()? || !reader.read_bit()? {
        return None;
    }
    let code = reader.read_ref()?;
    if !reader.read_bit()? {
        return None;
    }
    let data = reader.read_ref()?;
    if reader.read_bit()? || !reader.exhausted() {
        return None;
    } // no libraries
    Some(TonAccountCells {
        boc,
        computed,
        code,
        data,
    })
}

/// Original bounded account cells under their authenticated state root.
pub struct TonAccountCells {
    /// Account bag of cells.
    pub boc: TonBoc,
    /// Validated per-level cell hashes.
    pub computed: Buffer<TonComputedCell>,
    /// Exact `StateInit` code reference.
    pub code: usize,
    /// Exact `StateInit` data reference.
    pub data: usize,
}

/// Open an active ordinary account, checking its exact root and address.
///
/// # Errors
/// Refuses malformed account state or unsupported `StateInit` modifiers.
pub fn open_account_state(
    bytes: &[u8],
    expected: &H256,
    account: &H256,
    memory: &Memory<'_>,
) -> Result<TonAccountCells, TonNativeSourceError> {
    account_cells(bytes, expected, account, memory).ok_or(TonNativeSourceError::InvalidBoc)
}

fn account_seqno(
    bytes: &[u8],
    expected: &H256,
    account: &H256,
    wallet_id: u32,
    memory: &Memory<'_>,
) -> Option<u32> {
    let TonAccountCells {
        boc,
        computed,
        code,
        data,
    } = account_cells(bytes, expected, account, memory)?;
    if ton_original_tree_hash(&computed, code)? != CODE_HASH {
        return None;
    }
    let mut data = TonBitReader::new(boc.cells.get(ton_virtual_root_index(&boc, data)?)?)?;
    data.read_bit()?; // signature_allowed does not change seqno monotonicity
    let seqno = u32::try_from(data.read_u64(32)?).ok()?;
    if data.read_u64(32)? != u64::from(wallet_id) {
        return None;
    }
    data.read_h256()?; // original account hash already binds the deployed public key
    if data.read_bit()? {
        data.read_ref()?;
    } // extensions dictionary
    data.exhausted().then_some(seqno)
}

/// Authenticate the shard state update, exact account dictionary entry and v5r1 data.
///
/// # Errors
/// Refuses malformed bounded cell proofs, mismatched roots and nonstandard wallet code.
pub fn open_wallet_state(
    block_id: TonBlockIdExtV1,
    header: &[u8],
    state_proof: &[u8],
    account_state: &[u8],
    account: &H256,
    wallet_id: u32,
    memory: &Memory<'_>,
) -> Result<u32, TonNativeSourceError> {
    let hash = authenticated_account_hash(block_id, header, state_proof, account, memory)?;
    account_seqno(account_state, &hash, account, wallet_id, memory)
        .ok_or(TonNativeSourceError::InvalidBoc)
}

/// Authenticate the exact account entry through the shard block's state update.
///
/// # Errors
/// Refuses malformed proofs and mismatched block/state/account commitments.
pub fn authenticated_account_hash(
    block_id: TonBlockIdExtV1,
    header: &[u8],
    state_proof: &[u8],
    account: &H256,
    memory: &Memory<'_>,
) -> Result<H256, TonNativeSourceError> {
    let invalid = TonNativeSourceError::InvalidBoc;
    ton_open_shard_block_with(block_id, header, memory)?;
    let (header_boc, header_hashes, header_root) =
        ton_open_canonical_with(header, &block_id.root_hash, memory)?;
    let state_hash = ton_parse_block(&header_boc, &header_hashes, header_root)
        .and_then(|block| block.new_state_hash)
        .ok_or(invalid)?;
    let boc = parse_ton_boc_with(state_proof, memory).ok_or(invalid)?;
    if boc.roots.is_empty() || boc.roots.len() > 2 {
        return Err(invalid);
    }
    let computed = ton_boc_cell_hashes_in_order_with(&boc, (0..boc.cells.len()).rev(), memory)
        .ok_or(invalid)?;
    let mut roots = boc
        .roots
        .iter()
        .copied()
        .filter(|root| ton_proven_root_hash(&boc, &computed, *root) == Some(state_hash));
    let root = roots.next().ok_or(invalid)?;
    if roots.next().is_some() {
        return Err(invalid);
    }
    let root = ton_virtual_root_index(&boc, root).ok_or(invalid)?;
    let mut reader = TonBitReader::new(boc.cells.get(root).ok_or(invalid)?).ok_or(invalid)?;
    if reader.read_u64(32) != Some(u64::from(TON_SHARD_STATE_CONSTRUCTOR))
        || reader.read_i32(32) != Some(TON_MAINNET_GLOBAL_ID)
        || ton_read_shard_ident(&mut reader) != Some((block_id.workchain, block_id.shard))
        || reader.read_u64(32) != Some(u64::from(block_id.seqno))
    {
        return Err(invalid);
    }
    reader.skip_bits(32 + 32 + 64 + 32).ok_or(invalid)?;
    reader.read_ref().ok_or(invalid)?;
    reader.read_bit().ok_or(invalid)?;
    let accounts = reader.read_ref().ok_or(invalid)?;
    let root = ton_hashmap_aug_e_root(&boc, accounts, skip_balance).ok_or(invalid)?;
    let mut leaf =
        ton_hashmap_aug_leaf_reader(&boc, root, account, 256, skip_balance).ok_or(invalid)?;
    skip_balance(&mut leaf).ok_or(invalid)?;
    let account_cell = leaf.read_ref().ok_or(invalid)?;
    leaf.read_h256().ok_or(invalid)?;
    leaf.read_u64(64).ok_or(invalid)?;
    if !leaf.exhausted() {
        return Err(invalid);
    }
    ton_original_tree_hash(&computed, account_cell).ok_or(invalid)
}
