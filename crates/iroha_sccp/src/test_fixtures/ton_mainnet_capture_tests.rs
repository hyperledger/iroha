//! Recorded TON mainnet liteserver answers (`fixtures/sccp/rpc/ton/transport`, decoded by
//! `test_support::ton_capture`) through the native primitives (`specs/sccp.md` §4.13.3, §11):
//! a key block's configs 34, 28 and 15, the config-28 shuffle of the masterchain subset against
//! the subset hash real blocks carry, Simplex signatures of a block and of a key-block hop,
//! liteserver header, shard-link and transaction proofs that prune `state_update`, and a full
//! block served as an indexed `BoC` with cache bits.

use super::*;
use crate::test_support::ton_capture::{
    CAPTURED_ACCOUNT, CAPTURED_BLOCK_SEQNO, CAPTURED_KEY_BLOCK_SEQNO,
    CAPTURED_PREVIOUS_KEY_BLOCK_SEQNO, CAPTURED_TRANSACTION_LT, forward_link, full_block,
    key_block_config, shard_block_proof, transaction,
};

/// `K`'s header (from its full header proof) and validator epoch (from its state).
fn key_block_epoch() -> (TonMcHeaderV1, TonEpochConfigV1) {
    let config = key_block_config();
    let (header, shard) =
        ton_open_masterchain_block(config.block, &config.state_proof, None).expect("K header");
    assert_eq!(shard, None);
    let state_hash = header
        .new_state_hash
        .expect("the header proof opens state_update");
    let epoch = ton_open_state_config(&state_hash, &config.config_proof).expect("K configs");
    (header, epoch)
}

/// The validator config a key block's `McBlockExtra` carries, from a forward link's
/// `config_proof` rooted at that block.
fn block_extra_config(proof: &[u8], root_hash: &H256) -> TonValidatorConfigV1 {
    let (boc, _computed, root) = ton_open_canonical(proof, root_hash).expect("rooted at `from`");
    let block = ton_virtual_root_index(&boc, root).expect("block");
    let extra = ton_virtual_root_index(&boc, boc.cells[block].refs[3]).expect("extra");
    let mut reader = TonBitReader::new(&boc.cells[extra]).expect("extra cell");
    assert_eq!(
        reader.read_u64(32),
        Some(u64::from(TON_BLOCK_EXTRA_CONSTRUCTOR))
    );
    for _ in 0..3 {
        reader.read_ref().expect("descriptor ref");
    }
    reader.skip_bits(512).expect("rand_seed, created_by");
    assert_eq!(reader.read_bit(), Some(true), "masterchain extra");
    let custom = ton_virtual_root_index(&boc, reader.read_ref().expect("custom")).expect("custom");
    let mut custom = TonBitReader::new(&boc.cells[custom]).expect("custom cell");
    assert_eq!(
        custom.read_u64(16),
        Some(u64::from(TON_MC_BLOCK_EXTRA_CONSTRUCTOR))
    );
    assert_eq!(
        custom.read_bit(),
        Some(true),
        "a key block carries its config"
    );
    for _ in 0..2 {
        if custom.read_bit().expect("Maybe") {
            custom.read_ref().expect("shard hashes or fees");
        }
    }
    ton_skip_currency_collection(&mut custom).expect("fees");
    ton_skip_currency_collection(&mut custom).expect("create");
    custom.read_ref().expect("auxiliary");
    custom.read_h256().expect("config address");
    let dictionary = custom.read_ref().expect("config dictionary");
    ton_config_from_dictionary(&boc, dictionary).expect("configs 34 and 28")
}

#[test]
fn captured_key_block_epoch_and_shuffled_subset_verify_a_simplex_block() {
    let (key, epoch) = key_block_epoch();
    assert!(key.key_block);
    assert_eq!(key.block_id.seqno, CAPTURED_KEY_BLOCK_SEQNO);
    assert_eq!(key.prev_key_block_seqno, CAPTURED_PREVIOUS_KEY_BLOCK_SEQNO);
    assert_eq!(epoch.validators.validators.len(), 376);
    assert_eq!(epoch.validators.main_validator_count, 100);
    assert!(epoch.validators.shuffle_masterchain_validators);
    assert_eq!(epoch.stake_held_for, 32_768);
    assert_eq!(
        (epoch.validators.valid_since, epoch.validators.valid_until),
        (1_790_463_752, 1_790_529_288)
    );

    let link = forward_link("get_block_proof_forward");
    assert_eq!(
        (link.from, link.to.seqno),
        (key.block_id, CAPTURED_BLOCK_SEQNO)
    );
    assert!(!link.to_key_block);
    // The liteserver's header proof prunes `state_update`; the signed identity opens anyway.
    let (block, _) = ton_open_masterchain_block(link.to, &link.dest_proof, None).expect("B header");
    assert_eq!(block.new_state_hash, None);
    assert_eq!(block.prev_key_block_seqno, CAPTURED_KEY_BLOCK_SEQNO);
    let TonBlockSignaturesV1::Simplex(simplex) = &link.signatures else {
        panic!("mainnet signs under Simplex");
    };
    assert_eq!(
        (simplex.catchain_seqno, simplex.validator_list_hash_short),
        (block.catchain_seqno, block.validator_list_hash_short)
    );

    // Config 28 shuffles the first `main` validators per catchain session: the shuffled subset
    // reproduces the hash the block header carries, the unshuffled one does not.
    let subset = ton_select_masterchain_validator_set(&epoch.validators, block.catchain_seqno)
        .expect("subset");
    assert_eq!(subset.validators.len(), 100);
    assert_eq!(
        subset.validator_list_hash_short,
        block.validator_list_hash_short
    );
    assert_ne!(subset.validators[..], epoch.validators.validators[..100]);
    let mut unshuffled = epoch.validators.clone();
    unshuffled.shuffle_masterchain_validators = false;
    assert_ne!(
        ton_select_masterchain_validator_set(&unshuffled, block.catchain_seqno)
            .expect("subset")
            .validator_list_hash_short,
        block.validator_list_hash_short
    );
    assert_ne!(
        ton_select_masterchain_validator_set(&epoch.validators, block.catchain_seqno + 1)
            .expect("subset")
            .validator_list_hash_short,
        block.validator_list_hash_short
    );

    ton_verify_masterchain_signatures(&block, &epoch.validators, &link.signatures)
        .expect("the Simplex signatures verify");
    assert_eq!(
        ton_verify_masterchain_signatures(&block, &unshuffled, &link.signatures),
        Err(TonNativeSourceError::InvalidValidatorSet)
    );
    let mut forged = simplex.clone();
    forged.signatures[0].signature[0] ^= 1;
    assert_eq!(
        ton_verify_masterchain_signatures(
            &block,
            &epoch.validators,
            &TonBlockSignaturesV1::Simplex(forged)
        ),
        Err(TonNativeSourceError::InvalidSignatures)
    );
    let mut other_session = simplex.clone();
    other_session.session_id[0] ^= 1;
    assert_eq!(
        ton_verify_masterchain_signatures(
            &block,
            &epoch.validators,
            &TonBlockSignaturesV1::Simplex(other_session)
        ),
        Err(TonNativeSourceError::InvalidSignatures)
    );
}

#[test]
fn captured_key_block_hop_verifies_under_the_previous_epoch() {
    let hop = forward_link("get_block_proof_key_hop");
    assert!(hop.to_key_block);
    assert_eq!(
        (hop.from.seqno, hop.to.seqno),
        (CAPTURED_PREVIOUS_KEY_BLOCK_SEQNO, CAPTURED_KEY_BLOCK_SEQNO)
    );
    let (key, epoch) = key_block_epoch();
    let (dest, _) = ton_open_masterchain_block(hop.to, &hop.dest_proof, None).expect("K header");
    assert_eq!(
        (
            dest.catchain_seqno,
            dest.validator_list_hash_short,
            dest.prev_key_block_seqno
        ),
        (
            key.catchain_seqno,
            key.validator_list_hash_short,
            key.prev_key_block_seqno
        )
    );
    // `P`'s epoch from its own block (`McBlockExtra.config`) signs `K`.
    let previous = block_extra_config(&hop.config_proof, &hop.from.root_hash);
    assert!(previous.shuffle_masterchain_validators);
    ton_verify_masterchain_signatures(&key, &previous, &hop.signatures).expect("P's epoch signs K");
    // `K` announced no new current set (config 34 is unchanged since `P`).
    assert_eq!(previous.validators, epoch.validators.validators);
    let TonBlockSignaturesV1::Simplex(mut forged) = hop.signatures.clone() else {
        panic!("mainnet signs under Simplex");
    };
    forged.slot += 1;
    assert_eq!(
        ton_verify_masterchain_signatures(&key, &previous, &TonBlockSignaturesV1::Simplex(forged)),
        Err(TonNativeSourceError::InvalidSignatures)
    );
}

#[test]
fn captured_shard_and_transaction_proofs_open_with_a_pruned_state_update() {
    let transaction = transaction();
    let walk = shard_block_proof();
    assert_eq!(walk.links.len(), 1);
    let (registered_id, link_proof) = &walk.links[0];
    assert_eq!(*registered_id, transaction.block);
    // Link 0's proof is the masterchain block's `ShardHashes` path, not a shard header proof.
    let (boc, _computed, root) =
        ton_open_canonical(link_proof, &walk.masterchain.root_hash).expect("masterchain-rooted");
    let block = ton_virtual_root_index(&boc, root).expect("block");
    let extra = ton_parse_masterchain_extra(&boc, boc.cells[block].refs[3]).expect("extra");
    let (registered, _) = ton_select_shard_descriptor(
        &boc,
        extra.shard_hashes_root.expect("shard hashes"),
        TonStdAddress {
            workchain: TON_BASECHAIN_WORKCHAIN,
            account: CAPTURED_ACCOUNT,
        },
    )
    .expect("registered shard block");
    assert_eq!(registered, transaction.block);
    assert!(ton_open_shard_block(*registered_id, link_proof).is_err());

    // The event block's header opens from the transaction proof.
    let header = ton_open_shard_block(transaction.block, &transaction.proof)
        .expect("a shard header with a pruned state_update");
    assert_eq!(
        header.previous.map(|previous| previous.seqno),
        Some(transaction.block.seqno - 1)
    );
    // The jetton master's transaction is found and succeeded; it emits no SCCP event.
    assert_eq!(
        ton_open_sccp_event(
            transaction.block,
            &transaction.proof,
            &transaction.transaction,
            CAPTURED_ACCOUNT,
            CAPTURED_TRANSACTION_LT,
            0,
        ),
        Err(TonNativeSourceError::InvalidOutboundMessage)
    );
    assert_eq!(
        ton_open_sccp_event(
            transaction.block,
            &transaction.proof,
            &transaction.transaction,
            CAPTURED_ACCOUNT,
            CAPTURED_TRANSACTION_LT + 1,
            0,
        ),
        Err(TonNativeSourceError::InvalidTransaction)
    );
}

#[test]
fn captured_full_block_with_cache_bits_opens_as_a_header_proof() {
    let (id, block) = full_block();
    assert_eq!(id.seqno, CAPTURED_BLOCK_SEQNO);
    let (header, registered) =
        ton_open_masterchain_block(id, &block, Some(CAPTURED_ACCOUNT)).expect("full block");
    assert!(header.new_state_hash.is_some());
    let registered = registered.expect("the account's shard block");
    assert_eq!(registered.workchain, TON_BASECHAIN_WORKCHAIN);
    let link = forward_link("get_block_proof_forward");
    let (pruned, _) = ton_open_masterchain_block(link.to, &link.dest_proof, None).expect("B");
    assert_eq!(
        (pruned.catchain_seqno, pruned.validator_list_hash_short),
        (header.catchain_seqno, header.validator_list_hash_short)
    );
    // The recorded bytes carry an index with cache bits; without the index they are malformed.
    let raw = crate::test_support::ton_capture::full_block_raw();
    assert_eq!(raw[4] & 0xe0, 0xe0, "index, CRC and cache bits");
    assert_eq!(ton_boc_single_root_hash_v1(&raw), Some(id.root_hash));
    let mut unindexed = raw;
    unindexed[4] &= !0x80;
    assert!(parse_ton_boc(&unindexed).is_none());
}
