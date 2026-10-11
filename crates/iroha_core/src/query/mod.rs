//! This module contains [`store::LiveQueryStore`] and helpers.
#![allow(clippy::disallowed_types)]
pub(crate) mod archive_finality;
mod archive_index;
pub mod cursor;
pub mod final_promotion_account_custody;
/// Coherent native deployment custody and durable final-promotion operation history.
pub mod final_promotion_authority;
mod finalized_archive_fs;
#[cfg(test)]
mod fixture_write_tests;
pub mod index_status;
mod journal_io;
/// Challenged native Musubi inventory readback; daemon effects remain separately owned.
pub mod musubi_pin_outbox;
/// Original complete native context projection archive, authenticated by canonical R.
pub mod native_context_archive;
pub mod native_musubi_storage;
/// Historical receipt openings from original writes and native certified execution.
pub mod native_receipts;
pub mod pagination;
pub mod projection_checkpoint;
pub mod projection_checkpoint_journal;
pub mod projection_rowset;
pub mod projection_shard;
/// Finalized governed provider-admission authority.
pub mod provider_admission;
pub mod provider_attestation_inventory;
pub mod provider_ingest_finalized;
pub mod provider_ingest_source;
/// Raw role-13 custody history and same-State block finality; signing still requires executed Check.
pub mod release_manifest_authority;
pub mod reputation_finalized;
pub(crate) mod signer_check;
#[cfg(any(test, feature = "iroha-core-tests"))]
pub mod signer_check_test_fixture;
pub(crate) mod signer_custody_history;
/// Same-State certified-chain block finality verification for signer consumers.
pub mod signer_finality;
pub mod snapshot;
/// Explicit funded public-ballot setup; never production admission or finalized evidence.
#[cfg(any(test, feature = "iroha-core-tests"))]
pub mod standalone_plain_test_fixture;
pub mod store;
pub mod stream_token_authority;
/// Same-State historical native StreamToken custody control reader.
pub mod stream_token_custody;
/// Deterministic indexed stream-token gateway admission transitions.
/// Native gateway transitions and source-bound finalized serving observations.
pub mod stream_token_gateway;
/// Read-only bounded role-16 native row and index decoder; admission remains closed.
pub mod topology_authority;
use crate::state::{WorldReadOnly, WorldStateSnapshot};
use iroha_data_model::block::consensus::EvidenceRecord;
use mv::storage::StorageReadOnly;
#[cfg(any(test, feature = "iroha-core-tests"))]
use std::{
    convert::TryFrom,
    num::{NonZeroU64, NonZeroUsize},
};
/// Return the number of persisted evidence entries currently stored in WSV.
pub fn evidence_count(state: &impl WorldStateSnapshot) -> usize {
    evidence_count_from_world(state.world())
}
/// Return the number of persisted evidence entries currently stored in WSV.
pub fn evidence_count_from_world(world: &impl WorldReadOnly) -> usize {
    world.consensus_evidence().iter().count()
}
/// Snapshot persisted evidence records ordered latest-first.
pub fn evidence_list_snapshot(state: &impl WorldStateSnapshot) -> Vec<EvidenceRecord> {
    evidence_list_snapshot_from_world(state.world())
}
/// Snapshot persisted evidence records ordered latest-first.
pub fn evidence_list_snapshot_from_world(world: &impl WorldReadOnly) -> Vec<EvidenceRecord> {
    let mut records: Vec<_> = world
        .consensus_evidence()
        .iter()
        .map(|(_, record)| record.canonical_projection())
        .collect();
    records.sort_by(|a, b| {
        (a.recorded_at_height, a.recorded_at_view, a.recorded_at_ms)
            .cmp(&(b.recorded_at_height, b.recorded_at_view, b.recorded_at_ms))
            .reverse()
    });
    records
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        kura::Kura,
        query::store::LiveQueryStore,
        state::{State, World},
    };
    use std::sync::Arc;
    #[test]
    fn evidence_world_helpers_match_state_snapshot_helpers_on_empty_state() {
        let kura = Kura::blank_kura_for_testing();
        let query = LiveQueryStore::start_test();
        let state = State::new_for_testing(World::default(), Arc::clone(&kura), query);
        let world = state.world_view();
        let view = state.view();
        assert_eq!(evidence_count_from_world(&world), evidence_count(&view));
        assert_eq!(
            evidence_list_snapshot_from_world(&world),
            evidence_list_snapshot(&view),
        );
    }
    #[test]
    fn next_height_for_state_uses_transaction_storage_height() {
        let kura = Kura::blank_kura_for_testing();
        let query = LiveQueryStore::start_test();
        let mut state = State::new_for_testing(World::default(), Arc::clone(&kura), query);
        let (first, first_u64) = next_height_for_state(&mut state);
        let (second, second_u64) = next_height_for_state(&mut state);
        assert_eq!(usize::from(first), 1);
        assert_eq!(first, second);
        assert_eq!(first_u64, second_u64);
        let mut transactions = state.transactions.block();
        transactions.insert_block(std::collections::HashSet::new(), first);
        transactions.commit().expect("commit transaction height");
        let (third, third_u64) = next_height_for_state(&mut state);
        assert_eq!(usize::from(third), 2);
        assert_eq!(third_u64.get(), 2);
    }
}
#[cfg(any(test, feature = "iroha-core-tests"))]
fn next_height_for_state(state: &mut crate::state::State) -> (NonZeroUsize, NonZeroU64) {
    let next = state.transactions.latest_height().saturating_add(1);
    let nz_usize = NonZeroUsize::new(next).expect("height non-zero");
    let nz_u64 =
        NonZeroU64::new(u64::try_from(next).expect("height fits u64")).expect("height non-zero");
    (nz_usize, nz_u64)
}
// Query fixtures publish only World changes. They create neither finalized
// block hashes nor transaction membership, and publication failures are fatal.
/// Insert a verifying key record directly into WSV for tests.
#[cfg(any(test, feature = "iroha-core-tests"))]
pub fn insert_verifying_key_record_for_test(
    state: &mut crate::state::State,
    id: iroha_data_model::proof::VerifyingKeyId,
    rec: iroha_data_model::proof::VerifyingKeyRecord,
) {
    let circuit_key = (rec.circuit_id.clone(), rec.version);
    let (_, height_u64) = next_height_for_state(state);
    let header = iroha_data_model::block::BlockHeader::new(height_u64, None, None, 0, 0);
    let mut block = state.block(header);
    let mut stx = block.transaction();
    stx.world.verifying_keys.insert(id.clone(), rec);
    if !circuit_key.0.trim().is_empty() {
        stx.world.verifying_keys_by_circuit.insert(circuit_key, id);
    }
    stx.apply();
    block
        .commit_world_overlay_for_testing()
        .expect("commit query fixture world overlay");
}
/// Insert a consensus evidence record directly into WSV for tests.
#[cfg(any(test, feature = "iroha-core-tests"))]
pub fn insert_evidence_record_for_test(state: &mut crate::state::State, record: EvidenceRecord) {
    let (_, height_u64) = next_height_for_state(state);
    let header = iroha_data_model::block::BlockHeader::new(height_u64, None, None, 0, 0);
    let mut block = state.block(header);
    let mut stx = block.transaction();
    let key = crate::sumeragi::evidence::evidence_key(&record.evidence);
    let record =
        crate::state::RetainedEvidenceRecord::from_fixture(record, &state.ivm_execution_budget())
            .expect("query fixture graph is funded by the original execution pool");
    stx.world.consensus_evidence.insert(key, record);
    stx.apply();
    block
        .commit_world_overlay_for_testing()
        .expect("commit query fixture world overlay");
}
/// Insert a contract instance record directly into WSV for tests.
#[cfg(any(test, feature = "iroha-core-tests"))]
pub fn insert_contract_instance_for_test(
    state: &mut crate::state::State,
    contract_address: iroha_data_model::smart_contract::ContractAddress,
    code_hash: iroha_crypto::Hash,
) {
    let (_, height_u64) = next_height_for_state(state);
    let header = iroha_data_model::block::BlockHeader::new(height_u64, None, None, 0, 0);
    let mut block = state.block(header);
    let mut stx = block.transaction();
    stx.world
        .contract_instances
        .insert(contract_address, code_hash);
    stx.apply();
    block
        .commit_world_overlay_for_testing()
        .expect("commit query fixture world overlay");
}
/// Insert a proof record directly into WSV for tests.
#[cfg(any(test, feature = "iroha-core-tests"))]
pub fn insert_proof_record_for_test(
    state: &mut crate::state::State,
    id: iroha_data_model::proof::ProofId,
    mut rec: iroha_data_model::proof::ProofRecord,
) {
    rec.id = id;
    let (_, height_u64) = next_height_for_state(state);
    let header = iroha_data_model::block::BlockHeader::new(height_u64, None, None, 0, 0);
    let mut block = state.block(header);
    let mut stx = block.transaction();
    stx.world.insert_proof_record(rec);
    stx.apply();
    block
        .commit_world_overlay_for_testing()
        .expect("commit query fixture proof record");
}
/// Insert proof TLV tags directly into WSV indexes for tests.
#[cfg(any(test, feature = "iroha-core-tests"))]
pub fn insert_proof_tags_for_test(
    state: &mut crate::state::State,
    id: iroha_data_model::proof::ProofId,
    mut tags: Vec<[u8; 4]>,
) {
    tags.sort_unstable();
    tags.dedup();
    let (_, height_u64) = next_height_for_state(state);
    let header = iroha_data_model::block::BlockHeader::new(height_u64, None, None, 0, 0);
    let mut block = state.block(header);
    let mut stx = block.transaction();
    stx.world.proof_tags.insert(id.clone(), tags.clone());
    for tag in tags {
        let tag_slice: &[u8] = &tag;
        let mut ids = stx
            .world
            .proofs_by_tag
            .get(tag_slice)
            .cloned()
            .unwrap_or_default();
        if !ids.iter().any(|existing| existing == &id) {
            ids.push(id.clone());
            ids.sort();
        }
        stx.world.proofs_by_tag.insert(tag, ids);
    }
    stx.apply();
    block
        .commit_world_overlay_for_testing()
        .expect("commit query fixture proof tags");
}
/// Insert a governance proposal record for tests.
#[cfg(any(test, feature = "iroha-core-tests"))]
pub fn insert_gov_proposal_for_test(
    state: &mut crate::state::State,
    id: [u8; 32],
    rec: crate::state::GovernanceProposalRecord,
) {
    let (_, next_height_u64) = next_height_for_state(state);
    let header = iroha_data_model::block::BlockHeader::new(next_height_u64, None, None, 0, 0);
    let mut block = state.block(header);
    let mut stx = block.transaction();
    stx.world
        .put_governance_proposal(id, rec)
        .expect("query-test proposal must satisfy first-release JSON bounds");
    stx.apply();
    block
        .commit_world_overlay_for_testing()
        .expect("commit query fixture governance overlay");
}
/// Insert a governance referendum record for tests.
#[cfg(any(test, feature = "iroha-core-tests"))]
pub fn insert_gov_referendum_for_test(
    state: &mut crate::state::State,
    id: String,
    rec: crate::state::GovernanceReferendumRecord,
) {
    let (_, next_height_u64) = next_height_for_state(state);
    let header = iroha_data_model::block::BlockHeader::new(next_height_u64, None, None, 0, 0);
    let mut block = state.block(header);
    let mut stx = block.transaction();
    stx.world.governance_referenda.insert(id, rec);
    stx.apply();
    block
        .commit_world_overlay_for_testing()
        .expect("commit query fixture governance overlay");
}
/// Insert governance locks for a referendum for tests.
#[cfg(any(test, feature = "iroha-core-tests"))]
pub fn insert_gov_locks_for_test(
    state: &mut crate::state::State,
    id: String,
    locks: crate::state::GovernanceLocksForReferendum,
) {
    let (_, next_height_u64) = next_height_for_state(state);
    let header = iroha_data_model::block::BlockHeader::new(next_height_u64, None, None, 0, 0);
    let mut block = state.block(header);
    let mut stx = block.transaction();
    stx.world.put_governance_locks(id, locks);
    stx.apply();
    block
        .commit_world_overlay_for_testing()
        .expect("commit query fixture governance overlay");
}

/// Current finalized native lease authorization for remote repair chunk sources.
pub mod repair_source;
