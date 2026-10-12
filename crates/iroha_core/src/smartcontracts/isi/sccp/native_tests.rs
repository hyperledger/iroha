//! Genuine signed-genesis and native certificate tests for the SCCP production hook.

use crate::{
    smartcontracts::Execute as _,
    state::{State, StateReadOnly, World, WorldReadOnly},
    sumeragi::test_chain::{CertifiedTestChain, TestChainConfig},
};
use iroha_crypto::{Algorithm, KeyPair};
use iroha_data_model::{
    Registrable,
    account::{Account, AccountId},
    asset::{AssetBalancePolicy, AssetDefinition, AssetId},
    isi::{Mint, Register, sccp::InitializeSccpV1},
    nexus::{PublicLaneStakeShare, PublicLaneValidatorRecord, PublicLaneValidatorStatus},
    parameter::{
        Parameter,
        system::{SumeragiConsensusMode, SumeragiNposParameters, SumeragiParameter},
    },
    sccp::params::SccpParametersV1,
    sumeragi_finality::{CertifiedResultScope, CertifiedResultV1},
};
use iroha_model_base::{metadata::Metadata, peer::PeerId, topology::LaneId};
use iroha_primitives::numeric::{NumericSpec, Quantity};
use mv::storage::StorageReadOnly;
use std::{num::NonZeroU64, time::Duration};

/// Exact signed NPoS genesis configuration with the original primary-seat prestate.
/// The State executor, genuine CommitQC, Kura and contiguous native reader remain production.
/// This is component prestate, not a claim of transaction-driven staking qualification.
pub(crate) fn native_chain_config() -> TestChainConfig {
    let mut keys = (1..=4)
        .map(|seed| KeyPair::from_seed(vec![seed; 32], Algorithm::BlsNormal))
        .collect::<Vec<_>>();
    keys.sort_by_key(|pair| PeerId::new(pair.public_key().clone()));
    let authority = AccountId::new(
        KeyPair::from_seed(vec![0xce; 32], Algorithm::Ed25519)
            .public_key()
            .clone(),
    );
    let accounts = (1..=4)
        .map(|seed| {
            AccountId::new(
                KeyPair::from_seed(vec![seed + 16; 32], Algorithm::Ed25519)
                    .public_key()
                    .clone(),
            )
        })
        .collect::<Vec<_>>();
    let world = World::with(
        [],
        accounts
            .iter()
            .map(|id| Account::new(id.clone()).build(&authority)),
        [],
    );
    let policy = SumeragiNposParameters {
        epoch_length_blocks: NonZeroU64::new(3_600).unwrap(),
        ..SumeragiNposParameters::default()
    };
    // Seed genuine registered XOR backing before adding any positive staking
    // liability. Startup still reconciles every share, pinned asset and reserve.
    let state = State::new(
        world,
        crate::kura::Kura::blank_kura_for_testing(),
        crate::query::store::LiveQueryStore::start_test(),
    );
    {
        let header = iroha_data_model::block::BlockHeader::new(
            NonZeroU64::new(1).unwrap(),
            None,
            None,
            0,
            0,
        );
        let mut block = state.block(header);
        let mut transaction = block.transaction();
        transaction
            .world
            .parameters
            .set_parameter(Parameter::Custom(policy.clone().into_custom_parameter()))
            .unwrap();
        Register::asset_definition(AssetDefinition::new(
            policy.xor_asset_definition_id.clone(),
            "SCCP custody reserve",
            NumericSpec::fractional(9),
            AssetBalancePolicy::Global,
            None,
        ))
        .execute(&accounts[0], &mut transaction)
        .unwrap();
        for account in &accounts {
            Mint::asset_quantity(
                Quantity::from(10_u32),
                AssetId::new(policy.xor_asset_definition_id.clone(), account.clone()),
            )
            .execute(&accounts[0], &mut transaction)
            .unwrap();
        }
        transaction.apply();
        block.commit_world_overlay_for_testing().unwrap();
    }
    state.world.block().commit();
    let world = state.world;
    {
        let mut block = world.block();
        for (account, key) in accounts.iter().zip(&keys) {
            block.public_lane_validators.insert(
                (LaneId::SINGLE, account.clone()),
                PublicLaneValidatorRecord {
                    lane_id: LaneId::SINGLE,
                    validator: account.clone(),
                    peer_id: PeerId::new(key.public_key().clone()),
                    stake_account: account.clone(),
                    total_stake: Quantity::from(10_u32),
                    self_stake: Quantity::from(10_u32),
                    metadata: Metadata::default(),
                    status: PublicLaneValidatorStatus::Active,
                    activation_height: 1,
                    election_exit_height: None,
                    deactivation_height: None,
                },
            );
            block.public_lane_stake_shares.insert(
                (LaneId::SINGLE, account.clone(), account.clone()),
                PublicLaneStakeShare {
                    lane_id: LaneId::SINGLE,
                    validator: account.clone(),
                    staker: account.clone(),
                    bonded: Quantity::from(10_u32),
                    pending_unbonds: Default::default(),
                    metadata: Metadata::default(),
                },
            );
            let asset = AssetId::new(policy.xor_asset_definition_id.clone(), account.clone());
            block.public_lane_stake_custody.insert(
                (LaneId::SINGLE, account.clone()),
                (asset.clone(), Quantity::from(10_u32)),
            );
            block
                .public_lane_stake_reserves
                .insert(asset, Quantity::from(10_u32));
        }
        block.commit();
    }
    let parameters = SccpParametersV1::taira_default();
    let mut config = TestChainConfig::new(world, 1_000);
    config.validator_keys = Some(keys);
    config.consensus_mode = SumeragiConsensusMode::Npos;
    config.genesis_block_cadence_ms = NonZeroU64::new(1_000).unwrap();
    config.genesis_parameters.extend([
        Parameter::Sumeragi(SumeragiParameter::EpochLengthBlocks(
            policy.epoch_length_blocks,
        )),
        Parameter::Custom(policy.into_custom_parameter()),
    ]);
    let mut nexus = iroha_config::parameters::actual::Nexus::default();
    nexus.staking.unbonding_delay = Duration::from_millis(
        parameters.committee_validity_ms + parameters.forgery_evidence_grace_ms,
    );
    nexus.staking.max_slash_bps = 1;
    config.nexus = Some(nexus);
    config.genesis_instructions.push(
        InitializeSccpV1 {
            parameters,
            reset_nonce: [0x51; 32],
        }
        .into(),
    );
    config
}

#[test]
fn genuine_native_execution_persists_active_header_and_exact_parent_anchor() {
    let mut chain =
        CertifiedTestChain::start(native_chain_config()).expect("genuine SCCP signed genesis");
    let parent = chain
        .state()
        .view()
        .native_execution_tip()
        .expect("original genesis result");
    let genesis = chain.committed(1);
    assert!(genesis.finality_header().is_active());
    assert_eq!(genesis.finality_header().generation(), 1);
    assert_eq!(
        chain
            .state()
            .view()
            .world()
            .sccp_anchor_open()
            .anchors()
            .len(),
        0
    );
    chain.commit_at(2_000, Vec::new());
    let committed = chain.committed(2);
    assert!(committed.finality_header().is_active());
    assert_eq!(committed.finality_header().generation(), 1);
    let view = chain.state().view();
    let anchors = view.world().sccp_anchor_open().anchors();
    assert_eq!(anchors.len(), 1);
    assert_eq!(anchors[0].core_hash, parent.core_hash().0);
    assert_eq!(anchors[0].result, parent.result().0);
    assert!(view.world().sccp_anchor_chunks().iter().next().is_none());
    let block = view.latest_block().unwrap().unwrap();
    let certificate = block.commit_certificate().unwrap();
    let result = CertifiedResultV1::decode(
        certificate.result_preimage(),
        CertifiedResultScope::TairaGlobal,
    )
    .unwrap();
    assert_eq!(block.header().height().get(), 2);
    assert!(block.header().creation_time_ms >= 2_000);
    result
        .check_block(block.header().height().get(), block.header().creation_time_ms)
        .unwrap();
    assert_eq!(result.header(), committed.finality_header());
    assert_eq!(
        result.result().unwrap(),
        view.native_execution_tip().unwrap().result()
    );
    assert!(
        CertifiedResultV1::decode(
            &certificate.result_preimage()[221..],
            CertifiedResultScope::TairaGlobal
        )
        .is_err()
    );
}

#[test]
fn genuine_parent_is_anchored_even_when_missing_height_inputs_degrade_sccp() {
    let chain = CertifiedTestChain::start(native_chain_config()).unwrap();
    let parent = chain.state().view().native_execution_tip().unwrap();
    let candidate = iroha_data_model::block::BlockHeader::new(
        NonZeroU64::new(2).unwrap(),
        Some(parent.iroha_hash()),
        None,
        2_000,
        0,
    );
    let mut overlay = chain.state().block(candidate);
    super::hook::begin_block(&mut overlay, &candidate).unwrap();
    let header = super::hook::finalize_block(&mut overlay, &candidate, None).unwrap();
    assert!(!header.is_active());
    assert_eq!(overlay.world.sccp_degraded_run(), 1);
    assert_eq!(overlay.world.sccp_committee_current(), 1);
    let anchors = overlay.world.sccp_anchor_open().anchors();
    assert_eq!(anchors.len(), 1);
    assert_eq!(anchors[0].core_hash, parent.core_hash().0);
    assert_eq!(anchors[0].result, parent.result().0);
    assert!(overlay.require_storage_admission().is_ok());
    // This intentionally incomplete height-input attempt supplies no native certificate.
    // Dropping it preserves the original committed World and parent tip.
    drop(overlay);
    assert!(
        chain
            .state()
            .view()
            .world()
            .sccp_anchor_open()
            .anchors()
            .is_empty()
    );
    assert_eq!(chain.state().view().native_execution_tip(), Some(parent));
}

#[test]
fn original_anchor_capacity_refusal_stays_sticky_without_mutating_committed_cut() {
    use super::anchor::SccpAnchorLocalError;
    use crate::{block::BlockValidationError, state::StateStorageAdmissionError};
    let chain = CertifiedTestChain::start(native_chain_config()).unwrap();
    let parent = chain.state().view().native_execution_tip().unwrap();
    let candidate = iroha_data_model::block::BlockHeader::new(
        NonZeroU64::new(2).unwrap(),
        Some(parent.iroha_hash()),
        None,
        2_000,
        0,
    );
    let mut overlay = chain.state().block(candidate);
    super::hook::begin_block(&mut overlay, &candidate).unwrap();
    let budget = overlay.execution_budget();
    let old_limit = budget.limit_bytes();
    budget.set_limit_bytes(budget.reserved_bytes());
    let error = super::hook::finalize_block(&mut overlay, &candidate, None).unwrap_err();
    assert!(
        matches!(
            &error,
            BlockValidationError::StateStorageAdmission(StateStorageAdmissionError::SccpAnchor(
                SccpAnchorLocalError::Admission(
                    iroha_allocation::AllocationRefusal::Capacity { .. }
                )
            ))
        ),
        "{error:?}"
    );
    assert!(matches!(
        overlay.require_storage_admission(),
        Err(StateStorageAdmissionError::SccpAnchor(
            SccpAnchorLocalError::Admission(_)
        ))
    ));
    assert!(overlay.world.sccp_anchor_open().anchors().is_empty());
    assert_eq!(overlay.world.sccp_degraded_run(), 0);
    budget.set_limit_bytes(old_limit);
    drop(overlay);
    assert!(
        chain
            .state()
            .view()
            .world()
            .sccp_anchor_open()
            .anchors()
            .is_empty()
    );
    assert_eq!(chain.state().view().native_execution_tip(), Some(parent));
}

#[test]
fn late_header_projection_failure_retains_the_original_consecutive_degraded_run() {
    use iroha_data_model::parameter::system::ConsensusMode;
    let chain = CertifiedTestChain::start(native_chain_config()).unwrap();
    let parent = chain.state().view().native_execution_tip().unwrap();
    for original_run in [7, u32::MAX] {
        let candidate = iroha_data_model::block::BlockHeader::new(
            NonZeroU64::new(2).unwrap(),
            Some(parent.iroha_hash()),
            None,
            2_000,
            0,
        );
        let mut overlay = chain.state().block(candidate);
        super::hook::begin_block(&mut overlay, &candidate).unwrap();
        {
            let mut transaction = overlay.transaction();
            *transaction.world.sccp_degraded_run.get_mut() = original_run;
            // No leaves are committed in this component attempt. The deliberately malformed
            // retained history is discovered by the final fixed-header projection, after the
            // otherwise healthy generation step has reset its provisional counter.
            transaction.world.sccp_history.get_mut().size = 1;
            transaction.apply();
        }
        let inputs = super::height::SccpHeightInputsV1::from_sumeragi_schedule(
            &overlay.world,
            2,
            1,
            ConsensusMode::Npos,
        )
        .unwrap();
        let header = super::hook::finalize_block(&mut overlay, &candidate, Some(&inputs)).unwrap();
        assert!(!header.is_active());
        assert_eq!(
            overlay.world.sccp_degraded_run(),
            original_run.saturating_add(1)
        );
        assert_eq!(overlay.world.sccp_anchor_open().anchors().len(), 1);
        assert!(overlay.require_storage_admission().is_ok());
    }
}

#[test]
fn genuine_parent_cannot_be_rebound_to_another_candidate_header() {
    use super::anchor::SccpAnchorLocalError;
    use crate::{block::BlockValidationError, state::StateStorageAdmissionError};
    let chain = CertifiedTestChain::start(native_chain_config()).unwrap();
    let parent = chain.state().view().native_execution_tip().unwrap();
    let wrong =
        iroha_crypto::HashOf::from_untyped_unchecked(iroha_crypto::Hash::new(b"foreign parent"));
    for previous in [None, Some(wrong)] {
        let candidate = iroha_data_model::block::BlockHeader::new(
            NonZeroU64::new(2).unwrap(),
            previous,
            None,
            2_000,
            0,
        );
        let mut overlay = chain.state().block(candidate);
        let error = super::hook::finalize_block(&mut overlay, &candidate, None).unwrap_err();
        assert!(matches!(
            error,
            BlockValidationError::StateStorageAdmission(StateStorageAdmissionError::SccpAnchor(
                SccpAnchorLocalError::Invariant(_)
            ))
        ));
        assert!(matches!(
            overlay.require_storage_admission(),
            Err(StateStorageAdmissionError::SccpAnchor(
                SccpAnchorLocalError::Invariant(_)
            ))
        ));
        assert!(overlay.world.sccp_anchor_open().anchors().is_empty());
        assert_eq!(overlay.world.sccp_committee_current(), 1);
    }
    let original = iroha_data_model::block::BlockHeader::new(
        NonZeroU64::new(2).unwrap(),
        Some(parent.iroha_hash()),
        None,
        2_000,
        0,
    );
    let mut overlay = chain.state().block(original);
    let budget = overlay.execution_budget();
    let prepared =
        super::anchor::prepare(&overlay.world, &original, Some(parent), &budget).unwrap();
    let mut transaction = overlay.transaction();
    transaction._curr_block = iroha_data_model::block::BlockHeader::new(
        NonZeroU64::new(2).unwrap(),
        Some(wrong),
        None,
        2_000,
        0,
    );
    assert!(matches!(
        prepared.apply(&mut transaction, &budget),
        Err(StateStorageAdmissionError::SccpAnchor(
            SccpAnchorLocalError::Invariant(_)
        ))
    ));
    assert!(
        transaction
            .world
            .sccp_anchor_open
            .get()
            .anchors()
            .is_empty()
    );
    assert!(transaction.require_storage_admission().is_err());
    drop(transaction);
    drop(overlay);
    assert_eq!(chain.state().view().native_execution_tip(), Some(parent));
    assert!(
        chain
            .state()
            .view()
            .world()
            .sccp_anchor_open()
            .anchors()
            .is_empty()
    );
}
