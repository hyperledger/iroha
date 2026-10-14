//! Genuine signed-genesis SNS source, rollback, no-effect and deterministic replay controls.

use super::*;
use crate::state::State;
use crate::sumeragi::{
    startup,
    test_chain::{CertifiedTestChain, TestChainConfig},
};
use iroha_crypto::{Algorithm, Hash, KeyPair};
use iroha_data_model::{
    Registrable,
    account::Account,
    alias_setup::ResolvedDomainV1,
    asset::{Asset, AssetBalancePolicy, AssetDefinition},
    block::{SignedBlock, builder::BlockBuilder},
    domain::Domain,
    fastpq::FastpqSourceExecutionKindV1,
};
use std::num::NonZeroU64;

const EXPIRY: u64 = 10 * MS_PER_DAY;
const WINDOW: u64 = MS_PER_DAY;

struct Fixture {
    state: State,
    owner: AccountId,
    collector: AccountId,
    asset: AssetDefinitionId,
    selector: NameSelectorV1,
    target: AliasTargetV1,
}

fn fixture(balance: Quantity, free: bool, self_collector: bool) -> Fixture {
    let account = |seed| {
        AccountId::new(
            KeyPair::from_seed(vec![seed; 32], Algorithm::Ed25519)
                .public_key()
                .clone(),
        )
    };
    let owner = account(0xB1);
    let collector = if self_collector {
        owner.clone()
    } else {
        account(0xB2)
    };
    let asset: AssetDefinitionId = iroha_config::parameters::defaults::nexus::fees::fee_asset_id()
        .parse()
        .unwrap();
    let domain = DomainId::try_new("renewable", "universal").unwrap();
    let accounts = BTreeSet::from([owner.clone(), collector.clone()]);
    let mut world = World::with_assets(
        [
            Domain::new(DomainId::try_new("genesis", "universal").unwrap()).build(&collector),
            Domain::new(domain.clone()).build(&owner),
        ],
        accounts
            .into_iter()
            .map(|id| Account::new(id).build(&collector)),
        [
            AssetDefinition::numeric(asset.clone(), "xor", AssetBalancePolicy::Global, None)
                .build(&collector),
        ],
        (!balance.is_zero())
            .then(|| Asset::new(AssetId::of(asset.clone(), owner.clone()), balance)),
        [],
    );
    seed_default_namespace_policies(&mut world);
    let mut policy = policy_by_id(&world.view(), DOMAIN_NAME_SUFFIX_ID)
        .unwrap()
        .unwrap();
    policy.fund_splitter_account = collector.clone();
    if free {
        for tier in &mut policy.pricing {
            tier.base_price = TokenValue::new(asset.to_string(), Quantity::zero());
        }
    }
    world
        .smart_contract_state_mut_for_testing()
        .insert(policy_storage_key(DOMAIN_NAME_SUFFIX_ID), policy.encode());
    let selector = selector_for_domain(&domain).unwrap();
    let record = NameRecordV1::new(
        selector.clone(),
        owner.clone(),
        vec![NameControllerV1::account(
            &AccountAddress::from_account_id(&owner).unwrap(),
        )],
        0,
        0,
        EXPIRY,
        EXPIRY + 30 * MS_PER_DAY,
        EXPIRY + 90 * MS_PER_DAY,
        Metadata::default(),
    );
    world
        .smart_contract_state_mut_for_testing()
        .insert(record_storage_key(&selector), record.encode());
    let target = AliasTargetV1::Domain(ResolvedDomainV1::new(domain, DataSpaceId::UNIVERSAL));
    let config = AliasAutoRenewConfigV1 {
        term_years: 1,
        policy_version: policy.policy_version,
        payment_asset: asset.clone(),
        max_amount: Quantity::one(),
        renew_before_expiry_ms: WINDOW,
        retry_backoff_ms: 100,
        max_failures: 3,
    };
    world.smart_contract_state_mut_for_testing().insert(
        alias_auto_renew_storage_key(&target).unwrap(),
        AliasAutoRenewStateV1::new(target.clone(), owner.clone(), 1, Some(config)).encode(),
    );
    let mut config = TestChainConfig::new(world, 0);
    let mut nexus = iroha_config::parameters::actual::Nexus::default();
    nexus.fees.fee_asset_id = asset.to_string();
    config.nexus = Some(nexus);
    let genesis_account = AccountId::new(config.genesis_key.public_key().clone());
    let mode = config.consensus_mode;
    let prepared = CertifiedTestChain::prepare(config).expect("prepare real SNS genesis");
    let state = std::sync::Arc::try_unwrap(prepared.state)
        .unwrap_or_else(|_| panic!("unpublished State is unique"));
    startup::apply_genesis(
        &state,
        prepared.genesis.block().clone(),
        &genesis_account,
        mode.into(),
        None,
    )
    .expect("apply original signed SNS genesis");
    assert_eq!(state.committed_height(), 1);
    Fixture {
        state,
        owner,
        collector,
        asset,
        selector,
        target,
    }
}

fn source(state: &State, now: u64) -> SignedBlock {
    let view = state.view();
    let header = BlockHeader::new(
        NonZeroU64::new(u64::try_from(view.height()).unwrap() + 1).unwrap(),
        view.latest_block_hash(),
        None,
        now,
        0,
    );
    BlockBuilder::new(header)
        .build_with_signature(0, iroha_test_samples::ALICE_KEYPAIR.private_key())
}

fn balance(world: &impl WorldReadOnly, fixture: &Fixture, account: &AccountId) -> Quantity {
    world
        .asset(&AssetId::of(fixture.asset.clone(), account.clone()))
        .map(|asset| asset.value().clone().into_inner())
        .unwrap_or_else(|_| Quantity::zero())
}

#[test]
fn actual_sns_time_sweep_retains_one_native_purpose_and_exact_payment() {
    let fixture = fixture(Quantity::from(2_u32), false, false);
    let source = source(&fixture.state, EXPIRY - WINDOW);
    let (mut block, _recording, outputs, _) =
        crate::state::run_empty_network_owner_fixture(&fixture.state, &source);
    assert!(outputs.is_empty());
    let usage = block.native_maintenance_usage_for_testing();
    assert_eq!(
        (usage.executed_entries, usage.transcripts, usage.deltas),
        (1, 1, 1)
    );
    let captures = block.captured_fastpq_transcript_sources().unwrap();
    assert_eq!(captures.len(), 1);
    let source_capture = captures.values().next().unwrap();
    assert!(source_capture.is_protocol_purpose());
    assert_eq!(source_capture.source().network_id, fixture.state.network_id);
    assert_eq!(source_capture.source().height, 2);
    let entry_hash = source_capture.entry_hash();
    assert_eq!(
        balance(&block.world, &fixture, &fixture.owner),
        "1.5".parse().unwrap()
    );
    assert_eq!(
        balance(&block.world, &fixture, &fixture.collector),
        "0.5".parse().unwrap()
    );
    let record = record_by_selector(&block.world, &fixture.selector)
        .unwrap()
        .unwrap();
    assert_eq!(record.expires_at_ms, EXPIRY + MS_PER_YEAR);
    let renewed = alias_auto_renew_state(&block.world, &fixture.target)
        .unwrap()
        .unwrap();
    assert_eq!(renewed.revision, 2);
    assert_eq!(renewed.failure_count, 0);
    block
        .finalize_sns_owned_sources_for_testing(&source)
        .unwrap();
    let entries = block.fastpq_source_inventory().unwrap().unwrap().entries();
    let expected_tx_set_hash: [u8; 32] =
        iroha_data_model::nexus::axt_ordered_transaction_set_digest_v1(
            source.external_entrypoints_slice().iter(),
        )
        .unwrap()
        .into();
    assert_eq!(
        block
            .fastpq_source_inventory()
            .unwrap()
            .unwrap()
            .tx_set_hash(),
        expected_tx_set_hash,
        "native inventory retains its actual ordered canonical transaction-wire commitment"
    );
    assert_eq!(entries.len(), 1);
    assert_eq!(
        entries[0].execution_kind,
        FastpqSourceExecutionKindV1::ProtocolPurpose
    );
    assert_eq!(entries[0].entry_hash, entry_hash);
    assert_eq!(
        block
            .verified_fastpq_source_inventory_for_capture()
            .unwrap_err(),
        "FASTPQ witness capture refuses a poisoned carrier",
        "source-only inspection cannot authorize capture or publication"
    );
}

#[test]
fn failed_sns_payment_retains_retry_metadata_without_native_sources_or_partial_effects() {
    let fixture = fixture(Quantity::zero(), false, false);
    let source = source(&fixture.state, EXPIRY - WINDOW);
    let (mut block, _recording, outputs, _) =
        crate::state::run_empty_network_owner_fixture(&fixture.state, &source);
    assert!(outputs.is_empty());
    assert_eq!(
        block.native_maintenance_usage_for_testing(),
        crate::fastpq::source_reservation::SourceUsage::ZERO
    );
    assert!(
        block
            .captured_fastpq_transcript_sources()
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        balance(&block.world, &fixture, &fixture.owner),
        Quantity::zero()
    );
    assert_eq!(
        balance(&block.world, &fixture, &fixture.collector),
        Quantity::zero()
    );
    assert_eq!(
        record_by_selector(&block.world, &fixture.selector)
            .unwrap()
            .unwrap()
            .expires_at_ms,
        EXPIRY
    );
    let retry = alias_auto_renew_state(&block.world, &fixture.target)
        .unwrap()
        .unwrap();
    assert_eq!(retry.revision, 2);
    assert_eq!(retry.failure_count, 1);
    assert_eq!(retry.next_retry_at_ms, Some(EXPIRY - WINDOW + 100));
    block
        .finalize_sns_owned_sources_for_testing(&source)
        .unwrap();
    assert!(
        block
            .fastpq_source_inventory()
            .unwrap()
            .unwrap()
            .entries()
            .is_empty()
    );
}

#[test]
fn free_or_self_collector_renewal_has_no_unapplied_native_entry() {
    for (free, self_collector) in [(true, false), (false, true)] {
        let fixture = fixture(Quantity::from(2_u32), free, self_collector);
        let source = source(&fixture.state, EXPIRY - WINDOW);
        let (mut block, _recording, outputs, _) =
            crate::state::run_empty_network_owner_fixture(&fixture.state, &source);
        assert!(outputs.is_empty());
        assert_eq!(
            block.native_maintenance_usage_for_testing(),
            crate::fastpq::source_reservation::SourceUsage::ZERO
        );
        assert!(
            block
                .captured_fastpq_transcript_sources()
                .unwrap()
                .is_empty()
        );
        assert_eq!(
            balance(&block.world, &fixture, &fixture.owner),
            Quantity::from(2_u32)
        );
        assert_eq!(
            record_by_selector(&block.world, &fixture.selector)
                .unwrap()
                .unwrap()
                .expires_at_ms,
            EXPIRY + MS_PER_YEAR
        );
        block
            .finalize_sns_owned_sources_for_testing(&source)
            .unwrap();
        assert!(
            block
                .fastpq_source_inventory()
                .unwrap()
                .unwrap()
                .entries()
                .is_empty()
        );
    }
}

#[test]
fn same_signed_genesis_and_proposal_replay_derive_identical_native_inventory() {
    let first = fixture(Quantity::from(2_u32), false, false);
    let second = fixture(Quantity::from(2_u32), false, false);
    assert_eq!(first.state.network_id, second.state.network_id);
    let first_source = source(&first.state, EXPIRY - WINDOW);
    let second_source = source(&second.state, EXPIRY - WINDOW);
    assert_eq!(first_source.header(), second_source.header());
    let run = |fixture: &Fixture, source: &SignedBlock| {
        let (mut block, _recording, _, _) =
            crate::state::run_empty_network_owner_fixture(&fixture.state, source);
        block
            .finalize_sns_owned_sources_for_testing(source)
            .unwrap();
        let entries = block
            .fastpq_source_inventory()
            .unwrap()
            .unwrap()
            .entries()
            .to_vec();
        let record = alias_auto_renew_state(&block.world, &fixture.target)
            .unwrap()
            .unwrap();
        (
            entries,
            record,
            block.native_maintenance_usage_for_testing(),
        )
    };
    assert_eq!(run(&first, &first_source), run(&second, &second_source));
}

#[test]
fn native_record_binding_rejects_scope_revision_config_and_key_substitution() {
    let fixture = fixture(Quantity::from(2_u32), false, false);
    let source = source(&fixture.state, EXPIRY - WINDOW);
    let mut block = fixture.state.block(source.header());
    let mut transaction = block.transaction();
    let record = alias_auto_renew_state(&transaction.world, &fixture.target)
        .unwrap()
        .unwrap();
    // Structural binding controls do not mint a Time token or authorize a source.
    let permit = || SnsNativeMaintenancePermit {
        network: transaction.network_id,
        proposal: transaction._curr_block.hash(),
        direct_slot: transaction.direct_execution_identity().unwrap(),
        storage_key: alias_auto_renew_storage_key(&fixture.target).unwrap(),
        revision: record.revision,
        record_digest: SnsNativeMaintenancePermit::record_digest(
            &record,
            transaction.native_maintenance_binding_limit(),
        )
        .unwrap(),
    };
    permit().authenticate_source_record(&transaction).unwrap();
    let deferred = norito::with_decode_limits_scope(
        norito::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, 0, usize::MAX),
        || {
            permit()
                .authenticate_source_record(&transaction)
                .unwrap_err()
        },
    );
    assert!(matches!(deferred, SnsError::Deferred(_)));
    permit().authenticate_source_record(&transaction).unwrap();
    assert!(
        permit().authenticate(&transaction).is_err(),
        "structural scope alone never issues native authority"
    );
    for mutation in 0..6 {
        let mut altered = permit();
        match mutation {
            0 => altered.direct_slot = Hash::new(b"foreign slot"),
            1 => altered.revision += 1,
            2 => altered.record_digest = Hash::new(b"different configuration"),
            3 => altered.storage_key = alias_auto_renew_internal_key("foreign-record"),
            4 => {
                altered.network = iroha_data_model::NetworkId::from_genesis_hash(
                    iroha_crypto::HashOf::from_untyped_unchecked(Hash::new(b"foreign network")),
                )
            }
            5 => {
                altered.proposal =
                    iroha_crypto::HashOf::from_untyped_unchecked(Hash::new(b"foreign proposal"))
            }
            _ => unreachable!(),
        }
        assert!(
            altered.authenticate_source_record(&transaction).is_err(),
            "mutation {mutation}"
        );
    }
    let retained = permit();
    let mut changed = record;
    changed.config.as_mut().unwrap().max_amount = Quantity::from(2_u32);
    persist_alias_auto_renew_state(&mut transaction, &changed).unwrap();
    assert!(retained.authenticate_source_record(&transaction).is_err());
}

#[test]
fn sns_source_inspection_refuses_foreign_incomplete_and_repeated_native_owners() {
    for refusal in 0..3 {
        let fixture = fixture(Quantity::from(2_u32), false, false);
        let original = source(&fixture.state, EXPIRY - WINDOW);
        let parent_height = fixture.state.committed_height();
        let mut block;
        let recording;
        if refusal == 1 {
            block = Box::new(fixture.state.block(original.header()));
            recording = None;
        } else {
            let (actual, recorder, outputs, _) =
                crate::state::run_empty_network_owner_fixture(&fixture.state, &original);
            assert!(outputs.is_empty());
            block = actual;
            recording = Some(recorder);
        }
        let refused = if refusal == 0 {
            let foreign = source(&fixture.state, EXPIRY - WINDOW + 1);
            block.finalize_sns_owned_sources_for_testing(&foreign)
        } else {
            if refusal == 2 {
                block
                    .finalize_sns_owned_sources_for_testing(&original)
                    .unwrap();
                assert_eq!(
                    block
                        .fastpq_source_inventory()
                        .unwrap()
                        .unwrap()
                        .entries()
                        .len(),
                    1
                );
            }
            block.finalize_sns_owned_sources_for_testing(&original)
        };
        assert!(refused.is_err(), "refusal {refusal}");
        assert_eq!(
            block
                .verified_fastpq_source_inventory_for_capture()
                .unwrap_err(),
            "FASTPQ witness capture refuses a poisoned carrier",
            "refusal {refusal}"
        );
        assert!(
            !original.has_results(),
            "the caller's proposal stays unpublished"
        );
        assert!(matches!(
            block.commit().unwrap_err(),
            crate::state::storage_transactions::TransactionsBlockError::ExecutionOutputCapacity
        ));
        drop(recording);
        assert_eq!(fixture.state.committed_height(), parent_height);
        assert_eq!(
            balance(fixture.state.view().world(), &fixture, &fixture.owner),
            Quantity::from(2_u32)
        );
        assert_eq!(
            record_by_selector(fixture.state.view().world(), &fixture.selector)
                .unwrap()
                .unwrap()
                .expires_at_ms,
            EXPIRY
        );
    }
}

#[test]
fn original_sns_late_fee_refusal_drops_witness_before_retry_metadata() {
    let fixture = fixture(Quantity::from(2_u32), false, false);
    let source = source(&fixture.state, EXPIRY - WINDOW);
    {
        let (mut block, _recording) =
            crate::block::ValidBlock::start_component_execution(&source, &fixture.state).unwrap();
        let bad_receipt: StatePath = "retail_fee_receipts_v1/malformed_native_retry_test"
            .parse()
            .unwrap();
        let malformed = vec![0xff; 8];
        let original = norito::decode_canonical::<
            iroha_data_model::validation_fee::RetailFeeReceiptV1,
        >(&malformed)
        .unwrap_err();
        assert!(matches!(&original, norito::Error::InvalidMagic));
        {
            let mut setup = block.transaction();
            setup
                .world
                .smart_contract_state
                .insert(bad_receipt, malformed);
            setup.apply();
        }
        let before = block.native_maintenance_usage_for_testing();
        block.reserve_ordinary_execution_outputs(&source).unwrap();
        // SNS first rolls back its late fee refusal and persists retry metadata.
        // The subsequent conversion-offer pass must reject the same malformed
        // parent receipt; the entire carrier cannot be accepted as successful.
        let refusal = block
            .execute_ordinary_output_plan(&source, None)
            .unwrap_err();
        let expected = iroha_data_model::isi::error::InstructionExecutionError::InvariantViolation(
            original.to_string().into(),
        );
        assert!(
            matches!(&refusal, crate::state::ExecutionOutputAttemptError::Owner(reason)
                if reason == &format!("validation fee reward maintenance failed: {expected}")),
            "the unchanged Time owner must preserve the original late receipt rejection: {refusal:?}"
        );
        assert_eq!(block.native_maintenance_usage_for_testing(), before);
        assert!(
            block
                .captured_fastpq_transcript_sources()
                .unwrap()
                .is_empty()
        );
        assert_eq!(
            balance(&block.world, &fixture, &fixture.owner),
            Quantity::from(2_u32)
        );
        assert_eq!(
            balance(&block.world, &fixture, &fixture.collector),
            Quantity::zero()
        );
        assert_eq!(
            record_by_selector(&block.world, &fixture.selector)
                .unwrap()
                .unwrap()
                .expires_at_ms,
            EXPIRY
        );
        let retry = alias_auto_renew_state(&block.world, &fixture.target)
            .unwrap()
            .unwrap();
        assert_eq!(retry.revision, 2);
        assert_eq!(retry.failure_count, 1);
        assert_eq!(retry.next_retry_at_ms, Some(EXPIRY - WINDOW + 100));
        assert_eq!(retry.suspended_reason, None);
        assert!(
            crate::exec_witness::snapshot_exec_witness()
                .fastpq_transcripts
                .is_empty(),
            "original SNS late refusal must drop its prepared witness before retry metadata"
        );
    }
    // The abandoned carrier never publishes its receipt, retry record or debit.
    // Retrying the same genuine original Time source succeeds with its exact payment.
    let (block, _recording, outputs, _) =
        crate::state::run_empty_network_owner_fixture(&fixture.state, &source);
    assert!(outputs.is_empty());
    assert_eq!(
        block
            .native_maintenance_usage_for_testing()
            .executed_entries,
        1
    );
    assert_eq!(
        crate::exec_witness::snapshot_exec_witness()
            .fastpq_transcripts
            .len(),
        1
    );
    assert_eq!(
        balance(&block.world, &fixture, &fixture.owner),
        "1.5".parse().unwrap()
    );
    assert_eq!(
        balance(&block.world, &fixture, &fixture.collector),
        "0.5".parse().unwrap()
    );
    let renewed = alias_auto_renew_state(&block.world, &fixture.target)
        .unwrap()
        .unwrap();
    assert_eq!((renewed.revision, renewed.failure_count), (2, 0));
    assert_eq!(renewed.next_retry_at_ms, None);
    assert_eq!(renewed.suspended_reason, None);
}
