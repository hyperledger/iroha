//! Structural/original initial-credit tests; codec checkpoint bytes never establish native authority.

use super::*;
use crate::localnet::service_authorities::LocalnetServiceProfile;
use iroha_crypto::{Algorithm, HashOf, KeyPair};
use iroha_data_model::{
    NetworkId,
    account::AccountId,
    sorafs::{
        capacity::ProviderId,
        pin_registry::StorageClass,
        reserve::{
            RESERVE_AUTHORITY_POLICY_VERSION_V1, ReserveDuration, ReserveLifecycleStage,
            ReservePolicyV1, ReserveProviderTermsV1, ReserveTier,
        },
    },
    transaction::FeePaymentIntent,
};
use iroha_primitives::{json::Json, numeric::Quantity};
use sorafs_manifest::deal::XorQuantity;
use std::{collections::BTreeMap, time::Duration};

pub(super) fn fixture() -> (
    tempfile::TempDir,
    PreparedLocalnet,
    ManagedInitialProviderCredit,
) {
    let temporary = tempfile::tempdir().unwrap();
    let ports = crate::managed::LocalnetPorts::reserve().unwrap();
    let prepared = crate::localnet::prepare_localnet_at(
        "initial-provider-credit",
        &temporary.path().join("generation"),
        &ports,
        LocalnetServiceProfile::StreamTokenAuthorities,
        None,
    )
    .unwrap();
    let coordinator = ManagedInitialProviderCredit::open(
        &prepared,
        crate::managed::native_operation::test_support::provider_id(&prepared, 0),
    )
    .unwrap();
    (temporary, prepared, coordinator)
}

fn account(seed: u8) -> AccountId {
    AccountId::new(
        KeyPair::try_from_seed(vec![seed; 32], Algorithm::Ed25519)
            .unwrap()
            .public_key()
            .clone(),
    )
}

fn selected_policy(
    operator: AccountId,
    manager: AccountId,
    custody: AccountId,
    treasury: AccountId,
) -> ReserveAuthorityPolicyV1 {
    ReserveAuthorityPolicyV1 {
        version: RESERVE_AUTHORITY_POLICY_VERSION_V1,
        revision: 1,
        predecessor_policy_digest: None,
        economics: ReservePolicyV1::default(),
        asset_definition: AssetDefinitionId::parse_address_literal(
            crate::genesis::profile::TAIRA_XOR_ASSET_DEFINITION_ID,
        )
        .unwrap(),
        custody_account: custody,
        treasury_account: treasury,
        operations_authority: operator,
        decision_authority: manager,
        grace_period_days: 7,
        default_after_days: 30,
        max_provider_debt: XorQuantity::try_from_micro(1_000_000_000).unwrap(),
        max_pending_movements_per_provider: 4,
        max_open_appeals_per_provider: 2,
    }
}

pub(super) fn policy(coordinator: &ManagedInitialProviderCredit) -> ReserveAuthorityPolicyV1 {
    selected_policy(
        coordinator
            .authority
            .network_role(crate::localnet::service_authorities::NetworkServiceAuthorityRole::ReserveOperations)
            .unwrap()
            .clone(),
        coordinator.authority.config.account.clone(),
        coordinator
            .authority
            .manifest
            .network
            .reserve_accounts
            .custody
            .clone(),
        coordinator
            .authority
            .manifest
            .network
            .reserve_accounts
            .treasury
            .clone(),
    )
}

pub(super) fn partition(coordinator: &ManagedInitialProviderCredit) -> ReserveProviderAccountV1 {
    let policy = policy(coordinator);
    claimed_partition(
        coordinator.authority.provider_id().unwrap(),
        coordinator
            .authority
            .provider_role(StreamTokenAuthorityRole::IssuerOperator)
            .unwrap()
            .clone(),
        policy.digest().unwrap(),
    )
}
fn claimed_partition(
    provider_id: ProviderId,
    provider_account: AccountId,
    policy_digest: [u8; 32],
) -> ReserveProviderAccountV1 {
    // Structurally valid caller data only. Native tests independently derive a real partition.
    ReserveProviderAccountV1 {
        terms: ReserveProviderTermsV1 {
            provider_id,
            provider_account,
            tier: ReserveTier::TierA,
            storage_class: StorageClass::Hot,
            duration: ReserveDuration::Monthly,
            capacity_gib: 1,
        },
        policy_digest,
        revision: 7,
        reserve_balance: XorQuantity::zero(),
        debt_principal: XorQuantity::zero(),
        accrued_interest: XorQuantity::zero(),
        credit_cap: XorQuantity::zero(),
        lifecycle_stage: ReserveLifecycleStage::Warning,
        days_past_due: 0,
        pending_movements: 0,
        open_appeals: 0,
        rent_charged_through_unix: 1,
        interest_accrued_at_unix: 1,
        updated_at_unix: 1,
    }
}
pub(super) fn intent(
    coordinator: &ManagedInitialProviderCredit,
) -> ManagedInitialProviderCreditIntent {
    let partition = partition(coordinator);
    let record = ProviderCreditRecord::new(
        partition.terms.provider_id,
        Quantity::from(7_u32),
        Quantity::zero(),
        Quantity::zero(),
        Quantity::zero(),
        1,
        1,
        iroha_model_base::metadata::Metadata::default(),
    );
    ManagedInitialProviderCreditIntent {
        policy: policy(coordinator),
        partition,
        record,
    }
}

pub(super) fn options() -> BoundedTransactionOptions {
    BoundedTransactionOptions {
        fee_payment: FeePaymentIntent::authority(Vec::new(), None),
        max_total_fees: BTreeMap::new(),
        deadline: Instant::now() + Duration::from_secs(300),
    }
}

fn codec_original() -> Original {
    let policy = selected_policy(account(1), account(2), account(3), account(4));
    let partition = claimed_partition(
        ProviderId::new([7; 32]),
        policy.operations_authority.clone(),
        policy.digest().unwrap(),
    );
    let record = ProviderCreditRecord::new(
        partition.terms.provider_id,
        Quantity::from(7_u32),
        Quantity::zero(),
        Quantity::zero(),
        Quantity::zero(),
        1,
        1,
        iroha_model_base::metadata::Metadata::default(),
    );
    Original {
        selection: ProviderCreditUpsertSelection {
            chain_id: "codec-only-unproved-network".into(),
            network_id: NetworkId::from_genesis_hash(iroha_crypto::HashOf::from_untyped_unchecked(
                iroha_crypto::Hash::new(b"codec-only-unproved-genesis"),
            )),
            credit_authority: policy.decision_authority.clone(),
            provider_id: partition.terms.provider_id,
            provider_account: partition.terms.provider_account.clone(),
            expected_current: None,
            desired_record_hash: HashOf::new(&record),
            partition_revision: partition.revision,
            partition_policy_digest: partition.policy_digest,
            policy_digest: policy.digest().unwrap(),
            asset_definition: policy.asset_definition.clone(),
            custody_account: policy.custody_account.clone(),
            treasury_account: policy.treasury_account.clone(),
            operations_authority: policy.operations_authority.clone(),
            decision_authority: policy.decision_authority.clone(),
        },
        policy,
        partition,
        record,
        // Canonical persistence coverage only; never admitted as native finality.
        checkpoint: vec![0x5a; 16 * 1024],
    }
}

#[test]
fn initial_credit_original_roundtrip_and_large_checkpoint_preserve_explicit_absence() {
    let terms = Terms::new(now_ms().unwrap() + 600_000, &options()).unwrap();
    let term_bytes = encode(&terms, 16 * 1024).unwrap();
    let restored_terms: Terms = norito::decode_canonical_with_limits(
        &term_bytes,
        norito::DecodeLimits::new(4096, 16 * 1024, 16 * 1024, 64 * 1024, 16),
    )
    .unwrap();
    assert!(
        restored_terms == terms,
        "dispatch terms retain their own exact canonical record"
    );

    let temporary = tempfile::tempdir().unwrap();
    let directory = PrivateDirectory::open_or_create(temporary.path().join("install")).unwrap();
    let original = codec_original();
    journal::publish_intent(&directory, &original).unwrap();
    let bytes = directory.read("original.nrt", 256 * 1024).unwrap();
    let restored = journal::read_intent(&directory).unwrap().unwrap();
    assert_eq!(restored.checkpoint, original.checkpoint);
    assert!(restored.checkpoint.len() > 4096);
    assert_eq!(encode(&restored, 256 * 1024).unwrap(), bytes.as_slice());
    let mut replacement = original.clone();
    replacement.checkpoint.push(0x6b);
    assert!(journal::publish_intent(&directory, &replacement).is_err());
    assert_eq!(
        directory
            .read("original.nrt", 256 * 1024)
            .unwrap()
            .as_slice(),
        bytes.as_slice()
    );
    let request = restored.request(&terms, Instant::now() + Duration::from_secs(900));
    assert!(request.current_credit.is_none());
    assert!(request.selection.expected_current.is_none());
    assert_eq!(
        request.selection.credit_authority,
        original.policy.decision_authority
    );
    assert_eq!(request.policy, original.policy);
    assert_eq!(request.partition, original.partition);
    assert_eq!(request.record, original.record);
    assert_eq!(request.deadline_unix_ms, terms.signing_deadline_unix_ms);
}

#[test]
fn initial_credit_original_rejects_selected_bindings_guard_and_record_substitution() {
    let original = codec_original();
    original.validate().unwrap();
    for field in 0..17 {
        let mut changed = original.clone();
        match field {
            0 => changed.selection.expected_current = Some(HashOf::new(&changed.record)),
            1 => changed.selection.credit_authority = account(11),
            2 => changed.selection.provider_id = ProviderId::default(),
            3 => changed.selection.provider_account = account(12),
            4 => changed.selection.partition_revision += 1,
            5 => changed.selection.partition_policy_digest[0] ^= 1,
            6 => changed.selection.policy_digest[0] ^= 1,
            7 => changed.selection.operations_authority = account(13),
            8 => changed.selection.decision_authority = account(14),
            9 => changed.selection.custody_account = account(15),
            10 => changed.selection.treasury_account = account(16),
            11 => {
                changed.selection.asset_definition = AssetDefinitionId::from_uuid_bytes([
                    0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x48, 0x99, 0x88, 0x99, 0xaa, 0xbb, 0xcc,
                    0xdd, 0xee, 0xff,
                ])
                .unwrap()
            }
            12 => changed.record.available_credit = Quantity::from(8_u32),
            13 => changed.record.provider_id = ProviderId::new([9; 32]),
            14 => changed.record.slashed = Quantity::from(1_u32),
            15 => changed.record.last_penalty_epoch = Some(1),
            _ => changed.partition.terms.capacity_gib = 0,
        }
        assert!(changed.validate().is_err(), "changed binding {field}");
    }
}

#[test]
fn initial_credit_retains_full_intent_and_original_fee_utc_after_expiry() {
    let mut terms = Terms::new(now_ms().unwrap() + 600_000, &options()).unwrap();
    let original = codec_original();
    let now = now_ms().unwrap();
    terms.requested_deadline_unix_ms = now - 100;
    terms.signing_deadline_unix_ms = now - 200;
    original.validate().unwrap();
    let intent = original.intent();
    let deadline = terms.requested_deadline_unix_ms;
    let options = terms.options(Instant::now() + Duration::from_secs(900));
    original
        .matches_intent(&intent)
        .and_then(|()| terms.matches(deadline, &options))
        .unwrap();
    assert!(Terms::new(deadline, &options).is_err());
    assert!(terms.signing_deadline(options.deadline).is_err());
    assert_eq!(
        original.request(&terms, options.deadline).deadline_unix_ms,
        now - 200
    );
    assert!(
        original
            .matches_intent(&intent)
            .and_then(|()| terms.matches(deadline + 1, &options))
            .is_err()
    );
    for field in 0..4 {
        let mut changed = intent.clone();
        match field {
            0 => changed.policy.grace_period_days += 1,
            1 => changed.partition.updated_at_unix += 1,
            2 => changed.record.available_credit = Quantity::from(8_u32),
            _ => {
                let _ = changed
                    .record
                    .metadata
                    .insert("note".parse().unwrap(), Json::new("changed"));
            }
        }
        assert!(
            original
                .matches_intent(&changed)
                .and_then(|()| terms.matches(deadline, &options))
                .is_err()
        );
    }
    let mut changed = options.clone();
    changed.max_total_fees.insert(
        original.policy.asset_definition.clone(),
        Quantity::from(1_u32),
    );
    assert!(
        original
            .matches_intent(&intent)
            .and_then(|()| terms.matches(deadline, &changed))
            .is_err()
    );
    changed = options;
    changed.fee_payment = FeePaymentIntent::authority(Vec::new(), std::num::NonZeroU64::new(1));
    assert!(
        original
            .matches_intent(&intent)
            .and_then(|()| terms.matches(deadline, &changed))
            .is_err()
    );
}

#[test]
fn initial_credit_preserves_lagged_partition_digest_and_bounds_complete_record() {
    let mut original = codec_original();
    let previous = original.policy.digest().unwrap();
    original.policy.revision += 1;
    original.policy.predecessor_policy_digest = Some(previous);
    original.policy.grace_period_days += 1;
    original.selection.policy_digest = original.policy.digest().unwrap();
    original.validate().unwrap();
    assert_ne!(
        original.selection.policy_digest,
        original.partition.policy_digest
    );
    let _ = original.record.metadata.insert(
        "large".parse().unwrap(),
        Json::new("x".repeat(journal::MAX_CREDIT_BYTES)),
    );
    assert!(original.validate().is_err());
    let temporary = tempfile::tempdir().unwrap();
    let directory = PrivateDirectory::open_or_create(temporary.path().join("install")).unwrap();
    assert!(journal::publish_intent(&directory, &original).is_err());
    require_empty(&directory).unwrap();
}

#[test]
fn initial_credit_predecessor_comparison_requires_exact_partition_and_credit_absence() {
    let original = codec_original();
    // Pure comparison of claims: this creates no opaque verified proof or native authority.
    assert!(matches_predecessor(
        Some(&original.partition),
        None,
        &original.partition
    ));
    assert!(!matches_predecessor(None, None, &original.partition));
    assert!(!matches_predecessor(
        Some(&original.partition),
        Some(&original.record),
        &original.partition
    ));
    let mut changed = original.partition.clone();
    changed.revision += 1;
    assert!(!matches_predecessor(
        Some(&changed),
        None,
        &original.partition
    ));
    changed = original.partition.clone();
    changed.policy_digest[0] ^= 1;
    assert!(!matches_predecessor(
        Some(&changed),
        None,
        &original.partition
    ));
}

// Create a real committed request-only attempt through the sole wallet/epoch owner. This helper
// neither signs nor treats codec-only checkpoints as native evidence.
pub(super) fn retain_explicit_request(
    coordinator: &ManagedInitialProviderCredit,
    directory: &PrivateDirectory,
    original: &Original,
    utc: u64,
    options: &BoundedTransactionOptions,
) -> Selected<Original> {
    journal::publish_intent(directory, original).unwrap();
    let account = AccountService::new(coordinator.authority.config.clone()).unwrap();
    journal::explicit(directory, original, utc, options, &account).unwrap();
    let selected = journal::required_original(directory).unwrap();
    assert_eq!(
        account
            .inspect_provider_credit_upsert_preparation(
                &selected.directory().path().join("transaction"),
                &selected.request(options.deadline),
            )
            .unwrap()
            .phase(),
        iroha_wallet::operations::NativePreparationPhase::RequestOnly,
    );
    selected
}
