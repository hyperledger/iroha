//! Structural/original top_up tests; codec checkpoint bytes never establish native authority.

use super::*;
use crate::localnet::service_authorities::LocalnetServiceProfile;
use iroha_crypto::{Algorithm, KeyPair};
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
use sorafs_manifest::deal::XorQuantity;
use std::{collections::BTreeMap, time::Duration};

pub(super) fn fixture() -> (
    tempfile::TempDir,
    PreparedLocalnet,
    ManagedReserveTopUpRequest,
) {
    let temporary = tempfile::tempdir().unwrap();
    let ports = crate::managed::LocalnetPorts::reserve().unwrap();
    let prepared = crate::localnet::prepare_localnet_at(
        "reserve-top-up",
        &temporary.path().join("generation"),
        &ports,
        LocalnetServiceProfile::StreamTokenAuthorities,
        None,
    )
    .unwrap();
    let coordinator = ManagedReserveTopUpRequest::open(
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

pub(super) fn policy(coordinator: &ManagedReserveTopUpRequest) -> ReserveAuthorityPolicyV1 {
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

pub(super) fn partition(coordinator: &ManagedReserveTopUpRequest) -> ReserveProviderAccountV1 {
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
pub(super) fn intent(coordinator: &ManagedReserveTopUpRequest) -> ManagedReserveTopUpIntent {
    let partition = partition(coordinator);
    ManagedReserveTopUpIntent {
        policy: policy(coordinator),
        expected_provider_revision: partition.revision,
        partition,
        movement_id: [51; 32],
        amount: XorQuantity::try_from_micro(5_000_000).unwrap(),
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
    Original {
        selection: ReserveTopUpSelection {
            chain_id: "codec-only-unproved-network".into(),
            network_id: NetworkId::from_genesis_hash(iroha_crypto::HashOf::from_untyped_unchecked(
                iroha_crypto::Hash::new(b"codec-only-unproved-genesis"),
            )),
            operations_authority: policy.operations_authority.clone(),
            provider_id: partition.terms.provider_id,
            provider_account: partition.terms.provider_account.clone(),
            expected_provider_revision: partition.revision,
            partition_policy_digest: partition.policy_digest,
            policy_digest: policy.digest().unwrap(),
            asset_definition: policy.asset_definition.clone(),
            custody_account: policy.custody_account.clone(),
            treasury_account: policy.treasury_account.clone(),
            decision_authority: policy.decision_authority.clone(),
        },
        policy,
        partition,
        movement_id: [51; 32],
        amount: XorQuantity::try_from_micro(5_000_000).unwrap(),
        // Deliberately invalid as finality, used only for bounded retained-codec ownership.
        checkpoint: vec![0x5a; 16 * 1024],
    }
}

#[test]
fn top_up_original_roundtrip_retains_large_checkpoint_and_exact_movement() {
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
    let directory = PrivateDirectory::open_or_create(temporary.path().join("request")).unwrap();
    let original = codec_original();
    assert!(original.checkpoint.len() > 4096);
    journal::publish_intent(&directory, &original).unwrap();
    let bytes = directory.read("original.nrt", 256 * 1024).unwrap();
    let restored = journal::read_intent(&directory).unwrap().unwrap();
    assert_eq!(restored.checkpoint, original.checkpoint);
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
    assert_eq!(request.deadline_unix_ms, terms.signing_deadline_unix_ms);
    assert_eq!(request.policy, original.policy);
    assert_eq!(request.partition, original.partition);
    assert_eq!(request.movement_id, original.movement_id);
    assert_eq!(request.amount, original.amount);
    assert_eq!(
        encode(&request.selection, journal::MAX_SELECTION_BYTES).unwrap(),
        encode(&original.selection, journal::MAX_SELECTION_BYTES).unwrap()
    );
}

#[test]
fn top_up_original_rejects_selection_cas_movement_roles_and_structural_substitution() {
    let terms = Terms::new(now_ms().unwrap() + 600_000, &options()).unwrap();
    let original = codec_original();
    original.validate().unwrap();
    for field in 0..17 {
        let mut changed = original.clone();
        match field {
            0 => changed.selection.policy_digest[0] ^= 1,
            1 => changed.selection.provider_id = ProviderId::default(),
            2 => changed.selection.provider_id = ProviderId::new([9; 32]),
            3 => changed.selection.provider_account = account(12),
            4 => changed.selection.operations_authority = account(13),
            5 => changed.selection.decision_authority = account(14),
            6 => changed.selection.custody_account = account(15),
            7 => changed.selection.treasury_account = account(16),
            8 => {
                changed.selection.asset_definition = AssetDefinitionId::from_uuid_bytes([
                    0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x48, 0x99, 0x88, 0x99, 0xaa, 0xbb, 0xcc,
                    0xdd, 0xee, 0xff,
                ])
                .unwrap()
            }
            9 => changed.partition.terms.capacity_gib = 0,
            10 => changed.selection.expected_provider_revision += 1,
            11 => changed.selection.partition_policy_digest[0] ^= 1,
            12 => changed.movement_id = [0; 32],
            13 => changed.amount = XorQuantity::zero(),
            14 => {
                changed.partition.pending_movements =
                    changed.policy.max_pending_movements_per_provider
            }
            15 => {
                changed.partition.revision = u64::MAX;
                changed.selection.expected_provider_revision = u64::MAX;
            }
            _ => changed.checkpoint.clear(),
        }
        assert!(
            changed.validate().is_err(),
            "changed original field {field}"
        );
    }
    let options = terms.options(Instant::now() + Duration::from_secs(300));
    for field in 0..7 {
        let mut changed = original.intent();
        match field {
            0 => changed.policy.grace_period_days += 1,
            1 => changed.partition.terms.capacity_gib += 1,
            2 => changed.movement_id[0] ^= 1,
            3 => changed.amount = XorQuantity::try_from_micro(9_000_000).unwrap(),
            4 => {
                changed.partition.revision += 1;
                changed.expected_provider_revision += 1;
            }
            5 => changed.partition.policy_digest[0] ^= 1,
            _ => changed.partition.reserve_balance = XorQuantity::try_from_micro(1).unwrap(),
        }
        assert!(
            original
                .matches_intent(&changed)
                .and_then(|()| terms.matches(terms.requested_deadline_unix_ms, &options))
                .is_err()
        );
    }
}

#[test]
fn expired_top_up_preserves_utc_fees_and_lagged_partition_across_fresh_io() {
    let mut terms = Terms::new(now_ms().unwrap() + 600_000, &options()).unwrap();
    let mut original = codec_original();
    let now = now_ms().unwrap();
    terms.requested_deadline_unix_ms = now - 100;
    terms.signing_deadline_unix_ms = now - 200;
    original.policy.revision = 2;
    original.policy.predecessor_policy_digest = Some(original.selection.policy_digest);
    original.selection.policy_digest = original.policy.digest().unwrap();
    assert_ne!(
        original.selection.partition_policy_digest,
        original.selection.policy_digest
    );
    original.validate().unwrap();
    let temporary = tempfile::tempdir().unwrap();
    let directory = PrivateDirectory::open_or_create(temporary.path().join("request")).unwrap();
    journal::publish_intent(&directory, &original).unwrap();
    let bytes = directory.read("original.nrt", 256 * 1024).unwrap();
    let original = journal::read_intent(&directory).unwrap().unwrap();
    let options = terms.options(Instant::now() + Duration::from_secs(900));
    original
        .matches_intent(&original.intent())
        .and_then(|()| terms.matches(terms.requested_deadline_unix_ms, &options))
        .unwrap();
    assert!(terms.signing_deadline(options.deadline).is_err());
    assert!(Terms::new(terms.requested_deadline_unix_ms, &options).is_err());
    assert_eq!(
        original.request(&terms, options.deadline).deadline_unix_ms,
        now - 200
    );
    assert!(
        original
            .matches_intent(&original.intent())
            .and_then(|()| terms.matches(now + 600_000, &options))
            .is_err()
    );
    let mut changed = options.clone();
    changed.max_total_fees.insert(
        original.policy.asset_definition.clone(),
        iroha_primitives::numeric::Quantity::from(1_u32),
    );
    assert!(
        original
            .matches_intent(&original.intent())
            .and_then(|()| terms.matches(terms.requested_deadline_unix_ms, &changed))
            .is_err()
    );
    changed = options.clone();
    changed.fee_payment = FeePaymentIntent::authority(Vec::new(), std::num::NonZeroU64::new(1));
    assert!(
        original
            .matches_intent(&original.intent())
            .and_then(|()| terms.matches(terms.requested_deadline_unix_ms, &changed))
            .is_err()
    );
    let mut malformed = terms.clone();
    malformed.requested_deadline_unix_ms = u64::MAX;
    assert!(malformed.validate().is_err());
    assert_eq!(
        directory
            .read("original.nrt", 256 * 1024)
            .unwrap()
            .as_slice(),
        bytes.as_slice()
    );
}

#[test]
fn generated_top_up_binds_original_roles_and_independent_revision_without_claiming_state() {
    let _resources = crate::managed::native_test_guard();
    let (_temporary, prepared, coordinator) = fixture();
    let intent = intent(&coordinator);
    coordinator.validate_intent(&intent).unwrap();
    let selected = coordinator.selection(&intent).unwrap();
    assert_eq!(
        selected.provider_account,
        intent.partition.terms.provider_account
    );
    assert_eq!(
        selected.expected_provider_revision,
        intent.partition.revision
    );
    assert_ne!(
        selected.provider_account,
        coordinator.authority.config.account
    );
    let operator = coordinator.authority.issuer_operator_config().unwrap();
    assert_eq!(operator.account, selected.provider_account);
    assert_eq!(
        operator.account.try_signatory(),
        Some(operator.key_pair.public_key())
    );
    let mut rotated = intent.clone();
    rotated.policy.revision = 2;
    rotated.policy.predecessor_policy_digest = Some(intent.policy.digest().unwrap());
    coordinator.validate_intent(&rotated).unwrap();
    assert_ne!(
        coordinator.selection(&rotated).unwrap().policy_digest,
        selected.partition_policy_digest
    );
    assert!(
        ManagedReserveTopUpRequest::open(
            &prepared,
            crate::managed::native_operation::test_support::provider_id(&prepared, 0)
        )
        .is_err()
    );
    let mut changed = prepared.clone();
    changed.context.dataspace_id = 7;
    assert!(
        ManagedReserveTopUpRequest::open(
            &changed,
            crate::managed::native_operation::test_support::provider_id(&prepared, 0)
        )
        .is_err()
    );
    changed = prepared.clone();
    changed.service_profile = LocalnetServiceProfile::Standard;
    assert!(
        ManagedReserveTopUpRequest::open(
            &changed,
            crate::managed::native_operation::test_support::provider_id(&prepared, 0)
        )
        .is_err()
    );
    assert_eq!(
        coordinator.authority.directory.entries(2).unwrap(),
        [std::ffi::OsString::from("operation.lock")]
    );
    drop(coordinator);
    ManagedReserveTopUpRequest::open(
        &prepared,
        crate::managed::native_operation::test_support::provider_id(&prepared, 0),
    )
    .unwrap();
}

#[test]
fn public_applied_report_and_forged_finality_cannot_create_historical_binding() {
    let mut report = progress(OperationStatus::Applied, None, None);
    report.finalized = Some(ManagedTransactionFinality {
        transaction_hash: iroha_crypto::HashOf::from_untyped_unchecked(iroha_crypto::Hash::new(
            b"unproved transaction report",
        )),
        height: 99,
        block_hash: iroha_crypto::HashOf::from_untyped_unchecked(iroha_crypto::Hash::new(
            b"unproved block report",
        )),
        block_time_ms: 1,
    });
    assert!(report.historical().is_none());
    assert!(report.current.is_none());
}

// Create a real committed request-only attempt through the sole wallet/epoch owner. This helper
// neither signs nor treats codec-only checkpoints as native evidence.
pub(super) fn retain_explicit_request(
    coordinator: &ManagedReserveTopUpRequest,
    directory: &PrivateDirectory,
    original: &Original,
    utc: u64,
    options: &BoundedTransactionOptions,
) -> Selected<Original> {
    journal::publish_intent(directory, original).unwrap();
    let account =
        AccountService::new(coordinator.authority.issuer_operator_config().unwrap()).unwrap();
    journal::explicit(directory, original, utc, options, &account).unwrap();
    let selected = journal::required_original(directory).unwrap();
    assert_eq!(
        account
            .inspect_reserve_top_up_preparation(
                &selected.directory().path().join("transaction"),
                &selected.request(options.deadline),
            )
            .unwrap()
            .phase(),
        iroha_wallet::operations::NativePreparationPhase::RequestOnly,
    );
    selected
}

#[test]
fn original_selection_finishes_before_cold_checkpoint_admission_and_refuses_changed_root() {
    let _guard = crate::managed::native_test_guard();
    let (_temporary, _prepared, owner) = fixture();
    let intent = intent(&owner);
    let mut original = Original {
        selection: owner.selection(&intent).unwrap(),
        policy: intent.policy,
        partition: intent.partition,
        movement_id: intent.movement_id,
        amount: intent.amount,
        checkpoint: vec![0x5a; 16 * 1024],
    };
    original.validate().unwrap();
    owner.validate_original_selection(&original).unwrap();
    let before = owner.authority.test_checkpoint_import_attempts();
    let expected_network = original.selection.network_id;
    original.selection.network_id =
        NetworkId::from_genesis_hash(iroha_crypto::HashOf::from_untyped_unchecked(
            iroha_crypto::Hash::new(b"foreign selected original top-up root"),
        ));
    original.validate().unwrap();
    let selection_error = owner
        .validate_original_selection(&original)
        .unwrap_err()
        .to_string();
    assert!(
        selection_error.contains("original reserve top-up differs from authenticated generation")
    );
    assert_eq!(
        owner.validate_original(&original).unwrap_err().to_string(),
        selection_error
    );
    assert_eq!(owner.authority.test_checkpoint_import_attempts(), before);
    original.selection.network_id = expected_network;
    owner.validate_original_selection(&original).unwrap();
    let bytes = original.checkpoint.clone();
    assert!(
        owner
            .validate_original(&original)
            .unwrap_err()
            .to_string()
            .contains("invalid retained native operation checkpoint")
    );
    assert_eq!(
        owner.authority.test_checkpoint_import_attempts(),
        before + 1
    );
    assert_eq!(original.checkpoint, bytes);
    original.checkpoint.clear();
    assert!(
        owner
            .validate_original(&original)
            .unwrap_err()
            .to_string()
            .contains("original top-up checkpoint exceeds its bound")
    );
    assert_eq!(
        owner.authority.test_checkpoint_import_attempts(),
        before + 1
    );
    original.checkpoint = bytes;
    owner.validate_original_selection(&original).unwrap();
    assert!(owner.validate_original(&original).is_err());
    assert_eq!(
        owner.authority.test_checkpoint_import_attempts(),
        before + 2
    );
}
