//! Structural/original registration tests; codec checkpoint bytes never establish native authority.

use super::*;
use crate::localnet::service_authorities::LocalnetServiceProfile;
use crate::managed::native_operation::Fees;
use crate::managed::native_operation::attempts::metadata;
use iroha_crypto::{Algorithm, KeyPair};
use iroha_data_model::{
    NetworkId,
    account::AccountId,
    sorafs::{
        capacity::ProviderId,
        pin_registry::StorageClass,
        reserve::{
            RESERVE_AUTHORITY_POLICY_VERSION_V1, ReserveDuration, ReservePolicyV1, ReserveTier,
        },
    },
    transaction::FeePaymentIntent,
};
use sorafs_manifest::deal::XorQuantity;
use std::{collections::BTreeMap, time::Duration};

pub(super) fn fixture() -> (
    tempfile::TempDir,
    PreparedLocalnet,
    ManagedReserveAccountRegistration,
) {
    let temporary = tempfile::tempdir().unwrap();
    let ports = crate::managed::LocalnetPorts::reserve().unwrap();
    let prepared = crate::localnet::prepare_localnet_at(
        "reserve-register",
        &temporary.path().join("generation"),
        &ports,
        LocalnetServiceProfile::StreamTokenAuthorities,
        None,
    )
    .unwrap();
    let coordinator = ManagedReserveAccountRegistration::open(
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

pub(super) fn policy(coordinator: &ManagedReserveAccountRegistration) -> ReserveAuthorityPolicyV1 {
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

pub(super) fn underwriting(
    coordinator: &ManagedReserveAccountRegistration,
) -> ReserveProviderTermsV1 {
    ReserveProviderTermsV1 {
        provider_id: coordinator.authority.provider_id().unwrap(),
        provider_account: coordinator
            .authority
            .provider_role(StreamTokenAuthorityRole::IssuerOperator)
            .unwrap()
            .clone(),
        tier: ReserveTier::TierA,
        storage_class: StorageClass::Hot,
        duration: ReserveDuration::Monthly,
        capacity_gib: 1,
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
    let underwriting = ReserveProviderTermsV1 {
        provider_id: ProviderId::new([7; 32]),
        provider_account: policy.operations_authority.clone(),
        tier: ReserveTier::TierA,
        storage_class: StorageClass::Hot,
        duration: ReserveDuration::Monthly,
        capacity_gib: 1,
    };
    Original {
        selection: ReserveAccountRegistrationSelection {
            chain_id: "codec-only-unproved-network".into(),
            network_id: NetworkId::from_genesis_hash(iroha_crypto::HashOf::from_untyped_unchecked(
                iroha_crypto::Hash::new(b"codec-only-unproved-genesis"),
            )),
            operations_authority: policy.operations_authority.clone(),
            provider_id: underwriting.provider_id,
            provider_account: underwriting.provider_account.clone(),
            policy_digest: policy.digest().unwrap(),
            asset_definition: policy.asset_definition.clone(),
            custody_account: policy.custody_account.clone(),
            treasury_account: policy.treasury_account.clone(),
            decision_authority: policy.decision_authority.clone(),
        },
        policy,
        underwriting,
        // Deliberately invalid as finality, used only for bounded retained-codec ownership.
        checkpoint: vec![0x5a; 16 * 1024],
    }
}

#[test]
fn registration_original_roundtrip_admits_large_checkpoint_without_proof_claim() {
    let temporary = tempfile::tempdir().unwrap();
    let parent = PrivateDirectory::open_or_create(temporary.path().join("parent")).unwrap();
    let directory = metadata::ensure_operation(&parent, "register").unwrap();
    let original = codec_original();
    let terms = Terms::new(now_ms().unwrap() + 600_000, &options()).unwrap();
    assert!(original.checkpoint.len() > 4096);
    journal::publish_intent(&directory, &original).unwrap();
    let bytes = directory.read("original.nrt", 256 * 1024).unwrap();
    let terms_bytes = encode(&terms, 64 * 1024).unwrap();
    let restored_terms: Terms = norito::decode_canonical(&terms_bytes).unwrap();
    assert!(restored_terms == terms);
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
    assert_eq!(request.underwriting, original.underwriting);
    assert_eq!(
        encode(&request.selection, journal::MAX_SELECTION_BYTES).unwrap(),
        encode(&original.selection, journal::MAX_SELECTION_BYTES).unwrap()
    );
    // No generated profile or verified block is constructed by this codec test.
}

#[test]
fn registration_original_rejects_role_provider_digest_and_underwriting_substitution() {
    let original = codec_original();
    let terms = Terms::new(now_ms().unwrap() + 600_000, &options()).unwrap();
    original.validate().unwrap();
    for field in 0..10 {
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
            _ => changed.underwriting.capacity_gib = 0,
        }
        assert!(
            changed.validate().is_err(),
            "changed original field {field}"
        );
    }
    let options = terms.options(Instant::now() + Duration::from_secs(300));
    let mut changed_policy = original.policy.clone();
    changed_policy.grace_period_days += 1;
    assert!(
        original
            .matches_intent(&changed_policy, &original.underwriting)
            .and_then(|()| terms.matches(terms.requested_deadline_unix_ms, &options))
            .is_err()
    );
    for field in 0..4 {
        let mut changed = original.underwriting.clone();
        match field {
            0 => changed.capacity_gib += 1,
            1 => changed.tier = ReserveTier::TierB,
            2 => changed.duration = ReserveDuration::Annual,
            _ => changed.storage_class = StorageClass::Cold,
        }
        assert!(
            original
                .matches_intent(&original.policy, &changed)
                .and_then(|()| terms.matches(terms.requested_deadline_unix_ms, &options))
                .is_err()
        );
    }
}

#[test]
fn expired_registration_retains_original_utc_and_fees_across_fresh_io_deadline() {
    let original = codec_original();
    let mut terms = Terms::new(now_ms().unwrap() + 600_000, &options()).unwrap();
    let now = now_ms().unwrap();
    terms.requested_deadline_unix_ms = now - 100;
    terms.signing_deadline_unix_ms = now - 200;
    let terms_bytes = encode(&terms, 64 * 1024).unwrap();
    let restored_terms: Terms = norito::decode_canonical(&terms_bytes).unwrap();
    assert!(restored_terms == terms);
    original.validate().unwrap();
    let temporary = tempfile::tempdir().unwrap();
    let parent = PrivateDirectory::open_or_create(temporary.path().join("parent")).unwrap();
    let directory = metadata::ensure_operation(&parent, "register").unwrap();
    journal::publish_intent(&directory, &original).unwrap();
    let retained = directory.read("original.nrt", 256 * 1024).unwrap();
    let original = journal::read_intent(&directory).unwrap().unwrap();
    let options = terms.options(Instant::now() + Duration::from_secs(900));
    original
        .matches_intent(&original.policy, &original.underwriting)
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
            .matches_intent(&original.policy, &original.underwriting)
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
            .matches_intent(&original.policy, &original.underwriting)
            .and_then(|()| terms.matches(terms.requested_deadline_unix_ms, &changed))
            .is_err()
    );
    changed = options.clone();
    changed.fee_payment = FeePaymentIntent::authority(Vec::new(), std::num::NonZeroU64::new(1));
    assert!(
        original
            .matches_intent(&original.policy, &original.underwriting)
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
        retained.as_slice()
    );
}

#[test]
fn generated_registration_selects_exact_original_roles_and_accepts_policy_rotation() {
    let _resources = crate::managed::native_test_guard();
    let (_temporary, prepared, coordinator) = fixture();
    let policy = policy(&coordinator);
    let terms = underwriting(&coordinator);
    coordinator.validate_registration(&policy, &terms).unwrap();
    let selection = coordinator.selection(&policy, &terms).unwrap();
    assert_ne!(selection.operations_authority, terms.provider_account);
    assert_eq!(selection.operations_authority, *coordinator.authority.network_role(crate::localnet::service_authorities::NetworkServiceAuthorityRole::ReserveOperations).unwrap());
    assert_ne!(
        selection.operations_authority,
        coordinator.authority.config.account
    );
    let operator = coordinator.authority.reserve_operations_config().unwrap();
    assert_eq!(operator.account, selection.operations_authority);
    assert_eq!(
        operator.account.try_signatory(),
        Some(operator.key_pair.public_key())
    );
    let mut rotated = policy.clone();
    rotated.revision = 2;
    rotated.predecessor_policy_digest = Some(policy.digest().unwrap());
    coordinator.validate_registration(&rotated, &terms).unwrap();
    assert!(
        ManagedReserveAccountRegistration::open(
            &prepared,
            crate::managed::native_operation::test_support::provider_id(&prepared, 0)
        )
        .is_err()
    );
    let mut changed = prepared.clone();
    changed.context.dataspace_id = 7;
    assert!(
        ManagedReserveAccountRegistration::open(
            &changed,
            crate::managed::native_operation::test_support::provider_id(&prepared, 0)
        )
        .is_err()
    );
    changed = prepared.clone();
    changed.service_profile = LocalnetServiceProfile::Standard;
    assert!(
        ManagedReserveAccountRegistration::open(
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
    ManagedReserveAccountRegistration::open(
        &prepared,
        crate::managed::native_operation::test_support::provider_id(&prepared, 0),
    )
    .unwrap();
}

#[test]
fn selected_recovery_distinguishes_absent_empty_and_dirty_without_http() {
    let _guard = crate::managed::native_test_guard();
    let (_temporary, prepared, mut owner) = fixture();
    let policy = policy(&owner);
    let underwriting = underwriting(&owner);
    let options = options();
    let mut peers =
        crate::managed::native_operation::test_support::UnavailablePeers::start(&prepared);
    assert!(
        owner
            .recover_selected_if_present(
                &policy,
                &underwriting,
                &Fees::from_options(&options).unwrap(),
                options.deadline
            )
            .unwrap()
            .is_none()
    );
    assert!(!owner.authority.directory.path().join("register").exists());
    let directory = owner.authority.directory.ensure_child("register").unwrap();
    assert!(matches!(
        owner
            .recover_selected_if_present(
                &policy,
                &underwriting,
                &Fees::from_options(&options).unwrap(),
                options.deadline
            )
        , Err(crate::managed::Error::Invalid(message)) if message == "operation metadata image is absent"
    ));
    crate::managed::native_operation::require_empty(&directory).unwrap();
    let path = directory.path().to_path_buf();
    drop(directory);
    std::fs::remove_dir(&path).unwrap();
    let directory = metadata::ensure_operation(&owner.authority.directory, "register").unwrap();
    assert!(
        owner
            .recover_selected_if_present(
                &policy,
                &underwriting,
                &Fees::from_options(&options).unwrap(),
                options.deadline
            )
            .unwrap()
            .is_none()
    );
    metadata::require_unselected(&directory).unwrap();
    directory
        .write_atomic("incomplete.nrt", &[1], iroha_fs::PublishMode::CreateNew)
        .unwrap();
    assert!(
        owner
            .recover_selected_if_present(
                &policy,
                &underwriting,
                &Fees::from_options(&options).unwrap(),
                options.deadline
            )
            .is_err()
    );
    assert!(!directory.path().join("transaction").exists());
    assert_eq!(
        directory.read("incomplete.nrt", 1).unwrap().as_slice(),
        &[1]
    );
    assert!(peers.requests.lock().unwrap().is_empty());
    peers.finish();
}

// Create an actual committed RequestOnly history. No signature or native finality is invented.
pub(super) fn retain_explicit_request(
    coordinator: &ManagedReserveAccountRegistration,
    directory: &PrivateDirectory,
    original: &Original,
    utc: u64,
    options: &BoundedTransactionOptions,
) -> Selected<Original> {
    journal::publish_intent(directory, original).unwrap();
    assert_eq!(
        directory.entries(3).unwrap(),
        vec![
            std::ffi::OsString::from(metadata::FILE),
            std::ffi::OsString::from("original.nrt"),
        ]
    );
    assert!(
        journal::required_original(directory).is_err(),
        "semantic bytes alone are not a committed dispatch"
    );
    let wallet =
        AccountService::new(coordinator.authority.reserve_operations_config().unwrap()).unwrap();
    journal::explicit(directory, original, utc, options, &wallet).unwrap();
    let selected = journal::required_original(directory).unwrap();
    assert_eq!(
        wallet
            .inspect_reserve_account_registration_preparation(
                &selected.directory().path().join("transaction"),
                &selected.request(options.deadline)
            )
            .unwrap()
            .phase(),
        iroha_wallet::operations::NativePreparationPhase::RequestOnly
    );
    selected
}
