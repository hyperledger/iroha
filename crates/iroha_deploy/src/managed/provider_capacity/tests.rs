//! Generated profile binding and codec-only originals; dummy checkpoints never prove native state.

use super::*;
use crate::localnet::service_authorities::LocalnetServiceProfile;
use crate::managed::native_operation::test_support::native_fixture::policy as generated_policy;
use iroha_data_model::{
    sorafs::{capacity::CapacityDeclarationRecord, reserve::ReserveLifecycleStage},
    transaction::FeePaymentIntent,
};
use std::{collections::BTreeMap, time::Duration};

pub(super) fn fixture() -> (tempfile::TempDir, PreparedLocalnet, ManagedProviderCapacity) {
    let temporary = tempfile::tempdir().unwrap();
    let ports = crate::managed::LocalnetPorts::reserve().unwrap();
    let prepared = crate::localnet::prepare_localnet_at(
        "provider-capacity",
        &temporary.path().join("generation"),
        &ports,
        LocalnetServiceProfile::StreamTokenAuthorities,
        None,
    )
    .unwrap();
    let coordinator = ManagedProviderCapacity::open(
        &prepared,
        crate::managed::native_operation::test_support::provider_id(&prepared, 0),
    )
    .unwrap();
    (temporary, prepared, coordinator)
}
pub(super) fn options() -> BoundedTransactionOptions {
    BoundedTransactionOptions {
        fee_payment: FeePaymentIntent::authority(Vec::new(), None),
        max_total_fees: BTreeMap::new(),
        deadline: Instant::now() + Duration::from_secs(300),
    }
}
pub(super) fn policy(coordinator: &ManagedProviderCapacity) -> ReserveAuthorityPolicyV1 {
    generated_policy(&coordinator.authority)
}

pub(super) fn codec_original(coordinator: &ManagedProviderCapacity) -> Original {
    let plan = coordinator.plan().unwrap();
    let policy = policy(coordinator);
    let partition = ReserveProviderAccountV1 {
        terms: plan.reserve_terms().clone(),
        policy_digest: policy.digest().unwrap(),
        revision: 7,
        reserve_balance: "50".parse().unwrap(),
        debt_principal: "0".parse().unwrap(),
        accrued_interest: "0".parse().unwrap(),
        credit_cap: "0".parse().unwrap(),
        lifecycle_stage: ReserveLifecycleStage::Active,
        days_past_due: 0,
        pending_movements: 0,
        open_appeals: 0,
        rent_charged_through_unix: 1,
        interest_accrued_at_unix: 1,
        updated_at_unix: 1,
    };
    let observed_block_time_ms = now_ms().unwrap();
    let credit = ProviderCreditRecord::new(
        partition.terms.provider_id,
        "1".parse().unwrap(),
        "50".parse().unwrap(),
        "1".parse().unwrap(),
        "1".parse().unwrap(),
        observed_block_time_ms / 1000,
        observed_block_time_ms / 1000,
        iroha_model_base::metadata::Metadata::default(),
    );
    let economics = provider_economics::derive_retained(
        &plan,
        &policy,
        &partition,
        Some(&credit),
        plan.pricing(),
        observed_block_time_ms,
    )
    .unwrap();
    Original {
        selection: coordinator
            .selection(&policy, &partition, &credit, plan.declaration())
            .unwrap(),
        policy,
        partition,
        credit,
        declaration: plan.declaration().clone(),
        pricing: plan.pricing().clone(),
        previous_capacity: None,
        observed_block_time_ms,
        economics,
        checkpoint: vec![0x5a; 16 * 1024],
    }
}

#[test]
fn capacity_original_roundtrip_preserves_large_checkpoint_and_prior_capacity_bytes() {
    let _resources = crate::managed::native_test_guard();
    let (_temporary, _prepared, coordinator) = fixture();
    let mut original = codec_original(&coordinator);
    original.previous_capacity = Some(CapacityDeclarationRecord::new(
        original.selection.provider_id,
        vec![0x6b; 16 * 1024],
        1,
        1,
        1,
        2,
        iroha_model_base::metadata::Metadata::default(),
    ));
    // Raw previous bytes exercise codec admission only; no proof validator sees this specimen.
    let directory = coordinator
        .authority
        .directory
        .ensure_child("declare")
        .unwrap();
    journal::publish_intent(&directory, &original).unwrap();
    let restored = journal::read_intent(&directory).unwrap().unwrap();
    assert_eq!(
        encode(&restored, 512 * 1024).unwrap(),
        encode(&original, 512 * 1024).unwrap()
    );
    assert_eq!(restored.checkpoint.len(), 16 * 1024);
    assert_eq!(
        restored.previous_capacity.unwrap().declaration.len(),
        16 * 1024
    );
    let mut replacement = original.clone();
    replacement.checkpoint.push(0x6b);
    assert!(journal::publish_intent(&directory, &replacement).is_err());
}

#[test]
fn capacity_generation_binding_rejects_policy_declaration_pricing_and_network_substitution() {
    let _resources = crate::managed::native_test_guard();
    let (_temporary, _prepared, coordinator) = fixture();
    let original = codec_original(&coordinator);
    for field in 0..8 {
        let mut changed = original.clone();
        match field {
            0 => changed.selection.chain_id.push_str("-other"),
            1 => changed.pricing.notes = Some("different authenticated selection required".into()),
            2 => {
                changed.declaration.stake.pool_id[0] ^= 1;
                changed.selection.declaration_hash =
                    iroha_crypto::HashOf::try_new(&changed.declaration).unwrap();
            }
            3 => changed.economics.available_credit = "2".parse().unwrap(),
            4 => changed.partition.terms.capacity_gib += 1,
            5 => changed.selection.provider_account = changed.policy.decision_authority.clone(),
            6 => changed.policy.custody_account = changed.policy.treasury_account.clone(),
            _ => {
                changed.selection.network_id = iroha_data_model::NetworkId::from_genesis_hash(
                    iroha_crypto::HashOf::from_untyped_unchecked(iroha_crypto::Hash::new(
                        b"other actual genesis",
                    )),
                )
            }
        }
        let error = coordinator.validate_original(&changed).unwrap_err();
        assert!(
            !error
                .to_string()
                .contains("invalid retained native operation checkpoint"),
            "field {field} was not refused before checkpoint: {error}"
        );
    }
    assert!(
        coordinator
            .validate_original(&original)
            .unwrap_err()
            .to_string()
            .contains("invalid retained native operation checkpoint")
    );
}

#[test]
fn capacity_original_utc_and_fee_terms_never_renew_and_large_components_refuse() {
    let mut terms = Terms::new(now_ms().unwrap() + 600_000, &options()).unwrap();
    let _resources = crate::managed::native_test_guard();
    let (_temporary, _prepared, coordinator) = fixture();
    let mut original = codec_original(&coordinator);
    terms.signing_deadline_unix_ms = 1;
    let io = Instant::now() + Duration::from_secs(900);
    let options = terms.options(io);
    original
        .matches_intent(&original.policy)
        .and_then(|()| terms.matches(terms.requested_deadline_unix_ms, &options))
        .unwrap();
    assert_eq!(original.request(&terms, io).deadline_unix_ms, 1);
    assert!(terms.signing_deadline(io).is_err());
    assert!(
        original
            .matches_intent(&original.policy)
            .and_then(|()| terms.matches(terms.requested_deadline_unix_ms + 1, &options))
            .is_err()
    );
    let mut changed = options.clone();
    changed.max_total_fees.insert(
        original.policy.asset_definition.clone(),
        "1".parse().unwrap(),
    );
    assert!(
        original
            .matches_intent(&original.policy)
            .and_then(|()| terms.matches(terms.requested_deadline_unix_ms, &changed))
            .is_err()
    );
    changed = options;
    changed.fee_payment = FeePaymentIntent::authority(Vec::new(), std::num::NonZeroU64::new(1));
    assert!(
        original
            .matches_intent(&original.policy)
            .and_then(|()| terms.matches(terms.requested_deadline_unix_ms, &changed))
            .is_err()
    );
    original.previous_capacity = Some(CapacityDeclarationRecord::new(
        original.selection.provider_id,
        vec![0; journal::MAX_CAPACITY_BYTES],
        1,
        1,
        1,
        2,
        iroha_model_base::metadata::Metadata::default(),
    ));
    assert!(
        original
            .validate()
            .unwrap_err()
            .to_string()
            .contains("byte bound")
    );
}

// Create a real committed request-only attempt through the sole wallet/epoch owner. This helper
// neither signs nor treats codec-only checkpoints as native evidence.
pub(super) fn retain_explicit_request(
    coordinator: &ManagedProviderCapacity,
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
            .inspect_provider_capacity_declaration_preparation(
                &selected.directory().path().join("transaction"),
                &selected.request(options.deadline),
            )
            .unwrap()
            .phase(),
        iroha_wallet::operations::NativePreparationPhase::RequestOnly,
    );
    selected
}
