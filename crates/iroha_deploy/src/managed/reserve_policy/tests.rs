//! Original-intent and provenance controls; synthetic codec values never establish native proof.

use super::*;
use crate::managed::native_operation::Fees;
use crate::managed::native_operation::test_support::native_fixture::policy;
use iroha_crypto::{Algorithm, HashOf, KeyPair};
use iroha_data_model::{account::AccountId, transaction::FeePaymentIntent};
use std::{collections::BTreeMap, num::NonZeroU64, time::Duration};

fn fixture() -> (
    tempfile::TempDir,
    PreparedLocalnet,
    ManagedInitialReservePolicy,
) {
    let temporary = tempfile::tempdir().unwrap();
    let ports = crate::managed::LocalnetPorts::reserve().unwrap();
    let prepared = crate::localnet::prepare_localnet_at(
        "reserve-policy",
        &temporary.path().join("generation"),
        &ports,
        crate::localnet::LocalnetServiceProfile::StreamTokenAuthorities,
        None,
    )
    .unwrap();
    let coordinator = ManagedInitialReservePolicy::open(&prepared).unwrap();
    (temporary, prepared, coordinator)
}
fn account(seed: u8) -> AccountId {
    AccountId::new(
        KeyPair::from_seed(vec![seed; 32], Algorithm::Ed25519)
            .public_key()
            .clone(),
    )
}

fn options() -> BoundedTransactionOptions {
    BoundedTransactionOptions {
        fee_payment: FeePaymentIntent::authority(Vec::new(), None),
        max_total_fees: BTreeMap::new(),
        deadline: Instant::now() + Duration::from_secs(30),
    }
}
fn codec_original(coordinator: &ManagedInitialReservePolicy) -> Original {
    let policy = policy(&coordinator.authority);
    Original {
        selection: coordinator.selection(&policy).unwrap(),
        policy,
        // Explicit invalid finality bytes used only for codec and refusal controls.
        checkpoint: vec![1],
    }
}

#[test]
fn generated_reserve_roles_and_exclusive_original_profile_are_required() {
    let _resources = crate::managed::native_test_guard();
    let (_temporary, prepared, coordinator) = fixture();
    assert!(ManagedInitialReservePolicy::open(&prepared).is_err());
    let policy = policy(&coordinator.authority);
    coordinator.validate_policy(&policy).unwrap();
    for replace in 0..6 {
        let mut changed = policy.clone();
        match replace {
            0 => changed.custody_account = account(60),
            1 => changed.treasury_account = account(61),
            2 => changed.operations_authority = account(62),
            3 => changed.decision_authority = account(63),
            4 => {
                changed.revision = 2;
                changed.predecessor_policy_digest = Some([9; 32]);
            }
            _ => {
                changed.asset_definition = AssetDefinitionId::from_uuid_bytes([
                    0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x48, 0x99, 0x88, 0x99, 0xaa, 0xbb, 0xcc,
                    0xdd, 0xee, 0xff,
                ])
                .unwrap()
            }
        }
        assert!(
            coordinator.validate_policy(&changed).is_err(),
            "role/asset/revision {replace}"
        );
    }
    let mut changed = prepared.clone();
    changed.context.dataspace_id = 7;
    assert!(ManagedInitialReservePolicy::open(&changed).is_err());
    changed = prepared.clone();
    changed.service_profile = crate::localnet::LocalnetServiceProfile::Standard;
    assert!(ManagedInitialReservePolicy::open(&changed).is_err());
    let entries = coordinator.authority.directory.entries(8).unwrap();
    assert_eq!(entries, vec![std::ffi::OsString::from("operation.lock")]);
    drop(coordinator);
    ManagedInitialReservePolicy::open(&prepared).unwrap();
}

#[test]
fn reserve_original_roundtrip_preserves_expired_utc_and_rejects_replacement() {
    let _resources = crate::managed::native_test_guard();
    let (_temporary, _prepared, coordinator) = fixture();
    let directory = coordinator.authority.directory.ensure_child("set").unwrap();
    let original = codec_original(&coordinator);
    let mut terms = Terms::new(now_ms().unwrap() + 60_000, &options()).unwrap();
    terms.requested_deadline_unix_ms = now_ms().unwrap() - 100;
    terms.signing_deadline_unix_ms = now_ms().unwrap() - 200;
    journal::publish_intent(&directory, &original).unwrap();
    let bytes = directory.read("original.nrt", 256 * 1024).unwrap();
    let terms_bytes = encode(&terms, 64 * 1024).unwrap();
    let restored_terms: Terms = norito::decode_canonical(&terms_bytes).unwrap();
    assert!(restored_terms == terms);
    let restored = journal::read_intent(&directory).unwrap().unwrap();
    assert_eq!(bytes.as_slice(), encode(&restored, 256 * 1024).unwrap());
    let request = restored.request(&terms, Instant::now() + Duration::from_secs(600));
    assert_eq!(request.deadline_unix_ms, terms.signing_deadline_unix_ms);
    restored
        .matches_policy(&original.policy)
        .and_then(|()| terms.matches(terms.requested_deadline_unix_ms, &request.options))
        .unwrap();
    assert!(terms.signing_deadline(request.options.deadline).is_err());
    let mut replacement = restored.clone();
    replacement.checkpoint.push(0x6b);
    assert!(journal::publish_intent(&directory, &replacement).is_err());
    let mut changed = original.policy.clone();
    changed.grace_period_days += 1;
    assert!(
        restored
            .matches_policy(&changed)
            .and_then(|()| terms.matches(terms.requested_deadline_unix_ms, &request.options))
            .is_err()
    );
    assert!(
        restored
            .matches_policy(&original.policy)
            .and_then(|()| terms.matches(terms.requested_deadline_unix_ms + 1, &request.options))
            .is_err()
    );
    let mut changed = request.options.clone();
    changed.fee_payment = FeePaymentIntent::authority(Vec::new(), NonZeroU64::new(1));
    assert!(
        restored
            .matches_policy(&original.policy)
            .and_then(|()| terms.matches(terms.requested_deadline_unix_ms, &changed))
            .is_err()
    );
    let mut changed = request.options;
    changed.max_total_fees.insert(
        original.policy.asset_definition.clone(),
        iroha_primitives::numeric::Quantity::from(1_u64),
    );
    assert!(
        restored
            .matches_policy(&original.policy)
            .and_then(|()| terms.matches(terms.requested_deadline_unix_ms, &changed))
            .is_err()
    );
    assert_eq!(
        directory
            .read("original.nrt", 256 * 1024)
            .unwrap()
            .as_slice(),
        bytes.as_slice()
    );
}

#[test]
fn reserve_original_rejects_selection_mutations_and_invalid_native_checkpoint_before_wallet() {
    let _resources = crate::managed::native_test_guard();
    let (_temporary, _prepared, mut coordinator) = fixture();
    let original = codec_original(&coordinator);
    let original_bytes = encode(&original, 256 * 1024).unwrap();
    let imports = coordinator.authority.test_checkpoint_import_attempts();
    // This original is only a prelude/codec control: its invalid checkpoint grants no authority.
    coordinator.validate_original_selection(&original).unwrap();
    assert_eq!(
        coordinator.authority.test_checkpoint_import_attempts(),
        imports
    );
    for mutation in 0..8 {
        let mut changed = original.clone();
        match mutation {
            0 => changed.selection.manager = account(81),
            1 => changed.selection.chain_id.push_str("-changed"),
            2 => {
                changed.selection.network_id = NetworkId::from_genesis_hash(
                    HashOf::from_untyped_unchecked(Hash::new(b"different-genesis")),
                )
            }
            3 => changed.selection.policy_digest = [5; 32],
            4 => changed.selection.custody_account = account(82),
            5 => changed.selection.treasury_account = account(83),
            6 => changed.selection.operations_authority = account(84),
            _ => changed.selection.decision_authority = account(85),
        }
        let error = coordinator.validate_original(&changed).unwrap_err();
        let expected = if mutation < 3 {
            "original reserve selection differs from the authenticated generation"
        } else {
            "original reserve policy intent differs from its immutable selection"
        };
        assert!(
            error.to_string().contains(expected),
            "selection {mutation}: {error}"
        );
        assert_eq!(
            coordinator.authority.test_checkpoint_import_attempts(),
            imports
        );
        assert_eq!(encode(&original, 256 * 1024).unwrap(), original_bytes);
    }
    let error = coordinator.validate_original(&original).unwrap_err();
    assert!(
        error
            .to_string()
            .contains("invalid retained native operation checkpoint")
    );
    assert_eq!(
        coordinator.authority.test_checkpoint_import_attempts(),
        imports + 1
    );
    coordinator.validate_original_selection(&original).unwrap();
    assert_eq!(encode(&original, 256 * 1024).unwrap(), original_bytes);
    let directory = coordinator.authority.directory.ensure_child("set").unwrap();
    let original = retain_explicit_request(
        &coordinator,
        &directory,
        &original,
        now_ms().unwrap() + 60_000,
        &options(),
    );
    let bytes = directory.read("original.nrt", 256 * 1024).unwrap();
    for mode in [Advance::ObserveOnly, Advance::SubmitOriginal] {
        let error = coordinator
            .advance_original(Instant::now() + Duration::from_secs(10), mode, true, None)
            .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("invalid retained native operation checkpoint")
        );
        assert!(
            !original
                .directory()
                .path()
                .join("transaction/payload.json")
                .exists()
        );
        assert!(
            !original
                .directory()
                .path()
                .join("transaction/operation.json")
                .exists()
        );
        assert_eq!(
            directory
                .read("original.nrt", 256 * 1024)
                .unwrap()
                .as_slice(),
            bytes.as_slice()
        );
    }
}

#[test]
fn exact_reserve_record_comparison_does_not_create_activation_without_native_evidence() {
    let _resources = crate::managed::native_test_guard();
    let (_temporary, _prepared, coordinator) = fixture();
    let original = codec_original(&coordinator);
    // These are comparison-only values. They are never passed as verified chain or state facts.
    let finality = ManagedTransactionFinality {
        transaction_hash: HashOf::from_untyped_unchecked(Hash::new(b"comparison-transaction")),
        height: 3,
        block_hash: HashOf::from_untyped_unchecked(Hash::new(b"comparison-header")),
        block_time_ms: 123_456,
    };
    let record = ReserveAuthorityPolicyRecordV1 {
        policy: original.policy.clone(),
        policy_digest: original.selection.policy_digest,
        activated_by: original.selection.manager.clone(),
        activated_at_unix: 123,
    };
    assert!(matches_activation_record(&original, &finality, &record));
    for mutation in 0..4 {
        let mut changed = record.clone();
        match mutation {
            0 => changed.policy.grace_period_days += 1,
            1 => changed.policy_digest = [7; 32],
            2 => changed.activated_by = account(93),
            _ => changed.activated_at_unix += 1,
        }
        assert!(!matches_activation_record(&original, &finality, &changed));
    }
    let observed = progress(&original, OperationStatus::Applied, None, None);
    assert!(observed.finalized.is_none());
    assert!(
        observed.activation().is_none(),
        "node Applied is not original inclusion"
    );
    let historical_only = progress(&original, OperationStatus::Applied, Some(finality), None);
    assert!(
        historical_only.activation().is_none(),
        "historical report lacks fresh policy evidence"
    );
}

#[test]
fn original_reserve_codec_preserves_checkpoint_larger_than_small_collection_limit() {
    let _resources = crate::managed::native_test_guard();
    let (_temporary, _prepared, coordinator) = fixture();
    let directory = coordinator.authority.directory.ensure_child("set").unwrap();
    let mut original = codec_original(&coordinator);
    // Codec-only bytes exercise Vec<u8> admission, never native finality or initial eligibility.
    original.checkpoint = vec![0xa5; 16 * 1024];
    journal::publish_intent(&directory, &original).unwrap();
    let restored = journal::read_intent(&directory).unwrap().unwrap();
    assert_eq!(restored.checkpoint, original.checkpoint);
    assert_eq!(
        encode(&restored, 256 * 1024).unwrap(),
        encode(&original, 256 * 1024).unwrap()
    );
    assert!(
        coordinator.validate_original(&restored).is_err(),
        "codec bytes cannot become native authority"
    );
}

#[test]
fn selected_recovery_distinguishes_absent_empty_and_dirty_without_http() {
    let _guard = crate::managed::native_test_guard();
    let (_temporary, prepared, mut owner) = fixture();
    let policy = policy(&owner.authority);
    let options = options();
    let mut peers =
        crate::managed::native_operation::test_support::UnavailablePeers::start(&prepared);
    assert!(
        owner
            .recover_selected_if_present(
                &policy,
                &Fees::from_options(&options).unwrap(),
                options.deadline
            )
            .unwrap()
            .is_none()
    );
    assert!(!owner.authority.directory.path().join("set").exists());
    let directory = owner.authority.directory.ensure_child("set").unwrap();
    assert!(
        owner
            .recover_selected_if_present(
                &policy,
                &Fees::from_options(&options).unwrap(),
                options.deadline
            )
            .unwrap()
            .is_none()
    );
    require_empty(&directory).unwrap();
    directory
        .write_atomic("incomplete.nrt", &[1], iroha_fs::PublishMode::CreateNew)
        .unwrap();
    assert!(
        owner
            .recover_selected_if_present(
                &policy,
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
    coordinator: &ManagedInitialReservePolicy,
    directory: &PrivateDirectory,
    original: &Original,
    utc: u64,
    options: &BoundedTransactionOptions,
) -> Selected<Original> {
    journal::publish_intent(directory, original).unwrap();
    assert_eq!(
        directory.entries(3).unwrap(),
        vec![std::ffi::OsString::from("original.nrt")]
    );
    assert!(
        journal::required_original(directory).is_err(),
        "semantic bytes alone are not a committed dispatch"
    );
    let wallet = AccountService::new(coordinator.authority.config.clone()).unwrap();
    journal::explicit(directory, original, utc, options, &wallet).unwrap();
    let selected = journal::required_original(directory).unwrap();
    assert_eq!(
        wallet
            .inspect_initial_reserve_policy_preparation(
                &selected.directory().path().join("transaction"),
                &selected.request(options.deadline)
            )
            .unwrap()
            .phase(),
        iroha_wallet::operations::NativePreparationPhase::RequestOnly
    );
    selected
}
