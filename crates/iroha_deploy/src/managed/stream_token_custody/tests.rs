//! Managed custody intent persistence, role separation and immutable authorization regressions.

use super::*;
use iroha_crypto::{Algorithm, KeyPair};
use iroha_data_model::{
    account::AccountId, sorafs::capacity::ProviderId, transaction::FeePaymentIntent,
};
use sorafs_manifest::signer::{
    custody::SignerCustodyAuthorityV1,
    protocol::{SignerKeyAlgorithmV1, SignerPurposeBindingV1, SignerRoleV1},
};
use std::collections::BTreeMap;

fn key(seed: u8) -> KeyPair {
    KeyPair::from_seed(vec![seed; 32], Algorithm::Ed25519)
}
fn options() -> BoundedTransactionOptions {
    BoundedTransactionOptions {
        fee_payment: FeePaymentIntent::authority(Vec::new(), None),
        max_total_fees: BTreeMap::new(),
        deadline: Instant::now() + Duration::from_secs(30),
    }
}
fn policy() -> SignerCustodyPolicyV1 {
    let now = now_ms().unwrap();
    SignerCustodyPolicyV1 {
        binding: SignerCustodyBindingV1 {
            chain_id: "custody-network".into(),
            network_id: [1; 32],
            runtime_handle: "software://stream/runtime".into(),
            key_handle: "software://stream/key".into(),
            service_id: "stream-service".into(),
            administrator_id: "stream-admin".into(),
            role: SignerRoleV1::StreamToken,
            purpose: SignerPurposeBindingV1::StreamToken {
                provider_id: [2; 32],
            },
            algorithm: SignerKeyAlgorithmV1::Ed25519,
            public_key: key(3).public_key().clone(),
            key_revision: 1,
            policy_revision: 1,
            policy_digest: [4; 32],
        },
        attester_authority: SignerCustodyAuthorityV1 {
            service_id: "custody-service".into(),
            administrator_id: "custody-admin".into(),
            key_revision: 1,
            policy_revision: 1,
            policy_digest: [5; 32],
        },
        attester_public_key: key(6).public_key().clone(),
        active_from_unix_ms: now - 1_000,
        active_until_unix_ms: now + 120_000,
        max_validity_ms: 60_000,
        max_anchor_age_ms: 30_000,
    }
}
fn original() -> Original {
    let policy = policy();
    Original {
        selection: StreamTokenCustodySelection {
            provider_id: ProviderId::new([2; 32]),
            binding: policy.binding.clone(),
            expected_revision: 0,
            expected_digest: [0; 32],
            current: None,
        },
        action: Action::Configure(policy),
        // Codec-only fixture, never passed to a finality verifier or treated as an anchor.
        checkpoint: vec![1],
    }
}

#[test]
fn original_request_roundtrip_refuses_replacement_and_preserves_expired_terms() {
    let temporary = tempfile::tempdir().unwrap();
    let directory = PrivateDirectory::open_or_create(temporary.path().join("operation")).unwrap();
    require_empty(&directory).unwrap();
    assert!(journal::read_intent(&directory).unwrap().is_none());
    let original = original();
    let mut terms = Terms::new(now_ms().unwrap() + 60_000, &options()).unwrap();
    terms.requested_deadline_unix_ms = now_ms().unwrap() - 100;
    terms.signing_deadline_unix_ms = now_ms().unwrap() - 1_000;
    let terms_bytes = encode(&terms, 16 * 1024).unwrap();
    let restored_terms: Terms = norito::decode_canonical_with_limits(
        &terms_bytes,
        norito::DecodeLimits::new(4096, 16 * 1024, 16 * 1024, 64 * 1024, 32),
    )
    .unwrap();
    assert!(terms == restored_terms);
    journal::publish_intent(&directory, &original).unwrap();
    let mut replacement = original.clone();
    replacement.checkpoint.push(2);
    assert!(journal::publish_intent(&directory, &replacement).is_err());
    assert!(require_empty(&directory).is_err());
    let saved = directory.read("original.nrt", 256 * 1024).unwrap();
    let restored = journal::read_intent(&directory).unwrap().unwrap();
    assert_eq!(saved.as_slice(), encode(&restored, 256 * 1024).unwrap());
    assert!(
        restored_terms
            .signing_deadline(Instant::now() + Duration::from_secs(600))
            .is_err()
    );
    let request = restored
        .request(
            &restored_terms,
            original.initial_observation(),
            Instant::now() + Duration::from_secs(600),
        )
        .unwrap();
    let journal::Request::Configure(request) = request else {
        panic!("closed original purpose");
    };
    assert_eq!(request.deadline_unix_ms, terms.signing_deadline_unix_ms);
    restored.matches_configuration(&request.policy).unwrap();
    restored_terms
        .matches(terms.requested_deadline_unix_ms, &request.options)
        .unwrap();
    let mut changed = request.options;
    changed.fee_payment = FeePaymentIntent::authority(Vec::new(), NonZeroU64::new(1));
    assert!(
        restored_terms
            .matches(terms.requested_deadline_unix_ms, &changed)
            .is_err()
    );
    assert!(
        restored_terms
            .matches(terms.requested_deadline_unix_ms + 1, &options())
            .is_err()
    );
    assert_eq!(
        directory
            .read("original.nrt", 256 * 1024)
            .unwrap()
            .as_slice(),
        saved.as_slice()
    );
}

#[test]
fn original_fee_and_utc_bounds_are_admitted_before_signing() {
    let now = now_ms().unwrap();
    assert!(Terms::new(now, &options()).is_err());
    assert!(Terms::new(u64::MAX, &options()).is_err());
    let terms = Terms::new(now + 600_000, &options()).unwrap();
    assert!(terms.signing_deadline_unix_ms < terms.requested_deadline_unix_ms);
    let next_io = Instant::now() + Duration::from_secs(600);
    assert!(terms.signing_deadline(next_io).unwrap() < next_io);
    let mut excessive = options();
    let asset = iroha_wallet::operations::XOR_ASSET_DEFINITION
        .parse()
        .unwrap();
    excessive
        .max_total_fees
        .insert(asset, iroha_primitives::numeric::Quantity::zero());
    assert!(Terms::new(now + 60_000, &excessive).is_err());
    excessive.max_total_fees.clear();
    for value in 1..=17u8 {
        let mut bytes = [value; 16];
        bytes[6] = 0x40;
        bytes[8] = 0x80;
        excessive.max_total_fees.insert(
            iroha_data_model::asset::AssetDefinitionId::from_uuid_bytes(bytes).unwrap(),
            iroha_primitives::numeric::Quantity::from(1u32),
        );
    }
    assert!(Terms::new(now + 60_000, &excessive).is_err());
    let interval = ManagedCustodyEnrollmentInterval {
        issued_at_unix_ms: now,
        expires_at_unix_ms: now + 30_000,
        deadline_unix_ms: now + 20_000,
    };
    validate_interval(interval, now).unwrap();
    assert!(
        validate_interval(
            ManagedCustodyEnrollmentInterval {
                expires_at_unix_ms: u64::MAX,
                ..interval
            },
            now
        )
        .is_err()
    );
    assert!(
        validate_interval(
            ManagedCustodyEnrollmentInterval {
                issued_at_unix_ms: now + 1,
                ..interval
            },
            now
        )
        .is_err()
    );
    assert!(
        validate_interval(
            ManagedCustodyEnrollmentInterval {
                deadline_unix_ms: now + 30_001,
                ..interval
            },
            now
        )
        .is_err()
    );
}

#[test]
fn fresh_predecessor_must_match_original_absence_or_exact_record_before_signing() {
    use iroha_data_model::sorafs::stream_token_custody::StreamTokenCustodyControlRecordV1;
    use sorafs_manifest::signer::custody_control::configure_signer_custody_policy_v1;
    // Pure admission predicate fixture; no synthetic record is presented as verified evidence.
    let original = original();
    let Action::Configure(policy) = original.action else {
        panic!("configure");
    };
    let control = configure_signer_custody_policy_v1(None, policy).unwrap();
    let mut record = StreamTokenCustodyControlRecordV1 {
        provider_id: original.selection.provider_id,
        revision: 1,
        predecessor_digest: [0; 32],
        request_digest: [8; 32],
        execution_height: 2,
        ordinal: 0,
        recorded_at_unix_ms: now_ms().unwrap(),
        authority: AccountId::new(key(9).public_key().clone()),
        control_state: norito::encode_canonical(&control).unwrap(),
        active_enrollment: None,
    };
    assert!(matches_predecessor(&original.selection, None));
    assert!(!matches_predecessor(&original.selection, Some(&record)));
    let mut selected = original.selection;
    selected.expected_revision = record.revision;
    selected.expected_digest = record.canonical_digest().unwrap();
    selected.current = Some(record.clone());
    assert!(matches_predecessor(&selected, Some(&record)));
    assert!(!matches_predecessor(&selected, None));
    record.revision += 1;
    assert!(!matches_predecessor(&selected, Some(&record)));
    record.revision -= 1;
    let mut revoked = control;
    revoked.signer_revoked = true;
    record.control_state = norito::encode_canonical(&revoked).unwrap();
    assert!(!matches_predecessor(&selected, Some(&record)));
    assert_eq!(selected.expected_revision, 1);
    assert_eq!(selected.current.unwrap().revision, 1);
}

#[test]
fn original_journal_rejects_trailing_and_oversized_policy_frames() {
    let temporary = tempfile::tempdir().unwrap();
    let directory = PrivateDirectory::open_or_create(temporary.path().join("operation")).unwrap();
    let mut original = original();
    let mut bytes = encode(&original, 256 * 1024).unwrap();
    bytes.push(0);
    directory
        .write_atomic("original.nrt", &bytes, PublishMode::CreateNew)
        .unwrap();
    assert!(journal::read_intent(&directory).is_err());
    let Action::Configure(policy) = &mut original.action else {
        panic!("configure");
    };
    policy.binding.runtime_handle = "x".repeat(16 * 1024);
    assert!(original.validate().is_err());
}

#[test]
fn invalid_enrollment_interval_cannot_reserve_or_replace_original_journal() {
    use iroha_data_model::sorafs::stream_token_custody::StreamTokenCustodyControlRecordV1;
    use sorafs_manifest::signer::{
        custody::SignerCustodyAnchorV1, custody_control::configure_signer_custody_policy_v1,
    };
    let now = now_ms().unwrap();
    let mut policy = policy();
    policy.max_validity_ms = 30_000;
    let control = configure_signer_custody_policy_v1(None, policy.clone()).unwrap();
    let predecessor = StreamTokenCustodyControlRecordV1 {
        provider_id: ProviderId::new([2; 32]),
        revision: 1,
        predecessor_digest: [0; 32],
        request_digest: [8; 32],
        execution_height: 2,
        ordinal: 0,
        recorded_at_unix_ms: now - 1,
        authority: AccountId::new(key(9).public_key().clone()),
        control_state: norito::encode_canonical(&control).unwrap(),
        active_enrollment: None,
    };
    let anchor = SignerCustodyAnchorV1 {
        height: 2,
        block_hash: [7; 32],
        state_digest: predecessor.canonical_digest().unwrap(),
    };
    let make_original = |duration| {
        let interval = ManagedCustodyEnrollmentInterval {
            issued_at_unix_ms: now,
            expires_at_unix_ms: now + duration,
            deadline_unix_ms: now + 10_000,
        };
        let statement = SignerCustodyStatementV1 {
            magic: SIGNER_CUSTODY_MAGIC_V1,
            version: SIGNER_CUSTODY_VERSION_V1,
            binding: policy.binding.clone(),
            authority: policy.attester_authority.clone(),
            anchor,
            sequence: control.next_sequence,
            predecessor_digest: control.predecessor_digest,
            issued_at_unix_ms: interval.issued_at_unix_ms,
            expires_at_unix_ms: interval.expires_at_unix_ms,
            evidence_digest: [5; 32],
            revoked: false,
        };
        let attestation =
            Signature::new(key(6).private_key(), &statement.signing_payload().unwrap())
                .payload()
                .try_into()
                .unwrap();
        Original {
            selection: StreamTokenCustodySelection {
                provider_id: predecessor.provider_id,
                binding: policy.binding.clone(),
                expected_revision: 1,
                expected_digest: anchor.state_digest,
                current: Some(predecessor.clone()),
            },
            action: Action::Enroll {
                anchor,
                selected_at_unix_ms: now,
                validity: journal::EnrollmentValidity::from_interval(interval),
                enrollment: norito::encode_canonical(&SignerCustodyRecordV1 {
                    statement,
                    attestation,
                })
                .unwrap(),
            },
            checkpoint: vec![1], // Codec/authorization fixture, never authenticated finality.
        }
    };
    let temporary = tempfile::tempdir().unwrap();
    let directory = PrivateDirectory::open_or_create(temporary.path().join("enroll")).unwrap();
    let excessive = make_original(45_000);
    assert!(journal::publish_body_intent(&directory, &excessive).is_err());
    assert!(journal::read_body_intent(&directory).unwrap().is_none());
    let valid = make_original(20_000);
    assert!(journal::publish_intent(&directory, &valid).is_err()); // Configure owner cannot publish Enroll.
    journal::publish_body_intent(&directory, &valid).unwrap();
    let saved = directory.read("original.nrt", 256 * 1024).unwrap();
    assert!(journal::publish_body_intent(&directory, &excessive).is_err());
    assert_eq!(
        directory
            .read("original.nrt", 256 * 1024)
            .unwrap()
            .as_slice(),
        saved.as_slice()
    );
    let (restored, restored_bytes) = journal::read_body_intent(&directory).unwrap().unwrap();
    assert_eq!(restored_bytes, saved);
    let Action::Enroll { validity, .. } = restored.action else {
        panic!("enroll");
    };
    let interval = validity.interval(now + 10_000);
    let terms = Terms::new(interval.deadline_unix_ms, &options()).unwrap();
    restored.matches_enrollment_policy(&policy).unwrap();
    terms
        .matches(interval.deadline_unix_ms, &options())
        .unwrap();
    let request = restored
        .request(&terms, restored.initial_observation(), options().deadline)
        .unwrap();
    let journal::Request::Enroll(request) = request else {
        panic!("enroll request");
    };
    assert_eq!(request.issued_at_unix_ms, interval.issued_at_unix_ms);
    assert_eq!(request.expires_at_unix_ms, interval.expires_at_unix_ms);
    let mut changed_policy = policy.clone();
    changed_policy.max_anchor_age_ms += 1;
    assert!(restored.matches_enrollment_policy(&changed_policy).is_err());
    assert!(
        terms
            .matches(interval.deadline_unix_ms + 1, &options())
            .is_err()
    );
    let mut changed_options = options();
    changed_options.fee_payment = FeePaymentIntent::authority(Vec::new(), NonZeroU64::new(1));
    assert!(
        terms
            .matches(interval.deadline_unix_ms, &changed_options)
            .is_err()
    );
}

#[test]
fn generated_roles_and_original_genesis_are_required_before_coordinator_use() {
    let _resources = crate::managed::native_test_guard();
    let temporary = tempfile::tempdir().unwrap();
    let ports = crate::managed::LocalnetPorts::reserve().unwrap();
    let prepared = crate::localnet::prepare_localnet_at(
        "custody",
        &temporary.path().join("generation"),
        &ports,
        crate::localnet::LocalnetServiceProfile::StreamTokenAuthorities,
        None,
    )
    .unwrap();
    let coordinator = ManagedStreamTokenCustody::open(
        &prepared,
        crate::managed::native_operation::test_support::provider_id(&prepared, 0),
    )
    .unwrap();
    assert!(
        ManagedStreamTokenCustody::open(
            &prepared,
            crate::managed::native_operation::test_support::provider_id(&prepared, 0)
        )
        .is_err()
    );
    // Exercise endpoint iteration only: no integer test value is used as native proof evidence.
    let mut calls = 0;
    let deadline = Instant::now() + Duration::from_secs(30);
    let value = read_selected_peers(
        &coordinator.authority.peers,
        deadline,
        |_, attempt_deadline| {
            calls += 1;
            assert!(attempt_deadline <= deadline);
            if calls == 1 {
                Err(invalid("selected peer unavailable"))
            } else {
                Ok(7)
            }
        },
    )
    .unwrap();
    assert_eq!((calls, value), (2, 7));
    assert!(
        read_selected_peers::<()>(&coordinator.authority.peers, Instant::now(), |_, _| panic!(
            "elapsed read budget must not contact a peer"
        ))
        .is_err()
    );
    let mut policy = policy();
    policy.binding.chain_id = coordinator.authority.config.chain.to_string();
    policy.binding.network_id = *coordinator.authority.config.network_id.as_bytes();
    policy.binding.purpose = SignerPurposeBindingV1::StreamToken {
        provider_id: *coordinator.authority.provider_id().unwrap().as_bytes(),
    };
    policy.binding.public_key = coordinator
        .authority
        .provider_role(StreamTokenAuthorityRole::TokenSigner)
        .unwrap()
        .try_signatory()
        .unwrap()
        .clone();
    policy.attester_public_key = coordinator
        .authority
        .provider_role(StreamTokenAuthorityRole::CustodyAttester)
        .unwrap()
        .try_signatory()
        .unwrap()
        .clone();
    coordinator.validate_policy(&policy).unwrap();
    let selection = StreamTokenCustodySelection {
        provider_id: coordinator.authority.provider_id().unwrap(),
        binding: policy.binding.clone(),
        expected_revision: 0,
        expected_digest: [0; 32],
        current: None,
    };
    let evidence = coordinator
        .evidence_digest(&policy, &selection, b"bounded codec fixture")
        .unwrap();
    {
        let _foreign_profile =
            iroha_data_model::account::address::ChainDiscriminantGuard::enter(369);
        assert_eq!(
            coordinator
                .evidence_digest(&policy, &selection, b"bounded codec fixture")
                .unwrap(),
            evidence
        );
    }
    assert_ne!(
        coordinator
            .evidence_digest(&policy, &selection, b"different fixture")
            .unwrap(),
        evidence
    );
    assert_eq!(
        coordinator.attester().unwrap().public_key(),
        &policy.attester_public_key
    );
    policy.attester_public_key = coordinator.authority.config.key_pair.public_key().clone();
    assert!(coordinator.validate_policy(&policy).is_err());
    let mut changed = prepared.clone();
    changed.context.network_id = "another-network".into();
    assert!(
        ManagedStreamTokenCustody::open(
            &changed,
            crate::managed::native_operation::test_support::provider_id(&prepared, 0)
        )
        .is_err()
    );
    drop(coordinator);
    ManagedStreamTokenCustody::open(
        &prepared,
        crate::managed::native_operation::test_support::provider_id(&prepared, 0),
    )
    .unwrap();
}

#[test]
fn original_custody_codec_preserves_checkpoint_larger_than_small_collection_limit() {
    let temporary = tempfile::tempdir().unwrap();
    let directory = PrivateDirectory::open_or_create(temporary.path().join("operation")).unwrap();
    let mut original = original();
    // Codec-only bytes exercise Vec<u8> admission; they are never a certified checkpoint.
    original.checkpoint = vec![0x5a; 16 * 1024];
    journal::publish_intent(&directory, &original).unwrap();
    let restored = journal::read_intent(&directory).unwrap().unwrap();
    assert_eq!(restored.checkpoint, original.checkpoint);
    assert_eq!(
        encode(&restored, 256 * 1024).unwrap(),
        encode(&original, 256 * 1024).unwrap()
    );
}

std::thread_local! {
    static WALLET_CONSTRUCTIONS: std::cell::Cell<Option<usize>> = const { std::cell::Cell::new(None) };
}

pub(super) fn record_wallet_construction() {
    WALLET_CONSTRUCTIONS.with(|value| {
        if let Some(count) = value.get() {
            value.set(Some(
                count
                    .checked_add(1)
                    .expect("test wallet construction count"),
            ));
        }
    });
}

pub(super) fn count_wallet_constructions<T>(action: impl FnOnce() -> T) -> (T, usize) {
    struct Restore(Option<usize>);
    impl Drop for Restore {
        fn drop(&mut self) {
            WALLET_CONSTRUCTIONS.with(|value| value.set(self.0));
        }
    }
    let _restore = Restore(WALLET_CONSTRUCTIONS.with(|value| value.replace(Some(0))));
    let result = action();
    let count = WALLET_CONSTRUCTIONS.with(|value| value.get().expect("test counter active"));
    (result, count)
}
