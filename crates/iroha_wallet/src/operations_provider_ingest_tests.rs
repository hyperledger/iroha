//! Structural initial intent, exact signed profile and once-only journal controls.
use super::super::setup_test_support::{account, empty_quote, service};
use super::*;
use iroha_data_model::sorafs::pin_registry::ProviderIngestCompletionSignerPolicyV1;
use std::{sync::atomic::Ordering, time::Instant};

fn request(config: &Config, now: u64) -> InitialProviderIngestAuthorityRequest {
    InitialProviderIngestAuthorityRequest {
        chain_id: config.chain.to_string(),
        network_id: config.network_id,
        provider_id: ProviderId::new([0x21; 32]),
        authority: ProviderIngestCompletionAuthorityV1::new(
            config.account.clone(),
            account(22),
            ProviderIngestCompletionSignerPolicyV1 {
                policy_id: [0x23; 32],
                revision: 1,
                predecessor_digest: None,
                policy_digest: [0x24; 32],
            },
        ),
        deadline_unix_ms: now + 50_000,
        options: BoundedTransactionOptions {
            fee_payment: FeePaymentIntent::authority(Vec::new(), None),
            max_total_fees: BTreeMap::new(),
            deadline: Instant::now() + Duration::from_secs(60),
        },
    }
}
#[test]
fn exact_initial_set_binds_independent_signer_and_charges_only_owner_fees() {
    let (service, transport) = service();
    let request = request(&service.config, current_unix_ms().unwrap());
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("ingest");
    let report = service
        .prepare_initial_provider_ingest_authority(&request, &path)
        .unwrap();
    assert_eq!(report.status, OperationStatus::Prepared);
    let signed = service
        .verify_initial_provider_ingest_authority_journal(&path, &request)
        .unwrap();
    let Executable::Instructions(items) = signed.instructions() else {
        panic!("instructions")
    };
    assert_eq!(items.len(), 1);
    let instruction = items[0]
        .as_any()
        .downcast_ref::<SetProviderIngestCompletionAuthority>()
        .unwrap();
    assert_eq!(instruction.provider_id, request.provider_id);
    assert!(instruction.expected_current.is_none());
    assert_eq!(instruction.next, request.authority);
    assert_eq!(signed.authority(), &request.authority.provider_owner);
    assert_ne!(signed.authority(), &request.authority.completion_signer);
    let record: TransactionJournal = Journal::open(&path).unwrap().read_operation().unwrap();
    assert!(
        record
            .operation
            .principal(&service.config.account)
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        record.operation.kind(),
        NativeOperationKind::InitialProviderIngestAuthority
    );
    assert!(
        norito::json::to_json(&report.data)
            .unwrap()
            .contains("initial_provider_ingest_authority")
    );
    assert!(
        service
            .submit(&path, NativeOperationKind::InitialProviderIngestAuthority)
            .is_err()
    );
    assert!(
        service
            .resume(&path, NativeOperationKind::InitialProviderIngestAuthority)
            .is_err()
    );
    assert_eq!(transport.quotes.load(Ordering::SeqCst), 1);
    assert_eq!(transport.submissions.load(Ordering::SeqCst), 0);
}
#[test]
fn invalid_network_owner_initial_policy_and_finite_deadline_refuse_before_http() {
    let (service, transport) = service();
    let original = request(&service.config, current_unix_ms().unwrap());
    let root = tempfile::tempdir().unwrap();
    let changes: [fn(&mut InitialProviderIngestAuthorityRequest); 9] = [
        |r| r.chain_id.push('x'),
        |r| {
            r.network_id =
                NetworkId::from_genesis_hash(iroha_crypto::HashOf::from_untyped_unchecked(
                    iroha_crypto::Hash::new(b"foreign-ingest-network"),
                ))
        },
        |r| r.provider_id = ProviderId::new([0; 32]),
        |r| r.authority.provider_owner = account(33),
        |r| r.authority.signer_policy.policy_id = [0; 32],
        |r| r.authority.signer_policy.policy_digest = [0; 32],
        |r| {
            r.authority.signer_policy.revision = 2;
            r.authority.signer_policy.predecessor_digest = Some([7; 32]);
        },
        |r| r.deadline_unix_ms = 1,
        |r| r.deadline_unix_ms = u64::MAX,
    ];
    for (i, change) in changes.into_iter().enumerate() {
        let mut selected = original.clone();
        change(&mut selected);
        let path = root.path().join(i.to_string());
        assert!(
            service
                .prepare_initial_provider_ingest_authority(&selected, &path)
                .is_err()
        );
        assert!(!path.exists());
    }
    assert_eq!(transport.requests.load(Ordering::SeqCst), 0);
    // Signer selection is a structural claim. The generic native policy permits the same account;
    // the generated managed owner separately pins its dedicated distinct role.
    let mut same = original;
    same.authority.completion_signer = same.authority.provider_owner.clone();
    Plan::new(&same, current_unix_ms().unwrap())
        .unwrap()
        .instructions(&service.config)
        .unwrap();
}
#[test]
fn immutable_fields_fees_and_wire_survive_503_once_only_and_reopened_journal() {
    let (service, transport) = service();
    let mut request = request(&service.config, current_unix_ms().unwrap());
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("ingest");
    service
        .prepare_initial_provider_ingest_authority(&request, &path)
        .unwrap();
    *transport.journal.lock().unwrap() = Some(path.clone());
    let wire = service
        .verify_initial_provider_ingest_authority_journal(&path, &request)
        .unwrap()
        .encode_versioned();
    let original = std::fs::read(path.join("operation.json")).unwrap();
    let calls = transport.requests.load(Ordering::SeqCst);
    let changes: [fn(&mut InitialProviderIngestAuthorityRequest); 8] = [
        |r| r.provider_id = ProviderId::new([0x31; 32]),
        |r| r.authority.completion_signer = account(32),
        |r| r.authority.provider_owner = account(33),
        |r| r.authority.signer_policy.policy_id[0] ^= 1,
        |r| r.authority.signer_policy.policy_digest[0] ^= 1,
        |r| r.deadline_unix_ms += 1,
        |r| {
            r.options.fee_payment =
                FeePaymentIntent::authority(Vec::new(), std::num::NonZeroU64::new(1))
        },
        |r| {
            r.options
                .max_total_fees
                .insert(XOR_ASSET_DEFINITION.parse().unwrap(), Quantity::from(1u32));
        },
    ];
    for change in changes {
        let mut changed = request.clone();
        change(&mut changed);
        assert!(
            service
                .verify_initial_provider_ingest_authority_journal(&path, &changed)
                .is_err()
        );
        assert!(
            service
                .submit_initial_provider_ingest_authority(&path, &changed)
                .is_err()
        );
        assert!(
            service
                .resume_initial_provider_ingest_authority(&path, &changed)
                .is_err()
        );
    }
    assert_eq!(transport.requests.load(Ordering::SeqCst), calls);
    assert_eq!(
        service
            .resume_initial_provider_ingest_authority(&path, &request)
            .unwrap()
            .status,
        OperationStatus::Absent
    );
    assert!(!path.join("submission.json").exists());
    assert_eq!(
        service
            .submit_initial_provider_ingest_authority(&path, &request)
            .unwrap()
            .status,
        OperationStatus::Pending
    );
    let marker = std::fs::read(path.join("submission.json")).unwrap();
    request.options.deadline = Instant::now() + Duration::from_secs(120);
    for _ in 0..2 {
        assert_eq!(
            service
                .submit_initial_provider_ingest_authority(&path, &request)
                .unwrap()
                .status,
            OperationStatus::Pending
        );
        assert_eq!(
            service
                .resume_initial_provider_ingest_authority(&path, &request)
                .unwrap()
                .status,
            OperationStatus::Pending
        );
        assert_eq!(
            service
                .verify_initial_provider_ingest_authority_journal(&path, &request)
                .unwrap()
                .encode_versioned(),
            wire
        );
    }
    assert_eq!(transport.quotes.load(Ordering::SeqCst), 1);
    assert_eq!(transport.submissions.load(Ordering::SeqCst), 1);
    assert_eq!(
        std::fs::read(path.join("operation.json")).unwrap(),
        original
    );
    assert_eq!(std::fs::read(path.join("submission.json")).unwrap(), marker);
}
#[test]
fn signed_body_metadata_purpose_and_trailing_wire_substitutions_are_refused() {
    let (service, _) = service();
    let request = request(&service.config, current_unix_ms().unwrap());
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("ingest");
    service
        .prepare_initial_provider_ingest_authority(&request, &path)
        .unwrap();
    let record: TransactionJournal = Journal::open(&path).unwrap().read_operation().unwrap();
    let original = record.verify(&service.config).unwrap();
    for kind in 0..3 {
        let mut payload = original.payload().clone();
        let mut authority = request.authority.clone();
        if kind == 0 {
            authority.completion_signer = account(32);
        }
        let one: InstructionBox =
            SetProviderIngestCompletionAuthority::new(request.provider_id, None, authority).into();
        let mut items = vec![one.clone()];
        if kind == 1 {
            items.push(one);
        }
        if kind == 2 {
            payload.metadata.insert(
                "unexpected_ingest".parse().unwrap(),
                iroha_primitives::json::Json::new(true),
            );
        }
        payload.instructions = items.into();
        let signed = service
            .client
            .account_client()
            .sign_transaction(payload)
            .unwrap();
        let mut altered = record.clone();
        altered.signed_transaction_hex = hex::encode(signed.encode_versioned());
        altered.transaction_hash = signed.hash().to_string();
        assert!(altered.verify(&service.config).is_err());
    }
    let mut altered = record.clone();
    altered.signed_transaction_hex.push_str("00");
    assert!(altered.verify(&service.config).is_err());
    let mut altered = record;
    altered.operation = NativeOperation::InitialReservePolicy {
        plan: Vec::new(),
        terms: BoundedTerms::new(&request.options).unwrap(),
    };
    assert!(
        ProviderIngestExpectation(&request)
            .verify(&preparation::Selection {
                operation: &altered.operation,
                requested_fee: &altered.requested_fee,
                deadline_ms: altered.deadline_ms
            })
            .is_err()
    );
}
#[test]
fn component_fee_and_decode_bounds_precede_http_and_preserve_resource_errors() {
    let (service, transport) = service();
    let original = request(&service.config, current_unix_ms().unwrap());
    let root = tempfile::tempdir().unwrap();
    let mut oversized = original.clone();
    oversized.chain_id = "x".repeat(MAX_CHAIN_BYTES + 1);
    assert!(
        service
            .prepare_initial_provider_ingest_authority(&oversized, &root.path().join("oversized"))
            .is_err()
    );
    let mut overfees = original.clone();
    for value in 1..=17 {
        let mut bytes = [value; 16];
        bytes[6] = 0x40;
        bytes[8] = 0x80;
        overfees.options.max_total_fees.insert(
            AssetDefinitionId::from_uuid_bytes(bytes).unwrap(),
            Quantity::from(1u32),
        );
    }
    assert!(Plan::new(&overfees, current_unix_ms().unwrap()).is_err());
    let plan = Plan::new(&original, current_unix_ms().unwrap()).unwrap();
    let bytes = encode_bounded(&plan, MAX_PLAN_BYTES).unwrap();
    assert!(instructions(&service.config, &bytes, plan.validated_at_unix_ms).is_err());
    assert!(instructions(&service.config, &bytes, plan.deadline_unix_ms + 1).is_err());
    let error = norito::with_decode_limits_scope(
        norito::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, 0, 64),
        || instructions(&service.config, &bytes, plan.deadline_unix_ms),
    )
    .unwrap_err();
    assert!(error.chain().any(|cause| {
        cause
            .downcast_ref::<norito::Error>()
            .is_some_and(|e| matches!(e, norito::Error::TotalAllocationExceeded { .. }))
    }));
    assert!(instructions(&service.config, &bytes, plan.deadline_unix_ms).is_ok());
    assert_eq!(transport.requests.load(Ordering::SeqCst), 0);
}

#[test]
fn expired_original_can_be_verified_and_read_without_renewal_or_dispatch() {
    let (service, transport) = service();
    let original_time = current_unix_ms().unwrap() - 200_000;
    let mut request = request(&service.config, original_time);
    let plan = Plan::new(&request, original_time).unwrap();
    let mut terms = BoundedTerms::new(&request.options).unwrap();
    terms.deadline_ms = request.deadline_unix_ms;
    let operation = NativeOperation::InitialProviderIngestAuthority {
        plan: encode_bounded(&plan, MAX_PLAN_BYTES).unwrap(),
        terms,
    };
    let mut builder = iroha_data_model::transaction::TransactionBuilder::new(
        service.config.network_id,
        service.config.account.clone(),
        request.options.fee_payment.clone(),
    )
    .with_instructions(operation.instructions(&service.config).unwrap());
    builder.set_creation_time(Duration::from_millis(original_time));
    builder.set_ttl(Duration::from_millis(
        request.deadline_unix_ms - original_time,
    ));
    let signed = builder.sign(service.config.key_pair.private_key());
    let record = TransactionJournal {
        schema: "iroha.wallet.native-transaction.v1".into(),
        torii_url: service.config.torii_api_url.to_string(),
        chain_id: service.config.chain.to_string(),
        network_id: service.config.network_id,
        chain_discriminant: service.config.account_chain_discriminant,
        account_id: service.config.account.clone(),
        operation,
        requested_fee: request.options.fee_payment.clone(),
        quote: empty_quote(&service.config.account, &request.options.fee_payment),
        transaction_hash: signed.hash().to_string(),
        signed_transaction_hex: hex::encode(signed.encode_versioned()),
        deadline_ms: request.deadline_unix_ms,
    };
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("historical");
    drop(preparation::retain_signed_fixture(&path, &record).unwrap());
    let before = std::fs::read(path.join("operation.json")).unwrap();
    request.options.deadline = Instant::now() + Duration::from_secs(120);
    assert_eq!(
        service
            .verify_initial_provider_ingest_authority_journal(&path, &request)
            .unwrap()
            .encode_versioned(),
        signed.encode_versioned()
    );
    assert_eq!(transport.requests.load(Ordering::SeqCst), 0);
    assert_eq!(
        service
            .resume_initial_provider_ingest_authority(&path, &request)
            .unwrap()
            .status,
        OperationStatus::Expired
    );
    assert_eq!(
        service
            .submit_initial_provider_ingest_authority(&path, &request)
            .unwrap()
            .status,
        OperationStatus::Expired
    );
    assert!(
        service
            .prepare_initial_provider_ingest_authority(&request, &root.path().join("fresh"))
            .is_err()
    );
    assert!(!path.join("submission.json").exists());
    assert_eq!(std::fs::read(path.join("operation.json")).unwrap(), before);
    assert_eq!(transport.quotes.load(Ordering::SeqCst), 0);
    assert_eq!(transport.submissions.load(Ordering::SeqCst), 0);
}

#[test]
fn retain_initial_provider_ingest_authority_request_is_a_real_unsigned_zero_http_boundary() {
    let (service, transport) = service();
    let request = request(&service.config, current_unix_ms().unwrap());
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("request-only-boundary");
    let before = transport.requests.load(std::sync::atomic::Ordering::SeqCst);
    let first = service
        .retain_initial_provider_ingest_authority_request(&request, &path)
        .unwrap();
    assert_eq!(first.phase(), NativePreparationPhase::RequestOnly);
    let commitment = first.request_sha256().unwrap().to_owned();
    let original = std::fs::read(path.join("preparation.json")).unwrap();
    assert!(!path.join("payload.json").exists());
    assert!(!path.join("operation.json").exists());
    assert!(!path.join("submission.json").exists());
    let repeated = service
        .retain_initial_provider_ingest_authority_request(&request, &path)
        .unwrap();
    assert_eq!(repeated.request_sha256(), Some(commitment.as_str()));
    let mut changed = request.clone();
    changed.deadline_unix_ms += 1;
    assert!(
        service
            .retain_initial_provider_ingest_authority_request(&changed, &path)
            .is_err()
    );
    assert_eq!(
        transport.requests.load(std::sync::atomic::Ordering::SeqCst),
        before
    );
    assert_eq!(
        std::fs::read(path.join("preparation.json")).unwrap(),
        original
    );

    service
        .prepare_initial_provider_ingest_authority(&request, &path)
        .unwrap();
    let before = transport.requests.load(std::sync::atomic::Ordering::SeqCst);
    let signed = service
        .retain_initial_provider_ingest_authority_request(&request, &path)
        .unwrap();
    assert_eq!(signed.phase(), NativePreparationPhase::Signed);
    assert_eq!(signed.request_sha256(), Some(commitment.as_str()));
    assert_eq!(
        std::fs::read(path.join("preparation.json")).unwrap(),
        original
    );
    // Genuine durable prefix before signature publication; retain cannot finish the payload.
    std::fs::remove_file(path.join("operation.json")).unwrap();
    let partial = service
        .retain_initial_provider_ingest_authority_request(&request, &path)
        .unwrap();
    assert_eq!(partial.phase(), NativePreparationPhase::PayloadRetained);
    assert_eq!(partial.request_sha256(), Some(commitment.as_str()));
    assert!(!path.join("operation.json").exists());
    assert_eq!(
        transport.requests.load(std::sync::atomic::Ordering::SeqCst),
        before
    );
}

#[test]
fn retained_parent_initial_provider_ingest_authority_inspection_keeps_exact_phases_lock_and_offline_request_checks()
 {
    let (service, transport) = service();
    let request = request(&service.config, current_unix_ms().unwrap());
    let root = tempfile::tempdir().unwrap();
    let owner = iroha_fs::OwnerDirectory::open(root.path()).unwrap();
    let parent = owner.create_private_child("parent").unwrap();
    let name = std::ffi::OsStr::new("transaction");
    let path = parent.path().join(name);
    assert_eq!(
        service
            .inspect_initial_provider_ingest_authority_preparation_in_parent(
                &parent, name, &request
            )
            .unwrap()
            .phase(),
        NativePreparationPhase::Missing
    );
    assert!(!path.exists());
    assert!(
        service
            .inspect_initial_provider_ingest_authority_preparation_in_parent(
                &parent,
                std::ffi::OsStr::new("../transaction"),
                &request
            )
            .is_err()
    );
    assert_eq!(transport.requests.load(Ordering::SeqCst), 0);

    let first = service
        .retain_initial_provider_ingest_authority_request(&request, &path)
        .unwrap();
    let original = std::fs::read(path.join("preparation.json")).unwrap();
    let borrowed = service
        .inspect_initial_provider_ingest_authority_preparation_in_parent(&parent, name, &request)
        .unwrap();
    let absolute = service
        .inspect_initial_provider_ingest_authority_preparation(&path, &request)
        .unwrap();
    assert_eq!(borrowed.phase(), NativePreparationPhase::RequestOnly);
    assert_eq!(borrowed.phase(), absolute.phase());
    assert_eq!(borrowed.request_sha256(), first.request_sha256());
    assert_eq!(borrowed.request_sha256(), absolute.request_sha256());
    assert_eq!(borrowed.unprepared_status(), absolute.unprepared_status());
    assert!(borrowed.signed_transaction().is_none());
    let mut changed = request.clone();
    changed.deadline_unix_ms += 1;
    assert!(
        service
            .inspect_initial_provider_ingest_authority_preparation_in_parent(
                &parent, name, &changed
            )
            .is_err()
    );
    assert!(
        service
            .inspect_initial_provider_ingest_authority_preparation(&path, &changed)
            .is_err()
    );
    let held_lock = Journal::open(&path).unwrap();
    assert!(
        service
            .inspect_initial_provider_ingest_authority_preparation_in_parent(
                &parent, name, &request
            )
            .is_err()
    );
    drop(held_lock);
    assert_eq!(
        service
            .inspect_initial_provider_ingest_authority_preparation_in_parent(
                &parent, name, &request
            )
            .unwrap()
            .request_sha256(),
        first.request_sha256()
    );
    assert_eq!(transport.requests.load(Ordering::SeqCst), 0);
    assert_eq!(
        std::fs::read(path.join("preparation.json")).unwrap(),
        original
    );

    service
        .prepare_initial_provider_ingest_authority(&request, &path)
        .unwrap();
    let calls = transport.requests.load(Ordering::SeqCst);
    let absolute = service
        .inspect_initial_provider_ingest_authority_preparation(&path, &request)
        .unwrap();
    let borrowed = service
        .inspect_initial_provider_ingest_authority_preparation_in_parent(&parent, name, &request)
        .unwrap();
    assert_eq!(borrowed.phase(), NativePreparationPhase::Signed);
    assert_eq!(borrowed.request_sha256(), absolute.request_sha256());
    assert_eq!(
        borrowed.signed_transaction().unwrap().encode_versioned(),
        absolute.signed_transaction().unwrap().encode_versioned()
    );
    std::fs::remove_file(path.join("operation.json")).unwrap();
    let absolute = service
        .inspect_initial_provider_ingest_authority_preparation(&path, &request)
        .unwrap();
    let borrowed = service
        .inspect_initial_provider_ingest_authority_preparation_in_parent(&parent, name, &request)
        .unwrap();
    assert_eq!(borrowed.phase(), NativePreparationPhase::PayloadRetained);
    assert_eq!(borrowed.phase(), absolute.phase());
    assert_eq!(borrowed.request_sha256(), absolute.request_sha256());
    assert_eq!(borrowed.unprepared_status(), absolute.unprepared_status());
    assert!(borrowed.signed_transaction().is_none());
    assert!(!path.join("operation.json").exists());
    assert!(!path.join("submission.json").exists());
    assert_eq!(
        std::fs::read(path.join("preparation.json")).unwrap(),
        original
    );
    assert_eq!(transport.requests.load(Ordering::SeqCst), calls);
}
