//! Claimed setup inputs and real bounded wallet journals; no native authority is fabricated.

use super::super::setup_test_support::{account, empty_quote, service};
use super::*;
use std::{sync::atomic::Ordering, time::Instant};

use iroha_data_model::{
    isi::GrantBox, sorafs::stream_token_gateway::StreamTokenGatewayAdmissionQualificationV1,
};
use std::collections::BTreeSet;

fn request(config: &Config, now: u64) -> InitialGatewaySetupRequest {
    let label = "wallet-native-gateway".to_owned();
    let gateway_id = derive_stream_token_gateway_id_v1(&config.network_id, &label).unwrap();
    let operator = account(21);
    let observer = account(22);
    let mut policy = StreamTokenGatewayPolicyV1 {
        network_id: config.network_id,
        compliance_gateway_id: label.clone(),
        qualification: StreamTokenGatewayAdmissionQualificationV1 {
            gateway_id,
            revision: 1,
            policy_digest: [0; 32],
            max_pending: 64,
            max_tracked_tokens: 128,
            lease_ttl_ms: 30_000,
        },
        operators: BTreeSet::from([operator.clone()]),
        observers: BTreeSet::from([observer.clone()]),
        valid_from_unix_ms: now,
        valid_until_unix_ms: now + 600_000,
        max_observation_age_ms: 30_000,
        admission_enabled: true,
    };
    policy.qualification.policy_digest = policy.calculate_policy_digest().unwrap();
    policy.validate().unwrap();
    InitialGatewaySetupRequest {
        selection: InitialGatewaySetupSelection {
            chain_id: config.chain.to_string(),
            network_id: config.network_id,
            manager: config.account.clone(),
            compliance_gateway_id: label,
            gateway_id,
            policy_digest: policy.qualification.policy_digest,
            operator,
            observer,
        },
        policy,
        deadline_unix_ms: now + 50_000,
        options: BoundedTransactionOptions {
            fee_payment: FeePaymentIntent::authority(Vec::new(), None),
            max_total_fees: BTreeMap::new(),
            deadline: Instant::now() + Duration::from_secs(60),
        },
    }
}

#[test]
fn exact_ordered_configure_and_typed_grants_pay_only_manager_fees() {
    let (service, transport) = service();
    let request = request(&service.config, current_unix_ms().unwrap());
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("gateway");
    let report = service
        .prepare_initial_gateway_setup(&request, &path)
        .unwrap();
    assert_eq!(report.status, OperationStatus::Prepared);
    let signed = service
        .verify_initial_gateway_setup_journal(&path, &request)
        .unwrap();
    let Executable::Instructions(items) = signed.instructions() else {
        panic!("explicit instructions")
    };
    assert_eq!(items.len(), 3);
    let configure = items[0]
        .as_any()
        .downcast_ref::<MutateSorafsStreamTokenGateway>()
        .unwrap();
    assert_eq!(configure.request.expected_policy_revision, 0);
    assert_eq!(configure.request.expected_policy_digest, [0; 32]);
    assert_eq!(
        configure.request.action,
        StreamTokenGatewayActionV1::Configure(request.policy.clone())
    );
    for (index, expected, to) in [
        (
            1,
            iroha_data_model::permission::Permission::from(CanOperateSorafsStreamTokenGateway {
                gateway_id: request.selection.gateway_id,
            }),
            &request.selection.operator,
        ),
        (
            2,
            iroha_data_model::permission::Permission::from(CanCheckSorafsStreamTokenGateway {
                gateway_id: request.selection.gateway_id,
            }),
            &request.selection.observer,
        ),
    ] {
        let GrantBox::Permission(grant) = items[index].as_any().downcast_ref::<GrantBox>().unwrap()
        else {
            panic!("exact permission")
        };
        assert_eq!(grant.object(), &expected);
        assert_eq!(grant.destination(), to);
    }
    let record: TransactionJournal = Journal::open(&path).unwrap().read_operation().unwrap();
    assert!(
        record
            .operation
            .principal(&service.config.account)
            .unwrap()
            .is_empty()
    );
    assert_eq!(signed.authority(), &service.config.account);
    assert_eq!(transport.quotes.load(Ordering::SeqCst), 1);
    assert_eq!(transport.submissions.load(Ordering::SeqCst), 0);
    assert!(
        service
            .submit(&path, NativeOperationKind::InitialGatewaySetup)
            .is_err()
    );
    assert!(
        service
            .resume(&path, NativeOperationKind::InitialGatewaySetup)
            .is_err()
    );
}

#[test]
fn all_gateway_selection_bindings_and_roles_refuse_before_http() {
    let (service, transport) = service();
    let original = request(&service.config, current_unix_ms().unwrap());
    let changes: [fn(&mut InitialGatewaySetupRequest); 12] = [
        |r| r.selection.chain_id.push('x'),
        |r| {
            r.selection.network_id = iroha_data_model::NetworkId::from_genesis_hash(
                iroha_crypto::HashOf::from_untyped_unchecked(iroha_crypto::Hash::new(
                    b"other setup network",
                )),
            )
        },
        |r| r.selection.manager = account(31),
        |r| r.selection.compliance_gateway_id.push('x'),
        |r| r.selection.gateway_id[0] ^= 1,
        |r| r.selection.policy_digest[0] ^= 1,
        |r| r.selection.operator = account(31),
        |r| r.selection.observer = account(31),
        |r| {
            r.policy.operators.insert(account(31));
            r.policy.qualification.policy_digest = r.policy.calculate_policy_digest().unwrap();
            r.selection.policy_digest = r.policy.qualification.policy_digest;
        },
        |r| {
            r.policy.observers = BTreeSet::from([r.selection.operator.clone()]);
            r.selection.observer = r.selection.operator.clone();
            r.policy.qualification.policy_digest = r.policy.calculate_policy_digest().unwrap();
            r.selection.policy_digest = r.policy.qualification.policy_digest;
        },
        |r| {
            r.policy.qualification.revision = 2;
            r.policy.qualification.policy_digest = r.policy.calculate_policy_digest().unwrap();
            r.selection.policy_digest = r.policy.qualification.policy_digest;
        },
        |r| r.deadline_unix_ms = u64::MAX,
    ];
    let root = tempfile::tempdir().unwrap();
    for (index, change) in changes.into_iter().enumerate() {
        let mut r = original.clone();
        change(&mut r);
        let path = root.path().join(index.to_string());
        assert!(service.prepare_initial_gateway_setup(&r, &path).is_err());
        assert!(!path.exists());
    }
    assert_eq!(transport.requests.load(Ordering::SeqCst), 0);
}

#[test]
fn original_fields_fees_and_wire_survive_ambiguous_submission_and_reopen() {
    let (service, transport) = service();
    let mut request = request(&service.config, current_unix_ms().unwrap());
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("setup");
    service
        .prepare_initial_gateway_setup(&request, &path)
        .unwrap();
    *transport.journal.lock().unwrap() = Some(path.clone());
    let wire = service
        .verify_initial_gateway_setup_journal(&path, &request)
        .unwrap()
        .encode_versioned();
    let original = std::fs::read(path.join("operation.json")).unwrap();
    let calls = transport.requests.load(Ordering::SeqCst);
    let mut changed = request.clone();
    changed.deadline_unix_ms += 1;
    assert!(
        service
            .verify_initial_gateway_setup_journal(&path, &changed)
            .is_err()
    );
    assert!(
        service
            .submit_initial_gateway_setup(&path, &changed)
            .is_err()
    );
    let mut changed = request.clone();
    changed
        .options
        .max_total_fees
        .insert(XOR_ASSET_DEFINITION.parse().unwrap(), Quantity::from(1u32));
    assert!(
        service
            .resume_initial_gateway_setup(&path, &changed)
            .is_err()
    );
    let mut changed = request.clone();
    changed.policy.admission_enabled = false;
    changed.policy.qualification.policy_digest = changed.policy.calculate_policy_digest().unwrap();
    changed.selection.policy_digest = changed.policy.qualification.policy_digest;
    assert!(
        service
            .verify_initial_gateway_setup_journal(&path, &changed)
            .is_err()
    );
    assert_eq!(transport.requests.load(Ordering::SeqCst), calls);
    assert_eq!(
        service
            .submit_initial_gateway_setup(&path, &request)
            .unwrap()
            .status,
        OperationStatus::Pending
    );
    let marker = std::fs::read(path.join("submission.json")).unwrap();
    request.options.deadline = Instant::now() + Duration::from_secs(120);
    for _ in 0..2 {
        assert_eq!(
            service
                .submit_initial_gateway_setup(&path, &request)
                .unwrap()
                .status,
            OperationStatus::Pending
        );
        assert_eq!(
            service
                .resume_initial_gateway_setup(&path, &request)
                .unwrap()
                .status,
            OperationStatus::Pending
        );
        assert_eq!(
            service
                .verify_initial_gateway_setup_journal(&path, &request)
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
fn signed_order_body_metadata_and_purpose_substitution_are_refused() {
    let (service, _) = service();
    let request = request(&service.config, current_unix_ms().unwrap());
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("setup");
    service
        .prepare_initial_gateway_setup(&request, &path)
        .unwrap();
    let record: TransactionJournal = Journal::open(&path).unwrap().read_operation().unwrap();
    let original = record.verify(&service.config).unwrap();
    let expected = Plan::new(&request, current_unix_ms().unwrap())
        .unwrap()
        .instructions(&service.config)
        .unwrap();
    for kind in 0..3 {
        let mut payload = original.payload().clone();
        let mut items = expected.clone();
        if kind == 0 {
            items.swap(0, 1);
        } else if kind == 1 {
            items.push(expected[0].clone());
        } else {
            payload.metadata.insert(
                "unexpected_setup".parse().unwrap(),
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
        GatewaySetupExpectation(&request)
            .verify(&preparation::Selection {
                operation: &altered.operation,
                requested_fee: &altered.requested_fee,
                deadline_ms: altered.deadline_ms
            })
            .is_err()
    );
}

#[test]
fn component_and_fee_bounds_refuse_before_network_and_decode_refusal_survives() {
    let (service, transport) = service();
    let original = request(&service.config, current_unix_ms().unwrap());
    let root = tempfile::tempdir().unwrap();
    let mut oversized = original.clone();
    oversized.selection.compliance_gateway_id = "x".repeat(MAX_SELECTION_BYTES + 1);
    assert!(
        service
            .prepare_initial_gateway_setup(&oversized, &root.path().join("oversized"))
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
    let operation = NativeOperation::InitialGatewaySetup {
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
            .verify_initial_gateway_setup_journal(&path, &request)
            .unwrap()
            .encode_versioned(),
        signed.encode_versioned()
    );
    assert_eq!(transport.requests.load(Ordering::SeqCst), 0);
    assert_eq!(
        service
            .resume_initial_gateway_setup(&path, &request)
            .unwrap()
            .status,
        OperationStatus::Expired
    );
    assert_eq!(
        service
            .submit_initial_gateway_setup(&path, &request)
            .unwrap()
            .status,
        OperationStatus::Expired
    );
    assert!(
        service
            .prepare_initial_gateway_setup(&request, &root.path().join("fresh"))
            .is_err()
    );
    assert!(!path.join("submission.json").exists());
    assert_eq!(std::fs::read(path.join("operation.json")).unwrap(), before);
    assert_eq!(transport.quotes.load(Ordering::SeqCst), 0);
    assert_eq!(transport.submissions.load(Ordering::SeqCst), 0);
}

#[test]
fn retain_initial_gateway_setup_request_is_a_real_unsigned_zero_http_boundary() {
    let (service, transport) = service();
    let request = request(&service.config, current_unix_ms().unwrap());
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("request-only-boundary");
    let before = transport.requests.load(std::sync::atomic::Ordering::SeqCst);
    let first = service
        .retain_initial_gateway_setup_request(&request, &path)
        .unwrap();
    assert_eq!(first.phase(), NativePreparationPhase::RequestOnly);
    let commitment = first.request_sha256().unwrap().to_owned();
    let original = std::fs::read(path.join("preparation.json")).unwrap();
    assert!(!path.join("payload.json").exists());
    assert!(!path.join("operation.json").exists());
    assert!(!path.join("submission.json").exists());
    let repeated = service
        .retain_initial_gateway_setup_request(&request, &path)
        .unwrap();
    assert_eq!(repeated.request_sha256(), Some(commitment.as_str()));
    let mut changed = request.clone();
    changed.deadline_unix_ms += 1;
    assert!(
        service
            .retain_initial_gateway_setup_request(&changed, &path)
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
        .prepare_initial_gateway_setup(&request, &path)
        .unwrap();
    let before = transport.requests.load(std::sync::atomic::Ordering::SeqCst);
    let signed = service
        .retain_initial_gateway_setup_request(&request, &path)
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
        .retain_initial_gateway_setup_request(&request, &path)
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
fn retained_parent_initial_gateway_setup_inspection_keeps_exact_phases_lock_and_offline_request_checks()
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
            .inspect_initial_gateway_setup_preparation_in_parent(&parent, name, &request)
            .unwrap()
            .phase(),
        NativePreparationPhase::Missing
    );
    assert!(!path.exists());
    assert!(
        service
            .inspect_initial_gateway_setup_preparation_in_parent(
                &parent,
                std::ffi::OsStr::new("../transaction"),
                &request
            )
            .is_err()
    );
    assert_eq!(transport.requests.load(Ordering::SeqCst), 0);

    let first = service
        .retain_initial_gateway_setup_request(&request, &path)
        .unwrap();
    let original = std::fs::read(path.join("preparation.json")).unwrap();
    let borrowed = service
        .inspect_initial_gateway_setup_preparation_in_parent(&parent, name, &request)
        .unwrap();
    let absolute = service
        .inspect_initial_gateway_setup_preparation(&path, &request)
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
            .inspect_initial_gateway_setup_preparation_in_parent(&parent, name, &changed)
            .is_err()
    );
    assert!(
        service
            .inspect_initial_gateway_setup_preparation(&path, &changed)
            .is_err()
    );
    let held_lock = Journal::open(&path).unwrap();
    assert!(
        service
            .inspect_initial_gateway_setup_preparation_in_parent(&parent, name, &request)
            .is_err()
    );
    drop(held_lock);
    assert_eq!(
        service
            .inspect_initial_gateway_setup_preparation_in_parent(&parent, name, &request)
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
        .prepare_initial_gateway_setup(&request, &path)
        .unwrap();
    let calls = transport.requests.load(Ordering::SeqCst);
    let absolute = service
        .inspect_initial_gateway_setup_preparation(&path, &request)
        .unwrap();
    let borrowed = service
        .inspect_initial_gateway_setup_preparation_in_parent(&parent, name, &request)
        .unwrap();
    assert_eq!(borrowed.phase(), NativePreparationPhase::Signed);
    assert_eq!(borrowed.request_sha256(), absolute.request_sha256());
    assert_eq!(
        borrowed.signed_transaction().unwrap().encode_versioned(),
        absolute.signed_transaction().unwrap().encode_versioned()
    );
    std::fs::remove_file(path.join("operation.json")).unwrap();
    let absolute = service
        .inspect_initial_gateway_setup_preparation(&path, &request)
        .unwrap();
    let borrowed = service
        .inspect_initial_gateway_setup_preparation_in_parent(&parent, name, &request)
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
