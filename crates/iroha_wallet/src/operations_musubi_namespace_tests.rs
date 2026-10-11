//! Structural namespace intent and actual wallet journal controls; no native ownership is fabricated.
use super::super::setup_test_support::{account, empty_quote, service};
use super::*;
use iroha_data_model::musubi::{MusubiNamespaceV1, MusubiPackageScopeV1};
use iroha_model_base::topology::DataSpaceId;
use std::{sync::atomic::Ordering, time::Instant};

pub(super) fn request(config: &Config, now: u64) -> MusubiNamespaceBindingRequest {
    MusubiNamespaceBindingRequest {
        selection: MusubiNamespaceBindingSelection {
            chain_id: config.chain.to_string(),
            network_id: config.network_id,
            owner: config.account.clone(),
            expected_policy_revision: 1,
            binding: MusubiNamespaceBindingV1 {
                namespace: MusubiNamespaceV1::new("dev.universal").unwrap(),
                home_dataspace: DataSpaceId::UNIVERSAL,
                scope: MusubiPackageScopeV1::Domain("dev".parse().unwrap()),
                generation: 1,
            },
        },
        deadline_unix_ms: now + 50_000,
        options: BoundedTransactionOptions {
            fee_payment: FeePaymentIntent::authority(Vec::new(), None),
            max_total_fees: BTreeMap::new(),
            deadline: Instant::now() + Duration::from_secs(60),
        },
    }
}
#[test]
fn exact_namespace_register_uses_owner_fee_only_and_refuses_generic_dispatch() {
    let (service, transport) = service();
    let request = request(&service.config, current_unix_ms().unwrap());
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("namespace");
    let report = service
        .prepare_musubi_namespace_binding(&request, &path)
        .unwrap();
    assert_eq!(report.status, OperationStatus::Prepared);
    let signed = service
        .verify_musubi_namespace_binding_journal(&path, &request)
        .unwrap();
    let Executable::Instructions(items) = signed.instructions() else {
        panic!("native instruction")
    };
    assert_eq!(items.len(), 1);
    let register = items[0]
        .as_any()
        .downcast_ref::<RegisterMusubiNamespaceBindingV1>()
        .unwrap();
    assert_eq!(register.binding, request.selection.binding);
    assert_eq!(
        register.expected_policy_revision,
        request.selection.expected_policy_revision
    );
    assert_eq!(signed.authority(), &request.selection.owner);
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
        NativeOperationKind::MusubiNamespaceBinding
    );
    assert!(
        norito::json::to_json(&report.data)
            .unwrap()
            .contains("musubi_namespace_binding")
    );
    assert!(
        service
            .submit(&path, NativeOperationKind::MusubiNamespaceBinding)
            .is_err()
    );
    assert!(
        service
            .resume(&path, NativeOperationKind::MusubiNamespaceBinding)
            .is_err()
    );
    assert_eq!(transport.quotes.load(Ordering::SeqCst), 1);
    assert_eq!(transport.submissions.load(Ordering::SeqCst), 0);
}
#[test]
fn malformed_binding_identity_policy_and_utc_refuse_before_http_or_custody() {
    let (service, transport) = service();
    let original = request(&service.config, current_unix_ms().unwrap());
    let root = tempfile::tempdir().unwrap();
    let changes: [fn(&mut MusubiNamespaceBindingRequest); 9] = [
        |r| r.selection.chain_id.push('x'),
        |r| {
            r.selection.network_id =
                NetworkId::from_genesis_hash(iroha_crypto::HashOf::from_untyped_unchecked(
                    iroha_crypto::Hash::new(b"foreign namespace network"),
                ))
        },
        |r| r.selection.owner = account(44),
        |r| r.selection.expected_policy_revision = 0,
        |r| r.selection.binding.generation = 0,
        |r| r.selection.binding.namespace = MusubiNamespaceV1::new("other.universal").unwrap(),
        |r| r.selection.binding.scope = MusubiPackageScopeV1::DataspaceRoot,
        |r| r.deadline_unix_ms = 1,
        |r| r.deadline_unix_ms = u64::MAX,
    ];
    for (index, change) in changes.into_iter().enumerate() {
        let mut selected = original.clone();
        change(&mut selected);
        let path = root.path().join(index.to_string());
        assert!(
            service
                .prepare_musubi_namespace_binding(&selected, &path)
                .is_err()
        );
        assert!(!path.exists());
    }
    // Native generation/policy can advance; this structural wallet owner does not invent a V1-only rule.
    let mut later = original;
    later.selection.binding.generation = 2;
    later.selection.expected_policy_revision = 3;
    assert!(
        Plan::new(&later, current_unix_ms().unwrap())
            .unwrap()
            .instructions(&service.config)
            .is_ok()
    );
    assert_eq!(transport.requests.load(Ordering::SeqCst), 0);
}
#[test]
fn original_fields_fee_limits_and_wire_survive_503_once_only_reopen() {
    let (service, transport) = service();
    let mut selected = request(&service.config, current_unix_ms().unwrap());
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("namespace");
    service
        .prepare_musubi_namespace_binding(&selected, &path)
        .unwrap();
    *transport.journal.lock().unwrap() = Some(path.clone());
    let wire = service
        .verify_musubi_namespace_binding_journal(&path, &selected)
        .unwrap()
        .encode_versioned();
    let original = std::fs::read(path.join("operation.json")).unwrap();
    let calls = transport.requests.load(Ordering::SeqCst);
    let changes: [fn(&mut MusubiNamespaceBindingRequest); 8] = [
        |r| r.selection.binding.generation += 1,
        |r| r.selection.binding.home_dataspace = DataSpaceId::new(7),
        |r| {
            r.selection.binding.namespace = MusubiNamespaceV1::new("other.universal").unwrap();
            r.selection.binding.scope = MusubiPackageScopeV1::Domain("other".parse().unwrap());
        },
        |r| r.selection.expected_policy_revision += 1,
        |r| r.selection.owner = account(47),
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
        let mut changed = selected.clone();
        change(&mut changed);
        assert!(
            service
                .verify_musubi_namespace_binding_journal(&path, &changed)
                .is_err()
        );
        assert!(
            service
                .submit_musubi_namespace_binding(&path, &changed)
                .is_err()
        );
        assert!(
            service
                .resume_musubi_namespace_binding(&path, &changed)
                .is_err()
        );
    }
    assert_eq!(transport.requests.load(Ordering::SeqCst), calls);
    assert_eq!(
        service
            .resume_musubi_namespace_binding(&path, &selected)
            .unwrap()
            .status,
        OperationStatus::Absent
    );
    assert!(!path.join("submission.json").exists());
    assert_eq!(
        service
            .submit_musubi_namespace_binding(&path, &selected)
            .unwrap()
            .status,
        OperationStatus::Pending
    );
    let marker = std::fs::read(path.join("submission.json")).unwrap();
    selected.options.deadline = Instant::now() + Duration::from_secs(120);
    for _ in 0..2 {
        let (recovered, phase) = service
            .recover_musubi_namespace_binding_request(&path, &selected.selection, &selected.options)
            .unwrap();
        assert_eq!(recovered.deadline_unix_ms, selected.deadline_unix_ms);
        assert_eq!(phase.phase(), NativePreparationPhase::Signed);
        assert_eq!(
            service
                .submit_musubi_namespace_binding(&path, &recovered)
                .unwrap()
                .status,
            OperationStatus::Pending
        );
        assert_eq!(
            service
                .resume_musubi_namespace_binding(&path, &recovered)
                .unwrap()
                .status,
            OperationStatus::Pending
        );
        assert_eq!(
            service
                .verify_musubi_namespace_binding_journal(&path, &recovered)
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
fn original_request_getter_refuses_missing_changed_and_broken_custody_without_http() {
    let (service, transport) = service();
    let selected = request(&service.config, current_unix_ms().unwrap());
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("namespace");
    assert!(
        service
            .recover_musubi_namespace_binding_request(&path, &selected.selection, &selected.options)
            .is_err()
    );
    assert!(!path.exists());
    let first = service
        .retain_musubi_namespace_binding_request(&selected, &path)
        .unwrap();
    assert_eq!(first.phase(), NativePreparationPhase::RequestOnly);
    let original = std::fs::read(path.join("preparation.json")).unwrap();
    let (recovered, phase) = service
        .recover_musubi_namespace_binding_request(&path, &selected.selection, &selected.options)
        .unwrap();
    assert_eq!(phase.request_sha256(), first.request_sha256());
    assert_eq!(recovered.deadline_unix_ms, selected.deadline_unix_ms);
    let mut changed = selected.selection.clone();
    changed.binding.generation += 1;
    assert!(
        service
            .recover_musubi_namespace_binding_request(&path, &changed, &selected.options)
            .is_err()
    );
    let mut options = selected.options.clone();
    options
        .max_total_fees
        .insert(XOR_ASSET_DEFINITION.parse().unwrap(), Quantity::from(1u32));
    assert!(
        service
            .recover_musubi_namespace_binding_request(&path, &selected.selection, &options)
            .is_err()
    );
    assert_eq!(
        std::fs::read(path.join("preparation.json")).unwrap(),
        original
    );
    iroha_fs::PrivateDirectory::open(&path)
        .unwrap()
        .write_atomic("payload.json", b"{}", iroha_fs::PublishMode::CreateNew)
        .unwrap();
    assert!(
        service
            .recover_musubi_namespace_binding_request(&path, &selected.selection, &selected.options)
            .is_err()
    );
    std::fs::remove_file(path.join("payload.json")).unwrap();
    std::fs::remove_file(path.join("preparation.json")).unwrap();
    assert!(
        service
            .recover_musubi_namespace_binding_request(&path, &selected.selection, &selected.options)
            .is_err()
    );
    assert!(!path.join("preparation.json").exists());
    assert_eq!(transport.requests.load(Ordering::SeqCst), 0);
}
#[test]
fn request_only_retirement_is_explicit_and_does_not_create_payload_or_signature() {
    let (service, transport) = service();
    let selected = request(&service.config, current_unix_ms().unwrap());
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("namespace");
    let original = service
        .retain_musubi_namespace_binding_request(&selected, &path)
        .unwrap();
    let retired = service
        .retire_musubi_namespace_binding_unprepared(&path, &selected)
        .unwrap();
    assert_eq!(Some(retired.request_sha256()), original.request_sha256());
    let (recovered, inspection) = service
        .recover_musubi_namespace_binding_request(&path, &selected.selection, &selected.options)
        .unwrap();
    assert_eq!(recovered.deadline_unix_ms, selected.deadline_unix_ms);
    assert_eq!(inspection.phase(), NativePreparationPhase::Retired);
    assert!(
        service
            .prepare_musubi_namespace_binding(&recovered, &path)
            .is_err()
    );
    assert!(!path.join("payload.json").exists());
    assert!(!path.join("operation.json").exists());
    assert!(!path.join("submission.json").exists());
    assert_eq!(transport.requests.load(Ordering::SeqCst), 0);
}
#[test]
fn complete_signed_body_and_purpose_substitutions_cannot_pass_original_verification() {
    let (service, _) = service();
    let selected = request(&service.config, current_unix_ms().unwrap());
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("namespace");
    service
        .prepare_musubi_namespace_binding(&selected, &path)
        .unwrap();
    let record: TransactionJournal = Journal::open(&path).unwrap().read_operation().unwrap();
    let original = record.verify(&service.config).unwrap();
    for kind in 0..3 {
        let mut payload = original.payload().clone();
        let mut binding = selected.selection.binding.clone();
        if kind == 0 {
            binding.generation += 1;
        }
        let one: InstructionBox = RegisterMusubiNamespaceBindingV1::new(
            binding,
            selected.selection.expected_policy_revision,
        )
        .into();
        let mut items = vec![one.clone()];
        if kind == 1 {
            items.push(one);
        }
        if kind == 2 {
            payload.metadata.insert(
                "unexpected_namespace".parse().unwrap(),
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
        terms: BoundedTerms::new(&selected.options).unwrap(),
    };
    assert!(
        MusubiNamespaceExpectation(&selected)
            .verify(&preparation::Selection {
                operation: &altered.operation,
                requested_fee: &altered.requested_fee,
                deadline_ms: altered.deadline_ms
            })
            .is_err()
    );
}
#[test]
fn canonical_plan_bounds_and_original_interval_refuse_before_http() {
    let (service, transport) = service();
    let selected = request(&service.config, current_unix_ms().unwrap());
    let mut oversized = selected.clone();
    oversized.selection.chain_id = "x".repeat(MAX_CHAIN_BYTES + 1);
    let root = tempfile::tempdir().unwrap();
    assert!(
        service
            .prepare_musubi_namespace_binding(&oversized, &root.path().join("oversized"))
            .is_err()
    );
    let plan = Plan::new(&selected, current_unix_ms().unwrap()).unwrap();
    let bytes = encode_bounded(&plan, MAX_PLAN_BYTES).unwrap();
    assert!(instructions(&service.config, &bytes, plan.validated_at_unix_ms).is_err());
    assert!(instructions(&service.config, &bytes, plan.deadline_unix_ms + 1).is_err());
    let error = norito::with_decode_limits_scope(
        norito::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, 0, 64),
        || instructions(&service.config, &bytes, plan.deadline_unix_ms),
    )
    .unwrap_err();
    assert!(error.chain().any(|e| {
        e.downcast_ref::<norito::Error>()
            .is_some_and(|e| matches!(e, norito::Error::TotalAllocationExceeded { .. }))
    }));
    assert!(instructions(&service.config, &bytes, plan.deadline_unix_ms).is_ok());
    assert_eq!(transport.requests.load(Ordering::SeqCst), 0);
}

#[test]
fn expired_namespace_original_recovers_its_original_utc_without_dispatch() {
    let (service, transport) = service();
    let original_time = current_unix_ms().unwrap() - 200_000;
    let mut request = request(&service.config, original_time);
    let plan = Plan::new(&request, original_time).unwrap();
    let mut terms = BoundedTerms::new(&request.options).unwrap();
    terms.deadline_ms = request.deadline_unix_ms;
    let operation = NativeOperation::MusubiNamespaceBinding {
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
    let (recovered, inspected) = service
        .recover_musubi_namespace_binding_request(&path, &request.selection, &request.options)
        .unwrap();
    assert_eq!(recovered.deadline_unix_ms, request.deadline_unix_ms);
    assert_eq!(inspected.phase(), NativePreparationPhase::Signed);
    assert_eq!(
        service
            .verify_musubi_namespace_binding_journal(&path, &request)
            .unwrap()
            .encode_versioned(),
        signed.encode_versioned()
    );
    assert_eq!(transport.requests.load(Ordering::SeqCst), 0);
    assert_eq!(
        service
            .resume_musubi_namespace_binding(&path, &request)
            .unwrap()
            .status,
        OperationStatus::Expired
    );
    assert_eq!(
        service
            .submit_musubi_namespace_binding(&path, &request)
            .unwrap()
            .status,
        OperationStatus::Expired
    );
    assert!(
        service
            .prepare_musubi_namespace_binding(&request, &root.path().join("fresh"))
            .is_err()
    );
    assert!(!path.join("submission.json").exists());
    assert_eq!(std::fs::read(path.join("operation.json")).unwrap(), before);
    assert_eq!(transport.quotes.load(Ordering::SeqCst), 0);
    assert_eq!(transport.submissions.load(Ordering::SeqCst), 0);
}
