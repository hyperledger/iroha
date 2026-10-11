//! Custody planning preserves independent inputs, original signatures, fees and once-only dispatch.
//!
//! Fixture records are caller claims; these controls do not authenticate native execution,
//! provider permission, finality, hardware or operational custody.

use super::*;
use iroha::http::{HttpTransport, Response, TransportFuture, TransportRequest};
use iroha_crypto::{Algorithm, KeyPair, Signature};
use sorafs_manifest::signer::{
    custody::{
        SIGNER_CUSTODY_MAGIC_V1, SIGNER_CUSTODY_VERSION_V1, SignerCustodyAuthorityV1,
        SignerCustodyRecordV1, SignerCustodyStatementV1,
    },
    protocol::SignerKeyAlgorithmV1,
};
use std::{
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Instant,
};

#[derive(Debug, Default)]
struct Transport {
    requests: AtomicUsize,
    quotes: AtomicUsize,
    submissions: AtomicUsize,
}
impl HttpTransport for Transport {
    fn send_blocking(&self, request: TransportRequest) -> Result<Response<Vec<u8>>> {
        self.requests.fetch_add(1, Ordering::SeqCst);
        let (status, body) = match request.url.path() {
            "/v1/node/capabilities" => (
                200,
                norito::json::to_vec(&norito::json!({
                    "data_model_version": (iroha_data_model::DATA_MODEL_VERSION),
                    "signed_transaction_schema_hash_hex": (hex::encode(norito::schema::identity::frame_hash::<SignedTransaction>()))
                }))?,
            ),
            "/v1/fees/quote" => {
                self.quotes.fetch_add(1, Ordering::SeqCst);
                let request: iroha_torii_shared::FeeQuoteRequest =
                    norito::json::from_slice(&request.body)?;
                let payload = request.payload;
                (
                    200,
                    norito::json::to_vec(&FeeQuoteResponse {
                        intent: payload.fee_payment_intent().clone(),
                        observation: iroha_torii_shared::FeeQuoteObservation {
                            ledger_time_ms: current_unix_ms()?,
                            next_block_height: 1,
                            route_dataspace_id: iroha_model_base::topology::DataSpaceId::UNIVERSAL,
                        },
                        components: Vec::new(),
                        capacities: Vec::new(),
                        decision: iroha_torii_shared::FeeQuoteDecision::Accepted {
                            debit_source: iroha_data_model::nexus::FeeDebitSource::Account(
                                payload.authority().clone(),
                            ),
                            program_revision: None,
                        },
                    })?,
                )
            }
            "/v1/pipeline/transactions/status" => {
                let hash = request
                    .url
                    .query_pairs()
                    .find(|(key, _)| key == "hash")
                    .unwrap()
                    .1
                    .parse::<iroha_crypto::HashOf<SignedTransaction>>()?;
                let absence = iroha_torii_shared::ErrorEnvelope::new(
                    iroha_torii_shared::PIPELINE_TRANSACTION_STATUS_NOT_FOUND_CODE,
                    "Missing status.",
                )
                .with_details(iroha_torii_shared::ErrorDetails {
                    pipeline_transaction_status_not_found: Some(
                        iroha_torii_shared::PipelineTransactionStatusNotFoundV1::new(
                            &hash, "global",
                        ),
                    ),
                    ..iroha_torii_shared::ErrorDetails::default()
                });
                (404, norito::json::to_vec(&absence)?)
            }
            path if path == iroha_torii_shared::route_catalog::pipeline::TRANSACTION.path() => {
                self.submissions.fetch_add(1, Ordering::SeqCst);
                (503, b"unavailable".to_vec())
            }
            path => panic!("unexpected custody HTTP request {path}"),
        };
        Ok(Response::builder()
            .status(status)
            .header("Content-Type", "application/json")
            .body(body)?)
    }
    fn send(&self, request: TransportRequest) -> TransportFuture<'_> {
        Box::pin(async move { self.send_blocking(request) })
    }
}
fn service() -> (AccountService, Arc<Transport>) {
    let config = super::super::tests::fixture_config();
    let transport = Arc::new(Transport::default());
    let client = Client::with_http_transport(config.clone(), transport.clone()).unwrap();
    (
        AccountService {
            config,
            client,
            deadline: None,
            cancellation: None,
        },
        transport,
    )
}
fn key(seed: u8) -> KeyPair {
    KeyPair::try_from_seed(vec![seed; 32], Algorithm::Ed25519).unwrap()
}
fn configure(config: &Config, now: u64) -> StreamTokenCustodyConfigureRequest {
    let policy = SignerCustodyPolicyV1 {
        binding: SignerCustodyBindingV1 {
            chain_id: config.chain.to_string(),
            network_id: *config.network_id.as_bytes(),
            runtime_handle: "software://stream/primary".into(),
            key_handle: "software://stream/key".into(),
            service_id: "stream-service".into(),
            administrator_id: "stream-admin".into(),
            role: SignerRoleV1::StreamToken,
            purpose: SignerPurposeBindingV1::StreamToken {
                provider_id: [3; 32],
            },
            algorithm: SignerKeyAlgorithmV1::Ed25519,
            public_key: key(4).public_key().clone(),
            key_revision: 1,
            policy_revision: 1,
            policy_digest: [5; 32],
        },
        attester_authority: SignerCustodyAuthorityV1 {
            service_id: "custody-service".into(),
            administrator_id: "custody-admin".into(),
            key_revision: 1,
            policy_revision: 1,
            policy_digest: [6; 32],
        },
        attester_public_key: key(7).public_key().clone(),
        active_from_unix_ms: now - 1000,
        active_until_unix_ms: now + 120_000,
        max_validity_ms: 120_000,
        max_anchor_age_ms: 60_000,
    };
    StreamTokenCustodyConfigureRequest {
        selection: StreamTokenCustodySelection {
            provider_id: ProviderId::new([3; 32]),
            binding: policy.binding.clone(),
            expected_revision: 0,
            expected_digest: [0; 32],
            current: None,
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
fn enroll(config: &Config, now: u64) -> StreamTokenCustodyEnrollRequest {
    let request = configure(config, now);
    let state = configure_signer_custody_policy_v1(None, request.policy.clone()).unwrap();
    let record = StreamTokenCustodyControlRecordV1 {
        provider_id: request.selection.provider_id,
        revision: 1,
        predecessor_digest: [0; 32],
        request_digest: [8; 32],
        execution_height: 1,
        ordinal: 0,
        recorded_at_unix_ms: now - 10,
        authority: config.account.clone(),
        control_state: norito::encode_canonical(&state).unwrap(),
        active_enrollment: None,
    };
    let digest = record.canonical_digest().unwrap();
    let anchor = SignerCustodyAnchorV1 {
        height: 2,
        block_hash: [9; 32],
        state_digest: digest,
    };
    let statement = SignerCustodyStatementV1 {
        magic: SIGNER_CUSTODY_MAGIC_V1,
        version: SIGNER_CUSTODY_VERSION_V1,
        binding: request.policy.binding.clone(),
        authority: request.policy.attester_authority.clone(),
        anchor,
        sequence: 1,
        predecessor_digest: [0; 32],
        issued_at_unix_ms: now - 1,
        expires_at_unix_ms: now + 100_000,
        evidence_digest: [10; 32],
        revoked: false,
    };
    let attestation: [u8; 64] =
        Signature::new(key(7).private_key(), &statement.signing_payload().unwrap())
            .payload()
            .try_into()
            .unwrap();
    StreamTokenCustodyEnrollRequest {
        selection: StreamTokenCustodySelection {
            expected_revision: 1,
            expected_digest: digest,
            current: Some(record),
            ..request.selection
        },
        anchor,
        anchor_observed_at_unix_ms: now,
        issued_at_unix_ms: statement.issued_at_unix_ms,
        expires_at_unix_ms: statement.expires_at_unix_ms,
        enrollment: norito::encode_canonical(&SignerCustodyRecordV1 {
            statement,
            attestation,
        })
        .unwrap(),
        deadline_unix_ms: request.deadline_unix_ms,
        options: request.options,
    }
}

#[test]
fn configure_and_enroll_retain_one_canonical_instruction_and_exact_original_wire() {
    let (service, transport) = service();
    let now = current_unix_ms().unwrap();
    let configure = configure(&service.config, now);
    let enroll = enroll(&service.config, now);
    let root = tempfile::tempdir().unwrap();
    let configured = root.path().join("configure");
    let enrolled = root.path().join("enroll");
    service
        .prepare_stream_token_custody_configure(&configure, &configured)
        .unwrap();
    service
        .prepare_stream_token_custody_enroll(&enroll, &enrolled)
        .unwrap();
    let configured_transaction = service
        .verify_stream_token_custody_configure_journal(&configured, &configure)
        .unwrap();
    let enrolled_transaction = service
        .verify_stream_token_custody_enroll_journal(&enrolled, &enroll)
        .unwrap();
    for (path, returned) in [
        (&configured, configured_transaction),
        (&enrolled, enrolled_transaction),
    ] {
        let record: TransactionJournal = Journal::open(path).unwrap().read_operation().unwrap();
        let transaction = record.verify(&service.config).unwrap();
        assert_eq!(returned.encode_versioned(), transaction.encode_versioned());
        let Executable::Instructions(instructions) = transaction.instructions() else {
            panic!("native operation")
        };
        assert_eq!(instructions.len(), 1);
        assert!(
            instructions[0]
                .as_any()
                .is::<MutateSorafsStreamTokenCustody>()
        );
        assert!(record.deadline_ms <= configure.deadline_unix_ms);
        assert!(transaction.attachments().is_none() && transaction.multisig_signatures().is_none());
        assert!(service.submit(path, record.operation.kind()).is_err());
        assert!(service.resume(path, record.operation.kind()).is_err());
    }
    assert_eq!(transport.quotes.load(Ordering::SeqCst), 2);
    assert_eq!(transport.submissions.load(Ordering::SeqCst), 0);
    let original_signed_record = std::fs::read(configured.join("operation.json")).unwrap();
    let reused = service
        .prepare_stream_token_custody_configure(&configure, &configured)
        .unwrap();
    assert_eq!(reused.status, OperationStatus::Prepared);
    assert_eq!(
        std::fs::read(configured.join("operation.json")).unwrap(),
        original_signed_record,
        "preparation must retain the exact original signature and authorization"
    );
    assert_eq!(transport.quotes.load(Ordering::SeqCst), 2);
    assert_eq!(transport.submissions.load(Ordering::SeqCst), 0);
}

#[test]
fn independently_selected_cas_binding_interval_and_attester_cannot_be_substituted() {
    let (service, transport) = service();
    let now = current_unix_ms().unwrap();
    let request = enroll(&service.config, now);
    let mut variants = Vec::new();
    let mut changed = request.clone();
    changed.selection.expected_revision += 1;
    variants.push(changed);
    let mut changed = request.clone();
    changed.selection.expected_digest[0] ^= 1;
    variants.push(changed);
    let mut changed = request.clone();
    changed.issued_at_unix_ms += 1;
    variants.push(changed);
    let mut changed = request.clone();
    changed.anchor.block_hash[0] ^= 1;
    variants.push(changed);
    let mut changed = request.clone();
    changed.selection.binding.network_id[0] ^= 1;
    variants.push(changed);
    let mut changed = request.clone();
    changed.enrollment.push(0);
    variants.push(changed);
    let mut changed = request.clone();
    let mut signed: SignerCustodyRecordV1 =
        decode_bounded(&changed.enrollment, SIGNER_CUSTODY_MAX_BYTES_V1).unwrap();
    signed.attestation[0] ^= 1;
    changed.enrollment = norito::encode_canonical(&signed).unwrap();
    variants.push(changed);
    let mut changed = request.clone();
    changed.deadline_unix_ms = request.expires_at_unix_ms + 1;
    variants.push(changed);
    let mut changed = request.clone();
    changed.enrollment = vec![0; SIGNER_CUSTODY_MAX_BYTES_V1 + 1];
    variants.push(changed);
    let root = tempfile::tempdir().unwrap();
    for (index, changed) in variants.iter().enumerate() {
        let path = root.path().join(index.to_string());
        assert!(
            service
                .prepare_stream_token_custody_enroll(changed, &path)
                .is_err()
        );
        assert!(!path.exists());
    }
    assert_eq!(transport.quotes.load(Ordering::SeqCst), 0);
    assert_eq!(transport.submissions.load(Ordering::SeqCst), 0);
}

#[test]
fn recovery_keeps_original_request_and_dispatches_each_purpose_at_most_once() {
    let (service, transport) = service();
    let now = current_unix_ms().unwrap();
    let configure = configure(&service.config, now);
    let mut enroll = enroll(&service.config, now);
    let root = tempfile::tempdir().unwrap();
    let configured = root.path().join("configure");
    let enrolled = root.path().join("enroll");
    service
        .prepare_stream_token_custody_configure(&configure, &configured)
        .unwrap();
    service
        .prepare_stream_token_custody_enroll(&enroll, &enrolled)
        .unwrap();
    let before = std::fs::read(enrolled.join("operation.json")).unwrap();
    let mut changed = enroll.clone();
    changed.deadline_unix_ms += 1;
    assert!(
        service
            .submit_stream_token_custody_enroll(&enrolled, &changed)
            .is_err()
    );
    let mut changed = enroll.clone();
    changed
        .options
        .max_total_fees
        .insert(XOR_ASSET_DEFINITION.parse().unwrap(), Quantity::from(1u32));
    assert!(
        service
            .verify_stream_token_custody_enroll_journal(&enrolled, &changed)
            .is_err()
    );
    assert!(
        service
            .submit_stream_token_custody_enroll(&enrolled, &changed)
            .is_err()
    );
    let mut changed = configure.clone();
    changed.options.fee_payment =
        FeePaymentIntent::authority(Vec::new(), std::num::NonZeroU64::new(99));
    assert!(
        service
            .verify_stream_token_custody_configure_journal(&configured, &changed)
            .is_err()
    );
    assert!(
        service
            .submit_stream_token_custody_configure(&configured, &changed)
            .is_err()
    );
    assert_eq!(transport.submissions.load(Ordering::SeqCst), 0);
    for _ in 0..2 {
        assert_eq!(
            service
                .submit_stream_token_custody_configure(&configured, &configure)
                .unwrap()
                .status,
            OperationStatus::Pending
        );
        assert_eq!(
            service
                .submit_stream_token_custody_enroll(&enrolled, &enroll)
                .unwrap()
                .status,
            OperationStatus::Pending
        );
    }
    assert_eq!(
        service
            .resume_stream_token_custody_configure(&configured, &configure)
            .unwrap()
            .status,
        OperationStatus::Pending
    );
    assert_eq!(
        service
            .resume_stream_token_custody_enroll(&enrolled, &enroll)
            .unwrap()
            .status,
        OperationStatus::Pending
    );
    assert_eq!(transport.submissions.load(Ordering::SeqCst), 2);
    enroll.options.deadline = Instant::now() + Duration::from_secs(60);
    service
        .verify_stream_token_custody_enroll_journal(&enrolled, &enroll)
        .unwrap();
    assert_eq!(
        service
            .resume_stream_token_custody_enroll(&enrolled, &enroll)
            .unwrap()
            .status,
        OperationStatus::Pending
    );
    assert_eq!(
        std::fs::read(enrolled.join("operation.json")).unwrap(),
        before
    );
}

#[test]
fn bounded_fee_comparison_rejects_changed_assets_or_amounts_and_excessive_cardinality() {
    let (service, transport) = service();
    let mut request = configure(&service.config, current_unix_ms().unwrap());
    let asset: AssetDefinitionId = XOR_ASSET_DEFINITION.parse().unwrap();
    request
        .options
        .max_total_fees
        .insert(asset.clone(), Quantity::from(1u32));
    let terms = BoundedTerms::new(&request.options).unwrap();
    assert!(terms.matches_options(&request.options).unwrap());
    request
        .options
        .max_total_fees
        .insert(asset.clone(), Quantity::from(2u32));
    assert!(!terms.matches_options(&request.options).unwrap());
    request.options.max_total_fees.clear();
    assert!(!terms.matches_options(&request.options).unwrap());
    for value in 1..=17u8 {
        let mut bytes = [value; 16];
        bytes[6] = 0x40;
        bytes[8] = 0x80;
        request.options.max_total_fees.insert(
            AssetDefinitionId::from_uuid_bytes(bytes).unwrap(),
            Quantity::from(1u32),
        );
    }
    assert!(validate_options(&request.options).is_err());
    request.options.max_total_fees.clear();
    request.options.deadline = Instant::now() - Duration::from_secs(1);
    let root = tempfile::tempdir().unwrap();
    assert!(
        service
            .prepare_stream_token_custody_configure(&request, &root.path().join("expired"))
            .is_err()
    );
    assert_eq!(transport.quotes.load(Ordering::SeqCst), 0);
}

#[test]
fn configure_rejects_unbounded_utc_authorization_and_role_key_as_manager() {
    let (service, transport) = service();
    let root = tempfile::tempdir().unwrap();
    let mut request = configure(&service.config, current_unix_ms().unwrap());
    request.deadline_unix_ms = u64::MAX;
    assert!(
        service
            .prepare_stream_token_custody_configure(&request, &root.path().join("unbounded"))
            .is_err()
    );
    let mut request = configure(&service.config, current_unix_ms().unwrap());
    request.policy.binding.public_key = service.config.key_pair.public_key().clone();
    request.selection.binding = request.policy.binding.clone();
    assert!(
        service
            .prepare_stream_token_custody_configure(&request, &root.path().join("manager"))
            .is_err()
    );
    assert_eq!(transport.quotes.load(Ordering::SeqCst), 0);
    assert_eq!(transport.submissions.load(Ordering::SeqCst), 0);
}

#[test]
fn historical_plan_validation_does_not_renew_an_expired_utc_interval() {
    let (service, _) = service();
    let now = current_unix_ms().unwrap();
    let request = enroll(&service.config, now - 200_000);
    let expected = CustodyExpectation::Enroll(&request);
    let plan = expected.plan(now - 200_000).unwrap();
    let bytes = encode_bounded(&plan, MAX_PLAN_BYTES).unwrap();
    assert!(
        instructions(
            &service.config,
            &bytes,
            NativeOperationKind::StreamTokenCustodyEnroll,
            request.deadline_unix_ms
        )
        .is_ok()
    );
    assert!(
        instructions(
            &service.config,
            &bytes,
            NativeOperationKind::StreamTokenCustodyConfigure,
            request.deadline_unix_ms
        )
        .is_err()
    );
    assert!(
        instructions(
            &service.config,
            &bytes,
            NativeOperationKind::StreamTokenCustodyEnroll,
            now + 1
        )
        .is_err()
    );
    let root = tempfile::tempdir().unwrap();
    assert!(
        service
            .prepare_stream_token_custody_enroll(&request, &root.path().join("expired"))
            .is_err()
    );
}

#[test]
fn enrollment_rejects_revoked_roles_and_replaced_attester_even_with_consistent_cas() {
    let (service, transport) = service();
    let now = current_unix_ms().unwrap();
    let root = tempfile::tempdir().unwrap();
    for case in 0..3 {
        let mut request = enroll(&service.config, now);
        let native = request.selection.current.as_mut().unwrap();
        let mut state: SignerCustodyControlStateV1 =
            decode_bounded(&native.control_state, SIGNER_CUSTODY_CONTROL_MAX_BYTES_V1).unwrap();
        match case {
            0 => state.signer_revoked = true,
            1 => state.attester_revoked = true,
            _ => state.policy.attester_public_key = key(11).public_key().clone(),
        }
        native.control_state = norito::encode_canonical(&state).unwrap();
        request.selection.expected_digest = native.canonical_digest().unwrap();
        request.anchor.state_digest = request.selection.expected_digest;
        let mut signed: SignerCustodyRecordV1 =
            decode_bounded(&request.enrollment, SIGNER_CUSTODY_MAX_BYTES_V1).unwrap();
        signed.statement.anchor = request.anchor;
        signed.attestation = Signature::new(
            key(7).private_key(),
            &signed.statement.signing_payload().unwrap(),
        )
        .payload()
        .try_into()
        .unwrap();
        request.enrollment = norito::encode_canonical(&signed).unwrap();
        assert!(
            service
                .prepare_stream_token_custody_enroll(&request, &root.path().join(case.to_string()))
                .is_err()
        );
    }
    assert_eq!(transport.quotes.load(Ordering::SeqCst), 0);
    assert_eq!(transport.submissions.load(Ordering::SeqCst), 0);
}

fn test_key(seed: u8) -> KeyPair {
    KeyPair::try_from_seed(vec![seed; 32], Algorithm::Ed25519).unwrap()
}

fn fixture() -> (Config, SignerCustodyPolicyV1) {
    let config = super::super::tests::fixture_config();
    // Canonical public labels exercise the real grammar; deterministic keys and
    // caller claims below remain disposable test material, not qualified custody.
    let policy = SignerCustodyPolicyV1 {
        binding: SignerCustodyBindingV1 {
            chain_id: config.chain.to_string(),
            network_id: *config.network_id.as_bytes(),
            runtime_handle: "hsm://stream/primary".into(),
            key_handle: "pkcs11:stream/key-1".into(),
            service_id: "stream-service".into(),
            administrator_id: "stream-admin".into(),
            role: SignerRoleV1::StreamToken,
            purpose: SignerPurposeBindingV1::StreamToken {
                provider_id: [3; 32],
            },
            algorithm: SignerKeyAlgorithmV1::Ed25519,
            public_key: test_key(4).public_key().clone(),
            key_revision: 1,
            policy_revision: 1,
            policy_digest: [5; 32],
        },
        attester_authority: SignerCustodyAuthorityV1 {
            service_id: "custody-service".into(),
            administrator_id: "custody-admin".into(),
            key_revision: 1,
            policy_revision: 1,
            policy_digest: [6; 32],
        },
        attester_public_key: test_key(7).public_key().clone(),
        active_from_unix_ms: 100,
        active_until_unix_ms: 5_000,
        max_validity_ms: 2_000,
        max_anchor_age_ms: 1_000,
    };
    policy.validate().unwrap();
    (config, policy)
}

fn absent_selection(policy: &SignerCustodyPolicyV1) -> StreamTokenCustodySelection {
    StreamTokenCustodySelection {
        provider_id: ProviderId::new([3; 32]),
        binding: policy.binding.clone(),
        expected_revision: 0,
        expected_digest: [0; 32],
        current: None,
    }
}

fn configure_plan(policy: SignerCustodyPolicyV1) -> Plan {
    Plan {
        selection: absent_selection(&policy),
        action: Action::Configure(policy),
        validated_at_unix_ms: 1_000,
        deadline_unix_ms: 2_000,
    }
}

fn enrolled_request_plan(config: &Config, policy: SignerCustodyPolicyV1, revoked: bool) -> Plan {
    let mut state = configure_signer_custody_policy_v1(None, policy.clone()).unwrap();
    state.signer_revoked = revoked;
    let record = StreamTokenCustodyControlRecordV1 {
        provider_id: ProviderId::new([3; 32]),
        revision: 1,
        predecessor_digest: [0; 32],
        request_digest: [8; 32],
        execution_height: 10,
        ordinal: 0,
        recorded_at_unix_ms: 800,
        authority: config.account.clone(),
        control_state: encode_bounded(&state, SIGNER_CUSTODY_CONTROL_MAX_BYTES_V1).unwrap(),
        active_enrollment: None,
    };
    let digest = record.canonical_digest().unwrap();
    let anchor = SignerCustodyAnchorV1 {
        height: 10,
        block_hash: [9; 32],
        state_digest: digest,
    };
    let statement = SignerCustodyStatementV1 {
        magic: SIGNER_CUSTODY_MAGIC_V1,
        version: SIGNER_CUSTODY_VERSION_V1,
        binding: policy.binding.clone(),
        authority: policy.attester_authority.clone(),
        anchor,
        sequence: 1,
        predecessor_digest: [0; 32],
        issued_at_unix_ms: 900,
        expires_at_unix_ms: 2_000,
        evidence_digest: [10; 32],
        revoked: false,
    };
    let signature = Signature::try_new(
        test_key(7).private_key(),
        &statement.signing_payload().unwrap(),
    )
    .unwrap();
    let signed = SignerCustodyRecordV1 {
        statement,
        attestation: signature.payload().try_into().unwrap(),
    };
    Plan {
        selection: StreamTokenCustodySelection {
            provider_id: ProviderId::new([3; 32]),
            binding: policy.binding,
            expected_revision: 1,
            expected_digest: digest,
            current: Some(record),
        },
        action: Action::Enroll {
            anchor,
            anchor_observed_at_unix_ms: 950,
            issued_at_unix_ms: 900,
            expires_at_unix_ms: 2_000,
            enrollment: encode_bounded(&signed, SIGNER_CUSTODY_MAX_BYTES_V1).unwrap(),
        },
        validated_at_unix_ms: 1_000,
        deadline_unix_ms: 1_900,
    }
}

#[test]
fn configure_plan_retains_exact_instruction_canonical_bytes_purpose_and_deadline() {
    let (config, policy) = fixture();
    for change in [
        |policy: &mut SignerCustodyPolicyV1| {
            policy.binding.runtime_handle = "hsm://stream/test-only".into();
        },
        |policy: &mut SignerCustodyPolicyV1| {
            policy.binding.key_handle = "pkcs11:stream/test-only".into();
        },
        |policy: &mut SignerCustodyPolicyV1| {
            policy.binding.service_id = "test-stream-service".into();
        },
        |policy: &mut SignerCustodyPolicyV1| {
            policy.binding.administrator_id = "test-stream-admin".into();
        },
        |policy: &mut SignerCustodyPolicyV1| {
            policy.attester_authority.service_id = "test-custody-service".into();
        },
        |policy: &mut SignerCustodyPolicyV1| {
            policy.attester_authority.administrator_id = "test-custody-admin".into();
        },
    ] {
        let mut malformed = policy.clone();
        change(&mut malformed);
        assert!(malformed.validate().is_err());
    }
    let plan = configure_plan(policy.clone());
    let expected: InstructionBox = MutateSorafsStreamTokenCustody {
        provider_id: ProviderId::new([3; 32]),
        expected_revision: 0,
        expected_digest: [0; 32],
        action: SorafsStreamTokenCustodyActionV1::Configure(
            norito::encode_canonical(&policy).unwrap(),
        ),
    }
    .into();
    assert_eq!(plan.instruction(&config).unwrap(), expected);
    let bytes = encode_bounded(&plan, MAX_PLAN_BYTES).unwrap();
    let decoded: Plan = decode_bounded(&bytes, MAX_PLAN_BYTES).unwrap();
    assert_eq!(encode_bounded(&decoded, MAX_PLAN_BYTES).unwrap(), bytes);
    assert_eq!(
        instructions(
            &config,
            &bytes,
            NativeOperationKind::StreamTokenCustodyConfigure,
            1_999
        )
        .unwrap(),
        vec![expected]
    );
    for deadline in [0, 1_000, 2_001] {
        assert!(
            instructions(
                &config,
                &bytes,
                NativeOperationKind::StreamTokenCustodyConfigure,
                deadline
            )
            .is_err()
        );
    }
    assert!(
        instructions(
            &config,
            &bytes,
            NativeOperationKind::StreamTokenCustodyEnroll,
            1_999
        )
        .is_err()
    );
    assert!(decode_bounded::<Plan>(&bytes[..bytes.len() - 1], MAX_PLAN_BYTES).is_err());
    let mut appended = bytes.clone();
    appended.push(0);
    assert!(decode_bounded::<Plan>(&appended, MAX_PLAN_BYTES).is_err());
    assert!(decode_bounded::<Plan>(&bytes, bytes.len() - 1).is_err());
}

#[test]
fn target_rejects_foreign_provider_network_revision_and_coherent_predecessor_claims() {
    let (config, policy) = fixture();
    let plan = enrolled_request_plan(&config, policy.clone(), false);
    plan.selection.validate(&config).unwrap();
    let changes: &[fn(&mut StreamTokenCustodySelection)] = &[
        |s| s.provider_id = ProviderId::new([11; 32]),
        |s| s.binding.network_id = [12; 32],
        |s| s.expected_revision += 1,
        |s| s.expected_digest[0] ^= 1,
        |s| {
            let record = s.current.as_mut().unwrap();
            record.execution_height = 0;
            s.expected_digest = record.canonical_digest().unwrap();
        },
        |s| {
            let record = s.current.as_mut().unwrap();
            record.request_digest = [0; 32];
            s.expected_digest = record.canonical_digest().unwrap();
        },
        |s| {
            let record = s.current.as_mut().unwrap();
            record.predecessor_digest = [13; 32];
            s.expected_digest = record.canonical_digest().unwrap();
        },
    ];
    for change in changes {
        let mut changed = plan.selection.clone();
        change(&mut changed);
        assert!(changed.validate(&config).is_err());
    }
    let mut absent = absent_selection(&policy);
    absent.expected_digest = [1; 32];
    assert!(absent.validate(&config).is_err());
    let mut absent = absent_selection(&policy);
    absent.expected_revision = 1;
    assert!(absent.validate(&config).is_err());
    let mut oversized = plan.selection.clone();
    oversized
        .current
        .as_mut()
        .unwrap()
        .control_state
        .resize(SIGNER_CUSTODY_CONTROL_MAX_BYTES_V1 + 1, 0);
    assert!(oversized.admit().is_err());
}

#[test]
fn manager_must_remain_independent_of_both_selected_keys() {
    let (config, policy) = fixture();
    configure_plan(policy.clone()).instruction(&config).unwrap();
    for key in [test_key(4), test_key(7)] {
        let mut other = config.clone();
        other.key_pair = key;
        assert!(configure_plan(policy.clone()).instruction(&other).is_err());
    }
    let mut changed = configure_plan(policy);
    changed.selection.binding.key_revision += 1;
    assert!(changed.instruction(&config).is_err());
}

#[test]
fn enrollment_uses_real_signature_and_exact_original_anchor_interval_and_revocation() {
    let (config, policy) = fixture();
    let plan = enrolled_request_plan(&config, policy.clone(), false);
    let Action::Enroll { enrollment, .. } = &plan.action else {
        unreachable!()
    };
    let expected: InstructionBox = MutateSorafsStreamTokenCustody {
        provider_id: plan.selection.provider_id,
        expected_revision: 1,
        expected_digest: plan.selection.expected_digest,
        action: SorafsStreamTokenCustodyActionV1::Enroll(enrollment.clone()),
    }
    .into();
    assert_eq!(plan.instruction(&config).unwrap(), expected);
    for index in 0..5 {
        let mut changed = plan.clone();
        let Action::Enroll {
            anchor,
            anchor_observed_at_unix_ms,
            issued_at_unix_ms,
            expires_at_unix_ms,
            enrollment,
        } = &mut changed.action
        else {
            unreachable!()
        };
        match index {
            0 => anchor.block_hash[0] ^= 1,
            1 => *anchor_observed_at_unix_ms = 1_001,
            2 => *issued_at_unix_ms += 1,
            3 => *expires_at_unix_ms -= 1,
            _ => {
                let mut signed: SignerCustodyRecordV1 =
                    decode_bounded(enrollment, SIGNER_CUSTODY_MAX_BYTES_V1).unwrap();
                signed.attestation[0] ^= 1;
                *enrollment = encode_bounded(&signed, SIGNER_CUSTODY_MAX_BYTES_V1).unwrap();
            }
        }
        assert!(changed.instruction(&config).is_err());
    }
    let mut changed = plan.clone();
    changed.deadline_unix_ms = 2_001;
    assert!(changed.instruction(&config).is_err());
    assert!(
        enrolled_request_plan(&config, policy, true)
            .instruction(&config)
            .is_err(),
        "coherently signed new anchor cannot replace current revocation"
    );
}

#[test]
fn fee_and_enrollment_bounds_are_checked_before_request_cloning() {
    let (_, policy) = fixture();
    let options = BoundedTransactionOptions {
        fee_payment: FeePaymentIntent::authority(Vec::new(), None),
        max_total_fees: BTreeMap::new(),
        deadline: Instant::now() + Duration::from_secs(10),
    };
    validate_options(&options).unwrap();
    let mut request = StreamTokenCustodyConfigureRequest {
        selection: absent_selection(&policy),
        policy,
        deadline_unix_ms: 2_000,
        options,
    };
    let asset: AssetDefinitionId = XOR_ASSET_DEFINITION.parse().unwrap();
    request
        .options
        .max_total_fees
        .insert(asset, Quantity::zero());
    assert!(CustodyExpectation::Configure(&request).plan(1_000).is_err());
    request.options.max_total_fees.clear();
    CustodyExpectation::Configure(&request).plan(1_000).unwrap();
    let mut enroll = StreamTokenCustodyEnrollRequest {
        selection: request.selection,
        anchor: SignerCustodyAnchorV1 {
            height: 10,
            block_hash: [9; 32],
            state_digest: [10; 32],
        },
        anchor_observed_at_unix_ms: 950,
        issued_at_unix_ms: 900,
        expires_at_unix_ms: 2_000,
        enrollment: Vec::new(),
        deadline_unix_ms: 1_900,
        options: request.options,
    };
    assert!(CustodyExpectation::Enroll(&enroll).plan(1_000).is_err());
    enroll.enrollment.resize(SIGNER_CUSTODY_MAX_BYTES_V1 + 1, 0);
    assert!(CustodyExpectation::Enroll(&enroll).plan(1_000).is_err());
}

#[test]
fn retain_stream_token_custody_configure_request_is_a_real_unsigned_zero_http_boundary() {
    let (service, transport) = service();
    let request = configure(&service.config, current_unix_ms().unwrap());
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("request-only-boundary");
    let before = transport.requests.load(std::sync::atomic::Ordering::SeqCst);
    let first = service
        .retain_stream_token_custody_configure_request(&request, &path)
        .unwrap();
    assert_eq!(first.phase(), NativePreparationPhase::RequestOnly);
    let commitment = first.request_sha256().unwrap().to_owned();
    let original = std::fs::read(path.join("preparation.json")).unwrap();
    assert!(!path.join("payload.json").exists());
    assert!(!path.join("operation.json").exists());
    assert!(!path.join("submission.json").exists());
    let repeated = service
        .retain_stream_token_custody_configure_request(&request, &path)
        .unwrap();
    assert_eq!(repeated.request_sha256(), Some(commitment.as_str()));
    let mut changed = request.clone();
    changed.deadline_unix_ms += 1;
    assert!(
        service
            .retain_stream_token_custody_configure_request(&changed, &path)
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
        .prepare_stream_token_custody_configure(&request, &path)
        .unwrap();
    let before = transport.requests.load(std::sync::atomic::Ordering::SeqCst);
    let signed = service
        .retain_stream_token_custody_configure_request(&request, &path)
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
        .retain_stream_token_custody_configure_request(&request, &path)
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
fn retain_stream_token_custody_enroll_request_is_a_real_unsigned_zero_http_boundary() {
    let (service, transport) = service();
    let request = enroll(&service.config, current_unix_ms().unwrap());
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("request-only-boundary");
    let before = transport.requests.load(std::sync::atomic::Ordering::SeqCst);
    let first = service
        .retain_stream_token_custody_enroll_request(&request, &path)
        .unwrap();
    assert_eq!(first.phase(), NativePreparationPhase::RequestOnly);
    let commitment = first.request_sha256().unwrap().to_owned();
    let original = std::fs::read(path.join("preparation.json")).unwrap();
    assert!(!path.join("payload.json").exists());
    assert!(!path.join("operation.json").exists());
    assert!(!path.join("submission.json").exists());
    let repeated = service
        .retain_stream_token_custody_enroll_request(&request, &path)
        .unwrap();
    assert_eq!(repeated.request_sha256(), Some(commitment.as_str()));
    let mut changed = request.clone();
    changed.deadline_unix_ms += 1;
    assert!(
        service
            .retain_stream_token_custody_enroll_request(&changed, &path)
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
        .prepare_stream_token_custody_enroll(&request, &path)
        .unwrap();
    let before = transport.requests.load(std::sync::atomic::Ordering::SeqCst);
    let signed = service
        .retain_stream_token_custody_enroll_request(&request, &path)
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
        .retain_stream_token_custody_enroll_request(&request, &path)
        .unwrap();
    assert_eq!(partial.phase(), NativePreparationPhase::PayloadRetained);
    assert_eq!(partial.request_sha256(), Some(commitment.as_str()));
    assert!(!path.join("operation.json").exists());
    assert_eq!(
        transport.requests.load(std::sync::atomic::Ordering::SeqCst),
        before
    );
}

fn assert_frame_identity<T: norito::NoritoSchema>(name: &str, hash: &str) {
    assert_eq!(T::nominal_name(), name);
    assert_eq!(T::static_nominal_name(), Some(name));
    assert_eq!(T::frame_name(), name);
    assert_eq!(T::static_frame_name(), Some(name));
    assert_eq!(
        hex::encode(norito::schema::identity::frame_hash::<T>()),
        hash
    );
}

fn roundtrip_frame<T>(value: &T) -> T
where
    T: norito::core::NoritoSerialize + for<'de> norito::core::NoritoDeserialize<'de>,
{
    let bytes = encode_bounded(value, MAX_PLAN_BYTES).unwrap();
    let header = norito::core::Header::read(bytes.as_slice()).unwrap();
    assert_eq!(header.schema, norito::schema::identity::frame_hash::<T>());
    assert_eq!(bytes.len(), norito::canonical_frame_len(value).unwrap());
    let decoded = decode_bounded::<T>(&bytes, MAX_PLAN_BYTES).unwrap();
    assert_eq!(encode_bounded(&decoded, MAX_PLAN_BYTES).unwrap(), bytes);
    assert!(encode_bounded(value, bytes.len() - 1).is_err());
    assert!(decode_bounded::<T>(&bytes, bytes.len() - 1).is_err());
    let mut trailing = bytes;
    trailing.push(0);
    assert!(decode_bounded::<T>(&trailing, MAX_PLAN_BYTES).is_err());
    decoded
}

#[test]
fn custody_schema_identities_are_explicit_and_distinct() {
    assert_frame_identity::<StreamTokenCustodySelection>(
        "iroha_wallet::operations::StreamTokenCustodySelection",
        "adb2e9e4a6a3862fa2ca1be0afdd8945",
    );
    assert_frame_identity::<Action>(
        "iroha_wallet::operations::stream_token_custody::Action",
        "a64f78220e575339f580cd2c203d0de0",
    );
    assert_frame_identity::<Plan>(
        "iroha_wallet::operations::stream_token_custody::Plan",
        "33f75df80d445018fbb416cd20ddb755",
    );
}

#[test]
fn custody_original_selection_action_and_plan_frames_roundtrip() {
    let (config, policy) = fixture();
    for plan in [
        configure_plan(policy.clone()),
        enrolled_request_plan(&config, policy, false),
    ] {
        let selection = roundtrip_frame(&plan.selection);
        assert_eq!(selection.provider_id, plan.selection.provider_id);
        assert_eq!(selection.binding, plan.selection.binding);
        assert_eq!(
            selection.expected_revision,
            plan.selection.expected_revision
        );
        assert_eq!(selection.expected_digest, plan.selection.expected_digest);
        assert_eq!(selection.current, plan.selection.current);
        let action = roundtrip_frame(&plan.action);
        match (&action, &plan.action) {
            (Action::Configure(actual), Action::Configure(expected)) => {
                assert_eq!(actual, expected)
            }
            (
                Action::Enroll {
                    anchor: actual_anchor,
                    anchor_observed_at_unix_ms: actual_observed,
                    issued_at_unix_ms: actual_issued,
                    expires_at_unix_ms: actual_expires,
                    enrollment: actual_enrollment,
                },
                Action::Enroll {
                    anchor: expected_anchor,
                    anchor_observed_at_unix_ms: expected_observed,
                    issued_at_unix_ms: expected_issued,
                    expires_at_unix_ms: expected_expires,
                    enrollment: expected_enrollment,
                },
            ) => {
                assert_eq!(actual_anchor, expected_anchor);
                assert_eq!(actual_observed, expected_observed);
                assert_eq!(actual_issued, expected_issued);
                assert_eq!(actual_expires, expected_expires);
                assert_eq!(actual_enrollment, expected_enrollment);
            }
            _ => panic!("custody codec changed the action variant"),
        }
        let decoded = roundtrip_frame(&plan);
        assert_eq!(decoded.validated_at_unix_ms, plan.validated_at_unix_ms);
        assert_eq!(decoded.deadline_unix_ms, plan.deadline_unix_ms);
        assert_eq!(
            decoded.instruction(&config).unwrap(),
            plan.instruction(&config).unwrap()
        );
    }
}

#[test]
fn custody_decoders_reject_another_root_schema() {
    let (_, policy) = fixture();
    let plan = configure_plan(policy);
    let selection_bytes = encode_bounded(&plan.selection, MAX_PLAN_BYTES).unwrap();
    let action_bytes = encode_bounded(&plan.action, MAX_PLAN_BYTES).unwrap();
    let plan_bytes = encode_bounded(&plan, MAX_PLAN_BYTES).unwrap();
    assert!(matches!(
        norito::decode_canonical::<Plan>(&selection_bytes),
        Err(norito::Error::SchemaMismatch)
    ));
    assert!(matches!(
        norito::decode_canonical::<StreamTokenCustodySelection>(&action_bytes),
        Err(norito::Error::SchemaMismatch)
    ));
    assert!(matches!(
        norito::decode_canonical::<Action>(&plan_bytes),
        Err(norito::Error::SchemaMismatch)
    ));
    assert!(decode_bounded::<Plan>(&selection_bytes, MAX_PLAN_BYTES).is_err());
    assert!(decode_bounded::<StreamTokenCustodySelection>(&action_bytes, MAX_PLAN_BYTES).is_err());
    assert!(decode_bounded::<Action>(&plan_bytes, MAX_PLAN_BYTES).is_err());
}

#[test]
fn retained_parent_stream_token_custody_configure_inspection_keeps_exact_phases_lock_and_offline_request_checks()
 {
    let (service, transport) = service();
    let request = configure(&service.config, current_unix_ms().unwrap());
    let root = tempfile::tempdir().unwrap();
    let owner = iroha_fs::OwnerDirectory::open(root.path()).unwrap();
    let parent = owner.create_private_child("parent").unwrap();
    let name = std::ffi::OsStr::new("transaction");
    let path = parent.path().join(name);
    assert_eq!(
        service
            .inspect_stream_token_custody_configure_preparation_in_parent(&parent, name, &request)
            .unwrap()
            .phase(),
        NativePreparationPhase::Missing
    );
    assert!(!path.exists());
    assert!(
        service
            .inspect_stream_token_custody_configure_preparation_in_parent(
                &parent,
                std::ffi::OsStr::new("../transaction"),
                &request
            )
            .is_err()
    );
    assert_eq!(transport.requests.load(Ordering::SeqCst), 0);

    let first = service
        .retain_stream_token_custody_configure_request(&request, &path)
        .unwrap();
    let original = std::fs::read(path.join("preparation.json")).unwrap();
    let borrowed = service
        .inspect_stream_token_custody_configure_preparation_in_parent(&parent, name, &request)
        .unwrap();
    let absolute = service
        .inspect_stream_token_custody_configure_preparation(&path, &request)
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
            .inspect_stream_token_custody_configure_preparation_in_parent(&parent, name, &changed)
            .is_err()
    );
    assert!(
        service
            .inspect_stream_token_custody_configure_preparation(&path, &changed)
            .is_err()
    );
    let held_lock = Journal::open(&path).unwrap();
    assert!(
        service
            .inspect_stream_token_custody_configure_preparation_in_parent(&parent, name, &request)
            .is_err()
    );
    drop(held_lock);
    assert_eq!(
        service
            .inspect_stream_token_custody_configure_preparation_in_parent(&parent, name, &request)
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
        .prepare_stream_token_custody_configure(&request, &path)
        .unwrap();
    let calls = transport.requests.load(Ordering::SeqCst);
    let absolute = service
        .inspect_stream_token_custody_configure_preparation(&path, &request)
        .unwrap();
    let borrowed = service
        .inspect_stream_token_custody_configure_preparation_in_parent(&parent, name, &request)
        .unwrap();
    assert_eq!(borrowed.phase(), NativePreparationPhase::Signed);
    assert_eq!(borrowed.request_sha256(), absolute.request_sha256());
    assert_eq!(
        borrowed.signed_transaction().unwrap().encode_versioned(),
        absolute.signed_transaction().unwrap().encode_versioned()
    );
    std::fs::remove_file(path.join("operation.json")).unwrap();
    let absolute = service
        .inspect_stream_token_custody_configure_preparation(&path, &request)
        .unwrap();
    let borrowed = service
        .inspect_stream_token_custody_configure_preparation_in_parent(&parent, name, &request)
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

#[test]
fn retained_parent_stream_token_custody_enroll_inspection_keeps_exact_phases_lock_and_offline_request_checks()
 {
    let (service, transport) = service();
    let request = enroll(&service.config, current_unix_ms().unwrap());
    let root = tempfile::tempdir().unwrap();
    let owner = iroha_fs::OwnerDirectory::open(root.path()).unwrap();
    let parent = owner.create_private_child("parent").unwrap();
    let name = std::ffi::OsStr::new("transaction");
    let path = parent.path().join(name);
    assert_eq!(
        service
            .inspect_stream_token_custody_enroll_preparation_in_parent(&parent, name, &request)
            .unwrap()
            .phase(),
        NativePreparationPhase::Missing
    );
    assert!(!path.exists());
    assert!(
        service
            .inspect_stream_token_custody_enroll_preparation_in_parent(
                &parent,
                std::ffi::OsStr::new("../transaction"),
                &request
            )
            .is_err()
    );
    assert_eq!(transport.requests.load(Ordering::SeqCst), 0);

    let first = service
        .retain_stream_token_custody_enroll_request(&request, &path)
        .unwrap();
    let original = std::fs::read(path.join("preparation.json")).unwrap();
    let borrowed = service
        .inspect_stream_token_custody_enroll_preparation_in_parent(&parent, name, &request)
        .unwrap();
    let absolute = service
        .inspect_stream_token_custody_enroll_preparation(&path, &request)
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
            .inspect_stream_token_custody_enroll_preparation_in_parent(&parent, name, &changed)
            .is_err()
    );
    assert!(
        service
            .inspect_stream_token_custody_enroll_preparation(&path, &changed)
            .is_err()
    );
    let held_lock = Journal::open(&path).unwrap();
    assert!(
        service
            .inspect_stream_token_custody_enroll_preparation_in_parent(&parent, name, &request)
            .is_err()
    );
    drop(held_lock);
    assert_eq!(
        service
            .inspect_stream_token_custody_enroll_preparation_in_parent(&parent, name, &request)
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
        .prepare_stream_token_custody_enroll(&request, &path)
        .unwrap();
    let calls = transport.requests.load(Ordering::SeqCst);
    let absolute = service
        .inspect_stream_token_custody_enroll_preparation(&path, &request)
        .unwrap();
    let borrowed = service
        .inspect_stream_token_custody_enroll_preparation_in_parent(&parent, name, &request)
        .unwrap();
    assert_eq!(borrowed.phase(), NativePreparationPhase::Signed);
    assert_eq!(borrowed.request_sha256(), absolute.request_sha256());
    assert_eq!(
        borrowed.signed_transaction().unwrap().encode_versioned(),
        absolute.signed_transaction().unwrap().encode_versioned()
    );
    std::fs::remove_file(path.join("operation.json")).unwrap();
    let absolute = service
        .inspect_stream_token_custody_enroll_preparation(&path, &request)
        .unwrap();
    let borrowed = service
        .inspect_stream_token_custody_enroll_preparation_in_parent(&parent, name, &request)
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

#[cfg(unix)]
#[test]
fn retained_parent_custody_inspection_refuses_lost_and_same_bytes_replaced_parent_and_retries_original()
 {
    let (service, transport) = service();
    let request = configure(&service.config, current_unix_ms().unwrap());
    let root = tempfile::tempdir().unwrap();
    let ancestor = iroha_fs::OwnerDirectory::open(root.path()).unwrap();
    let parent = ancestor.create_private_child("parent").unwrap();
    let name = std::ffi::OsStr::new("transaction");
    let path = parent.path().join(name);
    let first = service
        .retain_stream_token_custody_configure_request(&request, &path)
        .unwrap();
    let original = parent.open_child(name).unwrap();
    let parent_id = parent.identity().unwrap();
    let journal_id = original.identity().unwrap();
    let request_id =
        iroha_fs::FileIdentity::of(&original.open_read("preparation.json").unwrap()).unwrap();
    let bytes = std::fs::read(path.join("preparation.json")).unwrap();
    let displaced = root.path().join("displaced-parent");
    std::fs::rename(parent.path(), &displaced).unwrap();
    for name in ["transaction", "absent"] {
        assert!(
            service
                .inspect_stream_token_custody_configure_preparation_in_parent(
                    &parent,
                    std::ffi::OsStr::new(name),
                    &request
                )
                .is_err()
        );
    }
    let replacement = ancestor.create_private_child("parent").unwrap();
    let copied = replacement.create_child("transaction").unwrap();
    for name in ["lock", "preparation.json"] {
        std::fs::copy(
            displaced.join("transaction").join(name),
            copied.path().join(name),
        )
        .unwrap();
    }
    assert_ne!(replacement.identity().unwrap(), parent_id);
    assert_ne!(copied.identity().unwrap(), journal_id);
    // Fresh path admission accepts the genuine copy; original retained custody refuses it.
    let fresh = service
        .inspect_stream_token_custody_configure_preparation(&path, &request)
        .unwrap();
    assert_eq!(fresh.phase(), NativePreparationPhase::RequestOnly);
    assert_eq!(fresh.request_sha256(), first.request_sha256());
    for name in ["transaction", "absent"] {
        assert!(
            service
                .inspect_stream_token_custody_configure_preparation_in_parent(
                    &parent,
                    std::ffi::OsStr::new(name),
                    &request
                )
                .is_err()
        );
    }
    drop(copied);
    drop(replacement);
    std::fs::remove_dir_all(parent.path()).unwrap();
    std::fs::rename(&displaced, parent.path()).unwrap();
    assert_eq!(parent.identity().unwrap(), parent_id);
    assert_eq!(original.identity().unwrap(), journal_id);
    assert_eq!(
        iroha_fs::FileIdentity::of(&original.open_read("preparation.json").unwrap()).unwrap(),
        request_id
    );
    let retry = service
        .inspect_stream_token_custody_configure_preparation_in_parent(&parent, name, &request)
        .unwrap();
    assert_eq!(retry.phase(), NativePreparationPhase::RequestOnly);
    assert_eq!(retry.request_sha256(), first.request_sha256());
    assert_eq!(std::fs::read(path.join("preparation.json")).unwrap(), bytes);
    assert!(!path.join("payload.json").exists());
    assert!(!path.join("submission.json").exists());
    assert_eq!(transport.requests.load(Ordering::SeqCst), 0);
}

#[cfg(windows)]
#[test]
fn retained_parent_custody_inspection_keeps_native_rename_refusal_and_original_retry() {
    let (service, transport) = service();
    let request = configure(&service.config, current_unix_ms().unwrap());
    let root = tempfile::tempdir().unwrap();
    let ancestor = iroha_fs::OwnerDirectory::open(root.path()).unwrap();
    let parent = ancestor.create_private_child("parent").unwrap();
    let name = std::ffi::OsStr::new("transaction");
    let path = parent.path().join(name);
    let first = service
        .retain_stream_token_custody_configure_request(&request, &path)
        .unwrap();
    let original = parent.open_child(name).unwrap();
    let parent_id = parent.identity().unwrap();
    let journal_id = original.identity().unwrap();
    let bytes = std::fs::read(path.join("preparation.json")).unwrap();
    assert!(std::fs::rename(parent.path(), root.path().join("displaced-parent")).is_err());
    assert_eq!(
        service
            .inspect_stream_token_custody_configure_preparation_in_parent(
                &parent,
                std::ffi::OsStr::new("absent"),
                &request
            )
            .unwrap()
            .phase(),
        NativePreparationPhase::Missing
    );
    assert!(!parent.path().join("absent").exists());
    let retry = service
        .inspect_stream_token_custody_configure_preparation_in_parent(&parent, name, &request)
        .unwrap();
    assert_eq!(retry.phase(), NativePreparationPhase::RequestOnly);
    assert_eq!(retry.request_sha256(), first.request_sha256());
    assert_eq!(parent.identity().unwrap(), parent_id);
    assert_eq!(original.identity().unwrap(), journal_id);
    assert_eq!(std::fs::read(path.join("preparation.json")).unwrap(), bytes);
    assert!(!path.join("payload.json").exists());
    assert!(!path.join("submission.json").exists());
    assert_eq!(transport.requests.load(Ordering::SeqCst), 0);
}
