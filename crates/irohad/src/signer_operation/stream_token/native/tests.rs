//! Production software runtime construction against real native custody and durable finality.
use super::*;
use iroha_config::parameters::actual;
use iroha_core::{
    query::stream_token_authority::test_fixture::StreamTokenRuntimeTestFixtureV1 as Fixture,
    queue::Queue,
};
use iroha_crypto::ExposedPrivateKey;
use sorafs_manifest::signer::stream_token_evidence::{
    SignerStreamTokenObservationExpectedV1, SignerStreamTokenObservationPhaseV1,
    verify_stream_token_signer_current_evidence_v1,
};
use std::fs;

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis()
        .try_into()
        .unwrap()
}
fn raw(seed: u8) -> [u8; 32] {
    Fixture::key(seed)
        .public_key()
        .to_bytes()
        .1
        .try_into()
        .unwrap()
}
fn write(path: &Path, bytes: &[u8]) {
    let directory = iroha_fs::PrivateDirectory::open(path.parent().unwrap()).unwrap();
    let mode = if path.exists() {
        iroha_fs::PublishMode::Replace
    } else {
        iroha_fs::PublishMode::CreateNew
    };
    directory
        .write_atomic(path.file_name().unwrap(), bytes, mode)
        .unwrap();
}
fn config(fixture: &Fixture) -> (tempfile::TempDir, actual::SorafsStorage) {
    let parent = std::env::current_dir().unwrap().join("target");
    fs::create_dir_all(&parent).unwrap();
    let dir = tempfile::tempdir_in(parent).unwrap();
    let private = iroha_fs::PrivateDirectory::open_or_create(dir.path().join("private")).unwrap();
    let root = private.path().to_path_buf();
    for (name, seed) in [("role", 4), ("operator", 2), ("observer", 3)] {
        let key = Zeroizing::new(
            ExposedPrivateKey(Fixture::key(seed).private_key().clone())
                .try_to_multihash_string()
                .unwrap(),
        );
        let mut bytes = Zeroizing::new(key.as_bytes().to_vec());
        bytes.push(b'\n');
        write(&root.join(name), &bytes);
    }
    write(&root.join("record"), &fixture.record);
    private.create_child("receipts").unwrap();
    let policy = &fixture.policy;
    let authority = |seed, service: &str, administrator: &str, digest| {
        actual::SorafsStreamTokenAuthorityConfig {
            service_id: service.into(),
            administrator_id: administrator.into(),
            public_key: raw(seed),
            key_revision: 1,
            policy_revision: 1,
            policy_digest: digest,
            active_from_unix_ms: policy.active_from_unix_ms,
            active_until_unix_ms: policy.active_until_unix_ms,
        }
    };
    let mut storage = actual::SorafsStorage {
        enabled: true,
        provider_id: Some(ProviderId::new(*fixture.provider.as_bytes())),
        ..actual::SorafsStorage::default()
    };
    storage.stream_tokens.enabled = true;
    storage.stream_tokens.signer = Some(actual::SorafsStreamTokenSignerConfig {
        clock_uncertainty_ms: 0,
        native: Some(actual::SorafsStreamTokenNativeConfig {
            signer_credential: root.join("role"),
            custody_record: root.join("record"),
            receipt_journal: root.join("receipts"),
            operator: AccountId::new(Fixture::key(2).public_key().clone()),
            operator_credential: root.join("operator"),
            observer_credential: root.join("observer"),
            fee_payment: iroha_data_model::transaction::FeePaymentIntent::authority(
                Vec::new(),
                None,
            ),
            timeout_ms: 10_000,
        }),
        runtime_handle: policy.binding.runtime_handle.clone(),
        key_handle: policy.binding.key_handle.clone(),
        service_id: policy.binding.service_id.clone(),
        administrator_id: policy.binding.administrator_id.clone(),
        public_key: raw(4),
        key_revision: 1,
        policy_revision: 1,
        policy_digest: policy.binding.policy_digest,
        attester: actual::SorafsStreamTokenAttesterConfig {
            authority: authority(7, "custody-service", "custody-admin", [6; 32]),
            max_validity_ms: policy.max_validity_ms,
            max_anchor_age_ms: policy.max_anchor_age_ms,
        },
        observer: actual::SorafsStreamTokenObserverConfig {
            runtime_handle: "software://sorafs/stream-observer/primary".into(),
            authority: authority(3, "observer-service", "observer-admin", [9; 32]),
            max_state_age_ms: 30_000,
        },
    });
    (dir, storage)
}
fn queue() -> Arc<Queue> {
    Arc::new(Queue::from_config(
        actual::Queue::default(),
        tokio::sync::broadcast::channel(32).0,
    ))
}
mod checked_reservation;
mod completed_observation;
mod phase_preparation;

#[test]
fn native_check_signing_and_submission_use_original_absolute_deadline() {
    let fixture = Fixture::new_at(now_ms());
    let queue = queue();
    let source = source(&fixture, queue.clone());
    let reviewed = reviewed(&source);
    let prepared = source
        .prepare_check(&reviewed, Phase::Current(reviewed.intent.previous_audit))
        .unwrap();
    let deadline = prepared.deadline();
    let before_sign = std::time::Instant::now();
    let signed = source
        .transactions
        .sign(prepared.instruction(), true, deadline)
        .unwrap();
    let ttl = signed.time_to_live().unwrap();
    assert!(!ttl.is_zero());
    assert!(ttl <= deadline.duration_since(before_sign));
    assert!(ttl < source.timeout);
    let pending = prepared.bind_signed_transaction(signed).unwrap();
    assert_eq!(pending.deadline(), deadline);
    let expired = std::time::Instant::now();
    assert!(matches!(
        source
            .transactions
            .submit_and_wait(pending.signed_transaction(), expired),
        Err(SignerOperationErrorV1::StateUnavailable)
    ));
    let iroha_data_model::transaction::Executable::Instructions(instructions) =
        pending.signed_transaction().instructions()
    else {
        panic!("native Check instruction")
    };
    let instruction = instructions[0]
        .as_any()
        .downcast_ref::<MutateSorafsStreamTokenAuthority>()
        .unwrap();
    assert!(matches!(
        source.transactions.sign(instruction, true, expired),
        Err(SignerOperationErrorV1::StateUnavailable)
    ));
    assert_eq!(queue.queued_len(), 0);
}

fn source(fixture: &Fixture, queue: Arc<Queue>) -> NativeStreamTokenSourceV1 {
    source_with_timeout(fixture, queue, Duration::from_secs(1))
}

fn source_with_timeout(
    fixture: &Fixture,
    queue: Arc<Queue>,
    timeout: Duration,
) -> NativeStreamTokenSourceV1 {
    NativeStreamTokenSourceV1 {
        state: fixture.state.clone(),
        binding: fixture.policy.binding.clone(),
        custody_record: fixture.record.clone(),
        custody_trust: fixture.policy.custody_trust(),
        transactions: NativeTransactionsV1::new(
            fixture.state.clone(),
            queue,
            AccountId::new(Fixture::key(2).public_key().clone()),
            Fixture::key(2),
            Fixture::key(3),
            iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
            timeout,
        )
        .unwrap(),
        timeout,
        uncertainty_ms: 0,
    }
}
fn reviewed(source: &NativeStreamTokenSourceV1) -> StreamTokenReviewedV1 {
    let current = source.capture([0; 32]).unwrap();
    let time = now_ms();
    let request = SignerStreamTokenRequestV1 {
        operation_id: [31; 32],
        binding_digest: stream_token_binding_digest_v1(&source.binding).unwrap(),
        original_custody: SignerOperationCustodyV1 {
            record_digest: current.control.active_head.unwrap().record_digest,
            control_state_digest: current.anchor.state_digest,
        },
        signing_payload_digest: [32; 32],
        signing_payload_size: 256,
        issued_at_unix_ms: time - 1000,
        expires_at_unix_ms: time + 60_000,
    };
    StreamTokenReviewedV1 {
        request,
        intent: SignerOperationIntentV1 {
            action: SignerOperationActionV1::Sign,
            operation_id: request.operation_id,
            request_digest: request.digest().unwrap(),
            previous_audit: current.head.audit,
        },
    }
}

#[test]
fn native_constructor_qualifies_current_software_custody_without_submitting_checks_at_startup() {
    let fixture = Fixture::new_at(now_ms());
    let (_dir, storage) = config(&fixture);
    let queue = queue();
    let runtime = runtime::build_native_stream_token_runtime_v1(
        &storage,
        fixture.state.clone(),
        queue.clone(),
    )
    .unwrap()
    .unwrap();
    assert_eq!(queue.queued_len(), 0);
    let pins = iroha_torii::sorafs::StreamTokenSignerPinsV1::from_config(
        &storage,
        &fixture.policy.binding.chain_id,
        fixture.policy.binding.network_id,
    )
    .unwrap()
    .unwrap();
    let mut expected = SignerStreamTokenObservationExpectedV1::current(
        pins.binding(),
        SignerStreamTokenObservationPhaseV1::Startup,
        [19; 32],
        runtime.anchor.anchor(),
        now_ms(),
    )
    .unwrap();
    let reply = runtime.observer.observe(expected.request()).unwrap();
    let (record, observation) = reply.current_evidence().unwrap();
    verify_stream_token_signer_current_evidence_v1(
        record,
        observation,
        pins.binding(),
        pins.custody_trust(),
        pins.observer_trust(),
        &mut expected,
        now_ms(),
    )
    .unwrap();
    assert_eq!(queue.queued_len(), 0);
    assert_eq!(runtime.signer.handle(), pins.binding().runtime_handle);
}

#[test]
fn native_constructor_rejects_wrong_operator_credential_and_substituted_record() {
    let fixture = Fixture::new_at(now_ms());
    let (_dir, mut storage) = config(&fixture);
    let native = storage
        .stream_tokens
        .signer
        .as_mut()
        .unwrap()
        .native
        .as_mut()
        .unwrap();
    let correct = native.operator_credential.clone();
    native.operator_credential = native.observer_credential.clone();
    assert!(
        runtime::build_native_stream_token_runtime_v1(&storage, fixture.state.clone(), queue())
            .is_err()
    );
    let native = storage
        .stream_tokens
        .signer
        .as_mut()
        .unwrap()
        .native
        .as_mut()
        .unwrap();
    native.operator_credential = correct;
    let mut record = fixture.record.clone();
    let index = record.len() - 1;
    record[index] ^= 1;
    write(&native.custody_record, &record);
    assert!(
        runtime::build_native_stream_token_runtime_v1(&storage, fixture.state.clone(), queue())
            .is_err()
    );
}

#[test]
fn native_configuration_does_not_activate_when_unselected() {
    let fixture = Fixture::new_at(now_ms());
    assert!(
        runtime::build_native_stream_token_runtime_v1(
            &actual::SorafsStorage::default(),
            fixture.state,
            queue()
        )
        .unwrap()
        .is_none()
    );
}

#[test]
fn emergency_fast_skips_native_stream_credentials_on_every_platform() {
    let source = include_str!("../../../main.rs");
    let assembly = source
        .split("let mut sorafs_stream_token_signer_client =")
        .nth(1)
        .unwrap()
        .split("let sorafs_stream_token_gateway_admission =")
        .next()
        .unwrap();
    let compact: String = assembly
        .chars()
        .filter(|value| !value.is_whitespace())
        .collect();
    assert!(compact.contains("if!emergency_fast&&config.torii.sorafs_storage.stream_tokens.signer.as_ref().is_some_and(|signer|signer.native.is_some()){"));
    assert!(!compact.contains("#[cfg(unix)]"));
    assert!(!compact.contains("#[cfg(not(unix))]"));
    assert_eq!(
        source
            .matches("::runtime::build_native_stream_token_runtime_v1(")
            .count(),
        1
    );
    assert_eq!(
        assembly
            .matches("::runtime::build_native_stream_token_runtime_v1(")
            .count(),
        1
    );
}

#[test]
fn native_constructor_rejects_epoch_substitution_and_utc_interval_outside_policy() {
    let fixture = Fixture::new_at(now_ms());
    let (_dir, mut storage) = config(&fixture);
    storage
        .stream_tokens
        .signer
        .as_mut()
        .unwrap()
        .policy_revision += 1;
    assert!(
        runtime::build_native_stream_token_runtime_v1(&storage, fixture.state.clone(), queue())
            .is_err()
    );
    storage
        .stream_tokens
        .signer
        .as_mut()
        .unwrap()
        .policy_revision -= 1;
    storage
        .stream_tokens
        .signer
        .as_mut()
        .unwrap()
        .clock_uncertainty_ms = 5000;
    assert!(
        runtime::build_native_stream_token_runtime_v1(&storage, fixture.state.clone(), queue())
            .is_err()
    );
}

#[test]
fn native_current_observer_rejects_floor_phase_and_live_revocation() {
    use iroha_data_model::{
        isi::sorafs::MutateSorafsStreamTokenCustody,
        sorafs::stream_token_custody::{
            SorafsStreamTokenCustodyActionV1, SorafsStreamTokenCustodyRevocationV1,
        },
    };
    let mut fixture = Fixture::new_at(now_ms());
    let (_dir, storage) = config(&fixture);
    let queue = queue();
    let runtime = runtime::build_native_stream_token_runtime_v1(
        &storage,
        fixture.state.clone(),
        queue.clone(),
    )
    .unwrap()
    .unwrap();
    let expected = SignerStreamTokenObservationExpectedV1::current(
        &fixture.policy.binding,
        SignerStreamTokenObservationPhaseV1::BeforeAdmission,
        [19; 32],
        runtime.anchor.anchor(),
        now_ms(),
    )
    .unwrap();
    let mut wrong_floor = expected.request().clone();
    wrong_floor.minimum_anchor.block_hash[0] ^= 1;
    assert!(runtime.observer.observe(&wrong_floor).is_err());
    let mut wrong_phase = expected.request().clone();
    wrong_phase.phase = SignerStreamTokenObservationPhaseV1::BeforeRelease;
    assert!(runtime.observer.observe(&wrong_phase).is_err());
    let current =
        capture_stream_token_authority_v1(&fixture.state.view(), &fixture.policy.binding, [0; 32])
            .unwrap();
    assert!(
        fixture.commit_instruction(
            MutateSorafsStreamTokenCustody {
                provider_id: fixture.provider,
                expected_revision: current.control_revision,
                expected_digest: current.anchor.state_digest,
                action: SorafsStreamTokenCustodyActionV1::Revoke(
                    SorafsStreamTokenCustodyRevocationV1 {
                        signer: true,
                        attester: false
                    }
                ),
            }
            .into(),
            1,
            now_ms()
        )
    );
    assert!(runtime.observer.observe(expected.request()).is_err());
    assert!(
        runtime::build_native_stream_token_runtime_v1(
            &storage,
            fixture.state.clone(),
            queue.clone()
        )
        .is_err()
    );
    assert_eq!(queue.queued_len(), 0);
}

#[test]
fn native_observer_requires_its_authority_at_both_utc_endpoints() {
    for expires in [false, true] {
        let fixture = Fixture::new_at(now_ms() - 60_000);
        let (_directory, mut storage) = config(&fixture);
        let signer = storage.stream_tokens.signer.as_mut().unwrap();
        signer.clock_uncertainty_ms = 5_000;
        if expires {
            signer.observer.authority.active_until_unix_ms = now_ms() + 4_000;
        } else {
            signer.observer.authority.active_from_unix_ms = now_ms() - 1;
        }
        let runtime =
            runtime::build_native_stream_token_runtime_v1(&storage, fixture.state.clone(), queue())
                .unwrap()
                .unwrap();
        let expected = SignerStreamTokenObservationExpectedV1::current(
            &fixture.policy.binding,
            SignerStreamTokenObservationPhaseV1::BeforeAdmission,
            [20; 32],
            runtime.anchor.anchor(),
            now_ms(),
        )
        .unwrap();
        assert!(runtime.observer.observe(expected.request()).is_err());
    }
}

#[test]
fn native_source_requires_current_operator_and_observer_permissions() {
    for seed in [2, 3] {
        let mut fixture = Fixture::new_at(now_ms());
        let queue = queue();
        let source = source(&fixture, queue.clone());
        let reviewed = reviewed(&source);
        let prepared = source
            .prepare_check(&reviewed, Phase::Current(reviewed.intent.previous_audit))
            .unwrap();
        let signed = source
            .transactions
            .sign(prepared.instruction(), true, prepared.deadline())
            .unwrap();
        let pending = prepared.bind_signed_transaction(signed).unwrap();
        assert!(fixture.revoke_runtime_permission(seed == 3, now_ms()));
        assert!(!fixture.commit_signed(pending.signed_transaction().clone(), now_ms()));
        assert!(pending.verify_finalized(|| source.time().map_err(|_| iroha_core::query::stream_token_authority::observation::StreamTokenObservationErrorV1::Clock)).is_err());
        assert_eq!(queue.queued_len(), 0);
    }
}

#[test]
fn native_current_authority_disappears_when_its_durable_qc_is_removed() {
    let fixture = Fixture::new_at(now_ms());
    let (_dir, storage) = config(&fixture);
    let runtime =
        runtime::build_native_stream_token_runtime_v1(&storage, fixture.state.clone(), queue())
            .unwrap()
            .unwrap();
    let expected = SignerStreamTokenObservationExpectedV1::current(
        &fixture.policy.binding,
        SignerStreamTokenObservationPhaseV1::BeforeAdmission,
        [19; 32],
        runtime.anchor.anchor(),
        now_ms(),
    )
    .unwrap();
    fixture
        .remove_finality_for_test(runtime.anchor.anchor().height)
        .unwrap();
    assert!(runtime.observer.observe(expected.request()).is_err());
    assert!(
        runtime::build_native_stream_token_runtime_v1(&storage, fixture.state.clone(), queue())
            .is_err()
    );
}

fn commit_native_with_timing(
    fixture: &mut Fixture,
    signed: iroha_data_model::transaction::SignedTransaction,
    scenario: &str,
    sequence: usize,
    started: std::time::Instant,
) -> bool {
    use iroha_data_model::{
        ValidationFail,
        transaction::{Executable, error::TransactionRejectionReason},
    };

    let Executable::Instructions(instructions) = signed.instructions() else {
        panic!("native source must submit instructions");
    };
    assert_eq!(instructions.len(), 1);
    let native = instructions[0]
        .as_any()
        .downcast_ref::<MutateSorafsStreamTokenAuthority>()
        .expect("native source must submit the role-11 instruction");
    let (phase, token_expiry, reservation_expiry) = match &native.request.action {
        Action::Reserve(reviewed) => ("Reserve", Some(reviewed.request.expires_at_unix_ms), None),
        Action::Complete(request) => (
            "Complete",
            Some(request.reviewed.request.expires_at_unix_ms),
            Some(request.reservation.expires_at_unix_ms),
        ),
        Action::Expire(request) => ("Expire", None, Some(request.reservation.expires_at_unix_ms)),
        Action::Check(check) => {
            let phase = match check.phase {
                Phase::Current(_) => "Check/Current",
                Phase::BeforeProvider(_) => "Check/BeforeProvider",
                Phase::AfterProvider(_) => "Check/AfterProvider",
                Phase::BeforeCommit(_) => "Check/BeforeCommit",
                Phase::AfterCommit(_) => "Check/AfterCommit",
                Phase::BeforeRelease(_) => "Check/BeforeRelease",
            };
            let reservation_expiry = match &check.phase {
                Phase::Current(_) => None,
                Phase::BeforeProvider(row)
                | Phase::AfterProvider(row)
                | Phase::BeforeCommit(row)
                | Phase::AfterCommit(row)
                | Phase::BeforeRelease(row) => Some(row.operation.reservation.expires_at_unix_ms),
            };
            (
                phase,
                Some(check.reviewed.request.expires_at_unix_ms),
                reservation_expiry,
            )
        }
    };
    let transaction_expiry = signed.creation_time() + signed.time_to_live().unwrap();
    let begin_elapsed_ms = started.elapsed().as_millis();
    let requested_block_time_ms = now_ms();
    let executed = fixture.commit_signed(signed, requested_block_time_ms);
    let finish_elapsed_ms = started.elapsed().as_millis();
    let finished_at_ms = now_ms();
    // Successful signing has 22 instructions; recovery and the issuer add fresh Checks.
    // Bound diagnostic output while always including the first failed execution.
    if sequence <= 32 || !executed {
        let block = fixture.state.view().latest_block().unwrap().unwrap();
        let failure = block.network_output_at(0).and_then(|(_, output)| {
            output.result.0.as_ref().err().map(|error| {
                // Print only the native rejection reason, never the signed instruction,
                // receipt, signature, credentials or an unrelated internal-error payload.
                let reason = match error {
                    TransactionRejectionReason::Validation(ValidationFail::InstructionFailed(
                        reason,
                    )) => reason.to_string(),
                    TransactionRejectionReason::InstructionExecution(failure) => {
                        failure.reason.clone()
                    }
                    _ => "non-native rejection (details omitted)".into(),
                };
                reason.chars().take(256).collect::<String>()
            })
        });
        eprintln!(
            "native_phase scenario={scenario} sequence={sequence} phase={phase} \
             begin_elapsed_ms={begin_elapsed_ms} finish_elapsed_ms={finish_elapsed_ms} \
             requested_block_time_ms={requested_block_time_ms} \
             block_time_ms={} finished_at_ms={finished_at_ms} \
             transaction_expiry_ms={} token_expiry_ms={token_expiry:?} \
             reservation_expiry_ms={reservation_expiry:?} executed={executed} failure={failure:?}",
            block.header().creation_time().as_millis(),
            transaction_expiry.as_millis(),
        );
    }
    executed
}

#[test]
fn native_software_issue_and_recovery_execute_exact_signed_queue_operations() {
    let mut fixture = Fixture::new_at(now_ms() - 5_000);
    let (_directory, storage) = config(&fixture);
    let state = fixture.state.clone();
    let queue = queue();
    let runtime =
        runtime::build_native_stream_token_runtime_v1(&storage, state.clone(), queue.clone())
            .unwrap()
            .unwrap();
    let binding = fixture.policy.binding.clone();
    let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let stopped = stop.clone();
    let started = std::time::Instant::now();
    let worker = std::thread::spawn(move || {
        let mut applied = std::collections::HashSet::new();
        while !stopped.load(std::sync::atomic::Ordering::Acquire) {
            let transactions = {
                let view = state.view();
                queue.all_transactions(&view).collect::<Vec<_>>()
            };
            for tx in transactions {
                let signed = tx.external().unwrap().clone();
                if applied.insert(signed.hash()) {
                    assert!(
                        commit_native_with_timing(
                            &mut fixture,
                            signed,
                            "native_issue_and_recovery",
                            applied.len(),
                            started,
                        ),
                        "actual native execution must succeed"
                    );
                }
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        applied.len()
    });
    let now = now_ms() / 1000;
    let body = StreamTokenBodyV1 {
        token_id: "a1".repeat(16),
        manifest_cid: sorafs_manifest::canonical_manifest_root_cid([3; 32]),
        provider_id: match binding.purpose {
            sorafs_manifest::signer::protocol::SignerPurposeBindingV1::StreamToken {
                provider_id,
            } => provider_id,
            _ => unreachable!(),
        },
        profile_handle: "sorafs.sf1@1.0.0".into(),
        max_streams: 2,
        ttl_epoch: now + 60,
        rate_limit_bytes: 1024,
        issued_at: now - 1,
        requests_per_minute: 60,
        token_pk_version: 1,
    };
    let expected = SignerStreamTokenExpectedV1::new(&body, &binding).unwrap();
    let issued = runtime.signer.sign(&expected, &body);
    let recovered = issued
        .as_ref()
        .ok()
        .map(|_| runtime.signer.recover(&expected, &body));
    stop.store(true, std::sync::atomic::Ordering::Release);
    let count = worker.join().unwrap();
    let issued =
        issued.expect("native producer must complete actual finalized Reserve/Check/Complete");
    let recovered = recovered.unwrap().unwrap();
    assert_eq!(issued.bytes(), recovered.bytes());
    assert!(
        count >= 6,
        "issuance/recovery must execute multiple independent native phases"
    );
}

#[test]
fn native_production_issuer_releases_verifiable_cid_token_and_rechecks_revocation() {
    use iroha_data_model::{
        isi::sorafs::MutateSorafsStreamTokenCustody,
        sorafs::stream_token_custody::{
            SorafsStreamTokenCustodyActionV1, SorafsStreamTokenCustodyRevocationV1,
        },
        transaction::Executable,
    };
    use iroha_torii::sorafs::{
        StreamTokenIssuer, decode_token_base64, encode_token_base64,
        native_issuer_test_fixture::{before_native_token_admission_v1, issue_native_token_v1},
    };

    // This is the production factory, issuer and private producer over actual signed queue
    // operations and durable 3-of-4 validator finality. It does not qualify the separate HTTP
    // operator authentication or deployment-owned gateway quota/sequencer/reputation services.
    let mut fixture = Fixture::new_at(now_ms() - 5_000);
    let (_directory, mut storage) = config(&fixture);
    storage.stream_tokens.default_ttl_secs = 60;
    let state = fixture.state.clone();
    let queue = queue();
    let runtime =
        runtime::build_native_stream_token_runtime_v1(&storage, state.clone(), queue.clone())
            .unwrap()
            .unwrap();
    let issuer = StreamTokenIssuer::from_config(
        &storage,
        &fixture.policy.binding.chain_id,
        fixture.policy.binding.network_id,
        Some(runtime.signer),
        Some(runtime.observer),
        Some(runtime.anchor),
        state.clone(),
    )
    .unwrap()
    .unwrap();
    assert_eq!(queue.queued_len(), 0, "startup cannot wait on consensus");
    let provider = *fixture.provider.as_bytes();
    let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let stopped = stop.clone();
    let started = std::time::Instant::now();
    let worker = std::thread::spawn(move || {
        let mut applied = std::collections::HashSet::new();
        let mut actions = Vec::new();
        while !stopped.load(std::sync::atomic::Ordering::Acquire) {
            let transactions = {
                let view = state.view();
                queue.all_transactions(&view).collect::<Vec<_>>()
            };
            for tx in transactions {
                let signed = tx.external().unwrap().clone();
                if applied.insert(signed.hash()) {
                    let Executable::Instructions(instructions) = signed.instructions() else {
                        panic!("native issuer submitted a non-instruction transaction");
                    };
                    for instruction in instructions {
                        let native = instruction
                            .as_any()
                            .downcast_ref::<MutateSorafsStreamTokenAuthority>()
                            .expect("issuer must use the closed native role-11 instruction");
                        assert_eq!(native.request.provider_id.as_bytes(), &provider);
                        actions.push(native.request.action.clone());
                    }
                    assert!(commit_native_with_timing(
                        &mut fixture,
                        signed,
                        "native_production_issuer",
                        applied.len(),
                        started,
                    ));
                }
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        (fixture, actions)
    });
    let cid = sorafs_manifest::canonical_manifest_root_cid([0x3a; 32]);
    let issuance_result = issue_native_token_v1(
        &issuer,
        Fixture::key(2).public_key(),
        cid.clone(),
        provider,
        "sorafs.sf1@1.0.0".into(),
    );
    let admitted = issuance_result
        .as_ref()
        .ok()
        .map(|token| before_native_token_admission_v1(&issuer, token));
    stop.store(true, std::sync::atomic::Ordering::Release);
    let (mut fixture, actions) = worker.join().unwrap();
    let token = issuance_result.expect("production issuer must consume native completed proofs");
    admitted
        .unwrap()
        .expect("issued token must pass fresh current-custody admission");
    let transported = decode_token_base64(&encode_token_base64(&token).unwrap()).unwrap();
    assert_eq!(transported, token);
    transported.verify(issuer.verifying_key()).unwrap();
    assert_eq!(issuer.verifying_key_bytes(), raw(4));
    assert_eq!(token.body.manifest_cid, cid);
    assert_eq!(token.body.provider_id, provider);
    assert_eq!(token.body.profile_handle, "sorafs.sf1@1.0.0");
    assert_eq!(token.body.token_pk_version, issuer.key_version());
    assert_eq!(
        token.body.max_streams,
        storage.stream_tokens.default_max_streams
    );
    assert_eq!(
        token.body.rate_limit_bytes,
        storage.stream_tokens.default_rate_limit_bytes
    );
    assert_eq!(
        token.body.requests_per_minute,
        storage.stream_tokens.default_requests_per_minute
    );
    assert_eq!(token.body.ttl_epoch - token.body.issued_at, 60);
    assert_eq!(
        actions
            .iter()
            .filter(|action| matches!(action, Action::Reserve(_)))
            .count(),
        1
    );
    assert_eq!(
        actions
            .iter()
            .filter(|action| matches!(action, Action::Complete(_)))
            .count(),
        1
    );
    assert!(
        !actions
            .iter()
            .any(|action| matches!(action, Action::Expire(_)))
    );
    for expected in [0, 1, 4, 5] {
        assert!(
            actions
                .iter()
                .any(|action| matches!(action, Action::Check(check) if
            matches!((&check.phase, expected),
                (Phase::Current(_), 0) | (Phase::BeforeProvider(_), 1) |
                (Phase::AfterCommit(_), 4) | (Phase::BeforeRelease(_), 5)))),
            "missing native phase {expected}"
        );
    }
    let current =
        capture_stream_token_authority_v1(&fixture.state.view(), &fixture.policy.binding, [0; 32])
            .unwrap();
    assert!(
        fixture.commit_instruction(
            MutateSorafsStreamTokenCustody {
                provider_id: fixture.provider,
                expected_revision: current.control_revision,
                expected_digest: current.anchor.state_digest,
                action: SorafsStreamTokenCustodyActionV1::Revoke(
                    SorafsStreamTokenCustodyRevocationV1 {
                        signer: true,
                        attester: false
                    },
                ),
            }
            .into(),
            1,
            now_ms(),
        )
    );
    // The signature remains mathematically valid, while the actual serving authority is revoked.
    token.verify(issuer.verifying_key()).unwrap();
    assert!(before_native_token_admission_v1(&issuer, &token).is_err());
    assert!(
        issue_native_token_v1(
            &issuer,
            Fixture::key(2).public_key(),
            cid,
            provider,
            "sorafs.sf1@1.0.0".into(),
        )
        .is_err()
    );
}
