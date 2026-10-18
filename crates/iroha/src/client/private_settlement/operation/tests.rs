//! SDK custody and finality controls with genuine QCs over synthetic outputs.
//! These fixtures do not claim proof generation, World execution or live-network qualification.

use super::super::tests as existing;
use super::*;
use crate::{
    client::evidence_http_tests::{base_url, client_with_base_url},
    workflow::{FileWorkflowStorage, RoundInputV1},
};
use iroha_data_model::{
    block::{
        BlockSignatures,
        builder::BlockBuilder,
        execution_output::{ExecutionOutputV1, NetworkExecutionOutputV1},
        output_budget::ExecutionOutputLimits,
    },
    nexus::{
        AxtPolicySnapshot, PrivateSettlementAuditPolicyV1, private_settlement_proof_digest_v1,
    },
    sumeragi_finality::{VerifiedSumeragiBlock, test_fixtures::NativeFinalityFixture},
    transaction::{
        TransactionBuilder, TransactionResult,
        error::{TransactionLimitError, TransactionRejectionReason},
    },
};
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::atomic::{AtomicUsize, Ordering},
    time::Duration,
};

fn prepared(
    client: &Client,
) -> (
    PrivateSettlementRequest,
    Vec<PrivateSettlementSidecarAvailabilityV1>,
) {
    let (template, _) = existing::availability_material_fixture_v1(client);
    let mut manifest = template.manifest.clone();
    manifest.authority_context_height = 1;
    let mut materials = (0..2)
        .map(|index| {
            let ordinal = u8::try_from(index).expect("two-leg fixture index fits u8");
            let mut material = template.clone();
            let route = manifest.legs[index].route;
            let (authority, _) = existing::finalization_authority_v1(route, ordinal);
            let mut policy = template.audit_policy.body.clone();
            policy.dataspace_id = route.dataspace_id;
            policy.activation_height = 1;
            material.audit_policy = PrivateSettlementAuditPolicyV1::new(policy).unwrap();
            manifest.legs[index].audit_policy_digest = material.audit_policy.policy_digest;
            material.committee_authority = authority;
            material
        })
        .collect::<Vec<_>>();
    manifest.bundle_id = manifest.computed_bundle_id().unwrap();
    for (index, material) in materials.iter_mut().enumerate() {
        let ordinal = u8::try_from(index).expect("two-leg fixture index fits u8");
        let leg = &manifest.legs[index];
        let mut delta = existing::finalization_delta_v1(&manifest, index);
        let aad = &mut material.audit_capsule.aad;
        aad.bundle_id = manifest.bundle_id;
        aad.leg_ordinal = ordinal;
        aad.route = leg.route;
        aad.authority_context_height = manifest.authority_context_height;
        aad.authority_digest = material.committee_authority.digest().unwrap();
        aad.audit_policy_digest = material.audit_policy.policy_digest;
        let statement = &mut material.statement;
        statement.bundle_id = manifest.bundle_id;
        statement.leg_ordinal = ordinal;
        statement.route = leg.route;
        statement.authority_context_height = manifest.authority_context_height;
        statement.pool_id = leg.pool_id;
        statement.asset_binding_commitment = leg.asset_binding_commitment;
        statement.old_root = delta.old_root;
        statement.new_root = delta.new_root;
        statement.nullifiers = delta.nullifiers.clone();
        statement.output_commitments = delta.output_commitments.clone();
        statement.encrypted_outputs = delta.encrypted_outputs.clone();
        statement.audit_policy_digest = material.audit_policy.policy_digest;
        statement.audit_capsule_digest = material.audit_capsule.digest().unwrap();
        material.proof = format!("restricted-proof-canary-{index}").into_bytes();
        delta.statement_digest = statement.digest().unwrap();
        delta.proof_digest = private_settlement_proof_digest_v1(&material.proof);
        delta.capsule_digest = statement.audit_capsule_digest;
        material.delta = delta;
        material.availability_body.bundle_id = manifest.bundle_id;
        material.availability_body.leg_ordinal = ordinal;
        material.availability_body.route = leg.route;
        material.availability_body.authority_context_height = manifest.authority_context_height;
        material.availability_body.authority_digest =
            material.committee_authority.digest().unwrap();
        material.manifest = manifest.clone();
        manifest.legs[index].delta_digest = material.delta.digest().unwrap();
        manifest.legs[index].payload_digest = material.payload_digest().unwrap();
        material.availability_body.payload_digest = manifest.legs[index].payload_digest;
        material.availability_body.payload_bytes = material
            .sidecar_material_bytes_len()
            .unwrap()
            .try_into()
            .unwrap();
    }
    for material in &mut materials {
        material.manifest = manifest.clone();
        material.validate().unwrap();
    }
    let certificates = materials
        .iter()
        .map(|material| availability(material, &[0, 1, 2]))
        .collect();
    let endpoints = vec![existing::availability_endpoints_fixture_v1(); 2];
    (
        PrivateSettlementRequest::new(
            materials,
            endpoints,
            PRIVATE_SETTLEMENT_MAX_RECEIPT_BYTES_V1 as u64,
        )
        .unwrap(),
        certificates,
    )
}
fn availability(
    material: &PrivateSettlementProvisionalLegMaterialV1,
    indices: &[usize],
) -> PrivateSettlementSidecarAvailabilityV1 {
    let (_, keys) = existing::finalization_authority_v1(
        material.statement.route,
        material.statement.leg_ordinal,
    );
    let preimage = material.availability_body.signature_preimage().unwrap();
    let shares = indices
        .iter()
        .map(|&index| PrivateSettlementAvailabilityShareV1 {
            version: ATOMIC_PRIVATE_SETTLEMENT_VERSION_V1,
            body: material.availability_body,
            signer: material.committee_authority.validators[index].clone(),
            signature: Signature::try_new(keys[index].private_key(), &preimage)
                .unwrap()
                .payload()
                .to_vec(),
        })
        .collect::<Vec<_>>();
    aggregate_availability_shares_v1(
        material.availability_body,
        &material.committee_authority,
        &shares,
    )
    .unwrap()
}
fn phase_certificates(
    request: &PrivateSettlementRequest,
    manifest: &AtomicPrivateSettlementV1,
    phase: PrivateSettlementPhaseV1,
    digest: Hash,
) -> Vec<PrivateSettlementPhaseCertificateV1> {
    request
        .0
        .materials
        .iter()
        .enumerate()
        .map(|(index, material)| {
            let ordinal = u8::try_from(index).expect("fixture leg ordinal fits u8");
            let (authority, keys) =
                existing::finalization_authority_v1(material.statement.route, ordinal);
            let body =
                expected_phase_body_v1(manifest, ordinal, &authority, phase, digest).unwrap();
            aggregate_phase_votes_v1(
                &body,
                ordinal,
                &authority,
                &existing::phase_votes_v1(&authority, &keys, &body, &[0, 1, 2]),
            )
            .unwrap()
        })
        .collect()
}
fn complete_round(journal: &mut WorkflowJournalV1, index: usize, bytes: Vec<u8>) {
    let round_id = crate::workflow::round_identity(
        &journal.id(),
        u32::try_from(index).expect("fixture workflow step index fits u32"),
    );
    journal
        .apply_round(index, RoundInputV1::Intent { round_id })
        .unwrap();
    journal
        .apply_round(
            index,
            RoundInputV1::Completed {
                participants: Vec::new(),
                transcript: bytes,
                custody_handles: Vec::new(),
            },
        )
        .unwrap();
}
fn checkpoint(
    request: &PrivateSettlementRequest,
    certificates: &[PrivateSettlementSidecarAvailabilityV1],
) -> WorkflowJournalV1 {
    let binding = WorkflowBindingV1 {
        network: request.manifest().network_id.to_string(),
        authority: "test-sponsor".into(),
    };
    let mut journal = WorkflowJournalV1::new(&request.plan(), &binding, 1).unwrap();
    complete_round(
        &mut journal,
        AVAILABILITY,
        norito::encode_canonical(&certificates.to_vec()).unwrap(),
    );
    let manifest = request.manifest_with(certificates).unwrap();
    let prepare = phase_certificates(
        request,
        &manifest,
        PrivateSettlementPhaseV1::Prepare,
        private_settlement_reserved_prepared_digest_v1(),
    );
    complete_round(
        &mut journal,
        PREPARE,
        norito::encode_canonical(&prepare).unwrap(),
    );
    journal.sequence = 1;
    journal
}
fn bundle(
    request: &PrivateSettlementRequest,
    journal: &WorkflowJournalV1,
) -> (
    PrivateSettlementPrepareBarrierV1,
    PrivateSettlementCommitBundleV1,
) {
    let barrier = request.barrier(journal).unwrap();
    let commits = phase_certificates(
        request,
        &barrier.manifest,
        PrivateSettlementPhaseV1::Commit,
        barrier.prepared_bundle_digest,
    );
    let bundle = build_private_settlement_commit_bundle_v1(&barrier, &commits).unwrap();
    (barrier, bundle)
}
fn certified(
    native: &mut NativeFinalityFixture,
    client: &Client,
    bundle: PrivateSettlementCommitBundleV1,
    rejected: bool,
) -> (
    VerifiedSumeragiBlock,
    iroha_data_model::query::CommittedTransaction,
) {
    let header = native.next_header();
    let mut builder = TransactionBuilder::new(
        client.network_id,
        client.account.clone(),
        bundle.manifest.public_fee_intent.clone(),
    )
    .with_instructions([FinalizeAtomicPrivateSettlementV1::new(bundle)]);
    builder.set_creation_time(Duration::from_millis(header.creation_time_ms - 1));
    let transaction = builder.sign(client.key_pair.private_key());
    let mut builder = BlockBuilder::new(header);
    builder.push_transaction(transaction);
    let mut block = builder.build(BlockSignatures::default());
    let result = TransactionResult::new(if rejected {
        Err(TransactionRejectionReason::LimitCheck(
            TransactionLimitError {
                reason: "rejected synthetic settlement".into(),
            },
        ))
    } else {
        Ok(Vec::new())
    });
    block
        .set_execution_outputs(
            vec![ExecutionOutputV1::Network(NetworkExecutionOutputV1 {
                input_index: 0,
                result,
                completions: Vec::new(),
            })],
            0,
            BTreeMap::default(),
            Vec::new(),
            AxtPolicySnapshot::default(),
            BTreeSet::default(),
            &ExecutionOutputLimits {
                max_outputs: 16,
                max_output_bytes: 16 * 1024 * 1024,
                max_total_output_bytes: 32 * 1024 * 1024,
                max_executed_wire_bytes: 32 * 1024 * 1024,
            },
        )
        .unwrap();
    let mut verifier = native.verifier();
    let proof = native.certify(block);
    let authenticated = verifier.verify(&proof).unwrap();
    let evidence = observation::evidence(authenticated.block(), 0).unwrap();
    (authenticated, evidence)
}

#[test]
fn private_settlement_certificate_checkpoint_is_exact_durable_and_contains_no_restricted_artifact()
{
    let client = client_with_base_url(base_url());
    let (request, certificates) = prepared(&client);
    request.plan().validate().unwrap();
    let journal = checkpoint(&request, &certificates);
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("private-workflow");
    let storage = FileWorkflowStorage::open_or_create(&root).unwrap();
    let record = journal.encode_record().unwrap();
    storage
        .compare_and_store(&journal.id(), None, &record)
        .unwrap();
    drop(storage);
    let storage = FileWorkflowStorage::open_or_create(&root).unwrap();
    let restored =
        WorkflowJournalV1::decode_record(&storage.load(&journal.id()).unwrap().unwrap()).unwrap();
    assert_eq!(
        request.barrier(&restored).unwrap(),
        request.barrier(&journal).unwrap()
    );
    let bytes = record;
    for material in &request.0.materials {
        assert!(
            !bytes
                .windows(material.proof.len())
                .any(|window| window == material.proof)
        );
        assert!(
            !bytes
                .windows(material.audit_capsule.ciphertext.len())
                .any(|window| window == material.audit_capsule.ciphertext)
        );
    }
    let mut changed = certificates.clone();
    changed[0] = availability(&request.0.materials[0], &[0, 1, 3]);
    assert_ne!(
        request.manifest_with(&changed).unwrap(),
        request.manifest_with(&certificates).unwrap(),
        "availability signatures are part of the exact durable manifest"
    );
    assert_eq!(
        transcript::<Vec<PrivateSettlementSidecarAvailabilityV1>>(&restored, AVAILABILITY).unwrap(),
        certificates
    );
}

#[test]
fn private_settlement_fixed_certificate_maximum_and_plan_fit_original_journal_caps() {
    let client = client_with_base_url(base_url());
    let (request, certificates) = prepared(&client);
    let journal = checkpoint(&request, &certificates);
    let barrier = request.barrier(&journal).unwrap();
    for bytes in [
        norito::encode_canonical(&vec![certificates[0].clone(); 255]).unwrap(),
        norito::encode_canonical(&vec![barrier.prepare_certificates[0].clone(); 255]).unwrap(),
    ] {
        assert!(bytes.len() < CERTIFICATE_TRANSCRIPT_BYTES as usize);
    }
    assert!(
        request.plan().journal_bytes_bound()
            <= crate::workflow::contract::MAX_WORKFLOW_JOURNAL_BYTES_V1
    );
    let mut changed = request.0.materials.clone();
    changed[0].proof[0] ^= 1;
    assert!(
        PrivateSettlementRequest::new(
            changed,
            request.0.endpoints.clone(),
            request.0.max_carrier_bytes
        )
        .is_err()
    );
    assert!(PrivateSettlementRequest::new(Vec::new(), Vec::new(), 1).is_err());
}

#[test]
fn private_settlement_verified_receipt_requires_successful_exact_final_tip_execution() {
    for rejected in [false, true] {
        let mut native = NativeFinalityFixture::start("private-settlement-sdk-receipt");
        let mut client = client_with_base_url(base_url());
        client.network_id = native.network_id();
        let (request, certificates) = prepared(&client);
        let (barrier, bundle) = bundle(&request, &checkpoint(&request, &certificates));
        let (block, evidence) = certified(&mut native, &client, bundle, rejected);
        let result =
            VerifiedPrivateSettlementReceipt::verify_recovered(&block, &barrier, evidence.clone());
        if rejected {
            assert!(matches!(
                result,
                Err(PrivateSettlementReceiptError::Rejected)
            ));
            continue;
        }
        let verified = result.unwrap();
        assert_eq!(verified.receipt().finalized_height, block.height());
        assert_eq!(verified.receipt().manifest, barrier.manifest);
        assert!(verified.nexus_fee_receipt().is_none());
        let wrong = HashOf::from_untyped_unchecked(Hash::new(b"different signed carrier"));
        assert!(
            VerifiedPrivateSettlementReceipt::verify(&block, &barrier, wrong, evidence.clone())
                .is_err()
        );
        let mut changed = barrier.clone();
        changed.deltas[0].nullifiers[0] =
            iroha_data_model::privacy::PrivacyNullifierV1::new([99; 32]);
        assert!(
            VerifiedPrivateSettlementReceipt::verify_recovered(&block, &changed, evidence.clone())
                .is_err()
        );
        let mut changed = barrier.clone();
        changed.manifest.network_id =
            iroha_data_model::NetworkId::from_genesis_hash(HashOf::from_untyped_unchecked(
                Hash::new(b"different independently selected private genesis"),
            ));
        assert_ne!(changed.manifest.network_id, barrier.manifest.network_id);
        assert!(
            VerifiedPrivateSettlementReceipt::verify_recovered(&block, &changed, evidence.clone())
                .is_err()
        );
        let mut changed = evidence.clone();
        changed.output_hash = HashOf::from_untyped_unchecked(Hash::new(b"changed execution"));
        assert!(
            VerifiedPrivateSettlementReceipt::verify_recovered(&block, &barrier, changed).is_err()
        );
    }
}

#[tokio::test]
async fn private_settlement_receipt_locator_recovers_only_successful_matching_finalization() {
    use crate::{client::evidence_http_tests::with_mock_http, http::Response};

    for rejected in [false, true] {
        let mut native = NativeFinalityFixture::start("private-settlement-receipt-locator");
        let verifier = native.verifier();
        let mut client = client_with_base_url(base_url());
        client.network_id = native.network_id();
        let (request, certificates) = prepared(&client);
        let journal = checkpoint(&request, &certificates);
        let (barrier, bundle) = bundle(&request, &journal);
        let (block, _) = certified(&mut native, &client, bundle.clone(), rejected);
        // The public locator claims success in both cases. Only authenticated execution
        // of the exact matching finalization may establish a successful receipt.
        let receipt = PrivateSettlementBundleReceiptResponseV1::Finalized(
            bundle.into_receipt(block.height()),
        );
        let proofs = BTreeMap::from([
            (1, native.genesis_proof().clone()),
            (block.height(), native.latest().clone()),
        ]);
        let transport = with_mock_http(
            move |http| {
                let path = http.url.path();
                let (content_type, body) = if path.ends_with("/receipt") {
                    ("application/json", norito::json::to_vec(&receipt)?)
                } else {
                    let height = path.rsplit('/').next().unwrap().parse::<u64>()?;
                    (
                        "application/x-norito",
                        norito::encode_canonical(&proofs[&height])?,
                    )
                };
                Ok(Response::builder()
                    .status(200)
                    .header("content-type", content_type)
                    .body(body)?)
            },
            |transport| transport,
        );
        let client = client.with_test_http_transport(transport);
        crate::client::evidence_http_tests::mark_data_model_compatible(&client);
        let ledger = SettlementLedger::new(
            client.account_client().unwrap(),
            request,
            Arc::new(Mutex::new(Some(PublicContext {
                barrier: barrier.clone(),
                phase: FINALIZE,
            }))),
            verifier,
            Arc::new(tokio::sync::Semaphore::new(1)),
        );
        ledger.begin_call(2).unwrap();
        let recovered = ledger.recover_business(&journal).await;
        if rejected {
            assert!(matches!(recovered, Err(PrivateSettlementError::Binding)));
        } else {
            let recovered = recovered.unwrap().unwrap();
            assert_eq!(recovered.receipt().manifest, barrier.manifest);
            assert_eq!(recovered.receipt().finalized_height, block.height());
        }
    }
}

struct CountingSigner {
    context: AccountWorkflowContext,
    calls: AtomicUsize,
}
impl WorkflowAccount for CountingSigner {
    fn binding(&self) -> WorkflowBindingV1 {
        self.context.binding()
    }
    fn identify(&self, bytes: &[u8]) -> std::result::Result<TransactionIdentityV1, StepFailure> {
        self.context.identify(bytes)
    }
    fn sign<'a>(
        &'a self,
        bytes: &'a [u8],
    ) -> WorkflowFuture<'a, std::result::Result<SignedStepTransaction, StepFailure>> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.context.sign(bytes)
    }
}
#[tokio::test]
async fn private_settlement_restored_unsigned_substitution_never_reaches_signer() {
    let client = client_with_base_url(base_url());
    let account = client.account_client().unwrap();
    let (request, certificates) = prepared(&client);
    let journal = checkpoint(&request, &certificates);
    let barrier = request.barrier(&journal).unwrap();
    let payload = account
        .prepare_transaction(AccountTransactionDraft::new(
            [InstructionBox::from(
                RegisterAtomicPrivateSettlementPrepareV1::new(barrier.clone()),
            )],
            barrier.manifest.public_fee_intent.clone(),
            Metadata::default(),
        ))
        .unwrap();
    let signer = Arc::new(CountingSigner {
        context: AccountWorkflowContext::new(account).unwrap(),
        calls: AtomicUsize::new(0),
    });
    let guarded = SettlementAccount {
        account: signer.clone(),
        request,
        state: Arc::new(Mutex::new(Some(PublicContext {
            barrier,
            phase: REGISTER,
        }))),
    };
    for changed in [
        {
            let mut p = payload.clone();
            p.metadata.insert(
                "unapproved".parse().unwrap(),
                iroha_primitives::json::Json::new(true),
            );
            p
        },
        {
            let mut p = payload.clone();
            p.fee_payment = iroha_data_model::transaction::FeePaymentIntent::authority(
                Vec::new(),
                std::num::NonZeroU64::new(1),
            );
            p
        },
    ] {
        let error = guarded
            .sign(&norito::encode_canonical(&changed).unwrap())
            .await
            .unwrap_err();
        assert_eq!(error.code, WorkflowErrorCode::BindingMismatch);
    }
    assert_eq!(signer.calls.load(Ordering::SeqCst), 0);
    guarded
        .sign(&norito::encode_canonical(&payload).unwrap())
        .await
        .unwrap();
    assert_eq!(signer.calls.load(Ordering::SeqCst), 1);
}

#[path = "online_tests.rs"]
mod online_tests;

#[test]
fn private_settlement_promotion_refuses_substituted_upload_identity_before_prepare() {
    use crate::client::evidence_http_tests::{SnapshotStore, respond_with, with_mock_http};
    use iroha_torii_shared::private_settlement_api::PrivateSettlementLegUploadDispositionV1;
    let client = client_with_base_url(base_url());
    let (request, certificates) = prepared(&client);
    let journal = checkpoint(&request, &certificates);
    for field in 0..3 {
        let mut response = PrivateSettlementLegUploadResponseV1 {
            bundle_id: request.manifest().bundle_id,
            payload_digest: request.0.materials[0].payload_digest().unwrap(),
            leg_ordinal: 0,
            disposition: PrivateSettlementLegUploadDispositionV1::AlreadyStored,
            lifecycle: PrivateSettlementLifecycleDtoV1::Collecting,
        };
        match field {
            0 => response.bundle_id = Hash::new(b"substituted bundle"),
            1 => response.payload_digest = Hash::new(b"substituted payload"),
            _ => response.leg_ordinal = 1,
        }
        let snapshots: SnapshotStore = Arc::new(Mutex::new(Vec::new()));
        let response = Response::builder()
            .status(200)
            .header("Content-Type", APPLICATION_JSON)
            .body(norito::json::to_vec(&response).unwrap())
            .unwrap();
        let result = with_mock_http(respond_with(&snapshots, response), |transport| {
            phases::run(
                &client.clone().with_test_http_transport(transport),
                &request,
                PREPARE,
                &journal,
                false,
            )
        });
        assert!(
            result.is_err(),
            "a substituted promotion cannot authorize Prepare"
        );
        let requests = snapshots.lock().unwrap();
        let n = request.0.materials[0].committee_authority.validators.len();
        assert_eq!(
            requests
                .iter()
                .filter(|r| r.url.path().ends_with("/legs"))
                .count(),
            n,
            "all invalid upload acknowledgements must leave Prepare unrequested"
        );
        assert_eq!(
            requests
                .iter()
                .filter(|r| r.url.path().ends_with("/availability-shares"))
                .count(),
            n,
            "at most one exact rehydration request is allowed for each failed endpoint"
        );
        assert!(
            requests.iter().all(|r| r.url.path().ends_with("/legs")
                || r.url.path().ends_with("/availability-shares"))
        );
    }
}

fn promotion_with_returning_replica(returning: bool, substituted_signer: bool) {
    use crate::client::evidence_http_tests::{SnapshotStore, with_mock_http};
    use iroha_torii_shared::private_settlement_api::PrivateSettlementLegUploadDispositionV1;
    let client = client_with_base_url(base_url());
    let (request, certificates) = prepared(&client);
    let snapshots: SnapshotStore = Arc::new(Mutex::new(Vec::new()));
    let recorded = snapshots.clone();
    let expected = certificates.clone();
    let endpoints = request.0.endpoints.clone();
    let materials = request.0.materials.clone();
    let promotion_started = Mutex::new(std::collections::BTreeSet::new());
    let provisional = Mutex::new(std::collections::BTreeSet::new());
    let result = with_mock_http(
        move |request| {
            let mut promotion_started = promotion_started.lock().unwrap();
            let mut provisional = provisional.lock().unwrap();
            let host = request.url.host_str().unwrap();
            let index = endpoints[0]
                .iter()
                .position(|endpoint| endpoint.host_str() == Some(host))
                .unwrap();
            let (status, body) = if request.url.path().ends_with("/availability-shares") {
                let upload: PrivateSettlementAvailabilityShareRequestV1 =
                    norito::json::from_slice(&request.body)?;
                let material = upload.material;
                let ordinal = material.statement.leg_ordinal;
                assert_eq!(
                    material,
                    materials[usize::from(ordinal)],
                    "rehydration must retain exact original prepared artifacts"
                );
                let promoting = promotion_started.contains(&ordinal);
                if (returning && index == 3 && !promoting) || (index == 0 && promoting) {
                    recorded.lock().unwrap().push(request);
                    return Ok(Response::builder()
                        .status(503)
                        .header("Content-Type", APPLICATION_JSON)
                        .body(Vec::new())?);
                }
                provisional.insert((ordinal, index));
                let (_, keys) = existing::finalization_authority_v1(
                    material.statement.route,
                    material.statement.leg_ordinal,
                );
                let signer_index = if promoting && index == 3 && substituted_signer {
                    2
                } else {
                    index
                };
                let share = PrivateSettlementAvailabilityShareV1 {
                    version: ATOMIC_PRIVATE_SETTLEMENT_VERSION_V1,
                    body: material.availability_body,
                    signer: material.committee_authority.validators[signer_index].clone(),
                    signature: Signature::try_new(
                        keys[signer_index].private_key(),
                        &material.availability_body.signature_preimage()?,
                    )?
                    .payload()
                    .to_vec(),
                };
                (
                    200,
                    norito::json::to_vec(&PrivateSettlementAvailabilityShareResponseV1 {
                        bundle_id: share.body.bundle_id,
                        payload_digest: share.body.payload_digest,
                        leg_ordinal: share.body.leg_ordinal,
                        disposition: PrivateSettlementLegUploadDispositionV1::Stored,
                        share,
                    })?,
                )
            } else {
                assert!(request.url.path().ends_with("/legs"));
                let upload: PrivateSettlementLegUploadRequestV1 =
                    norito::json::from_slice(&request.body)?;
                let ordinal = upload.payload.statement.leg_ordinal;
                promotion_started.insert(ordinal);
                assert_eq!(
                    upload.payload.availability,
                    expected[usize::from(ordinal)],
                    "promotion must retain the original exact availability certificate"
                );
                if index == 0 || !provisional.contains(&(ordinal, index)) {
                    if index == 0 {
                        assert_ne!(upload.payload.availability.signers_bitmap & 1, 0);
                    }
                    (
                        503,
                        br#"{"code":"private_settlement_service_unavailable","message":"offline"}"#
                            .to_vec(),
                    )
                } else {
                    (
                        200,
                        norito::json::to_vec(&PrivateSettlementLegUploadResponseV1 {
                            bundle_id: upload.manifest.bundle_id,
                            payload_digest: upload.payload.availability.body.payload_digest,
                            leg_ordinal: ordinal,
                            disposition: PrivateSettlementLegUploadDispositionV1::AlreadyStored,
                            lifecycle: PrivateSettlementLifecycleDtoV1::Collecting,
                        })?,
                    )
                }
            };
            recorded.lock().unwrap().push(request);
            Ok(Response::builder()
                .status(status)
                .header("Content-Type", APPLICATION_JSON)
                .body(body)?)
        },
        |transport| {
            client
                .clone()
                .with_test_http_transport(transport)
                .certify_and_upload_private_settlement_legs_v1(
                    &request.0.materials,
                    &request.0.endpoints,
                )
        },
    );
    if substituted_signer {
        assert!(returning);
        assert!(
            result.is_err(),
            "a different member's valid rehydration signature cannot authorize upload retry"
        );
        let captured = snapshots.lock().unwrap();
        assert_eq!(
            captured
                .iter()
                .filter(|r| r.url.path().ends_with("/legs"))
                .count(),
            request.0.materials[0].committee_authority.validators.len(),
            "substituted responder must not trigger another upload or progress to a later leg"
        );
        assert_eq!(
            captured
                .iter()
                .filter(|r| r.url.path().ends_with("/availability-shares"))
                .count(),
            request.0.materials.len() * request.0.materials[0].committee_authority.validators.len()
                + 2,
            "only the first leg's two failed endpoints can be rehydrated before refusal"
        );
        return;
    }
    let promoted = result.expect(if returning {
        "a returned healthy replica must recover original provisional custody without changing the availability certificate"
    } else {
        "one original availability signer going offline must not strand an alternate healthy promoted quorum"
    });
    let n = request.0.materials[0].committee_authority.validators.len();
    let q = n - (n - 1) / 3;
    assert_eq!(promoted.len(), request.0.materials.len() * q);
    let captured = snapshots.lock().unwrap();
    assert_eq!(
        captured
            .iter()
            .filter(|r| r.url.path().ends_with("/availability-shares"))
            .count(),
        request.0.materials.len() * (n + if returning { 2 } else { 0 }),
        "only failed replicas may receive the original provisional bytes after a promotion shortfall"
    );
    assert_eq!(
        captured
            .iter()
            .filter(|r| r.url.path().ends_with("/legs"))
            .count(),
        request.0.materials.len() * (n + usize::from(returning)),
        "all authorized replicas must be attempted and only a successfully rehydrated replica is retried"
    );
}

#[test]
fn private_settlement_promotion_survives_original_availability_signer_offline_without_reselection()
{
    promotion_with_returning_replica(false, false);
}

#[test]
fn private_settlement_returned_replica_rehydrates_exact_original_material_without_certificate_reselection()
 {
    promotion_with_returning_replica(true, false);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn private_settlement_cancelled_phase_retains_shared_dispatch_capacity() {
    use crate::client::evidence_http_tests::with_mock_http;
    let native = NativeFinalityFixture::start("private-settlement-cancelled-phase");
    let mut client = client_with_base_url(base_url());
    client.network_id = native.network_id();
    let (request, certificates) = prepared(&client);
    let journal = checkpoint(&request, &certificates);
    let barrier = request.barrier(&journal).unwrap();
    let (started, entered) = tokio::sync::oneshot::channel();
    let started = Mutex::new(Some(started));
    let (release, wait) = std::sync::mpsc::channel();
    let wait = Mutex::new(wait);
    let transport = with_mock_http(
        move |_| {
            let signal = started.lock().unwrap().take();
            if let Some(started) = signal {
                started.send(()).unwrap();
                wait.lock().unwrap().recv().unwrap();
            }
            Err(eyre!("original phase I/O stopped after test release"))
        },
        |transport| transport,
    );
    let client = client.with_test_http_transport(transport);
    let account = client.account_client().unwrap();
    let transaction = account
        .prepare_transaction(AccountTransactionDraft::new(
            [InstructionBox::from(
                RegisterAtomicPrivateSettlementPrepareV1::new(barrier.clone()),
            )],
            barrier.manifest.public_fee_intent.clone(),
            Metadata::default(),
        ))
        .and_then(|payload| account.sign_transaction(payload))
        .unwrap();
    let bytes = transaction.encode_wire_v1().unwrap();
    let worker = Arc::new(tokio::sync::Semaphore::new(1));
    let phases = OnlinePhases::new(client, request.clone(), worker.clone());
    let ledger = SettlementLedger::new(
        account,
        request,
        Arc::new(Mutex::new(Some(PublicContext {
            barrier,
            phase: REGISTER,
        }))),
        native.verifier(),
        worker.clone(),
    );
    let active = tokio::spawn(async move { phases.run(COMMIT, journal, false).await });
    entered.await.unwrap();
    active.abort();
    assert!(active.await.unwrap_err().is_cancelled());
    assert!(
        matches!(
            ledger.dispatch(&bytes, &identity(&transaction)).await,
            DispatchOutcome::NotAdmitted {
                code: WorkflowErrorCode::LocalResourceUnavailable,
                ..
            }
        ),
        "a cancelled certificate phase must keep its original capacity away from dispatch"
    );
    release.send(()).unwrap();
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            if worker.clone().try_acquire_owned().is_ok() {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("phase exit returns its original shared capacity");
}

#[test]
fn private_settlement_rehydration_rejects_valid_share_from_a_different_endpoint_member() {
    promotion_with_returning_replica(true, true);
}

#[test]
fn private_settlement_promotion_counts_only_three_exact_acknowledgements_after_one_substitution() {
    use crate::client::evidence_http_tests::{SnapshotStore, with_mock_http};
    use iroha_torii_shared::private_settlement_api::PrivateSettlementLegUploadDispositionV1;
    let client = client_with_base_url(base_url());
    let (request, certificates) = prepared(&client);
    let snapshots: SnapshotStore = Arc::new(Mutex::new(Vec::new()));
    let recorded = snapshots.clone();
    let endpoints = request.0.endpoints.clone();
    let expected = certificates.clone();
    let result = with_mock_http(move |http| {
        assert!(http.url.path().ends_with("/legs"), "a sufficient initial promotion set needs no rehydration or new certificate");
        let upload: PrivateSettlementLegUploadRequestV1 = norito::json::from_slice(&http.body)?;
        let ordinal = upload.payload.statement.leg_ordinal;
        let index = endpoints[usize::from(ordinal)].iter()
            .position(|endpoint| endpoint.host_str() == http.url.host_str()).unwrap();
        assert_eq!(upload.payload.availability, expected[usize::from(ordinal)]);
        let response = PrivateSettlementLegUploadResponseV1 {
            bundle_id: if index == 0 { Hash::new(b"substituted promotion bundle") } else { upload.manifest.bundle_id },
            payload_digest: upload.payload.availability.body.payload_digest,
            leg_ordinal: ordinal,
            disposition: PrivateSettlementLegUploadDispositionV1::AlreadyStored,
            lifecycle: PrivateSettlementLifecycleDtoV1::Collecting,
        };
        recorded.lock().unwrap().push(http);
        Ok(Response::builder().status(200).header("Content-Type", APPLICATION_JSON)
            .body(norito::json::to_vec(&response)?)?)
    }, |transport| {
        client.clone().with_test_http_transport(transport).promote_private_settlement_legs_v1(
            &request.0.materials, &certificates, &request.0.endpoints)
    }).expect("three exact acknowledgements suffice for Prepare preflight; only its later QC grants phase authority");
    let n = request.0.materials[0].committee_authority.validators.len();
    let q = n - (n - 1) / 3;
    assert_eq!(result.len(), q * request.0.materials.len());
    assert!(
        result
            .iter()
            .all(|ack| ack.bundle_id == request.manifest().bundle_id)
    );
    assert_eq!(
        snapshots.lock().unwrap().len(),
        n * request.0.materials.len()
    );
}

#[test]
fn private_settlement_advanced_material_accessor_borrows_exact_public_encrypted_owner() {
    let client = client_with_base_url(base_url());
    let (request, _) = prepared(&client);
    let original = request.0.materials.as_slice();
    let exposed = request.materials();
    assert_eq!(exposed.len(), original.len());
    assert!(
        std::ptr::eq(exposed.as_ptr(), original.as_ptr()),
        "advanced inspection must borrow the original encrypted/public material allocation"
    );
    assert_eq!(exposed, original);
    for material in exposed {
        material.validate().unwrap();
    }
    // The closed material type has no wallet witness, spending secret or plaintext audit
    // field. This accessor does not alter that schema or grant proof/finality authority.
}

#[test]
fn private_settlement_network_indices_preserve_binding_error_classification() {
    assert_eq!(observation::network_index(0).unwrap(), 0);
    let maximum = usize::try_from(u32::MAX).expect("supported pointer width represents u32");
    assert_eq!(observation::network_index(maximum).unwrap(), u32::MAX);
    if let Some(overflow) = maximum.checked_add(1) {
        assert!(matches!(
            observation::network_index(overflow),
            Err(PrivateSettlementError::Binding)
        ));
        assert!(matches!(
            observation::network_index(usize::MAX),
            Err(PrivateSettlementError::Binding)
        ));
    }
}

#[test]
fn private_settlement_step_failure_keeps_binding_and_local_resource_codes() {
    for (error, code) in [
        (
            PrivateSettlementError::Binding,
            WorkflowErrorCode::BindingMismatch,
        ),
        (
            PrivateSettlementError::Worker,
            WorkflowErrorCode::LocalResourceUnavailable,
        ),
        (
            PrivateSettlementError::ReadBudget,
            WorkflowErrorCode::LocalResourceUnavailable,
        ),
    ] {
        let converted = failure(&error);
        assert_eq!(converted.code, code);
        assert_eq!(converted.detail, error.to_string());
    }
}
