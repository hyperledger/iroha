//! Typed dispatch and crash tests with explicit mock proofs; no artifact/provider admission.

use super::*;

#[path = "intake_tests.rs"]
mod intake;

use crate::kagemusha_wallet_advance_v1::kagemusha_wallet_archive_object_digest_v1 as object_digest;

/// Which mock derivation a proof consumed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::kagemusha_wallet_state_v1) enum TestOriginV1 {
    Plan,
    Validate,
}

/// Mock call-scoped derivation, bound to the exact plan bytes it was derived from.
pub(in crate::kagemusha_wallet_state_v1) struct TestPreparedV1 {
    plan: [u8; 32],
    origin: TestOriginV1,
}

impl NativePreparation for TestProofs {
    type Prepared = TestPreparedV1;
    fn plan_preparation(
        &self,
        request: &NativeIntentV1,
        source: &PreparationSourceV1<'_>,
        custody: &mut PreparationCustodyV1<'_>,
    ) -> Result<(Vec<u8>, Self::Prepared), Error> {
        self.preparations.fetch_add(1, Ordering::SeqCst);
        self.derivations.fetch_add(1, Ordering::SeqCst);
        if !self.preparation_payload.is_empty() {
            custody
                .maps()
                .store()
                .stage_object(&self.preparation_payload, self.preparation_payload.len())?;
        }
        if self.fail_preparation_plan {
            return Err(Error::Invalid("test native plan refusal"));
        }
        if let Some(OperationActionV1::Load { finality, .. }) =
            request.user_request().map(|request| &request.action)
        {
            // This mock routes through the actual canonical decoder and epoch selector only.
            // It grants no finality, installation or proof authority.
            let evidence = KagemushaWalletLoadFinalityV1::decode_canonical(finality)
                .map_err(|_| Error::Invalid("test Load outer shape"))?;
            evidence.certificate.epoch_id().map_err(|error| {
                crate::kagemusha_wallet_state_v1::finality_read_error(
                    error,
                    Error::Proof("Load native epoch selector"),
                )
            })?;
            return Err(Error::Invalid("mock Load cannot accept finality"));
        }
        if request.user_request().map(|request| &request.action) != Some(&OperationActionV1::Retire)
        {
            return Err(Error::Invalid("test action"));
        }
        let fold = source.folded().ok_or(Error::FoldRequired)?;
        let mut retiring = frozen(
            Some(&source.released().frozen),
            KagemushaWalletEffectV1::Retiring,
        );
        let mut c = retiring.capsule.body().clone();
        c.predecessor_lineage = KagemushaWalletLineageSlotV1::Present {
            lineage: fold.lineage.clone(),
        };
        c.statement.lineage_burned_total = fold.lineage.public.burned_total;
        c.statement.lineage_pending_outgoing_root = fold.lineage.public.pending_outgoing_root;
        c.successor_state.core.burned_total = c.statement.lineage_burned_total;
        c.statement.successor = c.successor_state.commitment().unwrap();
        c.operation_id = c.statement.operation_id(&c.wallet_id).unwrap();
        c.output = KagemushaWalletOutputDescriptorV1::for_transition(
            &c.statement,
            &c.proof_digest().unwrap(),
            &c.payment_digest,
        )
        .unwrap();
        retiring.capsule = c
            .freeze()
            .expect("valid synthetic body")
            .seal([0; 32])
            .expect("synthetic opening");
        let plan = archive::encode(&retiring)?;
        let prepared = TestPreparedV1 {
            plan: object_digest(&plan),
            origin: TestOriginV1::Plan,
        };
        Ok((plan, prepared))
    }

    fn validate_preparation(
        &self,
        request: &NativeIntentV1,
        source: &PreparationSourceV1<'_>,
        custody: &mut PreparationCustodyV1<'_>,
        plan: &[u8],
    ) -> Result<Self::Prepared, Error> {
        self.validations.fetch_add(1, Ordering::SeqCst);
        self.derivations.fetch_add(1, Ordering::SeqCst);
        if !self.preparation_payload.is_empty() {
            custody
                .maps()
                .store()
                .stage_object(&self.preparation_payload, self.preparation_payload.len())?;
        }
        if self.fail_preparation_validation {
            return Err(Error::Invalid("test native validation refusal"));
        }
        let prepared: FrozenTransition = archive::decode(plan)?;
        prepared.validate()?;
        if request.user_request().map(|request| &request.action) != Some(&OperationActionV1::Retire)
            || prepared.capsule.body().predecessor_capsule_digest
                != source.released().frozen.capsule.custody_digest()
        {
            return Err(Error::Invalid("test plan binding"));
        }
        Ok(TestPreparedV1 {
            plan: object_digest(plan),
            origin: TestOriginV1::Validate,
        })
    }

    fn prove_preparation(
        &self,
        _: &NativeIntentV1,
        _: &PreparationSourceV1<'_>,
        prepared: Self::Prepared,
        plan: &[u8],
    ) -> Result<FrozenTransition, Error> {
        // Proving consumes the call's derivation and takes no custody.
        self.preparation_proofs.fetch_add(1, Ordering::SeqCst);
        if prepared.plan != object_digest(plan) {
            return Err(Error::WitnessLost("test prepared operation binding"));
        }
        self.proof_origins.lock().unwrap().push(prepared.origin);
        if let Some(hook) = &self.prove_hook {
            hook();
        }
        if self.fail_preparation_proof {
            return Err(Error::Proof("injected preparation stop"));
        }
        archive::decode(plan)
    }
}

fn request() -> OperationRequestV1 {
    OperationRequestV1 {
        request_id: [71; 32],
        action: OperationActionV1::Retire,
    }
}

fn prepared_wallet() -> Wallet {
    let mut wallet = wallet();
    wallet.commit(bootstrap()).unwrap();
    snapshot_test_fold(&mut wallet);
    wallet
}

fn restart(wallet: Wallet) -> Wallet {
    Coordinator::new(
        wallet.custody,
        wallet.archive,
        wallet.proofs,
        wallet.scheme_id,
        wallet.wallet_id,
    )
    .unwrap()
}

#[test]
fn exact_request_replay_survives_restart_without_reproving_or_resigning() {
    let mut wallet = prepared_wallet();
    let request = request();
    let complete = wallet.execute(request.clone()).unwrap();
    assert!(matches!(complete, Completion::Complete(_)));
    assert_eq!(wallet.proofs.preparations.load(Ordering::SeqCst), 1);
    assert_eq!(wallet.proofs.preparation_proofs.load(Ordering::SeqCst), 1);
    let actual = wallet
        .released_steps()
        .unwrap()
        .last()
        .unwrap()
        .frozen
        .capsule
        .body()
        .operation_id;
    assert_ne!(
        actual, request.request_id,
        "native protocol operation derives from statement"
    );
    assert_eq!(wallet.retry(&actual).unwrap(), Some(complete.clone()));
    let signatures = wallet.custody.signatures;
    let mut wallet = restart(wallet);
    assert_eq!(wallet.execute(request.clone()).unwrap(), complete);
    assert_eq!(
        wallet.retry_request(&request.request_id).unwrap(),
        RequestStatusV1::Outcome(complete)
    );
    assert_eq!(wallet.proofs.preparations.load(Ordering::SeqCst), 1);
    assert_eq!(wallet.proofs.preparation_proofs.load(Ordering::SeqCst), 1);
    assert_eq!(wallet.custody.signatures, signatures);
    let changed = OperationRequestV1 {
        request_id: request.request_id,
        action: OperationActionV1::Unload {
            amount: 1,
            charge: None,
        },
    };
    assert!(matches!(
        wallet.execute(changed),
        Err(Error::OperationConflict)
    ));
}

#[test]
fn request_replay_authenticates_exact_completion_in_each_retained_source_state() {
    for source in ["historical", "current", "released_before_index"] {
        for mutation in [8, 0, 1, 2, 3, 4, 5, 6, 7] {
            let mut wallet = prepared_wallet();
            let request = request();
            if source == "released_before_index" {
                // Persist the request/operation mapping first, then interrupt only the
                // post-Advance StepEntry publication. The Released marker still binds output.
                wallet.custody.pause = true;
                assert_eq!(
                    wallet.execute(request.clone()).unwrap(),
                    Completion::Pending
                );
                wallet.custody.pause = false;
                wallet.custody.fail_publication = Some(false);
                assert!(wallet.resume().is_err());
                assert!(matches!(wallet.status().unwrap(), SlotStatus::Released(_)));
            } else {
                assert!(matches!(
                    wallet.execute(request.clone()).unwrap(),
                    Completion::Complete(_)
                ));
            }
            let marker = wallet.status().unwrap();
            let (sequence, operation, capsule) = marker.marker().unwrap().head().unwrap();
            let original = wallet.custody.retained.get(&operation).unwrap().clone();
            let exact = Completion::Complete(original.record.output.clone());
            if source == "historical" {
                // Explicit mock policy proof: advance the head without collecting the old
                // completion. Keep the already-retiring lifecycle; this is retry custody,
                // not a claim of valid policy issuance or native proof admission.
                let previous = wallet.frozen(capsule).unwrap();
                let mut next = frozen(
                    Some(&previous),
                    KagemushaWalletEffectV1::RefreshPolicy {
                        update_kind: KagemushaWalletPolicyUpdateKindV1::TimeAnchor,
                        update: field(111),
                        accepted_time_floor_ms: previous
                            .capsule
                            .body()
                            .successor_state
                            .core
                            .accepted_time_floor_ms,
                    },
                );
                let mut body = next.capsule.body().clone();
                body.statement.lifecycle = KagemushaWalletLifecycleV1::Retiring;
                body.successor_state.core.lifecycle = KagemushaWalletLifecycleV1::Retiring;
                rebind_frozen_successor(&mut next, body);
                wallet.commit(next).unwrap();
                assert!(wallet.manifest().unwrap().1.indexed.unwrap() > sequence);
                assert_ne!(
                    wallet.status().unwrap().marker().unwrap().head().unwrap().1,
                    operation
                );
            } else if source == "released_before_index" {
                assert!(wallet.manifest().unwrap().1.indexed.unwrap() < sequence);
            } else {
                assert_eq!(wallet.manifest().unwrap().1.indexed, Some(sequence));
            }
            let signatures = wallet.custody.signatures;
            let plans = wallet.proofs.preparations.load(Ordering::SeqCst);
            let proofs = wallet.proofs.preparation_proofs.load(Ordering::SeqCst);
            let selected = wallet.custody.checkpoint.clone();
            assert_eq!(wallet.retry(&operation).unwrap(), Some(exact.clone()));
            assert_eq!(
                wallet.retry_request(&request.request_id).unwrap(),
                RequestStatusV1::Outcome(exact.clone())
            );
            assert_eq!(wallet.execute(request.clone()).unwrap(), exact);
            let retained = wallet.custody.retained.get_mut(&operation).unwrap();
            mutate_retained_completion(retained, mutation);
            // The altered record remains a valid self-contained completion frame. Neither
            // its recomputed hash nor the permanent request's IDs authorize these bytes.
            assert_eq!(
                KagemushaWalletCompletionRecordV1::decode_canonical(
                    &retained.frame,
                    &wallet.wallet_id
                )
                .unwrap(),
                retained.record
            );
            let direct = wallet.retry(&operation);
            let request_retry = wallet.retry_request(&request.request_id);
            let repeated = wallet.execute(request.clone());
            assert!(direct.is_err(), "{source}, mutation {mutation}");
            assert!(
                request_retry.is_err(),
                "request retry: {source}, mutation {mutation}"
            );
            assert!(
                repeated.is_err(),
                "repeated execute: {source}, mutation {mutation}"
            );
            if mutation == 8 {
                // Canonical structure, statement and receipt remain unchanged: only the
                // source-authenticated exact completion identity rejects the proof change.
                let expected = if source == "released_before_index" {
                    "unindexed retry marker"
                } else {
                    "retry selected completion binding"
                };
                assert!(matches!(direct, Err(Error::WitnessLost(reason)) if reason == expected));
                assert!(
                    matches!(request_retry, Err(Error::WitnessLost(reason)) if reason == expected)
                );
                assert!(matches!(repeated, Err(Error::WitnessLost(reason)) if reason == expected));
            }
            wallet.custody.retained.insert(operation, original);
            assert_eq!(wallet.retry(&operation).unwrap(), Some(exact.clone()));
            assert_eq!(
                wallet.retry_request(&request.request_id).unwrap(),
                RequestStatusV1::Outcome(exact.clone())
            );
            assert_eq!(wallet.execute(request).unwrap(), exact);
            assert_eq!(wallet.custody.signatures, signatures);
            assert_eq!(wallet.proofs.preparations.load(Ordering::SeqCst), plans);
            assert_eq!(
                wallet.proofs.preparation_proofs.load(Ordering::SeqCst),
                proofs
            );
            assert_eq!(wallet.custody.checkpoint, selected);
        }
    }
}

#[test]
fn runtime_capacity_refuses_before_planning_with_typed_results_and_keeps_the_binding() {
    use crate::kagemusha_wallet_capacity_v1::{
        KagemushaWalletRuntimeCapacityV1, KagemushaWalletRuntimeResourcesV1,
    };
    use crate::kagemusha_wallet_state_v1::capacity::INTAKE_STORAGE_RESERVATION_BYTES;
    let mut wallet = prepared_wallet();
    let signatures = wallet.custody.signatures;
    wallet.proofs.capacity = KagemushaWalletRuntimeCapacityV1 {
        storage_bytes: 1_000,
        memory_bytes: 2_000,
    };
    let enough_storage = INTAKE_STORAGE_RESERVATION_BYTES + 1_000;
    wallet.custody.resources = KagemushaWalletRuntimeResourcesV1 {
        storage_bytes: enough_storage - 1,
        memory_bytes: Some(u64::MAX),
    };
    assert!(matches!(
        wallet.execute(request()),
        Err(Error::NotEnoughStorage)
    ));
    assert_eq!(wallet.proofs.preparation_proofs.load(Ordering::SeqCst), 0);
    assert_eq!(wallet.custody.signatures, signatures, "nothing debited");
    // The fixed binding stays; private planning has not started and no plan was published.
    assert_eq!(
        wallet.retry_request(&request().request_id).unwrap(),
        RequestStatusV1::Preparing
    );
    wallet.custody.resources = KagemushaWalletRuntimeResourcesV1 {
        storage_bytes: enough_storage,
        memory_bytes: Some(1_999),
    };
    assert!(matches!(
        wallet.execute(request()),
        Err(Error::NotEnoughMemory)
    ));
    assert_eq!(wallet.proofs.preparation_proofs.load(Ordering::SeqCst), 0);
    assert_eq!(wallet.custody.signatures, signatures);
    // An unanswered memory probe evaluates storage only; proving and commit both check.
    wallet.custody.resources.memory_bytes = None;
    let queries = wallet.custody.resource_queries;
    let complete = wallet.execute(request()).unwrap();
    assert!(matches!(complete, Completion::Complete(_)));
    assert_eq!(wallet.proofs.preparation_proofs.load(Ordering::SeqCst), 1);
    assert_eq!(wallet.custody.signatures, signatures + 1);
    assert_eq!(wallet.custody.resource_queries, queries + 4);
    // A retained outcome never depends on current capacity.
    wallet.custody.resources = KagemushaWalletRuntimeResourcesV1 {
        storage_bytes: 0,
        memory_bytes: Some(0),
    };
    let queries = wallet.custody.resource_queries;
    assert_eq!(wallet.execute(request()).unwrap(), complete);
    assert_eq!(wallet.custody.resource_queries, queries);
    assert_eq!(wallet.custody.signatures, signatures + 1);
}

#[test]
fn runtime_capacity_refuses_a_fresh_commit_but_never_a_retained_one() {
    use crate::kagemusha_wallet_capacity_v1::KagemushaWalletRuntimeResourcesV1;
    let mut wallet = wallet();
    wallet.custody.resources = KagemushaWalletRuntimeResourcesV1 {
        storage_bytes: 0,
        memory_bytes: Some(u64::MAX),
    };
    assert!(matches!(
        wallet.commit(bootstrap()),
        Err(Error::NotEnoughStorage)
    ));
    assert_eq!(wallet.custody.signatures, 0, "refused before Advance");
    wallet.custody.resources = KagemushaWalletRuntimeResourcesV1 {
        storage_bytes: u64::MAX / 2,
        memory_bytes: Some(0),
    };
    wallet.proofs.capacity.memory_bytes = 1;
    assert!(matches!(
        wallet.commit(bootstrap()),
        Err(Error::NotEnoughMemory)
    ));
    assert_eq!(wallet.custody.signatures, 0);
    wallet.custody.resources.memory_bytes = Some(1);
    let complete = wallet.commit(bootstrap()).unwrap();
    assert!(matches!(complete, Completion::Complete(_)));
    assert_eq!(wallet.custody.signatures, 1);
    wallet.custody.resources = KagemushaWalletRuntimeResourcesV1 {
        storage_bytes: 0,
        memory_bytes: Some(0),
    };
    assert_eq!(wallet.commit(bootstrap()).unwrap(), complete);
    assert_eq!(wallet.custody.signatures, 1);
}

#[test]
fn durable_plan_resumes_after_proof_failure_without_resampling() {
    let mut wallet = prepared_wallet();
    wallet.proofs.fail_preparation_proof = true;
    assert!(matches!(wallet.execute(request()), Err(Error::Proof(_))));
    assert_eq!(
        wallet.retry_request(&request().request_id).unwrap(),
        RequestStatusV1::Preparing
    );
    assert_eq!(wallet.custody.signatures, 1);
    let mut wallet = restart(wallet);
    wallet.proofs.fail_preparation_proof = false;
    assert!(matches!(
        wallet.execute(request()).unwrap(),
        Completion::Complete(_)
    ));
    assert_eq!(wallet.proofs.preparations.load(Ordering::SeqCst), 1);
    assert_eq!(wallet.proofs.preparation_proofs.load(Ordering::SeqCst), 2);
    assert_eq!(wallet.custody.signatures, 2);
}

#[test]
fn lost_selected_request_index_fails_closed_before_any_new_preparation() {
    let mut wallet = prepared_wallet();
    wallet.proofs.fail_preparation_proof = true;
    assert!(wallet.execute(request()).is_err());
    let (_, manifest) = wallet.manifest().unwrap();
    assert_ne!(manifest.preparations.0, [0; 32]);
    wallet
        .archive
        .records
        .lock()
        .unwrap()
        .remove(&ArchiveKey::Object(manifest.preparations.0));
    assert!(matches!(
        wallet.retry_request(&request().request_id),
        Err(Error::WitnessLost(_))
    ));
    assert!(matches!(
        wallet.execute(request()),
        Err(Error::WitnessLost(_))
    ));
    assert_eq!(wallet.proofs.preparations.load(Ordering::SeqCst), 1);
    assert_eq!(wallet.custody.signatures, 1);
}

#[test]
fn request_publication_failure_never_reaches_proving_or_advance() {
    for published in [false, true] {
        let mut wallet = prepared_wallet();
        wallet.custody.fail_publication = Some(published);
        assert!(wallet.execute(request()).is_err());
        assert_eq!(wallet.proofs.preparations.load(Ordering::SeqCst), 0);
        assert_eq!(wallet.proofs.preparation_proofs.load(Ordering::SeqCst), 0);
        assert_eq!(wallet.custody.signatures, 1);
        let mut wallet = restart(wallet);
        assert!(matches!(
            wallet.execute(request()).unwrap(),
            Completion::Complete(_)
        ));
        assert_eq!(wallet.proofs.preparations.load(Ordering::SeqCst), 1);
        assert_eq!(wallet.custody.signatures, 2);
    }
}

#[test]
fn load_request_intake_preserves_actual_model_refusal_before_publication() {
    use iroha_data_model::{
        events::{
            EventBox,
            data::{DataEvent, kagemusha::KagemushaLoadCommittedV1},
        },
        isi::kagemusha_wallet::KagemushaWalletLoadReceiptV1,
        sumeragi_finality::SumeragiCommitCertificateV1,
    };
    let scheme: KagemushaWalletSchemeV1 = fixture("KagemushaWalletSchemeV1");
    let encoded: norito::json::Value = norito::json::from_str(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../fixtures/kagemusha/ordinary_load_receipt_v1.json"
    )))
    .unwrap();
    let receipt_bytes = hex::decode(encoded["receipt_frame_hex"].as_str().unwrap()).unwrap();
    let mut receipt = KagemushaWalletLoadReceiptV1::decode_canonical(&receipt_bytes).unwrap();
    receipt.scheme_id = scheme.scheme_id();
    let event = EventBox::Data(
        DataEvent::KagemushaLoadCommitted(
            KagemushaLoadCommittedV1::from_receipt(&receipt).unwrap(),
        )
        .into(),
    );
    let tree: iroha_crypto::MerkleTree<EventBox> =
        [iroha_crypto::HashOf::new(&event)].into_iter().collect();
    // Intake checks canonical shape only; these bytes grant no native finality.
    let finality = KagemushaWalletLoadFinalityV1 {
        version: 1,
        receipt_digest: receipt.receipt_digest().unwrap(),
        certificate: SumeragiCommitCertificateV1 {
            consensus_header: vec![1],
            commit_qc: vec![2],
            result_preimage: vec![3],
        },
        event_proof: tree.get_proof(0).unwrap(),
    };
    let request = OperationRequestV1 {
        request_id: [72; 32],
        action: OperationActionV1::Load {
            receipt: receipt.to_canonical_bytes().unwrap(),
            finality: finality.to_canonical_bytes().unwrap(),
        },
    };
    request.validate(&scheme).unwrap();
    let unchanged = request.clone();
    for limits in [
        norito::DecodeLimits::new(usize::MAX, 0, usize::MAX, usize::MAX, 64),
        norito::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, 0, 64),
    ] {
        let error =
            norito::with_decode_limits_scope(limits, || request.validate(&scheme)).unwrap_err();
        assert!(matches!(error, Error::DecodeResource(ref original)
            if original.kind() == norito::core::DecodeLocalRefusalKind::EnclosingLimit));
        assert_eq!(request, unchanged);
        request.validate(&scheme).unwrap();
    }
    let mut malformed = request;
    let OperationActionV1::Load { finality, .. } = &mut malformed.action else {
        unreachable!()
    };
    *finality = vec![0];
    assert!(matches!(
        malformed.validate(&scheme),
        Err(Error::Invalid(_))
    ));
}

#[test]
fn canonical_request_bounds_and_originals_are_checked_before_publication() {
    let scheme: KagemushaWalletSchemeV1 = fixture("KagemushaWalletSchemeV1");
    let bytes = archive::encode(&request()).unwrap();
    assert_eq!(
        OperationRequestV1::decode(&bytes, &scheme).unwrap(),
        request()
    );
    let mut trailing = bytes.clone();
    trailing.push(0);
    assert!(OperationRequestV1::decode(&trailing, &scheme).is_err());
    assert!(OperationRequestV1::decode(&vec![0; REQUEST_MAX_BYTES + 1], &scheme).is_err());
    let mut wallet = prepared_wallet();
    for action in [
        OperationActionV1::Unload {
            amount: 0,
            charge: None,
        },
        OperationActionV1::Send {
            request: vec![0; 10_001],
        },
        OperationActionV1::Load {
            receipt: vec![],
            finality: vec![],
        },
    ] {
        assert!(
            wallet
                .execute(OperationRequestV1 {
                    request_id: [72; 32],
                    action
                })
                .is_err()
        );
    }
    assert_eq!(
        wallet.manifest().unwrap().1.preparations,
        IndexRoot::default()
    );
    assert_eq!(wallet.proofs.preparations.load(Ordering::SeqCst), 0);
    assert_eq!(wallet.custody.signatures, 1);
}

#[test]
fn uncommitted_preparation_and_irreversible_pending_have_distinct_statuses() {
    let mut wallet = prepared_wallet();
    assert_eq!(
        wallet.retry_request(&request().request_id).unwrap(),
        RequestStatusV1::Unknown
    );
    wallet.proofs.fail_preparation_proof = true;
    assert!(wallet.execute(request()).is_err());
    assert_eq!(
        wallet.retry_request(&request().request_id).unwrap(),
        RequestStatusV1::Preparing
    );
    wallet.proofs.fail_preparation_proof = false;
    wallet.custody.pause = true;
    assert_eq!(wallet.execute(request()).unwrap(), Completion::Pending);
    assert_eq!(
        wallet.retry_request(&request().request_id).unwrap(),
        RequestStatusV1::Outcome(Completion::Pending)
    );
    let proofs = wallet.proofs.preparation_proofs.load(Ordering::SeqCst);
    assert_eq!(wallet.execute(request()).unwrap(), Completion::Pending);
    assert_eq!(
        wallet.proofs.preparation_proofs.load(Ordering::SeqCst),
        proofs
    );
    assert_eq!(wallet.custody.signatures, 1);
}

#[test]
fn source_rotation_does_not_rebase_a_durable_plan_or_repeat_proving() {
    let mut wallet = prepared_wallet();
    wallet.proofs.fail_preparation_proof = true;
    assert!(wallet.execute(request()).is_err());
    let previous = wallet.released_steps().unwrap().pop().unwrap();
    let fold = wallet.read_fold(&previous).unwrap().unwrap().record;
    let source = PreparationSourceV1 {
        released: &previous,
        folded: Some(&fold),
    };
    let (_, manifest) = wallet.manifest().unwrap();
    let (snapshot, map_state) = wallet
        .preparation_source_custody(&manifest, &previous, request().kind(), Some(&fold))
        .unwrap();
    let mut custody = PreparationCustodyV1::new(
        &mut wallet.archive,
        &snapshot,
        &map_state,
        request().kind(),
        None,
        manifest.issued_requests,
        manifest.direct_anchors,
        manifest.finality_epochs,
        manifest.blacklist.clone(),
    )
    .unwrap();
    let (plan, _) = wallet
        .proofs
        .plan_preparation(&NativeIntentV1::user(request()), &source, &mut custody)
        .unwrap();
    let mut other: FrozenTransition = archive::decode(&plan).unwrap();
    let mut body = other.capsule.body().clone();
    body.successor_state.core.state_nonce = field(91);
    rebind_frozen_successor(&mut other, body);
    wallet.commit(other).unwrap();
    let count = wallet.proofs.preparations.load(Ordering::SeqCst);
    wallet.proofs.fail_preparation_proof = false;
    assert_eq!(
        wallet.execute(request()).unwrap(),
        Completion::NotPerformed(NotPerformed::StaleHead)
    );
    assert_eq!(wallet.proofs.preparations.load(Ordering::SeqCst), count);
    assert_eq!(wallet.proofs.preparation_proofs.load(Ordering::SeqCst), 1);
    assert_eq!(wallet.custody.signatures, 2);
}

#[test]
fn freshness_after_durable_writes_rejects_without_advance_and_keeps_exact_preparation() {
    let mut wallet = prepared_wallet();
    wallet.proofs.capsule_writes = Some(Arc::clone(&wallet.archive.capsule_writes));
    wallet.proofs.expire_during_publication = true;
    assert!(matches!(
        wallet.execute(request()),
        Err(Error::Invalid("test controls expired during publication"))
    ));
    assert_eq!(wallet.custody.signatures, 1);
    assert_eq!(
        wallet.retry_request(&request().request_id).unwrap(),
        RequestStatusV1::Preparing
    );
    let proofs = wallet.proofs.preparation_proofs.load(Ordering::SeqCst);
    let mut wallet = restart(wallet);
    wallet.proofs.expire_during_publication = false;
    wallet.custody.pause = true;
    assert_eq!(wallet.execute(request()).unwrap(), Completion::Pending);
    assert_eq!(
        wallet.proofs.preparation_proofs.load(Ordering::SeqCst),
        proofs
    );
    let checks = wallet.proofs.advance_checks.load(Ordering::SeqCst);
    wallet.proofs.expire_during_publication = true;
    assert_eq!(wallet.execute(request()).unwrap(), Completion::Pending);
    assert_eq!(wallet.proofs.advance_checks.load(Ordering::SeqCst), checks);
    assert_eq!(wallet.custody.signatures, 1);
}

#[test]
fn prepared_capsule_keeps_exact_durable_plan_after_completion_and_restart() {
    let mut wallet = prepared_wallet();
    wallet.execute(request()).unwrap();
    let mut wallet = restart(wallet);
    let (_, manifest) = wallet.manifest().unwrap();
    let released = wallet
        .indexed_step(&manifest, manifest.indexed.unwrap())
        .unwrap();
    let plan = wallet
        .transition_preparation(&manifest, &released.frozen)
        .unwrap()
        .unwrap();
    assert_eq!(plan.request, NativeIntentV1::user(request()));
    assert_eq!(
        plan.source,
        released.frozen.capsule.body().predecessor_capsule_digest
    );
    let capsule = released.frozen.capsule.custody_digest();
    let bad = manifest
        .capsule_plans
        .set(&mut wallet.archive, capsule, &[7; 31])
        .unwrap();
    let mut changed = manifest;
    changed.capsule_plans = bad;
    assert!(matches!(
        wallet.transition_preparation(&changed, &released.frozen),
        Err(Error::WitnessLost("capsule plan address"))
    ));
}

#[test]
fn native_intent_is_canonical_and_does_not_decode_the_foreign_request_layout() {
    let scheme = wallet().proofs.ledger_scope().unwrap().0;
    let request = request();
    let intent = NativeIntentV1::user(request.clone());
    assert_eq!(intent.kind(), request.kind());
    assert_eq!(intent.request_id(), request.request_id);
    assert_eq!(intent.user_request(), Some(&request));
    assert!(intent.archive_request().is_none());
    assert!(intent.refresh().is_none());
    let bytes = archive::encode(&intent).unwrap();
    assert_eq!(NativeIntentV1::decode(&bytes, &scheme).unwrap(), intent);
    assert!(NativeIntentV1::decode(&archive::encode(&request).unwrap(), &scheme).is_err());
    assert!(NativeIntentV1::decode(&[bytes, vec![0]].concat(), &scheme).is_err());
    assert!(NativeIntentV1::decode(&vec![0; REQUEST_MAX_BYTES + 1], &scheme).is_err());
}

#[test]
fn model_intake_refusal_preserves_all_refresh_receive_and_unload_originals_before_preparation() {
    let scheme: KagemushaWalletSchemeV1 = fixture("KagemushaWalletSchemeV1");
    let credential: KagemushaWalletCredentialV1 = fixture("KagemushaWalletCredentialV1");
    // Intake validates canonical shape only. The empty set confers no issuer authority;
    // actual preparation must still authenticate every required signer and relation.
    let certificates =
        archive::encode(&KagemushaWalletCertificateSetV1::new(vec![]).unwrap()).unwrap();
    let payment: KagemushaWalletPaymentV1 = fixture("KagemushaWalletPaymentV1");
    let mut actions = vec![OperationActionV1::Receive {
        payment: payment.to_canonical_bytes().unwrap(),
        payer_credential: credential.to_canonical_bytes().unwrap(),
        certificates: certificates.clone(),
    }];
    use KagemushaWalletPolicyUpdateKindV1 as K;
    for (kind, update) in [
        (K::Credential, credential.to_canonical_bytes().unwrap()),
        (
            K::SchemePolicy,
            fixture::<KagemushaWalletSchemePolicyV1>("KagemushaWalletSchemePolicyV1")
                .to_canonical_bytes()
                .unwrap(),
        ),
        (
            K::TimeAnchor,
            fixture::<KagemushaWalletTimeAnchorV1>("KagemushaWalletTimeAnchorV1")
                .to_canonical_bytes()
                .unwrap(),
        ),
        (
            K::QuotaShare,
            fixture::<KagemushaWalletQuotaShareV1>("KagemushaWalletQuotaShareV1")
                .to_canonical_bytes()
                .unwrap(),
        ),
    ] {
        actions.push(OperationActionV1::Refresh {
            kind,
            update,
            certificates: certificates.clone(),
        });
    }
    actions.push(OperationActionV1::Unload {
        amount: 1,
        charge: Some(ChargeOriginalsV1 {
            quote: fixture::<KagemushaWalletChargeQuoteV1>("KagemushaWalletChargeQuoteV1")
                .to_canonical_bytes()
                .unwrap(),
            certificates,
        }),
    });
    for action in actions {
        let request = OperationRequestV1 {
            request_id: [73; 32],
            action,
        };
        request.validate(&scheme).unwrap();
        let exact = archive::encode(&request).unwrap();
        let mut w = wallet();
        // Resolve the mock ledger scope outside the constrained decoder. No fixture
        // construction or proof authority is introduced inside the observed read.
        w.proofs.ledger_scope = Some((scheme.clone(), "wallet-test-chain".into()));
        let root = w.manifest().unwrap().0;
        for limits in [
            norito::DecodeLimits::new(usize::MAX, 0, usize::MAX, usize::MAX, 64),
            norito::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, 0, 64),
        ] {
            let direct = norito::with_decode_limits_scope(limits, || request.validate(&scheme));
            assert!(matches!(direct, Err(Error::DecodeResource(ref cause))
                if cause.kind() == norito::core::DecodeLocalRefusalKind::EnclosingLimit));
            let public = norito::with_decode_limits_scope(limits, || w.execute(request.clone()));
            assert!(matches!(public, Err(Error::DecodeResource(ref cause))
                if cause.kind() == norito::core::DecodeLocalRefusalKind::EnclosingLimit));
            assert_eq!(archive::encode(&request).unwrap(), exact);
            assert_eq!(w.manifest().unwrap().0, root);
            assert_eq!(w.custody.signatures, 0);
            assert_eq!(w.proofs.preparations.load(Ordering::SeqCst), 0);
            assert_eq!(w.proofs.preparation_proofs.load(Ordering::SeqCst), 0);
            assert_eq!(
                OperationRequestV1::decode(&exact, &scheme).unwrap(),
                request
            );
        }
        let mut invalid = request;
        match &mut invalid.action {
            OperationActionV1::Receive { payment, .. } => *payment = vec![0],
            OperationActionV1::Refresh { update, .. } => *update = vec![0],
            OperationActionV1::Unload {
                charge: Some(charge),
                ..
            } => charge.quote = vec![0],
            _ => unreachable!(),
        }
        assert!(matches!(
            invalid.validate(&scheme),
            Err(Error::Invalid("G1 validation"))
        ));
    }
}

fn derivations(wallet: &Wallet) -> usize {
    wallet.proofs.derivations.load(Ordering::SeqCst)
}

#[test]
fn fresh_operation_derives_once_and_commit_derives_again_independently() {
    let mut wallet = prepared_wallet();
    let signatures = wallet.custody.signatures;
    let complete = wallet.execute(request()).unwrap();
    assert!(matches!(complete, Completion::Complete(_)));
    // The plan's derivation is proven; commit derives again. No replay, none in proving.
    assert_eq!(derivations(&wallet), 2);
    assert_eq!(wallet.proofs.preparations.load(Ordering::SeqCst), 1);
    assert_eq!(wallet.proofs.validations.load(Ordering::SeqCst), 0);
    assert_eq!(wallet.proofs.preparation_proofs.load(Ordering::SeqCst), 1);
    assert_eq!(
        *wallet.proofs.proof_origins.lock().unwrap(),
        [TestOriginV1::Plan]
    );
    assert_eq!(wallet.custody.signatures, signatures + 1);
    // Once Advance has selected the operation, retries derive nothing.
    let mut wallet = restart(wallet);
    assert_eq!(wallet.execute(request()).unwrap(), complete);
    assert_eq!(derivations(&wallet), 2);
    assert_eq!(wallet.custody.signatures, signatures + 1);
}

#[test]
fn held_plan_retry_validates_fresh_custody_once_and_proves_from_that_derivation() {
    let mut wallet = prepared_wallet();
    wallet.proofs.fail_preparation_proof = true;
    assert!(matches!(wallet.execute(request()), Err(Error::Proof(_))));
    assert_eq!(derivations(&wallet), 1);
    let signatures = wallet.custody.signatures;
    let mut wallet = restart(wallet);
    wallet.proofs.fail_preparation_proof = false;
    // Changed request bytes under the same identity conflict before any derivation.
    let changed = OperationRequestV1 {
        request_id: request().request_id,
        action: OperationActionV1::Unload {
            amount: 1,
            charge: None,
        },
    };
    assert!(matches!(
        wallet.execute(changed),
        Err(Error::OperationConflict)
    ));
    assert_eq!(derivations(&wallet), 1);
    assert!(matches!(
        wallet.execute(request()).unwrap(),
        Completion::Complete(_)
    ));
    assert_eq!(derivations(&wallet), 3, "validate and commit");
    assert_eq!(wallet.proofs.validations.load(Ordering::SeqCst), 1);
    assert_eq!(wallet.proofs.preparations.load(Ordering::SeqCst), 1);
    assert_eq!(
        *wallet.proofs.proof_origins.lock().unwrap(),
        [TestOriginV1::Plan, TestOriginV1::Validate]
    );
    assert_eq!(wallet.custody.signatures, signatures + 1);
}

#[test]
fn commit_derivation_refusal_never_advances_and_the_retained_capsule_resumes() {
    let mut wallet = prepared_wallet();
    let signatures = wallet.custody.signatures;
    wallet.proofs.fail_commit_derivation = true;
    assert!(matches!(
        wallet.execute(request()),
        Err(Error::Proof("injected commit derivation refusal"))
    ));
    assert_eq!(derivations(&wallet), 2);
    assert_eq!(wallet.proofs.preparation_proofs.load(Ordering::SeqCst), 1);
    assert_eq!(
        wallet.custody.signatures, signatures,
        "refused before Advance"
    );
    assert_eq!(
        wallet.retry_request(&request().request_id).unwrap(),
        RequestStatusV1::Preparing
    );
    let mut wallet = restart(wallet);
    wallet.proofs.fail_commit_derivation = false;
    assert!(matches!(
        wallet.execute(request()).unwrap(),
        Completion::Complete(_)
    ));
    // The capsule is already retained: validate and commit, nothing proven again.
    assert_eq!(derivations(&wallet), 4);
    assert_eq!(wallet.proofs.validations.load(Ordering::SeqCst), 1);
    assert_eq!(wallet.proofs.preparation_proofs.load(Ordering::SeqCst), 1);
    assert_eq!(wallet.custody.signatures, signatures + 1);
}

#[test]
fn retained_derivation_refuses_any_changed_archive_checkpoint_before_proving() {
    // A proof failure stops right after the pre-proof checkpoint read, which locates it.
    let mut reference = prepared_wallet();
    reference.proofs.fail_preparation_proof = true;
    reference.custody.checkpoint_calls = 0;
    assert!(matches!(reference.execute(request()), Err(Error::Proof(_))));
    let at = reference.custody.checkpoint_calls;
    let (_, selected) = reference.manifest().unwrap();
    let mutations: [fn(&mut manifest::Manifest); 9] = [
        |m| m.issued_requests.0[0] ^= 1,
        |m| m.direct_anchors.0[0] ^= 1,
        |m| m.finality_epochs.0[0] ^= 1,
        |m| m.capsule_sources.0[0] ^= 1,
        |m| m.folds.0[0] ^= 1,
        |m| m.fold_pending.0[0] ^= 1,
        |m| m.indexed = m.indexed.map(|sequence| sequence + 1),
        |m| m.capsule[0] ^= 1,
        // A foreign generation that keeps every root and the archive-indexed head.
        |m| m.finality_epoch = Some(m.finality_epoch.map_or(1, |epoch| epoch + 1)),
    ];
    for (case, mutate) in mutations.into_iter().enumerate() {
        let mut wallet = prepared_wallet();
        let signatures = wallet.custody.signatures;
        let mut changed = selected.clone();
        mutate(&mut changed);
        let bytes = archive::encode(&changed).unwrap();
        let digest =
            crate::kagemusha_wallet_advance_v1::kagemusha_wallet_archive_checkpoint_digest_v1(
                &bytes,
            );
        wallet.custody.checkpoint_calls = 0;
        wallet.custody.checkpoint_replacement = Some((at, (digest, bytes)));
        assert!(
            matches!(
                wallet.execute(request()),
                Err(Error::WitnessLost("retained derivation binding"))
            ),
            "case {case}"
        );
        assert_eq!(derivations(&wallet), 1, "case {case}: the plan only");
        assert_eq!(
            wallet.proofs.preparation_proofs.load(Ordering::SeqCst),
            0,
            "case {case}"
        );
        assert_eq!(wallet.custody.signatures, signatures, "case {case}");
        // Recovery never reuses a derivation: the retry validates fresh custody.
        wallet.custody.checkpoint_replacement = None;
        let mut wallet = restart(wallet);
        assert!(
            matches!(wallet.execute(request()).unwrap(), Completion::Complete(_)),
            "case {case}"
        );
        assert_eq!(derivations(&wallet), 3, "case {case}");
        assert_eq!(
            *wallet.proofs.proof_origins.lock().unwrap(),
            [TestOriginV1::Validate],
            "case {case}"
        );
        assert_eq!(wallet.custody.signatures, signatures + 1, "case {case}");
    }
}

#[test]
fn unsynced_head_move_after_the_binding_check_stops_at_the_final_source_check() {
    let mut wallet = prepared_wallet();
    wallet.proofs.fail_preparation_proof = true;
    assert!(matches!(wallet.execute(request()), Err(Error::Proof(_))));
    // Commit a genuine successor of the same source, then restore the earlier checkpoint
    // and marker: custody now holds an Advance that no archive checkpoint has indexed.
    let checkpoint = wallet.custody.checkpoint.clone();
    let status = wallet.custody.status.clone();
    let previous = wallet.released_steps().unwrap().pop().unwrap();
    let fold = wallet.read_fold(&previous).unwrap().unwrap().record;
    let source = PreparationSourceV1 {
        released: &previous,
        folded: Some(&fold),
    };
    let (_, manifest) = wallet.manifest().unwrap();
    let (snapshot, map_state) = wallet
        .preparation_source_custody(&manifest, &previous, request().kind(), Some(&fold))
        .unwrap();
    let mut custody = PreparationCustodyV1::new(
        &mut wallet.archive,
        &snapshot,
        &map_state,
        request().kind(),
        None,
        manifest.issued_requests,
        manifest.direct_anchors,
        manifest.finality_epochs,
        manifest.blacklist.clone(),
    )
    .unwrap();
    let (plan, _) = wallet
        .proofs
        .plan_preparation(&NativeIntentV1::user(request()), &source, &mut custody)
        .unwrap();
    let mut other: FrozenTransition = archive::decode(&plan).unwrap();
    let mut body = other.capsule.body().clone();
    // A different successor: the planned capsule already carries the fixture's field(92).
    body.successor_state.core.state_nonce = field(91);
    rebind_frozen_successor(&mut other, body);
    wallet.commit(other).unwrap();
    wallet.custody.moved_status = Some(wallet.custody.status.clone());
    wallet.custody.checkpoint = checkpoint;
    wallet.custody.status = status;
    let mut wallet = restart(wallet);
    // The head moves while proving, after the binding check passed.
    let armed = Arc::clone(&wallet.custody.move_head);
    wallet.proofs.prove_hook = Some(Arc::new(move || armed.store(true, Ordering::SeqCst)));
    wallet.proofs.fail_preparation_proof = false;
    let signatures = wallet.custody.signatures;
    let derived = derivations(&wallet);
    assert_eq!(
        wallet.execute(request()).unwrap(),
        Completion::NotPerformed(NotPerformed::StaleHead)
    );
    // Proving ran on the validated derivation; commit never derived or signed.
    assert_eq!(derivations(&wallet), derived + 1);
    assert_eq!(
        wallet.proofs.proof_origins.lock().unwrap().last(),
        Some(&TestOriginV1::Validate)
    );
    assert_eq!(wallet.custody.signatures, signatures);
}

#[test]
fn proven_successor_is_checked_on_durable_custody_before_capsule_publication() {
    let mut wallet = prepared_wallet();
    let previous = wallet.released_steps().unwrap().pop().unwrap();
    let fold = wallet.read_fold(&previous).unwrap().unwrap().record;
    let (_, manifest) = wallet.manifest().unwrap();
    let (snapshot, map_state) = wallet
        .preparation_source_custody(&manifest, &previous, request().kind(), Some(&fold))
        .unwrap();
    // The current credential original that the retained draft references.
    let credential = PreparationCustodyV1::new(
        &mut wallet.archive,
        &snapshot,
        &map_state,
        request().kind(),
        None,
        manifest.issued_requests,
        manifest.direct_anchors,
        manifest.finality_epochs,
        manifest.blacklist.clone(),
    )
    .unwrap()
    .original(crate::kagemusha_wallet_state_v1::PreparationOriginalV1::CurrentCredential)
    .unwrap()
    .unwrap();
    let key = object_digest(&credential);
    // Lost after the binding check and the read-back, while proving.
    let archive = wallet.archive.clone();
    wallet.proofs.prove_hook = Some(Arc::new(move || archive.hide_object(key)));
    let signatures = wallet.custody.signatures;
    let capsules = wallet.archive.capsule_writes.load(Ordering::SeqCst);
    assert!(matches!(
        wallet.execute(request()),
        Err(Error::WitnessLost("index object"))
    ));
    assert_eq!(wallet.proofs.preparation_proofs.load(Ordering::SeqCst), 1);
    assert_eq!(
        wallet.archive.capsule_writes.load(Ordering::SeqCst),
        capsules
    );
    assert_eq!(wallet.custody.signatures, signatures);
    assert_eq!(
        wallet.retry_request(&request().request_id).unwrap(),
        RequestStatusV1::Preparing,
        "no capsule was published"
    );
    wallet.archive.reveal_object(key);
    wallet.proofs.prove_hook = None;
    let mut wallet = restart(wallet);
    assert!(matches!(
        wallet.execute(request()).unwrap(),
        Completion::Complete(_)
    ));
    assert_eq!(wallet.custody.signatures, signatures + 1);
}

#[test]
fn every_crash_boundary_resumes_with_one_signature_exact_output_and_at_most_two_derivations() {
    let payload = vec![67_u8; 97];
    let object = object_digest(&payload);
    let capsule = {
        let mut reference = prepared_wallet();
        reference.proofs.preparation_payload = payload.clone();
        assert!(matches!(
            reference.execute(request()).unwrap(),
            Completion::Complete(_)
        ));
        reference
            .released_steps()
            .unwrap()
            .pop()
            .unwrap()
            .frozen
            .capsule
            .custody_digest()
    };
    for boundary in 0..12 {
        let mut wallet = prepared_wallet();
        wallet.proofs.preparation_payload = payload.clone();
        let calls = wallet.custody.publication_calls;
        match boundary {
            // Before and after the fixed request binding.
            0 | 1 => wallet.custody.fail_publication_at = Some((calls + 1, boundary == 1)),
            // Inside the read-back after plan publication.
            2 => wallet.archive.hide_object_once(object),
            // Staging cleanup.
            3 => wallet.archive.fail_remove = true,
            // During proving.
            4 => wallet.proofs.fail_preparation_proof = true,
            // Before and after the capsule put.
            5 | 6 => {
                *wallet.archive.fail_put.lock().unwrap() =
                    Some((ArchiveKey::Capsule(capsule), boundary == 6));
            }
            // Before and after the capsule publication.
            7 | 8 => wallet.custody.fail_publication_at = Some((calls + 3, boundary == 8)),
            // Inside commit, before Advance.
            9 => wallet.proofs.fail_commit_derivation = true,
            // Advance selected, receipt Pending.
            10 => wallet.custody.pause = true,
            // Released.
            _ => {}
        }
        let signatures = wallet.custody.signatures;
        let first = wallet.execute(request());
        match boundary {
            10 => assert_eq!(first.unwrap(), Completion::Pending),
            11 => assert!(matches!(first.unwrap(), Completion::Complete(_))),
            _ => assert!(first.is_err(), "boundary {boundary}"),
        }
        assert!(derivations(&wallet) <= 2, "boundary {boundary}");
        assert_eq!(
            wallet.custody.signatures,
            signatures + usize::from(boundary == 11),
            "boundary {boundary}"
        );
        wallet.archive.fail_remove = false;
        wallet.custody.pause = false;
        wallet.proofs.fail_preparation_proof = false;
        wallet.proofs.fail_commit_derivation = false;
        let mut wallet = restart(wallet);
        if boundary == 10 {
            let derived = derivations(&wallet);
            assert_eq!(wallet.execute(request()).unwrap(), Completion::Pending);
            assert!(matches!(
                wallet.resume().unwrap(),
                Some(Completion::Complete(_))
            ));
            assert_eq!(derivations(&wallet), derived);
        }
        let derived = derivations(&wallet);
        let result = wallet.execute(request()).unwrap();
        assert!(
            matches!(result, Completion::Complete(_)),
            "boundary {boundary}"
        );
        assert_eq!(
            derivations(&wallet) - derived,
            if boundary >= 10 { 0 } else { 2 },
            "boundary {boundary}"
        );
        assert_eq!(
            wallet.custody.signatures,
            signatures + 1,
            "boundary {boundary}"
        );
        assert_eq!(wallet.execute(request()).unwrap(), result);
        assert_eq!(wallet.custody.signatures, signatures + 1);
        assert!(
            !wallet
                .archive
                .records
                .lock()
                .unwrap()
                .contains_key(&ArchiveKey::PreparationDraft(request().request_id)),
            "boundary {boundary}"
        );
    }
}
