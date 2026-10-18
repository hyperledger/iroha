//! Typed dispatch and crash tests with explicit mock proofs; no artifact/provider admission.

use super::*;

impl NativePreparation for TestProofs {
    fn plan_preparation(
        &self,
        request: &NativeIntentV1,
        source: &PreparationSourceV1<'_>,
        _: &mut PreparationCustodyV1<'_>,
    ) -> Result<Vec<u8>, Error> {
        self.preparations.fetch_add(1, Ordering::SeqCst);
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
        archive::encode(&retiring)
    }

    fn validate_preparation(
        &self,
        request: &NativeIntentV1,
        source: &PreparationSourceV1<'_>,
        _: &mut PreparationCustodyV1<'_>,
        plan: &[u8],
    ) -> Result<(), Error> {
        let prepared: FrozenTransition = archive::decode(plan)?;
        prepared.validate()?;
        if request.user_request().map(|request| &request.action) != Some(&OperationActionV1::Retire)
            || prepared.capsule.body().predecessor_capsule_digest
                != source.released().frozen.capsule.custody_digest()
        {
            return Err(Error::Invalid("test plan binding"));
        }
        Ok(())
    }

    fn prove_preparation(
        &self,
        _: &NativeIntentV1,
        _: &PreparationSourceV1<'_>,
        _: &mut PreparationCustodyV1<'_>,
        plan: &[u8],
    ) -> Result<FrozenTransition, Error> {
        self.preparation_proofs.fetch_add(1, Ordering::SeqCst);
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
fn runtime_capacity_refuses_before_proving_with_typed_results_and_keeps_the_plan() {
    use crate::kagemusha_wallet_capacity_v1::{
        KagemushaWalletRuntimeCapacityV1, KagemushaWalletRuntimeResourcesV1,
    };
    use crate::kagemusha_wallet_state_v1::capacity::OPERATION_RESERVATION_BYTES;
    let mut wallet = prepared_wallet();
    let signatures = wallet.custody.signatures;
    wallet.proofs.capacity = KagemushaWalletRuntimeCapacityV1 {
        storage_bytes: 1_000,
        memory_bytes: 2_000,
    };
    let enough_storage = OPERATION_RESERVATION_BYTES + 1_000;
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
    // The durable plan stays: the request is still preparing, never performed or refused.
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
    assert_eq!(wallet.custody.resource_queries, queries + 2);
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
    )
    .unwrap();
    let plan = wallet
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
            K::Blacklist,
            fixture::<KagemushaWalletBlacklistV1>("KagemushaWalletBlacklistV1")
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
