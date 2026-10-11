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
        let c = &mut retiring.capsule;
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
            || prepared.capsule.predecessor_capsule_digest
                != source.released().frozen.capsule.capsule_digest().unwrap()
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
    other.capsule.successor_state.core.state_nonce = field(91);
    rebind_frozen_successor(&mut other);
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
        released.frozen.capsule.predecessor_capsule_digest
    );
    let capsule = released.frozen.capsule.capsule_digest().unwrap();
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
