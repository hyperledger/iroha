//! Original sealed lane carriers survive certification, merge and stateful opening.

use super::*;
use crate::sumeragi::lanes::Admission;
use iroha_data_model::{
    ValidationFail,
    transaction::{
        error::TransactionRejectionReason,
        signed::{
            SealedTransactionCommitmentPayload, SealedTransactionReveal,
            SignedSealedTransactionCommitment, compute_sealed_transaction_commitment,
        },
    },
};

fn sealed_inputs(
    fixture: &Fixture,
    text: &str,
    salt: [u8; 32],
    after: u64,
    deadline: u64,
) -> (
    TransactionEntrypoint,
    TransactionEntrypoint,
    SignedTransaction,
) {
    let key = lane_user();
    let signed = fixture.log(&key, text, GENESIS_MS - 1);
    let digest =
        compute_sealed_transaction_commitment(&fixture.chain.network_id(), &signed, salt, deadline);
    let commitment =
        TransactionEntrypoint::SealedCommitment(SignedSealedTransactionCommitment::sign(
            SealedTransactionCommitmentPayload::new(
                fixture.chain.network_id(),
                signed.authority().clone(),
                digest,
                after,
                deadline,
                None,
            ),
            key.private_key(),
        ));
    let reveal = TransactionEntrypoint::SealedReveal(SealedTransactionReveal::new(
        digest,
        signed.clone(),
        salt,
    ));
    assert_ne!(reveal.hash(), signed.hash_as_entrypoint());
    (commitment, reveal, signed)
}

#[inline(never)]
fn assert_merged_source(
    fixture: &Fixture,
    height: u64,
    expected: &TransactionEntrypoint,
    rejection: Option<&str>,
) {
    let committed = fixture.chain.committed(height);
    let block = committed.block();
    let matches = block
        .external_entrypoints_slice()
        .iter()
        .enumerate()
        .filter(|(_, input)| input.hash() == expected.hash())
        .collect::<Vec<_>>();
    assert_eq!(
        matches.len(),
        1,
        "the exact sealed lane carrier survives certified merge"
    );
    let (index, actual) = matches[0];
    assert_eq!(actual, expected);
    assert_eq!(
        norito::encode_canonical(actual).unwrap(),
        norito::encode_canonical(expected).unwrap()
    );
    let (_, output) = block
        .network_output_at(u32::try_from(index).unwrap())
        .unwrap();
    match rejection {
        None => assert!(
            output.result.0.is_ok(),
            "original merged input: {:?}",
            output.result
        ),
        Some(reason) => assert!(
            matches!(&output.result.0,
            Err(TransactionRejectionReason::Validation(ValidationFail::NotPermitted(actual)))
                if actual == reason),
            "original typed refusal: {:?}",
            output.result
        ),
    }
    let context = block
        .execution_context()
        .unwrap()
        .external
        .iter()
        .find(|context| context.entrypoint_hash == expected.hash())
        .unwrap();
    let record = fixture.record();
    assert_eq!(
        context,
        &ExternalExecutionContext::new(expected.hash(), record.lane, record.dataspace)
    );
}

#[inline(never)]
fn assert_stored_source(fixture: &Fixture, height: u64, expected: &[TransactionEntrypoint]) {
    let record = fixture.record();
    let stored = fixture
        .stores
        .block(LANE, &record.incarnation, height)
        .unwrap()
        .unwrap();
    let batch = stored.batch.as_ref().unwrap();
    assert_eq!(batch.transactions, expected);
    assert_eq!(
        LaneBatch::from_payload(&batch.to_payload()).unwrap(),
        *batch
    );
    let anchors = GlobalAnchors::new(
        Arc::clone(fixture.chain.state()),
        Arc::new(AppliedWatch::new(
            fixture.chain.height(),
            Some(fixture.anchor(fixture.chain.height())),
        )),
    );
    let Admission::Valid(result) = super::super::super::admit(
        &record,
        &anchors,
        &super::super::super::LaneChainView::default(),
        &StatelessChecks::new(fixture.chain.network_id()),
        &super::super::super::lane_height_config(&record).unwrap(),
        &batch.to_payload(),
    )
    .unwrap() else {
        panic!("the original retained lane bytes remain admitted");
    };
    assert_eq!(
        result.tx_hashes,
        expected
            .iter()
            .map(TransactionEntrypoint::hash)
            .collect::<Vec<_>>()
    );
    assert_eq!(
        result.payload_bytes,
        u64::try_from(batch.to_payload().len()).unwrap()
    );
    assert_eq!(result.hash(), stored.result);
}

#[inline(never)]
fn assert_proposed_source(fixture: &Fixture, expected: &TransactionEntrypoint) {
    let proposal = fixture.chain.proposal(None, Vec::new());
    let expansion = expand(
        fixture.chain.state(),
        &proposal,
        &*fixture.stores,
        Duration::ZERO,
    )
    .unwrap();
    assert!(
        expansion
            .entrypoints
            .iter()
            .any(|entrypoint| entrypoint == expected),
        "certified lane merge retains the complete original entrypoint"
    );
    assert_eq!(expansion.source, proposal.hash());
    assert!(std::ptr::eq(
        expansion.state,
        &raw const **fixture.chain.state()
    ));
    assert_eq!(
        expansion
            .entrypoints
            .iter()
            .filter(|input| input.hash() == expected.hash())
            .count(),
        1
    );
}

#[test]
fn certified_merge_retains_sealed_carrier_and_enforces_original_salt_before_execution() {
    let mut fixture = Fixture::start();
    fixture.chain.commit(Vec::new());
    fixture.chain.commit(Vec::new());
    let (commitment, reveal, signed) =
        sealed_inputs(&fixture, "original lane reveal", [0x76; 32], 5, 9);
    fixture.certify_entrypoints(1, 3, vec![commitment.clone()]);
    assert_stored_source(&fixture, 1, std::slice::from_ref(&commitment));
    fixture.chain.commit(Vec::new());
    assert_merged_source(&fixture, 4, &commitment, None);
    assert!(
        !fixture
            .chain
            .state()
            .view()
            .has_entrypoint(signed.hash_as_entrypoint())
    );

    let mut wrong = reveal.clone();
    let TransactionEntrypoint::SealedReveal(ref mut opened) = wrong else {
        unreachable!()
    };
    opened.salt[0] ^= 1;
    assert_ne!(wrong.hash(), reveal.hash());
    fixture.certify_entrypoints(2, 4, vec![wrong.clone()]);
    assert_stored_source(&fixture, 2, std::slice::from_ref(&wrong));
    assert_proposed_source(&fixture, &wrong);
    fixture.chain.commit(Vec::new());
    assert_merged_source(
        &fixture,
        5,
        &wrong,
        Some("sealed transaction reveal does not match commitment"),
    );
    assert!(
        !fixture
            .chain
            .state()
            .view()
            .has_entrypoint(signed.hash_as_entrypoint()),
        "a refused carrier cannot commit the enclosed execution identity"
    );

    let external_alias = TransactionEntrypoint::External(signed.clone());
    fixture.certify_entrypoints(3, 5, vec![reveal.clone(), external_alias.clone()]);
    assert_stored_source(&fixture, 3, &[reveal.clone(), external_alias]);
    fixture.chain.commit(Vec::new());
    assert_merged_source(&fixture, 6, &reveal, None);
    assert_eq!(
        fixture.chain.committed(6).block().merged_entrypoint_count(),
        1
    );
    assert!(fixture.chain.state().view().has_entrypoint(reveal.hash()));
    assert!(
        fixture
            .chain
            .state()
            .view()
            .has_entrypoint(signed.hash_as_entrypoint())
    );
    // A fresh carrier around already executed signed work is filtered by the same
    // authenticated replay membership used by queue admission, never executed twice.
    let mut replay = reveal.clone();
    let TransactionEntrypoint::SealedReveal(ref mut opened) = replay else {
        unreachable!()
    };
    opened.salt[1] ^= 1;
    fixture.certify_entrypoints(4, 6, vec![replay.clone()]);
    fixture.chain.commit(Vec::new());
    assert_eq!(
        fixture.chain.committed(7).block().merged_entrypoint_count(),
        0
    );
    assert!(!fixture.chain.state().view().has_entrypoint(replay.hash()));
    assert_eq!(fixture.record().merged.height, 4);
}

#[test]
fn certified_merge_preserves_reveal_window_deadline_and_missing_commitment_refusals() {
    let mut fixture = Fixture::start();
    fixture.chain.commit(Vec::new());
    fixture.chain.commit(Vec::new());
    let (first, at_deadline, _) = sealed_inputs(&fixture, "deadline inclusive", [0x71; 32], 6, 7);
    let (second, expired, _) = sealed_inputs(&fixture, "expired original", [0x72; 32], 5, 6);
    fixture.certify_entrypoints(1, 3, vec![first.clone(), second.clone()]);
    fixture.chain.commit(Vec::new());
    assert_merged_source(&fixture, 4, &first, None);
    assert_merged_source(&fixture, 4, &second, None);
    let mut early = at_deadline.clone();
    let TransactionEntrypoint::SealedReveal(ref mut opened) = early else {
        unreachable!()
    };
    opened.salt[0] ^= 1;
    fixture.certify_entrypoints(2, 4, vec![early.clone()]);
    fixture.chain.commit(Vec::new());
    assert_merged_source(
        &fixture,
        5,
        &early,
        Some("sealed transaction reveal is too early: height 5, reveal_after_height 6"),
    );
    let (_, missing, _) = sealed_inputs(&fixture, "never committed", [0x73; 32], 5, 9);
    fixture.certify_entrypoints(3, 5, vec![missing.clone()]);
    fixture.chain.commit(Vec::new());
    assert_merged_source(
        &fixture,
        6,
        &missing,
        Some("sealed transaction commitment is not pending"),
    );
    fixture.certify_entrypoints(4, 6, vec![at_deadline.clone(), expired.clone()]);
    fixture.chain.commit(Vec::new());
    assert_merged_source(&fixture, 7, &at_deadline, None);
    assert_merged_source(
        &fixture,
        7,
        &expired,
        Some("sealed transaction reveal deadline 6 passed at height 7"),
    );
}

#[test]
fn merge_identity_index_preserves_first_admitted_work_without_rehashing_carriers() {
    let fixture = Fixture::start();
    let (first, reveal, signed) = sealed_inputs(&fixture, "identity bounds", [0x74; 32], 5, 9);
    let TransactionEntrypoint::SealedCommitment(original) = &first else {
        unreachable!()
    };
    let mut payload = original.payload().clone();
    payload.nonce = std::num::NonZeroU64::new(1);
    let second = TransactionEntrypoint::SealedCommitment(SignedSealedTransactionCommitment::sign(
        payload,
        lane_user().private_key(),
    ));
    assert_ne!(first.hash(), second.hash());
    let mut changed_reveal = reveal.clone();
    let TransactionEntrypoint::SealedReveal(ref mut opened) = changed_reveal else {
        unreachable!()
    };
    opened.salt[0] ^= 1;
    assert_ne!(changed_reveal.hash(), reveal.hash());
    let external = TransactionEntrypoint::External(signed);
    let candidates = vec![
        (LANE, first.clone()),
        (LANE, second.clone()),
        (LANE, reveal.clone()),
        (LANE, changed_reveal.clone()),
        (LANE, external.clone()),
    ];
    let budget = fixture.chain.state().ivm_execution_budget();
    let before = budget.reserved_bytes();
    let rows = std::alloc::Layout::array::<(MergeWorkIdentity, bool)>(candidates.len()).unwrap();
    let cached = std::alloc::Layout::array::<MergeCandidateIdentity>(candidates.len()).unwrap();
    let demand = rows.size().checked_add(cached.size()).unwrap();
    let mut index = MergeIdentityIndex::new(&[], &candidates, &budget).unwrap();
    assert_eq!(budget.reserved_bytes(), before + demand);
    for (row, (_, expected)) in index.candidates.as_slice().iter().zip(&candidates) {
        assert_eq!(row.carrier, expected.hash());
        assert_eq!(row.work, MergeWorkIdentity::of(expected));
        assert_eq!(
            row.replay_alias,
            match expected {
                TransactionEntrypoint::SealedReveal(reveal) =>
                    Some(reveal.signed_transaction().hash_as_entrypoint()),
                TransactionEntrypoint::External(_) | TransactionEntrypoint::SealedCommitment(_) =>
                    None,
            }
        );
    }
    // A statelessly refused candidate never marks its identity. The first admitted
    // envelope wins independently of differing outer hashes; all later aliases lose.
    assert!(index.admit(MergeWorkIdentity::of(&second)));
    assert!(!index.admit(MergeWorkIdentity::of(&first)));
    assert!(index.admit(MergeWorkIdentity::of(&changed_reveal)));
    assert!(!index.admit(MergeWorkIdentity::of(&reveal)));
    assert!(!index.admit(MergeWorkIdentity::of(&external)));
    drop(index);
    assert_eq!(budget.reserved_bytes(), before);
    for prefix in [external, reveal] {
        let mut index =
            MergeIdentityIndex::new(std::slice::from_ref(&prefix), &candidates, &budget).unwrap();
        assert!(!index.admit(MergeWorkIdentity::of(&changed_reveal)));
        assert!(index.admit(MergeWorkIdentity::of(&first)));
    }
    assert_eq!(budget.reserved_bytes(), before);
}

#[test]
fn funded_merge_index_refuses_one_short_retries_same_source_and_releases_after_state_reads() {
    use std::{
        alloc::Layout,
        sync::atomic::{AtomicUsize, Ordering},
        task::{Context, Wake, Waker},
    };
    struct Probe {
        state: Arc<State>,
        calls: AtomicUsize,
        blocked: AtomicUsize,
    }
    impl Wake for Probe {
        fn wake(self: Arc<Self>) {
            self.wake_by_ref();
        }
        fn wake_by_ref(self: &Arc<Self>) {
            let free = self.state.crypto.try_write().is_some()
                && self.state.nexus.try_write().is_some()
                && self.state.lane_manifests.try_write().is_some();
            self.blocked.fetch_add(usize::from(!free), Ordering::SeqCst);
            self.calls.fetch_add(1, Ordering::SeqCst);
        }
    }
    // The genuine authenticated source read owns a larger, short-lived frame
    // allocation than merge scratch. Arm the scratch limit only after that read
    // has completed, on the same original pool. Retain its separate notifications
    // so only partial/successful scratch refunds can wake the probes below.
    struct AtScratch<'a> {
        stores: &'a crate::sumeragi::lanes::registry::LaneStores,
        budget: &'a iroha_allocation::AllocationBudget,
        before: usize,
        available: usize,
        registration: std::sync::Mutex<&'a mut iroha_allocation::release::ReleaseRegistration>,
        probe: Arc<Probe>,
        source_refunds: std::sync::Mutex<iroha_allocation::AllocationRefundBatch>,
        reads: AtomicUsize,
    }
    impl LaneBlockSource for AtScratch<'_> {
        fn tip(
            &self,
            lane: LaneId,
            incarnation: &[u8; 32],
        ) -> Result<Option<u64>, crate::execution_attempt::ExecutionAttemptError<std::io::Error>>
        {
            self.stores.tip(lane, incarnation)
        }

        fn block(
            &self,
            lane: LaneId,
            incarnation: &[u8; 32],
            height: u64,
        ) -> Result<
            Option<CommittedLaneBlock>,
            crate::execution_attempt::ExecutionAttemptError<std::io::Error>,
        > {
            let block = self
                .source_refunds
                .lock()
                .unwrap()
                .with_scope(|_| self.stores.block(lane, incarnation, height))?;
            assert!(
                block.is_some(),
                "the actual certified lane source is available"
            );
            assert_eq!(self.reads.fetch_add(1, Ordering::SeqCst), 0);
            assert_eq!(self.budget.reserved_bytes(), self.before);
            self.budget
                .set_limit_bytes(self.before.checked_add(self.available).unwrap());
            let waiting = self
                .budget
                .try_reserve(Layout::array::<u8>(self.available.checked_add(1).unwrap()).unwrap())
                .expect_err("the same original pool cannot exceed the exact scratch allowance");
            let iroha_allocation::AllocationRefusal::Capacity { release: wait, .. } = waiting
            else {
                panic!("original merge scratch pool capacity wait");
            };
            assert!(
                self.registration
                    .lock()
                    .unwrap()
                    .poll_wait(
                        &wait,
                        &mut Context::from_waker(&Waker::from(Arc::clone(&self.probe)))
                    )
                    .is_pending()
            );
            Ok(block)
        }

        fn wait_for(
            &self,
            lane: LaneId,
            incarnation: &[u8; 32],
            height: u64,
            timeout: Duration,
        ) -> Result<bool, crate::execution_attempt::ExecutionAttemptError<std::io::Error>> {
            self.stores.wait_for(lane, incarnation, height, timeout)
        }
    }
    let mut fixture = Fixture::start();
    fixture.chain.commit(Vec::new());
    fixture.chain.commit(Vec::new());
    let (commitment, _, _) = sealed_inputs(&fixture, "funded original", [0x75; 32], 5, 9);
    fixture.certify_entrypoints(1, 3, vec![commitment.clone()]);
    let proposal = fixture.chain.proposal(None, Vec::new());
    let original = proposal.canonical_wire().unwrap();
    drop(
        expand(
            fixture.chain.state(),
            &proposal,
            &*fixture.stores,
            Duration::ZERO,
        )
        .unwrap(),
    );
    let budget = fixture.chain.state().ivm_execution_budget();
    let mut registration = crate::unit_test_support::release_registration(&budget);
    let mut failure_registration = crate::unit_test_support::release_registration(&budget);
    let before = budget.reserved_bytes();
    let ceiling = budget.limit_bytes();
    let count = proposal.external_entrypoints_slice().len() + 1;
    let rows = Layout::array::<(MergeWorkIdentity, bool)>(count).unwrap();
    let cached = Layout::array::<MergeCandidateIdentity>(1).unwrap();
    let demand = rows.size().checked_add(cached.size()).unwrap();
    let failure_probe = Arc::new(Probe {
        state: Arc::clone(fixture.chain.state()),
        calls: AtomicUsize::new(0),
        blocked: AtomicUsize::new(0),
    });
    let failure_source = AtScratch {
        stores: &fixture.stores,
        budget: &budget,
        before,
        available: demand - 1,
        registration: std::sync::Mutex::new(&mut failure_registration),
        probe: Arc::clone(&failure_probe),
        source_refunds: std::sync::Mutex::new(budget.deferred_refund_batch()),
        reads: AtomicUsize::new(0),
    };
    let error = expand(
        fixture.chain.state(),
        &proposal,
        &failure_source,
        Duration::ZERO,
    )
    .expect_err("one byte short must refuse actual merge scratch");
    let MergeError::ResourceDeferred(original_refusal) = error else {
        panic!("the exact merge scratch owns the refusal: {error:?}");
    };
    assert!(matches!(
        original_refusal.allocation_refusal(),
        Some(iroha_allocation::AllocationRefusal::Capacity { .. })
    ));
    let Some(iroha_allocation::AllocationRefusal::Capacity {
        requested_bytes,
        reserved_bytes,
        limit_bytes,
        ..
    }) = original_refusal.allocation_refusal()
    else {
        unreachable!("original capacity refusal checked above")
    };
    assert_eq!(*requested_bytes, cached.size());
    assert_eq!(*reserved_bytes, before + rows.size());
    assert_eq!(*limit_bytes, before + demand - 1);
    assert_eq!(failure_source.reads.load(Ordering::SeqCst), 1);
    assert_eq!(budget.reserved_bytes(), before);
    assert_eq!(
        proposal.canonical_wire().unwrap().as_framed(),
        original.as_framed()
    );
    assert_eq!(fixture.record().merged.height, 0);
    assert!(failure_probe.calls.load(Ordering::SeqCst) > 0);
    assert_eq!(
        failure_probe.blocked.load(Ordering::SeqCst),
        0,
        "partial merge scratch refunds follow the actual State reader scopes"
    );
    drop(failure_source);
    // Restore the original read allowance before retrying that same source.
    budget.set_limit_bytes(ceiling);
    let probe = Arc::new(Probe {
        state: Arc::clone(fixture.chain.state()),
        calls: AtomicUsize::new(0),
        blocked: AtomicUsize::new(0),
    });
    let source = AtScratch {
        stores: &fixture.stores,
        budget: &budget,
        before,
        available: demand,
        registration: std::sync::Mutex::new(&mut registration),
        probe: Arc::clone(&probe),
        source_refunds: std::sync::Mutex::new(budget.deferred_refund_batch()),
        reads: AtomicUsize::new(0),
    };
    let expansion = expand(fixture.chain.state(), &proposal, &source, Duration::ZERO).unwrap();
    assert_eq!(source.reads.load(Ordering::SeqCst), 1);
    assert_eq!(expansion.entrypoints, vec![commitment]);
    assert_eq!(expansion.source, proposal.hash());
    assert_eq!(
        proposal.canonical_wire().unwrap().as_framed(),
        original.as_framed()
    );
    assert_eq!(budget.reserved_bytes(), before);
    assert!(probe.calls.load(Ordering::SeqCst) > 0);
    assert_eq!(
        probe.blocked.load(Ordering::SeqCst),
        0,
        "merge scratch refunds follow the actual State reader scopes"
    );
    drop(expansion);
    drop(source);
    budget.set_limit_bytes(ceiling);
    fixture.chain.commit(Vec::new());
    assert_eq!(fixture.record().merged.height, 1);
}

#[test]
fn certified_merge_drops_commitment_height_equality_and_later_digest_aliases() {
    let mut fixture = Fixture::start();
    fixture.chain.commit(Vec::new());
    fixture.chain.commit(Vec::new());
    let (equal, _, _) = sealed_inputs(&fixture, "height boundary", [0x77; 32], 4, 9);
    let TransactionEntrypoint::SealedCommitment(original) = &equal else {
        unreachable!()
    };
    let mut payload = original.payload().clone();
    payload.reveal_after_height = 5;
    let admitted = TransactionEntrypoint::SealedCommitment(
        SignedSealedTransactionCommitment::sign(payload.clone(), lane_user().private_key()),
    );
    payload.nonce = std::num::NonZeroU64::new(1);
    let later = TransactionEntrypoint::SealedCommitment(SignedSealedTransactionCommitment::sign(
        payload,
        lane_user().private_key(),
    ));
    assert_ne!(equal.hash(), admitted.hash());
    assert_ne!(later.hash(), admitted.hash());
    fixture.certify_entrypoints(1, 3, vec![equal.clone(), admitted.clone(), later.clone()]);
    fixture.chain.commit(Vec::new());
    assert_merged_source(&fixture, 4, &admitted, None);
    assert_eq!(
        fixture.chain.committed(4).block().merged_entrypoint_count(),
        1
    );
    assert!(!fixture.chain.state().view().has_entrypoint(equal.hash()));
    assert!(!fixture.chain.state().view().has_entrypoint(later.hash()));
    assert_eq!(fixture.record().merged.height, 1);
}

#[test]
fn certified_merge_respects_global_external_and_reveal_prefix_execution_aliases() {
    for prefix_reveals in [false, true] {
        let mut fixture = Fixture::start();
        fixture.chain.commit(Vec::new());
        fixture.chain.commit(Vec::new());
        let (commitment, reveal, signed) =
            sealed_inputs(&fixture, "prefix alias", [0x78; 32], 5, 9);
        fixture.certify_entrypoints(1, 3, vec![commitment]);
        fixture.chain.commit(Vec::new());
        let external = TransactionEntrypoint::External(signed);
        let (prefix, candidate) = if prefix_reveals {
            (reveal.clone(), external.clone())
        } else {
            (external.clone(), reveal.clone())
        };
        assert_ne!(prefix.hash(), candidate.hash());
        fixture.certify_entrypoints(2, 4, vec![candidate.clone()]);
        let committed = fixture.chain.commit_entrypoints(vec![prefix.clone()]);
        assert_eq!(committed.block().merged_entrypoint_count(), 0);
        assert_eq!(committed.block().external_entrypoints_slice(), &[prefix]);
        assert!(
            committed
                .block()
                .network_output_at(0)
                .unwrap()
                .1
                .result
                .is_ok()
        );
        assert!(fixture.chain.state().view().has_entrypoint(external.hash()));
        if !prefix_reveals {
            assert!(
                !fixture
                    .chain
                    .state()
                    .view()
                    .has_entrypoint(candidate.hash())
            );
        }
        assert_eq!(fixture.record().merged.height, 2);
    }
}

#[test]
fn native_lane_stateless_checks_require_each_carriers_original_network_and_signature() {
    use crate::sumeragi::lanes::{AdmissionAttemptError, AdmissionError, TransactionCheck};
    use iroha_crypto::SignatureOf;
    use iroha_data_model::transaction::TransactionSignature;

    let mut fixture = Fixture::start();
    fixture.chain.commit(Vec::new());
    fixture.chain.commit(Vec::new());
    let (commitment, reveal, signed) =
        sealed_inputs(&fixture, "intrinsic source", [0x79; 32], 5, 9);
    let external = TransactionEntrypoint::External(signed.clone());
    let record = fixture.record();
    let config = super::super::super::lane_height_config(&record).unwrap();
    let anchors = GlobalAnchors::new(
        Arc::clone(fixture.chain.state()),
        Arc::new(AppliedWatch::new(3, Some(fixture.anchor(3)))),
    );
    let checks = StatelessChecks::new(fixture.chain.network_id());
    let foreign_checks = StatelessChecks::new(crate::unit_test_support::synthetic_network_id(
        "foreign lane intrinsic network",
    ));
    let bad_key = KeyPair::from_seed(vec![0x79; 32], Algorithm::Ed25519);
    assert_ne!(bad_key.public_key(), lane_user().public_key());
    let mut invalid_signed = signed.clone();
    invalid_signed.set_signature(TransactionSignature(SignatureOf::new(
        bad_key.private_key(),
        signed.payload(),
    )));
    assert!(invalid_signed.verify_signature().is_err());
    let TransactionEntrypoint::SealedCommitment(original) = &commitment else {
        unreachable!()
    };
    let invalid_commitment =
        SignedSealedTransactionCommitment::sign(original.payload().clone(), bad_key.private_key());
    assert!(invalid_commitment.verify_signature().is_err());
    let TransactionEntrypoint::SealedReveal(original_reveal) = &reveal else {
        unreachable!()
    };
    let invalid_reveal = SealedTransactionReveal::new(
        original_reveal.commitment,
        invalid_signed.clone(),
        original_reveal.salt,
    );
    let cases = [
        (external, TransactionEntrypoint::External(invalid_signed)),
        (
            commitment,
            TransactionEntrypoint::SealedCommitment(invalid_commitment),
        ),
        (reveal, TransactionEntrypoint::SealedReveal(invalid_reveal)),
    ];
    for (original, invalid) in cases {
        let original_bytes = norito::encode_canonical(&original).unwrap();
        assert_eq!(checks.check(&original, 0), Ok(()));
        assert_eq!(
            foreign_checks.check(&original, 0),
            Err("the transaction belongs to another network".to_owned())
        );
        let original_signature_error = match &invalid {
            TransactionEntrypoint::External(signed) => {
                signed.verify_signature().unwrap_err().to_string()
            }
            TransactionEntrypoint::SealedReveal(reveal) => reveal
                .signed_transaction()
                .verify_signature()
                .unwrap_err()
                .to_string(),
            TransactionEntrypoint::SealedCommitment(commitment) => {
                commitment.verify_signature().unwrap_err().to_string()
            }
        };
        assert_eq!(
            checks.check(&invalid, 0),
            Err(original_signature_error.clone())
        );
        let batch = |entrypoint| {
            LaneBatch {
                anchor_height: 3,
                anchor_hash: fixture.anchor(3),
                transactions: vec![entrypoint],
            }
            .to_payload()
        };
        let history = super::super::super::LaneChainView::default();
        let admitted = super::super::super::admit(
            &record,
            &anchors,
            &history,
            &checks,
            &config,
            &batch(original.clone()),
        )
        .unwrap();
        let Admission::Valid(result) = admitted else {
            panic!("original carrier is admitted")
        };
        assert_eq!(result.tx_hashes, vec![original.hash()]);
        for (carrier, verifier, reason) in [
            (
                original.clone(),
                &foreign_checks,
                "the transaction belongs to another network".to_owned(),
            ),
            (invalid, &checks, original_signature_error),
        ] {
            assert!(matches!(
                super::super::super::admit(&record, &anchors, &history, verifier, &config, &batch(carrier)),
                Err(AdmissionAttemptError::Rejected(AdmissionError::Transaction { index: 0, reason: actual }))
                    if actual == reason
            ));
        }
        assert_eq!(norito::encode_canonical(&original).unwrap(), original_bytes);
        assert_eq!(checks.check(&original, 0), Ok(()));
        assert_eq!(fixture.record().merged.height, 0);
    }
}

#[test]
fn current_lane_batch_codec_preserves_all_carriers_and_rejects_flat_signed_rows() {
    use crate::sumeragi::lanes::{AdmissionAttemptError, AdmissionError};
    use norito::codec::Encode;

    // Encode only the replaced input shape to prove it cannot enter the one
    // production decoder. There is no alternate parser or compatibility path.
    #[derive(Encode)]
    struct FlatSignedRows {
        anchor_height: u64,
        anchor_hash: HashOf<iroha_data_model::block::BlockHeader>,
        transactions: Vec<SignedTransaction>,
    }
    let fixture = Fixture::start();
    let (commitment, reveal, signed) =
        sealed_inputs(&fixture, "closed carrier codec", [0x7A; 32], 5, 9);
    let batch = LaneBatch {
        anchor_height: 1,
        anchor_hash: fixture.anchor(1),
        transactions: vec![
            TransactionEntrypoint::External(signed.clone()),
            commitment,
            reveal,
        ],
    };
    let bytes = batch.to_payload();
    let original = (bytes.as_ptr(), bytes.len(), bytes.capacity());
    let decoded = LaneBatch::from_payload(&bytes).unwrap();
    assert_eq!(decoded, batch);
    assert_eq!(decoded.to_payload(), bytes);
    assert_eq!(
        decoded
            .transactions
            .iter()
            .map(TransactionEntrypoint::hash)
            .collect::<Vec<_>>(),
        batch
            .transactions
            .iter()
            .map(TransactionEntrypoint::hash)
            .collect::<Vec<_>>()
    );
    let flat = FlatSignedRows {
        anchor_height: batch.anchor_height,
        anchor_hash: batch.anchor_hash,
        transactions: vec![signed],
    }
    .encode();
    let mut trailing = bytes.clone();
    trailing.push(0);
    for malformed in [
        &flat[..],
        &bytes[..0],
        &bytes[..bytes.len() - 1],
        &trailing[..],
    ] {
        assert!(matches!(
            LaneBatch::from_payload(malformed),
            Err(AdmissionAttemptError::Rejected(AdmissionError::Encoding(_)))
        ));
    }
    assert_eq!((bytes.as_ptr(), bytes.len(), bytes.capacity()), original);
    assert_eq!(LaneBatch::from_payload(&bytes).unwrap(), batch);
}
