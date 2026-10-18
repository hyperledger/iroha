//! Business Decision suppression never fabricates an outcome for its exact expiry carrier.
//!
//! The existing native BLS fixture authenticates synthetic successful/rejected carrier
//! outputs; actual business Decision discovery is covered by the Core source reader tests.

use super::*;
use iroha::workflow::{
    FileWorkflowStorage, TransactionInputV1, TransactionStateV1, WorkflowClock, WorkflowEngine,
    WorkflowJournalV1, WorkflowKindV1, WorkflowPlanV1, WorkflowStorage,
};
use std::{sync::atomic::AtomicU64, time::Duration};

struct ReadOnlyAccount;
impl WorkflowAccount for ReadOnlyAccount {
    fn binding(&self) -> WorkflowBindingV1 {
        WorkflowBindingV1 {
            network: "exact-expiry-fixture".into(),
            authority: "exact-relay-fixture".into(),
        }
    }
    fn sign<'a>(
        &'a self,
        _: &'a [u8],
    ) -> WorkflowFuture<'a, Result<SignedStepTransaction, StepFailure>> {
        panic!("independently decided obligation cannot sign another carrier")
    }
    fn identify(&self, bytes: &[u8]) -> Result<TransactionIdentityV1, StepFailure> {
        let tx = SignedTransaction::decode_all_versioned(bytes).unwrap();
        tx.verify_signature().unwrap();
        Ok(TransactionIdentityV1 {
            signed_transaction_hash: *Hash::from(tx.hash()).as_ref(),
            entrypoint_hash: *Hash::from(tx.hash_as_entrypoint()).as_ref(),
        })
    }
}
#[derive(Default)]
struct Clock(AtomicU64);
impl WorkflowClock for Clock {
    fn now_unix_ms(&self) -> u64 {
        self.0.load(Ordering::Relaxed)
    }
    fn sleep(&self, duration: Duration) -> WorkflowFuture<'_, ()> {
        Box::pin(async move {
            let millis = u64::try_from(duration.as_millis())
                .expect("fixture sleep duration fits u64 milliseconds");
            self.0.fetch_add(millis, Ordering::Relaxed);
        })
    }
}

#[tokio::test]
async fn independently_decided_expiry_recovers_only_the_existing_exact_carrier_without_dispatch() {
    for state in [
        "never_started",
        "unsigned",
        "unknown",
        "applied",
        "rejected",
        "stale_completed",
    ] {
        let (ledger, identity, _) = super::proof_tests::fixture(state == "rejected");
        let proof = ledger
            .source
            .proof(NonZeroU64::new(2).unwrap())
            .await
            .unwrap();
        let block = iroha_data_model::block::decode_framed_signed_block(&proof.block_wire).unwrap();
        let transaction = block.external_transactions().next().unwrap();
        let bytes = transaction.encode_wire_v1().unwrap();
        let payload = norito::encode_canonical(transaction.payload()).unwrap();
        if matches!(state, "unknown" | "stale_completed") {
            // The exact original execution cannot currently be authenticated. Neither the
            // business Decision nor a decoded completed journal can replace that read.
            *ledger.instruction.lock().unwrap() = None;
        }
        let ledger = Arc::new(ledger);
        let account = Arc::new(ReadOnlyAccount);
        let directory = tempfile::tempdir().unwrap();
        let storage =
            Arc::new(FileWorkflowStorage::open_or_create(directory.path().join("expiry")).unwrap());
        let engine = WorkflowEngine::new(
            storage.clone(),
            account.clone(),
            ledger.clone(),
            Arc::new(Clock::default()),
        );
        let plan = WorkflowPlanV1 {
            kind: WorkflowKindV1::AmxRelay,
            instance: state.into(),
            driver: super::super::driver_identity(),
            request_context_digest: [55; 32],
            steps: vec![iroha::workflow::StepDescriptorV1::transaction(
                "relay", [55; 32],
            )],
        };
        let handle = engine.workflow(plan.clone()).unwrap();
        if state != "never_started" {
            let mut journal = WorkflowJournalV1::new(&plan, &account.binding(), 0).unwrap();
            journal.sequence = 1;
            for input in [
                TransactionInputV1::OpenAttempt,
                TransactionInputV1::BuildStarted,
                TransactionInputV1::PayloadBuilt { payload },
            ] {
                journal.apply_transaction(0, input).unwrap();
            }
            if state != "unsigned" {
                for input in [
                    TransactionInputV1::Signed {
                        signed_transaction: bytes,
                        identity,
                    },
                    TransactionInputV1::DispatchIntent {
                        retransmission_after_exact_absence: false,
                    },
                    TransactionInputV1::DispatchAmbiguous,
                ] {
                    journal.apply_transaction(0, input).unwrap();
                }
            }
            if state == "stale_completed" {
                journal
                    .apply_transaction(
                        0,
                        TransactionInputV1::ReconciledApplied {
                            block_height: Some(2),
                        },
                    )
                    .unwrap();
            }
            storage
                .compare_and_store(&handle.id(), None, &journal.encode_record().unwrap())
                .unwrap();
        }
        let result = super::super::expiry::recover_carrier(
            &engine,
            ledger.as_ref(),
            plan,
            Duration::from_millis(1),
        )
        .await;
        assert_eq!(
            result.is_ok(),
            matches!(state, "never_started" | "unsigned" | "applied" | "rejected"),
            "read-only carrier recovery must preserve independently authenticated outcomes: {state}"
        );
        if state == "never_started" {
            assert!(
                storage.load(&handle.id()).unwrap().is_none(),
                "a Decision must not create an expiry carrier journal which never started"
            );
            continue;
        }
        let record = storage.load(&handle.id()).unwrap().unwrap();
        let journal = WorkflowJournalV1::decode_record(&record).unwrap();
        let operation = journal.steps[0].transaction.as_ref().unwrap();
        let expected = match state {
            "unsigned" => TransactionStateV1::ReadyToSign,
            "unknown" => TransactionStateV1::OutcomeUnknown,
            "rejected" => TransactionStateV1::Rejected,
            "applied" | "stale_completed" => TransactionStateV1::Finalized,
            _ => unreachable!(),
        };
        assert_eq!(operation.state, expected, "{state}");
        assert_eq!(
            operation.attempts.len(),
            1,
            "business Decision cannot create a replacement identity"
        );
    }
}
