//! Authenticated rejection replacement and bounded exhaustion through the existing journal.

use super::*;
use iroha::workflow::{
    BuiltStepPayload, DriverIdentityV1, FileWorkflowStorage, SignedStepTransaction, StepContext,
    StepDescriptorV1, StepFailure, WorkflowAccount, WorkflowBindingV1, WorkflowClock,
    WorkflowDriver, WorkflowEngine, WorkflowErrorCode, WorkflowKindV1, WorkflowPlanV1,
    WorkflowRunOptions,
};
use iroha_data_model::{
    executor::ValidationFail, sumeragi_finality::test_fixtures::NativeFinalityFixture,
    transaction::error::TransactionRejectionReason,
};
use std::{collections::BTreeMap, sync::atomic::AtomicU64, time::Duration};

struct RetrySource {
    proofs: BTreeMap<u64, SumeragiFinalityProof>,
    identities: Vec<TransactionIdentityV1>,
    sent: Arc<AtomicUsize>,
}
impl Source for RetrySource {
    fn locate(&self, hash: HashOf<SignedTransaction>) -> WorkflowFuture<'_, Result<Location>> {
        Box::pin(async move {
            Ok(self
                .identities
                .iter()
                .take(self.sent.load(Ordering::Relaxed))
                .position(|identity| &identity.signed_transaction_hash == Hash::from(hash).as_ref())
                .map_or(Location::Absent, |index| {
                    Location::Observed(Some(index as u64 + 2))
                }))
        })
    }
    fn proof(&self, height: NonZeroU64) -> WorkflowFuture<'_, Result<SumeragiFinalityProof>> {
        Box::pin(async move {
            self.proofs
                .get(&height.get())
                .cloned()
                .ok_or_else(|| eyre!("no unrelated successor exists"))
        })
    }
}
struct Account {
    transactions: Vec<SignedTransaction>,
    identities: Vec<TransactionIdentityV1>,
    signs: AtomicUsize,
    sent: Arc<AtomicUsize>,
}
impl WorkflowAccount for Account {
    fn binding(&self) -> WorkflowBindingV1 {
        WorkflowBindingV1 {
            network: "relay_retry_fixture".into(),
            authority: "relay_funder_fixture".into(),
        }
    }
    fn sign<'a>(
        &'a self,
        payload: &'a [u8],
    ) -> WorkflowFuture<'a, Result<SignedStepTransaction, StepFailure>> {
        Box::pin(async move {
            let index = self
                .transactions
                .iter()
                .position(|transaction| {
                    norito::encode_canonical(transaction.payload()).unwrap() == payload
                })
                .unwrap();
            assert_eq!(self.signs.fetch_add(1, Ordering::Relaxed), index);
            Ok(SignedStepTransaction {
                signed_transaction: self.transactions[index].encode_wire_v1().unwrap(),
                identity: self.identities[index],
            })
        })
    }
    fn identify(&self, bytes: &[u8]) -> Result<TransactionIdentityV1, StepFailure> {
        self.transactions
            .iter()
            .position(|transaction| transaction.encode_wire_v1().unwrap() == bytes)
            .map(|index| self.identities[index])
            .ok_or_else(|| {
                StepFailure::new(WorkflowErrorCode::BindingMismatch, "unknown fixture bytes")
            })
    }
}
impl WorkflowLedger for Account {
    fn dispatch<'a>(
        &'a self,
        bytes: &'a [u8],
        identity: &'a TransactionIdentityV1,
    ) -> WorkflowFuture<'a, DispatchOutcome> {
        Box::pin(async move {
            assert_eq!(self.identify(bytes).unwrap(), *identity);
            let index = self.sent.fetch_add(1, Ordering::Relaxed);
            assert_eq!(self.identities[index], *identity);
            DispatchOutcome::Accepted
        })
    }
    fn committed_outcome<'a>(
        &'a self,
        _: &'a TransactionIdentityV1,
    ) -> WorkflowFuture<'a, CommittedOutcome> {
        panic!("only proof-gated outcome adapter may decide")
    }
}
struct ReauthenticatedDriver {
    payload: Mutex<Option<Vec<u8>>>,
    ordinal: u8,
}
impl WorkflowDriver for ReauthenticatedDriver {
    fn identity(&self) -> DriverIdentityV1 {
        super::super::driver_identity()
    }
    fn build_transaction<'a>(
        &'a self,
        context: StepContext<'a>,
    ) -> WorkflowFuture<'a, Result<BuiltStepPayload, StepFailure>> {
        Box::pin(async move {
            // Like the production move-only intent, each acquisition prepares only one carrier.
            let payload = self.payload.lock().unwrap().take().ok_or_else(|| {
                StepFailure::new(
                    WorkflowErrorCode::LocalResourceUnavailable,
                    "requires the next authenticated source acquisition",
                )
            })?;
            assert_eq!(context.identity_ordinal, self.ordinal);
            Ok(BuiltStepPayload {
                intent_digest: context.descriptor.intent_digest,
                unsigned_payload: payload,
            })
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
            self.0.fetch_add(
                u64::try_from(duration.as_millis()).expect("fixture duration fits u64"),
                Ordering::Relaxed,
            );
        })
    }
}

async fn replacement_case(rejections: &[bool]) {
    let mut fixture = NativeFinalityFixture::start("relay-funded-replacement");
    let verifier = fixture.verifier();
    let mut proofs: BTreeMap<_, _> = [(1, fixture.genesis_proof().clone())].into();
    let mut transactions = Vec::new();
    for rejected in rejections {
        let mut block = fixture.block_with_submitted_work(fixture.next_header());
        transactions.push(block.external_transactions().next().unwrap().clone());
        if *rejected {
            NativeFinalityFixture::install_network_results(
                &mut block,
                vec![Err(TransactionRejectionReason::Validation(
                    ValidationFail::NotPermitted("fixture fee funding unavailable".into()),
                ))],
            );
        }
        let proof = fixture.certify(block);
        proofs.insert(proof.height(), proof);
    }
    let identities: Vec<_> = transactions
        .iter()
        .map(|transaction| TransactionIdentityV1 {
            signed_transaction_hash: *Hash::from(transaction.hash()).as_ref(),
            entrypoint_hash: *Hash::from(transaction.hash_as_entrypoint()).as_ref(),
        })
        .collect();
    let sent = Arc::new(AtomicUsize::new(0));
    let account = Arc::new(Account {
        transactions,
        identities: identities.clone(),
        signs: AtomicUsize::new(0),
        sent: sent.clone(),
    });
    let Executable::Instructions(instructions) = account.transactions[0].instructions() else {
        panic!("native fixture")
    };
    let digest = instruction_digest(&instructions[0]).unwrap();
    let ledger = Arc::new(RelayLedger {
        source: Arc::new(RetrySource {
            proofs,
            identities,
            sent,
        }),
        dispatch: account.clone(),
        verifier: Mutex::new(verifier),
        network: fixture.network_id(),
        authority: account.transactions[0].authority().clone(),
        fee_payment: account.transactions[0].fee_payment_intent().clone(),
        instruction: Mutex::new(None),
        max_reads: 8,
        reads: AtomicUsize::new(0),
    });
    let directory = tempfile::tempdir().unwrap();
    let storage =
        Arc::new(FileWorkflowStorage::open_or_create(directory.path().join("relay")).unwrap());
    let engine = WorkflowEngine::new(
        storage,
        account.clone(),
        ledger.clone(),
        Arc::new(Clock::default()),
    );
    let handle = engine
        .workflow(WorkflowPlanV1 {
            kind: WorkflowKindV1::AmxRelay,
            instance: "exact_source".into(),
            driver: super::super::driver_identity(),
            request_context_digest: [8; 32],
            steps: vec![
                StepDescriptorV1::transaction("relay", [8; 32])
                    .with_max_transaction_identities(super::super::MAX_CARRIER_IDENTITIES),
            ],
        })
        .unwrap();
    let options = WorkflowRunOptions {
        observation_timeout: Duration::from_millis(2),
        poll_interval: Duration::from_millis(1),
        retransmit_identical_bytes: true,
        retry_rejected_step: true,
    };
    for (index, rejected) in rejections.iter().enumerate() {
        ledger.begin_observation(digest).unwrap();
        let driver = ReauthenticatedDriver {
            payload: Mutex::new(Some(
                norito::encode_canonical(account.transactions[index].payload()).unwrap(),
            )),
            ordinal: u8::try_from(index).expect("fixture index fits u8") + 1,
        };
        let result = handle.run(&driver, &options).await;
        if *rejected {
            let error = result.unwrap_err();
            assert!(
                error
                    .progress
                    .unwrap()
                    .partial_completion
                    .confirmed_steps
                    .is_empty()
            );
        } else {
            assert_eq!(result.unwrap().partial_completion.confirmed_steps, vec![0]);
        }
        assert_eq!(account.signs.load(Ordering::Relaxed), index + 1);
    }
    assert!(
        account.signs.load(Ordering::Relaxed) <= usize::from(super::super::MAX_CARRIER_IDENTITIES)
    );
}

#[tokio::test]
async fn relay_authenticated_rejection_allows_funded_fresh_source_retry() {
    replacement_case(&[true, false]).await;
}

#[tokio::test]
async fn relay_replacement_bound_exhaustion_never_claims_delivery() {
    replacement_case(&[true, true, true]).await;
}
