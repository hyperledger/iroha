//! Staged actual customer workload for finite native committee ceremony heights.
//!
//! Every height-driving operation has one distinct owner-scoped monetary intent.
//! The existing workflow owns signing, exact-byte retries and durable recovery.

use std::{
    num::NonZeroU64,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use eyre::{Result, ensure, eyre};
use iroha::{
    blocking::Client,
    client::{NativePaymentRequest, NativePaymentRunOptions, VerifiedPaymentReceipt},
    workflow::{FileWorkflowStorage, WorkflowRunOptions},
};
use iroha_data_model::{
    account::AccountId,
    asset::{AssetDefinitionId, AssetId},
    isi::{AtomicSettlementMovement, AtomicSettlementMovements, SettleAtomic, SettlementId},
    sumeragi_finality::{
        SignedGenesisPinsV1, SumeragiFinalityVerifier, authenticate_signed_genesis_v1,
    },
    transaction::{FeeChargeKind, FeePaymentIntent},
};
use iroha_model_base::metadata::Metadata;
use iroha_primitives::numeric::Quantity;

/// An independently pinned, durable owner for the monetary workload used by the ceremony.
pub(super) struct CustomerWorkload {
    pins: SignedGenesisPinsV1,
    genesis: Vec<u8>,
    asset: AssetDefinitionId,
    recipient: AccountId,
    fee: FeePaymentIntent,
    directory: PathBuf,
    last_height: NonZeroU64,
    receipts: Mutex<Vec<VerifiedPaymentReceipt>>,
}
impl CustomerWorkload {
    pub(super) fn new(
        pins: SignedGenesisPinsV1,
        genesis: Vec<u8>,
        asset: AssetDefinitionId,
        recipient: AccountId,
        fee: FeePaymentIntent,
        directory: PathBuf,
        last_height: NonZeroU64,
    ) -> Result<Self> {
        authenticate_signed_genesis_v1(&genesis, &pins)?;
        Ok(Self {
            pins,
            genesis,
            asset,
            recipient,
            fee,
            directory,
            last_height,
            receipts: Mutex::new(Vec::new()),
        })
    }
    pub(super) async fn submit(
        &self,
        client: &Client,
        height: u64,
        deadline: Instant,
    ) -> Result<()> {
        let selected = authenticate_signed_genesis_v1(&self.genesis, &self.pins)?;
        let verifier = SumeragiFinalityVerifier::new(
            selected.block(),
            &self.pins.chain_id,
            selected.validators().to_vec(),
        )?;
        let receipt = customer_payment_at_height(
            client,
            self.recipient.clone(),
            self.asset.clone(),
            NonZeroU64::new(height).ok_or_else(|| eyre!("customer workload height is zero"))?,
            self.last_height,
            self.fee.clone(),
            &self.directory,
            verifier,
            deadline,
        )
        .await?;
        let mut receipts = self
            .receipts
            .lock()
            .map_err(|_| eyre!("customer receipt owner poisoned"))?;
        ensure!(
            receipts
                .iter()
                .all(|prior| prior.settlement_id() != receipt.settlement_id()),
            "one ceremony height cannot credit the customer twice"
        );
        receipts.push(receipt);
        Ok(())
    }
    pub(super) fn credited_units(&self) -> Result<Quantity> {
        let receipts = self
            .receipts
            .lock()
            .map_err(|_| eyre!("customer receipt owner poisoned"))?;
        ensure!(
            !receipts.is_empty(),
            "rotation must perform actual customer work"
        );
        Ok(Quantity::from(u64::try_from(receipts.len())?))
    }
}

/// Make precisely one customer payment at the ceremony's requested next height.
///
/// `verifier` must be reconstructed from the test's independent signed-genesis pins.
/// `deadline` is the original absolute phase deadline, shared by transport and task wait.
/// The caller must retain this original request/storage when its outcome is unknown.
pub(super) async fn customer_payment_at_height(
    client: &Client,
    recipient: AccountId,
    asset: AssetDefinitionId,
    target_height: NonZeroU64,
    last_workload_height: NonZeroU64,
    fee: FeePaymentIntent,
    directory: &Path,
    verifier: SumeragiFinalityVerifier,
    deadline: Instant,
) -> Result<VerifiedPaymentReceipt> {
    ensure!(
        Instant::now() < deadline,
        "original ceremony payment deadline exhausted"
    );
    ensure!(target_height <= last_workload_height);
    ensure!(
        fee.charge_limits()
            .iter()
            .all(|limit| limit.kind == FeeChargeKind::Nexus),
        "customer workload uses the committed Nexus-only fee policy supported by verified receipts"
    );
    let bounded = client.with_request_deadline(deadline)?;
    let account = bounded.account_client();
    let owner = account.authority().clone();
    ensure!(owner != recipient);
    let id = SettlementId::new(
        owner.clone(),
        format!("rotation-customer-{}", target_height.get()).parse()?,
    );
    let terms = SettleAtomic::new(
        *account.network_id(),
        id.clone(),
        AtomicSettlementMovements::try_from(vec![AtomicSettlementMovement {
            source: AssetId::of(asset, owner.clone()),
            recipient,
            quantity: Quantity::one(),
        }])
        .map_err(|error| eyre!(error))?,
        last_workload_height,
        Metadata::default(),
    );
    let operation = account.native_payment(
        NativePaymentRequest::new(terms, fee)?,
        Arc::new(FileWorkflowStorage::open_or_create(directory)?),
        verifier,
    )?;
    let completed = owned_payment_until(deadline, async move {
        let options = NativePaymentRunOptions {
            workflow: WorkflowRunOptions {
                observation_timeout: deadline.saturating_duration_since(Instant::now()),
                poll_interval: Duration::from_millis(150),
                ..WorkflowRunOptions::default()
            },
            // Every operation starts with independent signed-genesis trust. The
            // explicit workload horizon needs a larger finite local observation
            // budget than the SDK's short-history default, never a protocol limit.
            max_finality_proof_reads: std::num::NonZeroU16::new(u16::try_from(
                last_workload_height
                    .get()
                    .checked_add(2)
                    .ok_or_else(|| eyre!("workload proof bound overflow"))?,
            )?)
            .ok_or_else(|| eyre!("workload proof bound is zero"))?,
        };
        Ok(operation.submit(&options).await?)
    })
    .await?;
    ensure!(completed.receipt.settlement_id() == &id);
    ensure!(
        completed.receipt.settlement().block_height == target_height.get(),
        "customer workload must certify exactly the requested ceremony height"
    );
    let paid = completed
        .receipt
        .nexus_fee_receipt()
        .ok_or_else(|| eyre!("customer workload has no authenticated fee outcome"))?;
    ensure!(!paid.fee_amount.is_zero() && paid.block_height == target_height.get());
    ensure!(paid.debit_source == iroha_data_model::nexus::FeeDebitSource::Account(owner.clone()));
    Ok(completed.receipt)
}

/// Poll the owned SDK operation on a fresh default worker stack, retaining the
/// original phase deadline and cancellation ownership. JoinSet aborts its child
/// on timeout, unwinding, or cancellation of this enclosing future; a detached
/// JoinHandle would let a payment continue after its ceremony owner disappeared.
async fn owned_payment_until<T, F>(deadline: Instant, payment: F) -> Result<T>
where
    T: Send + 'static,
    F: std::future::Future<Output = Result<T>> + Send + 'static,
{
    let deadline = tokio::time::Instant::from_std(deadline);
    ensure!(
        tokio::time::Instant::now() < deadline,
        "original ceremony payment deadline exhausted"
    );
    let mut tasks = tokio::task::JoinSet::new();
    tasks.spawn(async move {
        ensure!(
            tokio::time::Instant::now() < deadline,
            "original ceremony payment deadline exhausted"
        );
        payment.await
    });
    let joined = match tokio::time::timeout_at(deadline, tasks.join_next()).await {
        Ok(joined) => joined,
        Err(_) => {
            tasks.abort_all();
            return Err(eyre!("original ceremony payment deadline exhausted"));
        }
    };
    let completed = joined
        .ok_or_else(|| eyre!("owned ceremony payment task disappeared"))?
        .map_err(|error| eyre!("owned ceremony payment task failed: {error}"))??;
    // Tokio polls the child result before its timer. Synchronous verification
    // must not turn an already elapsed original deadline into a late success.
    ensure!(
        tokio::time::Instant::now() < deadline,
        "original ceremony payment deadline exhausted"
    );
    Ok(completed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, Ordering};
    use tokio::sync::oneshot;

    struct Dropped(Option<oneshot::Sender<()>>);
    impl Drop for Dropped {
        fn drop(&mut self) {
            if let Some(sender) = self.0.take() {
                let _ = sender.send(());
            }
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn owned_payment_returns_exact_success_error_and_task_failure() {
        let deadline = Instant::now() + Duration::from_secs(5);
        assert_eq!(
            owned_payment_until(deadline, async { Ok(17_u64) })
                .await
                .unwrap(),
            17
        );
        let error = owned_payment_until::<(), _>(deadline, async {
            Err(eyre!("original verification failure"))
        })
        .await
        .unwrap_err();
        assert_eq!(error.to_string(), "original verification failure");
        let error = owned_payment_until::<(), _>(deadline, async { panic!("owned task panic") })
            .await
            .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("owned ceremony payment task failed")
        );
    }

    #[tokio::test]
    async fn expired_payment_deadline_never_polls_submission() {
        let polled = Arc::new(AtomicBool::new(false));
        let observed = polled.clone();
        let error = owned_payment_until(Instant::now(), async move {
            observed.store(true, Ordering::SeqCst);
            Ok(())
        })
        .await
        .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("original ceremony payment deadline exhausted")
        );
        assert!(!polled.load(Ordering::SeqCst));
    }

    #[tokio::test(start_paused = true)]
    async fn ready_payment_cannot_bypass_elapsed_original_deadline() {
        use std::{future::Future as _, task::Poll};
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        let completed = Arc::new(AtomicBool::new(false));
        let observed = completed.clone();
        let (finished, finish_observed) = oneshot::channel();
        let mut owner = Box::pin(owned_payment_until(deadline.into_std(), async move {
            tokio::time::advance(Duration::from_secs(5)).await;
            observed.store(true, Ordering::SeqCst);
            let _ = finished.send(());
            Ok(())
        }));
        // Start the task and timer, then hold this owner's next poll until its
        // child has actually completed after advancing the original deadline.
        std::future::poll_fn(|cx| {
            assert!(owner.as_mut().poll(cx).is_pending());
            Poll::Ready(())
        })
        .await;
        finish_observed.await.unwrap();
        assert!(
            completed.load(Ordering::SeqCst),
            "the payment must actually complete"
        );
        assert_eq!(tokio::time::Instant::now(), deadline);
        let error = owner.await.unwrap_err();
        assert!(
            error
                .to_string()
                .contains("original ceremony payment deadline exhausted")
        );
    }

    #[tokio::test(start_paused = true)]
    async fn deadline_aborts_the_owned_payment_without_replenishment() {
        let (dropped, drop_observed) = oneshot::channel();
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        let error = owned_payment_until(deadline.into_std(), async move {
            let _owner = Dropped(Some(dropped));
            std::future::pending::<Result<()>>().await
        })
        .await
        .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("original ceremony payment deadline exhausted")
        );
        drop_observed
            .await
            .expect("deadline must cancel the child owner");
        assert_eq!(tokio::time::Instant::now(), deadline);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn dropping_ceremony_owner_aborts_the_child_payment() {
        let (started, start_observed) = oneshot::channel();
        let (dropped, drop_observed) = oneshot::channel();
        let owner = tokio::spawn(owned_payment_until(
            Instant::now() + Duration::from_secs(30),
            async move {
                let _owner = Dropped(Some(dropped));
                let _ = started.send(());
                std::future::pending::<Result<()>>().await
            },
        ));
        start_observed.await.unwrap();
        owner.abort();
        assert!(owner.await.unwrap_err().is_cancelled());
        tokio::time::timeout(Duration::from_secs(1), drop_observed)
            .await
            .expect("child must remain owned on outer cancellation")
            .unwrap();
    }
}
