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

use crate::amx_harness::owned_task::owned_payment_until;
use eyre::{Result, ensure, eyre};
use iroha::{
    blocking::Client,
    client::{NativePaymentRequest, NativePaymentRunOptions, NativePaymentSession, VerifiedPaymentReceipt},
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
    session: NativePaymentSession,
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
        let selected = authenticate_signed_genesis_v1(&genesis, &pins)?;
        let verifier = SumeragiFinalityVerifier::new(
            selected.block(),
            &pins.chain_id,
            selected.validators().to_vec(),
        )?;
        let session = NativePaymentSession::new(
            verifier,
            std::num::NonZeroUsize::new(64).expect("nonzero local history capacity"),
        )?;
        Ok(Self {
            session,
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
        let receipt = customer_payment_at_height(
            client,
            self.recipient.clone(),
            self.asset.clone(),
            NonZeroU64::new(height).ok_or_else(|| eyre!("customer workload height is zero"))?,
            self.last_height,
            self.fee.clone(),
            &self.directory,
            self.session.clone(),
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
/// `session` retains the test's original independently signed-genesis-rooted verifier.
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
    session: NativePaymentSession,
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
    let operation = account.native_payment_with_session(
        NativePaymentRequest::new(terms, fee)?,
        Arc::new(FileWorkflowStorage::open_or_create(directory)?),
        session,
    )?;
    let completed = owned_payment_until(deadline, async move {
        let options = NativePaymentRunOptions {
            workflow: WorkflowRunOptions {
                observation_timeout: deadline.saturating_duration_since(Instant::now()),
                poll_interval: Duration::from_millis(150),
                ..WorkflowRunOptions::default()
            },
            // Every operation uses the same independently selected original prefix.
            // Keep the existing finite workload observation allowance unchanged;
            // retained history and per-call proof reads are separate local limits.
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
