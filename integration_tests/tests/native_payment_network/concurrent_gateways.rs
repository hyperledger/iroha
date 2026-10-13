//! Two independent gateways recover one native monetary effect after a four-peer restart.

use super::*;
use iroha::workflow::{
    AttemptEvidenceKindV1, Digest32, TransactionIdentityV1, TransactionStateV1, WorkflowId,
    WorkflowJournalV1, WorkflowRunnerLease, WorkflowStorage, WorkflowStorageDurability,
    WorkflowStorageError, WorkflowStorageErrorKind,
};
use std::sync::{
    Condvar, Mutex,
    atomic::{AtomicBool, Ordering},
};

#[derive(Default)]
struct SignedRendezvous {
    identities: Mutex<Vec<TransactionIdentityV1>>,
    both_signed: Condvar,
}

impl SignedRendezvous {
    fn arrive(&self, identity: TransactionIdentityV1) -> Result<(), WorkflowStorageError> {
        let mut identities = self.identities.lock().map_err(|_| {
            WorkflowStorageError::new(
                WorkflowStorageErrorKind::WriteUncertain,
                "signature rendezvous poisoned after durable publication",
            )
        })?;
        identities.push(identity);
        self.both_signed.notify_all();
        let (identities, _) = self
            .both_signed
            .wait_timeout_while(identities, Duration::from_secs(60), |identities| {
                identities.len() < 2
            })
            .map_err(|_| {
                WorkflowStorageError::new(
                    WorkflowStorageErrorKind::WriteUncertain,
                    "signature rendezvous poisoned after durable publication",
                )
            })?;
        if identities.len() != 2 {
            return Err(WorkflowStorageError::new(
                WorkflowStorageErrorKind::WriteUncertain,
                "both independent gateways must persist signed carriers before either dispatches",
            ));
        }
        Ok(())
    }
}

/// A timing observer around the genuine durable store; record bytes and semantics are unchanged.
struct RendezvousStorage {
    inner: FileWorkflowStorage,
    rendezvous: Arc<SignedRendezvous>,
    arrived: AtomicBool,
}

impl WorkflowStorage for RendezvousStorage {
    fn durability(&self) -> WorkflowStorageDurability {
        self.inner.durability()
    }
    fn load(&self, id: &WorkflowId) -> Result<Option<Vec<u8>>, WorkflowStorageError> {
        self.inner.load(id)
    }
    fn compare_and_store(
        &self,
        id: &WorkflowId,
        expected: Option<&Digest32>,
        record: &[u8],
    ) -> Result<(), WorkflowStorageError> {
        // Decode only to observe the real engine transition. Never modify a record or sign bytes.
        let journal = WorkflowJournalV1::decode_record(record).map_err(|error| {
            WorkflowStorageError::new(WorkflowStorageErrorKind::Unavailable, error.to_string())
        })?;
        let signed = journal
            .steps
            .first()
            .and_then(|step| step.transaction.as_ref())
            .filter(|operation| operation.state == TransactionStateV1::Signed)
            .and_then(|operation| operation.attempts.last())
            .and_then(|attempt| attempt.identity);
        self.inner.compare_and_store(id, expected, record)?;
        if let Some(identity) = signed {
            if !self.arrived.swap(true, Ordering::SeqCst) {
                self.rendezvous.arrive(identity)?;
            }
        }
        Ok(())
    }
    fn acquire_runner(
        &self,
        id: &WorkflowId,
    ) -> Result<Box<dyn WorkflowRunnerLease>, WorkflowStorageError> {
        self.inner.acquire_runner(id)
    }
}

#[test]
fn native_payment_two_concurrent_gateways_recover_one_paid_effect_without_later_traffic()
-> Result<()> {
    let payer = AccountId::new(key(0x76).public_key().clone());
    let recipient = AccountId::new(key(0x77).public_key().clone());
    let (network, rt) = sandbox::start_network_blocking_or_skip(
        builder(&payer, &recipient),
        stringify!(
            native_payment_two_concurrent_gateways_recover_one_paid_effect_without_later_traffic
        ),
    )?
    .ok_or_else(|| eyre!("required four-process native payment acceptance cannot skip startup"))?;
    let result = (|| -> Result<()> {
        ensure!(network.validators().len() == 4 && network.topology_entries().len() == 4);
        let (genesis_wire, selected_pins) = pins(&network)?;
        let first_gateway =
            network.validators()[0].client_for(&payer, key(0x76).private_key().clone());
        let second_gateway =
            network.validators()[1].client_for(&payer, key(0x76).private_key().clone());
        let initial_height = rt.block_on(first_gateway.client().status().get())?.blocks;
        let request = NativePaymentRequest::new(
            SettleAtomic::new(
                network.network_id(),
                SettlementId::new(payer.clone(), "concurrent-invoice-250000".parse()?),
                AtomicSettlementMovements::try_from(vec![AtomicSettlementMovement {
                    source: AssetId::of(principal(), payer.clone()),
                    recipient: recipient.clone(),
                    quantity: 250_000_u32.into(),
                }])
                .map_err(|error| eyre!(error))?,
                NonZeroU64::new(initial_height + 100).unwrap(),
                Metadata::default(),
            ),
            FeePaymentIntent::authority(
                vec![FeeChargeLimit::new(
                    FeeChargeKind::Nexus,
                    fee_asset(),
                    Quantity::one(),
                )],
                None,
            ),
        )?;
        let options = NativePaymentRunOptions {
            workflow: WorkflowRunOptions {
                observation_timeout: Duration::from_secs(120),
                poll_interval: Duration::from_millis(200),
                // Neither a replacement identity nor a retransmission is authorized.
                ..WorkflowRunOptions::default()
            },
            ..NativePaymentRunOptions::default()
        };
        // Distinct valid carrier TTLs guarantee different signed bytes even in the same millisecond.
        // Rebuild through the public context API, preserving each gateway's endpoint and authority.
        let mut first_builder = first_gateway.client().to_builder();
        first_builder.transaction_ttl = Some(Duration::from_secs(600));
        let first_client = first_builder.build()?;
        let mut second_builder = second_gateway.client().to_builder();
        second_builder.transaction_ttl = Some(Duration::from_secs(601));
        let second_client = second_builder.build()?;
        // Keep application custody with peer stores when KEEP_DIRS preserves this network.
        let root = tempfile::tempdir_in(network.env_dir())?.keep();
        let rendezvous = Arc::new(SignedRendezvous::default());
        let first = first_client.account_client()?.native_payment(
            request.clone(),
            Arc::new(RendezvousStorage {
                inner: FileWorkflowStorage::open_or_create(root.join("gateway-a"))?,
                rendezvous: Arc::clone(&rendezvous),
                arrived: AtomicBool::new(false),
            }),
            verifier(&genesis_wire, &selected_pins)?,
        )?;
        let second = second_client.account_client()?.native_payment(
            request.clone(),
            Arc::new(RendezvousStorage {
                inner: FileWorkflowStorage::open_or_create(root.join("gateway-b"))?,
                rendezvous: Arc::clone(&rendezvous),
                arrived: AtomicBool::new(false),
            }),
            verifier(&genesis_wire, &selected_pins)?,
        )?;
        let first_id = first.id();
        let second_id = second.id();
        ensure!(
            first_id == second_id,
            "business identity must be shared despite independent carrier policies"
        );
        // Dedicated caller threads may block in their storage callbacks without blocking the node runtime.
        // Join both before propagating either result, so one failure cannot leave a caller running.
        let (first_join, second_join) = std::thread::scope(|scope| {
            let first_thread = scope.spawn(|| rt.handle().block_on(first.submit(&options)));
            let second_thread = scope.spawn(|| rt.handle().block_on(second.submit(&options)));
            (first_thread.join(), second_thread.join())
        });
        let first_settled = first_join.map_err(|_| eyre!("first gateway panicked"))??;
        let second_settled = second_join.map_err(|_| eyre!("second gateway panicked"))??;
        let signed = rendezvous
            .identities
            .lock()
            .map_err(|_| eyre!("rendezvous poisoned"))?;
        ensure!(
            signed.len() == 2 && signed[0] != signed[1],
            "the race must involve two distinct signed carriers"
        );
        let original_hash = first_settled.receipt.transaction_hash();
        ensure!(second_settled.receipt.transaction_hash() == original_hash);
        ensure!(first_settled.receipt.settlement() == second_settled.receipt.settlement());
        let original_receipt = first_settled.receipt.settlement().clone();
        let original_height = original_receipt.block_height;
        ensure!(
            original_height == initial_height + 1,
            "the first monetary effect needs no unrelated predecessor or successor"
        );
        ensure!(
            signed
                .iter()
                .filter(|identity| identity.signed_transaction_hash == *original_hash.as_ref())
                .count()
                == 1
        );
        for settled in [&first_settled, &second_settled] {
            let attempts = &settled.carrier.steps[0].identities;
            ensure!(
                attempts.len() == 1 && attempts[0].dispatch_ordinal == 1,
                "each gateway must dispatch exactly its original carrier once"
            );
            let identity = attempts[0]
                .identity
                .ok_or_else(|| eyre!("missing exact signed carrier"))?;
            ensure!(signed.contains(&identity));
            if identity.signed_transaction_hash != *original_hash.as_ref() {
                ensure!(
                    attempts[0]
                        .evidence
                        .as_ref()
                        .is_none_or(|evidence| evidence.kind != AttemptEvidenceKindV1::Applied),
                    "the rejected or unresolved retry carrier must never be relabelled Applied"
                );
            }
            let fee = settled
                .receipt
                .nexus_fee_receipt()
                .ok_or_else(|| eyre!("missing authenticated fee"))?;
            ensure!(fee.fee_amount == Quantity::one());
            ensure!(fee.settlement == NexusFeeSettlementV1::Burn);
            ensure!(fee.debit_source == FeeDebitSource::Account(payer.clone()));
            ensure!(fee.fee_asset_id == fee_asset());
        }
        drop(signed);
        rt.block_on(network.ensure_blocks(original_height))?;
        rt.block_on(wait_for_applied_height(&network, original_height))?;
        let bank_root = root.join("bank");
        let customer: Name = "same-customer".parse()?;
        let destination = AssetId::of(principal(), recipient.clone());
        let inbox = PaymentInbox::new(Arc::new(FileWorkflowStorage::open_or_create(&bank_root)?))?;
        ensure!(
            inbox.credit(&first_settled.receipt, &customer, &destination)?
                == PaymentCreditStatus::Recorded
        );
        ensure!(
            inbox.credit(&second_settled.receipt, &customer, &destination)?
                == PaymentCreditStatus::AlreadyRecorded {
                    notification_pending: true
                }
        );
        let before = [
            first_settled.carrier.clone(),
            second_settled.carrier.clone(),
        ];
        drop(inbox);
        drop(first_settled);
        drop(second_settled);
        drop(first);
        drop(second);
        drop(first_client);
        drop(second_client);

        // Stop all validators and both local operations. A loser may have an authenticated
        // rejected block or remain unresolved; neither is allowed to become another payment.
        rt.block_on(network.shutdown());
        rt.block_on(network.start_all())?;
        rt.block_on(network.ensure_blocks(original_height))?;
        rt.block_on(wait_for_applied_height(&network, original_height))?;
        let inbox = PaymentInbox::new(Arc::new(FileWorkflowStorage::open_or_create(bank_root)?))?;
        for (index, directory) in ["gateway-a", "gateway-b"].into_iter().enumerate() {
            let gateway =
                network.validators()[index + 2].client_for(&payer, key(0x76).private_key().clone());
            let resumed = gateway.account_client().native_payment(
                request.clone(),
                Arc::new(FileWorkflowStorage::open_or_create(root.join(directory))?),
                verifier(&genesis_wire, &selected_pins)?,
            )?;
            let recovery = rt.block_on(resumed.recover(&options))?;
            let receipt = recovery.receipt.ok_or_else(|| {
                eyre!("concurrent gateway lost original verified receipt on restart")
            })?;
            ensure!(
                receipt.transaction_hash() == original_hash
                    && receipt.settlement() == &original_receipt
            );
            ensure!(
                recovery
                    .carrier
                    .ok_or_else(|| eyre!("missing carrier progress"))?
                    .steps[0]
                    .identities
                    == before[index].steps[0].identities,
                "read-only recovery must neither resend nor replace either original carrier"
            );
            ensure!(
                inbox.credit(&receipt, &customer, &destination)?
                    == PaymentCreditStatus::AlreadyRecorded {
                        notification_pending: true
                    }
            );
        }
        for peer in network.validators() {
            let client = peer.client();
            // There are exactly two submitted carriers. A later block may contain the real
            // losing carrier; no traffic is manufactured to deliver either receipt.
            let height = rt.block_on(client.client().status().get())?.blocks;
            ensure!((original_height..=original_height + 1).contains(&height));
            let payer_asset = client
                .client()
                .query_single(FindAssetById::new(AssetId::of(principal(), payer.clone())))?;
            let recipient_asset = client
                .client()
                .query_single(FindAssetById::new(destination.clone()))?;
            let payer_fees = client
                .client()
                .query_single(FindAssetById::new(AssetId::of(fee_asset(), payer.clone())))?;
            let sink_fees = client
                .client()
                .query_single(FindAssetById::new(AssetId::of(
                    fee_asset(),
                    ALICE_ID.clone(),
                )))?;
            ensure!(payer_asset.value() == &Quantity::from(750_000_u32));
            ensure!(recipient_asset.value() == &Quantity::from(250_000_u32));
            ensure!(
                payer_fees.value() == &Quantity::from(99_u32),
                "the losing carrier must charge no rejection fee"
            );
            ensure!(
                sink_fees.value() == &Quantity::from(100_u32),
                "Nexus burns its one paid fee; the configured sink must retain its genesis 100, got {}",
                sink_fees.value()
            );
            let fee_definition = client
                .client()
                .query_single(FindAssetDefinitionById::new(fee_asset()))?;
            ensure!(
                fee_definition.total_quantity() == &Quantity::from(199_u32),
                "the losing carrier must burn no additional supply beyond the original fee, got {}",
                fee_definition.total_quantity()
            );
        }
        Ok(())
    })();
    rt.block_on(network.shutdown_and_release());
    result
}
