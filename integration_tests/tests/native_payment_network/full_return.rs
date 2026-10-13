//! Paid original and full reverse payments recover at H3 without successor traffic.

use super::*;
use iroha::client::{
    NativePaymentFullReturnRequest, VerifiedPaymentReceipt, VerifiedPaymentReturn,
};
use iroha_data_model::isi::{SettlementDetails, SettlementReceipt};
use std::collections::BTreeMap;

fn return_fee() -> FeePaymentIntent {
    FeePaymentIntent::authority(
        vec![FeeChargeLimit::new(
            FeeChargeKind::Nexus,
            fee_asset(),
            Quantity::one(),
        )],
        None,
    )
}

fn check_fee(receipt: &VerifiedPaymentReceipt, payer: &AccountId, height: u64) -> Result<()> {
    ensure!(receipt.evidence().result().is_ok());
    ensure!(receipt.settlement().block_height == height);
    let fee = receipt
        .nexus_fee_receipt()
        .ok_or_else(|| eyre!("authenticated payment fee absent"))?;
    fee.validate_for_network_input(receipt.evidence().entrypoint(), height)
        .map_err(|error| eyre!(error))?;
    ensure!(
        fee.fee_amount == Quantity::one()
            && fee.fee_asset_id == fee_asset()
            && fee.debit_source == FeeDebitSource::Account(payer.clone())
            && fee.settlement == NexusFeeSettlementV1::Burn
    );
    Ok(())
}

fn check_linked(
    receipt: &VerifiedPaymentReturn,
    original: &SettlementReceipt,
    payer: &AccountId,
    recipient: &AccountId,
) -> Result<()> {
    ensure!(
        receipt.original().settlement() == original,
        "a return never rewrites its successful original"
    );
    ensure!(receipt.original().transaction_hash() != receipt.reverse().transaction_hash());
    ensure!(receipt.original().settlement_id() != receipt.reverse().settlement_id());
    ensure!(receipt.reverse().settlement_id().owner() == recipient);
    let SettlementDetails::Atomic(reverse) = &receipt.reverse().settlement().details else {
        return Err(eyre!(
            "verified full return lost its atomic settlement details"
        ));
    };
    let [movement] = reverse.movements.as_slice() else {
        return Err(eyre!("full return must have exactly one reverse movement"));
    };
    ensure!(
        movement.source == AssetId::of(principal(), recipient.clone())
            && movement.destination == AssetId::of(principal(), payer.clone())
            && movement.quantity == Quantity::from(250_000_u32),
        "full return must preserve the exact original principal and reverse bucket direction"
    );
    ensure!(receipt.link().original_settlement_id == *receipt.original().settlement_id());
    ensure!(receipt.link().original_transaction == receipt.original().transaction_hash());
    ensure!(receipt.link().original_network == receipt.original().network());
    let SettlementDetails::Atomic(original_terms) = &original.details else {
        return Err(eyre!("original verified payment lost its atomic details"));
    };
    ensure!(
        receipt.link().original_intent_hash == original_terms.intent_hash,
        "signed return link must bind the exact original caller terms"
    );
    check_fee(receipt.original(), payer, 2)?;
    check_fee(receipt.reverse(), recipient, 3)
}

fn check_balances(
    network: &Network,
    payer: &AccountId,
    recipient: &AccountId,
    returned: bool,
) -> Result<()> {
    for peer in network.validators() {
        let payer_client = peer.client_for(payer, key(0x76).private_key().clone());
        let recipient_client = peer.client_for(recipient, key(0x77).private_key().clone());
        ensure!(
            account_snapshot(&payer_client, payer)?
                == BTreeMap::from([
                    (
                        AssetId::of(principal(), payer.clone()),
                        Quantity::from(if returned { 1_000_000_u32 } else { 750_000_u32 })
                    ),
                    (
                        AssetId::of(fee_asset(), payer.clone()),
                        Quantity::from(99_u32)
                    ),
                ])
        );
        let mut expected_receiver = BTreeMap::from([(
            AssetId::of(fee_asset(), recipient.clone()),
            Quantity::from(if returned { 99_u32 } else { 100_u32 }),
        )]);
        if !returned {
            expected_receiver.insert(
                AssetId::of(principal(), recipient.clone()),
                Quantity::from(250_000_u32),
            );
        }
        ensure!(
            account_snapshot(&recipient_client, recipient)? == expected_receiver,
            "full return removes the exact receiver principal row; a query failure is never zero"
        );
        let sink_client = peer.client();
        let sink = account_snapshot(&sink_client, &ALICE_ID)?;
        ensure!(
            sink.get(&AssetId::of(fee_asset(), ALICE_ID.clone())) == Some(&Quantity::from(100_u32))
        );
        let definition = sink_client
            .client()
            .query_single(FindAssetDefinitionById::new(fee_asset()))?;
        ensure!(
            definition.total_quantity()
                == &Quantity::from(if returned { 298_u32 } else { 299_u32 }),
            "only the independently verified original and return fees may burn the genesis 300"
        );
    }
    Ok(())
}

#[test]
#[ignore = "four validators and all-node restart; run with isolated network permit and immutable same-source daemon"]
fn paid_full_return_preserves_original_and_recovers_both_at_final_tip_without_new_effect()
-> Result<()> {
    let payer = AccountId::new(key(0x76).public_key().clone());
    let recipient = AccountId::new(key(0x77).public_key().clone());
    let (network, rt) = sandbox::start_network_blocking_or_skip(
        builder(&payer, &recipient).with_genesis_instruction(Mint::asset_quantity(
            100_u32,
            AssetId::of(fee_asset(), recipient.clone()),
        )),
        stringify!(
            paid_full_return_preserves_original_and_recovers_both_at_final_tip_without_new_effect
        ),
    )?
    .ok_or_else(|| eyre!("required four-process full-return acceptance cannot skip startup"))?;
    let result = (|| -> Result<()> {
        ensure!(network.validators().len() == 4 && network.topology_entries().len() == 4);
        let pids = rt.block_on(async {
            let mut pids = Vec::new();
            for peer in network.validators() {
                pids.push(
                    peer.process_id()
                        .await
                        .ok_or_else(|| eyre!("validator process absent"))?,
                );
            }
            Ok::<_, eyre::Report>(pids)
        })?;
        let (wire, trust) = pins(&network)?;
        let original_gateway =
            network.validators()[0].client_for(&payer, key(0x76).private_key().clone());
        ensure!(
            rt.block_on(original_gateway.client().status().get())?
                .blocks
                == 1,
            "the original must follow signed genesis without preparatory traffic"
        );
        let request = NativePaymentRequest::new(
            SettleAtomic::new(
                network.network_id(),
                SettlementId::new(payer.clone(), "linked-original-250000".parse()?),
                AtomicSettlementMovements::try_from(vec![AtomicSettlementMovement {
                    source: AssetId::of(principal(), payer.clone()),
                    recipient: recipient.clone(),
                    quantity: 250_000_u32.into(),
                }])
                .map_err(|error| eyre!(error))?,
                NonZeroU64::new(101).unwrap(),
                Metadata::default(),
            ),
            return_fee(),
        )?;
        // KEEP_DIRS retains both consensus storage and application custody on failure.
        let stores = network.env_dir().join("linked-return-workflows");
        eprintln!("linked-return durable custody: {}", stores.display());
        let options = NativePaymentRunOptions {
            workflow: WorkflowRunOptions {
                observation_timeout: Duration::from_secs(120),
                poll_interval: Duration::from_millis(200),
                ..WorkflowRunOptions::default()
            },
            ..NativePaymentRunOptions::default()
        };
        let original_operation = original_gateway.account_client().native_payment(
            request.clone(),
            Arc::new(FileWorkflowStorage::open_or_create(
                stores.join("original"),
            )?),
            verifier(&wire, &trust)?,
        )?;
        let paid = rt.block_on(original_operation.submit(&options))?;
        check_fee(&paid.receipt, &payer, 2)?;
        rt.block_on(network.ensure_blocks(2))?;
        rt.block_on(wait_for_applied_height(&network, 2))?;
        check_balances(&network, &payer, &recipient, false)?;
        let original_hash = paid.receipt.transaction_hash();
        let original_receipt = paid.receipt.settlement().clone();
        let customer: Name = "receiver-customer".parse()?;
        let original_destination = AssetId::of(principal(), recipient.clone());
        let original_inbox = PaymentInbox::new(Arc::new(FileWorkflowStorage::open_or_create(
            stores.join("original-inbox"),
        )?))?;
        ensure!(
            original_inbox.credit(&paid.receipt, &customer, &original_destination)?
                == PaymentCreditStatus::Recorded
        );
        let return_request = NativePaymentFullReturnRequest::new(
            paid.receipt.clone(),
            NonZeroU64::new(102).unwrap(),
            return_fee(),
        )?;
        let return_id = return_request.settlement_id().clone();
        let return_terms = return_request.payment().intent().clone();
        let link = return_request.link().clone();
        let receiver_gateway =
            network.validators()[1].client_for(&recipient, key(0x77).private_key().clone());
        let return_operation = receiver_gateway.account_client().native_payment_return(
            return_request,
            Arc::new(FileWorkflowStorage::open_or_create(stores.join("reverse"))?),
            verifier(&wire, &trust)?,
        )?;
        let returned = rt.block_on(return_operation.submit(&options))?;
        check_linked(&returned.receipt, &original_receipt, &payer, &recipient)?;
        let reverse_hash = returned.receipt.reverse().transaction_hash();
        let reverse_receipt = returned.receipt.reverse().settlement().clone();
        ensure!(returned.receipt.link() == &link);
        rt.block_on(network.ensure_blocks(3))?;
        rt.block_on(wait_for_applied_height(&network, 3))?;
        check_balances(&network, &payer, &recipient, true)?;
        let reverse_customer: Name = "returned-payer-customer".parse()?;
        let reverse_destination = AssetId::of(principal(), payer.clone());
        let reverse_inbox = PaymentInbox::new(Arc::new(FileWorkflowStorage::open_or_create(
            stores.join("reverse-inbox"),
        )?))?;
        ensure!(
            reverse_inbox.credit(
                returned.receipt.reverse(),
                &reverse_customer,
                &reverse_destination
            )? == PaymentCreditStatus::Recorded
        );
        drop((
            paid,
            returned,
            original_operation,
            return_operation,
            original_gateway,
            receiver_gateway,
            original_inbox,
            reverse_inbox,
        ));

        // No opaque verified receipt survives this boundary. Both are reconstructed
        // from independent signed-genesis trust and freshly fetched original proofs.
        rt.block_on(network.shutdown());
        rt.block_on(network.start_all())?;
        rt.block_on(network.ensure_blocks(3))?;
        rt.block_on(wait_for_applied_height(&network, 3))?;
        rt.block_on(async {
            for (peer, pid) in network.validators().iter().zip(&pids) {
                ensure!(peer.process_id().await.is_some_and(|actual| actual != *pid));
            }
            Ok::<_, eyre::Report>(())
        })?;
        let original_gateway =
            network.validators()[2].client_for(&payer, key(0x76).private_key().clone());
        let original_operation = original_gateway.account_client().native_payment(
            request,
            Arc::new(FileWorkflowStorage::open_or_create(
                stores.join("original"),
            )?),
            verifier(&wire, &trust)?,
        )?;
        let original = rt
            .block_on(original_operation.recover(&options))?
            .receipt
            .ok_or_else(|| eyre!("original H2 success was not freshly recovered"))?;
        ensure!(
            original.transaction_hash() == original_hash
                && original.settlement() == &original_receipt
        );
        let restored_return = NativePaymentFullReturnRequest::new(
            original.clone(),
            NonZeroU64::new(102).unwrap(),
            return_fee(),
        )?;
        ensure!(
            restored_return.settlement_id() == &return_id
                && restored_return.payment().intent() == &return_terms
                && restored_return.link() == &link
        );
        let receiver_gateway =
            network.validators()[2].client_for(&recipient, key(0x77).private_key().clone());
        let resumed_return = receiver_gateway.account_client().native_payment_return(
            restored_return.clone(),
            Arc::new(FileWorkflowStorage::open_or_create(stores.join("reverse"))?),
            verifier(&wire, &trust)?,
        )?;
        let recovered = rt
            .block_on(resumed_return.recover(&options))?
            .receipt
            .ok_or_else(|| eyre!("reverse H3 success was not freshly recovered"))?;
        check_linked(&recovered, &original_receipt, &payer, &recipient)?;
        ensure!(
            recovered.reverse().transaction_hash() == reverse_hash
                && recovered.reverse().settlement() == &reverse_receipt
        );
        let inbox = PaymentInbox::new(Arc::new(FileWorkflowStorage::open_or_create(
            stores.join("original-inbox"),
        )?))?;
        ensure!(
            inbox.credit(recovered.original(), &customer, &original_destination)?
                == PaymentCreditStatus::AlreadyRecorded {
                    notification_pending: true
                }
        );
        inbox.acknowledge_notification(recovered.original(), &customer, &original_destination)?;
        let reverse_inbox = PaymentInbox::new(Arc::new(FileWorkflowStorage::open_or_create(
            stores.join("reverse-inbox"),
        )?))?;
        ensure!(
            reverse_inbox.credit(recovered.reverse(), &reverse_customer, &reverse_destination)?
                == PaymentCreditStatus::AlreadyRecorded {
                    notification_pending: true
                }
        );
        reverse_inbox.acknowledge_notification(
            recovered.reverse(),
            &reverse_customer,
            &reverse_destination,
        )?;

        // An independent return gateway starts with no local carrier journal.
        // Consensus identity must find the exact H3 success before any signature.
        let fresh_gateway =
            network.validators()[3].client_for(&recipient, key(0x77).private_key().clone());
        let repeated = fresh_gateway.account_client().native_payment_return(
            restored_return,
            Arc::new(FileWorkflowStorage::open_or_create(
                stores.join("fresh-return-gateway"),
            )?),
            verifier(&wire, &trust)?,
        )?;
        let repeated = rt.block_on(repeated.resume(&options))?;
        check_linked(&repeated.receipt, &original_receipt, &payer, &recipient)?;
        ensure!(
            repeated.receipt.reverse().transaction_hash() == reverse_hash
                && repeated.receipt.reverse().settlement() == &reverse_receipt
        );
        ensure!(
            repeated
                .carrier
                .steps
                .iter()
                .all(|step| step.identities.is_empty()),
            "fresh return gateway must recover business success without signing or dispatching a carrier"
        );
        ensure!(
            inbox.credit(
                repeated.receipt.original(),
                &customer,
                &original_destination
            )? == PaymentCreditStatus::AlreadyRecorded {
                notification_pending: false
            }
        );
        ensure!(
            reverse_inbox.credit(
                repeated.receipt.reverse(),
                &reverse_customer,
                &reverse_destination
            )? == PaymentCreditStatus::AlreadyRecorded {
                notification_pending: false
            }
        );
        ensure!(
            inbox
                .pending_notification(
                    repeated.receipt.original(),
                    &customer,
                    &original_destination
                )?
                .is_none()
        );
        ensure!(
            reverse_inbox
                .pending_notification(
                    repeated.receipt.reverse(),
                    &reverse_customer,
                    &reverse_destination
                )?
                .is_none()
        );
        check_balances(&network, &payer, &recipient, true)?;
        for peer in network.validators() {
            ensure!(
                rt.block_on(peer.client().client().status().get())?.blocks == 3,
                "return recovery must require neither successor traffic nor another paid effect"
            );
        }
        Ok(())
    })();
    rt.block_on(network.shutdown_and_release());
    result
}
