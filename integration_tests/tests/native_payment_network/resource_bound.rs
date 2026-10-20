//! Actual fixed-cap paid carriers through HTTP, signed RS16, finality and cold Kura replay.
//! Reconciliation text is part of the exact monetary intent, never a fabricated proof.

use super::*;
use iroha::client::{AccountClient, AccountTransactionDraft};
use iroha_core::tx::{AcceptTransactionFail, AcceptedTransaction};
use iroha_crypto::HashOf;
use iroha_data_model::{
    ValidationFail,
    block::consensus::SumeragiRootScope,
    isi::{
        InstructionBox, SettlementInstructionBox,
        error::{InstructionExecutionError, MathError},
    },
    parameter::{Parameters, system::TransactionInclusionRoute},
    sumeragi_finality::{SumeragiFinalityProof, VerifiedSumeragiBlock},
    transaction::{SignedTransaction, TransactionEntrypoint, error::TransactionRejectionReason},
};
use iroha_primitives::json::Json;
use std::{collections::BTreeMap, time::Instant};

#[path = "resource_bound_transport.rs"]
mod transport;

const SIGNED_FRAME_CAP: usize = 10_485_760;
const BLOCK_PAYLOAD_CAP: usize = 16_777_216;
const SOURCE_SLACK: usize = 8_192;
const CASE_TIMEOUT: Duration = Duration::from_secs(120);

fn bounded<F: std::future::Future>(
    runtime: &tokio::runtime::Runtime,
    deadline: Instant,
    future: F,
) -> Result<F::Output> {
    Ok(runtime.block_on(async {
        tokio::time::timeout_at(tokio::time::Instant::from_std(deadline), future).await
    })?)
}

fn fees() -> FeePaymentIntent {
    FeePaymentIntent::authority(
        vec![FeeChargeLimit::new(
            FeeChargeKind::Nexus,
            fee_asset(),
            Quantity::one(),
        )],
        None,
    )
}

fn request(
    network: iroha_data_model::NetworkId,
    payer: &AccountId,
    recipient: &AccountId,
    reference: &str,
    quantity: u32,
    text_bytes: usize,
) -> Result<NativePaymentRequest> {
    let mut metadata = Metadata::default();
    // Each JSON value retains its existing 1 MiB bound. These ordered entries are
    // all signed settlement terms, contribute to intent_hash, and return in the
    // verified receipt; their aggregate exercises the complete transaction limit.
    let chunk_capacity = iroha_primitives::json::MAX_JSON_BYTES - 2; // JSON string quotes.
    let mut remaining = text_bytes;
    let mut index = 0;
    while remaining != 0 {
        let length = remaining.min(chunk_capacity);
        metadata.insert(
            format!("reconciliation_text_{index:02}").parse()?,
            Json::try_new("r".repeat(length))?,
        );
        remaining -= length;
        index += 1;
    }
    NativePaymentRequest::new(
        SettleAtomic::new(
            network,
            SettlementId::new(payer.clone(), reference.parse()?),
            AtomicSettlementMovements::try_from(vec![AtomicSettlementMovement {
                source: AssetId::of(principal(), payer.clone()),
                recipient: recipient.clone(),
                quantity: quantity.into(),
            }])
            .map_err(|error| eyre!(error))?,
            AtomicSettlementEscrows::empty(),
            NonZeroU64::new(101).unwrap(),
            metadata,
        ),
        fees(),
    )
    .map_err(Into::into)
}

fn signed(account: &AccountClient, request: &NativePaymentRequest) -> Result<SignedTransaction> {
    let payload = account.prepare_transaction(AccountTransactionDraft::new(
        vec![InstructionBox::from(SettlementInstructionBox::Atomic(
            request.intent().clone(),
        ))],
        request.fee_payment().clone(),
        Metadata::default(),
    ))?;
    Ok(account.sign_transaction(payload)?)
}

fn shape(transaction: &SignedTransaction) -> Result<(usize, usize)> {
    transaction.verify_signature()?;
    ensure!(
        transaction.nonce().is_none(),
        "sizing and workflow signing must retain the fixture's fixed absent-nonce geometry"
    );
    let frame = norito::encode_canonical(transaction)?;
    let wire = transaction.encode_wire_v1()?;
    let align = norito::core::archived_payload_align::<SignedTransaction>();
    let padding = (align - norito::core::Header::SIZE % align) % align;
    ensure!(norito::core::Header::SIZE == 40);
    ensure!(wire.first() == Some(&1));
    ensure!(
        frame.len() == wire.len() - 1 + 40 + padding,
        "committed signed-frame and V1 HTTP extents must not be conflated"
    );
    Ok((frame.len(), wire.len()))
}

fn sized_request(
    account: &AccountClient,
    network: iroha_data_model::NetworkId,
    payer: &AccountId,
    recipient: &AccountId,
    reference: &str,
    quantity: u32,
    target: usize,
) -> Result<(NativePaymentRequest, SignedTransaction)> {
    // Both probes stay in the same canonical length-prefix band. Measure the real
    // serializer without admitting under a larger policy or mutating a proof.
    let initial = target
        .checked_sub(SOURCE_SLACK)
        .ok_or_else(|| eyre!("small target"))?;
    let probe = request(network, payer, recipient, reference, quantity, initial)?;
    let measured = shape(&signed(account, &probe)?)?.0;
    let growth = target
        .checked_sub(measured)
        .ok_or_else(|| eyre!("fixture overhead exceeds slack"))?;
    let result = request(
        network,
        payer,
        recipient,
        reference,
        quantity,
        initial + growth,
    )?;
    let transaction = signed(account, &result)?;
    ensure!(
        shape(&transaction)?.0 == target,
        "canonical reconciliation text is not byte-linear"
    );
    Ok((result, transaction))
}

fn require_fixed_parameters(parameters: &Parameters) -> Result<()> {
    ensure!(parameters.transaction().max_tx_bytes().get() == SIGNED_FRAME_CAP as u64);
    ensure!(parameters.sumeragi().max_block_bytes.get() == BLOCK_PAYLOAD_CAP as u32);
    ensure!(
        iroha_data_model::parameter::system::BLOCK_PAYLOAD_NON_TRANSACTION_RESERVE_BYTES == 65_536
    );
    ensure!(
        parameters.max_includable_transaction_bytes(TransactionInclusionRoute::Global)
            == SIGNED_FRAME_CAP as u64
    );
    ensure!(SIGNED_FRAME_CAP + 65_536 <= BLOCK_PAYLOAD_CAP);
    Ok(())
}

#[test]
fn native_payment_exact_fixed_frame_and_first_excess_byte_use_real_signed_terms() -> Result<()> {
    let payer = AccountId::new(key(0x76).public_key().clone());
    let recipient = AccountId::new(key(0x77).public_key().clone());
    let network = builder(&payer, &recipient).build();
    let gateway = network.validators()[0].client_for(&payer, key(0x76).private_key().clone());
    let parameters = Parameters::default();
    require_fixed_parameters(&parameters)?;
    for (extra, allowed) in [(0, true), (1, false)] {
        let (request, transaction) = sized_request(
            gateway.account_client(),
            network.network_id(),
            &payer,
            &recipient,
            "maximum-payment",
            250_000,
            SIGNED_FRAME_CAP + extra,
        )?;
        let (frame, wire) = shape(&transaction)?;
        ensure!(frame == SIGNED_FRAME_CAP + extra && wire < frame);
        ensure!(
            parameters
                .check_signed_transaction_bytes(frame as u64, TransactionInclusionRoute::Global)
                .is_ok()
                == allowed
        );
        let accepted = AcceptedTransaction::accept(
            transaction,
            &network.network_id(),
            Duration::from_secs(1),
            parameters.transaction(),
            &iroha_config::parameters::actual::Crypto::default(),
        );
        if allowed {
            // `ensure!` may evaluate its condition twice; consume the result first.
            let accepted = accepted?;
            ensure!(accepted.encoded_len() == SIGNED_FRAME_CAP);
        } else {
            ensure!(matches!(
                accepted,
                Err(AcceptTransactionFail::TransactionLimit(_))
            ));
        }
        ensure!(request.intent().movements.as_slice().len() == 1);
        ensure!(request.intent().metadata.iter().count() > 1);
        ensure!(
            request
                .intent()
                .metadata
                .iter()
                .all(|(_, value)| { value.get().len() <= iroha_primitives::json::MAX_JSON_BYTES })
        );
    }
    Ok(())
}

async fn refuse_one_over_http(
    peer: &iroha_test_network::NetworkPeer,
    transaction: &SignedTransaction,
    deadline: Instant,
) -> Result<()> {
    ensure!(shape(transaction)?.0 == SIGNED_FRAME_CAP + 1);
    // Send the actual SDK-signed V1 wire directly to preserve the structured HTTP
    // refusal. The public SDK submit report erases that envelope into display text.
    let client = reqwest::Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .build()?;
    let mut response = tokio::time::timeout_at(
        tokio::time::Instant::from_std(deadline),
        client
            .post(format!("{}/v1/pipeline/transactions", peer.torii_url()))
            .header("Content-Type", "application/x-norito")
            .header("Accept", "application/x-norito")
            .body(transaction.encode_wire_v1()?)
            .send(),
    )
    .await??;
    ensure!(
        response.status() == reqwest::StatusCode::BAD_REQUEST,
        "first excess byte must be permanent admission refusal, got {}",
        response.status()
    );
    for (name, expected) in [
        ("content-type", "application/x-norito"),
        ("x-iroha-reject-code", "transaction_rejected"),
    ] {
        let mut values = response.headers().get_all(name).iter();
        ensure!(values.next().is_some_and(|value| value == expected));
        ensure!(
            values.next().is_none(),
            "ambiguous permanent refusal header"
        );
    }
    ensure!(
        !response.headers().contains_key("retry-after"),
        "permanent signed-size refusal must not invite a capacity retry"
    );
    const MAX_ERROR_BYTES: usize = 65_536;
    let mut body = Vec::new();
    while let Some(chunk) =
        tokio::time::timeout_at(tokio::time::Instant::from_std(deadline), response.chunk())
            .await??
    {
        ensure!(chunk.len() <= MAX_ERROR_BYTES - body.len());
        body.extend_from_slice(&chunk);
    }
    let envelope: iroha_torii_shared::ErrorEnvelope = norito::decode_canonical(&body)?;
    let expected = iroha_torii_shared::ErrorEnvelope::new(
        "transaction_rejected",
        format!(
            "failed to accept transaction: Transaction size {} bytes exceeds limit {} bytes",
            SIGNED_FRAME_CAP + 1,
            SIGNED_FRAME_CAP
        ),
    )
    .with_details(iroha_torii_shared::ErrorDetails {
        reject_code: Some("transaction_rejected".to_owned()),
        ..Default::default()
    });
    ensure!(norito::encode_canonical(&envelope)? == norito::encode_canonical(&expected)?);
    ensure!(body == norito::encode_canonical(&expected)?);
    ensure!(Instant::now() < deadline);
    Ok(())
}

fn exact_payment(
    verified: &VerifiedSumeragiBlock,
    expected: HashOf<SignedTransaction>,
) -> Result<&SignedTransaction> {
    let mut inputs = verified.block().network_entrypoints();
    let input = inputs.next().ok_or_else(|| eyre!("missing input"))?;
    let TransactionEntrypoint::External(signed) = input else {
        return Err(eyre!("unexpected non-payment input"));
    };
    ensure!(
        inputs.next().is_none(),
        "unrelated traffic entered the payment block"
    );
    ensure!(signed.hash() == expected && shape(signed)?.0 == SIGNED_FRAME_CAP);
    let (_, output) = verified
        .block()
        .network_output_at(0)
        .ok_or_else(|| eyre!("authenticated payment execution output absent"))?;
    match verified.height() {
        2 => ensure!(matches!(
            &output.result.0,
            Err(TransactionRejectionReason::Validation(
                ValidationFail::InstructionFailed(InstructionExecutionError::Math(
                    MathError::NotEnoughQuantity
                ))
            ))
        )),
        3 => ensure!(output.result.as_ref().is_ok()),
        _ => return Err(eyre!("unexpected maximum payment height")),
    }
    let fee = output
        .result
        .nexus_fee_receipt()
        .ok_or_else(|| eyre!("authenticated payment execution lacks actual fee receipt"))?;
    fee.validate_for_network_input(input, verified.height())
        .map_err(|error| eyre!(error))?;
    // The original signed genesis commits root_fees_v1 with one base unit and zero
    // byte/instruction/gas rates. Independently check that schedule against the
    // original signed source and authenticated output; never infer it from balances.
    ensure!(
        fee.fee_amount == Quantity::one()
            && fee.fee_asset_id == fee_asset()
            && fee.debit_source == FeeDebitSource::Account(signed.authority().clone())
            && fee.dataspace_id == iroha_model_base::topology::DataSpaceId::UNIVERSAL
            && fee.lane_id == iroha_model_base::topology::LaneId::new(0)
            && fee.settlement == NexusFeeSettlementV1::Burn
            && fee.schedule.base_fee == Quantity::one()
            && fee.schedule.per_byte_fee.is_zero()
            && fee.schedule.per_instruction_fee.is_zero()
            && fee.schedule.per_gas_unit_fee.is_zero()
            && fee.schedule.instruction_count == 1
    );
    let payload = verified.block().resultless_proposal_wire_len()?;
    ensure!(payload <= BLOCK_PAYLOAD_CAP && payload >= SIGNED_FRAME_CAP - 40);
    Ok(signed)
}

fn check_balances(
    network: &Network,
    payer: &AccountId,
    recipient: &AccountId,
    attempts: u32,
    transferred: u32,
    deadline: Instant,
) -> Result<()> {
    ensure!(matches!(
        (attempts, transferred),
        (0, 0) | (1, 0) | (2, 250_000)
    ));
    for peer in network.validators() {
        let payer_client = peer
            .client_for(payer, key(0x76).private_key().clone())
            .with_request_deadline(deadline)?;
        let recipient_client = peer
            .client_for(recipient, key(0x77).private_key().clone())
            .with_request_deadline(deadline)?;
        ensure!(
            account_snapshot(&payer_client, payer)?
                == BTreeMap::from([
                    (
                        AssetId::of(principal(), payer.clone()),
                        Quantity::from(1_000_000_u32 - transferred)
                    ),
                    (
                        AssetId::of(fee_asset(), payer.clone()),
                        Quantity::from(100_u32 - attempts)
                    ),
                ])
        );
        let expected_recipient = if transferred == 0 {
            BTreeMap::new()
        } else {
            BTreeMap::from([(
                AssetId::of(principal(), recipient.clone()),
                Quantity::from(transferred),
            )])
        };
        ensure!(account_snapshot(&recipient_client, recipient)? == expected_recipient);
        let system = peer.client().with_request_deadline(deadline)?;
        ensure!(
            system
                .client()
                .query_single(FindAssetDefinitionById::new(fee_asset()))?
                .total_quantity()
                == &Quantity::from(200_u32 - attempts)
        );
        ensure!(
            account_snapshot(&system, &ALICE_ID)?.get(&AssetId::of(fee_asset(), ALICE_ID.clone()))
                == Some(&Quantity::from(100_u32))
        );
        ensure!(Instant::now() < deadline);
    }
    Ok(())
}

#[test]
#[ignore = "four validators, actual 10 MiB payments, signed RS16 and all-node restart; same-source daemon required"]
fn fixed_maximum_payment_and_rejection_survive_http_rs16_kura_and_receipt_recovery() -> Result<()> {
    let payer = AccountId::new(key(0x76).public_key().clone());
    let recipient = AccountId::new(key(0x77).public_key().clone());
    let recipe = builder(&payer, &recipient).with_config_layer(|layer| {
        layer.write(["logger", "format"], "json");
    });
    let (network, rt) = sandbox::start_network_blocking_or_skip(
        recipe,
        stringify!(fixed_maximum_payment_and_rejection_survive_http_rs16_kura_and_receipt_recovery),
    )?
    .ok_or_else(|| eyre!("required fixed-cap network must not skip"))?;
    let deadline = Instant::now() + CASE_TIMEOUT;
    let result = (|| -> Result<()> {
        ensure!(network.validators().len() == 4);
        let (wire, selected) = pins(&network)?;
        let gateway = network.validators()[0]
            .client_for(&payer, key(0x76).private_key().clone())
            .with_request_deadline(deadline)?;
        require_fixed_parameters(&gateway.client().get_parameters()?)?;
        ensure!(bounded(&rt, deadline, gateway.client().status().get())??.blocks == 1);
        let original_pids = transport::processes(&network, &rt, deadline)?;
        ensure!(
            original_pids
                .iter()
                .copied()
                .collect::<std::collections::BTreeSet<_>>()
                .len()
                == 4
        );
        let (_, over) = sized_request(
            gateway.account_client(),
            network.network_id(),
            &payer,
            &recipient,
            "maximum-overrun",
            250_000,
            SIGNED_FRAME_CAP + 1,
        )?;
        for peer in network.validators() {
            bounded(&rt, deadline, refuse_one_over_http(peer, &over, deadline))??;
        }
        for peer in network.validators() {
            ensure!(bounded(&rt, deadline, peer.status())??.blocks == 1);
        }
        check_balances(&network, &payer, &recipient, 0, 0, deadline)?;
        let stores = network.env_dir().join("maximum-payment-workflows");
        let options = NativePaymentRunOptions {
            workflow: WorkflowRunOptions {
                observation_timeout: CASE_TIMEOUT,
                poll_interval: Duration::from_millis(200),
                retry_rejected_step: false,
                ..WorkflowRunOptions::default()
            },
            ..NativePaymentRunOptions::default()
        };
        let (rejected, _) = sized_request(
            gateway.account_client(),
            network.network_id(),
            &payer,
            &recipient,
            "maximum-rejected",
            1_000_001,
            SIGNED_FRAME_CAP,
        )?;
        let rejected_operation = gateway.account_client().native_payment(
            rejected.clone(),
            Arc::new(FileWorkflowStorage::open_or_create(
                stores.join("rejected"),
            )?),
            verifier(&wire, &selected)?,
        )?;
        let failed = bounded(
            &rt,
            deadline,
            rejected_payment::paid_rejection(&rejected_operation, &options),
        )??;
        let identity = rejected_payment::rejected_identity(&failed)?;
        let rejected_hash = bounded(
            &rt,
            deadline,
            rejected_payment::authenticate_rejection(
                &network, &wire, &selected, &rejected, identity, 2,
            ),
        )??;
        bounded(&rt, deadline, network.ensure_blocks(2))??;
        bounded(&rt, deadline, wait_for_applied_height(&network, 2))??;
        check_balances(&network, &payer, &recipient, 1, 0, deadline)?;
        let (request, _) = sized_request(
            gateway.account_client(),
            network.network_id(),
            &payer,
            &recipient,
            "maximum-payment",
            250_000,
            SIGNED_FRAME_CAP,
        )?;
        let operation = gateway.account_client().native_payment(
            request.clone(),
            Arc::new(FileWorkflowStorage::open_or_create(stores.join("success"))?),
            verifier(&wire, &selected)?,
        )?;
        let completed = bounded(&rt, deadline, operation.submit(&options))??;
        ensure!(completed.receipt.settlement().block_height == 3);
        ensure!(completed.receipt.settlement().metadata == request.intent().metadata);
        ensure!(
            completed
                .receipt
                .nexus_fee_receipt()
                .is_some_and(|fee| fee.fee_amount == Quantity::one()
                    && fee.fee_asset_id == fee_asset()
                    && fee.debit_source == FeeDebitSource::Account(payer.clone())
                    && fee.block_height == 3
                    && fee.settlement == NexusFeeSettlementV1::Burn)
        );
        let success_hash = completed.receipt.transaction_hash();
        let success_context = completed.receipt.context_id();
        let destination = AssetId::of(principal(), recipient.clone());
        let customer = "maximum-customer".parse()?;
        let inbox = PaymentInbox::new(Arc::new(FileWorkflowStorage::open_or_create(
            stores.join("bank"),
        )?))?;
        ensure!(
            inbox.credit(&completed.receipt, &customer, &destination)?
                == PaymentCreditStatus::Recorded
        );
        bounded(&rt, deadline, network.ensure_blocks(3))??;
        bounded(&rt, deadline, wait_for_applied_height(&network, 3))??;
        let mut contexts = [None; 2];
        for (index, peer) in network.validators().iter().enumerate() {
            let client = peer.client().with_request_deadline(deadline)?;
            let mut trusted = verifier(&wire, &selected)?;
            for (height, hash) in [(2, rejected_hash), (3, success_hash)] {
                let proof = client.client().get_sumeragi_finality_proof(
                    NonZeroU64::new(height).unwrap(),
                    SumeragiRootScope::Global,
                )?;
                let verified = trusted.verify(&proof)?;
                exact_payment(&verified, hash)?;
                let expected_context = &mut contexts[(height - 2) as usize];
                ensure!(
                    expected_context.is_none_or(|expected| expected == verified.context_id()),
                    "validators disagree on certified decision"
                );
                *expected_context = Some(verified.context_id());
                if height == 3 {
                    ensure!(verified.context_id() == success_context);
                }
                transport::verify_rows(&network, peer, original_pids[index], &verified, deadline)?;
            }
        }
        check_balances(&network, &payer, &recipient, 2, 250_000, deadline)?;
        drop(inbox);
        drop(completed);
        drop(operation);
        drop(rejected_operation);
        drop(gateway);
        bounded(&rt, deadline, network.shutdown())?;
        transport::verify_cold_stores(
            &network,
            &wire,
            &selected,
            [rejected_hash, success_hash],
            contexts.map(|value| value.expect("each independently verified maximum block")),
            deadline,
        )?;
        bounded(&rt, deadline, network.start_all())??;
        bounded(&rt, deadline, network.ensure_blocks(3))??;
        bounded(&rt, deadline, wait_for_applied_height(&network, 3))??;
        let restarted_pids = transport::processes(&network, &rt, deadline)?;
        ensure!(
            restarted_pids
                .iter()
                .zip(&original_pids)
                .all(|(now, old)| now != old)
        );
        for peer in network.validators() {
            let resumed = peer
                .client_for(&payer, key(0x76).private_key().clone())
                .with_request_deadline(deadline)?;
            let success = resumed.account_client().native_payment(
                request.clone(),
                Arc::new(FileWorkflowStorage::open_or_create(stores.join("success"))?),
                verifier(&wire, &selected)?,
            )?;
            let receipt = bounded(&rt, deadline, success.recover(&options))??
                .receipt
                .ok_or_else(|| eyre!("maximum receipt absent after restart"))?;
            ensure!(
                receipt.transaction_hash() == success_hash
                    && receipt.context_id() == success_context
                    && receipt.settlement().metadata == request.intent().metadata
            );
            let inbox = PaymentInbox::new(Arc::new(FileWorkflowStorage::open_or_create(
                stores.join("bank"),
            )?))?;
            ensure!(
                inbox.credit(&receipt, &customer, &destination)?
                    == PaymentCreditStatus::AlreadyRecorded {
                        notification_pending: true
                    }
            );
            let failure = resumed.account_client().native_payment(
                rejected.clone(),
                Arc::new(FileWorkflowStorage::open_or_create(
                    stores.join("rejected"),
                )?),
                verifier(&wire, &selected)?,
            )?;
            let recovery = bounded(&rt, deadline, failure.recover(&options))??;
            ensure!(recovery.receipt.is_none());
            let recovered_carrier = recovery
                .carrier
                .as_ref()
                .ok_or_else(|| eyre!("rejected carrier missing"))?;
            let recovered_identity = rejected_payment::rejected_identity(recovered_carrier)?;
            ensure!(recovered_identity == identity);
            ensure!(bounded(&rt, deadline, resumed.client().status().get())??.blocks == 3);
        }
        check_balances(&network, &payer, &recipient, 2, 250_000, deadline)?;
        ensure!(
            Instant::now() < deadline,
            "fixed-cap case exceeded its original deadline"
        );
        Ok(())
    })();
    rt.block_on(network.shutdown_and_release());
    result
}
