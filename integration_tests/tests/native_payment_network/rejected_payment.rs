//! A real included rejection never becomes a verified payment, including after restart.
//!
//! Rejected monetary intent is not a successful settlement identity. Read-only
//! recovery never retries it; an explicit submit at a fresh gateway is a separately
//! authorized attempt and may pay another fee without producing any principal credit.

use super::*;
use iroha::{
    client::{NativePaymentError, NativePaymentOperation, VerifiedPaymentReceipt},
    workflow::{
        AttemptEvidenceKindV1, TransactionIdentityV1, WorkflowErrorCode, WorkflowProgressV1,
        WorkflowStage,
    },
};
use iroha_crypto::{Hash, HashOf};
use iroha_data_model::{
    ValidationFail,
    block::{SignedBlock, consensus::SumeragiRootScope},
    isi::{
        SettlementInstructionBox,
        error::{InstructionExecutionError, MathError},
    },
    query::CommittedTransaction,
    transaction::{
        Executable, SignedTransaction, TransactionEntrypoint, error::TransactionRejectionReason,
    },
};
use std::collections::BTreeMap;

fn evidence(block: &SignedBlock, input: u32) -> Result<CommittedTransaction> {
    let entrypoint = block
        .network_entrypoint_at(usize::try_from(input)?)
        .ok_or_else(|| eyre!("original signed input is absent"))?
        .clone();
    let (output_index, _) = block
        .network_output_at(input)
        .ok_or_else(|| eyre!("original execution output is absent"))?;
    let output = block
        .execution_outputs()
        .get(usize::try_from(output_index)?)
        .ok_or_else(|| eyre!("original output index is absent"))?
        .clone();
    Ok(CommittedTransaction {
        block_hash: block.hash(),
        entrypoint_hash: entrypoint.hash(),
        entrypoint_proof: block
            .network_input_proof(input)
            .ok_or_else(|| eyre!("input proof absent"))?,
        entrypoint,
        output_hash: HashOf::new(&output),
        output_proof: block
            .output_proof(output_index)
            .ok_or_else(|| eyre!("output proof absent"))?,
        output,
    })
}

pub(super) fn rejected_identity(progress: &WorkflowProgressV1) -> Result<TransactionIdentityV1> {
    let [step] = progress.steps.as_slice() else {
        return Err(eyre!("payment must have one exact step"));
    };
    let [attempt] = step.identities.as_slice() else {
        return Err(eyre!("default policy must retain one carrier identity"));
    };
    ensure!(step.state == "rejected" && progress.partial_completion.confirmed_steps.is_empty());
    ensure!(attempt.dispatch_ordinal > 0);
    ensure!(
        attempt
            .evidence
            .as_ref()
            .is_some_and(|e| e.kind == AttemptEvidenceKindV1::LedgerRejected),
        "included rejection requires authenticated execution, not submission refusal"
    );
    attempt
        .identity
        .ok_or_else(|| eyre!("included rejection lost its exact signed identity"))
}

pub(super) async fn paid_rejection(
    operation: &NativePaymentOperation,
    options: &NativePaymentRunOptions,
) -> Result<WorkflowProgressV1> {
    let error = operation
        .submit(options)
        .await
        .expect_err("included-but-rejected payment must not return VerifiedPaymentReceipt");
    let NativePaymentError::Workflow(error) = error else {
        return Err(eyre!("expected an authenticated rejection, got {error:?}"));
    };
    ensure!(
        error.code == WorkflowErrorCode::Rejected && error.stage == WorkflowStage::Reconcile,
        "a transport or admission failure does not exercise included rejection: {error:?}"
    );
    let recovered = operation.recover(options).await?;
    ensure!(
        recovered.receipt.is_none(),
        "recovery must not turn included rejection into successful settlement"
    );
    let progress = recovered
        .carrier
        .ok_or_else(|| eyre!("rejected journal missing"))?;
    rejected_identity(&progress)?;
    Ok(progress)
}

pub(super) async fn authenticate_rejection(
    network: &Network,
    wire: &[u8],
    pins: &SignedGenesisPinsV1,
    request: &NativePaymentRequest,
    identity: TransactionIdentityV1,
    height: u64,
) -> Result<HashOf<SignedTransaction>> {
    let payer = request.intent().settlement_id.owner();
    let client = network.validators()[2].client_for(payer, key(0x76).private_key().clone());
    let hash = HashOf::from_untyped_unchecked(Hash::prehashed(identity.signed_transaction_hash));
    let mut trusted = verifier(wire, pins)?;
    ensure!((2..=3).contains(&height));
    let next = trusted.authenticated_height().unwrap_or(0) + 1;
    for candidate_height in next..=height {
        let proof = client
            .client()
            .get_sumeragi_finality_proof_async(
                NonZeroU64::new(candidate_height).unwrap(),
                SumeragiRootScope::Global,
            )
            .await?;
        let verified = trusted.verify(&proof)?;
        if candidate_height != height {
            continue;
        }
        let matches = verified
            .block()
            .network_entrypoints()
            .enumerate()
            .filter_map(|(i, entry)| match entry {
                TransactionEntrypoint::External(signed) if signed.hash() == hash => {
                    Some((i, signed))
                }
                _ => None,
            })
            .collect::<Vec<_>>();
        let [(index, signed)] = matches.as_slice() else {
            return Err(eyre!(
                "exact included rejected carrier absent or duplicated"
            ));
        };
        ensure!(
            signed.authority() == payer && signed.fee_payment_intent() == request.fee_payment()
        );
        ensure!(Hash::from(signed.hash_as_entrypoint()).as_ref() == &identity.entrypoint_hash);
        let Executable::Instructions(instructions) = signed.instructions() else {
            return Err(eyre!("expected direct signed payment"));
        };
        let [instruction] = instructions.as_ref() else {
            return Err(eyre!("expected one exact payment instruction"));
        };
        let terms = instruction
            .as_any()
            .downcast_ref::<SettleAtomic>()
            .or_else(|| {
                match instruction
                    .as_any()
                    .downcast_ref::<SettlementInstructionBox>()
                {
                    Some(SettlementInstructionBox::Atomic(terms)) => Some(terms),
                    _ => None,
                }
            })
            .ok_or_else(|| eyre!("included instruction is not atomic settlement"))?;
        ensure!(norito::encode_canonical(terms)? == norito::encode_canonical(request.intent())?);
        let included = evidence(verified.block(), u32::try_from(*index)?)?;
        verified.verify_transaction_execution(&network.network_id(), &included)?;
        ensure!(
            matches!(
                &included.result().0,
                Err(TransactionRejectionReason::Validation(
                    ValidationFail::InstructionFailed(InstructionExecutionError::Math(
                        MathError::NotEnoughQuantity
                    ))
                ))
            ),
            "expected genuine principal insufficiency, got {:?}",
            included.result()
        );
        ensure!(
            verified
                .verify_committed_transaction(&network.network_id(), &included)
                .is_err(),
            "successful-outcome verification must refuse an included rejection"
        );
        let fee = included
            .result()
            .nexus_fee_receipt()
            .ok_or_else(|| eyre!("included rejection lacks actual fee receipt"))?;
        ensure!(
            fee.fee_amount == Quantity::one()
                && fee.block_height == height
                && fee.fee_asset_id == fee_asset()
                && fee.debit_source == FeeDebitSource::Account(payer.clone())
                && fee.settlement == NexusFeeSettlementV1::Burn
                && fee.dataspace_id == iroha_model_base::topology::DataSpaceId::UNIVERSAL
        );
        ensure!(
            VerifiedPaymentReceipt::verify(
                &verified,
                network.network_id(),
                hash,
                request.intent(),
                included
            )
            .is_err(),
            "membership alone must not construct a verified payment receipt"
        );
        return Ok(hash);
    }
    Err(eyre!("certified rejected carrier was not authenticated"))
}

fn check_principal_and_fees(
    network: &Network,
    payer: &AccountId,
    recipient: &AccountId,
    attempts: u32,
) -> Result<()> {
    ensure!((1..=2).contains(&attempts));
    for peer in network.validators() {
        let payer_client = peer.client_for(payer, key(0x76).private_key().clone());
        let recipient_client = peer.client_for(recipient, key(0x77).private_key().clone());
        ensure!(
            account_snapshot(&payer_client, payer)?
                == BTreeMap::from([
                    (
                        AssetId::of(principal(), payer.clone()),
                        Quantity::from(1_000_000_u32)
                    ),
                    (
                        AssetId::of(fee_asset(), payer.clone()),
                        Quantity::from(100_u32 - attempts)
                    ),
                ]),
            "rejected principal must remain untouched; only authenticated attempt fees may burn"
        );
        ensure!(
            account_snapshot(&recipient_client, recipient)?.is_empty(),
            "complete successful query must show no customer principal credit; errors are never zero"
        );
        let system = peer.client();
        ensure!(
            account_snapshot(&system, &ALICE_ID)?.get(&AssetId::of(fee_asset(), ALICE_ID.clone()))
                == Some(&Quantity::from(100_u32))
        );
        ensure!(
            system
                .client()
                .query_single(FindAssetDefinitionById::new(fee_asset()))?
                .total_quantity()
                == &Quantity::from(200_u32 - attempts)
        );
    }
    Ok(())
}

async fn require_idle(network: &Network, height: u64) -> Result<()> {
    let end = tokio::time::Instant::now() + Duration::from_secs(3);
    while tokio::time::Instant::now() < end {
        for peer in network.validators() {
            ensure!(
                status_poll::read_until(end, || peer.status()).await?.blocks == height,
                "read-only rejection recovery produced successor traffic"
            );
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    Ok(())
}

#[test]
#[ignore = "four validators and all-node restart; isolated permits and immutable same-source daemon required"]
fn included_rejected_payment_never_credits_customer_across_restart_and_explicit_gateway_retry()
-> Result<()> {
    let payer = AccountId::new(key(0x76).public_key().clone());
    let recipient = AccountId::new(key(0x77).public_key().clone());
    let (network, rt) = sandbox::start_network_blocking_or_skip(builder(&payer, &recipient),
        stringify!(included_rejected_payment_never_credits_customer_across_restart_and_explicit_gateway_retry))?
        .ok_or_else(|| eyre!("required four-process rejection acceptance cannot skip startup"))?;
    let result = (|| -> Result<()> {
        ensure!(network.validators().len() == 4 && network.topology_entries().len() == 4);
        let (wire, selected) = pins(&network)?;
        let pids = rt.block_on(async {
            let mut ids = Vec::new();
            for peer in network.validators() {
                ids.push(
                    peer.process_id()
                        .await
                        .ok_or_else(|| eyre!("validator process missing"))?,
                );
            }
            Ok::<_, eyre::Report>(ids)
        })?;
        let request = NativePaymentRequest::new(
            SettleAtomic::new(
                network.network_id(),
                SettlementId::new(payer.clone(), "insufficient-1000001".parse()?),
                AtomicSettlementMovements::try_from(vec![AtomicSettlementMovement {
                    source: AssetId::of(principal(), payer.clone()),
                    recipient: recipient.clone(),
                    quantity: 1_000_001_u32.into(),
                }])
                .map_err(|e| eyre!(e))?,
                AtomicSettlementEscrows::empty(),
                NonZeroU64::new(101).unwrap(),
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
        let stores = network.env_dir().join("rejected-payment-workflows");
        let options = NativePaymentRunOptions {
            workflow: WorkflowRunOptions {
                observation_timeout: Duration::from_secs(120),
                poll_interval: Duration::from_millis(200),
                retry_rejected_step: false,
                ..WorkflowRunOptions::default()
            },
            ..NativePaymentRunOptions::default()
        };
        let gateway = network.validators()[0].client_for(&payer, key(0x76).private_key().clone());
        ensure!(rt.block_on(gateway.client().status().get())?.blocks == 1);
        let operation = gateway.account_client().native_payment(
            request.clone(),
            Arc::new(FileWorkflowStorage::open_or_create(
                stores.join("original"),
            )?),
            verifier(&wire, &selected)?,
        )?;
        let first = rt.block_on(paid_rejection(&operation, &options))?;
        let identity = rejected_identity(&first)?;
        rt.block_on(wait_for_applied_height(&network, 2))?;
        let original_hash = rt.block_on(authenticate_rejection(
            &network, &wire, &selected, &request, identity, 2,
        ))?;
        check_principal_and_fees(&network, &payer, &recipient, 1)?;
        let error = rt.block_on(operation.resume(&options)).expect_err(
            "resume must not reinterpret a retained rejected carrier as successful payment",
        );
        ensure!(matches!(error, NativePaymentError::Workflow(ref error)
            if error.code == WorkflowErrorCode::Rejected));
        let repeat = rt.block_on(operation.recover(&options))?;
        ensure!(repeat.receipt.is_none());
        let repeat = repeat
            .carrier
            .ok_or_else(|| eyre!("same journal lost rejected identity"))?;
        ensure!(
            repeat.steps[0].identities == first.steps[0].identities,
            "same journal/default policy must not create another paid rejected carrier"
        );
        rt.block_on(require_idle(&network, 2))?;
        drop(operation);
        drop(gateway);
        rt.block_on(network.shutdown());
        rt.block_on(network.start_all())?;
        rt.block_on(wait_for_applied_height(&network, 2))?;
        rt.block_on(async {
            for (peer, old) in network.validators().iter().zip(&pids) {
                ensure!(peer.process_id().await.is_some_and(|pid| pid != *old));
            }
            Ok::<_, eyre::Report>(())
        })?;
        let gateway = network.validators()[1].client_for(&payer, key(0x76).private_key().clone());
        let resumed = gateway.account_client().native_payment(
            request.clone(),
            Arc::new(FileWorkflowStorage::open_or_create(
                stores.join("original"),
            )?),
            verifier(&wire, &selected)?,
        )?;
        let recovered = rt.block_on(resumed.recover(&options))?;
        ensure!(recovered.receipt.is_none());
        let recovered = recovered
            .carrier
            .ok_or_else(|| eyre!("original carrier journal missing after restart"))?;
        ensure!(recovered.steps[0].identities == first.steps[0].identities);
        ensure!(
            rt.block_on(authenticate_rejection(
                &network,
                &wire,
                &selected,
                &request,
                rejected_identity(&recovered)?,
                2
            ))? == original_hash
        );
        let fresh = network.validators()[3]
            .client_for(&payer, key(0x76).private_key().clone())
            .account_client()
            .native_payment(
                request.clone(),
                Arc::new(FileWorkflowStorage::open_or_create(
                    stores.join("fresh-gateway"),
                )?),
                verifier(&wire, &selected)?,
            )?;
        let absent_success = rt.block_on(fresh.recover(&options))?;
        ensure!(
            absent_success.receipt.is_none() && absent_success.carrier.is_none(),
            "fresh read-only recovery must neither invent success nor sign a carrier"
        );
        let missing = rt.block_on(fresh.resume(&options)).expect_err(
            "fresh resume must require explicit new-attempt authorization rather than sign another rejected payment"
        );
        ensure!(
            matches!(
                missing,
                NativePaymentError::NewAttemptAuthorizationRequired { progress: None }
            ),
            "missing-journal resume must preserve typed authorization refusal: {missing:?}"
        );
        let still_unsubmitted = rt.block_on(fresh.recover(&options))?;
        ensure!(
            still_unsubmitted.receipt.is_none() && still_unsubmitted.carrier.is_none(),
            "refused resume must not create a signed identity or fee-producing carrier"
        );
        rt.block_on(require_idle(&network, 2))?;
        check_principal_and_fees(&network, &payer, &recipient, 1)?;
        // This is an explicit second business attempt. Failed execution did not
        // create a successful settlement receipt, so a new gateway may sign and
        // pay again. We deliberately do not claim exactly-once rejection fees.
        let second = rt.block_on(paid_rejection(&fresh, &options))?;
        rt.block_on(wait_for_applied_height(&network, 3))?;
        let second_hash = rt.block_on(authenticate_rejection(
            &network,
            &wire,
            &selected,
            &request,
            rejected_identity(&second)?,
            3,
        ))?;
        ensure!(
            second_hash != original_hash,
            "explicit fresh gateway attempt must have its own exact identity"
        );
        ensure!(rt.block_on(resumed.recover(&options))?.receipt.is_none());
        ensure!(rt.block_on(fresh.recover(&options))?.receipt.is_none());
        check_principal_and_fees(&network, &payer, &recipient, 2)?;
        rt.block_on(require_idle(&network, 3))?;
        Ok(())
    })();
    rt.block_on(network.shutdown_and_release());
    result
}
