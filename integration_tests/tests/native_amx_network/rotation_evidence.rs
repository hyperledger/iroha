//! Delayed source evidence and exact unknown carrier identity for the real rotation test.

use super::*;
use crate::amx_harness::{self as amx, proofs::Observer};
use iroha::workflow::{WorkflowJournalV1, contract::MAX_WORKFLOW_JOURNAL_BYTES_V1};
use iroha_data_model::sumeragi_finality::{VerifiedSumeragiBlock, authenticate_signed_genesis_v1};
use iroha_data_model::{
    isi::sumeragi_amx::{PrepareAmxV1, SettleAmxV1},
    sumeragi_amx::{AmxDebitApprovalV1, AmxRecordV1, AmxTransactionV1},
    transaction::{Executable, SignedTransaction, TransactionEntrypoint},
};
use iroha_version::codec::DecodeVersioned as _;

pub(super) async fn global_at(root: &amx::Root, height: u64) -> Result<VerifiedSumeragiBlock> {
    ensure!((2..=ROTATION_HISTORY_BOUND).contains(&height));
    let mut verifier = root.verifier()?;
    let client = root.client(&amx::genesis_key(0));
    let mut last = None;
    for at in verifier.authenticated_height().unwrap_or(0) + 1..=height {
        let proof = client
            .client()
            .get_sumeragi_finality_proof_async(NonZeroU64::new(at).unwrap(), root.scope)
            .await?;
        last = Some(verifier.verify(&proof)?);
    }
    last.ok_or_else(|| eyre!("authenticated Global carrier absent"))
}

pub(super) fn assert_boundary(
    block: &VerifiedSumeragiBlock,
    epoch: u64,
    current: usize,
    successor: usize,
    generation: u64,
) -> Result<()> {
    let schedule = &block.commitment().schedule;
    let boundary = schedule
        .boundary
        .as_ref()
        .ok_or_else(|| eyre!("actual epoch boundary absent"))?;
    ensure!(
        schedule.current.authorization.epoch == epoch
            && schedule.current.committee.len() == current
            && boundary.next.authorization.epoch == epoch + 1
            && boundary.next.authorization.authority_generation == generation
            && boundary.next.committee.len() == successor,
        "original certified boundary must authorize the exact 4→7→4 history"
    );
    Ok(())
}

pub(super) fn wait_frozen_obligation(
    exchange: &amx::Exchange,
    transaction: &AmxTransactionV1,
    approval: &AmxDebitApprovalV1,
    original_prepare: &PendingCarrier,
    prepare_fee: &Quantity,
) -> Result<()> {
    let root = &exchange.roots[2];
    let tx = transaction.id()?;
    let mut observer = Observer::new(root, &exchange.roots[0])?;
    exchange.runtime.block_on(async {
        let deadline = tokio::time::Instant::now() + WAIT;
        let mut last_acquisition = None;
        let result = tokio::time::timeout_at(deadline, async {
        loop {
            let mut retry_delay = POLL;
            let attempt = async {
                observer.refresh(root, tx, deadline).await?;
                let proof = observer.world(root, approval, deadline).await?;
                if !observer.balance_observation(&proof, 1,
                    [amx::PRINCIPAL - 250, 0, 250], &[[amx::PRINCIPAL, 0, 0]],
                )? { return Ok(false); }
                let tip = observer
                    .tip
                    .as_ref()
                    .ok_or_else(|| eyre!("no original bank cut"))?;
                let world = proof.world.authenticate(tip)?;
                world.verify_asset_absent(&AssetId::with_scope(
                    amx::fee_asset(),
                    amx::account(&amx::relay(2)),
                    AssetBalanceScope::Dataspace(amx::DATASPACES[1]),
                ))?;
                // Replay all original bank inputs: the exact previously signed
                // Prepare must consume its metered funding under the signed policy.
                let mut verifier = root.verifier()?;
                let mut prepared = false;
                for height in verifier.authenticated_height().unwrap_or(0) + 1..=tip.height() {
                    let proof = root
                        .client(&amx::relay(2))
                        .client()
                        .get_sumeragi_finality_proof_async(
                            NonZeroU64::new(height).unwrap(),
                            root.scope,
                        )
                        .await?;
                    let block = verifier.verify(&proof)?;
                    for (index, input) in block.block().network_entrypoints().enumerate() {
                        let TransactionEntrypoint::External(signed) = input else {
                            continue;
                        };
                        let Executable::Instructions(instructions) = signed.instructions() else {
                            continue;
                        };
                        if !instructions.iter().any(|instruction| {
                            instruction
                                .as_any()
                                .downcast_ref::<PrepareAmxV1>()
                                .is_some_and(|prepare| {
                                    prepare.transaction.id().is_ok_and(|id| id == tx)
                                })
                        }) {
                            continue;
                        }
                        let evidence = amx::proofs::evidence(block.block(), index.try_into()?)?;
                        block
                            .verify_committed_transaction(&root.network.network_id(), &evidence)?;
                        let fee = evidence
                            .output
                            .result()
                            .nexus_fee_receipt()
                            .ok_or_else(|| eyre!("Prepare fee absent"))?;
                        fee.validate_for_network_input(&evidence.entrypoint, height)
                            .map_err(|error| eyre!(error))?;
                        ensure!(
                            signed.hash() == original_prepare.hash()
                                && &fee.fee_amount == prepare_fee
                                && fee.schedule.base_fee == Quantity::one()
                                && fee.schedule.per_byte_fee.is_zero()
                                && fee.schedule.per_instruction_fee == Quantity::one()
                                && fee.schedule.per_gas_unit_fee == Quantity::one(),
                            "the exact original Prepare consumes its independently computed metered funding"
                        );
                        prepared = true;
                    }
                }
                ensure!(
                    prepared,
                    "empty relay fee account must be explained by its successful original Prepare"
                );
                ensure!(
                    observer.delivery.is_none(),
                    "fee-blocked bank must retain its unresolved original escrow"
                );
                Ok::<_, eyre::Report>(true)
            }.await;
            match attempt {
                Ok(true) => return Ok(()),
                Ok(false) => {},
                Err(error) => {
                    if !amx::proofs::retryable_approval_error(&error) {
                        if error.is::<tokio::time::error::Elapsed>() && tokio::time::Instant::now() >= deadline {
                            return Err(amx::proofs::approval_deadline_error(last_acquisition.take(), format!("original unresolved escrow HTTP deadline: {error}")));
                        }
                        return Err(error);
                    }
                    retry_delay = retry_delay.max(amx::proofs::approval_retry_delay(&error));
                    last_acquisition = Some(error);
                }
            }
            tokio::time::sleep_until(tokio::time::Instant::now().checked_add(retry_delay).unwrap_or(deadline).min(deadline)).await;
        }
        }).await;
        result.map_err(|error| amx::proofs::approval_deadline_error(last_acquisition,
            format!("original unresolved escrow proof deadline: {error}")))?
    })
}

pub(super) struct PendingCarrier {
    pub signed: SignedTransaction,
    pub bytes: Vec<u8>,
    pub dispatches: u8,
}
impl std::ops::Deref for PendingCarrier {
    type Target = SignedTransaction;
    fn deref(&self) -> &Self::Target {
        &self.signed
    }
}
#[derive(Clone, Copy)]
pub(super) enum PendingKind {
    Prepare,
    Settle,
}
pub(super) fn pending_carrier(
    exchange: &amx::Exchange,
    tx: [u8; 32],
    kind: PendingKind,
) -> Result<PendingCarrier> {
    // Local bytes identify a pending request only. They never prove execution,
    // rejection, absence or authority. Actual settlement is checked independently.
    let directory = exchange.custody.as_path().join("workflow-0");
    let mut count = 0;
    let mut selected = None;
    for row in fs::read_dir(directory)? {
        count += 1;
        ensure!(
            count <= 128,
            "fixture journal inspection exceeds finite workflow bound"
        );
        let row = row?;
        if !row.file_type()?.is_dir() {
            continue;
        }
        let path = row.path().join("journal");
        if !path.exists() {
            continue;
        }
        ensure!(fs::metadata(&path)?.len() <= MAX_WORKFLOW_JOURNAL_BYTES_V1 as u64);
        let journal = WorkflowJournalV1::decode_record(&fs::read(path)?)?;
        for step in &journal.steps {
            let Some(operation) = &step.transaction else {
                continue;
            };
            let Some(bytes) = &operation.signed_transaction else {
                continue;
            };
            let signed = SignedTransaction::decode_all_versioned(bytes)?;
            if signed.network_id() != Some(&exchange.roots[2].network.network_id()) {
                continue;
            }
            let Executable::Instructions(instructions) = signed.instructions() else {
                continue;
            };
            if instructions.len() == 1 && instructions.iter().any(|instruction| match kind {
                PendingKind::Prepare => instruction.as_any().downcast_ref::<PrepareAmxV1>()
                    .is_some_and(|prepare| prepare.transaction.id().is_ok_and(|id| id == tx)),
                PendingKind::Settle => instruction.as_any().downcast_ref::<SettleAmxV1>()
                    .is_some_and(|settle| matches!(&settle.decision.record, AmxRecordV1::Decision(value) if value.tx == tx)),
            }) {
                ensure!(selected.is_none(), "one source-bound pending carrier journal expected");
                ensure!(signed.authority() == &amx::account(&amx::relay(2)));
                signed.verify_signature()?;
                let attempt = operation.attempts.last().ok_or_else(|| eyre!("pending carrier lacks an identity"))?;
                ensure!(operation.attempts.len() == 1 && attempt.evidence.is_none(),
                    "the delayed relayer must preserve its original unresolved identity");
                ensure!(attempt.dispatch_ordinal > 0, "original carrier has not yet attempted dispatch");
                selected = Some(PendingCarrier { signed, bytes: bytes.clone(), dispatches: attempt.dispatch_ordinal });
            }
        }
    }
    selected.ok_or_else(|| eyre!("fee-blocked original carrier has not yet been durably signed"))
}

/// Stop the actual service before normal bounded retries are exhausted. This is
/// explicit P0 test isolation, not a protocol or autonomous-liveness claim.
pub(super) fn pause_with_pending(
    exchange: &amx::Exchange,
    tx: [u8; 32],
    kind: PendingKind,
) -> Result<PendingCarrier> {
    let deadline = Instant::now() + WAIT;
    loop {
        match pending_carrier(exchange, tx, kind) {
            Ok(_) => break,
            Err(error) if Instant::now() < deadline => {
                eprintln!("awaiting original delayed carrier: {error}");
                std::thread::sleep(POLL);
            }
            Err(error) => return Err(error),
        }
    }
    exchange
        .runtime
        .block_on(exchange.roots[0].pause_service())?;
    let carrier = pending_carrier(exchange, tx, kind)?;
    ensure!(
        carrier.dispatches < iroha::workflow::contract::MAX_DISPATCHES_PER_IDENTITY_V1,
        "setup exhausted the original eight-dispatch bound before deliberate pause"
    );
    require_live_carrier(&exchange.roots[2], &carrier)?;
    Ok(carrier)
}

pub(super) fn assert_preserved(
    exchange: &amx::Exchange,
    tx: [u8; 32],
    kind: PendingKind,
    original: &PendingCarrier,
) -> Result<()> {
    let actual = pending_carrier(exchange, tx, kind)?;
    ensure!(
        actual.bytes == original.bytes && actual.dispatches == original.dispatches,
        "deliberate pause must preserve exact signed bytes and original dispatch count"
    );
    require_live_carrier(&exchange.roots[2], &actual)
}

pub(super) fn require_live_carrier(root: &amx::Root, carrier: &SignedTransaction) -> Result<()> {
    let ttl = carrier
        .time_to_live()
        .ok_or_else(|| eyre!("rotation carrier needs finite original TTL"))?;
    let selected = authenticate_signed_genesis_v1(&root.genesis_wire, &root.pins)?;
    let max = selected
        .block()
        .external_transactions()
        .flat_map(|signed| match signed.instructions() {
            Executable::Instructions(instructions) => instructions.iter(),
            _ => panic!("signed genesis must retain original instruction parameters"),
        })
        .filter_map(|instruction| instruction.as_any().downcast_ref::<SetParameter>())
        .filter_map(|instruction| match instruction.inner() {
            Parameter::Transaction(
                iroha_data_model::parameter::system::TransactionParameter::MaxTimeToLiveMs(value),
            ) => Some(value.get()),
            _ => None,
        })
        .collect::<Vec<_>>();
    ensure!(
        max.len() == 1 && ttl.as_millis() <= u128::from(max[0]),
        "original finite TTL must fit signed genesis policy"
    );
    let expires = carrier
        .creation_time()
        .checked_add(ttl)
        .ok_or_else(|| eyre!("carrier expiry overflow"))?;
    ensure!(
        u128::from(amx::now_ms()?) < expires.as_millis(),
        "rotation setup exhausted original carrier TTL; do not replace an ambiguous identity"
    );
    Ok(())
}

/// Compute funding from the original signed immutable policy and the actual
/// native gas owner. It grants no execution authority; the later receipt and
/// authenticated zero balance must prove this exact amount was charged.
pub(super) fn native_carrier_fee(
    root: &amx::Root,
    carrier: &SignedTransaction,
) -> Result<Quantity> {
    let selected = authenticate_signed_genesis_v1(&root.genesis_wire, &root.pins)?;
    let mut policies = Vec::new();
    for signed in selected.block().external_transactions() {
        let Executable::Instructions(instructions) = signed.instructions() else {
            return Err(eyre!("non-instruction genesis"));
        };
        for instruction in instructions {
            let Some(set) = instruction.as_any().downcast_ref::<SetParameter>() else {
                continue;
            };
            let Parameter::Custom(parameter) = set.inner() else {
                continue;
            };
            if parameter.id() == &iroha_data_model::block::consensus::RootFeePolicy::parameter_id()
            {
                policies.push(
                    iroha_data_model::block::consensus::RootFeePolicy::from_custom_parameter(
                        parameter,
                    )?,
                );
            }
        }
    }
    ensure!(
        policies.len() == 1,
        "one original immutable private fee policy required"
    );
    let policy = &policies[0];
    let scope = &selected.metadata().sumeragi_context.root_scope;
    ensure!(
        *scope == root.scope
            && matches!(
                scope,
                iroha_data_model::block::consensus::SumeragiRootScope::Dataspace { .. }
            ),
        "original private fee policy must belong to the pinned bank root"
    );
    policy
        .validate_for_scope(scope)
        .map_err(|error| eyre!("original root fee policy is invalid for its scope: {error:?}"))?;
    ensure!(policy.fee_asset_id == amx::fee_asset() && policy.per_byte_fee.is_zero());
    let Executable::Instructions(instructions) = carrier.instructions() else {
        return Err(eyre!("original AMX instructions absent"));
    };
    ensure!(
        instructions.len() == 1
            && instructions
                .iter()
                .all(|i| i.as_any().is::<PrepareAmxV1>() || i.as_any().is::<SettleAmxV1>())
    );
    // These native AMX ISIs do not consult confidential proof schedules. Use the
    // production meter, not a duplicated gas constant.
    let gas = iroha_core::gas::meter_instructions(
        instructions.as_ref(),
        &iroha_core::gas::DEFAULT_ZK_GAS,
    )
    .map_err(|error| eyre!("native gas metering refused the original AMX carrier: {error:?}"))?;
    let instruction_charge =
        policy
            .per_instruction_fee
            .try_mul_decimal(&iroha_primitives::numeric::Numeric::from(
                instructions.len() as u64,
            ))?;
    let gas_charge = policy
        .per_gas_unit_fee
        .try_mul_decimal(&iroha_primitives::numeric::Numeric::from(gas))?;
    let amount = policy
        .base_fee
        .checked_add(&instruction_charge)?
        .checked_add(&gas_charge)?;
    ensure!(!amount.is_zero());
    Ok(amount)
}

/// A separately authorized replay pays its own fee and must be certified rejected
/// for retired/settled authority, preserving the first successful monetary effect.
pub(super) fn rejected_replay(
    exchange: &amx::Exchange,
    original: &SignedTransaction,
) -> Result<()> {
    let root = &exchange.roots[2];
    let client = root.client(&amx::relay(2));
    let account = client.account_client();
    let Executable::Instructions(instructions) = original.instructions() else {
        return Err(eyre!("original native input absent"));
    };
    let payload = account.prepare_transaction(iroha::client::AccountTransactionDraft::new(
        instructions.iter().cloned().collect::<Vec<_>>(),
        amx::fee_intent(),
        Metadata::default(),
    ))?;
    let replay = account.sign_transaction(payload)?;
    ensure!(
        replay.hash() != original.hash(),
        "replay control needs its separately signed carrier"
    );
    exchange.runtime.block_on(async {
        account.submit_transaction(&replay).await?;
        let mut verifier = root.verifier()?;
        let deadline = tokio::time::Instant::now() + WAIT;
        loop {
            let height = amx::status_poll::read_until(deadline, || async {
                client.client().status().get().await.map_err(Into::into)
            }).await?.blocks;
            ensure!(height <= 128);
            for at in verifier.authenticated_height().unwrap_or(0) + 1..=height {
                let proof = client.client().get_sumeragi_finality_proof_async(NonZeroU64::new(at).unwrap(), root.scope).await?;
                let block = verifier.verify(&proof)?;
                for (index, entry) in block.block().network_entrypoints().enumerate() {
                    let TransactionEntrypoint::External(signed) = entry else { continue; };
                    if signed.hash() != replay.hash() { continue; }
                    let evidence = amx::proofs::evidence(block.block(), index.try_into()?)?;
                    block.verify_transaction_execution(&root.network.network_id(), &evidence)?;
                    let error = evidence.output.result().as_ref().err().ok_or_else(|| eyre!("already settled old decision was applied again"))?;
                    let detail = error.to_string();
                    ensure!(detail.contains("certified epoch 0 is not tracked") || detail.contains("transaction was already settled"),
                        "replay must fail for retired/settled decision authority, not unrelated fee/clock rejection: {detail}");
                    let fee = evidence.output.result().nexus_fee_receipt().ok_or_else(|| eyre!("replay fee receipt absent"))?;
                    fee.validate_for_network_input(&evidence.entrypoint, at).map_err(|error| eyre!(error))?;
                    ensure!(!fee.fee_amount.is_zero() && fee.fee_asset_id == amx::fee_asset());
                    return Ok::<_, eyre::Report>(());
                }
            }
            ensure!(tokio::time::Instant::now() < deadline, "original replay outcome remains unresolved");
            tokio::time::sleep(POLL).await;
        }
    })
}
