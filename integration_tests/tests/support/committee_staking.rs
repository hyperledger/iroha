//! Source-bound real-XOR withdrawal across certified replacement and liability expiry.

use super::*;
use iroha::{
    client::{AccountTransactionDraft, FeeQuoteRequest},
    crypto::HashOf,
    data_model::{
        block::consensus::NexusFeeSettlementV1,
        isi::staking::{FinalizePublicLaneUnbond, SchedulePublicLaneUnbond},
        nexus::{
            FeeDebitSource, PublicLanePreparationBalanceV1, PublicLanePreparationOperationV1,
            PublicLanePreparationRequestV1, PublicLanePreparationV1, PublicLanePrepareBondV1,
            PublicLanePrepareClaimV1, PublicLanePrepareUnbondV1, PublicLanePreparedPlanV1,
            PublicLaneUnbonding, public_lane_unbonding_commitment,
        },
    },
};
use std::{
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};

/// Select a finite wall-clock unlock; eligibility still requires certified replacement
/// and the complete authenticated evidence/slashing horizon.
pub(super) fn finite_release_deadline() -> Result<u64> {
    let now = u64::try_from(SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis())?;
    now.checked_add(60_000)
        .ok_or_else(|| eyre!("disposable release timestamp overflow"))
}

struct Observation {
    prepared: PublicLanePreparationV1,
    chain: Vec<CertifiedBlock>,
    supply: Quantity,
    // A second unchanged read exposes the treasury and stake reserves without
    // changing the signed monetary/claim plan returned by the primary read.
    auxiliary: Option<PublicLanePreparationV1>,
}

impl Observation {
    fn asset(&self, asset: &AssetId) -> Result<&PublicLanePreparationBalanceV1> {
        self.prepared
            .balances
            .iter()
            .find(|row| &row.asset == asset)
            .or_else(|| {
                self.auxiliary
                    .as_ref()?
                    .balances
                    .iter()
                    .find(|row| &row.asset == asset)
            })
            .ok_or_else(|| eyre!("prepared plan omitted exact custody asset {asset}"))
    }

    fn assets(&self) -> impl Iterator<Item = &PublicLanePreparationBalanceV1> {
        self.prepared.balances.iter().chain(
            self.auxiliary
                .iter()
                .flat_map(|view| &view.balances)
                .filter(move |row| {
                    !self
                        .prepared
                        .balances
                        .iter()
                        .any(|primary| primary.asset == row.asset)
                }),
        )
    }
}

fn same_observed_tip(left: &PublicLanePreparationV1, right: &PublicLanePreparationV1) -> bool {
    left.observed_height == right.observed_height
        && left.observed_block_hash == right.observed_block_hash
}

fn validate_joined_custody(
    primary: &PublicLanePreparationV1,
    auxiliary: &PublicLanePreparationV1,
) -> Result<()> {
    ensure!(
        same_observed_tip(primary, auxiliary)
            && primary.network_id == auxiliary.network_id
            && primary.observed_ledger_time_ms == auxiliary.observed_ledger_time_ms
            && primary.assumed_execution_height == auxiliary.assumed_execution_height
            && primary.xor_asset_definition_id == auxiliary.xor_asset_definition_id,
        "supplemental custody must identify the same complete committed observation"
    );
    for row in &auxiliary.balances {
        if let Some(existing) = primary
            .balances
            .iter()
            .find(|existing| existing.asset == row.asset)
        {
            ensure!(
                existing == row,
                "one finalized tip returned inconsistent exact custody reserves"
            );
        }
    }
    Ok(())
}

fn validate_treasury_custody(
    escrow: &AssetId,
    treasury: &AssetId,
    fee_sink: &AccountId,
    xor: &AssetDefinitionId,
) -> Result<()> {
    ensure!(
        escrow == &AssetId::new(xor.clone(), escrow.account().clone())
            && treasury == &AssetId::new(xor.clone(), fee_sink.clone())
            && treasury != escrow,
        "signed staking escrow and funded reward fee sink must retain distinct exact global XOR custody"
    );
    Ok(())
}

/// Read the positive treasury mint from the actual retained signed genesis.
fn reward_treasury_from_signed_genesis(
    genesis: &iroha_genesis::GenesisBlock,
    xor: &AssetDefinitionId,
    fee_sink: &AccountId,
    escrow: &AssetId,
) -> Result<AssetId> {
    let mut treasury = None;
    for transaction in genesis.0.external_transactions() {
        let Executable::Instructions(instructions) = transaction.instructions() else {
            continue;
        };
        for instruction in instructions {
            let Some(iroha::data_model::isi::MintBox::Asset(mint)) =
                instruction
                    .as_any()
                    .downcast_ref::<iroha::data_model::isi::MintBox>()
            else {
                continue;
            };
            if mint.destination.definition() != xor || mint.destination.account() != fee_sink {
                continue;
            }
            ensure!(
                !mint.object.is_zero(),
                "signed reward treasury funding must be positive"
            );
            validate_treasury_custody(escrow, &mint.destination, fee_sink, xor)?;
            if let Some(existing) = &treasury {
                ensure!(
                    existing == &mint.destination,
                    "signed reward funding must retain one exact custody asset"
                );
            } else {
                treasury = Some(mint.destination.clone());
            }
        }
    }
    treasury.ok_or_else(|| {
        eyre!("signed genesis omitted positive XOR funding for the configured reward fee sink")
    })
}

fn validate_treasury_bond_observation(
    prepared: &PublicLanePreparationV1,
    request: &PublicLanePreparationRequestV1,
    network_id: NetworkId,
    treasury: &AssetId,
    escrow: &AssetId,
) -> Result<()> {
    let PublicLanePreparedPlanV1::Monetary(plan) = &prepared.plan else {
        return Err(eyre!("treasury custody observation returned a claim"));
    };
    ensure!(
        prepared.request == *request
            && prepared.network_id == network_id
            && plan.network_scope == PublicLaneMonetaryScopeV1::Network(network_id)
            && plan.source_asset == *treasury
            && plan.destination_asset == *escrow
            && plan.amount == Quantity::from(1_u64)
            && plan.has_canonical_shape()
            && matches!(
                &plan.precondition,
                PublicLaneMonetaryPreconditionV1::Bond(_)
            ),
        "supplemental ordinary bond preparation lost its exact treasury and signed stake custody"
    );
    Ok(())
}

/// Retained real stake and the exact obligation committed by its pending request.
pub(super) struct WithdrawalLifecycle {
    owner: Operator,
    escrow: AssetId,
    destination: AssetId,
    reward_treasury: AssetId,
    // An actual retained return-committee survivor stays registered after the
    // departing owner has withdrawn. This is a read, never a new delegation.
    reserve_validator: AccountId,
    pending: PublicLaneUnbonding,
    network_id: NetworkId,
    retained_stake: Quantity,
    history: Arc<committee_staking_history::RetainedHistory>,
}

impl WithdrawalLifecycle {
    fn unbond_intent(&self) -> PublicLanePreparationOperationV1 {
        PublicLanePreparationOperationV1::FinalizeUnbond(PublicLanePrepareUnbondV1 {
            validator: self.owner.account.clone(),
            staker: self.owner.account.clone(),
            request_id: self.pending.request_id,
        })
    }

    async fn prepare_until(
        &self,
        request: &PublicLanePreparationRequestV1,
        deadline: Instant,
    ) -> Result<PublicLanePreparationV1> {
        loop {
            let result = tokio::time::timeout_at(
                deadline.into(),
                self.owner
                    .client
                    .client()
                    .nexus()
                    .prepare_public_lane_plan(request),
            )
            .await
            .wrap_err("staking preparation exceeded its read deadline")?;
            match result {
                Ok(prepared) => return Ok(prepared),
                Err(error) => {
                    let remaining = deadline.saturating_duration_since(Instant::now());
                    if let Some(delay) = committee_read_retry_delay(&error, remaining) {
                        sleep(delay).await;
                    } else {
                        return Err(error.into());
                    }
                }
            }
        }
    }

    async fn observe(&self, operation: PublicLanePreparationOperationV1) -> Result<Observation> {
        let request = PublicLanePreparationRequestV1 {
            lane_id: LaneId::SINGLE,
            valid_for_blocks: EPOCH,
            operation,
        };
        let treasury_request = PublicLanePreparationRequestV1 {
            lane_id: LaneId::SINGLE,
            valid_for_blocks: EPOCH,
            operation: PublicLanePreparationOperationV1::Bond(PublicLanePrepareBondV1 {
                validator: self.reserve_validator.clone(),
                staker: self.reward_treasury.account().clone(),
                amount: 1_u64.into(),
            }),
        };
        let deadline = Instant::now() + WAIT;
        let (prepared, auxiliary, supply) = loop {
            ensure!(
                Instant::now() < deadline,
                "staking observation deadline elapsed"
            );
            let prepared = self.prepare_until(&request, deadline).await?;
            let auxiliary = self.prepare_until(&treasury_request, deadline).await?;
            validate_treasury_bond_observation(
                &auxiliary,
                &treasury_request,
                self.network_id,
                &self.reward_treasury,
                &self.escrow,
            )?;
            if !same_observed_tip(&prepared, &auxiliary) {
                continue;
            }
            validate_joined_custody(&prepared, &auxiliary)?;
            let supply = tokio::time::timeout_at(
                deadline.into(),
                read_on_dedicated_thread({
                    let client = self.owner.client.clone();
                    let xor = self.escrow.definition().clone();
                    move || -> Result<Quantity> {
                        Ok(client
                            .client()
                            .with_request_deadline(deadline)
                            .query_single(FindAssetDefinitionById::new(xor))?
                            .total_quantity()
                            .clone())
                    }
                }),
            )
            .await
            .wrap_err("real XOR supply observation exceeded its original deadline")?
            .wrap_err("real XOR supply observation worker failed")?;
            // The supply and supplemental reserve reads share the same tip as
            // both unchanged primary reads. No plan or reserve row is synthesized.
            let confirmed_auxiliary = self.prepare_until(&treasury_request, deadline).await?;
            let confirmed = self.prepare_until(&request, deadline).await?;
            if !same_observed_tip(&prepared, &confirmed)
                || !same_observed_tip(&prepared, &confirmed_auxiliary)
            {
                continue;
            }
            ensure!(
                prepared == confirmed && auxiliary == confirmed_auxiliary,
                "one finalized staking tip returned inconsistent custody observations"
            );
            validate_joined_custody(&confirmed, &confirmed_auxiliary)?;
            break (prepared, auxiliary, supply);
        };
        let chain = tokio::time::timeout_at(
            deadline.into(),
            read_on_dedicated_thread({
                let client = self.owner.client.clone();
                let history = Arc::clone(&self.history);
                let height = prepared.observed_height;
                move || history.read_until(&client, height, deadline)
            }),
        )
        .await
        .wrap_err("staking observation finality exceeded its original read deadline")?
        .wrap_err("staking observation finality worker failed")?;
        let tip = chain
            .last()
            .ok_or_else(|| eyre!("staking observation has no finality"))?;
        ensure!(
            prepared.network_id == self.network_id
                && prepared.request == request
                && prepared.xor_asset_definition_id == *self.escrow.definition()
                && prepared.observed_height == tip.height()
                && prepared.observed_block_hash == Hash::from(tip.block_hash())
                && prepared.observed_ledger_time_ms == tip.block_time_ms(),
            "staking observation does not identify the independently authenticated native tip"
        );
        for row in prepared.balances.iter().chain(&auxiliary.balances) {
            ensure!(
                row.balance >= row.stake_reserved.checked_add(&row.rewards_reserved)?,
                "real XOR balance does not cover additive stake and reward reserves"
            );
        }
        Ok(Observation {
            prepared,
            chain,
            supply,
            auxiliary: Some(auxiliary),
        })
    }

    fn withdrawal(&self, observation: &Observation) -> Result<FinalizePublicLaneUnbond> {
        let PublicLanePreparedPlanV1::Monetary(plan) = &observation.prepared.plan else {
            return Err(eyre!("withdrawal preparation returned a reward claim"));
        };
        ensure!(
            plan.network_scope == PublicLaneMonetaryScopeV1::Network(self.network_id)
                && plan.source_asset == self.escrow
                && plan.destination_asset == self.destination
                && plan.amount == self.pending.amount
                && matches!(&plan.precondition, PublicLaneMonetaryPreconditionV1::Unbond(binding)
                    if binding.request_hash == public_lane_unbonding_commitment(&self.pending)?),
            "withdrawal lost its exact asset, quantity or retained slashing-liability commitment"
        );
        Ok(FinalizePublicLaneUnbond {
            lane_id: LaneId::SINGLE,
            validator: self.owner.account.clone(),
            staker: self.owner.account.clone(),
            request_id: self.pending.request_id,
            monetary_plan: plan.clone(),
        })
    }

    /// All processes were restarted while the owner was still a seven-seat voter.
    pub(super) async fn verify_retained_after_restart(&self) -> Result<()> {
        let observation = self.observe(self.unbond_intent()).await?;
        self.withdrawal(&observation)?;
        ensure!(
            observation.prepared.observed_height < TARGET_LAST
                && observation.asset(&self.escrow)?.stake_reserved == self.retained_stake
                && observation.chain.last().is_some_and(|tip| tip
                    .commitment()
                    .schedule
                    .current
                    .committee
                    .iter()
                    .any(|seat| seat.validator == self.owner.peer)),
            "restart lost the pending principal or released a still-voting validator"
        );
        Ok(())
    }

    async fn reject_early(&self, before: Observation, reason: &str) -> Result<Observation> {
        let transaction =
            submit_signed(&self.owner.client, self.withdrawal(&before)?.into(), false).await?;
        let after = self.observe(self.unbond_intent()).await?;
        self.withdrawal(&after)?;
        let fee = actual_fee(
            &before,
            &after,
            &transaction,
            false,
            Some(reason),
            self.escrow.definition(),
        )?;
        assert_effects(
            &before,
            &after,
            &self.escrow,
            &self.destination,
            &Quantity::zero(),
            &Quantity::zero(),
            &Quantity::zero(),
            &self.owner.account,
            &fee,
        )?;
        Ok(after)
    }

    /// Prove replacement, retain slashable custody, then withdraw the full real bond.
    pub(super) async fn complete_withdrawal(
        self,
        network: &sandbox::SerializedNetwork,
        voters: &[PeerId],
        expected: &BTreeSet<PeerId>,
    ) -> Result<()> {
        let after_replacement = self.observe(self.unbond_intent()).await?;
        ensure!(
            after_replacement.prepared.observed_height >= TARGET_LAST + 1
                && after_replacement.prepared.observed_height
                    < self.pending.liability_release_height,
            "replacement must precede the independently retained evidence horizon"
        );
        verify_equal_vote_context(
            after_replacement.chain.last().expect("authenticated tip"),
            expected,
        )?;
        self.reject_early(after_replacement, "remains slashable")
            .await?;
        advance_to_height(network, voters, self.pending.liability_release_height).await?;
        let deadline = Instant::now() + WAIT;
        let before = loop {
            let observation = self.observe(self.unbond_intent()).await?;
            if observation.prepared.observed_ledger_time_ms >= self.pending.release_at_ms {
                break observation;
            }
            ensure!(
                Instant::now() < deadline,
                "finite real-time unbond release deadline elapsed"
            );
            // Wait on the actual clock, then let a paid transaction establish ledger time.
            // Neither a fabricated timestamp nor empty-block production advances release.
            sleep(Duration::from_secs(1)).await;
            advance_to_height(network, voters, observation.prepared.observed_height + 1).await?;
        };
        let transaction =
            submit_signed(&self.owner.client, self.withdrawal(&before)?.into(), true).await?;
        // Preparing a possible future delegation is a read: it observes both exact assets
        // after the withdrawn validator and its zero stake position have been pruned.
        let survivor = voters.first().ok_or_else(|| eyre!("no remaining voter"))?;
        let survivor_account = network
            .validators()
            .iter()
            .chain(network.committee_validators())
            .find(|peer| peer.id() == *survivor)
            .ok_or_else(|| eyre!("remaining voter has no process"))?
            .account_id();
        let observation_intent = PublicLanePreparationOperationV1::Bond(PublicLanePrepareBondV1 {
            validator: survivor_account,
            staker: self.owner.account.clone(),
            amount: 1_u64.into(),
        });
        let after = self.observe(observation_intent.clone()).await?;
        let fee = actual_fee(
            &before,
            &after,
            &transaction,
            true,
            None,
            self.escrow.definition(),
        )?;
        assert_effects(
            &before,
            &after,
            &self.escrow,
            &self.destination,
            &self.pending.amount,
            &self.pending.amount,
            &Quantity::zero(),
            &self.owner.account,
            &fee,
        )?;
        let replay =
            submit_signed(&self.owner.client, self.withdrawal(&before)?.into(), false).await?;
        ensure!(
            replay.hash() != transaction.hash(),
            "withdrawal replay must be a new signed transaction carrying the exact consumed plan"
        );
        let after_replay = self.observe(observation_intent).await?;
        let replay_fee = actual_fee(
            &after,
            &after_replay,
            &replay,
            false,
            Some("validator has no retained positive stake custody"),
            self.escrow.definition(),
        )?;
        assert_effects(
            &after,
            &after_replay,
            &self.escrow,
            &self.destination,
            &Quantity::zero(),
            &Quantity::zero(),
            &Quantity::zero(),
            &self.owner.account,
            &replay_fee,
        )?;
        for block in after_replay
            .chain
            .iter()
            .filter(|block| block.height() > TARGET_LAST)
        {
            verify_equal_vote_context(block, expected)?;
            ensure!(
                block
                    .commitment()
                    .schedule
                    .current
                    .authorization
                    .authority_generation
                    == 2,
                "custody-release progress must retain the authenticated four-seat generation"
            );
        }
        Ok(())
    }
}

/// Quote and sign a fresh transaction; callers authenticate its exact execution output.
pub(super) async fn submit_signed(
    client: &Client,
    instruction: InstructionBox,
    applied: bool,
) -> Result<SignedTransaction> {
    let deadline = Instant::now() + WAIT;
    committee_status::submit_async_until(client.client().clone(), deadline, |bounded| async move {
        let account = bounded.account_client()?;
        let mut payload = account.prepare_transaction(AccountTransactionDraft::new(
            vec![instruction],
            FeePaymentIntent::authority(Vec::new(), None),
            Metadata::default(),
        ))?;
        let quote = account
            .quote_fees(FeeQuoteRequest::AccountSignature { payload: &payload })
            .await?;
        ensure!(
            payload
                .fee_payment
                .has_same_payer_and_gas_bound(&quote.intent),
            "fee quote changed the selected monetary-plan signer"
        );
        payload.fee_payment = quote.intent;
        let transaction = account.sign_transaction(payload)?;
        let result = account.submit_transaction_and_wait(&transaction).await;
        if applied {
            result.wrap_err("signed monetary transaction failed")?;
            bounded
                .wait_until_transaction_applied_local(
                    transaction.hash(),
                    iroha::client::TransactionWaitOptions {
                        timeout: deadline.saturating_duration_since(Instant::now()),
                        poll_interval: POLL,
                    },
                )
                .await?;
        } else {
            let error = result
                .err()
                .ok_or_else(|| eyre!("rejected monetary operation unexpectedly applied"))?;
            let Some(failure) = error.chain().find_map(|cause| {
                cause.downcast_ref::<iroha::client::TransactionFinalityFailure>()
            }) else {
                return Err(error)
                    .wrap_err("signed monetary rejection lacks exact global State completion");
            };
            if failure.response().status.kind != "Rejected" {
                return Err(error)
                    .wrap_err("signed monetary operation did not reach State Rejected");
            }
            committee_status::observe_rejected_until(
                bounded,
                transaction.hash(),
                failure,
                deadline,
            )
            .await?;
        }
        // Local status is only a readback fence. Exact rejected Network output, fee and
        // monetary effects still come from the independently authenticated native chain.
        Ok(transaction)
    })
    .await
}

fn require_only_accounted_input(
    expected: Hash,
    mut inputs: impl Iterator<Item = Hash>,
) -> Result<()> {
    ensure!(
        inputs.next() == Some(expected) && inputs.next().is_none(),
        "accounting interval must contain exactly the signed monetary input and no unrelated transactions"
    );
    Ok(())
}

fn actual_fee(
    before: &Observation,
    after: &Observation,
    transaction: &SignedTransaction,
    applied: bool,
    rejection: Option<&str>,
    xor: &AssetDefinitionId,
) -> Result<Quantity> {
    ensure!(
        applied || rejection.is_some(),
        "rejected monetary work must identify its exact executed business failure"
    );
    let start = before.prepared.observed_height;
    let end = after.prepared.observed_height;
    ensure!(
        start < end
            && after.chain.iter().any(|block| block.height() == start
                && Hash::from(block.block_hash()) == before.prepared.observed_block_hash)
            && after.chain.last().is_some_and(|block| block.height() == end
                && Hash::from(block.block_hash()) == after.prepared.observed_block_hash),
        "accounting observations must bound one independently authenticated finality interval"
    );
    require_only_accounted_input(
        Hash::from(transaction.hash_as_entrypoint()),
        after
            .chain
            .iter()
            .filter(|block| block.height() > start)
            .flat_map(|block| block.block().network_entrypoints())
            .map(|input| Hash::from(input.hash())),
    )?;
    for block in after.chain.iter().filter(|block| block.height() > start) {
        for index in 0..block.block().network_entrypoint_count() {
            let Some(TransactionEntrypoint::External(input)) =
                block.block().network_entrypoint_at(index)
            else {
                continue;
            };
            if input.hash() != transaction.hash() {
                continue;
            }
            ensure!(
                input == transaction,
                "finalized monetary input differs from the signed transaction"
            );
            let (_, output) = block
                .block()
                .network_output_at(u32::try_from(index)?)
                .ok_or_else(|| eyre!("monetary input lost its explicit Network output"))?;
            ensure!(
                output.result.0.is_ok() == applied,
                "authenticated monetary outcome differs from expectation"
            );
            if let Some(reason) = rejection {
                ensure!(
                    output
                        .result
                        .0
                        .as_ref()
                        .err()
                        .is_some_and(|error| format!("{error:?}").contains(reason)),
                    "withdrawal rejected for a different reason than the retained obligation"
                );
            }
            // Every interval here contains authored, separately funded work. The
            // exact business-error check above excludes admission and fee-charge
            // failures: successful work and these business rejections both settle
            // their original Nexus fee basis through the canonical fee overlay.
            let receipt = output.result.nexus_fee_receipt().ok_or_else(|| {
                eyre!("executed monetary transaction omitted actual real-XOR fee settlement")
            })?;
            ensure!(
                receipt.source_id == *Hash::from(input.hash_as_entrypoint()).as_ref()
                    && receipt.block_height == block.height()
                    && receipt.fee_asset_id == *xor
                    && receipt.debit_source == FeeDebitSource::Account(input.authority().clone())
                    && matches!(receipt.settlement, NexusFeeSettlementV1::Burn)
                    && !receipt.fee_amount.is_zero(),
                "monetary execution must carry its actual separate authority-paid XOR burn"
            );
            return Ok(receipt.fee_amount.clone());
        }
    }
    Err(eyre!(
        "signed monetary transaction has no authenticated execution output"
    ))
}

#[allow(clippy::too_many_arguments)]
fn assert_effects(
    before: &Observation,
    after: &Observation,
    escrow: &AssetId,
    recipient: &AssetId,
    paid: &Quantity,
    released_stake: &Quantity,
    released_reward: &Quantity,
    fee_payer: &AccountId,
    fee: &Quantity,
) -> Result<()> {
    let source_before = before.asset(escrow)?;
    let source_after = after.asset(escrow)?;
    let recipient_before = before.asset(recipient)?;
    let recipient_after = after.asset(recipient)?;
    let source_fee = if escrow.account() == fee_payer {
        fee.clone()
    } else {
        Quantity::zero()
    };
    let recipient_fee = if recipient.account() == fee_payer {
        fee.clone()
    } else {
        Quantity::zero()
    };
    ensure!(
        source_before
            .balance
            .checked_sub(paid)?
            .checked_sub(&source_fee)?
            == source_after.balance
            && recipient_before
                .balance
                .checked_add(paid)?
                .checked_sub(&recipient_fee)?
                == recipient_after.balance
            && source_before.stake_reserved.checked_sub(released_stake)?
                == source_after.stake_reserved
            && source_before
                .rewards_reserved
                .checked_sub(released_reward)?
                == source_after.rewards_reserved
            && recipient_before.stake_reserved == recipient_after.stake_reserved
            && recipient_before.rewards_reserved == recipient_after.rewards_reserved
            && before.supply.checked_sub(fee)? == after.supply,
        "actual XOR movement, additive reserves or supply differ from principal/reward plus separate settled fees"
    );
    for row in before
        .assets()
        .filter(|row| &row.asset != escrow && &row.asset != recipient)
    {
        let current = after.asset(&row.asset)?;
        let settled_fee = if row.asset.account() == fee_payer {
            fee.clone()
        } else {
            Quantity::zero()
        };
        ensure!(
            row.balance.checked_sub(&settled_fee)? == current.balance
                && row.stake_reserved == current.stake_reserved
                && row.rewards_reserved == current.rewards_reserved,
            "paid monetary work changed unrelated treasury or stake custody"
        );
    }
    ensure!(
        after.assets().all(|row| before.asset(&row.asset).is_ok()),
        "paid monetary observation changed its exact custody asset set"
    );
    Ok(())
}

#[cfg(test)]
fn assert_reward_reservation(
    before: &Observation,
    after: &Observation,
    treasury: &AssetId,
    escrow: &AssetId,
    recipient: &AssetId,
    reward: &Quantity,
    fee: &Quantity,
) -> Result<()> {
    let source = before.asset(treasury)?;
    let reserved = after.asset(treasury)?;
    ensure!(
        source.balance.checked_sub(fee)? == reserved.balance
            && source.stake_reserved == reserved.stake_reserved
            && source.rewards_reserved.checked_add(reward)? == reserved.rewards_reserved
            && before.asset(escrow)? == after.asset(escrow)?
            && before.asset(recipient)? == after.asset(recipient)?
            && before.supply.checked_sub(fee)? == after.supply,
        "reward distribution must reserve existing treasury XOR and burn only its admin fee without consuming stake"
    );
    Ok(())
}

/// Schedule a full-bond withdrawal and preserve its authenticated committee liability.
pub(super) async fn schedule_retained_withdrawal(
    network: &sandbox::SerializedNetwork,
    admin: &Client,
    owner: &Operator,
    genesis_validator: bool,
    return_preparation: &ValidatorCommitteePreparationV1,
    signed_genesis_hash: HashOf<iroha::data_model::block::BlockHeader>,
) -> Result<WithdrawalLifecycle> {
    let ingress = exact_process_roster(
        network,
        &[return_preparation.committee[0].validator.clone()],
    )?[0];
    let mut owner = owner.clone();
    owner.client = rebind_blocking_client(&owner.client, |builder| {
        builder.torii_url = ingress.client().client().endpoint().clone();
        builder.transaction_status_timeout = WAIT;
    });
    let admin = rebind_blocking_client(admin, |builder| {
        builder.torii_url = ingress.client().client().endpoint().clone();
    });
    let xor: AssetDefinitionId = TAIRA_XOR.parse()?;
    let escrow = validator_xor_escrow(&network.genesis(), &xor)?;
    ensure!(
        network.genesis().0.hash() == signed_genesis_hash,
        "reward custody must come from the original retained signed genesis"
    );
    let mut fee_sink = None;
    for layer in network.config_layers() {
        if let Some(value) = layer
            .get("nexus")
            .and_then(|value| value.get("fees"))
            .and_then(|value| value.get("fee_sink_account_id"))
        {
            fee_sink = Some(AccountId::parse_encoded(value.as_str().ok_or_else(
                || eyre!("reward fee sink configuration must be a canonical account string"),
            )?)?);
        }
    }
    let fee_sink = fee_sink.ok_or_else(|| eyre!("actual reward fee sink configuration missing"))?;
    ensure!(
        fee_sink == *ALICE_ID,
        "the paid reward administrator must own the actual configured fee sink"
    );
    let reward_treasury =
        reward_treasury_from_signed_genesis(&network.genesis(), &xor, &fee_sink, &escrow)?;
    let reserve_validator = ingress.account_id();
    let parameters = read_on_dedicated_thread({
        let admin = admin.clone();
        move || Ok(admin.client().query_single(FindParameters)?)
    })
    .await
    .wrap_err("signed staking policy worker failed")?;
    let npos = SumeragiNposParameters::from_custom_parameter(
        parameters
            .custom()
            .get(&SumeragiNposParameters::parameter_id())
            .ok_or_else(|| eyre!("signed NPoS policy missing"))?,
    )?
    .ok_or_else(|| eyre!("signed NPoS policy invalid"))?;
    ensure!(
        npos.evidence_horizon_blocks == EPOCH * 2 && npos.slashing_delay_blocks == 1,
        "withdrawal must use the signed evidence and slashing horizons"
    );
    let pending = PublicLaneUnbonding {
        request_id: Hash::new_from_chunks(&[
            b"iroha:real-xor-withdrawal:v1",
            &norito::encode_canonical(&owner.account)?,
        ]),
        amount: if genesis_validator {
            1_000_u64.into()
        } else {
            2_000_u64.into()
        },
        release_at_ms: finite_release_deadline()?,
        slashable_through_height: return_preparation.last_height,
        liability_release_height: return_preparation
            .last_height
            .checked_add(npos.evidence_horizon_blocks)
            .and_then(|height| height.checked_add(npos.slashing_delay_blocks))
            .ok_or_else(|| eyre!("unbond liability horizon overflow"))?,
    };
    let history = Arc::new(committee_staking_history::RetainedHistory::new(
        network.chain_id(),
        network.network_id(),
        signed_genesis_hash,
    )?);
    let mut lifecycle = WithdrawalLifecycle {
        destination: AssetId::with_scope(xor, owner.account.clone(), *escrow.scope()),
        owner,
        escrow,
        reward_treasury,
        reserve_validator,
        pending,
        network_id: network.network_id(),
        retained_stake: Quantity::zero(),
        history,
    };
    let before_schedule = lifecycle
        .observe(PublicLanePreparationOperationV1::Bond(
            PublicLanePrepareBondV1 {
                validator: lifecycle.owner.account.clone(),
                staker: lifecycle.owner.account.clone(),
                amount: 1_u64.into(),
            },
        ))
        .await?;
    lifecycle.pending.release_at_ms = finite_release_deadline()?;
    let scheduled = submit_signed(
        &lifecycle.owner.client,
        SchedulePublicLaneUnbond {
            lane_id: LaneId::SINGLE,
            validator: lifecycle.owner.account.clone(),
            staker: lifecycle.owner.account.clone(),
            request_id: lifecycle.pending.request_id,
            amount: lifecycle.pending.amount.clone(),
            release_at_ms: lifecycle.pending.release_at_ms,
        }
        .into(),
        true,
    )
    .await?;
    let before_reward = lifecycle.observe(lifecycle.unbond_intent()).await?;
    let schedule_fee = actual_fee(
        &before_schedule,
        &before_reward,
        &scheduled,
        true,
        None,
        lifecycle.escrow.definition(),
    )?;
    assert_effects(
        &before_schedule,
        &before_reward,
        &lifecycle.escrow,
        &lifecycle.destination,
        &Quantity::zero(),
        &Quantity::zero(),
        &Quantity::zero(),
        &lifecycle.owner.account,
        &schedule_fee,
    )?;
    lifecycle.withdrawal(&before_reward)?;
    lifecycle.retained_stake = before_reward
        .asset(&lifecycle.escrow)?
        .stake_reserved
        .clone();
    ensure!(
        before_reward.prepared.observed_height < TARGET_LAST,
        "unbond scheduling missed the seven-seat tenure"
    );
    // TODO: qualify automatic funded reward conversion and signed nominator claims
    // in a real-peer scenario with authenticated monthly funding and reference
    // observations. This retained-tenure scenario only qualifies principal custody.
    lifecycle
        .reject_early(
            before_reward,
            "authenticated release of current and frozen committee obligations",
        )
        .await?;
    Ok(lifecycle)
}

#[cfg(test)]
mod tests {
    use super::*;
    use iroha_test_samples::BOB_ID;

    fn observation(
        source: u64,
        recipient: u64,
        stake: u64,
        reward: u64,
        supply: u64,
    ) -> Observation {
        let xor: AssetDefinitionId = TAIRA_XOR.parse().expect("canonical real XOR");
        let escrow = AssetId::new(xor.clone(), ALICE_ID.clone());
        let destination = AssetId::new(xor.clone(), BOB_ID.clone());
        let request = PublicLanePreparationRequestV1 {
            lane_id: LaneId::SINGLE,
            valid_for_blocks: EPOCH,
            operation: PublicLanePreparationOperationV1::ClaimRewards(PublicLanePrepareClaimV1 {
                recipient: BOB_ID.clone(),
            }),
        };
        let hash = Hash::new(b"accounting helper observation; not network qualification");
        let network_id = NetworkId::from_genesis_hash(HashOf::from_untyped_unchecked(hash));
        Observation {
            prepared: PublicLanePreparationV1 {
                request,
                network_id,
                observed_height: 1,
                observed_block_hash: hash,
                observed_ledger_time_ms: 1,
                assumed_execution_height: 2,
                xor_asset_definition_id: xor,
                plan: PublicLanePreparedPlanV1::Monetary(PublicLaneMonetaryPlanV1 {
                    network_scope: PublicLaneMonetaryScopeV1::Network(network_id),
                    valid_until_height: EPOCH,
                    source_asset: escrow.clone(),
                    destination_asset: destination.clone(),
                    amount: 1_u64.into(),
                    precondition: PublicLaneMonetaryPreconditionV1::Unbond(
                        iroha::data_model::nexus::PublicLaneMonetaryUnbondV1 {
                            activation_height: 1,
                            request_hash: hash,
                        },
                    ),
                }),
                balances: vec![
                    PublicLanePreparationBalanceV1 {
                        asset: escrow,
                        balance: source.into(),
                        stake_reserved: stake.into(),
                        rewards_reserved: reward.into(),
                    },
                    PublicLanePreparationBalanceV1 {
                        asset: destination,
                        balance: recipient.into(),
                        stake_reserved: Quantity::zero(),
                        rewards_reserved: Quantity::zero(),
                    },
                ],
            },
            chain: Vec::new(),
            supply: supply.into(),
            auxiliary: None,
        }
    }

    #[test]
    fn supply_observation_retries_a_changed_height_or_finalized_hash() {
        let observed = observation(1_000, 100, 800, 25, 1_100).prepared;
        assert!(same_observed_tip(&observed, &observed));
        let mut advanced = observed.clone();
        advanced.observed_height += 1;
        assert!(!same_observed_tip(&observed, &advanced));
        let mut replaced = observed.clone();
        replaced.observed_block_hash = Hash::new(b"different finalized tip");
        assert!(!same_observed_tip(&observed, &replaced));
    }

    #[test]
    fn accounting_interval_rejects_missing_repeated_and_unrelated_paid_inputs() -> Result<()> {
        let expected = Hash::new(b"exact signed withdrawal");
        let progress = Hash::new(b"unrelated paid progress input");
        require_only_accounted_input(expected, [expected].into_iter())?;
        for inputs in [
            vec![],
            vec![progress],
            vec![expected, expected],
            vec![progress, expected],
            vec![expected, progress],
        ] {
            assert!(require_only_accounted_input(expected, inputs.into_iter()).is_err());
        }
        Ok(())
    }

    #[test]
    fn real_xor_accounting_separates_fees_principal_and_reward_reserves() -> Result<()> {
        let before = observation(1_000, 100, 800, 25, 1_100);
        let after_reward = observation(975, 123, 800, 0, 1_098);
        let escrow = &before.prepared.balances[0].asset;
        let recipient = &before.prepared.balances[1].asset;
        let after_schedule = observation(1_000, 98, 800, 25, 1_098);
        assert_effects(
            &before,
            &after_schedule,
            escrow,
            recipient,
            &Quantity::zero(),
            &Quantity::zero(),
            &Quantity::zero(),
            &BOB_ID,
            &2_u64.into(),
        )?;
        assert_effects(
            &before,
            &after_reward,
            escrow,
            recipient,
            &25_u64.into(),
            &Quantity::zero(),
            &25_u64.into(),
            &BOB_ID,
            &2_u64.into(),
        )?;
        let after_withdrawal = observation(800, 298, 600, 25, 1_098);
        assert_effects(
            &before,
            &after_withdrawal,
            escrow,
            recipient,
            &200_u64.into(),
            &200_u64.into(),
            &Quantity::zero(),
            &BOB_ID,
            &2_u64.into(),
        )?;
        for incorrect in [
            observation(975, 125, 800, 0, 1_098), // fee disguised as free principal
            observation(975, 123, 775, 0, 1_098), // reward consumes bonded custody
            observation(975, 123, 800, 0, 1_100), // fee receipt without real supply burn
        ] {
            assert!(
                assert_effects(
                    &before,
                    &incorrect,
                    escrow,
                    recipient,
                    &25_u64.into(),
                    &Quantity::zero(),
                    &25_u64.into(),
                    &BOB_ID,
                    &2_u64.into()
                )
                .is_err()
            );
        }
        for reserve in [true, false] {
            let mut changed_recipient = observation(975, 123, 800, 0, 1_098);
            if reserve {
                changed_recipient.prepared.balances[1].stake_reserved = 1_u64.into();
            } else {
                changed_recipient.prepared.balances[1].rewards_reserved = 1_u64.into();
            }
            assert!(
                assert_effects(
                    &before,
                    &changed_recipient,
                    escrow,
                    recipient,
                    &25_u64.into(),
                    &Quantity::zero(),
                    &25_u64.into(),
                    &BOB_ID,
                    &2_u64.into(),
                )
                .is_err(),
                "reward payment cannot create unrelated recipient reservations"
            );
        }
        Ok(())
    }

    #[test]
    fn rejected_withdrawal_accounting_preserves_all_custody() -> Result<()> {
        let before = observation(1_000, 100, 800, 25, 1_100);
        let unchanged = observation(1_000, 100, 800, 25, 1_100);
        let escrow = &before.prepared.balances[0].asset;
        let recipient = &before.prepared.balances[1].asset;
        assert_effects(
            &before,
            &unchanged,
            escrow,
            recipient,
            &Quantity::zero(),
            &Quantity::zero(),
            &Quantity::zero(),
            &BOB_ID,
            &Quantity::zero(),
        )?;
        let lost_pending_principal = observation(1_000, 100, 600, 25, 1_100);
        assert!(
            assert_effects(
                &before,
                &lost_pending_principal,
                escrow,
                recipient,
                &Quantity::zero(),
                &Quantity::zero(),
                &Quantity::zero(),
                &BOB_ID,
                &Quantity::zero()
            )
            .is_err()
        );
        Ok(())
    }

    fn distinct_custody_observation(
        treasury: u64,
        escrow: u64,
        recipient: u64,
        stake: u64,
        reward: u64,
        supply: u64,
    ) -> Observation {
        let mut observed = observation(treasury, recipient, 0, reward, supply);
        let xor = observed.prepared.xor_asset_definition_id.clone();
        let escrow_account = AccountId::new(
            KeyPair::from_seed(
                b"committee-staking-distinct-escrow-control".to_vec(),
                iroha::crypto::Algorithm::Ed25519,
            )
            .public_key()
            .clone(),
        );
        observed
            .prepared
            .balances
            .push(PublicLanePreparationBalanceV1 {
                asset: AssetId::new(xor, escrow_account),
                balance: escrow.into(),
                stake_reserved: stake.into(),
                rewards_reserved: Quantity::zero(),
            });
        observed
    }

    #[test]
    fn reward_treasury_requires_exact_separate_xor_custody() -> Result<()> {
        let observed = distinct_custody_observation(1_000, 900, 100, 800, 0, 2_000);
        let treasury = &observed.prepared.balances[0].asset;
        let escrow = &observed.prepared.balances[2].asset;
        let xor = &observed.prepared.xor_asset_definition_id;
        validate_treasury_custody(escrow, treasury, &ALICE_ID, xor)?;
        assert!(validate_treasury_custody(escrow, escrow, &ALICE_ID, xor).is_err());
        assert!(validate_treasury_custody(treasury, treasury, &ALICE_ID, xor).is_err());
        assert!(validate_treasury_custody(escrow, treasury, &BOB_ID, xor).is_err());
        let routed = AssetId::with_scope(
            xor.clone(),
            ALICE_ID.clone(),
            iroha::data_model::asset::AssetBalanceScope::Dataspace(
                iroha_model_base::topology::DataSpaceId::new(7),
            ),
        );
        assert!(validate_treasury_custody(escrow, &routed, &ALICE_ID, xor).is_err());
        Ok(())
    }

    #[test]
    fn joined_custody_observations_require_exact_source_and_equal_overlap() -> Result<()> {
        let observed = observation(1_000, 100, 0, 25, 1_100).prepared;
        validate_joined_custody(&observed, &observed)?;
        let mut changed = observed.clone();
        changed.observed_height += 1;
        assert!(validate_joined_custody(&observed, &changed).is_err());
        changed = observed.clone();
        changed.observed_block_hash = Hash::new(b"different complete committed source");
        assert!(validate_joined_custody(&observed, &changed).is_err());
        changed = observed.clone();
        changed.network_id = NetworkId::from_genesis_hash(HashOf::from_untyped_unchecked(
            Hash::new(b"foreign signed genesis"),
        ));
        assert!(validate_joined_custody(&observed, &changed).is_err());
        changed = observed.clone();
        changed.observed_ledger_time_ms += 1;
        assert!(validate_joined_custody(&observed, &changed).is_err());
        changed = observed.clone();
        changed.balances[0].balance = 999_u64.into();
        assert!(validate_joined_custody(&observed, &changed).is_err());
        changed = observed.clone();
        changed.balances[0].stake_reserved = 1_u64.into();
        assert!(validate_joined_custody(&observed, &changed).is_err());
        changed = observed.clone();
        changed.balances[0].rewards_reserved = 26_u64.into();
        assert!(validate_joined_custody(&observed, &changed).is_err());
        Ok(())
    }

    #[test]
    fn supplemental_bond_observation_requires_exact_treasury_and_signed_escrow() -> Result<()> {
        let mut observed = distinct_custody_observation(1_000, 900, 100, 800, 0, 2_000).prepared;
        let treasury = observed.balances[0].asset.clone();
        let escrow = observed.balances[2].asset.clone();
        let request = PublicLanePreparationRequestV1 {
            lane_id: LaneId::SINGLE,
            valid_for_blocks: EPOCH,
            operation: PublicLanePreparationOperationV1::Bond(PublicLanePrepareBondV1 {
                validator: BOB_ID.clone(),
                staker: ALICE_ID.clone(),
                amount: 1_u64.into(),
            }),
        };
        observed.request = request.clone();
        let PublicLanePreparedPlanV1::Monetary(plan) = &mut observed.plan else {
            panic!("helper monetary plan");
        };
        plan.source_asset = treasury.clone();
        plan.destination_asset = escrow.clone();
        plan.amount = 1_u64.into();
        plan.precondition = PublicLaneMonetaryPreconditionV1::Bond(
            iroha::data_model::nexus::PublicLaneMonetaryBondV1 {
                activation_height: 1,
                peer_id: PeerId::new(
                    KeyPair::from_seed(
                        b"retained-survivor-custody-control".to_vec(),
                        iroha::crypto::Algorithm::BlsNormal,
                    )
                    .public_key()
                    .clone(),
                ),
            },
        );
        validate_treasury_bond_observation(
            &observed,
            &request,
            observed.network_id,
            &treasury,
            &escrow,
        )?;
        let mut confused = observed.clone();
        let PublicLanePreparedPlanV1::Monetary(plan) = &mut confused.plan else {
            unreachable!()
        };
        plan.source_asset = escrow.clone();
        assert!(
            validate_treasury_bond_observation(
                &confused,
                &request,
                observed.network_id,
                &treasury,
                &escrow
            )
            .is_err()
        );
        Ok(())
    }

    #[test]
    fn treasury_reward_reservation_burns_only_admin_fee_and_preserves_stake() -> Result<()> {
        let before = distinct_custody_observation(1_000, 900, 100, 800, 0, 2_000);
        let after = distinct_custody_observation(998, 900, 100, 800, 25, 1_998);
        let treasury = &before.prepared.balances[0].asset;
        let recipient = &before.prepared.balances[1].asset;
        let escrow = &before.prepared.balances[2].asset;
        assert_reward_reservation(
            &before,
            &after,
            treasury,
            escrow,
            recipient,
            &25_u64.into(),
            &2_u64.into(),
        )?;
        for invalid in [
            distinct_custody_observation(1_000, 898, 100, 800, 25, 1_998), // admin fee charged to stake escrow
            distinct_custody_observation(998, 900, 100, 775, 25, 1_998), // reward consumes principal
            distinct_custody_observation(973, 900, 125, 800, 0, 1_998), // reservation pays/mints prematurely
            distinct_custody_observation(998, 900, 100, 800, 25, 2_000), // missing mandatory Burn
        ] {
            assert!(
                assert_reward_reservation(
                    &before,
                    &invalid,
                    treasury,
                    escrow,
                    recipient,
                    &25_u64.into(),
                    &2_u64.into()
                )
                .is_err()
            );
        }
        Ok(())
    }

    #[test]
    fn reward_claim_pays_treasury_and_burns_recipient_fee_without_using_stake() -> Result<()> {
        let before = distinct_custody_observation(998, 900, 100, 800, 25, 1_998);
        let after = distinct_custody_observation(973, 900, 123, 800, 0, 1_996);
        let treasury = &before.prepared.balances[0].asset;
        let recipient = &before.prepared.balances[1].asset;
        assert_effects(
            &before,
            &after,
            treasury,
            recipient,
            &25_u64.into(),
            &Quantity::zero(),
            &25_u64.into(),
            &BOB_ID,
            &2_u64.into(),
        )?;
        for invalid in [
            distinct_custody_observation(998, 875, 123, 800, 0, 1_996), // reward paid from stake
            distinct_custody_observation(973, 898, 125, 800, 0, 1_996), // fee charged to stake
            distinct_custody_observation(973, 900, 123, 775, 0, 1_996), // stake reserve released
        ] {
            assert!(
                assert_effects(
                    &before,
                    &invalid,
                    treasury,
                    recipient,
                    &25_u64.into(),
                    &Quantity::zero(),
                    &25_u64.into(),
                    &BOB_ID,
                    &2_u64.into()
                )
                .is_err()
            );
        }
        Ok(())
    }

    #[test]
    fn rejected_reward_replay_preserves_both_custodies_and_burns_only_recipient_fee() -> Result<()>
    {
        let before = distinct_custody_observation(973, 900, 123, 800, 0, 1_996);
        let after = distinct_custody_observation(973, 900, 121, 800, 0, 1_994);
        let treasury = &before.prepared.balances[0].asset;
        let recipient = &before.prepared.balances[1].asset;
        assert_effects(
            &before,
            &after,
            treasury,
            recipient,
            &Quantity::zero(),
            &Quantity::zero(),
            &Quantity::zero(),
            &BOB_ID,
            &2_u64.into(),
        )?;
        let invalid = distinct_custody_observation(973, 898, 123, 800, 0, 1_994);
        assert!(
            assert_effects(
                &before,
                &invalid,
                treasury,
                recipient,
                &Quantity::zero(),
                &Quantity::zero(),
                &Quantity::zero(),
                &BOB_ID,
                &2_u64.into()
            )
            .is_err()
        );
        Ok(())
    }

    #[test]
    fn supplemental_custody_rows_are_observed_without_rewriting_primary_plan() -> Result<()> {
        let mut observed = observation(1_000, 100, 0, 25, 1_100);
        let original = observed.prepared.clone();
        let mut auxiliary = distinct_custody_observation(1_000, 900, 100, 800, 25, 2_000).prepared;
        let escrow = auxiliary.balances[2].asset.clone();
        // Supply is an independently sandwiched definition read, not a field of
        // either preparation response. Only matching custody rows are joined.
        validate_joined_custody(&observed.prepared, &auxiliary)?;
        observed.auxiliary = Some(auxiliary.clone());
        assert_eq!(observed.asset(&escrow)?.balance, Quantity::from(900_u64));
        assert_eq!(observed.assets().count(), 3);
        assert_eq!(observed.prepared, original);
        auxiliary.balances[0].balance = 999_u64.into();
        assert!(validate_joined_custody(&observed.prepared, &auxiliary).is_err());
        Ok(())
    }

    #[test]
    fn reward_treasury_selects_actual_signed_four_validator_genesis_funding() -> Result<()> {
        init_instruction_registry();
        // Materialize the existing signed fixture only; never start a peer or
        // submit an additional mint to a running ledger.
        let network = NetworkBuilder::new()
            .with_peers(4)
            .with_auto_populated_trusted_peers()
            .with_npos_consensus()
            .with_npos_genesis_bootstrap(1_000_u64.into())
            .with_base_seed("committee-treasury-signed-genesis-selection")
            .build();
        let genesis = network.genesis();
        let original_hash = genesis.0.hash();
        let original_wire = genesis.0.encode_wire()?;
        let xor: AssetDefinitionId = TAIRA_XOR.parse()?;
        // This original helper independently checks the four signed bond
        // destinations, their principal and the sole canonical XOR definition.
        let escrow = validator_xor_escrow(&genesis, &xor)?;
        let expected = AssetId::new(xor.clone(), ALICE_ID.clone());
        assert_ne!(escrow, expected);
        for transaction in genesis.0.external_transactions() {
            transaction.verify_signature()?;
        }
        for signature in genesis.0.signatures() {
            signature.signature().verify_hash(
                iroha_test_samples::SAMPLE_GENESIS_ACCOUNT_KEYPAIR.public_key(),
                original_hash,
            )?;
        }
        assert!(genesis.0.external_transactions().any(|transaction| {
            let Executable::Instructions(instructions) = transaction.instructions() else {
                return false;
            };
            instructions.iter().any(|instruction| {
                matches!(
                    instruction.as_any().downcast_ref::<iroha::data_model::isi::MintBox>(),
                    Some(iroha::data_model::isi::MintBox::Asset(mint))
                        if mint.destination == expected && !mint.object.is_zero()
                )
            })
        }));
        assert_eq!(
            reward_treasury_from_signed_genesis(&genesis, &xor, &ALICE_ID, &escrow)?,
            expected,
        );
        assert_eq!(genesis.0.hash(), original_hash);
        assert_eq!(genesis.0.encode_wire()?, original_wire);
        Ok(())
    }

    fn signed_treasury_selection_carrier(
        instructions: Vec<InstructionBox>,
    ) -> Result<iroha_genesis::GenesisBlock> {
        init_instruction_registry();
        let key = KeyPair::from_seed(
            b"committee-treasury-proposal-only-selection-control".to_vec(),
            iroha::crypto::Algorithm::Ed25519,
        );
        let mut builder = TransactionBuilder::new_genesis(
            AccountId::new(key.public_key().clone()),
            FeePaymentIntent::authority(Vec::new(), None),
        );
        builder.set_creation_time(Duration::from_millis(1_000));
        let transaction = builder
            .with_instructions(instructions)
            .try_sign(key.private_key())?;
        transaction.verify_signature()?;
        // Counterexamples are genuinely signed source carriers, deliberately
        // unexecuted. They do not claim that malformed funding is valid genesis.
        let block = SignedBlock::try_genesis(vec![transaction], key.private_key(), None, None)?;
        for signature in block.signatures() {
            signature
                .signature()
                .verify_hash(key.public_key(), block.hash())?;
        }
        Ok(iroha_genesis::GenesisBlock(block))
    }

    #[test]
    fn reward_treasury_signed_sources_reject_absent_zero_foreign_scoped_and_conflicting_funding()
    -> Result<()> {
        let observed = distinct_custody_observation(1_000, 900, 100, 800, 0, 2_000);
        let xor = observed.prepared.xor_asset_definition_id.clone();
        let treasury = AssetId::new(xor.clone(), ALICE_ID.clone());
        let escrow = observed.prepared.balances[2].asset.clone();
        let scoped = AssetId::with_scope(
            xor.clone(),
            ALICE_ID.clone(),
            iroha::data_model::asset::AssetBalanceScope::Dataspace(
                iroha_model_base::topology::DataSpaceId::new(7),
            ),
        );
        let mut foreign_uuid = [0xA7; 16];
        foreign_uuid[6] = 0x47;
        foreign_uuid[8] = 0x87;
        let foreign_definition = AssetDefinitionId::from_uuid_bytes(foreign_uuid)?;
        assert_ne!(foreign_definition, xor);
        let foreign_asset = AssetId::new(foreign_definition, ALICE_ID.clone());
        let foreign_account = AssetId::new(xor.clone(), BOB_ID.clone());
        let mint = |asset: &AssetId, amount: u64| -> InstructionBox {
            Mint::asset_quantity(amount, asset.clone()).into()
        };
        let cases = [
            (
                "absent",
                vec![Register::account(Account::new(BOB_ID.clone())).into()],
            ),
            ("zero", vec![mint(&treasury, 0)]),
            ("foreign definition", vec![mint(&foreign_asset, 1)]),
            ("foreign account", vec![mint(&foreign_account, 1)]),
            ("scoped", vec![mint(&scoped, 1)]),
            (
                "conflicting after exact",
                vec![mint(&treasury, 1), mint(&scoped, 1)],
            ),
            (
                "conflicting before exact",
                vec![mint(&scoped, 1), mint(&treasury, 1)],
            ),
            (
                "zero after exact",
                vec![mint(&treasury, 1), mint(&treasury, 0)],
            ),
        ];
        for (label, instructions) in cases {
            let genesis = signed_treasury_selection_carrier(instructions)?;
            let original_hash = genesis.0.hash();
            let original_wire = genesis.0.encode_wire()?;
            assert!(
                reward_treasury_from_signed_genesis(&genesis, &xor, &ALICE_ID, &escrow).is_err(),
                "signed {label} source must not select a funded treasury",
            );
            assert_eq!(genesis.0.hash(), original_hash);
            assert_eq!(genesis.0.encode_wire()?, original_wire);
        }
        let genesis = signed_treasury_selection_carrier(vec![
            mint(&foreign_asset, 3),
            mint(&foreign_account, 4),
            mint(&treasury, 1),
            mint(&treasury, 2),
        ])?;
        let original_wire = genesis.0.encode_wire()?;
        assert_eq!(
            reward_treasury_from_signed_genesis(&genesis, &xor, &ALICE_ID, &escrow)?,
            treasury,
            "unrelated funding is ignored; repeated exact positive custody remains one source",
        );
        assert_eq!(genesis.0.encode_wire()?, original_wire);
        Ok(())
    }
}
