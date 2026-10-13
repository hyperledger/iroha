//! A genuine Parliament draw whose slot is the boundary pulse that rotates the committee.
//! The request stays pending while the next committee's credentials are prepared, and it is
//! consumed after the rotation against the retained key session.

use super::*;
use iroha::data_model::{
    consensus::{
        FinalizedGlobalThresholdBeaconPulseV1, GlobalThresholdBeaconChainAnchorV1,
        GlobalThresholdBeaconKeySessionV1, GlobalThresholdBeaconPulseContextV1,
    },
    governance::types::{
        AbiVersion, BeaconPulseId, BeaconSessionId, BodyElectionAttemptId, DeployContractProposal,
        GovernanceAttemptId, ParliamentBody, ProposalKind, SortitionRequestV1,
    },
    isi::governance::{
        CreateParliamentGovernanceAttemptV1, ParliamentConsumeSortitionPulseBatchV1,
        ParliamentLifecycleTransitionV1, ProposeDeployContract, RegisterCitizen,
        SubmitParliamentLifecycleTransitionV1,
    },
    permission::Permission,
    smart_contract::ContractAddress,
    sumeragi::epoch::BeaconEpochBindingV1,
};
use iroha_core::{
    beacon::{
        global_threshold_beacon_governance_seed_v1, global_threshold_beacon_npos_successor_seed_v1,
        verify_finalized_global_threshold_beacon_pulse_v1,
    },
    governance::parliament::ParliamentAttemptStateV1,
};
use iroha_executor_data_model::permission::{
    governance::CanProposeContractDeployment, smart_contract::CanManageSmartContractCode,
};

const ADDRESS: &str = "irohac1qyqqqqqqqqqqqq95fes93ygegsv5enq9mqsz6x4lv4vp9gg4yxgjw";
const CITIZENS: usize = 24;
const BODY_SEATS: i64 = 3;
// Four actual transfer legs plus their fee remain below the canonical source bounds.
const CITIZEN_FUNDING_BATCH: usize = 4;
const CITIZEN_FEE_ALLOCATION: u64 = 10_000;

fn citizen_key(index: usize) -> Result<KeyPair> {
    KeyPair::try_from_seed(
        format!("committee-parliament-citizen-{index}").into_bytes(),
        iroha::crypto::Algorithm::Ed25519,
    )
    .map_err(Into::into)
}

fn citizenship_escrow() -> Result<AccountId> {
    Ok(AccountId::new(
        KeyPair::try_from_seed(
            b"committee-parliament-citizenship-escrow".to_vec(),
            iroha::crypto::Algorithm::Ed25519,
        )?
        .public_key()
        .clone(),
    ))
}

// The exact read peer must apply funding before a citizen's local fee quote and
// apply a request before its local attempt read. Quote retains its existing 300s
// bound; preparation, one submission and local completion share the 600s phase.
async fn submit_and_observe(
    admin: &Client,
    instructions: impl IntoIterator<Item = impl Into<InstructionBox>>,
    deadline: Instant,
    acknowledgement: &'static str,
) -> Result<SignedTransaction> {
    let preparation_client = admin.with_request_deadline(deadline)?;
    committee_status::submit_async_until(
        preparation_client.client().clone(),
        deadline,
        |bounded| async move {
            let transaction = parliament_submission::prepare_parliament_transaction(
                &preparation_client,
                instructions,
            )
            .await?;
            let applied = bounded
                .account_client()?
                .submit_transaction_and_wait(&transaction)
                .await?;
            ensure!(applied == transaction.hash(), acknowledgement);
            bounded
                .wait_until_transaction_applied_local(
                    transaction.hash(),
                    iroha::client::TransactionWaitOptions {
                        timeout: deadline.saturating_duration_since(Instant::now()),
                        poll_interval: POLL,
                    },
                )
                .await?;
            Ok(transaction)
        },
    )
    .await
}

/// Seed identities and permissions; real XOR funding waits for its signed genesis definition.
pub(super) fn genesis(mut builder: NetworkBuilder) -> Result<NetworkBuilder> {
    let xor: AssetDefinitionId = defaults::nexus::staking::stake_asset_id().parse()?;
    let escrow = citizenship_escrow()?;
    builder = builder
        .with_genesis_instruction(Register::account(Account::new(escrow.clone())))
        .with_config_layer(|layer| {
            layer
                .write(["gov", "citizenship_asset_id"], xor.to_string())
                .write(["gov", "citizenship_escrow_account"], escrow.to_string())
                .write(["gov", "parliament_alternate_size"], 0_i64)
                .write(["gov", "rules_committee_size"], BODY_SEATS)
                .write(["gov", "agenda_council_size"], BODY_SEATS)
                .write(["gov", "interest_panel_size"], BODY_SEATS)
                .write(["gov", "review_panel_size"], BODY_SEATS)
                .write(["gov", "oversight_committee_size"], BODY_SEATS)
                .write(["gov", "policy_jury_size"], BODY_SEATS);
        })
        .with_genesis_instruction(Grant::account_permission(
            Permission::from(CanManageSmartContractCode),
            ALICE_ID.clone(),
        ))
        .with_genesis_instruction(Grant::account_permission(
            Permission::from(CanProposeContractDeployment {
                contract_address: ADDRESS.parse()?,
            }),
            ALICE_ID.clone(),
        ));
    for index in 0..CITIZENS {
        let citizen = AccountId::new(citizen_key(index)?.public_key().clone());
        builder = builder.with_genesis_instruction(Register::account(Account::new(citizen)));
    }
    Ok(builder)
}

/// Fund exact account-owned XOR after bootstrap, then bind each citizen's own signed bond.
pub(super) async fn fund_and_register_citizens(
    network: &sandbox::SerializedNetwork,
    admin: &Client,
    xor: &AssetDefinitionId,
    signed_genesis_hash: iroha::crypto::HashOf<iroha::data_model::block::BlockHeader>,
) -> Result<()> {
    ensure!(
        admin.client().account() == &*ALICE_ID,
        "citizens use the exact funded bootstrap owner"
    );
    let bond = defaults::governance::citizenship_bond_amount();
    ensure!(
        !bond.is_zero(),
        "citizenship retains its actual positive XOR bond"
    );
    let funding = bond.try_add(&Quantity::from(CITIZEN_FEE_ALLOCATION))?;
    let citizens = (0..CITIZENS)
        .map(|index| {
            let key = citizen_key(index)?;
            Ok((AccountId::new(key.public_key().clone()), key))
        })
        .collect::<Result<Vec<_>>>()?;
    let (before_height, before_owner, before_supply) = read_on_dedicated_thread({
        let admin = admin.clone();
        let xor = xor.clone();
        move || -> Result<_> {
            let deadline = Instant::now() + WAIT;
            let height = committee_status::height_until_blocking(&admin, deadline)?;
            let owner = admin
                .client()
                .query_single(FindAssetById::new(AssetId::new(
                    xor.clone(),
                    ALICE_ID.clone(),
                )))?;
            let definition = admin
                .client()
                .query_single(FindAssetDefinitionById::new(xor))?;
            ensure!(
                committee_status::height_until_blocking(&admin, deadline)? == height,
                "citizen funding prestate changed during observation"
            );
            Ok((
                height,
                owner.value().clone(),
                definition.total_quantity().clone(),
            ))
        }
    })
    .await?;
    let setup_blocks = CITIZENS.div_ceil(CITIZEN_FUNDING_BATCH) + CITIZENS;
    ensure!(
        before_height >= 5 && before_height + u64::try_from(setup_blocks)? + 4 < SELECTION,
        "positive citizen funding and canonical proposal must finish before frozen selection"
    );
    let mut funding_transactions = Vec::new();
    for group in citizens.chunks(CITIZEN_FUNDING_BATCH) {
        let transfers = group.iter().map(|(citizen, _)| {
            Transfer::asset_quantity(
                AssetId::new(xor.clone(), ALICE_ID.clone()),
                funding.clone(),
                citizen.clone(),
            )
        });
        let transaction = submit_and_observe(
            admin,
            transfers,
            Instant::now() + WAIT,
            "citizen funding changed its exact signed source",
        )
        .await?;
        funding_transactions.push(transaction);
    }
    let mut registrations = Vec::new();
    for (citizen, key) in &citizens {
        let client = rebind_blocking_client(
            &network.validators()[0].client_for(citizen, key.private_key().clone()),
            |builder| {
                builder.transaction_status_timeout = WAIT;
            },
        );
        registrations.push(
            committee_staking::submit_signed(
                &client,
                RegisterCitizen {
                    owner: citizen.clone(),
                    amount: bond.clone(),
                }
                .into(),
                true,
            )
            .await?,
        );
    }
    let (height, owner_balance, supply, escrow_balance, balances) = read_on_dedicated_thread({
        let admin = admin.clone();
        let xor = xor.clone();
        let escrow = citizenship_escrow()?;
        let citizens = citizens
            .iter()
            .map(|(account, _)| account.clone())
            .collect::<Vec<_>>();
        move || -> Result<_> {
            let deadline = Instant::now() + WAIT;
            let height = committee_status::height_until_blocking(&admin, deadline)?;
            let balance = |account| -> Result<Quantity> {
                Ok(admin
                    .client()
                    .query_single(FindAssetById::new(AssetId::new(xor.clone(), account)))?
                    .value()
                    .clone())
            };
            let owner = balance(ALICE_ID.clone())?;
            let escrow = balance(escrow)?;
            let balances = citizens
                .into_iter()
                .map(balance)
                .collect::<Result<Vec<_>>>()?;
            let supply = admin
                .client()
                .query_single(FindAssetDefinitionById::new(xor))?
                .total_quantity()
                .clone();
            ensure!(
                committee_status::height_until_blocking(&admin, deadline)? == height,
                "citizen funding balances moved during observation"
            );
            Ok((height, owner, supply, escrow, balances))
        }
    })
    .await?;
    ensure!(
        height + 4 < SELECTION,
        "paid citizenship setup reached the selecting boundary"
    );
    let (_, chain) = read_on_dedicated_thread({
        let admin = admin.clone();
        let network_id = network.network_id();
        let root_scope = iroha_genesis::signed_genesis_consensus_metadata(&network.genesis().0)?
            .sumeragi_context
            .root_scope;
        move || {
            read_contiguous_finality_chain(
                &admin,
                network_id,
                signed_genesis_hash,
                height,
                root_scope,
            )
        }
    })
    .await?;
    let mut funding_fees = Quantity::zero();
    for transaction in &funding_transactions {
        funding_fees =
            funding_fees.try_add(&require_paid_and_applied(&chain, transaction, xor)?)?;
    }
    let mut total_fees = funding_fees.clone();
    let mut total_funding = Quantity::zero();
    let mut total_bond = Quantity::zero();
    for (transaction, balance) in registrations.iter().zip(balances) {
        let fee = require_paid_and_applied(&chain, transaction, xor)?;
        ensure!(
            balance == funding.try_sub(&bond)?.try_sub(&fee)?
                && balance >= fee
                && !balance.is_zero(),
            "citizen's exact XOR bond and separate actual fee must leave funded spendable balance"
        );
        total_fees = total_fees.try_add(&fee)?;
        total_funding = total_funding.try_add(&funding)?;
        total_bond = total_bond.try_add(&bond)?;
    }
    ensure!(
        escrow_balance == total_bond
            && owner_balance
                == before_owner
                    .try_sub(&total_funding)?
                    .try_sub(&funding_fees)?
            && supply == before_supply.try_sub(&total_fees)?,
        "paid citizen setup must conserve actual XOR bonds and burn only its finalized fees"
    );
    Ok(())
}

/// Admit a real canonical contract proposal before the committee selection cutoff.
pub(super) async fn stage_proposal(admin: &Client) -> Result<ProposalKind> {
    let artifact = parliament_submission::minimal_contract_artifact_with_identity(
        "CommitteePreparationPulse",
        "integration-tests",
    );
    let (code_hash, abi_hash) =
        parliament_submission::stage_contract_artifact(admin, &artifact).await?;
    let contract_address: ContractAddress = ADDRESS.parse()?;
    let proposal = ProposalKind::DeployContract(DeployContractProposal {
        proposal_operator: admin.client().account().clone(),
        contract_address: contract_address.clone(),
        code_hash,
        abi_hash,
        abi_version: AbiVersion::new(1),
        manifest_provenance: None,
    });
    committee_staking::submit_signed(
        admin,
        ProposeDeployContract {
            contract_address,
            code_hash,
            abi_hash,
            abi_version: AbiVersion::new(1),
            manifest_provenance: None,
        }
        .into(),
        true,
    )
    .await?;
    let height = read_on_dedicated_thread({
        let admin = admin.clone();
        move || committee_status::height_until_blocking(&admin, Instant::now() + WAIT)
    })
    .await?;
    ensure!(
        height < SELECTION,
        "admitted Parliament proposal missed the unfrozen setup interval"
    );
    Ok(proposal)
}

async fn attempt(admin: &Client, id: GovernanceAttemptId) -> Result<ParliamentAttemptStateV1> {
    let response = read_on_dedicated_thread({
        let client = admin.client().clone();
        move || client.get_parliament_attempt(id)
    })
    .await?;
    norito::decode_canonical(&hex::decode(response.state_payload_hex)?)
        .wrap_err("decode the actual Parliament reducer projection")
}

fn verified_pulse(
    chain: &[CertifiedBlock],
    height: u64,
    session: &GlobalThresholdBeaconKeySessionV1,
) -> Result<FinalizedGlobalThresholdBeaconPulseV1> {
    let block = chain
        .iter()
        .find(|block| block.height() == height)
        .ok_or_else(|| eyre!("requested Parliament pulse has no independently certified block"))?;
    let parent = chain
        .iter()
        .find(|block| block.height() + 1 == height)
        .ok_or_else(|| eyre!("requested pulse has no independently certified parent"))?;
    let pulse = block
        .commitment()
        .beacon
        .ok_or_else(|| eyre!("requested height lacks the mandatory signed pulse"))?;
    let header = block
        .header()
        .ok_or_else(|| eyre!("pulse cannot use a genesis-only context"))?;
    let context = GlobalThresholdBeaconPulseContextV1 {
        instance: header.instance.0,
        epoch: header.epoch.epoch,
        epoch_context_id: header.epoch.context.0,
        parent_consensus_hash: header.parent_hash.0,
        parent_result: header.parent_result.0,
    };
    let binding = GlobalThresholdBeaconSessionBindingV1 {
        network_id: session.network_id,
        session_id: session.session_id,
        roster_hash: session.roster_hash,
        transcript_hash: session.transcript_hash,
    };
    let validated = validate_global_threshold_beacon_session_v1(
        session,
        &binding,
        &iroha_allocation::AllocationBudget::new(64 * 1024 * 1024),
    )?;
    verify_finalized_global_threshold_beacon_pulse_v1(
        &validated,
        &pulse,
        GlobalThresholdBeaconChainAnchorV1 {
            height: parent.height(),
            block_hash: parent.block_hash(),
        },
        &context,
    )?;
    ensure!(
        matches!(block.commitment().schedule.current.authorization.beacon,
            BeaconEpochBindingV1::Installed(installed)
                if installed.session_id == session.session_id && installed.transcript_hash == session.transcript_hash),
        "pulse signer must be the installed current session from independently authenticated finality"
    );
    Ok(pulse)
}

/// One registered Parliament sortition generation that waits on the native boundary pulse.
pub(super) struct PendingSortition {
    id: GovernanceAttemptId,
    elections: Vec<BodyElectionAttemptId>,
    requests: Vec<SortitionRequestV1>,
    pulse_height: u64,
    request_transaction: SignedTransaction,
}

/// Register genuine sortition while both credential sets are installed.
///
/// The request is governance-local: its frozen slot is the consensus-native pre-boundary
/// pulse height of the epoch that rotates the committee and its beacon key session, so the
/// request creates no pulse of its own and nothing here waits for one.
pub(super) async fn request(
    admin: &Client,
    preparation: &ValidatorCommitteePreparationV1,
    current_session: &GlobalThresholdBeaconKeySessionV1,
    pending_session: &GlobalThresholdBeaconKeySessionV1,
    proposal: ProposalKind,
) -> Result<PendingSortition> {
    let before = read_validator_committee(admin, preparation.target_epoch).await?;
    ensure!(
        before.pending_beacon_session.as_ref() == Some(pending_session)
            && current_session.session_id != pending_session.session_id
            && before
                .selected
                .as_ref()
                .is_some_and(|row| row.transition.readiness.len() == preparation.committee.len()),
        "Parliament sortition must be requested with complete pending custody alongside current credentials"
    );
    let create = CreateParliamentGovernanceAttemptV1 {
        proposal,
        attempt_sequence: 0,
    };
    let id = create.governance_attempt_id();
    let instructions: Vec<InstructionBox> = vec![
        create.into(),
        SubmitParliamentLifecycleTransitionV1 {
            governance_attempt_id: id,
            transition: ParliamentLifecycleTransitionV1::CompleteQualification,
        }
        .into(),
        SubmitParliamentLifecycleTransitionV1 {
            governance_attempt_id: id,
            transition: ParliamentLifecycleTransitionV1::RegisterInitialSortition,
        }
        .into(),
    ];
    let request_transaction = submit_and_observe(
        admin,
        instructions,
        Instant::now() + WAIT,
        "Parliament request acknowledgement changed its signed source",
    )
    .await?;
    let registered = attempt(admin, id).await?;
    let elections = registered
        .required_bodies()
        .iter()
        .filter(|required| required.body != ParliamentBody::ConfirmationJury)
        .map(|required| BodyElectionAttemptId::derive_v1(id, required.body, 0))
        .collect::<Vec<_>>();
    ensure!(
        elections.len() == 6,
        "real contract proposal must require its complete six-body draw"
    );
    let requests = elections
        .iter()
        .map(|election| {
            registered
                .election(election)
                .map(|election| election.attempt().request)
                .ok_or_else(|| eyre!("canonical initial sortition omitted a required body"))
        })
        .collect::<Result<Vec<_>>>()?;
    let pulse_height = requests[0].pulse_height;
    let epoch_length = registered.sortition_pulse_epoch_length_blocks();
    let delay = registered.sortition_pulse_delay_blocks();
    ensure!(
        epoch_length == EPOCH
            && requests
                .iter()
                .all(|request| request.pulse_height == pulse_height
                    && request.candidate_count == CITIZENS as u32
                    && request.target_seats == BODY_SEATS as u32
                    && request.request_height > preparation.selection_height
                    && request.request_height + delay <= pulse_height
                    && pulse_height - (request.request_height + delay) < epoch_length)
            && (pulse_height + 1) % epoch_length == 0
            && pulse_height == CUTOFF - 1,
        "queued Parliament sortition must freeze the first native pulse height at or after its delay, which is the E+1 boundary pulse that also elects the committee"
    );
    Ok(PendingSortition {
        id,
        elections,
        requests,
        pulse_height,
        request_transaction,
    })
}

/// Consume the boundary pulse after the committee and beacon key session rotated on it.
///
/// The slot pulse was signed by the session that the boundary retired. Consumption in the
/// new authority generation must still succeed, verified against the session retained
/// under the pulse's own session id.
#[allow(clippy::too_many_arguments)]
pub(super) async fn consume_after_rotation(
    network: &sandbox::SerializedNetwork,
    admin: &Client,
    rotated_voters: &BTreeSet<PeerId>,
    pending: &PendingSortition,
    pulse: &FinalizedGlobalThresholdBeaconPulseV1,
    retired_session: &GlobalThresholdBeaconKeySessionV1,
    active_session: &GlobalThresholdBeaconKeySessionV1,
    signed_genesis_hash: iroha::crypto::HashOf<iroha::data_model::block::BlockHeader>,
    xor: &AssetDefinitionId,
) -> Result<()> {
    ensure!(
        pulse.height == pending.pulse_height,
        "the boundary pulse must sit at exactly the frozen sortition slot"
    );
    ensure!(
        pulse.session_id == retired_session.session_id,
        "the sortition slot pulse must be signed under the retired key session"
    );
    ensure!(
        retired_session.session_id != active_session.session_id,
        "the boundary must have rotated the active key session"
    );
    let awaiting = attempt(admin, pending.id).await?;
    ensure!(
        pending.elections.iter().all(|id| awaiting
            .election(id)
            .is_some_and(|election| election.pulse_id().is_none()
                && election.attempt().request.pulse_height == pending.pulse_height)),
        "the request must stay pending on its original slot across the rotation"
    );
    let mut request_ids = pending
        .requests
        .iter()
        .map(|request| request.id)
        .collect::<Vec<_>>();
    request_ids.sort_unstable();
    let consumer = committee_staking::submit_signed(
        admin,
        SubmitParliamentLifecycleTransitionV1 {
            governance_attempt_id: pending.id,
            transition: ParliamentLifecycleTransitionV1::ConsumeSortitionPulseBatch(
                ParliamentConsumeSortitionPulseBatchV1 {
                    request_ids,
                    beacon_session_id: BeaconSessionId::for_network_v1(&network.network_id()),
                    pulse_height: pending.pulse_height,
                    pulse_id: BeaconPulseId::new(pulse.pulse_id),
                },
            ),
        }
        .into(),
        true,
    )
    .await?;
    let (_, consumed_chain) = read_on_dedicated_thread({
        let admin = admin.clone();
        let network_id = network.network_id();
        let root_scope = iroha_genesis::signed_genesis_consensus_metadata(&network.genesis().0)?
            .sumeragi_context
            .root_scope;
        move || -> Result<_> {
            let tip = committee_status::height_until_blocking(&admin, Instant::now() + WAIT)?;
            read_contiguous_finality_chain(&admin, network_id, signed_genesis_hash, tip, root_scope)
        }
    })
    .await?;
    let rotated = consumed_chain
        .iter()
        .position(|block| block.height() > CUTOFF)
        .map(|first| &consumed_chain[first..])
        .ok_or_else(|| eyre!("pulse consumer lacks finality after the rotation boundary"))?;
    require_paid_and_applied(rotated, &consumer, xor)?;
    for block in rotated {
        verify_equal_vote_context(block, rotated_voters)?;
        let authorization = &block.commitment().schedule.current.authorization;
        ensure!(
            authorization.authority_generation == 1
                && authorization.epoch == 2
                && matches!(authorization.beacon,
                    BeaconEpochBindingV1::Installed(installed)
                        if installed.session_id == active_session.session_id
                            && installed.transcript_hash == active_session.transcript_hash),
            "the pulse must be consumed under the rotated committee and its new key session"
        );
    }
    let consumed = attempt(admin, pending.id).await?;
    let governance_seed = global_threshold_beacon_governance_seed_v1(pulse, pending.pulse_height);
    ensure!(
        governance_seed != pulse.seed
            && pending
                .elections
                .iter()
                .all(|id| consumed
                    .election(id)
                    .is_some_and(|election| election.pulse_id()
                        == Some(BeaconPulseId::new(pulse.pulse_id))
                        && election.pulse_output() == Some(governance_seed)
                        && election.primary_assignments().len() == BODY_SEATS as usize)),
        "every genuine Parliament body must consume the exact domain-separated boundary pulse against its retained session"
    );
    Ok(())
}

fn require_paid_and_applied(
    chain: &[CertifiedBlock],
    transaction: &SignedTransaction,
    xor: &AssetDefinitionId,
) -> Result<Quantity> {
    for block in chain {
        for index in 0..block.block().network_entrypoint_count() {
            if matches!(block.block().network_entrypoint_at(index),
                Some(TransactionEntrypoint::External(input)) if input == transaction)
            {
                let (_, output) = block
                    .block()
                    .network_output_at(u32::try_from(index)?)
                    .ok_or_else(|| {
                        eyre!("Parliament signed input has no explicit execution output")
                    })?;
                ensure!(
                    output.result.0.is_ok(),
                    "Parliament signed operation did not apply in authenticated finality"
                );
                let receipt = output
                    .result
                    .nexus_fee_receipt()
                    .ok_or_else(|| eyre!("Parliament signed operation lacks its actual XOR fee"))?;
                ensure!(
                    receipt.source_id == *Hash::from(transaction.hash_as_entrypoint()).as_ref()
                        && receipt.block_height == block.height()
                        && receipt.fee_asset_id == *xor
                        && receipt.debit_source
                            == iroha::data_model::nexus::FeeDebitSource::Account(
                                transaction.authority().clone()
                            )
                        && matches!(
                            receipt.settlement,
                            iroha::data_model::block::consensus::NexusFeeSettlementV1::Burn
                        )
                        && !receipt.fee_amount.is_zero(),
                    "Parliament fee must bind the exact signed source and account-owned XOR burn"
                );
                return Ok(receipt.fee_amount.clone());
            }
        }
    }
    Err(eyre!(
        "Parliament signed operation is absent from the independently authenticated prefix"
    ))
}

/// The sortition slot is the boundary pulse: one certified pulse feeds both the committee
/// election of the successor epoch and the governance draw, under separate domains.
pub(super) fn verify_boundary(
    chain: &[CertifiedBlock],
    pending: &PendingSortition,
    current_session: &GlobalThresholdBeaconKeySessionV1,
    voters: &BTreeSet<PeerId>,
    xor: &AssetDefinitionId,
) -> Result<FinalizedGlobalThresholdBeaconPulseV1> {
    let pulse = verified_pulse(chain, CUTOFF - 1, current_session)?;
    require_paid_and_applied(chain, &pending.request_transaction, xor)?;
    let cutoff = chain
        .last()
        .ok_or_else(|| eyre!("missing actual epoch cutoff"))?;
    let boundary = cutoff
        .commitment()
        .schedule
        .boundary
        .as_ref()
        .ok_or_else(|| eyre!("epoch cutoff omitted its mandatory decision"))?;
    for block in chain.iter().filter(|block| block.height() > SELECTION) {
        // Every block while the request is pending carries the genesis committee's exact
        // equal-vote context: the pending generation casts no vote before its boundary.
        verify_equal_vote_context(block, voters)?;
        ensure!(
            block
                .commitment()
                .schedule
                .current
                .authorization
                .authority_generation
                == 0
                && block.commitment().schedule.current.authorization.epoch == 1
                && matches!(block.commitment().schedule.current.authorization.beacon,
                BeaconEpochBindingV1::Installed(installed)
                    if installed.session_id == current_session.session_id && installed.transcript_hash == current_session.transcript_hash),
            "pending committee and beacon custody must remain inactive through the exact cutoff"
        );
    }
    // The request created no pulse of its own: the only pulse since the selecting boundary
    // is the native one at the slot.
    ensure!(
        chain
            .iter()
            .filter(|block| block.height() > SELECTION && block.height() != CUTOFF - 1)
            .all(|block| block.commitment().beacon.is_none()),
        "a pending Parliament request must not add a global beacon pulse inside the epoch"
    );
    let governance_seed = global_threshold_beacon_governance_seed_v1(&pulse, pulse.height);
    ensure!(
        cutoff.height() == CUTOFF
            && pending.pulse_height == pulse.height
            && pulse.height == CUTOFF - 1
            && boundary.next.leader_seed
                == global_threshold_beacon_npos_successor_seed_v1(&pulse, CUTOFF, 2)
            && governance_seed != boundary.next.leader_seed
            && governance_seed != pulse.seed
            && cutoff
                .commitment()
                .schedule
                .current
                .authorization
                .authority_generation
                == 0
            && boundary.next.authorization.authority_generation == 1,
        "the sortition slot must be the boundary pulse that schedules activation of the prepared generation, with the governance draw domain-separated from the committee seed"
    );
    Ok(pulse)
}

#[cfg(test)]
mod tests {
    use super::*;

    use iroha::http::{HttpTransport, Method, Response, TransportFuture, TransportRequest};
    use std::sync::{Arc, Mutex};

    #[derive(Debug)]
    struct SubmissionTransport {
        requests: Mutex<Vec<(String, Duration)>>,
        submitted: Mutex<Vec<Vec<u8>>>,
        observations: Mutex<Vec<(String, String)>>,
        budget: Duration,
    }

    impl HttpTransport for SubmissionTransport {
        fn send_blocking(&self, _: TransportRequest) -> Result<Response<Vec<u8>>> {
            panic!("Parliament submission must use the account-owned asynchronous transport")
        }

        fn send(&self, request: TransportRequest) -> TransportFuture<'_> {
            Box::pin(async move {
                assert_eq!(request.url.host_str(), Some("parliament-observer.invalid"));
                let remaining = request
                    .timeout
                    .expect("every dispatch keeps its phase deadline");
                assert!(remaining <= self.budget);
                let path = request.url.path();
                self.requests
                    .lock()
                    .unwrap()
                    .push((path.to_owned(), remaining));
                let (status, body) = match path {
                    "/v1/fees/quote" => {
                        assert_eq!(request.method, Method::POST);
                        let quote: iroha_torii_shared::FeeQuoteRequest =
                            norito::json::from_slice(&request.body)?;
                        let response = iroha_torii_shared::FeeQuoteResponse {
                            intent: quote.payload.fee_payment_intent().clone(),
                            observation: iroha_torii_shared::FeeQuoteObservation {
                                ledger_time_ms: 1,
                                next_block_height: 143,
                                route_dataspace_id:
                                    iroha_model_base::topology::DataSpaceId::UNIVERSAL,
                            },
                            components: Vec::new(),
                            capacities: Vec::new(),
                            decision: iroha_torii_shared::FeeQuoteDecision::Accepted {
                                debit_source: iroha_data_model::nexus::FeeDebitSource::Account(
                                    quote.payload.authority().clone(),
                                ),
                                program_revision: None,
                            },
                        };
                        (200, norito::json::to_vec(&response)?)
                    }
                    "/v1/node/capabilities" => {
                        assert_eq!(request.method, Method::GET);
                        (
                            200,
                            norito::json::to_vec(&norito::json!({
                                "data_model_version": (iroha_data_model::DATA_MODEL_VERSION),
                                "signed_transaction_schema_hash_hex": (hex::encode(
                                    norito::schema::identity::frame_hash::<SignedTransaction>()
                                )),
                            }))?,
                        )
                    }
                    "/v1/pipeline/transactions" => {
                        assert_eq!(request.method, Method::POST);
                        self.submitted.lock().unwrap().push(request.body);
                        (202, Vec::new())
                    }
                    "/v1/pipeline/transactions/status" => {
                        assert_eq!(request.method, Method::GET);
                        let parameter = |name| {
                            request
                                .url
                                .query_pairs()
                                .find(|(key, _)| key == name)
                                .unwrap()
                                .1
                                .into_owned()
                        };
                        let hash = parameter("hash");
                        let scope = parameter("scope");
                        let mut observations = self.observations.lock().unwrap();
                        let local_reads = observations
                            .iter()
                            .filter(|(scope, _)| scope == "local")
                            .count();
                        let (kind, source) = match scope.as_str() {
                            "global" => ("Applied", "state"),
                            "local" => match local_reads {
                                0 => ("Queued", "queue"),
                                1 => ("Applied", "cache"),
                                2 => ("Applied", "state"),
                                _ => panic!("local completion must stop further polling"),
                            },
                            other => panic!("unexpected observation scope: {other}"),
                        };
                        observations.push((scope.clone(), hash.clone()));
                        (
                            200,
                            norito::json::to_vec(&norito::json!({
                                "hash": hash,
                                "status": { "kind": kind, "block_height": 143 },
                                "scope": scope,
                                "resolved_from": source,
                            }))?,
                        )
                    }
                    other => panic!("unexpected Parliament dispatch: {other}"),
                };
                Ok(Response::builder()
                    .status(status)
                    .header("content-type", "application/json")
                    .body(body)?)
            })
        }
    }

    fn submission_client(transport: Arc<SubmissionTransport>) -> Client {
        let config = iroha::config::Config {
            chain: "parliament-observation-test".into(),
            network_id: NetworkId::from_genesis_hash(iroha_crypto::HashOf::from_untyped_unchecked(
                Hash::prehashed([0xA6; Hash::LENGTH]),
            )),
            key_pair: iroha_test_samples::ALICE_KEYPAIR.clone(),
            account: ALICE_ID.clone(),
            account_chain_discriminant: iroha_torii_shared::MINAMOTO_CHAIN_DISCRIMINANT,
            http_transport_policy: iroha::config::HttpTransportPolicy::Ordinary,
            torii_api_url: "http://parliament-observer.invalid/".parse().unwrap(),
            torii_request_timeout: iroha::config::DEFAULT_TORII_REQUEST_TIMEOUT,
            basic_auth: None,
            api_token: None,
            transaction_add_nonce: false,
            transaction_ttl: WAIT,
            transaction_status_timeout: WAIT,
            sorafs_alias_cache: iroha::config::AliasCache::default().into_policy(),
            sorafs_anonymity_policy: Default::default(),
            sorafs_rollout_phase: Default::default(),
        };
        Client::from_client(
            iroha::client::Client::builder(config)
                .http_transport(transport)
                .build()
                .unwrap(),
        )
        .unwrap()
    }

    #[test]
    fn parliament_submission_requires_exact_local_state_after_one_signed_write() -> Result<()> {
        init_instruction_registry();
        let budget = Duration::from_secs(2);
        let transport = Arc::new(SubmissionTransport {
            requests: Mutex::new(Vec::new()),
            submitted: Mutex::new(Vec::new()),
            observations: Mutex::new(Vec::new()),
            budget,
        });
        // Construct and retire the blocking holder outside its borrowed Tokio block.
        let admin = submission_client(transport.clone());
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        let transaction = runtime.block_on(submit_and_observe(
            &admin,
            [Log::new(
                Level::INFO,
                "Parliament local visibility".to_owned(),
            )],
            Instant::now() + budget,
            "Parliament request acknowledgement changed its signed source",
        ))?;
        assert_eq!(
            *transport.submitted.lock().unwrap(),
            vec![
                iroha::client::PreparedTransactionPayload::from_transaction(&transaction)
                    .as_bytes()
                    .to_vec()
            ],
            "visibility must not replace or resubmit the original signed request"
        );
        let observations = transport.observations.lock().unwrap();
        assert_eq!(
            observations
                .iter()
                .map(|(scope, _)| scope.as_str())
                .collect::<Vec<_>>(),
            ["global", "local", "local", "local"],
            "Parliament dependent reads require the exact local State, not global or cached success"
        );
        assert!(
            observations
                .iter()
                .all(|(_, hash)| hash == &transaction.hash().to_string())
        );
        let requests = transport.requests.lock().unwrap();
        assert_eq!(
            requests
                .iter()
                .filter(|(path, _)| path == "/v1/fees/quote")
                .count(),
            1
        );
        assert!(
            requests.windows(2).all(|pair| pair[1].1 < pair[0].1),
            "quote, submission and local visibility must consume the original phase deadline"
        );
        assert_eq!(admin.client().to_builder().transaction_status_timeout, WAIT);
        Ok(())
    }

    #[test]
    fn parliament_submission_refuses_expired_phase_before_quote_or_write() -> Result<()> {
        init_instruction_registry();
        let transport = Arc::new(SubmissionTransport {
            requests: Mutex::new(Vec::new()),
            submitted: Mutex::new(Vec::new()),
            observations: Mutex::new(Vec::new()),
            budget: Duration::from_secs(2),
        });
        let admin = submission_client(transport.clone());
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        let error = runtime
            .block_on(submit_and_observe(
                &admin,
                [Log::new(Level::INFO, "expired Parliament phase".to_owned())],
                Instant::now(),
                "citizen funding changed its exact signed source",
            ))
            .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("committee submission deadline elapsed")
        );
        assert!(transport.requests.lock().unwrap().is_empty());
        assert!(transport.submitted.lock().unwrap().is_empty());
        Ok(())
    }

    #[test]
    fn genesis_defines_real_xor_before_any_funding_and_leaves_citizen_bonds_for_signed_setup()
    -> Result<()> {
        init_instruction_registry();
        let network = genesis(
            NetworkBuilder::new()
                .with_peers(4)
                .with_npos_genesis_bootstrap(1_000_u64.into()),
        )?
        .build();
        let xor: AssetDefinitionId = defaults::nexus::staking::stake_asset_id().parse()?;
        let citizens = (0..CITIZENS)
            .map(|index| Ok(AccountId::new(citizen_key(index)?.public_key().clone())))
            .collect::<Result<BTreeSet<_>>>()?;
        let mut registered = BTreeSet::new();
        let mut definition_seen = false;
        let mut xor_mints = 0;
        for transaction in network.genesis().0.external_transactions() {
            let Executable::Instructions(instructions) = transaction.instructions() else {
                continue;
            };
            for instruction in instructions {
                if let Some(register) = instruction.as_any().downcast_ref::<RegisterBox>() {
                    match register {
                        RegisterBox::AssetDefinition(value) if value.object.id == xor => {
                            assert!(!definition_seen, "one canonical XOR definition");
                            assert_eq!(
                                value.object.spec,
                                iroha_primitives::numeric::NumericSpec::fractional(9)
                            );
                            definition_seen = true;
                        }
                        RegisterBox::Account(value) if citizens.contains(&value.object.id) => {
                            assert!(registered.insert(value.object.id.clone()));
                        }
                        _ => {}
                    }
                }
                if let Some(MintBox::Asset(mint)) = instruction.as_any().downcast_ref::<MintBox>()
                    && mint.destination.definition() == &xor
                {
                    assert!(
                        definition_seen,
                        "actual builder must define XOR before using it"
                    );
                    assert!(
                        !citizens.contains(mint.destination.account()),
                        "citizens receive existing XOR only through paid owner transfers"
                    );
                    xor_mints += 1;
                }
                assert!(
                    instruction
                        .as_any()
                        .downcast_ref::<RegisterCitizen>()
                        .is_none(),
                    "citizen bonds must use funded runtime owners, not precede automatic genesis XOR bootstrap"
                );
            }
        }
        assert!(definition_seen && xor_mints >= 4);
        assert_eq!(registered, citizens);
        assert!(!defaults::governance::citizenship_bond_amount().is_zero());
        Ok(())
    }
}
