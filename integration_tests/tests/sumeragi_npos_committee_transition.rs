//! Disposable NPoS qualification of an overfull candidate pool and certified retention.
//!
//! Four genesis voters admit separately running candidates into pools of five, eight or
//! eleven. The public rank freezes exactly four or seven seats two epochs ahead, bounded
//! by the signed seven-seat ceiling. A selected seat withholds its beacon share in the
//! retention cases; the eight-candidate case specifically withholds an incumbent. The
//! current exact quorum must cancel that immutable attempt without losing finality.
//! Retention scenarios restart every process, then authenticate a paid successor signed
//! by the unchanged generation and a fresh, separately identified future attempt.
//! The complete rotation withdraws a departing seat's full bond only after replacement and liability
//! expiry. Its genuine Parliament pulse consumes current credentials while the next
//! committee remains pending. Retail monthly policy and network slashing remain separate gates.

use eyre::{Result, WrapErr as _, ensure, eyre};
use integration_tests::{sandbox, sync::rebind_blocking_client};
use iroha::{
    blocking::Client,
    crypto::{Hash, KeyPair, SignatureOf},
    data_model::{
        NetworkId,
        isi::{
            consensus_keys::ApplyThresholdKeyLifecycleCertificateV1,
            staking::{
                ExitPublicLaneValidator, PublicLaneCandidateAuthorization,
                RegisterPublicLaneCandidate, RegisterPublicLaneValidator,
            },
        },
        nexus::{
            AdmitValidatorCommitteeSeatV1, PrepareValidatorCommitteeCredentialsV1,
            PublicLaneMonetaryPlanV1, PublicLaneMonetaryPreconditionV1,
            PublicLaneMonetaryRegistrationV1, PublicLaneMonetaryScopeV1,
            ValidatorCommitteeCredentialsV1, ValidatorCommitteeOperationV1,
            ValidatorCommitteePreparationV1, ValidatorCommitteeSeatReadinessV1,
        },
        parameter::system::{SumeragiNposParameters, SumeragiParameter},
        prelude::*,
        sumeragi::{
            epoch::ValidatorEpochDecisionV1,
            finality::{NativeFinalityArtifact, NativeFinalityJournal, NativeFinalityLimits},
        },
        transaction::FeePaymentIntent,
        validation_fee::ValidationFeePolicyRegistryV1,
    },
};
use iroha_config::parameters::defaults;
use iroha_core::{
    beacon::{
        GlobalThresholdBeaconSessionBindingV1, RuntimeGlobalThresholdBeaconShareCustodyV1,
        credential::global_beacon_partial_signer_public_inventory_digest_v1,
        global_threshold_beacon_roster_hash_v1, prove_global_threshold_beacon_seat_readiness_v1,
        validate_global_threshold_beacon_session_v1,
    },
    sumeragi::{
        certified_chain::CertifiedBlock,
        native_journal::{NativeJournalCursor, with_verified_native_journal},
    },
    validator_committee_evidence::{
        ValidatorCommitteeProvisioningEvidenceV1, ValidatorCommitteeSelectionEvidenceV1,
        verify_validator_committee_provisioning_evidence_v1,
    },
};
use iroha_model_base::{metadata::Metadata, peer::PeerId, topology::LaneId};
use iroha_test_network::{
    CommitteeValidatorP2pBootstrap, DisposableBeaconProviderBinding, DisposableGenesisDkgOutput,
    DisposablePendingCustodyInput, DisposablePreparedBeaconCustody,
    DisposableRetainedBeaconCredential, DisposableRotationDkgOutput, DisposableRotationProofInput,
    NetworkBuilder, NetworkPeer, init_instruction_registry, prepare_disposable_pending_custody,
    read_on_dedicated_thread, run_disposable_genesis_dkg, run_disposable_rotation_dkg,
};
use iroha_test_samples::ALICE_ID;
use irohad::{
    IrohaRuntimeProviderBindingsV1, IrohaRuntimeProviderSlotV1,
    external_software_signer::encode_consensus_threshold_credential_bundle_v1,
};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    num::NonZeroU64,
    path::PathBuf,
    time::{Duration, Instant},
};
use tokio::time::sleep;
use zeroize::Zeroizing;

#[derive(norito::derive::JsonDeserialize)]
#[norito(deny_unknown_fields)]
struct NativeProviderManifest {
    signer_index: u16,
    validator: PeerId,
    handle: String,
    revision: u64,
    policy_digest: [u8; 32],
}

#[path = "support/committee_parliament.rs"]
mod committee_parliament;
#[path = "support/committee_staking.rs"]
mod committee_staking;
#[path = "support/committee_staking_history.rs"]
mod committee_staking_history;
#[path = "support/committee_status.rs"]
mod committee_status;
#[path = "support/parliament_submission.rs"]
mod parliament_submission;

// Paid citizen setup precedes selection; one full preparation epoch then covers every seat.
const EPOCH: u64 = 64;
const MAX_QUALIFICATION_HEIGHT: u64 = EPOCH * 8;
const SELECTION: u64 = EPOCH;
const CUTOFF: u64 = EPOCH * 2;
const TARGET_FIRST: u64 = EPOCH * 2 + 1;
const TARGET_LAST: u64 = EPOCH * 3;
const WAIT: Duration = Duration::from_secs(600);
const POLL: Duration = Duration::from_millis(150);
const TAIRA_XOR: &str = "6TEAJqbb8oEPmLncoNiMRbLEK6tw";

/// Preserve the server's backpressure delay within the original test read deadline.
fn committee_read_retry_delay(error: &iroha::Error, remaining: Duration) -> Option<Duration> {
    let iroha::Error::Http {
        status: 429,
        retry_after,
        ..
    } = error
    else {
        return None;
    };
    let delay = retry_after.unwrap_or(POLL).max(POLL);
    (delay < remaining).then_some(delay)
}

/// Retry only an explicitly refused public read; submitted transactions are never replayed.
async fn read_validator_committee(
    client: &Client,
    target_epoch: u64,
) -> Result<iroha::data_model::nexus::ValidatorCommitteeStatusV1> {
    let deadline = tokio::time::Instant::now() + WAIT;
    loop {
        let result = tokio::time::timeout_at(
            deadline,
            client
                .client()
                .nexus()
                .validator_committee(Some(target_epoch)),
        )
        .await
        .wrap_err("committee status exceeded its original read deadline")?;
        match result {
            Ok(status) => return Ok(status),
            Err(error) => {
                let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
                let Some(delay) = committee_read_retry_delay(&error, remaining) else {
                    return Err(error.into());
                };
                sleep(delay).await;
            }
        }
    }
}

#[test]
fn committee_read_backoff_honors_server_delay_without_extending_deadline() {
    let error = |status, retry_after| iroha::Error::Http {
        operation: "nexus.validator_committee.read",
        status,
        retry_after,
        body: Vec::new(),
    };
    assert_eq!(
        committee_read_retry_delay(&error(429, None), WAIT),
        Some(POLL)
    );
    assert_eq!(
        committee_read_retry_delay(&error(429, Some(Duration::ZERO)), WAIT),
        Some(POLL)
    );
    assert_eq!(
        committee_read_retry_delay(&error(429, Some(Duration::from_secs(3))), WAIT),
        Some(Duration::from_secs(3)),
    );
    assert_eq!(
        committee_read_retry_delay(&error(429, Some(WAIT)), WAIT),
        None
    );
    assert_eq!(committee_read_retry_delay(&error(429, None), POLL), None);
    assert_eq!(
        committee_read_retry_delay(&error(429, None), Duration::ZERO),
        None
    );
    for status in [400, 401, 403, 404, 500, 503] {
        assert_eq!(committee_read_retry_delay(&error(status, None), WAIT), None);
    }
    assert_eq!(
        committee_read_retry_delay(
            &iroha::Error::Timeout {
                operation: "nexus.validator_committee.read",
            },
            WAIT
        ),
        None
    );
}

#[derive(Clone)]
struct Operator {
    account: AccountId,
    peer: PeerId,
    consensus_key: KeyPair,
    pop: Vec<u8>,
    client: Client,
}

fn exact_quorum(seats: usize) -> Result<u32> {
    ensure!(
        iroha::data_model::block::consensus::is_valid_committee_size(seats),
        "not an exact 3f+1 roster within the supported 4..31 seats"
    );
    let faults = (seats - 1) / 3;
    Ok(u32::try_from(seats - faults)?)
}

fn finality_limits() -> NativeFinalityLimits {
    NativeFinalityLimits {
        block_bytes: 32 * 1024 * 1024,
        journal_bytes: 64 * 1024 * 1024,
        block_count: usize::try_from(MAX_QUALIFICATION_HEIGHT).expect("bounded fixture history"),
        allocated_bytes: 512 * 1024 * 1024,
    }
}

fn verify_equal_vote_context(proof: &CertifiedBlock, expected: &BTreeSet<PeerId>) -> Result<()> {
    let context = &proof.commitment().schedule.current;
    let actual = context
        .committee
        .iter()
        .map(|seat| seat.validator.clone())
        .collect::<BTreeSet<_>>();
    let quorum = usize::try_from(exact_quorum(expected.len())?)?;
    ensure!(
        context.committee.len() == expected.len()
            && actual == *expected
            && proof
                .commit_qc()
                .is_some_and(|qc| qc.signers.count_ones() == quorum),
        "native finality is not an exact equal-vote certificate for the expected roster"
    );
    Ok(())
}

async fn prove_retained_successor_after_restart(
    network: &sandbox::SerializedNetwork,
    admin: &Client,
    genesis_voters: &BTreeSet<PeerId>,
    cancelled: &ValidatorCommitteePreparationV1,
    cutoff: &CertifiedBlock,
    signed_genesis_hash: iroha::crypto::HashOf<iroha::data_model::block::BlockHeader>,
) -> Result<()> {
    let boundary = cutoff
        .commitment()
        .schedule
        .boundary
        .as_ref()
        .ok_or_else(|| eyre!("retention cutoff lacks its authenticated boundary"))?;
    let replacement = boundary
        .preparation
        .as_ref()
        .ok_or_else(|| eyre!("cancelled attempt lacks a fresh E+3 selection"))?;
    ensure!(
        cutoff.height() == CUTOFF
            && boundary.next.authorization.decision == ValidatorEpochDecisionV1::RetainAndCancel
            && boundary.next.generation() == cutoff.commitment().schedule.current.generation()
            && boundary.next.committee == cutoff.commitment().schedule.current.committee
            && replacement.target_epoch == 3
            && replacement.selection_height == CUTOFF
            && replacement.transition_id().map_err(|error| eyre!(error))?
                != cancelled.transition_id().map_err(|error| eyre!(error))?
            && replacement
                .beacon_session_id()
                .map_err(|error| eyre!(error))?
                != cancelled
                    .beacon_session_id()
                    .map_err(|error| eyre!(error))?,
        "cancelled preparation cannot be shrunk or reused as the next attempt"
    );
    network.shutdown().await;
    network.start_all().await?;
    network.ensure_blocks(CUTOFF).await?;
    let restarted = read_validator_committee(admin, 2).await?;
    ensure!(
        restarted.selected.as_ref().is_some_and(|row| {
            row.transition.preparation == *cancelled
                && row.transition.outcome.as_ref() == Some(&boundary.next.authorization)
        }),
        "all-seat restart lost the immutable cancelled transition"
    );
    let transaction = committee_staking::submit_signed(
        admin,
        Log::new(
            Level::INFO,
            "prove retained generation after all-seat restart".to_owned(),
        )
        .into(),
        true,
    )
    .await?;
    network.ensure_blocks(TARGET_FIRST).await?;
    let (_, chain) = read_on_dedicated_thread({
        let admin = admin.clone();
        let network_id = network.network_id();
        move || {
            read_contiguous_finality_chain(&admin, network_id, signed_genesis_hash, TARGET_FIRST)
        }
    })
    .await
    .wrap_err("restarted retained-generation finality worker failed")?;
    let successor = chain
        .last()
        .ok_or_else(|| eyre!("retained generation did not certify its successor"))?;
    verify_equal_vote_context(successor, genesis_voters)?;
    let current = &successor.commitment().schedule.current;
    ensure!(
        genesis_voters.len() == 4
            && chain.iter().any(|block| {
                block.height() == CUTOFF && block.block_hash() == cutoff.block_hash()
            })
            && successor.height() == TARGET_FIRST
            && current.authorization.authority_generation == 0
            && current.authorization.epoch == 2
            && current == &boundary.next,
        "restarted successor must use the exact retained generation and ordered original four seats"
    );
    let block = successor.block();
    ensure!(
        block.network_entrypoint_count() == 1
            && matches!(block.network_entrypoint_at(0),
                Some(TransactionEntrypoint::External(input)) if input == &transaction),
        "retained successor must execute exactly the newly signed paid input"
    );
    let (_, output) = block
        .network_output_at(0)
        .ok_or_else(|| eyre!("retained successor lost its paid Network output"))?;
    let receipt = output
        .result
        .nexus_fee_receipt()
        .ok_or_else(|| eyre!("retained successor omitted actual fee settlement"))?;
    ensure!(
        output.result.0.is_ok()
            && receipt.source_id == *Hash::from(transaction.hash_as_entrypoint()).as_ref()
            && receipt.block_height == TARGET_FIRST
            && receipt.fee_asset_id == cancelled.eligibility.xor_asset_definition_id
            && receipt.debit_source
                == iroha::data_model::nexus::FeeDebitSource::Account(
                    transaction.authority().clone()
                )
            && matches!(
                receipt.settlement,
                iroha::data_model::block::consensus::NexusFeeSettlementV1::Burn
            )
            && !receipt.fee_amount.is_zero(),
        "retained-generation progress must settle its separate actual XOR fee"
    );
    let fresh = read_validator_committee(admin, 3).await?;
    ensure!(
        fresh.selected.as_ref().is_some_and(|row| {
            row.transition.preparation == *replacement && row.transition.outcome.is_none()
        }),
        "retained-generation restart must preserve the exact fresh E+3 preparation"
    );
    Ok(())
}

fn ranked_target(
    preparation: &ValidatorCommitteePreparationV1,
    pool: &BTreeSet<PeerId>,
    seats: usize,
) -> BTreeSet<PeerId> {
    let mut ranked = pool
        .iter()
        .map(|peer| {
            // Independent reproduction of the public, network/epoch-bound election rank.
            let identity = norito::encode_canonical(peer).expect("canonical candidate");
            let rank: [u8; 32] = Hash::new_from_chunks(&[
                b"iroha:validator-seat:v1",
                &[0],
                preparation.network_id.as_bytes(),
                &preparation.selection_epoch.to_le_bytes(),
                &preparation.target_epoch.to_le_bytes(),
                &preparation.election_seed,
                &identity,
            ])
            .into();
            (rank, peer.clone())
        })
        .collect::<Vec<_>>();
    ranked.sort();
    ranked
        .into_iter()
        .take(seats)
        .map(|(_, peer)| peer)
        .collect()
}

fn validator_xor_escrow(
    genesis: &iroha_genesis::GenesisBlock,
    xor: &AssetDefinitionId,
) -> Result<AssetId> {
    let fee_asset: AssetDefinitionId = defaults::nexus::fees::fee_asset_id().parse()?;
    ensure!(
        fee_asset == *xor && SumeragiNposParameters::default().xor_asset_definition_id == *xor,
        "fee, staking and NPoS defaults must select the same canonical XOR"
    );
    let mut definitions = 0;
    let mut signed_npos = 0;
    let mut registrations = 0;
    let mut alice_funded = false;
    let mut escrow = None;
    for transaction in genesis.0.external_transactions() {
        let Executable::Instructions(instructions) = transaction.instructions() else {
            continue;
        };
        for instruction in instructions {
            if let Some(iroha::data_model::isi::RegisterBox::AssetDefinition(register)) =
                instruction
                    .as_any()
                    .downcast_ref::<iroha::data_model::isi::RegisterBox>()
                && register.object.id == *xor
            {
                definitions += 1;
                ensure!(
                    register.object.spec == iroha_primitives::numeric::NumericSpec::fractional(9),
                    "signed XOR definition must have its canonical fractional quantity"
                );
            }
            if let Some(set) = instruction.as_any().downcast_ref::<SetParameter>()
                && let Parameter::Custom(custom) = set.inner()
                && custom.id() == &SumeragiNposParameters::parameter_id()
            {
                signed_npos += 1;
                let parameters = SumeragiNposParameters::from_custom_parameter(custom)?
                    .ok_or_else(|| eyre!("signed genesis NPoS parameters are invalid"))?;
                ensure!(
                    parameters.xor_asset_definition_id == *xor,
                    "signed NPoS parameters bind a foreign staking asset"
                );
            }
            if let Some(registration) = instruction
                .as_any()
                .downcast_ref::<RegisterPublicLaneValidator>()
            {
                registrations += 1;
                ensure!(
                    registration.monetary_plan.source_asset.definition() == xor
                        && registration.monetary_plan.destination_asset.definition() == xor
                        && registration.monetary_plan.amount == registration.initial_stake,
                    "signed validator bond must transfer exact canonical XOR principal"
                );
                if let Some(existing) = &escrow {
                    ensure!(
                        existing == &registration.monetary_plan.destination_asset,
                        "genesis validator bonds must share the exact XOR escrow"
                    );
                } else {
                    escrow = Some(registration.monetary_plan.destination_asset.clone());
                }
            }
            if let Some(iroha::data_model::isi::MintBox::Asset(mint)) =
                instruction
                    .as_any()
                    .downcast_ref::<iroha::data_model::isi::MintBox>()
                && mint.destination.definition() == xor
                && mint.destination.account() == &*ALICE_ID
            {
                alice_funded = true;
            }
        }
    }
    ensure!(
        definitions == 1 && signed_npos == 1 && registrations == 4 && alice_funded,
        "signed genesis must define one canonical XOR, bind NPoS, fund XOR and bond all four voters"
    );
    escrow.ok_or_else(|| eyre!("signed genesis has no exact validator XOR escrow"))
}

fn admit_candidates(
    admin: &Client,
    candidates: &[Operator],
    network_id: NetworkId,
    xor: &AssetDefinitionId,
    escrow: &AssetId,
) -> Result<()> {
    let parameters = admin.client().query_single(FindParameters)?;
    ensure!(
        !parameters
            .custom()
            .contains_key(&ValidationFeePolicyRegistryV1::parameter_id()),
        "this custody scenario requires no enacted validation-fee policy"
    );
    let funding = candidates
        .iter()
        .flat_map(|operator| {
            [
                Register::account(Account::new(operator.account.clone())).into(),
                Transfer::asset_quantity(
                    AssetId::new(xor.clone(), ALICE_ID.clone()),
                    10_000_u64,
                    operator.account.clone(),
                )
                .into(),
            ]
        })
        .collect::<Vec<InstructionBox>>();
    committee_status::submit_and_observe_until(
        admin.clone(),
        admin.clone(),
        Instant::now() + WAIT,
        |bounded| bounded.submit_all(funding, FeePaymentIntent::authority(Vec::new(), None)),
    )?;
    for operator in candidates {
        let inclusion_height =
            committee_status::height_until_blocking(admin, Instant::now() + WAIT)? + 1;
        ensure!(
            inclusion_height < SELECTION,
            "candidate missed the unfrozen selecting prestate"
        );
        let registration = RegisterPublicLaneValidator {
            lane_id: LaneId::SINGLE,
            validator: operator.account.clone(),
            peer_id: operator.peer.clone(),
            stake_account: operator.account.clone(),
            initial_stake: 2_000_u64.into(),
            metadata: Metadata::default(),
            monetary_plan: PublicLaneMonetaryPlanV1 {
                network_scope: PublicLaneMonetaryScopeV1::Network(network_id),
                valid_until_height: SELECTION - 1,
                source_asset: AssetId::new(xor.clone(), operator.account.clone()),
                destination_asset: escrow.clone(),
                amount: 2_000_u64.into(),
                precondition: PublicLaneMonetaryPreconditionV1::Registration(
                    PublicLaneMonetaryRegistrationV1 {
                        activation_height: TARGET_FIRST,
                    },
                ),
            },
        };
        let authorization =
            PublicLaneCandidateAuthorization::new(network_id, registration.clone(), TARGET_FIRST);
        let candidate = RegisterPublicLaneCandidate {
            registration,
            activation_height: TARGET_FIRST,
            proof_of_possession: operator.pop.clone(),
            peer_signature: SignatureOf::try_new(
                operator.consensus_key.private_key(),
                &authorization,
            )?,
        };
        committee_status::submit_and_observe_until(
            operator.client.clone(),
            admin.clone(),
            Instant::now() + WAIT,
            |bounded| bounded.submit(candidate, FeePaymentIntent::authority(Vec::new(), None)),
        )
        .wrap_err_with(|| format!("candidate {} admission failed", operator.peer))?;
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ProgressAction {
    Complete,
    AwaitCatchup,
    SubmitAt(u64),
}

/// Spend one progress transaction only after every voter has applied the prior one.
fn progress_action(
    heights: &[u64],
    target: u64,
    pending_height: Option<u64>,
) -> Result<ProgressAction> {
    let minimum = *heights
        .iter()
        .min()
        .ok_or_else(|| eyre!("no progress voters"))?;
    let maximum = *heights.iter().max().expect("nonempty voter heights");
    if minimum >= target {
        return Ok(ProgressAction::Complete);
    }
    if maximum >= target
        || minimum != maximum
        || pending_height.is_some_and(|height| minimum < height)
    {
        return Ok(ProgressAction::AwaitCatchup);
    }
    Ok(ProgressAction::SubmitAt(
        minimum
            .checked_add(1)
            .ok_or_else(|| eyre!("progress height overflow"))?,
    ))
}

async fn advance_to_height(
    network: &sandbox::SerializedNetwork,
    voters: &[PeerId],
    target: u64,
) -> Result<()> {
    let peers = exact_process_roster(network, voters)?;
    let deadline = Instant::now() + WAIT;
    let clients = peers
        .iter()
        .map(|peer| peer.client().client().clone())
        .collect::<Vec<_>>();
    let mut tick = 0_u64;
    let mut pending_height = None;
    loop {
        let heights = committee_status::heights_until(&clients, deadline).await?;
        ensure!(
            Instant::now() < deadline,
            "current validator quorum stalled before height {target}; heights={heights:?}"
        );
        match progress_action(&heights, target, pending_height)? {
            ProgressAction::Complete => return Ok(()),
            ProgressAction::AwaitCatchup => {}
            ProgressAction::SubmitAt(height) => {
                let client = peers[usize::try_from(tick)? % peers.len()].client();
                let message = format!("committee transition progress {target}:{tick}");
                pending_height = Some(height);
                committee_status::submit_async_until(
                    client.client().clone(),
                    deadline,
                    |bounded| async move {
                        let account = bounded.account_client()?;
                        let mut payload = account.prepare_transaction(
                            iroha::client::AccountTransactionDraft::new(
                                vec![Log::new(Level::INFO, message)],
                                FeePaymentIntent::authority(Vec::new(), None),
                                Metadata::default(),
                            ),
                        )?;
                        let quote = account
                            .quote_fees(iroha::client::FeeQuoteRequest::AccountSignature {
                                payload: &payload,
                            })
                            .await?;
                        ensure!(
                            payload
                                .fee_payment
                                .has_same_payer_and_gas_bound(&quote.intent),
                            "progress fee quote changed the signed payer"
                        );
                        payload.fee_payment = quote.intent;
                        let transaction = account.sign_transaction(payload)?;
                        account.submit_transaction_and_wait(&transaction).await?;
                        Ok::<_, eyre::Report>(())
                    },
                )
                .await
                .wrap_err("committee progress transaction failed")?;
                tick += 1;
            }
        }
        sleep(POLL).await;
    }
}

fn exact_process_roster<'a>(
    network: &'a sandbox::SerializedNetwork,
    roster: &[PeerId],
) -> Result<Vec<&'a NetworkPeer>> {
    let peers = network
        .validators()
        .iter()
        .chain(network.committee_validators());
    let mut ordered = Vec::with_capacity(roster.len());
    for validator in roster {
        let peer = peers
            .clone()
            .find(|peer| peer.id() == *validator)
            .ok_or_else(|| eyre!("authenticated committee lacks a disposable process"))?;
        ordered.push(peer);
    }
    ensure!(
        ordered.len() == roster.len()
            && roster.iter().collect::<BTreeSet<_>>().len() == roster.len(),
        "committee process roster is not an exact one-to-one mapping"
    );
    Ok(ordered)
}

async fn advance_exact_rotation_phase(
    network: &sandbox::SerializedNetwork,
    voters: &[PeerId],
    height: u64,
    deadline: Instant,
) -> Result<()> {
    ensure!(
        exact_quorum(voters.len()).is_ok(),
        "rotation phase requires an exact current quorum geometry"
    );
    let peers = exact_process_roster(network, voters)?;
    let mut before = Vec::with_capacity(peers.len());
    for peer in &peers {
        before.push(committee_status::height_until(peer.client().client(), deadline).await?);
    }
    ensure!(
        before.iter().all(|observed| *observed == height - 1),
        "rotation DKG phase h{height} started after a voter passed its predecessor: {before:?}"
    );
    let client = peers[0].client();
    read_on_dedicated_thread(move || {
        committee_status::submit_until(client, deadline, |bounded| {
            bounded.submit(
                Log::new(Level::INFO, format!("rotation DKG exact phase h{height}")),
                FeePaymentIntent::authority(Vec::new(), None),
            )
        })
    })
    .await
    .wrap_err("rotation DKG phase submit worker failed")?;
    loop {
        let mut observed = Vec::with_capacity(peers.len());
        for peer in &peers {
            observed.push(committee_status::height_until(peer.client().client(), deadline).await?);
        }
        ensure!(
            observed.iter().all(|current| *current <= height),
            "rotation DKG phase h{height} was overtaken: {observed:?}"
        );
        if observed.iter().all(|current| *current == height) {
            return Ok(());
        }
        ensure!(
            Instant::now() < deadline,
            "rotation DKG phase h{height} did not finalize on all current voters: {observed:?}"
        );
        sleep(POLL).await;
    }
}

async fn advance_exact_genesis_phase(
    network: &sandbox::SerializedNetwork,
    height: u64,
    deadline: Instant,
) -> Result<()> {
    ensure!(
        (2..=4).contains(&height),
        "invalid genesis DKG phase height"
    );
    let mut before = Vec::new();
    for peer in network.validators() {
        before.push(committee_status::height_until(peer.client().client(), deadline).await?);
    }
    ensure!(
        before.iter().all(|observed| *observed == height - 1),
        "genesis DKG phase h{height} started after a peer passed its predecessor: {before:?}"
    );
    let client = network.validators()[0].client();
    read_on_dedicated_thread(move || {
        committee_status::submit_until(client, deadline, |bounded| {
            bounded.submit(
                Log::new(Level::INFO, format!("genesis DKG exact phase h{height}")),
                FeePaymentIntent::authority(Vec::new(), None),
            )
        })
    })
    .await
    .wrap_err("genesis DKG phase submit worker failed")?;
    loop {
        let mut observed = Vec::new();
        for peer in network.validators() {
            observed.push(committee_status::height_until(peer.client().client(), deadline).await?);
        }
        ensure!(
            observed.iter().all(|current| *current <= height),
            "genesis DKG phase h{height} was overtaken: {observed:?}"
        );
        if observed.iter().all(|current| *current == height) {
            return Ok(());
        }
        ensure!(
            Instant::now() < deadline,
            "genesis DKG phase h{height} did not finalize on all four seats: {observed:?}"
        );
        sleep(POLL).await;
    }
}

fn read_genesis_dkg_finality_chain(
    client: &Client,
    network_id: NetworkId,
    signed_genesis_hash: iroha::crypto::HashOf<iroha::data_model::block::BlockHeader>,
    end: u64,
    deadline: Instant,
) -> Result<NativeFinalityJournal> {
    ensure!(
        (2..=4).contains(&end),
        "genesis DKG phase must have actual H2–H4 finality"
    );
    Ok(read_contiguous_finality_chain_until(
        client,
        network_id,
        signed_genesis_hash,
        end,
        deadline,
    )?
    .0)
}

fn read_contiguous_finality_chain(
    client: &Client,
    network_id: NetworkId,
    signed_genesis_hash: iroha::crypto::HashOf<iroha::data_model::block::BlockHeader>,
    end: u64,
) -> Result<(NativeFinalityJournal, Vec<CertifiedBlock>)> {
    read_contiguous_finality_chain_until(
        client,
        network_id,
        signed_genesis_hash,
        end,
        Instant::now() + WAIT,
    )
}

// One canonical reader implementation serves fresh observations and callers
// that already own an enclosing deadline; it never replenishes that deadline.
fn read_contiguous_finality_chain_until(
    client: &Client,
    network_id: NetworkId,
    signed_genesis_hash: iroha::crypto::HashOf<iroha::data_model::block::BlockHeader>,
    end: u64,
    deadline: Instant,
) -> Result<(NativeFinalityJournal, Vec<CertifiedBlock>)> {
    let source = client.client().with_request_deadline(deadline);
    finality_chain_from_proofs(
        client.client().chain(),
        network_id,
        signed_genesis_hash,
        end,
        deadline,
        interval_finality_fetch(&source, end),
    )
}

// Each request retains at most 64 actual full-proof DTOs. Consumed rows move into
// the existing native journal; they are never copied to a second authority graph.
// TODO: close the fixture's existing SDK DTO/journal metadata funding obligation.
fn interval_finality_fetch<'a>(
    client: &'a iroha::client::Client,
    end: u64,
) -> impl FnMut(NonZeroU64) -> Result<iroha::data_model::sumeragi_finality::SumeragiFinalityProof> + 'a
{
    interval_finality_fetch_with(end, move |from, to| {
        client.get_sumeragi_finality_interval(from, to)
    })
}
fn interval_finality_fetch_with<'a>(
    end: u64,
    mut fetch: impl FnMut(
        NonZeroU64,
        NonZeroU64,
    )
        -> Result<Vec<iroha::data_model::sumeragi_finality::SumeragiFinalityProof>>
    + 'a,
) -> impl FnMut(NonZeroU64) -> Result<iroha::data_model::sumeragi_finality::SumeragiFinalityProof> + 'a
{
    let mut rows = Vec::new().into_iter();
    let mut next = None;
    move |height| {
        ensure!(
            height.get() <= end,
            "interval source exceeds original final target"
        );
        if let Some(expected) = next {
            ensure!(
                height.get() == expected,
                "interval source requires its exact next original row"
            );
        }
        if rows.len() == 0 {
            let to = height.get().saturating_add(63).min(end);
            let batch = fetch(height, NonZeroU64::new(to).expect("positive final target"))?;
            ensure!(
                batch.len() as u64 == to - height.get() + 1,
                "interval source must retain every exact original row"
            );
            rows = batch.into_iter();
        }
        let proof = rows
            .next()
            .ok_or_else(|| eyre!("interval source has no original next row"))?;
        ensure!(
            proof.height() == height.get(),
            "interval source substituted its original row"
        );
        next = height.get().checked_add(1);
        Ok(proof)
    }
}

fn finality_chain_from_proofs(
    chain_id: &iroha_model_base::chain::ChainId,
    network_id: NetworkId,
    signed_genesis_hash: iroha::crypto::HashOf<iroha::data_model::block::BlockHeader>,
    end: u64,
    deadline: Instant,
    mut fetch: impl FnMut(
        NonZeroU64,
    ) -> Result<iroha::data_model::sumeragi_finality::SumeragiFinalityProof>,
) -> Result<(NativeFinalityJournal, Vec<CertifiedBlock>)> {
    ensure!(
        (2..=MAX_QUALIFICATION_HEIGHT).contains(&end),
        "committee proof cut exceeds its explicit disposable bound"
    );
    ensure!(
        network_id.into_genesis_hash() == signed_genesis_hash,
        "network differs from independent signed genesis"
    );
    let limits = finality_limits();
    let mut journal = NativeFinalityJournal { blocks: Vec::new() };
    let mut source_bytes = 0_usize;
    // Move each exact canonical carrier from the bounded public interval endpoint.
    // Candidate proof metadata never chooses the committee or substitutes for the
    // complete, independently genesis-anchored journal verification below.
    for height in 1..=end {
        ensure!(
            Instant::now() < deadline,
            "committee proof retrieval deadline elapsed"
        );
        let proof = fetch(NonZeroU64::new(height).expect("prefix starts at one"))?;
        ensure!(
            proof.height() == height,
            "committee proof differs from requested height"
        );
        ensure!(
            !proof.block_wire.is_empty() && proof.block_wire.len() <= limits.block_bytes,
            "committee proof exceeds its block source bound"
        );
        source_bytes = source_bytes
            .checked_add(proof.block_wire.len())
            .ok_or_else(|| eyre!("committee proof source size overflow"))?;
        ensure!(
            source_bytes <= limits.journal_bytes,
            "committee proof exceeds its journal source bound"
        );
        proof.decode_checked()?;
        journal.blocks.push(NativeFinalityArtifact {
            block_wire: proof.block_wire,
        });
    }
    let blocks = authenticate_finality_journal(&journal, chain_id, network_id, end, deadline)?;
    Ok((journal, blocks))
}

// Both the original fresh reader and the growing journal run the same complete
// native verifier. Earlier rows never acquire authority from being retained.
fn authenticate_finality_journal(
    journal: &NativeFinalityJournal,
    chain_id: &iroha_model_base::chain::ChainId,
    network_id: NetworkId,
    end: u64,
    deadline: Instant,
) -> Result<Vec<CertifiedBlock>> {
    let limits = finality_limits();
    let cursor = NativeJournalCursor::new(
        chain_id.clone(),
        network_id,
        iroha_data_model::block::consensus::SumeragiRootScope::Global,
        limits,
        &iroha_allocation::AllocationBudget::new(limits.allocated_bytes),
    )
    .map_err(|error| eyre!(error))?;
    let blocks = with_verified_native_journal(
        journal.into(),
        chain_id,
        &network_id,
        limits,
        cursor.allocation_budget(),
        |reader| {
            reader
                .walk(1, end)
                .collect::<std::result::Result<Vec<_>, _>>()
                .map_err(iroha_core::sumeragi::native_journal::NativeJournalError::History)
        },
    )
    .map_err(|error| eyre!(error))?;
    ensure!(
        Instant::now() < deadline,
        "committee proof verification deadline elapsed"
    );
    Ok(blocks)
}

// A terminal ceremony callback owns its original base and every acquired suffix
// row. Only actual new heights are requested; failure drops those original owners
// rather than resetting quotas, truncating for retry or refetching old frames.
// TODO: fund HTTP/DTO graphs and journal metadata/codec scratch independently;
// unchanged source bounds and native decoder counters are not full pool custody.
fn append_contiguous_finality_chain_until(
    client: &Client,
    network_id: NetworkId,
    signed_genesis_hash: iroha::crypto::HashOf<iroha::data_model::block::BlockHeader>,
    journal: NativeFinalityJournal,
    end: u64,
    deadline: Instant,
) -> Result<NativeFinalityJournal> {
    let source = client.client().with_request_deadline(deadline);
    append_finality_chain_from_proofs(
        client.client().chain(),
        network_id,
        signed_genesis_hash,
        journal,
        end,
        deadline,
        interval_finality_fetch(&source, end),
    )
}

fn append_finality_chain_from_proofs(
    chain_id: &iroha_model_base::chain::ChainId,
    network_id: NetworkId,
    signed_genesis_hash: iroha::crypto::HashOf<iroha::data_model::block::BlockHeader>,
    journal: NativeFinalityJournal,
    end: u64,
    deadline: Instant,
    fetch: impl FnMut(NonZeroU64) -> Result<iroha::data_model::sumeragi_finality::SumeragiFinalityProof>,
) -> Result<NativeFinalityJournal> {
    let base = u64::try_from(journal.blocks.len())?;
    ensure!(
        base >= 2 && base < end,
        "rotation phase must extend an original H2+ journal"
    );
    extend_finality_chain_from_proofs(
        chain_id,
        network_id,
        signed_genesis_hash,
        journal,
        end,
        deadline,
        fetch,
    )
    .map(|(journal, _)| journal)
}

// Staking observations may name the same immutable tip. Every observation still runs
// the complete native verifier; only already acquired physical source rows are retained.
fn extend_finality_chain_from_proofs(
    chain_id: &iroha_model_base::chain::ChainId,
    network_id: NetworkId,
    signed_genesis_hash: iroha::crypto::HashOf<iroha::data_model::block::BlockHeader>,
    mut journal: NativeFinalityJournal,
    end: u64,
    deadline: Instant,
    mut fetch: impl FnMut(
        NonZeroU64,
    ) -> Result<iroha::data_model::sumeragi_finality::SumeragiFinalityProof>,
) -> Result<(NativeFinalityJournal, Vec<CertifiedBlock>)> {
    ensure!(
        (2..=MAX_QUALIFICATION_HEIGHT).contains(&end),
        "committee proof cut exceeds its explicit disposable bound"
    );
    ensure!(
        network_id.into_genesis_hash() == signed_genesis_hash,
        "network differs from independent signed genesis"
    );
    ensure!(
        Instant::now() < deadline,
        "committee proof retrieval deadline elapsed"
    );
    let limits = finality_limits();
    journal
        .validate_source(limits)
        .map_err(|error| eyre!(error))?;
    let base = u64::try_from(journal.blocks.len())?;
    ensure!(
        base >= 2 && base <= end,
        "retained observation must preserve or extend its original H2+ journal"
    );
    eprintln!(
        "rotation finality prefix acquisition: base={base} target={end} planned_new_rows={}",
        end - base
    );
    let mut source_bytes = journal.blocks.iter().try_fold(0_usize, |count, artifact| {
        count
            .checked_add(artifact.block_wire.len())
            .ok_or_else(|| eyre!("committee proof source size overflow"))
    })?;
    for height in base + 1..=end {
        ensure!(
            Instant::now() < deadline,
            "committee proof retrieval deadline elapsed"
        );
        let proof = fetch(NonZeroU64::new(height).expect("successors are nonzero"))?;
        ensure!(
            proof.height() == height,
            "committee proof differs from requested height"
        );
        ensure!(
            !proof.block_wire.is_empty() && proof.block_wire.len() <= limits.block_bytes,
            "committee proof exceeds its block source bound"
        );
        source_bytes = source_bytes
            .checked_add(proof.block_wire.len())
            .ok_or_else(|| eyre!("committee proof source size overflow"))?;
        ensure!(
            source_bytes <= limits.journal_bytes,
            "committee proof exceeds its journal source bound"
        );
        proof.decode_checked()?;
        journal
            .blocks
            .try_reserve(1)
            .map_err(|error| eyre!(error))?;
        journal.blocks.push(NativeFinalityArtifact {
            block_wire: proof.block_wire,
        });
    }
    eprintln!(
        "rotation finality prefix acquired: base={base} target={end} actual_new_rows={}",
        end - base
    );
    let blocks = authenticate_finality_journal(&journal, chain_id, network_id, end, deadline)?;
    eprintln!("rotation finality prefix verified: tip={end}");
    Ok((journal, blocks))
}

async fn stage_genesis_brokers(
    network: &sandbox::SerializedNetwork,
    dkg: &DisposableGenesisDkgOutput,
) -> Result<BTreeMap<PeerId, Vec<u8>>> {
    let network_id = network.network_id();
    let chain_id = network.chain_id().to_string();
    ensure!(
        dkg.seats.len() == 4,
        "genesis DKG must yield four private seats"
    );
    let mut catalogs = BTreeMap::new();
    for output in &dkg.seats {
        let peer = network
            .validators()
            .iter()
            .find(|peer| peer.id() == output.validator)
            .ok_or_else(|| eyre!("DKG output has no real genesis voter"))?;
        let provider: NativeProviderManifest =
            norito::json::from_slice(&fs::read(&output.provider_path)?)?;
        let expected_digest = global_beacon_partial_signer_public_inventory_digest_v1(
            network_id,
            &[(dkg.public_session.record(), output.signer_index)],
        )?;
        ensure!(
            provider.signer_index == output.signer_index
                && provider.validator == output.validator
                && provider.handle == output.provider_handle
                && provider.revision == output.provider_revision
                && provider.policy_digest == expected_digest,
            "genesis provider manifest is not this exact real seat's public inventory"
        );
        let catalog = IrohaRuntimeProviderBindingsV1::with_prepared_beacon_inventory_v1(
            None,
            &chain_id,
            network_id,
            &provider.handle,
            provider.revision,
            provider.policy_digest, iroha_config::parameters::defaults::runtime_provider_broker::CREDENTIAL_MAX_MEMORY_BYTES.get(),
        )?
        .export_canonical_v1()?;
        let credential = Zeroizing::new(fs::read(&output.credential_path)?);
        let bundle = encode_consensus_threshold_credential_bundle_v1(Some(&credential), None)?;
        peer.provision_disposable_runtime_provider_broker(
            &catalog,
            bundle,
            DisposableBeaconProviderBinding {
                handle: provider.handle,
                revision: provider.revision,
                policy_digest: provider.policy_digest,
            },
        )
        .await?;
        catalogs.insert(output.validator.clone(), catalog);
    }
    Ok(catalogs)
}

#[derive(Clone)]
struct CurrentCustodyRecord {
    credential_path: PathBuf,
    catalog: Vec<u8>,
}

struct PreparedRotation {
    target: Vec<PeerId>,
    prepared: Vec<DisposablePreparedBeaconCustody>,
    _dkg: DisposableRotationDkgOutput,
}

fn genesis_current_custody(
    dkg: &DisposableGenesisDkgOutput,
    catalogs: &BTreeMap<PeerId, Vec<u8>>,
) -> Result<BTreeMap<PeerId, CurrentCustodyRecord>> {
    dkg.seats
        .iter()
        .map(|seat| {
            Ok((
                seat.validator.clone(),
                CurrentCustodyRecord {
                    credential_path: seat.credential_path.clone(),
                    catalog: catalogs
                        .get(&seat.validator)
                        .ok_or_else(|| eyre!("genesis seat lacks its exact public catalog"))?
                        .clone(),
                },
            ))
        })
        .collect()
}

fn prepared_current_custody(
    prepared: &[DisposablePreparedBeaconCustody],
) -> Result<BTreeMap<PeerId, CurrentCustodyRecord>> {
    prepared
        .iter()
        .map(|seat| {
            Ok((
                seat.validator.clone(),
                CurrentCustodyRecord {
                    credential_path: seat.credential_path.clone(),
                    catalog: fs::read(&seat.catalog_path)?,
                },
            ))
        })
        .collect()
}

async fn stage_prepared_brokers(
    network: &sandbox::SerializedNetwork,
    prepared: &[DisposablePreparedBeaconCustody],
    expected_revision: u64,
) -> Result<()> {
    for output in prepared {
        let catalog = fs::read(&output.catalog_path)?;
        let validated = IrohaRuntimeProviderBindingsV1::load_canonical_v1(&catalog)?;
        ensure!(
            validated.network_id() == &network.network_id()
                && validated.chain_id() == network.chain_id().to_string(),
            "prepared custody catalog differs from the signed network"
        );
        let binding = validated
            .iter()
            .find(|binding| binding.slot() == IrohaRuntimeProviderSlotV1::GlobalBeaconPartialSigner)
            .ok_or_else(|| eyre!("native prepared catalog has no beacon binding"))?;
        ensure!(
            binding.revision() == Some(expected_revision)
                && binding
                    .policy_digest()
                    .is_some_and(|digest| digest != [0; 32]),
            "native prepared catalog lacks the exact new revision and public digest"
        );
        let peer = network
            .validators()
            .iter()
            .chain(network.committee_validators())
            .find(|peer| peer.id() == output.validator)
            .ok_or_else(|| eyre!("prepared custody has no real target process"))?;
        let credential = Zeroizing::new(fs::read(&output.credential_path)?);
        let bundle = encode_consensus_threshold_credential_bundle_v1(Some(&credential), None)?;
        peer.provision_disposable_runtime_provider_broker(
            &catalog,
            bundle,
            DisposableBeaconProviderBinding {
                handle: binding.handle().to_owned(),
                revision: expected_revision,
                policy_digest: binding.policy_digest().expect("checked public digest"),
            },
        )
        .await?;
    }
    Ok(())
}

fn prove_exact_target_readiness(
    transition: &iroha::data_model::nexus::ValidatorCommitteeTransitionV1,
    session: &iroha::data_model::consensus::GlobalThresholdBeaconKeySessionV1,
    output: &iroha_test_network::DisposableRotationSeatOutput,
    process: &NetworkPeer,
) -> Result<AdmitValidatorCommitteeSeatV1> {
    let index = u32::from(output.signer_index - 1);
    let context = transition
        .readiness_context(index)
        .map_err(|error| eyre!(error))?;
    let roster = transition
        .preparation
        .committee
        .iter()
        .map(|seat| seat.validator.clone())
        .collect::<Vec<_>>();
    ensure!(
        roster.get(usize::try_from(index)?) == Some(&output.validator),
        "private share differs from the exact target roster seat"
    );
    let roster_hash = global_threshold_beacon_roster_hash_v1(&roster);
    ensure!(
        session.roster_hash == roster_hash && usize::from(session.committee_size) == roster.len(),
        "pending beacon is not bound to the exact ordered target committee"
    );
    let binding = GlobalThresholdBeaconSessionBindingV1 {
        network_id: session.network_id,
        session_id: session.session_id,
        roster_hash,
        transcript_hash: session.transcript_hash,
    };
    let validated = validate_global_threshold_beacon_session_v1(
        session,
        &binding,
        &iroha_allocation::AllocationBudget::new(64 * 1024 * 1024),
    )?;
    let share = Zeroizing::new(fs::read(&output.pending_share_path)?);
    ensure!(
        share.len() == 96,
        "native private share is not three exact components"
    );
    let mut components = Zeroizing::new([[0_u8; 32]; 3]);
    for (component, bytes) in components.iter_mut().zip(share.chunks_exact(32)) {
        component.copy_from_slice(bytes);
    }
    let custody = RuntimeGlobalThresholdBeaconShareCustodyV1::new();
    custody.import_components(validated.clone(), output.signer_index, components)?;
    ensure!(
        process.id() == output.validator,
        "beacon share belongs to another process"
    );
    let beacon = prove_global_threshold_beacon_seat_readiness_v1(
        &custody,
        &validated,
        &transition.preparation.generation(),
        &context,
    )?;
    Ok(AdmitValidatorCommitteeSeatV1 {
        transition_id: transition
            .preparation
            .transition_id()
            .map_err(|error| eyre!(error))?,
        target_epoch: transition.preparation.target_epoch,
        readiness: ValidatorCommitteeSeatReadinessV1 {
            validator_index: index,
            beacon,
        },
    })
}

async fn execute_rotation_preparation(
    network: &sandbox::SerializedNetwork,
    admin: &Client,
    operators: &BTreeMap<PeerId, Operator>,
    preparation: &ValidatorCommitteePreparationV1,
    current_custody: &BTreeMap<PeerId, CurrentCustodyRecord>,
    signed_genesis_hash: iroha::crypto::HashOf<iroha::data_model::block::BlockHeader>,
    provider_revision: u64,
    missing_custody: Option<&PeerId>,
) -> Result<PreparedRotation> {
    let network_id = network.network_id();
    let target_epoch = preparation.target_epoch;
    let transition_id = Hash::prehashed(preparation.transition_id().map_err(|error| eyre!(error))?);
    let status = read_validator_committee(&admin, target_epoch).await?;
    let observed = status
        .latest_finality
        .decode_block(finality_limits())
        .map_err(|error| eyre!(error))?
        .header()
        .height()
        .get();
    ensure!(
        status
            .selected
            .as_ref()
            .is_some_and(|selected| selected.transition.preparation == *preparation)
            && observed > preparation.selection_height
            && observed + 4 < preparation.first_height - 1,
        "rotation status missed the immutable preparation window"
    );
    let target = preparation
        .committee
        .iter()
        .map(|seat| seat.validator.clone())
        .collect::<Vec<_>>();
    let target_seats = exact_process_roster(network, &target)?;
    let (finality_journal, certified_chain) = read_on_dedicated_thread({
        let admin = admin.clone();
        move || read_contiguous_finality_chain(&admin, network_id, signed_genesis_hash, observed)
    })
    .await
    .wrap_err("selection finality worker failed")?;
    let latest = certified_chain
        .last()
        .ok_or_else(|| eyre!("missing observed native tip"))?;
    ensure!(
        NativeFinalityArtifact::from_block(latest.block(), finality_limits())
            .map_err(|error| eyre!(error))?
            == status.latest_finality,
        "status source differs from authenticated native tip"
    );
    let current_roster = latest
        .commitment()
        .schedule
        .current
        .committee
        .iter()
        .map(|seat| seat.validator.clone())
        .collect::<Vec<_>>();
    let authorizing_seats = exact_process_roster(network, &current_roster)?;
    // The original ingress peer may have left the committee. Preserve the same
    // operator and deadlines, but submit lifecycle control through an actual
    // current voter selected by the genesis-authenticated finality above.
    let control_peer = authorizing_seats
        .first()
        .ok_or_else(|| eyre!("authenticated current committee has no control ingress"))?;
    let admin = rebind_blocking_client(admin, |builder| {
        builder.torii_url = control_peer.client().client().endpoint().clone();
    });
    let selection_evidence = ValidatorCommitteeSelectionEvidenceV1 {
        status,
        finality_journal,
    };
    let input = DisposableRotationProofInput {
        network_id,
        chain_id: network.chain_id(),
        finality_limits: finality_limits(),
        target_epoch,
        transition_id,
    };
    let certificate_height = observed + 4;
    let dkg = run_disposable_rotation_dkg(
        &target_seats,
        &authorizing_seats,
        selection_evidence,
        input,
        provider_revision,
        certificate_height,
        |height, deadline, journal| {
            let admin = admin.clone();
            let voters = current_roster.clone();
            async move {
                advance_exact_rotation_phase(network, &voters, height, deadline).await?;
                let observed = read_on_dedicated_thread({
                    let admin = admin.clone();
                    move || -> Result<u64> {
                        Ok(committee_status::height_until_blocking(&admin, deadline)?)
                    }
                })
                .await
                .wrap_err("rotation phase status worker failed")?;
                ensure!(
                    observed == height,
                    "rotation DKG public phase missed exact h{height} observation"
                );
                read_on_dedicated_thread(move || {
                    append_contiguous_finality_chain_until(
                        &admin,
                        network_id,
                        signed_genesis_hash,
                        journal,
                        height,
                        deadline,
                    )
                })
                .await
                .wrap_err("rotation phase finality worker failed")
            }
        },
    )
    .await?;
    let finalize: Vec<InstructionBox> =
        norito::json::from_slice(&fs::read(&dkg.finalization_instruction_path)?)?;
    ensure!(
        finalize.len() == 1,
        "native rotation must emit one lifecycle instruction"
    );
    let certificate = finalize[0]
        .as_any()
        .downcast_ref::<ApplyThresholdKeyLifecycleCertificateV1>()
        .ok_or_else(|| eyre!("native rotation instruction is not beacon finalization"))?
        .certificate
        .clone();
    let at_height = read_on_dedicated_thread({
        let admin = admin.clone();
        move || -> Result<u64> {
            Ok(committee_status::height_until_blocking(&admin, Instant::now() + WAIT)? + 1)
        }
    })
    .await
    .wrap_err("rotation certificate height worker failed")?;
    ensure!(
        at_height == certificate_height && certificate.effective_height == certificate_height,
        "native finalization draft is not the exact next execution height"
    );
    read_on_dedicated_thread({
        let admin = admin.clone();
        let observer = admin.clone();
        let deadline = Instant::now() + WAIT;
        move || {
            committee_status::submit_and_observe_until(admin, observer, deadline, |bounded| {
                bounded.submit_all(finalize, FeePaymentIntent::authority(Vec::new(), None))
            })
        }
    })
    .await
    .wrap_err("rotation finalization worker failed")?;
    let finalized_status = read_validator_committee(&admin, target_epoch).await?;
    let session = finalized_status
        .pending_beacon_session
        .as_ref()
        .ok_or_else(|| eyre!("incumbent-certified target DKG is not pending on chain"))?;
    ensure!(
        session == dkg.public_session.record(),
        "on-chain pending beacon differs from the all-seat native transcript"
    );
    let credentials = ValidatorCommitteeCredentialsV1 {
        beacon: iroha::data_model::sumeragi::epoch::InstalledBeaconEpochBindingV1 {
            session_id: session.session_id,
            transcript_hash: session.transcript_hash,
        },
    };
    let prepare =
        ValidatorCommitteeOperationV1::PrepareCredentials(PrepareValidatorCommitteeCredentialsV1 {
            transition_id: preparation.transition_id().map_err(|error| eyre!(error))?,
            target_epoch,
            credentials,
        });
    let owner = operators
        .get(&target[0])
        .ok_or_else(|| eyre!("first target seat lacks an owning operator"))?
        .client
        .clone();
    read_on_dedicated_thread({
        let observer = admin.clone();
        let deadline = Instant::now() + WAIT;
        move || {
            committee_status::submit_and_observe_until(owner, observer, deadline, |bounded| {
                bounded.submit(
                    SetParameter::new(Parameter::Custom(prepare.into_custom_parameter())),
                    FeePaymentIntent::authority(Vec::new(), None),
                )
            })
        }
    })
    .await
    .wrap_err("rotation credential preparation worker failed")?;
    let prepared_status = read_validator_committee(&admin, target_epoch).await?;
    let prepared_transition = prepared_status
        .selected
        .as_ref()
        .ok_or_else(|| eyre!("prepared status lost its immutable selection"))?
        .transition
        .clone();
    ensure!(
        prepared_transition.credentials.is_some()
            && prepared_transition.readiness.is_empty()
            && prepared_status.pending_beacon_session.as_ref() == Some(dkg.public_session.record()),
        "prepared status lacks exact public target credentials"
    );
    let proof_end = prepared_status
        .latest_finality
        .decode_block(finality_limits())
        .map_err(|error| eyre!(error))?
        .header()
        .height()
        .get();
    let (custody_journal, _) = read_on_dedicated_thread({
        let admin = admin.clone();
        move || read_contiguous_finality_chain(&admin, network_id, signed_genesis_hash, proof_end)
    })
    .await
    .wrap_err("custody finality worker failed")?;
    let custody_evidence = ValidatorCommitteeProvisioningEvidenceV1 {
        status: prepared_status,
        finality_journal: custody_journal,
        beacon_finalization: certificate,
    };
    let credential_max_memory_bytes =
        defaults::runtime_provider_broker::CREDENTIAL_MAX_MEMORY_BYTES;
    let credential_budget =
        iroha_allocation::AllocationBudget::new(credential_max_memory_bytes.get());
    let proof_cursor = NativeJournalCursor::new(
        network.chain_id(),
        network_id,
        iroha_data_model::block::consensus::SumeragiRootScope::Global,
        finality_limits(),
        &credential_budget,
    )
    .map_err(|error| eyre!(error))?;
    verify_validator_committee_provisioning_evidence_v1(
        &custody_evidence,
        &network.chain_id(),
        network_id,
        target_epoch,
        preparation.transition_id().map_err(|error| eyre!(error))?,
        finality_limits(),
        &credential_budget,
    )
    .wrap_err("native custody evidence was not independently authorized")?;
    let mut prepared = Vec::with_capacity(target.len());
    let mut readiness_proofs = BTreeMap::new();
    for seat in &dkg.seats {
        if missing_custody == Some(&seat.validator) {
            fs::remove_file(&seat.pending_share_path)?;
            fs::remove_file(&seat.credential_path)?;
            continue;
        }
        let process = network
            .validators()
            .iter()
            .chain(network.committee_validators())
            .find(|peer| peer.id() == seat.validator)
            .ok_or_else(|| eyre!("prepared seat has no owner-private beacon share process"))?;
        // Bind the public proof to this exact prepared challenge before native import
        // consumes the one-shot share. Only public evidence survives the restart.
        let admission = prove_exact_target_readiness(
            &prepared_transition,
            dkg.public_session.record(),
            seat,
            process,
        )?;
        let retained = current_custody.get(&seat.validator).map(|current| {
            DisposableRetainedBeaconCredential {
                credential_path: &current.credential_path,
                catalog: &current.catalog,
            }
        });
        prepared.push(
            prepare_disposable_pending_custody(
                &custody_evidence,
                &seat.pending_share_path,
                retained,
                DisposablePendingCustodyInput {
                    credential_max_memory_bytes,
                    network_id,
                    finality_limits: finality_limits(),
                    target_epoch,
                    transition_id,
                    local_validator: seat.validator.clone(),
                    chain_id: network.chain_id().to_string(),
                    handle: seat.provider_handle.clone(),
                    revision: provider_revision,
                },
            )
            .await?,
        );
        ensure!(
            fs::metadata(&seat.pending_share_path)?.len() == 0,
            "native custody import did not consume its one-shot pending share"
        );
        ensure!(
            readiness_proofs
                .insert(seat.validator.clone(), admission)
                .is_none(),
            "target custody contains a duplicate seat"
        );
    }
    network.shutdown().await;
    stage_prepared_brokers(network, &prepared, provider_revision).await?;
    network.start_all().await?;
    network.ensure_blocks(proof_end).await?;
    for seat in &dkg.seats {
        if missing_custody == Some(&seat.validator) {
            continue;
        }
        let admission = readiness_proofs
            .remove(&seat.validator)
            .ok_or_else(|| eyre!("prepared seat lost its exact public readiness proof"))?;
        let owner = operators
            .get(&seat.validator)
            .ok_or_else(|| eyre!("prepared seat lacks a real owning operator"))?
            .client
            .clone();
        read_on_dedicated_thread({
            let observer = admin.clone();
            let deadline = Instant::now() + WAIT;
            move || {
                committee_status::submit_and_observe_until(owner, observer, deadline, |bounded| {
                    bounded.submit(
                        SetParameter::new(Parameter::Custom(
                            ValidatorCommitteeOperationV1::AdmitSeat(admission)
                                .into_custom_parameter(),
                        )),
                        FeePaymentIntent::authority(Vec::new(), None),
                    )
                })
            }
        })
        .await
        .wrap_err("target seat readiness admission worker failed")?;
    }
    ensure!(
        readiness_proofs.is_empty(),
        "target custody left an unsubmitted public readiness proof"
    );
    let readiness = read_validator_committee(&admin, target_epoch).await?;
    ensure!(
        readiness.selected.as_ref().is_some_and(|selected| {
            selected.transition.readiness.len()
                == target.len() - usize::from(missing_custody.is_some())
        }),
        "on-chain seat readiness does not match actual provisioned target custody: epoch {target_epoch}, observer {}, expected {}, observed {:?}",
        admin.client().endpoint(),
        target.len() - usize::from(missing_custody.is_some()),
        readiness
            .selected
            .as_ref()
            .map(|selected| selected.transition.readiness.len()),
    );
    Ok(PreparedRotation {
        target,
        prepared,
        _dkg: dkg,
    })
}

async fn run_custody_or_activation_scenario(
    scenario: QualificationScenario,
    network: &sandbox::SerializedNetwork,
    admin: &Client,
    genesis_dkg: &DisposableGenesisDkgOutput,
    genesis_catalogs: &BTreeMap<PeerId, Vec<u8>>,
    operators: &BTreeMap<PeerId, Operator>,
    genesis_voters: &BTreeSet<PeerId>,
    pool: &BTreeSet<PeerId>,
    first_preparation: &ValidatorCommitteePreparationV1,
    signed_genesis_hash: iroha::crypto::HashOf<iroha::data_model::block::BlockHeader>,
    parliament_proposal: Option<iroha::data_model::governance::types::ProposalKind>,
) -> Result<()> {
    let missing = match scenario {
        QualificationScenario::ActivateSevenThenReturnFour => None,
        QualificationScenario::MissingTargetCustody => first_preparation
            .committee
            .iter()
            .map(|seat| &seat.validator)
            .find(|peer| !genesis_voters.contains(*peer))
            .cloned(),
        _ => first_preparation
            .committee
            .iter()
            .map(|seat| &seat.validator)
            .find(|peer| genesis_voters.contains(*peer))
            .or_else(|| {
                (scenario != QualificationScenario::WithheldIncumbentCustody)
                    .then(|| {
                        first_preparation
                            .committee
                            .first()
                            .map(|seat| &seat.validator)
                    })
                    .flatten()
            })
            .cloned(),
    };
    ensure!(
        scenario == QualificationScenario::ActivateSevenThenReturnFour || missing.is_some(),
        "retention scenario requires its exact missing target custodian"
    );
    let first_current = genesis_current_custody(genesis_dkg, genesis_catalogs)?;
    let first = execute_rotation_preparation(
        network,
        admin,
        operators,
        first_preparation,
        &first_current,
        signed_genesis_hash,
        2,
        missing.as_ref(),
    )
    .await?;
    ensure!(
        first.target.len() == scenario.selected_seats()
            && first.prepared.len() == first.target.len() - usize::from(missing.is_some()),
        "first target custody preparation did not preserve the exact selected membership"
    );
    let governance_pulse = if scenario == QualificationScenario::ActivateSevenThenReturnFour {
        Some(
            committee_parliament::exercise(
                network,
                admin,
                genesis_voters,
                first_preparation,
                genesis_dkg.public_session.record(),
                first._dkg.public_session.record(),
                signed_genesis_hash,
                parliament_proposal.ok_or_else(|| {
                    eyre!("complete rotation lacks its admitted Parliament proposal")
                })?,
            )
            .await?,
        )
    } else {
        ensure!(
            parliament_proposal.is_none(),
            "retention-only scenario acquired an unrelated proposal"
        );
        None
    };
    let initial_roster = network
        .validators()
        .iter()
        .map(|peer| peer.id())
        .collect::<Vec<_>>();
    let survivors = if scenario == QualificationScenario::ActivateSevenThenReturnFour {
        let survivors = first
            .target
            .iter()
            .take(4)
            .cloned()
            .collect::<BTreeSet<_>>();
        ensure!(
            survivors.len() == 4,
            "return election must retain four distinct seats"
        );
        for peer in pool.difference(&survivors) {
            let owner = operators
                .get(peer)
                .ok_or_else(|| eyre!("exiting candidate lacks a real owner"))?
                .clone();
            let deadline = Instant::now() + WAIT;
            let observer = admin.clone();
            read_on_dedicated_thread(move || {
                committee_status::submit_and_observe_until(
                    owner.client,
                    observer,
                    deadline,
                    |bounded| {
                        bounded.submit(
                            ExitPublicLaneValidator {
                                lane_id: LaneId::SINGLE,
                                validator: owner.account,
                                release_at_ms: committee_staking::finite_release_deadline()?,
                            },
                            FeePaymentIntent::authority(Vec::new(), None),
                        )
                    },
                )
            })
            .await
            .wrap_err("future candidate exit worker failed")?;
        }
        let before_cutoff = read_on_dedicated_thread({
            let admin = admin.clone();
            move || -> Result<u64> {
                Ok(committee_status::height_until_blocking(
                    &admin,
                    Instant::now() + WAIT,
                )?)
            }
        })
        .await
        .wrap_err("pre-cutoff height worker failed")?;
        ensure!(
            before_cutoff < CUTOFF,
            "future exit requests must precede the E+3 selecting boundary"
        );
        Some(survivors)
    } else {
        None
    };
    advance_to_height(network, &initial_roster, CUTOFF).await?;
    let (_, cutoff_chain) = read_on_dedicated_thread({
        let admin = admin.clone();
        let network_id = network.network_id();
        move || read_contiguous_finality_chain(&admin, network_id, signed_genesis_hash, CUTOFF)
    })
    .await
    .wrap_err("first cutoff finality worker failed")?;
    if let Some(pulse) = &governance_pulse {
        committee_parliament::verify_boundary(
            &cutoff_chain,
            pulse,
            genesis_dkg.public_session.record(),
        )?;
    }
    let genesis = cutoff_chain
        .first()
        .ok_or_else(|| eyre!("missing authenticated signed genesis"))?;
    ensure!(
        genesis
            .commitment()
            .schedule
            .current
            .authorization
            .authority_generation
            == 0,
        "actual signed genesis must establish the initial validator generation"
    );
    let genesis_roster = genesis
        .commitment()
        .schedule
        .current
        .committee
        .iter()
        .map(|seat| seat.validator.clone())
        .collect::<BTreeSet<_>>();
    ensure!(
        genesis_roster == *genesis_voters,
        "signed genesis differs from the independently built roster"
    );
    let selection = cutoff_chain
        .iter()
        .find(|block| block.height() == SELECTION)
        .ok_or_else(|| eyre!("missing native selecting boundary"))?;
    verify_equal_vote_context(selection, genesis_voters)?;
    ensure!(
        selection
            .commitment()
            .schedule
            .boundary
            .as_ref()
            .is_some_and(|boundary| { boundary.preparation.as_ref() == Some(first_preparation) }),
        "the complete selected preparation must be frozen in the incumbent boundary QC"
    );
    let selection_status = read_validator_committee(admin, first_preparation.target_epoch).await?;
    ensure!(
        selection_status.selected.as_ref().is_some_and(|selected| {
            NativeFinalityArtifact::from_block(selection.block(), finality_limits())
                .is_ok_and(|artifact| artifact == selected.selecting_finality)
        }),
        "committee status must retain the exact authenticated selecting certificate"
    );
    let cutoff = cutoff_chain
        .last()
        .ok_or_else(|| eyre!("first cutoff lacks authenticated finality"))?;
    verify_equal_vote_context(cutoff, genesis_voters)?;
    let snapshot = cutoff
        .commitment()
        .schedule
        .boundary
        .as_ref()
        .ok_or_else(|| eyre!("first cutoff lacks certified epoch effect"))?;
    let decision = &snapshot.next.authorization;
    ensure!(
        decision.epoch == 2
            && decision.transition_id
                == first_preparation
                    .transition_id()
                    .map_err(|error| eyre!(error))?,
        "first cutoff does not decide the exact frozen committee attempt"
    );
    if let Some(withheld) = missing {
        ensure!(
            decision.decision == ValidatorEpochDecisionV1::RetainAndCancel
                && decision.authority_generation == 0
                && snapshot
                    .next
                    .committee
                    .iter()
                    .map(|seat| &seat.validator)
                    .collect::<BTreeSet<_>>()
                    == genesis_voters.iter().collect::<BTreeSet<_>>(),
            "one genuinely absent target custodian must force certified four-seat retention"
        );
        let progress = read_validator_committee(&admin, 2).await?;
        let transition = &progress
            .selected
            .as_ref()
            .ok_or_else(|| eyre!("terminal status lost the frozen attempt"))?
            .transition;
        ensure!(
            transition.readiness.len() == first.target.len() - 1
                && !transition.readiness.iter().any(|row| {
                    usize::try_from(row.validator_index)
                        .ok()
                        .and_then(|index| first_preparation.committee.get(index))
                        .is_some_and(|seat| seat.validator == withheld)
                })
                && transition.outcome.as_ref() == Some(decision),
            "certified retention must name exactly the missing target custody seat"
        );
        return prove_retained_successor_after_restart(
            network,
            admin,
            genesis_voters,
            first_preparation,
            cutoff,
            signed_genesis_hash,
        )
        .await;
    }
    ensure!(
        decision.decision == ValidatorEpochDecisionV1::Activate
            && decision.authority_generation == 1
            && snapshot
                .next
                .committee
                .iter()
                .map(|seat| seat.validator.clone())
                .collect::<Vec<_>>()
                == first.target,
        "complete seven-seat custody must activate as one certified boundary effect"
    );
    advance_to_height(network, &first.target, TARGET_FIRST).await?;
    let (_, activated_chain) = read_on_dedicated_thread({
        let admin = admin.clone();
        let network_id = network.network_id();
        move || {
            read_contiguous_finality_chain(&admin, network_id, signed_genesis_hash, TARGET_FIRST)
        }
    })
    .await
    .wrap_err("seven-seat activation finality worker failed")?;
    let seven = activated_chain
        .last()
        .ok_or_else(|| eyre!("seven-seat activation lacks finality"))?;
    let seven_set = first.target.iter().cloned().collect::<BTreeSet<_>>();
    verify_equal_vote_context(seven, &seven_set)?;
    ensure!(
        seven
            .commitment()
            .schedule
            .current
            .authorization
            .authority_generation
            == 1,
        "seven-seat activation did not publish the new validator generation"
    );
    let status = read_validator_committee(&admin, 3).await?;
    let return_preparation = status
        .selected
        .as_ref()
        .ok_or_else(|| eyre!("E+3 return election did not freeze"))?
        .transition
        .preparation
        .clone();
    let return_target = return_preparation
        .committee
        .iter()
        .map(|seat| seat.validator.clone())
        .collect::<BTreeSet<_>>();
    ensure!(
        return_preparation.selection_height == CUTOFF
            && return_preparation.target_epoch == 3
            && return_preparation.first_height == TARGET_LAST + 1
            && return_preparation.authority_generation == 2
            && return_target
                == survivors.ok_or_else(|| eyre!("missing requested return roster"))?
            && return_target.len() == 4,
        "genuine eight-candidate election must freeze the four non-exiting seats for E+3"
    );
    let departing = seven_set
        .difference(&return_target)
        .next()
        .ok_or_else(|| eyre!("seven-seat committee has no departing validator"))?;
    let lifecycle = committee_staking::schedule_retained_withdrawal(
        network,
        admin,
        operators
            .get(departing)
            .ok_or_else(|| eyre!("departing seat has no real owner"))?,
        genesis_voters.contains(departing),
        &return_preparation,
        signed_genesis_hash,
    )
    .await?;
    let seven_current = prepared_current_custody(&first.prepared)?;
    let second = execute_rotation_preparation(
        network,
        admin,
        operators,
        &return_preparation,
        &seven_current,
        signed_genesis_hash,
        3,
        None,
    )
    .await?;
    ensure!(
        second.target.len() == 4 && second.prepared.len() == 4,
        "return attempt must prove all four target custodians"
    );
    lifecycle.verify_retained_after_restart().await?;
    let second_cutoff = TARGET_LAST;
    advance_to_height(network, &first.target, second_cutoff).await?;
    let (_, return_chain) = read_on_dedicated_thread({
        let admin = admin.clone();
        let network_id = network.network_id();
        move || {
            read_contiguous_finality_chain(&admin, network_id, signed_genesis_hash, second_cutoff)
        }
    })
    .await
    .wrap_err("return cutoff finality worker failed")?;
    let return_boundary = return_chain
        .last()
        .ok_or_else(|| eyre!("return boundary lacks finality"))?;
    verify_equal_vote_context(return_boundary, &seven_set)?;
    let return_snapshot = return_boundary
        .commitment()
        .schedule
        .boundary
        .as_ref()
        .ok_or_else(|| eyre!("return boundary lacks certified epoch effect"))?;
    let return_decision = &return_snapshot.next.authorization;
    ensure!(
        return_decision.decision == ValidatorEpochDecisionV1::Activate
            && return_decision.epoch == 3
            && return_decision.authority_generation == 2
            && return_decision.transition_id
                == return_preparation
                    .transition_id()
                    .map_err(|error| eyre!(error))?
            && return_snapshot
                .next
                .committee
                .iter()
                .map(|seat| seat.validator.clone())
                .collect::<Vec<_>>()
                == second.target,
        "seven-seat exact quorum did not certify the independently prepared four-seat return"
    );
    let four_first = second_cutoff + 1;
    advance_to_height(network, &second.target, four_first).await?;
    let (_, four_chain) = read_on_dedicated_thread({
        let admin = admin.clone();
        let network_id = network.network_id();
        move || read_contiguous_finality_chain(&admin, network_id, signed_genesis_hash, four_first)
    })
    .await
    .wrap_err("four-seat return finality worker failed")?;
    let four = four_chain
        .last()
        .ok_or_else(|| eyre!("four-seat return lacks finality"))?;
    verify_equal_vote_context(four, &return_target)?;
    ensure!(
        four.commitment()
            .schedule
            .current
            .authorization
            .authority_generation
            == 2,
        "4→7→4 did not complete the second authenticated signing generation"
    );
    lifecycle
        .complete_withdrawal(network, &second.target, &return_target)
        .await?;
    Ok(())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum QualificationScenario {
    WithheldIncumbentCustody,
    FiveCandidateRetention,
    ElevenCandidateRetention,
    MissingTargetCustody,
    ActivateSevenThenReturnFour,
}

impl QualificationScenario {
    fn pool_size(self) -> usize {
        match self {
            Self::FiveCandidateRetention => 5,
            Self::ElevenCandidateRetention => 11,
            _ => 8,
        }
    }

    fn selected_seats(self) -> usize {
        let available = self.pool_size().min(7);
        3 * ((available - 1) / 3) + 1
    }

    fn seed(self) -> &'static str {
        match self {
            Self::WithheldIncumbentCustody => "npos-eight-candidates-withheld-custody",
            Self::FiveCandidateRetention => "npos-five-candidates-retention",
            Self::ElevenCandidateRetention => "npos-eleven-candidates-retention",
            Self::MissingTargetCustody => "npos-eight-candidates-missing-custody",
            Self::ActivateSevenThenReturnFour => "npos-eight-candidates-seven-then-four",
        }
    }
}

async fn run_overfull_qualification(scenario: QualificationScenario) -> Result<()> {
    init_instruction_registry();
    let pool_size = scenario.pool_size();
    let seats = scenario.selected_seats();
    let supplementary = pool_size - 4;
    let registry_capacity = i64::try_from(pool_size.max(7))?;
    let xor: AssetDefinitionId = defaults::nexus::staking::stake_asset_id().parse()?;
    ensure!(
        xor.to_string() == TAIRA_XOR,
        "staking must use real genesis-pinned XOR"
    );
    let mut npos = SumeragiNposParameters::default();
    npos.epoch_length_blocks = NonZeroU64::new(EPOCH).expect("nonzero epoch");
    npos.max_validators = 7;
    npos.min_self_bond = 1_000_u64.into();
    npos.evidence_horizon_blocks = EPOCH * 2;
    npos.slashing_delay_blocks = 1;
    npos.validate().map_err(|error| eyre!(error))?;
    let builder = NetworkBuilder::new()
        .with_peers(4)
        .with_max_validator_capacity(7)
        .with_auto_populated_trusted_peers()
        .with_npos_consensus()
        .with_npos_genesis_bootstrap(1_000_u64.into())
        .with_genesis_instruction(SetParameter::new(Parameter::Sumeragi(
            SumeragiParameter::EpochLengthBlocks(NonZeroU64::new(EPOCH).expect("nonzero epoch")),
        )))
        .with_committee_validator_p2p_bootstrap(CommitteeValidatorP2pBootstrap::new(
            supplementary,
        )?)?
        .with_config_layer(|layer| {
            // Admission may retain a larger candidate pool than the seven-seat
            // consensus ceiling; the authenticated election selects exactly 3f+1.
            layer.write(["nexus", "staking", "max_validators"], registry_capacity);
            // Retain durable vote and driver evidence across each paid rotation
            // and all-seat restart so a stalled readiness submission is diagnosable.
            layer.write(["logger", "filter"], "info,iroha_core::sumeragi=debug");
        })
        .with_genesis_instruction(SetParameter::new(Parameter::Custom(
            npos.into_custom_parameter(),
        )));
    let builder = if scenario == QualificationScenario::ActivateSevenThenReturnFour {
        committee_parliament::genesis(builder)?
    } else {
        builder
    };
    let network = sandbox::build_network_or_skip(builder, scenario.seed()).ok_or_else(|| {
        eyre!("committee qualification requires an actual {pool_size}-process disposable network")
    })?;
    let result = async {
        let genesis_bundle = network.native_genesis_provisioning_bundle()?;
        ensure!(
            genesis_bundle.block_hash == network.genesis().0.hash(),
            "genesis provisioners must consume the retained signed manifest and block"
        );
        network.start_all().await?;
        network.ensure_blocks(1).await?;
        let admin = rebind_blocking_client(&network.client(), |builder| {
            builder.transaction_status_timeout = WAIT;
        });
        let network_id = network.network_id();
        let block_hash = genesis_bundle.block_hash;
        let network_ref = &network;
        let genesis_dkg = run_disposable_genesis_dkg(
            &network,
            finality_limits(),
            5,
            |height, _public_snapshot, deadline| {
                let admin = admin.clone();
                async move {
                    advance_exact_genesis_phase(network_ref, height, deadline).await?;
                    let observed = read_on_dedicated_thread({
                        let admin = admin.clone();
                        move || -> Result<u64> {
                            Ok(committee_status::height_until_blocking(&admin, deadline)?)
                        }
                    })
                    .await
                    .wrap_err("genesis phase status worker failed")?;
                    ensure!(
                        observed == height,
                        "genesis DKG public phase missed exact h{height} observation"
                    );
                    read_on_dedicated_thread(move || {
                        read_genesis_dkg_finality_chain(
                            &admin, network_id, block_hash, height, deadline,
                        )
                    })
                    .await
                    .wrap_err("genesis phase finality worker failed")
                }
            },
        )
        .await?;
        let install: Vec<InstructionBox> =
            norito::json::from_slice(&fs::read(&genesis_dkg.install_instruction_path)?)?;
        ensure!(
            install.len() == 1,
            "native genesis install must emit one instruction"
        );
        let next_height = read_on_dedicated_thread({
            let admin = admin.clone();
            move || -> Result<u64> {
                Ok(committee_status::height_until_blocking(&admin, Instant::now() + WAIT)? + 1)
            }
        })
        .await
        .wrap_err("genesis install height worker failed")?;
        ensure!(
            next_height == 5,
            "genesis installation must execute immediately after the exact h4 DKG cutoff"
        );
        read_on_dedicated_thread({
            let admin = admin.clone();
            move || admin.submit_all(install, FeePaymentIntent::authority(Vec::new(), None))
        })
        .await
        .wrap_err("genesis beacon install worker failed")?;
        network.shutdown().await;
        let genesis_catalogs = stage_genesis_brokers(&network, &genesis_dkg).await?;
        network.start_all().await?;
        network.ensure_blocks(5).await?;
        ensure!(
            network.validators().len() == 4
                && network.committee_validators().len() == supplementary,
            "fixture must start four genesis voters and the exact separate candidate pool"
        );
        let network_id = network.network_id();
        let genesis_voters = network
            .validators()
            .iter()
            .map(|peer| peer.id())
            .collect::<BTreeSet<_>>();
        let pool = network
            .validators()
            .iter()
            .chain(network.committee_validators())
            .map(|peer| peer.id())
            .collect::<BTreeSet<_>>();
        ensure!(
            pool.len() == pool_size,
            "all candidate BLS keys must be distinct"
        );
        let escrow = validator_xor_escrow(&network.genesis(), &xor)?;
        ensure!(
            escrow.definition == xor,
            "genesis escrow must hold actual XOR"
        );
        let operators = network
            .validators()
            .iter()
            .chain(network.committee_validators())
            .map(|peer| {
                let account = peer.account_id();
                let client = rebind_blocking_client(
                    &network.validators()[0]
                        .client_for(&account, peer.streaming_key_pair().private_key().clone()),
                    |builder| builder.transaction_status_timeout = WAIT,
                );
                Ok((
                    peer.id(),
                    Operator {
                        account,
                        peer: peer.id(),
                        consensus_key: peer
                            .bls_key_pair()
                            .ok_or_else(|| eyre!("missing real BLS candidate key"))?
                            .clone(),
                        pop: peer
                            .bls_pop()
                            .ok_or_else(|| eyre!("missing real BLS possession proof"))?
                            .to_vec(),
                        client,
                    },
                ))
            })
            .collect::<Result<BTreeMap<_, _>>>()?;
        let fresh_peers = network
            .committee_validators()
            .iter()
            .map(|peer| peer.id())
            .collect::<Vec<_>>();
        let candidates = fresh_peers
            .iter()
            .map(|peer| {
                operators
                    .get(peer)
                    .ok_or_else(|| eyre!("missing candidate operator"))
            })
            .collect::<Result<Vec<_>>>()?;
        let initial_height = read_on_dedicated_thread({
            let admin = admin.clone();
            let xor = xor.clone();
            let escrow = escrow.clone();
            let candidates = candidates
                .iter()
                .map(|operator| Operator::clone(operator))
                .collect::<Vec<_>>();
            move || -> Result<u64> {
                admit_candidates(&admin, &candidates, network_id, &xor, &escrow)?;
                Ok(committee_status::height_until_blocking(
                    &admin,
                    Instant::now() + WAIT,
                )?)
            }
        })
        .await
        .wrap_err("candidate admission worker failed")?;
        ensure!(
            initial_height < SELECTION,
            "candidate pool did not enter the selecting prestate"
        );
        let parliament_proposal = if scenario == QualificationScenario::ActivateSevenThenReturnFour
        {
            committee_parliament::fund_and_register_citizens(
                &network,
                &admin,
                &xor,
                genesis_bundle.block_hash,
            )
            .await?;
            Some(committee_parliament::stage_proposal(&admin).await?)
        } else {
            None
        };
        let initial_roster = network
            .validators()
            .iter()
            .map(|peer| peer.id())
            .collect::<Vec<_>>();
        // Selection is certified at the final height of E. Preparation evidence
        // must also certify an E+1 block under the preparing authorization. The
        // progress helper stops exactly at its target, so pay for that successor
        // explicitly instead of relying on an accidental boundary overshoot.
        advance_to_height(&network, &initial_roster, SELECTION + 1).await?;
        let before = read_validator_committee(&admin, 2).await?;
        let selected = before
            .selected
            .as_ref()
            .ok_or_else(|| eyre!("boundary did not freeze E+2"))?;
        let preparation = selected.transition.preparation.clone();
        preparation.validate().map_err(|error| eyre!(error))?;
        let target = preparation
            .committee
            .iter()
            .map(|seat| seat.validator.clone())
            .collect::<BTreeSet<_>>();
        ensure!(
            preparation.network_id == network_id
                && preparation.selection_epoch == 0
                && preparation.selection_height == SELECTION
                && preparation.target_epoch == 2
                && preparation.first_height == TARGET_FIRST
                && preparation.last_height == TARGET_LAST
                && preparation.authority_generation == 1
                && target.len() == seats
                && target == ranked_target(&preparation, &pool, seats)
                && target.is_subset(&pool),
            "selection must freeze the exact public rank and 3f+1 size for the full candidate pool"
        );
        ensure!(
            target.intersection(&genesis_voters).count() >= seats.saturating_sub(supplementary),
            "selected incumbent overlap must satisfy the actual candidate pool geometry"
        );
        for seat in &preparation.committee {
            ensure!(
                operators
                    .get(&seat.validator)
                    .is_some_and(|operator| operator.pop == seat.proof_of_possession),
                "frozen seat must carry its real BLS possession proof"
            );
        }
        run_custody_or_activation_scenario(
            scenario,
            &network,
            &admin,
            &genesis_dkg,
            &genesis_catalogs,
            &operators,
            &genesis_voters,
            &pool,
            &preparation,
            genesis_bundle.block_hash,
            parliament_proposal,
        )
        .await
    }
    .await;
    network.shutdown_and_release().await;
    result
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn overfull_pool_freezes_seven_then_missing_incumbent_custody_certifies_four_retained()
-> Result<()> {
    run_overfull_qualification(QualificationScenario::WithheldIncumbentCustody).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn five_candidates_freeze_exact_four_and_certify_retention_without_reroll() -> Result<()> {
    run_overfull_qualification(QualificationScenario::FiveCandidateRetention).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn eleven_candidates_freeze_exact_seven_and_certify_retention_without_reroll() -> Result<()> {
    run_overfull_qualification(QualificationScenario::ElevenCandidateRetention).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn complete_dkg_but_missing_target_custody_certifies_four_retained() -> Result<()> {
    run_overfull_qualification(QualificationScenario::MissingTargetCustody).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn complete_real_xor_committee_rotates_four_to_seven_to_four() -> Result<()> {
    run_overfull_qualification(QualificationScenario::ActivateSevenThenReturnFour).await
}

#[test]
fn progress_waits_for_each_submitted_height_and_stops_at_the_first_target_observation() -> Result<()>
{
    let target = 24;
    let observations = [
        [22, 22, 22, 22],
        [22, 22, 22, 22], // submission remains outstanding
        [23, 22, 22, 22],
        [23, 23, 23, 22],
        [23, 23, 23, 23],
        [23, 23, 23, 23], // the final progress input remains outstanding
        [23, 24, 23, 23],
        [24, 24, 23, 24],
        [24, 24, 24, 24],
    ];
    let mut pending = None;
    let mut submitted = Vec::new();
    for (index, heights) in observations.iter().enumerate() {
        match progress_action(heights, target, pending)? {
            ProgressAction::SubmitAt(height) => {
                assert!(
                    index == 0 || index == 4,
                    "duplicate progress submission while catching up"
                );
                submitted.push(height);
                pending = Some(height);
            }
            ProgressAction::AwaitCatchup => assert_ne!(index, observations.len() - 1),
            ProgressAction::Complete => assert_eq!(index, observations.len() - 1),
        }
    }
    assert_eq!(submitted, [23, 24]);
    assert_eq!(
        progress_action(&[24, 23, 23, 23], 24, None)?,
        ProgressAction::AwaitCatchup,
        "a peer reaching the cutoff suppresses further work even without a local pending input"
    );
    assert_eq!(
        progress_action(&[23, 22, 22, 22], 24, None)?,
        ProgressAction::AwaitCatchup
    );
    assert!(progress_action(&[], 24, None).is_err());
    Ok(())
}

#[test]
fn exact_quorum_uses_only_three_f_plus_one_equal_vote_geometry() {
    for seats in 0..=64 {
        let result = exact_quorum(seats);
        if (4..=31).contains(&seats) && (seats - 1) % 3 == 0 {
            assert_eq!(result.unwrap() as usize, seats - (seats - 1) / 3);
        } else {
            assert!(result.is_err(), "unsupported roster of {seats} seats");
        }
    }
    assert!(exact_quorum(usize::MAX).is_err());
}

#[test]
fn committee_history_public_proofs_require_the_exact_genesis_anchored_prefix() -> Result<()> {
    use iroha_core::{
        state::{StateReadOnly as _, World},
        sumeragi::{
            finality::build_proof,
            test_chain::{CertifiedTestChain, TestChainConfig},
        },
    };

    let mut chain = CertifiedTestChain::start(TestChainConfig::new(World::new(), 10_000))
        .map_err(|error| eyre!("native fixture startup failed: {error:?}"))?;
    chain.commit_at(10_001, Vec::new());
    chain.commit_at(10_002, Vec::new());
    let view = chain.state().view();
    let chain_id = view.chain_id().clone();
    let proofs = (1..=3)
        .map(|height| build_proof(&view, height))
        .collect::<std::result::Result<Vec<_>, _>>()?;
    let verify = |end, source: &[iroha::data_model::sumeragi_finality::SumeragiFinalityProof]| {
        let mut requested = Vec::new();
        let result = finality_chain_from_proofs(
            &chain_id,
            chain.network_id(),
            chain.genesis().hash(),
            end,
            Instant::now() + WAIT,
            |height| {
                requested.push(height.get());
                source
                    .get(usize::try_from(height.get() - 1)?)
                    .cloned()
                    .ok_or_else(|| eyre!("missing requested proof"))
            },
        );
        (result, requested)
    };
    let (result, requested) = verify(3, &proofs);
    let (journal, certified) = result?;
    assert_eq!(requested, [1, 2, 3]);
    assert_eq!(certified.len(), 3);
    for (artifact, proof) in journal.blocks.iter().zip(&proofs) {
        assert_eq!(artifact.block_wire, proof.block_wire);
    }
    assert!(
        verify(3, &proofs[..2]).0.is_err(),
        "missing tip must reject"
    );
    let mut changed = proofs.clone();
    changed.swap(1, 2);
    assert!(
        verify(3, &changed).0.is_err(),
        "reordered heights must reject"
    );
    let mut changed = proofs.clone();
    changed[1].block_wire[0] ^= 1;
    assert!(
        verify(3, &changed).0.is_err(),
        "changed canonical wire must reject"
    );
    let mut changed = proofs.clone();
    changed[1].committee.pop();
    assert!(
        verify(3, &changed).0.is_err(),
        "substituted proof metadata must reject"
    );
    let foreign = CertifiedTestChain::start(TestChainConfig::new(World::new(), 20_000))
        .map_err(|error| eyre!("foreign fixture startup failed: {error:?}"))?;
    let mut changed = proofs.clone();
    changed[0] = build_proof(&foreign.state().view(), 1)?;
    assert!(
        verify(3, &changed).0.is_err(),
        "foreign signed genesis must reject"
    );
    for end in [0, 1, MAX_QUALIFICATION_HEIGHT + 1] {
        let (result, requested) = verify(end, &proofs);
        assert!(result.is_err());
        assert!(
            requested.is_empty(),
            "invalid bounds must reject before fetching"
        );
    }
    assert!(
        finality_chain_from_proofs(
            &chain_id,
            chain.network_id(),
            chain.genesis().hash(),
            3,
            Instant::now(),
            |_| panic!("expired reads must not fetch"),
        )
        .is_err()
    );
    Ok(())
}

#[test]
fn committee_rotation_history_queries_only_successors_and_reuses_original_frames() -> Result<()> {
    use iroha_core::{
        state::{StateReadOnly as _, World},
        sumeragi::{
            finality::build_proof,
            test_chain::{CertifiedTestChain, TestChainConfig},
        },
    };
    let mut chain = CertifiedTestChain::start(TestChainConfig::new(World::new(), 30_000))
        .map_err(|error| eyre!("native history fixture startup failed: {error:?}"))?;
    // commit_at supplies actual clock-account Log work; these are not empty blocks.
    for at in 30_001..=30_004 {
        chain.commit_at(at, Vec::new());
    }
    let view = chain.state().view();
    let chain_id = view.chain_id().clone();
    let proofs = (1..=5)
        .map(|height| build_proof(&view, height))
        .collect::<std::result::Result<Vec<_>, _>>()?;
    let fetch = |height: NonZeroU64| Ok(proofs[usize::try_from(height.get() - 1)?].clone());
    let (mut journal, _) = finality_chain_from_proofs(
        &chain_id,
        chain.network_id(),
        chain.genesis().hash(),
        2,
        Instant::now() + WAIT,
        fetch,
    )?;
    let mut original = journal
        .blocks
        .iter()
        .map(|artifact| {
            (
                artifact.block_wire.as_ptr(),
                artifact.block_wire.capacity(),
                artifact.block_wire.clone(),
            )
        })
        .collect::<Vec<_>>();
    let mut requested = Vec::new();
    let deadline = Instant::now() + WAIT;
    for end in 3..=5 {
        journal = append_finality_chain_from_proofs(
            &chain_id,
            chain.network_id(),
            chain.genesis().hash(),
            journal,
            end,
            deadline,
            |height| {
                requested.push(height.get());
                fetch(height)
            },
        )?;
        assert_eq!(journal.blocks.len(), usize::try_from(end)?);
        for (artifact, (pointer, capacity, bytes)) in journal.blocks.iter().zip(&original) {
            assert_eq!(artifact.block_wire.as_ptr(), *pointer);
            assert_eq!(artifact.block_wire.capacity(), *capacity);
            assert_eq!(&artifact.block_wire, bytes);
        }
        let retained_count = original.len();
        original.extend(journal.blocks.iter().skip(retained_count).map(|artifact| {
            (
                artifact.block_wire.as_ptr(),
                artifact.block_wire.capacity(),
                artifact.block_wire.clone(),
            )
        }));
        let (fresh, _) = finality_chain_from_proofs(
            &chain_id,
            chain.network_id(),
            chain.genesis().hash(),
            end,
            deadline,
            fetch,
        )?;
        assert_eq!(
            norito::encode_canonical(&journal)?,
            norito::encode_canonical(&fresh)?
        );
    }
    assert_eq!(
        requested,
        [3, 4, 5],
        "old prefix rows must never be fetched again"
    );
    Ok(())
}

#[test]
fn committee_rotation_history_refuses_changed_prefix_missing_rows_and_expired_deadline()
-> Result<()> {
    use iroha_core::{
        state::{StateReadOnly as _, World},
        sumeragi::{
            finality::build_proof,
            test_chain::{CertifiedTestChain, TestChainConfig},
        },
    };
    let mut chain = CertifiedTestChain::start(TestChainConfig::new(World::new(), 40_000))
        .map_err(|error| eyre!("native history fixture startup failed: {error:?}"))?;
    chain.commit_at(40_001, Vec::new());
    chain.commit_at(40_002, Vec::new());
    let view = chain.state().view();
    let chain_id = view.chain_id().clone();
    let proofs = (1..=3)
        .map(|height| build_proof(&view, height))
        .collect::<std::result::Result<Vec<_>, _>>()?;
    let fetch = |height: NonZeroU64| Ok(proofs[usize::try_from(height.get() - 1)?].clone());
    let (base, _) = finality_chain_from_proofs(
        &chain_id,
        chain.network_id(),
        chain.genesis().hash(),
        2,
        Instant::now() + WAIT,
        fetch,
    )?;
    for policy in 0..4 {
        let mut original = base.clone();
        let mut end = 3;
        let mut independent = chain.genesis().hash();
        let mut deadline = Instant::now() + WAIT;
        let expected = match policy {
            0 => {
                original.blocks.pop();
                "rotation phase must extend an original H2+ journal"
            }
            1 => {
                end = 2;
                "rotation phase must extend an original H2+ journal"
            }
            2 => {
                independent = iroha::crypto::HashOf::from_untyped_unchecked(Hash::new(
                    b"foreign independent genesis",
                ));
                "network differs from independent signed genesis"
            }
            _ => {
                deadline = Instant::now();
                "committee proof retrieval deadline elapsed"
            }
        };
        let error = append_finality_chain_from_proofs(
            &chain_id,
            chain.network_id(),
            independent,
            original,
            end,
            deadline,
            |_| panic!("invalid prefix/deadline must refuse before fetching"),
        )
        .expect_err("terminal admission cannot return a phase journal");
        assert!(error.to_string().contains(expected), "{error}");
    }
    let error = append_finality_chain_from_proofs(
        &chain_id,
        chain.network_id(),
        chain.genesis().hash(),
        base.clone(),
        3,
        Instant::now() + WAIT,
        |_| Err(eyre!("original successor read refused")),
    )
    .expect_err("original source failure terminates the ceremony");
    assert_eq!(error.to_string(), "original successor read refused");
    for changed in 0..3 {
        let mut original = base.clone();
        let mut successor = proofs[2].clone();
        match changed {
            0 => original.blocks[0].block_wire[0] ^= 1,
            1 => {
                original.blocks.swap(0, 1);
            }
            _ => {
                successor.committee.pop();
            }
        }
        let mut requested = Vec::new();
        assert!(
            append_finality_chain_from_proofs(
                &chain_id,
                chain.network_id(),
                chain.genesis().hash(),
                original,
                3,
                Instant::now() + WAIT,
                |height| {
                    requested.push(height.get());
                    Ok(successor.clone())
                },
            )
            .is_err(),
            "changed original native prefix/proof metadata must not publish"
        );
        assert_eq!(requested, [3]);
    }
    let mut requested = Vec::new();
    assert!(
        append_finality_chain_from_proofs(
            &chain_id,
            chain.network_id(),
            chain.genesis().hash(),
            base,
            3,
            Instant::now() + WAIT,
            |height| {
                requested.push(height.get());
                Ok(proofs[1].clone())
            },
        )
        .is_err(),
        "a returned predecessor cannot replace the exact requested successor"
    );
    assert_eq!(requested, [3]);
    Ok(())
}

#[test]
fn native_finality_rejects_wrong_independent_genesis_before_query() {
    let config = iroha::config::Config {
        chain: "committee-transition-unit".into(),
        network_id: NetworkId::from_genesis_hash(iroha::crypto::HashOf::from_untyped_unchecked(
            Hash::prehashed([0x5A; Hash::LENGTH]),
        )),
        key_pair: iroha_test_samples::ALICE_KEYPAIR.clone(),
        account: ALICE_ID.clone(),
        account_chain_discriminant: iroha_torii_shared::MINAMOTO_CHAIN_DISCRIMINANT,
        torii_api_url: "http://committee-transition.invalid/".parse().unwrap(),
        torii_request_timeout: iroha::config::DEFAULT_TORII_REQUEST_TIMEOUT,
        basic_auth: None,
        api_token: None,
        transaction_add_nonce: false,
        transaction_ttl: Duration::from_secs(5),
        transaction_status_timeout: Duration::from_secs(10),
        sorafs_alias_cache: iroha::config::AliasCache::default().into_policy(),
        sorafs_anonymity_policy: iroha_service_model::soranet::AnonymityPolicy::default(),
        sorafs_rollout_phase: iroha_service_model::soranet::RolloutPhase::default(),
    };
    let network_id = config.network_id;
    let client = Client::new(config).unwrap();
    let error = read_contiguous_finality_chain(
        &client,
        network_id,
        iroha::crypto::HashOf::from_untyped_unchecked(Hash::new(b"another signed genesis")),
        2,
    )
    .expect_err("foreign independent source is rejected before any query");
    assert!(
        error
            .to_string()
            .contains("network differs from independent signed genesis")
    );
}

#[test]
fn committee_history_observation_keeps_original_read_deadline_before_query() -> Result<()> {
    let config = iroha::config::Config {
        chain: "committee-deadline-unit".into(),
        network_id: NetworkId::from_genesis_hash(iroha::crypto::HashOf::from_untyped_unchecked(
            Hash::prehashed([0x5B; Hash::LENGTH]),
        )),
        key_pair: iroha_test_samples::ALICE_KEYPAIR.clone(),
        account: ALICE_ID.clone(),
        account_chain_discriminant: iroha_torii_shared::MINAMOTO_CHAIN_DISCRIMINANT,
        torii_api_url: "http://committee-deadline.invalid/".parse()?,
        torii_request_timeout: iroha::config::DEFAULT_TORII_REQUEST_TIMEOUT,
        basic_auth: None,
        api_token: None,
        transaction_add_nonce: false,
        transaction_ttl: Duration::from_secs(5),
        transaction_status_timeout: Duration::from_secs(10),
        sorafs_alias_cache: iroha::config::AliasCache::default().into_policy(),
        sorafs_anonymity_policy: iroha_service_model::soranet::AnonymityPolicy::default(),
        sorafs_rollout_phase: iroha_service_model::soranet::RolloutPhase::default(),
    };
    let network_id = config.network_id;
    let client = Client::new(config)?;
    let deadline = Instant::now();
    let error = read_contiguous_finality_chain_until(
        &client,
        network_id,
        network_id.into_genesis_hash(),
        2,
        deadline,
    )
    .expect_err("an exhausted original observation deadline must not be renewed");
    assert!(
        error
            .to_string()
            .contains("committee proof retrieval deadline elapsed"),
        "expired custody observations must refuse before any endpoint query: {error}",
    );
    Ok(())
}
