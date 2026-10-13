#![allow(clippy::all, clippy::pedantic, clippy::nursery, clippy::restriction)]
//! Four-validator modern SORA Parliament and mandatory timed-OVN lifecycle corridor.

use iroha::data_model::{
    parameter::system::{ConsensusHandshakeMetadata, consensus_metadata},
    prelude::{AssetId, FindAssetById, Identifiable as _},
};
use iroha::query::QueryError;
use iroha_data_model::sumeragi::PROTOCOL_VERSION;
use iroha_data_model::{
    ValidationFail,
    query::error::{FindError, QueryExecutionFail},
};
use iroha_sumeragi::availability::recommended_data_availability_layout;
use std::{
    collections::BTreeMap,
    num::NonZeroU64,
    str::FromStr as _,
    time::{Duration, Instant},
};

use eyre::{Result, WrapErr as _, eyre};
use integration_tests::sandbox;
use iroha::{
    blocking::Client,
    crypto::{Hash, KeyPair},
    data_model::{
        account::AccountId,
        governance::types::{
            AbiVersion, BallotAttemptId, BallotAttemptStatusV1, BeaconPulseId, BeaconSessionId,
            BodyElectionAttemptId, BodyElectionAttemptStatusV1, BodyInstanceId,
            BodyInstanceStatusV1, ContractAbiHash, ContractCodeHash, DeliberationPhaseV1,
            DeployContractProposal, GovernanceAttemptId, GovernanceAttemptStatusV1,
            GovernanceStageV1, ParliamentBody, ParliamentNoResultKindV1, ProposalKind,
            SortitionRequestV1, TleSessionId, parliament_ballot_participant_hash_v1,
            parliament_candidate_root_v1,
        },
        isi::{
            InstructionBox, Log,
            consensus_keys::ThresholdKeyLifecycleActionV1,
            governance::{
                CreateParliamentGovernanceAttemptV1, ParliamentAdvanceBodyPhaseV1,
                ParliamentBeginBallotOpeningBatchV1, ParliamentBeginInvitationAcceptanceV1,
                ParliamentCloseBallotRegistrationV1, ParliamentConsumeSortitionPulseBatchV1,
                ParliamentEndorsePublicFindingV1, ParliamentFailPublicFindingNoResultV1,
                ParliamentFinalizeOpenedBallotV1, ParliamentFreezeBallotSurvivorsV1,
                ParliamentFreezeTimedOvnCorpusV1, ParliamentInvitationDecisionV1,
                ParliamentLifecycleTransitionV1, ParliamentRecordAttemptAbsenceV1,
                ParliamentRecordInvitationResponseV1, ParliamentRegisterBallotAttemptV1,
                ParliamentRegisterBallotParticipantV1, ParliamentRegisterSortitionRequestV1,
                ParliamentSealBodyRosterV1, ParliamentSortitionRequestRegistrationV1,
                ParliamentTleFinalReleaseSignatureV1, ProposeDeployContract, RegisterCitizen,
                SubmitParliamentLifecycleTransitionV1,
            },
        },
        parameter::{
            Parameter,
            system::{SumeragiConsensusMode, SumeragiNposParameters, SumeragiParameter},
        },
        permission::Permission,
        prelude::{Account, Grant, Level, Register, SetParameter},
        smart_contract::ContractAddress,
        sumeragi::SumeragiStatus,
    },
};
use iroha_core::beacon::GlobalThresholdBeaconSessionBindingV1;
use iroha_core::beacon::global_threshold_beacon_governance_seed_v1;
use iroha_core::beacon::global_threshold_beacon_npos_successor_seed_v1;
use iroha_core::beacon::global_threshold_beacon_roster_hash_v1;
use iroha_core::beacon::parliament_test_network_signer::deterministic_parliament_beacon_key_record_v1;
use iroha_core::beacon::validate_global_threshold_beacon_session_v1;
use iroha_core::beacon::verify_finalized_global_threshold_beacon_pulse_v1;
use iroha_core::governance::parliament::ParliamentAttemptStateV1;
use iroha_core::tle_release::parliament_test_network_signer::deterministic_parliament_tle_key_public_state_v1;
use iroha_core_timed_ovn::tle::TleKeySessionPublicStateV1;
use iroha_crypto::timed_ovn::{TimedOvnChoiceV1, TimedOvnRegistrationSecretV1};
use iroha_data_model::governance::types::PARLIAMENT_TIMED_OVN_BALLOT_RECORD_BYTES_V1 as TIMED_OVN_BALLOT_RECORD_BYTES_V1;
use iroha_executor_data_model::permission::{
    governance::CanProposeContractDeployment, smart_contract::CanManageSmartContractCode,
};
use iroha_model_base::peer::PeerId;
use iroha_test_network::{NetworkBuilder, ParliamentBeaconSignerMode, read_on_dedicated_thread};
use iroha_test_samples::ALICE_ID;
use rand::{SeedableRng as _, rngs::StdRng};

#[path = "sora_parliament_lifecycle_support.rs"]
mod support;
use support::submission as parliament_submission;
use support::submission::{minimal_contract_artifact, minimal_contract_artifact_with_identity};
use support::*;
#[path = "support/parliament_contract.rs"]
mod parliament_contract;
use parliament_contract::stage_contract_artifact;

const MANDATORY_NPOS_EPOCH_LENGTH_BLOCKS: u64 = 8;

// Unrelated carriers committed past the retired `request_height + delay` slot by the
// isolation corridor; the first one lands on the height the retired rule stalled.
const ISOLATION_CARRIERS_PAST_RETIRED_SLOT: u64 = 12;

// Further carriers committed after the restarted validator has rejoined.
const ISOLATION_CARRIERS_AFTER_RESTART: u64 = 3;

const PARLIAMENT_NETWORK_STACK_BYTES: usize = 32 * 1024 * 1024;

const FAIL_CLOSED_BEACON_OBSERVATION_WINDOW: Duration = Duration::from_secs(8);

const FAIL_CLOSED_BEACON_SIGNER_MODES: [ParliamentBeaconSignerMode; VALIDATOR_COUNT] = [
    ParliamentBeaconSignerMode::Valid,
    ParliamentBeaconSignerMode::Absent,
    ParliamentBeaconSignerMode::Absent,
    ParliamentBeaconSignerMode::Invalid,
];

const CONTRACT_ADDRESS: &str = "irohac1qyqqqqqqqqqqqq95fes93ygegsv5enq9mqsz6x4lv4vp9gg4yxgjw";

const NO_RESULT_RETRY_CONTRACT_ADDRESS: &str =
    "irohac1qyqqqqqqqqqqqqputuv64zhf0a0a4hhlqdj2lhnwuzq4xjq3qexfh";

/// Read one validator's Sumeragi status together with its published native beacon horizon.
///
/// The status omits the horizon while its same-cut observation is being refreshed, so an
/// assertion guarded by `if let Some(..)` could pass without running. This read waits a bounded
/// time for the horizon and fails when the validator never publishes it.
async fn require_beacon_horizon(
    client: &Client,
    label: &str,
) -> Result<(
    iroha_data_model::sumeragi::SumeragiStatus,
    iroha_data_model::sumeragi::BeaconHorizonStatusV1,
)> {
    let deadline = Instant::now() + OPERATION_TIMEOUT;
    loop {
        let status = read_on_dedicated_thread({
            let client = client.client().clone();
            move || client.get_sumeragi_status()
        })
        .await?;
        if let Some(horizon) = status.beacon_horizon {
            return Ok((status, horizon));
        }
        if Instant::now() >= deadline {
            return Err(eyre!(
                "{label}: the validator never published its native beacon horizon"
            ));
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

async fn assert_governed_contract_absent(
    client: &Client,
    contract_address: &ContractAddress,
    label: &str,
) -> Result<()> {
    let response = read_on_dedicated_thread({
        let client = client.client().clone();
        let contract_address = (contract_address).clone();
        move || client.get_gov_contract_response(&contract_address)
    })
    .await
    .wrap_err_with(|| format!("{label}: inactive governed-contract lookup failed"))?;
    if response.status() != iroha::http::StatusCode::OK {
        return Err(eyre!(
            "{label}: expected governed-contract HTTP 200, observed {}",
            response.status(),
        ));
    }
    let projection: norito::json::Value = norito::json::from_slice(response.body())
        .wrap_err_with(|| format!("{label}: inactive governed-contract response is not JSON"))?;
    let object = projection
        .as_object()
        .ok_or_else(|| eyre!("{label}: inactive governed-contract response is not an object"))?;
    if object.len() != 3
        || object.get("found").and_then(norito::json::Value::as_bool) != Some(false)
        || object
            .get("contract_address")
            .and_then(norito::json::Value::as_str)
            != Some(contract_address.as_ref())
        || object
            .get("dataspace")
            .and_then(norito::json::Value::as_str)
            != Some("universal")
    {
        return Err(eyre!(
            "{label}: expected the exact inactive governed-contract projection, got {object:?}"
        ));
    }
    Ok(())
}

async fn assert_governed_contract_binding(
    client: &Client,
    contract_address: &ContractAddress,
    expected_code_hash: ContractCodeHash,
    expected_abi_hash: ContractAbiHash,
    label: &str,
) -> Result<()> {
    let response = read_on_dedicated_thread({
        let client = client.client().clone();
        let contract_address = (contract_address).clone();
        move || client.get_gov_contract_json(&contract_address)
    })
    .await
    .wrap_err_with(|| format!("{label}: active governed-contract lookup failed"))?;
    let object = response
        .as_object()
        .ok_or_else(|| eyre!("{label}: active governed-contract response is not an object"))?;
    let expected_subject = contract_address.subject_id().to_string();
    let expected_code_hash = expected_code_hash.to_hex();
    let expected_abi_hash = expected_abi_hash.to_hex();
    let has_exact_entrypoints = object
        .get("public_entrypoints")
        .and_then(norito::json::Value::as_array)
        .is_some_and(|entrypoints| {
            entrypoints.len() == 1 && entrypoints[0].as_str() == Some("main")
        });
    if object.len() != 7
        || object.get("found").and_then(norito::json::Value::as_bool) != Some(true)
        || object
            .get("contract_address")
            .and_then(norito::json::Value::as_str)
            != Some(contract_address.as_ref())
        || object
            .get("contract_subject_account")
            .and_then(norito::json::Value::as_str)
            != Some(expected_subject.as_str())
        || object
            .get("dataspace")
            .and_then(norito::json::Value::as_str)
            != Some("universal")
        || object
            .get("code_hash_hex")
            .and_then(norito::json::Value::as_str)
            != Some(expected_code_hash.as_str())
        || object
            .get("abi_hash_hex")
            .and_then(norito::json::Value::as_str)
            != Some(expected_abi_hash.as_str())
        || !has_exact_entrypoints
    {
        return Err(eyre!(
            "{label}: expected the exact active governed-contract projection, got {object:?}"
        ));
    }
    Ok(())
}

async fn assert_asset_not_found(client: &Client, asset_id: &AssetId, label: &str) -> Result<()> {
    let query = FindAssetById::new(asset_id.clone());
    assert_eq!(
        query.asset_id(),
        asset_id,
        "{label}: bind the exact requested asset"
    );
    match read_on_dedicated_thread({
        let client = client.client().clone();
        move || Ok(client.query_single(query))
    })
    .await?
    {
        Err(QueryError::Validation(ValidationFail::QueryFailed(QueryExecutionFail::Find(
            FindError::Asset(missing),
        )))) if missing.as_ref() == asset_id => Ok(()),
        Ok(asset) => Err(eyre!(
            "{label}: expected asset `{asset_id}` to be absent, but the query returned `{}`",
            asset.id()
        )),
        Err(error) => Err(eyre!(
            "{label}: expected typed absence of exact asset `{asset_id}`, got {error:?}"
        )),
    }
}

fn signed_consensus_handshake(
    network: &iroha_test_network::Network,
) -> Result<ConsensusHandshakeMetadata> {
    let mut handshakes = network
        .genesis_isi()
        .iter()
        .flatten()
        .filter_map(|instruction| instruction.as_any().downcast_ref::<SetParameter>())
        .filter_map(|set_parameter| match set_parameter.inner() {
            Parameter::Custom(custom)
                if custom.id() == &consensus_metadata::handshake_meta_id() =>
            {
                Some(custom)
            }
            _ => None,
        })
        .collect::<Vec<_>>();
    if handshakes.len() != 1 {
        return Err(eyre!("expected one signed consensus handshake"));
    }
    norito::json::from_str(
        handshakes
            .pop()
            .expect("handshake count checked")
            .payload()
            .get(),
    )
    .wrap_err("decode signed consensus handshake")
}

async fn assert_no_global_beacon_pulse_at(
    client: &Client,
    height: u64,
    label: &str,
    network: &iroha_test_network::Network,
) -> Result<()> {
    let block = exact_block(client, height, network)
        .await
        .wrap_err_with(|| format!("{label}: exact finalized block is unavailable"))?;
    if block.global_beacon_pulse().is_some() {
        return Err(eyre!(
            "{label}: finalized block {height} unexpectedly carries a global beacon pulse"
        ));
    }
    Ok(())
}

#[test]
// TODO: this corridor needs a hidden ballot to open, and the timed-OVN release slot is no
// longer consensus demand, so the ballot ends `ReleasePulseUnavailable` unless its frozen
// release height coincides with a native pre-boundary pulse. Re-enable it on the anonymous
// ballot (specs/parliament_private_ballot_design.md 12.2 step 4), which must replace the
// timed-OVN half of `enactment::enact`; the sortition half already uses the native slot,
// and the public-finding NoResult tail runs on its own in
// `four_validator_public_finding_no_result_retries_take_later_native_slots`.
#[ignore = "timed-OVN release slot is no longer consensus demand; the hidden ballot is replaced by the anonymous ballot (specs/parliament_private_ballot_design.md 12.2 step 4)"]
fn four_validator_policy_jury_uses_future_pulses_and_mandatory_timed_ovn() -> Result<()> {
    let name = stringify!(four_validator_policy_jury_uses_future_pulses_and_mandatory_timed_ovn);
    let handle = std::thread::Builder::new()
        .name(name.to_owned())
        .stack_size(PARLIAMENT_NETWORK_STACK_BYTES)
        .spawn(|| {
            tokio::runtime::Builder::new_multi_thread()
                .worker_threads(4)
                .thread_stack_size(PARLIAMENT_NETWORK_STACK_BYTES)
                .enable_all()
                .build()
                .expect("build four-validator Parliament test runtime")
                .block_on(
                    four_validator_policy_jury_uses_future_pulses_and_mandatory_timed_ovn_impl(),
                )
        })
        .expect("spawn four-validator Parliament test thread");
    match handle.join() {
        Ok(result) => result,
        Err(panic) => std::panic::resume_unwind(panic),
    }
}

async fn four_validator_policy_jury_uses_future_pulses_and_mandatory_timed_ovn_impl() -> Result<()>
{
    let citizen_keys = citizen_keys();
    let citizens = citizen_accounts(&citizen_keys);
    let contract_address = ContractAddress::from_str(CONTRACT_ADDRESS)?;
    let no_result_retry_contract_address =
        ContractAddress::from_str(NO_RESULT_RETRY_CONTRACT_ADDRESS)?;
    let builder = enactment::builder(
        NetworkBuilder::new()
            .with_peers(VALIDATOR_COUNT)
            .with_auto_populated_trusted_peers(),
    )
    .with_genesis_instruction(Grant::account_permission(
        Permission::from(CanManageSmartContractCode),
        ALICE_ID.clone(),
    ))
    .with_genesis_instruction(Grant::account_permission(
        Permission::from(CanProposeContractDeployment {
            contract_address: contract_address.clone(),
        }),
        ALICE_ID.clone(),
    ))
    .with_genesis_instruction(Grant::account_permission(
        Permission::from(CanProposeContractDeployment {
            contract_address: no_result_retry_contract_address.clone(),
        }),
        ALICE_ID.clone(),
    ));

    let context = stringify!(four_validator_policy_jury_uses_future_pulses_and_mandatory_timed_ovn);
    let network = sandbox::start_network_async_or_skip(builder, context).await?;
    let Some(network) = sandbox::enforce_network_start_requirement(network, context)? else {
        return Ok(());
    };
    assert_eq!(network.peers().len(), VALIDATOR_COUNT);
    let handshake = signed_consensus_handshake(&network)?;
    handshake
        .validate()
        .map_err(|error| eyre!("signed consensus handshake is invalid: {error}"))?;
    assert_eq!(handshake.mode, SumeragiConsensusMode::Npos);
    assert_eq!(
        handshake.wire_protocol_version,
        u32::from(PROTOCOL_VERSION),
        "the signed genesis handshake must select consensus revision 4",
    );
    assert_eq!(
        handshake.sumeragi_context.da_layout,
        recommended_data_availability_layout(),
        "the corridor must retain the signed revision-4 RS16 DA layout",
    );
    network.ensure_blocks(1).await?;
    let client = network.client();
    let ordered_roster = ordered_validator_roster(&network, &client).await?;
    let beacon_budget = iroha_allocation::AllocationBudget::new(64 * 1024 * 1024);
    let beacon_record = deterministic_parliament_beacon_key_record_v1(
        network.network_id(),
        &ordered_roster,
        &beacon_budget,
    )
    .wrap_err("derive exact public beacon fixture")?;
    let beacon_binding = GlobalThresholdBeaconSessionBindingV1 {
        network_id: beacon_record.session.network_id,
        session_id: beacon_record.session.session_id,
        roster_hash: beacon_record.session.roster_hash,
        transcript_hash: beacon_record.session.transcript_hash,
    };
    validate_global_threshold_beacon_session_v1(
        &beacon_record.session,
        &beacon_binding,
        &beacon_budget,
    )
    .wrap_err("replay the exact public beacon transcript")?;
    let tle_public_state =
        deterministic_parliament_tle_key_public_state_v1(network.network_id(), &ordered_roster)
            .wrap_err("derive exact public TLE fixture")?;
    let install_height = next_execution_height(
        &client,
        beacon_record.session.adaptive_dkg.finalized_at_height,
        "threshold-key installation",
    )
    .await?;
    let lifecycle_certificates = [
        InstructionBox::from(lifecycle_certificate(
            &network,
            &ordered_roster,
            ThresholdKeyLifecycleActionV1::FinalizeGlobalBeaconKey,
            beacon_record.session.session_id,
            beacon_record.session.transcript_hash,
            norito::encode_canonical(&beacon_record)?,
            install_height,
        )?),
        InstructionBox::from(lifecycle_certificate(
            &network,
            &ordered_roster,
            ThresholdKeyLifecycleActionV1::InstallParliamentTleKey,
            *tle_public_state.key_session_id.as_bytes(),
            tle_public_state.transcript_hash,
            norito::encode_canonical(&tle_public_state)?,
            install_height,
        )?),
    ];
    let submission_authority_height = current_height(&client).await?;
    let submission_roster = ordered_validator_roster(&network, &client).await?;
    if submission_roster != ordered_roster {
        return Err(eyre!(
            "threshold-key installation roster changed between fixture derivation and submission"
        ));
    }
    eprintln!(
        "SORA_PARLIAMENT_LIFECYCLE submit_lifecycle authority_height={submission_authority_height} install_height={install_height} roster_hash={}",
        hex::encode(global_threshold_beacon_roster_hash_v1(&ordered_roster)),
    );
    submit_parliament_instructions(&client, lifecycle_certificates).await?;
    assert_eq!(current_height(&client).await?, install_height);
    let activation_height = install_height
        .checked_add(1)
        .ok_or_else(|| eyre!("threshold-key activation height overflow"))?;
    admit_parliament_height_carrier(
        &client,
        [Log::new(
            Level::INFO,
            "carry Parliament threshold-key activation".to_owned(),
        )],
    )
    .await?;
    network.ensure_blocks(activation_height).await?;
    assert_eq!(current_height(&client).await?, activation_height);

    let (code_hash, abi_hash) =
        stage_contract_artifact(&client, &minimal_contract_artifact()).await?;
    let proposal = ProposalKind::DeployContract(DeployContractProposal {
        proposal_operator: client.client().account().clone(),
        contract_address: contract_address.clone(),
        code_hash,
        abi_hash,
        abi_version: AbiVersion::new(1),
        manifest_provenance: None,
    });
    let enacted_fixture = enactment::enact(
        &network,
        proposal,
        vec![
            ProposeDeployContract {
                contract_address: contract_address.clone(),
                code_hash,
                abi_hash,
                abi_version: AbiVersion::new(1),
                manifest_provenance: None,
            }
            .into(),
        ],
        None,
    )
    .await?;
    let attempt_id = enacted_fixture.attempt_id;
    let enacted_height = enacted_fixture.height;
    let logical_beacon = enacted_fixture.logical_beacon;
    let enacted_response = read_on_dedicated_thread({
        let client = client.client().clone();
        move || client.get_parliament_attempt(attempt_id)
    })
    .await?;
    assert_governed_contract_binding(
        &client,
        &contract_address,
        code_hash,
        abi_hash,
        "consensus-owned certificate enactment must bind the staged contract",
    )
    .await?;

    let mut peer_blocks = Vec::with_capacity(network.peers().len());
    for peer in network.peers() {
        peer_blocks.push(exact_block(&peer.client(), enacted_height, &network).await?);
    }
    assert!(
        peer_blocks
            .windows(2)
            .all(|pair| pair[0].hash() == pair[1].hash()),
        "all four validators must finalize the same exact enactment block",
    );
    for (peer, block) in network.peers().iter().zip(&peer_blocks) {
        let (proof, verified) = finality::certified_block(&network, &peer.client(), enacted_height)
            .await
            .wrap_err("independently verify the enactment block's native finality")?;
        assert_eq!(verified.block().hash(), block.hash());
        assert_eq!(verified.height(), enacted_height);
        let context = &verified.commitment().schedule.current;
        assert_eq!(context.committee.len(), VALIDATOR_COUNT);
        // The contiguous helper authenticates exactly three signatures; the native
        // committee has one vote per member and no caller-selected voting weights.
        let mut proof_roster = proof
            .committee
            .iter()
            .map(|entry| PeerId::new(entry.public_key.clone()))
            .collect::<Vec<_>>();
        proof_roster.sort_unstable();
        let mut signed_genesis_roster = ordered_roster.clone();
        signed_genesis_roster.sort_unstable();
        assert_eq!(
            proof_roster, signed_genesis_roster,
            "the native proof roster must equal the signed-genesis voting authority"
        );
        assert_eq!(
            context.da_layout,
            recommended_data_availability_layout(),
            "every enactment proof must retain the signed RS16 DA layout"
        );
    }
    for peer in network.peers() {
        let peer_client = peer.client();
        let response = read_on_dedicated_thread({
            let client = peer_client.client().clone();
            let attempt_id = (attempt_id).clone();
            move || client.get_parliament_attempt(attempt_id)
        })
        .await?;
        assert_eq!(response.current_height, enacted_height);
        assert_eq!(response.attempt.status, GovernanceAttemptStatusV1::Enacted);
        assert_eq!(
            response.state_payload_hex,
            enacted_response.state_payload_hex
        );
        assert_governed_contract_binding(
            &peer_client,
            &contract_address,
            code_hash,
            abi_hash,
            "every validator must expose the consensus-enacted contract",
        )
        .await?;
        let status = read_on_dedicated_thread({
            let client = peer_client.client().clone();
            move || client.get_sumeragi_status()
        })
        .await?;
        assert!(
            !status.is_halted(),
            "an enacted Parliament validator must not be live-but-fail-stopped",
        );
    }

    let restart_index = network.peers().len() - 1;
    let restart_peer = network.peers()[restart_index].clone();
    let config_layers = network.config_layers().collect::<Vec<_>>();
    assert!(
        restart_peer.shutdown_if_started().await,
        "selected validator must be running before the persistence restart",
    );
    tokio::time::timeout(
        network.peer_startup_timeout(),
        restart_peer.start_checked(config_layers.iter(), None),
    )
    .await
    .map_err(|_| eyre!("Parliament validator restart exceeded {OPERATION_TIMEOUT:?}"))??;
    tokio::time::timeout(
        network.sync_timeout(),
        restart_peer.once_block(enacted_height),
    )
    .await
    .map_err(|_| eyre!("restarted Parliament validator did not recover finalized state"))?;
    let restarted_response = read_on_dedicated_thread({
        let client = restart_peer.client().client().clone();
        let attempt_id = (attempt_id).clone();
        move || client.get_parliament_attempt(attempt_id)
    })
    .await?;
    assert_eq!(
        restarted_response.attempt.status,
        GovernanceAttemptStatusV1::Enacted
    );
    assert_eq!(
        restarted_response.state_payload_hex, enacted_response.state_payload_hex,
        "normal restart must restore the complete reducer/certificate state",
    );
    let restarted_block = exact_block(&restart_peer.client(), enacted_height, &network).await?;
    assert_eq!(restarted_block.hash(), peer_blocks[0].hash());
    assert_governed_contract_binding(
        &restart_peer.client(),
        &contract_address,
        code_hash,
        abi_hash,
        "normal restart must restore the consensus-enacted contract",
    )
    .await?;
    let restarted_status = read_on_dedicated_thread({
        let client = restart_peer.client().client().clone();
        move || client.get_sumeragi_status()
    })
    .await?;
    assert!(
        !restarted_status.is_halted(),
        "normal restart must restore a live non-fail-stopped consensus reducer",
    );
    no_result_paths::exercise_public_finding_no_result_retries_and_restore(
        &network,
        &client,
        &citizens,
        &citizen_keys,
        &no_result_retry_contract_address,
        code_hash,
        abi_hash,
        logical_beacon,
    )
    .await?;
    Ok(())
}

#[test]
fn four_validator_mandatory_npos_epoch_boundary_threshold_beacon_release_gate() -> Result<()> {
    let name =
        stringify!(four_validator_mandatory_npos_epoch_boundary_threshold_beacon_release_gate);
    let handle = std::thread::Builder::new()
        .name(name.to_owned())
        .stack_size(PARLIAMENT_NETWORK_STACK_BYTES)
        .spawn(|| {
            tokio::runtime::Builder::new_multi_thread()
                .worker_threads(4)
                .thread_stack_size(PARLIAMENT_NETWORK_STACK_BYTES)
                .enable_all()
                .build()
                .expect("build four-validator mandatory-beacon test runtime")
                .block_on(
                    four_validator_mandatory_npos_epoch_boundary_threshold_beacon_release_gate_impl(
                    ),
                )
        })
        .expect("spawn four-validator mandatory-beacon test thread");
    match handle.join() {
        Ok(result) => result,
        Err(panic) => std::panic::resume_unwind(panic),
    }
}

async fn four_validator_mandatory_npos_epoch_boundary_threshold_beacon_release_gate_impl()
-> Result<()> {
    let mut npos = SumeragiNposParameters::default();
    npos.epoch_length_blocks = NonZeroU64::new(MANDATORY_NPOS_EPOCH_LENGTH_BLOCKS)
        .expect("mandatory NPoS epoch length is non-zero");
    npos.evidence_horizon_blocks = MANDATORY_NPOS_EPOCH_LENGTH_BLOCKS * 2;
    npos.slashing_delay_blocks = MANDATORY_NPOS_EPOCH_LENGTH_BLOCKS;
    npos.validate()
        .map_err(|error| eyre!("invalid mandatory NPoS fixture: {error}"))?;

    let builder = NetworkBuilder::new()
        .with_peers(VALIDATOR_COUNT)
        .with_auto_populated_trusted_peers()
        .with_npos_consensus()
        .with_parliament_beacon_signer_modes(POSITIVE_BEACON_SIGNER_MODES)
        .with_block_cadence(EXACT_HEIGHT_SUBMISSION_CADENCE)
        .with_config_layer(|layer| {
            layer
                .write(
                    ["concurrency", "rayon_global_threads"],
                    PARLIAMENT_NETWORK_RAYON_THREADS_PER_PEER,
                )
                .write(
                    [
                        "network",
                        "soranet_handshake",
                        "pow",
                        "puzzle",
                        "memory_kib",
                    ],
                    i64::from(iroha_crypto::soranet::puzzle::MIN_MEMORY_KIB),
                )
                .write(
                    ["network", "soranet_handshake", "pow", "puzzle", "time_cost"],
                    1_i64,
                )
                .write(
                    ["network", "soranet_handshake", "pow", "puzzle", "lanes"],
                    1_i64,
                )
                .write(
                    ["nexus", "storage", "local_budget_bytes"],
                    TEST_NEXUS_LOCAL_STORAGE_BUDGET_BYTES,
                );
        })
        .with_genesis_instruction(SetParameter::new(Parameter::Sumeragi(
            SumeragiParameter::EpochLengthBlocks(npos.epoch_length_blocks),
        )))
        .with_genesis_instruction(SetParameter::new(Parameter::Custom(
            npos.into_custom_parameter(),
        )));
    let context =
        stringify!(four_validator_mandatory_npos_epoch_boundary_threshold_beacon_release_gate);
    let network = sandbox::start_network_async_or_skip(builder, context).await?;
    let Some(network) = sandbox::enforce_network_start_requirement(network, context)? else {
        return Ok(());
    };
    assert_eq!(network.peers().len(), VALIDATOR_COUNT);
    network.ensure_blocks(1).await?;

    let client = network.client();
    let ordered_roster = ordered_validator_roster(&network, &client).await?;
    let beacon_budget = iroha_allocation::AllocationBudget::new(64 * 1024 * 1024);
    let beacon_record = deterministic_parliament_beacon_key_record_v1(
        network.network_id(),
        &ordered_roster,
        &beacon_budget,
    )
    .wrap_err("derive mandatory NPoS beacon fixture")?;
    assert_eq!(beacon_record.session.committee_size, 4);
    assert_eq!(beacon_record.session.threshold, 2);
    let beacon_binding = GlobalThresholdBeaconSessionBindingV1 {
        network_id: beacon_record.session.network_id,
        session_id: beacon_record.session.session_id,
        roster_hash: beacon_record.session.roster_hash,
        transcript_hash: beacon_record.session.transcript_hash,
    };
    let validated_beacon_session = validate_global_threshold_beacon_session_v1(
        &beacon_record.session,
        &beacon_binding,
        &beacon_budget,
    )
    .wrap_err("replay mandatory NPoS beacon transcript")?;
    let install_height = next_execution_height(
        &client,
        beacon_record.session.adaptive_dkg.finalized_at_height,
        "mandatory beacon-key installation",
    )
    .await?;
    let lifecycle_certificate = lifecycle_certificate(
        &network,
        &ordered_roster,
        ThresholdKeyLifecycleActionV1::FinalizeGlobalBeaconKey,
        beacon_record.session.session_id,
        beacon_record.session.transcript_hash,
        norito::encode_canonical(&beacon_record)?,
        install_height,
    )?;
    submit_parliament_instructions(&client, [lifecycle_certificate]).await?;
    assert_eq!(current_height(&client).await?, install_height);
    let activation_height = install_height
        .checked_add(1)
        .ok_or_else(|| eyre!("mandatory beacon-key activation height overflow"))?;
    admit_parliament_height_carrier(
        &client,
        [Log::new(
            Level::INFO,
            "carry mandatory beacon-key activation".to_owned(),
        )],
    )
    .await?;
    network.ensure_blocks(activation_height).await?;
    assert_eq!(current_height(&client).await?, activation_height);

    let boundary_height = MANDATORY_NPOS_EPOCH_LENGTH_BLOCKS;
    let pulse_height = boundary_height - 1;
    advance_to_autonomous_predecessor(
        &network,
        &client,
        pulse_height,
        "initial mandatory pre-boundary pulse",
    )
    .await?;
    assert_no_global_beacon_pulse_at(
        &client,
        pulse_height - 1,
        "an unrequested non-boundary height must not emit a global pulse",
        &network,
    )
    .await?;
    network.ensure_blocks(pulse_height).await?;
    assert_eq!(
        current_height(&client).await?,
        pulse_height,
        "the mandatory threshold-beacon effect must autonomously finalize its exact pre-boundary height",
    );

    let mut pulses = Vec::with_capacity(network.peers().len());
    for peer in network.peers() {
        pulses.push(pulse_at(&peer.client(), pulse_height, &network).await?);
    }
    assert!(pulses.windows(2).all(|pair| pair[0] == pair[1]));
    let pulse = &pulses[0];
    assert_eq!(pulse.height, pulse_height);
    assert_eq!(pulse.session_id, beacon_record.session.session_id);
    assert_eq!(pulse.roster_hash, beacon_record.session.roster_hash);
    assert_eq!(pulse.transcript_hash, beacon_record.session.transcript_hash);
    assert_eq!(pulse.round, 0, "the mandatory pulse is view-independent");
    assert_eq!(pulse.finalized_chain_anchor.height + 1, pulse_height);
    assert_eq!(
        exact_block(&client, pulse.finalized_chain_anchor.height, &network)
            .await?
            .header()
            .hash(),
        pulse.finalized_chain_anchor.block_hash,
    );
    let (expected_anchor, expected_context) =
        finality::certified_pulse_context(&network, &client, pulse_height, &pulse).await?;
    verify_finalized_global_threshold_beacon_pulse_v1(
        &validated_beacon_session,
        pulse,
        expected_anchor,
        &expected_context,
    )
    .wrap_err("independently verify the mandatory pre-boundary pulse")?;

    let successor_epoch = 1;
    let successor_seed =
        global_threshold_beacon_npos_successor_seed_v1(pulse, boundary_height, successor_epoch);
    admit_parliament_height_carrier(
        &client,
        [Log::new(
            Level::INFO,
            "carry retained-authority successor progression".to_owned(),
        )],
    )
    .await?;
    network.ensure_blocks(boundary_height).await?;
    assert_eq!(current_height(&client).await?, boundary_height);
    network.ensure_blocks(boundary_height + 1).await?;
    assert_eq!(current_height(&client).await?, boundary_height + 1);
    for peer in network.peers() {
        let status = read_on_dedicated_thread({
            let client = peer.client().client().clone();
            move || client.get_sumeragi_status()
        })
        .await?;
        assert!(
            !status.is_halted(),
            "a successful mandatory beacon transition must not fail-stop a validator",
        );
        assert!(status.committed_height >= boundary_height + 1);
        assert!(status.applied_height <= status.committed_height);
        // Epoch state is certified finality evidence, not a local status field.
        let (_, verified) =
            finality::certified_block(&network, &peer.client(), boundary_height + 1).await?;
        assert_eq!(
            exact_block(&peer.client(), boundary_height + 1, &network)
                .await?
                .hash(),
            verified.block().hash(),
        );
        let context = &verified.commitment().schedule.current;
        assert_eq!(context.authorization.epoch, successor_epoch);
        assert_eq!(context.leader_seed, successor_seed);
        assert_eq!(
            context.authorization.last_height,
            boundary_height + MANDATORY_NPOS_EPOCH_LENGTH_BLOCKS
        );
    }

    let successor_pulse_height = boundary_height
        .checked_add(MANDATORY_NPOS_EPOCH_LENGTH_BLOCKS)
        .and_then(|height| height.checked_sub(1))
        .ok_or_else(|| eyre!("successor mandatory pulse height overflow"))?;
    advance_to_autonomous_predecessor(
        &network,
        &client,
        successor_pulse_height,
        "retained-session mandatory pre-boundary pulse",
    )
    .await?;
    network.ensure_blocks(successor_pulse_height).await?;
    let mut successor_pulses = Vec::with_capacity(network.peers().len());
    for peer in network.peers() {
        successor_pulses.push(pulse_at(&peer.client(), successor_pulse_height, &network).await?);
    }
    assert!(successor_pulses.windows(2).all(|pair| pair[0] == pair[1]));
    let successor_pulse = &successor_pulses[0];
    assert_eq!(successor_pulse.height, successor_pulse_height);
    assert_eq!(successor_pulse.session_id, beacon_record.session.session_id);
    assert_eq!(
        successor_pulse.roster_hash,
        beacon_record.session.roster_hash
    );
    assert_eq!(
        successor_pulse.transcript_hash,
        beacon_record.session.transcript_hash
    );
    assert_eq!(successor_pulse.session_id, pulse.session_id);
    let (expected_anchor, expected_context) = finality::certified_pulse_context(
        &network,
        &client,
        successor_pulse_height,
        &successor_pulse,
    )
    .await?;
    verify_finalized_global_threshold_beacon_pulse_v1(
        &validated_beacon_session,
        successor_pulse,
        expected_anchor,
        &expected_context,
    )
    .wrap_err("independently verify the retained-session mandatory pulse")?;

    let second_boundary_height = boundary_height
        .checked_add(MANDATORY_NPOS_EPOCH_LENGTH_BLOCKS)
        .ok_or_else(|| eyre!("second mandatory NPoS boundary overflow"))?;
    let second_successor_epoch = 2;
    let second_successor_seed = global_threshold_beacon_npos_successor_seed_v1(
        successor_pulse,
        second_boundary_height,
        second_successor_epoch,
    );
    admit_parliament_height_carrier(
        &client,
        [Log::new(
            Level::INFO,
            "carry the retained-session NPoS boundary".to_owned(),
        )],
    )
    .await?;
    network.ensure_blocks(second_boundary_height).await?;
    network.ensure_blocks(second_boundary_height + 1).await?;
    for peer in network.peers() {
        let status = read_on_dedicated_thread({
            let client = peer.client().client().clone();
            move || client.get_sumeragi_status()
        })
        .await?;
        assert!(!status.is_halted());
        assert!(status.committed_height >= second_boundary_height + 1);
        assert!(status.applied_height <= status.committed_height);
        // Epoch state is certified finality evidence, not a local status field.
        let (_, verified) =
            finality::certified_block(&network, &peer.client(), second_boundary_height + 1).await?;
        assert_eq!(
            exact_block(&peer.client(), second_boundary_height + 1, &network)
                .await?
                .hash(),
            verified.block().hash(),
        );
        let context = &verified.commitment().schedule.current;
        assert_eq!(context.authorization.epoch, second_successor_epoch);
        assert_eq!(context.leader_seed, second_successor_seed);
        assert_eq!(
            context.authorization.last_height,
            second_boundary_height + MANDATORY_NPOS_EPOCH_LENGTH_BLOCKS
        );
    }

    // Authenticate the whole prefix against the provisioned signed genesis;
    // no claimed server context may establish an authority or scheduling epoch.
    let expected_roster = ordered_roster.clone();
    let expected_session = beacon_record.session.session_id;
    let expected_transcript = beacon_record.session.transcript_hash;
    let mut original_authority = None;
    let mut frozen_attempt = None;
    finality::visit_certified_prefix(
        &network,
        &client,
        second_boundary_height + 1,
        move |proof, verified| {
            use iroha_data_model::sumeragi::epoch::{
                BeaconEpochBindingV1, InstalledBeaconEpochBindingV1, ValidatorEpochDecisionV1,
            };
            let height = verified.height();
            let schedule = &verified.commitment().schedule;
            let context = &schedule.current;
            if height == 1 {
                assert_eq!(
                    proof
                        .committee
                        .iter()
                        .map(|seat| PeerId::new(seat.public_key.clone()))
                        .collect::<Vec<_>>(),
                    expected_roster
                );
                original_authority = Some((
                    context.authorization.authority_generation,
                    context.authorization.authority_id,
                ));
            }
            assert_eq!(
                (
                    context.authorization.authority_generation,
                    context.authorization.authority_id,
                ),
                original_authority.unwrap()
            );
            assert_eq!(context.da_layout, recommended_data_availability_layout());
            assert_eq!(context.committee.len(), VALIDATOR_COUNT);
            // visit_certified_prefix checks the exact three equal native votes at
            // every non-genesis height before this callback sees the execution.
            if height == boundary_height {
                frozen_attempt = schedule.boundary.as_ref().unwrap().preparation.clone();
            }
            if [boundary_height + 1, second_boundary_height + 1].contains(&height) {
                let (expected_epoch, expected_seed, expected_end) = if height == boundary_height + 1
                {
                    (
                        successor_epoch,
                        successor_seed,
                        boundary_height + MANDATORY_NPOS_EPOCH_LENGTH_BLOCKS,
                    )
                } else {
                    (
                        second_successor_epoch,
                        second_successor_seed,
                        second_boundary_height + MANDATORY_NPOS_EPOCH_LENGTH_BLOCKS,
                    )
                };
                assert_eq!(context.authorization.epoch, expected_epoch);
                assert_eq!(context.leader_seed, expected_seed);
                assert_eq!(context.authorization.last_height, expected_end);
                let authorization = &context.authorization;
                assert_eq!(
                    authorization.epoch,
                    (height - 1) / MANDATORY_NPOS_EPOCH_LENGTH_BLOCKS
                );
                if height == second_boundary_height + 1 && frozen_attempt.is_some() {
                    assert_eq!(
                        authorization.decision,
                        ValidatorEpochDecisionV1::RetainAndCancel
                    );
                    assert_eq!(
                        authorization.transition_id,
                        frozen_attempt.as_ref().unwrap().transition_id().unwrap()
                    );
                } else {
                    assert_eq!(authorization.decision, ValidatorEpochDecisionV1::Retain);
                    assert_eq!(authorization.transition_id, [0; 32]);
                }
                assert_eq!(
                    authorization.beacon,
                    BeaconEpochBindingV1::Installed(InstalledBeaconEpochBindingV1 {
                        session_id: expected_session,
                        transcript_hash: expected_transcript,
                    })
                );
            }
            Ok(())
        },
    )
    .await
    .wrap_err("authenticate retained authority across both real scheduling boundaries")?;

    network.shutdown().await;
    Ok(())
}

#[test]
fn four_validator_mandatory_npos_beacon_fails_closed_below_threshold() -> Result<()> {
    let name = stringify!(four_validator_mandatory_npos_beacon_fails_closed_below_threshold);
    let handle = std::thread::Builder::new()
        .name(name.to_owned())
        .stack_size(PARLIAMENT_NETWORK_STACK_BYTES)
        .spawn(|| {
            tokio::runtime::Builder::new_multi_thread()
                .worker_threads(4)
                .thread_stack_size(PARLIAMENT_NETWORK_STACK_BYTES)
                .enable_all()
                .build()
                .expect("build four-validator fail-closed beacon test runtime")
                .block_on(four_validator_mandatory_npos_beacon_fails_closed_below_threshold_impl())
        })
        .expect("spawn four-validator fail-closed beacon test thread");
    match handle.join() {
        Ok(result) => result,
        Err(panic) => std::panic::resume_unwind(panic),
    }
}

async fn four_validator_mandatory_npos_beacon_fails_closed_below_threshold_impl() -> Result<()> {
    assert_eq!(
        FAIL_CLOSED_BEACON_SIGNER_MODES
            .iter()
            .filter(|mode| **mode == ParliamentBeaconSignerMode::Valid)
            .count(),
        1,
        "the negative corridor must retain exactly one proof-valid beacon share",
    );
    let mut npos = SumeragiNposParameters::default();
    npos.epoch_length_blocks = NonZeroU64::new(MANDATORY_NPOS_EPOCH_LENGTH_BLOCKS)
        .expect("mandatory NPoS epoch length is non-zero");
    npos.evidence_horizon_blocks = MANDATORY_NPOS_EPOCH_LENGTH_BLOCKS * 2;
    npos.slashing_delay_blocks = MANDATORY_NPOS_EPOCH_LENGTH_BLOCKS;
    npos.validate()
        .map_err(|error| eyre!("invalid fail-closed NPoS fixture: {error}"))?;

    let builder = NetworkBuilder::new()
        .with_peers(VALIDATOR_COUNT)
        .with_auto_populated_trusted_peers()
        .with_npos_consensus()
        .with_parliament_beacon_signer_modes(FAIL_CLOSED_BEACON_SIGNER_MODES)
        .with_block_cadence(EXACT_HEIGHT_SUBMISSION_CADENCE)
        .with_config_layer(|layer| {
            layer
                .write(
                    ["concurrency", "rayon_global_threads"],
                    PARLIAMENT_NETWORK_RAYON_THREADS_PER_PEER,
                )
                .write(
                    [
                        "network",
                        "soranet_handshake",
                        "pow",
                        "puzzle",
                        "memory_kib",
                    ],
                    i64::from(iroha_crypto::soranet::puzzle::MIN_MEMORY_KIB),
                )
                .write(
                    ["network", "soranet_handshake", "pow", "puzzle", "time_cost"],
                    1_i64,
                )
                .write(
                    ["network", "soranet_handshake", "pow", "puzzle", "lanes"],
                    1_i64,
                )
                .write(
                    ["nexus", "storage", "local_budget_bytes"],
                    TEST_NEXUS_LOCAL_STORAGE_BUDGET_BYTES,
                );
        })
        .with_genesis_instruction(SetParameter::new(Parameter::Sumeragi(
            SumeragiParameter::EpochLengthBlocks(npos.epoch_length_blocks),
        )))
        .with_genesis_instruction(SetParameter::new(Parameter::Custom(
            npos.into_custom_parameter(),
        )));
    let context = stringify!(four_validator_mandatory_npos_beacon_fails_closed_below_threshold);
    let network = sandbox::start_network_async_or_skip(builder, context).await?;
    let Some(network) = sandbox::enforce_network_start_requirement(network, context)? else {
        return Ok(());
    };
    assert_eq!(network.peers().len(), VALIDATOR_COUNT);
    network.ensure_blocks(1).await?;

    let client = network.client();
    let ordered_roster = ordered_validator_roster(&network, &client).await?;
    let beacon_budget = iroha_allocation::AllocationBudget::new(64 * 1024 * 1024);
    let beacon_record = deterministic_parliament_beacon_key_record_v1(
        network.network_id(),
        &ordered_roster,
        &beacon_budget,
    )
    .wrap_err("derive fail-closed NPoS beacon fixture")?;
    assert_eq!(beacon_record.session.committee_size, 4);
    assert_eq!(beacon_record.session.threshold, 2);
    let install_height = next_execution_height(
        &client,
        beacon_record.session.adaptive_dkg.finalized_at_height,
        "fail-closed beacon-key installation",
    )
    .await?;
    let lifecycle_certificate = lifecycle_certificate(
        &network,
        &ordered_roster,
        ThresholdKeyLifecycleActionV1::FinalizeGlobalBeaconKey,
        beacon_record.session.session_id,
        beacon_record.session.transcript_hash,
        norito::encode_canonical(&beacon_record)?,
        install_height,
    )?;
    submit_parliament_instructions(&client, [lifecycle_certificate]).await?;
    assert_eq!(current_height(&client).await?, install_height);
    let activation_height = install_height
        .checked_add(1)
        .ok_or_else(|| eyre!("fail-closed beacon-key activation height overflow"))?;
    admit_parliament_height_carrier(
        &client,
        [Log::new(
            Level::INFO,
            "carry fail-closed beacon-key activation".to_owned(),
        )],
    )
    .await?;
    network.ensure_blocks(activation_height).await?;
    assert_eq!(current_height(&client).await?, activation_height);

    let pulse_height = MANDATORY_NPOS_EPOCH_LENGTH_BLOCKS - 1;
    let predecessor_height = pulse_height - 1;
    assert_eq!(
        activation_height.checked_add(1),
        Some(predecessor_height),
        "the retained deterministic fixture must expose one committed predecessor after activation",
    );
    network.ensure_blocks(predecessor_height).await?;
    assert_eq!(current_height(&client).await?, predecessor_height);
    let pulse_status_is_active = |status: &SumeragiStatus| -> bool {
        assert!(
            !status.is_halted(),
            "below-threshold beacon liveness must stall without fail-stopping consensus",
        );
        assert_eq!(status.committed_height, predecessor_height);
        assert!(status.applied_height <= status.committed_height);
        if status.height == predecessor_height {
            // A committed round remains current only until its successor
            // configuration is available. Keep polling through that handoff.
            assert!(status.awaiting);
            return false;
        }
        assert_eq!(status.height, pulse_height);
        // Round entry and durable application are reported separately. Begin
        // the observation only once the predecessor is applied and the pulse
        // round has its configuration, so configuration/application lag cannot
        // masquerade as a below-threshold beacon stall.
        !status.awaiting && status.applied_height == predecessor_height
    };
    // Keep each synchronous request short and check one monotonic deadline
    // before and after it. The complete wait can therefore exceed its nominal
    // window by at most one request bound, without leaving detached blocking
    // tasks behind.
    let status_poll_window = network.sync_timeout();
    if status_poll_window.is_zero() {
        return Err(eyre!(
            "the fail-closed status polling window must be non-zero"
        ));
    }
    let requests_per_sweep = u32::try_from(network.peers().len())
        .ok()
        .and_then(|peers| peers.checked_mul(2))
        .filter(|requests| *requests != 0)
        .ok_or_else(|| eyre!("the fail-closed status sweep width must fit in u32"))?;
    let status_poll_request_timeout = status_poll_window
        .checked_div(requests_per_sweep)
        .unwrap_or(Duration::ZERO)
        .max(Duration::from_millis(1))
        .min(Duration::from_secs(5));
    let status_poll_clients = network
        .peers()
        .iter()
        .map(|peer| {
            integration_tests::sync::rebind_blocking_client(&peer.client(), |builder| {
                builder.torii_request_timeout = status_poll_request_timeout;
            })
        })
        .collect::<Vec<_>>();

    let activation_deadline = Instant::now()
        .checked_add(status_poll_window)
        .ok_or_else(|| eyre!("fail-closed activation deadline overflow"))?;
    let mut last_activation_status_error = None;
    loop {
        let mut all_pulse_heights_active = true;
        for (peer_index, peer_client) in status_poll_clients.iter().enumerate() {
            if Instant::now() >= activation_deadline {
                return Err(eyre!(
                    "validators did not publish the mandatory pulse-height context within {status_poll_window:?} plus the {status_poll_request_timeout:?} in-flight request bound; last status fetch error: {}",
                    last_activation_status_error.as_deref().unwrap_or("none"),
                ));
            }
            let observed_height = match current_height(peer_client).await {
                Ok(height) => height,
                Err(error) => {
                    last_activation_status_error =
                        Some(format!("peer {peer_index} height: {error}"));
                    all_pulse_heights_active = false;
                    continue;
                }
            };
            if Instant::now() >= activation_deadline {
                return Err(eyre!(
                    "validators did not publish the mandatory pulse-height context within {status_poll_window:?} plus the {status_poll_request_timeout:?} in-flight request bound; last status fetch error: {}",
                    last_activation_status_error.as_deref().unwrap_or("none"),
                ));
            }
            assert_eq!(
                observed_height, predecessor_height,
                "the pulse height must remain uncommitted during successor activation",
            );
            let status = match read_on_dedicated_thread({
                let client = peer_client.client().clone();
                move || client.get_sumeragi_status()
            })
            .await
            {
                Ok(status) => status,
                Err(error) => {
                    last_activation_status_error =
                        Some(format!("peer {peer_index} sumeragi status: {error}"));
                    all_pulse_heights_active = false;
                    continue;
                }
            };
            if Instant::now() >= activation_deadline {
                return Err(eyre!(
                    "validators did not publish the mandatory pulse-height context within {status_poll_window:?} plus the {status_poll_request_timeout:?} in-flight request bound; last status fetch error: {}",
                    last_activation_status_error.as_deref().unwrap_or("none"),
                ));
            }
            all_pulse_heights_active &= pulse_status_is_active(&status);
        }
        if all_pulse_heights_active {
            break;
        }
        let remaining = activation_deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(eyre!(
                "validators did not publish the mandatory pulse-height context within {status_poll_window:?} plus the {status_poll_request_timeout:?} in-flight request bound; last status fetch error: {}",
                last_activation_status_error.as_deref().unwrap_or("none"),
            ));
        }
        tokio::time::sleep(Duration::from_millis(100).min(remaining)).await;
    }

    let unexpected_pulse_height = tokio::time::timeout(
        FAIL_CLOSED_BEACON_OBSERVATION_WINDOW,
        network.peers()[0].once_block(pulse_height),
    )
    .await;
    assert!(
        unexpected_pulse_height.is_err(),
        "one valid share plus one proof-invalid share must not satisfy the exact threshold of two",
    );

    let post_observation_deadline = Instant::now()
        .checked_add(status_poll_window)
        .ok_or_else(|| eyre!("fail-closed post-observation deadline overflow"))?;
    let mut last_post_observation_status_error = None;
    loop {
        let mut all_post_observation_statuses_verified = true;
        for (peer_index, (peer, peer_client)) in
            network.peers().iter().zip(&status_poll_clients).enumerate()
        {
            assert!(
                peer.is_running(),
                "the beacon-share fault must not stop a consensus validator",
            );
            if Instant::now() >= post_observation_deadline {
                return Err(eyre!(
                    "validators did not retain the mandatory pulse-height context within {status_poll_window:?} plus the {status_poll_request_timeout:?} in-flight request bound after the below-threshold observation; last status fetch error: {}",
                    last_post_observation_status_error
                        .as_deref()
                        .unwrap_or("none"),
                ));
            }
            let observed_height = match current_height(peer_client).await {
                Ok(height) => height,
                Err(error) => {
                    last_post_observation_status_error =
                        Some(format!("peer {peer_index} height: {error}"));
                    all_post_observation_statuses_verified = false;
                    continue;
                }
            };
            if Instant::now() >= post_observation_deadline {
                return Err(eyre!(
                    "validators did not retain the mandatory pulse-height context within {status_poll_window:?} plus the {status_poll_request_timeout:?} in-flight request bound after the below-threshold observation; last status fetch error: {}",
                    last_post_observation_status_error
                        .as_deref()
                        .unwrap_or("none"),
                ));
            }
            assert_eq!(
                observed_height, predecessor_height,
                "the mandatory pre-boundary height must remain uncommitted below threshold",
            );
            let status = match read_on_dedicated_thread({
                let client = peer_client.client().clone();
                move || client.get_sumeragi_status()
            })
            .await
            {
                Ok(status) => status,
                Err(error) => {
                    last_post_observation_status_error =
                        Some(format!("peer {peer_index} sumeragi status: {error}"));
                    all_post_observation_statuses_verified = false;
                    continue;
                }
            };
            if Instant::now() >= post_observation_deadline {
                return Err(eyre!(
                    "validators did not retain the mandatory pulse-height context within {status_poll_window:?} plus the {status_poll_request_timeout:?} in-flight request bound after the below-threshold observation; last status fetch error: {}",
                    last_post_observation_status_error
                        .as_deref()
                        .unwrap_or("none"),
                ));
            }
            assert!(
                pulse_status_is_active(&status),
                "the bounded below-threshold observation must begin and end in the active pulse context",
            );
        }
        if all_post_observation_statuses_verified {
            break;
        }
        let remaining = post_observation_deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(eyre!(
                "validators did not retain the mandatory pulse-height context within {status_poll_window:?} plus the {status_poll_request_timeout:?} in-flight request bound after the below-threshold observation; last status fetch error: {}",
                last_post_observation_status_error
                    .as_deref()
                    .unwrap_or("none"),
            ));
        }
        tokio::time::sleep(Duration::from_millis(100).min(remaining)).await;
    }

    network.shutdown().await;
    Ok(())
}

#[test]
fn four_validator_pending_parliament_request_never_blocks_unrelated_work_or_restart() -> Result<()>
{
    let name = stringify!(
        four_validator_pending_parliament_request_never_blocks_unrelated_work_or_restart
    );
    let handle = std::thread::Builder::new()
        .name(name.to_owned())
        .stack_size(PARLIAMENT_NETWORK_STACK_BYTES)
        .spawn(|| {
            tokio::runtime::Builder::new_multi_thread()
                .worker_threads(4)
                .thread_stack_size(PARLIAMENT_NETWORK_STACK_BYTES)
                .enable_all()
                .build()
                .expect("build four-validator governance-isolation test runtime")
                .block_on(
                    four_validator_pending_parliament_request_never_blocks_unrelated_work_or_restart_impl(),
                )
        })
        .expect("spawn four-validator governance-isolation test thread");
    match handle.join() {
        Ok(result) => result,
        Err(panic) => std::panic::resume_unwind(panic),
    }
}

// A pending Parliament sortition request is governance-local. Its slot is the far native
// pre-boundary height of the default epoch, no validator quorum can sign a threshold pulse,
// and the chain still commits unrelated work, restarts a validator and stays ready.
async fn four_validator_pending_parliament_request_never_blocks_unrelated_work_or_restart_impl()
-> Result<()> {
    assert_eq!(
        FAIL_CLOSED_BEACON_SIGNER_MODES
            .iter()
            .filter(|mode| **mode == ParliamentBeaconSignerMode::Valid)
            .count(),
        1,
        "the isolation corridor must leave the beacon below its exact threshold of two",
    );
    let contract_address = ContractAddress::from_str(CONTRACT_ADDRESS)?;
    // No explicit NPoS snapshot: the network signs the default epoch length.
    let builder = enactment::builder_with_signer_modes(
        NetworkBuilder::new()
            .with_peers(VALIDATOR_COUNT)
            .with_auto_populated_trusted_peers(),
        FAIL_CLOSED_BEACON_SIGNER_MODES,
    )
    .with_genesis_instruction(Grant::account_permission(
        Permission::from(CanManageSmartContractCode),
        ALICE_ID.clone(),
    ))
    .with_genesis_instruction(Grant::account_permission(
        Permission::from(CanProposeContractDeployment {
            contract_address: contract_address.clone(),
        }),
        ALICE_ID.clone(),
    ));
    let context = stringify!(
        four_validator_pending_parliament_request_never_blocks_unrelated_work_or_restart
    );
    let network = sandbox::start_network_async_or_skip(builder, context).await?;
    let Some(network) = sandbox::enforce_network_start_requirement(network, context)? else {
        return Ok(());
    };
    assert_eq!(network.peers().len(), VALIDATOR_COUNT);
    assert_eq!(
        signed_consensus_handshake(&network)?.mode,
        SumeragiConsensusMode::Npos
    );
    network.ensure_blocks(1).await?;

    let client = network.client();
    let epoch_length_blocks = certified_npos_epoch_length(&network, &client).await?;
    assert_eq!(
        epoch_length_blocks,
        SumeragiNposParameters::default().epoch_length_blocks.get(),
        "the isolation corridor must run on the default signed NPoS epoch",
    );
    // No beacon key session is installed, and the signer profile stays below the exact
    // threshold of two for any session: no validator set can produce a threshold pulse
    // at any height of this corridor.
    // TODO: also run this corridor with an installed, below-threshold key session (as the
    // fail-closed corridor installs it) once the test-network beacon fixture
    // `deterministic_parliament_beacon_key_record_v1` is rebuilt on the all-edge DKG; it is
    // currently rejected with "test Parliament beacon cryptographic fixture is invalid".
    for peer in network.peers() {
        let (_, horizon) = require_beacon_horizon(
            &peer.client(),
            "governance-isolation precondition without a beacon key session",
        )
        .await?;
        assert!(
            horizon.active_session_id.is_none(),
            "the isolation corridor must run without an installed beacon key session",
        );
    }

    let (code_hash, abi_hash) =
        stage_contract_artifact(&client, &minimal_contract_artifact()).await?;
    let create = CreateParliamentGovernanceAttemptV1 {
        proposal: ProposalKind::DeployContract(DeployContractProposal {
            proposal_operator: client.client().account().clone(),
            contract_address: contract_address.clone(),
            code_hash,
            abi_hash,
            abi_version: AbiVersion::new(1),
            manifest_provenance: None,
        }),
        attempt_sequence: 0,
    };
    let attempt_id = create.governance_attempt_id();
    let request_height =
        next_execution_height(&client, 0, "governance-isolation sortition request").await?;
    submit_parliament_instructions(
        &client,
        [
            InstructionBox::from(ProposeDeployContract {
                contract_address: contract_address.clone(),
                code_hash,
                abi_hash,
                abi_version: AbiVersion::new(1),
                manifest_provenance: None,
            }),
            InstructionBox::from(create),
            InstructionBox::from(SubmitParliamentLifecycleTransitionV1 {
                governance_attempt_id: attempt_id,
                transition: ParliamentLifecycleTransitionV1::CompleteQualification,
            }),
            InstructionBox::from(SubmitParliamentLifecycleTransitionV1 {
                governance_attempt_id: attempt_id,
                transition: ParliamentLifecycleTransitionV1::RegisterInitialSortition,
            }),
        ],
    )
    .await?;
    assert_eq!(current_height(&client).await?, request_height);

    let pending = read_attempt(&client, attempt_id).await?;
    assert_eq!(pending.attempt().status, GovernanceAttemptStatusV1::Active);
    assert_eq!(
        pending.sortition_pulse_epoch_length_blocks(),
        epoch_length_blocks
    );
    let retired_slot = request_height
        .checked_add(pending.sortition_pulse_delay_blocks())
        .ok_or_else(|| eyre!("retired governance slot overflow"))?;
    let pending_slot = aligned_native_pulse_height(retired_slot, epoch_length_blocks)?;
    assert_eq!(
        pending_slot,
        epoch_length_blocks - 1,
        "the frozen slot must be the first native pre-boundary height of the default epoch",
    );
    let isolation_tip = retired_slot
        .checked_add(ISOLATION_CARRIERS_PAST_RETIRED_SLOT - 1)
        .ok_or_else(|| eyre!("governance-isolation tip overflow"))?;
    assert!(
        isolation_tip < pending_slot - 1,
        "the corridor must stay far below the only native pulse height",
    );
    let election_ids = pending
        .required_bodies()
        .iter()
        .filter(|required| required.body != ParliamentBody::ConfirmationJury)
        .map(|required| BodyElectionAttemptId::derive_v1(attempt_id, required.body, 0))
        .collect::<Vec<_>>();
    assert_eq!(election_ids.len(), 6);
    let assert_pending_on_original_slot = |state: &ParliamentAttemptStateV1| {
        assert_eq!(state.attempt().status, GovernanceAttemptStatusV1::Active);
        assert!(state.certificate().is_none());
        for election_id in &election_ids {
            let election = state
                .election(election_id)
                .expect("the pending sortition request must stay registered");
            assert_eq!(
                election.attempt().status,
                BodyElectionAttemptStatusV1::AwaitingPulse
            );
            assert_eq!(election.attempt().request.request_height, request_height);
            assert_eq!(
                election.attempt().request.pulse_height,
                pending_slot,
                "a pending sortition request must stay on exactly its original frozen slot",
            );
            assert!(election.pulse_id().is_none());
            assert!(election.pulse_output().is_none());
            assert!(election.primary_assignments().is_empty());
        }
    };
    assert_pending_on_original_slot(&pending);
    let pending_payload = read_on_dedicated_thread({
        let client = client.client().clone();
        move || client.get_parliament_attempt(attempt_id)
    })
    .await?
    .state_payload_hex;

    // Unrelated work up to the height just below the retired slot.
    advance_to_height_with_carriers(
        &network,
        &client,
        retired_slot - 1,
        "governance-isolation unrelated work before the retired slot",
    )
    .await?;
    admit_parliament_height_carrier(
        &client,
        [Log::new(
            Level::INFO,
            format!("governance-isolation unrelated work at the retired slot {retired_slot}"),
        )],
    )
    .await?;
    // BASELINE-FAILING ASSERTION: before governance availability was isolated, the pending
    // request made `request_height + delay` a consensus-demanded pulse height. No key session
    // is installed here (and the signer profile is below threshold for any session), so that
    // pulse could never be produced: this wait timed out and the chain stayed at
    // `retired_slot - 1`. It must now commit as an ordinary block.
    network.ensure_blocks(retired_slot).await?;
    observe_exact_height(
        &client,
        retired_slot,
        "a pending Parliament request must not stall the chain at its retired mid-epoch slot",
    )
    .await?;
    advance_to_height_with_carriers(
        &network,
        &client,
        isolation_tip,
        "governance-isolation unrelated work past the retired slot",
    )
    .await?;
    assert_eq!(
        isolation_tip - request_height,
        pending.sortition_pulse_delay_blocks() + ISOLATION_CARRIERS_PAST_RETIRED_SLOT - 1,
        "at least twelve unrelated carriers must commit while the request is pending",
    );
    network.ensure_blocks(isolation_tip).await?;

    let tip_hash = exact_block(&client, isolation_tip, &network).await?.hash();
    for peer in network.peers() {
        let peer_client = peer.client();
        assert_eq!(
            exact_block(&peer_client, isolation_tip, &network)
                .await?
                .hash(),
            tip_hash,
            "every validator must commit the same unrelated work",
        );
        for height in request_height..=isolation_tip {
            assert_no_global_beacon_pulse_at(
                &peer_client,
                height,
                "a pending Parliament request must not create a global beacon pulse",
                &network,
            )
            .await?;
        }
        let response = read_on_dedicated_thread({
            let client = peer_client.client().clone();
            move || client.get_parliament_attempt(attempt_id)
        })
        .await?;
        assert_eq!(
            response.state_payload_hex, pending_payload,
            "unrelated work must not move the pending request on any validator",
        );
        assert_pending_on_original_slot(&read_attempt(&peer_client, attempt_id).await?);
        // Readiness reads the consensus-native horizon only: the next required pulse is the
        // epoch's own pre-boundary height, never the governance request's retired slot. The
        // horizon is required, so these assertions cannot pass by its absence.
        let (status, horizon) = require_beacon_horizon(
            &peer_client,
            "governance-isolation readiness while the request is pending",
        )
        .await?;
        assert!(
            !status.is_halted(),
            "a pending Parliament request must not fail-stop a validator",
        );
        assert!(status.committed_height >= isolation_tip);
        assert!(status.applied_height <= status.committed_height);
        assert_eq!(horizon.epoch_length_blocks, epoch_length_blocks);
        assert_ne!(horizon.next_required_pulse_height, Some(retired_slot));
        assert_eq!(
            horizon.next_required_pulse_height,
            Some(pending_slot),
            "the beacon horizon must name only the native pre-boundary pulse",
        );
    }

    let restart_peer = network
        .peers()
        .last()
        .expect("four-validator network has a restart peer")
        .clone();
    let config_layers = network.config_layers().collect::<Vec<_>>();
    assert!(
        restart_peer.shutdown_if_started().await,
        "the restart validator must be running while the request is pending",
    );
    tokio::time::timeout(
        network.peer_startup_timeout(),
        restart_peer.start_checked(config_layers.iter(), None),
    )
    .await
    .map_err(|_| eyre!("governance-isolation restart exceeded its startup window"))??;
    tokio::time::timeout(
        network.sync_timeout(),
        restart_peer.once_block(isolation_tip),
    )
    .await
    .map_err(|_| eyre!("restarted validator did not recover the pending-request chain"))?;
    assert_eq!(
        exact_block(&restart_peer.client(), isolation_tip, &network)
            .await?
            .hash(),
        tip_hash,
    );
    let restarted_response = read_on_dedicated_thread({
        let client = restart_peer.client().client().clone();
        move || client.get_parliament_attempt(attempt_id)
    })
    .await?;
    assert_eq!(
        restarted_response.state_payload_hex, pending_payload,
        "restart must restore the pending request on exactly its original slot",
    );

    // The restarted validator rejoins and the chain keeps committing unrelated work.
    let final_tip = isolation_tip + ISOLATION_CARRIERS_AFTER_RESTART;
    advance_to_height_with_carriers(
        &network,
        &client,
        final_tip,
        "governance-isolation unrelated work after restart",
    )
    .await?;
    tokio::time::timeout(network.sync_timeout(), restart_peer.once_block(final_tip))
        .await
        .map_err(|_| eyre!("restarted validator did not catch up with later unrelated work"))?;
    let final_hash = exact_block(&client, final_tip, &network).await?.hash();
    for peer in network.peers() {
        let peer_client = peer.client();
        assert_eq!(
            exact_block(&peer_client, final_tip, &network).await?.hash(),
            final_hash
        );
        for height in isolation_tip..=final_tip {
            assert_no_global_beacon_pulse_at(
                &peer_client,
                height,
                "post-restart unrelated work must not create a global beacon pulse",
                &network,
            )
            .await?;
        }
        let response = read_on_dedicated_thread({
            let client = peer_client.client().clone();
            move || client.get_parliament_attempt(attempt_id)
        })
        .await?;
        assert_eq!(response.state_payload_hex, pending_payload);
        assert_pending_on_original_slot(&read_attempt(&peer_client, attempt_id).await?);
        let status = read_on_dedicated_thread({
            let client = peer_client.client().clone();
            move || client.get_sumeragi_status()
        })
        .await?;
        assert!(!status.is_halted());
        assert!(status.committed_height >= final_tip);
    }

    network.shutdown().await;
    Ok(())
}

#[test]
fn four_validator_public_finding_no_result_retries_take_later_native_slots() -> Result<()> {
    let name = stringify!(four_validator_public_finding_no_result_retries_take_later_native_slots);
    let handle = std::thread::Builder::new()
        .name(name.to_owned())
        .stack_size(PARLIAMENT_NETWORK_STACK_BYTES)
        .spawn(|| {
            tokio::runtime::Builder::new_multi_thread()
                .worker_threads(4)
                .thread_stack_size(PARLIAMENT_NETWORK_STACK_BYTES)
                .enable_all()
                .build()
                .expect("build four-validator public-finding NoResult test runtime")
                .block_on(
                    four_validator_public_finding_no_result_retries_take_later_native_slots_impl(),
                )
        })
        .expect("spawn four-validator public-finding NoResult test thread");
    match handle.join() {
        Ok(result) => result,
        Err(panic) => std::panic::resume_unwind(panic),
    }
}

// Sortition-only corridor: two governance attempts each draw from their own native
// pre-boundary pulse and end in a public-finding NoResult; no hidden ballot is registered.
async fn four_validator_public_finding_no_result_retries_take_later_native_slots_impl() -> Result<()>
{
    let citizen_keys = citizen_keys();
    let citizens = citizen_accounts(&citizen_keys);
    let contract_address = ContractAddress::from_str(NO_RESULT_RETRY_CONTRACT_ADDRESS)?;
    let builder = enactment::builder(
        NetworkBuilder::new()
            .with_peers(VALIDATOR_COUNT)
            .with_auto_populated_trusted_peers(),
    )
    .with_genesis_instruction(Grant::account_permission(
        Permission::from(CanManageSmartContractCode),
        ALICE_ID.clone(),
    ))
    .with_genesis_instruction(Grant::account_permission(
        Permission::from(CanProposeContractDeployment {
            contract_address: contract_address.clone(),
        }),
        ALICE_ID.clone(),
    ));
    let context =
        stringify!(four_validator_public_finding_no_result_retries_take_later_native_slots);
    let network = sandbox::start_network_async_or_skip(builder, context).await?;
    let Some(network) = sandbox::enforce_network_start_requirement(network, context)? else {
        return Ok(());
    };
    assert_eq!(network.peers().len(), VALIDATOR_COUNT);
    network.ensure_blocks(1).await?;
    let client = network.client();
    assert_eq!(
        certified_npos_epoch_length(&network, &client).await?,
        CORRIDOR_NPOS_EPOCH_LENGTH_BLOCKS,
    );
    enactment::fund_citizen_fees(&network, &client, &citizens).await?;
    let sessions = failure_paths::install_threshold_sessions(&network, &client).await?;
    let (code_hash, abi_hash) =
        stage_contract_artifact(&client, &minimal_contract_artifact()).await?;
    no_result_paths::exercise_public_finding_no_result_retries_and_restore(
        &network,
        &client,
        &citizens,
        &citizen_keys,
        &contract_address,
        code_hash,
        abi_hash,
        sessions.logical_beacon,
    )
    .await?;
    network.shutdown().await;
    Ok(())
}

#[test]
fn parliament_network_corridor_has_no_legacy_or_consensus_bypass_surface() {
    let source = [
        include_str!("sora_parliament_lifecycle_smoke.rs"),
        include_str!("sora_parliament_lifecycle_support.rs"),
        include_str!("sora_parliament_enactment.rs"),
        include_str!("sora_parliament_no_result_paths.rs"),
        include_str!("sora_parliament_failure_paths.rs"),
        include_str!("sora_parliament_private_ballot_retry.rs"),
    ]
    .concat();
    let rayon_threads_key = concat!("rayon_global_", "threads");
    assert_eq!(
        source.matches(rayon_threads_key).count(),
        6,
        "every four-validator builder must bound per-peer proving concurrency without disabling FastPQ",
    );
    let forbidden = [
        concat!(".", "submit("),
        concat!(".", "submit_all("),
        concat!("client.", "status()"),
        concat!("tokio::task::", "block_in_place"),
        concat!("tokio::task::", "spawn_blocking"),
        concat!("Cast", "PlainBallot"),
        concat!("Cast", "ParliamentBallot"),
        concat!("Finalize", "Referendum"),
        concat!("Enact", "Referendum"),
        concat!("Construct", "Certificate"),
        concat!("Parliament", "CertificateV1"),
        concat!("ParliamentAutomatic", "ExecutionOutcomeV1"),
        concat!("Mark", "Enacted"),
        concat!("Mark", "Superseded"),
        concat!("Mark", "ExecutionFailed"),
        concat!("Commit", "ContractDeployment"),
        concat!("without_npos_", "genesis_bootstrap"),
        concat!("with_consensus_", "message_control"),
        concat!("sumeragi.debug", ".rbc"),
        concat!("legacy", "_rbc"),
        concat!("rbc_", "bypass"),
    ];
    for name in forbidden {
        assert!(
            !source.contains(name),
            "modern Parliament corridor must not contain retired or bypass operation `{name}`",
        );
    }
    assert!(source.contains(concat!("with_peers(", "VALIDATOR_COUNT)")));
    assert!(source.contains(concat!("with_npos_", "consensus()")));
    assert!(source.contains(concat!(
        "with_parliament_beacon_",
        "signer_modes(POSITIVE_BEACON_SIGNER_MODES)"
    )));
    assert!(source.contains(concat!(
        "with_parliament_beacon_",
        "signer_modes(FAIL_CLOSED_BEACON_SIGNER_MODES)"
    )));
    assert!(source.contains(concat!("recommended_data_availability_", "layout()")));
    let boundary_helper = concat!("assert_transition_rejected_without_state_", "change(");
    assert_eq!(
        source.matches(boundary_helper).count(),
        12,
        "the helper definition plus eleven exact checkpoint/replay calls must remain",
    );
    assert_eq!(
        source
            .matches(concat!("assert_private_transition_", "rejected("))
            .count(),
        5,
        "the typed private-retry helper and all four boundary cases must remain",
    );
    // The retired mid-epoch slot rule and its Parliament-demanded pulse wait must not return.
    for retired in [
        concat!("request_height", " + 4"),
        concat!(".checked_add(CAPACITY_SORTITION", "_DELAY_BLOCKS)"),
        concat!("retry_request_height", "\n        .checked_add(4)"),
        concat!("demanded sortition ", "threshold-beacon effect"),
    ] {
        assert!(
            !source.contains(retired),
            "Parliament corridor restored the retired sortition slot rule `{retired}`",
        );
    }
    assert_eq!(
        source
            .matches(concat!("expected_sortition_", "slot("))
            .count(),
        6,
        "the helper definition plus five native-slot derivations must remain",
    );
    assert_eq!(
        source
            .matches(concat!("cross_native_boundary_", "after_pulse("))
            .count(),
        5,
        "the helper definition plus four after-boundary consumptions must remain",
    );
    for required in [
        concat!("ConsumeSortition", "PulseBatch"),
        concat!("with_signed_npos_", "epoch("),
        concat!("await_native_sortition_", "pulse("),
        concat!("BASELINE-FAILING ", "ASSERTION"),
        concat!(
            "builder_with_signer_modes(",
            "\n        NetworkBuilder::new()"
        ),
        concat!("RegisterBallot", "Participant"),
        concat!("CloseBallot", "Registration"),
        concat!("FreezeBallot", "Survivors"),
        concat!("FreezeTimedOvn", "Corpus"),
        concat!("FailBallot", "NoResult"),
        concat!("private_ballot_deadline_", "retry_impl"),
        concat!("combine_partial_", "releases"),
        concat!("FinalizeOpened", "Ballot"),
        concat!("GovernanceAttemptStatusV1::", "Enacted"),
        concat!("exercise_public_finding_", "no_result_retries_and_restore"),
        concat!(
            "ParliamentNoResultKindV1::",
            "PublicFindingQuorumUnreachable"
        ),
        concat!("ParliamentNoResultKindV1::", "PublicFindingDeadlineExpired"),
        concat!("attempt_sequence:", " 2"),
        concat!("attempt_sequence:", " 1"),
        concat!(
            "deterministic_parliament_beacon_",
            "successor_key_record_v1"
        ),
        concat!("lifecycle_certificate_", "replacing"),
        concat!("shutdown_if_", "started"),
        concat!("start_", "checked"),
    ] {
        assert!(
            source.contains(required),
            "modern Parliament corridor lost required operation `{required}`",
        );
    }
}

#[path = "sora_parliament_failure_paths.rs"]
mod failure_paths;

#[path = "sora_parliament_no_result_paths.rs"]
mod no_result_paths;
