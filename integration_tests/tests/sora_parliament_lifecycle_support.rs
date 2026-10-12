//! Shared real Parliament corridor, rooted in independently validated native genesis.
//! The publication harness imports these helpers without collecting unrelated beacon scenarios.

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

use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64_STANDARD};
use eyre::{Result, WrapErr as _, eyre};
use integration_tests::sandbox;
use iroha::{
    blocking::Client,
    client::{
        ParliamentTimedOvnCastingContextResponseV1, ParliamentTlePartialReleaseShareV1,
        ParliamentTleReleaseContextResponseV1,
    },
    crypto::{Algorithm, Hash, KeyPair, Signature},
    data_model::{
        account::AccountId,
        block::SignedBlock,
        governance::types::{
            AbiVersion, BallotAttemptId, BallotAttemptStatusV1, BeaconPulseId, BeaconSessionId,
            BodyElectionAttemptId, BodyInstanceId, BodyInstanceStatusV1, ContractAbiHash,
            ContractCodeHash, DeliberationPhaseV1, DeployContractProposal, GovernanceAttemptId,
            GovernanceAttemptStatusV1, GovernanceStageV1, ParliamentAggregateOutcomeV1,
            ParliamentBody, ParliamentNoResultKindV1, ProposalKind, SortitionRequestV1,
            TleSessionId, parliament_ballot_participant_hash_v1, parliament_candidate_root_v1,
        },
        isi::{
            InstructionBox, Log,
            consensus_keys::{
                ApplyThresholdKeyLifecycleCertificateV1, ThresholdKeyLifecycleActionV1,
                ThresholdKeyLifecycleCertificateV1, ThresholdKeyLifecycleSignatureV1,
            },
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
            system::{
                ConsensusHandshakeMetadata, SumeragiConsensusMode, SumeragiNposParameters,
                SumeragiParameter, consensus_metadata,
            },
        },
        permission::Permission,
        prelude::{
            Account, AssetId, FeePaymentIntent, FindAssetById, FindBlocks, Grant,
            Identifiable as _, Level, QueryBuilderExt as _, Register, SetParameter,
        },
        query::dsl::IntoPredicate as _,
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
use iroha_core::state::THRESHOLD_KEY_LIFECYCLE_CERTIFICATE_VERSION_V1;
use iroha_core::state::threshold_key_lifecycle_certificate_preimage_v1;
use iroha_core::state::verify_threshold_key_lifecycle_certificate_v1;
use iroha_core::tle_release::parliament_test_network_signer::deterministic_parliament_tle_key_public_state_v1;
use iroha_core_timed_ovn::casting::PARLIAMENT_TIMED_OVN_CASTING_CONTEXT_ARCHIVE_MAX_BYTES_V1;
use iroha_core_timed_ovn::casting::ParliamentTimedOvnCastingContextArchiveV1;
use iroha_core_timed_ovn::casting::ParliamentTimedOvnCastingPhaseV1;
use iroha_core_timed_ovn::evidence::TimedOvnReleaseIdentityPublicV1;
use iroha_core_timed_ovn::tle::AuthorizedTleReleaseProjectionV1;
use iroha_core_timed_ovn::tle::TLE_AUTHORIZED_RELEASE_IDENTITY_PAYLOAD_BYTES_V1;
use iroha_core_timed_ovn::tle::TLE_AUTHORIZED_RELEASE_PROJECTION_VERSION_V1;
use iroha_core_timed_ovn::tle::TleAdaptiveDealerCommitmentV1;
use iroha_core_timed_ovn::tle::TleAdaptivePublicShareV1;
use iroha_core_timed_ovn::tle::TleKeySessionPublicStateV1;
use iroha_core_timed_ovn::tle::TlePartialReleaseShareV1;
use iroha_crypto::timed_ovn::{TimedOvnChoiceV1, TimedOvnRegistrationSecretV1};
use iroha_data_model::governance::types::PARLIAMENT_TIMED_OVN_BALLOT_RECORD_BYTES_V1 as TIMED_OVN_BALLOT_RECORD_BYTES_V1;
use iroha_executor_data_model::permission::{
    governance::CanProposeContractDeployment, smart_contract::CanManageSmartContractCode,
};
use iroha_model_base::peer::PeerId;
use iroha_test_network::{NetworkBuilder, ParliamentBeaconSignerMode, read_on_dedicated_thread};
use iroha_test_samples::ALICE_ID;
use norito::codec::Encode as _;
use rand::{SeedableRng as _, rngs::StdRng};

pub(super) const VALIDATOR_COUNT: usize = 4;
pub(super) const CITIZEN_COUNT: usize = 24;
pub(super) const BODY_SEATS: u32 = 3;
// An isolated ordinary transaction executes in the next certified global carrier.
pub(super) const EXECUTION_CARRIER_BLOCKS: u64 = 1;
// Keep real FastPQ proving enabled, but prevent four local debug daemons from
// each provisioning a wide Rayon pool on the same host while consensus traffic is live.
pub(super) const PARLIAMENT_NETWORK_RAYON_THREADS_PER_PEER: i64 = 2;
// Six three-seat bodies can draw eighteen distinct invitees. Keep enough native
// execution heights for separately signed responses and the exact roster seal.
pub(super) const INVITATION_PHASE_BLOCKS: u64 = 56;
// The corridor executes three proof-valid registrations and one proof-invalid
// early close before the exact close, each in its own certified carrier.
pub(super) const REGISTRATION_PHASE_BLOCKS: u64 = 15;
pub(super) const SURVIVOR_PHASE_BLOCKS: u64 = 9;
// A replayed survivor freeze and an early corpus freeze each consume one full
// native transaction lifecycle before the exact corpus-freeze authority point.
pub(super) const COMMITMENT_PHASE_BLOCKS: u64 = 9;
// The replayed corpus freeze and wrong-pulse opening must terminate before the
// autonomous release pulse reaches its exact height.
pub(super) const RELEASE_DELAY_BLOCKS: u64 = 7;
pub(super) const OPENING_PHASE_BLOCKS: u64 = 9;
pub(super) const MIN_ENACTMENT_DELAY: u64 = 4;
pub(super) const MANDATORY_NPOS_EPOCH_LENGTH_BLOCKS: u64 = 8;
// One signed NPoS epoch length for every converted sortition corridor. A sortition slot
// is a consensus-native pre-boundary pulse height, so each draw waits for `(h + 1) % L == 0`.
// The corridors submit at exact heights, one carrier per height, and a native pulse height
// finalizes without a carrier. `L` therefore has to exceed the longest exact-height run
// between two draws: the invitation window (40, 56 or 68 blocks), the roster seal, the
// public-finding phases with their 8 or 20 block deadline, and two private registration
// windows of 12 blocks with their failure and restore heights. 128 covers each of those
// runs with margin while the first slot (height 127) stays reachable by plain carriers.
pub(super) const CORRIDOR_NPOS_EPOCH_LENGTH_BLOCKS: u64 = 128;
// Unrelated carriers committed past the retired `request_height + delay` slot by the
// isolation corridor; the first one lands on the height the retired rule stalled.
pub(super) const ISOLATION_CARRIERS_PAST_RETIRED_SLOT: u64 = 12;
// Further carriers committed after the restarted validator has rejoined.
pub(super) const ISOLATION_CARRIERS_AFTER_RESTART: u64 = 3;
// Exact-roster certificates bind their containing height. Leave time to sign
// and submit against the immediately preceding certified State.
pub(super) const EXACT_HEIGHT_SUBMISSION_CADENCE: Duration = Duration::from_secs(5);
pub(super) const PARLIAMENT_NETWORK_STACK_BYTES: usize = 32 * 1024 * 1024;
pub(super) const TEST_NEXUS_LOCAL_STORAGE_BUDGET_BYTES: i64 = 1_073_741_824;
pub(super) const FAIL_CLOSED_BEACON_OBSERVATION_WINDOW: Duration = Duration::from_secs(8);
pub(super) const POSITIVE_BEACON_SIGNER_MODES: [ParliamentBeaconSignerMode; VALIDATOR_COUNT] = [
    ParliamentBeaconSignerMode::Valid,
    ParliamentBeaconSignerMode::Valid,
    ParliamentBeaconSignerMode::Absent,
    ParliamentBeaconSignerMode::Invalid,
];
pub(super) const FAIL_CLOSED_BEACON_SIGNER_MODES: [ParliamentBeaconSignerMode; VALIDATOR_COUNT] = [
    ParliamentBeaconSignerMode::Valid,
    ParliamentBeaconSignerMode::Absent,
    ParliamentBeaconSignerMode::Absent,
    ParliamentBeaconSignerMode::Invalid,
];
pub(super) const CONTRACT_ADDRESS: &str =
    "irohac1qyqqqqqqqqqqqq95fes93ygegsv5enq9mqsz6x4lv4vp9gg4yxgjw";
pub(super) const NO_RESULT_RETRY_CONTRACT_ADDRESS: &str =
    "irohac1qyqqqqqqqqqqqqputuv64zhf0a0a4hhlqdj2lhnwuzq4xjq3qexfh";

#[path = "support/parliament_submission.rs"]
mod submission;
pub(super) use submission::{
    OPERATION_TIMEOUT, admit_parliament_height_carrier, fee, minimal_contract_artifact,
    minimal_contract_artifact_with_identity, prepare_parliament_transaction,
    stage_contract_artifact, submit_parliament_instructions,
};

pub(super) fn citizen_keys() -> Vec<KeyPair> {
    (0..CITIZEN_COUNT)
        .map(|index| {
            KeyPair::try_from_seed(
                format!("sora-parliament-modern-citizen-{index:02}").into_bytes(),
                Algorithm::Ed25519,
            )
            .expect("derive deterministic citizen key")
        })
        .collect()
}

pub(super) fn citizen_accounts(keys: &[KeyPair]) -> Vec<AccountId> {
    let mut accounts = keys
        .iter()
        .map(|key| AccountId::new(key.public_key().clone()))
        .collect::<Vec<_>>();
    accounts.sort_unstable();
    accounts
}

pub(super) fn client_for(base: &Client, account: &AccountId, keys: &[KeyPair]) -> Client {
    let key = keys
        .iter()
        .find(|key| {
            account
                .try_signatory()
                .is_some_and(|signatory| key.public_key() == signatory)
        })
        .expect("selected citizen owns one deterministic key")
        .clone();
    integration_tests::sync::rebind_blocking_client(base, |builder| {
        builder.account = account.clone();
        builder.key_pair = key;
    })
}

const STATUS_RETRY_DELAY: Duration = Duration::from_millis(150);
const STATUS_RETRY_WINDOW: Duration = Duration::from_secs(30);

/// Classify the two typed transient status refusals; every other error is final.
///
/// Same policy as `support/committee_status.rs`: only the SDK's typed `StateBusy` and
/// `DeadlineElapsed` reasons are retry authority, and never past the remaining window.
fn status_retry_delay(error: &iroha::Error, remaining: Duration) -> Option<Duration> {
    let iroha::Error::StatusUnavailable {
        reason:
            Some(iroha::StatusFailureReason::DeadlineElapsed | iroha::StatusFailureReason::StateBusy),
        retry_after,
    } = error
    else {
        return None;
    };
    let delay = retry_after
        .unwrap_or(STATUS_RETRY_DELAY)
        .max(STATUS_RETRY_DELAY);
    (delay < remaining).then_some(delay)
}

/// Read the finalized height from the status projection.
///
/// A status read that lost the State publication race answers HTTP 503 `status_state_busy`
/// without publishing a snapshot. That is a property of the read, not of the chain, so it is
/// retried inside one bounded window; any other failure is returned unchanged.
pub(super) async fn current_height(client: &Client) -> Result<u64> {
    let deadline = Instant::now() + STATUS_RETRY_WINDOW;
    loop {
        match client.client().status().get().await {
            Ok(status) => return Ok(status.blocks),
            Err(error) => {
                let Some(delay) =
                    status_retry_delay(&error, deadline.saturating_duration_since(Instant::now()))
                else {
                    return Err(error.into());
                };
                tokio::time::sleep(delay).await;
            }
        }
    }
}

#[test]
fn status_retry_accepts_only_typed_busy_or_deadline_inside_the_window() {
    use iroha::StatusFailureReason;
    let window = Duration::from_secs(1);
    for reason in [
        StatusFailureReason::StateBusy,
        StatusFailureReason::DeadlineElapsed,
    ] {
        let error = iroha::Error::StatusUnavailable {
            reason: Some(reason),
            retry_after: None,
        };
        assert_eq!(status_retry_delay(&error, window), Some(STATUS_RETRY_DELAY));
        assert_eq!(status_retry_delay(&error, STATUS_RETRY_DELAY), None);
        let advised = iroha::Error::StatusUnavailable {
            reason: Some(reason),
            retry_after: Some(Duration::from_millis(400)),
        };
        assert_eq!(
            status_retry_delay(&advised, window),
            Some(Duration::from_millis(400))
        );
    }
    for reason in [
        None,
        Some(StatusFailureReason::StateUnavailable),
        Some(StatusFailureReason::MissingBlock),
        Some(StatusFailureReason::MetricsStale),
    ] {
        let error = iroha::Error::StatusUnavailable {
            reason,
            retry_after: None,
        };
        assert_eq!(status_retry_delay(&error, window), None);
    }
}

pub(super) async fn tick(client: &Client, label: impl Into<String>) -> Result<u64> {
    submit_parliament_instructions(&client, [Log::new(Level::INFO, label.into())]).await?;
    current_height(client).await
}

pub(super) async fn next_execution_height(
    client: &Client,
    minimum_height: u64,
    label: &str,
) -> Result<u64> {
    loop {
        let authority_height = current_height(client).await?;
        let execution_height = authority_height
            .checked_add(EXECUTION_CARRIER_BLOCKS)
            .ok_or_else(|| eyre!("{label}: native transaction execution height overflow"))?;
        if execution_height >= minimum_height {
            return Ok(execution_height);
        }
        tick(
            client,
            format!("{label} authority-height tick {}", authority_height + 1),
        )
        .await?;
    }
}

pub(super) async fn advance_to_height_with_carriers(
    network: &iroha_test_network::Network,
    client: &Client,
    target_height: u64,
    label: &str,
) -> Result<()> {
    loop {
        let height = current_height(client).await?;
        if height == target_height {
            return Ok(());
        }
        if height > target_height {
            return Err(eyre!(
                "{label}: exact height {target_height} passed at finalized height {height}"
            ));
        }
        let carrier_height = height
            .checked_add(1)
            .ok_or_else(|| eyre!("{label}: native transaction carrier height overflow"))?;
        admit_parliament_height_carrier(
            &client,
            [Log::new(
                Level::INFO,
                format!("{label} admission carrier {carrier_height}"),
            )],
        )
        .await?;
        network.ensure_blocks(carrier_height).await?;
        observe_exact_height(client, carrier_height, label).await?;
    }
}

/// Read one validator's Sumeragi status together with its published native beacon horizon.
///
/// The status omits the horizon while its same-cut observation is being refreshed, so an
/// assertion guarded by `if let Some(..)` could pass without running. This read waits a bounded
/// time for the horizon and fails when the validator never publishes it.
pub(super) async fn require_beacon_horizon(
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

/// Observe one exact finalized height through the client's status projection.
///
/// `ensure_blocks` can return from durable block storage before the status projection
/// publishes the same height. The projection may therefore trail by a bounded interval,
/// but it must never pass the expected height.
pub(super) async fn observe_exact_height(
    client: &Client,
    expected_height: u64,
    label: &str,
) -> Result<()> {
    let deadline = Instant::now() + OPERATION_TIMEOUT;
    loop {
        let observed_height = current_height(client).await?;
        if observed_height == expected_height {
            return Ok(());
        }
        if observed_height > expected_height {
            return Err(eyre!(
                "{label}: expected exact height {expected_height}, observed {observed_height}"
            ));
        }
        if Instant::now() >= deadline {
            return Err(eyre!(
                "{label}: status stayed at height {observed_height} below committed height {expected_height} for {OPERATION_TIMEOUT:?}"
            ));
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

pub(super) async fn advance_to_execution_predecessor(
    network: &iroha_test_network::Network,
    client: &Client,
    execution_height: u64,
    label: &str,
) -> Result<()> {
    let authority_height = execution_height
        .checked_sub(EXECUTION_CARRIER_BLOCKS)
        .ok_or_else(|| {
            eyre!(
                "{label}: native transaction execution height {execution_height} has no H - {EXECUTION_CARRIER_BLOCKS} authority"
            )
        })?;
    advance_to_height_with_carriers(network, client, authority_height, label).await
}

pub(super) async fn advance_to_autonomous_predecessor(
    network: &iroha_test_network::Network,
    client: &Client,
    target_height: u64,
    label: &str,
) -> Result<()> {
    let predecessor_height = target_height.checked_sub(1).ok_or_else(|| {
        eyre!("{label}: autonomous target height {target_height} has no predecessor")
    })?;
    advance_to_height_with_carriers(network, client, predecessor_height, label).await
}

pub(super) async fn submit_transition(
    client: &Client,
    attempt_id: GovernanceAttemptId,
    transition: ParliamentLifecycleTransitionV1,
) -> Result<u64> {
    submit_parliament_instructions(
        &client,
        [SubmitParliamentLifecycleTransitionV1 {
            governance_attempt_id: attempt_id,
            transition,
        }],
    )
    .await?;
    current_height(client).await
}

pub(super) async fn submit_transitions(
    client: &Client,
    attempt_id: GovernanceAttemptId,
    transitions: impl IntoIterator<Item = ParliamentLifecycleTransitionV1>,
) -> Result<u64> {
    submit_parliament_instructions(
        &client,
        transitions.into_iter().map(|transition| {
            InstructionBox::from(SubmitParliamentLifecycleTransitionV1 {
                governance_attempt_id: attempt_id,
                transition,
            })
        }),
    )
    .await?;
    current_height(client).await
}

pub(super) async fn assert_transition_rejected_without_state_change(
    client: &Client,
    attempt_id: GovernanceAttemptId,
    transition: ParliamentLifecycleTransitionV1,
    label: &str,
) -> Result<()> {
    let before = read_on_dedicated_thread({
        let client = client.client().clone();
        let attempt_id = (attempt_id).clone();
        move || client.get_parliament_attempt(attempt_id)
    })
    .await?
    .state_payload_hex;
    if submit_parliament_instructions(
        &client,
        [SubmitParliamentLifecycleTransitionV1 {
            governance_attempt_id: attempt_id,
            transition,
        }],
    )
    .await
    .is_ok()
    {
        return Err(eyre!("{label}: invalid Parliament transition was accepted"));
    }
    let after = read_on_dedicated_thread({
        let client = client.client().clone();
        let attempt_id = (attempt_id).clone();
        move || client.get_parliament_attempt(attempt_id)
    })
    .await?
    .state_payload_hex;
    if after != before {
        return Err(eyre!(
            "{label}: rejected Parliament transition mutated reducer state"
        ));
    }
    Ok(())
}

pub(super) async fn assert_governed_contract_absent(
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

pub(super) async fn assert_governed_contract_binding(
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

pub(super) async fn assert_asset_not_found(
    client: &Client,
    asset_id: &AssetId,
    label: &str,
) -> Result<()> {
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

pub(super) async fn assert_timed_ovn_casting_context_not_castable(
    client: &Client,
    ballot_attempt_id: BallotAttemptId,
    label: &str,
) -> Result<()> {
    let error = read_on_dedicated_thread({
        let client = client.client().clone();
        let ballot_attempt_id = (ballot_attempt_id).clone();
        move || client.get_parliament_timed_ovn_casting_context(ballot_attempt_id)
    })
    .await
    .expect_err("a sealed timed-OVN corpus must not return a casting context");
    let rendered = format!("{error:#}");
    const PHASE_NOT_CASTABLE: &str = "Parliament timed-OVN casting context is not authorized: \
        timed-OVN lifecycle is no longer in a casting phase";
    if !rendered.contains("400 Bad Request") || !rendered.contains(PHASE_NOT_CASTABLE) {
        return Err(eyre!(
            "{label}: expected the exact sealed-corpus casting-context rejection, got {rendered}"
        ));
    }
    Ok(())
}

pub(super) async fn read_attempt(
    client: &Client,
    attempt_id: GovernanceAttemptId,
) -> Result<ParliamentAttemptStateV1> {
    let response = read_on_dedicated_thread({
        let client = client.client().clone();
        let attempt_id = (attempt_id).clone();
        move || client.get_parliament_attempt(attempt_id)
    })
    .await?;
    let frame = hex::decode(response.state_payload_hex)?;
    norito::decode_canonical(&frame).wrap_err("decode canonical Parliament reducer projection")
}

pub(super) async fn ordered_validator_roster(
    network: &iroha_test_network::Network,
    client: &Client,
) -> Result<Vec<PeerId>> {
    let height = current_height(client).await?;
    let (proof, verified) = finality::certified_block(network, client, height).await?;
    assert_eq!(verified.height(), height);
    let roster = proof
        .committee
        .into_iter()
        .map(|validator| PeerId::new(validator.public_key))
        .collect::<Vec<_>>();
    eprintln!(
        "SORA_PARLIAMENT_LIFECYCLE frozen_roster authority_height={height} roster_hash={}",
        hex::encode(global_threshold_beacon_roster_hash_v1(&roster)),
    );
    Ok(roster)
}

pub(super) fn lifecycle_certificate(
    network: &iroha_test_network::Network,
    ordered_roster: &[PeerId],
    action: ThresholdKeyLifecycleActionV1,
    session_id: [u8; 32],
    transcript_hash: [u8; 32],
    public_state: Vec<u8>,
    effective_height: u64,
) -> Result<ApplyThresholdKeyLifecycleCertificateV1> {
    lifecycle_certificate_replacing(
        network,
        ordered_roster,
        action,
        None,
        session_id,
        transcript_hash,
        public_state,
        effective_height,
    )
}

pub(super) fn lifecycle_certificate_replacing(
    network: &iroha_test_network::Network,
    ordered_roster: &[PeerId],
    action: ThresholdKeyLifecycleActionV1,
    expected_active_session_id: Option<[u8; 32]>,
    session_id: [u8; 32],
    transcript_hash: [u8; 32],
    public_state: Vec<u8>,
    effective_height: u64,
) -> Result<ApplyThresholdKeyLifecycleCertificateV1> {
    let mut certificate = ThresholdKeyLifecycleCertificateV1 {
        version: THRESHOLD_KEY_LIFECYCLE_CERTIFICATE_VERSION_V1,
        action,
        expected_active_session_id,
        effective_height,
        network_id: network.network_id(),
        roster_hash: global_threshold_beacon_roster_hash_v1(ordered_roster),
        committee_size: VALIDATOR_COUNT as u16,
        quorum: 3,
        session_id,
        transcript_hash,
        public_state,
        signatures: Vec::new(),
    };
    let preimage = threshold_key_lifecycle_certificate_preimage_v1(&certificate)
        .wrap_err("encode lifecycle QC preimage")?;
    certificate.signatures = ordered_roster
        .iter()
        .take(3)
        .enumerate()
        .map(|(index, peer_id)| {
            let peer = network
                .peers()
                .iter()
                .find(|peer| peer.id() == *peer_id)
                .ok_or_else(|| eyre!("signed roster peer is absent from the network"))?;
            let key = peer
                .bls_key_pair()
                .ok_or_else(|| eyre!("validator lacks its normal BLS keypair"))?;
            Ok(ThresholdKeyLifecycleSignatureV1 {
                signer_index: u16::try_from(index)?,
                signature: Signature::try_new(key.private_key(), &preimage)?,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    verify_threshold_key_lifecycle_certificate_v1(
        &certificate,
        &network.network_id(),
        effective_height,
        ordered_roster,
    )
    .wrap_err("independently verify the exact lifecycle certificate before submission")?;
    Ok(ApplyThresholdKeyLifecycleCertificateV1 { certificate })
}

pub(super) async fn pulse_at(
    client: &Client,
    height: u64,
    network: &iroha_test_network::Network,
) -> Result<iroha::data_model::consensus::FinalizedGlobalThresholdBeaconPulseV1> {
    exact_block(client, height, &network)
        .await?
        .global_beacon_pulse()
        .cloned()
        .ok_or_else(|| eyre!("block {height} does not carry a finalized global beacon pulse"))
}

pub(super) fn signed_consensus_handshake(
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

pub(super) fn casting_archive(
    response: &ParliamentTimedOvnCastingContextResponseV1,
    ballot_attempt_id: BallotAttemptId,
) -> Result<ParliamentTimedOvnCastingContextArchiveV1> {
    response
        .validate_for_ballot(ballot_attempt_id)
        .map_err(|error| eyre!(error))?;
    let bytes = BASE64_STANDARD
        .decode(response.archive_norito_base64.as_bytes())
        .wrap_err("decode padded canonical casting archive")?;
    if bytes.len() > PARLIAMENT_TIMED_OVN_CASTING_CONTEXT_ARCHIVE_MAX_BYTES_V1 {
        return Err(eyre!("casting archive exceeds its fixed V1 bound"));
    }
    let archive = norito::decode_canonical::<ParliamentTimedOvnCastingContextArchiveV1>(&bytes)
        .wrap_err("decode canonical casting-context Norito frame")?;
    archive
        .validate_v1()
        .wrap_err("replay-validate public casting archive")?;
    Ok(archive)
}

pub(super) fn release_projection(
    context: &ParliamentTleReleaseContextResponseV1,
) -> Result<AuthorizedTleReleaseProjectionV1> {
    context
        .validate_for_ballot(context.ballot_attempt_id)
        .map_err(|error| eyre!(error))?;
    let identity_payload: [u8; TLE_AUTHORIZED_RELEASE_IDENTITY_PAYLOAD_BYTES_V1] =
        hex::decode(&context.identity_payload_hex)
            .wrap_err("decode exact release identity payload")?
            .try_into()
            .map_err(|_| eyre!("release identity payload has the wrong width"))?;
    let key_session = &context.tle_key_session;
    Ok(AuthorizedTleReleaseProjectionV1 {
        version: TLE_AUTHORIZED_RELEASE_PROJECTION_VERSION_V1,
        ballot_attempt_id: context.ballot_attempt_id,
        opening_deadline_height: context.opening_deadline_height,
        finalized_height: context.current_height,
        key_session: TleKeySessionPublicStateV1 {
            version: key_session.version,
            key_session_id: key_session.key_session_id,
            network_id: key_session.network_id,
            roster_hash: key_session.roster_hash,
            committee_size: key_session.committee_size,
            threshold: key_session.threshold,
            generator_h: key_session.generator_h,
            generator_v: key_session.generator_v,
            qualified_dealers: key_session.qualified_dealers.clone(),
            qualified_dealer_commitments: key_session
                .qualified_dealer_commitments
                .iter()
                .map(|dealer| TleAdaptiveDealerCommitmentV1 {
                    dealer_index: dealer.dealer_index,
                    coefficient_commitments: dealer.coefficient_commitments.clone(),
                    constant_pok_commitment: dealer.constant_pok_commitment,
                    constant_pok_response: dealer.constant_pok_response,
                })
                .collect(),
            dkg_event_hash: key_session.dkg_event_hash,
            group_public_key: key_session.group_public_key,
            public_shares: key_session
                .public_shares
                .iter()
                .map(|share| TleAdaptivePublicShareV1 {
                    index: share.index,
                    participant_hash: share.participant_hash,
                    public_key_share: share.public_key_share,
                })
                .collect(),
            transcript_hash: key_session.transcript_hash,
        },
        public_release_identity: TimedOvnReleaseIdentityPublicV1 {
            tle_key_session_id: context.release_identity.tle_key_session_id,
            governance_attempt_id: *context.release_identity.governance_attempt_id.as_bytes(),
            body_instance_id: *context.release_identity.body_instance_id.as_bytes(),
            ballot_attempt_id: *context.release_identity.ballot_attempt_id.as_bytes(),
            survivor_corpus_root: context.release_identity.survivor_corpus_root,
            no_recovery_root: context.release_identity.no_recovery_root,
            target_finalized_height: context.release_identity.target_finalized_height,
            parameter_hash: context.release_identity.parameter_hash,
        },
        identity_payload,
        identity_digest: context.identity_digest,
    })
}

pub(super) fn release_partial(
    partial: ParliamentTlePartialReleaseShareV1,
) -> TlePartialReleaseShareV1 {
    TlePartialReleaseShareV1 {
        key_session_id: partial.key_session_id,
        identity_digest: partial.identity_digest,
        participant_index: partial.participant_index,
        sigma: partial.sigma,
        proof_x: partial.proof_x,
        proof_y: partial.proof_y,
        z_s: partial.z_s,
        z_r: partial.z_r,
        z_u: partial.z_u,
    }
}

pub(super) fn public_finding_root(
    attempt_id: GovernanceAttemptId,
    body: ParliamentBody,
) -> [u8; 32] {
    let body = body.encode();
    Hash::new_from_chunks(&[
        b"iroha.integration.parliament.public-finding.v1\0",
        attempt_id.as_bytes(),
        &body,
    ])
    .into()
}

pub(super) async fn exact_block(
    client: &Client,
    height: u64,
    network: &iroha_test_network::Network,
) -> Result<SignedBlock> {
    let requested_height =
        NonZeroU64::new(height).ok_or_else(|| eyre!("finalized block height must be nonzero"))?;
    let root_scope = iroha_genesis::signed_genesis_consensus_metadata(&network.genesis().0)?
        .sumeragi_context
        .root_scope;
    // Signed queries no longer admit an unbounded `FindBlocks` listing. The finality-proof
    // route returns exactly one finalized block for exactly one requested height.
    let proof = read_on_dedicated_thread({
        let client = client.client().clone();
        move || {
            client
                .get_sumeragi_finality_proof(requested_height, root_scope)
                .map_err(|error| eyre!("read finalized block for exact height {height}: {error}"))
        }
    })
    .await?;
    let block = iroha::data_model::block::decode_framed_signed_block(&proof.block_wire)
        .map_err(|error| eyre!("decode finalized block at exact height {height}: {error:?}"))?;
    if block.header().height() != requested_height {
        return Err(eyre!(
            "finality proof returned height {} for exact request {height}",
            block.header().height()
        ));
    }
    if block.header() != proof.block_header {
        return Err(eyre!(
            "finality proof header differs from its finalized block at height {height}"
        ));
    }
    Ok(block)
}

pub(super) async fn assert_no_global_beacon_pulse_at(
    client: &Client,
    height: u64,
    label: &str,
    network: &iroha_test_network::Network,
) -> Result<()> {
    let block = exact_block(client, height, &network)
        .await
        .wrap_err_with(|| format!("{label}: exact finalized block is unavailable"))?;
    if block.global_beacon_pulse().is_some() {
        return Err(eyre!(
            "{label}: finalized block {height} unexpectedly carries a global beacon pulse"
        ));
    }
    Ok(())
}

/// Sign one explicit NPoS snapshot whose epoch length is `epoch_length_blocks`.
/// This is the genesis recipe of the mandatory-beacon corridors, for any epoch length.
pub(super) fn with_signed_npos_epoch(
    builder: NetworkBuilder,
    epoch_length_blocks: u64,
) -> NetworkBuilder {
    let mut npos = SumeragiNposParameters::default();
    npos.epoch_length_blocks =
        NonZeroU64::new(epoch_length_blocks).expect("corridor NPoS epoch length is non-zero");
    npos.evidence_horizon_blocks = epoch_length_blocks * 2;
    npos.slashing_delay_blocks = epoch_length_blocks;
    npos.validate()
        .expect("corridor NPoS epoch fixture must be valid");
    // Genesis rejects an NPoS snapshot whose epoch length differs from the signed
    // Sumeragi schedule, so both parameters carry the same length.
    builder
        .with_genesis_instruction(SetParameter::new(Parameter::Sumeragi(
            SumeragiParameter::EpochLengthBlocks(npos.epoch_length_blocks),
        )))
        .with_genesis_instruction(SetParameter::new(Parameter::Custom(
            npos.into_custom_parameter(),
        )))
}

/// Read the NPoS epoch length from independently authenticated finality at the current tip.
/// The claimed status and local configuration never select this value.
pub(super) async fn certified_npos_epoch_length(
    network: &iroha_test_network::Network,
    client: &Client,
) -> Result<u64> {
    let height = current_height(client).await?;
    let (_, verified) = finality::certified_block(network, client, height).await?;
    let authorization = &verified.commitment().schedule.current.authorization;
    let epochs = authorization
        .epoch
        .checked_add(1)
        .ok_or_else(|| eyre!("certified NPoS epoch index overflow"))?;
    let epoch_length_blocks = authorization.last_height / epochs;
    if epoch_length_blocks < 3
        || authorization.last_height % epochs != 0
        || (height - 1) / epoch_length_blocks != authorization.epoch
    {
        return Err(eyre!(
            "certified NPoS authorization at height {height} does not expose a uniform epoch length"
        ));
    }
    Ok(epoch_length_blocks)
}

/// First consensus-native pulse height at or after `earliest`: `(h + 1) % L == 0`.
pub(super) fn aligned_native_pulse_height(earliest: u64, epoch_length_blocks: u64) -> Result<u64> {
    if earliest == 0 || epoch_length_blocks < 3 {
        return Err(eyre!(
            "native pulse alignment needs a height and an NPoS epoch"
        ));
    }
    earliest
        .checked_add(epoch_length_blocks - 1 - earliest % epoch_length_blocks)
        .filter(|height| height.checked_add(1).is_some())
        .ok_or_else(|| eyre!("native pulse height overflow"))
}

/// Slot of a sortition generation registered at `request_height`: the first native pulse
/// height at or after `max(request_height + delay, previous generation slot + 1)`.
/// The epoch length comes from certified finality and must equal the attempt's frozen one.
pub(super) async fn expected_sortition_slot(
    network: &iroha_test_network::Network,
    client: &Client,
    attempt_id: GovernanceAttemptId,
    request_height: u64,
    previous_generation_slot: Option<u64>,
) -> Result<u64> {
    let attempt = read_attempt(client, attempt_id).await?;
    let epoch_length_blocks = certified_npos_epoch_length(network, client).await?;
    if attempt.sortition_pulse_epoch_length_blocks() != epoch_length_blocks {
        return Err(eyre!(
            "attempt froze epoch length {} but certified finality schedules {epoch_length_blocks}",
            attempt.sortition_pulse_epoch_length_blocks()
        ));
    }
    let delayed = request_height
        .checked_add(attempt.sortition_pulse_delay_blocks())
        .ok_or_else(|| eyre!("sortition delay height overflow"))?;
    let earliest = match previous_generation_slot {
        Some(previous) => delayed.max(
            previous
                .checked_add(1)
                .ok_or_else(|| eyre!("sortition generation slot overflow"))?,
        ),
        None => delayed,
    };
    let slot = aligned_native_pulse_height(earliest, epoch_length_blocks)?;
    eprintln!(
        "SORA_PARLIAMENT_LIFECYCLE sortition_slot request_height={request_height} earliest={earliest} epoch_length={epoch_length_blocks} slot={slot}",
    );
    Ok(slot)
}

/// Governance-local wait: carry the chain to the slot's predecessor, then observe the
/// consensus-native pre-boundary pulse that every validator finalized at the slot.
pub(super) async fn await_native_sortition_pulse(
    network: &iroha_test_network::Network,
    client: &Client,
    slot: u64,
    label: &str,
) -> Result<iroha::data_model::consensus::FinalizedGlobalThresholdBeaconPulseV1> {
    advance_to_autonomous_predecessor(network, client, slot, label).await?;
    network.ensure_blocks(slot).await?;
    // The native pre-boundary pulse must finalize exactly the slot height.
    observe_exact_height(client, slot, label).await?;
    let mut pulses = Vec::with_capacity(network.peers().len());
    for peer in network.peers() {
        pulses.push(pulse_at(&peer.client(), slot, &network).await?);
    }
    if !pulses.windows(2).all(|pair| pair[0] == pair[1]) {
        return Err(eyre!(
            "{label}: validators disagree on the native slot pulse"
        ));
    }
    let pulse = pulses.swap_remove(0);
    if pulse.height != slot || pulse.network_id != network.network_id() {
        return Err(eyre!("{label}: slot {slot} carries a foreign beacon pulse"));
    }
    Ok(pulse)
}

/// Cross the epoch boundary behind a slot pulse and prove from certified finality that the
/// same pulse scheduled the successor epoch. Consumption therefore happens after the boundary.
pub(super) async fn cross_native_boundary_after_pulse(
    network: &iroha_test_network::Network,
    client: &Client,
    pulse: &iroha::data_model::consensus::FinalizedGlobalThresholdBeaconPulseV1,
    label: &str,
) -> Result<u64> {
    let epoch_length_blocks = certified_npos_epoch_length(network, client).await?;
    let boundary_height = pulse
        .height
        .checked_add(1)
        .ok_or_else(|| eyre!("{label}: boundary height overflow"))?;
    if boundary_height % epoch_length_blocks != 0 {
        return Err(eyre!(
            "{label}: sortition slot {} is not a native pre-boundary pulse height",
            pulse.height
        ));
    }
    admit_parliament_height_carrier(
        client,
        [Log::new(
            Level::INFO,
            format!("{label} boundary carrier {boundary_height}"),
        )],
    )
    .await?;
    network.ensure_blocks(boundary_height).await?;
    let successor_height = boundary_height
        .checked_add(1)
        .ok_or_else(|| eyre!("{label}: successor height overflow"))?;
    network.ensure_blocks(successor_height).await?;
    observe_exact_height(client, successor_height, label).await?;
    let successor_epoch = boundary_height / epoch_length_blocks;
    let (_, verified) = finality::certified_block(network, client, successor_height).await?;
    let context = &verified.commitment().schedule.current;
    if context.authorization.epoch != successor_epoch
        || context.authorization.last_height != boundary_height + epoch_length_blocks
        || context.leader_seed
            != global_threshold_beacon_npos_successor_seed_v1(
                pulse,
                boundary_height,
                successor_epoch,
            )
    {
        return Err(eyre!(
            "{label}: the slot pulse is not the consensus-native boundary pulse of epoch {successor_epoch}"
        ));
    }
    Ok(successor_height)
}

#[path = "sora_parliament_finality.rs"]
pub(super) mod finality;

#[path = "sora_parliament_enactment.rs"]
pub(super) mod enactment;

/// Prepare the actual seven-body provider governance corridor with independent threshold signers.
/// The caller must provision four validators and provider genesis inputs before network startup.
pub(crate) fn publication_parliament_builder(builder: NetworkBuilder) -> NetworkBuilder {
    enactment::builder(builder).with_config_layer(|layer| {
        layer
            .write(["gov", "coordination_council_size"], BODY_SEATS as i64)
            .write(["gov", "parliament_invitation_phase_blocks"], 68_i64);
    })
}

/// Execute a provider proposal through genuine citizen sortition, findings, timed OVN and enactment.
/// The return coordinates are observed only after all four peers agree on the enacted attempt.
pub(crate) async fn enact_publication_proposal(
    network: &iroha_test_network::Network,
    proposal: ProposalKind,
) -> Result<(GovernanceAttemptId, u64)> {
    let ProposalKind::SorafsProviderGovernance(provider) = &proposal else {
        return Err(eyre!(
            "publication corridor requires a provider governance proposal"
        ));
    };
    let preliminary = iroha_data_model::isi::governance::ProposeSorafsProviderGovernance {
        action: (*provider.action).clone(),
    };
    let keys = citizen_keys();
    let account = citizen_accounts(&keys).remove(0);
    let proposer = client_for(&network.client(), &account, &keys);
    let enacted =
        enactment::enact(network, proposal, vec![preliminary.into()], Some(proposer)).await?;
    let first = exact_block(&network.client(), enacted.height, &network).await?;
    for peer in network.peers() {
        let client = peer.client();
        let block = exact_block(&client, enacted.height, &network).await?;
        assert_eq!(block.hash(), first.hash());
        let attempt = read_attempt(&client, enacted.attempt_id).await?;
        assert_eq!(attempt.attempt().status, GovernanceAttemptStatusV1::Enacted);
        assert_eq!(attempt.terminal_height(), Some(enacted.height));
        let (_, verified) = finality::certified_block(network, &client, enacted.height).await?;
        assert_eq!(verified.block().hash(), block.hash());
        assert_eq!(
            verified.canonical_executed_wire()?,
            block.clone().with_commit_certificate(None).encode_wire()?,
            "per-peer enacted execution differs from its authenticated native decision",
        );
    }
    Ok((enacted.attempt_id, enacted.height))
}
