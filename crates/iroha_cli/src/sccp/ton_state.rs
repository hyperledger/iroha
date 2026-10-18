//! Native-finality-bound locked minter projections for journal effect evidence.

use super::*;
use eyre::ensure;
use iroha::data_model::sccp::deployment::{SccpCommitteePinV1, SccpDeploymentV1};
use iroha_sccp::{
    TonBlockIdExtV1,
    light_client::ton::{
        TonMasterchainAnchorV1,
        wallet_state::{TonAccountStateProofV1, TonMinterStateV1, verify_minter_state},
    },
};
use iroha_sccp_rpc::ton::LiteClient;
use iroha_sccp_wallet::{journal::SccpEvidenceItemV1, pure::ton::RecoveryRowV1};

type Evidence = Vec<SccpEvidenceItemV1>;

struct Projection {
    state: TonMinterStateV1,
    cut: RecoveryCut,
    evidence: Evidence,
}

/// Exact authenticated source blocks of the original recovery observation.
#[derive(
    Clone,
    Copy,
    Debug,
    PartialEq,
    Eq,
    norito::derive::JsonSerialize,
    norito::derive::JsonDeserialize,
)]
#[norito(deny_unknown_fields)]
pub(super) struct RecoveryCut {
    masterchain: TonBlockIdExtV1,
    shard: TonBlockIdExtV1,
}

/// Extract only after the account proof has passed native finality verification.
pub(super) fn authenticated_cut(proof: &TonAccountStateProofV1) -> RecoveryCut {
    RecoveryCut {
        masterchain: match &proof.masterchain {
            TonMasterchainAnchorV1::Signed(block) => block.block_id,
            // The fresh signer authenticates an older target; it is not the account's cut.
            TonMasterchainAnchorV1::BackLink(link) => link.block_id,
        },
        shard: proof.shard.block_id,
    }
}

fn one_evidence<'a>(items: &'a [SccpEvidenceItemV1], label: &str) -> Result<&'a [u8]> {
    let mut matching = items.iter().filter(|item| item.label == label);
    let value = matching
        .next()
        .ok_or_else(|| eyre!("original recovery lacks {label}"))?;
    ensure!(
        matching.next().is_none(),
        "original recovery has duplicate {label}"
    );
    Ok(&value.bytes)
}

/// Reopen the original cut, refusing missing custody or a cut detached from its retained proof.
pub(super) fn recovery_baseline(items: &[SccpEvidenceItemV1]) -> Result<RecoveryCut> {
    let cut = norito::json::from_slice(one_evidence(items, "ton.original_minter.cut")?)?;
    let proof: TonAccountStateProofV1 =
        norito::json::from_slice(one_evidence(items, "ton.original_minter.account_proof")?)?;
    ensure!(
        cut == authenticated_cut(&proof),
        "original recovery cut differs from its retained proof"
    );
    Ok(cut)
}

fn identity(
    state: &TonMinterStateV1,
    network: [u8; 32],
    instance: [u8; 32],
    revision: u32,
) -> Result<()> {
    ensure!(
        state.network == network && state.instance == instance && state.revision == revision,
        "authenticated minter identity differs from the original route"
    );
    Ok(())
}

fn observe(
    client: &BlockingClient,
    original: &origin::AuthenticatedOrigin,
    lite: &LiteClient,
    minter: [u8; 32],
    revision: u32,
) -> Result<Option<Projection>> {
    #[derive(norito::derive::JsonSerialize)]
    struct Locator {
        account: [u8; 32],
        revision: u32,
        verification_time_ms: u64,
    }
    let Some(source) = ton::account_state_evidence(client, original, lite, minter)? else {
        return Ok(None);
    };
    let state = verify_minter_state(
        &source.profiles.ton,
        source.replay.state(),
        &source.proof,
        minter,
        source.now,
    )?;
    identity(&state, original.network, original.instance, revision)?;
    let cut = authenticated_cut(&source.proof);
    let evidence = vec![
        flows::evidence(
            "ton.original_minter.locator",
            &Locator {
                account: minter,
                revision,
                verification_time_ms: source.now,
            },
        )?,
        flows::evidence("ton.original_minter.account_proof", &source.proof)?,
        flows::evidence("ton.original_minter.cut", &cut)?,
        flows::evidence("ton.original_minter.light_client", &source.light_client)?,
        flows::evidence("ton.original_minter.signing_set", &source.signing_set)?,
    ];
    Ok(Some(Projection {
        state,
        cut,
        evidence,
    }))
}

fn registered(
    client: &BlockingClient,
    original: &origin::AuthenticatedOrigin,
    lite: &LiteClient,
    minter: [u8; 32],
    state: &TonMinterStateV1,
) -> Result<()> {
    let bounded_client = lite
        .budget()
        .deadline()
        .map(|deadline| client.with_request_deadline(deadline))
        .transpose()?;
    let client = bounded_client.as_ref().unwrap_or(client);
    let network = SccpNetworkV1::TonMainnet;
    let route = client
        .sccp()
        .registry()?
        .into_iter()
        .find(|route| route.network == network)
        .ok_or_else(|| eyre!("original TON route is absent"))?;
    original.verify_route(network, &route)?;
    let record = route
        .revisions
        .get(&state.revision)
        .ok_or_else(|| eyre!("original TON revision is absent"))?;
    ensure!(
        record.initial_committee == state.initial && record.max_wrapped_supply == state.max_supply,
        "authenticated minter configuration differs from original registration"
    );
    ensure!(
        matches!(&record.deployment, SccpDeploymentV1::Ton(deployment)
        if deployment.master_account == minter)
            && record.destination_word == minter,
        "authenticated minter differs from registered deployment"
    );
    Ok(())
}

fn progress_ready(state: &TonMinterStateV1, control: Option<u64>, generation: Option<u64>) -> bool {
    state.initialized
        && (control.is_some() || generation.is_some())
        && control.is_none_or(|nonce| state.control_nonce >= nonce)
        && generation.is_none_or(|generation| state.committee.generation >= generation)
}

/// Observe an applied native control or committee synchronization through original TON finality.
pub(super) fn progress(
    client: &BlockingClient,
    original: &origin::AuthenticatedOrigin,
    lite: &LiteClient,
    minter: [u8; 32],
    revision: u32,
    control: Option<u64>,
    generation: Option<u64>,
) -> Result<Option<Evidence>> {
    let Some(projection) = observe(client, original, lite, minter, revision)? else {
        return Ok(None);
    };
    registered(client, original, lite, minter, &projection.state)?;
    Ok(progress_ready(&projection.state, control, generation).then_some(projection.evidence))
}

fn deployment_ready(
    state: &TonMinterStateV1,
    initial: &SccpCommitteePinV1,
    max_supply: u128,
) -> Result<bool> {
    ensure!(
        state.initial == *initial && state.max_supply == max_supply,
        "authenticated deployment differs from the retained original pin or supply cap"
    );
    Ok(state.initialized)
}

/// Prove one-time initialization of the exact pre-registration locked deployment.
pub(super) fn deployment(
    client: &BlockingClient,
    original: &origin::AuthenticatedOrigin,
    lite: &LiteClient,
    minter: [u8; 32],
    revision: u32,
    initial: &SccpCommitteePinV1,
    max_supply: u128,
) -> Result<Option<Evidence>> {
    let Some(projection) = observe(client, original, lite, minter, revision)? else {
        return Ok(None);
    };
    Ok(deployment_ready(&projection.state, initial, max_supply)?.then_some(projection.evidence))
}

/// Original recovery row together with its authenticated bounded account evidence.
pub(super) type RecoverySnapshot = (Option<(RecoveryRowV1, Vec<u8>)>, Evidence);

/// Retain the exact admitted row before preparing a paid retry.
pub(super) fn recovery_snapshot(
    client: &BlockingClient,
    original: &origin::AuthenticatedOrigin,
    lite: &LiteClient,
    minter: [u8; 32],
    revision: u32,
    operation_id: u64,
) -> Result<Option<RecoverySnapshot>> {
    ensure!(operation_id > 0, "recovery operation id is zero");
    let Some(projection) = observe(client, original, lite, minter, revision)? else {
        return Ok(None);
    };
    registered(client, original, lite, minter, &projection.state)?;
    ensure!(
        projection.state.initialized,
        "authenticated minter is not initialized"
    );
    let row = projection
        .state
        .recovery
        .into_iter()
        .find(|row| row.operation_id == operation_id)
        .map(|row| {
            (
                RecoveryRowV1 {
                    identity: row.identity,
                    stage: row.stage,
                    phase: row.phase,
                    attempt: row.attempt,
                },
                row.row_boc,
            )
        });
    Ok(Some((row, projection.evidence)))
}

pub(super) fn recovery_changed(
    state: &TonMinterStateV1,
    operation_id: u64,
    initial: &RecoveryRowV1,
    baseline: &RecoveryCut,
    observed: &RecoveryCut,
) -> Result<bool> {
    if !state.initialized
        || operation_id == 0
        || state.next_operation_id <= operation_id
        || observed.masterchain.workchain != baseline.masterchain.workchain
        || observed.masterchain.shard != baseline.masterchain.shard
        || observed.masterchain.seqno <= baseline.masterchain.seqno
        || observed.shard.workchain != baseline.shard.workchain
        || observed.shard == baseline.shard
    {
        return Ok(false);
    }
    let Some(row) = state
        .recovery
        .iter()
        .find(|row| row.operation_id == operation_id)
    else {
        return Ok(true);
    };
    ensure!(
        row.identity == initial.identity,
        "authenticated recovery cause differs from the retained original"
    );
    Ok(forward_recovery(initial, row.stage, row.phase, row.attempt))
}

fn forward_recovery(initial: &RecoveryRowV1, stage: u8, phase: u8, attempt: u64) -> bool {
    if stage != initial.stage {
        // Consumption can advance to mint or rollback; a bounced mint can only roll back.
        return phase != 3
            && match (initial.stage, stage) {
                (2, 3 | 4) => initial.phase != 2,
                (3, 4) => initial.phase == 0,
                _ => false,
            };
    }
    if attempt > initial.attempt {
        // Only activation and unconsume retain a failed row for another dispatch.
        return matches!(stage, 1 | 4) && initial.phase != 1 && phase != 3;
    }
    if attempt != initial.attempt {
        return false;
    }
    matches!((initial.phase, phase), (3, 0 | 1) | (0, 1))
        || (matches!(stage, 1 | 4) && matches!((initial.phase, phase), (3 | 0, 2)))
}

/// Prove original row progress or deletion; this is distinct from transfer completion.
#[allow(clippy::too_many_arguments)]
pub(super) fn recovery(
    client: &BlockingClient,
    original: &origin::AuthenticatedOrigin,
    lite: &LiteClient,
    minter: [u8; 32],
    revision: u32,
    operation_id: u64,
    initial: &RecoveryRowV1,
    baseline: &RecoveryCut,
) -> Result<Option<Evidence>> {
    let Some(projection) = observe(client, original, lite, minter, revision)? else {
        return Ok(None);
    };
    registered(client, original, lite, minter, &projection.state)?;
    Ok(recovery_changed(
        &projection.state,
        operation_id,
        initial,
        baseline,
        &projection.cut,
    )?
    .then_some(projection.evidence))
}

#[cfg(test)]
mod tests;

#[cfg(test)]
mod causal_tests;
