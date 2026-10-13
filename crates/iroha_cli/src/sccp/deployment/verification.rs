//! Read-only pre-vote checks against locked destination code and original native history.

use super::*;
use eyre::ensure;
use iroha::data_model::sccp::{
    deployment::{SccpDeploymentV1, SccpTonCodeRefV1},
    governance::{SccpGovernanceActionV1, SccpRegisterRouteActionV1},
};
use iroha_sccp::v1::{
    committee::CommitteeStateV1,
    evm_abi::{ConstructorArgsV1, PauseViewV1, ViewCallV1, ViewReturnV1},
    hashes::{keccak256, word_u64, word_u128},
};
use std::{collections::BTreeMap, io::Read as _, num::NonZeroU64, path::PathBuf};

mod ton_account;

/// Review a proposed or registered destination before registration or activation.
#[derive(clap::Args, Debug)]
pub struct VerifyArgs {
    /// Independently selected native genesis and complete certified World cut.
    #[command(flatten)]
    origin: origin::OriginArgs,
    /// External network profile.
    #[arg(long)]
    network: String,
    /// Exact revision selected from the proposal or authenticated registry.
    #[arg(long)]
    revision: u32,
    /// Bounded JSON array of proposed SCCP actions, including this RegisterRoute.
    #[arg(long, conflicts_with = "proposal_id")]
    actions: Option<PathBuf>,
    /// Exact proposal content id; its body must reproduce this fingerprint.
    #[arg(long, conflicts_with = "actions")]
    proposal_id: Option<String>,
    /// Configured endpoint override; empty uses the SCCP client configuration.
    #[arg(long, default_value = "")]
    rpc_url: String,
    /// Additional EVM checkpoint heights to inspect (at most sixteen).
    #[arg(long, value_parser = clap::value_parser!(u64).range(1..), num_args = 1..=16)]
    checkpoint_height: Vec<u64>,
}

fn select_registration(
    actions: &[SccpGovernanceActionV1],
    network: SccpNetworkV1,
    revision: u32,
) -> Result<SccpRegisterRouteActionV1> {
    ensure!(
        (1..=16).contains(&actions.len()),
        "proposal must contain 1..=16 actions"
    );
    let mut selected = None;
    for action in actions {
        if let SccpGovernanceActionV1::RegisterRoute(register) = action
            && register.network == network
            && register.revision == revision
        {
            ensure!(
                selected.is_none(),
                "proposal repeats the selected registration"
            );
            selected = Some(*register);
        }
    }
    selected
        .ok_or_else(|| eyre!("proposal has no RegisterRoute for the selected network and revision"))
}

fn selected_registration(
    context: &impl RunContext,
    client: &BlockingClient,
    original: &origin::AuthenticatedOrigin,
    args: &VerifyArgs,
    network: SccpNetworkV1,
) -> Result<SccpRegisterRouteActionV1> {
    if let Some(path) = &args.actions {
        let mut bytes = Vec::new();
        std::fs::File::open(path)?
            .take(16 * 1024 * 1024 + 1)
            .read_to_end(&mut bytes)?;
        ensure!(bytes.len() <= 16 * 1024 * 1024, "actions exceed 16 MiB");
        let actions: Vec<SccpGovernanceActionV1> = norito::json::from_slice(&bytes)?;
        // The existing proposal builder supplies only static validation here. Its current
        // revision candidates confer no enactment authority and nothing is submitted.
        let proposal = governance::build_proposal(
            context.config().network_id,
            &client.sccp().governance_revisions()?,
            actions,
        )?;
        return select_registration(&proposal.actions, network, args.revision);
    }
    if let Some(id) = &args.proposal_id {
        use iroha::data_model::governance::types::{ProposalKind, SccpRouteGovernanceProposal};
        let id = parse_word(id)?;
        let detail = client.sccp().governance_proposal(&id)?;
        detail
            .proposal
            .validate_static(&context.config().network_id)?;
        let fingerprint = ProposalKind::SccpRouteGovernance(SccpRouteGovernanceProposal {
            proposal: Box::new(detail.proposal.clone()),
        })
        .fingerprint();
        ensure!(
            detail.content_id.as_bytes() == &id && fingerprint == id,
            "proposal body differs from the selected content id"
        );
        return select_registration(&detail.proposal.actions, network, args.revision);
    }
    let route = client
        .sccp()
        .registry()?
        .into_iter()
        .find(|route| route.network == network)
        .ok_or_else(|| {
            eyre!("route is absent; supply --actions or --proposal-id for pre-registration review")
        })?;
    original.verify_route(network, &route)?;
    let revision = route
        .revisions
        .get(&args.revision)
        .ok_or_else(|| eyre!("registered revision is absent"))?;
    Ok(SccpRegisterRouteActionV1 {
        network,
        revision: args.revision,
        deployment: revision.deployment,
        max_wrapped_supply: revision.max_wrapped_supply,
        initial_committee: revision.initial_committee,
    })
}

fn constructor(
    original: &origin::AuthenticatedOrigin,
    registration: &SccpRegisterRouteActionV1,
) -> ConstructorArgsV1 {
    ConstructorArgsV1 {
        taira_network_id: original.network,
        consensus_instance: original.instance,
        network: registration.network,
        route_revision: registration.revision,
        max_wrapped_supply: registration.max_wrapped_supply,
        pin: registration.initial_committee,
    }
}

/// Materialize every immutable occurrence in the embedded compiler runtime template.
fn locked_evm_runtime(args: &ConstructorArgsV1) -> Result<Vec<u8>> {
    let lock: norito::json::Value = norito::json::from_str(ARTIFACT_LOCK)?;
    let contract =
        &lock["targets"]["evm"]["contracts"]["contracts/evm/sccp/SccpTairaXor.sol:SccpTairaXor"];
    let template = contract["runtime_template_hex"]
        .as_str()
        .ok_or_else(|| eyre!("missing runtime template"))?;
    let mut code = hex::decode(
        template
            .strip_prefix("0x")
            .ok_or_else(|| eyre!("unprefixed runtime"))?,
    )?;
    let values = BTreeMap::from([
        ("TAIRA_NETWORK_ID", args.taira_network_id),
        ("CONSENSUS_INSTANCE", args.consensus_instance),
        (
            "NETWORK_TAG",
            word_u64(u64::from(iroha_sccp::v1::network::tag(args.network))),
        ),
        ("ROUTE_REVISION", word_u64(u64::from(args.route_revision))),
        ("MAX_WRAPPED_SUPPLY", word_u128(args.max_wrapped_supply)),
        ("INITIAL_GENERATION", word_u64(args.pin.generation)),
        ("INITIAL_COMMITTEE_ROOT", args.pin.committee_root),
        ("INITIAL_START_HEIGHT", word_u64(args.pin.start_height)),
        ("INITIAL_UNTIL_MS", word_u64(args.pin.until_ms)),
    ]);
    let mut seen = std::collections::BTreeSet::new();
    let mut occupied = std::collections::BTreeSet::new();
    for item in contract["immutable_references"]
        .as_array()
        .ok_or_else(|| eyre!("missing immutable references"))?
    {
        let name = item["name"]
            .as_str()
            .ok_or_else(|| eyre!("missing immutable name"))?;
        let value = values
            .get(name)
            .ok_or_else(|| eyre!("unknown locked immutable {name}"))?;
        let start = usize::try_from(
            item["start"]
                .as_u64()
                .ok_or_else(|| eyre!("missing immutable offset"))?,
        )?;
        ensure!(
            item["length"].as_u64() == Some(32),
            "immutable is not one word"
        );
        let end = start
            .checked_add(32)
            .ok_or_else(|| eyre!("immutable offset overflows"))?;
        ensure!(
            (start..end).all(|index| occupied.insert(index)),
            "overlapping immutables"
        );
        code.get_mut(start..end)
            .ok_or_else(|| eyre!("immutable outside runtime"))?
            .copy_from_slice(value);
        seen.insert(name);
    }
    ensure!(
        seen.len() == values.len(),
        "runtime omits an expected immutable"
    );
    Ok(code)
}

fn verify_committee(
    client: &BlockingClient,
    original: &origin::AuthenticatedOrigin,
    initial_generation: u64,
    observed: &CommitteeStateV1,
) -> Result<()> {
    ensure!(
        !observed.equivocated && observed.generation >= initial_generation,
        "destination committee is latched or predates its pin"
    );
    ensure!(
        observed.start > 0 && observed.high >= observed.start - 1,
        "destination high-water mark predates its committee"
    );
    let native = original.verify_generation(
        observed.generation,
        client.sccp().committee(observed.generation)?,
    )?;
    ensure!(
        observed.root == native.committee_root
            && observed.start == native.start_height
            && observed.until_ms <= native.deadline_ms,
        "destination committee differs from original native generation"
    );
    Ok(())
}

fn verify_checkpoint(
    context: &impl RunContext,
    client: &BlockingClient,
    args: &origin::OriginArgs,
    height: u64,
    observed: [u8; 32],
) -> Result<()> {
    use iroha_sccp::v1::finality::{SccpFinalityHeaderV1, checkpoint_id, verify_certificate};
    ensure!(
        height > 0 && height <= args.at_height,
        "checkpoint lies beyond the selected native cut"
    );
    let (original, anchor) =
        origin::authenticate_origin_with_anchor(context, client, args, Some(height))?;
    let certificate = client.sccp().finality(SccpFinalityAt::Height(
        NonZeroU64::new(height).ok_or_else(|| eyre!("zero checkpoint"))?,
    ))?;
    let header = SccpFinalityHeaderV1::parse(&certificate.header)?;
    ensure!(
        header.height() == height && header.network_id() == original.network,
        "checkpoint coordinates differ"
    );
    let native = original.verify_generation(
        header.generation(),
        client.sccp().committee(header.generation())?,
    )?;
    let verified = verify_certificate(
        &original.instance,
        &certificate.qc,
        &certificate.header,
        &certificate.aggregate_signature,
        &native.keys,
    )?;
    let anchor = anchor.ok_or_else(|| eyre!("original checkpoint anchor unavailable"))?;
    ensure!(
        anchor.core_hash == verified.qc.block_hash
            && anchor.result == verified.result
            && checkpoint_id(&certificate.header) == observed,
        "stored checkpoint is not the original native certificate"
    );
    Ok(())
}

fn require_pristine_evm(
    args: &ConstructorArgsV1,
    mut read: impl FnMut(ViewCallV1) -> Result<ViewReturnV1>,
    total_supply: &[u8],
) -> Result<CommitteeStateV1> {
    let expected = [
        (
            ViewCallV1::TairaNetworkId,
            ViewReturnV1::Bytes32(args.taira_network_id),
        ),
        (
            ViewCallV1::ConsensusInstance,
            ViewReturnV1::Bytes32(args.consensus_instance),
        ),
        (
            ViewCallV1::RouteRevision,
            ViewReturnV1::U32(args.route_revision),
        ),
        (
            ViewCallV1::MaxWrappedSupply,
            ViewReturnV1::U128(args.max_wrapped_supply),
        ),
        (
            ViewCallV1::InitialCommittee,
            ViewReturnV1::InitialCommittee(args.pin),
        ),
        (ViewCallV1::OpCount, ViewReturnV1::U64(0)),
        (ViewCallV1::ControlNonce, ViewReturnV1::U64(0)),
        (ViewCallV1::Equivocated, ViewReturnV1::Bool(false)),
        (
            ViewCallV1::PauseState,
            ViewReturnV1::PauseState(PauseViewV1 {
                parliament_paused: false,
                fast_pause_until_ms: 0,
                control_nonce: 0,
                effective: false,
            }),
        ),
    ];
    for (call, expected) in expected {
        ensure!(
            read(call)? == expected,
            "deployment {call:?} differs from the proposed pristine state"
        );
    }
    ensure!(
        total_supply == [0; 32],
        "deployment supply is nonzero or noncanonical"
    );
    let ViewReturnV1::CommitteeState(committee) = read(ViewCallV1::CommitteeState)? else {
        return Err(eyre!("committee view has another type"));
    };
    Ok(committee.with_equivocated(false))
}

fn verify_evm(
    context: &impl RunContext,
    client: &BlockingClient,
    original: &origin::AuthenticatedOrigin,
    args: &VerifyArgs,
    registration: &SccpRegisterRouteActionV1,
) -> Result<()> {
    use iroha_sccp_rpc::evm::{BlockId, BlockTag, EvmCallRequest};
    let SccpDeploymentV1::Evm(deployment) = registration.deployment else {
        return Err(eyre!("not EVM"));
    };
    let constructor = constructor(original, registration);
    ensure!(
        constructor.address() == deployment.address,
        "proposed EVM address differs from locked CREATE2"
    );
    let expected_code = locked_evm_runtime(&constructor)?;
    ensure!(
        keccak256(&[&expected_code]) == deployment.runtime_code_hash,
        "proposed runtime hash differs from the locked constructor runtime"
    );
    let rpc =
        evm::connect_chain_config(&context.sccp_config()?, &args.rpc_url, registration.network)?;
    let block = rpc
        .block_by_number(BlockTag::Finalized)?
        .ok_or_else(|| eyre!("finalized destination block is unavailable"))?;
    let at = BlockId::Hash(block.header.hash);
    ensure!(
        rpc.code(&deployment.address, at)? == expected_code,
        "finalized destination code differs from the locked runtime"
    );
    let read = |call: ViewCallV1| -> Result<ViewReturnV1> {
        Ok(call.decode_return(&rpc.call(
            &EvmCallRequest::new(deployment.address, call.calldata()),
            at,
        )?)?)
    };
    let supply_selector = keccak256(&[b"totalSupply()"])[..4].to_vec();
    let total_supply = rpc.call(
        &EvmCallRequest::new(deployment.address, supply_selector),
        at,
    )?;
    let committee = require_pristine_evm(&constructor, read, &total_supply)?;
    verify_committee(
        client,
        original,
        registration.initial_committee.generation,
        &committee,
    )?;
    ensure!(
        args.checkpoint_height.len() <= 16,
        "too many sampled checkpoints"
    );
    let mut samples = args.checkpoint_height.clone();
    if committee.high >= committee.start
        || committee.generation > registration.initial_committee.generation
    {
        samples.push(committee.high);
    }
    samples.sort_unstable();
    samples.dedup();
    for height in samples {
        let ViewReturnV1::Bytes32(id) = read(ViewCallV1::CheckpointHeader(height))? else {
            return Err(eyre!("checkpoint view has another type"));
        };
        ensure!(id != [0; 32], "requested checkpoint is not stored");
        verify_checkpoint(context, client, &args.origin, height, id)?;
    }
    Ok(())
}

pub(crate) fn verify(context: &mut impl RunContext, args: VerifyArgs) -> Result<()> {
    let client = blocking(context)?;
    let original = origin::authenticate_origin(context, &client, &args.origin)?;
    let network = parse_network(&args.network)?;
    let registration = selected_registration(context, &client, &original, &args, network)?;
    let generation = client
        .sccp()
        .committee(registration.initial_committee.generation)?;
    let keys =
        original.verify_pin_generation(generation.clone(), &registration.initial_committee)?;
    let native =
        original.verify_generation(registration.initial_committee.generation, generation)?;
    ensure!(
        native.deadline_ms == registration.initial_committee.until_ms,
        "proposed pin deadline differs from its exact native generation"
    );
    match registration.deployment {
        SccpDeploymentV1::Evm(_) => verify_evm(context, &client, &original, &args, &registration)?,
        SccpDeploymentV1::Ton(_) => {
            ton_account::verify(context, &client, &original, &args, &registration, keys)?
        }
    }
    context.println("Deployment review passed: locked code, exact proposal identity, pristine monetary/control state, and original native committee/checkpoints. This read-only review does not register or authorize the route.")
}

#[cfg(test)]
mod tests;
