//! Deterministic destination deployment under original signed journal custody.

use super::*;
use iroha_sccp_wallet::{flow::SccpFlowActionV1 as Action, journal::SccpFlowKindV1 as Kind};

mod verification;
pub use verification::VerifyArgs;
pub(super) use verification::verify;

fn locked_ton_code(name: &str) -> Result<iroha::data_model::sccp::deployment::SccpTonCodeRefV1> {
    let index = match name {
        "SccpTairaXorMinter" => 0,
        "SccpTairaXorWallet" => 1,
        "SccpConsumedBucket" => 2,
        _ => return Err(eyre!("unknown locked TON contract")),
    };
    Ok(iroha_sccp::v1::ton_cell::locked_code_refs()[index])
}

fn require_locked_ton_code(
    name: &str,
    code: iroha::data_model::sccp::deployment::SccpTonCodeRefV1,
) -> Result<()> {
    eyre::ensure!(
        code == locked_ton_code(name)?,
        "{name} differs from the locked TON artifact"
    );
    Ok(())
}

#[derive(norito::derive::JsonSerialize)]
struct Intent {
    network: SccpNetworkV1,
    revision: u32,
    max_supply: String,
    generation: Option<u64>,
    artifacts: Vec<String>,
}

fn open_flow(
    context: &mut impl RunContext,
    args: &DeployArgs,
    network: SccpNetworkV1,
    supply: u128,
    artifacts: &[[u8; 32]],
) -> Result<flows::Flow> {
    let intent = Intent {
        network,
        revision: args.revision,
        max_supply: supply.to_string(),
        generation: args.generation,
        artifacts: artifacts.iter().map(hex::encode).collect(),
    };
    flows::open(
        context,
        Kind::Deployment,
        &args.flow,
        flows::intent(&norito::json::to_vec(&intent)?),
    )
}

fn retained_pin(
    flow: &flows::Flow,
) -> Result<Option<iroha::data_model::sccp::deployment::SccpCommitteePinV1>> {
    let Some(step) = flow.latest(Action::Deploy)? else {
        return Ok(None);
    };
    flows::check_flow(flow, &step)?;
    let value = step
        .record()
        .evidence
        .iter()
        .find(|item| item.label == "deployment.committee_pin")
        .ok_or_else(|| eyre!("original deployment lacks its immutable committee pin"))?;
    Ok(Some(norito::json::from_slice(&value.bytes)?))
}

/// Poll deployed code under the configured confirmation deadline.
fn wait_for_code(
    context: &impl RunContext,
    mut code_hash: impl FnMut() -> Result<[u8; 32]>,
) -> Result<[u8; 32]> {
    let config = context.sccp_config()?;
    let start = std::time::Instant::now();
    loop {
        if let Ok(hash) = code_hash() {
            return Ok(hash);
        }
        let Some(remaining) = config.confirmation_timeout.checked_sub(start.elapsed()) else {
            break;
        };
        std::thread::sleep(config.poll_interval.min(remaining));
    }
    Err(eyre!(
        "deployment code is still unavailable; recover the original flow without preparing another transaction"
    ))
}

/// The code cell of Acton artifact `<build_dir>/<name>.json` (`code_boc64`).
fn ton_code(build_dir: &std::path::Path, name: &str) -> Result<iroha_sccp::v1::ton_cell::Cell> {
    use base64::Engine as _;
    let path = build_dir.join(format!("{name}.json"));
    use std::io::Read as _;
    let mut text = Vec::new();
    std::fs::File::open(&path)?
        .take(4 * 1024 * 1024 + 1)
        .read_to_end(&mut text)?;
    eyre::ensure!(text.len() <= 4 * 1024 * 1024, "TON artifact exceeds 4 MiB");
    let artifact: norito::json::Value =
        norito::json::from_slice(&text).map_err(|error| eyre!("{}: {error}", path.display()))?;
    let encoded = artifact
        .get("code_boc64")
        .and_then(norito::json::Value::as_str)
        .ok_or_else(|| eyre!("{} has no `code_boc64`", path.display()))?;
    let boc = base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .map_err(|error| eyre!("{}: code_boc64: {error}", path.display()))?;
    let cell = iroha_sccp_wallet::pure::ton::code_cell(&boc)
        .map_err(|error| eyre!("{}: {error}", path.display()))?;
    require_locked_ton_code(
        name,
        iroha::data_model::sccp::deployment::SccpTonCodeRefV1 {
            hash: *cell.hash(),
            depth: cell.depth(),
        },
    )?;
    Ok(cell)
}

/// `iroha sccp deploy --network ton-mainnet`: deploy the minter pinned to a Taira generation
/// from the user's wallet (with `sccp_init`) and print its `RegisterRoute` action.
fn deploy_ton<C: RunContext>(context: &mut C, args: DeployArgs) -> Result<()> {
    use iroha::data_model::sccp::{
        deployment::{SccpDeploymentV1, SccpTonCodeRefV1, SccpTonDeploymentV1},
        governance::{SccpGovernanceActionV1, SccpRegisterRouteActionV1},
    };
    use iroha_sccp::v1::ton_cell::{TonMinterInitV1, minter_deployment_data, state_init};
    use iroha_sccp_wallet::pure::ton::{
        SEND_MODE_PAY_FEES_SEPARATELY_IGNORE_ERRORS, init_body, internal_message,
        minter_deploy_value,
    };
    let build_dir = args
        .ton_build_dir
        .as_deref()
        .ok_or_else(|| eyre!("TON deployments need `--ton-build-dir`"))?;
    let minter_code = ton_code(build_dir, "SccpTairaXorMinter")?;
    let wallet_code = ton_code(build_dir, "SccpTairaXorWallet")?;
    let bucket_code = ton_code(build_dir, "SccpConsumedBucket")?;
    let code_ref = |cell: &iroha_sccp::v1::ton_cell::Cell| SccpTonCodeRefV1 {
        hash: *cell.hash(),
        depth: cell.depth(),
    };
    let max_supply: Numeric = args.max_supply.parse().map_err(|_| {
        eyre!(
            "max supply `{}` is not a decimal XOR amount",
            args.max_supply
        )
    })?;
    let max_wrapped_supply = iroha_sccp::v1::amount::taira_units(&max_supply)
        .map_err(|error| eyre!("max supply: {error}"))?;
    if max_wrapped_supply == 0 {
        return Err(eyre!("max supply must be positive"));
    }
    if max_wrapped_supply >= (1_u128 << 96) {
        return Err(eyre!("TON supply cap must be below 2^96"));
    }
    let flow = open_flow(
        context,
        &args,
        SccpNetworkV1::TonMainnet,
        max_wrapped_supply,
        &[
            *minter_code.hash(),
            *wallet_code.hash(),
            *bucket_code.hash(),
        ],
    )?;
    let retained = retained_pin(&flow)?;
    let client = blocking(context)?;
    let authenticated_origin = origin::authenticate_origin(context, &client, &args.origin)?;
    let original = origin::authenticate(
        context,
        &client,
        &args.origin,
        retained.map(|pin| pin.generation).or(args.generation),
    )?;
    eyre::ensure!(
        retained.is_none_or(|pin| pin == original.pin),
        "original deployment pin changed"
    );
    let init = TonMinterInitV1 {
        taira_network_id: original.network,
        consensus_instance: original.instance,
        route_revision: args.revision,
        max_supply: max_wrapped_supply,
        pin: original.pin,
        keys: original.keys,
        wallet_code: code_ref(&wallet_code),
        bucket_code: code_ref(&bucket_code),
    };
    let data = minter_deployment_data(&init, wallet_code.clone(), bucket_code.clone())
        .map_err(|error| eyre!("minter data: {error}"))?;
    let state = state_init(minter_code.clone(), data.root)
        .map_err(|error| eyre!("minter StateInit: {error}"))?;
    let minter = *state.hash();
    let lite = ton::connect_config(&context.sccp_config()?, &args.rpc_url)?;
    let wallet = ton::TonWallet::load(
        &lite,
        args.ton_wallet
            .as_deref()
            .ok_or_else(|| eyre!("TON deployments need `--ton-wallet 0:<hex>`"))?,
        &args.key_file,
    )?;
    // §5.3.5: the deployment funds MINTER_FLOOR plus a margin, so the minter starts above its
    // floor instead of charging the deficit to its first caller.
    let message = internal_message(
        &minter,
        minter_deploy_value(),
        false,
        init_body(0).map_err(|error| eyre!("sccp_init: {error}"))?,
        Some(state),
    )
    .map_err(|error| eyre!("deployment message: {error}"))?;
    let destination = ton::TonDestination::connect(
        &context.sccp_config()?,
        &args.rpc_url,
        minter,
        iroha_sccp::v1::proof::DestinationV1 {
            network: SccpNetworkV1::TonMainnet,
            route_revision: args.revision,
            destination_word: minter,
        },
    )?;
    let outcome = flows::ton(
        context,
        &authenticated_origin,
        &flow,
        Action::Deploy,
        &lite,
        vec![flows::evidence("deployment.committee_pin", &original.pin)?],
        |_| {
            let now_ms = ton::block_time_ms(&lite, ton::last_block(&lite)?)?;
            eyre::ensure!(
                iroha_sccp::v1::destination::init_until_ms_is_valid(now_ms, original.pin.until_ms),
                "the authenticated pin is outside the current TON initialization window"
            );
            wallet.prepare(
                &lite,
                &[(message, SEND_MODE_PAY_FEES_SEPARATELY_IGNORE_ERRORS)],
            )
        },
        |_| match destination.progress_evidence(
            original.network,
            original.instance,
            None,
            Some(original.pin.generation),
        ) {
            Ok(evidence) => Ok(evidence),
            // A not-yet-active account has no getters. Absence never becomes a failed operation.
            Err(_) => Ok(None),
        },
    )?;
    context.println(format!("minter 0:{}", hex::encode(minter)))?;
    if !flows::confirmed(&outcome) {
        return Ok(());
    }
    let action = SccpGovernanceActionV1::RegisterRoute(SccpRegisterRouteActionV1 {
        network: SccpNetworkV1::TonMainnet,
        revision: args.revision,
        deployment: SccpDeploymentV1::Ton(SccpTonDeploymentV1 {
            master_account: minter,
            minter_code: code_ref(&minter_code),
            wallet_code: code_ref(&wallet_code),
            bucket_code: code_ref(&bucket_code),
        }),
        max_wrapped_supply,
        initial_committee: original.pin,
    });
    context.print_data(&vec![action])
}

/// `iroha sccp deploy`: deploy a pinned EVM or TON destination and print its `RegisterRoute`
/// action.
pub(super) fn run<C: RunContext>(context: &mut C, args: DeployArgs) -> Result<()> {
    use iroha::data_model::sccp::{
        deployment::{SccpDeploymentV1, SccpEvmDeploymentV1},
        governance::{SccpGovernanceActionV1, SccpRegisterRouteActionV1},
    };
    let network = parse_network(&args.network)?;
    match network {
        SccpNetworkV1::EthereumMainnet | SccpNetworkV1::BscMainnet => {}
        SccpNetworkV1::TonMainnet => return deploy_ton(context, args),
        SccpNetworkV1::SoraTaira => {
            return Err(eyre!("{} is not a destination", network.profile_key()));
        }
    }
    let bytecode = locked_creation_bytecode(
        args.creation_bytecode
            .as_deref()
            .ok_or_else(|| eyre!("Solidity deployments need `--creation-bytecode`"))?,
    )?;
    let max_supply: Numeric = args.max_supply.parse().map_err(|_| {
        eyre!(
            "max supply `{}` is not a decimal XOR amount",
            args.max_supply
        )
    })?;
    let max_wrapped_supply = iroha_sccp::v1::amount::taira_units(&max_supply)
        .map_err(|error| eyre!("max supply: {error}"))?;
    if max_wrapped_supply == 0 {
        return Err(eyre!("max supply must be positive"));
    }
    let flow = open_flow(
        context,
        &args,
        network,
        max_wrapped_supply,
        &[iroha_sccp::v1::hashes::keccak256(&[&bytecode])],
    )?;
    let retained = retained_pin(&flow)?;
    let client = blocking(context)?;
    let authenticated_origin = origin::authenticate_origin(context, &client, &args.origin)?;
    let original = origin::authenticate(
        context,
        &client,
        &args.origin,
        retained.map(|pin| pin.generation).or(args.generation),
    )?;
    eyre::ensure!(
        retained.is_none_or(|pin| pin == original.pin),
        "original deployment pin changed"
    );
    let mut data = bytecode;
    data.extend(evm::constructor_args(
        &original.network,
        &original.instance,
        network,
        args.revision,
        max_wrapped_supply,
        &original.pin,
    ));
    let deployment = evm::deployment(&context.sccp_config()?, &args.rpc_url, network, data)?;
    let address = deployment.address;
    let transport = deployment.transport();
    if !flows::recover_evm_call(
        context,
        &authenticated_origin,
        &flow,
        Action::Deploy,
        &transport,
    )? {
        let outcome = flows::evm_call(
            context,
            &authenticated_origin,
            &flow,
            Action::Deploy,
            network,
            &transport,
            &args.key_file,
            deployment.calldata.clone(),
            vec![flows::evidence("deployment.committee_pin", &original.pin)?],
        )?;
        if !flows::confirmed(&outcome) {
            return Ok(());
        }
    } else {
        let step = flow
            .latest(Action::Deploy)?
            .ok_or_else(|| eyre!("missing retained deployment"))?;
        if step.outcome()?.is_none_or(|outcome| {
            outcome.outcome != iroha_sccp_wallet::journal::SccpStepOutcomeKindV1::Confirmed
        }) {
            return Ok(());
        }
    }
    context.println(format!("contract 0x{}", hex::encode(address)))?;
    let runtime_code_hash = wait_for_code(context, || deployment.runtime_code_hash())?;
    let action = SccpGovernanceActionV1::RegisterRoute(SccpRegisterRouteActionV1 {
        network,
        revision: args.revision,
        deployment: SccpDeploymentV1::Evm(SccpEvmDeploymentV1 {
            address,
            runtime_code_hash,
        }),
        max_wrapped_supply,
        initial_committee: original.pin,
    });
    context.print_data(&vec![action])
}
