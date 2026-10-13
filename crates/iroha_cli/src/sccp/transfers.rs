//! Durable burn, settlement and refund command transitions.

mod burn_guard;

use super::*;
use eyre::ensure;
use iroha::data_model::{
    account::AccountAddress,
    isi::sccp::{AdvanceSccpLightClientV1, SettleSccpV1, SubmitSccpOutboundVoidV1},
};
use iroha_sccp_wallet::{
    flow::SccpFlowActionV1 as Action,
    journal::{SccpEvidenceItemV1, SccpFlowKindV1 as Kind},
};

/// Retry one admitted inbound settlement using its durable original transaction.
#[derive(Debug, clap::Args)]
pub struct SettleArgs {
    /// Inbound message identity.
    #[arg(long)]
    message_id: String,
    /// Original signed custody and exact-byte recovery policy.
    #[command(flatten)]
    flow: flows::FlowArgs,
}

/// Prove a finalized destination void, then retry its Taira refund when necessary.
#[derive(Debug, clap::Args)]
pub struct RefundArgs {
    /// Original authority and route snapshot.
    #[command(flatten)]
    origin: origin::OriginArgs,
    /// Original outbound message identity.
    #[arg(long)]
    message_id: String,
    /// Destination transaction hash; TON uses lt:hash.
    #[arg(long)]
    tx_hash: Option<String>,
    /// Event position within the transaction (receipt log or TON external message).
    #[arg(long, default_value_t = 0)]
    event_index: u16,
    /// EVM JSON-RPC endpoint or TON liteserver list.
    #[arg(long, default_value = "")]
    rpc_url: String,
    /// Ethereum beacon API for the original active profile.
    #[arg(long)]
    beacon_url: Option<String>,
    /// Original signed custody and exact-byte recovery policy.
    #[command(flatten)]
    flow: flows::FlowArgs,
}

/// Burn a registered destination token for a canonical Taira account.
#[derive(Debug, clap::Args)]
pub struct BurnArgs {
    /// Original authority and route snapshot.
    #[command(flatten)]
    origin: origin::OriginArgs,
    /// Source destination network.
    #[arg(long)]
    network: String,
    /// Exact source revision.
    #[arg(long)]
    revision: u32,
    /// Canonical Taira recipient; defaults to the configured account.
    #[arg(long)]
    recipient: Option<String>,
    /// Positive XOR amount in decimal units.
    #[arg(long)]
    amount: Numeric,
    /// External-chain endpoint.
    #[arg(long, default_value = "")]
    rpc_url: String,
    /// Runtime-only fee payer key file.
    #[arg(long)]
    key_file: std::path::PathBuf,
    /// TON fee payer's deployed v5r1 wallet address.
    #[arg(long)]
    ton_wallet: Option<String>,
    /// Original signed custody and exact-byte recovery policy.
    #[command(flatten)]
    flow: flows::FlowArgs,
}

pub(super) fn settle(context: &mut impl RunContext, args: SettleArgs) -> Result<()> {
    let id = parse_word(&args.message_id)?;
    let flow = flows::open(context, Kind::Inbound, &args.flow, id)?;
    if flows::recover_taira(context, &flow, Action::SettleInbound)? {
        flows::finish_message(context, &flow, &id)?;
        return Ok(());
    }
    if flows::finish_message(context, &flow, &id)? {
        return Ok(());
    }
    let status = blocking(context)?.sccp().message(&id)?;
    ensure!(status.inbound().is_some(), "the message is not inbound");
    flows::taira(
        context,
        &flow,
        Action::SettleInbound,
        vec![SettleSccpV1::inbound(id).into()],
        vec![flows::evidence("taira.inbound_before_settle", &status)?],
    )?;
    flows::finish_message(context, &flow, &id)?;
    Ok(())
}

pub(super) fn refund(context: &mut impl RunContext, args: RefundArgs) -> Result<()> {
    let id = parse_word(&args.message_id)?;
    let flow = flows::open(context, Kind::Refund, &args.flow, id)?;
    let action = if args.tx_hash.is_some() {
        Action::ProveVoid
    } else {
        Action::SettleRefund
    };
    if flows::recover_taira(context, &flow, action)? {
        flows::finish_message(context, &flow, &id)?;
        return Ok(());
    }
    if flows::recover_advance(context, &flow)? {
        return Ok(());
    }
    if flows::finish_message(context, &flow, &id)? {
        return Ok(());
    }
    let client = blocking(context)?;
    let original = origin::authenticate_origin(context, &client, &args.origin)?;
    let status = client.sccp().message(&id)?;
    let record = &status
        .outbound()
        .ok_or_else(|| eyre!("the message is not outbound"))?
        .record;
    let (deployment, _) =
        route_deployment(&client, &original, record.network, Some(record.revision))?;
    let Some(tx_hash) = args.tx_hash else {
        flows::taira(
            context,
            &flow,
            action,
            vec![SettleSccpV1::refund(record.network, record.revision, record.nonce).into()],
            vec![flows::evidence("taira.outbound_before_refund", &status)?],
        )?;
        flows::finish_message(context, &flow, &id)?;
        return Ok(());
    };
    let event = match deployment {
        iroha::data_model::sccp::deployment::SccpDeploymentV1::Evm(_) => SourceEventRefV1::Evm {
            tx_hash: parse_word(&tx_hash)?,
            event: iroha_sccp_rpc::builders::ethereum::EthereumEventV1::Void {
                first_log_index: u32::from(args.event_index),
                log_count: 1,
            },
        },
        iroha::data_model::sccp::deployment::SccpDeploymentV1::Ton(deployment) => {
            let (lt, hash) = tx_hash
                .split_once(':')
                .ok_or_else(|| eyre!("TON event requires lt:hash"))?;
            SourceEventRefV1::Ton {
                minter: deployment.master_account,
                lt: lt.parse()?,
                hash: parse_word(hash)?,
                message_index: args.event_index,
            }
        }
    };
    let profiles = original.light_client_profiles(&client)?;
    let builder = source_builder(
        &context.sccp_config()?,
        profiles,
        record.network,
        &args.rpc_url,
        args.beacon_url.as_deref(),
    )?;
    let evidence = prove(profiles, &client, record.network, builder.as_ref(), &event)?;
    let verified = ToriiLightClient::read(&client, record.network, profiles)?
        .replay()
        .verify_evidence(&evidence, wall_clock_ms())?;
    require_void_binding(&verified.event, &deployment, &id, record.nonce)?;
    let retained = SccpEvidenceItemV1 {
        label: "source.verified_void".to_owned(),
        bytes: evidence.proof.as_bytes().to_vec(),
    };
    for advance in evidence.backfills {
        let outcome = flows::taira(
            context,
            &flow,
            Action::Advance,
            vec![
                AdvanceSccpLightClientV1 {
                    network: record.network,
                    expected_state_hash: None,
                    advance,
                }
                .into(),
            ],
            vec![retained.clone()],
        )?;
        if !flows::confirmed(&outcome) {
            return Ok(());
        }
    }
    flows::taira(
        context,
        &flow,
        action,
        vec![
            SubmitSccpOutboundVoidV1 {
                network: record.network,
                revision: record.revision,
                proof: evidence.proof,
            }
            .into(),
        ],
        vec![retained],
    )?;
    flows::finish_message(context, &flow, &id)?;
    Ok(())
}

pub(super) fn burn(context: &mut impl RunContext, args: BurnArgs) -> Result<()> {
    let network = parse_network(&args.network)?;
    let recipient = args
        .recipient
        .as_deref()
        .map(|value| crate::resolve_account_id(context, value))
        .transpose()?
        .unwrap_or_else(|| context.config().account.clone());
    let recipient = AccountAddress::from_account_id(&recipient)?.canonical_bytes()?;
    let amount = iroha_sccp::v1::amount::taira_units(&args.amount)?;
    ensure!(amount > 0, "burn amount must be positive");
    #[derive(norito::derive::JsonSerialize)]
    struct BurnIntent {
        network: SccpNetworkV1,
        revision: u32,
        amount: String,
        recipient: String,
        owner: String,
    }
    let owner = if network == SccpNetworkV1::TonMainnet {
        hex::encode(ton::parse_account(
            args.ton_wallet
                .as_deref()
                .ok_or_else(|| eyre!("TON burns require --ton-wallet"))?,
        )?)
    } else {
        hex::encode(evm::load_key(&args.key_file)?.address())
    };
    let identity = BurnIntent {
        network,
        revision: args.revision,
        amount: amount.to_string(),
        recipient: hex::encode(&recipient),
        owner,
    };
    let flow = flows::open(
        context,
        Kind::Inbound,
        &args.flow,
        flows::intent(&norito::json::to_vec(&identity)?),
    )?;
    let client = blocking(context)?;
    let original = origin::authenticate_origin(context, &client, &args.origin)?;
    if network == SccpNetworkV1::TonMainnet {
        let (iroha::data_model::sccp::deployment::SccpDeploymentV1::Ton(deployment), _) =
            route_deployment(&client, &original, network, Some(args.revision))?
        else {
            return Err(eyre!("TON route has another deployment family"));
        };
        let (destination, wallet) = ton_destination(
            &context.sccp_config()?,
            &client,
            &original,
            network,
            Some(args.revision),
            &args.rpc_url,
            args.ton_wallet.as_deref(),
            &args.key_file,
        )?;
        let profiles = original.light_client_profiles(&client)?;
        let query_id = u64::from_be_bytes(flow.id().id[..8].try_into()?);
        flows::ton(
            context,
            &original, 
            &flow,
            Action::Burn,
            destination.lite(),
            vec![flows::evidence("verified.burn_intent", &identity)?],
            |items| {
                items.extend(burn_guard::preflight(
                    &client,
                    &original,
                    network,
                    args.revision,
                    &recipient,
                )?);
                destination.prepare_burn(
                    &wallet,
                    deployment.wallet_code,
                    query_id,
                    &recipient,
                    amount,
                    original.network,
                    original.instance,
                )
            },
            |step| {
                destination.burn_evidence(
                    &client,
                    profiles,
                    step,
                    deployment.wallet_code,
                    wallet.address(),
                    query_id,
                    &recipient,
                    amount,
                )
            },
        )?;
        return Ok(());
    }
    let destination = evm_destination(
        &context.sccp_config()?,
        &client,
        &original,
        network,
        Some(args.revision),
        &args.rpc_url,
    )?;
    if flows::recover_evm(context, &original, &flow, Action::Burn, &destination)? {
        return Ok(());
    }
    let mut evidence =
        burn_guard::preflight(&client, &original, network, args.revision, &recipient)?;
    evidence.push(flows::evidence("verified.burn_intent", &identity)?);
    let key = evm::load_key(&args.key_file)?;
    let call = destination.burn_call(
        &key,
        &recipient,
        amount,
        original.network,
        original.instance,
    )?;
    flows::evm(
        context,
        &original, 
        &flow,
        Action::Burn,
        network,
        &destination,
        &args.key_file,
        call,
        evidence,
    )?;
    Ok(())
}

/// Permanently consume one expired outbound nonce, or void it after destination freeze.
#[derive(Debug, clap::Args)]
pub struct VoidArgs {
    /// Original message, destination, payer and durable recovery arguments.
    #[command(flatten)]
    transfer: FinalizeArgs,
    /// Use the protocol frozen-destination path (still checked on the destination).
    #[arg(long)]
    frozen: bool,
}

pub(super) fn void(context: &mut impl RunContext, args: VoidArgs) -> Result<()> {
    let args_transfer = &args.transfer;
    ensure!(
        !args_transfer.emit,
        "unsigned export is available through finalize"
    );
    let key_file = args_transfer
        .key_file
        .as_deref()
        .ok_or_else(|| eyre!("void requires --key-file"))?;
    let id = parse_word(&args_transfer.message_id)?;
    let flow = flows::open(context, Kind::Refund, &args_transfer.flow, id)?;
    let client = blocking(context)?;
    let original = origin::authenticate_origin(context, &client, &args_transfer.origin)?;
    let status = client.sccp().message(&id)?;
    let record = &status
        .outbound()
        .ok_or_else(|| eyre!("the message is not outbound"))?
        .record;
    if record.network == SccpNetworkV1::TonMainnet {
        let (destination, wallet) = ton_destination(
            &context.sccp_config()?,
            &client,
            &original,
            record.network,
            Some(record.revision),
            &args_transfer.rpc_url,
            args_transfer.ton_wallet.as_deref(),
            key_file,
        )?;
        let profiles = original.light_client_profiles(&client)?;
        let bundle = if !args.frozen && flows::needs_preparation(&flow, Action::Void)? {
            let bundle = client
                .sccp()
                .message_proof(&id, parse_proof_height(&args_transfer.at)?)?;
            require_requested_message(&id, &bundle.message_id)?;
            Some(bundle)
        } else {
            None
        };
        let mut items = vec![flows::evidence("taira.outbound_to_void", &status)?];
        if let Some(bundle) = &bundle {
            items.push(flows::evidence("verified.void_bundle", bundle)?);
        }
        flows::ton(
            context,
            &original, 
            &flow,
            Action::Void,
            destination.lite(),
            items,
            |_| {
                destination.prepare_void(
                    bundle.as_ref(),
                    record.nonce,
                    args.frozen,
                    original.network,
                    original.instance,
                    &wallet,
                )
            },
            |step| {
                destination.terminal_evidence(
                    &client,
                    profiles,
                    step,
                    iroha_sccp::ton_watch::TerminalEvent::Voided {
                        message_id: if args.frozen { [0; 32] } else { id },
                        first_nonce: record.nonce,
                        count: 1,
                    },
                )
            },
        )?;
    } else {
        let destination = evm_destination(
            &context.sccp_config()?,
            &client,
            &original,
            record.network,
            Some(record.revision),
            &args_transfer.rpc_url,
        )?;
        if flows::recover_evm(context, &original, &flow, Action::Void, &destination)? {
            return Ok(());
        }
        let bundle = if args.frozen {
            None
        } else {
            let bundle = client
                .sccp()
                .message_proof(&id, parse_proof_height(&args_transfer.at)?)?;
            require_requested_message(&id, &bundle.message_id)?;
            Some(bundle)
        };
        let call = destination.void_call(
            bundle.as_ref(),
            record.nonce,
            args.frozen,
            original.network,
            original.instance,
        )?;
        let mut items = vec![flows::evidence("taira.outbound_to_void", &status)?];
        if let Some(bundle) = &bundle {
            items.push(flows::evidence("verified.void_bundle", bundle)?);
        }
        flows::evm(
            context,
            &original, 
            &flow,
            Action::Void,
            record.network,
            &destination,
            key_file,
            call,
            items,
        )?;
    }
    Ok(())
}

fn require_void_binding(
    event: &iroha_sccp::light_client::proof::SccpNormalizedEventV1,
    deployment: &iroha::data_model::sccp::deployment::SccpDeploymentV1,
    id: &[u8; 32],
    nonce: u64,
) -> Result<()> {
    use iroha::data_model::sccp::outbound::SccpVoidKindV1;
    use iroha_sccp::light_client::proof::SccpNormalizedEventV1;
    let SccpNormalizedEventV1::Void {
        emitter,
        kind,
        first_nonce,
        count,
        message_id_or_zero,
        ..
    } = event
    else {
        return Err(eyre!("proof is not a void event"));
    };
    ensure!(
        emitter.matches(deployment) && *first_nonce == nonce && *count == 1,
        "void event names another deployment or requested nonce"
    );
    ensure!(
        match kind {
            SccpVoidKindV1::Expired => message_id_or_zero == id,
            SccpVoidKindV1::Frozen => *message_id_or_zero == [0; 32],
        },
        "void event identity differs from requested outbound record"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use iroha::data_model::sccp::{
        deployment::{SccpDeploymentV1, SccpEvmDeploymentV1},
        inbound::SccpSourceLocatorV1,
        outbound::SccpVoidKindV1,
    };
    use iroha_sccp::light_client::proof::{SccpNormalizedEventV1, SccpSourceEmitterV1};

    #[test]
    fn refund_proof_must_bind_original_contract_nonce_and_message() {
        let deployment = SccpDeploymentV1::Evm(SccpEvmDeploymentV1 {
            address: [3; 20],
            runtime_code_hash: [4; 32],
        });
        let event = |kind, nonce, count, message, emitter| SccpNormalizedEventV1::Void {
            emitter,
            kind,
            first_nonce: nonce,
            count,
            message_id_or_zero: message,
            locator: SccpSourceLocatorV1 {
                source_height: 19,
                block_hash: [8; 32],
                index_in_block: 2,
            },
        };
        let emitter = SccpSourceEmitterV1::Evm([3; 20]);
        let expired = event(SccpVoidKindV1::Expired, 7, 1, [5; 32], emitter);
        assert!(require_void_binding(&expired, &deployment, &[5; 32], 7).is_ok());
        assert!(require_void_binding(&expired, &deployment, &[6; 32], 7).is_err());
        assert!(require_void_binding(&expired, &deployment, &[5; 32], 8).is_err());
        let foreign = event(
            SccpVoidKindV1::Expired,
            7,
            1,
            [5; 32],
            SccpSourceEmitterV1::Evm([9; 20]),
        );
        assert!(require_void_binding(&foreign, &deployment, &[5; 32], 7).is_err());
        let range = event(SccpVoidKindV1::Frozen, 7, 2, [0; 32], emitter);
        assert!(require_void_binding(&range, &deployment, &[5; 32], 7).is_err());
        let frozen = event(SccpVoidKindV1::Frozen, 7, 1, [0; 32], emitter);
        assert!(require_void_binding(&frozen, &deployment, &[5; 32], 7).is_ok());
        let wrong_sentinel = event(SccpVoidKindV1::Frozen, 7, 1, [5; 32], emitter);
        assert!(require_void_binding(&wrong_sentinel, &deployment, &[5; 32], 7).is_err());
    }
}
