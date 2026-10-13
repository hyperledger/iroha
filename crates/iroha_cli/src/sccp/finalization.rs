//! Verified destination prerequisites, durable mint submission and unsigned export.

use super::*;
use eyre::ensure;

#[derive(norito::derive::JsonSerialize)]
struct UnsignedRequest {
    format: &'static str,
    action: &'static str,
    network: SccpNetworkV1,
    payer: String,
    unsigned_hex: String,
    signing_hash: String,
}

fn emit(
    context: &mut impl RunContext,
    args: &FinalizeArgs,
    client: &BlockingClient,
    original: &origin::AuthenticatedOrigin,
    record: &iroha::data_model::sccp::outbound::SccpOutboundMessageRecordV1,
    message_id: [u8; 32],
) -> Result<()> {
    let bundle = client
        .sccp()
        .message_proof(&message_id, parse_proof_height(&args.at)?)?;
    require_requested_message(&message_id, &bundle.message_id)?;
    let required_control =
        administration::latest_control_nonce(client, original, record.network, record.revision)?;
    let request = if record.network == SccpNetworkV1::TonMainnet {
        ensure!(
            args.payer.is_none(),
            "TON export selects the payer with --ton-wallet"
        );
        let wallet = ton::parse_account(
            args.ton_wallet
                .as_deref()
                .ok_or_else(|| eyre!("TON unsigned export requires --ton-wallet"))?,
        )?;
        let (iroha::data_model::sccp::deployment::SccpDeploymentV1::Ton(deployment), route) =
            route_deployment(client, original, record.network, Some(record.revision))?
        else {
            return Err(eyre!("TON route has another deployment family"));
        };
        let destination = ton::TonDestination::connect(
            &context.sccp_config()?,
            &args.rpc_url,
            deployment.master_account,
            route,
        )?;
        let (action, messages) = match observe_next(
            client,
            original,
            (record.network, record.revision),
            &destination.monitor_observe()?,
            true,
        )? {
            Next::Checkpoint { from, target } => {
                let rotations = client
                    .sccp()
                    .rotations(from, iroha_sccp::v1::destination::MAX_CERTIFICATES_PER_CALL)?;
                (
                    "checkpoint",
                    destination.rotation_messages(
                        &rotations,
                        target,
                        original.network,
                        original.instance,
                        &wallet,
                    )?,
                )
            }
            Next::Control(nonce) => {
                let control = client.sccp().control_proof(
                    record.network,
                    record.revision,
                    nonce,
                    parse_proof_height("latest")?,
                )?;
                (
                    "control",
                    vec![(
                        destination.control_message(
                            &control,
                            original.network,
                            original.instance,
                            &wallet,
                        )?,
                        iroha_sccp_wallet::pure::ton::SEND_MODE_PAY_FEES_SEPARATELY_IGNORE_ERRORS,
                    )],
                )
            }
            Next::Finalize => (
                "finalize",
                vec![(
                    destination.finalize_message(
                        &bundle,
                        original.network,
                        original.instance,
                        required_control,
                        &wallet,
                    )?,
                    iroha_sccp_wallet::pure::ton::SEND_MODE_PAY_FEES_SEPARATELY_IGNORE_ERRORS,
                )],
            ),
        };
        let unsigned = ton::unsigned_wallet_request(destination.lite(), &wallet, &messages)?;
        UnsignedRequest {
            action,
            format: "ton-wallet-v5r1-signing-request-boc",
            network: record.network,
            payer: format!("0:{}", hex::encode(wallet)),
            unsigned_hex: hex::encode(unsigned.to_boc()?),
            signing_hash: hex::encode(unsigned.hash()),
        }
    } else {
        ensure!(
            args.ton_wallet.is_none(),
            "EVM export selects the payer with --payer"
        );
        let payer: [u8; 20] = parse_recipient(
            record.network,
            args.payer
                .as_deref()
                .ok_or_else(|| eyre!("EVM unsigned export requires --payer"))?,
        )?
        .try_into()
        .map_err(|_| eyre!("invalid EVM payer length"))?;
        let destination = evm_destination(
            &context.sccp_config()?,
            client,
            original,
            record.network,
            Some(record.revision),
            &args.rpc_url,
        )?;
        let (action, call) = match observe_next(
            client,
            original,
            (record.network, record.revision),
            &destination.monitor_observe()?,
            true,
        )? {
            Next::Checkpoint { from, target } => {
                let rotations = client
                    .sccp()
                    .rotations(from, iroha_sccp::v1::destination::MAX_CERTIFICATES_PER_CALL)?;
                let mut calls = destination.rotation_calls(
                    &rotations,
                    target,
                    original.network,
                    original.instance,
                )?;
                ensure!(!calls.is_empty(), "rotation plan is empty");
                ("checkpoint", calls.remove(0))
            }
            Next::Control(nonce) => {
                let control = client.sccp().control_proof(
                    record.network,
                    record.revision,
                    nonce,
                    parse_proof_height("latest")?,
                )?;
                (
                    "control",
                    destination.control_call(&control, original.network, original.instance)?,
                )
            }
            Next::Finalize => (
                "finalize",
                destination.finalize_call(
                    &bundle,
                    original.network,
                    original.instance,
                    required_control,
                )?,
            ),
        };
        let unsigned = destination
            .transport()
            .unsigned(payer, call)?
            .export_unsigned();
        UnsignedRequest {
            action,
            format: "eip1559-unsigned-transaction",
            network: record.network,
            payer: format!("0x{}", hex::encode(payer)),
            unsigned_hex: unsigned.hex(),
            signing_hash: hex::encode(unsigned.signing_hash),
        }
    };
    context.print_data(&request)
}

pub(super) fn run<C: RunContext>(context: &mut C, args: FinalizeArgs) -> Result<()> {
    let client = blocking(context)?;
    let original = origin::authenticate_origin(context, &client, &args.origin)?;
    let message_id = parse_word(&args.message_id)?;
    let record = client
        .sccp()
        .message(&message_id)?
        .outbound()
        .map(|view| view.record.clone())
        .ok_or_else(|| eyre!("{} is not an outbound message", args.message_id))?;
    if args.emit {
        return emit(context, &args, &client, &original, &record, message_id);
    }
    let key_file = args
        .key_file
        .as_deref()
        .ok_or_else(|| eyre!("signed finalization requires --key-file"))?;
    let flow = flows::open(
        context,
        iroha_sccp_wallet::journal::SccpFlowKindV1::Outbound,
        &args.flow,
        message_id,
    )?;
    if record.network == SccpNetworkV1::TonMainnet {
        use iroha_sccp_wallet::flow::SccpFlowActionV1 as Action;
        let (destination, wallet) = ton_destination(
            &context.sccp_config()?,
            &client,
            &original,
            record.network,
            Some(record.revision),
            &args.rpc_url,
            args.ton_wallet.as_deref(),
            key_file,
        )?;
        let fresh_finalize = flows::needs_preparation(&flow, Action::Finalize)?;
        if fresh_finalize
            && !ton_ready(
                context,
                &flow,
                &client,
                &original,
                (record.network, record.revision),
                true,
                &destination,
                &wallet,
            )?
        {
            return Ok(());
        }
        let profiles = original.light_client_profiles(&client)?;
        let bundle = if fresh_finalize {
            let bundle = client
                .sccp()
                .message_proof(&message_id, parse_proof_height(&args.at)?)?;
            require_requested_message(&message_id, &bundle.message_id)?;
            Some(bundle)
        } else {
            None
        };
        let items = bundle
            .as_ref()
            .map(|bundle| flows::evidence("taira.verified_message_bundle", bundle))
            .transpose()?
            .into_iter()
            .collect();
        flows::ton(
            context,
            &flow,
            Action::Finalize,
            destination.lite(),
            items,
            |_| {
                let required_control = administration::latest_control_nonce(
                    &client,
                    &original,
                    record.network,
                    record.revision,
                )?;
                destination.prepare_finalize(
                    bundle
                        .as_ref()
                        .ok_or_else(|| eyre!("missing original preparation proof"))?,
                    original.network,
                    original.instance,
                    required_control,
                    &wallet,
                )
            },
            |step| {
                destination.terminal_evidence(
                    &client,
                    profiles,
                    step,
                    iroha_sccp::ton_watch::TerminalEvent::Finalized {
                        message_id,
                        nonce: record.nonce,
                    },
                )
            },
        )?;
        return Ok(());
    }
    let destination = evm_destination(
        &context.sccp_config()?,
        &client,
        &original,
        record.network,
        Some(record.revision),
        &args.rpc_url,
    )?;
    if flows::recover_evm(
        context,
        &flow,
        iroha_sccp_wallet::flow::SccpFlowActionV1::Finalize,
        &destination,
    )? {
        return Ok(());
    }
    if !evm_ready(
        context,
        &flow,
        &client,
        &original,
        (record.network, record.revision),
        true,
        &destination,
        key_file,
    )? {
        return Ok(());
    }
    let bundle = client
        .sccp()
        .message_proof(&message_id, parse_proof_height(&args.at)?)?;
    require_requested_message(&message_id, &bundle.message_id)?;
    let required_control =
        administration::latest_control_nonce(&client, &original, record.network, record.revision)?;
    let calldata = destination.finalize_call(
        &bundle,
        original.network,
        original.instance,
        required_control,
    )?;
    flows::evm(
        context,
        &flow,
        iroha_sccp_wallet::flow::SccpFlowActionV1::Finalize,
        record.network,
        &destination,
        key_file,
        calldata,
        vec![flows::evidence("taira.verified_message_bundle", &bundle)?],
    )?;
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Next {
    Checkpoint { from: u64, target: u64 },
    Control(u64),
    Finalize,
}

fn next(generation: u64, current: u64, applied: u64, newest: u64, paused: bool) -> Result<Next> {
    ensure!(
        generation <= current,
        "destination is ahead of the selected original cut"
    );
    if generation < current {
        return Ok(Next::Checkpoint {
            from: generation,
            target: sync_target(generation, current)?,
        });
    }
    if applied < newest {
        return Ok(Next::Control(newest));
    }
    ensure!(
        !paused,
        "the newest applied control pauses minting; use the refund flow after expiry"
    );
    Ok(Next::Finalize)
}

fn observe_next(
    client: &BlockingClient,
    original: &origin::AuthenticatedOrigin,
    route: (SccpNetworkV1, u32),
    observed: &monitor::Observation,
    minting: bool,
) -> Result<Next> {
    ensure!(
        observed.network == original.network && observed.instance == original.instance,
        "destination differs from the independently selected original network"
    );
    next(
        observed.committee.generation,
        original.current_generation(&client.sccp().capabilities()?)?,
        observed.pause.control_nonce,
        administration::latest_control_nonce(client, original, route.0, route.1)?,
        minting && observed.pause.effective,
    )
}

fn target_item(target: u64) -> iroha_sccp_wallet::journal::SccpEvidenceItemV1 {
    iroha_sccp_wallet::journal::SccpEvidenceItemV1 {
        label: "sccp.prerequisite.target".to_owned(),
        bytes: target.to_be_bytes().to_vec(),
    }
}

#[allow(clippy::too_many_arguments)]
pub(super) fn evm_ready(
    context: &mut impl RunContext,
    flow: &flows::Flow,
    client: &BlockingClient,
    original: &origin::AuthenticatedOrigin,
    route: (SccpNetworkV1, u32),
    minting: bool,
    destination: &evm::EvmDestination,
    key: &std::path::Path,
) -> Result<bool> {
    use iroha_sccp_wallet::flow::SccpFlowActionV1 as Action;
    let pending = flow.pending()?.map(|step| step.record().action);
    if let Some(action @ (Action::Checkpoint | Action::Control)) = pending {
        flows::recover_evm(context, flow, action, destination)?;
        return Ok(false);
    }
    for _ in 0..3 {
        match observe_next(
            client,
            original,
            route,
            &destination.monitor_observe()?,
            minting,
        )? {
            Next::Finalize => return Ok(true),
            Next::Checkpoint { from, target } => {
                let rotations = client
                    .sccp()
                    .rotations(from, iroha_sccp::v1::destination::MAX_CERTIFICATES_PER_CALL)?;
                for call in destination.rotation_calls(
                    &rotations,
                    target,
                    original.network,
                    original.instance,
                )? {
                    if !flows::confirmed(&flows::evm(
                        context,
                        flow,
                        Action::Checkpoint,
                        route.0,
                        destination,
                        key,
                        call,
                        vec![
                            flows::evidence("taira.verified_rotations", &rotations)?,
                            target_item(target),
                        ],
                    )?) {
                        return Ok(false);
                    }
                }
            }
            Next::Control(nonce) => {
                let bundle = client.sccp().control_proof(
                    route.0,
                    route.1,
                    nonce,
                    parse_proof_height("latest")?,
                )?;
                let call =
                    destination.control_call(&bundle, original.network, original.instance)?;
                if !flows::confirmed(&flows::evm(
                    context,
                    flow,
                    Action::Control,
                    route.0,
                    destination,
                    key,
                    call,
                    vec![
                        flows::evidence("taira.verified_control", &bundle)?,
                        target_item(nonce),
                    ],
                )?) {
                    return Ok(false);
                }
            }
        }
    }
    context.println("Destination prerequisites advanced; rerun this flow to continue from its retained progress.")?;
    Ok(false)
}

#[allow(clippy::too_many_arguments)]
pub(super) fn ton_ready(
    context: &mut impl RunContext,
    flow: &flows::Flow,
    client: &BlockingClient,
    original: &origin::AuthenticatedOrigin,
    route: (SccpNetworkV1, u32),
    minting: bool,
    destination: &ton::TonDestination,
    wallet: &ton::TonWallet,
) -> Result<bool> {
    use iroha_sccp_wallet::flow::SccpFlowActionV1 as Action;
    let pending = flow
        .pending()?
        .map(|step| -> Result<_> {
            let action = step.record().action;
            if !matches!(action, Action::Checkpoint | Action::Control) {
                return Ok(None);
            }
            let bytes = &step
                .record()
                .evidence
                .iter()
                .find(|item| item.label == "sccp.prerequisite.target")
                .ok_or_else(|| eyre!("original prerequisite target is absent"))?
                .bytes;
            Ok(Some((
                action,
                u64::from_be_bytes(bytes.as_slice().try_into()?),
            )))
        })
        .transpose()?
        .flatten();
    if let Some((action, target)) = pending {
        flows::ton(
            context,
            flow,
            action,
            destination.lite(),
            Vec::new(),
            |_| Err(eyre!("recovery must not prepare another wallet message")),
            |_| {
                destination.progress_evidence(
                    original.network,
                    original.instance,
                    (action == Action::Control).then_some(target),
                    (action == Action::Checkpoint).then_some(target),
                )
            },
        )?;
        return Ok(false);
    }
    for _ in 0..3 {
        let outcome = match observe_next(
            client,
            original,
            route,
            &destination.monitor_observe()?,
            minting,
        )? {
            Next::Finalize => return Ok(true),
            Next::Checkpoint { from, target } => {
                let rotations = client
                    .sccp()
                    .rotations(from, iroha_sccp::v1::destination::MAX_CERTIFICATES_PER_CALL)?;
                flows::ton(
                    context,
                    flow,
                    Action::Checkpoint,
                    destination.lite(),
                    vec![
                        flows::evidence("taira.verified_rotations", &rotations)?,
                        target_item(target),
                    ],
                    |_| {
                        destination.prepare_rotation(
                            &rotations,
                            target,
                            original.network,
                            original.instance,
                            wallet,
                        )
                    },
                    |_| {
                        destination.progress_evidence(
                            original.network,
                            original.instance,
                            None,
                            Some(target),
                        )
                    },
                )?
            }
            Next::Control(nonce) => {
                let bundle = client.sccp().control_proof(
                    route.0,
                    route.1,
                    nonce,
                    parse_proof_height("latest")?,
                )?;
                flows::ton(
                    context,
                    flow,
                    Action::Control,
                    destination.lite(),
                    vec![
                        flows::evidence("taira.verified_control", &bundle)?,
                        target_item(nonce),
                    ],
                    |_| {
                        destination.prepare_control(
                            &bundle,
                            original.network,
                            original.instance,
                            wallet,
                        )
                    },
                    |_| {
                        destination.progress_evidence(
                            original.network,
                            original.instance,
                            Some(nonce),
                            None,
                        )
                    },
                )?
            }
        };
        if !flows::confirmed(&outcome) {
            return Ok(false);
        }
    }
    context.println("Destination prerequisites advanced; rerun this flow to continue from its retained progress.")?;
    Ok(false)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn finalization_orders_catch_up_then_latest_control_then_mint() {
        assert_eq!(
            next(1, 30, 2, 3, true).unwrap(),
            Next::Checkpoint {
                from: 1,
                target: 17
            }
        );
        assert_eq!(next(30, 30, 2, 3, true).unwrap(), Next::Control(3));
        assert!(next(30, 30, 3, 3, true).is_err());
        assert_eq!(next(30, 30, 3, 3, false).unwrap(), Next::Finalize);
        assert!(next(31, 30, 3, 3, false).is_err());
        assert_eq!(target_item(42).bytes, 42_u64.to_be_bytes());
    }

    #[test]
    fn external_signer_and_recovery_commands_parse_without_private_export_key() {
        use clap::Parser as _;
        #[derive(clap::Parser)]
        struct Cli {
            #[command(subcommand)]
            command: Command,
        }
        let public =
            iroha_crypto::KeyPair::from_seed(vec![1; 32], iroha_crypto::Algorithm::Ed25519)
                .public_key()
                .to_string();
        let hash = iroha_crypto::Hash::new(b"original export").to_string();
        let origin = [
            "--signed-genesis",
            "genesis.nrt",
            "--genesis-manifest",
            "genesis.json",
            "--genesis-public-key",
            &public,
            "--genesis-hash",
            &hash,
            "--at-height",
            "2",
            "--world-snapshot",
            "world.nrt",
            "--world-schema-hash",
            &hash,
        ];
        let mut args = vec![
            "sccp",
            "finalize",
            "--message-id",
            "00",
            "--emit",
            "--payer",
            "0x1111111111111111111111111111111111111111",
        ];
        args.extend(origin);
        let parsed = Cli::try_parse_from(&args).unwrap();
        assert!(matches!(
            parsed.command,
            Command::Finalize(FinalizeArgs {
                emit: true,
                key_file: None,
                ..
            })
        ));
        args.extend(["--key-file", "secret"]);
        assert!(Cli::try_parse_from(&args).is_err());
        for mut args in [
            vec![
                "sccp",
                "deploy",
                "--network",
                "ethereum-mainnet",
                "--revision",
                "1",
                "--max-supply",
                "100",
                "--key-file",
                "key",
            ],
            vec![
                "sccp",
                "ton-retry",
                "--revision",
                "1",
                "--operation-id",
                "1",
                "--ton-wallet",
                "0:00",
                "--key-file",
                "key",
            ],
        ] {
            args.extend(origin);
            Cli::try_parse_from(args).unwrap();
        }
    }
}

/// The independent keeper follows the same journaled checkpoint/control sequence as minting.
pub(super) fn maintain(context: &mut impl RunContext, args: CommitteeSyncArgs) -> Result<()> {
    let config = context.sccp_config()?;
    let client = blocking(context)?;
    let original = origin::authenticate_origin(context, &client, &args.origin)?;
    let network = parse_network(&args.network)?;
    let (_, selected) = route_deployment(&client, &original, network, args.revision)?;
    let revision = selected.route_revision;
    let flow = flows::open(
        context,
        iroha_sccp_wallet::journal::SccpFlowKindV1::CommitteeSync,
        &args.flow,
        flows::intent(
            format!("destination-upkeep:{}:{revision}", network.profile_key()).as_bytes(),
        ),
    )?;
    let ready = if network == SccpNetworkV1::TonMainnet {
        let (destination, wallet) = ton_destination(
            &config,
            &client,
            &original,
            network,
            Some(revision),
            &args.rpc_url,
            args.ton_wallet.as_deref(),
            &args.key_file,
        )?;
        ton_ready(
            context,
            &flow,
            &client,
            &original,
            (network, revision),
            false,
            &destination,
            &wallet,
        )?
    } else {
        let destination = evm_destination(
            &config,
            &client,
            &original,
            network,
            Some(revision),
            &args.rpc_url,
        )?;
        evm_ready(
            context,
            &flow,
            &client,
            &original,
            (network, revision),
            false,
            &destination,
            &args.key_file,
        )?
    };
    if ready {
        context.println("Destination committee and newest control are current.")?;
    }
    Ok(())
}
