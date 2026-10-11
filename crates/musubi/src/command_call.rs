//! Package-aware mutable calls with local argument encoding and durable exact-hash recovery.
use super::*;
use iroha::client::ContractCallDraftIntent;
use iroha_contract_deploy::call::{
    CallAuthorization, CallSimulation, ContractCallDisposition, ContractCallReceipt,
    ContractCallRequest, ContractCallService,
};
use iroha_data_model::{
    account::address::ChainDiscriminantGuard, smart_contract::ContractAddress,
    transaction::FeePaymentIntent,
};
use std::{
    collections::BTreeMap,
    num::NonZeroU64,
    time::{SystemTime, UNIX_EPOCH},
};

#[derive(Args, Debug)]
pub(super) struct CallArgs {
    #[command(flatten)]
    selection: SelectionArgs,
    /// Named configured network; defaults to the workspace network.
    #[arg(long)]
    network: Option<String>,
    /// Native client configuration bound to the selected network.
    #[arg(long)]
    config: Option<PathBuf>,
    /// Require the dependency lock to remain unchanged before building.
    #[arg(long, conflicts_with_all = ["resume", "cancel"])]
    locked: bool,
    /// Declared target, optional when only one contract is built.
    #[arg(long, conflicts_with_all = ["resume", "cancel"])]
    contract: Option<String>,
    /// Mutable public entrypoint, including an explicitly selected lifecycle hook.
    #[arg(long, required_unless_present_any = ["resume", "cancel"], conflicts_with_all = ["resume", "cancel"])]
    entrypoint: Option<String>,
    /// Named JSON arguments; omitted or {} for a zero-parameter entrypoint.
    #[arg(long, default_value = "{}", value_name = "JSON", conflicts_with_all = ["resume", "cancel"])]
    args: String,
    /// Read the named JSON arguments from this file instead of `--args`.
    #[arg(long, value_name = "PATH", conflicts_with_all = ["args", "resume", "cancel"])]
    args_file: Option<PathBuf>,
    /// Signature-bound VM execution budget; defaults to the simulated gas plus headroom.
    #[arg(long, value_parser = clap::value_parser!(u64).range(1..=iroha_contract_deploy::call::MAX_CALL_GAS_LIMIT), conflicts_with_all = ["resume", "cancel"])]
    gas_limit: Option<u64>,
    /// Fee asset for an explicit aggregate cap when the selected network has no finite maxima.
    #[arg(long, requires = "max_fee", conflicts_with_all = ["resume", "cancel"])]
    max_fee_asset: Option<iroha_data_model::asset::AssetDefinitionId>,
    /// Positive aggregate cap across the self-grant and mutable call in --max-fee-asset.
    #[arg(long, requires = "max_fee_asset", conflicts_with_all = ["resume", "cancel"])]
    max_fee: Option<iroha_primitives::numeric::Quantity>,
    /// Persist the reviewed operation without submitting its self-grant or call.
    #[arg(long, conflicts_with_all = ["resume", "cancel"])]
    prepare: bool,
    /// Recover this exact operation without rebuilding or re-signing attempted transactions.
    #[arg(long, value_name = "JOURNAL", conflicts_with = "cancel")]
    resume: Option<PathBuf>,
    /// Cancel an entirely unattempted local operation.
    #[arg(long, value_name = "JOURNAL")]
    cancel: Option<PathBuf>,
}
/// Verified local contract bound to its configured on-chain alias.
pub(super) struct CallTarget<'a> {
    /// Workspace manifest used for continuation commands.
    pub(super) manifest: &'a Path,
    /// Workspace root owning the call journals.
    pub(super) root: &'a Path,
    /// Selected network binding and signer reference.
    pub(super) network: &'a network::SelectedNetwork,
    /// Package declaring the contract target.
    pub(super) package: &'a MusubiPackageSelectorV1,
    /// Manifest-declared contract target.
    pub(super) target: &'a str,
    /// Complete verified local `.to` bytes.
    pub(super) artifact: Vec<u8>,
    /// Exact configured alias.
    pub(super) alias: iroha_data_model::smart_contract::ContractAlias,
}
/// One requested mutable invocation of a [`CallTarget`].
pub(super) struct CallInput<'a> {
    /// Canonical entrypoint selector.
    pub(super) entrypoint: &'a str,
    /// Named JSON arguments.
    pub(super) payload: Value,
    /// Caller-selected gas budget; simulation chooses one when absent.
    pub(super) gas_limit: Option<u64>,
    /// Explicit aggregate fee cap replacing the network's configured maxima.
    pub(super) max_fee: Option<(
        &'a iroha_data_model::asset::AssetDefinitionId,
        &'a iroha_primitives::numeric::Quantity,
    )>,
    /// Persist the plan without submitting it.
    pub(super) prepare: bool,
}
pub(super) fn run_call(
    manifest: Option<&Path>,
    args: &CallArgs,
    progress: &mut dyn FnMut(&str),
) -> CommandResult {
    if let Some(journal) = args.resume.as_ref().or(args.cancel.as_ref()) {
        return recover_call(manifest, args, journal, progress);
    }
    let entrypoint = requested_entrypoint(args)?;
    let payload = iroha_contract_deploy::call::parse_contract_arguments(&argument_source(
        Some(&args.args),
        args.args_file.as_deref(),
    )?)
    .map_err(|error| Diagnostic::new(ErrorCode::Usage, error.to_string()))?;
    progress("Building the selected artifact and preparing its exact mutable call...");
    let build = build::prepare_build(
        manifest,
        &call_build_args(args),
        CompilerActionV1::Build,
        network::NetworkPurpose::Deployment,
    )?;
    let artifact = deploy::select_artifact(&build.execution.artifacts, args.contract.as_deref())?;
    let alias = deploy::bound_alias(&build.network, &artifact.package, &artifact.target)?;
    let bytes = deploy::read_selected_artifact(artifact)?;
    execute_mutable_call(
        CallTarget {
            manifest: build.workspace.root_manifest_path(),
            root: build.workspace.root(),
            network: &build.network,
            package: &artifact.package,
            target: &artifact.target,
            artifact: bytes,
            alias,
        },
        CallInput {
            entrypoint,
            payload,
            gas_limit: args.gas_limit,
            max_fee: args.max_fee_asset.as_ref().zip(args.max_fee.as_ref()),
            prepare: args.prepare,
        },
        progress,
    )
}
/// Simulate, quote, sign, journal and (unless preparing) submit one mutable call.
///
/// Simulation runs before anything is signed: a rejected simulation stops the call, and a
/// successful one sets the signature-bound gas budget with headroom unless the caller chose one.
#[allow(
    clippy::too_many_lines,
    reason = "one recoverable call operation keeps its simulation, fee and journal steps together"
)]
pub(super) fn execute_mutable_call(
    target: CallTarget<'_>,
    input: CallInput<'_>,
    progress: &mut dyn FnMut(&str),
) -> CommandResult {
    let _profile = ChainDiscriminantGuard::enter(target.network.chain_discriminant);
    let service = ContractCallService::new(target.network.load_client()?)
        .map_err(|error| call_diagnostic(&error))?;
    let slot = call_slot(
        target.root,
        &target.network.name,
        target.package,
        target.target,
    )?;
    let writer = AtomicWriteRoot::open_or_create_private(&slot).map_err(atomic_diagnostic)?;
    let _lock = writer
        .lock_exclusive(Path::new("call.lock"))
        .map_err(atomic_diagnostic)?;
    ensure_previous_call_terminal(&writer, &service, target.manifest, target.network)?;
    let address = service
        .resolve_address(&target.alias)
        .map_err(|error| call_diagnostic(&error))?;
    let (intent, payload) =
        trusted_call_intent(&target.artifact, address, input.entrypoint, input.payload)?;
    progress("Simulating the call on current state before signing...");
    let simulation = service
        .simulate(&target.artifact, &intent, payload.as_ref())
        .map_err(|error| call_diagnostic(&error))?;
    let (gas_limit, gas_note) = choose_gas_limit(input.gas_limit, &simulation)?;
    let gas_limit = NonZeroU64::new(gas_limit)
        .ok_or_else(|| Diagnostic::new(ErrorCode::Usage, "gas limit must be positive"))?;
    let fee = gas_limited_fee_payment(target.network, gas_limit)?;
    let mut maxima = BTreeMap::new();
    for component in fee.charge_limits() {
        let total = maxima
            .entry(component.asset_definition_id().clone())
            .or_insert_with(iroha_primitives::numeric::Quantity::zero);
        *total = total
            .checked_add(component.max_amount())
            .map_err(|_| Diagnostic::new(ErrorCode::Usage, "configured call fee cap overflow"))?;
    }
    if let Some((asset, cap)) = input.max_fee {
        if cap.is_zero() {
            return Err(Diagnostic::new(
                ErrorCode::Usage,
                "--max-fee must be positive",
            ));
        }
        maxima = BTreeMap::from([(asset.clone(), cap.clone())]);
    }
    if maxima.is_empty() {
        return Err(Diagnostic::new(
            ErrorCode::Usage,
            "call requires finite configured fee maxima or --max-fee-asset and --max-fee",
        ));
    }
    let signing_deadline_unix_ms = u64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|error| call_diagnostic(&error.into()))?
            .as_millis(),
    )
    .ok()
    .and_then(|now| now.checked_add(60_000))
    .ok_or_else(|| Diagnostic::new(ErrorCode::Usage, "call signing deadline overflow"))?;
    let prepared = service
        .prepare(ContractCallRequest {
            artifact: target.artifact,
            alias: target.alias,
            payload,
            intent,
            fee_payment: fee,
            authorization: CallAuthorization {
                signing_deadline_unix_ms,
                max_total_fees: maxima,
            },
        })
        .map_err(|error| call_diagnostic(&error))?;
    let operation_id = prepared
        .operation_id()
        .map_err(|error| call_diagnostic(&error))?;
    let journal = slot.join(&operation_id);
    service
        .persist(&prepared, &journal)
        .map_err(|error| call_diagnostic(&error))?;
    writer
        .replace(Path::new("active-journal"), operation_id.as_bytes())
        .map_err(atomic_diagnostic)?;
    let permission_notice = if prepared.grants_entrypoint_to_self() {
        "The operation first grants this exact entrypoint to the calling account and waits for Applied.\n"
    } else {
        ""
    };
    let resume = deploy::contract_resume_command("call", target.manifest, target.network, &journal);
    if input.prepare {
        return Ok(Success {
            message: format!(
                "Prepared {} on {}\n{gas_note}\n{permission_notice}Journal: {}\nNext: {resume}",
                prepared.entrypoint(),
                prepared.contract_address(),
                journal.display()
            ),
            data: object([
                ("operation_id", Value::from(operation_id)),
                ("journal", Value::from(journal.display().to_string())),
                (
                    "grants_entrypoint_to_self",
                    Value::Bool(prepared.grants_entrypoint_to_self()),
                ),
                ("gas_limit", Value::from(gas_limit.get())),
                ("simulation", simulation_json(&simulation)),
            ]),
        });
    }
    progress(&format!(
        "{gas_note}\n{permission_notice}Submitting the retained operation; interrupted work resumes with `{resume}`"
    ));
    let receipt = service.resume(&journal).map_err(|error| {
        call_diagnostic(&error)
            .with_context("journal", journal.display().to_string())
            .with_help(format!("resume the same operation with `{resume}`"))
    })?;
    let mut success = call_receipt(&receipt, &journal)?;
    if let Value::Object(data) = &mut success.data {
        data.insert("gas_limit".to_owned(), Value::from(gas_limit.get()));
        data.insert("simulation".to_owned(), simulation_json(&simulation));
    }
    Ok(success)
}
/// Largest named-argument JSON file accepted by `--args-file`.
const ARGUMENT_FILE_BYTES: u64 = 64 * 1024;
/// Return the named JSON arguments given inline with `--args` or in an `--args-file`.
///
/// `call`, `view` and `deploy --activate` share these two flags; clap admits at most one of them.
pub(super) fn argument_source(
    inline: Option<&str>,
    file: Option<&Path>,
) -> Result<String, Diagnostic> {
    let Some(path) = file else {
        return Ok(inline.unwrap_or("{}").to_owned());
    };
    let bytes = read_bounded_single_link_regular_file_v1(path, ARGUMENT_FILE_BYTES)
        .map_err(|error| io_diagnostic("read --args-file", path, &error))?;
    String::from_utf8(bytes).map_err(|_| {
        Diagnostic::new(ErrorCode::Usage, "--args-file must contain UTF-8 JSON")
            .with_context("path", path.display().to_string())
    })
}
/// Choose the signature-bound gas budget from the caller's request and the simulation outcome.
fn choose_gas_limit(
    requested: Option<u64>,
    simulation: &CallSimulation,
) -> Result<(u64, String), Diagnostic> {
    match (simulation, requested) {
        (CallSimulation::Rejected { message, gas_used }, _) => Err(Diagnostic::new(
            ErrorCode::Network,
            "the node rejected the simulated call; nothing was signed or submitted",
        )
        .with_context("reason", message.clone())
        .with_context("simulated_gas", gas_used.to_string())),
        (CallSimulation::Executed { gas_used }, Some(limit)) if limit < *gas_used => {
            Err(Diagnostic::new(
                ErrorCode::Usage,
                "--gas-limit is below the gas the simulated call consumed",
            )
            .with_context("gas_limit", limit.to_string())
            .with_context("simulated_gas", gas_used.to_string())
            .with_help(format!(
                "omit --gas-limit, or pass at least {}",
                iroha_contract_deploy::call::gas_limit_with_headroom(*gas_used)
            )))
        }
        (CallSimulation::Executed { gas_used }, Some(limit)) => Ok((
            limit,
            format!("Simulated gas: {gas_used}; gas limit: {limit} (requested)"),
        )),
        (CallSimulation::Executed { gas_used }, None) => {
            let limit = iroha_contract_deploy::call::gas_limit_with_headroom(*gas_used);
            Ok((
                limit,
                format!(
                    "Simulated gas: {gas_used}; gas limit: {limit} (simulated gas plus headroom)"
                ),
            ))
        }
        (CallSimulation::RequiresSelfGrant, requested) => {
            let limit =
                requested.unwrap_or(iroha_contract_deploy::call::UNSIMULATED_CALL_GAS_LIMIT);
            Ok((
                limit,
                format!(
                    "Not simulated: this call first grants its own entrypoint permission. Gas limit: {limit}{}",
                    if requested.is_some() {
                        " (requested)"
                    } else {
                        "; pass --gas-limit to choose another budget"
                    }
                ),
            ))
        }
    }
}
fn simulation_json(simulation: &CallSimulation) -> Value {
    match simulation {
        CallSimulation::Executed { gas_used } => object([
            ("status", Value::from("executed")),
            ("gas_used", Value::from(*gas_used)),
        ]),
        CallSimulation::Rejected { message, gas_used } => object([
            ("status", Value::from("rejected")),
            ("gas_used", Value::from(*gas_used)),
            ("message", Value::from(message.clone())),
        ]),
        CallSimulation::RequiresSelfGrant => {
            object([("status", Value::from("requires_self_grant"))])
        }
    }
}
/// Cancel an entirely unattempted call, or recover its retained permission and call hashes.
fn recover_call(
    manifest: Option<&Path>,
    args: &CallArgs,
    journal: &Path,
    progress: &mut dyn FnMut(&str),
) -> CommandResult {
    let (workspace, _) = load_selected_workspace(manifest, &args.selection)?;
    let selected = network::select_network(
        workspace.root(),
        args.network.as_deref(),
        args.config.as_deref(),
        None,
        network::NetworkPurpose::Deployment,
    )?;
    let _profile = ChainDiscriminantGuard::enter(selected.chain_discriminant);
    let service = ContractCallService::new(selected.load_client()?)
        .map_err(|error| call_diagnostic(&error))?;
    if args.cancel.is_some() {
        let operation_id = service
            .cancel(journal)
            .map_err(|error| call_diagnostic(&error))?;
        return Ok(Success {
            message: format!("Cancelled unattempted call: {}", journal.display()),
            data: object([
                ("operation_id", Value::from(operation_id)),
                ("status", Value::from("cancelled")),
                ("journal", Value::from(journal.display().to_string())),
            ]),
        });
    }
    progress("Recovering the retained permission and call hashes...");
    call_receipt(
        &service.resume(journal).map_err(|error| {
            call_diagnostic(&error).with_context("journal", journal.display().to_string())
        })?,
        journal,
    )
}
/// Return the requested mutable entrypoint once it is a non-empty canonical selector.
fn requested_entrypoint(args: &CallArgs) -> Result<&str, Diagnostic> {
    let entrypoint = args
        .entrypoint
        .as_deref()
        .ok_or_else(|| Diagnostic::new(ErrorCode::Usage, "call requires --entrypoint"))?;
    if entrypoint.is_empty() || entrypoint.trim() != entrypoint {
        return Err(Diagnostic::new(
            ErrorCode::Usage,
            "entrypoint must use a non-empty canonical selector",
        ));
    }
    Ok(entrypoint)
}
/// Build the called contract online; only the dependency lock policy is caller-selected.
fn call_build_args(args: &CallArgs) -> BuildArgs {
    BuildArgs {
        profile: "production".into(),
        selection: args.selection.clone(),
        mode: GraphModeArgs {
            locked: args.locked,
            offline: false,
            frozen: false,
        },
        registry: RegistryReadArgs {
            config: args.config.clone(),
        },
        network: args.network.clone(),
        chain_discriminant: None,
        zk: false,
        deny_warnings: false,
    }
}
/// Bind the network's explicit fee payer to the signature-bound call gas limit.
fn gas_limited_fee_payment(
    network: &network::SelectedNetwork,
    gas_limit: NonZeroU64,
) -> Result<FeePaymentIntent, Diagnostic> {
    Ok(match deploy::selected_fee_payment(network)? {
        FeePaymentIntent::Authority(payment) => {
            FeePaymentIntent::authority(payment.charge_limits, Some(gas_limit))
        }
        FeePaymentIntent::Sponsor(payment) => FeePaymentIntent::sponsor(
            payment.program_id,
            payment.program_revision,
            payment.charge_limits,
            Some(gas_limit),
        ),
    })
}
fn trusted_call_intent(
    artifact: &[u8],
    address: ContractAddress,
    entrypoint: &str,
    payload: Value,
) -> Result<(ContractCallDraftIntent, Option<Value>), Diagnostic> {
    iroha_contract_deploy::call::trusted_contract_intent(
        artifact, address, entrypoint, payload, false,
    )
    .map_err(|error| Diagnostic::new(ErrorCode::Usage, error.to_string()))
}

fn call_slot(
    root: &Path,
    network_name: &str,
    package: &MusubiPackageSelectorV1,
    target: &str,
) -> Result<PathBuf, Diagnostic> {
    network::validate_name(network_name)?;
    network::validate_contract_target(target)?;
    Ok(root.join("target/call").join(network_name).join(
        blake3::hash(network::contract_key(package, target).as_bytes())
            .to_hex()
            .as_str(),
    ))
}
fn ensure_previous_call_terminal(
    writer: &AtomicWriteRoot,
    service: &ContractCallService,
    manifest: &Path,
    network: &network::SelectedNetwork,
) -> Result<(), Diagnostic> {
    let Some(bytes) = writer
        .load_immutable(Path::new("active-journal"), 64)
        .map_err(atomic_diagnostic)?
    else {
        return Ok(());
    };
    let id = std::str::from_utf8(&bytes)
        .map_err(|_| Diagnostic::new(ErrorCode::Io, "invalid active call journal"))?;
    deploy::validate_journal_id(id)?;
    let journal = writer.path().join(id);
    if matches!(
        service
            .inspect(&journal)
            .map_err(|error| call_diagnostic(&error))?,
        ContractCallDisposition::Pending
    ) {
        return Err(Diagnostic::new(
            ErrorCode::Network,
            "an earlier call is unresolved; a replacement operation was not prepared",
        )
        .with_context("journal", journal.display().to_string())
        .with_help(format!(
            "resume the exact call with `{}`",
            deploy::contract_resume_command("call", manifest, network, &journal)
        )));
    }
    Ok(())
}
fn call_diagnostic(error: &eyre::Report) -> Diagnostic {
    Diagnostic::new(ErrorCode::Network, format!("{error:#}"))
}
/// Human summary of the gas and fee an Applied transaction settled.
///
/// The charge comes from the committed fee receipt; a node that does not report it leaves the
/// Applied evidence intact and only this line says so.
pub(super) fn charge_line(
    label: &str,
    evidence: &iroha_contract_deploy::AppliedEvidence,
) -> String {
    evidence.charge.as_ref().map_or_else(
        || format!("{label}: gas and fee not reported by the node\n"),
        |charge| {
            format!(
                "{label}: gas used {}; fee {} {}\n",
                charge.gas_used, charge.fee_amount, charge.fee_asset
            )
        },
    )
}
fn call_receipt(receipt: &ContractCallReceipt, journal: &Path) -> CommandResult {
    let mut charges = String::new();
    if let Some(grant) = &receipt.grant {
        charges.push_str(&charge_line("Self-grant", grant));
    }
    charges.push_str(&charge_line("Call", &receipt.call));
    Ok(Success {
        message: format!(
            "Applied: {}\nContract: {}\nEntrypoint: {}\nHeight: {} ({}, {})\n{charges}Receipt: {}",
            receipt.call.hash,
            receipt.contract_address,
            receipt.entrypoint,
            receipt.call.block_height,
            receipt.call.scope,
            receipt.call.resolved_from,
            journal
                .join(iroha_contract_deploy::RECEIPT_FILE_NAME)
                .display()
        ),
        data: object([
            (
                "receipt",
                norito::json::to_value(receipt)
                    .map_err(|error| Diagnostic::new(ErrorCode::Internal, error.to_string()))?,
            ),
            ("journal", Value::from(journal.display().to_string())),
        ]),
    })
}
#[cfg(test)]
#[path = "command_call_tests.rs"]
mod tests;
