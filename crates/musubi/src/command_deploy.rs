//! Package-aware native deployment and authenticated on-chain views.
use super::*;
use crate::compiler::CompilerArtifactV1;
use crate::deployment_runtime::{DeploymentSlot, RetainedDeployment, RetryRequest};
use iroha_contract_deploy::{
    DeploymentError, DeploymentPreflight, DeploymentProgress, DeploymentReceipt, DeploymentRequest,
    DeploymentService, LifecycleHook,
};
use iroha_data_model::{
    account::address::ChainDiscriminantGuard,
    smart_contract::{ContractAddress, ContractAlias, ContractArtifactId},
    transaction::FeePaymentIntent,
};

#[derive(Args, Debug)]
pub(super) struct DeployArgs {
    #[command(flatten)]
    selection: SelectionArgs,
    /// Named configured network; uses the workspace default when omitted.
    #[arg(long)]
    network: Option<String>,
    /// Explicit native client file, which must match the pinned network identity.
    #[arg(long, value_name = "PATH")]
    config: Option<PathBuf>,
    /// Require the existing dependency lock to remain unchanged before building.
    #[arg(long)]
    locked: bool,
    /// One declared contract target; may be omitted when exactly one target is built.
    #[arg(long)]
    contract: Option<String>,
    /// Prepare and persist the exact signed plan without submitting it.
    #[arg(long, conflicts_with_all = ["resume", "cancel"])]
    prepare: bool,
    /// Resume this exact deployment journal, without rebuilding or re-signing its transactions.
    #[arg(long, value_name = "JOURNAL", conflicts_with_all = ["cancel", "contract", "locked", "workspace", "packages", "exclude"])]
    resume: Option<PathBuf>,
    /// Cancel an unattempted local plan; attempted transactions still require exact-hash recovery.
    #[arg(long, value_name = "JOURNAL", conflicts_with_all = ["contract", "locked", "workspace", "packages", "exclude"])]
    cancel: Option<PathBuf>,
    /// Deploy this prebuilt `.to` after verifying that the locked package source reproduces it.
    #[arg(long, value_name = "PATH", requires = "artifact_manifest", conflicts_with_all = ["resume", "cancel"])]
    artifact: Option<PathBuf>,
    /// Compiler manifest written beside the prebuilt artifact (`<name>.manifest.json`).
    #[arg(long, value_name = "PATH", requires = "artifact")]
    artifact_manifest: Option<PathBuf>,
    /// Run the seiyaku's hajimari/始まり hook after the deployment is Applied, as one recoverable
    /// call operation; the instance rejects every other call and view until it runs.
    #[arg(long, conflicts_with_all = ["prepare", "resume", "cancel"])]
    activate: bool,
    /// Named JSON arguments for the activating hook; omitted or {} when it takes none.
    #[arg(long, value_name = "JSON", requires = "activate")]
    args: Option<String>,
    /// Read the activating hook's named JSON arguments from this file instead of `--args`.
    #[arg(
        long,
        value_name = "PATH",
        requires = "activate",
        conflicts_with = "args"
    )]
    args_file: Option<PathBuf>,
    /// Signature-bound VM budget for the activating hook.
    #[arg(long, requires = "activate", value_parser = clap::value_parser!(u64).range(1..=iroha_contract_deploy::call::MAX_CALL_GAS_LIMIT))]
    gas_limit: Option<u64>,
    /// Fee asset for an explicit activation fee cap when the network has no finite maxima.
    #[arg(long, requires_all = ["activate", "max_fee"])]
    max_fee_asset: Option<iroha_data_model::asset::AssetDefinitionId>,
    /// Positive aggregate activation cap across its self-grant and hook call, in --max-fee-asset.
    #[arg(long, requires_all = ["activate", "max_fee_asset"])]
    max_fee: Option<iroha_primitives::numeric::Quantity>,
}

#[derive(Args, Debug)]
pub(super) struct ViewArgs {
    #[command(flatten)]
    selection: SelectionArgs,
    /// Named network; uses the configured workspace default when omitted.
    #[arg(long)]
    network: Option<String>,
    /// Declared contract target with an exact alias binding for this network.
    #[arg(long)]
    contract: String,
    /// Public kotodama view entrypoint.
    #[arg(long)]
    entrypoint: String,
    /// Named JSON arguments; omitted or {} for a zero-parameter view.
    #[arg(long, default_value = "{}", value_name = "JSON")]
    args: String,
    /// Read the named JSON arguments from this file instead of `--args`.
    #[arg(long, value_name = "PATH", conflicts_with = "args")]
    args_file: Option<PathBuf>,
    /// VM execution budget for the read-only view.
    #[arg(long, default_value_t = 1_000_000, value_parser = clap::value_parser!(u64).range(1..=10_000_000))]
    gas_limit: u64,
}

pub(super) fn run_deploy(
    manifest: Option<&Path>,
    args: &DeployArgs,
    progress: &mut dyn FnMut(&str),
) -> CommandResult {
    progress(if args.cancel.is_some() {
        "Validating unattempted deployment cancellation..."
    } else if args.resume.is_some() {
        "Recovering the exact retained deployment plan..."
    } else {
        "Preparing the contract, network binding, permissions, and exact fee quotes..."
    });
    if let Some(journal) = args.resume.as_ref().or(args.cancel.as_ref()) {
        return recover_deployment(manifest, args, journal, progress);
    }
    let activation_payload = if args.args.is_some() || args.args_file.is_some() {
        Some(
            iroha_contract_deploy::call::parse_contract_arguments(&call::argument_source(
                args.args.as_deref(),
                args.args_file.as_deref(),
            )?)
            .map_err(|error| Diagnostic::new(ErrorCode::Usage, error.to_string()))?,
        )
    } else {
        None
    };
    let build_args = BuildArgs {
        profile: "production".into(),
        selection: args.selection.clone(),
        mode: GraphModeArgs {
            locked: args.locked || args.artifact.is_some(),
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
    };
    let build = build::prepare_build(
        manifest,
        &build_args,
        CompilerActionV1::Build,
        network::NetworkPurpose::Deployment,
    )?;
    let artifact = select_artifact(&build.execution.artifacts, args.contract.as_deref())?;
    let alias = bound_alias(&build.network, &artifact.package, &artifact.target)?;
    let artifact_bytes = match (&args.artifact, &args.artifact_manifest) {
        (Some(prebuilt), Some(prebuilt_manifest)) => {
            read_reproduced_prebuilt_artifact(artifact, prebuilt, prebuilt_manifest)?
        }
        _ => read_selected_artifact(artifact)?,
    };
    let hook = LifecycleHook::from_artifact(&artifact_bytes);
    let activation_artifact = (args.activate && hook.is_some()).then(|| artifact_bytes.clone());
    let fee_payment = selected_fee_payment(&build.network)?;
    let _profile = ChainDiscriminantGuard::enter(build.network.chain_discriminant);
    if args.activate {
        check_activation_arguments(&artifact_bytes, hook.as_ref(), activation_payload.as_ref())?;
    }
    let service = DeploymentService::new(build.network.load_client()?)
        .map_err(|error| deployment_diagnostic(&error))?;
    let slot = deployment_slot(
        build.workspace.root(),
        &build.network.name,
        &artifact.package,
        &artifact.target,
    )?;
    let session = DeploymentSlot::open_package(&slot, alias.clone())
        .map_err(|error| runtime_diagnostic(&error))?;
    let retained = prepare_or_resume_deployment(
        &service,
        &session,
        &DeploymentRequest {
            artifact: artifact_bytes,
            alias,
            fee_payment,
            governance_approvers: Vec::new(),
        },
        args.prepare,
        progress,
    )
    .map_err(|error| runtime_diagnostic(&error))?;
    let journal = retained.journal;
    // A deployment completed by this command has not run its hook yet; one completed by an
    // earlier command may have been activated since.
    let known_pending = !retained.completed_earlier;
    if let Some(receipt) = retained.receipt {
        let mut deployed = receipt_output(&receipt, &journal)?;
        if !args.activate {
            if let Some(hook) = &hook {
                deployed.message.push_str(&activation_hint(
                    hook,
                    known_pending,
                    build.workspace.root_manifest_path(),
                    &build.network,
                    &artifact.package,
                    &artifact.target,
                ));
                if let Value::Object(data) = &mut deployed.data {
                    data.insert(
                        "activation".to_owned(),
                        object([
                            (
                                "status",
                                Value::from(if known_pending {
                                    "pending"
                                } else {
                                    "unverified"
                                }),
                            ),
                            ("entrypoint", Value::from(hook.name.clone())),
                            (
                                "command",
                                Value::from(activation_command(
                                    build.workspace.root_manifest_path(),
                                    &build.network,
                                    &artifact.package,
                                    &artifact.target,
                                    hook,
                                    None,
                                )),
                            ),
                        ]),
                    );
                }
            }
            return Ok(deployed);
        }
        let (Some(hook), Some(activation_artifact)) = (hook, activation_artifact) else {
            let _ = write!(
                deployed.message,
                "\nThis seiyaku declares no {}; the instance is already active.",
                hajimari_label()
            );
            return Ok(deployed);
        };
        progress(&format!(
            "Activating the deployed instance with its {} hook...",
            hajimari_label()
        ));
        let activation = call::execute_mutable_call(
            call::CallTarget {
                manifest: build.workspace.root_manifest_path(),
                root: build.workspace.root(),
                network: &build.network,
                package: &artifact.package,
                target: &artifact.target,
                artifact: activation_artifact,
                alias: receipt.contract_alias.clone(),
            },
            call::CallInput {
                entrypoint: &hook.name,
                payload: activation_payload
                    .clone()
                    .unwrap_or_else(|| Value::Object(norito::json::Map::new())),
                gas_limit: args.gas_limit,
                max_fee: args.max_fee_asset.as_ref().zip(args.max_fee.as_ref()),
                prepare: false,
            },
            progress,
        )
        .map_err(|diagnostic| {
            diagnostic
                .with_context(
                    "deployment_receipt",
                    iroha_contract_deploy::receipt_path(&journal)
                        .display()
                        .to_string(),
                )
                .with_context(
                    "activate_with",
                    activation_command(
                        build.workspace.root_manifest_path(),
                        &build.network,
                        &artifact.package,
                        &artifact.target,
                        &hook,
                        activation_payload.as_ref(),
                    ),
                )
        })?;
        return Ok(Success {
            message: format!(
                "{}\nActivated with {}:\n{}",
                deployed.message, hook.name, activation.message
            ),
            data: object([
                ("deployment", deployed.data),
                ("activation", activation.data),
            ]),
        });
    }
    if args.prepare {
        return Ok(Success {
            message: format!(
                "Prepared {} for {}\n{}Plan: {}\nNext: {}",
                artifact.target,
                build.network.name,
                render_preflight(&retained.preflight),
                journal.display(),
                contract_resume_command(
                    "deploy",
                    build.workspace.root_manifest_path(),
                    &build.network,
                    &journal,
                )
            ),
            data: object([
                ("journal", Value::from(journal.display().to_string())),
                ("preflight", deployment_json(&retained.preflight)?),
            ]),
        });
    }
    Err(Diagnostic::new(
        ErrorCode::Network,
        "deployment returned no authenticated receipt",
    ))
}

/// Shared fresh package consumer: inspect original publication before signing a new plan.
fn prepare_or_resume_deployment(
    service: &DeploymentService,
    session: &DeploymentSlot,
    request: &DeploymentRequest,
    prepare_only: bool,
    progress: &mut dyn FnMut(&str),
) -> eyre::Result<RetainedDeployment> {
    let code_hash = ivm::verify_contract_artifact(&request.artifact)
        .map_err(|error| eyre::eyre!("invalid contract artifact: {error}"))?
        .code_hash;
    if let Some(retained) = session.recover_matching(
        service,
        RetryRequest {
            code_hash,
            alias: &request.alias,
            fee_payment: &request.fee_payment,
            prepare_only,
        },
        &mut |_| Ok(()),
        &mut |event| progress(&render_progress(event)),
    )? {
        return Ok(retained);
    }
    let prepared = service.prepare(request)?;
    let journal = session.persist(service, &prepared)?;
    let receipt = if prepare_only {
        None
    } else {
        Some(session.execute(service, &prepared, &journal, &mut |event| {
            progress(&render_progress(event))
        })?)
    };
    Ok(RetainedDeployment {
        preflight: prepared.preflight().clone(),
        journal,
        receipt,
        completed_earlier: false,
    })
}

/// Cancel an unattempted plan, or resume an exact retained deployment journal without
/// rebuilding or re-signing its transactions.
fn recover_deployment(
    manifest: Option<&Path>,
    args: &DeployArgs,
    journal: &Path,
    progress: &mut dyn FnMut(&str),
) -> CommandResult {
    let (workspace, _) = load_selected_workspace(manifest, &args.selection)?;
    let network = network::select_network(
        workspace.root(),
        args.network.as_deref(),
        args.config.as_deref(),
        None,
        network::NetworkPurpose::Deployment,
    )?;
    let _profile = ChainDiscriminantGuard::enter(network.chain_discriminant);
    let service = DeploymentService::new(network.load_client()?)
        .map_err(|error| deployment_diagnostic(&error))?;
    let journal = retained_deployment_journal(workspace.root(), &network.name, journal)?;
    let slot = journal.parent().expect("admitted deployment slot");
    let slot_name = slot
        .file_name()
        .and_then(|name| name.to_str())
        .expect("admitted slot digest");
    let mut bindings = network
        .contracts
        .iter()
        .filter(|(key, _)| blake3::hash(key.as_bytes()).to_hex().as_str() == slot_name);
    let (contract_key, alias) = bindings
        .next()
        .filter(|_| bindings.next().is_none())
        .ok_or_else(|| {
            Diagnostic::new(
                ErrorCode::Usage,
                "deployment journal has no exact contract binding in the selected network",
            )
        })?;
    let session = DeploymentSlot::open_package_read(slot, alias.clone())
        .map_err(|error| runtime_diagnostic(&error))?;
    if args.cancel.is_some() {
        let cancellation = session
            .cancel(&service, &journal)
            .map_err(|error| runtime_diagnostic(&error))?;
        return Ok(Success {
            message: format!(
                "Cancelled unattempted deployment plan: {}",
                journal.display()
            ),
            data: object([
                ("status", Value::from("cancelled")),
                ("journal", Value::from(journal.display().to_string())),
                ("cancellation", deployment_json(&cancellation)?),
            ]),
        });
    }
    let expected = service.retained_preflight(&journal).map_err(|error| {
        deployment_diagnostic(&error).with_context("journal", journal.display().to_string())
    })?;
    let receipt = session
        .resume(&service, &journal, &expected, &mut |event| {
            progress(&render_progress(event))
        })
        .map_err(|error| {
            runtime_diagnostic(&error).with_context("journal", journal.display().to_string())
        })?;
    let mut resumed = receipt_output(&receipt, &journal)?;
    // The hint is presentation only; a failed artifact read leaves the Applied receipt intact.
    if let Ok(Some(hook)) = service.retained_lifecycle_hook(&journal, receipt.code_hash)
        && let Some((package, target)) = contract_key
            .split_once("::")
            .and_then(|(package, target)| Some((package.parse().ok()?, target)))
    {
        resumed.message.push_str(&activation_hint(
            &hook,
            false,
            workspace.root_manifest_path(),
            &network,
            &package,
            target,
        ));
    }
    Ok(resumed)
}

/// Label naming both spellings of the activation hook, from the shared keyword glossary.
fn hajimari_label() -> String {
    kotodama_lang::glossary::by_spelling("hajimari").map_or_else(
        || "hajimari".to_owned(),
        kotodama_lang::glossary::BrandedKeyword::label,
    )
}

/// Reject activation arguments that the hook cannot accept before anything is signed.
///
/// Arguments are checked against the verified artifact's hook schema in the network's address
/// profile, so a deployment never completes only for its activation to fail on its arguments.
fn check_activation_arguments(
    artifact: &[u8],
    hook: Option<&LifecycleHook>,
    payload: Option<&Value>,
) -> Result<(), Diagnostic> {
    let empty = Value::Object(norito::json::Map::new());
    match hook {
        None if payload.is_some_and(|payload| payload != &empty) => Err(Diagnostic::new(
            ErrorCode::Usage,
            format!(
                "--args are arguments for {}, which this seiyaku does not declare",
                hajimari_label()
            ),
        )
        .with_help("omit --args; the deployed instance is active without activation")),
        None => Ok(()),
        Some(hook) => iroha_contract_deploy::call::check_contract_arguments(
            artifact,
            &hook.name,
            payload.unwrap_or(&empty),
            false,
        )
        .map_err(|error| {
            Diagnostic::new(
                ErrorCode::Usage,
                format!(
                    "activation arguments do not match {}; nothing was signed or submitted",
                    hajimari_label()
                ),
            )
            .with_context("reason", error.to_string())
            .with_help(format!(
                "pass the hook's named arguments, for example --args '{}'",
                hook.arguments_template()
            ))
        }),
    }
}

/// Exact command that activates a deployed seiyaku through its hook.
///
/// `arguments` are the caller's activation arguments; without them the command carries the hook's
/// [`LifecycleHook::arguments_template`].
fn activation_command(
    manifest: &Path,
    network: &network::SelectedNetwork,
    package: &MusubiPackageSelectorV1,
    target: &str,
    hook: &LifecycleHook,
    arguments: Option<&Value>,
) -> String {
    let mut command = format!(
        "musubi --manifest-path {} call --network {}",
        quote_cli_argument(&manifest.display().to_string()),
        quote_cli_argument(&network.name),
    );
    if let Some(config) = &network.config {
        let _ = write!(
            command,
            " --config {}",
            quote_cli_argument(&config.display().to_string())
        );
    }
    let arguments = arguments
        .and_then(|arguments| norito::json::to_string(arguments).ok())
        .unwrap_or_else(|| hook.arguments_template());
    let _ = write!(
        command,
        " --package {} --contract {} --entrypoint {} --args {}",
        quote_cli_argument(&package.to_string()),
        quote_cli_argument(target),
        quote_cli_argument(&hook.name),
        quote_cli_argument(&arguments),
    );
    command
}

/// Explain that a deployed instance stays inactive until its hook runs, with the exact command.
///
/// `known_pending` is true only when this command itself completed the deployment; a deployment
/// that completed earlier may already have been activated, so the hint is then conditional.
fn activation_hint(
    hook: &LifecycleHook,
    known_pending: bool,
    manifest: &Path,
    network: &network::SelectedNetwork,
    package: &MusubiPackageSelectorV1,
    target: &str,
) -> String {
    let command = activation_command(manifest, network, package, target, hook, None);
    let placeholders = if hook.params.is_empty() {
        ""
    } else {
        "\nReplace each `<type>` placeholder with the argument value; int, decimal and quantity \
         values are canonical decimal strings such as \"5\"."
    };
    if known_pending {
        format!(
            "\nThis seiyaku declares {}; the deployed instance rejects every other call and view \
             until it runs.\nNext: {command}{placeholders}\n(`musubi deploy --activate` deploys and \
             activates in one step; pass the hook's arguments with --args.)",
            hajimari_label(),
        )
    } else {
        format!(
            "\nThis seiyaku declares {}; until it has run once, the instance rejects every other \
             call and view.\nIf it has not run yet: {command}{placeholders}",
            hajimari_label(),
        )
    }
}

/// Read a prebuilt artifact and require that the locked package build reproduces it exactly.
///
/// The compiler manifest written beside the artifact must name the same code and ABI hashes, so an
/// audited `.to` is deployed only when it is the reproducible output of the declared source.
pub(super) fn read_reproduced_prebuilt_artifact(
    built: &CompilerArtifactV1,
    prebuilt: &Path,
    prebuilt_manifest: &Path,
) -> Result<Vec<u8>, Diagnostic> {
    let bytes = read_bounded_single_link_regular_file_v1(
        prebuilt,
        iroha_contract_deploy::MAX_DEPLOYMENT_ARTIFACT_BYTES as u64,
    )
    .map_err(|error| io_diagnostic("read prebuilt contract", prebuilt, &error))?;
    let verified = ivm::verify_contract_artifact(&bytes)
        .map_err(|error| Diagnostic::new(ErrorCode::PackageInvalid, error.to_string()))?;
    let manifest_bytes =
        read_bounded_single_link_regular_file_v1(prebuilt_manifest, 4 * 1024 * 1024).map_err(
            |error| io_diagnostic("read prebuilt contract manifest", prebuilt_manifest, &error),
        )?;
    let manifest: iroha_data_model::smart_contract::manifest::ContractManifest =
        std::str::from_utf8(&manifest_bytes)
            .ok()
            .and_then(|text| norito::json::from_str(text).ok())
            .ok_or_else(|| {
                Diagnostic::new(
                    ErrorCode::PackageInvalid,
                    "the prebuilt contract manifest is not a valid compiler manifest",
                )
                .with_context("path", prebuilt_manifest.display().to_string())
            })?;
    let code_hash = verified.code_hash.to_string();
    let abi_hash = verified.abi_hash.to_string();
    if manifest.code_hash.as_ref() != Some(&verified.code_hash)
        || manifest.abi_hash.as_ref() != Some(&verified.abi_hash)
    {
        return Err(Diagnostic::new(
            ErrorCode::PackageInvalid,
            "the prebuilt artifact and its compiler manifest name different code or ABI hashes",
        )
        .with_context("artifact_code_hash", code_hash)
        .with_context(
            "manifest_code_hash",
            manifest
                .code_hash
                .map_or_else(|| "missing".to_owned(), |hash| hash.to_string()),
        ));
    }
    if code_hash != built.artifact_hash || abi_hash != built.abi_hash {
        return Err(Diagnostic::new(
            ErrorCode::PackageInvalid,
            "the prebuilt artifact is not reproduced by the locked package source",
        )
        .with_context("contract", &built.target)
        .with_context("prebuilt_code_hash", code_hash)
        .with_context("reproduced_code_hash", &built.artifact_hash)
        .with_help("build the artifact from this package's locked source with the same address profile, or deploy the reproduced build without --artifact"));
    }
    Ok(bytes)
}

/// Retain the exact selected workspace/network slot; the candidate itself may be absent
/// after a Preparing crash, so only its original existing parent is resolved here.
fn retained_deployment_journal(
    root: &Path,
    network: &str,
    journal: &Path,
) -> Result<PathBuf, Diagnostic> {
    network::validate_name(network)?;
    let invalid = || {
        Diagnostic::new(
            ErrorCode::Usage,
            "deployment journal must be an exact commit under the selected workspace and network",
        )
    };
    let name = journal
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(invalid)?;
    validate_journal_id(name)?;
    let parent = journal
        .parent()
        .ok_or_else(invalid)?
        .canonicalize()
        .map_err(|_| invalid())?;
    let expected_root = root
        .join("target/deploy")
        .join(network)
        .canonicalize()
        .map_err(|_| invalid())?;
    let relative = parent.strip_prefix(&expected_root).map_err(|_| invalid())?;
    if relative.components().count() != 1 {
        return Err(invalid());
    }
    let slot_name = relative.to_str().ok_or_else(invalid)?;
    // Slot names are raw BLAKE3 package/target digests, not tagged transaction hashes.
    if slot_name.len() != 64
        || !slot_name
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(invalid());
    }
    Ok(parent.join(name))
}

fn runtime_diagnostic(error: &eyre::Report) -> Diagnostic {
    Diagnostic::new(ErrorCode::Network, format!("{error:#}"))
}

fn render_progress(event: DeploymentProgress) -> String {
    match event {
        DeploymentProgress::Prepared(preflight) => {
            format!(
                "Deployment plan\n{}",
                render_preflight(&preflight).trim_end()
            )
        }
        DeploymentProgress::Submitting(stage) => format!(
            "Stage {}/{} — submitting {}\n  Transaction: {}",
            stage.number,
            stage.total,
            stage.name.replace('_', " "),
            stage.hash
        ),
        DeploymentProgress::Recovering(stage) => format!(
            "Stage {}/{} — recovering {} by exact hash\n  Transaction: {}",
            stage.number,
            stage.total,
            stage.name.replace('_', " "),
            stage.hash
        ),
        DeploymentProgress::Applied { stage, evidence } => format!(
            "Stage {}/{} — Applied at height {} ({}, {})",
            stage.number,
            stage.total,
            evidence.block_height,
            evidence.scope,
            evidence.resolved_from
        ),
        DeploymentProgress::ReadingBack { alias, address } => format!(
            "Verifying stored artifact and alias readback\n  Alias: {alias}\n  Contract: {address}"
        ),
    }
}

pub(super) fn read_selected_artifact(artifact: &CompilerArtifactV1) -> Result<Vec<u8>, Diagnostic> {
    let bytes = read_bounded_single_link_regular_file_v1(
        &artifact.artifact,
        iroha_contract_deploy::MAX_DEPLOYMENT_ARTIFACT_BYTES as u64,
    )
    .map_err(|error| io_diagnostic("read built contract", &artifact.artifact, &error))?;
    let verified = ivm::verify_contract_artifact(&bytes)
        .map_err(|error| Diagnostic::new(ErrorCode::PackageInvalid, error.to_string()))?;
    if verified.code_hash.to_string() != artifact.artifact_hash
        || verified.abi_hash.to_string() != artifact.abi_hash
    {
        return Err(Diagnostic::new(ErrorCode::PackageInvalid, "the built contract file no longer matches the selected compiler artifact")
            .with_context("contract", &artifact.target)
            .with_help("rebuild the selected package and inspect any concurrent process changing its target directory"));
    }
    Ok(bytes)
}

fn render_preflight(preflight: &DeploymentPreflight) -> String {
    let _profile = ChainDiscriminantGuard::enter(preflight.chain_discriminant);
    let mut output = format!(
        "Network identity: {}\nAddress profile: {}\nAuthority: {}\nAlias: {}\nContract: {}\nCode hash: {}\nABI hash: {}\nObserved height: {}\n",
        preflight.network_id,
        preflight.chain_discriminant,
        preflight.authority,
        preflight.contract_alias,
        preflight.contract_address,
        preflight.code_hash,
        preflight.abi_hash,
        preflight.observed_block_height,
    );
    for (index, (hash, quote)) in preflight
        .transaction_hashes
        .iter()
        .zip(&preflight.fee_quotes)
        .enumerate()
    {
        let _ = writeln!(output, "Transaction {}: {hash}", index + 1);
        match &quote.intent {
            FeePaymentIntent::Authority(_) => {
                output.push_str("  Fee payer: transaction authority\n");
            }
            FeePaymentIntent::Sponsor(sponsor) => {
                let _ = writeln!(
                    output,
                    "  Fee payer: sponsor {} at revision {}",
                    sponsor.program_id, sponsor.program_revision
                );
            }
        }
        if quote.components.is_empty() {
            output.push_str("  Quoted fee: no charge components\n");
        }
        for component in &quote.components {
            let _ = writeln!(
                output,
                "  {:?}: at most {} {}",
                component.kind, component.max_amount, component.asset_definition_id
            );
        }
    }
    output
}

pub(super) fn run_view(manifest: Option<&Path>, args: &ViewArgs) -> CommandResult {
    let (workspace, _) = load_selected_workspace(manifest, &args.selection)?;
    let selected = select_members(&workspace, &args.selection)?;
    let package = network::select_contract_package(&selected, &args.contract)?;
    let payload = parse_view_payload(&call::argument_source(
        Some(&args.args),
        args.args_file.as_deref(),
    )?)?;
    if args.entrypoint.is_empty() || args.entrypoint.trim() != args.entrypoint {
        return Err(Diagnostic::new(
            ErrorCode::Usage,
            "view entrypoint must be a non-empty canonical selector",
        ));
    }
    let network = network::select_network(
        workspace.root(),
        args.network.as_deref(),
        None,
        None,
        network::NetworkPurpose::Deployment,
    )?;
    let alias = bound_alias(&network, package, &args.contract)?;
    let _profile = ChainDiscriminantGuard::enter(network.chain_discriminant);
    let config = network.load_client()?;
    let authority = config.account.clone();
    let service = iroha_contract_deploy::call::ContractCallService::new(config.clone())
        .map_err(|error| view_diagnostic(&error))?;
    let client = iroha::blocking::Client::new(config).map_err(|error| view_diagnostic(&error))?;
    client
        .refresh_capabilities()
        .map_err(|error| view_diagnostic(&error))?;
    let address = service
        .resolve_address(&alias)
        .map_err(|error| view_diagnostic(&error))?;
    let artifact = read_view_artifact(client.client(), &address, &alias)?;
    let result = post_verified_view(
        client.client(),
        &authority,
        &artifact,
        &address,
        &args.entrypoint,
        payload,
        args.gas_limit,
    )?;
    let rendered = norito::json::to_string_pretty(&result).map_err(|_| {
        Diagnostic::new(
            ErrorCode::Internal,
            "contract view result could not be rendered",
        )
    })?;
    Ok(Success {
        message: format!(
            "{} · {} · {}\n{rendered}",
            network.name, alias, args.entrypoint
        ),
        data: object([
            ("network", network.json()),
            ("contract", Value::from(args.contract.clone())),
            ("alias", Value::from(alias.to_string())),
            ("entrypoint", Value::from(args.entrypoint.clone())),
            ("result", result),
        ]),
    })
}

/// Read the canonical active binding and its network/dataspace/hash-bound stored bytes.
/// No build, local deployment evidence, signing of transactions or journal write is required.
fn read_view_artifact(
    client: &iroha::client::Client,
    address: &ContractAddress,
    alias: &ContractAlias,
) -> Result<Vec<u8>, Diagnostic> {
    let binding = client
        .get_gov_contract_json(address)
        .map_err(|error| view_diagnostic(&error))?;
    let expected_address =
        norito::json::to_value(address).map_err(|error| view_diagnostic(&error.into()))?;
    let code_hash_hex = binding.get("code_hash_hex").and_then(Value::as_str);
    if binding.get("found").and_then(Value::as_bool) != Some(true)
        || binding.get("active").and_then(Value::as_bool) != Some(true)
        || binding.get("contract_address") != Some(&expected_address)
        || binding.get("dataspace").and_then(Value::as_str) != Some(alias.dataspace_segment())
        || binding
            .get("lifecycle")
            .and_then(|value| value.get("active_code_hash_hex"))
            .and_then(Value::as_str)
            != code_hash_hex
    {
        return Err(Diagnostic::new(
            ErrorCode::Network,
            "the active on-chain contract binding disagrees with the resolved target",
        ));
    }
    let hash = code_hash_hex
        .filter(|value| {
            value.len() == 64
                && value
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
        })
        .and_then(|value| hex::decode(value).ok())
        .and_then(|bytes| <[u8; 32]>::try_from(bytes).ok())
        .and_then(iroha::crypto::Hash::from_marked_bytes)
        .ok_or_else(|| {
            Diagnostic::new(
                ErrorCode::Network,
                "the active contract hash is not canonical",
            )
        })?;
    let artifact_id = ContractArtifactId::for_address(address, hash)
        .map_err(|error| Diagnostic::new(ErrorCode::Network, error.to_string()))?;
    client
        .get_contract_code_bytes(&artifact_id)
        .map_err(|error| view_diagnostic(&error))
}

/// Use the authenticated deployed artifact's native schema, then address that exact instance.
/// The shared normalizer omits payloads only for genuine zero-parameter views.
fn post_verified_view(
    client: &iroha::client::Client,
    authority: &iroha_data_model::account::AccountId,
    artifact: &[u8],
    address: &ContractAddress,
    entrypoint: &str,
    payload: Value,
    gas_limit: u64,
) -> Result<Value, Diagnostic> {
    let (intent, payload) = iroha_contract_deploy::call::trusted_contract_intent(
        artifact,
        address.clone(),
        entrypoint,
        payload,
        true,
    )
    .map_err(|error| Diagnostic::new(ErrorCode::Usage, error.to_string()))?;
    let result = client
        .post_contract_view_json(
            authority,
            Some(address),
            None,
            entrypoint,
            payload.as_ref(),
            gas_limit,
        )
        .map_err(|error| view_diagnostic(&error))?;
    let expected_code_hash = hex::encode(intent.invocation.expected_code_hash.as_ref());
    let expected_address =
        norito::json::to_value(address).map_err(|error| view_diagnostic(&error.into()))?;
    if result.get("ok").and_then(Value::as_bool) != Some(true)
        || result.get("contract_address") != Some(&expected_address)
        || result.get("code_hash_hex").and_then(Value::as_str) != Some(expected_code_hash.as_str())
        || result.get("entrypoint").and_then(Value::as_str) != Some(entrypoint)
    {
        return Err(Diagnostic::new(
            ErrorCode::Network,
            "the view response differs from the verified target, artifact or entrypoint",
        ));
    }
    Ok(result)
}

fn view_diagnostic(error: &eyre::Report) -> Diagnostic {
    Diagnostic::new(ErrorCode::Network, format!("{error:#}"))
}

pub(super) fn select_artifact<'a>(
    artifacts: &'a [CompilerArtifactV1],
    requested: Option<&str>,
) -> Result<&'a CompilerArtifactV1, Diagnostic> {
    let selected = artifacts
        .iter()
        .filter(|artifact| requested.is_none_or(|name| name == artifact.target))
        .collect::<Vec<_>>();
    match selected.as_slice() {
        [artifact] => Ok(artifact),
        [] => Err(Diagnostic::new(
            ErrorCode::Usage,
            "no deployable contract matches the selected package and target",
        )),
        _ => Err(Diagnostic::new(
            ErrorCode::Usage,
            "deployment requires one unambiguous contract target",
        )
        .with_help("select a package with --package and a contract with --contract")),
    }
}

pub(super) fn bound_alias(
    network: &network::SelectedNetwork,
    package: &MusubiPackageSelectorV1,
    target: &str,
) -> Result<ContractAlias, Diagnostic> {
    network.contracts.get(&network::contract_key(package, target)).cloned().ok_or_else(|| Diagnostic::new(ErrorCode::Usage, "the contract has no alias binding on this network")
        .with_context("contract", target).with_context("network", &network.name)
        .with_help(format!("run `musubi network configure {} --package {} --contract {} --alias <name::your-domain>`; the network's selected wallet and fee policy are retained", network.name, quote_cli_argument(&package.to_string()), quote_cli_argument(target))))
}

pub(super) fn selected_fee_payment(
    network: &network::SelectedNetwork,
) -> Result<FeePaymentIntent, Diagnostic> {
    network.fee_payment.clone().ok_or_else(|| Diagnostic::new(ErrorCode::Usage, "deployment requires an explicit fee payer")
        .with_help("configure --fee-payer authority, or --fee-payer sponsor with its exact program and revision"))
}

pub(super) fn parse_view_payload(source: &str) -> Result<Value, Diagnostic> {
    if source.len() > 64 * 1024 {
        return Err(Diagnostic::new(
            ErrorCode::Usage,
            "view arguments exceed the 64 KiB bound",
        ));
    }
    let value: Value = norito::json::from_str(source)
        .map_err(|_| Diagnostic::new(ErrorCode::Usage, "--args must contain valid JSON"))?;
    if !matches!(value, Value::Object(_)) {
        return Err(Diagnostic::new(
            ErrorCode::Usage,
            "--args must be a JSON object of named contract arguments",
        ));
    }
    Ok(value)
}

fn deployment_slot(
    root: &Path,
    network: &str,
    package: &MusubiPackageSelectorV1,
    target: &str,
) -> Result<PathBuf, Diagnostic> {
    network::validate_name(network)?;
    network::validate_contract_target(target)?;
    Ok(root.join("target/deploy").join(network).join(
        blake3::hash(network::contract_key(package, target).as_bytes())
            .to_hex()
            .as_str(),
    ))
}

pub(super) fn validate_journal_id(id: &str) -> Result<(), Diagnostic> {
    if id.parse::<iroha::crypto::Hash>().is_err()
        || id.len() != 64
        || !id
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        return Err(Diagnostic::new(
            ErrorCode::PackageInvalid,
            "deployment journal must name one exact transaction hash",
        ));
    }
    Ok(())
}

/// Render an exact continuation using the selected project, network and client file.
pub(super) fn contract_resume_command(
    subcommand: &str,
    manifest: &Path,
    network: &network::SelectedNetwork,
    journal: &Path,
) -> String {
    let mut command = format!(
        "musubi --manifest-path {} {} --network {}",
        quote_cli_argument(&manifest.display().to_string()),
        quote_cli_argument(subcommand),
        quote_cli_argument(&network.name),
    );
    if let Some(config) = &network.config {
        let _ = write!(
            command,
            " --config {}",
            quote_cli_argument(&config.display().to_string())
        );
    }
    let _ = write!(
        command,
        " --resume {}",
        quote_cli_argument(&journal.display().to_string())
    );
    command
}

fn receipt_output(receipt: &DeploymentReceipt, journal: &Path) -> CommandResult {
    let charges = receipt
        .stages
        .iter()
        .enumerate()
        .map(|(index, stage)| call::charge_line(&format!("Stage {}", index + 1), stage))
        .collect::<String>();
    Ok(Success {
        message: format!(
            "Applied: {}\nNetwork identity: {}\nAuthority: {}\nContract: {}\nAlias: {}\nCode hash: {}\nABI hash: {}\nHeight: {} ({}, {})\n{charges}Stored artifact verified: {}\nReceipt: {}",
            receipt.commit.hash,
            receipt.network_id,
            receipt.authority,
            receipt.contract_address,
            receipt.contract_alias,
            receipt.code_hash,
            receipt.abi_hash,
            receipt.commit.block_height,
            receipt.commit.scope,
            receipt.commit.resolved_from,
            receipt.stored_artifact_matches,
            iroha_contract_deploy::receipt_path(journal).display()
        ),
        data: object([
            ("receipt", deployment_json(receipt)?),
            (
                "receipt_path",
                Value::from(
                    iroha_contract_deploy::receipt_path(journal)
                        .display()
                        .to_string(),
                ),
            ),
        ]),
    })
}

fn deployment_json<T: norito::json::JsonSerialize + ?Sized>(
    value: &T,
) -> Result<Value, Diagnostic> {
    norito::json::to_value(value).map_err(|_| {
        Diagnostic::new(
            ErrorCode::Internal,
            "deployment evidence could not be rendered",
        )
    })
}

fn deployment_diagnostic(error: &DeploymentError) -> Diagnostic {
    if let DeploymentError::Failed(failure) = error {
        let details = deployment_json(failure).unwrap_or(Value::Null);
        return Diagnostic::new(ErrorCode::Network, error.to_string())
            .with_details("The exact transaction is terminal. Correct the reported cause before creating a new deployment.", &details);
    }
    let code = match error {
        DeploymentError::Artifact(_) => ErrorCode::PackageInvalid,
        DeploymentError::InvalidRequest(_) => ErrorCode::Usage,
        DeploymentError::Journal(_) => ErrorCode::Io,
        DeploymentError::Preflight { .. }
        | DeploymentError::Pending { .. }
        | DeploymentError::Failed(_)
        | DeploymentError::Readback(_) => ErrorCode::Network,
    };
    let diagnostic = Diagnostic::new(code, error.to_string());
    match error {
        DeploymentError::Preflight { source, .. }
        | DeploymentError::Pending { source, .. }
        | DeploymentError::Journal(source)
        | DeploymentError::Readback(source) => {
            diagnostic.with_context("cause", format!("{source:#}"))
        }
        _ => diagnostic,
    }
}

#[cfg(test)]
#[path = "command_view_tests.rs"]
mod view_tests;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fresh_package_retry_reuses_original_plan_after_preparing_or_active_crash() -> eyre::Result<()>
    {
        crate::deployment_runtime::resume_tests::assert_package_fresh_retry_preserves_original(
            |service, session, request, prepare_only, progress| {
                prepare_or_resume_deployment(service, session, &request, prepare_only, progress)
            },
        )
    }

    #[test]
    fn recovery_journal_retains_selected_workspace_network_and_raw_slot_digest() {
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().canonicalize().unwrap();
        let slot = root.join("target/deploy/test").join("00".repeat(32));
        std::fs::create_dir_all(&slot).unwrap();
        let id = hex::encode(iroha::crypto::Hash::new(b"original prepared candidate").as_ref());
        let candidate = slot.join(id);
        assert!(!candidate.exists());
        assert_eq!(
            retained_deployment_journal(&root, "test", &candidate).unwrap(),
            candidate
        );
        assert!(
            !candidate.exists(),
            "path admission must not create a missing candidate"
        );
        std::fs::create_dir_all(root.join("target/deploy/other")).unwrap();
        assert!(retained_deployment_journal(&root, "other", &candidate).is_err());
        let outside = root.join("outside");
        std::fs::create_dir(&outside).unwrap();
        assert!(retained_deployment_journal(&outside, "test", &candidate).is_err());
        let nested = slot.join("nested");
        std::fs::create_dir(&nested).unwrap();
        assert!(
            retained_deployment_journal(
                &root,
                "test",
                &nested.join(candidate.file_name().unwrap())
            )
            .is_err()
        );
        assert!(retained_deployment_journal(&root, "test", &slot.join("not-a-commit")).is_err());
    }

    #[test]
    fn runtime_diagnostic_preserves_the_complete_error_chain() {
        let report =
            eyre::eyre!("journal descriptor was replaced").wrap_err("open retained deployment");
        let diagnostic = runtime_diagnostic(&report);
        assert_eq!(diagnostic.code(), ErrorCode::Network);
        let rendered = diagnostic.render_human();
        assert!(rendered.contains("open retained deployment"));
        assert!(rendered.contains("journal descriptor was replaced"));
        assert_eq!(
            report.root_cause().to_string(),
            "journal descriptor was replaced"
        );
    }

    fn compiled(source: &str) -> Vec<u8> {
        kotodama_lang::compiler::Compiler::new()
            .compile_source(source)
            .expect("compile fixture contract")
    }

    #[test]
    fn lifecycle_hook_is_found_in_either_keyword_spelling() {
        let hook =
            |source: &str| LifecycleHook::from_artifact(&compiled(source)).map(|hook| hook.name);
        assert_eq!(
            hook(
                "seiyaku Counter { state int value; hajimari() { value = 0; } view fn current() authorize(anyone) -> int { return value; } }"
            )
            .as_deref(),
            Some("hajimari")
        );
        assert_eq!(
            hook(
                "誓約 Counter { state int value; 始まり() { value = 1; } view fn current() authorize(anyone) -> int { return value; } }"
            )
            .as_deref(),
            Some("hajimari")
        );
        assert_eq!(
            LifecycleHook::from_artifact(&compiled(
                "seiyaku Counter { state int value; 始まり(int start) { value = start; } view fn current() authorize(anyone) -> int { return value; } }"
            )),
            Some(LifecycleHook {
                name: "hajimari".to_owned(),
                params: vec![iroha_contract_deploy::LifecycleParameter {
                    name: "start".into(),
                    type_name: "int".into()
                }],
            })
        );
        assert_eq!(
            LifecycleHook::from_artifact(&compiled(
                "seiyaku Quote { view fn quote() authorize(anyone) -> int { return 30; } }"
            )),
            None
        );
        assert_eq!(LifecycleHook::from_artifact(b"not an artifact"), None);
    }

    #[test]
    fn deployment_hint_names_both_spellings_and_the_exact_activation_command() {
        let network = network::SelectedNetwork {
            name: "taira".to_owned(),
            config: Some(PathBuf::from("/runtime/owner wallet/client.toml")),
            config_image: None,
            chain_discriminant: 369,
            network_id: None,
            fee_payment: None,
            contracts: BTreeMap::new(),
        };
        let command = "musubi --manifest-path /projects/counter/Musubi.toml call --network taira --config '/runtime/owner wallet/client.toml' --package demo/counter --contract counter --entrypoint hajimari --args '{}'";
        let parameterless = LifecycleHook {
            name: "hajimari".to_owned(),
            params: Vec::new(),
        };
        let hint = |known_pending| {
            activation_hint(
                &parameterless,
                known_pending,
                Path::new("/projects/counter/Musubi.toml"),
                &network,
                &"demo/counter".parse().expect("package"),
                "counter",
            )
        };
        let fresh = hint(true);
        assert!(fresh.contains("hajimari (始まり)"), "{fresh}");
        assert!(
            fresh.contains("the deployed instance rejects every other call and view until it runs"),
            "{fresh}"
        );
        assert!(fresh.contains(&format!("Next: {command}")), "{fresh}");
        assert!(fresh.contains("musubi deploy --activate"), "{fresh}");
        let earlier = hint(false);
        assert!(earlier.contains("hajimari (始まり)"), "{earlier}");
        assert!(
            earlier.contains(&format!("If it has not run yet: {command}")),
            "{earlier}"
        );
        assert!(!earlier.contains("Next:"), "{earlier}");
        assert!(!earlier.contains("placeholder"), "{earlier}");
        let parameterized = LifecycleHook {
            name: "hajimari".to_owned(),
            params: vec![
                iroha_contract_deploy::LifecycleParameter {
                    name: "start".into(),
                    type_name: "int".into(),
                },
                iroha_contract_deploy::LifecycleParameter {
                    name: "owner".into(),
                    type_name: "AccountId".into(),
                },
            ],
        };
        assert_eq!(
            parameterized.arguments_template(),
            r#"{"owner":"<AccountId>","start":"<int>"}"#
        );
        let package = "demo/counter".parse().expect("package");
        let manifest = Path::new("/projects/counter/Musubi.toml");
        let templated = activation_hint(
            &parameterized,
            true,
            manifest,
            &network,
            &package,
            "counter",
        );
        assert!(
            templated.contains(r#"--args '{"owner":"<AccountId>","start":"<int>"}'"#),
            "{templated}"
        );
        assert!(
            templated.contains("Replace each `<type>` placeholder"),
            "{templated}"
        );
        let supplied = norito::json!({"owner": "it's", "start": "5"});
        assert!(
            activation_command(
                manifest,
                &network,
                &package,
                "counter",
                &parameterized,
                Some(&supplied)
            )
            .ends_with(r#"--args '{"owner":"it'"'"'s","start":"5"}'"#)
        );
    }

    #[test]
    fn activation_arguments_are_checked_before_deployment() {
        let _profile = ChainDiscriminantGuard::enter(753);
        let artifact = compiled(
            "seiyaku Counter { state int value; hajimari(int start) { value = start; } view fn current() authorize(anyone) -> int { return value; } }",
        );
        let hook = LifecycleHook::from_artifact(&artifact).expect("declared hook");
        let start = norito::json!({"start": "5"});
        assert!(check_activation_arguments(&artifact, Some(&hook), Some(&start)).is_ok());
        let missing = check_activation_arguments(&artifact, Some(&hook), None)
            .expect_err("the hook needs its argument");
        assert_eq!(missing.code(), ErrorCode::Usage);
        let rendered = missing.render_human();
        assert!(
            rendered.contains("nothing was signed or submitted"),
            "{rendered}"
        );
        assert!(rendered.contains("argument `start`"), "{rendered}");
        assert!(
            rendered.contains(r#"--args '{"start":"<int>"}'"#),
            "{rendered}"
        );
        let number = norito::json!({"start": 5});
        assert!(check_activation_arguments(&artifact, Some(&hook), Some(&number)).is_err());
        let plain =
            compiled("seiyaku Quote { view fn quote() authorize(anyone) -> int { return 30; } }");
        assert!(check_activation_arguments(&plain, None, None).is_ok());
        assert!(check_activation_arguments(&plain, None, Some(&norito::json!({}))).is_ok());
        let unexpected = check_activation_arguments(&plain, None, Some(&start))
            .expect_err("no hook takes these arguments");
        assert!(unexpected.render_human().contains("hajimari (始まり)"));
    }

    #[test]
    fn deploy_grammar_shares_args_and_guards_activation_and_prebuilt_artifacts() {
        let parse =
            |arguments: &[&str]| Cli::try_parse_from(["musubi", "deploy"].iter().chain(arguments));
        let Command::Deploy(args) = parse(&["--activate", "--args", "{\"limit\":\"5\"}"])
            .expect("activation with hook arguments")
            .command
        else {
            panic!("deploy command");
        };
        assert!(args.activate);
        assert_eq!(args.args.as_deref(), Some("{\"limit\":\"5\"}"));
        assert!(
            parse(&["--args", "{}"]).is_err(),
            "--args requires --activate"
        );
        assert!(
            parse(&["--gas-limit", "10"]).is_err(),
            "--gas-limit requires --activate"
        );
        assert!(parse(&["--activate", "--prepare"]).is_err());
        assert!(parse(&["--activate", "--resume", "/journal"]).is_err());
        assert!(
            parse(&["--artifact", "app.to"]).is_err(),
            "artifact needs its manifest"
        );
        assert!(parse(&["--artifact-manifest", "app.manifest.json"]).is_err());
        assert!(
            parse(&[
                "--artifact",
                "app.to",
                "--artifact-manifest",
                "app.manifest.json",
                "--activate",
            ])
            .is_ok()
        );
        assert!(
            parse(&[
                "--artifact",
                "app.to",
                "--artifact-manifest",
                "m.json",
                "--cancel",
                "/j"
            ])
            .is_err()
        );
    }

    #[test]
    fn prebuilt_artifacts_deploy_only_when_the_locked_build_reproduces_them() {
        let root = tempfile::tempdir().expect("artifact directory");
        let original =
            compiled("seiyaku Quote { view fn quote() authorize(anyone) -> int { return 30; } }");
        let other =
            compiled("seiyaku Quote { view fn quote() authorize(anyone) -> int { return 31; } }");
        let verified = ivm::verify_contract_artifact(&original).expect("admitted original");
        let artifact_path = root.path().join("quote.to");
        let manifest_path = root.path().join("quote.manifest.json");
        fs::write(&artifact_path, &original).expect("prebuilt artifact");
        let manifest_for = |artifact: &[u8]| {
            let verified = ivm::verify_contract_artifact(artifact).expect("admitted");
            norito::json::to_string(&verified.manifest).expect("compiler manifest")
        };
        fs::write(&manifest_path, manifest_for(&original)).expect("prebuilt manifest");
        let built = CompilerArtifactV1 {
            package: "demo/quote".parse().expect("package"),
            target: "quote".to_owned(),
            source: "contracts/quote.ko".to_owned(),
            artifact: root.path().join("reproduced.to"),
            manifest: PathBuf::new(),
            interface: PathBuf::new(),
            entrypoints: vec!["quote".to_owned()],
            artifact_hash: verified.code_hash.to_string(),
            abi_hash: verified.abi_hash.to_string(),
            fresh: false,
        };
        assert_eq!(
            read_reproduced_prebuilt_artifact(&built, &artifact_path, &manifest_path)
                .expect("reproduced prebuilt artifact"),
            original
        );
        fs::write(&manifest_path, manifest_for(&other)).expect("foreign manifest");
        let mismatch = read_reproduced_prebuilt_artifact(&built, &artifact_path, &manifest_path)
            .expect_err("manifest names other code");
        assert_eq!(mismatch.code(), ErrorCode::PackageInvalid);
        fs::write(&artifact_path, &other).expect("unreproducible artifact");
        let unreproduced =
            read_reproduced_prebuilt_artifact(&built, &artifact_path, &manifest_path)
                .expect_err("locked source builds different code");
        assert!(
            unreproduced
                .render_human()
                .contains("not reproduced by the locked package source")
        );
        fs::write(&manifest_path, "{").expect("malformed manifest");
        assert!(read_reproduced_prebuilt_artifact(&built, &artifact_path, &manifest_path).is_err());
    }

    #[test]
    fn deployment_rejects_replaced_artifact_bytes_before_signing() {
        let root = tempfile::tempdir().expect("build directory");
        let compiler = kotodama_lang::compiler::Compiler::new();
        let original = compiler
            .compile_source(
                "seiyaku Quote { view fn quote() authorize(anyone) -> int { return 30; } }",
            )
            .expect("original contract");
        let replacement = compiler
            .compile_source(
                "seiyaku Quote { view fn quote() authorize(anyone) -> int { return 31; } }",
            )
            .expect("replacement contract");
        let verified = ivm::verify_contract_artifact(&original).expect("admitted original");
        let path = root.path().join("quote.to");
        fs::write(&path, &original).expect("build output");
        let mut artifact = CompilerArtifactV1 {
            package: "demo/quote".parse().expect("package"),
            target: "quote".to_owned(),
            source: "contracts/quote.ko".to_owned(),
            artifact: path.clone(),
            manifest: PathBuf::new(),
            interface: PathBuf::new(),
            entrypoints: vec!["quote".to_owned()],
            artifact_hash: verified.code_hash.to_string(),
            abi_hash: verified.abi_hash.to_string(),
            fresh: false,
        };
        assert_eq!(
            read_selected_artifact(&artifact).expect("exact build bytes"),
            original
        );
        fs::write(&path, replacement).expect("concurrent substitution");
        assert!(read_selected_artifact(&artifact).is_err());
        fs::write(&path, &original).expect("restore bytes");
        artifact.abi_hash = iroha::crypto::Hash::new(b"different ABI").to_string();
        assert!(read_selected_artifact(&artifact).is_err());
        fs::write(&path, b"invalid artifact").expect("corrupt artifact");
        assert!(read_selected_artifact(&artifact).is_err());
    }

    /// One-transaction authority-paid plan, built under the caller's active address profile.
    fn authority_paid_preflight(
        id: iroha_data_model::NetworkId,
        authority: &iroha_data_model::account::AccountId,
        address: &iroha_data_model::smart_contract::ContractAddress,
        fee: &FeePaymentIntent,
    ) -> DeploymentPreflight {
        use iroha::crypto::Hash;
        use iroha_data_model::{nexus::FeeDebitSource, permission::Permission};
        use iroha_model_base::topology::DataSpaceId;
        let quote = norito::json::from_value(object([
            ("intent", deployment_json(fee).expect("intent")),
            (
                "observation",
                object([
                    ("ledger_time_ms", Value::from(1_u64)),
                    ("next_block_height", Value::from(2_u64)),
                    (
                        "route_dataspace_id",
                        deployment_json(&DataSpaceId::UNIVERSAL).expect("dataspace"),
                    ),
                ]),
            ),
            (
                "components",
                deployment_json(&fee.charge_limits().to_vec()).expect("components"),
            ),
            ("capacities", Value::Array(vec![])),
            (
                "decision",
                object([
                    ("status", Value::from("accepted")),
                    (
                        "value",
                        object([
                            (
                                "debit_source",
                                deployment_json(&FeeDebitSource::Account(authority.clone()))
                                    .expect("payer"),
                            ),
                            ("program_revision", Value::Null),
                        ]),
                    ),
                ]),
            ),
        ]))
        .expect("native quote");
        let token: Permission = iroha::executor_data_model::permission::account::CanManageAccountAlias {
            scope: iroha::executor_data_model::permission::account::AccountAliasPermissionScope::Dataspace(DataSpaceId::UNIVERSAL),
        }.into();
        DeploymentPreflight {
            network_id: id,
            chain_id: "test-chain".to_owned(),
            authority: authority.clone(),
            authorization: iroha_contract_deploy::DeploymentAuthorization {
                account_exists: true,
                manage_alias_permission: token,
            },
            chain_discriminant: 369,
            contract_alias: "coffee::universal".parse().expect("alias"),
            contract_address: address.clone(),
            dataspace_id: DataSpaceId::UNIVERSAL,
            code_hash: Hash::new(b"code"),
            abi_hash: Hash::new(b"abi"),
            deploy_nonce: 0,
            previous_contract_address: None,
            observed_block_height: 1,
            observed_block_hash: Hash::new(b"block").to_string(),
            fee_quotes: vec![quote],
            transaction_hashes: vec![Hash::new(b"transaction").to_string()],
        }
    }

    /// Deterministic signer, network, derived contract address and Nexus fee bound, built under
    /// the caller's active address profile.
    fn authority_paid_identities() -> (
        iroha_data_model::account::AccountId,
        iroha_data_model::NetworkId,
        iroha_data_model::smart_contract::ContractAddress,
        FeePaymentIntent,
    ) {
        use iroha::crypto::{Algorithm, Hash, HashOf, KeyPair};
        use iroha_data_model::{
            NetworkId,
            account::AccountId,
            smart_contract::ContractAddress,
            transaction::{FeeChargeKind, FeeChargeLimit},
        };
        use iroha_model_base::topology::DataSpaceId;
        let key = KeyPair::try_from_seed(vec![9; 32], Algorithm::Ed25519).expect("test key");
        let authority = AccountId::new(key.public_key().clone());
        let id =
            NetworkId::from_genesis_hash(HashOf::from_untyped_unchecked(Hash::new(b"genesis")));
        let address =
            ContractAddress::derive(&id, &authority, 0, DataSpaceId::UNIVERSAL).expect("address");
        let fee = FeePaymentIntent::authority(
            vec![FeeChargeLimit {
                kind: FeeChargeKind::Nexus,
                asset_definition_id: "6TEAJqbb8oEPmLncoNiMRbLEK6tw".parse().expect("asset"),
                max_amount: "2".parse().expect("fee"),
            }],
            None,
        );
        (authority, id, address, fee)
    }

    #[test]
    fn prepared_output_shows_exact_signer_alias_transactions_and_fee_bounds() {
        use iroha_data_model::nexus::{FeeDebitSource, FeeSponsorProgramId};
        let _profile = ChainDiscriminantGuard::enter(369);
        let (authority, id, address, fee) = authority_paid_identities();
        let mut preflight = authority_paid_preflight(id, &authority, &address, &fee);
        let signer = authority.to_string();
        let _foreign_profile = ChainDiscriminantGuard::enter(753);
        let human = render_preflight(&preflight);
        for expected in [
            id.to_string(),
            signer,
            address.to_string(),
            "coffee::universal".to_owned(),
            "Transaction 1:".to_owned(),
            "Fee payer: transaction authority".to_owned(),
            "at most 2 6TEAJqbb8oEPmLncoNiMRbLEK6tw".to_owned(),
        ] {
            assert!(human.contains(&expected), "missing {expected}: {human}");
        }
        assert_eq!(
            render_progress(DeploymentProgress::Prepared(Box::new(preflight.clone()))),
            format!("Deployment plan\n{}", human.trim_end())
        );
        let sponsor =
            FeeSponsorProgramId::new(authority, "coffee-fees".parse().expect("program name"));
        let encoded_sponsor = {
            let _profile = ChainDiscriminantGuard::enter(369);
            sponsor.to_string()
        };
        preflight.fee_quotes[0].intent =
            FeePaymentIntent::sponsor(sponsor.clone(), 7, fee.charge_limits().to_vec(), None);
        preflight.fee_quotes[0].decision = norito::json::from_value(object([
            ("status", Value::from("accepted")),
            (
                "value",
                object([
                    (
                        "debit_source",
                        deployment_json(&FeeDebitSource::SponsorProgram(sponsor)).expect("sponsor"),
                    ),
                    ("program_revision", Value::from(7_u64)),
                ]),
            ),
        ]))
        .expect("sponsored quote decision");
        let sponsored = render_preflight(&preflight);
        assert!(sponsored.contains(&format!(
            "Fee payer: sponsor {encoded_sponsor} at revision 7"
        )));
        assert!(!sponsored.contains("Fee payer: transaction authority"));
        assert!(sponsored.contains("at most 2 6TEAJqbb8oEPmLncoNiMRbLEK6tw"));
        assert_stage_progress_names_exact_transactions(preflight);
    }

    /// Stage progress names each exact transaction and never conflates submission, recovery,
    /// application and readback.
    fn assert_stage_progress_names_exact_transactions(preflight: DeploymentPreflight) {
        let stage = iroha_contract_deploy::DeploymentStage {
            number: 2,
            total: 3,
            name: "register_manifest".to_owned(),
            hash: preflight.transaction_hashes[0].clone(),
        };
        let submitting = render_progress(DeploymentProgress::Submitting(stage.clone()));
        assert!(submitting.contains("Stage 2/3 — submitting register manifest"));
        assert!(submitting.contains(&stage.hash));
        assert!(!submitting.contains("Applied"));
        let recovering = render_progress(DeploymentProgress::Recovering(stage.clone()));
        assert!(recovering.contains("recovering register manifest by exact hash"));
        assert!(!recovering.contains("submitting"));
        let applied = render_progress(DeploymentProgress::Applied {
            stage,
            evidence: iroha_contract_deploy::AppliedEvidence {
                hash: preflight.transaction_hashes[0].clone(),
                terminal_kind: "Applied".to_owned(),
                block_height: 42,
                scope: "global".to_owned(),
                resolved_from: "state".to_owned(),
                charge: None,
            },
        });
        assert!(applied.contains("Stage 2/3 — Applied at height 42 (global, state)"));
        let readback = render_progress(DeploymentProgress::ReadingBack {
            alias: preflight.contract_alias,
            address: preflight.contract_address,
        });
        assert!(readback.contains("Verifying stored artifact and alias readback"));
        assert!(readback.contains("coffee::universal"));
    }

    #[test]
    fn plan_journal_is_named_by_the_final_atomic_commit_hash() {
        use crate::deployment_runtime::plan_journal_id;
        use iroha::crypto::Hash;
        let _profile = ChainDiscriminantGuard::enter(369);
        let (authority, id, address, fee) = authority_paid_identities();
        let mut preflight = authority_paid_preflight(id, &authority, &address, &fee);
        let commit = Hash::new(b"atomic commit");
        preflight.transaction_hashes =
            vec![Hash::new(b"self grant").to_string(), commit.to_string()];
        assert_eq!(
            plan_journal_id(&preflight).expect("journal id"),
            hex::encode(commit.as_ref())
        );
        for (hashes, reason) in [
            (Vec::new(), "contains no atomic commit"),
            (
                vec!["not-a-transaction-hash".to_owned()],
                "contains an invalid transaction hash",
            ),
            // Valid hex whose least significant bit is clear is not a transaction hash.
            (
                vec!["00".repeat(32)],
                "contains an invalid transaction hash",
            ),
        ] {
            preflight.transaction_hashes = hashes;
            let error = plan_journal_id(&preflight).expect_err("unusable plan hashes");
            assert!(error.to_string().contains(reason), "{error}");
        }
    }

    #[test]
    fn deployment_continuation_retains_project_network_and_selected_client() {
        let manifest = Path::new("/projects/coffee club/Musubi.toml");
        let journal = Path::new("/projects/coffee club/target/deploy/exact-journal");
        let mut network = network::SelectedNetwork {
            name: "other-taira".to_owned(),
            config: Some(PathBuf::from("/runtime/owner's wallet/client.toml")),
            config_image: None,
            chain_discriminant: 369,
            network_id: None,
            fee_payment: None,
            contracts: BTreeMap::new(),
        };
        assert_eq!(
            contract_resume_command("deploy", manifest, &network, journal),
            r#"musubi --manifest-path '/projects/coffee club/Musubi.toml' deploy --network other-taira --config '/runtime/owner'"'"'s wallet/client.toml' --resume '/projects/coffee club/target/deploy/exact-journal'"#
        );
        let parsed = Cli::try_parse_from([
            "musubi",
            "--manifest-path",
            manifest.to_str().expect("manifest"),
            "deploy",
            "--network",
            &network.name,
            "--config",
            network
                .config
                .as_ref()
                .expect("client")
                .to_str()
                .expect("path"),
            "--resume",
            journal.to_str().expect("journal"),
        ])
        .expect("continuation is valid resume grammar without ignored package selection");
        assert_eq!(parsed.manifest_path.as_deref(), Some(manifest));
        let Command::Deploy(args) = parsed.command else {
            panic!("deployment continuation");
        };
        assert_eq!(args.network.as_deref(), Some("other-taira"));
        assert_eq!(args.config, network.config);
        assert_eq!(args.resume.as_deref(), Some(journal));
        network.config = None;
        assert_eq!(
            contract_resume_command("deploy", manifest, &network, journal),
            "musubi --manifest-path '/projects/coffee club/Musubi.toml' deploy --network other-taira --resume '/projects/coffee club/target/deploy/exact-journal'"
        );
    }

    #[test]
    fn deployment_progress_is_explicit_human_output_and_json_remains_one_document() {
        let temporary = tempfile::tempdir().expect("isolated progress invocation");
        let missing = temporary.path().join("missing-Musubi.toml");
        for format in ["human", "json"] {
            let mut progress = Vec::new();
            let invocation = invoke_with_progress(
                [
                    "musubi",
                    "--manifest-path",
                    missing.to_str().expect("path"),
                    "--format",
                    format,
                    "deploy",
                ],
                &mut |message| progress.push(message.to_owned()),
            );
            let output = invocation
                .output
                .render(invocation.format)
                .expect("routed output");
            assert_ne!(
                output.exit_code(),
                0,
                "missing manifest prevents any deployment"
            );
            if format == "human" {
                assert_eq!(progress.len(), 1);
                assert!(progress[0].contains("Preparing the contract"));
            } else {
                assert!(progress.is_empty());
                assert!(output.stderr().is_empty());
                let _: Value = norito::json::from_str(output.stdout()).expect("one JSON document");
            }
        }
        let message = "Alias: private_key=secret-value::universal\n\u{1b}[31mAuthorization: Bearer hidden-token";
        for format in [OutputFormat::Human, OutputFormat::Json] {
            let mut progress = Vec::new();
            report_progress(format, message, &mut |text| progress.push(text.to_owned()));
            if format == OutputFormat::Human {
                assert_eq!(progress.len(), 1);
                assert!(progress[0].contains("[REDACTED]"));
                for forbidden in ["secret-value", "hidden-token", "\u{1b}"] {
                    assert!(
                        !progress[0].contains(forbidden),
                        "leaked {forbidden:?}: {}",
                        progress[0]
                    );
                }
            } else {
                assert!(progress.is_empty());
            }
        }
    }

    #[test]
    fn deployment_keeps_the_actionable_sdk_cause_and_redacts_credentials() {
        let error = DeploymentError::Preflight {
            operation: "fee quote",
            source: eyre::eyre!(
                "route_unavailable at authoritative peer; private_key=secret-value"
            )
            .wrap_err("Torii request failed"),
        };
        let diagnostic = deployment_diagnostic(&error);
        for format in [OutputFormat::Human, OutputFormat::Json] {
            let rendered = CommandOutput::failure("deploy", diagnostic.clone())
                .render(format)
                .expect("diagnostic");
            let output = format!("{}{}", rendered.stdout(), rendered.stderr());
            assert!(output.contains("route_unavailable"));
            assert!(!output.contains("secret-value"));
            assert_ne!(rendered.exit_code(), 0);
        }
        let diagnostic = view_diagnostic(
            &eyre::eyre!("route_unavailable; private_key=secret-value").wrap_err("view failed"),
        );
        let rendered = CommandOutput::failure("view", diagnostic)
            .render(OutputFormat::Json)
            .expect("view diagnostic");
        assert!(rendered.stdout().contains("route_unavailable"));
        assert!(!rendered.stdout().contains("secret-value"));
        assert_ne!(rendered.exit_code(), 0);
    }

    #[test]
    fn deployment_never_invents_a_fee_payer() {
        let dir = tempfile::tempdir().expect("workspace");
        let mut network = network::select_network(
            dir.path(),
            None,
            None,
            None,
            network::NetworkPurpose::Deployment,
        )
        .expect("network");
        assert!(selected_fee_payment(&network).is_err());
        let intent = FeePaymentIntent::authority(Vec::new(), None);
        network.fee_payment = Some(intent.clone());
        assert_eq!(
            selected_fee_payment(&network).expect("explicit selection"),
            intent
        );
    }

    #[test]
    fn deploy_rejects_offline_modes_and_ignored_resume_selection() {
        for flag in ["--offline", "--frozen", "--release"] {
            assert!(Cli::try_parse_from(["musubi", "deploy", flag]).is_err());
        }
        assert!(
            Cli::try_parse_from(["musubi", "deploy", "--resume", "journal", "--locked"]).is_err()
        );
        assert!(
            Cli::try_parse_from([
                "musubi",
                "deploy",
                "--resume",
                "journal",
                "--contract",
                "coffee"
            ])
            .is_err()
        );
        assert!(
            Cli::try_parse_from([
                "musubi",
                "deploy",
                "--resume",
                "journal",
                "--network",
                "taira"
            ])
            .is_ok()
        );
        assert!(
            Cli::try_parse_from(["musubi", "deploy", "--contract", "coffee", "--locked"]).is_ok()
        );
        assert!(
            Cli::try_parse_from([
                "musubi",
                "deploy",
                "--cancel",
                "journal",
                "--network",
                "taira"
            ])
            .is_ok()
        );
        for flag in ["--prepare", "--locked", "--workspace"] {
            assert!(
                Cli::try_parse_from(["musubi", "deploy", "--cancel", "journal", flag]).is_err()
            );
        }
        assert!(
            Cli::try_parse_from([
                "musubi", "deploy", "--cancel", "journal", "--resume", "journal"
            ])
            .is_err()
        );
    }

    #[test]
    fn view_arguments_require_a_bounded_named_object() {
        assert_eq!(
            parse_view_payload("{\"coffees\":\"3\"}")
                .expect("arguments")
                .get("coffees")
                .and_then(Value::as_str),
            Some("3")
        );
        for source in ["null", "[]", "\"secret\"", "{broken"] {
            assert!(parse_view_payload(source).is_err());
        }
        assert!(parse_view_payload(&" ".repeat(65 * 1024)).is_err());
    }

    #[test]
    fn journal_paths_and_ids_cannot_escape_the_package() {
        let root = Path::new("/workspace");
        assert_eq!(
            deployment_slot(
                root,
                "taira",
                &"demo/coffee".parse().expect("package"),
                "coffee-club"
            )
            .expect("slot"),
            root.join("target/deploy/taira")
                .join(blake3::hash(b"demo/coffee::coffee-club").to_hex().as_str())
        );
        for invalid in ["../outside", "", "a/b", ".", "a\\b"] {
            assert!(
                deployment_slot(
                    root,
                    "taira",
                    &"demo/coffee".parse().expect("package"),
                    invalid
                )
                .is_err()
            );
        }
        for target in ["coffee.v1", "coffee::v1", "\u{73c8}\u{7432}"] {
            let slot = deployment_slot(
                root,
                "taira",
                &"demo/coffee".parse().expect("package"),
                target,
            )
            .expect("canonical target");
            assert_eq!(
                slot.parent(),
                Some(root.join("target/deploy/taira").as_path())
            );
            assert_eq!(slot.file_name().expect("hash").to_string_lossy().len(), 64);
        }
        assert!(validate_journal_id(&"ab".repeat(32)).is_ok());
        assert!(validate_journal_id(&"AB".repeat(32)).is_err());
        for invalid in ["../outside", "bad", &"x".repeat(64)] {
            assert!(validate_journal_id(invalid).is_err());
        }
    }

    #[test]
    fn deployment_rejects_absent_or_ambiguous_targets() {
        assert!(select_artifact(&[], None).is_err());
        let artifact = CompilerArtifactV1 {
            package: "demo/coffee".parse().expect("package"),
            target: "coffee".to_owned(),
            source: String::new(),
            artifact: PathBuf::new(),
            manifest: PathBuf::new(),
            interface: PathBuf::new(),
            entrypoints: vec![],
            abi_hash: String::new(),
            artifact_hash: String::new(),
            fresh: false,
        };
        let artifacts = [artifact.clone(), artifact];
        assert!(select_artifact(&artifacts, Some("coffee")).is_err());
        assert!(select_artifact(&artifacts[..1], Some("other")).is_err());
        assert_eq!(
            select_artifact(&artifacts[..1], None)
                .expect("one contract")
                .target,
            "coffee"
        );
    }
}
