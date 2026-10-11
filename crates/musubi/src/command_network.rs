//! Named network bindings keep public deployment identity separate from runtime credentials.
use super::*;
use iroha_data_model::{
    NetworkId, account::address::ChainDiscriminantGuard, smart_contract::ContractAlias,
    transaction::FeePaymentIntent,
};

const NETWORK_FILE: &str = "Musubi.networks.toml";
const MAX_NETWORK_FILE_BYTES: usize = 64 * 1024;

#[derive(Args, Debug)]
pub(super) struct NetworkCommandArgs {
    #[command(subcommand)]
    command: NetworkCommand,
}

#[derive(Subcommand, Debug)]
enum NetworkCommand {
    /// Bind an exact network and make it the workspace default; store references to runtime files.
    Configure(Box<ConfigureArgs>),
    /// Show the default and all configured network identities without loading a signer.
    List,
}

#[derive(Args, Debug)]
struct ConfigureArgs {
    #[command(flatten)]
    selection: SelectionArgs,
    /// Workspace network name, for example taira.
    name: String,
    /// Existing native client file instead of the integrated developer wallet.
    #[arg(long, value_name = "PATH", conflicts_with_all = ["wallet", "wallet_dir"])]
    config: Option<PathBuf>,
    /// Integrated wallet to bind; defaults to the local wallet named default.
    #[arg(long, value_name = "NAME")]
    wallet: Option<String>,
    /// Private wallet store outside projects.
    #[arg(long, value_name = "DIRECTORY")]
    wallet_dir: Option<PathBuf>,
    /// Explicit payer for SDK-quoted deployment fees.
    #[arg(long, value_enum)]
    fee_payer: Option<FeePayer>,
    /// Exact immutable sponsor program, required for sponsor-paid fees.
    #[arg(long, requires = "fee_payer")]
    fee_program: Option<String>,
    /// Exact nonzero sponsor program revision.
    #[arg(long, requires = "fee_payer", value_parser = clap::value_parser!(u64).range(1..))]
    fee_program_revision: Option<u64>,
    /// Contract target declared in Musubi.toml.
    #[arg(long, requires = "alias")]
    contract: Option<String>,
    /// Exact on-chain alias for this target, independent from its package namespace.
    #[arg(long, requires = "contract")]
    alias: Option<ContractAlias>,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum FeePayer {
    Authority,
    Sponsor,
}

pub(super) struct SelectedNetwork {
    pub(super) name: String,
    pub(super) config: Option<PathBuf>,
    pub(super) config_image: Option<std::sync::Arc<RegistryPublicConfigImageV1>>,
    pub(super) chain_discriminant: u16,
    pub(super) network_id: Option<NetworkId>,
    pub(super) fee_payment: Option<FeePaymentIntent>,
    pub(super) contracts: BTreeMap<String, ContractAlias>,
}

impl SelectedNetwork {
    pub(super) fn json(&self) -> Value {
        let _profile = ChainDiscriminantGuard::enter(self.chain_discriminant);
        object([
            ("name", Value::from(self.name.clone())),
            (
                "chain_discriminant",
                Value::from(u64::from(self.chain_discriminant)),
            ),
            (
                "network_id",
                self.network_id
                    .map_or(Value::Null, |id| Value::from(id.to_string())),
            ),
            ("configured", Value::from(self.config.is_some())),
            (
                "fee",
                match &self.fee_payment {
                    None => Value::Null,
                    Some(FeePaymentIntent::Authority(_)) => {
                        object([("payer", Value::from("authority"))])
                    }
                    Some(FeePaymentIntent::Sponsor(payment)) => object([
                        ("payer", Value::from("sponsor")),
                        ("program", Value::from(payment.program_id.to_string())),
                        (
                            "revision",
                            Value::from(payment.program_revision.to_string()),
                        ),
                    ]),
                },
            ),
            (
                "contracts",
                Value::Object(
                    self.contracts
                        .iter()
                        .map(|(target, alias)| (target.clone(), Value::from(alias.to_string())))
                        .collect(),
                ),
            ),
        ])
    }

    fn fee_label(&self) -> String {
        let _profile = ChainDiscriminantGuard::enter(self.chain_discriminant);
        match &self.fee_payment {
            None => "not selected".to_owned(),
            Some(FeePaymentIntent::Authority(_)) => "authority".to_owned(),
            Some(FeePaymentIntent::Sponsor(payment)) => format!(
                "sponsor {} at revision {}",
                payment.program_id, payment.program_revision
            ),
        }
    }

    /// Load the exact retained configuration image only at a signing boundary.
    pub(super) fn load_client(&self) -> Result<iroha::config::Config, Diagnostic> {
        let image = self
            .config_image
            .as_deref()
            .ok_or_else(|| missing_binding(&self.name))?;
        let (id, profile) = image
            .registry_binding()
            .map_err(|error| registry_diagnostic(error, ErrorCode::Usage))?;
        if Some(id) != self.network_id || profile != self.chain_discriminant {
            return Err(binding_changed(&self.name));
        }
        let (config, _) =
            iroha::config::Config::load_bytes_with_musubi_publication(image.path(), image.bytes())
                .map_err(|_| {
                    Diagnostic::new(
                ErrorCode::Usage,
                "the selected native client configuration could not be loaded",
            )
            .with_help(
                "check the network identity, account identity and runtime signing file permissions",
            )
                })?;
        if config.network_id != id || config.account_chain_discriminant != profile {
            return Err(binding_changed(&self.name));
        }
        Ok(config)
    }
}

/// Why a command selects a network, which decides the fallback when no binding is chosen.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum NetworkPurpose {
    /// `check`, `build` and `test`: compile for the data-model default address profile unless a
    /// network binding or `--chain-discriminant` selects another one.
    LocalCompilation,
    /// Deployment, calls and views require an explicitly bound network; Taira is suggested.
    Deployment,
}

/// Name reported for unbound local compilation.
pub(super) const LOCAL_NETWORK_NAME: &str = "local";

/// Address profile used when no network binding or explicit discriminant is selected.
///
/// This is the Iroha data-model default (SORA, `0x02F1` = 753), read from the same
/// `iroha_data_model::account::address::chain_discriminant` source that `koto` uses, so both
/// tools compile identical address literals by default.
pub(super) fn default_chain_discriminant() -> u16 {
    iroha_data_model::account::address::chain_discriminant()
}

pub(super) fn select_network(
    root: &Path,
    requested: Option<&str>,
    config_override: Option<&Path>,
    discriminant_override: Option<u16>,
    purpose: NetworkPurpose,
) -> Result<SelectedNetwork, Diagnostic> {
    let document = read_bindings(root)?;
    let fallback = if config_override.is_some() {
        "configured"
    } else if discriminant_override.is_some() || purpose == NetworkPurpose::LocalCompilation {
        LOCAL_NETWORK_NAME
    } else {
        "taira"
    };
    let name = requested
        .or_else(|| document.get("default").and_then(toml::Value::as_str))
        .unwrap_or(fallback);
    validate_name(name)?;
    let binding = document
        .get("networks")
        .and_then(toml::Value::as_table)
        .and_then(|networks| networks.get(name))
        .and_then(toml::Value::as_table);
    let stored_config = binding
        .and_then(|value| value.get("config"))
        .and_then(toml::Value::as_str)
        .map(|path| resolve_reference(root, Path::new(path)));
    let config = config_override
        .map(absolute_reference)
        .transpose()?
        .or(stored_config);
    let config_image = config
        .as_deref()
        .map(|path| RegistryPublicConfigImageV1::load(Some(path)))
        .transpose()
        .map_err(|error| registry_diagnostic(error, ErrorCode::Usage))?
        .map(std::sync::Arc::new);
    let builtin_profile = iroha::config::resolve_account_chain_discriminant(Some(name), None).ok();
    let stored_identity = binding.map(parse_binding_identity).transpose()?;
    let (network_id, profile) = if let Some(image) = &config_image {
        let profile = image
            .account_chain_discriminant()
            .map_err(|error| registry_diagnostic(error, ErrorCode::Usage))?;
        // Compilation requires only the public profile. Configured deployment bindings also
        // require and pin the exact genesis identity; a display name can never replace it.
        let id = image.registry_binding().ok().map(|(id, _)| id);
        if stored_identity.is_some_and(|(expected_id, expected_profile)| {
            Some(expected_id) != id || expected_profile != profile
        }) {
            return Err(binding_changed(name));
        }
        (id, profile)
    } else {
        let local_default =
            (binding.is_none() && name == LOCAL_NETWORK_NAME).then(default_chain_discriminant);
        (
            None,
            builtin_profile
                .or(discriminant_override)
                .or(local_default)
                .ok_or_else(|| missing_binding(name))?,
        )
    };
    if builtin_profile.is_some_and(|expected| expected != profile) {
        return Err(Diagnostic::new(
            ErrorCode::Usage,
            "the selected network name and client address profile disagree",
        )
        .with_context("network", name));
    }
    let chain_discriminant =
        select_compiler_chain_discriminant(profile, discriminant_override, true)?;
    let fee_payment = binding
        .map(|binding| parse_fee_selection(binding, chain_discriminant))
        .transpose()?
        .flatten();
    let contracts = binding
        .and_then(|value| value.get("contracts"))
        .and_then(toml::Value::as_table)
        .map(|contracts| {
            contracts
                .iter()
                .map(|(target, alias)| {
                    let alias = alias
                        .as_str()
                        .ok_or_else(invalid_bindings)?
                        .parse::<ContractAlias>()
                        .map_err(|_| invalid_bindings())?;
                    Ok((target.clone(), alias))
                })
                .collect::<Result<BTreeMap<_, _>, Diagnostic>>()
        })
        .transpose()?
        .unwrap_or_default();
    Ok(SelectedNetwork {
        name: name.to_owned(),
        config,
        config_image,
        chain_discriminant,
        network_id,
        fee_payment,
        contracts,
    })
}

pub(super) fn run_network(
    manifest_path: Option<&Path>,
    args: &NetworkCommandArgs,
) -> CommandResult {
    let path = project_manifest_path(manifest_path)?;
    let workspace = load_workspace(&path).map_err(workspace_diagnostic)?;
    match &args.command {
        NetworkCommand::Configure(args) => {
            let key = args
                .contract
                .as_deref()
                .map(|target| {
                    let selected = select_members(&workspace, &args.selection)?;
                    let package = select_contract_package(&selected, target)?;
                    Ok::<_, Diagnostic>(contract_key(package, target))
                })
                .transpose()?;
            configure(workspace.root(), args, key.as_deref())
        }
        NetworkCommand::List => {
            let document = read_bindings(workspace.root())?;
            let default = document.get("default").and_then(toml::Value::as_str);
            let names = document
                .get("networks")
                .and_then(toml::Value::as_table)
                .map(|networks| networks.keys().cloned().collect::<Vec<_>>())
                .unwrap_or_default();
            let mut message = default.map_or_else(
                || {
                    format!(
                        "Default: none; check, build and test use address profile {}\n",
                        default_chain_discriminant()
                    )
                },
                |default| format!("Default: {default}\n"),
            );
            let mut networks = Vec::new();
            for name in names {
                let binding = document
                    .get("networks")
                    .and_then(toml::Value::as_table)
                    .and_then(|networks| networks.get(&name))
                    .and_then(toml::Value::as_table)
                    .ok_or_else(invalid_bindings)?;
                let selected = stored_network(workspace.root(), &name, binding)?;
                let _ = writeln!(
                    message,
                    "{}: {} (address profile {})\n  Fee payer: {}",
                    selected.name,
                    selected
                        .network_id
                        .map_or_else(|| "unbound".to_owned(), |id| id.to_string()),
                    selected.chain_discriminant,
                    selected.fee_label()
                );
                networks.push(selected.json());
            }
            if networks.is_empty() {
                message.push_str("To deploy on Taira, create and fund a wallet with `musubi wallet create` and `musubi wallet fund`, then bind it with `musubi network configure taira`.\n");
            }
            Ok(Success {
                message,
                data: object([
                    ("default", default.map_or(Value::Null, Value::from)),
                    (
                        "local_chain_discriminant",
                        Value::from(u64::from(default_chain_discriminant())),
                    ),
                    ("networks", Value::Array(networks)),
                ]),
            })
        }
    }
}

fn stored_network(
    root: &Path,
    name: &str,
    binding: &toml::Table,
) -> Result<SelectedNetwork, Diagnostic> {
    let (id, profile) = parse_binding_identity(binding)?;
    let reference = |field: &str| {
        binding
            .get(field)
            .and_then(toml::Value::as_str)
            .map(|path| resolve_reference(root, Path::new(path)))
    };
    let contracts = binding
        .get("contracts")
        .and_then(toml::Value::as_table)
        .map(|contracts| {
            contracts
                .iter()
                .map(|(key, alias)| {
                    Ok((
                        key.clone(),
                        alias
                            .as_str()
                            .ok_or_else(invalid_bindings)?
                            .parse()
                            .map_err(|_| invalid_bindings())?,
                    ))
                })
                .collect::<Result<BTreeMap<_, _>, Diagnostic>>()
        })
        .transpose()?
        .unwrap_or_default();
    Ok(SelectedNetwork {
        name: name.to_owned(),
        config: reference("config"),
        config_image: None,
        chain_discriminant: profile,
        network_id: Some(id),
        fee_payment: parse_fee_selection(binding, profile)?,
        contracts,
    })
}

fn configure(root: &Path, args: &ConfigureArgs, contract: Option<&str>) -> CommandResult {
    validate_name(&args.name)?;
    let writer = AtomicWriteRoot::new(root).map_err(atomic_diagnostic)?;
    let _lock = writer
        .lock_exclusive(Path::new("Musubi.networks.lock"))
        .map_err(atomic_diagnostic)?;
    let mut document = read_bindings(root)?;
    let config = configured_client_path(root, args, &document)?;
    let image = RegistryPublicConfigImageV1::load(Some(&config))
        .map_err(|error| registry_diagnostic(error, ErrorCode::Usage))?;
    let (network_id, profile) = image
        .registry_binding()
        .map_err(|error| registry_diagnostic(error, ErrorCode::Usage))?;
    if let Ok(expected) = iroha::config::resolve_account_chain_discriminant(Some(&args.name), None)
        && expected != profile
    {
        return Err(binding_changed(&args.name));
    }
    document.insert("version".to_owned(), toml::Value::Integer(1));
    document.insert("default".to_owned(), toml::Value::String(args.name.clone()));
    let networks = document
        .entry("networks")
        .or_insert_with(|| toml::Value::Table(toml::Table::new()))
        .as_table_mut()
        .ok_or_else(invalid_bindings)?;
    let binding = networks
        .entry(&args.name)
        .or_insert_with(|| toml::Value::Table(toml::Table::new()))
        .as_table_mut()
        .ok_or_else(invalid_bindings)?;
    if !binding.is_empty() && parse_binding_identity(binding)? != (network_id, profile) {
        return Err(binding_changed(&args.name)
            .with_help("use a new network name for a different genesis identity"));
    }
    binding.insert(
        "config".to_owned(),
        toml::Value::String(path_string(&config)?),
    );
    binding.insert(
        "network-id".to_owned(),
        toml::Value::String(network_id.to_string()),
    );
    binding.insert(
        "chain-discriminant".to_owned(),
        toml::Value::Integer(i64::from(profile)),
    );
    if let Some(fee) = fee_selection_table(args, profile)? {
        binding.insert("fee".to_owned(), toml::Value::Table(fee));
    } else if !binding.contains_key("fee") {
        binding.insert(
            "fee".to_owned(),
            toml::Value::Table(toml::Table::from_iter([(
                "payer".to_owned(),
                toml::Value::String("authority".to_owned()),
            )])),
        );
    }
    if let (Some(target), Some(alias)) = (contract, &args.alias) {
        validate_contract_key(target)?;
        let contracts = binding
            .entry("contracts")
            .or_insert_with(|| toml::Value::Table(toml::Table::new()))
            .as_table_mut()
            .ok_or_else(invalid_bindings)?;
        contracts.insert(target.to_owned(), toml::Value::String(alias.to_string()));
    }
    let selected = stored_network(root, &args.name, binding)?;
    let encoded = encode_bindings(&document)?;
    writer
        .replace(Path::new(NETWORK_FILE), encoded.as_bytes())
        .map_err(atomic_diagnostic)?;
    let mut message = format!(
        "Configured {}: {network_id} (address profile {profile})\nDefault network: {}\nFee payer: {}\n",
        args.name,
        args.name,
        selected.fee_label()
    );
    for (target, alias) in &selected.contracts {
        let _ = writeln!(message, "Alias: {target} -> {alias}");
    }
    message.push_str("Next: musubi test && musubi build");
    Ok(Success {
        message,
        data: selected.json(),
    })
}

/// Select the bound client file: an explicit `--config`, the network's retained reference when
/// no wallet is requested, or the selected integrated wallet's client file.
fn configured_client_path(
    root: &Path,
    args: &ConfigureArgs,
    document: &toml::Table,
) -> Result<PathBuf, Diagnostic> {
    let retained_config = if args.wallet.is_none() && args.wallet_dir.is_none() {
        document
            .get("networks")
            .and_then(toml::Value::as_table)
            .and_then(|networks| networks.get(&args.name))
            .and_then(toml::Value::as_table)
            .and_then(|binding| binding.get("config"))
            .and_then(toml::Value::as_str)
            .map(|path| resolve_reference(root, Path::new(path)))
    } else {
        None
    };
    let config = if let Some(config) = &args.config {
        absolute_reference(config)?
    } else if let Some(config) = retained_config {
        config
    } else {
        let store =
            wallet::open_store(Some(&root.join("Musubi.toml")), args.wallet_dir.as_deref())?;
        store
            .config_path(args.wallet.as_deref().unwrap_or("default"))
            .map_err(wallet::wallet_error)?
    };
    Ok(config)
}

fn encode_bindings(document: &toml::Table) -> Result<String, Diagnostic> {
    let encoded = toml::to_string_pretty(document).map_err(|_| invalid_bindings())?;
    if encoded.len() > MAX_NETWORK_FILE_BYTES {
        return Err(Diagnostic::new(
            ErrorCode::Usage,
            "network bindings exceed the 64 KiB workspace limit",
        ));
    }
    Ok(encoded)
}

fn fee_selection_table(
    args: &ConfigureArgs,
    profile: u16,
) -> Result<Option<toml::Table>, Diagnostic> {
    let Some(payer) = args.fee_payer else {
        if args.fee_program.is_some() || args.fee_program_revision.is_some() {
            return Err(invalid_fee_selection());
        }
        return Ok(None);
    };
    let mut fee = toml::Table::new();
    match payer {
        FeePayer::Authority => {
            if args.fee_program.is_some() || args.fee_program_revision.is_some() {
                return Err(invalid_fee_selection());
            }
            fee.insert(
                "payer".to_owned(),
                toml::Value::String("authority".to_owned()),
            );
        }
        FeePayer::Sponsor => {
            fee.insert(
                "payer".to_owned(),
                toml::Value::String("sponsor".to_owned()),
            );
            fee.insert(
                "program".to_owned(),
                toml::Value::String(args.fee_program.clone().ok_or_else(invalid_fee_selection)?),
            );
            fee.insert(
                "revision".to_owned(),
                toml::Value::String(
                    args.fee_program_revision
                        .ok_or_else(invalid_fee_selection)?
                        .to_string(),
                ),
            );
        }
    }
    let mut binding = toml::Table::new();
    binding.insert("fee".to_owned(), toml::Value::Table(fee.clone()));
    parse_fee_selection(&binding, profile)?;
    Ok(Some(fee))
}

fn parse_fee_selection(
    binding: &toml::Table,
    profile: u16,
) -> Result<Option<FeePaymentIntent>, Diagnostic> {
    let Some(fee) = binding.get("fee") else {
        return Ok(None);
    };
    let fee = fee.as_table().ok_or_else(invalid_fee_selection)?;
    let payer = fee
        .get("payer")
        .and_then(toml::Value::as_str)
        .ok_or_else(invalid_fee_selection)?;
    let intent = match payer {
        "authority" if fee.len() == 1 => FeePaymentIntent::authority(Vec::new(), None),
        "sponsor" if fee.len() == 3 => {
            let _profile = ChainDiscriminantGuard::enter(profile);
            let program = fee
                .get("program")
                .and_then(toml::Value::as_str)
                .ok_or_else(invalid_fee_selection)?
                .parse()
                .map_err(|_| invalid_fee_selection())?;
            let revision_text = fee
                .get("revision")
                .and_then(toml::Value::as_str)
                .ok_or_else(invalid_fee_selection)?;
            let revision = revision_text
                .parse::<u64>()
                .map_err(|_| invalid_fee_selection())?;
            if revision == 0 || revision.to_string() != revision_text {
                return Err(invalid_fee_selection());
            }
            FeePaymentIntent::sponsor(program, revision, Vec::new(), None)
        }
        _ => return Err(invalid_fee_selection()),
    };
    intent.validate().map_err(|_| invalid_fee_selection())?;
    Ok(Some(intent))
}

fn invalid_fee_selection() -> Diagnostic {
    Diagnostic::new(
        ErrorCode::Usage,
        "choose --fee-payer authority, or --fee-payer sponsor with an exact --fee-program and nonzero --fee-program-revision",
    )
}

fn read_bindings(root: &Path) -> Result<toml::Table, Diagnostic> {
    let writer = AtomicWriteRoot::new(root).map_err(atomic_diagnostic)?;
    let Some(bytes) = writer
        .load_immutable(Path::new(NETWORK_FILE), MAX_NETWORK_FILE_BYTES)
        .map_err(atomic_diagnostic)?
    else {
        return Ok(toml::Table::new());
    };
    let table = std::str::from_utf8(&bytes)
        .map_err(|_| invalid_bindings())?
        .parse::<toml::Table>()
        .map_err(|_| invalid_bindings())?;
    if table.get("version").and_then(toml::Value::as_integer) != Some(1)
        || table
            .keys()
            .any(|key| !["version", "default", "networks"].contains(&key.as_str()))
    {
        return Err(invalid_bindings());
    }
    let default = table
        .get("default")
        .and_then(toml::Value::as_str)
        .ok_or_else(invalid_bindings)?;
    validate_name(default)?;
    let networks = table
        .get("networks")
        .and_then(toml::Value::as_table)
        .ok_or_else(invalid_bindings)?;
    if !networks.contains_key(default) {
        return Err(invalid_bindings());
    }
    for (name, binding) in networks {
        validate_name(name)?;
        let binding = binding.as_table().ok_or_else(invalid_bindings)?;
        if binding.keys().any(|key| {
            ![
                "config",
                "network-id",
                "chain-discriminant",
                "fee",
                "contracts",
            ]
            .contains(&key.as_str())
        }) {
            return Err(invalid_bindings());
        }
        let (_, profile) = parse_binding_identity(binding)?;
        parse_fee_selection(binding, profile)?;
        if binding
            .get("config")
            .and_then(toml::Value::as_str)
            .is_none_or(str::is_empty)
        {
            return Err(invalid_bindings());
        }
        if let Some(contracts) = binding.get("contracts") {
            for (target, alias) in contracts.as_table().ok_or_else(invalid_bindings)? {
                validate_contract_key(target)?;
                alias
                    .as_str()
                    .ok_or_else(invalid_bindings)?
                    .parse::<ContractAlias>()
                    .map_err(|_| invalid_bindings())?;
            }
        }
    }
    Ok(table)
}

fn parse_binding_identity(table: &toml::Table) -> Result<(NetworkId, u16), Diagnostic> {
    let id = table
        .get("network-id")
        .and_then(toml::Value::as_str)
        .ok_or_else(invalid_bindings)?
        .parse()
        .map_err(|_| invalid_bindings())?;
    let profile = table
        .get("chain-discriminant")
        .and_then(toml::Value::as_integer)
        .and_then(|value| u16::try_from(value).ok())
        .filter(|value| *value != 0)
        .ok_or_else(invalid_bindings)?;
    Ok((id, profile))
}

pub(super) fn contract_key(package: &MusubiPackageSelectorV1, target: &str) -> String {
    format!("{package}::{target}")
}

pub(super) fn select_contract_package<'a>(
    members: &[&'a WorkspaceMember],
    target: &str,
) -> Result<&'a MusubiPackageSelectorV1, Diagnostic> {
    let matching = members
        .iter()
        .filter(|member| {
            member
                .manifest
                .contracts
                .iter()
                .any(|contract| contract.name.as_ref() == target)
        })
        .collect::<Vec<_>>();
    match matching.as_slice() {
        [member] => Ok(&member.package.selector),
        [] => Err(Diagnostic::new(
            ErrorCode::Usage,
            "the selected package does not declare this contract target",
        )
        .with_context("contract", target)),
        _ => Err(Diagnostic::new(
            ErrorCode::Usage,
            "the contract target is ambiguous across packages",
        )
        .with_help("select its owning package with --package")),
    }
}

fn validate_contract_key(key: &str) -> Result<(), Diagnostic> {
    // Package selectors forbid ':', so the first delimiter is unambiguous even when
    // a canonical target name itself contains '::'.
    let (package, target) = key.split_once("::").ok_or_else(invalid_bindings)?;
    package
        .parse::<MusubiPackageSelectorV1>()
        .map_err(|_| invalid_bindings())?;
    validate_contract_target(target)
}

pub(super) fn validate_contract_target(target: &str) -> Result<(), Diagnostic> {
    target
        .parse::<iroha_model_base::name::Name>()
        .map_err(|_| invalid_bindings())?;
    if matches!(target, "." | "..") || target.contains(['/', '\\']) {
        return Err(invalid_bindings());
    }
    Ok(())
}

pub(super) fn validate_name(name: &str) -> Result<(), Diagnostic> {
    if name.is_empty()
        || name.len() > 128
        || !name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        return Err(Diagnostic::new(
            ErrorCode::Usage,
            "network names must contain 1–128 ASCII letters, digits, hyphens or underscores",
        ));
    }
    Ok(())
}

fn path_string(path: &Path) -> Result<String, Diagnostic> {
    path.to_str().map(str::to_owned).ok_or_else(|| {
        Diagnostic::new(
            ErrorCode::Usage,
            "network file references must be valid UTF-8 paths",
        )
    })
}

fn resolve_reference(root: &Path, path: &Path) -> PathBuf {
    if path.is_absolute() {
        path.to_owned()
    } else {
        root.join(path)
    }
}

fn absolute_reference(path: &Path) -> Result<PathBuf, Diagnostic> {
    std::env::current_dir()
        .map(|cwd| resolve_reference(&cwd, path))
        .map_err(|error| io_diagnostic("resolve runtime file reference", path, &error))
}

fn invalid_bindings() -> Diagnostic {
    Diagnostic::new(
        ErrorCode::Usage,
        "invalid Musubi.networks.toml; expected version 1 and explicit public network bindings",
    )
}

fn binding_changed(name: &str) -> Diagnostic {
    Diagnostic::new(
        ErrorCode::Usage,
        "the native client no longer matches the pinned network identity or address profile",
    )
    .with_context("network", name)
}

fn missing_binding(name: &str) -> Diagnostic {
    Diagnostic::new(ErrorCode::Usage, "deployment needs a wallet bound to the selected network")
        .with_help(format!("create and fund a wallet with `musubi wallet create` and `musubi wallet fund`, acquire a domain with `musubi wallet namespace <your-domain>`, then run `musubi network configure {name} --wallet default --contract <target> --alias <name::your-domain>`"))
}

#[cfg(test)]
mod tests {
    use super::*;
    const NETWORK_ID: &str =
        "hash:32C903E5B3497E34C2B844EBFE8A39C19E6CF8F95D44C1FFB8BA9DCB42F91149#A2F0";

    fn public_config(root: &Path) -> PathBuf {
        let path = root.join("runtime.toml");
        fs::write(&path, format!("network_id = '{NETWORK_ID}'\n[account]\nprofile = 'taira'\nprivate_key_file = 'missing-private-key'\n")).expect("public configuration");
        path
    }

    fn contract_workspace(root: &Path) -> Workspace {
        let project = root.join("coffee-club");
        let invocation = invoke([
            OsString::from("musubi"),
            OsString::from("new"),
            project.as_os_str().to_owned(),
            OsString::from("--namespace"),
            OsString::from("demo"),
        ]);
        let rendered = invocation
            .output
            .render(OutputFormat::Human)
            .expect("scaffold output");
        assert_eq!(rendered.exit_code(), 0, "{}", rendered.stderr());
        load_workspace(&project.join(MANIFEST_FILE_NAME)).expect("contract workspace")
    }

    #[test]
    fn retained_network_image_prevents_config_rotation_from_rebinding_the_graph() {
        let root = tempfile::tempdir().expect("root");
        let workspace = contract_workspace(root.path());
        let path = public_config(root.path());
        let selected = select_network(
            workspace.root(),
            Some("taira"),
            Some(&path),
            None,
            NetworkPurpose::Deployment,
        )
        .expect("select exact image");
        fs::write(&path, "invalid rotated configuration").expect("rotate path");
        let packages = workspace
            .members()
            .values()
            .map(|member| member.package.selector.clone())
            .collect::<Vec<_>>();
        let options = WorkspaceResolutionOptionsV1 {
            cache_root: None,
            archive_transport: None,
            mode: GraphModeArgs::default(),
            config: Some(&path),
            config_image: selected.config_image.clone(),
            expected_network_id: selected.network_id,
            fresh_only: false,
            purpose: GraphPurposeV1::Workspace,
            requested_chain_discriminant: Some(369),
        };
        let graph = resolve_and_persist_graph(&workspace, &packages, None, None, options.clone())
            .expect("resolve retained image");
        assert_eq!(
            graph.account_chain_discriminant().expect("bound profile"),
            369
        );
        fs::remove_file(workspace.root().join(LOCK_FILE_NAME)).expect("remove test lock");
        let mut mismatch = options;
        mismatch.expected_network_id = Some(NetworkId::from_genesis_hash(
            iroha::crypto::HashOf::from_untyped_unchecked(iroha::crypto::Hash::new(
                b"different genesis",
            )),
        ));
        assert!(resolve_and_persist_graph(&workspace, &packages, None, None, mismatch).is_err());
        assert!(!workspace.root().join(LOCK_FILE_NAME).exists());
    }

    #[test]
    fn listing_pinned_networks_does_not_require_runtime_files() {
        let root = tempfile::tempdir().expect("root");
        let workspace = contract_workspace(root.path());
        let path = public_config(root.path());
        let args = NetworkCommandArgs {
            command: NetworkCommand::Configure(Box::new(ConfigureArgs {
                selection: SelectionArgs::default(),
                name: "taira".to_owned(),
                config: Some(path.clone()),
                wallet: None,
                wallet_dir: None,
                fee_payer: None,
                fee_program: None,
                fee_program_revision: None,
                contract: Some("coffee-club".to_owned()),
                alias: Some("coffee-club::universal".parse().expect("alias")),
            })),
        };
        run_network(Some(workspace.root_manifest_path()), &args)
            .expect("configure declared target");
        fs::remove_file(path).expect("remove unavailable runtime config");
        let result = run_network(
            Some(workspace.root_manifest_path()),
            &NetworkCommandArgs {
                command: NetworkCommand::List,
            },
        )
        .expect("read public bindings");
        assert!(result.message.contains(NETWORK_ID));
        assert_eq!(
            result
                .data
                .pointer("/networks/0/contracts/demo~1coffee-club::coffee-club")
                .and_then(Value::as_str),
            Some("coffee-club::universal")
        );
    }

    fn client_selection(
        config: Option<PathBuf>,
        wallet: Option<&str>,
        wallet_dir: Option<PathBuf>,
    ) -> ConfigureArgs {
        ConfigureArgs {
            selection: SelectionArgs::default(),
            name: "taira".to_owned(),
            config,
            wallet: wallet.map(str::to_owned),
            wallet_dir,
            fee_payer: None,
            fee_program: None,
            fee_program_revision: None,
            contract: None,
            alias: None,
        }
    }

    #[test]
    fn configure_prefers_explicit_client_then_retained_binding_then_wallet() {
        let project = tempfile::tempdir().expect("project");
        let wallets = tempfile::tempdir().expect("wallet store outside the project");
        let retained = "[networks.taira]\nconfig = \"runtime/client.toml\"\n"
            .parse::<toml::Table>()
            .expect("retained binding");
        let explicit = PathBuf::from("/runtime/explicit/client.toml");
        assert_eq!(
            configured_client_path(
                project.path(),
                &client_selection(Some(explicit.clone()), None, None),
                &retained,
            )
            .expect("explicit client"),
            explicit
        );
        assert_eq!(
            configured_client_path(
                project.path(),
                &client_selection(None, None, None),
                &retained
            )
            .expect("retained client"),
            project.path().join("runtime/client.toml")
        );
        let absolute = "[networks.taira]\nconfig = \"/runtime/retained/client.toml\"\n"
            .parse::<toml::Table>()
            .expect("absolute retained binding");
        assert_eq!(
            configured_client_path(
                project.path(),
                &client_selection(None, None, None),
                &absolute
            )
            .expect("absolute retained client"),
            PathBuf::from("/runtime/retained/client.toml")
        );
        // Selecting a wallet bypasses the retained binding and requires that wallet's client.
        let wallet = client_selection(None, Some("missing"), Some(wallets.path().join("store")));
        assert!(configured_client_path(project.path(), &wallet, &retained).is_err());
    }

    #[test]
    fn unbound_local_compilation_uses_the_data_model_default_profile() {
        use NetworkPurpose::{Deployment, LocalCompilation};
        let dir = tempfile::tempdir().expect("workspace");
        let selected =
            select_network(dir.path(), None, None, None, LocalCompilation).expect("local default");
        assert_eq!(selected.name, LOCAL_NETWORK_NAME);
        assert_eq!(selected.chain_discriminant, 0x02F1);
        assert_eq!(selected.chain_discriminant, default_chain_discriminant());
        assert!(selected.config.is_none());
        assert!(selected.network_id.is_none());
        assert!(selected.load_client().is_err());
        assert_eq!(
            fs::read_dir(dir.path())
                .expect("unchanged directory")
                .count(),
            0
        );
        let deployment =
            select_network(dir.path(), None, None, None, Deployment).expect("taira suggestion");
        assert_eq!(deployment.name, "taira");
        assert_eq!(deployment.chain_discriminant, 369);
        let selected_taira =
            select_network(dir.path(), Some("taira"), None, None, LocalCompilation)
                .expect("explicit Taira profile");
        assert_eq!(selected_taira.chain_discriminant, 369);
        let explicit = select_network(dir.path(), None, None, Some(777), LocalCompilation)
            .expect("explicit local profile");
        assert_eq!(explicit.name, LOCAL_NETWORK_NAME);
        assert_eq!(explicit.chain_discriminant, 777);
        assert!(
            select_network(dir.path(), Some("taira"), None, Some(753), LocalCompilation).is_err()
        );
        assert!(select_network(dir.path(), Some("../bad"), None, None, LocalCompilation).is_err());
        assert!(select_network(dir.path(), Some("unknown"), None, None, LocalCompilation).is_err());
    }

    #[test]
    fn configure_pins_exact_identity_with_public_references_and_no_signer() {
        let dir = tempfile::tempdir().expect("workspace");
        let config = public_config(dir.path());
        let args = ConfigureArgs {
            selection: SelectionArgs::default(),
            name: "taira".to_owned(),
            config: Some(config.clone()),
            wallet: None,
            wallet_dir: None,
            fee_payer: Some(FeePayer::Authority),
            fee_program: None,
            fee_program_revision: None,
            contract: Some("coffee-club".to_owned()),
            alias: Some("coffee-club::universal".parse().expect("alias")),
        };
        let result = configure(dir.path(), &args, Some("demo/coffee-club::coffee-club"))
            .expect("signer-free configure");
        assert_eq!(
            result.data.get("network_id").and_then(Value::as_str),
            Some(NETWORK_ID)
        );
        assert_eq!(
            result.data.pointer("/fee/payer").and_then(Value::as_str),
            Some("authority")
        );
        assert!(result.message.contains("Fee payer: authority"));
        assert!(
            result
                .message
                .contains("Alias: demo/coffee-club::coffee-club -> coffee-club::universal")
        );
        let update = ConfigureArgs {
            config: None,
            fee_payer: None,
            contract: Some("espresso".to_owned()),
            alias: Some("espresso::universal".parse().expect("second alias")),
            ..args
        };
        configure(dir.path(), &update, Some("demo/coffee-club::espresso")).expect(
            "adding an alias retains the selected wallet without reading the default wallet",
        );
        let selected = select_network(dir.path(), None, None, None, NetworkPurpose::Deployment)
            .expect("persisted default");
        assert_eq!(selected.config.as_deref(), Some(config.as_path()));
        assert_eq!(
            selected.contracts["demo/coffee-club::espresso"].to_string(),
            "espresso::universal"
        );
        assert_eq!(
            selected.fee_payment,
            Some(FeePaymentIntent::authority(Vec::new(), None))
        );
        assert_eq!(
            selected.contracts["demo/coffee-club::coffee-club"].to_string(),
            "coffee-club::universal"
        );
        assert!(selected.load_client().is_err());
        let stored = fs::read_to_string(dir.path().join(NETWORK_FILE)).expect("bindings");
        assert!(!stored.contains("private_key"));
        assert!(!stored.contains("missing-private-key"));
        fs::write(
            &config,
            format!("network_id = '{NETWORK_ID}'\n[account]\nprofile = 'minamoto'\n"),
        )
        .expect("change profile");
        assert!(select_network(dir.path(), None, None, None, NetworkPurpose::Deployment).is_err());
        assert!(selected.load_client().is_err());
    }

    #[test]
    fn fee_selection_requires_one_explicit_payer_and_a_canonical_sponsor_revision() {
        use iroha::{
            crypto::{Algorithm, KeyPair},
            data_model::account::AccountId,
        };
        use iroha_data_model::nexus::FeeSponsorProgramId;
        let key = KeyPair::try_from_seed(vec![7; 32], Algorithm::Ed25519).expect("test key");
        let program = FeeSponsorProgramId::new(
            AccountId::new(key.public_key().clone()),
            "demo".parse().expect("program name"),
        );
        let encoded_program = {
            let _profile = ChainDiscriminantGuard::enter(369);
            program.to_string()
        };
        let mut args = ConfigureArgs {
            selection: SelectionArgs::default(),
            name: "taira".to_owned(),
            config: Some(PathBuf::from("unused.toml")),
            wallet: None,
            wallet_dir: None,
            fee_payer: None,
            fee_program: None,
            fee_program_revision: None,
            contract: None,
            alias: None,
        };
        assert!(
            fee_selection_table(&args, 369)
                .expect("no change")
                .is_none()
        );
        args.fee_program = Some(encoded_program.clone());
        assert!(fee_selection_table(&args, 369).is_err());
        args.fee_payer = Some(FeePayer::Authority);
        assert!(fee_selection_table(&args, 369).is_err());
        args.fee_payer = Some(FeePayer::Sponsor);
        assert!(fee_selection_table(&args, 369).is_err());
        args.fee_program_revision = Some(0);
        assert!(fee_selection_table(&args, 369).is_err());
        args.fee_program_revision = Some(u64::MAX);
        let fee = fee_selection_table(&args, 369)
            .expect("sponsor selection")
            .expect("fee");
        let mut binding = toml::Table::new();
        binding.insert("fee".to_owned(), toml::Value::Table(fee));
        let intent = parse_fee_selection(&binding, 369)
            .expect("canonical selection")
            .expect("intent");
        assert_eq!(intent.sponsor_program(), Some((&program, u64::MAX)));
        assert!(parse_fee_selection(&binding, 753).is_err());
        for revision in ["0", "01", "+1", "1 ", "18446744073709551616"] {
            binding
                .get_mut("fee")
                .expect("fee")
                .as_table_mut()
                .expect("table")
                .insert(
                    "revision".to_owned(),
                    toml::Value::String(revision.to_owned()),
                );
            assert!(parse_fee_selection(&binding, 369).is_err(), "{revision}");
        }
        let dir = tempfile::tempdir().expect("workspace");
        let mut selected = select_network(dir.path(), None, None, None, NetworkPurpose::Deployment)
            .expect("network");
        selected.fee_payment = Some(intent);
        let _outer_profile = ChainDiscriminantGuard::enter(753);
        assert_eq!(
            selected
                .json()
                .pointer("/fee/program")
                .and_then(Value::as_str),
            Some(encoded_program.as_str())
        );
        assert!(selected.fee_label().contains(&encoded_program));
    }

    #[test]
    fn fee_binding_rejects_unknown_fields_and_implicit_sponsorship() {
        for fee in [
            "payer='authority'\nprogram='unexpected'",
            "payer='sponsor'\nrevision='1'",
            "payer='sponsor'\nprogram='invalid'\nrevision=1",
            "payer='automatic'",
            "payer='authority'\ngas-limit=0",
        ] {
            let binding = format!("[fee]\n{fee}")
                .parse::<toml::Table>()
                .expect("test table");
            assert!(parse_fee_selection(&binding, 369).is_err(), "{fee}");
        }
        assert!(
            Cli::try_parse_from([
                "musubi",
                "network",
                "configure",
                "taira",
                "--config",
                "client.toml",
                "--fee-payment",
                "fee.json"
            ])
            .is_err()
        );
        assert!(
            Cli::try_parse_from([
                "musubi",
                "network",
                "configure",
                "taira",
                "--config",
                "client.toml",
                "--fee-payer",
                "sponsor",
                "--fee-program-revision",
                "0"
            ])
            .is_err()
        );
    }

    #[test]
    fn invalid_bindings_fail_closed_without_disclosing_source() {
        let dir = tempfile::tempdir().expect("workspace");
        for source in [
            "version = 2\n",
            "version = 1\ndefault = 'absent'\n[networks]\n",
            "version = 1\ndefault = 'taira'\nprivate_key = 'sensitive-value'\n[networks.taira]\n",
            "malformed 'sensitive-value",
        ] {
            fs::write(dir.path().join(NETWORK_FILE), source).expect("invalid file");
            let error = read_bindings(dir.path()).expect_err("invalid binding");
            let rendered = CommandOutput::failure("network", error)
                .render(OutputFormat::Json)
                .expect("redacted diagnostic");
            assert!(!rendered.stdout().contains("sensitive-value"));
        }
    }

    #[test]
    fn binding_writes_preserve_the_last_readable_image_at_the_size_limit() {
        let root = tempfile::tempdir().expect("workspace");
        let args = ConfigureArgs {
            selection: SelectionArgs::default(),
            name: "taira".to_owned(),
            config: Some(public_config(root.path())),
            wallet: None,
            wallet_dir: None,
            fee_payer: None,
            fee_program: None,
            fee_program_revision: None,
            contract: None,
            alias: None,
        };
        configure(root.path(), &args, None).expect("initial binding");
        let mut document = read_bindings(root.path()).expect("binding");
        let initial_len = encode_bindings(&document).expect("encoded").len();
        let config = document
            .get_mut("networks")
            .expect("networks")
            .as_table_mut()
            .expect("table")
            .get_mut("taira")
            .expect("taira")
            .as_table_mut()
            .expect("binding")
            .get_mut("config")
            .expect("config");
        let padded_len =
            config.as_str().expect("reference").len() + MAX_NETWORK_FILE_BYTES - initial_len;
        *config = toml::Value::String("x".repeat(padded_len));
        let at_limit = encode_bindings(&document).expect("inclusive bound");
        assert_eq!(at_limit.len(), MAX_NETWORK_FILE_BYTES);
        AtomicWriteRoot::new(root.path())
            .expect("root")
            .replace(Path::new(NETWORK_FILE), at_limit.as_bytes())
            .expect("existing bounded file");
        let next = ConfigureArgs {
            name: "another".to_owned(),
            ..args
        };
        assert!(configure(root.path(), &next, None).is_err());
        assert_eq!(
            fs::read_to_string(root.path().join(NETWORK_FILE)).expect("preserved image"),
            at_limit
        );
        assert!(read_bindings(root.path()).is_ok());
        document.insert("one-more-field".to_owned(), toml::Value::Boolean(true));
        assert!(encode_bindings(&document).is_err());
    }

    #[test]
    fn target_bindings_share_canonical_manifest_names_without_path_components() {
        for target in ["coffee.v1", "coffee::v1", "\u{73c8}\u{7432}"] {
            validate_contract_key(&format!("demo/coffee::{target}")).expect("canonical target");
        }
        for target in ["", ".", "..", "a/b", "a\\b", "e\u{0301}"] {
            assert!(validate_contract_key(&format!("demo/coffee::{target}")).is_err());
        }
        assert!(validate_contract_key("demo/coffee/other::target").is_err());
    }

    #[cfg(unix)]
    #[test]
    fn linked_bindings_cannot_redirect_reads_or_writes() {
        use std::os::unix::fs::symlink;
        let dir = tempfile::tempdir().expect("workspace");
        let external = tempfile::tempdir().expect("outside workspace");
        let victim = external.path().join("victim");
        fs::write(&victim, "do not touch").expect("victim");
        symlink(&victim, dir.path().join(NETWORK_FILE)).expect("symlink");
        assert!(read_bindings(dir.path()).is_err());
        assert_eq!(
            fs::read_to_string(&victim).expect("unchanged victim"),
            "do not touch"
        );
    }
}
