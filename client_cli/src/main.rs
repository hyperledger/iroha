//! iroha client command line
use std::{
    fs::{self, read as read_file},
    io::{stdin, stdout},
    path::PathBuf,
    str::FromStr,
    time::Duration,
};

use color_eyre::{
    eyre::{eyre, Error, WrapErr},
    Result,
};
// FIXME: sync with `kagami` (it uses `inquiry`, migrate both to something single)
use dialoguer::Confirm;
use erased_serde::Serialize;
use iroha_client::{
    client::{Client, QueryResult},
    config::{path::Path, Configuration as ClientConfiguration, ConfigurationProxy},
    data_model::prelude::*,
};
use iroha_config_base::proxy::{LoadFromDisk, LoadFromEnv, Override};
use iroha_primitives::addr::{Ipv4Addr, Ipv6Addr, SocketAddr};

/// Re-usable clap `--metadata <PATH>` (`-m`) argument.
/// Should be combined with `#[command(flatten)]` attr.
#[derive(clap::Args, Debug, Clone)]
// FIXME: `pub` is needed because Rust complains about "leaking private types"
//        when this type is used inside of modules. I don't know how to fix it.
pub struct MetadataArgs {
    /// The JSON/JSON5 file with key-value metadata pairs
    #[arg(short, long, value_name("PATH"), value_hint(clap::ValueHint::FilePath))]
    metadata: Option<PathBuf>,
}

impl MetadataArgs {
    fn load(self) -> Result<UnlimitedMetadata> {
        let value: Option<UnlimitedMetadata> = self
            .metadata
            .map(|path| {
                let content = fs::read_to_string(&path).wrap_err_with(|| {
                    eyre!("Failed to read the metadata file `{}`", path.display())
                })?;
                let metadata: UnlimitedMetadata =
                    json5::from_str(&content).wrap_err_with(|| {
                        eyre!(
                            "Failed to deserialize metadata from file `{}`",
                            path.display()
                        )
                    })?;
                Ok::<_, color_eyre::Report>(metadata)
            })
            .transpose()?;

        Ok(value.unwrap_or_default())
    }
}
/// Wrapper around Value to accept possible values and fallback to json
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValueArg(Value);

impl FromStr for ValueArg {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        s.parse::<bool>()
            .map(Value::Bool)
            .or_else(|_| s.parse::<Ipv4Addr>().map(Value::Ipv4Addr))
            .or_else(|_| s.parse::<Ipv6Addr>().map(Value::Ipv6Addr))
            .or_else(|_| s.parse::<NumericValue>().map(Value::Numeric))
            .or_else(|_| s.parse::<PublicKey>().map(Value::PublicKey))
            .or_else(|_| serde_json::from_str::<Value>(s).map_err(|e| e.into()))
            .map(ValueArg)
    }
}

/// Iroha CLI Client provides an ability to interact with Iroha Peers Web API without direct network usage.
#[derive(clap::Parser, Debug)]
#[command(name = "iroha_client_cli", version = concat!("version=", env!("CARGO_PKG_VERSION"), " git_commit_sha=", env!("VERGEN_GIT_SHA")), author)]
struct Args {
    /// Path to the configuration file, defaults to `config.json`/`config.json5`
    ///
    /// Supported extensions are `.json` and `.json5`. By default, Iroha Client looks for a
    /// `config` file with one of the supported extensions in the current working directory.
    /// If the default config file is not found, Iroha will rely on default values and environment
    /// variables. However, if the config path is set explicitly with this argument and the file
    /// is not found, Iroha Client will exit with an error.
    #[arg(
        short,
        long,
        value_name("PATH"),
        value_hint(clap::ValueHint::FilePath),
        value_parser(Path::user_provided_str)
    )]
    config: Option<Path>,
    /// More verbose output
    #[arg(short, long)]
    verbose: bool,
    /// Skip MST check. By setting this flag searching similar transactions on the server can be omitted.
    /// Thus if you don't use multisignature transactions you should use this flag as it will increase speed of submitting transactions.
    /// Also setting this flag could be useful when `iroha_client_cli` is used to submit the same transaction multiple times (like mint for example) in short period of time.
    #[arg(long)]
    skip_mst_check: bool,
    /// Subcommands of client cli
    #[command(subcommand)]
    subcommand: Subcommand,
}

#[derive(clap::Subcommand, Debug)]
enum Subcommand {
    /// The subcommand related to domains
    #[clap(subcommand)]
    Domain(domain::Args),
    /// The subcommand related to accounts
    #[clap(subcommand)]
    Account(account::Args),
    /// The subcommand related to assets
    #[clap(subcommand)]
    Asset(asset::Args),
    /// The subcommand related to p2p networking
    #[clap(subcommand)]
    Peer(peer::Args),
    /// The subcommand related to event streaming
    #[clap(subcommand)]
    Events(events::Args),
    /// The subcommand related to Wasm
    Wasm(wasm::Args),
    /// The subcommand related to block streaming
    Blocks(blocks::Args),
    /// The subcommand related to multi-instructions as Json or Json5
    Json(json::Args),
}

/// Context inside which command is executed
trait RunContext {
    /// Get access to configuration
    fn configuration(&self) -> &ClientConfiguration;

    /// Skip check for MST
    fn skip_mst_check(&self) -> bool;

    /// Serialize and print data
    ///
    /// # Errors
    /// - if serialization fails
    /// - if printing fails
    fn print_data(&mut self, data: &dyn Serialize) -> Result<()>;
}

struct PrintJsonContext<W> {
    write: W,
    config: ClientConfiguration,
    skip_mst_check: bool,
}

impl<W: std::io::Write> RunContext for PrintJsonContext<W> {
    fn configuration(&self) -> &ClientConfiguration {
        &self.config
    }

    fn print_data(&mut self, data: &dyn Serialize) -> Result<()> {
        writeln!(&mut self.write, "{}", serde_json::to_string_pretty(data)?)?;
        Ok(())
    }

    fn skip_mst_check(&self) -> bool {
        self.skip_mst_check
    }
}

/// Runs subcommand
trait RunArgs {
    /// Runs command
    ///
    /// # Errors
    /// if inner command errors
    fn run(self, context: &mut dyn RunContext) -> Result<()>;
}

macro_rules! match_all {
    (($self:ident, $context:ident), { $($variants:path),* $(,)?}) => {
        match $self {
            $($variants(variant) => RunArgs::run(variant, $context),)*
        }
    };
}

impl RunArgs for Subcommand {
    fn run(self, context: &mut dyn RunContext) -> Result<()> {
        use Subcommand::*;
        match_all!((self, context), { Domain, Account, Asset, Peer, Events, Wasm, Blocks, Json })
    }
}

// TODO: move into config.
const RETRY_COUNT_MST: u32 = 1;
const RETRY_IN_MST: Duration = Duration::from_millis(100);

static DEFAULT_CONFIG_PATH: &str = "config";

fn main() -> Result<()> {
    color_eyre::install()?;
    let Args {
        config: config_path,
        subcommand,
        verbose,
        skip_mst_check,
    } = clap::Parser::parse();

    let config = ConfigurationProxy::default();
    let config = if let Some(path) = config_path
        .unwrap_or_else(|| Path::default(DEFAULT_CONFIG_PATH))
        .try_resolve()
        .wrap_err("Failed to resolve config file")?
    {
        config.override_with(ConfigurationProxy::from_path(&*path))
    } else {
        config
    };
    let config = config.override_with(
        ConfigurationProxy::from_std_env().wrap_err("Failed to read config from ENV")?,
    );
    let config = config
        .build()
        .wrap_err("Failed to finalize configuration")?;

    if verbose {
        eprintln!(
            "Configuration: {}",
            &serde_json::to_string_pretty(&config)
                .wrap_err("Failed to serialize configuration.")?
        );
    }

    let mut context = PrintJsonContext {
        write: stdout(),
        config,
        skip_mst_check,
    };

    subcommand.run(&mut context)
}

/// Submit instruction with metadata to network.
///
/// # Errors
/// Fails if submitting over network fails
#[allow(clippy::shadow_unrelated)]
fn submit(
    instructions: impl Into<Executable>,
    metadata: UnlimitedMetadata,
    context: &mut dyn RunContext,
) -> Result<()> {
    let iroha_client = Client::new(context.configuration())?;
    let instructions = instructions.into();
    #[cfg(debug_assertions)]
    let err_msg = format!("Failed to build transaction from instruction {instructions:?}");
    #[cfg(not(debug_assertions))]
    let err_msg = "Failed to build transaction.";
    let tx = iroha_client
        .build_transaction(instructions, metadata)
        .wrap_err(err_msg)?;
    let tx = if context.skip_mst_check() {
        tx
    } else {
        match iroha_client.get_original_transaction(
            &tx,
            RETRY_COUNT_MST,
            RETRY_IN_MST,
        ) {
            Ok(Some(original_transaction)) if Confirm::new()
                .with_prompt("There is a similar transaction from your account waiting for more signatures. \
                            This could be because it wasn't signed with the right key, \
                            or because it's a multi-signature transaction (MST). \
                            Do you want to sign this transaction (yes) \
                            instead of submitting a new transaction (no)?")
                .interact()
                .wrap_err("Failed to show interactive prompt.")? => iroha_client.sign_transaction(original_transaction).wrap_err("Failed to sign transaction.")?,
            _ => tx,
        }
    };
    #[cfg(debug_assertions)]
    let err_msg = format!("Failed to submit transaction {tx:?}");
    #[cfg(not(debug_assertions))]
    let err_msg = "Failed to submit transaction.";
    let hash = iroha_client
        .submit_transaction_blocking(&tx)
        .wrap_err(err_msg)?;
    context.print_data(&hash)?;
    Ok(())
}

mod filter {
    use iroha_client::data_model::predicate::PredicateBox;

    use super::*;

    /// Filter for queries
    #[derive(Clone, Debug, clap::Parser)]
    pub struct Filter {
        /// Predicate for filtering given as JSON5 string
        #[clap(value_parser = parse_filter)]
        pub predicate: PredicateBox,
    }

    fn parse_filter(s: &str) -> Result<PredicateBox, String> {
        json5::from_str(s).map_err(|err| format!("Failed to deserialize filter from JSON5: {err}"))
    }
}

mod events {
    use iroha_client::client::Client;

    use super::*;

    /// Get event stream from iroha peer
    #[derive(clap::Subcommand, Debug, Clone, Copy)]
    pub enum Args {
        /// Gets pipeline events
        Pipeline,
        /// Gets data events
        Data,
        /// Get notification events
        Notification,
    }

    impl RunArgs for Args {
        fn run(self, context: &mut dyn RunContext) -> Result<()> {
            let filter = match self {
                Args::Pipeline => FilterBox::Pipeline(PipelineEventFilter::new()),
                Args::Data => FilterBox::Data(DataEventFilter::AcceptAll),
                Args::Notification => FilterBox::Notification(NotificationEventFilter::AcceptAll),
            };
            listen(filter, context)
        }
    }

    fn listen(filter: FilterBox, context: &mut dyn RunContext) -> Result<()> {
        let iroha_client = Client::new(context.configuration())?;
        eprintln!("Listening to events with filter: {filter:?}");
        iroha_client
            .listen_for_events(filter)
            .wrap_err("Failed to listen for events.")?
            .try_for_each(|event| context.print_data(&event?))?;
        Ok(())
    }
}

mod blocks {
    use std::num::NonZeroU64;

    use iroha_client::client::Client;

    use super::*;

    /// Get block stream from iroha peer
    #[derive(clap::Args, Debug, Clone, Copy)]
    pub struct Args {
        /// Block height from which to start streaming blocks
        height: NonZeroU64,
    }

    impl RunArgs for Args {
        fn run(self, context: &mut dyn RunContext) -> Result<()> {
            let Args { height } = self;
            listen(height, context)
        }
    }

    fn listen(height: NonZeroU64, context: &mut dyn RunContext) -> Result<()> {
        let iroha_client = Client::new(context.configuration())?;
        eprintln!("Listening to blocks from height: {height}");
        iroha_client
            .listen_for_blocks(height)
            .wrap_err("Failed to listen for blocks.")?
            .try_for_each(|event| context.print_data(&event?))?;
        Ok(())
    }
}

mod domain {
    use iroha_client::client;

    use super::*;

    /// Arguments for domain subcommand
    #[derive(Debug, clap::Subcommand)]
    pub enum Args {
        /// Register domain
        Register(Register),
        /// List domains
        #[clap(subcommand)]
        List(List),
        /// Transfer domain
        Transfer(Transfer),
        /// Edit domain metadata
        #[clap(subcommand)]
        Metadata(metadata::Args),
    }

    impl RunArgs for Args {
        fn run(self, context: &mut dyn RunContext) -> Result<()> {
            match_all!((self, context), { Args::Register, Args::List, Args::Transfer, Args::Metadata,  })
        }
    }

    /// Add subcommand for domain
    #[derive(Debug, clap::Args)]
    pub struct Register {
        /// Domain name as double-quoted string
        #[arg(short, long)]
        pub id: DomainId,
        #[command(flatten)]
        pub metadata: MetadataArgs,
    }

    impl RunArgs for Register {
        fn run(self, context: &mut dyn RunContext) -> Result<()> {
            let Self { id, metadata } = self;
            let create_domain = iroha_client::data_model::isi::Register::domain(Domain::new(id));
            submit([create_domain], metadata.load()?, context).wrap_err("Failed to create domain")
        }
    }

    /// List domains with this command
    #[derive(clap::Subcommand, Debug, Clone)]
    pub enum List {
        /// All domains
        All,
        /// Filter domains by given predicate
        Filter(filter::Filter),
    }

    impl RunArgs for List {
        fn run(self, context: &mut dyn RunContext) -> Result<()> {
            let client = Client::new(context.configuration())?;

            let vec = match self {
                Self::All => client
                    .request(client::domain::all())
                    .wrap_err("Failed to get all domains"),
                Self::Filter(filter) => client
                    .build_query(client::domain::all())
                    .with_filter(filter.predicate)
                    .execute()
                    .wrap_err("Failed to get filtered domains"),
            }?;
            context.print_data(&vec.collect::<QueryResult<Vec<_>>>()?)?;
            Ok(())
        }
    }

    /// Transfer a domain between accounts
    #[derive(Debug, clap::Args)]
    pub struct Transfer {
        /// Domain name as double-quited string
        #[arg(short, long)]
        pub id: DomainId,
        /// Account from which to transfer (in form `name@domain_name')
        #[arg(short, long)]
        pub from: AccountId,
        /// Account to which to transfer (in form `name@domain_name')
        #[arg(short, long)]
        pub to: AccountId,
        #[command(flatten)]
        pub metadata: MetadataArgs,
    }

    impl RunArgs for Transfer {
        fn run(self, context: &mut dyn RunContext) -> Result<()> {
            let Self {
                id,
                from,
                to,
                metadata,
            } = self;
            let transfer_domain = iroha_client::data_model::isi::Transfer::domain(from, id, to);
            submit([transfer_domain], metadata.load()?, context)
                .wrap_err("Failed to transfer domain")
        }
    }

    mod metadata {
        use iroha_client::data_model::{self, domain::DomainId};

        use super::*;

        /// A value wrapper that can be parsed from CLI arguments
        #[derive(Debug, Clone)]
        pub struct MetadataValue(data_model::Value);

        impl FromStr for MetadataValue {
            type Err = Error;

            fn from_str(s: &str) -> Result<Self> {
                let deser_err_msg = format!("Failed to deserialize `{s}` into value.");
                let metadata: Value = json5::from_str(s).wrap_err(deser_err_msg)?;
                Ok(Self(metadata))
            }
        }

        /// Edit domain subcommands
        #[derive(Debug, Clone, clap::Subcommand)]
        pub enum Args {
            /// Set metadata into domain
            Set(Set),
            /// Remove metadata into domain
            Remove(Remove),
        }

        impl RunArgs for Args {
            fn run(self, context: &mut dyn RunContext) -> Result<()> {
                match_all!((self, context), { Args::Set, Args::Remove, })
            }
        }

        /// Set metadata into domain
        #[derive(Debug, Clone, clap::Args)]
        pub struct Set {
            /// A domain id from which metadata is to be removed
            #[arg(short, long)]
            id: DomainId,
            /// A key of metadata
            #[arg(short, long)]
            key: Name,
            /// A value of metadata
            #[arg(short, long)]
            value: MetadataValue,
        }

        impl RunArgs for Set {
            fn run(self, context: &mut dyn RunContext) -> Result<()> {
                let Self {
                    id,
                    key,
                    value: MetadataValue(value),
                } = self;
                let set_key_value = SetKeyValue::domain(id, key, value);
                submit([set_key_value], UnlimitedMetadata::new(), context)
                    .wrap_err("Failed to submit Set instruction")
            }
        }

        /// Remove metadata into domain by key
        #[derive(Debug, Clone, clap::Args)]
        pub struct Remove {
            /// A domain id from which metadata is to be removed
            #[arg(short, long)]
            id: DomainId,
            /// A key of metadata
            #[arg(short, long)]
            key: Name,
        }

        impl RunArgs for Remove {
            fn run(self, context: &mut dyn RunContext) -> Result<()> {
                let Self { id, key } = self;
                let remove_key_value = RemoveKeyValue::domain(id, key);
                submit([remove_key_value], UnlimitedMetadata::new(), context)
                    .wrap_err("Failed to submit Remove instruction")
            }
        }
    }
}

mod account {
    use std::fmt::Debug;

    use iroha_client::client::{self};

    use super::*;

    /// subcommands for account subcommand
    #[derive(clap::Subcommand, Debug)]
    pub enum Args {
        /// Register account
        Register(Register),
        /// Set something in account
        #[command(subcommand)]
        Set(Set),
        /// List accounts
        #[command(subcommand)]
        List(List),
        /// Grant a permission to the account
        Grant(Grant),
        /// List all account permissions
        ListPermissions(ListPermissions),
    }

    impl RunArgs for Args {
        fn run(self, context: &mut dyn RunContext) -> Result<()> {
            match_all!((self, context), {
                Args::Register,
                Args::Set,
                Args::List,
                Args::Grant,
                Args::ListPermissions,
            })
        }
    }

    /// Register account
    #[derive(clap::Args, Debug)]
    pub struct Register {
        /// Id of account in form `name@domain_name'
        #[arg(short, long)]
        pub id: AccountId,
        /// Its public key
        #[arg(short, long)]
        pub key: PublicKey,
        #[command(flatten)]
        pub metadata: MetadataArgs,
    }

    impl RunArgs for Register {
        fn run(self, context: &mut dyn RunContext) -> Result<()> {
            let Self { id, key, metadata } = self;
            let create_account =
                iroha_client::data_model::isi::Register::account(Account::new(id, [key]));
            submit([create_account], metadata.load()?, context)
                .wrap_err("Failed to register account")
        }
    }

    /// Set subcommand of account
    #[derive(clap::Subcommand, Debug)]
    pub enum Set {
        /// Signature condition
        SignatureCondition(SignatureCondition),
    }

    impl RunArgs for Set {
        fn run(self, context: &mut dyn RunContext) -> Result<()> {
            match_all!((self, context), { Set::SignatureCondition })
        }
    }

    #[derive(Debug, Clone)]
    pub struct Signature(SignatureCheckCondition);

    impl FromStr for Signature {
        type Err = Error;
        fn from_str(s: &str) -> Result<Self> {
            let err_msg = format!("Failed to open the signature condition file {}", &s);
            let deser_err_msg =
                format!("Failed to deserialize signature condition from file {}", &s);
            let content = fs::read_to_string(s).wrap_err(err_msg)?;
            let condition: SignatureCheckCondition =
                json5::from_str(&content).wrap_err(deser_err_msg)?;
            Ok(Self(condition))
        }
    }

    /// Set accounts signature condition
    #[derive(clap::Args, Debug)]
    pub struct SignatureCondition {
        /// Signature condition file
        pub condition: Signature,
        #[command(flatten)]
        pub metadata: MetadataArgs,
    }

    impl RunArgs for SignatureCondition {
        fn run(self, context: &mut dyn RunContext) -> Result<()> {
            let account_id = context.configuration().account_id.clone();
            let Self {
                condition: Signature(condition),
                metadata,
            } = self;
            let mint_box = Mint::account_signature_check_condition(condition, account_id);
            submit([mint_box], metadata.load()?, context)
                .wrap_err("Failed to set signature condition")
        }
    }

    /// List accounts with this command
    #[derive(clap::Subcommand, Debug, Clone)]
    pub enum List {
        /// All accounts
        All,
        /// Filter accounts by given predicate
        Filter(filter::Filter),
    }

    impl RunArgs for List {
        fn run(self, context: &mut dyn RunContext) -> Result<()> {
            let client = Client::new(context.configuration())?;

            let vec = match self {
                Self::All => client
                    .request(client::account::all())
                    .wrap_err("Failed to get all accounts"),
                Self::Filter(filter) => client
                    .build_query(client::account::all())
                    .with_filter(filter.predicate)
                    .execute()
                    .wrap_err("Failed to get filtered accounts"),
            }?;
            context.print_data(&vec.collect::<QueryResult<Vec<_>>>()?)?;
            Ok(())
        }
    }

    #[derive(clap::Args, Debug)]
    pub struct Grant {
        /// Account id
        #[arg(short, long)]
        pub id: AccountId,
        /// The JSON/JSON5 file with a permission token
        #[arg(short, long)]
        pub permission: Permission,
        #[command(flatten)]
        pub metadata: MetadataArgs,
    }

    /// [`PermissionToken`] wrapper implementing [`FromStr`]
    #[derive(Debug, Clone)]
    pub struct Permission(PermissionToken);

    impl FromStr for Permission {
        type Err = Error;

        fn from_str(s: &str) -> Result<Self> {
            let content = fs::read_to_string(s)
                .wrap_err(format!("Failed to read the permission token file {}", &s))?;
            let permission_token: PermissionToken = json5::from_str(&content).wrap_err(format!(
                "Failed to deserialize the permission token from file {}",
                &s
            ))?;
            Ok(Self(permission_token))
        }
    }

    impl RunArgs for Grant {
        fn run(self, context: &mut dyn RunContext) -> Result<()> {
            let Self {
                id,
                permission,
                metadata,
            } = self;
            let grant = iroha_client::data_model::isi::Grant::permission_token(permission.0, id);
            submit([grant], metadata.load()?, context)
                .wrap_err("Failed to grant the permission to the account")
        }
    }

    /// List all account permissions
    #[derive(clap::Args, Debug)]
    pub struct ListPermissions {
        /// Account id
        #[arg(short, long)]
        id: AccountId,
    }

    impl RunArgs for ListPermissions {
        fn run(self, context: &mut dyn RunContext) -> Result<()> {
            let client = Client::new(context.configuration())?;
            let find_all_permissions = FindPermissionTokensByAccountId::new(self.id);
            let permissions = client
                .request(find_all_permissions)
                .wrap_err("Failed to get all account permissions")?;
            context.print_data(&permissions.collect::<QueryResult<Vec<_>>>()?)?;
            Ok(())
        }
    }
}

mod asset {
    use iroha_client::{
        client::{self, asset, Client},
        data_model::{asset::AssetDefinition, name::Name},
    };

    use super::*;

    /// Subcommand for dealing with asset
    #[derive(clap::Subcommand, Debug)]
    pub enum Args {
        /// Command for Registering a new asset
        Register(Register),
        /// Command for minting asset in existing Iroha account
        Mint(Mint),
        /// Command for burning asset in existing Iroha account
        Burn(Burn),
        /// Transfer asset between accounts
        Transfer(Transfer),
        /// Get info of asset
        Get(Get),
        /// List assets
        #[clap(subcommand)]
        List(List),
        /// Set a key-value entry in a Store asset
        SetKeyValue(SetKeyValue),
        /// Remove a key-value entry from a Store asset
        RemoveKeyValue(RemoveKeyValue),
        /// Get a value from a Store asset
        GetKeyValue(GetKeyValue),
    }

    impl RunArgs for Args {
        fn run(self, context: &mut dyn RunContext) -> Result<()> {
            match_all!(
                (self, context),
                { Args::Register, Args::Mint, Args::Burn, Args::Transfer, Args::Get, Args::List, Args::SetKeyValue, Args::RemoveKeyValue, Args::GetKeyValue}
            )
        }
    }

    /// Register subcommand of asset
    #[derive(clap::Args, Debug)]
    pub struct Register {
        /// Asset id for registering (in form of `name#domain_name')
        #[arg(short, long)]
        pub id: AssetDefinitionId,
        /// Mintability of asset
        #[arg(short, long)]
        pub unmintable: bool,
        /// Value type stored in asset
        #[arg(short, long)]
        pub value_type: AssetValueType,
        #[command(flatten)]
        pub metadata: MetadataArgs,
    }

    impl RunArgs for Register {
        fn run(self, context: &mut dyn RunContext) -> Result<()> {
            let Self {
                id,
                value_type,
                unmintable,
                metadata,
            } = self;
            let mut asset_definition = match value_type {
                AssetValueType::Quantity => AssetDefinition::quantity(id),
                AssetValueType::BigQuantity => AssetDefinition::big_quantity(id),
                AssetValueType::Fixed => AssetDefinition::fixed(id),
                AssetValueType::Store => AssetDefinition::store(id),
            };
            if unmintable {
                asset_definition = asset_definition.mintable_once();
            }
            let create_asset_definition =
                iroha_client::data_model::isi::Register::asset_definition(asset_definition);
            submit([create_asset_definition], metadata.load()?, context)
                .wrap_err("Failed to register asset")
        }
    }

    /// Command for minting asset in existing Iroha account
    #[derive(clap::Args, Debug)]
    pub struct Mint {
        /// Account id where asset is stored (in form of `name@domain_name')
        #[arg(long)]
        pub account: AccountId,
        /// Asset id from which to mint (in form of `name#domain_name')
        #[arg(long)]
        pub asset: AssetDefinitionId,
        /// Quantity to mint
        #[arg(short, long)]
        pub quantity: u32,
        #[command(flatten)]
        pub metadata: MetadataArgs,
    }

    impl RunArgs for Mint {
        fn run(self, context: &mut dyn RunContext) -> Result<()> {
            let Self {
                account,
                asset,
                quantity,
                metadata,
            } = self;
            let mint_asset = iroha_client::data_model::isi::Mint::asset_quantity(
                quantity,
                AssetId::new(asset, account),
            );
            submit([mint_asset], metadata.load()?, context)
                .wrap_err("Failed to mint asset of type `NumericValue::U32`")
        }
    }

    /// Command for minting asset in existing Iroha account
    #[derive(clap::Args, Debug)]
    pub struct Burn {
        /// Account id where asset is stored (in form of `name@domain_name')
        #[arg(long)]
        pub account: AccountId,
        /// Asset id from which to mint (in form of `name#domain_name')
        #[arg(long)]
        pub asset: AssetDefinitionId,
        /// Quantity to mint
        #[arg(short, long)]
        pub quantity: u32,
        #[command(flatten)]
        pub metadata: MetadataArgs,
    }

    impl RunArgs for Burn {
        fn run(self, context: &mut dyn RunContext) -> Result<()> {
            let Self {
                account,
                asset,
                quantity,
                metadata,
            } = self;
            let burn_asset = iroha_client::data_model::isi::Burn::asset_quantity(
                quantity,
                AssetId::new(asset, account),
            );
            submit([burn_asset], metadata.load()?, context)
                .wrap_err("Failed to burn asset of type `NumericValue::U32`")
        }
    }

    /// Transfer asset between accounts
    #[derive(clap::Args, Debug)]
    pub struct Transfer {
        /// Account from which to transfer (in form `name@domain_name')
        #[arg(short, long)]
        pub from: AccountId,
        /// Account to which to transfer (in form `name@domain_name')
        #[arg(short, long)]
        pub to: AccountId,
        /// Asset id to transfer (in form like `name#domain_name')
        #[arg(short, long)]
        pub asset_id: AssetDefinitionId,
        /// Quantity of asset as number
        #[arg(short, long)]
        pub quantity: u32,
        #[command(flatten)]
        pub metadata: MetadataArgs,
    }

    impl RunArgs for Transfer {
        fn run(self, context: &mut dyn RunContext) -> Result<()> {
            let Self {
                from,
                to,
                asset_id,
                quantity,
                metadata,
            } = self;
            let transfer_asset = iroha_client::data_model::isi::Transfer::asset_quantity(
                AssetId::new(asset_id, from),
                quantity,
                to,
            );
            submit([transfer_asset], metadata.load()?, context).wrap_err("Failed to transfer asset")
        }
    }

    /// Get info of asset
    #[derive(clap::Args, Debug)]
    pub struct Get {
        /// Account where asset is stored (in form of `name@domain_name')
        #[arg(long)]
        pub account: AccountId,
        /// Asset name to lookup (in form of `name#domain_name')
        #[arg(long)]
        pub asset: AssetDefinitionId,
    }

    impl RunArgs for Get {
        fn run(self, context: &mut dyn RunContext) -> Result<()> {
            let Self { account, asset } = self;
            let iroha_client = Client::new(context.configuration())?;
            let asset_id = AssetId::new(asset, account);
            let asset = iroha_client
                .request(asset::by_id(asset_id))
                .wrap_err("Failed to get asset.")?;
            context.print_data(&asset)?;
            Ok(())
        }
    }

    /// List assets with this command
    #[derive(clap::Subcommand, Debug, Clone)]
    pub enum List {
        /// All assets
        All,
        /// Filter assets by given predicate
        Filter(filter::Filter),
    }

    impl RunArgs for List {
        fn run(self, context: &mut dyn RunContext) -> Result<()> {
            let client = Client::new(context.configuration())?;

            let vec = match self {
                Self::All => client
                    .request(client::asset::all())
                    .wrap_err("Failed to get all assets"),
                Self::Filter(filter) => client
                    .build_query(client::asset::all())
                    .with_filter(filter.predicate)
                    .execute()
                    .wrap_err("Failed to get filtered assets"),
            }?;
            context.print_data(&vec.collect::<QueryResult<Vec<_>>>()?)?;
            Ok(())
        }
    }

    #[derive(clap::Args, Debug)]
    pub struct SetKeyValue {
        /// AssetId for the Store asset (in form of `asset##account@domain_name')
        #[clap(long)]
        pub asset_id: AssetId,
        /// The key for the store value
        #[clap(long)]
        pub key: Name,
        /// The value to be associated with the specified key.
        /// The following types are supported:
        /// Numbers: with a suffix, e.g. 42_u32 or 1000_u128
        /// Booleans: false/true
        /// IPv4/IPv6: e.g. 127.0.0.1, ::1
        /// Iroha Public Key Multihash: e.g. ed01207233BFC89DCBD68C19FDE6CE6158225298EC1131B6A130D1AEB454C1AB5183C0
        /// JSON: e.g. {"Vec":[{"String":"a"},{"String":"b"}]}
        #[clap(long)]
        pub value: ValueArg,
    }

    impl RunArgs for SetKeyValue {
        fn run(self, context: &mut dyn RunContext) -> Result<()> {
            let Self {
                asset_id,
                key,
                value: ValueArg(value),
            } = self;

            let set = iroha_client::data_model::isi::SetKeyValue::asset(asset_id, key, value);
            submit([set], UnlimitedMetadata::default(), context)?;
            Ok(())
        }
    }
    #[derive(clap::Args, Debug)]
    pub struct RemoveKeyValue {
        /// AssetId for the Store asset (in form of `asset##account@domain_name')
        #[clap(long)]
        pub asset_id: AssetId,
        /// The key for the store value
        #[clap(long)]
        pub key: Name,
    }

    impl RunArgs for RemoveKeyValue {
        fn run(self, context: &mut dyn RunContext) -> Result<()> {
            let Self { asset_id, key } = self;
            let remove = iroha_client::data_model::isi::RemoveKeyValue::asset(asset_id, key);
            submit([remove], UnlimitedMetadata::default(), context)?;
            Ok(())
        }
    }

    #[derive(clap::Args, Debug)]
    pub struct GetKeyValue {
        /// AssetId for the Store asset (in form of `asset##account@domain_name')
        #[clap(long)]
        pub asset_id: AssetId,
        /// The key for the store value
        #[clap(long)]
        pub key: Name,
    }

    impl RunArgs for GetKeyValue {
        fn run(self, context: &mut dyn RunContext) -> Result<()> {
            let Self { asset_id, key } = self;
            let client = Client::new(context.configuration())?;
            let find_key_value = FindAssetKeyValueByIdAndKey::new(asset_id, key);
            let asset = client
                .request(find_key_value)
                .wrap_err("Failed to get key-value")?;
            context.print_data(&asset)?;
            Ok(())
        }
    }
}

mod peer {
    use super::*;

    /// Subcommand for dealing with peer
    #[derive(clap::Subcommand, Debug)]
    pub enum Args {
        /// Register subcommand of peer
        Register(Register),
        /// Unregister subcommand of peer
        Unregister(Unregister),
    }

    impl RunArgs for Args {
        fn run(self, context: &mut dyn RunContext) -> Result<()> {
            match_all!(
                (self, context),
                { Args::Register, Args::Unregister }
            )
        }
    }

    /// Register subcommand of peer
    #[derive(clap::Args, Debug)]
    pub struct Register {
        /// P2P address of the peer e.g. `127.0.0.1:1337`
        #[arg(short, long)]
        pub address: SocketAddr,
        /// Public key of the peer
        #[arg(short, long)]
        pub key: PublicKey,
        #[command(flatten)]
        pub metadata: MetadataArgs,
    }

    impl RunArgs for Register {
        fn run(self, context: &mut dyn RunContext) -> Result<()> {
            let Self {
                address,
                key,
                metadata,
            } = self;
            let register_peer = iroha_client::data_model::isi::Register::peer(Peer::new(
                PeerId::new(&address, &key),
            ));
            submit([register_peer], metadata.load()?, context).wrap_err("Failed to register peer")
        }
    }

    /// Unregister subcommand of peer
    #[derive(clap::Args, Debug)]
    pub struct Unregister {
        /// P2P address of the peer e.g. `127.0.0.1:1337`
        #[arg(short, long)]
        pub address: SocketAddr,
        /// Public key of the peer
        #[arg(short, long)]
        pub key: PublicKey,
        #[command(flatten)]
        pub metadata: MetadataArgs,
    }

    impl RunArgs for Unregister {
        fn run(self, context: &mut dyn RunContext) -> Result<()> {
            let Self {
                address,
                key,
                metadata,
            } = self;
            let unregister_peer =
                iroha_client::data_model::isi::Unregister::peer(PeerId::new(&address, &key));
            submit([unregister_peer], metadata.load()?, context)
                .wrap_err("Failed to unregister peer")
        }
    }
}

mod wasm {
    use std::{io::Read, path::PathBuf};

    use super::*;

    /// Subcommand for dealing with Wasm
    #[derive(Debug, clap::Args)]
    pub struct Args {
        /// Specify a path to the Wasm file or skip this flag to read from stdin
        #[arg(short, long)]
        path: Option<PathBuf>,
    }

    impl RunArgs for Args {
        fn run(self, context: &mut dyn RunContext) -> Result<()> {
            let raw_data = if let Some(path) = self.path {
                read_file(path).wrap_err("Failed to read a Wasm from the file into the buffer")?
            } else {
                let mut buf = Vec::<u8>::new();
                stdin()
                    .read_to_end(&mut buf)
                    .wrap_err("Failed to read a Wasm from stdin into the buffer")?;
                buf
            };

            submit(
                WasmSmartContract::from_compiled(raw_data),
                UnlimitedMetadata::new(),
                context,
            )
            .wrap_err("Failed to submit a Wasm smart contract")
        }
    }
}

mod json {
    use std::io::{BufReader, Read as _};

    use super::*;

    /// Subcommand for submitting multi-instructions
    #[derive(Clone, Copy, Debug, clap::Args)]
    pub struct Args;

    impl RunArgs for Args {
        fn run(self, context: &mut dyn RunContext) -> Result<()> {
            let mut reader = BufReader::new(stdin());
            let mut raw_content = Vec::new();
            reader.read_to_end(&mut raw_content)?;

            let string_content = String::from_utf8(raw_content)?;
            let instructions: Vec<InstructionBox> = json5::from_str(&string_content)?;
            submit(instructions, UnlimitedMetadata::new(), context)
                .wrap_err("Failed to submit parsed instructions")
        }
    }
}
#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use iroha_client::data_model::Value;

    use super::*;

    #[test]
    fn parse_value_arg_cases() {
        macro_rules! case {
            ($input:expr, $expected:expr) => {
                let ValueArg(actual) =
                    ValueArg::from_str($input).expect("should not fail with valid input");
                assert_eq!(actual, $expected);
            };
        }

        // IPv4 address
        case!(
            "192.168.0.1",
            Value::Ipv4Addr(Ipv4Addr::new([192, 168, 0, 1]))
        );

        // IPv6 address
        case!(
            "::1",
            Value::Ipv6Addr(Ipv6Addr::new([0, 0, 0, 0, 0, 0, 0, 1]))
        );

        // Boolean values
        case!("true", Value::Bool(true));
        case!("false", Value::Bool(false));

        // Numeric values
        case!("123_u32", Value::Numeric(NumericValue::U32(123)));
        case!("123_u64", Value::Numeric(NumericValue::U64(123)));
        case!("123_u128", Value::Numeric(NumericValue::U128(123)));

        let expected_fixed = NumericValue::Fixed(123.0.try_into().unwrap());
        case!("123.0_fx", Value::Numeric(expected_fixed));

        // Public Key
        let public_key_str =
            "ed01207233BFC89DCBD68C19FDE6CE6158225298EC1131B6A130D1AEB454C1AB5183C0";
        case!(
            public_key_str,
            Value::PublicKey(PublicKey::from_str(public_key_str).unwrap())
        );

        // JSON Value
        let json_str = r#"{"Vec":[{"String":"a"},{"String":"b"}]}"#;
        let expected_json: Value = serde_json::from_str(json_str).unwrap();
        case!(json_str, expected_json);
    }

    #[test]
    fn error_parse_invalid_value() {
        let invalid_str = "not_a_valid_value";
        let _invalid_value = ValueArg::from_str(invalid_str)
            .expect_err("Should fail invalid type from string but passed");
    }
}
