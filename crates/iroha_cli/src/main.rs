//! Iroha client CLI

use std::{
    fs::{self, read as read_file},
    io::{stdin, stdout},
    path::PathBuf,
    str::FromStr,
    time::Duration,
};

use erased_serde::Serialize;
use error_stack::{fmt::ColorMode, IntoReportCompat, ResultExt};
use eyre::{eyre, Error, Result, WrapErr};
use futures::TryStreamExt;
use iroha::{client::Client, config::Config, data_model::prelude::*};
use iroha_primitives::json::Json;
use thiserror::Error;
use tokio::runtime::Runtime;

/// Re-usable clap `--metadata <PATH>` (`-m`) argument.
/// Should be combined with `#[command(flatten)]` attr.
#[derive(clap::Args, Debug, Clone)]
pub struct MetadataArgs {
    /// The JSON/JSON5 file with key-value metadata pairs
    #[arg(short, long, value_name("PATH"), value_hint(clap::ValueHint::FilePath))]
    metadata: Option<PathBuf>,
}

impl MetadataArgs {
    fn load(self) -> Result<Metadata> {
        let value: Option<Metadata> = self
            .metadata
            .map(|path| {
                let content = fs::read_to_string(&path).wrap_err_with(|| {
                    eyre!("Failed to read the metadata file `{}`", path.display())
                })?;
                let metadata: Metadata = json5::from_str(&content).wrap_err_with(|| {
                    eyre!(
                        "Failed to deserialize metadata from file `{}`",
                        path.display()
                    )
                })?;
                Ok::<_, eyre::Report>(metadata)
            })
            .transpose()?;

        Ok(value.unwrap_or_default())
    }
}

/// Re-usable clap `--value <MetadataValue>` (`-v`) argument.
/// Should be combined with `#[command(flatten)]` attr.
#[derive(clap::Args, Debug, Clone, PartialEq, Eq)]
pub struct MetadataValueArg {
    /// Wrapper around `MetadataValue` to accept possible values and fallback to json.
    ///
    /// The following types are supported:
    /// Numbers: decimal with optional point
    /// Booleans: false/true
    /// Objects: e.g. {"Vec":[{"String":"a"},{"String":"b"}]}
    #[arg(short, long)]
    value: Json,
}

impl FromStr for MetadataValueArg {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(MetadataValueArg {
            value: Json::from_str(s)?,
        })
    }
}

/// Iroha CLI Client provides an ability to interact with Iroha Peers Web API without direct network usage.
#[derive(clap::Parser, Debug)]
#[command(name = "iroha", version = concat!("version=", env!("CARGO_PKG_VERSION"), " git_commit_sha=", env!("VERGEN_GIT_SHA")), author)]
struct Args {
    /// Path to the configuration file
    #[arg(short, long, value_name("PATH"), value_hint(clap::ValueHint::FilePath))]
    #[clap(default_value = "client.toml")]
    config: PathBuf,
    /// More verbose output
    #[arg(short, long)]
    verbose: bool,
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
    Events(events::Args),
    /// The subcommand related to Wasm
    Wasm(wasm::Args),
    /// The subcommand related to block streaming
    Blocks(blocks::Args),
    /// The subcommand related to multi-instructions as Json or Json5
    Json(json::Args),
    /// The subcommand related to multisig accounts and transactions
    #[clap(subcommand)]
    Multisig(multisig::Args),
}

/// Context inside which command is executed
trait RunContext {
    /// Get access to configuration
    fn configuration(&self) -> &Config;

    fn client_from_config(&self) -> Client {
        Client::new(self.configuration())
    }

    /// Serialize and print data
    ///
    /// # Errors
    /// - if serialization fails
    /// - if printing fails
    fn print_data(&mut self, data: &dyn Serialize) -> Result<()>;
}

struct PrintJsonContext<W> {
    write: W,
    config: Config,
}

impl<W: std::io::Write> RunContext for PrintJsonContext<W> {
    fn configuration(&self) -> &Config {
        &self.config
    }

    fn print_data(&mut self, data: &dyn Serialize) -> Result<()> {
        writeln!(&mut self.write, "{}", serde_json::to_string_pretty(data)?)?;
        Ok(())
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
        match_all!((self, context), { Domain, Account, Asset, Peer, Events, Wasm, Blocks, Json, Multisig })
    }
}

#[derive(Error, Debug)]
enum MainError {
    #[error("Failed to load Iroha client configuration")]
    Config,
    #[error("Failed to serialize config")]
    SerializeConfig,
    #[error("Failed to run the command")]
    Subcommand,
}

fn main() -> error_stack::Result<(), MainError> {
    let Args {
        config: config_path,
        subcommand,
        verbose,
    } = clap::Parser::parse();

    error_stack::Report::set_color_mode(color_mode());

    let config = Config::load(config_path)
        // FIXME: would be nice to NOT change the context, it's unnecessary
        .change_context(MainError::Config)
        .attach_printable("config path was set by `--config` argument")?;
    if verbose {
        eprintln!(
            "Configuration: {}",
            &serde_json::to_string_pretty(&config)
                .change_context(MainError::SerializeConfig)
                .attach_printable("caused by `--verbose` argument")?
        );
    }

    let mut context = PrintJsonContext {
        write: stdout(),
        config,
    };
    subcommand
        .run(&mut context)
        .into_report()
        .map_err(|report| report.change_context(MainError::Subcommand))?;

    Ok(())
}

fn color_mode() -> ColorMode {
    if supports_color::on(supports_color::Stream::Stdout).is_some()
        && supports_color::on(supports_color::Stream::Stderr).is_some()
    {
        ColorMode::Color
    } else {
        ColorMode::None
    }
}

/// Submit instruction with metadata to network.
///
/// # Errors
/// Fails if submitting over network fails
#[allow(clippy::shadow_unrelated)]
fn submit(
    instructions: impl Into<Executable>,
    metadata: Metadata,
    context: &mut dyn RunContext,
) -> Result<()> {
    let client = context.client_from_config();
    let instructions = instructions.into();
    let tx = client.build_transaction(instructions, metadata);

    #[cfg(not(debug_assertions))]
    let err_msg = "Failed to submit transaction.";
    #[cfg(debug_assertions)]
    let err_msg = format!("Failed to submit transaction {tx:?}");
    let hash = client.submit_transaction_blocking(&tx).wrap_err(err_msg)?;
    context.print_data(&hash)?;

    Ok(())
}

mod filter {
    use iroha::data_model::query::dsl::CompoundPredicate;
    use serde::Deserialize;

    use super::*;

    /// Filter for domain queries
    #[derive(Clone, Debug, clap::Parser)]
    pub struct DomainFilter {
        /// Predicate for filtering given as JSON5 string
        #[clap(value_parser = parse_json5::<CompoundPredicate<Domain>>)]
        pub predicate: CompoundPredicate<Domain>,
    }

    /// Filter for account queries
    #[derive(Clone, Debug, clap::Parser)]
    pub struct AccountFilter {
        /// Predicate for filtering given as JSON5 string
        #[clap(value_parser = parse_json5::<CompoundPredicate<Account>>)]
        pub predicate: CompoundPredicate<Account>,
    }

    /// Filter for asset queries
    #[derive(Clone, Debug, clap::Parser)]
    pub struct AssetFilter {
        /// Predicate for filtering given as JSON5 string
        #[clap(value_parser = parse_json5::<CompoundPredicate<Asset>>)]
        pub predicate: CompoundPredicate<Asset>,
    }

    /// Filter for asset definition queries
    #[derive(Clone, Debug, clap::Parser)]
    pub struct AssetDefinitionFilter {
        /// Predicate for filtering given as JSON5 string
        #[clap(value_parser = parse_json5::<CompoundPredicate<AssetDefinition>>)]
        pub predicate: CompoundPredicate<AssetDefinition>,
    }

    fn parse_json5<T>(s: &str) -> Result<T, String>
    where
        T: for<'a> Deserialize<'a>,
    {
        json5::from_str(s).map_err(|err| format!("Failed to deserialize filter from JSON5: {err}"))
    }
}

mod events {

    use iroha::data_model::events::pipeline::{BlockEventFilter, TransactionEventFilter};

    use super::*;

    #[derive(clap::Args, Debug, Clone, Copy)]
    pub struct Args {
        /// Wait timeout
        #[clap(short, long, global = true)]
        timeout: Option<humantime::Duration>,
        #[clap(subcommand)]
        command: Command,
    }

    /// Get event stream from Iroha peer
    #[derive(clap::Subcommand, Debug, Clone, Copy)]
    enum Command {
        /// Gets block pipeline events
        BlockPipeline,
        /// Gets transaction pipeline events
        TransactionPipeline,
        /// Gets data events
        Data,
        /// Get execute trigger events
        ExecuteTrigger,
        /// Get trigger completed events
        TriggerCompleted,
    }

    impl RunArgs for Args {
        fn run(self, context: &mut dyn RunContext) -> Result<()> {
            let timeout: Option<Duration> = self.timeout.map(Into::into);

            match self.command {
                Command::TransactionPipeline => {
                    listen(TransactionEventFilter::default(), context, timeout)
                }
                Command::BlockPipeline => listen(BlockEventFilter::default(), context, timeout),
                Command::Data => listen(DataEventFilter::Any, context, timeout),
                Command::ExecuteTrigger => {
                    listen(ExecuteTriggerEventFilter::new(), context, timeout)
                }
                Command::TriggerCompleted => {
                    listen(TriggerCompletedEventFilter::new(), context, timeout)
                }
            }
        }
    }

    fn listen(
        filter: impl Into<EventFilterBox>,
        context: &mut dyn RunContext,
        timeout: Option<Duration>,
    ) -> Result<()> {
        let filter = filter.into();
        let client = context.client_from_config();

        if let Some(timeout) = timeout {
            eprintln!("Listening to events with filter: {filter:?} and timeout: {timeout:?}");
            let rt = Runtime::new().wrap_err("Failed to create runtime.")?;
            rt.block_on(async {
                let mut stream = client
                    .listen_for_events_async([filter])
                    .await
                    .expect("Failed to listen for events.");
                while let Ok(event) = tokio::time::timeout(timeout, stream.try_next()).await {
                    context.print_data(&event?)?;
                }
                eprintln!("Timeout period has expired.");
                Result::<()>::Ok(())
            })?;
        } else {
            eprintln!("Listening to events with filter: {filter:?}");
            client
                .listen_for_events([filter])
                .wrap_err("Failed to listen for events.")?
                .try_for_each(|event| context.print_data(&event?))?;
        }
        Ok(())
    }
}

mod blocks {
    use std::num::NonZeroU64;

    use super::*;

    /// Get block stream from Iroha peer
    #[derive(clap::Args, Debug, Clone, Copy)]
    pub struct Args {
        /// Block height from which to start streaming blocks
        height: NonZeroU64,

        /// Wait timeout
        #[clap(short, long)]
        timeout: Option<humantime::Duration>,
    }

    impl RunArgs for Args {
        fn run(self, context: &mut dyn RunContext) -> Result<()> {
            let Args { height, timeout } = self;
            let timeout: Option<Duration> = timeout.map(Into::into);
            listen(height, context, timeout)
        }
    }

    fn listen(
        height: NonZeroU64,
        context: &mut dyn RunContext,
        timeout: Option<Duration>,
    ) -> Result<()> {
        let client = context.client_from_config();
        if let Some(timeout) = timeout {
            eprintln!("Listening to blocks from height: {height} and timeout: {timeout:?}");
            let rt = Runtime::new().wrap_err("Failed to create runtime.")?;
            rt.block_on(async {
                let mut stream = client
                    .listen_for_blocks_async(height)
                    .await
                    .expect("Failed to listen for blocks.");
                while let Ok(event) = tokio::time::timeout(timeout, stream.try_next()).await {
                    context.print_data(&event?)?;
                }
                eprintln!("Timeout period has expired.");
                Result::<()>::Ok(())
            })?;
        } else {
            eprintln!("Listening to blocks from height: {height}");
            client
                .listen_for_blocks(height)
                .wrap_err("Failed to listen for blocks.")?
                .try_for_each(|event| context.print_data(&event?))?;
        }
        Ok(())
    }
}

mod domain {
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
            let create_domain = iroha::data_model::isi::Register::domain(Domain::new(id));
            submit([create_domain], metadata.load()?, context).wrap_err("Failed to create domain")
        }
    }

    /// List domains with this command
    #[derive(clap::Subcommand, Debug, Clone)]
    pub enum List {
        /// All domains
        All,
        /// Filter domains by given predicate
        Filter(filter::DomainFilter),
    }

    impl RunArgs for List {
        fn run(self, context: &mut dyn RunContext) -> Result<()> {
            let client = context.client_from_config();

            let query = client.query(FindDomains::new());

            let query = match self {
                List::All => query,
                List::Filter(filter) => query.filter(filter.predicate),
            };

            let result = query.execute_all().wrap_err("Failed to get all accounts")?;
            context.print_data(&result)?;

            Ok(())
        }
    }

    /// Transfer a domain between accounts
    #[derive(Debug, clap::Args)]
    pub struct Transfer {
        /// Domain name as double-quited string
        #[arg(short, long)]
        pub id: DomainId,
        /// Account from which to transfer (in form `name@domain_name`)
        #[arg(short, long)]
        pub from: AccountId,
        /// Account to which to transfer (in form `name@domain_name`)
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
            let transfer_domain = iroha::data_model::isi::Transfer::domain(from, id, to);
            submit([transfer_domain], metadata.load()?, context)
                .wrap_err("Failed to transfer domain")
        }
    }

    mod metadata {
        use iroha::data_model::domain::DomainId;

        use super::*;

        /// Edit domain subcommands
        #[derive(Debug, Clone, clap::Subcommand)]
        pub enum Args {
            /// Set domain metadata
            Set(Set),
            /// Remove domain metadata
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
            #[command(flatten)]
            value: MetadataValueArg,
        }

        impl RunArgs for Set {
            fn run(self, context: &mut dyn RunContext) -> Result<()> {
                let Self {
                    id,
                    key,
                    value: MetadataValueArg { value },
                } = self;
                let set_key_value = SetKeyValue::domain(id, key, value);
                submit([set_key_value], Metadata::default(), context)
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
                submit([remove_key_value], Metadata::default(), context)
                    .wrap_err("Failed to submit Remove instruction")
            }
        }
    }
}

mod account {
    use std::fmt::Debug;

    use super::{Permission as DataModelPermission, *};

    /// subcommands for account subcommand
    #[derive(clap::Subcommand, Debug)]
    pub enum Args {
        /// Register account
        Register(Register),
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
                Args::List,
                Args::Grant,
                Args::ListPermissions,
            })
        }
    }

    /// Register account
    #[derive(clap::Args, Debug)]
    pub struct Register {
        /// Id of account in form `name@domain_name`
        #[arg(short, long)]
        pub id: AccountId,
        #[command(flatten)]
        pub metadata: MetadataArgs,
    }

    impl RunArgs for Register {
        fn run(self, context: &mut dyn RunContext) -> Result<()> {
            let Self { id, metadata } = self;
            let create_account = iroha::data_model::isi::Register::account(Account::new(id));
            submit([create_account], metadata.load()?, context)
                .wrap_err("Failed to register account")
        }
    }

    /// List accounts with this command
    #[derive(clap::Subcommand, Debug, Clone)]
    pub enum List {
        /// All accounts
        All,
        /// Filter accounts by given predicate
        Filter(filter::AccountFilter),
    }

    impl RunArgs for List {
        fn run(self, context: &mut dyn RunContext) -> Result<()> {
            let client = context.client_from_config();

            let query = client.query(FindAccounts::new());

            let query = match self {
                List::All => query,
                List::Filter(filter) => query.filter(filter.predicate),
            };

            let result = query.execute_all().wrap_err("Failed to get all accounts")?;
            context.print_data(&result)?;

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

    /// [`DataModelPermission`] wrapper implementing [`FromStr`]
    #[derive(Debug, Clone)]
    pub struct Permission(DataModelPermission);

    impl FromStr for Permission {
        type Err = Error;

        fn from_str(s: &str) -> Result<Self> {
            let content = fs::read_to_string(s)
                .wrap_err(format!("Failed to read the permission token file {}", &s))?;
            let permission: DataModelPermission = json5::from_str(&content).wrap_err(format!(
                "Failed to deserialize the permission token from file {}",
                &s
            ))?;
            Ok(Self(permission))
        }
    }

    impl RunArgs for Grant {
        fn run(self, context: &mut dyn RunContext) -> Result<()> {
            let Self {
                id,
                permission,
                metadata,
            } = self;
            let grant = iroha::data_model::isi::Grant::account_permission(permission.0, id);
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
            let client = context.client_from_config();
            let find_all_permissions = FindPermissionsByAccountId::new(self.id);
            let permissions = client
                .query(find_all_permissions)
                .execute_all()
                .wrap_err("Failed to get all account permissions")?;
            context.print_data(&permissions)?;
            Ok(())
        }
    }
}

mod asset {
    use iroha::data_model::name::Name;

    use super::*;

    /// Subcommand for dealing with asset
    #[derive(clap::Subcommand, Debug)]
    pub enum Args {
        /// Command for managing asset definitions
        #[clap(subcommand)]
        Definition(definition::Args),
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
        /// Get a value from a Store asset
        GetKeyValue(GetKeyValue),
        /// Set a key-value entry in a Store asset
        SetKeyValue(SetKeyValue),
        /// Remove a key-value entry from a Store asset
        RemoveKeyValue(RemoveKeyValue),
    }

    impl RunArgs for Args {
        fn run(self, context: &mut dyn RunContext) -> Result<()> {
            match_all!(
                (self, context),
                { Args::Definition, Args::Mint, Args::Burn, Args::Transfer, Args::Get, Args::List, Args::SetKeyValue, Args::RemoveKeyValue, Args::GetKeyValue}
            )
        }
    }

    mod definition {
        use iroha::data_model::asset::{AssetDefinition, AssetDefinitionId, AssetType};

        use super::*;

        /// Subcommand for managing asset definitions
        #[derive(clap::Subcommand, Debug)]
        pub enum Args {
            /// Command for Registering a new asset
            Register(Register),
            /// List asset definitions
            #[clap(subcommand)]
            List(List),
        }

        impl RunArgs for Args {
            fn run(self, context: &mut dyn RunContext) -> Result<()> {
                match_all!(
                    (self, context),
                    { Args::Register, Args::List }
                )
            }
        }

        /// Register subcommand of asset
        #[derive(clap::Args, Debug)]
        pub struct Register {
            /// Asset definition id for registering (in form of `asset#domain_name`)
            #[arg(long)]
            pub id: AssetDefinitionId,
            /// Mintability of asset
            #[arg(short, long)]
            pub unmintable: bool,
            /// Value type stored in asset
            #[arg(short, long)]
            pub r#type: AssetType,
            #[command(flatten)]
            pub metadata: MetadataArgs,
        }

        impl RunArgs for Register {
            fn run(self, context: &mut dyn RunContext) -> Result<()> {
                let Self {
                    id: asset_id,
                    r#type,
                    unmintable,
                    metadata,
                } = self;
                let mut asset_definition = AssetDefinition::new(asset_id, r#type);
                if unmintable {
                    asset_definition = asset_definition.mintable_once();
                }
                let create_asset_definition =
                    iroha::data_model::isi::Register::asset_definition(asset_definition);
                submit([create_asset_definition], metadata.load()?, context)
                    .wrap_err("Failed to register asset")
            }
        }

        /// List asset definitions with this command
        #[derive(clap::Subcommand, Debug, Clone)]
        pub enum List {
            /// All asset definitions
            All,
            /// Filter asset definitions by given predicate
            Filter(filter::AssetDefinitionFilter),
        }

        impl RunArgs for List {
            fn run(self, context: &mut dyn RunContext) -> Result<()> {
                let client = context.client_from_config();

                let query = client.query(FindAssetsDefinitions::new());

                let query = match self {
                    List::All => query,
                    List::Filter(filter) => query.filter(filter.predicate),
                };

                let result = query
                    .execute_all()
                    .wrap_err("Failed to get all asset definitions")?;

                context.print_data(&result)?;
                Ok(())
            }
        }
    }

    /// Command for minting asset in existing Iroha account
    #[derive(clap::Args, Debug)]
    pub struct Mint {
        /// Asset id for the asset (in form of `asset##account@domain_name`)
        #[arg(long)]
        pub id: AssetId,
        /// Quantity to mint
        #[arg(short, long)]
        pub quantity: Numeric,
        #[command(flatten)]
        pub metadata: MetadataArgs,
    }

    impl RunArgs for Mint {
        fn run(self, context: &mut dyn RunContext) -> Result<()> {
            let Self {
                id: asset_id,
                quantity,
                metadata,
            } = self;
            let mint_asset = iroha::data_model::isi::Mint::asset_numeric(quantity, asset_id);
            submit([mint_asset], metadata.load()?, context)
                .wrap_err("Failed to mint asset of type `Numeric`")
        }
    }

    /// Command for minting asset in existing Iroha account
    #[derive(clap::Args, Debug)]
    pub struct Burn {
        /// Asset id for the asset (in form of `asset##account@domain_name`)
        #[arg(long)]
        pub id: AssetId,
        /// Quantity to mint
        #[arg(short, long)]
        pub quantity: Numeric,
        #[command(flatten)]
        pub metadata: MetadataArgs,
    }

    impl RunArgs for Burn {
        fn run(self, context: &mut dyn RunContext) -> Result<()> {
            let Self {
                id: asset_id,
                quantity,
                metadata,
            } = self;
            let burn_asset = iroha::data_model::isi::Burn::asset_numeric(quantity, asset_id);
            submit([burn_asset], metadata.load()?, context)
                .wrap_err("Failed to burn asset of type `Numeric`")
        }
    }

    /// Transfer asset between accounts
    #[derive(clap::Args, Debug)]
    pub struct Transfer {
        /// Account to which to transfer (in form `name@domain_name`)
        #[arg(long)]
        pub to: AccountId,
        /// Asset id to transfer (in form like `asset##account@domain_name`)
        #[arg(long)]
        pub id: AssetId,
        /// Quantity of asset as number
        #[arg(short, long)]
        pub quantity: Numeric,
        #[command(flatten)]
        pub metadata: MetadataArgs,
    }

    impl RunArgs for Transfer {
        fn run(self, context: &mut dyn RunContext) -> Result<()> {
            let Self {
                to,
                id: asset_id,
                quantity,
                metadata,
            } = self;
            let transfer_asset =
                iroha::data_model::isi::Transfer::asset_numeric(asset_id, quantity, to);
            submit([transfer_asset], metadata.load()?, context).wrap_err("Failed to transfer asset")
        }
    }

    /// Get info of asset
    #[derive(clap::Args, Debug)]
    pub struct Get {
        /// Asset id for the asset (in form of `asset##account@domain_name`)
        #[arg(long)]
        pub id: AssetId,
    }

    impl RunArgs for Get {
        fn run(self, context: &mut dyn RunContext) -> Result<()> {
            let Self { id: asset_id } = self;
            let client = context.client_from_config();
            let asset = client
                .query(FindAssets::new())
                .filter_with(|asset| asset.id.eq(asset_id))
                .execute_single()
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
        Filter(filter::AssetFilter),
    }

    impl RunArgs for List {
        fn run(self, context: &mut dyn RunContext) -> Result<()> {
            let client = context.client_from_config();

            let query = client.query(FindAssets::new());

            let query = match self {
                List::All => query,
                List::Filter(filter) => query.filter(filter.predicate),
            };

            let result = query.execute_all().wrap_err("Failed to get all accounts")?;
            context.print_data(&result)?;

            Ok(())
        }
    }

    #[derive(clap::Args, Debug)]
    pub struct SetKeyValue {
        /// Asset id for the Store asset (in form of `asset##account@domain_name`)
        #[clap(long)]
        pub id: AssetId,
        /// The key for the store value
        #[clap(long)]
        pub key: Name,
        #[command(flatten)]
        pub value: MetadataValueArg,
    }

    impl RunArgs for SetKeyValue {
        fn run(self, context: &mut dyn RunContext) -> Result<()> {
            let Self {
                id: asset_id,
                key,
                value: MetadataValueArg { value },
            } = self;

            let set = iroha::data_model::isi::SetKeyValue::asset(asset_id, key, value);
            submit([set], Metadata::default(), context)?;
            Ok(())
        }
    }
    #[derive(clap::Args, Debug)]
    pub struct RemoveKeyValue {
        /// Asset id for the Store asset (in form of `asset##account@domain_name`)
        #[clap(long)]
        pub id: AssetId,
        /// The key for the store value
        #[clap(long)]
        pub key: Name,
    }

    impl RunArgs for RemoveKeyValue {
        fn run(self, context: &mut dyn RunContext) -> Result<()> {
            let Self { id: asset_id, key } = self;
            let remove = iroha::data_model::isi::RemoveKeyValue::asset(asset_id, key);
            submit([remove], Metadata::default(), context)?;
            Ok(())
        }
    }

    #[derive(clap::Args, Debug)]
    pub struct GetKeyValue {
        /// Asset id for the Store asset (in form of `asset##account@domain_name`)
        #[clap(long)]
        pub id: AssetId,
        /// The key for the store value
        #[clap(long)]
        pub key: Name,
    }

    impl RunArgs for GetKeyValue {
        fn run(self, context: &mut dyn RunContext) -> Result<()> {
            let Self { id: asset_id, key } = self;
            let client = context.client_from_config();
            let find_key_value = FindAssetMetadata::new(asset_id, key);
            let asset = client
                .query_single(find_key_value)
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
        Register(Box<Register>),
        /// Unregister subcommand of peer
        Unregister(Box<Unregister>),
    }

    impl RunArgs for Args {
        fn run(self, context: &mut dyn RunContext) -> Result<()> {
            match self {
                Args::Register(register) => RunArgs::run(*register, context),
                Args::Unregister(unregister) => RunArgs::run(*unregister, context),
            }
        }
    }

    /// Register subcommand of peer
    #[derive(clap::Args, Debug)]
    pub struct Register {
        /// Public key of the peer
        #[arg(short, long)]
        pub key: PublicKey,
        #[command(flatten)]
        pub metadata: MetadataArgs,
    }

    impl RunArgs for Register {
        fn run(self, context: &mut dyn RunContext) -> Result<()> {
            let Self { key, metadata } = self;
            let register_peer = iroha::data_model::isi::Register::peer(key.into());
            submit([register_peer], metadata.load()?, context).wrap_err("Failed to register peer")
        }
    }

    /// Unregister subcommand of peer
    #[derive(clap::Args, Debug)]
    pub struct Unregister {
        /// Public key of the peer
        #[arg(short, long)]
        pub key: PublicKey,
        #[command(flatten)]
        pub metadata: MetadataArgs,
    }

    impl RunArgs for Unregister {
        fn run(self, context: &mut dyn RunContext) -> Result<()> {
            let Self { key, metadata } = self;
            let unregister_peer = iroha::data_model::isi::Unregister::peer(key.into());
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
                Metadata::default(),
                context,
            )
            .wrap_err("Failed to submit a Wasm smart contract")
        }
    }
}

mod json {
    use std::io::{BufReader, Read as _};

    use clap::Subcommand;
    use iroha::data_model::query::AnyQueryBox;

    use super::*;

    /// Subcommand for submitting multi-instructions
    #[derive(Clone, Copy, Debug, clap::Args)]
    pub struct Args {
        #[clap(subcommand)]
        variant: Variant,
    }

    #[derive(Clone, Copy, Debug, Subcommand)]
    enum Variant {
        Transaction,
        Query,
    }

    impl RunArgs for Args {
        fn run(self, context: &mut dyn RunContext) -> Result<()> {
            let mut reader = BufReader::new(stdin());
            let mut raw_content = Vec::new();
            reader.read_to_end(&mut raw_content)?;

            let string_content = String::from_utf8(raw_content)?;

            match self.variant {
                Variant::Transaction => {
                    let instructions: Vec<InstructionBox> = json5::from_str(&string_content)?;
                    submit(instructions, Metadata::default(), context)
                        .wrap_err("Failed to submit parsed instructions")
                }
                Variant::Query => {
                    let client = Client::new(context.configuration());
                    let query: AnyQueryBox = json5::from_str(&string_content)?;

                    match query {
                        AnyQueryBox::Singular(query) => {
                            let result = client
                                .query_single(query)
                                .wrap_err("Failed to query response")?;

                            context.print_data(&result)?;
                        }
                        AnyQueryBox::Iterable(query) => {
                            // we can't really do type-erased iterable queries in a nice way right now...
                            use iroha::data_model::query::builder::QueryExecutor;

                            let (mut accumulated_batch, _remaining_items, mut continue_cursor) =
                                client.start_query(query)?;

                            while let Some(cursor) = continue_cursor {
                                let (next_batch, _remaining_items, next_continue_cursor) =
                                    <Client as QueryExecutor>::continue_query(cursor)?;

                                accumulated_batch.extend(next_batch);
                                continue_cursor = next_continue_cursor;
                            }

                            // for efficiency reasons iroha encodes query results in a columnar format,
                            // so we need to transpose the batch to get the format that is more natural for humans
                            let mut batches = vec![Vec::new(); accumulated_batch.len()];
                            for batch in accumulated_batch.into_iter() {
                                // downcast to json and extract the actual array
                                // dynamic typing is just easier to use here than introducing a bunch of new types only for iroha_cli
                                let batch = serde_json::to_value(batch)?;
                                let serde_json::Value::Object(batch) = batch else {
                                    panic!("Expected the batch serialization to be a JSON object");
                                };
                                let (_ty, batch) = batch
                                    .into_iter()
                                    .next()
                                    .expect("Expected the batch to have exactly one key");
                                let serde_json::Value::Array(batch_vec) = batch else {
                                    panic!("Expected the batch payload to be a JSON array");
                                };
                                for (target, value) in batches.iter_mut().zip(batch_vec) {
                                    target.push(value);
                                }
                            }

                            context.print_data(&batches)?;
                        }
                    }

                    Ok(())
                }
            }
        }
    }
}

mod multisig {
    use std::{
        collections::BTreeMap,
        io::{BufReader, Read as _},
        num::{NonZeroU16, NonZeroU64},
        time::{Duration, SystemTime},
    };

    use derive_more::{Constructor, Display};
    use iroha::executor_data_model::isi::multisig::*;
    use serde::Serialize;
    use serde_with::{serde_as, DisplayFromStr, SerializeDisplay};

    use super::*;

    /// Arguments for multisig subcommand
    #[derive(Debug, clap::Subcommand)]
    pub enum Args {
        /// Register a multisig account
        Register(Register),
        /// Propose a multisig transaction, with `Vec<InstructionBox>` stdin
        Propose(Propose),
        /// Approve a multisig transaction
        Approve(Approve),
        /// List pending multisig transactions relevant to you
        #[clap(subcommand)]
        List(List),
    }

    impl RunArgs for Args {
        fn run(self, context: &mut dyn RunContext) -> Result<()> {
            match_all!((self, context), { Args::Register, Args::Propose, Args::Approve, Args::List })
        }
    }
    /// Args to register a multisig account
    #[derive(Debug, clap::Args)]
    pub struct Register {
        /// ID of the multisig account to be registered
        #[arg(short, long)]
        pub account: AccountId,
        /// Signatories of the multisig account
        #[arg(short, long, num_args(2..))]
        pub signatories: Vec<AccountId>,
        /// Relative weights of responsibility of respective signatories
        #[arg(short, long, num_args(2..))]
        pub weights: Vec<u8>,
        /// Threshold of total weight at which the multisig is considered authenticated
        #[arg(short, long)]
        pub quorum: u16,
        /// Time-to-live of multisig transactions made by the multisig account
        #[arg(short, long, default_value_t = default_transaction_ttl())]
        pub transaction_ttl: humantime::Duration,
    }

    fn default_transaction_ttl() -> humantime::Duration {
        std::time::Duration::from_millis(DEFAULT_MULTISIG_TTL_MS).into()
    }

    impl RunArgs for Register {
        fn run(self, context: &mut dyn RunContext) -> Result<()> {
            if self.signatories.len() != self.weights.len() {
                return Err(eyre!("signatories and weights must be equal in length"));
            }
            let register_multisig_account = MultisigRegister::new(
                self.account,
                MultisigSpec::new(
                    self.signatories.into_iter().zip(self.weights).collect(),
                    NonZeroU16::new(self.quorum).expect("quorum should not be 0"),
                    self.transaction_ttl
                        .as_millis()
                        .try_into()
                        .ok()
                        .and_then(NonZeroU64::new)
                        .expect("ttl should be between 1 ms and 584942417 years"),
                ),
            );

            submit([register_multisig_account], Metadata::default(), context)
                .wrap_err("Failed to register multisig account")
        }
    }

    /// Args to propose a multisig transaction
    #[derive(Debug, clap::Args)]
    pub struct Propose {
        /// Multisig authority of the multisig transaction
        #[arg(short, long)]
        pub account: AccountId,
        /// Time-to-live of multisig transactions that overrides to shorten the account default
        #[arg(short, long)]
        pub transaction_ttl: Option<humantime::Duration>,
    }

    impl RunArgs for Propose {
        fn run(self, context: &mut dyn RunContext) -> Result<()> {
            let instructions: Vec<InstructionBox> = {
                let mut reader = BufReader::new(stdin());
                let mut raw_content = Vec::new();
                reader.read_to_end(&mut raw_content)?;
                let string_content = String::from_utf8(raw_content)?;
                json5::from_str(&string_content)?
            };
            let transaction_ttl_ms = self.transaction_ttl.map(|duration| {
                duration
                    .as_millis()
                    .try_into()
                    .ok()
                    .and_then(NonZeroU64::new)
                    .expect("ttl should be between 1 ms and 584942417 years")
            });

            let instructions_hash = HashOf::new(&instructions);
            println!("{instructions_hash}");

            let propose_multisig_transaction =
                MultisigPropose::new(self.account, instructions, transaction_ttl_ms);

            submit([propose_multisig_transaction], Metadata::default(), context)
                .wrap_err("Failed to propose transaction")
        }
    }

    /// Args to approve a multisig transaction
    #[derive(Debug, clap::Args)]
    pub struct Approve {
        /// Multisig authority of the multisig transaction
        #[arg(short, long)]
        pub account: AccountId,
        /// Instructions to approve
        #[arg(short, long)]
        pub instructions_hash: ProposalKey,
    }

    impl RunArgs for Approve {
        fn run(self, context: &mut dyn RunContext) -> Result<()> {
            let approve_multisig_transaction =
                MultisigApprove::new(self.account, self.instructions_hash);

            submit([approve_multisig_transaction], Metadata::default(), context)
                .wrap_err("Failed to approve transaction")
        }
    }

    /// List pending multisig transactions relevant to you
    #[derive(clap::Subcommand, Debug, Clone)]
    pub enum List {
        /// All pending multisig transactions relevant to you
        All,
    }

    impl RunArgs for List {
        fn run(self, context: &mut dyn RunContext) -> Result<()> {
            let client = context.client_from_config();
            let me = client.account.clone();
            let Ok(my_multisig_roles) = client
                .query(FindRolesByAccountId::new(me.clone()))
                .filter_with(|role_id| role_id.name.starts_with(MULTISIG_SIGNATORY))
                .execute_all()
            else {
                return Ok(());
            };
            let mut stack = my_multisig_roles
                .iter()
                .filter_map(multisig_account_from)
                .map(|account_id| Context::new(me.clone(), account_id, None))
                .collect();
            let mut proposals = BTreeMap::new();

            fold_proposals(&mut proposals, &mut stack, &client)?;
            context.print_data(&proposals)?;

            Ok(())
        }
    }

    const DELIMITER: char = '/';
    const MULTISIG: &str = "multisig";
    const MULTISIG_SIGNATORY: &str = "MULTISIG_SIGNATORY";

    fn spec_key() -> Name {
        format!("{MULTISIG}{DELIMITER}spec").parse().unwrap()
    }

    fn proposal_key_prefix() -> String {
        format!("{MULTISIG}{DELIMITER}proposals{DELIMITER}")
    }

    fn multisig_account_from(role: &RoleId) -> Option<AccountId> {
        role.name()
            .as_ref()
            .strip_prefix(MULTISIG_SIGNATORY)?
            .rsplit_once(DELIMITER)
            .and_then(|(init, last)| {
                format!("{last}@{}", init.trim_matches(DELIMITER))
                    .parse()
                    .ok()
            })
    }

    type PendingProposals = BTreeMap<ProposalKey, ProposalStatus>;

    type ProposalKey = HashOf<Vec<InstructionBox>>;

    #[serde_as]
    #[derive(Debug, Serialize, Constructor)]
    struct ProposalStatus {
        instructions: Vec<InstructionBox>,
        #[serde_as(as = "DisplayFromStr")]
        proposed_at: humantime::Timestamp,
        #[serde_as(as = "DisplayFromStr")]
        expires_in: humantime::Duration,
        approval_path: Vec<ApprovalEdge>,
    }

    impl Default for ProposalStatus {
        fn default() -> Self {
            Self::new(
                Vec::new(),
                SystemTime::UNIX_EPOCH.into(),
                Duration::ZERO.into(),
                Vec::new(),
            )
        }
    }

    #[derive(Debug, SerializeDisplay, Display, Constructor)]
    #[display(fmt = "{weight} {} [{got}/{quorum}] {target}", "self.relation()")]
    struct ApprovalEdge {
        weight: u8,
        has_approved: bool,
        got: u16,
        quorum: u16,
        target: AccountId,
    }

    impl ApprovalEdge {
        fn relation(&self) -> &str {
            if self.has_approved {
                "joined"
            } else {
                "->"
            }
        }
    }

    #[derive(Debug, Constructor)]
    struct Context {
        child: AccountId,
        this: AccountId,
        key_span: Option<(ProposalKey, ProposalKey)>,
    }

    fn fold_proposals(
        proposals: &mut PendingProposals,
        stack: &mut Vec<Context>,
        client: &Client,
    ) -> Result<()> {
        let Some(context) = stack.pop() else {
            return Ok(());
        };
        let account = client
            .query(FindAccounts)
            .filter_with(|account| account.id.eq(context.this.clone()))
            .execute_single()?;
        let spec: MultisigSpec = account
            .metadata()
            .get(&spec_key())
            .unwrap()
            .try_into_any()?;
        for (proposal_key, proposal_value) in account
            .metadata()
            .iter()
            .filter_map(|(k, v)| {
                k.as_ref().strip_prefix(&proposal_key_prefix()).map(|k| {
                    (
                        k.parse::<ProposalKey>().unwrap(),
                        v.try_into_any::<MultisigProposalValue>().unwrap(),
                    )
                })
            })
            .filter(|(k, _v)| context.key_span.map_or(true, |(_, top)| *k == top))
        {
            let mut is_root_proposal = true;
            for instruction in &proposal_value.instructions {
                let InstructionBox::Custom(instruction) = instruction else {
                    continue;
                };
                let Ok(MultisigInstructionBox::Approve(approve)) = instruction.payload().try_into()
                else {
                    continue;
                };
                is_root_proposal = false;
                let leaf = context.key_span.map_or(proposal_key, |(leaf, _)| leaf);
                let top = approve.instructions_hash;
                stack.push(Context::new(
                    context.this.clone(),
                    approve.account,
                    Some((leaf, top)),
                ));
            }
            let proposal_status = match context.key_span {
                None => proposals.entry(proposal_key).or_default(),
                Some((leaf, _)) => proposals.get_mut(&leaf).unwrap(),
            };
            let edge = ApprovalEdge::new(
                *spec.signatories.get(&context.child).unwrap(),
                proposal_value.approvals.contains(&context.child),
                spec.signatories
                    .iter()
                    .filter(|(id, _)| proposal_value.approvals.contains(id))
                    .map(|(_, weight)| u16::from(*weight))
                    .sum(),
                spec.quorum.into(),
                context.this.clone(),
            );
            proposal_status.approval_path.push(edge);
            if is_root_proposal {
                proposal_status.instructions = proposal_value.instructions;
                proposal_status.proposed_at = {
                    let proposed_at = Duration::from_secs(
                        Duration::from_millis(proposal_value.proposed_at_ms.into()).as_secs(),
                    );
                    SystemTime::UNIX_EPOCH
                        .checked_add(proposed_at)
                        .unwrap()
                        .into()
                };
                proposal_status.expires_in = {
                    let now = SystemTime::now()
                        .duration_since(SystemTime::UNIX_EPOCH)
                        .unwrap();
                    let expires_at = Duration::from_millis(proposal_value.expires_at_ms.into());
                    Duration::from_secs(expires_at.saturating_sub(now).as_secs()).into()
                };
            }
        }
        fold_proposals(proposals, stack, client)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_value_arg_cases() {
        macro_rules! case {
            ($input:expr, $expected:expr) => {
                let MetadataValueArg { value } =
                    $input.parse().expect("should not fail with valid input");
                assert_eq!(value, $expected);
            };
        }

        // Boolean values
        case!("true", Json::new(true));
        case!("false", Json::new(false));

        // Numeric values
        case!("\"123\"", Json::new(numeric!(123)));
        case!("\"123.0\"", Json::new(numeric!(123.0)));

        // JSON Value
        let json_str = r#"{"Vec":[{"String":"a"},{"String":"b"}]}"#;
        case!(json_str, serde_json::from_str(json_str).unwrap());
    }
}
