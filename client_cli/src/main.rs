//! Iroha client CLI

use std::{
    fs::{self, read as read_file},
    io::{stdin, stdout},
    path::PathBuf,
    str::FromStr,
};

use erased_serde::Serialize;
use error_stack::{fmt::ColorMode, IntoReportCompat, ResultExt};
use eyre::{eyre, Error, Result, WrapErr};
use iroha::{client::Client, config::Config, data_model::prelude::*};
use iroha_primitives::{addr::SocketAddr, json::JsonString};
use thiserror::Error;

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
    value: JsonString,
}

impl FromStr for MetadataValueArg {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(MetadataValueArg {
            value: JsonString::from_str(s)?,
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
    fn configuration(&self) -> &Config;

    fn client_from_config(&self) -> Client {
        Client::new(self.configuration().clone())
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
        match_all!((self, context), { Domain, Account, Asset, Peer, Events, Wasm, Blocks, Json })
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
    let iroha = context.client_from_config();
    let instructions = instructions.into();
    let tx = iroha.build_transaction(instructions, metadata);

    #[cfg(not(debug_assertions))]
    let err_msg = "Failed to submit transaction.";
    #[cfg(debug_assertions)]
    let err_msg = format!("Failed to submit transaction {tx:?}");
    let hash = iroha.submit_transaction_blocking(&tx).wrap_err(err_msg)?;
    context.print_data(&hash)?;

    Ok(())
}

mod filter {
    use iroha::data_model::query::predicate::{
        predicate_atoms::{
            account::AccountPredicateBox, asset::AssetPredicateBox, domain::DomainPredicateBox,
        },
        CompoundPredicate,
    };
    use serde::Deserialize;

    use super::*;

    /// Filter for domain queries
    #[derive(Clone, Debug, clap::Parser)]
    pub struct DomainFilter {
        /// Predicate for filtering given as JSON5 string
        #[clap(value_parser = parse_json5::<CompoundPredicate<DomainPredicateBox>>)]
        pub predicate: CompoundPredicate<DomainPredicateBox>,
    }

    /// Filter for account queries
    #[derive(Clone, Debug, clap::Parser)]
    pub struct AccountFilter {
        /// Predicate for filtering given as JSON5 string
        #[clap(value_parser = parse_json5::<CompoundPredicate<AccountPredicateBox>>)]
        pub predicate: CompoundPredicate<AccountPredicateBox>,
    }

    /// Filter for asset queries
    #[derive(Clone, Debug, clap::Parser)]
    pub struct AssetFilter {
        /// Predicate for filtering given as JSON5 string
        #[clap(value_parser = parse_json5::<CompoundPredicate<AssetPredicateBox>>)]
        pub predicate: CompoundPredicate<AssetPredicateBox>,
    }

    /// Filter for asset definition queries
    #[derive(Clone, Debug, clap::Parser)]
    pub struct AssetDefinitionFilter {
        /// Predicate for filtering given as JSON5 string
        #[clap(value_parser = parse_json5::<CompoundPredicate<AssetDefinitionPredicateBox>>)]
        pub predicate: CompoundPredicate<AssetDefinitionPredicateBox>,
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

    /// Get event stream from Iroha peer
    #[derive(clap::Subcommand, Debug, Clone, Copy)]
    pub enum Args {
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
            match self {
                Args::TransactionPipeline => listen(TransactionEventFilter::default(), context),
                Args::BlockPipeline => listen(BlockEventFilter::default(), context),
                Args::Data => listen(DataEventFilter::Any, context),
                Args::ExecuteTrigger => listen(ExecuteTriggerEventFilter::new(), context),
                Args::TriggerCompleted => listen(TriggerCompletedEventFilter::new(), context),
            }
        }
    }

    fn listen(filter: impl Into<EventFilterBox>, context: &mut dyn RunContext) -> Result<()> {
        let filter = filter.into();
        let iroha = context.client_from_config();
        eprintln!("Listening to events with filter: {filter:?}");
        iroha
            .listen_for_events([filter])
            .wrap_err("Failed to listen for events.")?
            .try_for_each(|event| context.print_data(&event?))?;
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
    }

    impl RunArgs for Args {
        fn run(self, context: &mut dyn RunContext) -> Result<()> {
            let Args { height } = self;
            listen(height, context)
        }
    }

    fn listen(height: NonZeroU64, context: &mut dyn RunContext) -> Result<()> {
        let iroha = context.client_from_config();
        eprintln!("Listening to blocks from height: {height}");
        iroha
            .listen_for_blocks(height)
            .wrap_err("Failed to listen for blocks.")?
            .try_for_each(|event| context.print_data(&event?))?;
        Ok(())
    }
}

mod domain {
    use iroha::client;

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

            let query = client.query(client::domain::all());

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

    use iroha::client::{self};

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

            let query = client.query(client::account::all());

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
    use iroha::{
        client::{self, asset},
        data_model::name::Name,
    };

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

                let query = client.query(client::asset::all_definitions());

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
            let iroha = context.client_from_config();
            let asset = iroha
                .query(asset::all())
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

            let query = client.query(client::asset::all());

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
            let register_peer =
                iroha::data_model::isi::Register::peer(Peer::new(PeerId::new(address, key)));
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
                iroha::data_model::isi::Unregister::peer(PeerId::new(address, key));
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
                    let client = Client::new(context.configuration().clone());
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

                            let (mut first_batch, mut continue_cursor) =
                                client.start_query(query)?;

                            while let Some(cursor) = continue_cursor {
                                let (next_batch, next_continue_cursor) =
                                    <Client as QueryExecutor>::continue_query(cursor)?;

                                first_batch.extend(next_batch);
                                continue_cursor = next_continue_cursor;
                            }

                            context.print_data(&first_batch)?;
                        }
                    }

                    Ok(())
                }
            }
        }
    }
}
#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use super::*;

    #[test]
    fn parse_value_arg_cases() {
        macro_rules! case {
            ($input:expr, $expected:expr) => {
                let MetadataValueArg { value } =
                    MetadataValueArg::from_str($input).expect("should not fail with valid input");
                assert_eq!(value, $expected);
            };
        }

        // Boolean values
        case!("true", JsonString::new(true));
        case!("false", JsonString::new(false));

        // Numeric values
        case!("\"123\"", JsonString::new(numeric!(123)));
        case!("\"123.0\"", JsonString::new(numeric!(123.0)));

        // JSON Value
        let json_str = r#"{"Vec":[{"String":"a"},{"String":"b"}]}"#;
        case!(json_str, serde_json::from_str(json_str).unwrap());
    }
}
