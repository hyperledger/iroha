//! iroha client command line
use std::{
    fs::{self, read as read_file},
    io::{stdin, stdout},
    path::PathBuf,
    str::FromStr,
};

use color_eyre::{
    eyre::{eyre, Error, WrapErr},
    Result,
};
// FIXME: sync with `kagami` (it uses `inquiry`, migrate both to something single)
use erased_serde::Serialize;
use iroha_client::{
    client::{Client, QueryResult},
    config::Config,
    data_model::{metadata::MetadataValueBox, prelude::*},
};
use iroha_primitives::addr::SocketAddr;

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

/// Re-usable clap `--value <MetadataValue>` (`-v`) argument.
/// Should be combined with `#[command(flatten)]` attr.
#[derive(clap::Args, Debug, Clone, PartialEq, Eq)]
pub struct MetadataValueArg {
    /// Wrapper around `MetadataValue` to accept possible values and fallback to json.
    ///
    /// The following types are supported:
    /// Numbers: decimal with optional point
    /// Booleans: false/true
    /// JSON: e.g. {"Vec":[{"String":"a"},{"String":"b"}]}
    #[arg(short, long)]
    value: MetadataValueBox,
}

impl FromStr for MetadataValueArg {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        s.parse::<bool>()
            .map(MetadataValueBox::Bool)
            .or_else(|_| s.parse::<Numeric>().map(MetadataValueBox::Numeric))
            .or_else(|_| serde_json::from_str::<MetadataValueBox>(s).map_err(Into::into))
            .map(|value| MetadataValueArg { value })
    }
}

/// Iroha CLI Client provides an ability to interact with Iroha Peers Web API without direct network usage.
#[derive(clap::Parser, Debug)]
#[command(name = "iroha_client_cli", version = concat!("version=", env!("CARGO_PKG_VERSION"), " git_commit_sha=", env!("VERGEN_GIT_SHA")), author)]
struct Args {
    /// Path to the configuration file
    #[arg(short, long, value_name("PATH"), value_hint(clap::ValueHint::FilePath))]
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

fn main() -> Result<()> {
    color_eyre::install()?;

    let Args {
        config: config_path,
        subcommand,
        verbose,
    } = clap::Parser::parse();

    let config = Config::load(config_path)?;

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
    let iroha_client = context.client_from_config();
    let instructions = instructions.into();
    let tx = iroha_client.build_transaction(instructions, metadata);

    #[cfg(not(debug_assertions))]
    let err_msg = "Failed to submit transaction.";
    #[cfg(debug_assertions)]
    let err_msg = format!("Failed to submit transaction {tx:?}");
    let hash = iroha_client
        .submit_transaction_blocking(&tx)
        .wrap_err(err_msg)?;
    context.print_data(&hash)?;

    Ok(())
}

mod filter {
    use iroha_client::data_model::query::predicate::PredicateBox;

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

    use iroha_client::data_model::events::pipeline::{BlockEventFilter, TransactionEventFilter};

    use super::*;

    /// Get event stream from iroha peer
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
        let iroha_client = context.client_from_config();
        eprintln!("Listening to events with filter: {filter:?}");
        iroha_client
            .listen_for_events([filter])
            .wrap_err("Failed to listen for events.")?
            .try_for_each(|event| context.print_data(&event?))?;
        Ok(())
    }
}

mod blocks {
    use std::num::NonZeroU64;

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
        let iroha_client = context.client_from_config();
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
            let client = context.client_from_config();

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
            let transfer_domain = iroha_client::data_model::isi::Transfer::domain(from, id, to);
            submit([transfer_domain], metadata.load()?, context)
                .wrap_err("Failed to transfer domain")
        }
    }

    mod metadata {
        use iroha_client::data_model::domain::DomainId;

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
            let create_account = iroha_client::data_model::isi::Register::account(Account::new(id));
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
        Filter(filter::Filter),
    }

    impl RunArgs for List {
        fn run(self, context: &mut dyn RunContext) -> Result<()> {
            let client = context.client_from_config();

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
            let grant = iroha_client::data_model::isi::Grant::permission(permission.0, id);
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
        client::{self, asset},
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
        /// Asset definition id for registering (in form of `asset#domain_name`)
        #[arg(long)]
        pub definition_id: AssetDefinitionId,
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
                definition_id,
                value_type,
                unmintable,
                metadata,
            } = self;
            let mut asset_definition = AssetDefinition::new(definition_id, value_type);
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
        /// Asset id for the asset (in form of `asset##account@domain_name`)
        #[arg(long)]
        pub asset_id: AssetId,
        /// Quantity to mint
        #[arg(short, long)]
        pub quantity: Numeric,
        #[command(flatten)]
        pub metadata: MetadataArgs,
    }

    impl RunArgs for Mint {
        fn run(self, context: &mut dyn RunContext) -> Result<()> {
            let Self {
                asset_id,
                quantity,
                metadata,
            } = self;
            let mint_asset = iroha_client::data_model::isi::Mint::asset_numeric(quantity, asset_id);
            submit([mint_asset], metadata.load()?, context)
                .wrap_err("Failed to mint asset of type `Numeric`")
        }
    }

    /// Command for minting asset in existing Iroha account
    #[derive(clap::Args, Debug)]
    pub struct Burn {
        /// Asset id for the asset (in form of `asset##account@domain_name`)
        #[arg(long)]
        pub asset_id: AssetId,
        /// Quantity to mint
        #[arg(short, long)]
        pub quantity: Numeric,
        #[command(flatten)]
        pub metadata: MetadataArgs,
    }

    impl RunArgs for Burn {
        fn run(self, context: &mut dyn RunContext) -> Result<()> {
            let Self {
                asset_id,
                quantity,
                metadata,
            } = self;
            let burn_asset = iroha_client::data_model::isi::Burn::asset_numeric(quantity, asset_id);
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
        pub asset_id: AssetId,
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
                asset_id,
                quantity,
                metadata,
            } = self;
            let transfer_asset =
                iroha_client::data_model::isi::Transfer::asset_numeric(asset_id, quantity, to);
            submit([transfer_asset], metadata.load()?, context).wrap_err("Failed to transfer asset")
        }
    }

    /// Get info of asset
    #[derive(clap::Args, Debug)]
    pub struct Get {
        /// Asset id for the asset (in form of `asset##account@domain_name`)
        #[arg(long)]
        pub asset_id: AssetId,
    }

    impl RunArgs for Get {
        fn run(self, context: &mut dyn RunContext) -> Result<()> {
            let Self { asset_id } = self;
            let iroha_client = context.client_from_config();
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
            let client = context.client_from_config();

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
        /// Asset id for the Store asset (in form of `asset##account@domain_name`)
        #[clap(long)]
        pub asset_id: AssetId,
        /// The key for the store value
        #[clap(long)]
        pub key: Name,
        #[command(flatten)]
        pub value: MetadataValueArg,
    }

    impl RunArgs for SetKeyValue {
        fn run(self, context: &mut dyn RunContext) -> Result<()> {
            let Self {
                asset_id,
                key,
                value: MetadataValueArg { value },
            } = self;

            let set = iroha_client::data_model::isi::SetKeyValue::asset(asset_id, key, value);
            submit([set], UnlimitedMetadata::default(), context)?;
            Ok(())
        }
    }
    #[derive(clap::Args, Debug)]
    pub struct RemoveKeyValue {
        /// Asset id for the Store asset (in form of `asset##account@domain_name`)
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
        /// Asset id for the Store asset (in form of `asset##account@domain_name`)
        #[clap(long)]
        pub asset_id: AssetId,
        /// The key for the store value
        #[clap(long)]
        pub key: Name,
    }

    impl RunArgs for GetKeyValue {
        fn run(self, context: &mut dyn RunContext) -> Result<()> {
            let Self { asset_id, key } = self;
            let client = context.client_from_config();
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
                iroha_client::data_model::isi::Register::peer(Peer::new(PeerId::new(address, key)));
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
                iroha_client::data_model::isi::Unregister::peer(PeerId::new(address, key));
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
        case!("true", true.into());
        case!("false", false.into());

        // Numeric values
        case!("123", numeric!(123).into());
        case!("123.0", numeric!(123.0).into());

        // JSON Value
        let json_str = r#"{"Vec":[{"String":"a"},{"String":"b"}]}"#;
        case!(json_str, serde_json::from_str(json_str).unwrap());
    }

    #[test]
    fn error_parse_invalid_value() {
        let invalid_str = "not_a_valid_value";
        let _invalid_value = MetadataValueArg::from_str(invalid_str)
            .expect_err("Should fail invalid type from string but passed");
    }
}
