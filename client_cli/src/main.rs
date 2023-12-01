//! iroha client command line
use std::{
    fmt,
    fs::{self, read as read_file},
    io::{stdin, stdout},
    str::FromStr,
    time::Duration,
};

use clap::StructOpt;
use color_eyre::{
    eyre::{ContextCompat as _, Error, WrapErr},
    Result,
};
use dialoguer::Confirm;
use erased_serde::Serialize;
use iroha_client::{
    client::{Client, QueryResult},
    config::{path::Path as ConfigPath, Configuration as ClientConfiguration},
    data_model::prelude::*,
};
use iroha_primitives::addr::SocketAddr;

/// Metadata wrapper, which can be captured from cli arguments (from user supplied file).
#[derive(Debug, Clone)]
pub struct Metadata(pub UnlimitedMetadata);

impl fmt::Display for Metadata {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

impl FromStr for Metadata {
    type Err = Error;
    fn from_str(file: &str) -> Result<Self> {
        if file.is_empty() {
            return Ok(Self(UnlimitedMetadata::default()));
        }
        let err_msg = format!("Failed to open the metadata file {}.", &file);
        let deser_err_msg = format!("Failed to deserialize metadata from file: {}", &file);
        let content = fs::read_to_string(file).wrap_err(err_msg)?;
        let metadata: UnlimitedMetadata = json5::from_str(&content).wrap_err(deser_err_msg)?;
        Ok(Self(metadata))
    }
}

/// Client configuration wrapper. Allows getting itself from arguments from cli (from user supplied file).
#[derive(Debug, Clone)]
struct Configuration(pub ClientConfiguration);

impl FromStr for Configuration {
    type Err = Error;
    fn from_str(file: &str) -> Result<Self> {
        let deser_err_msg = format!("Failed to decode config file {} ", &file);
        let err_msg = format!("Failed to open config file {}", &file);
        let content = fs::read_to_string(file).wrap_err(err_msg)?;
        let cfg = json5::from_str(&content).wrap_err(deser_err_msg)?;
        Ok(Self(cfg))
    }
}

/// Iroha CLI Client provides an ability to interact with Iroha Peers Web API without direct network usage.
#[derive(StructOpt, Debug)]
#[structopt(name = "iroha_client_cli", version = concat!("version=", env!("CARGO_PKG_VERSION"), " git_commit_sha=", env!("VERGEN_GIT_SHA")), author)]
struct Args {
    /// Sets a config file path
    #[structopt(short, long)]
    config: Option<Configuration>,
    /// More verbose output
    #[structopt(short, long)]
    verbose: bool,
    /// Skip MST check. By setting this flag searching similar transactions on the server can be omitted.
    /// Thus if you don't use multisignature transactions you should use this flag as it will increase speed of submitting transactions.
    /// Also setting this flag could be useful when `iroha_client_cli` is used to submit the same transaction multiple times (like mint for example) in short period of time.
    #[structopt(long)]
    skip_mst_check: bool,
    /// Subcommands of client cli
    #[structopt(subcommand)]
    subcommand: Subcommand,
}

#[derive(StructOpt, Debug)]
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

static DEFAULT_CONFIG_PATH: once_cell::sync::Lazy<&'static std::path::Path> =
    once_cell::sync::Lazy::new(|| std::path::Path::new("config"));

fn main() -> Result<()> {
    color_eyre::install()?;
    let Args {
        config: config_opt,
        subcommand,
        verbose,
        skip_mst_check,
    } = clap::Parser::parse();
    let config = if let Some(config) = config_opt {
        config
    } else {
        let config_path = ConfigPath::default(&DEFAULT_CONFIG_PATH);
        Configuration::from_str(
            config_path
                .first_existing_path()
                .wrap_err("Configuration file does not exist")?
                .as_ref()
                .to_string_lossy()
                .as_ref(),
        )?
    };

    let Configuration(config) = config;

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
    #[derive(StructOpt, Debug, Clone, Copy)]
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
    #[derive(StructOpt, Debug, Clone, Copy)]
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
    }

    impl RunArgs for Args {
        fn run(self, context: &mut dyn RunContext) -> Result<()> {
            match_all!((self, context), { Args::Register, Args::List })
        }
    }

    /// Add subcommand for domain
    #[derive(Debug, StructOpt)]
    pub struct Register {
        /// Domain name as double-quoted string
        #[structopt(short, long)]
        pub id: DomainId,
        /// The JSON/JSON5 file with key-value metadata pairs
        #[structopt(short, long, default_value = "")]
        pub metadata: super::Metadata,
    }

    impl RunArgs for Register {
        fn run(self, context: &mut dyn RunContext) -> Result<()> {
            let Self {
                id,
                metadata: Metadata(metadata),
            } = self;
            let create_domain = RegisterExpr::new(Domain::new(id));
            submit([create_domain], metadata, context).wrap_err("Failed to create domain")
        }
    }

    /// List domains with this command
    #[derive(StructOpt, Debug, Clone)]
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
                    .request_with_filter(client::domain::all(), filter.predicate)
                    .wrap_err("Failed to get filtered domains"),
            }?;
            context.print_data(&vec.collect::<QueryResult<Vec<_>>>()?)?;
            Ok(())
        }
    }
}

mod account {
    use std::fmt::Debug;

    use iroha_client::client::{self};

    use super::*;

    /// subcommands for account subcommand
    #[derive(StructOpt, Debug)]
    pub enum Args {
        /// Register account
        Register(Register),
        /// Set something in account
        #[clap(subcommand)]
        Set(Set),
        /// List accounts
        #[clap(subcommand)]
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
    #[derive(StructOpt, Debug)]
    pub struct Register {
        /// Id of account in form `name@domain_name'
        #[structopt(short, long)]
        pub id: AccountId,
        /// Its public key
        #[structopt(short, long)]
        pub key: PublicKey,
        /// /// The JSON file with key-value metadata pairs
        #[structopt(short, long, default_value = "")]
        pub metadata: super::Metadata,
    }

    impl RunArgs for Register {
        fn run(self, context: &mut dyn RunContext) -> Result<()> {
            let Self {
                id,
                key,
                metadata: Metadata(metadata),
            } = self;
            let create_account = RegisterExpr::new(Account::new(id, [key]));
            submit([create_account], metadata, context).wrap_err("Failed to register account")
        }
    }

    /// Set subcommand of account
    #[derive(StructOpt, Debug)]
    pub enum Set {
        /// Signature condition
        SignatureCondition(SignatureCondition),
    }

    impl RunArgs for Set {
        fn run(self, context: &mut dyn RunContext) -> Result<()> {
            match_all!((self, context), { Set::SignatureCondition })
        }
    }

    #[derive(Debug)]
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
    #[derive(StructOpt, Debug)]
    pub struct SignatureCondition {
        /// Signature condition file
        pub condition: Signature,
        /// The JSON/JSON5 file with key-value metadata pairs
        #[structopt(short, long, default_value = "")]
        pub metadata: super::Metadata,
    }

    impl RunArgs for SignatureCondition {
        fn run(self, context: &mut dyn RunContext) -> Result<()> {
            let account = Account::new(context.configuration().account_id.clone(), []);
            let Self {
                condition: Signature(condition),
                metadata: Metadata(metadata),
            } = self;
            let mint_box = MintExpr::new(account, EvaluatesTo::new_unchecked(condition));
            submit([mint_box], metadata, context).wrap_err("Failed to set signature condition")
        }
    }

    /// List accounts with this command
    #[derive(StructOpt, Debug, Clone)]
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
                    .request_with_filter(client::account::all(), filter.predicate)
                    .wrap_err("Failed to get filtered accounts"),
            }?;
            context.print_data(&vec.collect::<QueryResult<Vec<_>>>()?)?;
            Ok(())
        }
    }

    #[derive(StructOpt, Debug)]
    pub struct Grant {
        /// Account id
        #[structopt(short, long)]
        pub id: AccountId,
        /// The JSON/JSON5 file with a permission token
        #[structopt(short, long)]
        pub permission: Permission,
        /// The JSON/JSON5 file with key-value metadata pairs
        #[structopt(short, long, default_value = "")]
        pub metadata: super::Metadata,
    }

    /// [`PermissionToken`] wrapper implementing [`FromStr`]
    #[derive(Debug)]
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
                metadata: Metadata(metadata),
            } = self;
            let grant = GrantExpr::new(permission.0, id);
            submit([grant], metadata, context)
                .wrap_err("Failed to grant the permission to the account")
        }
    }

    /// List all account permissions
    #[derive(StructOpt, Debug)]
    pub struct ListPermissions {
        /// Account id
        #[structopt(short, long)]
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
    use iroha_client::client::{self, asset, Client};

    use super::*;

    /// Subcommand for dealing with asset
    #[derive(StructOpt, Debug)]
    pub enum Args {
        /// Register subcommand of asset
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
    }

    impl RunArgs for Args {
        fn run(self, context: &mut dyn RunContext) -> Result<()> {
            match_all!(
                (self, context),
                { Args::Register, Args::Mint, Args::Burn, Args::Transfer, Args::Get, Args::List }
            )
        }
    }

    /// Register subcommand of asset
    #[derive(StructOpt, Debug)]
    pub struct Register {
        /// Asset id for registering (in form of `name#domain_name')
        #[structopt(short, long)]
        pub id: AssetDefinitionId,
        /// Mintability of asset
        #[structopt(short, long)]
        pub unmintable: bool,
        /// Value type stored in asset
        #[structopt(short, long)]
        pub value_type: AssetValueType,
        /// The JSON/JSON5 file with key-value metadata pairs
        #[structopt(short, long, default_value = "")]
        pub metadata: super::Metadata,
    }

    impl RunArgs for Register {
        fn run(self, context: &mut dyn RunContext) -> Result<()> {
            let Self {
                id,
                value_type,
                unmintable,
                metadata: Metadata(metadata),
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
            let create_asset_definition = RegisterExpr::new(asset_definition);
            submit([create_asset_definition], metadata, context)
                .wrap_err("Failed to register asset")
        }
    }

    /// Command for minting asset in existing Iroha account
    #[derive(StructOpt, Debug)]
    pub struct Mint {
        /// Account id where asset is stored (in form of `name@domain_name')
        #[structopt(long)]
        pub account: AccountId,
        /// Asset id from which to mint (in form of `name#domain_name')
        #[structopt(long)]
        pub asset: AssetDefinitionId,
        /// Quantity to mint
        #[structopt(short, long)]
        pub quantity: u32,
        /// The JSON/JSON5 file with key-value metadata pairs
        #[structopt(short, long, default_value = "")]
        pub metadata: super::Metadata,
    }

    impl RunArgs for Mint {
        fn run(self, context: &mut dyn RunContext) -> Result<()> {
            let Self {
                account,
                asset,
                quantity,
                metadata: Metadata(metadata),
            } = self;
            let mint_asset = MintExpr::new(
                quantity.to_value(),
                IdBox::AssetId(AssetId::new(asset, account)),
            );
            submit([mint_asset], metadata, context)
                .wrap_err("Failed to mint asset of type `NumericValue::U32`")
        }
    }

    /// Command for minting asset in existing Iroha account
    #[derive(StructOpt, Debug)]
    pub struct Burn {
        /// Account id where asset is stored (in form of `name@domain_name')
        #[structopt(long)]
        pub account: AccountId,
        /// Asset id from which to mint (in form of `name#domain_name')
        #[structopt(long)]
        pub asset: AssetDefinitionId,
        /// Quantity to mint
        #[structopt(short, long)]
        pub quantity: u32,
        /// The JSON/JSON5 file with key-value metadata pairs
        #[structopt(short, long, default_value = "")]
        pub metadata: super::Metadata,
    }

    impl RunArgs for Burn {
        fn run(self, context: &mut dyn RunContext) -> Result<()> {
            let Self {
                account,
                asset,
                quantity,
                metadata: Metadata(metadata),
            } = self;
            let burn_asset = BurnExpr::new(
                quantity.to_value(),
                IdBox::AssetId(AssetId::new(asset, account)),
            );
            submit([burn_asset], metadata, context)
                .wrap_err("Failed to burn asset of type `NumericValue::U32`")
        }
    }

    /// Transfer asset between accounts
    #[derive(StructOpt, Debug)]
    pub struct Transfer {
        /// Account from which to transfer (in form `name@domain_name')
        #[structopt(short, long)]
        pub from: AccountId,
        /// Account from which to transfer (in form `name@domain_name')
        #[structopt(short, long)]
        pub to: AccountId,
        /// Asset id to transfer (in form like `name#domain_name')
        #[structopt(short, long)]
        pub asset_id: AssetDefinitionId,
        /// Quantity of asset as number
        #[structopt(short, long)]
        pub quantity: u32,
        /// The JSON/JSON5 file with key-value metadata pairs
        #[structopt(short, long, default_value = "")]
        pub metadata: super::Metadata,
    }

    impl RunArgs for Transfer {
        fn run(self, context: &mut dyn RunContext) -> Result<()> {
            let Self {
                from,
                to,
                asset_id,
                quantity,
                metadata: Metadata(metadata),
            } = self;
            let transfer_asset = TransferExpr::new(
                IdBox::AssetId(AssetId::new(asset_id, from)),
                quantity.to_value(),
                IdBox::AccountId(to),
            );
            submit([transfer_asset], metadata, context).wrap_err("Failed to transfer asset")
        }
    }

    /// Get info of asset
    #[derive(StructOpt, Debug)]
    pub struct Get {
        /// Account where asset is stored (in form of `name@domain_name')
        #[structopt(long)]
        pub account: AccountId,
        /// Asset name to lookup (in form of `name#domain_name')
        #[structopt(long)]
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
    #[derive(StructOpt, Debug, Clone)]
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
                    .request_with_filter(client::asset::all(), filter.predicate)
                    .wrap_err("Failed to get filtered assets"),
            }?;
            context.print_data(&vec.collect::<QueryResult<Vec<_>>>()?)?;
            Ok(())
        }
    }
}

mod peer {
    use super::*;

    /// Subcommand for dealing with peer
    #[derive(StructOpt, Debug)]
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
    #[derive(StructOpt, Debug)]
    pub struct Register {
        /// P2P address of the peer e.g. `127.0.0.1:1337`
        #[structopt(short, long)]
        pub address: SocketAddr,
        /// Public key of the peer
        #[structopt(short, long)]
        pub key: PublicKey,
        /// The JSON/JSON5 file with key-value metadata pairs
        #[structopt(short, long, default_value = "")]
        pub metadata: super::Metadata,
    }

    impl RunArgs for Register {
        fn run(self, context: &mut dyn RunContext) -> Result<()> {
            let Self {
                address,
                key,
                metadata: Metadata(metadata),
            } = self;
            let register_peer = RegisterExpr::new(Peer::new(PeerId::new(&address, &key)));
            submit([register_peer], metadata, context).wrap_err("Failed to register peer")
        }
    }

    /// Unregister subcommand of peer
    #[derive(StructOpt, Debug)]
    pub struct Unregister {
        /// P2P address of the peer e.g. `127.0.0.1:1337`
        #[structopt(short, long)]
        pub address: SocketAddr,
        /// Public key of the peer
        #[structopt(short, long)]
        pub key: PublicKey,
        /// The JSON/JSON5 file with key-value metadata pairs
        #[structopt(short, long, default_value = "")]
        pub metadata: super::Metadata,
    }

    impl RunArgs for Unregister {
        fn run(self, context: &mut dyn RunContext) -> Result<()> {
            let Self {
                address,
                key,
                metadata: Metadata(metadata),
            } = self;
            let unregister_peer = UnregisterExpr::new(IdBox::PeerId(PeerId::new(&address, &key)));
            submit([unregister_peer], metadata, context).wrap_err("Failed to unregister peer")
        }
    }
}

mod wasm {
    use std::{io::Read, path::PathBuf};

    use super::*;

    /// Subcommand for dealing with Wasm
    #[derive(Debug, StructOpt)]
    pub struct Args {
        /// Specify a path to the Wasm file or skip this flag to read from stdin
        #[structopt(short, long)]
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
    #[derive(Clone, Copy, Debug, StructOpt)]
    pub struct Args;

    impl RunArgs for Args {
        fn run(self, context: &mut dyn RunContext) -> Result<()> {
            let mut reader = BufReader::new(stdin());
            let mut raw_content = Vec::new();
            reader.read_to_end(&mut raw_content)?;

            let string_content = String::from_utf8(raw_content)?;
            let instructions: Vec<InstructionExpr> = json5::from_str(&string_content)?;
            submit(instructions, UnlimitedMetadata::new(), context)
                .wrap_err("Failed to submit parsed instructions")
        }
    }
}
