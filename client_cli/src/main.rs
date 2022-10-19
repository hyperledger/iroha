//! iroha client command line
#![allow(
    clippy::arithmetic,
    clippy::std_instead_of_core,
    clippy::std_instead_of_alloc
)]
#![allow(
    missing_docs,
    clippy::print_stdout,
    clippy::use_debug,
    clippy::print_stderr
)]

use std::{
    fmt,
    fs::{read as read_file, File},
    io::stdin,
    str::FromStr,
    time::Duration,
};

use clap::StructOpt;
use color_eyre::{
    eyre::{Error, WrapErr},
    Result,
};
use dialoguer::Confirm;
use iroha_client::client::Client;
use iroha_config::client::Configuration as ClientConfiguration;
use iroha_crypto::prelude::*;
use iroha_data_model::prelude::*;

/// Metadata wrapper, which can be captured from cli arguments (from user supplied file).
#[derive(Debug, Clone)]
pub struct Metadata(pub UnlimitedMetadata);

impl fmt::Display for Metadata {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:?}", self)
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
        let file = File::open(file).wrap_err(err_msg)?;
        let metadata: UnlimitedMetadata = serde_json::from_reader(file).wrap_err(deser_err_msg)?;
        Ok(Self(metadata))
    }
}

/// Client configuration wrapper. Allows getting itself from arguments from cli (from user supplied file).
#[derive(Debug, Clone)]
pub struct Configuration(pub ClientConfiguration);

impl FromStr for Configuration {
    type Err = Error;
    fn from_str(file: &str) -> Result<Self> {
        let deser_err_msg = format!("Failed to decode config file {} ", &file);
        let err_msg = format!("Failed to open config file {}", &file);
        let file = File::open(file).wrap_err(err_msg)?;
        let cfg = serde_json::from_reader(file).wrap_err(deser_err_msg)?;
        Ok(Self(cfg))
    }
}

/// Iroha CLI Client provides an ability to interact with Iroha Peers Web API without direct network usage.
#[derive(StructOpt, Debug)]
#[structopt(
    name = "iroha_client_cli",
    version = concat!(env!("CARGO_PKG_VERSION"), " (", env!("VERGEN_GIT_SHA"), ")"),
    author
)]
pub struct Args {
    /// Sets a config file path
    #[structopt(short, long)]
    config: Option<Configuration>,
    /// Subcommands of client cli
    #[structopt(subcommand)]
    subcommand: Subcommand,
}

#[derive(StructOpt, Debug)]
pub enum Subcommand {
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
}

/// Runs subcommand
pub trait RunArgs {
    /// Runs command
    ///
    /// # Errors
    /// if inner command errors
    fn run(self, cfg: &ClientConfiguration) -> Result<()>;
}

macro_rules! match_run_all {
    (($self:ident, $cfg:ident), { $($variants:path),* $(,)?}) => {
        match $self {
            $($variants(variant) => RunArgs::run(variant, $cfg),)*
        }
    };
}

impl RunArgs for Subcommand {
    fn run(self, cfg: &ClientConfiguration) -> Result<()> {
        use Subcommand::*;
        match_run_all!((self, cfg), { Domain, Account, Asset, Peer, Events, Wasm, Blocks })
    }
}

// TODO: move into config.
const RETRY_COUNT_MST: u32 = 1;
const RETRY_IN_MST: Duration = Duration::from_millis(100);

fn main() -> Result<()> {
    color_eyre::install()?;
    let Args {
        config: config_opt,
        subcommand,
    } = clap::Parser::parse();
    let config = if let Some(config) = config_opt {
        config
    } else {
        Configuration::from_str("config.json")?
    };
    let Configuration(config) = config;
    println!(
        "User: {}@{}",
        config.account_id.name, config.account_id.domain_id
    );
    #[cfg(debug_assertions)]
    eprintln!(
        "{}",
        &serde_json::to_string(&config).wrap_err("Failed to serialize configuration.")?
    );
    #[cfg(not(debug_assertions))]
    eprintln!("This is a release build, debug information omitted from messages");
    subcommand.run(&config)?;
    Ok(())
}

/// Submit instruction with metadata to network.
///
/// # Errors
/// Fails if submitting over network fails
#[allow(clippy::shadow_unrelated)]
pub fn submit(
    instructions: impl Into<Executable>,
    cfg: &ClientConfiguration,
    metadata: UnlimitedMetadata,
) -> Result<()> {
    let iroha_client = Client::new(cfg)?;
    let instructions = instructions.into();
    #[cfg(debug_assertions)]
    let err_msg = format!(
        "Failed to build transaction from instruction {:?}",
        instructions
    );
    #[cfg(not(debug_assertions))]
    let err_msg = "Failed to build transaction.";
    let tx = iroha_client
        .build_transaction(instructions, metadata)
        .wrap_err(err_msg)?;
    let tx = match iroha_client.get_original_transaction(
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
    };
    #[cfg(debug_assertions)]
    let err_msg = format!("Failed to submit transaction {:?}", tx);
    #[cfg(not(debug_assertions))]
    let err_msg = "Failed to submit transaction.";
    iroha_client
        .submit_transaction_blocking(tx)
        .wrap_err(err_msg)?;
    Ok(())
}

mod events {
    use iroha_client::client::Client;
    use iroha_config::client::Configuration;

    use super::*;

    /// Get event stream from iroha peer
    #[derive(StructOpt, Debug, Clone, Copy)]
    pub enum Args {
        /// Gets pipeline events
        Pipeline,
        /// Gets data events
        Data,
    }

    impl RunArgs for Args {
        fn run(self, cfg: &ClientConfiguration) -> Result<()> {
            let filter = match self {
                Args::Pipeline => FilterBox::Pipeline(PipelineEventFilter::new()),
                Args::Data => FilterBox::Data(DataEventFilter::AcceptAll),
            };
            listen(filter, cfg)
        }
    }

    pub fn listen(filter: FilterBox, cfg: &Configuration) -> Result<()> {
        let iroha_client = Client::new(cfg)?;
        println!("Listening to events with filter: {:?}", filter);
        for event in iroha_client
            .listen_for_events(filter)
            .wrap_err("Failed to listen for events.")?
        {
            match event {
                Ok(event) => println!("{:#?}", event),
                Err(err) => println!("{:#?}", err),
            };
        }
        Ok(())
    }
}

mod blocks {
    use iroha_client::client::Client;
    use iroha_config::client::Configuration;

    use super::*;

    /// Get event stream from iroha peer
    #[derive(StructOpt, Debug, Clone, Copy)]
    pub struct Args {
        /// Block height from which to start streaming blocks
        height: u64,
    }

    impl RunArgs for Args {
        fn run(self, cfg: &ClientConfiguration) -> Result<()> {
            let Args { height } = self;
            listen(height, cfg)
        }
    }

    pub fn listen(height: u64, cfg: &Configuration) -> Result<()> {
        let iroha_client = Client::new(cfg)?;
        println!("Listening to blocks from height: {}", height);
        for block in iroha_client
            .listen_for_blocks(height)
            .wrap_err("Failed to listen for blocks.")?
        {
            match block {
                Ok(block) => println!("{:#?}", block),
                Err(err) => println!("{:#?}", err),
            };
        }
        Ok(())
    }
}

mod domain {
    use iroha_client::client;
    use iroha_config::client::Configuration;

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
        fn run(self, cfg: &Configuration) -> Result<()> {
            match_run_all!((self, cfg), { Args::Register, Args::List })
        }
    }

    /// Add subcommand for domain
    #[derive(Debug, StructOpt)]
    pub struct Register {
        /// Domain name as double-quoted string
        #[structopt(short, long)]
        pub id: DomainId,
        /// The JSON file with key-value metadata pairs
        #[structopt(short, long, default_value = "")]
        pub metadata: super::Metadata,
    }

    impl RunArgs for Register {
        fn run(self, cfg: &Configuration) -> Result<()> {
            let Self {
                id,
                metadata: Metadata(metadata),
            } = self;
            let create_domain = RegisterBox::new(Domain::new(id)).into();
            submit([create_domain], cfg, metadata).wrap_err("Failed to create domain")
        }
    }

    /// List domains with this command
    #[derive(StructOpt, Debug, Clone, Copy)]
    pub enum List {
        /// All domains
        All,
    }

    impl RunArgs for List {
        fn run(self, cfg: &ClientConfiguration) -> Result<()> {
            let client = Client::new(cfg)?;

            let vec = match self {
                Self::All => client
                    .request(client::domain::all())
                    .wrap_err("Failed to get all domains"),
            }?;
            println!("{:#?}", vec);
            Ok(())
        }
    }
}

mod account {
    use std::{fmt::Debug, fs::File};

    use iroha_client::client;

    use super::*;

    #[allow(variant_size_differences)]
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
        fn run(self, cfg: &ClientConfiguration) -> Result<()> {
            match_run_all!((self, cfg), {
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
        fn run(self, cfg: &ClientConfiguration) -> Result<()> {
            let Self {
                id,
                key,
                metadata: Metadata(metadata),
            } = self;
            let create_account = RegisterBox::new(Account::new(id, [key])).into();
            submit([create_account], cfg, metadata).wrap_err("Failed to register account")
        }
    }

    /// Set subcommand of account
    #[derive(StructOpt, Debug)]
    pub enum Set {
        /// Signature condition
        SignatureCondition(SignatureCondition),
    }

    impl RunArgs for Set {
        fn run(self, cfg: &ClientConfiguration) -> Result<()> {
            match_run_all!((self, cfg), { Set::SignatureCondition })
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
            let file = File::open(s).wrap_err(err_msg)?;
            let condition: Box<Expression> =
                serde_json::from_reader(file).wrap_err(deser_err_msg)?;
            Ok(Self(SignatureCheckCondition(EvaluatesTo::new_unchecked(
                condition,
            ))))
        }
    }

    /// Set accounts signature condition
    #[derive(StructOpt, Debug)]
    pub struct SignatureCondition {
        /// Signature condition file
        pub condition: Signature,
        /// The JSON file with key-value metadata pairs
        #[structopt(short, long, default_value = "")]
        pub metadata: super::Metadata,
    }

    impl RunArgs for SignatureCondition {
        fn run(self, cfg: &ClientConfiguration) -> Result<()> {
            let account = Account::new(cfg.account_id.clone(), []);
            let Self {
                condition: Signature(condition),
                metadata: Metadata(metadata),
            } = self;
            let mint_box =
                MintBox::new(account, EvaluatesTo::new_unchecked(condition.into())).into();
            submit([mint_box], cfg, metadata).wrap_err("Failed to set signature condition")
        }
    }

    /// List accounts with this command
    #[derive(StructOpt, Debug, Clone, Copy)]
    pub enum List {
        /// All accounts
        All,
    }

    impl RunArgs for List {
        fn run(self, cfg: &ClientConfiguration) -> Result<()> {
            let client = Client::new(cfg)?;

            let vec = match self {
                Self::All => client
                    .request(client::account::all())
                    .wrap_err("Failed to get all accounts"),
            }?;
            println!("{:#?}", vec);
            Ok(())
        }
    }

    #[derive(StructOpt, Debug)]
    pub struct Grant {
        /// Account id
        #[structopt(short, long)]
        pub id: <Account as Identifiable>::Id,
        /// The JSON file with a permission token
        #[structopt(short, long)]
        pub permission: Permission,
        /// The JSON file with key-value metadata pairs
        #[structopt(short, long, default_value = "")]
        pub metadata: super::Metadata,
    }

    /// [`PermissionToken`] wrapper implementing [`FromStr`]
    #[derive(Debug)]
    pub struct Permission(PermissionToken);

    impl FromStr for Permission {
        type Err = Error;

        fn from_str(s: &str) -> Result<Self> {
            let file = File::open(s)
                .wrap_err(format!("Failed to open the permission token file {}", &s))?;
            let permission_token: PermissionToken =
                serde_json::from_reader(file).wrap_err(format!(
                    "Failed to deserialize the permission token from file {}",
                    &s
                ))?;
            Ok(Self(permission_token))
        }
    }

    impl RunArgs for Grant {
        fn run(self, cfg: &ClientConfiguration) -> Result<()> {
            let Self {
                id,
                permission,
                metadata: Metadata(metadata),
            } = self;
            let grant = GrantBox::new(permission.0, id).into();
            submit([grant], cfg, metadata).wrap_err("Failed to grant the permission to the account")
        }
    }

    /// List all account permissions
    #[derive(StructOpt, Debug)]
    pub struct ListPermissions {
        /// Account id
        #[structopt(short, long)]
        id: <Account as Identifiable>::Id,
    }

    impl RunArgs for ListPermissions {
        fn run(self, cfg: &ClientConfiguration) -> Result<()> {
            let client = Client::new(cfg)?;
            let find_all_permissions = FindPermissionTokensByAccountId { id: self.id.into() };
            let permissions = client
                .request(find_all_permissions)
                .wrap_err("Failed to get all account permissions")?;
            println!("{:#?}", permissions);
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
        /// Transfer asset between accounts
        Transfer(Transfer),
        /// Get info of asset
        Get(Get),
        /// List assets
        #[clap(subcommand)]
        List(List),
    }

    impl RunArgs for Args {
        fn run(self, cfg: &ClientConfiguration) -> Result<()> {
            match_run_all!(
                (self, cfg),
                { Args::Register, Args::Mint, Args::Transfer, Args::Get, Args::List }
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
        /// /// The JSON file with key-value metadata pairs
        #[structopt(short, long, default_value = "")]
        pub metadata: super::Metadata,
    }

    impl RunArgs for Register {
        fn run(self, cfg: &ClientConfiguration) -> Result<()> {
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
            let create_asset_definition = RegisterBox::new(asset_definition).into();
            submit([create_asset_definition], cfg, metadata).wrap_err("Failed to register asset")
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
        /// /// The JSON file with key-value metadata pairs
        #[structopt(short, long, default_value = "")]
        pub metadata: super::Metadata,
    }

    impl RunArgs for Mint {
        fn run(self, cfg: &ClientConfiguration) -> Result<()> {
            let Self {
                account,
                asset,
                quantity,
                metadata: Metadata(metadata),
            } = self;
            let mint_asset = MintBox::new(
                Value::U32(quantity),
                IdBox::AssetId(AssetId::new(asset, account)),
            )
            .into();
            submit([mint_asset], cfg, metadata)
                .wrap_err("Failed to mint asset of type `Value::U32`")
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
        /// /// The JSON file with key-value metadata pairs
        #[structopt(short, long, default_value = "")]
        pub metadata: super::Metadata,
    }

    impl RunArgs for Transfer {
        fn run(self, cfg: &ClientConfiguration) -> Result<()> {
            let Self {
                from,
                to,
                asset_id,
                quantity,
                metadata: Metadata(metadata),
            } = self;
            let transfer_asset = TransferBox::new(
                IdBox::AssetId(AssetId::new(asset_id.clone(), from)),
                Value::U32(quantity),
                IdBox::AssetId(AssetId::new(asset_id, to)),
            )
            .into();
            submit([transfer_asset], cfg, metadata).wrap_err("Failed to transfer asset")
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
        fn run(self, cfg: &ClientConfiguration) -> Result<()> {
            let Self { account, asset } = self;
            let iroha_client = Client::new(cfg)?;
            let asset_id = AssetId::new(asset, account);
            let value = iroha_client
                .request(asset::by_id(asset_id))
                .wrap_err("Failed to get asset.")?;
            println!("Get Asset result: {:?}", value);
            Ok(())
        }
    }

    /// List assets with this command
    #[derive(StructOpt, Debug, Clone, Copy)]
    pub enum List {
        /// All assets
        All,
    }

    impl RunArgs for List {
        fn run(self, cfg: &ClientConfiguration) -> Result<()> {
            let client = Client::new(cfg)?;

            let vec = match self {
                Self::All => client
                    .request(client::asset::all())
                    .wrap_err("Failed to get all assets"),
            }?;
            println!("{:#?}", vec);
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
        fn run(self, cfg: &ClientConfiguration) -> Result<()> {
            match_run_all!(
                (self, cfg),
                { Args::Register, Args::Unregister }
            )
        }
    }

    /// Register subcommand of peer
    #[derive(StructOpt, Debug)]
    pub struct Register {
        /// P2P address of the peer e.g. `127.0.0.1:1337`
        #[structopt(short, long)]
        pub address: String,
        /// Public key of the peer
        #[structopt(short, long)]
        pub key: PublicKey,
        /// /// The JSON file with key-value metadata pairs
        #[structopt(short, long, default_value = "")]
        pub metadata: super::Metadata,
    }

    impl RunArgs for Register {
        fn run(self, cfg: &ClientConfiguration) -> Result<()> {
            let Self {
                address,
                key,
                metadata: Metadata(metadata),
            } = self;
            let register_peer = RegisterBox::new(Peer::new(PeerId::new(&address, &key))).into();
            submit([register_peer], cfg, metadata).wrap_err("Failed to register peer")
        }
    }

    /// Unregister subcommand of peer
    #[derive(StructOpt, Debug)]
    pub struct Unregister {
        /// P2P address of the peer e.g. `127.0.0.1:1337`
        #[structopt(short, long)]
        pub address: String,
        /// Public key of the peer
        #[structopt(short, long)]
        pub key: PublicKey,
        /// /// The JSON file with key-value metadata pairs
        #[structopt(short, long, default_value = "")]
        pub metadata: super::Metadata,
    }

    impl RunArgs for Unregister {
        fn run(self, cfg: &ClientConfiguration) -> Result<()> {
            let Self {
                address,
                key,
                metadata: Metadata(metadata),
            } = self;
            let unregister_peer =
                UnregisterBox::new(IdBox::PeerId(PeerId::new(&address, &key))).into();
            submit([unregister_peer], cfg, metadata).wrap_err("Failed to unregister peer")
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
        fn run(self, cfg: &ClientConfiguration) -> Result<()> {
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
                Executable::Wasm(WasmSmartContract { raw_data }),
                cfg,
                UnlimitedMetadata::new(),
            )
            .wrap_err("Failed to submit a Wasm smart contract")
        }
    }
}
