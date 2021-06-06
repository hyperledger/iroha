//! iroha client command line

#![allow(missing_docs, clippy::print_stdout, clippy::use_debug)]

use std::{fmt, fs::File, str::FromStr, time::Duration};

use dialoguer::Confirm;
use iroha_client::{client::Client, config::Configuration as ClientConfiguration};
use iroha_crypto::prelude::*;
use iroha_dsl::prelude::*;
use iroha_error::{Error, Reporter, Result, WrapErr};
use structopt::StructOpt;

/// Metadata wrapper, which can be captured from cli arguments (from user suplied file).
#[derive(Debug, Clone)]
pub struct Metadata(pub iroha_dsl::prelude::UnlimitedMetadata);

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

        let file = File::open(file).wrap_err("Failed to open the metadata file.")?;
        let metadata: UnlimitedMetadata = serde_json::from_reader(file)
            .wrap_err("Failed to deserialize metadata json from reader.")?;
        Ok(Self(metadata))
    }
}

/// Client configuration wrapper. Allows getting itself from arguments from cli (from user suplied file).
#[derive(Debug, Clone)]
pub struct Configuration(pub ClientConfiguration);

impl FromStr for Configuration {
    type Err = Error;
    fn from_str(file: &str) -> Result<Self> {
        let file = File::open(file).wrap_err("Failed to open config file")?;
        let cfg = serde_json::from_reader(file).wrap_err("Failed to decode config file")?;
        Ok(Self(cfg))
    }
}

/// Iroha CLI Client provides an ability to interact with Iroha Peers Web API
/// without direct network usage.
#[derive(StructOpt, Debug)]
#[structopt(
    name = "iroha_client_cli",
    version = "0.1.0",
    author = "Soramitsu Iroha2 team (https://github.com/orgs/soramitsu/teams/iroha2)"
)]
pub struct Args {
    /// Sets a config file path
    #[structopt(short, long, default_value = "config.json")]
    config: Configuration,
    /// Subcommands of client cli
    #[structopt(subcommand)]
    subcommand: Subcommand,
}

#[derive(StructOpt, Debug)]
pub enum Subcommand {
    /// Use this command to work with Domain Entities in Iroha Peer
    Domain(domain::Args),
    /// Use this command to work with Account Entities in Iroha Peer
    Account(account::Args),
    /// Use this command to work with Assets in Iroha Peer
    Asset(asset::Args),
    /// Use this command to listen to Iroha events over the streaming API
    Events(events::Args),
}

/// Runs subcommand
pub trait RunArgs {
    /// Runs command
    /// # Errors
    /// Depends on inner command
    fn run(self, cfg: &ClientConfiguration) -> Result<()>;
}

macro_rules! match_run_all {
    (($self:ident, $cfg:ident), { $($variants:path),* }) => {
        match $self {
            $($variants(variant) => variant.run($cfg),)*
        }
    };
}

impl RunArgs for Subcommand {
    fn run(self, cfg: &ClientConfiguration) -> Result<()> {
        use Subcommand::*;
        match_run_all!((self, cfg), { Domain, Account, Asset, Events })
    }
}

// TODO: move into config.
const RETRY_COUNT_MST: u32 = 1;
const RETRY_IN_MST: Duration = Duration::from_millis(100);

fn main() -> Result<(), Reporter> {
    iroha_error::install_panic_reporter();
    let Args {
        config: Configuration(config),
        subcommand,
    } = Args::from_args();

    println!("Value for config: {:?}", &config);
    subcommand
        .run(&config)
        .wrap_err("Failed to run subcommand")?;
    Ok(())
}

/// # Errors
/// Fails if submitting over network fails
pub fn submit(
    instruction: impl Into<Instruction>,
    cfg: &ClientConfiguration,
    metadata: UnlimitedMetadata,
) -> Result<()> {
    let instruction = instruction.into();
    let mut iroha_client = Client::new(cfg);
    let tx = iroha_client
        .build_transaction(vec![instruction], metadata)
        .wrap_err("Failed to build transaction.")?;
    let tx = match iroha_client.get_original_transaction(
        &tx,
        RETRY_COUNT_MST,
        RETRY_IN_MST,
    ) {
        Ok(Some(original_transaction)) if Confirm::new()
            .with_prompt("There is a similar transaction from your account waiting for more signatures. Do you want to sign it instead of submitting a new transaction?")
            .interact()
            .wrap_err("Failed to show interactive prompt.")? => iroha_client.sign_transaction(original_transaction).wrap_err("Failed to sign transaction.")?,
        _ => tx,
    };

    let _ = iroha_client
        .submit_transaction(tx)
        .wrap_err("Failed to submit transaction.")?;
    Ok(())
}

mod events {
    use iroha_client::{client::Client, config::Configuration};

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
                Args::Data => EventFilter::Pipeline(PipelineEventFilter::identity()),
                Args::Pipeline => EventFilter::Data(DataEventFilter),
            };
            listen(filter, cfg)
        }
    }

    pub fn listen(filter: EventFilter, cfg: &Configuration) -> Result<()> {
        let mut iroha_client = Client::new(cfg);
        println!("Listening to events with filter: {:?}", filter);
        for event in iroha_client
            .listen_for_events(filter)
            .wrap_err("Failed to listen to events.")?
        {
            match event {
                Ok(event) => println!("{:#?}", event),
                Err(err) => println!("{:#?}", err),
            };
        }
        Ok(())
    }
}

mod domain {
    use iroha_client::config::Configuration;

    use super::*;

    /// Arguments for domain subcommand
    #[derive(Debug, StructOpt)]
    pub enum Args {
        /// Register domain
        Register(Register),
    }

    impl RunArgs for Args {
        fn run(self, cfg: &Configuration) -> Result<()> {
            match_run_all!((self, cfg), { Args::Register })
        }
    }

    /// Add subcommand for domain
    #[derive(Debug, StructOpt)]
    pub struct Register {
        /// Domain's name as double-quoted string
        #[structopt(short, long)]
        pub id: Domain,
        /// The filename with key-value metadata pairs in JSON
        #[structopt(short, long, default_value = "")]
        pub metadata: super::Metadata,
    }

    impl RunArgs for Register {
        fn run(self, cfg: &Configuration) -> Result<()> {
            let Self {
                id,
                metadata: Metadata(metadata),
            } = self;
            let create_domain = RegisterBox::new(IdentifiableBox::from(id));
            submit(create_domain, cfg, metadata).wrap_err("Failed to create domain")
        }
    }
}

mod account {
    use std::{fmt::Debug, fs::File};

    use super::*;

    #[allow(variant_size_differences)]
    /// subcommands for account subcommand
    #[derive(StructOpt, Debug)]
    pub enum Args {
        /// Register account
        Register(Register),
        /// Set something in account
        Set(Set),
    }

    impl RunArgs for Args {
        fn run(self, cfg: &ClientConfiguration) -> Result<()> {
            match_run_all!((self, cfg), { Args::Register, Args::Set })
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
        /// The filename with key-value metadata pairs in JSON
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
            let create_account =
                RegisterBox::new(IdentifiableBox::from(NewAccount::with_signatory(id, key)));
            submit(create_account, cfg, metadata).wrap_err("Failed to register account")
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
            let file = File::open(s).wrap_err("Failed to open the signature condition file")?;
            let condition: Box<Expression> = serde_json::from_reader(file)
                .wrap_err("Failed to deserialize signature expression from reader")?;
            Ok(Self(SignatureCheckCondition(condition.into())))
        }
    }

    /// Set accounts signature condition
    #[derive(StructOpt, Debug)]
    pub struct SignatureCondition {
        /// Signature condition file
        pub condition: Signature,
        /// The filename with key-value metadata pairs in JSON
        #[structopt(short, long, default_value = "")]
        pub metadata: super::Metadata,
    }

    impl RunArgs for SignatureCondition {
        fn run(self, cfg: &ClientConfiguration) -> Result<()> {
            let account = Account::new(cfg.account_id.clone());
            let Self {
                condition: Signature(condition),
                metadata: Metadata(metadata),
            } = self;
            submit(MintBox::new(account, condition), cfg, metadata)
                .wrap_err("Failed to set signature condition")
        }
    }
}

mod asset {
    use iroha_client::client::{asset, Client};

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
    }

    impl RunArgs for Args {
        fn run(self, cfg: &ClientConfiguration) -> Result<()> {
            match_run_all!(
                (self, cfg),
                { Args::Register, Args::Mint, Args::Transfer, Args::Get }
            )
        }
    }

    /// Register subcommand of asset
    #[derive(StructOpt, Debug)]
    pub struct Register {
        /// Asset id for registering (in form of `name#domain_name')
        #[structopt(short, long)]
        pub id: AssetDefinitionId,
        /// Value type stored in asset
        #[structopt(short, long)]
        pub value_type: AssetValueType,
        /// The filename with key-value metadata pairs in JSON
        #[structopt(short, long, default_value = "")]
        pub metadata: super::Metadata,
    }

    impl RunArgs for Register {
        fn run(self, cfg: &ClientConfiguration) -> Result<()> {
            let Self {
                id,
                value_type,
                metadata: Metadata(metadata),
            } = self;
            submit(
                RegisterBox::new(IdentifiableBox::AssetDefinition(
                    AssetDefinition::new(id, value_type).into(),
                )),
                cfg,
                metadata,
            )
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
        /// The filename with key-value metadata pairs in JSON
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
            );
            submit(mint_asset, cfg, metadata).wrap_err("Failed to mint asset value")
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
        /// The filename with key-value metadata pairs in JSON
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
            );
            submit(transfer_asset, cfg, metadata).wrap_err("Failed to transfer asset")
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
            let mut iroha_client = Client::new(cfg);
            let value = iroha_client
                .request(asset::by_account_id_and_definition_id(account, asset))
                .wrap_err("Failed to get asset.")?;
            println!("Get Asset result: {:?}", value);
            Ok(())
        }
    }
}
