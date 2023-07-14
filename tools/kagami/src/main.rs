//! CLI for generating iroha sample configuration, genesis and
//! cryptographic key pairs. To be used with all compliant Iroha
//! installations.
#![allow(
    clippy::arithmetic_side_effects,
    clippy::std_instead_of_core,
    clippy::std_instead_of_alloc
)]
use std::{
    io::{stdout, BufWriter, Write},
    str::FromStr as _,
};

use clap::{Args as ClapArgs, Parser};
use color_eyre::eyre::WrapErr as _;
use iroha_data_model::prelude::*;

mod config;
mod crypto;
mod docs;
mod genesis;
mod schema;
mod swarm;
mod validator;

/// Outcome shorthand used throughout this crate
pub(crate) type Outcome = color_eyre::Result<()>;

// The reason for hard-coding this default is to ensure that the
// algorithm is matched to the public key in Ed25519 format. If
// you need to change either, you should definitely change both.
pub const DEFAULT_PUBLIC_KEY: &str =
    "ed01207233bfc89dcbd68c19fde6ce6158225298ec1131b6a130d1aeb454c1ab5183c0";
pub const GIT_REVISION: &str = env!("VERGEN_GIT_SHA");
pub const GIT_ORIGIN: &str = "https://github.com/hyperledger/iroha.git";
/// Config directory that is generated in the output directory
pub const DIR_CONFIG: &str = "config";
/// Config directory inside of the docker image
pub const DIR_CONFIG_IN_DOCKER: &str = "/config";
pub const DIR_CLONE: &str = "iroha-cloned";
pub const FILE_VALIDATOR: &str = "validator.wasm";
pub const FILE_CONFIG: &str = "config.json";
pub const FILE_GENESIS: &str = "genesis.json";
pub const FILE_COMPOSE: &str = "docker-compose.yml";
pub const FORCE_ARG_SUGGESTION: &str =
    "You can pass `--outdir-force` flag to remove the directory without prompting";
pub const GENESIS_KEYPAIR_SEED: &[u8; 7] = b"genesis";

fn main() -> Outcome {
    color_eyre::install()?;
    let args = Args::parse();
    let mut writer = BufWriter::new(stdout());
    args.run(&mut writer)
}

/// Trait to encapsulate common attributes of the commands and sub-commands.
pub trait RunArgs<T: Write> {
    /// Run the given command.
    ///
    /// # Errors
    /// if inner command fails.
    fn run(self, writer: &mut BufWriter<T>) -> Outcome;
}

/// Kagami is a tool used to generate and validate automatically generated data files that are
/// shipped with Iroha.
#[derive(Parser, Debug)]
#[command(name = "kagami", version, author)]
pub enum Args {
    /// Generate cryptographic key pairs using the given algorithm and either private key or seed
    Crypto(Box<crypto::Args>),
    /// Generate the schema used for code generation in Iroha SDKs
    Schema(schema::Args),
    /// Generate the genesis block that is used in tests
    Genesis(genesis::Args),
    /// Generate the default client/peer configuration
    Config(config::Args),
    /// Generate a Markdown reference of configuration parameters
    Docs(Box<docs::Args>),
    /// Generate the default validator. It clones the Iroha repo
    /// behind the scenes if the command is run from a standalone
    /// binary
    Validator(validator::Args),
    /// Generate Docker Compose configuration
    Swarm(swarm::Args),
}

impl<T: Write> RunArgs<T> for Args {
    fn run(self, writer: &mut BufWriter<T>) -> Outcome {
        use Args::*;

        match self {
            Crypto(args) => args.run(writer),
            Schema(args) => args.run(writer),
            Genesis(args) => args.run(writer),
            Config(args) => args.run(writer),
            Docs(args) => args.run(writer),
            Validator(args) => args.run(writer),
            Swarm(args) => args.run(),
        }
    }
}
