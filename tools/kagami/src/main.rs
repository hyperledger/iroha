//! CLI for generating iroha sample configuration, genesis and
//! cryptographic key pairs. To be used with all compliant Iroha
//! installations.
use std::{
    io::{stdout, BufWriter, Write},
    str::FromStr as _,
};

use clap::{Args as ClapArgs, Parser};
use color_eyre::eyre::WrapErr as _;
use iroha_data_model::prelude::*;

mod crypto;
mod genesis;
mod schema;

/// Outcome shorthand used throughout this crate
pub(crate) type Outcome = color_eyre::Result<()>;

// The reason for hard-coding this default is to ensure that the
// algorithm is matched to the public key in Ed25519 format. If
// you need to change either, you should definitely change both.
const DEFAULT_PUBLIC_KEY: &str =
    "ed01207233bfc89dcbd68c19fde6ce6158225298ec1131b6a130d1aeb454c1ab5183c0";

fn main() -> Outcome {
    color_eyre::install()?;
    let args = Args::parse();
    let mut writer = BufWriter::new(stdout());
    args.run(&mut writer)
}

/// Trait to encapsulate common attributes of the commands and sub-commands.
trait RunArgs<T: Write> {
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
enum Args {
    /// Generate cryptographic key pairs using the given algorithm and either private key or seed
    Crypto(Box<crypto::Args>),
    /// Generate the schema used for code generation in Iroha SDKs
    Schema(schema::Args),
    /// Generate the genesis block that is used in tests
    Genesis(genesis::Args),
}

impl<T: Write> RunArgs<T> for Args {
    fn run(self, writer: &mut BufWriter<T>) -> Outcome {
        use Args::*;

        match self {
            Crypto(args) => args.run(writer),
            Schema(args) => args.run(writer),
            Genesis(args) => args.run(writer),
        }
    }
}
