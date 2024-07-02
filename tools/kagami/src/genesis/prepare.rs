use std::{
    fs,
    io::{BufWriter, Write},
    path::PathBuf,
};

use clap::Parser;
use iroha_genesis::RawGenesisTransaction;
use parity_scale_codec::Encode;

use crate::{Outcome, RunArgs};

/// Prepare the genesis block.
/// Converts genesis.json to genesis.scale and prints its hash to stdout.
#[derive(Clone, Debug, Parser)]
pub struct Args {
    /// Path to input genesis json file
    genesis_file: PathBuf,
    /// Path to output genesis file in SCALE format
    #[clap(short, long, value_name("PATH"))]
    out_file: PathBuf,
}

impl<T: Write> RunArgs<T> for Args {
    fn run(self, stdout: &mut BufWriter<T>) -> Outcome {
        let raw_genesis = RawGenesisTransaction::from_path(&self.genesis_file)?;
        let genesis = raw_genesis.build()?;

        let bytes = genesis.encode();
        fs::write(self.out_file, bytes)?;

        let hash = genesis.hash();
        writeln!(stdout, "{hash}")?;

        Ok(())
    }
}
