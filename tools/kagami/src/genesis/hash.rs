use std::{
    io::{BufWriter, Write},
    path::PathBuf,
};

use clap::Parser;
use iroha_data_model::block::SignedBlock;
use iroha_version::prelude::DecodeVersioned;

use crate::{Outcome, RunArgs};

/// Get hash of the genesis block
#[derive(Clone, Debug, Parser)]
pub struct Args {
    /// Path to signed genesis file (in SCALE format)
    genesis_file: PathBuf,
}

impl<T: Write> RunArgs<T> for Args {
    fn run(self, writer: &mut BufWriter<T>) -> Outcome {
        let bytes = std::fs::read(self.genesis_file)?;
        let genesis = SignedBlock::decode_all_versioned(&bytes)?;
        let hash = genesis.hash();
        writeln!(writer, "{hash}")?;
        Ok(())
    }
}
