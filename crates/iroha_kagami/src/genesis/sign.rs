use std::{
    fs,
    fs::File,
    io::{BufWriter, Write},
    path::PathBuf,
};

use clap::{ArgGroup, Parser};
use color_eyre::eyre;
use iroha_crypto::{KeyPair, PrivateKey};
use iroha_data_model::prelude::*;
use iroha_genesis::RawGenesisTransaction;
use parity_scale_codec::Encode;

use crate::{Outcome, RunArgs};

/// Sign the genesis block
#[derive(Clone, Debug, Parser)]
#[command(group = ArgGroup::new("private_key_group").required(true))]
#[command(group = ArgGroup::new("public_key_group").required(true))]
pub struct Args {
    /// Path to genesis json file
    genesis_file: PathBuf,
    /// Genesis private key
    #[clap(long, group = "private_key_group", value_name("MULTIHASH"))]
    private_key: Option<PrivateKey>,
    /// Genesis public key
    #[clap(long, group = "public_key_group", value_name("MULTIHASH"))]
    public_key: Option<PublicKey>,
    /// Path to json-serialized `KeyPair`
    #[clap(
        long,
        group = "private_key_group",
        group = "public_key_group",
        value_name("PATH")
    )]
    keypair_file: Option<PathBuf>,
    /// Path to signed genesis output file in SCALE format (stdout by default)
    #[clap(short, long, value_name("PATH"))]
    out_file: Option<PathBuf>,
    /// Use this topology instead of specified in genesis.json.
    /// JSON-serialized vector of `PeerId`. For use in `iroha_swarm`.
    #[clap(short, long)]
    topology: Option<String>,
}

impl<T: Write> RunArgs<T> for Args {
    fn run(self, writer: &mut BufWriter<T>) -> Outcome {
        let genesis_key_pair = self.get_key_pair()?;
        let genesis = RawGenesisTransaction::from_path(&self.genesis_file)?;
        let mut builder = genesis.into_builder();
        if let Some(topology) = self.topology {
            let topology = serde_json::from_str(&topology).expect("Failed to parse topology");
            builder = builder.set_topology(topology);
        }
        let genesis_transaction = builder.build_and_sign(&genesis_key_pair)?;

        let mut writer: Box<dyn Write> = match self.out_file {
            None => Box::new(writer),
            Some(path) => Box::new(BufWriter::new(File::create(path)?)),
        };
        let bytes = genesis_transaction.0.encode();
        writer.write_all(&bytes)?;

        Ok(())
    }
}

impl Args {
    fn get_key_pair(&self) -> eyre::Result<KeyPair> {
        match (&self.keypair_file, &self.public_key, &self.private_key) {
            (Some(path), None, None) => {
                let content = fs::read_to_string(path)?;
                Ok(serde_json::from_str(&content)?)
            }
            (None, Some(public_key), Some(private_key)) => {
                Ok(KeyPair::new(public_key.clone(), private_key.clone())?)
            }
            _ => unreachable!("Clap group invariant"),
        }
    }
}
