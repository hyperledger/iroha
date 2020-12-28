//! This module contains execution Genesis Block logic, and GenesisBlock definition.
use crate::{init::config::InitConfiguration, tx::Accept, tx::AcceptedTransaction, Identifiable};
use iroha_crypto::KeyPair;
use iroha_data_model::{account::Account, isi::Instruction, prelude::*};
use serde::Deserialize;
use std::{fmt::Debug, fs::File, io::BufReader, path::Path};
/// GenesisBlock contains transactions for inisialize settings.
#[derive(Clone, Debug)]
pub struct GenesisBlock {
    /// transactions from GenesisBlock, any transaction is accepted
    pub transactions: Vec<AcceptedTransaction>,
}

#[derive(Clone, Deserialize, Debug)]
struct RawGenesisBlock {
    pub transactions: Vec<GenesisTransaction>,
}

/// GenesisTransaction is a transaction for inisialize settings.
#[derive(Clone, Deserialize, Debug)]
struct GenesisTransaction {
    isi: Vec<Instruction>,
}

impl GenesisTransaction {
    /// Convert GenesisTransaction into AcceptedTransaction with signature
    pub fn sign_and_accept(
        &self,
        genesis_key_pair: &KeyPair,
    ) -> Result<AcceptedTransaction, String> {
        Transaction::new(
            self.isi.clone(),
            <Account as Identifiable>::Id::genesis_account(),
            100_000,
        )
        .sign(&genesis_key_pair)?
        .accept()
    }
}

impl GenesisBlock {
    /// Construct `GenesisBlock` from genesis block json.
    pub fn from_configuration(
        genesis_block_path: &str,
        init_config: &InitConfiguration,
    ) -> Result<GenesisBlock, String> {
        let file = File::open(Path::new(&genesis_block_path))
            .map_err(|e| format!("Failed to open a genesis block file: {}", e))?;
        let reader = BufReader::new(file);
        let raw_block: RawGenesisBlock = serde_json::from_reader(reader)
            .map_err(|e| format!("Failed to deserialize json from reader: {}", e))?;
        let genesis_key_pair = KeyPair {
            public_key: init_config.genesis_account_public_key.clone(),
            private_key: init_config
                .genesis_account_private_key
                .clone()
                .ok_or("genesis account private key is empty")?,
        };
        Ok(GenesisBlock {
            transactions: raw_block
                .transactions
                .iter()
                .map(|raw_transaction| raw_transaction.sign_and_accept(&genesis_key_pair))
                .filter_map(Result::ok)
                .collect(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const GENESIS_BLOCK_PATH: &str = "tests/genesis.json";

    #[test]
    fn load_genesis_block() -> Result<(), String> {
        let root_key_pair = KeyPair::generate()?;
        let genesis_key_pair = KeyPair::generate()?;
        let _genesis_block = GenesisBlock::from_configuration(
            GENESIS_BLOCK_PATH,
            &InitConfiguration {
                root_public_key: root_key_pair.public_key,
                genesis_account_public_key: genesis_key_pair.public_key,
                genesis_account_private_key: Some(genesis_key_pair.private_key),
            },
        )?;
        Ok(())
    }
}
