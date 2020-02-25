/// Main entity in this crate is `Kura`.
/// You should start usage of `Kura` via initialization.
/// For example you can initialize `Kura` with full set of validations:
/// ```
/// use kura::Kura;
///
/// let kura = Kura::strict_init();
/// ```

/// High level data storage representation.
/// Provides all necessary methods to read and write data, hides implementation details.
struct Kura {}

impl Kura {
    /// Kura reads all transactions in all block keeping its order without any validation.
    /// Better to use only for operations with no expectations about correctnes.
    fn fast_init() -> Self {
        Kura {}
    }

    /// `Kura::fast_init` with transactions and blocks validation (signatures correctness and business rules).
    fn strict_init() -> Self {
        Kura::fast_init()
    }

    fn store(&mut self, block: iroha::Block) -> iroha::Hash {
        iroha::Hash {}
    }

    fn read(&mut self, hash: iroha::Hash) -> iroha::Block {
        iroha::Block {}
    }
}

use chashmap::CHashMap;
/// WSV reflects the current state of the system, can be considered as a snapshot. For example, WSV
/// holds information about an amount of assets that an account has at the moment but does not
/// contain any info history of transaction flow.
//TODO: can we assume that these queries https://iroha.readthedocs.io/en/latest/develop/api/queries.html
//will be use cases to read from WSV?
struct WorldStateView {
    /*Structure of arrays?*/
    accounts_assets: CHashMap<String, Vec<iroha::Asset>>,
    accounts_inbound_transactions: CHashMap<String, Vec<iroha::Transaction>>,
    accounts_outbound_transactions: CHashMap<String, Vec<iroha::Transaction>>,
    accounts_all_transactions: CHashMap<String, Vec<iroha::Transaction>>,
    assets_transactions: CHashMap<String, Vec<iroha::Transaction>>,
}

/// Representation of a consistent storage.
struct Disk {}

impl Disk {
    fn write(&mut self, block: iroha::Block) -> Result<u64, String> {
        Result::Err("Not implemented yet.".to_string())
    }
}

mod iroha {
    /// This module contains core `Iroha` stuctures.

    /// Transaction data is permanently recorded in files called blocks. Blocks are organized into
    /// a linear sequence over time (also known as the block chain).
    //TODO: based on https://iroha.readthedocs.io/en/latest/concepts_architecture/glossary.html#block
    //signatures placed outside of the payload - should we store them?
    pub struct Block {
        /// a number of blocks in the chain up to the block.
        height: u64,
        /// Unix time (in milliseconds) of block forming by a peer.
        timestamp: u64,
        /// array of transactions, which successfully passed validation and consensus step.
        transactions: Vec<Transaction>,
        /// hash of a previous block in the chain.
        previous_block_hash: Hash,
        /// rejected transactions hashes — array of transaction hashes, which did not pass stateful
        /// validation step; this field is optional.
        rejected_transactions_hashes: Option<Vec<Hash>>,
    }

    pub struct Hash {}

    pub struct Account {
        /// identifier of an account. Formatted as `account_name@domain_id`.
        id: String,
    }

    pub struct AccountHasAsset {
        account_id: String,
        asset_id: String,
        amount: u64,
    }

    pub struct Asset {
        /// identifier of asset, formatted as asset_name#domain_id
        id: String,
    }

    /// An ordered set of commands, which is applied to the ledger atomically.
    pub struct Transaction {
        /// An ordered set of commands.
        commands: Vec<Command>,
        /// Time of creation (unix time, in milliseconds).
        creation_time: u64,
        /// Account ID of transaction creator (username@domain).
        account_id: String,
        /// Quorum field (indicates required number of signatures).
        quorum: u8,
    }

    /// A command is an intention to change the state of the network.
    /// For example, in order to create a new role in Iroha you have to issue Create role command.
    pub struct Command {
        /// JSON command representation.
        json: String,
    }
}

#[cfg(test)]
mod tests {
    use crate::*;

    #[test]
    fn store_block() {
        Kura::fast_init().store(Block {});
    }

    #[test]
    fn read_block() {
        Kura::fast_init().read(Hash {});
    }
}
