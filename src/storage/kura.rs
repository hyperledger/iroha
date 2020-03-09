use crate::model::model;

/// Main entity in this crate is `Kura`.
/// You should start usage of `Kura` via initialization.
/// For example you can initialize `Kura` with full set of validations:
/// ```
/// use iroha::storage::kura::Kura;
///
/// let kura = Kura::strict_init();
/// ```

/// High level data storage representation.
/// Provides all necessary methods to read and write data, hides implementation details.
pub struct Kura {
    disk: Disk,
    pub world_state_view: WorldStateView,
    merkle_tree: MerkleTree,
}

impl Kura {
    /// Kura reads all transactions in all block keeping its order without any validation.
    /// Better to use only for operations with no expectations about correctnes.
    pub fn fast_init() -> Self {
        let disk = Disk {};
        let blocks = disk.read();
        Kura {
            disk: disk,
            world_state_view: WorldStateView::init(blocks),
            //TODO[@humb1t:RH2-13]: replace `default` with `new`
            merkle_tree: MerkleTree::default(),
        }
    }

    /// `Kura::fast_init` with transactions and blocks validation (signatures correctness and business rules).
    pub fn strict_init() -> Result<Self, String> {
        match validate() {
            Ok(_) => Ok(Kura::fast_init()),
            Err(error) => Err(error),
        }
    }

    /// Methods consumes new validated block and atomically stores and caches it.
    pub fn store(&mut self, block: model::Block) -> Result<model::Hash, String> {
        //TODO[@humb1t:RH2-14]: make `disk.write` and `world_state_view.put` async/parallel
        let disk_result = self.disk.write(block.clone());
        self.world_state_view.put(block.clone());
        self.merkle_tree.put(block.clone());
        match disk_result {
            Ok(hash) => Ok(hash),
            Err(error) => {
                self.world_state_view = WorldStateView::default();
                self.merkle_tree = MerkleTree::default();
                Err(error)
            }
        }
    }
}

#[test]
fn strict_init_kura() {
    assert!(Kura::strict_init().is_ok());
}

//TODO[@humb1t:RH2-15]: who is responsible for validation logic?
fn validate() -> Result<(), String> {
    println!("Validating...");
    Ok(())
}

use chashmap::CHashMap;
/// WSV reflects the current state of the system, can be considered as a snapshot. For example, WSV
/// holds information about an amount of assets that an account has at the moment but does not
/// contain any info history of transaction flow.
#[derive(Default)]
pub struct WorldStateView {
    /*Structure of arrays?*/
    /// Map of `account_id` to vector of assets.
    accounts_assets: CHashMap<String, Vec<model::Asset>>,
    /// Map of `account_id` to vector of inbound transactions.
    accounts_inbound_transactions: CHashMap<String, Vec<model::Transaction>>,
    /// Map of `account_id` to vector of outbound transactions.
    accounts_outbound_transactions: CHashMap<String, Vec<model::Transaction>>,
    /// Map of `account_id` to vector of all transactions.
    accounts_all_transactions: CHashMap<String, Vec<model::Transaction>>,
    /// Map of `asset_id` to vector of all transactions.
    assets_transactions: CHashMap<String, Vec<model::Transaction>>,
}

impl WorldStateView {
    fn init(blocks: Vec<model::Block>) -> Self {
        let mut world_state_view = WorldStateView::default();
        for block in blocks {
            world_state_view.put(block);
        }
        world_state_view
    }

    fn put(&mut self, block: model::Block) {
        self.accounts_assets = merge_accounts_assets(self.accounts_assets.clone(), block.clone());
        self.accounts_inbound_transactions =
            merge_inbound_transactions(self.accounts_inbound_transactions.clone(), block.clone());
        self.accounts_outbound_transactions =
            merge_outbound_transactions(self.accounts_outbound_transactions.clone(), block.clone());
        self.accounts_all_transactions =
            merge_all_transactions(self.accounts_all_transactions.clone(), block.clone());
        self.assets_transactions =
            merge_assets_transactions(self.assets_transactions.clone(), block.clone());
    }

    /// Return a `Vec` of `Asset`. Result will be empty if there are no assets associated with an
    /// account.
    pub fn get_assets_by_account_id(&self, account_id: &str) -> Vec<model::Asset> {
        match &self.accounts_assets.get(account_id) {
            Some(assets) => assets.clone().to_vec(),
            None => Vec::new(),
        }
    }
}

fn merge_accounts_assets(
    origin: CHashMap<String, Vec<model::Asset>>,
    block: model::Block,
) -> CHashMap<String, Vec<model::Asset>> {
    use crate::model::model::{Accountability, Assetibility, Relation};
    for tx in block.transactions.iter() {
        for command in &tx.commands {
            for relation in command.relations() {
                if let Relation::BelongsTo(account_id) = relation {
                    println!("BelongsTo {:?}", &account_id);
                    for asset_id in command.assets() {
                        origin.insert(
                            account_id.clone(),
                            vec![model::Asset {
                                id: asset_id.clone(),
                            }],
                        );
                    }
                }
            }
        }
    }
    origin
}

fn merge_inbound_transactions(
    origin: CHashMap<String, Vec<model::Transaction>>,
    block: model::Block,
) -> CHashMap<String, Vec<model::Transaction>> {
    use crate::model::model::{Accountability, Relation};
    for tx in block.transactions.iter() {
        for command in &tx.commands {
            for relation in command.relations() {
                if let Relation::GoingTo(account_id) = relation {
                    origin.upsert(
                        account_id.clone(),
                        || vec![tx.clone()],
                        |transactions| transactions.push(tx.clone()),
                    );
                }
            }
        }
    }
    origin
}

fn merge_outbound_transactions(
    origin: CHashMap<String, Vec<model::Transaction>>,
    block: model::Block,
) -> CHashMap<String, Vec<model::Transaction>> {
    use crate::model::model::{Accountability, Relation};
    for tx in block.transactions.iter() {
        for command in &tx.commands {
            for relation in command.relations() {
                if let Relation::GoingFrom(account_id) = relation {
                    origin.upsert(
                        account_id.clone(),
                        || vec![tx.clone()],
                        |transactions| transactions.push(tx.clone()),
                    );
                }
            }
        }
    }
    origin
}

fn merge_all_transactions(
    origin: CHashMap<String, Vec<model::Transaction>>,
    block: model::Block,
) -> CHashMap<String, Vec<model::Transaction>> {
    use crate::model::model::{Accountability, Relation};
    for tx in block.transactions.iter() {
        for command in &tx.commands {
            for relation in command.relations() {
                match relation {
                    Relation::GoingTo(account_id) => {
                        origin.upsert(
                            account_id.clone(),
                            || vec![tx.clone()],
                            |transactions| transactions.push(tx.clone()),
                        );
                    }
                    Relation::BelongsTo(account_id) => {
                        origin.upsert(
                            account_id.clone(),
                            || vec![tx.clone()],
                            |transactions| transactions.push(tx.clone()),
                        );
                    }
                    Relation::GoingFrom(account_id) => {
                        origin.upsert(
                            account_id.clone(),
                            || vec![tx.clone()],
                            |transactions| transactions.push(tx.clone()),
                        );
                    }
                }
            }
        }
    }
    origin
}

fn merge_assets_transactions(
    origin: CHashMap<String, Vec<model::Transaction>>,
    block: model::Block,
) -> CHashMap<String, Vec<model::Transaction>> {
    origin
}

#[derive(Default)]
struct MerkleTree {}

impl MerkleTree {
    fn put(&mut self, block: model::Block) {
        println!("Putting block into tree.");
    }
}

/// Representation of a consistent storage.
struct Disk {}

impl Disk {
    fn write(&mut self, block: model::Block) -> Result<model::Hash, String> {
        use std::fs::File;
        use std::io::prelude::*;
        //TODO: 1block == 1file filename = #
        match File::create("storage") {
            Ok(mut file) => {
                let hash = block.hash();
                let serialized_block: Vec<u8> = block.into();
                if let Err(error) = file.write_all(&serialized_block) {
                    return Err(format!("Failed to write to storage file {}", error));
                }
                return Ok(hash);
            }
            Err(error) => Result::Err(format!("Failed to open storage file {}", error)),
        }
    }

    fn read(&self) -> Vec<model::Block> {
        Vec::new()
    }
}

#[test]
fn write_block_to_disk() {
    let block = model::Block {
        height: 1,
        timestamp: 1,
        transactions: Vec::new(),
        previous_block_hash: model::Hash {},
        rejected_transactions_hashes: Option::None,
    };
    assert!(Disk {}.write(block).is_ok());
}

#[cfg(test)]
mod tests {
    use crate::storage::kura::*;

    ///Kura takes as input blocks, which comprise multiple transactions. Kura is meant to take only
    ///blocks as input that have passed stateless and stateful validation, and have been finalized
    ///by consensus. For finalized blocks, Kura simply commits the block to the block storage on
    ///the disk and updates atomically the in-memory hashmaps that make up the key-value store that
    ///is the world-state-view. To optimize networking syncing, which works on 100 block chunks,
    ///chunks of 100 blocks each are stored in files in the block store.
    #[test]
    fn store_block() {
        let account_id = "test@test";
        let transaction = model::Transaction {
            commands: Vec::new(),
            creation_time: 1,
            account_id: account_id.to_string(),
            quorum: 1,
            signatures: Vec::new(),
        };
        let block = model::Block {
            height: 1,
            timestamp: 1,
            transactions: vec![transaction],
            previous_block_hash: model::Hash {},
            rejected_transactions_hashes: Option::None,
        };
        let mut kura = Kura::fast_init();
        let _result = kura.store(block);
        assert!(kura
            .world_state_view
            .get_assets_by_account_id(account_id)
            .is_empty());
    }
}
