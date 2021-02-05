//! This module contains `Block` structures for each state, it's transitions, implementations and related traits
//! implementations.

use crate::{
    merkle::MerkleTree, permissions::PermissionsValidatorBox, prelude::*,
    sumeragi::InitializedNetworkTopology, tx::RejectedTransaction,
};
use iroha_crypto::{KeyPair, Signatures};
use iroha_data_model::events::prelude::*;
use iroha_derive::Io;
use parity_scale_codec::{Decode, Encode};
use std::iter;
use std::time::SystemTime;

/// Transaction data is permanently recorded in files called blocks. Blocks are organized into
/// a linear sequence over time (also known as the block chain).
/// Blocks lifecycle starts from "Pending" state which is represented by `PendingBlock` struct.
#[derive(Clone, Debug, Io, Encode, Decode)]
pub struct PendingBlock {
    /// Unix time (in milliseconds) of block forming by a peer.
    pub timestamp: u128,
    /// array of transactions, which successfully passed validation and consensus step.
    pub transactions: Vec<AcceptedTransaction>,
}

impl PendingBlock {
    /// Create a new `PendingBlock` from transactions.
    pub fn new(transactions: Vec<AcceptedTransaction>) -> PendingBlock {
        PendingBlock {
            timestamp: SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .expect("Failed to get System Time.")
                .as_millis(),
            transactions,
        }
    }

    /// Chain block with the existing blockchain.
    pub fn chain(
        self,
        height: u64,
        previous_block_hash: Hash,
        number_of_view_changes: u32,
        invalidated_blocks_hashes: Vec<Hash>,
    ) -> ChainedBlock {
        ChainedBlock {
            transactions: self.transactions,
            header: BlockHeader {
                timestamp: self.timestamp,
                height: height + 1,
                previous_block_hash,
                transactions_merkle_root_hash: Hash([0u8; 32]),
                rejected_transactions_merkle_root_hash: Hash([0u8; 32]),
                number_of_view_changes,
                invalidated_blocks_hashes,
                genesis_topology: None,
            },
        }
    }

    /// Create a new blockchain with current block as a first block.
    pub fn chain_first_with_genesis_topology(
        self,
        genesis_topology: InitializedNetworkTopology,
    ) -> ChainedBlock {
        ChainedBlock {
            transactions: self.transactions,
            header: BlockHeader {
                timestamp: self.timestamp,
                height: 1,
                previous_block_hash: Hash([0u8; 32]),
                transactions_merkle_root_hash: Hash([0u8; 32]),
                rejected_transactions_merkle_root_hash: Hash([0u8; 32]),
                number_of_view_changes: 0,
                invalidated_blocks_hashes: Vec::new(),
                genesis_topology: Some(genesis_topology),
            },
        }
    }

    /// Create a new blockchain with current block as a first block.
    pub fn chain_first(self) -> ChainedBlock {
        ChainedBlock {
            transactions: self.transactions,
            header: BlockHeader {
                timestamp: self.timestamp,
                height: 1,
                previous_block_hash: Hash([0u8; 32]),
                transactions_merkle_root_hash: Hash([0u8; 32]),
                rejected_transactions_merkle_root_hash: Hash([0u8; 32]),
                number_of_view_changes: 0,
                invalidated_blocks_hashes: Vec::new(),
                genesis_topology: None,
            },
        }
    }
}

/// When `PendingBlock` chained with a blockchain it becomes `ChainedBlock`
#[derive(Clone, Debug, Io, Encode, Decode)]
pub struct ChainedBlock {
    /// Header
    pub header: BlockHeader,
    /// Array of transactions, which successfully passed validation and consensus step.
    pub transactions: Vec<AcceptedTransaction>,
}

/// Header of the block. The hash should be taken from its byte representation.
#[derive(Clone, Debug, Io, Encode, Decode)]
pub struct BlockHeader {
    /// Unix time (in milliseconds) of block forming by a peer.
    pub timestamp: u128,
    /// a number of blocks in the chain up to the block.
    pub height: u64,
    /// Hash of a previous block in the chain.
    /// Is an array of zeros for the first block.
    pub previous_block_hash: Hash,
    /// Hash of merkle tree root of the tree of valid transactions' hashes.
    pub transactions_merkle_root_hash: Hash,
    /// Hash of merkle tree root of the tree of rejected transactions' hashes.
    pub rejected_transactions_merkle_root_hash: Hash,
    /// Number of view changes after the previous block was committed and before this block was committed.
    pub number_of_view_changes: u32,
    /// Hashes of the blocks that were rejected by consensus.
    pub invalidated_blocks_hashes: Vec<Hash>,
    /// Genesis topology
    pub genesis_topology: Option<InitializedNetworkTopology>,
}

impl BlockHeader {
    /// Calculate hash of the current block header.
    pub fn hash(&self) -> Hash {
        let bytes: Vec<u8> = self.into();
        Hash::new(&bytes)
    }

    /// Checks if it's a header of a genesis block.
    pub fn is_genesis(&self) -> bool {
        self.height == 1
    }
}

impl ChainedBlock {
    /// Validate block transactions against current state of the world.
    pub fn validate(
        self,
        world_state_view: &WorldStateView,
        permissions_validator: &PermissionsValidatorBox,
    ) -> ValidBlock {
        let mut transactions = Vec::new();
        let mut rejected_transactions = Vec::new();
        for transaction in self.transactions {
            match transaction.validate(
                world_state_view,
                permissions_validator,
                self.header.is_genesis(),
            ) {
                Ok(transaction) => transactions.push(transaction),
                Err(transaction) => {
                    log::warn!(
                        "Transaction validation failed: {}",
                        transaction.rejection_reason
                    );
                    rejected_transactions.push(transaction)
                }
            }
        }
        let mut header = self.header;
        header.transactions_merkle_root_hash = MerkleTree::new()
            .build(
                &transactions
                    .iter()
                    .map(|transaction| transaction.hash())
                    .collect::<Vec<_>>(),
            )
            .root_hash();
        header.rejected_transactions_merkle_root_hash = MerkleTree::new()
            .build(
                &rejected_transactions
                    .iter()
                    .map(|transaction| transaction.hash())
                    .collect::<Vec<_>>(),
            )
            .root_hash();
        ValidBlock {
            header,
            rejected_transactions,
            transactions,
            signatures: Signatures::default(),
        }
    }

    /// Calculate hash of the current block.
    pub fn hash(&self) -> Hash {
        self.header.hash()
    }
}

/// After full validation `ChainedBlock` can transform into `ValidBlock`.
#[derive(Clone, Debug, Io, Encode, Decode)]
pub struct ValidBlock {
    /// Header
    pub header: BlockHeader,
    /// Array of rejected transactions.
    pub rejected_transactions: Vec<RejectedTransaction>,
    /// Array of transactions.
    pub transactions: Vec<ValidTransaction>,
    /// Signatures of peers which approved this block.
    pub signatures: Signatures,
}

impl ValidBlock {
    /// Commit block to the store.
    //TODO: pass block store and block sender as parameters?
    pub fn commit(self) -> CommittedBlock {
        CommittedBlock {
            header: self.header,
            rejected_transactions: self.rejected_transactions,
            transactions: self.transactions,
            signatures: self.signatures,
        }
    }

    /// Validate block transactions against current state of the world.
    pub fn revalidate(
        self,
        world_state_view: &WorldStateView,
        permissions_validator: &PermissionsValidatorBox,
    ) -> ValidBlock {
        ValidBlock {
            signatures: self.signatures,
            ..ChainedBlock {
                header: self.header,
                transactions: self
                    .transactions
                    .into_iter()
                    .map(|transaction| transaction.into())
                    .chain(
                        self.rejected_transactions
                            .into_iter()
                            .map(|transaction| transaction.into()),
                    )
                    .collect(),
            }
            .validate(world_state_view, permissions_validator)
        }
    }

    /// Calculate hash of the current block.
    pub fn hash(&self) -> Hash {
        self.header.hash()
    }

    /// Sign this block and get `ValidBlock`.
    pub fn sign(mut self, key_pair: &KeyPair) -> Result<ValidBlock, String> {
        let signature = Signature::new(key_pair.clone(), self.hash().as_ref())?;
        self.signatures.add(signature);
        Ok(self)
    }

    /// Signatures that are verified with the `hash` of this block as `payload`.
    pub fn verified_signatures(&self) -> Vec<Signature> {
        self.signatures.verified(self.hash().as_ref())
    }

    /// Checks if there are no transactions in this block.
    pub fn is_empty(&self) -> bool {
        self.transactions.is_empty() && self.rejected_transactions.is_empty()
    }

    /// Checks if block has transactions that are already in blockchain.
    pub fn has_committed_transactions(&self, world_state_view: &WorldStateView) -> bool {
        self.transactions
            .iter()
            .any(|transaction| transaction.is_in_blockchain(world_state_view))
            || self
                .rejected_transactions
                .iter()
                .any(|transaction| transaction.is_in_blockchain(world_state_view))
    }
}

impl From<&ValidBlock> for Vec<Event> {
    fn from(block: &ValidBlock) -> Self {
        block
            .transactions
            .iter()
            .cloned()
            .map(|transaction| {
                PipelineEvent::new(
                    PipelineEntityType::Transaction,
                    PipelineStatus::Validating,
                    transaction.hash(),
                )
                .into()
            })
            .chain(
                block
                    .rejected_transactions
                    .iter()
                    .cloned()
                    .map(|transaction| {
                        PipelineEvent::new(
                            PipelineEntityType::Transaction,
                            PipelineStatus::Validating,
                            transaction.hash(),
                        )
                        .into()
                    }),
            )
            .chain(iter::once(
                PipelineEvent::new(
                    PipelineEntityType::Block,
                    PipelineStatus::Validating,
                    block.hash(),
                )
                .into(),
            ))
            .collect()
    }
}

/// When Kura receives `ValidBlock`, the block is stored and
/// then sent to later stage of the pipeline as `CommitedBlock`.
#[derive(Clone, Debug, Io, Encode, Decode)]
pub struct CommittedBlock {
    /// Header
    pub header: BlockHeader,
    /// Array of rejected transactions.
    pub rejected_transactions: Vec<RejectedTransaction>,
    /// array of transactions, which successfully passed validation and consensus step.
    pub transactions: Vec<ValidTransaction>,
    /// Signatures of peers which approved this block
    pub signatures: Signatures,
}

impl CommittedBlock {
    /// Calculate hash of the current block.
    /// `CommitedBlock` should have the same hash as `ValidBlock`.
    pub fn hash(&self) -> Hash {
        self.header.hash()
    }
}

impl From<&CommittedBlock> for Vec<Event> {
    fn from(block: &CommittedBlock) -> Self {
        block
            .transactions
            .iter()
            .cloned()
            .map(|transaction| {
                PipelineEvent::new(
                    PipelineEntityType::Transaction,
                    PipelineStatus::Committed,
                    transaction.hash(),
                )
                .into()
            })
            .chain(
                block
                    .rejected_transactions
                    .iter()
                    .cloned()
                    .map(|transaction| {
                        PipelineEvent::new(
                            PipelineEntityType::Transaction,
                            PipelineStatus::Rejected(transaction.rejection_reason.clone()),
                            transaction.hash(),
                        )
                        .into()
                    }),
            )
            .chain(
                block
                    .header
                    .invalidated_blocks_hashes
                    .iter()
                    .cloned()
                    .map(|hash| {
                        PipelineEvent::new(
                            PipelineEntityType::Block,
                            //TODO: store rejection reasons for blocks?
                            PipelineStatus::Rejected(
                                "Block was rejected during consensus.".to_string(),
                            ),
                            hash,
                        )
                        .into()
                    }),
            )
            .chain(iter::once(
                PipelineEvent::new(
                    PipelineEntityType::Block,
                    PipelineStatus::Committed,
                    block.hash(),
                )
                .into(),
            ))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use crate::block::{BlockHeader, ValidBlock};
    use iroha_crypto::{Hash, Signatures};

    #[test]
    pub fn committed_and_valid_block_hashes_are_equal() {
        let valid_block = ValidBlock {
            header: BlockHeader {
                timestamp: 0,
                height: 0,
                previous_block_hash: Hash([0u8; 32]),
                transactions_merkle_root_hash: Hash([0u8; 32]),
                rejected_transactions_merkle_root_hash: Hash([0u8; 32]),
                number_of_view_changes: 0,
                invalidated_blocks_hashes: Vec::new(),
                genesis_topology: None,
            },
            rejected_transactions: vec![],
            transactions: vec![],
            signatures: Signatures::default(),
        };
        let commited_block = valid_block.clone().commit();
        assert_eq!(valid_block.hash(), commited_block.hash())
    }
}
