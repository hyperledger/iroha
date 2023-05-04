//! This module contains [`Block`] structures for each state, it's
//! transitions, implementations and related traits
//! implementations. [`Block`]s are organised into a linear sequence
//! over time (also known as the block chain).  A Block's life-cycle
//! starts from [`PendingBlock`].
#![allow(
    clippy::module_name_repetitions,
    clippy::std_instead_of_core,
    clippy::std_instead_of_alloc,
    clippy::arithmetic_side_effects
)]

use std::error::Error;

use eyre::{bail, eyre, Context, Result};
use iroha_config::sumeragi::default::DEFAULT_CONSENSUS_ESTIMATION_MS;
use iroha_crypto::{HashOf, KeyPair, MerkleTree, SignatureOf, SignaturesOf};
use iroha_data_model::{block::*, events::prelude::*, transaction::prelude::*};
use parity_scale_codec::{Decode, Encode};

use crate::{
    prelude::*,
    sumeragi::network_topology::{Role, Topology},
    tx::TransactionValidator,
};

/// Transaction data is permanently recorded in chunks called
/// blocks.
#[derive(Debug, Clone, Decode, Encode)]
pub struct PendingBlock {
    /// Block header
    pub header: BlockHeader,
    /// Array of rejected transactions.
    pub rejected_transactions: Vec<VersionedRejectedTransaction>,
    /// Array of transactions, which successfully passed validation and consensus step.
    pub transactions: Vec<VersionedValidTransaction>,
    /// Event recommendations.
    pub event_recommendations: Vec<Event>,
    /// Signatures of peers which approved this block
    pub signatures: SignaturesOf<Self>,
}

/// Builder for `PendingBlock`
pub struct BlockBuilder<'a> {
    /// Block's transactions.
    pub transactions: Vec<VersionedAcceptedTransaction>,
    /// Block's event recommendations.
    pub event_recommendations: Vec<Event>,
    /// The height of the block.
    pub height: u64,
    /// The hash of the previous block if there is one.
    pub previous_block_hash: Option<HashOf<VersionedCommittedBlock>>,
    /// The view change index this block was committed with. Produced by consensus.
    pub view_change_index: u64,
    /// The topology thihs block was committed with. Produced by consensus.
    pub committed_with_topology: Topology,
    /// The keypair used to sign this block.
    pub key_pair: KeyPair,
    /// The transaction validator to be used when validating the block.
    pub transaction_validator: &'a TransactionValidator,
    /// The world state to be used when validating the block.
    pub wsv: WorldStateView,
}

impl BlockBuilder<'_> {
    /// Create a new [`PendingBlock`] from transactions.
    pub fn build(self) -> PendingBlock {
        let timestamp = crate::current_time().as_millis();
        // TODO: Need to check if the `transactions` vector is empty. It shouldn't be allowed.

        let mut header = BlockHeader {
            timestamp,
            consensus_estimation: DEFAULT_CONSENSUS_ESTIMATION_MS,
            height: self.height,
            view_change_index: self.view_change_index,
            previous_block_hash: self.previous_block_hash,
            transactions_hash: None,
            rejected_transactions_hash: None,
            committed_with_topology: self.committed_with_topology.sorted_peers,
        };

        let mut txs = Vec::new();
        let mut rejected = Vec::new();

        for tx in self.transactions {
            match self
                .transaction_validator
                .validate(tx.into_v1(), header.is_genesis(), &self.wsv)
            {
                Ok(tx) => txs.push(tx),
                Err(tx) => {
                    iroha_logger::warn!(
                        reason = %tx.as_v1().rejection_reason,
                        caused_by = ?tx.as_v1().rejection_reason.source(),
                        "Transaction validation failed",
                    );
                    rejected.push(tx)
                }
            }
        }
        header.transactions_hash = txs
            .iter()
            .map(VersionedValidTransaction::hash)
            .collect::<MerkleTree<_>>()
            .hash();
        header.rejected_transactions_hash = rejected
            .iter()
            .map(VersionedRejectedTransaction::hash)
            .collect::<MerkleTree<_>>()
            .hash();
        // TODO: Validate Event recommendations somehow?

        let signature = SignatureOf::from_hash(self.key_pair, &HashOf::new(&header).transmute())
            .expect("Signing of new block failed.");
        let signatures = SignaturesOf::from(signature);

        PendingBlock {
            header,
            rejected_transactions: rejected,
            transactions: txs,
            event_recommendations: self.event_recommendations,
            signatures,
        }
    }
}

impl PendingBlock {
    /// Calculate the hash of the current block.
    pub fn hash(&self) -> HashOf<Self> {
        HashOf::new(&self.header).transmute()
    }

    /// Return signatures that are verified with the `hash` of this block,
    /// removing all other signatures.
    #[inline]
    pub fn retain_verified_signatures(&mut self) -> impl Iterator<Item = &SignatureOf<Self>> {
        self.signatures.retain_verified_by_hash(self.hash())
    }

    /// Commit block to the store.
    /// When calling this function, the user is responsible for the validity of the block signatures.
    /// Preference should be given to [`Self::commit`], where signature verification is built in.
    #[inline]
    pub fn commit_unchecked(self) -> CommittedBlock {
        let Self {
            header,
            rejected_transactions,
            transactions,
            event_recommendations,
            signatures,
        } = self;

        CommittedBlock {
            event_recommendations,
            header,
            rejected_transactions,
            transactions,
            signatures: signatures.transmute(),
        }
    }

    /// Verify signatures and commit block to the store.
    ///
    /// # Errors
    ///
    /// Not enough signatures
    #[inline]
    pub fn commit(mut self, topology: &Topology) -> Result<CommittedBlock, (Self, eyre::Report)> {
        let verified_signatures = self.retain_verified_signatures();

        if topology
            .filter_signatures_by_roles(
                &[
                    Role::ValidatingPeer,
                    Role::Leader,
                    Role::ProxyTail,
                    Role::ObservingPeer,
                ],
                verified_signatures,
            )
            .len()
            .lt(&topology.min_votes_for_commit())
        {
            return Err((
                self,
                eyre!("The block doesn't have enough valid signatures to be committed."),
            ));
        }

        Ok(self.commit_unchecked())
    }

    /// Add additional signatures for [`SignedBlock`].
    ///
    /// # Errors
    /// Fails if signature generation fails
    pub fn sign(mut self, key_pair: KeyPair) -> Result<Self> {
        SignatureOf::from_hash(key_pair, &self.hash())
            .wrap_err(format!("Failed to sign block with hash {}", self.hash()))
            .map(|signature| {
                self.signatures.insert(signature);
                self
            })
    }

    /// Add additional signature for [`SignedBlock`]
    ///
    /// # Errors
    /// Fails if given signature doesn't match block hash
    pub fn add_signature(&mut self, signature: SignatureOf<Self>) -> Result<()> {
        signature
            .verify_hash(&self.hash())
            .map(|_| {
                self.signatures.insert(signature);
            })
            .wrap_err(format!(
                "Provided signature doesn't match block with hash {}",
                self.hash()
            ))
    }

    /// Create dummy [`ValidBlock`]. Used in tests
    ///
    /// # Panics
    /// If generating keys or block signing fails.
    #[allow(clippy::restriction)]
    #[cfg(test)]
    pub fn new_dummy() -> Self {
        let timestamp = crate::current_time().as_millis();

        let header = BlockHeader {
            timestamp,
            consensus_estimation: DEFAULT_CONSENSUS_ESTIMATION_MS,
            height: 1,
            view_change_index: 0,
            previous_block_hash: None,
            transactions_hash: None,
            rejected_transactions_hash: None,
            committed_with_topology: Vec::new(),
        };

        let key_pair = KeyPair::generate().unwrap();
        let signature = SignatureOf::from_hash(key_pair, &HashOf::new(&header).transmute())
            .expect("Signing of new block failed.");
        let signatures = SignaturesOf::from(signature);

        Self {
            header,
            rejected_transactions: Vec::new(),
            transactions: Vec::new(),
            event_recommendations: Vec::new(),
            signatures,
        }
    }
}

/// This trait represents the ability to revalidate a block. Should be
/// implemented for both `PendingBlock` and `VersionedCommittedBlock`.
pub trait Revalidate: Sized {
    /// # Errors
    /// - When the block is deemed invalid.
    fn revalidate<const IS_GENESIS: bool>(
        &self,
        transaction_validator: &TransactionValidator,
        wsv: WorldStateView,
        latest_block: Option<HashOf<VersionedCommittedBlock>>,
        block_height: u64,
    ) -> Result<(), eyre::Report>;

    /// Return whether or not the block contains transactions already committed.
    fn has_committed_transactions(&self, wsv: &WorldStateView) -> bool;
}

impl Revalidate for PendingBlock {
    /// Revalidate a block against the current state of the world.
    ///
    /// # Errors
    /// - Block is empty
    /// - Block has committed transactions
    /// - There is a mismatch between candidate block height and actual blockchain height
    /// - There is a mismatch between candidate block previous block hash and actual latest block hash
    /// - Block header transaction hashes don't match with computed transaction hashes
    /// - Error during revalidation of individual transactions
    #[allow(clippy::too_many_lines)]
    fn revalidate<const IS_GENESIS: bool>(
        &self,
        transaction_validator: &TransactionValidator,
        wsv: WorldStateView,
        latest_block: Option<HashOf<VersionedCommittedBlock>>,
        block_height: u64,
    ) -> Result<(), eyre::Report> {
        if self.transactions.is_empty() && self.rejected_transactions.is_empty() {
            bail!("Block is empty");
        }

        if self.has_committed_transactions(&wsv) {
            bail!("Block has committed transactions");
        }

        if latest_block != self.header.previous_block_hash {
            bail!(
                    "Mismatch between the actual and expected hashes of the latest block. Expected: {:?}, actual: {:?}",
                    latest_block,
                    &self.header.previous_block_hash
                );
        }

        if block_height + 1 != self.header.height {
            bail!(
                    "Mismatch between the actual and expected heights of the block. Expected: {}, actual: {}",
                    block_height + 1,
                    self.header.height
                );
        }

        // Validate that header transactions hashes are matched with actual hashes
        self.transactions
                .iter()
                .map(VersionedValidTransaction::hash)
                .collect::<MerkleTree<_>>()
                .hash()
                .eq(&self.header.transactions_hash)
                .then_some(())
                .ok_or_else(|| {
                    eyre!("The transaction hash stored in the block header does not match the actual transaction hash.")
                })?;

        self.rejected_transactions
                .iter()
                .map(VersionedRejectedTransaction::hash)
                .collect::<MerkleTree<_>>()
                .hash()
                .eq(&self.header.rejected_transactions_hash)
                .then_some(())
                .ok_or_else(|| eyre!("The hash of a rejected transaction stored in the block header does not match the actual hash or this transaction."))?;

        // Check that valid transactions are still valid
        let _transactions = self
            .transactions
            .iter()
            .cloned()
            .map(VersionedValidTransaction::into_v1)
            .map(|tx_v| {
                let tx = SignedTransaction {
                    payload: tx_v.payload,
                    signatures: tx_v.signatures.into(),
                };
                AcceptedTransaction::accept::<IS_GENESIS>(
                    tx,
                    &transaction_validator.transaction_limits,
                )
                .wrap_err("Failed to accept transaction")
            })
            .map(|accepted_tx| {
                accepted_tx.and_then(|tx| {
                    transaction_validator
                        .validate(tx, self.header.is_genesis(), &wsv)
                        .map_err(|rejected_tx| rejected_tx.into_v1().rejection_reason)
                        .wrap_err("Failed to validate transaction")
                })
            })
            .try_fold(Vec::new(), |mut acc, tx| {
                tx.map(|valid_tx| {
                    acc.push(valid_tx);
                    acc
                })
            })
            .wrap_err("Error during transaction revalidation")?;

        // Check that rejected transactions are indeed rejected
        let _rejected_transactions = self
            .rejected_transactions
            .iter()
            .cloned()
            .map(VersionedRejectedTransaction::into_v1)
            .map(|tx_r| {
                let tx = SignedTransaction {
                    payload: tx_r.payload,
                    signatures: tx_r.signatures.into(),
                };
                AcceptedTransaction::accept::<IS_GENESIS>(
                    tx,
                    &transaction_validator.transaction_limits,
                )
                .wrap_err("Failed to accept transaction")
            })
            .map(|accepted_tx| {
                accepted_tx.and_then(|tx| {
                    match transaction_validator.validate(tx, self.header.is_genesis(), &wsv) {
                        Err(rejected_transaction) => Ok(rejected_transaction),
                        Ok(_) => Err(eyre!("Transactions which supposed to be rejected is valid")),
                    }
                })
            })
            .try_fold(Vec::new(), |mut acc, rejected_tx| {
                rejected_tx.map(|tx| {
                    acc.push(tx);
                    acc
                })
            })
            .wrap_err("Error during transaction revalidation")?;
        Ok(())
    }

    /// Check if a block has transactions that are already in the blockchain.
    fn has_committed_transactions(&self, wsv: &WorldStateView) -> bool {
        self.transactions
            .iter()
            .any(|transaction| transaction.is_in_blockchain(wsv))
            || self
                .rejected_transactions
                .iter()
                .any(|transaction| transaction.is_in_blockchain(wsv))
    }
}

impl Revalidate for VersionedCommittedBlock {
    /// Revalidate a block against the current state of the world.
    ///
    /// # Errors
    /// - Block is empty
    /// - Block has committed transactions
    /// - There is a mismatch between candidate block height and actual blockchain height
    /// - There is a mismatch between candidate block previous block hash and actual latest block hash
    /// - Block header transaction hashes don't match with computed transaction hashes
    /// - Error during revalidation of individual transactions
    #[allow(clippy::too_many_lines)]
    fn revalidate<const IS_GENESIS: bool>(
        &self,
        transaction_validator: &TransactionValidator,
        wsv: WorldStateView,
        latest_block: Option<HashOf<VersionedCommittedBlock>>,
        block_height: u64,
    ) -> Result<(), eyre::Report> {
        if self.has_committed_transactions(&wsv) {
            bail!("Block has committed transactions");
        }
        match self {
            VersionedCommittedBlock::V1(block) => {
                if block.transactions.is_empty() && block.rejected_transactions.is_empty() {
                    bail!("Block is empty");
                }

                if latest_block != block.header.previous_block_hash {
                    bail!(
                    "Mismatch between the actual and expected hashes of the latest block. Expected: {:?}, actual: {:?}",
                    latest_block,
                    &block.header.previous_block_hash
                );
                }

                if block_height + 1 != block.header.height {
                    bail!(
                    "Mismatch between the actual and expected heights of the block. Expected: {}, actual: {}",
                    block_height + 1,
                    block.header.height
                );
                }

                // Validate that header transactions hashes are matched with actual hashes
                block.transactions
                .iter()
                .map(VersionedValidTransaction::hash)
                .collect::<MerkleTree<_>>()
                .hash()
                .eq(&block.header.transactions_hash)
                .then_some(())
                .ok_or_else(|| {
                    eyre!("The transaction hash stored in the block header does not match the actual transaction hash.")
                })?;

                block.rejected_transactions
                .iter()
                .map(VersionedRejectedTransaction::hash)
                .collect::<MerkleTree<_>>()
                .hash()
                .eq(&block.header.rejected_transactions_hash)
                .then_some(())
                .ok_or_else(|| eyre!("The hash of a rejected transaction stored in the block header does not match the actual hash or this transaction."))?;

                // Check that valid transactions are still valid
                let _transactions = block
                    .transactions
                    .iter()
                    .cloned()
                    .map(VersionedValidTransaction::into_v1)
                    .map(|tx_v| {
                        let tx = SignedTransaction {
                            payload: tx_v.payload,
                            signatures: tx_v.signatures.into(),
                        };
                        AcceptedTransaction::accept::<IS_GENESIS>(
                            tx,
                            &transaction_validator.transaction_limits,
                        )
                        .wrap_err("Failed to accept transaction")
                    })
                    .map(|accepted_tx| {
                        accepted_tx.and_then(|tx| {
                            transaction_validator
                                .validate(tx, block.header.is_genesis(), &wsv)
                                .map_err(|rejected_tx| rejected_tx.into_v1().rejection_reason)
                                .wrap_err("Failed to validate transaction")
                        })
                    })
                    .try_fold(Vec::new(), |mut acc, tx| {
                        tx.map(|valid_tx| {
                            acc.push(valid_tx);
                            acc
                        })
                    })
                    .wrap_err("Error during transaction revalidation")?;

                // Check that rejected transactions are indeed rejected
                let _rejected_transactions = block
                    .rejected_transactions
                    .iter()
                    .cloned()
                    .map(VersionedRejectedTransaction::into_v1)
                    .map(|tx_r| {
                        let tx = SignedTransaction {
                            payload: tx_r.payload,
                            signatures: tx_r.signatures.into(),
                        };
                        AcceptedTransaction::accept::<IS_GENESIS>(
                            tx,
                            &transaction_validator.transaction_limits,
                        )
                        .wrap_err("Failed to accept transaction")
                    })
                    .map(|accepted_tx| {
                        accepted_tx.and_then(|tx| {
                            match transaction_validator.validate(
                                tx,
                                block.header.is_genesis(),
                                &wsv,
                            ) {
                                Err(rejected_transaction) => Ok(rejected_transaction),
                                Ok(_) => Err(eyre!(
                                    "Transactions which supposed to be rejected is valid"
                                )),
                            }
                        })
                    })
                    .try_fold(Vec::new(), |mut acc, rejected_tx| {
                        rejected_tx.map(|tx| {
                            acc.push(tx);
                            acc
                        })
                    })
                    .wrap_err("Error during transaction revalidation")?;

                Ok(())
            }
        }
    }

    /// Check if a block has transactions that are already in the blockchain.
    fn has_committed_transactions(&self, wsv: &WorldStateView) -> bool {
        match self {
            VersionedCommittedBlock::V1(block) => {
                block
                    .transactions
                    .iter()
                    .any(|transaction| transaction.is_in_blockchain(wsv))
                    || block
                        .rejected_transactions
                        .iter()
                        .any(|transaction| transaction.is_in_blockchain(wsv))
            }
        }
    }
}

impl From<&PendingBlock> for Vec<Event> {
    fn from(block: &PendingBlock) -> Self {
        block
            .transactions
            .iter()
            .map(|transaction| -> Event {
                PipelineEvent {
                    entity_kind: PipelineEntityKind::Transaction,
                    status: PipelineStatus::Validating,
                    hash: transaction.hash().into(),
                }
                .into()
            })
            .chain(block.rejected_transactions.iter().map(|transaction| {
                PipelineEvent {
                    entity_kind: PipelineEntityKind::Transaction,
                    status: PipelineStatus::Validating,
                    hash: transaction.hash().into(),
                }
                .into()
            }))
            .chain([PipelineEvent {
                entity_kind: PipelineEntityKind::Block,
                status: PipelineStatus::Validating,
                hash: block.hash().into(),
            }
            .into()])
            .collect()
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::restriction)]

    use std::str::FromStr;

    use iroha_data_model::prelude::*;

    use super::*;
    use crate::{kura::Kura, smartcontracts::isi::Registrable as _};

    #[test]
    pub fn committed_and_valid_block_hashes_are_equal() {
        let valid_block = PendingBlock::new_dummy();
        let committed_block = valid_block.clone().commit_unchecked();

        assert_eq!(valid_block.hash().transmute(), committed_block.hash())
    }

    #[test]
    fn should_reject_due_to_repetition() {
        // Predefined world state
        let alice_id = AccountId::from_str("alice@wonderland").expect("Valid");
        let alice_keys = KeyPair::generate().expect("Valid");
        let account = Account::new(alice_id.clone(), [alice_keys.public_key().clone()])
            .build(alice_id.clone());
        let domain_id = DomainId::from_str("wonderland").expect("Valid");
        let mut domain = Domain::new(domain_id).build(alice_id.clone());
        assert!(domain.add_account(account).is_none());
        let world = World::with([domain], Vec::new());
        let kura = Kura::blank_kura_for_testing();
        let wsv = WorldStateView::new(world, kura);

        // Creating an instruction
        let asset_definition_id = AssetDefinitionId::from_str("xor#wonderland").expect("Valid");
        let create_asset_definition: InstructionBox =
            RegisterBox::new(AssetDefinition::quantity(asset_definition_id)).into();

        // Making two transactions that have the same instruction
        let transaction_limits = TransactionLimits {
            max_instruction_number: 100,
            max_wasm_size_bytes: 0,
        };
        let transaction_validator = TransactionValidator::new(transaction_limits);
        let tx = TransactionBuilder::new(alice_id, [create_asset_definition], 4000)
            .sign(alice_keys.clone())
            .expect("Valid");
        let tx: VersionedAcceptedTransaction =
            AcceptedTransaction::accept::<false>(tx, &transaction_limits)
                .map(Into::into)
                .expect("Valid");

        // Creating a block of two identical transactions and validating it
        let transactions = vec![tx.clone(), tx];
        let valid_block = BlockBuilder {
            transactions,
            event_recommendations: Vec::new(),
            height: 1,
            previous_block_hash: None,
            view_change_index: 0,
            committed_with_topology: Topology::new(Vec::new()),
            key_pair: alice_keys,
            transaction_validator: &transaction_validator,
            wsv,
        }
        .build();

        // The first transaction should be confirmed
        assert_eq!(valid_block.transactions.len(), 1);

        // The second transaction should be rejected
        assert_eq!(valid_block.rejected_transactions.len(), 1);
    }
}
