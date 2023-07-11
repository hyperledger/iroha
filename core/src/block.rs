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

use iroha_config::sumeragi::default::DEFAULT_CONSENSUS_ESTIMATION_MS;
use iroha_crypto::{HashOf, KeyPair, MerkleTree, SignatureOf, SignaturesOf};
use iroha_data_model::{
    block::*,
    events::prelude::*,
    peer::PeerId,
    transaction::{error::TransactionRejectionReason, prelude::*},
};
use iroha_genesis::GenesisTransaction;
use parity_scale_codec::{Decode, Encode};
use sealed::sealed;
use thiserror::Error;

use crate::{
    prelude::*,
    sumeragi::network_topology::{SignatureVerificationError, Topology},
    tx::{AcceptTransactionFail, TransactionValidator},
};

/// Errors occurred on block commit
#[derive(Debug, Error, displaydoc::Display, Clone, Copy)]
pub enum BlockCommitError {
    /// Error during signature verification
    SignatureVerificationError(#[from] SignatureVerificationError),
}

/// Errors occurred on signing block or adding additional signature
#[derive(Debug, Error, displaydoc::Display)]
pub enum BlockSignError {
    /// Failed to create signature
    Sign(#[source] iroha_crypto::error::Error),
    /// Failed to add signature for block
    AddSignature(#[source] iroha_crypto::error::Error),
}

/// Errors occurred on block revalidation
#[derive(Debug, Error, displaydoc::Display)]
pub enum BlockRevalidationError {
    /// Block is empty
    Empty,
    /// Block has committed transactions
    HasCommittedTransactions,
    /// Mismatch between the actual and expected hashes of the latest block. Expected: {expected:?}, actual: {actual:?}
    LatestBlockHashMismatch {
        /// Expected value
        expected: Option<HashOf<VersionedCommittedBlock>>,
        /// Actual value
        actual: Option<HashOf<VersionedCommittedBlock>>,
    },
    /// Mismatch between the actual and expected height of the latest block. Expected: {expected}, actual: {actual}
    LatestBlockHeightMismatch {
        /// Expected value
        expected: u64,
        /// Actual value
        actual: u64,
    },
    /// The transaction hash stored in the block header does not match the actual transaction hash
    TransactionHashMismatch,
    /// The hash of a rejected transaction stored in the block header does not match the actual hash or this transaction
    RejectedTransactionHashMismatch,
    /// Error during transaction revalidation
    TransactionRevalidation(#[from] TransactionRevalidationError),
    /// Mismatch between the actual and expected topology. Expected: {expected:?}, actual: {actual:?}
    TopologyMismatch {
        /// Expected value
        expected: Vec<PeerId>,
        /// Actual value
        actual: Vec<PeerId>,
    },
    /// Error during block signatures check
    SignatureVerification(#[from] SignatureVerificationError),
    /// Received view change index is too large
    ViewChangeIndexTooLarge,
}

/// Error during transaction revalidation
#[derive(Debug, Error, displaydoc::Display)]
pub enum TransactionRevalidationError {
    /// Failed to accept transaction
    Accept(#[from] AcceptTransactionFail),
    /// Transaction isn't valid but must be
    NotValid(#[from] TransactionRejectionReason),
    /// Rejected transaction in valid
    RejectedIsValid,
}

/// Transaction data is permanently recorded in chunks called
/// blocks.
#[derive(Debug, Clone, Decode, Encode)]
pub struct PendingBlock {
    /// Block header
    pub header: BlockHeader,
    /// Array of transactions.
    pub transactions: Vec<TransactionValue>,
    /// Event recommendations.
    pub event_recommendations: Vec<Event>,
    /// Signatures of peers which approved this block
    pub signatures: SignaturesOf<Self>,
}

/// Builder for `PendingBlock`
pub struct BlockBuilder<'world> {
    /// Block's transactions.
    pub transactions: Vec<AcceptedTransaction>,
    /// Block's event recommendations.
    pub event_recommendations: Vec<Event>,
    /// The view change index this block was committed with. Produced by consensus.
    pub view_change_index: u64,
    /// The topology thihs block was committed with. Produced by consensus.
    pub committed_with_topology: Topology,
    /// The keypair used to sign this block.
    pub key_pair: KeyPair,
    /// The world state to be used when validating the block.
    pub wsv: &'world mut WorldStateView,
}

impl BlockBuilder<'_> {
    /// Create a new [`PendingBlock`] from transactions.
    pub fn build(self) -> PendingBlock {
        let timestamp = crate::current_time().as_millis();
        let height = self.wsv.height() + 1;
        let previous_block_hash = self.wsv.latest_block_hash();
        let transaction_validator = self.wsv.transaction_validator();
        // TODO: Need to check if the `transactions` vector is empty. It shouldn't be allowed.

        let mut header = BlockHeader {
            timestamp,
            consensus_estimation: DEFAULT_CONSENSUS_ESTIMATION_MS,
            height,
            view_change_index: self.view_change_index,
            previous_block_hash,
            transactions_hash: None,
            rejected_transactions_hash: None,
            committed_with_topology: self.committed_with_topology.sorted_peers,
        };

        let mut txs = Vec::new();

        for tx in self.transactions {
            match transaction_validator.validate(tx, height == 1, self.wsv) {
                Ok(transaction) => txs.push(TransactionValue {
                    tx: transaction,
                    error: None,
                }),
                Err((transaction, error)) => {
                    iroha_logger::warn!(
                        reason = %error,
                        caused_by = ?error.source(),
                        "Transaction validation failed",
                    );
                    txs.push(TransactionValue {
                        tx: transaction,
                        error: Some(error),
                    });
                }
            }
        }
        header.transactions_hash = txs
            .iter()
            .filter(|tx| tx.error.is_none())
            .map(|tx| tx.tx.hash())
            .collect::<MerkleTree<_>>()
            .hash();
        header.rejected_transactions_hash = txs
            .iter()
            .filter(|tx| tx.error.is_some())
            .map(|tx| tx.tx.hash())
            .collect::<MerkleTree<_>>()
            .hash();
        // TODO: Validate Event recommendations somehow?

        let signature = SignatureOf::from_hash(
            self.key_pair,
            HashOf::from_untyped_unchecked(Hash::new(header.payload())),
        )
        .expect("Signing of new block failed.");
        let signatures = SignaturesOf::from(signature);

        PendingBlock {
            header,
            transactions: txs,
            event_recommendations: self.event_recommendations,
            signatures,
        }
    }
}

impl PendingBlock {
    const fn is_genesis(&self) -> bool {
        self.header.height == 1
    }

    /// Calculate the partial hash of the current block.
    pub fn partial_hash(&self) -> HashOf<Self> {
        HashOf::from_untyped_unchecked(Hash::new(self.header.payload()))
    }

    /// Return signatures that are verified with the `hash` of this block,
    /// removing all other signatures.
    #[inline]
    pub fn retain_verified_signatures(&mut self) -> impl Iterator<Item = &SignatureOf<Self>> {
        self.signatures.retain_verified_by_hash(self.partial_hash())
    }

    /// Commit block to the store.
    /// When calling this function, the user is responsible for the validity of the block signatures.
    /// Preference should be given to [`Self::commit`], where signature verification is built in.
    #[inline]
    pub fn commit_unchecked(self) -> CommittedBlock {
        let Self {
            header,
            transactions,
            event_recommendations,
            signatures,
        } = self;

        CommittedBlock {
            event_recommendations,
            header,
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
    pub fn commit(
        mut self,
        topology: &Topology,
    ) -> Result<CommittedBlock, (Self, BlockCommitError)> {
        let hash = self.partial_hash();
        if let Err(err) = topology.verify_signatures(&mut self.signatures, hash) {
            return Err((self, err.into()));
        }

        Ok(self.commit_unchecked())
    }

    /// Add additional signatures for [`SignedBlock`].
    ///
    /// # Errors
    /// Fails if signature generation fails
    pub fn sign(mut self, key_pair: KeyPair) -> Result<Self, BlockSignError> {
        SignatureOf::from_hash(key_pair, self.partial_hash())
            .map(|signature| {
                self.signatures.insert(signature);
                self
            })
            .map_err(BlockSignError::Sign)
    }

    /// Add additional signature for [`SignedBlock`]
    ///
    /// # Errors
    /// Fails if given signature doesn't match block hash
    pub fn add_signature(&mut self, signature: SignatureOf<Self>) -> Result<(), BlockSignError> {
        signature
            .verify_hash(self.partial_hash())
            .map(|_| {
                self.signatures.insert(signature);
            })
            .map_err(BlockSignError::AddSignature)
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
        let signature = SignatureOf::from_hash(key_pair, HashOf::new(&header).transmute())
            .expect("Signing of new block failed.");
        let signatures = SignaturesOf::from(signature);

        Self {
            header,
            transactions: Vec::new(),
            event_recommendations: Vec::new(),
            signatures,
        }
    }
}

/// This sealed trait represents the ability to revalidate a block. Should be
/// implemented for both [`PendingBlock`] and [`VersionedCommittedBlock`].
/// Public users should only use this trait's extensions [`InGenesis`] and
/// [`InBlock`].
#[sealed]
pub trait Revalidate: Sized {
    /// # Errors
    /// - When the block is deemed invalid.
    fn revalidate(&self, wsv: &mut WorldStateView) -> Result<(), BlockRevalidationError>;

    /// Return whether or not the block contains transactions already committed.
    fn has_committed_transactions(&self, wsv: &WorldStateView) -> bool;
}

#[sealed]
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
    fn revalidate(&self, wsv: &mut WorldStateView) -> Result<(), BlockRevalidationError> {
        let latest_block_hash = wsv.latest_block_hash();
        let block_height = wsv.height();
        let transaction_validator = wsv.transaction_validator();

        if self.transactions.is_empty() {
            return Err(BlockRevalidationError::Empty);
        }

        if self.has_committed_transactions(wsv) {
            return Err(BlockRevalidationError::HasCommittedTransactions);
        }

        if latest_block_hash != self.header.previous_block_hash {
            return Err(BlockRevalidationError::LatestBlockHashMismatch {
                expected: latest_block_hash,
                actual: self.header.previous_block_hash,
            });
        }

        if block_height + 1 != self.header.height {
            return Err(BlockRevalidationError::LatestBlockHeightMismatch {
                expected: block_height + 1,
                actual: self.header.height,
            });
        }

        revalidate_hashes(
            &self.transactions,
            self.header.transactions_hash,
            self.header.rejected_transactions_hash,
        )?;

        revalidate_transactions(
            &self.transactions,
            wsv,
            transaction_validator,
            self.is_genesis(),
        )?;

        Ok(())
    }

    /// Check if a block has transactions that are already in the blockchain.
    fn has_committed_transactions(&self, wsv: &WorldStateView) -> bool {
        self.transactions
            .iter()
            .any(|tx| wsv.has_transaction(tx.tx.hash()))
    }
}

#[sealed]
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
    fn revalidate(&self, wsv: &mut WorldStateView) -> Result<(), BlockRevalidationError> {
        let latest_block_hash = wsv.latest_block_hash();
        let block_height = wsv.height();
        let transaction_validator = wsv.transaction_validator();
        let is_genesis = block_height == 0;

        if self.has_committed_transactions(wsv) {
            return Err(BlockRevalidationError::HasCommittedTransactions);
        }

        match self {
            VersionedCommittedBlock::V1(block) => {
                if block.transactions.is_empty() {
                    return Err(BlockRevalidationError::Empty);
                }

                if latest_block_hash != block.header.previous_block_hash {
                    return Err(BlockRevalidationError::LatestBlockHashMismatch {
                        expected: latest_block_hash,
                        actual: block.header.previous_block_hash,
                    });
                }

                if block_height + 1 != block.header.height {
                    return Err(BlockRevalidationError::LatestBlockHeightMismatch {
                        expected: block_height + 1,
                        actual: block.header.height,
                    });
                }

                if !is_genesis {
                    // Recrate topology with witch block must be committed at given view change index
                    // And then verify committed_with_topology field and block signatures
                    let topology = {
                        let last_committed_block = wsv
                            .latest_block_ref()
                            .expect("Not in genesis round so must have at least genesis block");
                        let new_peers = wsv.peers_ids().iter().cloned().collect();
                        let view_change_index = block
                            .header
                            .view_change_index
                            .try_into()
                            .map_err(|_| BlockRevalidationError::ViewChangeIndexTooLarge)?;
                        Topology::recreate_topology(
                            &last_committed_block,
                            view_change_index,
                            new_peers,
                        )
                    };

                    if topology.sorted_peers != block.header.committed_with_topology {
                        return Err(BlockRevalidationError::TopologyMismatch {
                            expected: topology.sorted_peers,
                            actual: block.header.committed_with_topology.clone(),
                        });
                    }

                    topology.verify_signatures(
                        &mut block.signatures.clone(),
                        HashOf::from_untyped_unchecked(block.partial_hash().internal),
                    )?;
                }

                revalidate_hashes(
                    &block.transactions,
                    block.header.transactions_hash,
                    block.header.rejected_transactions_hash,
                )?;

                revalidate_transactions(
                    &block.transactions,
                    wsv,
                    transaction_validator,
                    block.is_genesis(),
                )?;

                Ok(())
            }
        }
    }

    /// Check if a block has transactions that are already in the blockchain.
    fn has_committed_transactions(&self, wsv: &WorldStateView) -> bool {
        match self {
            VersionedCommittedBlock::V1(block) => block
                .transactions
                .iter()
                .any(|tx| wsv.has_transaction(tx.tx.hash())),
        }
    }
}

/// Revalidate merkle tree root hashes of the transaction
fn revalidate_hashes(
    transactions: &[TransactionValue],
    transactions_hash: Option<HashOf<MerkleTree<VersionedSignedTransaction>>>,
    rejected_transactions_hash: Option<HashOf<MerkleTree<VersionedSignedTransaction>>>,
) -> Result<(), BlockRevalidationError> {
    // Validate that header transactions hashes are matched with actual hashes
    transactions
        .iter()
        .filter(|tx| tx.error.is_none())
        .map(|tx| tx.tx.hash())
        .collect::<MerkleTree<_>>()
        .hash()
        .eq(&transactions_hash)
        .then_some(())
        .ok_or_else(|| BlockRevalidationError::TransactionHashMismatch)?;

    transactions
        .iter()
        .filter(|tx| tx.error.is_some())
        .map(|tx| tx.tx.hash())
        .collect::<MerkleTree<_>>()
        .hash()
        .eq(&rejected_transactions_hash)
        .then_some(())
        .ok_or_else(|| BlockRevalidationError::RejectedTransactionHashMismatch)?;
    Ok(())
}

/// Revalidate transactions to ensure that valid transactions indeed valid and invalid are still invalid
fn revalidate_transactions(
    transactions: &[TransactionValue],
    wsv: &mut WorldStateView,
    transaction_validator: TransactionValidator,
    is_genesis: bool,
) -> Result<(), TransactionRevalidationError> {
    // Check that valid transactions are still valid
    for tx in transactions.iter().cloned() {
        if tx.error.is_some() {
            let _rejected_tx = if is_genesis {
                Ok(AcceptedTransaction::accept_genesis(GenesisTransaction(
                    tx.tx,
                )))
            } else {
                AcceptedTransaction::accept(tx.tx, &transaction_validator.transaction_limits)
            }
            .map_err(TransactionRevalidationError::Accept)
            .and_then(|tx| {
                match transaction_validator.validate(tx, is_genesis, wsv) {
                    Err(rejected_transaction) => Ok(rejected_transaction),
                    Ok(_) => Err(TransactionRevalidationError::RejectedIsValid),
                }
            })?;
        } else {
            let tx = if is_genesis {
                Ok(AcceptedTransaction::accept_genesis(GenesisTransaction(
                    tx.tx,
                )))
            } else {
                AcceptedTransaction::accept(tx.tx, &transaction_validator.transaction_limits)
            }
            .map_err(TransactionRevalidationError::Accept)?;

            transaction_validator
                .validate(tx, is_genesis, wsv)
                .map_err(|(_tx, error)| error)
                .map_err(TransactionRevalidationError::NotValid)?;
        }
    }

    Ok(())
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
                    hash: transaction.payload().hash().into(),
                }
                .into()
            })
            .chain([PipelineEvent {
                entity_kind: PipelineEntityKind::Block,
                status: PipelineStatus::Validating,
                hash: block.partial_hash().into(),
            }
            .into()])
            .collect()
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::restriction)]

    use std::str::FromStr as _;

    use iroha_data_model::prelude::*;

    use super::*;
    use crate::{kura::Kura, smartcontracts::isi::Registrable as _};

    #[test]
    pub fn committed_and_valid_block_hashes_are_equal() {
        let valid_block = PendingBlock::new_dummy();
        let committed_block = valid_block.clone().commit_unchecked();

        assert_eq!(
            *valid_block.partial_hash(),
            committed_block.partial_hash().internal
        )
    }

    #[test]
    fn should_reject_due_to_repetition() {
        // Predefined world state
        let alice_id = AccountId::from_str("alice@wonderland").expect("Valid");
        let alice_keys = KeyPair::generate().expect("Valid");
        let account =
            Account::new(alice_id.clone(), [alice_keys.public_key().clone()]).build(&alice_id);
        let domain_id = DomainId::from_str("wonderland").expect("Valid");
        let mut domain = Domain::new(domain_id).build(&alice_id);
        assert!(domain.add_account(account).is_none());
        let world = World::with([domain], Vec::new());
        let kura = Kura::blank_kura_for_testing();
        let mut wsv = WorldStateView::new(world, kura);

        // Creating an instruction
        let asset_definition_id = AssetDefinitionId::from_str("xor#wonderland").expect("Valid");
        let create_asset_definition =
            RegisterBox::new(AssetDefinition::quantity(asset_definition_id));

        // Making two transactions that have the same instruction
        let transaction_limits = &wsv.transaction_validator().transaction_limits;
        let tx = TransactionBuilder::new(alice_id)
            .with_instructions([create_asset_definition])
            .sign(alice_keys.clone())
            .expect("Valid");
        let tx = AcceptedTransaction::accept(tx, transaction_limits).expect("Valid");

        // Creating a block of two identical transactions and validating it
        let transactions = vec![tx.clone(), tx];
        let valid_block = BlockBuilder {
            transactions,
            event_recommendations: Vec::new(),
            view_change_index: 0,
            committed_with_topology: Topology::new(Vec::new()),
            key_pair: alice_keys,
            wsv: &mut wsv,
        }
        .build();

        // The first transaction should be confirmed
        assert!(valid_block.transactions[0].error.is_none());

        // The second transaction should be rejected
        assert!(valid_block.transactions[1].error.is_some());
    }

    #[test]
    fn tx_order_same_in_validation_and_revalidation() {
        // Predefined world state
        let alice_id = AccountId::from_str("alice@wonderland").expect("Valid");
        let alice_keys = KeyPair::generate().expect("Valid");
        let account =
            Account::new(alice_id.clone(), [alice_keys.public_key().clone()]).build(&alice_id);
        let domain_id = DomainId::from_str("wonderland").expect("Valid");
        let mut domain = Domain::new(domain_id).build(&alice_id);
        assert!(domain.add_account(account).is_none());
        let world = World::with([domain], Vec::new());
        let kura = Kura::blank_kura_for_testing();
        let mut wsv = WorldStateView::new(world, kura);

        // Creating an instruction
        let asset_definition_id = AssetDefinitionId::from_str("xor#wonderland").expect("Valid");
        let create_asset_definition =
            RegisterBox::new(AssetDefinition::quantity(asset_definition_id.clone()));

        // Making two transactions that have the same instruction
        let transaction_limits = &wsv.transaction_validator().transaction_limits;
        let tx = TransactionBuilder::new(alice_id.clone())
            .with_instructions([create_asset_definition])
            .sign(alice_keys.clone())
            .expect("Valid");
        let tx = AcceptedTransaction::accept(tx, transaction_limits).expect("Valid");

        let quantity: u32 = 200;
        let fail_quantity: u32 = 20;

        let fail_mint = MintBox::new(
            fail_quantity.to_value(),
            IdBox::AssetId(AssetId::new(asset_definition_id.clone(), alice_id.clone())),
        );

        let succeed_mint = MintBox::new(
            quantity.to_value(),
            IdBox::AssetId(AssetId::new(asset_definition_id, alice_id.clone())),
        );

        let tx0 = TransactionBuilder::new(alice_id.clone())
            .with_instructions([fail_mint])
            .sign(alice_keys.clone())
            .expect("Valid");
        let tx0 = AcceptedTransaction::accept(tx0, transaction_limits).expect("Valid");

        let tx2 = TransactionBuilder::new(alice_id)
            .with_instructions([succeed_mint])
            .sign(alice_keys.clone())
            .expect("Valid");
        let tx2 = AcceptedTransaction::accept(tx2, transaction_limits).expect("Valid");

        // Creating a block of two identical transactions and validating it
        let transactions = vec![tx0, tx, tx2];
        let valid_block = BlockBuilder {
            transactions,
            event_recommendations: Vec::new(),
            view_change_index: 0,
            committed_with_topology: Topology::new(Vec::new()),
            key_pair: alice_keys,
            wsv: &mut wsv.clone(),
        }
        .build();

        // The first transaction should fail
        assert!(valid_block.transactions[0].error.is_some());

        // The third transaction should succeed
        assert!(valid_block.transactions[2].error.is_none());

        valid_block.revalidate(&mut wsv).unwrap();
    }

    #[test]
    fn failed_transactions_revert() {
        // Predefined world state
        let alice_id = AccountId::from_str("alice@wonderland").expect("Valid");
        let alice_keys = KeyPair::generate().expect("Valid");
        let account =
            Account::new(alice_id.clone(), [alice_keys.public_key().clone()]).build(&alice_id);
        let domain_id = DomainId::from_str("wonderland").expect("Valid");
        let mut domain = Domain::new(domain_id).build(&alice_id);
        assert!(
            domain.add_account(account).is_none(),
            "`alice@wonderland` already exist in the blockchain"
        );
        let world = World::with([domain], Vec::new());
        let kura = Kura::blank_kura_for_testing();
        let mut wsv = WorldStateView::new(world, kura);
        let transaction_limits = &wsv.transaction_validator().transaction_limits;

        let domain_id = DomainId::from_str("domain").expect("Valid");
        let create_domain = RegisterBox::new(Domain::new(domain_id));
        let asset_definition_id = AssetDefinitionId::from_str("coin#domain").expect("Valid");
        let create_asset = RegisterBox::new(AssetDefinition::quantity(asset_definition_id));
        let instructions_fail: [InstructionBox; 2] = [
            create_domain.clone().into(),
            FailBox::new("Always fail").into(),
        ];
        let instructions_accept: [InstructionBox; 2] = [create_domain.into(), create_asset.into()];
        let tx_fail = TransactionBuilder::new(alice_id.clone())
            .with_instructions(instructions_fail)
            .sign(alice_keys.clone())
            .expect("Valid");
        let tx_fail = AcceptedTransaction::accept(tx_fail, transaction_limits).expect("Valid");
        let tx_accept = TransactionBuilder::new(alice_id)
            .with_instructions(instructions_accept)
            .sign(alice_keys.clone())
            .expect("Valid");
        let tx_accept = AcceptedTransaction::accept(tx_accept, transaction_limits).expect("Valid");

        // Creating a block of where first transaction must fail and second one fully executed
        let transactions = vec![tx_fail, tx_accept];
        let valid_block = BlockBuilder {
            transactions,
            event_recommendations: Vec::new(),
            view_change_index: 0,
            committed_with_topology: Topology::new(Vec::new()),
            key_pair: alice_keys,
            wsv: &mut wsv,
        }
        .build();

        // The first transaction should be rejected
        assert!(
            valid_block.transactions[0].error.is_some(),
            "The first transaction should be rejected, as it contains `FailBox`."
        );

        // The second transaction should be accepted
        assert!(
            valid_block.transactions[1].error.is_none(),
            "The second transaction should be accepted."
        );
    }
}
