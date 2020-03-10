pub mod commands;

use std::fmt;

struct Peer {
    ip: String,
    isLeader: bool,
}

/// This module contains core `Kura` stuctures.

/// Transaction data is permanently recorded in files called blocks. Blocks are organized into
/// a linear sequence over time (also known as the block chain).
//TODO[@humb1t:RH2-8]: based on https://iroha.readthedocs.io/en/latest/concepts_architecture/glossary.html#block
//signatures placed outside of the payload - should we store them?
#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct Block {
    /// a number of blocks in the chain up to the block.
    pub height: u64,
    /// Unix time (in milliseconds) of block forming by a peer.
    pub timestamp: u64,
    /// array of transactions, which successfully passed validation and consensus step.
    pub transactions: Vec<Transaction>,
    /// hash of a previous block in the chain.
    //TODO[@humb1t:RH2-9]: what to do if this block first?
    pub previous_block_hash: Hash,
    /// rejected transactions hashes — array of transaction hashes, which did not pass stateful
    /// validation step; this field is optional.
    pub rejected_transactions_hashes: Option<Vec<Hash>>,
}

impl Block {
    pub fn hash(&self) -> Hash {
        //TODO[@humb1t:RH2-10]: calculate block hash.
        Hash {}
    }
}

impl std::convert::From<Block> for Vec<u8> {
    fn from(block: Block) -> Self {
        bincode::serialize(&block).expect("Failed to serialize block.")
    }
}

impl std::convert::From<Vec<u8>> for Block {
    fn from(bytes: Vec<u8>) -> Self {
        bincode::deserialize(&bytes).expect("Failed to deserialize block.")
    }
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
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

#[derive(Clone)]
pub struct Asset {
    /// identifier of asset, formatted as asset_name#domain_id
    pub id: String,
}

/// An ordered set of commands, which is applied to the ledger atomically.
#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct Transaction {
    /// An ordered set of commands.
    pub commands: Vec<Command>,
    /// Time of creation (unix time, in milliseconds).
    pub creation_time: u64,
    /// Account ID of transaction creator (username@domain).
    pub account_id: String,
    /// Quorum field (indicates required number of signatures).
    pub quorum: u32, //TODO: this will almost certainly change; accounts need conditional multisig based on some rules, not associated with a transaction
    pub signatures: Vec<Signature>,
}

impl fmt::Display for Transaction {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:}", self.account_id) //TODO: implement
    }
}

impl fmt::Debug for Transaction {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:}", self.account_id) //TODO: implement
    }
}

#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct Signature {}

/// A command is an intention to change the state of the network.
/// For example, in order to create a new role in Iroha you have to issue Create role command.
#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct Command {
    pub version: u8,
    pub command_type: u8,
    pub payload: Vec<u8>,
}

//TODO[@humb1t:RH2-16]: rename
pub enum Relation {
    /// Belongs to account with defined identification.
    /// For example we can fill a map of accounts to assets by this relation.
    BelongsTo(String),
    GoingTo(String),
    GoingFrom(String),
}

/// This trait should be implemented for commands with `account_id` field.
/// Marking your command with `impl` of this trait you provide an ability
/// to retrieve information about relation to an account.
//TODO[@humb1t:RH2-16]: name is very bad, should be renamed.
pub trait Accountability {
    fn relations(&self) -> Vec<Relation>;
}

impl Accountability for Command {
    //TODO: implement
    fn relations(&self) -> Vec<Relation> {
        use Relation::*;
        match &self.command_type {
            17 => {
                let command: commands::TransferAsset = self.payload.clone().into();
                vec![
                    GoingFrom(command.source_account_id.clone()),
                    GoingTo(command.destination_account_id.clone()),
                    BelongsTo(command.destination_account_id.clone()),
                ]
            }
            _ => Vec::new(),
        }
    }
}

pub trait Assetibility {
    fn assets(&self) -> Vec<String>;
}

impl Assetibility for Command {
    //TODO: implement
    fn assets(&self) -> Vec<String> {
        match &self.command_type {
            17 => {
                let command: commands::TransferAsset = self.payload.clone().into();
                vec![command.asset_id.clone()]
            }
            _ => Vec::new(),
        }
    }
}
