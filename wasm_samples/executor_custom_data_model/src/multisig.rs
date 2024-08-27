//! Arguments attached on executing triggers for multisig accounts or transactions

use alloc::{collections::btree_map::BTreeMap, vec::Vec};

use iroha_data_model::prelude::*;
use serde::{Deserialize, Serialize};

/// Arguments to register multisig account
#[derive(Serialize, Deserialize)]
pub struct MultisigAccountArgs {
    /// Multisig account to be registered
    /// WARNING: any corresponding private key allows the owner to manipulate this account as a ordinary personal account
    pub account: PublicKey,
    /// List of accounts and their relative weights of responsibility for the multisig
    pub signatories: BTreeMap<AccountId, u8>,
    /// Threshold of total weight at which the multisig is considered authenticated
    pub quorum: u16,
    /// Multisig transaction time-to-live based on block timestamps. Defaults to [`DEFAULT_MULTISIG_TTL_SECS`]
    pub transaction_ttl_secs: Option<u32>,
}

// Default multisig transaction time-to-live based on block timestamps
pub const DEFAULT_MULTISIG_TTL_SECS: u32 = 60 * 60; // 1 hour

/// Arguments to propose or approve multisig transaction
#[derive(Serialize, Deserialize)]
pub enum MultisigTransactionArgs {
    /// Propose instructions and initialize approvals with the proposer's one
    Propose(Vec<InstructionBox>),
    /// Approve certain instructions
    Approve(HashOf<Vec<InstructionBox>>),
}
