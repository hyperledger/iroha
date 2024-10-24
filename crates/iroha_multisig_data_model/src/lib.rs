//! Arguments attached on executing triggers for multisig accounts or transactions

#![no_std]

extern crate alloc;

use alloc::{collections::btree_map::BTreeMap, format, string::String, vec::Vec};

use iroha_data_model::prelude::*;
use iroha_schema::IntoSchema;
use parity_scale_codec::{Decode, Encode};
use serde::{Deserialize, Serialize};

/// Arguments to register multisig account
#[derive(Debug, Clone, Decode, Encode, Serialize, Deserialize, IntoSchema)]
pub struct MultisigAccountArgs {
    /// Multisig account to be registered
    /// <div class="warning">
    ///
    /// Any corresponding private key allows the owner to manipulate this account as a ordinary personal account
    ///
    /// </div>
    // FIXME #5022 prevent multisig monopoly
    pub account: PublicKey,
    /// List of accounts and their relative weights of responsibility for the multisig
    pub signatories: BTreeMap<AccountId, Weight>,
    /// Threshold of total weight at which the multisig is considered authenticated
    pub quorum: u16,
    /// Multisig transaction time-to-live in milliseconds based on block timestamps. Defaults to [`DEFAULT_MULTISIG_TTL_MS`]
    pub transaction_ttl_ms: u64,
}

type Weight = u8;

/// Default multisig transaction time-to-live in milliseconds based on block timestamps
pub const DEFAULT_MULTISIG_TTL_MS: u64 = 60 * 60 * 1_000; // 1 hour

/// Arguments to propose or approve multisig transaction
#[derive(Debug, Clone, Decode, Encode, Serialize, Deserialize, IntoSchema)]
pub enum MultisigTransactionArgs {
    /// Propose instructions and initialize approvals with the proposer's one
    Propose(Vec<InstructionBox>),
    /// Approve certain instructions
    Approve(HashOf<Vec<InstructionBox>>),
}

impl From<MultisigAccountArgs> for Json {
    fn from(details: MultisigAccountArgs) -> Self {
        Json::new(details)
    }
}

impl TryFrom<&Json> for MultisigAccountArgs {
    type Error = serde_json::Error;

    fn try_from(payload: &Json) -> serde_json::Result<Self> {
        serde_json::from_str::<Self>(payload.as_ref())
    }
}

impl From<MultisigTransactionArgs> for Json {
    fn from(details: MultisigTransactionArgs) -> Self {
        Json::new(details)
    }
}

impl TryFrom<&Json> for MultisigTransactionArgs {
    type Error = serde_json::Error;

    fn try_from(payload: &Json) -> serde_json::Result<Self> {
        serde_json::from_str::<Self>(payload.as_ref())
    }
}
