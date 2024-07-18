//! Arguments to register and manage multisig account

use alloc::{collections::btree_set::BTreeSet, vec::Vec};

use iroha_data_model::{account::NewAccount, prelude::*};
use serde::{Deserialize, Serialize};

/// Arguments to multisig account register trigger
#[derive(Serialize, Deserialize)]
pub struct MultisigRegisterArgs {
    // Account id of multisig account should be manually checked to not have corresponding private key (or having master key is ok)
    pub account: NewAccount,
    // List of accounts responsible for handling multisig account
    pub signatories: BTreeSet<AccountId>,
}

/// Arguments to multisig account manager trigger
#[derive(Serialize, Deserialize)]
pub enum MultisigArgs {
    /// Accept instructions proposal and initialize votes with the proposer's one
    Instructions(Vec<InstructionBox>),
    /// Accept vote for certain instructions
    Vote(HashOf<Vec<InstructionBox>>),
}
