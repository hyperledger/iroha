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

impl From<MultisigRegisterArgs> for JsonValue {
    fn from(details: MultisigRegisterArgs) -> Self {
        JsonValue::new(details)
    }
}

impl TryFrom<&JsonValue> for MultisigRegisterArgs {
    type Error = serde_json::Error;

    fn try_from(payload: &JsonValue) -> serde_json::Result<Self> {
        serde_json::from_str::<Self>(payload.as_ref())
    }
}

impl From<MultisigArgs> for JsonValue {
    fn from(details: MultisigArgs) -> Self {
        JsonValue::new(details)
    }
}

impl TryFrom<&JsonValue> for MultisigArgs {
    type Error = serde_json::Error;

    fn try_from(payload: &JsonValue) -> serde_json::Result<Self> {
        serde_json::from_str::<Self>(payload.as_ref())
    }
}
