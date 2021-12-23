//! This module contains Transaction related functionality of the Iroha.
//!
//! `Transaction` is the start of the Transaction lifecycle.

use std::{cmp::min, time::Duration};

use eyre::{Result, WrapErr};
use iroha_crypto::SignaturesOf;
pub use iroha_data_model::prelude::*;
use iroha_version::{declare_versioned_with_scale, version_with_scale};
use parity_scale_codec::{Decode, Encode};

use crate::{
    prelude::*,
    smartcontracts::{
        permissions::{self, IsInstructionAllowedBoxed, IsQueryAllowedBoxed},
        Evaluate, Execute, FindError,
    },
    wsv::WorldTrait,
};

declare_versioned_with_scale!(VersionedAcceptedTransaction 1..2, Debug, Clone, iroha_macro::FromVariant);

impl VersionedAcceptedTransaction {
    /// Converts from `&VersionedAcceptedTransaction` to V1 reference
    pub const fn as_v1(&self) -> &AcceptedTransaction {
        match self {
            VersionedAcceptedTransaction::V1(v1) => v1,
        }
    }

    /// Converts from `&mut VersionedAcceptedTransaction` to V1 mutable reference
    pub fn as_mut_v1(&mut self) -> &mut AcceptedTransaction {
        match self {
            VersionedAcceptedTransaction::V1(v1) => v1,
        }
    }

    /// Performs the conversion from `VersionedAcceptedTransaction` to V1
    pub fn into_v1(self) -> AcceptedTransaction {
        match self {
            VersionedAcceptedTransaction::V1(v1) => v1,
        }
    }

    /// Accepts transaction
    /// # Errors
    /// Can fail if verification of some signature fails
    pub fn from_transaction(
        transaction: Transaction,
        max_instruction_number: u64,
    ) -> Result<VersionedAcceptedTransaction> {
        AcceptedTransaction::from_transaction(transaction, max_instruction_number).map(Into::into)
    }

    /// Checks if this transaction is waiting longer than specified in
    /// `transaction_time_to_live` from `QueueConfiguration` or
    /// `time_to_live_ms` of this transaction.  Meaning that the
    /// transaction will be expired as soon as the lesser of the
    /// specified TTLs was reached.
    pub fn is_expired(&self, transaction_time_to_live: Duration) -> bool {
        self.as_v1().is_expired(transaction_time_to_live)
    }

    /// If `true`, this transaction is regarded as one that has been
    /// tampered with. This is common practice in e.g. `https`, where
    /// setting your system clock back in time will prevent you from
    /// accessing any of the https web-sites.
    pub fn is_in_future(&self, threshold: Duration) -> bool {
        self.as_v1().is_in_future(threshold)
    }

    /// Move transaction lifecycle forward by checking an ability to
    /// apply instructions to the `WorldStateView<W>`.
    ///
    /// # Errors
    /// Fails if validation of instruction fails (e.g. permissions mismatch).
    pub fn validate<W: WorldTrait>(
        self,
        wsv: &WorldStateView<W>,
        is_instruction_allowed: &IsInstructionAllowedBoxed<W>,
        is_query_allowed: &IsQueryAllowedBoxed<W>,
        is_genesis: bool,
    ) -> Result<VersionedValidTransaction, VersionedRejectedTransaction> {
        self.into_v1()
            .validate(wsv, is_instruction_allowed, is_query_allowed, is_genesis)
            .map(Into::into)
            .map_err(Into::into)
    }

    /// Checks that the signatures of this transaction satisfy the
    /// signature condition specified in the account.
    ///
    /// # Errors
    /// - if signature conditionon fails
    /// - if account is not found
    pub fn check_signature_condition<W: WorldTrait>(
        &self,
        wsv: &WorldStateView<W>,
    ) -> Result<bool> {
        self.as_v1().check_signature_condition(wsv)
    }
}

impl Txn for VersionedAcceptedTransaction {
    type HashOf = VersionedTransaction;

    #[inline]
    fn payload(&self) -> &Payload {
        &self.as_v1().payload
    }
}

/// `AcceptedTransaction` represents a transaction accepted by iroha peer.
#[version_with_scale(n = 1, versioned = "VersionedAcceptedTransaction")]
#[derive(Debug, Clone, Decode, Encode)]
#[non_exhaustive]
pub struct AcceptedTransaction {
    /// Payload of this transaction.
    pub payload: Payload,
    /// Signatures for this transaction.
    pub signatures: SignaturesOf<Payload>,
}

impl AcceptedTransaction {
    /// Accepts transaction
    ///
    /// # Errors
    /// Can fail if verification of some signature fails
    pub fn from_transaction(
        transaction: Transaction,
        max_instruction_number: u64,
    ) -> Result<AcceptedTransaction> {
        transaction
            .check_instruction_len(max_instruction_number)
            .wrap_err("Failed to accept transaction")?;
        let signatures = SignaturesOf::from_iter(&transaction.payload, transaction.signatures)
            .wrap_err("Failed to verify transaction signatures")?;

        Ok(Self {
            payload: transaction.payload,
            signatures,
        })
    }

    /// Checks if this transaction is waiting longer than specified in
    /// `transaction_time_to_live` from `QueueConfiguration` or
    /// `time_to_live_ms` of this transaction.  Meaning that the
    /// transaction will be expired as soon as the lesser of the
    /// specified TTLs was reached.
    pub fn is_expired(&self, transaction_time_to_live: Duration) -> bool {
        let tx_timestamp = Duration::from_millis(self.payload.creation_time);
        current_time().saturating_sub(tx_timestamp)
            > min(
                transaction_time_to_live,
                Duration::from_millis(self.payload.time_to_live_ms),
            )
    }

    /// If `true`, this transaction is regarded to have been tampered
    /// to have a future timestamp.
    pub fn is_in_future(&self, threshold: Duration) -> bool {
        let tx_timestamp = Duration::from_millis(self.payload.creation_time);
        tx_timestamp.saturating_sub(current_time()) > threshold
    }

    #[allow(clippy::unwrap_in_result)]
    #[allow(clippy::expect_used)]
    fn validate_internal<W: WorldTrait>(
        &self,
        wsv: &WorldStateView<W>,
        is_instruction_allowed: &IsInstructionAllowedBoxed<W>,
        is_query_allowed: &IsQueryAllowedBoxed<W>,
        is_genesis: bool,
    ) -> Result<(), TransactionRejectionReason> {
        let wsv_temp = wsv.clone();
        let account_id = self.payload.account_id.clone();
        if !is_genesis && account_id == <Account as Identifiable>::Id::genesis() {
            return Err(TransactionRejectionReason::UnexpectedGenesisAccountSignature);
        }

        self.signatures
            .verify(&self.payload)
            .map_err(TransactionRejectionReason::SignatureVerification)?;

        let option_reason = match self.check_signature_condition(wsv) {
            Ok(true) => None,
            Ok(false) => Some("Signature condition not satisfied.".to_owned()),
            Err(reason) => Some(reason.to_string()),
        }
        .map(|reason| UnsatisfiedSignatureConditionFail { reason })
        .map(TransactionRejectionReason::UnsatisfiedSignatureCondition);

        if let Some(reason) = option_reason {
            return Err(reason);
        }

        for instruction in &self.payload.instructions {
            instruction
                .clone()
                .execute(account_id.clone(), &wsv_temp)
                .map_err(|reason| InstructionExecutionFail {
                    instruction: instruction.clone(),
                    reason: reason.to_string(),
                })
                .map_err(TransactionRejectionReason::InstructionExecution)?;

            // Permission validation is skipped for genesis.
            if !is_genesis {
                #[cfg(feature = "roles")]
                {
                    let instructions = permissions::unpack_if_role_grant(instruction.clone(), wsv)
                        .expect(
                            "Infallible. Evaluations have been checked by instruction execution.",
                        );
                    for isi in &instructions {
                        is_instruction_allowed
                            .check(&account_id, isi, wsv)
                            .map_err(|reason| NotPermittedFail { reason })
                            .map_err(TransactionRejectionReason::NotPermitted)?;
                    }
                }
                #[cfg(not(feature = "roles"))]
                {
                    is_instruction_allowed
                        .check(&account_id, instruction, wsv)
                        .map_err(|reason| NotPermittedFail { reason })
                        .map_err(TransactionRejectionReason::NotPermitted)?;
                }
                permissions::check_query_in_instruction(
                    &account_id,
                    instruction,
                    wsv,
                    is_query_allowed,
                )
                .map_err(|reason| NotPermittedFail { reason })
                .map_err(TransactionRejectionReason::NotPermitted)?;
            }
        }

        Ok(())
    }

    /// Move transaction lifecycle forward by checking an ability to apply instructions to the
    /// `WorldStateView<W>`.
    ///
    /// # Errors
    /// Can fail if:
    /// - signature verification fails
    /// - instruction execution fails
    /// - permission check fails
    pub fn validate<W: WorldTrait>(
        self,
        wsv: &WorldStateView<W>,
        is_instruction_allowed: &IsInstructionAllowedBoxed<W>,
        is_query_allowed: &IsQueryAllowedBoxed<W>,
        is_genesis: bool,
    ) -> Result<ValidTransaction, RejectedTransaction> {
        match self.validate_internal(wsv, is_instruction_allowed, is_query_allowed, is_genesis) {
            Ok(()) => Ok(ValidTransaction {
                payload: self.payload,
                signatures: self.signatures,
            }),
            Err(reason) => Err(self.reject(reason)),
        }
    }

    /// Checks that the signatures of this transaction satisfy the signature condition specified in the account.
    ///
    /// # Errors
    /// Can fail if signature conditionon account fails or if account is not found
    pub fn check_signature_condition<W: WorldTrait>(
        &self,
        wsv: &WorldStateView<W>,
    ) -> Result<bool> {
        let account_id = self.payload.account_id.clone();
        wsv.map_account(&account_id, |account| {
            account
                .check_signature_condition(&self.signatures)
                .evaluate(wsv, &Context::new())
                .map_err(|_err| FindError::Account(account_id.clone()))
        })?
        .wrap_err("Failed to find the account")
    }

    /// Rejects transaction with the `rejection_reason`.
    pub fn reject(self, rejection_reason: TransactionRejectionReason) -> RejectedTransaction {
        RejectedTransaction {
            payload: self.payload,
            signatures: self.signatures,
            rejection_reason,
        }
    }
}
impl Txn for AcceptedTransaction {
    type HashOf = Transaction;

    #[inline]
    fn payload(&self) -> &Payload {
        &self.payload
    }
}

impl IsInBlockchain for VersionedAcceptedTransaction {
    #[inline]
    fn is_in_blockchain<W: WorldTrait>(&self, wsv: &WorldStateView<W>) -> bool {
        wsv.has_transaction(&self.hash())
    }
}
impl IsInBlockchain for VersionedValidTransaction {
    #[inline]
    fn is_in_blockchain<W: WorldTrait>(&self, wsv: &WorldStateView<W>) -> bool {
        wsv.has_transaction(&self.hash())
    }
}
impl IsInBlockchain for VersionedRejectedTransaction {
    #[inline]
    fn is_in_blockchain<W: WorldTrait>(&self, wsv: &WorldStateView<W>) -> bool {
        wsv.has_transaction(&self.hash())
    }
}

impl From<VersionedAcceptedTransaction> for VersionedTransaction {
    fn from(tx: VersionedAcceptedTransaction) -> Self {
        let tx: AcceptedTransaction = tx.into_v1();
        let tx: Transaction = tx.into();
        tx.into()
    }
}

impl From<AcceptedTransaction> for Transaction {
    fn from(transaction: AcceptedTransaction) -> Self {
        Transaction {
            payload: transaction.payload,
            signatures: transaction.signatures.into_iter().collect(),
        }
    }
}

impl From<VersionedValidTransaction> for VersionedAcceptedTransaction {
    fn from(tx: VersionedValidTransaction) -> Self {
        let tx: ValidTransaction = tx.into_v1();
        let tx: AcceptedTransaction = tx.into();
        tx.into()
    }
}

impl From<ValidTransaction> for AcceptedTransaction {
    fn from(transaction: ValidTransaction) -> Self {
        AcceptedTransaction {
            payload: transaction.payload,
            signatures: transaction.signatures,
        }
    }
}

impl From<VersionedRejectedTransaction> for VersionedAcceptedTransaction {
    fn from(tx: VersionedRejectedTransaction) -> Self {
        let tx: RejectedTransaction = tx.into_v1();
        let tx: AcceptedTransaction = tx.into();
        tx.into()
    }
}

impl From<RejectedTransaction> for AcceptedTransaction {
    fn from(transaction: RejectedTransaction) -> Self {
        AcceptedTransaction {
            payload: transaction.payload,
            signatures: transaction.signatures,
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::pedantic, clippy::restriction)]

    use std::collections::BTreeSet;

    use eyre::Result;
    use iroha_data_model::{
        account::GENESIS_ACCOUNT_NAME, domain::GENESIS_DOMAIN_NAME,
        transaction::DEFAULT_MAX_INSTRUCTION_NUMBER,
    };

    use super::*;
    use crate::{
        init,
        samples::{get_config, get_trusted_peers},
        smartcontracts::permissions::AllowAll,
        wsv::World,
    };

    #[test]
    fn hash_should_be_the_same() {
        let key_pair = &KeyPair::generate().expect("Failed to generate key pair.");
        let mut config = get_config(
            get_trusted_peers(Some(&key_pair.public_key)),
            Some(key_pair.clone()),
        );
        config.genesis.account_private_key = Some(key_pair.private_key.clone());
        config.genesis.account_public_key = Some(key_pair.public_key.clone());

        let tx = Transaction::new(
            vec![],
            AccountId::test(GENESIS_ACCOUNT_NAME, GENESIS_DOMAIN_NAME),
            1000,
        );
        let tx_hash = tx.hash();

        let signed_tx = tx.sign(key_pair).expect("Failed to sign.");
        let signed_tx_hash = signed_tx.hash();
        let accepted_tx =
            AcceptedTransaction::from_transaction(signed_tx, 4096).expect("Failed to accept.");
        let accepted_tx_hash = accepted_tx.hash();
        let valid_tx_hash = accepted_tx
            .validate(
                &WorldStateView::new(World::with(
                    init::domains(&config).unwrap(),
                    BTreeSet::new(),
                )),
                &AllowAll.into(),
                &AllowAll.into(),
                true,
            )
            .expect("Failed to validate.")
            .hash();
        assert_eq!(tx_hash, signed_tx_hash);
        assert_eq!(tx_hash, accepted_tx_hash);
        assert_eq!(tx_hash, valid_tx_hash);
    }

    #[test]
    fn transaction_not_accepted() {
        let inst = FailBox {
            message: "Will fail".to_owned(),
        };
        let tx = Transaction::new(
            vec![inst.into(); DEFAULT_MAX_INSTRUCTION_NUMBER as usize + 1],
            AccountId::test("root", "global"),
            1000,
        );
        let result: Result<AcceptedTransaction> = AcceptedTransaction::from_transaction(tx, 4096);
        assert!(result.is_err());

        let err = result.unwrap_err();
        let mut chain = err.chain();
        assert_eq!(
            chain.next().unwrap().to_string(),
            "Failed to accept transaction"
        );
        assert_eq!(
            chain.next().unwrap().to_string(),
            "Too many instructions in payload"
        );
    }
}
