//! Selective Network input and output membership under a quorum-certified execution.
//!
//! A compact certificate authenticates the certified network-input and typed-output roots,
//! not the Iroha block header. This is the compact sibling of
//! [`crate::query::CommittedTransaction::verify_selective_in_authenticated_execution`]: it
//! binds one exact external entrypoint and its joined Network output to those certified
//! roots, without the uncertified header binding and without a block body.

use super::*;
use crate::{
    block::execution_output::{ExecutionOutputV1, NetworkExecutionOutputV1},
    transaction::{SignedTransaction, TransactionResult},
};
use iroha_crypto::MerkleProof;

/// Selective Network input/output membership under a QC-certified `ExecutionCommitment`.
///
/// Decoding is only a shape check. [`VerifiedSumeragiCommitV1::verify_external_execution`]
/// authenticates it under a certificate that an independently selected reader verified.
#[derive(
    Debug, Clone, PartialEq, Eq, Encode, Decode, iroha_schema::IntoSchema, norito::NoritoSchema,
)]
#[norito(deny_unknown_fields)]
#[norito_schema(name = "iroha_data_model::sumeragi_finality::CertifiedTransactionInclusionV1")]
pub struct CertifiedTransactionInclusionV1 {
    /// Membership of the exact entrypoint in the certified network-input tree.
    pub entry_proof: MerkleProof<TransactionEntrypoint>,
    /// The complete joined output row; only a Network row is admissible.
    pub output: ExecutionOutputV1,
    /// Membership of that complete row in the certified typed-output tree.
    pub output_proof: MerkleProof<ExecutionOutputV1>,
}

impl CertifiedTransactionInclusionV1 {
    /// Borrow the Network row whose input index equals both leaf indices.
    ///
    /// Network rows sit at the output position equal to their input index, so both leaf
    /// positions are bound locally. This is a DATA check; it grants no finality authority.
    ///
    /// # Errors
    /// A Pipeline or Time row, or a leaf index that differs from the row's input index.
    pub fn joined_network_output(&self) -> Result<&NetworkExecutionOutputV1, FinalityError> {
        let ExecutionOutputV1::Network(output) = &self.output else {
            return Err(FinalityError(
                "inclusion output is not a Network row".into(),
            ));
        };
        need(
            output.input_index == self.entry_proof.leaf_index(),
            "inclusion entry leaf differs from the output input index",
        )?;
        need(
            self.output_proof.leaf_index() == output.input_index,
            "inclusion output leaf differs from the output input index",
        )?;
        Ok(output)
    }
}

impl VerifiedSumeragiCommitV1 {
    /// Authenticate the exact external entrypoint's membership and its joined Network output.
    ///
    /// Returns the certified result: `Ok` is an applied transaction and `Err` its
    /// authenticated rejection. The caller owns the outcome predicate over the signed wire.
    /// Genesis is excluded by construction: only `SumeragiCommitVerifierV1::verify` builds
    /// this capability, for heights from two. A commitment with more leaves than a `u32`
    /// leaf index addresses fails its membership proof in `MerkleProof::verify`.
    ///
    /// # Errors
    /// A foreign network, an invalid signature, missing commitments, a non-Network or
    /// unjoined output, or a membership proof that differs.
    pub fn verify_external_execution<'a>(
        &self,
        network: &NetworkId,
        signed: &SignedTransaction,
        inclusion: &'a CertifiedTransactionInclusionV1,
    ) -> Result<&'a TransactionResult, FinalityError> {
        need(
            self.network == *network,
            "compact certificate network differs",
        )?;
        need(
            signed.network_id() == Some(network) && signed.verify_signature().is_ok(),
            "external entrypoint does not match the certified network",
        )?;
        let execution = self.execution();
        execution.validate().map_err(malformed)?;
        let (Some(inputs), Some(outputs)) = (
            execution.transaction_input_commitment,
            execution.transaction_output_commitment,
        ) else {
            return Err(FinalityError(
                "certified execution has no network inputs".into(),
            ));
        };
        let output = inclusion.joined_network_output()?;
        let entrypoint = signed.try_hash_as_entrypoint().map_err(malformed)?;
        need(
            inclusion.entry_proof.verify(&entrypoint, &inputs),
            "external entrypoint is not a certified network input",
        )?;
        let output_hash = HashOf::try_new(&inclusion.output).map_err(malformed)?;
        need(
            inclusion.output_proof.verify(&output_hash, &outputs),
            "joined output is not a certified execution output",
        )?;
        Ok(&output.result)
    }
}

#[cfg(test)]
mod tests;
