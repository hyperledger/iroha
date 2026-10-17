//! Direct ledger finality for one signed Activate or Unload attempt (§6.1).
//!
//! The envelope carries the inclusion block's original native certificate and the selective
//! membership of the exact external entrypoint and its joined Network output. Decoding is only
//! a shape check. The wallet verifies it on a private clone of the epoch reader that its
//! protected manifest selected, so an envelope never installs or advances epoch authority.

use super::{
    KagemushaWalletValidationErrorV1, WalletResult, decode_frame_v1, encode_frame_v1, invalid_v1,
    require_version_v1,
};
use crate::{
    block::execution_output::ExecutionOutputV1,
    parameter::ExecutionOutputPolicyV1,
    sumeragi_finality::{
        CertifiedTransactionInclusionV1, FinalityError, FinalityReadError,
        MAX_COMMIT_CERTIFICATE_BYTES_V1, SumeragiCommitCertificateV1, SumeragiCommitVerifierV1,
    },
    transaction::{SignedTransaction, TransactionEntrypoint},
};
use iroha_crypto::HashOf;
use iroha_schema::IntoSchema;
use norito::codec::{Decode, Encode};

#[cfg(test)]
#[path = "ledger_finality_tests.rs"]
mod ledger_finality_tests;

/// One complete output row under the genesis-fixed bootstrap output policy.
/// Core rejects post-genesis policy changes; a genesis that raises the row limit must raise
/// this bound in the same change.
#[allow(clippy::cast_possible_truncation)]
pub const KAGEMUSHA_WALLET_LEDGER_OUTPUT_MAX_BYTES_V1: usize =
    ExecutionOutputPolicyV1::bootstrap().max_output_bytes as usize;
/// Two audit paths of at most 32 siblings, their leaf indices, the entrypoint hash, the
/// version and canonical framing.
pub const KAGEMUSHA_WALLET_LEDGER_FINALITY_FRAMING_BYTES_V1: usize = 16 * 1024;
/// Complete ledger finality frame: one certificate, one complete output row and framing.
/// This bound is derived from the consensus limits, not measured: 1,327,104 bytes.
pub const KAGEMUSHA_WALLET_LEDGER_FINALITY_MAX_BYTES_V1: usize = MAX_COMMIT_CERTIFICATE_BYTES_V1
    + KAGEMUSHA_WALLET_LEDGER_OUTPUT_MAX_BYTES_V1
    + KAGEMUSHA_WALLET_LEDGER_FINALITY_FRAMING_BYTES_V1;

/// Original consensus evidence for the outcome of one signed Activate or Unload attempt.
/// There is no event: the certified transaction result is the outcome.
#[derive(Debug, Clone, PartialEq, Eq, Decode, Encode, IntoSchema, norito::NoritoSchema)]
#[norito(deny_unknown_fields)]
#[norito_schema(
    name = "iroha_data_model::kagemusha::kagemusha_wallet_v1::KagemushaWalletLedgerFinalityV1"
)]
pub struct KagemushaWalletLedgerFinalityV1 {
    /// First-release version, exactly one.
    pub version: u16,
    /// Entrypoint binding; the wallet recomputes it from its own retained signed wire.
    pub entrypoint_hash: HashOf<TransactionEntrypoint>,
    /// The inclusion block's original native certificate, without an epoch-history prefix.
    pub certificate: SumeragiCommitCertificateV1,
    /// Entry and joined-output membership in the certified execution roots.
    pub inclusion: CertifiedTransactionInclusionV1,
}

/// Outcome authenticated by [`KagemushaWalletLedgerFinalityV1::verify`].
/// There is no public constructor; decoding or projecting DATA never produces one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VerifiedKagemushaLedgerOutcomeV1 {
    entrypoint: [u8; 32],
    height: u64,
    commit_hash: [u8; 32],
    accepted: bool,
}

impl VerifiedKagemushaLedgerOutcomeV1 {
    /// Entrypoint hash recomputed from the caller's signed wire.
    #[must_use]
    pub const fn entrypoint(&self) -> [u8; 32] {
        self.entrypoint
    }

    /// Certified inclusion height.
    #[must_use]
    pub const fn height(&self) -> u64 {
        self.height
    }

    /// BLS-certified native consensus block identity; not the Iroha block-header hash.
    #[must_use]
    pub const fn commit_hash(&self) -> [u8; 32] {
        self.commit_hash
    }

    /// Whether the certified result applied the transaction; `false` is an authenticated
    /// rejection of this attempt only.
    #[must_use]
    pub const fn accepted(&self) -> bool {
        self.accepted
    }
}

/// Unauthenticated custody projection of a retained original. It is DATA, never authority.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LedgerFinalityBindingsV1 {
    /// Decoded header height.
    pub height: u64,
    /// Decoded `CommitQC` block identity; no signature is verified.
    pub qc_block_hash: [u8; 32],
    /// Whether the joined Network row carries an applied result.
    pub accepted: bool,
    /// Input index shared by the row, the entry leaf and the output leaf.
    pub input_index: u32,
}

impl KagemushaWalletLedgerFinalityV1 {
    /// Validate finite canonical data shape without granting finality authority.
    ///
    /// # Errors
    /// Rejects another version, an audit path over 32 siblings, a non-Network output,
    /// missing or oversized certificate components or an oversized frame.
    pub fn validate(&self) -> WalletResult<()> {
        require_version_v1("ledger_finality.version", self.version)?;
        if self.inclusion.entry_proof.audit_path().len() > 32
            || self.inclusion.output_proof.audit_path().len() > 32
        {
            return Err(invalid_v1("ledger_finality.inclusion.path"));
        }
        if !matches!(self.inclusion.output, ExecutionOutputV1::Network(_)) {
            return Err(invalid_v1("ledger_finality.inclusion.output"));
        }
        self.certificate
            .validate_shape()
            .map_err(|_| invalid_v1("ledger_finality.certificate"))?;
        // Count the canonical frame without allocating a copy of a megabyte-scale row.
        let actual = norito::canonical_frame_len(self)?;
        if actual > KAGEMUSHA_WALLET_LEDGER_FINALITY_MAX_BYTES_V1 {
            return Err(KagemushaWalletValidationErrorV1::EncodedSizeExceeded {
                actual,
                max: KAGEMUSHA_WALLET_LEDGER_FINALITY_MAX_BYTES_V1,
            });
        }
        Ok(())
    }

    /// Encode one validated complete canonical evidence frame.
    ///
    /// # Errors
    /// Rejects malformed fields, encoding errors or an oversized frame.
    pub fn to_canonical_bytes(&self) -> WalletResult<Vec<u8>> {
        self.validate()?;
        encode_frame_v1(self, KAGEMUSHA_WALLET_LEDGER_FINALITY_MAX_BYTES_V1)
    }

    /// Decode one bounded canonical evidence frame without granting finality authority.
    ///
    /// # Errors
    /// Rejects oversized, noncanonical or malformed evidence, including trailing bytes.
    pub fn decode_canonical(bytes: &[u8]) -> WalletResult<Self> {
        let evidence: Self = decode_frame_v1(bytes, KAGEMUSHA_WALLET_LEDGER_FINALITY_MAX_BYTES_V1)?;
        evidence.validate()?;
        Ok(evidence)
    }

    /// Unauthenticated `(epoch, height)` DATA selectors for epoch lookup and synchronization.
    /// They select already authenticated authority; they never grant it.
    ///
    /// # Errors
    /// Rejects missing, oversized or noncanonical native header data.
    pub fn selectors(&self) -> Result<(u64, u64), FinalityReadError> {
        Ok((self.certificate.epoch_id()?, self.certificate.height()?))
    }

    /// Unauthenticated recheck projection of a retained original: the decoded header height,
    /// the decoded `CommitQC` block hash, the joined row's outcome and the shared leaf index.
    /// No BLS signature is verified; callers compare it with their authenticated record.
    ///
    /// # Errors
    /// Rejects malformed certificate components, a non-Network row or a leaf index that
    /// differs from the row's input index.
    pub fn custody_bindings(&self) -> Result<LedgerFinalityBindingsV1, FinalityReadError> {
        let output = self.inclusion.joined_network_output()?;
        Ok(LedgerFinalityBindingsV1 {
            height: self.certificate.height()?,
            qc_block_hash: self.certificate.qc_block_hash()?.0,
            accepted: output.result.is_ok(),
            input_index: output.input_index,
        })
    }

    /// Verify direct finality of `signed` on a private clone of `selected`.
    ///
    /// `selected` is never mutated: a boundary successor certified by this envelope's
    /// certificate is discarded with the clone and is never trusted. The returned outcome
    /// is `accepted` only for a certified applied result; `false` is an authenticated
    /// rejection of this attempt only. Network and chain are bound by the certificate's
    /// consensus instance, which the reader derives from its signed genesis and chain label,
    /// and by the signed transaction's network; the global-scope check adds only the
    /// comparison with the caller's `chain` label.
    ///
    /// # Errors
    /// Malformed evidence, another entrypoint, a missing or substituted epoch authority,
    /// forged BLS, another network or chain, or membership that does not verify.
    pub fn verify(
        &self,
        selected: &SumeragiCommitVerifierV1,
        chain: &str,
        signed: &SignedTransaction,
    ) -> Result<VerifiedKagemushaLedgerOutcomeV1, FinalityReadError> {
        self.validate()
            .map_err(|error| FinalityError(error.to_string()))?;
        let entrypoint = signed
            .try_hash_as_entrypoint()
            .map_err(|error| FinalityError(error.to_string()))?;
        if entrypoint != self.entrypoint_hash {
            return Err(FinalityError("ledger finality entrypoint differs".into()).into());
        }
        let mut reader = selected.clone();
        let verified = reader.verify(&self.certificate)?;
        verified.verify_global_scope(reader.network(), chain)?;
        let result =
            verified.verify_external_execution(&reader.network(), signed, &self.inclusion)?;
        Ok(VerifiedKagemushaLedgerOutcomeV1 {
            entrypoint: *entrypoint.as_ref(),
            height: verified.height(),
            commit_hash: verified.core_hash().0,
            accepted: result.is_ok(),
        })
    }
}
