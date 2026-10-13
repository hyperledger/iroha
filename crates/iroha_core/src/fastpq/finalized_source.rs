//! Original complete-effect source custody joined to the actual certified native result.
//!
//! This owner exposes no submit operation or transfer-only artifact projection. It
//! preserves the exact D7/source/tape/allocation graph for the complete-effect backend.
//! TODO: promote that backend and retain this owner through durable artifact admission
//! before adding any finalized-source queue handoff.

use crate::{
    state::{AdmittedQuantityArchive, CapturedExecWitness, CapturedQuantityEntry},
    sumeragi::certified_chain::AuthenticatedExecutionBlock,
};
use iroha_allocation::AllocationBudget;
use iroha_data_model::fastpq::{
    FastpqOrdinarySourceStatementLeafV1, FastpqOrdinarySourceStatementManifestV1,
    FastpqSourceExecutionEntryV1,
};

/// Exact failed source join; no partially authenticated owner escapes.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub(crate) enum FinalizedFastpqSourceError {
    /// No native R preparation consumed this original captured witness.
    #[error("original FASTPQ witness has no native execution commitment")]
    MissingNativeResult,
    /// Authenticated block identity differs from the original completed source.
    #[error("FASTPQ source differs from the original authenticated native block")]
    BlockIdentity,
    /// Native R's complete execution preimage differs, including ordinary-write root.
    #[error("FASTPQ source differs from the original native execution result")]
    ExecutionResult,
    /// Offered witness changed or lost its retained mandatory D7 binding.
    #[error("FASTPQ source witness differs from its protected original")]
    WitnessContent,
    /// Bundle inventory differs from the certified wire's canonical complete map.
    #[error("FASTPQ transcript inventory differs from the certified native block")]
    TranscriptInventory,
    /// Any complete original transcript field differs from the certified block.
    #[error("FASTPQ transcript content differs from the certified native block")]
    TranscriptContent,
}

/// Move-only original captured source and actual certificate-backed native authority.
///
/// The native R builder calculated its ordinary root from this exact witness before
/// the certificate existed. Admission compares that fixed original commitment with
/// the authenticated result preimage and every original certified transcript field.
/// This comparison neither rebuilds a tree nor accepts a caller-supplied root.
/// The witness retains its original D7 write backing, mandatory source and optional
/// complete-effect archive. Optional archive refusal can prevent work selection but
/// cannot change certified bytes, coverage, block validity or source finality.
pub(crate) struct FinalizedFastpqSource {
    native: AuthenticatedExecutionBlock,
    witness: CapturedExecWitness,
}
impl FinalizedFastpqSource {
    /// Move both actual owners once. On failure both originals are returned unchanged.
    pub(crate) fn bind(
        witness: CapturedExecWitness,
        native: AuthenticatedExecutionBlock,
    ) -> Result<
        Self,
        (
            CapturedExecWitness,
            AuthenticatedExecutionBlock,
            FinalizedFastpqSourceError,
        ),
    > {
        if let Err(error) = witness.verify_finalized_source(&native) {
            return Err((witness, native, error));
        }
        Ok(Self { native, witness })
    }
    /// Consume the actual native owner and admit its immutable archive once.
    /// Every failure returns this same source; no job can pair another archive.
    pub(crate) fn into_work(
        self,
    ) -> Result<AdmittedFinalizedFastpqSource, (Self, FinalizedFastpqWorkError)> {
        if let Err(error) = self.verify_current() {
            return Err((self, error.into()));
        }
        let archive = match self.witness.admit_quantity_archive() {
            Ok(archive) => archive,
            Err(error) => return Err((self, FinalizedFastpqWorkError::Archive(error))),
        };
        Ok(AdmittedFinalizedFastpqSource {
            original: self,
            archive,
        })
    }
    /// Revalidate original custody without deriving a new tree or accepting expected truth.
    pub(crate) fn verify_current(&self) -> Result<(), FinalizedFastpqSourceError> {
        self.witness.verify_finalized_source(&self.native)
    }
    #[cfg(test)]
    pub(crate) fn offer_reconstructed_tamper_for_test(
        &mut self,
        mutate: impl FnOnce(&mut iroha_data_model::block::consensus::ExecWitness),
    ) {
        self.witness.offer_reconstructed_tamper_for_test(mutate);
    }
    #[cfg(test)]
    pub(crate) fn withhold_optional_archive_for_test(
        &mut self,
        issue: crate::state::QuantityCaptureIssue,
    ) {
        self.witness.withhold_optional_archive_for_test(issue);
    }
    #[cfg(test)]
    pub(crate) fn offered_wire_for_test(&self) -> &iroha_data_model::block::consensus::ExecWitness {
        self.witness.wire()
    }
    /// Exact authenticated R and original certified block, not a decoded authority DTO.
    pub(crate) fn native(&self) -> &AuthenticatedExecutionBlock {
        &self.native
    }
    /// Original bounded execution pool. A handle creates no new capacity or work admission.
    pub(crate) fn pool(&self) -> &AllocationBudget {
        self.witness.pool()
    }
    /// Complete mandatory D7 manifest carried by the authenticated ordinary write.
    #[cfg_attr(
        not(test),
        expect(
            dead_code,
            reason = "TODO: connect durable complete-effect artifact admission before dispatch; retain the authenticated original witness and its admitted archive"
        )
    )]
    pub(crate) fn manifest(&self) -> &FastpqOrdinarySourceStatementManifestV1 {
        self.witness.manifest()
    }
    /// Every original source position, including empty and rejected entries.
    #[cfg_attr(
        not(test),
        expect(
            dead_code,
            reason = "TODO: connect durable complete-effect artifact admission before dispatch; retain the authenticated original witness and its admitted archive"
        )
    )]
    pub(crate) fn entries(&self) -> &[FastpqSourceExecutionEntryV1] {
        self.witness.source_entries()
    }
    /// Every nonempty original complete-effect leaf in original source order.
    pub(crate) fn leaves(&self) -> &[FastpqOrdinarySourceStatementLeafV1] {
        self.witness.leaves()
    }
    /// Select the exact original borrowed tape, leaf and pool for complete-effect work.
    /// Caller-provided expected effects, routes, permission roots or transaction sets
    /// cannot replace these original fields. Physical work admission remains explicit.
    #[cfg_attr(
        not(test),
        expect(
            dead_code,
            reason = "TODO: connect durable complete-effect artifact admission before dispatch; retain the authenticated original witness and its admitted archive"
        )
    )]
    pub(crate) fn entry(
        &self,
        statement_index: usize,
    ) -> Result<CapturedQuantityEntry<'_>, crate::state::QuantityCaptureIssue> {
        self.witness.quantity_entry(statement_index)
    }
}

#[cfg(test)]
mod tests;

#[cfg(test)]
pub(crate) mod test_fixture;

/// A native source and its one-time admitted complete archive cannot be separated
/// or paired with another source. Only the consuming original join constructs it.
pub(crate) struct AdmittedFinalizedFastpqSource {
    original: FinalizedFastpqSource,
    archive: AdmittedQuantityArchive,
}
/// A rejected work admission returns the original native owner unchanged.
#[derive(Debug, thiserror::Error)]
pub(crate) enum FinalizedFastpqWorkError {
    #[error(transparent)]
    Native(#[from] FinalizedFastpqSourceError),
    #[error("original complete-effect archive unavailable: {0:?}")]
    Archive(crate::state::QuantityCaptureIssue),
}
impl AdmittedFinalizedFastpqSource {
    pub(crate) fn original(&self) -> &FinalizedFastpqSource {
        &self.original
    }
    pub(crate) fn native(&self) -> &AuthenticatedExecutionBlock {
        self.original.native()
    }
    #[cfg_attr(
        not(test),
        expect(
            dead_code,
            reason = "TODO: connect durable complete-effect artifact admission before dispatch; retain the authenticated original witness and its admitted archive"
        )
    )]
    pub(crate) fn pool(&self) -> &AllocationBudget {
        self.original.pool()
    }
    pub(crate) fn leaves(&self) -> &[FastpqOrdinarySourceStatementLeafV1] {
        self.original.leaves()
    }
    pub(crate) fn entry(
        &self,
        index: usize,
    ) -> Result<CapturedQuantityEntry<'_>, crate::state::QuantityCaptureIssue> {
        self.archive.entry(index)
    }
    #[cfg(test)]
    pub(crate) fn scan_counts_for_test() -> (usize, usize, usize, usize) {
        AdmittedQuantityArchive::scan_counts_for_test()
    }
    #[cfg(test)]
    pub(crate) fn verify_current(&self) -> Result<(), FinalizedFastpqSourceError> {
        self.original.verify_current()
    }
}
