//! Exact source resource measurement before private touched-tree construction.
//!
//! Public statement usage is additive only across complete disjoint entry bundles.
//! Fragments of the same entry must be remeasured together: common asset scales,
//! repeated-key chronology and framing span their complete ordered transcripts.
//! Execution-entry scope is supplied separately because non-transfer entries count.
//! This seam does not reserve runtime quotas or authenticate that entry scope.

use super::FastpqSourceStatementBuildLimits;
#[cfg(test)]
use super::{
    BTreeMap, Hash, TransferTranscript, measure_fastpq_source_transcript_inputs,
    source_statement_public_limits,
};
#[cfg(test)]
use crate::fastpq::quantity_statement::quantity_statement_frame_len_from_finalized_transcripts;

/// Exact measured complete-bundle dimensions, independent of owned execution-entry scope.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct FastpqSourceTranscriptUsage {
    /// Whole original transcript occurrences, including identical repeated occurrences.
    pub transcripts: usize,
    /// Original transfer deltas; every occurrence retains both participant rows.
    pub deltas: usize,
    /// Complete canonical private-input frames, including supplied witness paths.
    pub input_transcript_bytes: usize,
    /// Largest complete canonical public statement frame among the entry bundles.
    pub max_statement_bytes: usize,
    /// Sum of complete canonical public statement frames, one per nonempty entry bundle.
    pub total_statement_bytes: usize,
}

impl FastpqSourceTranscriptUsage {
    /// Add measurements for disjoint complete entry bundles, never fragments of one entry.
    /// Callers must ensure entry identities do not overlap and separately derive the complete
    /// prospective E count, including entries without transcripts, from owned identities.
    /// A repeated entry must be remeasured as its complete ordered transcript slice.
    ///
    /// # Errors
    /// Rejects arithmetic overflow without mutating either usage value.
    #[cfg(test)]
    fn checked_add_disjoint_entries(self, other: Self) -> Result<Self, String> {
        let add = |left: usize, right: usize| {
            left.checked_add(right)
                .ok_or_else(|| "FASTPQ source usage overflows".to_owned())
        };
        Ok(Self {
            transcripts: add(self.transcripts, other.transcripts)?,
            deltas: add(self.deltas, other.deltas)?,
            input_transcript_bytes: add(self.input_transcript_bytes, other.input_transcript_bytes)?,
            max_statement_bytes: self.max_statement_bytes.max(other.max_statement_bytes),
            total_statement_bytes: add(self.total_statement_bytes, other.total_statement_bytes)?,
        })
    }

    /// Check every construction cap using the separately owned complete E count.
    /// This checks numerical usage; it does not establish identity disjointness or provenance.
    ///
    /// # Errors
    /// Rejects an unrepresentable transcript ceiling or any exceeded inclusive cap.
    pub(crate) fn check_limits(
        self,
        executed_entry_count: u32,
        limits: FastpqSourceStatementBuildLimits,
    ) -> Result<(), String> {
        u32::try_from(limits.max_transcripts)
            .map_err(|_| "FASTPQ source transcript limit exceeds u32".to_owned())?;
        if executed_entry_count > limits.max_executed_entries {
            return Err("FASTPQ executed-entry limit exceeded".into());
        }
        for (name, actual, maximum) in [
            (
                "transcript occurrence",
                self.transcripts,
                limits.max_transcripts,
            ),
            ("transfer-delta", self.deltas, limits.max_deltas),
            (
                "canonical input transcript bytes",
                self.input_transcript_bytes,
                limits.max_input_transcript_bytes,
            ),
            (
                "canonical individual statement bytes",
                self.max_statement_bytes,
                limits.max_statement_bytes,
            ),
            (
                "canonical total statement bytes",
                self.total_statement_bytes,
                limits.max_total_statement_bytes,
            ),
        ] {
            if actual > maximum {
                return Err(format!(
                    "FASTPQ {name} limit exceeded: {actual} > {maximum}"
                ));
            }
        }
        Ok(())
    }
}

/// Measure every canonical source dimension before constructing any private SMT.
///
/// The current manifest producer validates its complete execution-entry archive and
/// supplies E before calling this function. Future transaction reservations must derive
/// their prospective E from the owned archive, not from transcript-map keys or by
/// summing independently measured fragments. This function checks bundle shapes but
/// does not authenticate the supplied E or associate map keys with an execution archive.
///
/// Single-delta digests must already be finalized and correct; missing digests fail
/// instead of returning a size that could grow when `None` becomes `Some`. Original
/// private witness bytes count exactly while the public measurement ignores those paths.
/// Shared row construction and public preparation check original quantities, occurrence
/// order, repeated-key balances and digests without building private SMT nodes/paths.
/// Placeholder fixed-width context fields affect statement bytes, never their length;
/// no placeholder statement or root escapes this measurement API.
///
/// # Errors
/// Rejects malformed or non-finalized transcripts, public preparation failures, arithmetic
/// overflow, or any of the six explicit construction caps. Inputs are never mutated.
#[cfg(test)]
pub(crate) fn measure_fastpq_source_statement_usage(
    executed_entry_count: u32,
    transcripts: &BTreeMap<Hash, Vec<TransferTranscript>>,
    limits: FastpqSourceStatementBuildLimits,
) -> Result<FastpqSourceTranscriptUsage, String> {
    FastpqSourceTranscriptUsage::default().check_limits(executed_entry_count, limits)?;
    let (transcript_count, delta_count, input_bytes) =
        measure_fastpq_source_transcript_inputs(transcripts, limits)?;
    let mut usage = FastpqSourceTranscriptUsage {
        transcripts: transcript_count,
        deltas: delta_count,
        input_transcript_bytes: input_bytes,
        ..FastpqSourceTranscriptUsage::default()
    };
    let public_limits = source_statement_public_limits(limits)?;
    for (entry_hash, bundle) in transcripts {
        let bytes = quantity_statement_frame_len_from_finalized_transcripts(bundle, public_limits)
            .map_err(|error| {
                format!("FASTPQ source bundle {entry_hash} is not finalized: {error}")
            })?;
        usage = usage.checked_add_disjoint_entries(FastpqSourceTranscriptUsage {
            max_statement_bytes: bytes,
            total_statement_bytes: bytes,
            ..FastpqSourceTranscriptUsage::default()
        })?;
        usage.check_limits(executed_entry_count, limits)?;
    }
    Ok(usage)
}

#[cfg(test)]
mod tests;
