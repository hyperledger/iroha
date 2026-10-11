//! Bounded transfer transcript measurement for optional local proof preparation.
//!
//! These input/resource checks grant no source finality or D7 authority. The sole D7
//! producer uses the original complete-effect journal, independently of this tape.

use std::collections::BTreeMap;

use fastpq_prover::gadgets::public_transfer_statement::PublicTransferLimits;
use iroha_crypto::Hash;
use iroha_data_model::fastpq::TransferTranscript;

#[cfg(test)]
use iroha_data_model::fastpq::{FastpqSourceExecutionKindV1, FastpqSourceRouteV1};
#[cfg(test)]
use iroha_model_base::topology::DataSpaceId;

#[cfg(test)]
use super::{
    FastpqPublicInputsTemplate, dataspace_id_bytes,
    quantity_statement_from_finalized_transcripts_for_testing,
};
#[cfg(test)]
use fastpq_prover::gadgets::public_transfer_statement::TransferSmtBuildLimits;
#[cfg(test)]
use iroha_data_model::fastpq::FastpqSourceStatementContextV1;
#[cfg(test)]
use std::collections::BTreeSet;

pub use iroha_data_model::fastpq::FastpqSourceExecutionEntryV1;

/// Explicit local construction bounds; these do not select a production admission profile.
#[derive(Debug, Clone, Copy)]
pub struct FastpqSourceStatementBuildLimits {
    /// Maximum complete execution-entry count, including entries with no transcripts.
    pub max_executed_entries: u32,
    /// Maximum cumulative number of transcript occurrences.
    pub max_transcripts: usize,
    /// Maximum cumulative number of transfer deltas.
    pub max_deltas: usize,
    /// Maximum cumulative canonical transcript bytes, including supplied private paths.
    pub max_input_transcript_bytes: usize,
    /// Maximum canonical frame bytes for one public statement.
    pub max_statement_bytes: usize,
    /// Maximum cumulative canonical public-statement frame bytes.
    pub max_total_statement_bytes: usize,
}

/// Validate complete archive shape and cumulative input limits before ownership hashing.
/// Counts complete canonical frames, including supplied private paths, without allocating
/// their output buffers. Serializer-internal scratch is separate from that frame allocation.
fn measure_fastpq_source_transcript_inputs(
    transcripts: &BTreeMap<Hash, Vec<TransferTranscript>>,
    limits: FastpqSourceStatementBuildLimits,
) -> Result<(usize, usize, usize), String> {
    measure_fastpq_source_bundle_inputs(
        transcripts
            .iter()
            .map(|(hash, bundle)| (hash, bundle.as_slice())),
        limits,
    )
}

/// Shared borrowed-bundle counting pass for archives and logical-entry reservations.
fn measure_fastpq_source_bundle_inputs<'a>(
    transcripts: impl IntoIterator<Item = (&'a Hash, &'a [TransferTranscript])>,
    limits: FastpqSourceStatementBuildLimits,
) -> Result<(usize, usize, usize), String> {
    u32::try_from(limits.max_transcripts)
        .map_err(|_| "FASTPQ source transcript limit exceeds u32".to_owned())?;
    let _canonical = norito::core::DecodeFlagsGuard::enter(norito::core::default_encode_flags());
    let mut transcript_count = 0usize;
    let mut delta_count = 0usize;
    let mut input_bytes_remaining = limits.max_input_transcript_bytes;
    for (entry_hash, bundle) in transcripts {
        if bundle.is_empty() {
            return Err("FASTPQ transcript bundle is empty".into());
        }
        transcript_count = transcript_count
            .checked_add(bundle.len())
            .filter(|count| *count <= limits.max_transcripts)
            .ok_or_else(|| "FASTPQ transcript occurrence limit exceeded".to_owned())?;
        for transcript in bundle {
            if transcript.batch_hash != *entry_hash || transcript.deltas.is_empty() {
                return Err(
                    "FASTPQ transcript call identity differs from its bundle or has no deltas"
                        .into(),
                );
            }
            delta_count = delta_count
                .checked_add(transcript.deltas.len())
                .filter(|count| *count <= limits.max_deltas)
                .ok_or_else(|| "FASTPQ transfer-delta limit exceeded".to_owned())?;
            // This is the same real counting pass used by `to_bytes_bounded`, including
            // canonical header/alignment bytes and checked framing arithmetic. The concrete
            // immutable transcript needs only its measured length here, not an output frame.
            let encoded_bytes = norito::core::encoded_frame_len(transcript)
                .map_err(norito::core::BoundedEncodeError::from)
                .and_then(|encoded_bytes| {
                    if encoded_bytes > input_bytes_remaining {
                        Err(norito::core::BoundedEncodeError::FrameTooLarge {
                            encoded_bytes,
                            max_bytes: input_bytes_remaining,
                        })
                    } else {
                        Ok(encoded_bytes)
                    }
                })
                .map_err(|error| {
                    format!(
                        "FASTPQ canonical input transcript exceeds construction budget: {error}"
                    )
                })?;
            input_bytes_remaining -= encoded_bytes;
        }
    }
    Ok((
        transcript_count,
        delta_count,
        limits.max_input_transcript_bytes - input_bytes_remaining,
    ))
}

/// Validate complete archive shape and input caps without allocating output frames.
pub(crate) fn preflight_fastpq_source_transcripts(
    transcripts: &BTreeMap<Hash, Vec<TransferTranscript>>,
    limits: FastpqSourceStatementBuildLimits,
) -> Result<usize, String> {
    measure_fastpq_source_transcript_inputs(transcripts, limits).map(|usage| usage.0)
}

mod budget;
pub(crate) use budget::FastpqSourceTranscriptUsage;
#[cfg(test)]
pub(crate) use budget::measure_fastpq_source_statement_usage;

fn source_statement_public_limits(
    limits: FastpqSourceStatementBuildLimits,
) -> Result<PublicTransferLimits, String> {
    let max_rows = limits
        .max_deltas
        .checked_mul(2)
        .ok_or_else(|| "FASTPQ source construction row limit overflows".to_owned())?;
    // Preparation counts bare public fields, while the final statement cap counts
    // its complete model frame. Keep a separate finite scratch envelope derived
    // from the caller's input/output caps; enforce exact output bytes below.
    let max_public_bytes = limits
        .max_input_transcript_bytes
        .checked_add(limits.max_statement_bytes)
        .and_then(|bytes| bytes.checked_mul(2))
        .ok_or_else(|| "FASTPQ source preparation byte limit overflows".to_owned())?;
    Ok(PublicTransferLimits {
        max_transcripts: limits.max_transcripts,
        max_deltas: limits.max_deltas,
        max_rows,
        max_public_bytes,
        max_unique_keys: max_rows,
        max_allocation_steps: max_rows
            .checked_mul(4)
            .ok_or_else(|| "FASTPQ source allocation limit overflows".to_owned())?,
    })
}

// Transfer-only preparation is retained solely as a local test diagnostic. Mandatory
// source D7 is produced from the complete ordered execution journal before native R.
#[cfg(test)]
mod transfer_diagnostic;
#[cfg(test)]
pub(crate) use transfer_diagnostic::{
    TransferArchiveDiagnostic, TransferEntryDiagnostic, prepare_transfer_archive_diagnostic,
};

#[cfg(test)]
mod tests;
