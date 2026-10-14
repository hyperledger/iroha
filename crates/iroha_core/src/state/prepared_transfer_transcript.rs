//! Prepare one exact local transcript occurrence before its movement is applied.

use super::*;

/// Already allocated transcript and the source facts observed at its preparation boundary.
/// This private value cannot be transported between transaction owners by a caller.
struct PreparedTransferOccurrence {
    transcript: TransferTranscript,
    capture: Result<
        crate::fastpq::FastpqCapturedTranscriptSource,
        crate::fastpq::FastpqSourceCaptureError,
    >,
}

impl StateTransaction<'_, '_> {
    fn refuse_fastpq_source_preparation(&mut self, error: String) {
        self.fastpq_source_quota.fail_preparation(error);
        *self.block_execution_output_plan =
            Some(output_capacity::ExecutionOutputPlanState::Poisoned);
    }

    #[cfg(test)]
    pub(crate) fn retail_fee_transcripts_for_test(&self) -> &[TransferTranscript] {
        &self.pending_transfer_transcripts
    }

    #[cfg(test)]
    pub(crate) fn retail_fee_source_kind_for_test(&self, hash: &Hash) -> bool {
        self.pending_fastpq_source_captures.sources().unwrap()[hash].is_protocol_purpose()
    }

    /// Capture native deductions before the next principal occurrence is prepared.
    /// Transaction deductions share their signed call identity; idle settlement binds
    /// its protocol purpose to the immutable fee receipt ID. These entries are created
    /// only by consensus fee collection, never from caller-supplied metadata.
    ///
    /// # Errors
    ///
    /// Source capture or quota reservation fails; the attempt is poisoned.
    pub(crate) fn flush_retail_fee_transfer_transcripts(&mut self) -> Result<(), Error> {
        for (authority, receipt_hash, delta) in
            core::mem::take(&mut self.world.retail_fee_pending_transcripts)
        {
            let purpose = self.tx_call_hash.unwrap_or(receipt_hash);
            let occurrence = self.prepare_transfer_occurrence(&authority, purpose, vec![delta]);
            if let Some(occurrence) = &occurrence {
                self.reserve_transfer_occurrence(occurrence)?;
            }
            self.stage_transfer_occurrence(occurrence);
        }
        Ok(())
    }

    /// Consume only the original idle sweep's exact receipt/delta custody.
    /// Failure leaves its State, source captures and quota journals disposable together.
    pub(crate) fn flush_retail_native_transfer_transcripts(
        &mut self,
        permit: crate::retail_fee::RetailNativeMaintenancePermit,
    ) -> Result<(), crate::execution_attempt::ExecutionAttemptError<String>> {
        let entries = match permit.into_entries(self) {
            Ok(entries) => entries,
            Err(error) => {
                if let crate::execution_attempt::ExecutionAttemptError::Rejected(message) = &error {
                    self.refuse_fastpq_source_preparation(message.clone());
                }
                return Err(error);
            }
        };
        #[cfg(not(all(test, sumeragi_core_mutation = "HC365")))]
        if let Err(error) = self.fastpq_source_quota.begin_retail_batch() {
            self.refuse_fastpq_source_preparation(error.clone());
            return Err(error.into());
        }
        for (authority, purpose, delta) in entries {
            #[cfg(not(all(test, sumeragi_core_mutation = "HC365")))]
            if let Err(error) = self.fastpq_source_quota.authorize_retail_receipt(purpose) {
                self.refuse_fastpq_source_preparation(error.clone());
                return Err(error.into());
            }
            let occurrence = self.prepare_transfer_occurrence(&authority, purpose, vec![delta]);
            if let Some(occurrence) = &occurrence {
                self.reserve_transfer_occurrence(occurrence)
                    .map_err(|error| error.to_string())?;
            }
            self.stage_transfer_occurrence(occurrence);
        }
        Ok(())
    }

    fn prepare_transfer_occurrence(
        &self,
        authority: &AccountId,
        batch_hash: Hash,
        deltas: Vec<TransferDeltaTranscript>,
    ) -> Option<PreparedTransferOccurrence> {
        if deltas.is_empty() {
            return None;
        }
        let authority_digest = crate::fastpq::authority_digest(authority);
        let poseidon_preimage_digest = match deltas.as_slice() {
            [delta] => Some(crate::fastpq::poseidon_preimage_digest(delta, &batch_hash)),
            _ => None,
        };
        Some(PreparedTransferOccurrence {
            transcript: TransferTranscript {
                batch_hash,
                deltas,
                authority_digest,
                poseidon_preimage_digest,
            },
            capture: self.capture_original_fastpq_transcript_source(batch_hash),
        })
    }

    fn reserve_transfer_occurrence(
        &mut self,
        occurrence: &PreparedTransferOccurrence,
    ) -> Result<(), Error> {
        let captured = match occurrence.capture.as_ref() {
            Ok(captured) => captured,
            Err(error) => {
                self.refuse_fastpq_source_preparation(error.to_string());
                return Err(Error::InvariantViolation(error.to_string().into()));
            }
        };
        if self.pending_transfer_transcripts.try_reserve(1).is_err() {
            let error = "host cannot retain FASTPQ pending transcript";
            self.refuse_fastpq_source_preparation(error.into());
            return Err(Error::InvariantViolation(error.into()));
        }
        let hash = occurrence.transcript.batch_hash;
        let bundle = self
            .fastpq_transcripts
            .get(&hash)
            .into_iter()
            .flatten()
            .chain(
                self.pending_transfer_transcripts
                    .iter()
                    .filter(|entry| entry.batch_hash == hash),
            )
            .chain(std::iter::once(&occurrence.transcript));
        let result =
            self.fastpq_source_quota
                .replace_entry(hash, captured.is_protocol_purpose(), bundle);
        if self.fastpq_source_quota.intrinsic_rejected().is_err() {
            *self.block_execution_output_plan =
                Some(output_capacity::ExecutionOutputPlanState::Poisoned);
        }
        result.map_err(|error| Error::InvariantViolation(error.into()))
    }

    fn stage_transfer_occurrence(&mut self, occurrence: Option<PreparedTransferOccurrence>) {
        let Some(PreparedTransferOccurrence {
            transcript,
            capture,
        }) = occurrence
        else {
            return;
        };
        self.pending_fastpq_source_captures.record(capture);
        crate::exec_witness::record_fastpq_transcript(&transcript);
        self.pending_transfer_transcripts.push(transcript);
    }

    #[cfg(test)]
    /// Preserve immediate recording for existing single and batch transcript owners.
    pub(super) fn stage_transfer_transcripts_with_batch_hash(
        &mut self,
        authority: &AccountId,
        batch_hash: Hash,
        deltas: Vec<TransferDeltaTranscript>,
    ) -> Result<(), Error> {
        let occurrence = self.prepare_transfer_occurrence(authority, batch_hash, deltas);
        if let Some(occurrence) = &occurrence {
            self.reserve_transfer_occurrence(occurrence)?;
        }
        self.stage_transfer_occurrence(occurrence);
        Ok(())
    }

    /// Prepare an exact occurrence, run its movement, then stage it only on success.
    ///
    /// The numeric movement caller supplies its exact prechecked delta and resolves its
    /// purpose identity immediately before this call. Its callback must keep execution
    /// identity, route and fragment context unchanged. The current callback only applies
    /// the prepared balance/control plan; receiver admission occurs before this boundary.
    /// No prepared occurrence escapes the exclusive transaction borrow.
    ///
    /// Reserve the exact complete-entry frame before the movement. Capture or quota
    /// failure poisons the physical attempt. Callback writes remain in the original
    /// State overlay and cannot apply after any returned preparation/movement error.
    ///
    /// # Errors
    ///
    /// Returns the movement error without staging its occurrence. No fallible operation
    /// is added after a successful callback; ordinary infallible collection allocation
    /// and witness recording remain part of staging.
    pub(crate) fn apply_with_prepared_transfer_transcripts<T>(
        &mut self,
        authority: &AccountId,
        batch_hash: Hash,
        deltas: Vec<TransferDeltaTranscript>,
        apply: impl FnOnce(&mut Self) -> Result<T, Error>,
    ) -> Result<T, Error> {
        self.flush_retail_fee_transfer_transcripts()?;
        let occurrence = self.prepare_transfer_occurrence(authority, batch_hash, deltas);
        if let Some(occurrence) = &occurrence {
            self.reserve_transfer_occurrence(occurrence)?;
        }
        let applied = match apply(self) {
            Ok(applied) => applied,
            Err(error) => {
                self.fastpq_source_quota.poison();
                return Err(error);
            }
        };
        self.stage_transfer_occurrence(occurrence);
        Ok(applied)
    }
    /// Prepare accepted deltas incrementally and publish one occurrence after the body succeeds.
    ///
    /// The independent-batch caller keeps its interleaved preparation and balance/control
    /// application order. It appends each exact accepted delta immediately before that
    /// leg's plan is applied, and propagates every preparation or apply error out of the
    /// whole callback. A preparation error must not become an independent-leg rejection.
    /// Rejected leg preparation must not append. These ordering and stable execution-context
    /// requirements are caller obligations; the scoped `FnMut` does not enforce them by type.
    ///
    /// The initial capture result is retained without publication. The first accepted delta
    /// receives its singleton digest before mutation; a second accepted delta clears that
    /// digest. The same Vec, values and capture result are staged once after whole-body
    /// success. An empty body never stages a transcript or capture error.
    ///
    /// The supplied capacity is an inclusive accepted-delta bound derived from the
    /// instruction's entry count. Storage grows only for accepted deltas; rejected legs
    /// do not preallocate a full transcript. Exceeding the bound rejects the whole body,
    /// even if a callback incorrectly ignores its preparation error.
    ///
    /// The source guard remeasures committed, pending and candidate occurrences before
    /// each movement. Callback mutations still require the original State rollback;
    /// capture/witness publication can allocate and a carrier unwind remains fatal.
    ///
    /// # Errors
    ///
    /// Propagates the callback error without publishing the prepared occurrence. The
    /// caller must preserve its existing transaction and witness rollback boundaries.
    pub(crate) fn apply_with_incremental_transfer_transcripts<T>(
        &mut self,
        authority: &AccountId,
        batch_hash: Hash,
        capacity: usize,
        apply: impl FnOnce(
            &mut Self,
            &mut dyn FnMut(&mut Self, TransferDeltaTranscript) -> Result<(), Error>,
        ) -> Result<T, Error>,
    ) -> Result<T, Error> {
        self.flush_retail_fee_transfer_transcripts()?;
        let capture = self.capture_original_fastpq_transcript_source(batch_hash);
        let mut empty_deltas = Vec::new();
        let mut occurrence: Option<PreparedTransferOccurrence> = None;
        let mut preparation_failed = false;
        let bound_error = || {
            Error::InvariantViolation("transfer transcript exceeds its declared entry bound".into())
        };
        let applied = {
            let mut append = |state: &mut Self, delta: TransferDeltaTranscript| {
                let count = occurrence
                    .as_ref()
                    .map_or(0, |entry| entry.transcript.deltas.len());
                if preparation_failed || count >= capacity {
                    preparation_failed = true;
                    state.refuse_fastpq_source_preparation(
                        "transfer transcript exceeds its declared entry bound".into(),
                    );
                    return Err(bound_error());
                }
                if let Some(occurrence) = &mut occurrence {
                    occurrence.transcript.poseidon_preimage_digest = None;
                    occurrence.transcript.deltas.try_reserve(1).map_err(|_| {
                        preparation_failed = true;
                        state.refuse_fastpq_source_preparation(
                            "host cannot retain FASTPQ delta".into(),
                        );
                        Error::InvariantViolation("host cannot retain FASTPQ delta".into())
                    })?;
                    occurrence.transcript.deltas.push(delta);
                } else {
                    let authority_digest = crate::fastpq::authority_digest(authority);
                    let poseidon_preimage_digest =
                        Some(crate::fastpq::poseidon_preimage_digest(&delta, &batch_hash));
                    empty_deltas.try_reserve(1).map_err(|_| {
                        preparation_failed = true;
                        state.refuse_fastpq_source_preparation(
                            "host cannot retain FASTPQ delta".into(),
                        );
                        Error::InvariantViolation("host cannot retain FASTPQ delta".into())
                    })?;
                    empty_deltas.push(delta);
                    occurrence = Some(PreparedTransferOccurrence {
                        transcript: TransferTranscript {
                            batch_hash,
                            deltas: core::mem::take(&mut empty_deltas),
                            authority_digest,
                            poseidon_preimage_digest,
                        },
                        capture,
                    });
                }
                let prepared = state.reserve_transfer_occurrence(
                    occurrence
                        .as_ref()
                        .expect("accepted delta creates occurrence"),
                );
                preparation_failed |= prepared.is_err();
                prepared
            };
            match apply(self, &mut append) {
                Ok(applied) => applied,
                Err(error) => {
                    self.fastpq_source_quota.poison();
                    return Err(error);
                }
            }
        };
        if preparation_failed {
            return Err(bound_error());
        }
        self.stage_transfer_occurrence(occurrence);
        Ok(applied)
    }
}

#[cfg(test)]
mod tests;
