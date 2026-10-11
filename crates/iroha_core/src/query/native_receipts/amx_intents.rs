//! Reconstruct one unresolved local relay intent from authenticated retained history.
//!
//! The caller retains its immutable State view until original proof/instruction admission.
//! Original `.ami` bytes are only coordinates: the existing native proof reader authenticates
//! the actual carrier, complete writes and Prepared record. No selector, filename, scalar
//! projection or zero authority byte grants permission to sign, pay or submit a transaction.
//! TODO(S6): connect delivery to an explicitly authorized, funded parent transaction journal
//! with restart/rejection/idempotency ownership. There is no autonomous validator relayer here.

use super::{
    NativeAmxRecordProofErrorV1, NativeAmxRecordProofPollV1, NativeAmxRecordProofReadV1,
    amx_record_proof,
};
use crate::{
    query::native_context_archive::{
        NativeContextArchive, NativeContextArchiveError, NativeContextRead,
        prepared_intents::{IntentProjection, Row},
    },
    state::StateReadOnly,
};
use iroha_allocation::{AllocationBudget, ChargedBuffer};
use iroha_crypto::{Hash, HashOf};
use iroha_data_model::{
    block::BlockHeader,
    isi::{AmxInstructionAdmissionErrorV1, InstructionBox, PendingAmxInstructionV1},
    sumeragi_amx::{AllocatedAmxRecordProofV1, AmxRecordKind, AmxRecordV1},
};

/// Exact original acquisition, decode, proof or instruction refusal; never record absence.
#[derive(Debug, thiserror::Error)]
pub enum NativeAmxPreparedRelayErrorV1 {
    /// Original archive descriptor, namespace, I/O or same-pool buffer refused.
    #[error(transparent)]
    Archive(#[from] NativeContextArchiveError),
    /// Original frame/field decode refused, with provenance captured before unwinding.
    #[error("native Prepared intent decode: {0}")]
    Decode(#[from] norito::core::DecodeAttemptError),
    /// The sole native carrier/record verifier or its original backing refused.
    #[error(transparent)]
    Proof(#[from] NativeAmxRecordProofErrorV1),
    /// The original move-only proof's instruction storage refused admission.
    #[error(transparent)]
    Instruction(#[from] AmxInstructionAdmissionErrorV1),
    /// Canonical record encoding refused, independently of decoder provenance.
    #[error("native Prepared intent record encoding: {0}")]
    Encoding(norito::Error),
    /// Intent coordinates or authenticated source identity differs.
    #[error("native Prepared intent source: {0}")]
    Source(&'static str),
}

/// Bounded acquisition, one move-only instruction, or exhaustion of the selected original frame.
#[derive(Debug)]
pub enum NativeAmxPreparedRelayPollV1 {
    /// The same source/proof job made bounded progress; no row was delivered.
    Pending,
    /// Exact funded Relay instruction, still lacking signing/fee/submission authority.
    Relay(InstructionBox),
    /// Every distinct original row was delivered once by this in-memory owner.
    Complete,
}

#[cfg(test)]
type InstructionProbe<'v> = Box<dyn FnOnce(&InstructionBox) + 'v>;

/// One original `.ami` selection and its original native proof/instruction admission.
///
/// This is synchronous and borrowed through pre-issuance refusal: keep the genuine immutable
/// State view alive, resume this exact owner, and retire it within the original refund scope.
/// A restart must select the original height from freshly authenticated replayed history;
/// this owner does not scan files, invent a signer, mark durable submission or delete intents.
/// Existing native prefix/epoch graph-funding TODOs in the proof reader remain open.
#[must_use = "retain this original intent/proof job through refusal or explicitly retire it"]
pub struct NativeAmxPreparedRelayReadV1<'v, V: StateReadOnly> {
    // Retire funded nested graphs before their original raw source and pool.
    instruction: Option<InstructionBox>,
    pending: Option<PendingAmxInstructionV1<'static>>,
    proof: Option<AllocatedAmxRecordProofV1>,
    proof_read: Option<NativeAmxRecordProofReadV1<'v, V>>,
    bytes: Option<ChargedBuffer<u8>>,
    read: NativeContextRead,
    projection: Option<IntentProjection>,
    row: Option<(Row, usize)>,
    previous_key: Option<[u8; iroha_data_model::sumeragi_amx::AMX_RECORD_WITNESS_KEY_BYTES]>,
    index: usize,
    offset: usize,
    complete: bool,
    absent: bool,
    height: u64,
    carrier: HashOf<BlockHeader>,
    view: &'v V,
    budget: AllocationBudget,
    #[cfg(test)]
    prepared_probe: Option<InstructionProbe<'v>>,
}

/// Select unresolved Prepared relay coordinates from the captured authenticated State history.
/// The file name is derived from that exact hash journal, never from an untrusted file claim.
/// No archive bytes are acquired until polling, and no signing/submission authority is inferred.
///
/// # Errors
/// The height is genesis/outside the captured history, or the original archive cannot open.
pub fn prepared_amx_relays<'v, V: StateReadOnly>(
    view: &'v V,
    height: u64,
) -> Result<NativeAmxPreparedRelayReadV1<'v, V>, NativeAmxPreparedRelayErrorV1> {
    let index = height
        .checked_sub(1)
        .and_then(|index| usize::try_from(index).ok())
        .filter(|_| height >= 2)
        .ok_or(NativeAmxPreparedRelayErrorV1::Source(
            "intent requires a certified non-genesis carrier",
        ))?;
    let carrier =
        view.block_hashes()
            .get(index)
            .copied()
            .ok_or(NativeAmxPreparedRelayErrorV1::Source(
                "intent carrier is outside captured history",
            ))?;
    let budget = view.prepared_contract_cache().execution_budget().clone();
    let archive = NativeContextArchive::open_existing(
        view.kura(),
        budget.clone(),
        view.kura().native_context_archive_max_bytes(),
    )?;
    Ok(NativeAmxPreparedRelayReadV1 {
        instruction: None,
        pending: None,
        proof: None,
        proof_read: None,
        bytes: None,
        read: archive.prepared_intent_read_job(height, carrier),
        projection: None,
        row: None,
        previous_key: None,
        index: 0,
        offset: 0,
        complete: false,
        absent: false,
        height,
        carrier,
        view,
        budget,
        #[cfg(test)]
        prepared_probe: None,
    })
}

fn record_hash(record: &AmxRecordV1) -> Result<Hash, NativeAmxPreparedRelayErrorV1> {
    let mut cause = None;
    let hash = Hash::new_from_writer(|writer| {
        norito::core::write_canonical_to_writer(record, writer).map_err(|error| {
            cause = Some(error);
            std::io::Error::from(std::io::ErrorKind::InvalidData)
        })
    });
    if let Some(cause) = cause {
        return Err(NativeAmxPreparedRelayErrorV1::Encoding(cause));
    }
    hash.map_err(|_| NativeAmxPreparedRelayErrorV1::Source("record digest writer refused"))
}
impl<'v, V: StateReadOnly> NativeAmxPreparedRelayReadV1<'v, V> {
    fn recheck(&self) -> Result<(), NativeAmxPreparedRelayErrorV1> {
        self.read.recheck_namespace()?;
        let index = usize::try_from(self.height - 1).map_err(|_| {
            NativeAmxPreparedRelayErrorV1::Source("intent height exceeds address space")
        })?;
        if self.view.block_hashes().get(index).copied() != Some(self.carrier)
            || self
                .bytes
                .as_ref()
                .is_some_and(|bytes| !bytes.belongs_to(&self.budget))
        {
            return Err(NativeAmxPreparedRelayErrorV1::Source(
                "original history or allocation pool changed",
            ));
        }
        if let Some(projection) = &self.projection
            && !projection.matches(
                self.bytes.as_ref().expect("original frame").as_slice(),
                self.view,
                &self.budget,
                self.height,
                self.carrier,
            )
        {
            return Err(NativeAmxPreparedRelayErrorV1::Source(
                "intent differs from original authenticated participant",
            ));
        }
        Ok(())
    }

    /// Advance the original source by one byte-read or proof stage and deliver at most one row.
    /// All completed bytes/proof/instruction backing survives every refused attempt unchanged.
    ///
    /// # Errors
    /// Exact original descriptor, source, decoder, proof or instruction admission refusal.
    /// Polling after complete refuses; no error acknowledges or advances an undelivered row.
    pub fn poll(&mut self) -> Result<NativeAmxPreparedRelayPollV1, NativeAmxPreparedRelayErrorV1> {
        use NativeAmxPreparedRelayErrorV1 as Error;
        use NativeAmxPreparedRelayPollV1 as Poll;
        if self.complete {
            return Err(Error::Source("intent read already completed"));
        }
        if self.absent {
            return Err(Error::Source(
                "intent names an absent original Prepared record",
            ));
        }
        self.recheck()?;
        if self.bytes.is_none() {
            self.bytes = self.read.poll()?;
            return Ok(Poll::Pending);
        }
        let bytes = self.bytes.as_ref().expect("original intent frame");
        if self.projection.is_none() {
            let projection = norito::core::classify_decode_attempt(|| {
                IntentProjection::decode(bytes.as_slice())
            })?;
            if !projection.matches(
                bytes.as_slice(),
                self.view,
                &self.budget,
                self.height,
                self.carrier,
            ) {
                return Err(Error::Source(
                    "intent differs from original authenticated participant",
                ));
            }
            self.offset = norito::core::classify_decode_attempt(|| {
                projection.first_offset(bytes.as_slice())
            })?;
            self.projection = Some(projection);
        }
        let projection = self
            .projection
            .as_ref()
            .expect("original scalar projection");
        if self.row.is_none() {
            let row = norito::core::classify_decode_attempt(|| {
                norito::core::with_decode_limits(
                    norito::canonical_decode_limits(bytes.as_slice().len()),
                    || projection.row(bytes.as_slice(), self.index, self.offset),
                )
            })?;
            let Some((row, next)) = row else {
                self.recheck()?;
                self.complete = true;
                return Ok(Poll::Complete);
            };
            if self
                .previous_key
                .is_some_and(|previous| previous >= row.key)
            {
                return Err(Error::Source(
                    "Prepared rows are not distinct canonical writes",
                ));
            }
            self.row = Some((row, next));
            self.proof_read = Some(amx_record_proof(
                self.view,
                self.height,
                AmxRecordKind::Prepared,
                row.tx,
            ));
        }
        if self.pending.is_none() && self.instruction.is_none() {
            if self.proof.is_none() {
                match self
                    .proof_read
                    .as_mut()
                    .expect("original record job")
                    .poll()?
                {
                    NativeAmxRecordProofPollV1::Pending => return Ok(Poll::Pending),
                    NativeAmxRecordProofPollV1::Complete(proof) => {
                        let Some(proof) = proof else {
                            self.absent = true;
                            return Err(Error::Source(
                                "intent names an absent original Prepared record",
                            ));
                        };
                        self.proof = Some(proof);
                    }
                }
            }
            // Count the actual authenticated full witness before delivering even the first
            // row. Ordered distinct per-row proofs then rule out a hidden or repeated subset.
            #[cfg(not(all(test, sumeragi_core_mutation = "HC218")))]
            if self
                .proof_read
                .as_ref()
                .expect("original verified record job")
                .authenticated_prepared_count()?
                != projection.record_count()
            {
                return Err(Error::Source(
                    "intent omits original certified Prepared writes",
                ));
            }
            let proof = self
                .proof
                .as_ref()
                .expect("original funded proof")
                .canonical();
            let row = self.row.as_ref().expect("current original row").0;
            if !self
                .proof_read
                .as_ref()
                .expect("original verifier")
                .matches_completed_execution(self.carrier, projection.ordinary_writes_root)
                || !matches!(&proof.record, AmxRecordV1::Prepared(prepared)
                    if prepared.tx == row.tx && prepared.participant == row.participant)
                || proof.record.witness_key() != row.key
                || record_hash(&proof.record)? != row.value
            {
                return Err(Error::Source(
                    "intent row differs from certified original execution",
                ));
            }
            self.recheck()?;
            self.pending = Some(
                self.proof
                    .take()
                    .expect("original proof moves once")
                    .into_relay(),
            );
        }
        self.recheck()?;
        if self.instruction.is_none() {
            self.instruction = Some(
                self.pending
                    .as_mut()
                    .expect("original pending instruction")
                    .complete(&self.budget)?,
            );
        }
        #[cfg(test)]
        if let Some(probe) = self.prepared_probe.take() {
            probe(
                self.instruction
                    .as_ref()
                    .expect("original complete instruction"),
            );
        }
        // The actual complete instruction remains owned here across final join refusal.
        // No fallible operation follows delivery of that same original allocation.
        #[cfg(not(all(test, sumeragi_core_mutation = "HC217")))]
        self.recheck()?;
        let instruction = self
            .instruction
            .take()
            .expect("original complete instruction");
        let (row, next) = self.row.take().expect("delivered original row");
        self.pending = None;
        self.proof_read = None;
        self.previous_key = Some(row.key);
        self.offset = next;
        self.index += 1;
        Ok(Poll::Relay(instruction))
    }

    /// Complete one original row without replacing any source after refusal.
    ///
    /// # Errors
    /// The same precise refusal returned by `poll`; the original job remains pending.
    pub fn complete_next(
        &mut self,
    ) -> Result<Option<InstructionBox>, NativeAmxPreparedRelayErrorV1> {
        loop {
            match self.poll()? {
                NativeAmxPreparedRelayPollV1::Pending => {}
                NativeAmxPreparedRelayPollV1::Relay(instruction) => return Ok(Some(instruction)),
                NativeAmxPreparedRelayPollV1::Complete => return Ok(None),
            }
        }
    }
    // Observes the actual completed instruction before its final original-source join.
    // It cannot install coordinates, proof fields, graph backing or a guard verdict.
    #[cfg(test)]
    pub(crate) fn probe_instruction_prepared_once(
        &mut self,
        probe: impl FnOnce(&InstructionBox) + 'v,
    ) {
        assert!(self.prepared_probe.is_none() && self.instruction.is_none() && self.index == 0);
        self.prepared_probe = Some(Box::new(probe));
    }
    #[cfg(test)]
    pub(crate) fn retained_instruction(&self) -> Option<&InstructionBox> {
        self.instruction.as_ref()
    }
    #[cfg(test)]
    pub(crate) fn acquired_frame_is_complete(&self) -> bool {
        self.bytes.is_some()
    }
    #[cfg(test)]
    pub(crate) fn acquired_frame(&self) -> Option<&[u8]> {
        self.bytes
            .as_ref()
            .map(ChargedBuffer::as_slice)
            .or_else(|| self.read.acquired_prefix())
    }
}
