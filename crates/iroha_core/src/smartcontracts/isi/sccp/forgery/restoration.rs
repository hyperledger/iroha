//! Restart reauthentication from complete original certified SCCP archive history.
//!
//! No snapshot generation, clock, G6 member, claimed id or current peer lookup is authority.
//! Both current and exact undo cuts are reconstructed from the same independently verified
//! native prefix. Archived permanent offences discover missing records as well as substitutes.
mod delta;
mod facts;
use super::*;
use crate::smartcontracts::isi::sccp::generation_record::{
    GenerationRecordError, GenerationRecordReadError,
};
use crate::{
    state::{
        EvidencePreparationError as Preparation, RetainedEvidenceRecord, State,
        sccp_forgery_custody::OffenceKey,
    },
    sumeragi::{
        evidence::EvidenceAdmissionError as Error, runtime_availability::history::sccp::SccpCarrier,
    },
};
use core::result::Result;
use iroha_allocation::ChargedBuffer;
use iroha_crypto::HashOf;
use iroha_data_model::block::BlockHeader;
use iroha_data_model::{
    block::consensus::{EvidencePenaltyStatus, EvidenceScope, RecordedEvidenceV1},
    consensus::NposPenaltyAction,
    isi::SetParameter,
    parameter::{
        Parameter,
        system::{
            AdmittedSumeragiNposParameters, SumeragiNposJsonAdmissionError, SumeragiNposParameters,
        },
    },
    sccp::params::SccpParametersV1,
    transaction::{Executable, TransactionEntrypoint},
};
use mv::storage::StorageReadOnly as _;

fn invalid(message: &'static str) -> Error {
    Error::Invalid(message.into())
}
fn codec(error: norito::Error) -> Error {
    Error::Source(crate::execution_attempt::norito_decode_attempt_error(
        error,
        |error| std::io::Error::new(std::io::ErrorKind::InvalidData, error),
    ))
}
impl From<norito::Error> for Error {
    fn from(error: norito::Error) -> Self {
        codec(error)
    }
}
impl From<norito::core::DecodeAttemptError> for Error {
    fn from(original: norito::core::DecodeAttemptError) -> Self {
        canonical_codec(original)
    }
}
fn generation_error(error: GenerationRecordReadError) -> Error {
    match error {
        GenerationRecordReadError::Decode(original) => canonical_codec(original),
        GenerationRecordReadError::Record(GenerationRecordError::Admission(original)) => {
            Preparation::Admission(original).into()
        }
        GenerationRecordReadError::Record(GenerationRecordError::Allocator { bytes }) => {
            Preparation::Allocator {
                requested_bytes: bytes,
            }
            .into()
        }
        GenerationRecordReadError::Record(GenerationRecordError::Account(original)) => {
            codec(original)
        }
        GenerationRecordReadError::Record(GenerationRecordError::Invalid(_)) => {
            invalid("invalid original generation custody")
        }
    }
}
fn canonical_codec(original: norito::core::DecodeAttemptError) -> Error {
    Error::Source(crate::execution_attempt::canonical_decode_attempt_error(
        original,
        |error| std::io::Error::new(std::io::ErrorKind::InvalidData, error),
    ))
}

impl From<crate::execution_attempt::ExecutionAttemptError<std::io::Error>> for Error {
    fn from(error: crate::execution_attempt::ExecutionAttemptError<std::io::Error>) -> Self {
        Self::Source(error)
    }
}
fn verification_error(error: ForgeryVerificationError) -> Error {
    match error {
        ForgeryVerificationError::Allocation(error) => Preparation::Admission(error).into(),
        ForgeryVerificationError::PhysicalAllocation(original) => Error::Source(
            crate::execution_attempt::ExecutionAttemptError::Deferred(original.into()),
        ),
        _ => invalid("restored SCCP evidence fails its original recorded relation"),
    }
}
/// The original signed-genesis policy is immutable by the SetParameter rule. Its admitted
/// decoder owns all nested allocation; the restored World policy is never read here.
fn delay(source: &SccpCarrier, budget: &AllocationBudget) -> Result<Option<u64>, Error> {
    let mut found = None;
    for transaction in source.block().external_transactions() {
        let Executable::Instructions(instructions) = transaction.instructions() else {
            return Err(invalid("genesis policy is not explicit"));
        };
        for instruction in instructions.iter() {
            let Some(set) = instruction.as_any().downcast_ref::<SetParameter>() else {
                continue;
            };
            let Parameter::Custom(custom) = set.inner() else {
                continue;
            };
            if custom.id() != &SumeragiNposParameters::parameter_id() {
                continue;
            }
            if found.is_some() {
                return Err(invalid("duplicate original NPoS policy"));
            }
            found = Some(
                policy_delay(custom, budget)?
                    .ok_or_else(|| invalid("missing original NPoS policy"))?,
            );
        }
    }
    if found == Some(0) {
        return Err(invalid("invalid original NPoS penalty delay"));
    }
    // Permissioned genesis may omit NPoS entirely. Preserve that authenticated absence;
    // only an actual successful SCCP Submit requires the policy when deriving its due height.
    Ok(found)
}

// Classify JSON while the same observer and original enclosing context still exist.
// In particular, a retired nested scope cannot be reconstructed from numeric limits.
fn policy_delay(
    custom: &iroha_data_model::parameter::CustomParameter,
    budget: &AllocationBudget,
) -> Result<Option<u64>, Error> {
    norito::core::classify_decode_attempt(|| {
        Ok::<_, norito::Error>(
            AdmittedSumeragiNposParameters::from_custom_parameter(custom, budget)
                .map(|policy| policy.map(|policy| policy.get().slashing_delay_blocks()))
                .map_err(|original| match original {
                    SumeragiNposJsonAdmissionError::Allocation(original) => {
                        Error::Preparation(original.into())
                    }
                    SumeragiNposJsonAdmissionError::Json(original) => Error::Source(
                        crate::execution_attempt::json_decode_attempt_error(original, |original| {
                            std::io::Error::new(std::io::ErrorKind::InvalidData, original)
                        }),
                    ),
                }),
        )
    })
    .map_err(canonical_codec)?
}

// Vec<SccpAnchorV1>'s fixed bare writer is a count plus named-record length prefixes.
// Decode each fixed record directly into exact original-pool backing; no uncharged Vec.
fn anchors(bytes: &[u8], budget: &AllocationBudget) -> Result<ChargedBuffer<SccpAnchorV1>, Error> {
    let prefix = bytes
        .get(..8)
        .ok_or_else(|| invalid("truncated original anchor count"))?;
    let count = usize::try_from(u64::from_le_bytes(prefix.try_into().expect("eight bytes")))
        .map_err(|_| invalid("anchor count overflows"))?;
    if count >= 4096 || count > bytes.len() / 8 {
        return Err(invalid("invalid original open chunk"));
    }
    let mut output = ChargedBuffer::new(count, budget).map_err(Preparation::from)?;
    let mut rest = &bytes[8..];
    let _flags = norito::core::DecodeFlagsGuard::enter(norito::core::default_encode_flags());
    for _ in 0..count {
        let (length, prefix) = norito::core::inspect_len_from_slice(rest)?;
        let end = prefix
            .checked_add(length)
            .ok_or_else(|| invalid("anchor length overflows"))?;
        let value = rest
            .get(prefix..end)
            .ok_or_else(|| invalid("truncated original anchor"))?;
        output.push_reserved(delta::fixed(value)?);
        rest = &rest[end..];
    }
    if !rest.is_empty() {
        return Err(invalid("trailing original anchors"));
    }
    Ok(output)
}

#[derive(Clone, Copy)]
struct Parent {
    height: u64,
    hash: HashOf<BlockHeader>,
    time: u64,
    core: Hash32,
    result: Hash32,
}
#[derive(Clone, Copy)]
struct RecordFact {
    key: Hash,
    height: u64,
    due: u64,
    marked: bool,
}
struct Admission {
    keys: [Option<OffenceKey>; 31],
    id: [u8; 32],
    generation: u64,
    due: u64,
    count: usize,
}
#[derive(Clone, Copy, Default)]
struct Progress {
    height: u64,
    network_index: usize,
    expected_offences: usize,
    offence_range: Option<(usize, usize)>,
    archived_lc: Option<u64>,
    submits_done: bool,
    delta_index: usize,
    delta_done: bool,
    mark_index: usize,
}

/// Provisional source reducer. Its only record-sized backing contains derived scalar facts;
/// immutable graph comparison borrows snapshot claims and never promotes them to authority.
/// No public value or installation grant escapes before the reader seals the complete tip.
pub(crate) struct SccpRestore {
    facts: facts::Facts,
    records: ChargedBuffer<RecordFact>,
    parent: Option<Parent>,
    delay: Option<u64>,
    progress: Progress,
    tip: u64,
    current_checked: bool,
    previous_checked: bool,
}
impl SccpRestore {
    pub(crate) fn new(state: &State, tip: u64, budget: &AllocationBudget) -> Result<Self, Error> {
        // Permanent record count is a memory plan, not an authority input. Omission causes
        // rejection when the original stream discovers the missing successful admission.
        let count = state
            .world
            .consensus_evidence
            .view()
            .iter()
            .filter(|(_, record)| record.native_evidence().is_none())
            .count();
        Ok(Self {
            facts: facts::Facts::new(budget)?,
            records: ChargedBuffer::new(count, budget).map_err(Preparation::from)?,
            parent: None,
            delay: None,
            progress: Progress::default(),
            tip,
            current_checked: false,
            previous_checked: false,
        })
    }
    pub(crate) fn is_complete(&self) -> bool {
        self.current_checked
            && self.previous_checked
            && self.parent.is_some_and(|p| p.height == self.tip)
    }
    /// Resumes the exact pending carrier. Every fallible edit is atomic in its private owner;
    /// its cursor advances immediately after success, with no fallible operation between them.
    pub(crate) fn consume(
        &mut self,
        source: &SccpCarrier,
        instance: Hash32,
        network: NetworkId,
        budget: &AllocationBudget,
        state: &State,
    ) -> Result<(), Error> {
        let h = source.block().header().height().get();
        if self.progress.height == 0 {
            if h != self.parent.map_or(1, |p| p.height + 1) || h > self.tip {
                return Err(invalid("restoration carrier order differs"));
            }
            let offence_range = delta::field_range(source.delta(), b"sccp_forgery_offences")?;
            let archived_lc = delta::select(source.delta(), b"sccp_liability_clock", None)?
                .and_then(delta::SelectedValue::value)
                .map(delta::fixed::<u64>)
                .transpose()?;
            self.progress.offence_range = offence_range;
            self.progress.archived_lc = archived_lc;
            self.progress.height = h;
        } else if self.progress.height != h {
            return Err(invalid("retry substituted a pending carrier"));
        }
        if h == 1 && self.delay.is_none() {
            self.delay = delay(source, budget)?;
        }
        if !self.progress.submits_done {
            // Header/source fields remain those of the executing parent until the entire
            // Network source has been consumed. Offence dedup additionally includes earlier
            // successful submissions in this same carrier, matching the actual child World.
            for (index, entrypoint) in source.block().network_entrypoints().enumerate() {
                if index < self.progress.network_index {
                    continue;
                }
                let transaction = match entrypoint {
                    TransactionEntrypoint::External(transaction) => Some(transaction),
                    TransactionEntrypoint::SealedReveal(reveal) => {
                        Some(reveal.signed_transaction())
                    }
                    TransactionEntrypoint::SealedCommitment(_) => None,
                };
                if let Some(transaction) = transaction {
                    if let Executable::Instructions(instructions) = transaction.instructions() {
                        let instructions: &[iroha_data_model::isi::InstructionBox] = instructions;
                        if let [only] = instructions {
                            if let Some(submit) =
                                only.as_any().downcast_ref::<SubmitSccpForgeryEvidenceV1>()
                            {
                                let output_index = u32::try_from(index)
                                    .map_err(|_| invalid("Network index overflows"))?;
                                let (_, output) = source
                                    .block()
                                    .network_output_at(output_index)
                                    .ok_or_else(|| invalid("Submit lacks exact Network output"))?;
                                if output.result.is_ok() {
                                    transaction
                                        .verify_signature()
                                        .map_err(|_| invalid("Submit signature differs"))?;
                                    let admission = self.prepare(
                                        source, submit, instance, network, budget, state,
                                    )?;
                                    self.install(admission, h)?;
                                }
                            }
                        }
                    }
                }
                self.progress.network_index = index.checked_add(1).ok_or(Preparation::Invariant)?;
            }
            self.require_offence_delta(source)?;
            self.progress.submits_done = true;
            #[cfg(test)]
            tests::after_submits_checkpoint(h, budget);
        }
        if !self.progress.delta_done {
            let mut index = 0usize;
            delta::visit::<Error>(source.delta(), |entry| {
                if index >= self.progress.delta_index {
                    self.facts.apply(entry, budget)?;
                    self.progress.delta_index =
                        index.checked_add(1).ok_or(Preparation::Invariant)?;
                }
                index = index.checked_add(1).ok_or(Preparation::Invariant)?;
                Ok(())
            })?;
            if self.facts.maximum != self.facts.derived_maximum {
                return Err(invalid(
                    "archived offence maximum differs from actual admissions",
                ));
            }
            self.progress.delta_done = true;
        }
        if let Some(effects) = source.block().npos_consensus_effects() {
            for (index, action) in effects.penalty_actions.iter().enumerate() {
                if index < self.progress.mark_index {
                    continue;
                }
                if let NposPenaltyAction::MarkConsensusEvidenceApplied(mark) = action {
                    if let Some(record) = self
                        .records
                        .as_mut_slice()
                        .iter_mut()
                        .find(|record| record.key == mark.evidence_key)
                    {
                        if record.marked || mark.height != record.due || h != record.due {
                            return Err(invalid(
                                "SCCP penalty mark has a foreign carrier or duplicate",
                            ));
                        }
                        record.marked = true;
                    }
                }
                self.progress.mark_index = index.checked_add(1).ok_or(Preparation::Invariant)?;
            }
        }
        if h == self.tip - 1 {
            self.check_cut(state, h, true)?;
            self.previous_checked = true;
        }
        if h == self.tip {
            self.check_cut(state, h, false)?;
            self.current_checked = true;
        }
        self.parent = Some(Parent {
            height: h,
            hash: source.block().hash(),
            time: source.block().header().creation_time_ms,
            core: source.core(),
            result: source.result(),
        });
        self.progress = Progress::default();
        Ok(())
    }
    fn prepare(
        &self,
        source: &SccpCarrier,
        submit: &SubmitSccpForgeryEvidenceV1,
        instance: Hash32,
        network: NetworkId,
        budget: &AllocationBudget,
        state: &State,
    ) -> Result<Admission, Error> {
        let parent = self
            .parent
            .ok_or_else(|| invalid("Submit has no original executed parent"))?;
        let h = source.block().header().height().get();
        let header = source.block().header();
        if h < 3
            || header.prev_block_hash() != Some(parent.hash)
            || header.creation_time_ms <= parent.time
        {
            return Err(invalid("Submit original parent/time differs"));
        }
        let x = SccpFinalityHeaderV1::parse(&submit.header)
            .map_err(|_| invalid("invalid original X"))?;
        if !x.is_active() || x.network_id() != *network.as_bytes() {
            return Err(invalid("original Submit scope/network differs"));
        }
        let parameters = self
            .facts
            .parameters
            .ok_or_else(|| invalid("SCCP absent at recorded parent"))?;
        let lc = next_liability_clock_v1(
            self.facts.lc,
            parent.time,
            header.creation_time_ms,
            parameters.committee_heartbeat_ms,
        );
        let archived_lc = self.progress.archived_lc.unwrap_or(self.facts.lc);
        if archived_lc != lc {
            return Err(invalid("original S0 clock differs"));
        }
        let generation = self
            .facts
            .generations
            .view()
            .get(&x.generation())
            .cloned()
            .ok_or_else(|| invalid("generation absent at original parent"))?;
        if generation.committee_root != x.committee_root()
            || !generation.is_liable(self.facts.current, lc)
        {
            return Err(invalid("original generation was not liable"));
        }
        let qc = QcFixedV1::parse(&submit.qc).map_err(|_| invalid("invalid original QC"))?;
        let message = verify_signature(
            &generation,
            instance,
            &x,
            &qc,
            &submit.aggregate_signature,
            budget,
            VerificationControl::Synchronous,
        )
        .map_err(verification_error)?;
        let result = outer_result(&x, &qc.result_body).0;
        let anchor = if x.height() >= generation.start_height
            && generation
                .end
                .as_ref()
                .is_none_or(|end| x.height() <= end.end_height)
            && x.height() < h
        {
            let (chunk, _) = anchor_chunk_position(x.height())
                .ok_or_else(|| invalid("invalid anchor height"))?;
            let root = self.facts.chunk(chunk);
            let offered = submit.anchor.as_ref().map(|w| SccpAnchorV1 {
                core_hash: w.core_hash,
                result: w.result,
            });
            let witness = offered
                .as_ref()
                .zip(submit.anchor.as_ref())
                .map(|(a, w)| (a, &w.path));
            Some(
                lookup_anchor(
                    parent.height,
                    SccpAnchorV1 {
                        core_hash: parent.core.0,
                        result: parent.result.0,
                    },
                    self.facts.open.as_slice(),
                    x.height(),
                    root.as_ref(),
                    witness,
                )
                .map_err(anchor_error)
                .map_err(verification_error)?,
            )
        } else {
            None
        };
        let rule = first_mismatch(&generation, h, x.height(), &qc, result, || {
            anchor.ok_or(ForgeryVerificationError::Unavailable(
                "required original anchor missing",
            ))
        })
        .map_err(verification_error)?;
        let id = forgery_evidence_id(generation.generation, &message, qc.signers);
        if self
            .records
            .as_slice()
            .iter()
            .any(|record| record.key == Hash::prehashed(id))
        {
            return Err(invalid("original record identity repeated"));
        }
        let mut keys: [Option<OffenceKey>; 31] = std::array::from_fn(|_| None);
        let mut selected = 0u32;
        let mut count = 0usize;
        for (index, member) in generation.members.iter().enumerate() {
            if qc.signers & (1u32 << index) == 0 {
                continue;
            }
            let Some(member) = member else {
                continue;
            };
            if generation.members[..index]
                .iter()
                .enumerate()
                .any(|(prior, old)| {
                    selected & (1u32 << prior) != 0
                        && old.as_ref().is_some_and(|old| {
                            old.lane_id == member.lane_id && old.validator == member.validator
                        })
                })
            {
                continue;
            }
            let key = OffenceKey::try_copy(
                generation.generation,
                member.lane_id,
                &member.validator,
                budget,
            )
            .map_err(Error::Storage)?;
            if self.facts.offences.view().get(&key).is_some() {
                continue;
            }
            let inserted = delta::select(
                self.offence_bytes(source),
                b"sccp_forgery_offences",
                Some(&|bytes| delta::matches(&key, bytes)),
            )?
            .and_then(delta::SelectedValue::value)
            .ok_or_else(|| invalid("Submit has no exact original offence delta"))?;
            if delta::fixed::<[u8; 32]>(inserted)? != id {
                return Err(invalid("original offence id differs"));
            }
            selected |= 1u32 << index;
            keys[index] = Some(key);
            count += 1;
        }
        if count == 0 {
            return Err(invalid("executed Submit has no new original offenders"));
        }
        self.claims(state, h, &Hash::prehashed(id), |record| {
            check_immutable(
                source,
                submit,
                &generation,
                instance,
                &qc,
                rule,
                selected,
                record,
            )
        })?;
        let due = h
            .checked_add(
                self.delay
                    .ok_or_else(|| invalid("original delay missing"))?,
            )
            .ok_or_else(|| invalid("penalty height overflows"))?;
        Ok(Admission {
            keys,
            id,
            generation: generation.generation,
            due,
            count,
        })
    }
    fn claims(
        &self,
        state: &State,
        h: u64,
        id: &Hash,
        mut check: impl FnMut(&RetainedEvidenceRecord) -> Result<(), Error>,
    ) -> Result<(), Error> {
        let snapshot = state.world.consensus_evidence.snapshot();
        let current = snapshot
            .current()
            .get(id)
            .ok_or_else(|| invalid("snapshot omits original permanent record"))?;
        check(current)?;
        if h < self.tip {
            let previous = match snapshot.revert_map().get(id) {
                Some(value) => value.as_ref(),
                None => Some(current),
            }
            .ok_or_else(|| invalid("undo omits original permanent record"))?;
            check(previous)?;
        }
        Ok(())
    }
    fn install(&mut self, admission: Admission, h: u64) -> Result<(), Error> {
        if self.records.as_slice().len() == self.records.capacity() {
            return Err(invalid("snapshot permanent record set is incomplete"));
        }
        let expected = self
            .progress
            .expected_offences
            .checked_add(admission.count)
            .ok_or(Preparation::Invariant)?;
        // One original-pool current/undo publication, or none. All nested account copies were
        // admitted before this call. A refused attempt cannot leave half a record's offenders.
        self.facts
            .offences
            .try_with_admitted_block(|block| {
                for key in admission.keys.iter().flatten() {
                    block
                        .try_insert_admitted(key.clone(), admission.id)
                        .map_err(|(_, error)| error)?;
                }
                Ok::<_, mv::storage::AdmittedStorageError>(())
            })
            .map_err(facts::block)?;
        self.records.push_reserved(RecordFact {
            key: Hash::prehashed(admission.id),
            height: h,
            due: admission.due,
            marked: false,
        });
        self.facts.derived_maximum = Some(
            self.facts
                .derived_maximum
                .map_or(admission.generation, |g| g.max(admission.generation)),
        );
        self.progress.expected_offences = expected;
        Ok(())
    }
    fn offence_bytes<'a>(&self, source: &'a SccpCarrier) -> &'a [u8] {
        self.progress
            .offence_range
            .map_or(&[], |(start, end)| &source.delta()[start..end])
    }
    fn require_offence_delta(&self, source: &SccpCarrier) -> Result<(), Error> {
        let mut count = 0usize;
        let h = source.block().header().height().get();
        let originals = self.facts.offences.view();
        let mut previous: Option<&OffenceKey> = None;
        delta::visit::<Error>(self.offence_bytes(source), |entry| {
            let key = entry.key.ok_or_else(|| invalid("offence key missing"))?;
            let id: [u8; 32] = delta::fixed(
                entry
                    .value
                    .ok_or_else(|| invalid("permanent offence deleted"))?,
            )?;
            let (original, value) = originals
                .iter()
                .find(|(original, _)| delta::matches(*original, key))
                .ok_or_else(|| invalid("offence delta has no original admitted tuple"))?;
            if previous.is_some_and(|previous| previous >= original)
                || *value != id
                || !self
                    .records
                    .as_slice()
                    .iter()
                    .any(|record| record.key == Hash::prehashed(id) && record.height == h)
            {
                return Err(invalid(
                    "offence delta order or successful original Submit differs",
                ));
            }
            previous = Some(original);
            count = count.checked_add(1).ok_or(Preparation::Invariant)?;
            Ok(())
        })?;
        if count != self.progress.expected_offences {
            return Err(invalid("offence delta omits or repeats an admission"));
        }
        Ok(())
    }
    fn check_cut(&self, state: &State, h: u64, previous: bool) -> Result<(), Error> {
        self.facts.check_cut(state, previous)?;
        let snapshot = state.world.consensus_evidence.snapshot();
        let records = snapshot
            .current()
            .iter()
            .filter(|(key, _)| !previous || !snapshot.revert_map().contains_key(*key))
            .chain(snapshot.revert_map().iter().filter_map(|(key, old)| {
                previous
                    .then_some(old.as_ref())
                    .flatten()
                    .map(|value| (key, value))
            }));
        let mut count = 0usize;
        for (key, record) in records {
            match (&record.evidence, record.attribution.scope) {
                (RecordedEvidenceV1::Native(_), EvidenceScope::Root | EvidenceScope::Lane(_)) => {
                    continue;
                }
                (RecordedEvidenceV1::SccpForgery(_), EvidenceScope::SccpGeneration { .. }) => {}
                _ => return Err(invalid("snapshot material/scope differs")),
            }
            let derived = self
                .records
                .as_slice()
                .iter()
                .find(|fact| fact.key == *key)
                .ok_or_else(|| invalid("snapshot adds a record without original execution"))?;
            let expected = if derived.marked {
                if derived.due > h {
                    return Err(invalid("future penalty mark"));
                }
                EvidencePenaltyStatus::Applied {
                    height: derived.due,
                }
            } else {
                if derived.due <= h {
                    return Err(invalid("original due penalty mark missing"));
                }
                EvidencePenaltyStatus::Pending
            };
            if derived.height > h || record.penalty_status != expected {
                return Err(invalid("snapshot penalty lifecycle differs"));
            }
            count += 1;
        }
        if count != self.records.as_slice().len() {
            return Err(invalid("snapshot omits original SCCP record"));
        }
        Ok(())
    }
}

fn check_immutable(
    source: &SccpCarrier,
    submit: &SubmitSccpForgeryEvidenceV1,
    generation: &RetainedSccpGeneration,
    instance: Hash32,
    qc: &QcFixedV1,
    rule: SccpForgeryRuleV1,
    selected: u32,
    record: &RetainedEvidenceRecord,
) -> Result<(), Error> {
    let RecordedEvidenceV1::SccpForgery(material) = &record.evidence else {
        return Err(invalid("SCCP id names Native material"));
    };
    material
        .validate_shape()
        .map_err(|_| invalid("invalid restored SCCP shape"))?;
    let header = source.block().header();
    let a = &record.attribution;
    if record.recorded_at_height != header.height().get()
        || record.recorded_at_view != header.view_change_index()
        || record.recorded_at_ms != header.creation_time_ms
        || material.evidence != *submit
        || material.rule != rule
        || material.generation != generation.generation
        || material.start_height != generation.start_height
        || a.scope
            != (EvidenceScope::SccpGeneration {
                generation: generation.generation,
            })
        || a.instance != instance.0
        || a.height != generation.start_height
        || a.epoch != qc.epoch
        || a.context_id != qc.epoch_context
        || a.authority_generation != generation.committee_root
        || !a.safety_violation
        || a.offenders.len() != material.offenders.len()
        || material.offenders.len()
            != usize::try_from(selected.count_ones()).map_err(|_| Preparation::Invariant)?
    {
        return Err(invalid(
            "restored immutable record differs from original admission",
        ));
    }
    let mut row = 0usize;
    for (index, member) in generation.members.iter().enumerate() {
        if selected & (1u32 << index) == 0 {
            continue;
        }
        let member = member
            .as_ref()
            .ok_or_else(|| invalid("selected original G6 slot absent"))?;
        let captured = &material.offenders[row];
        let attributed = &a.offenders[row];
        let (algorithm, key_bytes) = attributed
            .peer_id
            .public_key()
            .borrowed_parts()
            .map_err(|_| invalid("invalid restored peer envelope"))?;
        let signer = u32::try_from(index).map_err(|_| invalid("signer overflows"))?;
        if captured.signer != signer
            || captured.lane_id != member.lane_id
            || captured.validator != member.validator
            || captured.activation_height != member.activation_height
            || attributed.signer != signer
            || attributed.lane_stake.is_some()
            || algorithm != iroha_crypto::Algorithm::BlsNormal
            || key_bytes != generation.keys[index]
        {
            return Err(invalid(
                "restored offender differs from original G6/key slot",
            ));
        }
        row += 1;
    }
    Ok(())
}

#[cfg(test)]
mod tests;
