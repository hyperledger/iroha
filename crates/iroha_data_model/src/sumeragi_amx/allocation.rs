//! Exact physical custody of one AMX record proof from borrowed original execution writes.
//!
//! This is a local allocation owner, never foreign finality or monetary authority. Its caller
//! must authenticate the certificate, complete ordinary-write root and original carrier first.
//! The only materialized record field is Begin's bounded participant vector. Certificate bytes,
//! compressed siblings and that vector are prepaid by exact layout; tree scratch is separately
//! charged to the same pool. No canonical DTO clone or extraction API is exposed.

use super::{
    AmxBeginV1, AmxCertifiedBlockV1, AmxDecisionV1, AmxOutcomeV1, AmxPreparedV1, AmxRecordKind,
    AmxRecordProofV1, AmxRecordV1, AmxVoteV1, AmxWriteProofV1, MAX_AMX_HEADER_BYTES,
    MAX_AMX_PARTICIPANTS, MAX_AMX_QC_BYTES, MIN_AMX_PARTICIPANTS, amx_record_witness_key,
};
use crate::{
    block::{CommitCertificate, consensus::ExecWitness},
    sumeragi_finality::MAX_RESULT_PREIMAGE_BYTES,
};
use iroha_allocation::{
    AllocationBudget, AllocationCharge, AllocationRefusal, AllocationReservation, ChargedBuffer,
    ChargedBufferError, PrepaidBufferError, RetainedPayload,
};
use iroha_crypto::Hash;
use iroha_model_base::topology::DataSpaceId;
use norito::core as ncore;
use std::{alloc::Layout, fmt};

/// Why no original-pool proof owner was produced. Resource refusal is not record absence.
#[derive(Debug, thiserror::Error)]
pub enum AmxProofAllocationErrorV1 {
    /// Original finite pool admission refused a concrete layout before allocation.
    #[error(transparent)]
    Admission(#[from] AllocationRefusal),
    /// Charged scratch allocation failed.
    #[error(transparent)]
    Scratch(#[from] ChargedBufferError),
    /// A prepaid destination allocation or exact reservation split failed.
    #[error(transparent)]
    Destination(#[from] PrepaidBufferError),
    /// Canonical frame or inherited codec allowance refused the source.
    #[error(transparent)]
    Codec(#[from] norito::Error),
    /// The original source or the closed allocation plan is inconsistent.
    #[error("AMX proof allocation source: {0}")]
    Invalid(&'static str),
}
use AmxProofAllocationErrorV1 as Error;

/// Move-only canonical record proof and every charge for its actual nested backing.
///
/// No authority is granted by this owner. The immutable canonical borrow remains an ordinary
/// value; a caller-created clone is a different graph and is not funded by this ledger.
pub struct AllocatedAmxRecordProofV1(RetainedPayload<AmxRecordProofV1>);
impl fmt::Debug for AllocatedAmxRecordProofV1 {
    fn fmt(&self, out: &mut fmt::Formatter<'_>) -> fmt::Result {
        out.debug_struct("AllocatedAmxRecordProofV1")
            .field("canonical", self.canonical())
            .finish()
    }
}
impl PartialEq for AllocatedAmxRecordProofV1 {
    fn eq(&self, other: &Self) -> bool {
        self.canonical() == other.canonical()
    }
}
impl Eq for AllocatedAmxRecordProofV1 {}
impl AllocatedAmxRecordProofV1 {
    /// Borrow the original immutable canonical proof; the charge ledger remains attached.
    pub fn canonical(&self) -> &AmxRecordProofV1 {
        self.0.get()
    }
    /// Check the exact original pool, including ledger backing and every nested field charge.
    pub fn belongs_to(&self, budget: &AllocationBudget) -> bool {
        self.0.belongs_to(budget)
    }
    /// Sum exact retained layouts, including ledger backing. No encoding estimate is used.
    pub fn allocation_bytes(&self) -> Option<usize> {
        self.0.allocation_bytes()
    }
    // Sole private successor is the canonical InstructionBox owner; no public bare extraction.
    pub(crate) fn into_retained(self) -> RetainedPayload<AmxRecordProofV1> {
        self.0
    }

    /// Copy the already selected immutable proof into another complete same-pool owner.
    /// Each real destination layout, including its ledger, is admitted before any copy.
    /// Unlike Clone this operation can preserve and report the original capacity refusal.
    /// # Errors
    /// Refuses a different original pool, overflow, quota, capacity or physical allocation.
    pub fn try_copy(&self, budget: &AllocationBudget) -> Result<Self, Error> {
        if !self.belongs_to(budget) {
            return Err(Error::Invalid("foreign original proof pool"));
        }
        let original = self.canonical();
        let mut demand = Demand::default();
        demand.array::<u8>(original.block.consensus_header.len())?;
        demand.array::<u8>(original.block.commit_qc.len())?;
        demand.array::<u8>(original.block.result_preimage.len())?;
        demand.array::<[u8; 32]>(original.write.siblings.len())?;
        if let AmxRecordV1::Begin(begin) = &original.record {
            demand.array::<DataSpaceId>(begin.participants.len())?;
        }
        demand.finish()?;
        ncore::reserve_decode_allocation(demand.bytes)?;
        let mut construction = Construction::new(&demand, budget)?;
        let record = match &original.record {
            AmxRecordV1::Begin(begin) => {
                let mut participants = ChargedBuffer::from_reservation(
                    begin.participants.len(),
                    &mut construction.reservation,
                )?;
                for participant in &begin.participants {
                    participants.push_reserved(*participant);
                }
                AmxRecordV1::Begin(AmxBeginV1 {
                    tx: begin.tx,
                    participants: construction.vector(participants),
                    deadline: begin.deadline,
                })
            }
            AmxRecordV1::Prepared(prepared) => AmxRecordV1::Prepared(*prepared),
            AmxRecordV1::Decision(decision) => AmxRecordV1::Decision(*decision),
        };
        let block = AmxCertifiedBlockV1 {
            consensus_header: construction.bytes(&original.block.consensus_header)?,
            commit_qc: construction.bytes(&original.block.commit_qc)?,
            result_preimage: construction.bytes(&original.block.result_preimage)?,
        };
        let mut siblings = ChargedBuffer::from_reservation(
            original.write.siblings.len(),
            &mut construction.reservation,
        )?;
        for sibling in &original.write.siblings {
            siblings.push_reserved(*sibling);
        }
        let write = AmxWriteProofV1 {
            present: original.write.present,
            siblings: construction.vector(siblings),
        };
        construction.finish(
            AmxRecordProofV1 {
                block,
                record,
                write,
            },
            budget,
        )
    }

    /// Build the proof from the original borrowed writes and certificate, after source
    /// authentication by the native reader. Last-write selection and SMT geometry exactly
    /// match the canonical AMX proof. `None` means authenticated absence only if the caller
    /// first authenticated this complete write set. This constructor itself grants no trust.
    ///
    /// # Errors
    /// Refuses malformed record/frame, inconsistent original root, bounds or original-pool
    /// admission. On every failure all produced fields drop before their exact charges refund.
    pub fn from_original_witness(
        certificate: &CommitCertificate,
        witness: &ExecWitness,
        kind: AmxRecordKind,
        transaction: [u8; 32],
        original_root: Hash,
        budget: &AllocationBudget,
    ) -> Result<Option<Self>, Error> {
        let key = amx_record_witness_key(kind, transaction);
        let Some(written) = witness.writes.iter().rev().find(|write| write.key == key) else {
            return Ok(None);
        };
        if certificate.consensus_header().is_empty()
            || certificate.consensus_header().len() > MAX_AMX_HEADER_BYTES
            || certificate.commit_qc().is_empty()
            || certificate.commit_qc().len() > MAX_AMX_QC_BYTES
            || certificate.result_preimage().is_empty()
            || certificate.result_preimage().len() > MAX_RESULT_PREIMAGE_BYTES
        {
            return Err(Error::Invalid("certificate bounds"));
        }
        let frame = ncore::from_bytes_view(&written.value)?;
        let flags = frame.flags();
        if flags != ncore::default_encode_flags() {
            return Err(norito::Error::NonCanonicalEncoding.into());
        }
        let raw = frame.decode_exact_with::<AmxRecordV1, _, _>(|payload| {
            Ok((RawRecord::scan(payload)?, payload.len()))
        })?;
        // Tree scratch is a real charged 2*N Node allocation. Output demand is determined
        // only after computing the exact path; no uncharged leaf/subtree/value clone exists.
        let (present, siblings, root) = original_path(witness, &key, budget)?;
        if root != original_root {
            return Err(Error::Invalid("complete original ordinary-write root"));
        }
        let sibling_count = present
            .iter()
            .map(|byte| usize::try_from(byte.count_ones()).expect("eight bits fit usize"))
            .sum();
        let mut demand = Demand::default();
        demand.array::<u8>(certificate.consensus_header().len())?;
        demand.array::<u8>(certificate.commit_qc().len())?;
        demand.array::<u8>(certificate.result_preimage().len())?;
        demand.array::<[u8; 32]>(sibling_count)?;
        if let RawRecord::Begin { count, .. } = raw {
            #[cfg(all(test, sumeragi_model_mutation = "DM2"))]
            {
                let _ = count;
            }
            #[cfg(not(all(test, sumeragi_model_mutation = "DM2")))]
            {
                demand.array::<DataSpaceId>(count)?;
            }
        }
        demand.finish()?;
        // Construction precedes every detached field, including partial record materialization.
        ncore::reserve_decode_allocation(demand.bytes)?;
        let mut construction = Construction::new(&demand, budget)?;
        let record = raw.materialize(&mut construction)?;
        record
            .validate()
            .map_err(|_| Error::Invalid("malformed record"))?;
        if record.witness_key() != key {
            return Err(Error::Invalid("original record/key identity"));
        }
        // Compare the entire canonical frame to the original persisted value without a Vec.
        let mut exact = ExactWriter {
            expected: &written.value,
            offset: 0,
        };
        ncore::write_canonical_to_writer(&record, &mut exact)?;
        if exact.offset != written.value.len() {
            return Err(norito::Error::NonCanonicalEncoding.into());
        }
        let block = AmxCertifiedBlockV1 {
            consensus_header: construction.bytes(certificate.consensus_header())?,
            commit_qc: construction.bytes(certificate.commit_qc())?,
            result_preimage: construction.bytes(certificate.result_preimage())?,
        };
        let mut output =
            ChargedBuffer::from_reservation(sibling_count, &mut construction.reservation)?;
        for (level, hash) in siblings.iter().enumerate() {
            if present[level / 8] & (1 << (level % 8)) != 0 {
                output.push_reserved(*hash);
            }
        }
        let write = AmxWriteProofV1 {
            present,
            siblings: construction.vector(output),
        };
        // This root check borrows the original canonical value bytes, avoiding witness_value's
        // ordinary encoded Vec while retaining every canonical SMT/path validity check.
        if write
            .root(&key, &written.value)
            .map_err(|_| Error::Invalid("canonical path"))?
            != root
        {
            return Err(Error::Invalid("compressed original path"));
        }
        let proof = AmxRecordProofV1 {
            block,
            record,
            write,
        };
        construction.finish(proof, budget).map(Some)
    }
}

#[derive(Default)]
struct Demand {
    bytes: usize,
    count: usize,
}
impl Demand {
    fn array<T>(&mut self, count: usize) -> Result<(), Error> {
        let layout = Layout::array::<T>(count).map_err(|_| AllocationRefusal::DemandOverflow)?;
        self.bytes = self
            .bytes
            .checked_add(layout.size())
            .ok_or(AllocationRefusal::DemandOverflow)?;
        self.count = self
            .count
            .checked_add(1)
            .ok_or(AllocationRefusal::DemandOverflow)?;
        Ok(())
    }
    fn finish(&mut self) -> Result<(), Error> {
        let ledger = Layout::array::<AllocationCharge>(self.count)
            .map_err(|_| AllocationRefusal::DemandOverflow)?;
        self.bytes = self
            .bytes
            .checked_add(ledger.size())
            .ok_or(AllocationRefusal::DemandOverflow)?;
        Ok(())
    }
}
struct Construction {
    reservation: AllocationReservation,
    charges: Option<ChargedBuffer<AllocationCharge>>,
}
impl Drop for Construction {
    fn drop(&mut self) {
        // Detached fields may have an unwinding destructor. Do not turn uncertain reclamation
        // into retry capacity; exact normal drops below precede all refunds.
        if std::thread::panicking()
            && let Some(charges) = self.charges.take()
        {
            std::mem::forget(charges);
        }
    }
}
impl Construction {
    fn new(demand: &Demand, budget: &AllocationBudget) -> Result<Self, Error> {
        let mut reservation = budget.try_reserve_bytes(demand.bytes)?;
        let charges = ChargedBuffer::from_reservation(demand.count, &mut reservation)?;
        Ok(Self {
            reservation,
            charges: Some(charges),
        })
    }
    #[allow(unsafe_code)]
    fn vector<T>(&mut self, buffer: ChargedBuffer<T>) -> Vec<T> {
        // SAFETY: exact-capacity canonical fields never grow/change layout or escape. This
        // guard was declared before them and retains each charge through their destruction.
        let (values, charge) = unsafe { buffer.into_allocation_parts() };
        self.charges
            .as_mut()
            .expect("original construction")
            .push_reserved(charge);
        values
    }
    fn bytes(&mut self, source: &[u8]) -> Result<Vec<u8>, Error> {
        let mut output = ChargedBuffer::from_reservation(source.len(), &mut self.reservation)?;
        output
            .append(source)
            .map_err(|_| Error::Invalid("byte plan changed"))?;
        Ok(self.vector(output))
    }
    #[allow(unsafe_code)]
    fn finish(
        mut self,
        proof: AmxRecordProofV1,
        budget: &AllocationBudget,
    ) -> Result<AllocatedAmxRecordProofV1, Error> {
        let complete = self.reservation.remaining_bytes() == 0
            && self
                .charges
                .as_ref()
                .expect("original construction")
                .as_slice()
                .len()
                == self
                    .charges
                    .as_ref()
                    .expect("original construction")
                    .capacity();
        if !complete {
            drop(proof);
            return Err(Error::Invalid("exact proof plan changed"));
        }
        let charges = self.charges.take().expect("original construction");
        // SAFETY: three byte buffers, exact compressed siblings and the optional Begin vector
        // exhaust this closed DTO's heap fields. No sharing, mutation, Clone or extraction.
        match unsafe { RetainedPayload::try_new(proof, charges, budget) } {
            Ok(owner) => Ok(AllocatedAmxRecordProofV1(owner)),
            Err((proof, charges, _)) => {
                drop(proof);
                drop(charges);
                Err(Error::Invalid("foreign proof pool"))
            }
        }
    }
}

#[derive(Clone, Copy)]
enum RawRecord {
    Begin {
        tx: [u8; 32],
        deadline: u64,
        count: usize,
        participants: [DataSpaceId; MAX_AMX_PARTICIPANTS],
    },
    Prepared(AmxPreparedV1),
    Decision(AmxDecisionV1),
}
impl RawRecord {
    fn scan(payload: &[u8]) -> Result<Self, norito::Error> {
        let tag = record_tag(payload)?;
        let mut offset = 4;
        let record = match tag {
            0 => fixed_field::<AmxBeginV1, _>(payload, &mut offset, |body| {
                let mut field_offset = 0;
                let tx = ncore::framed_byte_array_field::<32>(body, &mut field_offset)?
                    .decode_owned()?;
                let read_participants = |bytes: &[u8]| {
                    let (count, mut participant_offset) = ncore::read_seq_len_slice(bytes)?;
                    if !(MIN_AMX_PARTICIPANTS..=MAX_AMX_PARTICIPANTS).contains(&count) {
                        return Err(norito::Error::LengthMismatch);
                    }
                    let mut parsed = [DataSpaceId::new(0); MAX_AMX_PARTICIPANTS];
                    for item in parsed.iter_mut().take(count) {
                        *item = fixed_field::<DataSpaceId, _>(
                            bytes,
                            &mut participant_offset,
                            fixed_dataspace,
                        )?;
                    }
                    finish_fixed(bytes, participant_offset)?;
                    Ok((count, parsed))
                };
                // DM4 skips only this canonical field's payload context, recreating the old
                // missing depth/field-boundary defect. Framing and borrowed stack parsing stay.
                #[cfg(all(test, sumeragi_model_mutation = "DM4"))]
                let (count, participants) = {
                    let field = ncore::framed_field::<Vec<DataSpaceId>>(body, &mut field_offset)?;
                    read_participants(field.bytes())?
                };
                #[cfg(not(all(test, sumeragi_model_mutation = "DM4")))]
                let (count, participants) =
                    fixed_field::<Vec<DataSpaceId>, _>(body, &mut field_offset, read_participants)?;
                let deadline = fixed_field::<u64, _>(body, &mut field_offset, fixed::<u64>)?;
                finish_fixed(body, field_offset)?;
                Ok(Self::Begin {
                    tx,
                    deadline,
                    count,
                    participants,
                })
            })?,
            1 => fixed_field::<AmxPreparedV1, _>(payload, &mut offset, fixed_prepared)
                .map(Self::Prepared)?,
            2 => fixed_field::<AmxDecisionV1, _>(payload, &mut offset, fixed_decision)
                .map(Self::Decision)?,
            _ => return Err(norito::Error::LengthMismatch),
        };
        finish_fixed(payload, offset)?;
        Ok(record)
    }
    fn materialize(self, construction: &mut Construction) -> Result<AmxRecordV1, Error> {
        Ok(match self {
            Self::Prepared(value) => AmxRecordV1::Prepared(value),
            Self::Decision(value) => AmxRecordV1::Decision(value),
            Self::Begin {
                tx,
                deadline,
                count,
                participants: parsed,
            } => {
                let mut participants =
                    ChargedBuffer::from_reservation(count, &mut construction.reservation)?;
                for participant in parsed.into_iter().take(count) {
                    participants.push_reserved(participant);
                }
                AmxRecordV1::Begin(AmxBeginV1 {
                    tx,
                    participants: construction.vector(participants),
                    deadline,
                })
            }
        })
    }
}
// The existing canonical field owner installs the original field ceiling, depth and flags.
// These closed stack projections never invoke an archived/derived alignment-copy decoder.
fn fixed_field<T, R>(
    payload: &[u8],
    offset: &mut usize,
    decode: impl FnOnce(&[u8]) -> Result<R, norito::Error>,
) -> Result<R, norito::Error>
where
    T: for<'de> norito::DeserializePayload<'de> + norito::SerializePayload,
{
    ncore::framed_field::<T>(payload, offset)?
        .with_payload(|bytes| {
            decode(bytes).map_err(ncore::DecodeIntoError::<std::convert::Infallible>::Codec)
        })
        .map_err(ncore::DecodeIntoError::into_codec)
}
fn finish_fixed(payload: &[u8], offset: usize) -> Result<(), norito::Error> {
    if offset != payload.len() {
        return Err(norito::Error::LengthMismatch);
    }
    ncore::finish_context_fields(payload.as_ptr(), offset)
}
fn record_tag(payload: &[u8]) -> Result<u32, norito::Error> {
    Ok(u32::from_le_bytes(
        payload
            .get(..4)
            .ok_or(norito::Error::LengthMismatch)?
            .try_into()
            .map_err(|_| norito::Error::LengthMismatch)?,
    ))
}
fn fixed_dataspace(payload: &[u8]) -> Result<DataSpaceId, norito::Error> {
    let mut offset = 0;
    let value = fixed_field::<u64, _>(payload, &mut offset, fixed::<u64>)?;
    finish_fixed(payload, offset)?;
    Ok(DataSpaceId::new(value))
}
fn fixed_prepared(payload: &[u8]) -> Result<AmxPreparedV1, norito::Error> {
    let mut offset = 0;
    let tx = ncore::framed_byte_array_field::<32>(payload, &mut offset)?.decode_owned()?;
    let participant = fixed_field::<DataSpaceId, _>(payload, &mut offset, fixed_dataspace)?;
    let vote = fixed_field::<AmxVoteV1, _>(payload, &mut offset, |vote| {
        let mut offset = 4;
        let result = match record_tag(vote)? {
            0 => AmxVoteV1::Yes(
                ncore::framed_byte_array_field::<32>(vote, &mut offset)?.decode_owned()?,
            ),
            1 => AmxVoteV1::No,
            _ => return Err(norito::Error::LengthMismatch),
        };
        finish_fixed(vote, offset)?;
        Ok(result)
    })?;
    finish_fixed(payload, offset)?;
    Ok(AmxPreparedV1 {
        tx,
        participant,
        vote,
    })
}
fn fixed_decision(payload: &[u8]) -> Result<AmxDecisionV1, norito::Error> {
    let mut offset = 0;
    let tx = ncore::framed_byte_array_field::<32>(payload, &mut offset)?.decode_owned()?;
    let outcome = fixed_field::<AmxOutcomeV1, _>(payload, &mut offset, |outcome| {
        let result = match record_tag(outcome)? {
            0 => AmxOutcomeV1::Commit,
            1 => AmxOutcomeV1::Abort,
            _ => return Err(norito::Error::LengthMismatch),
        };
        finish_fixed(outcome, 4)?;
        Ok(result)
    })?;
    finish_fixed(payload, offset)?;
    Ok(AmxDecisionV1 { tx, outcome })
}
fn fixed<T>(bytes: &[u8]) -> Result<T, norito::Error>
where
    T: Copy
        + for<'de> norito::core::DecodeFromSlice<'de>
        + for<'de> norito::DeserializePayload<'de>,
{
    let (value, used) = ncore::decode_field_canonical_slice::<T>(bytes)?;
    if used != bytes.len() {
        return Err(norito::Error::LengthMismatch);
    }
    Ok(value)
}
struct ExactWriter<'a> {
    expected: &'a [u8],
    offset: usize,
}
impl std::io::Write for ExactWriter<'_> {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        let end = self
            .offset
            .checked_add(bytes.len())
            .ok_or(std::io::ErrorKind::InvalidData)?;
        if self.expected.get(self.offset..end) != Some(bytes) {
            return Err(std::io::ErrorKind::InvalidData.into());
        }
        self.offset = end;
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[derive(Clone, Copy)]
struct Node {
    path: [u8; 32],
    hash: Hash,
    source: usize,
}
fn lookup<'a>(nodes: &'a [Node], path: &[u8; 32]) -> Option<&'a Node> {
    nodes
        .binary_search_by_key(path, |node| node.path)
        .ok()
        .map(|index| &nodes[index])
}
type OriginalPath = ([u8; 32], [[u8; 32]; 256], Hash);

fn original_path(
    witness: &ExecWitness,
    key: &[u8],
    budget: &AllocationBudget,
) -> Result<OriginalPath, Error> {
    let count = witness.writes.len();
    let capacity = count
        .checked_mul(2)
        .ok_or(AllocationRefusal::DemandOverflow)?;
    let scratch = Layout::array::<Node>(capacity).map_err(|_| AllocationRefusal::DemandOverflow)?;
    ncore::reserve_decode_allocation(scratch.size())?;
    let mut storage = ChargedBuffer::new(capacity, budget)?;
    let empty = Hash::new([]);
    for _ in 0..capacity {
        storage.push_reserved(Node {
            path: [0; 32],
            hash: empty,
            source: 0,
        });
    }
    let (mut current, mut next) = storage.as_mut_slice().split_at_mut(count);
    for (source, write) in witness.writes.iter().enumerate() {
        let path = Hash::new(&write.key);
        let value = Hash::new(&write.value);
        current[source] = Node {
            path: path.into(),
            hash: Hash::new_from_chunks(&[&[0], path.as_ref(), value.as_ref()]),
            source,
        };
    }
    current.sort_unstable_by_key(|node| (node.path, node.source));
    let mut length = 0;
    for source in 0..current.len() {
        let node = current[source];
        if length > 0 && current[length - 1].path == node.path {
            if witness.writes[current[length - 1].source].key != witness.writes[node.source].key {
                return Err(Error::Invalid("ordinary-write key-path collision"));
            }
            current[length - 1] = node;
        } else {
            current[length] = node;
            length += 1;
        }
    }
    let mut target: [u8; 32] = Hash::new(key).into();
    let mut present = [0_u8; 32];
    let mut siblings = [[0_u8; 32]; 256];
    for (level, output) in siblings.iter_mut().enumerate() {
        let bit = 255 - level;
        let byte = bit / 8;
        let mask = 1_u8 << (bit % 8);
        let mut sibling = target;
        sibling[byte] ^= mask;
        let hash = lookup(&current[..length], &sibling).map_or(empty, |node| node.hash);
        *output = hash.into();
        if hash != empty {
            present[level / 8] |= 1 << (level % 8);
        }
        let mut out = 0;
        for node in &current[..length] {
            let mut sibling = node.path;
            sibling[byte] ^= mask;
            let other = lookup(&current[..length], &sibling);
            let right = node.path[byte] & mask != 0;
            if right && other.is_some() {
                continue;
            }
            let other_hash = other.map_or(empty, |node| node.hash);
            let (left, right) = if right {
                (other_hash, node.hash)
            } else {
                (node.hash, other_hash)
            };
            let mut parent = node.path;
            parent[byte] &= !mask;
            next[out] = Node {
                path: parent,
                hash: Hash::new_from_chunks(&[&[1], left.as_ref(), right.as_ref()]),
                source: 0,
            };
            out += 1;
        }
        next[..out].sort_unstable_by_key(|node| node.path);
        target[byte] &= !mask;
        std::mem::swap(&mut current, &mut next);
        length = out;
    }
    if length != 1 {
        return Err(Error::Invalid("ordinary-write tree geometry"));
    }
    Ok((present, siblings, current[0].hash))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::block::consensus::ExecKv;

    #[test]
    fn original_funded_amx_path_matches_canonical_duplicate_default_and_unrelated_writes() {
        let tx = [0x5a; 32];
        let key = amx_record_witness_key(AmxRecordKind::Begin, tx);
        let value = |deadline| {
            norito::encode_canonical(&AmxRecordV1::Begin(AmxBeginV1 {
                tx,
                participants: vec![DataSpaceId::new(21), DataSpaceId::new(22)],
                deadline,
            }))
            .unwrap()
        };
        for unrelated in [0, 1, 7, 31] {
            for duplicate in [false, true] {
                let mut writes = Vec::new();
                if duplicate {
                    writes.push(ExecKv {
                        key: key.to_vec(),
                        value: value(10),
                    });
                }
                for index in 0..unrelated {
                    writes.push(ExecKv {
                        key: vec![index, 0x17],
                        value: vec![index, 0x31, 0xa4],
                    });
                }
                let original = value(11);
                writes.push(ExecKv {
                    key: key.to_vec(),
                    value: original.clone(),
                });
                let witness = ExecWitness {
                    writes,
                    ..ExecWitness::default()
                };
                let (canonical, selected) = AmxWriteProofV1::from_writes(
                    witness
                        .writes
                        .iter()
                        .map(|write| (write.key.as_slice(), write.value.as_slice())),
                    &key,
                )
                .unwrap();
                assert_eq!(
                    selected, original,
                    "the last write is the actual canonical record"
                );
                let budget = AllocationBudget::new(1 << 20);
                let (present, siblings, root) = original_path(&witness, &key, &budget).unwrap();
                assert_eq!(present, canonical.present);
                let compressed = siblings
                    .iter()
                    .enumerate()
                    .filter_map(|(level, hash)| {
                        (present[level / 8] & (1 << (level % 8)) != 0).then_some(*hash)
                    })
                    .collect::<Vec<_>>();
                assert_eq!(compressed, canonical.siblings);
                assert_eq!(root, canonical.root(&key, &original).unwrap());
                if unrelated == 0 {
                    assert_eq!(present, [0; 32]);
                    assert!(compressed.is_empty());
                } else {
                    assert!(!compressed.is_empty());
                }
                assert_eq!(
                    budget.reserved_bytes(),
                    0,
                    "only real temporary charged scratch was allocated"
                );
                let ceiling = original_scratch_layout(&witness).size();
                let insufficient = AllocationBudget::new(ceiling - 1);
                assert!(matches!(
                    original_path(&witness, &key, &insufficient),
                    Err(Error::Scratch(ChargedBufferError::Admission(
                        AllocationRefusal::ExceedsLimit { .. }
                    )))
                ));
                assert_eq!(insufficient.reserved_bytes(), 0);
            }
        }
    }

    fn original_scratch_layout(witness: &ExecWitness) -> Layout {
        Layout::array::<Node>(witness.writes.len().checked_mul(2).unwrap()).unwrap()
    }

    fn scan_fixed_frame(frame: &[u8]) -> Result<AmxRecordV1, norito::Error> {
        let view = ncore::from_bytes_view(frame)?;
        let record = view.decode_exact_with::<AmxRecordV1, _, _>(|payload| {
            let record = match RawRecord::scan(payload)? {
                RawRecord::Prepared(value) => AmxRecordV1::Prepared(value),
                RawRecord::Decision(value) => AmxRecordV1::Decision(value),
                RawRecord::Begin { .. } => return Err(norito::Error::LengthMismatch),
            };
            Ok((record, payload.len()))
        })?;
        let mut exact = ExactWriter {
            expected: frame,
            offset: 0,
        };
        ncore::write_canonical_to_writer(&record, &mut exact)?;
        if exact.offset != frame.len() {
            return Err(norito::Error::NonCanonicalEncoding);
        }
        Ok(record)
    }

    fn fixed_records() -> [AmxRecordV1; 4] {
        [
            AmxRecordV1::Prepared(AmxPreparedV1 {
                tx: [0x71; 32],
                participant: DataSpaceId::new(21),
                vote: AmxVoteV1::Yes([0xa3; 32]),
            }),
            AmxRecordV1::Prepared(AmxPreparedV1 {
                tx: [0x72; 32],
                participant: DataSpaceId::new(22),
                vote: AmxVoteV1::No,
            }),
            AmxRecordV1::Decision(AmxDecisionV1 {
                tx: [0x73; 32],
                outcome: AmxOutcomeV1::Commit,
            }),
            AmxRecordV1::Decision(AmxDecisionV1 {
                tx: [0x74; 32],
                outcome: AmxOutcomeV1::Abort,
            }),
        ]
    }

    #[test]
    fn fixed_amx_record_scan_matches_all_canonical_variants_without_alignment_allocation() {
        let limits = norito::DecodeLimits::new(0, usize::MAX, 0, 0, 8);
        for original in fixed_records() {
            let frame = norito::encode_canonical(&original).unwrap();
            // Each input allocation precedes the zero-allocation decode scope.
            // Eight offsets exercise every u64 alignment, including misaligned leaves.
            for offset in 0..8 {
                let mut input = vec![0xff; offset];
                input.extend_from_slice(&frame);
                let frame = &input[offset..];
                let view = ncore::from_bytes_view(frame).unwrap();
                assert_eq!(view.flags(), ncore::default_encode_flags());
                let (result, usage) =
                    ncore::with_decode_limits_measured(limits, || scan_fixed_frame(frame));
                assert_eq!(result.unwrap(), original);
                assert_eq!(usage.total_elements(), 0);
                assert_eq!(usage.total_allocated_bytes(), 0);
            }
        }
    }

    fn framed_test_field(bytes: &[u8]) -> Vec<u8> {
        let mut output = Vec::new();
        ncore::write_len_to_vec_with_flags(
            &mut output,
            u64::try_from(bytes.len()).unwrap(),
            ncore::default_encode_flags(),
        );
        output.extend_from_slice(bytes);
        output
    }

    fn fixed_test_record_payload(tag: u32, fields: &[Vec<u8>]) -> Vec<u8> {
        let body = fields.concat();
        let mut payload = tag.to_le_bytes().to_vec();
        payload.extend_from_slice(&framed_test_field(&body));
        payload
    }

    #[test]
    fn fixed_amx_record_scan_rejects_malformed_fields_tags_and_trailing_bodies() {
        let tx = framed_test_field(&[0x71; 32]);
        let participant = framed_test_field(&framed_test_field(&21_u64.to_le_bytes()));
        let mut yes = 0_u32.to_le_bytes().to_vec();
        yes.extend_from_slice(&framed_test_field(&[0xa3; 32]));
        let no = 1_u32.to_le_bytes().to_vec();
        let commit = 0_u32.to_le_bytes().to_vec();
        let abort = 1_u32.to_le_bytes().to_vec();
        let prepared = |tx: Vec<u8>, participant: Vec<u8>, vote: Vec<u8>| {
            fixed_test_record_payload(1, &[tx, participant, framed_test_field(&vote)])
        };
        let decision = |tx: Vec<u8>, outcome: Vec<u8>| {
            fixed_test_record_payload(2, &[tx, framed_test_field(&outcome)])
        };
        // Independent field construction must first match the actual derived canonical codec.
        let expected = fixed_records();
        for (original, payload) in [
            (
                &expected[0],
                prepared(tx.clone(), participant.clone(), yes.clone()),
            ),
            (
                &expected[1],
                prepared(
                    framed_test_field(&[0x72; 32]),
                    framed_test_field(&framed_test_field(&22_u64.to_le_bytes())),
                    no.clone(),
                ),
            ),
            (
                &expected[2],
                decision(framed_test_field(&[0x73; 32]), commit.clone()),
            ),
            (
                &expected[3],
                decision(framed_test_field(&[0x74; 32]), abort.clone()),
            ),
        ] {
            assert_eq!(
                ncore::frame_bare_with_header_flags::<AmxRecordV1>(
                    &payload,
                    ncore::default_encode_flags(),
                )
                .unwrap(),
                norito::encode_canonical(original).unwrap(),
            );
        }
        let mut malformed = vec![
            vec![1, 0, 0],
            1_u32.to_le_bytes().to_vec(),
            fixed_test_record_payload(3, &[]),
            prepared(Vec::new(), participant.clone(), yes.clone()),
            prepared(
                framed_test_field(&[0x71; 31]),
                participant.clone(),
                yes.clone(),
            ),
            prepared(
                tx.clone(),
                framed_test_field(&framed_test_field(&[0; 7])),
                yes.clone(),
            ),
            prepared(tx.clone(), participant.clone(), Vec::new()),
            prepared(tx.clone(), participant.clone(), vec![0, 0, 0]),
            prepared(
                tx.clone(),
                participant.clone(),
                2_u32.to_le_bytes().to_vec(),
            ),
            decision(Vec::new(), commit.clone()),
            decision(framed_test_field(&[0x73; 31]), commit.clone()),
            decision(tx.clone(), Vec::new()),
            decision(tx.clone(), vec![0, 0, 0]),
            decision(tx.clone(), 2_u32.to_le_bytes().to_vec()),
        ];
        for vote in [yes, no] {
            let mut trailing = vote.clone();
            trailing.push(0x17);
            malformed.push(prepared(tx.clone(), participant.clone(), trailing));
        }
        for outcome in [commit, abort] {
            let mut trailing = outcome;
            trailing.push(0x17);
            malformed.push(decision(tx.clone(), trailing));
        }
        let mut short_yes = 0_u32.to_le_bytes().to_vec();
        short_yes.extend_from_slice(&framed_test_field(&[0xa3; 31]));
        malformed.push(prepared(tx.clone(), participant.clone(), short_yes));
        for tag in [1, 2] {
            let mut fields = if tag == 1 {
                vec![
                    tx.clone(),
                    participant.clone(),
                    framed_test_field(&1_u32.to_le_bytes()),
                ]
            } else {
                vec![tx.clone(), framed_test_field(&0_u32.to_le_bytes())]
            };
            fields.push(vec![0x17]);
            malformed.push(fixed_test_record_payload(tag, &fields));
            let mut trailing = fixed_test_record_payload(tag, &fields[..fields.len() - 1]);
            trailing.push(0x17);
            malformed.push(trailing);
        }
        let limits = norito::DecodeLimits::new(0, usize::MAX, 0, 0, 8);
        for payload in malformed {
            // A correct header/checksum must not hide malformed fields or nested enum bodies.
            let frame = ncore::frame_bare_with_header_flags::<AmxRecordV1>(
                &payload,
                ncore::default_encode_flags(),
            )
            .unwrap();
            let (result, usage) =
                ncore::with_decode_limits_measured(limits, || scan_fixed_frame(&frame));
            assert!(matches!(result, Err(norito::Error::LengthMismatch)));
            assert_eq!(usage.total_elements(), 0);
            assert_eq!(usage.total_allocated_bytes(), 0);
        }
    }

    #[test]
    fn fixed_amx_record_scan_preserves_original_field_depth_refusal_and_exact_retry() {
        for original in fixed_records() {
            let frame = norito::encode_canonical(&original).unwrap();
            let original_pointer = frame.as_ptr();
            let view = ncore::from_bytes_view(&frame).unwrap();
            let (field_len, _) =
                ncore::read_len_from_slice_with_flags(&view.as_bytes()[4..], view.flags()).unwrap();
            for (limits, expected) in [
                (
                    norito::DecodeLimits::new(0, 1, 0, 0, 8),
                    ncore::DecodeResourceError::FieldLengthExceeded {
                        length: u64::try_from(field_len).unwrap(),
                        limit: 1,
                    },
                ),
                (
                    norito::DecodeLimits::new(0, usize::MAX, 0, 0, 0),
                    ncore::DecodeResourceError::NestingDepthExceeded {
                        depth: 1,
                        limit: 0,
                        context: "decode budget",
                    },
                ),
            ] {
                for _ in 0..2 {
                    let failure = norito::with_decode_limits_scope(limits, || {
                        ncore::classify_decode_attempt(|| scan_fixed_frame(&frame))
                    })
                    .unwrap_err();
                    assert_eq!(
                        failure.kind(),
                        ncore::DecodeAttemptErrorKind::EnclosingLimit
                    );
                    assert_eq!(failure.into_error().decode_resource_error(), Some(expected));
                    assert_eq!(frame.as_ptr(), original_pointer);
                }
            }
            let (retry, usage) = ncore::with_decode_limits_measured(
                norito::DecodeLimits::new(0, usize::MAX, 0, 0, 8),
                || scan_fixed_frame(&frame),
            );
            assert_eq!(retry.unwrap(), original);
            assert_eq!(usage.total_elements(), 0);
            assert_eq!(usage.total_allocated_bytes(), 0);
            assert_eq!(frame.as_ptr(), original_pointer);
        }
    }

    fn scan_original_begin_frame(frame: &[u8]) -> Result<RawRecord, norito::Error> {
        let view = ncore::from_bytes_view(frame)?;
        if view.flags() != ncore::default_encode_flags() {
            return Err(norito::Error::NonCanonicalEncoding);
        }
        view.decode_exact_with::<AmxRecordV1, _, _>(|payload| {
            Ok((RawRecord::scan(payload)?, payload.len()))
        })
    }

    #[test]
    fn original_begin_record_scan_preserves_canonical_depth_refusal_and_exact_retry() {
        for count in [MIN_AMX_PARTICIPANTS, MAX_AMX_PARTICIPANTS] {
            let original = AmxRecordV1::Begin(AmxBeginV1 {
                tx: [0x75; 32],
                participants: (1..=count)
                    .map(|value| DataSpaceId::new(u64::try_from(value).unwrap()))
                    .collect(),
                deadline: 17,
            });
            let frame = norito::encode_canonical(&original).unwrap();
            let pointer = frame.as_ptr();
            // Whole-frame owning decode adds its root value context. Its five levels are
            // root/Begin/Vec/DataSpaceId/u64. The prepared ArchiveView root does not enter
            // that extra context: the same four nested fields must still be enforced.
            let owning_limits = norito::DecodeLimits::new(count, usize::MAX, count, usize::MAX, 4);
            let owning = norito::decode_canonical_with_limits::<AmxRecordV1>(&frame, owning_limits)
                .unwrap_err();
            assert_eq!(
                owning.decode_resource_error(),
                Some(ncore::DecodeResourceError::NestingDepthExceeded {
                    depth: 5,
                    limit: 4,
                    context: "decode budget",
                })
            );
            let expected = ncore::DecodeResourceError::NestingDepthExceeded {
                depth: 4,
                limit: 3,
                context: "decode budget",
            };
            for _ in 0..2 {
                let failure = norito::with_decode_limits_scope(
                    norito::DecodeLimits::new(count, usize::MAX, count, usize::MAX, 3),
                    || ncore::classify_decode_attempt(|| scan_original_begin_frame(&frame)),
                )
                .err()
                .expect("original Begin field must retain its enclosing depth refusal");
                assert_eq!(
                    failure.kind(),
                    ncore::DecodeAttemptErrorKind::EnclosingLimit
                );
                assert_eq!(failure.into_error().decode_resource_error(), Some(expected));
                assert_eq!(frame.as_ptr(), pointer);
            }
            let (retry, usage) = ncore::with_decode_limits_measured(
                norito::DecodeLimits::new(count, usize::MAX, count, count, 4),
                || scan_original_begin_frame(&frame),
            );
            let RawRecord::Begin {
                tx,
                participants,
                count: decoded_count,
                deadline,
            } = retry.unwrap()
            else {
                panic!("exact original Begin variant");
            };
            let AmxRecordV1::Begin(begin) = &original else {
                unreachable!("fixture Begin");
            };
            assert_eq!(tx, begin.tx);
            assert_eq!(decoded_count, count);
            assert_eq!(
                &participants[..decoded_count],
                begin.participants.as_slice()
            );
            assert_eq!(deadline, begin.deadline);
            assert_eq!(usage.total_elements(), count);
            // read_seq_len_slice retains the pre-existing logical count charge. No body,
            // alignment, Vec or span backing is allocated by this stack projection.
            assert_eq!(usage.total_allocated_bytes(), count);
            assert_eq!(frame.as_ptr(), pointer);
            assert_eq!(
                norito::decode_canonical_with_limits::<AmxRecordV1>(
                    &frame,
                    norito::DecodeLimits::new(count, usize::MAX, count, usize::MAX, 5),
                )
                .unwrap(),
                original
            );
        }
    }

    #[test]
    fn original_begin_record_scan_preserves_sequence_ceiling_and_scalar_field_geometry() {
        let count = MIN_AMX_PARTICIPANTS;
        let original = AmxRecordV1::Begin(AmxBeginV1 {
            tx: [0x75; 32],
            participants: (1..=count)
                .map(|value| DataSpaceId::new(u64::try_from(value).unwrap()))
                .collect(),
            deadline: 17,
        });
        let frame = norito::encode_canonical(&original).unwrap();
        let failure = norito::with_decode_limits_scope(
            norito::DecodeLimits::new(count - 1, usize::MAX, count, usize::MAX, 4),
            || ncore::classify_decode_attempt(|| scan_original_begin_frame(&frame)),
        )
        .err()
        .expect("original declared sequence ceiling");
        assert_eq!(
            failure.kind(),
            ncore::DecodeAttemptErrorKind::EnclosingLimit
        );
        assert_eq!(
            failure.into_error().decode_resource_error(),
            Some(ncore::DecodeResourceError::SequenceLengthExceeded {
                length: u64::try_from(count).unwrap(),
                limit: u64::try_from(count - 1).unwrap(),
            })
        );
        // Isolate the actual original scalar field inside its Begin context. This uses the
        // same fixed_field kernel as production, borrowing the other two canonical fields.
        // It has no sequence materialization/count or alignment-copy obligation.
        let scalar_deadline = || {
            let view = ncore::from_bytes_view(&frame)?;
            view.decode_exact_with::<AmxRecordV1, _, _>(|payload| {
                let mut offset = 4;
                let deadline = fixed_field::<AmxBeginV1, _>(payload, &mut offset, |body| {
                    let mut offset = 0;
                    ncore::framed_byte_array_field::<32>(body, &mut offset)?;
                    ncore::framed_field::<Vec<DataSpaceId>>(body, &mut offset)?;
                    let deadline = fixed_field::<u64, _>(body, &mut offset, fixed::<u64>)?;
                    finish_fixed(body, offset)?;
                    Ok(deadline)
                })?;
                finish_fixed(payload, offset)?;
                Ok((deadline, offset))
            })
        };
        let failure = norito::with_decode_limits_scope(
            norito::DecodeLimits::new(0, usize::MAX, 0, 0, 1),
            || ncore::classify_decode_attempt(scalar_deadline),
        )
        .unwrap_err();
        assert_eq!(
            failure.kind(),
            ncore::DecodeAttemptErrorKind::EnclosingLimit
        );
        assert_eq!(
            failure.into_error().decode_resource_error(),
            Some(ncore::DecodeResourceError::NestingDepthExceeded {
                depth: 2,
                limit: 1,
                context: "decode budget",
            })
        );
        let (retry, usage) = ncore::with_decode_limits_measured(
            norito::DecodeLimits::new(0, usize::MAX, 0, 0, 2),
            scalar_deadline,
        );
        assert_eq!(retry.unwrap(), 17);
        assert_eq!(usage.total_elements(), 0);
        assert_eq!(usage.total_allocated_bytes(), 0);
        let mut participants = u64::try_from(count).unwrap().to_le_bytes().to_vec();
        for value in 1..=count {
            participants.extend_from_slice(&framed_test_field(&framed_test_field(
                &u64::try_from(value).unwrap().to_le_bytes(),
            )));
        }
        let fields = [
            framed_test_field(&[0x75; 32]),
            framed_test_field(&participants),
            framed_test_field(&17_u64.to_le_bytes()),
        ];
        let payload = fixed_test_record_payload(0, &fields);
        assert_eq!(
            ncore::frame_bare_with_header_flags::<AmxRecordV1>(
                &payload,
                ncore::default_encode_flags(),
            )
            .unwrap(),
            frame
        );
        let mut malformed = Vec::new();
        for bytes in [&[][..], &[0_u8; 7][..], &[0_u8; 9][..]] {
            let mut changed = fields.clone();
            changed[2] = framed_test_field(bytes);
            malformed.push(fixed_test_record_payload(0, &changed));
        }
        let mut changed = fields.clone();
        changed[0] = framed_test_field(&[0x75; 31]);
        malformed.push(fixed_test_record_payload(0, &changed));
        let mut trailing = participants;
        trailing.push(0x17);
        let mut changed = fields.clone();
        changed[1] = framed_test_field(&trailing);
        malformed.push(fixed_test_record_payload(0, &changed));
        let mut trailing = payload.clone();
        trailing.push(0x17);
        malformed.push(trailing);
        for payload in malformed {
            let frame = ncore::frame_bare_with_header_flags::<AmxRecordV1>(
                &payload,
                ncore::default_encode_flags(),
            )
            .unwrap();
            let failure = norito::with_decode_limits_scope(
                norito::DecodeLimits::new(count, usize::MAX, count, usize::MAX, 4),
                || scan_original_begin_frame(&frame),
            );
            assert!(matches!(failure, Err(norito::Error::LengthMismatch)));
        }
        // A well-checksummed alternate layout must not enter the canonical source scanner.
        let flags = ncore::default_encode_flags() ^ ncore::header_flags::COMPACT_LEN;
        let alternate =
            ncore::frame_bare_with_header_flags::<AmxRecordV1>(&payload, flags).unwrap();
        assert!(matches!(
            scan_original_begin_frame(&alternate),
            Err(norito::Error::NonCanonicalEncoding)
        ));
    }
}
