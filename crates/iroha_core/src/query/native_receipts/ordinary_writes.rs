//! Exact original-pool custody for the archived ordinary-write graph.
//!
//! The frame scanner borrows bytes and plans every write/key/value allocation before any
//! materialization. The complete ledger remains attached to the immutable witness until drop.
//! Lane values remain borrowed bytes until equality with their authenticated commitment.
//! TODO(S8): native proof graphs and downstream receipt/tree
//! construction still need their own original-pool owners. This owner funds none of those.

mod casting;
pub(super) use casting::CastingOwner;
use casting::RawCasting;

use crate::state::NativeExecutionProjectionV1;
use iroha_allocation::{
    AllocationBudget, AllocationCharge, AllocationRefusal, AllocationReservation, ChargedBuffer,
    PrepaidBufferError, RetainedPayload,
};
use iroha_crypto::HashOf;
use iroha_data_model::{
    block::{
        BlockHeader,
        consensus::{ExecKv, ExecWitness},
    },
    sumeragi_lanes::SumeragiLaneState,
};
use norito::core::{self as ncore, SerializePayload};
use std::alloc::Layout;

/// A source/canonical failure remains distinct from original-pool resource refusal.
#[derive(Debug, thiserror::Error)]
pub(crate) enum WriteDecodeError {
    /// The caller offered encoded bytes retained by a different original pool.
    #[error("native write source belongs to another allocation pool")]
    ForeignPool,
    /// Canonical frame or field validation failed.
    #[error(transparent)]
    Codec(#[from] norito::Error),
    /// The complete concrete layout demand was not admitted.
    #[error(transparent)]
    Admission(#[from] AllocationRefusal),
    /// An already admitted exact allocation or split failed.
    #[error(transparent)]
    Materialization(#[from] PrepaidBufferError),
    /// Internal scanning and construction disagreed; no substituted allocation is allowed.
    #[error("native write allocation plan changed")]
    PlanChanged,
}

/// Decoded archive fields with independent, move-only custody of every ordinary write.
/// Lane payload bytes borrow the original charged frame and confer no authority before the
/// complete commitment matches the independently authenticated native result.
pub(crate) struct DecodedProjection<'a> {
    /// Original carrier height.
    pub(crate) carrier_height: u64,
    /// Original carrier identity.
    pub(crate) carrier_hash: HashOf<BlockHeader>,
    /// Complete lane payload, still borrowing the original input owner.
    pub(super) lane_payload: &'a [u8],
    /// Exact SCCP delta preimage, joined to the sole synthetic ordinary write.
    pub(super) sccp_delta: &'a [u8],
    /// Typed original complete casting corpus.
    pub(super) casting_bindings: CastingOwner,
    /// All ordinary-write allocations retained in their original pool.
    pub(crate) witness: RetainedPayload<ExecWitness>,
}

fn field<'a>(bytes: &mut &'a [u8], flags: u8) -> Result<&'a [u8], norito::Error> {
    let (length, prefix) = ncore::read_len_from_slice_with_flags(bytes, flags)?;
    let end = prefix
        .checked_add(length)
        .ok_or(norito::Error::LengthMismatch)?;
    let value = bytes
        .get(prefix..end)
        .ok_or(norito::Error::LengthMismatch)?;
    *bytes = bytes.get(end..).ok_or(norito::Error::LengthMismatch)?;
    Ok(value)
}
fn fields<const N: usize>(mut bytes: &[u8], flags: u8) -> Result<[&[u8]; N], norito::Error> {
    let mut output = [&[][..]; N];
    for item in &mut output {
        *item = field(&mut bytes, flags)?;
    }
    if !bytes.is_empty() {
        return Err(norito::Error::LengthMismatch);
    }
    Ok(output)
}
fn count(bytes: &[u8]) -> Result<(usize, &[u8]), norito::Error> {
    let prefix = bytes.get(..8).ok_or(norito::Error::LengthMismatch)?;
    let count = usize::try_from(u64::from_le_bytes(prefix.try_into().expect("eight bytes")))
        .map_err(|_| norito::Error::LengthMismatch)?;
    Ok((count, &bytes[8..]))
}
fn raw_bytes(bytes: &[u8]) -> Result<&[u8], norito::Error> {
    let (length, raw) = count(bytes)?;
    if length != raw.len() {
        return Err(norito::Error::LengthMismatch);
    }
    Ok(raw)
}
// Re-encode the existing projection fields without decoding or allocating the unused lane DTO.
// The zero-length alignment field preserves the original lane type on every architecture.
#[repr(C)]
struct LanePayload<'a> {
    bytes: &'a [u8],
    _alignment: [SumeragiLaneState; 0],
}
impl SerializePayload for LanePayload<'_> {
    fn serialize(&self, writer: &mut ncore::Encoder<'_>) -> Result<(), norito::Error> {
        ncore::note_compact_len_emitted();
        std::io::Write::write_all(writer, self.bytes)?;
        Ok(())
    }
    fn encoded_len_hint(&self) -> Option<usize> {
        Some(self.bytes.len())
    }
    fn encoded_len_exact(&self) -> Option<usize> {
        Some(self.bytes.len())
    }
}
#[derive(norito::Encode)]
struct MaterializedProjection<'a> {
    carrier_height: u64,
    carrier_hash: HashOf<BlockHeader>,
    lanes: LanePayload<'a>,
    ordinary_writes: Vec<ExecKv>,
    casting_bindings: Vec<super::CastingBinding>,
    sccp_delta: &'a [u8],
}
impl norito::NoritoSchema for MaterializedProjection<'_> {
    fn nominal_name() -> String {
        <NativeExecutionProjectionV1 as norito::NoritoSchema>::nominal_name()
    }
    fn static_frame_name() -> Option<&'static str> {
        <NativeExecutionProjectionV1 as norito::NoritoSchema>::static_frame_name()
    }
}
const _: () = assert!(
    std::mem::align_of::<MaterializedProjection<'_>>()
        == std::mem::align_of::<NativeExecutionProjectionV1>()
);

#[derive(Clone, Copy)]
struct RawWrites<'a> {
    count: usize,
    bytes: &'a [u8],
    flags: u8,
}
impl<'a> RawWrites<'a> {
    fn new(bytes: &'a [u8], flags: u8) -> Result<Self, norito::Error> {
        ncore::validate_header_flags(flags)?;
        let (count, bytes) = count(bytes)?;
        // Every element has a nonempty length prefix. This fails hostile counts before looping.
        if count > bytes.len() {
            return Err(norito::Error::LengthMismatch);
        }
        Ok(Self {
            count,
            bytes,
            flags,
        })
    }
    fn visit<E: From<norito::Error>>(
        &self,
        mut visit: impl FnMut(&'a [u8], &'a [u8]) -> Result<(), E>,
    ) -> Result<(), E> {
        let mut bytes = self.bytes;
        for _ in 0..self.count {
            let [key, value] = fields::<2>(field(&mut bytes, self.flags)?, self.flags)?;
            visit(raw_bytes(key)?, raw_bytes(value)?)?;
        }
        if !bytes.is_empty() {
            return Err(norito::Error::LengthMismatch.into());
        }
        Ok(())
    }
    fn demand(&self) -> Result<Demand, WriteDecodeError> {
        let charges = self
            .count
            .checked_mul(2)
            .and_then(|n| n.checked_add(1))
            .ok_or(AllocationRefusal::DemandOverflow)?;
        let mut bytes = array::<ExecKv>(self.count)?
            .size()
            .checked_add(array::<AllocationCharge>(charges)?.size())
            .ok_or(AllocationRefusal::DemandOverflow)?;
        self.visit::<WriteDecodeError>(|key, value| {
            bytes = bytes
                .checked_add(array::<u8>(key.len())?.size())
                .and_then(|n| n.checked_add(value.len()))
                .ok_or(AllocationRefusal::DemandOverflow)?;
            array::<u8>(value.len())?;
            Ok(())
        })?;
        Ok(Demand { bytes, charges })
    }
}
fn array<T>(count: usize) -> Result<Layout, AllocationRefusal> {
    Layout::array::<T>(count).map_err(|_| AllocationRefusal::DemandOverflow)
}
struct Demand {
    bytes: usize,
    charges: usize,
}

/// Declared before every materialized payload. On normal failure payloads drop first; on an
/// unwind we conservatively retain the ledger rather than refund uncertain reclamation.
struct Construction {
    reservation: AllocationReservation,
    charges: Option<ChargedBuffer<AllocationCharge>>,
}
impl Drop for Construction {
    fn drop(&mut self) {
        if std::thread::panicking() {
            if let Some(charges) = self.charges.take() {
                std::mem::forget(charges);
            }
        }
    }
}
impl Construction {
    fn new(demand: Demand, budget: &AllocationBudget) -> Result<Self, WriteDecodeError> {
        let mut reservation = budget.try_reserve_bytes(demand.bytes)?;
        let charges = ChargedBuffer::from_reservation(demand.charges, &mut reservation)?;
        Ok(Self {
            reservation,
            charges: Some(charges),
        })
    }
    #[allow(
        unsafe_code,
        reason = "exact buffers move into immutable witness fields with their original ledger"
    )]
    fn vector<T>(&mut self, buffer: ChargedBuffer<T>) -> Result<Vec<T>, WriteDecodeError> {
        // SAFETY: every caller moves this buffer directly into the declared witness graph and
        // never changes its capacity. The external construction guard outlives all such fields.
        let (values, charge) = unsafe { buffer.into_allocation_parts() };
        if let Err(charge) = self
            .charges
            .as_mut()
            .expect("construction ledger")
            .try_push(charge)
        {
            // A programmer plan mismatch cannot refund a possibly live nested allocation.
            std::mem::forget(charge);
            return Err(WriteDecodeError::PlanChanged);
        }
        Ok(values)
    }
    fn bytes(&mut self, bytes: &[u8]) -> Result<Vec<u8>, WriteDecodeError> {
        let mut output = ChargedBuffer::from_reservation(bytes.len(), &mut self.reservation)?;
        output
            .append(bytes)
            .map_err(|_| WriteDecodeError::PlanChanged)?;
        self.vector(output)
    }
    fn writes(&mut self, source: RawWrites<'_>) -> Result<Vec<ExecKv>, WriteDecodeError> {
        let mut output = ChargedBuffer::from_reservation(source.count, &mut self.reservation)?;
        source.visit::<WriteDecodeError>(|key, value| {
            let key = self.bytes(key)?;
            let value = self.bytes(value)?;
            output
                .try_push(ExecKv { key, value })
                .map_err(|_| WriteDecodeError::PlanChanged)?;
            Ok(())
        })?;
        self.vector(output)
    }
    #[allow(
        unsafe_code,
        reason = "audited complete ordinary-write graph retains exact original allocation charges"
    )]
    fn finish(
        mut self,
        writes: Vec<ExecKv>,
        budget: &AllocationBudget,
    ) -> Result<RetainedPayload<ExecWitness>, WriteDecodeError> {
        let witness = ExecWitness {
            writes,
            ..ExecWitness::default()
        };
        let charges = self.charges.take().expect("construction ledger");
        // SAFETY: one charge for the exact outer Vec and every exact key/value Vec was recorded;
        // all other ExecWitness vectors are empty. This move-only owner exposes no mutation or
        // extraction. Its destructor destroys the complete graph before returning the ledger.
        match unsafe { RetainedPayload::try_new(witness, charges, budget) } {
            Ok(owner) => Ok(owner),
            Err((witness, charges, _)) => {
                drop(witness);
                drop(charges);
                Err(WriteDecodeError::ForeignPool)
            }
        }
    }
}

/// Decode the sole canonical projection frame while prepaying its exact ordinary-write graph.
/// Input bytes must already belong to this original pool. No witness allocation happens before
/// the complete checked demand is admitted; capacity failure preserves the original refusal.
pub(crate) fn decode_projection<'a>(
    bytes: &'a ChargedBuffer<u8>,
    budget: &AllocationBudget,
) -> Result<DecodedProjection<'a>, WriteDecodeError> {
    if !bytes.belongs_to(budget) {
        return Err(WriteDecodeError::ForeignPool);
    }
    let view = ncore::from_bytes_view(bytes.as_slice())?;
    let flags = view.flags();
    if flags != ncore::default_encode_flags() {
        return Err(norito::Error::NonCanonicalEncoding.into());
    }
    let mut construction = None;
    // Declared before the projection: its exact backing is always destroyed before refund.
    let mut casting_charge = None;
    let mut materialization_error = None;
    let projection = view
        .decode_exact_with::<NativeExecutionProjectionV1, MaterializedProjection<'_>, _>(
            |payload| {
                let decoded = (|| -> Result<MaterializedProjection<'_>, WriteDecodeError> {
                    let [height, hash, lanes, writes, casting, delta] =
                        fields::<6>(payload, flags)?;
                    let sccp_delta = raw_bytes(delta)?;
                    let raw = RawWrites::new(writes, flags)?;
                    let raw_casting = RawCasting::new(casting, flags)?;
                    let mut demand = raw.demand()?;
                    demand.bytes = demand
                        .bytes
                        .checked_add(array::<super::CastingBinding>(raw_casting.count())?.size())
                        .ok_or(AllocationRefusal::DemandOverflow)?;
                    construction = Some(Construction::new(demand, budget)?);
                    let ordinary_writes = construction
                        .as_mut()
                        .expect("admitted construction")
                        .writes(raw)?;
                    let carrier_height = u64::from_le_bytes(
                        height
                            .try_into()
                            .map_err(|_| norito::Error::LengthMismatch)?,
                    );
                    let carrier_hash = HashOf::from_untyped_unchecked(
                        iroha_crypto::Hash::from_marked_bytes(
                            hash.try_into().map_err(|_| norito::Error::LengthMismatch)?,
                        )
                        .ok_or(norito::Error::LengthMismatch)?,
                    );
                    let lanes = LanePayload {
                        bytes: lanes,
                        _alignment: [],
                    };
                    let original_casting = raw_casting.materialize(
                        &mut construction
                            .as_mut()
                            .expect("admitted construction")
                            .reservation,
                    )?;
                    let (casting_bindings, charge) = casting::split(original_casting);
                    casting_charge = Some(charge);
                    Ok(MaterializedProjection {
                        carrier_height,
                        carrier_hash,
                        lanes,
                        ordinary_writes,
                        casting_bindings,
                        sccp_delta,
                    })
                })();
                match decoded {
                    Ok(value) => Ok((value, payload.len())),
                    Err(error) => {
                        materialization_error = Some(error);
                        Err(norito::Error::LengthMismatch)
                    }
                }
            },
        );
    let projection = projection.map_err(|error| {
        materialization_error
            .take()
            .unwrap_or(WriteDecodeError::Codec(error))
    })?;
    // Mirror canonical decoding's exact streamed comparison, including canonical header flags,
    // schema, padding, all nested fields, and absence of suffixes. Never allocate a second frame.
    let mut exact = ExactWriter {
        expected: bytes.as_slice(),
        used: 0,
        mismatch: false,
    };
    let encoded = ncore::write_canonical_to_writer(&projection, &mut exact);
    if exact.mismatch || exact.used != bytes.as_slice().len() {
        return Err(norito::Error::NonCanonicalEncoding.into());
    }
    encoded?;
    let MaterializedProjection {
        carrier_height,
        carrier_hash,
        lanes,
        ordinary_writes,
        casting_bindings,
        sccp_delta,
    } = projection;
    let casting_bindings = casting::retain(
        casting_bindings,
        casting_charge.take().expect("complete casting array"),
        budget,
    )?;
    crate::smartcontracts::isi::sccp::witness::require_exact_delta(
        carrier_height,
        sccp_delta,
        &ordinary_writes,
    )?;
    let witness = construction
        .take()
        .expect("successful admitted decode")
        .finish(ordinary_writes, budget)?;
    Ok(DecodedProjection {
        carrier_height,
        carrier_hash,
        lane_payload: lanes.bytes,
        sccp_delta,
        casting_bindings,
        witness,
    })
}

/// Compare the canonical encoder's stream without retaining a duplicate frame.
struct ExactWriter<'a> {
    expected: &'a [u8],
    used: usize,
    mismatch: bool,
}
impl std::io::Write for ExactWriter<'_> {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        let end = self
            .used
            .checked_add(bytes.len())
            .ok_or(std::io::ErrorKind::InvalidData)?;
        if self.expected.get(self.used..end) != Some(bytes) {
            self.mismatch = true;
            return Err(std::io::ErrorKind::InvalidData.into());
        }
        self.used = end;
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests;
