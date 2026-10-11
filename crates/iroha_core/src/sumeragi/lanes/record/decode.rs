//! Original-funded lane decoding: raw record and all partial destinations survive refusal.

use std::ops::Range;

use iroha_sumeragi::availability::{MAX_AVAILABILITY_FRAME_BYTES, MAX_DA_PAYLOAD_SIZE_BYTES};
use norito::core as ncore;

use super::*;
use crate::sumeragi::durable_qc_codec::{self as qc, QcMetadata};
use crate::sumeragi::durable_record_codec::{byte_range, decode_header, field_range};

struct Layout {
    header: BlockHeader,
    availability: Range<usize>,
    payload: Range<usize>,
    qc: QcMetadata,
}

/// A retained original-pool raw frame plus actual destination backings and shared controls.
/// No decoded bulk Vec exists; successful output remains untrusted storage material.
pub(in crate::sumeragi) struct LaneRecordDecode {
    raw: ChargedBuffer<u8>,
    layout: Option<Layout>,
    table_backing: Option<ChargedBuffer<u8>>,
    payload_backing: Option<ChargedBuffer<u8>>,
    table: Option<AvailabilityFrame>,
    payload: Option<PayloadBytes>,
}
impl LaneRecordDecode {
    /// Retain the exact file backing; no metadata or bulk allocation occurs here.
    pub(in crate::sumeragi) fn new(raw: ChargedBuffer<u8>) -> Self {
        Self {
            raw,
            layout: None,
            table_backing: None,
            payload_backing: None,
            table: None,
            payload: None,
        }
    }

    /// Complete using the raw buffer's original pool, or return this unchanged ownership chain.
    #[allow(
        clippy::result_large_err,
        reason = "refusal returns every original owner without allocating"
    )]
    pub(in crate::sumeragi) fn complete(
        mut self,
        budget: &AllocationBudget,
    ) -> Result<LaneRecord, (Self, LaneRecordError)> {
        if let Err(error) = self.prepare(budget) {
            return Err((self, error));
        }
        let layout = self.layout.take().expect("validated canonical layout");
        let record = LaneRecord {
            header: layout.header,
            availability: self.table.take().expect("funded original table"),
            payload: self.payload.take().expect("funded original payload"),
            commit_qc: layout.qc.finish(),
        };
        // The source is released only after all actual destination owners exist.
        Ok(record)
    }

    fn prepare(&mut self, budget: &AllocationBudget) -> Result<(), LaneRecordError> {
        if !self.raw.belongs_to(budget) {
            return Err(LaneRecordError::ForeignBudget);
        }
        if self.layout.is_none() {
            self.layout = Some(parse(self.raw.as_slice()).map_err(LaneRecordError::Codec)?);
        }
        let layout = self.layout.as_ref().expect("validated ranges");
        if self.table.is_none() {
            fill(
                &mut self.table_backing,
                &self.raw.as_slice()[layout.availability.clone()],
                budget,
            )?;
            let bytes = self.table_backing.take().expect("table backing retained");
            match AvailabilityFrame::from_charged(bytes, budget) {
                Ok(table) => self.table = Some(table),
                Err((bytes, error)) => {
                    self.table_backing = Some(bytes);
                    return Err(LaneRecordError::Bytes(error));
                }
            }
        }
        if self.payload.is_none() {
            fill(
                &mut self.payload_backing,
                &self.raw.as_slice()[layout.payload.clone()],
                budget,
            )?;
            let bytes = self
                .payload_backing
                .take()
                .expect("payload backing retained");
            match PayloadBytes::from_charged(bytes, budget) {
                Ok(payload) => self.payload = Some(payload),
                Err((bytes, error)) => {
                    self.payload_backing = Some(bytes);
                    return Err(LaneRecordError::Bytes(error));
                }
            }
        }
        Ok(())
    }
}

fn fill(
    destination: &mut Option<ChargedBuffer<u8>>,
    bytes: &[u8],
    budget: &AllocationBudget,
) -> Result<(), LaneRecordError> {
    if destination.is_none() {
        *destination =
            Some(ChargedBuffer::new(bytes.len(), budget).map_err(LaneRecordError::Allocation)?);
    }
    let buffer = destination.as_mut().expect("retained destination backing");
    if buffer.as_slice().is_empty() {
        buffer
            .append(bytes)
            .map_err(|e| LaneRecordError::Codec(e.into()))?;
    }
    Ok(())
}

fn parse(raw: &[u8]) -> Result<Layout, norito::Error> {
    let view = ncore::from_bytes_view(raw)?;
    if view.schema() != norito::schema::identity::frame_hash::<LaneRecord>() {
        return Err(norito::Error::SchemaMismatch);
    }
    let bytes = view.as_bytes();
    let base = raw
        .len()
        .checked_sub(bytes.len())
        .ok_or(norito::Error::LengthMismatch)?;
    let (header, availability, payload, qc) =
        ncore::with_decode_limits(norito::canonical_decode_limits(raw.len()), || {
            let _context = ncore::PayloadCtxGuard::enter_with_schema_and_flags(
                bytes,
                view.schema(),
                view.flags(),
            );
            let mut offset = 0;
            let header = decode_header(&bytes[field_range(bytes, &mut offset)?])?;
            let table_field = field_range(bytes, &mut offset)?;
            let payload_field = field_range(bytes, &mut offset)?;
            let qc_field = field_range(bytes, &mut offset)?;
            if offset != bytes.len() {
                return Err(norito::Error::LengthMismatch);
            }
            // Lanes never persist the separately authenticated result-only global genesis form.
            let availability = byte_range(bytes, table_field, 1, MAX_AVAILABILITY_FRAME_BYTES)?;
            let payload = byte_range(bytes, payload_field, 1, MAX_DA_PAYLOAD_SIZE_BYTES as usize)?;
            let qc = qc::parse(&bytes[qc_field])?;
            Ok((header, availability, payload, qc))
        })?;
    norito::verify_exact_canonical_frame(
        &LaneRecordRef {
            header: FieldRef(&header),
            availability: BytesRef(&bytes[availability.clone()]),
            payload: BytesRef(&bytes[payload.clone()]),
            commit_qc: qc.borrowed(),
        },
        raw,
    )?;
    Ok(Layout {
        header,
        availability: (base + availability.start)..(base + availability.end),
        payload: (base + payload.start)..(base + payload.end),
        qc,
    })
}

#[cfg(test)]
#[path = "decode_tests.rs"]
mod tests;
