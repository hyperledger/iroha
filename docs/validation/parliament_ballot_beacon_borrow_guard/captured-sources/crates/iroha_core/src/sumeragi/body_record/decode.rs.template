//! Funded decoding of the sole stored record, retaining source and partial destination owners.

use std::ops::Range;

use iroha_sumeragi::{
    availability::{MAX_AVAILABILITY_FRAME_BYTES, MAX_DA_PAYLOAD_SIZE_BYTES},
    message::ByteAdmissionError,
};
use norito::core as ncore;

use super::*;
#[cfg(test)]
use crate::sumeragi::durable_record_codec::MAX_HEADER_METADATA_BYTES;
use crate::sumeragi::durable_record_codec::{byte_range, decode_header, field_range};

struct Layout {
    header: BlockHeader,
    availability: Range<usize>,
    payload: Range<usize>,
}

/// Decoding refusal, retaining the funded raw record and every completed destination phase.
#[derive(Debug)]
pub(in crate::sumeragi) enum BodyDecodeError {
    /// A retry supplied another State allocation pool.
    ForeignBudget,
    /// Invalid canonical frame, field structure, domain length or bounded header metadata.
    Decode(norito::Error),
    /// Original-pool backing or shared control refused admission or allocation.
    Bytes(ByteAdmissionError),
}

impl fmt::Display for BodyDecodeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ForeignBudget => {
                formatter.write_str("body decode uses a foreign allocation pool")
            }
            Self::Decode(error) => error.fmt(formatter),
            Self::Bytes(error) => error.fmt(formatter),
        }
    }
}
impl std::error::Error for BodyDecodeError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::ForeignBudget => None,
            Self::Decode(error) => Some(error),
            Self::Bytes(error) => Some(error),
        }
    }
}

/// One raw original-funded read and all partially completed decode allocations.
/// No bulk Vec or decoded-untrusted-copy path exists; cryptographic authority still belongs
/// solely to the subsequent `BodyRestoration` worker.
pub(in crate::sumeragi) struct BodyRecordDecode {
    raw: ChargedBuffer<u8>,
    layout: Option<Layout>,
    table_backing: Option<ChargedBuffer<u8>>,
    payload_backing: Option<ChargedBuffer<u8>>,
    table: Option<AvailabilityFrame>,
    payload: Option<PayloadBytes>,
}

impl BodyRecordDecode {
    /// Retain the actual file backing. No parse or allocation occurs until completion.
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

    /// Decode using the raw buffer's exact State pool; errors return every original owner.
    /// On success the source is released only after both complete admitted destinations exist.
    pub(in crate::sumeragi) fn complete(
        mut self,
        budget: &AllocationBudget,
    ) -> Result<BodyRecord, (Self, BodyDecodeError)> {
        if let Err(error) = self.prepare(budget) {
            return Err((self, error));
        }
        Ok(BodyRecord {
            header: self.layout.take().expect("validated layout").header,
            availability: self.table.take().expect("original-funded table"),
            payload: self.payload.take().expect("original-funded payload"),
        })
    }

    fn prepare(&mut self, budget: &AllocationBudget) -> Result<(), BodyDecodeError> {
        if !self.raw.belongs_to(budget) {
            return Err(BodyDecodeError::ForeignBudget);
        }
        if self.layout.is_none() {
            self.layout = Some(parse_layout(self.raw.as_slice()).map_err(BodyDecodeError::Decode)?);
        }
        let layout = self.layout.as_ref().expect("validated ranges retained");
        if self.table.is_none() {
            fill(
                &mut self.table_backing,
                &self.raw.as_slice()[layout.availability.clone()],
                budget,
            )?;
            let bytes = self.table_backing.take().expect("retained table backing");
            match AvailabilityFrame::from_charged(bytes, budget) {
                Ok(table) => self.table = Some(table),
                Err((bytes, error)) => {
                    self.table_backing = Some(bytes);
                    return Err(BodyDecodeError::Bytes(error));
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
                .expect("retained payload backing");
            match PayloadBytes::from_charged(bytes, budget) {
                Ok(payload) => self.payload = Some(payload),
                Err((bytes, error)) => {
                    self.payload_backing = Some(bytes);
                    return Err(BodyDecodeError::Bytes(error));
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
) -> Result<(), BodyDecodeError> {
    if destination.is_none() {
        *destination = Some(
            ChargedBuffer::new(bytes.len(), budget)
                .map_err(|error| BodyDecodeError::Bytes(ByteAdmissionError::Buffer(error)))?,
        );
    }
    let buffer = destination.as_mut().expect("retained destination backing");
    if buffer.as_slice().is_empty() {
        // Exact counted capacity; append cannot grow, replace, or detach its original charge.
        // Retain the allocation before invoking any fallible writer operation.
        buffer
            .append(bytes)
            .map_err(|error| BodyDecodeError::Decode(error.into()))?;
    }
    Ok(())
}

fn parse_layout(raw: &[u8]) -> Result<Layout, norito::Error> {
    let view = ncore::from_bytes_view(raw)?;
    if view.schema() != norito::schema::identity::frame_hash::<BodyRecord>() {
        return Err(norito::Error::SchemaMismatch);
    }
    let bytes = view.as_bytes();
    let base = raw
        .len()
        .checked_sub(bytes.len())
        .ok_or(norito::Error::LengthMismatch)?;
    let (header, availability, payload) =
        ncore::with_decode_limits(norito::canonical_decode_limits(raw.len()), || {
            let _context = ncore::PayloadCtxGuard::enter_with_schema_and_flags(
                bytes,
                view.schema(),
                view.flags(),
            );
            let mut offset = 0;
            let header_field = field_range(bytes, &mut offset)?;
            let header = decode_header(&bytes[header_field])?;
            let table_field = field_range(bytes, &mut offset)?;
            let payload_field = field_range(bytes, &mut offset)?;
            if offset != bytes.len() {
                return Err(norito::Error::LengthMismatch);
            }
            let table = byte_range(bytes, table_field, 0, MAX_AVAILABILITY_FRAME_BYTES)?;
            let payload = byte_range(
                bytes,
                payload_field,
                1,
                usize::try_from(MAX_DA_PAYLOAD_SIZE_BYTES)
                    .map_err(|_| norito::Error::LengthMismatch)?,
            )?;
            Ok((header, table, payload))
        })?;
    // This checks the complete canonical schema, flags, padding, lengths and exact field bytes
    // using borrowed slices. No alternate frame or guessed layout is accepted.
    norito::verify_exact_canonical_frame(
        &BodyRecordRef {
            header: FieldRef(&header),
            availability: BytesRef(&bytes[availability.clone()]),
            payload: BytesRef(&bytes[payload.clone()]),
        },
        raw,
    )?;
    Ok(Layout {
        header,
        availability: (base + availability.start)..(base + availability.end),
        payload: (base + payload.start)..(base + payload.end),
    })
}

#[cfg(test)]
#[path = "decode_tests.rs"]
mod tests;
