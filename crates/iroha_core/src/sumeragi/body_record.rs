//! One untrusted stored body record and original-funded preparation of its canonical bytes.
//!
//! Decoding grants no availability authority. Only the protocol restoration worker can recover
//! opaque custody from the mandatory original signature table and the independently chosen source.

use super::durable_record_codec::{BytesRef, FieldRef, FixedWriter};
use std::fmt;

use iroha_allocation::{AllocationBudget, ChargedBuffer, ChargedBufferError};
use iroha_sumeragi::{
    availability::{
        AvailabilityFrame, AvailabilitySource, AvailableBody, BodyRestoration, PayloadBytes,
    },
    message::BlockHeader,
};

#[path = "body_record/decode.rs"]
mod decode;
pub(super) use decode::{BodyDecodeError, BodyRecordDecode};

/// Untrusted disk material, in the sole canonical order: header, original table, payload.
/// Its byte owners remain untrusted until consumed by `BodyRestoration::complete`.
#[derive(Debug, norito::Encode, norito::NoritoSchema)]
#[norito_schema(name = "iroha_core::sumeragi::BodyRecord")]
pub(super) struct BodyRecord {
    header: BlockHeader,
    availability: AvailabilityFrame,
    payload: PayloadBytes,
}

impl BodyRecord {
    /// Untrusted metadata for diagnostics; never a source of historical authority.
    #[cfg(test)]
    pub(super) fn header(&self) -> &BlockHeader {
        &self.header
    }

    /// Move exact decoded owners into the worker job with an independently selected source.
    pub(super) fn into_restoration(self, source: AvailabilitySource) -> BodyRestoration {
        BodyRestoration::new(source, self.header, self.availability, self.payload)
    }
}

// Deriving the same three fields in the same order preserves the owned record's canonical
// payload while borrowing the exact admitted owners. The explicit identity is shared; a
// borrowed view must not become a second wire format or clone either bulk byte sequence.
#[derive(norito::Encode)]
struct BodyRecordRef<'a> {
    header: FieldRef<'a, BlockHeader>,
    availability: BytesRef<'a>,
    payload: BytesRef<'a>,
}

impl norito::NoritoSchema for BodyRecordRef<'_> {
    fn nominal_name() -> String {
        <BodyRecord as norito::NoritoSchema>::nominal_name()
    }
    fn static_frame_name() -> Option<&'static str> {
        Some("iroha_core::sumeragi::BodyRecord")
    }
}

impl<'a> From<&'a AvailableBody> for BodyRecordRef<'a> {
    fn from(body: &'a AvailableBody) -> Self {
        Self {
            header: FieldRef(body.header()),
            availability: BytesRef(body.availability().as_slice()),
            payload: BytesRef(body.payload().as_slice()),
        }
    }
}

/// Write preparation failure, with the original body and any acquired output still retained.
#[derive(Debug)]
pub(super) enum BodyWriteError {
    /// A caller supplied a pool other than the one funding the original body or output.
    ForeignBudget,
    /// The original pool or allocator refused the exact counted output backing.
    Allocation(ChargedBufferError),
    /// Canonical serialization or its exact measured length failed.
    Encoding(norito::Error),
}

impl fmt::Display for BodyWriteError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ForeignBudget => {
                formatter.write_str("stored body belongs to another allocation pool")
            }
            Self::Allocation(error) => error.fmt(formatter),
            Self::Encoding(error) => error.fmt(formatter),
        }
    }
}

impl std::error::Error for BodyWriteError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::ForeignBudget => None,
            Self::Allocation(error) => Some(error),
            Self::Encoding(error) => Some(error),
        }
    }
}

/// Retained write job. The body and output backing survive every preparation or I/O refusal.
/// The caller borrows the completed bytes until durable publication succeeds.
pub(super) struct PreparedBodyWrite {
    body: AvailableBody,
    bytes: Option<ChargedBuffer<u8>>,
    complete: bool,
}

impl PreparedBodyWrite {
    /// Take an already authenticated original owner; no allocation or serialization runs here.
    pub(super) fn new(body: AvailableBody) -> Self {
        Self {
            body,
            bytes: None,
            complete: false,
        }
    }

    /// The unchanged authenticated body retained through publication and retries.
    pub(super) fn body(&self) -> &AvailableBody {
        &self.body
    }

    /// Prepare one canonical frame in fixed backing from the body's exact original pool.
    /// Repeated successful calls borrow the same allocation without re-encoding.
    ///
    /// # Errors
    /// A foreign pool, an original-pool resource refusal, or a canonical encoding failure.
    /// Every error leaves this same job, its body and any output backing available to the caller.
    pub(super) fn prepare(&mut self, budget: &AllocationBudget) -> Result<&[u8], BodyWriteError> {
        if !self.body.admitted_to(budget)
            || self
                .bytes
                .as_ref()
                .is_some_and(|bytes| !bytes.belongs_to(budget))
        {
            return Err(BodyWriteError::ForeignBudget);
        }
        if !self.complete {
            let borrowed = BodyRecordRef::from(&self.body);
            let length =
                norito::canonical_frame_len(&borrowed).map_err(BodyWriteError::Encoding)?;
            if self.bytes.is_none() {
                self.bytes =
                    Some(ChargedBuffer::new(length, budget).map_err(BodyWriteError::Allocation)?);
            }
            let bytes = self.bytes.as_mut().expect("retained output allocation");
            if bytes.capacity() != length {
                return Err(BodyWriteError::Encoding(norito::Error::LengthMismatch));
            }
            bytes.truncate(0);
            norito::core::write_canonical_to_writer(&borrowed, &mut FixedWriter(bytes))
                .map_err(BodyWriteError::Encoding)?;
            if bytes.as_slice().len() != length {
                return Err(BodyWriteError::Encoding(norito::Error::LengthMismatch));
            }
            self.complete = true;
        }
        Ok(self
            .bytes
            .as_ref()
            .expect("completed output owner")
            .as_slice())
    }
}

#[cfg(test)]
#[path = "body_record/tests.rs"]
pub(super) mod tests;
