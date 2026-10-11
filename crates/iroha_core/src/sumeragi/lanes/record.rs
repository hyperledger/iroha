//! One canonical lane publication frame: authenticated body material and its commit certificate.
//!
//! Disk decoding retains charged byte owners but grants no trust. The independent historical
//! source must be checked by the store and Core must authenticate the returned certificate.
//! Actual body restoration remains mandatory; no raw-body or witness-free fallback exists.

use std::fmt;

use iroha_allocation::{AllocationBudget, ChargedBuffer, ChargedBufferError};
use iroha_sumeragi::{
    availability::{
        AvailabilityFrame, AvailabilitySource, AvailableBody, BodyRestoration, PayloadBytes,
    },
    crypto::Crypto,
    message::{BlockHeader, ByteAdmissionError, Qc, VoteKind},
};

use crate::sumeragi::durable_record_codec::{BytesRef, FieldRef, FixedWriter};

#[path = "record/decode.rs"]
mod decode;
use crate::sumeragi::durable_qc_codec::QcRef;
pub(in crate::sumeragi) use decode::LaneRecordDecode;

/// The only lane record, in fixed order: header, original availability, payload, CommitQC.
/// Both bulk domains are funded in the reader's original pool; this remains untrusted.
#[derive(Debug, norito::Encode, norito::NoritoSchema)]
#[norito_schema(name = "iroha_core::sumeragi::lanes::LaneRecord")]
pub(in crate::sumeragi) struct LaneRecord {
    header: BlockHeader,
    availability: AvailabilityFrame,
    payload: PayloadBytes,
    commit_qc: Qc,
}

impl LaneRecord {
    /// Untrusted decoded metadata, never a source of historical authority.
    pub(in crate::sumeragi) fn header(&self) -> &BlockHeader {
        &self.header
    }

    /// Untrusted mandatory original signature table, without a payload availability claim.
    #[cfg(test)]
    pub(in crate::sumeragi) fn availability(&self) -> &AvailabilityFrame {
        &self.availability
    }

    /// Untrusted certificate. Core retains its independent signature verification.
    pub(in crate::sumeragi) fn commit_qc(&self) -> &Qc {
        &self.commit_qc
    }

    /// Cross-check disk identities against the store's independently selected historical source.
    /// This checks consistency only; it does not authenticate a CommitQC.
    pub(in crate::sumeragi) fn check_context(
        &self,
        source: &AvailabilitySource,
        crypto: &dyn Crypto,
    ) -> Result<(), LaneRecordError> {
        check_context(&self.header, &self.commit_qc, source, crypto)
    }

    /// Move exact owners into untrusted restoration input and the independently verified QC path.
    /// The owning store must call `check_context`; Core must verify the returned certificate.
    pub(in crate::sumeragi) fn into_restoration<Source: std::borrow::Borrow<AvailabilitySource>>(
        self,
        source: Source,
    ) -> (BodyRestoration<Source>, Qc) {
        (
            BodyRestoration::new(source, self.header, self.availability, self.payload),
            self.commit_qc,
        )
    }
}

// Payload-only borrowed fields: neither wrapper records nor alternate root schema identities.
#[derive(norito::Encode)]
struct LaneRecordRef<'a> {
    header: FieldRef<'a, BlockHeader>,
    availability: BytesRef<'a>,
    payload: BytesRef<'a>,
    commit_qc: QcRef<'a>,
}
impl norito::NoritoSchema for LaneRecordRef<'_> {
    fn nominal_name() -> String {
        <LaneRecord as norito::NoritoSchema>::nominal_name()
    }
    fn static_frame_name() -> Option<&'static str> {
        Some("iroha_core::sumeragi::lanes::LaneRecord")
    }
}

/// Rejection of lane record structure, original resource custody, or certificate authority.
#[derive(Debug)]
pub(in crate::sumeragi) enum LaneRecordError {
    /// A source, retained buffer or witness belongs to another allocation pool.
    ForeignBudget,
    /// The original pool refused a physical destination backing.
    Allocation(ChargedBufferError),
    /// A bulk domain refused its exact backing or shared control admission.
    Bytes(ByteAdmissionError),
    /// Invalid canonical bytes, finite metadata limits, or domain lengths.
    Codec(norito::Error),
    /// Header, certificate and independently selected source disagree.
    Context,
}
impl fmt::Display for LaneRecordError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ForeignBudget => f.write_str("lane record uses a foreign allocation pool"),
            Self::Allocation(error) => error.fmt(f),
            Self::Bytes(error) => error.fmt(f),
            Self::Codec(error) => error.fmt(f),
            Self::Context => f.write_str("lane body, certificate and source contexts differ"),
        }
    }
}
impl std::error::Error for LaneRecordError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Allocation(error) => Some(error),
            Self::Bytes(error) => Some(error),
            Self::Codec(error) => Some(error),
            Self::ForeignBudget | Self::Context => None,
        }
    }
}

fn structural_context(header: &BlockHeader, qc: &Qc) -> Result<(), LaneRecordError> {
    if qc.kind != VoteKind::Commit
        || qc.instance != header.instance
        || qc.epoch != header.epoch
        || qc.height != header.height
    {
        return Err(LaneRecordError::Context);
    }
    Ok(())
}

fn check_context(
    header: &BlockHeader,
    qc: &Qc,
    source: &AvailabilitySource,
    crypto: &dyn Crypto,
) -> Result<(), LaneRecordError> {
    structural_context(header, qc)?;
    if header.instance != source.instance()
        || header.height != source.height()
        || header.epoch != source.config().epoch.id
        || header.hash(crypto) != source.block_hash()
        || qc.block_hash != source.block_hash()
    {
        return Err(LaneRecordError::Context);
    }
    Ok(())
}

/// Original body, certificate and fixed output retained through every publication retry.
pub(in crate::sumeragi) struct PreparedLaneWrite {
    body: AvailableBody,
    commit_qc: Qc,
    bytes: Option<ChargedBuffer<u8>>,
    complete: bool,
}
impl PreparedLaneWrite {
    /// Retain the exact supplied owners; validation and allocation occur in `prepare`.
    pub(in crate::sumeragi) fn new(body: AvailableBody, commit_qc: Qc) -> Self {
        Self {
            body,
            commit_qc,
            bytes: None,
            complete: false,
        }
    }
    /// Original available custody retained through failed preparations/publications.
    pub(in crate::sumeragi) fn body(&self) -> &AvailableBody {
        &self.body
    }
    /// Original certificate with its exact signer bitmap and aggregate.
    pub(in crate::sumeragi) fn commit_qc(&self) -> &Qc {
        &self.commit_qc
    }
    /// Move the exact decoded/restored owners without cloning header, schedule or QC metadata.
    pub(in crate::sumeragi) fn into_parts(self) -> (AvailableBody, Qc) {
        (self.body, self.commit_qc)
    }

    /// Store-side identity check before durable publication; Core owns certificate verification.
    pub(in crate::sumeragi) fn check_context(
        &self,
        source: &AvailabilitySource,
        crypto: &dyn Crypto,
    ) -> Result<(), LaneRecordError> {
        check_context(self.body.header(), &self.commit_qc, source, crypto)
    }
    /// Check structural consistency and encode once in exact original-pool backing.
    /// Every failure leaves all owners in this job. No payload or availability frame is copied into an uncharged Vec.
    pub(in crate::sumeragi) fn prepare(
        &mut self,
        budget: &AllocationBudget,
    ) -> Result<&[u8], LaneRecordError> {
        if !self.body.admitted_to(budget)
            || self.bytes.as_ref().is_some_and(|b| !b.belongs_to(budget))
        {
            return Err(LaneRecordError::ForeignBudget);
        }
        structural_context(self.body.header(), &self.commit_qc)?;
        if !self.complete {
            let borrowed = LaneRecordRef {
                header: FieldRef(self.body.header()),
                availability: BytesRef(self.body.availability().as_slice()),
                payload: BytesRef(self.body.payload().as_slice()),
                commit_qc: QcRef::from(&self.commit_qc),
            };
            let length = norito::canonical_frame_len(&borrowed).map_err(LaneRecordError::Codec)?;
            if self.bytes.is_none() {
                self.bytes =
                    Some(ChargedBuffer::new(length, budget).map_err(LaneRecordError::Allocation)?);
            }
            let bytes = self.bytes.as_mut().expect("retained original output");
            if bytes.capacity() != length {
                return Err(LaneRecordError::Codec(norito::Error::LengthMismatch));
            }
            bytes.truncate(0);
            norito::core::write_canonical_to_writer(&borrowed, &mut FixedWriter(bytes))
                .map_err(LaneRecordError::Codec)?;
            if bytes.as_slice().len() != length {
                return Err(LaneRecordError::Codec(norito::Error::LengthMismatch));
            }
            self.complete = true;
        }
        Ok(self.bytes.as_ref().expect("complete output").as_slice())
    }
}

#[cfg(test)]
#[path = "record/tests.rs"]
pub(in crate::sumeragi) mod tests;
