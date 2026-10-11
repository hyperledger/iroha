//! Qc's exact canonical payload with fixed metadata and pre-allocation bitmap bounds.

use iroha_sumeragi::{
    message::{MAX_BITMAP_BYTES, Qc, VoteKind},
    types::{AggregateSignature, Bitmap, EpochId, Hash32, MAX_COMMITTEE_SIZE},
};
use norito::core as ncore;

use crate::sumeragi::durable_record_codec::{FieldRef, field_range};

// Nine fields, including fixed scalar/hash/signature data and the bounded signer bitmap.
// This cap is checked before generic metadata decoding, independently of any body length.
pub(super) const MAX_QC_METADATA_BYTES: usize = 1024 + MAX_BITMAP_BYTES;

#[derive(norito::Encode)]
pub(super) struct QcRef<'a> {
    kind: FieldRef<'a, VoteKind>,
    instance: FieldRef<'a, Hash32>,
    epoch: FieldRef<'a, EpochId>,
    height: FieldRef<'a, u64>,
    view: FieldRef<'a, u64>,
    block_hash: FieldRef<'a, Hash32>,
    result: FieldRef<'a, Hash32>,
    signers: FieldRef<'a, Bitmap>,
    agg_sig: FieldRef<'a, AggregateSignature>,
}
impl norito::NoritoSchema for QcRef<'_> {
    fn nominal_name() -> String {
        <Qc as norito::NoritoSchema>::nominal_name()
    }
    fn static_frame_name() -> Option<&'static str> {
        Some("iroha_sumeragi::Qc")
    }
}

impl<'a> From<&'a Qc> for QcRef<'a> {
    fn from(qc: &'a Qc) -> Self {
        Self {
            kind: FieldRef(&qc.kind),
            instance: FieldRef(&qc.instance),
            epoch: FieldRef(&qc.epoch),
            height: FieldRef(&qc.height),
            view: FieldRef(&qc.view),
            block_hash: FieldRef(&qc.block_hash),
            result: FieldRef(&qc.result),
            signers: FieldRef(&qc.signers),
            agg_sig: FieldRef(&qc.agg_sig),
        }
    }
}

// The same nine fields and payload order as Qc, decoded only after the finite byte cap.
// Borrowed encoding validates the original canonical frame without copying these fields.
#[derive(norito::Encode, norito::Decode)]
pub(super) struct QcMetadata {
    kind: VoteKind,
    instance: Hash32,
    epoch: EpochId,
    height: u64,
    view: u64,
    block_hash: Hash32,
    result: Hash32,
    signers: Bitmap,
    agg_sig: AggregateSignature,
}
impl QcMetadata {
    pub(super) fn borrowed(&self) -> QcRef<'_> {
        QcRef {
            kind: FieldRef(&self.kind),
            instance: FieldRef(&self.instance),
            epoch: FieldRef(&self.epoch),
            height: FieldRef(&self.height),
            view: FieldRef(&self.view),
            block_hash: FieldRef(&self.block_hash),
            result: FieldRef(&self.result),
            signers: FieldRef(&self.signers),
            agg_sig: FieldRef(&self.agg_sig),
        }
    }
    pub(super) fn finish(self) -> Qc {
        Qc {
            kind: self.kind,
            instance: self.instance,
            epoch: self.epoch,
            height: self.height,
            view: self.view,
            block_hash: self.block_hash,
            result: self.result,
            signers: self.signers,
            agg_sig: self.agg_sig,
        }
    }
}

/// Decode only the declared nine-field layout after checking every finite field range.
pub(super) fn parse(bytes: &[u8]) -> Result<QcMetadata, norito::Error> {
    if bytes.len() > MAX_QC_METADATA_BYTES {
        return Err(norito::Error::FieldLengthExceeded {
            length: bytes.len() as u64,
            limit: MAX_QC_METADATA_BYTES as u64,
        });
    }
    let mut offset = 0;
    for _ in 0..9 {
        field_range(bytes, &mut offset)?;
    }
    if offset != bytes.len() {
        return Err(norito::Error::LengthMismatch);
    }
    let metadata: QcMetadata = ncore::with_decode_limits(
        norito::DecodeLimits::new(
            MAX_COMMITTEE_SIZE,
            MAX_QC_METADATA_BYTES,
            MAX_QC_METADATA_BYTES * 2,
            MAX_QC_METADATA_BYTES * 8,
            ncore::MAX_VALUE_NESTING_DEPTH,
        ),
        || ncore::decode_field_canonical(bytes).map(|(value, _)| value),
    )?;
    if metadata.signers.as_bytes().len() > MAX_BITMAP_BYTES {
        return Err(norito::Error::NonCanonicalEncoding);
    }
    Ok(metadata)
}

/// Validate the exact standalone canonical Qc frame without accepting a second layout.
pub(super) fn parse_frame(raw: &[u8]) -> Result<QcMetadata, norito::Error> {
    if raw.len() > MAX_QC_METADATA_BYTES + ncore::Header::SIZE {
        return Err(norito::Error::FieldLengthExceeded {
            length: raw.len() as u64,
            limit: (MAX_QC_METADATA_BYTES + ncore::Header::SIZE) as u64,
        });
    }
    let view = ncore::from_bytes_view(raw)?;
    if view.schema() != norito::schema::identity::frame_hash::<Qc>() {
        return Err(norito::Error::SchemaMismatch);
    }
    let bytes = view.as_bytes();
    let metadata = {
        let _context =
            ncore::PayloadCtxGuard::enter_with_schema_and_flags(bytes, view.schema(), view.flags());
        parse(bytes)?
    };
    norito::verify_exact_canonical_frame(&metadata.borrowed(), raw)?;
    Ok(metadata)
}
