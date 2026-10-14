//! Retained decoding of Kura's original certificate into funded protocol artifacts.

use std::ops::Range;

use iroha_allocation::{AllocationBudget, ChargedBuffer};
#[cfg(test)]
use iroha_data_model::block::SignedBlock;
use iroha_sumeragi::{
    availability::{AvailabilityFrame, MAX_AVAILABILITY_FRAME_BYTES},
    message::{BlockHeader, ByteAdmissionError, Qc},
};
use norito::core as ncore;

use crate::sumeragi::{
    durable_qc_codec::{self, QcMetadata},
    durable_record_codec::{BytesRef, MAX_HEADER_METADATA_BYTES, byte_range, decode_header},
};

/// Corruption and source errors remain distinct from a recoverable local allocation refusal.
#[derive(Debug)]
pub(in crate::sumeragi) enum CertificateReadError {
    ForeignBudget,
    MissingCertificate,
    Decode(norito::Error),
    Admission(ByteAdmissionError),
}
impl std::fmt::Display for CertificateReadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ForeignBudget => f.write_str("certificate read uses a foreign allocation pool"),
            Self::MissingCertificate => f.write_str("stored block has no certificate"),
            Self::Decode(error) => error.fmt(f),
            Self::Admission(error) => error.fmt(f),
        }
    }
}
impl std::error::Error for CertificateReadError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Decode(error) => Some(error),
            Self::Admission(error) => Some(error),
            _ => None,
        }
    }
}

struct Layout {
    header: BlockHeader,
    availability: Range<usize>,
    qc: QcMetadata,
}

/// Exact source and decoded artifacts; decoding alone does not authorize a historical body.
/// The caller checks independent height configuration, certificate relations and signatures.
pub(in crate::sumeragi) struct DecodedCertificate {
    pub(in crate::sumeragi) source: iroha_data_model::block::SharedSignedBlock,
    pub(in crate::sumeragi) header: BlockHeader,
    pub(in crate::sumeragi) availability: AvailabilityFrame,
    pub(in crate::sumeragi) commit_qc: Qc,
}

/// One bounded read owner retains its immutable source and every partial funded destination.
/// No generic availability decoding allocates a temporary bulk Vec.
pub(in crate::sumeragi) struct CertificateRead {
    source: iroha_data_model::block::SharedSignedBlock,
    budget: AllocationBudget,
    layout: Option<Layout>,
    table_backing: Option<ChargedBuffer<u8>>,
    table: Option<AvailabilityFrame>,
}
impl CertificateRead {
    pub(in crate::sumeragi) fn new(
        source: iroha_data_model::block::SharedSignedBlock,
        budget: AllocationBudget,
    ) -> Self {
        Self {
            source,
            budget,
            layout: None,
            table_backing: None,
            table: None,
        }
    }

    #[cfg(test)]
    pub(in crate::sumeragi) fn source(&self) -> &iroha_data_model::block::SharedSignedBlock {
        &self.source
    }

    /// Observe original owners without acquiring, replacing or advancing any decode phase.
    #[cfg(test)]
    pub(in crate::sumeragi) fn retained_owners_for_test(
        &self,
    ) -> (*const SignedBlock, Option<*const u8>) {
        let table = self
            .table
            .as_ref()
            .map(|table| table.as_slice().as_ptr())
            .or_else(|| {
                self.table_backing
                    .as_ref()
                    .map(|bytes| bytes.as_slice().as_ptr())
            });
        (std::ptr::from_ref(self.source.as_ref()), table)
    }

    #[allow(
        clippy::result_large_err,
        reason = "retain every original source and allocation owner"
    )]
    pub(in crate::sumeragi) fn complete(
        mut self,
        budget: &AllocationBudget,
    ) -> Result<DecodedCertificate, (Self, CertificateReadError)> {
        if let Err(error) = self.prepare(budget) {
            return Err((self, error));
        }
        let layout = self.layout.take().expect("validated canonical certificate");
        Ok(DecodedCertificate {
            source: self.source,
            header: layout.header,
            availability: self.table.take().expect("original-funded availability"),
            commit_qc: layout.qc.finish(),
        })
    }

    fn prepare(&mut self, budget: &AllocationBudget) -> Result<(), CertificateReadError> {
        if !self.budget.same_pool(budget) {
            return Err(CertificateReadError::ForeignBudget);
        }
        let certificate = self
            .source
            .commit_certificate()
            .ok_or(CertificateReadError::MissingCertificate)?;
        if self.layout.is_none() {
            let header =
                header(certificate.consensus_header()).map_err(CertificateReadError::Decode)?;
            let availability =
                table_range(certificate.availability()).map_err(CertificateReadError::Decode)?;
            let qc = durable_qc_codec::parse_frame(certificate.commit_qc())
                .map_err(CertificateReadError::Decode)?;
            self.layout = Some(Layout {
                header,
                availability,
                qc,
            });
        }
        let layout = self.layout.as_ref().expect("retained canonical ranges");
        if self.table.is_none() {
            fill(
                &mut self.table_backing,
                &certificate.availability()[layout.availability.clone()],
                budget,
            )?;
            let backing = self.table_backing.take().expect("original table backing");
            match AvailabilityFrame::from_charged(backing, budget) {
                Ok(table) => self.table = Some(table),
                Err((backing, error)) => {
                    self.table_backing = Some(backing);
                    return Err(CertificateReadError::Admission(error));
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
) -> Result<(), CertificateReadError> {
    if destination.is_none() {
        *destination =
            Some(ChargedBuffer::new(bytes.len(), budget).map_err(|error| {
                CertificateReadError::Admission(ByteAdmissionError::Buffer(error))
            })?);
    }
    let backing = destination.as_mut().expect("retained exact backing");
    if backing.as_slice().is_empty() {
        backing
            .append(bytes)
            .map_err(|error| CertificateReadError::Decode(error.into()))?;
    }
    Ok(())
}

fn header(raw: &[u8]) -> Result<BlockHeader, norito::Error> {
    if raw.len() > MAX_HEADER_METADATA_BYTES + ncore::Header::SIZE {
        return Err(norito::Error::FieldLengthExceeded {
            length: raw.len() as u64,
            limit: (MAX_HEADER_METADATA_BYTES + ncore::Header::SIZE) as u64,
        });
    }
    let view = ncore::from_bytes_view(raw)?;
    if view.schema() != norito::schema::identity::frame_hash::<BlockHeader>() {
        return Err(norito::Error::SchemaMismatch);
    }
    let header = {
        let _context = ncore::PayloadCtxGuard::enter_with_schema_and_flags(
            view.as_bytes(),
            view.schema(),
            view.flags(),
        );
        decode_header(view.as_bytes())?
    };
    norito::verify_exact_canonical_frame(&header, raw)?;
    Ok(header)
}

struct TableRef<'a>(&'a [u8]);
impl ncore::SerializePayload for TableRef<'_> {
    fn serialize(&self, encoder: &mut ncore::Encoder<'_>) -> Result<(), norito::Error> {
        ncore::SerializePayload::serialize(&BytesRef(self.0), encoder)
    }
}
impl norito::NoritoSchema for TableRef<'_> {
    fn nominal_name() -> String {
        <AvailabilityFrame as norito::NoritoSchema>::nominal_name()
    }
    fn static_frame_name() -> Option<&'static str> {
        Some("iroha_sumeragi::availability::AvailabilityFrame")
    }
}

fn table_range(raw: &[u8]) -> Result<Range<usize>, norito::Error> {
    let view = ncore::from_bytes_view(raw)?;
    if view.schema() != norito::schema::identity::frame_hash::<AvailabilityFrame>() {
        return Err(norito::Error::SchemaMismatch);
    }
    let bytes = view.as_bytes();
    let range = {
        let _context =
            ncore::PayloadCtxGuard::enter_with_schema_and_flags(bytes, view.schema(), view.flags());
        byte_range(bytes, 0..bytes.len(), 1, MAX_AVAILABILITY_FRAME_BYTES)?
    };
    let table = &bytes[range.clone()];
    let count = table.get(..4).ok_or(norito::Error::LengthMismatch)?;
    let count = u32::from_be_bytes(count.try_into().expect("exact count")) as usize;
    if !(2..=iroha_sumeragi::availability::MAX_DA_CHUNK_COUNT as usize).contains(&count)
        || table.len() != 100 + 128 * count
    {
        return Err(norito::Error::LengthMismatch);
    }
    norito::verify_exact_canonical_frame(&TableRef(table), raw)?;
    let base = raw
        .len()
        .checked_sub(bytes.len())
        .ok_or(norito::Error::LengthMismatch)?;
    Ok((base + range.start)..(base + range.end))
}

#[cfg(test)]
#[path = "certificate_read_tests.rs"]
mod tests;
