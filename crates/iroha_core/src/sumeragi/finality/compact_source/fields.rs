//! Borrow only selected DATA through the canonical record owners, never a body decoder.

use std::convert::Infallible;

use iroha_data_model::{
    block::{
        BlockHeader, BlockPayload, BlockResult, BlockSignatures, CommitCertificate, SignedBlock,
        execution_context::BlockExecutionContextBundle,
    },
    consensus::{FinalizedGlobalThresholdBeaconPulseV1, NposConsensusEffects},
    da::{
        commitment::{DaCommitmentBundle, DaProofPolicyBundle},
        pin_intent::DaPinIntentBundle,
    },
    transaction::signed::TransactionEntrypoint,
};
use norito::core::{
    CanonicalField, DecodeField, DecodeFromSlice, DecodeIntoError, DecodeRecordFields,
    FieldDestination, SequenceSpan,
};

type Result<T> = std::result::Result<T, DecodeIntoError<Infallible>>;

// Norito accounts for each borrowed byte as sequence metadata. Only the three
// certificate leaves are visited, never the availability or executed body graph.
pub(super) const SCRATCH_BYTES: usize = super::MAX_COMMIT_CERTIFICATE_BYTES_V1;

pub(super) struct Selected<'a> {
    pub(super) header: BlockHeader,
    pub(super) components: [&'a [u8]; 3],
}

pub(super) fn select(bytes: &[u8]) -> std::result::Result<Selected<'_>, norito::Error> {
    let limits =
        norito::DecodeLimits::new(bytes.len(), bytes.len(), bytes.len(), SCRATCH_BYTES, 32);
    norito::with_decode_limits(limits, || select_fields(bytes))
}

fn select_fields(bytes: &[u8]) -> std::result::Result<Selected<'_>, norito::Error> {
    let (&version, frame) = bytes.split_first().ok_or(norito::Error::LengthMismatch)?;
    if version != 1 {
        return Err(norito::Error::UnsupportedVersion {
            found: version,
            expected: 1,
        });
    }
    let archive = norito::core::from_bytes_view(frame)?;
    if archive.flags() != norito::core::default_encode_flags() {
        return Err(norito::Error::NonCanonicalEncoding);
    }
    let mut fields = BlockFields {
        source: bytes,
        header: None,
        components: None,
    };
    archive.decode_exact_with::<SignedBlock, _, _>(|payload| {
        let (_, used) = SignedBlock::decode_fields(payload, &mut fields)
            .map_err(DecodeIntoError::into_codec)?;
        Ok(((), used))
    })?;
    let spans = fields.components.ok_or(norito::Error::LengthMismatch)?;
    Ok(Selected {
        header: fields.header.ok_or(norito::Error::LengthMismatch)?,
        components: [
            spans[0].get(bytes)?,
            spans[1].get(bytes)?,
            spans[2].get(bytes)?,
        ],
    })
}

struct BlockFields<'a> {
    source: &'a [u8],
    header: Option<BlockHeader>,
    components: Option<[SequenceSpan; 3]>,
}
impl FieldDestination for BlockFields<'_> {
    type Error = Infallible;
}
struct PayloadFields(Option<BlockHeader>);
impl FieldDestination for PayloadFields {
    type Error = Infallible;
}

// Skipped subgraphs remain opaque DATA. The derived owner still checks each
// field prefix, its position, advertised layout and complete enclosing traversal.
macro_rules! opaque {
    ($owner:ty, $index:literal, $field:ty) => {
        impl DecodeField<$index, $field> for $owner {
            type Value = ();
            fn decode_field(&mut self, _field: CanonicalField<'_, $field>) -> Result<()> {
                Ok(())
            }
        }
    };
}
opaque!(BlockFields<'_>, 0, BlockSignatures);
opaque!(BlockFields<'_>, 2, Option<BlockResult>);
opaque!(PayloadFields, 1, Vec<TransactionEntrypoint>);
opaque!(PayloadFields, 2, Option<DaCommitmentBundle>);
opaque!(PayloadFields, 3, Option<DaProofPolicyBundle>);
opaque!(PayloadFields, 4, Option<DaPinIntentBundle>);
opaque!(PayloadFields, 5, Option<NposConsensusEffects>);
opaque!(
    PayloadFields,
    6,
    Option<FinalizedGlobalThresholdBeaconPulseV1>
);
opaque!(PayloadFields, 7, Option<BlockExecutionContextBundle>);

impl DecodeField<1, BlockPayload> for BlockFields<'_> {
    type Value = ();
    fn decode_field(&mut self, field: CanonicalField<'_, BlockPayload>) -> Result<()> {
        field.with_payload(|bytes| {
            let mut payload = PayloadFields(None);
            let (_, used) = BlockPayload::decode_fields(bytes, &mut payload)?;
            if used != bytes.len() {
                return Err(norito::Error::LengthMismatch.into());
            }
            self.header = payload.0;
            Ok(())
        })
    }
}
impl DecodeField<0, BlockHeader> for PayloadFields {
    type Value = ();
    fn decode_field(&mut self, field: CanonicalField<'_, BlockHeader>) -> Result<()> {
        self.0 = Some(field.with_payload(|bytes| {
            BlockHeader::decode_inline_payload(bytes).map_err(DecodeIntoError::Codec)
        })?);
        Ok(())
    }
}
impl DecodeField<3, Option<CommitCertificate>> for BlockFields<'_> {
    type Value = ();
    fn decode_field(&mut self, field: CanonicalField<'_, Option<CommitCertificate>>) -> Result<()> {
        self.components = field.decode_optional(|field| {
            field.with_payload(|bytes| {
                let mut certificate = CertificateFields {
                    source: self.source,
                    components: [None; 3],
                };
                let (_, used) = CommitCertificate::decode_fields(bytes, &mut certificate)?;
                if used != bytes.len() {
                    return Err(norito::Error::LengthMismatch.into());
                }
                let [Some(header), Some(qc), Some(result)] = certificate.components else {
                    return Err(norito::Error::LengthMismatch.into());
                };
                Ok([header, qc, result])
            })
        })?;
        Ok(())
    }
}
struct CertificateFields<'a> {
    source: &'a [u8],
    components: [Option<SequenceSpan>; 3],
}
impl FieldDestination for CertificateFields<'_> {
    type Error = Infallible;
}
impl<const INDEX: usize> DecodeField<INDEX, Vec<u8>> for CertificateFields<'_> {
    type Value = ();
    fn decode_field(&mut self, field: CanonicalField<'_, Vec<u8>>) -> Result<()> {
        // The fourth original field is opaque availability, not phone evidence.
        if INDEX == 3 {
            return Ok(());
        }
        let component = self
            .components
            .get_mut(INDEX)
            .ok_or(norito::Error::LengthMismatch)?;
        field.with_payload(|bytes| {
            let (leaf, used) = <&[u8] as DecodeFromSlice>::decode_from_slice(bytes)?;
            if used != bytes.len() {
                return Err(norito::Error::LengthMismatch.into());
            }
            let start = leaf
                .as_ptr()
                .addr()
                .checked_sub(self.source.as_ptr().addr())
                .ok_or(norito::Error::LengthMismatch)?;
            let end = start
                .checked_add(leaf.len())
                .ok_or(norito::Error::LengthMismatch)?;
            let span = SequenceSpan { start, end };
            if span.get(self.source)? != leaf {
                return Err(norito::Error::LengthMismatch.into());
            }
            *component = Some(span);
            Ok(())
        })
    }
}
