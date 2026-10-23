//! Reusable original-pool destinations for canonical crypto leaf decoding.
//!
//! These owners fund only retained byte backing. The enclosing decoder still
//! owns its frame, active logical limits, scope controls and scratch. Callers
//! must validate protocol-specific algorithm/length geometry before selecting
//! an exact destination. A geometry refusal here is a local planning error, not
//! evidence that the offered bytes are protocol-invalid.

use iroha_allocation::{AllocationBudget, AllocationCharge, ChargedBuffer, ChargedBufferError};
use norito::core::{Encoder, Error, SerializePayload};

use crate::{
    ChargedPublicKey, ChargedSignature, PublicKey, PublicKeyAllocationError, PublicKeyCompact,
    SignatureAllocationError, SignaturePayloadError, public_key_decode, signature,
};

/// A canonical leaf failure or a distinct mismatch with its prepared destination.
#[derive(Debug)]
pub enum PreparedCryptoDecodeError {
    /// Original framing, public-key validity or active decoder resource failure.
    Codec(Error),
    /// The authenticated/planned output geometry differs from the offered leaf.
    /// This variant must remain a local destination failure at protocol adapters.
    Geometry {
        /// Exact original allocation capacity selected before decoding.
        expected: usize,
        /// Decoded payload length (including the key algorithm tag for keys).
        offered: usize,
    },
    /// The canonical signature byte validity rule rejected the payload.
    Signature(SignaturePayloadError),
}

impl From<Error> for PreparedCryptoDecodeError {
    fn from(error: Error) -> Self {
        Self::Codec(error)
    }
}
impl std::fmt::Display for PreparedCryptoDecodeError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Codec(error) => error.fmt(formatter),
            Self::Geometry { expected, offered } => write!(
                formatter,
                "prepared crypto destination holds {expected} bytes, offered leaf holds {offered}"
            ),
            Self::Signature(error) => error.fmt(formatter),
        }
    }
}
impl std::error::Error for PreparedCryptoDecodeError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Codec(error) => Some(error),
            Self::Signature(error) => Some(error),
            Self::Geometry { .. } => None,
        }
    }
}

/// A canonical key failure or original-pool refusal at its retained-backing boundary.
///
/// Logical decode work is consumed before physical admission and is never rolled
/// back. This preserves the exact codec cause or original pool release observation;
/// diagnostic formatting is not performed while constructing either error.
#[derive(Debug)]
pub enum PublicKeyDecodeAdmissionError {
    /// Original canonical framing, key validation or cumulative decode-work failure.
    Codec(Error),
    /// Exact compact backing could not be admitted or physically allocated.
    Allocation(ChargedBufferError),
}
impl From<Error> for PublicKeyDecodeAdmissionError {
    fn from(error: Error) -> Self {
        Self::Codec(error)
    }
}
impl std::fmt::Display for PublicKeyDecodeAdmissionError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Codec(error) => error.fmt(formatter),
            Self::Allocation(error) => error.fmt(formatter),
        }
    }
}
impl std::error::Error for PublicKeyDecodeAdmissionError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Codec(error) => Some(error),
            Self::Allocation(error) => Some(error),
        }
    }
}

/// Original JSON syntax/resource failure or a distinct original-pool key refusal.
#[derive(Debug)]
pub enum PublicKeyJsonAdmissionError {
    /// The ordinary JSON/key parser's unchanged canonical failure.
    Json(norito::json::Error),
    /// Original compact-key validity or logical resource cause, without diagnostics.
    Codec(Error),
    /// The exact temporary string or retained compact key could not be funded.
    Allocation(ChargedBufferError),
}
impl From<norito::json::Error> for PublicKeyJsonAdmissionError {
    fn from(error: norito::json::Error) -> Self {
        Self::Json(error)
    }
}
impl From<ChargedBufferError> for PublicKeyJsonAdmissionError {
    fn from(error: ChargedBufferError) -> Self {
        Self::Allocation(error)
    }
}
impl std::fmt::Display for PublicKeyJsonAdmissionError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Json(error) => error.fmt(formatter),
            Self::Codec(error) => error.fmt(formatter),
            Self::Allocation(error) => error.fmt(formatter),
        }
    }
}
impl std::error::Error for PublicKeyJsonAdmissionError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Json(error) => Some(error),
            Self::Codec(error) => Some(error),
            Self::Allocation(error) => Some(error),
        }
    }
}

// The shared JSON kernel receives one fully initialized exact byte destination.
// It cannot grow or separate the buffer from its original pool charge.
struct JsonTextBuffer(ChargedBuffer<u8>);
impl AsMut<[u8]> for JsonTextBuffer {
    fn as_mut(&mut self) -> &mut [u8] {
        self.0.as_mut_slice()
    }
}

struct InitializedBytes {
    bytes: ChargedBuffer<u8>,
    ready: bool,
}
impl InitializedBytes {
    fn new(mut bytes: ChargedBuffer<u8>) -> Self {
        // Initialization precedes any decode attempt. No unsafe exposure or
        // capacity growth is needed, and even malformed input can overwrite the
        // complete initialized slice while retaining the original allocation.
        for _ in 0..bytes.capacity() {
            bytes.push_reserved(0);
        }
        Self {
            bytes,
            ready: false,
        }
    }
    fn decoded(&self) -> Option<&[u8]> {
        self.ready.then(|| self.bytes.as_slice())
    }
    fn check_length(&self, offered: usize) -> Result<(), PreparedCryptoDecodeError> {
        if offered != self.bytes.capacity() {
            return Err(PreparedCryptoDecodeError::Geometry {
                expected: self.bytes.capacity(),
                offered,
            });
        }
        Ok(())
    }
    fn serialize(&self, writer: &mut Encoder<'_>) -> Result<(), Error> {
        let payload = self.decoded().ok_or(Error::InvalidValue {
            context: "unfinished prepared crypto destination",
        })?;
        // This is the canonical ConstVec element encoder, not Vec<u8>'s raw
        // byte specialization. No second protocol type/schema is introduced.
        norito::core::write_element_sequence::<u8, _>(writer, payload.iter())
    }
}

/// Exact, initialized signature storage admitted before a decoding attempt.
///
/// Failed decoding and [`Self::reset`] retain the same backing and charge.
/// Successful decoding establishes codec validity only, not authentication.
/// There is no Clone or mutable/owning byte escape.
pub struct PreparedSignatureDecode(InitializedBytes);

impl PreparedSignatureDecode {
    /// Allocate and initialize the exact offered original charge before decoding.
    ///
    /// # Errors
    /// Returns the unchanged charge on foreign source, layout mismatch/overflow,
    /// or a physical allocator refusal. No admission or refund occurs on error.
    pub fn try_from_charge(
        exact_bytes: usize,
        budget: &AllocationBudget,
        charge: AllocationCharge,
    ) -> Result<Self, (AllocationCharge, SignatureAllocationError)> {
        if !charge.belongs_to(budget) {
            return Err((charge, SignatureAllocationError::ForeignPool));
        }
        let bytes = ChargedBuffer::try_from_charge(exact_bytes, charge)
            .map_err(|(charge, error)| (charge, SignatureAllocationError::Allocation(error)))?;
        Ok(Self(InitializedBytes::new(bytes)))
    }

    /// Decode one complete canonical signature payload into retained storage.
    /// The caller owns the advertised flags and enclosing decode scope.
    ///
    /// # Errors
    /// Preserves the original codec failure, fixed invalid-payload cause, or
    /// local prepared-geometry mismatch. Every error clears validity, including
    /// after a prior successful attempt, without refunding or replacing storage.
    pub fn decode_payload(&mut self, bytes: &[u8]) -> Result<(), PreparedCryptoDecodeError> {
        self.reset();
        let (length, raw_start) = signature::signature_payload_geometry(bytes)?;
        self.0.check_length(length)?;
        signature::decode_signature_payload_elements(
            bytes,
            raw_start,
            self.0.bytes.as_mut_slice(),
        )?;
        signature::validate_signature_payload(self.0.bytes.as_slice())
            .map_err(PreparedCryptoDecodeError::Signature)?;
        self.0.ready = true;
        Ok(())
    }

    /// Forget decoded validity while preserving the exact initialized backing.
    pub fn reset(&mut self) {
        self.0.ready = false;
    }

    /// Borrow validated bytes for the enclosing canonical stream comparison.
    /// This is codec validity only; signature authentication remains mandatory.
    #[must_use]
    pub fn decoded_payload(&self) -> Option<&[u8]> {
        self.0.decoded()
    }

    /// Whether this destination retains the exact original allocation source.
    #[must_use]
    pub fn belongs_to(&self, budget: &AllocationBudget) -> bool {
        self.0.bytes.belongs_to(budget)
    }

    /// Move the same complete allocation into the canonical immutable signature.
    ///
    /// # Errors
    /// Returns the unchanged destination unless its last decode completed. No
    /// allocation, shrinking, cloning, refund or revalidation occurs on success.
    pub fn finish(self) -> Result<ChargedSignature, Self> {
        if !self.0.ready {
            return Err(self);
        }
        Ok(signature::Signature::bind_payload_allocation(self.0.bytes))
    }
}

impl SerializePayload for PreparedSignatureDecode {
    fn serialize(&self, writer: &mut Encoder<'_>) -> Result<(), Error> {
        self.0.serialize(writer)
    }
}

/// Exact, initialized compact public-key storage admitted before decoding.
///
/// The fixed-stack canonical parser validates the key before copying into this
/// original backing. The stack scratch is bounded by the existing maximum key
/// size; it is not a heap allocation or a claim of enclosing stack admission.
pub struct PreparedPublicKeyDecode(InitializedBytes);

impl PreparedPublicKeyDecode {
    /// Restore a canonical JSON public-key leaf using its actual original finite pool.
    ///
    /// The shared JSON string kernel charges the ordinary decoded-string work
    /// before exact temporary backing. Canonical multihash geometry then precedes
    /// the ordinary compact logical charge, exact pool allocation and point check.
    /// The temporary string retires before return; only the immutable compact box
    /// and its original charge escape. This establishes syntax, not signer authority.
    /// Enclosing records, source bytes, controls and crypto scratch remain separate.
    ///
    /// # Errors
    /// Preserves ordinary JSON/key errors and exact original-pool or allocator
    /// refusal. Active cumulative decode counters are neither reset nor refunded.
    pub fn try_from_json(
        parser: &mut norito::json::Parser<'_>,
        budget: &AllocationBudget,
    ) -> Result<ChargedPublicKey, PublicKeyJsonAdmissionError> {
        let text = parser.parse_string_with_buffer(|length| {
            let mut buffer = ChargedBuffer::new(length, budget)?;
            for _ in 0..length {
                buffer.push_reserved(0);
            }
            Ok::<_, PublicKeyJsonAdmissionError>(JsonTextBuffer(buffer))
        })?;
        // The shared JSON kernel already checked UTF-8, including escaped scalars.
        let value = std::str::from_utf8(text.0.as_slice()).map_err(|_| {
            PublicKeyJsonAdmissionError::Json(norito::json::Error::Message(
                "invalid public key".into(),
            ))
        })?;
        Self::try_from_canonical_text(value, budget).map_err(|error| match error {
            PublicKeyDecodeAdmissionError::Codec(error) => {
                PublicKeyJsonAdmissionError::Codec(error)
            }
            PublicKeyDecodeAdmissionError::Allocation(error) => {
                PublicKeyJsonAdmissionError::Allocation(error)
            }
        })
    }

    /// Restore bare canonical multihash text without an intermediate owned key.
    ///
    /// Unlike raw-material admission, the ordinary JSON/key parser creates compact
    /// backing before point validation. This preserves that exact order and active
    /// logical charge while choosing original-pool storage at the physical boundary.
    ///
    /// # Errors
    /// Returns the unchanged canonical/resource failure or exact local refusal.
    pub fn try_from_canonical_text(
        value: &str,
        budget: &AllocationBudget,
    ) -> Result<ChargedPublicKey, PublicKeyDecodeAdmissionError> {
        let decoded =
            crate::multihash::decode_public_key_str_borrowed(value).ok_or(Error::InvalidValue {
                context: "public key",
            })?;
        let payload_bytes = decoded.payload_hex.len() / 2;
        let exact_bytes = public_key_decode::reserve_compact_decode_backing(payload_bytes)?;
        let mut backing = ChargedBuffer::new(exact_bytes, budget)
            .map_err(PublicKeyDecodeAdmissionError::Allocation)?;
        backing.push_reserved(PublicKeyCompact::algorithm_tag(decoded.algorithm));
        for pair in decoded.payload_hex.as_bytes().chunks_exact(2) {
            let byte = crate::multihash::decode_public_key_payload_byte(pair).ok_or(
                Error::InvalidValue {
                    context: "public key",
                },
            )?;
            backing.push_reserved(byte);
        }
        public_key_decode::validate(decoded.algorithm, &backing.as_slice()[1..])?;
        Ok(PublicKey::bind_compact_allocation(backing))
    }

    /// Validate already-owned raw key material and fund its exact compact backing.
    ///
    /// The original material is borrowed. The shared allocation-free canonical
    /// validator runs before pool admission, then the compact tag and payload are
    /// copied into the exact original-pool allocation. This is not a wire decoder:
    /// no framing or cumulative Norito decode counter is consumed or reset.
    /// Validation scratch and enclosing source ownership remain caller obligations.
    ///
    /// # Errors
    /// Returns the original canonical key-validation failure, exact pool refusal,
    /// or physical allocator refusal before a destination can escape.
    pub fn try_from_material(
        algorithm: super::Algorithm,
        payload: &[u8],
        budget: &AllocationBudget,
    ) -> Result<ChargedPublicKey, PublicKeyDecodeAdmissionError> {
        Self::from_material_with(algorithm, payload, budget, false)
    }

    /// Decode raw canonical key bytes directly into original-pool custody.
    ///
    /// Uses the same allocation-free validator and exact compact destination as
    /// [`Self::try_from_material`]. After validation, it consumes the ordinary
    /// decode backing charge before asking the original finite pool or allocator.
    /// No intermediate key, serialized envelope or replacement counter is made.
    ///
    /// # Errors
    /// Preserves the original canonical/logical refusal or exact physical refusal.
    pub fn try_from_material_for_decode(
        algorithm: super::Algorithm,
        payload: &[u8],
        budget: &AllocationBudget,
    ) -> Result<ChargedPublicKey, PublicKeyDecodeAdmissionError> {
        Self::from_material_with(algorithm, payload, budget, true)
    }

    fn from_material_with(
        algorithm: super::Algorithm,
        payload: &[u8],
        budget: &AllocationBudget,
        decode: bool,
    ) -> Result<ChargedPublicKey, PublicKeyDecodeAdmissionError> {
        public_key_decode::validate(algorithm, payload)?;
        let exact_bytes = if decode {
            public_key_decode::reserve_compact_decode_backing(payload.len())?
        } else {
            payload.len().checked_add(1).ok_or_else(|| {
                PublicKeyDecodeAdmissionError::Allocation(
                    iroha_allocation::ChargedBufferError::Admission(
                        iroha_allocation::AllocationRefusal::DemandOverflow,
                    ),
                )
            })?
        };
        let mut backing = ChargedBuffer::new(exact_bytes, budget)
            .map_err(PublicKeyDecodeAdmissionError::Allocation)?;
        backing.push_reserved(PublicKeyCompact::algorithm_tag(algorithm));
        for &byte in payload {
            backing.push_reserved(byte);
        }
        Ok(PublicKey::bind_compact_allocation(backing))
    }

    /// Decode once and admit the exact compact backing from the original pool.
    ///
    /// Sequence work, tag/point validity and nominal retained-byte admission run
    /// at the same points as the ordinary key decoder. Only then is the exact
    /// physical layout prepaid and allocated. No geometry preview, second parse,
    /// alignment copy, counter reset or quota refund occurs. The completed owner
    /// destroys its canonical key before returning its original physical credit.
    ///
    /// The caller supplies the original advertised flags and canonical field
    /// context and retains the source bytes, enclosing frame and decode controls.
    /// This method funds only the compact key, not those enclosing owners. A
    /// refusal retains no prepared backing; retrying the same borrowed source
    /// consumes additional work in the same cumulative decode context.
    ///
    /// # Errors
    /// Returns the original codec/refusal cause or exact physical allocation
    /// failure. Successful prefix work remains consumed on every failure.
    pub fn try_decode_payload(
        bytes: &[u8],
        budget: &AllocationBudget,
    ) -> Result<ChargedPublicKey, PublicKeyDecodeAdmissionError> {
        public_key_decode::with_decoded_compact(bytes, true, |algorithm, payload| {
            let exact_bytes = public_key_decode::reserve_compact_decode_backing(payload.len())?;
            let mut backing = ChargedBuffer::new(exact_bytes, budget)
                .map_err(PublicKeyDecodeAdmissionError::Allocation)?;
            backing.push_reserved(PublicKeyCompact::algorithm_tag(algorithm));
            for &byte in payload {
                backing.push_reserved(byte);
            }
            Ok::<_, PublicKeyDecodeAdmissionError>(PublicKey::bind_compact_allocation(backing))
        })
        .map(|(owner, _)| owner)
    }

    /// Recheck canonical payload boundaries against an already-retained public key.
    ///
    /// The sole compact parser, validator and ordinary logical backing admission
    /// run again in the active context. No physical storage is allocated, replaced
    /// or refunded; the caller keeps the original key and its funding together.
    ///
    /// # Errors
    /// Returns the original canonical/resource error or a changed canonical key.
    pub fn recheck_payload(bytes: &[u8], original: &PublicKey) -> Result<(), Error> {
        public_key_decode::with_decoded_compact(bytes, true, |algorithm, payload| {
            public_key_decode::reserve_compact_decode_backing(payload.len())?;
            if original.to_bytes() != (algorithm, payload) {
                return Err(Error::InvalidValue {
                    context: "public key",
                });
            }
            Ok(())
        })
        .map(|((), _)| ())
    }

    /// Allocate and initialize the exact compact allocation, including its tag.
    ///
    /// # Errors
    /// Returns the unchanged original charge on source/layout/allocator refusal.
    pub fn try_from_charge(
        exact_bytes: usize,
        budget: &AllocationBudget,
        charge: AllocationCharge,
    ) -> Result<Self, (AllocationCharge, PublicKeyAllocationError)> {
        if !charge.belongs_to(budget) {
            return Err((charge, PublicKeyAllocationError::ForeignPool));
        }
        let bytes = ChargedBuffer::try_from_charge(exact_bytes, charge)
            .map_err(|(charge, error)| (charge, PublicKeyAllocationError::Allocation(error)))?;
        Ok(Self(InitializedBytes::new(bytes)))
    }

    /// Decode one complete compact payload with the sole canonical key validator.
    /// The caller owns the advertised flags and enclosing decode scope.
    ///
    /// # Errors
    /// Returns the original codec failure or a distinct local destination shape
    /// failure. The exact backing survives, and stale validity is always cleared.
    pub fn decode_payload(&mut self, bytes: &[u8]) -> Result<(), PreparedCryptoDecodeError> {
        self.reset();
        public_key_decode::with_decoded_compact(bytes, true, |algorithm, payload| {
            self.0.check_length(payload.len() + 1)?;
            // Prepaid physical storage does not relax canonical logical work
            // ceilings. Preserve the ordinary compact owner's retained-storage
            // charge after the common sequence-count/element charges and
            // identical tag/point validation, before any copied byte.
            public_key_decode::reserve_compact_decode_backing(payload.len())?;
            let destination = self.0.bytes.as_mut_slice();
            destination[0] = PublicKeyCompact::algorithm_tag(algorithm);
            destination[1..].copy_from_slice(payload);
            Ok::<_, PreparedCryptoDecodeError>(())
        })?;
        self.0.ready = true;
        Ok(())
    }

    /// Forget decoded validity without changing original storage or charge.
    pub fn reset(&mut self) {
        self.0.ready = false;
    }

    /// Borrow validated canonical tag/payload bytes for exact stream comparison.
    #[must_use]
    pub fn decoded_compact(&self) -> Option<&[u8]> {
        self.0.decoded()
    }

    /// Whether this destination retains the exact original allocation source.
    #[must_use]
    pub fn belongs_to(&self, budget: &AllocationBudget) -> bool {
        self.0.bytes.belongs_to(budget)
    }

    /// Move complete original storage into the immutable canonical public key.
    ///
    /// # Errors
    /// Returns the unchanged destination unless the last decode succeeded. The
    /// fully filled exact buffer cannot shrink while being converted to a Box.
    pub fn finish(self) -> Result<ChargedPublicKey, Self> {
        if !self.0.ready {
            return Err(self);
        }
        Ok(PublicKey::bind_compact_allocation(self.0.bytes))
    }
}
impl SerializePayload for PreparedPublicKeyDecode {
    fn serialize(&self, writer: &mut Encoder<'_>) -> Result<(), Error> {
        self.0.serialize(writer)
    }
}

#[cfg(test)]
mod tests;
