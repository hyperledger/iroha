//! `Frame`, the length-prefixed preimage encoding of the evaluation record
//! (section 6.1), and the bounded opaque public inputs.
//!
//! ```text
//! Frame(tag; fields...) =
//!     u16_le(len(tag)) || ASCII(tag) ||
//!     u16_le(number_of_fields) ||
//!     concat(u32_le(len(field)) || field)
//! ```
//!
//! `Frame` is a cryptographic preimage definition, not a wire codec. The opaque
//! inputs are byte strings with a length bound and nothing else: this module does
//! not parse, normalise, delimit or terminate them. Whether two byte strings
//! encode the same typed node value is the caller's question, not this crate's.

use iroha_zkp_vole::hash::{SHA3_512_BYTES, Sha3_512};
use thiserror::Error;

/// Largest `Enc(body_context)` in bytes.
pub const BODY_CONTEXT_MAX_BYTES: usize = 4096;
/// Largest of each of the other opaque inputs in bytes.
pub const OPAQUE_FIELD_MAX_BYTES: usize = 256;
/// Length of every digest of the construction in bytes.
pub const DIGEST_BYTES: usize = SHA3_512_BYTES;
/// Length of a credential commitment in bytes.
pub const COMMITMENT_BYTES: usize = 128;

/// Errors of the framing layer and of the bounded inputs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum FramingError {
    /// A frame tag is longer than `u16::MAX` bytes.
    #[error("a frame tag of {actual} bytes does not fit its 16-bit length")]
    TagTooLong {
        /// Length supplied.
        actual: usize,
    },
    /// A frame tag is not ASCII.
    #[error("a frame tag must be ASCII")]
    TagNotAscii,
    /// A frame has more than `u16::MAX` fields.
    #[error("{actual} fields do not fit the 16-bit field count of a frame")]
    TooManyFields {
        /// Number of fields requested.
        actual: usize,
    },
    /// A field is longer than `u32::MAX` bytes.
    #[error("a field of {actual} bytes does not fit its 32-bit length")]
    FieldTooLong {
        /// Length supplied.
        actual: u64,
    },
    /// A field was started although every declared field was already written.
    #[error("the frame already has its declared number of fields")]
    UnexpectedField,
    /// A field was started, or the frame finished, while a streamed field still
    /// lacks bytes.
    #[error("the current field still lacks {missing} bytes")]
    FieldIncomplete {
        /// Bytes still owed to the current field.
        missing: u64,
    },
    /// More bytes were written than the current field declared.
    #[error("{excess} bytes more than the current field declared")]
    FieldOverrun {
        /// Bytes beyond the declared length.
        excess: u64,
    },
    /// The frame was finished before every declared field was written.
    #[error("the frame still lacks {missing} fields")]
    MissingFields {
        /// Fields still owed.
        missing: u16,
    },
    /// An opaque input is longer than its bound.
    #[error("an opaque input of {actual} bytes exceeds its bound of {bound} bytes")]
    BoundExceeded {
        /// The bound in bytes.
        bound: usize,
        /// Length supplied.
        actual: usize,
    },
    /// A fixed-size value does not have its size.
    #[error("a fixed-size value must be {expected} bytes long, got {actual}")]
    FixedLength {
        /// Required length in bytes.
        expected: usize,
        /// Length supplied.
        actual: usize,
    },
}

/// Something a frame can be written into.
pub trait Sink {
    /// Take the next bytes of the frame.
    fn absorb(&mut self, bytes: &[u8]);
}

impl Sink for Vec<u8> {
    fn absorb(&mut self, bytes: &[u8]) {
        self.extend_from_slice(bytes);
    }
}

impl Sink for Sha3_512 {
    fn absorb(&mut self, bytes: &[u8]) {
        self.update(bytes);
    }
}

/// An incremental writer of one `Frame(tag; fields...)` into a [`Sink`].
///
/// The number of fields is declared up front, as the encoding requires; a field
/// is either written whole with [`Frame::field`] or declared with
/// [`Frame::begin_field`] and streamed with [`Frame::write`]. [`Frame::finish`]
/// checks that exactly the declared fields and bytes were written.
#[derive(Debug)]
pub struct Frame<'s, S: Sink> {
    sink: &'s mut S,
    /// Fields not yet started.
    fields_left: u16,
    /// Bytes the current streamed field still lacks.
    bytes_left: u64,
}

impl<'s, S: Sink> Frame<'s, S> {
    /// Start a frame with `tag` and exactly `fields` fields.
    ///
    /// # Errors
    /// [`FramingError::TagNotAscii`], [`FramingError::TagTooLong`] or
    /// [`FramingError::TooManyFields`].
    pub fn begin(sink: &'s mut S, tag: &[u8], fields: usize) -> Result<Self, FramingError> {
        if !tag.is_ascii() {
            return Err(FramingError::TagNotAscii);
        }
        let tag_len =
            u16::try_from(tag.len()).map_err(|_| FramingError::TagTooLong { actual: tag.len() })?;
        let count =
            u16::try_from(fields).map_err(|_| FramingError::TooManyFields { actual: fields })?;
        sink.absorb(&tag_len.to_le_bytes());
        sink.absorb(tag);
        sink.absorb(&count.to_le_bytes());
        Ok(Self {
            sink,
            fields_left: count,
            bytes_left: 0,
        })
    }

    /// Declare the next field as `len` bytes long; its bytes follow through
    /// [`Frame::write`].
    ///
    /// # Errors
    /// [`FramingError::FieldIncomplete`] if the previous field lacks bytes,
    /// [`FramingError::UnexpectedField`] if every declared field was written and
    /// [`FramingError::FieldTooLong`] if `len` exceeds `u32::MAX`.
    pub fn begin_field(&mut self, len: u64) -> Result<(), FramingError> {
        if self.bytes_left != 0 {
            return Err(FramingError::FieldIncomplete {
                missing: self.bytes_left,
            });
        }
        let Some(left) = self.fields_left.checked_sub(1) else {
            return Err(FramingError::UnexpectedField);
        };
        let prefix = u32::try_from(len).map_err(|_| FramingError::FieldTooLong { actual: len })?;
        self.fields_left = left;
        self.bytes_left = len;
        self.sink.absorb(&prefix.to_le_bytes());
        Ok(())
    }

    /// Write the next bytes of the field declared with [`Frame::begin_field`].
    ///
    /// # Errors
    /// [`FramingError::FieldOverrun`] if `chunk` is longer than what the field
    /// still lacks; nothing is written then.
    pub fn write(&mut self, chunk: &[u8]) -> Result<(), FramingError> {
        let len = u64::try_from(chunk.len()).unwrap_or(u64::MAX);
        let Some(left) = self.bytes_left.checked_sub(len) else {
            return Err(FramingError::FieldOverrun {
                excess: len - self.bytes_left,
            });
        };
        self.bytes_left = left;
        self.sink.absorb(chunk);
        Ok(())
    }

    /// Write one whole field.
    ///
    /// # Errors
    /// As [`Frame::begin_field`].
    pub fn field(&mut self, bytes: &[u8]) -> Result<(), FramingError> {
        self.begin_field(u64::try_from(bytes.len()).unwrap_or(u64::MAX))?;
        self.write(bytes)
    }

    /// Finish the frame.
    ///
    /// # Errors
    /// [`FramingError::FieldIncomplete`] or [`FramingError::MissingFields`] if the
    /// frame is not complete.
    pub fn finish(self) -> Result<(), FramingError> {
        if self.bytes_left != 0 {
            return Err(FramingError::FieldIncomplete {
                missing: self.bytes_left,
            });
        }
        if self.fields_left != 0 {
            return Err(FramingError::MissingFields {
                missing: self.fields_left,
            });
        }
        Ok(())
    }
}

/// Write `Frame(tag; fields...)` into `sink`.
///
/// # Errors
/// As [`Frame::begin`] and [`Frame::field`].
pub fn write_frame<S: Sink>(
    sink: &mut S,
    tag: &[u8],
    fields: &[&[u8]],
) -> Result<(), FramingError> {
    let mut frame = Frame::begin(sink, tag, fields.len())?;
    for field in fields {
        frame.field(field)?;
    }
    frame.finish()
}

/// The bytes of `Frame(tag; fields...)`.
///
/// # Errors
/// As [`write_frame`].
pub fn frame_bytes(tag: &[u8], fields: &[&[u8]]) -> Result<Vec<u8>, FramingError> {
    let mut out = Vec::new();
    write_frame(&mut out, tag, fields)?;
    Ok(out)
}

/// `SHA3-512(Frame(tag; fields...))`.
///
/// # Errors
/// As [`write_frame`].
pub fn frame_digest(tag: &[u8], fields: &[&[u8]]) -> Result<Digest64, FramingError> {
    let mut sponge = Sha3_512::new();
    write_frame(&mut sponge, tag, fields)?;
    Ok(Digest64(sponge.finalize()))
}

/// `Enc(body_context)`: an opaque byte string of 0 to 4,096 bytes.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct BodyContext(Vec<u8>);

impl BodyContext {
    /// The body context `bytes`, taken as they are.
    ///
    /// # Errors
    /// [`FramingError::BoundExceeded`] above [`BODY_CONTEXT_MAX_BYTES`].
    pub fn new(bytes: &[u8]) -> Result<Self, FramingError> {
        if bytes.len() > BODY_CONTEXT_MAX_BYTES {
            return Err(FramingError::BoundExceeded {
                bound: BODY_CONTEXT_MAX_BYTES,
                actual: bytes.len(),
            });
        }
        Ok(Self(bytes.to_vec()))
    }

    /// The bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

/// One of the opaque inputs bounded at 256 bytes: `Enc(network_id)`,
/// `Enc(authority)`, `Enc(assignment_id)`, `Enc(governance_attempt_id)`,
/// `Enc(election_attempt_id)`, `Enc(body_role)`, and `Enc(body_instance_id)` of
/// the scope helper.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct OpaqueField(Vec<u8>);

impl OpaqueField {
    /// The opaque input `bytes`, taken as they are.
    ///
    /// # Errors
    /// [`FramingError::BoundExceeded`] above [`OPAQUE_FIELD_MAX_BYTES`].
    pub fn new(bytes: &[u8]) -> Result<Self, FramingError> {
        if bytes.len() > OPAQUE_FIELD_MAX_BYTES {
            return Err(FramingError::BoundExceeded {
                bound: OPAQUE_FIELD_MAX_BYTES,
                actual: bytes.len(),
            });
        }
        Ok(Self(bytes.to_vec()))
    }

    /// The bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

/// A 64-byte public value: `B`, `scope`, `R`, `auth`, `nf`, `policy_hash`,
/// `proposal_digest`, `D` or `D_reg`.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Digest64(pub [u8; DIGEST_BYTES]);

impl core::fmt::Debug for Digest64 {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write_hex(f, "Digest64", &self.0)
    }
}

impl Digest64 {
    /// The value in `bytes`.
    ///
    /// # Errors
    /// [`FramingError::FixedLength`] unless `bytes` is exactly 64 bytes long.
    pub fn from_slice(bytes: &[u8]) -> Result<Self, FramingError> {
        <[u8; DIGEST_BYTES]>::try_from(bytes)
            .map(Self)
            .map_err(|_| FramingError::FixedLength {
                expected: DIGEST_BYTES,
                actual: bytes.len(),
            })
    }

    /// The bytes.
    pub const fn as_bytes(&self) -> &[u8; DIGEST_BYTES] {
        &self.0
    }
}

/// A 128-byte credential commitment `C`, also the type of a sealed-list entry.
/// Ordered bytewise as unsigned bytes, the order of the sealed list.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Commitment(pub [u8; COMMITMENT_BYTES]);

impl core::fmt::Debug for Commitment {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write_hex(f, "Commitment", &self.0)
    }
}

impl Commitment {
    /// The commitment in `bytes`.
    ///
    /// # Errors
    /// [`FramingError::FixedLength`] unless `bytes` is exactly 128 bytes long.
    pub fn from_slice(bytes: &[u8]) -> Result<Self, FramingError> {
        <[u8; COMMITMENT_BYTES]>::try_from(bytes)
            .map(Self)
            .map_err(|_| FramingError::FixedLength {
                expected: COMMITMENT_BYTES,
                actual: bytes.len(),
            })
    }

    /// The bytes.
    pub const fn as_bytes(&self) -> &[u8; COMMITMENT_BYTES] {
        &self.0
    }
}

/// `name(hex)` for the `Debug` output of the public fixed-size values.
fn write_hex(f: &mut core::fmt::Formatter<'_>, name: &str, bytes: &[u8]) -> core::fmt::Result {
    write!(f, "{name}(")?;
    for byte in bytes {
        write!(f, "{byte:02x}")?;
    }
    write!(f, ")")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_frame_has_the_layout_of_the_record() {
        let bytes = frame_bytes(b"AB", &[b"xyz", b"", b"q"]).expect("valid frame");
        assert_eq!(
            bytes,
            [
                2, 0, b'A', b'B', // tag
                3, 0, // field count
                3, 0, 0, 0, b'x', b'y', b'z', // field 0
                0, 0, 0, 0, // field 1, empty
                1, 0, 0, 0, b'q', // field 2
            ]
        );
        // No fields at all is a frame too.
        assert_eq!(frame_bytes(b"", &[]).expect("valid frame"), [0, 0, 0, 0]);
        let mut sink = Vec::new();
        write_frame(&mut sink, b"AB", &[b"xyz", b"", b"q"]).expect("valid frame");
        assert_eq!(sink, bytes);
    }

    #[test]
    fn a_frame_digest_is_sha3_512_of_the_frame() {
        use sha3::Digest;
        let fields: [&[u8]; 2] = [&[7u8; 100], b"tail"];
        let bytes = frame_bytes(b"PARL/TEST", &fields).expect("valid frame");
        let expected: [u8; 64] = sha3::Sha3_512::digest(&bytes).into();
        assert_eq!(
            frame_digest(b"PARL/TEST", &fields).expect("valid frame"),
            Digest64(expected)
        );
    }

    #[test]
    fn a_streamed_field_gives_the_same_bytes_as_a_whole_one() {
        let payload: Vec<u8> = (0..=255u8).collect();
        let whole = frame_bytes(b"T", &[b"a", &payload]).expect("valid frame");
        let mut streamed = Vec::new();
        let mut frame = Frame::begin(&mut streamed, b"T", 2).expect("valid tag");
        frame.field(b"a").expect("first field");
        frame.begin_field(256).expect("second field");
        for chunk in payload.chunks(37) {
            frame.write(chunk).expect("within the declared length");
        }
        frame.finish().expect("complete");
        assert_eq!(streamed, whole);
    }

    #[test]
    fn frame_misuse_is_a_typed_error() {
        let mut sink = Vec::new();
        assert_eq!(
            Frame::begin(&mut sink, &[0x80], 0).err(),
            Some(FramingError::TagNotAscii)
        );
        assert_eq!(
            Frame::begin(&mut sink, &vec![b'a'; 65_536], 0).err(),
            Some(FramingError::TagTooLong { actual: 65_536 })
        );
        assert_eq!(
            Frame::begin(&mut sink, b"t", 65_536).err(),
            Some(FramingError::TooManyFields { actual: 65_536 })
        );
        assert!(sink.is_empty());

        let mut frame = Frame::begin(&mut sink, b"t", 2).expect("valid");
        assert_eq!(
            frame.begin_field(1 << 32),
            Err(FramingError::FieldTooLong { actual: 1 << 32 })
        );
        frame.begin_field(4).expect("declared");
        assert_eq!(
            frame.write(b"12345"),
            Err(FramingError::FieldOverrun { excess: 1 })
        );
        frame.write(b"12").expect("fits");
        assert_eq!(
            frame.begin_field(0),
            Err(FramingError::FieldIncomplete { missing: 2 })
        );
        assert_eq!(
            frame.field(b""),
            Err(FramingError::FieldIncomplete { missing: 2 })
        );
        frame.write(b"34").expect("fits");
        frame.field(b"").expect("second field");
        assert_eq!(frame.field(b""), Err(FramingError::UnexpectedField));
        assert_eq!(
            frame.write(b"x"),
            Err(FramingError::FieldOverrun { excess: 1 })
        );
        frame.finish().expect("complete");

        let mut frame = Frame::begin(&mut sink, b"t", 2).expect("valid");
        frame.begin_field(3).expect("declared");
        frame.write(b"1").expect("fits");
        assert_eq!(
            frame.finish(),
            Err(FramingError::FieldIncomplete { missing: 2 })
        );
        let mut frame = Frame::begin(&mut sink, b"t", 2).expect("valid");
        frame.field(b"1").expect("fits");
        assert_eq!(
            frame.finish(),
            Err(FramingError::MissingFields { missing: 1 })
        );
        assert_eq!(frame_bytes(&[0xff], &[]), Err(FramingError::TagNotAscii));
        assert_eq!(frame_digest(&[0xff], &[]), Err(FramingError::TagNotAscii));
    }

    #[test]
    fn opaque_inputs_enforce_their_bounds_and_nothing_else() {
        assert_eq!(BodyContext::new(&[]).expect("empty").as_bytes(), b"");
        let largest = vec![0u8; BODY_CONTEXT_MAX_BYTES];
        assert_eq!(
            BodyContext::new(&largest).expect("at the bound").as_bytes(),
            &largest[..]
        );
        assert_eq!(
            BodyContext::new(&vec![0u8; BODY_CONTEXT_MAX_BYTES + 1]),
            Err(FramingError::BoundExceeded {
                bound: 4096,
                actual: 4097
            })
        );
        assert_eq!(OpaqueField::new(&[]).expect("empty").as_bytes(), b"");
        assert!(OpaqueField::new(&[1u8; OPAQUE_FIELD_MAX_BYTES]).is_ok());
        assert_eq!(
            OpaqueField::new(&[1u8; OPAQUE_FIELD_MAX_BYTES + 1]),
            Err(FramingError::BoundExceeded {
                bound: 256,
                actual: 257
            })
        );
        // Bytes are kept exactly: no trimming, no terminator, no normalisation.
        let odd = b" \0caf\xc3\xa9\xff\n";
        assert_eq!(OpaqueField::new(odd).expect("opaque").as_bytes(), odd);
        assert_eq!(BodyContext::new(odd).expect("opaque").as_bytes(), odd);
    }

    #[test]
    fn fixed_size_values_have_exactly_their_size() {
        assert_eq!(
            Digest64::from_slice(&[9u8; 64]).expect("64 bytes"),
            Digest64([9; 64])
        );
        for len in [0usize, 63, 65, 128] {
            assert_eq!(
                Digest64::from_slice(&vec![0u8; len]),
                Err(FramingError::FixedLength {
                    expected: 64,
                    actual: len
                })
            );
        }
        assert_eq!(
            Commitment::from_slice(&[9u8; 128]).expect("128 bytes"),
            Commitment([9; 128])
        );
        for len in [0usize, 64, 127, 129] {
            assert_eq!(
                Commitment::from_slice(&vec![0u8; len]),
                Err(FramingError::FixedLength {
                    expected: 128,
                    actual: len
                })
            );
        }
        assert_eq!(Digest64([0xab; 64]).as_bytes(), &[0xab; 64]);
        assert_eq!(Commitment([0xab; 128]).as_bytes(), &[0xab; 128]);
        // Unsigned bytewise order.
        let mut low = [0u8; 128];
        let mut high = [0u8; 128];
        low[0] = 0x7f;
        high[0] = 0x80;
        assert!(Commitment(low) < Commitment(high));
        low[0] = 0x80;
        low[127] = 1;
        assert!(Commitment(high) < Commitment(low));
        assert_eq!(
            format!("{:?}", Digest64([0x0a; 64])).len(),
            "Digest64()".len() + 128
        );
        assert!(format!("{:?}", Commitment([0xff; 128])).starts_with("Commitment(ffff"));
    }
}
