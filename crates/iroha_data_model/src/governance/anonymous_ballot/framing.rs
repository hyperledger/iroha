//! The proof profile's `Frame`, SHA3-512 over it, and the pinned typed encoding `Enc`.
//!
//! ```text
//! Frame(tag; fields...) =
//!     u16_le(len(tag)) || ASCII(tag) ||
//!     u16_le(number_of_fields) ||
//!     concat(u32_le(len(field)) || field)
//! ```
//!
//! This is exactly `specs/parliament_ballot_proof_profile.md` §6.1 and
//! `iroha_parliament_ballot_proof::framing`, reimplemented here so that the data model
//! does not depend on the proof crate; a test cross-checks both. `Frame` is a
//! cryptographic preimage definition, not a wire codec.
//!
//! `Enc(x)` is one complete canonical, uncompressed, header-framed Norito frame of the
//! typed value `x` (integration decision 7), produced by [`norito::encode_canonical`]:
//!
//! | Bytes | Content |
//! | --- | --- |
//! | 0..4 | magic `NRT0` |
//! | 4, 5 | major and minor version `0`, `0` |
//! | 6..22 | the type's nominal schema identity, [`norito::schema::identity::frame_hash`] |
//! | 22 | compression `0` (none) |
//! | 23..31 | payload length, `u64` little-endian |
//! | 31..39 | CRC64-XZ of the payload, `u64` little-endian |
//! | 39 | layout flags: `0x02` (`COMPACT_LEN`), or `0x00` for a prefix-free payload |
//! | 40.. | alignment padding (none for every type used here) and the payload |
//!
//! The pinned flags rule (lifecycle decision K1):
//!
//! > `Enc<T>` uses the V1 compact-length encoding rules. Its flags byte is `0x02` exactly
//! > when payload encoding emits at least one per-value compact length prefix, and `0x00`
//! > otherwise. Sequence counts remain eight-byte little-endian values. All other flags are
//! > forbidden. Decoding enforces nominal schema identity, complete consumption and
//! > byte-for-byte equality with this pinned encoding, including the flags byte.
//!
//! So a prefix-free payload (a raw fixed-length leaf such as `NetworkId`, [`Digest512`] or
//! [`super::BallotAuthorityBindingV1`], or a unit enum such as `ParliamentBody`) carries
//! flags `0x00`, and every record type, which frames its fields, carries `0x02`. A future
//! codec change requires pinned cross-language golden vectors.
//!
//! [`enc`] fails closed unless Norito's canonical layout is still `COMPACT_LEN` and the
//! produced header matches this table, so a future change of the ambient Norito defaults
//! cannot silently change a digest preimage; [`decode_enc`] applies the same header check
//! and then [`norito::decode_canonical`] (bounded decode, complete consumption and
//! canonical byte equality, which also pins the flags byte).

use sha3::{Digest as _, Sha3_512};

use super::Digest512;

/// The pinned `Enc` layout: `COMPACT_LEN` per-value lengths. A frame's flags byte is this
/// value, or zero when its payload contains no per-value length prefix.
pub const ENC_LAYOUT_FLAGS_V1: u8 = 0x02;

/// Length of the Norito header that starts every `Enc` frame.
pub const ENC_HEADER_BYTES_V1: usize = 40;

/// Why a `Frame`, a digest or an `Enc` value could not be produced or read.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum AnonymousBallotCodecErrorV1 {
    /// The Norito canonical codec refused the value or the bytes.
    #[error("Norito canonical codec failed: {0}")]
    Codec(String),
    /// An `Enc` frame header is not the pinned canonical layout.
    #[error("`Enc` frame header is not the pinned canonical layout: {0}")]
    FrameLayout(&'static str),
    /// An encoded value exceeds its byte cap.
    #[error("{kind} has {actual} encoded bytes; at most {max} are allowed")]
    TooLarge {
        /// Kind of value.
        kind: &'static str,
        /// Encoded length.
        actual: usize,
        /// Cap in bytes.
        max: usize,
    },
    /// A `Frame` tag is not ASCII or longer than `u16::MAX` bytes.
    #[error("a `Frame` tag must be ASCII of at most 65,535 bytes")]
    InvalidTag,
    /// A `Frame` has more than `u16::MAX` fields.
    #[error("a `Frame` of {actual} fields exceeds its 16-bit field count")]
    TooManyFields {
        /// Number of fields requested.
        actual: usize,
    },
    /// A `Frame` field is longer than `u32::MAX` bytes.
    #[error("a `Frame` field of {actual} bytes exceeds its 32-bit length")]
    FieldTooLong {
        /// Length supplied.
        actual: usize,
    },
}

impl AnonymousBallotCodecErrorV1 {
    /// Wrap a Norito codec error.
    #[must_use]
    pub fn codec(error: &norito::Error) -> Self {
        Self::Codec(error.to_string())
    }
}

/// Feed `Frame(tag; fields...)` to `sink`, checking every length first.
fn write_frame(
    tag: &[u8],
    fields: &[&[u8]],
    mut sink: impl FnMut(&[u8]),
) -> Result<(), AnonymousBallotCodecErrorV1> {
    if !tag.is_ascii() {
        return Err(AnonymousBallotCodecErrorV1::InvalidTag);
    }
    let tag_len = u16::try_from(tag.len()).map_err(|_| AnonymousBallotCodecErrorV1::InvalidTag)?;
    let count =
        u16::try_from(fields.len()).map_err(|_| AnonymousBallotCodecErrorV1::TooManyFields {
            actual: fields.len(),
        })?;
    let mut prefixes = Vec::with_capacity(fields.len());
    for field in fields {
        let len =
            u32::try_from(field.len()).map_err(|_| AnonymousBallotCodecErrorV1::FieldTooLong {
                actual: field.len(),
            })?;
        prefixes.push(len.to_le_bytes());
    }
    sink(&tag_len.to_le_bytes());
    sink(tag);
    sink(&count.to_le_bytes());
    for (prefix, field) in prefixes.iter().zip(fields) {
        sink(prefix);
        sink(field);
    }
    Ok(())
}

/// The bytes of `Frame(tag; fields...)`.
///
/// # Errors
/// [`AnonymousBallotCodecErrorV1::InvalidTag`], [`AnonymousBallotCodecErrorV1::TooManyFields`]
/// or [`AnonymousBallotCodecErrorV1::FieldTooLong`]; nothing is produced then.
pub fn frame_bytes(tag: &[u8], fields: &[&[u8]]) -> Result<Vec<u8>, AnonymousBallotCodecErrorV1> {
    let mut out = Vec::new();
    write_frame(tag, fields, |bytes| out.extend_from_slice(bytes))?;
    Ok(out)
}

/// `SHA3-512(Frame(tag; fields...))`, streamed without materialising the frame.
///
/// # Errors
/// As [`frame_bytes`].
pub fn frame_digest(
    tag: &[u8],
    fields: &[&[u8]],
) -> Result<Digest512, AnonymousBallotCodecErrorV1> {
    let mut hasher = Sha3_512::new();
    write_frame(tag, fields, |bytes| hasher.update(bytes))?;
    Ok(Digest512::new(hasher.finalize().into()))
}

/// Check that `bytes` starts with the pinned `Enc` header of `T`.
fn check_enc_header<T: norito::NoritoSchema>(
    bytes: &[u8],
) -> Result<(), AnonymousBallotCodecErrorV1> {
    let header =
        bytes
            .get(..ENC_HEADER_BYTES_V1)
            .ok_or(AnonymousBallotCodecErrorV1::FrameLayout(
                "shorter than the header",
            ))?;
    if header[..4] != *b"NRT0" {
        return Err(AnonymousBallotCodecErrorV1::FrameLayout(
            "magic is not `NRT0`",
        ));
    }
    if header[4..6] != [0, 0] {
        return Err(AnonymousBallotCodecErrorV1::FrameLayout(
            "version is not 0.0",
        ));
    }
    if header[6..22] != norito::schema::identity::frame_hash::<T>() {
        return Err(AnonymousBallotCodecErrorV1::FrameLayout(
            "schema identity is not the value's type",
        ));
    }
    if header[22] != 0 {
        return Err(AnonymousBallotCodecErrorV1::FrameLayout(
            "payload is compressed",
        ));
    }
    if header[39] & !ENC_LAYOUT_FLAGS_V1 != 0 {
        return Err(AnonymousBallotCodecErrorV1::FrameLayout(
            "layout flags are neither 0x02 nor 0x00",
        ));
    }
    Ok(())
}

/// Fail closed if Norito's canonical encoder no longer uses the pinned layout.
fn check_canonical_layout() -> Result<(), AnonymousBallotCodecErrorV1> {
    if norito::core::default_encode_flags() == ENC_LAYOUT_FLAGS_V1 {
        Ok(())
    } else {
        Err(AnonymousBallotCodecErrorV1::FrameLayout(
            "Norito's canonical layout is no longer COMPACT_LEN",
        ))
    }
}

/// `Enc(value)`: the complete canonical uncompressed Norito frame of `value` with the
/// pinned header layout of this module.
///
/// # Errors
/// [`AnonymousBallotCodecErrorV1::Codec`] if Norito refuses the value and
/// [`AnonymousBallotCodecErrorV1::FrameLayout`] if Norito's canonical layout is no longer
/// `COMPACT_LEN` or the produced header is not the pinned layout.
pub fn enc<T: norito::NoritoSerialize>(value: &T) -> Result<Vec<u8>, AnonymousBallotCodecErrorV1> {
    check_canonical_layout()?;
    let bytes = norito::encode_canonical(value)
        .map_err(|error| AnonymousBallotCodecErrorV1::codec(&error))?;
    check_enc_header::<T>(&bytes)?;
    Ok(bytes)
}

/// Decode one exact `Enc` frame of `T`: the pinned header, then a bounded canonical decode
/// that consumes every byte and matches the canonical encoding byte for byte.
///
/// # Errors
/// [`AnonymousBallotCodecErrorV1::FrameLayout`] for another header and
/// [`AnonymousBallotCodecErrorV1::Codec`] for any decode failure.
pub fn decode_enc<T>(bytes: &[u8]) -> Result<T, AnonymousBallotCodecErrorV1>
where
    T: norito::NoritoSerialize + for<'de> norito::NoritoDeserialize<'de>,
{
    check_canonical_layout()?;
    check_enc_header::<T>(bytes)?;
    norito::decode_canonical::<T>(bytes).map_err(|error| AnonymousBallotCodecErrorV1::codec(&error))
}

/// `Enc(value)`, refused when it exceeds `max` bytes.
///
/// # Errors
/// As [`enc`], and [`AnonymousBallotCodecErrorV1::TooLarge`] above `max`.
pub fn enc_bounded<T: norito::NoritoSerialize>(
    value: &T,
    kind: &'static str,
    max: usize,
) -> Result<Vec<u8>, AnonymousBallotCodecErrorV1> {
    let actual = norito::canonical_frame_len(value)
        .map_err(|error| AnonymousBallotCodecErrorV1::codec(&error))?;
    if actual > max {
        return Err(AnonymousBallotCodecErrorV1::TooLarge { kind, actual, max });
    }
    enc(value)
}

/// [`decode_enc`] of at most `max` bytes; longer input is refused before decoding.
///
/// # Errors
/// [`AnonymousBallotCodecErrorV1::TooLarge`] above `max`, otherwise as [`decode_enc`].
pub fn decode_enc_bounded<T>(
    bytes: &[u8],
    kind: &'static str,
    max: usize,
) -> Result<T, AnonymousBallotCodecErrorV1>
where
    T: norito::NoritoSerialize + for<'de> norito::NoritoDeserialize<'de>,
{
    if bytes.len() > max {
        return Err(AnonymousBallotCodecErrorV1::TooLarge {
            kind,
            actual: bytes.len(),
            max,
        });
    }
    decode_enc(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::governance::anonymous_ballot::{BallotBodyContextV1, Digest512};

    /// `Frame` written independently of this module.
    fn reference_frame(tag: &[u8], fields: &[&[u8]]) -> Vec<u8> {
        let mut out = u16::try_from(tag.len())
            .expect("short")
            .to_le_bytes()
            .to_vec();
        out.extend_from_slice(tag);
        out.extend_from_slice(&u16::try_from(fields.len()).expect("few").to_le_bytes());
        for field in fields {
            out.extend_from_slice(&u32::try_from(field.len()).expect("short").to_le_bytes());
            out.extend_from_slice(field);
        }
        out
    }

    #[test]
    fn a_frame_has_the_layout_of_the_profile() {
        assert_eq!(
            frame_bytes(b"AB", &[b"xyz", b"", b"q"]).expect("frame"),
            [
                2, 0, b'A', b'B', // tag
                3, 0, // field count
                3, 0, 0, 0, b'x', b'y', b'z', // field 0
                0, 0, 0, 0, // field 1, empty
                1, 0, 0, 0, b'q', // field 2
            ]
        );
        assert_eq!(frame_bytes(b"", &[]).expect("frame"), [0, 0, 0, 0]);
        let long = vec![0x42; 70_000];
        assert_eq!(
            frame_bytes(b"PARL/TEST/v1", &[&long, b"tail"]).expect("frame"),
            reference_frame(b"PARL/TEST/v1", &[&long, b"tail"])
        );
    }

    #[test]
    fn a_frame_digest_is_sha3_512_of_the_frame() {
        let fields: [&[u8]; 3] = [&[7_u8; 100], b"", b"tail"];
        let expected: [u8; 64] = Sha3_512::digest(reference_frame(b"PARL/TEST/v1", &fields)).into();
        assert_eq!(
            frame_digest(b"PARL/TEST/v1", &fields).expect("frame"),
            Digest512::new(expected)
        );
        assert_ne!(
            frame_digest(b"PARL/TEST/v2", &fields).expect("frame"),
            Digest512::new(expected)
        );
    }

    #[test]
    fn frame_misuse_is_a_typed_error() {
        assert_eq!(
            frame_bytes(&[0x80], &[]),
            Err(AnonymousBallotCodecErrorV1::InvalidTag)
        );
        assert_eq!(
            frame_digest(&vec![b'a'; 65_536], &[]),
            Err(AnonymousBallotCodecErrorV1::InvalidTag)
        );
        let empty: &[u8] = b"";
        assert_eq!(
            frame_bytes(b"t", &vec![empty; 65_536]),
            Err(AnonymousBallotCodecErrorV1::TooManyFields { actual: 65_536 })
        );
        assert!(frame_bytes(b"t", &vec![empty; 65_535]).is_ok());
    }

    fn context() -> BallotBodyContextV1 {
        crate::governance::anonymous_ballot::test_fixtures::body_context()
    }

    #[test]
    fn enc_is_the_pinned_canonical_frame() {
        let value = context();
        let bytes = enc(&value).expect("enc");
        let payload = &bytes[ENC_HEADER_BYTES_V1..];
        // The complete header, field by field, with no alignment padding.
        let mut expected = b"NRT0".to_vec();
        expected.extend_from_slice(&[0, 0]);
        expected.extend_from_slice(&norito::core::schema_hash_for_name(
            "iroha_data_model::governance::anonymous_ballot::BallotBodyContextV1",
        ));
        expected.push(0);
        expected.extend_from_slice(&u64::try_from(payload.len()).expect("small").to_le_bytes());
        expected.extend_from_slice(&norito::hardware_crc64(payload).to_le_bytes());
        expected.push(0x02);
        expected.extend_from_slice(payload);
        assert_eq!(bytes, expected);
        assert_eq!(
            norito::schema::identity::frame_hash::<BallotBodyContextV1>(),
            norito::core::schema_hash_for_name(
                "iroha_data_model::governance::anonymous_ballot::BallotBodyContextV1"
            )
        );
        // The bare payload is the same bytes the bare codec produces.
        assert_eq!(payload, norito::codec::Encode::encode(&value));
        assert_eq!(decode_enc::<BallotBodyContextV1>(&bytes), Ok(value));
        assert_eq!(
            enc_bounded(&value, "context", bytes.len()),
            Ok(bytes.clone())
        );
        assert_eq!(
            enc_bounded(&value, "context", bytes.len() - 1),
            Err(AnonymousBallotCodecErrorV1::TooLarge {
                kind: "context",
                actual: bytes.len(),
                max: bytes.len() - 1
            })
        );
        assert_eq!(
            decode_enc_bounded::<BallotBodyContextV1>(&bytes, "context", bytes.len()),
            Ok(value)
        );
        assert!(matches!(
            decode_enc_bounded::<BallotBodyContextV1>(&bytes, "context", bytes.len() - 1),
            Err(AnonymousBallotCodecErrorV1::TooLarge { .. })
        ));
    }

    #[test]
    fn the_flags_byte_is_compact_len_exactly_when_a_length_prefix_is_written() {
        use crate::governance::{
            anonymous_ballot::{
                BallotAuthorityBindingV1, BallotChoiceV1,
                test_fixtures::{account, assignment, envelope, proposal, sealed_list},
            },
            types::ParliamentBody,
        };
        let context = context();
        let flags = |bytes: Vec<u8>| bytes[39];
        // Prefix-free payloads: raw fixed-length leaves and unit enums.
        assert_eq!(flags(enc(&context.network_id).expect("enc")), 0x00);
        assert_eq!(flags(enc(&ParliamentBody::PolicyJury).expect("enc")), 0x00);
        assert_eq!(
            flags(enc(&BallotAuthorityBindingV1::new([1; 64])).expect("enc")),
            0x00
        );
        assert_eq!(flags(enc(&Digest512::new([1; 64])).expect("enc")), 0x00);
        assert_eq!(flags(enc(&BallotChoiceV1::Aye).expect("enc")), 0x00);
        // Records and the 32-byte hash-wire identifiers frame their fields.
        assert_eq!(flags(enc(&context).expect("enc")), 0x02);
        assert_eq!(
            flags(enc(&context.governance_attempt_id).expect("enc")),
            0x02
        );
        assert_eq!(flags(enc(&assignment(1)).expect("enc")), 0x02);
        assert_eq!(flags(enc(&account()).expect("enc")), 0x02);
        assert_eq!(flags(enc(&proposal()).expect("enc")), 0x02);
        assert_eq!(flags(enc(&sealed_list(3)).expect("enc")), 0x02);
        assert_eq!(
            flags(enc(&envelope(BallotChoiceV1::Nay, 1)).expect("enc")),
            0x02
        );
        // A prefix-free leaf with the flag set is not canonical.
        let mut forced = enc(&context.network_id).expect("enc");
        forced[39] = ENC_LAYOUT_FLAGS_V1;
        assert!(decode_enc::<crate::NetworkId>(&forced).is_err());
        assert_eq!(ENC_LAYOUT_FLAGS_V1, norito::core::header_flags::COMPACT_LEN);
        assert_eq!(check_canonical_layout(), Ok(()));
    }

    #[test]
    fn decode_enc_refuses_every_other_header_and_payload() {
        let value = context();
        let bytes = enc(&value).expect("enc");
        let refused = |index: usize, byte: u8| {
            let mut changed = bytes.clone();
            changed[index] = byte;
            decode_enc::<BallotBodyContextV1>(&changed).is_err()
        };
        assert!(refused(0, b'X'), "magic");
        assert!(refused(4, 1), "major");
        assert!(refused(5, 1), "minor");
        assert!(refused(6, bytes[6] ^ 1), "schema");
        assert!(refused(22, 1), "compression");
        assert!(refused(23, bytes[23] ^ 1), "length");
        assert!(refused(31, bytes[31] ^ 1), "checksum");
        assert!(refused(39, 0x00), "flags 0x00");
        assert!(refused(39, 0x03), "flags 0x03");
        assert!(refused(39, 0x80), "flags 0x80");
        assert!(
            refused(bytes.len() - 1, bytes[bytes.len() - 1] ^ 1),
            "payload"
        );
        let mut extended = bytes.clone();
        extended.push(0);
        assert!(decode_enc::<BallotBodyContextV1>(&extended).is_err());
        assert!(decode_enc::<BallotBodyContextV1>(&bytes[..bytes.len() - 1]).is_err());
        assert_eq!(
            decode_enc::<BallotBodyContextV1>(&bytes[..10]),
            Err(AnonymousBallotCodecErrorV1::FrameLayout(
                "shorter than the header"
            ))
        );
        // A frame of another type is refused by its schema identity.
        let other = enc(&Digest512::new([1; 64])).expect("enc");
        assert_eq!(
            decode_enc::<BallotBodyContextV1>(&other),
            Err(AnonymousBallotCodecErrorV1::FrameLayout(
                "schema identity is not the value's type"
            ))
        );
        assert!(
            AnonymousBallotCodecErrorV1::codec(&norito::Error::LengthMismatch)
                .to_string()
                .starts_with("Norito canonical codec failed")
        );
    }
}
