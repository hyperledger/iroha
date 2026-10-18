//! Fixed-length byte values of the anonymous ballot and their raw Norito codecs.
//!
//! Every value here encodes as exactly its raw bytes: no per-element framing and no
//! inner length prefix (integration decision 7). The generic `[u8; N]` codec frames
//! each byte, which would double a commitment and make a 1,000-entry sealed list
//! exceed the 163,840-byte context cap. An enclosing record still frames each such
//! field with its ordinary length prefix and schema, so a value of any other length is
//! rejected when the field is decoded.
//!
//! JSON spells the short values as exactly `2 × LENGTH` lowercase hexadecimal digits
//! without a prefix, and the two proofs as padded standard base64 of exactly their
//! length. Both readers reject every other spelling and length.

use core::fmt;

use iroha_schema::{IntoSchema, MetaMap, Metadata, TypeId, UnnamedFieldsMeta};
use norito::json::{self, BoundedJsonError, JsonDeserialize, JsonSerialize, JsonWriteSink, Parser};

/// Why bytes or text are not a fixed-length anonymous-ballot value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum FixedBytesErrorV1 {
    /// The value does not have its exact length.
    #[error("{kind} must be exactly {expected} bytes, got {actual}")]
    Length {
        /// Type of the value.
        kind: &'static str,
        /// Required length in bytes.
        expected: usize,
        /// Length supplied.
        actual: usize,
    },
    /// The text is not the value's canonical spelling.
    #[error("{kind} text is not its canonical spelling")]
    Text {
        /// Type of the value.
        kind: &'static str,
    },
}

/// Exactly `2 × N` lowercase hexadecimal digits without a prefix, as `N` bytes.
fn decode_lowercase_hex<const N: usize>(text: &str) -> Option<[u8; N]> {
    if text.len() != N * 2
        || !text
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return None;
    }
    let mut out = [0_u8; N];
    hex::decode_to_slice(text, &mut out).ok()?;
    Some(out)
}

/// Implement a fixed-length byte value with the raw codec, lowercase-hex JSON and a
/// `Tuple([u8; N])` schema (the same shape as [`iroha_crypto::Hash`]).
macro_rules! fixed_bytes {
    ($(#[doc = $doc:literal])+ $name:ident, $len:literal, $schema:literal) => {
        $(#[doc = $doc])+
        ///
        /// Norito encodes the value as exactly its raw bytes; JSON as lowercase hexadecimal.
        #[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, TypeId, norito::NoritoSchema)]
        #[norito_schema(name = $schema)]
        #[repr(transparent)]
        pub struct $name([u8; $len]);

        impl $name {
            /// Exact length in bytes.
            pub const LENGTH: usize = $len;

            /// The value with exactly these bytes.
            #[must_use]
            pub const fn new(bytes: [u8; $len]) -> Self {
                Self(bytes)
            }

            /// The bytes.
            #[must_use]
            pub const fn as_bytes(&self) -> &[u8; $len] {
                &self.0
            }

            /// The bytes, by value.
            #[must_use]
            pub const fn into_bytes(self) -> [u8; $len] {
                self.0
            }

            /// The value in `bytes`.
            ///
            /// # Errors
            /// [`FixedBytesErrorV1::Length`] unless `bytes` has exactly `LENGTH` bytes.
            pub fn from_slice(bytes: &[u8]) -> Result<Self, FixedBytesErrorV1> {
                <[u8; $len]>::try_from(bytes)
                    .map(Self)
                    .map_err(|_| FixedBytesErrorV1::Length {
                        kind: stringify!($name),
                        expected: $len,
                        actual: bytes.len(),
                    })
            }

            /// The bytes as lowercase hexadecimal.
            #[must_use]
            pub fn to_hex(&self) -> String {
                hex::encode(self.0)
            }

            /// Parse exactly `2 × LENGTH` lowercase hexadecimal digits without a prefix.
            ///
            /// # Errors
            /// [`FixedBytesErrorV1::Text`] for any other spelling.
            pub fn from_hex(text: &str) -> Result<Self, FixedBytesErrorV1> {
                decode_lowercase_hex::<$len>(text)
                    .map(Self)
                    .ok_or(FixedBytesErrorV1::Text {
                        kind: stringify!($name),
                    })
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{}({})", stringify!($name), self.to_hex())
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(&self.to_hex())
            }
        }

        impl core::str::FromStr for $name {
            type Err = FixedBytesErrorV1;

            fn from_str(text: &str) -> Result<Self, Self::Err> {
                Self::from_hex(text)
            }
        }

        impl From<[u8; $len]> for $name {
            fn from(bytes: [u8; $len]) -> Self {
                Self(bytes)
            }
        }

        impl From<$name> for [u8; $len] {
            fn from(value: $name) -> Self {
                value.0
            }
        }

        impl AsRef<[u8]> for $name {
            fn as_ref(&self) -> &[u8] {
                &self.0
            }
        }

        impl norito::core::SerializePayload for $name {
            fn serialize(
                &self,
                writer: &mut norito::core::Encoder<'_>,
            ) -> Result<(), norito::core::Error> {
                writer.write_all(&self.0)?;
                Ok(())
            }

            fn encoded_len_hint(&self) -> Option<usize> {
                Some($len)
            }

            fn encoded_len_exact(&self) -> Option<usize> {
                Some($len)
            }
        }

        impl<'de> norito::core::DeserializePayload<'de> for $name {
            fn deserialize(archived: &'de norito::core::Archived<Self>) -> Self {
                Self::try_deserialize(archived)
                    .expect(concat!(stringify!($name), " decode needs exactly its raw bytes"))
            }

            fn try_deserialize(
                archived: &'de norito::core::Archived<Self>,
            ) -> Result<Self, norito::core::Error> {
                let ptr = core::ptr::from_ref(archived).cast::<u8>();
                let mut offset = 0;
                let bytes = norito::core::decode_context_byte_array::<$len>(ptr, &mut offset)?;
                // A canonical field holds exactly the raw bytes and nothing after them.
                norito::core::finish_context_fields(ptr, offset)?;
                Ok(Self(bytes))
            }
        }

        impl<'a> norito::core::DecodeFromSlice<'a> for $name {
            fn decode_from_slice(bytes: &'a [u8]) -> Result<(Self, usize), norito::core::Error> {
                let raw = bytes.get(..$len).ok_or(norito::core::Error::LengthMismatch)?;
                let mut value = [0_u8; $len];
                value.copy_from_slice(raw);
                Ok((Self(value), $len))
            }
        }

        impl IntoSchema for $name {
            fn type_name() -> String {
                stringify!($name).to_owned()
            }

            fn update_schema_map(map: &mut MetaMap) {
                if !map.contains_key::<Self>() {
                    <[u8; $len]>::update_schema_map(map);
                    map.insert::<Self>(Metadata::Tuple(UnnamedFieldsMeta {
                        types: vec![core::any::TypeId::of::<[u8; $len]>()],
                    }));
                }
            }
        }

        impl JsonSerialize for $name {
            fn json_serialize(&self, out: &mut String) {
                json::write_json_string(&self.to_hex(), out);
            }

            fn json_serialize_to(
                &self,
                out: &mut dyn JsonWriteSink,
            ) -> Result<(), BoundedJsonError> {
                json::write_json_string_to(&self.to_hex(), out)
            }
        }

        impl JsonDeserialize for $name {
            fn json_deserialize(parser: &mut Parser<'_>) -> Result<Self, json::Error> {
                let text = parser.parse_string()?;
                Self::from_hex(&text).map_err(|error| json::Error::Message(error.to_string()))
            }
        }
    };
}

fixed_bytes!(
    /// A 512-bit SHA3-512 digest: a list, body-context, policy, proposal, roster,
    /// registration-mapping, corpus, result, envelope or stamp digest.
    Digest512,
    64,
    "iroha_data_model::governance::anonymous_ballot::Digest512"
);

fixed_bytes!(
    /// A 1,024-bit credential commitment `C`, also the type of a sealed-list entry.
    ///
    /// The derived order is unsigned bytewise, the order of the sealed list.
    CredentialCommitmentV1,
    128,
    "iroha_data_model::governance::anonymous_ballot::CredentialCommitmentV1"
);

fixed_bytes!(
    /// The 512-bit registration authorization value `auth` published with a commitment.
    RegistrationAuthorizationV1,
    64,
    "iroha_data_model::governance::anonymous_ballot::RegistrationAuthorizationV1"
);

fixed_bytes!(
    /// The 1,024-bit nullifier `nf` of one credential in one ballot scope.
    NullifierV1,
    128,
    "iroha_data_model::governance::anonymous_ballot::NullifierV1"
);

fixed_bytes!(
    /// The 512-bit vote authorization value `auth_v` published in a ballot.
    VoteAuthorizationV1,
    64,
    "iroha_data_model::governance::anonymous_ballot::VoteAuthorizationV1"
);

fixed_bytes!(
    /// The 512-bit nullifier scope of one body instance's single ballot.
    BallotScopeV1,
    64,
    "iroha_data_model::governance::anonymous_ballot::BallotScopeV1"
);

fixed_bytes!(
    /// The public proof-profile identifier: the 64-byte descriptor digest `D` of the
    /// compiled parameter row (integration decision 6).
    ProofProfileIdV1,
    64,
    "iroha_data_model::governance::anonymous_ballot::ProofProfileIdV1"
);

fixed_bytes!(
    /// The 32-byte nonce of an admission stamp.
    AdmissionNonceV1,
    32,
    "iroha_data_model::governance::anonymous_ballot::AdmissionNonceV1"
);

fixed_bytes!(
    /// The nominal 64-byte registration authority binding
    /// `H(Frame("PARL/AUTHORITY/v1"; Enc(AccountId)))` whose `Enc` is the proof input
    /// `Enc(authority)` (integration decision 7).
    BallotAuthorityBindingV1,
    64,
    "iroha_data_model::governance::anonymous_ballot::BallotAuthorityBindingV1"
);

impl ProofProfileIdV1 {
    /// The only V1 profile: the descriptor digest `D` of the candidate row
    /// `(lambda, tau, w_grind, T_open, d_zk, n_mult) = (256, 33, 8, 229, 7, 704)`
    /// (`specs/parliament_ballot_proof_profile.md` §6.1).
    ///
    /// Selecting this row is not qualifying it; see
    /// [`super::PARLIAMENT_BALLOT_QUALIFICATION_V1`].
    pub const V1: Self = Self([
        0x01, 0xed, 0x9f, 0x56, 0x49, 0x81, 0xa0, 0x7a, //
        0xb3, 0x83, 0xd5, 0x13, 0xc4, 0xe8, 0x16, 0xf5, //
        0xa7, 0x65, 0x42, 0xc7, 0x22, 0x0e, 0xaa, 0xa3, //
        0x67, 0x42, 0xf8, 0xeb, 0x0c, 0x51, 0x34, 0x1d, //
        0xa0, 0x89, 0xe1, 0x54, 0xa8, 0x15, 0xf9, 0x2f, //
        0xcd, 0x18, 0x35, 0x30, 0x77, 0xcd, 0xe1, 0x8f, //
        0x43, 0x5d, 0xfa, 0xa0, 0x83, 0x4b, 0x65, 0xfd, //
        0xf3, 0xa6, 0x58, 0xb0, 0xac, 0xcd, 0xda, 0x28, //
    ]);

    /// Whether this is the V1 profile. Any other identifier is invalid in V1.
    #[must_use]
    pub fn is_v1(&self) -> bool {
        *self == Self::V1
    }
}

/// Implement an exact-length proof byte string: heap storage, raw codec of exactly
/// its length, base64 JSON and a `Tuple([u8; N])` schema.
macro_rules! exact_proof_bytes {
    ($(#[doc = $doc:literal])+ $name:ident, $len:literal, $schema:literal) => {
        $(#[doc = $doc])+
        ///
        /// Norito encodes the proof as exactly its raw bytes; decoding rejects any other
        /// length before allocating. JSON is padded standard base64.
        #[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, TypeId, norito::NoritoSchema)]
        #[norito_schema(name = $schema)]
        pub struct $name(Box<[u8]>);

        impl $name {
            /// Exact length in bytes.
            pub const LENGTH: usize = $len;

            /// The proof in `bytes`.
            ///
            /// # Errors
            /// [`FixedBytesErrorV1::Length`] unless `bytes` has exactly `LENGTH` bytes.
            pub fn new(bytes: Vec<u8>) -> Result<Self, FixedBytesErrorV1> {
                if bytes.len() == $len {
                    Ok(Self(bytes.into_boxed_slice()))
                } else {
                    Err(FixedBytesErrorV1::Length {
                        kind: stringify!($name),
                        expected: $len,
                        actual: bytes.len(),
                    })
                }
            }

            /// The proof in a copy of `bytes`.
            ///
            /// # Errors
            /// As [`Self::new`].
            pub fn from_slice(bytes: &[u8]) -> Result<Self, FixedBytesErrorV1> {
                if bytes.len() == $len {
                    Ok(Self(bytes.into()))
                } else {
                    Err(FixedBytesErrorV1::Length {
                        kind: stringify!($name),
                        expected: $len,
                        actual: bytes.len(),
                    })
                }
            }

            /// The bytes.
            #[must_use]
            pub fn as_bytes(&self) -> &[u8] {
                &self.0
            }

            /// The bytes, by value.
            #[must_use]
            pub fn into_bytes(self) -> Vec<u8> {
                self.0.into_vec()
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                let head = self.0.get(..8).unwrap_or(&self.0);
                write!(
                    f,
                    "{}({} bytes, {}..)",
                    stringify!($name),
                    self.0.len(),
                    hex::encode(head)
                )
            }
        }

        impl AsRef<[u8]> for $name {
            fn as_ref(&self) -> &[u8] {
                &self.0
            }
        }

        impl norito::core::SerializePayload for $name {
            fn serialize(
                &self,
                writer: &mut norito::core::Encoder<'_>,
            ) -> Result<(), norito::core::Error> {
                writer.write_all(&self.0)?;
                Ok(())
            }

            fn encoded_len_hint(&self) -> Option<usize> {
                Some(self.0.len())
            }

            fn encoded_len_exact(&self) -> Option<usize> {
                Some(self.0.len())
            }
        }

        impl<'de> norito::core::DeserializePayload<'de> for $name {
            fn deserialize(archived: &'de norito::core::Archived<Self>) -> Self {
                Self::try_deserialize(archived)
                    .expect(concat!(stringify!($name), " decode needs exactly its raw bytes"))
            }

            fn try_deserialize(
                archived: &'de norito::core::Archived<Self>,
            ) -> Result<Self, norito::core::Error> {
                let ptr = core::ptr::from_ref(archived).cast::<u8>();
                // Reject any other length before the copy is charged or allocated.
                norito::core::finish_context_fields(ptr, $len)?;
                let bytes = norito::core::payload_range_from_ptr(ptr, $len)?;
                norito::core::reserve_decode_allocation($len)?;
                Ok(Self(bytes.into()))
            }
        }

        impl<'a> norito::core::DecodeFromSlice<'a> for $name {
            fn decode_from_slice(bytes: &'a [u8]) -> Result<(Self, usize), norito::core::Error> {
                let raw = bytes.get(..$len).ok_or(norito::core::Error::LengthMismatch)?;
                norito::core::reserve_decode_allocation($len)?;
                Ok((Self(raw.into()), $len))
            }
        }

        impl IntoSchema for $name {
            fn type_name() -> String {
                stringify!($name).to_owned()
            }

            fn update_schema_map(map: &mut MetaMap) {
                if !map.contains_key::<Self>() {
                    <[u8; $len]>::update_schema_map(map);
                    map.insert::<Self>(Metadata::Tuple(UnnamedFieldsMeta {
                        types: vec![core::any::TypeId::of::<[u8; $len]>()],
                    }));
                }
            }
        }

        impl JsonSerialize for $name {
            fn json_serialize(&self, out: &mut String) {
                crate::json_helpers::base64_vec::serialize(&self.0, out);
            }

            fn json_serialize_to(
                &self,
                out: &mut dyn JsonWriteSink,
            ) -> Result<(), BoundedJsonError> {
                crate::json_helpers::base64_vec::serialize_bounded(&self.0, out)
            }
        }

        impl JsonDeserialize for $name {
            fn json_deserialize(parser: &mut Parser<'_>) -> Result<Self, json::Error> {
                let bytes = crate::json_helpers::base64_vec::deserialize(parser)?;
                Self::new(bytes).map_err(|error| json::Error::Message(error.to_string()))
            }
        }
    };
}

exact_proof_bytes!(
    /// A registration proof `pi_reg` of the V1 profile: exactly 160,148 bytes on the
    /// candidate row (`specs/parliament_ballot_proof_profile.md` §6.6).
    RegistrationProofBytesV1,
    160_148,
    "iroha_data_model::governance::anonymous_ballot::RegistrationProofBytesV1"
);

exact_proof_bytes!(
    /// A ballot proof `pi_vote` of the V1 profile: exactly 233,012 bytes on the
    /// candidate row (`specs/parliament_ballot_proof_profile.md` §6.6).
    BallotProofBytesV1,
    233_012,
    "iroha_data_model::governance::anonymous_ballot::BallotProofBytesV1"
);

#[cfg(test)]
mod tests {
    use norito::codec::{Decode, Encode};

    use super::*;

    /// A header-framed frame of `payload` declaring `T`'s schema and the layout `flags`,
    /// built by hand.
    fn frame_of<T: norito::NoritoSchema>(payload: &[u8], flags: u8) -> Vec<u8> {
        let mut out = b"NRT0".to_vec();
        out.extend_from_slice(&[0, 0]);
        out.extend_from_slice(&norito::schema::identity::frame_hash::<T>());
        out.push(0);
        out.extend_from_slice(&u64::try_from(payload.len()).expect("small").to_le_bytes());
        out.extend_from_slice(&norito::hardware_crc64(payload).to_le_bytes());
        out.push(flags);
        out.extend_from_slice(payload);
        out
    }

    fn check_fixed<T>(value: &T, raw: &[u8])
    where
        T: norito::NoritoSerialize
            + for<'de> norito::NoritoDeserialize<'de>
            + JsonSerialize
            + JsonDeserialize
            + PartialEq
            + fmt::Debug,
    {
        // The bare payload is exactly the raw bytes.
        assert_eq!(value.encode(), raw);
        assert_eq!(&T::decode(&mut &raw[..]).expect("exact length"), value);
        // The canonical frame is the header and the raw bytes; with no per-value length
        // prefix in the payload its flags byte is zero, and `COMPACT_LEN` is refused.
        let frame = norito::encode_canonical(value).expect("frame");
        assert_eq!(frame, frame_of::<T>(raw, 0x00));
        assert_eq!(
            &norito::decode_canonical::<T>(&frame).expect("canonical"),
            value
        );
        assert!(norito::decode_canonical::<T>(&frame_of::<T>(raw, 0x02)).is_err());
        // Every other length is rejected, framed or bare.
        for len in [0, raw.len() - 1, raw.len() + 1] {
            let mut other = raw.to_vec();
            other.resize(len, 0x5a);
            assert!(T::decode(&mut &other[..]).is_err(), "bare length {len}");
            assert!(
                norito::decode_canonical::<T>(&frame_of::<T>(&other, 0x00)).is_err(),
                "framed length {len}"
            );
        }
        let json = norito::json::to_json(value).expect("json");
        assert_eq!(&norito::json::from_str::<T>(&json).expect("json"), value);
    }

    #[test]
    fn short_values_encode_exactly_their_raw_bytes() {
        check_fixed(&Digest512::new([0xa1; 64]), &[0xa1; 64]);
        check_fixed(&CredentialCommitmentV1::new([0xb2; 128]), &[0xb2; 128]);
        check_fixed(&RegistrationAuthorizationV1::new([3; 64]), &[3; 64]);
        check_fixed(&NullifierV1::new([4; 128]), &[4; 128]);
        check_fixed(&VoteAuthorizationV1::new([5; 64]), &[5; 64]);
        check_fixed(&BallotScopeV1::new([6; 64]), &[6; 64]);
        check_fixed(&ProofProfileIdV1::V1, ProofProfileIdV1::V1.as_bytes());
        check_fixed(&AdmissionNonceV1::new([7; 32]), &[7; 32]);
        check_fixed(&BallotAuthorityBindingV1::new([8; 64]), &[8; 64]);
    }

    #[test]
    fn short_values_have_exactly_their_length_and_spelling() {
        assert_eq!(
            [
                Digest512::LENGTH,
                CredentialCommitmentV1::LENGTH,
                RegistrationAuthorizationV1::LENGTH,
                NullifierV1::LENGTH,
                VoteAuthorizationV1::LENGTH,
                BallotScopeV1::LENGTH,
                ProofProfileIdV1::LENGTH,
                AdmissionNonceV1::LENGTH,
                BallotAuthorityBindingV1::LENGTH,
            ],
            [64, 128, 64, 128, 64, 64, 64, 32, 64]
        );
        let nonce = AdmissionNonceV1::from_slice(&[0xab; 32]).expect("32 bytes");
        assert_eq!(nonce.as_bytes(), &[0xab; 32]);
        assert_eq!(nonce.into_bytes(), [0xab; 32]);
        assert_eq!(<[u8; 32]>::from(nonce), [0xab; 32]);
        assert_eq!(AdmissionNonceV1::from([0xab; 32]), nonce);
        assert_eq!(nonce.as_ref(), &[0xab; 32][..]);
        for len in [0, 31, 33, 64] {
            assert_eq!(
                AdmissionNonceV1::from_slice(&vec![0; len]),
                Err(FixedBytesErrorV1::Length {
                    kind: "AdmissionNonceV1",
                    expected: 32,
                    actual: len
                })
            );
        }
        let hex = "ab".repeat(32);
        assert_eq!(nonce.to_hex(), hex);
        assert_eq!(nonce.to_string(), hex);
        assert_eq!(hex.parse::<AdmissionNonceV1>(), Ok(nonce));
        assert_eq!(AdmissionNonceV1::from_hex(&hex), Ok(nonce));
        assert_eq!(format!("{nonce:?}"), format!("AdmissionNonceV1({hex})"));
        let rejected = Err(FixedBytesErrorV1::Text {
            kind: "AdmissionNonceV1",
        });
        for text in [
            "AB".repeat(32),
            format!("0x{}", "ab".repeat(31)),
            "ab".repeat(31),
            "ab".repeat(33),
            format!("{}zz", "ab".repeat(31)),
            String::new(),
        ] {
            assert_eq!(AdmissionNonceV1::from_hex(&text), rejected, "{text}");
        }
        assert!(
            norito::json::from_str::<AdmissionNonceV1>(&format!("\"{}\"", "AB".repeat(32)))
                .is_err()
        );
        assert_eq!(
            norito::json::to_json(&nonce).expect("json"),
            format!("\"{hex}\"")
        );
        // Unsigned bytewise order, the order of the sealed list.
        let mut low = [0_u8; 128];
        let mut high = [0_u8; 128];
        low[0] = 0x7f;
        high[0] = 0x80;
        assert!(CredentialCommitmentV1::new(low) < CredentialCommitmentV1::new(high));
        // A slice decode takes the raw prefix and reports its length.
        let (decoded, used) =
            <AdmissionNonceV1 as norito::core::DecodeFromSlice>::decode_from_slice(&[9_u8; 40])
                .expect("long enough");
        assert_eq!((decoded, used), (AdmissionNonceV1::new([9; 32]), 32));
        assert!(
            <AdmissionNonceV1 as norito::core::DecodeFromSlice>::decode_from_slice(&[9_u8; 31])
                .is_err()
        );
    }

    #[test]
    fn the_v1_profile_identifier_is_the_candidate_descriptor_digest() {
        assert_eq!(
            ProofProfileIdV1::V1.to_hex(),
            "01ed9f564981a07ab383d513c4e816f5a76542c7220eaaa36742f8eb0c51341d\
             a089e154a815f92fcd18353077cde18f435dfaa0834b65fdf3a658b0accdda28"
        );
        assert!(ProofProfileIdV1::V1.is_v1());
        assert!(!ProofProfileIdV1::new([0; 64]).is_v1());
    }

    fn check_proof<T>(make: impl Fn(Vec<u8>) -> Result<T, FixedBytesErrorV1>, len: usize)
    where
        T: norito::NoritoSerialize
            + for<'de> norito::NoritoDeserialize<'de>
            + JsonSerialize
            + JsonDeserialize
            + PartialEq
            + fmt::Debug
            + AsRef<[u8]>,
    {
        let raw: Vec<u8> = (0..len)
            .map(|i| u8::try_from(i % 251).expect("small"))
            .collect();
        let proof = make(raw.clone()).expect("exact length");
        assert_eq!(proof.as_ref(), &raw[..]);
        assert_eq!(proof.encode(), raw);
        assert_eq!(T::decode(&mut &raw[..]).expect("exact"), proof);
        let frame = norito::encode_canonical(&proof).expect("frame");
        assert_eq!(frame, frame_of::<T>(&raw, 0x00));
        assert!(norito::decode_canonical::<T>(&frame_of::<T>(&raw, 0x02)).is_err());
        assert_eq!(norito::decode_canonical::<T>(&frame).expect("frame"), proof);
        for other in [0, 1, len - 1, len + 1] {
            let mut bytes = raw.clone();
            bytes.resize(other, 0);
            assert!(make(bytes.clone()).is_err(), "constructed length {other}");
            assert!(T::decode(&mut &bytes[..]).is_err(), "bare length {other}");
            assert!(
                norito::decode_canonical::<T>(&frame_of::<T>(&bytes, 0x00)).is_err(),
                "framed length {other}"
            );
        }
        let json = norito::json::to_json(&proof).expect("json");
        assert_eq!(norito::json::from_str::<T>(&json).expect("json"), proof);
        // Base64 of another length is refused.
        let short = format!(
            "\"{}\"",
            base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &raw[1..])
        );
        assert!(norito::json::from_str::<T>(&short).is_err());
    }

    #[test]
    fn proofs_have_exactly_the_candidate_row_lengths() {
        assert_eq!(RegistrationProofBytesV1::LENGTH, 160_148);
        assert_eq!(BallotProofBytesV1::LENGTH, 233_012);
        check_proof(RegistrationProofBytesV1::new, 160_148);
        check_proof(BallotProofBytesV1::new, 233_012);
        let proof = BallotProofBytesV1::from_slice(&[0xcd; 233_012]).expect("exact");
        assert_eq!(
            format!("{proof:?}"),
            "BallotProofBytesV1(233012 bytes, cdcdcdcdcdcdcdcd..)"
        );
        assert_eq!(proof.as_bytes().len(), 233_012);
        assert_eq!(proof.clone().into_bytes(), vec![0xcd; 233_012]);
        assert_eq!(
            RegistrationProofBytesV1::from_slice(&[0; 3]),
            Err(FixedBytesErrorV1::Length {
                kind: "RegistrationProofBytesV1",
                expected: 160_148,
                actual: 3
            })
        );
        let (decoded, used) =
            <BallotProofBytesV1 as norito::core::DecodeFromSlice>::decode_from_slice(
                &[0xcd; 233_020],
            )
            .expect("long enough");
        assert_eq!((decoded, used), (proof, 233_012));
    }
}
