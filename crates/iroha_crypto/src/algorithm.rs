//! Canonical signing identities and wire geometry are independent of local backends.

use crate::error::NoSuchAlgorithm;
use core::{fmt, str::FromStr};
use iroha_schema::{IntoSchema, TypeId};
use norito::json::{
    self, JsonDeserialize as NoritoJsonDeserialize, JsonSerialize as NoritoJsonSerialize,
};
use norito::{Decode, Encode, core as norito_core};
use std::string::String;
/// String algorithm representation
pub const ED_25519: &str = "ed25519";
/// String algorithm representation
pub const SECP_256_K1: &str = "secp256k1";
/// String algorithm representation
pub const ML_DSA: &str = "ml-dsa";

/// String algorithm representation
pub const GOST_34_10_2012_256_A: &str = "gost3410-2012-256-paramset-a";

/// String algorithm representation
pub const GOST_34_10_2012_256_B: &str = "gost3410-2012-256-paramset-b";

/// String algorithm representation
pub const GOST_34_10_2012_256_C: &str = "gost3410-2012-256-paramset-c";

/// String algorithm representation
pub const GOST_34_10_2012_512_A: &str = "gost3410-2012-512-paramset-a";

/// String algorithm representation
pub const GOST_34_10_2012_512_B: &str = "gost3410-2012-512-paramset-b";

/// String algorithm representation
pub const BLS_NORMAL: &str = "bls_normal";

/// String algorithm representation
pub const BLS_SMALL: &str = "bls_small";

/// String algorithm representation
pub const SM2: &str = "sm2";
/// Algorithm for hashing & signing
///
/// Discriminants are part of the on-wire format; keep them stable and aligned
/// with `Algorithm::try_from` and `PublicKeyCompact` tag mappings.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Default,
    Decode,
    Encode,
    TypeId,
    norito::NoritoSchema,
)]
#[norito_schema(name = "iroha_crypto::algorithm::Algorithm")]
#[repr(u8)]
pub enum Algorithm {
    /// Ed25519 digital signature scheme
    #[default]
    Ed25519 = 0,
    /// ECDSA over secp256k1
    Secp256k1 = 1,

    /// BLS12-381 (normal) scheme
    BlsNormal = 2,

    /// BLS12-381 (small) scheme
    BlsSmall = 3,
    /// ML‑DSA (Dilithium) post-quantum signature scheme
    MlDsa = 4,

    /// GOST R 34.10-2012 with the `CryptoPro` 256-bit parameter set A (RFC 4357).
    Gost3410_2012_256ParamSetA = 5,

    /// GOST R 34.10-2012 with the `CryptoPro` 256-bit parameter set B (RFC 4357).
    Gost3410_2012_256ParamSetB = 6,

    /// GOST R 34.10-2012 with the `CryptoPro` 256-bit parameter set C (RFC 4357).
    Gost3410_2012_256ParamSetC = 7,

    /// GOST R 34.10-2012 512-bit curve, TC26 param set A
    Gost3410_2012_512ParamSetA = 8,

    /// GOST R 34.10-2012 512-bit curve, TC26 param set B
    Gost3410_2012_512ParamSetB = 9,

    /// SM2 signature scheme (GM/T 0003-2012)
    Sm2 = 10,
}
impl Algorithm {
    /// Every canonical first-release algorithm, ordered by its published wire tag.
    ///
    /// This identity registry is independent of compiled implementations.
    pub const ALL: &'static [Self] = &[
        Self::Ed25519,
        Self::Secp256k1,
        Self::BlsNormal,
        Self::BlsSmall,
        Self::MlDsa,
        Self::Gost3410_2012_256ParamSetA,
        Self::Gost3410_2012_256ParamSetB,
        Self::Gost3410_2012_256ParamSetC,
        Self::Gost3410_2012_512ParamSetA,
        Self::Gost3410_2012_512ParamSetB,
        Self::Sm2,
    ];

    /// Maps the algorithm to its static string representation
    pub const fn as_static_str(self) -> &'static str {
        match self {
            Self::Ed25519 => ED_25519,
            Self::Secp256k1 => SECP_256_K1,
            Self::MlDsa => ML_DSA,
            Self::Gost3410_2012_256ParamSetA => GOST_34_10_2012_256_A,
            Self::Gost3410_2012_256ParamSetB => GOST_34_10_2012_256_B,
            Self::Gost3410_2012_256ParamSetC => GOST_34_10_2012_256_C,
            Self::Gost3410_2012_512ParamSetA => GOST_34_10_2012_512_A,
            Self::Gost3410_2012_512ParamSetB => GOST_34_10_2012_512_B,
            Self::BlsNormal => BLS_NORMAL,
            Self::BlsSmall => BLS_SMALL,
            Self::Sm2 => SM2,
        }
    }
    /// Exact byte length of a canonical detached signature payload.
    ///
    /// This canonical geometry is independent of compiled verification implementations.
    pub const fn signature_payload_len(self) -> usize {
        match self {
            Self::Ed25519
            | Self::Secp256k1
            | Self::Gost3410_2012_256ParamSetA
            | Self::Gost3410_2012_256ParamSetB
            | Self::Gost3410_2012_256ParamSetC
            | Self::Sm2 => 64,
            Self::MlDsa => 3_309,
            Self::Gost3410_2012_512ParamSetA | Self::Gost3410_2012_512ParamSetB => 128,
            Self::BlsNormal => 96,
            Self::BlsSmall => 48,
        }
    }
}
impl fmt::Display for Algorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_static_str())
    }
}
impl FromStr for Algorithm {
    type Err = NoSuchAlgorithm;
    fn from_str(algorithm: &str) -> Result<Self, Self::Err> {
        match algorithm {
            ED_25519 => Ok(Algorithm::Ed25519),
            SECP_256_K1 => Ok(Algorithm::Secp256k1),
            ML_DSA => Ok(Algorithm::MlDsa),

            GOST_34_10_2012_256_A => Ok(Algorithm::Gost3410_2012_256ParamSetA),

            GOST_34_10_2012_256_B => Ok(Algorithm::Gost3410_2012_256ParamSetB),

            GOST_34_10_2012_256_C => Ok(Algorithm::Gost3410_2012_256ParamSetC),

            GOST_34_10_2012_512_A => Ok(Algorithm::Gost3410_2012_512ParamSetA),

            GOST_34_10_2012_512_B => Ok(Algorithm::Gost3410_2012_512ParamSetB),

            BLS_NORMAL => Ok(Algorithm::BlsNormal),

            BLS_SMALL => Ok(Algorithm::BlsSmall),

            SM2 => Ok(Algorithm::Sm2),
            _ => Err(NoSuchAlgorithm),
        }
    }
}
impl TryFrom<u8> for Algorithm {
    type Error = ();
    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Algorithm::Ed25519),
            1 => Ok(Algorithm::Secp256k1),
            4 => Ok(Algorithm::MlDsa),

            5 => Ok(Algorithm::Gost3410_2012_256ParamSetA),

            6 => Ok(Algorithm::Gost3410_2012_256ParamSetB),

            7 => Ok(Algorithm::Gost3410_2012_256ParamSetC),

            8 => Ok(Algorithm::Gost3410_2012_512ParamSetA),

            9 => Ok(Algorithm::Gost3410_2012_512ParamSetB),

            2 => Ok(Algorithm::BlsNormal),

            3 => Ok(Algorithm::BlsSmall),

            10 => Ok(Algorithm::Sm2),
            _ => Err(()),
        }
    }
}
impl IntoSchema for Algorithm {
    fn type_name() -> String {
        "Algorithm".into()
    }
    fn update_schema_map(map: &mut iroha_schema::MetaMap) {
        if map.contains_key::<Self>() {
            return;
        }
        let mut variants = Vec::new();
        let mut push_variant = |tag: &str, discriminant: u32| {
            variants.push(iroha_schema::EnumVariant {
                tag: tag.to_owned(),
                discriminant,
                ty: None,
            });
        };
        push_variant("Ed25519", Algorithm::Ed25519 as u32);
        push_variant("Secp256k1", Algorithm::Secp256k1 as u32);

        {
            push_variant("BlsNormal", Algorithm::BlsNormal as u32);
            push_variant("BlsSmall", Algorithm::BlsSmall as u32);
        }
        push_variant("MlDsa", Algorithm::MlDsa as u32);

        {
            push_variant(
                "Gost3410_2012_256ParamSetA",
                Algorithm::Gost3410_2012_256ParamSetA as u32,
            );
            push_variant(
                "Gost3410_2012_256ParamSetB",
                Algorithm::Gost3410_2012_256ParamSetB as u32,
            );
            push_variant(
                "Gost3410_2012_256ParamSetC",
                Algorithm::Gost3410_2012_256ParamSetC as u32,
            );
            push_variant(
                "Gost3410_2012_512ParamSetA",
                Algorithm::Gost3410_2012_512ParamSetA as u32,
            );
            push_variant(
                "Gost3410_2012_512ParamSetB",
                Algorithm::Gost3410_2012_512ParamSetB as u32,
            );
        }

        push_variant("Sm2", Algorithm::Sm2 as u32);
        map.insert::<Self>(iroha_schema::Metadata::Enum(iroha_schema::EnumMeta {
            variants,
        }));
    }
}
impl<'a> norito_core::DecodeFromSlice<'a> for Algorithm {
    fn decode_from_slice(bytes: &'a [u8]) -> Result<(Self, usize), norito_core::Error> {
        let (raw, used) = <u8 as norito_core::DecodeFromSlice>::decode_from_slice(bytes)?;
        let algorithm = Algorithm::try_from(raw)
            .map_err(|()| norito_core::Error::invalid_tag("Algorithm::try_from", raw))?;
        Ok((algorithm, used))
    }
}
impl NoritoJsonSerialize for Algorithm {
    fn json_serialize(&self, out: &mut String) {
        let value = self.as_static_str().to_string();
        NoritoJsonSerialize::json_serialize(&value, out);
    }
    fn json_serialize_to(
        &self,
        out: &mut dyn json::JsonWriteSink,
    ) -> Result<(), json::BoundedJsonError> {
        json::write_json_string_to(self.as_static_str(), out)
    }
}
impl NoritoJsonDeserialize for Algorithm {
    fn json_deserialize(parser: &mut json::Parser<'_>) -> Result<Self, json::Error> {
        let value: String = NoritoJsonDeserialize::json_deserialize(parser)?;
        Algorithm::from_str(&value)
            .map_err(|_| json::Error::Message(format!("unknown algorithm '{value}'")))
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn every_wire_identity_schema_and_json_name_is_feature_independent() {
        let published = [
            "ed25519",
            "secp256k1",
            "bls_normal",
            "bls_small",
            "ml-dsa",
            "gost3410-2012-256-paramset-a",
            "gost3410-2012-256-paramset-b",
            "gost3410-2012-256-paramset-c",
            "gost3410-2012-512-paramset-a",
            "gost3410-2012-512-paramset-b",
            "sm2",
        ];
        assert_eq!(Algorithm::ALL.len(), published.len());
        for (tag, (&algorithm, name)) in Algorithm::ALL.iter().zip(published).enumerate() {
            assert_eq!(algorithm as usize, tag);
            assert_eq!(
                Algorithm::try_from(u8::try_from(tag).unwrap()),
                Ok(algorithm)
            );
            assert_eq!(algorithm.as_static_str(), name);
            assert_eq!(name.parse::<Algorithm>().unwrap(), algorithm);
            let bytes = norito::encode_canonical(&algorithm).unwrap();
            assert_eq!(
                norito::decode_canonical::<Algorithm>(&bytes).unwrap(),
                algorithm
            );
            let json = json::to_json(&algorithm).unwrap();
            assert_eq!(json, format!("\"{name}\""));
            assert_eq!(json::from_str::<Algorithm>(&json).unwrap(), algorithm);
        }
        for tag in 11..=u8::MAX {
            assert_eq!(Algorithm::try_from(tag), Err(()));
        }
        let mut map = iroha_schema::MetaMap::new();
        Algorithm::update_schema_map(&mut map);
        let Some(iroha_schema::Metadata::Enum(schema)) = map.get::<Algorithm>() else {
            panic!("canonical enum schema")
        };
        assert_eq!(schema.variants.len(), 11);
        for (tag, variant) in schema.variants.iter().enumerate() {
            assert_eq!(variant.discriminant as usize, tag);
            assert_eq!(variant.tag, format!("{:?}", Algorithm::ALL[tag]));
            assert!(variant.ty.is_none());
        }
    }
    #[test]
    fn conversions_are_consistent() {
        let mut cases = Vec::new();
        cases.push((Algorithm::Ed25519, ED_25519, 0u8));
        cases.push((Algorithm::Secp256k1, SECP_256_K1, 1u8));
        cases.push((Algorithm::MlDsa, ML_DSA, 4u8));

        cases.extend_from_slice(&[
            (
                Algorithm::Gost3410_2012_256ParamSetA,
                GOST_34_10_2012_256_A,
                5u8,
            ),
            (
                Algorithm::Gost3410_2012_256ParamSetB,
                GOST_34_10_2012_256_B,
                6u8,
            ),
            (
                Algorithm::Gost3410_2012_256ParamSetC,
                GOST_34_10_2012_256_C,
                7u8,
            ),
            (
                Algorithm::Gost3410_2012_512ParamSetA,
                GOST_34_10_2012_512_A,
                8u8,
            ),
            (
                Algorithm::Gost3410_2012_512ParamSetB,
                GOST_34_10_2012_512_B,
                9u8,
            ),
        ]);

        cases.extend_from_slice(&[
            (Algorithm::BlsNormal, BLS_NORMAL, 2u8),
            (Algorithm::BlsSmall, BLS_SMALL, 3u8),
        ]);
        for (alg, name, value) in cases {
            assert_eq!(alg.as_static_str(), name);
            assert_eq!(Algorithm::from_str(name).unwrap(), alg);
            assert_eq!(Algorithm::try_from(value).unwrap(), alg);
            assert_eq!(alg as u8, value);
        }
    }
    #[test]
    fn canonical_signature_payload_lengths_are_stable() {
        assert_eq!(Algorithm::Ed25519.signature_payload_len(), 64);
        assert_eq!(Algorithm::Secp256k1.signature_payload_len(), 64);
        assert_eq!(Algorithm::MlDsa.signature_payload_len(), 3_309);

        {
            assert_eq!(
                Algorithm::Gost3410_2012_256ParamSetA.signature_payload_len(),
                64
            );
            assert_eq!(
                Algorithm::Gost3410_2012_256ParamSetB.signature_payload_len(),
                64
            );
            assert_eq!(
                Algorithm::Gost3410_2012_256ParamSetC.signature_payload_len(),
                64
            );
            assert_eq!(
                Algorithm::Gost3410_2012_512ParamSetA.signature_payload_len(),
                128
            );
            assert_eq!(
                Algorithm::Gost3410_2012_512ParamSetB.signature_payload_len(),
                128
            );
        }

        {
            assert_eq!(Algorithm::BlsNormal.signature_payload_len(), 96);
            assert_eq!(Algorithm::BlsSmall.signature_payload_len(), 48);
        }

        {
            assert_eq!(Algorithm::Sm2.signature_payload_len(), 64);
        }
    }
}
