//! Shared curve identifier registry for account controllers and address payloads.
use iroha_crypto::Algorithm;
use thiserror::Error;
/// Stable identifier assigned to a canonical signing algorithm.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CurveId(u8);
impl CurveId {
    /// Identifier for Ed25519 controllers.
    pub const ED25519: Self = Self(1);
    /// Identifier for secp256k1 controllers.
    pub const SECP256K1: Self = Self(4);
    /// Identifier for BLS12-381 (normal) controllers.
    pub const BLS_NORMAL: Self = Self(3);
    /// Identifier for BLS12-381 (small) controllers.
    pub const BLS_SMALL: Self = Self(5);
    /// Identifier for ML‑DSA controllers (Dilithium).
    pub const MLDSA: Self = Self(2);
    /// Identifier for GOST R 34.10-2012 256-bit curve, param set A.
    pub const GOST_256_A: Self = Self(10);
    /// Identifier for GOST R 34.10-2012 256-bit curve, param set B.
    pub const GOST_256_B: Self = Self(11);
    /// Identifier for GOST R 34.10-2012 256-bit curve, param set C.
    pub const GOST_256_C: Self = Self(12);
    /// Identifier for GOST R 34.10-2012 512-bit curve, param set A.
    pub const GOST_512_A: Self = Self(13);
    /// Identifier for GOST R 34.10-2012 512-bit curve, param set B.
    pub const GOST_512_B: Self = Self(14);
    /// Identifier for SM2 controllers.
    pub const SM2: Self = Self(15);
    /// Convert every canonical algorithm into its published curve identifier.
    ///
    /// This identity mapping never depends on local implementation availability.
    pub const fn from_algorithm(algorithm: Algorithm) -> Self {
        match algorithm {
            Algorithm::Ed25519 => Self::ED25519,
            Algorithm::Secp256k1 => Self::SECP256K1,
            Algorithm::BlsNormal => Self::BLS_NORMAL,
            Algorithm::BlsSmall => Self::BLS_SMALL,
            Algorithm::MlDsa => Self::MLDSA,
            Algorithm::Gost3410_2012_256ParamSetA => Self::GOST_256_A,
            Algorithm::Gost3410_2012_256ParamSetB => Self::GOST_256_B,
            Algorithm::Gost3410_2012_256ParamSetC => Self::GOST_256_C,
            Algorithm::Gost3410_2012_512ParamSetA => Self::GOST_512_A,
            Algorithm::Gost3410_2012_512ParamSetB => Self::GOST_512_B,
            Algorithm::Sm2 => Self::SM2,
        }
    }
    /// Export the identifier as its canonical byte.
    pub const fn as_u8(self) -> u8 {
        self.0
    }
    /// Convert the identifier back into an [`Algorithm`].
    pub fn algorithm(self) -> Algorithm {
        match self.0 {
            1 => Algorithm::Ed25519,
            4 => Algorithm::Secp256k1,

            3 => Algorithm::BlsNormal,

            5 => Algorithm::BlsSmall,
            2 => Algorithm::MlDsa,

            10 => Algorithm::Gost3410_2012_256ParamSetA,

            11 => Algorithm::Gost3410_2012_256ParamSetB,

            12 => Algorithm::Gost3410_2012_256ParamSetC,

            13 => Algorithm::Gost3410_2012_512ParamSetA,

            14 => Algorithm::Gost3410_2012_512ParamSetB,

            15 => Algorithm::Sm2,
            other => unreachable!("unsupported curve id {other}"),
        }
    }
}
impl TryFrom<u8> for CurveId {
    type Error = CurveRegistryError;
    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::ED25519),
            4 => Ok(Self::SECP256K1),

            3 => Ok(Self::BLS_NORMAL),

            5 => Ok(Self::BLS_SMALL),
            2 => Ok(Self::MLDSA),

            10 => Ok(Self::GOST_256_A),

            11 => Ok(Self::GOST_256_B),

            12 => Ok(Self::GOST_256_C),

            13 => Ok(Self::GOST_512_A),

            14 => Ok(Self::GOST_512_B),

            15 => Ok(Self::SM2),
            other => Err(CurveRegistryError::UnknownCurveId(other)),
        }
    }
}
impl From<CurveId> for u8 {
    fn from(value: CurveId) -> Self {
        value.0
    }
}
/// Error raised when a curve identifier lookup fails.
#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub enum CurveRegistryError {
    /// An unknown identifier was decoded from canonical bytes.
    #[error("unknown curve identifier: {0}")]
    UnknownCurveId(u8),
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn every_canonical_algorithm_has_one_feature_independent_curve() {
        let published = [1, 4, 3, 5, 2, 10, 11, 12, 13, 14, 15];
        assert_eq!(Algorithm::ALL.len(), published.len());
        for (&algorithm, expected) in Algorithm::ALL.iter().zip(published) {
            let curve = CurveId::from_algorithm(algorithm);
            assert_eq!(curve.as_u8(), expected);
            assert_eq!(CurveId::try_from(expected).unwrap(), curve);
            assert_eq!(curve.algorithm(), algorithm);
        }
        for byte in 0..=u8::MAX {
            assert_eq!(CurveId::try_from(byte).is_ok(), published.contains(&byte));
        }
    }

    #[test]
    fn bls_curve_ids_round_trip() {
        let normal = CurveId::from_algorithm(Algorithm::BlsNormal);
        let small = CurveId::from_algorithm(Algorithm::BlsSmall);
        assert_eq!(normal, CurveId::BLS_NORMAL);
        assert_eq!(small, CurveId::BLS_SMALL);
        assert_eq!(CurveId::try_from(u8::from(normal)).unwrap(), normal);
        assert_eq!(CurveId::try_from(u8::from(small)).unwrap(), small);
        assert_eq!(normal.algorithm(), Algorithm::BlsNormal);
        assert_eq!(small.algorithm(), Algorithm::BlsSmall);
    }
}
