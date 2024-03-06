pub use normal::{
    NormalBls as BlsNormal, NormalPrivateKey as BlsNormalPrivateKey,
    NormalPublicKey as BlsNormalPublicKey,
};
pub use small::{
    SmallBls as BlsSmall, SmallPrivateKey as BlsSmallPrivateKey,
    SmallPublicKey as BlsSmallPublicKey,
};

// Do not expose the [implementation] module & the [implementation::BlsConfiguration] trait
mod implementation;

/// This version is the "normal" BLS signature scheme
/// with the public key group in G1 and signature group in G2.
/// 192 byte signatures and 97 byte public keys
mod normal {
    use super::{implementation, implementation::BlsConfiguration};
    use crate::Algorithm;

    #[derive(Debug, Clone, Copy)]
    pub struct NormalConfiguration;

    impl BlsConfiguration for NormalConfiguration {
        const ALGORITHM: Algorithm = Algorithm::BlsNormal;

        type Engine = w3f_bls::ZBLS;
    }

    pub type NormalBls = implementation::BlsImpl<NormalConfiguration>;
    pub type NormalPublicKey =
        w3f_bls::PublicKey<<NormalConfiguration as BlsConfiguration>::Engine>;
    pub type NormalPrivateKey =
        w3f_bls::SecretKeyVT<<NormalConfiguration as BlsConfiguration>::Engine>;
}

/// Small BLS signature scheme results in smaller signatures but slower
/// operations and bigger public key.
///
/// This is good for situations where space is a consideration and verification is infrequent.
mod small {
    use super::implementation::{self, BlsConfiguration};
    use crate::Algorithm;

    #[derive(Debug, Clone, Copy)]
    pub struct SmallConfiguration;
    impl BlsConfiguration for SmallConfiguration {
        const ALGORITHM: Algorithm = Algorithm::BlsSmall;

        type Engine = w3f_bls::TinyBLS381;
    }

    pub type SmallBls = implementation::BlsImpl<SmallConfiguration>;
    pub type SmallPublicKey = w3f_bls::PublicKey<<SmallConfiguration as BlsConfiguration>::Engine>;
    pub type SmallPrivateKey =
        w3f_bls::SecretKeyVT<<SmallConfiguration as BlsConfiguration>::Engine>;
}

#[cfg(test)]
mod tests;
