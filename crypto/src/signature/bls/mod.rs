// Do not expose the [implementation] module & the [implementation::BlsConfiguration] trait
mod implementation;

pub const PRIVATE_KEY_SIZE: usize = amcl_wrapper::constants::MODBYTES;

/// This version is the "normal" BLS signature scheme
/// with the public key group in G1 and signature group in G2.
/// 192 byte signatures and 97 byte public keys
mod normal {
    use amcl_wrapper::{
        constants::{GroupG1_SIZE, GroupG2_SIZE},
        extension_field_gt::GT,
        group_elem_g1::G1,
        group_elem_g2::G2,
    };

    use super::{implementation, implementation::BlsConfiguration};
    use crate::Algorithm;

    pub type NormalGenerator = G1;
    pub type NormalSignatureGroup = G2;

    #[cfg(test)]
    pub fn normal_generate(
        g: &NormalGenerator,
    ) -> (NormalPublicKey, super::implementation::PrivateKey) {
        NormalConfiguration::generate(g)
    }

    #[derive(Debug, Clone, Copy)]
    pub struct NormalConfiguration;
    impl BlsConfiguration for NormalConfiguration {
        const ALGORITHM: Algorithm = Algorithm::BlsNormal;
        const PK_SIZE: usize = GroupG1_SIZE;
        const SIG_SIZE: usize = GroupG2_SIZE;
        type Generator = NormalGenerator;
        type SignatureGroup = NormalSignatureGroup;

        fn ate_2_pairing_is_one(
            p1: &Self::Generator,
            g1: &Self::SignatureGroup,
            p2: &Self::Generator,
            g2: &Self::SignatureGroup,
        ) -> bool {
            GT::ate_2_pairing(&-p1, g1, p2, g2).is_one()
        }

        fn set_pairs((g1, g2): &(Self::Generator, Self::SignatureGroup)) -> (&G1, &G2) {
            (g1, g2)
        }
    }

    pub type NormalBls = implementation::BlsImpl<NormalConfiguration>;
    #[cfg(test)]
    pub type NormalSignature = implementation::Signature<NormalConfiguration>;
    #[cfg(test)]
    pub type NormalPublicKey = implementation::PublicKey<NormalConfiguration>;
}

/// This version is the small BLS signature scheme
/// with the public key group in G2 and signature group in G1.
/// 97 bytes signatures and 192 byte public keys
///
/// This results in smaller signatures but slower operations and bigger public key.
/// This is good for situations where space is a consideration and verification is infrequent
mod small {
    use amcl_wrapper::{
        constants::{GroupG1_SIZE, GroupG2_SIZE},
        extension_field_gt::GT,
        group_elem_g1::G1,
        group_elem_g2::G2,
    };

    use super::implementation::{self, BlsConfiguration};
    use crate::Algorithm;

    pub type SmallGenerator = G2;
    pub type SmallSignatureGroup = G1;

    #[cfg(test)]
    pub fn small_generate(
        g: &SmallGenerator,
    ) -> (SmallPublicKey, super::implementation::PrivateKey) {
        SmallConfiguration::generate(g)
    }

    #[derive(Debug, Clone, Copy)]
    pub struct SmallConfiguration;
    impl BlsConfiguration for SmallConfiguration {
        const ALGORITHM: Algorithm = Algorithm::BlsSmall;
        const PK_SIZE: usize = GroupG2_SIZE;
        const SIG_SIZE: usize = GroupG1_SIZE;
        type Generator = SmallGenerator;
        type SignatureGroup = SmallSignatureGroup;

        fn ate_2_pairing_is_one(
            p1: &Self::Generator,
            g1: &Self::SignatureGroup,
            p2: &Self::Generator,
            g2: &Self::SignatureGroup,
        ) -> bool {
            GT::ate_2_pairing(g1, &-p1, g2, p2).is_one()
        }

        fn set_pairs((g2, g1): &(Self::Generator, Self::SignatureGroup)) -> (&G1, &G2) {
            (g1, g2)
        }
    }

    pub type SmallBls = implementation::BlsImpl<SmallConfiguration>;
    #[cfg(test)]
    pub type SmallSignature = implementation::Signature<SmallConfiguration>;
    #[cfg(test)]
    pub type SmallPublicKey = implementation::PublicKey<SmallConfiguration>;
}

pub use normal::NormalBls as BlsNormal;
pub use small::SmallBls as BlsSmall;

#[cfg(test)]
mod tests;
