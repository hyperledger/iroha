#![allow(clippy::redundant_pub_crate)]
//! Shared BN254 Poseidon width-3 parameter staging for GPU hosts.
use std::sync::OnceLock;
/// Number of 64-bit limbs in a canonical BN254 field element.
pub(crate) const BN254_LIMBS: usize = 4;
/// Poseidon width used for transcript digest hashing.
pub(crate) const BN254_POSEIDON_WIDTH: usize = 3;
/// Number of rounds in the original width-3 V1 permutation.
const BN254_POSEIDON_ROUNDS: usize = 65;
/// Number of limbs in the complete fixed round-constant bank.
const ROUND_CONSTANT_LIMBS: usize = BN254_POSEIDON_ROUNDS * BN254_POSEIDON_WIDTH * BN254_LIMBS;
/// Number of limbs in the complete fixed dense MDS bank.
const MDS_LIMBS: usize = BN254_POSEIDON_WIDTH * BN254_POSEIDON_WIDTH * BN254_LIMBS;
/// BN254 Poseidon width-3 constants flattened as canonical little-endian limbs.
pub(crate) struct Bn254PoseidonWidth3Params {
    /// Round constants, flattened as `[round][word][limb]`.
    pub(crate) round_constants: [u64; ROUND_CONSTANT_LIMBS],
    /// MDS matrix, flattened as `[row][column][limb]`.
    pub(crate) mds: [u64; MDS_LIMBS],
    /// Total round count.
    #[cfg(target_os = "macos")]
    pub(crate) round_count: u32,
}
/// Return the shared BN254 Poseidon width-3 parameters in canonical limb form.
///
/// The complete V1 banks use inline storage in the original `OnceLock`. Staging
/// copies the sole canonical fixed-width export without heap parameter owners.
pub(crate) fn bn254_poseidon_width3_params() -> &'static Bn254PoseidonWidth3Params {
    static PARAMS: OnceLock<Bn254PoseidonWidth3Params> = OnceLock::new();
    PARAMS.get_or_init(|| {
        let params = iroha_zkp_halo2::poseidon::bn254_poseidon_params_width3();
        let mut round_constants = [0u64; ROUND_CONSTANT_LIMBS];
        for (round_index, round) in params.round_constants.iter().enumerate() {
            for (word_index, word) in round.iter().enumerate() {
                let offset = (round_index * BN254_POSEIDON_WIDTH + word_index) * BN254_LIMBS;
                round_constants[offset..offset + BN254_LIMBS]
                    .copy_from_slice(&bn254_bytes_to_limbs(word));
            }
        }
        let mut mds = [0u64; MDS_LIMBS];
        for (row_index, row) in params.mds.iter().enumerate() {
            for (column_index, coeff) in row.iter().enumerate() {
                let offset = (row_index * BN254_POSEIDON_WIDTH + column_index) * BN254_LIMBS;
                mds[offset..offset + BN254_LIMBS].copy_from_slice(&bn254_bytes_to_limbs(coeff));
            }
        }
        Bn254PoseidonWidth3Params {
            round_constants,
            mds,
            #[cfg(target_os = "macos")]
            round_count: u32::try_from(BN254_POSEIDON_ROUNDS)
                .expect("Poseidon round count must fit into u32"),
        }
    })
}
/// Convert canonical BN254 bytes into little-endian 64-bit limbs.
pub(crate) fn bn254_bytes_to_limbs(bytes: &[u8; 32]) -> [u64; BN254_LIMBS] {
    let mut limbs = [0u64; BN254_LIMBS];
    for (index, limb) in limbs.iter_mut().enumerate() {
        let mut buf = [0u8; 8];
        buf.copy_from_slice(&bytes[index * 8..(index + 1) * 8]);
        *limb = u64::from_le_bytes(buf);
    }
    limbs
}
/// Convert little-endian BN254 limbs into canonical bytes.
pub(crate) fn bn254_limbs_to_bytes(limbs: &[u64]) -> [u8; 32] {
    debug_assert_eq!(limbs.len(), BN254_LIMBS);
    let mut out = [0u8; 32];
    for (index, limb) in limbs.iter().enumerate() {
        out[index * 8..(index + 1) * 8].copy_from_slice(&limb.to_le_bytes());
    }
    out
}

#[cfg(test)]
mod tests {
    use halo2curves::{
        bn256::Fr,
        ff::{Field, PrimeField},
    };

    use super::*;

    #[test]
    fn complete_fixed_banks_preserve_all_canonical_width3_limbs() {
        let canonical = iroha_zkp_halo2::poseidon::bn254_poseidon_params_width3();
        let staged = bn254_poseidon_width3_params();
        assert_eq!(canonical.round_constants.len(), BN254_POSEIDON_ROUNDS);
        assert_eq!(staged.round_constants.len(), 780);
        assert_eq!(staged.mds.len(), 36);
        let mut compared_limbs = 0;
        let mut fields_with_high_limbs = 0;
        for (round_index, round) in canonical.round_constants.iter().enumerate() {
            for (word_index, word) in round.iter().enumerate() {
                let offset = (round_index * BN254_POSEIDON_WIDTH + word_index) * BN254_LIMBS;
                let limbs = &staged.round_constants[offset..offset + BN254_LIMBS];
                for (limb_index, limb) in limbs.iter().enumerate() {
                    let expected = u64::from_le_bytes(
                        word[limb_index * 8..(limb_index + 1) * 8]
                            .try_into()
                            .expect("one complete canonical limb"),
                    );
                    assert_eq!(
                        *limb, expected,
                        "round {round_index}, word {word_index}, limb {limb_index}"
                    );
                    compared_limbs += 1;
                }
                assert_eq!(bn254_limbs_to_bytes(limbs), *word);
                fields_with_high_limbs += usize::from(limbs[1..].iter().any(|limb| *limb != 0));
            }
        }
        for (row_index, row) in canonical.mds.iter().enumerate() {
            for (column_index, word) in row.iter().enumerate() {
                let offset = (row_index * BN254_POSEIDON_WIDTH + column_index) * BN254_LIMBS;
                let limbs = &staged.mds[offset..offset + BN254_LIMBS];
                for (limb_index, limb) in limbs.iter().enumerate() {
                    let expected = u64::from_le_bytes(
                        word[limb_index * 8..(limb_index + 1) * 8]
                            .try_into()
                            .expect("one complete canonical limb"),
                    );
                    assert_eq!(
                        *limb, expected,
                        "MDS row {row_index}, column {column_index}, limb {limb_index}"
                    );
                    compared_limbs += 1;
                }
                assert_eq!(bn254_limbs_to_bytes(limbs), *word);
                fields_with_high_limbs += usize::from(limbs[1..].iter().any(|limb| *limb != 0));
            }
        }
        assert_eq!(compared_limbs, 816);
        assert_eq!(fields_with_high_limbs, 204);
        #[cfg(target_os = "macos")]
        assert_eq!(staged.round_count, 65);
    }

    #[test]
    fn fixed_banks_keep_one_stable_owner_and_existing_slice_geometry() {
        let first = bn254_poseidon_width3_params();
        let second = bn254_poseidon_width3_params();
        assert!(std::ptr::eq(first, second));
        assert_eq!(
            first.round_constants.as_ptr(),
            second.round_constants.as_ptr()
        );
        assert_eq!(first.mds.as_ptr(), second.mds.as_ptr());
        let round_slice: &[u64] = &first.round_constants;
        let mds_slice: &[u64] = &first.mds;
        assert_eq!(round_slice.len(), 65 * 3 * 4);
        assert_eq!(mds_slice.len(), 3 * 3 * 4);
        assert_eq!(round_slice.as_ptr(), first.round_constants.as_ptr());
        assert_eq!(mds_slice.as_ptr(), first.mds.as_ptr());
    }

    #[test]
    fn canonical_endian_staging_preserves_high_field_limbs_and_modulus_boundary() {
        // The final control is BN254 Fr::MODULUS - 1, not a low-word approximation.
        let controls = [
            [0, 0, 0, 0],
            [1, 0, 0, 0],
            [0, 1, 0, 0],
            [0, 0, 1, 0],
            [0, 0, 0, 1],
            [0, 0, 0, 1u64 << 61],
            [
                0x43e1_f593_f000_0000,
                0x2833_e848_79b9_7091,
                0xb850_45b6_8181_585d,
                0x3064_4e72_e131_a029,
            ],
        ];
        for limbs in controls {
            let bytes = bn254_limbs_to_bytes(&limbs);
            let canonical = Option::<Fr>::from(Fr::from_repr(bytes.into()))
                .expect("the full control is a canonical BN254 field value");
            let represented: [u8; 32] = canonical.to_repr().into();
            assert_eq!(represented, bytes);
            for (index, limb) in limbs.iter().enumerate() {
                assert_eq!(&bytes[index * 8..(index + 1) * 8], &limb.to_le_bytes());
            }
            assert_eq!(bn254_bytes_to_limbs(&bytes), limbs);
        }
        let boundary = bn254_limbs_to_bytes(&controls[controls.len() - 1]);
        assert_eq!(
            Option::<Fr>::from(Fr::from_repr(boundary.into())),
            Some(-Fr::ONE)
        );
    }
}
