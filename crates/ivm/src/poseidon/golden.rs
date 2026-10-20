//! Fixed public Poseidon known-answer vectors, independently checked against the pinned integer permutation and H.2 mode.

pub(crate) const TWO: [(u64, u64, u64); 5] = [
    (0, 0, 0x291e_f55c_ed50_4e95),
    (1, 0, 0x7e84_e466_0f9c_8602),
    (0, 1, 0xbe23_3ae4_87cc_493c),
    (1, 1, 0xc129_be07_2c4b_4483),
    (u64::MAX, u64::MAX, 0xc389_da81_dbdd_ae68),
];
pub(crate) const SIX: [([u64; 6], u64); 5] = [
    ([0, 0, 0, 0, 0, 0], 0xb528_4c49_a2aa_43dd),
    ([1, 2, 3, 4, 5, 6], 0xea55_3770_3da8_51ec),
    ([1, 0, 0, 0, 0, 0], 0x4412_6d18_7028_4f85),
    ([0, 1, 0, 0, 0, 0], 0x741c_dca6_d198_88b3),
    ([u64::MAX; 6], 0x732e_c89a_4e97_2a38),
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fixed_controls_match_current_cpu_poseidon_relations() {
        for (a, b, expected) in TWO {
            assert_eq!(crate::poseidon::poseidon2_simd(a, b), expected);
        }
        for (input, expected) in SIX {
            assert_eq!(crate::poseidon::poseidon6_simd(input), expected);
        }
    }
}
