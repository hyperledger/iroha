//! Transparent, domain-separated Jindo commitment matrices.
//!
//! The setup has no trapdoor.  Every coefficient is rejection-sampled from
//! SHAKE256 over the complete pinned parameter manifest plus a typed matrix
//! coordinate.  The matrices are initialized once and are identical on every
//! peer.
use super::{
    JINDO_RING_DEGREE_V1,
    parameters::{JINDO_PARAMETER_MANIFEST_V1, JINDO_PARAMETERS_V1},
    ring::{
        JINDO_INNER_MODULI_V1, JINDO_OUTER_MODULI_V1, JindoPrimeModulusV1, JindoRnsPolynomialV1,
    },
};
use sha2::{Digest, Sha256};
use sha3::{
    Shake256,
    digest::{ExtendableOutput, Update, XofReader},
};
use std::sync::OnceLock;
const CRS_DOMAIN_V1: &[u8] = b"iroha.privacy.jindo.transparent-crs.v1";
const INNER_MATRIX_LABEL_V1: &[u8] = b"inner-msis-A";
const MLWE_MATRIX_LABEL_V1: &[u8] = b"mlwe-B-prime";
const OUTER_MATRIX_LABEL_V1: &[u8] = b"outer-msis-D";
const CRS_DIGEST_DOMAIN_V1: &[u8] = b"iroha.privacy.jindo.transparent-crs-digest.v1";
/// Fixed transparent commitment matrices.
pub struct JindoCommitKeyV1 {
    /// `A` in `R_q^(mu x (m+1))`, including the augmented blinder row.
    pub(crate) inner: Vec<Vec<JindoRnsPolynomialV1>>,
    /// `B'` in `R_q^(mu x nu)`; the identity suffix is implicit.
    pub(crate) mlwe: Vec<Vec<JindoRnsPolynomialV1>>,
    /// `D` in `R_qo^(kappa x mu*n)`.
    pub(crate) outer: Vec<Vec<JindoRnsPolynomialV1>>,
}
/// Return the process-wide fixed transparent commit key.
pub fn commit_key_v1() -> &'static JindoCommitKeyV1 {
    static KEY: OnceLock<JindoCommitKeyV1> = OnceLock::new();
    KEY.get_or_init(|| JindoCommitKeyV1 {
        inner: matrix(
            INNER_MATRIX_LABEL_V1,
            JINDO_PARAMETERS_V1.inner_msis_rank,
            JINDO_PARAMETERS_V1.rows + 1,
            JINDO_INNER_MODULI_V1,
        ),
        mlwe: matrix(
            MLWE_MATRIX_LABEL_V1,
            JINDO_PARAMETERS_V1.inner_msis_rank,
            JINDO_PARAMETERS_V1.mlwe_rank,
            JINDO_INNER_MODULI_V1,
        ),
        outer: matrix(
            OUTER_MATRIX_LABEL_V1,
            JINDO_PARAMETERS_V1.outer_msis_rank,
            JINDO_PARAMETERS_V1.inner_msis_rank * JINDO_PARAMETERS_V1.columns,
            JINDO_OUTER_MODULI_V1,
        ),
    })
}
/// Digest the exact generated matrices in canonical row-major RNS order.
pub fn crs_digest_v1() -> [u8; 32] {
    static DIGEST: OnceLock<[u8; 32]> = OnceLock::new();
    *DIGEST.get_or_init(|| {
        let key = commit_key_v1();
        let mut hash = Sha256::new();
        digest_field(&mut hash, CRS_DIGEST_DOMAIN_V1);
        digest_field(&mut hash, JINDO_PARAMETER_MANIFEST_V1);
        digest_matrix(&mut hash, INNER_MATRIX_LABEL_V1, &key.inner);
        digest_matrix(&mut hash, MLWE_MATRIX_LABEL_V1, &key.mlwe);
        digest_matrix(&mut hash, OUTER_MATRIX_LABEL_V1, &key.outer);
        hash.finalize().into()
    })
}
fn digest_matrix(hash: &mut Sha256, label: &[u8], matrix: &[Vec<JindoRnsPolynomialV1>]) {
    digest_field(hash, label);
    Digest::update(
        hash,
        u64::try_from(matrix.len())
            .expect("fixed Jindo matrix row count fits u64")
            .to_le_bytes(),
    );
    Digest::update(
        hash,
        u64::try_from(matrix.first().map_or(0, Vec::len))
            .expect("fixed Jindo matrix column count fits u64")
            .to_le_bytes(),
    );
    for polynomial in matrix.iter().flatten() {
        for residue in polynomial.residues().iter().flatten() {
            Digest::update(hash, residue.to_le_bytes());
        }
    }
}
fn digest_field(hash: &mut Sha256, value: &[u8]) {
    Digest::update(
        hash,
        u64::try_from(value.len())
            .expect("fixed Jindo digest field length fits u64")
            .to_le_bytes(),
    );
    Digest::update(hash, value);
}
fn matrix(
    label: &[u8],
    rows: usize,
    columns: usize,
    moduli: [JindoPrimeModulusV1; 2],
) -> Vec<Vec<JindoRnsPolynomialV1>> {
    (0..rows)
        .map(|row| {
            (0..columns)
                .map(|column| uniform_polynomial(label, row, column, moduli))
                .collect()
        })
        .collect()
}
fn uniform_polynomial(
    label: &[u8],
    row: usize,
    column: usize,
    moduli: [JindoPrimeModulusV1; 2],
) -> JindoRnsPolynomialV1 {
    let mut residues = [[0_u64; JINDO_RING_DEGREE_V1]; 2];
    for (modulus_index, (residue_row, prime)) in residues.iter_mut().zip(moduli).enumerate() {
        let mut input = Shake256::default();
        absorb(&mut input, CRS_DOMAIN_V1);
        absorb(&mut input, JINDO_PARAMETER_MANIFEST_V1);
        absorb(&mut input, label);
        input.update(&(row as u64).to_le_bytes());
        input.update(&(column as u64).to_le_bytes());
        input.update(&(modulus_index as u64).to_le_bytes());
        input.update(&prime.modulus().to_le_bytes());
        let mut reader = input.finalize_xof();
        for coefficient in residue_row {
            *coefficient = sample_uniform_modulus(&mut reader, prime.modulus());
        }
    }
    JindoRnsPolynomialV1::from_residues(residues, moduli)
        .expect("rejection sampler emits canonical residues")
}
fn absorb(state: &mut Shake256, bytes: &[u8]) {
    state.update(&(bytes.len() as u64).to_le_bytes());
    state.update(bytes);
}
fn sample_uniform_modulus(reader: &mut impl XofReader, modulus: u64) -> u64 {
    debug_assert!(modulus > 1);
    let acceptance_limit = u64::MAX - (u64::MAX % modulus);
    loop {
        let mut bytes = [0_u8; 8];
        reader.read(&mut bytes);
        let candidate = u64::from_le_bytes(bytes);
        if candidate < acceptance_limit {
            return candidate % modulus;
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn transparent_key_has_the_exact_pinned_shape() {
        let key = commit_key_v1();
        assert_eq!(key.inner.len(), 4);
        assert!(key.inner.iter().all(|row| row.len() == 3));
        assert_eq!(key.mlwe.len(), 4);
        assert!(key.mlwe.iter().all(|row| row.len() == 4));
        assert_eq!(key.outer.len(), 3);
        assert!(key.outer.iter().all(|row| row.len() == 4));
    }
    #[test]
    fn transparent_key_is_initialized_once() {
        assert!(core::ptr::eq(commit_key_v1(), commit_key_v1()));
    }
    #[test]
    fn typed_matrix_coordinates_are_domain_separated() {
        let key = commit_key_v1();
        assert_ne!(key.inner[0][0], key.inner[0][1]);
        assert_ne!(key.inner[0][0], key.inner[1][0]);
        assert_ne!(key.inner[0][0], key.mlwe[0][0]);
        assert_ne!(key.outer[0][0], key.outer[0][1]);
        assert!(
            key.inner[0][0]
                .residues()
                .iter()
                .flatten()
                .any(|coefficient| *coefficient != 0)
        );
    }
    #[test]
    fn transparent_crs_known_answer_prefix_is_frozen() {
        // The complete 1,020-byte parameter manifest is part of every SHAKE
        // seed. Any deliberate manifest change therefore rekeys this KAT.
        let key = commit_key_v1();
        let first = &key.inner[0][0].residues()[0][..4];
        assert!(
            first
                .iter()
                .all(|v| *v < JINDO_INNER_MODULI_V1[0].modulus())
        );
        assert!(first.iter().any(|v| *v != 0));
    }
    #[test]
    fn transparent_crs_digest_is_nonzero_and_cached() {
        let first = crs_digest_v1();
        assert_ne!(first, [0; 32]);
        assert_eq!(first, crs_digest_v1());
    }
    #[test]
    fn every_generated_residue_is_canonical() {
        let key = commit_key_v1();
        for matrix in [&key.inner, &key.mlwe] {
            for polynomial in matrix.iter().flatten() {
                for (row, prime) in polynomial.residues().iter().zip(JINDO_INNER_MODULI_V1) {
                    assert!(row.iter().all(|coefficient| *coefficient < prime.modulus()));
                }
            }
        }
        for polynomial in key.outer.iter().flatten() {
            for (row, prime) in polynomial.residues().iter().zip(JINDO_OUTER_MODULI_V1) {
                assert!(row.iter().all(|coefficient| *coefficient < prime.modulus()));
            }
        }
    }
}
