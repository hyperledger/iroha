//! Portable Falcon-512 trapdoor and GPV sampling primitives.
//!
//! The arithmetic core is selectively vendored and adapted from Thomas
//! Pornin's `rust-fn-dsa` 0.3 implementation (Unlicense).  Only the portable
//! degree-512 key-generation and recursive ffSampling paths are compiled;
//! signature encoding, message hashing, legacy Falcon modes, and runtime
//! SIMD dispatch are deliberately outside this module.
//!
//! This is used as the concrete `[1 | h]` issuer specialization pinned by
//! `LaZeR`, not as an implementation of the full BLNS security reduction.
#![allow(non_camel_case_types, non_snake_case, non_upper_case_globals)]
mod comm;
#[cfg(test)]
mod kat_vectors;
mod kgen;
mod sign;
mod table_assets;
use zeroize::{Zeroize, Zeroizing};
pub(super) const DEGREE: usize = 512;
pub(super) const LOG_DEGREE: u32 = 9;
pub(super) const MODULUS: u16 = 12_289;
pub(super) const SIGNATURE_NORM_SQUARED_BOUND: u32 = 34_034_726;
pub const BOOTLE_LANTERN_FALCON512_DEFAULT_KEYGEN_CANDIDATES_V1: u32 = 4_096;
pub const BOOTLE_LANTERN_FALCON512_KEYGEN_PARITY_ATTEMPTS_V1: u32 =
    kgen::MAX_PARITY_ATTEMPTS_PER_POLYNOMIAL;
pub const BOOTLE_LANTERN_FALCON512_PREIMAGE_PROPOSALS_PER_COEFFICIENT_V1: u32 =
    sign::MAX_PROPOSALS_PER_COEFFICIENT;
pub const BOOTLE_LANTERN_FALCON512_PREIMAGE_TOTAL_PROPOSALS_V1: u32 =
    sign::TOTAL_GAUSSIAN_PROPOSAL_BUDGET;
pub const BOOTLE_LANTERN_FALCON512_MAPPING_DESCRIPTOR_V1: &[u8] = b"falcon512-ntru-r512-as-r64-rank8-interleaved|H_i[j]=h[8*j+i]|join(v)[i+8*j]=v_i[j]|B[r,c]=H_(r-c)-or-Y*H_(r-c+8)|R512:Z_12289[X]/(X^512+1)|R64:Z_12289[Y]/(Y^64+1),Y=X^8";
pub const BOOTLE_LANTERN_FALCON512_PROFILE_DESCRIPTOR_V1: &[u8] = b"lazer-falcon512-concrete-specialization-v1|not-full-blns-main-reduction|one-Falcon-512-NTRU-key|q=12289|degree=512|public=[1|h]|equations:fG-gF=q;f*h=g;s1+h*s2=target|mapping=falcon512-ntru-r512-as-r64-rank8-interleaved|keygen-candidates=4096|parity-attempts=128|preimage-prng=Falcon-ChaCha20-56-byte-word-major-8-block|preimage-proposals-per-coefficient=256|preimage-total-proposals=262144|signature-norm2<=34034726|self-check:exact-equation+norm";
pub const BOOTLE_LANTERN_FALCON512_IMPLEMENTATION_PROVENANCE_V1: &[u8] = b"rust-fn-dsa-v0.3-workspace@daf14859b5aa3f8d75c42966ba7de83e6eb59997|license=Unlicense|modules=fn-dsa-comm(mq,shake,ChaCha20-PRNG),fn-dsa-kgen(fxp,gauss,mp31,ntru,poly,vect,zint31),fn-dsa-sign(flr-emulated,poly,sampler)|deltas=scalar-only-no-unsafe-no-SIMD;bounded-keygen-and-gaussian-proposals;raw-trapdoor-output;arbitrary-R512-target;both-preimage-halves;mandatory-equation-and-norm-self-check";
/// A generated Falcon-512 NTRU trapdoor and its public multiplier.
pub(super) struct Trapdoor {
    pub(super) f: Zeroizing<Box<[i8]>>,
    pub(super) g: Zeroizing<Box<[i8]>>,
    pub(super) capital_f: Zeroizing<Box<[i8]>>,
    pub(super) capital_g: Zeroizing<Box<[i8]>>,
    pub(super) h: Zeroizing<Box<[u16]>>,
}
impl core::fmt::Debug for Trapdoor {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("Falcon512Trapdoor(<redacted>)")
    }
}
impl Zeroize for Trapdoor {
    fn zeroize(&mut self) {
        self.f.as_mut().zeroize();
        self.g.as_mut().zeroize();
        self.capital_f.as_mut().zeroize();
        self.capital_g.as_mut().zeroize();
        self.h.as_mut().zeroize();
    }
}
impl Drop for Trapdoor {
    fn drop(&mut self) {
        self.zeroize();
    }
}
/// One short preimage `s1 + h*s2 = target (mod q)`.
pub(super) struct Preimage {
    pub(super) first: Zeroizing<Box<[i16]>>,
    pub(super) second: Zeroizing<Box<[i16]>>,
    #[cfg(test)]
    pub(super) norm_squared: u32,
}
pub(super) fn generate_from_seed(seed: &[u8; 32], max_candidates: u32) -> Option<Trapdoor> {
    kgen::generate_from_seed(seed, max_candidates)
}
#[cfg(test)]
fn generate_from_seed_slice_for_test(seed: &[u8], max_candidates: u32) -> Option<Trapdoor> {
    kgen::generate_from_seed(seed, max_candidates)
}
pub(super) fn sample_preimage_from_seed(
    trapdoor: &Trapdoor,
    target: &[u16; DEGREE],
    seed: &[u8; 56],
) -> Option<Preimage> {
    sign::sample_preimage_from_seed(trapdoor, target, seed)
}
#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest as _, Sha256};
    use zeroize::Zeroizing;
    #[test]
    fn pinned_upstream_keygen_test0_raw_trapdoor_kat() {
        let trapdoor = generate_from_seed_slice_for_test(
            b"test0",
            BOOTLE_LANTERN_FALCON512_DEFAULT_KEYGEN_CANDIDATES_V1,
        )
        .expect("pinned Falcon-512 keygen candidate");
        let mut encoded = Zeroizing::new(Vec::with_capacity(4 * DEGREE));
        for polynomial in [
            &**trapdoor.f,
            &**trapdoor.g,
            &**trapdoor.capital_f,
            &**trapdoor.capital_g,
        ] {
            encoded.extend(
                polynomial
                    .iter()
                    .map(|coefficient| coefficient.cast_unsigned()),
            );
        }
        assert_eq!(encoded.len(), 2_048);
        assert_eq!(
            Sha256::digest(encoded.as_slice()).as_slice(),
            hex::decode("e5b8d48e5ce74c62e3e0ccd40f7ce5762d3a329d5b85bfbb3af88d31bdceb3e6")
                .expect("hex")
        );
    }
    #[test]
    fn keygen_zero_candidate_budget_is_typed_exhaustion() {
        assert!(generate_from_seed_slice_for_test(b"test0", 0).is_none());
    }
}
