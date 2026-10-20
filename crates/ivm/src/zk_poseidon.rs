//! Native Poseidon bridge to the canonical BN254 owner.
//!
//! `iroha_zkp_halo2::poseidon` reexports the native helpers implemented by
//! `iroha_zkp_poseidon`; these functions do not constrain a Halo2 circuit.
//! TODO(F.5): implement and qualify an actual BN254 constrained consumer before
//! claiming circuit parity. Low-64-bit results are opcode values, not commitments.
/// Hash a pair of `u64` values using original Poseidon with fixed arity two (width 3) and return the low 64 bits.
#[inline]
pub fn pair_hash_u64(a: u64, b: u64) -> u64 {
    iroha_zkp_halo2::poseidon::hash2_u64(a, b)
}
/// Hash a pair of `u64` values and return the canonical 32-byte field encoding.
#[inline]
pub fn pair_hash_bytes(a: u64, b: u64) -> [u8; 32] {
    iroha_zkp_halo2::poseidon::hash2_bytes(a, b)
}
