//! Constrained building blocks for zk-X509.
//!
//! This module contains algebraic constraints, not native re-checks disguised
//! as proofs.  Every row evaluator returns zero only when its polynomial
//! identities hold over Goldilocks. The production prover places these rows
//! in masked committed segments and evaluates the same identities at
//! transcript-derived points. The production aggregate binds the complete
//! numeric trace material and is independently replayed by the verifier.
use crate::privacy_engines::transparent_stark::GoldilocksFieldV1 as F;
use thiserror::Error;
/// Stable digest input for the implemented components.
pub const ZK_X509_AIR_COMPONENT_DESCRIPTOR_V1: &[u8] = b"byte-memory-permutation=complete|strict-der-segment=complete|projection-segment=complete|shared-current-next-deep-ali=complete|rfc5280-base-row-provider=complete|rfc5280-aggregate-and-eighteen-independent-output-role-products=complete|rfc5280-private-source-and-CA-original-polynomial-air-links=complete|sha-call-witness-assembly-and-terminal-binding=complete|p256-witness-assembly-and-private-committed-terminal-air-links=complete|compact-ca-subproof=complete|full-49-registration-prover-and-verifier=complete|combined-main-ca-envelope=complete|consensus-verifier-integration=complete|release-evidence-schema=deterministic-X5S1-KAT+public-binding-mutations+wire-corruption-and-truncation+maximum-shape-process-measurement|activation=unavailable-qualification";
/// SHA-256 of the dedicated compact-CA prover/verifier descriptor.
///
/// The pin binds the exact X5C1/X5C2 proof system rather than only its component name.
pub const ZK_X509_COMPACT_CA_SUBPROOF_DESCRIPTOR_SHA256_V1: [u8; 32] = [
    0x1d, 0xab, 0x24, 0xa7, 0xdd, 0x4c, 0x60, 0x61, 0xbb, 0x38, 0xe1, 0x58, 0x65, 0xdf, 0xdf, 0x5b,
    0xe7, 0x01, 0x67, 0x16, 0x97, 0xa7, 0xba, 0x66, 0x94, 0x55, 0xc7, 0x78, 0xdd, 0xc1, 0x46, 0x05,
];
/// Failure of an implemented zk-X509 AIR primitive.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
pub enum ZkX509AirErrorV1 {
    /// A purported bit is outside `{0,1}`.
    #[error("zk-X509 AIR boolean constraint failed")]
    NonBoolean,
    /// A bit decomposition does not reconstruct its packed value.
    #[error("zk-X509 AIR range decomposition constraint failed")]
    RangeDecomposition,
    /// A selected bitwise gate equation is unsatisfied.
    #[cfg(test)]
    #[error("zk-X509 AIR bit-gate constraint failed")]
    BitGate,
    /// Gate selectors are not a one-hot fixed row.
    #[cfg(test)]
    #[error("zk-X509 AIR gate selector constraint failed")]
    GateSelector,
}
/// One degree-two range-check row for a private byte.
#[cfg(test)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ByteRangeAirRowV1 {
    /// Packed byte value.
    pub(crate) value: F,
    /// Little-endian bit decomposition.
    pub(crate) bits: [F; 8],
}
#[cfg(test)]
impl ByteRangeAirRowV1 {
    /// Construct the canonical witness row for one byte.
    pub(crate) fn from_byte(value: u8) -> Self {
        Self {
            value: F(u64::from(value)),
            bits: core::array::from_fn(|bit| F(u64::from((value >> bit) & 1))),
        }
    }
    /// Evaluate all local degree-two AIR identities.
    pub(crate) fn validate(self) -> Result<(), ZkX509AirErrorV1> {
        validate_bits_v1(&self.bits)?;
        let packed = self
            .bits
            .iter()
            .copied()
            .enumerate()
            .fold(F::ZERO, |sum, (bit, value)| {
                sum.add(value.mul(F(1_u64 << bit)))
            });
        if packed != self.value {
            return Err(ZkX509AirErrorV1::RangeDecomposition);
        }
        Ok(())
    }
}
/// One degree-two range-check row for an address, clock, or SHA-256 word.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct U32RangeAirRowV1 {
    /// Packed 32-bit value.
    pub(crate) value: F,
    /// Little-endian bit decomposition.
    pub(crate) bits: [F; 32],
}
impl U32RangeAirRowV1 {
    /// Construct the canonical witness row.
    pub(crate) fn from_u32(value: u32) -> Self {
        Self {
            value: F(u64::from(value)),
            bits: core::array::from_fn(|bit| F(u64::from((value >> bit) & 1))),
        }
    }
    /// Evaluate all local degree-two AIR identities.
    pub(crate) fn validate(self) -> Result<(), ZkX509AirErrorV1> {
        validate_bits_v1(&self.bits)?;
        let packed = self
            .bits
            .iter()
            .copied()
            .enumerate()
            .fold(F::ZERO, |sum, (bit, value)| {
                sum.add(value.mul(F(1_u64 << bit)))
            });
        if packed != self.value {
            return Err(ZkX509AirErrorV1::RangeDecomposition);
        }
        Ok(())
    }
}
/// One fixed-selector Boolean gate row used by SHA-256 and P-256 bit logic.
///
/// Selectors are fixed preprocessing columns in the final segment.  Keeping
/// them in this row type makes differential tests evaluate the exact equations
/// that the verifier will mix into its composition polynomial.
#[cfg(test)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BooleanGateAirRowV1 {
    /// Select `out = left AND right`.
    pub(crate) select_and: F,
    /// Select `out = left XOR right`.
    pub(crate) select_xor: F,
    /// Select `left + right + carry_in = out + 2*carry_out`.
    pub(crate) select_full_adder: F,
    /// First Boolean input.
    pub(crate) left: F,
    /// Second Boolean input.
    pub(crate) right: F,
    /// Full-adder carry input; zero on AND/XOR rows.
    pub(crate) carry_in: F,
    /// Boolean result.
    pub(crate) out: F,
    /// Full-adder carry output; zero on AND/XOR rows.
    pub(crate) carry_out: F,
}
#[cfg(test)]
impl BooleanGateAirRowV1 {
    /// Canonical AND witness row.
    pub(crate) fn and(left: bool, right: bool) -> Self {
        Self::new_selector([1, 0, 0], left, right, false, left & right, false)
    }
    /// Canonical XOR witness row.
    pub(crate) fn xor(left: bool, right: bool) -> Self {
        Self::new_selector([0, 1, 0], left, right, false, left ^ right, false)
    }
    /// Canonical one-bit full-adder witness row.
    pub(crate) fn full_adder(left: bool, right: bool, carry_in: bool) -> Self {
        let sum = u8::from(left) + u8::from(right) + u8::from(carry_in);
        Self::new_selector([0, 0, 1], left, right, carry_in, sum & 1 == 1, sum >= 2)
    }
    fn new_selector(
        selectors: [u64; 3],
        left: bool,
        right: bool,
        carry_in: bool,
        out: bool,
        carry_out: bool,
    ) -> Self {
        Self {
            select_and: F(selectors[0]),
            select_xor: F(selectors[1]),
            select_full_adder: F(selectors[2]),
            left: F(u64::from(left)),
            right: F(u64::from(right)),
            carry_in: F(u64::from(carry_in)),
            out: F(u64::from(out)),
            carry_out: F(u64::from(carry_out)),
        }
    }
    /// Evaluate the selector, Boolean, and selected gate equations.
    ///
    /// The bit equations have degree two; multiplying them by one fixed
    /// selector yields degree three, within the profile's degree-seven ceiling.
    pub(crate) fn validate(self) -> Result<(), ZkX509AirErrorV1> {
        validate_bits_v1(&[
            self.select_and,
            self.select_xor,
            self.select_full_adder,
            self.left,
            self.right,
            self.carry_in,
            self.out,
            self.carry_out,
        ])?;
        if self
            .select_and
            .add(self.select_xor)
            .add(self.select_full_adder)
            != F::ONE
        {
            return Err(ZkX509AirErrorV1::GateSelector);
        }
        let and_constraint = self.out.sub(self.left.mul(self.right));
        let xor_constraint = self.out.sub(
            self.left
                .add(self.right)
                .sub(F(2).mul(self.left.mul(self.right))),
        );
        let adder_constraint = self
            .left
            .add(self.right)
            .add(self.carry_in)
            .sub(self.out)
            .sub(F(2).mul(self.carry_out));
        let selected = self
            .select_and
            .mul(and_constraint)
            .add(self.select_xor.mul(xor_constraint))
            .add(self.select_full_adder.mul(adder_constraint));
        if selected != F::ZERO {
            return Err(ZkX509AirErrorV1::BitGate);
        }
        if self.select_full_adder == F::ZERO
            && (self.carry_in != F::ZERO || self.carry_out != F::ZERO)
        {
            return Err(ZkX509AirErrorV1::BitGate);
        }
        Ok(())
    }
}
fn validate_bits_v1(bits: &[F]) -> Result<(), ZkX509AirErrorV1> {
    if bits
        .iter()
        .copied()
        .any(|bit| bit.mul(bit.sub(F::ONE)) != F::ZERO)
    {
        return Err(ZkX509AirErrorV1::NonBoolean);
    }
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::privacy_engines::zk_x509::{
        accumulator_air::{
            ZK_X509_CA_ACCUMULATOR_BASE_WIDTH_V1, ZK_X509_CA_ACCUMULATOR_TRACE_ROWS_V1,
        },
        accumulator_stark::{
            ZK_X509_ACCUMULATOR_STARK_DESCRIPTOR_V1, ZK_X509_CA_ACCUMULATOR_AUX_WIDTH_V1,
            ZK_X509_CA_ACCUMULATOR_CHUNKS_V1, ZK_X509_CA_ACCUMULATOR_CONSTRAINT_DEGREE_V1,
            ZK_X509_CA_ACCUMULATOR_DEEP_OPENING_BYTES_V1, ZK_X509_CA_ACCUMULATOR_FIXED_WIDTH_V1,
            ZK_X509_CA_ACCUMULATOR_FRAME_BYTES_V1, ZK_X509_CA_ACCUMULATOR_INNER_MAX_PROOF_BYTES_V1,
            ZK_X509_CA_ACCUMULATOR_LOCAL_CONSTRAINT_COUNT_V1,
            ZK_X509_CA_ACCUMULATOR_MAX_PROOF_BYTES_V1, ZK_X509_CA_ACCUMULATOR_TRACE_LOG2_V1,
        },
        profile::{
            ZK_X509_CA_FRI_LDE_LOG2_V1, ZK_X509_CA_FRI_ROUNDS_V1,
            ZK_X509_CA_FRI_TERMINAL_DEGREE_BOUND_V1, ZK_X509_CA_FRI_TERMINAL_LOG2_V1,
            ZK_X509_CA_TRACE_MASK_DEGREE_V1, ZK_X509_FRI_QUERY_COUNT_V1, ZK_X509_GRINDING_BITS_V1,
        },
    };
    use sha2::{Digest as _, Sha256};
    #[test]
    fn byte_and_word_range_rows_reject_every_local_malleation() {
        for value in 0..=u8::MAX {
            ByteRangeAirRowV1::from_byte(value)
                .validate()
                .expect("canonical byte row");
        }
        for value in [0, 1, u32::from(u8::MAX), 1 << 31, u32::MAX] {
            U32RangeAirRowV1::from_u32(value)
                .validate()
                .expect("canonical word row");
        }
        let mut changed = ByteRangeAirRowV1::from_byte(173);
        changed.bits[4] = F(2);
        assert_eq!(changed.validate(), Err(ZkX509AirErrorV1::NonBoolean));
        let mut changed = ByteRangeAirRowV1::from_byte(173);
        changed.value = changed.value.add(F::ONE);
        assert_eq!(
            changed.validate(),
            Err(ZkX509AirErrorV1::RangeDecomposition)
        );
        let mut changed = U32RangeAirRowV1::from_u32(0xdead_beef);
        changed.bits[31] = changed.bits[31].sub(F::ONE);
        assert_eq!(
            changed.validate(),
            Err(ZkX509AirErrorV1::RangeDecomposition)
        );
    }
    #[test]
    fn boolean_gate_rows_cover_truth_tables_and_reject_adversarial_outputs() {
        for left in [false, true] {
            for right in [false, true] {
                BooleanGateAirRowV1::and(left, right)
                    .validate()
                    .expect("AND row");
                BooleanGateAirRowV1::xor(left, right)
                    .validate()
                    .expect("XOR row");
                for carry in [false, true] {
                    BooleanGateAirRowV1::full_adder(left, right, carry)
                        .validate()
                        .expect("full-adder row");
                }
            }
        }
        let mut changed = BooleanGateAirRowV1::xor(true, false);
        changed.out = F::ZERO;
        assert_eq!(changed.validate(), Err(ZkX509AirErrorV1::BitGate));
        let mut changed = BooleanGateAirRowV1::and(true, true);
        changed.select_xor = F::ONE;
        assert_eq!(changed.validate(), Err(ZkX509AirErrorV1::GateSelector));
        let mut changed = BooleanGateAirRowV1::and(false, false);
        changed.carry_out = F::ONE;
        assert_eq!(changed.validate(), Err(ZkX509AirErrorV1::BitGate));
    }
    #[test]
    fn component_manifest_is_complete_and_activation_requires_qualification() {
        let descriptor = String::from_utf8_lossy(ZK_X509_AIR_COMPONENT_DESCRIPTOR_V1);
        assert_eq!(descriptor.matches("=complete").count(), 13);
        assert_eq!(descriptor.matches("=pending").count(), 0);
        assert!(
            descriptor.ends_with("activation=unavailable-qualification"),
            "{descriptor}"
        );
    }
    #[test]
    fn compact_ca_descriptor_pin_names_the_exact_dedicated_prover_and_verifier() {
        let digest: [u8; 32] = Sha256::digest(ZK_X509_ACCUMULATOR_STARK_DESCRIPTOR_V1).into();
        assert_eq!(digest, ZK_X509_COMPACT_CA_SUBPROOF_DESCRIPTOR_SHA256_V1);
        let descriptor = String::from_utf8_lossy(ZK_X509_ACCUMULATOR_STARK_DESCRIPTOR_V1);
        for required in [
            "wire-envelope-X5C1+inner-X5C2",
            "strict-version-length-and-no-trailing-bytes",
            "dedicated-lde-log16",
            "trace-mask2100-coefficients",
            "fri136-distinct-post-grinding20",
            "one-MAIN-and-CA-joint-deep-point-current+next",
            "all-four-terminal-families-algebraically-bound",
            "joint-original-polynomial-MAIN108-links=ordered-sha13-source-and-digest-plus-rfc91-root-consumer",
            "shared-X5S1-pre-aux-after-one-joined-main-plus-one-ca-base-roots",
            "root-spki-channel=30+2*public-disclosures",
            "checked-native-lde-scratch-resident-and-work-ceilings",
            "canonical-chunk-stride9079",
            "independent-adjacent-fp4-masks137-before-commitment",
            "producer-self-verifies",
        ] {
            assert!(
                descriptor.contains(required),
                "compact-CA descriptor must bind {required}"
            );
        }
        assert_eq!(ZK_X509_CA_ACCUMULATOR_TRACE_LOG2_V1, 12);
        assert_eq!(ZK_X509_CA_ACCUMULATOR_TRACE_ROWS_V1, 4096);
        assert_eq!(ZK_X509_CA_FRI_LDE_LOG2_V1, 16);
        assert_eq!(ZK_X509_CA_ACCUMULATOR_BASE_WIDTH_V1, 695);
        assert_eq!(ZK_X509_CA_ACCUMULATOR_AUX_WIDTH_V1, 128);
        assert_eq!(ZK_X509_CA_ACCUMULATOR_FIXED_WIDTH_V1, 80);
        assert_eq!(ZK_X509_CA_ACCUMULATOR_LOCAL_CONSTRAINT_COUNT_V1, 1_363);
        assert_eq!(ZK_X509_CA_ACCUMULATOR_CONSTRAINT_DEGREE_V1, 3);
        assert_eq!(ZK_X509_CA_ACCUMULATOR_CHUNKS_V1, 13);
        assert_eq!(ZK_X509_CA_TRACE_MASK_DEGREE_V1 + 1, 2100);
        assert_eq!(ZK_X509_FRI_QUERY_COUNT_V1, 136);
        assert_eq!(ZK_X509_CA_FRI_ROUNDS_V1, 6);
        assert_eq!(ZK_X509_CA_FRI_TERMINAL_LOG2_V1, 10);
        assert_eq!(ZK_X509_CA_FRI_TERMINAL_DEGREE_BOUND_V1, 143);
        assert_eq!(ZK_X509_GRINDING_BITS_V1, 20);
        assert_eq!(ZK_X509_CA_ACCUMULATOR_FRAME_BYTES_V1, 10);
        assert_eq!(ZK_X509_CA_ACCUMULATOR_DEEP_OPENING_BYTES_V1, 52_800);
        assert_eq!(ZK_X509_CA_ACCUMULATOR_INNER_MAX_PROOF_BYTES_V1, 1_498_816);
        assert_eq!(ZK_X509_CA_ACCUMULATOR_MAX_PROOF_BYTES_V1, 1_498_826);
        let _verifier =
            super::super::accumulator_stark::joint_verifier::CaJointVerifierOraclesV1::new_v1;
    }
}
