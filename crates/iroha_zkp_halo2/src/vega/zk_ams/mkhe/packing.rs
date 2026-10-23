//! Exact T256 packing through conjugate quadratic factors of `X^N + 1`.
use super::{
    BgvProfile, ZkAmsMkheErrorV1,
    manifest::{
        ZK_AMS_MKHE_RELEASE_RING_DEGREE_V1, ZK_AMS_MKHE_RELEASE_SLOT_COUNT_V1, release_profile_v1,
    },
};
#[cfg(test)]
use super::{
    RnsPolynomial, bytes_mod_u64, checked_coefficient_work, manifest::RELEASE_MODULI_V1,
    t256_centered_residue_with_modulus_residue,
};
#[cfg(test)]
use crate::vega::sponge::{Keccak256, keccak256};
use crate::vega::{VEGA_T256_SCALAR_MODULUS_BE_V1, VegaT256ScalarV1 as Scalar, sponge::shake256};
#[cfg(test)]
use core::fmt;
const PACKING_VERSION_V1: u8 = 1;
const SLOT_GALOIS_GENERATOR_V1: usize = 5;
const GALOIS_KEY_SCHEDULE_BITS_V1: u32 = 16;
const RELEASE_ROOT_DERIVATION_DOMAIN_V1: &[u8] = b"iroha.zk-ams.v1.mkhe.t256-fp2-root";
const RELEASE_ROOT_IDENTITY_DOMAIN_V1: &[u8] = b"iroha.zk-ams.v1.mkhe.t256-fp2-root-identity";
const PACKING_LAYOUT_DOMAIN_V1: &[u8] = b"iroha.zk-ams.v1.mkhe.t256-packing-layout";
#[cfg(test)]
const PACKED_PLAINTEXT_DOMAIN_V1: &[u8] = b"iroha.zk-ams.v1.mkhe.t256-packed-plaintext";
#[cfg(test)]
const PACKED_RNS_BINDING_DOMAIN_V1: &[u8] = b"iroha.zk-ams.v1.mkhe.t256-transformed-rns";
const PACKED_SUBFIELD_DOMAIN_V1: &[u8] = b"iroha.zk-ams.v1.mkhe.t256-packed-subfield";
const PACKED_SUBFIELD_RELATION_V1: &[u8] = b"sigma_p(M)=M mod p:sigma_p(X)=X^(p mod 2N)=X^(2N-1)";
const ROTATION_DOMAIN_V1: &[u8] = b"iroha.zk-ams.v1.mkhe.t256-rotation";
const GALOIS_KEY_SCHEDULE_DOMAIN_V1: &[u8] = b"iroha.zk-ams.v1.mkhe.t256-galois-key-schedule";
#[cfg(test)]
const ROTATION_CERTIFICATE_DOMAIN_V1: &[u8] = b"iroha.zk-ams.v1.mkhe.t256-rotation-certificate";
const RELEASE_PACKING_CERTIFICATE_DOMAIN_V1: &[u8] =
    b"iroha.zk-ams.v1.mkhe.t256-release-packing-certificate";
// Exact full BGV profile recorded by the existing packing KAT constants.
// Changing the schedule/profile identity must not relabel those observations.
// This pin establishes identity only; it is not independent release evidence.
const RELEASE_PACKING_EVIDENCE_PROFILE_DIGEST_V1: [u8; 32] = [
    0xa6, 0x4a, 0xd0, 0x4a, 0x95, 0x70, 0xbd, 0xa6, 0x1c, 0x0f, 0xd3, 0x63, 0x46, 0x39, 0x2a, 0x3d,
    0xfa, 0xf1, 0x22, 0x4b, 0x1e, 0x3a, 0x0b, 0x9d, 0x82, 0x20, 0xf7, 0x45, 0xe4, 0xbc, 0x8e, 0xcc,
];
/// Maximum number of logical values admitted by one governed packed vector.
pub const ZK_AMS_T256_MAX_LOGICAL_VALUES_V1: u32 = 1_048_576;
/// Exact number of unique Galois exponents in the minimal binary rotation schedule.
pub const ZK_AMS_T256_GALOIS_KEY_COUNT_V1: usize = 31;
/// Pinned digest of the exact ordered binary Galois-key schedule.
pub const ZK_AMS_T256_GALOIS_KEY_SCHEDULE_DIGEST_V1: [u8; 32] = [
    0x14, 0x4c, 0x6d, 0x54, 0xf0, 0x63, 0xb8, 0x48, 0x8c, 0xe6, 0x96, 0xef, 0xc8, 0x3d, 0x79, 0x46,
    0x91, 0xfb, 0xac, 0x4b, 0x22, 0xca, 0x68, 0x5d, 0xdc, 0xfa, 0xa3, 0x3a, 0x80, 0xe8, 0x52, 0x9d,
];
/// Pinned digest of the exact release-degree sparse-cosine packing input.
pub const ZK_AMS_T256_RELEASE_PACKED_INPUT_KAT_DIGEST_V1: [u8; 32] = [
    0x1f, 0xe3, 0xf5, 0xd9, 0x7d, 0xdc, 0x3d, 0xad, 0x31, 0x1a, 0xda, 0xcc, 0x80, 0xf5, 0xd4, 0x4d,
    0xa6, 0x1f, 0x65, 0xf7, 0xa6, 0xec, 0xb9, 0x72, 0x5e, 0x9a, 0x0f, 0xba, 0xb3, 0x53, 0xde, 0x52,
];
/// Pinned digest of the coefficient-domain release rotation KAT output.
pub const ZK_AMS_T256_RELEASE_PACKED_OUTPUT_KAT_DIGEST_V1: [u8; 32] = [
    0xa4, 0xb1, 0xcb, 0xcb, 0x1d, 0x66, 0x85, 0xb3, 0x4e, 0x6e, 0xac, 0x96, 0x93, 0xb1, 0xae, 0x65,
    0x1a, 0xe0, 0x72, 0x6d, 0x70, 0xfa, 0xc2, 0xa1, 0x8c, 0x01, 0x9e, 0x52, 0x5a, 0xd6, 0x20, 0x79,
];
/// Pinned digest of every transformed release-RNS limb in the packing KAT.
pub const ZK_AMS_T256_RELEASE_TRANSFORMED_RNS_KAT_DIGEST_V1: [u8; 32] = [
    0x25, 0xc5, 0xca, 0xaf, 0x78, 0xf0, 0x3e, 0x77, 0xcf, 0xef, 0x23, 0xe6, 0xaf, 0x99, 0x5f, 0x41,
    0x27, 0x2f, 0x21, 0x38, 0xf1, 0x0a, 0x75, 0x7a, 0x21, 0x07, 0xad, 0x6d, 0x7a, 0x1b, 0x62, 0x3f,
];
/// Pinned certificate digest for the exact release-degree packing/rotation KAT.
pub const ZK_AMS_T256_RELEASE_ROTATION_CERTIFICATE_KAT_DIGEST_V1: [u8; 32] = [
    0x4b, 0x59, 0x00, 0x5c, 0x59, 0xaa, 0x68, 0x9f, 0x70, 0xd5, 0xb3, 0xc3, 0xc0, 0x29, 0xe8, 0x9a,
    0x67, 0x82, 0x42, 0xed, 0xec, 0x17, 0x4e, 0xe7, 0x7e, 0x3a, 0x7e, 0xbc, 0xe8, 0x39, 0x2d, 0x46,
];
/// Pinned digest of the exact adversarial packing/rotation rejection catalogue.
pub const ZK_AMS_T256_RELEASE_PACKING_NEGATIVE_KAT_DIGEST_V1: [u8; 32] = [
    0xd7, 0xf3, 0x56, 0xce, 0xa3, 0x80, 0xb6, 0x9d, 0xa5, 0xc7, 0x08, 0xc8, 0x9a, 0x86, 0xb6, 0xb9,
    0xa7, 0x1b, 0x57, 0x0e, 0x61, 0x1c, 0xc3, 0x2d, 0xcc, 0xa2, 0xa6, 0x40, 0x7f, 0x8a, 0x9f, 0xf7,
];
/// Exact number of independently labelled rejection cases in the release KAT.
pub const ZK_AMS_T256_RELEASE_PACKING_NEGATIVE_CASE_COUNT_V1: u16 = 31;
#[cfg(test)]
const RELEASE_ROOT_EXPONENT_KAT_BE_V1: [u8; 64] = [
    0x00, 0x00, 0x3f, 0xff, 0xff, 0xff, 0x80, 0x00, 0x00, 0x00, 0xbf, 0xff, 0xff, 0xff, 0x80, 0x00,
    0x00, 0x00, 0x40, 0x00, 0x00, 0x00, 0x7f, 0xff, 0xff, 0xff, 0x80, 0x00, 0x00, 0x00, 0x7f, 0xff,
    0xff, 0xff, 0x80, 0x00, 0x00, 0x00, 0x7f, 0xff, 0xff, 0xff, 0xbf, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
];
const RELEASE_ROOT_C0_BE_V1: [u8; 32] = [
    0x2e, 0xb7, 0xc1, 0x99, 0xa1, 0x3f, 0x8f, 0xc4, 0x72, 0x3a, 0x51, 0x4c, 0x33, 0xa9, 0x8a, 0x23,
    0x00, 0xfd, 0x4b, 0x08, 0x23, 0x65, 0x17, 0xf6, 0xba, 0xb6, 0x9e, 0xd3, 0x0d, 0x11, 0x91, 0xb2,
];
const RELEASE_ROOT_C1_BE_V1: [u8; 32] = [
    0xe4, 0xec, 0x4e, 0xc7, 0xaf, 0x44, 0xce, 0x13, 0x75, 0xbf, 0xad, 0x21, 0x02, 0xd3, 0x87, 0x52,
    0xeb, 0x67, 0x44, 0xa0, 0x71, 0x96, 0x94, 0x3f, 0x63, 0x3b, 0x53, 0x05, 0x44, 0x0d, 0x6a, 0xb8,
];
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct T256Fp2 {
    c0: Scalar,
    c1: Scalar,
}
/// Test-only bounded scratch owner for scalar decoder parity checks.
/// Deliberately neither `Clone` nor `Debug`.
#[cfg(test)]
struct ZeroizingPackingScalarsV1(Vec<Scalar>);
#[cfg(test)]
impl ZeroizingPackingScalarsV1 {
    fn with_capacity(capacity: usize) -> Result<Self, ZkAmsMkheErrorV1> {
        let mut values = Vec::new();
        values
            .try_reserve_exact(capacity)
            .map_err(|_| ZkAmsMkheErrorV1::ResourceCeilingExceeded)?;
        Ok(Self(values))
    }
    fn push(&mut self, value: Scalar) {
        self.0.push(value);
    }
    fn take(&mut self) -> Vec<Scalar> {
        core::mem::take(&mut self.0)
    }
}
#[cfg(test)]
impl Drop for ZeroizingPackingScalarsV1 {
    fn drop(&mut self) {
        let values = core::hint::black_box(&mut self.0);
        for value in values.iter_mut() {
            value.clear_secret();
        }
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
        let _ = core::hint::black_box(&mut *values);
    }
}
/// Bounded scratch owner for the quadratic-extension NTT evaluations used by
/// packed decoding. Deliberately neither `Clone` nor `Debug`.
#[cfg(test)]
struct ZeroizingPackingFp2V1(Vec<T256Fp2>);
#[cfg(test)]
impl ZeroizingPackingFp2V1 {
    fn with_capacity(capacity: usize) -> Result<Self, ZkAmsMkheErrorV1> {
        let mut values = Vec::new();
        values
            .try_reserve_exact(capacity)
            .map_err(|_| ZkAmsMkheErrorV1::ResourceCeilingExceeded)?;
        Ok(Self(values))
    }
    #[cfg(test)]
    fn push(&mut self, value: T256Fp2) {
        self.0.push(value);
    }
}
#[cfg(test)]
impl Drop for ZeroizingPackingFp2V1 {
    fn drop(&mut self) {
        let values = core::hint::black_box(&mut self.0);
        for value in values.iter_mut() {
            value.c0.clear_secret();
            value.c1.clear_secret();
        }
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
        let _ = core::hint::black_box(&mut *values);
    }
}
/// Wiping owner borrowed by the visitor for one canonical decoded scalar.
/// Deliberately neither `Clone` nor `Debug`; errors and unwinds erase it.
#[cfg(test)]
struct ZeroizingPackingScalarBytesV1([u8; 32]);
#[cfg(test)]
std::thread_local! {
    static PACKING_SCALAR_BYTES_ZEROIZED_DROPS_V1: std::cell::Cell<usize> = const {
        std::cell::Cell::new(0)
    };
}
#[cfg(test)]
fn packing_scalar_bytes_zeroized_drop_count_v1() -> usize {
    PACKING_SCALAR_BYTES_ZEROIZED_DROPS_V1
        .try_with(std::cell::Cell::get)
        .unwrap_or(0)
}
#[cfg(test)]
impl ZeroizingPackingScalarBytesV1 {
    const fn new() -> Self {
        Self([0; 32])
    }
    fn encode_from(&mut self, value: &Scalar) {
        self.0 = value.to_be_bytes();
    }
    const fn as_array(&self) -> &[u8; 32] {
        &self.0
    }
}
#[cfg(test)]
impl Drop for ZeroizingPackingScalarBytesV1 {
    fn drop(&mut self) {
        let bytes = core::hint::black_box(&mut self.0);
        bytes.fill(0);
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
        #[cfg(test)]
        if bytes.iter().all(|byte| *byte == 0) {
            let _ = PACKING_SCALAR_BYTES_ZEROIZED_DROPS_V1
                .try_with(|drops| drops.set(drops.get().saturating_add(1)));
        }
        let _ = core::hint::black_box(&mut *bytes);
    }
}
/// Reusable, exactly release-sized decoder workspace. The sole evaluation vector is erased after
/// every chunk and again when the workspace is dropped. Deliberately neither `Clone` nor `Debug`.
#[cfg(test)]
pub(super) struct T256PackedPlaintextDecodeWorkspaceV1(ZeroizingPackingFp2V1);
#[cfg(test)]
impl T256PackedPlaintextDecodeWorkspaceV1 {
    /// Fallibly reserve the complete decoder workspace before consuming input.
    pub(super) fn try_new_v1() -> Result<Self, ZkAmsMkheErrorV1> {
        let mut evaluations =
            ZeroizingPackingFp2V1::with_capacity(ZK_AMS_MKHE_RELEASE_RING_DEGREE_V1)?;
        evaluations
            .0
            .resize(ZK_AMS_MKHE_RELEASE_RING_DEGREE_V1, T256Fp2::zero());
        Ok(Self(evaluations))
    }
}
/// Borrow guard that erases the named decoder workspace on success, error,
/// and unwind. Compiler-created scalar/register copies remain outside this
/// narrow optimizer-resistant guarantee.
#[cfg(test)]
struct ClearingPackingFp2BorrowV1<'workspace>(&'workspace mut [T256Fp2]);
#[cfg(test)]
std::thread_local! {
    static PACKING_WORKSPACE_ZEROIZED_DROPS_V1: std::cell::Cell<usize> = const {
        std::cell::Cell::new(0)
    };
}
#[cfg(test)]
fn packing_workspace_zeroized_drop_count_v1() -> usize {
    PACKING_WORKSPACE_ZEROIZED_DROPS_V1
        .try_with(std::cell::Cell::get)
        .unwrap_or(0)
}
#[cfg(test)]
impl Drop for ClearingPackingFp2BorrowV1<'_> {
    fn drop(&mut self) {
        let values = core::hint::black_box(&mut self.0);
        for value in values.iter_mut() {
            value.c0.clear_secret();
            value.c1.clear_secret();
        }
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
        #[cfg(test)]
        if values
            .iter()
            .all(|value| value.c0.is_zero() && value.c1.is_zero())
        {
            let _ = PACKING_WORKSPACE_ZEROIZED_DROPS_V1
                .try_with(|drops| drops.set(drops.get().saturating_add(1)));
        }
        let _ = core::hint::black_box(&mut *values);
    }
}
/// Test-only exact release-RNS plaintext owner used while hashing a native binding.
/// Deliberately neither `Clone` nor `Debug`.
#[cfg(test)]
struct ZeroizingPackedRnsBindingV1(RnsPolynomial);
#[cfg(test)]
std::thread_local! {
    static PACKED_RNS_BINDING_ZEROIZED_DROPS_V1: std::cell::Cell<usize> = const {
        std::cell::Cell::new(0)
    };
}
#[cfg(test)]
fn packed_rns_binding_zeroized_drop_count_v1() -> usize {
    PACKED_RNS_BINDING_ZEROIZED_DROPS_V1
        .try_with(std::cell::Cell::get)
        .unwrap_or(0)
}
#[cfg(test)]
impl Drop for ZeroizingPackedRnsBindingV1 {
    fn drop(&mut self) {
        let coefficients = core::hint::black_box(&mut self.0.coefficients);
        coefficients.fill(0);
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
        #[cfg(test)]
        if coefficients.iter().all(|coefficient| *coefficient == 0) {
            let _ = PACKED_RNS_BINDING_ZEROIZED_DROPS_V1
                .try_with(|drops| drops.set(drops.get().saturating_add(1)));
        }
        let _ = core::hint::black_box(&mut *coefficients);
    }
}
/// Heap-stable owner for exactly one release-RNS limb. Its storage is private,
/// optimizer-resistantly erased on every drop path, and deliberately neither `Clone` nor `Debug`.
#[cfg(test)]
#[allow(
    dead_code,
    reason = "private limb-stream prerequisite is intentionally not wired to release consumers yet"
)]
pub(super) struct ZeroizingT256ReleaseLimbV1 {
    coefficients: Box<[u64]>,
    filled_limb: Option<usize>,
}
/// Immutable typed borrow of one successfully filled release limb. The private ordinal and modulus
/// travel with the coefficient slice; future adapters must accept this typed borrow intact when
/// preserving that association. Reading its parts separately does not by itself enforce correct
/// pairing. Deliberately neither `Clone` nor `Debug`.
#[cfg(test)]
#[allow(
    dead_code,
    reason = "private limb-stream prerequisite is intentionally not wired to release consumers yet"
)]
pub(super) struct FilledT256ReleaseLimbV1<'limb> {
    limb: usize,
    modulus: u64,
    coefficients: &'limb [u64],
}
#[cfg(test)]
#[allow(
    dead_code,
    reason = "private limb-stream prerequisite is intentionally not wired to release consumers yet"
)]
impl FilledT256ReleaseLimbV1<'_> {
    /// Return the canonical zero-based release-limb ordinal.
    pub(super) fn limb_v1(&self) -> usize {
        self.limb
    }
    /// Return the release modulus bound to this limb ordinal.
    pub(super) fn modulus_v1(&self) -> u64 {
        self.modulus
    }
    /// Borrow the canonical residues without permitting mutation or transfer.
    pub(super) fn coefficients_v1(&self) -> &[u64] {
        self.coefficients
    }
}
#[cfg(test)]
std::thread_local! {
    static T256_RELEASE_LIMB_ZEROIZED_DROPS_V1: std::cell::Cell<usize> = const {
        std::cell::Cell::new(0)
    };
}
#[cfg(test)]
fn t256_release_limb_zeroized_drop_count_v1() -> usize {
    T256_RELEASE_LIMB_ZEROIZED_DROPS_V1
        .try_with(std::cell::Cell::get)
        .unwrap_or(0)
}
#[cfg(test)]
#[allow(
    dead_code,
    reason = "private limb-stream prerequisite is intentionally not wired to release consumers yet"
)]
impl ZeroizingT256ReleaseLimbV1 {
    /// Allocate one zeroed release limb before any plaintext-derived residue is
    /// written into the stable owner.
    pub(super) fn new_zeroed_v1() -> Result<Self, ZkAmsMkheErrorV1> {
        let mut coefficients = Vec::new();
        coefficients
            .try_reserve_exact(ZK_AMS_MKHE_RELEASE_RING_DEGREE_V1)
            .map_err(|_| ZkAmsMkheErrorV1::ResourceCeilingExceeded)?;
        coefficients.resize(ZK_AMS_MKHE_RELEASE_RING_DEGREE_V1, 0);
        Ok(Self {
            coefficients: coefficients.into_boxed_slice(),
            filled_limb: None,
        })
    }
    /// Borrow a successfully absorbed limb together with its exact release
    /// ordinal and modulus. An unfilled owner fails closed.
    pub(super) fn filled_v1(&self) -> Result<FilledT256ReleaseLimbV1<'_>, ZkAmsMkheErrorV1> {
        let limb = self
            .filled_limb
            .ok_or(ZkAmsMkheErrorV1::InvalidPolynomial)?;
        let modulus = *RELEASE_MODULI_V1
            .get(limb)
            .ok_or(ZkAmsMkheErrorV1::InvalidPolynomial)?;
        Ok(FilledT256ReleaseLimbV1 {
            limb,
            modulus,
            coefficients: &self.coefficients,
        })
    }
}
#[cfg(test)]
impl Drop for ZeroizingT256ReleaseLimbV1 {
    fn drop(&mut self) {
        self.filled_limb = None;
        #[cfg(test)]
        let label_cleared = self.filled_limb.is_none();
        let coefficients = core::hint::black_box(&mut self.coefficients);
        coefficients.fill(0);
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
        #[cfg(test)]
        if label_cleared && coefficients.iter().all(|coefficient| *coefficient == 0) {
            let _ = T256_RELEASE_LIMB_ZEROIZED_DROPS_V1
                .try_with(|drops| drops.set(drops.get().saturating_add(1)));
        }
        let _ = core::hint::black_box(&mut *coefficients);
    }
}
/// Borrowed, exact-validation capability for allocation-free release-limb lifting. Its fields stay
/// private so sibling modules cannot recover the raw packed artifact through this capability.
/// Deliberately neither `Clone` nor `Debug`.
#[cfg(test)]
#[allow(
    dead_code,
    reason = "private limb-stream prerequisite is intentionally not wired to release consumers yet"
)]
pub(super) struct ValidatedT256PackedPlaintextV1<'packed> {
    layout: ZkAmsT256PackingLayoutV1,
    packed: &'packed ZkAmsT256PackedPlaintextV1,
}
#[cfg(test)]
#[allow(
    dead_code,
    reason = "private limb-stream prerequisite is intentionally not wired to release consumers yet"
)]
impl<'packed> ValidatedT256PackedPlaintextV1<'packed> {
    /// Perform metadata, canonical-coefficient, digest, subfield, and decoded-
    /// padding artifact validation once, then preflight the same complete
    /// release-lift work gate used by the native full-RNS path.
    ///
    /// The work gate runs before decoder-workspace allocation. Once this method
    /// succeeds, partial or repeated limb reads neither bypass nor repeatedly
    /// claim the full 38-limb source-operation budget.
    pub(super) fn validate_for_release_limb_stream_v1(
        layout: ZkAmsT256PackingLayoutV1,
        packed: &'packed ZkAmsT256PackedPlaintextV1,
    ) -> Result<Self, ZkAmsMkheErrorV1> {
        validate_layout(layout)?;
        validate_packed(layout, packed)?;
        let profile = release_profile_v1();
        checked_coefficient_work(&profile, profile.moduli.len())?;
        // Padding is a slot-domain property, so coefficient checks alone are
        // insufficient. The in-place decoder performs the NTT in one Fp2
        // owner and visits no values here; it retains neither scalar nor byte
        // copies after validation.
        let mut workspace = T256PackedPlaintextDecodeWorkspaceV1::try_new_v1()?;
        visit_validated_packed_plaintext_used_slots_with_workspace_v1(
            packed,
            &mut workspace,
            |_| Ok(()),
        )?;
        Ok(Self { layout, packed })
    }
    /// Fill exactly one zeroizing release-limb owner without allocation.
    ///
    /// Invalid indices or buffer sizes are rejected before the output is touched. On success the
    /// owner retains the residues for later arithmetic and erases them automatically on drop.
    /// Scalar loop values and compiler-created temporaries are not claimed to be
    /// optimizer-resistantly zeroized.
    fn lift_release_limb_into_v1(
        &self,
        limb: usize,
        output: &mut ZeroizingT256ReleaseLimbV1,
    ) -> Result<(), ZkAmsMkheErrorV1> {
        let Some(&modulus) = RELEASE_MODULI_V1.get(limb) else {
            return Err(ZkAmsMkheErrorV1::InvalidPolynomial);
        };
        if output.coefficients.len() != ZK_AMS_MKHE_RELEASE_RING_DEGREE_V1 {
            return Err(ZkAmsMkheErrorV1::InvalidPolynomial);
        }
        debug_assert_eq!(self.packed.layout_digest, self.layout.digest);
        debug_assert_eq!(self.packed.coefficients.len(), output.coefficients.len());
        lift_centered_t256_coefficients_into_v1(
            &self.packed.coefficients,
            modulus,
            &mut output.coefficients,
        );
        Ok(())
    }
}
/// Move-only ordered transcript state shared by the release wrapper and tiny parity tests. It
/// retains only the Keccak state and non-secret profile geometry, never polynomial coefficients.
#[cfg(test)]
#[allow(
    dead_code,
    reason = "private limb-stream prerequisite is intentionally not wired to release consumers yet"
)]
struct OrderedRnsBindingHashV1 {
    hash: Box<Keccak256>,
    ring_degree: usize,
    moduli: &'static [u64],
    next_limb: usize,
}
#[cfg(test)]
#[allow(
    dead_code,
    reason = "private limb-stream prerequisite is intentionally not wired to release consumers yet"
)]
impl OrderedRnsBindingHashV1 {
    fn new(profile: &BgvProfile) -> Result<Self, ZkAmsMkheErrorV1> {
        profile.validate()?;
        // Establish a stable owner before absorbing any plaintext-derived byte.
        let mut hash = Box::new(Keccak256::new());
        hash.update(PACKED_RNS_BINDING_DOMAIN_V1);
        hash.update(&profile.digest()?);
        hash.update(
            &u32::try_from(profile.ring_degree)
                .map_err(|_| ZkAmsMkheErrorV1::InvalidProfile)?
                .to_be_bytes(),
        );
        hash.update(
            &u32::try_from(profile.moduli.len())
                .map_err(|_| ZkAmsMkheErrorV1::InvalidProfile)?
                .to_be_bytes(),
        );
        Ok(Self {
            hash,
            ring_degree: profile.ring_degree,
            moduli: profile.moduli,
            next_limb: 0,
        })
    }
    fn expect_limb(&self, limb: usize, coefficient_count: usize) -> Result<(), ZkAmsMkheErrorV1> {
        if limb != self.next_limb
            || limb >= self.moduli.len()
            || coefficient_count != self.ring_degree
        {
            return Err(ZkAmsMkheErrorV1::InvalidPolynomial);
        }
        Ok(())
    }
    fn absorb_limb(&mut self, limb: usize, coefficients: &[u64]) -> Result<(), ZkAmsMkheErrorV1> {
        self.expect_limb(limb, coefficients.len())?;
        let modulus = self.moduli[limb];
        if coefficients
            .iter()
            .any(|coefficient| *coefficient >= modulus)
        {
            return Err(ZkAmsMkheErrorV1::InvalidPolynomial);
        }
        self.hash.update(&modulus.to_be_bytes());
        for coefficient in coefficients {
            self.hash.update(&coefficient.to_be_bytes());
        }
        self.next_limb = self
            .next_limb
            .checked_add(1)
            .ok_or(ZkAmsMkheErrorV1::ResourceCeilingExceeded)?;
        Ok(())
    }
    fn finish(mut self) -> Result<[u8; 32], ZkAmsMkheErrorV1> {
        if self.next_limb != self.moduli.len() {
            return Err(ZkAmsMkheErrorV1::InvalidPolynomial);
        }
        let mut digest = [0_u8; 32];
        self.hash.finalize_into(&mut digest);
        Ok(digest)
    }
}
/// Move-only incremental native RNS-binding hasher for one validated packed
/// plaintext. It enforces the canonical release limb order `0..38` and retains
/// neither a full plaintext lift nor an individual limb.
#[cfg(test)]
#[allow(
    dead_code,
    reason = "private limb-stream prerequisite is intentionally not wired to release consumers yet"
)]
pub(super) struct T256PackedRnsBindingHasherV1<'packed> {
    plaintext: ValidatedT256PackedPlaintextV1<'packed>,
    transcript: OrderedRnsBindingHashV1,
}
#[cfg(test)]
#[allow(
    dead_code,
    reason = "private limb-stream prerequisite is intentionally not wired to release consumers yet"
)]
impl<'packed> T256PackedRnsBindingHasherV1<'packed> {
    /// Start the exact native RNS-binding transcript for a validated plaintext.
    pub(super) fn new(
        plaintext: ValidatedT256PackedPlaintextV1<'packed>,
    ) -> Result<Self, ZkAmsMkheErrorV1> {
        Ok(Self {
            plaintext,
            transcript: OrderedRnsBindingHashV1::new(&release_profile_v1())?,
        })
    }
    /// Lift and absorb the next canonical release limb into a caller-provided zeroizing owner. Its
    /// typed immutable borrow remains available after success.
    pub(super) fn absorb_next_release_limb_into_v1(
        &mut self,
        limb: usize,
        output: &mut ZeroizingT256ReleaseLimbV1,
    ) -> Result<(), ZkAmsMkheErrorV1> {
        // Check order and size first so a rejected duplicate/out-of-order call
        // cannot overwrite a caller's existing arithmetic buffer.
        self.transcript
            .expect_limb(limb, output.coefficients.len())?;
        // Once prechecks accept the call, invalidate the previous label before
        // overwriting bytes. An unexpected unwind therefore cannot expose new
        // residues under the old ordinal.
        output.filled_limb = None;
        self.plaintext.lift_release_limb_into_v1(limb, output)?;
        self.transcript.absorb_limb(limb, &output.coefficients)?;
        output.filled_limb = Some(limb);
        Ok(())
    }
    /// Finish only after all 38 release limbs were absorbed exactly once.
    ///
    /// The returned deterministic digest is a non-hiding in-process equality/lineage binding. It is
    /// not a proof, MAC, authorization, capability, or receipt, and equality or offline guesses can
    /// be visible for low-entropy plaintexts. No partial transcript state is exposed.
    pub(super) fn finish(self) -> Result<[u8; 32], ZkAmsMkheErrorV1> {
        self.transcript.finish()
    }
}
#[cfg(test)]
fn lift_centered_t256_coefficients_into_v1(
    coefficients: &[[u8; 32]],
    modulus: u64,
    output: &mut [u64],
) {
    debug_assert_eq!(coefficients.len(), output.len());
    let plaintext_modulus_residue = bytes_mod_u64(&VEGA_T256_SCALAR_MODULUS_BE_V1, modulus);
    for (output, coefficient) in output.iter_mut().zip(coefficients) {
        *output = t256_centered_residue_with_modulus_residue(
            coefficient,
            modulus,
            plaintext_modulus_residue,
        );
    }
}
impl T256Fp2 {
    #[cfg(test)]
    fn zero() -> Self {
        Self {
            c0: Scalar::zero(),
            c1: Scalar::zero(),
        }
    }
    fn one() -> Self {
        Self {
            c0: Scalar::one(),
            c1: Scalar::zero(),
        }
    }
    fn from_base(value: Scalar) -> Self {
        Self {
            c0: value,
            c1: Scalar::zero(),
        }
    }
    fn conjugate(self) -> Self {
        Self {
            c0: self.c0,
            c1: -self.c1,
        }
    }
    #[cfg(test)]
    fn add(self, rhs: Self) -> Self {
        Self {
            c0: self.c0 + rhs.c0,
            c1: self.c1 + rhs.c1,
        }
    }
    #[cfg(test)]
    fn sub(self, rhs: Self) -> Self {
        Self {
            c0: self.c0 - rhs.c0,
            c1: self.c1 - rhs.c1,
        }
    }
    fn mul(self, rhs: Self) -> Self {
        // `u^2 + 1` is irreducible because the frozen T256 prime is 3 mod 4.
        Self {
            c0: self.c0 * rhs.c0 - self.c1 * rhs.c1,
            c1: self.c0 * rhs.c1 + self.c1 * rhs.c0,
        }
    }
    #[cfg(test)]
    fn scale(self, scalar: Scalar) -> Self {
        Self {
            c0: self.c0 * scalar,
            c1: self.c1 * scalar,
        }
    }
    fn pow_u64(self, mut exponent: u64) -> Self {
        let mut base = self;
        let mut result = Self::one();
        while exponent != 0 {
            if exponent & 1 == 1 {
                result = result.mul(base);
            }
            base = base.mul(base);
            exponent >>= 1;
        }
        result
    }
    fn pow_be(self, exponent: &[u8]) -> Self {
        let mut result = Self::one();
        for byte in exponent {
            for bit in (0..8).rev() {
                result = result.mul(result);
                if (byte >> bit) & 1 == 1 {
                    result = result.mul(self);
                }
            }
        }
        result
    }
}
/// Canonical fixed chunk layout for one logical T256 vector.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ZkAmsT256PackingLayoutV1 {
    /// Layout schema version.
    pub version: u8,
    /// Digest of the sole release RNS-BGV profile.
    pub profile_digest: [u8; 32],
    /// Exact number of logical field values before padding.
    pub logical_value_count: u32,
    /// Frozen values per ciphertext chunk.
    pub slots_per_chunk: u32,
    /// Exact number of chunks.
    pub chunk_count: u32,
    /// Used slots in the final chunk.
    pub final_chunk_used_slots: u32,
    /// Digest binding every layout field and slot order.
    pub digest: [u8; 32],
}
/// One exact packed-plaintext chunk in coefficient representation.
#[cfg(test)]
#[cfg_attr(test, derive(Clone))]
#[derive(PartialEq, Eq)]
pub struct ZkAmsT256PackedPlaintextV1 {
    /// Packed artifact version.
    pub version: u8,
    /// Digest of the sole release RNS-BGV profile.
    pub profile_digest: [u8; 32],
    /// Layout digest for the complete logical vector.
    pub layout_digest: [u8; 32],
    /// Zero-based chunk index.
    pub chunk_index: u32,
    /// Number of non-padding slots in this chunk.
    pub used_slots: u32,
    /// Exactly `N` canonical T256 polynomial coefficients.
    pub coefficients: Vec<[u8; 32]>,
    /// Digest binding header, coefficients, and padding semantics.
    pub digest: [u8; 32],
}
#[cfg(test)]
std::thread_local! {
    static PACKED_PLAINTEXT_ZEROIZED_DROPS_V1: std::cell::Cell<usize> = const {
        std::cell::Cell::new(0)
    };
}
#[cfg(test)]
fn packed_plaintext_zeroized_drop_count_v1() -> usize {
    PACKED_PLAINTEXT_ZEROIZED_DROPS_V1
        .try_with(std::cell::Cell::get)
        .unwrap_or(0)
}
#[cfg(test)]
impl Drop for ZkAmsT256PackedPlaintextV1 {
    fn drop(&mut self) {
        let coefficients = core::hint::black_box(&mut self.coefficients);
        #[cfg(test)]
        let owned_coefficients = !coefficients.is_empty();
        for coefficient in coefficients.iter_mut() {
            coefficient.fill(0);
        }
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
        #[cfg(test)]
        if owned_coefficients
            && coefficients
                .iter()
                .all(|coefficient| *coefficient == [0; 32])
        {
            let _ = PACKED_PLAINTEXT_ZEROIZED_DROPS_V1
                .try_with(|drops| drops.set(drops.get().saturating_add(1)));
        }
        let _ = core::hint::black_box(&mut *coefficients);
    }
}
#[cfg(test)]
impl fmt::Debug for ZkAmsT256PackedPlaintextV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ZkAmsT256PackedPlaintextV1")
            .field("version", &self.version)
            .field("profile_digest", &self.profile_digest)
            .field("layout_digest", &self.layout_digest)
            .field("chunk_index", &self.chunk_index)
            .field("used_slots", &self.used_slots)
            .field("coefficient_count", &self.coefficients.len())
            .field("digest", &self.digest)
            .finish()
    }
}
/// Direction of the exact slot permutation induced by a Galois automorphism.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum ZkAmsT256RotationDirectionV1 {
    /// `output[s] = input[(s + steps) mod 65_536]`.
    Forward = 1,
    /// `output[s] = input[(s - steps) mod 65_536]`.
    Inverse = 2,
}
impl ZkAmsT256RotationDirectionV1 {
    const fn tag(self) -> u8 {
        self as u8
    }
}
/// One canonical unique exponent in the binary Galois-key schedule.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ZkAmsT256GaloisKeyScheduleEntryV1 {
    /// Direction represented by this key.
    pub direction: ZkAmsT256RotationDirectionV1,
    /// Power-of-two slot step represented by this key.
    pub steps: u32,
    /// Exact odd exponent modulo `2N`.
    pub exponent: u32,
}
/// Frozen minimal key schedule from which every governed rotation is composed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ZkAmsT256GaloisKeyScheduleV1 {
    /// Schedule schema version.
    pub version: u8,
    /// Digest of the sole release RNS-BGV profile.
    pub profile_digest: [u8; 32],
    /// Frozen release ring degree.
    pub ring_degree: u32,
    /// Frozen release slot count.
    pub slot_count: u32,
    /// Generator of the cyclic slot subgroup modulo `2N`.
    pub generator: u32,
    /// Exactly 31 unique, canonically ordered exponents.
    pub entries: Vec<ZkAmsT256GaloisKeyScheduleEntryV1>,
    /// Digest binding the complete ordered schedule.
    pub digest: [u8; 32],
}
/// Exact profile-, layout-, chunk-, and direction-bound rotation request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ZkAmsT256RotationV1 {
    /// Rotation schema version.
    pub version: u8,
    /// Digest of the sole release RNS-BGV profile.
    pub profile_digest: [u8; 32],
    /// Digest of the complete packed-vector layout.
    pub layout_digest: [u8; 32],
    /// Zero-based chunk index.
    pub chunk_index: u32,
    /// Exact number of used slots in the chunk.
    pub used_slots: u32,
    /// Rotation amount, strictly less than the slot count.
    pub steps: u32,
    /// Explicit permutation direction.
    pub direction: ZkAmsT256RotationDirectionV1,
    /// Exact odd Galois exponent for the amount and direction.
    pub exponent: u32,
    /// Digest binding all rotation fields and the governed key schedule.
    pub digest: [u8; 32],
}
/// Evidence that coefficient and release-RNS automorphisms agree exactly.
#[cfg(test)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ZkAmsT256RotationCertificateV1 {
    /// Certificate schema version.
    pub version: u8,
    /// Digest of the sole release RNS-BGV profile.
    pub profile_digest: [u8; 32],
    /// Digest of the complete packed-vector layout.
    pub layout_digest: [u8; 32],
    /// Zero-based chunk index.
    pub chunk_index: u32,
    /// Exact number of used slots in the chunk.
    pub used_slots: u32,
    /// Digest of the exact rotation request.
    pub rotation_digest: [u8; 32],
    /// Digest of the canonical binary Galois-key schedule.
    pub galois_key_schedule_digest: [u8; 32],
    /// Digest of the input coefficient polynomial.
    pub input_packed_digest: [u8; 32],
    /// Digest of the coefficient-domain automorphism result.
    pub output_packed_digest: [u8; 32],
    /// Digest of the exact transformed release-RNS limbs.
    pub transformed_rns_digest: [u8; 32],
    /// Digest binding the entire checked certificate.
    pub digest: [u8; 32],
}
/// Immutable evidence identity for the exact release packing KAT.
///
/// The focused release test recomputes every positive artifact and the ordered adversarial
/// catalogue from the native implementation. Runtime readiness consumes this compact, profile-bound
/// identity instead of repeating a release-degree NTT on each admission attempt.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ZkAmsT256ReleasePackingCertificateV1 {
    /// Certificate schema version.
    pub version: u8,
    /// Digest of the sole release RNS-BGV profile.
    pub profile_digest: [u8; 32],
    /// Frozen release cyclotomic degree.
    pub ring_degree: u32,
    /// Frozen number of conjugate-pair T256 slots.
    pub slot_count: u32,
    /// Digest of the exact full-chunk packing layout exercised by the KAT.
    pub layout_digest: [u8; 32],
    /// Digest of the modulus-derived exponent and exact primitive `Fp2` root.
    pub root_digest: [u8; 32],
    /// Exact `X -> X^(p mod 2N)` exponent fixing the packed base-field image.
    pub subfield_conjugation_exponent: u32,
    /// Digest of the coefficient-level packed-subfield relation.
    pub subfield_relation_digest: [u8; 32],
    /// Digest of the exact inverse rotation request exercised by the KAT.
    pub rotation_digest: [u8; 32],
    /// Exact number of keys in the canonical binary Galois schedule.
    pub galois_key_count: u8,
    /// Digest of the complete ordered Galois-key schedule.
    pub galois_key_schedule_digest: [u8; 32],
    /// Digest of the exact release-degree packed input.
    pub packed_input_kat_digest: [u8; 32],
    /// Digest of the exact coefficient-domain rotated output.
    pub packed_output_kat_digest: [u8; 32],
    /// Digest of every transformed release-RNS limb.
    pub transformed_rns_kat_digest: [u8; 32],
    /// Digest of the native rotation certificate produced by the KAT.
    pub rotation_certificate_kat_digest: [u8; 32],
    /// Number of ordered negative cases absorbed into the negative KAT.
    pub negative_case_count: u16,
    /// Digest of the exact ordered negative-case labels and error classes.
    pub negative_kat_digest: [u8; 32],
    /// Digest binding every preceding field.
    pub digest: [u8; 32],
}
/// Return the immutable profile-bound identity of the release packing KAT.
pub fn zk_ams_t256_release_packing_certificate_v1()
-> Result<ZkAmsT256ReleasePackingCertificateV1, ZkAmsMkheErrorV1> {
    let profile = release_profile_v1();
    let evidence_profile_digest = release_packing_evidence_profile_digest_v1(&profile)?;
    let layout = zk_ams_t256_packing_layout_v1(
        u32::try_from(ZK_AMS_MKHE_RELEASE_SLOT_COUNT_V1)
            .map_err(|_| ZkAmsMkheErrorV1::InvalidProfile)?,
    )?;
    let rotation =
        zk_ams_t256_rotation_v1(layout, 0, 0xA55A, ZkAmsT256RotationDirectionV1::Inverse)?;
    let schedule = zk_ams_t256_galois_key_schedule_v1()?;
    let root_exponent = release_root_exponent_be_v1()?;
    let root = release_root()?;
    let root_digest = release_root_identity_digest(root, &root_exponent)?;
    let subfield_conjugation_exponent = zk_ams_t256_packed_subfield_conjugation_exponent_v1()?;
    let mut certificate = ZkAmsT256ReleasePackingCertificateV1 {
        version: PACKING_VERSION_V1,
        profile_digest: evidence_profile_digest,
        ring_degree: u32::try_from(ZK_AMS_MKHE_RELEASE_RING_DEGREE_V1)
            .map_err(|_| ZkAmsMkheErrorV1::InvalidProfile)?,
        slot_count: u32::try_from(ZK_AMS_MKHE_RELEASE_SLOT_COUNT_V1)
            .map_err(|_| ZkAmsMkheErrorV1::InvalidProfile)?,
        layout_digest: layout.digest,
        root_digest,
        subfield_conjugation_exponent,
        subfield_relation_digest: packed_subfield_relation_digest(
            evidence_profile_digest,
            root_digest,
            subfield_conjugation_exponent,
        )?,
        rotation_digest: rotation.digest,
        galois_key_count: u8::try_from(ZK_AMS_T256_GALOIS_KEY_COUNT_V1)
            .map_err(|_| ZkAmsMkheErrorV1::InvalidProfile)?,
        galois_key_schedule_digest: schedule.digest,
        packed_input_kat_digest: ZK_AMS_T256_RELEASE_PACKED_INPUT_KAT_DIGEST_V1,
        packed_output_kat_digest: ZK_AMS_T256_RELEASE_PACKED_OUTPUT_KAT_DIGEST_V1,
        transformed_rns_kat_digest: ZK_AMS_T256_RELEASE_TRANSFORMED_RNS_KAT_DIGEST_V1,
        rotation_certificate_kat_digest: ZK_AMS_T256_RELEASE_ROTATION_CERTIFICATE_KAT_DIGEST_V1,
        negative_case_count: ZK_AMS_T256_RELEASE_PACKING_NEGATIVE_CASE_COUNT_V1,
        negative_kat_digest: ZK_AMS_T256_RELEASE_PACKING_NEGATIVE_KAT_DIGEST_V1,
        digest: [0; 32],
    };
    certificate.digest = release_packing_certificate_digest(certificate);
    validate_release_packing_certificate(certificate)?;
    Ok(certificate)
}
/// Return the exact Galois exponent whose fixed subspace is the canonical
/// 65,536-slot T256 plaintext image.
///
/// The frozen P-256 base-field modulus is `-1 mod 2N`. Consequently its
/// Frobenius action on the primitive `2N`-th root is conjugation/inversion,
/// represented by `X -> X^(2N-1)` in `Fp[X]/(X^N+1)`.
pub fn zk_ams_t256_packed_subfield_conjugation_exponent_v1() -> Result<u32, ZkAmsMkheErrorV1> {
    let twice_degree = ZK_AMS_MKHE_RELEASE_RING_DEGREE_V1
        .checked_mul(2)
        .ok_or(ZkAmsMkheErrorV1::InvalidProfile)?;
    if !twice_degree.is_power_of_two() {
        return Err(ZkAmsMkheErrorV1::InvalidProfile);
    }
    let twice_degree_u64 =
        u64::try_from(twice_degree).map_err(|_| ZkAmsMkheErrorV1::InvalidProfile)?;
    let low = u64::from_be_bytes(
        VEGA_T256_SCALAR_MODULUS_BE_V1[24..]
            .try_into()
            .map_err(|_| ZkAmsMkheErrorV1::InvalidProfile)?,
    );
    let remainder =
        usize::try_from(low % twice_degree_u64).map_err(|_| ZkAmsMkheErrorV1::InvalidProfile)?;
    let exponent = twice_degree
        .checked_sub(1)
        .ok_or(ZkAmsMkheErrorV1::InvalidProfile)?;
    if remainder != exponent || exponent.is_multiple_of(2) {
        return Err(ZkAmsMkheErrorV1::InvalidProfile);
    }
    u32::try_from(exponent).map_err(|_| ZkAmsMkheErrorV1::InvalidProfile)
}
/// Construct the sole canonical chunking layout for a nonempty logical vector.
pub fn zk_ams_t256_packing_layout_v1(
    logical_value_count: u32,
) -> Result<ZkAmsT256PackingLayoutV1, ZkAmsMkheErrorV1> {
    if logical_value_count == 0 {
        return Err(ZkAmsMkheErrorV1::InvalidPolynomial);
    }
    if logical_value_count > ZK_AMS_T256_MAX_LOGICAL_VALUES_V1 {
        return Err(ZkAmsMkheErrorV1::ResourceCeilingExceeded);
    }
    let slots = u32::try_from(ZK_AMS_MKHE_RELEASE_SLOT_COUNT_V1)
        .map_err(|_| ZkAmsMkheErrorV1::InvalidProfile)?;
    let chunk_count = logical_value_count
        .checked_add(slots - 1)
        .and_then(|value| value.checked_div(slots))
        .ok_or(ZkAmsMkheErrorV1::ResourceCeilingExceeded)?;
    let final_chunk_used_slots = logical_value_count
        .checked_sub((chunk_count - 1) * slots)
        .ok_or(ZkAmsMkheErrorV1::InvalidPolynomial)?;
    let mut layout = ZkAmsT256PackingLayoutV1 {
        version: PACKING_VERSION_V1,
        profile_digest: release_profile_v1().digest()?,
        logical_value_count,
        slots_per_chunk: slots,
        chunk_count,
        final_chunk_used_slots,
        digest: [0; 32],
    };
    layout.digest = packing_layout_digest(layout)?;
    validate_layout(layout)?;
    Ok(layout)
}
/// Return the exact odd Galois exponent implementing a forward cyclic rotation.
#[cfg(test)]
pub fn zk_ams_t256_rotation_exponent_v1(steps: u32) -> Result<u32, ZkAmsMkheErrorV1> {
    zk_ams_t256_rotation_exponent_for_direction_v1(steps, ZkAmsT256RotationDirectionV1::Forward)
}
/// Return the exact odd Galois exponent for an explicit rotation direction.
pub fn zk_ams_t256_rotation_exponent_for_direction_v1(
    steps: u32,
    direction: ZkAmsT256RotationDirectionV1,
) -> Result<u32, ZkAmsMkheErrorV1> {
    let slots = u32::try_from(ZK_AMS_MKHE_RELEASE_SLOT_COUNT_V1)
        .map_err(|_| ZkAmsMkheErrorV1::InvalidProfile)?;
    if steps >= slots {
        return Err(ZkAmsMkheErrorV1::InvalidKeyMaterial);
    }
    let exponent_steps = match direction {
        ZkAmsT256RotationDirectionV1::Forward => steps,
        ZkAmsT256RotationDirectionV1::Inverse => (slots - steps) % slots,
    };
    let generator =
        u64::try_from(SLOT_GALOIS_GENERATOR_V1).map_err(|_| ZkAmsMkheErrorV1::InvalidProfile)?;
    let cyclotomic_order = u64::try_from(2 * ZK_AMS_MKHE_RELEASE_RING_DEGREE_V1)
        .map_err(|_| ZkAmsMkheErrorV1::InvalidProfile)?;
    u32::try_from(iroha_fhe::modular::mod_pow_u64(
        generator,
        u64::from(exponent_steps),
        cyclotomic_order,
    ))
    .map_err(|_| ZkAmsMkheErrorV1::InvalidProfile)
}
/// Construct the exact minimal binary Galois-key schedule for all rotations.
pub fn zk_ams_t256_galois_key_schedule_v1() -> Result<ZkAmsT256GaloisKeyScheduleV1, ZkAmsMkheErrorV1>
{
    let mut entries = Vec::with_capacity(ZK_AMS_T256_GALOIS_KEY_COUNT_V1);
    for bit in 0..GALOIS_KEY_SCHEDULE_BITS_V1 {
        let steps = 1_u32
            .checked_shl(bit)
            .ok_or(ZkAmsMkheErrorV1::InvalidProfile)?;
        entries.push(ZkAmsT256GaloisKeyScheduleEntryV1 {
            direction: ZkAmsT256RotationDirectionV1::Forward,
            steps,
            exponent: zk_ams_t256_rotation_exponent_for_direction_v1(
                steps,
                ZkAmsT256RotationDirectionV1::Forward,
            )?,
        });
    }
    // The half-turn is self-inverse, so a second key for inverse 2^15 would
    // duplicate the forward exponent and is deliberately absent.
    for bit in 0..GALOIS_KEY_SCHEDULE_BITS_V1 - 1 {
        let steps = 1_u32
            .checked_shl(bit)
            .ok_or(ZkAmsMkheErrorV1::InvalidProfile)?;
        entries.push(ZkAmsT256GaloisKeyScheduleEntryV1 {
            direction: ZkAmsT256RotationDirectionV1::Inverse,
            steps,
            exponent: zk_ams_t256_rotation_exponent_for_direction_v1(
                steps,
                ZkAmsT256RotationDirectionV1::Inverse,
            )?,
        });
    }
    let mut schedule = ZkAmsT256GaloisKeyScheduleV1 {
        version: PACKING_VERSION_V1,
        profile_digest: release_profile_v1().digest()?,
        ring_degree: u32::try_from(ZK_AMS_MKHE_RELEASE_RING_DEGREE_V1)
            .map_err(|_| ZkAmsMkheErrorV1::InvalidProfile)?,
        slot_count: u32::try_from(ZK_AMS_MKHE_RELEASE_SLOT_COUNT_V1)
            .map_err(|_| ZkAmsMkheErrorV1::InvalidProfile)?,
        generator: u32::try_from(SLOT_GALOIS_GENERATOR_V1)
            .map_err(|_| ZkAmsMkheErrorV1::InvalidProfile)?,
        entries,
        digest: [0; 32],
    };
    schedule.digest = galois_key_schedule_digest(&schedule)?;
    validate_galois_key_schedule(&schedule)?;
    Ok(schedule)
}
/// Validate a caller-supplied schedule and reject missing, duplicate, or reordered keys.
#[cfg(test)]
pub fn validate_zk_ams_t256_galois_key_schedule_v1(
    schedule: &ZkAmsT256GaloisKeyScheduleV1,
) -> Result<(), ZkAmsMkheErrorV1> {
    validate_galois_key_schedule(schedule)
}
/// Validate the exact ordered exponent list provisioned by a key ceremony.
#[cfg(test)]
pub fn validate_zk_ams_t256_galois_key_exponents_v1(
    schedule: &ZkAmsT256GaloisKeyScheduleV1,
    provisioned_exponents: &[u32],
) -> Result<(), ZkAmsMkheErrorV1> {
    validate_galois_key_schedule(schedule)?;
    if provisioned_exponents.len() != ZK_AMS_T256_GALOIS_KEY_COUNT_V1
        || schedule
            .entries
            .iter()
            .zip(provisioned_exponents)
            .any(|(entry, exponent)| entry.exponent != *exponent)
    {
        return Err(ZkAmsMkheErrorV1::MissingEvaluatedKey);
    }
    Ok(())
}
/// Construct a canonical rotation request for one exact packed chunk.
pub fn zk_ams_t256_rotation_v1(
    layout: ZkAmsT256PackingLayoutV1,
    chunk_index: u32,
    steps: u32,
    direction: ZkAmsT256RotationDirectionV1,
) -> Result<ZkAmsT256RotationV1, ZkAmsMkheErrorV1> {
    validate_layout(layout)?;
    let mut rotation = ZkAmsT256RotationV1 {
        version: PACKING_VERSION_V1,
        profile_digest: layout.profile_digest,
        layout_digest: layout.digest,
        chunk_index,
        used_slots: used_slots_for_chunk(layout, chunk_index)?,
        steps,
        direction,
        exponent: zk_ams_t256_rotation_exponent_for_direction_v1(steps, direction)?,
        digest: [0; 32],
    };
    rotation.digest = rotation_digest(rotation)?;
    validate_rotation(layout, rotation)?;
    Ok(rotation)
}
/// Return the exact key exponents that compose a canonical rotation request.
#[cfg(test)]
pub fn zk_ams_t256_rotation_key_plan_v1(
    layout: ZkAmsT256PackingLayoutV1,
    rotation: ZkAmsT256RotationV1,
    schedule: &ZkAmsT256GaloisKeyScheduleV1,
) -> Result<Vec<u32>, ZkAmsMkheErrorV1> {
    validate_layout(layout)?;
    validate_rotation(layout, rotation)?;
    validate_galois_key_schedule(schedule)?;
    if schedule.profile_digest != layout.profile_digest {
        return Err(ZkAmsMkheErrorV1::InvalidKeyMaterial);
    }
    let mut plan = Vec::with_capacity(GALOIS_KEY_SCHEDULE_BITS_V1 as usize);
    for bit in 0..GALOIS_KEY_SCHEDULE_BITS_V1 {
        let bit_steps = 1_u32
            .checked_shl(bit)
            .ok_or(ZkAmsMkheErrorV1::InvalidProfile)?;
        if rotation.steps & bit_steps == 0 {
            continue;
        }
        let entry_direction = if rotation.direction == ZkAmsT256RotationDirectionV1::Inverse
            && bit + 1 == GALOIS_KEY_SCHEDULE_BITS_V1
        {
            ZkAmsT256RotationDirectionV1::Forward
        } else {
            rotation.direction
        };
        let entry = schedule
            .entries
            .iter()
            .find(|entry| entry.steps == bit_steps && entry.direction == entry_direction)
            .ok_or(ZkAmsMkheErrorV1::MissingEvaluatedKey)?;
        plan.push(entry.exponent);
    }
    let modulus = 2 * ZK_AMS_MKHE_RELEASE_RING_DEGREE_V1;
    let composed = plan.iter().try_fold(1_usize, |accumulator, exponent| {
        let exponent =
            usize::try_from(*exponent).map_err(|_| ZkAmsMkheErrorV1::InvalidKeyMaterial)?;
        Ok::<_, ZkAmsMkheErrorV1>(
            ((accumulator as u128 * exponent as u128) % modulus as u128) as usize,
        )
    })?;
    if composed
        != usize::try_from(rotation.exponent).map_err(|_| ZkAmsMkheErrorV1::InvalidKeyMaterial)?
    {
        return Err(ZkAmsMkheErrorV1::InvalidKeyMaterial);
    }
    Ok(plan)
}
/// Encode exactly one fixed-width chunk; nonzero unused slots are rejected.
#[cfg(test)]
pub fn encode_zk_ams_t256_packed_plaintext_v1(
    layout: ZkAmsT256PackingLayoutV1,
    chunk_index: u32,
    slots: &[[u8; 32]],
) -> Result<ZkAmsT256PackedPlaintextV1, ZkAmsMkheErrorV1> {
    validate_layout(layout)?;
    if slots.len() != ZK_AMS_MKHE_RELEASE_SLOT_COUNT_V1 || chunk_index >= layout.chunk_count {
        return Err(ZkAmsMkheErrorV1::InvalidPolynomial);
    }
    let used_slots = used_slots_for_chunk(layout, chunk_index)?;
    if slots[used_slots as usize..]
        .iter()
        .any(|slot| *slot != [0; 32])
    {
        return Err(ZkAmsMkheErrorV1::InvalidPolynomial);
    }
    let scalars = slots
        .iter()
        .map(|bytes| {
            Scalar::from_be_bytes_exact(*bytes).map_err(|_| ZkAmsMkheErrorV1::InvalidPolynomial)
        })
        .collect::<Result<Vec<_>, _>>()?;
    let coefficients = encode_coefficients(&scalars, ZK_AMS_MKHE_RELEASE_RING_DEGREE_V1)?
        .into_iter()
        .map(Scalar::to_be_bytes)
        .collect();
    let mut packed = ZkAmsT256PackedPlaintextV1 {
        version: PACKING_VERSION_V1,
        profile_digest: layout.profile_digest,
        layout_digest: layout.digest,
        chunk_index,
        used_slots,
        coefficients,
        digest: [0; 32],
    };
    packed.digest = packed_plaintext_digest(&packed)?;
    validate_packed(layout, &packed)?;
    Ok(packed)
}
/// Decode one exact chunk and reject non-subfield values or nonzero padding.
#[cfg(test)]
pub fn decode_zk_ams_t256_packed_plaintext_v1(
    layout: ZkAmsT256PackingLayoutV1,
    packed: &ZkAmsT256PackedPlaintextV1,
) -> Result<Vec<[u8; 32]>, ZkAmsMkheErrorV1> {
    validate_layout(layout)?;
    validate_packed(layout, packed)?;
    let mut decoded = Vec::new();
    decoded
        .try_reserve_exact(ZK_AMS_MKHE_RELEASE_SLOT_COUNT_V1)
        .map_err(|_| ZkAmsMkheErrorV1::ResourceCeilingExceeded)?;
    decoded.resize(ZK_AMS_MKHE_RELEASE_SLOT_COUNT_V1, [0; 32]);
    let mut workspace = T256PackedPlaintextDecodeWorkspaceV1::try_new_v1()?;
    let mut next_slot = 0_usize;
    visit_validated_packed_plaintext_used_slots_with_workspace_v1(
        packed,
        &mut workspace,
        |value| {
            let destination = decoded
                .get_mut(next_slot)
                .ok_or(ZkAmsMkheErrorV1::InvalidPolynomial)?;
            destination.copy_from_slice(value);
            next_slot = next_slot
                .checked_add(1)
                .ok_or(ZkAmsMkheErrorV1::ResourceCeilingExceeded)?;
            Ok(())
        },
    )?;
    if next_slot != packed.used_slots as usize {
        return Err(ZkAmsMkheErrorV1::InvalidPolynomial);
    }
    Ok(decoded)
}
/// Decode one validated chunk through a caller-owned reusable workspace.
#[cfg(test)]
pub(super) fn visit_zk_ams_t256_packed_plaintext_used_slots_with_workspace_v1(
    layout: ZkAmsT256PackingLayoutV1,
    packed: &ZkAmsT256PackedPlaintextV1,
    workspace: &mut T256PackedPlaintextDecodeWorkspaceV1,
    visit: impl FnMut(&[u8; 32]) -> Result<(), ZkAmsMkheErrorV1>,
) -> Result<(), ZkAmsMkheErrorV1> {
    validate_layout(layout)?;
    validate_packed(layout, packed)?;
    visit_validated_packed_plaintext_used_slots_with_workspace_v1(packed, workspace, visit)
}

/// Rehydrate one authenticated-source coefficient owner into the canonical
/// packed-chunk metadata and stream its used logical slots.
///
/// This sibling-private adapter exists so a confidential source snapshot can
/// reuse the sole packing decoder without cloning its coefficient vector or
/// exposing the private packed-artifact digest constructor. The temporary
/// packed owner erases every coefficient on all return and unwind paths.
#[cfg(test)]
pub(super) fn visit_rehydrated_t256_coefficients_used_slots_with_workspace_v1(
    layout: ZkAmsT256PackingLayoutV1,
    chunk_index: u32,
    coefficients: Vec<[u8; 32]>,
    workspace: &mut T256PackedPlaintextDecodeWorkspaceV1,
    visit: impl FnMut(&[u8; 32]) -> Result<(), ZkAmsMkheErrorV1>,
) -> Result<(), ZkAmsMkheErrorV1> {
    let mut packed = ZkAmsT256PackedPlaintextV1 {
        version: PACKING_VERSION_V1,
        profile_digest: layout.profile_digest,
        layout_digest: layout.digest,
        chunk_index,
        used_slots: 0,
        coefficients,
        digest: [0; 32],
    };
    validate_layout(layout)?;
    packed.used_slots = used_slots_for_chunk(layout, chunk_index)?;
    packed.digest = packed_plaintext_digest(&packed)?;
    visit_zk_ams_t256_packed_plaintext_used_slots_with_workspace_v1(
        layout, &packed, workspace, visit,
    )
}

#[cfg(test)]
fn visit_validated_packed_plaintext_used_slots_with_workspace_v1(
    packed: &ZkAmsT256PackedPlaintextV1,
    workspace: &mut T256PackedPlaintextDecodeWorkspaceV1,
    mut visit: impl FnMut(&[u8; 32]) -> Result<(), ZkAmsMkheErrorV1>,
) -> Result<(), ZkAmsMkheErrorV1> {
    let degree = ZK_AMS_MKHE_RELEASE_RING_DEGREE_V1;
    if workspace.0.0.len() != degree {
        return Err(ZkAmsMkheErrorV1::InvalidPolynomial);
    }
    let evaluations = ClearingPackingFp2BorrowV1(&mut workspace.0.0);
    let root = root_for_degree(degree)?;
    let omega = root.mul(root);
    let mut twist = T256Fp2::one();
    for (evaluation, bytes) in evaluations.0.iter_mut().zip(&packed.coefficients) {
        let coefficient =
            Scalar::from_be_bytes_exact(*bytes).map_err(|_| ZkAmsMkheErrorV1::InvalidPolynomial)?;
        *evaluation = T256Fp2::from_base(coefficient).mul(twist);
        twist = twist.mul(root);
    }
    cyclic_ntt(evaluations.0, omega);
    let used_slots = usize::try_from(packed.used_slots)
        .map_err(|_| ZkAmsMkheErrorV1::ResourceCeilingExceeded)?;
    for slot in 0..degree / 2 {
        let index = slot_root_index(degree, slot)?;
        let conjugate = degree - 1 - index;
        let value = &evaluations.0[index];
        if !value.c1.is_zero() || &evaluations.0[conjugate] != value {
            return Err(ZkAmsMkheErrorV1::InvalidPolynomial);
        }
        if slot >= used_slots && !value.c0.is_zero() {
            return Err(ZkAmsMkheErrorV1::InvalidPolynomial);
        }
    }
    let mut encoded = ZeroizingPackingScalarBytesV1::new();
    for slot in 0..used_slots {
        let index = slot_root_index(degree, slot)?;
        encoded.encode_from(&evaluations.0[index].c0);
        visit(encoded.as_array())?;
    }
    Ok(())
}
/// Apply the exact slot permutation as an independent plaintext oracle.
///
/// This helper exists to check the native coefficient/RNS path. Ciphertext
/// rotation never calls it and never substitutes cleartext evaluation.
#[cfg(test)]
pub fn permute_zk_ams_t256_slots_v1(
    layout: ZkAmsT256PackingLayoutV1,
    rotation: ZkAmsT256RotationV1,
    slots: &[[u8; 32]],
) -> Result<Vec<[u8; 32]>, ZkAmsMkheErrorV1> {
    validate_layout(layout)?;
    validate_rotation(layout, rotation)?;
    if slots.len() != ZK_AMS_MKHE_RELEASE_SLOT_COUNT_V1
        || slots
            .iter()
            .any(|value| Scalar::from_be_bytes_exact(*value).is_err())
        || slots[rotation.used_slots as usize..]
            .iter()
            .any(|value| *value != [0; 32])
    {
        return Err(ZkAmsMkheErrorV1::InvalidPolynomial);
    }
    reject_partial_chunk_rotation(rotation)?;
    let slot_count = ZK_AMS_MKHE_RELEASE_SLOT_COUNT_V1;
    let steps =
        usize::try_from(rotation.steps).map_err(|_| ZkAmsMkheErrorV1::InvalidKeyMaterial)?;
    let mut output = vec![[0_u8; 32]; slot_count];
    for (destination, value) in output.iter_mut().enumerate() {
        let source = match rotation.direction {
            ZkAmsT256RotationDirectionV1::Forward => (destination + steps) % slot_count,
            ZkAmsT256RotationDirectionV1::Inverse => {
                (destination + slot_count - steps) % slot_count
            }
        };
        *value = slots[source];
    }
    Ok(output)
}
/// Apply a rotation directly to canonical T256 coefficients without decoding slots.
#[cfg(test)]
pub fn rotate_zk_ams_t256_packed_plaintext_v1(
    layout: ZkAmsT256PackingLayoutV1,
    packed: &ZkAmsT256PackedPlaintextV1,
    rotation: ZkAmsT256RotationV1,
) -> Result<ZkAmsT256PackedPlaintextV1, ZkAmsMkheErrorV1> {
    validate_layout(layout)?;
    validate_packed(layout, packed)?;
    validate_rotation(layout, rotation)?;
    if packed.profile_digest != rotation.profile_digest
        || packed.layout_digest != rotation.layout_digest
        || packed.chunk_index != rotation.chunk_index
        || packed.used_slots != rotation.used_slots
    {
        return Err(ZkAmsMkheErrorV1::InvalidPolynomial);
    }
    reject_partial_chunk_rotation(rotation)?;
    let coefficients = packed
        .coefficients
        .iter()
        .map(|value| {
            Scalar::from_be_bytes_exact(*value).map_err(|_| ZkAmsMkheErrorV1::InvalidPolynomial)
        })
        .collect::<Result<Vec<_>, _>>()?;
    let coefficients = automorphism_coefficients(
        &coefficients,
        usize::try_from(rotation.exponent).map_err(|_| ZkAmsMkheErrorV1::InvalidKeyMaterial)?,
    )?
    .into_iter()
    .map(Scalar::to_be_bytes)
    .collect();
    let mut output = ZkAmsT256PackedPlaintextV1 {
        version: PACKING_VERSION_V1,
        profile_digest: packed.profile_digest,
        layout_digest: packed.layout_digest,
        chunk_index: packed.chunk_index,
        used_slots: packed.used_slots,
        coefficients,
        digest: [0; 32],
    };
    output.digest = packed_plaintext_digest(&output)?;
    validate_packed(layout, &output)?;
    Ok(output)
}
/// Verify limb-for-limb agreement between T256 and release-RNS automorphisms.
#[cfg(test)]
pub fn zk_ams_t256_rotation_certificate_v1(
    layout: ZkAmsT256PackingLayoutV1,
    packed: &ZkAmsT256PackedPlaintextV1,
    rotation: ZkAmsT256RotationV1,
) -> Result<ZkAmsT256RotationCertificateV1, ZkAmsMkheErrorV1> {
    validate_layout(layout)?;
    validate_packed(layout, packed)?;
    validate_rotation(layout, rotation)?;
    let schedule = zk_ams_t256_galois_key_schedule_v1()?;
    let _key_plan = zk_ams_t256_rotation_key_plan_v1(layout, rotation, &schedule)?;
    let profile = release_profile_v1();
    check_rotation_workspace(&profile)?;
    let transformed = rotate_zk_ams_t256_packed_plaintext_v1(layout, packed, rotation)?;
    let source_rns = packed_plaintext_to_rns_v1(layout, packed)?;
    let expected_rns = source_rns.automorphism(
        usize::try_from(rotation.exponent).map_err(|_| ZkAmsMkheErrorV1::InvalidKeyMaterial)?,
        &profile,
    )?;
    drop(source_rns);
    let transformed_rns = packed_plaintext_to_rns_v1(layout, &transformed)?;
    if transformed_rns != expected_rns {
        return Err(ZkAmsMkheErrorV1::InvalidPolynomial);
    }
    let transformed_rns_digest = rns_polynomial_digest(&profile, &transformed_rns)?;
    let mut certificate = ZkAmsT256RotationCertificateV1 {
        version: PACKING_VERSION_V1,
        profile_digest: layout.profile_digest,
        layout_digest: layout.digest,
        chunk_index: packed.chunk_index,
        used_slots: packed.used_slots,
        rotation_digest: rotation.digest,
        galois_key_schedule_digest: schedule.digest,
        input_packed_digest: packed.digest,
        output_packed_digest: transformed.digest,
        transformed_rns_digest,
        digest: [0; 32],
    };
    certificate.digest = rotation_certificate_digest(certificate);
    validate_rotation_certificate(layout, packed, rotation, &schedule, certificate)?;
    Ok(certificate)
}
#[cfg(test)]
pub(super) fn packed_plaintext_to_rns_v1(
    layout: ZkAmsT256PackingLayoutV1,
    packed: &ZkAmsT256PackedPlaintextV1,
) -> Result<RnsPolynomial, ZkAmsMkheErrorV1> {
    validate_layout(layout)?;
    validate_packed(layout, packed)?;
    RnsPolynomial::from_t256_plaintext_bytes(&release_profile_v1(), &packed.coefficients)
}
/// Test-only recomputation of the exact release-RNS image of one canonical packed chunk and
/// return its limb-major digest.
///
/// This is a native equality check, not a proof verifier: the caller supplies
/// the plaintext coefficients, and this function derives every residue under
/// all release moduli after rechecking the packed artifact.  It is useful to
/// bind an in-process verified capability to the real 38-limb representation, but cannot replace
/// the missing RNS-Link carry/quotient proof on untrusted wire bytes.
#[cfg(test)]
pub(super) fn packed_plaintext_rns_binding_digest_v1(
    layout: ZkAmsT256PackingLayoutV1,
    packed: &ZkAmsT256PackedPlaintextV1,
) -> Result<[u8; 32], ZkAmsMkheErrorV1> {
    let profile = release_profile_v1();
    let polynomial = ZeroizingPackedRnsBindingV1(packed_plaintext_to_rns_v1(layout, packed)?);
    rns_polynomial_digest(&profile, &polynomial.0)
}
fn validate_layout(layout: ZkAmsT256PackingLayoutV1) -> Result<(), ZkAmsMkheErrorV1> {
    if layout.logical_value_count > ZK_AMS_T256_MAX_LOGICAL_VALUES_V1 {
        return Err(ZkAmsMkheErrorV1::ResourceCeilingExceeded);
    }
    if layout.profile_digest != release_profile_v1().digest()? {
        return Err(ZkAmsMkheErrorV1::InvalidProfile);
    }
    if layout.version != PACKING_VERSION_V1
        || layout.logical_value_count == 0
        || layout.slots_per_chunk != ZK_AMS_MKHE_RELEASE_SLOT_COUNT_V1 as u32
        || layout.chunk_count == 0
        || layout.final_chunk_used_slots == 0
        || layout.final_chunk_used_slots > layout.slots_per_chunk
        || layout
            .chunk_count
            .checked_sub(1)
            .and_then(|chunks| chunks.checked_mul(layout.slots_per_chunk))
            .and_then(|prefix| prefix.checked_add(layout.final_chunk_used_slots))
            != Some(layout.logical_value_count)
        || layout.digest == [0; 32]
        || layout.digest != packing_layout_digest(layout)?
    {
        return Err(ZkAmsMkheErrorV1::InvalidPolynomial);
    }
    Ok(())
}
fn used_slots_for_chunk(
    layout: ZkAmsT256PackingLayoutV1,
    chunk_index: u32,
) -> Result<u32, ZkAmsMkheErrorV1> {
    if chunk_index >= layout.chunk_count {
        return Err(ZkAmsMkheErrorV1::InvalidPolynomial);
    }
    Ok(if chunk_index + 1 == layout.chunk_count {
        layout.final_chunk_used_slots
    } else {
        layout.slots_per_chunk
    })
}
#[cfg(test)]
fn validate_packed(
    layout: ZkAmsT256PackingLayoutV1,
    packed: &ZkAmsT256PackedPlaintextV1,
) -> Result<(), ZkAmsMkheErrorV1> {
    if packed.version != PACKING_VERSION_V1
        || packed.profile_digest != layout.profile_digest
        || packed.layout_digest != layout.digest
        || packed.chunk_index >= layout.chunk_count
        || packed.used_slots != used_slots_for_chunk(layout, packed.chunk_index)?
        || packed.coefficients.len() != ZK_AMS_MKHE_RELEASE_RING_DEGREE_V1
        || packed
            .coefficients
            .iter()
            .any(|bytes| Scalar::from_be_bytes_exact(*bytes).is_err())
        || packed.digest == [0; 32]
        || packed.digest != packed_plaintext_digest(packed)?
    {
        return Err(ZkAmsMkheErrorV1::InvalidPolynomial);
    }
    validate_packed_subfield_coefficients(&packed.coefficients)
}
#[cfg(test)]
fn validate_packed_subfield_coefficients(
    coefficients: &[[u8; 32]],
) -> Result<(), ZkAmsMkheErrorV1> {
    let degree = ZK_AMS_MKHE_RELEASE_RING_DEGREE_V1;
    let expected_exponent = degree
        .checked_mul(2)
        .and_then(|twice_degree| twice_degree.checked_sub(1))
        .and_then(|exponent| u32::try_from(exponent).ok())
        .ok_or(ZkAmsMkheErrorV1::InvalidProfile)?;
    if coefficients.len() != degree
        || zk_ams_t256_packed_subfield_conjugation_exponent_v1()? != expected_exponent
    {
        return Err(ZkAmsMkheErrorV1::InvalidPolynomial);
    }
    // For `sigma_{-1}: X -> X^-1`, coefficient zero is fixed and every
    // nonzero coefficient obeys `m[N-i] = -m[i]`. Scanning only through N/2
    // checks every pair exactly once; the midpoint must therefore be zero.
    for index in 1..=degree / 2 {
        let left = Scalar::from_be_bytes_exact(coefficients[index])
            .map_err(|_| ZkAmsMkheErrorV1::InvalidPolynomial)?;
        let right = Scalar::from_be_bytes_exact(coefficients[degree - index])
            .map_err(|_| ZkAmsMkheErrorV1::InvalidPolynomial)?;
        if right != -left {
            return Err(ZkAmsMkheErrorV1::InvalidPolynomial);
        }
    }
    Ok(())
}
fn packed_subfield_relation_digest(
    profile_digest: [u8; 32],
    root_digest: [u8; 32],
    exponent: u32,
) -> Result<[u8; 32], ZkAmsMkheErrorV1> {
    if profile_digest == [0; 32]
        || root_digest == [0; 32]
        || exponent != zk_ams_t256_packed_subfield_conjugation_exponent_v1()?
    {
        return Err(ZkAmsMkheErrorV1::InvalidProfile);
    }
    let mut hash = super::native_outer_identity_v1(
        super::NativeOuterIdentityRoleV1::Parameter,
        PACKED_SUBFIELD_DOMAIN_V1,
        7,
    );
    hash.push_field(&[PACKING_VERSION_V1])
        .expect("fixed bounded MKHE identity field");
    hash.push_field(&profile_digest)
        .expect("fixed bounded MKHE identity field");
    hash.push_field(&VEGA_T256_SCALAR_MODULUS_BE_V1)
        .expect("fixed bounded MKHE identity field");
    hash.push_field(
        &u32::try_from(ZK_AMS_MKHE_RELEASE_RING_DEGREE_V1)
            .map_err(|_| ZkAmsMkheErrorV1::InvalidProfile)?
            .to_be_bytes(),
    )
    .expect("fixed bounded MKHE identity field");
    hash.push_field(&exponent.to_be_bytes())
        .expect("fixed bounded MKHE identity field");
    hash.push_field(&root_digest)
        .expect("fixed bounded MKHE identity field");
    hash.push_field(PACKED_SUBFIELD_RELATION_V1)
        .expect("fixed bounded MKHE identity field");
    Ok(*hash
        .finish()
        .expect("exact MKHE outer identity field count")
        .as_bytes())
}
fn packing_layout_digest(layout: ZkAmsT256PackingLayoutV1) -> Result<[u8; 32], ZkAmsMkheErrorV1> {
    let mut hash = super::native_outer_identity_v1(
        super::NativeOuterIdentityRoleV1::Parameter,
        PACKING_LAYOUT_DOMAIN_V1,
        7,
    );
    hash.push_field(&[layout.version])
        .expect("fixed bounded MKHE identity field");
    hash.push_field(&layout.profile_digest)
        .expect("fixed bounded MKHE identity field");
    hash.push_field(&layout.logical_value_count.to_be_bytes())
        .expect("fixed bounded MKHE identity field");
    hash.push_field(&layout.slots_per_chunk.to_be_bytes())
        .expect("fixed bounded MKHE identity field");
    hash.push_field(&layout.chunk_count.to_be_bytes())
        .expect("fixed bounded MKHE identity field");
    hash.push_field(&layout.final_chunk_used_slots.to_be_bytes())
        .expect("fixed bounded MKHE identity field");
    hash.push_field(
        &u32::try_from(SLOT_GALOIS_GENERATOR_V1)
            .map_err(|_| ZkAmsMkheErrorV1::InvalidProfile)?
            .to_be_bytes(),
    )
    .expect("fixed bounded MKHE identity field");
    Ok(*hash
        .finish()
        .expect("exact MKHE outer identity field count")
        .as_bytes())
}
#[cfg(test)]
fn packed_plaintext_digest(
    packed: &ZkAmsT256PackedPlaintextV1,
) -> Result<[u8; 32], ZkAmsMkheErrorV1> {
    if packed.coefficients.len() != ZK_AMS_MKHE_RELEASE_RING_DEGREE_V1 {
        return Err(ZkAmsMkheErrorV1::InvalidPolynomial);
    }
    let mut hash = Keccak256::new();
    hash.update(PACKED_PLAINTEXT_DOMAIN_V1);
    hash.update(&[packed.version]);
    hash.update(&packed.profile_digest);
    hash.update(&packed.layout_digest);
    hash.update(&packed.chunk_index.to_be_bytes());
    hash.update(&packed.used_slots.to_be_bytes());
    hash.update(
        &u32::try_from(packed.coefficients.len())
            .map_err(|_| ZkAmsMkheErrorV1::ResourceCeilingExceeded)?
            .to_be_bytes(),
    );
    for coefficient in &packed.coefficients {
        hash.update(coefficient);
    }
    Ok(hash.finalize())
}
fn validate_galois_key_schedule(
    schedule: &ZkAmsT256GaloisKeyScheduleV1,
) -> Result<(), ZkAmsMkheErrorV1> {
    if schedule.version != PACKING_VERSION_V1
        || schedule.profile_digest != release_profile_v1().digest()?
        || schedule.ring_degree != ZK_AMS_MKHE_RELEASE_RING_DEGREE_V1 as u32
        || schedule.slot_count != ZK_AMS_MKHE_RELEASE_SLOT_COUNT_V1 as u32
        || schedule.generator != SLOT_GALOIS_GENERATOR_V1 as u32
        || schedule.entries.len() != ZK_AMS_T256_GALOIS_KEY_COUNT_V1
        || schedule.digest == [0; 32]
        || schedule.digest != ZK_AMS_T256_GALOIS_KEY_SCHEDULE_DIGEST_V1
        || schedule.digest != galois_key_schedule_digest(schedule)?
    {
        return Err(ZkAmsMkheErrorV1::InvalidKeyMaterial);
    }
    for (index, entry) in schedule.entries.iter().enumerate() {
        let (direction, bit) = if index < GALOIS_KEY_SCHEDULE_BITS_V1 as usize {
            (ZkAmsT256RotationDirectionV1::Forward, index as u32)
        } else {
            (
                ZkAmsT256RotationDirectionV1::Inverse,
                u32::try_from(index - GALOIS_KEY_SCHEDULE_BITS_V1 as usize)
                    .map_err(|_| ZkAmsMkheErrorV1::InvalidKeyMaterial)?,
            )
        };
        let steps = 1_u32
            .checked_shl(bit)
            .ok_or(ZkAmsMkheErrorV1::InvalidKeyMaterial)?;
        if entry.direction != direction
            || entry.steps != steps
            || entry.exponent != zk_ams_t256_rotation_exponent_for_direction_v1(steps, direction)?
            || entry.exponent == 0
            || entry.exponent.is_multiple_of(2)
        {
            return Err(ZkAmsMkheErrorV1::InvalidKeyMaterial);
        }
    }
    for (index, entry) in schedule.entries.iter().enumerate() {
        if schedule.entries[..index]
            .iter()
            .any(|prior| prior.exponent == entry.exponent)
        {
            return Err(ZkAmsMkheErrorV1::InvalidKeyMaterial);
        }
    }
    Ok(())
}
fn galois_key_schedule_digest(
    schedule: &ZkAmsT256GaloisKeyScheduleV1,
) -> Result<[u8; 32], ZkAmsMkheErrorV1> {
    if schedule.entries.len() != ZK_AMS_T256_GALOIS_KEY_COUNT_V1 {
        return Err(ZkAmsMkheErrorV1::InvalidKeyMaterial);
    }
    let mut hash = super::native_outer_identity_v1(
        super::NativeOuterIdentityRoleV1::Parameter,
        GALOIS_KEY_SCHEDULE_DOMAIN_V1,
        6 + 3 * schedule.entries.len(),
    );
    hash.push_field(&[schedule.version])
        .expect("fixed bounded MKHE identity field");
    hash.push_field(&schedule.profile_digest)
        .expect("fixed bounded MKHE identity field");
    hash.push_field(&schedule.ring_degree.to_be_bytes())
        .expect("fixed bounded MKHE identity field");
    hash.push_field(&schedule.slot_count.to_be_bytes())
        .expect("fixed bounded MKHE identity field");
    hash.push_field(&schedule.generator.to_be_bytes())
        .expect("fixed bounded MKHE identity field");
    hash.push_field(
        &u32::try_from(schedule.entries.len())
            .map_err(|_| ZkAmsMkheErrorV1::ResourceCeilingExceeded)?
            .to_be_bytes(),
    )
    .expect("fixed bounded MKHE identity field");
    for entry in &schedule.entries {
        hash.push_field(&[entry.direction.tag()])
            .expect("fixed bounded MKHE identity field");
        hash.push_field(&entry.steps.to_be_bytes())
            .expect("fixed bounded MKHE identity field");
        hash.push_field(&entry.exponent.to_be_bytes())
            .expect("fixed bounded MKHE identity field");
    }
    Ok(*hash
        .finish()
        .expect("exact MKHE outer identity field count")
        .as_bytes())
}
fn validate_rotation(
    layout: ZkAmsT256PackingLayoutV1,
    rotation: ZkAmsT256RotationV1,
) -> Result<(), ZkAmsMkheErrorV1> {
    if rotation.version != PACKING_VERSION_V1
        || rotation.profile_digest != layout.profile_digest
        || rotation.layout_digest != layout.digest
        || rotation.chunk_index >= layout.chunk_count
        || rotation.used_slots != used_slots_for_chunk(layout, rotation.chunk_index)?
        || rotation.steps >= ZK_AMS_MKHE_RELEASE_SLOT_COUNT_V1 as u32
        || rotation.exponent
            != zk_ams_t256_rotation_exponent_for_direction_v1(rotation.steps, rotation.direction)?
        || rotation.exponent == 0
        || rotation.exponent as usize >= 2 * ZK_AMS_MKHE_RELEASE_RING_DEGREE_V1
        || rotation.exponent.is_multiple_of(2)
        || rotation.digest == [0; 32]
        || rotation.digest != rotation_digest(rotation)?
    {
        return Err(ZkAmsMkheErrorV1::InvalidKeyMaterial);
    }
    Ok(())
}
fn rotation_digest(rotation: ZkAmsT256RotationV1) -> Result<[u8; 32], ZkAmsMkheErrorV1> {
    let schedule_digest = zk_ams_t256_galois_key_schedule_v1()?.digest;
    let mut hash = super::native_outer_identity_v1(
        super::NativeOuterIdentityRoleV1::Parameter,
        ROTATION_DOMAIN_V1,
        9,
    );
    hash.push_field(&[rotation.version])
        .expect("fixed bounded MKHE identity field");
    hash.push_field(&rotation.profile_digest)
        .expect("fixed bounded MKHE identity field");
    hash.push_field(&rotation.layout_digest)
        .expect("fixed bounded MKHE identity field");
    hash.push_field(&rotation.chunk_index.to_be_bytes())
        .expect("fixed bounded MKHE identity field");
    hash.push_field(&rotation.used_slots.to_be_bytes())
        .expect("fixed bounded MKHE identity field");
    hash.push_field(&rotation.steps.to_be_bytes())
        .expect("fixed bounded MKHE identity field");
    hash.push_field(&[rotation.direction.tag()])
        .expect("fixed bounded MKHE identity field");
    hash.push_field(&rotation.exponent.to_be_bytes())
        .expect("fixed bounded MKHE identity field");
    hash.push_field(&schedule_digest)
        .expect("fixed bounded MKHE identity field");
    Ok(*hash
        .finish()
        .expect("exact MKHE outer identity field count")
        .as_bytes())
}
#[cfg(test)]
fn reject_partial_chunk_rotation(rotation: ZkAmsT256RotationV1) -> Result<(), ZkAmsMkheErrorV1> {
    if rotation.steps != 0 && rotation.used_slots != ZK_AMS_MKHE_RELEASE_SLOT_COUNT_V1 as u32 {
        return Err(ZkAmsMkheErrorV1::InvalidPolynomial);
    }
    Ok(())
}
#[cfg(test)]
fn automorphism_coefficients(
    coefficients: &[Scalar],
    exponent: usize,
) -> Result<Vec<Scalar>, ZkAmsMkheErrorV1> {
    let degree = coefficients.len();
    let twice_degree = degree
        .checked_mul(2)
        .ok_or(ZkAmsMkheErrorV1::ResourceCeilingExceeded)?;
    if degree < 2
        || !degree.is_power_of_two()
        || degree > ZK_AMS_MKHE_RELEASE_RING_DEGREE_V1
        || exponent == 0
        || exponent >= twice_degree
        || exponent.is_multiple_of(2)
    {
        return Err(ZkAmsMkheErrorV1::InvalidKeyMaterial);
    }
    let mut output = vec![Scalar::zero(); degree];
    for (index, value) in coefficients.iter().copied().enumerate() {
        let mapped = index
            .checked_mul(exponent)
            .ok_or(ZkAmsMkheErrorV1::ResourceCeilingExceeded)?
            % twice_degree;
        if mapped >= degree {
            output[mapped - degree] = -value;
        } else {
            output[mapped] = value;
        }
    }
    Ok(output)
}
#[cfg(test)]
fn check_rotation_workspace(profile: &BgvProfile) -> Result<(), ZkAmsMkheErrorV1> {
    profile.validate()?;
    let rns_polynomial_bytes = profile
        .ring_degree
        .checked_mul(profile.moduli.len())
        .and_then(|words| words.checked_mul(core::mem::size_of::<u64>()))
        .ok_or(ZkAmsMkheErrorV1::ResourceCeilingExceeded)?;
    let t256_polynomial_bytes = profile
        .ring_degree
        .checked_mul(core::mem::size_of::<Scalar>())
        .ok_or(ZkAmsMkheErrorV1::ResourceCeilingExceeded)?;
    let workspace = rns_polynomial_bytes
        .checked_mul(2)
        .and_then(|bytes| bytes.checked_add(t256_polynomial_bytes.checked_mul(3)?))
        .ok_or(ZkAmsMkheErrorV1::ResourceCeilingExceeded)?;
    if workspace > profile.max_workspace_bytes {
        return Err(ZkAmsMkheErrorV1::ResourceCeilingExceeded);
    }
    Ok(())
}
#[cfg(test)]
pub(super) fn rns_polynomial_digest(
    profile: &BgvProfile,
    polynomial: &RnsPolynomial,
) -> Result<[u8; 32], ZkAmsMkheErrorV1> {
    polynomial.validate(profile)?;
    let mut hash = Keccak256::new();
    hash.update(PACKED_RNS_BINDING_DOMAIN_V1);
    hash.update(&profile.digest()?);
    hash.update(
        &u32::try_from(profile.ring_degree)
            .map_err(|_| ZkAmsMkheErrorV1::InvalidProfile)?
            .to_be_bytes(),
    );
    hash.update(
        &u32::try_from(profile.moduli.len())
            .map_err(|_| ZkAmsMkheErrorV1::InvalidProfile)?
            .to_be_bytes(),
    );
    for (limb, modulus) in profile.moduli.iter().copied().enumerate() {
        hash.update(&modulus.to_be_bytes());
        for coefficient in polynomial.limb(profile, limb) {
            hash.update(&coefficient.to_be_bytes());
        }
    }
    Ok(hash.finalize())
}
#[cfg(test)]
fn rotation_certificate_digest(certificate: ZkAmsT256RotationCertificateV1) -> [u8; 32] {
    let mut frame = Vec::with_capacity(320);
    frame.extend_from_slice(ROTATION_CERTIFICATE_DOMAIN_V1);
    frame.push(certificate.version);
    frame.extend_from_slice(&certificate.profile_digest);
    frame.extend_from_slice(&certificate.layout_digest);
    frame.extend_from_slice(&certificate.chunk_index.to_be_bytes());
    frame.extend_from_slice(&certificate.used_slots.to_be_bytes());
    frame.extend_from_slice(&certificate.rotation_digest);
    frame.extend_from_slice(&certificate.galois_key_schedule_digest);
    frame.extend_from_slice(&certificate.input_packed_digest);
    frame.extend_from_slice(&certificate.output_packed_digest);
    frame.extend_from_slice(&certificate.transformed_rns_digest);
    keccak256(&frame)
}
fn release_packing_certificate_digest(
    certificate: ZkAmsT256ReleasePackingCertificateV1,
) -> [u8; 32] {
    let mut hash = super::native_outer_identity_v1(
        super::NativeOuterIdentityRoleV1::Release,
        RELEASE_PACKING_CERTIFICATE_DOMAIN_V1,
        17,
    );
    hash.push_field(&[certificate.version])
        .expect("fixed bounded MKHE identity field");
    hash.push_field(&certificate.profile_digest)
        .expect("fixed bounded MKHE identity field");
    hash.push_field(&certificate.ring_degree.to_be_bytes())
        .expect("fixed bounded MKHE identity field");
    hash.push_field(&certificate.slot_count.to_be_bytes())
        .expect("fixed bounded MKHE identity field");
    hash.push_field(&certificate.layout_digest)
        .expect("fixed bounded MKHE identity field");
    hash.push_field(&certificate.root_digest)
        .expect("fixed bounded MKHE identity field");
    hash.push_field(&certificate.subfield_conjugation_exponent.to_be_bytes())
        .expect("fixed bounded MKHE identity field");
    hash.push_field(&certificate.subfield_relation_digest)
        .expect("fixed bounded MKHE identity field");
    hash.push_field(&certificate.rotation_digest)
        .expect("fixed bounded MKHE identity field");
    hash.push_field(&[certificate.galois_key_count])
        .expect("fixed bounded MKHE identity field");
    hash.push_field(&certificate.galois_key_schedule_digest)
        .expect("fixed bounded MKHE identity field");
    hash.push_field(&certificate.packed_input_kat_digest)
        .expect("fixed bounded MKHE identity field");
    hash.push_field(&certificate.packed_output_kat_digest)
        .expect("fixed bounded MKHE identity field");
    hash.push_field(&certificate.transformed_rns_kat_digest)
        .expect("fixed bounded MKHE identity field");
    hash.push_field(&certificate.rotation_certificate_kat_digest)
        .expect("fixed bounded MKHE identity field");
    hash.push_field(&certificate.negative_case_count.to_be_bytes())
        .expect("fixed bounded MKHE identity field");
    hash.push_field(&certificate.negative_kat_digest)
        .expect("fixed bounded MKHE identity field");
    *hash
        .finish()
        .expect("exact MKHE outer identity field count")
        .as_bytes()
}
// Keep the immutable evidence identity separate from candidate profile construction.
// In particular, regenerating a Galois schedule is not a packing KAT execution.
// Full-degree packing and rotation KATs must execute for these exact native
// identities; a regenerated schedule alone is insufficient release evidence.
fn release_packing_evidence_profile_digest_v1(
    profile: &BgvProfile,
) -> Result<[u8; 32], ZkAmsMkheErrorV1> {
    let profile_digest = profile.digest()?;
    if profile_digest != RELEASE_PACKING_EVIDENCE_PROFILE_DIGEST_V1 {
        return Err(ZkAmsMkheErrorV1::InvalidProfile);
    }
    Ok(profile_digest)
}
fn validate_release_packing_certificate(
    certificate: ZkAmsT256ReleasePackingCertificateV1,
) -> Result<(), ZkAmsMkheErrorV1> {
    let profile = release_profile_v1();
    let evidence_profile_digest = release_packing_evidence_profile_digest_v1(&profile)?;
    let slot_count = u32::try_from(ZK_AMS_MKHE_RELEASE_SLOT_COUNT_V1)
        .map_err(|_| ZkAmsMkheErrorV1::InvalidProfile)?;
    let layout = zk_ams_t256_packing_layout_v1(slot_count)?;
    let rotation =
        zk_ams_t256_rotation_v1(layout, 0, 0xA55A, ZkAmsT256RotationDirectionV1::Inverse)?;
    let schedule = zk_ams_t256_galois_key_schedule_v1()?;
    let root_exponent = release_root_exponent_be_v1()?;
    let root = release_root()?;
    let root_digest = release_root_identity_digest(root, &root_exponent)?;
    let subfield_conjugation_exponent = zk_ams_t256_packed_subfield_conjugation_exponent_v1()?;
    if certificate.version != PACKING_VERSION_V1
        || certificate.profile_digest != evidence_profile_digest
        || certificate.ring_degree
            != u32::try_from(ZK_AMS_MKHE_RELEASE_RING_DEGREE_V1)
                .map_err(|_| ZkAmsMkheErrorV1::InvalidProfile)?
        || certificate.slot_count != slot_count
        || certificate.layout_digest != layout.digest
        || certificate.root_digest != root_digest
        || certificate.subfield_conjugation_exponent != subfield_conjugation_exponent
        || certificate.subfield_relation_digest
            != packed_subfield_relation_digest(
                evidence_profile_digest,
                root_digest,
                subfield_conjugation_exponent,
            )?
        || certificate.rotation_digest != rotation.digest
        || certificate.galois_key_count
            != u8::try_from(ZK_AMS_T256_GALOIS_KEY_COUNT_V1)
                .map_err(|_| ZkAmsMkheErrorV1::InvalidProfile)?
        || certificate.galois_key_schedule_digest != schedule.digest
        || certificate.galois_key_schedule_digest != ZK_AMS_T256_GALOIS_KEY_SCHEDULE_DIGEST_V1
        || certificate.packed_input_kat_digest != ZK_AMS_T256_RELEASE_PACKED_INPUT_KAT_DIGEST_V1
        || certificate.packed_output_kat_digest != ZK_AMS_T256_RELEASE_PACKED_OUTPUT_KAT_DIGEST_V1
        || certificate.transformed_rns_kat_digest
            != ZK_AMS_T256_RELEASE_TRANSFORMED_RNS_KAT_DIGEST_V1
        || certificate.rotation_certificate_kat_digest
            != ZK_AMS_T256_RELEASE_ROTATION_CERTIFICATE_KAT_DIGEST_V1
        || certificate.negative_case_count != ZK_AMS_T256_RELEASE_PACKING_NEGATIVE_CASE_COUNT_V1
        || certificate.negative_kat_digest != ZK_AMS_T256_RELEASE_PACKING_NEGATIVE_KAT_DIGEST_V1
        || certificate.digest == [0; 32]
        || certificate.digest != release_packing_certificate_digest(certificate)
    {
        return Err(ZkAmsMkheErrorV1::InvalidProfile);
    }
    Ok(())
}
#[cfg(test)]
fn validate_rotation_certificate(
    layout: ZkAmsT256PackingLayoutV1,
    packed: &ZkAmsT256PackedPlaintextV1,
    rotation: ZkAmsT256RotationV1,
    schedule: &ZkAmsT256GaloisKeyScheduleV1,
    certificate: ZkAmsT256RotationCertificateV1,
) -> Result<(), ZkAmsMkheErrorV1> {
    if certificate.version != PACKING_VERSION_V1
        || certificate.profile_digest != layout.profile_digest
        || certificate.layout_digest != layout.digest
        || certificate.chunk_index != packed.chunk_index
        || certificate.used_slots != packed.used_slots
        || certificate.rotation_digest != rotation.digest
        || certificate.galois_key_schedule_digest != schedule.digest
        || certificate.input_packed_digest != packed.digest
        || certificate.output_packed_digest == [0; 32]
        || certificate.transformed_rns_digest == [0; 32]
        || certificate.digest == [0; 32]
        || certificate.digest != rotation_certificate_digest(certificate)
    {
        return Err(ZkAmsMkheErrorV1::InvalidPolynomial);
    }
    Ok(())
}
fn release_root_identity_digest(
    root: T256Fp2,
    exponent: &[u8; 64],
) -> Result<[u8; 32], ZkAmsMkheErrorV1> {
    let mut hash = super::native_outer_identity_v1(
        super::NativeOuterIdentityRoleV1::Parameter,
        RELEASE_ROOT_IDENTITY_DOMAIN_V1,
        5,
    );
    hash.push_field(&VEGA_T256_SCALAR_MODULUS_BE_V1)
        .expect("fixed bounded MKHE identity field");
    hash.push_field(
        &u32::try_from(ZK_AMS_MKHE_RELEASE_RING_DEGREE_V1)
            .map_err(|_| ZkAmsMkheErrorV1::InvalidProfile)?
            .to_be_bytes(),
    )
    .expect("fixed bounded MKHE identity field");
    hash.push_field(exponent)
        .expect("fixed bounded MKHE identity field");
    hash.push_field(&root.c0.to_be_bytes())
        .expect("fixed bounded MKHE identity field");
    hash.push_field(&root.c1.to_be_bytes())
        .expect("fixed bounded MKHE identity field");
    Ok(*hash
        .finish()
        .expect("exact MKHE outer identity field count")
        .as_bytes())
}
fn release_root_exponent_be_v1() -> Result<[u8; 64], ZkAmsMkheErrorV1> {
    let mut modulus = [0_u64; 4];
    for (index, chunk) in VEGA_T256_SCALAR_MODULUS_BE_V1.rchunks_exact(8).enumerate() {
        modulus[index] = u64::from_be_bytes(
            chunk
                .try_into()
                .map_err(|_| ZkAmsMkheErrorV1::InvalidProfile)?,
        );
    }
    // Compute `p^2 - 1` in eight little-endian 64-bit limbs. Keeping this
    // derivation native avoids the error-prone hand-transcribed 512-bit
    // exponent that previously drifted by two bytes.
    let mut product = [0_u64; 8];
    for (left_index, left) in modulus.iter().copied().enumerate() {
        let mut carry = 0_u128;
        for (right_index, right) in modulus.iter().copied().enumerate() {
            let output_index = left_index + right_index;
            let wide = u128::from(left)
                .checked_mul(u128::from(right))
                .and_then(|value| value.checked_add(u128::from(product[output_index])))
                .and_then(|value| value.checked_add(carry))
                .ok_or(ZkAmsMkheErrorV1::InvalidProfile)?;
            product[output_index] = wide as u64;
            carry = wide >> 64;
        }
        let mut output_index = left_index + modulus.len();
        while carry != 0 {
            let output = product
                .get_mut(output_index)
                .ok_or(ZkAmsMkheErrorV1::InvalidProfile)?;
            let wide = u128::from(*output)
                .checked_add(carry)
                .ok_or(ZkAmsMkheErrorV1::InvalidProfile)?;
            *output = wide as u64;
            carry = wide >> 64;
            output_index += 1;
        }
    }
    let mut borrow = 1_u64;
    for limb in &mut product {
        let (value, borrowed) = limb.overflowing_sub(borrow);
        *limb = value;
        borrow = borrowed.into();
        if borrow == 0 {
            break;
        }
    }
    if borrow != 0 {
        return Err(ZkAmsMkheErrorV1::InvalidProfile);
    }
    let root_order = ZK_AMS_MKHE_RELEASE_RING_DEGREE_V1
        .checked_mul(2)
        .ok_or(ZkAmsMkheErrorV1::InvalidProfile)?;
    if !root_order.is_power_of_two() {
        return Err(ZkAmsMkheErrorV1::InvalidProfile);
    }
    let shift = root_order.trailing_zeros();
    if shift == 0 || shift >= 64 || product[0] & ((1_u64 << shift) - 1) != 0 {
        return Err(ZkAmsMkheErrorV1::InvalidProfile);
    }
    let mut quotient = [0_u64; 8];
    for index in 0..quotient.len() {
        quotient[index] = product[index] >> shift;
        if let Some(high) = product.get(index + 1) {
            quotient[index] |= *high << (64 - shift);
        }
    }
    let mut exponent = [0_u8; 64];
    for (index, limb) in quotient.iter().rev().copied().enumerate() {
        exponent[index * 8..(index + 1) * 8].copy_from_slice(&limb.to_be_bytes());
    }
    Ok(exponent)
}
fn release_root() -> Result<T256Fp2, ZkAmsMkheErrorV1> {
    let pinned = T256Fp2 {
        c0: Scalar::from_be_bytes_exact(RELEASE_ROOT_C0_BE_V1)
            .map_err(|_| ZkAmsMkheErrorV1::InvalidProfile)?,
        c1: Scalar::from_be_bytes_exact(RELEASE_ROOT_C1_BE_V1)
            .map_err(|_| ZkAmsMkheErrorV1::InvalidProfile)?,
    };
    let mut frame = Vec::with_capacity(96);
    frame.extend_from_slice(RELEASE_ROOT_DERIVATION_DOMAIN_V1);
    frame.extend_from_slice(&(ZK_AMS_MKHE_RELEASE_RING_DEGREE_V1 as u32).to_be_bytes());
    frame.extend_from_slice(&0_u32.to_be_bytes());
    let uniform = shake256(&frame, 128);
    let first: [u8; 64] = uniform[..64]
        .try_into()
        .map_err(|_| ZkAmsMkheErrorV1::InvalidProfile)?;
    let second: [u8; 64] = uniform[64..]
        .try_into()
        .map_err(|_| ZkAmsMkheErrorV1::InvalidProfile)?;
    let derived = T256Fp2 {
        c0: Scalar::from_uniform_le_bytes(first),
        c1: Scalar::from_uniform_le_bytes(second),
    }
    .pow_be(&release_root_exponent_be_v1()?);
    let minus_one = T256Fp2::from_base(-Scalar::one());
    if derived != pinned
        || pinned.pow_u64(ZK_AMS_MKHE_RELEASE_RING_DEGREE_V1 as u64) != minus_one
        || pinned.pow_u64((2 * ZK_AMS_MKHE_RELEASE_RING_DEGREE_V1) as u64) != T256Fp2::one()
        || pinned.mul(pinned.conjugate()) != T256Fp2::one()
    {
        return Err(ZkAmsMkheErrorV1::InvalidProfile);
    }
    Ok(pinned)
}
#[cfg(test)]
fn root_for_degree(degree: usize) -> Result<T256Fp2, ZkAmsMkheErrorV1> {
    if degree < 2
        || !degree.is_power_of_two()
        || degree > ZK_AMS_MKHE_RELEASE_RING_DEGREE_V1
        || !ZK_AMS_MKHE_RELEASE_RING_DEGREE_V1.is_multiple_of(degree)
    {
        return Err(ZkAmsMkheErrorV1::InvalidProfile);
    }
    Ok(release_root()?.pow_u64(
        u64::try_from(ZK_AMS_MKHE_RELEASE_RING_DEGREE_V1 / degree)
            .map_err(|_| ZkAmsMkheErrorV1::InvalidProfile)?,
    ))
}
#[cfg(test)]
fn encode_coefficients(slots: &[Scalar], degree: usize) -> Result<Vec<Scalar>, ZkAmsMkheErrorV1> {
    if slots.len() != degree / 2 {
        return Err(ZkAmsMkheErrorV1::InvalidPolynomial);
    }
    let root = root_for_degree(degree)?;
    let omega = root.mul(root);
    let mut evaluations = vec![T256Fp2::zero(); degree];
    for (slot, value) in slots.iter().copied().enumerate() {
        let index = slot_root_index(degree, slot)?;
        let conjugate = degree - 1 - index;
        evaluations[index] = T256Fp2::from_base(value);
        evaluations[conjugate] = T256Fp2::from_base(value);
    }
    inverse_cyclic_ntt(&mut evaluations, omega)?;
    let inverse_root = root.conjugate();
    let mut untwist = T256Fp2::one();
    let mut coefficients = Vec::with_capacity(degree);
    for value in evaluations {
        let coefficient = value.mul(untwist);
        if !coefficient.c1.is_zero() {
            return Err(ZkAmsMkheErrorV1::InvalidPolynomial);
        }
        coefficients.push(coefficient.c0);
        untwist = untwist.mul(inverse_root);
    }
    Ok(coefficients)
}
#[cfg(test)]
fn decode_coefficients(
    coefficients: &[Scalar],
    degree: usize,
) -> Result<Vec<Scalar>, ZkAmsMkheErrorV1> {
    if coefficients.len() != degree {
        return Err(ZkAmsMkheErrorV1::InvalidPolynomial);
    }
    let root = root_for_degree(degree)?;
    let omega = root.mul(root);
    let mut twist = T256Fp2::one();
    let mut evaluations = ZeroizingPackingFp2V1::with_capacity(degree)?;
    for coefficient in coefficients {
        evaluations.push(T256Fp2::from_base(*coefficient).mul(twist));
        twist = twist.mul(root);
    }
    cyclic_ntt(&mut evaluations.0, omega);
    let mut slots = ZeroizingPackingScalarsV1::with_capacity(degree / 2)?;
    for slot in 0..degree / 2 {
        let index = slot_root_index(degree, slot)?;
        let conjugate = degree - 1 - index;
        let value = evaluations.0[index];
        if !value.c1.is_zero() || evaluations.0[conjugate] != value || slots.0.len() != slot {
            return Err(ZkAmsMkheErrorV1::InvalidPolynomial);
        }
        slots.push(value.c0);
    }
    Ok(slots.take())
}
#[cfg(test)]
fn slot_root_index(degree: usize, slot: usize) -> Result<usize, ZkAmsMkheErrorV1> {
    if slot >= degree / 2 {
        return Err(ZkAmsMkheErrorV1::InvalidPolynomial);
    }
    let exponent = mod_pow_usize(SLOT_GALOIS_GENERATOR_V1, slot, 2 * degree);
    if exponent == 0 || exponent.is_multiple_of(2) {
        return Err(ZkAmsMkheErrorV1::InvalidProfile);
    }
    Ok((exponent - 1) / 2)
}
#[cfg(test)]
fn bit_reverse_permute(values: &mut [T256Fp2]) {
    let mut target = 0_usize;
    for index in 1..values.len() {
        let mut bit = values.len() >> 1;
        while target & bit != 0 {
            target ^= bit;
            bit >>= 1;
        }
        target ^= bit;
        if index < target {
            values.swap(index, target);
        }
    }
}
#[cfg(test)]
fn cyclic_ntt(values: &mut [T256Fp2], root: T256Fp2) {
    bit_reverse_permute(values);
    let mut width = 2;
    while width <= values.len() {
        let twiddle_step = root.pow_u64((values.len() / width) as u64);
        for block in values.chunks_exact_mut(width) {
            let mut twiddle = T256Fp2::one();
            for offset in 0..width / 2 {
                let even = block[offset];
                let odd = block[offset + width / 2].mul(twiddle);
                block[offset] = even.add(odd);
                block[offset + width / 2] = even.sub(odd);
                twiddle = twiddle.mul(twiddle_step);
            }
        }
        width <<= 1;
    }
}
#[cfg(test)]
fn inverse_cyclic_ntt(values: &mut [T256Fp2], root: T256Fp2) -> Result<(), ZkAmsMkheErrorV1> {
    cyclic_ntt(values, root.conjugate());
    let inverse_degree = Scalar::from_u64(
        u64::try_from(values.len()).map_err(|_| ZkAmsMkheErrorV1::InvalidProfile)?,
    )
    .inverse()
    .map_err(|_| ZkAmsMkheErrorV1::InvalidProfile)?;
    for value in values {
        *value = value.scale(inverse_degree);
    }
    Ok(())
}
/// Test-only reference; production takes modular exponentiation from `iroha_fhe`.
#[cfg(test)]
fn mod_pow_usize(mut base: usize, mut exponent: usize, modulus: usize) -> usize {
    let mut result = 1_usize;
    while exponent != 0 {
        if exponent & 1 == 1 {
            result = ((result as u128 * base as u128) % modulus as u128) as usize;
        }
        base = ((base as u128 * base as u128) % modulus as u128) as usize;
        exponent >>= 1;
    }
    result
}
#[cfg(test)]
pub(super) mod tests {
    use super::super::PlaintextModulus;
    use super::*;
    use std::panic::{AssertUnwindSafe, catch_unwind};
    const TEST_RNS_MODULI_V1: [u64; 2] = [2_013_265_921, 1_811_939_329];
    const TEST_RNS_ROOTS_V1: [u64; 2] = [1_400_279_418, 677_356_115];
    fn tiny_rns_binding_profile_v1() -> BgvProfile {
        BgvProfile {
            profile_id: [0x83; 32],
            ring_degree: 8,
            moduli: &TEST_RNS_MODULI_V1,
            negacyclic_roots: &TEST_RNS_ROOTS_V1,
            plaintext_modulus: PlaintextModulus::Tiny(17),
            error_eta: 2,
            hybrid_rns_decomposition: false,
            gadget_base_log: 8,
            gadget_digits: 8,
            max_ciphertext_bytes: 1 << 20,
            max_evaluated_key_bytes: 16 << 20,
            max_round_bytes: 16 << 20,
            max_share_bytes: 4 << 20,
            max_workspace_bytes: 16 << 20,
            max_work_units: 1 << 20,
        }
    }
    fn schoolbook_negacyclic(left: &[Scalar], right: &[Scalar]) -> Vec<Scalar> {
        let mut output = vec![Scalar::zero(); left.len()];
        for (left_index, left_value) in left.iter().copied().enumerate() {
            for (right_index, right_value) in right.iter().copied().enumerate() {
                let value = left_value * right_value;
                let position = left_index + right_index;
                if position < left.len() {
                    output[position] += value;
                } else {
                    output[position - left.len()] -= value;
                }
            }
        }
        output
    }
    #[test]
    fn ordered_rns_binding_hash_matches_tiny_native_digest_and_fails_closed() {
        let profile = tiny_rns_binding_profile_v1();
        let coefficients = profile
            .moduli
            .iter()
            .copied()
            .enumerate()
            .flat_map(|(limb, modulus)| {
                (0..profile.ring_degree).map(move |index| {
                    u64::try_from(1 + limb * profile.ring_degree + index).unwrap() % modulus
                })
            })
            .collect::<Vec<_>>();
        let polynomial = RnsPolynomial::from_flat(&profile, coefficients).unwrap();
        let expected = rns_polynomial_digest(&profile, &polynomial).unwrap();
        let mut ordered = OrderedRnsBindingHashV1::new(&profile).unwrap();
        assert_eq!(
            ordered.absorb_limb(1, polynomial.limb(&profile, 1)),
            Err(ZkAmsMkheErrorV1::InvalidPolynomial),
            "out-of-order absorption must not advance the state"
        );
        ordered
            .absorb_limb(0, polynomial.limb(&profile, 0))
            .unwrap();
        assert_eq!(
            ordered.absorb_limb(0, polynomial.limb(&profile, 0)),
            Err(ZkAmsMkheErrorV1::InvalidPolynomial),
            "a duplicate limb must fail closed"
        );
        assert_eq!(
            ordered.absorb_limb(1, &polynomial.limb(&profile, 1)[..7]),
            Err(ZkAmsMkheErrorV1::InvalidPolynomial),
            "a short limb must not advance the state"
        );
        ordered
            .absorb_limb(1, polynomial.limb(&profile, 1))
            .unwrap();
        assert_eq!(ordered.finish().unwrap(), expected);
        assert_eq!(
            OrderedRnsBindingHashV1::new(&profile).unwrap().finish(),
            Err(ZkAmsMkheErrorV1::InvalidPolynomial),
            "early finalization consumes and rejects the incomplete state"
        );
        let mut noncanonical = polynomial.limb(&profile, 0).to_vec();
        noncanonical[0] = profile.moduli[0];
        let mut rejected = OrderedRnsBindingHashV1::new(&profile).unwrap();
        assert_eq!(
            rejected.absorb_limb(0, &noncanonical),
            Err(ZkAmsMkheErrorV1::InvalidPolynomial)
        );
        rejected
            .absorb_limb(0, polynomial.limb(&profile, 0))
            .unwrap();
    }
    #[test]
    fn typed_release_limb_owner_binds_ordinal_and_preserves_state_on_rejection() {
        // Direct construction is confined to this child test module. Production
        // callers can obtain this move-only view only through exact validation.
        let layout = zk_ams_t256_packing_layout_v1(65_536).unwrap();
        let mut coefficients = vec![[0_u8; 32]; ZK_AMS_MKHE_RELEASE_RING_DEGREE_V1];
        coefficients[0][31] = 1;
        let mut packed = ZkAmsT256PackedPlaintextV1 {
            version: PACKING_VERSION_V1,
            profile_digest: layout.profile_digest,
            layout_digest: layout.digest,
            chunk_index: 0,
            used_slots: 65_536,
            coefficients,
            digest: [0; 32],
        };
        packed.digest = packed_plaintext_digest(&packed).unwrap();
        let plaintext = ValidatedT256PackedPlaintextV1 {
            layout,
            packed: &packed,
        };
        let mut hasher = T256PackedRnsBindingHasherV1::new(plaintext).unwrap();
        let mut owner = ZeroizingT256ReleaseLimbV1::new_zeroed_v1().unwrap();
        assert!(owner.filled_v1().is_err());
        hasher
            .absorb_next_release_limb_into_v1(0, &mut owner)
            .unwrap();
        {
            let filled = owner.filled_v1().unwrap();
            assert_eq!(filled.limb_v1(), 0);
            assert_eq!(filled.modulus_v1(), RELEASE_MODULI_V1[0]);
            assert_eq!(filled.coefficients_v1()[0], 1);
            assert!(
                filled.coefficients_v1()[1..]
                    .iter()
                    .all(|value| *value == 0)
            );
        }
        for rejected_limb in [0, 2, RELEASE_MODULI_V1.len()] {
            assert_eq!(
                hasher.absorb_next_release_limb_into_v1(rejected_limb, &mut owner),
                Err(ZkAmsMkheErrorV1::InvalidPolynomial)
            );
            let unchanged = owner.filled_v1().unwrap();
            assert_eq!(unchanged.limb_v1(), 0);
            assert_eq!(unchanged.modulus_v1(), RELEASE_MODULI_V1[0]);
            assert_eq!(unchanged.coefficients_v1()[0], 1);
            assert!(
                unchanged.coefficients_v1()[1..]
                    .iter()
                    .all(|value| *value == 0)
            );
        }
        // These malformed sizes can only be forged inside this child test;
        // the production constructor always allocates exactly N coefficients.
        for malformed_len in [
            ZK_AMS_MKHE_RELEASE_RING_DEGREE_V1 - 1,
            ZK_AMS_MKHE_RELEASE_RING_DEGREE_V1 + 1,
        ] {
            let mut malformed = ZeroizingT256ReleaseLimbV1 {
                coefficients: vec![0x55_u64; malformed_len].into_boxed_slice(),
                filled_limb: Some(0),
            };
            assert_eq!(
                hasher.absorb_next_release_limb_into_v1(1, &mut malformed),
                Err(ZkAmsMkheErrorV1::InvalidPolynomial)
            );
            assert!(
                malformed
                    .coefficients
                    .iter()
                    .all(|coefficient| *coefficient == 0x55)
            );
            assert_eq!(malformed.filled_limb, Some(0));
        }
        hasher
            .absorb_next_release_limb_into_v1(1, &mut owner)
            .unwrap();
        assert_eq!(owner.filled_v1().unwrap().limb_v1(), 1);
        assert_eq!(
            owner.filled_v1().unwrap().modulus_v1(),
            RELEASE_MODULI_V1[1]
        );
        assert_eq!(
            hasher.finish(),
            Err(ZkAmsMkheErrorV1::InvalidPolynomial),
            "finishing after two limbs must fail without invalidating the last typed owner"
        );
        assert_eq!(owner.filled_v1().unwrap().limb_v1(), 1);
    }
    #[test]
    fn centered_t256_limb_fill_matches_native_boundaries() {
        let half = super::super::T256_CENTERED_MAX_BE_V1;
        let mut half_plus_one = half;
        for byte in half_plus_one.iter_mut().rev() {
            let (next, carry) = byte.overflowing_add(1);
            *byte = next;
            if !carry {
                break;
            }
        }
        let mut p_minus_one = VEGA_T256_SCALAR_MODULUS_BE_V1;
        for byte in p_minus_one.iter_mut().rev() {
            let (next, borrow) = byte.overflowing_sub(1);
            *byte = next;
            if !borrow {
                break;
            }
        }
        let mut one = [0_u8; 32];
        one[31] = 1;
        let coefficients = [[0_u8; 32], one, half, half_plus_one, p_minus_one];
        let modulus = RELEASE_MODULI_V1[0];
        let mut output = [u64::MAX; 5];
        lift_centered_t256_coefficients_into_v1(&coefficients, modulus, &mut output);
        assert_eq!(output[0], 0);
        assert_eq!(output[1], 1);
        assert_eq!(output[2], bytes_mod_u64(&half, modulus));
        assert_eq!(output[4], modulus - 1);
        assert_eq!(
            super::super::mod_add(output[2], output[3], modulus),
            0,
            "the two centered boundary representatives must be exact negatives"
        );
    }
    #[test]
    fn in_place_decoder_workspace_and_packed_owner_zeroize_on_drop_paths() {
        assert_eq!(core::mem::size_of::<Scalar>(), 32);
        assert_eq!(core::mem::size_of::<T256Fp2>(), 64);
        let dirty = T256Fp2 {
            c0: Scalar::from_u64(3),
            c1: Scalar::from_u64(5),
        };
        let cleared = |values: &[T256Fp2]| {
            values
                .iter()
                .all(|value| value.c0.is_zero() && value.c1.is_zero())
        };
        let mut success = vec![dirty; 3];
        drop(ClearingPackingFp2BorrowV1(&mut success));
        assert!(cleared(&success));
        fn reject(values: &mut [T256Fp2]) -> Result<(), ZkAmsMkheErrorV1> {
            let _guard = ClearingPackingFp2BorrowV1(values);
            Err(ZkAmsMkheErrorV1::InvalidPolynomial)
        }
        let mut error = vec![dirty; 3];
        assert_eq!(reject(&mut error), Err(ZkAmsMkheErrorV1::InvalidPolynomial));
        assert!(cleared(&error));
        let mut unwind_values = vec![dirty; 3];
        let unwind = catch_unwind(AssertUnwindSafe(|| {
            let _guard = ClearingPackingFp2BorrowV1(&mut unwind_values);
            panic!("intentional decoder-workspace erasure audit");
        }));
        assert!(unwind.is_err());
        assert!(cleared(&unwind_values));
        let scalar_bytes_before = packing_scalar_bytes_zeroized_drop_count_v1();
        let mut scalar_bytes = ZeroizingPackingScalarBytesV1::new();
        scalar_bytes.encode_from(&Scalar::from_u64(7));
        assert_eq!(scalar_bytes.as_array(), &Scalar::from_u64(7).to_be_bytes());
        drop(scalar_bytes);
        assert_eq!(
            packing_scalar_bytes_zeroized_drop_count_v1(),
            scalar_bytes_before + 1
        );
        fn reject_scalar_bytes() -> Result<(), ZkAmsMkheErrorV1> {
            let mut bytes = ZeroizingPackingScalarBytesV1::new();
            bytes.encode_from(&Scalar::from_u64(9));
            Err(ZkAmsMkheErrorV1::InvalidPolynomial)
        }
        assert_eq!(
            reject_scalar_bytes(),
            Err(ZkAmsMkheErrorV1::InvalidPolynomial)
        );
        assert_eq!(
            packing_scalar_bytes_zeroized_drop_count_v1(),
            scalar_bytes_before + 2
        );
        let unwind = catch_unwind(AssertUnwindSafe(|| {
            let mut bytes = ZeroizingPackingScalarBytesV1::new();
            bytes.encode_from(&Scalar::from_u64(11));
            panic!("intentional decoded-scalar erasure audit");
        }));
        assert!(unwind.is_err());
        assert_eq!(
            packing_scalar_bytes_zeroized_drop_count_v1(),
            scalar_bytes_before + 3
        );
        let before = packed_plaintext_zeroized_drop_count_v1();
        let packed = ZkAmsT256PackedPlaintextV1 {
            version: 1,
            profile_digest: [1; 32],
            layout_digest: [2; 32],
            chunk_index: 0,
            used_slots: 2,
            coefficients: vec![[0x5a; 32], [0xa5; 32]],
            digest: [3; 32],
        };
        assert!(format!("{packed:?}").len() < 1_024);
        drop(packed);
        assert_eq!(packed_plaintext_zeroized_drop_count_v1(), before + 1);
    }
    #[test]
    fn release_limb_owner_zeroizes_success_error_and_unwind() {
        let owner = || ZeroizingT256ReleaseLimbV1 {
            coefficients: vec![3, 5, 8].into_boxed_slice(),
            filled_limb: Some(7),
        };
        let before_success = t256_release_limb_zeroized_drop_count_v1();
        drop(owner());
        assert_eq!(
            t256_release_limb_zeroized_drop_count_v1(),
            before_success + 1
        );
        fn reject_owner(_owner: ZeroizingT256ReleaseLimbV1) -> Result<(), ZkAmsMkheErrorV1> {
            Err(ZkAmsMkheErrorV1::InvalidPolynomial)
        }
        let before_error = t256_release_limb_zeroized_drop_count_v1();
        assert_eq!(
            reject_owner(owner()),
            Err(ZkAmsMkheErrorV1::InvalidPolynomial)
        );
        assert_eq!(t256_release_limb_zeroized_drop_count_v1(), before_error + 1);
        let before_unwind = t256_release_limb_zeroized_drop_count_v1();
        let unwind = catch_unwind(AssertUnwindSafe(|| {
            let _owner = owner();
            panic!("intentional release-limb owner erasure audit");
        }));
        assert!(unwind.is_err());
        assert_eq!(
            t256_release_limb_zeroized_drop_count_v1(),
            before_unwind + 1
        );
    }
    #[test]
    fn packed_rns_binding_owner_zeroizes_success_error_and_unwind() {
        let owner = || {
            ZeroizingPackedRnsBindingV1(RnsPolynomial {
                coefficients: vec![3, 5, 8],
            })
        };
        let before_success = packed_rns_binding_zeroized_drop_count_v1();
        drop(owner());
        assert_eq!(
            packed_rns_binding_zeroized_drop_count_v1(),
            before_success + 1
        );
        fn reject_owner(_owner: ZeroizingPackedRnsBindingV1) -> Result<(), ZkAmsMkheErrorV1> {
            Err(ZkAmsMkheErrorV1::InvalidPolynomial)
        }
        let before_error = packed_rns_binding_zeroized_drop_count_v1();
        assert_eq!(
            reject_owner(owner()),
            Err(ZkAmsMkheErrorV1::InvalidPolynomial)
        );
        assert_eq!(
            packed_rns_binding_zeroized_drop_count_v1(),
            before_error + 1
        );
        let before_unwind = packed_rns_binding_zeroized_drop_count_v1();
        let unwind = catch_unwind(AssertUnwindSafe(|| {
            let _owner = owner();
            panic!("intentional packed RNS binding erasure audit");
        }));
        assert!(unwind.is_err());
        assert_eq!(
            packed_rns_binding_zeroized_drop_count_v1(),
            before_unwind + 1
        );
    }
    fn release_sparse_cosine_coefficients() -> Vec<Scalar> {
        let mut coefficients = vec![Scalar::zero(); ZK_AMS_MKHE_RELEASE_RING_DEGREE_V1];
        coefficients[0] = Scalar::from_u64(19);
        for (index, value) in [(1, 3_u64), (17, 5), (4_095, 7), (32_767, 11), (65_535, 13)] {
            let value = Scalar::from_u64(value);
            coefficients[index] += value;
            coefficients[ZK_AMS_MKHE_RELEASE_RING_DEGREE_V1 - index] -= value;
        }
        coefficients
    }
    #[test]
    fn limb_stream_source_guard_keeps_the_prerequisite_private_and_bounded() {
        let source = include_str!("packing.rs");
        let start = source
            .find("pub(super) struct ZeroizingT256ReleaseLimbV1")
            .expect("zeroizing limb-owner declaration");
        let end = source[start..]
            .find("impl T256Fp2")
            .map(|offset| start + offset)
            .expect("end of limb-stream prerequisite");
        let corridor = &source[start..end];
        assert!(!corridor.contains("#[derive("));
        assert!(!corridor.contains("pub coefficients"));
        assert!(!corridor.contains("pub layout"));
        assert!(!corridor.contains("pub packed"));
        assert!(!corridor.contains("pub digest"));
        assert!(!corridor.contains("Vec<Vec<u64>>"));
        assert!(!corridor.contains("RnsPolynomial"));
        assert!(!corridor.contains("callback"));
        assert!(!corridor.contains("authority"));
        assert!(!corridor.contains("impl Clone for"));
        assert!(!corridor.contains("impl Debug for"));
        assert!(!corridor.contains("fn take"));
        assert!(!corridor.contains("into_vec("));
        assert!(!corridor.contains("pub(super) fn as_mut"));
        assert!(!corridor.contains("pub(super) fn lift_release_limb_into_v1"));
        let plain_residue_clone = [".coefficients", ".to_vec()"].concat();
        assert!(!source.contains(&plain_residue_clone));
        assert!(!corridor.contains("ready: true"));
        assert!(!corridor.contains("available: true"));
        assert!(!corridor.contains("released: true"));
        assert!(corridor.contains("filled_limb: Option<usize>"));
        assert!(corridor.contains("pub(super) fn filled_v1"));
        assert!(corridor.contains("pub(super) fn limb_v1"));
        assert!(corridor.contains("pub(super) fn modulus_v1"));
        assert!(corridor.contains("pub(super) fn coefficients_v1"));
        assert!(corridor.contains("layout: ZkAmsT256PackingLayoutV1"));
        assert!(corridor.contains("packed: &'packed ZkAmsT256PackedPlaintextV1"));
        assert!(corridor.contains("hash: Box<Keccak256>"));
        assert!(corridor.contains("self.hash.finalize_into(&mut digest)"));
        assert!(corridor.contains("not a proof, MAC, authorization, capability, or receipt"));
        let artifact_validation = corridor
            .find("validate_packed(layout, packed)?")
            .expect("cheap exact artifact validation");
        let full_work_gate = corridor
            .find("checked_coefficient_work(&profile, profile.moduli.len())?")
            .expect("one full-lift work preflight");
        let padding_decode = corridor
            .find("visit_validated_packed_plaintext_used_slots_with_workspace_v1(")
            .expect("in-place decoded-padding validation");
        let absorb = corridor
            .find(".absorb_limb(limb, &output.coefficients)?")
            .expect("exact limb absorption");
        let label = corridor
            .find("output.filled_limb = Some(limb)")
            .expect("post-absorption ordinal label");
        assert!(artifact_validation < full_work_gate);
        assert!(full_work_gate < padding_decode);
        assert!(absorb < label);
        assert_eq!(corridor.matches("checked_coefficient_work(").count(), 1);
    }
    fn error_tag(error: ZkAmsMkheErrorV1) -> u8 {
        match error {
            ZkAmsMkheErrorV1::InvalidProfile => 1,
            ZkAmsMkheErrorV1::ResourceCeilingExceeded => 2,
            ZkAmsMkheErrorV1::InvalidPartySet => 3,
            ZkAmsMkheErrorV1::InvalidPolynomial => 4,
            ZkAmsMkheErrorV1::InvalidKeyMaterial => 5,
            ZkAmsMkheErrorV1::InvalidCiphertext => 6,
            ZkAmsMkheErrorV1::MissingEvaluatedKey => 7,
            ZkAmsMkheErrorV1::InvalidAuthentication => 8,
            ZkAmsMkheErrorV1::InvalidShareProof => 9,
            ZkAmsMkheErrorV1::InvalidShareSet => 10,
            ZkAmsMkheErrorV1::DecryptionBoundExceeded => 11,
            ZkAmsMkheErrorV1::InvalidPhase23Fold => 12,
            ZkAmsMkheErrorV1::RandomUnavailable => 13,
            ZkAmsMkheErrorV1::ReleaseUnavailable => 14,
            ZkAmsMkheErrorV1::InvalidWireEncoding => 15,
            ZkAmsMkheErrorV1::WireTooLarge => 16,
            ZkAmsMkheErrorV1::InvalidCksProof => 17,
            ZkAmsMkheErrorV1::InvalidCksSet => 18,
        }
    }
    struct NegativePackingKatV1 {
        hash: Keccak256,
        case_count: u16,
    }
    impl NegativePackingKatV1 {
        fn new() -> Self {
            let mut hash = Keccak256::new();
            hash.update(b"iroha.zk-ams.v1.mkhe.t256-packing-negative-kat");
            Self {
                hash,
                case_count: 0,
            }
        }
        fn record(&mut self, label: &[u8], error: ZkAmsMkheErrorV1) {
            self.hash.update(
                &u16::try_from(label.len())
                    .expect("fixed negative KAT label length")
                    .to_be_bytes(),
            );
            self.hash.update(label);
            self.hash.update(&[error_tag(error)]);
            self.case_count = self
                .case_count
                .checked_add(1)
                .expect("fixed negative KAT case count");
        }
        fn finalize(self) -> ([u8; 32], u16) {
            (self.hash.finalize(), self.case_count)
        }
    }
    fn record_negative<T: core::fmt::Debug>(
        kat: &mut NegativePackingKatV1,
        label: &[u8],
        result: Result<T, ZkAmsMkheErrorV1>,
        expected: ZkAmsMkheErrorV1,
    ) {
        let actual = result.expect_err("adversarial packing KAT must fail closed");
        assert_eq!(actual, expected, "negative KAT case {:?}", label);
        kat.record(label, actual);
    }
    #[test]
    fn fp2_crt_roundtrip_and_hadamard_match_naive_polynomial_oracle() {
        let left = [1_u64, 2, 3, 4].map(Scalar::from_u64).to_vec();
        let right = [4_u64, 3, 2, 1].map(Scalar::from_u64).to_vec();
        let encoded_left = encode_coefficients(&left, 8).unwrap();
        let encoded_right = encode_coefficients(&right, 8).unwrap();
        assert_eq!(decode_coefficients(&encoded_left, 8).unwrap(), left);
        assert_eq!(decode_coefficients(&encoded_right, 8).unwrap(), right);
        let product = schoolbook_negacyclic(&encoded_left, &encoded_right);
        assert_eq!(
            decode_coefficients(&product, 8).unwrap(),
            left.iter()
                .copied()
                .zip(right.iter().copied())
                .map(|(left, right)| left * right)
                .collect::<Vec<_>>()
        );
        let forward = automorphism_coefficients(&encoded_left, 5).unwrap();
        let mut expected_forward = left.clone();
        expected_forward.rotate_left(1);
        assert_eq!(decode_coefficients(&forward, 8).unwrap(), expected_forward);
        let inverse = automorphism_coefficients(&forward, 13).unwrap();
        assert_eq!(inverse, encoded_left);
        let mut expected_inverse = left.clone();
        expected_inverse.rotate_right(1);
        assert_eq!(
            decode_coefficients(&automorphism_coefficients(&encoded_left, 13).unwrap(), 8).unwrap(),
            expected_inverse
        );
    }
    #[test]
    fn fp2_decode_preserves_base_subfield_and_layout_rejects_nonzero_padding() {
        let mut coefficients =
            encode_coefficients(&[1_u64, 2, 3, 4].map(Scalar::from_u64), 8).unwrap();
        coefficients[0] += Scalar::one();
        assert_eq!(
            decode_coefficients(&coefficients, 8).unwrap(),
            [2_u64, 3, 4, 5].map(Scalar::from_u64)
        );
        assert_eq!(
            decode_coefficients(&coefficients[..coefficients.len() - 1], 8),
            Err(ZkAmsMkheErrorV1::InvalidPolynomial)
        );
        let layout = zk_ams_t256_packing_layout_v1(1).unwrap();
        let mut slots = vec![[0_u8; 32]; ZK_AMS_MKHE_RELEASE_SLOT_COUNT_V1];
        slots[0][31] = 1;
        slots[1][31] = 1;
        assert_eq!(
            encode_zk_ams_t256_packed_plaintext_v1(layout, 0, &slots),
            Err(ZkAmsMkheErrorV1::InvalidPolynomial)
        );
    }
    #[test]
    fn release_root_every_rotation_and_binary_key_schedule_are_exact() {
        assert_eq!(
            release_root_exponent_be_v1().unwrap(),
            RELEASE_ROOT_EXPONENT_KAT_BE_V1
        );
        let root = release_root().unwrap();
        assert_eq!(root.c0.to_be_bytes(), RELEASE_ROOT_C0_BE_V1);
        assert_eq!(root.c1.to_be_bytes(), RELEASE_ROOT_C1_BE_V1);
        let modulus = 2 * ZK_AMS_MKHE_RELEASE_RING_DEGREE_V1;
        let mut seen = vec![false; modulus];
        for steps in 0..ZK_AMS_MKHE_RELEASE_SLOT_COUNT_V1 as u32 {
            let forward = zk_ams_t256_rotation_exponent_for_direction_v1(
                steps,
                ZkAmsT256RotationDirectionV1::Forward,
            )
            .unwrap();
            let inverse = zk_ams_t256_rotation_exponent_for_direction_v1(
                steps,
                ZkAmsT256RotationDirectionV1::Inverse,
            )
            .unwrap();
            assert_eq!(forward % 4, 1);
            assert_eq!(inverse % 4, 1);
            assert_eq!(
                (u64::from(forward) * u64::from(inverse)) % modulus as u64,
                1
            );
            assert!(!seen[forward as usize]);
            seen[forward as usize] = true;
        }
        assert_eq!(seen.into_iter().filter(|value| *value).count(), 65_536);
        assert_eq!(zk_ams_t256_rotation_exponent_v1(0).unwrap(), 1);
        assert_eq!(zk_ams_t256_rotation_exponent_v1(1).unwrap(), 5);
        assert_eq!(zk_ams_t256_rotation_exponent_v1(2).unwrap(), 25);
        assert_eq!(zk_ams_t256_rotation_exponent_v1(65_535).unwrap(), 52_429);
        assert_eq!(
            zk_ams_t256_rotation_exponent_v1(65_536),
            Err(ZkAmsMkheErrorV1::InvalidKeyMaterial)
        );
        let schedule = zk_ams_t256_galois_key_schedule_v1().unwrap();
        assert_eq!(schedule.entries.len(), ZK_AMS_T256_GALOIS_KEY_COUNT_V1);
        assert_eq!(schedule.digest, ZK_AMS_T256_GALOIS_KEY_SCHEDULE_DIGEST_V1);
        let exponents = schedule
            .entries
            .iter()
            .map(|entry| entry.exponent)
            .collect::<Vec<_>>();
        validate_zk_ams_t256_galois_key_exponents_v1(&schedule, &exponents).unwrap();
        let layout = zk_ams_t256_packing_layout_v1(65_536).unwrap();
        for direction in [
            ZkAmsT256RotationDirectionV1::Forward,
            ZkAmsT256RotationDirectionV1::Inverse,
        ] {
            for steps in [0, 1, 2, 3, 0x5555, 32_768, 65_535] {
                let rotation = zk_ams_t256_rotation_v1(layout, 0, steps, direction).unwrap();
                let plan = zk_ams_t256_rotation_key_plan_v1(layout, rotation, &schedule).unwrap();
                assert_eq!(plan.len(), steps.count_ones() as usize);
            }
        }
        let mut missing = exponents.clone();
        missing.pop();
        assert_eq!(
            validate_zk_ams_t256_galois_key_exponents_v1(&schedule, &missing),
            Err(ZkAmsMkheErrorV1::MissingEvaluatedKey)
        );
        let mut duplicate = schedule.clone();
        duplicate.entries[1].exponent = duplicate.entries[0].exponent;
        duplicate.digest = galois_key_schedule_digest(&duplicate).unwrap();
        assert_eq!(
            validate_zk_ams_t256_galois_key_schedule_v1(&duplicate),
            Err(ZkAmsMkheErrorV1::InvalidKeyMaterial)
        );
        let mut reordered = schedule.clone();
        reordered.entries.swap(0, 1);
        reordered.digest = galois_key_schedule_digest(&reordered).unwrap();
        assert_eq!(
            validate_zk_ams_t256_galois_key_schedule_v1(&reordered),
            Err(ZkAmsMkheErrorV1::InvalidKeyMaterial)
        );
    }
    #[test]
    fn layout_caps_profile_binding_and_partial_chunk_semantics_fail_closed() {
        assert_eq!(
            zk_ams_t256_packing_layout_v1(0),
            Err(ZkAmsMkheErrorV1::InvalidPolynomial)
        );
        assert_eq!(
            zk_ams_t256_packing_layout_v1(ZK_AMS_T256_MAX_LOGICAL_VALUES_V1 + 1),
            Err(ZkAmsMkheErrorV1::ResourceCeilingExceeded)
        );
        assert_eq!(
            zk_ams_t256_packing_layout_v1(u32::MAX),
            Err(ZkAmsMkheErrorV1::ResourceCeilingExceeded)
        );
        let maximum = zk_ams_t256_packing_layout_v1(ZK_AMS_T256_MAX_LOGICAL_VALUES_V1).unwrap();
        assert_eq!(maximum.chunk_count, 16);
        assert_eq!(maximum.final_chunk_used_slots, 65_536);
        let partial = zk_ams_t256_packing_layout_v1(65_537).unwrap();
        assert_eq!(partial.chunk_count, 2);
        assert_eq!(partial.final_chunk_used_slots, 1);
        let mut wrong_profile = partial;
        wrong_profile.profile_digest[0] ^= 1;
        wrong_profile.digest = packing_layout_digest(wrong_profile).unwrap();
        assert_eq!(
            validate_layout(wrong_profile),
            Err(ZkAmsMkheErrorV1::InvalidProfile)
        );
        let mut wrong_count = partial;
        wrong_count.chunk_count = u32::MAX;
        wrong_count.digest = packing_layout_digest(wrong_count).unwrap();
        assert_eq!(
            validate_layout(wrong_count),
            Err(ZkAmsMkheErrorV1::InvalidPolynomial)
        );
        let tail_rotation =
            zk_ams_t256_rotation_v1(partial, 1, 1, ZkAmsT256RotationDirectionV1::Forward).unwrap();
        let mut padded = vec![[0_u8; 32]; ZK_AMS_MKHE_RELEASE_SLOT_COUNT_V1];
        padded[0] = Scalar::one().to_be_bytes();
        assert_eq!(
            permute_zk_ams_t256_slots_v1(partial, tail_rotation, &padded),
            Err(ZkAmsMkheErrorV1::InvalidPolynomial)
        );
        let identity =
            zk_ams_t256_rotation_v1(partial, 1, 0, ZkAmsT256RotationDirectionV1::Inverse).unwrap();
        assert_eq!(
            permute_zk_ams_t256_slots_v1(partial, identity, &padded).unwrap(),
            padded
        );
    }
    #[test]
    fn release_packing_evidence_accepts_only_its_recorded_profile() {
        let profile = release_profile_v1();
        let digest = release_packing_evidence_profile_digest_v1(&profile)
            .expect("the existing packing evidence records this exact profile");
        assert_eq!(digest, RELEASE_PACKING_EVIDENCE_PROFILE_DIGEST_V1);
        let certificate = zk_ams_t256_release_packing_certificate_v1().unwrap();
        assert_eq!(certificate.profile_digest, digest);
        validate_release_packing_certificate(certificate).unwrap();
    }
    #[test]
    fn release_packing_evidence_rejects_changed_profile_without_relabeling() {
        let baseline = release_profile_v1();
        let mut changed_id = baseline.clone();
        changed_id.profile_id[0] ^= 1;
        let mut changed_distribution = baseline.clone();
        changed_distribution.error_eta = 3;
        let mut changed_resource_policy = baseline.clone();
        changed_resource_policy.max_work_units += 1;
        let mut changed_modulus_chain = baseline.clone();
        changed_modulus_chain.moduli =
            &super::super::rns_native_profile::ZK_AMS_MKHE_RNS_NATIVE_MODULI_V1;
        changed_modulus_chain.negacyclic_roots =
            &super::super::rns_native_profile::ZK_AMS_MKHE_RNS_NATIVE_NEGACYCLIC_ROOTS_V1;
        changed_modulus_chain.gadget_digits = changed_modulus_chain.moduli.len();
        for changed in [
            changed_id,
            changed_distribution,
            changed_resource_policy,
            changed_modulus_chain,
        ] {
            changed
                .validate()
                .expect("the changed candidate is well formed");
            assert_ne!(changed.digest().unwrap(), baseline.digest().unwrap());
            assert_eq!(
                release_packing_evidence_profile_digest_v1(&changed),
                Err(ZkAmsMkheErrorV1::InvalidProfile)
            );
        }
    }
    #[test]
    fn release_packing_certificate_binds_every_kat_axis() {
        let certificate =
            zk_ams_t256_release_packing_certificate_v1().expect("release packing certificate");
        assert_eq!(certificate.version, PACKING_VERSION_V1);
        assert_eq!(
            certificate.ring_degree as usize,
            ZK_AMS_MKHE_RELEASE_RING_DEGREE_V1
        );
        assert_eq!(
            certificate.slot_count as usize,
            ZK_AMS_MKHE_RELEASE_SLOT_COUNT_V1
        );
        assert_eq!(
            usize::from(certificate.galois_key_count),
            ZK_AMS_T256_GALOIS_KEY_COUNT_V1
        );
        assert_eq!(
            certificate.subfield_conjugation_exponent,
            u32::try_from(2 * ZK_AMS_MKHE_RELEASE_RING_DEGREE_V1 - 1).unwrap()
        );
        assert_ne!(certificate.subfield_relation_digest, [0; 32]);
        assert_eq!(
            certificate.negative_case_count,
            ZK_AMS_T256_RELEASE_PACKING_NEGATIVE_CASE_COUNT_V1
        );
        assert_ne!(certificate.digest, [0; 32]);
        let mut mutations = Vec::new();
        macro_rules! rebound_mutation {
            ($field:ident, $value:expr) => {{
                let mut mutation = certificate;
                mutation.$field = $value;
                mutation.digest = release_packing_certificate_digest(mutation);
                mutations.push(mutation);
            }};
        }
        rebound_mutation!(version, certificate.version + 1);
        rebound_mutation!(profile_digest, [0; 32]);
        rebound_mutation!(ring_degree, certificate.ring_degree - 1);
        rebound_mutation!(slot_count, certificate.slot_count - 1);
        rebound_mutation!(layout_digest, [0; 32]);
        rebound_mutation!(root_digest, [0; 32]);
        rebound_mutation!(
            subfield_conjugation_exponent,
            certificate.subfield_conjugation_exponent - 2
        );
        rebound_mutation!(subfield_relation_digest, [0; 32]);
        rebound_mutation!(rotation_digest, [0; 32]);
        rebound_mutation!(galois_key_count, certificate.galois_key_count - 1);
        rebound_mutation!(galois_key_schedule_digest, [0; 32]);
        rebound_mutation!(packed_input_kat_digest, [0; 32]);
        rebound_mutation!(packed_output_kat_digest, [0; 32]);
        rebound_mutation!(transformed_rns_kat_digest, [0; 32]);
        rebound_mutation!(rotation_certificate_kat_digest, [0; 32]);
        rebound_mutation!(negative_case_count, certificate.negative_case_count - 1);
        rebound_mutation!(negative_kat_digest, [0; 32]);
        for mutation in mutations {
            assert_eq!(
                validate_release_packing_certificate(mutation),
                Err(ZkAmsMkheErrorV1::InvalidProfile)
            );
        }
        let mut corrupted_digest = certificate;
        corrupted_digest.digest[0] ^= 1;
        assert_eq!(
            validate_release_packing_certificate(corrupted_digest),
            Err(ZkAmsMkheErrorV1::InvalidProfile)
        );
    }
    #[test]
    fn release_degree_packing_rotation_rns_and_adversarial_kats_are_pinned() {
        let coefficients = release_sparse_cosine_coefficients();
        let slot_scalars =
            decode_coefficients(&coefficients, ZK_AMS_MKHE_RELEASE_RING_DEGREE_V1).unwrap();
        let slots = slot_scalars
            .into_iter()
            .map(Scalar::to_be_bytes)
            .collect::<Vec<_>>();
        assert_eq!(slots.len(), ZK_AMS_MKHE_RELEASE_SLOT_COUNT_V1);
        let layout = zk_ams_t256_packing_layout_v1(65_536).unwrap();
        let packed = encode_zk_ams_t256_packed_plaintext_v1(layout, 0, &slots).unwrap();
        assert_eq!(
            packed.coefficients,
            coefficients
                .iter()
                .copied()
                .map(Scalar::to_be_bytes)
                .collect::<Vec<_>>()
        );
        assert_eq!(
            packed.digest,
            ZK_AMS_T256_RELEASE_PACKED_INPUT_KAT_DIGEST_V1
        );
        let profile = release_profile_v1();
        assert_eq!(profile.moduli.len(), 38);
        let native =
            ZeroizingPackedRnsBindingV1(packed_plaintext_to_rns_v1(layout, &packed).unwrap());
        let native_binding_digest = rns_polynomial_digest(&profile, &native.0).unwrap();
        assert_ne!(native_binding_digest, [0; 32]);
        let workspace_drops_before = packing_workspace_zeroized_drop_count_v1();
        let plaintext =
            ValidatedT256PackedPlaintextV1::validate_for_release_limb_stream_v1(layout, &packed)
                .unwrap();
        assert_eq!(
            packing_workspace_zeroized_drop_count_v1(),
            workspace_drops_before + 1,
            "the validated view must erase its decoder workspace"
        );
        let mut streamed = T256PackedRnsBindingHasherV1::new(plaintext).unwrap();
        let limb_drops_before = t256_release_limb_zeroized_drop_count_v1();
        let mut limb_owner = ZeroizingT256ReleaseLimbV1::new_zeroed_v1().unwrap();
        assert_eq!(
            streamed.absorb_next_release_limb_into_v1(1, &mut limb_owner),
            Err(ZkAmsMkheErrorV1::InvalidPolynomial)
        );
        assert!(limb_owner.coefficients.iter().all(|value| *value == 0));
        assert!(limb_owner.filled_v1().is_err());
        for limb in 0..RELEASE_MODULI_V1.len() {
            if limb == 1 {
                assert_eq!(
                    streamed.absorb_next_release_limb_into_v1(0, &mut limb_owner),
                    Err(ZkAmsMkheErrorV1::InvalidPolynomial)
                );
                let unchanged = limb_owner.filled_v1().unwrap();
                assert_eq!(unchanged.limb_v1(), 0);
                assert_eq!(unchanged.modulus_v1(), profile.moduli[0]);
                assert_eq!(unchanged.coefficients_v1(), native.0.limb(&profile, 0));
            }
            streamed
                .absorb_next_release_limb_into_v1(limb, &mut limb_owner)
                .unwrap();
            let filled = limb_owner.filled_v1().unwrap();
            assert_eq!(filled.limb_v1(), limb);
            assert_eq!(filled.modulus_v1(), profile.moduli[limb]);
            assert_eq!(filled.coefficients_v1(), native.0.limb(&profile, limb));
        }
        assert_eq!(
            streamed.absorb_next_release_limb_into_v1(RELEASE_MODULI_V1.len(), &mut limb_owner),
            Err(ZkAmsMkheErrorV1::InvalidPolynomial)
        );
        let terminal = limb_owner.filled_v1().unwrap();
        assert_eq!(terminal.limb_v1(), RELEASE_MODULI_V1.len() - 1);
        assert_eq!(terminal.modulus_v1(), *profile.moduli.last().unwrap());
        assert_eq!(
            terminal.coefficients_v1(),
            native.0.limb(&profile, RELEASE_MODULI_V1.len() - 1)
        );
        assert_eq!(streamed.finish().unwrap(), native_binding_digest);
        drop(native);
        drop(limb_owner);
        assert_eq!(
            t256_release_limb_zeroized_drop_count_v1(),
            limb_drops_before + 1
        );
        let early_plaintext = ValidatedT256PackedPlaintextV1 {
            layout,
            packed: &packed,
        };
        assert_eq!(
            T256PackedRnsBindingHasherV1::new(early_plaintext)
                .unwrap()
                .finish(),
            Err(ZkAmsMkheErrorV1::InvalidPolynomial)
        );
        let mut stale_coefficient_digest = packed.clone();
        stale_coefficient_digest.coefficients[0][31] ^= 1;
        assert_eq!(
            packed_plaintext_rns_binding_digest_v1(layout, &stale_coefficient_digest),
            Err(ZkAmsMkheErrorV1::InvalidPolynomial)
        );
        assert!(matches!(
            ValidatedT256PackedPlaintextV1::validate_for_release_limb_stream_v1(
                layout,
                &stale_coefficient_digest
            ),
            Err(ZkAmsMkheErrorV1::InvalidPolynomial)
        ));
        let mut stale_metadata_digest = packed.clone();
        stale_metadata_digest.used_slots -= 1;
        assert_eq!(
            packed_plaintext_rns_binding_digest_v1(layout, &stale_metadata_digest),
            Err(ZkAmsMkheErrorV1::InvalidPolynomial)
        );
        let mut noncanonical_binding = packed.clone();
        noncanonical_binding.used_slots -= 1;
        noncanonical_binding.digest = packed_plaintext_digest(&noncanonical_binding).unwrap();
        assert_eq!(
            packed_plaintext_rns_binding_digest_v1(layout, &noncanonical_binding),
            Err(ZkAmsMkheErrorV1::InvalidPolynomial)
        );
        assert_eq!(
            decode_zk_ams_t256_packed_plaintext_v1(layout, &packed).unwrap(),
            slots
        );
        let conjugation_exponent =
            usize::try_from(zk_ams_t256_packed_subfield_conjugation_exponent_v1().unwrap())
                .unwrap();
        let packed_scalars = packed
            .coefficients
            .iter()
            .copied()
            .map(|coefficient| Scalar::from_be_bytes_exact(coefficient).unwrap())
            .collect::<Vec<_>>();
        assert_eq!(
            automorphism_coefficients(&packed_scalars, conjugation_exponent).unwrap(),
            packed_scalars
        );
        let rotation =
            zk_ams_t256_rotation_v1(layout, 0, 0xA55A, ZkAmsT256RotationDirectionV1::Inverse)
                .unwrap();
        assert_eq!(rotation.exponent, 44_681);
        let oracle = permute_zk_ams_t256_slots_v1(layout, rotation, &slots).unwrap();
        let transformed =
            rotate_zk_ams_t256_packed_plaintext_v1(layout, &packed, rotation).unwrap();
        assert_eq!(
            transformed.digest,
            ZK_AMS_T256_RELEASE_PACKED_OUTPUT_KAT_DIGEST_V1
        );
        assert_eq!(
            decode_zk_ams_t256_packed_plaintext_v1(layout, &transformed).unwrap(),
            oracle
        );
        let inverse = zk_ams_t256_rotation_v1(
            layout,
            0,
            rotation.steps,
            ZkAmsT256RotationDirectionV1::Forward,
        )
        .unwrap();
        assert_eq!(
            rotate_zk_ams_t256_packed_plaintext_v1(layout, &transformed, inverse).unwrap(),
            packed
        );
        let certificate = zk_ams_t256_rotation_certificate_v1(layout, &packed, rotation).unwrap();
        assert_eq!(
            certificate.galois_key_schedule_digest,
            ZK_AMS_T256_GALOIS_KEY_SCHEDULE_DIGEST_V1
        );
        assert_eq!(
            certificate.transformed_rns_digest,
            ZK_AMS_T256_RELEASE_TRANSFORMED_RNS_KAT_DIGEST_V1
        );
        assert_eq!(
            certificate.digest,
            ZK_AMS_T256_RELEASE_ROTATION_CERTIFICATE_KAT_DIGEST_V1
        );
        let schedule = zk_ams_t256_galois_key_schedule_v1().unwrap();
        let exponents = schedule
            .entries
            .iter()
            .map(|entry| entry.exponent)
            .collect::<Vec<_>>();
        let mut negative = NegativePackingKatV1::new();
        record_negative(
            &mut negative,
            b"layout.zero",
            zk_ams_t256_packing_layout_v1(0),
            ZkAmsMkheErrorV1::InvalidPolynomial,
        );
        record_negative(
            &mut negative,
            b"layout.resource",
            zk_ams_t256_packing_layout_v1(ZK_AMS_T256_MAX_LOGICAL_VALUES_V1 + 1),
            ZkAmsMkheErrorV1::ResourceCeilingExceeded,
        );
        record_negative(
            &mut negative,
            b"slots.short",
            permute_zk_ams_t256_slots_v1(layout, rotation, &slots[..slots.len() - 1]),
            ZkAmsMkheErrorV1::InvalidPolynomial,
        );
        {
            let mut noncanonical_slots = slots.clone();
            noncanonical_slots[0] = crate::vega::VEGA_T256_SCALAR_MODULUS_BE_V1;
            record_negative(
                &mut negative,
                b"slots.noncanonical",
                permute_zk_ams_t256_slots_v1(layout, rotation, &noncanonical_slots),
                ZkAmsMkheErrorV1::InvalidPolynomial,
            );
        }
        let partial_layout = zk_ams_t256_packing_layout_v1(1).unwrap();
        {
            let mut nonzero_padding = vec![[0_u8; 32]; ZK_AMS_MKHE_RELEASE_SLOT_COUNT_V1];
            nonzero_padding[0] = Scalar::one().to_be_bytes();
            nonzero_padding[1] = Scalar::one().to_be_bytes();
            record_negative(
                &mut negative,
                b"padding.nonzero",
                encode_zk_ams_t256_packed_plaintext_v1(partial_layout, 0, &nonzero_padding),
                ZkAmsMkheErrorV1::InvalidPolynomial,
            );
        }
        {
            let mut mutation = packed.clone();
            mutation.profile_digest[0] ^= 1;
            mutation.digest = packed_plaintext_digest(&mutation).unwrap();
            record_negative(
                &mut negative,
                b"packed.profile",
                decode_zk_ams_t256_packed_plaintext_v1(layout, &mutation),
                ZkAmsMkheErrorV1::InvalidPolynomial,
            );
        }
        {
            let mut mutation = packed.clone();
            mutation.layout_digest[0] ^= 1;
            mutation.digest = packed_plaintext_digest(&mutation).unwrap();
            record_negative(
                &mut negative,
                b"packed.layout",
                decode_zk_ams_t256_packed_plaintext_v1(layout, &mutation),
                ZkAmsMkheErrorV1::InvalidPolynomial,
            );
        }
        {
            let mut mutation = packed.clone();
            mutation.chunk_index = 1;
            mutation.digest = packed_plaintext_digest(&mutation).unwrap();
            record_negative(
                &mut negative,
                b"packed.chunk",
                decode_zk_ams_t256_packed_plaintext_v1(layout, &mutation),
                ZkAmsMkheErrorV1::InvalidPolynomial,
            );
        }
        {
            let mut mutation = packed.clone();
            mutation.used_slots -= 1;
            mutation.digest = packed_plaintext_digest(&mutation).unwrap();
            record_negative(
                &mut negative,
                b"packed.used",
                decode_zk_ams_t256_packed_plaintext_v1(layout, &mutation),
                ZkAmsMkheErrorV1::InvalidPolynomial,
            );
        }
        {
            let mut mutation = packed.clone();
            mutation.digest[0] ^= 1;
            record_negative(
                &mut negative,
                b"packed.digest",
                decode_zk_ams_t256_packed_plaintext_v1(layout, &mutation),
                ZkAmsMkheErrorV1::InvalidPolynomial,
            );
        }
        {
            let mut mutation = packed.clone();
            mutation.coefficients.pop();
            record_negative(
                &mut negative,
                b"packed.truncated",
                decode_zk_ams_t256_packed_plaintext_v1(layout, &mutation),
                ZkAmsMkheErrorV1::InvalidPolynomial,
            );
        }
        {
            let mut mutation = packed.clone();
            mutation.coefficients.push([0; 32]);
            record_negative(
                &mut negative,
                b"packed.extended",
                decode_zk_ams_t256_packed_plaintext_v1(layout, &mutation),
                ZkAmsMkheErrorV1::InvalidPolynomial,
            );
        }
        {
            let mut mutation = packed.clone();
            mutation.coefficients[0] = crate::vega::VEGA_T256_SCALAR_MODULUS_BE_V1;
            mutation.digest = packed_plaintext_digest(&mutation).unwrap();
            record_negative(
                &mut negative,
                b"packed.coefficient",
                decode_zk_ams_t256_packed_plaintext_v1(layout, &mutation),
                ZkAmsMkheErrorV1::InvalidPolynomial,
            );
        }
        {
            let mut mutation = packed.clone();
            let coefficient = Scalar::from_be_bytes_exact(mutation.coefficients[1]).unwrap();
            mutation.coefficients[1] = (coefficient + Scalar::one()).to_be_bytes();
            mutation.digest = packed_plaintext_digest(&mutation).unwrap();
            record_negative(
                &mut negative,
                b"packed.non-subfield",
                packed_plaintext_to_rns_v1(layout, &mutation),
                ZkAmsMkheErrorV1::InvalidPolynomial,
            );
        }
        {
            assert!(slots[1..].iter().any(|slot| *slot != [0; 32]));
            let mut mutation = packed.clone();
            mutation.layout_digest = partial_layout.digest;
            mutation.used_slots = 1;
            mutation.digest = packed_plaintext_digest(&mutation).unwrap();
            let workspace_drops_before = packing_workspace_zeroized_drop_count_v1();
            let actual = match ValidatedT256PackedPlaintextV1::validate_for_release_limb_stream_v1(
                partial_layout,
                &mutation,
            ) {
                Ok(_) => panic!("nonzero decoded padding must fail closed"),
                Err(error) => error,
            };
            assert_eq!(actual, ZkAmsMkheErrorV1::InvalidPolynomial);
            assert_eq!(
                packing_workspace_zeroized_drop_count_v1(),
                workspace_drops_before + 1,
                "decoder workspace must erase on padding rejection"
            );
            negative.record(b"decode.padding", actual);
        }
        record_negative(
            &mut negative,
            b"rotation.steps",
            zk_ams_t256_rotation_v1(layout, 0, 65_536, ZkAmsT256RotationDirectionV1::Forward),
            ZkAmsMkheErrorV1::InvalidKeyMaterial,
        );
        {
            let mut mutation = rotation;
            mutation.exponent = 2;
            mutation.digest = rotation_digest(mutation).unwrap();
            record_negative(
                &mut negative,
                b"rotation.exponent-even",
                zk_ams_t256_rotation_key_plan_v1(layout, mutation, &schedule),
                ZkAmsMkheErrorV1::InvalidKeyMaterial,
            );
        }
        {
            let mut mutation = rotation;
            mutation.exponent = 2 * ZK_AMS_MKHE_RELEASE_RING_DEGREE_V1 as u32 + 1;
            mutation.digest = rotation_digest(mutation).unwrap();
            record_negative(
                &mut negative,
                b"rotation.exponent-range",
                zk_ams_t256_rotation_key_plan_v1(layout, mutation, &schedule),
                ZkAmsMkheErrorV1::InvalidKeyMaterial,
            );
        }
        {
            let mut mutation = rotation;
            mutation.direction = ZkAmsT256RotationDirectionV1::Forward;
            mutation.digest = rotation_digest(mutation).unwrap();
            record_negative(
                &mut negative,
                b"rotation.direction",
                zk_ams_t256_rotation_key_plan_v1(layout, mutation, &schedule),
                ZkAmsMkheErrorV1::InvalidKeyMaterial,
            );
        }
        {
            let mut mutation = rotation;
            mutation.used_slots -= 1;
            mutation.digest = rotation_digest(mutation).unwrap();
            record_negative(
                &mut negative,
                b"rotation.used",
                zk_ams_t256_rotation_key_plan_v1(layout, mutation, &schedule),
                ZkAmsMkheErrorV1::InvalidKeyMaterial,
            );
        }
        {
            let other_layout = zk_ams_t256_packing_layout_v1(65_537).unwrap();
            record_negative(
                &mut negative,
                b"rotation.cross-layout",
                zk_ams_t256_rotation_key_plan_v1(other_layout, rotation, &schedule),
                ZkAmsMkheErrorV1::InvalidKeyMaterial,
            );
            let mut rebound = packed.clone();
            rebound.layout_digest = other_layout.digest;
            rebound.digest = packed_plaintext_digest(&rebound).unwrap();
            let other_rotation =
                zk_ams_t256_rotation_v1(other_layout, 1, 0, ZkAmsT256RotationDirectionV1::Forward)
                    .unwrap();
            record_negative(
                &mut negative,
                b"rotation.cross-chunk",
                rotate_zk_ams_t256_packed_plaintext_v1(other_layout, &rebound, other_rotation),
                ZkAmsMkheErrorV1::InvalidPolynomial,
            );
        }
        record_negative(
            &mut negative,
            b"schedule.missing",
            validate_zk_ams_t256_galois_key_exponents_v1(
                &schedule,
                &exponents[..exponents.len() - 1],
            ),
            ZkAmsMkheErrorV1::MissingEvaluatedKey,
        );
        {
            let mut extra = exponents.clone();
            extra.push(1);
            record_negative(
                &mut negative,
                b"schedule.extra",
                validate_zk_ams_t256_galois_key_exponents_v1(&schedule, &extra),
                ZkAmsMkheErrorV1::MissingEvaluatedKey,
            );
        }
        {
            let mut mutation = schedule.clone();
            mutation.entries[1].exponent = mutation.entries[0].exponent;
            mutation.digest = galois_key_schedule_digest(&mutation).unwrap();
            record_negative(
                &mut negative,
                b"schedule.duplicate",
                validate_zk_ams_t256_galois_key_schedule_v1(&mutation),
                ZkAmsMkheErrorV1::InvalidKeyMaterial,
            );
        }
        {
            let mut mutation = schedule.clone();
            mutation.entries.swap(0, 1);
            mutation.digest = galois_key_schedule_digest(&mutation).unwrap();
            record_negative(
                &mut negative,
                b"schedule.reordered",
                validate_zk_ams_t256_galois_key_schedule_v1(&mutation),
                ZkAmsMkheErrorV1::InvalidKeyMaterial,
            );
        }
        {
            let mut mutation = certificate;
            mutation.digest[0] ^= 1;
            record_negative(
                &mut negative,
                b"certificate.digest",
                validate_rotation_certificate(layout, &packed, rotation, &schedule, mutation),
                ZkAmsMkheErrorV1::InvalidPolynomial,
            );
        }
        {
            let mut mutation = certificate;
            mutation.profile_digest[0] ^= 1;
            mutation.digest = rotation_certificate_digest(mutation);
            record_negative(
                &mut negative,
                b"certificate.profile",
                validate_rotation_certificate(layout, &packed, rotation, &schedule, mutation),
                ZkAmsMkheErrorV1::InvalidPolynomial,
            );
        }
        {
            let partial_rotation = zk_ams_t256_rotation_v1(
                partial_layout,
                0,
                1,
                ZkAmsT256RotationDirectionV1::Forward,
            )
            .unwrap();
            let mut padded = vec![[0_u8; 32]; ZK_AMS_MKHE_RELEASE_SLOT_COUNT_V1];
            padded[0] = Scalar::one().to_be_bytes();
            record_negative(
                &mut negative,
                b"partial.rotation",
                permute_zk_ams_t256_slots_v1(partial_layout, partial_rotation, &padded),
                ZkAmsMkheErrorV1::InvalidPolynomial,
            );
        }
        {
            let mut mutation = layout;
            mutation.profile_digest[0] ^= 1;
            mutation.digest = packing_layout_digest(mutation).unwrap();
            record_negative(
                &mut negative,
                b"profile.layout",
                validate_layout(mutation),
                ZkAmsMkheErrorV1::InvalidProfile,
            );
        }
        {
            let mut mutation = schedule.clone();
            mutation.profile_digest[0] ^= 1;
            mutation.digest = galois_key_schedule_digest(&mutation).unwrap();
            record_negative(
                &mut negative,
                b"profile.schedule",
                validate_zk_ams_t256_galois_key_schedule_v1(&mutation),
                ZkAmsMkheErrorV1::InvalidKeyMaterial,
            );
        }
        let (negative_digest, negative_case_count) = negative.finalize();
        assert_eq!(
            negative_case_count,
            ZK_AMS_T256_RELEASE_PACKING_NEGATIVE_CASE_COUNT_V1
        );
        assert_eq!(
            negative_digest,
            ZK_AMS_T256_RELEASE_PACKING_NEGATIVE_KAT_DIGEST_V1
        );
    }
}
