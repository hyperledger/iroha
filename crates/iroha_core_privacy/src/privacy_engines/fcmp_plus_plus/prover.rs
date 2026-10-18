//! Canonical native FCMP++ prover.
//!
//! The public API accepts an output-opening and a complete alternating tree path for each input.
//! Re-randomization, branch blinding, divisor construction, both arithmetic-circuit proofs, SAL,
//! root-blind proof, and IFC1 framing are all produced here; callers cannot inject opaque
//! precomputed circuit witnesses.
#[cfg(test)]
use super::field::edwards_to_wei25519;
use super::field::{
    HELIOS_GENERATOR_COUNT_V1, SELENE_GENERATOR_COUNT_V1, SecretCycleCoordinatesV1,
    SecretCycleScalarV1, SecretEncodedScalarV1, encode_secret_field25519_scalar_v1,
    encode_secret_helioselene_scalar_v1, helios_generators, helios_hash_initializer,
    selene_generators, selene_hash_initializer,
};
use super::{
    FCMP_LAYER_ONE_LEN_V1, FCMP_LAYER_TWO_LEN_V1, FCMP_MAX_TREE_LAYERS_V1,
    FCMP_PROOF_WIRE_HEADER_BYTES_V1, FcmpNativeErrorV1, FcmpOutputCommitmentOpeningV1,
    FcmpOutputTupleV1, FcmpProofInputPublicV1, FcmpSalWitnessV1, FcmpSecretOutputIdV1,
    FcmpTreeCurveV1, FcmpTreeRootV1,
    bulletproof::Variable,
    circuit::{
        CYCLE_DLOG_PARAMETERS, Circuit, ED25519_DLOG_PARAMETERS, PointWithDlog,
        ProverVectorCommitmentTape,
    },
    divisor::{
        NormalizedDivisor, ed25519_scalar_decomposition, scalar_decomposition, scalar_mul_divisor,
    },
    field::{
        Field25519, HeliosPoint, HelioseleneField, SelenePoint, decode_secret_field25519_scalar_v1,
        decode_secret_helioselene_scalar_v1, secret_edwards_to_wei25519_v1,
    },
    membership::{
        TranscriptedInput, constrain_input, ed25519_curve, helios_curve, membership_context,
        native_parameters, selene_curve,
    },
    proof_math::{
        FcmpProofRandomSource, HeliosSuite, ProofPoint, ProofScalar, ProofSuite, ProverTranscript,
        SecretMultiexpBuilder, SecretPoint, SeleneSuite, helios_bp_generators,
        random_scalar_from_fcmp_rng, selene_bp_generators,
    },
    range::prove_fcmp_range_with_checked_rng_v1,
    sal::{
        FcmpSalSecretScalarEncodingV1, generator_t, generator_u, generator_v,
        prove_fcmp_sal_with_checked_rng_v1,
    },
    wire::{FCMP_PROOF_WIRE_MAGIC_V1, fcmp_plus_plus_wire_size_v1, ipa_rows},
};
use curve25519_dalek::{
    constants::ED25519_BASEPOINT_POINT,
    edwards::{CompressedEdwardsY, EdwardsPoint},
    scalar::Scalar,
    traits::Identity,
};
use p256::elliptic_curve::subtle::{Choice, ConstantTimeEq as _, ConstantTimeLess as _};
use rand_core_06::{CryptoRng, RngCore};
use zeroize::{Zeroize, Zeroizing};
const MAX_PROVER_SCALAR_ATTEMPTS_V1: usize = 128;
const MAX_MEMBERSHIP_PROVER_RESTARTS_V1: usize = 128;
struct ProverSecretCopyValueV1<T: Copy + Zeroize>(T);
struct BorrowedProverCopySlotV1<'a, T: Copy + Zeroize>(&'a mut T);
impl<T: Copy + Zeroize> BorrowedProverCopySlotV1<'_, T> {
    fn expose_copy(&self) -> T {
        *self.0
    }
}
impl<T: Copy + Zeroize> Drop for BorrowedProverCopySlotV1<'_, T> {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}
impl<T: Copy + Zeroize> ProverSecretCopyValueV1<T> {
    fn new(mut value: T) -> Self {
        Self::take(&mut value)
    }
    fn take(value: &mut T) -> Self {
        let incoming = BorrowedProverCopySlotV1(value);
        let owned = Self(incoming.expose_copy());
        drop(incoming);
        owned
    }
    fn expose_copy(&self) -> T {
        self.0
    }
    fn expose_ref(&self) -> &T {
        &self.0
    }
}
impl<T: Copy + Zeroize> Drop for ProverSecretCopyValueV1<T> {
    fn drop(&mut self) {
        self.0.zeroize();
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
        let _ = core::hint::black_box(&mut self.0);
        #[cfg(test)]
        let _ = PROVER_SECRET_COPY_OWNER_DROPS_V1.try_with(|drops| {
            drops.set(drops.get().saturating_add(1));
        });
    }
}
#[cfg(test)]
std::thread_local! {
    #[cfg(test)]
    static PROVER_SECRET_COPY_OWNER_DROPS_V1: std::cell::Cell<usize> =
        const { std::cell::Cell::new(0) };
}
/// Clears one prover-owned scalar on success, error, and unwind.
struct ProverSecretScalarV1<F: ProofScalar>(F);
#[cfg(test)]
struct BorrowedProverScalarSlotV1<'a, F: ProofScalar>(&'a mut F);
#[cfg(test)]
impl<F: ProofScalar> BorrowedProverScalarSlotV1<'_, F> {
    fn expose_copy(&self) -> F {
        *self.0
    }
}
#[cfg(test)]
impl<F: ProofScalar> Drop for BorrowedProverScalarSlotV1<'_, F> {
    fn drop(&mut self) {
        self.0.clear_secret();
    }
}
impl<F: ProofScalar> ProverSecretScalarV1<F> {
    fn copy_from_borrowed(value: &F) -> Self {
        Self(*value)
    }
    fn negated_owner_v1(&self) -> Self {
        Self(-self.0)
    }
    #[cfg(test)]
    fn take(value: &mut F) -> Self {
        let incoming = BorrowedProverScalarSlotV1(value);
        let owned = Self(incoming.expose_copy());
        drop(incoming);
        owned
    }
    fn expose_ref(&self) -> &F {
        &self.0
    }
    fn add_product_assign(&mut self, left: &F, right: &F) {
        self.0 += *left * *right;
    }
}
impl ProverSecretScalarV1<Field25519> {
    /// Publish the root-blind response and immediately erase the mutated nonce
    /// slot through the audited Field25519 encoding owner.
    fn encode_public_and_clear_v1(&mut self) -> [u8; 32] {
        let original = Self(core::mem::replace(&mut self.0, Field25519::ZERO));
        let encoded = encode_secret_field25519_scalar_v1(original.expose_ref());
        let public = *encoded.as_ref();
        drop(encoded);
        drop(original);
        public
    }
}
impl ProverSecretScalarV1<HelioseleneField> {
    /// Helioselene counterpart of the owner-confined root-response publication.
    fn encode_public_and_clear_v1(&mut self) -> [u8; 32] {
        let original = Self(core::mem::replace(&mut self.0, HelioseleneField::ZERO));
        let encoded = encode_secret_helioselene_scalar_v1(original.expose_ref());
        let public = *encoded.as_ref();
        drop(encoded);
        drop(original);
        public
    }
}
impl<F: ProofScalar> Drop for ProverSecretScalarV1<F> {
    fn drop(&mut self) {
        self.0.clear_secret();
        #[cfg(test)]
        let _ = PROVER_SECRET_SCALAR_OWNER_DROPS_V1.try_with(|drops| {
            drops.set(drops.get().saturating_add(1));
        });
    }
}
#[cfg(test)]
std::thread_local! {
    #[cfg(test)]
    static PROVER_SECRET_SCALAR_OWNER_DROPS_V1: std::cell::Cell<usize> =
        const { std::cell::Cell::new(0) };
}
fn prover_secret_edwards_scalar_sum_v1(
    left: &Scalar,
    right: &Scalar,
) -> ProverSecretCopyValueV1<Scalar> {
    let mut sum = left + right;
    ProverSecretCopyValueV1::take(&mut sum)
}
struct ProverSecretPointV1<P: ProofPoint>(P);
#[cfg(test)]
struct BorrowedProverPointSlotV1<'a, P: ProofPoint>(&'a mut P);
#[cfg(test)]
impl<P: ProofPoint> BorrowedProverPointSlotV1<'_, P> {
    fn expose_copy(&self) -> P {
        *self.0
    }
}
#[cfg(test)]
impl<P: ProofPoint> Drop for BorrowedProverPointSlotV1<'_, P> {
    fn drop(&mut self) {
        self.0.clear_secret();
    }
}
impl<P: ProofPoint> ProverSecretPointV1<P> {
    fn from_secret(point: SecretPoint<P>) -> Self {
        let mut owned = Self(P::identity());
        point.move_into(&mut owned.0);
        owned
    }
    #[cfg(test)]
    fn take(value: &mut P) -> Self {
        let incoming = BorrowedProverPointSlotV1(value);
        let owned = Self(incoming.expose_copy());
        drop(incoming);
        owned
    }
    fn expose_ref(&self) -> &P {
        &self.0
    }
}
impl ProverSecretPointV1<SelenePoint> {
    fn secret_x_owner_v1(&self) -> Option<SecretCycleScalarV1<HelioseleneField>> {
        self.0.secret_x_ref_v1()
    }
    fn secret_encoding_owner_v1(&self) -> Option<SecretEncodedScalarV1> {
        self.0.secret_encode_ref_v1()
    }
    /// Publish only the canonical root-nonce commitment bytes while the
    /// concrete secret point and its encoding remain in erasing owners.
    fn encode_public_and_clear_v1(&mut self) -> Result<[u8; 32], FcmpNativeErrorV1> {
        let encoded = core::mem::replace(&mut self.0, SelenePoint::identity())
            .secret_encode_v1()
            .ok_or(FcmpNativeErrorV1::CyclePointIdentity)?;
        let public = *encoded.as_ref();
        drop(encoded);
        Ok(public)
    }
}
impl ProverSecretPointV1<HeliosPoint> {
    fn secret_x_owner_v1(&self) -> Option<SecretCycleScalarV1<Field25519>> {
        self.0.secret_x_ref_v1()
    }
    fn secret_encoding_owner_v1(&self) -> Option<SecretEncodedScalarV1> {
        self.0.secret_encode_ref_v1()
    }
    /// Helios counterpart of the owner-confined Selene publication boundary.
    fn encode_public_and_clear_v1(&mut self) -> Result<[u8; 32], FcmpNativeErrorV1> {
        let encoded = core::mem::replace(&mut self.0, HeliosPoint::identity())
            .secret_encode_v1()
            .ok_or(FcmpNativeErrorV1::CyclePointIdentity)?;
        let public = *encoded.as_ref();
        drop(encoded);
        Ok(public)
    }
}
impl<P: ProofPoint> Drop for ProverSecretPointV1<P> {
    fn drop(&mut self) {
        self.0.clear_secret();
        #[cfg(test)]
        let _ = PROVER_SECRET_POINT_OWNER_DROPS_V1.try_with(|drops| {
            drops.set(drops.get().saturating_add(1));
        });
    }
}
#[cfg(test)]
std::thread_local! {
    #[cfg(test)]
    static PROVER_SECRET_POINT_OWNER_DROPS_V1: std::cell::Cell<usize> =
        const { std::cell::Cell::new(0) };
}
fn zeroizing_digest_buffer(
    exact_capacity: usize,
) -> Result<Zeroizing<Vec<[u8; 32]>>, FcmpNativeErrorV1> {
    let mut values = Vec::new();
    values
        .try_reserve_exact(exact_capacity)
        .map_err(|_| FcmpNativeErrorV1::ArithmeticInvariant)?;
    if values.capacity() < exact_capacity {
        return Err(FcmpNativeErrorV1::ArithmeticInvariant);
    }
    Ok(Zeroizing::new(values))
}
fn push_owned_secret_output_id_v1(
    values: &mut Zeroizing<Vec<[u8; 32]>>,
    value: FcmpSecretOutputIdV1,
) -> Result<(), FcmpNativeErrorV1> {
    require_preallocated_push(values.len(), values.capacity())?;
    values.push(*value.as_ref());
    drop(value);
    Ok(())
}
fn push_owned_prover_secret_digest_v1(
    values: &mut Zeroizing<Vec<[u8; 32]>>,
    value: ProverSecretCopyValueV1<[u8; 32]>,
) -> Result<(), FcmpNativeErrorV1> {
    require_preallocated_push(values.len(), values.capacity())?;
    values.push(*value.expose_ref());
    drop(value);
    Ok(())
}
fn zeroizing_exact_secret_buffer_v1<T: Zeroize>(
    exact_capacity: usize,
) -> Result<Zeroizing<Vec<T>>, FcmpNativeErrorV1> {
    let mut values = Vec::new();
    values
        .try_reserve_exact(exact_capacity)
        .map_err(|_| FcmpNativeErrorV1::ArithmeticInvariant)?;
    if values.capacity() < exact_capacity {
        return Err(FcmpNativeErrorV1::ArithmeticInvariant);
    }
    Ok(Zeroizing::new(values))
}
fn push_owned_secret_cycle_scalar_v1<F: ProofScalar + Zeroize>(
    values: &mut Zeroizing<Vec<F>>,
    value: SecretCycleScalarV1<F>,
) -> Result<(), FcmpNativeErrorV1> {
    let allocation_capacity = values.capacity();
    let allocation_ptr = values.as_ptr();
    let preflight = require_preallocated_push(values.len(), allocation_capacity);
    if let Err(error) = preflight {
        drop(value);
        return Err(error);
    }
    debug_assert_eq!(values.capacity(), allocation_capacity);
    debug_assert_eq!(values.as_ptr(), allocation_ptr);
    values.push(F::ZERO);
    let destination = values.len() - 1;
    value.move_into(&mut values[destination]);
    debug_assert_eq!(values.capacity(), allocation_capacity);
    debug_assert_eq!(values.as_ptr(), allocation_ptr);
    Ok(())
}
#[cfg(test)]
fn push_secret_scalar_v1<F: ProofScalar + Zeroize>(
    values: &mut Zeroizing<Vec<F>>,
    mut value: F,
) -> Result<(), FcmpNativeErrorV1> {
    let value = ProverSecretScalarV1::take(&mut value);
    push_owned_secret_scalar_v1(values, value)
}
fn push_owned_secret_scalar_v1<F: ProofScalar + Zeroize>(
    values: &mut Zeroizing<Vec<F>>,
    mut value: ProverSecretScalarV1<F>,
) -> Result<(), FcmpNativeErrorV1> {
    let allocation_capacity = values.capacity();
    let allocation_ptr = values.as_ptr();
    let preflight = require_preallocated_push(values.len(), allocation_capacity);
    if let Err(error) = preflight {
        drop(value);
        return Err(error);
    }
    debug_assert_eq!(values.capacity(), allocation_capacity);
    debug_assert_eq!(values.as_ptr(), allocation_ptr);
    // Install a public zero in the already-reserved destination, then swap the
    // two owned slots. This transfers the secret directly into its final
    // zeroizing vector owner without exposing a bare Copy value or moving a
    // field out of the Drop-bearing source owner.
    values.push(F::ZERO);
    let destination = values.len() - 1;
    core::mem::swap(&mut values[destination], &mut value.0);
    drop(value);
    debug_assert_eq!(values.capacity(), allocation_capacity);
    debug_assert_eq!(values.as_ptr(), allocation_ptr);
    Ok(())
}
fn push_borrowed_secret_scalar_v1<F: ProofScalar + Zeroize>(
    values: &mut Zeroizing<Vec<F>>,
    value: &F,
) -> Result<(), FcmpNativeErrorV1> {
    let allocation_capacity = values.capacity();
    let allocation_ptr = values.as_ptr();
    require_preallocated_push(values.len(), allocation_capacity)?;
    debug_assert_eq!(values.capacity(), allocation_capacity);
    debug_assert_eq!(values.as_ptr(), allocation_ptr);
    let value = ProverSecretScalarV1::copy_from_borrowed(value);
    push_owned_secret_scalar_v1(values, value)?;
    debug_assert_eq!(values.capacity(), allocation_capacity);
    debug_assert_eq!(values.as_ptr(), allocation_ptr);
    Ok(())
}
fn prover_secret_decode_edwards_point_v1(
    bytes: &[u8; 32],
) -> Result<ProverSecretCopyValueV1<EdwardsPoint>, FcmpNativeErrorV1> {
    let compressed = ProverSecretCopyValueV1::new(CompressedEdwardsY(*bytes));
    let point = ProverSecretCopyValueV1::new(
        compressed
            .expose_ref()
            .decompress()
            .ok_or(FcmpNativeErrorV1::EdwardsPointEncoding)?,
    );
    let recompressed = ProverSecretCopyValueV1::new(point.expose_ref().compress());
    if recompressed.expose_ref().as_bytes() != bytes || !point.expose_ref().is_torsion_free() {
        return Err(FcmpNativeErrorV1::EdwardsPointEncoding);
    }
    if point.expose_ref() == &EdwardsPoint::identity() {
        return Err(FcmpNativeErrorV1::EdwardsPointIdentity);
    }
    Ok(point)
}
fn prover_secret_edwards_encoding_v1(point: &EdwardsPoint) -> ProverSecretCopyValueV1<[u8; 32]> {
    let compressed = ProverSecretCopyValueV1::new(point.compress());
    ProverSecretCopyValueV1::new(*compressed.expose_ref().as_bytes())
}
fn prover_secret_key_image_id_v1(
    linking_bytes: &[u8; 32],
    spend_x: &Scalar,
) -> Result<ProverSecretCopyValueV1<[u8; 32]>, FcmpNativeErrorV1> {
    let linking = prover_secret_decode_edwards_point_v1(linking_bytes)?;
    let key_image = secret_edwards_product_v1(linking.expose_ref(), spend_x);
    Ok(prover_secret_edwards_encoding_v1(&key_image))
}
struct ProverSecretEdwardsCoordinateOwnerV1 {
    // Retain the coordinate tuple until its copied padding has entered the
    // zeroizing prover tape, including every downstream error or unwind.
    _coordinates: SecretCycleCoordinatesV1<Field25519>,
    padding: ProverSecretCopyValueV1<[Field25519; 2]>,
}
fn prover_secret_edwards_coordinate_owner_v1(
    bytes: &[u8; 32],
) -> Result<ProverSecretEdwardsCoordinateOwnerV1, FcmpNativeErrorV1> {
    let coordinates = secret_edwards_to_wei25519_v1(bytes)?;
    let (coordinate_x, coordinate_y) = coordinates.component_refs();
    let padding = ProverSecretCopyValueV1::new([*coordinate_x, *coordinate_y]);
    Ok(ProverSecretEdwardsCoordinateOwnerV1 {
        _coordinates: coordinates,
        padding,
    })
}
struct ProverSecretOutputCoordinateOwnersV1 {
    output: ProverSecretEdwardsCoordinateOwnerV1,
    linking: ProverSecretEdwardsCoordinateOwnerV1,
    commitment: ProverSecretEdwardsCoordinateOwnerV1,
}
fn prover_secret_output_coordinate_owners_v1(
    output_bytes: &[u8; 32],
    linking_bytes: &[u8; 32],
    commitment_bytes: &[u8; 32],
) -> Result<ProverSecretOutputCoordinateOwnersV1, FcmpNativeErrorV1> {
    Ok(ProverSecretOutputCoordinateOwnersV1 {
        output: prover_secret_edwards_coordinate_owner_v1(output_bytes)?,
        linking: prover_secret_edwards_coordinate_owner_v1(linking_bytes)?,
        commitment: prover_secret_edwards_coordinate_owner_v1(commitment_bytes)?,
    })
}
fn secret_edwards_product_v1(generator: &EdwardsPoint, scalar: &Scalar) -> Zeroizing<EdwardsPoint> {
    Zeroizing::new(generator * scalar)
}
fn secret_edwards_scalar_product_v1(left: &Scalar, right: &Scalar) -> Zeroizing<Scalar> {
    Zeroizing::new(left * right)
}
fn ct_slice_contains_by<T, U>(
    values: &[T],
    target: &U,
    mut equal: impl FnMut(&T, &U) -> Choice,
) -> Choice {
    let mut found = Choice::from(0);
    for value in values {
        found |= equal(value, target);
    }
    found
}
fn ct_has_duplicate_by<T>(values: &[T], mut equal: impl FnMut(&T, &T) -> Choice) -> Choice {
    let mut duplicate = Choice::from(0);
    for (index, left) in values.iter().enumerate() {
        for right in &values[index + 1..] {
            duplicate |= equal(left, right);
        }
    }
    duplicate
}
/// Compare every element when the public slice lengths agree.
fn ct_equal_slices_by<T>(
    left: &[T],
    right: &[T],
    mut equal: impl FnMut(&T, &T) -> Choice,
) -> Choice {
    if left.len() != right.len() {
        return Choice::from(0);
    }
    let mut all_equal = Choice::from(1);
    for (left, right) in left.iter().zip(right) {
        all_equal &= equal(left, right);
    }
    all_equal
}
fn ct_all_match_by<T, U>(
    values: &[T],
    expected: &U,
    mut matches: impl FnMut(&T, &U) -> Choice,
) -> Choice {
    let mut all_match = Choice::from(1);
    for value in values {
        all_match &= matches(value, expected);
    }
    all_match
}
/// Require an already allocated slot before a private value is constructed.
///
/// Calling this immediately before sampling/preparing and pushing a secret prevents `Vec::push`
/// from copying previously inserted secrets during a growth operation. The caller's count is
/// public, so capacity exhaustion is an arithmetic invariant rather than a secret-dependent branch.
fn require_preallocated_push(
    current_len: usize,
    allocation_capacity: usize,
) -> Result<(), FcmpNativeErrorV1> {
    if current_len >= allocation_capacity {
        return Err(FcmpNativeErrorV1::ArithmeticInvariant);
    }
    Ok(())
}
/// Compare every fixed-size digest pair without early exit.
///
/// The slice length is public transaction shape. Digest contents can identify
/// hidden spent leaves before proof publication, so neither equality nor the
/// duplicate position may influence the prover's control flow.
fn ct_has_duplicate_digests(values: &[[u8; 32]]) -> bool {
    bool::from(ct_has_duplicate_by(values, |left, right| {
        left.as_slice().ct_eq(right.as_slice())
    }))
}
fn ct_digest_slice_contains(values: &[[u8; 32]], target: &[u8; 32]) -> bool {
    bool::from(ct_slice_contains_by(values, target, |value, target| {
        value.as_slice().ct_eq(target.as_slice())
    }))
}
fn ct_secret_selene_point_eq_v1(
    left: &ProverSecretPointV1<SelenePoint>,
    public_right: &SelenePoint,
) -> Result<bool, FcmpNativeErrorV1> {
    let left = left
        .secret_encoding_owner_v1()
        .ok_or(FcmpNativeErrorV1::ArithmeticInvariant)?;
    let public_right = Zeroizing::new(public_right.encode());
    Ok(bool::from(
        left.as_ref().as_slice().ct_eq(public_right.as_slice()),
    ))
}
fn ct_secret_helios_point_eq_v1(
    left: &ProverSecretPointV1<HeliosPoint>,
    public_right: &HeliosPoint,
) -> Result<bool, FcmpNativeErrorV1> {
    let left = left
        .secret_encoding_owner_v1()
        .ok_or(FcmpNativeErrorV1::ArithmeticInvariant)?;
    let public_right = Zeroizing::new(public_right.encode());
    Ok(bool::from(
        left.as_ref().as_slice().ct_eq(public_right.as_slice()),
    ))
}
fn ct_field25519_slice_contains(
    values: &[Field25519],
    target: &SecretCycleScalarV1<Field25519>,
) -> bool {
    bool::from(ct_slice_contains_by(
        values,
        target.as_ref(),
        |value, target| {
            let difference = ProverSecretCopyValueV1::new(value.sub_ref(target));
            difference.expose_ref().ct_is_zero()
        },
    ))
}
fn ct_helioselene_slice_contains(
    values: &[HelioseleneField],
    target: &SecretCycleScalarV1<HelioseleneField>,
) -> bool {
    bool::from(ct_slice_contains_by(
        values,
        target.as_ref(),
        |value, target| {
            let difference = ProverSecretCopyValueV1::new(value.sub_ref(target));
            difference.expose_ref().ct_is_zero()
        },
    ))
}
enum AdditionalBranch {
    /// A branch of Selene x-coordinates which hashes to Helios.
    ToHelios(Vec<HelioseleneField>),
    /// A branch of Helios x-coordinates which hashes to Selene.
    ToSelene(Vec<Field25519>),
}
impl Zeroize for AdditionalBranch {
    fn zeroize(&mut self) {
        match self {
            Self::ToHelios(branch) => branch.zeroize(),
            Self::ToSelene(branch) => branch.zeroize(),
        }
    }
}
impl Drop for AdditionalBranch {
    fn drop(&mut self) {
        self.zeroize();
    }
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
fn duplicate_zeroizing_slice<T>(values: &[T]) -> Zeroizing<Vec<T>>
where
    T: Copy + Zeroize,
{
    let mut duplicate = Zeroizing::new(Vec::with_capacity(values.len()));
    duplicate.extend_from_slice(values);
    duplicate
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
fn duplicate_zeroizing_nested_slices<T>(values: &[Vec<T>]) -> Zeroizing<Vec<Vec<T>>>
where
    T: Copy + Zeroize,
{
    let mut duplicate = Zeroizing::new(Vec::with_capacity(values.len()));
    for values in values {
        let mut inner = duplicate_zeroizing_slice(values);
        duplicate.push(core::mem::take(&mut *inner));
    }
    duplicate
}
#[cfg(test)]
impl AdditionalBranch {
    fn duplicate_for_test(&self) -> Self {
        match self {
            Self::ToHelios(values) => {
                let mut duplicate = duplicate_zeroizing_slice(values);
                Self::ToHelios(core::mem::take(&mut *duplicate))
            }
            Self::ToSelene(values) => {
                let mut duplicate = duplicate_zeroizing_slice(values);
                Self::ToSelene(core::mem::take(&mut *duplicate))
            }
        }
    }
}
static PROVER_ED25519_SCALAR_MODULUS_LE_V1: [u8; 32] = [
    0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10,
];
#[cfg(test)]
std::thread_local! {
    #[cfg(test)]
    static PROVER_SECRET_EDWARDS_CANONICALITY_OWNER_DROPS_V1: std::cell::Cell<usize> =
        const { std::cell::Cell::new(0) };
    #[cfg(test)]
    static PROVER_SECRET_EDWARDS_WIDE_INPUT_OWNER_DROPS_V1: std::cell::Cell<usize> =
        const { std::cell::Cell::new(0) };
}
struct ProverSecretEdwardsCanonicalityStateV1 {
    less: Choice,
    greater: Choice,
    byte_less: Choice,
    byte_greater: Choice,
    prefix_decided: Choice,
    prefix_equal: Choice,
    less_update: Choice,
    greater_update: Choice,
}
impl ProverSecretEdwardsCanonicalityStateV1 {
    fn new_v1() -> Self {
        Self {
            less: Choice::from(0),
            greater: Choice::from(0),
            byte_less: Choice::from(0),
            byte_greater: Choice::from(0),
            prefix_decided: Choice::from(0),
            prefix_equal: Choice::from(0),
            less_update: Choice::from(0),
            greater_update: Choice::from(0),
        }
    }
    fn observe_byte_v1(&mut self, byte: &u8, modulus_byte: &u8) {
        self.prefix_decided = self.less | self.greater;
        self.prefix_equal = !self.prefix_decided;
        self.byte_less = byte.ct_lt(modulus_byte);
        self.byte_greater = modulus_byte.ct_lt(byte);
        self.less_update = self.prefix_equal & self.byte_less;
        self.greater_update = self.prefix_equal & self.byte_greater;
        self.less |= self.less_update;
        self.greater |= self.greater_update;
    }
}
impl Drop for ProverSecretEdwardsCanonicalityStateV1 {
    fn drop(&mut self) {
        self.less = Choice::from(0);
        self.greater = Choice::from(0);
        self.byte_less = Choice::from(0);
        self.byte_greater = Choice::from(0);
        self.prefix_decided = Choice::from(0);
        self.prefix_equal = Choice::from(0);
        self.less_update = Choice::from(0);
        self.greater_update = Choice::from(0);
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
        let _ = core::hint::black_box(&mut self.less);
        let _ = core::hint::black_box(&mut self.greater);
        let _ = core::hint::black_box(&mut self.byte_less);
        let _ = core::hint::black_box(&mut self.byte_greater);
        let _ = core::hint::black_box(&mut self.prefix_decided);
        let _ = core::hint::black_box(&mut self.prefix_equal);
        let _ = core::hint::black_box(&mut self.less_update);
        let _ = core::hint::black_box(&mut self.greater_update);
        #[cfg(test)]
        let _ = PROVER_SECRET_EDWARDS_CANONICALITY_OWNER_DROPS_V1.try_with(|drops| {
            drops.set(drops.get().saturating_add(1));
        });
    }
}
struct ProverValidatedSecretEdwardsScalarEncodingV1<'a>(&'a [u8; 32]);
impl<'a> ProverValidatedSecretEdwardsScalarEncodingV1<'a> {
    fn validate_v1(bytes: &'a [u8; 32]) -> Result<Self, FcmpNativeErrorV1> {
        let mut canonicality = ProverSecretEdwardsCanonicalityStateV1::new_v1();
        let mut index = PROVER_ED25519_SCALAR_MODULUS_LE_V1.len();
        while index != 0 {
            index -= 1;
            let byte = &bytes[index];
            let modulus_byte = &PROVER_ED25519_SCALAR_MODULUS_LE_V1[index];
            canonicality.observe_byte_v1(byte, modulus_byte);
        }
        let is_canonical = bool::from(canonicality.less);
        drop(canonicality);
        if !is_canonical {
            return Err(FcmpNativeErrorV1::ScalarEncoding);
        }
        Ok(Self(bytes))
    }
    fn into_scalar_owner_v1(self) -> ProverSecretCopyValueV1<Scalar> {
        let wide = ProverSecretEdwardsWideInputV1::from_borrowed_v1(self.0);
        let mut scalar = Scalar::from_bytes_mod_order_wide(&wide.0);
        drop(wide);
        ProverSecretCopyValueV1::take(&mut scalar)
    }
}
struct ProverSecretEdwardsWideInputV1([u8; 64]);
impl ProverSecretEdwardsWideInputV1 {
    fn from_borrowed_v1(bytes: &[u8; 32]) -> Self {
        let mut wide = Self([0_u8; 64]);
        wide.0[..32].copy_from_slice(bytes);
        wide
    }
}
impl Drop for ProverSecretEdwardsWideInputV1 {
    fn drop(&mut self) {
        self.0.zeroize();
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
        let _ = core::hint::black_box(&mut self.0);
        #[cfg(test)]
        let _ = PROVER_SECRET_EDWARDS_WIDE_INPUT_OWNER_DROPS_V1.try_with(|drops| {
            drops.set(drops.get().saturating_add(1));
        });
    }
}
fn prover_secret_decode_nonzero_edwards_scalar_v1(
    bytes: &[u8; 32],
) -> Result<ProverSecretCopyValueV1<Scalar>, FcmpNativeErrorV1> {
    let scalar =
        ProverValidatedSecretEdwardsScalarEncodingV1::validate_v1(bytes)?.into_scalar_owner_v1();
    let is_zero = bool::from(scalar.expose_ref().ct_eq(&Scalar::ZERO));
    if is_zero {
        return Err(FcmpNativeErrorV1::ScalarEncoding);
    }
    Ok(scalar)
}
/// Caller-selected rerandomization witness for one authoritative FCMP++ public input.
///
/// These values must be chosen with a cryptographically secure RNG before the
/// typed statement is hashed. Keeping them explicit makes O~/I~/R/C~/L
/// derivable in one pass and avoids any dependence on replaying an RNG stream.
pub struct FcmpInputRerandomizationV1 {
    output: Scalar,
    linking: Scalar,
    rerandomization_blind: Scalar,
    commitment: Scalar,
}
impl FcmpInputRerandomizationV1 {
    /// Decode four canonical non-zero Ed25519 scalars.
    pub fn new(
        mut output: [u8; 32],
        mut linking: [u8; 32],
        mut rerandomization_blind: [u8; 32],
        mut commitment: [u8; 32],
    ) -> Result<Self, FcmpNativeErrorV1> {
        let output = ProverSecretCopyValueV1::take(&mut output);
        let linking = ProverSecretCopyValueV1::take(&mut linking);
        let rerandomization_blind = ProverSecretCopyValueV1::take(&mut rerandomization_blind);
        let commitment = ProverSecretCopyValueV1::take(&mut commitment);
        Self::from_rerandomization_secret_byte_owners_v1(
            output,
            linking,
            rerandomization_blind,
            commitment,
        )
    }
    fn from_rerandomization_secret_byte_owners_v1(
        output: ProverSecretCopyValueV1<[u8; 32]>,
        linking: ProverSecretCopyValueV1<[u8; 32]>,
        rerandomization_blind: ProverSecretCopyValueV1<[u8; 32]>,
        commitment: ProverSecretCopyValueV1<[u8; 32]>,
    ) -> Result<Self, FcmpNativeErrorV1> {
        let mut output_scalar =
            prover_secret_decode_nonzero_edwards_scalar_v1(output.expose_ref())?;
        let mut linking_scalar =
            prover_secret_decode_nonzero_edwards_scalar_v1(linking.expose_ref())?;
        let mut rerandomization_blind_scalar =
            prover_secret_decode_nonzero_edwards_scalar_v1(rerandomization_blind.expose_ref())?;
        let mut commitment_scalar =
            prover_secret_decode_nonzero_edwards_scalar_v1(commitment.expose_ref())?;
        let mut rerandomization = Self {
            output: Scalar::ZERO,
            linking: Scalar::ZERO,
            rerandomization_blind: Scalar::ZERO,
            commitment: Scalar::ZERO,
        };
        core::mem::swap(&mut rerandomization.output, &mut output_scalar.0);
        drop(output_scalar);
        core::mem::swap(&mut rerandomization.linking, &mut linking_scalar.0);
        drop(linking_scalar);
        core::mem::swap(
            &mut rerandomization.rerandomization_blind,
            &mut rerandomization_blind_scalar.0,
        );
        drop(rerandomization_blind_scalar);
        core::mem::swap(&mut rerandomization.commitment, &mut commitment_scalar.0);
        drop(commitment_scalar);
        Ok(rerandomization)
    }
    #[cfg(test)]
    fn duplicate_for_test(&self) -> Self {
        let output = Zeroizing::new(self.output);
        let linking = Zeroizing::new(self.linking);
        let rerandomization_blind = Zeroizing::new(self.rerandomization_blind);
        let commitment = Zeroizing::new(self.commitment);
        Self {
            output: *output,
            linking: *linking,
            rerandomization_blind: *rerandomization_blind,
            commitment: *commitment,
        }
    }
}
impl Zeroize for FcmpInputRerandomizationV1 {
    fn zeroize(&mut self) {
        self.output.zeroize();
        self.linking.zeroize();
        self.rerandomization_blind.zeroize();
        self.commitment.zeroize();
    }
}
#[cfg(test)]
std::thread_local! {
    #[cfg(test)]
    static FCMP_INPUT_RERANDOMIZATION_OWNER_DROPS_V1: std::cell::Cell<usize> =
        const { std::cell::Cell::new(0) };
}
impl Drop for FcmpInputRerandomizationV1 {
    fn drop(&mut self) {
        self.zeroize();
        #[cfg(test)]
        let _ = FCMP_INPUT_RERANDOMIZATION_OWNER_DROPS_V1.try_with(|drops| {
            drops.set(drops.get().saturating_add(1));
        });
    }
}
impl core::fmt::Debug for FcmpInputRerandomizationV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("FcmpInputRerandomizationV1")
            .finish_non_exhaustive()
    }
}
/// Secret input and complete tree path for the native FCMP++ prover.
///
/// `additional_branches[0]` is the second-layer Helios branch (up to 18 canonical Helioselene-field
/// elements), index 1 is the third-layer Selene branch (up to 38 Field25519 elements), and the
/// curves continue alternating. The last branch is the shared root branch. Missing capacity is
/// canonically padded with zero by the prover.
pub struct FcmpProverInputV1 {
    output: FcmpOutputTupleV1,
    spend_x: Scalar,
    output_y: Scalar,
    rerandomization: FcmpInputRerandomizationV1,
    leaves: Vec<FcmpOutputTupleV1>,
    additional_branches: Vec<AdditionalBranch>,
}
impl Zeroize for FcmpProverInputV1 {
    fn zeroize(&mut self) {
        self.output.zeroize();
        self.spend_x.zeroize();
        self.output_y.zeroize();
        self.rerandomization.zeroize();
        self.leaves.zeroize();
        self.additional_branches.zeroize();
    }
}
#[cfg(test)]
std::thread_local! {
    #[cfg(test)]
    static FCMP_PROVER_INPUT_OWNER_DROPS_V1: std::cell::Cell<usize> =
        const { std::cell::Cell::new(0) };
}
impl Drop for FcmpProverInputV1 {
    fn drop(&mut self) {
        self.zeroize();
        #[cfg(test)]
        let _ = FCMP_PROVER_INPUT_OWNER_DROPS_V1.try_with(|drops| {
            drops.set(drops.get().saturating_add(1));
        });
    }
}
impl core::fmt::Debug for FcmpProverInputV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("FcmpProverInputV1")
            .field("leaf_count", &self.leaves.len())
            .field("layers", &(self.additional_branches.len() + 1))
            .finish_non_exhaustive()
    }
}
impl FcmpProverInputV1 {
    /// Validate one output opening, caller-selected pseudo-out commitment
    /// rerandomization, and alternating tree path.
    ///
    /// Making the commitment rerandomization explicit lets the transaction
    /// builder choose output commitment masks that satisfy the mandatory
    /// aggregate balance equation before hashing the authoritative statement.
    pub fn new(
        output: FcmpOutputTupleV1,
        mut spend_x: [u8; 32],
        mut output_y: [u8; 32],
        rerandomization: FcmpInputRerandomizationV1,
        leaves: Vec<FcmpOutputTupleV1>,
        additional_branches: Vec<Vec<[u8; 32]>>,
    ) -> Result<Self, FcmpNativeErrorV1> {
        let spend_x_bytes = ProverSecretCopyValueV1::take(&mut spend_x);
        let output_y_bytes = ProverSecretCopyValueV1::take(&mut output_y);
        Self::from_secret_byte_owners_v1(
            output,
            spend_x_bytes,
            output_y_bytes,
            rerandomization,
            leaves,
            additional_branches,
        )
    }
    fn from_secret_byte_owners_v1(
        output: FcmpOutputTupleV1,
        spend_x_bytes: ProverSecretCopyValueV1<[u8; 32]>,
        output_y_bytes: ProverSecretCopyValueV1<[u8; 32]>,
        rerandomization: FcmpInputRerandomizationV1,
        leaves: Vec<FcmpOutputTupleV1>,
        additional_branches: Vec<Vec<[u8; 32]>>,
    ) -> Result<Self, FcmpNativeErrorV1> {
        let mut leaves = Zeroizing::new(leaves);
        let additional_branches = Zeroizing::new(additional_branches);
        let spend_x_encoding =
            ProverValidatedSecretEdwardsScalarEncodingV1::validate_v1(spend_x_bytes.expose_ref())?;
        let output_y_encoding =
            ProverValidatedSecretEdwardsScalarEncodingV1::validate_v1(output_y_bytes.expose_ref())?;
        let mut spend_x_scalar = spend_x_encoding.into_scalar_owner_v1();
        let mut output_y_scalar = output_y_encoding.into_scalar_owner_v1();
        if leaves.is_empty()
            || leaves.len() > FCMP_LAYER_ONE_LEN_V1
            || additional_branches.len() + 1 > usize::from(FCMP_MAX_TREE_LAYERS_V1)
        {
            return Err(FcmpNativeErrorV1::ArithmeticInvariant);
        }
        let mut leaf_ids = zeroizing_digest_buffer(leaves.len())?;
        for leaf in leaves.iter() {
            require_preallocated_push(leaf_ids.len(), leaf_ids.capacity())?;
            push_owned_secret_output_id_v1(&mut leaf_ids, leaf.secret_output_id_v1())?;
        }
        let output_id = output.secret_output_id_v1();
        let output_present = ct_digest_slice_contains(&leaf_ids, output_id.as_ref());
        let duplicate_leaf = ct_has_duplicate_digests(&leaf_ids);
        let zero_spend = bool::from(spend_x_scalar.expose_ref().ct_eq(&Scalar::ZERO));
        if zero_spend || !output_present {
            return Err(FcmpNativeErrorV1::ArithmeticInvariant);
        }
        if duplicate_leaf {
            return Err(FcmpNativeErrorV1::DuplicateOutput);
        }
        let mut decoded = Vec::with_capacity(additional_branches.len());
        for (index, branch) in additional_branches.iter().enumerate() {
            let width = if index % 2 == 0 {
                FCMP_LAYER_TWO_LEN_V1
            } else {
                FCMP_LAYER_ONE_LEN_V1
            };
            if branch.is_empty() || branch.len() > width {
                return Err(FcmpNativeErrorV1::BranchWidth);
            }
            if index % 2 == 0 {
                let mut decoded_branch = Zeroizing::new(Vec::with_capacity(branch.len()));
                for encoded in branch {
                    require_preallocated_push(decoded_branch.len(), decoded_branch.capacity())?;
                    let scalar = decode_secret_helioselene_scalar_v1(encoded)?;
                    push_owned_secret_cycle_scalar_v1(&mut decoded_branch, scalar)?;
                }
                decoded.push(AdditionalBranch::ToHelios(core::mem::take(
                    &mut *decoded_branch,
                )));
            } else {
                let mut decoded_branch = Zeroizing::new(Vec::with_capacity(branch.len()));
                for encoded in branch {
                    require_preallocated_push(decoded_branch.len(), decoded_branch.capacity())?;
                    let scalar = decode_secret_field25519_scalar_v1(encoded)?;
                    push_owned_secret_cycle_scalar_v1(&mut decoded_branch, scalar)?;
                }
                decoded.push(AdditionalBranch::ToSelene(core::mem::take(
                    &mut *decoded_branch,
                )));
            }
        }
        let mut input = Self {
            output,
            spend_x: Scalar::ZERO,
            output_y: Scalar::ZERO,
            rerandomization,
            leaves: core::mem::take(&mut *leaves),
            additional_branches: decoded,
        };
        core::mem::swap(&mut input.spend_x, &mut spend_x_scalar.0);
        drop(spend_x_scalar);
        core::mem::swap(&mut input.output_y, &mut output_y_scalar.0);
        drop(output_y_scalar);
        Ok(input)
    }
    #[cfg(test)]
    fn duplicate_for_test(&self) -> Self {
        let output = Zeroizing::new(self.output);
        let spend_x = Zeroizing::new(self.spend_x);
        let output_y = Zeroizing::new(self.output_y);
        let rerandomization = self.rerandomization.duplicate_for_test();
        let mut leaves = duplicate_zeroizing_slice(&self.leaves);
        let mut additional_branches =
            Zeroizing::new(Vec::with_capacity(self.additional_branches.len()));
        for branch in &self.additional_branches {
            additional_branches.push(branch.duplicate_for_test());
        }
        Self {
            output: *output,
            spend_x: *spend_x,
            output_y: *output_y,
            rerandomization,
            leaves: core::mem::take(&mut *leaves),
            additional_branches: core::mem::take(&mut *additional_branches),
        }
    }
    /// Number of layers represented by this path.
    pub fn layers(&self) -> Result<u8, FcmpNativeErrorV1> {
        u8::try_from(self.additional_branches.len() + 1)
            .map_err(|_| FcmpNativeErrorV1::ArithmeticInvariant)
    }
    /// Derive the complete authoritative O~/I~/R/C~/L public relation before
    /// hashing the typed transaction statement.
    pub fn public_input(&self) -> Result<FcmpProofInputPublicV1, FcmpNativeErrorV1> {
        let (output_bytes, linking_bytes, commitment_bytes) = self.output.component_refs_v1();
        let output = prover_secret_decode_edwards_point_v1(output_bytes)?;
        let linking = prover_secret_decode_edwards_point_v1(linking_bytes)?;
        let amount_commitment = prover_secret_decode_edwards_point_v1(commitment_bytes)?;
        let spend_component = secret_edwards_product_v1(&ED25519_BASEPOINT_POINT, &self.spend_x);
        let output_component = secret_edwards_product_v1(&generator_t(), &self.output_y);
        let expected_output = Zeroizing::new(&*spend_component + &*output_component);
        if &*expected_output != output.expose_ref() {
            return Err(FcmpNativeErrorV1::SalWitnessMismatch);
        }
        let output_blind = secret_edwards_product_v1(&generator_t(), &self.rerandomization.output);
        let output_key_tilde = Zeroizing::new(output.expose_ref() + &*output_blind);
        let linking_blind =
            secret_edwards_product_v1(&generator_u(), &self.rerandomization.linking);
        let linking_tilde = Zeroizing::new(linking.expose_ref() + &*linking_blind);
        let rerandomization_v =
            secret_edwards_product_v1(&generator_v(), &self.rerandomization.linking);
        let rerandomization_t =
            secret_edwards_product_v1(&generator_t(), &self.rerandomization.rerandomization_blind);
        let rerandomization = Zeroizing::new(&*rerandomization_v + &*rerandomization_t);
        let commitment_blind =
            secret_edwards_product_v1(&ED25519_BASEPOINT_POINT, &self.rerandomization.commitment);
        let pseudo_out = Zeroizing::new(amount_commitment.expose_ref() + &*commitment_blind);
        let linking_spend =
            secret_edwards_scalar_product_v1(&self.rerandomization.linking, &self.spend_x);
        let key_image_left = secret_edwards_product_v1(&linking_tilde, &self.spend_x);
        let key_image_right = secret_edwards_product_v1(&generator_u(), &linking_spend);
        let key_image = Zeroizing::new(&*key_image_left - &*key_image_right);
        let output_key_tilde = prover_secret_edwards_encoding_v1(&output_key_tilde);
        let linking_tilde = prover_secret_edwards_encoding_v1(&linking_tilde);
        let rerandomization = prover_secret_edwards_encoding_v1(&rerandomization);
        let pseudo_out = prover_secret_edwards_encoding_v1(&pseudo_out);
        let key_image = prover_secret_edwards_encoding_v1(&key_image);
        FcmpProofInputPublicV1::new(
            output_key_tilde.expose_copy(),
            linking_tilde.expose_copy(),
            rerandomization.expose_copy(),
            pseudo_out.expose_copy(),
            key_image.expose_copy(),
        )
    }
    /// Borrow the complete canonical origin set used by a non-shipping release fixture.
    ///
    /// This is intentionally crate-private and feature-gated: production wallets retain their own
    /// output set, while the release network builder needs the public tuples to construct the exact
    /// authoritative bootstrap without exposing any spend witness.
    #[cfg(feature = "privacy-release-evidence")]
    #[doc(hidden)]
    pub fn release_origin_outputs_v1(&self) -> &[FcmpOutputTupleV1] {
        &self.leaves
    }
}
/// Complete result of native FCMP++ proving.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FcmpProvedBundleV1 {
    proof_wire: Vec<u8>,
    public_inputs: Vec<FcmpProofInputPublicV1>,
}
impl FcmpProvedBundleV1 {
    /// Canonical IFC1 proof bytes.
    pub fn proof_wire(&self) -> &[u8] {
        &self.proof_wire
    }
    /// Authoritative public input relations generated with the proof.
    pub fn public_inputs(&self) -> &[FcmpProofInputPublicV1] {
        &self.public_inputs
    }
    /// Consume the bundle.
    pub fn into_parts(self) -> (Vec<u8>, Vec<FcmpProofInputPublicV1>) {
        (self.proof_wire, self.public_inputs)
    }
}
#[cfg(any(test, feature = "test-utils", feature = "privacy-release-evidence"))]
type FcmpFixtureSpendableOutputV1 = (
    FcmpOutputTupleV1,
    ProverSecretCopyValueV1<[u8; 32]>,
    ProverSecretCopyValueV1<[u8; 32]>,
);
#[cfg(any(test, feature = "test-utils", feature = "privacy-release-evidence"))]
fn fcmp_fixture_spendable_output_from_scalars_v1(
    mut spend_x: Scalar,
    mut output_y: Scalar,
    mut linking: Scalar,
    mut amount: u64,
    mut commitment_mask: Scalar,
) -> Result<FcmpFixtureSpendableOutputV1, FcmpNativeErrorV1> {
    let spend_x = ProverSecretCopyValueV1::take(&mut spend_x);
    let output_y = ProverSecretCopyValueV1::take(&mut output_y);
    let linking = ProverSecretCopyValueV1::take(&mut linking);
    let amount = ProverSecretCopyValueV1::take(&mut amount);
    let commitment_mask = ProverSecretCopyValueV1::take(&mut commitment_mask);
    let spend_component = secret_edwards_product_v1(&ED25519_BASEPOINT_POINT, spend_x.expose_ref());
    let output_component = secret_edwards_product_v1(&generator_t(), output_y.expose_ref());
    let output_point = Zeroizing::new(&*spend_component + &*output_component);
    let linking_point = secret_edwards_product_v1(&ED25519_BASEPOINT_POINT, linking.expose_ref());
    let amount_scalar = ProverSecretCopyValueV1::new(Scalar::from(*amount.expose_ref()));
    let amount_generator = super::range::amount_generator()?;
    let amount_component = secret_edwards_product_v1(&amount_generator, amount_scalar.expose_ref());
    let mask_component =
        secret_edwards_product_v1(&ED25519_BASEPOINT_POINT, commitment_mask.expose_ref());
    let amount_point = Zeroizing::new(&*amount_component + &*mask_component);
    let output = FcmpOutputTupleV1::new(
        output_point.compress().to_bytes(),
        linking_point.compress().to_bytes(),
        amount_point.compress().to_bytes(),
    )?;
    let spend_x_bytes = ProverSecretCopyValueV1::new(spend_x.expose_ref().to_bytes());
    let output_y_bytes = ProverSecretCopyValueV1::new(output_y.expose_ref().to_bytes());
    Ok((output, spend_x_bytes, output_y_bytes))
}
#[cfg(any(test, feature = "test-utils", feature = "privacy-release-evidence"))]
fn with_fcmp_fixture_u64_secret_owners_v1<T>(
    spend_x: ProverSecretCopyValueV1<u64>,
    output_y: ProverSecretCopyValueV1<u64>,
    linking: ProverSecretCopyValueV1<u64>,
    amount: ProverSecretCopyValueV1<u64>,
    commitment_mask: ProverSecretCopyValueV1<u64>,
    operation: impl FnOnce(&u64, &u64, &u64, &u64, &u64) -> T,
) -> T {
    operation(
        spend_x.expose_ref(),
        output_y.expose_ref(),
        linking.expose_ref(),
        amount.expose_ref(),
        commitment_mask.expose_ref(),
    )
}
#[cfg(any(test, feature = "test-utils", feature = "privacy-release-evidence"))]
fn fcmp_fixture_spendable_output_v1(
    mut spend_x: u64,
    mut output_y: u64,
    mut linking: u64,
    mut amount: u64,
    mut commitment_mask: u64,
) -> Result<FcmpFixtureSpendableOutputV1, FcmpNativeErrorV1> {
    let spend_x = ProverSecretCopyValueV1::take(&mut spend_x);
    let output_y = ProverSecretCopyValueV1::take(&mut output_y);
    let linking = ProverSecretCopyValueV1::take(&mut linking);
    let amount = ProverSecretCopyValueV1::take(&mut amount);
    let commitment_mask = ProverSecretCopyValueV1::take(&mut commitment_mask);
    with_fcmp_fixture_u64_secret_owners_v1(
        spend_x,
        output_y,
        linking,
        amount,
        commitment_mask,
        |spend_x, output_y, linking, amount, commitment_mask| {
            fcmp_fixture_spendable_output_from_scalars_v1(
                Scalar::from(*spend_x),
                Scalar::from(*output_y),
                Scalar::from(*linking),
                *amount,
                Scalar::from(*commitment_mask),
            )
        },
    )
}
#[cfg(any(test, feature = "test-utils"))]
#[doc(hidden)]
pub fn fcmp_test_spendable_output_v1(
    spend_x: u64,
    output_y: u64,
    linking: u64,
    amount: u64,
    commitment_mask: u64,
) -> (FcmpOutputTupleV1, [u8; 32], [u8; 32]) {
    let (output, spend_x, output_y) =
        fcmp_fixture_spendable_output_v1(spend_x, output_y, linking, amount, commitment_mask)
            .expect("non-zero test scalars construct canonical FCMP++ points");
    (output, spend_x.expose_copy(), output_y.expose_copy())
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
fn with_fcmp_fixture_output_u64_secret_owners_v1<T>(
    output_key: ProverSecretCopyValueV1<u64>,
    linking: ProverSecretCopyValueV1<u64>,
    amount: ProverSecretCopyValueV1<u64>,
    mask: ProverSecretCopyValueV1<u64>,
    operation: impl FnOnce(&u64, &u64, &u64, &u64) -> T,
) -> T {
    operation(
        output_key.expose_ref(),
        linking.expose_ref(),
        amount.expose_ref(),
        mask.expose_ref(),
    )
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
fn fcmp_fixture_output_opening_v1(
    mut output_key: u64,
    mut linking: u64,
    mut amount: u64,
    mut mask: u64,
) -> Result<FcmpOutputCommitmentOpeningV1, FcmpNativeErrorV1> {
    let output_key = ProverSecretCopyValueV1::take(&mut output_key);
    let linking = ProverSecretCopyValueV1::take(&mut linking);
    let amount = ProverSecretCopyValueV1::take(&mut amount);
    let mask = ProverSecretCopyValueV1::take(&mut mask);
    with_fcmp_fixture_output_u64_secret_owners_v1(
        output_key,
        linking,
        amount,
        mask,
        |output_key, linking, amount, mask| {
            let output_key_scalar = ProverSecretCopyValueV1::new(Scalar::from(*output_key));
            let linking_scalar = ProverSecretCopyValueV1::new(Scalar::from(*linking));
            let amount_scalar = ProverSecretCopyValueV1::new(Scalar::from(*amount));
            let mask_scalar = ProverSecretCopyValueV1::new(Scalar::from(*mask));
            let output_key_point =
                secret_edwards_product_v1(&ED25519_BASEPOINT_POINT, output_key_scalar.expose_ref());
            let linking_point =
                secret_edwards_product_v1(&ED25519_BASEPOINT_POINT, linking_scalar.expose_ref());
            let amount_generator = super::range::amount_generator()?;
            let amount_component =
                secret_edwards_product_v1(&amount_generator, amount_scalar.expose_ref());
            let mask_component =
                secret_edwards_product_v1(&ED25519_BASEPOINT_POINT, mask_scalar.expose_ref());
            let amount_point = Zeroizing::new(&*amount_component + &*mask_component);
            let output = FcmpOutputTupleV1::new(
                output_key_point.compress().to_bytes(),
                linking_point.compress().to_bytes(),
                amount_point.compress().to_bytes(),
            )?;
            let mask_bytes = ProverSecretCopyValueV1::new(mask_scalar.expose_ref().to_bytes());
            FcmpOutputCommitmentOpeningV1::new_borrowed(output, amount, mask_bytes.expose_ref())
        },
    )
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
fn with_fcmp_fixture_rerandomization_u64_secret_owners_v1<T>(
    output: ProverSecretCopyValueV1<u64>,
    linking: ProverSecretCopyValueV1<u64>,
    blind: ProverSecretCopyValueV1<u64>,
    commitment: ProverSecretCopyValueV1<u64>,
    operation: impl FnOnce(&u64, &u64, &u64, &u64) -> T,
) -> T {
    operation(
        output.expose_ref(),
        linking.expose_ref(),
        blind.expose_ref(),
        commitment.expose_ref(),
    )
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
fn fcmp_fixture_rerandomization_v1(
    mut output: u64,
    mut linking: u64,
    mut blind: u64,
    mut commitment: u64,
) -> Result<FcmpInputRerandomizationV1, FcmpNativeErrorV1> {
    let output = ProverSecretCopyValueV1::take(&mut output);
    let linking = ProverSecretCopyValueV1::take(&mut linking);
    let blind = ProverSecretCopyValueV1::take(&mut blind);
    let commitment = ProverSecretCopyValueV1::take(&mut commitment);
    with_fcmp_fixture_rerandomization_u64_secret_owners_v1(
        output,
        linking,
        blind,
        commitment,
        |output, linking, blind, commitment| {
            let output_scalar = ProverSecretCopyValueV1::new(Scalar::from(*output));
            let linking_scalar = ProverSecretCopyValueV1::new(Scalar::from(*linking));
            let blind_scalar = ProverSecretCopyValueV1::new(Scalar::from(*blind));
            let commitment_scalar = ProverSecretCopyValueV1::new(Scalar::from(*commitment));
            let output_bytes = ProverSecretCopyValueV1::new(output_scalar.expose_ref().to_bytes());
            let linking_bytes =
                ProverSecretCopyValueV1::new(linking_scalar.expose_ref().to_bytes());
            let blind_bytes = ProverSecretCopyValueV1::new(blind_scalar.expose_ref().to_bytes());
            let commitment_bytes =
                ProverSecretCopyValueV1::new(commitment_scalar.expose_ref().to_bytes());
            FcmpInputRerandomizationV1::from_rerandomization_secret_byte_owners_v1(
                output_bytes,
                linking_bytes,
                blind_bytes,
                commitment_bytes,
            )
        },
    )
}
fn prover_secret_leaf_coordinates_v1(
    leaves: &[FcmpOutputTupleV1],
    padded_capacity: usize,
    mut convert: impl FnMut(
        &[u8; 32],
    ) -> Result<SecretCycleCoordinatesV1<Field25519>, FcmpNativeErrorV1>,
) -> Result<Zeroizing<Vec<Field25519>>, FcmpNativeErrorV1> {
    let populated_len = leaves
        .len()
        .checked_mul(6)
        .ok_or(FcmpNativeErrorV1::ArithmeticInvariant)?;
    if populated_len > padded_capacity {
        return Err(FcmpNativeErrorV1::ArithmeticInvariant);
    }
    let mut leaf_coordinates = zeroizing_exact_secret_buffer_v1::<Field25519>(padded_capacity)?;
    for leaf in leaves {
        let (output_key, linking_tag_generator, amount_commitment) = leaf.component_refs_v1();
        for point in [output_key, linking_tag_generator, amount_commitment] {
            let coordinate_pair = convert(point)?;
            let (coordinate_x, coordinate_y) = coordinate_pair.component_refs();
            push_borrowed_secret_scalar_v1(&mut leaf_coordinates, coordinate_x)?;
            push_borrowed_secret_scalar_v1(&mut leaf_coordinates, coordinate_y)?;
        }
    }
    if leaf_coordinates.len() != populated_len {
        return Err(FcmpNativeErrorV1::ArithmeticInvariant);
    }
    leaf_coordinates.resize(padded_capacity, Field25519::ZERO);
    Ok(leaf_coordinates)
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
fn with_fcmp_fixture_leaf_coordinate_owners_v1<T>(
    leaves: &[FcmpOutputTupleV1],
    convert: impl FnMut(&[u8; 32]) -> Result<SecretCycleCoordinatesV1<Field25519>, FcmpNativeErrorV1>,
    hash: impl FnOnce(&[Field25519]) -> Result<T, FcmpNativeErrorV1>,
) -> Result<T, FcmpNativeErrorV1> {
    let exact_capacity = leaves
        .len()
        .checked_mul(6)
        .ok_or(FcmpNativeErrorV1::ArithmeticInvariant)?;
    let leaf_coordinates = prover_secret_leaf_coordinates_v1(leaves, exact_capacity, convert)?;
    hash(&leaf_coordinates)
}
fn prover_secret_hash_selene_v1(
    values: &[Field25519],
) -> Result<ProverSecretPointV1<SelenePoint>, FcmpNativeErrorV1> {
    if values.is_empty() || values.len() > SELENE_GENERATOR_COUNT_V1 {
        return Err(FcmpNativeErrorV1::BranchWidth);
    }
    let exact_capacity = values
        .len()
        .checked_add(1)
        .ok_or(FcmpNativeErrorV1::ArithmeticInvariant)?;
    let mut terms = SecretMultiexpBuilder::<SeleneSuite>::new(exact_capacity)?;
    terms.push(&Field25519::ONE, &selene_hash_initializer())?;
    for (scalar, generator) in values.iter().zip(selene_generators()) {
        terms.push(scalar, generator)?;
    }
    let point = terms.evaluate()?;
    Ok(ProverSecretPointV1::from_secret(point))
}
fn prover_secret_hash_helios_v1(
    values: &[HelioseleneField],
) -> Result<ProverSecretPointV1<HeliosPoint>, FcmpNativeErrorV1> {
    if values.is_empty() || values.len() > HELIOS_GENERATOR_COUNT_V1 {
        return Err(FcmpNativeErrorV1::BranchWidth);
    }
    let exact_capacity = values
        .len()
        .checked_add(1)
        .ok_or(FcmpNativeErrorV1::ArithmeticInvariant)?;
    let mut terms = SecretMultiexpBuilder::<HeliosSuite>::new(exact_capacity)?;
    terms.push(&HelioseleneField::ONE, &helios_hash_initializer())?;
    for (scalar, generator) in values.iter().zip(helios_generators()) {
        terms.push(scalar, generator)?;
    }
    let point = terms.evaluate()?;
    Ok(ProverSecretPointV1::from_secret(point))
}
fn prover_secret_selene_x_v1(
    point: &ProverSecretPointV1<SelenePoint>,
) -> Result<SecretCycleScalarV1<HelioseleneField>, FcmpNativeErrorV1> {
    point
        .secret_x_owner_v1()
        .ok_or(FcmpNativeErrorV1::ArithmeticInvariant)
}
fn prover_secret_helios_x_v1(
    point: &ProverSecretPointV1<HeliosPoint>,
) -> Result<SecretCycleScalarV1<Field25519>, FcmpNativeErrorV1> {
    point
        .secret_x_owner_v1()
        .ok_or(FcmpNativeErrorV1::ArithmeticInvariant)
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
fn push_fcmp_fixture_secret_branch_v1(
    branches: &mut Zeroizing<Vec<Vec<[u8; 32]>>>,
    mut encoded: SecretEncodedScalarV1,
) -> Result<(), FcmpNativeErrorV1> {
    let branches_capacity = branches.capacity();
    let branches_pointer = branches.as_ptr();
    let outer_preflight = require_preallocated_push(branches.len(), branches_capacity);
    if let Err(error) = outer_preflight {
        drop(encoded);
        return Err(error);
    }
    let mut branch = zeroizing_exact_secret_buffer_v1::<[u8; 32]>(1)?;
    let branch_capacity = branch.capacity();
    let branch_pointer = branch.as_ptr();
    let inner_preflight = require_preallocated_push(branch.len(), branch_capacity);
    if let Err(error) = inner_preflight {
        drop(encoded);
        return Err(error);
    }
    let branch_index = branches.len();
    branches.push(core::mem::take(&mut *branch));
    debug_assert_eq!(branches.capacity(), branches_capacity);
    debug_assert_eq!(branches.as_ptr(), branches_pointer);
    let final_branch = &mut branches[branch_index];
    debug_assert_eq!(final_branch.capacity(), branch_capacity);
    debug_assert_eq!(final_branch.as_ptr(), branch_pointer);
    final_branch.push([0; 32]);
    let destination = final_branch.len() - 1;
    core::mem::swap(&mut final_branch[destination], encoded.as_mut());
    drop(encoded);
    debug_assert_eq!(final_branch.capacity(), branch_capacity);
    debug_assert_eq!(final_branch.as_ptr(), branch_pointer);
    Ok(())
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
fn fcmp_fixture_secret_helios_encoding_v1(
    point: &ProverSecretPointV1<HeliosPoint>,
) -> Result<SecretEncodedScalarV1, FcmpNativeErrorV1> {
    point
        .secret_encoding_owner_v1()
        .ok_or(FcmpNativeErrorV1::ArithmeticInvariant)
}
/// Build the canonical deterministic FCMP++ release fixture.
///
/// The maximum fixture binds two inputs, four strictly-positive outputs, and
/// all 32 alternating curve-tree layers. The smaller fixture binds one input,
/// one output, and one layer. Secret-bearing typed witnesses are returned only
/// inside tests or the non-shipping release-evidence feature.
#[cfg(any(test, feature = "privacy-release-evidence"))]
pub fn fcmp_release_fixture_v1(
    maximum: bool,
) -> Result<
    (
        Vec<FcmpProverInputV1>,
        Vec<FcmpOutputCommitmentOpeningV1>,
        FcmpTreeRootV1,
    ),
    FcmpNativeErrorV1,
> {
    const INPUT_AMOUNT: u64 = 5;
    if !maximum {
        let (output, spend_x, output_y) =
            fcmp_fixture_spendable_output_v1(17, 23, 31, INPUT_AMOUNT, 37)?;
        let new_output = fcmp_fixture_output_opening_v1(43, 47, INPUT_AMOUNT, 37 + 41)?;
        let root = super::build_fcmp_frontier_v1(&[output])?.root;
        let rerandomization = fcmp_fixture_rerandomization_v1(61, 67, 71, 41)?;
        let input = FcmpProverInputV1::from_secret_byte_owners_v1(
            output,
            spend_x,
            output_y,
            rerandomization,
            vec![output],
            Vec::new(),
        )?;
        return Ok((vec![input], vec![new_output], root));
    }
    let (output_1, spend_x_1, output_y_1) =
        fcmp_fixture_spendable_output_v1(401, 409, 431, INPUT_AMOUNT, 149)?;
    let (output_2, spend_x_2, output_y_2) =
        fcmp_fixture_spendable_output_v1(419, 421, 433, INPUT_AMOUNT, 157)?;
    let mut leaves = Zeroizing::new(vec![output_1, output_2]);
    let mut current_selene = with_fcmp_fixture_leaf_coordinate_owners_v1(
        &leaves,
        secret_edwards_to_wei25519_v1,
        prover_secret_hash_selene_v1,
    )?;
    let mut current_helios: Option<ProverSecretPointV1<HeliosPoint>> = None;
    let mut branches = zeroizing_exact_secret_buffer_v1::<Vec<[u8; 32]>>(usize::from(
        FCMP_MAX_TREE_LAYERS_V1.saturating_sub(1),
    ))?;
    for branch_index in 0..usize::from(FCMP_MAX_TREE_LAYERS_V1 - 1) {
        if branch_index % 2 == 0 {
            let child = prover_secret_selene_x_v1(&current_selene)?;
            push_fcmp_fixture_secret_branch_v1(
                &mut branches,
                encode_secret_helioselene_scalar_v1(child.expose_ref()),
            )?;
            current_helios = Some(prover_secret_hash_helios_v1(core::slice::from_ref(
                child.expose_ref(),
            ))?);
        } else {
            let child = prover_secret_helios_x_v1(
                current_helios
                    .as_ref()
                    .ok_or(FcmpNativeErrorV1::ArithmeticInvariant)?,
            )?;
            push_fcmp_fixture_secret_branch_v1(
                &mut branches,
                encode_secret_field25519_scalar_v1(child.expose_ref()),
            )?;
            current_selene =
                prover_secret_hash_selene_v1(core::slice::from_ref(child.expose_ref()))?;
        }
    }
    let root = FcmpTreeRootV1::new(
        FCMP_MAX_TREE_LAYERS_V1,
        fcmp_fixture_secret_helios_encoding_v1(
            current_helios
                .as_ref()
                .ok_or(FcmpNativeErrorV1::ArithmeticInvariant)?,
        )?
        .expose_public_copy_v1(),
    )?;
    let mut first_leaves = duplicate_zeroizing_slice(&leaves);
    let mut first_branches = duplicate_zeroizing_nested_slices(&branches);
    let first_rerandomization = fcmp_fixture_rerandomization_v1(439, 443, 449, 163)?;
    let first_input = FcmpProverInputV1::from_secret_byte_owners_v1(
        output_1,
        spend_x_1,
        output_y_1,
        first_rerandomization,
        core::mem::take(&mut *first_leaves),
        core::mem::take(&mut *first_branches),
    )?;
    let second_rerandomization = fcmp_fixture_rerandomization_v1(457, 461, 463, 167)?;
    let second_input = FcmpProverInputV1::from_secret_byte_owners_v1(
        output_2,
        spend_x_2,
        output_y_2,
        second_rerandomization,
        core::mem::take(&mut *leaves),
        core::mem::take(&mut *branches),
    )?;
    let inputs = vec![first_input, second_input];
    // Input masks plus their pseudo-out rerandomizations total 636. These
    // four masks preserve the aggregate while positive amounts total 10.
    let outputs = vec![
        fcmp_fixture_output_opening_v1(467, 479, 1, 101)?,
        fcmp_fixture_output_opening_v1(487, 491, 2, 103)?,
        fcmp_fixture_output_opening_v1(499, 503, 3, 107)?,
        fcmp_fixture_output_opening_v1(509, 521, 4, 325)?,
    ];
    Ok((inputs, outputs, root))
}
/// Build a maximum-shape fixture whose first canonical branch does not resolve
/// to the supplied authoritative root.
///
/// This is feature-only negative-test material. The public prover must reject
/// it during deterministic path preflight before producing any proof.
#[cfg(any(test, feature = "privacy-release-evidence"))]
fn replace_first_secret_coordinate_v1(
    branch: &mut AdditionalBranch,
) -> Result<(), FcmpNativeErrorV1> {
    match branch {
        AdditionalBranch::ToHelios(values) => {
            let destination = values
                .first_mut()
                .ok_or(FcmpNativeErrorV1::ArithmeticInvariant)?;
            let original = ProverSecretCopyValueV1::take(destination);
            let difference =
                ProverSecretCopyValueV1::new(original.expose_ref().sub_ref(&HelioseleneField::ONE));
            let mut replacement =
                ProverSecretCopyValueV1::new(HelioseleneField::conditional_select(
                    &HelioseleneField::ONE,
                    &HelioseleneField::ONE.add_ref(&HelioseleneField::ONE),
                    difference.expose_ref().ct_is_zero(),
                ));
            drop(difference);
            core::mem::swap(destination, &mut replacement.0);
            drop(replacement);
            drop(original);
        }
        AdditionalBranch::ToSelene(values) => {
            let destination = values
                .first_mut()
                .ok_or(FcmpNativeErrorV1::ArithmeticInvariant)?;
            let original = ProverSecretCopyValueV1::take(destination);
            let difference =
                ProverSecretCopyValueV1::new(original.expose_ref().sub_ref(&Field25519::ONE));
            let mut replacement = ProverSecretCopyValueV1::new(Field25519::conditional_select(
                &Field25519::ONE,
                &Field25519::ONE.add_ref(&Field25519::ONE),
                difference.expose_ref().ct_is_zero(),
            ));
            drop(difference);
            core::mem::swap(destination, &mut replacement.0);
            drop(replacement);
            drop(original);
        }
    }
    Ok(())
}
#[cfg(feature = "privacy-release-evidence")]
pub(crate) fn fcmp_release_invalid_path_fixture_v1() -> Result<
    (
        Vec<FcmpProverInputV1>,
        Vec<FcmpOutputCommitmentOpeningV1>,
        FcmpTreeRootV1,
    ),
    FcmpNativeErrorV1,
> {
    let (mut inputs, outputs, root) = fcmp_release_fixture_v1(true)?;
    let first_input = inputs
        .first_mut()
        .ok_or(FcmpNativeErrorV1::ArithmeticInvariant)?;
    let first_branch = first_input
        .additional_branches
        .first_mut()
        .ok_or(FcmpNativeErrorV1::ArithmeticInvariant)?;
    replace_first_secret_coordinate_v1(first_branch)?;
    Ok((inputs, outputs, root))
}
enum RootValues {
    C1(Vec<Field25519>),
    C2(Vec<HelioseleneField>),
}
fn root_values_ct_eq(left: &RootValues, right: &RootValues) -> Choice {
    // Variant and length are fixed by the public layer count. Only coordinate
    // contents are private, and equal-shape roots always scan every one.
    match (left, right) {
        (RootValues::C1(left), RootValues::C1(right)) => {
            ct_equal_slices_by(left, right, |left, right| {
                let difference = ProverSecretCopyValueV1::new(left.sub_ref(right));
                difference.expose_ref().ct_is_zero()
            })
        }
        (RootValues::C2(left), RootValues::C2(right)) => {
            ct_equal_slices_by(left, right, |left, right| {
                let difference = ProverSecretCopyValueV1::new(left.sub_ref(right));
                difference.expose_ref().ct_is_zero()
            })
        }
        _ => Choice::from(0),
    }
}
fn all_paths_share_root(paths: &[PathValues], shared_root: &RootValues) -> bool {
    bool::from(ct_all_match_by(paths, shared_root, |path, shared_root| {
        root_values_ct_eq(&path.root, shared_root)
    }))
}
impl Zeroize for RootValues {
    fn zeroize(&mut self) {
        match self {
            Self::C1(values) => values.zeroize(),
            Self::C2(values) => values.zeroize(),
        }
    }
}
impl Drop for RootValues {
    fn drop(&mut self) {
        self.zeroize();
    }
}
struct PathValues {
    c1_non_root: Vec<Vec<Field25519>>,
    c2_non_root: Vec<Vec<HelioseleneField>>,
    root: RootValues,
}
impl Drop for PathValues {
    fn drop(&mut self) {
        self.c1_non_root.zeroize();
        self.c2_non_root.zeroize();
        self.root.zeroize();
    }
}
#[derive(Clone)]
struct TranscriptedPath {
    c1_non_root: Vec<Vec<Variable>>,
    c2_non_root: Vec<Vec<Variable>>,
}
fn parse_path(
    input: &FcmpProverInputV1,
    root: FcmpTreeRootV1,
) -> Result<PathValues, FcmpNativeErrorV1> {
    if input.layers()? != root.layers() {
        return Err(FcmpNativeErrorV1::ProofHeaderMismatch);
    }
    let leaf_capacity = 6_usize
        .checked_mul(FCMP_LAYER_ONE_LEN_V1)
        .ok_or(FcmpNativeErrorV1::ArithmeticInvariant)?;
    let mut leaves = prover_secret_leaf_coordinates_v1(
        &input.leaves,
        leaf_capacity,
        secret_edwards_to_wei25519_v1,
    )?;
    let mut current_c1 = Some(prover_secret_hash_selene_v1(&leaves)?);
    let mut current_c2: Option<ProverSecretPointV1<HeliosPoint>> = None;
    let private_branch_capacity = input.additional_branches.len().saturating_add(1);
    let mut c1_non_root =
        zeroizing_exact_secret_buffer_v1::<Vec<Field25519>>(private_branch_capacity)?;
    let mut c2_non_root =
        zeroizing_exact_secret_buffer_v1::<Vec<HelioseleneField>>(private_branch_capacity)?;
    if input.additional_branches.is_empty() {
        let expected = SelenePoint::decode(root.point(), false)?;
        let matches_expected = match current_c1.as_ref() {
            Some(actual) => ct_secret_selene_point_eq_v1(actual, &expected)?,
            None => false,
        };
        if root.curve() != FcmpTreeCurveV1::Selene || !matches_expected {
            return Err(FcmpNativeErrorV1::RootMismatch);
        }
        return Ok(PathValues {
            c1_non_root: core::mem::take(&mut *c1_non_root),
            c2_non_root: core::mem::take(&mut *c2_non_root),
            root: RootValues::C1(core::mem::take(&mut *leaves)),
        });
    }
    require_preallocated_push(c1_non_root.len(), c1_non_root.capacity())?;
    c1_non_root.push(core::mem::take(&mut *leaves));
    let last = input.additional_branches.len() - 1;
    let mut root_values = None;
    for (index, branch) in input.additional_branches.iter().enumerate() {
        match branch {
            AdditionalBranch::ToHelios(branch) => {
                let prior_x = prover_secret_selene_x_v1(
                    current_c1
                        .as_ref()
                        .ok_or(FcmpNativeErrorV1::ArithmeticInvariant)?,
                )?;
                let mut padded =
                    zeroizing_exact_secret_buffer_v1::<HelioseleneField>(FCMP_LAYER_TWO_LEN_V1)?;
                let allocation_capacity = padded.capacity();
                for coordinate in branch {
                    push_borrowed_secret_scalar_v1(&mut padded, coordinate)?;
                }
                padded.resize(FCMP_LAYER_TWO_LEN_V1, HelioseleneField::ZERO);
                debug_assert!(allocation_capacity >= FCMP_LAYER_TWO_LEN_V1);
                debug_assert_eq!(padded.capacity(), allocation_capacity);
                if !ct_helioselene_slice_contains(&padded, &prior_x) {
                    return Err(FcmpNativeErrorV1::ArithmeticInvariant);
                }
                let next_c2 = prover_secret_hash_helios_v1(&padded)?;
                current_c2 = Some(next_c2);
                if index == last {
                    root_values = Some(RootValues::C2(core::mem::take(&mut *padded)));
                } else {
                    require_preallocated_push(c2_non_root.len(), c2_non_root.capacity())?;
                    c2_non_root.push(core::mem::take(&mut *padded));
                }
            }
            AdditionalBranch::ToSelene(branch) => {
                let prior_x = prover_secret_helios_x_v1(
                    current_c2
                        .as_ref()
                        .ok_or(FcmpNativeErrorV1::ArithmeticInvariant)?,
                )?;
                let mut padded =
                    zeroizing_exact_secret_buffer_v1::<Field25519>(FCMP_LAYER_ONE_LEN_V1)?;
                let allocation_capacity = padded.capacity();
                for coordinate in branch {
                    push_borrowed_secret_scalar_v1(&mut padded, coordinate)?;
                }
                padded.resize(FCMP_LAYER_ONE_LEN_V1, Field25519::ZERO);
                debug_assert!(allocation_capacity >= FCMP_LAYER_ONE_LEN_V1);
                debug_assert_eq!(padded.capacity(), allocation_capacity);
                if !ct_field25519_slice_contains(&padded, &prior_x) {
                    return Err(FcmpNativeErrorV1::ArithmeticInvariant);
                }
                let next_c1 = prover_secret_hash_selene_v1(&padded)?;
                current_c1 = Some(next_c1);
                if index == last {
                    root_values = Some(RootValues::C1(core::mem::take(&mut *padded)));
                } else {
                    require_preallocated_push(c1_non_root.len(), c1_non_root.capacity())?;
                    c1_non_root.push(core::mem::take(&mut *padded));
                }
            }
        }
    }
    let matches_root = match root.curve() {
        FcmpTreeCurveV1::Selene => {
            let expected = SelenePoint::decode(root.point(), false)?;
            match current_c1.as_ref() {
                Some(actual) => ct_secret_selene_point_eq_v1(actual, &expected)?,
                None => false,
            }
        }
        FcmpTreeCurveV1::Helios => {
            let expected = HeliosPoint::decode(root.point(), false)?;
            match current_c2.as_ref() {
                Some(actual) => ct_secret_helios_point_eq_v1(actual, &expected)?,
                None => false,
            }
        }
    };
    if !matches_root {
        return Err(FcmpNativeErrorV1::RootMismatch);
    }
    Ok(PathValues {
        c1_non_root: core::mem::take(&mut *c1_non_root),
        c2_non_root: core::mem::take(&mut *c2_non_root),
        root: root_values.ok_or(FcmpNativeErrorV1::ArithmeticInvariant)?,
    })
}
fn random_proof_scalar<F: ProofScalar>(
    rng: &mut (impl RngCore + CryptoRng),
) -> Result<ProverSecretScalarV1<F>, FcmpNativeErrorV1> {
    for _ in 0..MAX_PROVER_SCALAR_ATTEMPTS_V1 {
        if let Some(sampled) = random_scalar_from_fcmp_rng::<F, _>(rng)? {
            let scalar = ProverSecretScalarV1::copy_from_borrowed(sampled.expose_ref());
            drop(sampled);
            if scalar.expose_ref() != &F::ZERO {
                return Ok(scalar);
            }
        }
    }
    Err(FcmpNativeErrorV1::ProverRandomnessExhausted)
}
fn root_nonce_commitment_v1<S: ProofSuite>(
    nonce: &S::Scalar,
) -> Result<ProverSecretPointV1<S::Point>, FcmpNativeErrorV1> {
    let mut terms = SecretMultiexpBuilder::<S>::new(1)?;
    terms.push(nonce, &S::generators().h)?;
    let point = terms.evaluate()?;
    Ok(ProverSecretPointV1::from_secret(point))
}
fn prepared_secret_point_v1<S: ProofSuite>(
    scalar: &S::Scalar,
) -> Result<ProverSecretPointV1<S::Point>, FcmpNativeErrorV1> {
    let mut terms = SecretMultiexpBuilder::<S>::new(1)?;
    terms.push(scalar, &S::generators().h)?;
    let point = terms.evaluate()?;
    Ok(ProverSecretPointV1::from_secret(point))
}
struct PreparedEdBlind {
    decomposition: Vec<u64>,
    divisor: NormalizedDivisor<Field25519>,
    coordinates: SecretCycleCoordinatesV1<Field25519>,
}
impl Drop for PreparedEdBlind {
    fn drop(&mut self) {
        self.decomposition.zeroize();
    }
}
fn prepare_ed_blind(
    generator: EdwardsPoint,
    scalar: &Scalar,
    negate: bool,
) -> Result<PreparedEdBlind, FcmpNativeErrorV1> {
    let scalar = Zeroizing::new(if negate { -*scalar } else { *scalar });
    let mut decomposition = ed25519_scalar_decomposition(&scalar)?;
    let point = Zeroizing::new(&generator * &*scalar);
    let encoded_point = Zeroizing::new(point.compress().to_bytes());
    let coordinates = secret_edwards_to_wei25519_v1(&encoded_point)?;
    let curve = ed25519_curve();
    let divisor = scalar_mul_divisor(curve.a, curve.b, generator, &decomposition, &point)?;
    Ok(PreparedEdBlind {
        decomposition: core::mem::take(&mut *decomposition),
        divisor,
        coordinates,
    })
}
struct PreparedSeleneBlind {
    scalar: ProverSecretScalarV1<Field25519>,
    decomposition: Vec<u64>,
    divisor: NormalizedDivisor<HelioseleneField>,
    point: ProverSecretPointV1<SelenePoint>,
}
impl Drop for PreparedSeleneBlind {
    fn drop(&mut self) {
        self.decomposition.zeroize();
    }
}
fn prepare_selene_blind(
    scalar: ProverSecretScalarV1<Field25519>,
) -> Result<PreparedSeleneBlind, FcmpNativeErrorV1> {
    let mut decomposition =
        scalar_decomposition(scalar.expose_ref(), CYCLE_DLOG_PARAMETERS.scalar_bits)?;
    let generator = selene_bp_generators().h;
    let point = prepared_secret_point_v1::<SeleneSuite>(scalar.expose_ref())?;
    let curve = selene_curve();
    let divisor = scalar_mul_divisor(
        curve.a,
        curve.b,
        generator,
        &decomposition,
        point.expose_ref(),
    )?;
    Ok(PreparedSeleneBlind {
        scalar,
        decomposition: core::mem::take(&mut *decomposition),
        divisor,
        point,
    })
}
struct PreparedHeliosBlind {
    scalar: ProverSecretScalarV1<HelioseleneField>,
    decomposition: Vec<u64>,
    divisor: NormalizedDivisor<Field25519>,
    point: ProverSecretPointV1<HeliosPoint>,
}
impl Drop for PreparedHeliosBlind {
    fn drop(&mut self) {
        self.decomposition.zeroize();
    }
}
fn prepare_helios_blind(
    scalar: ProverSecretScalarV1<HelioseleneField>,
) -> Result<PreparedHeliosBlind, FcmpNativeErrorV1> {
    let mut decomposition =
        scalar_decomposition(scalar.expose_ref(), CYCLE_DLOG_PARAMETERS.scalar_bits)?;
    let generator = helios_bp_generators().h;
    let point = prepared_secret_point_v1::<HeliosSuite>(scalar.expose_ref())?;
    let curve = helios_curve();
    let divisor = scalar_mul_divisor(
        curve.a,
        curve.b,
        generator,
        &decomposition,
        point.expose_ref(),
    )?;
    Ok(PreparedHeliosBlind {
        scalar,
        decomposition: core::mem::take(&mut *decomposition),
        divisor,
        point,
    })
}
fn commitment_index(variable: Variable) -> Result<usize, FcmpNativeErrorV1> {
    match variable {
        Variable::CG { commitment, .. } => Ok(commitment),
        _ => Err(FcmpNativeErrorV1::ArithmeticInvariant),
    }
}
struct PreparedInput {
    public: FcmpProofInputPublicV1,
    sal: super::FcmpSalProofV1,
    transcripted: TranscriptedInput,
}
fn prove_fcmp_plus_plus_once_v1(
    rng: &mut (impl RngCore + CryptoRng),
    context_hash: [u8; 32],
    inputs: &[FcmpProverInputV1],
    new_output_openings: &[FcmpOutputCommitmentOpeningV1],
    root: FcmpTreeRootV1,
) -> Result<FcmpProvedBundleV1, FcmpNativeErrorV1> {
    if inputs.is_empty() || inputs.len() > super::FCMP_MAX_INPUTS_NATIVE_V1 {
        return Err(FcmpNativeErrorV1::InputCount {
            actual: inputs.len(),
            max: super::FCMP_MAX_INPUTS_NATIVE_V1,
        });
    }
    let mut spent_outputs = zeroizing_digest_buffer(inputs.len())?;
    let mut derived_key_images = zeroizing_digest_buffer(inputs.len())?;
    for input in inputs {
        require_preallocated_push(spent_outputs.len(), spent_outputs.capacity())?;
        push_owned_secret_output_id_v1(&mut spent_outputs, input.output.secret_output_id_v1())?;
        require_preallocated_push(derived_key_images.len(), derived_key_images.capacity())?;
        let linking_bytes = input.output.component_refs_v1().1;
        let key_image = prover_secret_key_image_id_v1(linking_bytes, &input.spend_x)?;
        push_owned_prover_secret_digest_v1(&mut derived_key_images, key_image)?;
    }
    if ct_has_duplicate_digests(&spent_outputs) {
        return Err(FcmpNativeErrorV1::DuplicateOutput);
    }
    if ct_has_duplicate_digests(&derived_key_images) {
        return Err(FcmpNativeErrorV1::DuplicateKeyImage);
    }
    if new_output_openings.is_empty()
        || new_output_openings.len() > super::FCMP_MAX_OUTPUTS_NATIVE_V1
    {
        return Err(FcmpNativeErrorV1::OutputCount {
            actual: new_output_openings.len(),
            max: super::FCMP_MAX_OUTPUTS_NATIVE_V1,
        });
    }
    let new_outputs = new_output_openings
        .iter()
        .map(FcmpOutputCommitmentOpeningV1::output)
        .collect::<Vec<_>>();
    let mut new_output_ids = zeroizing_digest_buffer(new_outputs.len())?;
    for output in &new_outputs {
        new_output_ids.push(output.output_id());
    }
    if ct_has_duplicate_digests(&new_output_ids) {
        return Err(FcmpNativeErrorV1::DuplicateOutput);
    }
    let layers = usize::from(root.layers());
    let mut paths = Vec::with_capacity(inputs.len());
    for input in inputs {
        paths.push(parse_path(input, root)?);
    }
    let shared_root = &paths
        .first()
        .ok_or(FcmpNativeErrorV1::ArithmeticInvariant)?
        .root;
    if !all_paths_share_root(&paths, shared_root) {
        return Err(FcmpNativeErrorV1::RootMismatch);
    }
    let (c1_rows, c2_rows) = ipa_rows(inputs.len(), layers)?;
    let c1_generators = <SeleneSuite as ProofSuite>::generators().reduce(c1_rows)?;
    let c2_generators = <HeliosSuite as ProofSuite>::generators().reduce(c2_rows)?;
    let mut c1_tape = ProverVectorCommitmentTape::new(c1_rows)?;
    let mut c2_tape = ProverVectorCommitmentTape::new(c2_rows)?;
    let c1_non_root_count = paths.iter().try_fold(0_usize, |count, path| {
        count
            .checked_add(path.c1_non_root.len())
            .ok_or(FcmpNativeErrorV1::TreeFull)
    })?;
    let c2_non_root_count = paths.iter().try_fold(0_usize, |count, path| {
        count
            .checked_add(path.c2_non_root.len())
            .ok_or(FcmpNativeErrorV1::TreeFull)
    })?;
    let mut transcripted_paths = Vec::with_capacity(paths.len());
    // The row counts are public upper bounds for every subsequently appended
    // vector commitment. Allocate them before accepting any branch mask so no
    // private scalar can be copied by a Vec growth operation.
    let mut c1_branch_masks = Zeroizing::new(Vec::with_capacity(c1_rows));
    let mut c2_branch_masks = Zeroizing::new(Vec::with_capacity(c2_rows));
    let mut selene_blinds = Vec::with_capacity(c1_non_root_count);
    let mut helios_blinds = Vec::with_capacity(c2_non_root_count);
    for path in &paths {
        let mut c1_non_root = Vec::with_capacity(path.c1_non_root.len());
        for branch in &path.c1_non_root {
            c1_non_root.push(c1_tape.append_branch(branch)?);
            require_preallocated_push(c1_branch_masks.len(), c1_branch_masks.capacity())?;
            require_preallocated_push(selene_blinds.len(), selene_blinds.capacity())?;
            let blind = prepare_selene_blind(random_proof_scalar(rng)?)?;
            push_owned_secret_scalar_v1(&mut c1_branch_masks, blind.scalar.negated_owner_v1())?;
            selene_blinds.push(blind);
        }
        let mut c2_non_root = Vec::with_capacity(path.c2_non_root.len());
        for branch in &path.c2_non_root {
            c2_non_root.push(c2_tape.append_branch(branch)?);
            require_preallocated_push(c2_branch_masks.len(), c2_branch_masks.capacity())?;
            require_preallocated_push(helios_blinds.len(), helios_blinds.capacity())?;
            let blind = prepare_helios_blind(random_proof_scalar(rng)?)?;
            push_owned_secret_scalar_v1(&mut c2_branch_masks, blind.scalar.negated_owner_v1())?;
            helios_blinds.push(blind);
        }
        transcripted_paths.push(TranscriptedPath {
            c1_non_root,
            c2_non_root,
        });
    }
    let root_variables = match shared_root {
        RootValues::C1(values) => {
            let variables = c1_tape.append_branch(values)?;
            require_preallocated_push(c1_branch_masks.len(), c1_branch_masks.capacity())?;
            push_owned_secret_scalar_v1(&mut c1_branch_masks, random_proof_scalar(rng)?)?;
            variables
        }
        RootValues::C2(values) => {
            let variables = c2_tape.append_branch(values)?;
            require_preallocated_push(c2_branch_masks.len(), c2_branch_masks.capacity())?;
            push_owned_secret_scalar_v1(&mut c2_branch_masks, random_proof_scalar(rng)?)?;
            variables
        }
    };
    let root_commitment_index = commitment_index(
        *root_variables
            .first()
            .ok_or(FcmpNativeErrorV1::ArithmeticInvariant)?,
    )?;
    let mut prepared_inputs = Vec::with_capacity(inputs.len());
    let mut generated_pseudo_outs = zeroizing_digest_buffer(inputs.len())?;
    for input in inputs {
        let (output_bytes, linking_bytes, commitment_bytes) = input.output.component_refs_v1();
        let public = input.public_input()?;
        generated_pseudo_outs.push(public.pseudo_out);
        let rerandomization = &input.rerandomization;
        let output_blind = prepare_ed_blind(generator_t(), &rerandomization.output, true)?;
        let input_blind_u = prepare_ed_blind(generator_u(), &rerandomization.linking, true)?;
        let input_blind_v = prepare_ed_blind(generator_v(), &rerandomization.linking, true)?;
        let input_blind_blind =
            prepare_ed_blind(generator_t(), &rerandomization.rerandomization_blind, false)?;
        let commitment_blind =
            prepare_ed_blind(ED25519_BASEPOINT_POINT, &rerandomization.commitment, true)?;
        let output_coordinates = prover_secret_output_coordinate_owners_v1(
            output_bytes,
            linking_bytes,
            commitment_bytes,
        )?;
        let (input_blind_v_x, input_blind_v_y) = input_blind_v.coordinates.component_refs();
        let input_blind_v_padding =
            ProverSecretCopyValueV1::new([*input_blind_v_x, *input_blind_v_y]);
        let (output_blind_claim, output_variables) = c1_tape.append_claimed_point(
            ED25519_DLOG_PARAMETERS,
            &output_blind.decomposition,
            &output_blind.divisor,
            output_blind.coordinates.component_pair_ref(),
            output_coordinates.output.padding.expose_ref().as_slice(),
        )?;
        let (input_blind_u_claim, linking_variables) = c1_tape.append_claimed_point(
            ED25519_DLOG_PARAMETERS,
            &input_blind_u.decomposition,
            &input_blind_u.divisor,
            input_blind_u.coordinates.component_pair_ref(),
            output_coordinates.linking.padding.expose_ref().as_slice(),
        )?;
        let (input_blind_v_divisor, _) = c1_tape.append_divisor(
            ED25519_DLOG_PARAMETERS,
            &input_blind_v.divisor,
            &Field25519::ZERO,
        )?;
        let (input_blind_blind_claim, input_blind_v_variables) = c1_tape.append_claimed_point(
            ED25519_DLOG_PARAMETERS,
            &input_blind_blind.decomposition,
            &input_blind_blind.divisor,
            input_blind_blind.coordinates.component_pair_ref(),
            input_blind_v_padding.expose_ref().as_slice(),
        )?;
        let (commitment_blind_claim, commitment_variables) = c1_tape.append_claimed_point(
            ED25519_DLOG_PARAMETERS,
            &commitment_blind.decomposition,
            &commitment_blind.divisor,
            commitment_blind.coordinates.component_pair_ref(),
            output_coordinates
                .commitment
                .padding
                .expose_ref()
                .as_slice(),
        )?;
        if output_variables.len() != 2
            || linking_variables.len() != 2
            || input_blind_v_variables.len() != 2
            || commitment_variables.len() != 2
        {
            return Err(FcmpNativeErrorV1::ArithmeticInvariant);
        }
        let input_blind_v_claim = PointWithDlog {
            point: (input_blind_v_variables[0], input_blind_v_variables[1]),
            dlog: input_blind_u_claim.dlog.clone(),
            divisor: input_blind_v_divisor,
        };
        let sal_y = prover_secret_edwards_scalar_sum_v1(&input.output_y, &rerandomization.output);
        let sal_y_bytes = FcmpSalSecretScalarEncodingV1::from_scalar_ref_v1(sal_y.expose_ref());
        let sal_linking_bytes =
            FcmpSalSecretScalarEncodingV1::from_scalar_ref_v1(&rerandomization.linking);
        let sal_spend_x_bytes = FcmpSalSecretScalarEncodingV1::from_scalar_ref_v1(&input.spend_x);
        let sal_rerandomization_blind_bytes = FcmpSalSecretScalarEncodingV1::from_scalar_ref_v1(
            &rerandomization.rerandomization_blind,
        );
        let sal_witness = FcmpSalWitnessV1::from_secret_scalar_encoding_owners_v1(
            sal_spend_x_bytes,
            sal_y_bytes,
            sal_linking_bytes,
            sal_rerandomization_blind_bytes,
        )?;
        let sal = prove_fcmp_sal_with_checked_rng_v1(rng, context_hash, &public, &sal_witness)?;
        drop(sal_witness);
        prepared_inputs.push(PreparedInput {
            public,
            sal,
            transcripted: TranscriptedInput {
                output_key: (output_variables[0], output_variables[1]),
                linking_generator: (linking_variables[0], linking_variables[1]),
                amount_commitment: (commitment_variables[0], commitment_variables[1]),
                output_blind: output_blind_claim,
                input_blind_u: input_blind_u_claim,
                input_blind_v: input_blind_v_claim,
                input_blind_blind: input_blind_blind_claim,
                commitment_blind: commitment_blind_claim,
            },
        });
    }
    if ct_has_duplicate_digests(&generated_pseudo_outs) {
        return Err(FcmpNativeErrorV1::DuplicatePseudoOut);
    }
    // The first proof field opens Helios branch blinds; the second opens
    // Selene branch blinds.
    let mut c1_blind_claims = Vec::with_capacity(helios_blinds.len());
    for blind in &helios_blinds {
        let coordinates = blind
            .point
            .expose_ref()
            .secret_coordinates_ref_v1()
            .ok_or(FcmpNativeErrorV1::ArithmeticInvariant)?;
        c1_blind_claims.push(
            c1_tape
                .append_claimed_point(
                    CYCLE_DLOG_PARAMETERS,
                    &blind.decomposition,
                    &blind.divisor,
                    coordinates.component_pair_ref(),
                    &[],
                )?
                .0,
        );
    }
    let mut c2_blind_claims = Vec::with_capacity(selene_blinds.len());
    for blind in &selene_blinds {
        let coordinates = blind
            .point
            .expose_ref()
            .secret_coordinates_ref_v1()
            .ok_or(FcmpNativeErrorV1::ArithmeticInvariant)?;
        c2_blind_claims.push(
            c2_tape
                .append_claimed_point(
                    CYCLE_DLOG_PARAMETERS,
                    &blind.decomposition,
                    &blind.divisor,
                    coordinates.component_pair_ref(),
                    &[],
                )?
                .0,
        );
    }
    if c1_tape.commitment_count() > c1_rows || c2_tape.commitment_count() > c2_rows {
        return Err(FcmpNativeErrorV1::ArithmeticInvariant);
    }
    let mut c1_masks = c1_branch_masks;
    let c1_mask_allocation_capacity = c1_masks.capacity();
    while c1_masks.len() < c1_tape.commitment_count() {
        require_preallocated_push(c1_masks.len(), c1_masks.capacity())?;
        push_owned_secret_scalar_v1(&mut c1_masks, random_proof_scalar(rng)?)?;
        debug_assert_eq!(c1_masks.capacity(), c1_mask_allocation_capacity);
    }
    let mut c2_masks = c2_branch_masks;
    let c2_mask_allocation_capacity = c2_masks.capacity();
    while c2_masks.len() < c2_tape.commitment_count() {
        require_preallocated_push(c2_masks.len(), c2_masks.capacity())?;
        push_owned_secret_scalar_v1(&mut c2_masks, random_proof_scalar(rng)?)?;
        debug_assert_eq!(c2_masks.capacity(), c2_mask_allocation_capacity);
    }
    let root_mask_c1 =
        (root.curve() == FcmpTreeCurveV1::Selene).then(|| &c1_masks[root_commitment_index]);
    let root_mask_c2 =
        (root.curve() == FcmpTreeCurveV1::Helios).then(|| &c2_masks[root_commitment_index]);
    let (c1_secret_commitments, c1_openings) =
        c1_tape.commitments_and_openings::<SeleneSuite>(c1_generators, c1_masks.as_slice())?;
    let (c2_secret_commitments, c2_openings) =
        c2_tape.commitments_and_openings::<HeliosSuite>(c2_generators, c2_masks.as_slice())?;
    let (root_blind_commitment, mut root_nonce_c1, mut root_nonce_c2): (
        [u8; 32],
        Option<ProverSecretScalarV1<Field25519>>,
        Option<ProverSecretScalarV1<HelioseleneField>>,
    ) = match root.curve() {
        FcmpTreeCurveV1::Selene => {
            let nonce = random_proof_scalar::<Field25519>(rng)?;
            let mut commitment = root_nonce_commitment_v1::<SeleneSuite>(nonce.expose_ref())?;
            (commitment.encode_public_and_clear_v1()?, Some(nonce), None)
        }
        FcmpTreeCurveV1::Helios => {
            let nonce = random_proof_scalar::<HelioseleneField>(rng)?;
            let mut commitment = root_nonce_commitment_v1::<HeliosSuite>(nonce.expose_ref())?;
            (commitment.encode_public_and_clear_v1()?, None, Some(nonce))
        }
    };
    let public_inputs = prepared_inputs
        .iter()
        .map(|input| input.public)
        .collect::<Vec<_>>();
    let mut pseudo_outs = zeroizing_digest_buffer(public_inputs.len())?;
    let mut key_images = zeroizing_digest_buffer(public_inputs.len())?;
    for public in &public_inputs {
        pseudo_outs.push(public.pseudo_out);
        key_images.push(public.key_image);
    }
    if ct_has_duplicate_digests(&pseudo_outs) {
        return Err(FcmpNativeErrorV1::DuplicatePseudoOut);
    }
    if ct_has_duplicate_digests(&key_images) {
        return Err(FcmpNativeErrorV1::DuplicateKeyImage);
    }
    super::verify_fcmp_commitment_balance_v1(&public_inputs, &new_outputs)?;
    let context = membership_context(root, &public_inputs, root_blind_commitment)?;
    let mut transcript = ProverTranscript::new(context);
    let c1_commitments =
        transcript.write_secret_commitments::<SeleneSuite>(c1_secret_commitments)?;
    let c2_commitments =
        transcript.write_secret_commitments::<HeliosSuite>(c2_secret_commitments)?;
    let root_blind_response = match root.curve() {
        FcmpTreeCurveV1::Selene => {
            let challenge = transcript.challenge::<SeleneSuite>()?;
            let nonce = root_nonce_c1
                .as_mut()
                .ok_or(FcmpNativeErrorV1::ArithmeticInvariant)?;
            let mask = root_mask_c1.ok_or(FcmpNativeErrorV1::ArithmeticInvariant)?;
            nonce.add_product_assign(&challenge, mask);
            nonce.encode_public_and_clear_v1()
        }
        FcmpTreeCurveV1::Helios => {
            let challenge = transcript.challenge::<HeliosSuite>()?;
            let nonce = root_nonce_c2
                .as_mut()
                .ok_or(FcmpNativeErrorV1::ArithmeticInvariant)?;
            let mask = root_mask_c2.ok_or(FcmpNativeErrorV1::ArithmeticInvariant)?;
            nonce.add_product_assign(&challenge, mask);
            nonce.encode_public_and_clear_v1()
        }
    };
    let mut c1_circuit = Circuit::<SeleneSuite>::prove(c1_openings, c1_rows)?;
    let mut c2_circuit = Circuit::<HeliosSuite>::prove(c2_openings, c2_rows)?;
    let mut c1_dlog_challenge = None;
    let mut c2_dlog_challenge = None;
    let mut c1_commitment_openings = c1_commitments
        .iter()
        .copied()
        .zip(c1_masks.iter())
        .zip(c2_blind_claims)
        .map(|((commitment, mask), blind)| (commitment, Some(mask), blind));
    let mut c2_commitment_openings = c2_commitments
        .iter()
        .copied()
        .zip(c2_masks.iter())
        .zip(c1_blind_claims)
        .map(|((commitment, mask), blind)| (commitment, Some(mask), blind));
    for ((path, prepared), public) in transcripted_paths
        .into_iter()
        .zip(prepared_inputs.iter())
        .zip(&public_inputs)
    {
        constrain_input(
            native_parameters(),
            layers,
            &mut transcript,
            &mut c1_circuit,
            &mut c1_dlog_challenge,
            &mut c2_circuit,
            &mut c2_dlog_challenge,
            &root_variables,
            &mut path.c1_non_root.into_iter(),
            &mut path.c2_non_root.into_iter(),
            &mut c1_commitment_openings,
            &mut c2_commitment_openings,
            public,
            prepared.transcripted.clone(),
        )?;
    }
    if c1_commitment_openings.next().is_some() || c2_commitment_openings.next().is_some() {
        return Err(FcmpNativeErrorV1::ArithmeticInvariant);
    }
    let expected_c1_muls = inputs
        .len()
        .checked_mul(
            97_usize
                .checked_add(
                    layers
                        .saturating_sub(1)
                        .checked_div(2)
                        .ok_or(FcmpNativeErrorV1::ArithmeticInvariant)?
                        .checked_mul(52)
                        .ok_or(FcmpNativeErrorV1::TreeFull)?,
                )
                .ok_or(FcmpNativeErrorV1::TreeFull)?,
        )
        .ok_or(FcmpNativeErrorV1::TreeFull)?;
    let expected_c2_muls = inputs
        .len()
        .checked_mul(
            (layers / 2)
                .checked_mul(32)
                .ok_or(FcmpNativeErrorV1::TreeFull)?,
        )
        .ok_or(FcmpNativeErrorV1::TreeFull)?;
    if c1_circuit.muls() != expected_c1_muls || c2_circuit.muls() != expected_c2_muls {
        return Err(FcmpNativeErrorV1::ArithmeticInvariant);
    }
    let (c1_statement, c1_witness) = c1_circuit.proving_statement(c1_generators, c1_commitments)?;
    c1_statement.prove(
        &mut FcmpProofRandomSource::new(rng),
        &mut transcript,
        c1_witness,
    )?;
    let (c2_statement, c2_witness) = c2_circuit.proving_statement(c2_generators, c2_commitments)?;
    c2_statement.prove(
        &mut FcmpProofRandomSource::new(rng),
        &mut transcript,
        c2_witness,
    )?;
    let circuit_proof = transcript.complete();
    let range_proof = prove_fcmp_range_with_checked_rng_v1(rng, context_hash, new_output_openings)?;
    let expected_wire_len =
        fcmp_plus_plus_wire_size_v1(inputs.len(), root.layers(), new_outputs.len())?;
    let mut proof_wire = Vec::with_capacity(expected_wire_len);
    proof_wire.extend_from_slice(&FCMP_PROOF_WIRE_MAGIC_V1);
    proof_wire.push(u8::try_from(inputs.len()).map_err(|_| FcmpNativeErrorV1::TreeFull)?);
    proof_wire.push(root.layers());
    proof_wire
        .push(u8::try_from(new_outputs.len()).map_err(|_| FcmpNativeErrorV1::ArithmeticInvariant)?);
    proof_wire.push(0);
    if proof_wire.len() != FCMP_PROOF_WIRE_HEADER_BYTES_V1 {
        return Err(FcmpNativeErrorV1::ArithmeticInvariant);
    }
    for prepared in &prepared_inputs {
        proof_wire.extend_from_slice(&prepared.public.output_key_tilde);
        proof_wire.extend_from_slice(&prepared.public.linking_tag_generator_tilde);
        proof_wire.extend_from_slice(&prepared.public.rerandomization_commitment);
        proof_wire.extend_from_slice(&prepared.sal.encode());
    }
    proof_wire.extend(circuit_proof);
    proof_wire.extend_from_slice(&root_blind_commitment);
    proof_wire.extend_from_slice(&root_blind_response);
    proof_wire.extend(range_proof.encode(new_outputs.len())?);
    if proof_wire.len() != expected_wire_len {
        return Err(FcmpNativeErrorV1::ProofLength {
            actual: proof_wire.len(),
            expected: expected_wire_len,
        });
    }
    Ok(FcmpProvedBundleV1 {
        proof_wire,
        public_inputs,
    })
}
fn retry_membership_prover<T>(
    mut prove_once: impl FnMut() -> Result<T, FcmpNativeErrorV1>,
) -> Result<T, FcmpNativeErrorV1> {
    for _ in 0..MAX_MEMBERSHIP_PROVER_RESTARTS_V1 {
        match prove_once() {
            Ok(proof) => return Ok(proof),
            Err(
                FcmpNativeErrorV1::TranscriptChallengeExhausted
                | FcmpNativeErrorV1::DlogChallengeExhausted
                | FcmpNativeErrorV1::DlogWitnessPole
                | FcmpNativeErrorV1::CircuitProverCommitmentIdentity
                | FcmpNativeErrorV1::InnerProductRoundIdentity,
            ) => {
                continue;
            }
            Err(error) => return Err(error),
        }
    }
    Err(FcmpNativeErrorV1::MembershipProverRestartExhausted)
}
struct FcmpProverPreflightV1 {
    new_outputs: Vec<FcmpOutputTupleV1>,
    public_inputs: Vec<FcmpProofInputPublicV1>,
}
fn preflight_fcmp_plus_plus_v1(
    inputs: &[FcmpProverInputV1],
    new_output_openings: &[FcmpOutputCommitmentOpeningV1],
    root: FcmpTreeRootV1,
) -> Result<FcmpProverPreflightV1, FcmpNativeErrorV1> {
    if inputs.is_empty() || inputs.len() > super::FCMP_MAX_INPUTS_NATIVE_V1 {
        return Err(FcmpNativeErrorV1::InputCount {
            actual: inputs.len(),
            max: super::FCMP_MAX_INPUTS_NATIVE_V1,
        });
    }
    if new_output_openings.is_empty()
        || new_output_openings.len() > super::FCMP_MAX_OUTPUTS_NATIVE_V1
    {
        return Err(FcmpNativeErrorV1::OutputCount {
            actual: new_output_openings.len(),
            max: super::FCMP_MAX_OUTPUTS_NATIVE_V1,
        });
    }
    let mut spent_outputs = zeroizing_digest_buffer(inputs.len())?;
    let mut key_images = zeroizing_digest_buffer(inputs.len())?;
    let mut public_inputs = Vec::with_capacity(inputs.len());
    let mut paths = Vec::with_capacity(inputs.len());
    for input in inputs {
        require_preallocated_push(spent_outputs.len(), spent_outputs.capacity())?;
        push_owned_secret_output_id_v1(&mut spent_outputs, input.output.secret_output_id_v1())?;
        let public = input.public_input()?;
        key_images.push(public.key_image);
        public_inputs.push(public);
        paths.push(parse_path(input, root)?);
    }
    if ct_has_duplicate_digests(&spent_outputs) {
        return Err(FcmpNativeErrorV1::DuplicateOutput);
    }
    if ct_has_duplicate_digests(&key_images) {
        return Err(FcmpNativeErrorV1::DuplicateKeyImage);
    }
    let shared_root = &paths
        .first()
        .ok_or(FcmpNativeErrorV1::ArithmeticInvariant)?
        .root;
    if !all_paths_share_root(&paths, shared_root) {
        return Err(FcmpNativeErrorV1::RootMismatch);
    }
    let mut pseudo_outs = zeroizing_digest_buffer(public_inputs.len())?;
    for public in &public_inputs {
        pseudo_outs.push(public.pseudo_out);
    }
    if ct_has_duplicate_digests(&pseudo_outs) {
        return Err(FcmpNativeErrorV1::DuplicatePseudoOut);
    }
    let new_outputs = new_output_openings
        .iter()
        .map(FcmpOutputCommitmentOpeningV1::output)
        .collect::<Vec<_>>();
    let mut new_output_ids = zeroizing_digest_buffer(new_outputs.len())?;
    for output in &new_outputs {
        new_output_ids.push(output.output_id());
    }
    if ct_has_duplicate_digests(&new_output_ids) {
        return Err(FcmpNativeErrorV1::DuplicateOutput);
    }
    super::verify_fcmp_commitment_balance_v1(&public_inputs, &new_outputs)?;
    Ok(FcmpProverPreflightV1 {
        new_outputs,
        public_inputs,
    })
}
/// Prove a complete first-release FCMP++ statement in native Rust.
///
/// Each input supplies its statement-visible rerandomization witness; all zero-knowledge proof
/// nonces and vector-commitment masks are sampled internally. The supplied paths must resolve
/// exactly to `root`, and all input paths must use the same canonical root branch. A transcript
/// challenge can exhaust the public exceptional-point sampler or hit a hidden dlog denominator
/// pole, exhaust its non-zero transcript challenge sampler, or produce an identity inner-product
/// round point with negligible probability; the prover rebuilds the commitments and transcript with
/// fresh randomness at a fixed bound instead of exposing an honest-abort failure.
pub fn prove_fcmp_plus_plus_v1(
    rng: &mut (impl RngCore + CryptoRng),
    context_hash: [u8; 32],
    inputs: &[FcmpProverInputV1],
    new_output_openings: &[FcmpOutputCommitmentOpeningV1],
    root: FcmpTreeRootV1,
) -> Result<FcmpProvedBundleV1, FcmpNativeErrorV1> {
    let preflight = preflight_fcmp_plus_plus_v1(inputs, new_output_openings, root)?;
    let mut checked_rng = super::health_checked_fcmp_rng_v1(rng)?;
    let bundle = retry_membership_prover(|| {
        prove_fcmp_plus_plus_once_v1(
            &mut checked_rng,
            context_hash,
            inputs,
            new_output_openings,
            root,
        )
    })?;
    if bundle.public_inputs != preflight.public_inputs {
        return Err(FcmpNativeErrorV1::ProverSelfCheckFailed);
    }
    super::verify_fcmp_transaction_v1(
        context_hash,
        bundle.proof_wire(),
        bundle.public_inputs(),
        &preflight.new_outputs,
        root,
    )
    .map_err(|_| FcmpNativeErrorV1::ProverSelfCheckFailed)?;
    Ok(bundle)
}
#[cfg(test)]
#[path = "prover/tests.rs"]
mod tests;
