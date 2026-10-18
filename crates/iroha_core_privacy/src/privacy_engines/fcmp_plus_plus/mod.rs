//! Native first-release FCMP++ primitives.
//!
//! This module implements the canonical Monero output tuple, strict Ed25519/Selene/Helios
//! encodings, the alternating FCMP++ curve-tree accumulator, bounded proof-wire parser,
//! Spend-Authorization-and-Linkability proof, canonical native dual generalized-Bulletproof
//! membership, strict-positive `u64` Bulletproofs+ output ranges, conservation, and the
//! authenticated fixed wallet note. Structural parsing remains a separate type and is never treated
//! as cryptographic verification.
//!
//! The FCMP++ construction and curve constants are derived from the
//! MIT-licensed `full-chain-membership-proofs`, `helioselene`, and
//! `monero-fcmp-plus-plus` crates (Copyright 2024 Luke Parker).
mod balance;
mod bulletproof;
mod circuit;
mod divisor;
mod field;
mod membership;
mod proof_math;
mod prover;
mod range;
#[cfg(feature = "privacy-release-evidence")]
#[doc(hidden)]
pub mod release_evidence_access;
mod sal;
mod tree;
mod wallet;
mod wire;
use self::field::{HeliosPoint, SelenePoint, decode_edwards_point};
use super::prover_randomness::{
    CURVE_PROVER_RANDOMNESS_POLICY_V1, HealthCheckedCryptoRngV1, ProverRandomnessErrorV1,
};
use iroha_data_model::{
    NetworkId,
    privacy::{
        PrivacyEngineManifestDigestV1, PrivacyParameterDigestV1, PrivacyParameterIdV1,
        PrivacyStatementDigestV1, PrivacyStatementSchemaDigestV1, PrivacyVerifierDigestV1,
    },
};
use sha2::{Digest as _, Sha256};
use thiserror::Error;
use zeroize::{Zeroize, Zeroizing};
#[cfg(test)]
pub(super) struct FailingRngV1;
#[cfg(test)]
impl rand_core_06::RngCore for FailingRngV1 {
    fn next_u32(&mut self) -> u32 {
        panic!("FCMP++ must use the fallible RNG interface")
    }
    fn next_u64(&mut self) -> u64 {
        panic!("FCMP++ must use the fallible RNG interface")
    }
    fn fill_bytes(&mut self, _destination: &mut [u8]) {
        panic!("FCMP++ must use the fallible RNG interface")
    }
    fn try_fill_bytes(&mut self, _destination: &mut [u8]) -> Result<(), rand_core_06::Error> {
        Err(rand_core_06::Error::new("injected FCMP++ RNG failure"))
    }
}
#[cfg(test)]
impl rand_core_06::CryptoRng for FailingRngV1 {}
#[cfg(test)]
pub(crate) use self::membership::verify_fcmp_plus_plus_v1;
#[cfg(any(test, feature = "test-utils"))]
#[doc(hidden)]
pub use self::prover::fcmp_test_spendable_output_v1;
#[cfg(test)]
pub use self::wallet::decrypt_fcmp_wallet_note_v1;
pub use self::{
    balance::{verify_fcmp_commitment_balance_v1, verify_fcmp_transaction_v1},
    prover::{
        FcmpInputRerandomizationV1, FcmpProvedBundleV1, FcmpProverInputV1, prove_fcmp_plus_plus_v1,
    },
    range::{
        FCMP_AMOUNT_BITS_V1, FCMP_BP_PLUS_GENERATOR_DIGEST_V1, FCMP_BP_PLUS_UPSTREAM_REVISION_V1,
        FCMP_MAX_RANGE_COMMITMENTS_V1, FCMP_RANGE_COMMITMENTS_PER_OUTPUT_V1,
        FcmpOutputCommitmentOpeningV1, FcmpRangeProofV1, fcmp_bp_plus_generator_digest_v1,
        fcmp_range_proof_size_v1, verify_fcmp_range_v1,
    },
    sal::{FCMP_SAL_PROOF_BYTES_V1, FcmpSalProofV1, FcmpSalWitnessV1, verify_fcmp_sal_v1},
    tree::{
        FcmpFrontierPartsV1, append_fcmp_outputs_v1, build_fcmp_frontier_v1,
        validate_fcmp_frontier_v1,
    },
    wallet::{
        FcmpWalletNoteV1, derive_fcmp_recipient_id_v1, encrypt_fcmp_wallet_note_v1,
        fcmp_recipient_public_key_v1, validate_fcmp_encrypted_output_v1,
    },
    wire::{
        FCMP_MAX_INPUTS_NATIVE_V1, FCMP_MAX_PROOF_WIRE_BYTES_V1, FCMP_MIN_PROOF_WIRE_BYTES_V1,
        FCMP_PROOF_INPUT_BYTES_V1, FCMP_PROOF_WIRE_HEADER_BYTES_V1, FCMP_PROOF_WIRE_MAGIC_V1,
        FcmpProofInputPublicV1, ParsedFcmpPlusPlusWireV1, ParsedFcmpProofInputV1,
        decode_fcmp_plus_plus_wire_v1, fcmp_plus_plus_wire_size_v1,
    },
};
#[cfg(test)]
pub use self::{range::prove_fcmp_range_v1, sal::prove_fcmp_sal_v1};
/// Upstream FCMP++ revision used for the native first-release port and interoperability vectors.
pub const FCMP_UPSTREAM_REVISION_V1: &str = "15ef71140944b5b5d2feff0e58569b71f34c84a2";
/// Auditable source profile for the clean-room native port.
pub const FCMP_SOURCE_PROFILE_V1: &[u8] = b"iroha-native-rust:clean-room:full-chain-membership-proofs+helioselene+monero-fcmp-plus-plus:15ef71140944b5b5d2feff0e58569b71f34c84a2:v1";
/// Complete consensus fields bound into every native FCMP++ transcript.
#[derive(Clone, Copy, Debug)]
pub struct FcmpRuntimeContextBindingV1<'a> {
    /// Exact genesis-header-derived network identity.
    pub network_id: &'a NetworkId,
    /// Zero-based action index in the direct privacy transaction.
    pub action_index: u32,
    /// Digest of the complete typed public statement.
    pub statement_digest: PrivacyStatementDigestV1,
    /// Governed parameter identifier.
    pub parameter_id: PrivacyParameterIdV1,
    /// Governed parameter archive digest.
    pub parameter_digest: PrivacyParameterDigestV1,
    /// Native verifier digest.
    pub verifier_digest: PrivacyVerifierDigestV1,
    /// Typed statement-schema digest.
    pub statement_schema_digest: PrivacyStatementSchemaDigestV1,
    /// Complete compiled engine-manifest digest.
    pub engine_manifest_digest: PrivacyEngineManifestDigestV1,
}
/// Derive the sole canonical native FCMP++ runtime transcript digest.
///
/// Both wallet-side proving and validator-side verification call this function, preventing either
/// boundary from carrying a private copy of the transcript framing.
#[must_use]
pub fn derive_fcmp_runtime_context_hash_v1(binding: &FcmpRuntimeContextBindingV1<'_>) -> [u8; 32] {
    const DOMAIN: &[u8] = b"iroha.privacy.fcmp-plus-plus.runtime-context.v1";
    let mut hash = Sha256::new();
    hash.update(DOMAIN);
    hash.update(binding.network_id.as_bytes());
    hash.update(binding.action_index.to_be_bytes());
    hash.update(binding.statement_digest.as_bytes());
    hash.update(binding.parameter_id.as_bytes());
    hash.update(binding.parameter_digest.as_bytes());
    hash.update(binding.verifier_digest.as_bytes());
    hash.update(binding.statement_schema_digest.as_bytes());
    hash.update(binding.engine_manifest_digest.as_bytes());
    hash.finalize().into()
}
/// Canonical description of every fixed first-release FCMP++ parameter family.
///
/// The compiled privacy profile hashes these bytes together with the numeric wire and tree bounds
/// below. Changing a curve, transcript, generator derivation, circuit dimension, or proof equation
/// therefore requires an explicit manifest revision instead of silently retaining an activation
/// fingerprint for different consensus code.
pub const FCMP_COMPILED_PROFILE_DESCRIPTOR_V1: &[u8] = b"fcmp++:ed25519-sal-blake2b512|field25519:7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed|helioselene-field:7fffffffffffffffffffffffffffffffbf7f782cb7656b586eb6d2727927c79f|helios:a=-3,b=22e8c739b0ea70b8be94a76b3ebb7b3b043f6f384113bf3522b49ee1edd73ad4|selene:a=-3,b=70127713695876c17f51bba595ffe279f3944bdf06ae900e68de0983cb5a4558|curve-tree:selene38-helios18-alternating-zero-pad|hash:keccak256-monero-domains|rng:rand-core06-try-fill-fail-closed+shared-fixed64-reservoir-health-check-zeroize-poison-on-error-or-unwind|sal:nonzero-prover-scalars-retry128+full-proof-retry128-on-point-or-challenge|membership-bp:blake2b512-tagged-transcript-nonzero-challenge-retry128-bounded-canonical-rng128-selene4096-helios2048|dlog:ed253-cycle255-divisor-backed-point-lift-retry128-exceptional-tuple-retry128|membership-restart:full-proof-retry128-on-transcript-or-dlog-exhaustion+hidden-pole+generalized-bulletproof-commitment-identity+inner-product-identity|membership:dual-generalized-bulletproofs+root-blind-pok|range:monero-bulletproofs-plus-64bit-ordered-C-and-C-minus-H-strict-positive-u64-outputs-max4+range-commitments-max8-keccak-transcript-context-output-order-bound+nonzero-prover-scalar-retry128+full-proof-retry128-on-point-or-challenge|witness:caller-explicit-rerandomization+full-input-output-path-scalar-vector-divisor-zeroize-on-drop+redacted-debug|balance:sum-pseudo-out-equals-sum-new-output-C-nonidentity|producer:deterministic-preflight-before-entropy+full-transaction-self-verify|wallet:IFCE-fixed280-x25519-sha256-kdf-xchacha20poly1305-authenticated-amount-u64le-commitment-mask-pool-recipient-ephemeral-output-tuple-aad+secret-key-shared-secret-plaintext-zeroize-on-drop|wire:IFC1-u8-inputs-u8-layers-u8-outputs-reserved0-membership-range-strict-exact|first-release:no-legacy:v1";
/// SHA-256 digest of the deterministic complete one-layer native IFC1
/// transfer vector. Its membership component retains the pinned upstream
/// encoding; the appended range proof is Iroha statement-bound.
pub const FCMP_NATIVE_KAT_WIRE_SHA256_V1: [u8; 32] = [
    0x79, 0x21, 0x0c, 0x93, 0xa4, 0xdb, 0xc9, 0x98, 0xd5, 0xa5, 0x61, 0xa4, 0x45, 0xb8, 0xa7, 0x13,
    0x6c, 0xa2, 0x5d, 0x2e, 0x29, 0xbf, 0x58, 0xda, 0xb7, 0x69, 0x54, 0x73, 0xdb, 0x35, 0xf0, 0xc4,
];
/// SHA-256 digest of the deterministic one-layer native public relation used
/// by the complete transfer vector.
pub const FCMP_NATIVE_KAT_PUBLIC_SHA256_V1: [u8; 32] = [
    0x20, 0xa7, 0xae, 0x5b, 0x4e, 0xa3, 0x8f, 0xb1, 0x5a, 0x85, 0x05, 0x30, 0x71, 0xe8, 0xfb, 0xb9,
    0x7b, 0x7d, 0x78, 0x63, 0xee, 0xfc, 0x06, 0x06, 0x50, 0x9a, 0xff, 0x79, 0x8c, 0xc3, 0xc6, 0x02,
];
/// Number of output tuples in one first-layer Selene branch.
pub const FCMP_LAYER_ONE_LEN_V1: usize = 38;
/// Number of child hashes in one second-layer Helios branch.
pub const FCMP_LAYER_TWO_LEN_V1: usize = 18;
/// Maximum FCMP++ tree layers representable by the first-release compact wire.
pub const FCMP_MAX_TREE_LAYERS_V1: u8 = 32;
/// Exact canonical compressed point width.
pub const FCMP_POINT_BYTES_V1: usize = 32;
/// Exact O/I/C output-tuple width.
pub const FCMP_OUTPUT_TUPLE_BYTES_V1: usize = 3 * FCMP_POINT_BYTES_V1;
/// Maximum newly created output count accepted by the complete native transaction verifier.
pub const FCMP_MAX_OUTPUTS_NATIVE_V1: usize = 4;
fn health_checked_fcmp_rng_v1<R>(
    rng: &mut R,
) -> Result<HealthCheckedCryptoRngV1<'_, R>, FcmpNativeErrorV1>
where
    R: rand_core_06::CryptoRng + rand_core_06::RngCore,
{
    HealthCheckedCryptoRngV1::new(rng).map_err(|error| match error {
        ProverRandomnessErrorV1::Unavailable => FcmpNativeErrorV1::RandomnessUnavailable,
        ProverRandomnessErrorV1::Unhealthy => FcmpNativeErrorV1::RandomnessHealthCheckFailed,
    })
}
const OUTPUT_ID_DOMAIN_V1: &[u8] = b"iroha.privacy.monero-fcmp-plus-plus.output-id.v1";
/// Digest the exact native implementation profile used by governance fingerprints.
#[must_use]
pub fn fcmp_compiled_profile_digest_v1() -> [u8; 32] {
    const DOMAIN: &[u8] = b"iroha.privacy.fcmp-plus-plus.compiled-profile.v1";
    let dimensions = [
        u64::try_from(FCMP_LAYER_ONE_LEN_V1).unwrap_or(u64::MAX),
        u64::try_from(FCMP_LAYER_TWO_LEN_V1).unwrap_or(u64::MAX),
        u64::from(FCMP_MAX_TREE_LAYERS_V1),
        u64::try_from(FCMP_POINT_BYTES_V1).unwrap_or(u64::MAX),
        u64::try_from(FCMP_OUTPUT_TUPLE_BYTES_V1).unwrap_or(u64::MAX),
        u64::try_from(FCMP_SAL_PROOF_BYTES_V1).unwrap_or(u64::MAX),
        u64::try_from(FCMP_MAX_INPUTS_NATIVE_V1).unwrap_or(u64::MAX),
        u64::try_from(FCMP_MAX_OUTPUTS_NATIVE_V1).unwrap_or(u64::MAX),
        u64::try_from(FCMP_PROOF_WIRE_HEADER_BYTES_V1).unwrap_or(u64::MAX),
        u64::try_from(FCMP_PROOF_INPUT_BYTES_V1).unwrap_or(u64::MAX),
        u64::try_from(FCMP_MIN_PROOF_WIRE_BYTES_V1).unwrap_or(u64::MAX),
        u64::try_from(FCMP_MAX_PROOF_WIRE_BYTES_V1).unwrap_or(u64::MAX),
        u64::try_from(FCMP_AMOUNT_BITS_V1).unwrap_or(u64::MAX),
        u64::try_from(FCMP_RANGE_COMMITMENTS_PER_OUTPUT_V1).unwrap_or(u64::MAX),
        u64::try_from(fcmp_range_proof_size_v1(1).unwrap_or(usize::MAX)).unwrap_or(u64::MAX),
        u64::try_from(fcmp_range_proof_size_v1(FCMP_MAX_OUTPUTS_NATIVE_V1).unwrap_or(usize::MAX))
            .unwrap_or(u64::MAX),
    ];
    let mut hasher = Sha256::new();
    hasher.update(DOMAIN);
    for field in [
        FCMP_SOURCE_PROFILE_V1,
        FCMP_UPSTREAM_REVISION_V1.as_bytes(),
        FCMP_BP_PLUS_UPSTREAM_REVISION_V1.as_bytes(),
        FCMP_COMPILED_PROFILE_DESCRIPTOR_V1,
        CURVE_PROVER_RANDOMNESS_POLICY_V1,
        &FCMP_BP_PLUS_GENERATOR_DIGEST_V1,
        &FCMP_PROOF_WIRE_MAGIC_V1,
        OUTPUT_ID_DOMAIN_V1,
        &FCMP_NATIVE_KAT_WIRE_SHA256_V1,
        &FCMP_NATIVE_KAT_PUBLIC_SHA256_V1,
    ] {
        hasher.update(u64::try_from(field.len()).unwrap_or(u64::MAX).to_be_bytes());
        hasher.update(field);
    }
    for dimension in dimensions {
        hasher.update(dimension.to_be_bytes());
    }
    hasher.finalize().into()
}
/// Validate one canonical, torsion-free, non-identity FCMP++ Edwards point.
///
/// This is the shared validation boundary for O/I/C output components and the public O~/I~/R/C~/L
/// relation. It rejects identity, small-order, non-canonical, and off-curve encodings.
///
/// # Errors
/// Returns an encoding error for an off-curve, non-canonical or non-torsion-free point,
/// or an identity error for the identity point.
pub fn validate_fcmp_edwards_point_v1(
    point: [u8; FCMP_POINT_BYTES_V1],
) -> Result<(), FcmpNativeErrorV1> {
    decode_edwards_point(point, false).map(|_| ())
}
/// Curve carrying an FCMP++ output-set root.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FcmpTreeCurveV1 {
    /// Odd layers, including the leaf layer, hash to Selene.
    Selene,
    /// Even layers hash to Helios.
    Helios,
}
/// One canonical hidden FCMP++ output-tree leaf.
///
/// The tuple is `(O, I, C)` as defined by FCMP++; it is not a digest or a
/// Pedersen commitment standing in for the tuple.  Each component is a
/// canonical, torsion-free, non-identity Ed25519 point.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct FcmpOutputTupleV1 {
    output_key: [u8; FCMP_POINT_BYTES_V1],
    linking_tag_generator: [u8; FCMP_POINT_BYTES_V1],
    amount_commitment: [u8; FCMP_POINT_BYTES_V1],
}
impl Zeroize for FcmpOutputTupleV1 {
    fn zeroize(&mut self) {
        self.output_key.zeroize();
        self.linking_tag_generator.zeroize();
        self.amount_commitment.zeroize();
    }
}
/// Move-only owner for a hidden spent-output identifier.
///
/// The nested owner clears the digest on normal return, error, and unwind;
/// callers can only borrow it until an audited preallocated insertion.
pub(crate) struct FcmpSecretOutputIdV1(wallet::WalletSecretCopyValueV1<[u8; 32]>);
impl FcmpSecretOutputIdV1 {
    pub(crate) fn as_ref(&self) -> &[u8; 32] {
        self.0.expose_ref()
    }
}
impl Drop for FcmpSecretOutputIdV1 {
    fn drop(&mut self) {
        #[cfg(test)]
        let _ = FCMP_SECRET_OUTPUT_ID_DROPS_V1.try_with(|drops| {
            drops.set(drops.get().saturating_add(1));
        });
    }
}
#[cfg(test)]
std::thread_local! {
    #[cfg(test)]
    static FCMP_SECRET_OUTPUT_ID_DROPS_V1: std::cell::Cell<usize> =
        const { std::cell::Cell::new(0) };
}
impl FcmpOutputTupleV1 {
    /// Construct one strict FCMP++ `(O, I, C)` output tuple.
    ///
    /// # Errors
    /// Returns an error if any component is not a canonical, torsion-free,
    /// non-identity Edwards point.
    pub fn new(
        output_key: [u8; FCMP_POINT_BYTES_V1],
        linking_tag_generator: [u8; FCMP_POINT_BYTES_V1],
        amount_commitment: [u8; FCMP_POINT_BYTES_V1],
    ) -> Result<Self, FcmpNativeErrorV1> {
        validate_fcmp_edwards_point_v1(output_key)?;
        validate_fcmp_edwards_point_v1(linking_tag_generator)?;
        validate_fcmp_edwards_point_v1(amount_commitment)?;
        Ok(Self {
            output_key,
            linking_tag_generator,
            amount_commitment,
        })
    }
    /// Decode exactly 96 canonical bytes.
    ///
    /// # Errors
    /// Returns an error if the input length differs from the tuple width or any
    /// decoded component fails the point checks in [`Self::new`].
    pub fn decode(bytes: &[u8]) -> Result<Self, FcmpNativeErrorV1> {
        if bytes.len() != FCMP_OUTPUT_TUPLE_BYTES_V1 {
            return Err(FcmpNativeErrorV1::OutputTupleLength {
                actual: bytes.len(),
                expected: FCMP_OUTPUT_TUPLE_BYTES_V1,
            });
        }
        let mut output_key = [0_u8; FCMP_POINT_BYTES_V1];
        let mut linking_tag_generator = [0_u8; FCMP_POINT_BYTES_V1];
        let mut amount_commitment = [0_u8; FCMP_POINT_BYTES_V1];
        output_key.copy_from_slice(&bytes[..32]);
        linking_tag_generator.copy_from_slice(&bytes[32..64]);
        amount_commitment.copy_from_slice(&bytes[64..96]);
        Self::new(output_key, linking_tag_generator, amount_commitment)
    }
    /// Return the canonical `(O, I, C)` components.
    pub const fn components(
        self,
    ) -> (
        [u8; FCMP_POINT_BYTES_V1],
        [u8; FCMP_POINT_BYTES_V1],
        [u8; FCMP_POINT_BYTES_V1],
    ) {
        (
            self.output_key,
            self.linking_tag_generator,
            self.amount_commitment,
        )
    }
    /// Borrow the canonical `(O, I, C)` components without copying hidden
    /// tuple bytes into by-value prover slots.
    pub(crate) const fn component_refs_v1(
        &self,
    ) -> (
        &[u8; FCMP_POINT_BYTES_V1],
        &[u8; FCMP_POINT_BYTES_V1],
        &[u8; FCMP_POINT_BYTES_V1],
    ) {
        (
            &self.output_key,
            &self.linking_tag_generator,
            &self.amount_commitment,
        )
    }
    /// Derive a hidden spent-output identifier without copying the tuple into
    /// a by-value receiver or leaving SHA-256 state and encoding scratch alive.
    pub(crate) fn secret_output_id_v1(&self) -> FcmpSecretOutputIdV1 {
        let mut encoded = Zeroizing::new([0_u8; FCMP_OUTPUT_TUPLE_BYTES_V1]);
        let (output_key, linking_tag_generator, amount_commitment) = self.component_refs_v1();
        encoded[..32].copy_from_slice(output_key);
        encoded[32..64].copy_from_slice(linking_tag_generator);
        encoded[64..].copy_from_slice(amount_commitment);
        FcmpSecretOutputIdV1(wallet::secret_sha256_v1(&[
            OUTPUT_ID_DOMAIN_V1,
            encoded.as_ref(),
        ]))
    }
    /// Encode the tuple without framing.
    pub fn encode(self) -> [u8; FCMP_OUTPUT_TUPLE_BYTES_V1] {
        let mut encoded = [0; FCMP_OUTPUT_TUPLE_BYTES_V1];
        encoded[..32].copy_from_slice(&self.output_key);
        encoded[32..64].copy_from_slice(&self.linking_tag_generator);
        encoded[64..].copy_from_slice(&self.amount_commitment);
        encoded
    }
    /// Derive the namespace-independent tuple identifier used only for ledger
    /// indexing and duplicate detection.
    ///
    /// This digest is not substituted for the tuple in the curve tree or membership relation.
    pub fn output_id(self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(OUTPUT_ID_DOMAIN_V1);
        hasher.update(self.encode());
        hasher.finalize().into()
    }
}
/// Canonical FCMP++ tree root with its cryptographically significant layer count.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FcmpTreeRootV1 {
    layers: u8,
    point: [u8; FCMP_POINT_BYTES_V1],
}
impl FcmpTreeRootV1 {
    /// Validate a root against the curve selected by layer parity.
    ///
    /// # Errors
    /// Returns an error if the layer count is outside the compiled range or the
    /// point is not a canonical, non-identity point on the selected curve.
    pub fn new(layers: u8, point: [u8; FCMP_POINT_BYTES_V1]) -> Result<Self, FcmpNativeErrorV1> {
        validate_layer_count(layers)?;
        match curve_for_layers(layers) {
            FcmpTreeCurveV1::Selene => {
                SelenePoint::decode(point, false)?;
            }
            FcmpTreeCurveV1::Helios => {
                HeliosPoint::decode(point, false)?;
            }
        }
        Ok(Self { layers, point })
    }
    fn from_selene(layers: u8, point: SelenePoint) -> Result<Self, FcmpNativeErrorV1> {
        if curve_for_layers(layers) != FcmpTreeCurveV1::Selene || point.is_identity() {
            return Err(FcmpNativeErrorV1::RootCurve);
        }
        Self::new(layers, point.encode())
    }
    fn from_helios(layers: u8, point: HeliosPoint) -> Result<Self, FcmpNativeErrorV1> {
        if curve_for_layers(layers) != FcmpTreeCurveV1::Helios || point.is_identity() {
            return Err(FcmpNativeErrorV1::RootCurve);
        }
        Self::new(layers, point.encode())
    }
    /// Number of alternating curve-tree layers.
    pub const fn layers(self) -> u8 {
        self.layers
    }
    /// Curve carrying this root.
    pub const fn curve(self) -> FcmpTreeCurveV1 {
        curve_for_layers(self.layers)
    }
    /// Canonical compressed Selene or Helios point.
    pub const fn point(self) -> [u8; FCMP_POINT_BYTES_V1] {
        self.point
    }
}
/// Native FCMP++ codec, accumulator, or structural proof failure.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
pub enum FcmpNativeErrorV1 {
    /// An O/I/C tuple did not have exactly 96 bytes.
    #[error("FCMP++ output tuple length {actual} does not equal {expected}")]
    OutputTupleLength {
        /// Supplied byte length.
        actual: usize,
        /// Required byte length.
        expected: usize,
    },
    /// A compressed Ed25519 point was non-canonical, off-curve, or not in the prime-order subgroup.
    #[error("FCMP++ Ed25519 point encoding is invalid")]
    EdwardsPointEncoding,
    /// A public Ed25519 tuple component was the identity.
    #[error("FCMP++ public Ed25519 point must be non-identity")]
    EdwardsPointIdentity,
    /// A compressed Selene/Helios point was non-canonical or off-curve.
    #[error("FCMP++ Selene/Helios point encoding is invalid")]
    CyclePointEncoding,
    /// A Selene/Helios point used a forbidden identity or negative-zero encoding.
    #[error("FCMP++ Selene/Helios point must be non-identity")]
    CyclePointIdentity,
    /// A scalar was not reduced modulo its exact curve field.
    #[error("FCMP++ scalar encoding is non-canonical")]
    ScalarEncoding,
    /// An invariant expected from a validated curve point did not hold.
    #[error("FCMP++ curve arithmetic invariant failed")]
    ArithmeticInvariant,
    /// A caller-supplied prover RNG failed to produce a non-zero scalar within
    /// the fixed retry bound.
    #[error("FCMP++ prover randomness exhausted its fixed retry bound")]
    ProverRandomnessExhausted,
    /// The caller-supplied cryptographic RNG reported that entropy was unavailable.
    #[error("FCMP++ cryptographic randomness is unavailable")]
    RandomnessUnavailable,
    /// The caller-supplied cryptographic RNG repeated a catastrophic
    /// constant or short-period prefix.
    #[error("FCMP++ cryptographic randomness failed its health check")]
    RandomnessHealthCheckFailed,
    /// The independently invoked complete transaction verifier rejected the
    /// proof just produced by the native prover.
    #[error("FCMP++ native prover self-check failed")]
    ProverSelfCheckFailed,
    /// Every domain-separated retry for a required non-zero generalized
    /// Bulletproof transcript challenge reduced to zero.
    #[error("FCMP++ transcript challenge exhausted its fixed non-zero retry bound")]
    TranscriptChallengeExhausted,
    /// No bounded transcript-derived embedded-curve challenge avoided every
    /// public exceptional denominator required by the dlog gadget.
    #[error("FCMP++ dlog challenge exhausted its fixed exceptional-point retry bound")]
    DlogChallengeExhausted,
    /// A transcript challenge hit a hidden dlog denominator pole. The
    /// complete membership prover retries this event with fresh commitments.
    #[error("FCMP++ dlog challenge hit a hidden witness denominator pole")]
    DlogWitnessPole,
    /// A randomized generalized-Bulletproof commitment was the identity. The complete membership
    /// prover retries this negligible honest abort with fresh commitments.
    #[error("FCMP++ generalized-Bulletproof prover commitment was the identity")]
    CircuitProverCommitmentIdentity,
    /// An inner-product prover round produced an identity commitment. The complete membership
    /// prover retries this negligible honest abort with fresh commitments.
    #[error("FCMP++ inner-product prover round produced an identity commitment")]
    InnerProductRoundIdentity,
    /// Every bounded complete membership-proof attempt hit a retryable transcript/dlog exhaustion,
    /// hidden denominator pole, or inner-product identity.
    #[error("FCMP++ membership prover exhausted its fixed restart bound")]
    MembershipProverRestartExhausted,
    /// A branch was empty or exceeded its compiled curve width.
    #[error("FCMP++ curve-tree branch width is invalid")]
    BranchWidth,
    /// A root had zero, excessive, or wrong-parity layers.
    #[error("FCMP++ tree layer count is invalid")]
    LayerCount,
    /// A root point did not match the curve selected by layer parity.
    #[error("FCMP++ tree root curve does not match layer parity")]
    RootCurve,
    /// An output set or append batch was empty.
    #[error("FCMP++ output set must be non-empty")]
    EmptyOutputSet,
    /// A tuple was duplicated within the supplied append batch.
    #[error("FCMP++ append batch contains a duplicate output tuple")]
    DuplicateOutput,
    /// Two public inputs reused the same pseudo-out.
    #[error("FCMP++ proof inputs contain a duplicate pseudo-out")]
    DuplicatePseudoOut,
    /// Two public inputs reused the same key image.
    #[error("FCMP++ proof inputs contain a duplicate key image")]
    DuplicateKeyImage,
    /// The persisted compact frontier shape disagreed with its tree size.
    #[error("FCMP++ compact frontier has a non-canonical mixed-radix shape")]
    FrontierShape,
    /// Reconstructing a compact frontier produced a different root.
    #[error("FCMP++ compact frontier root does not match reconstructed state")]
    RootMismatch,
    /// The mixed-radix tree cannot represent another output.
    #[error("FCMP++ output-set tree is full")]
    TreeFull,
    /// The proof wire did not use the sole first-release magic/version.
    #[error("FCMP++ proof wire magic/version is not IFC1")]
    ProofWireMagic,
    /// Reserved proof-wire header bytes were nonzero.
    #[error("FCMP++ proof wire reserved header bytes must be zero")]
    ProofWireReserved,
    /// The proof input count was outside the compiled first-release range.
    #[error("FCMP++ proof input count {actual} is outside 1..={max}")]
    InputCount {
        /// Supplied input count.
        actual: usize,
        /// Compiled maximum.
        max: usize,
    },
    /// The new-output count was outside the compiled first-release range.
    #[error("FCMP++ output count {actual} is outside 1..={max}")]
    OutputCount {
        /// Supplied output count.
        actual: usize,
        /// Compiled maximum.
        max: usize,
    },
    /// The commitment aggregates cancelled to the identity.
    #[error("FCMP++ commitment balance aggregate must be non-identity")]
    CommitmentBalanceIdentity,
    /// Pseudo-outs and new output amount commitments did not conserve value.
    #[error("FCMP++ pseudo-out and new-output commitment aggregates do not balance")]
    CommitmentBalanceEquation,
    /// The proof byte length did not equal the unique length implied by its
    /// input, layer, and output counts.
    #[error("FCMP++ proof wire length {actual} does not equal canonical length {expected}")]
    ProofLength {
        /// Supplied byte length.
        actual: usize,
        /// Required byte length.
        expected: usize,
    },
    /// Header input, layer, or output counts differed from the ledger statement.
    #[error("FCMP++ proof wire header differs from the authoritative public statement")]
    ProofHeaderMismatch,
    /// Wire O~/I~/R differed from the authoritative public relation.
    #[error("FCMP++ proof wire input {index} differs from the authoritative public relation")]
    ProofPublicInputMismatch {
        /// Zero-based mismatching input index.
        index: usize,
    },
    /// The generalized Bulletproof body was the all-zero sentinel.
    #[error("FCMP++ generalized Bulletproof body must be nonzero")]
    EmptyCircuitProof,
    /// A SAL witness did not open the authoritative public relation.
    #[error("FCMP++ spend-authorization witness does not open O~/R/L")]
    SalWitnessMismatch,
    /// A randomized SAL proof commitment was the identity.
    #[error("FCMP++ spend-authorization prover commitment was the identity")]
    SalProofPointIdentity,
    /// The SAL Fiat--Shamir challenge reduced to zero.
    #[error("FCMP++ spend-authorization challenge reduced to zero")]
    SalChallengeZero,
    /// Every bounded SAL proof attempt hit a retryable point or challenge.
    #[error("FCMP++ spend-authorization prover exhausted its fixed restart bound")]
    SalProverRestartExhausted,
    /// A SAL proof failed one or more of its four verification equations.
    #[error("FCMP++ spend-authorization and linkability proof is invalid")]
    SalEquation,
    /// The root vector commitment did not differ from the authoritative root
    /// by the proved Pedersen blind.
    #[error("FCMP++ root-blind proof of knowledge is invalid")]
    RootBlindEquation,
    /// One of the two generalized Bulletproof arithmetic-circuit equations failed.
    #[error("FCMP++ generalized Bulletproof arithmetic circuit is invalid")]
    CircuitEquation,
    /// A proof transcript did not consume exactly the canonical proof body.
    #[error("FCMP++ proof transcript contains trailing or missing elements")]
    TranscriptConsumption,
    /// An FCMP++ wallet ciphertext did not have the exact fixed width.
    #[error("FCMP++ encrypted output length {actual} does not equal canonical length {expected}")]
    EncryptedOutputLength {
        /// Observed ciphertext field width.
        actual: usize,
        /// Sole accepted ciphertext field width.
        expected: usize,
    },
    /// An FCMP++ wallet ciphertext did not use the sole first-release codec.
    #[error("FCMP++ encrypted output magic/version is not IFCE")]
    EncryptedOutputMagic,
    /// An FCMP++ X25519 recipient or ephemeral key is non-canonical or low order.
    #[error("FCMP++ encrypted output contains an invalid X25519 public key")]
    EncryptedOutputKey,
    /// The ciphertext nonce or ephemeral secret was the zero sentinel.
    #[error("FCMP++ encrypted output randomness must be non-zero")]
    EncryptedOutputRandomness,
    /// Public recipient, ephemeral-key, output-id, pool, or tuple bindings differ.
    #[error("FCMP++ encrypted output public binding is invalid")]
    EncryptedOutputBinding,
    /// XChaCha20-Poly1305 authentication failed.
    #[error("FCMP++ encrypted output authentication failed")]
    EncryptedOutputAuthentication,
    /// The fixed wallet note plaintext was malformed or did not open its output.
    #[error("FCMP++ wallet note plaintext is invalid")]
    WalletNoteEncoding,
    /// The amount-proof output count was outside the fixed first-release cap.
    #[error("FCMP++ range-proof output count {actual} is outside 1..={max}")]
    RangeOutputCount {
        /// Supplied output count.
        actual: usize,
        /// Compiled output cap.
        max: usize,
    },
    /// A new output did not encode a strictly positive `u64` amount.
    #[error("FCMP++ amount witness must be in 1..=u64::MAX")]
    RangeWitnessOutOfRange,
    /// A supplied amount and mask did not open the public commitment.
    #[error("FCMP++ amount witness does not open the public output commitment")]
    RangeCommitmentOpeningMismatch,
    /// The strict-positive adjusted commitment `C-H` was identity.
    #[error("FCMP++ adjusted range commitment C-H must be non-identity")]
    RangeAdjustedCommitment,
    /// The exact Monero Bulletproofs+ generator basis could not be derived.
    #[error("FCMP++ Bulletproofs+ generator derivation failed")]
    RangeGeneratorDerivation,
    /// A Fiat--Shamir challenge reduced to the prohibited zero scalar.
    #[error("FCMP++ Bulletproofs+ transcript challenge reduced to zero")]
    RangeChallengeZero,
    /// A range-proof point was identity, non-canonical, or outside the prime subgroup.
    #[error("FCMP++ Bulletproofs+ proof point is not canonical")]
    RangeProofPoint,
    /// The range-proof byte width differed from the sole output-count-dependent shape.
    #[error("FCMP++ range-proof length {actual} does not equal canonical length {expected}")]
    RangeProofLength {
        /// Supplied proof width.
        actual: usize,
        /// Required proof width.
        expected: usize,
    },
    /// The range proof used an impossible vector dimension.
    #[error("FCMP++ Bulletproofs+ proof shape is invalid")]
    RangeProofShape,
    /// The Bulletproofs+ verification equation failed.
    #[error("FCMP++ Bulletproofs+ range equation is invalid")]
    RangeProofEquation,
    /// A fixed internal range-proof arithmetic invariant failed.
    #[error("FCMP++ Bulletproofs+ internal arithmetic invariant failed")]
    RangeArithmeticInvariant,
    /// Prohibited zero/identity prover intermediates exhausted the restart cap.
    #[error("FCMP++ Bulletproofs+ prover exhausted its fixed restart bound")]
    RangeProverRestartExhausted,
}
pub(super) const fn curve_for_layers(layers: u8) -> FcmpTreeCurveV1 {
    if layers % 2 == 1 {
        FcmpTreeCurveV1::Selene
    } else {
        FcmpTreeCurveV1::Helios
    }
}
pub(super) fn validate_layer_count(layers: u8) -> Result<(), FcmpNativeErrorV1> {
    if layers == 0 || layers > FCMP_MAX_TREE_LAYERS_V1 {
        return Err(FcmpNativeErrorV1::LayerCount);
    }
    Ok(())
}
#[cfg(test)]
pub(super) fn output_from_multiples(
    output_key: u64,
    linking_tag_generator: u64,
    amount_commitment: u64,
) -> FcmpOutputTupleV1 {
    use curve25519_dalek::{constants::ED25519_BASEPOINT_POINT, scalar::Scalar};
    FcmpOutputTupleV1::new(
        (ED25519_BASEPOINT_POINT * Scalar::from(output_key))
            .compress()
            .to_bytes(),
        (ED25519_BASEPOINT_POINT * Scalar::from(linking_tag_generator))
            .compress()
            .to_bytes(),
        (ED25519_BASEPOINT_POINT * Scalar::from(amount_commitment))
            .compress()
            .to_bytes(),
    )
    .expect("nonzero test multiples are canonical")
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn compiled_profile_binds_every_fallible_retry_policy() {
        let descriptor =
            std::str::from_utf8(FCMP_COMPILED_PROFILE_DESCRIPTOR_V1).expect("ASCII profile");
        for required in [
            "rand-core06-try-fill-fail-closed",
            "shared-fixed64-reservoir-health-check-zeroize-poison-on-error-or-unwind",
            "nonzero-challenge-retry128",
            "bounded-canonical-rng128",
            "sal:nonzero-prover-scalars-retry128",
            "sal:nonzero-prover-scalars-retry128+full-proof-retry128-on-point-or-challenge",
            "point-lift-retry128",
            "exceptional-tuple-retry128",
            "full-proof-retry128-on-transcript-or-dlog-exhaustion+hidden-pole+generalized-bulletproof-commitment-identity+inner-product-identity",
            "outputs-max4+range-commitments-max8",
            "nonzero-prover-scalar-retry128+full-proof-retry128-on-point-or-challenge",
            "deterministic-preflight-before-entropy+full-transaction-self-verify",
            "full-input-output-path-scalar-vector-divisor-zeroize-on-drop",
            "redacted-debug",
            "secret-key-shared-secret-plaintext-zeroize-on-drop",
        ] {
            assert!(
                descriptor.contains(required),
                "profile is missing `{required}`"
            );
        }
        assert_ne!(fcmp_compiled_profile_digest_v1(), [0; 32]);
    }
    #[test]
    fn output_tuple_codec_is_exact_and_identifier_does_not_replace_tuple() {
        let output = output_from_multiples(1, 2, 3);
        assert_eq!(
            FcmpOutputTupleV1::decode(&output.encode()).expect("roundtrip"),
            output
        );
        assert_ne!(output.output_id(), [0; 32]);
        assert_eq!(
            FcmpOutputTupleV1::decode(&output.encode()[..95]),
            Err(FcmpNativeErrorV1::OutputTupleLength {
                actual: 95,
                expected: 96,
            })
        );
        for component_offset in [0, 32, 64] {
            let mut identity = output.encode();
            identity[component_offset..component_offset + 32].fill(0);
            identity[component_offset] = 1;
            assert_eq!(
                FcmpOutputTupleV1::decode(&identity),
                Err(FcmpNativeErrorV1::EdwardsPointIdentity)
            );
            let mut noncanonical = output.encode();
            noncanonical[component_offset..component_offset + 32].fill(u8::MAX);
            assert_eq!(
                FcmpOutputTupleV1::decode(&noncanonical),
                Err(FcmpNativeErrorV1::EdwardsPointEncoding)
            );
            let mut torsion = output.encode();
            torsion[component_offset..component_offset + 32].copy_from_slice(
                &curve25519_dalek::constants::EIGHT_TORSION[1]
                    .compress()
                    .to_bytes(),
            );
            assert_eq!(
                FcmpOutputTupleV1::decode(&torsion),
                Err(FcmpNativeErrorV1::EdwardsPointEncoding)
            );
        }
        let reordered = FcmpOutputTupleV1::new(
            output.components().1,
            output.components().0,
            output.components().2,
        )
        .expect("reordered points remain individually valid");
        assert_ne!(output.output_id(), reordered.output_id());
    }
    #[test]
    fn hidden_output_identifier_matches_public_bytes_and_drops_on_return_and_unwind() {
        let output = output_from_multiples(5, 7, 11);
        let expected = output.output_id();
        FCMP_SECRET_OUTPUT_ID_DROPS_V1.with(|drops| drops.set(0));
        let identifier = output.secret_output_id_v1();
        assert_eq!(identifier.as_ref(), &expected);
        assert_eq!(FCMP_SECRET_OUTPUT_ID_DROPS_V1.with(std::cell::Cell::get), 0);
        drop(identifier);
        assert_eq!(FCMP_SECRET_OUTPUT_ID_DROPS_V1.with(std::cell::Cell::get), 1);

        FCMP_SECRET_OUTPUT_ID_DROPS_V1.with(|drops| drops.set(0));
        let unwind = std::panic::catch_unwind(|| {
            let identifier = output.secret_output_id_v1();
            assert_eq!(identifier.as_ref(), &expected);
            let _ = core::hint::black_box(&identifier);
            panic!("exercise hidden output identifier unwind");
        });
        assert!(unwind.is_err());
        assert_eq!(FCMP_SECRET_OUTPUT_ID_DROPS_V1.with(std::cell::Cell::get), 1);
    }
    #[test]
    fn hidden_output_identifier_source_borrows_tuple_and_erases_hash_scratch() {
        let source = include_str!("mod.rs");
        let secret_identifier = source
            .split_once("pub(crate) fn secret_output_id_v1(&self)")
            .expect("borrowed hidden output identifier")
            .1
            .split_once("/// Encode the tuple without framing.")
            .expect("hidden output identifier boundary")
            .0;
        for required in [
            "Zeroizing::new([0_u8; FCMP_OUTPUT_TUPLE_BYTES_V1])",
            "self.component_refs_v1()",
            "wallet::secret_sha256_v1(&[",
            "OUTPUT_ID_DOMAIN_V1,",
            "encoded.as_ref(),",
        ] {
            assert!(secret_identifier.contains(required), "missing {required}");
        }
        for forbidden in [
            "self.encode()",
            "Sha256::new()",
            ".finalize()",
            "self.output_key",
            "self.linking_tag_generator",
            "self.amount_commitment",
        ] {
            assert!(
                !secret_identifier.contains(forbidden),
                "retained {forbidden}"
            );
        }
        let owner = source
            .split_once("pub(crate) struct FcmpSecretOutputIdV1")
            .expect("hidden output identifier owner")
            .1
            .split_once("impl FcmpOutputTupleV1")
            .expect("hidden output identifier owner boundary")
            .0;
        assert!(owner.contains("pub(crate) fn as_ref(&self) -> &[u8; 32]"));
        assert!(owner.contains("impl Drop for FcmpSecretOutputIdV1"));
        assert!(!owner.contains("#[derive(Clone"));
        assert!(!owner.contains("impl Clone for FcmpSecretOutputIdV1"));
        assert!(!owner.contains("impl Copy for FcmpSecretOutputIdV1"));

        let wallet_source = include_str!("wallet.rs");
        let secret_sha = wallet_source
            .split_once("struct WalletSecretSha256V1 {")
            .expect("shared secret SHA-256 owner")
            .1
            .split_once("/// Decrypted fixed-width FCMP++ wallet note.")
            .expect("shared secret SHA-256 boundary")
            .0;
        for required in [
            "state: [u32; 8]",
            "block: [u8; 64]",
            "compress256(&mut self.state",
            "self.block.zeroize()",
            "impl Drop for WalletSecretSha256V1",
            "self.state.zeroize()",
            "compiler_fence",
            "black_box",
        ] {
            assert!(secret_sha.contains(required), "missing {required}");
        }
        let borrowed_hash = wallet_source
            .split_once("pub(super) fn secret_sha256_v1(inputs: &[&[u8]])")
            .expect("borrowed secret SHA-256 helper")
            .1
            .split_once("/// Decrypted fixed-width FCMP++ wallet note.")
            .expect("borrowed secret SHA-256 helper boundary")
            .0;
        assert!(borrowed_hash.contains("WalletSecretSha256V1::new()"));
        assert!(borrowed_hash.contains("for input in inputs"));
        assert!(borrowed_hash.contains("hash.update_v1(input)"));
        assert!(borrowed_hash.contains("hash.finalize_v1()"));
    }
    #[test]
    fn root_codec_binds_layer_range_and_curve_parity() {
        let selene = field::selene_hash_initializer();
        let helios = field::helios_hash_initializer();
        assert_eq!(
            FcmpTreeRootV1::new(0, selene.encode()),
            Err(FcmpNativeErrorV1::LayerCount)
        );
        assert_eq!(
            FcmpTreeRootV1::new(FCMP_MAX_TREE_LAYERS_V1 + 1, selene.encode()),
            Err(FcmpNativeErrorV1::LayerCount)
        );
        assert_eq!(
            FcmpTreeRootV1::new(1, [0; 32]),
            Err(FcmpNativeErrorV1::CyclePointIdentity)
        );
        assert!(FcmpTreeRootV1::new(1, helios.encode()).is_err());
        assert!(FcmpTreeRootV1::new(2, selene.encode()).is_err());
        assert_eq!(
            FcmpTreeRootV1::new(1, selene.encode()).expect("odd root"),
            FcmpTreeRootV1::from_selene(1, selene).expect("odd root")
        );
        assert_eq!(
            FcmpTreeRootV1::new(2, helios.encode()).expect("even root"),
            FcmpTreeRootV1::from_helios(2, helios).expect("even root")
        );
    }
}
