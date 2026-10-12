//! Native STARK/FRI (binary folding) verifier used by the `stark/fri/*` backends.
//!
//! This module provides the deterministic first-release verifier over the Goldilocks prime field.
//! Every native-STARK commitment and transcript challenge uses the canonical six-independent-lane
//! Poseidon-x7 digest. There is no hash selector or alternate commitment decoder.
//!
//! The verifier implements a multi-round binary FRI consistency check.
//!
//! The wire format is defined with Norito. The proof envelope carries params, Merkle
//! roots, and query decommitments. Verification replays the transcript and checks:
//! - Merkle openings for each queried value
//! - The domain-aware fold relation for adjacent `(x, -x)` openings in bit-reversed layer order
//! - Distinct transcript-derived query positions
//! - Optional composition leaf constraints when `comp_root` is present
//! - Exact reconstruction of the deterministic generic Binding AIR trace commitment
//!
//! Size and structural limits are enforced to reject oversized or malformed payloads
//! deterministically (see [`StarkVerifierLimits`]).
#![allow(clippy::needless_pass_by_value)]
use fastpq_isi::{GoldilocksDigestDomainV1, hash_bytes_384_v1};
use iroha_data_model::privacy::{
    GoldilocksDigest384V1, PRIVACY_EXACT12_CATALOG_COMMITMENT_WORDS_V1,
};
use norito::derive::{JsonDeserialize, JsonSerialize};
use std::collections::{BTreeMap, BTreeSet};
/// Goldilocks prime modulus p = 2^64 - 2^32 + 1
const MOD_P: u128 = (1u128 << 64) - (1u128 << 32) + 1;
const MOD_P_U64: u64 = MOD_P as u64;
const GOLDILOCKS_GENERATOR: u64 = 7;
/// Sole first-release native STARK/FRI profile identifier.
pub const STARK_FRI_PROFILE_ID_V1: &str = "stark/fri/poseidon-x7-goldilocks-6x64-v1";
/// Minimum evaluation-domain exponent accepted by generic STARK admission.
pub const STARK_FRI_CONSENSUS_MIN_N_LOG2: u8 = 10;
/// Minimum FRI blowup exponent accepted by generic STARK admission.
pub const STARK_FRI_CONSENSUS_MIN_BLOWUP_LOG2: u8 = 3;
/// Minimum verifier query count accepted by generic STARK admission.
///
/// The first-release query schedule is a multiple of eight and never contains fewer than 64
/// distinct transcript-derived positions.
pub const STARK_FRI_CONSENSUS_MIN_QUERIES: u16 = 64;
/// Trace width of the generic OpenVerify binding AIR used by STARK/FRI v1 proofs.
pub const STARK_BINDING_AIR_TRACE_WIDTH_V1: u16 = 8;
/// Largest generic Binding AIR domain whose canonical trace root V1 reconstructs during
/// verification.
///
/// The exact root check closes unsampled-row substitutions without allowing an attacker to make
/// verification hash an otherwise valid domain of up to 2^24 rows. Explicit and dedicated typed
/// AIR contexts retain their circuit-specific domain limits.
pub const MAX_BINDING_AIR_DOMAIN_LOG2: u8 = 12;
const MAX_DOMAIN_LOG2: u8 = 24;
const MAX_FRI_LAYERS: usize = 32;
const MAX_FRI_QUERIES: usize = 64;
const MAX_MERKLE_DEPTH: usize = 32;
const MAX_AUX_TERMS: usize = 64;
const MAX_AIR_WIDTH: usize = 64;
// Statement-bound domain tags retain every byte of the six-lane digest as hex.
const MAX_DOMAIN_TAG_LEN: usize = GoldilocksDigest384V1::BYTES * 2;
const MAX_TRANSCRIPT_LABEL_LEN: usize = 128;
const MAX_ENVELOPE_BYTES: usize = 1 << 20; // 1 MiB guard for decoded envelopes
pub(crate) const STARK_FRI_QUERY_INDEX_REPEATED_ERROR: &str = "FRI query index repeated";
const STARK_FRI_BOUNDED_QUERY_REJECTION_ATTEMPTS: usize = 8;
#[cfg(test)]
const BFV_FULL_BOOTSTRAP_STARK_AIR_TRANSCRIPT_LABEL_ATTEMPTS: u32 = 1024;
const GENERIC_STARK_AIR_BFV_FULL_BOOTSTRAP_RESERVED_ERROR: &str = "generic STARK AIR prover cannot target the BFV full-bootstrap circuit; use the BFV full-bootstrap STARK prover";
const GENERIC_STARK_AIR_ZK_ACE_RESERVED_ERROR: &str =
    "generic STARK AIR prover cannot target the typed ZK-ACE relation; use SubmitPrivacyProofV1";
const GENERIC_STARK_AIR_IVM_EXECUTION_RESERVED_ERROR: &str = "generic STARK AIR prover cannot target an IVM execution relation; the complete native relation is not yet admitted";
const GENERIC_STARK_AIR_SORACLOUD_RESERVED_ERROR: &str = "generic STARK AIR prover cannot target a Soracloud FHE relation; a dedicated typed Soracloud verifier is required";
const GENERIC_STARK_AIR_GOVERNANCE_RESERVED_ERROR: &str = "generic STARK AIR prover cannot target a governance vote role; a dedicated semantic governance circuit is required";
fn validate_stark_transcript_label(label: &str, max_len: usize) -> Result<(), &'static str> {
    if label.is_empty() {
        return Err("transcript label must not be empty");
    }
    if label.len() > max_len {
        return Err("transcript label exceeds maximum length");
    }
    if !label.bytes().all(|byte| byte.is_ascii_graphic()) {
        return Err("transcript label must contain only printable ASCII bytes without whitespace");
    }
    Ok(())
}
fn validate_stark_circuit_id(circuit_id: &str) -> Result<(), &'static str> {
    if circuit_id.is_empty() {
        return Err("circuit id must not be empty");
    }
    if circuit_id.len() > MAX_TRANSCRIPT_LABEL_LEN {
        return Err("circuit id exceeds maximum length");
    }
    if !circuit_id.bytes().all(|byte| byte.is_ascii_graphic()) {
        return Err("circuit id must contain only printable ASCII bytes without whitespace");
    }
    Ok(())
}
fn stark_air_circuit_id_targets_reserved_circuit(circuit_id: &str, canonical: &str) -> bool {
    let trimmed = circuit_id.trim();
    trimmed == canonical
        || trimmed
            .strip_suffix(canonical)
            .is_some_and(|prefix| prefix.ends_with(':') || prefix.ends_with('/'))
}
fn stark_air_circuit_id_targets_bfv_full_bootstrap(circuit_id: &str) -> bool {
    stark_air_circuit_id_targets_reserved_circuit(
        circuit_id,
        iroha_crypto::BFV_FULL_BOOTSTRAP_CIRCUIT_ID_V1,
    )
}
fn stark_air_circuit_id_targets_zk_ace(circuit_id: &str) -> bool {
    stark_air_circuit_id_targets_reserved_circuit(
        circuit_id,
        iroha_data_model::zk::ZK_ACE_PQ_AUTHORIZATION_V1_CIRCUIT_ID,
    )
}
fn stark_air_circuit_id_targets_ivm_execution(circuit_id: &str) -> bool {
    crate::ivm_proof_identity::circuit_id_uses_reserved_ivm_namespace(circuit_id)
}
fn stark_air_circuit_id_targets_governance_vote_relation(circuit_id: &str) -> bool {
    [
        crate::GOVERNANCE_BALLOT_CIRCUIT_ID_V1,
        crate::GOVERNANCE_TALLY_CIRCUIT_ID_V1,
    ]
    .into_iter()
    .any(|canonical| stark_air_circuit_id_targets_reserved_circuit(circuit_id, canonical))
}
fn stark_air_circuit_id_targets_soracloud_fhe_relation(circuit_id: &str) -> bool {
    [
        iroha_data_model::soracloud::SORACLOUD_FHE_INPUT_ADMISSION_CIRCUIT_ID_V1,
        iroha_data_model::soracloud::SORACLOUD_FHE_PUBLIC_KEY_PROOF_CIRCUIT_ID_V1,
        iroha_data_model::soracloud::SORACLOUD_FHE_BOOTSTRAP_KEY_PROOF_CIRCUIT_ID_V1,
        iroha_data_model::soracloud::SORACLOUD_FHE_FULL_BOOTSTRAP_EXECUTION_PROOF_CIRCUIT_ID_V1,
    ]
    .into_iter()
    .any(|canonical| stark_air_circuit_id_targets_reserved_circuit(circuit_id, canonical))
}
fn stark_air_circuit_id_uses_generic_binding(circuit_id: &str) -> bool {
    !stark_air_circuit_id_targets_bfv_full_bootstrap(circuit_id)
        && !stark_air_circuit_id_targets_zk_ace(circuit_id)
        && !stark_air_circuit_id_targets_ivm_execution(circuit_id)
        && !stark_air_circuit_id_targets_governance_vote_relation(circuit_id)
        && !stark_air_circuit_id_targets_soracloud_fhe_relation(circuit_id)
}
fn validate_generic_stark_air_circuit_id(circuit_id: &str) -> Result<(), String> {
    validate_stark_circuit_id(circuit_id)
        .map_err(|err| format!("invalid STARK AIR circuit_id: {err}"))?;
    if stark_air_circuit_id_targets_bfv_full_bootstrap(circuit_id) {
        return Err(GENERIC_STARK_AIR_BFV_FULL_BOOTSTRAP_RESERVED_ERROR.to_owned());
    }
    if stark_air_circuit_id_targets_zk_ace(circuit_id) {
        return Err(GENERIC_STARK_AIR_ZK_ACE_RESERVED_ERROR.to_owned());
    }
    if stark_air_circuit_id_targets_ivm_execution(circuit_id) {
        return Err(GENERIC_STARK_AIR_IVM_EXECUTION_RESERVED_ERROR.to_owned());
    }
    if stark_air_circuit_id_targets_governance_vote_relation(circuit_id) {
        return Err(GENERIC_STARK_AIR_GOVERNANCE_RESERVED_ERROR.to_owned());
    }
    if stark_air_circuit_id_targets_soracloud_fhe_relation(circuit_id) {
        return Err(GENERIC_STARK_AIR_SORACLOUD_RESERVED_ERROR.to_owned());
    }
    Ok(())
}
fn validate_stark_domain_tag(domain_tag: &str, max_len: usize) -> Result<(), &'static str> {
    if domain_tag.is_empty() {
        return Err("domain tag must not be empty");
    }
    if domain_tag.len() > max_len {
        return Err("domain tag exceeds maximum length");
    }
    if !domain_tag.bytes().all(|byte| byte.is_ascii_graphic()) {
        return Err("domain tag must contain only printable ASCII bytes without whitespace");
    }
    Ok(())
}
/// Tunable limits applied during STARK envelope verification to prevent denial-of-service inputs.
///
/// These values can tighten the built-in protocol caps for a caller, but they cannot relax
/// canonical verifier structure limits. Values above the native caps are clamped internally.
#[derive(Clone, Copy, Debug)]
pub struct StarkVerifierLimits {
    /// Caller cap for domain log2, clamped to the native protocol maximum.
    pub max_domain_log2: u8,
    /// Caller cap for blowup log2, clamped to the native protocol maximum.
    pub max_blowup_log2: u8,
    /// Caller cap for fold arity, clamped to the native verifier maximum.
    pub max_fold_arity: u8,
    /// Caller cap for query count, clamped to the native protocol maximum.
    pub max_queries: usize,
    /// Caller cap for Merkle depth, clamped to the native verifier maximum.
    pub max_merkle_depth: usize,
    /// Caller cap for auxiliary terms in a composition leaf, clamped natively.
    pub max_aux_terms: usize,
    /// Caller cap for values in a sampled AIR trace row, clamped natively.
    pub max_air_width: usize,
    /// Caller cap for domain tag length, clamped to the canonical maximum.
    pub max_domain_tag_len: usize,
    /// Caller cap for transcript label length, clamped to the canonical maximum.
    pub max_transcript_label_len: usize,
    /// Caller cap for encoded envelope size, clamped to the native byte budget.
    pub max_envelope_bytes: usize,
}
impl Default for StarkVerifierLimits {
    fn default() -> Self {
        Self {
            max_domain_log2: MAX_DOMAIN_LOG2,
            max_blowup_log2: MAX_DOMAIN_LOG2,
            max_fold_arity: 1 << 5,
            max_queries: MAX_FRI_QUERIES,
            max_merkle_depth: MAX_MERKLE_DEPTH,
            max_aux_terms: MAX_AUX_TERMS,
            max_air_width: MAX_AIR_WIDTH,
            max_domain_tag_len: MAX_DOMAIN_TAG_LEN,
            max_transcript_label_len: MAX_TRANSCRIPT_LABEL_LEN,
            max_envelope_bytes: MAX_ENVELOPE_BYTES,
        }
    }
}
fn effective_max_domain_log2(limits: &StarkVerifierLimits) -> u8 {
    limits.max_domain_log2.min(MAX_DOMAIN_LOG2)
}
fn effective_max_blowup_log2(limits: &StarkVerifierLimits) -> u8 {
    limits.max_blowup_log2.min(MAX_DOMAIN_LOG2)
}
fn effective_max_fold_arity(limits: &StarkVerifierLimits) -> u8 {
    limits.max_fold_arity.min(1 << 5)
}
fn effective_max_queries(limits: &StarkVerifierLimits) -> usize {
    limits.max_queries.min(MAX_FRI_QUERIES)
}
fn effective_max_merkle_depth(limits: &StarkVerifierLimits) -> usize {
    limits.max_merkle_depth.min(MAX_MERKLE_DEPTH)
}
fn effective_max_aux_terms(limits: &StarkVerifierLimits) -> usize {
    limits.max_aux_terms.min(MAX_AUX_TERMS)
}
fn effective_max_air_width(limits: &StarkVerifierLimits) -> usize {
    limits.max_air_width.min(MAX_AIR_WIDTH)
}
fn effective_max_domain_tag_len(limits: &StarkVerifierLimits) -> usize {
    limits.max_domain_tag_len.min(MAX_DOMAIN_TAG_LEN)
}
fn effective_max_transcript_label_len(limits: &StarkVerifierLimits) -> usize {
    limits
        .max_transcript_label_len
        .min(MAX_TRANSCRIPT_LABEL_LEN)
}
fn effective_max_envelope_bytes(limits: &StarkVerifierLimits) -> usize {
    limits.max_envelope_bytes.min(MAX_ENVELOPE_BYTES)
}
/// Whether an encoded envelope of `len` bytes is above the effective envelope bound. The
/// bound is inclusive: an envelope of exactly the bound is decoded.
fn envelope_exceeds_limit(len: usize, limits: &StarkVerifierLimits) -> bool {
    len > effective_max_envelope_bytes(limits)
}
/// Goldilocks field element with canonical modular reduction.
///
/// This backend keeps values in the range `[0, MOD_P)` and implements the minimal arithmetic
/// required by the native STARK verifier. Although kept intentionally small, it now performs full
/// modular reduction so that callers do not need to pre-normalise inputs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Fq(u64);
impl Fq {
    /// Construct an element from an arbitrary 64-bit integer by reducing it modulo `MOD_P`.
    fn new(v: u64) -> Self {
        Self::reduce(v as u128)
    }
    /// Construct from canonical representative. Returns `None` if the input is
    /// outside `[0, MOD_P)`.
    fn from_canonical_u64(v: u64) -> Option<Self> {
        if v >= MOD_P_U64 { None } else { Some(Self(v)) }
    }
    fn zero() -> Self {
        Self(0)
    }
    fn one() -> Self {
        Self(1)
    }
    fn add(self, rhs: Self) -> Self {
        let mut x = (self.0 as u128) + (rhs.0 as u128);
        if x >= MOD_P {
            x -= MOD_P;
        }
        Self(x as u64)
    }
    fn sub(self, rhs: Self) -> Self {
        let a = self.0 as u128;
        let b = rhs.0 as u128;
        let x = if a >= b { a - b } else { (a + MOD_P) - b };
        Self(x as u64)
    }
    fn mul(self, rhs: Self) -> Self {
        let x = (self.0 as u128) * (rhs.0 as u128);
        Self::reduce(x)
    }
    fn pow(self, mut e: u128) -> Self {
        let mut base = self;
        let mut acc = Self::one();
        while e > 0 {
            if e & 1 == 1 {
                acc = acc.mul(base);
            }
            base = base.mul(base);
            e >>= 1;
        }
        acc
    }
    fn inv(self) -> Option<Self> {
        if self.0 == 0 {
            return None;
        }
        // Fermat's little theorem: a^(p-2) mod p
        Some(self.pow((MOD_P - 2) as u128))
    }
    fn to_le_bytes(self) -> [u8; 8] {
        self.0.to_le_bytes()
    }
    fn reduce(v: u128) -> Self {
        Self((v % MOD_P) as u64)
    }
}
fn two_inv() -> Fq {
    // (p + 1) / 2 for the odd Goldilocks prime.
    Fq(((MOD_P + 1) / 2) as u64)
}
/// Canonical coefficient representation of one Goldilocks quartic-extension element.
///
/// Coefficients are ordered from constant through cubic degree under the irreducible polynomial
/// `U^4 - 7`. Seven generates the multiplicative group of the Goldilocks field; because the field
/// order is one modulo four, the finite-field binomial irreducibility criterion makes `U^4 - 7`
/// irreducible. Every verifier entry point rejects coefficients outside the canonical base-field
/// range. The Norito payload is exactly four little-endian coefficients (32 bytes), using the
/// same canonical field codec as FASTPQ without a struct frame.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, JsonSerialize, JsonDeserialize, norito::NoritoSchema,
)]
#[norito_schema(name = "iroha_core::zk_stark::GoldilocksFp4V1")]
pub struct GoldilocksFp4V1 {
    c0: u64,
    c1: u64,
    c2: u64,
    c3: u64,
}
impl GoldilocksFp4V1 {
    /// Exact byte length of the canonical polynomial-basis encoding.
    pub const BYTES: usize = fastpq_prover::GoldilocksFp4V1::BYTES;
    /// Construct an extension element from four canonical Goldilocks coefficients.
    #[must_use]
    pub fn new(coefficients: [u64; 4]) -> Option<Self> {
        coefficients
            .iter()
            .all(|coefficient| *coefficient < MOD_P_U64)
            .then_some(Self {
                c0: coefficients[0],
                c1: coefficients[1],
                c2: coefficients[2],
                c3: coefficients[3],
            })
    }
    /// Embed one canonical Goldilocks base-field value into the quartic extension.
    #[must_use]
    pub fn from_base(value: u64) -> Option<Self> {
        Self::new([value, 0, 0, 0])
    }
    /// Return the four canonical coefficients in wire order.
    #[must_use]
    pub const fn coefficients(self) -> [u64; 4] {
        [self.c0, self.c1, self.c2, self.c3]
    }
}
impl norito::SerializePayload for GoldilocksFp4V1 {
    fn serialize(&self, writer: &mut norito::core::Encoder<'_>) -> Result<(), norito::Error> {
        let value = fastpq_prover::GoldilocksFp4V1::new(self.coefficients()).ok_or_else(|| {
            norito::Error::Message("non-canonical GoldilocksFp4V1 coefficient".into())
        })?;
        norito::SerializePayload::serialize(&value, writer)
    }

    fn encoded_len_hint(&self) -> Option<usize> {
        Some(Self::BYTES)
    }

    fn encoded_len_exact(&self) -> Option<usize> {
        Some(Self::BYTES)
    }
}
impl<'de> norito::DeserializePayload<'de> for GoldilocksFp4V1 {
    fn deserialize(archived: &'de norito::core::Archived<Self>) -> Self {
        Self::try_deserialize(archived).expect("canonical GoldilocksFp4V1 decode")
    }

    fn try_deserialize(archived: &'de norito::core::Archived<Self>) -> Result<Self, norito::Error> {
        let value =
            <fastpq_prover::GoldilocksFp4V1 as norito::DeserializePayload>::try_deserialize(
                archived.cast(),
            )?;
        let [c0, c1, c2, c3] = value.coefficients();
        Ok(Self { c0, c1, c2, c3 })
    }
}
impl<'de> norito::core::DecodeFromSlice<'de> for GoldilocksFp4V1 {
    fn decode_from_slice(bytes: &'de [u8]) -> Result<(Self, usize), norito::Error> {
        let (value, consumed) =
            <fastpq_prover::GoldilocksFp4V1 as norito::core::DecodeFromSlice>::decode_from_slice(
                bytes,
            )?;
        let [c0, c1, c2, c3] = value.coefficients();
        Ok((Self { c0, c1, c2, c3 }, consumed))
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Fp4([Fq; 4]);
impl Fp4 {
    fn from_wire(value: GoldilocksFp4V1) -> Option<Self> {
        let coefficients = value.coefficients();
        Some(Self([
            Fq::from_canonical_u64(coefficients[0])?,
            Fq::from_canonical_u64(coefficients[1])?,
            Fq::from_canonical_u64(coefficients[2])?,
            Fq::from_canonical_u64(coefficients[3])?,
        ]))
    }
    fn from_base(value: Fq) -> Self {
        Self([value, Fq::zero(), Fq::zero(), Fq::zero()])
    }
    fn zero() -> Self {
        Self::from_base(Fq::zero())
    }
    fn add(self, rhs: Self) -> Self {
        Self([
            self.0[0].add(rhs.0[0]),
            self.0[1].add(rhs.0[1]),
            self.0[2].add(rhs.0[2]),
            self.0[3].add(rhs.0[3]),
        ])
    }
    fn sub(self, rhs: Self) -> Self {
        Self([
            self.0[0].sub(rhs.0[0]),
            self.0[1].sub(rhs.0[1]),
            self.0[2].sub(rhs.0[2]),
            self.0[3].sub(rhs.0[3]),
        ])
    }
    fn mul_base(self, rhs: Fq) -> Self {
        Self([
            self.0[0].mul(rhs),
            self.0[1].mul(rhs),
            self.0[2].mul(rhs),
            self.0[3].mul(rhs),
        ])
    }
    fn mul(self, rhs: Self) -> Self {
        let mut product = [Fq::zero(); 7];
        for left in 0..4 {
            for right in 0..4 {
                product[left + right] = product[left + right].add(self.0[left].mul(rhs.0[right]));
            }
        }
        let non_residue = Fq::new(GOLDILOCKS_GENERATOR);
        for degree in (4..=6).rev() {
            product[degree - 4] = product[degree - 4].add(product[degree].mul(non_residue));
        }
        Self([product[0], product[1], product[2], product[3]])
    }
    fn to_wire(self) -> GoldilocksFp4V1 {
        GoldilocksFp4V1 {
            c0: self.0[0].0,
            c1: self.0[1].0,
            c2: self.0[2].0,
            c3: self.0[3].0,
        }
    }
    fn to_le_bytes(self) -> [u8; 32] {
        let mut bytes = [0_u8; 32];
        for (index, coefficient) in self.0.iter().enumerate() {
            let offset = index * 8;
            bytes[offset..offset + 8].copy_from_slice(&coefficient.to_le_bytes());
        }
        bytes
    }
}
fn domain_x_for_pair(layer_domain: usize, pair_index: usize) -> Option<Fq> {
    if layer_domain < 2 || !layer_domain.is_power_of_two() || pair_index >= layer_domain / 2 {
        return None;
    }
    let field_domain = u128::try_from(layer_domain).ok()?;
    // An exact-order subgroup must exist before deriving its generator. Integer division alone
    // would silently accept domains beyond the Goldilocks field's 32-bit two-adicity.
    if !(MOD_P - 1).is_multiple_of(field_domain) {
        return None;
    }
    // Every FRI layer is stored in bit-reversed evaluation order. Adjacent positions `2j` and
    // `2j + 1` therefore hold `(f(x), f(-x))`, where the subgroup exponent of `x` is `j` with the
    // pair-index bits reversed. Folding preserves the same ordering in the next layer.
    let pair_index_bits = layer_domain.trailing_zeros().checked_sub(1)?;
    let pair_exponent = if pair_index_bits == 0 {
        0
    } else {
        pair_index.reverse_bits() >> (usize::BITS - pair_index_bits)
    };
    let exponent = (MOD_P - 1) / field_domain;
    let root = Fq::new(GOLDILOCKS_GENERATOR).pow(exponent);
    Some(root.pow(pair_exponent as u128))
}
fn fri_fold_pair(y0: Fp4, y1: Fp4, beta: Fp4, x: Fq) -> Option<Fp4> {
    let inv_2x = x.mul(Fq::from_canonical_u64(2)?).inv()?;
    let even = y0.add(y1).mul_base(two_inv());
    let odd = y0.sub(y1).mul_base(inv_2x);
    Some(even.add(beta.mul(odd)))
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum StarkMerkleTreeRoleV1 {
    FriLayer,
    AirTrace,
    AirComposition,
    AuxiliaryComposition,
}
impl StarkMerkleTreeRoleV1 {
    const fn domain_tag(self) -> &'static [u8] {
        match self {
            Self::FriLayer => b"fri-layer",
            Self::AirTrace => b"air-trace",
            Self::AirComposition => b"air-composition",
            Self::AuxiliaryComposition => b"auxiliary-composition",
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct StarkMerkleDomainV1 {
    role: StarkMerkleTreeRoleV1,
    oracle_level: u64,
}
impl StarkMerkleDomainV1 {
    fn fri_layer(round: usize) -> Option<Self> {
        let Ok(oracle_level) = u64::try_from(round) else {
            return None;
        };
        Some(Self {
            role: StarkMerkleTreeRoleV1::FriLayer,
            oracle_level,
        })
    }
    const fn air_trace() -> Self {
        Self {
            role: StarkMerkleTreeRoleV1::AirTrace,
            oracle_level: 0,
        }
    }
    const fn air_composition() -> Self {
        Self {
            role: StarkMerkleTreeRoleV1::AirComposition,
            oracle_level: 0,
        }
    }
    const fn auxiliary_composition() -> Self {
        Self {
            role: StarkMerkleTreeRoleV1::AuxiliaryComposition,
            oracle_level: 0,
        }
    }
}
fn stark_catalog_commitment_bytes_v1() -> [u8; GoldilocksDigest384V1::BYTES] {
    GoldilocksDigest384V1::new(PRIVACY_EXACT12_CATALOG_COMMITMENT_WORDS_V1)
        .expect("the pinned Exact12 catalog commitment is canonical")
        .to_le_bytes()
}
fn stark_digest_v1(
    params: &StarkFriParamsV1,
    role: &[u8],
    phase: &[u8],
    level: u64,
    index: u64,
    counter: u64,
    fields: &[&[u8]],
) -> Option<GoldilocksDigest384V1> {
    let catalog = stark_catalog_commitment_bytes_v1();
    hash_bytes_384_v1(
        GoldilocksDigestDomainV1 {
            catalog: &catalog,
            protocol: params.domain_tag.as_bytes(),
            profile: STARK_FRI_PROFILE_ID_V1.as_bytes(),
            role,
            phase,
            level,
            index,
            counter,
        },
        fields,
    )
    .map(Into::into)
}
#[doc(hidden)]
pub fn stark_public_digest_v1(
    params: &StarkFriParamsV1,
    circuit_id: &str,
    statement_bytes: &[u8],
) -> Option<GoldilocksDigest384V1> {
    stark_digest_v1(
        params,
        b"public-statement",
        b"digest",
        0,
        0,
        0,
        &[circuit_id.as_bytes(), statement_bytes],
    )
}
/// Derive the six-lane digest used as the canonical generic OpenVerify STARK domain tag.
#[must_use]
pub fn stark_open_verify_domain_digest_v1(
    binding_preimage: &[u8],
) -> Option<GoldilocksDigest384V1> {
    let catalog = stark_catalog_commitment_bytes_v1();
    hash_bytes_384_v1(
        GoldilocksDigestDomainV1 {
            catalog: &catalog,
            protocol: b"iroha-native-stark-open-verify-v1",
            profile: STARK_FRI_PROFILE_ID_V1.as_bytes(),
            role: b"outer-binding",
            phase: b"domain-tag",
            level: 0,
            index: 0,
            counter: 0,
        },
        &[binding_preimage],
    )
    .map(Into::into)
}
/// Derive the independent six-lane digest expanded into generic Binding AIR terms.
pub(crate) fn stark_open_verify_air_terms_digest_v1(
    binding_preimage: &[u8],
) -> Option<GoldilocksDigest384V1> {
    let catalog = stark_catalog_commitment_bytes_v1();
    hash_bytes_384_v1(
        GoldilocksDigestDomainV1 {
            catalog: &catalog,
            protocol: b"iroha-native-stark-open-verify-v1",
            profile: STARK_FRI_PROFILE_ID_V1.as_bytes(),
            role: b"public-statement",
            phase: b"air-terms",
            level: 0,
            index: 0,
            counter: 0,
        },
        &[binding_preimage],
    )
    .map(Into::into)
}
fn merkle_leaf_hash(
    params: &StarkFriParamsV1,
    domain: StarkMerkleDomainV1,
    val: Fq,
    index: usize,
) -> Option<GoldilocksDigest384V1> {
    let index = u64::try_from(index).ok()?;
    let value = val.to_le_bytes();
    stark_digest_v1(
        params,
        domain.role.domain_tag(),
        b"field-leaf",
        domain.oracle_level,
        index,
        0,
        &[&value],
    )
}
fn fri_merkle_leaf_hash(
    params: &StarkFriParamsV1,
    domain: StarkMerkleDomainV1,
    value: Fp4,
    index: usize,
) -> Option<GoldilocksDigest384V1> {
    let index = u64::try_from(index).ok()?;
    let value = value.to_le_bytes();
    stark_digest_v1(
        params,
        domain.role.domain_tag(),
        b"fp4-leaf",
        domain.oracle_level,
        index,
        0,
        &[&value],
    )
}
fn merkle_node_hash(
    params: &StarkFriParamsV1,
    domain: StarkMerkleDomainV1,
    merkle_depth: usize,
    index: usize,
    left: &GoldilocksDigest384V1,
    right: &GoldilocksDigest384V1,
) -> Option<GoldilocksDigest384V1> {
    let index = u64::try_from(index).ok()?;
    let merkle_depth = u64::try_from(merkle_depth).ok()?;
    stark_digest_v1(
        params,
        domain.role.domain_tag(),
        b"node",
        domain.oracle_level,
        index,
        merkle_depth,
        &[left.as_ref(), right.as_ref()],
    )
}
/// Verify a Merkle inclusion proof for a leaf value to `root`.
fn merkle_verify(
    params: &StarkFriParamsV1,
    domain: StarkMerkleDomainV1,
    root: &GoldilocksDigest384V1,
    leaf: Fq,
    path: &MerklePath,
) -> bool {
    let Some(mut current_index) = merkle_path_index(path) else {
        return false;
    };
    let Some(mut acc) = merkle_leaf_hash(params, domain, leaf, current_index) else {
        return false;
    };
    for (depth, sib) in path.siblings.iter().enumerate() {
        let i = depth;
        let byte = i / 8;
        if byte >= path.dirs.len() {
            return false;
        }
        let dir_bit = (path.dirs[byte] >> (i % 8)) & 1; // 0: leaf on left, 1: leaf on right
        let parent_index = current_index / 2;
        acc = match if dir_bit == 0 {
            merkle_node_hash(params, domain, depth + 1, parent_index, &acc, sib)
        } else {
            merkle_node_hash(params, domain, depth + 1, parent_index, sib, &acc)
        } {
            Some(value) => value,
            None => return false,
        };
        current_index = parent_index;
    }
    &acc == root
}
fn fri_merkle_verify(
    params: &StarkFriParamsV1,
    domain: StarkMerkleDomainV1,
    root: &GoldilocksDigest384V1,
    leaf: Fp4,
    path: &MerklePath,
) -> bool {
    let Some(mut current_index) = merkle_path_index(path) else {
        return false;
    };
    let Some(mut acc) = fri_merkle_leaf_hash(params, domain, leaf, current_index) else {
        return false;
    };
    for (depth, sibling) in path.siblings.iter().enumerate() {
        let byte = depth / 8;
        if byte >= path.dirs.len() {
            return false;
        }
        let parent_index = current_index / 2;
        let direction = (path.dirs[byte] >> (depth % 8)) & 1;
        acc = match if direction == 0 {
            merkle_node_hash(params, domain, depth + 1, parent_index, &acc, sibling)
        } else {
            merkle_node_hash(params, domain, depth + 1, parent_index, sibling, &acc)
        } {
            Some(value) => value,
            None => return false,
        };
        current_index = parent_index;
    }
    &acc == root
}
fn merkle_path_index(path: &MerklePath) -> Option<usize> {
    let depth = path.siblings.len();
    if depth == 0 {
        return Some(0);
    }
    if depth > usize::BITS as usize {
        return None;
    }
    let mut index = 0usize;
    for i in 0..depth {
        let byte = i / 8;
        if byte >= path.dirs.len() {
            return None;
        }
        let dir_bit = (path.dirs[byte] >> (i % 8)) & 1;
        index |= (dir_bit as usize) << i;
    }
    Some(index)
}
fn merkle_path_depth_ok(
    path: &MerklePath,
    expected_depth: usize,
    limits: &StarkVerifierLimits,
) -> bool {
    if expected_depth > effective_max_merkle_depth(limits) || path.siblings.len() != expected_depth
    {
        return false;
    }
    let required_dir_bytes = (expected_depth + 7) / 8;
    if path.dirs.len() != required_dir_bytes {
        return false;
    }
    if expected_depth % 8 != 0 {
        let used_bits = expected_depth % 8;
        if let Some(&last) = path.dirs.last() {
            let mask = !((1u8 << used_bits) - 1);
            if last & mask != 0 {
                return false;
            }
        } else {
            return false;
        }
    }
    true
}
#[cfg(any(test, feature = "test-utils"))]
/// Verify a STARK FRI envelope under `zk-stark` with default limits.
pub fn verify_stark_fri_envelope(bytes: &[u8]) -> bool {
    verify_stark_fri_envelope_with_limits(bytes, &StarkVerifierLimits::default())
}
fn log2_usize(value: usize) -> Option<usize> {
    if value == 0 || !value.is_power_of_two() {
        return None;
    }
    Some(usize::BITS as usize - 1 - value.leading_zeros() as usize)
}
fn layers_required(params: &StarkFriParamsV1) -> Option<usize> {
    // Opening verification calls this before validating the remaining parameters. Compute the
    // sole V1 binary geometry directly, without shifting by an untrusted wire exponent or
    // accepting arities that FoldDecommitV1 cannot represent.
    let layers = usize::from(params.n_log2);
    (params.fold_arity == 2
        && layers != 0
        && params.n_log2 <= MAX_DOMAIN_LOG2
        && layers <= MAX_FRI_LAYERS)
        .then_some(layers)
}
fn validate_params(
    params: &StarkFriParamsV1,
    roots_len: usize,
    query_count: usize,
    limits: &StarkVerifierLimits,
) -> Option<usize> {
    if params.version != 1
        || params.n_log2 == 0
        || params.n_log2 > effective_max_domain_log2(limits)
    {
        return None;
    }
    if params.blowup_log2 == 0
        || params.blowup_log2 > effective_max_blowup_log2(limits)
        || params.blowup_log2 > params.n_log2
    {
        return None;
    }
    // The current wire format (`FoldDecommitV1`) carries a binary fold (y0,y1),
    // so only `fold_arity = 2` is supported by the native verifier.
    if params.fold_arity != 2 || params.fold_arity > effective_max_fold_arity(limits) {
        return None;
    }
    if params.merkle_arity != 2 {
        return None;
    }
    if validate_stark_domain_tag(&params.domain_tag, effective_max_domain_tag_len(limits)).is_err()
    {
        return None;
    }
    if params.queries == 0
        || params.queries as usize > effective_max_queries(limits)
        || params.queries as usize != query_count
    {
        return None;
    }
    let domain = 1usize.checked_shl(u32::from(params.n_log2))?;
    if query_count > domain {
        return None;
    }
    if roots_len == 0 || roots_len > effective_max_merkle_depth(limits) + 1 {
        return None;
    }
    let required_layers = layers_required(params)?;
    if roots_len != required_layers + 1 {
        return None;
    }
    Some(required_layers)
}
fn validate_stark_opening_commitment_params_with_limits_v1(
    params: &StarkFriParamsV1,
    limits: &StarkVerifierLimits,
) -> Result<(), &'static str> {
    let roots_len = layers_required(params)
        .and_then(|layers| layers.checked_add(1))
        .ok_or("STARK opening commitment parameters invalid")?;
    if validate_params(params, roots_len, usize::from(params.queries), limits).is_none() {
        return Err("STARK opening commitment parameters invalid");
    }
    Ok(())
}
#[cfg(test)]
#[path = "stark/frame_identity_tests.rs"]
mod frame_identity_tests;
#[cfg(test)]
mod tests {
    include!("stark/tests.rs");
}
#[cfg(test)]
fn derive_query_index(
    label: &str,
    params: &StarkFriParamsV1,
    roots: &[GoldilocksDigest384V1],
    query_idx: usize,
) -> Option<usize> {
    if params.n_log2 as u32 >= usize::BITS {
        return None;
    }
    let domain = 1usize << params.n_log2;
    if domain == 0 {
        return None;
    }
    let (word, _) = derive_query_challenge_word(label, params, roots, query_idx, 0)?;
    Some((u128::from(word) % (domain as u128)) as usize)
}
fn stark_params_transcript_bytes_v1(params: &StarkFriParamsV1) -> Option<Vec<u8>> {
    let domain_len = u32::try_from(params.domain_tag.len()).ok()?;
    let mut bytes = Vec::with_capacity(2 + 4 + 2 + 4 + params.domain_tag.len());
    bytes.extend_from_slice(&params.version.to_le_bytes());
    bytes.extend_from_slice(&[
        params.n_log2,
        params.blowup_log2,
        params.fold_arity,
        params.merkle_arity,
    ]);
    bytes.extend_from_slice(&params.queries.to_le_bytes());
    bytes.extend_from_slice(&domain_len.to_le_bytes());
    bytes.extend_from_slice(params.domain_tag.as_bytes());
    Some(bytes)
}
fn derive_query_challenge_word(
    label: &str,
    params: &StarkFriParamsV1,
    roots: &[GoldilocksDigest384V1],
    query_idx: usize,
    rejection_attempt: usize,
) -> Option<(u64, u128)> {
    let query_idx = u64::try_from(query_idx).ok()?;
    let rejection_attempt = u64::try_from(rejection_attempt).ok()?;
    let params_bytes = stark_params_transcript_bytes_v1(params)?;
    let mut roots_bytes = Vec::with_capacity(roots.len() * GoldilocksDigest384V1::BYTES);
    for root in roots {
        roots_bytes.extend_from_slice(root.as_ref());
    }
    let digest = stark_digest_v1(
        params,
        b"transcript",
        b"query-index",
        0,
        query_idx,
        rejection_attempt,
        &[label.as_bytes(), &params_bytes, &roots_bytes],
    )?;
    Some((digest.words()[0], MOD_P))
}
fn derive_bounded_query_offset(
    label: &str,
    params: &StarkFriParamsV1,
    roots: &[GoldilocksDigest384V1],
    query_idx: usize,
    bound: usize,
) -> Result<usize, &'static str> {
    if bound == 0 {
        return Err("FRI query index derivation failed");
    }
    let bound = bound as u128;
    for rejection_attempt in 0..STARK_FRI_BOUNDED_QUERY_REJECTION_ATTEMPTS {
        let (word, source_space) =
            derive_query_challenge_word(label, params, roots, query_idx, rejection_attempt)
                .ok_or("FRI query index derivation failed")?;
        let limit = source_space
            .checked_sub(source_space % bound)
            .ok_or("FRI query index derivation failed")?;
        let word = u128::from(word);
        if word < limit {
            return usize::try_from(word % bound).map_err(|_| "FRI query index derivation failed");
        }
    }
    Err("FRI query index derivation failed")
}
fn derive_query_indices_without_replacement(
    label: &str,
    params: &StarkFriParamsV1,
    roots: &[GoldilocksDigest384V1],
    query_count: usize,
    domain: usize,
) -> Result<Vec<usize>, &'static str> {
    if domain == 0 {
        return Err("FRI domain size overflow");
    }
    if query_count > domain {
        return Err("FRI query count exceeds domain size");
    }
    let mut swaps = BTreeMap::new();
    let mut indices = Vec::with_capacity(query_count);
    for query_number in 0..query_count {
        let remaining = domain
            .checked_sub(query_number)
            .ok_or("FRI query index derivation failed")?;
        let offset = derive_bounded_query_offset(label, params, roots, query_number, remaining)?;
        let draw = query_number
            .checked_add(offset)
            .ok_or("FRI query index derivation failed")?;
        let selected = swaps.get(&draw).copied().unwrap_or(draw);
        if indices.contains(&selected) {
            return Err(STARK_FRI_QUERY_INDEX_REPEATED_ERROR);
        }
        let replacement = swaps.get(&query_number).copied().unwrap_or(query_number);
        swaps.insert(draw, replacement);
        indices.push(selected);
    }
    Ok(indices)
}
/// Norito-serializable Merkle path (dirs as bitset, siblings as hashes).
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_core::zk_stark::MerklePath")]
#[derive(
    Debug, Clone, JsonSerialize, JsonDeserialize, norito::NoritoSerialize, norito::NoritoDeserialize,
)]
pub struct MerklePath {
    /// Direction bits per level: 0 => leaf/hash on left, 1 => on right
    pub dirs: Vec<u8>,
    /// Sibling hashes from leaf to root (one per level)
    pub siblings: Vec<GoldilocksDigest384V1>,
}
/// Parameters for a binary multi-round FRI check.
#[derive(
    Debug,
    Clone,
    JsonSerialize,
    JsonDeserialize,
    norito::NoritoSerialize,
    norito::NoritoDeserialize,
    norito::NoritoSchema,
)]
#[norito_schema(name = "iroha_core::zk_stark::StarkFriParamsV1")]
pub struct StarkFriParamsV1 {
    /// Version tag for format evolution
    pub version: u16,
    /// Log2 of evaluation domain size (e.g., 3 for size 8)
    pub n_log2: u8,
    /// Log2 of the blowup factor applied before FRI folding (e.g., 3 for 8x)
    pub blowup_log2: u8,
    /// Arity of each FRI fold; the sole V1 wire representation requires exactly 2.
    pub fold_arity: u8,
    /// Number of queries expected in the proof (must match `proof.queries.len()`)
    pub queries: u16,
    /// Merkle branching factor (current backend supports binary trees only)
    pub merkle_arity: u8,
    /// Domain tag mixed into transcripts and query sampling
    pub domain_tag: String,
}
/// Minimal verifying-key payload for the `stark/fri/*` backends.
///
/// This is stored inside [`iroha_data_model::proof::VerifyingKeyBox::bytes`] and
/// pins the verifier parameters (domain size, query count, etc.). The digest is fixed to
/// [`STARK_FRI_PROFILE_ID_V1`] and therefore has no selector on the wire.
///
/// Note: `domain_tag` is **not** part of the verifying key because it is instance-specific
/// and is derived from the outer [`iroha_data_model::zk::OpenVerifyEnvelope`] metadata.
#[derive(
    Debug,
    Clone,
    JsonSerialize,
    JsonDeserialize,
    norito::NoritoSerialize,
    norito::NoritoDeserialize,
    norito::NoritoSchema,
)]
#[norito_schema(name = "iroha_core::zk_stark::StarkFriVerifyingKeyV1")]
pub struct StarkFriVerifyingKeyV1 {
    /// Version tag for format evolution.
    pub version: u16,
    /// Canonical circuit identifier string.
    pub circuit_id: String,
    /// Log2 of evaluation domain size.
    pub n_log2: u8,
    /// Log2 of the blowup factor applied before FRI folding.
    pub blowup_log2: u8,
    /// Arity of each FRI fold (current wire format supports 2).
    pub fold_arity: u8,
    /// Number of queries sampled by the verifier.
    pub queries: u16,
    /// Merkle branching factor (current backend supports binary trees only).
    pub merkle_arity: u8,
}
pub use crate::STARK_FRI_VERIFYING_KEY_V1_MAX_BYTES;
const STARK_FRI_VERIFYING_KEY_V1_MAX_NESTING_DEPTH: usize = 8;
/// Decode one exact canonical STARK/FRI V1 verifying-key payload under a
/// schema-specific resource budget.
///
/// # Errors
///
/// Returns an error when the frame exceeds the V1 byte bound, advertises an oversized field or
/// allocation, is not canonical Norito, or does not decode to [`StarkFriVerifyingKeyV1`].
pub fn decode_stark_fri_verifying_key_v1(bytes: &[u8]) -> Result<StarkFriVerifyingKeyV1, String> {
    if bytes.len() > STARK_FRI_VERIFYING_KEY_V1_MAX_BYTES {
        return Err(format!(
            "STARK/FRI verifier key exceeds the {}-byte limit",
            STARK_FRI_VERIFYING_KEY_V1_MAX_BYTES
        ));
    }
    let circuit_id_limit = MAX_TRANSCRIPT_LABEL_LEN;
    let limits = norito::DecodeLimits::new(
        circuit_id_limit,
        STARK_FRI_VERIFYING_KEY_V1_MAX_BYTES,
        circuit_id_limit.saturating_add(16),
        STARK_FRI_VERIFYING_KEY_V1_MAX_BYTES.saturating_mul(2),
        STARK_FRI_VERIFYING_KEY_V1_MAX_NESTING_DEPTH,
    );
    norito::decode_canonical_with_limits(bytes, limits)
        .map_err(|err| format!("invalid canonical STARK/FRI verifier key: {err}"))
}
/// Validate that a STARK/FRI verifier-key payload uses ledger-grade verifier parameters.
///
/// This is a control-plane floor for proof-system admission. It rejects historical
/// PoC-sized STARK/FRI parameters while leaving circuit-specific algebraic validation to the
/// verifier for each proof. The only commitment construction is fixed by the V1 schema.
pub fn validate_stark_fri_canonical_verifying_key_payload(
    payload: &StarkFriVerifyingKeyV1,
    circuit_id: &str,
    label: &str,
) -> Result<(), String> {
    validate_stark_circuit_id(circuit_id).map_err(|err| {
        format!("{label} STARK/FRI verifier key expected circuit id invalid: {err}")
    })?;
    if payload.version != 1 {
        return Err(format!("{label} STARK/FRI verifier key must use version 1"));
    }
    validate_stark_circuit_id(&payload.circuit_id)
        .map_err(|err| format!("{label} STARK/FRI verifier key circuit id invalid: {err}"))?;
    if payload.circuit_id != circuit_id {
        return Err(format!(
            "{label} STARK/FRI verifier key circuit id mismatch"
        ));
    }
    if stark_air_circuit_id_targets_ivm_execution(circuit_id) {
        return Err(format!(
            "{label} IVM execution relation is unavailable until complete native STARK verification"
        ));
    }
    if payload.fold_arity != 2 {
        return Err(format!(
            "{label} STARK/FRI verifier key must use binary FRI folding"
        ));
    }
    if payload.merkle_arity != 2 {
        return Err(format!(
            "{label} STARK/FRI verifier key must use binary Merkle paths"
        ));
    }
    if payload.n_log2 < STARK_FRI_CONSENSUS_MIN_N_LOG2 {
        return Err(format!(
            "{label} STARK/FRI n_log2 {} is below consensus floor {}",
            payload.n_log2, STARK_FRI_CONSENSUS_MIN_N_LOG2
        ));
    }
    if stark_air_circuit_id_uses_generic_binding(&payload.circuit_id)
        && payload.n_log2 > MAX_BINDING_AIR_DOMAIN_LOG2
    {
        return Err(format!(
            "{label} Binding AIR n_log2 {} exceeds exact trace-root reconstruction limit {}",
            payload.n_log2, MAX_BINDING_AIR_DOMAIN_LOG2
        ));
    }
    if payload.blowup_log2 < STARK_FRI_CONSENSUS_MIN_BLOWUP_LOG2 {
        return Err(format!(
            "{label} STARK/FRI blowup_log2 {} is below consensus floor {}",
            payload.blowup_log2, STARK_FRI_CONSENSUS_MIN_BLOWUP_LOG2
        ));
    }
    if payload.blowup_log2 > payload.n_log2 {
        return Err(format!(
            "{label} STARK/FRI blowup_log2 {} exceeds n_log2 {}",
            payload.blowup_log2, payload.n_log2
        ));
    }
    if payload.queries < STARK_FRI_CONSENSUS_MIN_QUERIES {
        return Err(format!(
            "{label} STARK/FRI queries {} is below consensus floor {}",
            payload.queries, STARK_FRI_CONSENSUS_MIN_QUERIES
        ));
    }
    if payload.n_log2 > MAX_DOMAIN_LOG2
        || payload.blowup_log2 > MAX_DOMAIN_LOG2
        || usize::from(payload.queries) > MAX_FRI_QUERIES
    {
        return Err(format!(
            "{label} STARK/FRI verifier key exceeds native verifier limits"
        ));
    }
    Ok(())
}
#[cfg(test)]
mod verifying_key_decode_tests {
    use super::*;
    #[derive(norito::NoritoSchema)]
    #[norito_schema(
        name = "iroha_core::zk_stark::verifying_key_decode_tests::RetiredSelectorVerifyingKeyV0"
    )]
    #[derive(norito::NoritoSerialize)]
    struct RetiredSelectorVerifyingKeyV0 {
        version: u16,
        circuit_id: String,
        n_log2: u8,
        blowup_log2: u8,
        fold_arity: u8,
        queries: u16,
        merkle_arity: u8,
        hash_fn: u8,
    }
    fn canonical_payload() -> StarkFriVerifyingKeyV1 {
        StarkFriVerifyingKeyV1 {
            version: 1,
            circuit_id: "stark/fri/poseidon-x7-goldilocks-6x64-v1:bounded-vk-test".to_owned(),
            n_log2: STARK_FRI_CONSENSUS_MIN_N_LOG2,
            blowup_log2: STARK_FRI_CONSENSUS_MIN_BLOWUP_LOG2,
            fold_arity: 2,
            queries: STARK_FRI_CONSENSUS_MIN_QUERIES,
            merkle_arity: 2,
        }
    }
    #[test]
    fn bounded_verifying_key_decode_accepts_canonical_payload() {
        let payload = canonical_payload();
        let bytes = norito::encode_canonical(&payload).expect("encode canonical STARK key");
        let decoded = decode_stark_fri_verifying_key_v1(&bytes)
            .expect("bounded decoder must accept canonical STARK key");
        assert_eq!(decoded.circuit_id, payload.circuit_id);
        assert_eq!(decoded.queries, payload.queries);
    }
    #[test]
    fn bounded_verifying_key_decode_rejects_alternate_layout() {
        let payload = canonical_payload();
        let alternate_flags =
            norito::core::default_encode_flags() ^ norito::core::header_flags::COMPACT_LEN;
        let alternate = {
            let _guard = norito::core::DecodeFlagsGuard::enter(alternate_flags);
            norito::to_bytes(&payload).expect("encode alternate-layout STARK key")
        };
        norito::decode_from_bytes::<StarkFriVerifyingKeyV1>(&alternate)
            .expect("ordinary decoder accepts the advertised alternate layout");
        assert!(
            decode_stark_fri_verifying_key_v1(&alternate).is_err(),
            "registry decoder must accept only the canonical layout"
        );
    }
    #[test]
    fn bounded_verifying_key_decode_rejects_retired_hash_selector_wire() {
        let payload = canonical_payload();
        let retired = RetiredSelectorVerifyingKeyV0 {
            version: payload.version,
            circuit_id: payload.circuit_id,
            n_log2: payload.n_log2,
            blowup_log2: payload.blowup_log2,
            fold_arity: payload.fold_arity,
            queries: payload.queries,
            merkle_arity: payload.merkle_arity,
            hash_fn: 1,
        };
        let (payload, flags) = norito::codec::encode_with_header_flags(&retired);
        let bytes =
            norito::core::frame_bare_with_header_flags::<StarkFriVerifyingKeyV1>(&payload, flags)
                .expect("frame retired key payload under the actual V1 owner");
        let view = norito::core::from_bytes_view(&bytes).expect("valid frame and checksum");
        assert_eq!(
            view.schema(),
            norito::schema::identity::frame_hash::<StarkFriVerifyingKeyV1>(),
            "rejection must exercise the retired payload, not an unrelated frame identity"
        );
        assert_eq!(view.as_bytes(), payload);
        assert!(
            decode_stark_fri_verifying_key_v1(&bytes).is_err(),
            "the selector-free V1 decoder must reject pre-release selector-bearing keys"
        );
    }
    #[test]
    fn bounded_verifying_key_decode_rejects_huge_declared_inner_length() {
        let payload = canonical_payload();
        let mut bytes = norito::encode_canonical(&payload).expect("encode canonical STARK key");
        let circuit = payload.circuit_id.as_bytes();
        let circuit_offset = bytes
            .windows(circuit.len())
            .position(|window| window == circuit)
            .expect("encoded circuit id");
        assert!(circuit_offset > 0, "circuit id must carry a length prefix");
        bytes[circuit_offset - 1] = u8::MAX;
        assert!(
            decode_stark_fri_verifying_key_v1(&bytes).is_err(),
            "a tiny frame must not allocate from an attacker-declared inner length"
        );
    }
    #[test]
    fn bounded_verifying_key_decode_rejects_oversized_frame() {
        let bytes = vec![0_u8; STARK_FRI_VERIFYING_KEY_V1_MAX_BYTES + 1];
        let error = decode_stark_fri_verifying_key_v1(&bytes)
            .expect_err("oversized verifier-key frame must fail before decoding");
        assert!(error.contains("exceeds"), "unexpected error: {error}");
    }
}
/// Commitments for multiple layers and optional composition root.
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_core::zk_stark::StarkCommitmentsV1")]
#[derive(
    Debug, Clone, JsonSerialize, JsonDeserialize, norito::NoritoSerialize, norito::NoritoDeserialize,
)]
pub struct StarkCommitmentsV1 {
    /// Version tag for format evolution
    pub version: u16,
    /// Merkle roots per layer, from layer 0 (original evaluations) to layer L (final folded layer)
    pub roots: Vec<GoldilocksDigest384V1>,
    /// Optional composition polynomial root over the final layer domain (length n >> L)
    pub comp_root: Option<GoldilocksDigest384V1>,
}
/// Auxiliary term contributing to the composition polynomial evaluation.
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_core::zk_stark::StarkCompositionTermV1")]
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    JsonSerialize,
    JsonDeserialize,
    norito::NoritoSerialize,
    norito::NoritoDeserialize,
)]
pub struct StarkCompositionTermV1 {
    /// Canonical wire index for this auxiliary value (monotonic, caller-defined ordering)
    pub wire_index: u32,
    /// Value contributed by this wire
    pub value: u64,
    /// Coefficient multiplied with the value
    pub coeff: u64,
}
/// Composition leaf data stored under `comp_root`.
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_core::zk_stark::StarkCompositionValueV1")]
#[derive(
    Debug, Clone, JsonSerialize, JsonDeserialize, norito::NoritoSerialize, norito::NoritoDeserialize,
)]
pub struct StarkCompositionValueV1 {
    /// Merkle leaf value recorded under `comp_root`
    pub leaf: u64,
    /// Constant term added to the composition result
    pub constant: u64,
    /// Coefficient applied to the final folded `z` value
    pub z_coeff: u64,
    /// Additional auxiliary wire contributions
    pub aux_terms: Vec<StarkCompositionTermV1>,
    /// Inclusion path for the leaf under `comp_root`
    pub path: MerklePath,
}
/// Sampled AIR trace and composition opening for one verifier query.
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_core::zk_stark::StarkAirOpeningV1")]
#[derive(
    Debug, Clone, JsonSerialize, JsonDeserialize, norito::NoritoSerialize, norito::NoritoDeserialize,
)]
pub struct StarkAirOpeningV1 {
    /// Evaluation-domain index sampled by the verifier transcript.
    pub index: u32,
    /// AIR trace row at `index`.
    pub row: Vec<u64>,
    /// AIR trace row at `(index + 1) mod domain_size`.
    pub next_row: Vec<u64>,
    /// Inclusion path for `row` under [`StarkAirProofV1::trace_root`].
    pub row_path: MerklePath,
    /// Inclusion path for `next_row` under [`StarkAirProofV1::trace_root`].
    pub next_row_path: MerklePath,
    /// AIR composition evaluation at `index`; this is the FRI base-layer value.
    pub composition_value: u64,
    /// Inclusion path for `composition_value` under [`StarkAirProofV1::composition_root`].
    pub composition_path: MerklePath,
}
/// Verifier-owned AIR statement carried by V1 STARK proofs.
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_core::zk_stark::StarkAirProofV1")]
#[derive(
    Debug, Clone, JsonSerialize, JsonDeserialize, norito::NoritoSerialize, norito::NoritoDeserialize,
)]
pub struct StarkAirProofV1 {
    /// Version tag.
    pub version: u16,
    /// Canonical circuit identifier for the public statement.
    pub circuit_id: String,
    /// Six-lane digest of the public statement reconstructed by the caller.
    pub public_digest: GoldilocksDigest384V1,
    /// Merkle root over row-major AIR trace rows. Generic Binding verification reconstructs this
    /// root exactly from the public statement within [`MAX_BINDING_AIR_DOMAIN_LOG2`].
    pub trace_root: GoldilocksDigest384V1,
    /// Merkle root over AIR composition evaluations; must equal FRI layer root 0.
    pub composition_root: GoldilocksDigest384V1,
    /// Number of field values in each AIR trace row.
    pub trace_width: u16,
    /// Sampled AIR openings, one per FRI query.
    pub openings: Vec<StarkAirOpeningV1>,
}
/// Decommitment for one fold step at layer `k`.
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_core::zk_stark::FoldDecommitV1")]
#[derive(
    Debug, Clone, JsonSerialize, JsonDeserialize, norito::NoritoSerialize, norito::NoritoDeserialize,
)]
pub struct FoldDecommitV1 {
    /// Index j at this bit-reversed layer (so layer k reads positions 2*j and 2*j+1 from layer k)
    pub j: u32,
    /// Left value from the adjacent `(x, -x)` pair at bit-reversed layer position `2*j`.
    pub y0: GoldilocksFp4V1,
    /// Right value from the adjacent `(x, -x)` pair at bit-reversed layer position `2*j+1`.
    pub y1: GoldilocksFp4V1,
    /// Merkle paths for y0 and y1 in layer k
    pub path_y0: MerklePath,
    /// Merkle path for y1 in layer k
    pub path_y1: MerklePath,
    /// Folded value at layer k+1, with Merkle path into root[k+1].
    ///
    /// Current V1 semantics interpret the two adjacent openings as evaluations at `(x, -x)` and
    /// require `z = (y0 + y1) / 2 + r_k * (y0 - y1) / (2x)`.
    pub z: GoldilocksFp4V1,
    /// Merkle path for the folded value z in the next layer (k+1)
    pub path_z: MerklePath,
}
/// STARK proof carrying commitments and query decommitments.
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_core::zk_stark::StarkProofV1")]
#[derive(
    Debug, Clone, JsonSerialize, JsonDeserialize, norito::NoritoSerialize, norito::NoritoDeserialize,
)]
pub struct StarkProofV1 {
    /// Version tag
    pub version: u16,
    /// Commitment roots
    pub commits: StarkCommitmentsV1,
    /// Query decommitments: one chain of folds per query
    pub queries: Vec<Vec<FoldDecommitV1>>,
    /// Optional composition leaf, auxiliary inputs, and path at final layer per query.
    ///
    /// When present, the expected composition leaf is
    /// `constant + z_coeff*z_final + sum_i coeff_i * value_i`.
    pub comp_values: Option<Vec<StarkCompositionValueV1>>,
    /// V1 AIR section binding sampled trace and composition openings to FRI.
    pub air: Option<StarkAirProofV1>,
}
/// Verification envelope for STARK FRI multi-round (binary) proofs.
#[derive(
    Debug,
    Clone,
    JsonSerialize,
    JsonDeserialize,
    norito::NoritoSerialize,
    norito::NoritoDeserialize,
    norito::NoritoSchema,
)]
#[norito_schema(name = "iroha_core::zk_stark::StarkVerifyEnvelopeV1")]
pub struct StarkVerifyEnvelopeV1 {
    /// Parameters used by the prover
    pub params: StarkFriParamsV1,
    /// Proof object
    pub proof: StarkProofV1,
    /// Transcript label to domain-separate instances
    pub transcript_label: String,
}
fn merkle_levels_from_values(
    params: &StarkFriParamsV1,
    values: &[Fq],
    domain: StarkMerkleDomainV1,
) -> Option<Vec<Vec<GoldilocksDigest384V1>>> {
    if values.is_empty() {
        return None;
    }
    let mut current = values
        .iter()
        .copied()
        .enumerate()
        .map(|(index, value)| merkle_leaf_hash(params, domain, value, index))
        .collect::<Option<Vec<_>>>()?;
    let mut levels = Vec::new();
    let mut merkle_depth = 0_usize;
    loop {
        levels.push(current.clone());
        if current.len() == 1 {
            break;
        }
        if current.len() % 2 == 1 {
            let last = *current.last()?;
            current.push(last);
        }
        let mut next = Vec::with_capacity(current.len() / 2);
        merkle_depth = merkle_depth.checked_add(1)?;
        for (index, pair) in current.chunks_exact(2).enumerate() {
            next.push(merkle_node_hash(
                params,
                domain,
                merkle_depth,
                index,
                &pair[0],
                &pair[1],
            )?);
        }
        current = next;
    }
    Some(levels)
}
fn fri_merkle_levels_from_values(
    params: &StarkFriParamsV1,
    values: &[Fp4],
    domain: StarkMerkleDomainV1,
) -> Option<Vec<Vec<GoldilocksDigest384V1>>> {
    if values.is_empty() {
        return None;
    }
    let mut current = values
        .iter()
        .copied()
        .enumerate()
        .map(|(index, value)| fri_merkle_leaf_hash(params, domain, value, index))
        .collect::<Option<Vec<_>>>()?;
    let mut levels = Vec::new();
    let mut merkle_depth = 0_usize;
    loop {
        levels.push(current.clone());
        if current.len() == 1 {
            break;
        }
        if current.len() % 2 == 1 {
            current.push(*current.last()?);
        }
        merkle_depth = merkle_depth.checked_add(1)?;
        let mut next = Vec::with_capacity(current.len() / 2);
        for (index, pair) in current.chunks_exact(2).enumerate() {
            next.push(merkle_node_hash(
                params,
                domain,
                merkle_depth,
                index,
                &pair[0],
                &pair[1],
            )?);
        }
        current = next;
    }
    Some(levels)
}
fn merkle_path_from_levels(
    index: usize,
    levels: &[Vec<GoldilocksDigest384V1>],
) -> Option<MerklePath> {
    let leaf_level = levels.first()?;
    if index >= leaf_level.len() {
        return None;
    }
    let depth = levels.len().checked_sub(1)?;
    if depth > usize::BITS as usize {
        return None;
    }
    let mut dirs = vec![0u8; (depth + 7) / 8];
    let mut siblings = Vec::with_capacity(depth);
    let mut current_index = index;
    for (level_idx, level) in levels.iter().take(depth).enumerate() {
        if current_index >= level.len() {
            return None;
        }
        let sibling_idx = if current_index.is_multiple_of(2) {
            current_index + 1
        } else {
            current_index.saturating_sub(1)
        };
        let sibling = level
            .get(sibling_idx)
            .copied()
            .unwrap_or_else(|| level[current_index]);
        if current_index % 2 == 1 {
            dirs[level_idx / 8] |= 1u8 << (level_idx % 8);
        }
        siblings.push(sibling);
        current_index /= 2;
    }
    Some(MerklePath { dirs, siblings })
}
fn merkle_root_from_levels(levels: &[Vec<GoldilocksDigest384V1>]) -> Option<GoldilocksDigest384V1> {
    levels.last()?.first().copied()
}
fn stark_constant_field_merkle_root_v1(
    params: &StarkFriParamsV1,
    value: Fq,
    value_count: usize,
) -> Option<GoldilocksDigest384V1> {
    if value_count == 0 || !value_count.is_power_of_two() {
        return None;
    }
    let values = vec![value; value_count];
    let levels =
        merkle_levels_from_values(params, &values, StarkMerkleDomainV1::air_composition())?;
    merkle_root_from_levels(&levels)
}
fn merkle_levels_from_hashes(
    params: &StarkFriParamsV1,
    leaves: Vec<GoldilocksDigest384V1>,
    domain: StarkMerkleDomainV1,
) -> Option<Vec<Vec<GoldilocksDigest384V1>>> {
    if leaves.is_empty() {
        return None;
    }
    let mut current = leaves;
    let mut levels = Vec::new();
    let mut merkle_depth = 0_usize;
    loop {
        levels.push(current.clone());
        if current.len() == 1 {
            break;
        }
        if current.len() % 2 == 1 {
            let last = *current.last()?;
            current.push(last);
        }
        let mut next = Vec::with_capacity(current.len() / 2);
        merkle_depth = merkle_depth.checked_add(1)?;
        for (index, pair) in current.chunks_exact(2).enumerate() {
            next.push(merkle_node_hash(
                params,
                domain,
                merkle_depth,
                index,
                &pair[0],
                &pair[1],
            )?);
        }
        current = next;
    }
    Some(levels)
}
fn merkle_verify_hash(
    params: &StarkFriParamsV1,
    domain: StarkMerkleDomainV1,
    root: &GoldilocksDigest384V1,
    leaf: &GoldilocksDigest384V1,
    path: &MerklePath,
) -> bool {
    let Some(mut current_index) = merkle_path_index(path) else {
        return false;
    };
    let mut acc = *leaf;
    for (depth, sib) in path.siblings.iter().enumerate() {
        let i = depth;
        let byte = i / 8;
        if byte >= path.dirs.len() {
            return false;
        }
        let dir_bit = (path.dirs[byte] >> (i % 8)) & 1;
        let parent_index = current_index / 2;
        acc = match if dir_bit == 0 {
            merkle_node_hash(params, domain, depth + 1, parent_index, &acc, sib)
        } else {
            merkle_node_hash(params, domain, depth + 1, parent_index, sib, &acc)
        } {
            Some(value) => value,
            None => return false,
        };
        current_index = parent_index;
    }
    &acc == root
}
/// Build the V1 AIR composition Merkle root from canonical field values.
#[doc(hidden)]
pub fn stark_merkle_root_from_field_values_v1(
    params: &StarkFriParamsV1,
    values: &[u64],
) -> Option<GoldilocksDigest384V1> {
    let values = values
        .iter()
        .copied()
        .map(Fq::from_canonical_u64)
        .collect::<Option<Vec<_>>>()?;
    let levels =
        merkle_levels_from_values(params, &values, StarkMerkleDomainV1::air_composition())?;
    merkle_root_from_levels(&levels)
}
/// Build a v1 STARK AIR trace Merkle root from row-major trace values.
#[doc(hidden)]
pub fn stark_air_trace_root_from_rows_v1(
    params: &StarkFriParamsV1,
    rows: &[Vec<u64>],
) -> Option<GoldilocksDigest384V1> {
    let trace_leaves = rows
        .iter()
        .enumerate()
        .map(|(index, row)| stark_air_trace_leaf_hash(params, row, index))
        .collect::<Option<Vec<_>>>()?;
    let levels = merkle_levels_from_hashes(params, trace_leaves, StarkMerkleDomainV1::air_trace())?;
    merkle_root_from_levels(&levels)
}
/// Build a V1 auxiliary-composition Merkle root and path from canonical field values.
#[cfg(any(test, feature = "test-utils"))]
#[doc(hidden)]
pub fn stark_merkle_root_and_path_from_field_values_v1(
    params: &StarkFriParamsV1,
    values: &[u64],
    index: usize,
) -> Option<(GoldilocksDigest384V1, MerklePath)> {
    let values = values
        .iter()
        .copied()
        .map(Fq::from_canonical_u64)
        .collect::<Option<Vec<_>>>()?;
    let levels = merkle_levels_from_values(
        params,
        &values,
        StarkMerkleDomainV1::auxiliary_composition(),
    )?;
    Some((
        merkle_root_from_levels(&levels)?,
        merkle_path_from_levels(index, &levels)?,
    ))
}
/// Build a deterministic V1 STARK/FRI envelope from canonical field values.
#[cfg(test)]
pub(crate) fn stark_synthesize_fri_envelope_from_field_values_v1(
    params: StarkFriParamsV1,
    transcript_label: String,
    values: &[u64],
    extra_query_roots: &[GoldilocksDigest384V1],
) -> Option<StarkVerifyEnvelopeV1> {
    let values = values
        .iter()
        .copied()
        .map(Fq::from_canonical_u64)
        .collect::<Option<Vec<_>>>()?;
    synthesize_stark_fri_envelope_from_values(params, transcript_label, values, extra_query_roots)
        .ok()
}
/// Verify that one native AIR opening is bound to its Merkle path indices and roots.
#[cfg(test)]
pub(crate) fn validate_stark_air_opening_commitment_roots_v1(
    params: &StarkFriParamsV1,
    air: &StarkAirProofV1,
    opening: &StarkAirOpeningV1,
) -> Result<(), &'static str> {
    validate_stark_air_opening_commitment_roots_with_limits_v1(
        params,
        air,
        opening,
        &StarkVerifierLimits::default(),
    )
}
/// Verify that one native AIR opening is bound to its Merkle path indices and roots.
#[doc(hidden)]
pub fn validate_stark_air_opening_commitment_roots_with_limits_v1(
    params: &StarkFriParamsV1,
    air: &StarkAirProofV1,
    opening: &StarkAirOpeningV1,
    limits: &StarkVerifierLimits,
) -> Result<(), &'static str> {
    validate_stark_opening_commitment_params_with_limits_v1(params, limits)?;
    let domain_size = 1_usize
        .checked_shl(u32::from(params.n_log2))
        .ok_or("opening domain size overflow")?;
    let opening_index = usize::try_from(opening.index).map_err(|_| "opening index out of range")?;
    if opening_index >= domain_size {
        return Err("opening index out of range");
    }
    let expected_depth = log2_usize(domain_size).ok_or("opening Merkle path depth mismatch")?;
    if !merkle_path_depth_ok(&opening.row_path, expected_depth, limits)
        || !merkle_path_depth_ok(&opening.next_row_path, expected_depth, limits)
        || !merkle_path_depth_ok(&opening.composition_path, expected_depth, limits)
    {
        return Err("opening Merkle path depth mismatch");
    }
    let next_index = (opening_index + 1) % domain_size;
    if merkle_path_index(&opening.row_path) != Some(opening_index)
        || merkle_path_index(&opening.next_row_path) != Some(next_index)
        || merkle_path_index(&opening.composition_path) != Some(opening_index)
    {
        return Err("opening Merkle path index mismatch");
    }
    let row_leaf = stark_air_trace_leaf_hash(params, &opening.row, opening_index)
        .ok_or("row leaf hash failed")?;
    if !merkle_verify_hash(
        params,
        StarkMerkleDomainV1::air_trace(),
        &air.trace_root,
        &row_leaf,
        &opening.row_path,
    ) {
        return Err("row Merkle root mismatch");
    }
    let next_row_leaf = stark_air_trace_leaf_hash(params, &opening.next_row, next_index)
        .ok_or("next-row leaf hash failed")?;
    if !merkle_verify_hash(
        params,
        StarkMerkleDomainV1::air_trace(),
        &air.trace_root,
        &next_row_leaf,
        &opening.next_row_path,
    ) {
        return Err("next-row Merkle root mismatch");
    }
    let composition =
        Fq::from_canonical_u64(opening.composition_value).ok_or("composition field element")?;
    if !merkle_verify(
        params,
        StarkMerkleDomainV1::air_composition(),
        &air.composition_root,
        composition,
        &opening.composition_path,
    ) {
        return Err("composition Merkle root mismatch");
    }
    Ok(())
}
/// Validate FRI query-chain shape, commitments, folds, and return transcript-derived base indices.
pub(crate) fn validate_stark_fri_query_shape_and_indices_v1(
    params: &StarkFriParamsV1,
    transcript_label: &str,
    roots: &[GoldilocksDigest384V1],
    extra_query_roots: &[GoldilocksDigest384V1],
    queries: &[Vec<FoldDecommitV1>],
) -> Result<Vec<usize>, &'static str> {
    validate_stark_fri_query_shape_and_indices_with_limits_v1(
        params,
        transcript_label,
        roots,
        extra_query_roots,
        queries,
        &StarkVerifierLimits::default(),
    )
}
pub(crate) fn validate_stark_fri_query_shape_and_indices_with_limits_v1(
    params: &StarkFriParamsV1,
    transcript_label: &str,
    roots: &[GoldilocksDigest384V1],
    extra_query_roots: &[GoldilocksDigest384V1],
    queries: &[Vec<FoldDecommitV1>],
    limits: &StarkVerifierLimits,
) -> Result<Vec<usize>, &'static str> {
    validate_stark_transcript_label(transcript_label, effective_max_transcript_label_len(limits))
        .map_err(|_| "FRI transcript label invalid")?;
    let expected_chain_len = validate_params(params, roots.len(), queries.len(), limits)
        .ok_or("FRI parameter/root/query shape mismatch")?;
    let total_domain = 1_usize
        .checked_shl(u32::from(params.n_log2))
        .ok_or("FRI domain size overflow")?;
    let fold_arity = usize::from(params.fold_arity);
    let mut query_roots = roots.to_vec();
    query_roots.extend_from_slice(extra_query_roots);
    let base_indices = derive_query_indices_without_replacement(
        transcript_label,
        params,
        &query_roots,
        queries.len(),
        total_domain,
    )?;
    for (chain, mut idx_layer) in queries.iter().zip(base_indices.iter().copied()) {
        if chain.len() != expected_chain_len {
            return Err("FRI query chain length mismatch");
        }
        let mut layer_domain = total_domain;
        for (round, decommit) in chain.iter().enumerate() {
            if layer_domain < fold_arity {
                return Err("FRI query layer domain underflow");
            }
            let expected_pairs = layer_domain / fold_arity;
            let expected_j = idx_layer / fold_arity;
            if expected_j >= expected_pairs || usize::try_from(decommit.j).ok() != Some(expected_j)
            {
                return Err("FRI query fold index mismatch");
            }
            let depth_current =
                log2_usize(layer_domain).ok_or("FRI query current layer depth mismatch")?;
            let depth_next = log2_usize(layer_domain / fold_arity)
                .ok_or("FRI query next layer depth mismatch")?;
            if !merkle_path_depth_ok(&decommit.path_y0, depth_current, limits)
                || !merkle_path_depth_ok(&decommit.path_y1, depth_current, limits)
                || !merkle_path_depth_ok(&decommit.path_z, depth_next, limits)
            {
                return Err("FRI query Merkle path depth mismatch");
            }
            let expected_y0 = expected_j
                .checked_mul(fold_arity)
                .ok_or("FRI query y0 index overflow")?;
            let expected_y1 = expected_y0
                .checked_add(1)
                .ok_or("FRI query y1 index overflow")?;
            if merkle_path_index(&decommit.path_y0) != Some(expected_y0)
                || merkle_path_index(&decommit.path_y1) != Some(expected_y1)
                || merkle_path_index(&decommit.path_z) != Some(expected_j)
            {
                return Err("FRI query Merkle path index mismatch");
            }
            let y0 = Fp4::from_wire(decommit.y0).ok_or("FRI query y0 field element")?;
            let y1 = Fp4::from_wire(decommit.y1).ok_or("FRI query y1 field element")?;
            let z = Fp4::from_wire(decommit.z).ok_or("FRI query z field element")?;
            let current_root = roots.get(round).ok_or("FRI query current root missing")?;
            let next_root = roots.get(round + 1).ok_or("FRI query next root missing")?;
            let current_domain = StarkMerkleDomainV1::fri_layer(round)
                .ok_or("FRI query current layer index overflow")?;
            let next_domain = StarkMerkleDomainV1::fri_layer(round + 1)
                .ok_or("FRI query next layer index overflow")?;
            if !fri_merkle_verify(params, current_domain, current_root, y0, &decommit.path_y0)
                || !fri_merkle_verify(params, current_domain, current_root, y1, &decommit.path_y1)
            {
                return Err("FRI query Merkle root mismatch");
            }
            let beta = fri_round_challenge(params, transcript_label, round, current_root)
                .ok_or("FRI query challenge derivation failed")?;
            let x = domain_x_for_pair(layer_domain, expected_j)
                .ok_or("FRI query domain element derivation failed")?;
            if fri_fold_pair(y0, y1, beta, x) != Some(z) {
                return Err("FRI query fold relation mismatch");
            }
            if !fri_merkle_verify(params, next_domain, next_root, z, &decommit.path_z) {
                return Err("FRI query folded Merkle root mismatch");
            }
            layer_domain /= fold_arity;
            idx_layer = expected_j;
        }
        if layer_domain != 1 || idx_layer != 0 {
            return Err("FRI query does not collapse to final layer");
        }
        let final_z = chain
            .last()
            .and_then(|decommit| Fp4::from_wire(decommit.z))
            .ok_or("FRI query final field element")?;
        if final_z != Fp4::zero() {
            return Err("FRI query final value mismatch");
        }
    }
    Ok(base_indices)
}
pub(crate) fn validate_stark_fri_query_shape_for_base_indices_v1(
    params: &StarkFriParamsV1,
    transcript_label: &str,
    roots: &[GoldilocksDigest384V1],
    queries: &[Vec<FoldDecommitV1>],
    base_indices: &[usize],
) -> Result<Vec<usize>, &'static str> {
    validate_stark_fri_query_shape_for_base_indices_with_limits_v1(
        params,
        transcript_label,
        roots,
        queries,
        base_indices,
        &StarkVerifierLimits::default(),
    )
}
#[doc(hidden)]
pub fn validate_stark_fri_query_shape_for_base_indices_with_limits_v1(
    params: &StarkFriParamsV1,
    transcript_label: &str,
    roots: &[GoldilocksDigest384V1],
    queries: &[Vec<FoldDecommitV1>],
    base_indices: &[usize],
    limits: &StarkVerifierLimits,
) -> Result<Vec<usize>, &'static str> {
    validate_stark_transcript_label(transcript_label, effective_max_transcript_label_len(limits))
        .map_err(|_| "FRI transcript label invalid")?;
    let expected_chain_len = validate_params(params, roots.len(), queries.len(), limits)
        .ok_or("FRI parameter/root/query shape mismatch")?;
    let total_domain = 1_usize
        .checked_shl(u32::from(params.n_log2))
        .ok_or("FRI domain size overflow")?;
    if base_indices.len() != queries.len() {
        return Err("FRI query base index count mismatch");
    }
    if base_indices.iter().any(|&index| index >= total_domain) {
        return Err("FRI query base index exceeds domain");
    }
    let mut seen_indices = BTreeSet::new();
    if base_indices
        .iter()
        .copied()
        .any(|index| !seen_indices.insert(index))
    {
        return Err(STARK_FRI_QUERY_INDEX_REPEATED_ERROR);
    }
    let fold_arity = usize::from(params.fold_arity);
    for (chain, mut idx_layer) in queries.iter().zip(base_indices.iter().copied()) {
        if chain.len() != expected_chain_len {
            return Err("FRI query chain length mismatch");
        }
        let mut layer_domain = total_domain;
        for (round, decommit) in chain.iter().enumerate() {
            if layer_domain < fold_arity {
                return Err("FRI query layer domain underflow");
            }
            let expected_pairs = layer_domain / fold_arity;
            let expected_j = idx_layer / fold_arity;
            if expected_j >= expected_pairs || usize::try_from(decommit.j).ok() != Some(expected_j)
            {
                return Err("FRI query fold index mismatch");
            }
            let depth_current =
                log2_usize(layer_domain).ok_or("FRI query current layer depth mismatch")?;
            let depth_next = log2_usize(layer_domain / fold_arity)
                .ok_or("FRI query next layer depth mismatch")?;
            if !merkle_path_depth_ok(&decommit.path_y0, depth_current, limits)
                || !merkle_path_depth_ok(&decommit.path_y1, depth_current, limits)
                || !merkle_path_depth_ok(&decommit.path_z, depth_next, limits)
            {
                return Err("FRI query Merkle path depth mismatch");
            }
            let expected_y0 = expected_j
                .checked_mul(fold_arity)
                .ok_or("FRI query y0 index overflow")?;
            let expected_y1 = expected_y0
                .checked_add(1)
                .ok_or("FRI query y1 index overflow")?;
            if merkle_path_index(&decommit.path_y0) != Some(expected_y0)
                || merkle_path_index(&decommit.path_y1) != Some(expected_y1)
                || merkle_path_index(&decommit.path_z) != Some(expected_j)
            {
                return Err("FRI query Merkle path index mismatch");
            }
            let y0 = Fp4::from_wire(decommit.y0).ok_or("FRI query y0 field element")?;
            let y1 = Fp4::from_wire(decommit.y1).ok_or("FRI query y1 field element")?;
            let z = Fp4::from_wire(decommit.z).ok_or("FRI query z field element")?;
            let current_root = roots.get(round).ok_or("FRI query current root missing")?;
            let next_root = roots.get(round + 1).ok_or("FRI query next root missing")?;
            let current_domain = StarkMerkleDomainV1::fri_layer(round)
                .ok_or("FRI query current layer index overflow")?;
            let next_domain = StarkMerkleDomainV1::fri_layer(round + 1)
                .ok_or("FRI query next layer index overflow")?;
            if !fri_merkle_verify(params, current_domain, current_root, y0, &decommit.path_y0)
                || !fri_merkle_verify(params, current_domain, current_root, y1, &decommit.path_y1)
            {
                return Err("FRI query Merkle root mismatch");
            }
            let beta = fri_round_challenge(params, transcript_label, round, current_root)
                .ok_or("FRI query challenge derivation failed")?;
            let x = domain_x_for_pair(layer_domain, expected_j)
                .ok_or("FRI query domain element derivation failed")?;
            if fri_fold_pair(y0, y1, beta, x) != Some(z) {
                return Err("FRI query fold relation mismatch");
            }
            if !fri_merkle_verify(params, next_domain, next_root, z, &decommit.path_z) {
                return Err("FRI query folded Merkle root mismatch");
            }
            layer_domain /= fold_arity;
            idx_layer = expected_j;
        }
        if layer_domain != 1 || idx_layer != 0 {
            return Err("FRI query does not collapse to final layer");
        }
        let final_z = chain
            .last()
            .and_then(|decommit| Fp4::from_wire(decommit.z))
            .ok_or("FRI query final field element")?;
        if final_z != Fp4::zero() {
            return Err("FRI query final value mismatch");
        }
    }
    Ok(base_indices.to_vec())
}
/// Verify that an AIR opening is the value opened by the first FRI layer.
#[doc(hidden)]
pub fn validate_stark_air_opening_first_fri_value_v1(
    opening: &StarkAirOpeningV1,
    base_index: usize,
    first_decommit: &FoldDecommitV1,
) -> Result<(), &'static str> {
    if usize::try_from(opening.index).ok() != Some(base_index) {
        return Err("AIR/FRI opening index mismatch");
    }
    let opened_fri_value = if base_index.is_multiple_of(2) {
        Fp4::from_wire(first_decommit.y0)
    } else {
        Fp4::from_wire(first_decommit.y1)
    };
    let Some(composition_value) = Fq::from_canonical_u64(opening.composition_value) else {
        return Err("AIR/FRI composition value is non-canonical");
    };
    if opened_fri_value != Some(Fp4::from_base(composition_value)) {
        return Err("AIR/FRI composition value mismatch");
    }
    Ok(())
}
fn stark_air_trace_width() -> usize {
    usize::from(STARK_BINDING_AIR_TRACE_WIDTH_V1)
}
#[derive(Clone, Copy)]
struct StarkAirExplicitVerificationContext<'a> {
    circuit_id: &'a str,
    public_digest: &'a GoldilocksDigest384V1,
    rows: &'a [Vec<u64>],
    composition_values: &'a [u64],
    base_indices: Option<&'a [usize]>,
}
#[derive(Clone, Copy)]
enum StarkAirVerificationContext<'a> {
    Binding,
    BfvFullBootstrapPublicPadding {
        statement_hash: &'a iroha_crypto::Hash,
        trace_material_digest: &'a iroha_crypto::Hash,
        slot_index: u32,
        bound_mode: iroha_crypto::BfvFullBootstrapExecutionProofBoundModeV1,
    },
    Explicit(&'a StarkAirExplicitVerificationContext<'a>),
}
impl StarkAirVerificationContext<'_> {
    fn allows_auxiliary_composition(self) -> bool {
        matches!(self, Self::Binding)
    }
    fn trace_width(self) -> usize {
        match self {
            Self::Binding => stark_air_trace_width(),
            Self::BfvFullBootstrapPublicPadding { .. } => {
                usize::from(iroha_crypto::BFV_FULL_BOOTSTRAP_ARITHMETIC_TRACE_ROW_WIDTH_V1)
            }
            Self::Explicit(explicit) => explicit.rows.first().map(Vec::len).unwrap_or(usize::MAX),
        }
    }
}
fn stark_air_row(index: usize, public_digest: &GoldilocksDigest384V1) -> Option<Vec<u64>> {
    let index = u64::try_from(index).ok()?;
    let index = (u128::from(index) % MOD_P) as u64;
    let limbs = public_digest.words();
    let width = u64::try_from(stark_air_trace_width()).ok()?;
    Some(vec![
        index, limbs[0], limbs[1], limbs[2], limbs[3], limbs[4], limbs[5], width,
    ])
}
fn stark_air_trace_leaf_hash(
    params: &StarkFriParamsV1,
    row: &[u64],
    index: usize,
) -> Option<GoldilocksDigest384V1> {
    if row
        .iter()
        .copied()
        .any(|value| Fq::from_canonical_u64(value).is_none())
    {
        return None;
    }
    let row_len = u64::try_from(row.len()).ok()?;
    let index = u64::try_from(index).ok()?;
    let mut row_bytes = Vec::with_capacity(row.len().checked_mul(8)?);
    for value in row {
        row_bytes.extend_from_slice(&value.to_le_bytes());
    }
    stark_digest_v1(
        params,
        StarkMerkleTreeRoleV1::AirTrace.domain_tag(),
        b"row-leaf",
        0,
        index,
        0,
        &[&row_len.to_le_bytes(), &row_bytes],
    )
}
fn stark_binding_air_trace_root(
    params: &StarkFriParamsV1,
    public_digest: &GoldilocksDigest384V1,
    domain_size: usize,
) -> Option<GoldilocksDigest384V1> {
    if params.n_log2 == 0 || params.n_log2 > MAX_BINDING_AIR_DOMAIN_LOG2 {
        return None;
    }
    let expected_domain = 1_usize.checked_shl(u32::from(params.n_log2))?;
    if domain_size != expected_domain {
        return None;
    }
    let depth = usize::from(params.n_log2);
    let mut frontier = vec![None; depth + 1];
    for index in 0..domain_size {
        let row = stark_air_row(index, public_digest)?;
        let mut accumulated = stark_air_trace_leaf_hash(params, &row, index)?;
        let mut level = 0_usize;
        loop {
            let slot = frontier.get_mut(level)?;
            let Some(left) = slot.take() else {
                *slot = Some(accumulated);
                break;
            };
            let merkle_depth = level.checked_add(1)?;
            let parent_index = index.checked_shr(u32::try_from(merkle_depth).ok()?)?;
            accumulated = merkle_node_hash(
                params,
                StarkMerkleDomainV1::air_trace(),
                merkle_depth,
                parent_index,
                &left,
                &accumulated,
            )?;
            level = level.checked_add(1)?;
        }
    }
    let root = frontier.get_mut(depth)?.take()?;
    if frontier.iter().any(Option::is_some) {
        return None;
    }
    Some(root)
}
fn stark_air_composition_value(
    index: usize,
    domain_size: usize,
    public_digest: &GoldilocksDigest384V1,
    row: &[u64],
    next_row: &[u64],
) -> Option<Fq> {
    let width = stark_air_trace_width();
    if domain_size == 0 || row.len() != width || next_row.len() != width {
        return None;
    }
    let expected = stark_air_row(index, public_digest)?;
    let expected_next = stark_air_row((index + 1) % domain_size, public_digest)?;
    // Check each transcript-sampled row and its neighbour against the verifier-owned binding AIR.
    // The Binding context separately reconstructs the complete deterministic trace commitment, so
    // these opened rows also authenticate the exact committed root used by the transcript.
    if row != expected.as_slice() || next_row != expected_next.as_slice() {
        return None;
    }
    Some(Fq::zero())
}
fn stark_air_composition_value_for_context(
    params: &StarkFriParamsV1,
    context: StarkAirVerificationContext<'_>,
    index: usize,
    domain_size: usize,
    public_digest: &GoldilocksDigest384V1,
    row: &[u64],
    next_row: &[u64],
) -> Option<Fq> {
    match context {
        StarkAirVerificationContext::Binding => {
            stark_air_composition_value(index, domain_size, public_digest, row, next_row)
        }
        StarkAirVerificationContext::BfvFullBootstrapPublicPadding {
            statement_hash,
            trace_material_digest,
            slot_index,
            bound_mode,
        } => {
            if !bfv_full_bootstrap_public_padding_inputs_are_admissible(
                *statement_hash,
                *trace_material_digest,
                slot_index,
                bound_mode,
            ) {
                return None;
            }
            let statement_bytes: [u8; iroha_crypto::Hash::LENGTH] = (*statement_hash).into();
            if stark_public_digest_v1(
                params,
                iroha_crypto::BFV_FULL_BOOTSTRAP_CIRCUIT_ID_V1,
                &statement_bytes,
            ) != Some(*public_digest)
            {
                return None;
            }
            let opening_index = u32::try_from(index).ok()?;
            iroha_crypto::validate_bfv_full_bootstrap_arithmetic_trace_public_padding_opening_v1(
                opening_index,
                row,
                next_row,
                *statement_hash,
                slot_index,
                bound_mode,
            )
            .ok()?;
            Some(Fq::zero())
        }
        StarkAirVerificationContext::Explicit(explicit) => {
            if domain_size == 0
                || explicit.public_digest != public_digest
                || explicit.rows.len() != domain_size
                || explicit.composition_values.len() != domain_size
                || index >= domain_size
            {
                return None;
            }
            if row != explicit.rows.get(index)?
                || next_row != explicit.rows.get((index + 1) % domain_size)?
            {
                return None;
            }
            Fq::from_canonical_u64(*explicit.composition_values.get(index)?)
        }
    }
}
fn stark_binding_air_commitments_match_statement(
    params: &StarkFriParamsV1,
    air: &StarkAirProofV1,
    total_domain: usize,
) -> bool {
    params.n_log2 <= MAX_BINDING_AIR_DOMAIN_LOG2
        && stark_binding_air_trace_root(params, &air.public_digest, total_domain)
            == Some(air.trace_root)
        && stark_constant_field_merkle_root_v1(params, Fq::zero(), total_domain)
            == Some(air.composition_root)
}
fn stark_air_context_matches_statement(
    params: &StarkFriParamsV1,
    air: &StarkAirProofV1,
    total_domain: usize,
    context: StarkAirVerificationContext<'_>,
) -> bool {
    match context {
        StarkAirVerificationContext::Binding => {
            stark_air_circuit_id_uses_generic_binding(&air.circuit_id)
                && stark_binding_air_commitments_match_statement(params, air, total_domain)
        }
        StarkAirVerificationContext::BfvFullBootstrapPublicPadding {
            statement_hash,
            trace_material_digest,
            slot_index,
            bound_mode,
        } => {
            let expected_params = bfv_full_bootstrap_stark_air_params_v1(*statement_hash);
            let statement_bytes: [u8; iroha_crypto::Hash::LENGTH] = (*statement_hash).into();
            bfv_full_bootstrap_public_padding_inputs_are_admissible(
                *statement_hash,
                *trace_material_digest,
                slot_index,
                bound_mode,
            ) && bfv_full_bootstrap_stark_air_params_match_v1(params, &expected_params)
                && air.circuit_id == iroha_crypto::BFV_FULL_BOOTSTRAP_CIRCUIT_ID_V1
                && stark_public_digest_v1(
                    params,
                    iroha_crypto::BFV_FULL_BOOTSTRAP_CIRCUIT_ID_V1,
                    &statement_bytes,
                ) == Some(air.public_digest)
        }
        StarkAirVerificationContext::Explicit(explicit) => {
            if air.circuit_id != explicit.circuit_id
                || *explicit.public_digest != air.public_digest
                || explicit.rows.len() != total_domain
                || explicit.composition_values.len() != total_domain
            {
                return false;
            }
            let Some(trace_width) = explicit.rows.first().map(Vec::len) else {
                return false;
            };
            if trace_width == 0 || trace_width != usize::from(air.trace_width) {
                return false;
            }
            if explicit.rows.iter().any(|row| row.len() != trace_width) {
                return false;
            }
            let Some(trace_root) = stark_air_trace_root_from_rows_v1(params, explicit.rows) else {
                return false;
            };
            if air.trace_root != trace_root {
                return false;
            }
            let Some(composition_root) =
                stark_merkle_root_from_field_values_v1(params, explicit.composition_values)
            else {
                return false;
            };
            air.composition_root == composition_root
        }
    }
}
fn bfv_full_bootstrap_statement_hash_is_admissible(
    statement_hash: iroha_crypto::Hash,
    slot_index: u32,
    bound_mode: iroha_crypto::BfvFullBootstrapExecutionProofBoundModeV1,
) -> bool {
    iroha_crypto::bfv_full_bootstrap_arithmetic_trace_public_padding_row_v1(
        u32::from(iroha_crypto::BFV_FULL_BOOTSTRAP_ARITHMETIC_TRACE_PRIVATE_ROW_COUNT_V1),
        statement_hash,
        slot_index,
        bound_mode,
    )
    .is_ok()
}
fn bfv_full_bootstrap_public_padding_inputs_are_admissible(
    statement_hash: iroha_crypto::Hash,
    trace_material_digest: iroha_crypto::Hash,
    slot_index: u32,
    bound_mode: iroha_crypto::BfvFullBootstrapExecutionProofBoundModeV1,
) -> bool {
    bfv_full_bootstrap_statement_hash_is_admissible(statement_hash, slot_index, bound_mode)
        && iroha_crypto::bfv_full_bootstrap_arithmetic_trace_canonical_opening_indices_from_transcript_v1(
            statement_hash,
            trace_material_digest,
        )
        .is_ok()
}
fn bfv_full_bootstrap_expected_base_indices_v1(
    statement_hash: iroha_crypto::Hash,
    trace_material_digest: iroha_crypto::Hash,
    query_count: usize,
    total_domain: usize,
) -> Result<Vec<usize>, &'static str> {
    let indices =
        iroha_crypto::bfv_full_bootstrap_arithmetic_trace_canonical_opening_indices_from_transcript_v1(
            statement_hash,
            trace_material_digest,
        )
        .map_err(|_| "BFV full-bootstrap opening transcript derivation failed")?;
    if indices.len() != query_count {
        return Err("BFV full-bootstrap opening schedule count mismatch");
    }
    let mut seen_indices = BTreeSet::new();
    indices
        .into_iter()
        .map(|index| {
            let index = usize::try_from(index)
                .map_err(|_| "BFV full-bootstrap opening index exceeds usize")?;
            if index >= total_domain {
                return Err("BFV full-bootstrap opening index exceeds STARK domain");
            }
            if !seen_indices.insert(index) {
                return Err(STARK_FRI_QUERY_INDEX_REPEATED_ERROR);
            }
            Ok(index)
        })
        .collect()
}
fn stark_air_public_statement_commitment_v1(
    params: &StarkFriParamsV1,
    circuit_id: &str,
    trace_width: u16,
    public_digest: &GoldilocksDigest384V1,
) -> Option<GoldilocksDigest384V1> {
    let trace_width = trace_width.to_le_bytes();
    stark_digest_v1(
        params,
        b"transcript",
        b"public-statement",
        0,
        0,
        0,
        &[circuit_id.as_bytes(), &trace_width, public_digest.as_ref()],
    )
}
fn stark_air_query_roots(
    params: &StarkFriParamsV1,
    roots: &[GoldilocksDigest384V1],
    air: Option<&StarkAirProofV1>,
) -> Option<Vec<GoldilocksDigest384V1>> {
    let mut query_roots = roots.to_vec();
    if let Some(air) = air {
        query_roots.push(air.trace_root);
        query_roots.push(air.composition_root);
        query_roots.push(stark_air_public_statement_commitment_v1(
            params,
            &air.circuit_id,
            air.trace_width,
            &air.public_digest,
        )?);
    }
    Some(query_roots)
}
fn bfv_full_bootstrap_stark_air_params_v1(statement_hash: iroha_crypto::Hash) -> StarkFriParamsV1 {
    StarkFriParamsV1 {
        version: 1,
        n_log2: iroha_crypto::BFV_FULL_BOOTSTRAP_NATIVE_STARK_FRI_N_LOG2_V1,
        blowup_log2: iroha_crypto::BFV_FULL_BOOTSTRAP_NATIVE_STARK_FRI_BLOWUP_LOG2_V1,
        fold_arity: iroha_crypto::BFV_FULL_BOOTSTRAP_NATIVE_STARK_FRI_FOLD_ARITY_V1,
        queries: iroha_crypto::BFV_FULL_BOOTSTRAP_NATIVE_STARK_FRI_QUERIES_V1,
        merkle_arity: iroha_crypto::BFV_FULL_BOOTSTRAP_NATIVE_STARK_FRI_MERKLE_ARITY_V1,
        domain_tag: iroha_crypto::bfv_full_bootstrap_native_stark_air_domain_tag_v1(statement_hash),
    }
}

/// Derive the typed six-lane public digest for one BFV full-bootstrap STARK statement.
#[doc(hidden)]
pub fn bfv_full_bootstrap_stark_public_digest_v1(
    params: &StarkFriParamsV1,
    statement_hash: iroha_crypto::Hash,
) -> Option<GoldilocksDigest384V1> {
    let statement_bytes: [u8; iroha_crypto::Hash::LENGTH] = statement_hash.into();
    stark_public_digest_v1(
        params,
        iroha_crypto::BFV_FULL_BOOTSTRAP_CIRCUIT_ID_V1,
        &statement_bytes,
    )
}
fn bfv_full_bootstrap_stark_air_params_match_v1(
    actual: &StarkFriParamsV1,
    expected: &StarkFriParamsV1,
) -> bool {
    actual.version == expected.version
        && actual.n_log2 == expected.n_log2
        && actual.blowup_log2 == expected.blowup_log2
        && actual.fold_arity == expected.fold_arity
        && actual.queries == expected.queries
        && actual.merkle_arity == expected.merkle_arity
        && actual.domain_tag == expected.domain_tag
}
#[cfg(any(test, feature = "test-utils"))]
fn bfv_full_bootstrap_stark_air_transcript_label_v1(attempt: u32) -> String {
    if attempt == 0 {
        return iroha_crypto::BFV_FULL_BOOTSTRAP_NATIVE_STARK_AIR_TRANSCRIPT_LABEL_V1.to_owned();
    }
    format!(
        "{}:{attempt}",
        iroha_crypto::BFV_FULL_BOOTSTRAP_NATIVE_STARK_AIR_TRANSCRIPT_LABEL_V1
    )
}
fn bfv_full_bootstrap_stark_air_transcript_label_allowed_v1(label: &str) -> bool {
    label == iroha_crypto::BFV_FULL_BOOTSTRAP_NATIVE_STARK_AIR_TRANSCRIPT_LABEL_V1
}
fn validate_generic_binding_air_domain(params: &StarkFriParamsV1) -> Result<(), String> {
    if params.n_log2 > MAX_BINDING_AIR_DOMAIN_LOG2 {
        return Err(format!(
            "generic Binding AIR n_log2 {} exceeds exact trace-root reconstruction limit {}",
            params.n_log2, MAX_BINDING_AIR_DOMAIN_LOG2
        ));
    }
    Ok(())
}
fn validate_stark_prover_params(
    params: &StarkFriParamsV1,
    transcript_label: &str,
) -> Result<usize, String> {
    if params.version != 1 {
        return Err("unsupported STARK params version".to_owned());
    }
    if params.n_log2 == 0 || params.n_log2 > MAX_DOMAIN_LOG2 {
        return Err("unsupported STARK domain size".to_owned());
    }
    if params.blowup_log2 == 0
        || params.blowup_log2 > MAX_DOMAIN_LOG2
        || params.blowup_log2 > params.n_log2
    {
        return Err("unsupported STARK blowup factor".to_owned());
    }
    if params.fold_arity != 2 {
        return Err("unsupported STARK fold_arity (expected 2)".to_owned());
    }
    if params.merkle_arity != 2 {
        return Err("unsupported STARK merkle_arity (expected 2)".to_owned());
    }
    validate_stark_domain_tag(&params.domain_tag, MAX_DOMAIN_TAG_LEN)
        .map_err(|err| format!("invalid STARK domain tag: {err}"))?;
    let query_count = params.queries as usize;
    if query_count == 0 || query_count > MAX_FRI_QUERIES {
        return Err("invalid STARK query count".to_owned());
    }
    validate_stark_transcript_label(transcript_label, MAX_TRANSCRIPT_LABEL_LEN)
        .map_err(str::to_owned)?;
    let n_log2 = params.n_log2 as usize;
    if n_log2 > MAX_MERKLE_DEPTH {
        return Err("STARK domain depth exceeds verifier limits".to_owned());
    }
    let domain = 1usize
        .checked_shl(u32::from(params.n_log2))
        .ok_or_else(|| "STARK domain size overflow".to_owned())?;
    if query_count > domain {
        return Err("STARK query count exceeds domain size".to_owned());
    }
    layers_required(params).ok_or_else(|| "invalid STARK folding parameters".to_owned())
}
fn fri_round_challenge(
    params: &StarkFriParamsV1,
    transcript_label: &str,
    round: usize,
    root: &GoldilocksDigest384V1,
) -> Option<Fp4> {
    let round = u64::try_from(round).ok()?;
    let params_bytes = stark_params_transcript_bytes_v1(params)?;
    let digest = stark_digest_v1(
        params,
        b"transcript",
        b"fri-fold-challenge",
        round,
        0,
        0,
        &[transcript_label.as_bytes(), &params_bytes, root.as_ref()],
    )?;
    let words = digest.words();
    Some(Fp4([
        Fq::from_canonical_u64(words[0])?,
        Fq::from_canonical_u64(words[1])?,
        Fq::from_canonical_u64(words[2])?,
        Fq::from_canonical_u64(words[3])?,
    ]))
}
#[cfg(test)]
fn synthesize_stark_fri_envelope_from_values(
    params: StarkFriParamsV1,
    transcript_label: String,
    base_values: Vec<Fq>,
    extra_query_roots: &[GoldilocksDigest384V1],
) -> Result<StarkVerifyEnvelopeV1, String> {
    synthesize_stark_fri_envelope_from_values_with_base_indices(
        params,
        transcript_label,
        base_values,
        extra_query_roots,
        None,
    )
}
fn synthesize_stark_fri_envelope_from_values_with_base_indices(
    params: StarkFriParamsV1,
    transcript_label: String,
    base_values: Vec<Fq>,
    extra_query_roots: &[GoldilocksDigest384V1],
    base_indices: Option<&[usize]>,
) -> Result<StarkVerifyEnvelopeV1, String> {
    let required_layers = validate_stark_prover_params(&params, &transcript_label)?;
    let total_domain = 1usize
        .checked_shl(u32::from(params.n_log2))
        .ok_or_else(|| "STARK domain size overflow".to_owned())?;
    if base_values.len() != total_domain {
        return Err("STARK base evaluations do not match domain size".to_owned());
    }
    let fold_arity = params.fold_arity as usize;
    let mut layer_values: Vec<Vec<Fp4>> = Vec::with_capacity(required_layers + 1);
    let mut layer_merkle = Vec::with_capacity(required_layers + 1);
    let mut roots = Vec::with_capacity(required_layers + 1);
    layer_values.push(base_values.into_iter().map(Fp4::from_base).collect());
    for round in 0..required_layers {
        let current = layer_values
            .get(round)
            .ok_or_else(|| "missing STARK FRI layer".to_owned())?;
        let fri_domain = StarkMerkleDomainV1::fri_layer(round)
            .ok_or_else(|| "STARK FRI layer index overflow".to_owned())?;
        let levels = fri_merkle_levels_from_values(&params, current, fri_domain)
            .ok_or_else(|| "failed to build STARK FRI Merkle layer".to_owned())?;
        let root = merkle_root_from_levels(&levels)
            .ok_or_else(|| "failed to derive STARK FRI root".to_owned())?;
        let beta = fri_round_challenge(&params, &transcript_label, round, &root)
            .ok_or_else(|| "failed to derive STARK FRI challenge".to_owned())?;
        roots.push(root);
        layer_merkle.push(levels);
        let mut next = Vec::with_capacity(current.len() / fold_arity);
        for (pair_index, pair) in current.chunks_exact(fold_arity).enumerate() {
            let x = domain_x_for_pair(current.len(), pair_index)
                .ok_or_else(|| "failed to derive STARK FRI domain element".to_owned())?;
            let folded = fri_fold_pair(pair[0], pair[1], beta, x)
                .ok_or_else(|| "failed to fold STARK FRI pair".to_owned())?;
            next.push(folded);
        }
        layer_values.push(next);
    }
    let final_values = layer_values
        .last()
        .ok_or_else(|| "missing STARK final FRI layer".to_owned())?;
    if final_values.len() != 1 || final_values.first().copied() != Some(Fp4::zero()) {
        return Err("STARK final FRI value must be zero".to_owned());
    }
    let final_domain = StarkMerkleDomainV1::fri_layer(required_layers)
        .ok_or_else(|| "STARK final FRI layer index overflow".to_owned())?;
    let final_levels = fri_merkle_levels_from_values(&params, final_values, final_domain)
        .ok_or_else(|| "failed to build STARK final FRI Merkle layer".to_owned())?;
    let final_root = merkle_root_from_levels(&final_levels)
        .ok_or_else(|| "failed to derive STARK final FRI root".to_owned())?;
    roots.push(final_root);
    layer_merkle.push(final_levels);
    let mut query_roots = roots.clone();
    query_roots.extend_from_slice(extra_query_roots);
    let query_count = params.queries as usize;
    let query_indices = if let Some(base_indices) = base_indices {
        if base_indices.len() != query_count {
            return Err("STARK explicit query schedule count mismatch".to_owned());
        }
        if base_indices.iter().any(|&index| index >= total_domain) {
            return Err("STARK explicit query schedule index exceeds domain".to_owned());
        }
        let mut seen_indices = BTreeSet::new();
        if base_indices
            .iter()
            .copied()
            .any(|index| !seen_indices.insert(index))
        {
            return Err(STARK_FRI_QUERY_INDEX_REPEATED_ERROR.to_owned());
        }
        base_indices.to_vec()
    } else {
        derive_query_indices_without_replacement(
            &transcript_label,
            &params,
            &query_roots,
            query_count,
            total_domain,
        )
        .map_err(|err| format!("failed to derive STARK query schedule: {err}"))?
    };
    let mut queries = Vec::with_capacity(query_count);
    for mut idx_layer in query_indices {
        let mut chain = Vec::with_capacity(required_layers);
        for k in 0..required_layers {
            let j = idx_layer / 2;
            let y0_idx = j
                .checked_mul(2)
                .ok_or_else(|| "query index overflow".to_owned())?;
            let y1_idx = y0_idx
                .checked_add(1)
                .ok_or_else(|| "query index overflow".to_owned())?;
            let path_y0 = merkle_path_from_levels(y0_idx, &layer_merkle[k])
                .ok_or_else(|| "failed to build y0 path".to_owned())?;
            let path_y1 = merkle_path_from_levels(y1_idx, &layer_merkle[k])
                .ok_or_else(|| "failed to build y1 path".to_owned())?;
            let path_z = merkle_path_from_levels(j, &layer_merkle[k + 1])
                .ok_or_else(|| "failed to build z path".to_owned())?;
            let j_u32 = u32::try_from(j).map_err(|_| "query index does not fit u32".to_owned())?;
            let y0 = layer_values
                .get(k)
                .and_then(|values| values.get(y0_idx))
                .copied()
                .ok_or_else(|| "query y0 is out of range".to_owned())?;
            let y1 = layer_values
                .get(k)
                .and_then(|values| values.get(y1_idx))
                .copied()
                .ok_or_else(|| "query y1 is out of range".to_owned())?;
            let z = layer_values
                .get(k + 1)
                .and_then(|values| values.get(j))
                .copied()
                .ok_or_else(|| "query z is out of range".to_owned())?;
            chain.push(FoldDecommitV1 {
                j: j_u32,
                y0: y0.to_wire(),
                y1: y1.to_wire(),
                path_y0,
                path_y1,
                z: z.to_wire(),
                path_z,
            });
            idx_layer = j;
        }
        if idx_layer != 0 {
            return Err("final query index must collapse to zero".to_owned());
        }
        queries.push(chain);
    }
    let envelope = StarkVerifyEnvelopeV1 {
        params,
        proof: StarkProofV1 {
            version: 1,
            commits: StarkCommitmentsV1 {
                version: 1,
                roots,
                comp_root: None,
            },
            queries,
            comp_values: None,
            air: None,
        },
        transcript_label,
    };
    Ok(envelope)
}
/// Build a deterministic STARK FRI proof envelope that passes native verification.
///
/// The generated witness uses all-zero layer evaluations and deterministic Merkle openings for
/// transcript-derived query indices. This keeps proving deterministic and avoids trusted setup.
///
/// Returns Norito-encoded [`StarkVerifyEnvelopeV1`] bytes.
#[cfg(test)]
fn synthesize_stark_fri_envelope_bytes(
    params: StarkFriParamsV1,
    transcript_label: String,
) -> Result<Vec<u8>, String> {
    let domain = 1usize
        .checked_shl(u32::from(params.n_log2))
        .ok_or_else(|| "STARK domain size overflow".to_owned())?;
    let values = vec![Fq::zero(); domain];
    let envelope =
        synthesize_stark_fri_envelope_from_values(params, transcript_label, values, &[])?;
    norito::to_bytes(&envelope).map_err(|err| format!("failed to encode STARK envelope: {err}"))
}
fn validate_stark_composition_terms(
    constant: u64,
    z_coeff: u64,
    aux_terms: &[StarkCompositionTermV1],
) -> Result<(), String> {
    if aux_terms.len() > MAX_AUX_TERMS {
        return Err("too many STARK composition auxiliary terms".to_owned());
    }
    if Fq::from_canonical_u64(constant).is_none() {
        return Err("invalid STARK constant".to_owned());
    }
    if Fq::from_canonical_u64(z_coeff).is_none() {
        return Err("invalid STARK z coefficient".to_owned());
    }
    let mut last_wire = None;
    for term in aux_terms {
        if Fq::from_canonical_u64(term.value).is_none()
            || Fq::from_canonical_u64(term.coeff).is_none()
        {
            return Err("invalid STARK composition auxiliary field element".to_owned());
        }
        if let Some(prev) = last_wire
            && term.wire_index <= prev
        {
            return Err("STARK composition auxiliary wires must be strictly ordered".to_owned());
        }
        last_wire = Some(term.wire_index);
    }
    Ok(())
}
/// Build the canonical six-lane V1 public AIR digest for composition terms.
pub fn stark_air_public_digest_from_composition(
    constant: u64,
    z_coeff: u64,
    aux_terms: &[StarkCompositionTermV1],
) -> Result<GoldilocksDigest384V1, String> {
    validate_stark_composition_terms(constant, z_coeff, aux_terms)?;
    let term_count = u64::try_from(aux_terms.len())
        .map_err(|_| "STARK composition term count does not fit u64".to_owned())?;
    let mut term_bytes = Vec::with_capacity(aux_terms.len().saturating_mul(20));
    for term in aux_terms {
        term_bytes.extend_from_slice(&term.wire_index.to_le_bytes());
        term_bytes.extend_from_slice(&term.value.to_le_bytes());
        term_bytes.extend_from_slice(&term.coeff.to_le_bytes());
    }
    let catalog = stark_catalog_commitment_bytes_v1();
    hash_bytes_384_v1(
        GoldilocksDigestDomainV1 {
            catalog: &catalog,
            protocol: b"iroha-native-stark-air-v1",
            profile: STARK_FRI_PROFILE_ID_V1.as_bytes(),
            role: b"public-statement",
            phase: b"composition",
            level: 0,
            index: 0,
            counter: 0,
        },
        &[
            &constant.to_le_bytes(),
            &z_coeff.to_le_bytes(),
            &term_count.to_le_bytes(),
            &term_bytes,
        ],
    )
    .map(Into::into)
    .ok_or_else(|| "failed to derive six-lane STARK AIR public digest".to_owned())
}
/// Build a V1 STARK/FRI AIR envelope from caller-validated rows and composition values.
///
/// Domain-specific AIR callers remain responsible for proving that the supplied rows and
/// composition evaluations are the result of their arithmetic constraint system. This helper commits
/// those already-evaluated vectors and emits transcript-derived AIR openings bound to the same FRI
/// query roots replayed by the verifier.
#[cfg(test)]
pub(crate) fn prove_stark_fri_air_envelope_from_rows_and_composition_values_bytes(
    params: StarkFriParamsV1,
    transcript_label: String,
    circuit_id: String,
    public_digest: GoldilocksDigest384V1,
    rows: Vec<Vec<u64>>,
    composition_values: Vec<u64>,
) -> Result<Vec<u8>, String> {
    validate_generic_stark_air_circuit_id(&circuit_id)?;
    prove_stark_fri_air_envelope_from_rows_and_composition_values_bytes_for_validated_circuit(
        params,
        transcript_label,
        circuit_id,
        public_digest,
        rows,
        composition_values,
        None,
    )
}
#[cfg(test)]
pub(crate) fn prove_stark_fri_air_envelope_from_rows_and_composition_values_with_base_indices_bytes(
    params: StarkFriParamsV1,
    transcript_label: String,
    circuit_id: String,
    public_digest: GoldilocksDigest384V1,
    rows: Vec<Vec<u64>>,
    composition_values: Vec<u64>,
    base_indices: &[usize],
) -> Result<Vec<u8>, String> {
    validate_generic_stark_air_circuit_id(&circuit_id)?;
    prove_stark_fri_air_envelope_from_rows_and_composition_values_bytes_for_validated_circuit(
        params,
        transcript_label,
        circuit_id,
        public_digest,
        rows,
        composition_values,
        Some(base_indices),
    )
}
#[cfg(any(test, feature = "test-utils"))]
/// Build a reserved-circuit AIR envelope with an explicit query schedule.
#[doc(hidden)]
pub fn prove_stark_fri_reserved_air_envelope_from_rows_and_composition_values_with_base_indices_bytes(
    params: StarkFriParamsV1,
    transcript_label: String,
    circuit_id: String,
    public_digest: GoldilocksDigest384V1,
    rows: Vec<Vec<u64>>,
    composition_values: Vec<u64>,
    base_indices: &[usize],
) -> Result<Vec<u8>, String> {
    validate_stark_circuit_id(&circuit_id)
        .map_err(|err| format!("invalid STARK AIR circuit_id: {err}"))?;
    prove_stark_fri_air_envelope_from_rows_and_composition_values_bytes_for_validated_circuit(
        params,
        transcript_label,
        circuit_id,
        public_digest,
        rows,
        composition_values,
        Some(base_indices),
    )
}
fn prove_stark_fri_air_envelope_from_rows_and_composition_values_bytes_for_validated_circuit(
    params: StarkFriParamsV1,
    transcript_label: String,
    circuit_id: String,
    public_digest: GoldilocksDigest384V1,
    rows: Vec<Vec<u64>>,
    composition_values: Vec<u64>,
    base_indices: Option<&[usize]>,
) -> Result<Vec<u8>, String> {
    let composition_values = composition_values
        .into_iter()
        .map(|value| {
            Fq::from_canonical_u64(value).ok_or_else(|| {
                "STARK AIR composition contains non-canonical field element".to_owned()
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    prove_stark_fri_air_envelope_from_rows_and_composition_values_fq_bytes(
        params,
        transcript_label,
        circuit_id,
        public_digest,
        rows,
        composition_values,
        base_indices,
    )
}
fn prove_stark_fri_air_envelope_from_rows_and_composition_values_fq_bytes(
    params: StarkFriParamsV1,
    transcript_label: String,
    circuit_id: String,
    public_digest: GoldilocksDigest384V1,
    rows: Vec<Vec<u64>>,
    composition_values: Vec<Fq>,
    base_indices: Option<&[usize]>,
) -> Result<Vec<u8>, String> {
    validate_stark_circuit_id(&circuit_id)
        .map_err(|err| format!("invalid STARK AIR circuit_id: {err}"))?;
    validate_stark_prover_params(&params, &transcript_label)?;
    let domain = 1usize
        .checked_shl(u32::from(params.n_log2))
        .ok_or_else(|| "STARK domain size overflow".to_owned())?;
    if rows.len() != domain {
        return Err("STARK AIR row count does not match domain size".to_owned());
    }
    if composition_values.len() != domain {
        return Err("STARK AIR composition count does not match domain size".to_owned());
    }
    let trace_width = rows
        .first()
        .map(Vec::len)
        .ok_or_else(|| "STARK AIR rows must not be empty".to_owned())?;
    if trace_width == 0 || trace_width > MAX_AIR_WIDTH {
        return Err("invalid STARK AIR trace width".to_owned());
    }
    let trace_width = u16::try_from(trace_width)
        .map_err(|_| "STARK AIR trace width does not fit u16".to_owned())?;
    for row in &rows {
        if row.len() != usize::from(trace_width) {
            return Err("STARK AIR rows must have uniform width".to_owned());
        }
        if row
            .iter()
            .copied()
            .any(|value| Fq::from_canonical_u64(value).is_none())
        {
            return Err("STARK AIR row contains non-canonical field element".to_owned());
        }
    }
    let trace_leaves = rows
        .iter()
        .enumerate()
        .map(|(index, row)| {
            stark_air_trace_leaf_hash(&params, row, index)
                .ok_or_else(|| "failed to hash STARK AIR row".to_owned())
        })
        .collect::<Result<Vec<_>, _>>()?;
    let trace_levels =
        merkle_levels_from_hashes(&params, trace_leaves, StarkMerkleDomainV1::air_trace())
            .ok_or_else(|| "failed to build STARK AIR trace commitment".to_owned())?;
    let trace_root = merkle_root_from_levels(&trace_levels)
        .ok_or_else(|| "failed to derive STARK AIR trace root".to_owned())?;
    let composition_levels = merkle_levels_from_values(
        &params,
        &composition_values,
        StarkMerkleDomainV1::air_composition(),
    )
    .ok_or_else(|| "failed to build STARK AIR composition commitment".to_owned())?;
    let composition_root = merkle_root_from_levels(&composition_levels)
        .ok_or_else(|| "failed to derive STARK AIR composition root".to_owned())?;
    let statement_commitment =
        stark_air_public_statement_commitment_v1(&params, &circuit_id, trace_width, &public_digest)
            .ok_or_else(|| "failed to bind STARK AIR public statement".to_owned())?;
    let extra_query_roots = [trace_root, composition_root, statement_commitment];
    let mut envelope = synthesize_stark_fri_envelope_from_values_with_base_indices(
        params,
        transcript_label,
        composition_values.clone(),
        &extra_query_roots,
        base_indices,
    )?;
    let query_indices = if let Some(base_indices) = base_indices {
        validate_stark_fri_query_shape_for_base_indices_v1(
            &envelope.params,
            &envelope.transcript_label,
            &envelope.proof.commits.roots,
            &envelope.proof.queries,
            base_indices,
        )
    } else {
        validate_stark_fri_query_shape_and_indices_v1(
            &envelope.params,
            &envelope.transcript_label,
            &envelope.proof.commits.roots,
            &extra_query_roots,
            &envelope.proof.queries,
        )
    }
    .map_err(|err| format!("STARK AIR FRI query shape failed validation: {err}"))?;
    let mut openings = Vec::with_capacity(envelope.proof.queries.len());
    for index in query_indices {
        let next_index = (index + 1) % domain;
        let row_path = merkle_path_from_levels(index, &trace_levels)
            .ok_or_else(|| "failed to open STARK AIR row".to_owned())?;
        let next_row_path = merkle_path_from_levels(next_index, &trace_levels)
            .ok_or_else(|| "failed to open next STARK AIR row".to_owned())?;
        let composition_path = merkle_path_from_levels(index, &composition_levels)
            .ok_or_else(|| "failed to open STARK AIR composition".to_owned())?;
        let composition_value = composition_values
            .get(index)
            .copied()
            .ok_or_else(|| "STARK AIR composition index is out of range".to_owned())?;
        openings.push(StarkAirOpeningV1 {
            index: u32::try_from(index)
                .map_err(|_| "STARK AIR query index does not fit u32".to_owned())?,
            row: rows[index].clone(),
            next_row: rows[next_index].clone(),
            row_path,
            next_row_path,
            composition_value: composition_value.0,
            composition_path,
        });
    }
    let composition_values_u64 = composition_values
        .iter()
        .map(|value| value.0)
        .collect::<Vec<_>>();
    envelope.proof.air = Some(StarkAirProofV1 {
        version: 1,
        circuit_id: circuit_id.clone(),
        public_digest,
        trace_root,
        composition_root,
        trace_width,
        openings,
    });
    let bytes = ivm_abi::codec::encode_canonical_norito(&envelope)
        .map_err(|err| format!("failed to encode STARK envelope: {err}"))?;
    let mut limits = StarkVerifierLimits::default();
    limits.max_envelope_bytes = usize::MAX;
    let self_verified = if let Some(base_indices) = base_indices {
        verify_stark_fri_air_envelope_from_rows_and_composition_values_with_base_indices_with_limits(
            &bytes,
            &limits,
            &circuit_id,
            &public_digest,
            &rows,
            &composition_values_u64,
            base_indices,
        )
    } else {
        verify_stark_fri_air_envelope_from_rows_and_composition_values_with_limits(
            &bytes,
            &limits,
            &circuit_id,
            &public_digest,
            &rows,
            &composition_values_u64,
        )
    };
    if !self_verified {
        return Err("STARK AIR envelope self-verification failed".to_owned());
    }
    Ok(bytes)
}
/// Build a deterministic V1 STARK/FRI envelope with an explicit verifier-owned AIR section.
pub fn prove_stark_fri_air_envelope_bytes(
    params: StarkFriParamsV1,
    transcript_label: String,
    circuit_id: String,
    public_digest: GoldilocksDigest384V1,
) -> Result<Vec<u8>, String> {
    validate_generic_stark_air_circuit_id(&circuit_id)?;
    validate_generic_binding_air_domain(&params)?;
    prove_stark_fri_air_envelope_bytes_for_validated_circuit(
        params,
        transcript_label,
        circuit_id,
        public_digest,
    )
}
/// Build a test-only AIR envelope for reserved circuits to exercise rejection.
#[cfg(any(test, feature = "test-utils"))]
#[doc(hidden)]
pub fn prove_stark_fri_reserved_air_envelope_bytes(
    params: StarkFriParamsV1,
    transcript_label: String,
    circuit_id: String,
    public_digest: GoldilocksDigest384V1,
) -> Result<Vec<u8>, String> {
    validate_stark_circuit_id(&circuit_id)
        .map_err(|err| format!("invalid STARK AIR circuit_id: {err}"))?;
    prove_stark_fri_air_envelope_bytes_for_validated_circuit(
        params,
        transcript_label,
        circuit_id,
        public_digest,
    )
}
fn prove_stark_fri_air_envelope_bytes_for_validated_circuit(
    params: StarkFriParamsV1,
    transcript_label: String,
    circuit_id: String,
    public_digest: GoldilocksDigest384V1,
) -> Result<Vec<u8>, String> {
    validate_stark_prover_params(&params, &transcript_label)?;
    let domain = 1usize
        .checked_shl(u32::from(params.n_log2))
        .ok_or_else(|| "STARK domain size overflow".to_owned())?;
    let rows = (0..domain)
        .map(|index| {
            stark_air_row(index, &public_digest)
                .ok_or_else(|| "failed to build STARK AIR row".to_owned())
        })
        .collect::<Result<Vec<_>, _>>()?;
    let composition_values = (0..domain)
        .map(|index| {
            stark_air_composition_value(
                index,
                domain,
                &public_digest,
                &rows[index],
                &rows[(index + 1) % domain],
            )
            .ok_or_else(|| "failed to evaluate STARK AIR composition".to_owned())
        })
        .collect::<Result<Vec<_>, _>>()?;
    prove_stark_fri_air_envelope_from_rows_and_composition_values_bytes_for_validated_circuit(
        params,
        transcript_label,
        circuit_id,
        public_digest,
        rows,
        composition_values
            .into_iter()
            .map(|value| value.0)
            .collect::<Vec<_>>(),
        None,
    )
}
#[cfg(test)]
/// Build a V1 STARK/FRI AIR envelope from caller-validated rows and zero composition values.
///
/// This helper only constructs commitments and transcript-derived openings. Domain-specific AIR
/// callers remain responsible for proving that the supplied rows satisfy their arithmetic
/// constraints; this function records the already-zero composition vector used by those constraints.
/// Generic Binding proofs are capped by [`MAX_BINDING_AIR_DOMAIN_LOG2`] because verification
/// reconstructs their complete deterministic trace commitment.
pub fn prove_stark_fri_zero_composition_air_envelope_bytes(
    params: StarkFriParamsV1,
    transcript_label: String,
    circuit_id: String,
    public_digest: GoldilocksDigest384V1,
    rows: Vec<Vec<u64>>,
) -> Result<Vec<u8>, String> {
    validate_generic_stark_air_circuit_id(&circuit_id)?;
    validate_generic_binding_air_domain(&params)?;
    let domain = 1usize
        .checked_shl(u32::from(params.n_log2))
        .ok_or_else(|| "STARK domain size overflow".to_owned())?;
    let composition_values = vec![Fq::zero(); domain];
    prove_stark_fri_air_envelope_from_rows_and_composition_values_fq_bytes(
        params,
        transcript_label,
        circuit_id,
        public_digest,
        rows,
        composition_values,
        None,
    )
}
#[cfg(any(test, feature = "test-utils"))]
/// Build a canonical BFV full-bootstrap native STARK/FRI AIR proof envelope for Core internals.
///
/// The proof is synthesized from validated
/// [`iroha_crypto::BfvFullBootstrapExecutionProverInputMaterialV1`]. The wrapper binds the native
/// STARK domain tag to the BFV execution statement hash and uses the crypto-derived explicit
/// public-padding opening schedule. BFV execution AIR proofs are emitted under the canonical base
/// transcript label only, so equivalent suffixed-label proof bytes cannot become alternate
/// encodings of the same governed statement. Public native proof generation must use the Soracloud
/// release/audit-aware entry points, which validate caller-owned governed artifacts before reaching
/// this crate-scoped helper.
///
/// # Errors
///
/// Returns an error when the BFV prover input material is invalid, the STARK
/// envelope cannot be built, or no deterministic transcript label yields the
/// canonical duplicate-free public opening set.
#[doc(hidden)]
pub fn prove_stark_fri_bfv_full_bootstrap_air_envelope_bytes(
    material: &iroha_crypto::BfvFullBootstrapExecutionProverInputMaterialV1,
) -> Result<Vec<u8>, String> {
    iroha_crypto::validate_bfv_full_bootstrap_execution_prover_input_material_v1(material)
        .map_err(|err| format!("BFV full-bootstrap prover input material invalid: {err}"))?;
    let statement_hash = material.proof_input_material.statement_hash;
    let params = bfv_full_bootstrap_stark_air_params_v1(statement_hash);
    let statement_bytes: [u8; iroha_crypto::Hash::LENGTH] = statement_hash.into();
    let public_digest = stark_public_digest_v1(
        &params,
        iroha_crypto::BFV_FULL_BOOTSTRAP_CIRCUIT_ID_V1,
        &statement_bytes,
    )
    .ok_or_else(|| "failed to derive six-lane BFV STARK public digest".to_owned())?;
    let rows = material.arithmetic_trace_material.rows.clone();
    let composition_values = material
        .arithmetic_air_evaluation_material
        .composition_values
        .clone();
    let expected_base_indices = bfv_full_bootstrap_expected_base_indices_v1(
        statement_hash,
        material.arithmetic_trace_material_digest,
        usize::from(iroha_crypto::BFV_FULL_BOOTSTRAP_NATIVE_STARK_FRI_QUERIES_V1),
        1_usize
            .checked_shl(u32::from(params.n_log2))
            .ok_or_else(|| "BFV full-bootstrap STARK domain size overflow".to_owned())?,
    )
    .map_err(|err| format!("BFV full-bootstrap opening schedule invalid: {err}"))?;
    let bytes =
        prove_stark_fri_reserved_air_envelope_from_rows_and_composition_values_with_base_indices_bytes(
            params,
            bfv_full_bootstrap_stark_air_transcript_label_v1(0),
            iroha_crypto::BFV_FULL_BOOTSTRAP_CIRCUIT_ID_V1.to_owned(),
            public_digest,
            rows,
            composition_values,
            &expected_base_indices,
        )?;
    let mut limits = StarkVerifierLimits::default();
    limits.max_envelope_bytes = usize::MAX;
    if verify_stark_fri_bfv_full_bootstrap_air_envelope_with_limits(&bytes, &limits, material) {
        Ok(bytes)
    } else {
        Err(
            "BFV full-bootstrap STARK/FRI envelope failed transcript-bound self-verification"
                .to_owned(),
        )
    }
}
#[cfg(test)]
/// Verify a canonical BFV full-bootstrap native STARK/FRI AIR proof envelope.
///
/// This is the default-limit companion to
/// [`verify_stark_fri_bfv_full_bootstrap_air_envelope_with_limits`]. The supplied
/// full material is self-contained; callers with governed artifacts should use
/// [`verify_stark_fri_bfv_full_bootstrap_air_envelope_for_artifacts_with_limits`]
/// to replay its arithmetic source.
#[must_use]
pub fn verify_stark_fri_bfv_full_bootstrap_air_envelope(
    bytes: &[u8],
    material: &iroha_crypto::BfvFullBootstrapExecutionProverInputMaterialV1,
) -> bool {
    verify_stark_fri_bfv_full_bootstrap_air_envelope_with_limits(
        bytes,
        &StarkVerifierLimits::default(),
        material,
    )
}
#[cfg(test)]
/// Reject a BFV full-bootstrap proof when only public-padding data is available.
///
/// The V1 proof does not separately establish low degree for the hidden trace columns. Sampled
/// public-padding rows therefore cannot authenticate the unobserved private trace. Callers must
/// use [`verify_stark_fri_bfv_full_bootstrap_air_envelope`] with the governed full trace material.
#[must_use]
pub fn verify_stark_fri_bfv_full_bootstrap_air_public_padding_envelope(
    bytes: &[u8],
    statement_hash: iroha_crypto::Hash,
    trace_material_digest: iroha_crypto::Hash,
    slot_index: u32,
    bound_mode: iroha_crypto::BfvFullBootstrapExecutionProofBoundModeV1,
) -> bool {
    verify_stark_fri_bfv_full_bootstrap_air_public_padding_envelope_with_limits(
        bytes,
        &StarkVerifierLimits::default(),
        statement_hash,
        trace_material_digest,
        slot_index,
        bound_mode,
    )
}
#[cfg(test)]
/// Reject a BFV full-bootstrap proof when only public-padding data is available, with limits.
///
/// Resource limits do not repair the missing hidden-trace low-degree argument, so this entrypoint
/// intentionally fails closed. Full-material verification uses a private structural precheck and
/// then reconstructs the verifier-owned trace and composition commitments exactly.
#[must_use]
pub fn verify_stark_fri_bfv_full_bootstrap_air_public_padding_envelope_with_limits(
    bytes: &[u8],
    limits: &StarkVerifierLimits,
    statement_hash: iroha_crypto::Hash,
    trace_material_digest: iroha_crypto::Hash,
    slot_index: u32,
    bound_mode: iroha_crypto::BfvFullBootstrapExecutionProofBoundModeV1,
) -> bool {
    // TODO: Re-enable public-only verification after V1 proves low degree for every hidden trace
    // column and binds those columns to the sampled AIR composition evaluations.
    let _ = (
        bytes,
        limits,
        statement_hash,
        trace_material_digest,
        slot_index,
        bound_mode,
    );
    false
}
/// Check the public-padding structure before a caller performs exact full-material replay.
#[doc(hidden)]
pub fn verify_stark_fri_bfv_full_bootstrap_air_public_padding_structure_with_limits(
    bytes: &[u8],
    limits: &StarkVerifierLimits,
    statement_hash: iroha_crypto::Hash,
    trace_material_digest: iroha_crypto::Hash,
    slot_index: u32,
    bound_mode: iroha_crypto::BfvFullBootstrapExecutionProofBoundModeV1,
) -> bool {
    if !bfv_full_bootstrap_public_padding_inputs_are_admissible(
        statement_hash,
        trace_material_digest,
        slot_index,
        bound_mode,
    ) {
        return false;
    }
    if !verify_stark_fri_envelope_with_context(
        bytes,
        limits,
        StarkAirVerificationContext::BfvFullBootstrapPublicPadding {
            statement_hash: &statement_hash,
            trace_material_digest: &trace_material_digest,
            slot_index,
            bound_mode,
        },
    ) {
        return false;
    }
    let env: StarkVerifyEnvelopeV1 = match norito::decode_from_bytes(bytes) {
        Ok(env) => env,
        Err(_) => return false,
    };
    if !bfv_full_bootstrap_stark_air_transcript_label_allowed_v1(&env.transcript_label) {
        return false;
    }
    let expected_params = bfv_full_bootstrap_stark_air_params_v1(statement_hash);
    if !bfv_full_bootstrap_stark_air_params_match_v1(&env.params, &expected_params) {
        return false;
    }
    let statement_bytes: [u8; iroha_crypto::Hash::LENGTH] = statement_hash.into();
    let Some(expected_public_digest) = stark_public_digest_v1(
        &env.params,
        iroha_crypto::BFV_FULL_BOOTSTRAP_CIRCUIT_ID_V1,
        &statement_bytes,
    ) else {
        return false;
    };
    let Some(air) = env.proof.air.as_ref() else {
        return false;
    };
    if air.circuit_id != iroha_crypto::BFV_FULL_BOOTSTRAP_CIRCUIT_ID_V1
        || air.public_digest != expected_public_digest
        || usize::from(air.trace_width)
            != usize::from(iroha_crypto::BFV_FULL_BOOTSTRAP_ARITHMETIC_TRACE_ROW_WIDTH_V1)
        || air.openings.len()
            != usize::from(iroha_crypto::BFV_FULL_BOOTSTRAP_NATIVE_STARK_FRI_QUERIES_V1)
    {
        return false;
    }
    let opening_indices = air
        .openings
        .iter()
        .map(|opening| opening.index)
        .collect::<Vec<_>>();
    let opened_rows = air
        .openings
        .iter()
        .map(|opening| opening.row.clone())
        .collect::<Vec<_>>();
    let opened_next_rows = air
        .openings
        .iter()
        .map(|opening| opening.next_row.clone())
        .collect::<Vec<_>>();
    if iroha_crypto::validate_bfv_full_bootstrap_arithmetic_trace_transcript_public_padding_openings_v1(
        &opening_indices,
        &opened_rows,
        &opened_next_rows,
        statement_hash,
        trace_material_digest,
        slot_index,
        bound_mode,
    )
    .is_err()
    {
        return false;
    }
    air.openings
        .iter()
        .all(|opening| opening.composition_value == 0)
}
fn bfv_full_bootstrap_air_openings_match_public_opening_material_v1(
    air: &StarkAirProofV1,
    material: &iroha_crypto::BfvFullBootstrapArithmeticTracePublicOpeningMaterialV1,
) -> bool {
    if air.openings.len() != material.opening_indices.len()
        || air.openings.len() != material.opened_rows.len()
        || air.openings.len() != material.opened_next_rows.len()
    {
        return false;
    }
    air.openings.iter().enumerate().all(|(position, opening)| {
        material.opening_indices.get(position) == Some(&opening.index)
            && material.opened_rows.get(position).map(Vec::as_slice) == Some(opening.row.as_slice())
            && material.opened_next_rows.get(position).map(Vec::as_slice)
                == Some(opening.next_row.as_slice())
    })
}
#[cfg(any(test, feature = "test-utils"))]
/// Verify a BFV full-bootstrap native proof against concrete governed artifacts.
///
/// The standalone full-material verifier checks the proof against the material it receives.
/// This wrapper first reconstructs that material from the caller's public key, bootstrap key,
/// artifact bundle, and Galois keys, including every coefficient of the execution trace.
#[must_use]
#[allow(clippy::too_many_arguments)]
#[doc(hidden)]
pub fn verify_stark_fri_bfv_full_bootstrap_air_envelope_for_artifacts_with_limits(
    bytes: &[u8],
    limits: &StarkVerifierLimits,
    params: &iroha_crypto::BfvParameters,
    public_key: &iroha_crypto::BfvPublicKey,
    bootstrap_key: &iroha_crypto::BfvBootstrapKey,
    artifacts: &iroha_crypto::BfvFullBootstrapCircuitArtifactBundleV1,
    galois_keys: &[iroha_crypto::BfvGaloisKey],
    material: &iroha_crypto::BfvFullBootstrapExecutionProverInputMaterialV1,
) -> bool {
    iroha_crypto::validate_bfv_full_bootstrap_execution_prover_input_material_for_public_key_and_artifacts_v1(
        params,
        public_key,
        bootstrap_key,
        artifacts,
        galois_keys,
        material,
    )
    .is_ok()
        && verify_stark_fri_bfv_full_bootstrap_air_envelope_with_limits(bytes, limits, material)
}
/// Verify a BFV full-bootstrap native STARK/FRI AIR proof envelope with limits.
///
/// Generic STARK verification is only the first stage. This BFV wrapper also requires the exact
/// first-release BFV STARK parameters, the statement-bound domain tag, the canonical BFV circuit
/// id, the statement hash as the public digest, the canonical opening count, sampled public-padding
/// rows that match the BFV statement header, and the typed public-opening material carried by the
/// execution prover-input package. This self-contained check does not replay external governed
/// artifacts; use [`verify_stark_fri_bfv_full_bootstrap_air_envelope_for_artifacts_with_limits`]
/// when those artifacts are the source of authority.
#[must_use]
pub fn verify_stark_fri_bfv_full_bootstrap_air_envelope_with_limits(
    bytes: &[u8],
    limits: &StarkVerifierLimits,
    material: &iroha_crypto::BfvFullBootstrapExecutionProverInputMaterialV1,
) -> bool {
    if iroha_crypto::validate_bfv_full_bootstrap_execution_prover_input_material_v1(material)
        .is_err()
    {
        return false;
    }
    let statement_hash = material.proof_input_material.statement_hash;
    let expected_params = bfv_full_bootstrap_stark_air_params_v1(statement_hash);
    let statement_bytes: [u8; iroha_crypto::Hash::LENGTH] = statement_hash.into();
    let Some(public_digest) = stark_public_digest_v1(
        &expected_params,
        iroha_crypto::BFV_FULL_BOOTSTRAP_CIRCUIT_ID_V1,
        &statement_bytes,
    ) else {
        return false;
    };
    let witness = &material.proof_input_material.witness_material;
    if !verify_stark_fri_bfv_full_bootstrap_air_public_padding_structure_with_limits(
        bytes,
        limits,
        statement_hash,
        material.arithmetic_trace_material_digest,
        witness.slot_index,
        witness.bound_mode,
    ) {
        return false;
    }
    let expected_base_indices = match bfv_full_bootstrap_expected_base_indices_v1(
        statement_hash,
        material.arithmetic_trace_material_digest,
        usize::from(iroha_crypto::BFV_FULL_BOOTSTRAP_NATIVE_STARK_FRI_QUERIES_V1),
        material.arithmetic_trace_material.rows.len(),
    ) {
        Ok(indices) => indices,
        Err(_) => return false,
    };
    if !verify_stark_fri_air_envelope_from_rows_and_composition_values_with_base_indices_with_limits(
        bytes,
        limits,
        iroha_crypto::BFV_FULL_BOOTSTRAP_CIRCUIT_ID_V1,
        &public_digest,
        &material.arithmetic_trace_material.rows,
        &material
            .arithmetic_air_evaluation_material
            .composition_values,
        &expected_base_indices,
    ) {
        return false;
    }
    let env: StarkVerifyEnvelopeV1 = match norito::decode_from_bytes(bytes) {
        Ok(env) => env,
        Err(_) => return false,
    };
    if !bfv_full_bootstrap_stark_air_transcript_label_allowed_v1(&env.transcript_label) {
        return false;
    }
    if !bfv_full_bootstrap_stark_air_params_match_v1(&env.params, &expected_params) {
        return false;
    }
    let Some(air) = env.proof.air.as_ref() else {
        return false;
    };
    if air.circuit_id != iroha_crypto::BFV_FULL_BOOTSTRAP_CIRCUIT_ID_V1
        || air.public_digest != public_digest
        || usize::from(air.trace_width)
            != usize::from(iroha_crypto::BFV_FULL_BOOTSTRAP_ARITHMETIC_TRACE_ROW_WIDTH_V1)
        || air.openings.len()
            != usize::from(iroha_crypto::BFV_FULL_BOOTSTRAP_NATIVE_STARK_FRI_QUERIES_V1)
    {
        return false;
    }
    if !bfv_full_bootstrap_air_openings_match_public_opening_material_v1(
        air,
        &material.public_opening_material,
    ) {
        return false;
    }
    let opening_indices = air
        .openings
        .iter()
        .map(|opening| opening.index)
        .collect::<Vec<_>>();
    let opened_rows = air
        .openings
        .iter()
        .map(|opening| opening.row.clone())
        .collect::<Vec<_>>();
    let opened_next_rows = air
        .openings
        .iter()
        .map(|opening| opening.next_row.clone())
        .collect::<Vec<_>>();
    iroha_crypto::validate_bfv_full_bootstrap_arithmetic_trace_transcript_public_padding_openings_v1(
        &opening_indices,
        &opened_rows,
        &opened_next_rows,
        statement_hash,
        material.arithmetic_trace_material_digest,
        witness.slot_index,
        witness.bound_mode,
    )
    .is_ok()
}
#[cfg(any(test, feature = "test-utils"))]
/// Build a deterministic V1 STARK/FRI envelope with verifier-owned composition terms.
pub fn prove_stark_fri_composition_envelope_bytes(
    params: StarkFriParamsV1,
    transcript_label: String,
    constant: u64,
    z_coeff: u64,
    aux_terms: Vec<StarkCompositionTermV1>,
) -> Result<Vec<u8>, String> {
    validate_stark_composition_terms(constant, z_coeff, &aux_terms)?;
    let constant_f =
        Fq::from_canonical_u64(constant).ok_or_else(|| "invalid STARK constant".to_owned())?;
    Fq::from_canonical_u64(z_coeff).ok_or_else(|| "invalid STARK z coefficient".to_owned())?;
    let public_digest = stark_air_public_digest_from_composition(constant, z_coeff, &aux_terms)?;
    let bytes = prove_stark_fri_air_envelope_bytes(
        params,
        transcript_label,
        "composition-v1".to_owned(),
        public_digest,
    )?;
    let mut envelope: StarkVerifyEnvelopeV1 = norito::decode_from_bytes(&bytes)
        .map_err(|err| format!("failed to decode STARK AIR envelope: {err}"))?;
    let z_final = envelope
        .proof
        .queries
        .first()
        .and_then(|chain| chain.last())
        .and_then(|decommit| Fp4::from_wire(decommit.z))
        .ok_or_else(|| "invalid STARK final folded value".to_owned())?;
    if z_final != Fp4::zero() {
        return Err("STARK terminal polynomial is not zero".to_owned());
    }
    let mut expected = constant_f;
    for term in &aux_terms {
        let coeff = Fq::from_canonical_u64(term.coeff)
            .ok_or_else(|| "invalid STARK composition coefficient".to_owned())?;
        let value = Fq::from_canonical_u64(term.value)
            .ok_or_else(|| "invalid STARK composition value".to_owned())?;
        expected = expected.add(coeff.mul(value));
    }
    let comp_levels = merkle_levels_from_values(
        &envelope.params,
        &[expected],
        StarkMerkleDomainV1::auxiliary_composition(),
    )
    .ok_or_else(|| "failed to build STARK composition commitment".to_owned())?;
    let comp_root = merkle_root_from_levels(&comp_levels)
        .ok_or_else(|| "failed to derive STARK composition root".to_owned())?;
    let comp_path = merkle_path_from_levels(0, &comp_levels)
        .ok_or_else(|| "failed to derive STARK composition path".to_owned())?;
    let comp_value = StarkCompositionValueV1 {
        leaf: expected.0,
        constant,
        z_coeff,
        aux_terms,
        path: comp_path,
    };
    let comp_values = vec![comp_value; envelope.proof.queries.len()];
    envelope.proof.commits.comp_root = Some(comp_root);
    envelope.proof.comp_values = Some(comp_values);
    ivm_abi::codec::encode_canonical_norito(&envelope)
        .map_err(|err| format!("failed to encode STARK envelope: {err}"))
}
fn verify_stark_air_opening(
    params: &StarkFriParamsV1,
    air: &StarkAirProofV1,
    opening: &StarkAirOpeningV1,
    base_index: usize,
    total_domain: usize,
    first_decommit: &FoldDecommitV1,
    limits: &StarkVerifierLimits,
    context: StarkAirVerificationContext<'_>,
) -> bool {
    if usize::try_from(opening.index).ok() != Some(base_index)
        || opening.row.len() != air.trace_width as usize
        || opening.next_row.len() != air.trace_width as usize
        || opening.row.len() > effective_max_air_width(limits)
        || opening.next_row.len() > effective_max_air_width(limits)
    {
        return false;
    }
    let depth = match log2_usize(total_domain) {
        Some(value) => value,
        None => return false,
    };
    if !merkle_path_depth_ok(&opening.row_path, depth, limits)
        || !merkle_path_depth_ok(&opening.next_row_path, depth, limits)
        || !merkle_path_depth_ok(&opening.composition_path, depth, limits)
    {
        return false;
    }
    let next_index = (base_index + 1) % total_domain;
    if merkle_path_index(&opening.row_path) != Some(base_index)
        || merkle_path_index(&opening.next_row_path) != Some(next_index)
        || merkle_path_index(&opening.composition_path) != Some(base_index)
    {
        return false;
    }
    let row_leaf = match stark_air_trace_leaf_hash(params, &opening.row, base_index) {
        Some(value) => value,
        None => return false,
    };
    if !merkle_verify_hash(
        params,
        StarkMerkleDomainV1::air_trace(),
        &air.trace_root,
        &row_leaf,
        &opening.row_path,
    ) {
        return false;
    }
    let next_row_leaf = match stark_air_trace_leaf_hash(params, &opening.next_row, next_index) {
        Some(value) => value,
        None => return false,
    };
    if !merkle_verify_hash(
        params,
        StarkMerkleDomainV1::air_trace(),
        &air.trace_root,
        &next_row_leaf,
        &opening.next_row_path,
    ) {
        return false;
    }
    let composition = match Fq::from_canonical_u64(opening.composition_value) {
        Some(value) => value,
        None => return false,
    };
    if !merkle_verify(
        params,
        StarkMerkleDomainV1::air_composition(),
        &air.composition_root,
        composition,
        &opening.composition_path,
    ) {
        return false;
    }
    let expected = match stark_air_composition_value_for_context(
        params,
        context,
        base_index,
        total_domain,
        &air.public_digest,
        &opening.row,
        &opening.next_row,
    ) {
        Some(value) => value,
        None => return false,
    };
    if expected != composition {
        return false;
    }
    let opened_fri_value = if base_index.is_multiple_of(2) {
        Fp4::from_wire(first_decommit.y0)
    } else {
        Fp4::from_wire(first_decommit.y1)
    };
    if opened_fri_value != Some(Fp4::from_base(composition)) {
        return false;
    }
    true
}
/// Verify a STARK FRI envelope under `zk-stark` with caller-provided limits.
pub fn verify_stark_fri_envelope_with_limits(bytes: &[u8], limits: &StarkVerifierLimits) -> bool {
    verify_stark_fri_envelope_with_context(bytes, limits, StarkAirVerificationContext::Binding)
}
/// Verify a STARK FRI AIR envelope against caller-provided trace rows and composition values.
#[cfg(test)]
pub(crate) fn verify_stark_fri_air_envelope_from_rows_and_composition_values(
    bytes: &[u8],
    circuit_id: &str,
    public_digest: &GoldilocksDigest384V1,
    rows: &[Vec<u64>],
    composition_values: &[u64],
) -> bool {
    verify_stark_fri_air_envelope_from_rows_and_composition_values_with_limits(
        bytes,
        &StarkVerifierLimits::default(),
        circuit_id,
        public_digest,
        rows,
        composition_values,
    )
}
/// Verify a STARK FRI AIR envelope against caller-provided trace rows and composition values.
pub(crate) fn verify_stark_fri_air_envelope_from_rows_and_composition_values_with_limits(
    bytes: &[u8],
    limits: &StarkVerifierLimits,
    circuit_id: &str,
    public_digest: &GoldilocksDigest384V1,
    rows: &[Vec<u64>],
    composition_values: &[u64],
) -> bool {
    let explicit = StarkAirExplicitVerificationContext {
        circuit_id,
        public_digest,
        rows,
        composition_values,
        base_indices: None,
    };
    verify_stark_fri_envelope_with_context(
        bytes,
        limits,
        StarkAirVerificationContext::Explicit(&explicit),
    )
}
#[doc(hidden)]
pub fn verify_stark_fri_air_envelope_from_rows_and_composition_values_with_base_indices_with_limits(
    bytes: &[u8],
    limits: &StarkVerifierLimits,
    circuit_id: &str,
    public_digest: &GoldilocksDigest384V1,
    rows: &[Vec<u64>],
    composition_values: &[u64],
    base_indices: &[usize],
) -> bool {
    let explicit = StarkAirExplicitVerificationContext {
        circuit_id,
        public_digest,
        rows,
        composition_values,
        base_indices: Some(base_indices),
    };
    verify_stark_fri_envelope_with_context(
        bytes,
        limits,
        StarkAirVerificationContext::Explicit(&explicit),
    )
}
fn verify_stark_fri_envelope_with_context(
    bytes: &[u8],
    limits: &StarkVerifierLimits,
    context: StarkAirVerificationContext<'_>,
) -> bool {
    if envelope_exceeds_limit(bytes.len(), limits) {
        return false;
    }
    // Decode the single canonical V1 representation.
    let env: StarkVerifyEnvelopeV1 = match ivm_abi::codec::decode_canonical_norito(bytes) {
        Ok(e) => e,
        Err(_) => return false,
    };
    if validate_stark_transcript_label(
        &env.transcript_label,
        effective_max_transcript_label_len(limits),
    )
    .is_err()
    {
        return false;
    }
    if env.proof.version != 1 || env.proof.commits.version != 1 {
        return false;
    }
    let roots = &env.proof.commits.roots;
    let query_count = env.proof.queries.len();
    let expected_chain_len = match validate_params(&env.params, roots.len(), query_count, limits) {
        Some(v) => v,
        None => return false,
    };
    if env.proof.commits.comp_root.is_some() != env.proof.comp_values.is_some() {
        return false;
    }
    if !context.allows_auxiliary_composition()
        && (env.proof.commits.comp_root.is_some() || env.proof.comp_values.is_some())
    {
        return false;
    }
    if let Some(values) = env.proof.comp_values.as_ref() {
        if values.len() != query_count {
            return false;
        }
    }
    let Some(air) = env.proof.air.as_ref() else {
        return false;
    };
    if air.version != 1
        || validate_stark_circuit_id(&air.circuit_id).is_err()
        || air.trace_width as usize != context.trace_width()
        || air.trace_width as usize > effective_max_air_width(limits)
        || air.openings.len() != query_count
    {
        return false;
    }
    let total_domain = match 1usize.checked_shl(u32::from(env.params.n_log2)) {
        Some(value) if value != 0 => value,
        _ => return false,
    };
    if !stark_air_context_matches_statement(&env.params, air, total_domain, context) {
        return false;
    }
    let Some(query_roots) = stark_air_query_roots(&env.params, roots, Some(air)) else {
        return false;
    };
    let fold_arity = env.params.fold_arity as usize;
    let sampled_base_indices = match context {
        StarkAirVerificationContext::BfvFullBootstrapPublicPadding {
            statement_hash,
            trace_material_digest,
            ..
        } => match bfv_full_bootstrap_expected_base_indices_v1(
            *statement_hash,
            *trace_material_digest,
            query_count,
            total_domain,
        ) {
            Ok(indices) => indices,
            Err(_) => return false,
        },
        StarkAirVerificationContext::Explicit(explicit) => {
            if let Some(base_indices) = explicit.base_indices {
                match validate_stark_fri_query_shape_for_base_indices_with_limits_v1(
                    &env.params,
                    &env.transcript_label,
                    roots,
                    &env.proof.queries,
                    base_indices,
                    limits,
                ) {
                    Ok(indices) => indices,
                    Err(_) => return false,
                }
            } else {
                match derive_query_indices_without_replacement(
                    &env.transcript_label,
                    &env.params,
                    &query_roots,
                    query_count,
                    total_domain,
                ) {
                    Ok(indices) => indices,
                    Err(_) => return false,
                }
            }
        }
        _ => match derive_query_indices_without_replacement(
            &env.transcript_label,
            &env.params,
            &query_roots,
            query_count,
            total_domain,
        ) {
            Ok(indices) => indices,
            Err(_) => return false,
        },
    };
    for (qi, (chain, base_index)) in env
        .proof
        .queries
        .iter()
        .zip(sampled_base_indices.iter().copied())
        .enumerate()
    {
        if chain.len() != expected_chain_len {
            return false;
        }
        let Some(opening) = air.openings.get(qi) else {
            return false;
        };
        let Some(first_decommit) = chain.first() else {
            return false;
        };
        if !verify_stark_air_opening(
            &env.params,
            air,
            opening,
            base_index,
            total_domain,
            first_decommit,
            limits,
            context,
        ) {
            return false;
        }
        let mut idx_layer = base_index;
        let mut layer_domain = total_domain;
        let mut last_z: Option<Fp4> = None;
        for (k, decommit) in chain.iter().enumerate() {
            if layer_domain < fold_arity {
                return false;
            }
            let expected_pairs = layer_domain / fold_arity;
            let expected_j = idx_layer / fold_arity;
            if expected_j >= expected_pairs || decommit.j as usize != expected_j {
                return false;
            }
            let depth_current = match log2_usize(layer_domain) {
                Some(v) => v,
                None => return false,
            };
            let depth_next = match log2_usize(layer_domain / fold_arity) {
                Some(v) => v,
                None => return false,
            };
            if !merkle_path_depth_ok(&decommit.path_y0, depth_current, limits)
                || !merkle_path_depth_ok(&decommit.path_y1, depth_current, limits)
                || !merkle_path_depth_ok(&decommit.path_z, depth_next, limits)
            {
                return false;
            }
            // Bind Merkle openings to the expected indices for this fold. Without this, a prover
            // can mix-and-match openings from arbitrary positions while still satisfying the
            // fold relation and Merkle roots, which breaks soundness.
            let idx_y0 = match merkle_path_index(&decommit.path_y0) {
                Some(v) => v,
                None => return false,
            };
            let idx_y1 = match merkle_path_index(&decommit.path_y1) {
                Some(v) => v,
                None => return false,
            };
            let idx_z = match merkle_path_index(&decommit.path_z) {
                Some(v) => v,
                None => return false,
            };
            let expected_y0 = match expected_j.checked_mul(fold_arity) {
                Some(v) => v,
                None => return false,
            };
            let expected_y1 = match expected_y0.checked_add(1) {
                Some(v) => v,
                None => return false,
            };
            if idx_y0 != expected_y0 || idx_y1 != expected_y1 || idx_z != expected_j {
                return false;
            }
            let r_k = match fri_round_challenge(&env.params, &env.transcript_label, k, &roots[k]) {
                Some(v) => v,
                None => return false,
            };
            let y0 = match Fp4::from_wire(decommit.y0) {
                Some(v) => v,
                None => return false,
            };
            let y1 = match Fp4::from_wire(decommit.y1) {
                Some(v) => v,
                None => return false,
            };
            let Some(current_domain) = StarkMerkleDomainV1::fri_layer(k) else {
                return false;
            };
            let Some(next_domain) = StarkMerkleDomainV1::fri_layer(k + 1) else {
                return false;
            };
            if !fri_merkle_verify(
                &env.params,
                current_domain,
                &roots[k],
                y0,
                &decommit.path_y0,
            ) {
                return false;
            }
            if !fri_merkle_verify(
                &env.params,
                current_domain,
                &roots[k],
                y1,
                &decommit.path_y1,
            ) {
                return false;
            }
            let z = match Fp4::from_wire(decommit.z) {
                Some(v) => v,
                None => return false,
            };
            let x = match domain_x_for_pair(layer_domain, expected_j) {
                Some(v) => v,
                None => return false,
            };
            let zr = match fri_fold_pair(y0, y1, r_k, x) {
                Some(v) => v,
                None => return false,
            };
            if zr != z {
                return false;
            }
            if !fri_merkle_verify(&env.params, next_domain, &roots[k + 1], z, &decommit.path_z) {
                return false;
            }
            last_z = Some(z);
            layer_domain /= fold_arity;
            idx_layer = expected_j;
        }
        if last_z != Some(Fp4::zero()) {
            return false;
        }
        if let (Some(comp_root), Some(cv_all)) =
            (env.proof.commits.comp_root, env.proof.comp_values.as_ref())
        {
            if qi >= cv_all.len() {
                return false;
            }
            let comp_entry = &cv_all[qi];
            if comp_entry.aux_terms.len() > effective_max_aux_terms(limits) {
                return false;
            }
            let depth_comp = match log2_usize(layer_domain) {
                Some(v) => v,
                None => return false,
            };
            if !merkle_path_depth_ok(&comp_entry.path, depth_comp, limits) {
                return false;
            }
            let cv_f = match Fq::from_canonical_u64(comp_entry.leaf) {
                Some(v) => v,
                None => return false,
            };
            if !merkle_verify(
                &env.params,
                StarkMerkleDomainV1::auxiliary_composition(),
                &comp_root,
                cv_f,
                &comp_entry.path,
            ) {
                return false;
            }
            let constant = match Fq::from_canonical_u64(comp_entry.constant) {
                Some(v) => v,
                None => return false,
            };
            if Fq::from_canonical_u64(comp_entry.z_coeff).is_none() {
                return false;
            }
            let expected_public_digest = match stark_air_public_digest_from_composition(
                comp_entry.constant,
                comp_entry.z_coeff,
                &comp_entry.aux_terms,
            ) {
                Ok(digest) => digest,
                Err(_) => return false,
            };
            if expected_public_digest != air.public_digest {
                return false;
            }
            let mut expected = constant;
            // The terminal polynomial is enforced as the zero Fp4 element above, so the
            // base-field `z_coeff * z_final` contribution is canonically zero.
            if last_z.is_none() && comp_entry.z_coeff != 0 {
                return false;
            }
            let mut last_wire: Option<u32> = None;
            for term in &comp_entry.aux_terms {
                if let Some(prev) = last_wire {
                    if term.wire_index <= prev {
                        return false;
                    }
                }
                last_wire = Some(term.wire_index);
                let coeff = match Fq::from_canonical_u64(term.coeff) {
                    Some(v) => v,
                    None => return false,
                };
                let value = match Fq::from_canonical_u64(term.value) {
                    Some(v) => v,
                    None => return false,
                };
                expected = expected.add(coeff.mul(value));
            }
            if cv_f != expected {
                return false;
            }
        }
        if layer_domain != 1 || idx_layer != 0 {
            return false;
        }
    }
    true
}
