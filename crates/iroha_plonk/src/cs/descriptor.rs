//! `CircuitDescriptorV1`: the canonical statement of everything a PIPA-v1
//! verifier evaluates (spec section 4).
//!
//! The descriptor is the finalized constraint system (selectors already
//! substituted, expression trees as written: no CSE or simplification) plus
//! the protocol parameters: curve and moduli, pinned params digest, `k`,
//! transcript, instance mode with the exact length of every instance column,
//! proof suffix, degree, blinding factors, permutation chunk length, quotient
//! piece count and lookup kind. Its bytes are the canonical Norito frame
//! `D = norito::encode_canonical(&CircuitDescriptorV1)`, and
//!
//! ```text
//! descriptor_digest = BLAKE2b(32, person "PIPA-v1-CircDesc", D)
//! transcript_repr   = F::from_uniform_bytes(
//!     BLAKE2b(64, person "Iroha-PlonkVK-v1", descriptor_digest || vk_bytes))
//! ```
//!
//! Verification depends only on the decoded descriptor, never on
//! `configure()`, so nodes can verify against pinned descriptor blobs.
//! [`CircuitDescriptorV1::validate`] enforces the nine validation rules of the
//! spec; every failure is a typed [`DescriptorRule`].
//!
//! The schema is frozen: any change is a new type and version.

use std::collections::{BTreeMap, BTreeSet};

use core::fmt;

use blake2::{
    Blake2bVarCore,
    digest::core_api::{Buffer, UpdateCore, VariableOutputCore},
};
use ff::{FromUniformBytes, PrimeField};
use iroha_pasta::{Fp, Fq, PastaField};
use norito::{NoritoDeserialize, NoritoSchema, NoritoSerialize};

use super::{
    constraint_system::{ConstraintSystem, CsError, FinalizedConstraintSystem, MAX_K},
    expression::{Any, Column, Expression},
    selector_compression::{self, SelectorDescription},
};

/// Norito schema name of the descriptor frame.
pub const DESCRIPTOR_SCHEMA_NAME: &str = "iroha.plonk.pipa.circuit_descriptor.v1";
/// The only protocol version.
pub const PROTOCOL_VERSION: u16 = 1;
/// `BLAKE2b` personalization of the descriptor digest.
pub const DESCRIPTOR_DIGEST_PERSONA: &[u8; 16] = b"PIPA-v1-CircDesc";
/// `BLAKE2b` personalization of `transcript_repr`.
pub const TRANSCRIPT_REPR_PERSONA: &[u8; 16] = b"Iroha-PlonkVK-v1";
/// Largest descriptor frame (16 MiB).
pub const MAX_DESCRIPTOR_BYTES: usize = 16 * 1024 * 1024;
/// Largest count of any descriptor list or column kind.
pub const MAX_COUNT: usize = 65_535;
/// Largest stack depth while evaluating a postfix expression.
pub const MAX_EXPRESSION_STACK: usize = 1_024;
/// Smallest circuit degree.
pub const MIN_DEGREE: usize = 3;
/// Largest circuit degree (format cap; gadget chips stay at 6 or below).
pub const MAX_DEGREE: usize = 9;

/// The proof curve.
#[derive(
    Clone,
    Copy,
    Debug,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    NoritoSerialize,
    NoritoDeserialize,
    NoritoSchema,
)]
#[norito_schema(name = "iroha.plonk.pipa.CurveV1")]
pub enum CurveV1 {
    /// Pallas (`Ep`): base field `Fp`, scalar field `Fq`.
    Pallas,
    /// Vesta (`Eq`): base field `Fq`, scalar field `Fp`.
    Vesta,
}

impl CurveV1 {
    /// The little-endian base-field modulus.
    #[must_use]
    pub fn base_modulus(self) -> [u8; 32] {
        match self {
            Self::Pallas => modulus_le_bytes::<Fp>(),
            Self::Vesta => modulus_le_bytes::<Fq>(),
        }
    }

    /// The little-endian scalar-field modulus.
    #[must_use]
    pub fn scalar_modulus(self) -> [u8; 32] {
        match self {
            Self::Pallas => modulus_le_bytes::<Fq>(),
            Self::Vesta => modulus_le_bytes::<Fp>(),
        }
    }
}

/// The Fiat-Shamir transcript (spec sections 6.1, 6.2).
#[derive(
    Clone,
    Copy,
    Debug,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    NoritoSerialize,
    NoritoDeserialize,
    NoritoSchema,
)]
#[norito_schema(name = "iroha.plonk.pipa.TranscriptV1")]
pub enum TranscriptV1 {
    /// BLAKE2b-512 `Halo2-Transcript` with `Challenge255`.
    Blake2bChallenge255,
    /// The KAGEMUSHA RP57 Poseidon sponge.
    KagemushaPoseidonRp57,
}

/// How instance columns enter the proof (spec section 6.3).
#[derive(
    Clone,
    Copy,
    Debug,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    NoritoSerialize,
    NoritoDeserialize,
    NoritoSchema,
)]
#[norito_schema(name = "iroha.plonk.pipa.InstanceModeV1")]
pub enum InstanceModeV1 {
    /// Instance columns are committed and opened.
    Committed,
    /// Instance values are absorbed and evaluated directly by the verifier.
    Direct,
}

/// What follows the IPA messages in the proof (spec section 11).
#[derive(
    Clone,
    Copy,
    Debug,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    NoritoSerialize,
    NoritoDeserialize,
    NoritoSchema,
)]
#[norito_schema(name = "iroha.plonk.pipa.ProofSuffixV1")]
pub enum ProofSuffixV1 {
    /// Nothing.
    None,
    /// The folded generator `G'_0`, not absorbed.
    FoldedGenerator,
}

/// The lookup argument.
#[derive(
    Clone,
    Copy,
    Debug,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    NoritoSerialize,
    NoritoDeserialize,
    NoritoSchema,
)]
#[norito_schema(name = "iroha.plonk.pipa.LookupKindV1")]
pub enum LookupKindV1 {
    /// halo2's permuted lookup `(A', S', z)`.
    Halo2Permuted,
}

/// A query: a column index and a rotation.
#[derive(
    Clone,
    Copy,
    Debug,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    NoritoSerialize,
    NoritoDeserialize,
    NoritoSchema,
)]
#[norito_schema(name = "iroha.plonk.pipa.QueryV1")]
pub struct QueryV1 {
    /// The column index.
    pub column: u32,
    /// The rotation.
    pub rotation: i32,
}

/// One original selector's place in the selector plan.
#[derive(
    Clone,
    Copy,
    Debug,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    NoritoSerialize,
    NoritoDeserialize,
    NoritoSchema,
)]
#[norito_schema(name = "iroha.plonk.pipa.SelectorEntryV1")]
pub struct SelectorEntryV1 {
    /// The selector's gate degree (0 for complex and unused selectors).
    pub max_degree: u8,
    /// The combination; its fixed column is `first_column + combination`.
    pub combination: u32,
    /// The 1-based root the selector's rows hold in the combination column.
    pub root: u8,
}

/// The selector map.
#[derive(Clone, Debug, PartialEq, Eq, Hash, NoritoSerialize, NoritoDeserialize, NoritoSchema)]
#[norito_schema(name = "iroha.plonk.pipa.SelectorsV1")]
pub struct SelectorsV1 {
    /// Whether halo2 selector compression ran.
    pub compress: bool,
    /// The first selector fixed column.
    pub first_column: u32,
    /// One entry per original selector.
    pub entries: Vec<SelectorEntryV1>,
}

/// One node of a postfix expression.
#[derive(
    Clone,
    Copy,
    Debug,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    NoritoSerialize,
    NoritoDeserialize,
    NoritoSchema,
)]
#[norito_schema(name = "iroha.plonk.pipa.ExprNodeV1")]
pub enum ExprNodeV1 {
    /// A canonical little-endian scalar constant.
    Constant([u8; 32]),
    /// A fixed query, by index into `fixed_queries`.
    Fixed(u32),
    /// An advice query, by index into `advice_queries`.
    Advice(u32),
    /// An instance query, by index into `instance_queries`.
    Instance(u32),
    /// Negates the top of the stack.
    Negated,
    /// Adds the two topmost values (the deeper one is the left operand).
    Sum,
    /// Multiplies the two topmost values (the deeper one is the left operand).
    Product,
    /// Multiplies the top of the stack by a canonical constant.
    Scaled([u8; 32]),
}

/// An expression in postfix order.
pub type ExprV1 = Vec<ExprNodeV1>;

/// The kind of a permutation column.
#[derive(
    Clone,
    Copy,
    Debug,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    NoritoSerialize,
    NoritoDeserialize,
    NoritoSchema,
)]
#[norito_schema(name = "iroha.plonk.pipa.ColumnKindV1")]
pub enum ColumnKindV1 {
    /// An advice column.
    Advice,
    /// A fixed column.
    Fixed,
    /// An instance column.
    Instance,
}

/// A permutation column.
#[derive(
    Clone,
    Copy,
    Debug,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    NoritoSerialize,
    NoritoDeserialize,
    NoritoSchema,
)]
#[norito_schema(name = "iroha.plonk.pipa.PermutationColumnV1")]
pub struct PermutationColumnV1 {
    /// The column kind.
    pub kind: ColumnKindV1,
    /// The column index.
    pub index: u32,
}

/// A lookup of input expressions into table expressions.
#[derive(Clone, Debug, PartialEq, Eq, Hash, NoritoSerialize, NoritoDeserialize, NoritoSchema)]
#[norito_schema(name = "iroha.plonk.pipa.LookupV1")]
pub struct LookupV1 {
    /// The input expressions.
    pub inputs: Vec<ExprV1>,
    /// The table expressions.
    pub tables: Vec<ExprV1>,
}

/// The canonical PIPA-v1 circuit descriptor (spec section 4).
#[derive(Clone, Debug, PartialEq, Eq, Hash, NoritoSerialize, NoritoDeserialize, NoritoSchema)]
#[norito_schema(name = "iroha.plonk.pipa.circuit_descriptor.v1")]
pub struct CircuitDescriptorV1 {
    /// Always [`PROTOCOL_VERSION`].
    pub protocol_version: u16,
    /// The proof curve.
    pub curve: CurveV1,
    /// The curve's base-field modulus, little-endian.
    pub base_modulus: [u8; 32],
    /// The curve's scalar-field modulus, little-endian.
    pub scalar_modulus: [u8; 32],
    /// `PINNED_PARAMS_V1[(curve, k)]`.
    pub params_digest: [u8; 32],
    /// `log2` of the domain size.
    pub k: u8,
    /// The transcript.
    pub transcript: TranscriptV1,
    /// The instance mode.
    pub instance_mode: InstanceModeV1,
    /// The proof suffix.
    pub proof_suffix: ProofSuffixV1,
    /// The circuit degree `d`.
    pub degree: u8,
    /// The blinding factors `b`.
    pub blinding_factors: u16,
    /// Columns per permutation set, `d - 2`.
    pub permutation_chunk_len: u8,
    /// Quotient pieces, `d - 1`.
    pub quotient_pieces: u8,
    /// The lookup argument.
    pub lookup_kind: LookupKindV1,
    /// Fixed columns after selector substitution.
    pub num_fixed_columns: u32,
    /// Advice columns.
    pub num_advice_columns: u32,
    /// The exact length of each instance column.
    pub instance_lengths: Vec<u32>,
    /// Fixed queries in halo2 order.
    pub fixed_queries: Vec<QueryV1>,
    /// Advice queries in halo2 order.
    pub advice_queries: Vec<QueryV1>,
    /// Instance queries in halo2 order.
    pub instance_queries: Vec<QueryV1>,
    /// The selector map.
    pub selectors: SelectorsV1,
    /// Gate polynomials after selector substitution, per gate.
    pub gates: Vec<Vec<ExprV1>>,
    /// Equality columns in `enable_equality` order.
    pub permutation: Vec<PermutationColumnV1>,
    /// The lookups.
    pub lookups: Vec<LookupV1>,
}

/// The descriptor validation rule that failed (spec section 4, rules 1-9).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DescriptorRule {
    /// Rule 1: the frame is not one canonical descriptor.
    Decode,
    /// Rule 1: the frame exceeds 16 MiB.
    FrameTooLarge,
    /// Rule 1: `k` or a count is outside the section 1 bounds.
    Bounds,
    /// Rule 2: the protocol version is not 1.
    Version,
    /// Rule 2: the moduli do not match the curve.
    Moduli,
    /// Rule 2: the params digest is not the pinned one.
    ParamsDigest,
    /// Rule 3: the degree, chunk length, piece count or extended domain.
    Degree,
    /// Rule 4: the blinding factors do not follow the masks formula, or the
    /// domain is too small for them.
    BlindingFactors,
    /// Rule 4: an instance length exceeds the usable rows.
    InstanceLength,
    /// Rule 4: V2 instance types are missing or invalid.
    InstanceType,
    /// Rule 2: the transcript profile requires different instance or suffix modes.
    TranscriptProfile,
    /// Rule 5: a query names a missing column.
    QueryColumn,
    /// Rule 5: a `(column, rotation)` query repeats.
    DuplicateQuery,
    /// Rule 5: two rotations coincide modulo `n`.
    RotationCollision,
    /// Rule 6: a malformed postfix expression, out-of-range index or
    /// non-canonical constant.
    Expression,
    /// Rule 6: an expression degree exceeds `d`.
    ExpressionDegree,
    /// Rule 6: a gate has no polynomial.
    EmptyGate,
    /// Rule 6: a lookup has no or unequal inputs and tables, or its required
    /// degree exceeds `d`.
    Lookup,
    /// Rule 7: a permutation column repeats, is missing or has no rotation-0
    /// query.
    Permutation,
    /// Rule 8: the selector map is inconsistent.
    Selectors,
    /// Rule 9: a witness polynomial reveals more evaluations than its
    /// blinding allows.
    ZeroKnowledgeBudget,
}

impl DescriptorRule {
    /// The spec section 4 rule number (1-9).
    #[must_use]
    pub const fn rule_number(self) -> u8 {
        match self {
            Self::Decode | Self::FrameTooLarge | Self::Bounds => 1,
            Self::Version | Self::Moduli | Self::ParamsDigest | Self::TranscriptProfile => 2,
            Self::Degree => 3,
            Self::BlindingFactors | Self::InstanceLength | Self::InstanceType => 4,
            Self::QueryColumn | Self::DuplicateQuery | Self::RotationCollision => 5,
            Self::Expression | Self::ExpressionDegree | Self::EmptyGate | Self::Lookup => 6,
            Self::Permutation => 7,
            Self::Selectors => 8,
            Self::ZeroKnowledgeBudget => 9,
        }
    }
}

/// A descriptor could not be built, encoded or admitted.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DescriptorError {
    /// `DescriptorInvalid(rule)`.
    Invalid(DescriptorRule),
    /// The constraint system is not usable.
    ConstraintSystem(Box<CsError>),
    /// The constraint system's field is not the curve's scalar field.
    FieldMismatch,
    /// The constraint system still contains a virtual selector.
    UnsubstitutedSelector,
    /// An expression queries a cell that was never interned.
    UninternedQuery,
    /// No params digest is pinned for this curve and `k`.
    UnpinnedParams {
        /// The curve.
        curve: CurveV1,
        /// The `k`.
        k: u32,
    },
    /// Norito encoding failed.
    Encode,
}

impl fmt::Display for DescriptorError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Invalid(rule) => write!(
                f,
                "DescriptorInvalid({rule:?}, rule {})",
                rule.rule_number()
            ),
            Self::ConstraintSystem(error) => write!(f, "constraint system: {error}"),
            Self::FieldMismatch => f.write_str("the field is not the curve's scalar field"),
            Self::UnsubstitutedSelector => f.write_str("a virtual selector was not substituted"),
            Self::UninternedQuery => f.write_str("an expression queries an uninterned cell"),
            Self::UnpinnedParams { curve, k } => {
                write!(f, "no params digest is pinned for {curve:?} at k = {k}")
            }
            Self::Encode => f.write_str("Norito encoding failed"),
        }
    }
}

impl std::error::Error for DescriptorError {}

impl DescriptorError {
    /// Whether descriptor construction stopped because its caller cancelled.
    pub fn is_cancelled(&self) -> bool {
        matches!(self, Self::ConstraintSystem(error) if matches!(error.as_ref(), CsError::Cancelled))
    }
}

impl From<DescriptorRule> for DescriptorError {
    fn from(rule: DescriptorRule) -> Self {
        Self::Invalid(rule)
    }
}

impl From<CsError> for DescriptorError {
    fn from(error: CsError) -> Self {
        Self::ConstraintSystem(Box::new(error))
    }
}

/// The protocol parameters a descriptor binds besides the constraint system.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DescriptorConfig {
    /// The proof curve; the constraint system's field must be its scalar field.
    pub curve: CurveV1,
    /// `log2` of the domain size.
    pub k: u32,
    /// The transcript.
    pub transcript: TranscriptV1,
    /// The instance mode.
    pub instance_mode: InstanceModeV1,
    /// The proof suffix.
    pub proof_suffix: ProofSuffixV1,
}

/// Decodes a 64-character lowercase hex string. It is only evaluated in the
/// `PINNED_PARAMS_V1` constant, so a malformed literal is a compile error,
/// never a runtime panic.
const fn hex32(text: &str) -> [u8; 32] {
    const fn nibble(byte: u8) -> u8 {
        match byte {
            b'0'..=b'9' => byte - b'0',
            b'a'..=b'f' => byte - b'a' + 10,
            _ => panic!("pinned digest is not lowercase hex"),
        }
    }
    let bytes = text.as_bytes();
    assert!(bytes.len() == 64, "pinned digest is not 64 hex characters");
    let mut out = [0_u8; 32];
    let mut i = 0;
    while i < 32 {
        out[i] = (nibble(bytes[2 * i]) << 4) | nibble(bytes[2 * i + 1]);
        i += 1;
    }
    out
}

/// `PINNED_PARAMS_V1`: SHA-256 of the `ParamsIpa` bytes per `(curve, k)`,
/// seeded from `fixtures/native_prover/kats_v1.json` (`params_ipa[*].sha256`,
/// `k = 6..=16`) and recomputed from the derivation by this crate's tests.
///
/// TODO: pin `k > 16` once the release qualification computes those digests.
pub const PINNED_PARAMS_V1: &[(CurveV1, u8, [u8; 32])] = &[
    (
        CurveV1::Pallas,
        6,
        hex32("81ecfc65612a3e22f46adcd8775b547b476671a5e17e98e53081408d5c9c7aa7"),
    ),
    (
        CurveV1::Pallas,
        7,
        hex32("f999cf187832b2fe6c54e68656bcedc92d0902ab42fa279f5c845f31338c5ecf"),
    ),
    (
        CurveV1::Pallas,
        8,
        hex32("6e3c9ff565425ebea04de329b34fb3bb6061a3d43417706448ab00e8e3efb602"),
    ),
    (
        CurveV1::Pallas,
        9,
        hex32("30c2a8e1a423467b96a586ee97f2e6b04d6cc95de1d0dab4f233a9ddad3d0c51"),
    ),
    (
        CurveV1::Pallas,
        10,
        hex32("422e1701e538cf2c50fa2f7489c30d73477d5700d8da6ff73f75c2a7aedf04e4"),
    ),
    (
        CurveV1::Pallas,
        11,
        hex32("56ec863de1374a91a99e53b247ec804c4ea7888400df9f23add747e227000a6a"),
    ),
    (
        CurveV1::Pallas,
        12,
        hex32("4b20d41b76f4249829f16b08b1df0a8d6cc8897fa4394b74681b51332f4039b6"),
    ),
    (
        CurveV1::Pallas,
        13,
        hex32("345da39c48ee9d86cc74c9610536ff007bd8b611d801d00598dd3b90c22149d4"),
    ),
    (
        CurveV1::Pallas,
        14,
        hex32("2527d71bdb1d374a1b5cc29cf73f7849a87bce5e24c0d1bda0b284f12bf570c4"),
    ),
    (
        CurveV1::Pallas,
        15,
        hex32("0e177a0c9bcf63020c884269dbc3db8a27e583394f1ac65383e7fb2ed45df687"),
    ),
    (
        CurveV1::Pallas,
        16,
        hex32("2eb6e09a8f0dfdd18df0ec2ad5186d900acd5374eac817bdbb72f0f51b694628"),
    ),
    (
        CurveV1::Vesta,
        6,
        hex32("606ec71853588ea2414707e98ffb181091f6985d294d03d4165fb400a9a6b3a6"),
    ),
    (
        CurveV1::Vesta,
        7,
        hex32("432e492288c43ccabdffb913625109ca76f66312cd4625c9a258a2e33a28c400"),
    ),
    (
        CurveV1::Vesta,
        8,
        hex32("96d2448c483f4df37e69b4f72db328cd8520b09d49f5e7c801da7994150b9b33"),
    ),
    (
        CurveV1::Vesta,
        9,
        hex32("b7ea13dd3cfe5db384fab28fd90c4ca7327fb20d3fde16c12eb8b3f81538cb62"),
    ),
    (
        CurveV1::Vesta,
        10,
        hex32("65235f086265cdf98b12514ab36fe9b849198870918d73cd160903ceb0a954dc"),
    ),
    (
        CurveV1::Vesta,
        11,
        hex32("1eab6f93a080ce41b908d935c04bd2e3ed1ac23f277c15d11c499d56d28fa0f7"),
    ),
    (
        CurveV1::Vesta,
        12,
        hex32("1b97b06da453b9efb1ae18b9ba77c3d870f22dc72898297d5707e340c3f44865"),
    ),
    (
        CurveV1::Vesta,
        13,
        hex32("76ebe6b75b5281cb1dcc2eb04888968573758672b521522f62abedf6366bb876"),
    ),
    (
        CurveV1::Vesta,
        14,
        hex32("1cb278fe4d9cf5325e5cbc710d863c0deca3e961e1b8f6c8736890c43345c461"),
    ),
    (
        CurveV1::Vesta,
        15,
        hex32("e1fb29749c7bd0870768044d5329b4e293cb2d44dae24db2554605427b19d0dd"),
    ),
    (
        CurveV1::Vesta,
        16,
        hex32("174780f80c577d968d10bc3f0a8f819e55a96b9e882ffe73c15d55e9f94053e2"),
    ),
];

/// The pinned params digest for `(curve, k)`, if any.
#[must_use]
pub fn pinned_params_digest(curve: CurveV1, k: u32) -> Option<[u8; 32]> {
    PINNED_PARAMS_V1
        .iter()
        .find(|(pinned_curve, pinned_k, _)| *pinned_curve == curve && u32::from(*pinned_k) == k)
        .map(|(_, _, digest)| *digest)
}

/// The little-endian modulus of `F` (`repr(-1) + 1`).
#[must_use]
pub fn modulus_le_bytes<F: PrimeField<Repr = [u8; 32]>>() -> [u8; 32] {
    let mut bytes = (-F::ONE).to_repr();
    for byte in &mut bytes {
        let (sum, carry) = byte.overflowing_add(1);
        *byte = sum;
        if !carry {
            break;
        }
    }
    bytes
}

/// Whether the little-endian integer `value` is below `modulus`.
fn is_canonical(value: &[u8; 32], modulus: &[u8; 32]) -> bool {
    for (v, m) in value.iter().rev().zip(modulus.iter().rev()) {
        if v != m {
            return v < m;
        }
    }
    false
}

/// Incremental personalised `BLAKE2b` with an `N`-byte output (`N <= 64`):
/// the streaming form of [`blake2b_personal`], for digests over data too
/// large to concatenate (witness and copy-mapping digests). Updates may be
/// split anywhere; the digest depends only on the concatenated input.
pub(crate) struct Blake2bPersonal<const N: usize> {
    core: Blake2bVarCore,
    buffer: Buffer<Blake2bVarCore>,
}

impl<const N: usize> Blake2bPersonal<N> {
    /// A fresh state with personalization `persona`.
    pub(crate) fn new(persona: &[u8; 16]) -> Self {
        Self {
            core: Blake2bVarCore::new_with_params(&[], persona, 0, N),
            buffer: Buffer::<Blake2bVarCore>::default(),
        }
    }

    /// Absorbs `part`.
    pub(crate) fn update(&mut self, part: &[u8]) {
        let core = &mut self.core;
        self.buffer
            .digest_blocks(part, |blocks| core.update_blocks(blocks));
    }

    /// The `N`-byte digest.
    pub(crate) fn finalize(mut self) -> [u8; N] {
        let mut full = blake2::digest::Output::<Blake2bVarCore>::default();
        self.core
            .finalize_variable_core(&mut self.buffer, &mut full);
        let mut out = [0_u8; N];
        out.copy_from_slice(&full[..N]);
        out
    }
}

/// Personalised `BLAKE2b` with an `N`-byte output (`N <= 64`) over the
/// concatenation of `parts`.
pub(crate) fn blake2b_personal<const N: usize>(persona: &[u8; 16], parts: &[&[u8]]) -> [u8; N] {
    let mut hasher = Blake2bPersonal::<N>::new(persona);
    for part in parts {
        hasher.update(part);
    }
    hasher.finalize()
}

/// `BLAKE2b(32, person "PIPA-v1-CircDesc", encoded)`.
#[must_use]
pub fn descriptor_digest(encoded: &[u8]) -> [u8; 32] {
    blake2b_personal::<32>(DESCRIPTOR_DIGEST_PERSONA, &[encoded])
}

/// `transcript_repr = F::from_uniform_bytes(BLAKE2b(64, person
/// "Iroha-PlonkVK-v1", descriptor_digest || vk_bytes))`.
#[must_use]
pub fn transcript_repr<F: FromUniformBytes<64>>(
    descriptor_digest: &[u8; 32],
    vk_bytes: &[u8],
) -> F {
    let wide = blake2b_personal::<64>(TRANSCRIPT_REPR_PERSONA, &[descriptor_digest, vk_bytes]);
    F::from_uniform_bytes(&wide)
}

/// Converts a count or index to `u32`, rejecting values above [`MAX_COUNT`].
fn bounded_u32(value: usize) -> Result<u32, DescriptorError> {
    if value > MAX_COUNT {
        return Err(DescriptorRule::Bounds.into());
    }
    u32::try_from(value).map_err(|_| DescriptorRule::Bounds.into())
}

/// Converts a query table.
fn queries_v1<C: super::expression::ColumnType>(
    queries: &[(Column<C>, super::expression::Rotation)],
) -> Result<Vec<QueryV1>, DescriptorError> {
    queries
        .iter()
        .map(|(column, rotation)| {
            Ok(QueryV1 {
                column: bounded_u32(column.index())?,
                rotation: rotation.0,
            })
        })
        .collect()
}

/// Appends `expression` in postfix order, resolving queries to indices.
fn push_postfix<F: PastaField>(
    expression: &Expression<F>,
    cs: &ConstraintSystem<F>,
    out: &mut ExprV1,
) -> Result<(), DescriptorError> {
    let index = |column: Column<Any>, rotation| {
        cs.query_index(column, rotation)
            .ok_or(DescriptorError::UninternedQuery)
            .and_then(bounded_u32)
    };
    match expression {
        Expression::Constant(value) => out.push(ExprNodeV1::Constant(value.to_repr())),
        Expression::Selector(_) => return Err(DescriptorError::UnsubstitutedSelector),
        Expression::Fixed(query) => out.push(ExprNodeV1::Fixed(index(
            Column::new(query.column_index, Any::Fixed),
            query.rotation,
        )?)),
        Expression::Advice(query) => out.push(ExprNodeV1::Advice(index(
            Column::new(query.column_index, Any::Advice),
            query.rotation,
        )?)),
        Expression::Instance(query) => out.push(ExprNodeV1::Instance(index(
            Column::new(query.column_index, Any::Instance),
            query.rotation,
        )?)),
        Expression::Negated(inner) => {
            push_postfix(inner, cs, out)?;
            out.push(ExprNodeV1::Negated);
        }
        Expression::Sum(left, right) => {
            push_postfix(left, cs, out)?;
            push_postfix(right, cs, out)?;
            out.push(ExprNodeV1::Sum);
        }
        Expression::Product(left, right) => {
            push_postfix(left, cs, out)?;
            push_postfix(right, cs, out)?;
            out.push(ExprNodeV1::Product);
        }
        Expression::Scaled(inner, factor) => {
            push_postfix(inner, cs, out)?;
            out.push(ExprNodeV1::Scaled(factor.to_repr()));
        }
    }
    Ok(())
}

/// Converts an expression to postfix form.
fn postfix<F: PastaField>(
    expression: &Expression<F>,
    cs: &ConstraintSystem<F>,
) -> Result<ExprV1, DescriptorError> {
    let mut out = Vec::with_capacity(expression.node_count());
    push_postfix(expression, cs, &mut out)?;
    Ok(out)
}

/// Query-table sizes and the scalar modulus an expression is checked against.
struct ExpressionContext<'a> {
    fixed: usize,
    advice: usize,
    instance: usize,
    modulus: &'a [u8; 32],
}

/// Checks a postfix expression and returns its degree.
fn expression_degree(
    expression: &[ExprNodeV1],
    context: &ExpressionContext<'_>,
) -> Result<usize, DescriptorRule> {
    if expression.is_empty() || expression.len() > MAX_COUNT {
        return Err(DescriptorRule::Expression);
    }
    let mut stack: Vec<usize> = Vec::new();
    for node in expression {
        match node {
            ExprNodeV1::Constant(value) => {
                if !is_canonical(value, context.modulus) {
                    return Err(DescriptorRule::Expression);
                }
                stack.push(0);
            }
            ExprNodeV1::Fixed(index) | ExprNodeV1::Advice(index) | ExprNodeV1::Instance(index) => {
                let table = match node {
                    ExprNodeV1::Fixed(_) => context.fixed,
                    ExprNodeV1::Advice(_) => context.advice,
                    _ => context.instance,
                };
                if usize::try_from(*index).map_or(true, |index| index >= table) {
                    return Err(DescriptorRule::Expression);
                }
                stack.push(1);
            }
            ExprNodeV1::Negated => {
                if stack.is_empty() {
                    return Err(DescriptorRule::Expression);
                }
            }
            ExprNodeV1::Scaled(value) => {
                if stack.is_empty() || !is_canonical(value, context.modulus) {
                    return Err(DescriptorRule::Expression);
                }
            }
            ExprNodeV1::Sum | ExprNodeV1::Product => {
                let (Some(right), Some(left)) = (stack.pop(), stack.pop()) else {
                    return Err(DescriptorRule::Expression);
                };
                stack.push(if matches!(node, ExprNodeV1::Sum) {
                    left.max(right)
                } else {
                    left.checked_add(right).ok_or(DescriptorRule::Expression)?
                });
            }
        }
        if stack.len() > MAX_EXPRESSION_STACK {
            return Err(DescriptorRule::Expression);
        }
    }
    match stack.as_slice() {
        [degree] => Ok(*degree),
        _ => Err(DescriptorRule::Expression),
    }
}

/// `ceil(log2(value))` for `value >= 1`.
fn ceil_log2(value: usize) -> u32 {
    value.next_power_of_two().trailing_zeros()
}

impl CircuitDescriptorV1 {
    /// Builds and validates the descriptor of a finalized constraint system.
    ///
    /// # Errors
    ///
    /// [`DescriptorError`] when the constraint system is unusable, its field
    /// is not the curve's scalar field, no params digest is pinned, or the
    /// result fails validation.
    pub fn from_constraint_system<F: PastaField>(
        finalized: &FinalizedConstraintSystem<F>,
        config: DescriptorConfig,
    ) -> Result<Self, DescriptorError> {
        let cs = finalized.constraint_system();
        cs.check()?;
        if modulus_le_bytes::<F>() != config.curve.scalar_modulus() {
            return Err(DescriptorError::FieldMismatch);
        }
        let k = u8::try_from(config.k).map_err(|_| DescriptorRule::Bounds)?;
        let params_digest = pinned_params_digest(config.curve, config.k).ok_or(
            DescriptorError::UnpinnedParams {
                curve: config.curve,
                k: config.k,
            },
        )?;
        let degree_usize = cs.degree();
        let degree = u8::try_from(degree_usize).map_err(|_| DescriptorRule::Degree)?;
        let blinding_factors =
            u16::try_from(cs.blinding_factors()).map_err(|_| DescriptorRule::BlindingFactors)?;
        let plan = finalized.selector_plan();
        let selectors = SelectorsV1 {
            compress: plan.compress,
            first_column: bounded_u32(plan.first_column)?,
            entries: plan
                .entries
                .iter()
                .map(|entry| {
                    Ok(SelectorEntryV1 {
                        max_degree: u8::try_from(entry.max_degree)
                            .map_err(|_| DescriptorRule::Selectors)?,
                        combination: bounded_u32(entry.combination)?,
                        root: u8::try_from(entry.root).map_err(|_| DescriptorRule::Selectors)?,
                    })
                })
                .collect::<Result<_, DescriptorError>>()?,
        };
        let gates = cs
            .gates()
            .iter()
            .map(|gate| {
                gate.polynomials()
                    .iter()
                    .map(|poly| postfix(poly, cs))
                    .collect::<Result<Vec<_>, _>>()
            })
            .collect::<Result<Vec<_>, _>>()?;
        let lookups = cs
            .lookups()
            .iter()
            .map(|lookup| {
                Ok(LookupV1 {
                    inputs: lookup
                        .input_expressions()
                        .iter()
                        .map(|e| postfix(e, cs))
                        .collect::<Result<_, DescriptorError>>()?,
                    tables: lookup
                        .table_expressions()
                        .iter()
                        .map(|e| postfix(e, cs))
                        .collect::<Result<_, DescriptorError>>()?,
                })
            })
            .collect::<Result<Vec<_>, DescriptorError>>()?;
        let permutation = cs
            .permutation()
            .columns()
            .iter()
            .map(|column| {
                Ok(PermutationColumnV1 {
                    kind: match column.column_type() {
                        Any::Advice => ColumnKindV1::Advice,
                        Any::Fixed => ColumnKindV1::Fixed,
                        Any::Instance => ColumnKindV1::Instance,
                    },
                    index: bounded_u32(column.index())?,
                })
            })
            .collect::<Result<Vec<_>, DescriptorError>>()?;
        let descriptor = Self {
            protocol_version: PROTOCOL_VERSION,
            curve: config.curve,
            base_modulus: config.curve.base_modulus(),
            scalar_modulus: config.curve.scalar_modulus(),
            params_digest,
            k,
            transcript: config.transcript,
            instance_mode: config.instance_mode,
            proof_suffix: config.proof_suffix,
            degree,
            blinding_factors,
            permutation_chunk_len: degree.checked_sub(2).ok_or(DescriptorRule::Degree)?,
            quotient_pieces: degree.checked_sub(1).ok_or(DescriptorRule::Degree)?,
            lookup_kind: LookupKindV1::Halo2Permuted,
            num_fixed_columns: bounded_u32(cs.num_fixed_columns())?,
            num_advice_columns: bounded_u32(cs.num_advice_columns())?,
            instance_lengths: cs
                .instance_lengths()
                .iter()
                .map(|length| bounded_u32(*length))
                .collect::<Result<_, _>>()?,
            fixed_queries: queries_v1(cs.fixed_queries())?,
            advice_queries: queries_v1(cs.advice_queries())?,
            instance_queries: queries_v1(cs.instance_queries())?,
            selectors,
            gates,
            permutation,
            lookups,
        };
        descriptor.validate()?;
        // The degree used for the descriptor is the constraint system's.
        debug_assert_eq!(usize::from(descriptor.degree), degree_usize);
        Ok(descriptor)
    }

    /// The canonical Norito frame `D`.
    ///
    /// # Errors
    ///
    /// [`DescriptorError::Encode`] when Norito fails, or rule 1 when the frame
    /// exceeds 16 MiB.
    pub fn encode(&self) -> Result<Vec<u8>, DescriptorError> {
        let bytes = norito::encode_canonical(self).map_err(|_| DescriptorError::Encode)?;
        if bytes.len() > MAX_DESCRIPTOR_BYTES {
            return Err(DescriptorRule::FrameTooLarge.into());
        }
        Ok(bytes)
    }

    /// Admission decode: one exact canonical frame (re-encoding reproduces
    /// `bytes`), followed by [`Self::validate`].
    ///
    /// # Errors
    ///
    /// [`DescriptorError::Invalid`] naming the failed rule.
    pub fn decode(bytes: &[u8]) -> Result<Self, DescriptorError> {
        if bytes.len() > MAX_DESCRIPTOR_BYTES {
            return Err(DescriptorRule::FrameTooLarge.into());
        }
        let descriptor: Self = norito::decode_canonical_for_admission(
            bytes,
            norito::canonical_decode_limits(bytes.len()),
        )
        .map_err(|_| DescriptorRule::Decode)?;
        if descriptor.encode()? != bytes {
            return Err(DescriptorRule::Decode.into());
        }
        descriptor.validate()?;
        Ok(descriptor)
    }

    /// `descriptor_digest` of the canonical frame.
    ///
    /// # Errors
    ///
    /// See [`Self::encode`].
    pub fn digest(&self) -> Result<[u8; 32], DescriptorError> {
        Ok(descriptor_digest(&self.encode()?))
    }

    /// `n = 2^k`.
    fn n(&self) -> Result<usize, DescriptorRule> {
        let k = u32::from(self.k);
        if !(1..=MAX_K).contains(&k) {
            return Err(DescriptorRule::Bounds);
        }
        1_usize.checked_shl(k).ok_or(DescriptorRule::Bounds)
    }

    /// The number of permutation sets `n_z = ceil(m / (d - 2))`.
    fn permutation_sets(&self) -> usize {
        let chunk = usize::from(self.permutation_chunk_len).max(1);
        self.permutation.len().div_ceil(chunk)
    }

    /// Checks the spec section 4 rules 1-9 (rule 1's frame checks run in
    /// [`Self::decode`]).
    ///
    /// # Errors
    ///
    /// [`DescriptorError::Invalid`] naming the first failed rule.
    pub fn validate(&self) -> Result<(), DescriptorError> {
        self.check_bounds()?;
        self.check_identity()?;
        let n = self.n()?;
        let degree = self.check_degree()?;
        let usable = self.check_blinding(n)?;
        let _ = usable;
        self.check_queries(n)?;
        self.check_expressions(degree)?;
        self.check_permutation()?;
        self.check_selectors(degree)?;
        self.check_zero_knowledge()?;
        Ok(())
    }

    /// Rule 1: section 1 bounds.
    fn check_bounds(&self) -> Result<(), DescriptorRule> {
        let counts = [
            self.num_fixed_columns as usize,
            self.num_advice_columns as usize,
            self.instance_lengths.len(),
            self.fixed_queries.len(),
            self.advice_queries.len(),
            self.instance_queries.len(),
            self.selectors.entries.len(),
            self.gates.len(),
            self.permutation.len(),
            self.lookups.len(),
        ];
        if counts.iter().any(|count| *count > MAX_COUNT)
            || self.gates.iter().any(|gate| gate.len() > MAX_COUNT)
            || self
                .lookups
                .iter()
                .any(|lookup| lookup.inputs.len() > MAX_COUNT || lookup.tables.len() > MAX_COUNT)
        {
            return Err(DescriptorRule::Bounds);
        }
        self.n().map(|_| ())
    }

    /// Rule 2: version, moduli and pinned params digest.
    fn check_identity(&self) -> Result<(), DescriptorRule> {
        if self.protocol_version != PROTOCOL_VERSION {
            return Err(DescriptorRule::Version);
        }
        if self.base_modulus != self.curve.base_modulus()
            || self.scalar_modulus != self.curve.scalar_modulus()
        {
            return Err(DescriptorRule::Moduli);
        }
        if pinned_params_digest(self.curve, u32::from(self.k)) != Some(self.params_digest) {
            return Err(DescriptorRule::ParamsDigest);
        }
        Ok(())
    }

    /// Rule 3: degree range, chunk length, piece count and extended domain.
    fn check_degree(&self) -> Result<usize, DescriptorRule> {
        let degree = usize::from(self.degree);
        if !(MIN_DEGREE..=MAX_DEGREE).contains(&degree)
            || usize::from(self.permutation_chunk_len) != degree - 2
            || usize::from(self.quotient_pieces) != degree - 1
        {
            return Err(DescriptorRule::Degree);
        }
        let extended = u32::from(self.k)
            .checked_add(ceil_log2(degree - 1))
            .ok_or(DescriptorRule::Degree)?;
        if extended > 32 {
            return Err(DescriptorRule::Degree);
        }
        Ok(degree)
    }

    /// Rule 4: blinding factors, minimum rows and instance lengths. Returns
    /// the usable rows.
    fn check_blinding(&self, n: usize) -> Result<usize, DescriptorRule> {
        let mut per_column = vec![0_usize; self.num_advice_columns as usize];
        for query in &self.advice_queries {
            // Out-of-range columns are reported by rule 5.
            if let Some(count) = per_column.get_mut(query.column as usize) {
                *count += 1;
            }
        }
        let max_queries = per_column.iter().copied().max().unwrap_or(1);
        let expected = max_queries.max(3) + 2;
        let blinding = usize::from(self.blinding_factors);
        if blinding != expected || n < blinding + 3 {
            return Err(DescriptorRule::BlindingFactors);
        }
        let usable = n - blinding - 1;
        if self
            .instance_lengths
            .iter()
            .any(|length| *length as usize > usable)
        {
            return Err(DescriptorRule::InstanceLength);
        }
        Ok(usable)
    }

    /// Rule 5: queries name existing columns, never repeat, and all
    /// rotations (implied ones included) are distinct modulo `n`.
    fn check_queries(&self, n: usize) -> Result<(), DescriptorRule> {
        let tables = [
            (&self.fixed_queries, self.num_fixed_columns as usize),
            (&self.advice_queries, self.num_advice_columns as usize),
            (&self.instance_queries, self.instance_lengths.len()),
        ];
        let mut rotations = BTreeSet::new();
        for (queries, columns) in tables {
            let mut seen = BTreeSet::new();
            for query in queries {
                if query.column as usize >= columns {
                    return Err(DescriptorRule::QueryColumn);
                }
                if !seen.insert((query.column, query.rotation)) {
                    return Err(DescriptorRule::DuplicateQuery);
                }
                rotations.insert(i64::from(query.rotation));
            }
        }
        let sets = self.permutation_sets();
        rotations.insert(0);
        if sets + self.lookups.len() > 0 {
            rotations.insert(1);
        }
        if !self.lookups.is_empty() {
            rotations.insert(-1);
        }
        if sets >= 2 {
            rotations.insert(-(i64::from(self.blinding_factors) + 1));
        }
        let n = i64::try_from(n).map_err(|_| DescriptorRule::Bounds)?;
        let points: BTreeSet<i64> = rotations.iter().map(|r| r.rem_euclid(n)).collect();
        if points.len() != rotations.len() {
            return Err(DescriptorRule::RotationCollision);
        }
        Ok(())
    }

    /// Rule 6: well-formed expressions, degrees, gates and lookups.
    fn check_expressions(&self, degree: usize) -> Result<(), DescriptorRule> {
        let context = ExpressionContext {
            fixed: self.fixed_queries.len(),
            advice: self.advice_queries.len(),
            instance: self.instance_queries.len(),
            modulus: &self.scalar_modulus,
        };
        let mut computed = MIN_DEGREE;
        for gate in &self.gates {
            if gate.is_empty() {
                return Err(DescriptorRule::EmptyGate);
            }
            for poly in gate {
                let poly_degree = expression_degree(poly, &context)?;
                if poly_degree > degree {
                    return Err(DescriptorRule::ExpressionDegree);
                }
                computed = computed.max(poly_degree);
            }
        }
        for lookup in &self.lookups {
            if lookup.inputs.is_empty() || lookup.inputs.len() != lookup.tables.len() {
                return Err(DescriptorRule::Lookup);
            }
            let mut input_degree = 1;
            for input in &lookup.inputs {
                input_degree = input_degree.max(expression_degree(input, &context)?);
            }
            let mut table_degree = 1;
            for table in &lookup.tables {
                table_degree = table_degree.max(expression_degree(table, &context)?);
            }
            let required = 4.max(input_degree + table_degree + 2);
            if required > degree {
                return Err(DescriptorRule::Lookup);
            }
            computed = computed.max(required);
        }
        if computed > degree {
            return Err(DescriptorRule::Degree);
        }
        Ok(())
    }

    /// Rule 7: distinct, existing permutation columns with rotation-0 queries.
    fn check_permutation(&self) -> Result<(), DescriptorRule> {
        let mut seen = BTreeSet::new();
        for column in &self.permutation {
            if !seen.insert((column.kind, column.index)) {
                return Err(DescriptorRule::Permutation);
            }
            let (queries, columns) = match column.kind {
                ColumnKindV1::Advice => (&self.advice_queries, self.num_advice_columns as usize),
                ColumnKindV1::Fixed => (&self.fixed_queries, self.num_fixed_columns as usize),
                ColumnKindV1::Instance => (&self.instance_queries, self.instance_lengths.len()),
            };
            if column.index as usize >= columns
                || !queries.contains(&QueryV1 {
                    column: column.index,
                    rotation: 0,
                })
            {
                return Err(DescriptorRule::Permutation);
            }
        }
        Ok(())
    }

    /// Rule 8: the selector map is consistent with the fixed columns.
    fn check_selectors(&self, degree: usize) -> Result<(), DescriptorRule> {
        let selectors = &self.selectors;
        let combinations = self
            .num_fixed_columns
            .checked_sub(selectors.first_column)
            .ok_or(DescriptorRule::Selectors)? as usize;
        let mut members: BTreeMap<u32, Vec<&SelectorEntryV1>> = BTreeMap::new();
        for (index, entry) in selectors.entries.iter().enumerate() {
            if entry.combination as usize >= combinations || usize::from(entry.max_degree) > degree
            {
                return Err(DescriptorRule::Selectors);
            }
            if !selectors.compress && (entry.combination as usize != index || entry.root != 1) {
                return Err(DescriptorRule::Selectors);
            }
            members.entry(entry.combination).or_default().push(entry);
        }
        if members.len() != combinations {
            return Err(DescriptorRule::Selectors);
        }
        for (combination, entries) in &members {
            let mut roots: Vec<usize> = entries.iter().map(|e| usize::from(e.root)).collect();
            roots.sort_unstable();
            if roots != (1..=entries.len()).collect::<Vec<_>>() {
                return Err(DescriptorRule::Selectors);
            }
            if selectors.compress {
                let complex = entries.iter().any(|e| e.max_degree == 0);
                if complex && entries.len() != 1 {
                    return Err(DescriptorRule::Selectors);
                }
                if !complex {
                    let t = entries
                        .iter()
                        .map(|e| usize::from(e.max_degree) - 1)
                        .max()
                        .unwrap_or(0);
                    if t + entries.len() > degree {
                        return Err(DescriptorRule::Selectors);
                    }
                }
            }
            let column = selectors
                .first_column
                .checked_add(*combination)
                .ok_or(DescriptorRule::Selectors)?;
            if !self.fixed_queries.contains(&QueryV1 {
                column,
                rotation: 0,
            }) {
                return Err(DescriptorRule::Selectors);
            }
        }
        Ok(())
    }

    /// Rule 9 (S7): every witness polynomial reveals at most `b - 1`
    /// evaluations (its distinct query rotations plus one for `x_3`).
    fn check_zero_knowledge(&self) -> Result<(), DescriptorRule> {
        let budget = usize::from(self.blinding_factors).saturating_sub(1);
        let mut per_column: BTreeMap<u32, BTreeSet<i32>> = BTreeMap::new();
        for query in &self.advice_queries {
            per_column
                .entry(query.column)
                .or_default()
                .insert(query.rotation);
        }
        let mut revealed: Vec<usize> = per_column.values().map(BTreeSet::len).collect();
        if !self.lookups.is_empty() {
            // A' at {0, -1}, S' at {0}, the lookup product z at {0, 1}.
            revealed.extend([2, 1, 2]);
        }
        let sets = self.permutation_sets();
        if sets > 0 {
            // z_s at {0, 1}, plus -(b+1) for every set but the last.
            revealed.push(if sets >= 2 { 3 } else { 2 });
        }
        if revealed.iter().any(|count| count + 1 > budget) {
            return Err(DescriptorRule::ZeroKnowledgeBudget);
        }
        Ok(())
    }

    /// Re-runs selector compression on the verifying key's activation bitmaps
    /// with this descriptor's `max_degree` entries and requires the same map
    /// (the registration check of spec section 5).
    ///
    /// # Errors
    ///
    /// Rule 8 when the activations disagree with the selector map.
    pub fn check_selector_plan(&self, activations: &[Vec<bool>]) -> Result<(), DescriptorError> {
        self.check_selector_plan_cancellable(activations, None)
    }

    /// Recheck the same selector map with bounded activation-row cancellation.
    ///
    /// # Errors
    /// As [`Self::check_selector_plan`], or typed constraint-system cancellation.
    pub fn check_selector_plan_cancellable(
        &self,
        activations: &[Vec<bool>],
        cancellation: Option<&iroha_pasta::CancellationToken>,
    ) -> Result<(), DescriptorError> {
        iroha_pasta::CancellationToken::checkpoint(cancellation).map_err(CsError::from)?;
        let entries = &self.selectors.entries;
        let n = self.n()?;
        if activations.len() != entries.len() || activations.iter().any(|rows| rows.len() != n) {
            return Err(DescriptorRule::Selectors.into());
        }
        if !self.selectors.compress {
            return Ok(());
        }
        let descriptions: Vec<SelectorDescription<'_>> = activations
            .iter()
            .zip(entries)
            .enumerate()
            .map(|(selector, (rows, entry))| SelectorDescription {
                selector,
                activations: rows,
                max_degree: usize::from(entry.max_degree),
            })
            .collect();
        let plan = selector_compression::plan_cancellable(
            &descriptions,
            usize::from(self.degree),
            cancellation,
        )
        .map_err(|error| match error {
            selector_compression::CompressionError::Cancelled => {
                DescriptorError::from(CsError::Cancelled)
            }
            _ => DescriptorError::from(DescriptorRule::Selectors),
        })?;
        for (combination, members) in plan.iter().enumerate() {
            iroha_pasta::CancellationToken::checkpoint(cancellation).map_err(CsError::from)?;
            for (member, selector) in members.iter().enumerate() {
                let entry = entries.get(*selector).ok_or(DescriptorRule::Selectors)?;
                if entry.combination as usize != combination
                    || usize::from(entry.root) != member + 1
                {
                    return Err(DescriptorRule::Selectors.into());
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use ff::Field;
    use iroha_pasta::{Fp, Fq};

    use super::*;
    use crate::cs::expression::Rotation;

    /// A circuit exercising every descriptor section.
    fn sample_cs<F: PastaField>() -> ConstraintSystem<F> {
        let mut cs = ConstraintSystem::<F>::new();
        let a = cs.advice_column();
        let b = cs.advice_column();
        let fixed = cs.fixed_column();
        let instance = cs.instance_column(3);
        let s0 = cs.selector();
        let s1 = cs.selector();
        let complex = cs.complex_selector();
        let table = cs.lookup_table_column();
        cs.enable_equality(a);
        cs.enable_equality(instance);
        cs.enable_constant(fixed);
        cs.create_gate("mul", |meta| {
            let s0 = meta.query_selector(s0);
            let a_cur = meta.query_advice(a, Rotation::cur());
            let b_cur = meta.query_advice(b, Rotation::cur());
            let a_next = meta.query_advice(a, Rotation::next());
            vec![s0 * (a_cur * b_cur - a_next) * F::from(3)]
        });
        cs.create_gate("bool", |meta| {
            let s1 = meta.query_selector(s1);
            let bit = meta.query_advice(b, Rotation::cur());
            let public = meta.query_instance(instance, Rotation::cur());
            vec![
                (
                    "bool",
                    s1.clone() * bit.clone() * (Expression::Constant(F::ONE) - bit),
                ),
                ("pub", -(s1 * public)),
            ]
        });
        cs.lookup("range", |meta| {
            let enabled = meta.query_selector(complex);
            let value = meta.query_advice(a, Rotation::cur());
            vec![(enabled * value, table)]
        });
        cs
    }

    fn activations(n: usize) -> Vec<Vec<bool>> {
        (0..3)
            .map(|s| (0..n).map(|row| row % 4 == s).collect())
            .collect()
    }

    fn config(curve: CurveV1, k: u32) -> DescriptorConfig {
        DescriptorConfig {
            curve,
            k,
            transcript: TranscriptV1::Blake2bChallenge255,
            instance_mode: InstanceModeV1::Committed,
            proof_suffix: ProofSuffixV1::None,
        }
    }

    fn sample_descriptor(compress: bool) -> CircuitDescriptorV1 {
        let finalized = sample_cs::<Fp>()
            .finalize(&activations(64), compress)
            .expect("finalize");
        CircuitDescriptorV1::from_constraint_system(&finalized, config(CurveV1::Vesta, 6))
            .expect("descriptor")
    }

    #[test]
    fn modulus_bytes_and_curves() {
        let p = modulus_le_bytes::<Fp>();
        let q = modulus_le_bytes::<Fq>();
        assert_eq!(p[31], 0x40);
        assert_eq!(p[0], 0x01);
        assert_ne!(p, q);
        assert_eq!(CurveV1::Vesta.scalar_modulus(), p);
        assert_eq!(CurveV1::Pallas.scalar_modulus(), q);
        assert_eq!(CurveV1::Pallas.base_modulus(), p);
        assert_eq!(CurveV1::Vesta.base_modulus(), q);
        assert!(is_canonical(&(-Fp::ONE).to_repr(), &p));
        assert!(!is_canonical(&p, &p));
        assert!(!is_canonical(&[0xff; 32], &p));
        assert!(is_canonical(&[0; 32], &p));
    }

    #[test]
    fn blake2b_personal_matches_reference_vectors() {
        // Python: hashlib.blake2b(b"abc", digest_size=64).hexdigest() (RFC 7693).
        let plain = blake2b_personal::<64>(&[0; 16], &[b"abc"]);
        assert_eq!(
            hex(&plain),
            "ba80a53f981c4d0d6a2797b69f12f6e94c212f14685ac4b74b12bb6fdbffa2d1\
             7d87c5392aab792dc252d5de4533cc9518d38aa8dbf1925ab92386edd4009923"
        );
        // Python: hashlib.blake2b(b"abc", digest_size=32, person=b"PIPA-v1-CircDesc").
        assert_eq!(
            hex(&descriptor_digest(b"abc")),
            "23d5475982e5c61115e164305cdc1c0940d46b9fcfb66d645c6b933cf547fece"
        );
        // Python: hashlib.blake2b(bytes(range(256)), digest_size=64,
        // person=b"Iroha-PlonkVK-v1"). Splitting the input across parts and
        // block boundaries changes nothing.
        let long: Vec<u8> = (0..=255).collect();
        let whole = blake2b_personal::<64>(TRANSCRIPT_REPR_PERSONA, &[&long]);
        assert_eq!(
            hex(&whole),
            "8bba4bf6154ac6dc9ee8a4318c8c1292b36736706edbf3d5581bcd43312f3880\
             d850c97024dbafb8f79e69f809a17ed403a394498489ec90a6cf77d13202c9c8"
        );
        let split = blake2b_personal::<64>(TRANSCRIPT_REPR_PERSONA, &[&long[..100], &long[100..]]);
        assert_eq!(whole, split);
        let three =
            blake2b_personal::<64>(TRANSCRIPT_REPR_PERSONA, &[&long[..128], &[], &long[128..]]);
        assert_eq!(whole, three);
        // The streaming hasher equals the one-shot digest for any split.
        for split in [0, 1, 63, 64, 65, 128, 200, 256] {
            let mut hasher = Blake2bPersonal::<64>::new(TRANSCRIPT_REPR_PERSONA);
            hasher.update(&long[..split]);
            for byte in &long[split..] {
                hasher.update(core::slice::from_ref(byte));
            }
            assert_eq!(hasher.finalize(), whole, "split {split}");
        }
        let mut short = Blake2bPersonal::<32>::new(DESCRIPTOR_DIGEST_PERSONA);
        short.update(b"ab");
        short.update(b"c");
        assert_eq!(short.finalize(), descriptor_digest(b"abc"));
    }

    fn hex(bytes: &[u8]) -> String {
        use core::fmt::Write as _;
        bytes.iter().fold(String::new(), |mut out, byte| {
            let _ = write!(out, "{byte:02x}");
            out
        })
    }

    #[test]
    fn pinned_params_table() {
        assert_eq!(PINNED_PARAMS_V1.len(), 22);
        assert!(pinned_params_digest(CurveV1::Pallas, 5).is_none());
        assert!(pinned_params_digest(CurveV1::Vesta, 17).is_none());
        assert_eq!(
            hex(&pinned_params_digest(CurveV1::Vesta, 6).expect("pinned")),
            "606ec71853588ea2414707e98ffb181091f6985d294d03d4165fb400a9a6b3a6"
        );
    }

    #[test]
    fn build_encode_decode_round_trip() {
        for compress in [true, false] {
            let descriptor = sample_descriptor(compress);
            let bytes = descriptor.encode().expect("encode");
            assert_eq!(CircuitDescriptorV1::decode(&bytes), Ok(descriptor.clone()));
            // Building twice gives identical bytes and digest.
            let again = sample_descriptor(compress);
            assert_eq!(again.encode().expect("encode"), bytes);
            assert_eq!(again.digest(), descriptor.digest());
            assert_eq!(descriptor.selectors.compress, compress);
        }
        assert_ne!(
            sample_descriptor(true).digest(),
            sample_descriptor(false).digest()
        );
    }

    #[test]
    fn descriptor_contents() {
        let d = sample_descriptor(true);
        assert_eq!(d.protocol_version, 1);
        assert_eq!(d.k, 6);
        assert_eq!(d.degree, 5, "the lookup c * a needs degree 5");
        assert_eq!((d.permutation_chunk_len, d.quotient_pieces), (3, 4));
        assert_eq!(d.blinding_factors, 5);
        assert_eq!(d.instance_lengths, vec![3]);
        assert_eq!(d.num_advice_columns, 2);
        assert_eq!(d.gates.len(), 2);
        assert_eq!(d.gates[1].len(), 2);
        assert_eq!(d.permutation.len(), 3);
        assert_eq!(d.lookups.len(), 1);
        // The first gate polynomial in postfix: q*(2-q) ... no: s0 shares with s1?
        // Both are simple selectors with disjoint rows; they combine.
        assert_eq!(d.selectors.entries.len(), 3);
        let s0 = d.selectors.entries[0];
        let s1 = d.selectors.entries[1];
        assert_eq!(s0.combination, s1.combination);
        assert_eq!((s0.root, s1.root), (1, 2));
        assert_eq!(d.selectors.entries[2].combination, 0, "complex first");
        assert_eq!(
            d.num_fixed_columns,
            d.selectors.first_column + 2,
            "two selector columns"
        );
        let postfix = &d.gates[0][0];
        assert!(matches!(postfix.last(), Some(ExprNodeV1::Scaled(_))));
    }

    #[test]
    fn transcript_repr_binds_digest_and_vk() {
        let digest = sample_descriptor(true).digest().expect("digest");
        let repr: Fp = transcript_repr(&digest, b"vk");
        assert_eq!(repr, transcript_repr::<Fp>(&digest, b"vk"));
        assert_ne!(repr, transcript_repr::<Fp>(&digest, b"vk2"));
        let mut other = digest;
        other[0] ^= 1;
        assert_ne!(repr, transcript_repr::<Fp>(&other, b"vk"));
    }

    #[test]
    fn build_rejects_wrong_field_and_unpinned_k() {
        let finalized = sample_cs::<Fp>()
            .finalize(&activations(64), true)
            .expect("finalize");
        assert_eq!(
            CircuitDescriptorV1::from_constraint_system(&finalized, config(CurveV1::Pallas, 6)),
            Err(DescriptorError::FieldMismatch)
        );
        assert_eq!(
            CircuitDescriptorV1::from_constraint_system(&finalized, config(CurveV1::Vesta, 5)),
            Err(DescriptorError::UnpinnedParams {
                curve: CurveV1::Vesta,
                k: 5
            })
        );
        let pallas = sample_cs::<Fq>()
            .finalize(&activations(64), true)
            .expect("finalize");
        assert!(
            CircuitDescriptorV1::from_constraint_system(&pallas, config(CurveV1::Pallas, 6))
                .is_ok()
        );
    }

    #[test]
    fn duplicate_queries_are_rejected() {
        let mut d = sample_descriptor(true);
        let first = d.advice_queries[0];
        d.advice_queries.push(first);
        assert_eq!(
            d.validate(),
            Err(DescriptorRule::DuplicateQuery.into()),
            "S2: a repeated (column, rotation) is a rejection"
        );
    }

    #[test]
    fn rotation_collisions_modulo_n_are_rejected() {
        let mut d = sample_descriptor(true);
        // Rotation 64 + 1 coincides with rotation 1 at k = 6.
        d.fixed_queries.push(QueryV1 {
            column: 0,
            rotation: 65,
        });
        assert_eq!(d.validate(), Err(DescriptorRule::RotationCollision.into()));
    }

    #[test]
    fn instance_lengths_are_exact_and_bounded() {
        let mut d = sample_descriptor(true);
        d.instance_lengths[0] = 64;
        assert_eq!(d.validate(), Err(DescriptorRule::InstanceLength.into()));
        let mut d = sample_descriptor(true);
        d.instance_lengths[0] = 4;
        assert_ne!(d.digest(), sample_descriptor(true).digest());
        assert_eq!(d.validate(), Ok(()));
    }

    /// Every rule is reachable by a single-field mutation.
    ///
    /// DEV-10 (spec section 14): the descriptor rules of section 4 are enforced at build time; the
    /// vendored stack has none.
    #[test]
    fn mutations_fail_the_named_rule() {
        type Mutation = fn(&mut CircuitDescriptorV1);
        let cases: Vec<(Mutation, DescriptorRule)> = vec![
            (|d| d.protocol_version = 2, DescriptorRule::Version),
            (|d| d.base_modulus[0] ^= 1, DescriptorRule::Moduli),
            (
                |d| d.scalar_modulus = d.base_modulus,
                DescriptorRule::Moduli,
            ),
            (|d| d.params_digest[0] ^= 1, DescriptorRule::ParamsDigest),
            (|d| d.k = 7, DescriptorRule::ParamsDigest),
            (|d| d.k = 0, DescriptorRule::Bounds),
            (|d| d.curve = CurveV1::Pallas, DescriptorRule::Moduli),
            (|d| d.degree = 10, DescriptorRule::Degree),
            (|d| d.degree = 4, DescriptorRule::Degree),
            (|d| d.permutation_chunk_len = 2, DescriptorRule::Degree),
            (|d| d.quotient_pieces = 5, DescriptorRule::Degree),
            (|d| d.blinding_factors = 4, DescriptorRule::BlindingFactors),
            (|d| d.blinding_factors = 6, DescriptorRule::BlindingFactors),
            (|d| d.num_advice_columns = 1, DescriptorRule::QueryColumn),
            (
                |d| d.instance_queries[0].column = 4,
                DescriptorRule::QueryColumn,
            ),
            (|d| d.gates[0][0].clear(), DescriptorRule::Expression),
            (|d| d.gates.push(vec![]), DescriptorRule::EmptyGate),
            (
                |d| d.gates[0][0].push(ExprNodeV1::Sum),
                DescriptorRule::Expression,
            ),
            (
                |d| d.gates[0][0].push(ExprNodeV1::Fixed(0)),
                DescriptorRule::Expression,
            ),
            (
                |d| d.gates[0][0][0] = ExprNodeV1::Advice(99),
                DescriptorRule::Expression,
            ),
            (
                |d| {
                    let modulus = d.scalar_modulus;
                    d.gates[0][0].push(ExprNodeV1::Scaled(modulus));
                },
                DescriptorRule::Expression,
            ),
            (
                |d| {
                    let poly = d.gates[0][0].clone();
                    let mut squared = poly.clone();
                    squared.extend(poly);
                    squared.push(ExprNodeV1::Product);
                    d.gates[0][0] = squared;
                },
                DescriptorRule::ExpressionDegree,
            ),
            (|d| d.lookups[0].tables.clear(), DescriptorRule::Lookup),
            (
                |d| {
                    let input = d.lookups[0].inputs[0].clone();
                    let mut cubed = input.clone();
                    cubed.extend(input.clone());
                    cubed.push(ExprNodeV1::Product);
                    d.lookups[0].inputs[0] = cubed;
                },
                DescriptorRule::Lookup,
            ),
            (
                |d| {
                    let first = d.permutation[0];
                    d.permutation.push(first);
                },
                DescriptorRule::Permutation,
            ),
            (|d| d.permutation[0].index = 7, DescriptorRule::Permutation),
            (
                |d| d.permutation[1].kind = ColumnKindV1::Fixed,
                DescriptorRule::Permutation,
            ),
            (|d| d.selectors.first_column += 1, DescriptorRule::Selectors),
            (
                |d| d.selectors.entries[0].root = 3,
                DescriptorRule::Selectors,
            ),
            (
                |d| d.selectors.entries[2].combination = 1,
                DescriptorRule::Selectors,
            ),
            (
                |d| {
                    d.selectors.entries.pop();
                },
                DescriptorRule::Selectors,
            ),
            (
                |d| d.selectors.entries[0].max_degree = 9,
                DescriptorRule::Selectors,
            ),
            (|d| d.selectors.compress = false, DescriptorRule::Selectors),
        ];
        let base = sample_descriptor(true);
        let base_digest = base.digest().expect("digest");
        for (index, (mutate, rule)) in cases.into_iter().enumerate() {
            let mut d = base.clone();
            mutate(&mut d);
            assert_eq!(
                d.validate(),
                Err(DescriptorError::Invalid(rule)),
                "case {index}"
            );
            // A mutated descriptor never shares the digest, and never decodes.
            if let Ok(digest) = d.digest() {
                assert_ne!(digest, base_digest, "case {index}");
            }
            if let Ok(bytes) = d.encode() {
                assert_eq!(
                    CircuitDescriptorV1::decode(&bytes),
                    Err(DescriptorError::Invalid(rule)),
                    "case {index}"
                );
            }
        }
    }

    #[test]
    fn valid_field_mutations_change_the_digest() {
        type Mutation = fn(&mut CircuitDescriptorV1);
        let cases: Vec<Mutation> = vec![
            |d| d.transcript = TranscriptV1::KagemushaPoseidonRp57,
            |d| d.instance_mode = InstanceModeV1::Direct,
            |d| d.proof_suffix = ProofSuffixV1::FoldedGenerator,
            |d| d.instance_lengths[0] = 1,
            |d| {
                if let Some(ExprNodeV1::Scaled(factor)) = d.gates[0][0].last_mut() {
                    factor[0] ^= 1;
                }
            },
            |d| d.gates.swap(0, 1),
        ];
        let base = sample_descriptor(true);
        let base_digest = base.digest().expect("digest");
        for (index, mutate) in cases.into_iter().enumerate() {
            let mut d = base.clone();
            mutate(&mut d);
            assert_eq!(d.validate(), Ok(()), "case {index}");
            assert_ne!(d.digest().expect("digest"), base_digest, "case {index}");
            let bytes = d.encode().expect("encode");
            assert_eq!(CircuitDescriptorV1::decode(&bytes), Ok(d), "case {index}");
        }
    }

    #[test]
    fn decode_rejects_non_canonical_frames() {
        let bytes = sample_descriptor(true).encode().expect("encode");
        let mut trailing = bytes.clone();
        trailing.push(0);
        assert_eq!(
            CircuitDescriptorV1::decode(&trailing),
            Err(DescriptorRule::Decode.into())
        );
        assert_eq!(
            CircuitDescriptorV1::decode(&bytes[..bytes.len() - 1]),
            Err(DescriptorRule::Decode.into())
        );
        let mut flipped = bytes.clone();
        let last = flipped.len() - 1;
        flipped[last] ^= 0x80;
        assert!(CircuitDescriptorV1::decode(&flipped).is_err());
        assert_eq!(
            CircuitDescriptorV1::decode(&[]),
            Err(DescriptorRule::Decode.into())
        );
        let oversized = vec![0_u8; MAX_DESCRIPTOR_BYTES + 1];
        assert_eq!(
            CircuitDescriptorV1::decode(&oversized),
            Err(DescriptorRule::FrameTooLarge.into())
        );
    }

    #[test]
    fn selector_plan_registration_check() {
        let d = sample_descriptor(true);
        assert_eq!(d.check_selector_plan(&activations(64)), Ok(()));
        // Overlapping s0 and s1 rows force separate combinations.
        let mut overlapping = activations(64);
        overlapping[1][0] = true;
        assert_eq!(
            d.check_selector_plan(&overlapping),
            Err(DescriptorRule::Selectors.into())
        );
        assert_eq!(
            d.check_selector_plan(&activations(32)),
            Err(DescriptorRule::Selectors.into())
        );
        let direct = sample_descriptor(false);
        assert_eq!(direct.check_selector_plan(&overlapping), Ok(()));
    }

    #[test]
    fn zero_knowledge_budget_and_rule_numbers() {
        let mut d = sample_descriptor(true);
        assert_eq!(d.check_zero_knowledge(), Ok(()));
        d.blinding_factors = 3;
        assert_eq!(
            d.check_zero_knowledge(),
            Err(DescriptorRule::ZeroKnowledgeBudget)
        );
        let rules = [
            (DescriptorRule::Decode, 1),
            (DescriptorRule::FrameTooLarge, 1),
            (DescriptorRule::Bounds, 1),
            (DescriptorRule::Version, 2),
            (DescriptorRule::Moduli, 2),
            (DescriptorRule::ParamsDigest, 2),
            (DescriptorRule::Degree, 3),
            (DescriptorRule::BlindingFactors, 4),
            (DescriptorRule::InstanceLength, 4),
            (DescriptorRule::QueryColumn, 5),
            (DescriptorRule::DuplicateQuery, 5),
            (DescriptorRule::RotationCollision, 5),
            (DescriptorRule::Expression, 6),
            (DescriptorRule::ExpressionDegree, 6),
            (DescriptorRule::EmptyGate, 6),
            (DescriptorRule::Lookup, 6),
            (DescriptorRule::Permutation, 7),
            (DescriptorRule::Selectors, 8),
            (DescriptorRule::ZeroKnowledgeBudget, 9),
        ];
        for (rule, number) in rules {
            assert_eq!(rule.rule_number(), number);
            assert!(!DescriptorError::Invalid(rule).to_string().is_empty());
        }
        for error in [
            DescriptorError::ConstraintSystem(Box::new(CsError::Overflow)),
            DescriptorError::FieldMismatch,
            DescriptorError::UnsubstitutedSelector,
            DescriptorError::UninternedQuery,
            DescriptorError::UnpinnedParams {
                curve: CurveV1::Pallas,
                k: 3,
            },
            DescriptorError::Encode,
        ] {
            assert!(!error.to_string().is_empty());
        }
    }

    #[test]
    fn postfix_rejects_unsubstituted_selectors() {
        let cs = sample_cs::<Fp>();
        let poly = &cs.gates()[0].polynomials()[0];
        assert_eq!(
            postfix(poly, &cs),
            Err(DescriptorError::UnsubstitutedSelector)
        );
        let stray = Expression::<Fp>::Advice(crate::cs::expression::AdviceQuery {
            column_index: 0,
            rotation: Rotation(5),
        });
        assert_eq!(postfix(&stray, &cs), Err(DescriptorError::UninternedQuery));
    }

    #[test]
    fn expression_degree_stack_machine() {
        let modulus = modulus_le_bytes::<Fp>();
        let context = ExpressionContext {
            fixed: 1,
            advice: 1,
            instance: 1,
            modulus: &modulus,
        };
        let one = Fp::ONE.to_repr();
        let ok = [
            ExprNodeV1::Advice(0),
            ExprNodeV1::Fixed(0),
            ExprNodeV1::Product,
            ExprNodeV1::Instance(0),
            ExprNodeV1::Sum,
            ExprNodeV1::Negated,
            ExprNodeV1::Scaled(one),
            ExprNodeV1::Constant(one),
            ExprNodeV1::Product,
        ];
        assert_eq!(expression_degree(&ok, &context), Ok(2));
        assert_eq!(
            expression_degree(&[ExprNodeV1::Negated], &context),
            Err(DescriptorRule::Expression)
        );
        assert_eq!(
            expression_degree(&[ExprNodeV1::Scaled(one)], &context),
            Err(DescriptorRule::Expression)
        );
        assert_eq!(
            expression_degree(&[ExprNodeV1::Instance(1)], &context),
            Err(DescriptorRule::Expression)
        );
        let deep = vec![ExprNodeV1::Constant(one); MAX_EXPRESSION_STACK + 1];
        assert_eq!(
            expression_degree(&deep, &context),
            Err(DescriptorRule::Expression)
        );
        assert_eq!(ceil_log2(1), 0);
        assert_eq!(ceil_log2(4), 2);
        assert_eq!(ceil_log2(5), 3);
    }
}
