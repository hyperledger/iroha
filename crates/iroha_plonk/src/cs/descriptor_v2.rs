//! Explicit V2 descriptor and the common, non-wire protocol description.
//!
//! V1 admission remains explicit for retained consumers. V2 admission never
//! attempts V1 decoding. Both schemas normalize into the same arithmetic
//! description; transcript profiles and instance types remain explicit.

use super::descriptor::*;
use iroha_pasta::{Fp, PastaField};
use norito::{NoritoDeserialize, NoritoSchema, NoritoSerialize};
use std::borrow::Cow;

/// V2 Fiat–Shamir profiles.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, Hash, NoritoSerialize, NoritoDeserialize, NoritoSchema,
)]
#[norito_schema(name = "iroha.plonk.pipa.TranscriptV2")]
pub enum TranscriptV2 {
    /// The retained `BLAKE2b` profile.
    Blake2bChallenge255,
    /// The retained scalar-field Poseidon profile.
    KagemushaPoseidonRp57,
    /// PIPA-R: RP57 Poseidon in the proof curve's base field.
    KagemushaPoseidonRp57Base,
}
impl From<TranscriptV1> for TranscriptV2 {
    fn from(value: TranscriptV1) -> Self {
        match value {
            TranscriptV1::Blake2bChallenge255 => Self::Blake2bChallenge255,
            TranscriptV1::KagemushaPoseidonRp57 => Self::KagemushaPoseidonRp57,
        }
    }
}

/// The integer range of every value in one instance column.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, Hash, NoritoSerialize, NoritoDeserialize, NoritoSchema,
)]
#[norito_schema(name = "iroha.plonk.pipa.InstanceTypeV2")]
pub enum InstanceType {
    /// A canonical element of the proof scalar field.
    Field,
    /// An integer strictly below the smaller Pasta modulus p.
    Bounded,
    /// An integer strictly below 2^b, for 0 <= b <= 253.
    Bits(u8),
}
impl InstanceType {
    /// Its single-element transcript tag.
    #[must_use]
    pub const fn code(self) -> u64 {
        match self {
            Self::Field => 0,
            Self::Bounded => 1,
            Self::Bits(bits) => 2 + bits as u64,
        }
    }
    /// Whether a canonical scalar belongs to this declared type.
    #[must_use]
    pub fn contains<F: PastaField>(self, value: &F) -> bool {
        match self {
            Self::Field => true,
            Self::Bounded => {
                bool::from(Fp::from_canonical_limbs(value.to_canonical_limbs()).is_some())
            }
            Self::Bits(bits) if bits <= 253 => {
                let limbs = value.to_canonical_limbs();
                (usize::from(bits)..256).all(|bit| (limbs[bit / 64] >> (bit % 64)) & 1 == 0)
            }
            Self::Bits(_) => false,
        }
    }
}

/// The canonical V2 wire descriptor (protocol version remains one).
#[derive(Clone, Debug, PartialEq, Eq, Hash, NoritoSerialize, NoritoDeserialize, NoritoSchema)]
#[norito_schema(name = "iroha.plonk.pipa.circuit_descriptor.v2")]
pub struct CircuitDescriptorV2 {
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
    pub transcript: TranscriptV2,
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
    /// One declared type per instance column.
    pub instance_types: Vec<InstanceType>,
}

/// Common descriptor data used by protocol arithmetic; not a wire format.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProtocolDescriptor {
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
    pub transcript: TranscriptV2,
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
    /// Typed instances for V2, absent for the retained V1 schema.
    pub instance_types: Option<Vec<InstanceType>>,
}

/// A descriptor that can provide the common protocol arithmetic data.
pub trait DescriptorSource {
    /// Its explicit normalized description.
    fn protocol_descriptor(&self) -> Cow<'_, ProtocolDescriptor>;
}
impl DescriptorSource for ProtocolDescriptor {
    fn protocol_descriptor(&self) -> Cow<'_, ProtocolDescriptor> {
        Cow::Borrowed(self)
    }
}
impl DescriptorSource for CircuitDescriptorV1 {
    fn protocol_descriptor(&self) -> Cow<'_, ProtocolDescriptor> {
        Cow::Owned(self.into())
    }
}
impl DescriptorSource for CircuitDescriptorV2 {
    fn protocol_descriptor(&self) -> Cow<'_, ProtocolDescriptor> {
        Cow::Owned(self.into())
    }
}
impl From<&CircuitDescriptorV1> for ProtocolDescriptor {
    fn from(value: &CircuitDescriptorV1) -> Self {
        Self {
            protocol_version: value.protocol_version,
            curve: value.curve,
            base_modulus: value.base_modulus,
            scalar_modulus: value.scalar_modulus,
            params_digest: value.params_digest,
            k: value.k,
            transcript: value.transcript.into(),
            instance_mode: value.instance_mode,
            proof_suffix: value.proof_suffix,
            degree: value.degree,
            blinding_factors: value.blinding_factors,
            permutation_chunk_len: value.permutation_chunk_len,
            quotient_pieces: value.quotient_pieces,
            lookup_kind: value.lookup_kind,
            num_fixed_columns: value.num_fixed_columns,
            num_advice_columns: value.num_advice_columns,
            instance_lengths: value.instance_lengths.clone(),
            fixed_queries: value.fixed_queries.clone(),
            advice_queries: value.advice_queries.clone(),
            instance_queries: value.instance_queries.clone(),
            selectors: value.selectors.clone(),
            gates: value.gates.clone(),
            permutation: value.permutation.clone(),
            lookups: value.lookups.clone(),
            instance_types: None,
        }
    }
}
impl From<&CircuitDescriptorV2> for ProtocolDescriptor {
    fn from(value: &CircuitDescriptorV2) -> Self {
        Self {
            protocol_version: value.protocol_version,
            curve: value.curve,
            base_modulus: value.base_modulus,
            scalar_modulus: value.scalar_modulus,
            params_digest: value.params_digest,
            k: value.k,
            transcript: value.transcript,
            instance_mode: value.instance_mode,
            proof_suffix: value.proof_suffix,
            degree: value.degree,
            blinding_factors: value.blinding_factors,
            permutation_chunk_len: value.permutation_chunk_len,
            quotient_pieces: value.quotient_pieces,
            lookup_kind: value.lookup_kind,
            num_fixed_columns: value.num_fixed_columns,
            num_advice_columns: value.num_advice_columns,
            instance_lengths: value.instance_lengths.clone(),
            fixed_queries: value.fixed_queries.clone(),
            advice_queries: value.advice_queries.clone(),
            instance_queries: value.instance_queries.clone(),
            selectors: value.selectors.clone(),
            gates: value.gates.clone(),
            permutation: value.permutation.clone(),
            lookups: value.lookups.clone(),
            instance_types: Some(value.instance_types.clone()),
        }
    }
}

impl PartialEq<CircuitDescriptorV1> for ProtocolDescriptor {
    fn eq(&self, other: &CircuitDescriptorV1) -> bool {
        self.instance_types.is_none()
            && self.protocol_version == other.protocol_version
            && self.curve == other.curve
            && self.base_modulus == other.base_modulus
            && self.scalar_modulus == other.scalar_modulus
            && self.params_digest == other.params_digest
            && self.k == other.k
            && self.transcript == TranscriptV2::from(other.transcript)
            && self.instance_mode == other.instance_mode
            && self.proof_suffix == other.proof_suffix
            && self.degree == other.degree
            && self.blinding_factors == other.blinding_factors
            && self.permutation_chunk_len == other.permutation_chunk_len
            && self.quotient_pieces == other.quotient_pieces
            && self.lookup_kind == other.lookup_kind
            && self.num_fixed_columns == other.num_fixed_columns
            && self.num_advice_columns == other.num_advice_columns
            && self.instance_lengths == other.instance_lengths
            && self.fixed_queries == other.fixed_queries
            && self.advice_queries == other.advice_queries
            && self.instance_queries == other.instance_queries
            && self.selectors == other.selectors
            && self.gates == other.gates
            && self.permutation == other.permutation
            && self.lookups == other.lookups
    }
}

impl PartialEq<ProtocolDescriptor> for CircuitDescriptorV1 {
    fn eq(&self, other: &ProtocolDescriptor) -> bool {
        other == self
    }
}

impl CircuitDescriptorV2 {
    /// Uses a finalized V1 arithmetization with an explicit V2 transcript and types.
    /// No V1 encoding or digest is included in the V2 frame.
    ///
    /// # Errors
    /// A shared arithmetic rule, instance type or transcript profile is invalid.
    pub fn from_layout(
        layout: CircuitDescriptorV1,
        transcript: TranscriptV2,
        instance_types: Vec<InstanceType>,
    ) -> Result<Self, DescriptorError> {
        let descriptor = Self {
            protocol_version: layout.protocol_version,
            curve: layout.curve,
            base_modulus: layout.base_modulus,
            scalar_modulus: layout.scalar_modulus,
            params_digest: layout.params_digest,
            k: layout.k,
            transcript,
            instance_mode: layout.instance_mode,
            proof_suffix: layout.proof_suffix,
            degree: layout.degree,
            blinding_factors: layout.blinding_factors,
            permutation_chunk_len: layout.permutation_chunk_len,
            quotient_pieces: layout.quotient_pieces,
            lookup_kind: layout.lookup_kind,
            num_fixed_columns: layout.num_fixed_columns,
            num_advice_columns: layout.num_advice_columns,
            instance_lengths: layout.instance_lengths,
            fixed_queries: layout.fixed_queries,
            advice_queries: layout.advice_queries,
            instance_queries: layout.instance_queries,
            selectors: layout.selectors,
            gates: layout.gates,
            permutation: layout.permutation,
            lookups: layout.lookups,
            instance_types,
        };
        descriptor.validate()?;
        Ok(descriptor)
    }

    /// Validates the arithmetic and the V2 profile.
    ///
    /// # Errors
    /// The first failed arithmetic, instance-type or profile rule.
    pub fn validate(&self) -> Result<(), DescriptorError> {
        // The V1 validator owns the shared arithmetic rules, not V2's
        // transcript or binding. Its temporary profile has no protocol use.
        let arithmetic = CircuitDescriptorV1 {
            protocol_version: self.protocol_version,
            curve: self.curve,
            base_modulus: self.base_modulus,
            scalar_modulus: self.scalar_modulus,
            params_digest: self.params_digest,
            k: self.k,
            transcript: TranscriptV1::Blake2bChallenge255,
            instance_mode: self.instance_mode,
            proof_suffix: self.proof_suffix,
            degree: self.degree,
            blinding_factors: self.blinding_factors,
            permutation_chunk_len: self.permutation_chunk_len,
            quotient_pieces: self.quotient_pieces,
            lookup_kind: self.lookup_kind,
            num_fixed_columns: self.num_fixed_columns,
            num_advice_columns: self.num_advice_columns,
            instance_lengths: self.instance_lengths.clone(),
            fixed_queries: self.fixed_queries.clone(),
            advice_queries: self.advice_queries.clone(),
            instance_queries: self.instance_queries.clone(),
            selectors: self.selectors.clone(),
            gates: self.gates.clone(),
            permutation: self.permutation.clone(),
            lookups: self.lookups.clone(),
        };
        arithmetic.validate()?;
        if self.instance_types.len() != self.instance_lengths.len()
            || self
                .instance_types
                .iter()
                .any(|ty| matches!(ty, InstanceType::Bits(bits) if *bits > 253))
        {
            return Err(DescriptorRule::InstanceType.into());
        }
        if self.transcript == TranscriptV2::KagemushaPoseidonRp57Base
            && (self.instance_mode != InstanceModeV1::Direct
                || self.proof_suffix != ProofSuffixV1::FoldedGenerator)
        {
            return Err(DescriptorRule::TranscriptProfile.into());
        }
        Ok(())
    }

    /// Encodes one canonical V2 frame.
    ///
    /// # Errors
    /// Canonical encoding fails or exceeds the descriptor byte limit.
    pub fn encode(&self) -> Result<Vec<u8>, DescriptorError> {
        let bytes = norito::encode_canonical(self).map_err(|_| DescriptorError::Encode)?;
        if bytes.len() > MAX_DESCRIPTOR_BYTES {
            return Err(DescriptorRule::FrameTooLarge.into());
        }
        Ok(bytes)
    }

    /// Admits exactly one canonical V2 frame; no V1 fallback is attempted.
    ///
    /// # Errors
    /// The frame is not canonical V2 or a descriptor rule fails.
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

    /// The V2-domain digest of the canonical frame.
    ///
    /// # Errors
    /// Canonical encoding fails or exceeds the descriptor byte limit.
    pub fn digest(&self) -> Result<[u8; 32], DescriptorError> {
        Ok(descriptor_digest_v2(&self.encode()?))
    }
}

/// V2 descriptor digest, with a domain distinct from V1.
#[must_use]
pub fn descriptor_digest_v2(bytes: &[u8]) -> [u8; 32] {
    blake2b_personal::<32>(b"PIPA-v2-CircDesc", &[bytes])
}

impl ProtocolDescriptor {
    /// Validates the VK selector activation against the shared selector plan.
    ///
    /// # Errors
    /// The activation rows do not reproduce the declared selector plan.
    pub fn check_selector_plan(&self, selectors: &[Vec<bool>]) -> Result<(), DescriptorError> {
        self.arithmetic_layout().check_selector_plan(selectors)
    }

    /// Recheck the same selector map with operation-local cancellation.
    ///
    /// # Errors
    /// As [`Self::check_selector_plan`], or typed constraint-system cancellation.
    pub fn check_selector_plan_cancellable(
        &self,
        selectors: &[Vec<bool>],
        cancellation: Option<&iroha_pasta::CancellationToken>,
    ) -> Result<(), DescriptorError> {
        iroha_pasta::CancellationToken::checkpoint(cancellation).map_err(super::CsError::from)?;
        self.arithmetic_layout()
            .check_selector_plan_cancellable(selectors, cancellation)
    }

    /// The common arithmetic in the retained validator's input type. The
    /// temporary hash profile is never used for binding or transcript dispatch.
    pub(crate) fn arithmetic_layout(&self) -> CircuitDescriptorV1 {
        CircuitDescriptorV1 {
            protocol_version: self.protocol_version,
            curve: self.curve,
            base_modulus: self.base_modulus,
            scalar_modulus: self.scalar_modulus,
            params_digest: self.params_digest,
            k: self.k,
            transcript: TranscriptV1::Blake2bChallenge255,
            instance_mode: self.instance_mode,
            proof_suffix: self.proof_suffix,
            degree: self.degree,
            blinding_factors: self.blinding_factors,
            permutation_chunk_len: self.permutation_chunk_len,
            quotient_pieces: self.quotient_pieces,
            lookup_kind: self.lookup_kind,
            num_fixed_columns: self.num_fixed_columns,
            num_advice_columns: self.num_advice_columns,
            instance_lengths: self.instance_lengths.clone(),
            fixed_queries: self.fixed_queries.clone(),
            advice_queries: self.advice_queries.clone(),
            instance_queries: self.instance_queries.clone(),
            selectors: self.selectors.clone(),
            gates: self.gates.clone(),
            permutation: self.permutation.clone(),
            lookups: self.lookups.clone(),
        }
    }
    /// Returns the first instance value outside its declared integer type.
    #[must_use]
    pub fn invalid_instance<F: PastaField>(&self, instances: &[Vec<F>]) -> Option<(usize, usize)> {
        let types = self.instance_types.as_ref()?;
        for (column, (ty, values)) in types.iter().zip(instances).enumerate() {
            if let Some(row) = values.iter().position(|value| !ty.contains(value)) {
                return Some((column, row));
            }
        }
        None
    }
}
impl TranscriptV2 {
    /// The retained scalar profile, when this is not PIPA-R.
    #[must_use]
    pub const fn retained(self) -> Option<TranscriptV1> {
        match self {
            Self::Blake2bChallenge255 => Some(TranscriptV1::Blake2bChallenge255),
            Self::KagemushaPoseidonRp57 => Some(TranscriptV1::KagemushaPoseidonRp57),
            Self::KagemushaPoseidonRp57Base => None,
        }
    }
}

impl From<CircuitDescriptorV1> for ProtocolDescriptor {
    fn from(value: CircuitDescriptorV1) -> Self {
        Self {
            protocol_version: value.protocol_version,
            curve: value.curve,
            base_modulus: value.base_modulus,
            scalar_modulus: value.scalar_modulus,
            params_digest: value.params_digest,
            k: value.k,
            transcript: value.transcript.into(),
            instance_mode: value.instance_mode,
            proof_suffix: value.proof_suffix,
            degree: value.degree,
            blinding_factors: value.blinding_factors,
            permutation_chunk_len: value.permutation_chunk_len,
            quotient_pieces: value.quotient_pieces,
            lookup_kind: value.lookup_kind,
            num_fixed_columns: value.num_fixed_columns,
            num_advice_columns: value.num_advice_columns,
            instance_lengths: value.instance_lengths,
            fixed_queries: value.fixed_queries,
            advice_queries: value.advice_queries,
            instance_queries: value.instance_queries,
            selectors: value.selectors,
            gates: value.gates,
            permutation: value.permutation,
            lookups: value.lookups,
            instance_types: None,
        }
    }
}

impl From<CircuitDescriptorV2> for ProtocolDescriptor {
    fn from(value: CircuitDescriptorV2) -> Self {
        Self {
            protocol_version: value.protocol_version,
            curve: value.curve,
            base_modulus: value.base_modulus,
            scalar_modulus: value.scalar_modulus,
            params_digest: value.params_digest,
            k: value.k,
            transcript: value.transcript,
            instance_mode: value.instance_mode,
            proof_suffix: value.proof_suffix,
            degree: value.degree,
            blinding_factors: value.blinding_factors,
            permutation_chunk_len: value.permutation_chunk_len,
            quotient_pieces: value.quotient_pieces,
            lookup_kind: value.lookup_kind,
            num_fixed_columns: value.num_fixed_columns,
            num_advice_columns: value.num_advice_columns,
            instance_lengths: value.instance_lengths,
            fixed_queries: value.fixed_queries,
            advice_queries: value.advice_queries,
            instance_queries: value.instance_queries,
            selectors: value.selectors,
            gates: value.gates,
            permutation: value.permutation,
            lookups: value.lookups,
            instance_types: Some(value.instance_types),
        }
    }
}
