//! Key generation, proving and verification of the step relations
//! ([`SigmaProver`], [`SigmaVerifier`]), and the σ verifying-key allowlist a
//! consumer selects them from ([`SigmaAllowlist`], owner answer Q11).
//!
//! A verifier needs only the descriptor bytes, the verifying-key bytes, the
//! pinned parameters of `k` and the public input (spec section 8): it never
//! configures the circuit. [`SigmaProver::prove`] refuses a witness that
//! breaks the relation ([`SigmaError::RelationViolated`]) before the engine
//! runs; the circuit itself has no satisfying assignment for one either.
//!
//! # Allowlist
//!
//! Statements carry one scheme-level relation identity; a consumer selects
//! σ's verifying key by the operation tag and, for Send, by Ω(pred)'s
//! enabled-controls mask: the G1 selector `(tag, mask)`
//! ([`SigmaRelation::selector`]). [`SigmaAllowlist`] holds one verifier per
//! selector and emits the G1 `KagemushaWalletVerifyingKeyEntryV1`
//! transcript of each entry ([`VerifyingKeyEntry`]) with its exact proof
//! length.

use core::fmt;

use iroha_pasta::{PastaCurve, msm::MemoryBudget, poseidon::PoseidonField};
use iroha_plonk::{
    DescriptorBinding, KeyError, Protocol, ProverConfig, ProverError, ProverRandomness, ProvingKey,
    VerifyError, VerifyingKey,
    cs::{CsError, DescriptorError},
    frontend::Error,
    keys::{KeygenConfig, VkError, keygen_pk},
    pcs::ipa::{ParamsTrustError, PinnedParams},
    prove_circuit, verify_full,
};
use iroha_plonk_gadgets::statement::StepRelation;

use crate::{
    circuit::{ParamsError, SigmaCircuit},
    shape::{ProofFormat, SigmaShape},
    witness::{SigmaRelation, StepPublic, StepWitness, Violation},
};

/// Why a step-relation operation failed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SigmaError {
    /// The circuit parameters are invalid.
    Params(ParamsError),
    /// The relation does not fit `k`.
    DoesNotFit {
        /// The `k` tried.
        k: u32,
    },
    /// No shape in the policy's range fits and meets the byte budget.
    NoShape,
    /// Synthesis failed.
    Synthesis(Error),
    /// The constraint system could not be finalized.
    ConstraintSystem(CsError),
    /// The descriptor is invalid.
    Descriptor(DescriptorError),
    /// The protocol tables could not be derived.
    Protocol(iroha_plonk::ProtocolError),
    /// The curve is not a descriptor curve (never for the Pasta curves).
    UnknownCurve,
    /// The parameters could not be derived or are not pinned.
    ParamsTrust(ParamsTrustError),
    /// The parameters have another `k` than the shape.
    ParamsK {
        /// The shape's `k`.
        expected: u32,
        /// The parameters' `k`.
        found: u32,
    },
    /// Key generation failed.
    Key(KeyError),
    /// The verifying key failed strict decoding.
    VerifyingKey(VkError),
    /// The witness belongs to another step relation.
    WrongRelation {
        /// The circuit's relation.
        expected: StepRelation,
        /// The witness's relation.
        found: StepRelation,
    },
    /// The witness breaks the relation.
    RelationViolated(Vec<Violation>),
    /// The allowlist has no verifier for the selector `(tag, mask)`.
    NoVerifier((u8, u32)),
    /// The allowlist already has a verifier for the selector `(tag, mask)`.
    DuplicateSelector((u8, u32)),
    /// A proof length does not fit the allowlist's `u32` field.
    ProofLength(usize),
    /// The engine failed to prove.
    Prover(ProverError),
    /// The proof was rejected.
    Verify(VerifyError),
}

impl fmt::Display for SigmaError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Params(error) => write!(f, "parameters: {error}"),
            Self::DoesNotFit { k } => write!(f, "the relation does not fit k = {k}"),
            Self::NoShape => f.write_str("no shape fits the policy"),
            Self::Synthesis(error) => write!(f, "synthesis: {error}"),
            Self::ConstraintSystem(error) => write!(f, "constraint system: {error}"),
            Self::Descriptor(error) => write!(f, "descriptor: {error}"),
            Self::Protocol(error) => write!(f, "protocol: {error}"),
            Self::UnknownCurve => f.write_str("the curve is not a descriptor curve"),
            Self::ParamsTrust(error) => write!(f, "parameters: {error}"),
            Self::ParamsK { expected, found } => {
                write!(
                    f,
                    "parameters for k = {found}, the shape needs k = {expected}"
                )
            }
            Self::Key(error) => write!(f, "key generation: {error}"),
            Self::VerifyingKey(error) => write!(f, "verifying key: {error}"),
            Self::WrongRelation { expected, found } => {
                write!(f, "a {found:?} witness for a {expected:?} circuit")
            }
            Self::RelationViolated(violations) => {
                write!(f, "the witness breaks the relation: {violations:?}")
            }
            Self::NoVerifier(selector) => {
                write!(f, "no allowlisted verifier for selector {selector:?}")
            }
            Self::DuplicateSelector(selector) => {
                write!(f, "selector {selector:?} is already allowlisted")
            }
            Self::ProofLength(bytes) => write!(f, "a proof length of {bytes} bytes"),
            Self::Prover(error) => write!(f, "prover: {error}"),
            Self::Verify(error) => write!(f, "verifier: {error:?}"),
        }
    }
}

impl std::error::Error for SigmaError {}

/// Memory and speed choices of a proving key. They change neither the
/// verifying key nor any proof byte.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct KeyOptions {
    /// The budget of each fixed-base commitment table (of `g` and
    /// `g_lagrange`), or `None` for no tables. At the budget shape
    /// (`k = 12`, one lane) the pair saves about 4-6% of the one-thread
    /// prove CPU and raises the single-prover peak RSS by about 11 MiB
    /// (M12 stage FIX, medians of three processes each).
    pub commitment_tables: Option<MemoryBudget>,
}

impl KeyOptions {
    /// Fixed-base tables of at most 8 MiB each.
    pub const WITH_TABLES: Self = Self {
        commitment_tables: Some(MemoryBudget::new(8 << 20)),
    };
}

/// A step proof and the public input it proves.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SigmaProof<F> {
    /// The public input.
    pub public: StepPublic<F>,
    /// The proof bytes.
    pub bytes: Vec<u8>,
}

/// The public input as the single instance column.
fn instance<F: Copy>(public: &StepPublic<F>) -> Vec<Vec<F>> {
    vec![public.instance()]
}

/// The proving side of one step shape: parameters and proving key.
#[derive(Clone, Debug)]
pub struct SigmaProver<C: PastaCurve> {
    shape: SigmaShape,
    format: ProofFormat,
    params: PinnedParams<C>,
    pk: ProvingKey<C>,
}

impl<C: PastaCurve> SigmaProver<C>
where
    C::ScalarExt: PoseidonField,
{
    /// Derives the parameters of `shape.k` and generates the keys.
    ///
    /// # Errors
    ///
    /// [`SigmaError::ParamsTrust`] from the derivation, and the errors of
    /// [`Self::keygen_with_params`].
    pub fn keygen(shape: SigmaShape, format: ProofFormat) -> Result<Self, SigmaError> {
        let params = PinnedParams::derive(shape.k).map_err(SigmaError::ParamsTrust)?;
        Self::keygen_with_params(shape, format, params)
    }

    /// Generates the keys with already derived or pinned `params` and the
    /// default [`KeyOptions`].
    ///
    /// # Errors
    ///
    /// As [`Self::keygen_with_options`].
    pub fn keygen_with_params(
        shape: SigmaShape,
        format: ProofFormat,
        params: PinnedParams<C>,
    ) -> Result<Self, SigmaError> {
        Self::keygen_with_options(shape, format, params, KeyOptions::default())
    }

    /// Generates the keys with already derived or pinned `params` and
    /// `options` (which change memory and speed, never a key or proof byte).
    ///
    /// # Errors
    ///
    /// [`SigmaError::ParamsK`] when `params` are for another `k`, and
    /// [`SigmaError::Key`] from key generation (a shape that does not fit
    /// included).
    pub fn keygen_with_options(
        shape: SigmaShape,
        format: ProofFormat,
        params: PinnedParams<C>,
        options: KeyOptions,
    ) -> Result<Self, SigmaError> {
        if params.k() != shape.k {
            return Err(SigmaError::ParamsK {
                expected: shape.k,
                found: params.k(),
            });
        }
        let mut config = KeygenConfig::new(format.transcript);
        config.instance_mode = format.instance_mode;
        config.proof_suffix = format.proof_suffix;
        config.table_budget = options.commitment_tables;
        let circuit = SigmaCircuit::<C::ScalarExt>::keygen(shape.params);
        let pk = keygen_pk(&params, &circuit, &config).map_err(SigmaError::Key)?;
        Ok(Self {
            shape,
            format,
            params,
            pk,
        })
    }

    /// The shape.
    #[must_use]
    pub const fn shape(&self) -> &SigmaShape {
        &self.shape
    }

    /// The proof format.
    #[must_use]
    pub const fn format(&self) -> ProofFormat {
        self.format
    }

    /// The parameters.
    #[must_use]
    pub const fn params(&self) -> &PinnedParams<C> {
        &self.params
    }

    /// The proving key.
    #[must_use]
    pub const fn proving_key(&self) -> &ProvingKey<C> {
        &self.pk
    }

    /// The circuit of `witness` under this shape.
    ///
    /// # Errors
    ///
    /// [`SigmaError::WrongRelation`] for a witness of the other step.
    pub fn circuit(
        &self,
        witness: &StepWitness<C::ScalarExt>,
    ) -> Result<SigmaCircuit<C::ScalarExt>, SigmaError> {
        let expected = self.shape.params.relation().step();
        let found = witness.relation();
        if expected != found {
            return Err(SigmaError::WrongRelation { expected, found });
        }
        Ok(SigmaCircuit::new(self.shape.params, witness.clone()))
    }

    /// Proves `witness` with `randomness` (on the caller's Rayon pool).
    ///
    /// # Errors
    ///
    /// [`SigmaError::WrongRelation`], [`SigmaError::RelationViolated`] for a
    /// witness that breaks the relation (checked natively first), and
    /// [`SigmaError::Prover`] from the engine.
    pub fn prove(
        &self,
        witness: &StepWitness<C::ScalarExt>,
        randomness: ProverRandomness<'_>,
    ) -> Result<SigmaProof<C::ScalarExt>, SigmaError> {
        let circuit = self.circuit(witness)?;
        let native = circuit
            .native()
            .ok_or(SigmaError::Synthesis(Error::Synthesis))?;
        if !native.is_honest() {
            return Err(SigmaError::RelationViolated(native.violations.clone()));
        }
        let public = native.public();
        let instances = instance(&public);
        let bytes = prove_circuit(
            &self.params,
            &self.pk,
            &circuit,
            &instances,
            randomness,
            ProverConfig::default(),
        )
        .map_err(SigmaError::Prover)?;
        Ok(SigmaProof { public, bytes })
    }

    /// The matching verifier.
    #[must_use]
    pub fn verifier(&self) -> SigmaVerifier<C> {
        SigmaVerifier {
            relation: self.shape.params.relation().relation,
            params: self.params.clone(),
            binding: self.pk.binding().clone(),
            vk: self.pk.vk().clone(),
            budget: MemoryBudget::DEFAULT,
        }
    }
}

/// The verifying side: the relation it verifies (its allowlist selector),
/// the descriptor, the verifying key and the pinned parameters (no circuit
/// code).
#[derive(Clone, Debug)]
pub struct SigmaVerifier<C: PastaCurve> {
    relation: SigmaRelation,
    params: PinnedParams<C>,
    binding: DescriptorBinding,
    vk: VerifyingKey<C>,
    budget: MemoryBudget,
}

impl<C: PastaCurve> SigmaVerifier<C>
where
    C::ScalarExt: PoseidonField,
{
    /// A verifier from the canonical descriptor and verifying-key bytes.
    ///
    /// # Errors
    ///
    /// [`SigmaError::Descriptor`] or [`SigmaError::VerifyingKey`] from strict
    /// decoding, and [`SigmaError::ParamsK`] when `params` are for another
    /// `k`.
    pub fn from_bytes(
        relation: SigmaRelation,
        params: PinnedParams<C>,
        descriptor: &[u8],
        vk: &[u8],
    ) -> Result<Self, SigmaError> {
        let binding = DescriptorBinding::decode(descriptor).map_err(SigmaError::Descriptor)?;
        let k = u32::from(binding.descriptor().k);
        if params.k() != k {
            return Err(SigmaError::ParamsK {
                expected: k,
                found: params.k(),
            });
        }
        let vk = VerifyingKey::read(vk, &binding).map_err(SigmaError::VerifyingKey)?;
        Ok(Self {
            relation,
            params,
            binding,
            vk,
            budget: MemoryBudget::DEFAULT,
        })
    }

    /// The relation this verifier verifies.
    #[must_use]
    pub const fn relation(&self) -> SigmaRelation {
        self.relation
    }

    /// The canonical descriptor bytes.
    #[must_use]
    pub fn descriptor_bytes(&self) -> &[u8] {
        self.binding.encoded()
    }

    /// The verifying-key digest of the allowlist entry: the PIPA-v1
    /// `transcript_repr` of the key (`BLAKE2b` over the descriptor digest and
    /// the verifying-key bytes, reduced into the scalar field; spec
    /// `plonk_ipa_v1.md` 6.3), which every proof absorbs first.
    // TODO(G3): the frozen artifact set fixes the verifying-key digest rule
    // of the allowlist; this is the interim choice.
    #[must_use]
    pub fn verifying_key_digest(&self) -> [u8; 32] {
        self.vk.transcript_repr_bytes()
    }

    /// The exact proof length the descriptor admits.
    ///
    /// # Errors
    ///
    /// [`SigmaError::Protocol`] when the protocol tables cannot be derived.
    pub fn proof_bytes(&self) -> Result<usize, SigmaError> {
        Ok(Protocol::new(self.binding.descriptor())
            .map_err(SigmaError::Protocol)?
            .proof_length())
    }

    /// The G1 allowlist entry of this verifier: its selector, verifying-key
    /// digest and exact proof length.
    ///
    /// # Errors
    ///
    /// As [`Self::proof_bytes`], and [`SigmaError::ProofLength`] for a
    /// length above `u32::MAX`.
    pub fn allowlist_entry(&self) -> Result<VerifyingKeyEntry, SigmaError> {
        let bytes = self.proof_bytes()?;
        let (kind, enabled_controls) = self.relation.selector();
        Ok(VerifyingKeyEntry {
            kind,
            enabled_controls,
            verifying_key_digest: self.verifying_key_digest(),
            proof_bytes: u32::try_from(bytes).map_err(|_| SigmaError::ProofLength(bytes))?,
        })
    }

    /// The verifying-key bytes.
    #[must_use]
    pub fn vk_bytes(&self) -> &[u8] {
        self.vk.to_bytes()
    }

    /// The descriptor binding.
    #[must_use]
    pub const fn binding(&self) -> &DescriptorBinding {
        &self.binding
    }

    /// The verifying key.
    #[must_use]
    pub const fn vk(&self) -> &VerifyingKey<C> {
        &self.vk
    }

    /// The parameters.
    #[must_use]
    pub const fn params(&self) -> &PinnedParams<C> {
        &self.params
    }

    /// Verifies `proof` for `public` in full.
    ///
    /// # Errors
    ///
    /// [`SigmaError::Verify`] with the engine's typed rejection.
    pub fn verify(
        &self,
        public: &StepPublic<C::ScalarExt>,
        proof: &[u8],
    ) -> Result<(), SigmaError> {
        let instances = instance(public);
        verify_full(
            &self.params,
            &self.binding,
            &self.vk,
            &instances,
            proof,
            self.budget,
        )
        .map_err(SigmaError::Verify)
    }
}

/// Bytes of one allowlist entry transcript: `tag kind || LE32 mask ||
/// verifying_key_digest || LE32 proof_bytes` (G1
/// `KAGEMUSHA_WALLET_VERIFYING_KEY_ENTRY_TRANSCRIPT_BYTES_V1`).
pub const VERIFYING_KEY_ENTRY_TRANSCRIPT_BYTES: usize = 1 + 4 + 32 + 4;

/// One σ entry of the G1 verifying-key allowlist
/// (`KagemushaWalletVerifyingKeyEntryV1`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VerifyingKeyEntry {
    /// The operation tag.
    pub kind: u8,
    /// The enabled-controls mask of a Send relation; zero otherwise.
    pub enabled_controls: u32,
    /// The verifying-key digest.
    pub verifying_key_digest: [u8; 32],
    /// The exact proof length.
    pub proof_bytes: u32,
}

impl VerifyingKeyEntry {
    /// The selector `(tag, mask)` that orders the allowlist.
    #[must_use]
    pub const fn selector(&self) -> (u8, u32) {
        (self.kind, self.enabled_controls)
    }

    /// The exact entry transcript of the `verifying-key-set` digest.
    #[must_use]
    pub fn transcript(&self) -> [u8; VERIFYING_KEY_ENTRY_TRANSCRIPT_BYTES] {
        let mut bytes = [0_u8; VERIFYING_KEY_ENTRY_TRANSCRIPT_BYTES];
        bytes[0] = self.kind;
        bytes[1..5].copy_from_slice(&self.enabled_controls.to_le_bytes());
        bytes[5..37].copy_from_slice(&self.verifying_key_digest);
        bytes[37..].copy_from_slice(&self.proof_bytes.to_le_bytes());
        bytes
    }
}

/// The G1 selector of a consumer's statement: the operation tag and, for
/// Send, the enabled-controls mask (equal to Ω(pred)'s by the consumer
/// checks); every other operation selects the empty mask (G1
/// `KagemushaWalletPackageV1::verifying_key_selector`).
#[must_use]
pub const fn selector_for(step: StepRelation, enabled_controls: u32) -> SigmaRelation {
    match step {
        StepRelation::Send => SigmaRelation::send(enabled_controls),
        StepRelation::Receive => SigmaRelation::RECEIVE,
    }
}

/// σ verifiers keyed by their G1 selector `(tag, mask)`.
#[derive(Clone, Debug)]
pub struct SigmaAllowlist<C: PastaCurve> {
    verifiers: std::collections::BTreeMap<(u8, u32), SigmaVerifier<C>>,
}

impl<C: PastaCurve> Default for SigmaAllowlist<C> {
    fn default() -> Self {
        Self {
            verifiers: std::collections::BTreeMap::new(),
        }
    }
}

impl<C: PastaCurve> SigmaAllowlist<C>
where
    C::ScalarExt: PoseidonField,
{
    /// An empty allowlist.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds `verifier` under its relation's selector.
    ///
    /// # Errors
    ///
    /// [`SigmaError::DuplicateSelector`] when the selector is taken.
    pub fn insert(&mut self, verifier: SigmaVerifier<C>) -> Result<(), SigmaError> {
        let selector = verifier.relation().selector();
        if self.verifiers.contains_key(&selector) {
            return Err(SigmaError::DuplicateSelector(selector));
        }
        self.verifiers.insert(selector, verifier);
        Ok(())
    }

    /// The verifier of `relation`'s selector.
    ///
    /// # Errors
    ///
    /// [`SigmaError::NoVerifier`] when the allowlist has none (for example
    /// a Send mask with no allowlisted relation).
    pub fn select(&self, relation: SigmaRelation) -> Result<&SigmaVerifier<C>, SigmaError> {
        let selector = relation.selector();
        self.verifiers
            .get(&selector)
            .ok_or(SigmaError::NoVerifier(selector))
    }

    /// Selects the verifier of `relation` and verifies `proof` for `public`.
    ///
    /// # Errors
    ///
    /// As [`Self::select`] and [`SigmaVerifier::verify`].
    pub fn verify(
        &self,
        relation: SigmaRelation,
        public: &StepPublic<C::ScalarExt>,
        proof: &[u8],
    ) -> Result<(), SigmaError> {
        self.select(relation)?.verify(public, proof)
    }

    /// The allowlist entries, strictly ascending by selector (the G1 order).
    ///
    /// # Errors
    ///
    /// As [`SigmaVerifier::allowlist_entry`].
    pub fn entries(&self) -> Result<Vec<VerifyingKeyEntry>, SigmaError> {
        self.verifiers
            .values()
            .map(SigmaVerifier::allowlist_entry)
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use ff::Field;
    use iroha_pasta::Fp;

    use super::*;
    use crate::witness::CONTROL_BLACKLIST;

    #[test]
    fn instances_are_the_statement_digest() {
        let public = StepPublic { statement: Fp::ONE };
        assert_eq!(instance(&public), vec![vec![Fp::ONE]]);
    }

    #[test]
    fn selectors_follow_g1() {
        assert_eq!(selector_for(StepRelation::Send, 0), SigmaRelation::SEND);
        assert_eq!(
            selector_for(StepRelation::Send, CONTROL_BLACKLIST).selector(),
            (3, 1)
        );
        // Every operation other than Send selects the empty mask.
        assert_eq!(
            selector_for(StepRelation::Receive, CONTROL_BLACKLIST),
            SigmaRelation::RECEIVE
        );
        let entry = VerifyingKeyEntry {
            kind: 3,
            enabled_controls: 0x0102_0304,
            verifying_key_digest: [0xab; 32],
            proof_bytes: 3_296,
        };
        let transcript = entry.transcript();
        assert_eq!(transcript.len(), VERIFYING_KEY_ENTRY_TRANSCRIPT_BYTES);
        assert_eq!(transcript[0], 3);
        assert_eq!(transcript[1..5], [4, 3, 2, 1]);
        assert_eq!(transcript[5..37], [0xab; 32]);
        assert_eq!(transcript[37..], 3_296_u32.to_le_bytes());
        assert_eq!(entry.selector(), (3, 0x0102_0304));
        let empty = SigmaAllowlist::<iroha_pasta::Eq>::new();
        assert!(matches!(
            empty.select(SigmaRelation::RECEIVE),
            Err(SigmaError::NoVerifier((4, 0)))
        ));
        assert_eq!(empty.entries(), Ok(Vec::new()));
    }

    #[test]
    fn errors_display() {
        for error in [
            SigmaError::NoShape,
            SigmaError::DoesNotFit { k: 9 },
            SigmaError::NoVerifier((3, 1)),
            SigmaError::DuplicateSelector((4, 0)),
            SigmaError::ProofLength(usize::MAX),
            SigmaError::UnknownCurve,
            SigmaError::ParamsK {
                expected: 10,
                found: 11,
            },
            SigmaError::WrongRelation {
                expected: StepRelation::Send,
                found: StepRelation::Receive,
            },
            SigmaError::RelationViolated(vec![Violation::Overdraft]),
            SigmaError::Synthesis(Error::Synthesis),
            SigmaError::Params(ParamsError::Lanes(0)),
        ] {
            assert!(!error.to_string().is_empty(), "{error:?}");
        }
    }
}
