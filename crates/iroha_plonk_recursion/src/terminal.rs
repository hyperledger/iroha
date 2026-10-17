//! Closed native terminal-A intake and four-slot Vesta fold.
//!
//! Installation supplies the authenticated terminal-key catalog once. This owner
//! neither manufactures installation authority nor decides the retained opening.
//! It derives every slot from the same successful succinct A parse and binds its
//! raw first base-field squeeze, exact descriptor and own opening to the fold.

use ff::{Field, PrimeField};
use iroha_pasta::{Eq, EqAffine, Fp, Fq};
use iroha_plonk::{
    DescriptorBinding, VerifyingKey,
    cs::{CurveV1, InstanceModeV1, InstanceType, ProofSuffixV1, TranscriptV2},
    pcs::ipa::PinnedParams,
    transcript::decode_point,
    verifier::{SuccinctFrame, VerifyError, accumulate_frame_cancellable},
};
use zeroize::Zeroizing;

use crate::{
    AccumulatorT, FoldConfig, FoldInput, FoldPurpose, FoldTape, FoldWitness, K,
    VESTA_TRIVIAL_GENERATOR,
    accumulation::{InputBinding, create_fold_bound, verify_fold_bound},
};

/// A rejected catalog/frame, failed succinct check, or failed fold operation.
#[derive(Debug)]
pub enum Error {
    /// Descriptor, parameter prefix, catalog membership or canonical frame differs.
    Input,
    /// Actual succinct verification did not return a complete opening obligation.
    Verification(VerifyError),
    /// Fold construction or verification failed; no success is returned.
    Fold(crate::Error),
}
impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Input => f.write_str("terminal A catalog or frame differs"),
            Self::Verification(e) => write!(f, "terminal A succinct verification: {e}"),
            Self::Fold(e) => write!(f, "terminal A fold: {e}"),
        }
    }
}
impl std::error::Error for Error {}
impl Error {
    /// Whether an actual verifier or fold refused due to cancellation.
    pub fn is_cancelled(&self) -> bool {
        match self {
            Self::Input => false,
            Self::Verification(e) => e.is_cancelled(),
            Self::Fold(e) => e.is_cancelled(),
        }
    }
}
impl From<crate::Error> for Error {
    fn from(value: crate::Error) -> Self {
        Self::Fold(value)
    }
}

/// Fixed terminal-A descriptor and exact key allowlist selected by installation.
/// Per-proof callers can choose only an index in this retained catalog.
pub struct TerminalPlan {
    params: PinnedParams<Eq>,
    binding: DescriptorBinding,
    keys: Vec<VerifyingKey<Eq>>,
}
impl core::fmt::Debug for TerminalPlan {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("TerminalPlan")
            .field("keys", &self.keys.len())
            .finish_non_exhaustive()
    }
}
impl TerminalPlan {
    /// Select the exact authenticated catalog. This validates structural bindings;
    /// the calling installation owner must establish catalog authenticity.
    ///
    /// # Errors
    /// Anything other than a Vesta k16 Direct RP57-base suffix proof with one
    /// 69-word Bounded frame, or an empty/duplicate/malformed key catalog.
    pub fn new(
        descriptor: &[u8],
        catalog: &[Vec<u8>],
        params: PinnedParams<Eq>,
    ) -> Result<Self, Error> {
        if params.k() != 16
            || descriptor.is_empty()
            || descriptor.len() > 1 << 20
            || catalog.is_empty()
            || catalog.len() > 32
        {
            return Err(Error::Input);
        }
        let binding = DescriptorBinding::decode_v2(descriptor).map_err(|_| Error::Input)?;
        let d = binding.descriptor();
        if d.curve != CurveV1::Vesta
            || d.k != 16
            || d.transcript != TranscriptV2::KagemushaPoseidonRp57Base
            || d.instance_mode != InstanceModeV1::Direct
            || d.proof_suffix != ProofSuffixV1::FoldedGenerator
            || d.instance_lengths != [69]
            || d.instance_types.as_deref() != Some(&[InstanceType::Bounded])
        {
            return Err(Error::Input);
        }
        let mut keys = Vec::with_capacity(catalog.len());
        let mut digests = Vec::with_capacity(catalog.len());
        for original in catalog {
            if original.is_empty() || original.len() > 1 << 18 {
                return Err(Error::Input);
            }
            let key = VerifyingKey::<Eq>::read(original, &binding).map_err(|_| Error::Input)?;
            let digest = key.kagemusha_digest(&binding).map_err(|_| Error::Input)?;
            if digests.contains(&digest) {
                return Err(Error::Input);
            }
            keys.push(key);
            digests.push(digest);
        }
        Ok(Self {
            params,
            binding,
            keys,
        })
    }

    /// Parse and succinctly verify one catalog member's exact frame and proof.
    /// The result retains an undecided opening, never a complete proof verdict.
    ///
    /// # Errors
    /// Unknown key index, malformed proof/frame, cancellation, or failed equation.
    pub fn read<'a>(
        &'a self,
        key_index: usize,
        instances: &[Vec<Fp>],
        proof: &[u8],
        config: &FoldConfig,
    ) -> Result<TerminalFrame<'a>, Error> {
        let key = self.keys.get(key_index).ok_or(Error::Input)?;
        let parsed = accumulate_frame_cancellable(
            &self.params,
            &self.binding,
            key,
            instances,
            proof,
            config.kernel_budget,
            config.cancellation.as_ref(),
        )
        .map_err(Error::Verification)?;
        let columns = parsed.instances();
        if columns.len() != 1 || columns[0].len() != 69 || parsed.own_claim().k() != 16 {
            return Err(Error::Input);
        }
        let opening =
            FoldInput::from_opening(*parsed.own_claim().g(), parsed.own_claim().challenges())?;
        let inputs = PrivateInputs(derive_inputs(&columns[0], opening)?);
        Ok(TerminalFrame {
            plan: self,
            parsed,
            inputs,
        })
    }
}

struct PrivateInputs([FoldInput<Eq>; 4]);
impl Drop for PrivateInputs {
    fn drop(&mut self) {
        for input in &mut self.0 {
            input.clear_private_owner();
        }
    }
}

/// A single successfully parsed A frame tied to its retained catalog and prefix.
/// This private non-Clone owner cannot be constructed from arbitrary digest/raw
/// values or caller-selected slots. Its own opening must still be discharged.
#[must_use = "the same-frame own opening remains undecided"]
pub struct TerminalFrame<'a> {
    plan: &'a TerminalPlan,
    parsed: SuccinctFrame<Eq>,
    inputs: PrivateInputs,
}
impl core::fmt::Debug for TerminalFrame<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("TerminalFrame { private: [REDACTED], opening: undecided }")
    }
}
impl TerminalFrame<'_> {
    fn binding(&self) -> InputBinding<Eq> {
        InputBinding::Terminal {
            descriptor: *self.parsed.binding().digest(),
            raw: *self.parsed.first_raw(),
        }
    }
    /// Exact lineage word from the same successfully parsed frame.
    pub fn lineage(&self) -> Fp {
        self.parsed.instances()[0][0]
    }

    /// Consumes this private parse and fresh tape to create its fixed four-slot
    /// WrapperVesta fold. The returned output is an undecided obligation.
    ///
    /// # Errors
    /// Cancellation, malformed/false input claims, or failed fold equation.
    pub fn create(
        self,
        tape: FoldTape<Eq>,
        config: &FoldConfig,
    ) -> Result<(FoldWitness<Eq>, AccumulatorT<Eq>), Error> {
        create_fold_bound(
            &self.plan.params,
            &self.inputs.0,
            tape,
            FoldPurpose::WrapperVesta,
            config,
            &self.binding(),
        )
        .map_err(Error::Fold)
    }

    /// Check retained original witness bytes against this same successful parse;
    /// no fresh randomness is sampled. The returned claim must still decide.
    ///
    /// # Errors
    /// Cancellation, mismatched commitment/prefix/claim, or failed fold equation.
    pub fn verify(
        &self,
        witness: &FoldWitness<Eq>,
        config: &FoldConfig,
    ) -> Result<AccumulatorT<Eq>, Error> {
        verify_fold_bound(
            &self.plan.params,
            &self.inputs.0,
            witness,
            FoldPurpose::WrapperVesta,
            config,
            &self.binding(),
        )
        .map_err(Error::Fold)
    }
}

fn limb(value: Fp) -> Result<u128, Error> {
    let bytes = Zeroizing::new(value.to_repr());
    if bytes[16..].iter().any(|b| *b != 0) {
        return Err(Error::Input);
    }
    Ok(u128::from_le_bytes(
        bytes[..16].try_into().map_err(|_| Error::Input)?,
    ))
}
fn coordinate(words: &[Fp]) -> Result<Fq, Error> {
    let [low, high] = words else {
        return Err(Error::Input);
    };
    let mut repr = Zeroizing::new([0; 32]);
    repr[..16].copy_from_slice(&limb(*low)?.to_le_bytes());
    repr[16..].copy_from_slice(&limb(*high)?.to_le_bytes());
    Option::<Fq>::from(Fq::from_repr(*repr)).ok_or(Error::Input)
}
fn point(words: &[Fp]) -> Result<EqAffine, Error> {
    if words.len() != 4 {
        return Err(Error::Input);
    }
    iroha_plonk::transcript::generator_from_coordinates::<Eq>(
        coordinate(&words[..2])?,
        coordinate(&words[2..])?,
    )
    .map_err(|_| Error::Input)
}
fn claim(words: &[Fp], scalars: &[Fp], k: u32) -> Result<FoldInput<Eq>, Error> {
    FoldInput::from_normalized(
        point(words)?,
        k,
        scalars.try_into().map_err(|_| Error::Input)?,
    )
    .map_err(Error::Fold)
}
fn derive_inputs(frame: &[Fp], opening: FoldInput<Eq>) -> Result<[FoldInput<Eq>; 4], Error> {
    if frame.len() != 69 || opening.source_k() != 16 {
        return Err(Error::Input);
    }
    let k = u32::try_from(limb(frame[1])?).map_err(|_| Error::Input)?;
    if !matches!(k, 12 | 14 | 16) {
        return Err(Error::Input);
    }
    let part = claim(&frame[2..6], &frame[6..22], k)?;
    let predecessor = claim(&frame[22..26], &frame[26..42], 16)?;
    let incoming = claim(&frame[42..46], &frame[46..62], 16)?;
    let corrected = point(&frame[65..69])?;
    let selected = match [frame[62], frame[63], frame[64]] {
        m if m == [Fp::ONE, Fp::ZERO, Fp::ZERO] => incoming,
        m if m == [Fp::ZERO, Fp::ONE, Fp::ZERO] => FoldInput::from_normalized(
            decode_point::<Eq>(&VESTA_TRIVIAL_GENERATOR).map_err(|_| Error::Input)?,
            16,
            [Fp::ONE; K],
        )?,
        m if m == [Fp::ZERO, Fp::ZERO, Fp::ONE] => {
            if &corrected == incoming.g() {
                return Err(Error::Input);
            }
            FoldInput::from_normalized(corrected, 16, *incoming.challenges())?
        }
        _ => return Err(Error::Input),
    };
    Ok([part, opening, predecessor, selected])
}
