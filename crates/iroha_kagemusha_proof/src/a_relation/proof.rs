//! Hard recursive proof ownership and exact Pallas fold input ordering.

use super::{
    AFramePlan, BoundSigmaCells, LineagePublicCells, SigmaBindingCells, VestaClaimCells,
    bind_sigma, lineage_digest,
};
use crate::q_sigma::QSigmaPlan;
use core::num::NonZeroU16;
use iroha_pasta::{Ep, Fp};
use iroha_plonk::{
    VerifyingKey,
    cs::InstanceType,
    frontend::{Error, Region},
    pcs::ipa::PinnedParams,
};
use iroha_plonk_gadgets::{
    Bit, GlueChip, Uint, Word,
    bytes::{
        element::{LeElement, decode_le_element},
        tape::{ByteRun, SegmentSpec},
    },
};
use iroha_plonk_recursion::{
    accumulation_circuit::{FoldInputCells, FoldPlan, FoldSource},
    codec::ScalarCells,
    obligation::{
        ModeCells, constrain_incoming_modes,
        ledger::{Ledger, Variant},
    },
    verifier::{VerificationMode, VerifierChip, VerifierKeyCells, VerifierPlan},
};

/// One descriptor-fixed, circuit-constant Q verifying key.
#[derive(Clone, Debug)]
pub struct QProofPlan {
    verifier: VerifierPlan<Ep>,
    pub(super) key: VerifyingKey<Ep>,
}
impl QProofPlan {
    /// Pins a k16 Q key to its admitted descriptor.
    ///
    /// # Errors
    /// A wrong k, profile or descriptor/key digest mismatch.
    pub fn new(verifier: VerifierPlan<Ep>, key: VerifyingKey<Ep>) -> Result<Self, Error> {
        if verifier.binding().descriptor().k != 16
            || key.descriptor_digest() != verifier.binding().digest()
        {
            return Err(Error::Synthesis);
        }
        Ok(Self { verifier, key })
    }
    /// Exact proof program, including its byte length and instance schema.
    pub const fn verifier(&self) -> &VerifierPlan<Ep> {
        &self.verifier
    }
}

/// Circuit-fixed A recursive program; `Q_sigma` is the first Q slot.
#[derive(Clone, Debug)]
pub struct AProofPlan {
    frame: AFramePlan,
    pub(super) sigma: QSigmaPlan,
    q: Vec<QProofPlan>,
    omega: Option<VerifierPlan<Ep>>,
    pallas_fold: Option<FoldPlan<Ep>>,
    ledger: Ledger,
}
impl AProofPlan {
    /// Fixes every hard Q, predecessor/incoming Omega and fold slot.
    /// Bootstrap has no Omega verifier. One Q is forwarded; multiple Q
    /// openings require the fixed hard Q-only `F_P` fold.
    ///
    /// # Errors
    /// Any fixed descriptor, variant, slot count or instance-shape mismatch.
    pub fn new(
        variant: Variant,
        sigma: QSigmaPlan,
        q: Vec<QProofPlan>,
        omega: Option<VerifierPlan<Ep>>,
        params: &PinnedParams<Ep>,
    ) -> Result<Self, Error> {
        let frame = AFramePlan::new(variant, sigma.part_source_k())?;
        let count = NonZeroU16::new(u16::try_from(q.len()).map_err(|_| Error::BoundsFailure)?)
            .ok_or(Error::Synthesis)?;
        let own_k = sigma
            .class(0)
            .ok_or(Error::Synthesis)?
            .verifier()
            .binding()
            .descriptor()
            .k;
        let incoming_k = sigma
            .class(1)
            .map(|class| class.verifier().binding().descriptor().k);
        let ledger =
            Ledger::new(variant, count, own_k, incoming_k).map_err(|_| Error::Synthesis)?;
        let descriptor = q[0].verifier.binding().descriptor();
        if descriptor
            .instance_lengths
            .iter()
            .map(|len| *len as usize)
            .collect::<Vec<_>>()
            != sigma.instance_lengths()
            || descriptor.instance_types.as_deref() != Some(&QSigmaPlan::instance_types())
            || omega.is_some() != frame.has_predecessor()
        {
            return Err(Error::Synthesis);
        }
        if let Some(omega) = &omega {
            let descriptor = omega.binding().descriptor();
            if descriptor.k != 16
                || descriptor.instance_lengths != [1, 2, 16]
                || descriptor.instance_types.as_deref()
                    != Some(&[
                        InstanceType::Bounded,
                        InstanceType::Field,
                        InstanceType::Bounded,
                    ])
            {
                return Err(Error::Synthesis);
            }
        }
        let pallas_fold = if frame.has_predecessor() || q.len() > 1 {
            let mut sources = vec![FoldSource::Fixed(16); 2 * usize::from(frame.has_predecessor())];
            if frame.has_incoming() {
                sources.extend([FoldSource::Incoming(16); 2]);
            }
            sources.extend(vec![FoldSource::Fixed(16); q.len()]);
            Some(FoldPlan::with_sources(params, sources).map_err(|_| Error::Synthesis)?)
        } else {
            None
        };
        Ok(Self {
            frame,
            sigma,
            q,
            omega,
            pallas_fold,
            ledger,
        })
    }
    /// Exact A-to-Omega public frame.
    pub const fn frame(&self) -> AFramePlan {
        self.frame
    }
    /// Complete fixed ledger, including routes owned by Q and Omega.
    pub const fn ledger(&self) -> &Ledger {
        &self.ledger
    }
    /// Number of hard Q openings, each retained independently.
    pub fn q_count(&self) -> usize {
        self.q.len()
    }
    /// A hard Q verifier, in canonical descriptor order.
    pub fn q(&self, index: usize) -> Option<&QProofPlan> {
        self.q.get(index)
    }
    /// The shared predecessor/incoming Omega proof program.
    pub const fn omega(&self) -> Option<&VerifierPlan<Ep>> {
        self.omega.as_ref()
    }
}

/// Proof words and actual length decoded from one constrained byte tape.
#[derive(Clone, Debug)]
pub struct ProofMessageCells {
    messages: Vec<LeElement<Fp>>,
    length: Uint<Fp, 32>,
}
impl ProofMessageCells {
    /// Retain checked exact 256-bit messages and their actual `UInt32` length.
    ///
    /// This contains no separate byte-tape provenance. A consuming digest or
    /// source export must copy-bind all three limbs to its independently
    /// decoded original tape. Recursive continuations may retain this compact
    /// view because the fixed source owner establishes that binding.
    /// # Errors
    /// Empty or overflowing fixed message schedule.
    pub fn from_messages(
        messages: Vec<LeElement<Fp>>,
        length: Uint<Fp, 32>,
    ) -> Result<Self, Error> {
        if messages.is_empty()
            || messages
                .len()
                .checked_mul(32)
                .and_then(|n| u32::try_from(n).ok())
                .is_none()
        {
            return Err(Error::Synthesis);
        }
        Ok(Self { messages, length })
    }

    /// Decode an embedded fixed-length proof. Its enclosing transport decoder
    /// separately contributes the original outer-length verdict to `soft_ok`.
    pub(super) fn fixed_slice(
        chip: &mut VerifierChip<Ep>,
        region: &mut Region<'_, Fp>,
        run: &ByteRun<Fp>,
        offset: usize,
        byte_length: usize,
    ) -> Result<Self, Error> {
        if byte_length == 0 || !byte_length.is_multiple_of(32) {
            return Err(Error::Synthesis);
        }
        let end = offset
            .checked_add(byte_length)
            .ok_or(Error::BoundsFailure)?;
        if end > run.len() {
            return Err(Error::BoundsFailure);
        }
        let messages = (offset..end)
            .step_by(32)
            .map(|start| decode_le_element(&mut chip.uint(), region, run, start))
            .collect::<Result<Vec<_>, _>>()?;
        let length = chip.uint().constant::<32>(
            region,
            u128::from(u32::try_from(byte_length).map_err(|_| Error::BoundsFailure)?),
        )?;
        Ok(Self { messages, length })
    }
    /// Decode LE32 actual length followed by a fixed message buffer.
    /// `run` must contain the length segment and the low/high segments from
    /// `le_message_segments(offset + 4, byte_length / 32)`.
    ///
    /// # Errors
    /// Invalid fixed size, missing tape segments, overflow or layout failure.
    pub fn from_run(
        chip: &mut VerifierChip<Ep>,
        region: &mut Region<'_, Fp>,
        run: &ByteRun<Fp>,
        offset: usize,
        byte_length: usize,
    ) -> Result<Self, Error> {
        if byte_length == 0 || !byte_length.is_multiple_of(32) {
            return Err(Error::Synthesis);
        }
        let body = offset.checked_add(4).ok_or(Error::BoundsFailure)?;
        let end = body.checked_add(byte_length).ok_or(Error::BoundsFailure)?;
        if end > run.len() {
            return Err(Error::BoundsFailure);
        }
        let length = chip.uint().range_check::<32>(
            region,
            run.secondary_segment(SegmentSpec::little(offset, 4))?
                .word(),
        )?;
        let mut messages = Vec::with_capacity(byte_length / 32);
        for start in (body..end).step_by(32) {
            messages.push(decode_le_element(&mut chip.uint(), region, run, start)?);
        }
        Ok(Self { messages, length })
    }
    /// The fixed descriptor-sized message schedule.
    pub fn messages(&self) -> &[LeElement<Fp>] {
        &self.messages
    }
    /// The actual LE32 length from the same tape.
    pub const fn length(&self) -> &Uint<Fp, 32> {
        &self.length
    }
}

/// A verified hard Q opening; its identity fixes its position in `F_P`.
#[derive(Clone, Debug)]
pub struct VerifiedQCells {
    pub(super) index: usize,
    pub(super) opening: FoldInputCells<Ep>,
    pub(super) instances: Vec<Vec<ScalarCells<Ep>>>,
    pub(super) key_digest: Word<Fp>,
}
impl VerifiedQCells {
    /// The retained generator obligation; verifying the Q does not decide it.
    pub const fn opening(&self) -> &FoldInputCells<Ep> {
        &self.opening
    }
}

/// Hard-verifies a Q using its circuit-fixed complete key.
///
/// # Errors
/// Wrong fixed index/shape or layout error; an invalid proof is unsatisfiable.
pub fn verify_q(
    chip: &mut VerifierChip<Ep>,
    region: &mut Region<'_, Fp>,
    plan: &AProofPlan,
    index: usize,
    instances: &[Vec<ScalarCells<Ep>>],
    proof: &ProofMessageCells,
) -> Result<VerifiedQCells, Error> {
    let fixed = plan.q.get(index).ok_or(Error::Synthesis)?;
    let key = chip.constant_key(region, &fixed.verifier, &fixed.key)?;
    let output = chip.verify(
        region,
        &fixed.verifier,
        &key,
        instances,
        &proof.messages,
        &proof.length,
        VerificationMode::Hard,
    )?;
    Ok(VerifiedQCells {
        index,
        instances: instances.to_vec(),
        key_digest: output.key_digest.clone(),
        opening: FoldInputCells::from_claim(chip, region, &output.claim)?,
    })
}

/// Hard-verifies `Q_sigma` and binds its exact same instance cells to the operation.
///
/// # Errors
/// Fixed shape/layout mismatch or an unsatisfied hard proof/own consumer check.
pub fn verify_sigma(
    chip: &mut VerifierChip<Ep>,
    region: &mut Region<'_, Fp>,
    plan: &AProofPlan,
    instances: &[Vec<ScalarCells<Ep>>],
    proof: &ProofMessageCells,
    bindings: &[SigmaBindingCells],
) -> Result<(VerifiedQCells, BoundSigmaCells), Error> {
    let verified = verify_q(chip, region, plan, 0, instances, proof)?;
    let sigma = bind_sigma(chip, region, &plan.sigma, instances, bindings)?;
    Ok((verified, sigma))
}

/// A predecessor's hard proof and separately retained transported claims.
#[derive(Clone, Debug)]
pub struct PredecessorCells {
    pub(super) proof: ProofMessageCells,
    pub(super) public: [Word<Fp>; 18],
    pub(super) pallas: FoldInputCells<Ep>,
    pub(super) opening: FoldInputCells<Ep>,
    pub(super) vesta: VestaClaimCells,
}
impl PredecessorCells {
    /// Hard predecessor Vesta obligation, copied to Omega's fold.
    pub const fn vesta(&self) -> &VestaClaimCells {
        &self.vesta
    }
}

pub(super) fn omega_instances(
    chip: &mut VerifierChip<Ep>,
    region: &mut Region<'_, Fp>,
    digest: &Word<Fp>,
    vesta: &VestaClaimCells,
) -> Result<Vec<Vec<ScalarCells<Ep>>>, Error> {
    if vesta.source_k() != 16 {
        return Err(Error::Synthesis);
    }
    let digest = ScalarCells::from_native_word(&mut chip.uint(), region, digest)?;
    let mut challenges = Vec::with_capacity(16);
    for value in vesta.challenges() {
        challenges.push(ScalarCells::from_native_word(
            &mut chip.uint(),
            region,
            value,
        )?);
    }
    Ok(vec![vec![digest], vesta.coordinates().to_vec(), challenges])
}

/// Hard-verifies the predecessor, binds its complete public digest, and copies
/// the witnessed Omega key digest into the operation's successor public fields.
///
/// # Errors
/// Missing Omega program/layout failure; any mismatch is unsatisfiable.
#[allow(clippy::too_many_arguments)]
pub fn verify_predecessor(
    chip: &mut VerifierChip<Ep>,
    region: &mut Region<'_, Fp>,
    plan: &AProofPlan,
    key: &VerifierKeyCells<Ep>,
    public: &LineagePublicCells,
    successor: &LineagePublicCells,
    pallas: &FoldInputCells<Ep>,
    vesta: &VestaClaimCells,
    proof: &ProofMessageCells,
) -> Result<PredecessorCells, Error> {
    let omega = plan.omega.as_ref().ok_or(Error::Synthesis)?;
    let digest = lineage_digest(chip, region, public, pallas)?;
    let instances = omega_instances(chip, region, &digest, vesta)?;
    let output = chip.verify(
        region,
        omega,
        key,
        &instances,
        &proof.messages,
        &proof.length,
        VerificationMode::Hard,
    )?;
    GlueChip::assert_equal(region, &output.key_digest, public.omega_key_digest())?;
    GlueChip::assert_equal(
        region,
        public.omega_key_digest(),
        successor.omega_key_digest(),
    )?;
    Ok(PredecessorCells {
        proof: proof.clone(),
        public: public.fields().clone(),
        pallas: pallas.clone(),
        opening: FoldInputCells::from_claim(chip, region, &output.claim)?,
        vesta: vesta.clone(),
    })
}

/// Incoming Omega's total verifier result and its separate pending obligations.
#[must_use = "include incoming.valid in the global branch rule"]
#[derive(Clone, Debug)]
pub struct IncomingOmegaCells {
    pub(super) carried_key: Word<Fp>,
    pub(super) lineage_valid: Bit<Fp>,
    pub(super) public: [Word<Fp>; 18],
    pub(super) vesta: VestaClaimCells,
    pub(super) proof: IncomingProofBinding,
    /// Proof, key continuity and both transported-decoder checks.
    pub valid: Bit<Fp>,
    pub(super) pallas: FoldInputCells<Ep>,
    pub(super) opening: FoldInputCells<Ep>,
}

/// Internal provenance copied into a selected incoming claim. Receive's active
/// form is constructed only from a W-authenticated complete owner context.
#[derive(Clone, Debug)]
pub(super) enum IncomingProofBinding {
    Messages(ProofMessageCells),
    ReceiveActive([Word<Fp>; 3]),
}

/// Soft-verifies an incoming Omega under the same carried key identity.
/// Decoders must supply verdicts determined by the original bytes; the two
/// decoded claims supplied here are their fixed valid outputs on failure.
///
/// # Errors
/// Missing fixed program or layout failure. Byte-derived failures return false.
#[allow(clippy::too_many_arguments)]
pub fn verify_incoming(
    chip: &mut VerifierChip<Ep>,
    region: &mut Region<'_, Fp>,
    plan: &AProofPlan,
    key: &VerifierKeyCells<Ep>,
    public: &super::IncomingLineageCells,
    carried_key: &Word<Fp>,
    pallas: &FoldInputCells<Ep>,
    vesta: &VestaClaimCells,
    decode_bits: &[Bit<Fp>; 2],
    proof: &ProofMessageCells,
) -> Result<IncomingOmegaCells, Error> {
    if !plan.frame.has_incoming() {
        return Err(Error::Synthesis);
    }
    let omega = plan.omega.as_ref().ok_or(Error::Synthesis)?;
    let digest = super::binding::lineage_digest_fields(chip, region, public.fields(), pallas)?;
    let instances = omega_instances(chip, region, &digest, vesta)?;
    let output = chip.verify(
        region,
        omega,
        key,
        &instances,
        &proof.messages,
        &proof.length,
        VerificationMode::Soft,
    )?;
    // The witness key itself is hard-bound; a foreign lineage field is a soft failure.
    GlueChip::assert_equal(region, &output.key_digest, carried_key)?;
    let same_key = chip
        .uint()
        .glue()
        .is_equal(region, public.omega_key_digest(), carried_key)?;
    let mut valid = chip.uint().glue().and(region, &output.valid, &same_key)?;
    valid = chip.uint().glue().and(region, &valid, public.valid())?;
    for bit in decode_bits {
        valid = chip.uint().glue().and(region, &valid, bit)?;
    }
    Ok(IncomingOmegaCells {
        carried_key: carried_key.clone(),
        lineage_valid: public.valid().clone(),
        public: public.fields().clone(),
        vesta: vesta.clone(),
        proof: IncomingProofBinding::Messages(proof.clone()),
        valid,
        pallas: pallas.clone(),
        opening: FoldInputCells::from_claim(chip, region, &output.claim)?,
    })
}

/// Explicit mode-selected pair retaining both incoming Pallas obligations.
#[derive(Clone, Debug)]
pub struct SelectedPallasCells {
    pub(super) origin: IncomingOmegaCells,
    pub(super) modes: [ModeCells<Fp>; 2],
    pub(super) corrected: [iroha_plonk_gadgets::ecc::NonIdentityPoint<Fp>; 2],
    pub(super) pallas: FoldInputCells<Ep>,
    pub(super) opening: FoldInputCells<Ep>,
}

/// Selects incoming transported and proof-opening claims without merging them.
/// The very same modes must enter [`bind_modes`].
///
/// # Errors
/// Layout failure; equal Corrected points are unsatisfiable.
pub fn select_incoming(
    chip: &mut VerifierChip<Ep>,
    region: &mut Region<'_, Fp>,
    incoming: &IncomingOmegaCells,
    modes: &[ModeCells<Fp>; 2],
    corrected: &[iroha_plonk_gadgets::ecc::NonIdentityPoint<Fp>; 2],
) -> Result<SelectedPallasCells, Error> {
    Ok(SelectedPallasCells {
        origin: incoming.clone(),
        modes: modes.clone(),
        corrected: corrected.clone(),
        pallas: FoldInputCells::select_incoming(
            chip,
            region,
            &incoming.pallas,
            &corrected[0],
            &modes[0],
        )?,
        opening: FoldInputCells::select_incoming(
            chip,
            region,
            &incoming.opening,
            &corrected[1],
            &modes[1],
        )?,
    })
}

/// Constrains the global branch rule with every fixed incoming obligation.
/// Modes are ordered incoming Pallas, opening, Vesta, then sigma (when present).
/// All operation/consumer/decoder soft checks must be included in `soft_bits`.
///
/// # Errors
/// Wrong fixed mode count, empty soft checks, or layout failure.
pub fn bind_modes(
    chip: &mut VerifierChip<Ep>,
    region: &mut Region<'_, Fp>,
    plan: &AProofPlan,
    soft_bits: &[Bit<Fp>],
    modes: &[ModeCells<Fp>],
) -> Result<Bit<Fp>, Error> {
    let expected =
        3 * usize::from(plan.frame.has_incoming()) + usize::from(plan.sigma.slot_count() == 2);
    if modes.len() != expected || expected == 0 {
        return Err(Error::Synthesis);
    }
    constrain_incoming_modes(chip.uint().glue(), region, soft_bits, modes)
}

/// Closes A's exact Pallas schedule, or forwards Bootstrap's one hard Q opening.
/// The optional local fold exists exactly for non-bootstrap variants.
///
/// # Errors
/// Any dropped/reordered/duplicated Q, missing/extra predecessor/incoming slot,
/// unexpected fold proof or layout failure. `F_P` is always verified hard.
pub fn fold_pallas(
    chip: &mut VerifierChip<Ep>,
    region: &mut Region<'_, Fp>,
    plan: &AProofPlan,
    predecessor: Option<&PredecessorCells>,
    incoming: Option<&SelectedPallasCells>,
    q: &[VerifiedQCells],
    fold: Option<&ProofMessageCells>,
) -> Result<FoldInputCells<Ep>, Error> {
    if predecessor.is_some() != plan.frame.has_predecessor()
        || incoming.is_some() != plan.frame.has_incoming()
        || q.len() != plan.q.len()
        || q.iter().enumerate().any(|(index, q)| index != q.index)
    {
        return Err(Error::Synthesis);
    }
    for (expected, value) in plan.q.iter().zip(q) {
        let digest = expected
            .key
            .kagemusha_digest(expected.verifier.binding())
            .map_err(|_| Error::Synthesis)?;
        GlueChip::assert_constant(region, &value.key_digest, digest)?;
    }
    let Some(fold_plan) = &plan.pallas_fold else {
        if fold.is_some() || q.len() != 1 {
            return Err(Error::Synthesis);
        }
        return Ok(q[0].opening.clone());
    };
    let fold = fold.ok_or(Error::Synthesis)?;
    let mut inputs = Vec::with_capacity(2 + 2 * usize::from(incoming.is_some()) + q.len());
    if let Some(pred) = predecessor {
        inputs.extend([pred.pallas.clone(), pred.opening.clone()]);
    }
    if let Some(incoming) = incoming {
        inputs.extend([incoming.pallas.clone(), incoming.opening.clone()]);
    }
    inputs.extend(q.iter().map(|q| q.opening.clone()));
    let output = chip.verify_fold(
        region,
        fold_plan,
        &inputs,
        &fold.messages,
        &fold.length,
        VerificationMode::Hard,
    )?;
    FoldInputCells::from_claim(chip, region, &output.claim)
}
