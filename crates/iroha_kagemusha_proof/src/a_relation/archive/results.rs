//! Typed Archive evidence-result commitments and their unique fixed owners.
//!
//! Proposed bits are never evidence of execution. Every admitted stage program
//! must derive its own bit from exact committed sources. The Status proof owner
//! additionally binds the original soft Omega opening, including its failure dummy.

use iroha_pasta::{Ep, Fp};
use iroha_plonk::frontend::{Error, Region, Value};
use iroha_plonk_gadgets::{Bit, GlueChip};
use iroha_plonk_recursion::{
    accumulation_circuit::{FoldInputCells, FoldSource},
    obligation::{ModeCells, ledger::Variant},
    verifier::VerifierChip,
};

use super::{require_task, require_variant};
use crate::a_relation::{
    AProofPlan, IncomingOmegaCells, IncomingVestaCells, SelectedPallasCells, bind_modes,
    context::{
        ContextIncomingProof, ContextInputs, ContextObjectCells, ContextObjectSpec, ContextPlan,
    },
    proof::IncomingProofBinding,
    schedule::OperationTask,
    select_incoming,
};

#[cfg(test)]
mod tests;

/// Each of Archive's three complete incoming predicate groups.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum ArchiveResultTag {
    /// Original proof decoders, succinct verification and fixed key selection.
    Proofs = 1,
    /// Same-original evidence semantics, including exact credit/Payment binding.
    Evidence = 2,
    /// Receipt signature under the exact retained Request receiver key.
    Signatures = 3,
}
impl ArchiveResultTag {
    /// Fixed complete terminal result set, independent of all witness bytes.
    pub const ALL: [Self; 3] = [Self::Proofs, Self::Evidence, Self::Signatures];
    /// Unique production task allowed to derive this result.
    pub const fn task(self) -> OperationTask {
        match self {
            Self::Proofs => OperationTask::ArchiveProofs,
            Self::Evidence => OperationTask::ArchiveEvidence,
            Self::Signatures => OperationTask::ArchiveSignatures,
        }
    }
}

/// Complete result ownership and one fixed internal-word context slot.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ArchiveResultPlan {
    variant: Variant,
    owners: [u32; 3],
    index: usize,
    spec: ContextObjectSpec,
}
impl ArchiveResultPlan {
    /// The fixed size is11 words, plus35 original opening words for Status.
    /// The schema contains version, evidence kind, all three tag/owner pairs,
    /// all three result bits and the optional original k16 Pallas opening.
    /// # Errors
    /// Non-Archive variant or zero context tag.
    pub fn context_spec(variant: Variant, tag: u32) -> Result<ContextObjectSpec, Error> {
        require_variant(variant)?;
        if tag == 0 {
            return Err(Error::Synthesis);
        }
        Ok(ContextObjectSpec {
            tag,
            capacity: 32 * (11 + 35 * u32::from(variant == Variant::ArchiveStatus)),
        })
    }

    fn from_tasks(
        variant: Variant,
        groups: &[Vec<OperationTask>],
        index: usize,
        spec: ContextObjectSpec,
    ) -> Result<Self, Error> {
        require_variant(variant)?;
        OperationTask::validate(variant, groups)?;
        if groups.len() < 2
            || spec != Self::context_spec(variant, spec.tag)?
            || !groups
                .last()
                .is_some_and(|tasks| tasks.contains(&OperationTask::ArchiveEffects))
            || groups
                .last()
                .is_some_and(|tasks| tasks.contains(&OperationTask::ArchiveProofs))
        {
            return Err(Error::Synthesis);
        }
        let mut owners = [0; 3];
        for (owner, tag) in owners.iter_mut().zip(ArchiveResultTag::ALL) {
            *owner = u32::try_from(
                groups
                    .iter()
                    .position(|tasks| tasks.contains(&tag.task()))
                    .ok_or(Error::Synthesis)?,
            )
            .map_err(|_| Error::BoundsFailure)?;
        }
        Ok(Self {
            variant,
            owners,
            index,
            spec,
        })
    }

    /// Derive result ownership from all mandatory Archive operation tasks.
    /// This constructor validates metadata, not execution or artifact admission.
    /// # Errors
    /// Wrong variant, missing/duplicated tasks, nonterminal Effects, terminal
    /// Proofs owner, missing object index or incorrect fixed internal-word size.
    pub fn new(context: &ContextPlan, index: usize) -> Result<Self, Error> {
        let groups = (0..context.stage_count())
            .map(|stage| {
                context
                    .operation_tasks(stage)
                    .map(<[OperationTask]>::to_vec)
                    .ok_or(Error::Synthesis)
            })
            .collect::<Result<Vec<_>, _>>()?;
        Self::from_tasks(
            context.operation().frame().variant(),
            &groups,
            index,
            *context.object_specs().get(index).ok_or(Error::Synthesis)?,
        )
    }

    /// The single fixed stage required to constrain the named complete result.
    pub const fn owner(self, tag: ArchiveResultTag) -> u32 {
        self.owners[tag as usize - 1]
    }

    /// The exact internal-word schema committed by every continuation.
    pub const fn spec(self) -> ContextObjectSpec {
        self.spec
    }

    fn require_status_selection(self, stage: u32, stage_count: usize) -> Result<(), Error> {
        if self.variant != Variant::ArchiveStatus
            || usize::try_from(stage).ok().and_then(|s| s.checked_add(1)) != Some(stage_count)
            || self.owner(ArchiveResultTag::Proofs) >= stage
        {
            return Err(Error::Synthesis);
        }
        Ok(())
    }
}

/// Proposed incoming results and exact original Status opening, bound in `D_ctx`.
/// This does not certify any predicate and exposes no unchecked acceptance bit.
#[derive(Clone, Debug)]
pub struct ArchiveResultClaims {
    plan: ArchiveResultPlan,
    values: [Bit<Fp>; 3],
    opening: Option<FoldInputCells<Ep>>,
    context: ContextObjectCells,
}
impl ArchiveResultClaims {
    /// Assign three boolean claims and commit their complete typed schema.
    /// Status requires one canonical original k16 opening, Receive none.
    /// # Errors
    /// Missing/extraneous/wrong-source opening or layout failure.
    pub fn assign(
        chip: &mut VerifierChip<Ep>,
        region: &mut Region<'_, Fp>,
        plan: ArchiveResultPlan,
        values: [Value<bool>; 3],
        opening: Option<&FoldInputCells<Ep>>,
    ) -> Result<Self, Error> {
        if opening.is_some() != (plan.variant == Variant::ArchiveStatus)
            || opening.is_some_and(|o| o.source() != FoldSource::Fixed(16))
        {
            return Err(Error::Synthesis);
        }
        let values: [Bit<Fp>; 3] = values
            .map(|v| chip.uint().glue().boolean(region, v))
            .into_iter()
            .collect::<Result<Vec<_>, _>>()?
            .try_into()
            .map_err(|_| Error::Synthesis)?;
        let kind = if plan.variant == Variant::ArchiveReceive {
            1
        } else {
            2
        };
        let mut constants = vec![1, kind];
        for tag in ArchiveResultTag::ALL {
            constants.extend([u64::from(tag as u8), u64::from(plan.owner(tag))]);
        }
        let mut words = constants
            .into_iter()
            .map(|v| chip.uint().glue().constant(region, Fp::from(v)))
            .collect::<Result<Vec<_>, _>>()?;
        words.extend(values.iter().map(|v| v.word().clone()));
        if let Some(opening) = opening {
            words.extend([
                opening.source_k().clone(),
                opening.g().x().clone(),
                opening.g().y().clone(),
            ]);
            for challenge in opening.challenges() {
                words.extend([challenge.lo().word().clone(), challenge.hi().word().clone()]);
            }
        }
        let context = ContextObjectCells::from_internal_words(chip, region, plan.spec, &words)?;
        Ok(Self {
            plan,
            values,
            opening: opening.cloned(),
            context,
        })
    }

    /// Retain this proposed-result commitment at the plan's exact context index.
    pub const fn context(&self) -> &ContextObjectCells {
        &self.context
    }

    pub(super) fn bind_context(
        &self,
        region: &mut Region<'_, Fp>,
        plan: &ContextPlan,
        input: &ContextInputs<'_>,
    ) -> Result<(), Error> {
        if ArchiveResultPlan::new(plan, self.plan.index)? != self.plan
            || input.own_statement.variant() != self.plan.variant
            || input.objects.len() != plan.object_specs().len()
        {
            return Err(Error::Synthesis);
        }
        let expected = input.objects.get(self.plan.index).ok_or(Error::Synthesis)?;
        for (a, b) in self
            .context
            .commitment_words()
            .iter()
            .zip(expected.commitment_words())
        {
            GlueChip::assert_equal(region, a, &b)?;
        }
        Ok(())
    }

    pub(super) fn bind_derived(
        &self,
        region: &mut Region<'_, Fp>,
        plan: &ContextPlan,
        stage: u32,
        input: &ContextInputs<'_>,
        tag: ArchiveResultTag,
        derived: &Bit<Fp>,
    ) -> Result<(), Error> {
        require_task(plan, stage, tag.task())?;
        self.bind_context(region, plan, input)?;
        if self.plan.owner(tag) != stage {
            return Err(Error::Synthesis);
        }
        GlueChip::assert_equal(region, self.values[tag as usize - 1].word(), derived.word())
    }

    pub(super) fn opening(&self) -> Result<&FoldInputCells<Ep>, Error> {
        self.opening.as_ref().ok_or(Error::Synthesis)
    }

    /// Select the original Status obligations retained by the authenticated context.
    ///
    /// The complete staged source must resume W and execute terminal Effects.
    /// Its preceding Proofs owner binds the exact result and original opening
    /// retained here; no independently supplied verdict or opening is accepted.
    /// Transported Pallas, verifier opening and Vesta remain distinct obligations.
    /// # Errors
    /// Wrong variant or terminal owner, missing original messages, changed result
    /// context, incorrect correction/mode shape, or layout failure.
    pub fn select_status_incoming(
        &self,
        chip: &mut VerifierChip<Ep>,
        region: &mut Region<'_, Fp>,
        plan: &ContextPlan,
        stage: u32,
        input: &ContextInputs<'_>,
    ) -> Result<(SelectedPallasCells, IncomingVestaCells), Error> {
        require_task(plan, stage, OperationTask::ArchiveEffects)?;
        self.bind_context(region, plan, input)?;
        self.plan
            .require_status_selection(stage, plan.stage_count())?;
        let incoming = input.incoming.ok_or(Error::Synthesis)?;
        let ContextIncomingProof::Messages(messages) = incoming.proof else {
            return Err(Error::Synthesis);
        };
        let [pallas_mode, opening_mode, vesta_mode] = input.modes else {
            return Err(Error::Synthesis);
        };
        let [pallas_correction, opening_correction] = input.pallas_corrections else {
            return Err(Error::Synthesis);
        };
        let [vesta_correction] = input.vesta_corrections else {
            return Err(Error::Synthesis);
        };
        let origin = IncomingOmegaCells {
            carried_key: input.successor.public.omega_key_digest().clone(),
            lineage_valid: incoming.public.valid().clone(),
            public: incoming.public.fields().clone(),
            vesta: incoming.vesta.clone(),
            proof: IncomingProofBinding::Messages(messages.clone()),
            valid: self.values[ArchiveResultTag::Proofs as usize - 1].clone(),
            pallas: incoming.pallas.clone(),
            opening: self.opening()?.clone(),
        };
        let selected = select_incoming(
            chip,
            region,
            &origin,
            &[pallas_mode.clone(), opening_mode.clone()],
            &[pallas_correction.clone(), opening_correction.clone()],
        )?;
        Ok((
            selected,
            IncomingVestaCells {
                claim: incoming.vesta.clone(),
                mode: vesta_mode.clone(),
                corrected: vesta_correction.clone(),
            },
        ))
    }

    pub(super) fn lineage_verdict(
        &self,
        chip: &mut VerifierChip<Ep>,
        region: &mut Region<'_, Fp>,
        plan: &ContextPlan,
        stage: u32,
        input: &ContextInputs<'_>,
    ) -> Result<Bit<Fp>, Error> {
        require_task(plan, stage, OperationTask::ArchiveLineagePending)?;
        self.bind_context(region, plan, input)?;
        self.mode_verdict(chip, region, plan.operation(), input.modes)
    }

    // Shared by the early adjusted-map owner and the terminal iff closure.
    // A corrected obligation forces no-op even when every soft bit is true.
    fn mode_verdict(
        &self,
        chip: &mut VerifierChip<Ep>,
        region: &mut Region<'_, Fp>,
        operation: &AProofPlan,
        modes: &[ModeCells<Fp>],
    ) -> Result<Bit<Fp>, Error> {
        bind_modes(chip, region, operation, &self.values, modes)
    }

    pub(super) fn terminal_modes(
        &self,
        chip: &mut VerifierChip<Ep>,
        region: &mut Region<'_, Fp>,
        plan: &ContextPlan,
        stage: u32,
        input: &ContextInputs<'_>,
    ) -> Result<Bit<Fp>, Error> {
        require_task(plan, stage, OperationTask::ArchiveEffects)?;
        self.bind_context(region, plan, input)?;
        if usize::try_from(stage).ok().and_then(|s| s.checked_add(1)) != Some(plan.stage_count()) {
            return Err(Error::Synthesis);
        }
        self.mode_verdict(chip, region, plan.operation(), input.modes)
    }
}
