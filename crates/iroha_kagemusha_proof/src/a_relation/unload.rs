//! Unload and Retiring's complete fixed operation-task composition (lean lineage).
//!
//! Both consume an already folded predecessor. A proves the transition directly,
//! so there is no own sigma verifier, and the own receipt is authenticated under
//! the predecessor's payment key. The credential digest and payment key are
//! carried by continuity, so the credential and its certificate are not
//! re-verified. The receipt's `proof_digest` names the `Omega(pred) || sigma`
//! carriers the ledger verifies natively; Λ reads it from the signed receipt body,
//! and `receipt::bind` keeps it nonzero. Stage keys must additionally close their
//! exact recursive obligation ledger before admission.
//! TODO: qualify the genuine complete stage chains and admit only their terminal
//! keys through the final rooted artifact catalog.

use ff::Field;
use iroha_pasta::{Ep, Fp};
use iroha_plonk::frontend::{Error, Region, Value};
use iroha_plonk_gadgets::{GlueChip, UintChip, bytes::tape::BytesChip, p256::VerifyMode};
use iroha_plonk_recursion::{obligation::ledger::Variant, verifier::VerifierChip};

use super::{
    SignatureQCells,
    context::{ContextInputs, ContextObjectCells, ContextObjectSpec, ContextPlan},
    own::OwnPolicy,
    schedule::OperationTask,
};
use crate::{
    operation_relation::{
        administrative,
        map_effects::{InsertCells, MapEffectsChip, MapState, MapTransition},
        objects::{
            ObjectKind, SignedObjectCells,
            receipt::{self, ReceiptContext},
        },
    },
    q_signature::{QSignaturePlan, SignatureKey, SignatureSlot},
};

const KINDS: [ObjectKind; 1] = [ObjectKind::Receipt];

/// Exact own receipt tape, the only signed object Λ consumes.
#[derive(Clone, Debug)]
pub struct UnloadObjects {
    objects: [SignedObjectCells; 1],
    context: [ContextObjectCells; 1],
}
impl UnloadObjects {
    /// Fixed ordered object schema, including each original signature.
    /// # Errors
    /// Impossible fixed-size conversion.
    pub fn context_specs() -> Result<[ContextObjectSpec; 1], Error> {
        KINDS
            .into_iter()
            .enumerate()
            .map(|(i, kind)| {
                Ok(ContextObjectSpec {
                    tag: u32::try_from(i + 1).map_err(|_| Error::BoundsFailure)?,
                    capacity: u32::try_from(kind.body_len() + 64)
                        .map_err(|_| Error::BoundsFailure)?,
                })
            })
            .collect::<Result<Vec<_>, Error>>()?
            .try_into()
            .map_err(|_| Error::Synthesis)
    }

    /// Decode hard own objects and commit the identical bounded byte tapes.
    /// # Errors
    /// Wrong fixed schema or layout failure; malformed own objects are unsatisfiable.
    pub fn decode(
        chip: &mut VerifierChip<Ep>,
        bytes: &mut BytesChip<Fp>,
        region: &mut Region<'_, Fp>,
        sources: [&[Value<u8>]; 1],
    ) -> Result<Self, Error> {
        let mut objects = Vec::new();
        let mut context = Vec::new();
        for ((kind, source), spec) in KINDS.into_iter().zip(sources).zip(Self::context_specs()?) {
            let run = bytes.run(
                region,
                source,
                &kind.primary_segments(),
                &kind.secondary_segments(),
            )?;
            let lanes = chip.operation_lanes()?;
            let object = SignedObjectCells::from_run(
                &mut UintChip::new(lanes.glue, lanes.range),
                lanes.hash,
                region,
                kind,
                &run,
            )?;
            context.push(ContextObjectCells::from_exact_run(
                chip,
                region,
                spec,
                object.digest(),
                &run,
            )?);
            objects.push(object);
        }
        Ok(Self {
            objects: objects.try_into().map_err(|_| Error::Synthesis)?,
            context: context.try_into().map_err(|_| Error::Synthesis)?,
        })
    }

    /// Same-tape commitments retained by every stage's split context.
    pub const fn context(&self) -> &[ContextObjectCells; 1] {
        &self.context
    }

    fn bind_context(
        &self,
        region: &mut Region<'_, Fp>,
        input: &ContextInputs<'_>,
    ) -> Result<(), Error> {
        if input.objects.len() != self.context.len() {
            return Err(Error::Synthesis);
        }
        for (actual, expected) in self.context.iter().zip(input.objects) {
            for (actual, expected) in actual
                .commitment_words()
                .iter()
                .zip(expected.commitment_words())
            {
                GlueChip::assert_equal(region, actual, &expected)?;
            }
        }
        Ok(())
    }

    fn authenticate(
        &self,
        chip: &mut VerifierChip<Ep>,
        region: &mut Region<'_, Fp>,
        policy: OwnPolicy,
        input: &ContextInputs<'_>,
        signature: &SignatureQCells,
    ) -> Result<(), Error> {
        let slots = signature.slots();
        let schema = UnloadStagePlan::signature_schema()?;
        if slots.len() != schema.slots().len()
            || slots.iter().zip(schema.slots()).any(|(actual, expected)| {
                actual.mode() != expected.mode || actual.key_policy() != expected.key
            })
        {
            return Err(Error::Synthesis);
        }
        let predecessor = input.predecessor.ok_or(Error::Synthesis)?;
        // The payment key is carried by continuity from the predecessor lineage.
        let key = core::array::from_fn(|i| predecessor.public.fields()[9 + i].clone());
        let valid = self.objects[0].bind_signature(region, &slots[0], &key)?;
        GlueChip::assert_constant(region, valid.word(), Fp::ONE)?;
        let provider = policy.provider(chip, region)?;
        let wallet = core::array::from_fn(|i| predecessor.public.fields()[6 + i].clone());
        let zero = chip.uint().glue().constant(region, Fp::ZERO)?;
        let lanes = chip.operation_lanes()?;
        let valid = receipt::bind(
            &mut UintChip::new(lanes.glue, lanes.range),
            lanes.hash,
            region,
            &self.objects[0],
            &ReceiptContext {
                wallet: &wallet,
                provider: &provider,
                statement: input.own_statement,
                // Λ proves the transition directly, so this sigma-only digest
                // names carriers Λ does not consume; it is the signed body's own.
                proof_digest: self.objects[0].word(9)?,
                payment_digest: &zero,
            },
        )?;
        GlueChip::assert_constant(region, valid.word(), Fp::ONE)
    }
}

/// Private inputs present exactly when the fixed stage owns their task.
#[derive(Clone, Copy, Default)]
pub struct UnloadStageWitness<'a> {
    /// Unload's recovery insertion; always absent for Retiring.
    pub recovery: Option<&'a InsertCells>,
    /// Hard own-receipt Q0 signature.
    pub signatures: Option<&'a SignatureQCells>,
}

/// Fixed Unload/Retiring task, object and signature-Q ownership.
#[derive(Clone, Debug)]
pub struct UnloadStagePlan {
    context: ContextPlan,
    policy: OwnPolicy,
}
impl UnloadStagePlan {
    /// The one mandatory hard slot: the own receipt under the predecessor payment key.
    /// # Errors
    /// Impossible fixed schema.
    pub fn signature_schema() -> Result<QSignaturePlan, Error> {
        QSignaturePlan::new(vec![SignatureSlot {
            mode: VerifyMode::Hard,
            key: SignatureKey::Variable,
        }])
    }

    /// Require every task once, exact object/Q schemas and the owning stage.
    /// The plan is inline (no own sigma verifier), and Q0 is the hard own receipt.
    /// # Errors
    /// Wrong variant, missing task, schema mismatch or misplaced owner.
    pub fn new(context: ContextPlan, policy: OwnPolicy) -> Result<Self, Error> {
        let variant = context.operation().frame().variant();
        if !matches!(variant, Variant::Unload | Variant::Retiring)
            || !context.operation().is_inline()
            || context.operation().q_count() != 1
            || context.object_specs() != UnloadObjects::context_specs()?
        {
            return Err(Error::Synthesis);
        }
        let signature = Self::signature_schema()?;
        let descriptor = context
            .operation()
            .q(0)
            .ok_or(Error::Synthesis)?
            .verifier()
            .binding()
            .descriptor();
        if descriptor.instance_lengths
            != [u32::try_from(signature.instance_length()).map_err(|_| Error::BoundsFailure)?]
            || descriptor.instance_types.as_deref() != Some(&QSignaturePlan::instance_types())
        {
            return Err(Error::Synthesis);
        }
        let groups = (0..context.stage_count())
            .map(|stage| context.operation_tasks(stage).unwrap_or_default().to_vec())
            .collect::<Vec<_>>();
        OperationTask::validate(variant, &groups)?;
        // A1: the transition beside the hard predecessor; A2: the own receipt on Q0.
        let effect = if variant == Variant::Unload {
            OperationTask::UnloadRecovery
        } else {
            OperationTask::RetiringState
        };
        let partitions = [vec![], vec![0]];
        if groups != [vec![effect], vec![OperationTask::UnloadAuthorization]]
            || context.predecessor_stage() != Some(0)
            || partitions
                .iter()
                .enumerate()
                .any(|(stage, expected)| context.q_partition(stage) != Some(expected.as_slice()))
        {
            return Err(Error::Synthesis);
        }
        Ok(Self { context, policy })
    }

    /// Exact context whose digest every fixed continuation binds.
    pub const fn context(&self) -> &ContextPlan {
        &self.context
    }

    /// Execute this stage's tasks directly on the committed context cells.
    ///
    /// No incoming soft verifier or selectable burn branch exists here. The own
    /// receipt, its signature and the state effects are hard requirements.
    /// # Errors
    /// Wrong stage/variant, missing or extraneous witness, or a failed constraint.
    pub fn constrain_stage(
        &self,
        chip: &mut VerifierChip<Ep>,
        region: &mut Region<'_, Fp>,
        stage: usize,
        objects: &UnloadObjects,
        input: &ContextInputs<'_>,
        witness: UnloadStageWitness<'_>,
    ) -> Result<(), Error> {
        let tasks = self
            .context
            .operation_tasks(stage)
            .ok_or(Error::Synthesis)?;
        if input.own_statement.variant() != self.context.operation().frame().variant()
            || tasks.contains(&OperationTask::UnloadRecovery) != witness.recovery.is_some()
            || tasks.contains(&OperationTask::UnloadAuthorization) != witness.signatures.is_some()
        {
            return Err(Error::Synthesis);
        }
        objects.bind_context(region, input)?;
        let predecessor = input.predecessor.ok_or(Error::Synthesis)?;
        let transition = MapTransition {
            statement: input.own_statement,
            predecessor: MapState {
                state: predecessor.state,
                lineage: predecessor.public,
            },
            successor: MapState {
                state: input.successor.state,
                lineage: input.successor.public,
            },
        };
        for task in tasks {
            match task {
                OperationTask::UnloadRecovery => {
                    let lanes = chip.operation_lanes()?;
                    MapEffectsChip::new(lanes.glue, lanes.range, lanes.hash).recovery(
                        region,
                        &transition,
                        witness.recovery.ok_or(Error::Synthesis)?,
                    )?;
                }
                OperationTask::RetiringState => {
                    let lanes = chip.operation_lanes()?;
                    administrative::monetary(
                        &mut UintChip::new(lanes.glue, lanes.range),
                        lanes.hash,
                        region,
                        &transition,
                    )?;
                }
                OperationTask::UnloadAuthorization => {
                    let signature = witness.signatures.ok_or(Error::Synthesis)?;
                    signature.bind_context(
                        region,
                        self.context.operation(),
                        0,
                        input.q_instances.first().ok_or(Error::Synthesis)?,
                    )?;
                    objects.authenticate(chip, region, self.policy, input, signature)?;
                }
                _ => return Err(Error::Synthesis),
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests;
