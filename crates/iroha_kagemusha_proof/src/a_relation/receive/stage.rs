//! Fixed Receive task dispatch with complete object and signature-Q schemas.

use iroha_pasta::{Ep, Fp};
use iroha_plonk::frontend::{Error, Region};
use iroha_plonk_gadgets::{imt::OpeningCells, p256::VerifyMode};
use iroha_plonk_recursion::{obligation::ledger::Variant, verifier::VerifierChip};

use super::{
    ReceiveObjects, ReceiveProofDigest, ReceiveProofInputs, ReceiveSignedObjects,
    authorization::{
        ReceiveAuthorizationObjects, ReceiveSignatureInputs, ReceiveSignatureQProjection,
    },
    maps::{self, ReceiveEffectsCells},
};
use crate::{
    a_relation::{
        SignatureQCells,
        context::{ContextInputs, ContextObjectSpec, ContextPlan},
        own::OwnPolicy,
        schedule::OperationTask,
        transition::TransitionInputs,
    },
    operation_relation::map_effects::ReceiveMapWitness,
    q_signature::{QSignaturePlan, SignatureKey, SignatureSlot},
};

#[cfg(test)]
mod tests;

/// Complete fixed Receive task and object plan (lean lineage). A proves the own
/// Receive step inline (`ReceiveTransition`); Q0 is the incoming-only `Q_sigma`
/// over the original Send sigma, and Q1 the merged signature leaf: the own
/// receipt hard, then the original incoming Send receipt and Request soft, plus
/// the quoted credential and its fixed-root certificate when renewed.
///
/// This validates a program schema, not artifact admission. Every generated
/// stage circuit must execute `constrain_stage` and close its exact recursive
/// ledger before the final catalog can authenticate its key.
#[derive(Clone, Debug)]
pub struct ReceiveStagePlan {
    context: ContextPlan,
    policy: OwnPolicy,
    signature: QSignaturePlan,
}

/// Exact common context and same-source object views consumed by each stage.
#[derive(Clone, Copy)]
pub struct ReceiveStageInputs<'a> {
    /// Original context rebound by the split continuation proof.
    pub context: &'a ContextInputs<'a>,
    /// Exact combined consuming digest producer, only in `ProofDigest`.
    pub proof_digest: Option<&'a ReceiveProofDigest>,
    /// Complete incoming Payment views, only when this stage owns Objects.
    pub objects: Option<&'a ReceiveObjects>,
    /// Original signed sources, only for Signatures.
    pub signed: Option<&'a ReceiveSignedObjects>,
    /// Own receipt and quoted tapes, only for Authorization or Signatures.
    pub authorization: Option<&'a ReceiveAuthorizationObjects>,
}

/// Inputs present exactly for the named tasks assigned to the current stage.
#[derive(Clone, Copy, Default)]
pub struct ReceiveStageWitness<'a> {
    /// Actual incoming verifier inputs, only in the Proofs owner.
    pub proofs: Option<ReceiveProofInputs<'a>>,
    /// The merged signature Q1 verified in this stage, only in Authorization,
    /// which owns its hard own-receipt slot.
    pub own_signatures: Option<&'a SignatureQCells>,
    /// The incoming soft slots of the same Q1, only in Signatures.
    pub incoming_signatures: Option<&'a ReceiveSignatureQProjection>,
    /// Unique consumed-credit search route, only in Nonmembership.
    pub nonmembership: Option<&'a OpeningCells<Fp>>,
    /// Exact OQ-3/credit-record paths, only in the consumed/credit effect owners.
    pub effects: Option<&'a ReceiveMapWitness>,
    /// The σ_recv step relation, only in the Transition owner.
    pub transition: Option<TransitionInputs<'a>>,
}

impl ReceiveStagePlan {
    /// Fixed Q index of the merged signature leaf; Q0 is the incoming-only `Q_sigma`.
    pub const SIGNATURE_Q: usize = 1;

    /// Require all fixed task owners, exact nine tapes and the merged signature schema.
    /// # Errors
    /// Wrong variant/Q count/schema, an own sigma verifier, absent tasks, wrong
    /// signature-Q partition or invalid fixed capacities/root key.
    pub fn new(context: ContextPlan, policy: OwnPolicy) -> Result<Self, Error> {
        let variant = context.operation().frame().variant();
        if !matches!(variant, Variant::Receive | Variant::ReceiveRenewed)
            || context.operation().q_count() != 2
            || !context.operation().is_inline()
            || !context.operation().has_incoming_sigma()
            || context.receive_results().is_none()
        {
            return Err(Error::Synthesis);
        }
        let specs = context.object_specs();
        if specs.len() != 9
            || specs
                != Self::context_specs(
                    variant,
                    specs[4].capacity as usize,
                    specs[5].capacity as usize,
                )?
        {
            return Err(Error::Synthesis);
        }
        let signature = Self::signature_schema_for(variant, policy)?;
        let descriptor = context
            .operation()
            .q(Self::SIGNATURE_Q)
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
        for stage in 0..context.stage_count() {
            let tasks = context.operation_tasks(stage).ok_or(Error::Synthesis)?;
            let partition = context.q_partition(stage).ok_or(Error::Synthesis)?;
            if stage + 1 == context.stage_count()
                && tasks.iter().any(|task| {
                    matches!(
                        task,
                        OperationTask::ReceiveConsumedEffects | OperationTask::ReceiveCreditEffects
                    )
                })
            {
                return Err(Error::Synthesis);
            }
            // Authorization verifies Q1 in its own stage; Signatures projects the
            // same Q1 in that stage or a later one.
            let q = Self::SIGNATURE_Q;
            for task in [
                OperationTask::ReceiveAuthorization,
                OperationTask::ReceiveSignatures,
            ] {
                let earlier = task == OperationTask::ReceiveSignatures
                    && (0..stage).any(|i| {
                        context
                            .q_partition(i)
                            .is_some_and(|partition| partition.contains(&q))
                    });
                if tasks.contains(&task) && !partition.contains(&q) && !earlier {
                    return Err(Error::Synthesis);
                }
            }
        }
        Ok(Self {
            context,
            policy,
            signature,
        })
    }

    /// The merged signature leaf: the own receipt hard (1V), then the incoming
    /// Send receipt and Request soft (2V), plus the quoted credential and its
    /// fixed-root certificate soft when renewed (1V1F).
    /// # Errors
    /// Non-Receive variant or invalid pinned root key.
    pub fn signature_schema_for(
        variant: Variant,
        policy: OwnPolicy,
    ) -> Result<QSignaturePlan, Error> {
        if !matches!(variant, Variant::Receive | Variant::ReceiveRenewed) {
            return Err(Error::Synthesis);
        }
        let mut slots = vec![SignatureSlot {
            mode: VerifyMode::Hard,
            key: SignatureKey::Variable,
        }];
        slots.extend(
            [SignatureSlot {
                mode: VerifyMode::Soft,
                key: SignatureKey::Variable,
            }; 2],
        );
        if variant == Variant::ReceiveRenewed {
            slots.extend([
                SignatureSlot {
                    mode: VerifyMode::Soft,
                    key: SignatureKey::Variable,
                },
                SignatureSlot {
                    mode: VerifyMode::Soft,
                    key: SignatureKey::Fixed(policy.root),
                },
            ]);
        }
        QSignaturePlan::new(slots)
    }

    /// Fixed incoming six-slot prefix and mandatory own-receipt/quoted three-slot suffix.
    /// # Errors
    /// Wrong variant or invalid active carrier capacities.
    pub fn context_specs(
        variant: Variant,
        omega_capacity: usize,
        sigma_capacity: usize,
    ) -> Result<Vec<ContextObjectSpec>, Error> {
        let mut specs = ReceiveObjects::context_specs(omega_capacity, sigma_capacity)?.to_vec();
        specs.extend(ReceiveAuthorizationObjects::context_specs(variant)?);
        Ok(specs)
    }

    /// Context bound by every stage and its corresponding W verifier.
    pub const fn context(&self) -> &ContextPlan {
        &self.context
    }

    /// Fixed signature schema of Q1; Q0 is the separate sigma program.
    pub fn signature_schema(&self, index: usize) -> Option<&QSignaturePlan> {
        (index == Self::SIGNATURE_Q).then_some(&self.signature)
    }

    /// Execute exactly this stage's named tasks on its context-bound sources.
    ///
    /// Returns terminal map effects only in the last stage. This does not
    /// replace hard Q/W/predecessor verification or accumulator closure.
    /// # Errors
    /// Missing/extraneous task inputs, wrong bundle identity, or constraint failure.
    pub fn constrain_stage(
        &self,
        chip: &mut VerifierChip<Ep>,
        region: &mut Region<'_, Fp>,
        stage: u32,
        input: ReceiveStageInputs<'_>,
        witness: ReceiveStageWitness<'_>,
    ) -> Result<Option<ReceiveEffectsCells>, Error> {
        let tasks = self
            .context
            .operation_tasks(usize::try_from(stage).map_err(|_| Error::BoundsFailure)?)
            .ok_or(Error::Synthesis)?;
        for (needed, present) in [
            (
                tasks.contains(&OperationTask::ReceiveProofDigest),
                input.proof_digest.is_some(),
            ),
            (
                tasks.contains(&OperationTask::ReceiveObjects),
                input.objects.is_some(),
            ),
            (
                tasks
                    .iter()
                    .any(|task| matches!(task, OperationTask::ReceiveSignatures)),
                input.signed.is_some(),
            ),
            (
                tasks.iter().any(|task| {
                    matches!(
                        task,
                        OperationTask::ReceiveAuthorization | OperationTask::ReceiveSignatures
                    )
                }),
                input.authorization.is_some(),
            ),
        ] {
            if needed != present {
                return Err(Error::Synthesis);
            }
        }
        for (task, present) in [
            (OperationTask::ReceiveProofs, witness.proofs.is_some()),
            (
                OperationTask::ReceiveAuthorization,
                witness.own_signatures.is_some(),
            ),
            (
                OperationTask::ReceiveSignatures,
                witness.incoming_signatures.is_some(),
            ),
            (
                OperationTask::ReceiveNonmembership,
                witness.nonmembership.is_some(),
            ),
            (
                OperationTask::ReceiveTransition,
                witness.transition.is_some(),
            ),
        ] {
            if tasks.contains(&task) != present {
                return Err(Error::Synthesis);
            }
        }
        let needs_maps = tasks.iter().any(|task| {
            matches!(
                task,
                OperationTask::ReceiveConsumedEffects | OperationTask::ReceiveCreditEffects
            )
        });
        if needs_maps != witness.effects.is_some() {
            return Err(Error::Synthesis);
        }
        if witness
            .own_signatures
            .is_some_and(|bundle| bundle.verified().index != Self::SIGNATURE_Q)
        {
            return Err(Error::Synthesis);
        }
        let mut effects = None;
        for task in tasks {
            match task {
                OperationTask::ReceiveProofDigest => input
                    .proof_digest
                    .ok_or(Error::Synthesis)?
                    .bind_context(region, &self.context, stage, input.context)?,
                OperationTask::ReceiveProofs => witness
                    .proofs
                    .ok_or(Error::Synthesis)?
                    .sources
                    .constrain_proofs(
                        chip,
                        region,
                        &self.context,
                        stage,
                        input.context,
                        witness.proofs.ok_or(Error::Synthesis)?,
                    )?,
                OperationTask::ReceiveObjects => input
                    .objects
                    .ok_or(Error::Synthesis)?
                    .bind_result(chip, region, &self.context, stage, input.context)?,
                OperationTask::ReceiveSignatures => input
                    .authorization
                    .ok_or(Error::Synthesis)?
                    .constrain_signatures(
                        chip,
                        region,
                        &self.context,
                        stage,
                        input.context,
                        ReceiveSignatureInputs {
                            policy: self.policy,
                            objects: input.signed.ok_or(Error::Synthesis)?,
                            incoming: witness.incoming_signatures.ok_or(Error::Synthesis)?,
                        },
                    )?,
                OperationTask::ReceiveNonmembership => maps::constrain_nonmembership(
                    chip,
                    region,
                    &self.context,
                    stage,
                    input.context,
                    witness.nonmembership.ok_or(Error::Synthesis)?,
                )?,
                OperationTask::ReceiveAuthorization => input
                    .authorization
                    .ok_or(Error::Synthesis)?
                    .constrain_own_receipt(
                        chip,
                        region,
                        &self.context,
                        stage,
                        input.context,
                        (self.policy, witness.own_signatures.ok_or(Error::Synthesis)?),
                    )?,
                OperationTask::ReceiveTransition => witness
                    .transition
                    .ok_or(Error::Synthesis)?
                    .constrain(chip, region, input.context.own_statement)?,
                OperationTask::ReceiveConsumedEffects | OperationTask::ReceiveCreditEffects => {
                    maps::constrain_map_effects(
                        chip,
                        region,
                        &self.context,
                        stage,
                        input.context,
                        witness.effects.ok_or(Error::Synthesis)?,
                        *task,
                    )?
                }
                OperationTask::ReceiveEffects => {
                    effects = Some(maps::constrain_effects(
                        chip,
                        region,
                        &self.context,
                        stage,
                        input.context,
                    )?)
                }
                _ => return Err(Error::Synthesis),
            }
        }
        Ok(effects)
    }
}
