//! Complete fixed Archive owner dispatch and original-object schema.

use iroha_pasta::{Ep, Fp};
use iroha_plonk::frontend::{Error, Region};
use iroha_plonk_gadgets::bytes::tape::BytesChip;
use iroha_plonk_recursion::{obligation::ledger::Variant, verifier::VerifierChip};

use super::{
    authorization::ArchiveAuthorizationObjects,
    evidence::{self, ArchiveEvidenceSource},
    incoming::ArchiveIncomingObjects,
    maps::{self, ArchiveEffectsCells, ArchivePendingWitness},
    proofs::{ArchiveProofInputs, ArchiveProofSources},
    results::{ArchiveResultClaims, ArchiveResultPlan},
    retained::{ArchiveRetainedPayment, ArchiveRetainedProofs},
};
use crate::{
    a_relation::{
        SignatureQCells,
        context::{ContextInputs, ContextObjectSpec, ContextPlan},
        own::OwnPolicy,
        schedule::OperationTask,
    },
    q_signature::QSignaturePlan,
};

/// Fixed complete Archive program. This checks source schema and dispatch,
/// not circuit capacity, actual Q/A/W execution or terminal artifact admission.
#[derive(Clone, Debug)]
pub struct ArchiveStagePlan {
    context: ContextPlan,
    policy: OwnPolicy,
    signature: QSignaturePlan,
    signature_q: usize,
    results: ArchiveResultPlan,
}

/// Same original context and exact views required by this particular stage.
#[derive(Clone, Copy)]
pub struct ArchiveStageInputs<'a> {
    /// Complete source context, rebound by every recursive continuation.
    pub context: &'a ContextInputs<'a>,
    /// All three proposed results and original Status opening.
    pub results: &'a ArchiveResultClaims,
    /// Own receipt only for its Authorization owner.
    pub own: Option<&'a ArchiveAuthorizationObjects>,
    /// Exact historical Payment only for its mandatory hard owner.
    pub retained: Option<&'a ArchiveRetainedPayment>,
    /// Exact opaque proof tapes only for their independent hard owner.
    pub retained_proofs: Option<&'a ArchiveRetainedProofs>,
    /// Held Request/receiver and soft receipt, for Evidence or Signatures.
    pub incoming: Option<&'a ArchiveIncomingObjects>,
    /// Exact incoming proof carrier only for the Proofs owner.
    pub proof_source: Option<&'a ArchiveProofSources>,
}

/// Additional actual verifiers, original tapes and paths for the assigned tasks.
#[derive(Clone, Copy, Default)]
pub struct ArchiveStageWitness<'a> {
    /// Merged signature leaf: the own receipt hard and the incoming receipt soft.
    /// Required exactly at the stage owning Authorization and Signatures.
    pub signatures: Option<&'a SignatureQCells>,
    /// Receive marker or the Status trusted Omega key.
    pub proof: Option<ArchiveProofInputs<'a>>,
    /// Original incoming evidence tapes, only for Evidence.
    pub evidence: Option<ArchiveEvidenceSource<'a>>,
    /// Exact unconditional committed-core pending removal.
    pub core_pending: Option<&'a ArchivePendingWitness>,
    /// Exact adjusted pending removal, with the committed three-result verdict.
    pub lineage_pending: Option<&'a ArchivePendingWitness>,
}

impl ArchiveStagePlan {
    /// Compose every original-source owner over the complete envelope domain.
    ///
    /// The first stage verifies the hard predecessor. `ArchiveReceive`'s
    /// incoming-only `Q_sigma` has a dedicated proof stage; the merged signature
    /// leaf belongs to the stage owning both Authorization and Signatures. Source
    /// capacities and owner order are compiled properties; private inputs cannot
    /// narrow them. Actual source key generation must still establish each
    /// stage's capacity and every recursive proof must close before artifact
    /// admission.
    /// # Errors
    /// Wrong operation, missing predecessor or invalid fixed Q/source schema.
    pub fn full(
        operation: crate::a_relation::AProofPlan,
        policy: OwnPolicy,
    ) -> Result<Self, Error> {
        let variant = operation.frame().variant();
        let specs = Self::full_context_specs(variant)?;
        let context =
            crate::a_relation::schedule::compiled::OperationSchedule::for_variant(variant)
                .bind(operation, specs)?;
        Self::new(context, policy)
    }

    /// Complete current envelope domains, including malformed incoming originals.
    ///
    /// Historical proof bytes are opaque to the retained owner, so its capacity
    /// cannot be inferred from a measured sigma or pending-descriptor membership.
    /// The retained owner separately enforces the hard combined Payment bound.
    /// Exact incoming descriptor lengths remain total verifier predicates.
    /// # Errors
    /// Non-Archive variant or invalid fixed source schema.
    pub fn full_context_specs(variant: Variant) -> Result<Vec<ContextObjectSpec>, Error> {
        let incoming = match variant {
            Variant::ArchiveReceive => super::MAX_RECEIVE_SIGMA_RAW_BYTES,
            Variant::ArchiveStatus => super::MAX_STATUS_OMEGA_RAW_BYTES,
            _ => return Err(Error::Synthesis),
        };
        Self::context_specs(
            variant,
            crate::a_relation::receive::MAX_OMEGA_RAW_BYTES,
            crate::a_relation::receive::MAX_SIGMA_RAW_BYTES,
            incoming,
        )
    }

    /// Own receipt, retained9, incoming receipt/raw proof, exact evidence and typed results.
    /// All capacities belong to this fixed key schema, never a witness choice.
    /// Smaller component profiles do not qualify the complete envelope domain;
    /// production composition starts with [`Self::full_context_specs`].
    /// # Errors
    /// Wrong variant or empty/overflowing active-proof capacity.
    pub fn context_specs(
        variant: Variant,
        retained_omega: usize,
        retained_sigma: usize,
        incoming_proof: usize,
    ) -> Result<Vec<ContextObjectSpec>, Error> {
        super::require_variant(variant)?;
        if incoming_proof == 0 {
            return Err(Error::Synthesis);
        }
        let mut specs = ArchiveAuthorizationObjects::context_specs()?.to_vec();
        specs.extend(ArchiveRetainedPayment::context_specs(
            retained_omega,
            retained_sigma,
        )?);
        specs.push(ArchiveIncomingObjects::context_specs()?[2]);
        specs.push(ContextObjectSpec {
            tag: 12,
            capacity: u32::try_from(incoming_proof).map_err(|_| Error::BoundsFailure)?,
        });
        specs.extend(evidence::evidence_specs(variant)?);
        specs.push(ArchiveResultPlan::context_spec(
            variant,
            u32::try_from(specs.len() + 1).map_err(|_| Error::BoundsFailure)?,
        )?);
        Ok(specs)
    }

    /// Validate complete tasks, all original categories and the actual Q schemas.
    /// A proves the own step inline, so the plan verifies no own sigma and keeps
    /// `Q_sigma` exactly for `ArchiveReceive`'s incoming sigma. Authorization and
    /// Signatures must execute where the merged signature leaf is verified.
    /// # Errors
    /// Wrong class/count/shape, missing or repeated owner, or misplaced Q.
    pub fn new(context: ContextPlan, policy: OwnPolicy) -> Result<Self, Error> {
        let variant = context.operation().frame().variant();
        let signature_q = super::signature_q(variant)?;
        let operation = context.operation();
        let specs = context.object_specs();
        if !operation.is_inline()
            || operation.has_incoming_sigma() != (variant == Variant::ArchiveReceive)
            || operation.q_count() != signature_q + 1
            || specs.len() < 12
            || specs
                != Self::context_specs(
                    variant,
                    specs[7].capacity as usize,
                    specs[8].capacity as usize,
                    specs[11].capacity as usize,
                )?
        {
            return Err(Error::Synthesis);
        }
        let signature = ArchiveAuthorizationObjects::signature_schema()?;
        let descriptor = operation
            .q(signature_q)
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
        let results = ArchiveResultPlan::new(&context, specs.len() - 1)?;
        for stage in 0..context.stage_count() {
            let tasks = context.operation_tasks(stage).ok_or(Error::Synthesis)?;
            let partition = context.q_partition(stage).ok_or(Error::Synthesis)?;
            if (tasks.contains(&OperationTask::ArchiveAuthorization)
                || tasks.contains(&OperationTask::ArchiveSignatures))
                && !partition.contains(&signature_q)
            {
                return Err(Error::Synthesis);
            }
        }
        Ok(Self {
            context,
            policy,
            signature,
            signature_q,
            results,
        })
    }

    /// Exact context used by every split A/W continuation.
    pub const fn context(&self) -> &ContextPlan {
        &self.context
    }
    /// Complete result plan used to assign the same proposal at every stage.
    pub const fn results(&self) -> ArchiveResultPlan {
        self.results
    }
    /// Index of the merged signature leaf: Q1 after `ArchiveReceive`'s
    /// incoming-only `Q_sigma`, or `ArchiveStatus`'s only Q.
    pub const fn signature_q(&self) -> usize {
        self.signature_q
    }
    /// The fixed merged signature-Q schema at [`Self::signature_q`]. `Q_sigma`
    /// is the separate sigma program.
    pub fn signature_schema(&self, q: usize) -> Option<&QSignaturePlan> {
        (q == self.signature_q).then_some(&self.signature)
    }

    /// Execute every assigned task exactly once on the same original context.
    /// The recursive owner must still hard-verify Q/W/predecessor obligations,
    /// close every deferred claim, and admit only measured complete stage keys.
    /// # Errors
    /// Missing/extraneous task source, wrong context/schema, altered original
    /// bytes, discretionary no-op or failed hard state/path/authentication rule.
    pub fn constrain_stage(
        &self,
        chip: &mut VerifierChip<Ep>,
        bytes: &mut BytesChip<Fp>,
        region: &mut Region<'_, Fp>,
        stage: u32,
        input: ArchiveStageInputs<'_>,
        witness: ArchiveStageWitness<'_>,
    ) -> Result<Option<ArchiveEffectsCells>, Error> {
        use OperationTask::*;
        let tasks = self
            .context
            .operation_tasks(usize::try_from(stage).map_err(|_| Error::BoundsFailure)?)
            .ok_or(Error::Synthesis)?;
        for (required, present) in [
            (tasks.contains(&ArchiveAuthorization), input.own.is_some()),
            (
                tasks.contains(&ArchiveRetainedPayment),
                input.retained.is_some(),
            ),
            (
                tasks.contains(&ArchiveRetainedProofs),
                input.retained_proofs.is_some(),
            ),
            (
                tasks.contains(&ArchiveEvidence) || tasks.contains(&ArchiveSignatures),
                input.incoming.is_some(),
            ),
            (tasks.contains(&ArchiveProofs), input.proof_source.is_some()),
            (tasks.contains(&ArchiveProofs), witness.proof.is_some()),
            (
                tasks.contains(&ArchiveAuthorization) || tasks.contains(&ArchiveSignatures),
                witness.signatures.is_some(),
            ),
            (tasks.contains(&ArchiveEvidence), witness.evidence.is_some()),
            (
                tasks.contains(&ArchiveCorePending),
                witness.core_pending.is_some(),
            ),
            (
                tasks.contains(&ArchiveLineagePending),
                witness.lineage_pending.is_some(),
            ),
        ] {
            if required != present {
                return Err(Error::Synthesis);
            }
        }
        input
            .results
            .bind_context(region, &self.context, input.context)?;
        let mut effects = None;
        for task in tasks {
            match task {
                ArchiveRetainedProofs => input
                    .retained_proofs
                    .ok_or(Error::Synthesis)?
                    .bind_context(region, &self.context, stage, input.context)?,
                ArchiveRetainedPayment => input.retained.ok_or(Error::Synthesis)?.bind_context(
                    region,
                    &self.context,
                    stage,
                    input.context,
                )?,
                ArchiveAuthorization => input.own.ok_or(Error::Synthesis)?.constrain_current(
                    chip,
                    region,
                    &self.context,
                    stage,
                    input.context,
                    (self.policy, witness.signatures.ok_or(Error::Synthesis)?),
                )?,
                ArchiveSignatures => input
                    .incoming
                    .ok_or(Error::Synthesis)?
                    .constrain_signature(
                        region,
                        &self.context,
                        stage,
                        input.context,
                        input.results,
                        witness.signatures.ok_or(Error::Synthesis)?,
                    )?,
                ArchiveProofs => {
                    let source = input.proof_source.ok_or(Error::Synthesis)?;
                    source.require_context_slot(11)?;
                    source.constrain_proofs(
                        chip,
                        region,
                        &self.context,
                        stage,
                        input.context,
                        input.results,
                        witness.proof.ok_or(Error::Synthesis)?,
                    )?;
                }
                ArchiveEvidence => evidence::constrain_evidence(
                    chip,
                    bytes,
                    region,
                    &self.context,
                    stage,
                    input.context,
                    input.results,
                    self.policy,
                    input.incoming.ok_or(Error::Synthesis)?,
                    witness.evidence.ok_or(Error::Synthesis)?,
                )?,
                ArchiveEffects => {
                    effects = Some(maps::constrain_effects(
                        chip,
                        region,
                        &self.context,
                        stage,
                        input.context,
                        input.results,
                    )?)
                }
                ArchiveCorePending => maps::constrain_core_pending(
                    chip,
                    region,
                    &self.context,
                    stage,
                    input.context,
                    witness.core_pending.ok_or(Error::Synthesis)?,
                )?,
                ArchiveLineagePending => maps::constrain_lineage_pending(
                    chip,
                    region,
                    &self.context,
                    stage,
                    input.context,
                    input.results,
                    witness.lineage_pending.ok_or(Error::Synthesis)?,
                )?,
                _ => return Err(Error::Synthesis),
            }
        }
        Ok(effects)
    }
}
