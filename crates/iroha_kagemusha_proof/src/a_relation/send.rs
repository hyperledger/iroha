//! Send's current-credential, exact Request, held-fee and depth32 map composition.
//!
//! The hard predecessor authenticates held object digests. Every step also
//! re-verifies the current credential, its certificate and the own receipt.
//! The receiver owns the separate Request signature obligation.
//! The complete A schedule must also hard-verify the exact control-selected
//! sigma and retain all predecessor/Q opening obligations.

use ff::Field;
use iroha_pasta::{Ep, Fp};
use iroha_plonk::frontend::{Error, Region, Value};
use iroha_plonk_gadgets::{GlueChip, UintChip, bytes::tape::BytesChip};
use iroha_plonk_recursion::{obligation::ledger::Variant, verifier::VerifierChip};

use super::{
    SigmaBindingCells,
    context::{ContextObjectCells, ContextObjectSpec},
    own::{ConsumingProofCells, CurrentAuthorization, OwnPolicy, authenticate_current},
};
use crate::operation_relation::{
    map_effects::{InsertCells, MapEffectsChip, MapState, MapTransition},
    objects::{
        ObjectKind, SignedObjectCells, credential::CredentialCells, fee, policy::PolicyCells,
        request::RequestCells,
    },
};

/// Exact payer credential, signed Request and fixed held-fee slot, in that order.
#[derive(Clone, Debug)]
pub struct SendObjects {
    objects: [SignedObjectCells; 3],
    context: [ContextObjectCells; 3],
}

/// The exact state and sigma cells retained by the complete A schedule.
#[derive(Clone, Copy, Debug)]
pub struct SendInputs<'a> {
    /// State and public prefix authenticated by the hard predecessor proof.
    pub predecessor: MapState<'a>,
    /// Successor state and public prefix committed by the operation.
    pub successor: MapState<'a>,
    /// Own statement and exact sigma bytes bound to the hard `Q_sigma` output.
    pub sigma: &'a SigmaBindingCells,
}

/// Same-cell ownership/Request/fee facts, retaining their exact state transition.
///
/// A fixed complete stage schedule must execute both `pending` and
/// `fee_and_unchanged`, possibly in different proofs that rebind the same context.
/// Constructing this value alone does not establish the operation's map effects.
#[derive(Clone, Debug)]
pub struct SendCells<'a> {
    input: SendInputs<'a>,
    fee_schedule: iroha_plonk_gadgets::Word<Fp>,
}
impl SendCells<'_> {
    fn transition(&self) -> Result<MapTransition<'_>, Error> {
        Ok(MapTransition {
            statement: self.input.sigma.hard_statement()?,
            predecessor: self.input.predecessor,
            successor: self.input.successor,
        })
    }
    /// Check the exact pending descriptor insertion into the adjusted lineage map.
    ///
    /// # Errors
    /// Layout failure or invalid authenticated path/descriptor/root.
    pub fn pending(
        &self,
        chip: &mut VerifierChip<Ep>,
        region: &mut Region<'_, Fp>,
        path: &InsertCells,
    ) -> Result<(), Error> {
        let lanes = chip.operation_lanes()?;
        MapEffectsChip::new(lanes.glue, lanes.range, lanes.hash).send_pending(
            region,
            &self.transition()?,
            path,
        )
    }
    /// Check the fee insert/no-op and every untouched map and adjusted balance.
    ///
    /// The schedule digest comes only from this same authenticated Request.
    /// # Errors
    /// Layout failure or invalid fee path/root/unchanged fields.
    pub fn fee_and_unchanged(
        &self,
        chip: &mut VerifierChip<Ep>,
        region: &mut Region<'_, Fp>,
        path: &InsertCells,
    ) -> Result<(), Error> {
        let lanes = chip.operation_lanes()?;
        MapEffectsChip::new(lanes.glue, lanes.range, lanes.hash).send_fee_and_unchanged(
            region,
            &self.transition()?,
            path,
            &self.fee_schedule,
        )
    }
}

impl SendObjects {
    /// Fixed context categories, including every original signature byte.
    ///
    /// # Errors
    /// An impossible fixed-schema capacity conversion.
    pub fn context_specs() -> Result<[ContextObjectSpec; 3], Error> {
        [
            ObjectKind::Credential,
            ObjectKind::Request,
            ObjectKind::FeeSchedule,
        ]
        .into_iter()
        .enumerate()
        .map(|(index, kind)| -> Result<_, Error> {
            Ok(ContextObjectSpec {
                tag: u32::try_from(index + 1).map_err(|_| Error::BoundsFailure)?,
                capacity: u32::try_from(kind.body_len() + 64).map_err(|_| Error::BoundsFailure)?,
            })
        })
        .collect::<Result<Vec<_>, _>>()?
        .try_into()
        .map_err(|_| Error::Synthesis)
    }

    /// Decode one tape per object and commit those identical bytes to context.
    ///
    /// The fee slot is total: a head with no held schedule permits a malformed
    /// fixed dummy, whose original digest still enters context. Credential and
    /// Request structure are hard own-operation requirements.
    ///
    /// # Errors
    /// Wrong fixed shape or layout failure; malformed own objects are unsatisfiable.
    pub fn decode(
        chip: &mut VerifierChip<Ep>,
        bytes: &mut BytesChip<Fp>,
        region: &mut Region<'_, Fp>,
        sources: [&[Value<u8>]; 3],
    ) -> Result<Self, Error> {
        let mut objects = Vec::new();
        let mut context = Vec::new();
        for ((kind, source), spec) in [
            ObjectKind::Credential,
            ObjectKind::Request,
            ObjectKind::FeeSchedule,
        ]
        .into_iter()
        .zip(sources)
        .zip(Self::context_specs()?)
        {
            let run = bytes.run(
                region,
                source,
                &kind.primary_segments(),
                &kind.secondary_segments(),
            )?;
            let lanes = chip.operation_lanes()?;
            let mut uint = UintChip::new(lanes.glue, lanes.range);
            let object = if kind == ObjectKind::FeeSchedule {
                SignedObjectCells::decode_soft(&mut uint, lanes.hash, region, kind, &run)?.0
            } else {
                SignedObjectCells::from_run(&mut uint, lanes.hash, region, kind, &run)?
            };
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

    /// Original same-tape commitments for every stage of the fixed schedule.
    pub const fn context(&self) -> &[ContextObjectCells; 3] {
        &self.context
    }

    /// Bind current ownership, exact credit/fees and both depth32 insertions.
    ///
    /// The fee-map value uses this same Request's historical schedule digest;
    /// callers cannot supply an independently chosen fee schedule. The exact
    /// control-selected sigma remains a separate hard Q obligation of A.
    ///
    /// # Errors
    /// Wrong variant or layout failure; wrong ownership, fees or paths reject.
    pub fn constrain(
        &self,
        chip: &mut VerifierChip<Ep>,
        region: &mut Region<'_, Fp>,
        input: SendInputs<'_>,
        pending: &InsertCells,
        fee_path: &InsertCells,
    ) -> Result<(), Error> {
        let cells = self.authenticate(chip, region, input)?;
        cells.pending(chip, region, pending)?;
        cells.fee_and_unchanged(chip, region, fee_path)
    }

    /// Check current ownership and exact Request/held-fee terms on the same tapes.
    ///
    /// The returned cells retain the exact transition for separate fixed-stage
    /// map checks; they cannot be assembled from unchecked host verdicts.
    /// # Errors
    /// Wrong operation class or layout failure; false ownership/fees reject.
    pub fn authenticate<'a>(
        &self,
        chip: &mut VerifierChip<Ep>,
        region: &mut Region<'_, Fp>,
        input: SendInputs<'a>,
    ) -> Result<SendCells<'a>, Error> {
        let statement = input.sigma.hard_statement()?;
        if statement.variant() != Variant::Send {
            return Err(Error::Synthesis);
        }
        let lanes = chip.operation_lanes()?;
        let mut uint = UintChip::new(lanes.glue, lanes.range);
        let payer = CredentialCells::check(&mut uint, region, &self.objects[0])?;
        let valid = payer.bind_current(
            &mut uint,
            region,
            input.predecessor.state,
            input.predecessor.lineage,
        )?;
        GlueChip::assert_constant(region, valid.word(), Fp::ONE)?;
        let request = RequestCells::check(&mut uint, lanes.hash, region, &self.objects[1])?;
        let valid = request.bind_send(&mut uint, region, statement, &payer)?;
        GlueChip::assert_constant(region, valid.word(), Fp::ONE)?;
        let schedule = PolicyCells::check(&mut uint, region, &self.objects[2])?;
        let valid = fee::bind_send(
            &mut uint,
            region,
            &request,
            input.predecessor.state,
            &schedule,
        )?;
        GlueChip::assert_constant(region, valid.word(), Fp::ONE)?;
        Ok(SendCells {
            input,
            fee_schedule: request.object().word(10)?.clone(),
        })
    }
}

/// Complete fixed Send task assignment; operation ownership is never a witness bit.
#[derive(Clone, Debug)]
pub struct SendStagePlan {
    context: super::context::ContextPlan,
}
/// Exact paths and own-authorization inputs owned by this fixed stage.
#[derive(Clone, Copy, Debug, Default)]
pub struct SendStageWitness<'a> {
    /// Present exactly in the pending insertion stage.
    pub pending: Option<&'a InsertCells>,
    /// Present exactly in the fee insertion/unchanged-fields stage.
    pub fee: Option<&'a InsertCells>,
    /// Present exactly in the mandatory own signature authorization stage.
    pub authorization: Option<SendAuthorization<'a>>,
    /// Exact consuming-proof binding, present in the hard predecessor stage.
    pub proof: Option<SendProofBinding<'a>>,
}
impl SendStagePlan {
    /// Require every Send task exactly once in the committed stage schema.
    /// Q0 is the own sigma and Q1 proves receipt/current credential/certificate.
    /// # Errors
    /// Wrong operation, task coverage or Q count.
    pub fn new(context: super::context::ContextPlan) -> Result<Self, Error> {
        use super::schedule::OperationTask;
        if context.operation().frame().variant() != Variant::Send
            || context.operation().q_count() != 2
            || context.object_specs() != Self::context_specs()?
        {
            return Err(Error::Synthesis);
        }
        let groups = (0..context.stage_count())
            .map(|i| context.operation_tasks(i).unwrap_or_default().to_vec())
            .collect::<Vec<_>>();
        OperationTask::validate(Variant::Send, &groups)?;
        for (stage, tasks) in groups.iter().enumerate() {
            if tasks.contains(&OperationTask::SendProof)
                && context.predecessor_stage() != Some(stage)
            {
                return Err(Error::Synthesis);
            }
            if tasks.contains(&OperationTask::SendAuthorization)
                && !context
                    .q_partition(stage)
                    .ok_or(Error::Synthesis)?
                    .contains(&1)
            {
                return Err(Error::Synthesis);
            }
        }
        Ok(Self { context })
    }
    /// Complete fixed object schema, including mandatory own certificate and receipt.
    /// # Errors
    /// An impossible fixed capacity conversion.
    pub fn context_specs() -> Result<Vec<ContextObjectSpec>, Error> {
        let mut specs = SendObjects::context_specs()?.to_vec();
        specs.extend(SendAuthorizationObjects::context_specs()?);
        Ok(specs)
    }
    /// Context whose exact task assignment is pinned in every stage key.
    pub const fn context(&self) -> &super::context::ContextPlan {
        &self.context
    }
    /// Execute the fixed stage's named constraints against the same context inputs.
    ///
    /// Object validity may be proved in another stage; its original byte tapes,
    /// both state openings and the exact statement are rebound by `D_ctx` in all
    /// stages. No individual stage establishes a complete accepted operation.
    /// # Errors
    /// Invalid stage/path presence or failed ownership/map constraints.
    #[allow(clippy::too_many_arguments)] // Fixed plan and exact context-bound operation inputs.
    pub fn constrain_stage(
        &self,
        chip: &mut VerifierChip<Ep>,
        region: &mut Region<'_, Fp>,
        stage: usize,
        objects: &SendObjects,
        input: SendInputs<'_>,
        paths: SendStageWitness<'_>,
    ) -> Result<(), Error> {
        use super::schedule::OperationTask;
        let tasks = self
            .context
            .operation_tasks(stage)
            .ok_or(Error::Synthesis)?;
        if tasks.contains(&OperationTask::SendPending) != paths.pending.is_some()
            || tasks.contains(&OperationTask::SendFeeAndCarry) != paths.fee.is_some()
            || tasks.contains(&OperationTask::SendAuthorization) != paths.authorization.is_some()
            || tasks.contains(&OperationTask::SendProof) != paths.proof.is_some()
        {
            return Err(Error::Synthesis);
        }
        let transition = MapTransition {
            statement: input.sigma.hard_statement()?,
            predecessor: input.predecessor,
            successor: input.successor,
        };
        if transition.statement.variant() != Variant::Send {
            return Err(Error::Synthesis);
        }
        for task in tasks {
            match task {
                OperationTask::SendObjects => {
                    objects.authenticate(chip, region, input)?;
                }
                OperationTask::SendPending => {
                    let lanes = chip.operation_lanes()?;
                    MapEffectsChip::new(lanes.glue, lanes.range, lanes.hash).send_pending(
                        region,
                        &transition,
                        paths.pending.ok_or(Error::Synthesis)?,
                    )?;
                }
                OperationTask::SendFeeAndCarry => {
                    let lanes = chip.operation_lanes()?;
                    MapEffectsChip::new(lanes.glue, lanes.range, lanes.hash)
                        .send_fee_and_unchanged(
                            region,
                            &transition,
                            paths.fee.ok_or(Error::Synthesis)?,
                            objects.objects[1].word(10)?,
                        )?;
                }
                OperationTask::SendAuthorization => {
                    let auth = paths.authorization.ok_or(Error::Synthesis)?;
                    auth.signature.bundle.bind_context(
                        region,
                        self.context.operation(),
                        1,
                        auth.signature.instances,
                    )?;
                    auth.objects.constrain(chip, region, objects, input, auth)?;
                }
                OperationTask::SendProof => {
                    let proof = paths.proof.ok_or(Error::Synthesis)?;
                    proof
                        .proof
                        .bind(region, input.predecessor.lineage, input.sigma)?;
                    GlueChip::assert_equal(
                        region,
                        proof.objects.objects[1].word(9)?,
                        proof.proof.digest(),
                    )?;
                }
                _ => return Err(Error::Synthesis),
            }
        }
        Ok(())
    }
}

/// The additional same-tape Enrollment certificate and own Send receipt.
#[derive(Clone, Debug)]
pub struct SendAuthorizationObjects {
    objects: [SignedObjectCells; 2],
    context: [ContextObjectCells; 2],
}
/// Inputs bound by the owning hard signature Q and exact consuming proof tape.
#[derive(Clone, Copy, Debug)]
pub struct SendAuthorization<'a> {
    /// The same original certificate and receipt committed by context.
    pub objects: &'a SendAuthorizationObjects,
    /// Fixed artifact's provider/root policy; the own state carries scheme identity.
    pub policy: OwnPolicy,
    /// Opaque Q1 exports, ordered receipt, current credential, fixed-root certificate.
    pub signature: super::SignatureQContext<'a>,
}
/// Original receipt and exact proof tape checked beside the hard predecessor.
/// The fixed context commits these same receipt bytes in the signature stage.
#[derive(Clone, Copy, Debug)]
pub struct SendProofBinding<'a> {
    /// The same certificate/receipt tapes retained by every operation stage.
    pub objects: &'a SendAuthorizationObjects,
    /// Exact Ω predecessor plus sigma digest with all transport claims linked.
    pub proof: &'a ConsumingProofCells,
}
impl SendAuthorizationObjects {
    /// Additional context slots after the three Send object slots.
    /// # Errors
    /// Impossible fixed capacity conversion.
    pub fn context_specs() -> Result<[ContextObjectSpec; 2], Error> {
        [ObjectKind::Certificate, ObjectKind::Receipt]
            .into_iter()
            .enumerate()
            .map(|(i, kind)| {
                Ok(ContextObjectSpec {
                    tag: u32::try_from(i + 4).map_err(|_| Error::BoundsFailure)?,
                    capacity: u32::try_from(kind.body_len() + 64)
                        .map_err(|_| Error::BoundsFailure)?,
                })
            })
            .collect::<Result<Vec<_>, Error>>()?
            .try_into()
            .map_err(|_| Error::Synthesis)
    }
    /// Decode both hard own objects and commit their identical original tapes.
    /// # Errors
    /// Wrong schema, malformed own object, or layout failure.
    pub fn decode(
        chip: &mut VerifierChip<Ep>,
        bytes: &mut BytesChip<Fp>,
        region: &mut Region<'_, Fp>,
        sources: [&[Value<u8>]; 2],
    ) -> Result<Self, Error> {
        let mut objects = Vec::new();
        let mut context = Vec::new();
        for ((kind, source), spec) in [ObjectKind::Certificate, ObjectKind::Receipt]
            .into_iter()
            .zip(sources)
            .zip(Self::context_specs()?)
        {
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
    /// Exact additional commitments appended to `SendObjects::context`.
    pub const fn context(&self) -> &[ContextObjectCells; 2] {
        &self.context
    }
    fn constrain(
        &self,
        chip: &mut VerifierChip<Ep>,
        region: &mut Region<'_, Fp>,
        objects: &SendObjects,
        input: SendInputs<'_>,
        auth: SendAuthorization<'_>,
    ) -> Result<(), Error> {
        use crate::operation_relation::objects::receipt::{self, ReceiptContext};
        if auth.signature.bundle.slots().len() != 3 {
            return Err(Error::Synthesis);
        }
        let statement = input.sigma.hard_statement()?;
        authenticate_current(
            chip,
            region,
            auth.policy,
            CurrentAuthorization {
                credential: &objects.objects[0],
                certificate: &self.objects[0],
                credential_proof: &auth.signature.bundle.slots()[1],
                certificate_proof: &auth.signature.bundle.slots()[2],
                current: input.predecessor,
                statement,
            },
        )?;
        let provider = auth.policy.provider(chip, region)?;
        let key = core::array::from_fn(|i| input.predecessor.lineage.fields()[9 + i].clone());
        let signature =
            self.objects[1].bind_signature(region, &auth.signature.bundle.slots()[0], &key)?;
        GlueChip::assert_constant(region, signature.word(), Fp::ONE)?;
        let zero = chip.uint().glue().constant(region, Fp::ZERO)?;
        let wallet = core::array::from_fn(|i| input.predecessor.lineage.fields()[6 + i].clone());
        let lanes = chip.operation_lanes()?;
        let valid = receipt::bind(
            &mut UintChip::new(lanes.glue, lanes.range),
            lanes.hash,
            region,
            &self.objects[1],
            &ReceiptContext {
                wallet: &wallet,
                provider: &provider,
                statement,
                // SendProof independently binds this field to the verified
                // predecessor and own sigma. D_ctx retains the entire receipt
                // tape across the two mandatory fixed tasks.
                proof_digest: self.objects[1].word(9)?,
                payment_digest: &zero,
            },
        )?;
        GlueChip::assert_constant(region, valid.word(), Fp::ONE)
    }
}
