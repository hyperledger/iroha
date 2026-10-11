//! Ordinary finalized Load receipt, own signatures and recovery-map composition.
//!
//! The receipt terms come from one exact byte tape. Native verifies genesis-rooted
//! BLS finality before requesting the Advance signature bound to this receipt.

use ff::Field;
use iroha_pasta::{Ep, Fp};
use iroha_plonk::frontend::{Error, Region, Value};
use iroha_plonk_gadgets::{GlueChip, UintChip, bytes::tape::BytesChip};
use iroha_plonk_recursion::{obligation::ledger::Variant, verifier::VerifierChip};

use super::{
    SigmaBindingCells, SignatureProofCells,
    context::{ContextObjectCells, ContextObjectSpec},
    load_receipt::LoadReceiptCells,
    own::{CurrentAuthorization, OwnPolicy, authenticate_current},
};
use crate::{
    operation_relation::{
        map_effects::{InsertCells, MapEffectsChip, MapState, MapTransition},
        objects::{
            ObjectKind, SignedObjectCells,
            receipt::{self, ReceiptContext},
        },
    },
    q_signature::SignatureKey,
};

/// Ordinary ledger receipt, own Advance receipt, Enrollment certificate and credential.
#[derive(Clone, Debug)]
pub struct LoadObjects {
    receipt: LoadReceiptCells,
    objects: [SignedObjectCells; 3],
    context: [ContextObjectCells; 4],
}
/// State and authenticated Q outputs consumed by Load's signed-object relation.
#[derive(Clone, Copy)]
pub struct LoadInputs<'a> {
    /// Canonical state and public prefix authenticated by the hard predecessor.
    pub predecessor: MapState<'a>,
    /// Canonical successor state and public prefix retained by A.
    pub successor: MapState<'a>,
    /// Own exact statement and sigma-only proof digest from the Q-bound tape.
    pub sigma: &'a SigmaBindingCells,
    /// Own Advance receipt slot, or current credential/Enrollment certificate slots.
    pub signatures: &'a [SignatureProofCells],
}
impl LoadObjects {
    /// Fixed ordered context object schema, including raw signatures.
    ///
    /// # Errors
    /// An impossible size conversion in the fixed schema.
    pub fn context_specs() -> Result<[ContextObjectSpec; 4], Error> {
        let mut out = vec![ContextObjectSpec {
            tag: 1,
            capacity: u32::try_from(LoadReceiptCells::BYTES).map_err(|_| Error::BoundsFailure)?,
        }];
        for (tag, kind) in [
            (2, ObjectKind::Receipt),
            (3, ObjectKind::Certificate),
            (4, ObjectKind::Credential),
        ] {
            out.push(ContextObjectSpec {
                tag,
                capacity: u32::try_from(kind.body_len() + 64).map_err(|_| Error::BoundsFailure)?,
            });
        }
        out.try_into().map_err(|_| Error::Synthesis)
    }
    /// Parse the ordinary receipt and all three signed objects from their exact tapes.
    /// # Errors
    /// Wrong fixed lengths, malformed canonical fields or circuit layout failure.
    pub fn decode(
        chip: &mut VerifierChip<Ep>,
        bytes: &mut BytesChip<Fp>,
        region: &mut Region<'_, Fp>,
        source: [&[Value<u8>]; 4],
    ) -> Result<Self, Error> {
        let specs = Self::context_specs()?;
        let run = bytes.run(
            region,
            source[0],
            &LoadReceiptCells::primary_segments(),
            &LoadReceiptCells::secondary_segments(),
        )?;
        let (mut uint, hash) = chip.uint_and_hasher()?;
        let receipt = LoadReceiptCells::from_run(&mut uint, hash, region, &run)?;
        let mut context = vec![ContextObjectCells::from_exact_run(
            chip,
            region,
            specs[0],
            receipt.digest(),
            &run,
        )?];
        let mut objects = Vec::new();
        for ((kind, source), spec) in [
            ObjectKind::Receipt,
            ObjectKind::Certificate,
            ObjectKind::Credential,
        ]
        .into_iter()
        .zip(&source[1..])
        .zip(&specs[1..])
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
                *spec,
                object.digest(),
                &run,
            )?);
            objects.push(object);
        }
        Ok(Self {
            receipt,
            objects: objects.try_into().map_err(|_| Error::Synthesis)?,
            context: context.try_into().map_err(|_| Error::Synthesis)?,
        })
    }
    /// Same-tape object commitments rebound by every split stage.
    pub const fn context(&self) -> &[ContextObjectCells; 4] {
        &self.context
    }
    /// Exact ordinary receipt parsed from the immutable stage context.
    pub const fn receipt(&self) -> &LoadReceiptCells {
        &self.receipt
    }

    /// Bind every monetary projection to the exact ordinary receipt.
    /// The same stage authenticates the native-authorized Advance signature.
    /// # Errors
    /// Wrong operation or layout; any projected identity/amount mismatch is unsatisfied.
    pub fn bind_finalized_terms(
        &self,
        region: &mut Region<'_, Fp>,
        input: LoadInputs<'_>,
    ) -> Result<(), Error> {
        let statement = input.sigma.hard_statement()?;
        if statement.variant() != Variant::Load {
            return Err(Error::Synthesis);
        }
        let fields = statement.fields();
        for (actual, expected) in self
            .receipt
            .scheme()
            .iter()
            .zip(&fields[3..5])
            .chain(self.receipt.asset().iter().zip(&fields[5..7]))
            .chain(
                self.receipt
                    .wallet()
                    .iter()
                    .zip(&input.successor.lineage.fields()[6..8]),
            )
        {
            GlueChip::assert_equal(region, actual, expected)?;
        }
        for (actual, expected) in [
            (self.receipt.digest(), &fields[17]),
            (self.receipt.ordinal().word(), &fields[18]),
            (self.receipt.amount().word(), &fields[19]),
            (self.receipt.online_charge().word(), &fields[20]),
        ] {
            GlueChip::assert_equal(region, actual, expected)?;
        }
        Ok(())
    }
    /// Authenticate the own Advance receipt under the hard predecessor payment key.
    /// # Errors
    /// Wrong slot or operation; signature and exact sigma/statement bindings are hard.
    pub fn authenticate(
        &self,
        chip: &mut VerifierChip<Ep>,
        region: &mut Region<'_, Fp>,
        policy: OwnPolicy,
        input: LoadInputs<'_>,
    ) -> Result<(), Error> {
        let statement = input.sigma.hard_statement()?;
        if statement.variant() != Variant::Load
            || input.signatures.len() != 1
            || input.signatures[0].key_policy() != SignatureKey::Variable
        {
            return Err(Error::Synthesis);
        }
        let mut uint = chip.uint();
        let provider = policy
            .provider
            .map(|v| uint.constant::<128>(region, v).map(|v| v.word().clone()))
            .into_iter()
            .collect::<Result<Vec<_>, _>>()?
            .try_into()
            .map_err(|_| Error::Synthesis)?;
        let wallet = [
            input.successor.lineage.fields()[6].clone(),
            input.successor.lineage.fields()[7].clone(),
        ];
        let payment_key =
            core::array::from_fn(|i| input.predecessor.lineage.fields()[9 + i].clone());
        let valid = self.objects[0].bind_signature(region, &input.signatures[0], &payment_key)?;
        GlueChip::assert_constant(region, valid.word(), Fp::ONE)?;
        let zero = uint.glue().constant(region, Fp::ZERO)?;
        let lanes = chip.operation_lanes()?;
        let valid = receipt::bind(
            &mut UintChip::new(lanes.glue, lanes.range),
            lanes.hash,
            region,
            &self.objects[0],
            &ReceiptContext {
                wallet: &wallet,
                provider: &provider,
                statement,
                proof_digest: input.sigma.step_digest()?,
                payment_digest: &zero,
            },
        )?;
        GlueChip::assert_constant(region, valid.word(), Fp::ONE)
    }
    /// Reverify the current credential and its Enrollment certificate for this step.
    /// # Errors
    /// Wrong signature count/root/scope, wrong own state, or layout failure.
    pub fn authenticate_current(
        &self,
        chip: &mut VerifierChip<Ep>,
        region: &mut Region<'_, Fp>,
        policy: OwnPolicy,
        input: LoadInputs<'_>,
    ) -> Result<(), Error> {
        if input.signatures.len() != 2 || input.sigma.hard_statement()?.variant() != Variant::Load {
            return Err(Error::Synthesis);
        }
        authenticate_current(
            chip,
            region,
            policy,
            CurrentAuthorization {
                credential: &self.objects[2],
                certificate: &self.objects[1],
                credential_proof: &input.signatures[0],
                certificate_proof: &input.signatures[1],
                current: input.predecessor,
                statement: input.sigma.hard_statement()?,
            },
        )
    }
    /// Prove the exact recovery insertion, arithmetic and unchanged-field rules.
    ///
    /// This hard map obligation can occupy a separate fixed split stage from
    /// object authentication, provided its state/statement is rebound by context.
    ///
    /// # Errors
    /// Wrong statement/variant or layout error; incorrect paths are unsatisfiable.
    pub fn recovery(
        chip: &mut VerifierChip<Ep>,
        region: &mut Region<'_, Fp>,
        input: LoadInputs<'_>,
        insertion: &InsertCells,
    ) -> Result<(), Error> {
        let statement = input.sigma.hard_statement()?;
        if statement.variant() != Variant::Load {
            return Err(Error::Synthesis);
        }
        let lanes = chip.operation_lanes()?;
        MapEffectsChip::new(lanes.glue, lanes.range, lanes.hash).recovery(
            region,
            &MapTransition {
                statement,
                predecessor: input.predecessor,
                successor: input.successor,
            },
            insertion,
        )
    }
}

/// Fixed Load task ownership, coupled to the same Q/key/context schema.
#[derive(Clone, Debug)]
pub struct LoadStagePlan {
    context: super::context::ContextPlan,
}
impl LoadStagePlan {
    /// Require recovery, receipt-term binding, own receipt authorization and current-credential
    /// authorization exactly once, with hard signature Q slots1 and2 respectively.
    /// # Errors
    /// Wrong variant/task set, signature-Q count or stage assignment.
    pub fn new(context: super::context::ContextPlan) -> Result<Self, Error> {
        use super::schedule::OperationTask;
        if context.operation().frame().variant() != Variant::Load
            || context.operation().q_count() != 3
            || context.object_specs() != LoadObjects::context_specs()?
        {
            return Err(Error::Synthesis);
        }
        let groups = (0..context.stage_count())
            .map(|i| context.operation_tasks(i).unwrap_or_default().to_vec())
            .collect::<Vec<_>>();
        OperationTask::validate(Variant::Load, &groups)?;
        let required = vec![
            vec![OperationTask::LoadRecovery],
            vec![],
            vec![OperationTask::LoadReceipt],
            vec![OperationTask::LoadCurrentAuthorization],
        ];
        let partitions = [vec![], vec![0], vec![1], vec![2]];
        if groups != required
            || context.predecessor_stage() != Some(0)
            || partitions
                .iter()
                .enumerate()
                .any(|(stage, expected)| context.q_partition(stage) != Some(expected.as_slice()))
        {
            return Err(Error::Synthesis);
        }

        for (stage, tasks) in groups.iter().enumerate() {
            for (task, q) in [
                (OperationTask::LoadReceipt, 1),
                (OperationTask::LoadCurrentAuthorization, 2),
            ] {
                if tasks.contains(&task)
                    && !context
                        .q_partition(stage)
                        .ok_or(Error::Synthesis)?
                        .contains(&q)
                {
                    return Err(Error::Synthesis);
                }
            }
        }
        Ok(Self { context })
    }
    /// Context committed by every stage and its pinned W wrapper.
    pub const fn context(&self) -> &super::context::ContextPlan {
        &self.context
    }
    /// Execute precisely the fixed stage's operation tasks on context-bound cells.
    /// # Errors
    /// Wrong stage, missing/extraneous recovery path, or any failed constraint.
    #[allow(clippy::too_many_arguments)] // One fixed stage and its same-cell operation inputs.
    pub fn constrain_stage(
        &self,
        chip: &mut VerifierChip<Ep>,
        region: &mut Region<'_, Fp>,
        stage: usize,
        objects: &LoadObjects,
        policy: OwnPolicy,
        input: LoadInputs<'_>,
        insertion: Option<&InsertCells>,
        signature: Option<super::SignatureQContext<'_>>,
    ) -> Result<(), Error> {
        use super::schedule::OperationTask;
        let tasks = self
            .context
            .operation_tasks(stage)
            .ok_or(Error::Synthesis)?;
        if tasks.contains(&OperationTask::LoadRecovery) != insertion.is_some() {
            return Err(Error::Synthesis);
        }
        let owning_q = if tasks.contains(&OperationTask::LoadReceipt) {
            Some(1)
        } else if tasks.contains(&OperationTask::LoadCurrentAuthorization) {
            Some(2)
        } else {
            None
        };
        if owning_q.is_some() != signature.is_some() {
            return Err(Error::Synthesis);
        }
        let input = if let Some(q) = signature {
            q.bundle.bind_context(
                region,
                self.context.operation(),
                owning_q.ok_or(Error::Synthesis)?,
                q.instances,
            )?;
            LoadInputs {
                signatures: q.bundle.slots(),
                ..input
            }
        } else {
            input
        };
        for task in tasks {
            match task {
                OperationTask::LoadRecovery => {
                    LoadObjects::recovery(chip, region, input, insertion.ok_or(Error::Synthesis)?)?
                }
                OperationTask::LoadReceipt => {
                    objects.bind_finalized_terms(region, input)?;
                    objects.authenticate(chip, region, policy, input)?;
                }
                OperationTask::LoadCurrentAuthorization => {
                    objects.authenticate_current(chip, region, policy, input)?
                }
                _ => return Err(Error::Synthesis),
            }
        }
        Ok(())
    }
}
