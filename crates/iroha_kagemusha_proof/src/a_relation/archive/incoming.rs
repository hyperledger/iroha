//! Original held receiver identity and the soft incoming receipt signature.

use ff::Field;
use iroha_pasta::{Ep, Fp};
use iroha_plonk::frontend::{Error, Region, Value};
use iroha_plonk_gadgets::{Bit, GlueChip, UintChip, bytes::tape::BytesChip, p256::VerifyMode};
use iroha_plonk_recursion::verifier::VerifierChip;

use super::{
    require_task,
    results::{ArchiveResultClaims, ArchiveResultTag},
};
use crate::{
    a_relation::{
        SignatureQCells,
        context::{ContextInputs, ContextObjectCells, ContextObjectSpec, ContextPlan},
        schedule::OperationTask,
    },
    operation_relation::objects::{
        ObjectKind, SignedObjectCells, credential::CredentialCells, request::RequestCells,
    },
    q_signature::{QSignaturePlan, SignatureKey},
};

const SLOTS: [usize; 3] = [3, 6, 12];
const KINDS: [ObjectKind; 3] = [
    ObjectKind::Request,
    ObjectKind::Credential,
    ObjectKind::Receipt,
];

/// Exact held Request and quoted credential, plus the original incoming receipt.
/// The first two are the same hard retained sources, while the receipt remains
/// total even when its body or signature is malformed.
#[derive(Clone, Debug)]
pub struct ArchiveIncomingObjects {
    request: RequestCells,
    receiver: CredentialCells,
    receipt: SignedObjectCells,
    context: [ContextObjectCells; 3],
}

impl ArchiveIncomingObjects {
    /// Exact tags4/7/13 and fixed signed-transcript sizes.
    /// # Errors
    /// Impossible fixed-size conversion.
    pub fn context_specs() -> Result<[ContextObjectSpec; 3], Error> {
        KINDS
            .into_iter()
            .zip(SLOTS)
            .map(|(kind, slot)| {
                Ok(ContextObjectSpec {
                    tag: u32::try_from(slot + 1).map_err(|_| Error::BoundsFailure)?,
                    capacity: u32::try_from(kind.body_len() + 64)
                        .map_err(|_| Error::BoundsFailure)?,
                })
            })
            .collect::<Result<Vec<_>, Error>>()?
            .try_into()
            .map_err(|_| Error::Synthesis)
    }

    /// Decode Request, quoted receiver credential and evidence receipt, in order.
    /// The exact quoted credential address binds before any soft receipt result.
    /// # Errors
    /// Wrong sizes, malformed held sources, changed quoted credential or layout.
    pub fn decode(
        chip: &mut VerifierChip<Ep>,
        bytes: &mut BytesChip<Fp>,
        region: &mut Region<'_, Fp>,
        sources: [&[Value<u8>]; 3],
    ) -> Result<Self, Error> {
        let mut objects = Vec::new();
        let mut context = Vec::new();
        for (i, ((kind, source), spec)) in KINDS
            .into_iter()
            .zip(sources)
            .zip(Self::context_specs()?)
            .enumerate()
        {
            let run = bytes.run(
                region,
                source,
                &kind.primary_segments(),
                &kind.secondary_segments(),
            )?;
            let lanes = chip.operation_lanes()?;
            let mut uint = UintChip::new(lanes.glue, lanes.range);
            let object = if i == 2 {
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
        let lanes = chip.operation_lanes()?;
        let mut uint = UintChip::new(lanes.glue, lanes.range);
        let request = RequestCells::check(&mut uint, lanes.hash, region, &objects[0])?;
        let receiver = CredentialCells::check(&mut uint, region, &objects[1])?;
        GlueChip::assert_equal(
            region,
            request.object().word(8)?,
            receiver.object().digest(),
        )?;
        for valid in [request.valid(), receiver.valid()] {
            GlueChip::assert_constant(region, valid.word(), Fp::ONE)?;
        }
        Ok(Self {
            request,
            receiver,
            receipt: objects.remove(2),
            context: context.try_into().map_err(|_| Error::Synthesis)?,
        })
    }

    /// Exact retained Request, including its recorded blacklist and receiver quote.
    pub const fn request(&self) -> &RequestCells {
        &self.request
    }
    /// Original quoted key; this does not require current credential equality.
    pub const fn receiver(&self) -> &CredentialCells {
        &self.receiver
    }
    /// Original soft receipt view; its structural verdict belongs to Evidence.
    pub const fn receipt(&self) -> &SignedObjectCells {
        &self.receipt
    }
    /// Three commitments placed at fixed slots3,6,12 respectively.
    pub const fn context(&self) -> &[ContextObjectCells; 3] {
        &self.context
    }

    pub(super) fn bind_context(
        &self,
        region: &mut Region<'_, Fp>,
        plan: &ContextPlan,
        input: &ContextInputs<'_>,
    ) -> Result<(), Error> {
        self.bind_original_context(region, plan, input.own_statement, input.objects)
    }

    // Original-only source binding shared with pre-Q witness evaluation.
    pub(crate) fn bind_original_context(
        &self,
        region: &mut Region<'_, Fp>,
        plan: &ContextPlan,
        statement: &crate::operation_relation::statement::StatementCells,
        objects: &[ContextObjectCells],
    ) -> Result<(), Error> {
        super::require_variant(plan.operation().frame().variant())?;
        if statement.variant() != plan.operation().frame().variant()
            || objects.len() != plan.object_specs().len()
        {
            return Err(Error::Synthesis);
        }
        for ((actual, index), spec) in self.context.iter().zip(SLOTS).zip(Self::context_specs()?) {
            if plan.object_specs().get(index) != Some(&spec) {
                return Err(Error::Synthesis);
            }
            let expected = objects.get(index).ok_or(Error::Synthesis)?;
            for (a, b) in actual
                .commitment_words()
                .iter()
                .zip(expected.commitment_words())
            {
                GlueChip::assert_equal(region, a, &b)?;
            }
        }
        Ok(())
    }

    /// Bind the sole incoming soft signature to Q2 and the retained receiver key.
    /// Q2 must be hard-verified by this exact stage; its deferred opening remains
    /// mandatory in the recursive ledger even when the receipt verdict is false.
    /// # Errors
    /// Wrong owner/Q/schema/key, substituted source, missing result or layout.
    pub fn constrain_signature(
        &self,
        region: &mut Region<'_, Fp>,
        plan: &ContextPlan,
        stage: u32,
        input: &ContextInputs<'_>,
        claims: &ArchiveResultClaims,
        bundle: &SignatureQCells,
    ) -> Result<(), Error> {
        require_task(plan, stage, OperationTask::ArchiveSignatures)?;
        if !plan
            .q_partition(usize::try_from(stage).map_err(|_| Error::BoundsFailure)?)
            .is_some_and(|q| q.contains(&2))
        {
            return Err(Error::Synthesis);
        }
        let valid = self.derive_signature(region, plan, input, bundle)?;
        claims.bind_derived(
            region,
            plan,
            stage,
            input,
            ArchiveResultTag::Signatures,
            &valid,
        )
    }

    // Native preparation shares the exact receipt, held key and Q2 bindings.
    // The owning stage separately hard-verifies Q2 and binds the proposed bit.
    pub(crate) fn derive_signature(
        &self,
        region: &mut Region<'_, Fp>,
        plan: &ContextPlan,
        input: &ContextInputs<'_>,
        bundle: &SignatureQCells,
    ) -> Result<Bit<Fp>, Error> {
        self.bind_context(region, plan, input)?;
        bundle.bind_context(
            region,
            plan.operation(),
            2,
            input.q_instances.get(2).ok_or(Error::Synthesis)?,
        )?;
        self.bind_signature_slot(region, bundle.slots())
    }

    // Q-free projection of genuine native signature exports, with no sigma frame.
    // The staged adapter above still binds every original object and Q2 context.
    pub(crate) fn signature_projection(
        &self,
        chip: &mut VerifierChip<Ep>,
        region: &mut Region<'_, Fp>,
        operation: &crate::a_relation::AProofPlan,
        schema: &QSignaturePlan,
        instances: &[Vec<iroha_plonk_recursion::codec::ScalarCells<Ep>>],
    ) -> Result<Bit<Fp>, Error> {
        let projection = crate::a_relation::signature::project_signature_q(
            chip, region, operation, 2, schema, instances,
        )?;
        projection.bind_context(region, operation, 2, instances)?;
        self.bind_signature_slot(region, projection.slots())
    }

    fn bind_signature_slot(
        &self,
        region: &mut Region<'_, Fp>,
        slots: &[crate::a_relation::signature::SignatureProofCells],
    ) -> Result<Bit<Fp>, Error> {
        let [slot] = slots else {
            return Err(Error::Synthesis);
        };
        if slot.mode() != VerifyMode::Soft || slot.key_policy() != SignatureKey::Variable {
            return Err(Error::Synthesis);
        }
        self.receipt
            .bind_signature(region, slot, self.receiver.payment_key()?)
    }
}
