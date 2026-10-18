//! Mandatory Archive own receipt and the merged signature leaf (lean lineage).
//!
//! The own receipt is the only own signed object Λ consumes. It is hard-verified
//! under the predecessor payment key in slot 0 of the merged signature leaf;
//! slot 1 is the soft incoming receipt, owned by the Signatures task in the same
//! stage. The credential digest and payment key are carried by continuity, so the
//! current credential and its Enrollment certificate are not re-verified.

use ff::Field;
use iroha_pasta::{Ep, Fp};
use iroha_plonk::frontend::{Error, Region, Value};
use iroha_plonk_gadgets::{GlueChip, UintChip, bytes::tape::BytesChip, p256::VerifyMode};
use iroha_plonk_recursion::{obligation::ledger::Variant, verifier::VerifierChip};

use super::{require_task, require_variant, signature_q};
use crate::{
    a_relation::{
        SignatureProofCells, SignatureQCells,
        context::{ContextInputs, ContextObjectCells, ContextObjectSpec, ContextPlan},
        own::OwnPolicy,
        schedule::OperationTask,
    },
    operation_relation::objects::{
        ObjectKind, SignedObjectCells,
        receipt::{self, ReceiptContext},
    },
    q_signature::{QSignaturePlan, SignatureKey, SignatureSlot},
};

const KINDS: [ObjectKind; 1] = [ObjectKind::Receipt];

/// Exact own receipt, the hard tag1 prefix of every Archive split context.
#[derive(Clone, Debug)]
pub struct ArchiveAuthorizationObjects {
    variant: Variant,
    objects: [SignedObjectCells; 1],
    context: [ContextObjectCells; 1],
}

impl ArchiveAuthorizationObjects {
    /// The merged signature-Q schema, in slot order: the own receipt hard under
    /// the predecessor payment key, then the incoming receipt soft under the
    /// Request's quoted receiver key. Both Archive variants share it; incoming
    /// evidence can never soft-fail the own slot.
    /// # Errors
    /// Impossible fixed schema.
    pub fn signature_schema() -> Result<QSignaturePlan, Error> {
        QSignaturePlan::new(vec![
            SignatureSlot {
                mode: VerifyMode::Hard,
                key: SignatureKey::Variable,
            },
            SignatureSlot {
                mode: VerifyMode::Soft,
                key: SignatureKey::Variable,
            },
        ])
    }

    /// Check extracted merged-leaf slots against the fixed schema, slot by slot.
    /// Both owners of the leaf run this check, so neither can read a bundle of
    /// another shape or let the soft slot stand in for the hard one.
    pub(super) fn require_signature_slots(slots: &[SignatureProofCells]) -> Result<(), Error> {
        let schema = Self::signature_schema()?;
        if slots.len() != schema.slots().len()
            || slots.iter().zip(schema.slots()).any(|(actual, expected)| {
                actual.mode() != expected.mode || actual.key_policy() != expected.key
            })
        {
            return Err(Error::Synthesis);
        }
        Ok(())
    }

    /// Fixed tag1; the original signature is included in its tape.
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

    /// Parse the hard own receipt from the identical original tape committed in `D_ctx`.
    /// # Errors
    /// Non-Archive variant, wrong fixed tape size or malformed own receipt.
    pub fn decode(
        chip: &mut VerifierChip<Ep>,
        bytes: &mut BytesChip<Fp>,
        region: &mut Region<'_, Fp>,
        variant: Variant,
        sources: [&[Value<u8>]; 1],
    ) -> Result<Self, Error> {
        require_variant(variant)?;
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
            variant,
            objects: objects.try_into().map_err(|_| Error::Synthesis)?,
            context: context.try_into().map_err(|_| Error::Synthesis)?,
        })
    }

    /// Same-tape prefix retained by every recursive continuation.
    pub const fn context(&self) -> &[ContextObjectCells; 1] {
        &self.context
    }

    fn bind_context(
        &self,
        region: &mut Region<'_, Fp>,
        plan: &ContextPlan,
        input: &ContextInputs<'_>,
    ) -> Result<(), Error> {
        let specs = Self::context_specs()?;
        if input.own_statement.variant() != self.variant
            || plan.operation().frame().variant() != self.variant
            || plan.object_specs().get(..1) != Some(specs.as_slice())
            || input.objects.len() != plan.object_specs().len()
        {
            return Err(Error::Synthesis);
        }
        for (actual, expected) in self.context.iter().zip(input.objects) {
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

    /// Hard-authenticate the own receipt on slot 0 of the merged signature leaf.
    /// The leaf must be verified at this task's stage; the recursive ledger still
    /// owns its deferred opening. Its soft incoming slot cannot gate this check.
    /// # Errors
    /// Wrong owner/schema/Q identity or unsatisfiable own authorization.
    pub fn constrain_current(
        &self,
        chip: &mut VerifierChip<Ep>,
        region: &mut Region<'_, Fp>,
        plan: &ContextPlan,
        stage: u32,
        input: &ContextInputs<'_>,
        policy_and_bundle: (OwnPolicy, &SignatureQCells),
    ) -> Result<(), Error> {
        require_task(plan, stage, OperationTask::ArchiveAuthorization)?;
        self.bind_context(region, plan, input)?;
        let (policy, bundle) = policy_and_bundle;
        let index = signature_q(self.variant)?;
        let slots = bundle.slots();
        Self::require_signature_slots(slots)?;
        if !plan
            .q_partition(usize::try_from(stage).map_err(|_| Error::BoundsFailure)?)
            .is_some_and(|q| q.contains(&index))
        {
            return Err(Error::Synthesis);
        }
        bundle.bind_context(
            region,
            plan.operation(),
            index,
            input.q_instances.get(index).ok_or(Error::Synthesis)?,
        )?;
        let predecessor = input.predecessor.ok_or(Error::Synthesis)?;
        // The payment key is carried by continuity from the predecessor lineage.
        let key = core::array::from_fn(|i| predecessor.public.fields()[9 + i].clone());
        let valid = self.objects[0].bind_signature(region, &slots[0], &key)?;
        GlueChip::assert_constant(region, valid.word(), Fp::ONE)?;
        let wallet = core::array::from_fn(|i| predecessor.public.fields()[6 + i].clone());
        let provider = policy.provider(chip, region)?;
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
                // Λ proves the own step directly, so this sigma-only digest names
                // the sigma_archive carrier Λ does not consume; it is the signed
                // body's own, and `receipt::bind` keeps it nonzero.
                proof_digest: self.objects[0].word(9)?,
                payment_digest: &zero,
            },
        )?;
        GlueChip::assert_constant(region, valid.word(), Fp::ONE)
    }
}
