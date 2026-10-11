//! Mandatory Archive receipt, current credential and direct root authorization.

use ff::Field;
use iroha_pasta::{Ep, Fp};
use iroha_plonk::frontend::{Error, Region, Value};
use iroha_plonk_gadgets::{GlueChip, UintChip, bytes::tape::BytesChip, p256::VerifyMode};
use iroha_plonk_recursion::{obligation::ledger::Variant, verifier::VerifierChip};

use super::{require_task, require_variant};
use crate::{
    a_relation::{
        SigmaBindingCells, SignatureQCells, bounded_word,
        context::{ContextInputs, ContextObjectCells, ContextObjectSpec, ContextPlan},
        own::{CurrentAuthorization, OwnPolicy, authenticate_current},
        schedule::{OperationTask, sigma_selector},
    },
    operation_relation::{
        map_effects::MapState,
        objects::{
            ObjectKind, SignedObjectCells,
            receipt::{self, ReceiptContext},
        },
    },
    q_signature::{QSignaturePlan, SignatureKey, SignatureSlot},
};

const KINDS: [ObjectKind; 3] = [
    ObjectKind::Credential,
    ObjectKind::Certificate,
    ObjectKind::Receipt,
];

/// Exact current credential, direct Enrollment certificate and own receipt.
/// These are the hard tags1..3 prefix of every Archive split context.
#[derive(Clone, Debug)]
pub struct ArchiveAuthorizationObjects {
    variant: Variant,
    objects: [SignedObjectCells; 3],
    context: [ContextObjectCells; 3],
}

impl ArchiveAuthorizationObjects {
    /// Fixed own2V1F and incoming1V signature-Q schemas, in Q1/Q2 order.
    /// The incoming receipt is soft; the three own signatures always remain hard.
    /// # Errors
    /// Invalid fixed scheme-root key.
    pub fn signature_schemas(policy: OwnPolicy) -> Result<[QSignaturePlan; 2], Error> {
        Ok([
            QSignaturePlan::new(vec![
                SignatureSlot {
                    mode: VerifyMode::Hard,
                    key: SignatureKey::Variable,
                },
                SignatureSlot {
                    mode: VerifyMode::Hard,
                    key: SignatureKey::Variable,
                },
                SignatureSlot {
                    mode: VerifyMode::Hard,
                    key: SignatureKey::Fixed(policy.root),
                },
            ])?,
            QSignaturePlan::new(vec![SignatureSlot {
                mode: VerifyMode::Soft,
                key: SignatureKey::Variable,
            }])?,
        ])
    }

    /// Fixed tags1..3; every original signature is included in its tape.
    /// # Errors
    /// Impossible fixed-size conversion.
    pub fn context_specs() -> Result<[ContextObjectSpec; 3], Error> {
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

    /// Parse hard own objects from the identical original tapes committed in `D_ctx`.
    /// # Errors
    /// Non-Archive variant, wrong fixed tape size or malformed own object.
    pub fn decode(
        chip: &mut VerifierChip<Ep>,
        bytes: &mut BytesChip<Fp>,
        region: &mut Region<'_, Fp>,
        variant: Variant,
        sources: [&[Value<u8>]; 3],
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
    pub const fn context(&self) -> &[ContextObjectCells; 3] {
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
            || plan.object_specs().get(..3) != Some(specs.as_slice())
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

    /// Hard-authenticate the current credential, its direct certificate and own receipt.
    /// Q1 must be verified at this task's stage; the recursive ledger still owns
    /// its deferred opening. Incoming evidence cannot gate any of these checks.
    /// # Errors
    /// Wrong owner/schema/root/Q identity or unsatisfiable own authorization.
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
        let [schema, _] = Self::signature_schemas(policy)?;
        let slots = bundle.slots();
        if !plan
            .q_partition(usize::try_from(stage).map_err(|_| Error::BoundsFailure)?)
            .is_some_and(|q| q.contains(&1))
            || slots.len() != schema.slots().len()
            || slots.iter().zip(schema.slots()).any(|(actual, expected)| {
                actual.mode() != expected.mode || actual.key_policy() != expected.key
            })
        {
            return Err(Error::Synthesis);
        }
        bundle.bind_context(
            region,
            plan.operation(),
            1,
            input.q_instances.get(1).ok_or(Error::Synthesis)?,
        )?;
        let predecessor = input.predecessor.ok_or(Error::Synthesis)?;
        authenticate_current(
            chip,
            region,
            policy,
            CurrentAuthorization {
                credential: &self.objects[0],
                certificate: &self.objects[1],
                credential_proof: &slots[1],
                certificate_proof: &slots[2],
                current: MapState {
                    state: predecessor.state,
                    lineage: predecessor.public,
                },
                statement: input.own_statement,
            },
        )?;
        let key = core::array::from_fn(|i| predecessor.public.fields()[9 + i].clone());
        let valid = self.objects[2].bind_signature(region, &slots[0], &key)?;
        GlueChip::assert_constant(region, valid.word(), Fp::ONE)?;
        let wallet = core::array::from_fn(|i| predecessor.public.fields()[6 + i].clone());
        let provider = policy.provider(chip, region)?;
        let zero = chip.uint().glue().constant(region, Fp::ZERO)?;
        let lanes = chip.operation_lanes()?;
        let valid = receipt::bind(
            &mut UintChip::new(lanes.glue, lanes.range),
            lanes.hash,
            region,
            &self.objects[2],
            &ReceiptContext {
                wallet: &wallet,
                provider: &provider,
                statement: input.own_statement,
                // ArchiveOwnProof independently binds this same committed field.
                proof_digest: self.objects[2].word(9)?,
                payment_digest: &zero,
            },
        )?;
        GlueChip::assert_constant(region, valid.word(), Fp::ONE)
    }

    /// Bind the exact own sigma, canonical tag5 selector and sigma-only receipt digest.
    /// Q0 is hard-verified at its unique fixed owner; these public exports are
    /// retained in the same context even if this task executes at another stage.
    /// # Errors
    /// Wrong owner, sigma class, source shape or unsatisfied original-byte binding.
    pub fn constrain_own_proof(
        &self,
        chip: &mut VerifierChip<Ep>,
        region: &mut Region<'_, Fp>,
        plan: &ContextPlan,
        stage: u32,
        input: &ContextInputs<'_>,
        sigma: &SigmaBindingCells,
    ) -> Result<(), Error> {
        require_task(plan, stage, OperationTask::ArchiveOwnProof)?;
        self.bind_context(region, plan, input)?;
        let statement = sigma.hard_statement()?;
        for (a, b) in statement.fields().iter().zip(input.own_statement.fields()) {
            GlueChip::assert_equal(region, a, b)?;
        }
        let selector = Fp::from(u64::from(sigma_selector(5, 0).ok_or(Error::Synthesis)?));
        GlueChip::assert_constant(region, sigma.key_index(), selector)?;
        let columns = input.q_instances.first().ok_or(Error::Synthesis)?;
        let sigma_plan = &plan.operation().sigma;
        if columns.len() != 5
            || columns
                .iter()
                .zip(sigma_plan.instance_lengths())
                .any(|(c, n)| c.len() != n)
        {
            return Err(Error::Synthesis);
        }
        let digest = bounded_word(chip, region, &columns[0][0])?;
        GlueChip::assert_equal(region, &digest, statement.digest())?;
        let index = bounded_word(chip, region, &columns[2][0])?;
        GlueChip::assert_constant(region, &index, selector)?;
        let chunks = sigma_plan.chunk_range(0).ok_or(Error::Synthesis)?;
        if chunks.len() != sigma.proof_chunks().len() {
            return Err(Error::Synthesis);
        }
        for (i, expected) in chunks.zip(sigma.proof_chunks()) {
            let actual = bounded_word(chip, region, &columns[0][i])?;
            GlueChip::assert_equal(region, &actual, expected)?;
        }
        GlueChip::assert_equal(region, self.objects[2].word(9)?, sigma.step_digest()?)
    }
}
