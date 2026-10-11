//! Receive's mandatory own authorization and total incoming signature result.

use ff::Field;
use iroha_pasta::{Ep, Fp};
use iroha_plonk::frontend::{Error, Region, Value};
use iroha_plonk_gadgets::{Bit, GlueChip, UintChip, bytes::tape::BytesChip, p256::VerifyMode};
use iroha_plonk_recursion::{obligation::ledger::Variant, verifier::VerifierChip};

use super::{ReceiveSignedObjects, maps::require_task};
use crate::{
    a_relation::{
        SigmaBindingCells, SignatureQCells, bounded_word,
        context::{ContextInputs, ContextObjectCells, ContextObjectSpec, ContextPlan},
        own::{CurrentAuthorization, OwnPolicy, authenticate_current},
        results::ReceiveResultTag,
        schedule::OperationTask,
    },
    operation_relation::{
        map_effects::MapState,
        objects::{
            ObjectKind, SignedObjectCells,
            credential::{CredentialAuthorization, CredentialCells},
            predicates::all,
            receipt::{self, ReceiptContext},
            request::RequestCells,
        },
    },
    q_signature::{QSignaturePlan, SignatureKey},
};

#[cfg(test)]
mod tests;

/// Original own objects and the exact pair carried by the incoming Request.
#[derive(Clone, Copy)]
pub struct ReceiveAuthorizationSources<'a> {
    /// Current credential body and signature.
    pub current: &'a [Value<u8>],
    /// Current direct Enrollment certificate body and signature.
    pub certificate: &'a [Value<u8>],
    /// Own Receive receipt body and signature.
    pub receipt: &'a [Value<u8>],
    /// Original quoted credential and its certificate, even when signatures deduplicate.
    pub quoted: [&'a [Value<u8>]; 2],
}

/// Fixed authorization tapes following Receive's six incoming-source context slots.
#[derive(Clone, Debug)]
pub struct ReceiveAuthorizationObjects {
    variant: Variant,
    objects: Vec<SignedObjectCells>,
    context: Vec<ContextObjectCells>,
}

/// Exact Q bundles and incoming objects consumed by the Signatures owner.
#[derive(Clone, Copy)]
pub struct ReceiveSignatureInputs<'a> {
    /// Circuit-fixed provider and root key; scheme is carried by the own state.
    pub policy: OwnPolicy,
    /// Same original incoming Request, payer credential and Send receipt.
    pub objects: &'a ReceiveSignedObjects,
    /// Soft Send receipt/Request slots, followed by the quoted credential and
    /// fixed-root certificate only in the renewed variant.
    pub incoming: &'a ReceiveSignatureQProjection,
}

/// Exact raw predicate inputs shared by staged verification and native preparation.
#[derive(Clone, Copy)]
pub(crate) struct ReceiveSignaturePredicateInputs<'a> {
    pub policy: OwnPolicy,
    pub own_statement: &'a crate::operation_relation::statement::StatementCells,
    pub predecessor: MapState<'a>,
    pub objects: &'a ReceiveSignedObjects,
    pub slots: &'a [crate::a_relation::SignatureProofCells],
}

/// Exact context-bound incoming Q2 exports. Q2 remains a separately verified
/// and folded hard obligation at its unique preceding (or same) fixed stage.
#[derive(Clone, Debug)]
pub struct ReceiveSignatureQProjection {
    projection: crate::a_relation::signature::SignatureQProjection,
}
impl ReceiveSignatureQProjection {
    /// Extract only the fixed Q2 schema and public cells of this Signatures owner.
    /// This does not verify Q2 or create a replacement deferred opening.
    /// # Errors
    /// Wrong owner, missing/future Q2 verification, wrong fixed schema or public shape.
    pub fn from_context(
        chip: &mut VerifierChip<Ep>,
        region: &mut Region<'_, Fp>,
        plan: &ContextPlan,
        stage: u32,
        policy: OwnPolicy,
        input: &ContextInputs<'_>,
    ) -> Result<Self, Error> {
        require_task(plan, stage, OperationTask::ReceiveSignatures)?;
        let owner = (0..plan.stage_count())
            .find(|i| plan.q_partition(*i).is_some_and(|q| q.contains(&2)))
            .ok_or(Error::Synthesis)?;
        if owner > usize::try_from(stage).map_err(|_| Error::BoundsFailure)? {
            return Err(Error::Synthesis);
        }
        let schemas =
            super::ReceiveStagePlan::signature_schemas(plan.operation().frame().variant(), policy)?;
        Ok(Self {
            projection: crate::a_relation::signature::project_signature_q(
                chip,
                region,
                plan.operation(),
                2,
                &schemas[1],
                input.q_instances.get(2).ok_or(Error::Synthesis)?,
            )?,
        })
    }
    // Native source evaluation projects only the real signature schema. It has no
    // sigma/Q0 frame or pending proof opening and cannot enter an accumulation ledger.
    pub(crate) fn from_original_instances(
        chip: &mut VerifierChip<Ep>,
        region: &mut Region<'_, Fp>,
        operation: &crate::a_relation::AProofPlan,
        schema: &QSignaturePlan,
        instances: &[Vec<iroha_plonk_recursion::codec::ScalarCells<Ep>>],
    ) -> Result<Self, Error> {
        Ok(Self {
            projection: crate::a_relation::signature::project_signature_q(
                chip, region, operation, 2, schema, instances,
            )?,
        })
    }

    /// Original raw message, key/signature and exact soft verdict exports.
    pub fn slots(&self) -> &[crate::a_relation::SignatureProofCells] {
        self.projection.slots()
    }
    fn bind_context(
        &self,
        region: &mut Region<'_, Fp>,
        plan: &ContextPlan,
        stage: u32,
        input: &ContextInputs<'_>,
    ) -> Result<(), Error> {
        require_task(plan, stage, OperationTask::ReceiveSignatures)?;
        self.projection.bind_context(
            region,
            plan.operation(),
            2,
            input.q_instances.get(2).ok_or(Error::Synthesis)?,
        )
    }
}

fn kinds(variant: Variant) -> Result<Vec<ObjectKind>, Error> {
    if !matches!(variant, Variant::Receive | Variant::ReceiveRenewed) {
        return Err(Error::Synthesis);
    }
    let mut out = vec![
        ObjectKind::Credential,
        ObjectKind::Certificate,
        ObjectKind::Receipt,
    ];
    out.extend([ObjectKind::Credential, ObjectKind::Certificate]);
    Ok(out)
}

fn bind_bundle(
    region: &mut Region<'_, Fp>,
    plan: &ContextPlan,
    stage: u32,
    input: &ContextInputs<'_>,
    bundle: &SignatureQCells,
) -> Result<(), Error> {
    let index = bundle.verified().index;
    if !plan
        .q_partition(usize::try_from(stage).map_err(|_| Error::BoundsFailure)?)
        .ok_or(Error::Synthesis)?
        .contains(&index)
    {
        return Err(Error::Synthesis);
    }
    bundle.bind_context(
        region,
        plan.operation(),
        index,
        input.q_instances.get(index).ok_or(Error::Synthesis)?,
    )
}

impl ReceiveAuthorizationObjects {
    fn bind_quoted_sources(
        &self,
        uint: &mut UintChip<'_, Fp>,
        region: &mut Region<'_, Fp>,
        request: &RequestCells,
    ) -> Result<(), Error> {
        // Payment omits these tapes; bind their content addresses before any
        // soft semantic or signature verdict can participate in a burn.
        GlueChip::assert_equal(region, request.object().word(8)?, self.objects[3].digest())?;
        GlueChip::assert_equal(region, self.objects[3].word(28)?, self.objects[4].digest())?;
        let same_current =
            uint.glue()
                .is_equal(region, self.objects[3].digest(), self.objects[0].digest())?;
        GlueChip::assert_constant(
            region,
            same_current.word(),
            if self.variant == Variant::Receive {
                Fp::ONE
            } else {
                Fp::ZERO
            },
        )?;
        if self.variant == Variant::Receive {
            GlueChip::assert_equal(region, self.objects[4].digest(), self.objects[1].digest())?;
        }
        Ok(())
    }

    /// Fixed tags7..11: own current/certificate/receipt and original quoted pair.
    /// # Errors
    /// Non-Receive variant or impossible fixed size conversion.
    pub fn context_specs(variant: Variant) -> Result<Vec<ContextObjectSpec>, Error> {
        kinds(variant)?
            .into_iter()
            .enumerate()
            .map(|(i, kind)| {
                Ok(ContextObjectSpec {
                    tag: u32::try_from(i + 7).map_err(|_| Error::BoundsFailure)?,
                    capacity: u32::try_from(kind.body_len() + 64)
                        .map_err(|_| Error::BoundsFailure)?,
                })
            })
            .collect()
    }

    /// Decode hard own tapes and total soft quoted tapes from their exact bytes.
    /// # Errors
    /// Wrong fixed variant/shape or layout error; malformed own tapes fail hard.
    pub fn decode(
        chip: &mut VerifierChip<Ep>,
        bytes: &mut BytesChip<Fp>,
        region: &mut Region<'_, Fp>,
        variant: Variant,
        source: ReceiveAuthorizationSources<'_>,
    ) -> Result<Self, Error> {
        let mut sources = vec![source.current, source.certificate, source.receipt];
        sources.extend(source.quoted);
        let mut objects = Vec::new();
        let mut context = Vec::new();
        for (index, ((kind, source), spec)) in kinds(variant)?
            .into_iter()
            .zip(sources)
            .zip(Self::context_specs(variant)?)
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
            let object = if index < 3 {
                SignedObjectCells::from_run(&mut uint, lanes.hash, region, kind, &run)?
            } else {
                SignedObjectCells::decode_soft(&mut uint, lanes.hash, region, kind, &run)?.0
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
            variant,
            objects,
            context,
        })
    }

    /// Ordered same-tape context suffix following the six incoming-source slots.
    pub fn context(&self) -> &[ContextObjectCells] {
        &self.context
    }

    pub(super) fn bind_context(
        &self,
        region: &mut Region<'_, Fp>,
        plan: &ContextPlan,
        input: &ContextInputs<'_>,
    ) -> Result<(), Error> {
        let specs = Self::context_specs(self.variant)?;
        if input.own_statement.variant() != self.variant
            || plan.operation().frame().variant() != self.variant
            || plan.object_specs().get(6..) != Some(specs.as_slice())
            || input.objects.len() != 6 + self.context.len()
        {
            return Err(Error::Synthesis);
        }
        for (actual, expected) in self.context.iter().zip(&input.objects[6..]) {
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

    /// Bind the own receipt's proof digest to its exact Q-exported sigma tape.
    /// # Errors
    /// Wrong owner/schema, absent same-tape digest or unsatisfied byte/input binding.
    pub fn constrain_own_proof(
        &self,
        chip: &mut VerifierChip<Ep>,
        region: &mut Region<'_, Fp>,
        plan: &ContextPlan,
        stage: u32,
        input: &ContextInputs<'_>,
        sigma: &SigmaBindingCells,
    ) -> Result<(), Error> {
        require_task(plan, stage, OperationTask::ReceiveOwnProof)?;
        self.bind_context(region, plan, input)?;
        let statement = sigma.hard_statement()?;
        for (a, b) in statement.fields().iter().zip(input.own_statement.fields()) {
            GlueChip::assert_equal(region, a, b)?;
        }
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

    /// Hard reverify C4 and the own receipt from the same context and hard Q bundle.
    /// Slots are own receipt, current credential and fixed-root Enrollment certificate.
    /// # Errors
    /// Wrong fixed task, Q partition, slot class or context; invalid own authorization fails hard.
    pub fn constrain_current(
        &self,
        chip: &mut VerifierChip<Ep>,
        region: &mut Region<'_, Fp>,
        plan: &ContextPlan,
        stage: u32,
        input: &ContextInputs<'_>,
        policy_and_bundle: (OwnPolicy, &SignatureQCells),
    ) -> Result<(), Error> {
        require_task(plan, stage, OperationTask::ReceiveAuthorization)?;
        self.bind_context(region, plan, input)?;
        let (policy, bundle) = policy_and_bundle;
        bind_bundle(region, plan, stage, input, bundle)?;
        let slots = bundle.slots();
        if slots.len() != 3 || slots.iter().any(|slot| slot.mode() != VerifyMode::Hard) {
            return Err(Error::Synthesis);
        }
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
        let payment_key = core::array::from_fn(|i| predecessor.public.fields()[9 + i].clone());
        let signature = self.objects[2].bind_signature(region, &slots[0], &payment_key)?;
        GlueChip::assert_constant(region, signature.word(), Fp::ONE)?;
        let provider = policy.provider(chip, region)?;
        let wallet = core::array::from_fn(|i| predecessor.public.fields()[6 + i].clone());
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
                proof_digest: self.objects[2].word(9)?,
                payment_digest: input
                    .objects
                    .get(3)
                    .ok_or(Error::Synthesis)?
                    .authenticated_digest(),
            },
        )?;
        GlueChip::assert_constant(region, valid.word(), Fp::ONE)
    }

    /// Derive the incoming signatures and quoted receiver authorization result.
    ///
    /// All messages, keys and raw r/s values are hard-linked to their original
    /// tapes before taking a soft verdict. Ordinary Receive deduplicates the
    /// quoted credential with mandatory current C4; Renewed verifies the extra
    /// quoted credential/certificate under the same circuit-fixed root.
    /// # Errors
    /// Wrong task/Q/soft-slot/root policy or context shape, or layout failure.
    pub fn constrain_signatures(
        &self,
        chip: &mut VerifierChip<Ep>,
        region: &mut Region<'_, Fp>,
        plan: &ContextPlan,
        stage: u32,
        input: &ContextInputs<'_>,
        proof: ReceiveSignatureInputs<'_>,
    ) -> Result<(), Error> {
        let valid = self.derive_signatures(chip, region, plan, stage, input, proof)?;
        input.receive_results.ok_or(Error::Synthesis)?.bind_derived(
            region,
            plan.receive_results().ok_or(Error::Synthesis)?,
            stage,
            ReceiveResultTag::Signatures,
            &valid,
        )
    }

    // Same production predicate for native witness preparation. This returns assigned
    // cells only; the fixed owning stage still binds and proves the result.
    pub(crate) fn derive_signatures(
        &self,
        chip: &mut VerifierChip<Ep>,
        region: &mut Region<'_, Fp>,
        plan: &ContextPlan,
        stage: u32,
        input: &ContextInputs<'_>,
        proof: ReceiveSignatureInputs<'_>,
    ) -> Result<Bit<Fp>, Error> {
        require_task(plan, stage, OperationTask::ReceiveSignatures)?;
        self.bind_context(region, plan, input)?;
        proof.objects.bind_context(region, plan, input)?;
        proof.incoming.bind_context(region, plan, stage, input)?;
        self.signature_predicate(
            chip,
            region,
            ReceiveSignaturePredicateInputs {
                policy: proof.policy,
                own_statement: input.own_statement,
                predecessor: MapState {
                    state: input.predecessor.ok_or(Error::Synthesis)?.state,
                    lineage: input.predecessor.ok_or(Error::Synthesis)?.public,
                },
                objects: proof.objects,
                slots: proof.incoming.slots(),
            },
        )
    }

    // Shared exact raw predicate: staged ownership/context bindings remain above.
    // Native pre-Q evaluation supplies original signature exports, never Q0 columns.
    pub(crate) fn signature_predicate(
        &self,
        chip: &mut VerifierChip<Ep>,
        region: &mut Region<'_, Fp>,
        input: ReceiveSignaturePredicateInputs<'_>,
    ) -> Result<Bit<Fp>, Error> {
        let ReceiveSignaturePredicateInputs {
            policy,
            own_statement,
            predecessor,
            objects,
            slots,
        } = input;
        let renewed = self.variant == Variant::ReceiveRenewed;
        if slots.len() != if renewed { 4 } else { 2 }
            || slots.iter().any(|slot| slot.mode() != VerifyMode::Soft)
            || slots[..2]
                .iter()
                .any(|slot| slot.key_policy() != SignatureKey::Variable)
        {
            return Err(Error::Synthesis);
        }
        let scope = policy.scope(chip, region, predecessor.state)?;
        let lanes = chip.operation_lanes()?;
        let mut uint = UintChip::new(lanes.glue, lanes.range);
        let receiver = CredentialCells::check(&mut uint, region, &self.objects[3])?;
        let payer = CredentialCells::check(&mut uint, region, &objects.objects[1])?;
        let request = RequestCells::check(&mut uint, lanes.hash, region, &objects.objects[0])?;
        self.bind_quoted_sources(&mut uint, region, &request)?;
        let mut checks = vec![
            objects.objects[2].structural_valid().clone(),
            objects.objects[2].bind_signature(region, &slots[0], payer.payment_key()?)?,
            request.bind_receive(
                &mut uint,
                region,
                own_statement,
                &receiver,
                predecessor.lineage,
                &slots[1],
            )?,
        ];
        if renewed {
            if slots[2].key_policy() != SignatureKey::Variable
                || slots[3].key_policy() != SignatureKey::Fixed(policy.root)
            {
                return Err(Error::Synthesis);
            }
            checks.push(receiver.authenticate(
                &mut uint,
                region,
                &CredentialAuthorization {
                    certificate: &self.objects[4],
                    certificate_proof: &slots[3],
                    credential_proof: &slots[2],
                    root_key: slots[3].key(),
                    scheme: &scope.scheme,
                    provider: &scope.provider,
                },
            )?);
        } else {
            // Signature deduplication does not omit original wrapper evidence.
            // A malformed original quoted object/certificate still returns false.
            checks.push(self.objects[4].structural_valid().clone());
        }
        let valid = all(uint.glue(), region, &checks)?;
        Ok(valid)
    }
}
