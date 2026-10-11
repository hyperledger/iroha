//! Hard binding of an Archive's retained Payment and pending descriptor.
//!
//! Historical Send proofs are opaque here: their exact original bytes are
//! hashed into the Payment that the incoming evidence must acknowledge. This
//! owner does not replace incoming evidence verification or pending membership.

use ff::Field;
use iroha_pasta::{Ep, Fp};
use iroha_plonk::frontend::{Error, Region, Value};
use iroha_plonk_gadgets::{
    GlueChip, UintChip, Word,
    bytes::{tape::BytesChip, variable::ActiveBytes},
};
use iroha_plonk_recursion::{obligation::ledger::Variant, verifier::VerifierChip};

use super::require_task;
use crate::{
    a_relation::{
        context::{ContextInputs, ContextObjectCells, ContextObjectSpec, ContextPlan},
        own::OwnPolicy,
        schedule::OperationTask,
    },
    operation_relation::{
        incoming_statement::{IncomingStatementCells, StatementView},
        objects::{
            ObjectKind, SignedObjectCells,
            credential::CredentialCells,
            payment::{PaymentCells, PaymentInputs},
            request::RequestCells,
        },
    },
};

const KINDS: [ObjectKind; 4] = [
    ObjectKind::Request,
    ObjectKind::Credential,
    ObjectKind::Receipt,
    ObjectKind::Credential,
];

pub(super) const DESCRIPTOR_SLOT: usize = 11;
pub(super) const DESCRIPTOR_SPEC: ContextObjectSpec = ContextObjectSpec {
    tag: 12,
    capacity: 7 * 32,
};

/// Exact signed sources and transitive Payment transcript retained after Send.
#[derive(Clone, Copy)]
pub struct ArchiveRetainedSources<'a> {
    /// Request, payer credential, Send receipt and quoted receiver credential.
    /// Each includes its original raw signature after the fixed body.
    pub signed: [&'a [Value<u8>]; 4],
    /// Canonical163-byte Payment transcript derived from the retained frame.
    pub payment: &'a [Value<u8>],
}

/// Original historical Send statement and the two exact opaque proof tapes.
#[derive(Clone, Copy)]
pub struct ArchiveRetainedInputs<'a> {
    /// All26 original Send statement words, including the pending descriptor.
    pub statement: &'a [Word<Fp>; 26],
    /// Exact raw Omega carrier used by the native consuming proof digest.
    pub omega: &'a ActiveBytes<Fp>,
    /// Exact original sigma bytes, without fixed-descriptor padding.
    pub sigma: &'a ActiveBytes<Fp>,
}

/// Both exact retained proof commitments and their shared consuming digest.
/// Authentication requires execution at the fixed retained-proofs owner.
#[derive(Clone, Debug)]
pub struct ArchiveRetainedProofs {
    context: [ContextObjectCells; 2],
    specs: [ContextObjectSpec; 2],
}
impl ArchiveRetainedProofs {
    /// Hash every original byte and hard-enforce the complete Payment proof budget.
    /// # Errors
    /// Invalid capacities, oversized combined lengths or layout failure.
    pub fn from_sources(
        chip: &mut VerifierChip<Ep>,
        region: &mut Region<'_, Fp>,
        omega: &ActiveBytes<Fp>,
        sigma: &ActiveBytes<Fp>,
    ) -> Result<Self, Error> {
        let specs = ArchiveRetainedPayment::context_specs(omega.run().len(), sigma.run().len())?;
        let specs = [specs[6], specs[7]];
        let lanes = chip.operation_lanes()?;
        let mut uint = UintChip::new(lanes.glue, lanes.range);
        let within = crate::a_relation::receive::joint_length_valid(
            &mut uint,
            region,
            omega.length(),
            sigma.length(),
        )?;
        GlueChip::assert_constant(region, within.word(), Fp::ONE)?;
        let left = omega.packed().length_prefixed(&mut uint, region)?;
        let right = sigma.packed().length_prefixed(&mut uint, region)?;
        let digest = left.concat(&mut uint, region, &right)?.digest(
            &mut uint,
            lanes.hash.sponge_mut()?,
            region,
            u64::from_le_bytes(*b"kgwprf_1"),
        )?;
        let mut context = Vec::new();
        for (spec, carrier) in specs.into_iter().zip([omega, sigma]) {
            context.push(ContextObjectCells::from_active(
                chip, region, spec, &digest, carrier,
            )?);
        }
        Ok(Self {
            context: context.try_into().map_err(|_| Error::Synthesis)?,
            specs,
        })
    }

    fn from_context(
        region: &mut Region<'_, Fp>,
        plan: &ContextPlan,
        objects: &[ContextObjectCells],
    ) -> Result<Self, Error> {
        let specs: [ContextObjectSpec; 2] = plan
            .object_specs()
            .get(9..11)
            .ok_or(Error::Synthesis)?
            .try_into()
            .map_err(|_| Error::Synthesis)?;
        let expected = ArchiveRetainedPayment::context_specs(
            specs[0].capacity as usize,
            specs[1].capacity as usize,
        )?;
        if specs != [expected[6], expected[7]] {
            return Err(Error::Synthesis);
        }
        let context: [ContextObjectCells; 2] = objects
            .get(9..11)
            .ok_or(Error::Synthesis)?
            .to_vec()
            .try_into()
            .map_err(|_| Error::Synthesis)?;
        GlueChip::assert_equal(
            region,
            context[0].authenticated_digest(),
            context[1].authenticated_digest(),
        )?;
        Ok(Self { context, specs })
    }

    /// Bind both exact tapes at their mandatory owner, independent of soft evidence.
    /// # Errors
    /// Wrong owner/schema or any changed digest, original length or byte commitment.
    pub fn bind_context(
        &self,
        region: &mut Region<'_, Fp>,
        plan: &ContextPlan,
        stage: u32,
        input: &ContextInputs<'_>,
    ) -> Result<(), Error> {
        require_task(plan, stage, OperationTask::ArchiveRetainedProofs)?;
        let expected = Self::from_context(region, plan, input.objects)?;
        if self.specs != expected.specs {
            return Err(Error::Synthesis);
        }
        for (a, b) in self.context.iter().zip(&expected.context) {
            for (actual, expected) in a.commitment_words().iter().zip(b.commitment_words()) {
                GlueChip::assert_equal(region, actual, &expected)?;
            }
        }
        Ok(())
    }
}

/// Hard original Payment binding shared by every evidence and removal owner.
#[derive(Clone, Debug)]
pub struct ArchiveRetainedPayment {
    request: RequestCells,
    receiver: CredentialCells,
    payment: PaymentCells,
    statement: IncomingStatementCells,
    context: [ContextObjectCells; 9],
    specs: [ContextObjectSpec; 9],
}

impl ArchiveRetainedPayment {
    /// Fixed tags4..12 following Archive's three own authorization objects.
    /// Slots are four signed sources, Payment, Send words, raw Omega, raw sigma
    /// and the seven-word pending descriptor. Proof capacities are key-fixed.
    /// # Errors
    /// Empty/overflowing proof capacity or impossible fixed-size conversion.
    pub fn context_specs(
        omega_capacity: usize,
        sigma_capacity: usize,
    ) -> Result<[ContextObjectSpec; 9], Error> {
        if omega_capacity == 0 || sigma_capacity == 0 {
            return Err(Error::Synthesis);
        }
        let mut capacities = KINDS.map(|kind| kind.body_len() + 64).to_vec();
        capacities.extend([
            PaymentCells::BYTES,
            26 * 32,
            omega_capacity,
            sigma_capacity,
            7 * 32,
        ]);
        capacities
            .into_iter()
            .enumerate()
            .map(|(i, capacity)| {
                Ok(ContextObjectSpec {
                    tag: u32::try_from(i + 4).map_err(|_| Error::BoundsFailure)?,
                    capacity: u32::try_from(capacity).map_err(|_| Error::BoundsFailure)?,
                })
            })
            .collect::<Result<Vec<_>, Error>>()?
            .try_into()
            .map_err(|_| Error::Synthesis)
    }

    /// Derive every retained commitment from the same original tapes.
    /// This hard own-data binding runs even when incoming evidence is invalid.
    /// No signature or proof verdict is inferred from these historical bytes.
    /// # Errors
    /// Wrong source size/schema, malformed retained objects, changed quoted
    /// credential, oversized joint proof tape or inconsistent Payment/Send
    /// component addresses.
    pub fn from_sources(
        chip: &mut VerifierChip<Ep>,
        bytes: &mut BytesChip<Fp>,
        region: &mut Region<'_, Fp>,
        policy: OwnPolicy,
        sources: ArchiveRetainedSources<'_>,
        input: ArchiveRetainedInputs<'_>,
    ) -> Result<Self, Error> {
        let proofs = ArchiveRetainedProofs::from_sources(chip, region, input.omega, input.sigma)?;
        Self::from_proof_cells(
            chip,
            bytes,
            region,
            policy,
            sources,
            input.statement,
            &proofs,
        )
    }

    /// Derive signed Payment semantics from the two fixed context proof commitments.
    /// The mandatory `ArchiveRetainedProofs` owner must independently derive both
    /// commitments and enforce the joint envelope bound before terminal closure.
    /// # Errors
    /// Wrong full source schema, unequal proof digests or inconsistent signed sources.
    pub fn from_committed_proofs(
        chip: &mut VerifierChip<Ep>,
        bytes: &mut BytesChip<Fp>,
        region: &mut Region<'_, Fp>,
        policy: OwnPolicy,
        sources: ArchiveRetainedSources<'_>,
        statement: &[Word<Fp>; 26],
        context: (&ContextPlan, &ContextInputs<'_>),
    ) -> Result<Self, Error> {
        let proofs = ArchiveRetainedProofs::from_context(region, context.0, context.1.objects)?;
        Self::from_proof_cells(chip, bytes, region, policy, sources, statement, &proofs)
    }

    fn from_proof_cells(
        chip: &mut VerifierChip<Ep>,
        bytes: &mut BytesChip<Fp>,
        region: &mut Region<'_, Fp>,
        policy: OwnPolicy,
        sources: ArchiveRetainedSources<'_>,
        fields: &[Word<Fp>; 26],
        proofs: &ArchiveRetainedProofs,
    ) -> Result<Self, Error> {
        let specs = Self::context_specs(
            proofs.specs[0].capacity as usize,
            proofs.specs[1].capacity as usize,
        )?;
        let mut objects = Vec::new();
        let mut context = Vec::new();
        for ((kind, source), spec) in KINDS.into_iter().zip(sources.signed).zip(specs) {
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
        let provider = policy.provider(chip, region)?;
        let run = bytes.run(
            region,
            sources.payment,
            &PaymentCells::primary_segments(),
            &PaymentCells::secondary_segments(),
        )?;
        let lanes = chip.operation_lanes()?;
        let mut uint = UintChip::new(lanes.glue, lanes.range);
        let statement = IncomingStatementCells::constrain(
            &mut uint,
            lanes.hash,
            region,
            Variant::Send,
            fields,
        )?;
        let request = RequestCells::check(&mut uint, lanes.hash, region, &objects[0])?;
        let payer = CredentialCells::check(&mut uint, region, &objects[1])?;
        let receiver = CredentialCells::check(&mut uint, region, &objects[3])?;
        GlueChip::assert_equal(
            region,
            request.object().word(8)?,
            receiver.object().digest(),
        )?;
        GlueChip::assert_constant(region, receiver.valid().word(), Fp::ONE)?;
        for (request_index, credential_index) in [(1, 1), (2, 2), (5, 3), (6, 4)] {
            for (a, b) in request
                .object()
                .identifier(request_index)?
                .iter()
                .zip(receiver.object().identifier(credential_index)?)
            {
                GlueChip::assert_equal(region, a, b)?;
            }
        }
        let payment = PaymentCells::from_run(
            &mut uint,
            lanes.hash,
            region,
            &run,
            &PaymentInputs {
                request: &request,
                payer: &payer,
                statement: &statement,
                receipt: &objects[2],
                provider: &provider,
                proof_digest: proofs.context[0].authenticated_digest(),
            },
        )?;
        GlueChip::assert_constant(region, payment.valid().word(), Fp::ONE)?;
        context.push(ContextObjectCells::from_exact_run(
            chip,
            region,
            specs[4],
            payment.digest(),
            &run,
        )?);
        context.push(ContextObjectCells::from_internal_words(
            chip,
            region,
            specs[5],
            statement.fields(),
        )?);
        context.extend(proofs.context.iter().cloned());
        context.push(ContextObjectCells::from_internal_words(
            chip,
            region,
            specs[8],
            &statement.fields()[17..24],
        )?);
        Ok(Self {
            request,
            receiver,
            payment,
            statement,
            context: context.try_into().map_err(|_| Error::Synthesis)?,
            specs,
        })
    }

    /// Same original nine commitments, placed after the three own objects.
    pub const fn context(&self) -> &[ContextObjectCells; 9] {
        &self.context
    }

    /// Original held Request used by both forms of incoming evidence.
    pub const fn request(&self) -> &RequestCells {
        &self.request
    }

    /// Original quoted receiver credential; current receiver renewal is allowed.
    pub const fn receiver(&self) -> &CredentialCells {
        &self.receiver
    }

    /// Digest of the exact retained Payment, including both opaque proof tapes.
    pub const fn payment(&self) -> &PaymentCells {
        &self.payment
    }

    /// Bind this hard owner to the common context, own wallet and credit.
    /// The `CorePending` and terminal Effects owners must authenticate their
    /// respective removals using the descriptor committed at slot11.
    /// Incoming evidence may not gate this task.
    /// # Errors
    /// Wrong owner/schema, another wallet/credit or substituted retained source.
    pub fn bind_context(
        &self,
        region: &mut Region<'_, Fp>,
        plan: &ContextPlan,
        stage: u32,
        input: &ContextInputs<'_>,
    ) -> Result<(), Error> {
        require_task(plan, stage, OperationTask::ArchiveRetainedPayment)?;
        if plan.object_specs().get(3..12) != Some(self.specs.as_slice())
            || input.objects.len() != plan.object_specs().len()
            || input.own_statement.variant() != plan.operation().frame().variant()
        {
            return Err(Error::Synthesis);
        }
        let predecessor = input.predecessor.ok_or(Error::Synthesis)?;
        for (a, b) in self
            .request
            .object()
            .identifier(3)?
            .iter()
            .zip(&predecessor.public.fields()[6..8])
        {
            GlueChip::assert_equal(region, a, b)?;
        }
        for (a, b) in self.statement.fields()[1..7]
            .iter()
            .zip(&input.own_statement.fields()[1..7])
        {
            GlueChip::assert_equal(region, a, b)?;
        }
        GlueChip::assert_equal(
            region,
            self.request.credit_id(),
            &input.own_statement.fields()[17],
        )?;
        for (actual, expected) in self.context.iter().zip(&input.objects[3..12]) {
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
}

#[cfg(test)]
mod tests;
