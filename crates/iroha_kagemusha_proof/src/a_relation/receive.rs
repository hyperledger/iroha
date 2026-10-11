//! Receive's same-tape incoming object result and split-context ownership.
//!
//! Typed owners derive all five result groups, own hard authorization, map
//! effects and the terminal iff rule. The native producer composes ten fixed A
//! stages and nine W continuations. TODO: qualify both variants, acceptance and
//! corrected claims under the authenticated final catalog before admitting a
//! Receive key; component chains alone do not establish catalog execution.

use iroha_pasta::{Ep, Fp};
use iroha_plonk::frontend::{Error, Region, Value};
use iroha_plonk_gadgets::{Bit, GlueChip, Uint, UintChip, Word, bytes::tape::BytesChip};
use iroha_plonk_recursion::{obligation::ledger::Variant, verifier::VerifierChip};

use super::{
    LineagePublicCells, SigmaBindingCells, bounded_word,
    context::{ContextInputs, ContextObjectCells, ContextObjectSpec, ContextPlan},
    incoming_transport::IncomingTransportCells,
    own::OwnPolicy,
    results::ReceiveResultTag,
};
use crate::operation_relation::{
    incoming_statement::StatementView,
    objects::{
        ObjectKind, SignedObjectCells,
        credential::CredentialCells,
        payment::{IncomingPaymentCells, PaymentCells, PaymentInputs},
        predicates::{all, equal},
        request::RequestCells,
    },
    statement::StatementCells,
};

pub mod authorization;
mod digest;
pub use digest::ReceiveProofDigest;
pub mod maps;
mod proofs;
pub use proofs::{ReceiveProofInputs, ReceiveProofSources};
mod signed;
pub use signed::ReceiveSignedObjects;
mod stage;
pub use stage::{ReceiveStageInputs, ReceiveStagePlan, ReceiveStageWitness};

#[cfg(test)]
mod tests;

// Active tapes separately constrain each individual length to its fixed capacity.
// Their UInt32 lengths make this UInt33 sum exact, including cap+1; this shared
// component is exercised for every boundary split without duplicating raw tapes.
pub(super) fn joint_length_valid(
    uint: &mut UintChip<'_, Fp>,
    region: &mut Region<'_, Fp>,
    omega: &Uint<Fp, 32>,
    sigma: &Uint<Fp, 32>,
) -> Result<Bit<Fp>, Error> {
    let length = uint.glue().add(region, omega.word(), sigma.word())?;
    let length = uint.range_check::<33>(region, &length)?;
    let limit = uint.constant::<33>(region, (MAX_OMEGA_RAW_BYTES + 1) as u128)?;
    uint.lt(region, &length, &limit)
}

/// Wire section4 joint raw Omega-transport and sigma budget: `10,000 - 1,723`.
///
/// This is an envelope bound, not an admitted proof length. Exact lengths still
/// come from the frozen verifier descriptors and participate in the soft check.
pub const PAYMENT_PROOF_BUDGET: usize = 8_277;
/// Largest incoming Omega raw tape, including its 320-byte public transcript.
/// The other proof may be empty on the total malformed-input path.
pub const MAX_OMEGA_RAW_BYTES: usize = PAYMENT_PROOF_BUDGET + 320;
/// Largest incoming sigma raw tape when the other proof is empty.
pub const MAX_SIGMA_RAW_BYTES: usize = PAYMENT_PROOF_BUDGET;

/// Fixed signed Request, retained payer credential, Send receipt and Payment tape.
#[derive(Clone, Copy)]
pub struct ReceiveObjectSources<'a> {
    /// Original Request body and raw signature.
    pub request: &'a [Value<u8>],
    /// Payer credential retained from the Offer, including its signature.
    pub payer: &'a [Value<u8>],
    /// Exact Send receipt body and signature.
    pub receipt: &'a [Value<u8>],
    /// Original 163-byte transitive Payment transcript.
    pub payment: &'a [Value<u8>],
}

/// Actual constrained inputs retained by the same split context.
#[derive(Clone, Copy)]
pub struct ReceiveObjectInputs<'a> {
    /// Own hard Receive/ReceiveRenewed statement.
    pub own: &'a StatementCells,
    /// Current receiver prefix authenticated by its hard predecessor.
    pub receiver: &'a LineagePublicCells,
    /// Original active incoming Omega and its total decoders.
    pub incoming: &'a IncomingTransportCells,
    /// Original active Send sigma and exact original statement.
    pub sigma: &'a SigmaBindingCells,
    /// Combined consuming digest claimed by the same context. The mandatory
    /// `ProofDigest` owner derives it from both exact original active tapes.
    pub consuming_digest: &'a Word<Fp>,
}

/// Opaque Objects predicate derived from exact tapes and their consumer bindings.
#[must_use = "bind the derived result and these exact objects to the fixed stage context"]
#[derive(Clone, Debug)]
pub struct ReceiveObjects {
    signed: ReceiveSignedObjects,
    payment: IncomingPaymentCells,
    context: [ContextObjectCells; 6],
    specs: [ContextObjectSpec; 6],
    own: [Word<Fp>; 26],
    receiver: [Word<Fp>; 18],
    incoming: [Word<Fp>; 18],
    incoming_valid: Bit<Fp>,
    sigma: SigmaBindingCells,
    valid: Bit<Fp>,
}

impl ReceiveObjects {
    /// Fixed prefix of the full Receive context's object schema.
    /// Tags1..6 are Request, payer credential, Send receipt, Payment, raw Omega,
    /// raw sigma. Additional own/quoted-credential authorization objects follow.
    /// # Errors
    /// Zero/overflowing active capacities or impossible fixed schema lengths.
    pub fn context_specs(
        omega_capacity: usize,
        sigma_capacity: usize,
    ) -> Result<[ContextObjectSpec; 6], Error> {
        if omega_capacity == 0 || sigma_capacity == 0 {
            return Err(Error::Synthesis);
        }
        let capacities = [
            ObjectKind::Request.body_len() + 64,
            ObjectKind::Credential.body_len() + 64,
            ObjectKind::Receipt.body_len() + 64,
            PaymentCells::BYTES,
            omega_capacity,
            sigma_capacity,
        ];
        capacities
            .into_iter()
            .enumerate()
            .map(|(i, capacity)| {
                Ok(ContextObjectSpec {
                    tag: u32::try_from(i + 1).map_err(|_| Error::BoundsFailure)?,
                    capacity: u32::try_from(capacity).map_err(|_| Error::BoundsFailure)?,
                })
            })
            .collect::<Result<Vec<_>, Error>>()?
            .try_into()
            .map_err(|_| Error::Synthesis)
    }

    /// Decode objects against the context's separately hard-derived proof digest.
    ///
    /// Both proofs must have active original provenance: safe fixed buffers are
    /// rejected by construction. Original malformed fields return false; the
    /// deterministic Send selector is hard-bound to the sigma binding, so a
    /// prover cannot choose another key merely to manufacture a false verdict.
    /// The two active lengths also enforce the wire's fixed Payment overhead
    /// and 10,000-byte joint bound. This fixed-field G1 transcript component
    /// does not validate an external Norito envelope.
    /// # Errors
    /// Wrong fixed schema, absent active provenance, non-Receive own statement,
    /// inconsistent computed selector or layout failure.
    pub fn decode(
        chip: &mut VerifierChip<Ep>,
        bytes: &mut BytesChip<Fp>,
        region: &mut Region<'_, Fp>,
        policy: OwnPolicy,
        source: ReceiveObjectSources<'_>,
        input: ReceiveObjectInputs<'_>,
    ) -> Result<Self, Error> {
        if !matches!(
            input.own.variant(),
            Variant::Receive | Variant::ReceiveRenewed
        ) {
            return Err(Error::Synthesis);
        }
        let omega = input.incoming.active_carrier()?;
        let sigma = input.sigma.active_carrier()?;
        let specs = Self::context_specs(omega.run().len(), sigma.run().len())?;
        let proof_digest = input.consuming_digest.clone();
        let signed = ReceiveSignedObjects::decode(
            chip,
            bytes,
            region,
            [source.request, source.payer, source.receipt],
        )?;
        let objects = &signed.objects;
        let mut context = signed.context.to_vec();
        let provider = policy.provider(chip, region)?;
        let run = bytes.run(
            region,
            source.payment,
            &PaymentCells::primary_segments(),
            &PaymentCells::secondary_segments(),
        )?;
        let lanes = chip.operation_lanes()?;
        let mut uint = UintChip::new(lanes.glue, lanes.range);
        let request = RequestCells::check(&mut uint, lanes.hash, region, &objects[0])?;
        let payer = CredentialCells::check(&mut uint, region, &objects[1])?;
        let payment = IncomingPaymentCells::from_run(
            &mut uint,
            lanes.hash,
            region,
            &run,
            &PaymentInputs {
                request: &request,
                payer: &payer,
                statement: input.sigma.incoming_statement()?,
                receipt: &objects[2],
                provider: &provider,
                proof_digest: &proof_digest,
            },
            input.incoming.public(),
            input.receiver,
        )?;
        GlueChip::assert_equal(region, input.sigma.key_index(), payment.sigma_index())?;
        let own = input.own.fields();
        let mut checks = vec![payment.payment().valid().clone()];
        // Wire section4: |Omega transport| + |sigma| <= 10,000 - 1,723.
        // The active Omega source additionally contains its 320-byte public
        // transcript. UInt32 sources make the sum an exact 33-bit integer.
        checks.push(joint_length_valid(
            &mut uint,
            region,
            omega.length(),
            sigma.length(),
        )?);
        // Own effect inputs are deterministic projections of the exact
        // Request. A prover cannot change them to manufacture a false Objects
        // verdict for an otherwise valid fixed Payment. Scope/relation are
        // likewise anchored by the authenticated current receiver.
        for (a, b) in [
            (&own[1..3], &input.receiver.fields()[3..5]),
            (&own[3..5], &input.receiver.fields()[1..3]),
            (&own[18..20], request.object().identifier(3)?.as_slice()),
        ] {
            for (a, b) in a.iter().zip(b) {
                GlueChip::assert_equal(region, a, b)?;
            }
        }
        for (a, b) in [
            (&own[17], request.credit_id()),
            (&own[20], request.object().word(9)?),
        ] {
            GlueChip::assert_equal(region, a, b)?;
        }
        // An original wrong-asset Payment remains a total soft failure. Own
        // asset/wallet are independently hard-bound to authenticated state.
        checks.push(equal(
            uint.glue(),
            region,
            &own[5..7],
            request.object().identifier(2)?,
        )?);
        let valid = all(uint.glue(), region, &checks)?;
        context.push(ContextObjectCells::from_exact_run(
            chip,
            region,
            specs[3],
            payment.payment().digest(),
            &run,
        )?);
        context.push(ContextObjectCells::from_active(
            chip,
            region,
            specs[4],
            &proof_digest,
            omega,
        )?);
        context.push(ContextObjectCells::from_active(
            chip,
            region,
            specs[5],
            input.sigma.step_digest()?,
            sigma,
        )?);
        Ok(Self {
            signed,
            payment,
            context: context.try_into().map_err(|_| Error::Synthesis)?,
            specs,
            own: own.clone(),
            receiver: input.receiver.fields().clone(),
            incoming: input.incoming.public().fields().clone(),
            incoming_valid: input.incoming.public().valid().clone(),
            sigma: input.sigma.clone(),
            valid,
        })
    }

    // Native witness evaluation reads the same derived predicate. It cannot
    // create a result proof or bypass the actual fixed owner's context binding.
    pub(crate) const fn native_predicate(&self) -> &Bit<Fp> {
        &self.valid
    }

    /// The exact six context objects that must prefix every stage's context.
    pub const fn context(&self) -> &[ContextObjectCells; 6] {
        &self.context
    }
    /// Parsed Request, payer credential and Send receipt, for exact signature links.
    pub const fn objects(&self) -> &[SignedObjectCells; 3] {
        &self.signed.objects
    }
    /// Reuse the already parsed signed sources when tasks share one stage.
    pub const fn signed_sources(&self) -> &ReceiveSignedObjects {
        &self.signed
    }
    /// Original Payment/package digest and total consumer binding.
    pub const fn payment(&self) -> &IncomingPaymentCells {
        &self.payment
    }

    /// Bind the privately derived result only at its fixed owner and exact context.
    ///
    /// This copy-binds all consumed fields/tapes and incoming Q exports before
    /// equating the proposed Objects bit. Q verification may occur in another
    /// fixed stage, but its identical instances are committed here. No arbitrary
    /// witness bit can be passed as the derived result.
    /// # Errors
    /// Wrong owner/schema, missing context input or layout failure. Any spliced
    /// tape, header, statement, selector, proof chunk or result is unsatisfiable.
    pub fn bind_result(
        &self,
        chip: &mut VerifierChip<Ep>,
        region: &mut Region<'_, Fp>,
        plan: &ContextPlan,
        stage: u32,
        input: &ContextInputs<'_>,
    ) -> Result<(), Error> {
        let valid = self.derive_objects(chip, region, plan, input)?;
        input.receive_results.ok_or(Error::Synthesis)?.bind_derived(
            region,
            plan.receive_results().ok_or(Error::Synthesis)?,
            stage,
            ReceiveResultTag::Objects,
            &valid,
        )
    }

    // Native preparation consumes the same private Objects predicate. The complete
    // fixed owning stage still binds this bit and proves all of its original sources.
    pub(crate) fn derive_objects(
        &self,
        chip: &mut VerifierChip<Ep>,
        region: &mut Region<'_, Fp>,
        plan: &ContextPlan,
        input: &ContextInputs<'_>,
    ) -> Result<Bit<Fp>, Error> {
        self.bind_context_inputs(chip, region, plan, input)?;
        Ok(self.valid.clone())
    }

    fn bind_context_inputs(
        &self,
        chip: &mut VerifierChip<Ep>,
        region: &mut Region<'_, Fp>,
        plan: &ContextPlan,
        input: &ContextInputs<'_>,
    ) -> Result<(), Error> {
        if input.objects.len() < 6
            || plan.object_specs().len() < 6
            || plan.object_specs()[..6] != self.specs
            || input.own_statement.variant() != plan.operation().frame().variant()
        {
            return Err(Error::Synthesis);
        }
        let incoming = input.incoming.ok_or(Error::Synthesis)?;
        let receiver = input.predecessor.ok_or(Error::Synthesis)?.public;
        let statement = input.incoming_statement.ok_or(Error::Synthesis)?;
        for (a, b) in self
            .own
            .iter()
            .zip(input.own_statement.fields())
            .chain(self.receiver.iter().zip(receiver.fields()))
            .chain(self.incoming.iter().zip(incoming.public.fields()))
            .chain(
                self.sigma
                    .incoming_statement()?
                    .fields()
                    .iter()
                    .zip(statement.fields()),
            )
        {
            GlueChip::assert_equal(region, a, b)?;
        }
        GlueChip::assert_equal(
            region,
            self.incoming_valid.word(),
            incoming.public.valid().word(),
        )?;
        for (a, b) in self.context.iter().zip(input.objects) {
            for (a, b) in a.commitment_words().iter().zip(b.commitment_words()) {
                GlueChip::assert_equal(region, a, &b)?;
            }
        }
        let instances = input.q_instances.first().ok_or(Error::Synthesis)?;
        let sigma_plan = &plan.operation().sigma;
        if sigma_plan.slot_count() != 2
            || instances.len() != 5
            || instances
                .iter()
                .zip(sigma_plan.instance_lengths())
                .any(|(c, n)| c.len() != n)
        {
            return Err(Error::Synthesis);
        }
        for (actual, expected) in [
            (&instances[0][1], self.sigma.statement().digest()),
            (&instances[2][1], self.sigma.key_index()),
        ] {
            let actual = bounded_word(chip, region, actual)?;
            GlueChip::assert_equal(region, &actual, expected)?;
        }
        let chunks = sigma_plan.chunk_range(1).ok_or(Error::Synthesis)?;
        if chunks.len() != self.sigma.proof_chunks().len() {
            return Err(Error::Synthesis);
        }
        for (index, expected) in chunks.zip(self.sigma.proof_chunks()) {
            let actual = bounded_word(chip, region, &instances[0][index])?;
            GlueChip::assert_equal(region, &actual, expected)?;
        }
        Ok(())
    }
}
