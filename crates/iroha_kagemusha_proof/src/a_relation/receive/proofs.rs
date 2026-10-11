//! Same-original-source recursive verdict and incoming opening export.

use iroha_pasta::{Ep, Fp};
use iroha_plonk::frontend::{Error, Region};
use iroha_plonk_gadgets::{Bit, GlueChip};
use iroha_plonk_recursion::verifier::{VerifierChip, VerifierKeyCells};

use crate::operation_relation::incoming_statement::StatementView;

use crate::a_relation::{
    SigmaBindingCells, bind_sigma, bounded_word,
    context::{ContextIncomingProof, ContextInputs, ContextObjectCells, ContextPlan},
    incoming_transport::IncomingTransportCells,
    results::ReceiveResultTag,
    split::{bind_claim, bind_mode, bind_statements},
};

/// Exact trusted key and own sigma source needed by the Receive Proofs owner.
#[derive(Clone, Copy)]
pub struct ReceiveProofInputs<'a> {
    /// Original active Omega and the exact incoming sigma Q projection.
    pub sources: &'a ReceiveProofSources,
    /// Witness key whose digest is hard-bound to the carried normal Omega key.
    pub omega_key: &'a VerifierKeyCells<Ep>,
    /// Own hard sigma binding, in addition to the retained original incoming sigma.
    pub own_sigma: &'a SigmaBindingCells,
}

/// Same-source total Omega view and incoming sigma Q binding. The fixed Objects
/// owner authenticates the original sigma tape, including its original LE32
/// length and every descriptor-sized chunk, against the same Q0 instances.
/// This owner reuses that hard context binding instead of allocating and hashing
/// a second maximum-capacity sigma tape. `ProofDigest` separately derives the
/// combined consuming digest; all fixed owners remain mandatory on false results.
#[derive(Clone, Debug)]
pub struct ReceiveProofSources {
    transport: IncomingTransportCells,
    sigma: SigmaBindingCells,
}

impl ReceiveProofSources {
    /// Retain an original active Omega and the incoming sigma's Q-bound view.
    ///
    /// Sigma may be a field/chunk projection: `bind_context` hard-binds its
    /// statement, selector and every original-length-prefixed chunk to Q0.
    /// The required Objects owner independently binds those same Q0 cells to
    /// its original active sigma bytes, even when Objects derives false.
    /// # Errors
    /// A fixed padded Omega view or non-incoming sigma is rejected.
    pub fn from_active_omega(
        transport: &IncomingTransportCells,
        sigma: &SigmaBindingCells,
    ) -> Result<Self, Error> {
        transport.active_carrier()?;
        sigma.incoming_statement()?;
        Ok(Self {
            transport: transport.clone(),
            sigma: sigma.clone(),
        })
    }

    pub(super) fn bind_context(
        &self,
        chip: &mut VerifierChip<Ep>,
        region: &mut Region<'_, Fp>,
        plan: &ContextPlan,
        input: &ContextInputs<'_>,
    ) -> Result<(), Error> {
        if input.objects.len() != 11 || plan.object_specs().len() != 11 {
            return Err(Error::Synthesis);
        }
        let incoming = input.incoming.ok_or(Error::Synthesis)?;
        if !matches!(incoming.proof, ContextIncomingProof::ReceiveActive) {
            return Err(Error::Synthesis);
        }
        for (a, b) in self
            .transport
            .public()
            .fields()
            .iter()
            .zip(incoming.public.fields())
            .chain(
                self.sigma
                    .incoming_statement()?
                    .fields()
                    .iter()
                    .zip(input.incoming_statement.ok_or(Error::Synthesis)?.fields()),
            )
        {
            GlueChip::assert_equal(region, a, b)?;
        }
        GlueChip::assert_equal(
            region,
            self.transport.public().valid().word(),
            incoming.public.valid().word(),
        )?;
        // ProofDigest derives the combined consuming digest. This owner
        // authenticates the original Omega tape and exact active length; the
        // sigma's raw source is hard-bound by Objects to the identical Q0 below.
        let actual = ContextObjectCells::from_active(
            chip,
            region,
            plan.object_specs()[4],
            input.objects[4].authenticated_digest(),
            self.transport.active_carrier()?,
        )?;
        for (a, b) in actual
            .commitment_words()
            .iter()
            .zip(input.objects[4].commitment_words())
        {
            GlueChip::assert_equal(region, a, &b)?;
        }
        let columns = input.q_instances.first().ok_or(Error::Synthesis)?;
        let sigma_plan = &plan.operation().sigma;
        if columns.len() != 5
            || sigma_plan.slot_count() != 2
            || columns
                .iter()
                .zip(sigma_plan.instance_lengths())
                .any(|(c, n)| c.len() != n)
        {
            return Err(Error::Synthesis);
        }
        for (actual, expected) in [
            (&columns[0][1], self.sigma.statement().digest()),
            (&columns[2][1], self.sigma.key_index()),
        ] {
            let actual = bounded_word(chip, region, actual)?;
            GlueChip::assert_equal(region, &actual, expected)?;
        }
        let chunks = sigma_plan.chunk_range(1).ok_or(Error::Synthesis)?;
        if chunks.len() != self.sigma.proof_chunks().len() {
            return Err(Error::Synthesis);
        }
        for (index, expected) in chunks.zip(self.sigma.proof_chunks()) {
            let actual = bounded_word(chip, region, &columns[0][index])?;
            GlueChip::assert_equal(region, &actual, expected)?;
        }
        Ok(())
    }
    /// Derive both actual recursive verdicts and bind the original Omega opening.
    ///
    /// The incoming key/digest/class and sigma verifier inputs are hard-bound,
    /// while original malformed bytes and verifier failures remain soft. All
    /// cells of the actual total verifier opening, including its fixed valid
    /// dummy on failure, equal the context export regardless of the verdict.
    /// The corresponding Q must still be hard-verified exactly once by its
    /// fixed stage; this method does not remove any deferred obligation.
    ///
    /// # Errors
    /// Wrong owner/schema, missing active source/export or layout failure.
    /// Spliced bytes/claims/keys and freely chosen false verifier inputs fail hard.
    pub fn constrain_proofs(
        &self,
        chip: &mut VerifierChip<Ep>,
        region: &mut Region<'_, Fp>,
        plan: &ContextPlan,
        stage: u32,
        input: &ContextInputs<'_>,
        proof: ReceiveProofInputs<'_>,
    ) -> Result<(), Error> {
        let (valid, omega) = self.derive_proofs(chip, region, plan, stage, input, proof)?;
        let claims = input.receive_results.ok_or(Error::Synthesis)?;
        bind_claim(region, claims.opening()?, &omega.opening)?;
        claims.bind_derived(
            region,
            plan.receive_results().ok_or(Error::Synthesis)?,
            stage,
            ReceiveResultTag::Proofs,
            &valid,
        )
    }

    // Extract the same complete total-verifier result and original opening for native
    // witness preparation. No proposed opening or boolean supplies the result.
    pub(crate) fn derive_proofs(
        &self,
        chip: &mut VerifierChip<Ep>,
        region: &mut Region<'_, Fp>,
        plan: &ContextPlan,
        stage: u32,
        input: &ContextInputs<'_>,
        proof: ReceiveProofInputs<'_>,
    ) -> Result<(Bit<Fp>, crate::a_relation::IncomingOmegaCells), Error> {
        let result_plan = plan.receive_results().ok_or(Error::Synthesis)?;
        if stage != result_plan.owner(ReceiveResultTag::Proofs) {
            return Err(Error::Synthesis);
        }
        self.bind_context(chip, region, plan, input)?;
        let expected = input.incoming.ok_or(Error::Synthesis)?;
        bind_claim(region, expected.pallas, self.transport.pallas())?;
        for (a, b) in expected
            .vesta
            .words()
            .iter()
            .zip(self.transport.vesta().words())
        {
            GlueChip::assert_equal(region, a, &b)?;
        }
        // There is no separately assigned message proposal in this schema.
        // The actual verifier below consumes only this active tape's checked
        // decoder; bind_context authenticates its exact original commitment.
        let omega = self.transport.verify(
            chip,
            region,
            plan.operation(),
            proof.omega_key,
            input.successor.public.omega_key_digest(),
        )?;
        let bindings = [proof.own_sigma.clone(), self.sigma.clone()];
        bind_statements(region, input, &bindings)?;
        let sigma = bind_sigma(
            chip,
            region,
            &plan.operation().sigma,
            input.q_instances.first().ok_or(Error::Synthesis)?,
            &bindings,
        )?;
        bind_mode(
            region,
            sigma.incoming_mode.as_ref().ok_or(Error::Synthesis)?,
            input.modes.get(3).ok_or(Error::Synthesis)?,
        )?;
        let valid = chip.uint().glue().and(
            region,
            &omega.valid,
            sigma.incoming_valid.as_ref().ok_or(Error::Synthesis)?,
        )?;
        Ok((valid, omega))
    }
}
