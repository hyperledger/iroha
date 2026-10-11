//! Archive's exact incoming proof source, total verifier and original opening.

use iroha_pasta::{Ep, Fp};
use iroha_plonk::frontend::{Error, Region};
use iroha_plonk_gadgets::{Bit, GlueChip, UintChip};
use iroha_plonk_recursion::{
    accumulation_circuit::FoldInputCells,
    obligation::ledger::Variant,
    verifier::{VerifierChip, VerifierKeyCells},
};

use super::{
    require_task,
    results::{ArchiveResultClaims, ArchiveResultTag},
};
use crate::{
    a_relation::{
        SigmaBindingCells, bind_sigma,
        context::{ContextIncomingProof, ContextInputs, ContextObjectCells, ContextPlan},
        incoming_transport::IncomingTransportCells,
        split::{bind_claim, bind_mode, bind_proof, bind_statements},
    },
    operation_relation::incoming_statement::StatementView,
};

#[derive(Clone, Debug)]
enum Source {
    Receive(Box<SigmaBindingCells>),
    Status(Box<IncomingTransportCells>),
}

/// Original active incoming sigma or Status Omega, never a fixed padded carrier.
#[derive(Clone, Debug)]
pub struct ArchiveProofSources {
    source: Source,
    raw_slot: usize,
}
/// Exact extra inputs selected by the circuit-fixed evidence kind.
#[derive(Clone, Copy)]
pub enum ArchiveProofInputs<'a> {
    /// Own hard sigma projection; the incoming slot is retained in the source.
    Receive(&'a SigmaBindingCells),
    /// Status Omega key, whose identity must equal the current lineage's key.
    Status(&'a VerifierKeyCells<Ep>),
}

/// Constrained original proof result used to prepare Archive's committed claims.
/// These cells do not replace the mandatory staged proof owner.
#[derive(Clone, Debug)]
pub(crate) struct ArchiveDerivedProofs {
    /// Complete total-verifier verdict, including original decoder results.
    pub valid: Bit<Fp>,
    /// Original Status verifier opening, retained even for a false verdict.
    pub opening: Option<FoldInputCells<Ep>>,
}
impl ArchiveProofSources {
    pub(super) fn require_context_slot(&self, index: usize) -> Result<(), Error> {
        if self.raw_slot != index {
            return Err(Error::Synthesis);
        }
        Ok(())
    }

    /// Retain the exact original Receive sigma and its fixed context object slot.
    /// The Evidence owner separately binds the Request-recorded sigma selector.
    /// # Errors
    /// Missing active provenance or a non-Receive incoming statement.
    pub fn receive(sigma: &SigmaBindingCells, raw_slot: usize) -> Result<Self, Error> {
        sigma.active_carrier()?;
        if !matches!(
            sigma.incoming_statement()?.variant(),
            Variant::Receive | Variant::ReceiveRenewed
        ) {
            return Err(Error::Synthesis);
        }
        Ok(Self {
            source: Source::Receive(Box::new(sigma.clone())),
            raw_slot,
        })
    }
    /// Retain the exact original Status Omega/public/claim bytes.
    /// # Errors
    /// Missing original active carrier provenance.
    pub fn status(transport: &IncomingTransportCells, raw_slot: usize) -> Result<Self, Error> {
        transport.active_carrier()?;
        Ok(Self {
            source: Source::Status(Box::new(transport.clone())),
            raw_slot,
        })
    }
    /// Derive the actual total proof result and bind every original input.
    ///
    /// Source digests use the sigma-only or exact lineage-byte domain. Both the
    /// declared raw length and every byte participate even when verification
    /// fails. Status exports its exact verifier opening unconditionally;
    /// Receive exports the same incoming sigma mode verified inside hard Q0.
    /// # Errors
    /// Wrong task/kind/schema, missing mode/source, spliced bytes/public/claims,
    /// foreign key identity or layout failure.
    #[allow(
        clippy::too_many_arguments,
        reason = "one owner binds the exact context, source and fixed result"
    )]
    pub fn constrain_proofs(
        &self,
        chip: &mut VerifierChip<Ep>,
        region: &mut Region<'_, Fp>,
        plan: &ContextPlan,
        stage: u32,
        input: &ContextInputs<'_>,
        claims: &ArchiveResultClaims,
        proof: ArchiveProofInputs<'_>,
    ) -> Result<(), Error> {
        require_task(
            plan,
            stage,
            crate::a_relation::schedule::OperationTask::ArchiveProofs,
        )?;
        claims.bind_context(region, plan, input)?;
        let derived = self.derive_proofs(chip, region, plan, input, proof)?;
        if let Some(opening) = &derived.opening {
            bind_claim(region, claims.opening()?, opening)?;
        }
        claims.bind_derived(
            region,
            plan,
            stage,
            input,
            ArchiveResultTag::Proofs,
            &derived.valid,
        )
    }

    // Native witness preparation evaluates the same source-bound constraints.
    // Only the fixed owner may authenticate the proposed result in a stage proof.
    pub(crate) fn derive_proofs(
        &self,
        chip: &mut VerifierChip<Ep>,
        region: &mut Region<'_, Fp>,
        plan: &ContextPlan,
        input: &ContextInputs<'_>,
        proof: ArchiveProofInputs<'_>,
    ) -> Result<ArchiveDerivedProofs, Error> {
        let spec = *plan
            .object_specs()
            .get(self.raw_slot)
            .ok_or(Error::Synthesis)?;
        let (context, valid, opening) = match (&self.source, proof) {
            (Source::Receive(sigma), ArchiveProofInputs::Receive(own)) => {
                if plan.operation().frame().variant() != Variant::ArchiveReceive {
                    return Err(Error::Synthesis);
                }
                let bound = [own.clone(), sigma.as_ref().clone()];
                bind_statements(region, input, &bound)?;
                let result = bind_sigma(
                    chip,
                    region,
                    &plan.operation().sigma,
                    input.q_instances.first().ok_or(Error::Synthesis)?,
                    &bound,
                )?;
                bind_mode(
                    region,
                    result.incoming_mode.as_ref().ok_or(Error::Synthesis)?,
                    input.modes.first().ok_or(Error::Synthesis)?,
                )?;
                let context = ContextObjectCells::from_active(
                    chip,
                    region,
                    spec,
                    sigma.step_digest()?,
                    sigma.active_carrier()?,
                )?;
                (
                    context,
                    result.incoming_valid.ok_or(Error::Synthesis)?,
                    None,
                )
            }
            (Source::Status(transport), ArchiveProofInputs::Status(key)) => {
                if plan.operation().frame().variant() != Variant::ArchiveStatus {
                    return Err(Error::Synthesis);
                }
                let expected = input.incoming.ok_or(Error::Synthesis)?;
                for (a, b) in transport
                    .public()
                    .fields()
                    .iter()
                    .zip(expected.public.fields())
                {
                    GlueChip::assert_equal(region, a, b)?;
                }
                GlueChip::assert_equal(
                    region,
                    transport.public().valid().word(),
                    expected.public.valid().word(),
                )?;
                bind_claim(region, expected.pallas, transport.pallas())?;
                for (a, b) in expected.vesta.words().iter().zip(transport.vesta().words()) {
                    GlueChip::assert_equal(region, a, &b)?;
                }
                let ContextIncomingProof::Messages(messages) = expected.proof else {
                    return Err(Error::Synthesis);
                };
                bind_proof(region, messages, transport.proof())?;
                let omega = transport.verify(
                    chip,
                    region,
                    plan.operation(),
                    key,
                    input.successor.public.omega_key_digest(),
                )?;
                let carrier = transport.active_carrier()?;
                let lanes = chip.operation_lanes()?;
                let digest = carrier.packed().digest(
                    &mut UintChip::new(lanes.glue, lanes.range),
                    lanes.hash.sponge_mut()?,
                    region,
                    u64::from_le_bytes(*b"kgwlin_1"),
                )?;
                let context =
                    ContextObjectCells::from_active(chip, region, spec, &digest, carrier)?;
                (context, omega.valid, Some(omega.opening))
            }
            _ => return Err(Error::Synthesis),
        };
        let expected = input.objects.get(self.raw_slot).ok_or(Error::Synthesis)?;
        for (a, b) in context
            .commitment_words()
            .iter()
            .zip(expected.commitment_words())
        {
            GlueChip::assert_equal(region, a, &b)?;
        }
        Ok(ArchiveDerivedProofs { valid, opening })
    }
}
