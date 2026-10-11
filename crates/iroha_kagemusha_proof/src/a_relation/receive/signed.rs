//! Original signed incoming objects, independent of the expensive proof-byte hash.

use iroha_pasta::{Ep, Fp};
use iroha_plonk::frontend::{Error, Region, Value};
use iroha_plonk_gadgets::{GlueChip, UintChip, bytes::tape::BytesChip};
use iroha_plonk_recursion::verifier::VerifierChip;

use crate::{
    a_relation::context::{ContextInputs, ContextObjectCells, ContextObjectSpec, ContextPlan},
    operation_relation::objects::{ObjectKind, SignedObjectCells},
};

/// Exact Request, payer credential and Send receipt tapes. Their semantic and
/// signature verdicts belong to separate fixed owners; this type only derives
/// canonical total views and content commitments from the original bytes.
#[derive(Clone, Debug)]
pub struct ReceiveSignedObjects {
    pub(super) objects: [SignedObjectCells; 3],
    pub(super) context: [ContextObjectCells; 3],
}
impl ReceiveSignedObjects {
    /// Decode the original three signed tapes without decoding either proof.
    /// # Errors
    /// Wrong fixed body/signature sizes or layout failure. Malformed payloads
    /// retain their structural false bit and original content digest.
    pub fn decode(
        chip: &mut VerifierChip<Ep>,
        bytes: &mut BytesChip<Fp>,
        region: &mut Region<'_, Fp>,
        sources: [&[Value<u8>]; 3],
    ) -> Result<Self, Error> {
        let mut objects = Vec::new();
        let mut context = Vec::new();
        for (i, (kind, source)) in [
            ObjectKind::Request,
            ObjectKind::Credential,
            ObjectKind::Receipt,
        ]
        .into_iter()
        .zip(sources)
        .enumerate()
        {
            let run = bytes.run(
                region,
                source,
                &kind.primary_segments(),
                &kind.secondary_segments(),
            )?;
            let lanes = chip.operation_lanes()?;
            let object = SignedObjectCells::decode_soft(
                &mut UintChip::new(lanes.glue, lanes.range),
                lanes.hash,
                region,
                kind,
                &run,
            )?
            .0;
            context.push(ContextObjectCells::from_exact_run(
                chip,
                region,
                ContextObjectSpec {
                    tag: u32::try_from(i + 1).map_err(|_| Error::BoundsFailure)?,
                    capacity: u32::try_from(kind.body_len() + 64)
                        .map_err(|_| Error::BoundsFailure)?,
                },
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

    pub(super) fn bind_context(
        &self,
        region: &mut Region<'_, Fp>,
        plan: &ContextPlan,
        input: &ContextInputs<'_>,
    ) -> Result<(), Error> {
        if plan.receive_results().is_none()
            || input.objects.len() != plan.object_specs().len()
            || input.objects.len() != 11
        {
            return Err(Error::Synthesis);
        }
        for (i, actual) in self.context.iter().enumerate() {
            let kind = self.objects[i].kind();
            if plan.object_specs()[i]
                != (ContextObjectSpec {
                    tag: u32::try_from(i + 1).map_err(|_| Error::BoundsFailure)?,
                    capacity: u32::try_from(kind.body_len() + 64)
                        .map_err(|_| Error::BoundsFailure)?,
                })
            {
                return Err(Error::Synthesis);
            }
            for (a, b) in actual
                .commitment_words()
                .iter()
                .zip(input.objects[i].commitment_words())
            {
                GlueChip::assert_equal(region, a, &b)?;
            }
        }
        Ok(())
    }
}
