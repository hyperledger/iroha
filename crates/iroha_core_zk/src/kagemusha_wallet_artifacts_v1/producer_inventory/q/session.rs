//! Complete Q qualification with private exact-signature-source reuse.

use super::*;

/// Observation of one Q program's complete qualification; never authority.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum QQualificationProgressV1 {
    /// Source qualification is beginning for this signed program index.
    Started {
        /// Zero-based signed operation-program index.
        program_index: u32,
    },
    /// Every Q source and original of this program qualified successfully.
    Completed {
        /// Zero-based signed operation-program index.
        program_index: u32,
    },
}

// One immutable owner set is borrowed for the whole batch. No entry can be
// supplied by a caller, loaded from disk, or carried into another installation.
struct QualificationInputs<'a> {
    inventory: &'a AuthenticatedProducerInventoryV1,
    installed: &'a InstalledVerifierPackV1,
    sigmas: &'a QualifiedSigmasV1,
    config: ReadConfig,
}

fn require_installation_identities(
    installed: ([u8; 32], [u8; 32]),
    inventory: ([u8; 32], [u8; 32]),
    sigmas: ([u8; 32], [u8; 32]),
) -> Result<(), Error> {
    if installed != inventory || installed != sigmas {
        return Err(Error::Authority);
    }
    Ok(())
}

impl QualificationInputs<'_> {
    fn identity(&self) -> Result<([u8; 32], [u8; 32]), Error> {
        let identity = (
            self.installed.verifier().scheme().scheme_id(),
            self.installed.verifier().manifest_digest(),
        );
        require_installation_identities(
            identity,
            self.inventory.installation(),
            self.sigmas.installation(),
        )?;
        Ok(identity)
    }

    fn pallas(&self) -> &PinnedParams<Ep> {
        self.installed.verifier().pallas_parameters().as_ref()
    }
}

#[cfg(test)]
#[path = "session/tests.rs"]
mod tests;

#[cfg(test)]
pub(crate) use tests::{assert_builtin_signature_reuse_controls, assert_signature_reuse_controls};

// Qualified origin is opaque. Production constructs this only from the typed
// strict or compiled-member importer, never from signed metadata alone.
struct AdmittedSignature {
    installation: ([u8; 32], [u8; 32]),
    member: u32,
    original: OriginalV1,
    plan: QSignaturePlan,
    key: KeyArtifact<Ep>,
    seal: InstalledSourceSealV1<Ep>,
}
impl AdmittedSignature {
    fn import(
        inputs: &QualificationInputs<'_>,
        member: u32,
        plan: QSignaturePlan,
        originals: &mut dyn OriginalSourceV1,
        compiled: Option<iroha_plonk::keys::BuiltinSourceMemberV1>,
    ) -> Result<Self, QQualificationErrorV1> {
        let installation = inputs.identity()?;
        let original = *inputs.inventory.inventory.member(member)?;
        let bytes =
            inputs
                .inventory
                .read_original(member, originals, inputs.config.maximum_bytes)?;
        let native = match compiled {
            Some(compiled) => QSignatureProver::from_builtin_original_artifact_cancellable(
                plan,
                inputs.pallas().clone(),
                &bytes.descriptor,
                &bytes.verifying_key,
                &bytes.proving_key,
                inputs.config,
                compiled,
                None,
            )?,
            None => QSignatureProver::from_original_artifact_cancellable(
                plan,
                inputs.pallas().clone(),
                &bytes.descriptor,
                &bytes.verifying_key,
                &bytes.proving_key,
                inputs.config,
                None,
            )?,
        };
        let plan = native.plan().clone();
        let (binding, key, seal) = native.into_metadata().into_parts();
        Ok(Self {
            installation,
            member,
            original,
            plan,
            key: KeyArtifact::new(binding, key)?,
            seal: InstalledSourceSealV1::new(member, seal),
        })
    }

    fn metadata(&self) -> (KeyArtifact<Ep>, InstalledSourceSealV1<Ep>) {
        (self.key.clone(), self.seal.clone())
    }

    #[cfg(test)]
    fn revalidate(
        &self,
        inputs: &QualificationInputs<'_>,
        member: u32,
        plan: &QSignaturePlan,
        originals: &mut dyn OriginalSourceV1,
    ) -> Result<(KeyArtifact<Ep>, InstalledSourceSealV1<Ep>), QQualificationErrorV1> {
        self.revalidate_with_member(inputs, member, plan, originals, None)
    }

    fn revalidate_with_member(
        &self,
        inputs: &QualificationInputs<'_>,
        member: u32,
        plan: &QSignaturePlan,
        originals: &mut dyn OriginalSourceV1,
        compiled: Option<iroha_plonk::keys::BuiltinSourceMemberV1>,
    ) -> Result<(KeyArtifact<Ep>, InstalledSourceSealV1<Ep>), QQualificationErrorV1> {
        if inputs.identity()? != self.installation {
            return Err(Error::Authority.into());
        }
        // slots() includes order, hard/soft modes, variable/fixed treatment and
        // every exact fixed P-256 key. QSignaturePlan::new deterministically
        // derives its only other field, fixed_keys, from those slots.
        if member != self.member
            || plan.slots() != self.plan.slots()
            || inputs.inventory.inventory.member(member)? != &self.original
        {
            return Err(QQualificationErrorV1::Source);
        }
        let view = self.seal.bind(member, &self.key, None)?;
        let native = QSignatureProverView::from_source_bound(plan, inputs.pallas(), view)?;
        if native.binding().n() > inputs.config.maximum_rows
            || inputs.config.maximum_bytes == 0
            || inputs.config.maximum_bytes > PROVING_KEY_MAX_BYTES_V1
        {
            return Err(Error::Inventory.into());
        }
        // All role bounds precede any open; no earlier larger limit is inherited.
        self.original.descriptor.length(DESCRIPTOR_MAX_BYTES_V1)?;
        self.original
            .verifying_key
            .length(VERIFYING_KEY_MAX_BYTES_V1)?;
        self.original
            .proving_key
            .length(inputs.config.maximum_bytes)?;
        match compiled {
            Some(compiled) => {
                let bytes = inputs.inventory.read_original(
                    member,
                    originals,
                    inputs.config.maximum_bytes,
                )?;
                super::super::builtin::require_member_source(
                    compiled,
                    &bytes,
                    inputs.pallas(),
                    inputs.config,
                    self.seal.bind(member, &self.key, None)?,
                    self.seal.seal(member)?,
                )?;
            }
            None => inputs.inventory.revalidate_original_cancellable(
                member,
                originals,
                inputs.config.maximum_bytes,
                None,
            )?,
        }
        Ok(self.metadata())
    }
}

// The only owner lives on one batch's stack. Entries have an exact qualified
// origin; QSigma is intentionally outside this type and never reused here.
#[derive(Default)]
struct SignatureAdmissions {
    entries: Vec<AdmittedSignature>,
}
impl SignatureAdmissions {
    #[cfg(test)]
    fn qualify(
        &mut self,
        inputs: &QualificationInputs<'_>,
        member: u32,
        plan: &QSignaturePlan,
        originals: &mut dyn OriginalSourceV1,
    ) -> Result<(KeyArtifact<Ep>, InstalledSourceSealV1<Ep>), QQualificationErrorV1> {
        self.qualify_with_member(inputs, member, plan, originals, None)
    }

    fn qualify_with_member(
        &mut self,
        inputs: &QualificationInputs<'_>,
        member: u32,
        plan: &QSignaturePlan,
        originals: &mut dyn OriginalSourceV1,
        compiled: Option<iroha_plonk::keys::BuiltinSourceMemberV1>,
    ) -> Result<(KeyArtifact<Ep>, InstalledSourceSealV1<Ep>), QQualificationErrorV1> {
        if let Some(admitted) = self.entries.iter().find(|entry| entry.member == member) {
            return admitted.revalidate_with_member(inputs, member, plan, originals, compiled);
        }
        let admitted =
            AdmittedSignature::import(inputs, member, plan.clone(), originals, compiled)?;
        let result = admitted.metadata();
        self.entries.push(admitted);
        Ok(result)
    }
}

impl AuthenticatedProducerInventoryV1 {
    /// Strictly qualify every Q program using one immutable installation and sigma owner.
    ///
    /// Only exact signature sources admitted within this call may be reused. Each
    /// hit checks the same ordered slots, original member, current profile/limits
    /// and all three signed originals before returning its private source seal.
    /// Every `QSigma` source is strictly imported independently. Program identities
    /// remain distinct, and complete A/W/context/Omega qualification remains required.
    /// Original-reader cancellation has the standalone qualifier's semantics and
    /// returns no partial vector or success event for the interrupted program.
    /// # Errors
    /// Another installation, invalid recipe/profile, changed/unavailable original,
    /// cancellation, resource-bound violation or any strict native import refusal.
    pub fn qualify_q_programs(
        &self,
        installed: &InstalledVerifierPackV1,
        sigmas: &QualifiedSigmasV1,
        originals: &mut dyn OriginalSourceV1,
        config: ReadConfig,
        observer: impl FnMut(QQualificationProgressV1),
    ) -> Result<Vec<QualifiedQProgramV1>, QQualificationErrorV1> {
        self.qualify_q_programs_with_admission(
            installed,
            sigmas,
            originals,
            config,
            observer,
            super::super::builtin::Admission::Strict,
        )
    }

    // Only the complete built-in profile owner selects the compiled mode.
    pub(in super::super) fn qualify_q_programs_with_admission(
        &self,
        installed: &InstalledVerifierPackV1,
        sigmas: &QualifiedSigmasV1,
        originals: &mut dyn OriginalSourceV1,
        config: ReadConfig,
        mut observer: impl FnMut(QQualificationProgressV1),
        admission: super::super::builtin::Admission<'_>,
    ) -> Result<Vec<QualifiedQProgramV1>, QQualificationErrorV1> {
        let inputs = QualificationInputs {
            inventory: self,
            installed,
            sigmas,
            config,
        };
        let identity = inputs.identity()?;
        let mut signatures_admitted = SignatureAdmissions::default();
        let mut programs = Vec::with_capacity(self.inventory.operations.len());
        for (program, record) in self.inventory.operations.iter().enumerate() {
            let program_index = u32::try_from(program).map_err(|_| Error::Inventory)?;
            observer(QQualificationProgressV1::Started { program_index });
            let (source, signatures) = source(
                record,
                installed.verifier().scheme(),
                sigmas.metadata(),
                &|k| Ok(installed.verifier().vesta_parameters(k)?.as_ref().clone()),
            )?;
            let mut keys = Vec::with_capacity(record.q.len());
            let mut seals = Vec::with_capacity(record.q.len());
            for (index, member) in record.q.iter().copied().enumerate() {
                let compiled = admission.member(&[
                    2,
                    program_index,
                    u32::try_from(index).map_err(|_| Error::Inventory)?,
                ])?;
                let offset = usize::from(source.is_some());
                let (key, seal) = if index < offset {
                    // Every QSigma still passes its typed serialized-foreign,
                    // two-range-bus importer; only the admission origin differs.
                    let bytes = self.read_original(member, originals, config.maximum_bytes)?;
                    let metadata = import_with_admission(
                        index,
                        source.as_ref(),
                        &signatures,
                        &bytes,
                        inputs.pallas(),
                        config,
                        compiled,
                        None,
                    )?
                    .into_metadata();
                    let (binding, key, seal) = metadata.into_parts();
                    (
                        KeyArtifact::new(binding, key)?,
                        InstalledSourceSealV1::new(member, seal),
                    )
                } else {
                    let plan = signatures.get(index - offset).ok_or(Error::Inventory)?;
                    signatures_admitted
                        .qualify_with_member(&inputs, member, plan, originals, compiled)?
                };
                keys.push(key);
                seals.push(seal);
            }
            let qualified = QualifiedQProgramV1 {
                program: program_index,
                installation: identity,
                recipe: QProgramRecipeV1::from_metadata(
                    source.as_ref().map(|source| source.plan().clone()),
                    signatures,
                    keys,
                )?,
                seals: seals.into_boxed_slice(),
            };
            observer(QQualificationProgressV1::Completed { program_index });
            programs.push(qualified);
        }
        Ok(programs)
    }
}
