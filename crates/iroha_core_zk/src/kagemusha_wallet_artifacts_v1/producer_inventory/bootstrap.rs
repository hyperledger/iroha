//! Exact unsplit Bootstrap A source qualification under the imported Q source.

use iroha_kagemusha_proof::a_relation::{
    AProofPlan, QProofPlan,
    native::{artifact::KeyArtifact, bootstrap as native},
};
use iroha_plonk::{keys::pk::artifact::ReadConfig, pcs::ipa::PinnedParams};
use iroha_plonk_recursion::verifier::VerifierPlan;

use super::recipe::InstalledSourceSealV1;
use super::*;

/// Bootstrap source qualification failed before any wallet capability was granted.
#[derive(Clone, Debug, thiserror::Error)]
pub enum BootstrapQualificationErrorV1 {
    /// Installation, canonical metadata or bounded original read mismatch.
    #[error(transparent)]
    Original(#[from] Error),
    /// The fixed source plan or entire signed context schema differs.
    #[error("invalid compiled Bootstrap source/context")]
    Source,
    /// Strict native original source/key import failed.
    #[error(transparent)]
    Native(#[from] native::Error),
}

/// The strictly imported terminal Bootstrap A source for one authenticated program.
/// Bootstrap is one unsplit A with no W. Only metadata is retained; no PK, final
/// Omega or wallet-open capability is owned.
pub struct QualifiedBootstrapProgramV1 {
    installation: ([u8; 32], [u8; 32]),
    program: u32,
    prover: native::Prover,
    terminal: InstalledSourceSealV1<Eq>,
    stage_memory: crate::kagemusha_wallet_capacity_v1::KagemushaWalletProvingMemoryV1,
}
impl QualifiedBootstrapProgramV1 {
    /// Design §5.3 peak proving memory of the single terminal A stage, fused quotient.
    pub const fn stage_memory_bytes(&self) -> u64 {
        self.stage_memory.fused_bytes
    }
    /// Design §5.3 peak proving memory of the single terminal A stage, under both quotient plans.
    pub const fn stage_memory(
        &self,
    ) -> crate::kagemusha_wallet_capacity_v1::KagemushaWalletProvingMemoryV1 {
        self.stage_memory
    }
    /// Exact authenticated installation and selected program.
    pub const fn identity(&self) -> (([u8; 32], [u8; 32]), u32) {
        (self.installation, self.program)
    }
    /// Metadata-only native stage owner; qualified stage acquisition borrows sealed metadata.
    /// This component alone cannot authorize a complete wallet or final Omega.
    pub const fn prover(&self) -> &native::Prover {
        &self.prover
    }
}

fn metadata<C: PastaCurve>(
    original: DecodedVerifierOriginal,
) -> Result<KeyArtifact<C>, BootstrapQualificationErrorV1> {
    let binding = original
        .binding
        .map_err(|_| BootstrapQualificationErrorV1::Source)?;
    let key = VerifyingKey::read(&original.verifying_key, &binding)
        .map_err(|_| BootstrapQualificationErrorV1::Source)?;
    KeyArtifact::new(binding, key).map_err(|_| BootstrapQualificationErrorV1::Source)
}

// The shared offline/intake factory reconstructs every fixed context word from
// the already-qualified Q key and installed root. No signed context is a recipe.
#[cfg(test)]
pub(super) fn plan(
    scope: SourceScopeV1,
    recipe: &QProgramRecipeV1,
) -> Result<native::Plan, BootstrapQualificationErrorV1> {
    let pallas = PinnedParams::derive(16).map_err(|_| BootstrapQualificationErrorV1::Source)?;
    let vesta = PinnedParams::derive(16).map_err(|_| BootstrapQualificationErrorV1::Source)?;
    plan_with_parameters(scope, recipe, pallas, vesta)
}

pub(super) fn plan_with_parameters(
    scope: SourceScopeV1,
    recipe: &QProgramRecipeV1,
    pallas: PinnedParams<Ep>,
    vesta: PinnedParams<Eq>,
) -> Result<native::Plan, BootstrapQualificationErrorV1> {
    if pallas.k() != 16 || vesta.k() != 16 {
        return Err(BootstrapQualificationErrorV1::Source);
    }
    // Lean lineage: A proves the Bootstrap transition directly, so there is no
    // sigma source and the hard 2V1F signature leaf is the only Q.
    if recipe.sigma().is_some() || recipe.signatures().len() != 1 || recipe.keys().len() != 1 {
        return Err(BootstrapQualificationErrorV1::Source);
    }
    let policy = scope.bootstrap()?;
    let keys = recipe
        .keys()
        .iter()
        .map(|key| {
            let verifier = VerifierPlan::new(key.binding().clone(), pallas.clone())
                .map_err(|_| BootstrapQualificationErrorV1::Source)?;
            QProofPlan::new(verifier, key.key().clone())
                .map_err(|_| BootstrapQualificationErrorV1::Source)
        })
        .collect::<Result<Vec<_>, _>>()?;
    let operation = AProofPlan::inline(Variant::Bootstrap, keys, None, &pallas)
        .map_err(|_| BootstrapQualificationErrorV1::Source)?;
    native::Plan::new(
        operation,
        policy,
        recipe.signatures()[0].clone(),
        pallas,
        vesta,
    )
    .map_err(Into::into)
}

impl AuthenticatedProducerInventoryV1 {
    /// Reconstruct the whole fixed Bootstrap context and strictly import its one
    /// signed terminal A original. Its metadata alone never bypasses the original
    /// source, table, commitment and full VK checks.
    /// # Errors
    /// Different installation/program/Q scope, wrong entire context, malformed
    /// metadata, capped or substituted original, or any strict source failure.
    pub fn qualify_bootstrap_program(
        &self,
        installed: &InstalledVerifierPackV1,
        qualified_q: &QualifiedQProgramV1,
        program: u32,
        originals: &mut dyn OriginalSourceV1,
        config: ReadConfig,
    ) -> Result<QualifiedBootstrapProgramV1, BootstrapQualificationErrorV1> {
        self.qualify_bootstrap_program_with_admission(
            installed,
            qualified_q,
            program,
            originals,
            config,
            0,
            super::builtin::Admission::Strict,
            &DescriptorMemo::default(),
        )
    }

    // `descriptors` belongs to the calling qualification and is dropped with it.
    #[allow(clippy::too_many_arguments)]
    pub(super) fn qualify_bootstrap_program_with_admission(
        &self,
        installed: &InstalledVerifierPackV1,
        qualified_q: &QualifiedQProgramV1,
        program: u32,
        originals: &mut dyn OriginalSourceV1,
        config: ReadConfig,
        route_index: u32,
        admission: super::builtin::Admission<'_>,
        descriptors: &DescriptorMemo,
    ) -> Result<QualifiedBootstrapProgramV1, BootstrapQualificationErrorV1> {
        let scheme = installed.verifier().scheme();
        let identity = (scheme.scheme_id(), installed.verifier().manifest_digest());
        if identity != self.installation() || qualified_q.identity() != (identity, program) {
            return Err(Error::Authority.into());
        }
        let record = self
            .inventory
            .operations
            .get(usize::try_from(program).map_err(|_| Error::Inventory)?)
            .ok_or(Error::Inventory)?;
        if Variant::ALL.get(
            usize::from(record.variant)
                .checked_sub(1)
                .ok_or(Error::Inventory)?,
        ) != Some(&Variant::Bootstrap)
            || record.a.len() != 1
            || !record.w.is_empty()
        {
            return Err(Error::Inventory.into());
        }
        let plan = plan_with_parameters(
            SourceScopeV1::from_scheme(scheme)?,
            qualified_q.recipe(),
            installed.verifier().pallas_parameters().as_ref().clone(),
            installed.verifier().vesta_parameters(16)?.as_ref().clone(),
        )?;
        let context_fields: Vec<_> = plan
            .context()
            .schema()
            .iter()
            .map(PrimeField::to_repr)
            .collect();
        if context_fields != record.context {
            return Err(BootstrapQualificationErrorV1::Source);
        }
        let terminal =
            metadata(self.read_verifier_metadata(record.a[0], originals, descriptors)?)?;
        let stage_memory = peak_proving_memory([&terminal])?;
        let prover = native::Prover::from_artifacts(plan, terminal)?;
        let terminal = {
            let original = self.read_original(record.a[0], originals, config.maximum_bytes)?;
            InstalledSourceSealV1::new(
                record.a[0],
                match admission.member(&[3, route_index, 0])? {
                    Some(member) => prover.import_terminal_builtin_cancellable(
                        &original.proving_key,
                        config,
                        member,
                        None,
                    )?,
                    None => prover.import_terminal(&original.proving_key, config)?,
                },
            )
        };
        Ok(QualifiedBootstrapProgramV1 {
            installation: identity,
            program,
            prover,
            terminal,
            stage_memory,
        })
    }
}

impl QualifiedBootstrapProgramV1 {
    pub(super) fn bind_a(
        &self,
        stage: usize,
        expected_member: u32,
        cancellation: Option<&iroha_pasta::CancellationToken>,
    ) -> Result<iroha_plonk::keys::SourceBoundViewV2<'_, Eq>, BootstrapQualificationErrorV1> {
        iroha_pasta::CancellationToken::checkpoint(cancellation).map_err(|_| Error::Cancelled)?;
        // The one unsplit terminal A is Bootstrap's only stage; no W exists.
        if stage != 0 {
            return Err(Error::Inventory.into());
        }
        Ok(self
            .prover
            .bind_terminal(self.terminal.seal(expected_member)?, cancellation)?)
    }
}
