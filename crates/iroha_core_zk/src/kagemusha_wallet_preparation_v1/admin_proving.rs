//! Administrative sigma proving through exact installed keys and one verifier.
//!
//! Typed native owners have already imported their original compiled sources.
//! These adapters match them to the authenticated installation and verify each
//! resulting proof under that installation. Native admission, custody and the
//! complete producer catalog remain mandatory; no wallet-open grant is created.

use iroha_kagemusha_proof::admin_sigma::{
    ArchiveWitness,
    native::{
        AdminSigmaProof, ArchiveProver, BootstrapProver, LoadProver, RefreshProver, RetiringProver,
        UnloadProver,
    },
};
use iroha_plonk::{ProverConfig, ProverRandomness};

use super::*;

fn bind_statement(
    kind: KagemushaWalletOperationKindV1,
    original: &[Fp; 26],
    statement: &KagemushaWalletStatementV1,
) -> Result<(), Error> {
    if statement.effect.kind() != kind
        || *original != fields::<26>(authority(statement.field_items())?)?
    {
        return Err(Error::Authority);
    }
    Ok(())
}

fn bind_original(
    installed: &crate::kagemusha_wallet_artifacts_v1::ArtifactOriginalV1,
    descriptor: &[u8],
    key: &[u8],
) -> Result<(), Error> {
    if descriptor != installed.descriptor || key != installed.verifying_key {
        return Err(Error::Profile);
    }
    Ok(())
}

fn bind_result(
    statement: &KagemushaWalletStatementV1,
    proof: AdminSigmaProof,
) -> Result<KagemushaWalletStepProofV1, Error> {
    let instance = fields::<1>(vec![authority(statement.statement_digest())?])?;
    if proof.instances[0].as_slice() != instance {
        return Err(Error::Proof);
    }
    let proof = KagemushaWalletStepProofV1 { bytes: proof.bytes };
    authority(proof.validate())?;
    Ok(proof)
}

macro_rules! prove_admin {
    ($method:ident, $kind:ident, $witness:ty, $prover:ty, $doc:literal) => {
        #[doc = $doc]
        ///
        /// The original component must match the installed selector, descriptor
        /// and VK exactly. The statement is derived from the same typed witness;
        /// the result is fully verified by the installed artifact owner.
        ///
        /// # Errors
        /// Foreign owner, statement/operation/instance mismatch, different key
        /// material, failed proof generation or native verification.
        pub fn $method(
            &self,
            owner: &AuthenticatedCredentialV1,
            witness: &$witness,
            statement: &KagemushaWalletStatementV1,
            prover: &$prover,
            randomness: ProverRandomness<'_>,
            budget: MemoryBudget,
        ) -> Result<KagemushaWalletStepProofV1, Error> {
            let kind = KagemushaWalletOperationKindV1::$kind;
            self.statement_fields(owner, statement)?;
            bind_statement(kind, &witness.statement, statement)?;
            self.admin_original(
                kind,
                prover.binding().encoded(),
                &prover.verifying_key().to_bytes(),
            )?;
            let proof = prover
                .prove(
                    witness,
                    randomness,
                    ProverConfig {
                        msm_budget: budget,
                        cancellation: self.cancellation,
                    },
                )
                .map_err(|error| {
                    if error.is_cancelled() {
                        Error::Cancelled
                    } else {
                        Error::Proof
                    }
                })?;
            self.admin_result(statement, proof, kind, budget)
        }
    };
}

impl PreparationV1<'_> {
    fn admin_original(
        &self,
        kind: KagemushaWalletOperationKindV1,
        descriptor: &[u8],
        key: &[u8],
    ) -> Result<(), Error> {
        let installed = self
            .installed
            .originals()
            .steps
            .iter()
            .find(|entry| entry.kind == kind && entry.enabled_controls == 0)
            .ok_or(Error::Inventory)?;
        bind_original(&installed.artifact, descriptor, key)
    }

    fn admin_result(
        &self,
        statement: &KagemushaWalletStatementV1,
        proof: AdminSigmaProof,
        kind: KagemushaWalletOperationKindV1,
        budget: MemoryBudget,
    ) -> Result<KagemushaWalletStepProofV1, Error> {
        let proof = bind_result(statement, proof)?;
        self.installed.verifier().verify_step_proof_cancellable(
            statement,
            &proof,
            kind,
            0,
            budget,
            self.cancellation,
        )?;
        Ok(proof)
    }

    prove_admin!(
        prove_bootstrap_sigma,
        Bootstrap,
        BootstrapWitness,
        BootstrapProver,
        "Prove a prepared zero-value Bootstrap under its installed original key."
    );
    prove_admin!(
        prove_load_sigma,
        Load,
        LoadWitness,
        LoadProver,
        "Prove a prepared Load sigma; finalized ledger evidence remains an A obligation."
    );
    prove_admin!(
        prove_unload_sigma,
        Unload,
        ConsumingWitness,
        UnloadProver,
        "Prove a prepared Unload sigma with its exact consuming lineage projection."
    );
    prove_admin!(
        prove_retiring_sigma,
        Retiring,
        ConsumingWitness,
        RetiringProver,
        "Prove a prepared irreversible Retiring sigma under the installed Retiring key."
    );
    prove_admin!(
        prove_archive_sigma,
        ArchiveSent,
        ArchiveWitness,
        ArchiveProver,
        "Prove a prepared Archive sigma; background A owns incoming evidence and adjusted no-op."
    );

    /// Prove an authenticated Refresh preparation with the one installed five-kind key.
    /// Its private construction retains exact originals and the released source identity.
    ///
    /// # Errors
    /// Foreign installation/owner, changed statement or key, failed proof or native verification.
    pub fn prove_refresh_sigma(
        &self,
        owner: &AuthenticatedCredentialV1,
        step: &RefreshStepV1,
        prover: &RefreshProver,
        randomness: ProverRandomness<'_>,
        budget: MemoryBudget,
    ) -> Result<KagemushaWalletStepProofV1, Error> {
        if step.manifest_digest() != self.installed.verifier().manifest_digest() {
            return Err(Error::Authority);
        }
        let kind = KagemushaWalletOperationKindV1::RefreshPolicy;
        self.statement_fields(owner, step.statement())?;
        bind_statement(kind, &step.witness().statement, step.statement())?;
        self.admin_original(
            kind,
            prover.binding().encoded(),
            &prover.verifying_key().to_bytes(),
        )?;
        let proof = prover
            .prove(
                step.witness(),
                randomness,
                ProverConfig {
                    msm_budget: budget,
                    cancellation: self.cancellation,
                },
            )
            .map_err(|error| {
                if error.is_cancelled() {
                    Error::Cancelled
                } else {
                    Error::Proof
                }
            })?;
        self.admin_result(step.statement(), proof, kind, budget)
    }
}

#[cfg(test)]
#[path = "admin_proving/tests.rs"]
mod tests;
