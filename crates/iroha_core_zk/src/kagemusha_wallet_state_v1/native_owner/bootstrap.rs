//! Restart-safe Bootstrap choices, subordinate to the generation-zero provider marker.

use super::*;
use crate::kagemusha_wallet_artifacts_v1::producer_inventory::ImportedSigmaV1;
use iroha_plonk::ProverRandomness;

const PLAN_MAX: usize = 4096;

#[derive(norito::Encode, norito::Decode, norito::NoritoSchema)]
#[norito_schema(name = "iroha_core_zk::kagemusha_wallet_state_v1::BootstrapPreparationV1")]
struct BootstrapPlanV1 {
    version: u16,
    marker: [u8; 32],
    credential: [u8; 32],
    manifest: [u8; 32],
    nonce: [u8; 32],
}
impl BootstrapPlanV1 {
    fn require(
        &self,
        marker: [u8; 32],
        credential: [u8; 32],
        manifest: [u8; 32],
    ) -> Result<(), Error> {
        use ff::PrimeField;
        if self.version != 1
            || marker == [0; 32]
            || self.marker != marker
            || self.credential != credential
            || self.manifest != manifest
            || self.nonce == [0; 32]
            || !bool::from(iroha_pasta::Fp::from_repr(self.nonce).is_some())
        {
            return Err(Error::WitnessLost("Bootstrap preparation binding"));
        }
        Ok(())
    }
}

impl<F: KagemushaWalletFsV1, P: KagemushaWalletPlatformV1, S: OriginalSourceV1 + Send>
    Coordinator<AdvanceHandle<F, P>, ProviderArchive<F, P>, NativeWalletProofsV1<F, P, S>>
{
    /// Finish generation-zero enrollment with one retained native Bootstrap and Advance.
    /// Retries resolve the provider's selected output first. No plan or archive filename
    /// can establish that an enrollment, selection or release happened.
    ///
    /// # Errors
    /// Missing/corrupt source custody, changed admission, unavailable original keys or proof,
    /// and uncertain provider outcomes. Lost released bytes never cause a new signature.
    pub fn bootstrap(&mut self) -> Result<Completion, Error> {
        let _payment = self.scheduler.payment();
        let marker = match self.status()? {
            SlotStatus::Enrollment(marker) => marker,
            SlotStatus::Pending(marker) => {
                let (sequence, _, capsule) = marker
                    .head()
                    .ok_or(Error::WitnessLost("selected Bootstrap source"))?;
                if sequence == 0 {
                    let frozen = self.frozen(capsule)?;
                    return self.commit(frozen);
                }
                let (_, manifest) = self.manifest()?;
                let entry = self.step_entry(&manifest, 0)?;
                return self
                    .retry(&entry.operation)?
                    .ok_or(Error::WitnessLost("released Bootstrap lookup"));
            }
            SlotStatus::Released(_) => {
                let (_, manifest) = self.sync_manifest()?;
                let entry = self.step_entry(&manifest, 0)?;
                return self
                    .retry(&entry.operation)?
                    .ok_or(Error::WitnessLost("released Bootstrap lookup"));
            }
            _ => return Err(Error::Invalid("Bootstrap requires enrolled custody")),
        };
        let marker_digest = *marker.marker_digest();
        let credential = self.proofs.enrollment.credential_digest();
        let manifest = self.proofs.installed.verifier().manifest_digest();
        let plan: BootstrapPlanV1 = match self
            .archive
            .get(ArchiveKey::BootstrapPreparation, PLAN_MAX)?
        {
            Some(bytes) => archive::decode(&bytes)?,
            None => {
                let plan = BootstrapPlanV1 {
                    version: 1,
                    marker: marker_digest,
                    credential,
                    manifest,
                    nonce: NativeChoicesV1::fresh_nonce(&[0; 32])?,
                };
                self.archive
                    .put(ArchiveKey::BootstrapPreparation, &archive::encode(&plan)?)?;
                plan
            }
        };
        plan.require(marker_digest, credential, manifest)?;
        let installed = Arc::clone(&self.proofs.installed);
        let preparation = proof(PreparationV1::new(&installed))?;
        let owner = preparation.authenticate_credential_set(
            &valid(self.proofs.enrollment.to_canonical_bytes())?,
            &self.proofs.enrollment_certificates,
        )?;
        let prepared = proof(preparation.prepare_bootstrap(&owner, marker_digest, plan.nonce))?;
        let frozen = if let Some(reference) = self.archive.get(ArchiveKey::BootstrapFrozen, 32)? {
            let capsule = reference
                .try_into()
                .map_err(|_| Error::WitnessLost("Bootstrap frozen reference"))?;
            let frozen = self.frozen(capsule)?;
            let expected = proof(preparation.body_bootstrap(
                &owner,
                &prepared,
                frozen.capsule.body().step_proof.clone(),
                self.proofs.budget,
            ))?;
            proof(expected.require_matches(&frozen))?;
            frozen
        } else {
            // Design §5.3: check this phone before proving; commit checks it again.
            self.require_runtime_capacity()?;
            let sigma = {
                let mut originals =
                    self.proofs.originals.lock().map_err(|_| {
                        Error::ArtifactsUnavailable("proving original owner poisoned")
                    })?;
                let imported = self
                    .proofs
                    .sources
                    .import_sigma(0, &mut *originals, self.proofs.read)
                    .map_err(|error| {
                        if error.is_unavailable() {
                            Error::ArtifactsUnavailable("Bootstrap sigma original")
                        } else {
                            Error::Proof("Bootstrap sigma original")
                        }
                    })?;
                let ImportedSigmaV1::Bootstrap(prover) = imported else {
                    return Err(Error::Proof("Bootstrap sigma role"));
                };
                proof(preparation.prove_bootstrap_sigma(
                    &owner,
                    &prepared.witness,
                    &prepared.statement,
                    &prover,
                    ProverRandomness::hedged(),
                    self.proofs.budget,
                ))?
            };
            let frozen =
                proof(preparation.freeze_bootstrap(&owner, &prepared, sigma, self.proofs.budget))?;
            let capsule = frozen.capsule.custody_digest();
            self.archive
                .put(ArchiveKey::Capsule(capsule), &archive::encode(&frozen)?)?;
            self.archive.put(ArchiveKey::BootstrapFrozen, &capsule)?;
            frozen
        };
        self.commit(frozen)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ff::PrimeField;
    #[test]
    fn retained_bootstrap_choices_bind_original_marker_credential_and_installation() {
        let plan = BootstrapPlanV1 {
            version: 1,
            marker: [1; 32],
            credential: [2; 32],
            manifest: [3; 32],
            nonce: iroha_pasta::Fp::from(5).to_repr(),
        };
        plan.require([1; 32], [2; 32], [3; 32]).unwrap();
        for bindings in [
            ([9; 32], [2; 32], [3; 32]),
            ([1; 32], [9; 32], [3; 32]),
            ([1; 32], [2; 32], [9; 32]),
        ] {
            assert!(plan.require(bindings.0, bindings.1, bindings.2).is_err());
        }
        let bytes = archive::encode(&plan).unwrap();
        let mut decoded: BootstrapPlanV1 = archive::decode(&bytes).unwrap();
        assert_eq!(decoded.nonce, plan.nonce);
        for nonce in [[0; 32], [255; 32]] {
            decoded.nonce = nonce;
            assert!(decoded.require([1; 32], [2; 32], [3; 32]).is_err());
        }
    }
}
