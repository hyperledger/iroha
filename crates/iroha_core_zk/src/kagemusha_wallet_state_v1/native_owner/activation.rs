//! One durable inner Activate and independently retained signed outer transaction attempts.

use super::*;
mod confirmation;
pub use confirmation::ActivationFinalityProgressV1;

const PLAN_MAX: usize = KAGEMUSHA_WALLET_ACTIVATION_MAX_BYTES_V1 + 4096;

#[derive(Clone, norito::Encode, norito::Decode, norito::NoritoSchema)]
#[norito_schema(name = "iroha_core_zk::kagemusha_wallet_state_v1::ActivationPlanV1")]
struct Plan {
    version: u16,
    capsule: [u8; 32],
    completion: [u8; 32],
    credential: KagemushaWalletCredentialV1,
    certificates: KagemushaWalletCertificateSetV1,
    asset: KagemushaWalletAssetScopeV1,
    bootstrap: KagemushaWalletPackageV1,
    nonce: [u8; 32],
    output: Option<[u8; 32]>,
    confirmation: Option<[u8; 32]>,
    attempts: IndexRoot,
}
impl Plan {
    fn body(&self) -> Result<KagemushaWalletLedgerControlBodyV1, Error> {
        Ok(KagemushaWalletLedgerControlBodyV1 {
            version: 1,
            scheme_id: self.credential.body.scheme_id,
            asset_digest: self.asset.asset_digest(),
            wallet_id: self.credential.body.wallet_id,
            action: KagemushaWalletLedgerControlActionV1::Activate {
                package_digest: valid(self.bootstrap.verify(&self.credential))?.package,
            },
            nonce: self.nonce,
        })
    }
    fn require(
        &self,
        scheme: &[u8; 32],
        wallet: &[u8; 32],
        asset: &KagemushaWalletAssetScopeV1,
    ) -> Result<(), Error> {
        valid(self.asset.validate())?;
        valid(self.body()?.validate())?;
        if self.version != 1
            || self.capsule == [0; 32]
            || self.completion == [0; 32]
            || self.output == Some([0; 32])
            || self.confirmation == Some([0; 32])
            || (self.attempts != IndexRoot::default() && self.output.is_none())
            || (self.confirmation.is_some() && self.output.is_none())
            || &self.credential.body.scheme_id != scheme
            || &self.credential.body.wallet_id != wallet
            || self.asset != *asset
            || self.asset.asset_digest() != self.credential.body.asset_digest
            || self.bootstrap.statement.sequence != 0
            || self.bootstrap.receipt.capsule_digest != self.capsule
            || !matches!(
                self.bootstrap.statement.effect,
                KagemushaWalletEffectV1::Bootstrap { .. }
            )
        {
            return Err(Error::WitnessLost("activation original binding"));
        }
        Ok(())
    }
    fn output(&self, bytes: &[u8]) -> Result<KagemushaWalletActivationV1, Error> {
        let value = valid(KagemushaWalletActivationV1::decode_canonical(
            bytes,
            &self.credential.body.scheme_id,
        ))?;
        if value.control.body != self.body()?
            || value.credential != self.credential
            || value.certificates != self.certificates
            || value.asset != self.asset
            || value.bootstrap != self.bootstrap
        {
            return Err(Error::WitnessLost("activation output binding"));
        }
        Ok(value)
    }
}
impl<C: Custody, A: ArchiveStore, N: NativeProofs> Coordinator<C, A, N> {
    fn activation_plan(&mut self, asset: &KagemushaWalletAssetScopeV1) -> Result<Plan, Error> {
        let (_, selected) = self.manifest()?;
        if let Some(address) = selected.activation {
            let plan: Plan = archive::decode(&self.archive.read_object(&address, PLAN_MAX)?)?;
            plan.require(&self.scheme_id, &self.wallet_id, asset)?;
            return Ok(plan);
        }
        let (root, mut manifest) = self.sync_manifest()?;
        let source = self.indexed_step(&manifest, 0)?;
        let snapshot = self.source_custody(&manifest, &source)?;
        let certificates = snapshot
            .original(
                &mut self.archive,
                &source.frozen.capsule.successor_state,
                PreparationOriginalV1::EnrollmentCertificates,
            )?
            .ok_or(Error::WitnessLost("activation issuer original"))?;
        let plan = Plan {
            version: 1,
            capsule: source.retained.capsule_digest,
            completion: source.retained.completion_digest,
            credential: source.frozen.credential,
            certificates: archive::decode(&certificates)?,
            asset: asset.clone(),
            bootstrap: archive::decode(&source.retained.record.output)?,
            nonce: NativeChoicesV1::fresh_nonce(&[0; 32])?,
            output: None,
            confirmation: None,
            attempts: IndexRoot::default(),
        };
        plan.require(&self.scheme_id, &self.wallet_id, asset)?;
        manifest.activation = Some(
            self.archive
                .write_object(&archive::encode(&plan)?, PLAN_MAX)?,
        );
        self.publish_manifest(root, &manifest)?;
        Ok(plan)
    }
    pub(in crate::kagemusha_wallet_state_v1) fn require_activation_retention(
        &mut self,
        address: [u8; 32],
        step: &manifest::StepEntry,
    ) -> Result<(), Error> {
        let plan: Plan = archive::decode(&self.archive.read_object(&address, PLAN_MAX)?)?;
        plan.require(&self.scheme_id, &self.wallet_id, &plan.asset)?;
        if plan.capsule != step.capsule || plan.completion != step.completion {
            return Err(Error::WitnessLost("activation retained Bootstrap"));
        }
        if let Some(output) = plan.output {
            plan.output(
                &self
                    .archive
                    .read_object(&output, KAGEMUSHA_WALLET_ACTIVATION_MAX_BYTES_V1)?,
            )?;
        }
        self.retained_activation_confirmation(&plan)?;
        Ok(())
    }
    fn retained_activation(&mut self, plan: &Plan) -> Result<Option<Vec<u8>>, Error> {
        let Some(address) = plan.output else {
            return Ok(None);
        };
        let bytes = self
            .archive
            .read_object(&address, KAGEMUSHA_WALLET_ACTIVATION_MAX_BYTES_V1)?;
        plan.output(&bytes)?;
        Ok(Some(bytes))
    }
    fn finish_activation(&mut self, plan: &Plan, bytes: &[u8]) -> Result<(), Error> {
        plan.output(bytes)?;
        let (root, mut manifest) = self.sync_manifest()?;
        let address = manifest
            .activation
            .ok_or(Error::WitnessLost("selected activation plan"))?;
        if self.archive.read_object(&address, PLAN_MAX)? != archive::encode(plan)?
            || plan.output.is_some()
        {
            return Err(Error::WitnessLost("activation plan changed"));
        }
        let mut done = plan.clone();
        done.output = Some(
            self.archive
                .write_object(bytes, KAGEMUSHA_WALLET_ACTIVATION_MAX_BYTES_V1)?,
        );
        manifest.activation = Some(
            self.archive
                .write_object(&archive::encode(&done)?, PLAN_MAX)?,
        );
        self.publish_manifest(root, &manifest)?;
        Ok(())
    }
}
impl<F: KagemushaWalletFsV1, P: KagemushaWalletPlatformV1, S: OriginalSourceV1 + Send>
    Coordinator<AdvanceHandle<F, P>, ProviderArchive<F, P>, NativeWalletProofsV1<F, P, S>>
{
    fn authenticate_activation_plan(&self, plan: &Plan) -> Result<(), Error> {
        if plan.credential.body.account_digest != self.proofs.enrollment.body.account_digest
            || plan.credential.body.payment_key != self.proofs.enrollment.body.payment_key
            || plan.credential.body.enrollment_id != self.proofs.enrollment.body.enrollment_id
        {
            return Err(Error::Proof("activation admitted incarnation"));
        }

        let preparation = proof(PreparationV1::new(&self.proofs.installed))?;
        preparation.authenticate_credential_set(
            &valid(plan.credential.to_canonical_bytes())?,
            &archive::encode(&plan.certificates)?,
        )?;
        proof(self.proofs.installed.verifier().verify_package_proofs(
            &plan.bootstrap,
            None,
            self.proofs.budget,
        ))?;
        Ok(())
    }
    /// Return the exact durable Activate frame for ordinary signed ledger submission.
    /// This transport result is not a ledger activation acknowledgement or permission to load.
    /// Later heads and uncertain delivery preserve the original selected bytes.
    /// # Errors
    /// Unreleased/missing Bootstrap, lost selected originals, invalid installed proofs,
    /// unavailable hardware/storage, or uncertain publication. No failure re-signs a selected output.
    pub fn activation(&mut self) -> Result<Vec<u8>, Error> {
        let _payment = self.scheduler.payment();
        let asset = self.proofs.asset.clone();
        let plan = self.activation_plan(&asset)?;
        self.authenticate_activation_plan(&plan)?;
        if let Some(bytes) = self.retained_activation(&plan)? {
            return Ok(bytes);
        }
        let SlotStatus::Released(marker) = self.status()? else {
            return Err(Error::Invalid("activation requires released custody"));
        };
        let (_, _, source) = marker.head().ok_or(Error::NoHead)?;
        let body = plan.body()?;
        let signature =
            self.custody
                .sign_activation(source, &plan.credential.body.payment_key, &body)?;
        let value = KagemushaWalletActivationV1 {
            version: 1,
            control: KagemushaWalletLedgerControlV1 { body, signature },
            credential: plan.credential,
            bootstrap: plan.bootstrap.clone(),
            asset: plan.asset.clone(),
            certificates: plan.certificates.clone(),
        };
        let bytes = valid(value.to_canonical_bytes())?;
        self.finish_activation(&plan, &bytes)?;
        Ok(bytes)
    }
}

#[cfg(test)]
#[path = "activation/tests.rs"]
mod tests;
