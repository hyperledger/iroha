//! Exact durable CloseLoads transport from a source-selected Retiring package.
use super::*;

const PLAN_MAX: usize = KAGEMUSHA_WALLET_CLOSE_LOADS_MAX_BYTES_V1 + 4096;
#[derive(Clone, norito::Encode, norito::Decode, norito::NoritoSchema)]
#[norito_schema(name = "iroha_core_zk::kagemusha_wallet_state_v1::CloseLoadsPlanV1")]
struct Plan {
    version: u16,
    request_id: [u8; 32],
    capsule: [u8; 32],
    completion: [u8; 32],
    credential: KagemushaWalletCredentialV1,
    certificates: KagemushaWalletCertificateSetV1,
    package: KagemushaWalletPackageV1,
    nonce: [u8; 32],
    output: Option<[u8; 32]>,
}
impl Plan {
    fn body(&self) -> Result<KagemushaWalletLedgerControlBodyV1, Error> {
        Ok(KagemushaWalletLedgerControlBodyV1 {
            version: 1,
            scheme_id: self.credential.body.scheme_id,
            asset_digest: self.credential.body.asset_digest,
            wallet_id: self.credential.body.wallet_id,
            action: KagemushaWalletLedgerControlActionV1::CloseLoads {
                package_digest: valid(self.package.verify(&self.credential))?.package,
                next_load: self.package.statement.next_load,
            },
            nonce: self.nonce,
        })
    }
    fn require(&self, scheme: &[u8; 32], wallet: &[u8; 32]) -> Result<(), Error> {
        valid(self.body()?.validate())?;
        if self.request_id == [0; 32]
            || self.version != 1
            || self.capsule == [0; 32]
            || self.completion == [0; 32]
            || self.output == Some([0; 32])
            || &self.credential.body.scheme_id != scheme
            || &self.credential.body.wallet_id != wallet
            || self.package.receipt.capsule_digest != self.capsule
            || self.package.statement.lifecycle != KagemushaWalletLifecycleV1::Retiring
            || !self.package.statement.effect.kind().consumes_lineage()
        {
            return Err(Error::WitnessLost("CloseLoads original binding"));
        }
        Ok(())
    }
    fn output(&self, bytes: &[u8]) -> Result<KagemushaWalletCloseLoadsV1, Error> {
        let value = valid(KagemushaWalletCloseLoadsV1::decode_canonical(
            bytes,
            &self.credential.body.scheme_id,
        ))?;
        if value.control.body != self.body()?
            || value.credential != self.credential
            || value.certificates != self.certificates
            || value.package != self.package
        {
            return Err(Error::WitnessLost("CloseLoads output binding"));
        }
        Ok(value)
    }
}
impl<C: Custody, A: ArchiveStore, N: NativeProofs> Coordinator<C, A, N> {
    fn close_loads_plan(&mut self, request_id: [u8; 32]) -> Result<Plan, Error> {
        if request_id == [0; 32] {
            return Err(Error::Invalid("CloseLoads retry identity"));
        }
        let (_, selected) = self.manifest()?;
        if let Some(value) = selected.close_loads.get(&mut self.archive, &request_id)? {
            let address: [u8; 32] = value
                .try_into()
                .map_err(|_| Error::WitnessLost("CloseLoads plan index"))?;
            let plan: Plan = archive::decode(&self.archive.read_object(&address, PLAN_MAX)?)?;
            plan.require(&self.scheme_id, &self.wallet_id)?;
            if plan.request_id != request_id {
                return Err(Error::WitnessLost("CloseLoads retry binding"));
            }
            return Ok(plan);
        }
        let (root, mut manifest) = self.sync_manifest()?;
        let SlotStatus::Released(marker) = self.status()? else {
            return Err(Error::Invalid("CloseLoads requires released custody"));
        };
        let (sequence, _, capsule) = marker.head().ok_or(Error::NoHead)?;
        let source = self.indexed_step(&manifest, sequence)?;
        if source.retained.capsule_digest != capsule {
            return Err(Error::WitnessLost("CloseLoads current source"));
        }
        let snapshot = self.source_custody(&manifest, &source)?;
        let certificates = snapshot
            .original(
                &mut self.archive,
                &source.frozen.capsule.successor_state,
                PreparationOriginalV1::EnrollmentCertificates,
            )?
            .ok_or(Error::WitnessLost("CloseLoads issuer original"))?;
        let plan = Plan {
            version: 1,
            request_id,
            capsule,
            completion: source.retained.completion_digest,
            credential: source.frozen.credential,
            certificates: archive::decode(&certificates)?,
            package: if source.frozen.capsule.kind == KagemushaWalletOperationKindV1::Send {
                valid(KagemushaWalletPaymentV1::decode_canonical(
                    &source.retained.record.output,
                    &self.scheme_id,
                ))?
                .send
            } else {
                archive::decode(&source.retained.record.output)?
            },
            nonce: NativeChoicesV1::fresh_nonce(&[0; 32])?,
            output: None,
        };
        plan.require(&self.scheme_id, &self.wallet_id)?;
        // All selected originals are now owned by this immutable object, so later
        // collection of the historical transition cannot strand closure/replay.
        let address = self
            .archive
            .write_object(&archive::encode(&plan)?, PLAN_MAX)?;
        manifest.close_loads = manifest
            .close_loads
            .set(&mut self.archive, request_id, &address)?;
        self.publish_manifest(root, &manifest)?;
        Ok(plan)
    }
    fn retained_close_loads(&mut self, plan: &Plan) -> Result<Option<Vec<u8>>, Error> {
        let Some(address) = plan.output else {
            return Ok(None);
        };
        let bytes = self
            .archive
            .read_object(&address, KAGEMUSHA_WALLET_CLOSE_LOADS_MAX_BYTES_V1)?;
        plan.output(&bytes)?;
        Ok(Some(bytes))
    }
    fn finish_close_loads(&mut self, plan: &Plan, bytes: &[u8]) -> Result<(), Error> {
        plan.output(bytes)?;
        let (root, mut manifest) = self.sync_manifest()?;
        let address: [u8; 32] = manifest
            .close_loads
            .get(&mut self.archive, &plan.request_id)?
            .ok_or(Error::WitnessLost("selected CloseLoads plan"))?
            .try_into()
            .map_err(|_| Error::WitnessLost("CloseLoads plan index"))?;
        if self.archive.read_object(&address, PLAN_MAX)? != archive::encode(plan)?
            || plan.output.is_some()
        {
            return Err(Error::WitnessLost("CloseLoads plan changed"));
        }
        let mut done = plan.clone();
        done.output = Some(
            self.archive
                .write_object(bytes, KAGEMUSHA_WALLET_CLOSE_LOADS_MAX_BYTES_V1)?,
        );
        let address = self
            .archive
            .write_object(&archive::encode(&done)?, PLAN_MAX)?;
        manifest.close_loads =
            manifest
                .close_loads
                .set(&mut self.archive, plan.request_id, &address)?;
        self.publish_manifest(root, &manifest)?;
        Ok(())
    }
}
impl<F: KagemushaWalletFsV1, P: KagemushaWalletPlatformV1, S: OriginalSourceV1 + Send>
    Coordinator<AdvanceHandle<F, P>, ProviderArchive<F, P>, NativeWalletProofsV1<F, P, S>>
{
    /// Retain and return the exact signed load-closure transport for ledger submission.
    /// Reuse request_id for exact delivery retries. After a preissued Load changes next_load,
    /// use a fresh request_id to select the newer complete consumer; old ids remain retrievable.
    /// The package and next_load come from released native custody; no ledger acknowledgement
    /// or permission to retire the payment key is inferred from this result.
    /// # Errors
    /// Current source is not a complete Retiring consumer, proof/key checks fail, storage is
    /// unavailable, publication is uncertain, or an already selected original was lost.
    pub fn close_loads(&mut self, request_id: [u8; 32]) -> Result<Vec<u8>, Error> {
        let _payment = self.scheduler.payment();
        let plan = self.close_loads_plan(request_id)?;
        if plan.credential.body.account_digest != self.proofs.enrollment.body.account_digest
            || plan.credential.body.payment_key != self.proofs.enrollment.body.payment_key
            || plan.credential.body.enrollment_id != self.proofs.enrollment.body.enrollment_id
        {
            return Err(Error::Proof("CloseLoads admitted incarnation"));
        }
        let preparation = proof(PreparationV1::new(&self.proofs.installed))?;
        preparation.authenticate_credential_set(
            &valid(plan.credential.to_canonical_bytes())?,
            &archive::encode(&plan.certificates)?,
        )?;
        proof(self.proofs.installed.verifier().verify_package_proofs(
            &plan.package,
            None,
            self.proofs.budget,
        ))?;
        if let Some(bytes) = self.retained_close_loads(&plan)? {
            return Ok(bytes);
        }
        let SlotStatus::Released(marker) = self.status()? else {
            return Err(Error::Invalid("CloseLoads requires released custody"));
        };
        let (_, _, source) = marker.head().ok_or(Error::NoHead)?;
        let body = plan.body()?;
        let signature =
            self.custody
                .sign_close_loads(source, &plan.credential.body.payment_key, &body)?;
        let value = KagemushaWalletCloseLoadsV1 {
            version: 1,
            control: KagemushaWalletLedgerControlV1 { body, signature },
            credential: plan.credential,
            certificates: plan.certificates.clone(),
            package: plan.package.clone(),
        };
        let bytes = valid(value.to_canonical_bytes())?;
        self.finish_close_loads(&plan, &bytes)?;
        Ok(bytes)
    }
}

#[cfg(test)]
mod tests;
