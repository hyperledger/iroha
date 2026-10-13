//! Genuine native component helpers; no production constructors, source mutators or proof stubs.
use super::*;
use iroha_fs::PublishMode;
impl ManagedProviderCapacity {
    pub(in crate::managed) fn funding_retain_selected(
        &self,
        policy: &ReserveAuthorityPolicyV1,
        funding: FundingSelection<'_>,
        utc: u64,
        options: &BoundedTransactionOptions,
        current: &VerifiedReserveAccountStateV1,
        verifier: &FinalityVerifier,
    ) -> Result<()> {
        self.authority.validate_profile()?;
        self.validate_policy(policy)?;
        journal::admit_selection_inputs(
            funding.partition,
            funding.credit,
            self.plan()?.declaration(),
        )?;
        let original = self.retain_observed_original(policy, current, verifier, Some(funding))?;
        let directory = self.authority.directory.open_child("declare")?;
        let account = AccountService::new(self.authority.issuer_operator_config()?)
            .map_err(|_| invalid("fixture wallet"))?;
        journal::explicit(&directory, &original, utc, options, &account)
    }
    pub(in crate::managed) fn funding_prepare(
        &self,
        policy: &ReserveAuthorityPolicyV1,
        funding: FundingSelection<'_>,
        utc: u64,
        options: &BoundedTransactionOptions,
        current: &VerifiedReserveAccountStateV1,
        verifier: &FinalityVerifier,
    ) -> Result<SignedTransaction> {
        self.funding_retain_selected(policy, funding, utc, options, current, verifier)?;
        let directory = self.authority.directory.open_child("declare")?;
        let original = journal::required_original(&directory)?;
        let directory = original.directory();
        AccountService::new(self.authority.issuer_operator_config()?)
            .map_err(|_| invalid("fixture wallet"))?
            .prepare_provider_capacity_declaration(
                &original.request(original.terms.signing_deadline(options.deadline)?),
                &directory.path().join("transaction"),
            )
            .map_err(|_| invalid("fixture wallet prepare"))?;
        self.verify_wallet(directory, &original, options.deadline)
    }
    pub(in crate::managed) fn funding_retain(
        &self,
        verifier: &FinalityVerifier,
        deadline: Instant,
    ) -> Result<()> {
        let directory = self.authority.directory.open_child("declare")?;
        let original = journal::required_original(&directory)?;
        let directory = original.directory();
        self.validate_original(&original)?;
        let signed = self.verify_wallet(directory, &original, deadline)?;
        let finalized = crate::managed::native_operation::verify_carrier(verifier, &signed)?;
        self.validate_carrier(&original, &finalized)?;
        directory.write_atomic(
            "carrier.nrt",
            &checkpoint_bytes(verifier)?,
            PublishMode::CreateNew,
        )?;
        Ok(())
    }
}
