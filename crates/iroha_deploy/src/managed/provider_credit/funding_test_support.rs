//! Genuine native component helpers; no production constructors, source mutators or proof stubs.
use super::*;
use iroha_fs::PublishMode;
impl ManagedInitialProviderCredit {
    pub(in crate::managed) fn funding_prepare(
        &self,
        intent: &ManagedInitialProviderCreditIntent,
        utc: u64,
        options: &BoundedTransactionOptions,
        current: &VerifiedReserveAccountStateV1,
        verifier: &FinalityVerifier,
    ) -> Result<SignedTransaction> {
        self.authority.validate_profile()?;
        self.validate_intent(intent)?;
        let tip = verifier
            .verified_tip()
            .map_err(|_| invalid("invalid native fixture cut"))?;
        if current.height() != tip.height()
            || current.context_id() != tip.context_id()
            || current.block_time_ms() != tip.header().creation_time_ms
            || current.policy().policy != intent.policy
        {
            return Err(invalid("fixture current cut differs"));
        }
        if current.current() != Some(&intent.partition) {
            return Err(invalid("fixture exact predecessor differs"));
        }
        if current.credit().is_some() {
            return Err(invalid("fixture credit exists"));
        }
        let original = Original {
            selection: self.selection(intent)?,
            policy: intent.policy.clone(),
            partition: intent.partition.clone(),
            record: intent.record.clone(),
            checkpoint: checkpoint_bytes(verifier)?,
        };
        self.validate_original(&original)?;
        let directory = self.authority.directory.ensure_child("install")?;
        journal::publish_intent(&directory, &original)?;
        let account = AccountService::new(self.authority.config.clone())
            .map_err(|_| invalid("fixture wallet"))?;
        journal::explicit(&directory, &original, utc, options, &account)?;
        let original = journal::required_original(&directory)?;
        let directory = original.directory();
        account
            .prepare_provider_credit_upsert(
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
        let directory = self.authority.directory.open_child("install")?;
        let original = journal::required_original(&directory)?;
        self.validate_original(&original)?;
        let directory = original.directory();
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
