//! Genuine native component helpers; no production constructors, source mutators or proof stubs.
use super::*;
use iroha_fs::PublishMode;
impl ManagedReserveTopUpRequest {
    pub(in crate::managed) fn funding_prepare(
        &self,
        intent: &ManagedReserveTopUpIntent,
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
        let original = Original {
            selection: self.selection(intent)?,
            policy: intent.policy.clone(),
            partition: intent.partition.clone(),
            movement_id: intent.movement_id,
            amount: intent.amount.clone(),
            checkpoint: checkpoint_bytes(verifier)?,
        };
        self.validate_original(&original)?;
        let directory = self.authority.directory.ensure_child("request")?;
        journal::publish_intent(&directory, &original)?;
        let account = AccountService::new(self.authority.issuer_operator_config()?)
            .map_err(|_| invalid("fixture wallet"))?;
        journal::explicit(&directory, &original, utc, options, &account)?;
        let original = journal::required_original(&directory)?;
        let directory = original.directory();
        account
            .prepare_reserve_top_up(
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
        let directory = self.authority.directory.open_child("request")?;
        let original = journal::required_original(&directory)?;
        self.validate_original(&original)?;
        let directory = original.directory();
        let signed = self.verify_wallet(directory, &original, deadline)?;
        self.historical_binding(&original, &signed, verifier)?;
        directory.write_atomic(
            "carrier.nrt",
            &checkpoint_bytes(verifier)?,
            PublishMode::CreateNew,
        )?;
        Ok(())
    }
}
