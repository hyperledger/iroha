//! Test-only registration through its sole owner and genuine native provider absence proof.
use super::*;
use crate::managed::native_operation::Fees;
use crate::managed::native_operation::attempts::metadata;
use crate::managed::native_operation::test_support::native_fixture::{
    NativeFixture, NativeReadHttp,
};
use iroha_fs::PublishMode;
use std::sync::Arc;

impl ManagedReserveAccountRegistration {
    pub(in crate::managed) fn bootstrap_native(
        &mut self,
        native: &mut NativeFixture,
        policy: &ReserveAuthorityPolicyV1,
        underwriting: &ReserveProviderTermsV1,
        utc: u64,
        options: &BoundedTransactionOptions,
    ) -> ManagedReserveAccountProgress {
        self.authority.validate_profile().unwrap();
        self.validate_registration(policy, underwriting).unwrap();
        let verifier = native.observe(&self.authority);
        let current = native.bootstrap_reserve(&self.authority, policy, &verifier);
        assert!(current.current().is_none());
        let original = Original {
            selection: self.selection(policy, underwriting).unwrap(),
            policy: policy.clone(),
            underwriting: underwriting.clone(),
            checkpoint: checkpoint_bytes(&verifier).unwrap(),
        };
        self.validate_original(&original).unwrap();
        let directory = metadata::ensure_operation(&self.authority.directory, "register").unwrap();
        let original =
            super::tests::retain_explicit_request(self, &directory, &original, utc, options);
        let operator = self.authority.reserve_operations_config().unwrap();
        let wallet = AccountService::new(operator.clone()).unwrap();
        let path = original.directory().path().join("transaction");
        let mut http = NativeReadHttp::start_config(&operator, Arc::clone(native.chain.state()));
        wallet
            .prepare_reserve_account_registration(
                &original.request(original.terms.signing_deadline(options.deadline).unwrap()),
                &path,
            )
            .unwrap();
        let signed = self
            .verify_wallet(original.directory(), &original, options.deadline)
            .unwrap();
        http.finish();
        assert!(!path.join("submission.json").exists());
        let carrier = native.bootstrap_commit(&self.authority, &signed);
        let finalized =
            crate::managed::native_operation::verify_carrier(&carrier, &signed).unwrap();
        self.validate_carrier(&original, &finalized).unwrap();
        original
            .directory()
            .write_atomic(
                "carrier.nrt",
                &checkpoint_bytes(&carrier).unwrap(),
                PublishMode::CreateNew,
            )
            .unwrap();
        self.recover_selected_if_present(
            policy,
            underwriting,
            &Fees::from_options(options).unwrap(),
            options.deadline,
        )
        .unwrap()
        .unwrap()
    }
}
