//! Test-only exact setup preparation through the original closed intent and wallet owners.
use super::*;
use crate::managed::native_operation::Fees;
use crate::managed::native_operation::{
    test_support::native_fixture::{NativeFixture, NativeReadHttp},
    verify_carrier,
};
use crate::verify::finality::FinalityVerifier;
use iroha_fs::PublishMode;
use std::sync::Arc;

impl ManagedInitialGatewaySetup {
    pub(in crate::managed) fn bootstrap_native(
        &mut self,
        native: &mut NativeFixture,
        policy: &StreamTokenGatewayPolicyV1,
        utc: u64,
        options: &BoundedTransactionOptions,
    ) -> ManagedInitialServiceSetupProgress {
        let intent = Intent::gateway(&self.inner.authority, policy).unwrap();
        self.inner.bootstrap_native(native, intent, utc, options);
        self.recover_selected_if_present(
            policy,
            &Fees::from_options(options).unwrap(),
            options.deadline,
        )
        .unwrap()
        .unwrap()
    }
}
impl ManagedInitialGatewaySetup {
    pub(in crate::managed) fn bootstrap_native_prepare(
        &self,
        native: &NativeFixture,
        policy: &StreamTokenGatewayPolicyV1,
        utc: u64,
        options: &BoundedTransactionOptions,
    ) -> SignedTransaction {
        let intent = Intent::gateway(&self.inner.authority, policy).unwrap();
        self.inner
            .bootstrap_native_prepare(native, intent, utc, options)
    }

    pub(in crate::managed) fn bootstrap_native_retain(
        &self,
        carrier: &FinalityVerifier,
        deadline: Instant,
    ) {
        self.inner.bootstrap_native_retain(carrier, deadline);
    }
}
impl ManagedInitialReputationPolicy {
    pub(in crate::managed) fn bootstrap_native(
        &mut self,
        native: &mut NativeFixture,
        labels: &[String],
        policy: &ReputationJournalAuthorityPolicyV1,
        utc: u64,
        options: &BoundedTransactionOptions,
    ) -> ManagedInitialServiceSetupProgress {
        let intent = Intent::reputation(&self.inner.authority, labels, policy).unwrap();
        self.inner.bootstrap_native(native, intent, utc, options);
        self.recover_selected_if_present(
            labels,
            policy,
            &Fees::from_options(options).unwrap(),
            options.deadline,
        )
        .unwrap()
        .unwrap()
    }
}
impl ManagedInitialProviderIngestAuthority {
    pub(in crate::managed) fn bootstrap_native(
        &mut self,
        native: &mut NativeFixture,
        authority: &ProviderIngestCompletionAuthorityV1,
        utc: u64,
        options: &BoundedTransactionOptions,
    ) -> ManagedInitialServiceSetupProgress {
        let intent = Intent::provider_ingest(&self.inner.authority, authority).unwrap();
        self.inner.bootstrap_native(native, intent, utc, options);
        self.recover_selected_if_present(
            authority,
            &Fees::from_options(options).unwrap(),
            options.deadline,
        )
        .unwrap()
        .unwrap()
    }
}
impl Setup {
    fn bootstrap_native(
        &self,
        native: &mut NativeFixture,
        intent: Intent,
        utc: u64,
        options: &BoundedTransactionOptions,
    ) {
        let signed = self.bootstrap_native_prepare(native, intent, utc, options);
        let carrier = native.bootstrap_commit(&self.authority, &signed);
        self.bootstrap_native_retain(&carrier, options.deadline);
    }

    fn bootstrap_native_prepare(
        &self,
        native: &NativeFixture,
        intent: Intent,
        utc: u64,
        options: &BoundedTransactionOptions,
    ) -> SignedTransaction {
        self.authority.validate_profile().unwrap();
        self.validate_intent(&intent).unwrap();
        let verifier = native.observe(&self.authority);
        let original = Original {
            intent,
            checkpoint: checkpoint_bytes(&verifier).unwrap(),
        };
        self.validate_original(&original).unwrap();
        let directory = self.authority.directory.ensure_child("setup").unwrap();
        let original =
            super::tests::retain_explicit_request(self, &directory, &original, || utc, options);
        let path = original.directory().path().join("transaction");
        let mut http = NativeReadHttp::start_config(
            &self.wallet_config().unwrap(),
            Arc::clone(native.chain.state()),
        );
        original
            .request(original.terms.signing_deadline(options.deadline).unwrap())
            .prepare(&self.wallet().unwrap(), &path)
            .unwrap();
        let signed = self
            .verify_wallet(original.directory(), &original, options.deadline)
            .unwrap();
        http.finish();
        assert!(!path.join("submission.json").exists());
        signed
    }

    fn bootstrap_native_retain(&self, carrier: &FinalityVerifier, deadline: Instant) {
        self.authority.validate_profile().unwrap();
        let directory = self.authority.directory.open_child("setup").unwrap();
        let original = journal::required_original(&directory, self.purpose().unwrap()).unwrap();
        self.validate_original(&original).unwrap();
        let signed = self
            .verify_wallet(original.directory(), &original, deadline)
            .unwrap();
        self.validate_carrier(&original, &verify_carrier(carrier, &signed).unwrap())
            .unwrap();
        original
            .directory()
            .write_atomic(
                "carrier.nrt",
                &checkpoint_bytes(carrier).unwrap(),
                PublishMode::CreateNew,
            )
            .unwrap();
    }
}
