//! Test-only reserve preparation through its sole owner and genuine native absence proof.
use super::*;
use crate::managed::native_operation::Fees;
use crate::managed::native_operation::test_support::native_fixture::{
    NativeFixture, NativeReadHttp,
};
use iroha_fs::PublishMode;
use std::sync::Arc;

impl ManagedInitialReservePolicy {
    pub(in crate::managed) fn bootstrap_native(
        &mut self,
        native: &mut NativeFixture,
        policy: &ReserveAuthorityPolicyV1,
        utc: u64,
        options: &BoundedTransactionOptions,
    ) -> ManagedReservePolicyProgress {
        self.authority.validate_profile().unwrap();
        self.validate_policy(policy).unwrap();
        let verifier = native.observe(&self.authority);
        let current = native
            .policy_proof(&self.authority.config.account)
            .verify(
                &self.authority.config.chain.to_string(),
                self.authority.config.network_id,
                &self.authority.config.account,
                policy,
                iroha_core::state::State::native_world_schema_hash_v1().unwrap(),
                &verifier.verified_tip().unwrap(),
            )
            .unwrap();
        assert!(current.current().is_none());
        let original = Original {
            selection: self.selection(policy).unwrap(),
            policy: policy.clone(),
            checkpoint: checkpoint_bytes(&verifier).unwrap(),
        };
        self.validate_original(&original).unwrap();
        let directory = self.authority.directory.ensure_child("set").unwrap();
        let original =
            super::tests::retain_explicit_request(self, &directory, &original, utc, options);
        let wallet = AccountService::new(self.authority.config.clone()).unwrap();
        self.bootstrap_native_selected(native, &original, &wallet, options)
    }

    // Both explicit and generated fixtures prepare only their already-retained exact request.
    pub(super) fn bootstrap_native_selected(
        &mut self,
        native: &mut NativeFixture,
        original: &Selected<Original>,
        wallet: &AccountService,
        options: &BoundedTransactionOptions,
    ) -> ManagedReservePolicyProgress {
        let path = original.directory().path().join("transaction");
        assert_eq!(
            wallet
                .inspect_initial_reserve_policy_preparation(
                    &path,
                    &original.request(options.deadline),
                )
                .unwrap()
                .phase(),
            iroha_wallet::operations::NativePreparationPhase::RequestOnly,
        );
        let retained_request = std::fs::read(path.join("preparation.json")).unwrap();
        let mut http =
            NativeReadHttp::start_config(&self.authority.config, Arc::clone(native.chain.state()));
        wallet
            .prepare_initial_reserve_policy(
                &original.request(original.terms.signing_deadline(options.deadline).unwrap()),
                &path,
            )
            .unwrap();
        let signed =
            Self::verify_wallet(wallet, original.directory(), original, options.deadline).unwrap();
        http.finish();
        assert_eq!(
            std::fs::read(path.join("preparation.json")).unwrap(),
            retained_request
        );
        assert!(!path.join("submission.json").exists());
        let carrier = native.bootstrap_commit(&self.authority, &signed);
        let finalized =
            crate::managed::native_operation::verify_carrier(&carrier, &signed).unwrap();
        self.validate_carrier(original, &finalized).unwrap();
        original
            .directory()
            .write_atomic(
                "carrier.nrt",
                &checkpoint_bytes(&carrier).unwrap(),
                PublishMode::CreateNew,
            )
            .unwrap();
        self.recover_selected_if_present(
            &original.policy,
            &Fees::from_options(options).unwrap(),
            options.deadline,
        )
        .unwrap()
        .unwrap()
    }
}
