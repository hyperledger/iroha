//! Test-only generated selection using a real native cut, followed by the existing wallet/carrier owner.
use super::*;
use crate::managed::native_operation::test_support::native_fixture::NativeFixture;
use crate::managed::native_operation::{Fees, authorization::DispatchAuthorization};

impl ManagedInitialReservePolicy {
    pub(in crate::managed) fn bootstrap_native_generated(
        &mut self,
        native: &mut NativeFixture,
        policy: &ReserveAuthorityPolicyV1,
        authorization: &BootstrapChildAuthorization<'_>,
        options: &BoundedTransactionOptions,
    ) -> ManagedReservePolicyProgress {
        let deadline = authorization
            .validate(&self.authority, Purpose::ReservePolicy, options.deadline)
            .unwrap();
        assert_eq!(policy, &authorization.policies().network.reserve);
        assert!(Fees::from_options(options).unwrap() == *authorization.fees());
        let verifier = native.observe(&self.authority);
        let original = Original {
            selection: self.selection(policy).unwrap(),
            policy: policy.clone(),
            checkpoint: checkpoint_bytes(&verifier).unwrap(),
        };
        self.validate_original(&original).unwrap();
        let directory = self.authority.directory.ensure_child("set").unwrap();
        journal::publish_intent(&directory, &original).unwrap();
        let account = authorization
            .bind_account(AccountService::new(self.authority.config.clone()).unwrap())
            .unwrap();
        attempts::generated(
            crate::managed::native_operation::attempts::GeneratedSelection {
                operation: &directory,
                purpose: Purpose::ReservePolicy,
                semantic: original.digest().unwrap(),
                scope: &crate::managed::native_operation::attempts::HistoryScope::FixedBody,
                authorization,
                deadline,
                body_expiry: None,
            },
            |attempt| {
                account
                    .inspect_initial_reserve_policy_preparation(
                        &attempt.wallet_path(),
                        &original.request(attempt.terms(), deadline),
                    )
                    .map_err(|_| invalid("test reserve inspection failed"))
            },
            |attempt| {
                account
                    .retire_initial_reserve_policy_unprepared(
                        &attempt.wallet_path(),
                        &original.request(attempt.terms(), deadline),
                    )
                    .map_err(|_| invalid("test reserve retirement failed"))
            },
            |attempt, _, deadline| {
                account
                    .retain_initial_reserve_policy_request(
                        &original.request(attempt.terms(), deadline),
                        &attempt.wallet_path(),
                    )
                    .map_err(|_| invalid("test reserve request retention failed"))
            },
            |_, _| {
                let cut = native.observe(&self.authority);
                let state = native
                    .policy_proof(&self.authority.config.account)
                    .verify(
                        self.authority.config.chain.as_ref(),
                        self.authority.config.network_id,
                        &self.authority.config.account,
                        policy,
                        iroha_core::state::State::native_world_schema_hash_v1().unwrap(),
                        &cut.verified_tip().unwrap(),
                    )
                    .unwrap();
                assert!(state.current().is_none());
                assert_eq!(cut.checkpoint().height(), verifier.checkpoint().height());
                Ok(Observation::ordinary())
            },
            |_| Ok(true),
        )
        .unwrap();
        let selected = journal::required_original(&directory).unwrap();
        assert!(matches!(
            selected.attempt().origin(),
            attempts::Origin::Generated { .. }
        ));
        assert!(
            !selected
                .directory()
                .path()
                .join("transaction/payload.json")
                .exists()
        );
        assert!(selected.attempt().origin() == &authorization.origin().unwrap());
        // Preserve the actual generated selection; the explicit setup helper requires empty custody.
        self.bootstrap_native_selected(native, &selected, &account, options)
    }
}
