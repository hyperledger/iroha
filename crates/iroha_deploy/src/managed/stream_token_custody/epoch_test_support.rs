//! Test-only generated Configure retention from native absence; execution uses the existing owner.
use super::*;
use crate::managed::native_operation::attempts::metadata;
use crate::managed::native_operation::test_support::native_fixture::NativeFixture;

impl ManagedStreamTokenCustody {
    pub(in crate::managed) fn bootstrap_native_configure_generated(
        &mut self,
        native: &mut NativeFixture,
        policy: &SignerCustodyPolicyV1,
        authorization: &BootstrapChildAuthorization<'_>,
        options: &BoundedTransactionOptions,
    ) -> ManagedCustodyProgress {
        let purpose = Purpose::CustodyConfigure(self.authority.provider_id().unwrap());
        let deadline = authorization
            .validate(&self.authority, purpose, options.deadline)
            .unwrap();
        assert_eq!(
            policy,
            &authorization
                .policies()
                .provider(self.authority.provider_id().unwrap())
                .unwrap()
                .custody
        );
        assert!(Fees::from_options(options).unwrap() == *authorization.fees());
        let verifier = native.observe(&self.authority);
        let current = native.bootstrap_custody(&self.authority, policy, &verifier);
        assert!(current.current().is_none());
        let original = Original {
            selection: self.selection(&policy.binding, &current).unwrap(),
            action: Action::Configure(policy.clone()),
            checkpoint: checkpoint_bytes(&verifier).unwrap(),
        };
        self.validate_original(&original, CustodyPurpose::Configure)
            .unwrap();
        let directory = metadata::ensure_operation(&self.authority.directory, "configure").unwrap();
        journal::publish_intent(&directory, &original).unwrap();
        let account = authorization.bind_account(self.wallet().unwrap()).unwrap();
        attempts::generated(
            &directory,
            purpose,
            original.digest().unwrap(),
            &HistoryScope::FixedBody,
            authorization,
            deadline,
            None,
            |attempt| {
                original
                    .request(attempt.terms(), attempt.observation()?, deadline)?
                    .inspect(&account, &attempt.wallet_path())
            },
            |attempt| {
                original
                    .request(attempt.terms(), attempt.observation()?, deadline)?
                    .retire(&account, &attempt.wallet_path())
            },
            |attempt, observation, deadline| {
                original
                    .request(attempt.terms(), observation, deadline)?
                    .retain(&account, &attempt.wallet_path())
            },
            |_, _| {
                let cut = native.observe(&self.authority);
                let current = native.bootstrap_custody(&self.authority, policy, &cut);
                assert!(matches_predecessor(
                    &original.selection,
                    current.current().map(|value| value.record())
                ));
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
        let utc = selected.terms.requested_deadline_unix_ms;
        self.bootstrap_native_configure(native, policy, utc, options)
    }
}
