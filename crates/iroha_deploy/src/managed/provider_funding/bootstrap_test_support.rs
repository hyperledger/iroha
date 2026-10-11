//! Test-only complete economics using the sole funding selection and each actual child owner.
use super::*;
use crate::managed::native_operation::Terms;
use crate::managed::native_operation::test_support::native_fixture::{
    NativeFixture, NativeReadHttp,
};
use iroha_wallet::operations::BoundedTransactionOptions;
use std::sync::Arc;

impl ProviderFundingBootstrap {
    // Finish all genuine child production before freshly recovering retained originals.
    // The original fees move once; no current proof or selection graph crosses this boundary.
    #[inline(never)]
    pub(in crate::managed) fn bootstrap_native(
        &mut self,
        native: &mut NativeFixture,
        policy: &ReserveAuthorityPolicyV1,
        utc: u64,
        options: &BoundedTransactionOptions,
    ) -> ProviderFundingProgress {
        let fees = self.bootstrap_native_children(native, policy, utc, options);
        self.recover_local_selected_if_present(policy, &fees, options.deadline)
            .unwrap()
            .unwrap()
    }

    #[inline(never)]
    fn bootstrap_native_children(
        &mut self,
        native: &mut NativeFixture,
        policy: &ReserveAuthorityPolicyV1,
        utc: u64,
        options: &BoundedTransactionOptions,
    ) -> Fees {
        self.authority.validate_profile().unwrap();
        self.validate_policy(policy).unwrap();
        let plan = self.plan().unwrap();
        let mut verifier = native.observe(&self.authority);
        let mut current = native.bootstrap_reserve(&self.authority, policy, &verifier);
        let original = Original::select(
            &plan,
            policy,
            &current,
            &verifier,
            Fees::from_options(options).unwrap(),
        )
        .unwrap();
        self.validate_original(&plan, &original).unwrap();
        let directory = self.authority.directory.ensure_child("funding").unwrap();
        original::publish(&directory, &plan, &original).unwrap();
        let child_utc = Terms::new(utc, options).unwrap().signing_deadline_unix_ms;
        let child_options = original.fees.options(options.deadline);
        let manager = self.authority.config.clone();
        let operator = self.authority.issuer_operator_config().unwrap();
        if let Some(intent) = original.top_up() {
            let mut request = ManagedReserveTopUpRequest::open(
                &self.authority.prepared,
                self.authority.provider_id().unwrap(),
            )
            .unwrap();
            let mut http =
                NativeReadHttp::start_config(&operator, Arc::clone(native.chain.state()));
            let signed = request
                .funding_prepare(&intent, child_utc, &child_options, &current, &verifier)
                .unwrap();
            http.finish();
            verifier = native.bootstrap_commit(&self.authority, &signed);
            request.funding_retain(&verifier, options.deadline).unwrap();
            let history = request
                .recover_selected_if_present(&intent, &original.fees, child_options.deadline)
                .unwrap()
                .unwrap()
                .historical()
                .unwrap()
                .clone();
            assert_eq!(history.original().height, verifier.checkpoint().height());
            drop(request);
            current = native.bootstrap_reserve(&self.authority, policy, &verifier);
            let selected = SelectedStage::select(
                Stage::Approval,
                &original,
                &current,
                &verifier,
                history.original().height,
            )
            .unwrap();
            self.validate_stage(
                &selected,
                Stage::Approval,
                &original,
                history.original().height,
            )
            .unwrap();
            stage::publish(&directory, Stage::Approval, &original, &selected).unwrap();
            let intent = selected.approval(&original).unwrap();
            let approval = ManagedReserveTopUpApproval::open(
                &self.authority.prepared,
                self.authority.provider_id().unwrap(),
            )
            .unwrap();
            let mut http = NativeReadHttp::start_config(&manager, Arc::clone(native.chain.state()));
            let signed = approval
                .funding_prepare(
                    &history,
                    &intent,
                    child_utc,
                    &child_options,
                    &current,
                    &verifier,
                )
                .unwrap();
            http.finish();
            verifier = native.bootstrap_commit(&self.authority, &signed);
            approval
                .funding_retain(&history, &verifier, options.deadline)
                .unwrap();
            drop(approval);
            current = native.bootstrap_reserve(&self.authority, policy, &verifier);
        }
        let credit_stage = SelectedStage::select(
            Stage::Credit,
            &original,
            &current,
            &verifier,
            verifier.checkpoint().height(),
        )
        .unwrap();
        self.validate_stage(
            &credit_stage,
            Stage::Credit,
            &original,
            verifier.checkpoint().height(),
        )
        .unwrap();
        stage::publish(&directory, Stage::Credit, &original, &credit_stage).unwrap();
        let intent = credit_stage.credit(&original).unwrap();
        let credit = ManagedInitialProviderCredit::open(
            &self.authority.prepared,
            self.authority.provider_id().unwrap(),
        )
        .unwrap();
        let mut http = NativeReadHttp::start_config(&manager, Arc::clone(native.chain.state()));
        let signed = credit
            .funding_prepare(&intent, child_utc, &child_options, &current, &verifier)
            .unwrap();
        http.finish();
        verifier = native.bootstrap_commit(&self.authority, &signed);
        credit.funding_retain(&verifier, options.deadline).unwrap();
        drop(credit);
        current = native.bootstrap_reserve(&self.authority, policy, &verifier);
        assert_eq!(current.credit(), Some(&intent.record));
        let capacity = ManagedProviderCapacity::open(
            &self.authority.prepared,
            self.authority.provider_id().unwrap(),
        )
        .unwrap();
        let mut http = NativeReadHttp::start_config(&operator, Arc::clone(native.chain.state()));
        let signed = capacity
            .funding_prepare(
                policy,
                &credit_stage.partition,
                &intent.record,
                verifier.checkpoint().height(),
                child_utc,
                &child_options,
                &current,
                &verifier,
            )
            .unwrap();
        http.finish();
        verifier = native.bootstrap_commit(&self.authority, &signed);
        capacity
            .funding_retain(&verifier, options.deadline)
            .unwrap();
        drop(capacity);
        original.fees
    }
}
