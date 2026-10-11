//! Test-only preparation through the custody owner using genuine selected native cuts.
use super::*;
use crate::managed::native_operation::test_support::native_fixture::{
    NativeFixture, NativeReadHttp,
};
use std::sync::Arc;

/// Supplies an actual State proof at the exact retained native checkpoint.
pub(super) struct NativeEnrollmentReads<'a>(pub(super) &'a NativeFixture);
impl body_history::EnrollmentReads for NativeEnrollmentReads<'_> {
    fn historical(
        &self,
        owner: &ManagedStreamTokenCustody,
        policy: &SignerCustodyPolicyV1,
        checkpoint: &FinalityVerifier,
        deadline: Instant,
    ) -> Result<VerifiedStreamTokenCustodyStateV1> {
        require_deadline(deadline)?;
        assert_eq!(checkpoint.checkpoint().height(), self.0.chain.height());
        Ok(self
            .0
            .bootstrap_custody(&owner.authority, policy, checkpoint))
    }
}

impl ManagedStreamTokenCustody {
    pub(super) fn bootstrap_native_body(
        &self,
        native: &NativeFixture,
        purpose: CustodyPurpose,
        unsigned: body_history::UnsignedEnrollment,
        utc: u64,
        options: &BoundedTransactionOptions,
    ) -> BodyHistory {
        // TODO: Remove this timing scope and static phases after native interval cost is localized.
        let _timing = crate::custody_timing::Scope::enter();
        eprintln!("custody-body phase: helper-enter");
        let terms = Terms::new(utc, options).unwrap();
        let turn = SigningTurn::Explicit(&terms);
        let checkpoint = self
            .authority
            .decode_checkpoint(&unsigned.checkpoint)
            .unwrap();
        let policy = body_history::selected_policy(&unsigned.selection).unwrap();
        eprintln!("custody-body phase: selection-decoded native-current-start");
        let current = native.bootstrap_custody(&self.authority, &policy, &checkpoint);
        eprintln!("custody-body phase: native-current-complete initialize-start");
        let history = BodyHistory::initialize(
            self,
            purpose,
            unsigned,
            &terms.fees,
            &turn,
            options.deadline,
        )
        .unwrap();
        eprintln!("custody-body phase: initialize-complete prefix-assertions-start");
        assert!(history.has_pending());
        assert!(history.original().unwrap().is_none());
        assert!(history.dispatch().is_err());
        eprintln!("custody-body phase: prefix-assertions-complete finish-start");
        let history = history
            .finish_pending_with_reads(
                self,
                &current,
                &turn,
                options.deadline,
                &NativeEnrollmentReads(native),
            )
            .unwrap();
        eprintln!("custody-body phase: finish-complete");
        history
    }

    pub(in crate::managed) fn bootstrap_native_configure(
        &mut self,
        native: &mut NativeFixture,
        policy: &SignerCustodyPolicyV1,
        utc: u64,
        options: &BoundedTransactionOptions,
    ) -> ManagedCustodyProgress {
        self.authority.validate_profile().unwrap();
        self.validate_policy(policy).unwrap();
        let verifier = native.observe(&self.authority);
        let current = native.bootstrap_custody(&self.authority, policy, &verifier);
        assert!(current.current().is_none());
        let original = Original {
            selection: self.selection(&policy.binding, &current).unwrap(),
            action: Action::Configure(policy.clone()),
            checkpoint: checkpoint_bytes(&verifier).unwrap(),
        };
        self.bootstrap_native_original(native, CustodyPurpose::Configure, &original, utc, options);
        self.recover_configure_selected_if_present(
            policy,
            &Fees::from_options(options).unwrap(),
            options.deadline,
        )
        .unwrap()
        .unwrap()
    }

    pub(in crate::managed) fn bootstrap_native_enroll(
        &mut self,
        native: &mut NativeFixture,
        policy: &SignerCustodyPolicyV1,
        interval: ManagedCustodyEnrollmentInterval,
        options: &BoundedTransactionOptions,
    ) -> ManagedCustodyProgress {
        self.bootstrap_native_enroll_with_interval(native, policy, |_| interval, options)
            .1
    }

    // Select a test's original short interval only after authenticating all prerequisites.
    // The interval is then immutable and every ordinary signing/expiry check still applies.
    pub(super) fn bootstrap_native_enroll_with_interval(
        &mut self,
        native: &mut NativeFixture,
        policy: &SignerCustodyPolicyV1,
        select_interval: impl FnOnce(u64) -> ManagedCustodyEnrollmentInterval,
        options: &BoundedTransactionOptions,
    ) -> (ManagedCustodyEnrollmentInterval, ManagedCustodyProgress) {
        self.authority.validate_profile().unwrap();
        self.validate_policy(policy).unwrap();
        let configured = self.authority.directory.open_child("configure").unwrap();
        let configuration = journal::required_original(&configured).unwrap();
        let transaction = self
            .verify_wallet(configuration.directory(), &configuration, options.deadline)
            .unwrap();
        let finalized = self
            .authority
            .retained_finality(configuration.directory(), &transaction)
            .unwrap()
            .unwrap();
        let verifier = native.observe(&self.authority);
        let current = native.bootstrap_custody(&self.authority, policy, &verifier);
        let state = current.current().unwrap();
        assert_eq!(state.control().policy, *policy);
        assert_eq!(state.record().execution_height, finalized.height);
        assert_eq!(state.record().authority, self.authority.config.account);
        assert_eq!(state.record().revision, 1);
        assert!(!state.control().signer_revoked && !state.control().attester_revoked);
        assert!(state.control().active_head.is_none());
        let now = now_ms().unwrap();
        let interval = select_interval(now);
        validate_interval(interval, now).unwrap();
        let unsigned = self
            .unsigned_enrollment(policy, &current, &verifier, interval, now)
            .unwrap();
        let body = self.bootstrap_native_body(
            native,
            CustodyPurpose::InitialEnroll,
            unsigned,
            interval.deadline_unix_ms,
            options,
        );
        self.bootstrap_native_enrollment_original(
            native,
            CustodyPurpose::InitialEnroll,
            &body,
            interval.deadline_unix_ms,
            options,
        );
        let progress = self
            .recover_enroll_selected_if_present(
                policy,
                &Fees::from_options(options).unwrap(),
                options.deadline,
            )
            .unwrap()
            .unwrap();
        (interval, progress)
    }

    pub(super) fn bootstrap_native_original(
        &self,
        native: &mut NativeFixture,
        purpose: CustodyPurpose,
        original: &Original,
        utc: u64,
        options: &BoundedTransactionOptions,
    ) {
        self.validate_original(original, purpose).unwrap();
        let directory = self
            .authority
            .directory
            .ensure_child(&purpose.directory_name().unwrap())
            .unwrap();
        journal::publish_intent(&directory, original).unwrap();
        let account = AccountService::new(self.authority.config.clone()).unwrap();
        journal::explicit(
            &directory,
            original,
            utc,
            options,
            &account,
            &HistoryScope::FixedBody,
        )
        .unwrap();
        let original = journal::required_original(&directory).unwrap();
        self.bootstrap_native_selected(native, &original, &account, options);
    }

    fn bootstrap_native_enrollment_original(
        &self,
        native: &mut NativeFixture,
        purpose: CustodyPurpose,
        history: &BodyHistory,
        utc: u64,
        options: &BoundedTransactionOptions,
    ) {
        let (directory, original, scope) = history.dispatch().unwrap();
        self.validate_original(original, purpose).unwrap();
        let account = AccountService::new(self.authority.config.clone()).unwrap();
        journal::explicit(directory, original, utc, options, &account, scope).unwrap();
        let selected = self.required_enrollment(purpose).unwrap();
        self.bootstrap_native_selected(native, &selected, &account, options);
    }

    fn bootstrap_native_selected(
        &self,
        native: &mut NativeFixture,
        original: &Selected<Original>,
        account: &AccountService,
        options: &BoundedTransactionOptions,
    ) {
        let directory = original.directory();
        let mut http =
            NativeReadHttp::start_config(&self.authority.config, Arc::clone(native.chain.state()));
        let path = directory.path().join("transaction");
        match original
            .request(original.terms.signing_deadline(options.deadline).unwrap())
            .unwrap()
        {
            journal::Request::Configure(request) => {
                account.prepare_stream_token_custody_configure(&request, &path)
            }
            journal::Request::Enroll(request) => {
                account.prepare_stream_token_custody_enroll(&request, &path)
            }
        }
        .unwrap();
        let signed = self
            .verify_wallet(directory, original, options.deadline)
            .unwrap();
        http.finish();
        assert!(!path.join("submission.json").exists());
        let carrier = native.bootstrap_commit(&self.authority, &signed);
        assert!(
            carrier.checkpoint().height()
                > self
                    .authority
                    .decode_checkpoint(&original.checkpoint)
                    .unwrap()
                    .checkpoint()
                    .height()
        );
        directory
            .write_atomic(
                "carrier.nrt",
                &checkpoint_bytes(&carrier).unwrap(),
                PublishMode::CreateNew,
            )
            .unwrap();
    }
}

// Component tests retain the ordinary wallet and certified native carrier. The caller must
// supply a real initial interval whose midpoint has elapsed; no generated clock is bypassed.
impl ManagedStreamTokenCustody {
    pub(in crate::managed) fn bootstrap_native_renew(
        &mut self,
        native: &mut NativeFixture,
        policy: &SignerCustodyPolicyV1,
        sequence: u64,
        utc: u64,
        options: &BoundedTransactionOptions,
    ) -> RetainedCustodyEnrollment {
        let verifier = native.observe(&self.authority);
        let current = native.bootstrap_custody(&self.authority, policy, &verifier);
        let terms = Terms::new(utc, options).unwrap();
        let unsigned = self
            .select_renewal_unsigned(
                sequence,
                policy,
                &current,
                &verifier,
                &terms,
                options.deadline,
            )
            .unwrap();
        let body = self.bootstrap_native_body(
            native,
            CustodyPurpose::Renewal(sequence),
            unsigned,
            utc,
            options,
        );
        self.bootstrap_native_enrollment_original(
            native,
            CustodyPurpose::Renewal(sequence),
            &body,
            utc,
            options,
        );
        let recovered = self
            .recover_renewal(sequence, options.deadline)
            .unwrap()
            .unwrap();
        let retained = self
            .retained_renewed_enrollment(sequence, policy, options.deadline)
            .unwrap();
        assert_eq!(recovered.finalized.as_ref(), Some(retained.finalized()));
        retained
    }
}
