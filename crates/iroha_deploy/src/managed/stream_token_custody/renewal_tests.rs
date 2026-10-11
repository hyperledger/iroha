//! Generated renewal through real original custody wallets and native executed carriers.
//! These component controls do not claim full worker renewal or running service qualification.

use super::*;
use crate::managed::native_operation::{
    test_support::{
        UnavailablePeers,
        native_fixture::{NativeFixture, NativeReadHttp, quote_instructions},
    },
    verify_carrier,
};
use iroha_data_model::{
    asset::AssetDefinitionId,
    executor::ValidationFail,
    isi::{
        InstructionBox, Log,
        error::{InstructionExecutionError, InvalidParameterError},
        sorafs::MutateSorafsStreamTokenCustody,
    },
    sorafs::stream_token_custody::{
        SorafsStreamTokenCustodyActionV1, SorafsStreamTokenCustodyRevocationV1,
    },
    transaction::{FeePaymentIntent, error::TransactionRejectionReason},
};
use iroha_primitives::numeric::Quantity;
use std::{collections::BTreeMap, sync::Arc};

pub(super) struct Fixture {
    pub(super) _temporary: tempfile::TempDir,
    pub(super) prepared: PreparedLocalnet,
    pub(super) owner: ManagedStreamTokenCustody,
    pub(super) native: NativeFixture,
    pub(super) policy: SignerCustodyPolicyV1,
    pub(super) options: BoundedTransactionOptions,
    pub(super) initial: ManagedCustodyEnrollmentInterval,
}
impl Fixture {
    pub(super) fn enrolled(validity_ms: u64) -> Self {
        Self::enrolled_with_renewal_validity(validity_ms, 120_000)
    }
    pub(super) fn enrolled_with_renewal_validity(
        validity_ms: u64,
        renewal_validity_ms: u64,
    ) -> Self {
        Self::enrolled_with_policy_lifetime(
            validity_ms,
            renewal_validity_ms,
            Duration::from_secs(600),
        )
    }
    // The deep-history campaign selects its original finite policy before native Configure;
    // ordinary renewal and short-expiry fixtures keep the existing ten-minute policy above.
    pub(super) fn enrolled_with_policy_lifetime(
        validity_ms: u64,
        renewal_validity_ms: u64,
        policy_lifetime: Duration,
    ) -> Self {
        let temporary = tempfile::tempdir().unwrap();
        let ports = crate::managed::LocalnetPorts::reserve().unwrap();
        let prepared = crate::localnet::prepare_localnet_at(
            "custody-renewal",
            &temporary.path().join("generation"),
            &ports,
            crate::localnet::LocalnetServiceProfile::StreamTokenAuthorities,
            None,
        )
        .unwrap();
        let mut owner = ManagedStreamTokenCustody::open(
            &prepared,
            crate::managed::native_operation::test_support::provider_id(&prepared, 0),
        )
        .unwrap();
        let mut policy = super::transport_tests::policy(&owner);
        policy.active_until_unix_ms = now_ms()
            .unwrap()
            .checked_add(u64::try_from(policy_lifetime.as_millis()).unwrap())
            .unwrap();
        policy.max_validity_ms = renewal_validity_ms;
        policy.max_anchor_age_ms = 120_000;
        let mut native = NativeFixture::from_generated(&prepared, &owner.authority);
        let log = quote_instructions(
            &native,
            &owner.authority.config,
            [InstructionBox::from(Log::new(
                iroha_data_model::Level::INFO,
                "custody renewal prerequisites".into(),
            ))],
        );
        assert_eq!(native.chain.commit(vec![log]), vec![true]);
        let asset = AssetDefinitionId::parse_address_literal(
            crate::genesis::profile::TAIRA_XOR_ASSET_DEFINITION_ID,
        )
        .unwrap();
        let options = BoundedTransactionOptions {
            fee_payment: FeePaymentIntent::authority(Vec::new(), None),
            max_total_fees: BTreeMap::from([(asset, Quantity::from(1_000u64))]),
            deadline: Instant::now() + Duration::from_secs(300),
        };
        drop(ports);
        assert_eq!(
            owner
                .bootstrap_native_configure(
                    &mut native,
                    &policy,
                    now_ms().unwrap() + 240_000,
                    &options
                )
                .finalized
                .unwrap()
                .height,
            3
        );
        let (initial, enrolled) = owner.bootstrap_native_enroll_with_interval(
            &mut native,
            &policy,
            |now| ManagedCustodyEnrollmentInterval {
                issued_at_unix_ms: now,
                expires_at_unix_ms: now.checked_add(validity_ms).unwrap(),
                deadline_unix_ms: now.checked_add(validity_ms).unwrap(),
            },
            &options,
        );
        assert_eq!(
            initial.expires_at_unix_ms - initial.issued_at_unix_ms,
            validity_ms
        );
        assert_eq!(initial.deadline_unix_ms, initial.expires_at_unix_ms);
        assert_eq!(enrolled.finalized.unwrap().height, 4);
        Self {
            _temporary: temporary,
            prepared,
            owner,
            native,
            policy,
            options,
            initial,
        }
    }
    pub(super) fn current(&self) -> (FinalityVerifier, VerifiedStreamTokenCustodyStateV1) {
        let checkpoint =
            fixture_observe(&self.native, &self.owner.authority, self.options.deadline).unwrap();
        let current =
            self.native
                .bootstrap_custody(&self.owner.authority, &self.policy, &checkpoint);
        (checkpoint, current)
    }
    fn select(&self, sequence: u64) -> BodyHistory {
        let utc = now_ms().unwrap() + 60_000;
        let (checkpoint, current) = self.current();
        self.select_with_deadline(sequence, utc, &checkpoint, &current)
    }
    fn select_with_deadline(
        &self,
        sequence: u64,
        utc: u64,
        checkpoint: &FinalityVerifier,
        current: &VerifiedStreamTokenCustodyStateV1,
    ) -> BodyHistory {
        let terms = Terms::new(utc, &self.options).unwrap();
        let unsigned = self
            .owner
            .select_renewal_unsigned(
                sequence,
                &self.policy,
                current,
                checkpoint,
                &terms,
                self.options.deadline,
            )
            .unwrap();
        self.owner.bootstrap_native_body(
            &self.native,
            current,
            CustodyPurpose::Renewal(sequence),
            unsigned,
            utc,
            &self.options,
        )
    }
    fn prepare(
        &self,
        history: &BodyHistory,
    ) -> (PrivateDirectory, Selected<Original>, SignedTransaction) {
        let (directory, original, scope) = history.dispatch().unwrap();
        let directory = PrivateDirectory::open_exact(directory.path()).unwrap();
        let account = AccountService::new(self.owner.authority.config.clone()).unwrap();
        journal::explicit(
            &directory,
            original,
            now_ms().unwrap() + 60_000,
            &self.options,
            &account,
            scope,
        )
        .unwrap();
        let original = self
            .owner
            .required_enrollment(CustodyPurpose::Renewal(2))
            .unwrap();
        let mut http = NativeReadHttp::start_config(
            &self.owner.authority.config,
            Arc::clone(self.native.chain.state()),
        );
        let journal::Request::Enroll(request) = original
            .request(
                original
                    .terms
                    .signing_deadline(self.options.deadline)
                    .unwrap(),
            )
            .unwrap()
        else {
            panic!("renewal must be Enroll")
        };
        account
            .prepare_stream_token_custody_enroll(
                &request,
                &original.directory().path().join("transaction"),
            )
            .unwrap();
        let signed = self
            .owner
            .verify_wallet(original.directory(), &original, self.options.deadline)
            .unwrap();
        http.finish();
        assert!(
            !original
                .directory()
                .path()
                .join("transaction/submission.json")
                .exists()
        );
        (directory, original, signed)
    }
}

pub(super) fn wait_until(utc: u64, limit: Duration) {
    let deadline = Instant::now() + limit;
    while now_ms().unwrap() < utc {
        assert!(
            Instant::now() < deadline,
            "original finite clock did not advance in bounded wait"
        );
        std::thread::sleep(Duration::from_millis(
            utc.saturating_sub(now_ms().unwrap()).min(25),
        ));
    }
}

#[test]
fn generated_renewal_changes_native_head_and_preserves_initial_and_renewed_history_offline() {
    let _guard = crate::managed::native_test_guard();
    let mut fixture = Fixture::enrolled(20_000);
    let initial = fixture
        .owner
        .retained_initial_enrollment(&fixture.policy, fixture.initial, fixture.options.deadline)
        .unwrap();
    assert_eq!(initial.statement().sequence, 1);
    assert_eq!(initial.finalized().height, 4);
    let initial_bytes = initial.bytes().to_vec();
    // Arithmetic-only selections do not produce proof or modify the genuine native head.
    let old = initial.statement();
    let midpoint = old.issued_at_unix_ms + 10_000;
    assert!(
        renewal::renewal_interval(
            old,
            &fixture.policy,
            midpoint - 1,
            fixture.policy.active_until_unix_ms,
            midpoint + 1_000
        )
        .is_err()
    );
    let capped_end = old.expires_at_unix_ms + 1;
    let capped =
        renewal::renewal_interval(old, &fixture.policy, midpoint, capped_end, midpoint + 1_000)
            .unwrap();
    assert_eq!(capped.expires_at_unix_ms, capped_end);
    assert!(
        renewal::renewal_interval(
            old,
            &fixture.policy,
            midpoint,
            old.expires_at_unix_ms,
            midpoint + 1_000
        )
        .is_err()
    );
    assert!(
        renewal::renewal_interval(old, &fixture.policy, midpoint, capped_end, capped_end + 1)
            .is_err()
    );

    let (old_checkpoint, old_current) = fixture.current();
    let observed_at = now_ms().unwrap();
    let selected_initial = fixture
        .owner
        .select_retained_current_enrollment(
            &fixture.policy,
            fixture.initial,
            initial.finalized().height,
            *initial.finalized().block_hash.as_ref(),
            &old_current,
            observed_at,
            fixture.options.deadline,
        )
        .unwrap_or_else(|error| {
            panic!(
                "initial current-use refusal: {error:?}; observed_at={observed_at}; issued={}; expires={}; policy_from={}; policy_until={}; current_height={}",
                fixture.initial.issued_at_unix_ms,
                fixture.initial.expires_at_unix_ms,
                fixture.policy.active_from_unix_ms,
                fixture.policy.active_until_unix_ms,
                old_current.height(),
            )
        });
    assert_eq!(selected_initial.bytes(), initial.bytes());
    assert_eq!(selected_initial.finalized(), initial.finalized());

    // Native current-use verification consumes real time. The clock may already have passed
    // the original midpoint: classify the genuine selection's own observation, rather than
    // assuming every host still reaches this call in the first ten seconds. The exact
    // midpoint-minus-one refusal above remains unconditional.
    let selection_started = now_ms().unwrap();
    let selection = fixture.owner.select_renewal_unsigned(
        2,
        &fixture.policy,
        &old_current,
        &old_checkpoint,
        &Terms::new(selection_started + 60_000, &fixture.options).unwrap(),
        fixture.options.deadline,
    );
    let selection_finished = now_ms().unwrap();
    match selection {
        Err(crate::managed::Error::Invalid(message))
            if message == "generated custody renewal is premature" =>
        {
            assert!(selection_started < midpoint);
        }
        Ok(unsigned) => {
            assert!(unsigned.selected_at_unix_ms >= midpoint);
            assert!(unsigned.selected_at_unix_ms >= selection_started);
            assert!(unsigned.selected_at_unix_ms <= selection_finished);
            assert_eq!(
                unsigned.statement.issued_at_unix_ms,
                unsigned.selected_at_unix_ms
            );
            assert_eq!(unsigned.statement.sequence, 2);
            assert_eq!(unsigned.statement.anchor.height, initial.finalized().height);
            assert_eq!(
                unsigned.statement.anchor.block_hash,
                *initial.finalized().block_hash.as_ref()
            );
            assert_eq!(
                unsigned.checkpoint,
                checkpoint_bytes(&old_checkpoint).unwrap()
            );
            assert_eq!(
                unsigned.selection.current.as_ref().unwrap(),
                old_current.current().unwrap().record()
            );
        }
        other => panic!("genuine midpoint selection failed: {:?}", other.err()),
    }
    assert_eq!(fixture.native.chain.height(), initial.finalized().height);
    assert_eq!(
        old_current
            .current()
            .unwrap()
            .control()
            .active_head
            .unwrap()
            .sequence,
        1
    );
    assert!(
        !fixture
            .owner
            .authority
            .directory
            .path()
            .join(renewal::directory_name(2).unwrap())
            .exists()
    );
    wait_until(
        fixture.initial.issued_at_unix_ms + 10_000,
        Duration::from_secs(12),
    );
    let original = fixture.select(2);
    let (directory, original, signed) = fixture.prepare(&original);
    let wire = signed.encode_wire_v1().unwrap();
    let operation = std::fs::read(
        original
            .directory()
            .path()
            .join("transaction/operation.json"),
    )
    .unwrap();
    let original_bytes = directory
        .read("original.nrt", MAX_CHECKPOINT_BYTES + 128 * 1024)
        .unwrap();
    assert_eq!(
        fixture.native.chain.commit(vec![signed.clone()]),
        vec![true]
    );
    let (carrier, current) = fixture.current();
    let finalized = verify_carrier(&carrier, &signed).unwrap();
    assert_eq!(finalized.height, 5);
    let state = current.current().unwrap();
    assert_eq!(state.control().active_head.unwrap().sequence, 2);
    assert_eq!(state.control().next_sequence, 3);
    assert!(state.record().active_enrollment.as_ref().unwrap() != &initial_bytes);
    let Action::Enroll {
        validity,
        enrollment,
        ..
    } = &original.action
    else {
        unreachable!()
    };
    assert!(validity.expires_at_unix_ms > fixture.initial.expires_at_unix_ms);
    assert_eq!(
        state.record().active_enrollment.as_ref().unwrap(),
        enrollment
    );
    original
        .directory()
        .write_atomic(
            "carrier.nrt",
            &checkpoint_bytes(&carrier).unwrap(),
            PublishMode::CreateNew,
        )
        .unwrap();
    // A valid current proof and an unrelated original cut cannot be joined by shape alone.
    assert!(
        fixture
            .owner
            .select_renewal_unsigned(
                3,
                &fixture.policy,
                &old_current,
                &carrier,
                &Terms::new(now_ms().unwrap() + 60_000, &fixture.options).unwrap(),
                fixture.options.deadline
            )
            .is_err()
    );
    assert!(
        fixture
            .owner
            .select_renewal_unsigned(
                2,
                &fixture.policy,
                &current,
                &carrier,
                &Terms::new(now_ms().unwrap() + 60_000, &fixture.options).unwrap(),
                fixture.options.deadline
            )
            .is_err()
    );
    let renewed_for_runtime = fixture
        .owner
        .retained_renewed_enrollment(2, &fixture.policy, fixture.options.deadline)
        .unwrap();
    fixture
        .owner
        .verify_enrollment_at(
            &renewed_for_runtime,
            &fixture.policy,
            finalized.height,
            *finalized.block_hash.as_ref(),
            &current,
            now_ms().unwrap(),
            fixture.options.deadline,
        )
        .unwrap();
    // Reconstruction selects the exact native sequence, never the highest directory name.
    fixture
        .owner
        .authority
        .directory
        .ensure_child(&renewal::directory_name(64).unwrap())
        .unwrap();
    let selected = fixture
        .owner
        .select_retained_current_enrollment(
            &fixture.policy,
            fixture.initial,
            initial.finalized().height,
            *initial.finalized().block_hash.as_ref(),
            &current,
            now_ms().unwrap(),
            fixture.options.deadline,
        )
        .unwrap();
    assert_eq!(selected.statement().sequence, 2);
    assert_eq!(selected.bytes(), renewed_for_runtime.bytes());
    assert_eq!(selected.finalized(), renewed_for_runtime.finalized());
    assert_eq!(
        selected.finalized().transaction_hash,
        finalized.transaction_hash
    );
    // Missing exact selected history cannot fall back to initial or another numbered journal.
    let retained_original = directory.path().join("original.nrt");
    let moved_original = directory.path().join("original-held.nrt");
    std::fs::rename(&retained_original, &moved_original).unwrap();
    assert!(
        fixture
            .owner
            .select_retained_current_enrollment(
                &fixture.policy,
                fixture.initial,
                finalized.height,
                *finalized.block_hash.as_ref(),
                &current,
                now_ms().unwrap(),
                fixture.options.deadline,
            )
            .is_err()
    );
    std::fs::rename(&moved_original, &retained_original).unwrap();
    assert_eq!(
        directory
            .read("original.nrt", MAX_CHECKPOINT_BYTES + 128 * 1024)
            .unwrap(),
        original_bytes
    );
    assert!(
        fixture
            .owner
            .select_retained_current_enrollment(
                &fixture.policy,
                fixture.initial,
                finalized.height,
                *finalized.block_hash.as_ref(),
                &old_current,
                now_ms().unwrap(),
                fixture.options.deadline,
            )
            .is_err()
    );
    for (height, hash) in [(0, *finalized.block_hash.as_ref()), (2, [0; 32])] {
        assert!(
            fixture
                .owner
                .select_retained_current_enrollment(
                    &fixture.policy,
                    fixture.initial,
                    height,
                    hash,
                    &current,
                    now_ms().unwrap(),
                    fixture.options.deadline,
                )
                .is_err()
        );
    }
    // A genuine predecessor proof cannot select the newly committed runtime record.
    assert!(
        fixture
            .owner
            .verify_enrollment_at(
                &renewed_for_runtime,
                &fixture.policy,
                finalized.height,
                *finalized.block_hash.as_ref(),
                &old_current,
                now_ms().unwrap(),
                fixture.options.deadline,
            )
            .is_err()
    );
    // Conversely, the new native head cannot reactivate the old retained enrollment.
    assert!(
        fixture
            .owner
            .verify_enrollment_at(
                &initial,
                &fixture.policy,
                finalized.height,
                *finalized.block_hash.as_ref(),
                &current,
                now_ms().unwrap(),
                fixture.options.deadline,
            )
            .is_err()
    );
    for (height, hash) in [
        (finalized.height + 1, *finalized.block_hash.as_ref()),
        (finalized.height, [99; 32]),
    ] {
        assert!(
            fixture
                .owner
                .verify_enrollment_at(
                    &renewed_for_runtime,
                    &fixture.policy,
                    height,
                    hash,
                    &current,
                    now_ms().unwrap(),
                    fixture.options.deadline,
                )
                .is_err()
        );
    }
    let mut changed_policy = fixture.policy.clone();
    changed_policy.max_anchor_age_ms -= 1;
    assert!(
        fixture
            .owner
            .retained_renewed_enrollment(2, &changed_policy, fixture.options.deadline)
            .is_err()
    );
    let mut changed_interval = fixture.initial;
    changed_interval.expires_at_unix_ms += 1;
    assert!(
        fixture
            .owner
            .retained_initial_enrollment(
                &fixture.policy,
                changed_interval,
                fixture.options.deadline
            )
            .is_err()
    );
    // Real current revocation rejects an otherwise unexpired renewed record. Historical
    // recovery below must still return its exact successful H5 carrier without reading H6.
    assert!(now_ms().unwrap() < renewed_for_runtime.statement().expires_at_unix_ms);
    let revoke = quote_instructions(
        &fixture.native,
        &fixture.owner.authority.config,
        [InstructionBox::from(MutateSorafsStreamTokenCustody {
            provider_id: fixture.owner.authority.provider_id().unwrap(),
            expected_revision: state.record().revision,
            expected_digest: state.anchor().state_digest,
            action: SorafsStreamTokenCustodyActionV1::Revoke(
                SorafsStreamTokenCustodyRevocationV1 {
                    signer: true,
                    attester: false,
                },
            ),
        })],
    );
    assert_eq!(fixture.native.chain.commit(vec![revoke]), vec![true]);
    let (_, revoked_for_runtime) = fixture.current();
    assert!(
        revoked_for_runtime
            .current()
            .unwrap()
            .control()
            .signer_revoked
    );
    assert!(
        fixture
            .owner
            .verify_enrollment_at(
                &renewed_for_runtime,
                &fixture.policy,
                finalized.height,
                *finalized.block_hash.as_ref(),
                &revoked_for_runtime,
                now_ms().unwrap(),
                fixture.options.deadline,
            )
            .is_err()
    );
    assert!(
        fixture
            .owner
            .select_retained_current_enrollment(
                &fixture.policy,
                fixture.initial,
                finalized.height,
                *finalized.block_hash.as_ref(),
                &revoked_for_runtime,
                now_ms().unwrap(),
                fixture.options.deadline,
            )
            .is_err()
    );
    let mut changed_options = fixture.options.clone();
    changed_options.max_total_fees.clear();
    let mut peers = UnavailablePeers::start(&fixture.prepared);
    assert!(
        fixture
            .owner
            .renew(
                2,
                original.terms.requested_deadline_unix_ms,
                &changed_options
            )
            .is_err()
    );
    assert!(
        fixture
            .owner
            .renew(
                2,
                original.terms.requested_deadline_unix_ms + 1,
                &fixture.options
            )
            .is_err()
    );
    drop(fixture.owner);
    for _ in 0..2 {
        let mut owner = ManagedStreamTokenCustody::open(
            &fixture.prepared,
            crate::managed::native_operation::test_support::provider_id(&fixture.prepared, 0),
        )
        .unwrap();
        let deadline = Instant::now() + Duration::from_secs(30);
        let progress = owner.recover_renewal(2, deadline).unwrap().unwrap();
        assert_eq!(progress.transaction_status, OperationStatus::Applied);
        assert_eq!(progress.finalized, Some(finalized));
        assert!(progress.current.is_none());
        let renewed = owner
            .retained_renewed_enrollment(2, &fixture.policy, deadline)
            .unwrap();
        assert_eq!(renewed.bytes(), enrollment);
        assert_eq!(renewed.statement().sequence, 2);
        assert_eq!(
            renewed.record_digest(),
            state.control().active_head.unwrap().record_digest
        );
        assert_eq!(*renewed.finalized(), finalized);
        assert_eq!(
            owner
                .retained_initial_enrollment(&fixture.policy, fixture.initial, deadline)
                .unwrap()
                .bytes(),
            initial_bytes
        );
        assert_eq!(
            directory
                .read("original.nrt", MAX_CHECKPOINT_BYTES + 128 * 1024)
                .unwrap(),
            original_bytes
        );
        assert_eq!(
            std::fs::read(
                original
                    .directory()
                    .path()
                    .join("transaction/operation.json")
            )
            .unwrap(),
            operation
        );
        assert_eq!(
            owner
                .verify_wallet(original.directory(), &original, deadline)
                .unwrap()
                .encode_wire_v1()
                .unwrap(),
            wire
        );
        assert!(
            !original
                .directory()
                .path()
                .join("transaction/submission.json")
                .exists()
        );
    }
    assert!(peers.requests.lock().unwrap().is_empty());
    peers.finish();
}

#[test]
fn expired_unrevoked_head_can_renew_but_real_revocation_invalidates_the_original_cas() {
    let _guard = crate::managed::native_test_guard();
    let mut fixture = Fixture::enrolled(8_000);
    wait_until(fixture.initial.expires_at_unix_ms, Duration::from_secs(10));
    let retained = fixture
        .owner
        .retained_initial_enrollment(&fixture.policy, fixture.initial, fixture.options.deadline)
        .unwrap();
    let (_, expired_current) = fixture.current();
    assert!(
        fixture
            .owner
            .select_retained_current_enrollment(
                &fixture.policy,
                fixture.initial,
                retained.finalized().height,
                *retained.finalized().block_hash.as_ref(),
                &expired_current,
                now_ms().unwrap(),
                fixture.options.deadline,
            )
            .is_err()
    );

    assert!(
        fixture
            .owner
            .verify_enrollment_at(
                &retained,
                &fixture.policy,
                retained.finalized().height,
                *retained.finalized().block_hash.as_ref(),
                &expired_current,
                now_ms().unwrap(),
                fixture.options.deadline,
            )
            .is_err()
    ); // Genuine wall-clock expiry is not revived by fresh observation.
    let original = fixture.select(2); // Genuine elapsed old interval, never a clock rewrite.
    let (_directory, original, signed) = fixture.prepare(&original);
    let (_, before) = fixture.current();
    let state = before.current().unwrap();
    let revoke = quote_instructions(
        &fixture.native,
        &fixture.owner.authority.config,
        [InstructionBox::from(MutateSorafsStreamTokenCustody {
            provider_id: fixture.owner.authority.provider_id().unwrap(),
            expected_revision: state.record().revision,
            expected_digest: state.anchor().state_digest,
            action: SorafsStreamTokenCustodyActionV1::Revoke(
                SorafsStreamTokenCustodyRevocationV1 {
                    signer: false,
                    attester: true,
                },
            ),
        })],
    );
    assert_eq!(fixture.native.chain.commit(vec![revoke]), vec![true]);
    let (revoked_checkpoint, revoked) = fixture.current();
    assert!(revoked.current().unwrap().control().attester_revoked);
    assert!(
        fixture
            .owner
            .verify_enrollment_at(
                &retained,
                &fixture.policy,
                retained.finalized().height,
                *retained.finalized().block_hash.as_ref(),
                &revoked,
                now_ms().unwrap(),
                fixture.options.deadline,
            )
            .is_err()
    );

    assert!(
        fixture
            .owner
            .select_renewal_unsigned(
                2,
                &fixture.policy,
                &revoked,
                &revoked_checkpoint,
                &Terms::new(now_ms().unwrap() + 60_000, &fixture.options).unwrap(),
                fixture.options.deadline
            )
            .is_err()
    );
    assert_eq!(
        fixture.native.chain.commit(vec![signed.clone()]),
        vec![false]
    );
    let (rejected_carrier, after) = fixture.current();
    let rejected = rejected_carrier.verified_tip().unwrap();
    assert_eq!(rejected.block().network_entrypoint_count(), 1);
    assert_eq!(
        rejected
            .block()
            .external_transactions()
            .next()
            .unwrap()
            .encode_wire_v1()
            .unwrap(),
        signed.encode_wire_v1().unwrap()
    );
    assert_eq!(
        rejected
            .block()
            .network_output_at(0)
            .unwrap()
            .1
            .result
            .as_ref()
            .unwrap_err(),
        &TransactionRejectionReason::Validation(ValidationFail::InstructionFailed(
            InstructionExecutionError::InvalidParameter(InvalidParameterError::SmartContract(
                "StreamToken custody control rejected: Conflict".into()
            ))
        ))
    );
    assert!(verify_carrier(&rejected_carrier, &signed).is_err());
    assert_eq!(
        after.current().unwrap().record(),
        revoked.current().unwrap().record()
    );
    assert!(
        fixture
            .owner
            .retained_renewed_enrollment(2, &fixture.policy, fixture.options.deadline)
            .is_err()
    );
    assert!(!original.directory().path().join("carrier.nrt").exists());
    // A generated profile from another genuine signed genesis cannot consume this native proof.
    let other_ports = crate::managed::LocalnetPorts::reserve().unwrap();
    let other = crate::localnet::prepare_localnet_at(
        "other-custody-renewal",
        &fixture._temporary.path().join("other"),
        &other_ports,
        crate::localnet::LocalnetServiceProfile::StreamTokenAuthorities,
        None,
    )
    .unwrap();
    let other_owner = ManagedStreamTokenCustody::open(
        &other,
        crate::managed::native_operation::test_support::provider_id(&other, 0),
    )
    .unwrap();
    assert_ne!(
        other_owner.authority.config.network_id,
        fixture.owner.authority.config.network_id
    );
    assert!(
        other_owner
            .verify_enrollment_at(
                &retained,
                &fixture.policy,
                retained.finalized().height,
                *retained.finalized().block_hash.as_ref(),
                &revoked,
                now_ms().unwrap(),
                fixture.options.deadline,
            )
            .is_err()
    );
    assert!(
        other_owner
            .select_renewal_unsigned(
                2,
                &fixture.policy,
                &revoked,
                &revoked_checkpoint,
                &Terms::new(now_ms().unwrap() + 60_000, &fixture.options).unwrap(),
                fixture.options.deadline
            )
            .is_err()
    );
}

#[test]
fn missing_renewal_and_out_of_range_sequences_have_no_http_or_journal_effect() {
    let _guard = crate::managed::native_test_guard();
    let temporary = tempfile::tempdir().unwrap();
    let ports = crate::managed::LocalnetPorts::reserve().unwrap();
    let prepared = crate::localnet::prepare_localnet_at(
        "custody-renewal-empty",
        &temporary.path().join("generation"),
        &ports,
        crate::localnet::LocalnetServiceProfile::StreamTokenAuthorities,
        None,
    )
    .unwrap();
    let mut owner = ManagedStreamTokenCustody::open(
        &prepared,
        crate::managed::native_operation::test_support::provider_id(&prepared, 0),
    )
    .unwrap();
    drop(ports);
    let mut peers = UnavailablePeers::start(&prepared);
    let deadline = Instant::now() + Duration::from_secs(30);
    assert!(owner.recover_renewal(2, deadline).unwrap().is_none());
    assert!(
        !owner
            .authority
            .directory
            .path()
            .join(renewal::directory_name(2).unwrap())
            .exists()
    );
    for sequence in [0, 1, 65, u64::MAX] {
        assert!(owner.recover_renewal(sequence, deadline).is_err());
        assert!(owner.advance_renewal(sequence, deadline).is_err());
    }
    assert!(peers.requests.lock().unwrap().is_empty());
    peers.finish();
}

#[test]
fn unprepared_renewal_expires_without_replacing_original_or_creating_wallet_on_recovery() {
    let _guard = crate::managed::native_test_guard();
    let mut fixture = Fixture::enrolled(8_000);
    wait_until(
        fixture.initial.issued_at_unix_ms + 4_000,
        Duration::from_secs(6),
    );
    // Select the short absolute interval only after the genuine current proof is available.
    let (checkpoint, current) = fixture.current();
    let utc = now_ms().unwrap() + 2_000;
    let history = fixture.select_with_deadline(2, utc, &checkpoint, &current);
    let (directory, original, scope) = history.dispatch().unwrap();
    let directory = PrivateDirectory::open_exact(directory.path()).unwrap();
    let account = AccountService::new(fixture.owner.authority.config.clone()).unwrap();
    journal::explicit(&directory, original, utc, &fixture.options, &account, scope).unwrap();
    let original = fixture
        .owner
        .required_enrollment(CustodyPurpose::Renewal(2))
        .unwrap();
    let wallet = original.directory().open_child("transaction").unwrap();
    let request_bytes = wallet.read("preparation.json", 4 * 1024 * 1024).unwrap();
    let wallet_inventory = wallet.entries(8).unwrap();
    let bytes = directory
        .read("original.nrt", MAX_CHECKPOINT_BYTES + 128 * 1024)
        .unwrap();
    let mut peers = UnavailablePeers::start(&fixture.prepared);
    let report = fixture
        .owner
        .recover_renewal(2, Instant::now() + Duration::from_secs(10))
        .unwrap()
        .unwrap();
    assert_eq!(report.transaction_status, OperationStatus::Absent);
    assert!(report.finalized.is_none() && report.current.is_none());
    wait_until(utc, Duration::from_secs(3));
    drop(fixture.owner);
    let mut owner = ManagedStreamTokenCustody::open(
        &fixture.prepared,
        crate::managed::native_operation::test_support::provider_id(&fixture.prepared, 0),
    )
    .unwrap();
    let report = owner
        .recover_renewal(2, Instant::now() + Duration::from_secs(30))
        .unwrap()
        .unwrap();
    assert_eq!(report.transaction_status, OperationStatus::Expired);
    assert!(report.finalized.is_none() && report.current.is_none());
    assert_eq!(
        directory
            .read("original.nrt", MAX_CHECKPOINT_BYTES + 128 * 1024)
            .unwrap(),
        bytes
    );
    assert!(
        !wallet.path().join("payload.json").exists()
            && !wallet.path().join("operation.json").exists()
    );
    assert_eq!(wallet.entries(8).unwrap(), wallet_inventory);
    assert_eq!(
        wallet.read("preparation.json", 4 * 1024 * 1024).unwrap(),
        request_bytes
    );
    // Expired paid authorization is still inspectable locally; this accessor grants no advance.
    assert_eq!(
        owner
            .inspect_local_initial_interval(&fixture.policy)
            .unwrap(),
        fixture.initial
    );
    let restored = owner
        .required_enrollment(CustodyPurpose::Renewal(2))
        .unwrap();
    assert_eq!(restored.terms.requested_deadline_unix_ms, utc);
    assert!(
        restored
            .terms
            .signing_deadline(Instant::now() + Duration::from_secs(300))
            .is_err()
    );
    assert!(peers.requests.lock().unwrap().is_empty());
    peers.finish();
}

impl Fixture {
    pub(super) fn renewal_turn(&self) -> renewal::GeneratedRenewalTurn {
        let mut diagnostic =
            crate::managed::native_operation::deadline_diagnostics::StageGuard::enter(
                crate::managed::native_operation::deadline_diagnostics::Stage::RetainedInitial,
            );
        let initial = self
            .owner
            .retained_initial_enrollment(&self.policy, self.initial, self.options.deadline)
            .unwrap();
        diagnostic.change(crate::managed::native_operation::deadline_diagnostics::Stage::Begin);
        renewal::GeneratedRenewalTurn::begin(
            &self.owner,
            &self.policy,
            Fees::from_options(&self.options).unwrap(),
            *initial.finalized(),
            self.options.deadline,
            Arc::new(std::sync::atomic::AtomicBool::new(false)),
        )
        .unwrap()
    }

    // Only transport is replaced by an actually executed NativeFixture. The fresh predecessor
    // predicate, sealed live authorization, attempt transition and canonical wallet stay shared.
    // Match production by carrying the authorization already issued for this turn through
    // body completion and request retention, without repeating its issuance preflight.
    pub(super) fn retain_generated_attempt(
        &self,
        authorization: &renewal::GeneratedRenewalAuthorization,
        history: &BodyHistory,
        historical: &VerifiedStreamTokenCustodyStateV1,
    ) -> Result<Selected<Original>> {
        use crate::managed::native_operation::authorization::DispatchAuthorization;
        let proof_started = Instant::now();
        let (_, current) = self.current();
        let retention_started = Instant::now();
        let deadline = self.options.deadline;
        let (directory, original, scope) = history.dispatch()?;
        let account = authorization.bind_account(self.owner.wallet()?)?;
        let Action::Enroll { validity, .. } = &original.action else {
            unreachable!()
        };
        let retained = attempts::generated(
            directory,
            original.dispatch_purpose()?,
            original.digest()?,
            scope,
            authorization,
            deadline,
            Some(validity.expires_at_unix_ms),
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
            |_, deadline| {
                self.owner
                    .fresh_predecessor_observation(original, historical, &current, deadline)
            },
            |attempt| {
                let observed = attempt
                    .observation()?
                    .enrollment_observed_at_unix_ms
                    .ok_or_else(|| invalid("test original observation absent"))?;
                let now = now_ms()?;
                Ok(observed <= now && now - observed <= self.policy.max_anchor_age_ms)
            },
        )
        .and_then(|()| history.retained_selected(&self.owner));
        if retained.is_err() {
            let failed_at = Instant::now();
            eprintln!(
                "generated request retention timing: fresh_proof_us={}, native_attempt_us={}, helper_total_us={}",
                retention_started.duration_since(proof_started).as_micros(),
                failed_at.duration_since(retention_started).as_micros(),
                failed_at.duration_since(proof_started).as_micros(),
            );
        }
        retained
    }
}

// Use the production cursor/challenge/persistence owner. Only peer transport is supplied
// by the genuinely executed fixture; every proof and signed attestation is still verified.
fn fixture_observe(
    native: &NativeFixture,
    authority: &ServiceAuthority,
    deadline: Instant,
) -> Result<FinalityVerifier> {
    let (checkpoint, verified) = authority.observe_finality_with_source(deadline, |_, _| {
        Ok(NativeRenewalSource {
            native,
            trace: None,
            replay_challenge: None,
        })
    })?;
    assert_eq!(verified, 4);
    assert_eq!(checkpoint.checkpoint().height(), native.chain.height());
    Ok(checkpoint)
}

#[derive(Default)]
struct ObservationTrace {
    factories: Vec<u64>,
    proofs: Vec<u64>,
    challenges: Vec<[u8; 32]>,
}
struct NativeRenewalSource<'a> {
    native: &'a NativeFixture,
    trace: Option<&'a std::cell::RefCell<ObservationTrace>>,
    replay_challenge: Option<[u8; 32]>,
}
impl crate::verify::finality::FinalitySource for NativeRenewalSource<'_> {
    type Error = std::io::Error;
    fn finality_proof(
        &self,
        height: std::num::NonZeroU64,
    ) -> std::io::Result<iroha_data_model::sumeragi_finality::SumeragiFinalityProof> {
        if let Some(trace) = self.trace {
            trace.borrow_mut().proofs.push(height.get());
        }
        crate::verify::finality::FinalitySource::finality_proof(self.native, height)
    }
    fn latest_attestation(
        &self,
        peer: &iroha_model_base::peer::PeerId,
        challenge: &[u8; 32],
    ) -> std::io::Result<crate::verify::finality::FinalityAttestation> {
        if let Some(trace) = self.trace {
            trace.borrow_mut().challenges.push(*challenge);
        }
        crate::verify::finality::FinalitySource::latest_attestation(
            self.native,
            peer,
            self.replay_challenge.as_ref().unwrap_or(challenge),
        )
    }
    fn latest_attestations(
        &self,
        peers: &[iroha_model_base::peer::PeerId],
        challenge: &[u8; 32],
    ) -> Vec<std::io::Result<crate::verify::finality::FinalityAttestation>> {
        if norito::core::decode_limits_active() {
            // In-process native producers retain the caller's original cumulative charges.
            return peers
                .iter()
                .map(|peer| self.latest_attestation(peer, challenge))
                .collect();
        }
        if let Some(trace) = self.trace {
            trace
                .borrow_mut()
                .challenges
                .extend(peers.iter().map(|_| *challenge));
        }
        // Match HttpFinalitySource's bounded independent peer reads. Borrow the native
        // fixture itself, not this source's caller-only RefCell trace. Each worker produces
        // a fresh Core attestation; Raw results retain every independent verifier check.
        let native = self.native;
        let challenge = *self.replay_challenge.as_ref().unwrap_or(challenge);
        let mut results = Vec::with_capacity(peers.len());
        for batch in peers.chunks(8) {
            results.extend(std::thread::scope(|scope| {
                let handles = batch
                    .iter()
                    .map(|peer| {
                        std::thread::Builder::new()
                            .name("native-renewal-read".into())
                            .spawn_scoped(scope, move || {
                                crate::verify::finality::FinalitySource::latest_attestation(
                                    native, peer, &challenge,
                                )
                            })
                    })
                    .collect::<Vec<_>>();
                handles
                    .into_iter()
                    .map(|handle| match handle {
                        Ok(handle) => handle.join().unwrap_or_else(|_| {
                            Err(std::io::Error::other(
                                "native renewal attestation worker panicked",
                            ))
                        }),
                        Err(error) => Err(error),
                    })
                    .collect::<Vec<_>>()
            }));
        }
        results
    }
}

pub(super) struct FixtureReads<'a> {
    pub(super) native: &'a NativeFixture,
}
impl renewal::RenewalReads for FixtureReads<'_> {
    fn observe(
        &self,
        owner: &mut ManagedStreamTokenCustody,
        policy: &SignerCustodyPolicyV1,
        deadline: Instant,
    ) -> Result<(FinalityVerifier, VerifiedStreamTokenCustodyStateV1)> {
        require_deadline(deadline)?;
        let checkpoint = fixture_observe(self.native, &owner.authority, deadline)?;
        let current = self
            .native
            .bootstrap_custody(&owner.authority, policy, &checkpoint);
        Ok((checkpoint, current))
    }
    fn retain_carrier(
        &self,
        authority: &ServiceAuthority,
        directory: &PrivateDirectory,
        checkpoint: &[u8],
        transaction: &SignedTransaction,
        height: u64,
        observed_height: u64,
        deadline: Instant,
    ) -> Result<()> {
        require_deadline(deadline)?;
        assert!(height <= observed_height);
        let mut replay = authority.decode_checkpoint(checkpoint)?;
        crate::managed::native_operation::retain_carrier_progress(
            directory,
            transaction,
            &mut replay,
            height,
            self.native,
        )?;
        Ok(())
    }
}

#[test]
fn expired_unsigned_renewal_uses_new_closed_epoch_same_body_and_recovers_exact_native_carrier() {
    use crate::managed::native_operation::authorization::DispatchAuthorization;
    use iroha_wallet::operations::NativePreparationPhase;
    let _guard = crate::managed::native_test_guard();
    let mut fixture = Fixture::enrolled(8_000);
    // Expired unrevoked use is refused, while its exact material remains a native predecessor.
    wait_until(fixture.initial.expires_at_unix_ms, Duration::from_secs(10));
    let initial = fixture
        .owner
        .retained_initial_enrollment(&fixture.policy, fixture.initial, fixture.options.deadline)
        .unwrap();
    let (_, historical) = fixture.current();
    assert!(
        fixture
            .owner
            .select_retained_current_enrollment(
                &fixture.policy,
                fixture.initial,
                initial.finalized().height,
                *initial.finalized().block_hash.as_ref(),
                &historical,
                now_ms().unwrap(),
                fixture.options.deadline,
            )
            .is_err()
    );
    let material = fixture
        .owner
        .retained_head_material_at(
            &fixture.policy,
            fixture.initial,
            initial.finalized().height,
            *initial.finalized().block_hash.as_ref(),
            &historical,
            fixture.options.deadline,
        )
        .unwrap();
    assert_eq!(material.bytes(), initial.bytes());
    let history = fixture.select(2);
    let (directory, original, scope) = history.dispatch().unwrap();
    let directory = PrivateDirectory::open_exact(directory.path()).unwrap();
    let body = directory
        .read("original.nrt", journal::MAX_ORIGINAL_BYTES)
        .unwrap();
    let account = fixture.owner.wallet().unwrap();
    let old_utc = now_ms().unwrap() + 2_000;
    journal::explicit(
        &directory,
        original,
        old_utc,
        &fixture.options,
        &account,
        scope,
    )
    .unwrap();
    let old = fixture
        .owner
        .required_enrollment(CustodyPurpose::Renewal(2))
        .unwrap();
    let request_path = old.directory().path().join("transaction");
    let old_request = std::fs::read(request_path.join("preparation.json")).unwrap();
    assert_eq!(
        old.request(fixture.options.deadline)
            .unwrap()
            .inspect(&account, &request_path)
            .unwrap()
            .phase(),
        NativePreparationPhase::RequestOnly
    );
    wait_until(old_utc, Duration::from_secs(3));
    let mut peers = UnavailablePeers::start(&fixture.prepared);
    let progress = fixture
        .owner
        .recover_renewal(2, fixture.options.deadline)
        .unwrap()
        .unwrap();
    assert_eq!(progress.transaction_status, OperationStatus::Expired);
    assert!(!request_path.join("payload.json").exists());
    let mut turn = fixture.renewal_turn();
    let authorization = turn
        .authorize_retained(&fixture.owner, &history, fixture.options.deadline)
        .unwrap();
    let selected = fixture
        .retain_generated_attempt(authorization, &history, &historical)
        .unwrap();
    assert!(selected.terms.requested_deadline_unix_ms > old_utc);
    assert_ne!(selected.directory().path(), old.directory().path());
    assert_eq!(
        old.request(fixture.options.deadline)
            .unwrap()
            .inspect(&account, &request_path)
            .unwrap()
            .phase(),
        NativePreparationPhase::Retired
    );
    assert_eq!(
        std::fs::read(request_path.join("preparation.json")).unwrap(),
        old_request
    );
    assert!(!request_path.join("payload.json").exists());
    assert_eq!(
        directory
            .read("original.nrt", journal::MAX_ORIGINAL_BYTES)
            .unwrap(),
        body
    );
    let epochs = history.root().open_child("epochs").unwrap();
    assert_eq!(epochs.entries(128).unwrap().len(), 2); // one epoch + its exact replacement claim
    let authorization = turn
        .authorize_retained(&fixture.owner, &history, fixture.options.deadline)
        .unwrap();
    assert!(
        authorization
            .check(
                Purpose::CustodyEnroll(fixture.owner.authority.provider_id().unwrap()),
                fixture.options.deadline
            )
            .is_err()
    );
    fixture
        .retain_generated_attempt(authorization, &history, &historical)
        .unwrap();
    assert_eq!(epochs.entries(128).unwrap().len(), 2);
    assert!(peers.requests.lock().unwrap().is_empty());
    peers.finish();

    // Prepare the same retained successor through the ordinary positive-fee quote path once.
    let mut http = NativeReadHttp::start_config(
        &fixture.owner.authority.config,
        Arc::clone(fixture.native.chain.state()),
    );
    let journal::Request::Enroll(request) = selected.request(fixture.options.deadline).unwrap()
    else {
        unreachable!()
    };
    account
        .prepare_stream_token_custody_enroll(
            &request,
            &selected.directory().path().join("transaction"),
        )
        .unwrap();
    let signed = fixture
        .owner
        .verify_wallet(selected.directory(), &selected, fixture.options.deadline)
        .unwrap();
    let wire = signed.encode_wire_v1().unwrap();
    http.finish();
    assert_eq!(
        fixture.native.chain.commit(vec![signed.clone()]),
        vec![true]
    );
    let (_, renewed) = fixture.current();
    assert_eq!(
        renewed
            .current()
            .unwrap()
            .control()
            .active_head
            .unwrap()
            .sequence,
        2
    );
    assert!(!selected.directory().path().join("carrier.nrt").exists());
    // Crash prefix: native success already exists, local original carrier has not been retained.
    let reconciled = fixture
        .owner
        .reconcile_generated_with_reads(
            &mut turn,
            fixture.options.deadline,
            &FixtureReads {
                native: &fixture.native,
            },
        )
        .unwrap();
    let renewal::Reconciliation::Current(recovered_head) = reconciled else {
        panic!("actual native head must finish original recovery")
    };
    let finalized = *recovered_head.finalized();
    assert_eq!(finalized.height, 5);
    assert_eq!(recovered_head.statement().sequence, 2);
    let replay = fixture
        .owner
        .authority
        .decode_checkpoint(
            &selected
                .directory()
                .read("carrier.nrt", MAX_CHECKPOINT_BYTES)
                .unwrap(),
        )
        .unwrap();
    assert_eq!(
        replay
            .verified_tip()
            .unwrap()
            .block()
            .network_entrypoint_count(),
        1
    );
    assert_eq!(
        replay
            .verified_tip()
            .unwrap()
            .block()
            .external_transactions()
            .next()
            .unwrap()
            .encode_wire_v1()
            .unwrap(),
        wire
    );
    let retained = fixture
        .owner
        .retained_renewed_enrollment(2, &fixture.policy, fixture.options.deadline)
        .unwrap();
    fixture
        .owner
        .verify_enrollment_at(
            &retained,
            &fixture.policy,
            finalized.height,
            *finalized.block_hash.as_ref(),
            &renewed,
            now_ms().unwrap(),
            fixture.options.deadline,
        )
        .unwrap();
    assert_eq!(
        directory
            .read("original.nrt", journal::MAX_ORIGINAL_BYTES)
            .unwrap(),
        body
    );
    drop(turn);
    drop(fixture.owner);
    let mut peers = UnavailablePeers::start(&fixture.prepared);
    let mut reopened = ManagedStreamTokenCustody::open(
        &fixture.prepared,
        crate::managed::native_operation::test_support::provider_id(&fixture.prepared, 0),
    )
    .unwrap();
    let recovered = reopened
        .recover_renewal(2, fixture.options.deadline)
        .unwrap()
        .unwrap();
    assert_eq!(recovered.finalized, Some(finalized));
    assert_eq!(recovered.transaction_status, OperationStatus::Applied);
    assert_eq!(
        reopened
            .verify_wallet(selected.directory(), &selected, fixture.options.deadline)
            .unwrap()
            .encode_wire_v1()
            .unwrap(),
        wire
    );
    assert!(
        !selected
            .directory()
            .path()
            .join("transaction/submission.json")
            .exists()
    );
    assert!(peers.requests.lock().unwrap().is_empty());
    peers.finish();
}

#[test]
fn renewal_selection_commitment_refuses_lost_body_and_uncertain_epoch_cannot_reissue_in_turn() {
    let _guard = crate::managed::native_test_guard();
    let fixture = Fixture::enrolled(8_000);
    wait_until(
        fixture.initial.issued_at_unix_ms + 4_000,
        Duration::from_secs(6),
    );
    let history = fixture.select(2);
    let directory = PrivateDirectory::open_exact(history.dispatch().unwrap().0.path()).unwrap();
    let body = directory
        .read("original.nrt", journal::MAX_ORIGINAL_BYTES)
        .unwrap();
    let mut peers = UnavailablePeers::start(&fixture.prepared);
    // Actual signed body publication precedes dispatch and grants no wallet phase by itself.
    assert!(
        BodyHistory::open(&fixture.owner, CustodyPurpose::Renewal(2))
            .unwrap()
            .unwrap()
            .original()
            .unwrap()
            .is_some()
    );
    assert!(!directory.path().join("attempts").exists());
    let held = fixture._temporary.path().join("held-renewal-original.nrt");
    std::fs::rename(directory.path().join("original.nrt"), &held).unwrap();
    assert!(matches!(
        fixture.owner.original_renewal_if_present(2),
        Err(crate::managed::Error::Bootstrap(
            ManagedBootstrapFailure::RetainedMaterial
        ))
    ));
    assert!(!directory.path().join("original.nrt").exists());
    std::fs::rename(&held, directory.path().join("original.nrt")).unwrap();
    let name = renewal::directory_name(2).unwrap();
    let moved = fixture._temporary.path().join("held-renewal-directory");
    std::fs::rename(history.root().path(), &moved).unwrap();
    assert!(matches!(
        fixture.owner.original_renewal_if_present(2),
        Err(crate::managed::Error::Bootstrap(
            ManagedBootstrapFailure::RetainedMaterial
        ))
    ));
    assert!(
        !fixture
            .owner
            .authority
            .directory
            .path()
            .join(&name)
            .exists()
    );
    std::fs::rename(&moved, fixture.owner.authority.directory.path().join(&name)).unwrap();
    let mut turn = fixture.renewal_turn();
    let epochs = history.root().ensure_child("epochs").unwrap();
    epochs
        .write_atomic(
            "unknown.nrt",
            b"refuse this custody",
            PublishMode::CreateNew,
        )
        .unwrap();
    assert!(
        turn.authorize_retained(&fixture.owner, &history, fixture.options.deadline)
            .is_err()
    );
    std::fs::remove_file(epochs.path().join("unknown.nrt")).unwrap();
    // Even a failure before publication consumes issue permission in this turn. Removing the
    // obstruction cannot append; a later live invocation must own its own finite authorization.
    assert!(matches!(
        turn.authorize_retained(&fixture.owner, &history, fixture.options.deadline),
        Err(crate::managed::Error::Bootstrap(
            ManagedBootstrapFailure::TransitionPending
        ))
    ));
    assert!(epochs.entries(0).unwrap().is_empty());
    let mut next_turn = fixture.renewal_turn();
    next_turn
        .authorize_retained(&fixture.owner, &history, fixture.options.deadline)
        .unwrap();
    assert_eq!(
        epochs.entries(128).unwrap(),
        vec![std::ffi::OsString::from("0001.nrt")]
    );
    assert_eq!(
        directory
            .read("original.nrt", journal::MAX_ORIGINAL_BYTES)
            .unwrap(),
        body
    );
    assert!(!directory.path().join("attempts").exists());
    assert!(peers.requests.lock().unwrap().is_empty());
    peers.finish();
}

#[test]
fn expired_original_attester_body_is_terminal_without_epoch_or_wallet_replacement() {
    let _guard = crate::managed::native_test_guard();
    let mut fixture = Fixture::enrolled_with_renewal_validity(4_000, 8_000);
    wait_until(
        fixture.initial.issued_at_unix_ms + 2_000,
        Duration::from_secs(4),
    );
    // Select the short absolute interval only after the genuine current proof is available.
    let (checkpoint, current) = fixture.current();
    let utc = now_ms().unwrap() + 2_000;
    let history = fixture.select_with_deadline(2, utc, &checkpoint, &current);
    let (directory, original, scope) = history.dispatch().unwrap();
    let directory = PrivateDirectory::open_exact(directory.path()).unwrap();
    let Action::Enroll { validity, .. } = &original.action else {
        unreachable!()
    };
    let expires = validity.expires_at_unix_ms;
    journal::explicit(
        &directory,
        original,
        utc,
        &fixture.options,
        &fixture.owner.wallet().unwrap(),
        scope,
    )
    .unwrap();
    let selected = fixture
        .owner
        .required_enrollment(CustodyPurpose::Renewal(2))
        .unwrap();
    let wallet = selected.directory().open_child("transaction").unwrap();
    let bytes = wallet.read("preparation.json", 4 * 1024 * 1024).unwrap();
    let body = directory
        .read("original.nrt", journal::MAX_ORIGINAL_BYTES)
        .unwrap();
    let inventory = wallet.entries(8).unwrap();
    wait_until(expires, Duration::from_secs(10));
    let mut peers = UnavailablePeers::start(&fixture.prepared);
    // Explicit one-intent calls cannot refresh the retained dispatch UTC or replace this body.
    // Semantic replacement requires a separate live generated issuer and native predecessor join.
    assert!(
        fixture
            .owner
            .renew(2, now_ms().unwrap() + 60_000, &fixture.options)
            .is_err()
    );
    assert!(!history.root().path().join("epochs").exists());
    assert_eq!(wallet.entries(8).unwrap(), inventory);
    assert_eq!(
        wallet.read("preparation.json", 4 * 1024 * 1024).unwrap(),
        bytes
    );
    assert_eq!(
        directory
            .read("original.nrt", journal::MAX_ORIGINAL_BYTES)
            .unwrap(),
        body
    );
    assert_eq!(
        fixture
            .owner
            .recover_renewal(2, fixture.options.deadline)
            .unwrap()
            .unwrap()
            .transaction_status,
        OperationStatus::Expired
    );
    assert!(peers.requests.lock().unwrap().is_empty());
    peers.finish();
}

#[test]
fn renewal_observation_resumes_exact_cursor_with_fresh_quorum_and_persists_catchup() {
    let _guard = crate::managed::native_test_guard();
    let mut fixture = Fixture::enrolled(4_000);
    let mut peers = UnavailablePeers::start(&fixture.prepared);
    let trace = std::cell::RefCell::new(ObservationTrace::default());
    let observe = |fixture: &Fixture| {
        fixture.owner.authority.observe_finality_with_source(
            fixture.options.deadline,
            |height, _| {
                trace.borrow_mut().factories.push(height);
                Ok(NativeRenewalSource {
                    native: &fixture.native,
                    trace: Some(&trace),
                    replay_challenge: None,
                })
            },
        )
    };
    assert!(
        read_optional(
            &fixture.owner.authority.directory,
            "current-checkpoint.nrt",
            MAX_CHECKPOINT_BYTES,
        )
        .unwrap()
        .is_none()
    );
    let (first, verified) = observe(&fixture).unwrap();
    assert_eq!(verified, 4);
    assert_eq!(first.checkpoint().height(), 4);
    assert_eq!(trace.borrow().factories, vec![1, 1]);
    assert!(trace.borrow().proofs.contains(&1));
    assert_eq!(trace.borrow().challenges.len(), 4);
    let first_challenge = trace.borrow().challenges[0];
    assert_ne!(first_challenge, [0; 32]);
    assert!(
        trace
            .borrow()
            .challenges
            .iter()
            .all(|value| value == &first_challenge)
    );
    let original = checkpoint_bytes(&first).unwrap();
    assert_eq!(
        fixture
            .owner
            .authority
            .directory
            .read("current-checkpoint.nrt", MAX_CHECKPOINT_BYTES)
            .unwrap()
            .as_slice(),
        original.as_slice()
    );

    *trace.borrow_mut() = ObservationTrace::default();
    let (resumed, verified) = observe(&fixture).unwrap();
    assert_eq!(verified, 4);
    assert_eq!(checkpoint_bytes(&resumed).unwrap(), original);
    assert_eq!(trace.borrow().factories, vec![4]);
    assert!(!trace.borrow().proofs.contains(&1));
    assert_eq!(trace.borrow().challenges.len(), 4);
    let resumed_challenge = trace.borrow().challenges[0];
    assert_ne!(resumed_challenge, first_challenge);
    assert!(
        trace
            .borrow()
            .challenges
            .iter()
            .all(|value| value == &resumed_challenge)
    );

    // Valid signatures over a previous challenge must not renew the retained cursor.
    *trace.borrow_mut() = ObservationTrace::default();
    let stale = fixture.owner.authority.observe_finality_with_source(
        fixture.options.deadline,
        |height, _| {
            trace.borrow_mut().factories.push(height);
            Ok(NativeRenewalSource {
                native: &fixture.native,
                trace: Some(&trace),
                replay_challenge: Some(first_challenge),
            })
        },
    );
    assert!(stale.is_err());
    assert_eq!(trace.borrow().factories, vec![4]);
    assert_eq!(trace.borrow().challenges.len(), 4);
    assert_ne!(trace.borrow().challenges[0], first_challenge);
    assert_eq!(
        fixture
            .owner
            .authority
            .directory
            .read("current-checkpoint.nrt", MAX_CHECKPOINT_BYTES)
            .unwrap()
            .as_slice(),
        original.as_slice()
    );

    fixture
        .owner
        .authority
        .directory
        .write_atomic("current-checkpoint.nrt", &[0xff], PublishMode::Replace)
        .unwrap();
    *trace.borrow_mut() = ObservationTrace::default();
    assert!(observe(&fixture).is_err());
    assert!(trace.borrow().factories.is_empty());
    assert!(trace.borrow().proofs.is_empty());
    assert!(trace.borrow().challenges.is_empty());
    assert_eq!(
        fixture
            .owner
            .authority
            .directory
            .read("current-checkpoint.nrt", MAX_CHECKPOINT_BYTES)
            .unwrap()
            .as_slice(),
        [0xff].as_slice()
    );
    fixture
        .owner
        .authority
        .directory
        .write_atomic("current-checkpoint.nrt", &original, PublishMode::Replace)
        .unwrap();

    // A real paid native successor must be caught up from the retained H4, never accepted
    // through the cursor alone. This exercises the same persistence owner as production.
    let transaction = quote_instructions(
        &fixture.native,
        &fixture.owner.authority.config,
        [InstructionBox::from(Log::new(
            iroha_data_model::Level::INFO,
            "renewal observation successor".into(),
        ))],
    );
    assert_eq!(fixture.native.chain.commit(vec![transaction]), vec![true]);
    assert_eq!(fixture.native.chain.height(), 5);
    *trace.borrow_mut() = ObservationTrace::default();
    let (advanced, verified) = observe(&fixture).unwrap();
    assert_eq!(verified, 4);
    assert_eq!(advanced.checkpoint().height(), 5);
    assert_eq!(trace.borrow().factories, vec![4]);
    assert!(!trace.borrow().proofs.contains(&1));
    assert_eq!(trace.borrow().challenges.len(), 4);
    assert_ne!(trace.borrow().challenges[0], resumed_challenge);
    let retained = fixture
        .owner
        .authority
        .directory
        .read("current-checkpoint.nrt", MAX_CHECKPOINT_BYTES)
        .unwrap();
    assert_eq!(
        retained.as_slice(),
        checkpoint_bytes(&advanced).unwrap().as_slice()
    );
    assert_eq!(
        fixture
            .owner
            .authority
            .decode_checkpoint(&retained)
            .unwrap(),
        advanced
    );
    *trace.borrow_mut() = ObservationTrace::default();
    let expired =
        fixture
            .owner
            .authority
            .observe_finality_with_source(Instant::now(), |height, _| {
                trace.borrow_mut().factories.push(height);
                Ok(NativeRenewalSource {
                    native: &fixture.native,
                    trace: Some(&trace),
                    replay_challenge: None,
                })
            });
    assert!(expired.is_err());
    assert!(trace.borrow().factories.is_empty());
    assert_eq!(
        fixture
            .owner
            .authority
            .directory
            .read("current-checkpoint.nrt", MAX_CHECKPOINT_BYTES)
            .unwrap(),
        retained
    );
    assert!(peers.requests.lock().unwrap().is_empty());
    peers.finish();
}

#[test]
fn generated_pending_signed_body_requires_fresh_quorum_before_dispatch_and_preserves_original() {
    use iroha_wallet::operations::NativePreparationPhase;

    let _guard = crate::managed::native_test_guard();
    let mut fixture = Fixture::enrolled(4_000);
    wait_until(
        fixture.initial.issued_at_unix_ms + 2_000,
        Duration::from_secs(4),
    );
    let mut turn = fixture.renewal_turn();
    let history = fixture.select(2);
    let (directory, original, signed) = fixture.prepare(&history);
    let wire = signed.encode_wire_v1().unwrap();
    let terms = original.terms.clone();
    let wallet = original.directory().open_child("transaction").unwrap();
    let inventory = wallet.entries(8).unwrap();
    let records = ["preparation.json", "payload.json", "operation.json"]
        .map(|name| (name, wallet.read(name, 4 * 1024 * 1024).unwrap()));
    let body = directory
        .read("original.nrt", journal::MAX_ORIGINAL_BYTES)
        .unwrap();
    let anchor = history
        .root()
        .read("anchor.nrt", MAX_CHECKPOINT_BYTES)
        .unwrap();
    let selection = history.root().read("original.nrt", 128 * 1024).unwrap();
    assert_eq!(
        history.outer_bytes().unwrap().as_slice(),
        selection.as_slice()
    );
    let account = fixture.owner.wallet().unwrap();
    assert_eq!(
        original
            .request(fixture.options.deadline)
            .unwrap()
            .inspect(&account, wallet.path())
            .unwrap()
            .phase(),
        NativePreparationPhase::Signed
    );
    assert_eq!(fixture.native.chain.height(), 4);
    assert!(!original.directory().path().join("carrier.nrt").exists());
    assert!(!wallet.path().join("submission.json").exists());

    // The material phase sees native head 1 and an existing signed Renewal 2. It must enter
    // pending dispatch, preserve the paid body, and reach the ordinary fresh HTTP quorum gate.
    // This transport refuses that gate; it supplies no invented pending or successful receipt.
    let mut peers = UnavailablePeers::start(&fixture.prepared);
    let result = fixture.owner.reconcile_generated_with_reads(
        &mut turn,
        fixture.options.deadline,
        &FixtureReads {
            native: &fixture.native,
        },
    );
    assert!(matches!(
        result,
        Err(crate::managed::Error::Invalid(message))
            if message == "fresh native operation quorum unavailable"
    ));
    {
        let requests = peers.requests.lock().unwrap();
        for peer in 0..4 {
            assert!(requests.iter().any(|request| {
                request.peer == peer
                    && request.method == "GET"
                    && request.path.split('?').next() == Some("/v1/bridge/finality/attestation/4")
            }));
        }
        assert!(requests.iter().all(|request| {
            request.method == "GET"
                && matches!(
                    request.path.split('?').next(),
                    Some("/v1/node/capabilities" | "/v1/bridge/finality/attestation/4")
                )
        }));
    }
    peers.finish();

    assert_eq!(fixture.native.chain.height(), 4);
    assert_eq!(wallet.entries(8).unwrap(), inventory);
    for (name, bytes) in records {
        assert_eq!(wallet.read(name, 4 * 1024 * 1024).unwrap(), bytes);
    }
    assert!(!wallet.path().join("submission.json").exists());
    assert!(!original.directory().path().join("carrier.nrt").exists());
    assert!(!original.directory().path().join("replay.nrt").exists());
    assert_eq!(
        directory
            .read("original.nrt", journal::MAX_ORIGINAL_BYTES)
            .unwrap(),
        body
    );
    assert_eq!(
        history
            .root()
            .read("anchor.nrt", MAX_CHECKPOINT_BYTES)
            .unwrap(),
        anchor
    );
    assert_eq!(
        history.root().read("original.nrt", 128 * 1024).unwrap(),
        selection
    );
    let retained = fixture
        .owner
        .required_enrollment(CustodyPurpose::Renewal(2))
        .unwrap();
    assert_eq!(retained.directory().path(), original.directory().path());
    assert!(retained.terms == terms);
    let prepared = retained
        .request(fixture.options.deadline)
        .unwrap()
        .inspect(&account, wallet.path())
        .unwrap();
    assert_eq!(prepared.phase(), NativePreparationPhase::Signed);
    assert_eq!(
        prepared
            .into_signed_transaction()
            .unwrap()
            .encode_wire_v1()
            .unwrap(),
        wire
    );
}

#[path = "renewal_tests/batch_tests.rs"]
mod batch_tests;
