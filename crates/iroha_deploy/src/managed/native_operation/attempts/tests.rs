//! Real purpose-owned wallet prefixes exercise local dispatch custody only. These tests do not
//! construct native completion, current-state authority or readiness. Epoch controls obtain the
//! real non-cloneable capability from the new-start producer; local records remain non-authority.

use super::*;
use crate::managed::{
    PreparedLocalnet,
    native_operation::{
        now_ms,
        test_support::{
            UnavailablePeers,
            native_fixture::{NativeFixture, NativeReadHttp, policy, quote_instructions},
        },
    },
    service_authority::{NetworkPurpose, ServiceAuthority},
};
use iroha_data_model::{
    isi::{InstructionBox, Log},
    sorafs::reserve::ReserveAuthorityPolicyV1,
    transaction::FeePaymentIntent,
};
use iroha_primitives::numeric::Quantity;
use iroha_wallet::operations::{
    AccountService, BoundedTransactionOptions, InitialReservePolicyRequest,
    InitialReservePolicySelection,
};
use std::{
    collections::BTreeMap,
    sync::Arc,
    time::{Duration, Instant},
};

struct Fixture {
    _temporary: tempfile::TempDir,
    prepared: PreparedLocalnet,
    authority: ServiceAuthority,
    operation: PrivateDirectory,
    wallet: AccountService,
    policy: ReserveAuthorityPolicyV1,
    terms: Terms,
    deadline: Instant,
    semantic: [u8; 32],
    authorization: Option<crate::managed::service_bootstrap::GeneratedBootstrapAuthorization>,
    cancelled: Arc<std::sync::atomic::AtomicBool>,
}
impl Fixture {
    fn new() -> Self {
        Self::build(false)
    }
    fn build(authorized: bool) -> Self {
        let temporary = tempfile::tempdir().unwrap();
        let ports = crate::managed::LocalnetPorts::reserve().unwrap();
        let prepared = crate::localnet::prepare_localnet_at(
            "dispatch-prefix",
            &temporary.path().join("generation"),
            &ports,
            crate::localnet::LocalnetServiceProfile::StreamTokenAuthorities,
            None,
        )
        .unwrap();
        let deadline = Instant::now() + Duration::from_secs(600);
        let cancelled = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let authorization = if authorized {
            let mut parent =
                crate::managed::service_bootstrap::ManagedServiceBootstrap::open(&prepared)
                    .unwrap();
            parent
                .authorize_generated_startup(deadline, Arc::clone(&cancelled))
                .unwrap()
        } else {
            None
        };
        let authority =
            ServiceAuthority::open_network(&prepared, NetworkPurpose::InitialReservePolicy)
                .unwrap();
        let policy = policy(&authority);
        let options = authorization
            .as_ref()
            .map(|value| value.test_terms().options(deadline))
            .unwrap_or_else(|| BoundedTransactionOptions {
                fee_payment: FeePaymentIntent::authority(Vec::new(), None),
                max_total_fees: BTreeMap::from([(
                    policy.asset_definition.clone(),
                    Quantity::from(1_000_u64),
                )]),
                deadline,
            });
        let terms = Terms::new(now_ms().unwrap() + 1_200_000, &options).unwrap();
        let operation = authority.directory.create_child("set").unwrap();
        // The actual canonical policy is sufficient semantic input for this local-record test.
        // The concrete coordinator additionally retains its authentic original checkpoint.
        let bytes = encode(&policy, MAX_RECORD_BYTES).unwrap();
        let semantic = *Hash::new(&bytes).as_ref();
        operation
            .write_atomic("original.nrt", &bytes, PublishMode::CreateNew)
            .unwrap();
        let wallet = AccountService::new(authority.config.clone()).unwrap();
        Self {
            _temporary: temporary,
            prepared,
            authority,
            operation,
            wallet,
            policy,
            terms,
            deadline,
            semantic,
            authorization,
            cancelled,
        }
    }
    fn history(&self) -> Result<History> {
        History::read(
            &self.operation,
            Purpose::ReservePolicy,
            self.semantic,
            &crate::managed::native_operation::attempts::HistoryScope::FixedBody,
        )
    }
    fn reserve(&self) -> Attempt {
        self.history()
            .unwrap()
            .reserve(&self.operation, Origin::Explicit, self.terms.clone())
            .unwrap()
    }
    fn request(&self, attempt: &Attempt) -> InitialReservePolicyRequest {
        InitialReservePolicyRequest {
            selection: InitialReservePolicySelection {
                chain_id: self.authority.config.chain.to_string(),
                network_id: self.authority.config.network_id,
                manager: self.authority.config.account.clone(),
                policy_digest: self.policy.digest().unwrap(),
                asset_definition: self.policy.asset_definition.clone(),
                custody_account: self.policy.custody_account.clone(),
                treasury_account: self.policy.treasury_account.clone(),
                operations_authority: self.policy.operations_authority.clone(),
                decision_authority: self.policy.decision_authority.clone(),
            },
            policy: self.policy.clone(),
            deadline_unix_ms: attempt.terms().signing_deadline_unix_ms,
            options: attempt.terms().options(self.deadline),
        }
    }
    fn inspect(&self, attempt: &Attempt) -> Result<VerifiedNativePreparation> {
        self.wallet
            .inspect_initial_reserve_policy_preparation(
                &attempt.wallet_path(),
                &self.request(attempt),
            )
            .map_err(|_| invalid("test original wallet inspection failed"))
    }
    fn retain(&self, attempt: &Attempt) -> VerifiedNativePreparation {
        attempt.retain_observation(Observation::ordinary()).unwrap();
        self.wallet
            .retain_initial_reserve_policy_request(&self.request(attempt), &attempt.wallet_path())
            .unwrap()
    }
    fn commit(&self, attempt: &Attempt) {
        let retained = self.retain(attempt);
        super::commit(attempt, None, Observation::ordinary(), &retained).unwrap();
    }
    fn current_native(&self) -> NativeFixture {
        let mut native = NativeFixture::from_generated(&self.prepared, &self.authority);
        assert_eq!(native.chain.height(), 1);
        let log = quote_instructions(
            &native,
            &self.authority.config,
            [InstructionBox::from(Log::new(
                iroha_data_model::Level::INFO,
                "authenticate attempt prerequisite".into(),
            ))],
        );
        assert_eq!(native.chain.commit(vec![log]), vec![true]);
        assert_eq!(native.chain.height(), 2);
        native
    }
    fn sign(&self, attempt: &Attempt) {
        let native = NativeFixture::from_generated(&self.prepared, &self.authority);
        let mut http =
            NativeReadHttp::start_config(&self.authority.config, Arc::clone(native.chain.state()));
        self.wallet
            .prepare_initial_reserve_policy(&self.request(attempt), &attempt.wallet_path())
            .unwrap();
        http.finish();
        assert!(!attempt.wallet_path().join("submission.json").exists());
    }
}

#[test]
fn original_only_and_reserved_missing_prefixes_are_readonly_and_do_not_create_wallets() {
    let _resources = crate::managed::native_test_guard();
    let fixture = Fixture::new();
    let mut peers = UnavailablePeers::start(&fixture.prepared);
    let before = fixture.operation.entries(3).unwrap();
    assert!(fixture.history().unwrap().selected().unwrap().is_none());
    assert_eq!(fixture.operation.entries(3).unwrap(), before);
    let attempt = fixture.reserve();
    assert!(!attempt.wallet_path().exists());
    let inventory = attempt.directory.entries(7).unwrap();
    let history = fixture.history().unwrap();
    history
        .verify_wallets(|attempt| fixture.inspect(attempt))
        .unwrap();
    assert!(matches!(
        history.selected(),
        Err(crate::managed::Error::Bootstrap(
            ManagedBootstrapFailure::TransitionPending
        ))
    ));
    assert_eq!(attempt.directory.entries(7).unwrap(), inventory);
    assert!(!attempt.wallet_path().exists());
    assert!(peers.requests.lock().unwrap().is_empty());
    peers.finish();
}

#[test]
fn genuine_request_only_prefix_commits_without_http_and_preserves_canonical_request() {
    let _resources = crate::managed::native_test_guard();
    let fixture = Fixture::new();
    let mut peers = UnavailablePeers::start(&fixture.prepared);
    let attempt = fixture.reserve();
    let retained = fixture.retain(&attempt);
    assert_eq!(retained.phase(), NativePreparationPhase::RequestOnly);
    let bytes = std::fs::read(attempt.wallet_path().join("preparation.json")).unwrap();
    fixture
        .history()
        .unwrap()
        .verify_wallets(|attempt| fixture.inspect(attempt))
        .unwrap();
    assert!(!attempt.directory.path().join("committed.nrt").exists());
    commit(&attempt, None, Observation::ordinary(), &retained).unwrap();
    let history = fixture.history().unwrap();
    history
        .verify_wallets(|attempt| fixture.inspect(attempt))
        .unwrap();
    assert_eq!(history.selected().unwrap().unwrap().ordinal(), 1);
    assert_eq!(
        std::fs::read(attempt.wallet_path().join("preparation.json")).unwrap(),
        bytes
    );
    assert!(!attempt.wallet_path().join("payload.json").exists());
    assert!(peers.requests.lock().unwrap().is_empty());
    peers.finish();
}

#[test]
fn committed_missing_wallet_and_lost_attempts_are_refused_before_http_or_recreation() {
    let _resources = crate::managed::native_test_guard();
    let fixture = Fixture::new();
    let attempt = fixture.reserve();
    fixture.commit(&attempt);
    let mut peers = UnavailablePeers::start(&fixture.prepared);
    std::fs::remove_dir_all(attempt.wallet_path()).unwrap();
    let history = fixture.history().unwrap();
    assert!(
        history
            .verify_wallets(|attempt| fixture.inspect(attempt))
            .is_err()
    );
    assert!(!attempt.wallet_path().exists());
    std::fs::remove_dir_all(fixture.operation.path().join("attempts")).unwrap();
    assert!(fixture.history().is_err());
    assert!(!fixture.operation.path().join("attempts").exists());
    assert!(fixture.operation.path().join("dispatch.nrt").is_file());
    assert!(peers.requests.lock().unwrap().is_empty());
    peers.finish();
}

#[test]
fn only_exact_unpaid_first_authorization_can_recover_missing_root_commitment() {
    let _resources = crate::managed::native_test_guard();
    let fixture = Fixture::new();
    // The producer now retains Reserved before the child. Only that exact prefix can finish
    // the final Published commitment; an absent anchor is no longer a recoverable old layout.
    fixture
        .history()
        .unwrap()
        .reserve_pending(&fixture.operation, Origin::Explicit, fixture.terms.clone())
        .unwrap();
    let history = fixture.history().unwrap();
    assert!(history.reservation_pending());
    assert!(!fixture.operation.path().join("attempts").exists());
    let original = history.dispatch.as_ref().unwrap().highest.clone();
    let attempt = history
        .finish_reserved(&fixture.operation, false)
        .unwrap()
        .unwrap();
    assert!(attempt.authorization == original);
    assert!(!fixture.history().unwrap().reservation_pending());
    fixture.commit(&attempt);
    std::fs::remove_file(fixture.operation.path().join("dispatch.nrt")).unwrap();
    assert!(fixture.history().is_err());
    assert!(!fixture.operation.path().join("dispatch.nrt").exists());
}

#[test]
fn uncommitted_genuine_signed_and_payload_prefixes_cannot_be_selected_or_replaced() {
    let _resources = crate::managed::native_test_guard();
    let fixture = Fixture::new();
    let attempt = fixture.reserve();
    fixture.retain(&attempt);
    fixture.sign(&attempt);
    let signed = fixture.inspect(&attempt).unwrap();
    assert_eq!(signed.phase(), NativePreparationPhase::Signed);
    assert!(commit(&attempt, None, Observation::ordinary(), &signed).is_err());
    assert!(
        fixture
            .history()
            .unwrap()
            .verify_wallets(|attempt| fixture.inspect(attempt))
            .is_err()
    );
    std::fs::remove_file(attempt.wallet_path().join("operation.json")).unwrap();
    let payload = fixture.inspect(&attempt).unwrap();
    assert_eq!(payload.phase(), NativePreparationPhase::PayloadRetained);
    assert!(commit(&attempt, None, Observation::ordinary(), &payload).is_err());
    assert!(
        fixture
            .history()
            .unwrap()
            .verify_wallets(|attempt| fixture.inspect(attempt))
            .is_err()
    );
    assert!(!attempt.directory.path().join("committed.nrt").exists());
}

#[test]
fn committed_genuine_signed_and_payload_originals_remain_readonly_exact_custody() {
    let _resources = crate::managed::native_test_guard();
    let fixture = Fixture::new();
    let attempt = fixture.reserve();
    fixture.commit(&attempt);
    fixture.sign(&attempt);
    let signed = std::fs::read(attempt.wallet_path().join("operation.json")).unwrap();
    let mut peers = UnavailablePeers::start(&fixture.prepared);
    fixture
        .history()
        .unwrap()
        .verify_wallets(|attempt| fixture.inspect(attempt))
        .unwrap();
    assert_eq!(
        fixture.inspect(&attempt).unwrap().phase(),
        NativePreparationPhase::Signed
    );
    assert_eq!(
        std::fs::read(attempt.wallet_path().join("operation.json")).unwrap(),
        signed
    );
    std::fs::remove_file(attempt.wallet_path().join("operation.json")).unwrap();
    let payload = std::fs::read(attempt.wallet_path().join("payload.json")).unwrap();
    fixture
        .history()
        .unwrap()
        .verify_wallets(|attempt| fixture.inspect(attempt))
        .unwrap();
    assert_eq!(
        fixture.inspect(&attempt).unwrap().phase(),
        NativePreparationPhase::PayloadRetained
    );
    assert_eq!(
        std::fs::read(attempt.wallet_path().join("payload.json")).unwrap(),
        payload
    );
    assert!(!attempt.wallet_path().join("operation.json").exists());
    assert!(peers.requests.lock().unwrap().is_empty());
    peers.finish();
}

#[test]
fn local_retirement_requires_exact_real_unsigned_request_and_reserved_successor() {
    let _resources = crate::managed::native_test_guard();
    let fixture = Fixture::new();
    let first = fixture.reserve();
    fixture.commit(&first);
    // These are local metadata refusal/control values, not a live worker capability.
    let history = fixture.history().unwrap();
    let next = history
        .reserve(
            &fixture.operation,
            Origin::Generated {
                ordinal: 1,
                epoch: [1; 32],
                parent_intent: [2; 32],
            },
            fixture.terms.clone(),
        )
        .unwrap();
    assert!(retire_missing(&first, &next).is_err());
    let receipt = fixture
        .wallet
        .retire_initial_reserve_policy_unprepared(&first.wallet_path(), &fixture.request(&first))
        .unwrap();
    retire_request(&first, &next, &receipt).unwrap();
    let retained = fixture.retain(&next);
    commit(&next, Some(&first), Observation::ordinary(), &retained).unwrap();
    let history = fixture.history().unwrap();
    history
        .verify_wallets(|attempt| fixture.inspect(attempt))
        .unwrap();
    assert_eq!(history.selected().unwrap().unwrap().ordinal(), 2);
    assert_eq!(
        fixture.inspect(&first).unwrap().phase(),
        NativePreparationPhase::Retired
    );
    assert_eq!(
        fixture.inspect(&next).unwrap().phase(),
        NativePreparationPhase::RequestOnly
    );
}

#[test]
fn record_or_namespace_change_refuses_before_any_request_creation() {
    let _resources = crate::managed::native_test_guard();
    let fixture = Fixture::new();
    let attempt = fixture.reserve();
    let history = fixture.history().unwrap();
    let path = attempt.directory.path().join("authorization.nrt");
    let original = std::fs::read(&path).unwrap();
    let mut trailing = original.clone();
    trailing.push(0);
    std::fs::write(&path, &trailing).unwrap();
    assert!(fixture.history().is_err());
    assert!(
        history
            .verify_wallets(|attempt| fixture.inspect(attempt))
            .is_err()
    );
    std::fs::write(&path, &original).unwrap();
    attempt
        .directory
        .write_atomic("foreign.nrt", b"unknown", PublishMode::CreateNew)
        .unwrap();
    assert!(fixture.history().is_err());
    assert!(!attempt.wallet_path().exists());
}

#[test]
fn live_unsigned_prefix_keeps_its_original_terms_and_request_under_a_current_epoch() {
    let _resources = crate::managed::native_test_guard();
    for retained_request in [false, true] {
        let fixture = Fixture::build(true);
        let attempt = fixture.reserve(); // Genuine ordinary original, not an epoch constructed by a test.
        if retained_request {
            fixture.retain(&attempt);
        }
        let original_authorization = attempt
            .directory
            .read("authorization.nrt", MAX_RECORD_BYTES)
            .unwrap();
        let original_request = retained_request
            .then(|| std::fs::read(attempt.wallet_path().join("preparation.json")).unwrap());
        let cap = fixture.authorization.as_ref().unwrap();
        let grant = cap.test_child(Purpose::ReservePolicy).unwrap();
        let entered = std::cell::Cell::new(false);
        let mut peers = UnavailablePeers::start(&fixture.prepared);
        generated(
            &fixture.operation,
            Purpose::ReservePolicy,
            fixture.semantic,
            &crate::managed::native_operation::attempts::HistoryScope::FixedBody,
            &grant,
            fixture.deadline,
            None,
            |attempt| fixture.inspect(attempt),
            |_| panic!("live original cannot be retired"),
            |attempt, _, _| Ok(fixture.retain(attempt)),
            |terms, _| {
                entered.set(true);
                assert!(terms == &fixture.terms);
                Ok(Observation::ordinary())
            },
            |_| Ok(true),
        )
        .unwrap();
        assert!(entered.get());
        let history = fixture.history().unwrap();
        assert_eq!(history.attempts.len(), 1);
        let selected = history.selected().unwrap().unwrap();
        assert!(selected.terms() == &fixture.terms);
        assert_eq!(
            selected
                .directory
                .read("authorization.nrt", MAX_RECORD_BYTES)
                .unwrap(),
            original_authorization
        );
        if let Some(bytes) = original_request {
            assert_eq!(
                std::fs::read(selected.wallet_path().join("preparation.json")).unwrap(),
                bytes
            );
        }
        assert_eq!(
            fixture.inspect(selected).unwrap().phase(),
            NativePreparationPhase::RequestOnly
        );
        assert!(!selected.wallet_path().join("payload.json").exists());
        let parent_root = fixture
            .prepared
            .context
            .client_config
            .parent()
            .unwrap()
            .join("runtime/service-operations/network/service-bootstrap/initial/epochs");
        assert!(!parent_root.join("0001-replacement.nrt").exists());
        assert!(peers.requests.lock().unwrap().is_empty());
        peers.finish();
    }
}

#[test]
fn cancellation_during_genuine_native_prerequisite_cannot_retain_request_or_commit_dispatch() {
    let _resources = crate::managed::native_test_guard();
    let fixture = Fixture::build(true);
    let native = fixture.current_native();
    let cap = fixture.authorization.as_ref().unwrap();
    let grant = cap.test_child(Purpose::ReservePolicy).unwrap();
    let entered = std::cell::Cell::new(false);
    let error = generated(
        &fixture.operation,
        Purpose::ReservePolicy,
        fixture.semantic,
        &crate::managed::native_operation::attempts::HistoryScope::FixedBody,
        &grant,
        fixture.deadline,
        None,
        |attempt| fixture.inspect(attempt),
        |_| panic!("no predecessor"),
        |_, _, _| panic!("cancelled prerequisite cannot reach request retention"),
        |_, _| {
            let checkpoint = native.observe(&fixture.authority);
            assert_eq!(checkpoint.verified_tip().unwrap().height(), 2);
            let proof = native.policy_proof(&fixture.authority.config.account);
            let current = proof
                .verify(
                    &fixture.authority.config.chain.to_string(),
                    fixture.authority.config.network_id,
                    &fixture.authority.config.account,
                    &fixture.policy,
                    iroha_core::state::State::native_world_schema_hash_v1().unwrap(),
                    &checkpoint.verified_tip().unwrap(),
                )
                .unwrap();
            assert!(current.current().is_none());
            entered.set(true);
            fixture
                .cancelled
                .store(true, std::sync::atomic::Ordering::Release);
            Ok(Observation::ordinary())
        },
        |_| Ok(true),
    )
    .unwrap_err();
    assert!(entered.get());
    assert!(matches!(
        error,
        crate::managed::Error::Bootstrap(ManagedBootstrapFailure::Cancelled)
    ));
    let history = fixture.history().unwrap();
    let selected = history.last().unwrap();
    assert!(!selected.is_committed());
    assert!(!selected.wallet_path().exists());
    assert!(!selected.directory.path().join("observation.nrt").exists());
    assert!(
        grant
            .check(Purpose::ReservePolicy, fixture.deadline)
            .is_err()
    );
}

#[test]
fn full_fee_binding_checks_retired_attempts_before_any_wallet_inspection() {
    let _resources = crate::managed::native_test_guard();
    let fixture = Fixture::new();
    let first = fixture.reserve();
    fixture.commit(&first);
    let mut changed = fixture.terms.clone();
    let mut changed_options = changed.options(fixture.deadline);
    changed_options.max_total_fees.clear();
    changed.fees = crate::managed::native_operation::Fees::from_options(&changed_options).unwrap();
    let origin = Origin::Generated {
        ordinal: 1,
        epoch: [3; 32],
        parent_intent: [4; 32],
    };
    assert!(
        fixture
            .history()
            .unwrap()
            .reserve(&fixture.operation, origin.clone(), changed.clone())
            .is_err()
    );
    assert!(!fixture.operation.path().join("attempts/0002").exists());
    let next = fixture
        .history()
        .unwrap()
        .reserve(&fixture.operation, origin, fixture.terms.clone())
        .unwrap();
    let receipt = fixture
        .wallet
        .retire_initial_reserve_policy_unprepared(&first.wallet_path(), &fixture.request(&first))
        .unwrap();
    retire_request(&first, &next, &receipt).unwrap();
    let retained = fixture.retain(&next);
    commit(&next, Some(&first), Observation::ordinary(), &retained).unwrap();
    let history = fixture.history().unwrap();
    assert_eq!(history.attempts.len(), 2);
    assert!(history.require_fees(&changed.fees).is_err());
    history.require_fees(&fixture.terms.fees).unwrap();
}

#[test]
fn common_semantic_bound_accepts_the_capacity_envelope_and_refuses_one_byte_over() {
    let _resources = crate::managed::native_test_guard();
    let temporary = tempfile::tempdir().unwrap();
    let operation = PrivateDirectory::open_or_create(temporary.path().join("bound")).unwrap();
    // Descriptor-bound control only. No bytes here are presented to a concrete native decoder.
    let mut bytes = vec![0x42; super::super::MAX_CHECKPOINT_BYTES + 3 * 1024 * 1024];
    operation
        .write_atomic("original.nrt", &bytes, PublishMode::CreateNew)
        .unwrap();
    assert!(
        History::read(
            &operation,
            Purpose::ReservePolicy,
            *Hash::new(&bytes).as_ref(),
            &crate::managed::native_operation::attempts::HistoryScope::FixedBody
        )
        .unwrap()
        .last()
        .is_none()
    );
    bytes.push(0);
    operation
        .write_atomic("original.nrt", &bytes, PublishMode::Replace)
        .unwrap();
    assert!(
        History::read(
            &operation,
            Purpose::ReservePolicy,
            *Hash::new(&bytes).as_ref(),
            &crate::managed::native_operation::attempts::HistoryScope::FixedBody
        )
        .is_err()
    );
}

#[test]
fn expired_missing_or_request_only_prefix_requires_a_live_epoch_and_preserves_its_retirement() {
    let _resources = crate::managed::native_test_guard();
    for request_only in [false, true] {
        let mut fixture = Fixture::build(true);
        fixture.terms = Terms::new(
            now_ms().unwrap() + 500,
            &fixture.terms.options(fixture.deadline),
        )
        .unwrap();
        let first = fixture.reserve();
        if request_only {
            fixture.commit(&first);
        }
        let authorization_bytes = first
            .directory
            .read("authorization.nrt", MAX_RECORD_BYTES)
            .unwrap();
        let request_bytes = request_only
            .then(|| std::fs::read(first.wallet_path().join("preparation.json")).unwrap());
        let bound = Instant::now() + Duration::from_secs(3);
        while now_ms().unwrap() < first.terms().signing_deadline_unix_ms {
            assert!(Instant::now() < bound);
            std::thread::sleep(Duration::from_millis(10));
        }
        let native = fixture.current_native();
        let grant = fixture
            .authorization
            .as_ref()
            .unwrap()
            .test_child(Purpose::ReservePolicy)
            .unwrap();
        let observed = std::cell::Cell::new(false);
        generated(
            &fixture.operation,
            Purpose::ReservePolicy,
            fixture.semantic,
            &crate::managed::native_operation::attempts::HistoryScope::FixedBody,
            &grant,
            fixture.deadline,
            None,
            |attempt| fixture.inspect(attempt),
            |attempt| {
                fixture
                    .wallet
                    .retire_initial_reserve_policy_unprepared(
                        &attempt.wallet_path(),
                        &fixture.request(attempt),
                    )
                    .map_err(|_| invalid("canonical retirement refused"))
            },
            |attempt, _, _| Ok(fixture.retain(attempt)),
            |_, _| {
                let checkpoint = native.observe(&fixture.authority);
                assert_eq!(checkpoint.verified_tip().unwrap().height(), 2);
                let current = native
                    .policy_proof(&fixture.authority.config.account)
                    .verify(
                        &fixture.authority.config.chain.to_string(),
                        fixture.authority.config.network_id,
                        &fixture.authority.config.account,
                        &fixture.policy,
                        iroha_core::state::State::native_world_schema_hash_v1().unwrap(),
                        &checkpoint.verified_tip().unwrap(),
                    )
                    .unwrap();
                assert!(current.current().is_none());
                observed.set(true);
                Ok(Observation::ordinary())
            },
            |_| Ok(true),
        )
        .unwrap();
        assert!(observed.get());
        let history = fixture.history().unwrap();
        history
            .verify_wallets(|attempt| fixture.inspect(attempt))
            .unwrap();
        assert_eq!(history.attempts.len(), 2);
        assert_eq!(history.selected().unwrap().unwrap().ordinal(), 2);
        assert_eq!(
            first
                .directory
                .read("authorization.nrt", MAX_RECORD_BYTES)
                .unwrap(),
            authorization_bytes
        );
        if let Some(bytes) = request_bytes {
            assert_eq!(
                std::fs::read(first.wallet_path().join("preparation.json")).unwrap(),
                bytes
            );
            assert_eq!(
                fixture.inspect(&first).unwrap().phase(),
                NativePreparationPhase::Retired
            );
        } else {
            assert!(!first.wallet_path().exists());
        }
        let selected = history.selected().unwrap().unwrap();
        assert_eq!(
            fixture.inspect(selected).unwrap().phase(),
            NativePreparationPhase::RequestOnly
        );
        assert!(!selected.wallet_path().join("payload.json").exists());
        assert!(!selected.wallet_path().join("operation.json").exists());
        assert!(fixture.prepared.context.client_config.parent().unwrap().join("runtime/service-operations/network/service-bootstrap/initial/epochs/0001-replacement.nrt").is_file());
    }
}

#[test]
fn exact_reserved_prefixes_finish_once_without_new_terms_or_wallet_io() {
    let _resources = crate::managed::native_test_guard();
    for prefix in 0..3 {
        let fixture = Fixture::new();
        fixture
            .history()
            .unwrap()
            .reserve_pending(&fixture.operation, Origin::Explicit, fixture.terms.clone())
            .unwrap();
        let reserved = read_record::<Dispatch>(&fixture.operation, "dispatch.nrt")
            .unwrap()
            .unwrap();
        let original = encode(&reserved.highest, MAX_RECORD_BYTES).unwrap();
        if prefix > 0 {
            let root = fixture.operation.create_child("attempts").unwrap();
            let directory = root.create_child("0001").unwrap();
            if prefix == 2 {
                // Exact bytes from the actual reservation, never another authorization DTO.
                write_record(&directory, "authorization.nrt", &reserved.highest).unwrap();
            }
        }
        let mut peers = UnavailablePeers::start(&fixture.prepared);
        let history = fixture.history().unwrap();
        assert_eq!(history.reserved_attempt_count(), 1);
        assert!(history.selected().is_err());
        history
            .verify_wallets(|attempt| fixture.inspect(attempt))
            .unwrap();
        let before = fixture
            .operation
            .read("dispatch.nrt", MAX_RECORD_BYTES)
            .unwrap();
        let mut changed = fixture.terms.clone();
        changed.requested_deadline_unix_ms += 1;
        assert!(
            history
                .reserve(&fixture.operation, Origin::Explicit, changed)
                .is_err()
        );
        assert_eq!(
            fixture
                .operation
                .read("dispatch.nrt", MAX_RECORD_BYTES)
                .unwrap(),
            before
        );
        let attempt = history
            .finish_reserved(&fixture.operation, false)
            .unwrap()
            .unwrap();
        assert_eq!(
            attempt
                .directory
                .read("authorization.nrt", MAX_RECORD_BYTES)
                .unwrap()
                .as_slice(),
            original.as_slice()
        );
        assert_eq!(fixture.history().unwrap().reserved_attempt_count(), 1);
        assert!(!attempt.wallet_path().exists());
        assert!(
            fixture
                .history()
                .unwrap()
                .finish_reserved(&fixture.operation, false)
                .unwrap()
                .is_none()
        );
        assert!(peers.requests.lock().unwrap().is_empty());
        peers.finish();
    }
}

#[test]
fn reserved_last_slot_finishes_at_the_bound_without_refunding_or_appending() {
    let _resources = crate::managed::native_test_guard();
    let fixture = Fixture::new();
    let mut previous = fixture.reserve();
    for ordinal in 2..MAX_ATTEMPTS {
        let next = fixture
            .history()
            .unwrap()
            .reserve(
                &fixture.operation,
                Origin::Generated {
                    ordinal: u8::try_from(ordinal - 1).unwrap(),
                    epoch: [u8::try_from(ordinal).unwrap(); 32],
                    parent_intent: [0x31; 32],
                },
                fixture.terms.clone(),
            )
            .unwrap();
        retire_missing(&previous, &next).unwrap();
        previous = next;
    }
    let last_origin = Origin::Generated {
        ordinal: 63,
        epoch: [64; 32],
        parent_intent: [0x31; 32],
    };
    fixture
        .history()
        .unwrap()
        .reserve_pending(&fixture.operation, last_origin, fixture.terms.clone())
        .unwrap();
    let history = fixture.history().unwrap();
    assert_eq!(history.reserved_attempt_count(), MAX_ATTEMPTS);
    assert_eq!(history.cumulative_reserved_count(), MAX_ATTEMPTS);
    assert!(!fixture.operation.path().join("attempts/0064").exists());
    let last = history
        .finish_reserved(&fixture.operation, false)
        .unwrap()
        .unwrap();
    retire_missing(&previous, &last).unwrap();
    let history = fixture.history().unwrap();
    history
        .verify_wallets(|attempt| fixture.inspect(attempt))
        .unwrap();
    assert_eq!(history.reserved_attempt_count(), MAX_ATTEMPTS);
    assert!(
        history
            .reserve(
                &fixture.operation,
                Origin::Generated {
                    ordinal: 64,
                    epoch: [65; 32],
                    parent_intent: [0x31; 32],
                },
                fixture.terms.clone()
            )
            .is_err()
    );
    assert!(!fixture.operation.path().join("attempts/0065").exists());
    assert!(
        history
            .finish_reserved(&fixture.operation, false)
            .unwrap()
            .is_none()
    );
}

#[test]
fn published_latest_signed_suffix_loss_and_unanchored_empty_tail_refuse_repair() {
    let _resources = crate::managed::native_test_guard();
    let fixture = Fixture::new();
    let first = fixture.reserve();
    fixture.commit(&first);
    let next = fixture
        .history()
        .unwrap()
        .reserve(
            &fixture.operation,
            Origin::Generated {
                ordinal: 1,
                epoch: [0x42; 32],
                parent_intent: [0x43; 32],
            },
            fixture.terms.clone(),
        )
        .unwrap();
    let retired = fixture
        .wallet
        .retire_initial_reserve_policy_unprepared(&first.wallet_path(), &fixture.request(&first))
        .unwrap();
    retire_request(&first, &next, &retired).unwrap();
    let retained = fixture.retain(&next);
    commit(&next, Some(&first), Observation::ordinary(), &retained).unwrap();
    fixture.sign(&next);
    assert_eq!(
        fixture.inspect(&next).unwrap().phase(),
        NativePreparationPhase::Signed
    );
    let anchor = fixture
        .operation
        .read("dispatch.nrt", MAX_RECORD_BYTES)
        .unwrap();
    std::fs::remove_dir_all(next.directory.path()).unwrap();
    let mut peers = UnavailablePeers::start(&fixture.prepared);
    assert!(fixture.history().is_err());
    assert!(!next.directory.path().exists());
    assert_eq!(
        fixture
            .operation
            .read("dispatch.nrt", MAX_RECORD_BYTES)
            .unwrap(),
        anchor
    );
    assert!(peers.requests.lock().unwrap().is_empty());
    peers.finish();

    let separate = Fixture::new();
    separate
        .operation
        .create_child("attempts")
        .unwrap()
        .create_child("0001")
        .unwrap();
    assert!(separate.history().is_err());
    assert!(!separate.operation.path().join("dispatch.nrt").exists());
}

#[test]
fn fixed_body_scope_rejects_enrollment_purposes_before_mutation() {
    let _resources = crate::managed::native_test_guard();
    let fixture = Fixture::new();
    let before = fixture.operation.entries(3).unwrap();
    for purpose in [
        Purpose::CustodyEnroll(ProviderId::new([0x23; 32])),
        Purpose::CustodyRenewal {
            provider: ProviderId::new([0x23; 32]),
            sequence: 2,
        },
    ] {
        assert!(
            History::read(
                &fixture.operation,
                purpose,
                fixture.semantic,
                &HistoryScope::FixedBody
            )
            .is_err()
        );
        assert_eq!(fixture.operation.entries(3).unwrap(), before);
        assert!(!fixture.operation.path().join("dispatch.nrt").exists());
        assert!(!fixture.operation.path().join("attempts").exists());
    }
}

#[test]
fn dispatch_compare_writer_refuses_changed_expected_record_and_illegal_edges() {
    let _resources = crate::managed::native_test_guard();
    let fixture = Fixture::new();
    fixture
        .history()
        .unwrap()
        .reserve_pending(&fixture.operation, Origin::Explicit, fixture.terms.clone())
        .unwrap();
    let reserved = read_record::<Dispatch>(&fixture.operation, "dispatch.nrt")
        .unwrap()
        .unwrap();
    let original = fixture
        .operation
        .read("dispatch.nrt", MAX_RECORD_BYTES)
        .unwrap();
    let mut wrong_expected = reserved.clone();
    wrong_expected.first = [0x77; 32];
    let mut published = reserved.clone();
    published.state = ReservationState::Published;
    assert!(replace_dispatch(&fixture.operation, Some(&wrong_expected), &published).is_err());
    assert!(replace_dispatch(&fixture.operation, None, &reserved).is_err());
    let mut changed = published.clone();
    changed.highest.terms.requested_deadline_unix_ms += 1;
    assert!(replace_dispatch(&fixture.operation, Some(&reserved), &changed).is_err());
    assert_eq!(
        fixture
            .operation
            .read("dispatch.nrt", MAX_RECORD_BYTES)
            .unwrap(),
        original
    );
    assert!(!fixture.operation.path().join("attempts").exists());
    fixture
        .history()
        .unwrap()
        .finish_reserved(&fixture.operation, false)
        .unwrap()
        .unwrap();
    let retained = fixture
        .operation
        .read("dispatch.nrt", MAX_RECORD_BYTES)
        .unwrap();
    assert!(replace_dispatch(&fixture.operation, Some(&published), &reserved).is_err());
    let mut skipped = reserved.clone();
    skipped.highest.ordinal = 3;
    skipped.highest.previous = Some(digest(&published.highest).unwrap());
    assert!(replace_dispatch(&fixture.operation, Some(&published), &skipped).is_err());
    assert_eq!(
        fixture
            .operation
            .read("dispatch.nrt", MAX_RECORD_BYTES)
            .unwrap(),
        retained
    );
    assert_eq!(fixture.history().unwrap().cumulative_reserved_count(), 1);
}

#[test]
fn explicit_reserved_recovery_reuses_original_signing_cap_under_a_later_io_budget() {
    let _resources = crate::managed::native_test_guard();
    let fixture = Fixture::new();
    fixture
        .history()
        .unwrap()
        .reserve_pending(&fixture.operation, Origin::Explicit, fixture.terms.clone())
        .unwrap();
    let history = fixture.history().unwrap();
    assert!(history.last().is_none());
    let later = fixture.deadline + Duration::from_secs(60);
    let options = fixture.terms.options(later);
    let retained = history.retained_terms().unwrap().clone();
    retained
        .matches(fixture.terms.requested_deadline_unix_ms, &options)
        .unwrap();
    assert!(
        Terms::new(fixture.terms.requested_deadline_unix_ms, &options)
            .unwrap()
            .signing_deadline_unix_ms
            > retained.signing_deadline_unix_ms
    );
    let original = encode(&retained, MAX_RECORD_BYTES).unwrap();
    let mut peers = UnavailablePeers::start(&fixture.prepared);
    initial(
        history,
        retained,
        Observation::ordinary(),
        later,
        |attempt| fixture.inspect(attempt),
        |attempt, _, _| Ok(fixture.retain(attempt)),
    )
    .unwrap();
    let complete = fixture.history().unwrap();
    let selected = complete.selected().unwrap().unwrap();
    assert_eq!(
        encode(selected.terms(), MAX_RECORD_BYTES).unwrap(),
        original
    );
    assert_eq!(complete.reserved_attempt_count(), 1);
    assert_eq!(
        fixture.inspect(selected).unwrap().phase(),
        NativePreparationPhase::RequestOnly
    );
    assert!(!selected.wallet_path().join("payload.json").exists());
    assert!(!selected.wallet_path().join("operation.json").exists());
    assert!(peers.requests.lock().unwrap().is_empty());
    peers.finish();
}

#[test]
fn full_bound_revalidation_preserves_originals_and_refuses_record_or_directory_substitution() {
    let _resources = crate::managed::native_test_guard();
    let fixture = Fixture::new();
    let mut previous = fixture.reserve();
    for ordinal in 2..=MAX_ATTEMPTS {
        let next = fixture
            .history()
            .unwrap()
            .reserve(
                &fixture.operation,
                Origin::Generated {
                    ordinal: u8::try_from(ordinal - 1).unwrap(),
                    epoch: [u8::try_from(ordinal).unwrap(); 32],
                    parent_intent: [0x71; 32],
                },
                fixture.terms.clone(),
            )
            .unwrap();
        retire_missing(&previous, &next).unwrap();
        previous = next;
    }
    let history = fixture.history().unwrap();
    let history = history.reread().unwrap();
    assert_eq!(history.reserved_attempt_count(), MAX_ATTEMPTS);
    assert_eq!(history.cumulative_reserved_count(), MAX_ATTEMPTS);
    history.require_current().unwrap();
    // A fixed semantic body can contain all 64 attempts without any body predecessor.
    // Its existing local census already checks every record/identity before and after.
    let (validated, census) = history.test_require_current(1);
    validated.unwrap();
    assert_eq!(census.visits, 1);
    assert_eq!(census.distinct_histories, 1);
    history
        .verify_wallets(|attempt| fixture.inspect(attempt))
        .unwrap();
    let root_names = fixture.operation.entries(3).unwrap();
    let original = fixture
        .operation
        .read(
            "original.nrt",
            super::super::MAX_CHECKPOINT_BYTES + 3 * 1024 * 1024,
        )
        .unwrap();
    let mut changed = original.to_vec();
    *changed.last_mut().unwrap() ^= 1;
    fixture
        .operation
        .write_atomic("original.nrt", &changed, PublishMode::Replace)
        .unwrap();
    assert!(history.require_current().is_err());
    let (refused, census) = history.test_require_current(1);
    assert!(refused.is_err());
    assert_eq!(census.visits, 1);
    assert_eq!(census.distinct_histories, 1);
    fixture
        .operation
        .write_atomic("original.nrt", &original, PublishMode::Replace)
        .unwrap();
    let (restored, census) = history.test_require_current(1);
    restored.unwrap();
    assert_eq!(census.visits, 1);
    assert_eq!(census.distinct_histories, 1);

    let dispatch = fixture
        .operation
        .read("dispatch.nrt", MAX_RECORD_BYTES)
        .unwrap();
    let mut changed = history.dispatch.clone().unwrap();
    changed.first[0] ^= 1;
    fixture
        .operation
        .write_atomic(
            "dispatch.nrt",
            &encode(&changed, MAX_RECORD_BYTES).unwrap(),
            PublishMode::Replace,
        )
        .unwrap();
    assert!(history.require_current().is_err());
    fixture
        .operation
        .write_atomic("dispatch.nrt", &dispatch, PublishMode::Replace)
        .unwrap();

    let interior = &history.attempts[31];
    let authorization = interior
        .directory
        .read("authorization.nrt", MAX_RECORD_BYTES)
        .unwrap();
    let mut changed = interior.authorization.clone();
    changed.terms.requested_deadline_unix_ms += 1;
    interior
        .directory
        .write_atomic(
            "authorization.nrt",
            &encode(&changed, MAX_RECORD_BYTES).unwrap(),
            PublishMode::Replace,
        )
        .unwrap();
    assert!(history.require_current().is_err());
    interior
        .directory
        .write_atomic("authorization.nrt", &authorization, PublishMode::Replace)
        .unwrap();
    interior
        .directory
        .write_atomic(
            "observation.nrt",
            &encode(&Observation::ordinary(), MAX_RECORD_BYTES).unwrap(),
            PublishMode::CreateNew,
        )
        .unwrap();
    assert!(history.require_current().is_err());
    std::fs::remove_file(interior.directory.path().join("observation.nrt")).unwrap();
    let retirement = interior
        .directory
        .read("retired.nrt", MAX_RECORD_BYTES)
        .unwrap();
    let mut changed = interior.retirement.clone().unwrap();
    changed.successor[0] ^= 1;
    interior
        .directory
        .write_atomic(
            "retired.nrt",
            &encode(&changed, MAX_RECORD_BYTES).unwrap(),
            PublishMode::Replace,
        )
        .unwrap();
    assert!(history.require_current().is_err());
    interior
        .directory
        .write_atomic("retired.nrt", &retirement, PublishMode::Replace)
        .unwrap();
    for name in ["foreign", "carrier.nrt"] {
        interior
            .directory
            .write_atomic(name, b"not-authority", PublishMode::CreateNew)
            .unwrap();
        assert!(history.require_current().is_err());
        std::fs::remove_file(interior.directory.path().join(name)).unwrap();
    }
    history.require_current().unwrap();
    assert_eq!(fixture.operation.entries(3).unwrap(), root_names);
    assert_eq!(
        fixture
            .operation
            .read("original.nrt", original.len())
            .unwrap()
            .as_slice(),
        original.as_slice()
    );
    assert_eq!(
        interior
            .directory
            .read("authorization.nrt", MAX_RECORD_BYTES)
            .unwrap()
            .as_slice(),
        authorization.as_slice()
    );
    assert_eq!(
        interior
            .directory
            .read("retired.nrt", MAX_RECORD_BYTES)
            .unwrap()
            .as_slice(),
        retirement.as_slice()
    );
    assert!(!fixture.operation.path().join("attempts/0065").exists());

    #[cfg(unix)]
    {
        // Same canonical records at the same path cannot replace the retained native identity.
        let last = history.last().unwrap();
        let exact = last
            .directory
            .read("authorization.nrt", MAX_RECORD_BYTES)
            .unwrap();
        let saved = fixture._temporary.path().join("displaced-attempt");
        std::fs::rename(last.directory.path(), &saved).unwrap();
        let root = fixture.operation.open_child("attempts").unwrap();
        let substitute = root.create_child("0064").unwrap();
        substitute
            .write_atomic("authorization.nrt", &exact, PublishMode::CreateNew)
            .unwrap();
        assert_eq!(fixture.operation.entries(3).unwrap(), root_names);
        assert!(history.require_current().is_err());
        assert_eq!(
            substitute
                .read("authorization.nrt", MAX_RECORD_BYTES)
                .unwrap()
                .as_slice(),
            exact.as_slice()
        );
        assert_eq!(
            std::fs::read(saved.join("authorization.nrt")).unwrap(),
            exact.to_vec()
        );
        assert!(history.reread().is_err());
    }
}

#[test]
fn reserved_empty_tail_keeps_original_parser_semantics_without_losing_published_custody() {
    let _resources = crate::managed::native_test_guard();
    let fixture = Fixture::new();
    fixture
        .history()
        .unwrap()
        .reserve_pending(&fixture.operation, Origin::Explicit, fixture.terms.clone())
        .unwrap();
    let no_root = fixture.history().unwrap();
    no_root.require_current().unwrap();
    let dispatch_bytes = fixture
        .operation
        .read("dispatch.nrt", MAX_RECORD_BYTES)
        .unwrap();
    let root = fixture.operation.create_child("attempts").unwrap();
    assert!(no_root.require_current().is_err());
    drop(no_root);

    let missing = fixture.history().unwrap();
    assert!(missing.empty_tail);
    assert!(missing.attempts.is_empty());
    missing.require_current().unwrap();
    let empty = root.create_child("0001").unwrap();
    drop(empty);
    // The sole parser treats both reserved missing and reserved empty leaves as the same
    // unfinished prefix. An empty leaf has no retained authorization or native authority.
    missing.require_current().unwrap();
    let witnessed_empty = fixture.history().unwrap();
    assert!(witnessed_empty.empty_tail);
    assert!(witnessed_empty.attempts.is_empty());
    std::fs::remove_dir(root.path().join("0001")).unwrap();
    missing.require_current().unwrap();
    witnessed_empty.require_current().unwrap();
    assert_eq!(
        fixture
            .operation
            .read("dispatch.nrt", MAX_RECORD_BYTES)
            .unwrap(),
        dispatch_bytes
    );
    assert!(!root.path().join("0001").exists());

    let attempt = witnessed_empty
        .finish_reserved(&fixture.operation, false)
        .unwrap()
        .unwrap();
    assert_eq!(attempt.ordinal(), 1);
    assert!(!attempt.wallet_path().exists());
    assert!(missing.require_current().is_err());
    assert!(witnessed_empty.require_current().is_err());
    let published = fixture.history().unwrap();
    assert!(!published.empty_tail);
    published.require_current().unwrap();
    std::fs::remove_file(attempt.directory.path().join("authorization.nrt")).unwrap();
    assert!(published.require_current().is_err());
    assert!(fixture.history().is_err());
    assert!(!attempt.wallet_path().exists());
}

#[test]
fn retained_reparse_admits_canonical_append_and_refuses_changed_original_custody() {
    let _guard = crate::managed::native_test_guard();
    let fixture = Fixture::build(true);
    let before = fixture.history().unwrap();
    assert!(before.root.is_none());
    let attempt = fixture.reserve();
    fixture.commit(&attempt);
    let request = std::fs::read(attempt.wallet_path().join("preparation.json")).unwrap();
    let current = History::read_retained(
        &fixture.operation,
        Purpose::ReservePolicy,
        fixture.semantic,
        &HistoryScope::FixedBody,
        &before,
    )
    .unwrap();
    current
        .verify_wallets(|attempt| fixture.inspect(attempt))
        .unwrap();
    assert_eq!(current.attempts.len(), 1);
    assert_eq!(
        current.operation.identity().unwrap(),
        before.operation.identity().unwrap()
    );
    assert_eq!(
        current.attempts[0].directory.identity().unwrap(),
        attempt.directory.identity().unwrap()
    );
    let reparse = || {
        History::read_retained(
            &fixture.operation,
            Purpose::ReservePolicy,
            fixture.semantic,
            &HistoryScope::FixedBody,
            &current,
        )
    };
    let repeated = reparse().unwrap();
    repeated
        .verify_wallets(|attempt| fixture.inspect(attempt))
        .unwrap();
    assert_eq!(
        repeated.root.as_ref().unwrap().identity().unwrap(),
        current.root.as_ref().unwrap().identity().unwrap()
    );
    assert_eq!(
        repeated.attempts[0].directory.identity().unwrap(),
        current.attempts[0].directory.identity().unwrap()
    );
    assert_eq!(
        std::fs::read(attempt.wallet_path().join("preparation.json")).unwrap(),
        request
    );
    assert!(!attempt.wallet_path().join("payload.json").exists());
    assert!(!attempt.wallet_path().join("operation.json").exists());
    assert!(
        History::read_retained(
            &fixture.operation,
            Purpose::ReservePolicy,
            [7; 32],
            &HistoryScope::FixedBody,
            &current,
        )
        .is_err()
    );
    let authorization = attempt
        .directory
        .read("authorization.nrt", MAX_RECORD_BYTES)
        .unwrap();
    attempt
        .directory
        .write_atomic(
            "authorization.nrt",
            b"invalid retained authorization",
            PublishMode::Replace,
        )
        .unwrap();
    assert!(reparse().is_err());
    attempt
        .directory
        .write_atomic("authorization.nrt", &authorization, PublishMode::Replace)
        .unwrap();
    reparse().unwrap();
    attempt
        .directory
        .write_atomic("foreign.nrt", b"unknown", PublishMode::CreateNew)
        .unwrap();
    assert!(reparse().is_err());
    std::fs::remove_file(attempt.directory.path().join("foreign.nrt")).unwrap();
    reparse().unwrap();
    // The original native row stays live: Unix detects its displacement, while Windows's
    // no-delete-sharing custody refuses the displacement itself. Neither path recreates it.
    let displaced = fixture.operation.path().join("held-attempt");
    #[cfg(unix)]
    {
        std::fs::rename(attempt.directory.path(), &displaced).unwrap();
        assert!(reparse().is_err());
        assert!(!attempt.directory.path().exists());
        std::fs::rename(&displaced, attempt.directory.path()).unwrap();
    }
    #[cfg(windows)]
    {
        assert!(std::fs::rename(attempt.directory.path(), &displaced).is_err());
        assert!(!displaced.exists());
    }
    reparse()
        .unwrap()
        .verify_wallets(|attempt| fixture.inspect(attempt))
        .unwrap();
    assert_eq!(
        std::fs::read(attempt.wallet_path().join("preparation.json")).unwrap(),
        request
    );

    // A genuine live epoch reserves an exact successor but no child or wallet is created.
    // Restoring the earlier published root remains a valid ordinary prefix, yet cannot erase
    // the higher reservation observed by this still-owned parser input.
    use crate::managed::native_operation::authorization::DispatchAuthorization;
    let grant = fixture
        .authorization
        .as_ref()
        .unwrap()
        .test_child(Purpose::ReservePolicy)
        .unwrap();
    let published = fixture
        .operation
        .read("dispatch.nrt", MAX_RECORD_BYTES)
        .unwrap();
    current
        .reserve_pending(
            &fixture.operation,
            grant.origin().unwrap(),
            fixture.terms.clone(),
        )
        .unwrap();
    let pending = History::read_retained(
        &fixture.operation,
        Purpose::ReservePolicy,
        fixture.semantic,
        &HistoryScope::FixedBody,
        &current,
    )
    .unwrap();
    assert_eq!(pending.reserved_attempt_count(), 2);
    assert!(!fixture.operation.path().join("attempts/0002").exists());
    let reservation = fixture
        .operation
        .read("dispatch.nrt", MAX_RECORD_BYTES)
        .unwrap();
    fixture
        .operation
        .write_atomic("dispatch.nrt", &published, PublishMode::Replace)
        .unwrap();
    assert!(fixture.history().is_ok());
    assert!(
        History::read_retained(
            &fixture.operation,
            Purpose::ReservePolicy,
            fixture.semantic,
            &HistoryScope::FixedBody,
            &pending,
        )
        .is_err()
    );
    fixture
        .operation
        .write_atomic("dispatch.nrt", &reservation, PublishMode::Replace)
        .unwrap();
    let recovered = History::read_retained(
        &fixture.operation,
        Purpose::ReservePolicy,
        fixture.semantic,
        &HistoryScope::FixedBody,
        &pending,
    )
    .unwrap();
    assert_eq!(recovered.reserved_attempt_count(), 2);
    assert!(!fixture.operation.path().join("attempts/0002").exists());
    assert_eq!(
        std::fs::read(attempt.wallet_path().join("preparation.json")).unwrap(),
        request
    );
}

#[test]
fn explicit_owned_history_rechecks_original_and_namespace_before_any_wallet_effect() {
    let _resources = crate::managed::native_test_guard();
    let fixture = Fixture::new();
    let original = fixture
        .operation
        .read("original.nrt", MAX_RECORD_BYTES)
        .unwrap();
    for mutation in 0..4 {
        let history = fixture.history().unwrap();
        match mutation {
            0 => {
                let mut changed = original.to_vec();
                changed[0] ^= 1;
                fixture
                    .operation
                    .write_atomic("original.nrt", &changed, PublishMode::Replace)
                    .unwrap();
            }
            1 => std::fs::remove_file(fixture.operation.path().join("original.nrt")).unwrap(),
            2 => fixture
                .operation
                .write_atomic("foreign.nrt", b"unknown", PublishMode::CreateNew)
                .unwrap(),
            _ => fixture
                .history()
                .unwrap()
                .reserve_pending(&fixture.operation, Origin::Explicit, fixture.terms.clone())
                .unwrap(),
        }
        let before = fixture.operation.entries(6).unwrap();
        let dispatch = read_optional(&fixture.operation, "dispatch.nrt", MAX_RECORD_BYTES).unwrap();
        let inspected = std::cell::Cell::new(false);
        let retained = std::cell::Cell::new(false);
        assert!(
            initial(
                history,
                fixture.terms.clone(),
                Observation::ordinary(),
                fixture.deadline,
                |_| {
                    inspected.set(true);
                    Err(invalid("unexpected wallet inspection"))
                },
                |_, _, _| {
                    retained.set(true);
                    Err(invalid("unexpected wallet retention"))
                },
            )
            .is_err(),
            "mutation {mutation}"
        );
        assert!(!inspected.get(), "mutation {mutation}");
        assert!(!retained.get(), "mutation {mutation}");
        assert_eq!(fixture.operation.entries(6).unwrap(), before);
        assert_eq!(
            read_optional(&fixture.operation, "dispatch.nrt", MAX_RECORD_BYTES).unwrap(),
            dispatch
        );
        assert!(!fixture.operation.path().join("attempts").exists());
        match mutation {
            0 => fixture
                .operation
                .write_atomic("original.nrt", &original, PublishMode::Replace)
                .unwrap(),
            1 => fixture
                .operation
                .write_atomic("original.nrt", &original, PublishMode::CreateNew)
                .unwrap(),
            2 => std::fs::remove_file(fixture.operation.path().join("foreign.nrt")).unwrap(),
            _ => std::fs::remove_file(fixture.operation.path().join("dispatch.nrt")).unwrap(),
        }
        assert!(fixture.history().unwrap().last().is_none());
    }
    #[cfg(unix)]
    {
        let history = fixture.history().unwrap();
        let path = fixture.operation.path().to_path_buf();
        let displaced = fixture.authority.directory.path().join("held-set");
        std::fs::rename(&path, &displaced).unwrap();
        let replacement = PrivateDirectory::open_or_create(&path).unwrap();
        replacement
            .write_atomic("original.nrt", &original, PublishMode::CreateNew)
            .unwrap();
        let inspected = std::cell::Cell::new(false);
        let retained = std::cell::Cell::new(false);
        assert!(
            initial(
                history,
                fixture.terms.clone(),
                Observation::ordinary(),
                fixture.deadline,
                |_| {
                    inspected.set(true);
                    Err(invalid("unexpected replaced-directory inspection"))
                },
                |_, _, _| {
                    retained.set(true);
                    Err(invalid("unexpected replaced-directory retention"))
                },
            )
            .is_err()
        );
        assert!(!inspected.get());
        assert!(!retained.get());
        assert_eq!(
            replacement.read("original.nrt", MAX_RECORD_BYTES).unwrap(),
            original
        );
        assert!(!path.join("dispatch.nrt").exists());
        assert!(!path.join("attempts").exists());
        assert!(!displaced.join("dispatch.nrt").exists());
        assert!(!displaced.join("attempts").exists());
        drop(replacement);
        std::fs::remove_dir_all(&path).unwrap();
        std::fs::rename(&displaced, &path).unwrap();
        assert!(fixture.history().unwrap().last().is_none());
    }
}

#[test]
fn explicit_owned_history_keeps_genuine_request_and_refuses_inspection_callback_mutation() {
    let _resources = crate::managed::native_test_guard();
    let fixture = Fixture::new();
    let mut peers = UnavailablePeers::start(&fixture.prepared);
    let retained = std::cell::Cell::new(0);
    initial(
        fixture.history().unwrap(),
        fixture.terms.clone(),
        Observation::ordinary(),
        fixture.deadline,
        |attempt| fixture.inspect(attempt),
        |attempt, _, _| {
            retained.set(retained.get() + 1);
            Ok(fixture.retain(attempt))
        },
    )
    .unwrap();
    assert_eq!(retained.get(), 1);
    let history = fixture.history().unwrap();
    let selected = history.selected().unwrap().unwrap();
    assert!(selected.terms() == &fixture.terms);
    assert_eq!(history.reserved_attempt_count(), 1);
    assert_eq!(
        fixture.inspect(selected).unwrap().phase(),
        NativePreparationPhase::RequestOnly
    );
    let request = std::fs::read(selected.wallet_path().join("preparation.json")).unwrap();
    let wallet_path = selected.wallet_path();
    let dispatch = fixture
        .operation
        .read("dispatch.nrt", MAX_RECORD_BYTES)
        .unwrap();
    initial(
        history,
        fixture.terms.clone(),
        Observation::ordinary(),
        fixture.deadline,
        |attempt| fixture.inspect(attempt),
        |_, _, _| {
            retained.set(retained.get() + 1);
            Err(invalid("committed request must be reused"))
        },
    )
    .unwrap();
    assert_eq!(retained.get(), 1);
    let history = fixture.history().unwrap();
    let original = fixture
        .operation
        .read("original.nrt", MAX_RECORD_BYTES)
        .unwrap();
    let inspected = std::cell::Cell::new(false);
    assert!(
        initial(
            history,
            fixture.terms.clone(),
            Observation::ordinary(),
            fixture.deadline,
            |attempt| {
                let preparation = fixture.inspect(attempt)?;
                let mut changed = original.to_vec();
                changed[0] ^= 1;
                fixture
                    .operation
                    .write_atomic("original.nrt", &changed, PublishMode::Replace)
                    .unwrap();
                inspected.set(true);
                Ok(preparation)
            },
            |_, _, _| {
                retained.set(retained.get() + 1);
                Err(invalid("changed original cannot retain a wallet"))
            },
        )
        .is_err()
    );
    assert!(inspected.get());
    assert_eq!(retained.get(), 1);
    assert_eq!(
        fixture
            .operation
            .read("dispatch.nrt", MAX_RECORD_BYTES)
            .unwrap(),
        dispatch
    );
    assert_eq!(
        std::fs::read(wallet_path.join("preparation.json")).unwrap(),
        request
    );
    assert!(!wallet_path.join("payload.json").exists());
    assert!(!wallet_path.join("operation.json").exists());
    fixture
        .operation
        .write_atomic("original.nrt", &original, PublishMode::Replace)
        .unwrap();
    assert_eq!(fixture.history().unwrap().reserved_attempt_count(), 1);
    assert!(peers.requests.lock().unwrap().is_empty());
    peers.finish();
}
