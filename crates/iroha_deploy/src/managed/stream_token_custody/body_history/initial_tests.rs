//! Initial-body replacement through the original generated parent and genuine native execution.
//! These component carriers do not qualify running services or the complete bootstrap sequence.

use super::*;
use crate::managed::{
    ManagedInitialReservePolicy,
    native_operation::{
        authorization::DispatchAuthorization,
        test_support::{
            UnavailablePeers,
            native_fixture::{NativeFixture, NativeReadHttp, quote_instructions},
            provider_id,
        },
        verify_carrier,
    },
    service_bootstrap::{ManagedServiceBootstrap, authorization::GeneratedBootstrapAuthorization},
    stream_token_custody::{
        bootstrap_test_support::NativeEnrollmentReads, renewal_tests::wait_until,
    },
};
use iroha_core::state::StateReadOnly as _;
use iroha_data_model::{
    asset::AssetDefinitionId,
    isi::{InstructionBox, Log},
    sorafs::capacity::ProviderId,
    transaction::FeePaymentIntent,
};
use iroha_primitives::numeric::Quantity;
use iroha_wallet::operations::NativePreparationPhase;
use std::{collections::BTreeMap, num::NonZeroU64, path::PathBuf};
use zeroize::Zeroizing;

#[test]
fn expired_initial_body_uses_fresh_parent_authorization_and_preserves_original_native_custody() {
    let _guard = crate::managed::native_test_guard();
    let temporary = tempfile::tempdir().unwrap();
    let mut original = prepare_expired_initial(&temporary);
    let authorization = original
        .parent
        .authorize_test_startup(&original.options)
        .unwrap()
        .unwrap();
    finish_initial_replacement(original, authorization);
}

// This fixture moves the exact original owners and observations between phases. It retains
// no new source verdict, clone of a native graph, clock, signed input or live authorization.
struct ExpiredInitial {
    prepared: crate::managed::PreparedLocalnet,
    provider: ProviderId,
    options: BoundedTransactionOptions,
    parent: ManagedServiceBootstrap,
    native: Box<NativeFixture>,
    first_ordinal: u8,
    policy: SignerCustodyPolicyV1,
    configured_root: PrivateDirectory,
    configured_original: attempts::Selected<journal::Original>,
    configured_body: Zeroizing<Vec<u8>>,
    configured_carrier: Zeroizing<Vec<u8>>,
    configured_operation: Vec<u8>,
    previous_current: VerifiedStreamTokenCustodyStateV1,
    original_history: BodyHistory,
    old: attempts::Selected<journal::Original>,
    old_request: journal::Request,
    account: iroha_wallet::operations::AccountService,
    old_wallet: PathBuf,
    request_bytes: Vec<u8>,
    body_bytes: Zeroizing<Vec<u8>>,
    reserved_bytes: Zeroizing<Vec<u8>>,
    outer_bytes: Zeroizing<Vec<u8>>,
    peers: UnavailablePeers,
}

// Inspect the actual signed carrier and committed charge, not a synthetic fee estimate.
#[inline(never)]
fn assert_native_fee(
    native: &NativeFixture,
    height: u64,
    options: &BoundedTransactionOptions,
    instruction_count: usize,
    gas: u64,
) {
    let committed = native.chain.committed(height);
    let block = committed.block();
    let input = block.network_entrypoint_at(0).unwrap();
    let iroha_data_model::transaction::TransactionEntrypoint::External(signed) = input else {
        panic!("bootstrap must retain its real wallet-signed external input");
    };
    let iroha_data_model::transaction::Executable::Instructions(instructions) =
        signed.instructions()
    else {
        panic!("bootstrap must execute its exact native instruction vector");
    };
    assert_eq!(instructions.len(), instruction_count);
    assert_eq!(iroha_core::gas::meter_instructions(instructions), gas);
    assert_eq!(
        signed.fee_payment_intent().gas_limit(),
        options.fee_payment.gas_limit()
    );
    let (_, output) = block.network_output_at(0).unwrap();
    let receipt = output
        .result
        .nexus_fee_receipt()
        .expect("actual native fee settlement");
    receipt.validate_for_network_input(input, height).unwrap();
    assert_eq!(receipt.schedule.instruction_count, instruction_count as u64);
    assert_eq!(receipt.schedule.gas_used, gas);
    assert!(receipt.fee_amount <= *options.max_total_fees.get(&receipt.fee_asset_id).unwrap());
    let view = native.chain.state().view();
    assert_eq!(
        receipt.schedule.per_instruction_fee,
        view.nexus().fees.per_instruction_fee
    );
    assert_eq!(
        receipt.schedule.per_gas_unit_fee,
        view.nexus().fees.per_gas_unit_fee
    );
}

// The complete genuine prerequisite and expired-body preparation frame is gone before the
// second startup traverses native retained finality on the ordinary test-thread stack.
#[inline(never)]
fn prepare_expired_initial(temporary: &tempfile::TempDir) -> ExpiredInitial {
    let ports = crate::managed::LocalnetPorts::reserve().unwrap();
    let prepared = crate::localnet::prepare_localnet_at(
        "initial-body-retirement",
        &temporary.path().join("generation"),
        &ports,
        crate::localnet::LocalnetServiceProfile::StreamTokenAuthorities,
        None,
    )
    .unwrap();
    let provider = provider_id(&prepared, 0);
    let asset = AssetDefinitionId::parse_address_literal(
        crate::genesis::profile::TAIRA_XOR_ASSET_DEFINITION_ID,
    )
    .unwrap();
    // The original parent authorizes all prerequisites with one immutable fee intent.
    // SetSorafsReservePolicy, custody Configure and custody Enroll each meter 128 gas.
    let options = BoundedTransactionOptions {
        fee_payment: FeePaymentIntent::authority(Vec::new(), NonZeroU64::new(128)),
        max_total_fees: BTreeMap::from([(asset, Quantity::from(1_000u64))]),
        deadline: Instant::now() + Duration::from_secs(300),
    };
    let mut parent = ManagedServiceBootstrap::open(&prepared).unwrap();
    let initial_authorization = parent.authorize_test_startup(&options).unwrap().unwrap();
    let first_ordinal = initial_authorization.test_ordinal();
    let policies = initial_authorization
        .test_child(Purpose::CustodyConfigure(provider))
        .unwrap()
        .policies()
        .clone();
    let policy = policies.provider(provider).unwrap().custody.clone();
    let mut owner = ManagedStreamTokenCustody::open(&prepared, provider).unwrap();
    let mut native = NativeFixture::from_generated(&prepared, &owner.authority);
    let log = quote_instructions(
        &native,
        &owner.authority.config,
        [InstructionBox::from(Log::new(
            iroha_data_model::Level::INFO,
            "initial body prerequisites".into(),
        ))],
    );
    assert_eq!(native.chain.commit(vec![log]), vec![true]);
    assert_eq!(native.chain.height(), 2);
    drop(ports);
    // Preserve the real parent dependency order, including its network reserve prerequisite.
    let mut reserve = ManagedInitialReservePolicy::open(&prepared).unwrap();
    let reserve_result = reserve.bootstrap_native_generated(
        &mut native,
        &policies.network.reserve,
        &initial_authorization
            .test_child(Purpose::ReservePolicy)
            .unwrap(),
        &options,
    );
    assert_eq!(reserve_result.finalized.unwrap().height, 3);
    assert!(reserve_result.current.is_none());
    assert_native_fee(&native, 3, &options, 1, 128);
    drop(reserve);
    let configured = owner.bootstrap_native_configure_generated(
        &mut native,
        &policy,
        &initial_authorization
            .test_child(Purpose::CustodyConfigure(provider))
            .unwrap(),
        &options,
    );
    let configured_finality = configured.finalized.unwrap();
    assert_eq!(configured_finality.height, 4);
    assert!(configured.current.is_none());
    assert_native_fee(&native, 4, &options, 1, 128);
    let configured_root = owner.authority.directory.open_child("configure").unwrap();
    let configured_original = journal::required_original(&configured_root).unwrap();
    let configured_body = configured_root
        .read("original.nrt", journal::MAX_ORIGINAL_BYTES)
        .unwrap();
    let configured_carrier = configured_original
        .directory()
        .read("carrier.nrt", MAX_CHECKPOINT_BYTES)
        .unwrap();
    let configured_operation = std::fs::read(
        configured_original
            .directory()
            .path()
            .join("transaction/operation.json"),
    )
    .unwrap();

    let checkpoint = native.observe(&owner.authority);
    let current = native.bootstrap_custody(&owner.authority, &policy, &checkpoint);
    let state = current.current().unwrap();
    assert_eq!(state.control().policy, policy);
    assert_eq!(state.record().execution_height, 4);
    assert_eq!(state.control().next_sequence, 1);
    assert!(state.control().active_head.is_none());
    let now = now_ms().unwrap();
    let short = ManagedCustodyEnrollmentInterval {
        issued_at_unix_ms: now,
        expires_at_unix_ms: now + 6_000,
        deadline_unix_ms: now + 3_000,
    };
    assert!(short.expires_at_unix_ms - short.issued_at_unix_ms < policy.max_validity_ms);
    let unsigned = owner
        .unsigned_enrollment(&policy, &current, &checkpoint, short, now)
        .unwrap();
    let original_history = owner.bootstrap_native_body(
        &native,
        &current,
        CustodyPurpose::InitialEnroll,
        unsigned,
        short.deadline_unix_ms,
        &options,
    );
    let (body, original, scope) = original_history.dispatch().unwrap();
    let account = owner.wallet().unwrap();
    journal::explicit(
        body,
        original,
        short.deadline_unix_ms,
        &options,
        &account,
        scope,
    )
    .unwrap();
    let old = owner
        .required_enrollment(CustodyPurpose::InitialEnroll)
        .unwrap();
    let old_request = old.request(options.deadline).unwrap();
    let old_wallet = old.directory().path().join("transaction");
    let request_bytes = std::fs::read(old_wallet.join("preparation.json")).unwrap();
    let body_bytes = body
        .read("original.nrt", journal::MAX_ORIGINAL_BYTES)
        .unwrap();
    let reserved_bytes = body.read("reserved.nrt", MAX_BODY_BYTES).unwrap();
    let outer_bytes = original_history
        .root
        .read("original.nrt", MAX_SELECTION_BYTES)
        .unwrap();
    assert_eq!(
        old_request.inspect(&account, &old_wallet).unwrap().phase(),
        NativePreparationPhase::RequestOnly
    );
    assert!(!old_wallet.join("payload.json").exists());
    assert!(!old_wallet.join("operation.json").exists());
    wait_until(short.expires_at_unix_ms, Duration::from_secs(8));
    let peers = UnavailablePeers::start(&prepared);
    let expired = owner
        .recover_enroll_selected_if_present(
            &policy,
            &Fees::from_options(&options).unwrap(),
            options.deadline,
        )
        .unwrap()
        .unwrap();
    assert_eq!(expired.transaction_status, OperationStatus::Expired);
    assert!(expired.finalized.is_none() && expired.current.is_none());
    // A new invocation goes through the actual parent census after releasing the child lock.
    drop(owner);
    drop(initial_authorization);
    ExpiredInitial {
        prepared,
        provider,
        options,
        parent,
        native: Box::new(native),
        first_ordinal,
        policy,
        configured_root,
        configured_original,
        configured_body,
        configured_carrier,
        configured_operation,
        previous_current: current,
        original_history,
        old,
        old_request,
        account,
        old_wallet,
        request_bytes,
        body_bytes,
        reserved_bytes,
        outer_bytes,
        peers,
    }
}

#[inline(never)]
fn finish_initial_replacement(
    original: ExpiredInitial,
    authorization: GeneratedBootstrapAuthorization,
) {
    let ExpiredInitial {
        prepared,
        provider,
        options,
        parent: _parent,
        mut native,
        first_ordinal,
        policy,
        configured_root,
        configured_original,
        configured_body,
        configured_carrier,
        configured_operation,
        previous_current,
        original_history,
        old,
        old_request,
        account,
        old_wallet,
        request_bytes,
        body_bytes,
        reserved_bytes,
        outer_bytes,
        mut peers,
    } = original;
    assert_eq!(authorization.test_ordinal(), first_ordinal + 1);
    let child = authorization
        .test_child(Purpose::CustodyEnroll(provider))
        .unwrap();
    assert_eq!(child.policies().provider(provider).unwrap().custody, policy);
    let mut owner = ManagedStreamTokenCustody::open(&prepared, provider).unwrap();
    child
        .validate(
            &owner.authority,
            Purpose::CustodyEnroll(provider),
            options.deadline,
        )
        .unwrap();
    let terms = child
        .terms(options.deadline, Some(policy.active_until_unix_ms))
        .unwrap();
    let now = now_ms().unwrap();
    let interval = child
        .policies()
        .provider(provider)
        .unwrap()
        .initial_enrollment(now, terms.requested_deadline_unix_ms)
        .unwrap();
    let checkpoint = native.observe(&owner.authority);
    let current = native.bootstrap_custody(&owner.authority, &policy, &checkpoint);
    assert_eq!(
        current.current().unwrap().record(),
        previous_current.current().unwrap().record()
    );
    let unsigned = owner
        .unsigned_enrollment(&policy, &current, &checkpoint, interval, now)
        .unwrap();
    let history = BodyHistory::open(&owner, CustodyPurpose::InitialEnroll)
        .unwrap()
        .unwrap()
        .reserve_successor(&owner, unsigned, &current, &child, options.deadline)
        .unwrap()
        .finish_pending_with_reads(
            &owner,
            &current,
            &SigningTurn::Generated(&child),
            options.deadline,
            &NativeEnrollmentReads(&native),
        )
        .unwrap();
    assert_eq!(history.anchor.highest, 2);
    assert_eq!(
        history
            .current_history()
            .unwrap()
            .cumulative_reserved_count(),
        1
    );
    assert_eq!(
        old_request.inspect(&account, &old_wallet).unwrap().phase(),
        NativePreparationPhase::Retired
    );
    let (operation, original, scope) = history.dispatch().unwrap();
    let account = child.bind_account(owner.wallet().unwrap()).unwrap();
    let historical = native.bootstrap_custody(&owner.authority, &policy, &checkpoint);
    attempts::generated(
        operation,
        Purpose::CustodyEnroll(provider),
        original.digest().unwrap(),
        scope,
        &child,
        options.deadline,
        Some(interval.expires_at_unix_ms),
        |attempt| {
            original
                .request(attempt.terms(), attempt.observation()?, options.deadline)?
                .inspect(&account, &attempt.wallet_path())
        },
        |attempt| {
            original
                .request(attempt.terms(), attempt.observation()?, options.deadline)?
                .retire(&account, &attempt.wallet_path())
        },
        |attempt, observation, deadline| {
            original
                .request(attempt.terms(), observation, deadline)?
                .retain(&account, &attempt.wallet_path())
        },
        |_, deadline| {
            let cut = native.observe(&owner.authority);
            let current = native.bootstrap_custody(&owner.authority, &policy, &cut);
            owner.fresh_predecessor_observation(original, &historical, &current, deadline)
        },
        |attempt| {
            let observed = attempt
                .observation()?
                .enrollment_observed_at_unix_ms
                .ok_or_else(|| invalid("initial dispatch observation absent"))?;
            let now = now_ms()?;
            Ok(observed <= now && now - observed <= policy.max_anchor_age_ms)
        },
    )
    .unwrap();
    let selected = owner
        .required_enrollment(CustodyPurpose::InitialEnroll)
        .unwrap();
    assert!(matches!(
        selected.attempt().origin(),
        attempts::Origin::Generated { .. }
    ));
    assert!(selected.attempt().origin() == &child.origin().unwrap());
    assert_ne!(selected.directory().path(), old.directory().path());
    assert_eq!(
        BodyHistory::open(&owner, CustodyPurpose::InitialEnroll)
            .unwrap()
            .unwrap()
            .current_history()
            .unwrap()
            .cumulative_reserved_count(),
        2
    );
    assert!(peers.requests.lock().unwrap().is_empty());
    peers.finish();

    let path = selected.directory().path().join("transaction");
    let mut http =
        NativeReadHttp::start_config(&owner.authority.config, Arc::clone(native.chain.state()));
    let journal::Request::Enroll(request) = selected.request(options.deadline).unwrap() else {
        unreachable!()
    };
    account
        .prepare_stream_token_custody_enroll(&request, &path)
        .unwrap();
    let signed = owner
        .verify_wallet(selected.directory(), &selected, options.deadline)
        .unwrap();
    http.finish();
    let wire = signed.encode_wire_v1().unwrap();
    let carrier = native.bootstrap_commit(&owner.authority, &signed);
    let finalized = verify_carrier(&carrier, &signed).unwrap();
    assert_eq!(finalized.height, 5);
    assert_native_fee(&native, finalized.height, &options, 1, 128);
    selected
        .directory()
        .write_atomic(
            "carrier.nrt",
            &checkpoint_bytes(&carrier).unwrap(),
            PublishMode::CreateNew,
        )
        .unwrap();
    let current = native.bootstrap_custody(&owner.authority, &policy, &carrier);
    let state = current.current().unwrap();
    assert_eq!(state.control().policy, policy);
    assert_eq!(state.control().active_head.unwrap().sequence, 1);
    assert_eq!(state.control().next_sequence, 2);
    let retained = owner
        .retained_initial_enrollment(&policy, selected.interval().unwrap(), options.deadline)
        .unwrap();
    assert_eq!(retained.finalized(), &finalized);
    owner
        .verify_enrollment_at(
            &retained,
            &policy,
            finalized.height,
            *finalized.block_hash.as_ref(),
            &current,
            now_ms().unwrap(),
            options.deadline,
        )
        .unwrap();
    let mut peers = UnavailablePeers::start(&prepared);
    let recovered = owner
        .recover_enroll_selected_if_present(&policy, child.fees(), options.deadline)
        .unwrap()
        .unwrap();
    assert_eq!(recovered.transaction_status, OperationStatus::Applied);
    assert_eq!(recovered.finalized, Some(finalized));
    assert!(recovered.current.is_none());
    assert_eq!(
        owner
            .verify_wallet(selected.directory(), &selected, options.deadline)
            .unwrap()
            .encode_wire_v1()
            .unwrap(),
        wire
    );
    // Borrow the same retained old body owner again; dispatch only exposes this image's
    // original directory/value/scope and performs no I/O, clock read or new authorization.
    let (body, _, _) = original_history.dispatch().unwrap();
    assert_eq!(
        body.read("original.nrt", journal::MAX_ORIGINAL_BYTES)
            .unwrap(),
        body_bytes
    );
    assert_eq!(
        body.read("reserved.nrt", MAX_BODY_BYTES).unwrap(),
        reserved_bytes
    );
    assert_eq!(
        history
            .root
            .read("original.nrt", MAX_SELECTION_BYTES)
            .unwrap(),
        outer_bytes
    );
    assert_eq!(
        std::fs::read(old_wallet.join("preparation.json")).unwrap(),
        request_bytes
    );
    assert!(
        !old_wallet.join("payload.json").exists() && !old_wallet.join("operation.json").exists()
    );
    assert!(!old_wallet.join("submission.json").exists() && !path.join("submission.json").exists());
    assert_eq!(
        configured_root
            .read("original.nrt", journal::MAX_ORIGINAL_BYTES)
            .unwrap(),
        configured_body
    );
    assert_eq!(
        configured_original
            .directory()
            .read("carrier.nrt", MAX_CHECKPOINT_BYTES)
            .unwrap(),
        configured_carrier
    );
    assert_eq!(
        std::fs::read(
            configured_original
                .directory()
                .path()
                .join("transaction/operation.json")
        )
        .unwrap(),
        configured_operation
    );
    assert!(peers.requests.lock().unwrap().is_empty());
    peers.finish();
}
