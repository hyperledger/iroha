//! Boundary tests; stand-in ownership is test-only and cannot open a production wallet.

use super::*;
use advance::{
    KagemushaWalletPlatformV1 as _, KagemushaWalletProbeV1 as Probe,
    KagemushaWalletUnavailableV1 as U,
};
use std::sync::atomic::{AtomicUsize, Ordering};

pub(super) struct TestWallet {
    pub(super) calls: Arc<AtomicUsize>,
    pub(super) drops: Arc<AtomicUsize>,
    pub(super) expected_request: Option<state::OperationRequestV1>,
}
impl Drop for TestWallet {
    fn drop(&mut self) {
        self.drops.fetch_add(1, Ordering::SeqCst);
    }
}
impl Wallet for TestWallet {
    fn setup(&mut self, _: setup::Setup) -> Result<Response> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Ok(Response {
            kind: 12,
            bytes: vec![0, 255, 7],
            ..Response::default()
        })
    }
    fn snapshot(&mut self) -> Result<state::Snapshot> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Ok(state::Snapshot {
            scheme_id: [1; 32],
            wallet_id: [2; 32],
            head: [3; 32],
            credential_digest: [4; 32],
            sequence: (1_u128 << 93) + 7,
            lifecycle: KagemushaWalletLifecycleV1::Retiring,
            balance: u128::MAX,
            core_burned_total: 3,
            known_burned_total: 3,
            owned_balance: u128::MAX - 3,
            folded_balance: None,
            fold_backlog: 1,
            verified_fold: Some(state::SnapshotFold {
                sequence: (1_u128 << 93) + 6,
                head: [5; 32],
                credential_digest: [6; 32],
                burned_total: 3,
            }),
        })
    }
    fn review(&mut self, input: review::Input) -> Result<Response> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        let review::Input::Unload {
            amount,
            charge,
            beneficiary,
        } = input
        else {
            panic!("expected Unload review fixture")
        };
        assert_eq!(beneficiary, Some(vec![3, 255, 0, 1]));
        assert_eq!(
            state::OperationActionV1::Unload { amount, charge },
            self.expected_request
                .as_ref()
                .expect("expected review originals")
                .action,
        );
        Err(Failure::code(PROOF_REJECTED))
    }
    fn execute(&mut self, request: state::OperationRequestV1) -> Result<Response> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        if let Some(expected) = &self.expected_request {
            assert_eq!(&request, expected);
        }
        Err(Failure::code(PROOF_REJECTED))
    }
    fn request_status(&mut self, _: &[u8; 32]) -> Result<Response> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Ok(Response {
            kind: 11,
            ..Response::default()
        })
    }
    fn retry(&mut self, op: &[u8; 32]) -> Result<Response> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        match op[0] {
            0 => Ok(Response::default()),
            1 => completion(Some(state::Completion::Complete(vec![0, 255, 0, 7]))),
            2 => completion(Some(state::Completion::Pending)),
            3 => completion(Some(state::Completion::DeliveryDataLoss)),
            _ => Err(Failure::unavailable(UNAVAILABLE, U::Io(5))),
        }
    }
    fn resume(&mut self) -> Result<Response> {
        completion(Some(state::Completion::Pending))
    }
    fn fold(&mut self) -> Result<Response> {
        Ok(Response {
            kind: 8,
            sequence: (1_u128 << 93) + 7,
            detail: 3,
            ..Response::default()
        })
    }
    fn credit(&mut self, _: &[u8; 32], _: &[u8; 32]) -> Result<Response> {
        Err(Failure::code(FOLD_REQUIRED))
    }
}
fn installed() -> (u64, Arc<AtomicUsize>, Arc<AtomicUsize>) {
    let calls = Arc::new(AtomicUsize::new(0));
    let drops = Arc::new(AtomicUsize::new(0));
    let id = install(
        Box::new(TestWallet {
            calls: calls.clone(),
            drops: drops.clone(),
            expected_request: None,
        }),
        state::Scheduler::new(),
    )
    .unwrap();
    (id, calls, drops)
}
#[test]
fn handles_never_repeat_close_releases_owner_and_stale_captures_cannot_act() {
    let (id, calls, drops) = installed();
    let stale = owner(id).unwrap();
    activity(id, false, false).unwrap();
    assert_eq!(retry(id, &[1; 32]).unwrap().bytes, [0, 255, 0, 7]);
    close(id).unwrap();
    assert!(stale.wallet.lock().unwrap().is_none());
    assert_eq!(drops.load(Ordering::SeqCst), 1);
    assert_eq!(close(id).unwrap_err().status, CLOSED);
    assert_eq!(retry(id, &[1; 32]).unwrap_err().status, CLOSED);
    assert_eq!(activity(id, false, false).unwrap_err().status, CLOSED);
    let (next, _, _) = installed();
    assert!(next > id);
    close(next).unwrap();
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}
#[test]
fn c_calls_preserve_exact_retry_unknown_pending_loss_and_platform_failure() {
    let (id, calls, _) = installed();
    for _ in 0..2 {
        let mut result = WalletResult::default();
        assert_eq!(
            unsafe { connect_norito_kagemusha_wallet_retry_v1(id, [1; 32].as_ptr(), &mut result) },
            0
        );
        assert_eq!(result.status, 1);
        assert_eq!(
            unsafe { std::slice::from_raw_parts(result.bytes, result.length) },
            [0, 255, 0, 7]
        );
        crate::connect_norito_free(result.bytes);
    }
    assert_eq!(retry(id, &[0; 32]).unwrap().kind, 0);
    assert_eq!(retry(id, &[2; 32]).unwrap().kind, 2);
    assert_eq!(retry(id, &[3; 32]).unwrap().kind, 5);
    assert_eq!(
        retry(id, &[4; 32]).unwrap_err(),
        Failure {
            status: UNAVAILABLE,
            reason: 3,
            platform_code: 5
        }
    );
    assert_eq!(retry(id, &[0; 31]).unwrap_err().status, INVALID);
    assert_eq!(
        requests::request(&[0; 5], 9, 0, [&[]; 3])
            .unwrap_err()
            .status,
        INVALID
    );
    assert_eq!(calls.load(Ordering::SeqCst), 6);
    let mut result = WalletResult::default();
    assert_eq!(
        unsafe { connect_norito_kagemusha_wallet_fold_v1(id, &mut result) },
        0
    );
    assert_eq!(
        (
            result.status,
            result.sequence_low,
            result.sequence_high,
            result.detail
        ),
        (8, 7, 1 << 29, 3)
    );
    assert_eq!(
        unsafe { connect_norito_kagemusha_wallet_execute_v1(id, std::ptr::null(), &mut result) },
        INVALID
    );
    assert_eq!(
        unsafe { connect_norito_kagemusha_wallet_resume_v1(id, std::ptr::null_mut()) },
        INVALID
    );
    close(id).unwrap();
}
#[test]
fn failure_mapping_never_turns_uncertain_or_missing_custody_into_absence() {
    use advance::KagemushaWalletProviderErrorV1 as E;
    for reason in [
        U::Locked,
        U::BeforeFirstUnlock,
        U::Busy,
        U::Io(5),
        U::Platform(-1),
        U::KeyUnusable,
        U::PermanentlyInvalidated,
    ] {
        assert_eq!(Failure::from(E::Unavailable(reason)).status, UNAVAILABLE);
        assert_eq!(Failure::from(E::Uncertain(reason)).status, UNCERTAIN);
    }
    assert_eq!(
        Failure::from(E::UnavailableCustodyData {
            object: "archive checkpoint"
        })
        .status,
        CUSTODY_LOST
    );
    assert_eq!(
        Failure::from(state::Error::WitnessLost("Ω")).status,
        CUSTODY_LOST
    );
    assert_eq!(
        Failure::from(state::Error::ArtifactsUnavailable("original sigma PK")).status,
        ARTIFACTS_UNAVAILABLE
    );
    assert_eq!(
        run::<()>(|| panic!("test contained panic"))
            .unwrap_err()
            .status,
        INTERNAL
    );
}

#[test]
fn original_decoder_refusal_maps_to_resource_after_its_scope_retires() {
    let bytes = norito::encode_canonical(&vec![7u8; 128]).unwrap();
    let limits = norito::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, 0, 64);
    let original = norito::with_decode_limits_scope(limits, || {
        norito::decode_canonical_for_admission::<Vec<u8>>(
            &bytes,
            norito::canonical_decode_limits(bytes.len()),
        )
    })
    .unwrap_err();
    assert_eq!(
        original.kind(),
        norito::core::DecodeAttemptErrorKind::EnclosingLimit
    );
    // An unrelated scope with identical numbers does not reclassify the saved original.
    let failure = norito::with_decode_limits_scope(limits, || {
        Failure::from(state::Error::DecodeResource(
            original.into_local_refusal().unwrap(),
        ))
    });
    assert_eq!(failure, Failure::code(RESOURCE));
    assert_eq!(failure.reason, -1);
    assert_eq!(failure.platform_code, 0);
    assert_ne!(failure.status, PROOF_REJECTED);
    assert_ne!(failure.status, CUSTODY_LOST);
    assert_ne!(failure.status, NOT_ENOUGH_MEMORY);
}

#[derive(Default)]
struct CallbackState {
    retained: AtomicUsize,
    released: AtomicUsize,
    calls: AtomicUsize,
    invocations: Mutex<Vec<(u32, Vec<u8>, usize)>>,
    answer: Mutex<(PlatformReply, Vec<u8>)>,
}
unsafe extern "C" fn retain(pointer: *mut std::ffi::c_void) {
    unsafe { &*pointer.cast::<CallbackState>() }
        .retained
        .fetch_add(1, Ordering::SeqCst);
}
unsafe extern "C" fn release(pointer: *mut std::ffi::c_void) {
    unsafe { &*pointer.cast::<CallbackState>() }
        .released
        .fetch_add(1, Ordering::SeqCst);
}
unsafe extern "C" fn invoke(
    pointer: *mut std::ffi::c_void,
    operation: u32,
    _: *const u8,
    input: *const u8,
    input_length: usize,
    _: u32,
    output: *mut u8,
    capacity: usize,
    reply: *mut PlatformReply,
) {
    let state = unsafe { &*pointer.cast::<CallbackState>() };
    state.calls.fetch_add(1, Ordering::SeqCst);
    state.invocations.lock().unwrap().push((
        operation,
        unsafe { std::slice::from_raw_parts(input, input_length) }.to_vec(),
        capacity,
    ));
    let answer = state.answer.lock().unwrap();
    if answer.1.len() <= capacity {
        unsafe { std::ptr::copy_nonoverlapping(answer.1.as_ptr(), output, answer.1.len()) };
    }
    unsafe { reply.write(answer.0) };
}
fn callbacks(state: &CallbackState) -> PlatformCallbacks {
    PlatformCallbacks {
        version: 1,
        anchor_policy: 1,
        context: std::ptr::from_ref(state).cast_mut().cast(),
        retain: Some(retain),
        release: Some(release),
        invoke: Some(invoke),
    }
}
#[test]
fn callback_tri_state_bounds_anchor_policy_and_lifetime_are_explicit() {
    let state = CallbackState::default();
    let adapter = unsafe { CallbackPlatform::new(callbacks(&state)) }.unwrap();
    let slot = advance::KagemushaWalletSlotIdV1([1; 32]);
    assert_eq!(
        adapter.anchor_policy(),
        advance::KagemushaWalletAnchorPolicyV1::Keychain
    );
    assert_eq!(state.retained.load(Ordering::SeqCst), 1);
    assert_eq!(adapter.key_probe(&slot), Probe::Unavailable(U::Platform(0)));
    *state.answer.lock().unwrap() = (
        PlatformReply {
            tag: 1,
            ..PlatformReply::default()
        },
        vec![],
    );
    assert_eq!(adapter.key_probe(&slot), Probe::Absent);
    assert_eq!(adapter.storage_state(), Err(U::Platform(0)));
    for (reason, expected) in [
        (0, U::Locked),
        (1, U::BeforeFirstUnlock),
        (2, U::Busy),
        (3, U::Io(9)),
        (4, U::Platform(9)),
        (5, U::KeyUnusable),
        (6, U::PermanentlyInvalidated),
        (77, U::Platform(0)),
    ] {
        *state.answer.lock().unwrap() = (
            PlatformReply {
                tag: 2,
                reason,
                code: 9,
                length: 0,
            },
            vec![],
        );
        assert_eq!(adapter.key_probe(&slot), Probe::Unavailable(expected));
        assert_eq!(adapter.storage_state(), Err(expected));
    }
    *state.answer.lock().unwrap() = (
        PlatformReply {
            tag: 0,
            length: 66,
            ..PlatformReply::default()
        },
        vec![],
    );
    assert_eq!(adapter.key_probe(&slot), Probe::Unavailable(U::Platform(0)));
    assert_eq!(
        adapter.anchor_create(&slot, b"a"),
        advance::KagemushaWalletPublishOutcomeV1::Uncertain(U::Platform(0))
    );
    *state.answer.lock().unwrap() = (
        PlatformReply {
            tag: 0,
            length: 4,
            ..PlatformReply::default()
        },
        b"/tmp".to_vec(),
    );
    assert_eq!(
        adapter.custody_root().unwrap(),
        std::path::Path::new("/tmp")
    );
    drop(adapter);
    assert_eq!(state.released.load(Ordering::SeqCst), 1);
    let mut invalid = callbacks(&state);
    invalid.anchor_policy = 0;
    assert!(unsafe { CallbackPlatform::new(invalid) }.is_err());
    assert_eq!(state.retained.load(Ordering::SeqCst), 1);
}
#[test]
fn callback_anchor_bounds_forward_canonical_max_and_reject_oversized_inputs() {
    use advance::{
        KAGEMUSHA_WALLET_ANCHOR_MAX_BYTES_V1 as MAX, KagemushaWalletNotPublishedV1 as NotPublished,
        KagemushaWalletPublishOutcomeV1 as Publish,
    };

    let state = CallbackState::default();
    let adapter = unsafe { CallbackPlatform::new(callbacks(&state)) }.unwrap();
    let slot = advance::KagemushaWalletSlotIdV1([7; 32]);
    let anchor = vec![0xa5; MAX];
    *state.answer.lock().unwrap() = (
        PlatformReply {
            tag: 0,
            ..PlatformReply::default()
        },
        vec![],
    );

    assert_eq!(adapter.anchor_create(&slot, &anchor), Publish::Published);
    assert_eq!(adapter.anchor_update(&slot, &anchor), Publish::Published);
    assert_eq!(state.calls.load(Ordering::SeqCst), 2);
    assert_eq!(
        *state.invocations.lock().unwrap(),
        [(5, anchor.clone(), 0), (6, anchor.clone(), 0)]
    );

    let oversized = vec![0xa5; MAX + 1];
    let rejected = Publish::NotPublished(NotPublished::Failed(U::Platform(0)));
    assert_eq!(adapter.anchor_create(&slot, &oversized), rejected);
    assert_eq!(adapter.anchor_update(&slot, &oversized), rejected);
    assert_eq!(state.calls.load(Ordering::SeqCst), 2);
    assert_eq!(state.invocations.lock().unwrap().len(), 2);

    *state.answer.lock().unwrap() = (
        PlatformReply {
            tag: 0,
            length: MAX,
            ..PlatformReply::default()
        },
        anchor.clone(),
    );
    assert_eq!(adapter.anchor_read(&slot), Probe::Present(anchor.clone()));
    assert_eq!(state.calls.load(Ordering::SeqCst), 3);
    assert_eq!(
        state.invocations.lock().unwrap().last(),
        Some(&(4, vec![], MAX))
    );

    state.answer.lock().unwrap().0.length = MAX + 1;
    assert_eq!(
        adapter.anchor_read(&slot),
        Probe::Unavailable(U::Platform(0))
    );
    assert_eq!(state.calls.load(Ordering::SeqCst), 4);
}
#[test]
fn foreign_open_requires_native_runtime_and_never_accepts_digest_authority() {
    let bytes = [1u8];
    let request = WalletOpenRequest {
        credential: bytes.as_ptr(),
        credential_length: 1,
        certificates: bytes.as_ptr(),
        certificates_length: 1,
        account: bytes.as_ptr(),
        account_length: 1,
        asset: bytes.as_ptr(),
        asset_length: 1,
    };
    let mut result = WalletResult::default();
    assert_eq!(
        unsafe { connect_norito_kagemusha_wallet_open_begin_v1(u64::MAX, &request, &mut result) },
        ARTIFACTS_UNAVAILABLE
    );
    assert_eq!(result.status, ARTIFACTS_UNAVAILABLE);
    assert_eq!(result.sequence_low, 0);
    assert!(result.bytes.is_null());
    assert_eq!(
        unsafe {
            connect_norito_kagemusha_wallet_open_begin_v1(u64::MAX, std::ptr::null(), &mut result)
        },
        INVALID
    );
    assert_eq!(
        unsafe {
            connect_norito_kagemusha_wallet_open_finish_v1(
                u64::MAX,
                std::ptr::null(),
                0,
                &mut result,
            )
        },
        ARTIFACTS_UNAVAILABLE
    );
    assert_eq!(
        connect_norito_kagemusha_wallet_open_cancel_v1(u64::MAX),
        ARTIFACTS_UNAVAILABLE
    );
}
#[test]
fn open_request_layout_has_exact_four_original_pointer_length_pairs() {
    use std::mem::{offset_of, size_of};
    let word = size_of::<usize>();
    assert_eq!(size_of::<WalletOpenRequest>(), 8 * word);
    assert_eq!(offset_of!(WalletOpenRequest, credential), 0);
    assert_eq!(offset_of!(WalletOpenRequest, credential_length), word);
    assert_eq!(offset_of!(WalletOpenRequest, certificates), 2 * word);
    assert_eq!(offset_of!(WalletOpenRequest, certificates_length), 3 * word);
    assert_eq!(offset_of!(WalletOpenRequest, account), 4 * word);
    assert_eq!(offset_of!(WalletOpenRequest, account_length), 5 * word);
    assert_eq!(offset_of!(WalletOpenRequest, asset), 6 * word);
    assert_eq!(offset_of!(WalletOpenRequest, asset_length), 7 * word);
}

#[test]
fn collected_receive_returns_existing_credit_status_response_kind() {
    let response = completion(Some(state::Completion::CreditStatus(vec![1, 2, 3]))).unwrap();
    assert_eq!(response.kind, 10);
    assert_eq!(response.bytes, [1, 2, 3]);
}

#[test]
fn runtime_capacity_shortfalls_are_typed_failures_never_device_verdicts() {
    use advance::{KagemushaWalletNotPerformedV1 as N, KagemushaWalletProviderErrorV1 as P};
    assert_eq!((NOT_ENOUGH_STORAGE, NOT_ENOUGH_MEMORY), (-12, -14));
    // Before proving and before commit (design §5.3).
    for (error, status) in [
        (state::Error::NotEnoughStorage, NOT_ENOUGH_STORAGE),
        (state::Error::NotEnoughMemory, NOT_ENOUGH_MEMORY),
        (state::Error::Provider(P::NoSpace), NOT_ENOUGH_STORAGE),
    ] {
        let failure = Failure::from(error);
        assert_eq!(failure, Failure::code(status));
        assert_eq!((failure.reason, failure.platform_code), (-1, 0));
    }
    // Advance's own commit-time reservation is the same typed storage result, not a
    // not-performed detail.
    assert_eq!(
        completion(Some(state::Completion::NotPerformed(N::CapacityWait))).unwrap_err(),
        Failure::code(NOT_ENOUGH_STORAGE)
    );
    for (reason, detail) in [(N::StaleHead, 0), (N::Invalid { field: "x" }, 2)] {
        let response = completion(Some(state::Completion::NotPerformed(reason))).unwrap();
        assert_eq!((response.kind, response.detail), (3, detail));
        assert!(response.bytes.is_empty());
    }
    // The C result carries the status with no bytes and no platform reason.
    for status in [NOT_ENOUGH_STORAGE, NOT_ENOUGH_MEMORY] {
        let mut out = WalletResult::default();
        let returned = unsafe { exports::output(&mut out, || Err(Failure::code(status))) };
        assert_eq!((returned, out.status, out.reason), (status, status, -1));
        assert!(out.bytes.is_null());
        assert_eq!(out.length, 0);
    }
}

#[test]
fn callback_key_inventory_has_exact_bounded_complete_grammar_and_retained_lifetime() {
    let state = CallbackState::default();
    let adapter = unsafe { CallbackPlatform::new(callbacks(&state)) }.unwrap();
    let maximum = advance::KAGEMUSHA_WALLET_KEY_ENUMERATION_MAX_SLOTS_V1;
    let set = |tag, bytes: Vec<u8>| {
        *state.answer.lock().unwrap() = (
            PlatformReply {
                tag,
                length: bytes.len(),
                ..PlatformReply::default()
            },
            bytes,
        );
    };
    set(0, vec![]);
    assert_eq!(adapter.key_enumerate(), Ok(vec![]));
    let slots = [
        advance::KagemushaWalletSlotIdV1([1; 32]),
        advance::KagemushaWalletSlotIdV1([2; 32]),
    ];
    set(0, slots.iter().flat_map(|s| s.0).collect());
    assert_eq!(adapter.key_enumerate(), Ok(slots.to_vec()));
    assert_eq!(
        state.invocations.lock().unwrap().last(),
        Some(&(10, vec![], maximum * 32))
    );
    for malformed in [
        vec![1; 31],
        vec![0; 32],
        [vec![1; 32], vec![1; 32]].concat(),
        [vec![2; 32], vec![1; 32]].concat(),
        vec![1; maximum * 32 + 1],
    ] {
        set(0, malformed);
        assert_eq!(adapter.key_enumerate(), Err(U::Platform(0)));
    }
    // Neither an absent tag nor an unavailable answer carrying bytes is a complete inventory.
    set(1, vec![]);
    assert_eq!(adapter.key_enumerate(), Err(U::Platform(0)));
    set(2, vec![1; 32]);
    assert_eq!(adapter.key_enumerate(), Err(U::Platform(0)));
    for reason in [0, 1, 2, 3, 4, 5, 6] {
        *state.answer.lock().unwrap() = (
            PlatformReply {
                tag: 2,
                reason,
                code: 19,
                ..PlatformReply::default()
            },
            vec![],
        );
        assert_eq!(
            adapter.key_enumerate(),
            Err(platform::reason(state.answer.lock().unwrap().0))
        );
    }
    drop(adapter);
    assert_eq!(state.retained.load(Ordering::SeqCst), 1);
    assert_eq!(state.released.load(Ordering::SeqCst), 1);
}

#[test]
fn callback_key_inventory_accepts_exact_maximum_without_truncation() {
    let state = CallbackState::default();
    let adapter = unsafe { CallbackPlatform::new(callbacks(&state)) }.unwrap();
    let maximum = advance::KAGEMUSHA_WALLET_KEY_ENUMERATION_MAX_SLOTS_V1;
    let slots: Vec<_> = (1..=maximum)
        .map(|i| {
            let mut bytes = [0; 32];
            bytes[28..].copy_from_slice(&(i as u32).to_be_bytes());
            advance::KagemushaWalletSlotIdV1(bytes)
        })
        .collect();
    let bytes: Vec<_> = slots.iter().flat_map(|slot| slot.0).collect();
    *state.answer.lock().unwrap() = (
        PlatformReply {
            tag: 0,
            length: bytes.len(),
            ..PlatformReply::default()
        },
        bytes,
    );
    assert_eq!(adapter.key_enumerate(), Ok(slots));
}

#[test]
fn c_snapshot_preserves_u128_lifecycle_and_explicit_unfolded_value() {
    let (id, _, _) = installed();
    let mut result = WalletSnapshot::default();
    assert_eq!(
        unsafe { connect_norito_kagemusha_wallet_snapshot_v1(id, &mut result) },
        0
    );
    assert_eq!((result.status, result.lifecycle, result.flags), (0, 2, 1));
    assert_eq!((result.sequence.low, result.sequence.high), (7, 1 << 29));
    assert_eq!(
        (result.balance.low, result.balance.high),
        (u64::MAX, u64::MAX)
    );
    assert_eq!(
        (result.owned_balance.low, result.owned_balance.high),
        (u64::MAX - 3, u64::MAX)
    );
    assert_eq!(result.folded_balance, WalletU128::default());
    assert_eq!(result.folded_head, [5; 32]);
    close(id).unwrap();
    // Failure clears every projection; stale output is never an empty or spendable wallet.
    assert_eq!(
        unsafe { connect_norito_kagemusha_wallet_snapshot_v1(id, &mut result) },
        CLOSED
    );
    assert_eq!(
        (result.status, result.flags, result.lifecycle),
        (CLOSED, 0, 0)
    );
    assert_eq!(result.balance, WalletU128::default());
    assert_eq!(result.head, [0; 32]);
    assert_eq!(
        unsafe { connect_norito_kagemusha_wallet_snapshot_v1(id, std::ptr::null_mut()) },
        INVALID
    );
}
#[test]
fn snapshot_pod_has_explicit_presence_for_a_valid_zero_folded_balance() {
    let (id, _, _) = installed();
    let mut value = snapshot(id).unwrap();
    close(id).unwrap();
    value.folded_balance = Some(0);
    value.owned_balance = 0;
    value.verified_fold.as_mut().unwrap().sequence = value.sequence;
    let out = WalletSnapshot::from(value);
    assert_eq!(out.flags, 3);
    assert_eq!(out.folded_balance, WalletU128::default());
    let fail = WalletSnapshot::from(Failure::unavailable(UNCERTAIN, U::Io(5)));
    assert_eq!(
        (fail.status, fail.reason, fail.platform_code),
        (UNCERTAIN, 3, 5)
    );
    assert_eq!(fail.flags, 0);
    assert_eq!(fail.owned_balance, WalletU128::default());
}

#[test]
fn c_typed_execute_preserves_intake_bounds_and_distinct_preparation_status() {
    let (id, calls, _) = installed();
    let identity = [1; 32];
    let mut request = WalletOperationRequest {
        request_id: identity.as_ptr(),
        selector: 9,
        amount: WalletU128::default(),
        first: std::ptr::null(),
        first_length: 0,
        second: std::ptr::null(),
        second_length: 0,
        third: std::ptr::null(),
        third_length: 0,
    };
    let mut result = WalletResult::default();
    assert_eq!(
        unsafe { connect_norito_kagemusha_wallet_execute_v1(id, &request, &mut result) },
        PROOF_REJECTED
    );
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert_eq!(result.status, PROOF_REJECTED);
    assert!(result.bytes.is_null());
    request.first_length = 1;
    assert_eq!(
        unsafe { connect_norito_kagemusha_wallet_execute_v1(id, &request, &mut result) },
        INVALID
    );
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert_eq!(
        unsafe {
            connect_norito_kagemusha_wallet_request_status_v1(id, identity.as_ptr(), &mut result)
        },
        0
    );
    assert_eq!(result.status, 11);
    assert_eq!(result.length, 0);
    assert_eq!(calls.load(Ordering::SeqCst), 2);
    close(id).unwrap();
}

#[test]
fn c_operation_request_layout_and_reviewed_unsigned_amount_reach_the_exact_typed_owner() {
    use std::mem::{align_of, offset_of, size_of};
    // Derive the C field placement from primitive platform ABI alignment. In particular,
    // the amount is two u64 limbs, not compiler-specific u128 or an opaque byte codec.
    let align = |position: usize, alignment: usize| position.div_ceil(alignment) * alignment;
    let pointer = size_of::<*const u8>();
    let selector = align(pointer, align_of::<u32>());
    let amount = align(selector + size_of::<u32>(), align_of::<WalletU128>());
    let first = align(amount + size_of::<WalletU128>(), align_of::<*const u8>());
    assert_eq!(offset_of!(WalletU128, low), 0);
    assert_eq!(offset_of!(WalletU128, high), size_of::<u64>());
    assert_eq!(size_of::<WalletU128>(), 2 * size_of::<u64>());
    assert_eq!(offset_of!(WalletOperationRequest, request_id), 0);
    assert_eq!(offset_of!(WalletOperationRequest, selector), selector);
    assert_eq!(offset_of!(WalletOperationRequest, amount), amount);
    assert_eq!(offset_of!(WalletOperationRequest, first), first);
    assert_eq!(
        offset_of!(WalletOperationRequest, first_length),
        first + pointer
    );
    assert_eq!(
        offset_of!(WalletOperationRequest, second),
        first + 2 * pointer
    );
    assert_eq!(
        offset_of!(WalletOperationRequest, second_length),
        first + 3 * pointer
    );
    assert_eq!(
        offset_of!(WalletOperationRequest, third),
        first + 4 * pointer
    );
    assert_eq!(
        offset_of!(WalletOperationRequest, third_length),
        first + 5 * pointer
    );
    assert_eq!(
        size_of::<WalletOperationRequest>(),
        align(first + 6 * pointer, align_of::<WalletOperationRequest>())
    );

    let identity = [19; 32];
    let quote = [1, 0, 255, 2];
    let certificates = [2, 255, 0, 1];
    let amount = (u128::from(0xfedc_ba98_7654_3210_u64) << 64) | 0x0123_4567_89ab_cdef;
    let calls = Arc::new(AtomicUsize::new(0));
    let handle = install(
        Box::new(TestWallet {
            calls: calls.clone(),
            drops: Arc::new(AtomicUsize::new(0)),
            expected_request: Some(state::OperationRequestV1 {
                request_id: identity,
                action: state::OperationActionV1::Unload {
                    amount,
                    charge: Some(state::ChargeOriginalsV1 {
                        quote: quote.to_vec(),
                        certificates: certificates.to_vec(),
                    }),
                },
            }),
        }),
        state::Scheduler::new(),
    )
    .unwrap();
    let request = WalletOperationRequest {
        request_id: identity.as_ptr(),
        selector: 8,
        amount: WalletU128 {
            low: amount as u64,
            high: (amount >> 64) as u64,
        },
        first: quote.as_ptr(),
        first_length: quote.len(),
        second: certificates.as_ptr(),
        second_length: certificates.len(),
        third: std::ptr::null(),
        third_length: 0,
    };
    let mut result = WalletResult::default();
    // Unload must first pass review; direct execution never reaches the owner.
    assert_eq!(
        unsafe { connect_norito_kagemusha_wallet_execute_v1(handle, &request, &mut result) },
        INVALID
    );
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    let mut companion = b"KWUCV1\0\0".to_vec();
    companion.extend_from_slice(&(certificates.len() as u32).to_le_bytes());
    companion.extend_from_slice(&certificates);
    companion.extend_from_slice(&4_u32.to_le_bytes());
    companion.extend_from_slice(&[3, 255, 0, 1]);
    let review = WalletReviewRequest {
        selector: request.selector,
        amount: request.amount,
        first: request.first,
        first_length: request.first_length,
        second: companion.as_ptr(),
        second_length: companion.len(),
    };
    // The stand-in review owner asserts the exact unsigned amount and charge originals.
    assert_eq!(
        unsafe { connect_norito_kagemusha_wallet_review_v1(handle, &review, &mut result) },
        PROOF_REJECTED
    );
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert_eq!(result.status, PROOF_REJECTED);
    assert!(result.bytes.is_null());
    close(handle).unwrap();
}

#[test]
fn setup_c_layout_and_bounds_preserve_exact_identity_amount_and_unused_slots() {
    use std::mem::{align_of, offset_of, size_of};
    let align = |n: usize, a: usize| (n + a - 1) & !(a - 1);
    let pointer = size_of::<*const u8>();
    let amount = align(pointer + 4, align_of::<WalletU128>());
    let token = align(amount + size_of::<WalletU128>(), align_of::<u64>());
    let first = align(token + 8, align_of::<*const u8>());
    assert_eq!(offset_of!(WalletSetupRequest, setup_id), 0);
    assert_eq!(offset_of!(WalletSetupRequest, selector), pointer);
    assert_eq!(offset_of!(WalletSetupRequest, amount), amount);
    assert_eq!(offset_of!(WalletSetupRequest, token), token);
    assert_eq!(offset_of!(WalletSetupRequest, first), first);
    assert_eq!(
        offset_of!(WalletSetupRequest, first_length),
        first + pointer
    );
    assert_eq!(offset_of!(WalletSetupRequest, second), first + 2 * pointer);
    assert_eq!(
        offset_of!(WalletSetupRequest, second_length),
        first + 3 * pointer
    );
    assert_eq!(offset_of!(WalletSetupRequest, third), first + 4 * pointer);
    assert_eq!(
        offset_of!(WalletSetupRequest, third_length),
        first + 5 * pointer
    );
    assert_eq!(
        size_of::<WalletSetupRequest>(),
        align(first + 6 * pointer, align_of::<WalletSetupRequest>())
    );
    let id = [4; 32];
    let calls = Arc::new(AtomicUsize::new(0));
    let handle = install(
        Box::new(TestWallet {
            calls: calls.clone(),
            drops: Arc::new(AtomicUsize::new(0)),
            expected_request: None,
        }),
        state::Scheduler::new(),
    )
    .unwrap();
    let mut request = WalletSetupRequest {
        setup_id: id.as_ptr(),
        selector: 1,
        amount: WalletU128 {
            low: u64::MAX,
            high: u64::MAX,
        },
        token: 0,
        first: std::ptr::null(),
        first_length: 0,
        second: std::ptr::null(),
        second_length: 0,
        third: std::ptr::null(),
        third_length: 0,
    };
    let mut result = WalletResult::default();
    assert_eq!(
        unsafe { connect_norito_kagemusha_wallet_setup_v1(handle, &request, &mut result) },
        0
    );
    assert_eq!(result.status, 12);
    assert_eq!(
        unsafe { std::slice::from_raw_parts(result.bytes, result.length) },
        &[0, 255, 7]
    );
    crate::connect_norito_free(result.bytes);
    request.token = 1;
    assert_eq!(
        unsafe { connect_norito_kagemusha_wallet_setup_v1(handle, &request, &mut result) },
        INVALID
    );
    assert!(result.bytes.is_null());
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    close(handle).unwrap();
}

#[test]
fn unload_setup_c_refuses_unknown_owner_and_invalid_shape_without_output() {
    let id = [9; 32];
    let zero = [0; 32];
    let mut request = WalletSetupRequest {
        setup_id: id.as_ptr(),
        selector: 45,
        amount: WalletU128 { low: 0, high: 0 },
        token: 0,
        first: std::ptr::null(),
        first_length: 0,
        second: std::ptr::null(),
        second_length: 0,
        third: std::ptr::null(),
        third_length: 0,
    };
    let mut result = WalletResult::default();
    assert_eq!(
        unsafe { connect_norito_kagemusha_wallet_setup_v1(0, &request, &mut result) },
        CLOSED
    );
    assert_eq!(result.status, CLOSED);
    assert!(result.bytes.is_null());
    assert_eq!(result.length, 0);
    request.setup_id = zero.as_ptr();
    assert_eq!(
        unsafe { connect_norito_kagemusha_wallet_setup_v1(0, &request, &mut result) },
        INVALID
    );
    request.setup_id = id.as_ptr();
    request.token = 1;
    assert_eq!(
        unsafe { connect_norito_kagemusha_wallet_setup_v1(0, &request, &mut result) },
        INVALID
    );
    request.token = 0;
    let overlong = vec![1; 16_385];
    request.first = overlong.as_ptr();
    request.first_length = overlong.len();
    assert_eq!(
        unsafe { connect_norito_kagemusha_wallet_setup_v1(0, &request, &mut result) },
        INVALID
    );
    assert!(result.bytes.is_null());
    assert_eq!(result.length, 0);
}

#[test]
fn interrupted_open_response_recovers_same_live_handle_and_closed_is_final() {
    let (id, calls, drops) = installed();
    for _ in 0..2 {
        let value = open::finish(id, &[]).unwrap();
        assert_eq!((value.kind, value.sequence), (16, u128::from(id)));
        assert!(value.bytes.is_empty());
    }
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    close(id).unwrap();
    assert_eq!(open::finish(id, &[]).unwrap_err().status, CLOSED);
    assert_eq!(drops.load(Ordering::SeqCst), 1);
}

#[test]
fn callback_generation_recovery_preserves_original_none_unavailable_and_bounds() {
    let state = CallbackState::default();
    let adapter = unsafe { CallbackPlatform::new(callbacks(&state)) }.unwrap();
    let slot = advance::KagemushaWalletSlotIdV1([9; 32]);
    let request = advance::KagemushaWalletKeyGenerationRequestV1 {
        challenge_digest: [10; 32],
        profile: advance::KagemushaWalletKeyProfileV1::SecureElementOrTee,
    };
    assert_eq!(
        adapter.key_recover_generation_reply(&slot, &request),
        Err(U::Platform(0))
    );
    *state.answer.lock().unwrap() = (
        PlatformReply {
            tag: 3,
            length: 0,
            ..PlatformReply::default()
        },
        vec![],
    );
    assert_eq!(
        adapter.key_recover_generation_reply(&slot, &request),
        Ok(None)
    );
    // No held return is independent of an unknown current key probe.
    assert_eq!(adapter.key_probe(&slot), Probe::Unavailable(U::Platform(0)));
    *state.answer.lock().unwrap() = (
        PlatformReply {
            tag: 2,
            reason: 0,
            length: 0,
            ..PlatformReply::default()
        },
        vec![],
    );
    assert_eq!(
        adapter.key_recover_generation_reply(&slot, &request),
        Err(U::Locked)
    );
    assert_eq!(adapter.key_probe(&slot), Probe::Unavailable(U::Locked));
    let payment = p256::ecdsa::SigningKey::from_bytes((&[9; 32]).into()).unwrap();
    let bytes = payment
        .verifying_key()
        .to_encoded_point(false)
        .as_bytes()
        .to_vec();
    let expected =
        iroha_data_model::kagemusha::KagemushaDevicePublicKeyV1::from_sec1_bytes(&bytes).unwrap();
    *state.answer.lock().unwrap() = (
        PlatformReply {
            tag: 0,
            length: 65,
            ..PlatformReply::default()
        },
        bytes,
    );
    assert_eq!(
        adapter.key_recover_generation_reply(&slot, &request),
        Ok(Some(expected))
    );
    *state.answer.lock().unwrap() = (
        PlatformReply {
            tag: 0,
            length: 65,
            ..PlatformReply::default()
        },
        vec![0; 65],
    );
    assert_eq!(
        adapter.key_recover_generation_reply(&slot, &request),
        Err(U::KeyUnusable)
    );
    for (tag, length) in [(0, 66), (3, 1), (2, 1), (1, 0), (99, 0)] {
        *state.answer.lock().unwrap() = (
            PlatformReply {
                tag,
                length,
                ..PlatformReply::default()
            },
            vec![0; length],
        );
        assert_eq!(
            adapter.key_recover_generation_reply(&slot, &request),
            Err(U::Platform(0))
        );
    }
    assert_eq!(
        state
            .invocations
            .lock()
            .unwrap()
            .iter()
            .filter(|(op, _, _)| *op == 1)
            .count(),
        0
    );
    for (op, bytes, capacity) in state.invocations.lock().unwrap().iter() {
        if *op == 13 {
            assert_eq!(bytes.as_slice(), &request.challenge_digest[..]);
            assert_eq!(*capacity, 65);
        }
    }
}

#[test]
fn retained_intake_and_preparation_refusals_map_to_resource_without_reclassification() {
    use iroha_core_zk::kagemusha_wallet_intake_v1 as intake;
    let bytes = norito::encode_canonical(&vec![7u8; 128]).unwrap();
    let limits = norito::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, 0, 64);
    let original = norito::with_decode_limits_scope(limits, || {
        norito::decode_canonical_for_admission::<Vec<u8>>(
            &bytes,
            norito::canonical_decode_limits(bytes.len()),
        )
    })
    .unwrap_err()
    .into_local_refusal()
    .unwrap();
    let retained = original.clone();
    let failure = norito::with_decode_limits_scope(limits, || {
        Failure::from(state::NativeOpenErrorV1::Intake(
            intake::Error::DecodeResource(original),
        ))
    });
    assert_eq!(failure, Failure::code(RESOURCE));
    assert_eq!(
        Failure::from(state::Error::DecodeResource(retained)),
        failure
    );
    assert_ne!(failure.status, PROOF_REJECTED);
    assert_ne!(failure.status, CUSTODY_LOST);
    assert_ne!(failure.status, NOT_ENOUGH_MEMORY);
    assert_eq!(
        Failure::from(state::NativeOpenErrorV1::Intake(intake::Error::Authority(
            "bad original"
        ))),
        Failure::code(INVALID)
    );
    assert_eq!(
        Failure::from(state::NativeOpenErrorV1::Intake(
            intake::Error::SourceChanged
        )),
        Failure::code(CONFLICT)
    );
    assert_eq!(
        norito::decode_canonical::<Vec<u8>>(&bytes).unwrap(),
        vec![7; 128]
    );
}

#[test]
fn custody_failure_reasons_report_only_the_existing_closed_cause() {
    use advance::{KagemushaWalletLostCustodyV1 as L, KagemushaWalletProviderErrorV1 as E};
    for (error, reason) in [
        (E::LostCustody(L::KeyWithoutMarker), 100),
        (E::LostCustody(L::JournalWithoutMarker), 101),
        (E::LostCustody(L::AnchorMissing), 102),
        (E::LostCustody(L::RolledBack), 103),
        (E::LostCustody(L::AnchorMismatch), 104),
        (E::LostCustody(L::CompletionLost), 105),
        (
            E::UnavailableCustodyData {
                object: "enrollment intent",
            },
            111,
        ),
        (
            E::UnavailableCustodyData {
                object: "enrollment phase",
            },
            112,
        ),
        (
            E::UnavailableCustodyData {
                object: "committed enrollment marker",
            },
            113,
        ),
        (
            E::UnavailableCustodyData {
                object: "abandoned slot custody conflict",
            },
            114,
        ),
        (
            E::UnavailableCustodyData {
                object: "unlisted private object label",
            },
            110,
        ),
        (
            E::UnexpectedEntry {
                dir: "unlisted private directory label",
            },
            120,
        ),
    ] {
        let expected = Failure {
            status: CUSTODY_LOST,
            reason,
            platform_code: 0,
        };
        assert_eq!(Failure::from(error), expected);
        // The real enrollment path wraps the same already-computed provider error.
        assert_eq!(
            Failure::from(iroha_core_zk::kagemusha_wallet_enrollment_v1::Error::Provider(error)),
            expected
        );
    }
}

#[test]
fn custody_failure_reasons_preserve_other_failure_contracts() {
    use advance::{KagemushaWalletProviderErrorV1 as E, KagemushaWalletUnavailableV1 as U};
    for (error, status) in [
        (E::Unavailable(U::Io(17)), UNAVAILABLE),
        (E::Uncertain(U::Io(17)), UNCERTAIN),
    ] {
        assert_eq!(
            Failure::from(error),
            Failure {
                status,
                reason: 3,
                platform_code: 17
            }
        );
    }
    for (error, status) in [
        (E::NoSpace, NOT_ENOUGH_STORAGE),
        (E::NoReplaceUnsupported, INVALID),
        (E::Invalid { field: "unchanged" }, INVALID),
        (E::KeyLost, TERMINAL),
        (E::Terminal, TERMINAL),
    ] {
        assert_eq!(Failure::from(error), Failure::code(status));
    }
}
