//! C ABI, with initialized outputs and panic containment at each boundary.

use super::*;

/// Typed call result. `bytes` uses the existing `connect_norito_free` allocator contract.
#[repr(C)]
#[derive(Debug)]
pub struct WalletResult {
    /// 0 unknown, 1 complete, 2 pending, 3 not performed, 4 archived, 5 delivery loss,
    /// 6 idle, 7 caught up, 8 checkpoint, 9 folded, 10 CreditStatus, 11 preparing;
    /// setup only: 12 original, 13 owned time challenge, 14 time exchange retained.
    /// Open: 15 account challenge,16 admitted handle;17 retained Activation.
    /// Enrollment18..28 are typed challenge/evidence/retained-original/runtime statuses;
    /// 58 is a local no-marker enrollment abandonment (nothing to submit).
    /// CloseLoads30; FeeClaim31/absent32; selected ledger tip33/absent34; fee payout acknowledged35.
    /// FeeClaim transport36; enrollment selection37/Apple originals38/custody acknowledgement39.
    /// Ledger instruction40/Unload confirmation42; retired result kinds41/43 are rejected.
    /// Activation confirmed44/verifying45/not started46/rejected49; UnloadClaim48.
    /// Collection idle50/progress51/collected52: no bytes/detail, sequence only for51/52.
    /// Destructive review53: token+254 DATA bytes; deleted54: marker32; discarded55/not-deleted56 empty.
    /// Background29: phase/eligibility/backlog-known in detail; sequence is last observed backlog.
    /// CreditProjection47: exact typed header92 plus receiver original up to10000 bytes.
    /// Negative is failure.
    pub status: i32,
    /// Failure platform reason or -1. Never conflate `UNAVAILABLE` with unknown/absent.
    pub reason: i32,
    /// OS/platform code for a failure.
    pub platform_code: i32,
    /// Low 64 bits of a checkpoint/fold sequence.
    pub sequence_low: u64,
    /// High 64 bits of the sequence.
    pub sequence_high: u64,
    /// Checkpoint ordinal; for not-performed: 0 stale head, 2 invalid. A storage or memory
    /// shortfall is the typed failure `NOT_ENOUGH_STORAGE` (-12) or `NOT_ENOUGH_MEMORY` (-14).
    pub detail: u32,
    /// Canonical result bytes; null for an empty result. Release with `connect_norito_free`.
    pub bytes: *mut u8,
    /// Exact initialized bytes length.
    pub length: usize,
}
impl Default for WalletResult {
    fn default() -> Self {
        Self {
            status: INTERNAL,
            reason: -1,
            platform_code: 0,
            sequence_low: 0,
            sequence_high: 0,
            detail: 0,
            bytes: std::ptr::null_mut(),
            length: 0,
        }
    }
}
pub(super) unsafe fn output(
    out: *mut WalletResult,
    action: impl FnOnce() -> Result<Response>,
) -> i32 {
    unsafe { output_with(out, action, allocate_bytes) }
}
fn allocate_bytes(value: &mut WalletResult, bytes: &[u8]) -> std::result::Result<(), ()> {
    let mut length = 0;
    // Local initialized outputs and an exact borrowed slice; same bridge allocation owner.
    unsafe { crate::write_bytes(&mut value.bytes, &mut length, bytes) }.map_err(|_| ())?;
    value.length = length as usize;
    Ok(())
}
// One serialization path lets tests inject a post-issuance allocator refusal without OOM.
pub(super) unsafe fn output_with(
    out: *mut WalletResult,
    action: impl FnOnce() -> Result<Response>,
    allocate: impl FnOnce(&mut WalletResult, &[u8]) -> std::result::Result<(), ()>,
) -> i32 {
    if out.is_null() {
        return INVALID;
    }
    // SAFETY: caller provides writable aligned result memory.
    unsafe { out.write(WalletResult::default()) };
    let result = run(action);
    let value = match result {
        Ok(response) => {
            let mut value = WalletResult {
                status: response.kind,
                sequence_low: response.sequence as u64,
                sequence_high: (response.sequence >> 64) as u64,
                detail: response.detail,
                ..WalletResult::default()
            };
            if !response.bytes.is_empty() && allocate(&mut value, &response.bytes).is_err() {
                // Preserve the initialized failure geometry even after the owner issued DATA.
                unsafe {
                    out.write(WalletResult {
                        status: RESOURCE,
                        ..WalletResult::default()
                    })
                };
                return RESOURCE;
            }
            value
        }
        Err(error) => WalletResult {
            status: error.status,
            reason: error.reason,
            platform_code: error.platform_code,
            ..WalletResult::default()
        },
    };
    let status = if value.status < 0 { value.status } else { 0 };
    // SAFETY: admitted writable result memory; no previous owned output exists here.
    unsafe { out.write(value) };
    status
}
pub(super) unsafe fn input<'a>(
    pointer: *const u8,
    length: usize,
    bound: usize,
) -> Result<&'a [u8]> {
    if length > bound || (pointer.is_null() && length != 0) {
        return Err(Failure::code(INVALID));
    }
    if length == 0 {
        return Ok(&[]);
    }
    // SAFETY: caller supplies initialized input of length; bound checked before constructing slice.
    Ok(unsafe { std::slice::from_raw_parts(pointer, length) })
}
/// Wallet ABI revision. This is not evidence that the native artifacts are available.
#[unsafe(no_mangle)]
pub extern "C" fn connect_norito_kagemusha_wallet_revision_v1() -> u32 {
    1
}
/// Original owner frames. Native selects slot, scheme, wallet and complete proof owners.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct WalletOpenRequest {
    /// Original issuer-authenticated credential.
    pub credential: *const u8,
    /// Exact credential frame length.
    pub credential_length: usize,
    /// Original Enrollment CertificateSet.
    pub certificates: *const u8,
    /// Exact certificate-set frame length.
    pub certificates_length: usize,
    /// Existing canonical AccountId frame.
    pub account: *const u8,
    /// Exact account frame length.
    pub account_length: usize,
    /// Original issuer-bound asset scope and scale.
    pub asset: *const u8,
    /// Exact asset-scope frame length.
    pub asset_length: usize,
}
/// Reconcile a native-provisioned runtime and return one fresh account challenge (kind15).
/// # Safety
/// Request/input memory must be readable for its declared lengths and output writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn connect_norito_kagemusha_wallet_open_begin_v1(
    runtime: u64,
    request: *const WalletOpenRequest,
    result: *mut WalletResult,
) -> i32 {
    // SAFETY: caller supplies writable output; individual original bounds precede slices.
    unsafe {
        output(result, || {
            let request = request.as_ref().ok_or(Failure::code(INVALID))?;
            open::begin(
                runtime,
                [
                    input(
                        request.credential,
                        request.credential_length,
                        open::BOUNDS[0],
                    )?,
                    input(
                        request.certificates,
                        request.certificates_length,
                        open::BOUNDS[1],
                    )?,
                    input(request.account, request.account_length, open::BOUNDS[2])?,
                    input(request.asset, request.asset_length, open::BOUNDS[3])?,
                ],
            )
        })
    }
}
/// Consume one account challenge and return the admitted wallet handle (kind16).
/// Wrong signatures consume the challenge and retain unadmitted custody for a fresh begin.
/// # Safety
/// Signature must be readable for length and output writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn connect_norito_kagemusha_wallet_open_finish_v1(
    runtime: u64,
    signature: *const u8,
    length: usize,
    result: *mut WalletResult,
) -> i32 {
    // SAFETY: caller supplies writable result and readable signature. An invalid byte length
    // reaches the native finish as an empty signature so its one-use challenge is consumed.
    unsafe {
        output(result, || {
            let signature = if length != 64 || signature.is_null() {
                &[]
            } else {
                input(signature, length, 64)?
            };
            open::finish(runtime, signature)
        })
    }
}
/// Abandon an account challenge without discarding native custody or accepting authority.
#[unsafe(no_mangle)]
pub extern "C" fn connect_norito_kagemusha_wallet_open_cancel_v1(runtime: u64) -> i32 {
    run(|| open::cancel(runtime))
        .err()
        .map_or(0, |error| error.status)
}
/// Close an owner, cooperatively join a running fold, and release exclusive custody.
#[unsafe(no_mangle)]
pub extern "C" fn connect_norito_kagemusha_wallet_close_v1(handle: u64) -> i32 {
    run(|| close(handle)).err().map_or(0, |error| error.status)
}
/// Update foreground/charging eligibility; inactive cancels a running sub-proof.
#[unsafe(no_mangle)]
pub extern "C" fn connect_norito_kagemusha_wallet_activity_v1(
    handle: u64,
    foreground: u8,
    charging: u8,
) -> i32 {
    run(|| {
        if foreground > 1 || charging > 1 {
            return Err(Failure::code(INVALID));
        }
        activity(handle, foreground != 0, charging != 0)
    })
    .err()
    .map_or(0, |error| error.status)
}
/// Typed lifecycle input. Unused original slots and amount limbs must be zero/empty.
/// Selectors: Load0, Send1, Receive2, Credential3, SchemePolicy4, Blacklist5,
/// TimeAnchor6, QuotaShare7, Unload8, Retire9, ReceiveFromOffer10. These never select proof keys.
/// ReceiveFromOffer carries exact Payment and signed Offer originals; Native extracts payer custody.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct WalletOperationRequest {
    /// Exactly32 readable bytes; nonzero local retry identity, not a protocol operation ID.
    pub request_id: *const u8,
    /// One fixed lifecycle selector documented above.
    pub selector: u32,
    /// Requested Unload amount only; zero for all other operations.
    pub amount: WalletU128,
    /// First original: receipt/Request/Payment/update/charge quote, depending on selector.
    pub first: *const u8,
    /// Exact first-original length.
    pub first_length: usize,
    /// Second original: finality/payer credential/certificate set, depending on selector.
    pub second: *const u8,
    /// Exact second-original length.
    pub second_length: usize,
    /// Third original: Receive certificate set only.
    pub third: *const u8,
    /// Exact third-original length.
    pub third_length: usize,
}
/// Execute typed intent under the exclusive native preparation/proof owner.
/// # Safety
/// Request and its pointers are initialized for their lengths; out is writable with no old result.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn connect_norito_kagemusha_wallet_execute_v1(
    handle: u64,
    request: *const WalletOperationRequest,
    out: *mut WalletResult,
) -> i32 {
    unsafe {
        output(out, || {
            if request.is_null() {
                return Err(Failure::code(INVALID));
            }
            let request = &*request;
            let bounds = requests::bounds(request.selector)?;
            let value = requests::request(
                input(request.request_id, 32, 32)?,
                request.selector,
                u128::from(request.amount.low) | (u128::from(request.amount.high) << 64),
                [
                    input(request.first, request.first_length, bounds[0])?,
                    input(request.second, request.second_length, bounds[1])?,
                    input(request.third, request.third_length, bounds[2])?,
                ],
            )?;
            execute(handle, value)
        })
    }
}
/// Typed setup input for the same exclusive Native wallet owner.
/// Selectors: Bootstrap0, Offer1, Request2, Credited3, BeginTime4, FinishTime5, CancelTime6.
/// Envelope wrap7..10/unwrap11..14 follows Offer, Request, Payment, Credited order.
/// Unused fields must be zero/empty. No field supplies a clock, nonce or signature body.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct WalletSetupRequest {
    /// Exactly 32 readable bytes; nonzero only for selectors requiring a retained identity.
    pub setup_id: *const u8,
    /// One fixed setup selector documented above.
    pub selector: u32,
    /// Positive Offer/ledger Load amount, or historical sequence for collection47 (zero allowed).
    /// Zero for every other selector.
    pub amount: WalletU128,
    /// Native time/destructive-review token or ledger instruction kind, selected by operation.
    pub token: u64,
    /// Complete canonical original according to the selected operation.
    pub first: *const u8,
    /// Exact first-original length.
    pub first_length: usize,
    /// Second canonical original according to the selected operation, empty when unused.
    pub second: *const u8,
    /// Exact second-original length.
    pub second_length: usize,
    /// Optional Request fee signer certificate or Certificates envelope; empty when unused.
    pub third: *const u8,
    /// Exact third-original length.
    pub third_length: usize,
}
/// Execute source-bound setup through the existing exclusive Native wallet owner.
/// Bootstrap/Credited return existing completion statuses. Offer/Request return original12;
/// BeginTime returns challenge13 with its opaque token in sequence; FinishTime returns retained14.
/// CancelTime returns idle6; envelope conversion returns original12 without monetary authority.
/// # Safety
/// Request and its input pointers are initialized for their stated lengths; out is writable
/// with no previously allocated result. setup_id always points to exactly 32 readable bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn connect_norito_kagemusha_wallet_setup_v1(
    handle: u64,
    request: *const WalletSetupRequest,
    out: *mut WalletResult,
) -> i32 {
    unsafe { setup_output_with(handle, request, out, allocate_bytes) }
}
// Shared exact C intake/delivery path; the allocator seam is private and never configurable.
pub(super) unsafe fn setup_output_with(
    handle: u64,
    request: *const WalletSetupRequest,
    out: *mut WalletResult,
    allocate: impl FnOnce(&mut WalletResult, &[u8]) -> std::result::Result<(), ()>,
) -> i32 {
    let mut pending = None;
    let status = unsafe {
        output_with(
            out,
            || {
                if request.is_null() {
                    return Err(Failure::code(INVALID));
                }
                let request = &*request;
                let bounds = setup::bounds(request.selector)?;
                // Check all original lengths before creating any input slice.
                if [
                    request.first_length,
                    request.second_length,
                    request.third_length,
                ]
                .into_iter()
                .zip(bounds)
                .any(|(length, bound)| length > bound)
                {
                    return Err(Failure::code(INVALID));
                }
                let value = setup::request(
                    input(request.setup_id, 32, 32)?,
                    request.selector,
                    u128::from(request.amount.low) | (u128::from(request.amount.high) << 64),
                    request.token,
                    [
                        input(request.first, request.first_length, bounds[0])?,
                        input(request.second, request.second_length, bounds[1])?,
                        input(request.third, request.third_length, bounds[2])?,
                    ],
                )?;
                let result = setup(handle, value);
                pending = Some(terminal::ReviewDelivery::new(
                    handle,
                    request.selector,
                    &result,
                ));
                result
            },
            allocate,
        )
    };
    if status >= 0
        && let Some(pending) = &mut pending
    {
        pending.delivered();
    }
    status
}
#[cfg(test)]
mod setup_boundary_tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct SetupWallet {
        calls: Arc<AtomicUsize>,
        panic: bool,
    }
    impl Wallet for SetupWallet {
        fn setup(&mut self, input: setup::Setup) -> Result<Response> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            assert!(!self.panic, "contained setup boundary panic");
            let (kind, sequence, bytes) = match input {
                setup::Setup::BackgroundStatus => panic!("status bypasses wallet lock"),
                setup::Setup::Bootstrap => (1, 0, vec![0, 255, 1]),
                setup::Setup::CollectRetained { sequence } => (51, sequence, vec![]),
                setup::Setup::UnloadClaim {
                    request_id,
                    beneficiary,
                } => {
                    assert_eq!(request_id, [7; 32]);
                    assert_eq!(beneficiary, Some(vec![0, 255, 7]));
                    (
                        48,
                        0,
                        vec![0xf2; KAGEMUSHA_WALLET_UNLOAD_CLAIM_MAX_BYTES_V1],
                    )
                }
                setup::Setup::FeeClaim { .. } => (31, 0, vec![1; state::FEE_CLAIM_MAX_BYTES_V1]),
                setup::Setup::FeeOriginal { original, .. } => (12, 0, original),
                setup::Setup::FeeClaimTransport { .. } => {
                    (36, 0, vec![0xf1; KAGEMUSHA_WALLET_FEE_CLAIM_MAX_BYTES_V1])
                }
                setup::Setup::LedgerFinality(_) | setup::Setup::LedgerStatus => {
                    (33, u128::from(u64::MAX), vec![7; 32])
                }
                setup::Setup::FeePayout { .. } => (35, 0, vec![]),
                setup::Setup::CloseLoads { .. } => (30, 0, vec![0xc1; 16_384]),
                setup::Setup::Activation => (17, 0, vec![0xa1; 16_384]),
                setup::Setup::Offer { id, amount } => {
                    assert_eq!(id, [7; 32]);
                    assert_eq!(amount, u128::MAX);
                    (12, 0, vec![0, 255, 2])
                }
                setup::Setup::Request { id, offer, fee } => {
                    assert_eq!(id, [7; 32]);
                    assert_eq!(offer, [0, 255, 7]);
                    assert!(fee.is_none());
                    (12, 0, vec![0, 255, 3])
                }
                setup::Setup::Credited(bytes) => {
                    assert_eq!(bytes, [0, 255, 7]);
                    (4, 0, vec![])
                }
                setup::Setup::CreditedOriginal { status, original } => {
                    assert_eq!(original, [0, 255, 7]);
                    (12, 0, vec![u8::from(status), 0, 255])
                }
                setup::Setup::BeginTime => (13, 19, vec![0, 255, 4]),
                setup::Setup::BoundCredited { .. } => panic!("unexpected bound Credited fixture"),
                setup::Setup::CreditProjection { id, anchor, newer } => {
                    assert_eq!(id, [7; 32]);
                    assert!(anchor.is_empty());
                    assert!(newer.is_empty());
                    (47, 0, vec![0xc3; 92])
                }
                setup::Setup::CancelTime { token } => {
                    assert_eq!(token, 19);
                    (6, 0, vec![])
                }
                setup::Setup::Transport {
                    kind,
                    wrap,
                    original,
                } => {
                    assert_eq!(original, [0, 255, 7]);
                    (12, 0, vec![kind, u8::from(wrap), 0, 255])
                }
                setup::Setup::LedgerLoad { id, amount } => {
                    assert_eq!(id, [7; 32]);
                    assert_eq!(amount, u128::MAX);
                    (40, 0, vec![0xa2])
                }
                setup::Setup::LedgerInstruction { kind, original } => {
                    assert_eq!(kind, 2);
                    assert_eq!(original, [0, 255, 7]);
                    (40, 0, vec![0xc2])
                }
                setup::Setup::ConfirmUnload {
                    transaction,
                    original,
                } => {
                    assert_eq!(transaction, [7; 32]);
                    assert_eq!(original, [0, 255, 7]);
                    (42, u128::from(u64::MAX), vec![8; 32])
                }
                setup::Setup::UnloadProofProgress {
                    transaction,
                    original,
                } => {
                    assert_eq!(transaction, [7; 32]);
                    assert_eq!(original, [0, 255, 7]);
                    (34, 0, vec![])
                }
                setup::Setup::UnloadProofStep {
                    transaction,
                    original,
                    finality,
                } => {
                    assert_eq!(transaction, [7; 32]);
                    assert_eq!(original, [0, 255, 7]);
                    assert_eq!(finality, [0, 255, 7]);
                    (33, u128::from(u64::MAX), vec![9; 32])
                }
                setup::Setup::ConfirmActivation(signed) => {
                    assert_eq!(signed, [0, 255, 7]);
                    (44, u128::from(u64::MAX), vec![10; 32])
                }
                setup::Setup::RetainActivationAttempt(signed) => {
                    assert!(!signed.is_empty());
                    (46, 0, Vec::new())
                }
                setup::Setup::ActivationProofProgress(signed) => {
                    assert_eq!(signed, [0, 255, 7]);
                    (46, 0, vec![])
                }
                setup::Setup::ActivationProofStep { signed, original } => {
                    assert_eq!(signed, [0, 255, 7]);
                    assert_eq!(original, [0, 255, 7]);
                    (45, u128::from(u64::MAX), vec![11; 32])
                }
                setup::Setup::ReviewCustodyDeletion
                | setup::Setup::ConfirmCustodyDeletion { .. }
                | setup::Setup::ResumeCustodyDeletion
                | setup::Setup::DiscardCustodyDeletion { .. } => {
                    panic!("separate terminal fixture")
                }
                setup::Setup::FinishTime { .. } => panic!("unexpected unsigned time fixture"),
                setup::Setup::EpochStatus => {
                    (57, 0, [1u64.to_le_bytes(), 3u64.to_le_bytes()].concat())
                }
                setup::Setup::EpochBoundary { epoch, original } => {
                    assert!(!original.is_empty());
                    (
                        57,
                        u128::from(epoch + 1),
                        [4u64.to_le_bytes(), 6u64.to_le_bytes()].concat(),
                    )
                }
                setup::Setup::RequestFeeSelection => (12, 0, vec![0xf3; 64]),
                setup::Setup::ValidateRequestFeePolicy { .. } => {
                    panic!("unexpected fee validation fixture")
                }
                setup::Setup::RequestWithFeePolicy { .. } => {
                    panic!("unexpected fee PolicyData Request fixture")
                }
            };
            Ok(Response {
                kind,
                sequence,
                bytes,
                ..Response::default()
            })
        }
        fn snapshot(&mut self) -> Result<state::Snapshot> {
            panic!("not setup")
        }
        fn execute(&mut self, _: state::OperationRequestV1) -> Result<Response> {
            panic!("not setup")
        }
        fn request_status(&mut self, _: &[u8; 32]) -> Result<Response> {
            panic!("not setup")
        }
        fn retry(&mut self, _: &[u8; 32]) -> Result<Response> {
            panic!("not setup")
        }
        fn resume(&mut self) -> Result<Response> {
            panic!("not setup")
        }
        fn fold(&mut self) -> Result<ControlFlow<Response, FoldProof>> {
            panic!("not setup")
        }
        fn credit(&mut self, _: &[u8; 32], _: &[u8; 32]) -> Result<Response> {
            panic!("not setup")
        }
    }
    fn installed(panic: bool) -> (u64, Arc<AtomicUsize>) {
        let calls = Arc::new(AtomicUsize::new(0));
        let handle = install(
            Box::new(SetupWallet {
                calls: calls.clone(),
                panic,
            }),
            state::Scheduler::new(),
        )
        .unwrap();
        (handle, calls)
    }
    fn request(id: &[u8; 32], selector: u32) -> WalletSetupRequest {
        WalletSetupRequest {
            setup_id: id.as_ptr(),
            selector,
            amount: WalletU128::default(),
            token: 0,
            first: std::ptr::null(),
            first_length: 0,
            second: std::ptr::null(),
            second_length: 0,
            third: std::ptr::null(),
            third_length: 0,
        }
    }
    fn assert_failure(handle: u64, request: &WalletSetupRequest, expected: i32) {
        let mut out = WalletResult {
            status: 14,
            reason: 99,
            platform_code: 99,
            sequence_low: 99,
            sequence_high: 99,
            detail: 99,
            bytes: std::ptr::null_mut(),
            length: 99,
        };
        assert_eq!(
            unsafe { connect_norito_kagemusha_wallet_setup_v1(handle, request, &mut out) },
            expected
        );
        assert_eq!(
            (out.status, out.reason, out.platform_code),
            (expected, -1, 0)
        );
        assert_eq!(
            (out.sequence_low, out.sequence_high, out.detail, out.length),
            (0, 0, 0, 0)
        );
        assert!(out.bytes.is_null());
    }
    #[test]
    fn collection_c_preserves_full_sequence_and_refuses_foreign_authority() {
        let (handle, calls) = installed(false);
        let zero = [0; 32];
        for sequence in [0, 1, u128::MAX] {
            let mut input = request(&zero, 47);
            input.amount = WalletU128 {
                low: sequence as u64,
                high: (sequence >> 64) as u64,
            };
            let mut out = WalletResult::default();
            assert_eq!(
                unsafe { connect_norito_kagemusha_wallet_setup_v1(handle, &input, &mut out) },
                0
            );
            assert_eq!(
                (
                    out.status,
                    out.sequence_low,
                    out.sequence_high,
                    out.detail,
                    out.length
                ),
                (51, sequence as u64, (sequence >> 64) as u64, 0, 0)
            );
            assert!(out.bytes.is_null());
        }
        let mut input = request(&zero, 47);
        input.token = 1;
        assert_failure(handle, &input, INVALID);
        let foreign = [7; 32];
        assert_failure(handle, &request(&foreign, 47), INVALID);
        for index in 0..3 {
            let mut input = request(&zero, 47);
            match index {
                0 => {
                    input.first = foreign.as_ptr();
                    input.first_length = 1;
                }
                1 => {
                    input.second = foreign.as_ptr();
                    input.second_length = 1;
                }
                _ => {
                    input.third = foreign.as_ptr();
                    input.third_length = 1;
                }
            }
            assert_failure(handle, &input, INVALID);
        }
        assert_failure(handle, &request(&zero, 54), INVALID);
        assert_eq!(calls.load(Ordering::SeqCst), 3);
        assert_eq!(connect_norito_kagemusha_wallet_close_v1(handle), 0);
    }

    #[test]
    fn setup_c_preserves_typed_owner_input_and_distinct_exact_original_results() {
        let (handle, calls) = installed(false);
        let zero = [0; 32];
        let id = [7; 32];
        let original = [0, 255, 7];
        for (selector, expected, sequence, bytes) in [
            (0, 1, 0, vec![0, 255, 1]),
            (1, 12, 0, vec![0, 255, 2]),
            (2, 12, 0, vec![0, 255, 3]),
            (3, 4, 0, vec![]),
            (4, 13, 19, vec![0, 255, 4]),
            (15, 17, 0, vec![0xa1; 16_384]),
            (16, 12, 0, vec![0, 0, 255]),
            (17, 12, 0, vec![1, 0, 255]),
            (19, 30, 0, vec![0xc1; 16_384]),
            (20, 31, 0, vec![1; state::FEE_CLAIM_MAX_BYTES_V1]),
            (21, 12, 0, vec![0, 255, 7]),
            (22, 12, 0, vec![0, 255, 7]),
            (23, 33, u64::MAX, vec![7; 32]),
            (24, 33, u64::MAX, vec![7; 32]),
            (25, 35, 0, vec![]),
            (
                26,
                36,
                0,
                vec![0xf1; KAGEMUSHA_WALLET_FEE_CLAIM_MAX_BYTES_V1],
            ),
            (27, 40, 0, vec![0xa2]),
            (29, 40, 0, vec![0xc2]),
            (30, 42, u64::MAX, vec![8; 32]),
            (33, 34, 0, vec![]),
            (34, 33, u64::MAX, vec![9; 32]),
            (35, 44, u64::MAX, vec![10; 32]),
            (36, 45, u64::MAX, vec![11; 32]),
            (37, 46, 0, vec![]),
            (46, 46, 0, vec![]),
            (38, 12, 0, vec![0xf3; 64]),
            (43, 47, 0, vec![0xc3; 92]),
            (
                45,
                48,
                0,
                vec![0xf2; KAGEMUSHA_WALLET_UNLOAD_CLAIM_MAX_BYTES_V1],
            ),
        ] {
            let mut request = request(
                if matches!(selector, 1 | 2 | 19 | 20 | 25 | 27 | 30 | 33 | 34 | 43 | 45) {
                    &id
                } else {
                    &zero
                },
                selector,
            );
            if matches!(selector, 1 | 27) {
                request.amount = WalletU128 {
                    low: u64::MAX,
                    high: u64::MAX,
                };
            }
            if matches!(selector, 2 | 3 | 16 | 17 | 21..=23 | 25 | 26 | 29 | 30 | 33..=37 | 45 | 46)
            {
                request.first = original.as_ptr();
                request.first_length = original.len();
            }
            if matches!(selector, 25 | 26 | 34 | 36) {
                request.second = original.as_ptr();
                request.second_length = original.len();
            }
            if selector == 29 {
                request.token = 2;
            }
            let mut out = WalletResult::default();
            assert_eq!(
                unsafe { connect_norito_kagemusha_wallet_setup_v1(handle, &request, &mut out) },
                0
            );
            assert_eq!(
                (out.status, out.sequence_low, out.sequence_high),
                (expected, sequence, 0)
            );
            assert_eq!(out.length, bytes.len());
            if bytes.is_empty() {
                assert!(out.bytes.is_null());
            } else {
                assert_eq!(
                    unsafe { std::slice::from_raw_parts(out.bytes, out.length) },
                    bytes
                );
                crate::connect_norito_free(out.bytes);
            }
        }
        assert_eq!(calls.load(Ordering::SeqCst), 28);
        let mut status = WalletResult::default();
        assert_eq!(
            unsafe {
                connect_norito_kagemusha_wallet_setup_v1(handle, &request(&zero, 18), &mut status)
            },
            0
        );
        assert_eq!((status.status, status.detail, status.length), (29, 0, 0));
        assert_eq!(
            calls.load(Ordering::SeqCst),
            28,
            "worker status does not acquire the wallet"
        );
        assert_failure(handle, &request(&zero, 19), INVALID);
        for selector in [28, 31, 32] {
            assert_failure(handle, &request(&zero, selector), INVALID);
        }
        close(handle).unwrap();
        assert_failure(handle, &request(&zero, 0), CLOSED);
        assert_eq!(calls.load(Ordering::SeqCst), 28);
    }
    #[test]
    fn setup_c_routes_cancellation_and_every_envelope_form_to_the_same_owner() {
        let (handle, calls) = installed(false);
        let zero = [0; 32];
        let original = [0, 255, 7];
        for selector in 6..=14 {
            let mut value = request(&zero, selector);
            if selector == 6 {
                value.token = 19;
            } else {
                value.first = original.as_ptr();
                value.first_length = original.len();
            }
            let mut out = WalletResult::default();
            assert_eq!(
                unsafe { connect_norito_kagemusha_wallet_setup_v1(handle, &value, &mut out) },
                0
            );
            assert_eq!((out.sequence_low, out.sequence_high, out.detail), (0, 0, 0));
            if selector == 6 {
                assert_eq!(out.status, 6);
                assert_eq!(out.length, 0);
                assert!(out.bytes.is_null());
            } else {
                assert_eq!(out.status, 12);
                assert_eq!(out.length, 4);
                assert_eq!(
                    unsafe { std::slice::from_raw_parts(out.bytes, out.length) },
                    [
                        u8::try_from((selector - 7) % 4 + 1).unwrap(),
                        u8::from(selector < 11),
                        0,
                        255
                    ]
                );
                crate::connect_norito_free(out.bytes);
            }
        }
        assert_eq!(calls.load(Ordering::SeqCst), 9);
        close(handle).unwrap();
    }
    #[test]
    fn setup_c_checks_all_bounds_and_unused_fields_before_owner_or_pointer_reads() {
        let (handle, calls) = installed(false);
        let zero = [0; 32];
        let id = [7; 32];
        let invalid_pointer = std::ptr::dangling::<u8>();
        let mut value = request(&id, 2);
        // Even first is unreadable: the oversized last original must reject first.
        value.first = invalid_pointer;
        value.first_length = 1;
        value.third = invalid_pointer;
        value.third_length = KAGEMUSHA_WALLET_CERTIFICATE_MAX_BYTES_V1 + 1;
        assert_failure(handle, &value, INVALID);
        value = request(&zero, 6);
        value.first = invalid_pointer;
        value.first_length = usize::MAX;
        assert_failure(handle, &value, INVALID);
        value = request(&zero, 4);
        value.token = 1;
        assert_failure(handle, &value, INVALID);
        value = request(&id, 0);
        assert_failure(handle, &value, INVALID);
        value = request(&zero, 0);
        value.amount.low = 1;
        assert_failure(handle, &value, INVALID);
        value = request(&id, 2);
        let original = [7];
        value.first = original.as_ptr();
        value.first_length = 1;
        value.second = original.as_ptr();
        value.second_length = 1;
        assert_failure(handle, &value, INVALID);
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        close(handle).unwrap();
    }
    #[test]
    fn setup_c_null_outputs_and_panics_never_fabricate_completion() {
        let (handle, calls) = installed(false);
        let zero = [0; 32];
        let value = request(&zero, 0);
        assert_eq!(
            unsafe {
                connect_norito_kagemusha_wallet_setup_v1(handle, &value, std::ptr::null_mut())
            },
            INVALID
        );
        let mut out = WalletResult::default();
        assert_eq!(
            unsafe { connect_norito_kagemusha_wallet_setup_v1(handle, std::ptr::null(), &mut out) },
            INVALID
        );
        assert_eq!(out.status, INVALID);
        assert!(out.bytes.is_null());
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        close(handle).unwrap();
        let (handle, calls) = installed(true);
        assert_failure(handle, &value, INTERNAL);
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        // The panic poisons this test-only owner; close still removes its handle.
        assert!(close(handle).is_err());
        assert_eq!(owner(handle).err().unwrap().status, CLOSED);
    }
    #[test]
    fn setup_c_layout_tracks_native_pointer_and_u128_alignment() {
        use std::mem::{align_of, offset_of, size_of};
        fn align(value: usize, alignment: usize) -> usize {
            value.div_ceil(alignment) * alignment
        }
        let pointer = size_of::<*const u8>();
        let selector = pointer;
        let amount = align(selector + size_of::<u32>(), align_of::<WalletU128>());
        let token = align(amount + size_of::<WalletU128>(), align_of::<u64>());
        let first = align(token + size_of::<u64>(), align_of::<*const u8>());
        assert_eq!(offset_of!(WalletSetupRequest, setup_id), 0);
        assert_eq!(offset_of!(WalletSetupRequest, selector), selector);
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
    }
}
/// Resolve exact request custody; preparing11 is not irreversible pending2 or completion1.
/// # Safety
/// Request identity is exactly32 readable bytes; out is writable with no old result.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn connect_norito_kagemusha_wallet_request_status_v1(
    handle: u64,
    request_id: *const u8,
    out: *mut WalletResult,
) -> i32 {
    unsafe { output(out, || request_status(handle, input(request_id, 32, 32)?)) }
}
/// Return the exact source-retained output, without signing or proving again.
/// # Safety
/// Operation is exactly32 readable bytes; out is writable with no unfreed previous result.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn connect_norito_kagemusha_wallet_retry_v1(
    handle: u64,
    operation: *const u8,
    out: *mut WalletResult,
) -> i32 {
    unsafe { output(out, || retry(handle, input(operation, 32, 32)?)) }
}
/// Reconcile/resume the selected operation, preserving any committed debit and output.
/// # Safety
/// Out is writable with no unfreed previous result.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn connect_norito_kagemusha_wallet_resume_v1(
    handle: u64,
    out: *mut WalletResult,
) -> i32 {
    unsafe { output(out, || resume(handle)) }
}
/// Compute and durably retain at most one native folding checkpoint or final Ω.
/// # Safety
/// Out is writable with no unfreed previous result.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn connect_norito_kagemusha_wallet_fold_v1(
    handle: u64,
    out: *mut WalletResult,
) -> i32 {
    unsafe { output(out, || fold(handle)) }
}
/// Construct canonical CreditStatus from the authenticated persistent first-credit index.
/// # Safety
/// Both identities are exactly32 readable bytes; out is writable with no unfreed old result.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn connect_norito_kagemusha_wallet_credit_status_v1(
    handle: u64,
    credit_id: *const u8,
    payment_digest: *const u8,
    out: *mut WalletResult,
) -> i32 {
    unsafe {
        output(out, || {
            credit(
                handle,
                input(credit_id, 32, 32)?,
                input(payment_digest, 32, 32)?,
            )
        })
    }
}

/// Lossless scalar representation shared by the typed snapshot C ABI.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct WalletU128 {
    /// Least significant 64 bits.
    pub low: u64,
    /// Most significant 64 bits.
    pub high: u64,
}
impl From<u128> for WalletU128 {
    fn from(value: u128) -> Self {
        Self {
            low: value as u64,
            high: (value >> 64) as u64,
        }
    }
}

/// Fixed typed Native projection; no caller identities, financial codec, or allocated bytes.
/// Zeroed optional storage is meaningful only under its explicit flags after status success.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct WalletSnapshot {
    /// Zero success; otherwise an exact negative failure and no snapshot values.
    pub status: i32,
    /// Platform failure reason, or -1.
    pub reason: i32,
    /// Platform failure code, or zero.
    pub platform_code: i32,
    /// Actual lifecycle tag: Active1 or Retiring2; never operation readiness.
    pub lifecycle: u32,
    /// Bit0: verified_fold exists; bit1: current head is folded. Other bits zero.
    pub flags: u32,
    /// Current Native scheme identity.
    pub scheme: [u8; 32],
    /// Current Native wallet incarnation identity.
    pub wallet: [u8; 32],
    /// Exact current source-selected head.
    pub head: [u8; 32],
    /// Exact current credential digest.
    pub credential: [u8; 32],
    /// Exact source-indexed verified folded head, iff bit0.
    pub folded_head: [u8; 32],
    /// Credential of that folded head, iff bit0; renewal may differ from current.
    pub folded_credential: [u8; 32],
    /// Current retained sequence.
    pub sequence: WalletU128,
    /// Current retained gross balance.
    pub balance: WalletU128,
    /// Burns in current retained core.
    pub core_burned_total: WalletU128,
    /// Last verified burns, or actual retained core before any fold.
    pub known_burned_total: WalletU128,
    /// Gross minus known burns, computed by Native only; unfinished folds remain subject to P4.
    pub owned_balance: WalletU128,
    /// Balance with Ω of current head, iff bit1; grants no operation readiness.
    pub folded_balance: WalletU128,
    /// Released heads still requiring local proof.
    pub fold_backlog: WalletU128,
    /// Exact folded head sequence, iff bit0.
    pub folded_sequence: WalletU128,
    /// Exact verified cumulative burns, iff bit0.
    pub folded_burned_total: WalletU128,
}
impl Default for WalletSnapshot {
    fn default() -> Self {
        Self {
            status: INTERNAL,
            reason: -1,
            platform_code: 0,
            lifecycle: 0,
            flags: 0,
            scheme: [0; 32],
            wallet: [0; 32],
            head: [0; 32],
            credential: [0; 32],
            folded_head: [0; 32],
            folded_credential: [0; 32],
            sequence: WalletU128::default(),
            balance: WalletU128::default(),
            core_burned_total: WalletU128::default(),
            known_burned_total: WalletU128::default(),
            owned_balance: WalletU128::default(),
            folded_balance: WalletU128::default(),
            fold_backlog: WalletU128::default(),
            folded_sequence: WalletU128::default(),
            folded_burned_total: WalletU128::default(),
        }
    }
}
impl From<state::Snapshot> for WalletSnapshot {
    fn from(value: state::Snapshot) -> Self {
        let mut out = Self {
            status: 0,
            lifecycle: u32::from(value.lifecycle.tag()),
            scheme: value.scheme_id,
            wallet: value.wallet_id,
            head: value.head,
            credential: value.credential_digest,
            sequence: value.sequence.into(),
            balance: value.balance.into(),
            core_burned_total: value.core_burned_total.into(),
            known_burned_total: value.known_burned_total.into(),
            owned_balance: value.owned_balance.into(),
            fold_backlog: value.fold_backlog.into(),
            ..Self::default()
        };
        if let Some(fold) = value.verified_fold {
            out.flags |= 1;
            out.folded_head = fold.head;
            out.folded_credential = fold.credential_digest;
            out.folded_sequence = fold.sequence.into();
            out.folded_burned_total = fold.burned_total.into();
        }
        if let Some(balance) = value.folded_balance {
            out.flags |= 2;
            out.folded_balance = balance.into();
        }
        out
    }
}
impl From<Failure> for WalletSnapshot {
    fn from(error: Failure) -> Self {
        Self {
            status: error.status,
            reason: error.reason,
            platform_code: error.platform_code,
            ..Self::default()
        }
    }
}

/// Read a source-selected current ownership/fold snapshot. Run off the UI thread.
/// Pending, uncertain, missing witness and proof failures return no monetary projection.
/// # Safety
/// Out must be writable aligned complete WalletSnapshot storage. It owns no allocated memory.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn connect_norito_kagemusha_wallet_snapshot_v1(
    handle: u64,
    out: *mut WalletSnapshot,
) -> i32 {
    if out.is_null() {
        return INVALID;
    }
    // SAFETY: caller supplies writable aligned snapshot memory.
    unsafe { out.write(WalletSnapshot::default()) };
    let value = match run(|| snapshot(handle)) {
        Ok(value) => WalletSnapshot::from(value),
        Err(error) => WalletSnapshot::from(error),
    };
    let status = value.status;
    // SAFETY: admitted complete output storage; all fields are initialized, no heap ownership.
    unsafe { out.write(value) };
    status
}

/// One original certificate in an enrollment request; no decoded platform facts.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct WalletEnrollmentItem {
    /// Exactly `length` readable original bytes.
    pub bytes: *const u8,
    /// Bounded by 16,384.
    pub length: usize,
}
/// Typed native enrollment actions. Unused fields must be empty.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct WalletEnrollmentRequest {
    /// 0 begin(E1/account/asset),1 authorize(signature),2 status,3 Android(`KeyMint` chain only),
    /// 4 Apple(keyid/attestation/assertion),5 retain E5(signature),6 E6(result),7 load runtime,8 original open from retained E5/E6.
    pub selector: u32,
    /// First exact original according to selector.
    pub first: *const u8,
    /// Exact first length.
    pub first_length: usize,
    /// Second exact original according to selector.
    pub second: *const u8,
    /// Exact second length.
    pub second_length: usize,
    /// Third exact original according to selector.
    pub third: *const u8,
    /// Exact third length.
    pub third_length: usize,
    /// Android certificate items only, leaf first; null when count is zero.
    pub certificates: *const WalletEnrollmentItem,
    /// 2..8 for Android selector3; zero otherwise.
    pub certificate_count: usize,
}
/// Drive original enrollment under a native-provisioned exclusive owner.
/// Results18 local challenge32,19 target161(slot32,key65,challenge32,binding32),20 pending,
/// 21 abandoned,22 Bootstrap selected,23 E5 challenge32,24 exact E5,25 exact E6,26 runtime ready.
/// Selector20 permanently abandons and returns 59 with the exact canonical Abandon ledger
/// instruction (<=65536 bytes, same handle in sequence), or58 empty for the local form.
/// Abandon10 returns 58 for the local no-marker form (nothing to submit) or 28 with the exact
/// retained signed Abandonment frame for the marker form.
/// Selector21 consumes one issuer-signed E1 expiry proof and returns 58 only after Native has
/// authenticated the exact Accepted/no-Slot attempt and retained the immutable Expired marker.
/// The same opaque runtime handle is returned in sequence. E6 does not imply ledger activation.
/// # Safety
/// Request and each bounded item/input must be readable; output writable and unallocated.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn connect_norito_kagemusha_wallet_enrollment_v1(
    runtime: u64,
    request: *const WalletEnrollmentRequest,
    out: *mut WalletResult,
) -> i32 {
    unsafe {
        output(out, || {
            let request = request.as_ref().ok_or(Failure::code(INVALID))?;
            let bounds = enrollment::bounds(request.selector)?;
            if request.certificate_count > 8
                || (request.certificate_count != 0 && request.certificates.is_null())
                || (request.selector != 3 && request.certificate_count != 0)
                || [
                    request.first_length,
                    request.second_length,
                    request.third_length,
                ]
                .into_iter()
                .zip(bounds)
                .any(|(length, bound)| length > bound)
            {
                return Err(Failure::code(INVALID));
            }
            let certificates = if request.certificate_count == 0 {
                &[][..]
            } else {
                std::slice::from_raw_parts(request.certificates, request.certificate_count)
            };
            if certificates
                .iter()
                .any(|item| item.length == 0 || item.length > 16_384)
            {
                return Err(Failure::code(INVALID));
            }
            let chain = certificates
                .iter()
                .map(|item| input(item.bytes, item.length, 16_384))
                .collect::<Result<Vec<_>>>()?;
            let action = enrollment::request(
                request.selector,
                [
                    input(request.first, request.first_length, bounds[0])?,
                    input(request.second, request.second_length, bounds[1])?,
                    input(request.third, request.third_length, bounds[2])?,
                ],
                &chain,
            )?;
            enrollment::call(runtime, action)
        })
    }
}
/// Holder class of one relayed closed E1 refusal code (design §2.4): 1 Phone, 2 App,
/// 3 Attempt, 4 Account. `android` is 1 for Android evidence and 0 for Apple evidence. Zero,
/// unknown and platform-inapplicable codes, and any other `android` value, return `INVALID`.
/// Pure table lookup: no handle, state, allocation, I/O or admission verdict.
#[unsafe(no_mangle)]
pub extern "C" fn connect_norito_kagemusha_wallet_enrollment_refusal_v1(
    code: u16,
    android: u8,
) -> i32 {
    let android = match android {
        0 => false,
        1 => true,
        _ => return INVALID,
    };
    enrollment::refusal_class(code, android).unwrap_or_else(|failure| failure.status)
}
