//! Native boundary tests use scripted custody only; actual provider fault tests live in CoreZk.
use super::*;
use std::sync::atomic::{AtomicUsize, Ordering};

fn view() -> state::CustodyDeletionReviewV1 {
    state::CustodyDeletionReviewV1 {
        pending: true,
        lifecycle: KagemushaWalletLifecycleV1::Retiring,
        operation_kind: KagemushaWalletOperationKindV1::Send,
        pending_outgoing: true,
        fee_claims: false,
        load_redeem: true,
        slot: [1; 32],
        marker_file_digest: [2; 32],
        scheme_id: [3; 32],
        asset_digest: [4; 32],
        wallet_id: [5; 32],
        head: [6; 32],
        sequence: u128::MAX,
        gross_balance: u128::MAX,
        core_burned_total: 7,
    }
}
#[test]
fn deletion_projection_is_exact_retained_data_with_closed_fixed_shape() {
    let bytes = projection(&view()).unwrap();
    assert_eq!(bytes.len(), REVIEW_BYTES);
    assert_eq!(&bytes[..8], MAGIC);
    assert_eq!(&bytes[8..14], &[1, 2, 3, 1, 0, 1]);
    for (i, value) in (1_u8..=6).enumerate() {
        assert_eq!(&bytes[14 + i * 32..46 + i * 32], &[value; 32]);
    }
    assert_eq!(&bytes[206..222], &u128::MAX.to_le_bytes());
    assert_eq!(&bytes[222..238], &u128::MAX.to_le_bytes());
    assert_eq!(&bytes[238..], &7_u128.to_le_bytes());
    let mut invalid = view();
    invalid.head = [0; 32];
    assert!(projection(&invalid).is_err());
    let mut invalid = view();
    invalid.gross_balance = 6;
    assert!(projection(&invalid).is_err());
    let result = progress(state::CustodyDeletionProgressV1::NotDeleted);
    assert_eq!(
        (
            result.kind,
            result.sequence,
            result.detail,
            result.bytes.len()
        ),
        (56, 0, 0, 0)
    );
}
#[test]
fn deletion_intake_accepts_only_zero_unused_fields_and_actual_token_slot() {
    for selector in 48..=51 {
        let token = if [49, 51].contains(&selector) { 7 } else { 0 };
        assert_eq!(setup::bounds(selector).unwrap(), [0; 3]);
        assert!(setup::request(&[0; 32], selector, 0, token, [&[]; 3]).is_ok());
        assert!(setup::request(&[1; 32], selector, 0, token, [&[]; 3]).is_err());
        assert!(setup::request(&[0; 32], selector, 1, token, [&[]; 3]).is_err());
        assert!(setup::request(&[0; 32], selector, 0, u64::from(token == 0), [&[]; 3]).is_err());
        for field in 0..3 {
            let mut originals: [&[u8]; 3] = [&[]; 3];
            originals[field] = &[1];
            assert!(setup::request(&[0; 32], selector, 0, token, originals).is_err());
        }
    }
    assert!(setup::bounds(54).is_err());
}
struct Script {
    base: super::super::tests::TestWallet,
    phase: Arc<AtomicUsize>,
    tokens: review::Tokens<()>,
}
impl Wallet for Script {
    fn require_custody_operations(&self) -> Result<()> {
        if self.phase.load(Ordering::SeqCst) == 0 {
            Ok(())
        } else {
            Err(Failure::code(TERMINAL))
        }
    }
    fn setup(&mut self, input: setup::Setup) -> Result<Response> {
        match input {
            setup::Setup::ReviewCustodyDeletion => {
                self.require_custody_operations()?;
                Ok(Response {
                    kind: 53,
                    sequence: self.tokens.put(())?.into(),
                    bytes: projection(&view())?,
                    ..Response::default()
                })
            }
            setup::Setup::ConfirmCustodyDeletion { token } => {
                self.tokens.take(token)?;
                self.phase.store(1, Ordering::SeqCst);
                Err(Failure::code(UNCERTAIN))
            }
            setup::Setup::ResumeCustodyDeletion if self.phase.load(Ordering::SeqCst) != 0 => {
                self.phase.store(2, Ordering::SeqCst);
                Ok(progress(state::CustodyDeletionProgressV1::Deleted {
                    marker_file_digest: [9; 32],
                }))
            }
            setup::Setup::DiscardCustodyDeletion { token } => {
                self.tokens.take(token)?;
                Ok(Response {
                    kind: 55,
                    ..Response::default()
                })
            }
            _ => self.base.setup(input),
        }
    }
    fn snapshot(&mut self) -> Result<state::Snapshot> {
        self.base.snapshot()
    }
    fn observe(&mut self, selector: u32, _identity: &[u8]) -> Result<Response> {
        self.base.calls.fetch_add(1, Ordering::SeqCst);
        Ok(Response {
            kind: 12,
            bytes: vec![selector as u8],
            ..Response::default()
        })
    }
    fn execute(&mut self, request: state::OperationRequestV1) -> Result<Response> {
        self.base.execute(request)
    }
    fn request_status(&mut self, request: &[u8; 32]) -> Result<Response> {
        self.base.request_status(request)
    }
    fn retry(&mut self, operation: &[u8; 32]) -> Result<Response> {
        self.base.retry(operation)
    }
    fn resume(&mut self) -> Result<Response> {
        self.base.resume()
    }
    fn fold(&mut self) -> Result<Response> {
        self.require_custody_operations()?;
        self.base.fold()
    }
    fn credit(&mut self, credit: &[u8; 32], payment: &[u8; 32]) -> Result<Response> {
        self.base.credit(credit, payment)
    }
}
fn scripted() -> (u64, Arc<AtomicUsize>, Arc<AtomicUsize>) {
    let calls = Arc::new(AtomicUsize::new(0));
    let drops = Arc::new(AtomicUsize::new(0));
    let phase = Arc::new(AtomicUsize::new(0));
    let id = install(
        Box::new(Script {
            base: super::super::tests::TestWallet {
                calls: calls.clone(),
                drops: drops.clone(),
                expected_request: None,
            },
            phase,
            tokens: review::Tokens::default(),
        }),
        state::Scheduler::new(),
    )
    .unwrap();
    (id, calls, drops)
}
fn call(handle: u64, selector: u32, token: u64) -> WalletResult {
    let zero = [0; 32];
    let request = WalletSetupRequest {
        setup_id: zero.as_ptr(),
        selector,
        amount: WalletU128 { low: 0, high: 0 },
        token,
        first: std::ptr::null(),
        first_length: 0,
        second: std::ptr::null(),
        second_length: 0,
        third: std::ptr::null(),
        third_length: 0,
    };
    let mut result = WalletResult::default();
    let rc = unsafe { connect_norito_kagemusha_wallet_setup_v1(handle, &request, &mut result) };
    assert_eq!(rc, if result.status < 0 { result.status } else { 0 });
    result
}
#[test]
fn c_boundary_preserves_foreign_review_freezes_money_and_keeps_only_terminal_reconciliation() {
    let (a, _, a_drops) = scripted();
    let (b, b_calls, b_drops) = scripted();
    let ra = call(a, 48, 0);
    let rb = call(b, 48, 0);
    assert_eq!(ra.status, 53);
    assert_eq!(rb.status, 53);
    assert_ne!(ra.sequence_low, rb.sequence_low);
    assert_eq!((ra.sequence_high, ra.detail, ra.length), (0, 0, 254));
    let bytes = unsafe { std::slice::from_raw_parts(ra.bytes, ra.length) };
    assert_eq!(bytes, projection(&view()).unwrap());
    crate::connect_norito_free(ra.bytes);
    crate::connect_norito_free(rb.bytes);
    assert_eq!(call(b, 49, ra.sequence_low).status, INVALID);
    snapshot(b).unwrap(); // foreign token neither consumed B's review nor froze its owner
    assert_eq!(call(b, 49, rb.sequence_low).status, UNCERTAIN);
    let calls = b_calls.load(Ordering::SeqCst);
    assert_eq!(snapshot(b).unwrap_err().status, TERMINAL);
    assert_eq!(
        setup(b, setup::Setup::Bootstrap).unwrap_err().status,
        TERMINAL
    );
    assert_eq!(fold(b).unwrap_err().status, TERMINAL);
    assert_eq!(b_calls.load(Ordering::SeqCst), calls);
    assert_eq!(call(b, 49, rb.sequence_low).status, INVALID);
    for _ in 0..2 {
        let terminal = call(b, 50, 0);
        assert_eq!(
            (
                terminal.status,
                terminal.sequence_low,
                terminal.sequence_high,
                terminal.detail,
                terminal.length
            ),
            (54, 0, 0, 0, 32)
        );
        assert_eq!(
            unsafe { std::slice::from_raw_parts(terminal.bytes, 32) },
            &[9; 32]
        );
        crate::connect_norito_free(terminal.bytes);
    }
    assert_eq!(snapshot(b).unwrap_err().status, TERMINAL);
    assert_eq!(call(b, 48, 0).status, TERMINAL);
    close(a).unwrap();
    close(b).unwrap();
    assert_eq!(a_drops.load(Ordering::SeqCst), 1);
    assert_eq!(b_drops.load(Ordering::SeqCst), 1);
}

#[test]
fn c_boundary_observations_share_the_custody_deletion_gate() {
    let (id, calls, drops) = scripted();
    let identity = [1; 32];
    for phase in 0..3 {
        let previous_calls = calls.load(Ordering::SeqCst);
        for selector in 0..=3 {
            let mut out = WalletResult::default();
            let rc = unsafe {
                connect_norito_kagemusha_wallet_observe_v1(
                    id,
                    selector,
                    identity.as_ptr(),
                    if selector == 0 { 0 } else { identity.len() },
                    &mut out,
                )
            };
            assert_eq!((out.sequence_low, out.sequence_high, out.detail), (0, 0, 0));
            if phase == 0 {
                assert_eq!((rc, out.status, out.length), (0, 12, 1));
                assert_eq!(unsafe { *out.bytes }, selector as u8);
                crate::connect_norito_free(out.bytes);
            } else {
                assert_eq!((rc, out.status, out.length), (TERMINAL, TERMINAL, 0));
                assert!(out.bytes.is_null());
            }
        }
        assert_eq!(
            calls.load(Ordering::SeqCst),
            previous_calls + if phase == 0 { 4 } else { 0 },
            "uncertain and terminal deletion must not reach the observation implementation"
        );
        if phase == 0 {
            let review = call(id, 48, 0);
            assert_eq!(review.status, 53);
            crate::connect_norito_free(review.bytes);
            assert_eq!(call(id, 49, review.sequence_low).status, UNCERTAIN);
        } else if phase == 1 {
            let deleted = call(id, 50, 0);
            assert_eq!(deleted.status, 54);
            crate::connect_norito_free(deleted.bytes);
        }
    }
    close(id).unwrap();
    assert_eq!(drops.load(Ordering::SeqCst), 1);
}

#[test]
fn c_allocator_failure_after_review_issuance_discards_only_the_undelivered_review() {
    let (id, _, _) = scripted();
    let prior = call(id, 48, 0);
    crate::connect_norito_free(prior.bytes);
    let zero = [0; 32];
    let request = WalletSetupRequest {
        setup_id: zero.as_ptr(),
        selector: 48,
        amount: WalletU128 { low: 0, high: 0 },
        token: 0,
        first: std::ptr::null(),
        first_length: 0,
        second: std::ptr::null(),
        second_length: 0,
        third: std::ptr::null(),
        third_length: 0,
    };
    let mut out = WalletResult::default();
    let mut failed_token = 0;
    let result = unsafe {
        exports::setup_output_with(id, &request, &mut out, |value, bytes| {
            assert_eq!(value.status, 53);
            assert_eq!(bytes.len(), 254);
            assert_ne!(value.sequence_low, prior.sequence_low);
            failed_token = value.sequence_low;
            Err(()) // exact post-issuance output allocator refusal, not null-out preflight
        })
    };
    assert_eq!(result, RESOURCE);
    assert_ne!(failed_token, 0);
    assert_eq!(
        (
            out.status,
            out.sequence_low,
            out.sequence_high,
            out.detail,
            out.length
        ),
        (RESOURCE, 0, 0, 0, 0)
    );
    assert!(out.bytes.is_null());
    assert_eq!(call(id, 49, failed_token).status, INVALID);
    assert_eq!(
        call(id, 51, prior.sequence_low).status,
        55,
        "unrelated issued review remains usable"
    );
    snapshot(id).unwrap();
    close(id).unwrap();
}

#[test]
fn jni_delivery_refusal_discards_new_review_but_never_rolls_back_terminal_outcome() {
    let (id, _, _) = scripted();
    let mut failed_token = 0;
    let result = setup(id, setup::Setup::ReviewCustodyDeletion);
    let null = deliver(id, 48, result, |result| {
        let result = result.unwrap();
        assert_eq!(result.kind, 53);
        failed_token = result.sequence as u64;
        (std::ptr::null_mut::<u8>(), false) // the exact null outcome of failed JNI response construction
    });
    assert!(null.is_null());
    assert_ne!(failed_token, 0);
    assert_eq!(call(id, 49, failed_token).status, INVALID);
    snapshot(id).unwrap();
    let result = setup(id, setup::Setup::ReviewCustodyDeletion);
    let token = deliver(id, 48, result, |result| {
        (result.unwrap().sequence as u64, true)
    });
    assert_eq!(call(id, 49, token).status, UNCERTAIN);
    let result = setup(id, setup::Setup::ResumeCustodyDeletion);
    let null = deliver(id, 50, result, |result| {
        assert_eq!(result.unwrap().kind, 54);
        (std::ptr::null_mut::<u8>(), false)
    });
    assert!(null.is_null());
    assert_eq!(snapshot(id).unwrap_err().status, TERMINAL);
    let again = call(id, 50, 0);
    assert_eq!(again.status, 54);
    crate::connect_norito_free(again.bytes);
    close(id).unwrap();
}
