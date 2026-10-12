//! Exclusive mobile ownership of the shared KAGEMUSHA state machine.
//!
//! The C/JNI boundary carries canonical Norito objects and exact retained output bytes.
//! Native startup qualifies its complete signed installation against independently deployed
//! native trust and genesis. Foreign open supplies only bounded original owner frames and
//! the existing account signature. Unprovisioned runtimes remain unavailable.

use iroha_core_zk::kagemusha_wallet_artifacts_v1::producer_inventory::OriginalSourceV1;
use iroha_core_zk::{kagemusha_wallet_advance_v1 as advance, kagemusha_wallet_state_v1 as state};
use iroha_data_model::kagemusha::*;
use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex, OnceLock},
};

mod platform;
pub use platform::{CallbackPlatform, PlatformCallbacks, PlatformReply};
#[cfg(any(
    target_os = "android",
    target_os = "linux",
    target_os = "macos",
    windows
))]
mod android;
#[cfg(any(
    target_os = "android",
    target_os = "linux",
    target_os = "macos",
    windows
))]
pub use android::AndroidPlatform;
mod background;
mod closing;
pub(crate) mod enrollment;
mod exports;
pub(crate) mod observation;
pub use observation::{
    connect_norito_kagemusha_wallet_account_display_v1,
    connect_norito_kagemusha_wallet_account_original_v1,
    connect_norito_kagemusha_wallet_observe_v1,
};
mod installed;
pub(crate) use installed::relocate_registration_source;
pub use installed::{WalletInstallationAttempt, WalletRuntimeOriginals};
pub use installed::{
    connect_norito_kagemusha_wallet_installation_begin_v1,
    connect_norito_kagemusha_wallet_installation_close_v1,
    connect_norito_kagemusha_wallet_installation_register_v1,
    connect_norito_kagemusha_wallet_registration_source_relocate_v1,
};
pub(crate) mod open;
pub use open::{
    NativeRegistrationRetry, NativeStartupFailure, retain_native_runtime, start_native_wallet,
};
pub(crate) mod requests;
pub(crate) mod setup;
pub(crate) mod terminal;
mod transport;
pub use exports::*;
pub(crate) mod review;
pub use review::{
    WalletReviewRequest, connect_norito_kagemusha_wallet_discard_review_v1,
    connect_norito_kagemusha_wallet_execute_reviewed_v1, connect_norito_kagemusha_wallet_review_v1,
};
#[cfg(test)]
mod tests;

/// Invalid input or malformed callback result.
pub const INVALID: i32 = -1;
/// Closed, closing, or unknown opaque handle.
pub const CLOSED: i32 = -2;
/// Owner/handle capacity or an original local canonical-read budget was exhausted.
/// No proof rejection or loss of monetary custody is implied.
pub const RESOURCE: i32 = -3;
/// Required authenticated native proof artifacts are unavailable.
pub const ARTIFACTS_UNAVAILABLE: i32 = -4;
/// Storage or the key store gave no definitive answer.
pub const UNAVAILABLE: i32 = -5;
/// A publication may have committed; reconciliation is required.
pub const UNCERTAIN: i32 = -6;
/// Source-bound custody or required fold witnesses were lost.
pub const CUSTODY_LOST: i32 = -7;
/// Current head must be folded before this operation.
pub const FOLD_REQUIRED: i32 = -8;
/// Native proof verification failed.
pub const PROOF_REJECTED: i32 = -9;
/// Cooperative cancellation completed, with durable state retained.
pub const CANCELLED: i32 = -10;
/// An existing operation/credit identity has different inputs.
pub const CONFLICT: i32 = -11;
/// Design §5.3 `NotEnoughStorage`: free custody storage does not cover the operation (the
/// runtime capacity check before proving or commit, or a full disk). Refused before commit:
/// nothing was debited or credited and the receipt or Payment stays deliverable. Retry after
/// freeing storage. Never a device verdict.
pub const NOT_ENOUGH_STORAGE: i32 = -12;
/// Custody is terminal or the payment key has been lost.
pub const TERMINAL: i32 = -13;
/// Design §5.3 `NotEnoughMemory`: memory available to the app does not cover the installed
/// relations' peak proving memory. Refused before commit: nothing was debited or credited.
/// Retry after freeing memory. Never a device verdict.
pub const NOT_ENOUGH_MEMORY: i32 = -14;
/// Internal panic or poisoned owner; no outcome should be inferred.
pub const INTERNAL: i32 = -100;

const MAX_OWNERS: usize = 32;

/// Bridge failure. `reason` preserves platform tri-state errors instead of calling them absent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Failure {
    /// One negative bridge status above.
    pub status: i32,
    /// Platform reason: 0 locked, 1 before first unlock, 2 busy, 3 I/O, 4 platform,
    /// 5 unusable key, 6 permanently invalidated, or -1 when inapplicable.
    pub reason: i32,
    /// Original OS/platform error code; zero when inapplicable.
    pub platform_code: i32,
}
impl Failure {
    pub(crate) fn code(status: i32) -> Self {
        Self {
            status,
            reason: -1,
            platform_code: 0,
        }
    }
    fn unavailable(status: i32, value: advance::KagemushaWalletUnavailableV1) -> Self {
        use advance::KagemushaWalletUnavailableV1 as U;
        let (reason, platform_code) = match value {
            U::Locked => (0, 0),
            U::BeforeFirstUnlock => (1, 0),
            U::Busy => (2, 0),
            U::Io(code) => (3, code),
            U::Platform(code) => (4, code),
            U::KeyUnusable => (5, 0),
            U::PermanentlyInvalidated => (6, 0),
        };
        Self {
            status,
            reason,
            platform_code,
        }
    }
}
impl From<advance::KagemushaWalletProviderErrorV1> for Failure {
    fn from(value: advance::KagemushaWalletProviderErrorV1) -> Self {
        use advance::KagemushaWalletProviderErrorV1 as E;
        match value {
            E::Unavailable(reason) => Self::unavailable(UNAVAILABLE, reason),
            E::Uncertain(reason) => Self::unavailable(UNCERTAIN, reason),
            E::NoSpace => Self::code(NOT_ENOUGH_STORAGE),
            E::NoReplaceUnsupported | E::Invalid { .. } => Self::code(INVALID),
            E::UnavailableCustodyData { .. } | E::LostCustody(_) | E::UnexpectedEntry { .. } => {
                Self::code(CUSTODY_LOST)
            }
            E::KeyLost | E::Terminal => Self::code(TERMINAL),
            E::OperationIdConflict { .. } => Self::code(CONFLICT),
        }
    }
}
impl From<state::Error> for Failure {
    fn from(value: state::Error) -> Self {
        use state::Error as E;
        match value {
            E::Provider(error) => error.into(),
            E::Storage(error) => Self::unavailable(
                UNAVAILABLE,
                advance::KagemushaWalletUnavailableV1::from_io(&error),
            ),
            E::DecodeResource(original) => match original.kind() {
                norito::core::DecodeAttemptErrorKind::Allocator
                | norito::core::DecodeAttemptErrorKind::EnclosingLimit => Self::code(RESOURCE),
                norito::core::DecodeAttemptErrorKind::Invalid => Self::code(INTERNAL),
            },
            // Compact binary wallet readers cannot originate signed-genesis reads.
            // Preserve an unexpected typed read until this final ABI projection;
            // do not invent locality or an invalidity verdict from its diagnostic.
            E::FinalityRead(_) => Self::code(INTERNAL),
            E::Invalid(_) | E::Collected => Self::code(INVALID),
            E::WitnessLost(_) => Self::code(CUSTODY_LOST),
            E::CreditConflict | E::OperationConflict => Self::code(CONFLICT),
            E::FoldRequired => Self::code(FOLD_REQUIRED),
            E::Pending => Self::code(UNCERTAIN),
            E::NoHead => Self::code(INVALID),
            E::Cancelled => Self::code(CANCELLED),
            E::ArtifactsUnavailable(_) => Self::code(ARTIFACTS_UNAVAILABLE),
            E::Proof(_) => Self::code(PROOF_REJECTED),
            E::NotEnoughStorage => Self::code(NOT_ENOUGH_STORAGE),
            E::NotEnoughMemory => Self::code(NOT_ENOUGH_MEMORY),
        }
    }
}
pub(crate) type Result<T> = std::result::Result<T, Failure>;

#[derive(Debug, Default)]
pub(crate) struct Response {
    // 0 unknown, 1 complete, 2 pending, 3 not performed, 4 archived, 5 delivery loss;
    // 6 idle, 7 caught up, 8 checkpoint, 9 folded, 10 CreditStatus, 11 preparing,
    // 12 exact setup original, 13 time challenge (sequence=token, bytes=nonce32), 14 time retained;
    // 15 account challenge (sequence=runtime, bytes=challenge32), 16 admitted owner.
    pub(crate) kind: i32,
    pub(crate) sequence: u128,
    pub(crate) detail: u32,
    pub(crate) bytes: Vec<u8>,
}
/// Project one coordinator completion. Advance's commit-time storage shortfall is the typed
/// `NOT_ENOUGH_STORAGE` failure (design §5.3), the same status as the check before proving;
/// not-performed `detail` is 0 stale head or 2 invalid.
fn completion(value: Option<state::Completion>) -> Result<Response> {
    use advance::KagemushaWalletNotPerformedV1 as N;
    use state::Completion as C;
    Ok(match value {
        None => Response::default(),
        Some(C::Complete(bytes)) => Response {
            kind: 1,
            bytes,
            ..Response::default()
        },
        Some(C::CreditStatus(bytes)) => Response {
            kind: 10,
            bytes,
            ..Response::default()
        },
        Some(C::Pending) => Response {
            kind: 2,
            ..Response::default()
        },
        Some(C::NotPerformed(reason)) => Response {
            kind: 3,
            detail: match reason {
                N::StaleHead => 0,
                N::CapacityWait => return Err(Failure::code(NOT_ENOUGH_STORAGE)),
                N::Invalid { .. } => 2,
            },
            ..Response::default()
        },
        Some(C::Archived) => Response {
            kind: 4,
            ..Response::default()
        },
        Some(C::DeliveryDataLoss) => Response {
            kind: 5,
            ..Response::default()
        },
    })
}
trait Wallet: Send {
    fn require_custody_operations(&self) -> Result<()> {
        Ok(())
    }
    fn snapshot(&mut self) -> Result<state::Snapshot>;
    fn review(&mut self, _input: review::Input) -> Result<Response> {
        Err(Failure::code(INVALID))
    }
    fn execute_reviewed(&mut self, _token: u64, _request: [u8; 32]) -> Result<Response> {
        Err(Failure::code(INVALID))
    }
    fn discard_review(&mut self, _token: u64) -> Result<()> {
        Err(Failure::code(INVALID))
    }
    fn observe(&mut self, _selector: u32, _identity: &[u8]) -> Result<Response> {
        Err(Failure::code(INVALID))
    }
    fn setup(&mut self, input: setup::Setup) -> Result<Response>;
    fn execute(&mut self, request: state::OperationRequestV1) -> Result<Response>;
    fn request_status(&mut self, request: &[u8; 32]) -> Result<Response>;
    fn retry(&mut self, operation: &[u8; 32]) -> Result<Response>;
    fn resume(&mut self) -> Result<Response>;
    fn fold(&mut self) -> Result<Response>;
    fn credit(&mut self, credit: &[u8; 32], payment: &[u8; 32]) -> Result<Response>;
}
struct NativeWallet<P: advance::KagemushaWalletPlatformV1, S: OriginalSourceV1 + Send> {
    wallet: state::NativeWalletCoordinatorV1<advance::KagemushaWalletStdFsV1, P, S>,
    times: BTreeMap<u64, state::DirectTimeExchangeV1>,
    reviews: review::Tokens<state::ReviewedOperationV1>,
    deletion_reviews: review::Tokens<state::ReviewedCustodyDeletionV1>,
}
impl<P: advance::KagemushaWalletPlatformV1, S: OriginalSourceV1 + Send> Wallet
    for NativeWallet<P, S>
{
    fn require_custody_operations(&self) -> Result<()> {
        Ok(self.wallet.require_custody_operations()?)
    }
    fn observe(&mut self, selector: u32, identity: &[u8]) -> Result<Response> {
        self.observe_inner(selector, identity)
    }
    fn setup(&mut self, input: setup::Setup) -> Result<Response> {
        self.setup_inner(input)
    }
    fn review(&mut self, input: review::Input) -> Result<Response> {
        self.review_inner(input)
    }
    fn execute_reviewed(&mut self, token: u64, request: [u8; 32]) -> Result<Response> {
        self.execute_reviewed_inner(token, request)
    }
    fn discard_review(&mut self, token: u64) -> Result<()> {
        self.reviews.take(token).map(drop)
    }
    fn snapshot(&mut self) -> Result<state::Snapshot> {
        Ok(self.wallet.snapshot()?)
    }
    fn execute(&mut self, request: state::OperationRequestV1) -> Result<Response> {
        completion(Some(self.wallet.execute(request)?))
    }
    fn request_status(&mut self, request: &[u8; 32]) -> Result<Response> {
        Ok(match self.wallet.retry_request(request)? {
            state::RequestStatusV1::Unknown => Response::default(),
            state::RequestStatusV1::Preparing => Response {
                kind: 11,
                ..Response::default()
            },
            state::RequestStatusV1::Outcome(value) => completion(Some(value))?,
        })
    }
    fn retry(&mut self, operation: &[u8; 32]) -> Result<Response> {
        completion(self.wallet.retry(operation)?)
    }
    fn resume(&mut self) -> Result<Response> {
        completion(self.wallet.resume()?)
    }
    fn fold(&mut self) -> Result<Response> {
        self.require_custody_operations()?;
        use state::FoldStatus as F;
        Ok(match self.wallet.fold_once()? {
            F::Idle => Response {
                kind: 6,
                ..Response::default()
            },
            F::CaughtUp => Response {
                kind: 7,
                ..Response::default()
            },
            F::Checkpoint { sequence, ordinal } => Response {
                kind: 8,
                sequence,
                detail: ordinal,
                ..Response::default()
            },
            F::Folded(sequence) => Response {
                kind: 9,
                sequence,
                ..Response::default()
            },
        })
    }
    fn credit(&mut self, credit: &[u8; 32], payment: &[u8; 32]) -> Result<Response> {
        let value = self.wallet.credit_status(credit, payment)?;
        let bytes = norito::encode_canonical(&value).map_err(|_| Failure::code(INTERNAL))?;
        Ok(Response {
            kind: 10,
            bytes,
            ..Response::default()
        })
    }
}
struct Owner {
    background: background::Background,
    closing: Arc<closing::CloseState>,
    scheduler: state::Scheduler,
    // The shared closing state blocks new calls; this owner remains registered until
    // the actual scheduler join and custody drop complete successfully.
    wallet: Mutex<Option<Box<dyn Wallet>>>,
}
#[derive(Default)]
struct Registry {
    next: u64,
    owners: BTreeMap<u64, Arc<Owner>>,
    runtimes: BTreeMap<u64, Arc<open::RuntimeOwner>>,
}
fn registry() -> &'static Mutex<Registry> {
    static VALUE: OnceLock<Mutex<Registry>> = OnceLock::new();
    VALUE.get_or_init(|| Mutex::new(Registry::default()))
}
#[cfg(test)]
fn install(wallet: Box<dyn Wallet>, scheduler: state::Scheduler) -> Result<u64> {
    let mut registry = registry().lock().map_err(|_| Failure::code(INTERNAL))?;
    if registry.owners.len() + registry.runtimes.len() >= MAX_OWNERS {
        return Err(Failure::code(RESOURCE));
    }
    let id = registry
        .next
        .checked_add(1)
        .filter(|id| *id <= i64::MAX as u64)
        .ok_or(Failure::code(RESOURCE))?;
    registry.next = id;
    registry.owners.insert(
        id,
        Arc::new(Owner {
            background: background::Background::default(),
            closing: Arc::new(closing::CloseState::default()),
            scheduler,
            wallet: Mutex::new(Some(wallet)),
        }),
    );
    Ok(id)
}
fn owner(id: u64) -> Result<Arc<Owner>> {
    let owner = registry()
        .lock()
        .map_err(|_| Failure::code(INTERNAL))?
        .owners
        .get(&id)
        .cloned()
        .ok_or(Failure::code(CLOSED))?;
    owner.closing.require_open()?;
    Ok(owner)
}
pub(crate) fn close(id: u64) -> Result<()> {
    closing::close_with(registry(), id)
}
pub(crate) fn activity(id: u64, foreground: bool, charging: bool) -> Result<()> {
    // Order activity with the closing mark without acquiring the wallet mutex:
    // a running fold needs this cancellation signal.
    let selected = registry().lock().map_err(|_| Failure::code(INTERNAL))?;
    let owner = selected.owners.get(&id).ok_or(Failure::code(CLOSED))?;
    owner.closing.require_open()?;
    owner.scheduler.set_activity(foreground, charging);
    if let Err(error) = owner.background.activity(owner, foreground || charging) {
        owner.scheduler.set_activity(false, false);
        return Err(error);
    }
    Ok(())
}
fn with_wallet<T>(
    id: u64,
    payment: bool,
    action: impl FnOnce(&mut dyn Wallet) -> Result<T>,
) -> Result<T> {
    let owner = owner(id)?;
    with_wallet_owner(owner, payment, action)
}
fn with_wallet_owner<T>(
    owner: Arc<Owner>,
    payment: bool,
    action: impl FnOnce(&mut dyn Wallet) -> Result<T>,
) -> Result<T> {
    owner.closing.require_open()?;
    // Signal and join before the owner lock. Reversing these locks deadlocks against proving.
    let _priority = payment.then(|| owner.background.payment(&owner.scheduler));
    let mut guard = owner.wallet.lock().map_err(|_| Failure::code(INTERNAL))?;
    owner.closing.require_open()?;
    let wallet = guard.as_deref_mut().ok_or(Failure::code(CLOSED))?;
    wallet.require_custody_operations()?;
    action(wallet)
}
pub(crate) fn snapshot(id: u64) -> Result<state::Snapshot> {
    // A view does not cancel a useful background fold. Call off the UI thread.
    with_wallet(id, false, |wallet| wallet.snapshot())
}
pub(crate) fn setup(id: u64, input: setup::Setup) -> Result<Response> {
    if terminal::is_terminal_input(&input) {
        return terminal::dispatch(id, input);
    }
    if matches!(input, setup::Setup::BackgroundStatus) {
        return owner(id)?.background.status();
    }
    // Collection uses the same background scheduler as folding. A payment reservation
    // here would make its own scheduler start return Idle forever; real payments still
    // cancel/join collection before acquiring this wallet mutex.
    let payment = !matches!(input, setup::Setup::CollectRetained { .. });
    with_wallet(id, payment, |wallet| wallet.setup(input))
}
pub(crate) fn execute(id: u64, request: state::OperationRequestV1) -> Result<Response> {
    if matches!(
        &request.action,
        state::OperationActionV1::Send { .. } | state::OperationActionV1::Unload { .. }
    ) {
        return Err(Failure::code(INVALID));
    }
    with_wallet(id, true, |wallet| wallet.execute(request))
}
pub(crate) fn request_status(id: u64, request: &[u8]) -> Result<Response> {
    let request: &[u8; 32] = request.try_into().map_err(|_| Failure::code(INVALID))?;
    if *request == [0; 32] {
        return Err(Failure::code(INVALID));
    }
    with_wallet(id, true, |wallet| wallet.request_status(request))
}
pub(crate) fn retry(id: u64, operation: &[u8]) -> Result<Response> {
    let operation = operation.try_into().map_err(|_| Failure::code(INVALID))?;
    with_wallet(id, true, |wallet| wallet.retry(operation))
}
pub(crate) fn resume(id: u64) -> Result<Response> {
    with_wallet(id, true, |wallet| wallet.resume())
}
pub(crate) fn fold(id: u64) -> Result<Response> {
    with_wallet(id, false, |wallet| wallet.fold())
}
pub(crate) fn credit(id: u64, credit: &[u8], payment: &[u8]) -> Result<Response> {
    let credit = credit.try_into().map_err(|_| Failure::code(INVALID))?;
    let payment = payment.try_into().map_err(|_| Failure::code(INVALID))?;
    with_wallet(id, true, |wallet| wallet.credit(credit, payment))
}
pub(crate) fn run<T>(action: impl FnOnce() -> Result<T>) -> Result<T> {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(action))
        .unwrap_or(Err(Failure::code(INTERNAL)))
}
