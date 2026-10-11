//! One signed readiness transaction overlaps transport setup without weakening final proof.

use super::{POLL, PreparedLocalnet, store};
use iroha::blocking::Client;
use iroha_crypto::HashOf;
use iroha_data_model::{
    Level,
    isi::Log,
    transaction::{FeePaymentIntent, SignedTransaction},
};
mod fees;

use std::{
    sync::atomic::{AtomicBool, AtomicU8, Ordering},
    thread,
    time::{Duration, Instant},
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
enum Phase {
    Initialization,
    Genesis,
    Submission,
    Peer0,
    Peer1,
    Peer2,
    Peer3,
    Mesh,
}

impl Phase {
    const fn description(self) -> &'static str {
        match self {
            Self::Initialization => "constructing the retained readiness clients",
            Self::Genesis => "waiting for genesis on all four validators",
            Self::Submission => "submitting and confirming the single readiness transaction",
            Self::Peer0 => "confirming the exact readiness transaction on validator 0",
            Self::Peer1 => "confirming the exact readiness transaction on validator 1",
            Self::Peer2 => "confirming the exact readiness transaction on validator 2",
            Self::Peer3 => "confirming the exact readiness transaction on validator 3",
            Self::Mesh => "confirming the complete four-validator peer mesh",
        }
    }
}

/// Closed phase observation shared with the worker's original startup deadline.
#[derive(Default)]
pub(super) struct Progress(AtomicU8);

impl Progress {
    fn enter(&self, phase: Phase) {
        self.0.store(phase as u8, Ordering::Release);
    }

    fn phase(&self) -> Phase {
        match self.0.load(Ordering::Acquire) {
            1 => Phase::Genesis,
            2 => Phase::Submission,
            3 => Phase::Peer0,
            4 => Phase::Peer1,
            5 => Phase::Peer2,
            6 => Phase::Peer3,
            7 => Phase::Mesh,
            _ => Phase::Initialization,
        }
    }

    pub(super) fn deadline(&self) -> Failure {
        Failure {
            phase: self.phase(),
            cause: Cause::Deadline,
        }
    }

    pub(super) fn unconfirmed(&self) -> Failure {
        Failure {
            phase: self.phase(),
            cause: Cause::Unconfirmed,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Cause {
    Deadline,
    Cancelled,
    Unconfirmed,
}

/// Safe internal failure; server bodies, credentials and arbitrary errors are never retained.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Failure {
    phase: Phase,
    cause: Cause,
}

impl Failure {
    pub(super) fn message(self) -> String {
        let cause = match self.cause {
            Cause::Deadline => "startup readiness deadline expired",
            Cause::Cancelled => "startup readiness was cancelled",
            Cause::Unconfirmed => "startup readiness could not be confirmed",
        };
        format!("{cause} while {}", self.phase.description())
    }
}

struct Budget<'a> {
    started: Instant,
    timeout: Duration,
    cancelled: &'a AtomicBool,
    progress: &'a Progress,
    clock: &'a dyn Clock,
}

trait Clock {
    fn now(&self) -> Instant;
    fn wait(&self, duration: Duration);
}

struct WallClock;

impl Clock for WallClock {
    fn now(&self) -> Instant {
        Instant::now()
    }

    fn wait(&self, duration: Duration) {
        thread::sleep(duration);
    }
}

impl Budget<'_> {
    fn remaining(&self) -> Result<Duration, Failure> {
        if self.cancelled.load(Ordering::Acquire) {
            return Err(Failure {
                phase: self.progress.phase(),
                cause: Cause::Cancelled,
            });
        }
        self.timeout
            .checked_sub(self.clock.now().saturating_duration_since(self.started))
            .filter(|remaining| !remaining.is_zero())
            .ok_or_else(|| self.progress.deadline())
    }

    fn unconfirmed(&self) -> Failure {
        self.remaining()
            .err()
            .unwrap_or_else(|| self.progress.unconfirmed())
    }
}

#[derive(Clone, Copy)]
struct PeerStatus {
    blocks: u64,
    peers: u64,
}

// Internal orchestration seam only. The native implementation keeps canonical SDK signing,
// dispatch ambiguity recovery and state-resolved Applied validation together.
trait Backend {
    type Hash: Copy + Eq;
    fn status(&mut self, peer: usize) -> Option<PeerStatus>;
    fn submit_and_confirm(&mut self, remaining: Duration) -> Result<Self::Hash, ()>;
    fn wait_applied(
        &mut self,
        peer: usize,
        hash: Self::Hash,
        remaining: Duration,
    ) -> Result<Self::Hash, ()>;
}

struct Native {
    clients: Vec<Client>,
    deadline: Instant,
    fee_payment: FeePaymentIntent,
}

impl Backend for Native {
    type Hash = HashOf<SignedTransaction>;

    fn status(&mut self, peer: usize) -> Option<PeerStatus> {
        self.clients[peer]
            .status()
            .get()
            .ok()
            .map(|status| PeerStatus {
                blocks: status.blocks,
                peers: status.peers,
            })
    }

    fn submit_and_confirm(&mut self, remaining: Duration) -> Result<Self::Hash, ()> {
        let submitter = self.submitter(remaining)?;
        let signed = smoke_transaction(submitter.account_client(), self.fee_payment.clone())?;
        submitter
            .submit_transaction_and_wait(&signed)
            .map_err(|_| ())
    }

    fn wait_applied(
        &mut self,
        peer: usize,
        hash: Self::Hash,
        remaining: Duration,
    ) -> Result<Self::Hash, ()> {
        self.clients[peer]
            .wait_for_transaction_applied_local(
                hash,
                iroha::client::TransactionWaitOptions {
                    timeout: remaining,
                    poll_interval: POLL,
                },
            )
            .map(|_| hash)
            .map_err(|_| ())
    }
}

impl Native {
    fn submitter(&self, remaining: Duration) -> Result<Client, ()> {
        // Peer 0 owns the original submission settings and its already-warmed transport.
        // Rebuilding revalidates that immutable context with fresh compatibility/probe state;
        // only this call's remaining confirmation budget changes.
        if remaining.is_zero() || Instant::now() >= self.deadline {
            return Err(());
        }
        let mut builder = self.clients.first().ok_or(())?.client().to_builder();
        builder.transaction_status_timeout = remaining;
        let native = builder
            .build()
            .map_err(|_| ())?
            .with_request_deadline(self.deadline);
        Client::from_client(native).map_err(|_| ())
    }
}

// Use the canonical account builder/signature owner directly. The convenience submit API
// requests a quote and replaces charge limits; this fixed local cap must remain signature-bound.
fn smoke_transaction(
    account: &iroha::client::AccountClient,
    payment: FeePaymentIntent,
) -> Result<SignedTransaction, ()> {
    let payload = account
        .prepare_transaction(iroha::client::AccountTransactionDraft::new(
            [iroha_data_model::isi::InstructionBox::from(Log::new(
                Level::INFO,
                format!("managed localnet readiness {}", store::random_token()),
            ))],
            payment,
            iroha_model_base::metadata::Metadata::default(),
        ))
        .map_err(|_| ())?;
    account.sign_transaction(payload).map_err(|_| ())
}

/// One successful paid smoke proof bound to its original generation and exact transaction.
/// Private fields prevent callers from minting a receipt from an Applied DTO/hash alone.
pub(super) struct Receipt {
    prepared: PreparedLocalnet,
    genesis_hash: HashOf<iroha_data_model::block::BlockHeader>,
    transaction_hash: HashOf<SignedTransaction>,
}

impl std::fmt::Debug for Receipt {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ReadinessReceipt").finish_non_exhaustive()
    }
}

pub(super) fn prove(
    prepared: &PreparedLocalnet,
    started: Instant,
    timeout: Duration,
    cancelled: &AtomicBool,
    progress: &Progress,
) -> Result<Receipt, Failure> {
    let budget = Budget {
        started,
        timeout,
        cancelled,
        progress,
        clock: &WallClock,
    };
    let (mut native, genesis_hash) = native(prepared, &budget)?;
    let transaction_hash = run(&mut native, &budget)?;
    Ok(Receipt {
        prepared: prepared.clone(),
        genesis_hash,
        transaction_hash,
    })
}

/// Recheck the original paid smoke after restart, without submitting another transaction.
/// The process owner supplies the same activation budget across a restart. A later credential
/// renewal gets a separately bounded read-only check of these exact original bytes.
pub(super) fn reprove(
    prepared: &PreparedLocalnet,
    receipt: &Receipt,
    started: Instant,
    timeout: Duration,
    cancelled: &AtomicBool,
    progress: &Progress,
) -> Result<(), Failure> {
    let budget = Budget {
        started,
        timeout,
        cancelled,
        progress,
        clock: &WallClock,
    };
    budget.remaining()?;
    if prepared != &receipt.prepared {
        return Err(budget.unconfirmed());
    }
    let (mut native, genesis_hash) = native(prepared, &budget)?;
    if genesis_hash != receipt.genesis_hash {
        return Err(budget.unconfirmed());
    }
    run_existing(&mut native, &budget, receipt.transaction_hash)
}

fn native(
    prepared: &PreparedLocalnet,
    budget: &Budget<'_>,
) -> Result<(Native, HashOf<iroha_data_model::block::BlockHeader>), Failure> {
    budget.progress.enter(Phase::Initialization);
    budget.remaining()?;
    let deadline = budget
        .started
        .checked_add(budget.timeout)
        .ok_or_else(|| budget.unconfirmed())?;
    let mut config = prepared
        .context
        .load_client_config()
        .map_err(|_| budget.unconfirmed())?;
    let selected = fees::select(prepared, &config).map_err(|_| budget.unconfirmed())?;
    budget.remaining()?;
    config.torii_request_timeout = Duration::from_millis(750);
    config.transaction_status_timeout = budget.timeout;
    config.transaction_ttl = budget.timeout.max(Duration::from_secs(60));
    let endpoints = prepared
        .peers
        .iter()
        .map(|peer| peer.torii_url.parse())
        .collect::<Result<Vec<url::Url>, _>>()
        .map_err(|_| budget.unconfirmed())?;
    let clients = readiness_clients(iroha::client::Client::builder(config), &endpoints, deadline)
        .map_err(|()| budget.unconfirmed())?;
    Ok((
        Native {
            clients,
            deadline,
            fee_payment: selected.payment,
        },
        selected.genesis_hash,
    ))
}

// One readiness session retains its first peer's native transport. Rebuilding each selected
// peer context still validates its endpoint/account and starts independent compatibility probes;
// only the connection pools and original deadline are shared. Every runtime owner stays alive
// until the whole session returns, including connections first driven by another peer's runtime.
fn readiness_clients(
    mut selected: iroha::client::ClientBuilder,
    endpoints: &[url::Url],
    deadline: Instant,
) -> Result<Vec<Client>, ()> {
    if endpoints.len() != 4 {
        return Err(());
    }
    let submission_endpoint = selected.torii_url.clone();
    selected.torii_url = endpoints[0].clone();
    let first = selected
        .build()
        .map_err(|_| ())?
        .with_request_deadline(deadline);
    // The loader and SDK builder apply the same canonical endpoint normalization.
    if first.endpoint() != &submission_endpoint {
        return Err(());
    }
    let mut clients = vec![Client::from_client(first).map_err(|_| ())?];
    for endpoint in &endpoints[1..] {
        let mut builder = clients[0].client().to_builder();
        builder.torii_url = endpoint.clone();
        let peer = builder
            .build()
            .map_err(|_| ())?
            .with_request_deadline(deadline);
        clients.push(Client::from_client(peer).map_err(|_| ())?);
    }
    Ok(clients)
}

#[cfg(test)]
#[path = "readiness/client_tests.rs"]
mod client_tests;

fn wait_status(backend: &mut impl Backend, budget: &Budget<'_>, mesh: bool) -> Result<(), Failure> {
    loop {
        budget.remaining()?;
        let complete = (0..4).all(|peer| {
            backend
                .status(peer)
                .is_some_and(|status| status.blocks > 0 && (!mesh || status.peers >= 3))
        });
        let remaining = budget.remaining()?;
        if complete {
            return Ok(());
        }
        budget.clock.wait(POLL.min(remaining));
    }
}

fn run<B: Backend>(backend: &mut B, budget: &Budget<'_>) -> Result<B::Hash, Failure> {
    budget.progress.enter(Phase::Genesis);
    wait_status(backend, budget, false)?;
    // Admission can retain this exact transaction while authenticated links establish. Only
    // final evidence below grants Ready; a paid transaction can apply while startup still fails.
    budget.progress.enter(Phase::Submission);
    let remaining = budget.remaining()?;
    let hash = backend
        .submit_and_confirm(remaining)
        .map_err(|()| budget.unconfirmed())?;
    confirm_all(backend, budget, hash)?;
    Ok(hash)
}

fn run_existing<B: Backend>(
    backend: &mut B,
    budget: &Budget<'_>,
    hash: B::Hash,
) -> Result<(), Failure> {
    budget.progress.enter(Phase::Genesis);
    wait_status(backend, budget, false)?;
    confirm_all(backend, budget, hash)
}

fn confirm_all<B: Backend>(
    backend: &mut B,
    budget: &Budget<'_>,
    hash: B::Hash,
) -> Result<(), Failure> {
    budget.remaining()?;
    for (peer, phase) in [Phase::Peer0, Phase::Peer1, Phase::Peer2, Phase::Peer3]
        .into_iter()
        .enumerate()
    {
        budget.progress.enter(phase);
        let remaining = budget.remaining()?;
        let applied = backend
            .wait_applied(peer, hash, remaining)
            .map_err(|()| budget.unconfirmed())?;
        budget.remaining()?;
        if applied != hash {
            return Err(budget.unconfirmed());
        }
    }
    budget.progress.enter(Phase::Mesh);
    wait_status(backend, budget, true)?;
    budget.remaining()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    struct FakeClock {
        started: Instant,
        elapsed: std::cell::Cell<Duration>,
    }

    impl FakeClock {
        fn new() -> Self {
            Self {
                started: Instant::now(),
                elapsed: std::cell::Cell::new(Duration::ZERO),
            }
        }
    }

    impl Clock for FakeClock {
        fn now(&self) -> Instant {
            self.started + self.elapsed.get()
        }

        fn wait(&self, duration: Duration) {
            self.elapsed.set(self.elapsed.get() + duration);
        }
    }

    struct Fake {
        genesis: [bool; 4],
        mesh: bool,
        submit_error: bool,
        missing_applied: Option<usize>,
        wrong_hash: Option<usize>,
        submits: usize,
        applied: Vec<(usize, u64)>,
        mesh_reads: usize,
        connect_after_applied: bool,
    }

    impl Default for Fake {
        fn default() -> Self {
            Self {
                genesis: [true; 4],
                mesh: false,
                submit_error: false,
                missing_applied: None,
                wrong_hash: None,
                submits: 0,
                applied: Vec::new(),
                mesh_reads: 0,
                connect_after_applied: true,
            }
        }
    }

    impl Backend for Fake {
        type Hash = u64;

        fn status(&mut self, peer: usize) -> Option<PeerStatus> {
            if self.applied.len() == 4 {
                self.mesh_reads += 1;
                if self.connect_after_applied {
                    self.mesh = true;
                }
            }
            Some(PeerStatus {
                blocks: u64::from(self.genesis[peer]),
                peers: if self.mesh { 3 } else { 0 },
            })
        }

        fn submit_and_confirm(&mut self, _remaining: Duration) -> Result<Self::Hash, ()> {
            assert!(self.genesis.iter().all(|loaded| *loaded));
            assert!(
                !self.mesh,
                "submission must overlap incomplete transport setup"
            );
            self.submits += 1;
            if self.submit_error { Err(()) } else { Ok(41) }
        }

        fn wait_applied(
            &mut self,
            peer: usize,
            hash: Self::Hash,
            _remaining: Duration,
        ) -> Result<Self::Hash, ()> {
            self.applied.push((peer, hash));
            if self.missing_applied == Some(peer) {
                return Err(());
            }
            Ok(if self.wrong_hash == Some(peer) {
                42
            } else {
                hash
            })
        }
    }

    fn attempt(
        backend: &mut Fake,
        timeout: Duration,
        cancelled: &AtomicBool,
        progress: &Progress,
    ) -> Result<(), Failure> {
        let clock = FakeClock::new();
        run(
            backend,
            &Budget {
                started: clock.now(),
                timeout,
                cancelled,
                progress,
                clock: &clock,
            },
        )
        .map(drop)
    }

    #[test]
    fn submission_overlaps_mesh_but_all_four_exact_applied_and_final_mesh_are_required() {
        let mut backend = Fake::default();
        let progress = Progress::default();
        attempt(
            &mut backend,
            Duration::from_secs(1),
            &AtomicBool::new(false),
            &progress,
        )
        .unwrap();
        assert_eq!(backend.submits, 1);
        assert_eq!(backend.applied, [(0, 41), (1, 41), (2, 41), (3, 41)]);
        assert_eq!(backend.mesh_reads, 4);
        assert!(backend.mesh);
        assert_eq!(progress.phase(), Phase::Mesh);
    }

    #[test]
    fn missing_genesis_times_out_without_submitting() {
        let mut backend = Fake {
            genesis: [true, true, true, false],
            ..Fake::default()
        };
        let failure = attempt(
            &mut backend,
            Duration::from_millis(5),
            &AtomicBool::new(false),
            &Progress::default(),
        )
        .unwrap_err();
        assert_eq!(
            failure,
            Failure {
                phase: Phase::Genesis,
                cause: Cause::Deadline
            }
        );
        assert_eq!(backend.submits, 0);
        assert!(backend.applied.is_empty());
    }

    #[test]
    fn paid_applied_transaction_without_final_mesh_still_times_out() {
        let mut backend = Fake {
            connect_after_applied: false,
            ..Fake::default()
        };
        let failure = attempt(
            &mut backend,
            Duration::from_millis(5),
            &AtomicBool::new(false),
            &Progress::default(),
        )
        .unwrap_err();
        assert_eq!(
            failure,
            Failure {
                phase: Phase::Mesh,
                cause: Cause::Deadline
            }
        );
        assert_eq!(backend.submits, 1);
        assert_eq!(backend.applied.len(), 4);
        assert!(!backend.mesh);
    }

    #[test]
    fn missing_or_substituted_peer_confirmation_fails_without_a_replacement_transaction() {
        for wrong_hash in [false, true] {
            let mut backend = Fake::default();
            if wrong_hash {
                backend.wrong_hash = Some(3);
            } else {
                backend.missing_applied = Some(3);
            }
            let failure = attempt(
                &mut backend,
                Duration::from_secs(1),
                &AtomicBool::new(false),
                &Progress::default(),
            )
            .unwrap_err();
            assert_eq!(
                failure,
                Failure {
                    phase: Phase::Peer3,
                    cause: Cause::Unconfirmed
                }
            );
            assert_eq!(backend.submits, 1);
            assert_eq!(backend.mesh_reads, 0);
        }
    }

    #[test]
    fn sdk_submission_failure_never_replaces_or_claims_applied() {
        let mut backend = Fake {
            submit_error: true,
            ..Fake::default()
        };
        let failure = attempt(
            &mut backend,
            Duration::from_secs(1),
            &AtomicBool::new(false),
            &Progress::default(),
        )
        .unwrap_err();
        assert_eq!(
            failure,
            Failure {
                phase: Phase::Submission,
                cause: Cause::Unconfirmed
            }
        );
        assert_eq!(backend.submits, 1);
        assert!(backend.applied.is_empty());
    }

    #[test]
    fn original_deadline_and_cancellation_fail_before_dispatch() {
        let progress = Progress::default();
        let cancelled = AtomicBool::new(false);
        let clock = FakeClock::new();
        let budget = Budget {
            started: clock.now() - Duration::from_secs(2),
            timeout: Duration::from_secs(1),
            cancelled: &cancelled,
            progress: &progress,
            clock: &clock,
        };
        let mut backend = Fake::default();
        assert_eq!(
            run(&mut backend, &budget).unwrap_err().cause,
            Cause::Deadline
        );
        assert_eq!(backend.submits, 0);
        cancelled.store(true, Ordering::Release);
        assert_eq!(
            attempt(&mut backend, Duration::from_secs(1), &cancelled, &progress)
                .unwrap_err()
                .cause,
            Cause::Cancelled
        );
        assert_eq!(backend.submits, 0);
    }

    #[test]
    fn successful_sdk_confirmation_after_original_deadline_never_becomes_ready() {
        struct LateConfirmation<'a> {
            backend: Fake,
            clock: &'a FakeClock,
        }
        impl Backend for LateConfirmation<'_> {
            type Hash = u64;

            fn status(&mut self, peer: usize) -> Option<PeerStatus> {
                self.backend.status(peer)
            }

            fn submit_and_confirm(&mut self, remaining: Duration) -> Result<u64, ()> {
                let result = self.backend.submit_and_confirm(remaining);
                self.clock.wait(remaining);
                result
            }

            fn wait_applied(
                &mut self,
                peer: usize,
                hash: u64,
                remaining: Duration,
            ) -> Result<u64, ()> {
                self.backend.wait_applied(peer, hash, remaining)
            }
        }
        let clock = FakeClock::new();
        let progress = Progress::default();
        let cancelled = AtomicBool::new(false);
        let mut backend = LateConfirmation {
            backend: Fake::default(),
            clock: &clock,
        };
        let failure = run(
            &mut backend,
            &Budget {
                started: clock.now(),
                timeout: Duration::from_secs(1),
                cancelled: &cancelled,
                progress: &progress,
                clock: &clock,
            },
        )
        .unwrap_err();
        assert_eq!(
            failure,
            Failure {
                phase: Phase::Submission,
                cause: Cause::Deadline
            }
        );
        assert_eq!(backend.backend.submits, 1);
        assert!(backend.backend.applied.is_empty());
    }

    #[test]
    fn reproof_waits_for_the_original_hash_without_any_second_submission() {
        let clock = FakeClock::new();
        let progress = Progress::default();
        let cancelled = AtomicBool::new(false);
        let budget = Budget {
            started: clock.now(),
            timeout: Duration::from_secs(1),
            cancelled: &cancelled,
            progress: &progress,
            clock: &clock,
        };
        let mut backend = Fake::default();
        run_existing(&mut backend, &budget, 41).unwrap();
        assert_eq!(backend.submits, 0);
        assert_eq!(backend.applied, [(0, 41), (1, 41), (2, 41), (3, 41)]);
        assert!(backend.mesh);
    }

    #[test]
    fn reproof_refuses_changed_hash_and_elapsed_original_budget_without_resubmission() {
        let clock = FakeClock::new();
        let progress = Progress::default();
        let cancelled = AtomicBool::new(false);
        let budget = Budget {
            started: clock.now(),
            timeout: Duration::from_secs(1),
            cancelled: &cancelled,
            progress: &progress,
            clock: &clock,
        };
        let mut backend = Fake {
            wrong_hash: Some(2),
            ..Fake::default()
        };
        assert_eq!(
            run_existing(&mut backend, &budget, 41).unwrap_err().phase,
            Phase::Peer2
        );
        assert_eq!(backend.submits, 0);
        clock.wait(Duration::from_secs(1));
        let mut backend = Fake::default();
        assert_eq!(
            run_existing(&mut backend, &budget, 41).unwrap_err().cause,
            Cause::Deadline
        );
        assert_eq!(backend.submits, 0);
        assert!(backend.applied.is_empty());
    }

    #[test]
    fn later_finite_reproof_checks_all_original_hashes_without_another_payment() {
        let clock = FakeClock::new();
        let progress = Progress::default();
        let cancelled = AtomicBool::new(false);
        let initial = Budget {
            started: clock.now(),
            timeout: Duration::from_secs(120),
            cancelled: &cancelled,
            progress: &progress,
            clock: &clock,
        };
        let mut first = Fake::default();
        let original = run(&mut first, &initial).unwrap();
        assert_eq!(first.submits, 1);
        clock.wait(Duration::from_secs(43_200));
        let mut restarted = Fake::default();
        assert_eq!(
            run_existing(&mut restarted, &initial, original)
                .unwrap_err()
                .cause,
            Cause::Deadline
        );
        assert!(restarted.applied.is_empty());
        let renewal = Budget {
            started: clock.now(),
            ..initial
        };
        run_existing(&mut restarted, &renewal, original).unwrap();
        assert_eq!(restarted.submits, 0);
        assert_eq!(
            restarted.applied,
            [(0, original), (1, original), (2, original), (3, original)]
        );
        assert!(restarted.mesh);
        clock.wait(Duration::from_secs(120));
        let mut late = Fake::default();
        assert_eq!(
            run_existing(&mut late, &renewal, original)
                .unwrap_err()
                .cause,
            Cause::Deadline
        );
        assert_eq!(late.submits, 0);
        assert!(late.applied.is_empty());
    }

    #[test]
    fn failure_messages_only_expose_closed_phases_and_causes() {
        let progress = Progress::default();
        for phase in [
            Phase::Initialization,
            Phase::Genesis,
            Phase::Submission,
            Phase::Peer0,
            Phase::Peer1,
            Phase::Peer2,
            Phase::Peer3,
            Phase::Mesh,
        ] {
            progress.enter(phase);
            assert_eq!(progress.phase(), phase);
            assert_eq!(
                progress.deadline().message(),
                format!(
                    "startup readiness deadline expired while {}",
                    phase.description()
                )
            );
            assert_eq!(
                progress.unconfirmed().message(),
                format!(
                    "startup readiness could not be confirmed while {}",
                    phase.description()
                )
            );
        }
    }
}

#[cfg(test)]
#[path = "readiness/fee_tests.rs"]
mod fee_tests;

#[cfg(test)]
#[path = "readiness/transport_tests.rs"]
mod transport_tests;
