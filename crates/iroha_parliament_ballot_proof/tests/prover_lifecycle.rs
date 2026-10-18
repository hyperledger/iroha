//! Finish-and-discard lifecycle tests against the actual synchronous prover.
//! Uses public deterministic fixture material, not production randomness.
//! The allocator observes only named heap ranges before release; this is not
//! evidence of compiler, register, stack, provider, or abort-path erasure.

mod common;
#[path = "../examples/prover_lifecycle/job.rs"]
mod job;
#[allow(unsafe_code)]
#[path = "prover_lifecycle/allocator_probe.rs"]
mod probe;

use iroha_parliament_ballot_proof::{
    credential::CredentialSecret,
    layout::{REGISTRATION_WITNESS_BITS, VOTE_WITNESS_BITS},
    profile::{Role, Row},
    proving::{ProveError, ProvingTape},
    registration, vote,
};
use job::{Cancellation, Computation, Input, Job, Outcome, Statement};
use probe::Buffer;
use std::sync::{Arc, Barrier};

/// Every compiled row: the comparator joins with the `diagnostics` feature.
const ROWS: [Row; Row::ALL.len()] = Row::ALL;
const ROLES: [Role; 2] = [Role::Registration, Role::Vote];

#[test]
fn observer_distinguishes_zeroed_and_nonzero_releases_including_last_byte() {
    let _serial = probe::SERIAL.lock().expect("test lock");
    for length in [48, 112, 4480, 6688, 160_148] {
        for nonzero in [false, true] {
            probe::reset();
            let mut bytes = vec![0u8; length];
            if nonzero {
                bytes[length - 1] = 0xa5;
            }
            probe::track(Buffer::Proof, &bytes);
            drop(bytes);
            if nonzero {
                probe::assert_not_erased(Buffer::Proof);
            } else {
                probe::assert_erased(Buffer::Proof, length);
            }
        }
    }
}

fn witness_bytes(role: Role) -> usize {
    match role {
        Role::Registration => REGISTRATION_WITNESS_BITS / 8,
        Role::Vote => VOTE_WITNESS_BITS / 8,
    }
}

fn input(row: Row, role: Role, wrong_secret: bool) -> Input {
    let (statement, mut bytes, tape) = match role {
        Role::Registration => {
            let case = common::reg_case(row);
            (
                Statement::Registration(case.statement),
                case.secret,
                case.tape,
            )
        }
        Role::Vote => {
            let case = common::vote_case(row, 3, 1);
            (Statement::Vote(case.statement, 1), case.secret, case.tape)
        }
    };
    if wrong_secret {
        bytes = common::other_secret();
    }
    let secret = CredentialSecret::fill_with(|destination| {
        destination.copy_from_slice(&bytes);
        probe::track(Buffer::Secret, destination);
        Ok::<_, ()>(())
    })
    .expect("fixture fill");
    let tape = ProvingTape::fill_with(|destination| {
        destination.copy_from_slice(&tape);
        probe::track(Buffer::Tape, destination);
        Ok::<_, ()>(())
    })
    .expect("fixture fill");
    Input {
        row,
        statement,
        secret,
        tape,
    }
}

fn observe_proof(proof: Option<&[u8]>) {
    if let Some(proof) = proof {
        probe::track(Buffer::Proof, proof);
    }
}

fn assert_input_erased() {
    probe::assert_erased(Buffer::Secret, 48);
    probe::assert_erased(Buffer::Tape, 112);
}

fn expected_proof(row: Row, role: Role) -> Vec<u8> {
    let bytes: &[u8] = match (row, role) {
        (Row::Candidate, Role::Registration) => include_bytes!("fixtures/reg_fast.proof"),
        #[cfg(feature = "diagnostics")]
        (Row::Comparator, Role::Registration) => include_bytes!("fixtures/reg_comparator.proof"),
        (Row::Candidate, Role::Vote) => include_bytes!("fixtures/vote_S3_i1_fast.proof"),
        #[cfg(feature = "diagnostics")]
        (Row::Comparator, Role::Vote) => include_bytes!("fixtures/vote_S3_i1_comparator.proof"),
    };
    bytes.to_vec()
}

#[test]
fn ordinary_publication_matches_independent_fixtures_and_cleans_input_owners() {
    let _serial = probe::SERIAL.lock().expect("test lock");
    for row in ROWS {
        for role in ROLES {
            probe::reset();
            let job = Job::spawn(input(row, role, false)).expect("worker");
            let cancellation = job.cancellation();
            let Outcome::Published(proof) = job.finish() else {
                panic!("expected publication")
            };
            assert_input_erased();
            assert_eq!(&**proof, &expected_proof(row, role));
            match role {
                Role::Registration => {
                    registration::verify(row, &common::reg_case(row).statement, &proof)
                }
                Role::Vote => vote::verify(row, &common::vote_case(row, 3, 1).statement, &proof),
            }
            .expect("ordinary proof verifies");
            assert_eq!(cancellation.cancel(), Cancellation::TooLate);
            println!(
                "published row={row:?} role={role:?} bytes={} fixture_equal=true input_owners_erased=true",
                proof.len()
            );
        }
    }
}

#[test]
fn cancellation_inside_actual_prove_finishes_discards_and_erases_selected_buffers() {
    let _serial = probe::SERIAL.lock().expect("test lock");
    assert_eq!(witness_bytes(Role::Registration), 4480);
    assert_eq!(witness_bytes(Role::Vote), 6688);
    for row in ROWS {
        for role in ROLES {
            probe::reset();
            let bytes = witness_bytes(role);
            let job = Job::spawn_observed(
                input(row, role, false),
                move || probe::arm_witness(bytes),
                observe_proof,
            )
            .expect("worker");
            // Created after job: on an assertion unwind this releases the worker
            // before Job::drop joins. No panic-unwind erasure claim is inferred.
            let release_guard = probe::ReleaseGuard;
            assert!(
                probe::wait_for_witness(),
                "real prover milestone not reached"
            );
            probe::assert_live(Buffer::Secret);
            probe::assert_live(Buffer::Tape);
            let control = job.cancellation();
            let cancelled_at = std::time::Instant::now();
            assert_eq!(control.cancel(), Cancellation::Accepted);
            assert_eq!(control.cancel(), Cancellation::AlreadyRequested);
            drop(release_guard);
            assert!(matches!(
                job.finish(),
                Outcome::Discarded(Computation::Proved)
            ));
            assert_input_erased();
            probe::assert_erased(Buffer::Witness, bytes);
            probe::assert_erased(Buffer::Proof, row.proof_bytes(role));
            assert_eq!(control.cancel(), Cancellation::TooLate);
            println!(
                "cancel_in_prove row={row:?} role={role:?} witness_bytes={bytes} computation=proved published=false selected_buffers_erased=true cancellation_to_finish_ms={:.3}",
                cancelled_at.elapsed().as_secs_f64() * 1000.0
            );
        }
    }
}

#[test]
fn completed_but_unpublished_proof_can_still_be_cancelled() {
    let _serial = probe::SERIAL.lock().expect("test lock");
    for row in ROWS {
        for role in ROLES {
            probe::reset();
            let mut job =
                Job::spawn_observed(input(row, role, false), || {}, observe_proof).expect("worker");
            assert_eq!(job.wait(), Computation::Proved);
            assert_eq!(job.wait(), Computation::Proved);
            assert_input_erased();
            probe::assert_live(Buffer::Proof);
            assert_eq!(job.cancellation().cancel(), Cancellation::Accepted);
            assert!(matches!(
                job.finish(),
                Outcome::Discarded(Computation::Proved)
            ));
            probe::assert_erased(Buffer::Proof, row.proof_bytes(role));
        }
    }
}

#[test]
fn dropping_inflight_job_joins_and_discards() {
    let _serial = probe::SERIAL.lock().expect("test lock");
    for row in ROWS {
        for role in ROLES {
            probe::reset();
            let bytes = witness_bytes(role);
            let job = Job::spawn_observed(
                input(row, role, false),
                move || probe::arm_witness(bytes),
                observe_proof,
            )
            .expect("worker");
            let release_guard = probe::ReleaseGuard;
            assert!(probe::wait_for_witness());
            let control = job.cancellation();
            // A separate controller releases the barrier; Job's destructor itself
            // must cancel, join, and erase before this test observes completion.
            let observer = control.clone();
            let releaser = std::thread::spawn(move || {
                let started = std::time::Instant::now();
                while !observer.cancellation_requested() {
                    if started.elapsed() > std::time::Duration::from_secs(30) {
                        probe::release();
                        return false;
                    }
                    std::thread::yield_now();
                }
                probe::release();
                true
            });
            drop(job);
            drop(release_guard);
            assert!(
                releaser.join().expect("release thread"),
                "Drop did not cancel before joining"
            );
            assert_input_erased();
            probe::assert_erased(Buffer::Witness, bytes);
            probe::assert_erased(Buffer::Proof, row.proof_bytes(role));
            assert_eq!(control.cancel(), Cancellation::TooLate);
        }
    }
}

#[test]
fn ordinary_errors_do_not_publish_or_retain_secret_and_tape() {
    let _serial = probe::SERIAL.lock().expect("test lock");
    for row in ROWS {
        for role in ROLES {
            for cancelled in [false, true] {
                probe::reset();
                let job = Job::spawn_observed(input(row, role, true), || {}, observe_proof)
                    .expect("worker");
                if cancelled {
                    assert_eq!(job.cancellation().cancel(), Cancellation::Accepted);
                }
                match (cancelled, job.finish()) {
                    (false, Outcome::Failed(ProveError::WitnessRejected))
                    | (
                        true,
                        Outcome::Discarded(Computation::Failed(ProveError::WitnessRejected)),
                    ) => {}
                    _ => panic!("wrong ordinary failure"),
                }
                assert_input_erased();
                probe::assert_no_proof();
            }
        }
    }
}

#[test]
fn partial_entropy_fill_failure_erases_actual_owner_allocations() {
    let _serial = probe::SERIAL.lock().expect("test lock");
    probe::reset();
    assert!(
        CredentialSecret::fill_with(|destination| {
            destination[..17].fill(0xa5);
            probe::track(Buffer::Secret, destination);
            Err::<(), _>("entropy unavailable")
        })
        .is_err()
    );
    assert!(
        ProvingTape::fill_with(|destination| {
            destination[..53].fill(0x5a);
            probe::track(Buffer::Tape, destination);
            Err::<(), _>("entropy unavailable")
        })
        .is_err()
    );
    assert_input_erased();
    probe::assert_no_proof();
}

#[test]
fn publication_and_cancellation_race_has_one_consistent_winner() {
    let _serial = probe::SERIAL.lock().expect("test lock");
    for role in ROLES {
        probe::reset();
        let row = Row::Candidate;
        let mut job =
            Job::spawn_observed(input(row, role, false), || {}, observe_proof).expect("worker");
        assert_eq!(job.wait(), Computation::Proved);
        let control = job.cancellation();
        let barrier = Arc::new(Barrier::new(2));
        let other = Arc::clone(&barrier);
        let request = std::thread::spawn(move || {
            other.wait();
            control.cancel()
        });
        barrier.wait();
        let outcome = job.finish();
        match (request.join().expect("controller"), outcome) {
            (Cancellation::Accepted, Outcome::Discarded(Computation::Proved)) => {}
            (Cancellation::TooLate, Outcome::Published(proof)) => {
                assert_eq!(&**proof, &expected_proof(row, role));
                drop(proof);
            }
            _ => panic!("inconsistent publication decision"),
        }
        assert_input_erased();
        probe::assert_erased(Buffer::Proof, row.proof_bytes(role));
    }
}
