//! Measurement of the two experimental ballot proofs: proof bytes, prove and
//! verify wall time and peak heap use, on both rows, for registration and for
//! votes over lists of 3, 500 and 1,000 entries.
//!
//! Run in release: `cargo run --release -p iroha_parliament_ballot_proof
//! --example measure [--features accel]`. The numbers describe the machine the
//! example runs on and nothing else; no row is selected or qualified. The tapes
//! are derived from a counter so that runs are reproducible, which is permitted
//! for measurement and tests only: a real prover takes fresh random bytes.

use std::{
    alloc::{GlobalAlloc, Layout, System},
    sync::atomic::{AtomicUsize, Ordering},
    time::{Duration, Instant},
};

use iroha_parliament_ballot_proof::{
    credential::{CredentialSecret, RegistrationContext, body_digest},
    framing::{BodyContext, Commitment, Digest64, FramingError, OpaqueField},
    profile::{Profile, Role, Row},
    proving::ProvingTape,
    registration::{self, RegistrationStatement},
    sealed_list::SealedList,
    vote::{self, Vote, VoteStatement},
};
use iroha_zkp_vole::{hash::Xof, params::SecurityLevel};

/// Proofs per table row.
const REPETITIONS: usize = 7;

/// The system allocator with a running and a peak byte count.
struct Counting;

static CURRENT: AtomicUsize = AtomicUsize::new(0);
static PEAK: AtomicUsize = AtomicUsize::new(0);

// The only unsafe code of this package: a global allocator cannot be written
// without it. It forwards every call to the system allocator unchanged and only
// counts bytes.
#[allow(unsafe_code)]
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        // SAFETY: the caller upholds the contract of `GlobalAlloc::alloc`, which
        // is forwarded unchanged.
        let pointer = unsafe { System.alloc(layout) };
        if !pointer.is_null() {
            let now = CURRENT.fetch_add(layout.size(), Ordering::Relaxed) + layout.size();
            PEAK.fetch_max(now, Ordering::Relaxed);
        }
        pointer
    }

    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        // SAFETY: the caller upholds the contract of `GlobalAlloc::dealloc`,
        // which is forwarded unchanged.
        unsafe { System.dealloc(pointer, layout) };
        CURRENT.fetch_sub(layout.size(), Ordering::Relaxed);
    }
}

#[global_allocator]
static ALLOCATOR: Counting = Counting;

/// Run `work` and return its result, its wall time and the peak heap growth
/// above the level at entry.
fn measured<T>(work: impl FnOnce() -> T) -> (T, Duration, usize) {
    let base = CURRENT.load(Ordering::Relaxed);
    PEAK.store(base, Ordering::Relaxed);
    let start = Instant::now();
    let result = work();
    let elapsed = start.elapsed();
    let peak = PEAK.load(Ordering::Relaxed).saturating_sub(base);
    (result, elapsed, peak)
}

/// SHAKE256 of a label: deterministic inputs for the measurement.
fn derive<const N: usize>(label: &str) -> [u8; N] {
    let mut xof = Xof::new(SecurityLevel::L256);
    xof.update(b"iroha_parliament_ballot_proof/measure/");
    xof.update(label.as_bytes());
    let mut out = [0u8; N];
    xof.finalize().squeeze(&mut out);
    out
}

fn tape(label: &str, repetition: usize) -> ProvingTape {
    ProvingTape::from_bytes(&derive(&format!("tape/{label}/{repetition}")))
}

fn member(index: usize) -> CredentialSecret {
    CredentialSecret::from_bytes(&derive(&format!("member/{index}")))
}

/// Minimum and median of a sample, in milliseconds.
fn summary(samples: &mut [Duration]) -> (f64, f64) {
    samples.sort_unstable();
    let millis = |duration: Duration| duration.as_secs_f64() * 1e3;
    (
        samples.first().copied().map_or(0.0, millis),
        samples.get(samples.len() / 2).copied().map_or(0.0, millis),
    )
}

/// A byte count as mebibytes with two decimals.
fn mebibytes(bytes: usize) -> String {
    let hundredths = bytes.saturating_mul(100) >> 20;
    format!("{}.{:02}", hundredths / 100, hundredths % 100)
}

/// One table row from `REPETITIONS` proofs.
fn report(
    row: Row,
    relation: &str,
    size: &str,
    mut prove: impl FnMut(usize) -> Vec<u8>,
    verify: impl Fn(&[u8]) -> bool,
) {
    let mut prove_times = Vec::new();
    let mut verify_times = Vec::new();
    let (mut prove_peak, mut verify_peak, mut bytes) = (0usize, 0usize, 0usize);
    for repetition in 0..REPETITIONS {
        let (proof, elapsed, peak) = measured(|| prove(repetition));
        prove_times.push(elapsed);
        prove_peak = prove_peak.max(peak);
        bytes = proof.len();
        let (accepted, elapsed, peak) = measured(|| verify(&proof));
        assert!(accepted, "an honest proof must verify");
        verify_times.push(elapsed);
        verify_peak = verify_peak.max(peak);
    }
    let (prove_min, prove_median) = summary(&mut prove_times);
    let (verify_min, verify_median) = summary(&mut verify_times);
    println!(
        "{:<10} {:<12} {:>5} {:>9} {:>10.1} {:>10.1} {:>10.1} {:>10.1} {:>11} {:>11}",
        match row {
            Row::Candidate => "candidate",
            Row::Comparator => "comparator",
        },
        relation,
        size,
        bytes,
        prove_min,
        prove_median,
        verify_min,
        verify_median,
        mebibytes(prove_peak),
        mebibytes(verify_peak),
    );
}

fn opaque(text: &str) -> Result<OpaqueField, FramingError> {
    OpaqueField::new(text.as_bytes())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!(
        "EXPERIMENTAL ballot proofs: no row is selected or qualified. {REPETITIONS} proofs per \
         line, one thread, accel feature {}, build profile: {}.",
        if cfg!(feature = "accel") { "on" } else { "off" },
        if cfg!(debug_assertions) {
            "DEBUG BUILD: timings are not meaningful"
        } else {
            "release"
        }
    );
    println!("Measured on the machine running this example; not a validator or phone baseline.");
    println!(
        "Heap is incremental requested allocation above entry: excludes existing inputs, stack, allocator overhead and RSS."
    );
    println!(
        "Verification starts from decoded statements; no fresh wire decoding, cold-process or late-invalid-input qualification."
    );
    println!(
        "{:<10} {:<12} {:>5} {:>9} {:>10} {:>10} {:>10} {:>10} {:>11} {:>11}",
        "row",
        "relation",
        "S",
        "proof B",
        "prove min",
        "prove med",
        "verify min",
        "verify med",
        "prove heap",
        "verify heap"
    );
    println!(
        "{:<10} {:<12} {:>5} {:>9} {:>10} {:>10} {:>10} {:>10} {:>11} {:>11}",
        "", "", "", "", "ms", "ms", "ms", "ms", "MiB peak", "MiB peak"
    );
    let body_context = BodyContext::new(b"measure: body context")?;
    let body = body_digest(&body_context)?;
    let scope = Digest64(derive("scope"));
    let policy = Digest64(derive("policy"));
    for row in Row::ALL {
        let profile = Profile::new(row)?;
        let voter = member(0);
        let statement = RegistrationStatement::for_secret(
            &profile,
            &voter,
            body_context.clone(),
            RegistrationContext {
                network_id: opaque("measure: network")?,
                authority: opaque("measure: authority")?,
                assignment_id: opaque("measure: assignment")?,
                governance_attempt_id: opaque("measure: governance attempt")?,
                election_attempt_id: opaque("measure: election attempt")?,
                body_role: opaque("measure: role")?,
            },
        )?;
        assert_eq!(
            profile.proof_bytes(Role::Registration),
            row.proof_bytes(Role::Registration)
        );
        report(
            row,
            "registration",
            "-",
            |repetition| {
                registration::prove(row, &statement, &voter, tape("reg", repetition))
                    .expect("honest measurement proof")
            },
            |proof| registration::verify(row, &statement, proof).is_ok(),
        );
        for size in [3usize, 500, 1000] {
            let entries: Vec<Commitment> = (0..size)
                .map(|index| member(index).commitment(&body))
                .collect();
            let list = SealedList::from_unsorted(entries)?;
            let position = list
                .position(&voter.commitment(&body))
                .ok_or("the voter is a member")?;
            let statement =
                VoteStatement::for_secret(&profile, &voter, body, scope, &list, Vote::Aye, policy)?;
            report(
                row,
                "vote",
                &size.to_string(),
                |repetition| {
                    vote::prove(
                        row,
                        &statement,
                        &voter,
                        position,
                        tape(&format!("vote/{size}"), repetition),
                    )
                    .expect("honest measurement proof")
                },
                |proof| vote::verify(row, &statement, proof).is_ok(),
            );
        }
    }
    Ok(())
}
