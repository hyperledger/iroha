//! Public-fixture demonstration of finish-and-discard cancellation. Never use
//! the deterministic fixture secret or tape for production proving. The worker
//! always runs one synchronous call; cancellation suppresses publication.

#[path = "../tests/common/mod.rs"]
mod common;
#[path = "prover_lifecycle/job.rs"]
mod job;

use iroha_parliament_ballot_proof::{
    credential::CredentialSecret,
    profile::{Role, Row},
    proving::ProvingTape,
};
use job::{Cancellation, Computation, Input, Job, Outcome, Statement};

#[derive(norito::json::JsonSerialize)]
struct Report<'a> {
    fixture_only: bool,
    profile_qualified: bool,
    backend: &'static str,
    row: &'a str,
    role: &'a str,
    mode: &'a str,
    outcome: &'a str,
    released_proof_bytes: usize,
    elapsed_ms: f64,
    cancellation_after_completion: String,
    stack_request_bytes: usize,
    whole_secret_erasure_qualified: bool,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.len() != 3 {
        return Err("usage: prover_lifecycle candidate|comparator registration|vote publish|cancel|cancel-after-wait|drop (public fixtures only)".into());
    }
    let row = match args[0].as_str() {
        "candidate" => Row::Candidate,
        "comparator" => Row::Comparator,
        _ => return Err("unknown row".into()),
    };
    let role = match args[1].as_str() {
        "registration" => Role::Registration,
        "vote" => Role::Vote,
        _ => return Err("unknown role".into()),
    };
    let mode = args[2].as_str();
    if !matches!(mode, "publish" | "cancel" | "cancel-after-wait" | "drop") {
        return Err("unknown lifecycle mode".into());
    }
    let (statement, secret, tape) = match role {
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
    let input = Input {
        row,
        statement,
        secret: CredentialSecret::from_bytes(&secret),
        tape: ProvingTape::from_bytes(&tape),
    };
    let started = std::time::Instant::now();
    let mut job = Job::spawn(input)?;
    let control = job.cancellation();
    if mode == "cancel-after-wait" && job.wait() != Computation::Proved {
        return Err("fixture did not prove".into());
    }
    if matches!(mode, "cancel" | "cancel-after-wait") && control.cancel() != Cancellation::Accepted
    {
        return Err("unpublished job did not accept cancellation".into());
    }
    let (outcome, bytes) = if mode == "drop" {
        drop(job);
        ("dropped_and_joined", 0)
    } else {
        match job.finish() {
            Outcome::Published(proof) => ("published", proof.len()),
            Outcome::Discarded(Computation::Proved) => ("proved_and_discarded", 0),
            Outcome::Discarded(status) => {
                return Err(format!("fixture discarded after {status:?}").into());
            }
            Outcome::Failed(error) => return Err(error.into()),
            Outcome::WorkerPanicked => return Err("worker did not join normally".into()),
        }
    };
    let report = Report {
        fixture_only: true,
        profile_qualified: false,
        backend: if cfg!(feature = "accel") {
            "accel"
        } else {
            "portable"
        },
        row: &args[0],
        role: &args[1],
        mode,
        outcome,
        released_proof_bytes: bytes,
        elapsed_ms: started.elapsed().as_secs_f64() * 1000.0,
        cancellation_after_completion: format!("{:?}", control.cancel()),
        stack_request_bytes: 8 * 1024 * 1024,
        whole_secret_erasure_qualified: false,
    };
    println!("{}", norito::json::to_json(&report)?);
    Ok(())
}
