//! Callable resource-observation runner. This module installs a Rust counting
//! allocator and can be included by a temporary device harness. It never selects
//! or qualifies a profile and never introduces a production record schema.
//!
//! Calls must be serialized: the allocator counters are process-wide. Foreign
//! allocators, including Objective-C allocations, are outside these counters.

pub mod malformed;

use std::{
    alloc::{GlobalAlloc, Layout, System},
    error::Error,
    io::Write,
    sync::atomic::{AtomicUsize, Ordering},
    time::Instant,
};

use iroha_parliament_ballot_proof::{
    credential::{CredentialSecret, RegistrationContext, body_digest},
    framing::{BODY_CONTEXT_MAX_BYTES, BodyContext, Digest64, OPAQUE_FIELD_MAX_BYTES, OpaqueField},
    profile::{Profile, ProofField, Role, Row},
    proving::{ProveError, ProvingTape, VerifyError},
    registration::{self, RegistrationRelation, RegistrationStatement},
    sealed_list::SealedList,
    test_codec,
    vote::{self, Vote, VoteRelation, VoteStatement},
};
use iroha_zkp_vole::{
    field::Gf256,
    hash::Xof,
    params::SecurityLevel,
    proof::{self, ProofError},
};
use norito::json::JsonSerialize;

struct Counting;
static LIVE: AtomicUsize = AtomicUsize::new(0);
static PEAK: AtomicUsize = AtomicUsize::new(0);
static ALLOCATIONS: AtomicUsize = AtomicUsize::new(0);
static ALLOCATED_BYTES: AtomicUsize = AtomicUsize::new(0);

// The allocator forwards the caller's layout and pointer to System unchanged.
// GlobalAlloc's default realloc/alloc_zeroed call these methods, so their
// requested allocations are counted too, including transient realloc copies.
#[allow(unsafe_code)]
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        // SAFETY: the caller's GlobalAlloc contract is forwarded unchanged.
        let pointer = unsafe { System.alloc(layout) };
        if !pointer.is_null() {
            let live = LIVE.fetch_add(layout.size(), Ordering::Relaxed) + layout.size();
            PEAK.fetch_max(live, Ordering::Relaxed);
            ALLOCATIONS.fetch_add(1, Ordering::Relaxed);
            ALLOCATED_BYTES.fetch_add(layout.size(), Ordering::Relaxed);
        }
        pointer
    }

    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        // SAFETY: the caller's GlobalAlloc contract is forwarded unchanged.
        unsafe { System.dealloc(pointer, layout) };
        LIVE.fetch_sub(layout.size(), Ordering::Relaxed);
    }
}

#[global_allocator]
static ALLOCATOR: Counting = Counting;

type Result<T> = std::result::Result<T, Box<dyn Error>>;

const HELP: &str = "Experimental ballot resource observations (Norito JSON lines).\n\
Usage: qualify [--samples 1..1001] [--row all|candidate|comparator]\n\
               [--case all|registration|vote3|vote500|vote1000]\n\
               [--source-id MANIFEST_SHA256] [--run-id LABEL]\n\
Default: 31 fresh proofs per case, both rows, all four cases.\n\
No production Norito mapping or hardware qualification is established.\n";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Case {
    Registration,
    Vote(usize),
}

impl Case {
    const ALL: [Self; 4] = [
        Self::Registration,
        Self::Vote(3),
        Self::Vote(500),
        Self::Vote(1000),
    ];

    fn name(self) -> &'static str {
        match self {
            Self::Registration => "registration",
            Self::Vote(3) => "vote3",
            Self::Vote(500) => "vote500",
            Self::Vote(1000) => "vote1000",
            Self::Vote(_) => unreachable!("only the four fixed cases are constructed"),
        }
    }

    fn role(self) -> Role {
        match self {
            Self::Registration => Role::Registration,
            Self::Vote(_) => Role::Vote,
        }
    }

    fn seats(self) -> usize {
        match self {
            Self::Registration => 0,
            Self::Vote(seats) => seats,
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
struct Options {
    samples: usize,
    rows: Vec<Row>,
    cases: Vec<Case>,
    source_id: String,
    run_id: String,
}

fn options(arguments: &[String]) -> Result<Option<Options>> {
    let mut result = Options {
        samples: 31,
        rows: Row::ALL.to_vec(),
        cases: Case::ALL.to_vec(),
        source_id: "unrecorded".to_owned(),
        run_id: "unspecified".to_owned(),
    };
    let mut args = arguments.iter();
    while let Some(flag) = args.next() {
        if flag == "--help" || flag == "-h" {
            return Ok(None);
        }
        let value = args
            .next()
            .ok_or_else(|| format!("missing value for {flag}"))?;
        match flag.as_str() {
            "--samples" => {
                result.samples = value.parse()?;
                if !(1..=1001).contains(&result.samples) {
                    return Err("--samples must be in 1..=1001".into());
                }
            }
            "--row" => {
                result.rows = match value.as_str() {
                    "all" => Row::ALL.to_vec(),
                    "candidate" => vec![Row::Candidate],
                    "comparator" => vec![Row::Comparator],
                    _ => return Err("--row must be all, candidate or comparator".into()),
                };
            }
            "--case" => {
                result.cases = match value.as_str() {
                    "all" => Case::ALL.to_vec(),
                    "registration" => vec![Case::Registration],
                    "vote3" => vec![Case::Vote(3)],
                    "vote500" => vec![Case::Vote(500)],
                    "vote1000" => vec![Case::Vote(1000)],
                    _ => {
                        return Err(
                            "--case must be all, registration, vote3, vote500 or vote1000".into(),
                        );
                    }
                };
            }
            "--source-id" => result.source_id.clone_from(value),
            "--run-id" => result.run_id.clone_from(value),
            _ => return Err(format!("unknown option {flag}").into()),
        }
    }
    Ok(Some(result))
}

fn row_name(row: Row) -> &'static str {
    match row {
        Row::Candidate => "candidate",
        Row::Comparator => "comparator",
    }
}

#[derive(Debug, Clone, Copy, JsonSerialize)]
struct Metric {
    elapsed_ns: u64,
    live_at_entry_bytes: usize,
    live_at_exit_bytes: usize,
    total_peak_live_bytes: usize,
    incremental_peak_bytes: usize,
    allocation_calls: usize,
    allocated_bytes: usize,
}

fn measured<T>(work: impl FnOnce() -> T) -> (T, Metric) {
    let base = LIVE.load(Ordering::Relaxed);
    let allocations = ALLOCATIONS.load(Ordering::Relaxed);
    let allocated_bytes = ALLOCATED_BYTES.load(Ordering::Relaxed);
    PEAK.store(base, Ordering::Relaxed);
    let start = Instant::now();
    let result = work();
    let elapsed = start.elapsed();
    let peak = PEAK.load(Ordering::Relaxed);
    let metric = Metric {
        elapsed_ns: u64::try_from(elapsed.as_nanos()).unwrap_or(u64::MAX),
        live_at_entry_bytes: base,
        live_at_exit_bytes: LIVE.load(Ordering::Relaxed),
        total_peak_live_bytes: peak,
        incremental_peak_bytes: peak.saturating_sub(base),
        allocation_calls: ALLOCATIONS
            .load(Ordering::Relaxed)
            .saturating_sub(allocations),
        allocated_bytes: ALLOCATED_BYTES
            .load(Ordering::Relaxed)
            .saturating_sub(allocated_bytes),
    };
    (result, metric)
}

#[derive(Debug, Clone, Copy, JsonSerialize)]
struct Phase {
    name: &'static str,
    metric: Metric,
}

#[derive(Debug, JsonSerialize)]
struct Observation {
    kind: &'static str,
    row: &'static str,
    case: &'static str,
    sample_index: usize,
    proof_bytes: usize,
    proof_shake256_32: String,
    seats: usize,
    honest_result: &'static str,
    statement_bytes: usize,
    test_record_bytes: usize,
    retry_counter: u32,
    challenge_attempts: u32,
    late_invalid_result: &'static str,
    late_invalid_backend_diagnostic: &'static str,
    phases: Vec<Phase>,
}

#[derive(Debug, JsonSerialize)]
struct Distribution {
    count: usize,
    min: u64,
    median: u64,
    p95: u64,
    max: u64,
}

fn distribution(mut values: Vec<u64>) -> Distribution {
    assert!(!values.is_empty(), "a distribution has at least one sample");
    values.sort_unstable();
    let n = values.len();
    // Nearest rank: rank ceil(p*n), one-based. Median uses the same rule.
    Distribution {
        count: n,
        min: values[0],
        median: values[n.div_ceil(2) - 1],
        p95: values[(95 * n).div_ceil(100) - 1],
        max: values[n - 1],
    }
}

#[derive(Debug, JsonSerialize)]
struct PhaseSummary {
    name: &'static str,
    elapsed_ns: Distribution,
    total_peak_live_bytes: Distribution,
    incremental_peak_bytes: Distribution,
    live_at_entry_bytes: Distribution,
    allocation_calls: Distribution,
    allocated_bytes: Distribution,
}

#[derive(Debug, JsonSerialize)]
struct Summary {
    kind: &'static str,
    row: &'static str,
    case: &'static str,
    samples_completed: usize,
    retry_counter: Distribution,
    challenge_attempts: Distribution,
    phases: Vec<PhaseSummary>,
}

fn summarize(row: Row, case: Case, samples: &[Observation]) -> Summary {
    let phases = samples[0]
        .phases
        .iter()
        .enumerate()
        .map(|(index, phase)| {
            let collect = |field: fn(&Metric) -> usize| {
                distribution(
                    samples
                        .iter()
                        .map(|s| u64::try_from(field(&s.phases[index].metric)).unwrap_or(u64::MAX))
                        .collect(),
                )
            };
            PhaseSummary {
                name: phase.name,
                elapsed_ns: distribution(
                    samples
                        .iter()
                        .map(|s| s.phases[index].metric.elapsed_ns)
                        .collect(),
                ),
                total_peak_live_bytes: collect(|m| m.total_peak_live_bytes),
                incremental_peak_bytes: collect(|m| m.incremental_peak_bytes),
                live_at_entry_bytes: collect(|m| m.live_at_entry_bytes),
                allocation_calls: collect(|m| m.allocation_calls),
                allocated_bytes: collect(|m| m.allocated_bytes),
            }
        })
        .collect();
    Summary {
        kind: "case_summary",
        row: row_name(row),
        case: case.name(),
        samples_completed: samples.len(),
        retry_counter: distribution(samples.iter().map(|s| u64::from(s.retry_counter)).collect()),
        challenge_attempts: distribution(
            samples
                .iter()
                .map(|s| u64::from(s.challenge_attempts))
                .collect(),
        ),
        phases,
    }
}

fn emit(output: &mut impl Write, value: &impl JsonSerialize) -> Result<()> {
    let line = norito::json::to_json(value)?;
    output.write_all(line.as_bytes())?;
    output.write_all(b"\n")?;
    output.flush()?;
    Ok(())
}

fn derive<const N: usize>(label: &str) -> [u8; N] {
    let mut xof = Xof::new(SecurityLevel::L256);
    xof.update(b"iroha_parliament_ballot_proof/qualification/b6/");
    xof.update(label.as_bytes());
    let mut out = [0u8; N];
    xof.finalize().squeeze(&mut out);
    out
}

fn proof_digest(bytes: &[u8]) -> String {
    let mut xof = Xof::new(SecurityLevel::L256);
    xof.update(bytes);
    let mut digest = [0u8; 32];
    xof.finalize().squeeze(&mut digest);
    let alphabet = b"0123456789abcdef";
    digest
        .iter()
        .flat_map(|byte| {
            [
                char::from(alphabet[usize::from(byte >> 4)]),
                char::from(alphabet[usize::from(byte & 15)]),
            ]
        })
        .collect()
}

fn member(index: usize) -> CredentialSecret {
    CredentialSecret::from_bytes(&derive(&format!("member/{index}")))
}

enum Statement {
    Registration(Box<RegistrationStatement>),
    Vote(Box<VoteStatement>),
}

impl Statement {
    fn encode(&self, profile: &Profile) -> Result<Vec<u8>> {
        Ok(match self {
            Self::Registration(s) => test_codec::encode_registration(profile, s)?,
            Self::Vote(s) => test_codec::encode_vote(profile, s)?,
        })
    }

    fn decode(profile: &Profile, role: Role, bytes: &[u8]) -> Result<Self> {
        Ok(match role {
            Role::Registration => {
                Self::Registration(Box::new(test_codec::decode_registration(profile, bytes)?))
            }
            Role::Vote => Self::Vote(Box::new(test_codec::decode_vote(profile, bytes)?)),
        })
    }

    fn verify(&self, row: Row, proof: &[u8]) -> std::result::Result<(), VerifyError> {
        match self {
            Self::Registration(s) => registration::verify(row, s, proof),
            Self::Vote(s) => vote::verify(row, s, proof),
        }
    }

    fn prove(
        &self,
        row: Row,
        secret: &CredentialSecret,
        position: u16,
        tape: ProvingTape,
    ) -> std::result::Result<Vec<u8>, ProveError> {
        match self {
            Self::Registration(s) => registration::prove(row, s, secret, tape),
            Self::Vote(s) => vote::prove(row, s, secret, position, tape),
        }
    }

    // Diagnostic only; the timed late-invalid phase uses the public verifier.
    fn backend_diagnostic(&self, profile: &Profile, bytes: &[u8]) -> Result<ProofError> {
        let result = match self {
            Self::Registration(s) => {
                let instance = s.instance(profile)?;
                proof::verify::<Gf256, _>(
                    &profile.context(Role::Registration)?,
                    &RegistrationRelation,
                    instance.public(),
                    instance.mu(),
                    bytes,
                )
            }
            Self::Vote(s) => {
                let instance = s.instance(profile)?;
                proof::verify::<Gf256, _>(
                    &profile.context(Role::Vote)?,
                    &VoteRelation,
                    instance.public(),
                    instance.mu(),
                    bytes,
                )
            }
        };
        result
            .err()
            .ok_or_else(|| "late-invalid proof unexpectedly accepted by backend".into())
    }
}

struct Prepared {
    profile: Profile,
    secret: CredentialSecret,
    statement: Statement,
    position: u16,
}

fn prepare(row: Row, case: Case) -> Result<Prepared> {
    let profile = Profile::new(row)?;
    let secret = member(0);
    let body_context = BodyContext::new(&derive::<BODY_CONTEXT_MAX_BYTES>("maximum/body"))?;
    let body = body_digest(&body_context)?;
    let (statement, position) = match case {
        Case::Registration => {
            let opaque = |label: &str| OpaqueField::new(&derive::<OPAQUE_FIELD_MAX_BYTES>(label));
            let statement = RegistrationStatement::for_secret(
                &profile,
                &secret,
                body_context,
                RegistrationContext {
                    network_id: opaque("maximum/network")?,
                    authority: opaque("maximum/authority")?,
                    assignment_id: opaque("maximum/assignment")?,
                    governance_attempt_id: opaque("maximum/governance")?,
                    election_attempt_id: opaque("maximum/election")?,
                    body_role: opaque("maximum/role")?,
                },
            )?;
            (Statement::Registration(Box::new(statement)), 0)
        }
        Case::Vote(seats) => {
            let list = SealedList::from_unsorted(
                (0..seats).map(|i| member(i).commitment(&body)).collect(),
            )?;
            let position = list
                .position(&secret.commitment(&body))
                .ok_or("voter missing from list")?;
            let statement = VoteStatement::for_secret(
                &profile,
                &secret,
                body,
                Digest64(derive("scope")),
                &list,
                Vote::Aye,
                Digest64(derive("policy")),
            )?;
            (Statement::Vote(Box::new(statement)), position)
        }
    };
    Ok(Prepared {
        profile,
        secret,
        statement,
        position,
    })
}

fn field_offset(row: Row, role: Role, field: ProofField) -> usize {
    row.proof_layout(role)
        .iter()
        .find(|segment| segment.field == field)
        .expect("frozen layout contains every field")
        .offset
}

fn counter(row: Row, role: Role, bytes: &[u8]) -> Result<u32> {
    if bytes.len() != row.proof_bytes(role) {
        return Err("counter extraction requires exact proof length".into());
    }
    let start = field_offset(row, role, ProofField::Counter);
    let value = u32::from_le_bytes(bytes[start..start + 4].try_into()?);
    if value > 0x000f_ffff {
        return Err("counter exceeds the frozen retry limit".into());
    }
    Ok(value)
}

fn decode_record(row: Row, case: Case, record: &[u8]) -> Result<(Statement, &[u8])> {
    let profile = Profile::new(row)?;
    let (statement, proof) = test_codec::decode_record(&profile, case.role(), record)?;
    Ok((Statement::decode(&profile, case.role(), statement)?, proof))
}

fn cold_verify(
    row: Row,
    case: Case,
    record: &[u8],
) -> Result<std::result::Result<(), VerifyError>> {
    let (statement, proof) = decode_record(row, case, record)?;
    Ok(statement.verify(row, proof))
}

fn sample(row: Row, case: Case, index: usize) -> Result<Observation> {
    // Reserve the result storage before phases so vector growth cannot pollute a phase.
    let mut phases = Vec::with_capacity(7);
    let (prepared, metric) = measured(|| prepare(row, case));
    phases.push(Phase {
        name: "input_setup",
        metric,
    });
    let prepared = prepared?;
    let (proof, metric) = measured(|| {
        let tape = ProvingTape::from_bytes(&derive(&format!(
            "tape/{}/{}/{index}",
            row_name(row),
            case.name()
        )));
        prepared
            .statement
            .prove(row, &prepared.secret, prepared.position, tape)
    });
    phases.push(Phase {
        name: "prove",
        metric,
    });
    let proof = proof.map_err(|error| format!("prove: {error:?}"))?;
    let proof_shake256_32 = proof_digest(&proof);
    let retry_counter = counter(row, case.role(), &proof)?;
    let proof_bytes = proof.len();
    let (encoded, metric) = measured(|| -> Result<_> {
        let encoded = prepared.statement.encode(&prepared.profile)?;
        let statement_bytes = encoded.len();
        Ok((
            test_codec::encode_record(&encoded, &proof)?,
            statement_bytes,
        ))
    });
    phases.push(Phase {
        name: "test_record_encode",
        metric,
    });
    let (mut record, statement_bytes) = encoded?;
    // Cold-input verification retains only the encoded record, not the prover's
    // secret, typed statement, profile or separate proof buffer.
    drop(proof);
    drop(prepared);
    let (accepted, metric) = measured(|| cold_verify(row, case, &record));
    phases.push(Phase {
        name: "cold_input_valid",
        metric,
    });
    accepted?.map_err(|error| format!("cold_input_valid: {error:?}"))?;
    let (decoded, metric) = measured(|| decode_record(row, case, &record));
    phases.push(Phase {
        name: "decode_only",
        metric,
    });
    let (statement, proof) = decoded?;
    let (accepted, metric) = measured(|| statement.verify(row, proof));
    phases.push(Phase {
        name: "warm_valid",
        metric,
    });
    accepted.map_err(|error| format!("warm_valid: {error:?}"))?;
    drop(statement);
    // Corrupt one canonical GF(2^256) coefficient. The record size, counter,
    // opening and field encoding remain well formed; final challenge fails.
    let proof_start = 8 + statement_bytes;
    record[proof_start + field_offset(row, case.role(), ProofField::Coefficients)] ^= 1;
    let (rejected, metric) = measured(|| cold_verify(row, case, &record));
    phases.push(Phase {
        name: "cold_input_late_invalid",
        metric,
    });
    if rejected? != Err(VerifyError::Rejected) {
        return Err("late-invalid public verifier did not return VerifyError::Rejected".into());
    }
    // Establish the precise late failure on the first fresh proof of each case.
    // This extra diagnostic is outside every timed phase and is explicit below.
    let diagnostic = if index == 0 {
        let profile = Profile::new(row)?;
        let (statement, proof) = decode_record(row, case, &record)?;
        let actual = statement.backend_diagnostic(&profile, proof)?;
        if actual != ProofError::ChallengeMismatch {
            return Err(format!(
                "late-invalid backend diagnostic: expected ChallengeMismatch, got {actual:?}"
            )
            .into());
        }
        "ProofError::ChallengeMismatch (untimed, this sample)"
    } else {
        "not rerun; mutation classified on sample 0"
    };
    Ok(Observation {
        kind: "sample",
        row: row_name(row),
        case: case.name(),
        sample_index: index,
        proof_bytes,
        proof_shake256_32,
        seats: case.seats(),
        honest_result: "Ok(())",
        statement_bytes,
        test_record_bytes: record.len(),
        retry_counter,
        challenge_attempts: retry_counter + 1,
        late_invalid_result: "VerifyError::Rejected",
        late_invalid_backend_diagnostic: diagnostic,
        phases,
    })
}

// This immutable report records independent build facts and explicit gates;
// these flags are not mutable state-machine state.
#[allow(clippy::struct_excessive_bools)]
#[derive(JsonSerialize)]
struct Header<'a> {
    kind: &'static str,
    schema: &'static str,
    source_id: &'a str,
    run_id: &'a str,
    accel_feature: bool,
    debug_assertions: bool,
    target_arch: &'static str,
    target_os: &'static str,
    samples_per_case: usize,
    rows: Vec<&'static str>,
    cases: Vec<&'static str>,
    profile_qualified: bool,
    production_norito_mapping: bool,
    hardware_qualification: bool,
    body_context_bytes: usize,
    registration_opaque_field_count: usize,
    registration_opaque_field_bytes: usize,
    method: Vec<&'static str>,
}

#[derive(JsonSerialize)]
struct Failure<'a> {
    kind: &'static str,
    row: &'static str,
    case: &'static str,
    sample_index: usize,
    error: &'a str,
    profile_qualified: bool,
}

#[derive(JsonSerialize)]
struct Complete {
    kind: &'static str,
    profile_qualified: bool,
}

/// Run the selected cases, flushing a Norito JSON line after every sample and
/// case summary. Arguments exclude the executable name; `--help` writes text.
///
/// This entry point does not access environment variables or files. A temporary
/// device wrapper can call it off its UI thread with its own `Write` sink. Calls
/// must be serialized because the module's Rust allocator counters are global.
/// The wrapper must enable its `accel` feature when forwarding backend accel so
/// the report's feature label agrees with the compiled backend.
///
/// # Errors
/// Returns invalid-option, setup, prover, verifier, encoding or output errors.
/// It emits an error record with the row/case/sample context before returning
/// a sample failure; previously flushed observations remain available.
pub fn run(arguments: &[String], output: &mut impl Write) -> Result<()> {
    let Some(options) = options(arguments)? else {
        output.write_all(HELP.as_bytes())?;
        output.flush()?;
        return Ok(());
    };
    emit(
        output,
        &Header {
            kind: "run_header",
            schema: "parliament-ballot-resource-observations-b6-v1",
            source_id: &options.source_id,
            run_id: &options.run_id,
            accel_feature: cfg!(feature = "accel"),
            debug_assertions: cfg!(debug_assertions),
            target_arch: std::env::consts::ARCH,
            target_os: std::env::consts::OS,
            samples_per_case: options.samples,
            rows: options.rows.iter().map(|row| row_name(*row)).collect(),
            cases: options.cases.iter().map(|case| case.name()).collect(),
            profile_qualified: false,
            production_norito_mapping: false,
            hardware_qualification: false,
            body_context_bytes: BODY_CONTEXT_MAX_BYTES,
            registration_opaque_field_count: 6,
            registration_opaque_field_bytes: OPAQUE_FIELD_MAX_BYTES,
            method: vec![
                "Each sample proves once using a distinct deterministic tape; these tapes are test-only, never production randomness.",
                "Input setup includes profile, maximum registration fields or bounded sealed list, credential and statement; encoding is separate.",
                "Cold-input valid/invalid phases begin with one retained test-codec record; fresh descriptor, statement/list decode, public digest validation, context, relation and transcript verification run inside the phase.",
                "Warm verification retains the encoded record and decoded statement but recomputes context, digests and transcript through the ordinary public verifier.",
                "Late invalid flips the first coefficient byte; sample 0 separately confirms backend ChallengeMismatch outside timed phases; every sample checks public Rejected.",
                "Heap is requested live bytes through this Rust global allocator, including retained input and harness buffers; entry/exit, absolute peak, incremental peak and allocation traffic are reported.",
                "Stack, allocator metadata/fragmentation, native/Objective-C heaps, GPU memory and RSS are excluded. Rust allocations on other concurrent threads can contaminate counters.",
                "Default allocator realloc uses allocate-copy-free under instrumentation; its transient requested-byte peak is included.",
                "No cold process/cache, operating-system isolation, production Norito envelope, production adapter, power or hardware qualification is established.",
                "Observations execute setup, prove, encode, cold valid, decode, warm valid, cold late invalid in that fixed order; caches and thermal state carry across phases.",
                "The harness retains prior sample metrics until case summary; absolute heap includes this bounded bookkeeping. JSON formatting/output is outside measured phases.",
                "p95 and median use nearest rank ceil(p*n); small-sample p95 is descriptive only. Retry counter counts failed challenges, attempts=counter+1.",
            ],
        },
    )?;
    for &row in &options.rows {
        for &case in &options.cases {
            let mut samples = Vec::with_capacity(options.samples);
            for index in 0..options.samples {
                match sample(row, case, index) {
                    Ok(sample) => {
                        emit(output, &sample)?;
                        samples.push(sample);
                    }
                    Err(error) => {
                        emit(
                            output,
                            &Failure {
                                kind: "sample_error",
                                row: row_name(row),
                                case: case.name(),
                                sample_index: index,
                                error: &error.to_string(),
                                profile_qualified: false,
                            },
                        )?;
                        return Err(error);
                    }
                }
            }
            emit(output, &summarize(row, case, &samples))?;
        }
    }
    emit(
        output,
        &Complete {
            kind: "run_complete",
            profile_qualified: false,
        },
    )
}

#[cfg(test)]
mod tests;
