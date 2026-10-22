//! Explicitly ignored real-family comparison; compiled only for unit tests.
//! No advice or original artifact is written. RSS is a lifetime high-water mark.

use std::time::Instant;

use ff::PrimeField;
use iroha_measurement::probe::{
    InstructionProbeError, ProcessInstructionSnapshot, ProcessSnapshot,
};
use iroha_pasta::{PastaCurve, msm::MemoryBudget, poseidon::PoseidonField};
use iroha_plonk::{
    ProverConfig, ProverRandomness, Witness, create_proof_owned_with_claim,
    frontend::Circuit,
    keys::{CosetCachePolicy, ProvingKey, SourceBoundViewV2, keygen_pk_from_vk_v2_cancellable},
    pcs::ipa::PinnedParams,
    prover::rebuild_key_and_witness_v2_cancellable,
    verifier::verify_full_opening_cancellable,
};
use sha2::{Digest, Sha256};

// Instruction counts are an optional diagnostic, never a proof verdict. Keep
// incomplete cuts typed and separate from a completed numeric observation.
enum InstructionObservation {
    Complete {
        process_id: u32,
        process_start_abstime: u64,
        before: u64,
        after: u64,
        delta: u64,
    },
    Unavailable {
        before: Option<InstructionProbeError>,
        after: Option<InstructionProbeError>,
        delta: Option<InstructionProbeError>,
    },
}

impl InstructionObservation {
    fn from_captures(
        before: Result<ProcessInstructionSnapshot, InstructionProbeError>,
        after: Result<ProcessInstructionSnapshot, InstructionProbeError>,
    ) -> Self {
        match (before, after) {
            (Ok(before), Ok(after)) => {
                let values = (
                    before.process_id(),
                    before.process_start_abstime(),
                    before.instructions(),
                    after.instructions(),
                );
                match after.instructions_since(before) {
                    Ok(delta) => Self::Complete {
                        process_id: values.0,
                        process_start_abstime: values.1,
                        before: values.2,
                        after: values.3,
                        delta,
                    },
                    Err(error) => Self::Unavailable {
                        before: None,
                        after: None,
                        delta: Some(error),
                    },
                }
            }
            (before, after) => Self::Unavailable {
                before: before.err(),
                after: after.err(),
                delta: None,
            },
        }
    }

    fn marker_fields(&self) -> String {
        match self {
            Self::Complete {
                process_id,
                process_start_abstime,
                before,
                after,
                delta,
            } => format!(
                "status=available process_id={process_id} process_start_abstime={process_start_abstime} instructions_before={before} instructions_after={after} instructions_delta={delta}"
            ),
            Self::Unavailable {
                before,
                after,
                delta,
            } => {
                let capture_status = |error: &Option<InstructionProbeError>| {
                    error.as_ref().map_or("available", |error| error.code())
                };
                let delta_status = delta.as_ref().map_or("not_computed", |error| error.code());
                format!(
                    "status=unavailable before={} after={} delta={delta_status} numeric_sample=false",
                    capture_status(before),
                    capture_status(after),
                )
            }
        }
    }
}

#[test]
fn instruction_marker_preserves_availability_without_numeric_substitutes() {
    let unavailable = InstructionObservation::from_captures(
        Err(InstructionProbeError::Unsupported),
        Err(InstructionProbeError::Unsupported),
    )
    .marker_fields();
    assert!(unavailable.starts_with("status=unavailable "));
    assert!(unavailable.contains("numeric_sample=false"));
    assert!(!unavailable.contains("instructions_"));
    assert!(!unavailable.contains("process_start_abstime="));

    // Successful captures can still yield an invalid cut: no numeric fallback.
    let invalid = InstructionObservation::Unavailable {
        before: None,
        after: None,
        delta: Some(InstructionProbeError::CounterWentBackwards),
    }
    .marker_fields();
    assert!(invalid.contains("before=available after=available"));
    assert!(invalid.contains("numeric_sample=false"));
    assert!(!invalid.contains("instructions_"));

    let complete = InstructionObservation::Complete {
        process_id: 17,
        process_start_abstime: 29,
        before: 101,
        after: 157,
        delta: 56,
    }
    .marker_fields();
    assert_eq!(
        complete,
        "status=available process_id=17 process_start_abstime=29 instructions_before=101 instructions_after=157 instructions_delta=56"
    );
}

#[derive(Debug, PartialEq, Eq)]
struct PublicKeyIdentity {
    artifact: Vec<u8>,
    descriptor: Vec<u8>,
    copy_digest: [u8; 32],
    polynomial_digest: [u8; 32],
}

fn hash_column<F: PrimeField>(hash: &mut Sha256, column: &[F]) {
    hash.update(u64::try_from(column.len()).unwrap().to_le_bytes());
    for value in column {
        hash.update(value.to_repr().as_ref());
    }
}

// Only public fixed/selector/permutation/mask material is hashed. Lengths bind
// each group and column; this observation does not replace source admission.
fn key_identity<C: PastaCurve>(key: &ProvingKey<C>) -> PublicKeyIdentity {
    assert!(!key.has_coset_cache());
    let mut hash = Sha256::new();
    for columns in [
        key.fixed_values(),
        key.fixed_polys(),
        key.selector_values(),
        key.permutation_values(),
        key.permutation_polys(),
    ] {
        hash.update(u64::try_from(columns.len()).unwrap().to_le_bytes());
        for column in columns {
            hash_column(&mut hash, column);
        }
    }
    for (first, last, active) in [key.mask_values(), key.mask_polys()] {
        hash_column(&mut hash, first);
        hash_column(&mut hash, last);
        hash_column(&mut hash, active);
    }
    PublicKeyIdentity {
        artifact: key.artifact_bytes_v2().unwrap(),
        descriptor: key.binding().encoded().to_vec(),
        copy_digest: *key.copy_digest(),
        polynomial_digest: hash.finalize().into(),
    }
}

/// Explicit cfg(test) workload selection; no production caller reads these
/// settings. An absent selection keeps the existing single-pair diagnostic.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct RepeatSchedule {
    measured_pairs: usize,
    separate_first: bool,
}

impl RepeatSchedule {
    fn parse(pairs: Option<&str>, first: Option<&str>) -> Result<Option<Self>, &'static str> {
        let (pairs, first) = match (pairs, first) {
            (None, None) => return Ok(None),
            (Some(pairs), Some(first)) => (pairs, first),
            _ => return Err("set both IROHA_FUSED_REPEAT_PAIRS and IROHA_FUSED_REPEAT_FIRST"),
        };
        let measured_pairs = pairs
            .parse::<usize>()
            .map_err(|_| "expected integer pairs")?;
        if !(2..=16).contains(&measured_pairs) || measured_pairs % 2 != 0 {
            return Err("repeat pairs must be even and within 2..=16");
        }
        let separate_first = match first {
            "separate" => true,
            "fused" => false,
            _ => return Err("first must be separate or fused"),
        };
        Ok(Some(Self {
            measured_pairs,
            separate_first,
        }))
    }

    fn from_environment() -> Option<Self> {
        let read = |name| match std::env::var(name) {
            Ok(value) => Some(value),
            Err(std::env::VarError::NotPresent) => None,
            Err(error) => panic!("invalid explicit repeat setting {name}: {error}"),
        };
        let pairs = read("IROHA_FUSED_REPEAT_PAIRS");
        let first = read("IROHA_FUSED_REPEAT_FIRST");
        Self::parse(pairs.as_deref(), first.as_deref()).expect("explicit repeat configuration")
    }

    fn order(self, measured_pair: usize) -> [&'static str; 2] {
        if self.separate_first == (measured_pair % 2 == 0) {
            ["separate", "fused"]
        } else {
            ["fused", "separate"]
        }
    }
}

#[test]
fn repeat_schedule_is_opt_in_bounded_and_balances_both_orders() {
    assert_eq!(RepeatSchedule::parse(None, None), Ok(None));
    for (pairs, first) in [
        (Some("6"), None),
        (None, Some("separate")),
        (Some(""), Some("separate")),
        (Some("0"), Some("separate")),
        (Some("1"), Some("separate")),
        (Some("3"), Some("separate")),
        (Some("18"), Some("separate")),
        (Some("6"), Some("unknown")),
    ] {
        assert!(RepeatSchedule::parse(pairs, first).is_err());
    }
    for pairs in ["2", "6", "16"] {
        for first in ["separate", "fused"] {
            let schedule = RepeatSchedule::parse(Some(pairs), Some(first))
                .unwrap()
                .unwrap();
            let orders: Vec<_> = (0..schedule.measured_pairs)
                .map(|i| schedule.order(i))
                .collect();
            assert_eq!(orders[0][0], first);
            assert_eq!(
                orders.iter().filter(|order| order[0] == "separate").count(),
                schedule.measured_pairs / 2
            );
            assert!(
                orders
                    .windows(2)
                    .all(|pair| pair[0][0] == pair[1][1] && pair[0][1] == pair[1][0])
            );
        }
    }
}

/// One separate/fused pair over the same admitted source, actual circuit and
/// public instances. Fresh hedged OS randomness is required for each proof.
/// Generic plonk unit tests, which can access private advice and test RNGs,
/// separately cover exact witness and seeded proof-byte equality.
/// Explicit test-only repeat settings add a checked warmup pair and alternating
/// measured pairs. Returns the actual additional proof count, including warmups.
/// The caller uses it only to keep its fixture completion summary accurate.
pub(crate) fn compare<C, Ci, S>(
    label: &str,
    params: &PinnedParams<C>,
    metadata: &SourceBoundViewV2<'_, C>,
    source: impl Fn() -> S,
    circuit: &Ci,
    instances: &[Vec<C::ScalarExt>],
    mut decide_carried_claims: impl FnMut(),
) -> usize
where
    C: PastaCurve,
    C::Base: PoseidonField,
    C::ScalarExt: PoseidonField,
    Ci: Circuit<C::ScalarExt>,
    S: Circuit<C::ScalarExt>,
{
    assert!(
        !cfg!(debug_assertions),
        "run real-family measurement with --release"
    );
    let repeated = RepeatSchedule::from_environment();
    let mut first_key = None;
    let mut first_proof = None;
    let mut seen_proof_digests = std::collections::BTreeSet::<[u8; 32]>::new();
    // One pair and unchanged timing probes by default. Repeat mode adds one
    // reported warmup pair and balances first/second positions across an even
    // number of measured pairs. It does not remove drift, cache or load effects.
    let iterations = repeated.map_or(1, |schedule| schedule.measured_pairs + 1);
    if let Some(schedule) = repeated {
        println!(
            "FUSED_REAL_FAMILY_REPEAT_CONFIG label={label} measured_pairs={} warmup_pairs=1 first={} order=alternating expected_additional_proofs={}",
            schedule.measured_pairs,
            schedule.order(0)[0],
            2 * iterations
        );
    }
    for iteration in 0..iterations {
        let warmup = repeated.is_some() && iteration == 0;
        let sample = iteration.saturating_sub(1);
        let order = repeated.map_or(["separate", "fused"], |schedule| schedule.order(sample));
        let mut observations = Vec::with_capacity(if repeated.is_some() { 6 } else { 0 });
        let mut instruction_observations = Vec::with_capacity(2);
        for (position, variant) in order.into_iter().enumerate() {
            if repeated.is_some() {
                // Missing completion or any failed arm invalidates the diagnostic
                // run. Preserve this start and failure; never silently replace it.
                println!(
                    "FUSED_REAL_FAMILY_REPEAT_START label={label} sample={sample} warmup={warmup} position={position} variant={variant}"
                );
            }
            let before = ProcessSnapshot::capture().expect("required process probes");
            let started = Instant::now();
            let (key, witness) = if variant == "separate" {
                let source = source();
                let key = keygen_pk_from_vk_v2_cancellable(
                    params,
                    &source,
                    metadata,
                    CosetCachePolicy::OnDemand,
                    None,
                )
                .unwrap();
                drop(source);
                let witness =
                    Witness::from_circuit_cancellable(&key, circuit, instances, None).unwrap();
                (key, witness)
            } else {
                rebuild_key_and_witness_v2_cancellable(
                    params,
                    circuit,
                    metadata,
                    instances,
                    CosetCachePolicy::OnDemand,
                    None,
                )
                .unwrap()
            };
            // Preparation includes source construction for the separate path and
            // all synthesis/rebuild/witness work, excluding fixture keygen and admission.
            let preparation_ns = started.elapsed().as_nanos();
            let after = ProcessSnapshot::capture().expect("required process probes");
            // ProcessSnapshot reads CPU before its other probes: this CPU delta
            // includes the first snapshot's RSS/load/thermal probe overhead.
            let preparation_cpu_ns = after.cpu_since(before).expect("monotonic process CPU");
            assert!(after.peak_rss_bytes >= before.peak_rss_bytes);
            assert_eq!(witness.instances(), instances);
            let identity = key_identity(&key);
            if let Some(expected) = &first_key {
                assert_eq!(
                    &identity, expected,
                    "exact metadata and public polynomial digest parity"
                );
            } else {
                first_key = Some(identity);
            }
            // Test-only sampler trigger after reconstruction, witness assignment
            // and public key identity hashing. No private data is emitted.
            eprintln!(
                "FUSED_REAL_FAMILY_PROVE_BEGIN pid={} label={label} variant={variant} iteration={iteration} sample={sample} warmup={warmup} position={position} k={} workers={} after_rebuild_witness_key_identity=true diagnostic_only=true",
                std::process::id(),
                params.k(),
                rayon::current_num_threads(),
            );
            let proving_before =
                repeated.map(|_| ProcessSnapshot::capture().expect("required proving probes"));
            // Outside the existing proof wall cut. Unsupported counters do not
            // change correctness; this capture is inside the optional CPU cut.
            let instructions_before = ProcessInstructionSnapshot::capture();
            let started = Instant::now();
            let output = create_proof_owned_with_claim(
                params,
                &key,
                witness,
                ProverRandomness::hedged(),
                ProverConfig::default(),
            )
            .unwrap();
            let proof_elapsed = started.elapsed();
            let instructions_after = ProcessInstructionSnapshot::capture();
            eprintln!(
                "FUSED_REAL_FAMILY_PROVE_END pid={} label={label} variant={variant} iteration={iteration} sample={sample} warmup={warmup} position={position} k={} workers={} proof_ns={} before_key_drop=true diagnostic_only=true",
                std::process::id(),
                params.k(),
                rayon::current_num_threads(),
                proof_elapsed.as_nanos(),
            );
            // Keep marker I/O outside the reported proof-plus-key-drop wall
            // duration. Optional process CPU still includes the END marker
            // and now both instruction probes. Compare CPU only with matched
            // instrumentation; the old field schema and cuts are unchanged.
            let key_drop_started = Instant::now();
            drop(key); // No PK remains during verification or the next preparation.
            let proving_ns = proof_elapsed
                .saturating_add(key_drop_started.elapsed())
                .as_nanos();
            let proving_after =
                repeated.map(|_| ProcessSnapshot::capture().expect("required proving probes"));
            let verification_before =
                repeated.map(|_| ProcessSnapshot::capture().expect("required verification probes"));
            let started = Instant::now();
            let verified = verify_full_opening_cancellable(
                params,
                metadata.binding(),
                metadata.verifying_key(),
                instances,
                &output.proof,
                MemoryBudget::DEFAULT,
                None,
            )
            .unwrap();
            assert!(verified.matches(&output.opening));
            decide_carried_claims();
            let verification_ns = started.elapsed().as_nanos();
            let verification_after =
                repeated.map(|_| ProcessSnapshot::capture().expect("required verification probes"));
            if let Some(expected) = &first_proof {
                assert_ne!(
                    &output.proof, expected,
                    "fresh independent OS entropy for each proof"
                );
            } else {
                first_proof = Some(output.proof.clone());
            }
            if let Some(schedule) = repeated {
                let digest: [u8; 32] = Sha256::digest(&output.proof).into();
                assert!(
                    seen_proof_digests.insert(digest),
                    "repeated diagnostic proof bytes"
                );
                for (phase, wall_ns, phase_before, phase_after) in [
                    ("preparation", preparation_ns, before, after),
                    (
                        "proving_and_key_drop",
                        proving_ns,
                        proving_before.unwrap(),
                        proving_after.unwrap(),
                    ),
                    (
                        "full_verification_and_claims",
                        verification_ns,
                        verification_before.unwrap(),
                        verification_after.unwrap(),
                    ),
                ] {
                    let cpu_ns = phase_after
                        .cpu_since(phase_before)
                        .expect("monotonic phase process CPU");
                    assert!(phase_after.peak_rss_bytes >= phase_before.peak_rss_bytes);
                    // CPU includes the first probe's non-CPU overhead. Lifetime
                    // RSS is a level, not a per-phase peak; never subtract it.
                    // Strings and parity hashes are created after all timed cuts.
                    observations.push(format!(
                    "FUSED_REAL_FAMILY_REPEAT label={label} phase={phase} variant={variant} sample={sample} warmup={warmup} position={position} measured_pairs={} k={} workers={} wall_ns={wall_ns} process_cpu_probe_inclusive_ns={cpu_ns} proof_bytes={} kernel_lifetime_peak_rss_before={} kernel_lifetime_peak_rss_after={} load_before={:?} load_after={:?} thermal_before={:?} thermal_after={:?} exact_public_key_and_instances_equal=true full_opening_and_carried_claims_verified=true distinct_fresh_proof=true pair_verified=true advice_equality_observed=false exact_proof_byte_parity=false randomness=fresh-hedged device_p95=false",
                    schedule.measured_pairs, params.k(), rayon::current_num_threads(), output.proof.len(),
                    phase_before.peak_rss_bytes, phase_after.peak_rss_bytes,
                    phase_before.load_milli, phase_after.load_milli, phase_before.thermal, phase_after.thermal,
                ));
                }
            } else {
                // Neither the polynomial digest nor witness data is emitted.
                println!(
                    "FUSED_REAL_FAMILY label={label} variant={variant} k={} workers={} preparation_ns={preparation_ns} preparation_process_cpu_probe_inclusive_ns={preparation_cpu_ns} proving_and_key_drop_ns={proving_ns} full_verification_and_claims_ns={verification_ns} proof_bytes={} kernel_lifetime_peak_rss_before={} kernel_lifetime_peak_rss_after={} load_before={:?} load_after={:?} thermal_before={:?} thermal_after={:?} public_instances_equal=true cross_variant_parity={} advice_equality_observed=false exact_proof_byte_parity=false randomness=fresh-hedged sample_count=1 device_p95=false",
                    params.k(),
                    rayon::current_num_threads(),
                    output.proof.len(),
                    before.peak_rss_bytes,
                    after.peak_rss_bytes,
                    before.load_milli,
                    after.load_milli,
                    before.thermal,
                    after.thermal,
                    if variant == "fused" {
                        "verified"
                    } else {
                        "pending"
                    },
                );
            }
            let instructions =
                InstructionObservation::from_captures(instructions_before, instructions_after);
            // Render only after full opening/claim verification and freshness
            // checks; publish only when both arms of the pair have completed.
            instruction_observations.push(format!(
                "FUSED_REAL_FAMILY_INSTRUCTIONS label={label} phase=proof_creation variant={variant} iteration={iteration} sample={sample} warmup={warmup} position={position} k={} workers={} {} process_scope=all_threads probe_inclusive=true instruction_cut_includes_clock_and_probe_overhead=true existing_proving_cpu_includes_instruction_probes=true full_opening_and_carried_claims_verified=true pair_verified=true randomness=fresh-hedged native_entry_cut=false device_p95=false",
                params.k(),
                rayon::current_num_threads(),
                instructions.marker_fields(),
            ));
        }
        assert_eq!(instruction_observations.len(), 2);
        for observation in instruction_observations {
            println!("{observation}");
        }
        if repeated.is_some() {
            // Publish comparisons only after both fresh proofs, every exact
            // metadata/instance check and each carried claim have passed.
            assert_eq!(observations.len(), 6);
            for observation in observations {
                println!("{observation}");
            }
            println!(
                "FUSED_REAL_FAMILY_REPEAT_PAIR label={label} sample={sample} warmup={warmup} first={} pair_verified=true",
                order[0]
            );
        } else {
            println!("FUSED_REAL_FAMILY_PAIR label={label} pair_verified=true");
        }
    }
    if let Some(schedule) = repeated {
        assert_eq!(seen_proof_digests.len(), 2 * iterations);
        println!(
            "FUSED_REAL_FAMILY_REPEAT_COMPLETE label={label} measured_pairs={} warmup_pairs=1 additional_proofs={} complete=true device_p95=false",
            schedule.measured_pairs,
            2 * iterations
        );
    }
    2 * iterations
}
