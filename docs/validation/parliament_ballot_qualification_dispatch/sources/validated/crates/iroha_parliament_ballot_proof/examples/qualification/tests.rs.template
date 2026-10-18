//! Cheap deterministic checks of the resource harness, separate from timed runs.

use super::*;

fn args(values: &[&str]) -> Vec<String> {
    values.iter().map(|value| (*value).to_owned()).collect()
}

#[test]
fn options_bound_work_and_reject_ambiguous_values() {
    let defaults = options(&[]).expect("defaults").expect("run");
    assert_eq!(defaults.samples, 31);
    assert_eq!(defaults.rows, Row::ALL);
    assert_eq!(defaults.cases, Case::ALL);
    for n in [1, 31, 101, 1001] {
        let input = args(&[
            "--samples",
            &n.to_string(),
            "--row",
            "candidate",
            "--case",
            "vote1000",
            "--source-id",
            "sha256-example",
            "--run-id",
            "test",
        ]);
        let parsed = options(&input).expect("valid").expect("run");
        assert_eq!(parsed.samples, n);
        assert_eq!(parsed.cases, [Case::Vote(1000)]);
        assert_eq!(parsed.rows, [Row::Candidate]);
        assert_eq!(parsed.source_id, "sha256-example");
        assert_eq!(parsed.run_id, "test");
    }
    for input in [
        vec!["--samples", "0"],
        vec!["--samples", "1002"],
        vec!["--samples", "abc"],
        vec!["--samples"],
        vec!["--unknown", "x"],
        vec!["--row", "fast"],
        vec!["--case", "vote2"],
    ] {
        assert!(options(&args(&input)).is_err(), "{input:?}");
    }
    assert!(options(&args(&["--help"])).expect("help").is_none());
    let parsed = options(&args(&["--row", "comparator", "--case", "registration"]))
        .expect("options")
        .expect("run");
    assert_eq!(parsed.rows, [Row::Comparator]);
    assert_eq!(parsed.cases, [Case::Registration]);
}

#[test]
fn nearest_rank_keeps_max_and_small_sample_p95_honest() {
    let one = distribution(vec![17]);
    assert_eq!(
        (one.count, one.min, one.median, one.p95, one.max),
        (1, 17, 17, 17, 17)
    );
    let odd = distribution((0..31).rev().collect());
    assert_eq!(
        (odd.count, odd.min, odd.median, odd.p95, odd.max),
        (31, 0, 15, 29, 30)
    );
    let even = distribution((1..=100).rev().collect());
    assert_eq!((even.median, even.p95, even.max), (50, 95, 100));
    assert_eq!(distribution(vec![1, 2, 100]).p95, 100);
}

#[test]
fn reproducible_inputs_use_maximum_fields_and_bound_list_sizes() {
    for row in Row::ALL {
        for case in Case::ALL {
            let prepared = prepare(row, case).expect("public inputs");
            match &prepared.statement {
                Statement::Registration(s) => {
                    assert_eq!(s.body_context().as_bytes().len(), BODY_CONTEXT_MAX_BYTES);
                    assert!(
                        s.context()
                            .fields()
                            .iter()
                            .all(|field| field.len() == OPAQUE_FIELD_MAX_BYTES)
                    );
                }
                Statement::Vote(s) => {
                    assert_eq!(s.list.len(), case.seats());
                    assert_eq!(usize::from(s.size), case.seats());
                    assert_eq!(
                        s.list[usize::from(prepared.position)],
                        prepared.secret.commitment(&s.body_digest)
                    );
                }
            }
            let encoded = prepared
                .statement
                .encode(&prepared.profile)
                .expect("encode");
            assert_eq!(
                encoded.len(),
                if case == Case::Registration {
                    6016
                } else {
                    576 + 128 * case.seats()
                }
            );
            let decoded =
                Statement::decode(&prepared.profile, case.role(), &encoded).expect("decode");
            assert_eq!(
                decoded.encode(&prepared.profile).expect("re-encode"),
                encoded
            );
            assert!(matches!(
                decoded.verify(row, &[]),
                Err(VerifyError::ProofLength { actual: 0, .. })
            ));
            let record = test_codec::encode_record(&encoded, &[]).expect("record");
            assert!(
                cold_verify(row, case, &record).is_err(),
                "record checks length before transcript"
            );
        }
    }
}

#[test]
fn counter_extraction_obeys_exact_width_and_limit_on_both_rows() {
    for row in Row::ALL {
        for role in Role::ALL {
            let mut proof = vec![0; row.proof_bytes(role)];
            let offset = field_offset(row, role, ProofField::Counter);
            assert_eq!(offset + 4, proof.len());
            assert!(field_offset(row, role, ProofField::Coefficients) < offset);
            assert_eq!(counter(row, role, &proof).expect("zero"), 0);
            proof[offset..].copy_from_slice(&0x000f_ffff_u32.to_le_bytes());
            assert_eq!(counter(row, role, &proof).expect("last"), 0x000f_ffff);
            proof[offset..].copy_from_slice(&0x0010_0000_u32.to_le_bytes());
            assert!(counter(row, role, &proof).is_err());
            assert!(counter(row, role, &proof[..proof.len() - 1]).is_err());
        }
    }
}

#[test]
fn deterministic_domains_and_proof_digest_are_reproducible() {
    use sha3::digest::{ExtendableOutput, Update, XofReader};
    let a = derive::<112>("tape/candidate/vote3/0");
    assert_eq!(a, derive::<112>("tape/candidate/vote3/0"));
    assert_ne!(a, derive::<112>("tape/candidate/vote3/1"));
    assert_ne!(a, derive::<112>("tape/comparator/vote3/0"));
    assert_ne!(a, derive::<112>("tape/candidate/vote500/0"));
    let mut expected = [0u8; 32];
    let mut shake = sha3::Shake256::default();
    shake.update(&a);
    shake.finalize_xof().read(&mut expected);
    let actual = proof_digest(&a);
    assert_eq!(actual.len(), 64);
    for (index, byte) in expected.iter().enumerate() {
        assert_eq!(
            u8::from_str_radix(&actual[2 * index..2 * index + 2], 16).expect("hex"),
            *byte
        );
    }
    assert_eq!(member(0).expose_bytes(), member(0).expose_bytes());
    assert_ne!(member(0).expose_bytes(), member(1).expose_bytes());
}

#[test]
fn allocator_metrics_include_retained_input_and_new_output() {
    // Run the harness tests with --test-threads=1 for exact allocation isolation.
    // Even with unrelated allocations, the fundamental inequalities must hold.
    let retained = vec![0x5au8; 8192];
    std::hint::black_box(&retained);
    let (new, metric) = measured(|| vec![0xc3u8; 16384]);
    std::hint::black_box(&new);
    assert!(metric.live_at_entry_bytes >= retained.len());
    assert!(metric.total_peak_live_bytes >= metric.live_at_entry_bytes);
    assert!(metric.total_peak_live_bytes >= metric.live_at_exit_bytes);
    assert_eq!(
        metric.incremental_peak_bytes,
        metric
            .total_peak_live_bytes
            .saturating_sub(metric.live_at_entry_bytes)
    );
    assert!(metric.allocated_bytes >= new.len());
    assert!(metric.allocation_calls >= 1);
}

#[derive(Default)]
struct Sink {
    bytes: Vec<u8>,
    flushes: usize,
}
impl Write for Sink {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.bytes.extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.flushes += 1;
        Ok(())
    }
}

#[test]
fn norito_records_flush_and_round_trip_without_environment_access() {
    let mut output = Sink::default();
    emit(&mut output, &distribution(vec![7, 2, 13])).expect("emit");
    assert_eq!(output.flushes, 1);
    assert_eq!(output.bytes.last(), Some(&b'\n'));
    let value: norito::json::Value = norito::json::from_slice(&output.bytes).expect("valid JSON");
    assert_eq!(value["count"].as_u64(), Some(3));
    assert_eq!(value["p95"].as_u64(), Some(13));
    let mut help = Sink::default();
    run(&args(&["--help"]), &mut help).expect("help");
    assert_eq!(help.bytes, HELP.as_bytes());
    assert_eq!(help.flushes, 1);
    assert!(run(&args(&["--samples", "0"]), &mut Sink::default()).is_err());
}

#[test]
fn malformed_dispatch_preserves_help_and_rejects_invalid_options_before_work() {
    let mut help = Sink::default();
    run(&args(&["malformed", "--help"]), &mut help).expect("malformed help");
    assert_eq!(
        help.bytes,
        [
            b"Use: qualify malformed [the qualify options below]\n".as_slice(),
            HELP.as_bytes()
        ]
        .concat()
    );
    assert_eq!(help.flushes, 1);
    for (input, expected) in [
        (
            vec!["malformed", "--samples", "0"],
            "--samples must be in 1..=1001",
        ),
        (
            vec!["malformed", "--samples"],
            "missing value for --samples",
        ),
        (
            vec!["malformed", "malformed", "--help"],
            "unknown option malformed",
        ),
        (
            vec!["--row", "malformed"],
            "--row must be all, candidate or comparator",
        ),
    ] {
        let mut output = Sink::default();
        let error = run(&args(&input), &mut output).expect_err("invalid options");
        assert_eq!(error.to_string(), expected);
        assert!(output.bytes.is_empty());
        assert_eq!(output.flushes, 0);
    }
}

#[test]
fn malformed_dispatch_preserves_output_errors() {
    let mut buffer = [0_u8; 0];
    let mut output = std::io::Cursor::new(&mut buffer[..]);
    let error = run(&args(&["malformed", "--help"]), &mut output)
        .expect_err("the caller's full output buffer must fail");
    assert_eq!(
        error
            .downcast_ref::<std::io::Error>()
            .expect("output error")
            .kind(),
        std::io::ErrorKind::WriteZero
    );
}

#[test]
fn summaries_keep_the_phase_and_retry_sample_counts() {
    let metric = Metric {
        elapsed_ns: 5,
        live_at_entry_bytes: 2,
        live_at_exit_bytes: 2,
        total_peak_live_bytes: 7,
        incremental_peak_bytes: 5,
        allocation_calls: 1,
        allocated_bytes: 5,
    };
    let samples: Vec<_> = [0, 3, 9]
        .into_iter()
        .map(|retry_counter| Observation {
            kind: "sample",
            row: "candidate",
            case: "vote3",
            sample_index: 0,
            proof_bytes: 233012,
            proof_shake256_32: "test".to_owned(),
            seats: 3,
            honest_result: "Ok(())",
            statement_bytes: 960,
            test_record_bytes: 233980,
            retry_counter,
            challenge_attempts: retry_counter + 1,
            late_invalid_result: "VerifyError::Rejected",
            late_invalid_backend_diagnostic: "not rerun",
            phases: vec![Phase {
                name: "prove",
                metric,
            }],
        })
        .collect();
    let summary = summarize(Row::Candidate, Case::Vote(3), &samples);
    assert_eq!(summary.samples_completed, 3);
    assert_eq!(summary.retry_counter.max, 9);
    assert_eq!(summary.challenge_attempts.max, 10);
    assert_eq!(summary.phases[0].elapsed_ns.count, 3);
    assert_eq!(summary.phases[0].total_peak_live_bytes.p95, 7);
}
