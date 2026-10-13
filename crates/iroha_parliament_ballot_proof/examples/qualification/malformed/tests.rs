//! Deterministic mutation-class and reporting checks, separate from observations.

use super::*;

#[test]
fn mutation_classes_reject_at_the_declared_boundary_on_all_cases() {
    for row in Row::ALL {
        for case in Case::ALL {
            let prepared = prepare(row, case).expect("bounded public inputs");
            let statement = prepared
                .statement
                .encode(&prepared.profile)
                .expect("statement");
            // Only syntax is needed: every mutated proof must stop in the
            // codec, before this zero-filled non-proof could be evaluated.
            let proof = vec![0u8; row.proof_bytes(case.role())];
            let record = test_codec::encode_record(&statement, &proof).expect("record");
            let mutations = Mutation::all(case);
            let names: std::collections::BTreeSet<_> = mutations.iter().map(|m| m.name()).collect();
            assert_eq!(names.len(), mutations.len());
            assert_eq!(
                mutations.len(),
                if case == Case::Registration { 16 } else { 22 }
            );
            for mutation in mutations {
                let malformed = mutant(row, case, mutation, &record).expect("bounded mutation");
                assert_ne!(malformed, record, "{}", mutation.name());
                let decoded = decode_record(row, case, &malformed);
                match mutation.outcome() {
                    "decode_rejected" => assert!(decoded.is_err(), "{}", mutation.name()),
                    "verification_rejected" => {
                        let (statement, proof) = decoded.expect("outer encoding is canonical");
                        let error = statement
                            .backend_diagnostic(&prepared.profile, proof)
                            .expect("rejects");
                        assert!(
                            mutation.matches_codec_error(&error),
                            "{}: {error:?}",
                            mutation.name()
                        );
                    }
                    other => panic!("unexpected outcome {other}"),
                }
            }
        }
    }
}

#[test]
fn field_ranges_reject_truncation_trailing_and_oversized_lengths() {
    let encoded = frame_bytes(b"example", &[b"one", b"", b"two"]).expect("frame");
    let ranges = field_ranges(&encoded).expect("canonical");
    assert_eq!(
        ranges
            .iter()
            .map(|r| &encoded[r.clone()])
            .collect::<Vec<_>>(),
        [b"one".as_slice(), b"", b"two"]
    );
    for length in [0, 1, 9, encoded.len() - 1] {
        assert!(field_ranges(&encoded[..length]).is_err());
    }
    let mut trailing = encoded.clone();
    trailing.push(0);
    assert!(field_ranges(&trailing).is_err());
    let mut overflow = encoded;
    overflow[ranges[0].start - 4..ranges[0].start].copy_from_slice(&u32::MAX.to_le_bytes());
    assert!(field_ranges(&overflow).is_err());
}

#[test]
fn outcome_and_summary_preserve_rejection_classes_and_extrema() {
    assert_eq!(outcome(&Ok(Ok(()))), "accepted");
    assert_eq!(
        outcome(&Ok(Err(VerifyError::Rejected))),
        "verification_rejected"
    );
    assert_eq!(outcome(&Err("bad encoding".into())), "decode_rejected");
    let metrics = [3, 1, 9].map(|value| Metric {
        elapsed_ns: value,
        live_at_entry_bytes: 10,
        live_at_exit_bytes: 11,
        total_peak_live_bytes: 20,
        incremental_peak_bytes: 10,
        allocation_calls: 4,
        allocated_bytes: 40,
    });
    let summary = summarize_metrics("test", &metrics);
    assert_eq!(
        (
            summary.elapsed_ns.count,
            summary.elapsed_ns.min,
            summary.elapsed_ns.median,
            summary.elapsed_ns.p95,
            summary.elapsed_ns.max
        ),
        (3, 1, 3, 9, 9)
    );
    assert_eq!(summary.total_peak_live_bytes.max, 20);
    assert_eq!(summary.incremental_peak_bytes.max, 10);
    assert_eq!(summary.allocation_calls.max, 4);
    assert_eq!(summary.allocated_bytes.max, 40);
}

#[test]
fn command_help_and_options_fail_before_proving() {
    let mut output = Vec::new();
    run(&["--help".into()], &mut output).expect("help");
    assert!(output.starts_with(b"Use: qualify malformed"));
    assert!(run(&["--samples".into(), "0".into()], &mut Vec::new()).is_err());
}

#[test]
fn one_honest_setup_produces_only_expected_rejection_observations() {
    let mut bytes = Vec::new();
    run_case(Row::Candidate, Case::Registration, 1, &mut bytes).expect("bounded campaign");
    let lines: Vec<norito::json::Value> = bytes
        .split(|byte| *byte == b'\n')
        .filter(|line| !line.is_empty())
        .map(|line| norito::json::from_slice(line).expect("Norito JSON"))
        .collect();
    assert_eq!(lines.len(), 32);
    for pair in lines.chunks_exact(2) {
        assert_eq!(pair[0]["kind"].as_str(), Some("malformed_sample"));
        assert_eq!(pair[1]["kind"].as_str(), Some("malformed_summary"));
        assert!(matches!(
            pair[0]["outcome"].as_str(),
            Some("decode_rejected" | "verification_rejected")
        ));
        assert_eq!(pair[1]["metrics"]["elapsed_ns"]["count"].as_u64(), Some(1));
    }
}
