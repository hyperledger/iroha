//! Shared source inventory and observable expectations for native private-call pairs.

/// A typed completed public result word.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Word {
    /// Pointer-backed canonical Int that fits the fixture's i64 expectation.
    Int(i64),
    /// The sole canonical Unit representation.
    Unit,
}
/// A checked numeric fault preserved through private-body movement.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Fault {
    /// Checked integer division by zero.
    DivisionByZero,
    /// Checked bounded integer overflow.
    MantissaOverflow,
}
/// The observable outcome of actual native VM execution.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Outcome {
    /// Complete canonical typed public result words.
    Success(&'static [Word]),
    /// The exact VM numeric fault, with no completed result.
    Fault(Fault),
}
/// One source-bound native before/after compiler capture.
pub(crate) struct Case {
    /// Exact row identity, also naming the checked-in .ko file.
    pub(crate) id: &'static str,
    /// Identical complete source used by both compiler variants.
    pub(crate) source: &'static str,
    /// The private helper that must disappear only from the optimized callable inventory.
    pub(crate) moved_helper: &'static str,
    /// Expected real VM result or checked fault.
    pub(crate) outcome: Outcome,
    /// Expected durable trace after constructor and main, including before a VM fault.
    pub(crate) trace: Option<i64>,
}
/// Complete canonical seven-case source inventory; no additional rows are accepted.
pub(crate) const CASES: &[Case] = &[
    Case {
        id: "conditional",
        source: include_str!("conditional.ko"),
        moved_helper: "choose",
        outcome: Outcome::Success(&[Word::Int(59)]),
        trace: None,
    },
    Case {
        id: "nested_loops",
        source: include_str!("nested_loops.ko"),
        moved_helper: "accumulate",
        outcome: Outcome::Success(&[Word::Int(10)]),
        trace: None,
    },
    Case {
        id: "unit",
        source: include_str!("unit.ko"),
        moved_helper: "stamp",
        outcome: Outcome::Success(&[Word::Unit, Word::Int(7)]),
        trace: Some(7),
    },
    Case {
        id: "discarded",
        source: include_str!("discarded.ko"),
        moved_helper: "update",
        outcome: Outcome::Success(&[Word::Int(7)]),
        trace: Some(7),
    },
    Case {
        id: "ordered_arguments",
        source: include_str!("ordered_arguments.ko"),
        moved_helper: "combine",
        outcome: Outcome::Success(&[Word::Int(12), Word::Int(2)]),
        trace: Some(2),
    },
    Case {
        id: "division_trap",
        source: include_str!("division_trap.ko"),
        moved_helper: "checked",
        outcome: Outcome::Fault(Fault::DivisionByZero),
        trace: Some(41),
    },
    Case {
        id: "overflow_trap",
        source: include_str!("overflow_trap.ko"),
        moved_helper: "checked",
        outcome: Outcome::Fault(Fault::MantissaOverflow),
        trace: None,
    },
];
/// Repository-relative canonical native capture consumed by compiler and VM tests.
pub(crate) const CAPTURE_PATH: &str = "fixtures/kotodama/private_single_use/native_v1.tsv";
/// Bound on one canonical captured artifact, before any hex allocation.
pub(crate) const MAX_ARTIFACT_BYTES: usize = 64 * 1024;

/// Exact canonical artifact pair, checked against its source and full byte hashes.
pub(crate) struct Pair {
    /// Artifact emitted with ordinary private calls retained by the scoped test guard.
    pub(crate) before: Vec<u8>,
    /// Artifact emitted with the sole-call body movement enabled.
    pub(crate) after: Vec<u8>,
}
/// Load the complete native capture, rejecting missing, duplicate, oversized or altered rows.
pub(crate) fn load_pairs(
    repository_root: &std::path::Path,
) -> std::collections::BTreeMap<String, Pair> {
    let path = repository_root.join(CAPTURE_PATH);
    let metadata = std::fs::metadata(&path)
        .expect("capture native compiler rows before running parity or VM consumers");
    assert!(metadata.len() <= ((MAX_ARTIFACT_BYTES * 4 + 4096) * CASES.len()) as u64);
    let text = std::fs::read_to_string(path).expect("native capture is bounded UTF-8 TSV");
    let mut pairs = std::collections::BTreeMap::new();
    for line in text
        .lines()
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
    {
        let fields = line.split('\t').collect::<Vec<_>>();
        assert_eq!(fields.len(), 6, "one exact V1 native pair row");
        let case = CASES
            .iter()
            .find(|case| case.id == fields[0])
            .expect("only declared source-bound cases may appear");
        assert_eq!(
            fields[1],
            iroha_crypto::Hash::new(case.source.as_bytes()).to_string(),
            "exact complete source identity"
        );
        let artifact = |hex_text: &str, expected_hash: &str| {
            assert!(hex_text.len() <= MAX_ARTIFACT_BYTES * 2 && hex_text.len().is_multiple_of(2));
            let bytes = hex::decode(hex_text).expect("native artifact hex");
            assert_eq!(hex::encode(&bytes), hex_text, "canonical lowercase hex");
            assert_eq!(
                iroha_crypto::Hash::new(&bytes).to_string(),
                expected_hash,
                "full canonical artifact identity"
            );
            bytes
        };
        let pair = Pair {
            before: artifact(fields[4], fields[2]),
            after: artifact(fields[5], fields[3]),
        };
        assert_ne!(
            pair.before, pair.after,
            "this pass must actually change the captured executable ownership"
        );
        assert!(
            pairs.insert(case.id.to_owned(), pair).is_none(),
            "duplicate pair identity"
        );
    }
    assert_eq!(
        pairs.len(),
        CASES.len(),
        "the complete native case inventory is mandatory"
    );
    pairs
}
