//! Complete exact-source inventory for actual local-emission native pairs.

/// One completed canonical typed result word.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Word {
    /// Canonical pointer-backed integer.
    Int(i64),
    /// Canonical decimal with exact expected value.
    Decimal(&'static str),
    /// Canonical nonnegative quantity with exact expected value.
    Quantity(&'static str),
    /// Canonical Unit representation.
    Unit,
}
/// Actual native VM outcome; source declarations do not establish execution.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Outcome {
    /// Every typed result word must be reproduced.
    Success(&'static [Word]),
    /// A declared nominal failure with the complete original authenticated descriptor.
    Abort { code: u32, name: &'static str },
    /// The unchanged checked numeric division failure.
    DivisionByZero,
    /// The original dynamic precision bound rejects scale 29.
    InvalidScale,
    /// The original nonnegative monetary subtraction bound remains enforced.
    QuantityUnderflow,
    /// Role creation succeeds with authority and rejects without it.
    Permission,
}
/// One exact source pair, with complete observable expectations.
pub(crate) struct Case {
    /// Complete ordered capture identity.
    pub(crate) id: &'static str,
    /// Identical complete source used by both compiler sequences.
    pub(crate) source: &'static str,
    /// Actual observable outcome.
    pub(crate) outcome: Outcome,
    /// Actual CoreHost trace, including the final write before a failure.
    pub(crate) trace: Option<i64>,
}
/// Complete inventory; missing or extra rows are rejected.
pub(crate) const CASES: &[Case] = &[
    Case {
        id: "rounded_values",
        source: include_str!("../../../../../fixtures/kotodama/compact_emission/rounded_values.ko"),
        outcome: Outcome::Success(&[
            Word::Quantity("0.12"),
            Word::Quantity("0.13"),
            Word::Quantity("0.12"),
            Word::Quantity("0.13"),
            Word::Quantity("0.12"),
            Word::Quantity("0.13"),
            Word::Quantity("0.12"),
            Word::Decimal("0.13"),
            Word::Quantity("0.38"),
            Word::Decimal("-0.13"),
            Word::Decimal("-0.37"),
            Word::Int(81),
            Word::Int(9),
            Word::Int(37),
            Word::Int(6),
        ]),
        trace: None,
    },
    Case {
        id: "unit_loop",
        source: include_str!("../../../../../fixtures/kotodama/compact_emission/unit_loop.ko"),
        outcome: Outcome::Success(&[Word::Unit, Word::Unit, Word::Int(8)]),
        trace: Some(8),
    },
    Case {
        id: "wide_arguments",
        source: include_str!("../../../../../fixtures/kotodama/compact_emission/wide_arguments.ko"),
        outcome: Outcome::Success(&[Word::Int(420)]),
        trace: None,
    },
    Case {
        id: "abort_first",
        source: include_str!("../../../../../fixtures/kotodama/compact_emission/abort_first.ko"),
        outcome: Outcome::Abort {
            code: 3,
            name: "Low",
        },
        trace: Some(7),
    },
    Case {
        id: "abort_second",
        source: include_str!("../../../../../fixtures/kotodama/compact_emission/abort_second.ko"),
        outcome: Outcome::Abort {
            code: 9,
            name: "High",
        },
        trace: Some(11),
    },
    Case {
        id: "rounded_trap",
        source: include_str!("../../../../../fixtures/kotodama/compact_emission/rounded_trap.ko"),
        outcome: Outcome::DivisionByZero,
        trace: Some(31),
    },
    Case {
        id: "invalid_scale",
        source: include_str!("../../../../../fixtures/kotodama/compact_emission/invalid_scale.ko"),
        outcome: Outcome::InvalidScale,
        trace: Some(43),
    },
    Case {
        id: "permission",
        source: include_str!("../../../../../fixtures/kotodama/compact_emission/permission.ko"),
        outcome: Outcome::Permission,
        trace: None,
    },
    Case {
        id: "chain_values",
        source: include_str!("../../../../../fixtures/kotodama/local_emission/chain_values.ko"),
        outcome: Outcome::Success(&[Word::Int(40), Word::Int(12), Word::Int(1)]),
        trace: Some(40),
    },
    Case {
        id: "map_values",
        source: include_str!("../../../../../fixtures/kotodama/local_emission/map_values.ko"),
        outcome: Outcome::Success(&[
            Word::Quantity("60"),
            Word::Quantity("40"),
            Word::Quantity("100"),
        ]),
        trace: None,
    },
    Case {
        id: "map_underflow",
        source: include_str!("../../../../../fixtures/kotodama/local_emission/map_underflow.ko"),
        outcome: Outcome::QuantityUnderflow,
        trace: None,
    },
    Case {
        id: "zero_chain",
        source: "seiyaku ZeroChain { fn chain(quantity left, quantity right) -> quantity { let first=left+right; let second=first+right; return second+left; } view fn main() authorize(anyone) ->quantity { let quantity left=5; let quantity right=7; return chain(left:left,right:right); } }",
        outcome: Outcome::Success(&[Word::Quantity("24")]),
        trace: None,
    },
];
/// Repository-relative canonical native capture consumed by compiler and VM tests.
pub(crate) const CAPTURE_PATH: &str = "fixtures/kotodama/numeric_zero/native_v1.tsv";
/// Bound on one canonical captured artifact, before any hex allocation.
pub(crate) const MAX_ARTIFACT_BYTES: usize = 64 * 1024;

/// Exact canonical artifact pair, checked against its source and full byte hashes.
pub(crate) struct Pair {
    /// Complete artifact with the original numeric zero assignments retained by its scoped test guard.
    pub(crate) before: Vec<u8>,
    /// Complete artifact with the sole production numeric emitter enabled.
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
    for (index, line) in text
        .lines()
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .enumerate()
    {
        let fields = line.split('\t').collect::<Vec<_>>();
        assert_eq!(fields.len(), 6, "one exact V1 native pair row");
        let case = CASES.get(index).expect("no extra native rows");
        assert_eq!(
            case.id, fields[0],
            "exact complete ordered source inventory"
        );
        assert_eq!(
            fields[1],
            iroha_crypto::Hash::new(case.source.as_bytes()).to_string(),
            "exact complete source identity"
        );
        let artifact = |hex_text: &str, expected_hash: &str| {
            assert!(hex_text.len() <= MAX_ARTIFACT_BYTES * 2 && hex_text.len() % 2 == 0);
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
        assert!(
            pair.after.len() <= pair.before.len(),
            "no complete pair may grow"
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
    assert!(
        pairs.values().any(|pair| pair.before != pair.after),
        "actual emission reduction must be captured"
    );
    pairs
}
