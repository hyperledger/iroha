//! Shared source inventory and observable expectations for native exact frame-emission pairs.

/// A typed completed public result word.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Word {
    /// Pointer-backed canonical Int that fits the fixture's i64 expectation.
    Int(i64),
    /// The sole canonical Unit representation.
    Unit,
}
/// A checked numeric fault preserved through exact frame emission.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Fault {
    /// Checked integer division by zero.
    DivisionByZero,
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
    /// A genuinely executed private helper retained in both exact callable inventories.
    pub(crate) retained_helper: &'static str,
    /// Expected real VM result or checked fault.
    pub(crate) outcome: Outcome,
    /// Expected durable trace after constructor and main, including before a VM fault.
    pub(crate) trace: Option<i64>,
}
/// Complete canonical four-case source inventory; no additional rows are accepted.
pub(crate) const CASES: &[Case] = &[
    Case {
        id: "large_frame",
        source: include_str!("large_frame.ko"),
        retained_helper: "pulse",
        outcome: Outcome::Success(&[
            Word::Int(1),
            Word::Int(2),
            Word::Int(3),
            Word::Int(4),
            Word::Int(5),
            Word::Int(6),
            Word::Int(7),
            Word::Int(8),
            Word::Int(9),
            Word::Int(10),
            Word::Int(11),
            Word::Int(12),
            Word::Int(13),
            Word::Int(14),
            Word::Int(15),
            Word::Int(16),
            Word::Int(17),
            Word::Int(18),
            Word::Int(19),
            Word::Int(20),
            Word::Int(21),
            Word::Int(22),
            Word::Int(23),
            Word::Int(24),
            Word::Int(25),
            Word::Int(26),
            Word::Int(27),
            Word::Int(28),
            Word::Int(29),
            Word::Int(30),
            Word::Int(31),
            Word::Int(32),
            Word::Int(33),
            Word::Int(34),
            Word::Int(35),
            Word::Int(36),
            Word::Int(37),
            Word::Int(38),
            Word::Int(39),
            Word::Int(40),
            Word::Int(41),
            Word::Int(42),
            Word::Int(43),
            Word::Int(44),
            Word::Int(45),
            Word::Int(46),
            Word::Int(47),
            Word::Int(48),
            Word::Int(49),
            Word::Int(50),
            Word::Int(2),
        ]),
        trace: Some(2),
    },
    Case {
        id: "both_returns",
        source: include_str!("both_returns.ko"),
        retained_helper: "compute",
        outcome: Outcome::Success(&[
            Word::Int(1),
            Word::Int(2),
            Word::Int(3),
            Word::Int(4),
            Word::Int(5),
            Word::Int(6),
            Word::Int(7),
            Word::Int(8),
            Word::Int(9),
            Word::Int(10),
            Word::Int(11),
            Word::Int(12),
            Word::Int(13),
            Word::Int(14),
            Word::Int(15),
            Word::Int(16),
            Word::Int(17),
            Word::Int(18),
            Word::Int(19),
            Word::Int(20),
            Word::Int(21),
            Word::Int(22),
            Word::Int(23),
            Word::Int(24),
            Word::Int(25),
            Word::Int(26),
            Word::Int(27),
            Word::Int(28),
            Word::Int(29),
            Word::Int(30),
            Word::Int(31),
            Word::Int(32),
            Word::Int(33),
            Word::Int(34),
            Word::Int(35),
            Word::Int(36),
            Word::Int(37),
            Word::Int(38),
            Word::Int(39),
            Word::Int(40),
            Word::Int(41),
            Word::Int(42),
            Word::Int(43),
            Word::Int(44),
            Word::Int(45),
            Word::Int(46),
            Word::Int(47),
            Word::Int(48),
            Word::Int(49),
            Word::Int(50),
            Word::Int(2),
            Word::Int(52),
            Word::Int(51),
            Word::Int(50),
            Word::Int(49),
            Word::Int(48),
            Word::Int(47),
            Word::Int(46),
            Word::Int(45),
            Word::Int(44),
            Word::Int(43),
            Word::Int(42),
            Word::Int(41),
            Word::Int(40),
            Word::Int(39),
            Word::Int(38),
            Word::Int(37),
            Word::Int(36),
            Word::Int(35),
            Word::Int(34),
            Word::Int(33),
            Word::Int(32),
            Word::Int(31),
            Word::Int(30),
            Word::Int(29),
            Word::Int(28),
            Word::Int(27),
            Word::Int(26),
            Word::Int(25),
            Word::Int(24),
            Word::Int(23),
            Word::Int(22),
            Word::Int(21),
            Word::Int(20),
            Word::Int(19),
            Word::Int(18),
            Word::Int(17),
            Word::Int(16),
            Word::Int(15),
            Word::Int(14),
            Word::Int(13),
            Word::Int(12),
            Word::Int(11),
            Word::Int(10),
            Word::Int(9),
            Word::Int(8),
            Word::Int(7),
            Word::Int(6),
            Word::Int(5),
            Word::Int(4),
            Word::Int(3),
            Word::Int(4),
        ]),
        trace: Some(4),
    },
    Case {
        id: "unit_returns",
        source: include_str!("unit_returns.ko"),
        retained_helper: "compute",
        outcome: Outcome::Success(&[Word::Unit, Word::Unit, Word::Int(65026)]),
        trace: Some(65026),
    },
    Case {
        id: "division_trap",
        source: include_str!("division_trap.ko"),
        retained_helper: "pulse",
        outcome: Outcome::Fault(Fault::DivisionByZero),
        trace: Some(41),
    },
];
/// Repository-relative canonical native capture consumed by compiler and VM tests.
pub(crate) const CAPTURE_PATH: &str = "fixtures/kotodama/frame_emission/native_v1.tsv";
/// Bound on one canonical captured artifact, before any hex allocation.
pub(crate) const MAX_ARTIFACT_BYTES: usize = 64 * 1024;

/// Exact canonical artifact pair, checked against its source and full byte hashes.
pub(crate) struct Pair {
    /// Artifact emitted with individual original saved-slot addressing and restoration retained by the scoped test guard.
    pub(crate) before: Vec<u8>,
    /// Artifact emitted with the windowed saved slots and shared equivalent restoration enabled.
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
            "this pass must actually change the captured frame emission"
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
