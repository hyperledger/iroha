//! Finality header, certified result and `X ‖ body` reader tests
//! (`specs/sccp.md` §3.6, §3.7, §3.9 and §11.2).
//!
//! The table-driven tests read the shared reference vectors `fixtures/sccp/finality_v1.json`
//! row by row; a missing file fails, so they never pass vacuously. The spec's worked examples
//! are also pinned here as literals, independently of that file.

use std::{collections::BTreeSet, path::PathBuf};

use iroha_crypto::{HashOf, KeyPair, keccak256};
use iroha_model_base::peer::PeerId;
use iroha_sumeragi::types::ChainParams;
use norito::json::Value;

use super::{
    CertifiedResultScope::{NonGlobal, TairaGlobal},
    *,
};
use crate::{
    sumeragi::epoch::{
        ValidatorEpochBoundaryV1, ValidatorEpochDecisionV1,
        tests::{fixture, retained},
    },
    sumeragi_finality::{
        ChainParamsRecord, ExecutionCommitment, NativeLaneStateProof, ScheduleOutcome,
        ScheduledConfig, ScheduledSlot,
    },
};

const REFERENCE: &str = "fixtures/sccp/finality_v1.json";
const SCHEMA: &str = "iroha.sccp.finality.v1";

/// Block time of the §11.2 worked examples.
const T0: u64 = 1_790_000_000_000;

fn reference() -> Value {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join(REFERENCE);
    let text = std::fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("read {}: {error}", path.display()));
    let value: Value = norito::json::from_str(&text)
        .unwrap_or_else(|error| panic!("parse {}: {error}", path.display()));
    assert_eq!(text_of(&value, "schema"), SCHEMA);
    value
}

fn field<'a>(value: &'a Value, key: &str) -> &'a Value {
    value
        .get(key)
        .unwrap_or_else(|| panic!("reference field `{key}` is missing"))
}

fn text_of<'a>(value: &'a Value, key: &str) -> &'a str {
    field(value, key)
        .as_str()
        .unwrap_or_else(|| panic!("reference field `{key}` is not a string"))
}

fn number(value: &Value, key: &str) -> u64 {
    field(value, key)
        .as_u64()
        .unwrap_or_else(|| panic!("reference field `{key}` is not an unsigned integer"))
}

/// A non-empty array field.
fn rows<'a>(value: &'a Value, key: &str) -> &'a [Value] {
    let rows = field(value, key)
        .as_array()
        .unwrap_or_else(|| panic!("reference field `{key}` is not an array"));
    assert!(!rows.is_empty(), "reference field `{key}` is empty");
    rows
}

/// Bytes of a `0x`-prefixed lowercase hex string.
fn bytes(hex: &str) -> Vec<u8> {
    let digits = hex
        .strip_prefix("0x")
        .unwrap_or_else(|| panic!("`{hex}` lacks its 0x prefix"));
    hex::decode(digits).unwrap_or_else(|error| panic!("`{hex}`: {error}"))
}

fn word(value: &Value, key: &str) -> [u8; 32] {
    bytes(text_of(value, key))
        .try_into()
        .unwrap_or_else(|_| panic!("reference field `{key}` is not 32 bytes"))
}

fn fields_of(value: &Value) -> SccpFinalityHeaderFieldsV1 {
    SccpFinalityHeaderFieldsV1 {
        network_id: word(value, "network_id"),
        height: number(value, "height"),
        timestamp_ms: number(value, "timestamp_ms"),
        flags: u8::try_from(number(value, "flags")).unwrap(),
        message_count: u32::try_from(number(value, "message_count")).unwrap(),
        sccp_root: word(value, "sccp_root"),
        history_size: number(value, "history_size"),
        history_root: word(value, "history_root"),
        generation: number(value, "generation"),
        committee_root: word(value, "committee_root"),
        validity_ms: number(value, "validity_ms"),
        next_committee_root: word(value, "next_committee_root"),
    }
}

/// The non-rotation example of §11.2: the common fields at height 7199.
fn non_rotation_example() -> SccpFinalityHeaderFieldsV1 {
    SccpFinalityHeaderFieldsV1 {
        network_id: [0x11; 32],
        height: 7199,
        timestamp_ms: T0 - 1000,
        flags: FLAG_ACTIVE,
        message_count: 2,
        sccp_root: [0x22; 32],
        history_size: 5,
        history_root: [0x33; 32],
        generation: 3,
        committee_root: [0x44; 32],
        validity_ms: 0,
        next_committee_root: [0; 32],
    }
}

/// The rotation example of §11.2: a key change to `0x55^32` at height 7200.
fn rotation_example() -> SccpFinalityHeaderFieldsV1 {
    SccpFinalityHeaderFieldsV1 {
        height: 7200,
        timestamp_ms: T0,
        flags: FLAG_ACTIVE | FLAG_ROTATION,
        validity_ms: 1_209_600_000,
        next_committee_root: [0x55; 32],
        ..non_rotation_example()
    }
}

/// The heartbeat example of §11.2: the rotation with the committee's own root as successor.
fn heartbeat_example() -> SccpFinalityHeaderFieldsV1 {
    SccpFinalityHeaderFieldsV1 {
        next_committee_root: [0x44; 32],
        ..rotation_example()
    }
}

fn header(fields: &SccpFinalityHeaderFieldsV1) -> SccpFinalityHeaderV1 {
    SccpFinalityHeaderV1::from_fields(fields).unwrap()
}

fn parse_error(fields: &SccpFinalityHeaderFieldsV1) -> FinalityHeaderError {
    SccpFinalityHeaderV1::from_fields(fields).unwrap_err()
}

fn result_hex(result: Hash32) -> String {
    format!("0x{}", hex::encode(result.0))
}

// Local errors are move-only. Compare every deterministic variant and its fields without
// manufacturing equality for an original decoder attempt.
fn assert_certified_error(actual: &CertifiedResultError, expected: &CertifiedResultError) {
    use CertifiedResultError as C;
    match (actual, expected) {
        (C::PreimageLength(a), C::PreimageLength(b)) => assert_eq!(a, b),
        (C::Header(a), C::Header(b)) => assert_eq!(a, b),
        (C::HeightMismatch { header: a, body: b }, C::HeightMismatch { header: c, body: d }) => {
            assert_eq!((a, b), (c, d))
        }
        (C::NetworkMismatch, C::NetworkMismatch)
        | (C::CommitteeRootMismatch, C::CommitteeRootMismatch)
        | (C::RotationMismatch, C::RotationMismatch)
        | (C::ActiveOutsideGlobal, C::ActiveOutsideGlobal)
        | (C::BlockMismatch, C::BlockMismatch) => (),
        (C::Body(a), C::Body(b)) => {
            use CommitmentError as B;
            match (a, b) {
                (B::MissingResult, B::MissingResult)
                | (B::CertifiedBlock, B::CertifiedBlock)
                | (B::NativeLaneState, B::NativeLaneState) => (),
                (B::InvalidOutputs(a), B::InvalidOutputs(b))
                | (B::Schedule(a), B::Schedule(b))
                | (B::Beacon(a), B::Beacon(b))
                | (B::Encoding(a), B::Encoding(b)) => assert_eq!(a, b),
                (B::WireLength(a), B::WireLength(b)) => assert_eq!(a, b),
                (B::PreimageLength(a), B::PreimageLength(b)) => assert_eq!(a, b),
                _ => panic!("expected deterministic body verdict {b:?}, got {a:?}"),
            }
        }
        _ => panic!("expected deterministic result verdict {expected:?}, got {actual:?}"),
    }
}

macro_rules! assert_certified_eq {
    ($actual:expr, $expected:expr $(, $message:expr)* $(,)?) => {{
        match (&$actual, &$expected) {
            (Ok(actual), Ok(expected)) => assert_eq!(actual, expected $(, $message)*),
            (Err(actual), Err(expected)) => assert_certified_error(actual, expected),
            (actual, expected) => panic!("expected {expected:?}, got {actual:?}"),
        }
    }};
}

#[test]
fn finality_header_layout_offsets_are_frozen() {
    let fields = SccpFinalityHeaderFieldsV1 {
        network_id: [0xa1; 32],
        height: 0x0102_0304_0506_0708,
        timestamp_ms: 0x1112_1314_1516_1718,
        flags: FLAG_ACTIVE | FLAG_ROTATION,
        message_count: 0x0102,
        sccp_root: [0xb2; 32],
        history_size: 0x2122_2324,
        history_root: [0xc3; 32],
        generation: 0x3132_3334_3536_3738,
        committee_root: [0xd4; 32],
        validity_ms: 0x4142_4344,
        next_committee_root: [0xe5; 32],
    };
    let parsed = header(&fields);
    let x = parsed.as_bytes();
    assert_eq!((X_LEN, X_HEAD_LEN, X_TAIL_LEN), (221, 109, 112));
    assert_eq!(x.len(), 221);
    assert_eq!(x[0..16], *b"SCCP/FINALITY/V1");
    assert_eq!(x[16..48], [0xa1; 32]);
    assert_eq!(x[48..56], [1, 2, 3, 4, 5, 6, 7, 8]);
    assert_eq!(x[56..64], [0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18]);
    assert_eq!(x[64], 0x03);
    assert_eq!(x[65..69], [0, 0, 1, 2]);
    assert_eq!(x[69..101], [0xb2; 32]);
    assert_eq!(x[101..109], [0, 0, 0, 0, 0x21, 0x22, 0x23, 0x24]);
    assert_eq!(x[109..141], [0xc3; 32]);
    assert_eq!(
        x[141..149],
        [0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38]
    );
    assert_eq!(x[149..181], [0xd4; 32]);
    assert_eq!(x[181..189], [0, 0, 0, 0, 0x41, 0x42, 0x43, 0x44]);
    assert_eq!(x[189..221], [0xe5; 32]);

    // The TON split is at offset 109, between the history size and the history root.
    assert_eq!(parsed.head()[..], x[..109]);
    assert_eq!(parsed.tail()[..], x[109..]);
    assert_eq!(parsed.as_ref(), &x[..]);
    assert_eq!(fields.to_bytes(), *x);

    assert_eq!(parsed.fields(), fields);
    assert_eq!(parsed.network_id(), fields.network_id);
    assert_eq!(parsed.height(), fields.height);
    assert_eq!(parsed.timestamp_ms(), fields.timestamp_ms);
    assert_eq!(parsed.flags(), 0x03);
    assert!(parsed.is_active() && parsed.is_rotation());
    assert_eq!(parsed.message_count(), 258);
    assert_eq!(parsed.sccp_root(), fields.sccp_root);
    assert_eq!(parsed.history_size(), fields.history_size);
    assert_eq!(parsed.history_root(), fields.history_root);
    assert_eq!(parsed.generation(), fields.generation);
    assert_eq!(parsed.committee_root(), fields.committee_root);
    assert_eq!(parsed.validity_ms(), fields.validity_ms);
    assert_eq!(parsed.next_committee_root(), fields.next_committee_root);
}

#[test]
fn finality_constants_match_the_spec_and_the_reference_vectors() {
    assert_eq!(X_MAGIC, b"SCCP/FINALITY/V1");
    assert_eq!((FLAG_ACTIVE, FLAG_ROTATION), (0x01, 0x02));
    assert_eq!(MAX_VALIDITY_MS, 2_592_000_000);
    assert_eq!(MAX_HISTORY_SIZE, 4_294_967_296);
    assert_eq!(RESULT_TAG, b"iroha/sumeragi/result/v1");
    assert_eq!(RESULT_BODY_TAG, b"iroha/sumeragi/result-body/v1");
    assert_eq!(COMMITTEE_TAG, b"SCCP/COMMITTEE/V1");
    assert_eq!(
        (X_MAGIC.len(), RESULT_TAG.len(), RESULT_BODY_TAG.len()),
        (16, 24, 29)
    );
    assert_eq!(COMMITTEE_TAG.len(), 17);
    assert_eq!(SCCP_MESSAGES_MAX_PER_BLOCK_V1, 512);

    let reference = reference();
    let constants = field(&reference, "constants");
    let ascii = |key| text_of(field(constants, key), "ascii").as_bytes();
    assert_eq!(ascii("x_magic"), X_MAGIC);
    assert_eq!(ascii("result_tag"), RESULT_TAG);
    assert_eq!(ascii("result_body_tag"), RESULT_BODY_TAG);
    assert_eq!(
        text_of(constants, "committee_tag").as_bytes(),
        COMMITTEE_TAG
    );
    assert_eq!(number(constants, "x_len"), X_LEN as u64);
    assert_eq!(number(constants, "x_head_len"), X_HEAD_LEN as u64);
    assert_eq!(number(constants, "x_tail_len"), X_TAIL_LEN as u64);
    assert_eq!(number(constants, "max_validity_ms"), MAX_VALIDITY_MS);
    assert_eq!(
        text_of(constants, "max_history_size"),
        MAX_HISTORY_SIZE.to_string()
    );
}

#[test]
fn finality_header_parse_enforces_x1_to_x7() {
    let reference = reference();
    let headers = field(&reference, "headers");

    for row in rows(headers, "valid") {
        let label = text_of(row, "label");
        let x = bytes(text_of(row, "x"));
        let parsed = SccpFinalityHeaderV1::parse(&x)
            .unwrap_or_else(|error| panic!("valid row `{label}` is refused: {error}"));
        let fields = fields_of(field(row, "fields"));
        assert_eq!(parsed.as_bytes()[..], x[..], "{label}");
        assert_eq!(parsed.fields(), fields, "{label}");
        assert_eq!(fields.to_bytes()[..], x[..], "{label}");
        assert_eq!(
            SccpFinalityHeaderV1::from_fields(&fields),
            Ok(parsed),
            "{label}"
        );
        assert_eq!(
            Some(parsed.is_active()),
            field(row, "active").as_bool(),
            "{label}"
        );
        assert_eq!(
            Some(parsed.is_rotation()),
            field(row, "rotation").as_bool(),
            "{label}"
        );
        assert_eq!(
            parsed.head()[..],
            bytes(text_of(row, "x_head"))[..],
            "{label}"
        );
        assert_eq!(
            parsed.tail()[..],
            bytes(text_of(row, "x_tail"))[..],
            "{label}"
        );
        // A destination accepts exactly the active headers.
        let destination = if parsed.is_active() {
            "accept"
        } else {
            "BadHeader"
        };
        assert_eq!(text_of(row, "destination"), destination, "{label}");
    }

    // Every row names the first violated check; the rows are taken as the file lists them,
    // so a new row is covered without a change here.
    let mut seen = BTreeSet::new();
    for row in rows(headers, "invalid") {
        let label = text_of(row, "label");
        let expected = text_of(row, "error");
        match SccpFinalityHeaderV1::parse(&bytes(text_of(row, "x"))) {
            Ok(_) => panic!("invalid row `{label}` parses, expected {expected}"),
            Err(error) => assert_eq!(error.name(), expected, "{label}"),
        }
        assert_eq!(text_of(row, "destination"), "BadHeader", "{label}");
        seen.insert(expected.to_owned());
    }
    let every_check = ["Length", "X1", "X2", "X3", "X4", "X5", "X6", "X7"];
    assert_eq!(
        seen.iter().map(String::as_str).collect::<Vec<_>>(),
        every_check,
        "the reference must exercise the length and every invariant"
    );
}

/// Every check of §3.6 that `x` violates, each evaluated on its own from the raw bytes. It
/// shares no code with the parser, which reports the first one only.
fn violations(x: &[u8]) -> Vec<&'static str> {
    if x.len() != X_LEN {
        return vec!["Length"];
    }
    let u64_at = |offset: usize| u64::from_be_bytes(x[offset..offset + 8].try_into().unwrap());
    let nonzero = |range: std::ops::Range<usize>| x[range].iter().any(|byte| *byte != 0);
    let flags = x[64];
    let (active, rotation) = (flags & FLAG_ACTIVE != 0, flags & FLAG_ROTATION != 0);
    let height = u64_at(48);
    let message_count = u32::from_be_bytes(x[65..69].try_into().unwrap());
    let history_size = u64_at(101);
    let (generation, validity_ms) = (u64_at(141), u64_at(181));
    let mut out = Vec::new();
    if x[..16] != X_MAGIC[..] || flags & 0xfc != 0 {
        out.push("X1");
    }
    if !active && (nonzero(65..X_LEN) || rotation) {
        out.push("X2");
    }
    if active && (generation == 0 || !nonzero(149..181)) {
        out.push("X3");
    }
    if (message_count == 0) == nonzero(69..101) || message_count > 512 {
        out.push("X4");
    }
    if (history_size == 0) == nonzero(109..141) || history_size > MAX_HISTORY_SIZE {
        out.push("X5");
    }
    let x6 = if rotation {
        !nonzero(189..221)
            || validity_ms == 0
            || validity_ms > MAX_VALIDITY_MS
            || height > u64::MAX - 1
            || generation > u64::MAX - 1
    } else {
        validity_ms != 0 || nonzero(189..221)
    };
    if x6 {
        out.push("X6");
    }
    if height == 0 {
        out.push("X7");
    }
    out
}

#[test]
fn reference_headers_pin_the_check_order() {
    let reference = reference();
    let headers = field(&reference, "headers");
    let order = ["Length", "X1", "X2", "X3", "X4", "X5", "X6", "X7"];
    let rank = |name: &str| order.iter().position(|check| *check == name).unwrap();

    for row in rows(headers, "valid") {
        assert!(
            violations(&bytes(text_of(row, "x"))).is_empty(),
            "{}",
            text_of(row, "label")
        );
    }
    // Every invalid row reports the first check it violates, and for each adjacent pair of
    // the order some row violates both, so swapping two checks changes a reported error.
    let mut pairs = BTreeSet::new();
    for row in rows(headers, "invalid") {
        let label = text_of(row, "label");
        let violated = violations(&bytes(text_of(row, "x")));
        let first = violated
            .iter()
            .copied()
            .min_by_key(|name| rank(name))
            .unwrap_or_else(|| panic!("invalid row `{label}` violates nothing"));
        assert_eq!(text_of(row, "error"), first, "{label}: {violated:?}");
        for earlier in &violated {
            for later in &violated {
                if rank(earlier) < rank(later) {
                    pairs.insert((*earlier, *later));
                }
            }
        }
    }
    // X2 needs an inactive header and X3 an active one: each follows X1, and X7 closes both.
    let adjacent = [
        ("X1", "X2"),
        ("X1", "X3"),
        ("X3", "X4"),
        ("X4", "X5"),
        ("X5", "X6"),
        ("X6", "X7"),
        ("X2", "X7"),
    ];
    for pair in adjacent {
        assert!(pairs.contains(&pair), "no row violates both of {pair:?}");
    }
}

#[test]
fn parse_reports_the_first_violated_invariant() {
    // Each case violates the named invariant and every later one that can coexist with it.
    let broken_tail = SccpFinalityHeaderFieldsV1 {
        height: 0,
        message_count: 513,
        history_size: MAX_HISTORY_SIZE + 1,
        validity_ms: 1,
        ..non_rotation_example()
    };

    let mut x1 = SccpFinalityHeaderFieldsV1 {
        generation: 0,
        ..broken_tail
    }
    .to_bytes();
    x1[0] ^= 0x20;
    assert_eq!(
        SccpFinalityHeaderV1::parse(&x1),
        Err(FinalityHeaderError::X1)
    );
    let reserved = SccpFinalityHeaderFieldsV1 {
        flags: FLAG_ACTIVE | 0x04,
        generation: 0,
        ..broken_tail
    };
    assert_eq!(parse_error(&reserved), FinalityHeaderError::X1);

    let x2 = SccpFinalityHeaderFieldsV1 {
        flags: 0,
        ..broken_tail
    };
    assert_eq!(parse_error(&x2), FinalityHeaderError::X2);
    // X1 precedes X2 on an inactive header too: a bad magic, and a reserved flag bit.
    let mut inactive_x1 = x2.to_bytes();
    inactive_x1[0] ^= 0x20;
    assert_eq!(
        SccpFinalityHeaderV1::parse(&inactive_x1),
        Err(FinalityHeaderError::X1)
    );
    let inactive_reserved = SccpFinalityHeaderFieldsV1 { flags: 0x04, ..x2 };
    assert_eq!(parse_error(&inactive_reserved), FinalityHeaderError::X1);
    let x3 = SccpFinalityHeaderFieldsV1 {
        generation: 0,
        ..broken_tail
    };
    assert_eq!(parse_error(&x3), FinalityHeaderError::X3);
    assert_eq!(parse_error(&broken_tail), FinalityHeaderError::X4);
    let x5 = SccpFinalityHeaderFieldsV1 {
        message_count: 2,
        ..broken_tail
    };
    assert_eq!(parse_error(&x5), FinalityHeaderError::X5);
    let x6 = SccpFinalityHeaderFieldsV1 {
        history_size: 5,
        ..x5
    };
    assert_eq!(parse_error(&x6), FinalityHeaderError::X6);
    let x7 = SccpFinalityHeaderFieldsV1 {
        validity_ms: 0,
        ..x6
    };
    assert_eq!(parse_error(&x7), FinalityHeaderError::X7);
    assert_eq!(
        header(&SccpFinalityHeaderFieldsV1 { height: 1, ..x7 }).height(),
        1
    );

    // The length is checked before anything else, whatever the bytes are.
    let valid = non_rotation_example().to_bytes();
    for length in [0, 220, 222] {
        let mut input = valid.to_vec();
        input.resize(length, 0);
        assert_eq!(
            SccpFinalityHeaderV1::parse(&input),
            Err(FinalityHeaderError::Length)
        );
    }

    let names = [
        (FinalityHeaderError::Length, "Length"),
        (FinalityHeaderError::X1, "X1"),
        (FinalityHeaderError::X2, "X2"),
        (FinalityHeaderError::X3, "X3"),
        (FinalityHeaderError::X4, "X4"),
        (FinalityHeaderError::X5, "X5"),
        (FinalityHeaderError::X6, "X6"),
        (FinalityHeaderError::X7, "X7"),
    ];
    for (error, name) in names {
        assert_eq!(error.name(), name);
        assert!(!error.to_string().is_empty());
    }
}

#[test]
fn x4_x5_and_x6_bounds_are_inclusive() {
    let base = rotation_example();
    for (message_count, accepted) in [(1, true), (512, true), (513, false)] {
        let fields = SccpFinalityHeaderFieldsV1 {
            message_count,
            ..base
        };
        assert_eq!(
            SccpFinalityHeaderV1::from_fields(&fields).map_err(FinalityHeaderError::name),
            if accepted {
                Ok(header(&fields))
            } else {
                Err("X4")
            }
        );
    }
    for (history_size, accepted) in [(MAX_HISTORY_SIZE, true), (MAX_HISTORY_SIZE + 1, false)] {
        let fields = SccpFinalityHeaderFieldsV1 {
            history_size,
            ..base
        };
        assert_eq!(
            SccpFinalityHeaderV1::from_fields(&fields).is_ok(),
            accepted,
            "history size {history_size}"
        );
    }
    for (validity_ms, accepted) in [
        (0, false),
        (1, true),
        (MAX_VALIDITY_MS, true),
        (MAX_VALIDITY_MS + 1, false),
    ] {
        let fields = SccpFinalityHeaderFieldsV1 {
            validity_ms,
            ..base
        };
        assert_eq!(
            SccpFinalityHeaderV1::from_fields(&fields).map_err(FinalityHeaderError::name),
            if accepted {
                Ok(header(&fields))
            } else {
                Err("X6")
            }
        );
    }
    // X4 and X5 are equivalences: an empty block and an empty history are valid.
    let empty = SccpFinalityHeaderFieldsV1 {
        message_count: 0,
        sccp_root: [0; 32],
        history_size: 0,
        history_root: [0; 32],
        ..base
    };
    assert!(SccpFinalityHeaderV1::from_fields(&empty).is_ok());
    // A heartbeat names the committee's own root as the successor.
    assert!(header(&heartbeat_example()).is_rotation());
}

#[test]
fn rotation_at_max_height_violates_x6() {
    // The successor generation starts at `height + 1`, so a rotation needs `height ≤ 2^64 − 2`.
    for rotation in [rotation_example(), heartbeat_example()] {
        let last = SccpFinalityHeaderFieldsV1 {
            height: u64::MAX - 1,
            ..rotation
        };
        assert_eq!(header(&last).height(), u64::MAX - 1);
        let overflowing = SccpFinalityHeaderFieldsV1 {
            height: u64::MAX,
            ..rotation
        };
        assert_eq!(parse_error(&overflowing), FinalityHeaderError::X6);
        assert_eq!(
            SccpFinalityHeaderV1::parse(&overflowing.to_bytes()),
            Err(FinalityHeaderError::X6)
        );
    }
    // Only a rotation has a successor: the last height still carries any other header.
    let non_rotation = SccpFinalityHeaderFieldsV1 {
        height: u64::MAX,
        ..non_rotation_example()
    };
    assert_eq!(header(&non_rotation).height(), u64::MAX);
    assert_eq!(
        SccpFinalityHeaderV1::inactive([0x11; 32], u64::MAX, T0)
            .unwrap()
            .height(),
        u64::MAX
    );
}

#[test]
fn rotation_at_max_generation_violates_x6() {
    // The successor is generation `generation + 1`, so a rotation needs `generation ≤ 2^64 − 2`.
    for rotation in [rotation_example(), heartbeat_example()] {
        let last = SccpFinalityHeaderFieldsV1 {
            generation: u64::MAX - 1,
            ..rotation
        };
        assert_eq!(header(&last).generation(), u64::MAX - 1);
        let overflowing = SccpFinalityHeaderFieldsV1 {
            generation: u64::MAX,
            ..rotation
        };
        assert_eq!(parse_error(&overflowing), FinalityHeaderError::X6);
        assert_eq!(
            SccpFinalityHeaderV1::parse(&overflowing.to_bytes()),
            Err(FinalityHeaderError::X6)
        );
        // Both bounds at once are still X6, and both at their last valid value parse.
        let both = SccpFinalityHeaderFieldsV1 {
            height: u64::MAX,
            ..overflowing
        };
        assert_eq!(parse_error(&both), FinalityHeaderError::X6);
        let both_last = SccpFinalityHeaderFieldsV1 {
            height: u64::MAX - 1,
            ..last
        };
        assert!(SccpFinalityHeaderV1::from_fields(&both_last).is_ok());
        // X3, X4 and X5 are reported before X6.
        let earlier = [
            (
                SccpFinalityHeaderFieldsV1 {
                    committee_root: [0; 32],
                    ..overflowing
                },
                FinalityHeaderError::X3,
            ),
            (
                SccpFinalityHeaderFieldsV1 {
                    message_count: 513,
                    ..overflowing
                },
                FinalityHeaderError::X4,
            ),
            (
                SccpFinalityHeaderFieldsV1 {
                    history_root: [0; 32],
                    ..overflowing
                },
                FinalityHeaderError::X5,
            ),
        ];
        for (fields, error) in earlier {
            assert_eq!(parse_error(&fields), error);
        }
    }
    // Only a rotation has a successor: the last generation still certifies any other header.
    let non_rotation = SccpFinalityHeaderFieldsV1 {
        generation: u64::MAX,
        ..non_rotation_example()
    };
    assert_eq!(header(&non_rotation).generation(), u64::MAX);

    // The reference row is exactly this case.
    let reference = reference();
    let row = rows(field(&reference, "headers"), "invalid")
        .iter()
        .find(|row| text_of(row, "label") == "rotation_at_max_generation")
        .expect("the reference row");
    let x = bytes(text_of(row, "x"));
    assert_eq!(x[141..149], [0xff; 8]);
    assert_eq!(x[64], FLAG_ACTIVE | FLAG_ROTATION);
    assert_eq!(
        SccpFinalityHeaderV1::parse(&x),
        Err(FinalityHeaderError::X6)
    );
    assert_eq!(text_of(row, "error"), "X6");
}

#[test]
fn inactive_form_is_zero_after_flags() {
    let inactive = SccpFinalityHeaderV1::inactive([0x11; 32], 9, T0).unwrap();
    let x = inactive.as_bytes();
    assert_eq!(x[..16], *X_MAGIC);
    assert_eq!(x[16..48], [0x11; 32]);
    assert_eq!(x[48..56], 9_u64.to_be_bytes());
    assert_eq!(x[56..64], T0.to_be_bytes());
    assert_eq!(x[64], 0x00);
    assert_eq!(x[65..], [0; 156]);
    assert!(!inactive.is_active() && !inactive.is_rotation());
    assert_eq!(
        inactive.fields(),
        SccpFinalityHeaderFieldsV1 {
            network_id: [0x11; 32],
            height: 9,
            timestamp_ms: T0,
            ..SccpFinalityHeaderFieldsV1::default()
        }
    );
    // The constructor runs `parse`: height 0 is X7, and any time is a time.
    assert_eq!(
        SccpFinalityHeaderV1::inactive([0x11; 32], 0, T0),
        Err(FinalityHeaderError::X7)
    );
    assert!(SccpFinalityHeaderV1::inactive([0; 32], 1, 0).is_ok());
    // Any nonzero byte after the flags of an inactive header is X2.
    for offset in 65..X_LEN {
        let mut dirty = *x;
        dirty[offset] = 1;
        assert_eq!(
            SccpFinalityHeaderV1::parse(&dirty),
            Err(FinalityHeaderError::X2),
            "offset {offset}"
        );
    }
}

#[test]
fn outer_result_matches_spec_worked_examples() {
    let d_body = [0x66; 32];
    let inactive = SccpFinalityHeaderV1::inactive([0x11; 32], 9, T0).unwrap();
    let cases = [
        (
            "rotation",
            header(&rotation_example()),
            "0x3fcdcdfce761808f1a1f633fd209c197738d93032a0c5496ff20fb9bbcd783d7",
        ),
        (
            "heartbeat",
            header(&heartbeat_example()),
            "0xec15d2c034f21de8f6a6192bd246d5ee7acf99ae452c7a70f7c6003b567b1ed4",
        ),
        (
            "non_rotation",
            header(&non_rotation_example()),
            "0x93d642e5cd5e489a395a937a88c63834fceaa8db9ef267e600f70ba58027c9ac",
        ),
        (
            "inactive",
            inactive,
            "0x541b29c5e6058adb34edef96855cb321fdcdc635fc92e4ac25777d1b3ea07b1a",
        ),
    ];
    for (name, x, expected) in &cases {
        assert_eq!(result_hex(outer_result(x, &d_body)), *expected, "{name}");
    }

    // The two `X` byte strings the spec prints.
    let repeated = |byte: &str| byte.repeat(32);
    let rotation_x = [
        "534343502f46494e414c4954592f5631",
        &repeated("11"),
        "0000000000001c20",
        "000001a0c4506c00",
        "03",
        "00000002",
        &repeated("22"),
        "0000000000000005",
        &repeated("33"),
        "0000000000000003",
        &repeated("44"),
        "0000000048190800",
        &repeated("55"),
    ]
    .concat();
    assert_eq!(hex::encode(cases[0].1.as_bytes()), rotation_x);
    let non_rotation_x = [
        "534343502f46494e414c4954592f5631",
        &repeated("11"),
        "0000000000001c1f",
        "000001a0c4506818",
        "01",
        "00000002",
        &repeated("22"),
        "0000000000000005",
        &repeated("33"),
        "0000000000000003",
        &repeated("44"),
        "0000000000000000",
        &repeated("00"),
    ]
    .concat();
    assert_eq!(hex::encode(cases[2].1.as_bytes()), non_rotation_x);

    // The reference vectors carry the same four cases.
    let reference = reference();
    let examples = field(field(&reference, "worked_examples"), "cases");
    for (name, x, expected) in &cases {
        let case = field(examples, name);
        assert_eq!(bytes(text_of(case, "x"))[..], x.as_bytes()[..], "{name}");
        assert_eq!(fields_of(field(case, "fields")), x.fields(), "{name}");
        assert_eq!(word(case, "d_body"), d_body, "{name}");
        assert_eq!(text_of(case, "r"), *expected, "{name}");
    }
}

#[test]
fn outer_result_changes_with_header_and_body_digest() {
    let base = rotation_example();
    let d_body = [0x66; 32];
    let variants = [
        base,
        SccpFinalityHeaderFieldsV1 {
            network_id: [0x12; 32],
            ..base
        },
        SccpFinalityHeaderFieldsV1 {
            height: base.height + 1,
            ..base
        },
        SccpFinalityHeaderFieldsV1 {
            timestamp_ms: base.timestamp_ms + 1,
            ..base
        },
        SccpFinalityHeaderFieldsV1 {
            message_count: base.message_count + 1,
            ..base
        },
        SccpFinalityHeaderFieldsV1 {
            sccp_root: [0x23; 32],
            ..base
        },
        SccpFinalityHeaderFieldsV1 {
            history_size: base.history_size + 1,
            ..base
        },
        SccpFinalityHeaderFieldsV1 {
            history_root: [0x34; 32],
            ..base
        },
        SccpFinalityHeaderFieldsV1 {
            generation: base.generation + 1,
            ..base
        },
        SccpFinalityHeaderFieldsV1 {
            committee_root: [0x45; 32],
            ..base
        },
        SccpFinalityHeaderFieldsV1 {
            validity_ms: base.validity_ms + 1,
            ..base
        },
        SccpFinalityHeaderFieldsV1 {
            next_committee_root: [0x56; 32],
            ..base
        },
        // The flags alone: the same block as a non-rotation.
        SccpFinalityHeaderFieldsV1 {
            flags: FLAG_ACTIVE,
            validity_ms: 0,
            next_committee_root: [0; 32],
            ..base
        },
    ];
    let mut results = BTreeSet::new();
    for fields in &variants {
        let x = header(fields);
        let result = outer_result(&x, &d_body);
        // `R` is SHA-256 over exactly RESULT_TAG ‖ X ‖ D_body.
        let input = [RESULT_TAG, x.as_bytes(), &d_body].concat();
        assert_eq!(input.len(), 24 + 221 + 32);
        assert_eq!(result.0, iroha_crypto::sha256(&input));
        assert!(results.insert(result), "{fields:?} repeats a result");
    }
    // The body digest is bound as well, bit by bit.
    let x = header(&base);
    for bit in [0, 7, 128, 255] {
        let mut other = d_body;
        other[bit / 8] ^= 1 << (bit % 8);
        assert!(results.insert(outer_result(&x, &other)), "bit {bit}");
    }
    assert_eq!(results.len(), variants.len() + 4);
}

#[test]
fn result_is_raw_sha256_without_hash_marker() {
    // The heartbeat `R` of §11.2 ends in 0xd4: its least significant bit is 0, so it is not a
    // marked Iroha hash, and forcing the marker would change it.
    let result = outer_result(&header(&heartbeat_example()), &[0x66; 32]);
    assert_eq!(result.0[31], 0xd4);
    assert_eq!(result.0[31] & 1, 0);
    assert!(Hash::from_marked_bytes(result.0).is_none());
    assert_ne!(<[u8; 32]>::from(Hash::prehashed(result.0)), result.0);

    // `result_of_preimage` returns the same raw digest of the same 277 bytes.
    let x = header(&heartbeat_example());
    let body = b"any body";
    let preimage = [x.as_bytes().as_slice(), body].concat();
    let expected = iroha_crypto::sha256([RESULT_TAG, x.as_bytes(), &body_digest(body)].concat());
    assert_eq!(result_of_preimage(&preimage), Some(Hash32(expected)));
}

#[test]
fn body_digest_is_h_iroha_of_result_body_tag() {
    let body = b"canonical result body";
    let digest = body_digest(body);
    let tagged = [RESULT_BODY_TAG, body].concat();
    assert_eq!(digest, <[u8; 32]>::from(Hash::new(&tagged)));
    // An Iroha hash: the marker bit is set, unlike `R`.
    assert_eq!(digest[31] & 1, 1);
    assert!(Hash::from_marked_bytes(digest).is_some());
    // The tag separates the digest from a bare hash of the body and from the outer tag.
    assert_ne!(digest, <[u8; 32]>::from(Hash::new(body)));
    assert_ne!(
        digest,
        <[u8; 32]>::from(Hash::new([RESULT_TAG, body].concat()))
    );
    assert_ne!(digest, body_digest(b"canonical result body."));

    // `D_body` of every reference row that carries its preimage.
    let reference = reference();
    let mut checked = 0;
    for row in rows(&reference, "result_of_preimage") {
        if let (Some(preimage), Some(d_body)) = (row.get("preimage"), row.get("d_body")) {
            let preimage = bytes(preimage.as_str().unwrap());
            assert_eq!(
                body_digest(&preimage[X_LEN..])[..],
                bytes(d_body.as_str().unwrap())[..],
                "{}",
                text_of(row, "label")
            );
            checked += 1;
        }
    }
    assert!(checked > 0);
}

/// The preimage of one `result_of_preimage` reference row: its bytes, or the stated
/// construction (the `X` of row `one_byte_body` followed by zero bytes up to `preimage_len`).
fn row_preimage(row: &Value, all: &[Value]) -> Vec<u8> {
    if let Some(preimage) = row.get("preimage") {
        return bytes(preimage.as_str().unwrap());
    }
    assert!(text_of(row, "construction").contains("the X of row one_byte_body"));
    let template = all
        .iter()
        .find(|row| text_of(row, "label") == "one_byte_body")
        .expect("the template row");
    let mut preimage = bytes(text_of(template, "preimage"));
    preimage.truncate(X_LEN);
    preimage.resize(usize::try_from(number(row, "preimage_len")).unwrap(), 0);
    preimage
}

#[test]
fn result_of_preimage_bounds_and_unparseable_header_return_none() {
    let reference = reference();
    let all = rows(&reference, "result_of_preimage");
    let (mut some, mut none) = (0, 0);
    for row in all {
        let label = text_of(row, "label");
        let preimage = row_preimage(row, all);
        let result = result_of_preimage(&preimage);
        if field(row, "r").is_null() {
            assert_eq!(result, None, "{label}");
            none += 1;
        } else {
            assert_eq!(
                result.map(result_hex).as_deref(),
                Some(text_of(row, "r")),
                "{label}"
            );
            assert_eq!(
                body_digest(&preimage[X_LEN..])[..],
                bytes(text_of(row, "d_body"))[..],
                "{label}"
            );
            some += 1;
        }
    }
    assert!(some > 0 && none > 0);

    // The bounds, directly: 222 ≤ len ≤ 65 536 and a header that parses.
    let x = header(&non_rotation_example());
    let with_body = |body_len: usize| {
        let mut preimage = x.as_bytes().to_vec();
        preimage.resize(X_LEN + body_len, 0xab);
        preimage
    };
    assert_eq!(result_of_preimage(&[]), None);
    assert_eq!(result_of_preimage(&with_body(0)), None);
    assert_eq!(result_of_preimage(&with_body(0)[..220]), None);
    assert_eq!(
        result_of_preimage(&with_body(1)),
        Some(outer_result(&x, &body_digest(&[0xab])))
    );
    assert!(result_of_preimage(&with_body(MAX_RESULT_BODY_BYTES)).is_some());
    assert_eq!(
        result_of_preimage(&with_body(MAX_RESULT_BODY_BYTES + 1)),
        None
    );
    // Each invariant decides: one that fails gives nothing, whatever the body is.
    for fields in [
        SccpFinalityHeaderFieldsV1 {
            height: 0,
            ..non_rotation_example()
        },
        SccpFinalityHeaderFieldsV1 {
            flags: 0x04 | FLAG_ACTIVE,
            ..non_rotation_example()
        },
        SccpFinalityHeaderFieldsV1 {
            height: u64::MAX,
            ..rotation_example()
        },
        SccpFinalityHeaderFieldsV1 {
            generation: u64::MAX,
            ..rotation_example()
        },
    ] {
        let mut preimage = fields.to_bytes().to_vec();
        preimage.push(0xab);
        assert_eq!(result_of_preimage(&preimage), None, "{fields:?}");
    }
}

#[test]
fn max_result_body_bytes_is_preimage_bound_minus_header() {
    assert_eq!(MAX_RESULT_PREIMAGE_BYTES, 65_536);
    assert_eq!(MAX_RESULT_BODY_BYTES, 65_315);
    assert_eq!(X_LEN + MAX_RESULT_BODY_BYTES, MAX_RESULT_PREIMAGE_BYTES);
    // The reader applies the same bound before it looks at the body.
    let x = header(&non_rotation_example());
    let mut preimage = x.as_bytes().to_vec();
    preimage.resize(MAX_RESULT_PREIMAGE_BYTES + 1, 0);
    assert_certified_eq!(
        CertifiedResultV1::decode(&preimage, CertifiedResultScope::TairaGlobal),
        Err(CertifiedResultError::PreimageLength(
            MAX_RESULT_PREIMAGE_BYTES + 1
        ))
    );
    assert_certified_eq!(
        CertifiedResultV1::decode(x.as_bytes(), CertifiedResultScope::TairaGlobal),
        Err(CertifiedResultError::PreimageLength(X_LEN))
    );
}

#[test]
fn committee_root_matches_spec_example() {
    let keys = [[0x01; 48], [0x02; 48], [0x03; 48], [0x04; 48]];
    let expected = "fe8902a93a6592a748b8528a9f49312e9cbc5d1abcccb1ff7431b0acba92b2b9";
    assert_eq!(hex::encode(committee_root(&keys).unwrap()), expected);
    // keccak256("SCCP/COMMITTEE/V1" ‖ u8 n ‖ keys) over 18 + 48n bytes.
    let preimage = [b"SCCP/COMMITTEE/V1".as_slice(), &[4], keys.as_flattened()].concat();
    assert_eq!(preimage.len(), 18 + 48 * 4);
    assert_eq!(committee_root(&keys), Some(keccak256(&preimage)));

    let reference = reference();
    let synthetic = field(
        field(&reference, "worked_examples"),
        "synthetic_committee_root",
    );
    let listed: Vec<[u8; 48]> = rows(synthetic, "keys")
        .iter()
        .map(|key| bytes(key.as_str().unwrap()).try_into().unwrap())
        .collect();
    assert_eq!(listed, keys);
    assert_eq!(text_of(synthetic, "root"), format!("0x{expected}"));
    // Every committee of the reference, at every size it uses.
    let committees = field(&reference, "committees")
        .as_object()
        .expect("committees by name");
    assert!(!committees.is_empty());
    for (name, committee) in committees {
        let keys: Vec<[u8; 48]> = rows(committee, "keys")
            .iter()
            .map(|key| bytes(key.as_str().unwrap()).try_into().unwrap())
            .collect();
        assert_eq!(number(committee, "n"), keys.len() as u64, "{name}");
        assert_eq!(
            committee_root(&keys),
            Some(word(committee, "root")),
            "{name}"
        );
    }

    // The root binds the order, the count and every key.
    let root = committee_root(&keys);
    let swapped = [keys[1], keys[0], keys[2], keys[3]];
    assert!(committee_root(&swapped).is_some_and(|other| Some(other) != root));
    assert!(committee_root(&keys[..3]).is_some_and(|other| Some(other) != root));
    let mut changed = keys;
    changed[3][47] ^= 1;
    assert!(committee_root(&changed).is_some_and(|other| Some(other) != root));
}

#[test]
fn committee_root_is_defined_for_1_to_255_keys() {
    // The count is one byte: 1 ≤ n ≤ 255, and no list outside that range has a root.
    assert_eq!(committee_root(&[]), None);
    assert_eq!(committee_root(&vec![[0x07; 48]; 256]), None);
    assert_eq!(committee_root(&vec![[0x07; 48]; 257]), None);
    let single = [[0x07; 48]];
    let preimage = [COMMITTEE_TAG, &[1], single.as_flattened()].concat();
    assert_eq!(preimage.len(), 18 + 48);
    assert_eq!(committee_root(&single), Some(keccak256(&preimage)));
    let largest = vec![[0x07; 48]; 255];
    let preimage = [COMMITTEE_TAG, &[255], largest.as_flattened()].concat();
    assert_eq!(preimage.len(), 18 + 48 * 255);
    assert_eq!(committee_root(&largest), Some(keccak256(&preimage)));
    // No root is the zero root, which X3 and X6 forbid in a header.
    for count in [1, 4, 31, 255] {
        assert_ne!(committee_root(&vec![[0; 48]; count]), Some([0; 32]));
    }
}

// ---------------------------------------------------------------------------------------
// `CertifiedResultV1`: real bodies over real BLS committees.
// ---------------------------------------------------------------------------------------

/// A successor that activates another committee at the boundary (a key change).
fn activated(previous: &ValidatorEpochContextV1) -> ValidatorEpochContextV1 {
    let mut next = retained(previous);
    next.committee = fixture(7).committee;
    next.authorization.authority_generation += 1;
    next.authorization.transition_id = [0x61; 32];
    next.authorization.decision = ValidatorEpochDecisionV1::Activate;
    next.authorization.authority_id = next.generation().generation_id().unwrap();
    next.validate_successor(previous).unwrap();
    next
}

/// A valid body at `height` of the four-seat fixture epoch (heights 1..=10); with a
/// successor, the boundary decision at the epoch's last height.
fn body_at(height: u64, successor: Option<ValidatorEpochContextV1>) -> ExecutionResultCommitment {
    let current = fixture(4);
    let params = ChainParamsRecord::from_core(&ChainParams::default());
    let authorized = successor.clone().unwrap_or_else(|| current.clone());
    let slot = |height| {
        ScheduledSlot::Ready(ScheduledConfig {
            height,
            epoch: authorized.clone(),
            params,
        })
    };
    let boundary = successor.map(|next| ValidatorEpochBoundaryV1 {
        version: 1,
        height,
        predecessor_context_id: current.context_id().unwrap(),
        selection_anchor: HashOf::from_untyped_unchecked(Hash::new(
            b"synthetic certified-result boundary parent",
        )),
        next,
        preparation: None,
    });
    let (native_lanes, root) = NativeLaneStateProof::empty_for_testing(current.network_id, height);
    ExecutionResultCommitment::new(
        height,
        ExecutionCommitment {
            parent_state_root: Hash::new(b"certified result prestate"),
            post_state_root: root,
            ordinary_writes_root: root,
            parent_world_state_root: Hash::new(b"fixture parent world"),
            world_state_root: Hash::new(b"fixture world"),
            event_commitment: None,
            executed_block_wire_len: 1,
            executed_block_wire_hash: Hash::new(b"synthetic codec result, not executed World"),
            transaction_input_commitment: None,
            transaction_output_commitment: None,
        },
        ScheduleOutcome {
            height,
            boundary,
            next: slot(height + 1),
            after_next: slot(height + 2),
            current,
        },
        None,
        native_lanes,
    )
    .unwrap()
}

fn network_of(body: &ExecutionResultCommitment) -> [u8; 32] {
    *body.schedule.current.network_id.as_bytes()
}

fn current_root(body: &ExecutionResultCommitment) -> [u8; 32] {
    context_committee_root(&body.schedule.current).unwrap()
}

/// An active, non-rotating header that matches `body` (C1–C3).
fn active_fields(body: &ExecutionResultCommitment) -> SccpFinalityHeaderFieldsV1 {
    SccpFinalityHeaderFieldsV1 {
        network_id: network_of(body),
        height: body.height,
        timestamp_ms: T0,
        flags: FLAG_ACTIVE,
        generation: 1,
        committee_root: current_root(body),
        ..SccpFinalityHeaderFieldsV1::default()
    }
}

/// The same header rotating to `successor`.
fn rotating_fields(
    body: &ExecutionResultCommitment,
    successor: [u8; 32],
) -> SccpFinalityHeaderFieldsV1 {
    SccpFinalityHeaderFieldsV1 {
        flags: FLAG_ACTIVE | FLAG_ROTATION,
        validity_ms: 1_209_600_000,
        next_committee_root: successor,
        ..active_fields(body)
    }
}

fn inactive_for(body: &ExecutionResultCommitment) -> SccpFinalityHeaderV1 {
    SccpFinalityHeaderV1::inactive(network_of(body), body.height, T0).unwrap()
}

/// One body with its canonical bytes and the epoch validation work shared by its readers.
struct Stored {
    body: ExecutionResultCommitment,
    bytes: Vec<u8>,
    validation: EpochValidationScope,
}

impl Stored {
    fn new(body: ExecutionResultCommitment) -> Self {
        let bytes = norito::encode_canonical(&body).unwrap();
        Self {
            body,
            bytes,
            validation: EpochValidationScope::new(),
        }
    }

    fn preimage(&self, x: &SccpFinalityHeaderV1) -> Vec<u8> {
        [x.as_bytes().as_slice(), &self.bytes].concat()
    }

    fn decode(
        &mut self,
        x: &SccpFinalityHeaderV1,
        scope: CertifiedResultScope,
    ) -> Result<CertifiedResultV1, CertifiedResultError> {
        let preimage = self.preimage(x);
        CertifiedResultV1::decode_with_validation(&preimage, scope, &mut self.validation)
    }

    /// Decode under the global scope and require the verdict; an accepted pair must also
    /// reproduce its header, its body and `R`.
    fn expect(
        &mut self,
        fields: &SccpFinalityHeaderFieldsV1,
        verdict: Result<(), CertifiedResultError>,
    ) {
        let x = header(fields);
        match (self.decode(&x, TairaGlobal), verdict) {
            (Ok(value), Ok(())) => {
                assert_eq!(value.header(), &x);
                assert_eq!(value.commitment(), &self.body);
                assert_eq!(value.preimage().unwrap(), self.preimage(&x));
                assert_eq!(
                    value.result().unwrap(),
                    result_of_preimage(&self.preimage(&x)).unwrap()
                );
            }
            (Err(error), Err(expected)) => assert_certified_error(&error, &expected),
            (decoded, verdict) => panic!("{fields:?}: expected {verdict:?}, decoded {decoded:?}"),
        }
    }
}

#[test]
fn context_committee_root_hashes_the_context_keys_in_order() {
    let context = fixture(4);
    let keys: Vec<[u8; 48]> = context
        .committee
        .iter()
        .map(|member| {
            let (algorithm, key) = member.validator.public_key().to_bytes();
            assert_eq!(algorithm, Algorithm::BlsNormal);
            key.try_into().unwrap()
        })
        .collect();
    assert!(keys.is_sorted());
    assert!(context_committee_root(&context).is_some());
    assert_eq!(context_committee_root(&context), committee_root(&keys));
    // Retention keeps the committee, so the root; an activation changes both.
    assert_eq!(
        context_committee_root(&retained(&context)),
        context_committee_root(&context)
    );
    assert_ne!(
        context_committee_root(&activated(&context)),
        context_committee_root(&context)
    );
    // A committee without a member has no root, like any list `committee_root` cannot name.
    let mut empty = context.clone();
    empty.committee.clear();
    assert_eq!(context_committee_root(&empty), None);
    // A member that is not a BLS-normal key has no committee root.
    let mut foreign = context;
    let ed25519 = KeyPair::try_from_seed(vec![9; 32], Algorithm::Ed25519).unwrap();
    foreign.committee[0].validator = PeerId::new(ed25519.public_key().clone());
    assert_eq!(context_committee_root(&foreign), None);
}

#[test]
fn context_root_streaming_preserves_the_entire_count_domain() {
    let mut context = fixture(4);
    let member = context.committee[0].clone();
    let (_, bytes) = member.validator.public_key().try_to_bytes().unwrap();
    let key: [u8; 48] = bytes.try_into().unwrap();
    for count in [1, 4, 31, 254, 255, 256] {
        context.committee = vec![member.clone(); count];
        assert_eq!(
            context_committee_root(&context),
            committee_root(&vec![key; count])
        );
    }
}

#[test]
fn certified_result_decode_checks_c1_to_c4_and_scope() {
    let mut plain = Stored::new(body_at(5, None));
    let active = active_fields(&plain.body);
    let root = current_root(&plain.body);
    let other_root = [0x5a; 32];

    // Inactive `X` is accepted under both scopes.
    let inactive = inactive_for(&plain.body);
    for scope in [TairaGlobal, NonGlobal] {
        let decoded = plain.decode(&inactive, scope).unwrap();
        assert_eq!(decoded.header(), &inactive);
        assert_eq!(decoded.commitment(), &plain.body);
        let (x, body) = decoded.into_parts();
        assert_eq!((x, &body), (inactive, &plain.body));
    }

    // Scope: an active `X` belongs to the global chain only, whatever else holds.
    assert!(plain.decode(&header(&active), TairaGlobal).is_ok());
    assert_certified_eq!(
        plain.decode(&header(&active), NonGlobal),
        Err(CertifiedResultError::ActiveOutsideGlobal)
    );

    // C1: the header must parse, and name the body's height.
    let mut unparseable = plain.preimage(&inactive);
    unparseable[0] ^= 0x20;
    assert_certified_eq!(
        CertifiedResultV1::decode(&unparseable, TairaGlobal),
        Err(CertifiedResultError::Header(FinalityHeaderError::X1))
    );
    for base in [inactive.fields(), active] {
        plain.expect(
            &SccpFinalityHeaderFieldsV1 { height: 6, ..base },
            Err(CertifiedResultError::HeightMismatch { header: 6, body: 5 }),
        );
        // C2: the network of the epoch context the schedule assigns to that height.
        let mut network_id = base.network_id;
        network_id[0] ^= 1;
        plain.expect(
            &SccpFinalityHeaderFieldsV1 { network_id, ..base },
            Err(CertifiedResultError::NetworkMismatch),
        );
    }

    // C3: an active header names the root of exactly that context's committee.
    plain.expect(&active, Ok(()));
    plain.expect(
        &SccpFinalityHeaderFieldsV1 {
            committee_root: other_root,
            ..active
        },
        Err(CertifiedResultError::CommitteeRootMismatch),
    );
    plain.expect(
        &SccpFinalityHeaderFieldsV1 {
            committee_root: context_committee_root(&activated(&plain.body.schedule.current))
                .unwrap(),
            ..active
        },
        Err(CertifiedResultError::CommitteeRootMismatch),
    );

    // C4 without a boundary decision in the body: a heartbeat is the only rotation.
    plain.expect(&rotating_fields(&plain.body, root), Ok(()));
    plain.expect(
        &rotating_fields(&plain.body, other_root),
        Err(CertifiedResultError::RotationMismatch),
    );

    // C4 with a boundary that retains the committee: the same, with or without a heartbeat.
    let current = fixture(4);
    let mut retaining = Stored::new(body_at(10, Some(retained(&current))));
    assert_eq!(current_root(&retaining.body), root);
    retaining.expect(&active_fields(&retaining.body), Ok(()));
    retaining.expect(&rotating_fields(&retaining.body, root), Ok(()));
    retaining.expect(
        &rotating_fields(&retaining.body, other_root),
        Err(CertifiedResultError::RotationMismatch),
    );

    // C4 with a boundary that changes the keys: a rotation to exactly the successor's root.
    let successor = activated(&current);
    let successor_root = context_committee_root(&successor).unwrap();
    assert_ne!(successor_root, root);
    let mut changing = Stored::new(body_at(10, Some(successor)));
    changing.expect(&rotating_fields(&changing.body, successor_root), Ok(()));
    changing.expect(
        &active_fields(&changing.body),
        Err(CertifiedResultError::RotationMismatch),
    );
    changing.expect(
        &rotating_fields(&changing.body, root),
        Err(CertifiedResultError::RotationMismatch),
    );
    changing.expect(
        &rotating_fields(&changing.body, other_root),
        Err(CertifiedResultError::RotationMismatch),
    );
    // C3 is checked before C4, and an inactive header carries no committee claim at all.
    changing.expect(
        &SccpFinalityHeaderFieldsV1 {
            committee_root: successor_root,
            ..rotating_fields(&changing.body, successor_root)
        },
        Err(CertifiedResultError::CommitteeRootMismatch),
    );
    let inactive = inactive_for(&changing.body);
    for scope in [TairaGlobal, NonGlobal] {
        assert!(changing.decode(&inactive, scope).is_ok());
    }
}

#[test]
fn certified_result_check_order_is_pinned() {
    // Each input fails the named check and a later one; the earlier one is reported.
    let mut stored = Stored::new(body_at(5, None));
    let body = stored.body.clone();
    let active = active_fields(&body);
    let inactive = inactive_for(&body).fields();
    let mut other_network = active.network_id;
    other_network[0] ^= 1;
    let other_root = [0x5a; 32];

    // 1. The preimage length, before the header is read.
    assert_certified_eq!(
        CertifiedResultV1::decode(&[0; X_LEN], NonGlobal),
        Err(CertifiedResultError::PreimageLength(X_LEN))
    );
    assert_certified_eq!(
        CertifiedResultV1::decode(&vec![0; MAX_RESULT_PREIMAGE_BYTES + 1], NonGlobal),
        Err(CertifiedResultError::PreimageLength(
            MAX_RESULT_PREIMAGE_BYTES + 1
        ))
    );

    // 2. The header parse, before the scope rule: an active header with a reserved flag bit.
    let reserved = SccpFinalityHeaderFieldsV1 {
        flags: FLAG_ACTIVE | 0x04,
        ..active
    };
    let preimage = [reserved.to_bytes().as_slice(), &stored.bytes].concat();
    assert_certified_eq!(
        CertifiedResultV1::decode(&preimage, NonGlobal),
        Err(CertifiedResultError::Header(FinalityHeaderError::X1))
    );

    // 3. The scope rule, before the body is decoded: an active header over bytes that are no
    //    body.
    let no_body = [header(&active).as_bytes().as_slice(), &[0xff; 40]].concat();
    assert_certified_eq!(
        CertifiedResultV1::decode(&no_body, NonGlobal),
        Err(CertifiedResultError::ActiveOutsideGlobal)
    );
    assert!(matches!(
        CertifiedResultV1::decode(&no_body, TairaGlobal),
        Err(CertifiedResultError::Body(_))
    ));

    // 4. The body decode and the body's own validation, before C1: a header of another height.
    let wrong_height = header(&SccpFinalityHeaderFieldsV1 {
        height: 6,
        ..inactive
    });
    let truncated = stored.preimage(&wrong_height);
    assert!(matches!(
        CertifiedResultV1::decode(&truncated[..truncated.len() - 1], NonGlobal),
        Err(CertifiedResultError::Body(CommitmentError::Encoding(_)))
    ));
    let mut invalid = body.clone();
    invalid.execution.executed_block_wire_len = 0;
    let invalid_bytes = norito::encode_canonical(&invalid).unwrap();
    assert_certified_eq!(
        CertifiedResultV1::decode(
            &[wrong_height.as_bytes().as_slice(), &invalid_bytes].concat(),
            NonGlobal
        ),
        Err(CertifiedResultError::Body(CommitmentError::WireLength(0)))
    );
    // `new` runs the same order from the scope rule on.
    assert_certified_eq!(
        CertifiedResultV1::new(wrong_height, invalid.clone(), NonGlobal),
        Err(CertifiedResultError::Body(CommitmentError::WireLength(0)))
    );
    assert_certified_eq!(
        CertifiedResultV1::new(header(&active), invalid, NonGlobal),
        Err(CertifiedResultError::ActiveOutsideGlobal)
    );

    // 5. C1 before C2: another height and another network.
    stored.expect(
        &SccpFinalityHeaderFieldsV1 {
            height: 6,
            network_id: other_network,
            ..active
        },
        Err(CertifiedResultError::HeightMismatch { header: 6, body: 5 }),
    );
    // 6. C2 before C3: another network and another committee root.
    stored.expect(
        &SccpFinalityHeaderFieldsV1 {
            network_id: other_network,
            committee_root: other_root,
            ..active
        },
        Err(CertifiedResultError::NetworkMismatch),
    );
    // 7. C3 before C4: another committee root and a key change the body does not carry.
    stored.expect(
        &SccpFinalityHeaderFieldsV1 {
            committee_root: other_root,
            ..rotating_fields(&body, [0x5b; 32])
        },
        Err(CertifiedResultError::CommitteeRootMismatch),
    );
    // 8. C4 is the last check.
    stored.expect(
        &rotating_fields(&body, [0x5b; 32]),
        Err(CertifiedResultError::RotationMismatch),
    );
    stored.expect(&active, Ok(()));
}

#[test]
fn certified_result_new_applies_the_reader_checks() {
    let body = body_at(5, None);
    let active = active_fields(&body);
    let bind = |fields: &SccpFinalityHeaderFieldsV1, scope| {
        CertifiedResultV1::new(header(fields), body.clone(), scope).map(|value| {
            assert_eq!(value.header(), &header(fields));
            assert_eq!(value.commitment(), &body);
        })
    };
    assert_certified_eq!(bind(&active, TairaGlobal), Ok(()));
    assert_certified_eq!(bind(&inactive_for(&body).fields(), NonGlobal), Ok(()));
    assert_certified_eq!(
        bind(&active, NonGlobal),
        Err(CertifiedResultError::ActiveOutsideGlobal)
    );
    assert_certified_eq!(
        bind(
            &SccpFinalityHeaderFieldsV1 {
                height: 4,
                ..active
            },
            TairaGlobal
        ),
        Err(CertifiedResultError::HeightMismatch { header: 4, body: 5 })
    );
    assert_certified_eq!(
        bind(
            &SccpFinalityHeaderFieldsV1 {
                network_id: [0x11; 32],
                ..active
            },
            TairaGlobal
        ),
        Err(CertifiedResultError::NetworkMismatch)
    );
    assert_certified_eq!(
        bind(
            &SccpFinalityHeaderFieldsV1 {
                committee_root: [0x5a; 32],
                ..active
            },
            TairaGlobal
        ),
        Err(CertifiedResultError::CommitteeRootMismatch)
    );
    assert_certified_eq!(
        bind(&rotating_fields(&body, [0x5a; 32]), TairaGlobal),
        Err(CertifiedResultError::RotationMismatch)
    );
}

#[test]
fn certified_result_assembles_without_checks_and_validates_afterwards() {
    let body = body_at(5, None);
    let active = active_fields(&body);
    // The assembler is a move: it takes any header with any body and never fails.
    let cases = [
        (active, TairaGlobal, Ok(())),
        (inactive_for(&body).fields(), NonGlobal, Ok(())),
        (inactive_for(&body).fields(), TairaGlobal, Ok(())),
        (
            active,
            NonGlobal,
            Err(CertifiedResultError::ActiveOutsideGlobal),
        ),
        (
            SccpFinalityHeaderFieldsV1 {
                height: 4,
                ..active
            },
            TairaGlobal,
            Err(CertifiedResultError::HeightMismatch { header: 4, body: 5 }),
        ),
        (
            SccpFinalityHeaderFieldsV1 {
                network_id: [0x11; 32],
                ..active
            },
            TairaGlobal,
            Err(CertifiedResultError::NetworkMismatch),
        ),
        (
            SccpFinalityHeaderFieldsV1 {
                committee_root: [0x5a; 32],
                ..active
            },
            TairaGlobal,
            Err(CertifiedResultError::CommitteeRootMismatch),
        ),
        (
            rotating_fields(&body, [0x5a; 32]),
            TairaGlobal,
            Err(CertifiedResultError::RotationMismatch),
        ),
    ];
    for (fields, scope, verdict) in cases {
        let assembled = CertifiedResultV1::from_parts_unvalidated(header(&fields), body.clone());
        assert_eq!(assembled.header(), &header(&fields));
        assert_eq!(assembled.commitment(), &body);
        assert_certified_eq!(assembled.validate(scope), verdict);
        assert_certified_eq!(
            assembled.validate_with_validation(scope, &mut EpochValidationScope::new()),
            verdict
        );
        // `new` is the assembler followed by the check, and returns the same value.
        match (
            CertifiedResultV1::new(header(&fields), body.clone(), scope),
            &verdict,
        ) {
            (Ok(value), Ok(())) => assert_eq!(value, assembled),
            (Err(actual), Err(expected)) => assert_certified_error(&actual, expected),
            (actual, expected) => panic!("expected {expected:?}, got {actual:?}"),
        }
        // A value that validates is the one `decode` reads back from its preimage.
        if verdict.is_ok() {
            let preimage = assembled.preimage().unwrap();
            assert_certified_eq!(CertifiedResultV1::decode(&preimage, scope), Ok(assembled));
        }
    }

    // The body's own validation is part of the check: an invalid body under a header that
    // agrees with it in every bound field is refused as a body, after the scope rule.
    let mut broken = body.clone();
    broken.schedule.height = 6;
    let assembled = CertifiedResultV1::from_parts_unvalidated(header(&active), broken);
    assert!(matches!(
        assembled.validate(TairaGlobal),
        Err(CertifiedResultError::Body(_))
    ));
    assert_certified_eq!(
        assembled.validate(NonGlobal),
        Err(CertifiedResultError::ActiveOutsideGlobal)
    );
    // One validation scope serves several values of a walk.
    let mut validation = EpochValidationScope::new();
    for _ in 0..2 {
        let assembled = CertifiedResultV1::from_parts_unvalidated(header(&active), body.clone());
        assert_certified_eq!(
            assembled.validate_with_validation(TairaGlobal, &mut validation),
            Ok(())
        );
    }
}

#[test]
fn certified_result_body_bound_is_checked_before_a_value_is_accepted() {
    // The bound itself: `MAX_RESULT_BODY_BYTES` is the largest body, and the error names the
    // preimage length the body would give.
    assert_certified_eq!(check_body_len(0), Ok(()));
    assert_certified_eq!(check_body_len(MAX_RESULT_BODY_BYTES), Ok(()));
    assert_certified_eq!(
        check_body_len(MAX_RESULT_BODY_BYTES + 1),
        Err(CertifiedResultError::PreimageLength(
            MAX_RESULT_PREIMAGE_BYTES + 1
        ))
    );
    assert_certified_eq!(
        check_body_len(usize::MAX),
        Err(CertifiedResultError::PreimageLength(usize::MAX))
    );
    // `validate`, `new` and `preimage` measure the same canonical length and apply it.
    let body = body_at(5, None);
    let value =
        CertifiedResultV1::new(header(&active_fields(&body)), body.clone(), TairaGlobal).unwrap();
    let body_len = norito::canonical_frame_len(&body).unwrap();
    assert_certified_eq!(value.body_len(), Ok(body_len));
    assert_eq!(value.preimage().unwrap().len(), X_LEN + body_len);
    assert!(body_len <= MAX_RESULT_BODY_BYTES);
}

#[test]
fn certified_result_decode_rejects_malformed_bodies_and_keeps_local_refusals() {
    let stored = Stored::new(body_at(5, None));
    let x = inactive_for(&stored.body);
    let preimage = stored.preimage(&x);
    let decoded = CertifiedResultV1::decode(&preimage, NonGlobal).unwrap();
    assert_eq!(decoded.commitment(), &stored.body);

    // A truncated or extended body is not one canonical frame.
    let mut extended = preimage.clone();
    extended.push(0);
    for malformed in [&preimage[..preimage.len() - 1], &extended[..]] {
        assert!(matches!(
            CertifiedResultV1::decode(malformed, NonGlobal),
            Err(CertifiedResultError::Body(CommitmentError::Encoding(_)))
        ));
    }
    // An invalid body is refused by the body's own validation.
    let mut invalid = stored.body.clone();
    invalid.execution.executed_block_wire_len = 0;
    let invalid_bytes = norito::encode_canonical(&invalid).unwrap();
    assert_certified_eq!(
        CertifiedResultV1::decode(
            &[x.as_bytes().as_slice(), &invalid_bytes].concat(),
            NonGlobal
        ),
        Err(CertifiedResultError::Body(CommitmentError::WireLength(0)))
    );
    assert_certified_eq!(
        CertifiedResultV1::new(x, invalid, NonGlobal),
        Err(CertifiedResultError::Body(CommitmentError::WireLength(0)))
    );

    // The consumer runs once, after every check, and never for a rejected preimage.
    let mut calls = 0;
    let height = CertifiedResultV1::decode_with_validation_into(
        &preimage,
        NonGlobal,
        &mut EpochValidationScope::new(),
        |value| {
            calls += 1;
            value.commitment().height
        },
    );
    assert_certified_eq!(height, Ok(5));
    assert_eq!(calls, 1);
    let wrong_height = SccpFinalityHeaderV1::inactive(network_of(&stored.body), 6, T0).unwrap();
    let rejected = CertifiedResultV1::decode_with_validation_into(
        &stored.preimage(&wrong_height),
        NonGlobal,
        &mut EpochValidationScope::new(),
        |_| calls += 1,
    );
    assert_certified_eq!(
        rejected,
        Err(CertifiedResultError::HeightMismatch { header: 6, body: 5 })
    );
    assert_eq!(calls, 1);

    // A refusal of the caller's decoder budget stays a local resource error, not a verdict.
    let limits = norito::DecodeLimits::new(
        96,
        MAX_RESULT_PREIMAGE_BYTES,
        norito::canonical_decode_limits(MAX_RESULT_PREIMAGE_BYTES).max_total_elements(),
        0,
        32,
    );
    let refused = norito::with_decode_limits_scope(limits, || {
        CertifiedResultV1::decode(&preimage, NonGlobal)
    });
    assert!(matches!(
        refused,
        Err(CertifiedResultError::Body(CommitmentError::Resource(_)))
    ));
    assert_certified_eq!(CertifiedResultV1::decode(&preimage, NonGlobal), Ok(decoded));
}

#[test]
fn certified_result_preimage_and_result_round_trip() {
    let body = body_at(5, None);
    let x = header(&active_fields(&body));
    let value = CertifiedResultV1::new(x, body.clone(), TairaGlobal).unwrap();
    let preimage = value.preimage().unwrap();
    assert_eq!(preimage[..X_LEN], x.as_bytes()[..]);
    assert_eq!(
        preimage[X_LEN..],
        norito::encode_canonical(&body).unwrap()[..]
    );
    assert!(preimage.len() <= MAX_RESULT_PREIMAGE_BYTES);
    assert_certified_eq!(
        CertifiedResultV1::decode(&preimage, TairaGlobal),
        Ok(value.clone())
    );

    let result = value.result().unwrap();
    assert_eq!(Some(result), result_of_preimage(&preimage));
    assert_eq!(result, outer_result(&x, &body_digest(&preimage[X_LEN..])));
    // The public R function accepts only X ‖ body; there is no body-only result path.
    assert_eq!(
        crate::sumeragi_finality::result_of_preimage(&preimage),
        Some(result)
    );
    assert_eq!(
        crate::sumeragi_finality::result_of_preimage(&preimage[X_LEN..]),
        None
    );
    // The same body under another header is another result.
    let inactive = CertifiedResultV1::new(inactive_for(&body), body, NonGlobal).unwrap();
    assert_ne!(inactive.result().unwrap(), result);
}

#[test]
fn certified_result_check_block_enforces_c5() {
    let body = body_at(5, None);
    for x in [inactive_for(&body), header(&active_fields(&body))] {
        let value = CertifiedResultV1::new(x, body.clone(), TairaGlobal).unwrap();
        assert_certified_eq!(value.check_block(5, T0), Ok(()));
        // The block height and the block time are both bound, to the millisecond.
        for (height, timestamp_ms) in [(4, T0), (6, T0), (5, T0 - 1), (5, T0 + 1), (0, 0)] {
            assert_certified_eq!(
                value.check_block(height, timestamp_ms),
                Err(CertifiedResultError::BlockMismatch),
                "block {height} at {timestamp_ms}"
            );
        }
    }
}

#[test]
fn certified_result_scope_maps_the_selected_signed_root_kind() {
    use crate::block::consensus::SumeragiRootScope;
    assert_eq!(
        CertifiedResultScope::from(SumeragiRootScope::Global),
        CertifiedResultScope::TairaGlobal
    );
    let scope = SumeragiRootScope::Dataspace {
        parent_network_id: crate::NetworkId::from_genesis_hash(HashOf::from_untyped_unchecked(
            Hash::new(b"scope parent"),
        )),
        dataspace_id: iroha_model_base::topology::DataSpaceId::new(19),
    };
    assert_eq!(
        CertifiedResultScope::from(scope),
        CertifiedResultScope::NonGlobal
    );
}
