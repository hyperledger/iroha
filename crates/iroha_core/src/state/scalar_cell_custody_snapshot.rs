//! Allocation-free decoding of the exact persisted u64 Cell layout.

use norito::json::{Error, Parser};

/// Decode both retained cuts with the exact bytes emitted by MV's Cell codec.
/// No map, temporary string, payload copy or comparison serialization is needed.
pub(crate) fn decode_snapshot(source: &str) -> Result<(u64, Option<u64>), Error> {
    let mut parser = Parser::new(source);
    literal(&mut parser, b"{\"revert\":")?;
    let revert = if parser.peek() == Some(b'n') {
        parser.parse_null()?;
        None
    } else {
        literal(&mut parser, b"{\"value\":")?;
        let value = integer(&mut parser)?;
        literal(&mut parser, b"}")?;
        Some(value)
    };
    literal(&mut parser, b",\"blocks\":")?;
    let blocks = integer(&mut parser)?;
    literal(&mut parser, b"}")?;
    if !parser.eof() {
        return Err(noncanonical(&parser));
    }
    Ok((blocks, revert))
}

fn integer(parser: &mut Parser<'_>) -> Result<u64, Error> {
    // Norito rejects leading zeros and overflow. Its ordinary number API permits
    // leading whitespace, which is excluded from this signed canonical layout.
    if !parser.peek().is_some_and(|byte| byte.is_ascii_digit()) {
        return Err(noncanonical(parser));
    }
    parser.parse_u64()
}

fn literal(parser: &mut Parser<'_>, expected: &[u8]) -> Result<(), Error> {
    for byte in expected {
        if parser.bump() != Some(*byte) {
            return Err(noncanonical(parser));
        }
    }
    Ok(())
}

fn noncanonical(parser: &Parser<'_>) -> Error {
    let byte = parser.position();
    let (mut line, mut col) = (1, 1);
    for byte in parser.input().as_bytes().iter().take(byte) {
        if *byte == b'\n' {
            line += 1;
            col = 1;
        } else {
            col += 1;
        }
    }
    Error::WithPos {
        msg: "noncanonical scalar Cell snapshot",
        byte,
        line,
        col,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use iroha_allocation::AllocationBudget;
    use mv::cell::CellInitialization;

    #[test]
    fn complete_layout_matches_actual_charged_cell_codec_and_both_cuts() {
        for current in [0, 1, 10, u64::MAX / 2, u64::MAX] {
            for previous in [None, Some(0), Some(1), Some(u64::MAX)] {
                let bytes = CellInitialization::<u64>::allocation_layouts()
                    .into_iter()
                    .map(|layout| layout.size())
                    .sum();
                let source = AllocationBudget::new(bytes);
                let cell = CellInitialization::try_reserve(&source)
                    .unwrap()
                    .initialize(current, previous);
                let encoded = norito::json::to_json(&cell).unwrap();
                assert_eq!(decode_snapshot(&encoded).unwrap(), (current, previous));
                assert_eq!(*cell.view().get(), current);
                assert_eq!(*cell.predecessor_view().get(), previous);
                assert_eq!(source.reserved_bytes(), bytes);
            }
        }
    }

    #[test]
    fn rejects_noncanonical_shape_values_and_every_truncation() {
        for source in [
            r#"{"revert":6,"blocks":9}"#,
            r#"{"revert":{},"blocks":9}"#,
            r#"{"revert":{"value":6,"value":6},"blocks":9}"#,
            r#"{"revert":{"value":6,"extra":0},"blocks":9}"#,
            r#"{"blocks":9,"revert":{"value":6}}"#,
            r#"{"revert":{"value":6},"blocks":9,"extra":0}"#,
            r#"{"revert":{"value":6},"blocks":9,"blocks":9}"#,
            r#"{"revert":{"value":6},"revert":{"value":6},"blocks":9}"#,
            r#"{"revert":{"value":6}}"#,
            r#"{"blocks":9}"#,
            r#"{"revert":{"value":6},"blocks":null}"#,
            r#"{"revert":{"value":true},"blocks":9}"#,
            r#"{"revert":{"value":"6"},"blocks":9}"#,
            r#"{"revert":{"value":6},"blocks":"9"}"#,
            r#"{"revert":{"value":+6},"blocks":9}"#,
            r#"{"revert":{"value":-0},"blocks":9}"#,
            r#"{"revert":{"value":6},"blocks":-1}"#,
            r#"{"revert":{"value":06},"blocks":9}"#,
            r#"{"revert":{"value":6},"blocks":09}"#,
            r#"{"revert":{"value":6.0},"blocks":9}"#,
            r#"{"revert":{"value":6},"blocks":9e0}"#,
            r#"{"revert":{"value":18446744073709551616},"blocks":9}"#,
            r#"{"revert":{"value":6},"blocks":18446744073709551616}"#,
            r#"{"revert":{"value": 6},"blocks":9}"#,
            r#"{"revert": null,"blocks":9}"#,
            r#"{"revert":{"value":6},"blocks": 9}"#,
            r#"{"revert":{"value":6} ,"blocks":9}"#,
            r#" {"revert":{"value":6},"blocks":9}"#,
            r#"{"revert":{"value":6},"blocks":9} "#,
            r#"{"revert":{"value":6},"blocks":9}{}"#,
            r#"{"revert":{"value":６},"blocks":9}"#,
            r#"{"re\u0076ert":{"value":6},"blocks":9}"#,
            r#"{"revert":nullx,"blocks":9}"#,
            r"[6,9]",
            "null",
            "{}",
        ] {
            assert!(decode_snapshot(source).is_err(), "accepted {source}");
        }
        let valid = r#"{"revert":{"value":18446744073709551615},"blocks":9}"#;
        for length in 0..valid.len() {
            assert!(decode_snapshot(&valid[..length]).is_err());
        }
    }
}
