//! Canonical serialisation of a table set to `u64` words, and its rendering as Rust
//! source.
//!
//! # Word format
//! `MAGIC, lambda, tau, w_grind, n_mult`, then the `tau` tree moduli (one word
//! each), `M_TREE` in `ceil((n_delta + 1) / 64)` words, and the tables `F`, `G`,
//! `W_TREE`, `W_GATE`, `W_CRT`, each as its rows in order with `ceil(width / 64)`
//! words per row. The header fixes every length, and the decoder accepts exactly
//! that many words.
//!
//! # Rust source
//! The crate embeds the eight table sets as generated Rust source, one file per
//! profile under `src/crt/generated/`, each a module of [`super::generated`]:
//! [`write_rust_source`] renders the scalars as constants and each table as one
//! static array of `u64`.

use std::fmt::Write as _;

use super::{
    bits::index,
    error::CrtError,
    tables::{CrtTables, TableWords},
};

/// First word of the canonical encoding: `FAESTCRT` as little-endian bytes.
pub const MAGIC: u64 = u64::from_le_bytes(*b"FAESTCRT");

/// Number of header words of the canonical encoding.
const HEADER_WORDS: usize = 5;

/// Number of `u64` literals per line of generated source.
pub const WORDS_PER_LINE: usize = 4;

/// Number of `u16` literals per line of generated source.
pub const MODULI_PER_LINE: usize = 8;

/// Serialise a table set to its canonical word string.
pub fn encode_words(tables: &CrtTables<'_>) -> Vec<u64> {
    let words = tables.as_words();
    let mut out = vec![
        MAGIC,
        u64::from(words.lambda),
        u64::from(words.tau),
        u64::from(words.w_grind),
        u64::from(words.n_mult),
    ];
    out.extend(words.tree_moduli.iter().map(|modulus| u64::from(*modulus)));
    for part in [
        words.m_tree,
        words.f,
        words.g,
        words.w_tree,
        words.w_gate,
        words.w_crt,
    ] {
        out.extend_from_slice(part);
    }
    out
}

/// Take the next `count` words of `rest`.
fn take<'a>(rest: &mut &'a [u64], count: usize) -> Result<&'a [u64], CrtError> {
    let (head, tail) = rest.split_at_checked(count).ok_or(CrtError::Shape {
        what: "encoded table words",
        expected: count,
        actual: rest.len(),
    })?;
    *rest = tail;
    Ok(head)
}

/// Parse the canonical word string of a table set.
///
/// # Errors
/// [`CrtError::NonCanonical`] for a wrong first word or a header field or modulus
/// out of range, [`CrtError::Shape`] unless the input has exactly the length its
/// header implies, and the errors of [`CrtTables::from_words`] for tables that are
/// inconsistent.
pub fn decode_words(words: &[u64]) -> Result<CrtTables<'static>, CrtError> {
    let mut rest = words;
    let header = take(&mut rest, HEADER_WORDS)?;
    let field = |position: usize| -> Result<u32, CrtError> {
        header
            .get(position)
            .and_then(|word| u32::try_from(*word).ok())
            .ok_or(CrtError::NonCanonical {
                what: "a header field does not fit 32 bits",
            })
    };
    if header.first() != Some(&MAGIC) {
        return Err(CrtError::NonCanonical {
            what: "the encoding does not start with the magic word",
        });
    }
    let (lambda, tau, w_grind, n_mult) = (field(1)?, field(2)?, field(3)?, field(4)?);
    if w_grind >= lambda {
        return Err(CrtError::UnsupportedParameters {
            lambda,
            tau,
            w_grind,
        });
    }
    let n_delta = lambda - w_grind;
    let row_words = |width: u32| index(width).div_ceil(64);
    let table_words = |rows: u32, width: u32| -> Result<usize, CrtError> {
        index(rows)
            .checked_mul(row_words(width))
            .ok_or(CrtError::Shape {
                what: "encoded table words",
                expected: usize::MAX,
                actual: words.len(),
            })
    };
    let moduli_words = take(&mut rest, index(tau))?;
    let m_tree = take(&mut rest, (index(n_delta) + 1).div_ceil(64))?;
    let f = take(&mut rest, table_words(n_mult, lambda)?)?;
    let g = take(&mut rest, table_words(n_mult, n_delta)?)?;
    let w_tree = take(&mut rest, table_words(lambda, n_delta)?)?;
    let w_gate = take(&mut rest, table_words(lambda, n_mult)?)?;
    let w_crt = take(&mut rest, table_words(lambda, n_delta)?)?;
    if !rest.is_empty() {
        return Err(CrtError::Shape {
            what: "encoded table words",
            expected: words.len() - rest.len(),
            actual: words.len(),
        });
    }
    let tree_moduli = moduli_words
        .iter()
        .map(|word| {
            u16::try_from(*word).map_err(|_| CrtError::NonCanonical {
                what: "a tree modulus does not fit 16 bits",
            })
        })
        .collect::<Result<Vec<u16>, _>>()?;
    Ok(CrtTables::from_words(&TableWords {
        lambda,
        tau,
        w_grind,
        n_mult,
        tree_moduli: &tree_moduli,
        m_tree,
        f,
        g,
        w_tree,
        w_gate,
        w_crt,
    })?
    .into_owned())
}

/// A `u64` as a hexadecimal literal with digit groups of four.
fn hex_u64(word: u64) -> String {
    format!(
        "0x{:04x}_{:04x}_{:04x}_{:04x}",
        word >> 48,
        (word >> 32) & 0xffff,
        (word >> 16) & 0xffff,
        word & 0xffff
    )
}

/// Append one static array with `per_line` literals per line.
fn push_array(
    out: &mut String,
    doc: &str,
    name: &str,
    element: &str,
    literals: &[String],
    per_line: usize,
) {
    // Writing to a `String` cannot fail.
    let _ = writeln!(out, "\n/// {doc}");
    let _ = writeln!(out, "#[rustfmt::skip]");
    let _ = writeln!(
        out,
        "pub static {name}: [{element}; {}] = [",
        literals.len()
    );
    for line in literals.chunks(per_line.max(1)) {
        let _ = writeln!(out, "    {},", line.join(", "));
    }
    let _ = writeln!(out, "];");
}

/// Render a table set as Rust source.
///
/// The output is a sequence of items without inner attributes, to be a module of
/// its own: the constants `LAMBDA`, `TAU`, `W_GRIND`, `N_DELTA` and
/// `N_MULT` (`u32`), the static `TREE_MODULI` (`u16`, [`MODULI_PER_LINE`] literals
/// per line) and the statics `M_TREE`, `F`, `G`, `W_TREE`, `W_GATE` and `W_CRT`
/// (`u64`, [`WORDS_PER_LINE`] literals per line, rows in order). A header comment
/// marks the file as generated and names the generator call that reproduces it;
/// `label` names the profile in the comments.
///
/// # Errors
/// [`CrtError::NonCanonical`] unless `label` is a non-empty string of ASCII
/// letters, digits and underscores.
pub fn write_rust_source(tables: &CrtTables<'_>, label: &str) -> Result<String, CrtError> {
    let valid = !label.is_empty()
        && label
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_');
    if !valid {
        return Err(CrtError::NonCanonical {
            what: "a label is letters, digits and underscores",
        });
    }
    let words = tables.as_words();
    let n_delta = tables.n_delta();
    let mut out = String::new();
    // Writing to a `String` cannot fail.
    let _ = writeln!(
        out,
        "// @generated by `iroha_zkp_vole::crt::codec::write_rust_source` from\n\
         // `iroha_zkp_vole::crt::generator::generate({}, {}, {})`. Do not edit.\n\
         //\n\
         // CRT and VOLE-multiplication tables of FAEST v3.0, profile `{label}`. Rows are bit\n\
         // vectors packed little-endian into `u64` words, `ceil(width / 64)` words per row.",
        words.lambda, words.tau, words.w_grind
    );
    let scalars = [
        ("Security parameter `lambda`", "LAMBDA", words.lambda),
        ("Number of small-VOLE instances `tau`", "TAU", words.tau),
        (
            "Number of grinding bits `w_grind`",
            "W_GRIND",
            words.w_grind,
        ),
        (
            "Challenge length `n_delta = lambda - w_grind`",
            "N_DELTA",
            n_delta,
        ),
        (
            "Number of multiplication gates `n_mult`",
            "N_MULT",
            words.n_mult,
        ),
    ];
    for (doc, name, value) in scalars {
        let _ = writeln!(
            out,
            "\n/// {doc} of profile `{label}`.\npub const {name}: u32 = {value};"
        );
    }
    let moduli: Vec<String> = words
        .tree_moduli
        .iter()
        .map(|modulus| format!("0x{modulus:04x}"))
        .collect();
    push_array(
        &mut out,
        "The tree moduli, each with its leading bit; bit `i` is the coefficient of `x^i`.",
        "TREE_MODULI",
        "u16",
        &moduli,
        MODULI_PER_LINE,
    );
    let tables_list = [
        (
            format!(
                "`M_TREE`, the product of the tree moduli: {} bits.",
                n_delta + 1
            ),
            "M_TREE",
            words.m_tree,
        ),
        (
            format!("Table `F`: {} rows of {} bits.", words.n_mult, words.lambda),
            "F",
            words.f,
        ),
        (
            format!("Table `G`: {} rows of {n_delta} bits.", words.n_mult),
            "G",
            words.g,
        ),
        (
            format!("Table `W_TREE`: {} rows of {n_delta} bits.", words.lambda),
            "W_TREE",
            words.w_tree,
        ),
        (
            format!(
                "Table `W_GATE`: {} rows of {} bits.",
                words.lambda, words.n_mult
            ),
            "W_GATE",
            words.w_gate,
        ),
        (
            format!("Table `W_CRT`: {} rows of {n_delta} bits.", words.lambda),
            "W_CRT",
            words.w_crt,
        ),
    ];
    for (doc, name, data) in tables_list {
        let literals: Vec<String> = data.iter().map(|word| hex_u64(*word)).collect();
        push_array(&mut out, &doc, name, "u64", &literals, WORDS_PER_LINE);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::{super::tables::testing::TOY, *};

    fn toy() -> CrtTables<'static> {
        CrtTables::from_words(&TOY).expect("consistent")
    }

    #[test]
    fn magic_is_ascii() {
        assert_eq!(MAGIC.to_le_bytes(), *b"FAESTCRT");
    }

    #[test]
    fn take_splits_or_fails() {
        let words = [1u64, 2, 3];
        let mut rest = &words[..];
        assert_eq!(take(&mut rest, 2), Ok(&words[..2]));
        assert_eq!(rest, &words[2..]);
        assert_eq!(
            take(&mut rest, 2),
            Err(CrtError::Shape {
                what: "encoded table words",
                expected: 2,
                actual: 1
            })
        );
        assert_eq!(take(&mut rest, 1), Ok(&words[2..]));
        assert!(rest.is_empty());
    }

    #[test]
    fn words_round_trip() {
        let tables = toy();
        let words = encode_words(&tables);
        assert_eq!(
            words,
            vec![
                MAGIC, 4, 2, 1, 2, 0b10, 0b111, 0b1110, 0b1001, 0b0110, 0b101, 0b011, 0b001, 0b010,
                0b100, 0b111, 0b01, 0b10, 0b11, 0b00, 0b110, 0b011, 0b101, 0
            ]
        );
        assert_eq!(decode_words(&words), Ok(tables));
    }

    #[test]
    fn malformed_words_are_rejected() {
        let words = encode_words(&toy());
        // Every proper prefix and every extension is the wrong length.
        for length in 0..words.len() {
            assert!(
                matches!(decode_words(&words[..length]), Err(CrtError::Shape { .. })),
                "{length}"
            );
        }
        let mut longer = words.clone();
        longer.push(0);
        assert_eq!(
            decode_words(&longer),
            Err(CrtError::Shape {
                what: "encoded table words",
                expected: words.len(),
                actual: words.len() + 1
            })
        );
        let with = |position: usize, value: u64| {
            let mut changed = words.clone();
            changed[position] = value;
            decode_words(&changed)
        };
        assert!(matches!(
            with(0, MAGIC ^ 1),
            Err(CrtError::NonCanonical { .. })
        ));
        assert!(matches!(
            with(1, 1 << 32),
            Err(CrtError::NonCanonical { .. })
        ));
        assert!(matches!(
            with(4, u64::MAX),
            Err(CrtError::NonCanonical { .. })
        ));
        assert!(matches!(
            with(3, 4),
            Err(CrtError::UnsupportedParameters { .. })
        ));
        assert!(matches!(
            with(3, 0),
            Err(CrtError::Shape { .. } | CrtError::UnsupportedParameters { .. })
        ));
        // A huge row count is rejected by its length, without allocating.
        assert!(matches!(
            with(4, u64::from(u32::MAX)),
            Err(CrtError::Shape { .. })
        ));
        assert!(matches!(
            with(2, u64::from(u32::MAX)),
            Err(CrtError::Shape { .. })
        ));
        assert!(matches!(
            with(5, 1 << 16),
            Err(CrtError::NonCanonical { .. })
        ));
        assert!(matches!(with(5, 0b11), Err(CrtError::NonCanonical { .. })));
        assert!(matches!(
            with(7, 0b1111),
            Err(CrtError::NonCanonical { .. })
        ));
        assert!(matches!(
            with(8, 1 << 4),
            Err(CrtError::NonCanonical { .. })
        ));
        assert!(matches!(with(23, 1), Err(CrtError::NonCanonical { .. })));
    }

    #[test]
    fn literals_and_arrays() {
        assert_eq!(hex_u64(0), "0x0000_0000_0000_0000");
        assert_eq!(hex_u64(0x0123_4567_89ab_cdef), "0x0123_4567_89ab_cdef");
        let mut out = String::new();
        let literals: Vec<String> = (0..5).map(|value| value.to_string()).collect();
        push_array(&mut out, "Doc.", "NAME", "u8", &literals, 2);
        assert_eq!(
            out,
            "\n/// Doc.\n#[rustfmt::skip]\npub static NAME: [u8; 5] = [\n    0, 1,\n    2, 3,\n    4,\n];\n"
        );
    }

    #[test]
    fn rust_source_of_the_toy_set() {
        let source = write_rust_source(&toy(), "toy_1").expect("valid label");
        assert!(
            source.starts_with("// @generated by `iroha_zkp_vole::crt::codec::write_rust_source`")
        );
        assert!(source.contains("generator::generate(4, 2, 1)`. Do not edit."));
        assert!(source.contains("profile `toy_1`."));
        assert!(source.contains("\npub const LAMBDA: u32 = 4;\n"));
        assert!(source.contains("\npub const TAU: u32 = 2;\n"));
        assert!(source.contains("\npub const W_GRIND: u32 = 1;\n"));
        assert!(source.contains("\npub const N_DELTA: u32 = 3;\n"));
        assert!(source.contains("\npub const N_MULT: u32 = 2;\n"));
        assert!(source.contains("pub static TREE_MODULI: [u16; 2] = [\n    0x0002, 0x0007,\n];\n"));
        assert!(
            source.contains("pub static M_TREE: [u64; 1] = [\n    0x0000_0000_0000_000e,\n];\n")
        );
        assert!(source.contains(
            "pub static W_TREE: [u64; 4] = [\n    0x0000_0000_0000_0001, 0x0000_0000_0000_0002, \
             0x0000_0000_0000_0004, 0x0000_0000_0000_0007,\n];\n"
        ));
        for name in ["F", "G", "W_GATE", "W_CRT"] {
            assert!(source.contains(&format!("pub static {name}: [u64; ")));
        }
        assert!(source.ends_with("];\n"));
        assert!(source.is_ascii());
        for label in ["", "a b", "x\ny", "caf\u{e9}", "a*/"] {
            assert!(write_rust_source(&toy(), label).is_err(), "{label:?}");
        }
    }
}
