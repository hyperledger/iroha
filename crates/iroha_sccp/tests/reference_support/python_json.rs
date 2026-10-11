//! Python-canonical JSON text.
//!
//! The reference fixtures are written by two generators that must agree byte for byte, and
//! the Python one writes `json.dumps(document, indent=2, sort_keys=True) + "\n"`. [`render`]
//! writes exactly that text for a [`Value`]: keys in code-point order, two-space indentation,
//! `[]` and `{}` for empty containers, and every character outside printable ASCII escaped
//! (`ensure_ascii`). `norito::json::to_string_pretty` writes non-ASCII characters raw, so it
//! cannot be used here.
//!
//! [`first_difference`] names the first place where two documents differ, so a drift failure
//! reads as a path into the fixture, not as two megabytes of text.

use std::fmt::Write as _;

use norito::json::{Number, Value};

/// `json.dumps(value, indent=2, sort_keys=True) + "\n"`.
///
/// # Panics
/// On a floating-point number: the reference fixtures hold integers only, and Python and
/// Rust do not print floats alike.
pub fn render(value: &Value) -> String {
    let mut out = String::new();
    write_value(&mut out, value, 0);
    out.push('\n');
    out
}

fn write_value(out: &mut String, value: &Value, depth: usize) {
    match value {
        Value::Null => out.push_str("null"),
        Value::Bool(true) => out.push_str("true"),
        Value::Bool(false) => out.push_str("false"),
        Value::Number(number) => write_number(out, number),
        Value::String(text) => write_string(out, text),
        Value::Array(items) if items.is_empty() => out.push_str("[]"),
        Value::Array(items) => {
            out.push('[');
            for (index, item) in items.iter().enumerate() {
                if index > 0 {
                    out.push(',');
                }
                write_indent(out, depth + 1);
                write_value(out, item, depth + 1);
            }
            write_indent(out, depth);
            out.push(']');
        }
        Value::Object(map) if map.is_empty() => out.push_str("{}"),
        // `Map` is a `BTreeMap<String, _>`: it iterates in byte order of the UTF-8 keys, which
        // is the code-point order `sort_keys` uses.
        Value::Object(map) => {
            out.push('{');
            for (index, (key, item)) in map.iter().enumerate() {
                if index > 0 {
                    out.push(',');
                }
                write_indent(out, depth + 1);
                write_string(out, key);
                out.push_str(": ");
                write_value(out, item, depth + 1);
            }
            write_indent(out, depth);
            out.push('}');
        }
    }
}

fn write_indent(out: &mut String, depth: usize) {
    out.push('\n');
    for _ in 0..depth {
        out.push_str("  ");
    }
}

fn write_number(out: &mut String, number: &Number) {
    match number {
        Number::I64(value) => write!(out, "{value}"),
        Number::U64(value) => write!(out, "{value}"),
        Number::U128(value) => write!(out, "{value}"),
        Number::F64(value) => panic!("the reference fixtures hold no float, found {value}"),
    }
    .expect("writing to a string does not fail");
}

/// A JSON string as Python writes it with `ensure_ascii`: `"` and `\` escaped, the five short
/// control escapes, and every other character outside `' '..='~'` as `\uXXXX` in lowercase
/// hexadecimal (a surrogate pair above the basic plane).
fn write_string(out: &mut String, text: &str) {
    out.push('"');
    for character in text.chars() {
        match character {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{8}' => out.push_str("\\b"),
            '\u{c}' => out.push_str("\\f"),
            ' '..='~' => out.push(character),
            _ => {
                let mut units = [0_u16; 2];
                for unit in character.encode_utf16(&mut units) {
                    write!(out, "\\u{unit:04x}").expect("writing to a string does not fail");
                }
            }
        }
    }
    out.push('"');
}

/// The first place where `generated` and `committed` differ, as a path with both values, or
/// `None` when the documents are equal.
///
/// Object keys are visited in order and a key present on one side only is reported at its
/// parent. Long values are cut: the path is what a reader needs.
pub fn first_difference(generated: &Value, committed: &Value) -> Option<String> {
    difference_at("$", generated, committed)
}

fn difference_at(path: &str, generated: &Value, committed: &Value) -> Option<String> {
    match (generated, committed) {
        (Value::Object(left), Value::Object(right)) => {
            if let Some(key) = left.keys().find(|key| !right.contains_key(*key)) {
                return Some(format!(
                    "{path}: key `{key}` is generated but not committed"
                ));
            }
            if let Some(key) = right.keys().find(|key| !left.contains_key(*key)) {
                return Some(format!(
                    "{path}: key `{key}` is committed but not generated"
                ));
            }
            left.iter()
                .find_map(|(key, item)| difference_at(&format!("{path}.{key}"), item, &right[key]))
        }
        (Value::Array(left), Value::Array(right)) => left
            .iter()
            .zip(right)
            .enumerate()
            .find_map(|(index, (item, other))| {
                difference_at(&format!("{path}[{index}]"), item, other)
            })
            .or_else(|| {
                (left.len() != right.len()).then(|| {
                    format!(
                        "{path}: {} items generated, {} committed",
                        left.len(),
                        right.len()
                    )
                })
            }),
        _ if generated == committed => None,
        _ => Some(format!(
            "{path}: generated {}, committed {}",
            excerpt(generated),
            excerpt(committed)
        )),
    }
}

/// The canonical text of a value on one line, cut to a readable length.
fn excerpt(value: &Value) -> String {
    const LIMIT: usize = 200;
    let text = render(value);
    let mut line: String = text.split_whitespace().collect::<Vec<_>>().join(" ");
    if line.len() > LIMIT {
        let cut = (0..=LIMIT)
            .rev()
            .find(|index| line.is_char_boundary(*index))
            .unwrap_or(0);
        line.truncate(cut);
        line.push('…');
    }
    line
}
