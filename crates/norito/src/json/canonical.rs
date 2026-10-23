//! Canonical JSON validation through the existing field kernels and checked writers.
//!
//! No semantic object/array tree or rewritten document is materialized. String
//! scratch is supplied by the caller; object order requires only the previous
//! decoded key, whose owner remains alive until the next key is compared.

use super::{
    BoundedJsonError, Error, JsonSerialize, JsonWriteSink, KeyRef, MapVisitor, Number, Parser,
    SeqVisitor, Value,
};

/// Validate the exact compact, sorted-key JSON spelling with caller-owned scratch.
///
/// This reuses the ordinary lexical preflight, container visitors, string and
/// number decoders, and checked scalar/string writers. The writer compares each
/// emitted byte with the original source instead of retaining another document.
/// The inherited decoder context and observer are neither replaced nor reset.
/// Caller destinations must provide exactly the initialized byte span requested
/// by the string kernel. Their original ownership lasts through each comparison.
///
/// # Errors
/// Preserves original JSON syntax/resource errors and caller scratch refusals;
/// rejects any spelling that differs from Norito's canonical writer.
#[doc(hidden)]
pub fn validate_canonical_json_with_buffer<B, E>(
    source: &str,
    mut allocate: impl FnMut(usize) -> Result<B, E>,
) -> Result<(), E>
where
    B: AsMut<[u8]> + AsRef<[u8]>,
    E: From<Error>,
{
    let mut parser = Parser::new(source);
    parser.preflight_document()?;
    let mut comparison = Comparison {
        source: source.as_bytes(),
        position: 0,
        equal: true,
    };
    validate_value(&mut parser, &mut comparison, &mut allocate)?;
    parser.finish_document()?;
    if !comparison.equal || comparison.position != source.len() {
        return Err(noncanonical().into());
    }
    Ok(())
}

fn noncanonical() -> Error {
    Error::WithPos {
        msg: "Json payload is valid but not in canonical lexical form",
        byte: 0,
        line: 1,
        col: 1,
    }
}

struct Comparison<'a> {
    source: &'a [u8],
    position: usize,
    equal: bool,
}

impl JsonWriteSink for Comparison<'_> {
    fn push(&mut self, value: char) -> Result<(), BoundedJsonError> {
        let mut bytes = [0; 4];
        self.push_str(value.encode_utf8(&mut bytes))
    }
    fn push_str(&mut self, value: &str) -> Result<(), BoundedJsonError> {
        if self
            .source
            .get(self.position..)
            .is_some_and(|remaining| remaining.starts_with(value.as_bytes()))
        {
            self.position += value.len();
        } else {
            self.equal = false;
        }
        Ok(())
    }
    fn begin_container(&mut self) -> Result<(), BoundedJsonError> {
        Ok(())
    }
    fn end_container(&mut self) {}
}

fn key_text<'a, B: AsRef<[u8]>>(key: &'a KeyRef<'_, B>) -> &'a str {
    match key {
        KeyRef::Borrowed(text) => text,
        KeyRef::Owned(bytes) => std::str::from_utf8(bytes.as_ref())
            .expect("the original JSON string kernel writes UTF-8"),
    }
}

fn emitted<E: From<Error>>(result: Result<(), BoundedJsonError>) -> Result<(), E> {
    result.map_err(|error| Error::from_decode_resource(error.into_core_error()).into())
}

enum Frame<'a, B> {
    Object {
        state: super::visitors::MapState,
        previous: KeyRef<'a, B>,
    },
    Array(super::visitors::SeqState),
}

fn validate_value<B, E>(
    parser: &mut Parser<'_>,
    output: &mut Comparison<'_>,
    allocate: &mut impl FnMut(usize) -> Result<B, E>,
) -> Result<(), E>
where
    B: AsMut<[u8]> + AsRef<[u8]>,
    E: From<Error>,
{
    // The lexical scanner enforces this same fixed depth ceiling. No recursive
    // value walk, semantic container tree or dynamically grown frame Vec exists.
    // With the supplied Vec/charged-byte destinations this is bounded stack
    // control; only decoded string scratch can own a heap allocation.
    let mut frames: [Option<Frame<'_, B>>; super::MAX_JSON_VALUE_NESTING_DEPTH] =
        [const { None }; super::MAX_JSON_VALUE_NESTING_DEPTH];
    let mut depth = 0;
    'value: loop {
        super::ensure_json_value_depth(depth + 1)?;
        parser.skip_ws();
        match parser.peek() {
            Some(b'{') => {
                let mut object = MapVisitor::new(parser)?;
                emitted::<E>(output.push('{'))?;
                if let Some(key) = object.next_key_with_buffer(&mut *allocate)? {
                    emitted::<E>(super::write_json_string_to(key_text(&key), output))?;
                    emitted::<E>(output.push(':'))?;
                    frames[depth] = Some(Frame::Object {
                        state: object.suspend(),
                        previous: key,
                    });
                    depth += 1;
                    continue 'value;
                }
                object.finish()?;
                emitted::<E>(output.push('}'))?;
            }
            Some(b'[') => {
                let mut array = SeqVisitor::new(parser)?;
                emitted::<E>(output.push('['))?;
                if array.begin_element()? {
                    frames[depth] = Some(Frame::Array(array.suspend()));
                    depth += 1;
                    continue 'value;
                }
                array.finish()?;
                emitted::<E>(output.push(']'))?;
            }
            Some(b'"') => {
                let decoded = parser.parse_string_with_buffer(&mut *allocate)?;
                let text = std::str::from_utf8(decoded.as_ref())
                    .expect("the original JSON string kernel writes UTF-8");
                emitted::<E>(super::write_json_string_to(text, output))?;
            }
            Some(b'n') => {
                parser.parse_null()?;
                emitted::<E>(output.push_str("null"))?;
            }
            Some(b't' | b'f') => {
                let value = parser.parse_bool()?;
                emitted::<E>(value.json_serialize_to(output))?;
            }
            Some(b'-' | b'0'..=b'9') => {
                // This maintained kernel returns one scalar variant and never
                // constructs a Value tree, String or rewritten source document.
                let Value::Number(value) = super::parse_number_value(parser)? else {
                    unreachable!("numeric kernel returns a scalar number")
                };
                emitted::<E>(match value {
                    Number::I64(value) => value.json_serialize_to(output),
                    Number::U64(value) => value.json_serialize_to(output),
                    Number::U128(value) => value.json_serialize_to(output),
                    Number::F64(value) => value.json_serialize_to(output),
                })?;
            }
            _ => return Err(parser.err_unexpected_char().into()),
        }
        loop {
            if depth == 0 {
                return Ok(());
            }
            depth -= 1;
            match frames[depth]
                .take()
                .expect("one original suspended visitor per open container")
            {
                Frame::Object { state, previous } => {
                    let mut object = MapVisitor::resume(parser, state);
                    object.complete_value()?;
                    if let Some(key) = object.next_key_with_buffer(&mut *allocate)? {
                        if key_text(&previous) >= key_text(&key) {
                            return Err(noncanonical().into());
                        }
                        emitted::<E>(output.push(','))?;
                        emitted::<E>(super::write_json_string_to(key_text(&key), output))?;
                        emitted::<E>(output.push(':'))?;
                        frames[depth] = Some(Frame::Object {
                            state: object.suspend(),
                            previous: key,
                        });
                        depth += 1;
                        continue 'value;
                    }
                    object.finish()?;
                    emitted::<E>(output.push('}'))?;
                }
                Frame::Array(state) => {
                    let mut array = SeqVisitor::resume(parser, state);
                    array.complete_element()?;
                    if array.begin_element()? {
                        emitted::<E>(output.push(','))?;
                        frames[depth] = Some(Frame::Array(array.suspend()));
                        depth += 1;
                        continue 'value;
                    }
                    array.finish()?;
                    emitted::<E>(output.push(']'))?;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests;
