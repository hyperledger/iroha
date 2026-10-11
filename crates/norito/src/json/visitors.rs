use super::{
    CoerceKey, Error, JsonDeserialize, KeyRef, Parser, Visitor, try_decode_string_copy, visit_value,
};
/// Streaming visitor for a JSON object.
pub struct MapVisitor<'a, 'p> {
    parser: &'p mut Parser<'a>,
    finished: bool,
    value_pending: bool,
    after_comma: bool,
    total_entries: usize,
}
impl<'a, 'p> MapVisitor<'a, 'p> {
    /// Begin visiting an object at the parser's current position.
    pub fn new(parser: &'p mut Parser<'a>) -> Result<Self, Error> {
        let total_entries = parser.preflight_object_entries()?;
        parser.expect(b'{')?;
        let mut visitor = Self {
            parser,
            finished: false,
            value_pending: false,
            after_comma: false,
            total_entries,
        };
        if visitor.parser.try_consume_char(b'}')? {
            visitor.finished = true;
        }
        Ok(visitor)
    }
    /// Access the underlying parser.
    #[inline]
    pub fn parser(&mut self) -> &mut Parser<'a> {
        self.parser
    }
    /// Return whether the closing delimiter has been consumed.
    #[inline]
    pub fn is_finished(&self) -> bool {
        self.finished && !self.value_pending
    }
    /// Number of entries lexically admitted for this object.
    #[doc(hidden)]
    #[inline]
    pub fn total_entries(&self) -> usize {
        self.total_entries
    }
    /// Parse the next object key without materializing its value.
    pub fn next_key(&mut self) -> Result<Option<KeyRef<'a>>, Error> {
        self.next_key_with(|parser| parser.parse_key())
    }
    /// Read the next key while preserving an original escaped-text admission owner.
    ///
    /// The ordinary object lifecycle/colon/escape checks remain shared. Unescaped
    /// text is borrowed from the original source; only escaped text invokes the
    /// exact initialized destination callback. This adds no duplicate, unknown-field
    /// or record policy and funds no enclosing source, record/control or diagnostic.
    ///
    /// # Errors
    /// Preserves original JSON syntax and the caller's exact typed refusal.
    pub fn next_key_with_buffer<B, E>(
        &mut self,
        allocate: impl FnOnce(usize) -> Result<B, E>,
    ) -> Result<Option<KeyRef<'a, B>>, E>
    where
        B: AsMut<[u8]>,
        E: From<Error>,
    {
        self.next_key_with(|parser| parser.parse_key_with_buffer(allocate))
    }
    fn next_key_with<K, E: From<Error>>(
        &mut self,
        parse: impl FnOnce(&mut Parser<'a>) -> Result<K, E>,
    ) -> Result<Option<K>, E> {
        if self.finished {
            return Ok(None);
        }
        if self.value_pending {
            return Err(Error::Message(
                "attempted to read a new key before consuming the previous value".into(),
            )
            .into());
        }
        self.reject_trailing_comma()?;
        if self.parser.try_consume_char(b'}')? {
            self.finished = true;
            return Ok(None);
        }
        let key = parse(self.parser)?;
        self.after_comma = false;
        self.value_pending = true;
        Ok(Some(key))
    }
    /// Parse the value belonging to the current key.
    pub fn parse_value<T: JsonDeserialize>(&mut self) -> Result<T, Error> {
        self.parse_value_with_parser(T::json_deserialize)
    }
    /// Parse the pending value directly from the underlying parser.
    ///
    /// The closure must consume exactly one JSON value. Object delimiter handling remains owned by
    /// this visitor, so custom seeded decoders can stream into typed owners without constructing an
    /// intermediate [`crate::json::Value`].
    pub fn parse_value_with_parser<T>(
        &mut self,
        parse: impl FnOnce(&mut Parser<'a>) -> Result<T, Error>,
    ) -> Result<T, Error> {
        self.parse_value_with_parser_typed(parse)
    }
    /// Parse one pending value while retaining an original typed caller refusal.
    ///
    /// Syntax and delimiter errors use the same kernel as ordinary field parsing;
    /// no owned intermediate JSON value is created. `E` must retain conversion
    /// from the original JSON error rather than relabel a local refusal as syntax.
    pub fn parse_value_with_parser_typed<T, E: From<Error>>(
        &mut self,
        parse: impl FnOnce(&mut Parser<'a>) -> Result<T, E>,
    ) -> Result<T, E> {
        if !self.value_pending {
            return Err(Error::Message("no pending value for current key".into()).into());
        }
        let value = parse(self.parser)?;
        self.finish_value()?;
        Ok(value)
    }
    /// Parse the current value with a custom streaming visitor.
    pub fn parse_value_with<V>(&mut self, visitor: V) -> Result<V::Value, Error>
    where
        V: Visitor<'a>,
    {
        if !self.value_pending {
            return Err(Error::Message("no pending value for current key".into()));
        }
        let value = visit_value(self.parser, visitor)?;
        self.finish_value()?;
        Ok(value)
    }
    /// Skip the value belonging to the current key.
    pub fn skip_value(&mut self) -> Result<(), Error> {
        if !self.value_pending {
            return Err(Error::Message("no pending value for current key".into()));
        }
        self.parser.skip_value_lexical()?;
        self.finish_value()
    }
    /// Parse the next key and typed value as one owned entry.
    pub fn next_entry<T: JsonDeserialize>(&mut self) -> Result<Option<(String, T)>, Error> {
        match self.next_key()? {
            Some(key) => {
                let owned = match key {
                    KeyRef::Borrowed(s) => try_decode_string_copy(s)?,
                    KeyRef::Owned(s) => s,
                };
                let value = self.parse_value::<T>()?;
                Ok(Some((owned, value)))
            }
            None => Ok(None),
        }
    }
    /// Fetch the next key and coerce it into `T` using `FromStr`.
    ///
    /// Returns `Ok(None)` when the object has no more entries. Any parse failure from `T::from_str`
    /// is wrapped in a deterministic JSON [`Error`].
    pub fn coerce_key<T>(&mut self) -> Result<Option<T>, Error>
    where
        T: core::str::FromStr,
        T::Err: core::fmt::Display,
    {
        match self.next_key()? {
            Some(key) => {
                let parsed = CoerceKey::from(key).parse::<T>()?;
                Ok(Some(parsed))
            }
            None => Ok(None),
        }
    }
    /// Fetch the next key/value pair, coercing the key via `FromStr` and
    /// deserializing the value using `JsonDeserialize`.
    pub fn next_entry_coerced<T, V>(&mut self) -> Result<Option<(T, V)>, Error>
    where
        T: core::str::FromStr,
        T::Err: core::fmt::Display,
        V: JsonDeserialize,
    {
        match self.next_key()? {
            Some(key) => {
                let parsed_key = CoerceKey::from(key).parse::<T>()?;
                let value = self.parse_value::<V>()?;
                Ok(Some((parsed_key, value)))
            }
            None => Ok(None),
        }
    }
    /// Finish the object and require its closing delimiter.
    pub fn finish(mut self) -> Result<(), Error> {
        if self.value_pending {
            return Err(Error::Message(
                "object ended before consuming value for current key".into(),
            ));
        }
        if !self.finished {
            self.reject_trailing_comma()?;
            if self.parser.try_consume_char(b'}')? {
                self.finished = true;
            } else {
                let (byte, line, col) =
                    crate::json::pos_from_offset(self.parser.input(), self.parser.position());
                return Err(Error::ExpectedCommaOrObjectEnd { byte, line, col });
            }
        }
        Ok(())
    }
    /// Construct a missing-field error.
    #[inline]
    pub fn missing_field(field: &'static str) -> Error {
        Error::missing_field(field)
    }
    /// Construct a duplicate-field error.
    #[inline]
    pub fn duplicate_field(field: &str) -> Error {
        Error::duplicate_field(field)
    }
    /// Construct an unknown-field error.
    #[inline]
    pub fn unknown_field(field: &str) -> Error {
        Error::unknown_field(field)
    }
    fn reject_trailing_comma(&mut self) -> Result<(), Error> {
        self.parser.skip_ws();
        if self.after_comma && self.parser.peek() == Some(b'}') {
            return Err(self.parser.err_here("trailing comma in object"));
        }
        Ok(())
    }
    fn finish_value(&mut self) -> Result<(), Error> {
        self.parser.skip_ws();
        match self.parser.peek() {
            Some(b',') => {
                self.parser.bump();
                self.value_pending = false;
                self.after_comma = true;
                Ok(())
            }
            Some(b'}') => {
                self.parser.bump();
                self.finished = true;
                self.value_pending = false;
                Ok(())
            }
            Some(_) => {
                let (byte, line, col) =
                    crate::json::pos_from_offset(self.parser.input(), self.parser.position());
                Err(Error::ExpectedCommaOrObjectEnd { byte, line, col })
            }
            None => {
                let (byte, line, col) =
                    crate::json::pos_from_offset(self.parser.input(), self.parser.position());
                Err(Error::UnexpectedEof { byte, line, col })
            }
        }
    }
}
/// Streaming visitor for a JSON array.
pub struct SeqVisitor<'a, 'p> {
    parser: &'p mut Parser<'a>,
    finished: bool,
    after_comma: bool,
    total_entries: usize,
}
impl<'a, 'p> SeqVisitor<'a, 'p> {
    /// Begin visiting an array at the parser's current position.
    pub fn new(parser: &'p mut Parser<'a>) -> Result<Self, Error> {
        let total_entries = parser.preflight_array_entries()?;
        parser.expect(b'[')?;
        let mut visitor = Self {
            parser,
            finished: false,
            after_comma: false,
            total_entries,
        };
        if visitor.parser.try_consume_char(b']')? {
            visitor.finished = true;
        }
        Ok(visitor)
    }
    /// Access the underlying parser.
    #[inline]
    pub fn parser(&mut self) -> &mut Parser<'a> {
        self.parser
    }
    /// Return whether the closing delimiter has been consumed.
    #[inline]
    pub fn is_finished(&self) -> bool {
        self.finished
    }
    /// Exact entries admitted by the original lexical/count preflight.
    #[doc(hidden)]
    pub fn total_entries(&self) -> usize {
        self.total_entries
    }
    /// Parse the next typed array element.
    pub fn next_element<T: JsonDeserialize>(&mut self) -> Result<Option<T>, Error> {
        self.next_element_with_parser_typed(T::json_deserialize)
    }
    /// Parse one element with no intermediate value or erasure of caller refusal.
    pub fn next_element_with_parser_typed<T, E: From<Error>>(
        &mut self,
        parse: impl FnOnce(&mut Parser<'a>) -> Result<T, E>,
    ) -> Result<Option<T>, E> {
        if self.finished {
            return Ok(None);
        }
        self.prepare_element()?;
        let value = parse(self.parser)?;
        self.finish_element()?;
        Ok(Some(value))
    }
    /// Parse the next element with a custom streaming visitor.
    pub fn next_element_with<V>(&mut self, visitor: V) -> Result<Option<V::Value>, Error>
    where
        V: Visitor<'a>,
    {
        if self.finished {
            return Ok(None);
        }
        self.prepare_element()?;
        let value = visit_value(self.parser, visitor)?;
        self.finish_element()?;
        Ok(Some(value))
    }
    /// Skip the next array element.
    pub fn skip_element(&mut self) -> Result<(), Error> {
        if self.finished {
            return Ok(());
        }
        self.prepare_element()?;
        self.parser.skip_value_lexical()?;
        self.finish_element()
    }
    /// Finish the array and require its closing delimiter.
    pub fn finish(mut self) -> Result<(), Error> {
        if !self.finished {
            self.reject_trailing_comma()?;
            if self.parser.try_consume_char(b']')? {
                self.finished = true;
            } else {
                let (byte, line, col) =
                    crate::json::pos_from_offset(self.parser.input(), self.parser.position());
                return Err(Error::ExpectedCommaOrArrayEnd { byte, line, col });
            }
        }
        Ok(())
    }
    fn prepare_element(&mut self) -> Result<(), Error> {
        self.reject_trailing_comma()?;
        self.after_comma = false;
        Ok(())
    }
    fn reject_trailing_comma(&mut self) -> Result<(), Error> {
        self.parser.skip_ws();
        if self.after_comma && self.parser.peek() == Some(b']') {
            return Err(self.parser.err_here("trailing comma in array"));
        }
        Ok(())
    }
    fn finish_element(&mut self) -> Result<(), Error> {
        self.parser.skip_ws();
        match self.parser.peek() {
            Some(b',') => {
                self.parser.bump();
                self.after_comma = true;
                Ok(())
            }
            Some(b']') => {
                self.parser.bump();
                self.finished = true;
                self.after_comma = false;
                Ok(())
            }
            Some(_) => {
                let (byte, line, col) =
                    crate::json::pos_from_offset(self.parser.input(), self.parser.position());
                Err(Error::ExpectedCommaOrArrayEnd { byte, line, col })
            }
            None => {
                let (byte, line, col) =
                    crate::json::pos_from_offset(self.parser.input(), self.parser.position());
                Err(Error::UnexpectedEof { byte, line, col })
            }
        }
    }
}

#[cfg(test)]
#[path = "visitors/destination_tests.rs"]
mod destination_tests;
