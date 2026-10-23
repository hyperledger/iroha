//! One strict scalar layout/encoding grammar with caller-owned text scratch.

use norito::json::{
    self, JsonDeserialize,
    scratch::{OrdinaryScratch, ScratchDestination, key_text},
};

use super::{DataAvailabilityLayout, PayloadEncoding};

fn invalid(message: &'static str) -> json::Error {
    json::Error::WithPos {
        msg: message,
        byte: 0,
        line: 1,
        col: 1,
    }
}

impl PayloadEncoding {
    /// Read the canonical tagged encoding using a caller's text destination.
    ///
    /// The original parser and cumulative decoder remain active. This scalar
    /// result retains no backing; the caller checks document completion.
    /// # Errors
    /// Preserves original syntax/allocation refusals and rejects unknown,
    /// duplicate, missing or non-null unit content.
    #[doc(hidden)]
    pub fn json_decode_with<D: ScratchDestination>(
        parser: &mut json::Parser<'_>,
        destination: &D,
    ) -> Result<Self, D::Error> {
        let mut encoding = None;
        let mut details = None;
        let mut object = json::MapVisitor::new(parser)?;
        while let Some(key) = destination.key(&mut object)? {
            match key_text(&key) {
                "encoding" => {
                    if encoding.is_some() {
                        return Err(invalid("duplicate encoding tag").into());
                    }
                    encoding = Some(object.parse_value_with_parser_typed(
                        |parser| -> Result<_, D::Error> {
                            let value = destination.string(parser)?;
                            match value.as_ref() {
                                "reed_solomon16" => Ok(Self::ReedSolomon16),
                                _ => Err(invalid("unknown payload encoding").into()),
                            }
                        },
                    )?);
                }
                "details" => {
                    if details.is_some() {
                        return Err(invalid("duplicate encoding details").into());
                    }
                    details = Some(object.parse_value_with_parser(|parser| parser.parse_null())?);
                }
                _ => return Err(invalid("unknown payload encoding field").into()),
            }
        }
        object.finish()?;
        details.ok_or_else(|| invalid("missing encoding details"))?;
        Ok(encoding.ok_or_else(|| invalid("missing encoding tag"))?)
    }
}
impl JsonDeserialize for PayloadEncoding {
    fn json_deserialize(parser: &mut json::Parser<'_>) -> Result<Self, json::Error> {
        Self::json_decode_with(parser, &OrdinaryScratch)
    }
}

impl DataAvailabilityLayout {
    /// Read all six signed layout fields into their scalar destination.
    ///
    /// Ordinary and admitted callers use this same relation. Intrinsic layout
    /// validation remains explicit in [`Self::validate`]. No Value tree or
    /// restaged parser is constructed; the caller checks document completion.
    /// # Errors
    /// Preserves original syntax/allocation refusals and required-field checks.
    #[doc(hidden)]
    pub fn json_decode_with<D: ScratchDestination>(
        parser: &mut json::Parser<'_>,
        destination: &D,
    ) -> Result<Self, D::Error> {
        let mut encoding = None;
        let mut chunk_size_bytes = None;
        let mut data_shards = None;
        let mut parity_shards = None;
        let mut max_payload_size_bytes = None;
        let mut max_chunk_count = None;
        let mut object = json::MapVisitor::new(parser)?;
        while let Some(key) = destination.key(&mut object)? {
            macro_rules! scalar {
                ($field:ident, $ty:ty) => {{
                    if $field.is_some() {
                        return Err(invalid(concat!(
                            "duplicate layout field: ",
                            stringify!($field)
                        ))
                        .into());
                    }
                    $field = Some(object.parse_value_with_parser(|parser| {
                        <$ty>::try_from(parser.parse_u64()?)
                            .map_err(|_| invalid(concat!(stringify!($field), " integer overflow")))
                    })?);
                }};
            }
            match key_text(&key) {
                "encoding" => {
                    if encoding.is_some() {
                        return Err(invalid("duplicate layout encoding").into());
                    }
                    encoding = Some(object.parse_value_with_parser_typed(|parser| {
                        PayloadEncoding::json_decode_with(parser, destination)
                    })?);
                }
                "chunk_size_bytes" => scalar!(chunk_size_bytes, u32),
                "data_shards" => scalar!(data_shards, u16),
                "parity_shards" => scalar!(parity_shards, u16),
                "max_payload_size_bytes" => scalar!(max_payload_size_bytes, u64),
                "max_chunk_count" => scalar!(max_chunk_count, u32),
                _ => return Err(invalid("unknown data availability layout field").into()),
            }
        }
        object.finish()?;
        macro_rules! required {
            ($field:ident) => {
                $field
                    .ok_or_else(|| invalid(concat!("missing layout field: ", stringify!($field))))?
            };
        }
        Ok(Self {
            encoding: required!(encoding),
            chunk_size_bytes: required!(chunk_size_bytes),
            data_shards: required!(data_shards),
            parity_shards: required!(parity_shards),
            max_payload_size_bytes: required!(max_payload_size_bytes),
            max_chunk_count: required!(max_chunk_count),
        })
    }
}
impl JsonDeserialize for DataAvailabilityLayout {
    fn json_deserialize(parser: &mut json::Parser<'_>) -> Result<Self, json::Error> {
        Self::json_decode_with(parser, &OrdinaryScratch)
    }
}

// Tape reads delegate to the same ordinary typed kernel, as the former derive did.
impl<'a> json::FastFromJson<'a> for DataAvailabilityLayout {
    fn parse(
        walker: &mut json::TapeWalker<'a>,
        _arena: &mut json::Arena,
    ) -> Result<Self, norito::Error> {
        walker.ensure_document_depth()?;
        let mut parser = json::Parser::new_at(walker.input(), walker.raw_pos());
        let value = Self::json_deserialize(&mut parser).map_err(norito::Error::from)?;
        walker.sync_to_raw(parser.position());
        Ok(value)
    }
}

// Tape reads delegate to the same ordinary typed kernel, as the former derive did.
impl<'a> json::FastFromJson<'a> for PayloadEncoding {
    fn parse(
        walker: &mut json::TapeWalker<'a>,
        _arena: &mut json::Arena,
    ) -> Result<Self, norito::Error> {
        walker.ensure_document_depth()?;
        let mut parser = json::Parser::new_at(walker.input(), walker.raw_pos());
        let value = Self::json_deserialize(&mut parser).map_err(norito::Error::from)?;
        walker.sync_to_raw(parser.position());
        Ok(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use iroha_allocation::AllocationBudget;
    use norito::json::scratch::AdmittedScratch;

    #[test]
    fn layout_and_encoding_share_ordinary_and_funded_grammar() {
        let expected = super::super::recommended_data_availability_layout();
        let source = json::to_json(&expected).unwrap();
        let pool = AllocationBudget::new(4096);
        let actual = DataAvailabilityLayout::json_decode_with(
            &mut json::Parser::new(&source),
            &AdmittedScratch::new(&pool),
        )
        .unwrap();
        assert_eq!(actual, expected);
        assert_eq!(
            json::from_str::<DataAvailabilityLayout>(&source).unwrap(),
            actual
        );
        assert_eq!(pool.reserved_bytes(), 0);
        for source in [
            r#"{"details":null,"encoding":"reed_solomon16"}"#,
            r#"{"encoding":"reed_solomon16","details":null}"#,
        ] {
            assert_eq!(
                json::from_str::<PayloadEncoding>(source).unwrap(),
                PayloadEncoding::ReedSolomon16
            );
            assert_eq!(
                PayloadEncoding::json_decode_with(
                    &mut json::Parser::new(source),
                    &AdmittedScratch::new(&pool)
                )
                .unwrap(),
                PayloadEncoding::ReedSolomon16
            );
        }
    }
    #[test]
    fn encoding_rejects_unknown_duplicate_missing_and_nonunit_details() {
        let pool = AllocationBudget::new(4096);
        for source in [
            r#"{"encoding":"reed_solomon16"}"#,
            r#"{"encoding":"reed_solomon16","details":{}}"#,
            r#"{"encoding":"reed_solomon16","details":null,"other":0}"#,
            r#"{"encoding":"reed_solomon16","details":null,"details":null}"#,
            r#"{"encoding":"reed_solomon16","encod\u0069ng":"reed_solomon16","details":null}"#,
            r#"{"encoding":"reed_solomon8","details":null}"#,
        ] {
            assert!(
                json::from_str::<PayloadEncoding>(source).is_err(),
                "{source}"
            );
            assert!(
                PayloadEncoding::json_decode_with(
                    &mut json::Parser::new(source),
                    &AdmittedScratch::new(&pool)
                )
                .is_err(),
                "{source}"
            );
            assert_eq!(pool.reserved_bytes(), 0);
        }
    }
}
