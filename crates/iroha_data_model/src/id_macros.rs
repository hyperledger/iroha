//! Macros for implementing common traits for ID types.
macro_rules! string_id {
    ($($ty:ty),+ $(,)?) => {
        $(

            impl norito::json::FastJsonWrite for $ty {
                fn write_json(&self, out: &mut String) {
                    norito::json::write_json_unbounded(self, out);
                }
                fn write_json_to(
                    &self,
                    out: &mut dyn norito::json::JsonWriteSink,
                ) -> Result<(), norito::json::BoundedJsonError> {
                    norito::json::write_json_display_to(self, out)
                }
            }

            impl norito::json::JsonDeserialize for $ty {
                fn json_deserialize(
                    parser: &mut norito::json::Parser<'_>,
                ) -> Result<Self, norito::json::Error> {
                    let value = parser.parse_string()?;
                    value
                        .parse()
                        .map_err(|err| norito::json::Error::Message(format!("{err}")))
                }
            }
        )+
    };
}

#[cfg(test)]
mod checked_string_id_tests {
    use norito::json::{JsonDeserialize, JsonSerialize};
    fn assert_canonical_stream<
        T: JsonSerialize + JsonDeserialize + std::fmt::Display + std::fmt::Debug + PartialEq,
    >(
        id: &T,
    ) {
        let expected = norito::json::to_json(&id.to_string()).unwrap();
        assert_eq!(norito::json::to_json(id).unwrap(), expected);
        let limits =
            |bytes| norito::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, bytes, 32);
        let (body, usage) =
            norito::core::with_decode_limits_measured(limits(expected.len()), || {
                norito::json::to_json_bounded_boxed(id, expected.len())
            });
        let body = body.unwrap();
        assert_eq!(&*body, expected.as_bytes());
        assert_eq!(usage.total_allocated_bytes(), expected.len());
        assert_eq!(&norito::json::from_slice::<T>(&body).unwrap(), id);
        assert!(norito::json::to_json_bounded_boxed(id, expected.len() - 1).is_err());
        assert!(
            norito::with_decode_limits_scope(limits(expected.len() - 1), || {
                norito::json::to_json_bounded_boxed(id, expected.len())
            })
            .is_err()
        );
    }
    #[test]
    fn native_string_ids_stream_exact_wire_without_literal_scratch() {
        assert_canonical_stream(
            &"rose$wonderland.universal"
                .parse::<crate::nft::NftId>()
                .unwrap(),
        );
        assert_canonical_stream(&"notify".parse::<crate::trigger::TriggerId>().unwrap());
        assert_canonical_stream(
            &"repo_trade"
                .parse::<crate::repo::RepoAgreementId>()
                .unwrap(),
        );
        assert_canonical_stream(
            &"fx_trade"
                .parse::<crate::isi::settlement::SettlementId>()
                .unwrap(),
        );
    }
}
