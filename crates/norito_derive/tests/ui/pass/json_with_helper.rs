//! pass: JSON derives invoke the field helper for a payload without JSON traits.
//! The pass binary runs the complete roundtrip and checks the helper's exact width.
mod json_with_helper {
    use norito::derive::{JsonDeserialize, JsonSerialize};
    use norito::json::{self, JsonDeserialize as _, Parser};
    use std::vec::Vec;

    #[derive(Debug, PartialEq, Eq)]
    struct Payload([u8; 4]);

    #[derive(Debug, PartialEq, Eq, JsonSerialize, JsonDeserialize)]
    struct Wrapper {
        #[norito(with = "helpers")]
        payload: Payload,
    }

    mod helpers {
        use super::*;

        pub fn serialize(bytes: &Payload, out: &mut String) {
            let buf: Vec<u8> = bytes.0.to_vec();
            json::JsonSerialize::json_serialize(&buf, out);
        }

        pub fn deserialize(parser: &mut Parser<'_>) -> Result<Payload, json::Error> {
            let buf = Vec::<u8>::json_deserialize(parser)?;
            buf.try_into().map(Payload).map_err(|bytes: Vec<u8>| {
                json::Error::Message(format!("expected 4 bytes, got {}", bytes.len()))
            })
        }
    }

    /// Exercise the helper-only payload in the genuine trybuild pass binary.
    pub fn roundtrip() {
        let input = Wrapper {
            payload: Payload([1, 2, 3, 4]),
        };
        let json = json::to_json(&input).expect("serialize");
        assert_eq!(json, "{\"payload\":[1,2,3,4]}");
        let decoded: Wrapper = json::from_str(&json).expect("deserialize");
        assert_eq!(decoded, input);
        assert!(json::from_str::<Wrapper>(r#"{"payload":[1,2,3]}"#).is_err());
        assert!(json::from_str::<Wrapper>(r#"{"payload":[1,2,3,4,5]}"#).is_err());
    }
}

fn main() {
    json_with_helper::roundtrip();
}
