//! pass: named enum helpers own generic fields without default JSON trait bounds.
use core::marker::PhantomData;
use norito::json::{self, JsonSerialize as _};

struct Custom<T>(PhantomData<T>);
struct NoJson;

mod helper {
    use super::*;

    pub fn serialize<T>(_: &Custom<T>, out: &mut String) {
        "helper".json_serialize(out);
    }

    pub fn serialize_bounded<T>(
        _: &Custom<T>,
        out: &mut dyn json::JsonWriteSink,
    ) -> Result<(), json::BoundedJsonError> {
        "helper".json_serialize_to(out)
    }

    pub fn deserialize<T>(parser: &mut json::Parser<'_>) -> Result<Custom<T>, json::Error> {
        if parser.parse_string()? != "helper" {
            return Err(json::Error::Message("expected helper literal".into()));
        }
        Ok(Custom(PhantomData))
    }
}

#[derive(norito::derive::JsonSerialize, norito::derive::JsonDeserialize)]
#[norito(tag = "kind", content = "payload", deny_unknown_fields)]
enum Generic<T> {
    Combined {
        #[norito(json = "helper")]
        value: Custom<T>,
    },
    Separate {
        #[norito(with = "helper", bounded_with = "helper::serialize_bounded")]
        value: Custom<T>,
    },
}

fn main() {
    for value in [
        Generic::<NoJson>::Combined {
            value: Custom(PhantomData),
        },
        Generic::<NoJson>::Separate {
            value: Custom(PhantomData),
        },
    ] {
        let text = json::to_json(&value).unwrap();
        let _: Generic<NoJson> = json::from_str(&text).unwrap();
        assert_eq!(json::to_json_bounded(&value, text.len()).unwrap(), text);
        let mut walker = json::TapeWalker::new(&text);
        let mut arena = json::Arena::new();
        let decoded = <Generic<NoJson> as json::FastFromJson>::parse(&mut walker, &mut arena)
            .expect("helper-owned generic type needs no default JSON trait bound");
        assert_eq!(json::to_json(&decoded).unwrap(), text);
    }
}
