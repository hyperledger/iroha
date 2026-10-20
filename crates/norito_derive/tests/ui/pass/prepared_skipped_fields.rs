//! Skipped caches require Default only, never codec or schema implementations.
#[derive(Default)]
struct Cache;
#[derive(norito::NoritoSerialize, norito::NoritoDeserialize, norito::NoritoSchema)]
#[norito(decode_fields, decode_from_slice)]
#[norito_schema(name = "prepared.skip.ui.Named")]
struct Named {
    first: u8,
    #[norito(skip)]
    cache: Cache,
    last: u64,
}
#[derive(norito::NoritoSerialize, norito::NoritoDeserialize, norito::NoritoSchema)]
#[norito(decode_fields, decode_from_slice)]
#[norito_schema(name = "prepared.skip.ui.Tuple")]
struct Tuple(u8, #[norito(skip)] Cache, u64);
#[derive(norito::NoritoSerialize, norito::NoritoDeserialize, norito::NoritoSchema)]
#[norito(decode_fields, decode_from_slice, validate = "Self::validate")]
#[norito_schema(name = "prepared.skip.ui.Checked")]
struct Checked {
    first: u8,
    #[norito(skip)]
    cache: Cache,
    last: u64,
}
impl Checked {
    fn validate(self) -> Result<Self, norito::Error> {
        Ok(self)
    }
}
#[derive(norito::NoritoSerialize, norito::NoritoDeserialize, norito::NoritoSchema)]
#[norito(decode_fields, decode_from_slice)]
#[norito_schema(name = "prepared.skip.ui.OnlySkipped")]
struct OnlySkipped {
    #[norito(skip)]
    cache: Cache,
}
fn main() {
    for bytes in [
        norito::encode_canonical(&Named {
            first: 1,
            cache: Cache,
            last: 2,
        })
        .unwrap(),
        norito::encode_canonical(&Tuple(1, Cache, 2)).unwrap(),
        norito::encode_canonical(&Checked {
            first: 1,
            cache: Cache,
            last: 2,
        })
        .unwrap(),
        norito::encode_canonical(&OnlySkipped { cache: Cache }).unwrap(),
    ] {
        assert!(!bytes.is_empty());
    }
}
