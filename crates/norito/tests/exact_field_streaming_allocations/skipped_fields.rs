//! Skipped caches have no wire callbacks and default only on owned reconstruction.
use norito::core::{
    CanonicalField, DecodeField, DecodeIntoError, DecodeRecordFields, DecodeValueFields,
    FieldDestination,
};
use norito::{NoritoDeserialize, NoritoSchema, NoritoSerialize};
use std::cell::Cell;
thread_local! {
    static DEFAULTS: Cell<usize> = const { Cell::new(0) };
    static HOOKS: Cell<usize> = const { Cell::new(0) };
}
#[derive(Debug, PartialEq)]
struct Cache;
impl Default for Cache {
    fn default() -> Self {
        DEFAULTS.set(DEFAULTS.get() + 1);
        Self
    }
}
#[derive(Debug, PartialEq, NoritoSerialize, NoritoDeserialize, NoritoSchema)]
#[norito(decode_fields, decode_from_slice)]
#[norito_schema(name = "skip.named")]
struct Named {
    first: u64,
    #[norito(skip)]
    cache: Cache,
    last: u32,
}
#[derive(Debug, PartialEq, NoritoSerialize, NoritoDeserialize, NoritoSchema)]
#[norito(decode_from_slice)]
#[norito_schema(name = "skip.named")]
struct OriginalNamed {
    first: u64,
    #[norito(skip)]
    cache: Cache,
    last: u32,
}
#[derive(Debug, PartialEq, NoritoSerialize, NoritoDeserialize, NoritoSchema)]
#[norito(decode_fields, decode_from_slice)]
#[norito_schema(name = "skip.tuple")]
struct Tuple(u64, #[norito(skip)] Cache, u32);
#[derive(Debug, PartialEq, NoritoSerialize, NoritoDeserialize, NoritoSchema)]
#[norito(decode_from_slice)]
#[norito_schema(name = "skip.tuple")]
struct OriginalTuple(u64, #[norito(skip)] Cache, u32);
#[derive(Debug, PartialEq, NoritoSerialize, NoritoDeserialize, NoritoSchema)]
#[norito(decode_fields, decode_from_slice, validate = "Self::validate")]
#[norito_schema(name = "skip.validated")]
struct Validated {
    first: u64,
    #[norito(skip)]
    cache: Cache,
    last: u32,
}
impl Validated {
    fn validate(self) -> Result<Self, norito::Error> {
        assert_eq!(DEFAULTS.get(), 1);
        HOOKS.set(HOOKS.get() + 1);
        Ok(self)
    }
}
#[derive(Default)]
struct Destination {
    coordinates: Vec<usize>,
}
impl FieldDestination for Destination {
    type Error = std::convert::Infallible;
}
impl<const I: usize, T> DecodeField<I, T> for Destination {
    type Value = T;
    fn decode_field(
        &mut self,
        field: CanonicalField<'_, T>,
    ) -> Result<T, DecodeIntoError<Self::Error>> {
        self.coordinates.push(I);
        Ok(field.decode_owned()?)
    }
}
#[test]
fn skipped_named_and_tuple_cache_preserve_original_wire_without_wire_type_bounds() {
    let named = Named {
        first: 9,
        cache: Cache,
        last: 11,
    };
    let bytes = norito::encode_canonical(&named).unwrap();
    assert_eq!(
        bytes,
        norito::encode_canonical(&OriginalNamed {
            first: 9,
            cache: Cache,
            last: 11
        })
        .unwrap()
    );
    DEFAULTS.set(0);
    assert_eq!(norito::decode_canonical::<Named>(&bytes).unwrap(), named);
    assert_eq!(DEFAULTS.get(), 1);
    DEFAULTS.set(0);
    assert_eq!(
        norito::decode_canonical::<OriginalNamed>(&bytes)
            .unwrap()
            .first,
        9
    );
    assert_eq!(DEFAULTS.get(), 1);
    let tuple = Tuple(9, Cache, 11);
    let bytes = norito::encode_canonical(&tuple).unwrap();
    assert_eq!(
        bytes,
        norito::encode_canonical(&OriginalTuple(9, Cache, 11)).unwrap()
    );
    DEFAULTS.set(0);
    assert_eq!(norito::decode_canonical::<Tuple>(&bytes).unwrap(), tuple);
    assert_eq!(DEFAULTS.get(), 1);
    DEFAULTS.set(0);
    assert_eq!(
        norito::decode_canonical::<OriginalTuple>(&bytes).unwrap().2,
        11
    );
    assert_eq!(DEFAULTS.get(), 1);
}
#[test]
fn skipped_cache_never_constructs_in_record_walk_and_defaults_once_before_value_hook() {
    for flags in [0, norito::core::header_flags::COMPACT_LEN] {
        let _flags = norito::core::DecodeFlagsGuard::enter(flags);
        let bytes = super::bare_bytes(
            &Named {
                first: 9,
                cache: Cache,
                last: 11,
            },
            flags,
        );
        DEFAULTS.set(0);
        let mut destination = Destination::default();
        let (values, used) = Named::decode_fields(&bytes, &mut destination).unwrap();
        assert_eq!(values, (9, 11));
        assert_eq!(used, bytes.len());
        assert_eq!(destination.coordinates, [0, 2]);
        assert_eq!(DEFAULTS.get(), 0);
        HOOKS.set(0);
        let mut destination = Destination::default();
        let (value, used) = Validated::decode_value_fields(&bytes, &mut destination).unwrap();
        assert_eq!((value.first, value.last), (9, 11));
        assert_eq!(used, bytes.len());
        assert_eq!(destination.coordinates, [0, 2]);
        assert_eq!(DEFAULTS.get(), 1);
        assert_eq!(HOOKS.get(), 1);
        // The cache is a reconstruction detail, so no default or hook runs when
        // later wire fields cannot be read. The positional callback remains2.
        for end in 0..bytes.len() {
            DEFAULTS.set(0);
            HOOKS.set(0);
            assert!(
                Validated::decode_value_fields(&bytes[..end], &mut Destination::default()).is_err()
            );
            assert_eq!(DEFAULTS.get(), 0);
            assert_eq!(HOOKS.get(), 0);
        }
        let mut trailing = bytes.clone();
        trailing.push(0);
        DEFAULTS.set(0);
        HOOKS.set(0);
        assert!(norito::core::decode_field_canonical::<Validated>(&trailing).is_err());
        assert_eq!(DEFAULTS.get(), 0);
        assert_eq!(HOOKS.get(), 0);
    }
}
