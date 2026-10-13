//! Payload-only query views preserve canonical output frames and ownership limits.

use super::*;
use norito::{NoritoSchema, core as ncore};

/// A source intentionally lacking a root-frame identity.
struct PayloadOnly<T>(T);
impl<T: SerializePayload> SerializePayload for PayloadOnly<T> {
    fn serialize(&self, writer: &mut Encoder<'_>) -> Result<(), ncore::Error> {
        self.0.serialize(writer)
    }
    fn encoded_len_exact(&self) -> Option<usize> {
        self.0.encoded_len_exact()
    }
}

#[derive(Debug, PartialEq, Eq, norito::Encode, norito::Decode, norito::NoritoSchema)]
#[norito_schema(name = "iroha.core.test.singular-query.aligned-output")]
#[repr(align(64))]
struct AlignedOutput {
    value: u128,
}

fn assert_output_frame<S, T>(source: &S, output: &T)
where
    S: SerializePayload,
    T: NoritoSerialize + for<'de> NoritoDeserialize<'de>,
{
    let frame = SingularQueryFrame::<T>::new(source);
    let canonical = ncore::to_bytes_bounded(output, 65_536).expect("owned output frame");
    let actual = ncore::to_bytes_bounded(&frame, canonical.len()).expect("borrowed output frame");
    assert_eq!(actual, canonical, "identity, padding, flags and payload");
    assert_eq!(frame.encoded_len_exact(), source.encoded_len_exact());
    assert_eq!(
        norito::schema::identity::frame_hash::<SingularQueryFrame<'_, T>>(),
        norito::schema::identity::frame_hash::<T>(),
    );
    assert_ne!(SingularQueryFrame::<T>::nominal_name(), T::nominal_name());
    assert!(matches!(
        ncore::to_bytes_bounded(&frame, actual.len() - 1),
        Err(ncore::BoundedEncodeError::FrameTooLarge { encoded_bytes, max_bytes })
            if encoded_bytes == actual.len() && max_bytes == actual.len() - 1,
    ));
    let decoded: T = norito::decode_from_bytes(&actual).expect("owned result decodes");
    assert_eq!(
        ncore::to_bytes_bounded(&decoded, 65_536).unwrap(),
        canonical
    );
}

#[test]
fn output_frame_selects_the_owned_identity_and_alignment() {
    for flags in [0, ncore::header_flags::COMPACT_LEN] {
        let _flags = DecodeFlagsGuard::enter(flags);
        assert_output_frame(&PayloadOnly(7_u8), &7_u8);
        assert_output_frame(&PayloadOnly(u128::MAX), &u128::MAX);
        let value = u128::MAX;
        assert_output_frame(
            &BorrowedSingularStruct::<1>::new([&value]),
            &AlignedOutput { value },
        );
    }
}

#[test]
fn borrowed_option_and_iterator_require_only_payload_codecs() {
    for flags in [0, ncore::header_flags::COMPACT_LEN] {
        let _flags = DecodeFlagsGuard::enter(flags);
        let values = [
            PayloadOnly("alpha".to_owned()),
            PayloadOnly("beta".to_owned()),
        ];
        for value in [None, Some(&values[0])] {
            assert_output_frame(
                &BorrowedSingularOption::new(value),
                &value.map(|value| value.0.clone()),
            );
        }
        // Filter's closure has no protocol identity; the output remains Vec<String>.
        let borrowed = BorrowedSequence {
            values: values.iter().filter(|value| !value.0.is_empty()),
        };
        let owned = vec!["alpha".to_owned(), "beta".to_owned()];
        assert_output_frame(&borrowed, &owned);
        assert_eq!(
            borrowed.encoded_len_exact(),
            Some(ncore::encoded_payload_len(&borrowed).unwrap()),
        );
    }
}

#[test]
fn borrowed_roundtrip_enforces_output_and_allocation_limits() {
    let previous = ncore::get_decode_flags();
    let flags = DecodeFlagsGuard::enter(ncore::default_encode_flags());
    let output = "bounded output".to_owned();
    let source = PayloadOnly(output.clone());
    let bytes = ncore::to_bytes_bounded(&output, 1_024).unwrap();
    let accepted = SingularQueryOutputLimits::new(bytes.len() as u64, 1_024);
    assert_eq!(
        bounded_roundtrip::<_, String>(&source, accepted).unwrap(),
        output
    );
    let too_small = SingularQueryOutputLimits::new(bytes.len() as u64 - 1, 1_024);
    assert!(matches!(
        bounded_roundtrip::<_, String>(&source, too_small),
        Err(Error::CapacityLimit)
    ));
    let no_allocation = SingularQueryOutputLimits::new(bytes.len() as u64, 0);
    assert!(matches!(
        bounded_roundtrip::<_, String>(&source, no_allocation),
        Err(Error::CapacityLimit)
    ));
    assert_eq!(
        bounded_roundtrip::<_, String>(&source, accepted).unwrap(),
        output
    );
    drop(flags);
    assert_eq!(ncore::get_decode_flags(), previous);
}

#[test]
fn payload_only_owned_source_drops_before_the_result_decoder() {
    struct Source(PayloadOnly<u8>);
    impl SerializePayload for Source {
        fn serialize(&self, writer: &mut Encoder<'_>) -> Result<(), ncore::Error> {
            self.0.serialize(writer)
        }
    }
    impl Drop for Source {
        fn drop(&mut self) {
            SOURCE_DROPPED.set(true);
        }
    }
    thread_local! {
        static SOURCE_DROPPED: Cell<bool> = const { Cell::new(false) };
    }
    #[derive(norito::NoritoSchema)]
    #[norito_schema(name = "iroha.core.test.singular-query.owned-output")]
    struct Output(u8);
    impl SerializePayload for Output {
        fn serialize(&self, writer: &mut Encoder<'_>) -> Result<(), ncore::Error> {
            self.0.serialize(writer)
        }
    }
    impl<'de> ncore::DeserializePayload<'de> for Output {
        fn deserialize(archived: &'de ncore::Archived<Self>) -> Self {
            Self::try_deserialize(archived).expect("owned result")
        }
        fn try_deserialize(archived: &'de ncore::Archived<Self>) -> Result<Self, ncore::Error> {
            assert!(
                SOURCE_DROPPED.get(),
                "producer must be dropped before allocating output"
            );
            let bytes = ncore::payload_slice_from_ptr(core::ptr::from_ref(archived).cast())?;
            Ok(Self(ncore::decode_field_canonical::<u8>(bytes)?.0))
        }
    }
    SOURCE_DROPPED.set(false);
    let _limits = SingularOutputLimitGuard::enter(SingularQueryOutputLimits::new(1_024, 1_024));
    let result = own_singular_query_serialized_source::<_, Output>(Source(PayloadOnly(7))).unwrap();
    assert_eq!(result.0, 7);
    assert!(SOURCE_DROPPED.get());
}
