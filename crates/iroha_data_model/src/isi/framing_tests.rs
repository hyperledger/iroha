//! Instruction tuple framing, counting propagation, and registry ownership contracts.

use std::{cell::Cell, sync::Arc};

use iroha_primitives::const_vec::ConstVec;
use norito::codec::Encode;
use norito::core::{
    Archived, DecodeFlagsGuard, DeserializePayload, Encoder, Error, Header, SerializePayload,
    encoded_payload_len, from_bytes, serialize_to_buffer, supported_header_flags, to_bytes,
    validate_header_flags,
};

use super::{INSTRUCTION_REGISTRY_OVERRIDE, InstructionBox, InstructionRegistry};

const COUNTED_WIRE_ID: &str = "test.instruction.v1::CountedFrame";

thread_local! {
    static SERIALIZE_VISITS: Cell<usize> = const { Cell::new(0) };
}

#[derive(Clone, Debug, PartialEq, PartialOrd, norito::NoritoSchema)]
#[norito_schema(name = "test::iroha_data_model::CountedInstruction", frame = "u8")]
struct CountedInstruction(u8);

impl crate::seal::Instruction for CountedInstruction {}

impl SerializePayload for CountedInstruction {
    fn serialize(&self, writer: &mut Encoder<'_>) -> Result<(), Error> {
        SERIALIZE_VISITS.with(|visits| visits.set(visits.get() + 1));
        self.0.serialize(writer)
    }

    fn encoded_len_exact(&self) -> Option<usize> {
        panic!("instruction frame measurement must not trust a length hint")
    }
}

impl<'a> DeserializePayload<'a> for CountedInstruction {
    fn deserialize(archived: &'a Archived<Self>) -> Self {
        Self::try_deserialize(archived).expect("decode counted instruction")
    }

    fn try_deserialize(archived: &'a Archived<Self>) -> Result<Self, Error> {
        u8::try_deserialize(archived.cast()).map(Self)
    }
}

struct RegistryGuard(Option<Arc<InstructionRegistry>>);

impl RegistryGuard {
    fn enter() -> Self {
        let registry =
            InstructionRegistry::new().register_with_id::<CountedInstruction>(COUNTED_WIRE_ID);
        Self(INSTRUCTION_REGISTRY_OVERRIDE.with(|slot| slot.replace(Some(Arc::new(registry)))))
    }
}

impl Drop for RegistryGuard {
    fn drop(&mut self) {
        INSTRUCTION_REGISTRY_OVERRIDE.with(|slot| {
            *slot.borrow_mut() = self.0.take();
        });
    }
}

fn layouts() -> impl Iterator<Item = u8> {
    (0..=supported_header_flags()).filter(|flags| validate_header_flags(*flags).is_ok())
}

// A field has no frame identity; only its enclosing instruction owns a frame.
#[derive(Debug, PartialEq, norito::SerializePayload, norito::DeserializePayload)]
#[norito(decode_from_slice)]
struct PayloadOnlyField {
    count: u32,
    values: Vec<u16>,
    tag: Option<u8>,
}

#[test]
fn canonical_field_decoders_preserve_bounds_and_flags_without_a_frame_identity() {
    let value = PayloadOnlyField {
        count: 7,
        values: vec![3, 5, 11],
        tag: Some(9),
    };
    for flags in layouts() {
        let _requested = DecodeFlagsGuard::enter(flags);
        let (payload, actual) = norito::codec::encode_with_header_flags(&value);
        let outer = if actual == 0 {
            norito::core::header_flags::COMPACT_LEN
        } else {
            0
        };
        let _outer = DecodeFlagsGuard::enter(outer);
        assert_eq!(
            super::decode_aos_canonical_field::<PayloadOnlyField>(&payload, actual).unwrap(),
            value
        );
        assert_eq!(
            super::decode_aos_slice_field::<PayloadOnlyField>(&payload, actual).unwrap(),
            value
        );
        assert_eq!(norito::core::effective_decode_flags(), Some(outer));
        for len in 0..payload.len() {
            assert!(
                super::decode_aos_canonical_field::<PayloadOnlyField>(&payload[..len], actual)
                    .is_err()
            );
            assert!(
                super::decode_aos_slice_field::<PayloadOnlyField>(&payload[..len], actual).is_err()
            );
            assert_eq!(norito::core::effective_decode_flags(), Some(outer));
        }
        let mut trailing = payload;
        trailing.push(0);
        assert!(super::decode_aos_canonical_field::<PayloadOnlyField>(&trailing, actual).is_err());
        assert!(super::decode_aos_slice_field::<PayloadOnlyField>(&trailing, actual).is_err());
        assert_eq!(norito::core::effective_decode_flags(), Some(outer));
    }
}

#[test]
fn instruction_box_and_const_vec_measure_each_instruction_once() {
    let _registry = RegistryGuard::enter();
    for flags in layouts() {
        let _flags = DecodeFlagsGuard::enter(flags);
        let boxed = InstructionBox(Box::new(CountedInstruction(0xa5)));
        let sequence = ConstVec::from(vec![boxed.clone()]);
        let cases: [(&dyn SerializePayload, usize); 2] = [(&boxed, 2), (&sequence, 3)];
        for (value, output_visits) in cases {
            SERIALIZE_VISITS.with(|visits| visits.set(0));
            let length = encoded_payload_len(value).expect("measure instruction payload");
            assert_eq!(
                SERIALIZE_VISITS.with(Cell::get),
                1,
                "counting replayed the framed instruction, flags {flags:#x}"
            );
            SERIALIZE_VISITS.with(|visits| visits.set(0));
            let mut bytes = Vec::new();
            serialize_to_buffer(value, &mut bytes).expect("emit checked instruction payload");
            assert_eq!(bytes.len(), length);
            assert_eq!(
                SERIALIZE_VISITS.with(Cell::get),
                output_visits,
                "actual output added a redundant frame-length pass, flags {flags:#x}"
            );
        }
    }
}

#[test]
fn instruction_box_preserves_scalar_frame_and_tuple_bytes_in_every_layout() {
    let _registry = RegistryGuard::enter();
    for flags in layouts() {
        let _flags = DecodeFlagsGuard::enter(flags);
        let boxed = InstructionBox(Box::new(CountedInstruction(0xa5)));
        // The fixture instruction has the scalar u8 wire/schema contract. This
        // independent buffer encoder pins its embedded header, checksum and body.
        let scalar_frame = to_bytes(&0xa5_u8).expect("canonical scalar frame");
        let pair = (COUNTED_WIRE_ID.to_owned(), scalar_frame);
        let mut expected = Vec::new();
        serialize_to_buffer(&pair, &mut expected).expect("canonical tuple fields");
        let mut actual = Vec::new();
        serialize_to_buffer(&boxed, &mut actual).expect("instruction tuple");
        assert_eq!(
            actual, expected,
            "instruction tuple changed, flags {flags:#x}"
        );
        assert_eq!(encoded_payload_len(&boxed).unwrap(), expected.len());

        let frame = to_bytes(&boxed).expect("frame instruction box");
        let header = Header::read(&mut &frame[..]).expect("instruction box header");
        let _frame_flags = DecodeFlagsGuard::enter(header.flags);
        let archived =
            from_bytes::<InstructionBox>(&frame).expect("validate instruction box frame");
        let decoded =
            InstructionBox::try_deserialize(archived).expect("decode registered instruction");
        assert_eq!(
            decoded.as_any().downcast_ref::<CountedInstruction>(),
            Some(&CountedInstruction(0xa5))
        );
    }
}

#[test]
fn borrowed_encoding_lookup_preserves_authoritative_empty_and_custom_local_registries() {
    struct Restore(Option<Arc<InstructionRegistry>>);
    impl Drop for Restore {
        fn drop(&mut self) {
            INSTRUCTION_REGISTRY_OVERRIDE.with(|slot| *slot.borrow_mut() = self.0.take());
        }
    }
    let restore = Restore(
        INSTRUCTION_REGISTRY_OVERRIDE
            .with(|slot| slot.replace(Some(Arc::new(InstructionRegistry::new())))),
    );
    let boxed = super::Log::new(crate::Level::INFO, "original".into()).into();
    assert_eq!(super::instruction_wire_id(&boxed), None);
    assert_eq!(SerializePayload::encoded_len_exact(&boxed), None);
    assert_eq!(SerializePayload::encoded_len_hint(&boxed), None);
    assert!(matches!(
        norito::canonical_frame_len(&boxed),
        Err(Error::InvalidValue {
            context: "unregistered instruction"
        })
    ));
    let custom = InstructionRegistry::new().register_with_id::<super::Log>("test.original.log");
    INSTRUCTION_REGISTRY_OVERRIDE.with(|slot| *slot.borrow_mut() = Some(Arc::new(custom)));
    assert_eq!(
        super::instruction_wire_id(&boxed),
        Some("test.original.log")
    );
    let framed = super::framed_instruction_payload(&boxed).expect("original custom registry frame");
    let expected = (framed.0.to_owned(), framed.1).encode();
    assert_eq!(boxed.encode(), expected);
    assert_eq!(
        SerializePayload::encoded_len_exact(&boxed),
        Some(expected.len())
    );
    assert_eq!(
        SerializePayload::encoded_len_hint(&boxed),
        Some(expected.len())
    );
    drop(restore);
}

#[test]
fn cold_encoding_inventory_is_the_exact_default_registry_and_frame_geometry() {
    let default = super::registry::default();
    for (type_name, wire_id) in super::registry::encoding_inventory_for_tests() {
        let cold =
            super::registry::default_encoding_entry(type_name).expect("same static inventory");
        let installed = default
            .entry_for_type_name(type_name)
            .expect("same default registry");
        assert_eq!(cold.wire_id, wire_id);
        assert_eq!(cold.wire_id, installed.wire_id);
        for length in [0, 1, 127, 128, 65_536] {
            assert_eq!((cold.frame_len)(length), (installed.frame_len)(length));
        }
    }
    assert!(super::registry::default_encoding_entry("unregistered.public.synthetic").is_none());
}
