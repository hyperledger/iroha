//! Temporary micro-benchmark for byte-element framing and frame-hash memoization.
use norito::{
    DeserializePayload, NoritoSchema, SerializePayload,
    core::{self, Archived, Encoder, Error},
};
use std::time::Instant;

#[derive(Clone, Copy)]
struct GenericByte(u8);
impl SerializePayload for GenericByte {
    fn serialize(&self, writer: &mut Encoder<'_>) -> Result<(), Error> {
        writer.write_all(&[self.0])?;
        Ok(())
    }
}
impl<'de> DeserializePayload<'de> for GenericByte {
    fn deserialize(archived: &'de Archived<Self>) -> Self {
        Self::try_deserialize(archived).unwrap()
    }
    fn try_deserialize(archived: &'de Archived<Self>) -> Result<Self, Error> {
        let bytes = core::payload_range_from_ptr(std::ptr::from_ref(archived).cast(), 1)?;
        Ok(Self(bytes[0]))
    }
}
struct Seq<'a, T>(&'a [T]);
impl<T: SerializePayload> SerializePayload for Seq<'_, T> {
    fn serialize(&self, writer: &mut Encoder<'_>) -> Result<(), Error> {
        core::write_element_sequence::<T, _>(writer, self.0.iter())
    }
}

fn best<F: FnMut()>(iterations: usize, mut f: F) -> f64 {
    let mut best = f64::MAX;
    for _ in 0..7 {
        let start = Instant::now();
        for _ in 0..iterations {
            f();
        }
        best = best.min(start.elapsed().as_secs_f64() * 1e9 / iterations as f64);
    }
    best
}

fn main() {
    let bytes: Vec<u8> = (0..3309).map(|i| (i * 7) as u8).collect();
    let wrapped: Vec<GenericByte> = bytes.iter().copied().map(GenericByte).collect();
    let mut out = Vec::new();
    let encode_fast = best(200, || {
        out.clear();
        norito::core::serialize_to_buffer(&Seq(&bytes), &mut out).unwrap();
    });
    let encoded = out.clone();
    let encode_generic = best(20, || {
        out.clear();
        norito::core::serialize_to_buffer(&Seq(&wrapped), &mut out).unwrap();
    });
    assert_eq!(out, encoded);
    let limits = norito::canonical_decode_limits(encoded.len());
    let decode_fast = best(200, || {
        let decoded = norito::with_decode_limits(limits, || {
            core::decode_element_sequence_from_slice_serial::<u8>(&encoded)
        })
        .unwrap();
        std::hint::black_box(decoded);
    });
    let decode_generic = best(20, || {
        let decoded = norito::with_decode_limits(limits, || {
            core::decode_element_sequence_from_slice_serial::<GenericByte>(&encoded)
        })
        .unwrap();
        std::hint::black_box(decoded.0.len());
    });
    println!(
        "byte elements x3309: encode fast {encode_fast:.0} ns, generic {encode_generic:.0} ns; decode fast {decode_fast:.0} ns, generic {decode_generic:.0} ns"
    );
    let array: [u8; 32] = std::array::from_fn(|i| i as u8);
    let warray: [GenericByte; 32] = array.map(GenericByte);
    let enc_array_fast = best(20000, || {
        out.clear();
        norito::core::serialize_to_buffer(&array, &mut out).unwrap();
    });
    let encoded_array = out.clone();
    let enc_array_generic = best(2000, || {
        out.clear();
        norito::core::serialize_to_buffer(&warray, &mut out).unwrap();
    });
    let dec_array = best(20000, || {
        let decoded = norito::with_decode_limits(limits, || {
            core::decode_field_canonical::<[u8; 32]>(&encoded_array)
        })
        .unwrap();
        std::hint::black_box(decoded);
    });
    println!(
        "[u8; 32]: encode fast {enc_array_fast:.0} ns, generic {enc_array_generic:.0} ns; canonical field decode {dec_array:.0} ns"
    );
    let static_hash = best(200000, || {
        std::hint::black_box(norito::schema::identity::frame_hash::<norito::schema::SamplePayload>());
    });
    let generic_hash = best(200000, || {
        std::hint::black_box(norito::schema::identity::frame_hash::<Vec<Option<(u32, String)>>>());
    });
    let name = <Vec<Option<(u32, String)>> as NoritoSchema>::frame_name();
    let sha_only = best(200000, || {
        std::hint::black_box(core::schema_hash_for_name(std::hint::black_box(&name)));
    });
    let build_and_sha = best(100000, || {
        let name = <Vec<Option<(u32, String)>> as NoritoSchema>::frame_name();
        std::hint::black_box(core::schema_hash_for_name(&name));
    });
    println!(
        "frame_hash: memo literal {static_hash:.1} ns, memo generic {generic_hash:.1} ns; uncached generic (name+sha) {build_and_sha:.0} ns, sha only {sha_only:.0} ns"
    );
}
