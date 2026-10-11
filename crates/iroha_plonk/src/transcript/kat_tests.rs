//! Transcript known-answer tests.
//!
//! The vendored vectors come from `fixtures/native_prover/kats_v1.json`
//! (`blake2b_transcript` and `poseidon_transcript`), recorded by
//! the now-retired differential capture owner from
//! `halo2_axiom::transcript::Blake2bWrite` (`blake2b_simd` 1.0.4) and
//! snark-verifier's `PoseidonTranscript<C, NativeLoader, _, 3, 2, 8, 57>`.
//! Every script is replayed on a writer (challenges, absorbed bytes or
//! elements, and proof bytes must match) and then on a reader over the
//! recorded stream (challenges must match and every byte must be consumed).
//! The Poseidon vectors use oracle-mode `fe_to_fe` absorption.
//!
//! The production vectors at the end (injective Poseidon point absorption and
//! the instance-frame prelude, spec 6.2 and 6.3) have no vendored equivalent;
//! they pin this implementation's output and are recomputed independently from
//! the raw sponge.

use ff::PrimeField;
use group::GroupEncoding;
use iroha_pasta::{
    Ep, Eq, PastaAffine, PastaCurve,
    poseidon::{PoseidonField, Sponge},
};
use norito::json::Value;

use super::{
    Blake2bHash, PointAbsorption, PoseidonHash, Transcript, TranscriptError, TranscriptHash,
    TranscriptRead, TranscriptReader, TranscriptWrite, TranscriptWriter, absorb_prelude,
    blake2b::point_absorption, decode_point, decode_scalar, kagemusha_poseidon::point_elements,
};

/// The parsed fixture.
fn fixture() -> Value {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../fixtures/native_prover/kats_v1.json"
    );
    let text = std::fs::read_to_string(path).expect("read kats_v1.json");
    norito::json::parse_value(&text).expect("parse kats_v1.json")
}

fn hex_decode(text: &str) -> Vec<u8> {
    assert!(text.len().is_multiple_of(2), "odd hex length");
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).expect("hex digit"))
        .collect()
}

fn hex_encode(bytes: &[u8]) -> String {
    use core::fmt::Write as _;
    bytes.iter().fold(String::new(), |mut out, byte| {
        let _ = write!(out, "{byte:02x}");
        out
    })
}

fn bytes32(text: &str) -> [u8; 32] {
    hex_decode(text).try_into().expect("32 bytes")
}

fn field<'a>(value: &'a Value, key: &str) -> &'a Value {
    value
        .get(key)
        .unwrap_or_else(|| panic!("missing field {key}"))
}

fn text<'a>(value: &'a Value, key: &str) -> &'a str {
    field(value, key).as_str().expect("string field")
}

/// One recorded transcript operation.
enum Op<C: PastaCurve> {
    CommonPoint(C::AffineExt),
    CommonScalar(C::ScalarExt),
    WritePoint(C::AffineExt),
    WriteScalar(C::ScalarExt),
    Squeeze {
        challenge: [u8; 32],
        absorbed: usize,
    },
}

fn parse_ops<C: PastaCurve>(script: &Value) -> Vec<Op<C>> {
    field(script, "ops")
        .as_array()
        .expect("ops array")
        .iter()
        .map(|op| {
            let name = text(op, "op");
            let point = || decode_point::<C>(&bytes32(text(op, "value"))).expect("fixture point");
            let scalar =
                || decode_scalar::<C::ScalarExt>(&bytes32(text(op, "value"))).expect("scalar");
            match name {
                "common_point" => Op::CommonPoint(point()),
                "common_scalar" => Op::CommonScalar(scalar()),
                "write_point" => Op::WritePoint(point()),
                "write_scalar" => Op::WriteScalar(scalar()),
                "squeeze" => Op::Squeeze {
                    challenge: bytes32(text(op, "challenge")),
                    absorbed: usize::try_from(field(op, "absorbed").as_u64().expect("count"))
                        .expect("fits usize"),
                },
                other => panic!("unknown op {other}"),
            }
        })
        .collect()
}

/// What one absorption contributes to the recorded `absorbed` log.
trait AbsorbedLog<C: PastaCurve> {
    /// The log entry type (bytes for `BLAKE2b`, field elements for Poseidon).
    type Entry: Clone + PartialEq + core::fmt::Debug;
    fn point(point: &C::AffineExt) -> Vec<Self::Entry>;
    fn scalar(scalar: &C::ScalarExt) -> Vec<Self::Entry>;
    fn squeeze() -> Vec<Self::Entry>;
    fn recorded(script: &Value) -> Vec<Self::Entry>;
}

struct BlakeLog;

impl<C: PastaCurve> AbsorbedLog<C> for BlakeLog {
    type Entry = u8;
    fn point(point: &C::AffineExt) -> Vec<u8> {
        point_absorption::<C>(point).expect("finite").to_vec()
    }
    fn scalar(scalar: &C::ScalarExt) -> Vec<u8> {
        let mut bytes = vec![2_u8];
        bytes.extend_from_slice(&scalar.to_repr());
        bytes
    }
    fn squeeze() -> Vec<u8> {
        vec![0]
    }
    fn recorded(script: &Value) -> Vec<u8> {
        hex_decode(text(script, "absorbed_hex"))
    }
}

struct FeToFeLog;

impl<C: PastaCurve> AbsorbedLog<C> for FeToFeLog {
    type Entry = [u8; 32];
    fn point(point: &C::AffineExt) -> Vec<[u8; 32]> {
        point_elements::<C>(point, PointAbsorption::FeToFe)
            .expect("finite")
            .iter()
            .map(PrimeField::to_repr)
            .collect()
    }
    fn scalar(scalar: &C::ScalarExt) -> Vec<[u8; 32]> {
        vec![scalar.to_repr()]
    }
    fn squeeze() -> Vec<[u8; 32]> {
        Vec::new()
    }
    fn recorded(script: &Value) -> Vec<[u8; 32]> {
        field(script, "absorbed")
            .as_array()
            .expect("absorbed array")
            .iter()
            .map(|entry| bytes32(entry.as_str().expect("hex")))
            .collect()
    }
}

/// Replays every script of one curve section on writers and readers.
fn check_scripts<C, H, L>(section: &Value, fresh: impl Fn() -> H) -> usize
where
    C: PastaCurve,
    H: TranscriptHash<C>,
    L: AbsorbedLog<C>,
{
    let scripts = field(section, "scripts").as_array().expect("scripts");
    for script in scripts {
        let name = text(script, "name");
        let ops = parse_ops::<C>(script);
        let mut writer = TranscriptWriter::<C, H>::new(fresh());
        let mut log = Vec::new();
        for op in &ops {
            match op {
                Op::CommonPoint(point) => {
                    writer.common_point(point).expect("common_point");
                    log.extend(L::point(point));
                }
                Op::CommonScalar(scalar) => {
                    writer.common_scalar(scalar);
                    log.extend(L::scalar(scalar));
                }
                Op::WritePoint(point) => {
                    writer.write_point(point).expect("write_point");
                    log.extend(L::point(point));
                }
                Op::WriteScalar(scalar) => {
                    writer.write_scalar(scalar);
                    log.extend(L::scalar(scalar));
                }
                Op::Squeeze {
                    challenge,
                    absorbed,
                } => {
                    log.extend(L::squeeze());
                    assert_eq!(
                        writer.squeeze_challenge().to_repr(),
                        *challenge,
                        "{name}: challenge"
                    );
                    assert_eq!(log.len(), *absorbed, "{name}: absorbed count");
                }
            }
        }
        assert_eq!(log, L::recorded(script), "{name}: absorbed log");
        let stream = writer.finish();
        assert_eq!(
            hex_encode(&stream),
            text(script, "stream_hex"),
            "{name}: stream"
        );

        let mut reader = TranscriptReader::<C, H>::new(fresh(), &stream);
        for op in &ops {
            match op {
                Op::CommonPoint(point) => reader.common_point(point).expect("common_point"),
                Op::CommonScalar(scalar) => reader.common_scalar(scalar),
                Op::WritePoint(point) => assert_eq!(reader.read_point(), Ok(*point)),
                Op::WriteScalar(scalar) => assert_eq!(reader.read_scalar(), Ok(*scalar)),
                Op::Squeeze { challenge, .. } => assert_eq!(
                    reader.squeeze_challenge().to_repr(),
                    *challenge,
                    "{name}: replayed challenge"
                ),
            }
        }
        assert_eq!(reader.finish(), Ok(()), "{name}: stream consumed");
    }
    scripts.len()
}

/// Checks every recorded rejection of one curve section.
fn check_rejections<C: PastaCurve, H: TranscriptHash<C>>(
    section: &Value,
    fresh: impl Fn() -> H,
) -> usize {
    let rejections = field(section, "rejections").as_array().expect("rejections");
    for rejection in rejections {
        let name = text(rejection, "name");
        assert_eq!(text(rejection, "result"), "rejected", "{name}");
        let result = match text(rejection, "op") {
            "common_point" => {
                let mut writer = TranscriptWriter::<C, H>::new(fresh());
                writer.common_point(&C::AffineExt::default())
            }
            "read_scalar" => {
                let bytes = hex_decode(text(rejection, "input_hex"));
                let mut reader = TranscriptReader::<C, H>::new(fresh(), &bytes);
                reader.read_scalar().map(|_| ())
            }
            "read_point" => {
                let bytes = hex_decode(text(rejection, "input_hex"));
                let mut reader = TranscriptReader::<C, H>::new(fresh(), &bytes);
                reader.read_point().map(|_| ())
            }
            other => panic!("unknown rejection op {other}"),
        };
        let expected = match name {
            "common_point_identity" | "point_identity" => TranscriptError::IdentityPoint,
            "scalar_modulus" | "scalar_all_ones" => TranscriptError::NonCanonicalScalar,
            "point_non_canonical_x" | "point_off_curve" => TranscriptError::InvalidPoint,
            other => panic!("unknown rejection {other}"),
        };
        assert_eq!(result, Err(expected), "{name}");
    }
    rejections.len()
}

#[test]
fn blake2b_transcript_matches_vendored_vectors() {
    let fixture = fixture();
    let section = field(&fixture, "blake2b_transcript");
    assert_eq!(
        text(section, "hash"),
        "BLAKE2b, 64-byte output, personalization \"Halo2-Transcript\""
    );
    let scripts =
        check_scripts::<Ep, Blake2bHash<Ep>, BlakeLog>(field(section, "ep"), Blake2bHash::new)
            + check_scripts::<Eq, Blake2bHash<Eq>, BlakeLog>(
                field(section, "eq"),
                Blake2bHash::new,
            );
    let rejections = check_rejections::<Ep, _>(field(section, "ep"), Blake2bHash::new)
        + check_rejections::<Eq, _>(field(section, "eq"), Blake2bHash::new);
    assert_eq!((scripts, rejections), (8, 12));
}

#[test]
fn poseidon_transcript_matches_vendored_vectors_in_oracle_mode() {
    let fixture = fixture();
    let section = field(&fixture, "poseidon_transcript");
    let scripts = check_scripts::<Ep, PoseidonHash<Ep>, FeToFeLog>(
        field(section, "ep"),
        PoseidonHash::new_oracle,
    ) + check_scripts::<Eq, PoseidonHash<Eq>, FeToFeLog>(
        field(section, "eq"),
        PoseidonHash::new_oracle,
    );
    let rejections = check_rejections::<Ep, _>(field(section, "ep"), PoseidonHash::new_oracle)
        + check_rejections::<Eq, _>(field(section, "eq"), PoseidonHash::new_oracle);
    // Production absorption rejects exactly the same inputs.
    let production = check_rejections::<Ep, _>(field(section, "ep"), PoseidonHash::new)
        + check_rejections::<Eq, _>(field(section, "eq"), PoseidonHash::new);
    assert_eq!((scripts, rejections, production), (8, 12, 12));
}

/// The points of the fixture's `points` script for curve `C`.
fn fixture_points<C: PastaCurve>(curve: &str) -> Vec<C::AffineExt> {
    let fixture = fixture();
    let scripts = field(
        field(field(&fixture, "poseidon_transcript"), curve),
        "scripts",
    )
    .as_array()
    .expect("scripts");
    let mut points = Vec::new();
    for script in scripts {
        for op in parse_ops::<C>(script) {
            if let Op::CommonPoint(point) | Op::WritePoint(point) = op {
                points.push(point);
            }
        }
    }
    points
}

/// `a - b` for little-endian 256-bit integers with `a >= b`.
fn sub_le(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
    let mut out = [0_u8; 32];
    let mut borrow = 0_i16;
    for i in 0..32 {
        let mut digit = i16::from(a[i]) - i16::from(b[i]) - borrow;
        borrow = 0;
        if digit < 0 {
            digit += 256;
            borrow = 1;
        }
        out[i] = u8::try_from(digit).expect("byte");
    }
    assert_eq!(borrow, 0, "a >= b");
    out
}

/// Production Poseidon challenge over `points`, from the transcript and from
/// the raw sponge with the spec 6.2 encoding computed independently.
fn production_poseidon<C: PastaCurve>(points: &[C::AffineExt]) -> C::ScalarExt
where
    C::ScalarExt: PoseidonField,
{
    let mut writer = TranscriptWriter::<C, PoseidonHash<C>>::new(PoseidonHash::new());
    let mut sponge = Sponge::<C::ScalarExt>::new();
    let modulus = crate::cs::descriptor::modulus_le_bytes::<C::ScalarExt>();
    for point in points {
        writer.write_point(point).expect("finite");
        let (x, y): (C::Base, C::Base) = Option::from(point.coordinates()).expect("finite");
        let x_bytes = x.to_repr();
        // Big-endian comparison of the little-endian encodings.
        let high = x_bytes.iter().rev().cmp(modulus.iter().rev()) != core::cmp::Ordering::Less;
        let low_bytes = if high {
            sub_le(&x_bytes, &modulus)
        } else {
            x_bytes
        };
        let low = decode_scalar::<C::ScalarExt>(&low_bytes).expect("x mod |F| < |F|");
        let parity = u64::from(y.to_repr()[0] & 1);
        sponge.update(&[low, C::ScalarExt::from(u64::from(high) + 2 * parity)]);
    }
    let challenge = writer.squeeze_challenge();
    assert_eq!(challenge, sponge.squeeze());
    challenge
}

#[test]
fn production_poseidon_and_prelude_vectors() {
    let pallas = production_poseidon::<Ep>(&fixture_points::<Ep>("ep"));
    let vesta = production_poseidon::<Eq>(&fixture_points::<Eq>("eq"));
    // Injective absorption differs from the vendored fe_to_fe vectors.
    let mut oracle = TranscriptWriter::<Eq, PoseidonHash<Eq>>::new(PoseidonHash::new_oracle());
    for point in fixture_points::<Eq>("eq") {
        oracle.write_point(&point).expect("finite");
    }
    assert_ne!(oracle.squeeze_challenge(), vesta);

    let prelude = |hash_pallas: &mut dyn Transcript<Ep>| {
        let repr = iroha_pasta::Fq::from(0x0123_4567_89ab_cdef_u64);
        absorb_prelude::<Ep, _>(hash_pallas, &repr, &[1, 0, 65_535]);
        hash_pallas.squeeze_challenge()
    };
    let mut blake = TranscriptWriter::<Ep, Blake2bHash<Ep>>::new(Blake2bHash::new());
    let mut poseidon = TranscriptWriter::<Ep, PoseidonHash<Ep>>::new(PoseidonHash::new());
    let prelude_blake = prelude(&mut blake);
    let prelude_poseidon = prelude(&mut poseidon);

    let pinned = [
        hex_encode(&pallas.to_repr()),
        hex_encode(&vesta.to_repr()),
        hex_encode(&prelude_blake.to_repr()),
        hex_encode(&prelude_poseidon.to_repr()),
    ];
    assert_eq!(pinned, PRODUCTION_VECTORS.map(str::to_owned), "{pinned:#?}");
}

/// Pinned production vectors: Poseidon over the Pallas and Vesta fixture
/// points with injective absorption, then the prelude
/// (`repr = 0x0123456789abcdef`, lengths `[1, 0, 65535]`) on `BLAKE2b` and on
/// Poseidon (Pallas).
const PRODUCTION_VECTORS: [&str; 4] = [
    "ca9a3e4330753feb32e72fc1e04d5c98923911a29aa4386f5714c4b3fba17b01",
    "e03edf8aac0538cf8f297624111e0468011ed8b17410ff9ca8b42488e5c5b506",
    "2e5dad28cd276cc2f9c2d2394d7a09109954df8cf8e8a094970afdf96efa752f",
    "54ab7e702c276e3c0da757c9f2f930aebc9f75e27054cea12e4a327951ec3f3a",
];

#[test]
fn fixture_points_round_trip() {
    for point in fixture_points::<Ep>("ep") {
        assert_eq!(decode_point::<Ep>(&point.to_bytes()), Ok(point));
    }
}
