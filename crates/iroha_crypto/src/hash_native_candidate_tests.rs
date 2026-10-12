//! Candidate canonical native commitment frame and its comparator digests.
//!
//! Task H.1 of `specs/zk_delivery_plan.md` selects raw BLAKE3-256 over one
//! canonical byte frame as the candidate for commitments that are hashed
//! natively and never recomputed inside a proof relation. `canonical_native_commitment`
//! in `specs/zk_primitive_workloads.json` is the specification; H.2 freezes it
//! and F.5 implements it. Nothing here is a production owner: the encoder below
//! exists so the specification has an executable reference.
//!
//! `hash_native_candidate_vectors.txt` holds the example inputs, the exact frame
//! and three digests of it. `scripts/check_zk_primitive_workloads.py` rebuilds
//! every frame from the layout the specification states and computes all three
//! columns without this crate: BLAKE3-256 with the pure-Python reference in
//! `scripts/zk_blake3_reference.py`, BLAKE2b-256 and SHAKE256/48 with the Python
//! standard library. The tests here recompute all three with the Rust crates, so
//! each tracked digest is checked by two independent implementations.

use super::Hash;
use blake2::{Blake2b, Digest as _, digest::consts::U32};
use sha3::{
    Sha3_384, Shake256,
    digest::{ExtendableOutput as _, Update as _, XofReader as _},
};

const VECTORS: &str = include_str!("hash_native_candidate_vectors.txt");
const FRAME_MAGIC_V1: &[u8] = b"iroha:native-commitment:frame:v1\0";
const MAX_DOMAIN_FIELD_BYTES_V1: usize = 4096;
const MAX_PAYLOAD_FIELDS_V1: usize = 65_535;
/// Column of the payload field count in an `example` row; the fields follow it.
const FIELD_COUNT_COLUMN: usize = 11;

struct ExampleV1 {
    name: String,
    algorithm: Vec<u8>,
    domain: [Vec<u8>; 5],
    coordinates: [u64; 3],
    fields: Vec<Vec<u8>>,
    frame: Vec<u8>,
    blake3: String,
    blake2b_256: String,
    shake256_384: String,
}

fn unhex(text: &str) -> Vec<u8> {
    if text == "-" {
        return Vec::new();
    }
    hex::decode(text).expect("vector hex")
}

fn examples() -> Vec<ExampleV1> {
    VECTORS
        .lines()
        .filter(|line| line.starts_with("example "))
        .map(|line| {
            let row = line.split(' ').collect::<Vec<_>>();
            let field_count = row[FIELD_COUNT_COLUMN]
                .parse::<usize>()
                .expect("field count");
            let tail = FIELD_COUNT_COLUMN + 1 + field_count;
            assert_eq!(row.len(), tail + 4, "example row shape: {}", row[1]);
            ExampleV1 {
                name: row[1].to_owned(),
                algorithm: unhex(row[2]),
                domain: core::array::from_fn(|index| unhex(row[3 + index])),
                coordinates: core::array::from_fn(|index| {
                    row[8 + index].parse::<u64>().expect("coordinate")
                }),
                fields: row[FIELD_COUNT_COLUMN + 1..tail]
                    .iter()
                    .map(|field| unhex(field))
                    .collect(),
                frame: unhex(row[tail]),
                blake3: row[tail + 1].to_owned(),
                blake2b_256: row[tail + 2].to_owned(),
                shake256_384: row[tail + 3].to_owned(),
            }
        })
        .collect()
}

/// Reference encoder of the candidate frame, version 1.
///
/// Every position is always present: an empty byte string is encoded with a
/// zero length and is distinct from a missing field, which the frame cannot
/// express. All integers are little-endian.
fn frame_v1(
    algorithm: &[u8],
    domain: &[Vec<u8>; 5],
    coordinates: [u64; 3],
    fields: &[Vec<u8>],
) -> Option<Vec<u8>> {
    if fields.len() > MAX_PAYLOAD_FIELDS_V1 {
        return None;
    }
    let mut frame = FRAME_MAGIC_V1.to_vec();
    let labelled = core::iter::once(algorithm).chain(domain.iter().map(Vec::as_slice));
    for (tag, bytes) in (1u8..).zip(labelled) {
        if bytes.len() > MAX_DOMAIN_FIELD_BYTES_V1 {
            return None;
        }
        frame.push(tag);
        frame.extend_from_slice(&u32::try_from(bytes.len()).ok()?.to_le_bytes());
        frame.extend_from_slice(bytes);
    }
    for (tag, value) in (7u8..).zip(coordinates) {
        frame.push(tag);
        frame.extend_from_slice(&value.to_le_bytes());
    }
    frame.push(0x0a);
    frame.extend_from_slice(&u32::try_from(fields.len()).ok()?.to_le_bytes());
    for field in fields {
        u32::try_from(field.len()).ok()?;
        frame.push(0x0b);
        frame.extend_from_slice(&(field.len() as u64).to_le_bytes());
        frame.extend_from_slice(field);
    }
    Some(frame)
}

fn blake2b_256(bytes: &[u8]) -> [u8; 32] {
    Blake2b::<U32>::digest(bytes).into()
}

fn shake256_384(bytes: &[u8]) -> [u8; 48] {
    let mut shake = Shake256::default();
    shake.update(bytes);
    let mut out = [0u8; 48];
    shake.finalize_xof().read(&mut out);
    out
}

#[test]
fn candidate_frames_and_digests_match_the_tracked_vectors() {
    let examples = examples();
    assert!(examples.len() >= 8, "the fixture lists every example");
    for example in &examples {
        let frame = frame_v1(
            &example.algorithm,
            &example.domain,
            example.coordinates,
            &example.fields,
        )
        .expect("example is within the frame bounds");
        assert_eq!(frame, example.frame, "frame of {}", example.name);
        assert_eq!(
            blake3::hash(&frame).to_hex().as_str(),
            example.blake3,
            "BLAKE3-256 of {}",
            example.name
        );
        assert_eq!(
            hex::encode(blake2b_256(&frame)),
            example.blake2b_256,
            "BLAKE2b-256 of {}",
            example.name
        );
        assert_eq!(
            hex::encode(shake256_384(&frame)),
            example.shake256_384,
            "SHAKE256/48 of {}",
            example.name
        );
    }
}

#[test]
fn every_frame_position_separates_the_digest() {
    let examples = examples();
    let base = examples
        .iter()
        .find(|example| example.name == "spentness-node")
        .expect("spentness example");
    let reference = frame_v1(
        &base.algorithm,
        &base.domain,
        base.coordinates,
        &base.fields,
    )
    .expect("reference frame");
    let mut frames = vec![reference];
    let mut algorithm = base.algorithm.clone();
    algorithm.push(b'x');
    frames.push(frame_v1(&algorithm, &base.domain, base.coordinates, &base.fields).unwrap());
    for index in 0..5 {
        let mut domain = base.domain.clone();
        domain[index].push(b'x');
        frames.push(frame_v1(&base.algorithm, &domain, base.coordinates, &base.fields).unwrap());
    }
    for index in 0..3 {
        let mut coordinates = base.coordinates;
        coordinates[index] += 1;
        frames.push(frame_v1(&base.algorithm, &base.domain, coordinates, &base.fields).unwrap());
    }
    // Moving a byte across a field boundary, adding an empty field and
    // swapping two fields all change the frame.
    let joined = vec![base.fields.concat()];
    frames.push(frame_v1(&base.algorithm, &base.domain, base.coordinates, &joined).unwrap());
    let mut with_empty = base.fields.clone();
    with_empty.push(Vec::new());
    frames.push(frame_v1(&base.algorithm, &base.domain, base.coordinates, &with_empty).unwrap());
    let mut swapped = base.fields.clone();
    swapped.reverse();
    frames.push(frame_v1(&base.algorithm, &base.domain, base.coordinates, &swapped).unwrap());

    let digests = frames
        .iter()
        .map(|frame| *blake3::hash(frame).as_bytes())
        .collect::<std::collections::BTreeSet<_>>();
    assert_eq!(digests.len(), frames.len(), "every variation is distinct");
}

#[test]
fn frame_rejects_inputs_outside_its_bounds() {
    let domain: [Vec<u8>; 5] = core::array::from_fn(|_| b"d".to_vec());
    let oversized = vec![0u8; MAX_DOMAIN_FIELD_BYTES_V1 + 1];
    assert!(frame_v1(&oversized, &domain, [0; 3], &[]).is_none());
    let mut wide = domain.clone();
    wide[2] = oversized;
    assert!(frame_v1(b"blake3-256", &wide, [0; 3], &[]).is_none());
    assert!(
        frame_v1(
            b"blake3-256",
            &domain,
            [0; 3],
            &vec![Vec::new(); MAX_PAYLOAD_FIELDS_V1 + 1]
        )
        .is_none()
    );
    assert!(
        frame_v1(
            b"blake3-256",
            &domain,
            [0; 3],
            &vec![Vec::new(); MAX_PAYLOAD_FIELDS_V1]
        )
        .is_some()
    );
}

/// Published empty-input vectors of the candidate and its comparators, and the
/// difference between raw BLAKE2b-256 and the marked ledger [`Hash`].
#[test]
fn candidate_and_comparator_primitives_match_published_vectors() {
    // Official BLAKE3 test vectors: the input is 0, 1, .., 250 repeated to the
    // stated length. `scripts/zk_blake3_reference.py` pins the same values.
    for (length, expected) in [
        (
            0usize,
            "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262",
        ),
        (
            1,
            "2d3adedff11b61f14c886e35afa036736dcd87a74d27b5c1510225d0f592e213",
        ),
        (
            1023,
            "10108970eeda3eb932baac1428c7a2163b0e924c9a9e25b35bba72b28f70bd11",
        ),
        (
            1024,
            "42214739f095a406f3fc83deb889744ac00df831c10daa55189b5d121c855af7",
        ),
        (
            1025,
            "d00278ae47eb27b34faecf67b4fe263f82d5412916c1ffd97c8cb7fb814b8444",
        ),
        (
            2048,
            "e776b6028c7cd22a4d0ba182a8bf62205d2ef576467e838ed6f2529b85fba24a",
        ),
        (
            3072,
            "b98cb0ff3623be03326b373de6b9095218513e64f1ee2edd2525c7ad1e5cffd2",
        ),
    ] {
        let message = (0..length)
            .map(|index| u8::try_from(index % 251).expect("below 251"))
            .collect::<Vec<_>>();
        assert_eq!(
            blake3::hash(&message).to_hex().as_str(),
            expected,
            "BLAKE3 test vector of {length} bytes"
        );
    }
    assert_eq!(super::blake3_256(b""), *blake3::hash(b"").as_bytes());
    let raw = blake2b_256(b"");
    assert_eq!(
        hex::encode(raw),
        "0e5751c026e543b2e8ab2eb06099daa1d1e5df47778f7787faab45cdf12fe3a8"
    );
    assert_eq!(
        hex::encode(Sha3_384::digest(b"")),
        "0c63a75b845e4f7d01107d852e4c2485c51a50aaaa94fc61995e71bbee983a2a\
         c3713831264adb47fb6bd1e058d5f004"
    );
    assert_eq!(
        hex::encode(shake256_384(b"")),
        "46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762f\
         d75dc4ddd8c0f200cb05019d67b592f6"
    );
    // The ledger identity hash is not raw BLAKE2b-256: it forces the low bit of
    // the last byte, so its output space is half of the 256-bit strings.
    let marked: [u8; 32] = Hash::new(b"").into();
    assert_ne!(marked, raw);
    let mut expected = raw;
    expected[31] |= 1;
    assert_eq!(marked, expected);
}

/// Exploratory single-thread timing of the candidate, its comparators and the
/// six-lane digest it would replace. It prints nanoseconds per digest and
/// asserts nothing about them: the numbers guide the H.1 choice and are never a
/// qualification result.
#[test]
#[ignore = "exploratory timing; run in release with --nocapture"]
fn exploratory_native_digest_timing() {
    use std::{hint::black_box, time::Instant};
    let domain = fastpq_isi::GoldilocksDigestDomainV1 {
        catalog: b"iroha-privacy-exact12-v1",
        protocol: b"h1-exploratory-native-digest-v1",
        profile: b"poseidon-x7-goldilocks-6x64-v1",
        role: b"timing",
        phase: b"one-shot",
        level: 0,
        index: 0,
        counter: 0,
    };
    for length in [64usize, 256, 1024, 4096] {
        let message = (0..length)
            .map(|index| index.to_le_bytes()[0])
            .collect::<Vec<_>>();
        let time = |iterations: u32, run: &dyn Fn(&[u8]) -> u8| {
            let mut best = u128::MAX;
            for _ in 0..5 {
                let start = Instant::now();
                let mut sink = 0u8;
                for _ in 0..iterations {
                    sink ^= run(black_box(&message));
                }
                black_box(sink);
                best = best.min(start.elapsed().as_nanos() / u128::from(iterations));
            }
            best
        };
        let blake3_ns = time(20_000, &|bytes| blake3::hash(bytes).as_bytes()[0]);
        let blake2b_ns = time(20_000, &|bytes| blake2b_256(bytes)[0]);
        let marked_ns = time(20_000, &|bytes| Hash::new(bytes).as_ref()[0]);
        let shake_ns = time(20_000, &|bytes| shake256_384(bytes)[0]);
        let sha3_ns = time(20_000, &|bytes| Sha3_384::digest(bytes)[0]);
        let digest384_ns = time(200, &|bytes| {
            fastpq_isi::hash_bytes_384_v1(domain, &[bytes])
                .expect("message within framing limits")
                .to_le_bytes()[0]
        });
        println!(
            "h1-exploratory bytes={length} blake3_256_ns={blake3_ns} blake2b_256_ns={blake2b_ns} \
             iroha_hash_ns={marked_ns} shake256_384_ns={shake_ns} sha3_384_ns={sha3_ns} \
             goldilocks_digest384_ns={digest384_ns}"
        );
    }
}
