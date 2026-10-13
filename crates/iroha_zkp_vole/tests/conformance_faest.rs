//! Plain FAEST against the official FAEST v3.0.2 full-signature vectors
//! (`faest_tvs.txt`) on all twelve parameter sets.
//!
//! Per set, from the fixture's secret key, message and signing randomness:
//!
//! * the public key and the extended witness of the secret key;
//! * the exact signature bytes, which pins every layer at once, including the
//!   counter loop with both retry causes;
//! * acceptance of the official signature.
//!
//! Further, per set: rejection of single-bit flips in every signature field, of a
//! wrong message and a wrong public key, of non-zero grinding bits and of
//! non-canonical opening padding; and a sign-then-verify round trip with a fresh
//! key and fresh deterministic randomness.
//!
//! Each set has its own tests so that the harness runs them in parallel.

mod common;

use std::time::Instant;

use common::Fixture;
use iroha_zkp_vole::{
    bavc::{self, BavcError},
    codec::{self, CodecError, Field},
    faest::{self, FaestError, PublicKey, SecretKey},
    params::{
        FAEST_128F, FAEST_128S, FAEST_192F, FAEST_192S, FAEST_256F, FAEST_256S, FAEST_EM_128F,
        FAEST_EM_128S, FAEST_EM_192F, FAEST_EM_192S, FAEST_EM_256F, FAEST_EM_256S, FaestParams,
    },
    proof::ProofError,
};

/// The fixture name of every set, in the fixture's order.
const SETS: [(&str, &FaestParams); 12] = [
    ("faest_128s", &FAEST_128S),
    ("faest_128f", &FAEST_128F),
    ("faest_192s", &FAEST_192S),
    ("faest_192f", &FAEST_192F),
    ("faest_256s", &FAEST_256S),
    ("faest_256f", &FAEST_256F),
    ("faest_em_128s", &FAEST_EM_128S),
    ("faest_em_128f", &FAEST_EM_128F),
    ("faest_em_192s", &FAEST_EM_192S),
    ("faest_em_192f", &FAEST_EM_192F),
    ("faest_em_256s", &FAEST_EM_256S),
    ("faest_em_256f", &FAEST_EM_256F),
];

/// The counter each official signature ends with, as measured by the validated
/// prototype: the number of rejected counters before the accepted one.
const COUNTERS: [u32; 12] = [
    12741, 370, 2757, 459, 51, 318, 2138, 175, 6225, 242, 5329, 363,
];

/// The entries of one set.
struct Vector {
    fixture: Fixture,
    set: &'static FaestParams,
    sk: Vec<u8>,
    pk: Vec<u8>,
    witness: Vec<u8>,
    signature: Vec<u8>,
    message: Vec<u8>,
    rho: Vec<u8>,
}

fn vector(name: &'static str) -> Vector {
    let (_, set) = SETS
        .iter()
        .find(|(set_name, _)| *set_name == name)
        .expect("a fixture name");
    let fixture = Fixture::load("faest_tvs");
    let entry = |field: &str| fixture.bytes(&format!("faest_tvs.{name}.{field}"));
    let (sk, pk, witness, signature) = (
        entry("sk"),
        entry("pk"),
        entry("witness"),
        entry("signature"),
    );
    let message = fixture.bytes("faest_tvs.message");
    let rho = fixture.bytes("faest_tvs.random_seed");
    fixture.assert_consumed(&format!("faest_tvs.{name}."));
    Vector {
        fixture,
        set,
        sk,
        pk,
        witness,
        signature,
        message,
        rho,
    }
}

/// Public key, witness, exact signature bytes and acceptance.
fn reproduces(name: &'static str) {
    let vector = vector(name);
    let set = vector.set;
    assert_eq!(vector.sk.len(), set.secret_key_bytes(), "{name}");
    assert_eq!(vector.pk.len(), set.public_key_bytes(), "{name}");
    assert_eq!(vector.signature.len(), set.signature_bytes(), "{name}");
    assert_eq!(8 * vector.witness.len(), set.owf().ell(), "{name}");

    let secret = SecretKey::from_bytes(set, &vector.sk).expect("the official key is valid");
    assert_eq!(secret.public_key().as_bytes(), vector.pk, "{name}: pk");
    assert_eq!(
        secret.witness().expect("valid key")[..],
        vector.witness[..],
        "{name}: witness"
    );

    let start = Instant::now();
    let signature = secret
        .sign(&vector.message, &vector.rho)
        .expect("signing succeeds");
    let signing = start.elapsed();
    // Compare field by field first so that a failure names the layer.
    let params = set.proof();
    for field in Field::ALL {
        let range = field.offset(params)..field.offset(params) + field.bytes(params);
        assert_eq!(
            signature[range.clone()],
            vector.signature[range],
            "{name}: {field:?}"
        );
    }
    assert_eq!(signature, vector.signature, "{name}: signature");
    let fields = codec::decode(params, &signature).expect("canonical");
    let index = SETS.iter().position(|(set_name, _)| *set_name == name);
    assert_eq!(
        Some(fields.counter),
        index.map(|index| COUNTERS[index]),
        "{name}"
    );

    let start = Instant::now();
    assert_eq!(
        faest::verify(set, &vector.pk, &vector.message, &vector.signature),
        Ok(()),
        "{name}: verification of the official signature"
    );
    // Shown with `--nocapture`.
    println!(
        "{name}: sign {:.2} s, verify {:.2} s",
        signing.as_secs_f64(),
        start.elapsed().as_secs_f64()
    );
    let public = PublicKey::from_bytes(set, &vector.pk).expect("official length");
    assert_eq!(public.verify(&vector.message, &vector.signature), Ok(()));
    vector
        .fixture
        .assert_consumed(&format!("faest_tvs.{name}."));
}

/// A signature of the official key whose opening leaves at least one of the
/// `T_open` node slots unused, with its message and the number of used slots.
fn padded_signature(vector: &Vector) -> (Vec<u8>, Vec<u8>, usize) {
    let row = vector.set.vole();
    let used = |signature: &[u8]| {
        let fields = codec::decode(vector.set.proof(), signature).expect("canonical");
        let hidden = bavc::decode_challenge(row, fields.challenge).expect("zero grinding bits");
        bavc::opening_nodes(row, &hidden).expect("valid pattern")
    };
    let nodes = used(&vector.signature);
    if nodes < row.t_open() {
        return (vector.message.clone(), vector.signature.clone(), nodes);
    }
    // The official signature fills every slot: sign `message || byte` with the
    // official key and randomness until one does not.
    let secret = SecretKey::from_bytes(vector.set, &vector.sk).expect("the official key is valid");
    (0u8..=255)
        .find_map(|byte| {
            let mut message = vector.message.clone();
            message.push(byte);
            let signature = secret
                .sign(&message, &vector.rho)
                .expect("signing succeeds");
            let nodes = used(&signature);
            (nodes < row.t_open()).then_some((message, signature, nodes))
        })
        .expect("some signature opens with fewer than T_open keys")
}

/// Everything that must be rejected, starting from the official signature.
fn rejects(name: &'static str) {
    let vector = vector(name);
    let (set, params) = (vector.set, vector.set.proof());
    let row = params.vole();
    let accepts =
        |pk: &[u8], message: &[u8], signature: &[u8]| faest::verify(set, pk, message, signature);
    let mismatch = Err(FaestError::Proof(ProofError::ChallengeMismatch));

    // Single-bit flips in every field: the first, a middle and the last bit on
    // the fast sets; one of the three, rotating, on the small sets, whose
    // verification is several times slower.
    let thin = name.ends_with('s');
    let mut flipped = 0;
    for (index, field) in Field::ALL.into_iter().enumerate() {
        let (offset, bits) = (field.offset(params), 8 * field.bytes(params));
        let positions = [0, bits / 2 + 3, bits - 1];
        for (kind, bit) in positions.into_iter().enumerate() {
            // The grinding-bit flip is cheap and always taken.
            let grinding = field == Field::Challenge && kind == 2;
            if thin && kind != index % 3 && !grinding {
                continue;
            }
            let mut forged = vector.signature.clone();
            forged[offset + bit / 8] ^= 1 << (bit % 8);
            let outcome = accepts(&vector.pk, &vector.message, &forged);
            assert!(outcome.is_err(), "{name}: {field:?} bit {bit} was accepted");
            if grinding {
                assert_eq!(
                    outcome,
                    Err(FaestError::Proof(ProofError::Codec(CodecError::Challenge(
                        BavcError::GrindingBitsSet
                    )))),
                    "{name}"
                );
            }
            // These fields are bound through the hash chain only.
            if matches!(field, Field::Counter | Field::IvPre | Field::UTilde) {
                assert_eq!(outcome, mismatch, "{name}: {field:?}");
            }
            flipped += 1;
        }
    }
    assert_eq!(flipped, if thin { 10 } else { 27 }, "{name}");

    // Every grinding bit, alone.
    let challenge = Field::Challenge.offset(params);
    for bit in row.n_delta()..row.lambda().bits() {
        let mut forged = vector.signature.clone();
        forged[challenge + bit / 8] ^= 1 << (bit % 8);
        assert_eq!(
            accepts(&vector.pk, &vector.message, &forged),
            Err(FaestError::Proof(ProofError::Codec(CodecError::Challenge(
                BavcError::GrindingBitsSet
            )))),
            "{name}: grinding bit {bit}"
        );
    }

    // Another message, and another public key: a flipped bit of x and of y.
    let mut message = vector.message.clone();
    message[0] ^= 1;
    assert_eq!(accepts(&vector.pk, &message, &vector.signature), mismatch);
    assert_eq!(accepts(&vector.pk, &[], &vector.signature), mismatch);
    for bit in [0, 8 * vector.pk.len() - 1] {
        let mut pk = vector.pk.clone();
        pk[bit / 8] ^= 1 << (bit % 8);
        assert_eq!(
            accepts(&pk, &vector.message, &vector.signature),
            mismatch,
            "{name}: public key bit {bit}"
        );
    }

    // Wrong lengths.
    let length = vector.signature.len();
    for len in [0, length - 1] {
        assert_eq!(
            accepts(&vector.pk, &vector.message, &vector.signature[..len]),
            Err(FaestError::Proof(ProofError::Codec(
                CodecError::InvalidLength {
                    expected: length,
                    actual: len
                }
            ))),
            "{name}"
        );
    }
    let mut longer = vector.signature.clone();
    longer.push(0);
    assert!(accepts(&vector.pk, &vector.message, &longer).is_err());
    assert!(matches!(
        accepts(&vector.pk[1..], &vector.message, &vector.signature),
        Err(FaestError::InvalidLength { .. })
    ));

    // Non-canonical padding of the opening.
    let (message, signature, used) = padded_signature(&vector);
    assert_eq!(accepts(&vector.pk, &message, &signature), Ok(()), "{name}");
    let lb = row.lambda().bytes();
    let start = Field::Decommitment.offset(params) + (row.tau() * row.n_leafcom() + used) * lb;
    let end = challenge;
    assert!(start < end, "{name}");
    assert!(signature[start..end].iter().all(|&byte| byte == 0));
    for (at, value) in [(start, 1u8), (end - 1, 0x80)] {
        let mut forged = signature.clone();
        forged[at] = value;
        assert_eq!(
            accepts(&vector.pk, &message, &forged),
            Err(FaestError::Proof(ProofError::Codec(
                CodecError::NonZeroPadding {
                    field: Field::Decommitment
                }
            ))),
            "{name}: padding byte {at}"
        );
    }
    vector
        .fixture
        .assert_consumed(&format!("faest_tvs.{name}."));
}

/// A deterministic stand-in for a randomness source.
fn source(seed: u64) -> impl FnMut(&mut [u8]) {
    let mut state = seed.wrapping_mul(0x9e37_79b9_7f4a_7c15) | 1;
    move |buffer: &mut [u8]| {
        for byte in buffer {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            *byte = state.to_le_bytes()[3];
        }
    }
}

/// Sign and verify with a fresh key, message and randomness.
fn round_trips(name: &'static str) {
    let (index, set) = SETS
        .iter()
        .enumerate()
        .find_map(|(index, (set_name, set))| (*set_name == name).then_some((index, *set)))
        .expect("a fixture name");
    let seed = 1000 + u64::try_from(index).expect("small");
    let secret = SecretKey::generate(set, source(seed)).expect("random source");
    let mut rho = vec![0u8; set.vole().lambda().bytes()];
    source(seed + 100)(&mut rho);
    let mut message = vec![0u8; 5 + 13 * index];
    source(seed + 200)(&mut message);

    let signature = secret.sign(&message, &rho).expect("signing succeeds");
    assert_eq!(signature.len(), set.signature_bytes(), "{name}");
    let public = secret.public_key();
    assert_eq!(public.verify(&message, &signature), Ok(()), "{name}");
    // Deterministic in its inputs.
    if name.ends_with('f') {
        assert_eq!(secret.sign(&message, &rho), Ok(signature.clone()), "{name}");
    }
    // Bound to the message.
    message.push(0);
    assert_eq!(
        public.verify(&message, &signature),
        Err(FaestError::Proof(ProofError::ChallengeMismatch)),
        "{name}"
    );
}

macro_rules! per_set {
    ($($module:ident => $name:literal),* $(,)?) => {
        $(
            mod $module {
                #[test]
                fn the_official_signature_is_reproduced_and_verifies() {
                    super::reproduces($name);
                }

                #[test]
                fn forgeries_and_non_canonical_encodings_are_rejected() {
                    super::rejects($name);
                }

                #[test]
                fn a_fresh_signature_verifies() {
                    super::round_trips($name);
                }
            }
        )*

        /// The names the modules above cover.
        const COVERED: &[&str] = &[$($name),*];
    };
}

per_set! {
    faest_128s => "faest_128s",
    faest_128f => "faest_128f",
    faest_192s => "faest_192s",
    faest_192f => "faest_192f",
    faest_256s => "faest_256s",
    faest_256f => "faest_256f",
    faest_em_128s => "faest_em_128s",
    faest_em_128f => "faest_em_128f",
    faest_em_192s => "faest_em_192s",
    faest_em_192f => "faest_em_192f",
    faest_em_256s => "faest_em_256s",
    faest_em_256f => "faest_em_256f",
}

/// Every entry of the fixture belongs to a set that has its tests above, each of
/// which reads all four entries of its set and the two shared ones.
#[test]
fn every_entry_of_the_fixture_is_covered_by_a_per_set_test() {
    let fixture = Fixture::load("faest_tvs");
    assert_eq!(COVERED.len(), 12);
    for ((name, _), covered) in SETS.iter().zip(COVERED) {
        assert_eq!(name, covered);
    }
    let mut expected = vec![
        "faest_tvs.random_seed".to_owned(),
        "faest_tvs.message".to_owned(),
    ];
    for name in COVERED {
        for field in ["sk", "pk", "witness", "signature"] {
            expected.push(format!("faest_tvs.{name}.{field}"));
        }
    }
    assert_eq!(fixture.names(), expected);
    for name in fixture.names() {
        assert!(!fixture.bytes(name).is_empty(), "{name}");
    }
    fixture.assert_consumed("faest_tvs.");
}
