//! The AES and Even-Mansour one-way functions against the official FAEST v3.0.2
//! vectors (`owf_tvs.txt`): `OWF_key(input) = output` for the three security
//! levels of both families.
//!
//! The upstream generator has vectors for the six `f` sets only; the one-way
//! function depends on the family and the security level alone, so the `s` sets
//! are checked against the same vectors.

mod common;

use common::Fixture;
use iroha_zkp_vole::{
    faest::{self, FaestError, PublicKey, SecretKey},
    params::{
        FAEST_128F, FAEST_128S, FAEST_192F, FAEST_192S, FAEST_256F, FAEST_256S, FAEST_EM_128F,
        FAEST_EM_128S, FAEST_EM_192F, FAEST_EM_192S, FAEST_EM_256F, FAEST_EM_256S, FaestParams,
    },
};

/// The fixture name of each vector with the fast and the small set it covers.
const VECTORS: [(&str, &FaestParams, &FaestParams); 6] = [
    ("FAEST_128F", &FAEST_128F, &FAEST_128S),
    ("FAEST_192F", &FAEST_192F, &FAEST_192S),
    ("FAEST_256F", &FAEST_256F, &FAEST_256S),
    ("FAEST_EM_128F", &FAEST_EM_128F, &FAEST_EM_128S),
    ("FAEST_EM_192F", &FAEST_EM_192F, &FAEST_EM_192S),
    ("FAEST_EM_256F", &FAEST_EM_256F, &FAEST_EM_256S),
];

#[test]
fn the_one_way_functions_reproduce_the_official_vectors() {
    let fixture = Fixture::load("owf_tvs");
    let mut rule_violations = 0;
    for (name, fast, small) in VECTORS {
        let entry = |field: &str| fixture.bytes(&format!("owf_tvs.{name}.{field}"));
        let (key, input, output) = (entry("key"), entry("input"), entry("output"));
        for set in [fast, small] {
            assert_eq!(
                faest::one_way_function(*set.owf(), &key, &input).as_ref(),
                Ok(&output),
                "{name} on {}",
                set.name()
            );
            // The same value through the key types: sk = input || key and
            // pk = input || output. The vectors' keys are uniformly random, so
            // some violate the key rule and are refused by the import.
            let secret: Vec<u8> = input.iter().chain(&key).copied().collect();
            let public: Vec<u8> = input.iter().chain(&output).copied().collect();
            assert_eq!(public.len(), set.public_key_bytes());
            match SecretKey::from_bytes(set, &secret) {
                Ok(secret) => {
                    assert_ne!(key[0] & 3, 3, "{name}");
                    assert_eq!(
                        Ok(secret.public_key()),
                        PublicKey::from_bytes(set, &public).as_ref()
                    );
                }
                Err(error) => {
                    assert_eq!(error, FaestError::InvalidSecretKey, "{name}");
                    assert_eq!(key[0] & 3, 3, "{name}");
                    rule_violations += 1;
                }
            }
            // The witness starts with the key and has the length of the set.
            let witness = faest::extend_witness(*set.owf(), &key, &input).expect("valid lengths");
            assert_eq!(8 * witness.len(), set.owf().ell());
            assert_eq!(witness[..key.len()], key[..]);
        }
    }
    // At least one vector key (FAEST_192F, first byte 0x6b) violates the rule.
    let expected = VECTORS
        .iter()
        .filter(|(name, _, _)| fixture.bytes(&format!("owf_tvs.{name}.key"))[0] & 3 == 3)
        .count();
    assert_eq!(rule_violations, 2 * expected);
    assert!(expected >= 1, "the vectors include a key the rule refuses");
    fixture.assert_consumed("owf_tvs.");
    assert_eq!(fixture.names().len(), 3 * VECTORS.len());
}
