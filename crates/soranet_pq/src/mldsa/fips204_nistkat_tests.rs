//! FIPS 204 known-answer responses and structural identities.
//!
//! The response is `count = 0` of the NIST known-answer generator as `PQClean`
//! prints it. `scripts/zk_pq_kat_reference.py` derives the randomness with its
//! own AES-256 `CTR_DRBG` and checks that each tracked `.rsp` file hashes to the
//! `nistkat-sha256` value of the vendored `PQClean` metadata. The tests here
//! show that the portable key generation and signing print exactly those files,
//! and pin the same published digests over the included file text, so a
//! response file regenerated from a changed implementation cannot pass on its own.
use super::*;
use crate::nistkat_sha256;
use sha3::{
    Shake256,
    digest::{ExtendableOutput as _, Update as _, XofReader as _},
};

const SUITES: [MlDsaSuite; 3] = [
    MlDsaSuite::MlDsa44,
    MlDsaSuite::MlDsa65,
    MlDsaSuite::MlDsa87,
];
const INPUTS: &str = include_str!("../../tests/fixtures/nistkat/inputs.txt");

fn input(name: &str) -> Vec<u8> {
    let line = INPUTS
        .lines()
        .find_map(|line| line.strip_prefix(name)?.strip_prefix(' '))
        .unwrap_or_else(|| panic!("known-answer input `{name}` is present"));
    line.as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let text = core::str::from_utf8(pair).expect("input hex is ASCII");
            u8::from_str_radix(text, 16).expect("input hex digit")
        })
        .collect()
}

fn hex_upper(bytes: &[u8]) -> String {
    use core::fmt::Write as _;
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        write!(out, "{byte:02X}").expect("writing to a string cannot fail");
    }
    out
}

fn keygen_seed() -> [u8; 32] {
    input("mldsa_keygen_seed")
        .try_into()
        .expect("xi is 32 bytes")
}

fn signing_randomness() -> [u8; 32] {
    input("mldsa_signing_randomness")
        .try_into()
        .expect("rnd is 32 bytes")
}

fn fixture(suite: MlDsaSuite) -> &'static str {
    match suite {
        MlDsaSuite::MlDsa44 => include_str!("../../tests/fixtures/nistkat/ml-dsa-44.rsp"),
        MlDsaSuite::MlDsa65 => include_str!("../../tests/fixtures/nistkat/ml-dsa-65.rsp"),
        MlDsaSuite::MlDsa87 => include_str!("../../tests/fixtures/nistkat/ml-dsa-87.rsp"),
    }
}

fn fixture_name(suite: MlDsaSuite) -> &'static str {
    match suite {
        MlDsaSuite::MlDsa44 => "ml-dsa-44.rsp",
        MlDsaSuite::MlDsa65 => "ml-dsa-65.rsp",
        MlDsaSuite::MlDsa87 => "ml-dsa-87.rsp",
    }
}

/// Matrix dimensions `(k, l)` of FIPS 204, the bytes that separate key generation by parameter set.
fn dimensions(suite: MlDsaSuite) -> [u8; 2] {
    match suite {
        MlDsaSuite::MlDsa44 => [4, 4],
        MlDsaSuite::MlDsa65 => [6, 5],
        MlDsaSuite::MlDsa87 => [8, 7],
    }
}

struct Run {
    keypair: MlDsaKeyPair,
    message: Vec<u8>,
    signature: MlDsaSignature,
}

fn run(suite: MlDsaSuite) -> Run {
    let keypair =
        generate_mldsa_keypair_from_fips_seed(suite, &keygen_seed()).expect("seeded keygen");
    let message = input("mldsa_message");
    let signature = sign_mldsa_from_coins(
        suite,
        keypair.secret_key(),
        b"",
        &message,
        &signing_randomness(),
    )
    .expect("hedged signing with fixed randomness");
    Run {
        keypair,
        message,
        signature,
    }
}

fn response(suite: MlDsaSuite) -> String {
    let run = run(suite);
    let mut signed_message = run.signature.as_bytes().to_vec();
    signed_message.extend_from_slice(&run.message);
    format!(
        "count = 0\nseed = {}\nmlen = {}\nmsg = {}\npk = {}\nsk = {}\nsmlen = {}\nsm = {}\n",
        hex_upper(&input("seed")),
        run.message.len(),
        hex_upper(&run.message),
        hex_upper(run.keypair.public_key()),
        hex_upper(run.keypair.secret_key()),
        signed_message.len(),
        hex_upper(&signed_message),
    )
}

/// `nistkat-sha256` of `PQClean` for each parameter set (`pqcrypto-mldsa` 0.1.2
/// `META.yml`); `scripts/zk_pq_kat_reference.py` pins the same values.
fn official_nistkat_sha256(suite: MlDsaSuite) -> &'static str {
    match suite {
        MlDsaSuite::MlDsa44 => "9a196e7fb32fbc93757dc2d8dc1924460eab66303c0c08aeb8b798fb8d8f8cf3",
        MlDsaSuite::MlDsa65 => "7cb96242eac9907a55b5c84c202f0ebd552419c50b2e986dc2e28f07ecebf072",
        MlDsaSuite::MlDsa87 => "4537905d2aabcf302fab2f242baed293459ecda7c230e6a67063b02c7e2840ed",
    }
}

#[test]
fn tracked_responses_hash_to_the_official_nistkat_digests() {
    for suite in SUITES {
        assert_eq!(
            nistkat_sha256::sha256_hex(fixture(suite).as_bytes()),
            official_nistkat_sha256(suite),
            "{suite:?}: {} is not the official known-answer response",
            fixture_name(suite)
        );
    }
    // A response that differs in one character has another digest.
    let changed = fixture(MlDsaSuite::MlDsa65).replacen("smlen = ", "smlen = 0", 1);
    assert_ne!(
        nistkat_sha256::sha256_hex(changed.as_bytes()),
        official_nistkat_sha256(MlDsaSuite::MlDsa65)
    );
}

#[test]
fn seeded_keygen_and_signing_reproduce_the_official_response_for_every_suite() {
    for suite in SUITES {
        assert_eq!(response(suite), fixture(suite), "{suite:?}");
    }
}

#[test]
fn the_official_signature_verifies_only_under_its_context_and_message() {
    for suite in SUITES {
        let run = run(suite);
        let public = run.keypair.public_key();
        let signature = run.signature.as_bytes();
        verify_mldsa(suite, public, b"", &run.message, signature).expect("official signature");
        assert!(
            verify_mldsa(suite, public, b"iroha", &run.message, signature).is_err(),
            "{suite:?}: a substituted context must not verify"
        );
        let mut message = run.message.clone();
        message[0] ^= 1;
        assert!(
            verify_mldsa(suite, public, b"", &message, signature).is_err(),
            "{suite:?}: a changed message must not verify"
        );
        let mut tampered = signature.to_vec();
        tampered[0] ^= 1;
        assert!(
            verify_mldsa(suite, public, b"", &run.message, &tampered).is_err(),
            "{suite:?}: a changed signature must not verify"
        );
    }
}

#[test]
fn a_signature_made_under_one_context_does_not_verify_under_another() {
    for suite in SUITES {
        let run = run(suite);
        let signature = sign_mldsa_from_coins(
            suite,
            run.keypair.secret_key(),
            b"iroha",
            &run.message,
            &signing_randomness(),
        )
        .expect("context-bound signing");
        let public = run.keypair.public_key();
        verify_mldsa(suite, public, b"iroha", &run.message, signature.as_bytes())
            .expect("signature under its own context");
        assert!(
            verify_mldsa(suite, public, b"", &run.message, signature.as_bytes()).is_err(),
            "{suite:?}: the empty context must not accept it"
        );
        assert_ne!(signature.as_bytes(), run.signature.as_bytes(), "{suite:?}");
    }
}

/// FIPS 204 final: `(rho, rho', K) = H(xi || k || l)`, and the secret key holds
/// the 64-byte `tr = H(pk)`. Round-three Dilithium hashed `xi` alone and stored a
/// shorter `tr`.
#[test]
fn outputs_satisfy_the_fips204_final_identities() {
    for suite in SUITES {
        let run = run(suite);
        let public = run.keypair.public_key();
        let secret = run.keypair.secret_key();

        let mut expand = Shake256::default();
        expand.update(&keygen_seed());
        expand.update(&dimensions(suite));
        let mut expanded = [0u8; 128];
        expand.finalize_xof().read(&mut expanded);
        assert_eq!(
            &public[..32],
            &expanded[..32],
            "{suite:?}: rho is H(xi || k || l)"
        );
        assert_eq!(&secret[..32], &expanded[..32], "{suite:?}: rho in sk");
        assert_eq!(&secret[32..64], &expanded[96..], "{suite:?}: K in sk");

        let mut public_hash = Shake256::default();
        public_hash.update(public);
        let mut tr = [0u8; 64];
        public_hash.finalize_xof().read(&mut tr);
        assert_eq!(&secret[64..128], &tr, "{suite:?}: tr is H(pk, 64)");
    }
}

#[test]
fn a_changed_seed_changes_the_response() {
    let suite = MlDsaSuite::MlDsa65;
    let mut seed = keygen_seed();
    seed[0] ^= 1;
    let keypair = generate_mldsa_keypair_from_fips_seed(suite, &seed).expect("seeded keygen");
    assert!(!fixture(suite).contains(&hex_upper(keypair.public_key())));
}

#[test]
#[ignore = "rewrites the tracked response files; run only to regenerate them"]
fn write_nistkat_response_fixtures() {
    for suite in SUITES {
        // Cargo runs tests from the package directory.
        let path = std::env::current_dir()
            .expect("package directory")
            .join("tests/fixtures/nistkat")
            .join(fixture_name(suite));
        std::fs::write(path, response(suite)).expect("write response fixture");
    }
}
