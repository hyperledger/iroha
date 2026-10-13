//! FIPS 203 known-answer responses and structural identities.
//!
//! The response is `count = 0` of the NIST known-answer generator as `PQClean`
//! prints it. `scripts/zk_pq_kat_reference.py` derives the randomness with its
//! own AES-256 `CTR_DRBG` and checks that each tracked `.rsp` file hashes to the
//! `nistkat-sha256` value of the vendored `PQClean` metadata. The tests here
//! show that the derandomized entry points print exactly those files, and pin
//! the same published digests over the included file text, so a response file
//! regenerated from a changed implementation cannot pass on its own.
use super::*;
use crate::nistkat_sha256;
use sha3::{
    Sha3_512, Shake256,
    digest::{ExtendableOutput as _, Update as _, XofReader as _},
};

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

fn keypair_coins() -> [u8; 64] {
    input("mlkem_keypair_coins")
        .try_into()
        .expect("d || z is 64 bytes")
}

fn encapsulation_coins() -> [u8; 32] {
    input("mlkem_encapsulation_coins")
        .try_into()
        .expect("m is 32 bytes")
}

fn fixture(suite: MlKemSuite) -> &'static str {
    match suite {
        MlKemSuite::MlKem512 => include_str!("../../tests/fixtures/nistkat/ml-kem-512.rsp"),
        MlKemSuite::MlKem768 => include_str!("../../tests/fixtures/nistkat/ml-kem-768.rsp"),
        MlKemSuite::MlKem1024 => include_str!("../../tests/fixtures/nistkat/ml-kem-1024.rsp"),
    }
}

fn fixture_name(suite: MlKemSuite) -> &'static str {
    match suite {
        MlKemSuite::MlKem512 => "ml-kem-512.rsp",
        MlKemSuite::MlKem768 => "ml-kem-768.rsp",
        MlKemSuite::MlKem1024 => "ml-kem-1024.rsp",
    }
}

/// Module rank `k` of FIPS 203, the byte that separates key generation by parameter set.
fn rank(suite: MlKemSuite) -> u8 {
    match suite {
        MlKemSuite::MlKem512 => 2,
        MlKemSuite::MlKem768 => 3,
        MlKemSuite::MlKem1024 => 4,
    }
}

struct Run {
    keypair: MlKemKeyPair,
    ciphertext: MlKemCiphertext,
    shared: MlKemSharedSecret,
}

fn run(suite: MlKemSuite) -> Run {
    let keypair =
        generate_mlkem_keypair_from_coins(suite, &keypair_coins()).expect("derandomized keygen");
    let (shared, ciphertext) =
        encapsulate_mlkem_from_coins(suite, keypair.public_key(), &encapsulation_coins())
            .expect("derandomized encapsulation");
    Run {
        keypair,
        ciphertext,
        shared,
    }
}

fn response(suite: MlKemSuite) -> String {
    let run = run(suite);
    format!(
        "count = 0\nseed = {}\npk = {}\nsk = {}\nct = {}\nss = {}\n",
        hex_upper(&input("seed")),
        hex_upper(run.keypair.public_key()),
        hex_upper(run.keypair.secret_key()),
        hex_upper(run.ciphertext.as_bytes()),
        hex_upper(run.shared.as_bytes()),
    )
}

/// `nistkat-sha256` of `PQClean` for each parameter set (`pqcrypto-mlkem` 0.1.1
/// `META.yml`); `scripts/zk_pq_kat_reference.py` pins the same values.
fn official_nistkat_sha256(suite: MlKemSuite) -> &'static str {
    match suite {
        MlKemSuite::MlKem512 => "c70041a761e01cd6426fa60e9fd6a4412c2be817386c8d0f3334898082512782",
        MlKemSuite::MlKem768 => "5352539586b6c3df58be6158a6250aeff402bd73060b0a3de68850ac074c17c3",
        MlKemSuite::MlKem1024 => "f580d851e5fb27e6876e5e203fa18be4cdbfd49e05d48fec3d3992c8f43a13e6",
    }
}

#[test]
fn tracked_responses_hash_to_the_official_nistkat_digests() {
    for suite in MlKemSuite::ALL {
        assert_eq!(
            nistkat_sha256::sha256_hex(fixture(suite).as_bytes()),
            official_nistkat_sha256(suite),
            "{suite:?}: {} is not the official known-answer response",
            fixture_name(suite)
        );
    }
    // A response that differs in one character has another digest.
    let changed = fixture(MlKemSuite::MlKem768).replacen("ss = ", "ss = 0", 1);
    assert_ne!(
        nistkat_sha256::sha256_hex(changed.as_bytes()),
        official_nistkat_sha256(MlKemSuite::MlKem768)
    );
}

#[test]
fn derandomized_outputs_reproduce_the_official_response_for_every_suite() {
    for suite in MlKemSuite::ALL {
        assert_eq!(response(suite), fixture(suite), "{suite:?}");
    }
}

#[test]
fn decapsulation_recovers_the_official_shared_secret() {
    for suite in MlKemSuite::ALL {
        let run = run(suite);
        let recovered =
            decapsulate_mlkem(suite, run.keypair.secret_key(), run.ciphertext.as_bytes())
                .expect("decapsulation");
        assert_eq!(recovered.as_bytes(), run.shared.as_bytes(), "{suite:?}");
    }
}

/// FIPS 203 final: `(rho, sigma) = G(d || k)`, `dk = dk_pke || ek || H(ek) || z`,
/// `(K, r) = G(m || H(ek))` with `K` returned unchanged. Round-three Kyber hashed
/// `d` without `k`, hashed `m` first and derived the key through a further KDF.
#[test]
fn outputs_satisfy_the_fips203_final_identities() {
    for suite in MlKemSuite::ALL {
        let run = run(suite);
        let public = run.keypair.public_key();
        let secret = run.keypair.secret_key();
        let coins = keypair_coins();

        let mut keygen = Sha3_512::default();
        Digest::update(&mut keygen, &coins[..32]);
        Digest::update(&mut keygen, [rank(suite)]);
        let expanded = keygen.finalize();
        assert_eq!(
            &public[public.len() - 32..],
            &expanded[..32],
            "{suite:?}: rho is G(d || k)"
        );

        let public_hash = Sha3_256::digest(public);
        let tail = secret.len() - 64;
        assert_eq!(
            &secret[tail - public.len()..tail],
            public,
            "{suite:?}: ek embedded"
        );
        assert_eq!(
            &secret[tail..tail + 32],
            public_hash.as_slice(),
            "{suite:?}: H(ek)"
        );
        assert_eq!(&secret[tail + 32..], &coins[32..], "{suite:?}: z");

        let mut encapsulation = Sha3_512::default();
        Digest::update(&mut encapsulation, encapsulation_coins());
        Digest::update(&mut encapsulation, public_hash);
        assert_eq!(
            run.shared.as_bytes(),
            &encapsulation.finalize()[..32],
            "{suite:?}: K is the first half of G(m || H(ek))"
        );
    }
}

/// FIPS 203 implicit rejection: a ciphertext that fails re-encryption yields
/// `J(z || c) = SHAKE256(z || c, 32)`.
#[test]
fn modified_ciphertext_yields_the_fips203_implicit_rejection_key() {
    for suite in MlKemSuite::ALL {
        let run = run(suite);
        let mut ciphertext = run.ciphertext.as_bytes().to_vec();
        ciphertext[0] ^= 1;
        let rejected = decapsulate_mlkem(suite, run.keypair.secret_key(), &ciphertext)
            .expect("implicit rejection returns a key");
        let mut shake = Shake256::default();
        shake.update(&keypair_coins()[32..]);
        shake.update(&ciphertext);
        let mut expected = [0u8; 32];
        shake.finalize_xof().read(&mut expected);
        assert_eq!(rejected.as_bytes(), expected, "{suite:?}");
        assert_ne!(rejected.as_bytes(), run.shared.as_bytes(), "{suite:?}");
    }
}

#[test]
fn a_changed_coin_changes_the_response() {
    let suite = MlKemSuite::MlKem768;
    let mut coins = keypair_coins();
    coins[0] ^= 1;
    let keypair = generate_mlkem_keypair_from_coins(suite, &coins).expect("derandomized keygen");
    assert!(!fixture(suite).contains(&hex_upper(keypair.public_key())));
}

#[test]
#[ignore = "rewrites the tracked response files; run only to regenerate them"]
fn write_nistkat_response_fixtures() {
    for suite in MlKemSuite::ALL {
        // Cargo runs tests from the package directory.
        let path = std::env::current_dir()
            .expect("package directory")
            .join("tests/fixtures/nistkat")
            .join(fixture_name(suite));
        std::fs::write(path, response(suite)).expect("write response fixture");
    }
}
