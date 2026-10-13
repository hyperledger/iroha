//! Universal-hash conformance: every entry of the official `universal_hashing_tvs`
//! vectors (`LeafHash`, `VOLEHash`) and the `ZKHash` known answers of the upstream
//! `tests/universal_hashing.cpp`.

mod common;

use common::Fixture;
use iroha_zkp_vole::{
    field::{BinaryField, Gf128, Gf192, Gf256, LambdaField},
    universal_hash::{
        UniversalHashError, VoleHasher, ZkHasher, leaf_hash, leaf_hash_bytes, vole_hash, zk_hash,
    },
};

fn leaf_hash_vector<F: LambdaField>(fixture: &Fixture) {
    let name = |field: &str| format!("universal_hashing_tvs.leaf_hash_{}.{field}", F::BITS);
    let uhash = fixture.bytes(&name("uhash"));
    let x = fixture.bytes(&name("x"));
    let expected = fixture.bytes(&name("expected_h"));

    let mut out = vec![0u8; expected.len()];
    leaf_hash_bytes::<F>(&uhash, &x, &mut out).expect("exact lengths");
    assert_eq!(out, expected, "lambda = {}", F::BITS);

    let key = F::Tripled::from_bytes(&uhash).expect("3 lambda bits");
    let x0 = F::from_bytes(&x[..F::BYTES]).expect("lambda bits");
    let x1 = F::Tripled::from_bytes(&x[F::BYTES..]).expect("3 lambda bits");
    assert_eq!(
        leaf_hash::<F>(key, x0, x1).to_bytes().as_ref(),
        &expected[..]
    );

    let mut short = vec![0u8; expected.len() - 1];
    assert_eq!(
        leaf_hash_bytes::<F>(&uhash, &x, &mut short),
        Err(UniversalHashError::InvalidLength {
            expected: expected.len(),
            actual: expected.len() - 1
        })
    );
}

fn vole_hash_vector<F: LambdaField>(fixture: &Fixture) {
    let name = |field: &str| format!("universal_hashing_tvs.vole_hash_{}_7_tv.{field}", F::BITS);
    let ell = usize::try_from(fixture.integer(&name("ell"))).expect("small");
    let d_zk = usize::try_from(fixture.integer(&name("d_zk"))).expect("small");
    let ell_prime = usize::try_from(fixture.integer(&name("ell_prime"))).expect("small");
    assert_eq!(ell_prime, ell + d_zk - 1);
    let seed = fixture.bytes(&name("sd"));
    let x = F::vec_from_bytes(&fixture.bytes(&name("x"))).expect("whole elements");
    let expected = fixture.bytes(&name("digest"));
    assert_eq!(seed.len(), VoleHasher::<F>::SEED_BYTES);
    assert_eq!(x.len(), ell_prime + 4);

    // The first `ell + d_zk - 1` elements are x_0, the last four are x_1.
    let (x0, x1) = x.split_at(ell_prime);
    let x1: [F; 4] = x1.try_into().expect("four elements");
    let digest = vole_hash(&seed, x0, &x1).expect("valid seed");
    let bytes: Vec<u8> = digest
        .iter()
        .flat_map(|h| h.to_bytes().as_ref().to_vec())
        .collect();
    assert_eq!(bytes, expected, "lambda = {}", F::BITS);

    let mut hasher = VoleHasher::<F>::new(&seed).expect("valid seed");
    for element in x0 {
        hasher.update(*element);
    }
    assert_eq!(hasher.finalize(&x1), digest);

    assert_eq!(
        vole_hash::<F>(&seed[..seed.len() - 1], x0, &x1),
        Err(UniversalHashError::InvalidSeedLength {
            expected: seed.len(),
            actual: seed.len() - 1
        })
    );
}

#[test]
fn every_universal_hashing_vector_is_reproduced() {
    let fixture = Fixture::load("universal_hashing_tvs");
    leaf_hash_vector::<Gf128>(&fixture);
    leaf_hash_vector::<Gf192>(&fixture);
    leaf_hash_vector::<Gf256>(&fixture);
    vole_hash_vector::<Gf128>(&fixture);
    vole_hash_vector::<Gf192>(&fixture);
    vole_hash_vector::<Gf256>(&fixture);
    fixture.assert_consumed("");
}

/// Upstream `test_zk_hash_<lambda>_tv`: four vectors of eight elements plus the
/// masking element; consecutive vectors start eight elements apart.
fn zk_hash_vectors<F: LambdaField>(fixture: &Fixture) {
    const VECTORS: usize = 4;
    const XS: usize = 8;
    let name = |field: &str| format!("universal_hashing.zk_hash_{}_{field}", F::BITS);
    let seeds = fixture.bytes(&name("sd"));
    let xs = F::vec_from_bytes(&fixture.bytes(&name("xs"))).expect("whole elements");
    let digests = F::vec_from_bytes(&fixture.bytes(&name("digest"))).expect("whole elements");
    let seed_bytes = ZkHasher::<F>::SEED_BYTES;
    assert_eq!(seeds.len(), VECTORS * seed_bytes);
    assert_eq!(xs.len(), VECTORS * (XS + 1));
    assert_eq!(digests.len(), VECTORS);

    for (i, digest) in digests.iter().enumerate() {
        let seed = &seeds[i * seed_bytes..(i + 1) * seed_bytes];
        let x = &xs[i * XS..=i * XS + XS];
        let (x0, x1) = x.split_at(XS);
        assert_eq!(
            zk_hash(seed, x0, x1[0]),
            Ok(*digest),
            "lambda = {} vector {i}",
            F::BITS
        );
        let mut hasher = ZkHasher::<F>::new(seed).expect("valid seed");
        for element in x0 {
            hasher.update(*element);
        }
        assert_eq!(hasher.finalize(x1[0]), *digest);
    }
    assert_eq!(
        zk_hash::<F>(&seeds[..=seed_bytes], &xs[..XS], xs[XS]),
        Err(UniversalHashError::InvalidSeedLength {
            expected: seed_bytes,
            actual: seed_bytes + 1
        })
    );
}

#[test]
fn upstream_zk_hash_known_answers() {
    let fixture = Fixture::load_extracted();
    zk_hash_vectors::<Gf128>(&fixture);
    zk_hash_vectors::<Gf192>(&fixture);
    zk_hash_vectors::<Gf256>(&fixture);
    fixture.assert_consumed("universal_hashing.");
}
