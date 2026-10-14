use h2::norito_helpers as nh;
use iroha_zkp_halo2 as h2;
use iroha_zkp_halo2::backend::pallas::PallasBackend;
use ivm::zk_verify::batch_verify_open_envelopes;
#[test]
fn zk_open_batch_smoke() {
    // Build two identical envelopes that should verify successfully.
    let params = h2::Params::new(2).unwrap();
    let coeffs = vec![h2::PrimeField64::from(1u64), h2::PrimeField64::from(2u64)];
    let poly = h2::Polynomial::from_coeffs(coeffs);
    let mut transcript = h2::Transcript::new("smoke");
    let p_g = poly.commit(&params).unwrap();
    let z = h2::PrimeField64::from(2u64);
    let (proof, t) = poly.open(&params, &mut transcript, z, p_g).unwrap();
    let envelope = h2::OpenVerifyEnvelope {
        params: nh::params_to_wire(&params),
        public: nh::poly_open_public::<PallasBackend>(params.n(), z, t, p_g),
        proof: nh::proof_to_wire(&proof),
        transcript_label: "smoke".to_string(),
        vk_commitment: None,
        public_inputs_schema_hash: None,
        domain_tag: None,
    };
    let res = batch_verify_open_envelopes(&[envelope.clone(), envelope]);
    assert_eq!(res.len(), 2);
    assert!(res.iter().all(|r| matches!(r, Ok(true))));
}
#[test]
fn zk_open_batch_mixed_validity_ok_and_bad() {
    // Build a valid envelope (ToyP61, small vector length)
    let params = h2::Params::new(8).unwrap();
    let n = params.n();
    let mut coeffs = vec![h2::PrimeField64::zero(); n];
    coeffs[0] = 1u64.into();
    coeffs[1] = 2u64.into();
    coeffs[2] = 3u64.into();
    let poly = h2::Polynomial::from_coeffs(coeffs);
    let mut tr = h2::Transcript::new("ok");
    let p_g = poly.commit(&params).unwrap();
    let z = h2::PrimeField64::from(5u64);
    let (proof, t) = poly.open(&params, &mut tr, z, p_g).unwrap();
    let env_ok = h2::OpenVerifyEnvelope {
        params: nh::params_to_wire(&params),
        public: nh::poly_open_public::<PallasBackend>(params.n(), z, t, p_g),
        proof: nh::proof_to_wire(&proof),
        transcript_label: "ok".to_string(),
        vk_commitment: None,
        public_inputs_schema_hash: None,
        domain_tag: None,
    };
    // Build an invalid envelope by corrupting `t` while keeping the rest consistent.
    let mut bad_public = env_ok.public.clone();
    let mut corrupted_t = bad_public.t;
    corrupted_t[0] = corrupted_t[0].wrapping_add(1);
    bad_public.t = corrupted_t;
    let env_bad = h2::OpenVerifyEnvelope {
        params: env_ok.params,
        public: bad_public,
        proof: env_ok.proof.clone(),
        transcript_label: env_ok.transcript_label.clone(),
        vk_commitment: None,
        public_inputs_schema_hash: None,
        domain_tag: None,
    };
    let res = batch_verify_open_envelopes(&[env_ok, env_bad]);
    assert_eq!(res.len(), 2);
    assert!(matches!(res[0], Ok(true)), "first must verify");
    assert!(
        matches!(res[1], Ok(false)),
        "second must be a clean verification failure"
    );
}
