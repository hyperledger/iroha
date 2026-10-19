// Core STARK verifier and transcript regression tests.
//
// Included by `stark::tests` to preserve exact libtest names.
use super::*;
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_core::zk_stark::tests::RetiredSelectorParamsV0")]
#[derive(norito::NoritoSerialize)]
struct RetiredSelectorParamsV0 {
    version: u16,
    n_log2: u8,
    blowup_log2: u8,
    fold_arity: u8,
    queries: u16,
    merkle_arity: u8,
    hash_fn: u8,
    domain_tag: String,
}
fn test_digest(word: u64) -> GoldilocksDigest384V1 {
    GoldilocksDigest384V1::new([word; 6]).expect("canonical test digest")
}
fn mutate_test_digest(digest: &mut GoldilocksDigest384V1) {
    let mut words = digest.words();
    words[0] ^= 1;
    *digest = GoldilocksDigest384V1::new(words).expect("mutated test digest remains canonical");
}
fn attach_valid_auxiliary_composition_values(envelope: &mut StarkVerifyEnvelopeV1) {
    let query_count = envelope.proof.queries.len();
    let leaf = 30_u64;
    let (comp_root, path) =
        stark_merkle_root_and_path_from_field_values_v1(&envelope.params, &[leaf], 0)
            .expect("derive auxiliary composition root");
    let comp_values = (0..query_count)
        .map(|_| StarkCompositionValueV1 {
            leaf,
            constant: 7,
            z_coeff: 0,
            aux_terms: vec![
                StarkCompositionTermV1 {
                    wire_index: 1,
                    value: 5,
                    coeff: 3,
                },
                StarkCompositionTermV1 {
                    wire_index: 3,
                    value: 2,
                    coeff: 4,
                },
            ],
            path: path.clone(),
        })
        .collect();
    envelope.proof.commits.comp_root = Some(comp_root);
    envelope.proof.comp_values = Some(comp_values);
}
#[test]
fn fq_canonical_arithmetic_matches_wide_boundary_pair_oracle() {
    let radix = 1_u64 << 32;
    let samples = [
        0,
        1,
        2,
        radix - 1,
        radix,
        radix + 1,
        MOD_P_U64 / 2,
        MOD_P_U64 - 2,
        MOD_P_U64 - 1,
        MOD_P_U64,
        MOD_P_U64 + 1,
        u64::MAX,
    ];
    let residue = |value: u128| {
        u64::try_from(value % MOD_P).expect("wide reference remainder fits the field word")
    };
    for left in samples {
        for right in samples {
            let a = u128::from(left) % MOD_P;
            let b = u128::from(right) % MOD_P;
            let first = Fq::new(left);
            let second = Fq::new(right);
            for (actual, expected, operation) in [
                (first.add(second), residue(a + b), "add"),
                (first.sub(second), residue(a + MOD_P - b), "sub"),
                (first.mul(second), residue(a * b), "mul"),
            ] {
                assert_eq!(actual.0, expected, "{operation}({left}, {right})");
                assert!(actual.0 < MOD_P_U64, "canonical {operation} result");
            }
        }
    }
    for input in [
        0,
        MOD_P - 1,
        MOD_P,
        MOD_P + 1,
        u128::from(u64::MAX),
        u128::from(u64::MAX) + 1,
        MOD_P * MOD_P - 1,
        u128::MAX,
    ] {
        assert_eq!(Fq::reduce(input).0, residue(input), "reduce({input})");
    }
}

#[test]
fn fq_modulus_words_and_inverse_of_two_are_exact() {
    assert_eq!(u128::from(MOD_P_U64), MOD_P);
    let half = two_inv();
    assert_eq!(u128::from(half.0) * 2, MOD_P + 1);
    assert!(half.0 < MOD_P_U64);
    assert_eq!(half.add(half), Fq::one());
    assert_eq!(half.mul(Fq::new(2)), Fq::one());
    assert_eq!(Fq::new(2).inv(), Some(half));
    assert_eq!(Fq::zero().inv(), None);
}

#[test]
fn fq_addition_wraps_correctly() {
    let a = Fq::from_canonical_u64(MOD_P_U64 - 1).unwrap();
    let b = Fq::one();
    assert_eq!(a.add(b), Fq::zero());
}
#[test]
fn fq_subtraction_borrows_mod_prime() {
    let a = Fq::zero();
    let b = Fq::one();
    let expected = Fq::from_canonical_u64(MOD_P_U64 - 1).unwrap();
    assert_eq!(a.sub(b), expected);
}
#[test]
fn fq_multiplication_reduces() {
    let a = Fq::from_canonical_u64(2).unwrap();
    let b = Fq::from_canonical_u64(MOD_P_U64 - 1).unwrap();
    let product = a.mul(b);
    let expected = Fq::from_canonical_u64(MOD_P_U64 - 2).unwrap();
    assert_eq!(product, expected);
}
#[test]
fn fq_inverse_round_trip() {
    let element = Fq::from_canonical_u64(5).unwrap();
    let inv = element.inv().expect("invertible");
    assert_eq!(element.mul(inv), Fq::one());
}
#[test]
fn fq_new_reduces_large_inputs() {
    let value = u64::MAX;
    let reduced = Fq::new(value);
    let expected = Fq::from_canonical_u64(((value as u128) % MOD_P) as u64).unwrap();
    assert_eq!(reduced, expected);
}
#[test]
fn fq_from_canonical_rejects_out_of_range() {
    assert!(Fq::from_canonical_u64(MOD_P_U64).is_none());
}
#[test]
fn stark_params_decoder_rejects_retired_hash_selector_wire() {
    let retired = RetiredSelectorParamsV0 {
        version: 1,
        n_log2: 6,
        blowup_log2: 3,
        fold_arity: 2,
        queries: STARK_FRI_CONSENSUS_MIN_QUERIES,
        merkle_arity: 2,
        hash_fn: 1,
        domain_tag: "iroha:test:retired-selector-wire".to_owned(),
    };
    let (payload, flags) = norito::codec::encode_with_header_flags(&retired);
    let bytes = norito::core::frame_bare_with_header_flags::<StarkFriParamsV1>(&payload, flags)
        .expect("frame retired parameter payload under the actual V1 owner");
    let view = norito::core::from_bytes_view(&bytes).expect("valid frame and checksum");
    assert_eq!(
        view.schema(),
        norito::schema::identity::frame_hash::<StarkFriParamsV1>(),
        "rejection must exercise the retired payload, not an unrelated frame identity"
    );
    assert_eq!(view.as_bytes(), payload);
    assert!(
        norito::decode_canonical::<StarkFriParamsV1>(&bytes).is_err(),
        "the selector-free V1 decoder must reject pre-release selector-bearing parameters"
    );
}
#[test]
fn fp4_wire_is_exactly_four_little_endian_coefficients() {
    use norito::{SerializePayload, codec::Encode, core::DecodeFromSlice};

    let coefficients = [1, MOD_P_U64 - 1, 3, 4];
    let value = GoldilocksFp4V1::new(coefficients).expect("canonical field element");
    let shared = fastpq_prover::GoldilocksFp4V1::new(coefficients).expect("canonical shared field");
    let encoded = value.encode();
    assert_eq!(encoded, shared.to_le_bytes());
    assert_eq!(encoded.len(), GoldilocksFp4V1::BYTES);
    assert_eq!(value.encoded_len_hint(), Some(32));
    assert_eq!(value.encoded_len_exact(), Some(32));
    let framed = norito::to_bytes(&value).expect("encode field frame");
    assert_eq!(
        norito::decode_from_bytes::<GoldilocksFp4V1>(&framed).unwrap(),
        value
    );
    for truncated in 0..GoldilocksFp4V1::BYTES {
        assert!(GoldilocksFp4V1::decode_from_slice(&encoded[..truncated]).is_err());
    }
    let mut with_suffix = encoded;
    with_suffix.extend_from_slice(&[0xa5; 8]);
    assert_eq!(
        GoldilocksFp4V1::decode_from_slice(&with_suffix).unwrap(),
        (value, 32)
    );
}
#[test]
fn fp4_wire_rejects_every_noncanonical_coefficient() {
    use norito::core::DecodeFromSlice;

    for coefficient in 0..4 {
        for invalid in [MOD_P_U64, u64::MAX] {
            let mut coefficients = [1, 2, 3, 4];
            coefficients[coefficient] = invalid;
            let [c0, c1, c2, c3] = coefficients;
            let invalid_value = GoldilocksFp4V1 { c0, c1, c2, c3 };
            assert!(norito::to_bytes(&invalid_value).is_err());
            let mut raw = [0_u8; 32];
            for (word, bytes) in coefficients.iter().zip(raw.chunks_exact_mut(8)) {
                bytes.copy_from_slice(&word.to_le_bytes());
            }
            assert!(GoldilocksFp4V1::decode_from_slice(&raw).is_err());
            let framed = norito::core::frame_bare_with_header_flags::<GoldilocksFp4V1>(&raw, 0)
                .expect("frame adversarial canonical-width bytes");
            assert!(norito::decode_from_bytes::<GoldilocksFp4V1>(&framed).is_err());
        }
    }
}
#[test]
fn fp4_wire_rejects_the_retired_struct_frame_under_the_same_schema() {
    #[derive(norito::NoritoSchema)]
    #[norito_schema(
        name = "iroha_core::zk_stark::tests::fp4_wire_rejects_the_retired_struct_frame_under_the_same_schema::RetiredStructFrame",
        frame = "iroha_core::zk_stark::GoldilocksFp4V1"
    )]
    #[derive(norito::NoritoSerialize)]
    struct RetiredStructFrame {
        c0: u64,
        c1: u64,
        c2: u64,
        c3: u64,
    }
    assert_eq!(
        norito::schema::identity::frame_hash::<RetiredStructFrame>(),
        norito::schema::identity::frame_hash::<GoldilocksFp4V1>(),
        "payload rejection must not depend on a changed schema name"
    );
    let retired = RetiredStructFrame {
        c0: 1,
        c1: 2,
        c2: 3,
        c3: 4,
    };
    let (payload, flags) = norito::codec::encode_with_header_flags(&retired);
    let framed = norito::core::frame_bare_with_header_flags::<GoldilocksFp4V1>(&payload, flags)
        .expect("frame the retired payload under the live scalar owner");
    let view = norito::core::from_bytes_view(&framed).expect("valid retired frame/checksum");
    assert_eq!(
        view.schema(),
        norito::schema::identity::frame_hash::<GoldilocksFp4V1>(),
        "payload rejection must not depend on a changed schema name"
    );
    assert_eq!(view.as_bytes(), payload);
    assert!(norito::decode_from_bytes::<GoldilocksFp4V1>(&framed).is_err());
}
#[test]
fn fp4_modulus_reduces_u_to_the_fourth_to_seven() {
    let zero = Fq::zero();
    let one = Fq::one();
    let u = Fp4([zero, one, zero, zero]);
    let u_cubed = Fp4([zero, zero, zero, one]);
    assert_eq!(
        u.mul(u_cubed),
        Fp4::from_base(Fq::new(GOLDILOCKS_GENERATOR)),
        "Fp4 multiplication must reduce U^4 through U^4 - 7"
    );
}
#[test]
fn seven_is_a_goldilocks_primitive_element_for_fp4_modulus() {
    let generator = Fq::new(GOLDILOCKS_GENERATOR);
    for prime_factor in [2_u128, 3, 5, 17, 257, 65_537] {
        assert_ne!(
            generator.pow((MOD_P - 1) / prime_factor),
            Fq::one(),
            "seven must have full Goldilocks multiplicative order"
        );
    }
}
#[test]
fn fri_transcript_challenge_uses_non_base_fp4_coefficients() {
    let params = StarkFriParamsV1 {
        version: 1,
        n_log2: 6,
        blowup_log2: 3,
        fold_arity: 2,
        queries: STARK_FRI_CONSENSUS_MIN_QUERIES,
        merkle_arity: 2,
        domain_tag: "iroha:test:fp4-transcript-challenge".to_owned(),
    };
    let challenge =
        fri_round_challenge(&params, "IROHA-STARK-FP4-CHALLENGE-V1", 0, &test_digest(17))
            .expect("derive canonical Fp4 transcript challenge");
    assert!(
        challenge.0[1..]
            .iter()
            .any(|coefficient| *coefficient != Fq::zero()),
        "the deterministic transcript challenge must not collapse to the base field"
    );
    assert!(
        GoldilocksFp4V1::new(challenge.to_wire().coefficients()).is_some(),
        "the derived challenge must preserve canonical wire coefficients"
    );
}
#[test]
fn air_composition_root_uses_its_own_role_for_every_tree_level() {
    let params = StarkFriParamsV1 {
        version: 1,
        n_log2: 4,
        blowup_log2: 2,
        fold_arity: 2,
        queries: 2,
        merkle_arity: 2,
        domain_tag: "iroha:test:air-composition-root-role".to_owned(),
    };
    for domain in [1, 2, 16] {
        let values = (0..domain).map(|value| value as u64).collect::<Vec<_>>();
        let fields = values.iter().copied().map(Fq::new).collect::<Vec<_>>();
        let expected =
            merkle_levels_from_values(&params, &fields, StarkMerkleDomainV1::air_composition())
                .and_then(|levels| merkle_root_from_levels(&levels))
                .expect("AIR composition root");
        let auxiliary = merkle_levels_from_values(
            &params,
            &fields,
            StarkMerkleDomainV1::auxiliary_composition(),
        )
        .and_then(|levels| merkle_root_from_levels(&levels))
        .expect("auxiliary composition root");
        assert_eq!(
            stark_merkle_root_from_field_values_v1(&params, &values),
            Some(expected)
        );
        assert_ne!(expected, auxiliary, "role separation at domain {domain}");
    }
}
#[test]
fn constant_zero_merkle_root_matches_allocated_builder() {
    let params = StarkFriParamsV1 {
        version: 1,
        n_log2: 4,
        blowup_log2: 2,
        fold_arity: 2,
        queries: 2,
        merkle_arity: 2,
        domain_tag: "iroha:test:constant-zero-root-equivalence".to_owned(),
    };
    for domain in [1, 2, 16] {
        assert_eq!(
            stark_constant_field_merkle_root_v1(&params, Fq::zero(), domain),
            stark_merkle_root_from_field_values_v1(&params, &vec![0; domain]),
            "constant-tree derivation must match the ordinary six-lane Merkle builder for domain {domain}"
        );
    }
    assert!(stark_constant_field_merkle_root_v1(&params, Fq::zero(), 0).is_none());
    assert!(stark_constant_field_merkle_root_v1(&params, Fq::zero(), 3).is_none());
}
#[test]
fn fri_pair_domain_uses_bit_reversed_layer_order() {
    let layer_domain = 8_usize;
    let subgroup_root = Fq::new(GOLDILOCKS_GENERATOR)
        .pow((MOD_P - 1) / u128::try_from(layer_domain).expect("domain fits u128"));
    // In a three-bit bit-reversed layer, pair j=1 occupies the evaluations at exponents 2 and 6:
    // `(f(omega^2), f(-omega^2))`. The old `omega^j` calculation incorrectly used `omega`.
    let polynomial_x = subgroup_root.pow(2);
    let y0 = Fp4::from_base(polynomial_x);
    let y1 = Fp4::from_base(Fq::zero().sub(polynomial_x));
    let beta = Fp4::from_base(Fq::from_canonical_u64(2).expect("canonical beta"));
    let pair_x = domain_x_for_pair(layer_domain, 1).expect("derive bit-reversed pair point");
    assert_eq!(pair_x, polynomial_x);
    assert_eq!(
        fri_fold_pair(y0, y1, beta, pair_x),
        Some(beta),
        "folding f(X)=X at (x, -x) must produce the challenge beta"
    );

    let legacy_pair_x = subgroup_root;
    assert_ne!(
        fri_fold_pair(y0, y1, beta, legacy_pair_x),
        Some(beta),
        "the former non-bit-reversed exponent must not satisfy the polynomial fold"
    );
}
#[test]
fn fri_pair_domain_rejects_nonexistent_goldilocks_subgroups() {
    assert!(domain_x_for_pair(0, 0).is_none());
    assert!(domain_x_for_pair(1, 0).is_none());
    assert!(domain_x_for_pair(3, 0).is_none());
    assert!(domain_x_for_pair(8, 4).is_none());
    assert_eq!(domain_x_for_pair(2, 0), Some(Fq::one()));
    for exponent in 2..usize::BITS {
        let domain = 1_usize.checked_shl(exponent).expect("representable domain");
        let x = domain_x_for_pair(domain, domain / 2 - 1);
        if exponent <= 32 {
            // The final pair has an odd bit-reversed exponent, hence exact subgroup order.
            let x = x.expect("Goldilocks supports this two-adic subgroup");
            assert_eq!(x.pow(domain as u128), Fq::one());
            assert_ne!(x.pow((domain / 2) as u128), Fq::one());
        } else {
            assert!(x.is_none(), "2^{exponent} cannot be a Goldilocks subgroup");
        }
    }
}
#[test]
fn fri_layer_geometry_rejects_every_noncanonical_exponent_and_arity() {
    let mut params = StarkFriParamsV1 {
        version: 1,
        n_log2: 1,
        blowup_log2: 1,
        fold_arity: 2,
        queries: 1,
        merkle_arity: 2,
        domain_tag: "iroha:test:fri-layer-geometry".to_owned(),
    };
    for exponent in 0..=u8::MAX {
        params.n_log2 = exponent;
        for arity in 0..=u8::MAX {
            params.fold_arity = arity;
            let expected = (arity == 2 && (1..=MAX_DOMAIN_LOG2).contains(&exponent))
                .then_some(usize::from(exponent));
            assert_eq!(
                layers_required(&params),
                expected,
                "unexpected geometry for exponent {exponent} and arity {arity}"
            );
        }
    }
}
#[test]
fn opening_commitment_validation_rejects_hostile_geometry_without_panicking() {
    let mut params = StarkFriParamsV1 {
        version: 1,
        n_log2: 1,
        blowup_log2: 1,
        fold_arity: 2,
        queries: 1,
        merkle_arity: 2,
        domain_tag: "iroha:test:opening-geometry".to_owned(),
    };
    let limits = StarkVerifierLimits::default();
    for exponent in 0..=u8::MAX {
        params.n_log2 = exponent;
        assert_eq!(
            validate_stark_opening_commitment_params_with_limits_v1(&params, &limits).is_ok(),
            (1..=MAX_DOMAIN_LOG2).contains(&exponent),
            "opening verification must reject invalid wire exponent {exponent}"
        );
    }
    params.n_log2 = 4;
    for arity in 0..=u8::MAX {
        params.fold_arity = arity;
        assert_eq!(
            validate_stark_opening_commitment_params_with_limits_v1(&params, &limits).is_ok(),
            arity == 2,
            "opening verification must reject invalid wire arity {arity}"
        );
    }
}
#[test]
fn fri_challenges_bind_the_exact_round() {
    let params = StarkFriParamsV1 {
        version: 1,
        n_log2: 4,
        blowup_log2: 2,
        fold_arity: 2,
        queries: 2,
        merkle_arity: 2,
        domain_tag: "iroha:test:fri-round-binding".to_owned(),
    };
    let root = GoldilocksDigest384V1::new([0x42; 6]).expect("canonical test digest");
    let first = fri_round_challenge(&params, "IROHA-TEST-FRI-ROUND-BINDING", 0, &root)
        .expect("derive first-round challenge");
    let second = fri_round_challenge(&params, "IROHA-TEST-FRI-ROUND-BINDING", 1, &root)
        .expect("derive second-round challenge");
    assert_ne!(
        first, second,
        "equal roots at different depths must not reuse a FRI challenge"
    );
}
#[test]
fn six_lane_merkle_paths_bind_tree_role_and_indices() {
    let params = StarkFriParamsV1 {
        version: 1,
        n_log2: 1,
        blowup_log2: 1,
        fold_arity: 2,
        queries: 1,
        merkle_arity: 2,
        domain_tag: "iroha:test:six-lane-value-path-binding".to_owned(),
    };
    let leaf = Fq::from_canonical_u64(7).expect("canonical leaf");
    let values = [leaf, Fq::zero()];
    let fri_domain = StarkMerkleDomainV1::fri_layer(0).expect("FRI layer");
    let levels = merkle_levels_from_values(&params, &values, fri_domain).expect("Merkle levels");
    let root = merkle_root_from_levels(&levels).expect("Merkle root");
    let canonical_path = merkle_path_from_levels(0, &levels).expect("Merkle path");
    assert!(merkle_verify(
        &params,
        fri_domain,
        &root,
        leaf,
        &canonical_path
    ));
    assert!(
        !merkle_verify(
            &params,
            StarkMerkleDomainV1::air_composition(),
            &root,
            leaf,
            &canonical_path,
        ),
        "the same opening must not verify under a different tree role"
    );
}
#[test]
fn six_lane_digest_rejects_noncanonical_field_words() {
    let mut bytes = [0_u8; GoldilocksDigest384V1::BYTES];
    bytes[..8].copy_from_slice(&MOD_P_U64.to_le_bytes());
    assert!(GoldilocksDigest384V1::from_le_bytes(bytes).is_none());
}
#[test]
fn stark_fri_canonical_verifying_key_payload_validation_fails_closed() {
    const CIRCUIT_ID: &str = "soracloud:test-canonical-circuit";
    let valid = StarkFriVerifyingKeyV1 {
        version: 1,
        circuit_id: CIRCUIT_ID.to_owned(),
        n_log2: STARK_FRI_CONSENSUS_MIN_N_LOG2,
        blowup_log2: STARK_FRI_CONSENSUS_MIN_BLOWUP_LOG2,
        fold_arity: 2,
        queries: STARK_FRI_CONSENSUS_MIN_QUERIES,
        merkle_arity: 2,
    };
    validate_stark_fri_canonical_verifying_key_payload(&valid, CIRCUIT_ID, "test")
        .expect("canonical STARK/FRI payload is accepted");
    let mutations: [(&str, fn(&mut StarkFriVerifyingKeyV1)); 10] = [
        ("version", |payload: &mut StarkFriVerifyingKeyV1| {
            payload.version = 2
        }),
        ("circuit", |payload: &mut StarkFriVerifyingKeyV1| {
            payload.circuit_id = "other".to_owned()
        }),
        ("fold", |payload: &mut StarkFriVerifyingKeyV1| {
            payload.fold_arity = 4;
        }),
        ("merkle", |payload: &mut StarkFriVerifyingKeyV1| {
            payload.merkle_arity = 4;
        }),
        ("n_log2_floor", |payload: &mut StarkFriVerifyingKeyV1| {
            payload.n_log2 = STARK_FRI_CONSENSUS_MIN_N_LOG2 - 1;
        }),
        ("blowup_floor", |payload: &mut StarkFriVerifyingKeyV1| {
            payload.blowup_log2 = STARK_FRI_CONSENSUS_MIN_BLOWUP_LOG2 - 1;
        }),
        ("blowup_domain", |payload: &mut StarkFriVerifyingKeyV1| {
            payload.blowup_log2 = payload.n_log2 + 1;
        }),
        ("queries_floor", |payload: &mut StarkFriVerifyingKeyV1| {
            payload.queries = STARK_FRI_CONSENSUS_MIN_QUERIES - 1;
        }),
        ("domain_limit", |payload: &mut StarkFriVerifyingKeyV1| {
            payload.n_log2 = MAX_DOMAIN_LOG2 + 1;
        }),
        ("query_limit", |payload: &mut StarkFriVerifyingKeyV1| {
            payload.queries = MAX_FRI_QUERIES as u16 + 1;
        }),
    ];
    for (label, mutate) in mutations {
        let mut invalid = valid.clone();
        mutate(&mut invalid);
        assert!(
            validate_stark_fri_canonical_verifying_key_payload(&invalid, CIRCUIT_ID, "test")
                .is_err(),
            "{label} mutation must fail closed"
        );
    }
    let overlong_circuit_id = "soracloud:".to_owned() + &"x".repeat(MAX_TRANSCRIPT_LABEL_LEN);
    for circuit_id in [
        "",
        " ",
        "soracloud:test canonical-circuit",
        "soracloud:test\tproduction-circuit",
        overlong_circuit_id.as_str(),
    ] {
        let mut invalid = valid.clone();
        invalid.circuit_id = circuit_id.to_owned();
        assert!(
            validate_stark_fri_canonical_verifying_key_payload(&invalid, circuit_id, "test")
                .is_err(),
            "matching noncanonical circuit id {circuit_id:?} must fail closed"
        );
    }
}
#[test]
fn generic_binding_verifying_key_rejects_domain_above_exact_root_cap() {
    let circuit_id = "stark/fri/poseidon-x7-goldilocks-6x64-v1:binding-root-cap-test";
    let payload = StarkFriVerifyingKeyV1 {
        version: 1,
        circuit_id: circuit_id.to_owned(),
        n_log2: MAX_BINDING_AIR_DOMAIN_LOG2 + 1,
        blowup_log2: STARK_FRI_CONSENSUS_MIN_BLOWUP_LOG2,
        fold_arity: 2,
        queries: STARK_FRI_CONSENSUS_MIN_QUERIES,
        merkle_arity: 2,
    };
    let error = validate_stark_fri_canonical_verifying_key_payload(&payload, circuit_id, "test")
        .expect_err("oversized generic Binding verifier key must fail admission");
    assert!(
        error
            .to_string()
            .contains("exact trace-root reconstruction limit"),
        "unexpected generic Binding verifier-key error: {error}"
    );
}
#[test]
fn ivm_binding_verifying_key_is_unavailable_without_complete_relation() {
    let circuit_id = format!(
        "{}:{}",
        crate::ZK_BACKEND_STARK_FRI_V1,
        crate::IVM_EXECUTION_V1_CIRCUIT_ID
    );
    let payload = StarkFriVerifyingKeyV1 {
        version: 1,
        circuit_id: circuit_id.clone(),
        n_log2: STARK_FRI_CONSENSUS_MIN_N_LOG2,
        blowup_log2: STARK_FRI_CONSENSUS_MIN_BLOWUP_LOG2,
        fold_arity: 2,
        queries: STARK_FRI_CONSENSUS_MIN_QUERIES,
        merkle_arity: 2,
    };
    let error = validate_stark_fri_canonical_verifying_key_payload(&payload, &circuit_id, "test")
        .expect_err("binding-only IVM verifier key must fail admission");
    assert!(
        error
            .to_string()
            .contains("complete native STARK verification")
    );
}
/// The length predicate of the envelope bound, which the verifier calls before it decodes
/// a byte: the bound is inclusive, and a caller can lower it but not raise it above
/// `MAX_ENVELOPE_BYTES`. Nothing is decoded here; the verifier itself is exercised at
/// the bound by `stark_verifier_accepts_an_envelope_of_exactly_its_bound_and_refuses_one_byte_more`.
#[test]
fn stark_envelope_length_predicate_admits_exactly_the_bound_and_refuses_one_byte_more() {
    let limits = StarkVerifierLimits::default();
    assert_eq!(MAX_ENVELOPE_BYTES, 1 << 20);
    assert_eq!(effective_max_envelope_bytes(&limits), MAX_ENVELOPE_BYTES);
    assert!(!envelope_exceeds_limit(MAX_ENVELOPE_BYTES, &limits));
    assert!(envelope_exceeds_limit(MAX_ENVELOPE_BYTES + 1, &limits));
    assert!(!envelope_exceeds_limit(0, &limits));

    let mut lowered = StarkVerifierLimits::default();
    lowered.max_envelope_bytes = 4096;
    assert!(!envelope_exceeds_limit(4096, &lowered));
    assert!(envelope_exceeds_limit(4097, &lowered));

    let mut raised = StarkVerifierLimits::default();
    raised.max_envelope_bytes = MAX_ENVELOPE_BYTES + 1;
    assert!(!envelope_exceeds_limit(MAX_ENVELOPE_BYTES, &raised));
    assert!(
        envelope_exceeds_limit(MAX_ENVELOPE_BYTES + 1, &raised),
        "a caller limit above the bound is clamped to the bound"
    );
}
/// The verifier applies the envelope bound to a real proof: with the bound set to the
/// length of a valid envelope the proof verifies, and with the bound one byte below that
/// length the same envelope is refused. The bound a caller sets is never above
/// `MAX_ENVELOPE_BYTES` (the predicate test above), so this is the behaviour at the limit.
#[test]
fn stark_verifier_accepts_an_envelope_of_exactly_its_bound_and_refuses_one_byte_more() {
    let params = StarkFriParamsV1 {
        version: 1,
        n_log2: 4,
        blowup_log2: 2,
        fold_arity: 2,
        queries: 2,
        merkle_arity: 2,
        domain_tag: "iroha:test:envelope-bound".to_owned(),
    };
    let bytes = prove_stark_fri_air_envelope_bytes(
        params,
        "IROHA-TEST-STARK".to_owned(),
        "stark/fri/poseidon-x7-goldilocks-6x64-v1:test".to_owned(),
        test_digest(0x33),
    )
    .expect("valid STARK envelope");
    assert!(bytes.len() > 1 && bytes.len() < MAX_ENVELOPE_BYTES);
    let mut limits = StarkVerifierLimits::default();
    assert!(
        verify_stark_fri_envelope_with_limits(&bytes, &limits)
            .expect("semantic verification fixture must complete")
    );
    limits.max_envelope_bytes = bytes.len();
    assert!(
        verify_stark_fri_envelope_with_limits(&bytes, &limits)
            .expect("semantic verification fixture must complete"),
        "an envelope of exactly the bound is decoded and verifies"
    );
    limits.max_envelope_bytes = bytes.len() - 1;
    assert!(
        !verify_stark_fri_envelope_with_limits(&bytes, &limits)
            .expect("semantic verification fixture must complete"),
        "the same envelope, one byte above the bound, is refused"
    );
}
#[test]
fn stark_verifier_limits_cannot_relax_canonical_structure_caps() {
    let valid = StarkFriParamsV1 {
        version: 1,
        n_log2: 4,
        blowup_log2: 2,
        fold_arity: 2,
        queries: 2,
        merkle_arity: 2,
        domain_tag: "iroha:test:canonical-limit-cap".to_owned(),
    };
    assert_eq!(
        validate_params(&valid, 5, 2, &StarkVerifierLimits::default()),
        Some(4)
    );
    let mut relaxed = StarkVerifierLimits::default();
    relaxed.max_domain_log2 = MAX_DOMAIN_LOG2 + 1;
    relaxed.max_blowup_log2 = MAX_DOMAIN_LOG2 + 1;
    relaxed.max_queries = MAX_FRI_QUERIES + 1;
    relaxed.max_merkle_depth = MAX_MERKLE_DEPTH + 1;
    relaxed.max_aux_terms = MAX_AUX_TERMS + 1;
    relaxed.max_air_width = MAX_AIR_WIDTH + 1;
    relaxed.max_domain_tag_len = MAX_DOMAIN_TAG_LEN + 1;
    relaxed.max_transcript_label_len = MAX_TRANSCRIPT_LABEL_LEN + 1;
    relaxed.max_envelope_bytes = MAX_ENVELOPE_BYTES + 1;
    let mut oversized_domain = valid.clone();
    oversized_domain.n_log2 = MAX_DOMAIN_LOG2 + 1;
    oversized_domain.queries = 1;
    assert!(
        validate_params(
            &oversized_domain,
            usize::from(MAX_DOMAIN_LOG2) + 2,
            1,
            &relaxed
        )
        .is_none(),
        "caller limits must not relax canonical domain depth"
    );
    let mut oversized_blowup = valid.clone();
    oversized_blowup.blowup_log2 = MAX_DOMAIN_LOG2 + 1;
    assert!(
        validate_params(&oversized_blowup, 5, 2, &relaxed).is_none(),
        "caller limits must not relax canonical blowup depth"
    );
    let mut impossible_blowup = valid.clone();
    impossible_blowup.blowup_log2 = valid.n_log2 + 1;
    assert!(
        validate_params(&impossible_blowup, 5, 2, &relaxed).is_none(),
        "verifier must reject blowup depth greater than the evaluation domain"
    );
    let mut too_many_queries = valid.clone();
    too_many_queries.n_log2 = 6;
    too_many_queries.queries = (MAX_FRI_QUERIES + 1) as u16;
    assert!(
        validate_params(&too_many_queries, 7, MAX_FRI_QUERIES + 1, &relaxed).is_none(),
        "caller limits must not relax canonical query count"
    );
    let mut overlong_domain_tag = valid.clone();
    overlong_domain_tag.domain_tag = "d".repeat(MAX_DOMAIN_TAG_LEN + 1);
    assert!(
        validate_params(&overlong_domain_tag, 5, 2, &relaxed).is_none(),
        "caller limits must not relax canonical domain-tag length"
    );
    let too_deep_path = MerklePath {
        dirs: vec![0; (MAX_MERKLE_DEPTH + 8) / 8],
        siblings: vec![GoldilocksDigest384V1::default(); MAX_MERKLE_DEPTH + 1],
    };
    assert!(
        !merkle_path_depth_ok(&too_deep_path, MAX_MERKLE_DEPTH + 1, &relaxed),
        "caller limits must not relax canonical Merkle depth"
    );
    let overlong_transcript_label = "T".repeat(MAX_TRANSCRIPT_LABEL_LEN + 1);
    assert!(
        validate_stark_transcript_label(
            &overlong_transcript_label,
            effective_max_transcript_label_len(&relaxed),
        )
        .is_err(),
        "caller limits must not relax canonical transcript-label length"
    );
    assert_eq!(effective_max_aux_terms(&relaxed), MAX_AUX_TERMS);
    assert_eq!(effective_max_air_width(&relaxed), MAX_AIR_WIDTH);
    assert_eq!(effective_max_envelope_bytes(&relaxed), MAX_ENVELOPE_BYTES);
}
#[test]
fn synthesized_envelope_verifies_six_lane_digest() {
    let params = StarkFriParamsV1 {
        version: 1,
        n_log2: 4,
        blowup_log2: 2,
        fold_arity: 2,
        queries: 2,
        merkle_arity: 2,
        domain_tag: "iroha:test:six-lane-digest".to_owned(),
    };
    let bytes = prove_stark_fri_air_envelope_bytes(
        params,
        "IROHA-TEST-STARK".to_owned(),
        "stark/fri/poseidon-x7-goldilocks-6x64-v1:test".to_owned(),
        test_digest(0x11),
    )
    .expect("ok");
    assert!(
        verify_stark_fri_envelope(&bytes).expect("semantic verification fixture must complete")
    );
}
#[test]
fn binding_air_rejects_fixed_coefficient_cancellation_rows() {
    let params = StarkFriParamsV1 {
        version: 1,
        n_log2: 4,
        blowup_log2: 2,
        fold_arity: 2,
        queries: 2,
        merkle_arity: 2,
        domain_tag: "iroha:test:binding-air-fixed-coefficient-cancellation".to_owned(),
    };
    let domain = 1_usize << usize::from(params.n_log2);
    let public_digest = test_digest(0x61);
    let one = Fq::one();
    let two = Fq::from_canonical_u64(2).expect("canonical two");
    let rows = (0..domain)
        .map(|index| {
            let expected = stark_air_row(index, &public_digest).expect("build binding AIR row");
            let mut forged = expected.clone();
            forged[0] = Fq::from_canonical_u64(forged[0])
                .expect("canonical row coordinate")
                .add(one)
                .0;
            forged[1] = Fq::from_canonical_u64(forged[1])
                .expect("canonical row coordinate")
                .sub(two)
                .0;
            forged[2] = Fq::from_canonical_u64(forged[2])
                .expect("canonical row coordinate")
                .add(one)
                .0;
            assert_ne!(forged, expected);
            forged
        })
        .collect::<Vec<_>>();

    // The former fixed coefficients accepted this non-zero residue vector:
    // 3 * 1 + 5 * (-2) + 7 * 1 = 0 in the proof field.
    let legacy_collision = Fq::from_canonical_u64(3)
        .expect("canonical three")
        .sub(Fq::from_canonical_u64(5).expect("canonical five").mul(two))
        .add(Fq::from_canonical_u64(7).expect("canonical seven"));
    assert_eq!(legacy_collision, Fq::zero());
    assert_eq!(
        stark_air_composition_value(0, domain, &public_digest, &rows[0], &rows[1]),
        None,
        "a sampled forged row must fail the verifier-owned coordinate check"
    );

    let bytes = prove_stark_fri_zero_composition_air_envelope_bytes(
        params,
        "IROHA-TEST-BINDING-AIR-FIXED-COEFFICIENT-CANCELLATION".to_owned(),
        "stark/fri/custom-binding-air-fixed-coefficient-cancellation:test".to_owned(),
        public_digest,
        rows,
    )
    .expect("explicit-row prover constructs the forged cancellation envelope");
    assert!(
        !verify_stark_fri_envelope(&bytes).expect("semantic verification fixture must complete"),
        "generic binding AIR verifier must reject every sampled forged row"
    );
}
#[test]
fn binding_air_rejects_unsampled_row_via_exact_trace_root() {
    let params = StarkFriParamsV1 {
        version: 1,
        n_log2: 4,
        blowup_log2: 2,
        fold_arity: 2,
        queries: 2,
        merkle_arity: 2,
        domain_tag: "iroha:test:binding-air-unsampled-row".to_owned(),
    };
    let domain = 1_usize << usize::from(params.n_log2);
    let public_digest = test_digest(0x62);
    let circuit_id = "stark/fri/custom-binding-air-unsampled-row:test";
    let canonical_rows = (0..domain)
        .map(|index| stark_air_row(index, &public_digest).expect("build canonical Binding AIR row"))
        .collect::<Vec<_>>();
    let expected_root = stark_binding_air_trace_root(&params, &public_digest, domain)
        .expect("reconstruct canonical Binding AIR trace root");
    assert_eq!(
        stark_air_trace_root_from_rows_v1(&params, &canonical_rows),
        Some(expected_root),
        "streaming reconstruction must match the ordinary Merkle builder"
    );

    for bad_index in 0..domain {
        let mut forged_rows = canonical_rows.clone();
        forged_rows[bad_index][0] = Fq::from_canonical_u64(forged_rows[bad_index][0])
            .expect("canonical Binding row index")
            .add(Fq::one())
            .0;
        let bytes = prove_stark_fri_zero_composition_air_envelope_bytes(
            params.clone(),
            "IROHA-TEST-BINDING-AIR-UNSAMPLED-ROW".to_owned(),
            circuit_id.to_owned(),
            public_digest,
            forged_rows.clone(),
        )
        .expect("explicit-row prover constructs the sparse forged envelope");
        let envelope: StarkVerifyEnvelopeV1 =
            norito::decode_from_bytes(&bytes).expect("decode sparse forged envelope");
        let air = envelope.proof.air.as_ref().expect("AIR section");
        let bad_row_is_opened = air.openings.iter().any(|opening| {
            let index = usize::try_from(opening.index).expect("opening index fits usize");
            index == bad_index || (index + 1) % domain == bad_index
        });
        if bad_row_is_opened {
            continue;
        }

        assert_ne!(air.trace_root, expected_root);
        assert!(air.openings.iter().all(|opening| {
            let index = usize::try_from(opening.index).expect("opening index fits usize");
            stark_air_composition_value(
                index,
                domain,
                &public_digest,
                &opening.row,
                &opening.next_row,
            ) == Some(Fq::zero())
        }));
        let composition_values = vec![0; domain];
        assert!(
            verify_stark_fri_air_envelope_from_rows_and_composition_values(
                &bytes,
                circuit_id,
                &public_digest,
                &forged_rows,
                &composition_values,
            )
            .expect("semantic verification fixture must complete"),
            "all commitments, FRI folds, and sampled explicit rows remain valid"
        );
        assert!(
            !verify_stark_fri_envelope(&bytes)
                .expect("semantic verification fixture must complete"),
            "generic Binding must reject the unsampled row through exact trace-root equality"
        );
        return;
    }
    panic!("failed to place the forged row outside every sampled row and successor");
}
#[test]
fn binding_air_rejects_sparse_composition_layer_substitution_via_exact_zero_root() {
    let params = StarkFriParamsV1 {
        version: 1,
        n_log2: 4,
        blowup_log2: 2,
        fold_arity: 2,
        queries: 2,
        merkle_arity: 2,
        domain_tag: "iroha:test:binding-air-sparse-composition".to_owned(),
    };
    let domain = 1_usize << usize::from(params.n_log2);
    let public_digest = test_digest(0x65);
    let circuit_id = "stark/fri/custom-binding-air-sparse-composition:test";
    let rows = (0..domain)
        .map(|index| stark_air_row(index, &public_digest).expect("build canonical Binding AIR row"))
        .collect::<Vec<_>>();
    let trace_leaves = rows
        .iter()
        .enumerate()
        .map(|(index, row)| {
            stark_air_trace_leaf_hash(&params, row, index).expect("hash canonical Binding AIR row")
        })
        .collect::<Vec<_>>();
    let trace_levels =
        merkle_levels_from_hashes(&params, trace_leaves, StarkMerkleDomainV1::air_trace())
            .expect("build Binding trace tree");
    let trace_root = merkle_root_from_levels(&trace_levels).expect("derive Binding trace root");
    let zero_composition_root = stark_constant_field_merkle_root_v1(&params, Fq::zero(), domain)
        .expect("derive exact zero-composition root");

    for attempt in 0..64_u32 {
        let transcript_label = format!("IROHA-TEST-BINDING-AIR-SPARSE-COMPOSITION:{attempt}");
        for bad_pair in 0..domain / 2 {
            let mut base_values = vec![Fq::zero(); domain];
            base_values[bad_pair * 2] = Fq::one();
            let composition_levels = merkle_levels_from_values(
                &params,
                &base_values,
                StarkMerkleDomainV1::air_composition(),
            )
            .expect("build sparse AIR composition tree");
            let composition_root = merkle_root_from_levels(&composition_levels)
                .expect("derive sparse AIR composition root");
            let mut layer_values = vec![
                base_values
                    .iter()
                    .copied()
                    .map(Fp4::from_base)
                    .collect::<Vec<_>>(),
            ];
            while layer_values.last().is_some_and(|layer| layer.len() > 1) {
                let next_len = layer_values.last().expect("FRI layer").len() / 2;
                layer_values.push(vec![Fp4::zero(); next_len]);
            }
            let layer_merkle = layer_values
                .iter()
                .enumerate()
                .map(|(round, values)| {
                    fri_merkle_levels_from_values(
                        &params,
                        values,
                        StarkMerkleDomainV1::fri_layer(round).expect("bounded FRI round"),
                    )
                    .expect("build sparse FRI layer tree")
                })
                .collect::<Vec<_>>();
            let roots = layer_merkle
                .iter()
                .map(|levels| merkle_root_from_levels(levels).expect("derive sparse FRI root"))
                .collect::<Vec<_>>();
            let statement_commitment = stark_air_public_statement_commitment_v1(
                &params,
                circuit_id,
                STARK_BINDING_AIR_TRACE_WIDTH_V1,
                &public_digest,
            )
            .expect("bind sparse AIR public statement");
            let extra_query_roots = [trace_root, composition_root, statement_commitment];
            let mut query_roots = roots.clone();
            query_roots.extend_from_slice(&extra_query_roots);
            let base_indices = derive_query_indices_without_replacement(
                &transcript_label,
                &params,
                &query_roots,
                usize::from(params.queries),
                domain,
            )
            .expect("derive sparse-composition query schedule");
            if base_indices.iter().any(|index| index / 2 == bad_pair) {
                continue;
            }
            let beta = fri_round_challenge(&params, &transcript_label, 0, &roots[0])
                .expect("derive first FRI challenge");
            let x = domain_x_for_pair(domain, bad_pair).expect("derive sparse-pair point");
            if fri_fold_pair(Fp4::from_base(Fq::one()), Fp4::zero(), beta, x) == Some(Fp4::zero()) {
                continue;
            }

            let queries = base_indices
                .iter()
                .copied()
                .map(|mut index| {
                    let mut chain = Vec::with_capacity(usize::from(params.n_log2));
                    for round in 0..usize::from(params.n_log2) {
                        let j = index / 2;
                        let y0_index = j * 2;
                        let y1_index = y0_index + 1;
                        chain.push(FoldDecommitV1 {
                            j: u32::try_from(j).expect("fold index fits u32"),
                            y0: layer_values[round][y0_index].to_wire(),
                            y1: layer_values[round][y1_index].to_wire(),
                            path_y0: merkle_path_from_levels(y0_index, &layer_merkle[round])
                                .expect("open sparse FRI y0"),
                            path_y1: merkle_path_from_levels(y1_index, &layer_merkle[round])
                                .expect("open sparse FRI y1"),
                            z: layer_values[round + 1][j].to_wire(),
                            path_z: merkle_path_from_levels(j, &layer_merkle[round + 1])
                                .expect("open sparse FRI z"),
                        });
                        index = j;
                    }
                    chain
                })
                .collect::<Vec<_>>();
            let openings = base_indices
                .iter()
                .copied()
                .map(|index| {
                    let next_index = (index + 1) % domain;
                    StarkAirOpeningV1 {
                        index: u32::try_from(index).expect("opening index fits u32"),
                        row: rows[index].clone(),
                        next_row: rows[next_index].clone(),
                        row_path: merkle_path_from_levels(index, &trace_levels)
                            .expect("open canonical Binding row"),
                        next_row_path: merkle_path_from_levels(next_index, &trace_levels)
                            .expect("open next canonical Binding row"),
                        composition_value: 0,
                        composition_path: merkle_path_from_levels(index, &composition_levels)
                            .expect("open sampled zero composition"),
                    }
                })
                .collect::<Vec<_>>();
            let envelope = StarkVerifyEnvelopeV1 {
                params: params.clone(),
                proof: StarkProofV1 {
                    version: 1,
                    commits: StarkCommitmentsV1 {
                        version: 1,
                        roots,
                        comp_root: None,
                    },
                    queries,
                    comp_values: None,
                    air: Some(StarkAirProofV1 {
                        version: 1,
                        circuit_id: circuit_id.to_owned(),
                        public_digest,
                        trace_root,
                        composition_root,
                        trace_width: STARK_BINDING_AIR_TRACE_WIDTH_V1,
                        openings,
                    }),
                },
                transcript_label,
            };
            let air = envelope.proof.air.as_ref().expect("AIR section");
            assert_ne!(air.composition_root, zero_composition_root);
            assert_ne!(
                envelope.proof.commits.roots.first(),
                Some(&air.composition_root)
            );
            assert!(
                validate_stark_fri_query_shape_and_indices_v1(
                    &envelope.params,
                    &envelope.transcript_label,
                    &envelope.proof.commits.roots,
                    &extra_query_roots,
                    &envelope.proof.queries,
                )
                .is_ok(),
                "sampled Merkle openings and fold chains deliberately avoid the substituted pair"
            );
            let bytes = ivm_abi::codec::encode_canonical_norito(&envelope)
                .expect("encode sparse-composition envelope");
            let mut sparse_composition = vec![0; domain];
            sparse_composition[bad_pair * 2] = 1;
            assert!(
                verify_stark_fri_air_envelope_from_rows_and_composition_values(
                    &bytes,
                    circuit_id,
                    &public_digest,
                    &rows,
                    &sparse_composition,
                )
                .expect("semantic verification fixture must complete"),
                "sampled FRI replay alone accepts the unqueried first-layer substitution"
            );
            assert!(
                !verify_stark_fri_envelope(&bytes)
                    .expect("semantic verification fixture must complete"),
                "generic Binding must require the exact all-zero base-composition commitment"
            );
            return;
        }
    }
    panic!("failed to derive a query schedule outside the sparse substituted pair");
}
#[test]
fn generic_binding_provers_reject_domain_above_exact_root_cap() {
    let params = StarkFriParamsV1 {
        version: 1,
        n_log2: MAX_BINDING_AIR_DOMAIN_LOG2 + 1,
        blowup_log2: 3,
        fold_arity: 2,
        queries: 2,
        merkle_arity: 2,
        domain_tag: "iroha:test:binding-air-prover-root-cap".to_owned(),
    };
    let circuit_id = "stark/fri/custom-binding-air-prover-root-cap:test";
    let public_digest = test_digest(0x63);
    let error = prove_stark_fri_air_envelope_bytes(
        params.clone(),
        "IROHA-TEST-BINDING-AIR-PROVER-ROOT-CAP".to_owned(),
        circuit_id.to_owned(),
        public_digest,
    )
    .expect_err("canonical generic Binding prover must reject an oversized domain");
    assert!(
        error
            .to_string()
            .contains("exact trace-root reconstruction limit")
    );
    let error = prove_stark_fri_zero_composition_air_envelope_bytes(
        params,
        "IROHA-TEST-BINDING-AIR-PROVER-ROOT-CAP".to_owned(),
        circuit_id.to_owned(),
        public_digest,
        Vec::new(),
    )
    .expect_err("explicit-row generic Binding prover must reject an oversized domain");
    assert!(
        error
            .to_string()
            .contains("exact trace-root reconstruction limit")
    );
}
#[test]
fn generic_binding_verifier_rejects_domain_above_exact_root_cap() {
    let params = StarkFriParamsV1 {
        version: 1,
        n_log2: MAX_BINDING_AIR_DOMAIN_LOG2 + 1,
        blowup_log2: 3,
        fold_arity: 2,
        queries: 2,
        merkle_arity: 2,
        domain_tag: "iroha:test:binding-air-verifier-root-cap".to_owned(),
    };
    let domain = 1_usize << usize::from(params.n_log2);
    let public_digest = test_digest(0x64);
    let circuit_id = "stark/fri/custom-binding-air-verifier-root-cap:test";
    let rows = (0..domain)
        .map(|index| stark_air_row(index, &public_digest).expect("build canonical Binding AIR row"))
        .collect::<Vec<_>>();
    let composition_values = vec![0; domain];
    let bytes = prove_stark_fri_air_envelope_from_rows_and_composition_values_bytes(
        params,
        "IROHA-TEST-BINDING-AIR-VERIFIER-ROOT-CAP".to_owned(),
        circuit_id.to_owned(),
        public_digest,
        rows.clone(),
        composition_values.clone(),
    )
    .expect("Explicit context retains the native domain limit");
    assert!(
        verify_stark_fri_air_envelope_from_rows_and_composition_values(
            &bytes,
            circuit_id,
            &public_digest,
            &rows,
            &composition_values,
        )
        .expect("semantic verification fixture must complete")
    );
    assert!(
        !verify_stark_fri_envelope(&bytes).expect("semantic verification fixture must complete"),
        "generic Binding verification must reject before oversized root reconstruction"
    );
}
#[test]
fn public_generic_air_provers_reject_bfv_full_bootstrap_circuit_aliases() {
    let params = StarkFriParamsV1 {
        version: 1,
        n_log2: 4,
        blowup_log2: 2,
        fold_arity: 2,
        queries: 2,
        merkle_arity: 2,
        domain_tag: "iroha:test:reserved-bfv-generic-air".to_owned(),
    };
    let rows = vec![vec![0]; 1_usize << usize::from(params.n_log2)];
    let composition_values = vec![0; rows.len()];
    let base_indices = [0_usize, 1];
    let canonical = iroha_crypto::BFV_FULL_BOOTSTRAP_CIRCUIT_ID_V1;
    let circuit_ids = [
        canonical.to_owned(),
        format!("stark/fri/poseidon-x7-goldilocks-6x64-v1:{canonical}"),
        format!("stark/fri/poseidon-x7-goldilocks-6x64-v1/{canonical}"),
        format!("stark/fri/poseidon2-goldilocks:{canonical}"),
    ];
    for circuit_id in circuit_ids {
        let err = prove_stark_fri_air_envelope_bytes(
            params.clone(),
            "IROHA-TEST-RESERVED-BFV-GENERIC-AIR".to_owned(),
            circuit_id.clone(),
            test_digest(0xB4),
        )
        .expect_err("generic AIR prover must reject BFV full-bootstrap circuit aliases");
        assert!(
            err.to_string().contains("BFV full-bootstrap"),
            "unexpected generic AIR rejection for {circuit_id}: {err}"
        );
        let err = prove_stark_fri_zero_composition_air_envelope_bytes(
            params.clone(),
            "IROHA-TEST-RESERVED-BFV-ZERO-AIR".to_owned(),
            circuit_id.clone(),
            test_digest(0xB5),
            rows.clone(),
        )
        .expect_err("zero-composition AIR prover must reject BFV full-bootstrap circuit aliases");
        assert!(
            err.to_string().contains("BFV full-bootstrap"),
            "unexpected zero-composition AIR rejection for {circuit_id}: {err}"
        );
        let err = prove_stark_fri_air_envelope_from_rows_and_composition_values_bytes(
            params.clone(),
            "IROHA-TEST-RESERVED-BFV-EXPLICIT-AIR".to_owned(),
            circuit_id.clone(),
            test_digest(0xB6),
            rows.clone(),
            composition_values.clone(),
        )
        .expect_err("explicit row/composition AIR prover must reject BFV aliases");
        assert!(
            err.to_string().contains("BFV full-bootstrap"),
            "unexpected explicit AIR rejection for {circuit_id}: {err}"
        );
        let err =
            prove_stark_fri_air_envelope_from_rows_and_composition_values_with_base_indices_bytes(
                params.clone(),
                "IROHA-TEST-RESERVED-BFV-EXPLICIT-BASE-AIR".to_owned(),
                circuit_id.clone(),
                test_digest(0xB7),
                rows.clone(),
                composition_values.clone(),
                &base_indices,
            )
            .expect_err("explicit-base AIR prover must reject BFV aliases");
        assert!(
            err.to_string().contains("BFV full-bootstrap"),
            "unexpected explicit-base AIR rejection for {circuit_id}: {err}"
        );
    }
}
#[test]
fn public_generic_air_provers_reject_zk_ace_circuit_aliases() {
    let params = StarkFriParamsV1 {
        version: 1,
        n_log2: 4,
        blowup_log2: 2,
        fold_arity: 2,
        queries: 2,
        merkle_arity: 2,
        domain_tag: "iroha:test:reserved-zk-ace-generic-air".to_owned(),
    };
    let rows = vec![vec![0]; 1_usize << usize::from(params.n_log2)];
    for canonical in [iroha_data_model::zk::ZK_ACE_PQ_AUTHORIZATION_V1_CIRCUIT_ID] {
        let circuit_ids = [
            canonical.to_owned(),
            format!("stark/fri/poseidon-x7-goldilocks-6x64-v1:{canonical}"),
            format!("stark/fri/poseidon-x7-goldilocks-6x64-v1/{canonical}"),
            format!("stark/fri/poseidon2-goldilocks:{canonical}"),
        ];
        for circuit_id in circuit_ids {
            let err = prove_stark_fri_air_envelope_bytes(
                params.clone(),
                "IROHA-TEST-RESERVED-ZK-ACE-GENERIC-AIR".to_owned(),
                circuit_id.clone(),
                test_digest(0xC4),
            )
            .expect_err("generic AIR prover must reject ZK-ACE circuit aliases");
            assert!(
                err.to_string().contains("ZK-ACE"),
                "unexpected generic AIR rejection for {circuit_id}: {err}"
            );
            let err = prove_stark_fri_zero_composition_air_envelope_bytes(
                params.clone(),
                "IROHA-TEST-RESERVED-ZK-ACE-ZERO-AIR".to_owned(),
                circuit_id.clone(),
                test_digest(0xC5),
                rows.clone(),
            )
            .expect_err("zero-composition AIR prover must reject ZK-ACE circuit aliases");
            assert!(
                err.to_string().contains("ZK-ACE"),
                "unexpected zero-composition AIR rejection for {circuit_id}: {err}"
            );
        }
    }
}
#[test]
fn public_generic_air_provers_reject_ivm_execution_circuit_aliases() {
    let params = StarkFriParamsV1 {
        version: 1,
        n_log2: 4,
        blowup_log2: 2,
        fold_arity: 2,
        queries: 2,
        merkle_arity: 2,
        domain_tag: "iroha:test:reserved-ivm-generic-air".to_owned(),
    };
    let rows = vec![vec![0]; 1_usize << usize::from(params.n_log2)];
    let canonical = crate::IVM_EXECUTION_V1_CIRCUIT_ID;
    let circuit_ids = [
        canonical.to_owned(),
        format!("stark/fri/poseidon-x7-goldilocks-6x64-v1:{canonical}"),
        format!("stark/fri/poseidon-x7-goldilocks-6x64-v1/{canonical}"),
        format!("stark/fri/poseidon2-goldilocks:{canonical}"),
    ];
    for circuit_id in circuit_ids {
        let err = prove_stark_fri_air_envelope_bytes(
            params.clone(),
            "IROHA-TEST-RESERVED-IVM-GENERIC-AIR".to_owned(),
            circuit_id.clone(),
            test_digest(0xD4),
        )
        .expect_err("generic AIR prover must reject IVM execution circuit aliases");
        assert!(
            err.to_string().contains("IVM execution"),
            "unexpected generic AIR rejection for {circuit_id}: {err}"
        );
        let err = prove_stark_fri_zero_composition_air_envelope_bytes(
            params.clone(),
            "IROHA-TEST-RESERVED-IVM-ZERO-AIR".to_owned(),
            circuit_id.clone(),
            test_digest(0xD5),
            rows.clone(),
        )
        .expect_err("zero-composition AIR prover must reject IVM execution circuit aliases");
        assert!(
            err.to_string().contains("IVM execution"),
            "unexpected zero-composition AIR rejection for {circuit_id}: {err}"
        );
    }
}
#[test]
fn generic_binding_air_reserves_governance_vote_role_aliases() {
    let params = StarkFriParamsV1 {
        version: 1,
        n_log2: 4,
        blowup_log2: 2,
        fold_arity: 2,
        queries: 2,
        merkle_arity: 2,
        domain_tag: "iroha:test:reserved-governance-generic-air".to_owned(),
    };
    for canonical in [
        crate::GOVERNANCE_BALLOT_CIRCUIT_ID_V1,
        crate::GOVERNANCE_TALLY_CIRCUIT_ID_V1,
    ] {
        for circuit_id in [
            canonical.to_owned(),
            format!("stark/fri/poseidon-x7-goldilocks-6x64-v1:{canonical}"),
            format!("stark/fri/poseidon-x7-goldilocks-6x64-v1/{canonical}"),
            format!("stark/fri/poseidon2-goldilocks:{canonical}"),
        ] {
            let err = validate_generic_stark_air_circuit_id(&circuit_id)
                .expect_err("governance vote roles must be reserved from generic AIR");
            assert!(
                err.to_string().contains("governance vote role"),
                "unexpected governance role rejection for {circuit_id}: {err}"
            );
            let air = StarkAirProofV1 {
                version: 1,
                circuit_id: circuit_id.clone(),
                public_digest: GoldilocksDigest384V1::default(),
                trace_root: GoldilocksDigest384V1::default(),
                composition_root: GoldilocksDigest384V1::default(),
                trace_width: STARK_BINDING_AIR_TRACE_WIDTH_V1,
                openings: Vec::new(),
            };
            assert!(
                !stark_air_context_matches_statement(
                    &params,
                    &air,
                    1_usize << usize::from(params.n_log2),
                    StarkAirVerificationContext::Binding,
                ),
                "generic verifier context must reject governance role {circuit_id}"
            );
        }
    }
    assert!(
        validate_generic_stark_air_circuit_id(
            "stark/fri/poseidon-x7-goldilocks-6x64-v1:vote-ballot-near-miss"
        )
        .is_ok(),
        "reservation must match complete semantic role ids"
    );
}
#[test]
fn generic_air_circuit_classifier_reserves_every_soracloud_fhe_relation_alias() {
    use iroha_data_model::soracloud::{
        SORACLOUD_FHE_BOOTSTRAP_KEY_PROOF_CIRCUIT_ID_V1,
        SORACLOUD_FHE_FULL_BOOTSTRAP_EXECUTION_PROOF_CIRCUIT_ID_V1,
        SORACLOUD_FHE_INPUT_ADMISSION_CIRCUIT_ID_V1, SORACLOUD_FHE_PUBLIC_KEY_PROOF_CIRCUIT_ID_V1,
    };
    for canonical in [
        SORACLOUD_FHE_INPUT_ADMISSION_CIRCUIT_ID_V1,
        SORACLOUD_FHE_PUBLIC_KEY_PROOF_CIRCUIT_ID_V1,
        SORACLOUD_FHE_BOOTSTRAP_KEY_PROOF_CIRCUIT_ID_V1,
        SORACLOUD_FHE_FULL_BOOTSTRAP_EXECUTION_PROOF_CIRCUIT_ID_V1,
    ] {
        for circuit_id in [
            canonical.to_owned(),
            format!("stark/fri/poseidon-x7-goldilocks-6x64-v1:{canonical}"),
            format!("stark/fri/poseidon-x7-goldilocks-6x64-v1/{canonical}"),
            format!("stark/fri/poseidon2-goldilocks:{canonical}"),
        ] {
            let err = validate_generic_stark_air_circuit_id(&circuit_id)
                .expect_err("Soracloud FHE relation must be reserved from generic AIR");
            assert!(
                err.to_string().contains("Soracloud")
                    || err.to_string().contains("BFV full-bootstrap"),
                "unexpected Soracloud relation rejection for {circuit_id}: {err}"
            );
        }
    }
    assert!(
        validate_generic_stark_air_circuit_id(
            "stark/fri/poseidon-x7-goldilocks-6x64-v1:soracloud_fhe_input_admission_v1_near_miss",
        )
        .is_ok(),
        "reservation must match complete relation ids, not unrelated prefixes"
    );
}
#[test]
fn synthesized_field_values_envelope_has_replayable_query_shape() {
    let params = StarkFriParamsV1 {
        version: 1,
        n_log2: 4,
        blowup_log2: 2,
        fold_arity: 2,
        queries: 2,
        merkle_arity: 2,
        domain_tag: "iroha:test:field-values".to_owned(),
    };
    let values = vec![0; 1_usize << usize::from(params.n_log2)];
    let extra_query_roots = [test_digest(0xA1), test_digest(0xA2), test_digest(0xA3)];
    let envelope = stark_synthesize_fri_envelope_from_field_values_v1(
        params.clone(),
        "IROHA-TEST-STARK".to_owned(),
        &values,
        &extra_query_roots,
    )
    .expect("synthesize field-value FRI envelope");
    let indices = validate_stark_fri_query_shape_and_indices_v1(
        &params,
        &envelope.transcript_label,
        &envelope.proof.commits.roots,
        &extra_query_roots,
        &envelope.proof.queries,
    )
    .expect("query shape replays");
    assert_eq!(indices.len(), usize::from(params.queries));
    assert!(
        indices
            .iter()
            .enumerate()
            .all(|(index, sampled)| !indices[..index].contains(sampled)),
        "query sampling must not repeat base indices"
    );
    let mut stale_merkle = envelope.clone();
    let mut stale_words = stale_merkle.proof.queries[0][0].path_y0.siblings[0].words();
    stale_words[0] ^= 1;
    stale_merkle.proof.queries[0][0].path_y0.siblings[0] =
        GoldilocksDigest384V1::new(stale_words).expect("mutated sibling remains canonical");
    assert_eq!(
        validate_stark_fri_query_shape_and_indices_v1(
            &params,
            &stale_merkle.transcript_label,
            &stale_merkle.proof.commits.roots,
            &extra_query_roots,
            &stale_merkle.proof.queries,
        )
        .expect_err("stale FRI Merkle openings must be rejected"),
        "FRI query Merkle root mismatch"
    );
    let mut stale_folded_merkle = envelope.clone();
    let mut stale_words = stale_folded_merkle.proof.queries[0][0].path_z.siblings[0].words();
    stale_words[0] ^= 1;
    stale_folded_merkle.proof.queries[0][0].path_z.siblings[0] =
        GoldilocksDigest384V1::new(stale_words).expect("mutated sibling remains canonical");
    assert_eq!(
        validate_stark_fri_query_shape_and_indices_v1(
            &params,
            &stale_folded_merkle.transcript_label,
            &stale_folded_merkle.proof.commits.roots,
            &extra_query_roots,
            &stale_folded_merkle.proof.queries,
        )
        .expect_err("stale folded FRI Merkle openings must be rejected"),
        "FRI query folded Merkle root mismatch"
    );
    let mut stale_fold = envelope;
    let mut stale_coefficients = stale_fold.proof.queries[0][0].z.coefficients();
    stale_coefficients[0] = stale_coefficients[0].saturating_add(1);
    stale_fold.proof.queries[0][0].z =
        GoldilocksFp4V1::new(stale_coefficients).expect("mutated fold remains canonical");
    assert_eq!(
        validate_stark_fri_query_shape_and_indices_v1(
            &params,
            &stale_fold.transcript_label,
            &stale_fold.proof.commits.roots,
            &extra_query_roots,
            &stale_fold.proof.queries,
        )
        .expect_err("stale FRI fold values must be rejected"),
        "FRI query fold relation mismatch"
    );
    let nonzero_values = vec![1; 1_usize << usize::from(params.n_log2)];
    assert!(
        stark_synthesize_fri_envelope_from_field_values_v1(
            params.clone(),
            "IROHA-TEST-STARK".to_owned(),
            &nonzero_values,
            &extra_query_roots,
        )
        .is_none(),
        "prover must reject non-zero final FRI values before emitting proof bytes"
    );
    let public_err = prove_stark_fri_air_envelope_from_rows_and_composition_values_bytes(
        params,
        "IROHA-TEST-STARK".to_owned(),
        "stark/fri/nonzero-final:test".to_owned(),
        test_digest(0xA5),
        vec![vec![0]; 1_usize << 4],
        nonzero_values,
    )
    .expect_err("public AIR prover must reject non-zero final FRI values");
    assert!(
        matches!(public_err, StarkProofProductionError::Input(ref message)
            if message == "STARK final FRI value must be zero"),
        "non-zero final FRI values must fail during proof construction: {public_err}"
    );
}
#[test]
fn stark_fri_query_shape_rejects_unused_merkle_direction_bits() {
    let params = StarkFriParamsV1 {
        version: 1,
        n_log2: 4,
        blowup_log2: 2,
        fold_arity: 2,
        queries: 2,
        merkle_arity: 2,
        domain_tag: "iroha:test:unused-merkle-dir-bits".to_owned(),
    };
    let values = vec![0; 1_usize << usize::from(params.n_log2)];
    let mut envelope = stark_synthesize_fri_envelope_from_field_values_v1(
        params.clone(),
        "IROHA-TEST-STARK-UNUSED-MERKLE-DIR-BITS".to_owned(),
        &values,
        &[],
    )
    .expect("synthesize field-value FRI envelope");
    let path = &mut envelope.proof.queries[0][0].path_y0;
    assert_eq!(path.dirs.len(), 1);
    path.dirs[0] |= 0b1000_0000;
    assert_eq!(
        validate_stark_fri_query_shape_and_indices_v1(
            &params,
            &envelope.transcript_label,
            &envelope.proof.commits.roots,
            &[],
            &envelope.proof.queries,
        )
        .expect_err("unused Merkle direction bits must be rejected"),
        "FRI query Merkle path depth mismatch"
    );
}
#[test]
fn without_replacement_query_schedule_uses_bound_specific_offsets() {
    let mut params = StarkFriParamsV1 {
        version: 1,
        n_log2: 3,
        blowup_log2: 1,
        fold_arity: 2,
        queries: 4,
        merkle_arity: 2,
        domain_tag: String::new(),
    };
    let label = "IROHA-TEST-BOUNDED-STARK-QUERY-OFFSET";
    let roots = [
        GoldilocksDigest384V1::new([0x42; 6]).expect("canonical root"),
        GoldilocksDigest384V1::new([0x24; 6]).expect("canonical root"),
    ];
    let domain = 1_usize << usize::from(params.n_log2);
    let query_number = 1;
    let remaining = domain - query_number;
    for nonce in 0_u32..4096 {
        params.domain_tag = format!("iroha:test:six-lane:bounded-query-offset:{nonce}");
        let domain_remodulo = derive_query_index(label, &params, &roots, query_number)
            .expect("query index")
            % remaining;
        let bounded = derive_bounded_query_offset(label, &params, &roots, query_number, remaining)
            .expect("bounded query offset");
        if domain_remodulo == bounded {
            continue;
        }
        let first_draw =
            derive_bounded_query_offset(label, &params, &roots, 0, domain).expect("first draw");
        let mut swaps = BTreeMap::new();
        let first_selected = first_draw;
        swaps.insert(first_draw, 0);
        let bounded_selected = swaps
            .get(&(query_number + bounded))
            .copied()
            .unwrap_or(query_number + bounded);
        let remodulo_selected = swaps
            .get(&(query_number + domain_remodulo))
            .copied()
            .unwrap_or(query_number + domain_remodulo);
        if bounded_selected == remodulo_selected {
            continue;
        }
        let indices = derive_query_indices_without_replacement(label, &params, &roots, 2, domain)
            .expect("without-replacement schedule");
        assert_eq!(indices[0], first_selected);
        assert_eq!(indices[1], bounded_selected);
        assert_ne!(
            indices[1], remodulo_selected,
            "query schedule must use a bound-specific draw, not domain sample modulo remaining"
        );
        return;
    }
    panic!("failed to find a six-lane bounded-offset fixture that differs from domain remodulo");
}
#[test]
fn air_opening_first_fri_value_binding_uses_sampled_parity() {
    let empty_path = || MerklePath {
        dirs: Vec::new(),
        siblings: Vec::new(),
    };
    let opening = StarkAirOpeningV1 {
        index: 0,
        row: Vec::new(),
        next_row: Vec::new(),
        row_path: empty_path(),
        next_row_path: empty_path(),
        composition_value: 11,
        composition_path: empty_path(),
    };
    let decommit = FoldDecommitV1 {
        j: 0,
        y0: GoldilocksFp4V1::from_base(11).expect("canonical y0"),
        y1: GoldilocksFp4V1::from_base(17).expect("canonical y1"),
        path_y0: empty_path(),
        path_y1: empty_path(),
        z: GoldilocksFp4V1::from_base(0).expect("canonical z"),
        path_z: empty_path(),
    };
    validate_stark_air_opening_first_fri_value_v1(&opening, 0, &decommit)
        .expect("even sampled index binds y0");
    let mut odd_opening = opening.clone();
    odd_opening.index = 1;
    odd_opening.composition_value = 17;
    validate_stark_air_opening_first_fri_value_v1(&odd_opening, 1, &decommit)
        .expect("odd sampled index binds y1");
    assert_eq!(
        validate_stark_air_opening_first_fri_value_v1(&opening, 1, &decommit)
            .expect_err("mismatched sampled index must fail"),
        "AIR/FRI opening index mismatch"
    );
    let mut wrong_side_opening = odd_opening;
    wrong_side_opening.composition_value = 11;
    assert_eq!(
        validate_stark_air_opening_first_fri_value_v1(&wrong_side_opening, 1, &decommit)
            .expect_err("wrong FRI side must fail"),
        "AIR/FRI composition value mismatch"
    );
}
#[test]
fn synthesized_envelope_verifies_six_lane_profile() {
    let params = StarkFriParamsV1 {
        version: 1,
        n_log2: 4,
        blowup_log2: 2,
        fold_arity: 2,
        queries: 2,
        merkle_arity: 2,
        domain_tag: "iroha:test:six-lane".to_owned(),
    };
    let bytes = prove_stark_fri_air_envelope_bytes(
        params,
        "IROHA-TEST-STARK".to_owned(),
        "stark/fri/poseidon-x7-goldilocks-6x64-v1:test".to_owned(),
        test_digest(0x22),
    )
    .expect("ok");
    assert!(
        verify_stark_fri_envelope(&bytes).expect("semantic verification fixture must complete")
    );
}
#[test]
fn stark_fri_rejects_noncanonical_transcript_labels() {
    let hash_label = "six-lane";
    let circuit_id = "stark/fri/poseidon-x7-goldilocks-6x64-v1:canonical-transcript-label";
    let digest_byte = 0x51_u8;
    let params = StarkFriParamsV1 {
        version: 1,
        n_log2: 4,
        blowup_log2: 2,
        fold_arity: 2,
        queries: 2,
        merkle_arity: 2,
        domain_tag: "iroha:test:canonical-transcript-label:six-lane".to_owned(),
    };
    let bytes = prove_stark_fri_air_envelope_bytes(
        params.clone(),
        format!("IROHA-TEST-STARK-CANONICAL-LABEL-{hash_label}"),
        circuit_id.to_owned(),
        test_digest(u64::from(digest_byte)),
    )
    .expect("valid labeled STARK envelope");
    assert!(
        verify_stark_fri_envelope(&bytes).expect("semantic verification fixture must complete")
    );
    let mut envelope: StarkVerifyEnvelopeV1 =
        norito::decode_from_bytes(&bytes).expect("decode labeled STARK envelope");
    let air = envelope.proof.air.as_ref().expect("AIR section");
    let statement_commitment = stark_air_public_statement_commitment_v1(
        &params,
        &air.circuit_id,
        air.trace_width,
        &air.public_digest,
    )
    .expect("bind AIR public statement");
    let extra_query_roots = [air.trace_root, air.composition_root, statement_commitment];
    let invalid_labels = [
        ("empty", String::new()),
        ("leading whitespace", " IROHA-TEST-STARK".to_owned()),
        ("embedded whitespace", "IROHA TEST STARK".to_owned()),
        ("control byte", "IROHA-TEST\nSTARK".to_owned()),
        ("non-ASCII", "IROHA-TEST-STARK-π".to_owned()),
        ("overlong", "A".repeat(MAX_TRANSCRIPT_LABEL_LEN + 1)),
    ];
    for (label_case, invalid_label) in invalid_labels {
        let err = prove_stark_fri_air_envelope_bytes(
            params.clone(),
            invalid_label.clone(),
            circuit_id.to_owned(),
            test_digest(u64::from(digest_byte)),
        )
        .expect_err("noncanonical STARK transcript labels must be rejected by proof construction");
        assert!(
            err.to_string().contains("transcript label"),
            "{hash_label} {label_case} error should mention transcript labels, got: {err}"
        );
        assert_eq!(
            validate_stark_fri_query_shape_and_indices_v1(
                &params,
                &invalid_label,
                &envelope.proof.commits.roots,
                &extra_query_roots,
                &envelope.proof.queries,
            )
            .expect_err("query replay must reject noncanonical transcript labels"),
            "FRI transcript label invalid"
        );
        envelope.transcript_label = invalid_label;
        let tampered =
            norito::to_bytes(&envelope).expect("encode noncanonical-label STARK envelope");
        assert!(
            !verify_stark_fri_envelope(&tampered)
                .expect("semantic verification fixture must complete"),
            "{hash_label} verifier must reject {label_case} transcript labels"
        );
    }
}
#[test]
fn stark_fri_rejects_noncanonical_circuit_ids() {
    let hash_label = "six-lane";
    let circuit_id = "stark/fri/poseidon-x7-goldilocks-6x64-v1:canonical-circuit-id";
    let digest = test_digest(0x61);
    let params = StarkFriParamsV1 {
        version: 1,
        n_log2: 4,
        blowup_log2: 2,
        fold_arity: 2,
        queries: 2,
        merkle_arity: 2,
        domain_tag: "iroha:test:canonical-circuit-id:six-lane".to_owned(),
    };
    let transcript_label = format!("IROHA-TEST-STARK-CANONICAL-CIRCUIT-{hash_label}");
    let bytes = prove_stark_fri_air_envelope_bytes(
        params.clone(),
        transcript_label.clone(),
        circuit_id.to_owned(),
        digest,
    )
    .expect("valid circuit-id STARK envelope");
    assert!(
        verify_stark_fri_envelope(&bytes).expect("semantic verification fixture must complete")
    );
    let mut envelope: StarkVerifyEnvelopeV1 =
        norito::decode_from_bytes(&bytes).expect("decode circuit-id STARK envelope");
    let invalid_circuit_ids = [
        ("empty", String::new()),
        (
            "leading whitespace",
            " stark/fri/poseidon-x7-goldilocks-6x64-v1:test".to_owned(),
        ),
        (
            "embedded whitespace",
            "stark/fri/sha256 goldilocks:test".to_owned(),
        ),
        (
            "control byte",
            "stark/fri/poseidon-x7-goldilocks-6x64-v1:\ntest".to_owned(),
        ),
        (
            "non-ASCII",
            "stark/fri/poseidon-x7-goldilocks-6x64-v1:π".to_owned(),
        ),
        ("overlong", "c".repeat(MAX_TRANSCRIPT_LABEL_LEN + 1)),
    ];
    for (id_case, invalid_circuit_id) in invalid_circuit_ids {
        let err = prove_stark_fri_air_envelope_bytes(
            params.clone(),
            transcript_label.clone(),
            invalid_circuit_id.clone(),
            digest,
        )
        .expect_err("noncanonical STARK circuit ids must be rejected by proof construction");
        assert!(
            err.to_string().contains("circuit_id"),
            "{hash_label} {id_case} error should mention circuit_id, got: {err}"
        );
        envelope.proof.air.as_mut().expect("AIR section").circuit_id = invalid_circuit_id;
        let tampered =
            norito::to_bytes(&envelope).expect("encode noncanonical-circuit STARK envelope");
        assert!(
            !verify_stark_fri_envelope(&tampered)
                .expect("semantic verification fixture must complete"),
            "{hash_label} verifier must reject {id_case} circuit ids"
        );
    }
}
#[test]
fn stark_fri_rejects_noncanonical_domain_tags() {
    let hash_label = "six-lane";
    let circuit_id = "stark/fri/poseidon-x7-goldilocks-6x64-v1:canonical-domain-tag";
    let digest = test_digest(0x71);
    let params = StarkFriParamsV1 {
        version: 1,
        n_log2: 4,
        blowup_log2: 2,
        fold_arity: 2,
        queries: 2,
        merkle_arity: 2,
        domain_tag: "iroha:test:canonical-domain-tag:six-lane".to_owned(),
    };
    let transcript_label = format!("IROHA-TEST-STARK-CANONICAL-DOMAIN-{hash_label}");
    let bytes = prove_stark_fri_air_envelope_bytes(
        params.clone(),
        transcript_label.clone(),
        circuit_id.to_owned(),
        digest,
    )
    .expect("valid domain-tag STARK envelope");
    assert!(
        verify_stark_fri_envelope(&bytes).expect("semantic verification fixture must complete")
    );
    let mut envelope: StarkVerifyEnvelopeV1 =
        norito::decode_from_bytes(&bytes).expect("decode domain-tag STARK envelope");
    let invalid_domain_tags = [
        ("empty", String::new()),
        ("leading whitespace", " iroha:test:domain".to_owned()),
        ("embedded whitespace", "iroha:test domain".to_owned()),
        ("control byte", "iroha:test:\ndomain".to_owned()),
        ("non-ASCII", "iroha:test:π".to_owned()),
        ("overlong", "d".repeat(MAX_DOMAIN_TAG_LEN + 1)),
    ];
    for (tag_case, invalid_domain_tag) in invalid_domain_tags {
        let mut invalid_params = params.clone();
        invalid_params.domain_tag = invalid_domain_tag.clone();
        let err = prove_stark_fri_air_envelope_bytes(
            invalid_params,
            transcript_label.clone(),
            circuit_id.to_owned(),
            digest,
        )
        .expect_err("noncanonical STARK domain tags must be rejected by proof construction");
        assert!(
            err.to_string().contains("domain tag"),
            "{hash_label} {tag_case} error should mention domain tag, got: {err}"
        );
        envelope.params.domain_tag = invalid_domain_tag;
        let tampered =
            norito::to_bytes(&envelope).expect("encode noncanonical-domain STARK envelope");
        assert!(
            !verify_stark_fri_envelope(&tampered)
                .expect("semantic verification fixture must complete"),
            "{hash_label} verifier must reject {tag_case} domain tags"
        );
    }
}
#[test]
fn synthesized_envelope_without_air_is_rejected() {
    let params = StarkFriParamsV1 {
        version: 1,
        n_log2: 4,
        blowup_log2: 2,
        fold_arity: 2,
        queries: 2,
        merkle_arity: 2,
        domain_tag: "iroha:test:missing-air".to_owned(),
    };
    let bytes =
        synthesize_stark_fri_envelope_bytes(params, "IROHA-TEST-STARK".to_owned()).expect("ok");
    assert!(
        !verify_stark_fri_envelope(&bytes).expect("semantic verification fixture must complete")
    );
}
#[test]
fn air_envelope_verifies_and_rejects_tampered_opening() {
    let params = StarkFriParamsV1 {
        version: 1,
        n_log2: 4,
        blowup_log2: 2,
        fold_arity: 2,
        queries: 2,
        merkle_arity: 2,
        domain_tag: "iroha:test:air".to_owned(),
    };
    let bytes = prove_stark_fri_air_envelope_bytes(
        params,
        "IROHA-TEST-STARK-AIR".to_owned(),
        "stark/fri/poseidon-x7-goldilocks-6x64-v1:air-test".to_owned(),
        test_digest(0x42),
    )
    .expect("air proof");
    assert!(
        verify_stark_fri_envelope(&bytes).expect("semantic verification fixture must complete")
    );
    let mut envelope: StarkVerifyEnvelopeV1 =
        norito::decode_from_bytes(&bytes).expect("decode air envelope");
    let air = envelope.proof.air.as_mut().expect("air section");
    air.openings[0].row[1] ^= 1;
    let tampered = norito::to_bytes(&envelope).expect("encode tampered air envelope");
    assert!(
        !verify_stark_fri_envelope(&tampered).expect("semantic verification fixture must complete")
    );
}
#[test]
fn explicit_composition_air_envelope_binds_caller_rows_to_fri_queries() {
    let params = StarkFriParamsV1 {
        version: 1,
        n_log2: 4,
        blowup_log2: 2,
        fold_arity: 2,
        queries: 2,
        merkle_arity: 2,
        domain_tag: "iroha:test:zero-composition-air".to_owned(),
    };
    let domain = 1_usize << usize::from(params.n_log2);
    let rows = (0..domain)
        .map(|index| {
            vec![
                u64::try_from(index).expect("index fits u64"),
                u64::try_from(index * 3 + 1).expect("sample value fits u64"),
                7,
            ]
        })
        .collect::<Vec<_>>();
    let composition_values = vec![0; domain];
    let public_digest = test_digest(0x55);
    let circuit_id = "stark/fri/custom-zero-air:test";
    let bytes = prove_stark_fri_air_envelope_from_rows_and_composition_values_bytes(
        params.clone(),
        "IROHA-TEST-ZERO-COMPOSITION-AIR".to_owned(),
        circuit_id.to_owned(),
        public_digest,
        rows.clone(),
        composition_values.clone(),
    )
    .expect("zero-composition AIR envelope");
    assert!(
        verify_stark_fri_air_envelope_from_rows_and_composition_values(
            &bytes,
            circuit_id,
            &public_digest,
            &rows,
            &composition_values,
        )
        .expect("semantic verification fixture must complete")
    );
    assert!(
        !verify_stark_fri_envelope(&bytes).expect("semantic verification fixture must complete")
    );
    let mut auxiliary_envelope: StarkVerifyEnvelopeV1 =
        norito::decode_from_bytes(&bytes).expect("decode zero-composition AIR envelope");
    attach_valid_auxiliary_composition_values(&mut auxiliary_envelope);
    let auxiliary_bytes =
        norito::to_bytes(&auxiliary_envelope).expect("encode auxiliary AIR envelope");
    assert!(
        !verify_stark_fri_air_envelope_from_rows_and_composition_values(
            &auxiliary_bytes,
            circuit_id,
            &public_digest,
            &rows,
            &composition_values,
        )
        .expect("semantic verification fixture must complete"),
        "caller-owned explicit AIR must reject auxiliary generic composition commitments"
    );
    let mut drifted_rows = rows.clone();
    drifted_rows[0][0] ^= 1;
    assert!(
        !verify_stark_fri_air_envelope_from_rows_and_composition_values(
            &bytes,
            circuit_id,
            &public_digest,
            &drifted_rows,
            &composition_values,
        )
        .expect("semantic verification fixture must complete")
    );
    let mut drifted_composition_values = composition_values.clone();
    drifted_composition_values[0] = 1;
    assert!(
        !verify_stark_fri_air_envelope_from_rows_and_composition_values(
            &bytes,
            circuit_id,
            &public_digest,
            &rows,
            &drifted_composition_values,
        )
        .expect("semantic verification fixture must complete")
    );
    assert!(
        !verify_stark_fri_air_envelope_from_rows_and_composition_values(
            &bytes,
            "stark/fri/custom-zero-air:other",
            &public_digest,
            &rows,
            &composition_values,
        )
        .expect("semantic verification fixture must complete")
    );
    let wrong_public_digest = test_digest(0x56);
    assert!(
        !verify_stark_fri_air_envelope_from_rows_and_composition_values(
            &bytes,
            circuit_id,
            &wrong_public_digest,
            &rows,
            &composition_values,
        )
        .expect("semantic verification fixture must complete")
    );
    let envelope: StarkVerifyEnvelopeV1 =
        norito::decode_from_bytes(&bytes).expect("decode zero-composition AIR envelope");
    let air = envelope.proof.air.as_ref().expect("AIR section");
    assert_eq!(air.trace_width, 3);
    assert_eq!(air.public_digest, public_digest);
    assert_eq!(air.openings.len(), usize::from(params.queries));
    assert_ne!(
        envelope.proof.commits.roots.first(),
        Some(&air.composition_root)
    );
    let mut malformed_opening_params = envelope.params.clone();
    malformed_opening_params.domain_tag = "iroha:test:bad domain tag".to_owned();
    assert_eq!(
        validate_stark_air_opening_commitment_roots_v1(
            &malformed_opening_params,
            air,
            air.openings.first().expect("AIR opening")
        )
        .expect_err("opening root replay must reject malformed STARK params"),
        "STARK opening commitment parameters invalid"
    );
    let mut impossible_opening_params = envelope.params.clone();
    impossible_opening_params.blowup_log2 = impossible_opening_params.n_log2 + 1;
    assert_eq!(
        validate_stark_air_opening_commitment_roots_v1(
            &impossible_opening_params,
            air,
            air.openings.first().expect("AIR opening")
        )
        .expect_err("opening root replay must reject impossible FRI geometry"),
        "STARK opening commitment parameters invalid"
    );
    let statement_commitment = stark_air_public_statement_commitment_v1(
        &params,
        &air.circuit_id,
        air.trace_width,
        &air.public_digest,
    )
    .expect("bind AIR public statement");
    let extra_query_roots = [air.trace_root, air.composition_root, statement_commitment];
    let mut tight_opening_limits = StarkVerifierLimits::default();
    tight_opening_limits.max_domain_log2 = params.n_log2.saturating_sub(1);
    assert_eq!(
        validate_stark_air_opening_commitment_roots_with_limits_v1(
            &params,
            air,
            air.openings.first().expect("AIR opening"),
            &tight_opening_limits,
        )
        .expect_err("opening root replay must honor caller domain limits"),
        "STARK opening commitment parameters invalid"
    );
    let mut tight_query_limits = StarkVerifierLimits::default();
    tight_query_limits.max_queries = envelope.proof.queries.len().saturating_sub(1);
    assert_eq!(
        validate_stark_fri_query_shape_and_indices_with_limits_v1(
            &envelope.params,
            &envelope.transcript_label,
            &envelope.proof.commits.roots,
            &extra_query_roots,
            &envelope.proof.queries,
            &tight_query_limits,
        )
        .expect_err("FRI query replay must honor caller query limits"),
        "FRI parameter/root/query shape mismatch"
    );
    let indices = validate_stark_fri_query_shape_and_indices_v1(
        &envelope.params,
        &envelope.transcript_label,
        &envelope.proof.commits.roots,
        &extra_query_roots,
        &envelope.proof.queries,
    )
    .expect("query shape replays");
    let mut tight_base_index_limits = StarkVerifierLimits::default();
    tight_base_index_limits.max_queries = envelope.proof.queries.len().saturating_sub(1);
    assert!(
            !verify_stark_fri_air_envelope_from_rows_and_composition_values_with_base_indices_with_limits(
                &bytes,
                &tight_base_index_limits,
                circuit_id,
                &public_digest,
                &rows,
                &composition_values,
                &indices,
            ).expect("semantic verification fixture must complete"),
            "explicit base-index AIR verifier must honor caller query limits"
        );
    for (opening_number, (opening, index)) in
        air.openings.iter().zip(indices.iter().copied()).enumerate()
    {
        assert_eq!(usize::try_from(opening.index).ok(), Some(index));
        assert_eq!(opening.row, rows[index]);
        assert_eq!(opening.next_row, rows[(index + 1) % domain]);
        assert_eq!(opening.composition_value, 0);
        validate_stark_air_opening_commitment_roots_v1(&params, air, opening)
            .expect("opening binds to trace and composition roots");
        validate_stark_air_opening_first_fri_value_v1(
            opening,
            index,
            envelope.proof.queries[opening_number]
                .first()
                .expect("query chain carries first decommitment"),
        )
        .expect("opening binds to first FRI layer");
    }
    let mut retargeted_opening_index = air.openings.first().expect("AIR opening").clone();
    let original_opening_index =
        usize::try_from(retargeted_opening_index.index).expect("opening index fits usize");
    retargeted_opening_index.index =
        u32::try_from((original_opening_index + 1) % domain).expect("domain fits u32");
    assert_eq!(
        validate_stark_air_opening_commitment_roots_v1(&params, air, &retargeted_opening_index)
            .expect_err("opening index retarget must fail before root replay"),
        "opening Merkle path index mismatch"
    );
    let mut retargeted_row_path = air.openings.first().expect("AIR opening").clone();
    retargeted_row_path.row_path.dirs[0] ^= 1;
    assert_eq!(
        validate_stark_air_opening_commitment_roots_v1(&params, air, &retargeted_row_path)
            .expect_err("row Merkle path retarget must fail before root replay"),
        "opening Merkle path index mismatch"
    );
    let mut retargeted_next_row_path = air.openings.first().expect("AIR opening").clone();
    retargeted_next_row_path.next_row_path.dirs[0] ^= 1;
    assert_eq!(
        validate_stark_air_opening_commitment_roots_v1(&params, air, &retargeted_next_row_path)
            .expect_err("next-row Merkle path retarget must fail before root replay"),
        "opening Merkle path index mismatch"
    );
    let mut retargeted_composition_path = air.openings.first().expect("AIR opening").clone();
    retargeted_composition_path.composition_path.dirs[0] ^= 1;
    assert_eq!(
        validate_stark_air_opening_commitment_roots_v1(&params, air, &retargeted_composition_path)
            .expect_err("composition Merkle path retarget must fail before root replay"),
        "opening Merkle path index mismatch"
    );
    let mut tampered = envelope;
    let tampered_air = tampered.proof.air.as_mut().expect("AIR section");
    tampered_air.openings[0].row[0] ^= 1;
    let tampered_opening = tampered_air.openings[0].clone();
    assert_eq!(
        validate_stark_air_opening_commitment_roots_v1(&params, tampered_air, &tampered_opening)
            .expect_err("tampered caller row must not match trace root"),
        "row Merkle root mismatch"
    );
    let mut noncanonical_composition = vec![0; domain];
    noncanonical_composition[0] = MOD_P_U64;
    assert!(matches!(
        prove_stark_fri_air_envelope_from_rows_and_composition_values_bytes(
            params.clone(),
            "IROHA-TEST-ZERO-COMPOSITION-AIR".to_owned(),
            "stark/fri/custom-zero-air:test".to_owned(),
            public_digest,
            rows.clone(),
            noncanonical_composition.clone(),
        )
        .expect_err("non-canonical composition values must be rejected"),
        StarkProofProductionError::Input(message) if message == "STARK AIR composition contains non-canonical field element"
    ));
    assert!(
        stark_merkle_root_from_field_values_v1(&params, &noncanonical_composition).is_none(),
        "explicit AIR composition roots must reject non-canonical field elements"
    );
    assert!(
        !verify_stark_fri_air_envelope_from_rows_and_composition_values(
            &bytes,
            circuit_id,
            &public_digest,
            &rows,
            &noncanonical_composition,
        )
        .expect("semantic verification fixture must complete"),
        "explicit AIR verification must reject non-canonical caller composition values"
    );
    let mut noncanonical_rows = rows;
    noncanonical_rows[domain - 1][1] = MOD_P_U64;
    assert!(matches!(
        prove_stark_fri_air_envelope_from_rows_and_composition_values_bytes(
            params.clone(),
            "IROHA-TEST-ZERO-COMPOSITION-AIR".to_owned(),
            "stark/fri/custom-zero-air:test".to_owned(),
            public_digest,
            noncanonical_rows.clone(),
            composition_values.clone(),
        )
        .expect_err("non-canonical AIR rows must be rejected"),
        StarkProofProductionError::Input(message) if message == "STARK AIR row contains non-canonical field element"
    ));
    assert!(
        stark_air_trace_root_from_rows_v1(&params, &noncanonical_rows).is_none(),
        "explicit AIR trace roots must reject non-canonical row field elements"
    );
    assert!(
        !verify_stark_fri_air_envelope_from_rows_and_composition_values(
            &bytes,
            circuit_id,
            &public_digest,
            &noncanonical_rows,
            &composition_values,
        )
        .expect("semantic verification fixture must complete"),
        "explicit AIR verification must reject non-canonical caller rows"
    );
}
#[test]
fn air_prover_rejects_more_queries_than_domain() {
    let params = StarkFriParamsV1 {
        version: 1,
        n_log2: 1,
        blowup_log2: 1,
        fold_arity: 2,
        queries: 3,
        merkle_arity: 2,
        domain_tag: "iroha:test:repeated-air-query".to_owned(),
    };
    let err = prove_stark_fri_air_envelope_bytes(
        params,
        "IROHA-TEST-REPEATED-AIR-QUERY".to_owned(),
        "stark/fri/custom-repeated-query-air:test".to_owned(),
        test_digest(0x71),
    )
    .expect_err("pigeonhole-small AIR query schedule must not emit proof bytes");
    assert!(
        err.to_string()
            .contains("STARK query count exceeds domain size"),
        "unexpected impossible-query rejection: {err}"
    );
}
#[test]
fn air_envelope_skips_repeated_transcript_query_indices() {
    let mut params = StarkFriParamsV1 {
        version: 1,
        n_log2: 3,
        blowup_log2: 1,
        fold_arity: 2,
        queries: 4,
        merkle_arity: 2,
        domain_tag: String::new(),
    };
    let domain = 1_usize << usize::from(params.n_log2);
    let values = vec![Fq::zero(); domain];
    for nonce in 0_u32..1024 {
        params.domain_tag = format!("iroha:test:skip-repeated-query:{nonce}");
        let envelope = synthesize_stark_fri_envelope_from_values(
            params.clone(),
            "IROHA-TEST-SKIP-REPEATED-AIR-QUERY".to_owned(),
            values.clone(),
            &[],
        )
        .expect("duplicate-free query schedule must synthesize");
        let raw_indices = (0..usize::from(params.queries))
            .map(|query_number| {
                derive_query_index(
                    &envelope.transcript_label,
                    &params,
                    &envelope.proof.commits.roots,
                    query_number,
                )
                .expect("query index")
                    % domain
            })
            .collect::<Vec<_>>();
        if !raw_indices
            .iter()
            .enumerate()
            .any(|(index, sampled)| raw_indices[..index].contains(sampled))
        {
            continue;
        }
        let replayed_indices = validate_stark_fri_query_shape_and_indices_v1(
            &params,
            &envelope.transcript_label,
            &envelope.proof.commits.roots,
            &[],
            &envelope.proof.queries,
        )
        .expect("colliding raw transcript samples are mapped without replacement");
        assert_eq!(replayed_indices.len(), usize::from(params.queries));
        assert!(
            !replayed_indices
                .iter()
                .enumerate()
                .any(|(index, sampled)| replayed_indices[..index].contains(sampled)),
            "replayed transcript query indices must be duplicate-free"
        );
        assert_ne!(
            raw_indices, replayed_indices,
            "fixture must exercise collision skipping"
        );
        let public_digest = test_digest(0x73);
        let circuit_id = "stark/fri/custom-skip-repeated-query-air:test";
        let rows = (0..domain)
            .map(|index| {
                stark_air_row(index, &public_digest).expect("build duplicate-skip AIR row")
            })
            .collect::<Vec<_>>();
        let composition_values = (0..domain)
            .map(|index| {
                stark_air_composition_value(
                    index,
                    domain,
                    &public_digest,
                    &rows[index],
                    &rows[(index + 1) % domain],
                )
                .expect("build duplicate-skip AIR composition value")
            })
            .collect::<Vec<_>>();
        let composition_values_u64 = composition_values
            .iter()
            .map(|value| value.0)
            .collect::<Vec<_>>();
        let bytes = prove_stark_fri_air_envelope_from_rows_and_composition_values_fq_bytes(
            params.clone(),
            "IROHA-TEST-SKIP-REPEATED-AIR-QUERY".to_owned(),
            circuit_id.to_owned(),
            public_digest,
            rows.clone(),
            composition_values.clone(),
            None,
        )
        .expect("colliding raw samples must still produce a duplicate-free AIR envelope");
        assert!(
            verify_stark_fri_air_envelope_from_rows_and_composition_values(
                &bytes,
                circuit_id,
                &public_digest,
                &rows,
                &composition_values_u64,
            )
            .expect("semantic verification fixture must complete")
        );
        let mut duplicate_opening: StarkVerifyEnvelopeV1 =
            norito::decode_from_bytes(&bytes).expect("decode duplicate-free AIR envelope");
        duplicate_opening.proof.queries[1] = duplicate_opening.proof.queries[0].clone();
        let first_opening = duplicate_opening
            .proof
            .air
            .as_ref()
            .expect("duplicate-free AIR section")
            .openings[0]
            .clone();
        duplicate_opening
            .proof
            .air
            .as_mut()
            .expect("duplicate-free AIR section")
            .openings[1] = first_opening;
        let duplicate_opening_bytes =
            norito::to_bytes(&duplicate_opening).expect("encode duplicate AIR opening");
        assert!(
            !verify_stark_fri_air_envelope_from_rows_and_composition_values(
                &duplicate_opening_bytes,
                circuit_id,
                &public_digest,
                &rows,
                &composition_values_u64,
            )
            .expect("semantic verification fixture must complete"),
            "duplicate raw query/opening replay must not satisfy skipped transcript samples"
        );
        return;
    }
    panic!("failed to find small-domain transcript query collision fixture");
}
// Full-bootstrap fixtures and remaining rejection profiles stay in this lexical module.
include!("bfv_full_bootstrap_tests.rs");

#[test]
fn composition_producer_retains_input_and_original_self_verifier_refusal() {
    let params = StarkFriParamsV1 {
        version: 1,
        n_log2: 4,
        blowup_log2: 2,
        fold_arity: 2,
        queries: 2,
        merkle_arity: 2,
        domain_tag: "iroha:test:composition-original-owner".to_owned(),
    };
    let invalid = prove_stark_fri_composition_envelope_bytes(
        params.clone(),
        "IROHA-TEST-STARK".to_owned(),
        MOD_P_U64,
        0,
        vec![],
    )
    .expect_err("non-canonical input must reject before proving");
    assert!(matches!(invalid, StarkProofProductionError::Input(message)
        if message == "invalid STARK constant"));
    let zero = norito::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, 0, usize::MAX);
    let refused = norito::with_decode_limits_scope(zero, || {
        prove_stark_fri_composition_envelope_bytes(
            params.clone(),
            "IROHA-TEST-STARK".to_owned(),
            7,
            0,
            vec![],
        )
    })
    .expect_err("the actual self-verifier must retain its enclosing reader refusal");
    let StarkProofProductionError::Deferred(original) = refused else {
        panic!("lost original self-verifier owner: {refused}");
    };
    assert_eq!(
        original.kind(),
        iroha_plonk::verification_attempt::VerificationRefusalKind::Decode(
            norito::core::DecodeLocalRefusalKind::EnclosingLimit
        )
    );
    let borrowed = original
        .decode_refusal()
        .expect("original self-verifier reader refusal")
        .clone();
    let moved = original
        .into_decode_refusal()
        .expect("single original codec owner");
    assert_eq!(moved, borrowed);
    let bytes = prove_stark_fri_composition_envelope_bytes(
        params,
        "IROHA-TEST-STARK".to_owned(),
        7,
        0,
        vec![],
    )
    .expect("fresh producer retries after the enclosing scope retires");
    let envelope: StarkVerifyEnvelopeV1 = norito::decode_from_bytes(&bytes).unwrap();
    assert!(envelope.proof.air.is_some());
    assert!(envelope.proof.commits.comp_root.is_some());
    assert_eq!(
        envelope.proof.comp_values.as_ref().unwrap().len(),
        envelope.proof.queries.len()
    );
}
