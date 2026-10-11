//! Fresh native re-proving of the independent Sigma/Wide source corpus.
//!
//! The source capture is produced by the retiring independent implementation.
//! Native circuits regenerate every witness, descriptor and key; only historical
//! transcript representatives and expected bytes are supplied by the corpus.

use ff::Field;
use iroha_pasta::{Ep, Eq, PastaCurve, PastaField, msm::MemoryBudget, poseidon::PoseidonField};
use norito::json::Value;
use sha2::{Digest, Sha256};

use crate::{
    cs::{ProofSuffixV1, TranscriptV1},
    frontend::Circuit,
    keys::{DescriptorBinding, KeygenConfig, keygen_pk},
    pcs::ipa::PinnedParams,
    prover::{ProverConfig, ProverRandomness, Witness, create_proof_oracle},
    verifier::verify_full_oracle,
};

#[path = "captured_goldens/circuits.rs"]
mod circuits;
use circuits::{SigmaCircuit, WideCircuit};

fn bytes(value: &Value) -> Vec<u8> {
    let text = value.as_str().expect("hex string");
    assert!(text.len().is_multiple_of(2));
    text.as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let pair = core::str::from_utf8(pair).expect("ASCII hex");
            let value = u8::from_str_radix(pair, 16).expect("hex byte");
            assert_eq!(pair, format!("{value:02x}"));
            value
        })
        .collect()
}

fn scalar<F: PastaField>(value: &Value) -> F {
    Option::<F>::from(F::from_repr(bytes(value).try_into().expect("scalar width")))
        .expect("canonical field value")
}

fn corpus() -> Value {
    let document: Value = norito::json::from_str(include_str!(
        "../../../fixtures/native_prover/golden_sources_v1.json"
    ))
    .expect("independent golden source corpus");
    assert_eq!(
        document["format"].as_str(),
        Some("iroha.native_prover.golden_sources.v1")
    );
    assert_eq!(
        document["original_circuit_source_sha256"].as_str(),
        Some("f17349f2880f818be27f6508950cfaf909354b4a14e3f55bf7375a0fa3d03129")
    );
    let cases = document["cases"].as_array().expect("cases");
    let actual = cases
        .iter()
        .map(|case| {
            (
                case["curve"].as_str().expect("curve"),
                case["family"].as_str().expect("family"),
                case["k"].as_u64().expect("domain"),
                case["profile"].as_str().expect("profile"),
                case["seed_byte"].as_u64().expect("seed"),
            )
        })
        .collect::<std::collections::BTreeSet<_>>();
    let mut expected = std::collections::BTreeSet::new();
    for curve in ["ep", "eq"] {
        for (family, domains) in [("sigma", &[6, 9, 11][..]), ("wide", &[8, 10][..])] {
            for &k in domains {
                for profile in ["blake", "poseidon"] {
                    for seed in [42, 43] {
                        expected.insert((curve, family, k, profile, seed));
                    }
                }
            }
        }
        expected.insert((curve, "wide", 13, "blake", 0xa7));
    }
    assert_eq!(cases.len(), 42, "complete original golden matrix");
    assert_eq!(actual, expected, "no missing, duplicate or unknown source");
    document
}

fn replay_circuit<C: PastaCurve, Ci: Circuit<C::ScalarExt> + Sync>(
    circuit: &Ci,
    public: Vec<C::ScalarExt>,
    cases: &[&Value],
) where
    C::ScalarExt: PoseidonField,
    C::Base: PoseidonField,
{
    let first = cases.first().expect("nonempty source group");
    let k = u32::try_from(first["k"].as_u64().expect("k")).expect("bounded k");
    let params = PinnedParams::<C>::derive(k).expect("pinned parameters");
    let profile = first["profile"].as_str().expect("profile");
    let mut config = match profile {
        "blake" => KeygenConfig::new(TranscriptV1::Blake2bChallenge255),
        "poseidon" => {
            let mut config = KeygenConfig::new(TranscriptV1::KagemushaPoseidonRp57);
            config.proof_suffix = ProofSuffixV1::FoldedGenerator;
            config
        }
        _ => panic!("unknown fixed profile"),
    };
    let binding = DescriptorBinding::decode(&bytes(&first["descriptor"]))
        .expect("original canonical descriptor");
    config.compress_selectors = binding.descriptor().selectors.compress;
    let instances = vec![public];
    let pools = [1, 2, 4, 7].map(|threads| {
        rayon::ThreadPoolBuilder::new()
            .num_threads(threads)
            .build()
            .expect("fixed worker pool")
    });
    for pool in &pools {
        pool.install(|| {
            let pk = keygen_pk(&params, &circuit.without_witnesses(), &config)
                .expect("native source key generation");
            assert_eq!(pk.binding().encoded(), bytes(&first["descriptor"]));
            assert_eq!(pk.vk().to_bytes(), bytes(&first["verifying_key"]));
            let witness = Witness::from_circuit(&pk, circuit, &instances)
                .expect("native circuit and key correspond exactly");
            for case in cases {
                assert_eq!(case["descriptor"], first["descriptor"]);
                assert_eq!(case["verifying_key"], first["verifying_key"]);
                assert_eq!(case["transcript_repr"], first["transcript_repr"]);
                let original_instances = case["instances"]
                    .as_array()
                    .expect("columns")
                    .iter()
                    .map(|column| {
                        column
                            .as_array()
                            .expect("column values")
                            .iter()
                            .map(scalar::<C::ScalarExt>)
                            .collect::<Vec<_>>()
                    })
                    .collect::<Vec<_>>();
                assert_eq!(
                    instances, original_instances,
                    "native witness public values"
                );
                let expected = bytes(&case["proof"]);
                assert_eq!(
                    format!("{:x}", Sha256::digest(&expected)),
                    case["proof_sha256"].as_str().expect("proof hash")
                );
                let seed = u8::try_from(case["seed_byte"].as_u64().expect("seed"))
                    .expect("single-byte seed");
                let repr = scalar::<C::ScalarExt>(&case["transcript_repr"]);
                let proof = create_proof_oracle(
                    &params,
                    &pk,
                    &witness,
                    ProverRandomness::fixed_seed_for_tests([seed; 32]),
                    ProverConfig::default(),
                    repr,
                )
                .expect("fresh native proof");
                assert_eq!(
                    proof, expected,
                    "exact independent bytes at every worker count"
                );
                let verify = |values: &[Vec<C::ScalarExt>], candidate: &[u8]| {
                    verify_full_oracle(
                        &params,
                        pk.binding(),
                        pk.vk(),
                        values,
                        candidate,
                        MemoryBudget::DEFAULT,
                        repr,
                    )
                };
                verify(&instances, &proof).expect("every generated proof verifies");
                let mut changed = proof.clone();
                changed[0] ^= 1;
                assert!(verify(&instances, &changed).is_err());
                assert!(verify(&instances, &proof[..proof.len() - 1]).is_err());
                let mut extended = proof.clone();
                extended.push(0);
                assert!(verify(&instances, &extended).is_err());
                let mut wrong_instances = instances.clone();
                wrong_instances[0][0] += C::ScalarExt::ONE;
                assert!(verify(&wrong_instances, &proof).is_err());
            }
        });
    }
}

fn replay<C: PastaCurve>(curve: &str)
where
    C::ScalarExt: PoseidonField,
    C::Base: PoseidonField,
{
    let document = corpus();
    let mut groups = std::collections::BTreeMap::new();
    for case in document["cases"].as_array().expect("cases") {
        if case["curve"].as_str() != Some(curve) {
            continue;
        }
        let family = case["family"].as_str().expect("family");
        let k = u32::try_from(case["k"].as_u64().expect("k")).expect("bounded k");
        let profile = case["profile"].as_str().expect("profile");
        groups
            .entry((family, k, profile))
            .or_insert_with(Vec::new)
            .push(case);
    }
    assert_eq!(groups.len(), 11);
    for ((family, k, _profile), cases) in groups {
        match family {
            "sigma" => {
                let circuit = SigmaCircuit::<C::ScalarExt>::new(k);
                let public = circuit.public();
                replay_circuit::<C, _>(&circuit, public, &cases);
            }
            "wide" => {
                let circuit = WideCircuit::<C::ScalarExt>::new(k);
                let public = circuit.public();
                replay_circuit::<C, _>(&circuit, public, &cases);
            }
            _ => panic!("unknown original family"),
        }
    }
}

#[test]
fn fresh_native_pallas_proofs_reproduce_every_independent_golden() {
    replay::<Ep>("ep");
}

#[test]
fn fresh_native_vesta_proofs_reproduce_every_independent_golden() {
    replay::<Eq>("eq");
}
