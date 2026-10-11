//! Replay the independent snark-verifier corpus without linking the retired stack.
//!
//! Historical transcript framing is available only in unit tests. The
//! captured native descriptor and original key/proof bytes stay reviewable after
//! vendor retirement. A cheap result is checked against G/u and then decided.

use ff::{Field, PrimeField};
use group::GroupEncoding;
use iroha_pasta::{Ep, Eq, PastaCurve, msm::MemoryBudget, poseidon::PoseidonField};
use norito::json::Value;
use sha2::{Digest, Sha256};

use super::accumulate_succinct_oracle;
use crate::{
    keys::{DescriptorBinding, VerifyingKey},
    pcs::ipa::{PinnedParams, accumulator::PendingAccumulator},
};

fn bytes(value: &Value) -> Vec<u8> {
    let text = value.as_str().expect("hex string");
    assert!(text.len().is_multiple_of(2));
    text.as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let pair = core::str::from_utf8(pair).expect("ASCII hex");
            let byte = u8::from_str_radix(pair, 16).expect("hex byte");
            assert_eq!(pair, format!("{byte:02x}"));
            byte
        })
        .collect()
}

fn scalar<F: PrimeField<Repr = [u8; 32]>>(value: &Value) -> F {
    Option::<F>::from(F::from_repr(bytes(value).try_into().expect("scalar width")))
        .expect("canonical scalar")
}

fn replay<C: PastaCurve>(curve: &str)
where
    C::Base: PoseidonField,
    C::ScalarExt: PoseidonField,
{
    let document: Value = norito::json::from_str(include_str!(
        "../../../../fixtures/native_prover/succinct_v1.json"
    ))
    .expect("captured corpus");
    assert_eq!(
        document["format"].as_str(),
        Some("iroha.snark_verifier.succinct.v1")
    );
    let cases = document["cases"].as_array().expect("cases");
    assert_eq!(cases.len(), 8);
    let identities = cases
        .iter()
        .map(|case| {
            (
                case["curve"].as_str().expect("curve"),
                case["family"].as_str().expect("family"),
                case["k"].as_u64().expect("k"),
                case["seed_byte"].as_u64().expect("seed"),
            )
        })
        .collect::<std::collections::BTreeSet<_>>();
    let expected = ["eq", "ep"]
        .into_iter()
        .flat_map(|curve| {
            [("Sigma", 6), ("Wide", 8)]
                .into_iter()
                .flat_map(move |(family, k)| {
                    [42, 43]
                        .into_iter()
                        .map(move |seed| (curve, family, k, seed))
                })
        })
        .collect();
    assert_eq!(identities, expected, "exact independent source matrix");
    let selected = cases
        .iter()
        .filter(|case| case["curve"].as_str() == Some(curve))
        .collect::<Vec<_>>();
    assert_eq!(selected.len(), 4);
    for case in selected {
        let k = u32::try_from(case["k"].as_u64().expect("k")).expect("bounded k");
        let params = PinnedParams::<C>::derive(k).expect("pinned parameters");
        let binding =
            DescriptorBinding::decode(&bytes(&case["descriptor"])).expect("captured descriptor");
        let vk = VerifyingKey::<C>::read(&bytes(&case["verifying_key"]), &binding)
            .expect("captured original key");
        let proof = bytes(&case["proof"]);
        assert_eq!(
            format!("{:x}", Sha256::digest(&proof)),
            case["proof_sha256"].as_str().expect("proof hash")
        );
        let instances: Vec<Vec<C::ScalarExt>> = case["instances"]
            .as_array()
            .expect("columns")
            .iter()
            .map(|column| {
                column
                    .as_array()
                    .expect("values")
                    .iter()
                    .map(scalar)
                    .collect()
            })
            .collect();
        let repr = scalar::<C::ScalarExt>(&case["transcript_repr"]);
        let (claim, native_challenges) = accumulate_succinct_oracle(
            &params,
            &binding,
            &vk,
            &instances,
            &proof,
            MemoryBudget::DEFAULT,
            repr,
        )
        .expect("cheap verification");
        assert_eq!(claim.g().to_bytes().as_ref(), bytes(&case["g"]));
        let rounds = case["u"]
            .as_array()
            .expect("rounds")
            .iter()
            .map(scalar::<C::ScalarExt>)
            .collect::<Vec<_>>();
        assert_eq!(claim.challenges(), rounds);
        assert_eq!(rounds.len(), k as usize);
        let challenges = case["challenges"]
            .as_array()
            .expect("all challenges")
            .iter()
            .map(scalar::<C::ScalarExt>)
            .collect::<Vec<_>>();
        assert_eq!(challenges.len(), k as usize + 11);
        assert_eq!(native_challenges, challenges, "every native squeeze");
        assert_eq!(&challenges[challenges.len() - rounds.len()..], rounds);
        let mut tape = Vec::new();
        for challenge in &challenges {
            tape.extend_from_slice(challenge.to_repr().as_ref());
        }
        tape.extend_from_slice(&bytes(&case["g"]));
        for challenge in &rounds {
            tape.extend_from_slice(challenge.to_repr().as_ref());
        }
        assert_eq!(
            format!("{:x}", Sha256::digest(&tape)),
            case["tape_sha256"].as_str().expect("tape hash")
        );
        claim
            .clone()
            .decide(&params, MemoryBudget::DEFAULT)
            .expect("complete generator decision");

        // A valid cheap proof does not authorize dropping the generator obligation.
        // Alter a still-canonical nonzero round in its retained claim; deciding it
        // must fail, independently of the proof parsing and succinct equation.
        let mut forged_claim = claim.to_bytes();
        let changed_round = rounds[0] + C::ScalarExt::ONE;
        assert!(!bool::from(changed_round.is_zero()));
        forged_claim[66..98].copy_from_slice(changed_round.to_repr().as_ref());
        let forged_claim =
            PendingAccumulator::<C>::from_bytes(&forged_claim).expect("well-formed changed claim");
        assert!(forged_claim.decide(&params, MemoryBudget::DEFAULT).is_err());

        let mut wrong_instances = instances.clone();
        wrong_instances[0][0] += C::ScalarExt::ONE;
        let mut altered = proof.clone();
        altered[32] ^= 1;
        let mut suffix = proof.clone();
        let last = suffix.len() - 32;
        suffix[last..].copy_from_slice(params.params().g()[0].to_bytes().as_ref());
        let mut trailing = proof.clone();
        trailing.push(0);
        for (label, instance, proof) in [
            ("instance", wrong_instances, proof.clone()),
            ("proof", instances.clone(), altered),
            ("suffix", instances.clone(), suffix),
            ("trailing", instances.clone(), trailing),
            (
                "truncated",
                instances.clone(),
                proof[..proof.len() - 1].to_vec(),
            ),
        ] {
            let result = accumulate_succinct_oracle(
                &params,
                &binding,
                &vk,
                &instance,
                &proof,
                MemoryBudget::DEFAULT,
                repr,
            );
            assert!(
                result.ok().is_none_or(|(pending, _)| pending
                    .decide(&params, MemoryBudget::DEFAULT)
                    .is_err()),
                "{label}"
            );
        }
    }
}

#[test]
fn captured_snark_succinct_pallas_decides_and_rejects_mutations() {
    replay::<Ep>("ep");
}
#[test]
fn captured_snark_succinct_vesta_decides_and_rejects_mutations() {
    replay::<Eq>("eq");
}
