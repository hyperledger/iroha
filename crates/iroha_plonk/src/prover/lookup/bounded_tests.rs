//! Public-table eligibility and seeded proof parity against full-width commitments.

use super::*;
use crate::{
    cs::descriptor::ExprNodeV1,
    prover::{AllTerms, Mode, ProverConfig, ProverRandomness, Witness, WitnessInput, prove},
    test_circuits::{CHOICES, K, Lookups, Setup, setup},
};
use ff::Field;
use iroha_pasta::{Ep, Eq, poseidon::PoseidonField};

const CIRCUIT: Lookups = Lookups {
    rows: 9,
    tamper: None,
    out_of_range: false,
    offset: 0,
};

#[test]
fn eligibility_requires_an_unrotated_single_public_fixed_table() {
    let setup = setup::<Ep, _>(&CIRCUIT, CHOICES[1]);
    let mut descriptor = setup.pk.binding().descriptor().clone();
    let fixed = setup.pk.fixed_values();
    assert_eq!(
        public_table_bits(&descriptor, fixed, 0, None).unwrap(),
        None
    );
    assert_eq!(
        public_table_bits(&descriptor, fixed, 1, None).unwrap(),
        Some(4)
    );
    assert_eq!(
        public_table_bits(&descriptor, fixed, 2, None).unwrap(),
        None
    );
    let ExprNodeV1::Fixed(query) = descriptor.lookups[1].tables[0][0] else {
        panic!("singleton fixed table")
    };
    let query = usize::try_from(query).unwrap();
    let column = usize::try_from(descriptor.fixed_queries[query].column).unwrap();
    let mut values = fixed.to_vec();
    // Include even an unused public row; never infer width from the witness.
    *values[column].last_mut().unwrap() = iroha_pasta::Fq::from(1_u64 << 15);
    assert_eq!(
        public_table_bits(&descriptor, &values, 1, None).unwrap(),
        Some(16)
    );
    *values[column].last_mut().unwrap() = -iroha_pasta::Fq::ONE;
    assert_eq!(
        public_table_bits(&descriptor, &values, 1, None).unwrap(),
        None
    );
    values[column].fill(iroha_pasta::Fq::ZERO);
    assert_eq!(
        public_table_bits(&descriptor, &values, 1, None).unwrap(),
        Some(0)
    );
    descriptor.fixed_queries[query].rotation = 1;
    assert_eq!(
        public_table_bits(&descriptor, fixed, 1, None).unwrap(),
        None
    );
    descriptor.fixed_queries[query].rotation = 0;
    descriptor.lookups[1].tables[0].push(ExprNodeV1::Negated);
    assert_eq!(
        public_table_bits(&descriptor, fixed, 1, None).unwrap(),
        None
    );
    let cancellation = CancellationToken::new();
    cancellation.cancel();
    assert!(public_table_bits(&descriptor, fixed, 1, Some(&cancellation)).is_err());
}

/// Honest membership/permutation with the pre-optimization commitment route.
/// The default opt-out is shared with malicious-prover verifier tests.
struct FullWidthReference;
impl<F: PastaField> LookupPermutation<F> for FullWidthReference {
    fn permute<R: RngCore>(
        &mut self,
        input: &[F],
        table: &[F],
        usable_rows: usize,
        n: usize,
        lookup: usize,
        rng: &mut R,
    ) -> Result<(Vec<F>, Vec<F>), ProverError> {
        permute(input, table, usable_rows, n, lookup, rng)
    }
}

fn proof_parity<C: PastaCurve>()
where
    C::ScalarExt: PoseidonField,
    C::Base: PoseidonField,
{
    for profile in 0..=CHOICES.len() {
        let setup = CHOICES.get(profile).map_or_else(
            || {
                let params = crate::pcs::ipa::PinnedParams::<C>::derive(K).unwrap();
                let mut config = crate::keys::KeygenConfigV2::pipa_r(Vec::new());
                config.coset_cache = crate::keys::CosetCachePolicy::OnDemand;
                let pk = crate::keys::keygen_pk_v2(&params, &CIRCUIT, &config).unwrap();
                Setup { params, pk }
            },
            |choice| setup::<C, _>(&CIRCUIT, *choice),
        );
        assert_eq!(
            public_table_bits(
                setup.pk.binding().descriptor(),
                setup.pk.fixed_values(),
                1,
                None
            )
            .unwrap(),
            Some(4)
        );
        let witness = Witness::from_circuit(&setup.pk, &CIRCUIT, &[]).unwrap();
        let reference = prove(
            &setup.params,
            &setup.pk,
            WitnessInput::Borrowed(&witness),
            ProverRandomness::fixed_seed_for_tests([31; 32]),
            ProverConfig::default(),
            Mode {
                oracle: false,
                transcript_repr: *setup.pk.vk().transcript_repr(),
            },
            &mut FullWidthReference,
            &AllTerms,
        )
        .unwrap();
        assert_eq!(setup.verify(&[], &reference), Ok(()));
        for threads in [1, 4] {
            let pool = rayon::ThreadPoolBuilder::new()
                .num_threads(threads)
                .build()
                .unwrap();
            let bounded = pool.install(|| setup.prove(&CIRCUIT, &[], 31)).unwrap();
            assert_eq!(
                bounded, reference,
                "same seed, {threads} workers, profile={profile}"
            );
            assert_eq!(setup.verify(&[], &bounded), Ok(()));
        }
    }
}

#[test]
fn complete_seeded_proofs_equal_the_full_width_reference_on_both_curves() {
    proof_parity::<Ep>();
    proof_parity::<Eq>();
}
