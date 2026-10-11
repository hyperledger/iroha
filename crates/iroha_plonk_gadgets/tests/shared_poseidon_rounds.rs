//! Aligned Poseidon lanes share only their four round selectors. Native
//! digests, complete cell binding, asymmetric schedule rejection and real
//! proofs cover both Pasta fields; ordinary lane configuration is unchanged.

use core::marker::PhantomData;

use ff::Field as _;
use iroha_pasta::{
    Ep, Eq, Fp, Fq, PastaCurve,
    msm::MemoryBudget,
    poseidon::{PoseidonField, hash_with_domain},
};
use iroha_plonk::{
    ProverConfig, ProverRandomness,
    check::{CheckMode, check_circuit},
    cs::{Column, ConstraintSystem, Instance, TranscriptV1},
    frontend::{Circuit, Error, Layouter, SimpleFloorPlanner, synthesize},
    keys::{CosetCachePolicy, KeygenConfig, keygen_pk},
    pcs::ipa::PinnedParams,
    prove_circuit, verify_full,
};
use iroha_plonk_gadgets::{
    poseidon::{
        AbsorbInput, Pow5Columns, RoundConstantColumns, SharedRoundSelectors, SpongeChip,
        SpongeConfig,
    },
    tamper::undetected_tampers,
};

const K: u32 = 8;

#[derive(Clone, Debug, Default)]
struct Shape {
    shared: bool,
    arities: Vec<Vec<usize>>,
}

#[derive(Clone, Debug)]
struct Lanes<F> {
    shape: Shape,
    field: PhantomData<F>,
}

#[derive(Clone, Debug)]
struct Config<F> {
    lanes: Vec<SpongeConfig<F>>,
    instance: Column<Instance>,
}

fn domain(lane: usize) -> u64 {
    1_000 + lane as u64
}

fn inputs<F: PoseidonField>(lane: usize, hash: usize, arity: usize) -> Vec<F> {
    (0..arity)
        .map(|index| F::from((10 * lane + 5 * hash + index + 1) as u64))
        .collect()
}

impl<F: PoseidonField> Lanes<F> {
    fn new(shared: bool, arities: Vec<Vec<usize>>) -> Self {
        Self {
            shape: Shape { shared, arities },
            field: PhantomData,
        }
    }

    fn public(&self) -> Vec<F> {
        self.shape
            .arities
            .iter()
            .enumerate()
            .flat_map(|(lane, arities)| {
                arities.iter().enumerate().map(move |(hash, arity)| {
                    hash_with_domain(domain(lane), &inputs::<F>(lane, hash, *arity))
                })
            })
            .collect()
    }
}

impl<F: PoseidonField> Circuit<F> for Lanes<F> {
    type Config = Config<F>;
    type FloorPlanner = SimpleFloorPlanner;
    type Params = Shape;

    fn without_witnesses(&self) -> Self {
        self.clone()
    }
    fn params(&self) -> Shape {
        self.shape.clone()
    }
    fn configure(meta: &mut ConstraintSystem<F>) -> Config<F> {
        Self::configure_with_params(meta, Shape::default())
    }
    fn configure_with_params(meta: &mut ConstraintSystem<F>, params: Shape) -> Config<F> {
        let constants = meta.fixed_column();
        meta.enable_constant(constants);
        let round_constants = RoundConstantColumns::allocate(meta);
        let shared = params.shared.then(|| SharedRoundSelectors::allocate(meta));
        let lanes = (0..params.arities.len())
            .map(|lane| {
                let columns = Pow5Columns::allocate(meta);
                let folded = [(domain(lane), 2), (domain(lane), 3), (domain(lane), 4)];
                match shared {
                    Some(shared) => SpongeConfig::configure_with_shared_round_selectors(
                        meta,
                        columns,
                        round_constants,
                        &folded,
                        shared,
                    ),
                    None => SpongeConfig::configure(meta, columns, round_constants, &folded),
                }
            })
            .collect();
        let instance = meta.instance_column(params.arities.iter().map(Vec::len).sum());
        meta.enable_equality(instance);
        Config { lanes, instance }
    }
    fn synthesize(&self, config: Config<F>, mut layouter: impl Layouter<F>) -> Result<(), Error> {
        let outputs = layouter.assign_region(
            || "shared rounds",
            |mut region| {
                let mut outputs = Vec::new();
                for (lane, lane_config) in config.lanes.iter().enumerate() {
                    let mut sponge = SpongeChip::new(lane_config.clone());
                    for (hash, arity) in self.shape.arities[lane].iter().enumerate() {
                        let values = inputs::<F>(lane, hash, *arity);
                        let absorb: Vec<_> =
                            values.into_iter().map(AbsorbInput::Constant).collect();
                        outputs.push(sponge.hash(&mut region, domain(lane), &absorb)?.cell());
                    }
                }
                Ok(outputs)
            },
        )?;
        for (row, output) in outputs.into_iter().enumerate() {
            layouter.constrain_instance(output, config.instance, row)?;
        }
        Ok(())
    }
}

fn satisfied<F: PoseidonField>(circuit: &Lanes<F>) -> bool {
    check_circuit(circuit, K, &[circuit.public()], CheckMode::Strict)
        .expect("check")
        .is_satisfied()
}

fn fixed_columns<F: PoseidonField>(circuit: &Lanes<F>) -> usize {
    let synthesis = synthesize(circuit, K, Some(&[circuit.public()])).expect("synthesis");
    synthesis
        .cs
        .finalize(synthesis.tables.selectors(), true)
        .expect("finalize")
        .constraint_system()
        .num_fixed_columns()
}

fn check_aligned<F: PoseidonField>() {
    // The same round schedules can carry different domains, input values
    // and folded prefixes. Arities 2 and 3 both use two permutations.
    let arities = vec![
        vec![2, 3],
        vec![3, 2],
        vec![2, 2],
        vec![3, 3],
        vec![2, 3],
        vec![3, 2],
    ];
    let ordinary = Lanes::<F>::new(false, arities.clone());
    let shared = Lanes::<F>::new(true, arities);
    assert!(satisfied(&ordinary));
    assert!(satisfied(&shared));
    assert_eq!(ordinary.public(), shared.public());
    assert_eq!(fixed_columns(&ordinary) - fixed_columns(&shared), 20);
}

#[test]
fn six_aligned_lanes_keep_native_digests_and_remove_twenty_fixed_columns() {
    check_aligned::<Fp>();
    check_aligned::<Fq>();
}

fn check_asymmetric<F: PoseidonField>() {
    for arities in [
        vec![vec![2, 2], vec![2]],    // unequal spans
        vec![vec![2], vec![4]],       // different squeeze/continuation boundaries
        vec![vec![4, 2], vec![2, 4]], // equal total span, different boundaries
    ] {
        assert!(satisfied(&Lanes::<F>::new(false, arities.clone())));
        assert!(!satisfied(&Lanes::<F>::new(true, arities)));
    }
}

#[test]
fn asymmetric_schedules_are_rejected_in_both_fields() {
    check_asymmetric::<Fp>();
    check_asymmetric::<Fq>();
}

fn check_tampers<F: PoseidonField>() {
    let circuit = Lanes::<F>::new(true, vec![vec![2], vec![3]]);
    assert!(
        undetected_tampers(&circuit, K, &[circuit.public()])
            .expect("tamper sweep")
            .is_empty()
    );
}

#[test]
fn every_shared_lane_advice_cell_remains_bound_in_both_fields() {
    check_tampers::<Fp>();
    check_tampers::<Fq>();
}

fn prove<C: PastaCurve>()
where
    C::ScalarExt: PoseidonField,
    C::Base: PoseidonField,
{
    let circuit = Lanes::<C::ScalarExt>::new(true, vec![vec![2, 3]; 6]);
    let params = PinnedParams::<C>::derive(K).expect("params");
    let mut config = KeygenConfig::new(TranscriptV1::Blake2bChallenge255);
    config.coset_cache = CosetCachePolicy::OnDemand;
    let pk = keygen_pk(&params, &circuit.without_witnesses(), &config).expect("keygen");
    let instances = vec![circuit.public()];
    let proof = prove_circuit(
        &params,
        &pk,
        &circuit,
        &instances,
        ProverRandomness::os(),
        ProverConfig::default(),
    )
    .expect("proof");
    verify_full(
        &params,
        pk.binding(),
        pk.vk(),
        &instances,
        &proof,
        MemoryBudget::DEFAULT,
    )
    .expect("verify");
    let mut forged = instances;
    forged[0][0] += C::ScalarExt::ONE;
    assert!(
        verify_full(
            &params,
            pk.binding(),
            pk.vk(),
            &forged,
            &proof,
            MemoryBudget::DEFAULT
        )
        .is_err()
    );
}

#[test]
fn shared_lanes_have_real_proofs_on_both_curves() {
    prove::<Ep>();
    prove::<Eq>();
}
