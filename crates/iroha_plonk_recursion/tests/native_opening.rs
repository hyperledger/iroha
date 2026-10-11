//! Native PIPA-R generator claims enter PIPA-AS with checked prefix padding.

use ff::Field as _;
use iroha_pasta::{Ep, Eq, PastaCurve, PastaField, msm::MemoryBudget};
use iroha_plonk::{
    ProverConfig, ProverRandomness, Witness, create_proof_owned_with_claim,
    cs::{Column, ConstraintSystem, Instance, InstanceType},
    frontend::{Circuit, Error, Layouter, SimpleFloorPlanner, Value},
    keys::{KeygenConfigV2, keygen_pk_v2},
    pcs::ipa::PinnedParams,
    verifier::accumulate_generator,
};
use iroha_plonk_gadgets::{GlueChip, GlueConfig};
use iroha_plonk_recursion::{FoldInput, K};

#[derive(Clone)]
struct Square;

impl<F: PastaField> Circuit<F> for Square {
    type Config = (GlueConfig, Column<Instance>);
    type FloorPlanner = SimpleFloorPlanner;
    type Params = ();

    fn without_witnesses(&self) -> Self {
        self.clone()
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        let advice = core::array::from_fn(|_| meta.advice_column());
        let constants = meta.fixed_column();
        let glue = GlueConfig::configure(meta, advice, constants);
        let instance = meta.instance_column(1);
        meta.enable_equality(instance);
        (glue, instance)
    }

    fn synthesize(
        &self,
        (config, instance): Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {
        let mut glue = GlueChip::new(config);
        let square = layouter.assign_region(
            || "square",
            |mut region| {
                let value = glue.witness(&mut region, Value::known(F::from(3)))?;
                glue.mul(&mut region, &value, &value)
            },
        )?;
        layouter.constrain_instance(square.cell(), instance, 0)
    }
}

fn roundtrip<C: PastaCurve>() {
    let params = PinnedParams::<C>::derive(6).expect("params");
    let config = KeygenConfigV2::pipa_r(vec![InstanceType::Field]);
    let key = keygen_pk_v2(&params, &Square, &config).expect("PIPA-R key");
    let instances = [vec![C::ScalarExt::from(9)]];
    let witness = Witness::from_circuit(&key, &Square, &instances).expect("witness");
    let output = create_proof_owned_with_claim(
        &params,
        &key,
        witness,
        ProverRandomness::os(),
        ProverConfig::default(),
    )
    .expect("proof and generator claim");
    let verified = accumulate_generator(
        &params,
        key.binding(),
        key.vk(),
        &instances,
        &output.proof,
        MemoryBudget::DEFAULT,
    )
    .expect("succinct verifier");
    assert_eq!(verified, output.opening);
    let input = FoldInput::<C>::from_opening(*verified.g(), verified.challenges())
        .expect("checked padding");
    assert_eq!(input.source_k(), verified.k());
    assert_eq!(&input.challenges()[..K - 6], &[C::ScalarExt::ZERO; K - 6]);
    assert_eq!(&input.challenges()[K - 6..], verified.challenges());
    input
        .decide(&params, MemoryBudget::new(0))
        .expect("independent complete decision");
}

#[test]
fn native_pipa_r_claims_enter_fold_on_both_curves() {
    roundtrip::<Ep>();
    roundtrip::<Eq>();
}
