// Shared genuine builder items. Registered tests remain in the integration harness.
use ff::Field;
use iroha_kagemusha_proof::{
    a_relation::{
        LineagePublicCells, SigmaBindingCells,
        load::{LoadInputs, LoadObjects},
        own::OwnPolicy,
    },
    admin_sigma::{LoadCircuit, LoadWitness, StateWitness},
    operation_relation::{
        map_effects::{InsertCells, MapState},
        state::StateCells,
        statement::StatementCells,
    },
    tree::IndexedInsert,
};
use iroha_pasta::{Ep, Fp, Fq, msm::MemoryBudget};
use iroha_plonk::{
    ProverConfig, Witness,
    check::{CheckMode, check_circuit},
    create_proof_owned_with_claim,
    cs::{Column, ConstraintSystem, Instance},
    frontend::{Circuit, Error, Layouter, Region, SimpleFloorPlanner, Value, synthesize},
    keys::{KeygenConfigV2, keygen_pk_v2},
    pcs::ipa::PinnedParams,
    verifier::accumulate_generator,
};
use iroha_plonk_gadgets::{
    UintChip,
    bytes::tape::{BytesChip, BytesConfig},
    imt::{LeafCells, OpeningCells, PathCells},
};
use iroha_plonk_recursion::{
    obligation::ledger::Variant,
    verifier::{VerifierChip, VerifierConfig},
};

#[derive(Clone)]
pub(crate) struct LoadMaps {
    pub(crate) witness: LoadWitness,
    pub(crate) insertion: IndexedInsert<Fp>,
    pub(crate) receipt: load_objects::OrdinaryReceipt,
    pub(crate) objects: [bootstrap_objects::Signed; 3],
    pub(crate) known: bool,
}
#[derive(Clone, Debug)]
pub(crate) struct Config {
    verifier: VerifierConfig<Ep>,
    bytes: BytesConfig,
    public: Column<Instance>,
}
impl LoadMaps {
    fn value<T: Copy>(&self, value: T) -> Value<T> {
        if self.known {
            Value::known(value)
        } else {
            Value::unknown()
        }
    }
    pub(crate) fn state(
        &self,
        chip: &mut VerifierChip<Ep>,
        region: &mut Region<'_, Fp>,
        witness: &StateWitness,
    ) -> Result<(StateCells, LineagePublicCells), Error> {
        let core = chip
            .uint()
            .glue()
            .witnesses(region, &witness.core.map(|v| self.value(v)))?
            .try_into()
            .map_err(|_| Error::Synthesis)?;
        let rest = chip
            .uint()
            .glue()
            .witnesses(region, &witness.rest.map(|v| self.value(v)))?
            .try_into()
            .map_err(|_| Error::Synthesis)?;
        let state = StateCells::constrain_with_verifier(chip, region, &core, &rest)?;
        let public = chip
            .uint()
            .glue()
            .witnesses(region, &witness.lineage.map(|v| self.value(v)))?
            .try_into()
            .map_err(|_| Error::Synthesis)?;
        let public = LineagePublicCells::constrain(&mut chip.uint(), region, &public)?;
        Ok((state, public))
    }
    pub(crate) fn insertion(
        &self,
        uint: &mut UintChip<'_, Fp>,
        region: &mut Region<'_, Fp>,
    ) -> Result<InsertCells, Error> {
        let leaf = self.insertion.leaf;
        let words = uint
            .glue()
            .witnesses(
                region,
                &[leaf.key, leaf.value, leaf.next_key].map(|v| self.value(v)),
            )?
            .try_into()
            .map_err(|_| Error::Synthesis)?;
        let leaf = LeafCells::from_words(words);
        let mut paths = Vec::new();
        for (index, siblings) in [
            (self.insertion.leaf_slot, self.insertion.leaf_siblings),
            (self.insertion.slot, self.insertion.slot_siblings),
        ] {
            let index = uint
                .glue()
                .witness(region, self.value(Fp::from(u64::from(index))))?;
            let siblings = uint
                .glue()
                .witnesses(region, &siblings.map(|v| self.value(v)))?
                .try_into()
                .map_err(|_| Error::Synthesis)?;
            paths.push(PathCells::from_words(uint, region, &index, siblings)?);
        }
        let [low, slot] = paths.try_into().map_err(|_| Error::Synthesis)?;
        Ok(InsertCells {
            low: OpeningCells { leaf, path: low },
            slot,
        })
    }
    fn public(&self) -> Vec<Vec<Fp>> {
        vec![
            std::iter::once(self.receipt.digest())
                .chain(self.objects.iter().map(bootstrap_objects::Signed::digest))
                .collect(),
        ]
    }
}
impl Circuit<Fp> for LoadMaps {
    type Config = Config;
    type FloorPlanner = SimpleFloorPlanner;
    type Params = ();
    fn without_witnesses(&self) -> Self {
        Self {
            known: false,
            ..self.clone()
        }
    }
    fn configure(meta: &mut ConstraintSystem<Fp>) -> Config {
        let verifier = VerifierConfig::configure(meta);
        let a = meta.advice_column();
        let b = meta.advice_column();
        let bytes = BytesConfig::configure(meta, a, b);
        let public = meta.instance_column(4);
        meta.enable_equality(public);
        Config {
            verifier,
            bytes,
            public,
        }
    }
    fn synthesize(&self, config: Config, mut layouter: impl Layouter<Fp>) -> Result<(), Error> {
        let mut chip = VerifierChip::new(config.verifier);
        let mut bytes = BytesChip::new(config.bytes);
        chip.load_tables(&mut layouter)?;
        bytes.load_table(&mut layouter)?;
        let out = layouter.assign_region(
            || "Load maps and exact object tapes",
            |mut region| {
                let (before, pred) =
                    self.state(&mut chip, &mut region, &self.witness.predecessor)?;
                let (after, next) = self.state(&mut chip, &mut region, &self.witness.successor)?;
                let fields = chip
                    .uint()
                    .glue()
                    .witnesses(&mut region, &self.witness.statement.map(|v| self.value(v)))?
                    .try_into()
                    .map_err(|_| Error::Synthesis)?;
                let statement = StatementCells::constrain_with_verifier(
                    &mut chip,
                    &mut region,
                    Variant::Load,
                    &fields,
                )?;
                let index = chip.uint().glue().constant(
                    &mut region,
                    Fp::from(u64::from(
                        iroha_kagemusha_proof::a_relation::schedule::sigma_selector(2, 0).unwrap(),
                    )),
                )?;
                let sigma = SigmaBindingCells::from_statement(&statement, index, vec![]);
                let sources: [Vec<Value<u8>>; 4] = core::array::from_fn(|i| {
                    let raw: &[u8] = if i == 0 {
                        &self.receipt.bytes
                    } else {
                        &self.objects[i - 1].bytes
                    };
                    raw.iter().map(|v| self.value(*v)).collect()
                });
                let objects = LoadObjects::decode(
                    &mut chip,
                    &mut bytes,
                    &mut region,
                    sources.each_ref().map(Vec::as_slice),
                )?;
                objects.bind_finalized_terms(
                    &mut region,
                    LoadInputs {
                        predecessor: MapState {
                            state: &before,
                            lineage: &pred,
                        },
                        successor: MapState {
                            state: &after,
                            lineage: &next,
                        },
                        sigma: &sigma,
                        signatures: &[],
                    },
                )?;
                let insertion = self.insertion(&mut chip.uint(), &mut region)?;
                LoadObjects::recovery(
                    &mut chip,
                    &mut region,
                    LoadInputs {
                        predecessor: MapState {
                            state: &before,
                            lineage: &pred,
                        },
                        successor: MapState {
                            state: &after,
                            lineage: &next,
                        },
                        sigma: &sigma,
                        signatures: &[],
                    },
                    &insertion,
                )?;
                Ok(objects
                    .context()
                    .iter()
                    .map(|o| o.authenticated_digest().clone())
                    .collect::<Vec<_>>())
            },
        )?;
        for (i, value) in out.iter().enumerate() {
            layouter.constrain_instance(value.cell(), config.public, i)?;
        }
        Ok(())
    }
}

fn fixture() -> (LoadMaps, Vec<u8>) {
    let (before, _, _) = bootstrap_objects::enrollment();
    fixture_from(&before)
}
pub(crate) fn fixture_from(
    before: &iroha_kagemusha_proof::admin_sigma::BootstrapWitness,
) -> (LoadMaps, Vec<u8>) {
    let (witness, insertion, ordinary) = load_objects::funded(before);
    let sigma = LoadCircuit::new(&witness);
    let params = common::vesta_params(12);
    let key = keygen_pk_v2(
        &params,
        &sigma,
        &KeygenConfigV2::pipa_r(LoadCircuit::instance_types().to_vec()),
    )
    .unwrap();
    let proof = create_proof_owned_with_claim(
        &params,
        &key,
        Witness::from_circuit(&key, &sigma, &sigma.instances()).unwrap(),
        common::recovery(191),
        ProverConfig::default(),
    )
    .unwrap();
    let opening = accumulate_generator(
        &params,
        key.binding(),
        key.vk(),
        &sigma.instances(),
        &proof.proof,
        MemoryBudget::DEFAULT,
    )
    .unwrap();
    opening.decide(&params, MemoryBudget::DEFAULT).unwrap();
    let receipt = load_objects::receipt(&witness, &proof.proof);
    let (_, enrollment, current) = bootstrap_objects::enrollment();
    assert_eq!(current.digest(), before.core[7]);
    (
        LoadMaps {
            witness,
            insertion,
            receipt: ordinary,
            objects: [receipt, enrollment, current],
            known: true,
        },
        proof.proof,
    )
}
