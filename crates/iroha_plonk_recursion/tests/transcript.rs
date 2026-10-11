//! Both-field parity, framing and cell binding of the recursive transcript lane.

use ff::Field as _;
use iroha_pasta::{
    Ep, Eq, Fp, Fq, PastaCurve,
    poseidon::{PoseidonField, Sponge},
};
use iroha_plonk::{
    check::{CheckMode, check_circuit},
    cs::{Column, ConstraintSystem, Instance, InstanceType},
    frontend::{Circuit, Error, Layouter, SimpleFloorPlanner, Value},
    transcript::{
        TranscriptHash,
        pipa_r::{BasePoseidonHash, challenge_from_base},
    },
};
use iroha_plonk_gadgets::{
    GlueChip, GlueConfig,
    poseidon::{Pow5Columns, RoundConstantColumns},
    pow5_fq::{DuplexChip, DuplexConfig},
    tamper::undetected_tampers,
};
use iroha_plonk_recursion::transcript::{Domain, TranscriptChip};

const TYPES: [InstanceType; 4] = [
    InstanceType::Field,
    InstanceType::Bounded,
    InstanceType::Bits(0),
    InstanceType::Bits(128),
];
const LENGTHS: [u32; 4] = [2, 1, 0, 1];

#[derive(Clone, Debug)]
struct Config<F> {
    glue: GlueConfig,
    duplex: DuplexConfig<F>,
    public: Column<Instance>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Lane {
    Fresh,
    Reuse,
    RejectLive,
}

#[derive(Clone, Debug)]
struct Shape {
    domain: Domain,
    framed: bool,
    rounds: usize,
    reversed_types: bool,
    lane: Lane,
}

impl Default for Shape {
    fn default() -> Self {
        Self {
            domain: Domain::Proof,
            framed: false,
            rounds: 1,
            reversed_types: false,
            lane: Lane::Fresh,
        }
    }
}

#[derive(Clone)]
struct Script<F> {
    shape: Shape,
    inputs: Vec<Vec<F>>,
    known: bool,
}

impl<F: PoseidonField> Script<F> {
    fn new(domain: Domain, framed: bool, inputs: Vec<Vec<F>>) -> Self {
        Self {
            shape: Shape {
                domain,
                framed,
                rounds: inputs.len(),
                reversed_types: false,
                lane: Lane::Fresh,
            },
            inputs,
            known: true,
        }
    }

    fn reference(&self) -> Vec<F> {
        let mut native = Sponge::new();
        native.update(&[F::from(u64::from_le_bytes(self.shape.domain.tag()))]);
        if self.shape.framed {
            native.update(&[
                F::from(42),
                F::from(u64::from_le_bytes(*b"pipainst")),
                F::from(4),
            ]);
            native.update(&LENGTHS.map(|len| F::from(u64::from(len))));
            native.update(&TYPES.map(|ty| F::from(ty.code())));
        }
        self.inputs
            .iter()
            .map(|words| {
                native.update(&[F::from(99)]);
                native.update(words);
                native.squeeze()
            })
            .collect()
    }
}

impl<F: PoseidonField> Circuit<F> for Script<F> {
    type Config = Config<F>;
    type FloorPlanner = SimpleFloorPlanner;
    type Params = Shape;

    fn without_witnesses(&self) -> Self {
        Self {
            known: false,
            ..self.clone()
        }
    }

    fn params(&self) -> Shape {
        self.shape.clone()
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> Config<F> {
        Self::configure_with_params(meta, Shape::default())
    }

    fn configure_with_params(meta: &mut ConstraintSystem<F>, shape: Shape) -> Config<F> {
        let advice = core::array::from_fn(|_| meta.advice_column());
        let constants = meta.fixed_column();
        let glue = GlueConfig::configure(meta, advice, constants);
        let lane = Pow5Columns::allocate(meta);
        let round_constants = RoundConstantColumns::allocate(meta);
        let duplex = DuplexConfig::configure(meta, lane, round_constants, &[]);
        let public = meta.instance_column(shape.rounds);
        meta.enable_equality(public);
        Config {
            glue,
            duplex,
            public,
        }
    }

    fn synthesize(&self, config: Config<F>, mut layouter: impl Layouter<F>) -> Result<(), Error> {
        let mut glue = GlueChip::new(config.glue);
        let outputs = layouter.assign_region(
            || "recursive transcript",
            |mut region| {
                if self.shape.lane == Lane::RejectLive {
                    let mut duplex = DuplexChip::new(config.duplex.clone());
                    duplex.absorb_constant(F::from(7));
                    let word = duplex.squeeze(&mut region)?;
                    assert!(TranscriptChip::from_duplex(duplex, self.shape.domain).is_err());
                    return Ok(vec![word.cell()]);
                }
                let mut transcript = if self.shape.lane == Lane::Reuse {
                    let mut buffered = DuplexChip::new(config.duplex.clone());
                    buffered.absorb_constant(F::from(7));
                    assert!(TranscriptChip::from_duplex(buffered, self.shape.domain).is_err());
                    let mut duplex = DuplexChip::new(config.duplex.clone());
                    duplex.absorb_constant(F::from(7));
                    duplex.squeeze_and_clear(&mut region)?;
                    let mut prior = TranscriptChip::from_duplex(duplex, self.shape.domain)?;
                    prior.common_constant(F::from(8));
                    prior.squeeze_base(&mut region)?;
                    prior.common_constant(F::from(9));
                    let cleared = prior.into_duplex();
                    assert!(cleared.is_clear());
                    TranscriptChip::from_duplex(cleared, self.shape.domain)?
                } else {
                    TranscriptChip::new(config.duplex.clone(), self.shape.domain)
                };
                if self.shape.framed {
                    let repr = glue.constant(&mut region, F::from(42))?;
                    // Invalid metadata must not alter the fresh state.
                    assert!(transcript.proof_prelude(&repr, &[1], &[]).is_err());
                    assert!(
                        transcript
                            .proof_prelude(&repr, &[1], &[InstanceType::Bits(254)])
                            .is_err()
                    );
                    let mut types = TYPES;
                    if self.shape.reversed_types {
                        types.reverse();
                    }
                    transcript.proof_prelude(&repr, &LENGTHS, &types)?;
                    assert!(transcript.proof_prelude(&repr, &LENGTHS, &types).is_err());
                }
                let mut outputs = Vec::new();
                for (round, values) in self.inputs.iter().enumerate() {
                    transcript.common_constant(F::from(99));
                    for value in values {
                        let value = if self.known {
                            Value::known(*value)
                        } else {
                            Value::unknown()
                        };
                        let word = glue.witness(&mut region, value)?;
                        transcript.common_word(&word);
                    }
                    if round + 1 == self.inputs.len() {
                        outputs.push(transcript.finish(&mut region)?.cell());
                        return Ok(outputs);
                    }
                    outputs.push(transcript.squeeze_base(&mut region)?.cell());
                }
                Err(Error::Synthesis)
            },
        )?;
        for (index, output) in outputs.into_iter().enumerate() {
            layouter.constrain_instance(output, config.public, index)?;
        }
        Ok(())
    }
}

fn accepts<F: PoseidonField>(circuit: &Script<F>, expected: &[F]) -> bool {
    check_circuit(circuit, 10, &[expected.to_vec()], CheckMode::Strict)
        .expect("synthesis")
        .is_satisfied()
}

fn parity<C: PastaCurve>()
where
    C::Base: PoseidonField,
{
    for domain in [Domain::Proof, Domain::Fold] {
        for framed in [false, true] {
            if domain == Domain::Fold && framed {
                continue;
            }
            let script = Script::new(
                domain,
                framed,
                vec![
                    vec![],
                    vec![C::Base::ONE],
                    vec![C::Base::ZERO, -C::Base::ONE],
                    vec![C::Base::from(7); 3],
                    vec![],
                ],
            );
            let expected = script.reference();
            assert!(accepts(&script, &expected));
            let mut native = BasePoseidonHash::<C>::with_domain(domain.tag());
            if framed {
                for value in [
                    C::Base::from(42),
                    C::Base::from(u64::from_le_bytes(*b"pipainst")),
                    C::Base::from(4),
                ] {
                    native.absorb_base(&value).unwrap();
                }
                for len in LENGTHS {
                    native.absorb_base(&C::Base::from(u64::from(len))).unwrap();
                }
                for ty in TYPES {
                    native.absorb_base(&C::Base::from(ty.code())).unwrap();
                }
            }
            for (words, base) in script.inputs.iter().zip(&expected) {
                native.absorb_base(&C::Base::from(99)).unwrap();
                for word in words {
                    native.absorb_base(word).unwrap();
                }
                assert_eq!(native.squeeze(), challenge_from_base::<C>(base));
            }
            for index in 0..expected.len() {
                let mut wrong = expected.clone();
                wrong[index] += C::Base::ONE;
                assert!(!accepts(&script, &wrong));
            }
            if framed {
                let mut swapped = script.clone();
                swapped.shape.reversed_types = true;
                assert!(!accepts(&swapped, &expected));
            }
            let mut foreign_domain = script.clone();
            foreign_domain.shape.framed = false;
            foreign_domain.shape.domain = if domain == Domain::Proof {
                Domain::Fold
            } else {
                Domain::Proof
            };
            assert!(!accepts(&foreign_domain, &expected));
        }
    }
}

#[test]
fn native_and_circuit_transcript_match_both_base_fields() {
    parity::<Ep>();
    parity::<Eq>();
}

#[test]
fn every_transcript_cell_is_bound_through_continuing_and_final_squeezes() {
    fn run<F: PoseidonField>() {
        let script = Script::new(Domain::Proof, false, vec![vec![F::from(7)], vec![]]);
        assert!(
            undetected_tampers(&script, 8, &[script.reference()])
                .unwrap()
                .is_empty()
        );
    }
    run::<Fp>();
    run::<Fq>();
}

#[test]
fn cleared_duplex_lane_retains_its_cursor_and_rejects_live_state() {
    fn run<F: PoseidonField>() {
        let mut script = Script::new(Domain::Proof, true, vec![vec![F::from(17)], vec![]]);
        script.shape.lane = Lane::Reuse;
        assert!(accepts(&script, &script.reference()));
        assert!(
            undetected_tampers(&script, 10, &[script.reference()])
                .unwrap()
                .is_empty()
        );
        let mut rejected = Script::new(Domain::Proof, false, vec![vec![]]);
        rejected.shape.lane = Lane::RejectLive;
        let mut native = Sponge::<F>::new();
        native.update(&[F::from(7)]);
        assert!(accepts(&rejected, &[native.squeeze()]));
    }
    run::<Fp>();
    run::<Fq>();
}
