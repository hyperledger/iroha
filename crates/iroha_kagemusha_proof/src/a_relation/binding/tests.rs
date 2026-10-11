//! Q export wiring only: substituted verifier inputs cannot manufacture burn.

use super::*;
use crate::{operation_relation::incoming_statement::IncomingStatementCells, q_sigma::SigmaClass};
use ff::PrimeField;
use iroha_pasta::Fq;
use iroha_plonk::{
    DescriptorBinding,
    check::{CheckMode, check_circuit},
    cs::{
        CircuitDescriptorV1, CircuitDescriptorV2, Column, ConstraintSystem, CurveV1,
        DescriptorConfig, Instance, InstanceModeV1, ProofSuffixV1, TranscriptV1, TranscriptV2,
    },
    frontend::{Circuit, Layouter, SimpleFloorPlanner, Value, synthesize},
    pcs::ipa::PinnedParams,
};
use iroha_plonk_gadgets::UintChip;
use iroha_plonk_recursion::{
    obligation::ledger::Variant,
    verifier::{VerifierConfig, VerifierPlan},
};

#[derive(Clone, Debug)]
struct Config {
    verifier: VerifierConfig<Ep>,
    public: Column<Instance>,
}

#[derive(Clone, Copy)]
enum Mutation {
    None,
    Digest,
    Index,
    Bytes,
}

#[derive(Clone)]
struct Bindings {
    plan: QSigmaPlan,
    own: [Fp; 26],
    incoming: [Fp; 26],
    verdict: bool,
    mutation: Mutation,
    known: bool,
}

impl Circuit<Fp> for Bindings {
    type Config = Config;
    type Params = ();
    type FloorPlanner = SimpleFloorPlanner;
    fn without_witnesses(&self) -> Self {
        Self {
            known: false,
            ..self.clone()
        }
    }
    fn configure(meta: &mut ConstraintSystem<Fp>) -> Config {
        let verifier = VerifierConfig::configure(meta);
        let public = meta.instance_column(1);
        meta.enable_equality(public);
        Config { verifier, public }
    }
    fn synthesize(&self, c: Config, mut layouter: impl Layouter<Fp>) -> Result<(), Error> {
        let mut chip = VerifierChip::new(c.verifier);
        chip.load_tables(&mut layouter)?;
        let out = layouter.assign_region(
            || "bind exact Q exports",
            |mut region| {
                let value = |v| {
                    if self.known {
                        Value::known(v)
                    } else {
                        Value::unknown()
                    }
                };
                let lanes = chip.operation_lanes()?;
                let mut uint = UintChip::new(lanes.glue, lanes.range);
                let own = uint
                    .glue()
                    .witnesses(&mut region, &self.own.map(value))?
                    .try_into()
                    .map_err(|_| Error::Synthesis)?;
                let own = StatementCells::constrain(
                    &mut uint,
                    lanes.hash,
                    &mut region,
                    Variant::Receive,
                    &own,
                )?;
                let incoming = uint
                    .glue()
                    .witnesses(&mut region, &self.incoming.map(value))?
                    .try_into()
                    .map_err(|_| Error::Synthesis)?;
                let incoming = IncomingStatementCells::constrain(
                    &mut uint,
                    lanes.hash,
                    &mut region,
                    Variant::Send,
                    &incoming,
                )?;
                let own_index = uint.glue().witness(&mut region, value(Fp::from(10)))?;
                let incoming_index = uint.glue().witness(&mut region, value(Fp::from(2)))?;
                let zero = uint.glue().constant(&mut region, Fp::ZERO)?;
                let bindings = [
                    SigmaBindingCells::from_statement(
                        &own,
                        own_index,
                        vec![zero.clone(); self.plan.chunk_range(0).ok_or(Error::Synthesis)?.len()],
                    ),
                    SigmaBindingCells::from_incoming(
                        &incoming,
                        incoming_index,
                        vec![zero; self.plan.chunk_range(1).ok_or(Error::Synthesis)?.len()],
                    ),
                ];
                let digest = incoming.digest().value().map(|v| {
                    v + if matches!(self.mutation, Mutation::Digest) {
                        Fp::ONE
                    } else {
                        Fp::ZERO
                    }
                });
                let mut native = self
                    .plan
                    .instance_lengths()
                    .map(|n| vec![Value::known(Fp::ZERO); n]);
                native[0][0] = own.digest().value();
                native[0][1] = digest;
                native[2][0] = value(Fp::from(10));
                native[2][1] = value(Fp::from(if matches!(self.mutation, Mutation::Index) {
                    3
                } else {
                    2
                }));
                native[3][0] = value(Fp::ONE);
                native[3][1] = value(Fp::from(u64::from(self.verdict)));
                // The mode itself is correctly one-hot; a substituted verifier
                // input must fail even when Q legitimately reports false/Trivial.
                native[3][3] = value(Fp::ONE);
                native[4][0] = value(Fp::from(16));
                for i in self.plan.challenge_range() {
                    native[0][i] = value(Fp::ONE);
                }
                if matches!(self.mutation, Mutation::Bytes) {
                    native[0][self.plan.chunk_range(1).ok_or(Error::Synthesis)?.start] =
                        value(Fp::ONE);
                }
                let mut instances = Vec::new();
                for column in native {
                    let mut cells = Vec::new();
                    for value in column {
                        let word = chip.uint().glue().witness(&mut region, value)?;
                        cells.push(ScalarCells::from_native_word(
                            &mut chip.uint(),
                            &mut region,
                            &word,
                        )?);
                    }
                    instances.push(cells);
                }
                let trivial = VestaClaimCells::trivial(&mut chip, &mut region)?;
                instances[1] = trivial.coordinates().to_vec();
                let bound = bind_sigma(&mut chip, &mut region, &self.plan, &instances, &bindings)?;
                Ok(bound.incoming_valid.ok_or(Error::Synthesis)?.word().clone())
            },
        )?;
        layouter.constrain_instance(out.cell(), c.public, 0)
    }
}

fn fixture() -> Bindings {
    let json: norito::json::Value = norito::json::from_str(include_str!(
        "../../../../../fixtures/kagemusha/wallet_v1_vectors.json"
    ))
    .unwrap();
    let fields = |name: &str| {
        json["field_encodings"][name]["items"]
            .as_array()
            .unwrap()
            .iter()
            .map(|word| {
                let hex = word.as_str().unwrap().as_bytes();
                let bytes = core::array::from_fn(|i| {
                    u8::from_str_radix(core::str::from_utf8(&hex[2 * i..2 * i + 2]).unwrap(), 16)
                        .unwrap()
                });
                Fp::from_repr(bytes).into_option().unwrap()
            })
            .collect::<Vec<_>>()
            .try_into()
            .unwrap()
    };
    let mut cs = ConstraintSystem::<Fp>::default();
    cs.instance_column(1);
    let layout = CircuitDescriptorV1::from_constraint_system(
        &cs.finalize(&[], false).unwrap(),
        DescriptorConfig {
            curve: CurveV1::Vesta,
            k: 12,
            transcript: TranscriptV1::KagemushaPoseidonRp57,
            instance_mode: InstanceModeV1::Direct,
            proof_suffix: ProofSuffixV1::FoldedGenerator,
        },
    )
    .unwrap();
    let descriptor = CircuitDescriptorV2::from_layout(
        layout,
        TranscriptV2::KagemushaPoseidonRp57Base,
        vec![InstanceType::Bounded],
    )
    .unwrap();
    let params = PinnedParams::<Eq>::derive(16).unwrap();
    let verifier = VerifierPlan::new(
        DescriptorBinding::new_v2(descriptor).unwrap(),
        PinnedParams::<Eq>::derive(12).unwrap(),
    )
    .unwrap();
    // Descriptor/key hashes below are only Q export-link metadata. This unit
    // test does not produce or accept a recursive proof under a fixture key.
    let own = SigmaClass::new(verifier.clone(), vec![(10, Fq::from(11))]).unwrap();
    let incoming = SigmaClass::new(verifier, vec![(2, Fq::from(12)), (3, Fq::from(13))]).unwrap();
    Bindings {
        plan: QSigmaPlan::new(own, Some(incoming), &params).unwrap(),
        own: fields("receive_statement"),
        incoming: fields("send_statement"),
        verdict: false,
        mutation: Mutation::None,
        known: true,
    }
}

/// Fixed descriptor-only sigma classes for A input-link tests.
pub(in crate::a_relation) fn sigma_fixture() -> QSigmaPlan {
    fixture().plan
}

#[test]
fn incoming_verifier_input_substitutions_cannot_manufacture_soft_false() {
    let c = fixture();
    for verdict in [false, true] {
        let honest = Bindings {
            verdict,
            ..c.clone()
        };
        let public = vec![vec![Fp::from(u64::from(verdict))]];
        assert!(
            check_circuit(&honest, 16, &public, CheckMode::Strict)
                .unwrap()
                .is_satisfied()
        );
        for mutation in [Mutation::Digest, Mutation::Index, Mutation::Bytes] {
            let wrong = Bindings {
                mutation,
                ..honest.clone()
            };
            assert!(
                !check_circuit(&wrong, 16, &[vec![Fp::ZERO]], CheckMode::Strict)
                    .unwrap()
                    .is_satisfied()
            );
        }
    }
    let mut malformed = c.clone();
    malformed.incoming[0] = Fp::from(2);
    assert!(
        check_circuit(&malformed, 16, &[vec![Fp::ZERO]], CheckMode::Strict)
            .unwrap()
            .is_satisfied()
    );
    let known = synthesize(&c, 16, None).unwrap();
    let unknown = synthesize(&c.without_witnesses(), 16, None).unwrap();
    assert_eq!(known.tables.fixed(), unknown.tables.fixed());
    assert_eq!(known.tables.permutation(), unknown.tables.permutation());
}
