//! Receipt binding predicate boundaries, independently of finding a hash preimage.

use super::*;
use ff::PrimeField;
use iroha_plonk::{
    check::{CheckMode, check_circuit},
    cs::{Column, ConstraintSystem, Instance},
    frontend::{Circuit, Layouter, SimpleFloorPlanner, Value},
};
use iroha_plonk_gadgets::{
    GlueChip, GlueConfig, LimbBits, Pow5Columns, RoundConstantColumns, RunningSumChip,
    RunningSumConfig, SpongeChip, SpongeConfig,
    bytes::tape::{BytesChip, BytesConfig},
};

#[derive(Clone)]
struct BindingCircuit {
    operation: Fp,
    receive: bool,
    known: bool,
}

#[derive(Clone, Debug)]
struct Config {
    glue: GlueConfig,
    range: RunningSumConfig,
    bytes: BytesConfig,
    hash: SpongeConfig<Fp>,
    instance: Column<Instance>,
}

impl Circuit<Fp> for BindingCircuit {
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
        let advice = core::array::from_fn(|_| meta.advice_column());
        let constants = meta.fixed_column();
        let glue = GlueConfig::configure(meta, advice, constants);
        let range_column = meta.advice_column();
        let range = RunningSumConfig::configure(meta, range_column, LimbBits::new(8).unwrap());
        let z = meta.advice_column();
        let w = meta.advice_column();
        let bytes = BytesConfig::configure(meta, z, w);
        let columns = Pow5Columns::allocate(meta);
        let constants = RoundConstantColumns::allocate(meta);
        let hash = SpongeConfig::configure(meta, columns, constants, &[]);
        let instance = meta.instance_column(1);
        meta.enable_equality(instance);
        Config {
            glue,
            range,
            bytes,
            hash,
            instance,
        }
    }

    fn synthesize(&self, c: Config, mut layouter: impl Layouter<Fp>) -> Result<(), Error> {
        let mut glue = GlueChip::new(c.glue);
        let mut range = RunningSumChip::new(c.range);
        let mut bytes = BytesChip::new(c.bytes);
        let mut hash = SpongeChip::new(c.hash);
        range.load_table(&mut layouter)?;
        bytes.load_table(&mut layouter)?;
        let verdict = layouter.assign_region(
            || "consistent derived receipt context",
            |mut region| {
                // A canonical receipt body with every context join consistent.
                // Signature verification is owned by Q and is outside this predicate.
                let mut tape = vec![0; ObjectKind::Receipt.body_len() + 64];
                tape[..2].copy_from_slice(&1_u16.to_le_bytes());
                for (value, offset) in [(1, 2), (2, 34), (3, 66), (15, 274)] {
                    tape[offset..offset + 32].fill(value);
                }
                tape[98..114].copy_from_slice(&1_u128.to_le_bytes());
                tape[114..146].copy_from_slice(&self.operation.to_repr());
                for (value, offset) in [(11, 146), (12, 178), (13, 210), (14, 242)] {
                    tape[offset..offset + 32].copy_from_slice(&Fp::from(value).to_repr());
                }
                if self.receive {
                    tape[306..338].copy_from_slice(&Fp::from(16).to_repr());
                }
                let input = tape
                    .iter()
                    .map(|byte| {
                        if self.known {
                            Value::known(*byte)
                        } else {
                            Value::unknown()
                        }
                    })
                    .collect::<Vec<_>>();
                let run = bytes.run(
                    &mut region,
                    &input,
                    &ObjectKind::Receipt.primary_segments(),
                    &ObjectKind::Receipt.secondary_segments(),
                )?;
                let mut uint = UintChip::new(&mut glue, &mut range);
                let receipt = SignedObjectCells::from_run(
                    &mut uint,
                    &mut hash,
                    &mut region,
                    ObjectKind::Receipt,
                    &run,
                )?;
                let zero = uint.glue().constant(&mut region, Fp::ZERO)?;
                let mut fields = core::array::from_fn(|_| zero.clone());
                fields[3..5].clone_from_slice(receipt.identifier(1)?);
                fields[9] = receipt.word(4)?.clone();
                fields[14] = receipt.word(6)?.clone();
                fields[15] = receipt.word(7)?.clone();
                let one = uint.glue().constant(&mut region, Fp::ONE)?;
                let valid = uint.glue().assert_bool(&mut region, &one)?;
                let receive_word = uint
                    .glue()
                    .constant(&mut region, Fp::from(u64::from(self.receive)))?;
                let receive = uint.glue().assert_bool(&mut region, &receive_word)?;
                // This is the production binding predicate at its derived-context
                // boundary. It does not claim that RP57 has a known zero preimage.
                bind_context(
                    &mut uint,
                    &mut region,
                    &receipt,
                    &BindingContext {
                        wallet: receipt.identifier(2)?,
                        provider: receipt.identifier(3)?,
                        fields: &fields,
                        digest: receipt.word(8)?,
                        proof_digest: receipt.word(9)?,
                        payment_digest: receipt.word(11)?,
                        valid: &valid,
                        operation: receipt.word(5)?,
                        receive: &receive,
                    },
                )
            },
        )?;
        layouter.constrain_instance(verdict.word().cell(), c.instance, 0)
    }
}

fn accepts(operation: Fp, receive: bool, verdict: bool) -> bool {
    check_circuit(
        &BindingCircuit {
            operation,
            receive,
            known: true,
        },
        11,
        &[vec![Fp::from(u64::from(verdict))]],
        CheckMode::Strict,
    )
    .expect("strict receipt binding layout")
    .is_satisfied()
}

#[test]
fn zero_operation_identity_has_a_false_total_binding_verdict() {
    for receive in [false, true] {
        assert!(accepts(Fp::ZERO, receive, false));
        assert!(!accepts(Fp::ZERO, receive, true));
    }
}

#[test]
fn nonzero_operation_identity_preserves_consistent_binding() {
    for operation in [Fp::ONE, -Fp::ONE] {
        for receive in [false, true] {
            assert!(accepts(operation, receive, true));
            assert!(!accepts(operation, receive, false));
        }
    }
}
