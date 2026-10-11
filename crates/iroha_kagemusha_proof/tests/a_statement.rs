//! Typed statements and same-tape proof decoding used by A's recursive frame.

use ff::{Field, PrimeField};
use iroha_kagemusha_proof::{
    a_relation::{ProofMessageCells, SigmaBindingCells},
    operation_relation::statement::StatementCells,
};
use iroha_pasta::{Ep, Fp, poseidon::hash_with_domain};
use iroha_plonk::{
    check::{CheckMode, check_circuit},
    cs::{Column, ConstraintSystem, Instance},
    frontend::{Circuit, Error, Layouter, SimpleFloorPlanner, Value, synthesize},
};
use iroha_plonk_gadgets::{
    bytes::{
        element::le_message_segments,
        tape::{BytesChip, BytesConfig, SegmentSpec},
    },
    statement::STATEMENT_DOMAIN,
};
use iroha_plonk_recursion::{
    obligation::ledger::Variant,
    verifier::{VerifierChip, VerifierConfig},
};

#[derive(Clone, Debug)]
struct Config {
    verifier: VerifierConfig<Ep>,
    bytes: BytesConfig,
    public: Column<Instance>,
}
#[derive(Clone)]
struct Binding {
    fields: [Fp; 26],
    bytes: [u8; 68],
    known: bool,
    offset: usize,
    fixed_bytes: usize,
}
impl Circuit<Fp> for Binding {
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
        let primary = meta.advice_column();
        let secondary = meta.advice_column();
        let bytes = BytesConfig::configure(meta, primary, secondary);
        let public = meta.instance_column(9);
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
        let output = layouter.assign_region(
            || "typed A bindings",
            |mut region| {
                let fields = self.fields.map(|v| {
                    if self.known {
                        Value::known(v)
                    } else {
                        Value::unknown()
                    }
                });
                let fields = chip.uint().glue().witnesses(&mut region, &fields)?;
                let statement = StatementCells::constrain_with_verifier(
                    &mut chip,
                    &mut region,
                    Variant::Send,
                    &fields.try_into().map_err(|_| Error::Synthesis)?,
                )?;
                let values = self.bytes.map(|v| {
                    if self.known {
                        Value::known(v)
                    } else {
                        Value::unknown()
                    }
                });
                let mut segments = vec![SegmentSpec::little(0, 4)];
                segments.extend(le_message_segments(4, 2));
                let run = bytes.run(&mut region, &values, &[31, 31, 6], &segments)?;
                let proof = ProofMessageCells::from_run(
                    &mut chip,
                    &mut region,
                    &run,
                    self.offset,
                    self.fixed_bytes,
                )?;
                let key = chip.uint().glue().constant(&mut region, Fp::from(5))?;
                let binding = SigmaBindingCells::from_statement(
                    &statement,
                    key,
                    run.primary().iter().map(|s| s.word().clone()).collect(),
                );
                assert_eq!(binding.statement().variant(), Variant::Send);
                let mut out = vec![
                    binding.statement().digest().clone(),
                    proof.length().word().clone(),
                ];
                for word in proof.messages() {
                    out.extend([
                        word.lo().word().clone(),
                        word.hi().word().clone(),
                        word.top().word().clone(),
                    ]);
                }
                // A second framed hash must retain the lane cursor and not overwrite
                // or absorb the previous statement's duplex state.
                out.push(chip.hash_words(&mut region, STATEMENT_DOMAIN, statement.fields())?);
                Ok(out)
            },
        )?;
        for (row, word) in output.iter().enumerate() {
            layouter.constrain_instance(word.cell(), config.public, row)?;
        }
        Ok(())
    }
}
impl Binding {
    fn new() -> Self {
        let mut fields = [Fp::ONE; 26];
        fields[11] = Fp::ZERO;
        fields[12] = Fp::ZERO;
        fields[13] = Fp::from(77);
        fields[16] = Fp::from(3);
        for (i, value) in [1, 2, 3, 4, 5, 6, 7, 8, 9].into_iter().enumerate() {
            fields[17 + i] = Fp::from(value);
        }
        let mut bytes = core::array::from_fn(|i| u8::try_from(i).unwrap().wrapping_mul(7));
        bytes[..4].copy_from_slice(&64u32.to_le_bytes());
        Self {
            fields,
            bytes,
            known: true,
            offset: 0,
            fixed_bytes: 64,
        }
    }
    fn public(&self) -> Vec<Fp> {
        let digest = hash_with_domain(STATEMENT_DOMAIN, &self.fields);
        let mut out = vec![
            digest,
            Fp::from(u64::from(u32::from_le_bytes(
                self.bytes[..4].try_into().unwrap(),
            ))),
        ];
        for message in self.bytes[4..].chunks_exact(32) {
            let low = u128::from_le_bytes(message[..16].try_into().unwrap());
            let high = u128::from_le_bytes(message[16..].try_into().unwrap());
            out.extend([
                Fp::from_u128(low),
                Fp::from_u128(high & ((1 << 127) - 1)),
                Fp::from_u128(high >> 127),
            ]);
        }
        out.push(digest);
        out
    }
    fn accepts(&self, public: &[Vec<Fp>]) -> bool {
        check_circuit(self, 16, public, CheckMode::Strict).is_ok_and(|r| r.is_satisfied())
    }
}
#[test]
fn shared_statement_hash_and_carrier_length_bytes_are_bound() {
    let circuit = Binding::new();
    let public = [circuit.public()];
    assert!(circuit.accepts(&public));
    let known = synthesize(&circuit, 16, Some(&public)).unwrap();
    let unknown = synthesize(&circuit.without_witnesses(), 16, None).unwrap();
    assert_eq!(known.tables.fixed(), unknown.tables.fixed());
    assert_eq!(
        known.tables.advice_assigned(),
        unknown.tables.advice_assigned()
    );
    for index in [0, 3, 4, 19, 20, 35, 36, 67] {
        let mut wrong = circuit.clone();
        wrong.bytes[index] ^= 1;
        assert!(!wrong.accepts(&public), "tape byte {index}");
    }
    for index in [0, 3, 13, 16, 21, 25] {
        let mut wrong = circuit.clone();
        wrong.fields[index] += Fp::ONE;
        assert!(!wrong.accepts(&public), "statement field {index}");
    }
    let mut overflow = circuit.clone();
    overflow.fields[21] = Fp::from_u128(u128::MAX);
    assert!(!overflow.accepts(&[overflow.public()]));
    for (offset, fixed_bytes) in [(1, 64), (0, 0), (0, 31), (0, 96), (usize::MAX, 64)] {
        let mut wrong = circuit.clone();
        wrong.offset = offset;
        wrong.fixed_bytes = fixed_bytes;
        assert!(!wrong.accepts(&public));
    }
}

#[derive(Clone)]
struct IncomingBinding {
    fields: [Fp; 26],
    known: bool,
}
impl Circuit<Fp> for IncomingBinding {
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
        let primary = meta.advice_column();
        let secondary = meta.advice_column();
        let bytes = BytesConfig::configure(meta, primary, secondary);
        let public = meta.instance_column(2);
        meta.enable_equality(public);
        Config {
            verifier,
            bytes,
            public,
        }
    }
    fn synthesize(&self, config: Config, mut layouter: impl Layouter<Fp>) -> Result<(), Error> {
        use iroha_kagemusha_proof::operation_relation::incoming_statement::IncomingStatementCells;
        use iroha_plonk_gadgets::UintChip;
        let mut chip = VerifierChip::new(config.verifier);
        chip.load_tables(&mut layouter)?;
        BytesChip::new(config.bytes).load_table(&mut layouter)?;
        let output = layouter.assign_region(
            || "total original incoming statement",
            |mut region| {
                let fields = self.fields.map(|value| {
                    if self.known {
                        Value::known(value)
                    } else {
                        Value::unknown()
                    }
                });
                let fields = chip
                    .uint()
                    .glue()
                    .witnesses(&mut region, &fields)?
                    .try_into()
                    .map_err(|_| Error::Synthesis)?;
                let lanes = chip.operation_lanes()?;
                let statement = IncomingStatementCells::constrain(
                    &mut UintChip::new(lanes.glue, lanes.range),
                    lanes.hash,
                    &mut region,
                    Variant::Send,
                    &fields,
                )?;
                let index = chip.uint().glue().constant(&mut region, Fp::from(5))?;
                let binding = SigmaBindingCells::from_incoming(&statement, index, vec![]);
                assert!(binding.hard_statement().is_err());
                assert!(binding.step_digest().is_err());
                let valid = binding
                    .statement()
                    .validity(&mut chip.uint(), &mut region)?;
                Ok([binding.statement().digest().clone(), valid.word().clone()])
            },
        )?;
        for (index, word) in output.iter().enumerate() {
            layouter.constrain_instance(word.cell(), config.public, index)?;
        }
        Ok(())
    }
}
#[test]
fn incoming_binding_keeps_original_invalid_statement_and_soft_bit() {
    let fields = Binding::new().fields;
    let mut circuit = IncomingBinding {
        fields,
        known: true,
    };
    for (bad_index, value) in [
        (None, Fp::ONE),
        (Some(16), Fp::from(9)),
        (Some(21), -Fp::ONE),
    ] {
        circuit.fields = fields;
        if let Some(index) = bad_index {
            circuit.fields[index] = value;
        }
        let expected = Fp::from(u64::from(bad_index.is_none()));
        let digest = hash_with_domain(STATEMENT_DOMAIN, &circuit.fields);
        let public = [vec![digest, expected]];
        assert!(
            check_circuit(&circuit, 16, &public, CheckMode::Strict)
                .unwrap()
                .is_satisfied()
        );
        assert!(
            !check_circuit(
                &circuit,
                16,
                &[vec![digest, Fp::ONE - expected]],
                CheckMode::Strict
            )
            .unwrap()
            .is_satisfied()
        );
        if bad_index.is_some() {
            assert!(
                !check_circuit(
                    &circuit,
                    16,
                    &[vec![hash_with_domain(STATEMENT_DOMAIN, &fields), expected]],
                    CheckMode::Strict
                )
                .unwrap()
                .is_satisfied()
            );
        }
        let known = synthesize(&circuit, 16, None).unwrap();
        let unknown = synthesize(&circuit.without_witnesses(), 16, None).unwrap();
        assert_eq!(known.tables.fixed(), unknown.tables.fixed());
        assert_eq!(
            known.tables.advice_assigned(),
            unknown.tables.advice_assigned()
        );
    }
}
