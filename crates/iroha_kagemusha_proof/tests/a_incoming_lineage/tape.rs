//! Exact public320 carrier decoding, malformed aliases and byte substitutions.

use super::*;
use iroha_kagemusha_proof::a_relation::own::ConsumingProofCells;
use iroha_plonk_gadgets::bytes::{
    chunk_segments,
    tape::{BytesChip, BytesConfig},
};

const PROOF_BYTES: usize = 32;
const LENGTH: usize = 4 + 320 + PROOF_BYTES + 1088;
const PUBLIC: usize = 37 + LENGTH.div_ceil(31);

#[derive(Clone, Debug)]
struct TapeConfig {
    base: Config,
    bytes: BytesConfig,
}
#[derive(Clone)]
struct Tape {
    bytes: Vec<u8>,
    key: Fp,
    known: bool,
}
impl Circuit<Fp> for Tape {
    type Config = TapeConfig;
    type FloorPlanner = SimpleFloorPlanner;
    type Params = ();
    fn without_witnesses(&self) -> Self {
        Self {
            known: false,
            ..self.clone()
        }
    }
    fn configure(meta: &mut ConstraintSystem<Fp>) -> Self::Config {
        let columns = core::array::from_fn(|_| meta.advice_column());
        let constants = meta.fixed_column();
        let glue = GlueConfig::configure(meta, columns, constants);
        let advice = meta.advice_column();
        let range = RunningSumConfig::configure(meta, advice, LimbBits::new(9).unwrap());
        let public = meta.instance_column(PUBLIC);
        meta.enable_equality(public);
        let a = meta.advice_column();
        let b = meta.advice_column();
        TapeConfig {
            base: Config {
                glue,
                range,
                public,
            },
            bytes: BytesConfig::configure(meta, a, b),
        }
    }
    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<Fp>,
    ) -> Result<(), Error> {
        let mut glue = GlueChip::new(config.base.glue);
        let mut range = RunningSumChip::new(config.base.range);
        let mut bytes = BytesChip::new(config.bytes);
        range.load_table(&mut layouter)?;
        bytes.load_table(&mut layouter)?;
        let output = layouter.assign_region(
            || "exact incoming public320",
            |mut region| {
                let witness = self
                    .bytes
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
                    &witness,
                    &chunk_segments(0, LENGTH),
                    &ConsumingProofCells::omega_segments(PROOF_BYTES)?,
                )?;
                let key = glue.witness(
                    &mut region,
                    if self.known {
                        Value::known(self.key)
                    } else {
                        Value::unknown()
                    },
                )?;
                let incoming = IncomingLineageCells::from_run(
                    &mut UintChip::new(&mut glue, &mut range),
                    &mut region,
                    &run,
                    PROOF_BYTES,
                    &key,
                )?;
                let mut output = incoming.fields().to_vec();
                output.extend(incoming.checked().fields().iter().cloned());
                output.push(incoming.valid().word().clone());
                // The untouched primary chunks model the caller's original-byte
                // commitment; aliases must never disappear behind selected zero.
                output.extend(
                    incoming
                        .carrier()?
                        .primary()
                        .iter()
                        .map(|segment| segment.word().clone()),
                );
                Ok(output)
            },
        )?;
        for (i, word) in output.iter().enumerate() {
            layouter.constrain_instance(word.cell(), config.base.public, i)?;
        }
        Ok(())
    }
}

fn input() -> Tape {
    let mut bytes = vec![0_u8; LENGTH];
    bytes[..4].copy_from_slice(&u32::try_from(LENGTH - 4).unwrap().to_le_bytes());
    let public = &mut bytes[4..324];
    public[..2].copy_from_slice(&1_u16.to_le_bytes());
    for (offset, value) in [
        (2, 3_u128),
        (18, u128::MAX),
        (34, 5),
        (50, 7),
        (98, 11),
        (114, 13),
    ] {
        public[offset..offset + 16].copy_from_slice(&value.to_le_bytes());
    }
    for (offset, value) in [
        (66, -Fp::ONE),
        (130, Fp::from(17)),
        (256, Fp::ZERO),
        (288, Fp::from(23)),
    ] {
        public[offset..offset + 32].copy_from_slice(&value.to_repr());
    }
    public[162] = 4;
    for (i, value) in [29_u128, 31, 37, u128::MAX].into_iter().enumerate() {
        public[163 + 16 * i..179 + 16 * i].copy_from_slice(&value.to_be_bytes());
    }
    public[227] = u8::MAX;
    public[228..236].copy_from_slice(&u64::MAX.to_le_bytes());
    public[236..240].copy_from_slice(&u32::MAX.to_le_bytes());
    public[240..256].copy_from_slice(&u128::MAX.to_le_bytes());
    Tape {
        bytes,
        key: Fp::from(41),
        known: true,
    }
}

fn reference(input: &Tape) -> Vec<Vec<Fp>> {
    let public = &input.bytes[4..324];
    let mut fields = [Fp::ZERO; 18];
    let le128 = |offset| {
        Fp::from_u128(u128::from_le_bytes(
            public[offset..offset + 16].try_into().unwrap(),
        ))
    };
    fields[0] = Fp::from(u64::from(u16::from_le_bytes(
        public[..2].try_into().unwrap(),
    )));
    let mut valid = fields[0] == Fp::ONE
        && public[162] == 4
        && u32::from_le_bytes(input.bytes[..4].try_into().unwrap())
            == u32::try_from(LENGTH - 4).unwrap();
    for (offset, index) in [(2, 1), (34, 3), (98, 6)] {
        fields[index] = le128(offset);
        fields[index + 1] = le128(offset + 16);
    }
    for (offset, index) in [(66, 5), (130, 8), (256, 15), (288, 16)] {
        let value = Option::<Fp>::from(Fp::from_repr(
            public[offset..offset + 32].try_into().unwrap(),
        ));
        valid &= value.is_some();
        fields[index] = value.unwrap_or(Fp::ZERO);
    }
    for (i, index) in [10, 9, 12, 11].into_iter().enumerate() {
        fields[index] = Fp::from_u128(u128::from_be_bytes(
            public[163 + 16 * i..179 + 16 * i].try_into().unwrap(),
        ));
    }
    let mut packed = [0; 16];
    packed[..13].copy_from_slice(&public[227..240]);
    fields[13] = Fp::from_u128(u128::from_le_bytes(packed));
    fields[14] = le128(240);
    fields[17] = input.key;
    let mut output = fields.to_vec();
    output.extend(if valid {
        fields
    } else {
        let mut dummy = [Fp::ZERO; 18];
        dummy[0] = Fp::ONE;
        dummy
    });
    output.push(Fp::from(u64::from(valid)));
    output.extend(input.bytes.chunks(31).map(|chunk| {
        let mut bytes = [0; 32];
        bytes[..chunk.len()].copy_from_slice(chunk);
        Fp::from_repr(bytes).unwrap()
    }));
    vec![output]
}

fn satisfied(input: &Tape, public: &[Vec<Fp>]) -> bool {
    check_circuit(input, 14, public, CheckMode::Strict)
        .unwrap()
        .is_satisfied()
}

#[test]
fn exact_public_carrier_matches_native_layout_and_preserves_every_original_byte() {
    let source = input();
    let public = reference(&source);
    assert_eq!(public[0][36], Fp::ONE);
    assert!(satisfied(&source, &public));
    for index in 0..324 {
        let mut changed = source.clone();
        changed.bytes[index] ^= 0x80;
        let expected = reference(&changed);
        assert!(satisfied(&changed, &expected), "total byte{index}");
        let mut forged = expected;
        // Keeping the old byte commitment must fail even if decoded fields and
        // the validity/dummy output are all consistently recomputed.
        forged[0][37..].copy_from_slice(&public[0][37..]);
        assert!(!satisfied(&changed, &forged), "original byte{index}");
    }
    let known = synthesize(&source, 14, None).unwrap();
    let unknown = synthesize(&source.without_witnesses(), 14, None).unwrap();
    assert_eq!(known.tables.fixed(), unknown.tables.fixed());
    assert_eq!(known.tables.permutation(), unknown.tables.permutation());
    assert_eq!(
        known.tables.advice_assigned(),
        unknown.tables.advice_assigned()
    );
    let rows = known
        .tables
        .advice_assigned()
        .iter()
        .map(|c| c.iter().rposition(|v| *v).map_or(0, |i| i + 1))
        .collect::<Vec<_>>();
    eprintln!("same-tape total incoming public320 rows={rows:?}");
}

#[test]
fn noncanonical_field_aliases_lengths_and_prefixes_cannot_forge_a_true_verdict() {
    let source = input();
    let mut modulus = (-Fp::ONE).to_repr();
    for byte in &mut modulus {
        let (next, carry) = byte.overflowing_add(1);
        *byte = next;
        if !carry {
            break;
        }
    }
    let mut cases = Vec::new();
    for offset in [66, 130, 256, 288] {
        for encoding in [modulus, [0xff; 32]] {
            let mut bad = source.clone();
            bad.bytes[4 + offset..36 + offset].copy_from_slice(&encoding);
            cases.push(bad);
        }
    }
    for (offset, value) in [(0, 0), (4, 2), (166, 2)] {
        let mut bad = source.clone();
        bad.bytes[offset] = value;
        cases.push(bad);
    }
    let good_shape = synthesize(&source, 14, None).unwrap();
    for bad in cases {
        let public = reference(&bad);
        assert_eq!(public[0][36], Fp::ZERO);
        assert!(satisfied(&bad, &public));
        let mut forged = public.clone();
        forged[0][36] = Fp::ONE;
        assert!(!satisfied(&bad, &forged));
        let mut forged = public;
        let original = forged[0][..18].to_vec();
        forged[0][18..36].copy_from_slice(&original);
        assert!(!satisfied(&bad, &forged));
        let shape = synthesize(&bad, 14, None).unwrap();
        assert_eq!(good_shape.tables.fixed(), shape.tables.fixed());
        assert_eq!(good_shape.tables.permutation(), shape.tables.permutation());
        assert_eq!(
            good_shape.tables.advice_assigned(),
            shape.tables.advice_assigned()
        );
    }
}

#[test]
fn every_public_carrier_decoder_cell_is_constrained() {
    let source = input();
    let undetected =
        iroha_plonk_gadgets::tamper::undetected_tampers(&source, 14, &reference(&source)).unwrap();
    assert!(undetected.is_empty(), "unbound cells: {undetected:?}");
}
