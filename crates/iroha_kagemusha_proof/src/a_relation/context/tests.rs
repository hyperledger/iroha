//! Injective typed Q framing for the fixed Receive context representation.

use super::*;
use iroha_pasta::Fq;
use iroha_plonk::{
    check::{CheckMode, check},
    cs::{Column, ConstraintSystem, Instance},
    frontend::{Circuit, Layouter, SimpleFloorPlanner, synthesize},
};
use iroha_plonk_gadgets::statement::foreign_limbs;
use iroha_plonk_recursion::verifier::VerifierConfig;

#[derive(Clone)]
struct InternalWords {
    words: Vec<Fp>,
    spec: ContextObjectSpec,
    known: bool,
}
impl Circuit<Fp> for InternalWords {
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
        let verifier = VerifierConfig::configure_serialized_foreign_tagged(meta, 3).unwrap();
        let public = meta.instance_column(2);
        meta.enable_equality(public);
        Config { verifier, public }
    }
    fn synthesize(&self, config: Config, mut layouter: impl Layouter<Fp>) -> Result<(), Error> {
        let mut chip = VerifierChip::new(config.verifier);
        chip.load_tables(&mut layouter)?;
        let out = layouter.assign_region(
            || "typed internal context",
            |mut r| {
                let values = self
                    .words
                    .iter()
                    .map(|v| {
                        if self.known {
                            Value::known(*v)
                        } else {
                            Value::unknown()
                        }
                    })
                    .collect::<Vec<_>>();
                let words = chip.uint().glue().witnesses(&mut r, &values)?;
                let bound =
                    ContextObjectCells::from_internal_words(&mut chip, &mut r, self.spec, &words)?;
                let [digest, length, tape] = bound.commitment_words();
                GlueChip::assert_equal(&mut r, &digest, &tape)?;
                Ok([digest, length])
            },
        )?;
        for (i, word) in out.iter().enumerate() {
            layouter.constrain_instance(word.cell(), config.public, i)?;
        }
        Ok(())
    }
}
impl InternalWords {
    fn public(&self) -> Vec<Vec<Fp>> {
        let mut words = vec![
            Fp::from(u64::from(self.spec.tag)),
            Fp::from(self.words.len() as u64),
        ];
        words.extend_from_slice(&self.words);
        vec![vec![
            iroha_pasta::poseidon::hash_with_domain(
                u64::from_le_bytes(INTERNAL_WORDS_DOMAIN),
                &words,
            ),
            Fp::from(u64::from(self.spec.capacity)),
        ]]
    }
    fn accepts(&self, public: &[Vec<Fp>]) -> bool {
        synthesize(self, 16, Some(public)).is_ok_and(|a| {
            check(&a.cs, &a.tables, CheckMode::Strict)
                .unwrap()
                .is_satisfied()
        })
    }
}

#[test]
fn internal_word_context_has_exact_domain_count_tag_and_original_words() {
    for count in [3, 578] {
        let c = InternalWords {
            words: (0..count).map(|i| Fp::from(i + 1)).collect(),
            spec: ContextObjectSpec {
                tag: 24,
                capacity: u32::try_from(count * 32).unwrap(),
            },
            known: true,
        };
        let public = c.public();
        assert!(c.accepts(&public));
        for i in [0, 1, 2, 255, 256, 511, 512, 575, 576, 577]
            .into_iter()
            .filter(|i| *i < usize::try_from(count).unwrap())
        {
            let mut changed = c.clone();
            changed.words[i] += Fp::ONE;
            assert!(!changed.accepts(&public), "word {i}");
        }
        let mut wrong = c.clone();
        wrong.spec.tag += 1;
        assert!(!wrong.accepts(&public));
        assert!(wrong.accepts(&wrong.public()));
        wrong.spec.capacity += 1;
        assert!(!wrong.accepts(&wrong.public()));
        wrong = c.clone();
        wrong.spec.tag = 0;
        assert!(!wrong.accepts(&wrong.public()));
        let known = synthesize(&c, 16, None).unwrap();
        let unknown = synthesize(&c.without_witnesses(), 16, None).unwrap();
        assert_eq!(known.tables.fixed(), unknown.tables.fixed());
        assert_eq!(known.tables.permutation(), unknown.tables.permutation());
        let mut input = vec![Fp::from(24), Fp::from(count)];
        input.extend_from_slice(&c.words);
        for domain in [TAPE_DOMAIN, ACTIVE_TAPE_DOMAIN, CONTEXT_DOMAIN] {
            assert_ne!(
                public[0][0],
                iroha_pasta::poseidon::hash_with_domain(u64::from_le_bytes(domain), &input)
            );
        }
    }
    let empty = InternalWords {
        words: vec![],
        spec: ContextObjectSpec {
            tag: 1,
            capacity: 0,
        },
        known: true,
    };
    assert!(!empty.accepts(&empty.public()));
}

#[derive(Clone, Debug)]
struct Config {
    verifier: VerifierConfig<Ep>,
    public: Column<Instance>,
}

#[derive(Clone)]
struct Encoding {
    value: Fq,
    ty: InstanceType,
    receive: bool,
    known: bool,
}

impl Circuit<Fp> for Encoding {
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
        let public = meta.instance_column(2);
        meta.enable_equality(public);
        Config { verifier, public }
    }
    fn synthesize(&self, config: Config, mut layouter: impl Layouter<Fp>) -> Result<(), Error> {
        let mut chip = VerifierChip::new(config.verifier);
        chip.load_tables(&mut layouter)?;
        let output = layouter.assign_region(
            || "typed Receive Q context",
            |mut region| {
                let witness = |value| {
                    if self.known {
                        Value::known(value)
                    } else {
                        Value::unknown()
                    }
                };
                let [lo, hi] = foreign_limbs(&self.value);
                let lo = chip.uint().assign::<128>(&mut region, witness(lo))?;
                let hi = chip.uint().assign::<127>(&mut region, witness(hi))?;
                let value = ScalarCells::from_limbs(&mut chip.uint(), &mut region, &lo, &hi)?;
                let mut words = Vec::new();
                push_q_context(
                    &mut words,
                    &mut chip,
                    &mut region,
                    &value,
                    self.ty,
                    self.receive,
                )?;
                assert_eq!(words.len(), if self.packed() { 1 } else { 2 });
                // Padding belongs only to this two-column test surface; the real
                // context appends exactly one or two words according to its schema.
                if words.len() == 1 {
                    words.push(chip.uint().glue().constant(&mut region, Fp::ZERO)?);
                }
                Ok(words)
            },
        )?;
        for (i, value) in output.iter().enumerate() {
            layouter.constrain_instance(value.cell(), config.public, i)?;
        }
        Ok(())
    }
}

impl Encoding {
    fn packed(&self) -> bool {
        self.receive && matches!(self.ty, InstanceType::Bounded | InstanceType::Bits(0..=253))
    }
    fn public(&self) -> Vec<Vec<Fp>> {
        let [lo, hi] = foreign_limbs(&self.value).map(Fp::from_u128);
        vec![if self.packed() {
            vec![lo + hi * Fp::from(2).pow_vartime([128]), Fp::ZERO]
        } else {
            vec![lo, hi]
        }]
    }
    fn accepts(&self, public: &[Vec<Fp>]) -> bool {
        synthesize(self, 16, Some(public)).is_ok_and(|a| {
            check(&a.cs, &a.tables, CheckMode::Strict)
                .unwrap()
                .is_satisfied()
        })
    }
}

#[test]
fn receive_typed_q_encoding_rejects_modular_aliases_and_exact_bit_overflow() {
    let p_minus_one = Fq::from_repr((-Fp::ONE).to_repr()).unwrap();
    for value in [Fq::ZERO, Fq::ONE, p_minus_one] {
        let c = Encoding {
            value,
            ty: InstanceType::Bounded,
            receive: true,
            known: true,
        };
        assert!(c.accepts(&c.public()));
        let mut wrong = c.public();
        wrong[0][0] += Fp::ONE;
        assert!(!c.accepts(&wrong));
    }
    for value in [p_minus_one + Fq::ONE, p_minus_one + Fq::from(2), -Fq::ONE] {
        let c = Encoding {
            value,
            ty: InstanceType::Bounded,
            receive: true,
            known: true,
        };
        assert!(
            !c.accepts(&c.public()),
            "a canonical Fq scalar is not an injective Fp encoding"
        );
        for ty in [InstanceType::Field, InstanceType::Bits(254)] {
            let full = Encoding { ty, ..c.clone() };
            assert!(!full.packed());
            assert!(full.accepts(&full.public()));
        }
    }
    for (value, expected) in [(7, true), (8, false)] {
        let c = Encoding {
            value: Fq::from(value),
            ty: InstanceType::Bits(3),
            receive: true,
            known: true,
        };
        assert_eq!(c.accepts(&c.public()), expected);
    }
    let explicit = Encoding {
        value: p_minus_one + Fq::ONE,
        ty: InstanceType::Bounded,
        receive: false,
        known: true,
    };
    assert!(!explicit.packed());
    assert!(
        explicit.accepts(&explicit.public()),
        "non-Receive retains the unchanged two-limb context format"
    );
}

#[test]
fn receive_typed_q_encoding_has_witness_independent_layout() {
    for ty in [
        InstanceType::Bounded,
        InstanceType::Bits(5),
        InstanceType::Field,
    ] {
        let c = Encoding {
            value: Fq::from(17),
            ty,
            receive: true,
            known: true,
        };
        let known = synthesize(&c, 16, Some(&c.public())).unwrap();
        let unknown = synthesize(&c.without_witnesses(), 16, None).unwrap();
        assert_eq!(known.cs, unknown.cs);
        assert_eq!(known.tables.fixed(), unknown.tables.fixed());
        assert_eq!(
            known.tables.advice_assigned(),
            unknown.tables.advice_assigned()
        );
        assert_eq!(known.tables.permutation(), unknown.tables.permutation());
    }
}

#[derive(Clone)]
struct MessageEncoding {
    bytes: [u8; 32],
    known: bool,
}
impl Circuit<Fp> for MessageEncoding {
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
        let verifier = VerifierConfig::configure_serialized_foreign_tagged(meta, 3).unwrap();
        let public = meta.instance_column(2);
        meta.enable_equality(public);
        Config { verifier, public }
    }
    fn synthesize(&self, config: Config, mut layouter: impl Layouter<Fp>) -> Result<(), Error> {
        let mut chip = VerifierChip::new(config.verifier);
        chip.load_tables(&mut layouter)?;
        let words = layouter.assign_region(
            || "two exact message halves",
            |mut region| {
                let message = iroha_plonk_gadgets::bytes::element::LeElement::assign(
                    &mut chip.uint(),
                    &mut region,
                    if self.known {
                        Value::known(self.bytes)
                    } else {
                        Value::unknown()
                    },
                )?;
                let mut words = Vec::new();
                push_message_context(&mut words, &mut chip, &mut region, &message)?;
                Ok(words)
            },
        )?;
        for (index, word) in words.iter().enumerate() {
            layouter.constrain_instance(word.cell(), config.public, index)?;
        }
        Ok(())
    }
}
impl MessageEncoding {
    fn public(&self) -> Vec<Vec<Fp>> {
        vec![
            self.bytes
                .chunks_exact(16)
                .map(|half| Fp::from_u128(u128::from_le_bytes(half.try_into().unwrap())))
                .collect(),
        ]
    }
    fn accepts(&self, public: &[Vec<Fp>]) -> bool {
        synthesize(self, 16, Some(public)).is_ok_and(|layout| {
            check(&layout.cs, &layout.tables, CheckMode::Strict)
                .unwrap()
                .is_satisfied()
        })
    }
}

#[test]
fn context_message_halves_preserve_all_bits_including_malformed_encodings() {
    let patterns = [
        [0; 32],
        [255; 32],
        core::array::from_fn(|i| u8::try_from(i * 7 + 19).unwrap()),
        {
            let mut bytes = [0; 32];
            bytes[31] = 128;
            bytes
        },
        {
            let mut bytes = [0; 32];
            bytes[15] = 128;
            bytes[16] = 1;
            bytes[31] = 64;
            bytes
        },
    ];
    let mut reference = None;
    for bytes in patterns {
        let source = MessageEncoding { bytes, known: true };
        let public = source.public();
        assert!(source.accepts(&public));
        let known = synthesize(&source, 16, Some(&public)).unwrap();
        let unknown = synthesize(&source.without_witnesses(), 16, None).unwrap();
        assert_eq!(known.tables.fixed(), unknown.tables.fixed());
        assert_eq!(known.tables.permutation(), unknown.tables.permutation());
        assert_eq!(
            known.tables.advice_assigned(),
            unknown.tables.advice_assigned()
        );
        if let Some((fixed, permutation, advice)) = &reference {
            assert_eq!(known.tables.fixed(), fixed);
            assert_eq!(known.tables.permutation(), permutation);
            assert_eq!(known.tables.advice_assigned(), advice);
        } else {
            reference = Some((
                known.tables.fixed().to_vec(),
                known.tables.permutation().clone(),
                known.tables.advice_assigned().to_vec(),
            ));
        }
        for half in 0..2 {
            let mut wrong = public.clone();
            wrong[0][half] += Fp::ONE;
            assert!(!source.accepts(&wrong), "changed half{half}");
        }
    }
    let source = MessageEncoding {
        bytes: patterns[2],
        known: true,
    };
    let original = source.public();
    for index in 0..32 {
        let mut changed = source.clone();
        changed.bytes[index] ^= 128;
        assert!(!changed.accepts(&original), "original byte{index}");
    }
}
