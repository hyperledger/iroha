//! Canonical transcript codecs, totality, boundary vectors and cell binding.

use core::marker::PhantomData;

use ff::{Field, PrimeField};
use iroha_pasta::{Ep, Eq, Fp, PastaAffine, PastaCurve, PastaField};
use iroha_plonk::{
    check::{CheckMode, check_circuit},
    cs::{Column, ConstraintSystem, Instance, InstanceType},
    frontend::{Circuit, Error, Layouter, SimpleFloorPlanner, Value, synthesize},
    transcript::{
        BasePoseidonHash, TranscriptHash, decode_point as native_point,
        decode_scalar as native_scalar, encode_point,
    },
};
use iroha_plonk_gadgets::{
    GlueChip, GlueConfig,
    bytes::{
        element::{decode_le_element, le_message_segments},
        tape::{BytesChip, BytesConfig},
    },
    ecc::{EccChip, EccConfig},
    poseidon::{Pow5Columns, RoundConstantColumns},
    pow5_fq::DuplexConfig,
    range::{
        running_sum::{LimbBits, RunningSumChip, RunningSumConfig},
        u128::UintChip,
    },
    statement::{bytes_to_limbs, foreign_limbs},
    tamper::{assigned_advice_cells, undetected_tampers},
};
use iroha_plonk_recursion::{
    codec::{
        ScalarCells, decode_point, decode_point_soft, decode_scalar, decode_scalar_soft,
        map_challenge,
    },
    transcript::{Domain, TranscriptChip},
};

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
enum Mode {
    Scalar {
        hard: bool,
        ty: InstanceType,
    },
    Point {
        hard: bool,
    },
    #[default]
    Challenge,
    Limbs,
    Native,
    Transcript,
}

impl Mode {
    const fn outputs(self) -> usize {
        match self {
            Self::Scalar { .. } => 6,
            Self::Point { .. } => 7,
            Self::Challenge => 3,
            Self::Limbs | Self::Native => 4,
            Self::Transcript => 8,
        }
    }
}

#[derive(Clone, Debug)]
struct Config<C: PastaCurve> {
    glue: GlueConfig,
    range: RunningSumConfig,
    bytes: BytesConfig,
    ecc: EccConfig<C>,
    duplex: DuplexConfig<C::Base>,
    public: Column<Instance>,
}

#[derive(Clone)]
struct Program<C: PastaCurve> {
    mode: Mode,
    bytes: [u8; 32],
    point: [u8; 32],
    word: C::Base,
    known: bool,
    marker: PhantomData<C>,
}

impl<C: PastaCurve> Program<C> {
    fn new(mode: Mode, bytes: [u8; 32]) -> Self {
        Self {
            mode,
            bytes,
            point: encode_point::<C>(&C::generator().to_affine()),
            word: C::Base::ZERO,
            known: true,
            marker: PhantomData,
        }
    }

    fn witness<T: Copy>(&self, value: T) -> Value<T> {
        if self.known {
            Value::known(value)
        } else {
            Value::unknown()
        }
    }
}

impl<C: PastaCurve> Circuit<C::Base> for Program<C> {
    type Config = Config<C>;
    type FloorPlanner = SimpleFloorPlanner;
    type Params = Mode;

    fn without_witnesses(&self) -> Self {
        Self {
            known: false,
            ..self.clone()
        }
    }
    fn params(&self) -> Mode {
        self.mode
    }
    fn configure(meta: &mut ConstraintSystem<C::Base>) -> Config<C> {
        Self::configure_with_params(meta, Mode::Challenge)
    }
    fn configure_with_params(meta: &mut ConstraintSystem<C::Base>, mode: Mode) -> Config<C> {
        let advice = core::array::from_fn(|_| meta.advice_column());
        let constants = meta.fixed_column();
        let glue = GlueConfig::configure(meta, advice, constants);
        let range_column = meta.advice_column();
        let range = RunningSumConfig::configure(meta, range_column, LimbBits::new(8).unwrap());
        let primary = meta.advice_column();
        let secondary = meta.advice_column();
        let bytes = BytesConfig::configure(meta, primary, secondary);
        let ecc_columns = core::array::from_fn(|_| meta.advice_column());
        let ecc = EccConfig::configure(meta, ecc_columns);
        let lane = Pow5Columns::allocate(meta);
        let constants = RoundConstantColumns::allocate(meta);
        let duplex = DuplexConfig::configure(meta, lane, constants, &[]);
        let public = meta.instance_column(mode.outputs());
        meta.enable_equality(public);
        Config {
            glue,
            range,
            bytes,
            ecc,
            duplex,
            public,
        }
    }

    fn synthesize(
        &self,
        config: Config<C>,
        mut layouter: impl Layouter<C::Base>,
    ) -> Result<(), Error> {
        let mut glue = GlueChip::new(config.glue);
        let mut range = RunningSumChip::new(config.range);
        let mut bytes = BytesChip::new(config.bytes);
        let mut ecc = EccChip::new(&config.ecc);
        range.load_table(&mut layouter)?;
        bytes.load_table(&mut layouter)?;
        let outputs = layouter.assign_region(
            || "codec",
            |mut region| {
                let mut uint = UintChip::new(&mut glue, &mut range);
                if self.mode == Mode::Challenge {
                    let word = uint.glue().witness(&mut region, self.witness(self.word))?;
                    let scalar = map_challenge::<C>(&mut uint, &mut region, &word)?;
                    return Ok(vec![word.cell(), scalar.lo().cell(), scalar.hi().cell()]);
                }
                if self.mode == Mode::Native {
                    let word = uint.glue().witness(&mut region, self.witness(self.word))?;
                    let scalar = ScalarCells::<C>::from_native_word(&mut uint, &mut region, &word)?;
                    let bounded =
                        scalar.instance_type(&mut uint, &mut region, InstanceType::Bounded)?;
                    return Ok(vec![
                        word.cell(),
                        scalar.lo().cell(),
                        scalar.hi().cell(),
                        bounded.cell(),
                    ]);
                }
                if self.mode == Mode::Limbs {
                    let [lo, hi] = bytes_to_limbs(&self.bytes);
                    let lo = uint.assign::<128>(&mut region, self.witness(lo))?;
                    let hi = uint.assign::<127>(&mut region, self.witness(hi))?;
                    let scalar = ScalarCells::<C>::from_limbs(&mut uint, &mut region, &lo, &hi)?;
                    return Ok(vec![
                        lo.cell(),
                        hi.cell(),
                        scalar.lo().cell(),
                        scalar.hi().cell(),
                    ]);
                }
                let input = self.bytes.map(|byte| self.witness(byte));
                let run = bytes.run(&mut region, &input, &[16, 16], &le_message_segments(0, 1))?;
                let mut out = run
                    .primary()
                    .iter()
                    .map(|segment| segment.word().cell())
                    .collect::<Vec<_>>();
                let element = decode_le_element(&mut uint, &mut region, &run, 0)?;
                match self.mode {
                    Mode::Scalar { hard, ty } => {
                        let (scalar, valid) = if hard {
                            let scalar = decode_scalar::<C>(&mut uint, &mut region, &element)?;
                            let one = uint.glue().constant(&mut region, C::Base::ONE)?;
                            (scalar, one)
                        } else {
                            let decoded =
                                decode_scalar_soft::<C>(&mut uint, &mut region, &element)?;
                            (decoded.value, decoded.valid.word().clone())
                        };
                        let membership = scalar.instance_type(&mut uint, &mut region, ty)?;
                        out.extend([
                            scalar.lo().cell(),
                            scalar.hi().cell(),
                            valid.cell(),
                            membership.cell(),
                        ]);
                    }
                    Mode::Point { hard } => {
                        let (point, valid) = if hard {
                            let point =
                                decode_point::<C>(&mut uint, &mut ecc, &mut region, &element)?;
                            let one = uint.glue().constant(&mut region, C::Base::ONE)?;
                            (point, one)
                        } else {
                            let decoded =
                                decode_point_soft::<C>(&mut uint, &mut ecc, &mut region, &element)?;
                            (decoded.value, decoded.valid.word().clone())
                        };
                        // Every decoded value, including a malformed input's dummy,
                        // enters complete inverse-point addition unconditionally.
                        let opposite = EccChip::<C>::neg(uint.glue(), &mut region, point.point())?;
                        let identity = ecc.add(&mut region, point.point(), &opposite)?;
                        out.extend([
                            point.x().cell(),
                            point.y().cell(),
                            valid.cell(),
                            identity.x().cell(),
                            identity.y().cell(),
                        ]);
                    }
                    Mode::Transcript => {
                        let scalar = decode_scalar::<C>(&mut uint, &mut region, &element)?;
                        let input = self.point.map(|byte| self.witness(byte));
                        let run = bytes.run(
                            &mut region,
                            &input,
                            &[16, 16],
                            &le_message_segments(0, 1),
                        )?;
                        out.extend(run.primary().iter().map(|segment| segment.word().cell()));
                        let element = decode_le_element(&mut uint, &mut region, &run, 0)?;
                        let point = decode_point::<C>(&mut uint, &mut ecc, &mut region, &element)?;
                        let mut transcript =
                            TranscriptChip::new(config.duplex.clone(), Domain::Proof);
                        transcript.common_scalar(&scalar);
                        transcript.common_point(&point);
                        let first = transcript.squeeze_scalar::<C>(&mut uint, &mut region)?;
                        transcript.common_scalar(&first);
                        let second = transcript.squeeze_scalar::<C>(&mut uint, &mut region)?;
                        out.extend([
                            first.lo().cell(),
                            first.hi().cell(),
                            second.lo().cell(),
                            second.hi().cell(),
                        ]);
                    }
                    Mode::Challenge | Mode::Limbs | Mode::Native => return Err(Error::Synthesis),
                }
                Ok(out)
            },
        )?;
        for (row, cell) in outputs.into_iter().enumerate() {
            layouter.constrain_instance(cell, config.public, row)?;
        }
        Ok(())
    }
}

fn bytes_fields<F: PastaField>(bytes: &[u8; 32]) -> Vec<F> {
    bytes_to_limbs(bytes).map(F::from_u128).to_vec()
}

fn accepts<C: PastaCurve>(circuit: &Program<C>, expected: Vec<C::Base>) -> bool {
    check_circuit(circuit, 11, &[expected], CheckMode::Strict)
        .expect("layout")
        .is_satisfied()
}

fn modulus<F: PastaField>() -> [u8; 32] {
    increment((-F::ONE).to_repr())
}
fn increment(mut value: [u8; 32]) -> [u8; 32] {
    for byte in &mut value {
        let (next, carry) = byte.overflowing_add(1);
        *byte = next;
        if !carry {
            break;
        }
    }
    value
}
fn subtract(left: [u8; 32], right: [u8; 32]) -> [u8; 32] {
    let mut borrow = false;
    core::array::from_fn(|i| {
        let (a, first) = left[i].overflowing_sub(right[i]);
        let (b, second) = a.overflowing_sub(u8::from(borrow));
        borrow = first || second;
        b
    })
}
fn less(left: &[u8; 32], right: &[u8; 32]) -> bool {
    left.iter().rev().cmp(right.iter().rev()).is_lt()
}

fn scalar_expected<C: PastaCurve>(bytes: &[u8; 32], ty: InstanceType) -> Vec<C::Base> {
    let scalar = native_scalar::<C::ScalarExt>(bytes);
    let valid = scalar.is_ok();
    let value = scalar.unwrap_or(C::ScalarExt::ZERO);
    let mut out = bytes_fields::<C::Base>(bytes);
    out.extend(foreign_limbs(&value).map(C::Base::from_u128));
    out.push(C::Base::from(u64::from(valid)));
    let member = match ty {
        InstanceType::Field => true,
        InstanceType::Bounded => less(&value.to_repr(), &modulus::<Fp>()),
        InstanceType::Bits(bits) => {
            let mut limit = [0_u8; 32];
            limit[usize::from(bits / 8)] = 1 << (bits % 8);
            less(&value.to_repr(), &limit)
        }
    };
    out.push(C::Base::from(u64::from(member)));
    out
}

fn point_expected<C: PastaCurve>(bytes: &[u8; 32]) -> Vec<C::Base> {
    let point = native_point::<C>(bytes);
    let valid = point.is_ok();
    let (x, y) = point
        .ok()
        .and_then(|p| Option::from(p.coordinates()))
        .unwrap_or_else(|| (-C::Base::ONE, C::Base::from(2)));
    let mut out = bytes_fields::<C::Base>(bytes);
    out.extend([
        x,
        y,
        C::Base::from(u64::from(valid)),
        C::Base::ZERO,
        C::Base::ZERO,
    ]);
    out
}

fn scalar_boundaries<C: PastaCurve>() {
    let scalar_modulus = modulus::<C::ScalarExt>();
    let mut top = [0; 32];
    top[31] = 128;
    let vectors = [
        [0; 32],
        C::ScalarExt::ONE.to_repr(),
        (-C::ScalarExt::ONE).to_repr(),
        scalar_modulus,
        increment(scalar_modulus),
        modulus::<Fp>(),
        [255; 32],
        top,
    ];
    for bytes in vectors {
        for ty in [
            InstanceType::Field,
            InstanceType::Bounded,
            InstanceType::Bits(0),
            InstanceType::Bits(1),
            InstanceType::Bits(127),
            InstanceType::Bits(128),
            InstanceType::Bits(253),
        ] {
            let mut circuit = Program::<C>::new(Mode::Scalar { hard: false, ty }, bytes);
            let expected = scalar_expected::<C>(&bytes, ty);
            assert!(
                accepts(&circuit, expected.clone()),
                "soft scalar {bytes:?} {ty:?}"
            );
            for output in 2..expected.len() {
                let mut forged = expected.clone();
                forged[output] += C::Base::ONE;
                assert!(!accepts(&circuit, forged));
            }
            circuit.mode = Mode::Scalar { hard: true, ty };
            let native = native_scalar::<C::ScalarExt>(&bytes).is_ok();
            assert_eq!(accepts(&circuit, expected), native, "hard scalar");
        }
    }
    for bytes in vectors {
        let circuit = Program::<C>::new(Mode::Limbs, bytes);
        let mut expected = bytes_fields::<C::Base>(&bytes);
        expected.extend(expected.clone());
        assert_eq!(
            accepts(&circuit, expected),
            native_scalar::<C::ScalarExt>(&bytes).is_ok()
        );
    }
    for bits in [0, 1, 127, 128, 253] {
        let mut boundary = [0; 32];
        boundary[usize::from(bits / 8)] = 1 << (bits % 8);
        for bytes in [
            subtract(boundary, C::ScalarExt::ONE.to_repr()),
            boundary,
            increment(boundary),
        ] {
            let ty = InstanceType::Bits(bits);
            let circuit = Program::<C>::new(Mode::Scalar { hard: false, ty }, bytes);
            assert!(accepts(&circuit, scalar_expected::<C>(&bytes, ty)));
        }
    }
    let invalid = Program::<C>::new(
        Mode::Scalar {
            hard: false,
            ty: InstanceType::Bits(254),
        },
        [0; 32],
    );
    assert!(matches!(
        check_circuit(&invalid, 11, &[vec![C::Base::ZERO; 6]], CheckMode::Strict),
        Err(Error::Synthesis)
    ));
}

#[test]
fn scalar_encodings_and_typed_instances_match_native_boundaries() {
    scalar_boundaries::<Ep>();
    scalar_boundaries::<Eq>();
}

#[test]
fn native_embedding_retains_its_hard_bound_and_all_cells_on_both_curves() {
    fn run<C: PastaCurve>() {
        for bytes in [
            C::Base::ZERO.to_repr(),
            C::Base::ONE.to_repr(),
            (-C::Base::ONE).to_repr(),
            (-Fp::ONE).to_repr(),
            modulus::<Fp>(),
            increment(modulus::<Fp>()),
        ] {
            let Ok(word) = native_scalar::<C::Base>(&bytes) else {
                continue;
            };
            let mut circuit = Program::<C>::new(Mode::Native, [0; 32]);
            circuit.word = word;
            let mut public = vec![word];
            public.extend(bytes_fields::<C::Base>(&bytes));
            public.push(C::Base::ONE);
            assert_eq!(
                accepts(&circuit, public.clone()),
                native_scalar::<C::ScalarExt>(&bytes).is_ok(),
                "native embedding must prove both moduli, {bytes:?}",
            );
            if bytes != (-Fp::ONE).to_repr() {
                continue;
            }
            let assigned = synthesize(&circuit, 11, Some(std::slice::from_ref(&public))).unwrap();
            let unknown = synthesize(&circuit.without_witnesses(), 11, None).unwrap();
            assert_eq!(assigned.tables.fixed(), unknown.tables.fixed());
            assert_eq!(assigned.tables.permutation(), unknown.tables.permutation());
            assert_eq!(
                assigned.tables.advice_assigned(),
                unknown.tables.advice_assigned()
            );
            assert!(
                undetected_tampers(&circuit, 11, std::slice::from_ref(&public))
                    .unwrap()
                    .is_empty()
            );
            for output in 0..4 {
                let mut changed = public.clone();
                changed[output] += C::Base::ONE;
                assert!(!accepts(&circuit, changed));
            }
        }
    }
    run::<Ep>();
    run::<Eq>();
}

fn challenge_boundaries<C: PastaCurve>() {
    let p = modulus::<Fp>();
    let mut vectors = vec![
        [0; 32],
        C::Base::ONE.to_repr(),
        (-C::Base::ONE).to_repr(),
        (-Fp::ONE).to_repr(),
        p,
        increment(p),
    ];
    vectors.retain(|bytes| native_scalar::<C::Base>(bytes).is_ok());
    for bytes in vectors {
        let mut circuit = Program::<C>::new(Mode::Challenge, [0; 32]);
        circuit.word = native_scalar::<C::Base>(&bytes).unwrap();
        let reduced = if C::ScalarExt::MODULUS == Fp::MODULUS && !less(&bytes, &p) {
            subtract(bytes, p)
        } else {
            bytes
        };
        let mut expected = vec![circuit.word];
        expected.extend(bytes_fields::<C::Base>(&reduced));
        assert!(accepts(&circuit, expected.clone()));
        for forged_bytes in [
            bytes,
            increment(reduced),
            modulus::<C::ScalarExt>(),
            subtract(modulus::<C::Base>(), p),
        ] {
            if forged_bytes == reduced {
                continue;
            }
            let mut forged = vec![circuit.word];
            forged.extend(bytes_fields::<C::Base>(&forged_bytes));
            assert!(
                !accepts(&circuit, forged),
                "challenge alias {forged_bytes:?}"
            );
        }
    }
}

#[test]
fn challenge_map_is_exact_across_both_modulus_boundaries() {
    challenge_boundaries::<Ep>();
    challenge_boundaries::<Eq>();
}

fn points<C: PastaCurve>() {
    let generator = C::generator();
    let mut signed_zero = [0; 32];
    signed_zero[31] = 128;
    let mut vectors = vec![
        encode_point::<C>(&generator.to_affine()),
        encode_point::<C>(&(-generator).to_affine()),
        encode_point::<C>(&generator.double().to_affine()),
        [0; 32],
        signed_zero,
        modulus::<C::Base>(),
        increment(modulus::<C::Base>()),
        [255; 32],
    ];
    // An on-curve x with the full base modulus added is a consistent
    // field-residue alias. Its curve equation still holds, but its bytes fail.
    let x = (1_u64..256)
        .find(|x| native_point::<C>(&C::Base::from(*x).to_repr()).is_ok())
        .unwrap();
    let canonical = C::Base::from(x).to_repr();
    let alias = (0..x).fold(modulus::<C::Base>(), |value, _| increment(value));
    assert!(native_point::<C>(&alias).is_err());
    vectors.extend([canonical, alias]);
    // Deterministic arbitrary byte strings exercise soft totality, independent
    // of whether x^3+5 is square and whether the encoding is canonical.
    let mut seed = 0x55aa_0134_9876_3210_u64;
    for _ in 0..32 {
        vectors.push(core::array::from_fn(|_| {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed.to_le_bytes()[0]
        }));
    }
    for bytes in vectors {
        let mut circuit = Program::<C>::new(Mode::Point { hard: false }, bytes);
        let expected = point_expected::<C>(&bytes);
        assert!(accepts(&circuit, expected.clone()), "total point {bytes:?}");
        let mut wrong_bit = expected.clone();
        wrong_bit[4] = C::Base::ONE - wrong_bit[4];
        assert!(!accepts(&circuit, wrong_bit));
        circuit.mode = Mode::Point { hard: true };
        assert_eq!(
            accepts(&circuit, expected),
            native_point::<C>(&bytes).is_ok()
        );
    }
}

#[test]
fn every_point_encoding_has_the_native_verdict_and_safe_complete_arithmetic() {
    points::<Ep>();
    points::<Eq>();
}

fn transcript<C: PastaCurve>() {
    let mut scalars = vec![C::ScalarExt::ZERO, C::ScalarExt::ONE, -C::ScalarExt::ONE];
    for bytes in [modulus::<Fp>(), increment(modulus::<Fp>())] {
        if let Ok(value) = native_scalar::<C::ScalarExt>(&bytes) {
            scalars.push(value);
        }
    }
    for scalar in scalars {
        let circuit = Program::<C>::new(Mode::Transcript, scalar.to_repr());
        let mut native = BasePoseidonHash::<C>::new();
        native.absorb_scalar(&scalar);
        native.absorb_point(&C::generator().to_affine()).unwrap();
        let first = native.squeeze();
        native.absorb_scalar(&first);
        let second = native.squeeze();
        let mut expected = bytes_fields::<C::Base>(&circuit.bytes);
        expected.extend(bytes_fields::<C::Base>(&circuit.point));
        expected.extend(foreign_limbs(&first).map(C::Base::from_u128));
        expected.extend(foreign_limbs(&second).map(C::Base::from_u128));
        assert!(accepts(&circuit, expected.clone()));
        let known = synthesize(&circuit, 11, Some(&[expected])).unwrap();
        let unknown = synthesize(&circuit.without_witnesses(), 11, None).unwrap();
        assert_eq!(
            known.tables.advice_assigned(),
            unknown.tables.advice_assigned()
        );
        assert_eq!(known.tables.fixed(), unknown.tables.fixed());
        assert_eq!(known.tables.selectors(), unknown.tables.selectors());
    }
}

#[test]
fn typed_absorption_and_continuing_challenges_match_native_with_unknown_layout_parity() {
    transcript::<Ep>();
    transcript::<Eq>();
}

fn tamper<C: PastaCurve>() {
    let scalar = Program::<C>::new(
        Mode::Scalar {
            hard: false,
            ty: InstanceType::Bounded,
        },
        (-C::ScalarExt::ONE).to_repr(),
    );
    let point = Program::<C>::new(Mode::Point { hard: false }, [0; 32]);
    let valid_point = Program::<C>::new(
        Mode::Point { hard: false },
        encode_point::<C>(&C::generator().to_affine()),
    );
    let invalid_scalar = Program::<C>::new(
        Mode::Scalar {
            hard: false,
            ty: InstanceType::Bounded,
        },
        modulus::<C::ScalarExt>(),
    );
    let mut challenge = Program::<C>::new(Mode::Challenge, [0; 32]);
    challenge.word = -C::Base::ONE;
    let reduced = if C::ScalarExt::MODULUS == Fp::MODULUS {
        subtract(challenge.word.to_repr(), modulus::<Fp>())
    } else {
        challenge.word.to_repr()
    };
    let mut expected_challenge = vec![challenge.word];
    expected_challenge.extend(bytes_fields::<C::Base>(&reduced));
    let mut small_challenge = challenge.clone();
    small_challenge.word = C::Base::ONE;
    for (name, circuit, expected, inventory) in [
        (
            "scalar",
            &scalar,
            scalar_expected::<C>(&scalar.bytes, InstanceType::Bounded),
            if C::ScalarExt::MODULUS == Fp::MODULUS {
                (34, 149)
            } else {
                (66, 204)
            },
        ),
        (
            "invalid scalar",
            &invalid_scalar,
            scalar_expected::<C>(&invalid_scalar.bytes, InstanceType::Bounded),
            if C::ScalarExt::MODULUS == Fp::MODULUS {
                (34, 149)
            } else {
                (66, 204)
            },
        ),
        (
            "point",
            &point,
            point_expected::<C>(&point.bytes),
            (100, 273),
        ),
        (
            "valid point",
            &valid_point,
            point_expected::<C>(&valid_point.bytes),
            (100, 273),
        ),
        (
            "challenge",
            &challenge,
            expected_challenge,
            if C::ScalarExt::MODULUS == Fp::MODULUS {
                (163, 227)
            } else {
                (66, 84)
            },
        ),
        (
            "small challenge",
            &small_challenge,
            vec![C::Base::ONE, C::Base::ONE, C::Base::ZERO],
            if C::ScalarExt::MODULUS == Fp::MODULUS {
                (163, 227)
            } else {
                (66, 84)
            },
        ),
    ] {
        let instances = [expected];
        let cells = assigned_advice_cells(circuit, 10, &instances).unwrap();
        let rows = cells.iter().map(|(_, row)| row + 1).max().unwrap();
        assert_eq!((rows, cells.len()), inventory, "{} {name}", C::CURVE_ID);
        let known = synthesize(circuit, 10, Some(&instances)).unwrap();
        let unknown = synthesize(&circuit.without_witnesses(), 10, None).unwrap();
        assert_eq!(
            known.tables.advice_assigned(),
            unknown.tables.advice_assigned()
        );
        assert_eq!(known.tables.fixed(), unknown.tables.fixed());
        assert_eq!(known.tables.selectors(), unknown.tables.selectors());
        assert!(
            undetected_tampers(circuit, 10, &instances)
                .unwrap()
                .is_empty(),
            "{} {name}",
            C::CURVE_ID
        );
    }
}

#[test]
fn every_assigned_codec_cell_is_bound() {
    tamper::<Ep>();
    tamper::<Eq>();
}
