//! Key generation, the `0x02` codec and the proving-key tables.

use ff::Field;
use iroha_pasta::{Ep, Eq, Fp, PastaCurve, PastaField, fft::FftDomain, msm::MemoryBudget};

use super::*;
use crate::{
    cs::{
        Advice, Any, Column, ConstraintSystem, Fixed, Instance, PermutationArgument,
        PermutationAssembly, Rotation, Selector, TableColumn, TranscriptV1, transcript_repr,
    },
    frontend::{Circuit, Error, Layouter, SimpleFloorPlanner, Value},
    pcs::ipa::{
        PinnedParams,
        commit::{Secrecy, commit_lagrange},
    },
    transcript::TranscriptError,
};

/// Columns of the test circuit.
#[derive(Clone, Copy, Debug)]
struct TestConfig {
    a: Column<Advice>,
    b: Column<Advice>,
    c: Column<Advice>,
    coeff: Column<Fixed>,
    instance: Column<Instance>,
    mul: Selector,
    add: Selector,
    range: Selector,
    table: TableColumn,
}

/// `mul * (a b - c)` and `add * (a + coeff b - c)` on alternating rows (two
/// simple selectors that compression combines), a range lookup of `a` into
/// `0..8`, a constant, copies `c[i] = a[i+1]` and the public output.
#[derive(Clone, Copy, Debug)]
struct TestCircuit {
    rows: usize,
}

const ROWS: usize = 4;

#[test]
fn verifier_only_binding_matches_full_keys_on_both_curves() {
    fn check<C: PastaCurve>() {
        let params = PinnedParams::<C>::derive(6).expect("parameters");
        let config = KeygenConfigV2::pipa_r(vec![crate::cs::InstanceType::Field]);
        let circuit = TestCircuit { rows: ROWS };
        let (binding, key) =
            keygen_vk_with_binding_v2(&params, &circuit, &config).expect("verifier");
        let pk = keygen_pk_v2(&params, &circuit, &config).expect("prover");
        assert_eq!(&binding, pk.binding());
        assert_eq!(key.to_bytes(), pk.vk().to_bytes());
        assert_eq!(key.descriptor_digest(), binding.digest());
        assert_eq!(
            keygen_vk_v2(&params, &circuit, &config)
                .expect("key only")
                .to_bytes(),
            key.to_bytes()
        );
        let mut wrong = config;
        wrong.instance_types.clear();
        assert!(keygen_vk_with_binding_v2(&params, &circuit, &wrong).is_err());
    }
    check::<Ep>();
    check::<Eq>();
}

impl<F: PastaField> Circuit<F> for TestCircuit {
    type Config = TestConfig;
    type FloorPlanner = SimpleFloorPlanner;
    type Params = ();

    fn without_witnesses(&self) -> Self {
        *self
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> TestConfig {
        let a = meta.advice_column();
        let b = meta.advice_column();
        let c = meta.advice_column();
        let constants = meta.fixed_column();
        meta.enable_constant(constants);
        let coeff = meta.fixed_column();
        let instance = meta.instance_column(1);
        for column in [a, c] {
            meta.enable_equality(column);
        }
        meta.enable_equality(instance);
        let mul = meta.selector();
        let add = meta.selector();
        meta.create_gate("mul", |cells| {
            let enabled = cells.query_selector(mul);
            let left = cells.query_advice(a, Rotation::cur());
            let right = cells.query_advice(b, Rotation::cur());
            let out = cells.query_advice(c, Rotation::cur());
            vec![enabled * (left * right - out)]
        });
        meta.create_gate("add", |cells| {
            let enabled = cells.query_selector(add);
            let left = cells.query_advice(a, Rotation::cur());
            let right = cells.query_advice(b, Rotation::cur());
            let scale = cells.query_fixed(coeff, Rotation::cur());
            let out = cells.query_advice(c, Rotation::cur());
            vec![enabled * (left + scale * right - out)]
        });
        let range = meta.complex_selector();
        let table = meta.lookup_table_column();
        meta.lookup("range", |cells| {
            let enabled = cells.query_selector(range);
            let left = cells.query_advice(a, Rotation::cur());
            vec![(enabled * left, table)]
        });
        TestConfig {
            a,
            b,
            c,
            coeff,
            instance,
            mul,
            add,
            range,
            table,
        }
    }

    fn synthesize(&self, config: TestConfig, mut layouter: impl Layouter<F>) -> Result<(), Error> {
        layouter.assign_table(
            || "range",
            |mut table| {
                for value in 0..8_u64 {
                    let offset = usize::try_from(value).map_err(|_| Error::Synthesis)?;
                    table.assign_cell(
                        || "v",
                        config.table,
                        offset,
                        || Value::known(F::from(value)),
                    )?;
                }
                Ok(())
            },
        )?;
        let last = layouter.assign_region(
            || "chain",
            |mut region| {
                let mut a_value = F::from(2);
                let mut previous = None;
                let mut last = None;
                for row in 0..self.rows {
                    let b_value = F::from(1 + row as u64);
                    let c_value = if row % 2 == 0 {
                        config.mul.enable(&mut region, row)?;
                        a_value * b_value
                    } else {
                        config.add.enable(&mut region, row)?;
                        region.assign_fixed(config.coeff, row, F::from(3))?;
                        a_value + F::from(3) * b_value
                    };
                    if row < 2 {
                        region.enable_selector(|| "range", &config.range, row)?;
                    }
                    let a = if row == 0 {
                        region
                            .assign_advice_from_constant(|| "two", config.a, 0, F::from(2))?
                            .cell()
                    } else {
                        region
                            .assign_advice(config.a, row, Value::known(a_value))?
                            .cell()
                    };
                    if let Some(previous) = previous {
                        region.constrain_equal(previous, a)?;
                    }
                    region.assign_advice(config.b, row, Value::known(b_value))?;
                    let c = region.assign_advice(config.c, row, Value::known(c_value))?;
                    previous = Some(c.cell());
                    last = Some(c.cell());
                    a_value = c_value;
                }
                last.ok_or(Error::Synthesis)
            },
        )?;
        layouter.constrain_instance(last, config.instance, 0)
    }
}

const K: u32 = 6;
const CIRCUIT: TestCircuit = TestCircuit { rows: ROWS };

#[test]
fn proving_key_artifact_round_trip_proves_on_both_curves() {
    fn check<C: PastaCurve>() {
        use crate::{ProverConfig, ProverRandomness, Witness, create_proof_owned, verify_full};
        let params = params::<C>();
        for compress in [true, false] {
            let mut profile = KeygenConfigV2::pipa_r(vec![crate::cs::InstanceType::Field]);
            profile.compress_selectors = compress;
            let original = keygen_pk_v2(&params, &CIRCUIT, &profile).expect("frozen producer");
            let encoded = original.artifact_bytes_v2().expect("original bytes");
            let config = pk::artifact::ReadConfig {
                maximum_bytes: encoded.len(),
                maximum_rows: 1 << K,
                coset_cache: CosetCachePolicy::OnDemand,
                msm_budget: MemoryBudget::DEFAULT,
            };
            let imported = ProvingKey::<C>::from_artifact_v2(
                &encoded,
                original.binding(),
                &params,
                &CIRCUIT,
                config,
            )
            .expect("installed original");
            assert!(!imported.has_coset_cache());
            assert_eq!(imported.artifact_bytes_v2().unwrap(), encoded);
            assert_eq!(imported.fixed_polys(), original.fixed_polys());
            assert_eq!(imported.permutation_polys(), original.permutation_polys());
            assert_eq!(imported.mask_polys(), original.mask_polys());
            let instances = vec![vec![C::ScalarExt::from(36)]];
            let witness = Witness::from_circuit(&imported, &CIRCUIT, &instances).unwrap();
            let proof = create_proof_owned(
                &params,
                &imported,
                witness,
                ProverRandomness::hedged(),
                ProverConfig::default(),
            )
            .expect("actual imported proof");
            verify_full(
                &params,
                original.binding(),
                original.vk(),
                &instances,
                &proof,
                MemoryBudget::DEFAULT,
            )
            .expect("actual original VK");
            let mut changed = instances;
            changed[0][0] += C::ScalarExt::ONE;
            assert!(
                verify_full(
                    &params,
                    original.binding(),
                    original.vk(),
                    &changed,
                    &proof,
                    MemoryBudget::DEFAULT
                )
                .is_err()
            );
        }
    }
    check::<Ep>();
    check::<Eq>();
}

#[test]
fn proving_key_artifact_rejects_source_encoding_allocation_and_commitment_changes() {
    use pk::artifact::{Error as ArtifactError, ReadConfig};
    #[derive(Clone, Copy)]
    struct NeverSynthesize;
    impl<F: PastaField> Circuit<F> for NeverSynthesize {
        type Config = ();
        type FloorPlanner = SimpleFloorPlanner;
        type Params = ();
        fn without_witnesses(&self) -> Self {
            panic!("invalid original reached synthesis")
        }
        fn configure(_: &mut ConstraintSystem<F>) {
            panic!("invalid original reached configuration")
        }
        fn synthesize(&self, (): (), _: impl Layouter<F>) -> Result<(), Error> {
            panic!("invalid original reached layout")
        }
    }
    let params = params::<Ep>();
    let profile = KeygenConfigV2::pipa_r(vec![crate::cs::InstanceType::Field]);
    let original = keygen_pk_v2(&params, &CIRCUIT, &profile).unwrap();
    let encoded = original.artifact_bytes_v2().unwrap();
    let config = ReadConfig {
        maximum_bytes: encoded.len(),
        maximum_rows: 1 << K,
        coset_cache: CosetCachePolicy::OnDemand,
        msm_budget: MemoryBudget::DEFAULT,
    };
    let read = |bytes: &[u8], source: &TestCircuit, selected: ReadConfig| {
        ProvingKey::<Ep>::from_artifact_v2(bytes, original.binding(), &params, source, selected)
            .err()
    };
    for bytes in [&encoded[..0], &encoded[..43], &encoded[..encoded.len() - 1]] {
        assert_eq!(read(bytes, &CIRCUIT, config), Some(ArtifactError::Length));
    }
    let mut extended = encoded.clone();
    extended.push(0);
    assert_eq!(
        read(&extended, &CIRCUIT, config),
        Some(ArtifactError::Length)
    );
    for index in [0, 8, 39] {
        let mut changed = encoded.clone();
        changed[index] ^= 1;
        assert_eq!(
            read(&changed, &CIRCUIT, config),
            Some(ArtifactError::Encoding)
        );
    }
    let mut changed = encoded.clone();
    changed[40] ^= 1;
    assert_eq!(
        read(&changed, &CIRCUIT, config),
        Some(ArtifactError::Length)
    );
    let mut cap = config;
    cap.maximum_bytes -= 1;
    assert_eq!(read(&encoded, &CIRCUIT, cap), Some(ArtifactError::Length));
    cap = config;
    cap.maximum_rows -= 1;
    assert_eq!(read(&encoded, &CIRCUIT, cap), Some(ArtifactError::Length));
    assert_eq!(
        ProvingKey::<Ep>::from_artifact_v2(
            &encoded,
            original.binding(),
            &params,
            &NeverSynthesize,
            cap
        )
        .err(),
        Some(ArtifactError::Length)
    );
    let mut malformed = encoded.clone();
    malformed[0] ^= 1;
    assert_eq!(
        ProvingKey::<Ep>::from_artifact_v2(
            &malformed,
            original.binding(),
            &params,
            &NeverSynthesize,
            config
        )
        .err(),
        Some(ArtifactError::Encoding)
    );
    assert!(read(&encoded, &TestCircuit { rows: ROWS + 1 }, config).is_some());
    let vk_end = 44 + original.vk().to_bytes().len();
    let mut changed = encoded.clone();
    changed[vk_end] ^= 1;
    assert_eq!(
        read(&changed, &CIRCUIT, config),
        Some(ArtifactError::Source)
    );
    let mut changed = encoded.clone();
    changed[vk_end + 32..vk_end + 64].fill(0xff);
    assert_eq!(
        read(&changed, &CIRCUIT, config),
        Some(ArtifactError::Encoding)
    );
    let mut changed = encoded.clone();
    changed[vk_end + 32..vk_end + 64].fill(0);
    changed[vk_end + 32] = 19;
    assert_eq!(
        read(&changed, &CIRCUIT, config),
        Some(ArtifactError::Source)
    );
    let sigma_start = vk_end + 32 + original.fixed_values().len() * original.binding().n() * 32;
    let mut changed = encoded.clone();
    changed[sigma_start..sigma_start + 32].fill(0);
    changed[sigma_start] = 19;
    assert_eq!(
        read(&changed, &CIRCUIT, config),
        Some(ArtifactError::Source)
    );
    let selectors_start =
        44 + 10 + (original.fixed_values().len() + original.permutation_values().len()) * 32;
    let mut changed = encoded.clone();
    changed[selectors_start] ^= 1;
    assert!(read(&changed, &CIRCUIT, config).is_some());
    // A valid point in another column leaves codec/profile valid but changes the commitment.
    let mut changed = encoded.clone();
    let alternate = &original.vk().to_bytes()[10 + 32..10 + 64];
    assert_ne!(&encoded[44 + 10..44 + 10 + 32], alternate);
    changed[44 + 10..44 + 10 + 32].copy_from_slice(alternate);
    assert_eq!(
        read(&changed, &CIRCUIT, config),
        Some(ArtifactError::Commitment)
    );
    let wrong_params = PinnedParams::<Ep>::derive(K + 1).unwrap();
    assert_eq!(
        ProvingKey::<Ep>::from_artifact_v2(
            &encoded,
            original.binding(),
            &wrong_params,
            &CIRCUIT,
            config
        )
        .err(),
        Some(ArtifactError::Profile)
    );
    let wrong_curve = PinnedParams::<Eq>::derive(K).unwrap();
    assert!(
        ProvingKey::<Eq>::from_artifact_v2(
            &encoded,
            original.binding(),
            &wrong_curve,
            &CIRCUIT,
            config
        )
        .is_err()
    );
    let v1 = keygen_pk(
        &params,
        &CIRCUIT,
        &KeygenConfig::new(TranscriptV1::Blake2bChallenge255),
    )
    .unwrap();
    assert_eq!(v1.artifact_bytes_v2().err(), Some(ArtifactError::Profile));
    assert_eq!(
        ProvingKey::<Ep>::from_artifact_v2(&encoded, v1.binding(), &params, &CIRCUIT, config).err(),
        Some(ArtifactError::Profile)
    );
}

fn params<C: PastaCurve>() -> PinnedParams<C> {
    PinnedParams::<C>::derive(K).expect("params")
}

fn config(transcript: TranscriptV1, compress: bool) -> KeygenConfig {
    let mut config = KeygenConfig::new(transcript);
    config.compress_selectors = compress;
    config
}

fn round_trip<C: PastaCurve>() {
    let params = params::<C>();
    for compress in [true, false] {
        let config = config(TranscriptV1::Blake2bChallenge255, compress);
        let pk = keygen_pk(&params, &CIRCUIT, &config).expect("pk");
        let vk = keygen_vk(&params, &CIRCUIT, &config).expect("vk");
        assert_eq!(pk.vk(), &vk);
        let descriptor = pk.binding().descriptor();
        let fixed = descriptor.num_fixed_columns as usize;
        let sigma = descriptor.permutation.len();
        // Three configure fixed columns (constants, coeff, table) plus the
        // selector columns: mul and add share one column when compressed.
        assert_eq!(fixed, if compress { 3 + 2 } else { 3 + 3 });
        // a, c, the instance and the constants column (`enable_constant`).
        assert_eq!(sigma, 4);
        let bitmaps = if compress { 3 * 64 / 8 } else { 0 };
        assert_eq!(vk.to_bytes().len(), 10 + 32 * (fixed + sigma) + bitmaps);
        assert_eq!(vk.to_bytes()[0], VK_VERSION);
        assert_eq!(vk.k(), K);
        assert_eq!(vk.compress_selectors(), compress);
        assert_eq!(vk.selectors().len(), if compress { 3 } else { 0 });
        let read = VerifyingKey::<C>::read(vk.to_bytes(), pk.binding()).expect("read");
        assert_eq!(read, vk);
        assert_eq!(
            *vk.transcript_repr(),
            crate::transcript::TranscriptRepr::Scalar(transcript_repr::<C::ScalarExt>(
                pk.binding().digest(),
                vk.to_bytes()
            ))
        );
        assert_eq!(vk.descriptor_digest(), pk.binding().digest());
        assert_eq!(pk.transcript_repr_bytes(), vk.transcript_repr_bytes());
        // A descriptor decoded from its frame binds the same key.
        let decoded = DescriptorBinding::decode(pk.binding().encoded()).expect("decode");
        assert_eq!(&decoded, pk.binding());
    }
}

#[test]
fn keys_round_trip_on_both_curves() {
    round_trip::<Ep>();
    round_trip::<Eq>();
}

#[test]
fn the_descriptor_binds_transcript_repr_but_not_vk_bytes() {
    // DEV-01: the VK bytes depend only on the keys; transcript_repr also
    // binds the descriptor (here: the transcript choice).
    let params = params::<Ep>();
    let blake = keygen_vk(
        &params,
        &CIRCUIT,
        &config(TranscriptV1::Blake2bChallenge255, true),
    )
    .expect("vk");
    let poseidon = keygen_vk(
        &params,
        &CIRCUIT,
        &config(TranscriptV1::KagemushaPoseidonRp57, true),
    )
    .expect("vk");
    assert_eq!(blake.to_bytes(), poseidon.to_bytes());
    assert_ne!(blake.descriptor_digest(), poseidon.descriptor_digest());
    assert_ne!(blake.transcript_repr(), poseidon.transcript_repr());
    let mut direct = config(TranscriptV1::Blake2bChallenge255, true);
    direct.instance_mode = crate::cs::InstanceModeV1::Direct;
    let direct = keygen_vk(&params, &CIRCUIT, &direct).expect("vk");
    assert_eq!(blake.to_bytes(), direct.to_bytes());
    assert_ne!(blake.transcript_repr(), direct.transcript_repr());
}

/// DEV-06 (spec section 14): the strict `0x02` reader rejects a wrong
/// version, `k`, compress flag or fixed count, any other length (trailing
/// bytes included), identity and invalid points, and bitmaps that change the
/// selector plan, where the vendored reader trusts a prefix.
#[test]
fn the_reader_rejects_every_malformed_field() {
    let params = params::<Ep>();
    let pk = keygen_pk(
        &params,
        &CIRCUIT,
        &config(TranscriptV1::Blake2bChallenge255, true),
    )
    .expect("pk");
    let binding = pk.binding();
    let bytes = pk.vk().to_bytes().to_vec();
    let read = |bytes: &[u8]| VerifyingKey::<Ep>::read(bytes, binding).err();
    let edited = |offset: usize, value: u8| {
        let mut bytes = bytes.clone();
        bytes[offset] = value;
        bytes
    };
    assert_eq!(read(&edited(0, 0x01)), Some(VkError::Version { found: 1 }));
    assert_eq!(
        read(&edited(1, 7)),
        Some(VkError::K {
            expected: 6,
            found: 7
        })
    );
    assert_eq!(
        read(&edited(5, 2)),
        Some(VkError::Compress {
            expected: true,
            found: 2
        })
    );
    assert_eq!(
        read(&edited(5, 0)),
        Some(VkError::Compress {
            expected: true,
            found: 0
        })
    );
    assert_eq!(
        read(&edited(6, 9)),
        Some(VkError::FixedCount {
            expected: 5,
            found: 9
        })
    );
    let expected = bytes.len();
    assert_eq!(
        read(&bytes[..expected - 1]),
        Some(VkError::Length {
            expected,
            actual: expected - 1
        })
    );
    assert_eq!(
        read(&bytes[..4]),
        Some(VkError::Length {
            expected,
            actual: 4
        })
    );
    let mut long = bytes.clone();
    long.push(0);
    assert_eq!(
        read(&long),
        Some(VkError::Length {
            expected,
            actual: expected + 1
        })
    );
    let mut identity = bytes.clone();
    identity[10 + 32..10 + 64].fill(0);
    assert_eq!(
        read(&identity),
        Some(VkError::Point {
            index: 1,
            error: TranscriptError::IdentityPoint
        })
    );
    let mut invalid = bytes.clone();
    invalid[10 + 32 * 6..10 + 32 * 7].fill(0);
    invalid[10 + 32 * 6] = 2;
    assert_eq!(
        read(&invalid),
        Some(VkError::Point {
            index: 6,
            error: TranscriptError::InvalidPoint
        })
    );
    // Bitmaps: selectors are [mul, add, range]; mul and add share a column
    // because they are never active together. Making add active on a mul
    // row changes the compression plan (registration rule).
    let bitmaps = 10 + 32 * (5 + 4);
    let mut overlapping = bytes.clone();
    overlapping[bitmaps + 8] |= 1;
    assert_eq!(read(&overlapping), Some(VkError::SelectorPlan));
    // Moving the complex range selector keeps the plan; the key decodes but
    // binds a different transcript_repr.
    let mut moved = bytes.clone();
    moved[bitmaps + 16] |= 1 << 5;
    let moved = VerifyingKey::<Ep>::read(&moved, binding).expect("same plan");
    assert_ne!(moved.transcript_repr(), pk.vk().transcript_repr());
    // A Pallas descriptor does not decode a Vesta key.
    assert_eq!(
        VerifyingKey::<Eq>::read(&bytes, binding).err(),
        Some(VkError::CurveMismatch {
            descriptor: crate::cs::CurveV1::Pallas
        })
    );
    // Parts that do not match the descriptor are refused.
    assert_eq!(
        VerifyingKey::<Ep>::from_parts(binding, Vec::new(), Vec::new(), Vec::new()).err(),
        Some(VkError::Shape)
    );
}

#[test]
fn permutation_values_follow_the_copy_cycles() {
    let mut argument = PermutationArgument::new();
    let left: Column<Any> = Column::new(0, Advice).into();
    let right: Column<Any> = Column::new(0, Fixed).into();
    argument.add_column(left);
    argument.add_column(right);
    let mut assembly = PermutationAssembly::new(8, &argument).expect("assembly");
    assembly.copy(left, 1, right, 3).expect("copy");
    assembly.copy(right, 3, left, 5).expect("copy");
    let domain = FftDomain::<Fp>::new(3).expect("domain");
    let omega = domain.omega();
    let values = permutation_values(&assembly, omega).expect("values");
    let delta = <Fp as ff::PrimeField>::DELTA;
    let id = |column: usize, row: usize| {
        let base = if column == 0 { Fp::ONE } else { delta };
        base * omega.pow_vartime([row as u64])
    };
    for (column, column_values) in values.iter().enumerate() {
        for (row, value) in column_values.iter().enumerate() {
            let (target_column, target_row) = assembly.mapping(column, row).expect("cell");
            assert_eq!(*value, id(target_column, target_row));
        }
    }
    // The three copied cells form one cycle; the others are fixed points.
    assert_ne!(values[0][1], id(0, 1));
    assert_ne!(values[1][3], id(1, 3));
    assert_ne!(values[0][5], id(0, 5));
    assert_eq!(values[0][2], id(0, 2));
    let mut cycle = vec![values[0][1], values[1][3], values[0][5]];
    cycle.sort();
    let mut cells = vec![id(0, 1), id(1, 3), id(0, 5)];
    cells.sort();
    assert_eq!(cycle, cells);
    // sigma is a permutation of the identity labels: equal products.
    let product = |f: &dyn Fn(usize, usize) -> Fp| {
        (0..2)
            .flat_map(|c| (0..8).map(move |r| (c, r)))
            .fold(Fp::ONE, |acc, (c, r)| acc * f(c, r))
    };
    assert_eq!(product(&|c, r| values[c][r]), product(&id));
}

fn check_pk_tables<C: PastaCurve>() {
    let params = params::<C>();
    let mut eager_config = config(TranscriptV1::Blake2bChallenge255, true);
    eager_config.table_budget = Some(MemoryBudget::DEFAULT);
    let eager = keygen_pk(&params, &CIRCUIT, &eager_config).expect("pk");
    let mut lazy_config = eager_config;
    lazy_config.coset_cache = CosetCachePolicy::OnDemand;
    lazy_config.table_budget = None;
    let lazy = keygen_pk(&params, &CIRCUIT, &lazy_config).expect("pk");
    assert!(eager.has_coset_cache());
    assert!(!lazy.has_coset_cache());
    assert!(eager.coset_cache_bytes() > 0);
    assert_eq!(lazy.coset_cache_bytes(), 0);
    assert_eq!(eager.commitment_tables().present(), (true, true));
    assert_eq!(lazy.commitment_tables().present(), (false, false));
    assert_eq!(eager.vk(), lazy.vk());

    let domain = eager.domain();
    let n = domain.n();
    let blind = C::ScalarExt::ONE;
    for (index, (values, poly)) in eager
        .fixed_values()
        .iter()
        .zip(eager.fixed_polys())
        .enumerate()
    {
        let mut evaluated = poly.clone();
        domain.fft(&mut evaluated).expect("fft");
        assert_eq!(&evaluated, values);
        let commitment = commit_lagrange(
            params.params(),
            values,
            &blind,
            Secrecy::Public,
            MemoryBudget::DEFAULT,
        )
        .expect("commit")
        .to_affine();
        assert_eq!(commitment, eager.vk().fixed_commitments()[index]);
    }
    for (index, values) in eager.permutation_values().iter().enumerate() {
        let commitment = commit_lagrange(
            params.params(),
            values,
            &blind,
            Secrecy::Public,
            MemoryBudget::DEFAULT,
        )
        .expect("commit")
        .to_affine();
        assert_eq!(commitment, eager.vk().permutation_commitments()[index]);
    }
    let blinding = usize::from(eager.binding().descriptor().blinding_factors);
    let (l0, l_last, l_active) = eager.mask_values();
    assert_eq!(l0.iter().filter(|v| **v == C::ScalarExt::ONE).count(), 1);
    assert_eq!(l0[0], C::ScalarExt::ONE);
    assert_eq!(l_last[n - blinding - 1], C::ScalarExt::ONE);
    assert_eq!(
        l_active.iter().filter(|v| **v == C::ScalarExt::ONE).count(),
        n - blinding - 1
    );
    let (p0, _, _) = eager.mask_polys();
    let mut evaluated = p0.to_vec();
    domain.fft(&mut evaluated).expect("fft");
    assert_eq!(evaluated, l0);

    let pieces = eager.quotient_domain().pieces();
    assert_eq!(pieces, usize::from(eager.binding().descriptor().degree) - 1);
    let fixed = eager.fixed_values().len();
    let sigma = eager.permutation_values().len();
    let polys = (0..fixed)
        .map(CosetPolynomial::Fixed)
        .chain((0..sigma).map(CosetPolynomial::Permutation))
        .chain([
            CosetPolynomial::L0,
            CosetPolynomial::LLast,
            CosetPolynomial::LActive,
        ]);
    for poly in polys {
        for coset in 0..pieces {
            let cached = eager.coset_values(poly, coset).expect("cached");
            let computed = lazy.coset_values(poly, coset).expect("computed");
            assert_eq!(cached, computed, "{poly:?} coset {coset}");
        }
    }
    assert_eq!(
        eager.coset_values(CosetPolynomial::Fixed(fixed), 0).err(),
        Some(KeyError::CosetIndex)
    );
    assert_eq!(
        lazy.coset_values(CosetPolynomial::Permutation(sigma), 0)
            .err(),
        Some(KeyError::CosetIndex)
    );
    assert_eq!(
        eager.coset_values(CosetPolynomial::L0, pieces).err(),
        Some(KeyError::CosetIndex)
    );
    assert_eq!(
        eager.constraint_system().selector_plan().compress,
        eager.vk().compress_selectors()
    );
    // The masks are computed per coset from their closed forms and equal
    // the coset FFT of the mask polynomials; they are not cached.
    let (p0, p_last, p_active) = eager.mask_polys();
    for coset in 0..pieces {
        let masks = eager.coset_masks(coset).expect("masks");
        let quotient = eager.quotient_domain();
        for (closed, poly) in [
            (&masks.l0, p0),
            (&masks.l_last, p_last),
            (&masks.l_active, p_active),
        ] {
            let fft = quotient.evaluate(domain, poly, coset).expect("fft");
            assert_eq!(closed, &fft, "coset {coset}");
        }
        assert_eq!(masks, lazy.coset_masks(coset).expect("masks"));
    }
    assert_eq!(eager.coset_masks(pieces).err(), Some(KeyError::CosetIndex));
    let cached_polys = fixed + sigma;
    assert_eq!(
        eager.coset_cache_bytes(),
        cached_polys * pieces * n * core::mem::size_of::<C::ScalarExt>()
    );
    // The selector columns live once, as the last fixed columns, and the
    // key reports them from there.
    let first =
        usize::try_from(eager.binding().descriptor().selectors.first_column).expect("first column");
    assert!(first <= fixed);
    assert_eq!(eager.selector_values(), &eager.fixed_values()[first..]);
    assert_eq!(
        eager.selector_values().len(),
        eager.constraint_system().selector_plan().num_columns()
    );
    // The same system and selector columns as a fresh finalization.
    let synthesized = crate::frontend::synthesize(&CIRCUIT, params.k(), None).expect("synthesis");
    let finalized = synthesized
        .cs
        .finalize(
            synthesized.tables.selectors(),
            eager_config.compress_selectors,
        )
        .expect("finalize");
    assert!(!finalized.selector_columns().is_empty());
    assert_eq!(eager.selector_values(), finalized.selector_columns());
    assert_eq!(
        eager.constraint_system().constraint_system(),
        finalized.constraint_system()
    );
    assert_eq!(
        eager.constraint_system().selector_plan(),
        finalized.selector_plan()
    );
}

#[test]
fn proving_key_tables_and_cosets_are_consistent() {
    check_pk_tables::<Ep>();
    check_pk_tables::<Eq>();
}

#[test]
fn keys_are_identical_across_thread_pools() {
    let params = params::<Eq>();
    let config = config(TranscriptV1::KagemushaPoseidonRp57, true);
    let reference = keygen_vk(&params, &CIRCUIT, &config).expect("vk");
    for threads in [1, 2, 4, 7] {
        let pool = rayon::ThreadPoolBuilder::new()
            .num_threads(threads)
            .build()
            .expect("pool");
        let vk = pool
            .install(|| keygen_vk(&params, &CIRCUIT, &config))
            .expect("vk");
        assert_eq!(vk, reference, "{threads} threads");
    }
}

#[test]
fn keygen_from_tables_checks_shapes() {
    let params = params::<Eq>();
    let synthesized = crate::frontend::synthesize(&CIRCUIT, K, None).expect("synthesize");
    let tables = synthesized.tables;
    let config = config(TranscriptV1::Blake2bChallenge255, true);
    let fixed = tables.fixed().to_vec();
    let selectors = tables.selectors().to_vec();
    keygen_from_tables(
        &params,
        synthesized.cs.clone(),
        fixed.clone(),
        selectors.clone(),
        tables.permutation(),
        &config,
    )
    .expect("pk");
    let shape = |result: Result<ProvingKey<Eq>, KeyError>| match result {
        Err(KeyError::Shape { what, .. }) => what,
        other => panic!("expected a shape error, got {:?}", other.err()),
    };
    assert_eq!(
        shape(keygen_from_tables(
            &params,
            synthesized.cs.clone(),
            fixed[1..].to_vec(),
            selectors.clone(),
            tables.permutation(),
            &config
        )),
        "fixed columns"
    );
    let mut short_rows = fixed.clone();
    short_rows[0].pop();
    assert_eq!(
        shape(keygen_from_tables(
            &params,
            synthesized.cs.clone(),
            short_rows,
            selectors.clone(),
            tables.permutation(),
            &config
        )),
        "fixed rows"
    );
    assert_eq!(
        shape(keygen_from_tables(
            &params,
            synthesized.cs.clone(),
            fixed.clone(),
            selectors[1..].to_vec(),
            tables.permutation(),
            &config
        )),
        "selectors"
    );
    let empty = PermutationAssembly::new(64, &PermutationArgument::new()).expect("assembly");
    assert_eq!(
        shape(keygen_from_tables(
            &params,
            synthesized.cs,
            fixed,
            selectors,
            &empty,
            &config
        )),
        "permutation columns"
    );
}

/// Imported key-generation tables follow the frontend's row rule (spec 6.4):
/// a copy, an enabled selector or a nonzero fixed value at or beyond the
/// usable rows is refused, and the key stores the digest of its copies.
#[test]
fn keygen_from_tables_refuses_unusable_rows() {
    let params = params::<Eq>();
    let synthesized = crate::frontend::synthesize(&CIRCUIT, K, None).expect("synthesize");
    let tables = synthesized.tables;
    let usable = tables.usable_rows();
    let config = config(TranscriptV1::Blake2bChallenge255, false);
    let keygen = |fixed: Vec<Vec<Fp>>, selectors: Vec<Vec<bool>>, copies: &PermutationAssembly| {
        keygen_from_tables(
            &params,
            synthesized.cs.clone(),
            fixed,
            selectors,
            copies,
            &config,
        )
    };
    let fixed = tables.fixed().to_vec();
    let selectors = tables.selectors().to_vec();
    let pk = keygen(fixed.clone(), selectors.clone(), tables.permutation()).expect("pk");
    assert_eq!(pk.copy_digest(), &tables.permutation().mapping_digest());

    // A copy into the first blinding row (the row of l_last is u).
    let mut copies = tables.permutation().clone();
    let column = copies.columns()[0];
    copies
        .copy(column, 0, column, usable)
        .expect("in the domain");
    assert_eq!(
        keygen(fixed.clone(), selectors.clone(), &copies).err(),
        Some(KeyError::UnusableRow {
            what: "copy",
            column: 0,
            row: usable
        })
    );
    // A copy on the last usable row is fine.
    let mut copies = tables.permutation().clone();
    copies
        .copy(column, 0, column, usable - 1)
        .expect("in the domain");
    let pk = keygen(fixed.clone(), selectors.clone(), &copies).expect("usable copy");
    assert_ne!(pk.copy_digest(), &tables.permutation().mapping_digest());

    let mut late_selector = selectors.clone();
    late_selector[1][usable + 1] = true;
    assert_eq!(
        keygen(fixed.clone(), late_selector, tables.permutation()).err(),
        Some(KeyError::UnusableRow {
            what: "selector",
            column: 1,
            row: usable + 1
        })
    );
    let mut late_fixed = fixed;
    let last = late_fixed[1].len() - 1;
    late_fixed[1][last] = Fp::ONE;
    assert_eq!(
        keygen(late_fixed, selectors, tables.permutation()).err(),
        Some(KeyError::UnusableRow {
            what: "fixed",
            column: 1,
            row: last
        })
    );
    assert!(
        KeyError::UnusableRow {
            what: "copy",
            column: 2,
            row: 60
        }
        .to_string()
        .contains("unusable row 60")
    );
}

#[test]
fn small_domains_are_unpinned() {
    // Descriptors pin params for k = 6..=16 only (DescriptorError::UnpinnedParams).
    let params = PinnedParams::<Ep>::derive(5).expect("params");
    let error = keygen_vk(
        &params,
        &CIRCUIT,
        &config(TranscriptV1::Blake2bChallenge255, true),
    )
    .expect_err("unpinned");
    assert!(matches!(
        error,
        KeyError::Descriptor(crate::cs::DescriptorError::UnpinnedParams { k: 5, .. })
    ));
}

#[test]
fn unit_tests_can_inject_the_captured_transcript_repr() {
    use iroha_pasta::Fq;
    let params = params::<Ep>();
    let vk = keygen_vk(
        &params,
        &CIRCUIT,
        &config(TranscriptV1::Blake2bChallenge255, true),
    )
    .expect("vk");
    let injected = vk.clone().with_transcript_repr_for_oracle(Fq::from(5));
    assert_eq!(
        *injected.transcript_repr(),
        crate::transcript::TranscriptRepr::Scalar(Fq::from(5))
    );
    assert_eq!(injected.to_bytes(), vk.to_bytes());
}

fn wallet_digest<C: PastaCurve>() {
    use crate::{
        cs::{CircuitDescriptorV2, CurveV1, InstanceType, TranscriptV2},
        transcript::TranscriptRepr,
    };
    use ff::PrimeField;
    use iroha_pasta::{PastaAffine, poseidon::hash_with_domain};

    let params = params::<C>();
    let config = KeygenConfigV2::pipa_r(vec![InstanceType::Bounded]);
    let pk = keygen_pk_v2(&params, &CIRCUIT, &config).expect("PIPA-R keys");
    let vk = pk.vk();
    let digest = vk.kagemusha_digest(pk.binding()).expect("wallet digest");
    let TranscriptRepr::Base(repr) = *vk.transcript_repr() else {
        panic!("base repr")
    };
    let descriptor = pk.binding().descriptor();
    let curve = match descriptor.curve {
        CurveV1::Pallas => 0,
        CurveV1::Vesta => 1,
    };
    let mut fields = vec![
        C::Base::ONE,
        C::Base::from(curve),
        C::Base::from(u64::from(K)),
        C::Base::from(vk.fixed_commitments().len() as u64),
        C::Base::from(vk.permutation_commitments().len() as u64),
        repr,
    ];
    for chunk in pk.binding().digest().chunks_exact(16) {
        fields.push(C::Base::from_u128(u128::from_le_bytes(
            chunk.try_into().expect("16 bytes"),
        )));
    }
    for point in vk
        .fixed_commitments()
        .iter()
        .chain(vk.permutation_commitments())
    {
        let (x, y) = point.coordinates().expect("finite");
        fields.extend([x, y]);
    }
    let domain = u64::from_le_bytes(*b"kgwvkey1");
    assert_eq!(digest, hash_with_domain(domain, &fields));
    assert_ne!(digest, hash_with_domain(domain ^ 1, &fields));
    // Every header, digest limb, coordinate and exact arity is bound.
    for index in 0..fields.len() {
        let mut changed = fields.clone();
        changed[index] += C::Base::ONE;
        assert_ne!(digest, hash_with_domain(domain, &changed), "field {index}");
    }
    assert_ne!(
        digest,
        hash_with_domain(domain, &fields[..fields.len() - 1])
    );
    let mut swapped = fields.clone();
    swapped.swap(8, 10);
    swapped.swap(9, 11);
    assert_ne!(digest, hash_with_domain(domain, &swapped));
    let mut changed = CircuitDescriptorV2::decode(pk.binding().encoded()).expect("descriptor");
    changed.instance_types = vec![InstanceType::Field];
    let other = DescriptorBinding::new_v2(changed).expect("other binding");
    assert_eq!(vk.kagemusha_digest(&other), Err(VkError::Binding));
    let rebound = VerifyingKey::<C>::read(vk.to_bytes(), &other).expect("same arithmetic key");
    assert_ne!(digest, rebound.kagemusha_digest(&other).expect("digest"));
    let mut fixed = vk.fixed_commitments().to_vec();
    fixed.swap(0, 1);
    let foreign = VerifyingKey::<C>::from_parts(
        pk.binding(),
        fixed,
        vk.permutation_commitments().to_vec(),
        vk.selectors().to_vec(),
    )
    .expect("foreign key");
    assert_ne!(
        digest,
        foreign.kagemusha_digest(pk.binding()).expect("digest")
    );
    let mut scalar = config;
    scalar.transcript = TranscriptV2::KagemushaPoseidonRp57;
    let legacy_profile = keygen_pk_v2(&params, &CIRCUIT, &scalar).expect("retained scalar profile");
    assert_eq!(
        legacy_profile
            .vk()
            .kagemusha_digest(legacy_profile.binding()),
        Err(VkError::Binding)
    );
}

#[test]
fn wallet_digest_binds_native_fields_and_v2_keys_on_both_curves() {
    wallet_digest::<Ep>();
    wallet_digest::<Eq>();
}

#[test]
fn cancellable_keygen_preserves_originals_and_fresh_retry_on_both_curves() {
    fn check<C: PastaCurve>() {
        use iroha_pasta::CancellationToken;
        let params = PinnedParams::<C>::derive(6).unwrap();
        let circuit = TestCircuit { rows: ROWS };
        for (coset_cache, table_budget) in [
            (CosetCachePolicy::Eager, Some(MemoryBudget::DEFAULT)),
            (CosetCachePolicy::OnDemand, None),
            (CosetCachePolicy::OnDemand, Some(MemoryBudget::new(0))),
        ] {
            let mut config = KeygenConfigV2::pipa_r(vec![crate::cs::InstanceType::Field]);
            config.coset_cache = coset_cache;
            config.table_budget = table_budget;
            let expected = keygen_pk_v2(&params, &circuit, &config).unwrap();
            let token = CancellationToken::new();
            token.cancel();
            assert!(matches!(
                keygen_pk_v2_cancellable(&params, &circuit, &config, Some(&token)),
                Err(KeyError::Cancelled)
            ));
            assert!(matches!(
                keygen_vk_with_binding_v2_cancellable(&params, &circuit, &config, Some(&token)),
                Err(KeyError::Cancelled)
            ));
            let fresh = CancellationToken::new();
            let retry = keygen_pk_v2_cancellable(&params, &circuit, &config, Some(&fresh)).unwrap();
            let (binding, vk) =
                keygen_vk_with_binding_v2_cancellable(&params, &circuit, &config, Some(&fresh))
                    .unwrap();
            assert_eq!(
                retry.artifact_bytes_v2().unwrap(),
                expected.artifact_bytes_v2().unwrap()
            );
            assert_eq!(
                retry.commitment_tables().present(),
                expected.commitment_tables().present()
            );
            assert_eq!(retry.has_coset_cache(), expected.has_coset_cache());
            assert_eq!(&binding, expected.binding());
            assert_eq!(vk.to_bytes(), expected.vk().to_bytes());
            assert_eq!(
                VerifyingKey::<C>::read_cancellable(vk.to_bytes(), &binding, Some(&fresh)).unwrap(),
                vk
            );
            assert!(matches!(
                VerifyingKey::<C>::read_cancellable(vk.to_bytes(), &binding, Some(&token)),
                Err(VkError::Cancelled)
            ));
            assert!(matches!(
                VerifyingKey::<C>::from_parts_cancellable(
                    &binding,
                    vk.fixed_commitments().to_vec(),
                    vk.permutation_commitments().to_vec(),
                    vk.selectors().to_vec(),
                    Some(&token)
                ),
                Err(VkError::Cancelled)
            ));
            assert!(
                binding
                    .descriptor()
                    .check_selector_plan_cancellable(vk.selectors(), Some(&token))
                    .unwrap_err()
                    .is_cancelled()
            );
            assert_eq!(
                binding
                    .descriptor()
                    .check_selector_plan_cancellable(vk.selectors(), Some(&fresh)),
                Ok(())
            );
            if table_budget.is_some_and(|budget| budget.bytes() == 0) {
                assert_eq!(retry.commitment_tables().present(), (false, false));
            }
        }
    }
    check::<Ep>();
    check::<Eq>();
}

#[test]
fn keygen_cancellation_after_real_synthesis_is_typed_and_operation_local() {
    #[derive(Clone)]
    struct CancelAfterSynthesis {
        circuit: TestCircuit,
        token: iroha_pasta::CancellationToken,
    }
    impl<F: PastaField> Circuit<F> for CancelAfterSynthesis {
        type Config = TestConfig;
        type FloorPlanner = SimpleFloorPlanner;
        type Params = ();
        fn without_witnesses(&self) -> Self {
            self.clone()
        }
        fn configure(meta: &mut ConstraintSystem<F>) -> TestConfig {
            TestCircuit::configure(meta)
        }
        fn synthesize(&self, config: TestConfig, layouter: impl Layouter<F>) -> Result<(), Error> {
            self.circuit.synthesize(config, layouter)?;
            self.token.cancel();
            Ok(())
        }
    }
    fn check<C: PastaCurve>() {
        let params = PinnedParams::<C>::derive(6).unwrap();
        let config = KeygenConfigV2::pipa_r(vec![crate::cs::InstanceType::Field]);
        let circuit = TestCircuit { rows: ROWS };
        for verifier_only in [false, true] {
            let token = iroha_pasta::CancellationToken::new();
            let interrupted = CancelAfterSynthesis {
                circuit,
                token: token.clone(),
            };
            let result = if verifier_only {
                keygen_vk_with_binding_v2_cancellable(&params, &interrupted, &config, Some(&token))
                    .map(|_| ())
            } else {
                keygen_pk_v2_cancellable(&params, &interrupted, &config, Some(&token)).map(|_| ())
            };
            assert!(matches!(result, Err(KeyError::Cancelled)));
            let fresh = iroha_pasta::CancellationToken::new();
            let retry = keygen_pk_v2_cancellable(&params, &circuit, &config, Some(&fresh)).unwrap();
            assert_eq!(
                retry.artifact_bytes_v2().unwrap(),
                keygen_pk_v2(&params, &circuit, &config)
                    .unwrap()
                    .artifact_bytes_v2()
                    .unwrap()
            );
        }
        assert!(KeyError::from(crate::cs::CsError::Cancelled).is_cancelled());
        assert!(matches!(
            Error::from(crate::cs::CsError::Cancelled),
            Error::Cancelled
        ));
    }
    check::<Ep>();
    check::<Eq>();
}

#[test]
fn cancellable_vk_hash_matches_every_transcript_profile() {
    fn check<C: PastaCurve>() {
        use crate::{cs::TranscriptV2, transcript::TranscriptRepr};
        use iroha_pasta::CancellationToken;
        let bytes = (0_u32..12_345)
            .map(|index| u8::try_from(index % 251).unwrap())
            .collect::<Vec<_>>();
        let fresh = CancellationToken::new();
        let cancelled = CancellationToken::new();
        cancelled.cancel();
        for v2 in [false, true] {
            for profile in [
                TranscriptV2::Blake2bChallenge255,
                TranscriptV2::KagemushaPoseidonRp57,
                TranscriptV2::KagemushaPoseidonRp57Base,
            ] {
                assert_eq!(
                    TranscriptRepr::<C>::derive_cancellable(
                        v2,
                        profile,
                        &[19; 32],
                        &bytes,
                        Some(&fresh)
                    )
                    .unwrap(),
                    TranscriptRepr::<C>::derive(v2, profile, &[19; 32], &bytes)
                );
                assert_eq!(
                    TranscriptRepr::<C>::derive_cancellable(
                        v2,
                        profile,
                        &[19; 32],
                        &bytes,
                        Some(&cancelled)
                    ),
                    Err(iroha_pasta::Cancelled)
                );
            }
        }
    }
    check::<Ep>();
    check::<Eq>();
}
