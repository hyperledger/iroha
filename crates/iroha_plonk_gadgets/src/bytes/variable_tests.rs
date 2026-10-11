//! Exact variable-byte framing, adversarial padding and fixed-shape tests.
use super::*;
use crate::bytes::BytesConfig;
use crate::{
    GlueConfig, LimbBits, Pow5Columns, RoundConstantColumns, RunningSumChip, RunningSumConfig,
    phase::PhaseColumns,
    pow5_fq::{DuplexChip, DuplexConfig},
    tamper::undetected_tampers,
};
use iroha_pasta::{Fp, Fq};
use iroha_plonk::{
    check::{CheckMode, check_circuit},
    cs::{Column, ConstraintSystem, Instance},
    frontend::{Circuit, Layouter, SimpleFloorPlanner, synthesize},
};
use std::marker::PhantomData;
const DOMAIN: u64 = u64::from_le_bytes(*b"kgwprf_1");
#[derive(Clone)]
struct Test<F, const A: usize, const B: usize, const MODE: u8> {
    a: Option<Vec<u8>>,
    b: Option<Vec<u8>>,
    marker: PhantomData<F>,
}
impl<F, const A: usize, const B: usize, const MODE: u8> Test<F, A, B, MODE> {
    fn new(a: Vec<u8>, b: Vec<u8>) -> Self {
        Self {
            a: Some(a),
            b: Some(b),
            marker: PhantomData,
        }
    }
}
#[derive(Clone)]
struct Config<F> {
    glue: GlueConfig,
    range: RunningSumConfig,
    bytes: BytesConfig,
    sponge: DuplexConfig<F>,
    public: Column<Instance>,
}
impl<F: PoseidonField, const A: usize, const B: usize, const MODE: u8> Circuit<F>
    for Test<F, A, B, MODE>
{
    type Config = Config<F>;
    type FloorPlanner = SimpleFloorPlanner;
    type Params = ();
    fn without_witnesses(&self) -> Self {
        Self {
            a: None,
            b: None,
            marker: PhantomData,
        }
    }
    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        let advice = core::array::from_fn(|_| meta.advice_column());
        let constants = meta.fixed_column();
        let glue = GlueConfig::configure(meta, advice, constants);
        let z = meta.advice_column();
        let limb_bits = if A + B > 128 { 15 } else { 8 };
        let range = RunningSumConfig::configure(meta, z, LimbBits::new(limb_bits).unwrap());
        let primary = meta.advice_column();
        let secondary = meta.advice_column();
        let bytes = BytesConfig::configure(meta, primary, secondary);
        let lane = Pow5Columns::allocate(meta);
        let sponge = if MODE == 7 {
            let phases = PhaseColumns::allocate(meta);
            DuplexConfig::configure_phased(meta, lane, phases)
        } else {
            let rc = RoundConstantColumns::allocate(meta);
            DuplexConfig::configure(meta, lane, rc, &[])
        };
        let public = meta.instance_column(1);
        meta.enable_equality(public);
        Config {
            glue,
            range,
            bytes,
            sponge,
            public,
        }
    }
    fn synthesize(&self, config: Config<F>, mut layouter: impl Layouter<F>) -> Result<(), Error> {
        let mut glue = GlueChip::new(config.glue);
        let mut range = RunningSumChip::new(config.range);
        let mut bytes = BytesChip::new(config.bytes);
        let mut sponge = DuplexChip::new(config.sponge);
        range.load_table(&mut layouter)?;
        bytes.load_table(&mut layouter)?;
        let digest = layouter.assign_region(
            || "exact active bytes",
            |mut region| {
                let mut uint = UintChip::new(&mut glue, &mut range);
                let raw = |v: &Option<Vec<u8>>| v.clone().map_or(Value::unknown(), Value::known);
                let a =
                    ActiveBytes::assign(&mut uint, &mut bytes, &mut region, A, &raw(&self.a), &[])?;
                let packed = match MODE {
                    0 | 7 => a.packed().clone(),
                    1 | 2 | 5 => {
                        let b = ActiveBytes::assign(
                            &mut uint,
                            &mut bytes,
                            &mut region,
                            B,
                            &raw(&self.b),
                            &[],
                        )?;
                        if MODE == 1 {
                            a.packed().concat(&mut uint, &mut region, b.packed())?
                        } else {
                            let left = a.packed().length_prefixed(&mut uint, &mut region)?;
                            let right = b.packed().length_prefixed(&mut uint, &mut region)?;
                            left.concat(&mut uint, &mut region, &right)?
                        }
                    }
                    3 => a.packed().length_prefixed(&mut uint, &mut region)?,
                    4 => {
                        // A coherent padded buffer with a shorter claimed length.
                        // Its nonzero discarded byte must be rejected by from_run.
                        let length = uint.constant::<32>(&mut region, 0)?;
                        ActiveBytes::from_run(
                            &mut uint,
                            &mut bytes,
                            &mut region,
                            a.run().clone(),
                            length,
                        )?
                        .packed()
                        .clone()
                    }
                    _ => return Err(Error::Synthesis),
                };
                let digest = packed.digest(&mut uint, sponge.sponge_mut()?, &mut region, DOMAIN)?;
                sponge.absorb(&digest);
                assert!(sponge.sponge_mut().is_err());
                if MODE == 5 {
                    // A real live transcript must finish before the lane can be
                    // borrowed. Its reserved continuation cannot be overwritten.
                    sponge.squeeze(&mut region)?;
                    assert!(sponge.sponge_mut().is_err());
                }
                sponge.clear();
                if MODE == 5 {
                    let again =
                        packed.digest(&mut uint, sponge.sponge_mut()?, &mut region, DOMAIN)?;
                    GlueChip::assert_equal(&mut region, &digest, &again)?;
                }
                if A + B > 128 {
                    eprintln!(
                        "active byte capacity={A}+{B} rows: glue={} range={} bytes={}",
                        uint.glue().next_row(),
                        uint.range().next_row(),
                        bytes.next_row()
                    );
                }
                Ok(digest)
            },
        )?;
        layouter.constrain_instance(digest.cell(), config.public, 0)
    }
}
fn message(a: &[u8], b: &[u8], mode: u8) -> Vec<u8> {
    let frame = |v: &[u8]| {
        let mut out = u32::try_from(v.len()).unwrap().to_le_bytes().to_vec();
        out.extend_from_slice(v);
        out
    };
    match mode {
        0 => a.to_vec(),
        1 => [a, b].concat(),
        2 | 5 => [frame(a), frame(b)].concat(),
        3 => frame(a),
        _ => vec![],
    }
}
fn check<F: PoseidonField, const A: usize, const B: usize, const MODE: u8>(a: Vec<u8>, b: Vec<u8>) {
    let public = vec![vec![super::super::p_bytes_native::<F>(
        DOMAIN,
        &message(&a, &b, MODE),
    )]];
    let circuit = Test::<F, A, B, MODE>::new(a, b);
    let report = check_circuit(&circuit, 12, &public, CheckMode::Strict).unwrap();
    assert!(report.is_satisfied(), "{report}");
    let mut wrong = public.clone();
    wrong[0][0] += F::ONE;
    assert!(
        !check_circuit(&circuit, 12, &wrong, CheckMode::Strict)
            .unwrap()
            .is_satisfied()
    );
    let known = synthesize(&circuit, 12, Some(&public)).unwrap();
    let unknown = synthesize(&circuit.without_witnesses(), 12, None).unwrap();
    assert_eq!(known.cs, unknown.cs);
    assert_eq!(known.tables.fixed(), unknown.tables.fixed());
    assert_eq!(known.tables.permutation(), unknown.tables.permutation());
}
fn boundaries<F: PoseidonField>() {
    for len in [0, 1, 2, 29, 30, 31, 32, 61, 62, 63, 64] {
        let a = (0..len)
            .map(|i| u8::try_from((i * 13 + 5) % 256).unwrap())
            .collect::<Vec<_>>();
        check::<F, 64, 0, 0>(a.clone(), vec![]);
        check::<F, 64, 0, 3>(a, vec![]);
    }
    check::<F, 0, 0, 0>(vec![], vec![]);
    check::<F, 0, 0, 3>(vec![], vec![]);
}
#[test]
fn variable_bytes_boundaries_and_padding_match_native_both_fields() {
    boundaries::<Fp>();
    boundaries::<Fq>();
}
fn crossing<F: PoseidonField>() {
    for (left, right) in [
        (0, 0),
        (0, 1),
        (1, 0),
        (1, 1),
        (29, 32),
        (30, 31),
        (31, 30),
        (32, 29),
        (61, 32),
        (62, 31),
        (63, 33),
        (64, 64),
    ] {
        let a = (0..left)
            .map(|i| u8::try_from((i * 7) % 256).unwrap())
            .collect::<Vec<_>>();
        let b = (0..right)
            .map(|i| u8::try_from((i * 11 + 17) % 256).unwrap())
            .collect::<Vec<_>>();
        check::<F, 64, 64, 1>(a.clone(), b.clone());
        check::<F, 64, 64, 2>(a, b);
    }
    check::<F, 0, 31, 1>(vec![], vec![255; 31]);
    check::<F, 31, 0, 1>(vec![255; 31], vec![]);
}
#[test]
fn variable_bytes_concat_crossings_have_no_intermediate_padding() {
    crossing::<Fp>();
    crossing::<Fq>();
}
#[test]
fn variable_bytes_lengths_separate_equal_zero_padded_views_and_reject_discarded_data() {
    let empty = super::super::p_bytes_native::<Fp>(DOMAIN, &[]);
    let zero = super::super::p_bytes_native::<Fp>(DOMAIN, &[0]);
    assert_ne!(empty, zero);
    let circuit = Test::<Fp, 32, 0, 0>::new(vec![0], vec![]);
    assert!(
        !check_circuit(&circuit, 12, &[vec![empty]], CheckMode::Strict)
            .unwrap()
            .is_satisfied()
    );
    let malformed = Test::<Fp, 32, 0, 4>::new(vec![1], vec![]);
    assert!(
        !check_circuit(&malformed, 12, &[vec![empty]], CheckMode::Strict)
            .unwrap()
            .is_satisfied()
    );
    let oversized = Test::<Fp, 32, 0, 0>::new(vec![0; 33], vec![]);
    assert!(check_circuit(&oversized, 12, &[vec![empty]], CheckMode::Strict).is_err());
}
#[test]
fn variable_bytes_every_assigned_cell_is_bound() {
    let a = vec![255];
    let b = vec![3];
    let circuit = Test::<Fp, 1, 1, 2>::new(a.clone(), b.clone());
    let public = vec![vec![super::super::p_bytes_native::<Fp>(
        DOMAIN,
        &message(&a, &b, 2),
    )]];
    assert!(
        undetected_tampers(&circuit, 11, &public)
            .unwrap()
            .is_empty()
    );
}

#[test]
fn variable_bytes_all_shift_residues_and_shared_transcript_cursor() {
    for left in 0..31 {
        check::<Fp, 31, 31, 2>(vec![255; left], vec![128; 31 - left]);
        check::<Fq, 31, 31, 2>(vec![0; left], vec![255; 31]);
    }
    check::<Fp, 64, 64, 5>(vec![255; 30], vec![131; 32]);
    check::<Fq, 64, 64, 5>(vec![255; 31], vec![131; 30]);
}

#[test]
fn variable_bytes_compact_phase_tap_is_rejected() {
    let circuit = Test::<Fp, 32, 0, 7>::new(vec![1], vec![]);
    assert!(synthesize(&circuit, 12, None).is_err());
}

#[test]
fn variable_bytes_maximum_incoming_tapes_fit_k16() {
    // The largest admitted status-lineage body is 320 public bytes plus
    // 7,812 transport bytes; even a malformed sigma may fill a 10,000-byte
    // envelope. This deliberately bounds each source independently. The
    // Payment relation must also enforce its stricter joint envelope limit.
    let a = (0..8_132)
        .map(|i| u8::try_from((i * 13 + 9) % 256).unwrap())
        .collect::<Vec<_>>();
    let b = (0..10_000)
        .map(|i| u8::try_from((i * 11 + 3) % 256).unwrap())
        .collect::<Vec<_>>();
    let public = vec![vec![super::super::p_bytes_native::<Fp>(
        DOMAIN,
        &message(&a, &b, 2),
    )]];
    let circuit = Test::<Fp, 8_132, 10_000, 2>::new(a, b);
    let report = check_circuit(&circuit, 16, &public, CheckMode::Strict).unwrap();
    assert!(report.is_satisfied(), "{report}");
    let known = synthesize(&circuit, 16, Some(&public)).unwrap();
    let unknown = synthesize(&circuit.without_witnesses(), 16, None).unwrap();
    assert_eq!(known.cs, unknown.cs);
    assert_eq!(known.tables.fixed(), unknown.tables.fixed());
    assert_eq!(known.tables.permutation(), unknown.tables.permutation());
}
