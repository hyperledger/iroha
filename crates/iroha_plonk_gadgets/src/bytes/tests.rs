//! Circuit tests of the byte-linking chip:
//!
//! - `P_bytes` against the shared wallet vectors of
//!   `fixtures/kagemusha/wallet_v1_vectors.json`, which the data-model
//!   implementation (`kagemusha_wallet_poseidon_bytes_v1`,
//!   `iroha_data_model` `kagemusha_wallet_v1/poseidon.rs`) writes and
//!   asserts: the packing vectors at the chunk boundaries, every
//!   large-input digest (both `proof_digest` domains, the Payment, lineage,
//!   credit-opening, credit-status and credited digests) and every signing
//!   message;
//! - the length-prefixed export and its realignment at every in-chunk offset;
//! - tape segments (little- and big-endian) against the native integers;
//! - compressed points: the opposite point, a flipped sign bit, a wrong `x`,
//!   a non-canonical `x + p` and the parity alias `y + p` are rejected (hard)
//!   or flagged (soft), on both curves; the soft decode equals the native
//!   decoder (the identity, the signed zero, `x` off the curve) under forced
//!   square bits and roots;
//! - scalars at `m - 1`, `m`, `m + 1` and with bit 255 set; big-endian values
//!   against the P-256 modulus;
//! - opaque chunks at `2^(8 len) - 1` and `2^(8 len)`;
//! - per-cell tamper suites, the inventory and the k16 measurement (ignored;
//!   run in release).

use std::{path::PathBuf, time::Instant};

use ff::{Field, PrimeField};
use iroha_pasta::{
    EpAffine, EqAffine, Fp, Fq, PastaAffine, PastaField,
    poseidon::{PoseidonField, hash_with_domain},
};
use iroha_plonk::{
    check::{CheckFailure, CheckMode, check_circuit},
    cs::{Advice, Column, ConstraintSystem, Instance},
    frontend::{
        Circuit, Error, Layouter, Region, SimpleFloorPlanner, Value, configure, synthesize,
    },
};
use norito::json::Value as Json;

use super::*;
use crate::{
    arith::{GlueChip, GlueConfig},
    cells::{known, to_u128},
    poseidon::{Pow5Columns, RoundConstantColumns, SpongeChip, SpongeConfig, domain_permutations},
    range::{
        running_sum::{LimbBits, RunningSumChip, RunningSumConfig},
        u128::UintChip,
    },
    statement::foreign_limbs,
    tamper::undetected_tampers,
};

// ---------------------------------------------------------------------------
// Harness
// ---------------------------------------------------------------------------

/// The step-proof digest domain (`kgwstep1`).
const STEP_DOMAIN: u64 = u64::from_le_bytes(*b"kgwstep1");
/// The Omega || sigma `proof_digest` domain (`kgwprf_1`).
const PROOF_DOMAIN: u64 = u64::from_le_bytes(*b"kgwprf_1");

/// The chips a program drives.
struct Chips<F: PoseidonField> {
    glue: GlueChip<F>,
    range: RunningSumChip<F>,
    bytes: BytesChip<F>,
    sponge: SpongeChip<F>,
}

impl<F: PoseidonField> Chips<F> {
    fn uint(&mut self) -> UintChip<'_, F> {
        UintChip::new(&mut self.glue, &mut self.range)
    }
}

/// The inputs of a program: bytes and field witnesses (unknown during key
/// generation) and configuration-time arguments.
#[derive(Clone, Debug, Default)]
struct Inputs<F> {
    bytes: Vec<u8>,
    fields: Vec<F>,
    args: Vec<u64>,
    known: bool,
}

impl<F: PastaField> Inputs<F> {
    fn new(bytes: Vec<u8>, fields: Vec<F>, args: Vec<u64>) -> Self {
        Self {
            bytes,
            fields,
            args,
            known: true,
        }
    }

    fn bytes(&self) -> Vec<Value<u8>> {
        self.bytes
            .iter()
            .map(|byte| {
                if self.known {
                    Value::known(*byte)
                } else {
                    Value::unknown()
                }
            })
            .collect()
    }

    fn field(&self, index: usize) -> Value<F> {
        match self.fields.get(index) {
            Some(value) if self.known => Value::known(*value),
            _ => Value::unknown(),
        }
    }

    fn all_fields(&self) -> Vec<Value<F>> {
        (0..self.fields.len())
            .map(|index| self.field(index))
            .collect()
    }

    fn arg(&self, index: usize) -> u64 {
        self.args.get(index).copied().unwrap_or(0)
    }

    fn arg_usize(&self, index: usize) -> usize {
        usize::try_from(self.arg(index)).unwrap_or(usize::MAX)
    }
}

/// A program over the chips; its words become the public instance.
type Program<F> = fn(&mut Chips<F>, &mut Region<'_, F>, &Inputs<F>) -> Result<Vec<Word<F>>, Error>;

/// The configuration-time shape: public outputs and the running-sum limb
/// width.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Shape {
    public: usize,
    limb_bits: usize,
}

impl Default for Shape {
    fn default() -> Self {
        Self {
            public: 1,
            limb_bits: 8,
        }
    }
}

#[derive(Clone)]
struct BytesCircuit<F: PoseidonField> {
    shape: Shape,
    program: Program<F>,
    inputs: Inputs<F>,
}

#[derive(Clone, Debug)]
struct BytesTestConfig<F> {
    glue: GlueConfig,
    range: RunningSumConfig,
    bytes: BytesConfig,
    sponge: SpongeConfig<F>,
    instance: Column<Instance>,
}

impl<F: PoseidonField> Circuit<F> for BytesCircuit<F> {
    type Config = BytesTestConfig<F>;
    type FloorPlanner = SimpleFloorPlanner;
    type Params = Shape;

    fn without_witnesses(&self) -> Self {
        let mut circuit = self.clone();
        circuit.inputs.known = false;
        circuit
    }

    fn params(&self) -> Shape {
        self.shape
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        Self::configure_with_params(meta, Shape::default())
    }

    fn configure_with_params(meta: &mut ConstraintSystem<F>, shape: Shape) -> Self::Config {
        let advice: [Column<Advice>; 4] = core::array::from_fn(|_| meta.advice_column());
        let constants = meta.fixed_column();
        let glue = GlueConfig::configure(meta, advice, constants);
        let z = meta.advice_column();
        let limb_bits = LimbBits::new(shape.limb_bits).unwrap_or_else(|| unreachable!("width"));
        let range = RunningSumConfig::configure(meta, z, limb_bits);
        let primary = meta.advice_column();
        let secondary = meta.advice_column();
        let bytes = BytesConfig::configure(meta, primary, secondary);
        let lane = Pow5Columns::allocate(meta);
        let round_constants = RoundConstantColumns::allocate(meta);
        let sponge = SpongeConfig::configure(meta, lane, round_constants, &[]);
        let instance = meta.instance_column(shape.public);
        meta.enable_equality(instance);
        BytesTestConfig {
            glue,
            range,
            bytes,
            sponge,
            instance,
        }
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {
        let mut chips = Chips {
            glue: GlueChip::new(config.glue),
            range: RunningSumChip::new(config.range),
            bytes: BytesChip::new(config.bytes),
            sponge: SpongeChip::new(config.sponge),
        };
        chips.range.load_table(&mut layouter)?;
        chips.bytes.load_table(&mut layouter)?;
        let program = self.program;
        let outputs = layouter.assign_region(
            || "bytes",
            |mut region| program(&mut chips, &mut region, &self.inputs),
        )?;
        if outputs.len() != self.shape.public {
            return Err(Error::Synthesis);
        }
        for (row, word) in outputs.iter().enumerate() {
            layouter.constrain_instance(word.cell(), config.instance, row)?;
        }
        Ok(())
    }
}

/// Advice columns of [`BytesCircuit`]: glue 0..4, range 4, tape 5 and 6,
/// lane 7..11.
const GLUE_COLUMNS: core::ops::Range<usize> = 0..4;
const RANGE_COLUMN: usize = 4;
const TAPE_COLUMNS: [usize; 2] = [5, 6];

fn build<F: PoseidonField>(
    program: Program<F>,
    inputs: Inputs<F>,
    public: usize,
) -> BytesCircuit<F> {
    BytesCircuit {
        shape: Shape {
            public,
            limb_bits: 8,
        },
        program,
        inputs,
    }
}

fn accepts<F: PoseidonField>(circuit: &BytesCircuit<F>, k: u32, public: &[F]) -> bool {
    check_circuit(circuit, k, &[public.to_vec()], CheckMode::Strict)
        .is_ok_and(|report| report.is_satisfied())
}

fn report<F: PoseidonField>(circuit: &BytesCircuit<F>, k: u32, public: &[F]) -> String {
    check_circuit(circuit, k, &[public.to_vec()], CheckMode::Strict).map_or_else(
        |error| format!("synthesis error: {error}"),
        |report| report.to_string(),
    )
}

/// Whether the circuit is rejected and every failure is a missing lookup
/// input (a range or byte table rejected a value).
fn only_lookup_failures<F: PoseidonField>(circuit: &BytesCircuit<F>, k: u32, public: &[F]) -> bool {
    let report = check_circuit(circuit, k, &[public.to_vec()], CheckMode::Strict).expect("check");
    !report.is_satisfied()
        && report
            .failures()
            .iter()
            .all(|failure| matches!(failure, CheckFailure::LookupInputMissing { .. }))
}

fn assert_no_undetected<F: PoseidonField>(circuit: &BytesCircuit<F>, k: u32, public: &[F]) {
    assert_eq!(
        undetected_tampers(circuit, k, &[public.to_vec()]),
        Ok(Vec::new()),
        "{}",
        report(circuit, k, public)
    );
}

/// Deterministic test bytes.
fn pattern(len: usize, seed: u8) -> Vec<u8> {
    (0..len)
        .map(|index| {
            let index = u8::try_from(index % 251).unwrap_or(0);
            index.wrapping_mul(37).wrapping_add(seed) ^ 0x5a
        })
        .collect()
}

fn hex_bytes(text: &str) -> Vec<u8> {
    assert_eq!(text.len() % 2, 0, "even hex");
    (0..text.len() / 2)
        .map(|i| u8::from_str_radix(&text[2 * i..2 * i + 2], 16).expect("hex digit"))
        .collect()
}

fn hex_field<F: PastaField>(text: &str) -> F {
    let bytes: [u8; 32] = hex_bytes(text).try_into().expect("32 bytes");
    Option::from(F::from_repr(bytes)).expect("canonical")
}

fn wallet_vectors() -> Json {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures/kagemusha/wallet_v1_vectors.json");
    let text = std::fs::read_to_string(&path).expect("read wallet_v1_vectors.json");
    norito::json::parse_value(&text).expect("parse wallet_v1_vectors.json")
}

fn text<'a>(value: &'a Json, key: &str) -> &'a str {
    value.get(key).and_then(Json::as_str).expect(key)
}

fn domain_word(label: &str) -> u64 {
    u64::from_le_bytes(label.as_bytes().try_into().expect("8-byte domain"))
}

/// The `poseidon.packing` vectors: `(bytes, domain, items, digest)`.
fn packing_vectors() -> Vec<(Vec<u8>, u64, Vec<Fp>, Fp)> {
    let vectors = wallet_vectors();
    vectors
        .get("poseidon")
        .and_then(|section| section.get("packing"))
        .and_then(Json::as_array)
        .expect("packing vectors")
        .iter()
        .map(|vector| {
            let poseidon = vector.get("poseidon").expect("poseidon");
            let items = poseidon
                .get("items")
                .and_then(Json::as_array)
                .expect("items")
                .iter()
                .map(|item| hex_field(item.as_str().expect("hex")))
                .collect();
            (
                hex_bytes(text(vector, "bytes_hex")),
                domain_word(text(poseidon, "domain")),
                items,
                hex_field(text(poseidon, "digest_hex")),
            )
        })
        .collect()
}

fn word(value: usize) -> u64 {
    u64::try_from(value).expect("64-bit")
}

fn bit<F: PastaField>(value: bool) -> F {
    if value { F::ONE } else { F::ZERO }
}

// ---------------------------------------------------------------------------
// Programs
// ---------------------------------------------------------------------------

/// `P_bytes(arg 0, bytes)` with bytes `0 .. arg 1` constant and the rest on
/// the tape. Outputs every chunk (constant chunks pinned) and the digest.
fn p_bytes_program<F: PoseidonField>(
    chips: &mut Chips<F>,
    region: &mut Region<'_, F>,
    inputs: &Inputs<F>,
) -> Result<Vec<Word<F>>, Error> {
    let split = inputs.arg_usize(1).min(inputs.bytes.len());
    let mut string = PBytes::new();
    string.push_constant(&inputs.bytes[..split]);
    string.push_run(&mut chips.bytes, region, &inputs.bytes()[split..], &[])?;
    let mut out: Vec<Word<F>> = string
        .chunk_words(&mut chips.glue, region)?
        .into_iter()
        .map(|piece| piece.word().clone())
        .collect();
    out.push(string.digest(&mut chips.glue, &mut chips.sponge, region, inputs.arg(0))?);
    Ok(out)
}

/// The leaf-to-aggregator path in one circuit: bytes `0 .. arg 2` are a
/// prefix on the tape; the rest is a proof exported as `LE32 len || proof`
/// pieces at origin `arg 1`, then appended after the prefix (split where
/// they cross a chunk boundary). Outputs `P_bytes(arg 0, ...)`.
fn realign_program<F: PoseidonField>(
    chips: &mut Chips<F>,
    region: &mut Region<'_, F>,
    inputs: &Inputs<F>,
) -> Result<Vec<Word<F>>, Error> {
    let bytes = inputs.bytes();
    let (prefix, proof) = bytes.split_at(inputs.arg_usize(2).min(bytes.len()));
    let mut string = PBytes::new();
    string.push_run(&mut chips.bytes, region, prefix, &[])?;
    let (_run, pieces) = export_length_prefixed(
        &mut chips.bytes,
        &mut chips.glue,
        region,
        proof,
        &[],
        inputs.arg_usize(1),
    )?;
    let mut uint = chips.uint();
    for piece in &pieces {
        let trusted =
            BoundedBytes::trusted(piece.word().clone(), piece.len()).ok_or(Error::Synthesis)?;
        string.push_bounded_split(&mut uint, region, &trusted)?;
    }
    Ok(vec![string.digest(
        &mut chips.glue,
        &mut chips.sponge,
        region,
        inputs.arg(0),
    )?])
}

/// Secondary segments covering most of a run of `len` bytes, little- and
/// big-endian, with one-byte gaps.
fn mixed_segments(len: usize) -> Vec<SegmentSpec> {
    let lengths = [16, 16, 1, 31, 5, 2, 7];
    let mut specs = Vec::new();
    let mut start = 0;
    let mut index = 0;
    while start < len {
        let take = lengths[index % lengths.len()].min(len - start);
        specs.push(if index % 2 == 0 {
            SegmentSpec::little(start, take)
        } else {
            SegmentSpec::big(start, take)
        });
        start += take + usize::from(index % 3 == 2);
        index += 1;
    }
    specs
}

/// A run with primary segments from origin `arg 0` and the secondary
/// segments of [`mixed_segments`]; outputs every primary then every
/// secondary word.
fn tape_program<F: PoseidonField>(
    chips: &mut Chips<F>,
    region: &mut Region<'_, F>,
    inputs: &Inputs<F>,
) -> Result<Vec<Word<F>>, Error> {
    let primary = chunk_segments(inputs.arg_usize(0), inputs.bytes.len());
    let run = chips.bytes.run(
        region,
        &inputs.bytes(),
        &primary,
        &mixed_segments(inputs.bytes.len()),
    )?;
    Ok(run
        .primary()
        .iter()
        .chain(run.secondary())
        .map(|segment| segment.word().clone())
        .collect())
}

fn tape_public<F: PastaField>(bytes: &[u8], origin: usize) -> Vec<F> {
    let mut public = Vec::new();
    let mut at = 0;
    for len in chunk_segments(origin, bytes.len()) {
        public.push(le_value::<F>(&bytes[at..at + len]).expect("segment"));
        at += len;
    }
    for spec in mixed_segments(bytes.len()) {
        let segment = &bytes[spec.start..spec.end()];
        public.push(segment_value::<F>(segment, spec.order).expect("segment"));
    }
    public
}

/// One 32-byte message laid out `[31, 1]` / `[16, 15, 1]` and decoded.
fn message<F: PoseidonField>(
    chips: &mut Chips<F>,
    region: &mut Region<'_, F>,
    inputs: &Inputs<F>,
) -> Result<LeElement<F>, Error> {
    let run = chips.bytes.run(
        region,
        &inputs.bytes(),
        &chunk_segments(0, MESSAGE_BYTES),
        &le_message_segments(0, 1),
    )?;
    decode_le_element(&mut chips.uint(), region, &run, 0)
}

fn direct_message_program<F: PoseidonField>(
    chips: &mut Chips<F>,
    region: &mut Region<'_, F>,
    inputs: &Inputs<F>,
) -> Result<Vec<Word<F>>, Error> {
    let raw: [u8; 32] = inputs
        .bytes
        .clone()
        .try_into()
        .map_err(|_| Error::Synthesis)?;
    let raw = if inputs.known {
        Value::known(raw)
    } else {
        Value::unknown()
    };
    let direct = LeElement::assign(&mut chips.uint(), region, raw)?;
    let tape = message(chips, region, inputs)?;
    let direct = [direct.lo().word(), direct.hi().word(), direct.top().word()];
    for (direct, tape) in direct
        .iter()
        .zip([tape.lo().word(), tape.hi().word(), tape.top().word()])
    {
        GlueChip::assert_equal(region, direct, tape)?;
    }
    Ok(direct.into_iter().cloned().collect())
}
fn direct_messages<F: PoseidonField>() {
    for bytes in [
        vec![0; 32],
        vec![255; 32],
        pattern(32, 11),
        pattern(32, 251),
    ] {
        let lo = u128::from_le_bytes(bytes[..16].try_into().unwrap());
        let hi = u128::from_le_bytes(bytes[16..].try_into().unwrap()) & ((1_u128 << 127) - 1);
        let expected = [
            F::from_u128(lo),
            F::from_u128(hi),
            F::from(u64::from(bytes[31] >> 7)),
        ];
        let circuit = build(
            direct_message_program,
            Inputs::new(bytes, vec![], vec![]),
            3,
        );
        assert!(accepts(&circuit, 9, &expected));
        assert_no_undetected(&circuit, 9, &expected);
        for index in 0..3 {
            let mut bad = expected;
            bad[index] += F::ONE;
            assert!(!accepts(&circuit, 9, &bad));
        }
        let assigned = synthesize(&circuit, 9, Some(&[expected.to_vec()])).unwrap();
        let unknown = synthesize(&circuit.without_witnesses(), 9, None).unwrap();
        assert_eq!(assigned.tables.fixed(), unknown.tables.fixed());
        assert_eq!(assigned.tables.selectors(), unknown.tables.selectors());
        assert_eq!(assigned.tables.permutation(), unknown.tables.permutation());
        assert_eq!(
            assigned.tables.advice_assigned(),
            unknown.tables.advice_assigned()
        );
    }
}
#[test]
fn direct_private_message_assignment_matches_tape_and_rejects_every_cell_tamper() {
    direct_messages::<Fp>();
    direct_messages::<Fq>();
}

/// The point link of the message with `(x, y) = fields`; mode `arg 0`:
/// 0 hard link, 1 soft link, 2 hard decode (`y` given), 3 soft decode (no
/// field input), 4 soft decode with the forced witness `q = arg 1`,
/// `w = fields[1]`, 5 PIPA soft decode, 6 PIPA soft decode with the forced
/// witness. Outputs `[bit,] x, y, lo` (the decoded `x, y` in modes 3-6).
fn point_program<F: PoseidonField>(
    chips: &mut Chips<F>,
    region: &mut Region<'_, F>,
    inputs: &Inputs<F>,
) -> Result<Vec<Word<F>>, Error> {
    let element = message(chips, region, inputs)?;
    let lo = element.lo().word().clone();
    let mode = inputs.arg(0);
    if mode >= 5 {
        let mut uint = chips.uint();
        let decoded = if mode == 5 {
            decode_pipa_point_soft(&mut uint, region, &element)?
        } else {
            let x = element_value(uint.glue(), region, &element)?;
            let witness = inputs.field(1).map(|w| (inputs.arg(1) == 1, w));
            super::element::decode_pipa_point_soft_witnessed(
                &mut uint, region, &element, &x, witness,
            )?
        };
        return Ok(vec![decoded.valid.word().clone(), decoded.x, decoded.y, lo]);
    }
    if mode >= 3 {
        let mut uint = chips.uint();
        let decoded = if mode == 3 {
            decode_point_soft(&mut uint, region, &element)?
        } else {
            let x = element_value(uint.glue(), region, &element)?;
            let witness = inputs.field(1).map(|w| (inputs.arg(1) == 1, w));
            super::element::decode_point_soft_witnessed(&mut uint, region, &element, &x, witness)?
        };
        return Ok(vec![decoded.valid.word().clone(), decoded.x, decoded.y, lo]);
    }
    let y = chips.glue.witness(region, inputs.field(1))?;
    let mut uint = chips.uint();
    match mode {
        0 => {
            let x = uint.glue().witness(region, inputs.field(0))?;
            assert_point_bytes(&mut uint, region, &element, &x, &y)?;
            Ok(vec![x, y, lo])
        }
        1 => {
            let x = uint.glue().witness(region, inputs.field(0))?;
            let valid = point_bytes_match(&mut uint, region, &element, &x, &y)?;
            Ok(vec![valid.word().clone(), x, y, lo])
        }
        _ => {
            let x = decode_point(&mut uint, region, &element, &y)?;
            Ok(vec![x, y, lo])
        }
    }
}

/// The scalar link of the message as a scalar of `Fp` (`arg 1 = 0`) or `Fq`
/// (`arg 1 = 1`); `arg 0`: 0 hard, 1 soft. Outputs `[bit,] lo, hi`.
fn scalar_program<F: PoseidonField>(
    chips: &mut Chips<F>,
    region: &mut Region<'_, F>,
    inputs: &Inputs<F>,
) -> Result<Vec<Word<F>>, Error> {
    let element = message(chips, region, inputs)?;
    let mut uint = chips.uint();
    let valid = match (inputs.arg(0) == 1, inputs.arg(1)) {
        (false, 0) => assert_scalar_bytes::<F, Fp>(&mut uint, region, &element).map(|()| None)?,
        (false, _) => assert_scalar_bytes::<F, Fq>(&mut uint, region, &element).map(|()| None)?,
        (true, 0) => Some(scalar_bytes_canonical::<F, Fp>(
            &mut uint, region, &element,
        )?),
        (true, _) => Some(scalar_bytes_canonical::<F, Fq>(
            &mut uint, region, &element,
        )?),
    };
    let mut out: Vec<Word<F>> = valid.into_iter().map(|bit| bit.word().clone()).collect();
    out.push(element.lo().word().clone());
    out.push(element.hi().word().clone());
    Ok(out)
}

/// The parity of `fields[0]` with the forced decomposition
/// `(fields[1], fields[2], fields[3])`; outputs the bit and `y`.
fn forced_parity_program<F: PoseidonField>(
    chips: &mut Chips<F>,
    region: &mut Region<'_, F>,
    inputs: &Inputs<F>,
) -> Result<Vec<Word<F>>, Error> {
    let y = chips.glue.witness(region, inputs.field(0))?;
    let witness = inputs
        .field(1)
        .zip(inputs.field(2))
        .zip(inputs.field(3))
        .map(|((bit, half), hi)| {
            (
                bit == F::ONE,
                to_u128(&half).unwrap_or(u128::MAX),
                to_u128(&hi).unwrap_or(u128::MAX),
            )
        });
    let parity_bit = element::parity_with_witness(&mut chips.uint(), region, &y, witness)?;
    Ok(vec![parity_bit.word().clone(), y])
}

/// Opaque words of `arg 0` bytes for every field input; outputs them.
fn opaque_program<F: PoseidonField>(
    chips: &mut Chips<F>,
    region: &mut Region<'_, F>,
    inputs: &Inputs<F>,
) -> Result<Vec<Word<F>>, Error> {
    (0..inputs.fields.len())
        .map(|index| {
            opaque_bytes(
                &mut chips.range,
                region,
                inputs.field(index),
                inputs.arg_usize(0),
            )
            .map(|piece| piece.word().clone())
        })
        .collect()
}

/// The big-endian 32-byte value at offset 1 of `0x04 || X` (the head of a
/// SEC1 key), compared with the 256-bit `max = (args 0, 1) + 2^128 (args 2,
/// 3)` as 64-bit words. Outputs `hi, lo, bit` and both chunk words.
fn be_program<F: PoseidonField>(
    chips: &mut Chips<F>,
    region: &mut Region<'_, F>,
    inputs: &Inputs<F>,
) -> Result<Vec<Word<F>>, Error> {
    let run = chips.bytes.run(
        region,
        &inputs.bytes(),
        &chunk_segments(0, inputs.bytes.len()),
        &be_value_segments(1, 1),
    )?;
    let value = decode_be_element(&run, 1)?;
    let words = [0, 1, 2, 3].map(|index| u128::from(inputs.arg(index)));
    let max = [words[0] | (words[1] << 64), words[2] | (words[3] << 64)];
    let within = le_max(&mut chips.uint(), region, value.lo(), value.hi(), max)?;
    let mut out = vec![
        value.hi().word().clone(),
        value.lo().word().clone(),
        within.word().clone(),
    ];
    out.extend(run.primary().iter().map(|segment| segment.word().clone()));
    Ok(out)
}

/// A bounded word pushed across a chunk boundary is refused, and accepted
/// once the string is aligned; outputs the word.
fn crossing_program<F: PoseidonField>(
    chips: &mut Chips<F>,
    region: &mut Region<'_, F>,
    inputs: &Inputs<F>,
) -> Result<Vec<Word<F>>, Error> {
    let word = chips.glue.witness(region, inputs.field(0))?;
    let piece = BoundedBytes::trusted(word.clone(), 2).ok_or(Error::Synthesis)?;
    let mut string = PBytes::new();
    string.push_constant(&[0; 30]);
    if string.push_bounded(piece.clone()) != Err(Error::Synthesis) || string.len() != 30 {
        return Err(Error::BoundsFailure);
    }
    string.push_constant(&[0]);
    string.push_bounded(piece)?;
    if string.len() != 33 || string.piece_lengths() != vec![31, 2] {
        return Err(Error::BoundsFailure);
    }
    Ok(vec![word])
}

// ---------------------------------------------------------------------------
// P_bytes
// ---------------------------------------------------------------------------

#[test]
fn chunk_planner_cuts_at_chunk_boundaries() {
    assert!(chunk_segments(0, 0).is_empty());
    assert_eq!(chunk_segments(0, 30), vec![30]);
    assert_eq!(chunk_segments(0, 31), vec![31]);
    assert_eq!(chunk_segments(0, 32), vec![31, 1]);
    assert_eq!(chunk_segments(0, 62), vec![31, 31]);
    assert_eq!(chunk_segments(4, 30), vec![27, 3]);
    assert_eq!(chunk_segments(28, 3), vec![3]);
    assert_eq!(chunk_segments(62, 1), vec![1]);
    // The sigma export: 3,300 bytes of `LE32 len || sigma` from origin 0.
    let pieces = chunk_segments(0, LENGTH_PREFIX_BYTES + SIGMA_PROOF_BYTES);
    assert_eq!(pieces.len(), SIGMA_EXPORT_CHUNKS);
    assert_eq!(pieces[106], 14);
    assert!(pieces[..106].iter().all(|len| *len == 31));
    let proof = chunk_segments(LENGTH_PREFIX_BYTES, SIGMA_PROOF_BYTES);
    assert_eq!(proof[0], 27);
    assert_eq!(proof.len(), SIGMA_EXPORT_CHUNKS);
    assert_eq!(length_prefixed_chunks(48), 2);
    for offset in 0..70 {
        for len in [0, 1, 30, 31, 32, 62, 100] {
            let plan = chunk_segments(offset, len);
            assert_eq!(plan.iter().sum::<usize>(), len);
            let mut at = offset;
            for piece in plan {
                assert!(piece >= 1 && at % CHUNK_BYTES + piece <= CHUNK_BYTES);
                at += piece;
            }
        }
    }
}

#[test]
fn native_p_bytes_matches_the_wallet_vectors() {
    let vectors = packing_vectors();
    assert_eq!(vectors.len(), 7);
    for (bytes, domain, items, digest) in vectors {
        assert_eq!(p_bytes_items_native::<Fp>(&bytes), items, "{}", bytes.len());
        assert_eq!(p_bytes_native::<Fp>(domain, &bytes), digest);
    }
}

/// The in-circuit `P_bytes` of the shared wallet packing vectors (written
/// and asserted by the data-model implementation) at lengths 0, 30, 31, 32
/// and 62, plus the fixture's 1 and 63: with every split between constant
/// bytes and tape bytes, every chunk word and the digest equal the vector;
/// a wrong chunk or digest is rejected; the same strings over `Fq` match
/// the native reference.
#[test]
fn p_bytes_link_matches_native_at_chunk_boundaries() {
    let mut lengths = Vec::new();
    for (bytes, domain, items, digest) in packing_vectors() {
        lengths.push(bytes.len());
        let mut public = items[1..].to_vec();
        public.push(digest);
        for split in 0..=bytes.len() {
            let inputs = Inputs::new(bytes.clone(), Vec::new(), vec![domain, word(split)]);
            let circuit = build(p_bytes_program::<Fp>, inputs, public.len());
            assert!(
                accepts(&circuit, 9, &public),
                "len {} split {split}: {}",
                bytes.len(),
                report(&circuit, 9, &public)
            );
            if split == 0 || split == bytes.len() / 2 {
                for position in 0..public.len() {
                    let mut wrong = public.clone();
                    wrong[position] += Fp::ONE;
                    assert!(!accepts(&circuit, 9, &wrong), "position {position}");
                }
            }
        }
        let mut fq_public = p_bytes_items_native::<Fq>(&bytes)[1..].to_vec();
        fq_public.push(p_bytes_native::<Fq>(domain, &bytes));
        let inputs = Inputs::new(bytes.clone(), Vec::new(), vec![domain, 0]);
        let fq_circuit = build(p_bytes_program::<Fq>, inputs, fq_public.len());
        assert!(accepts(&fq_circuit, 9, &fq_public));
    }
    lengths.sort_unstable();
    assert_eq!(lengths, vec![0, 1, 30, 31, 32, 62, 63]);
}

/// The proofs of a `LE32 len || proof || ...` body, or `None` when the body
/// is not such a concatenation.
fn split_length_prefixed(body: &[u8]) -> Option<Vec<Vec<u8>>> {
    let mut proofs = Vec::new();
    let mut at = 0;
    while at < body.len() {
        let len = u32::from_le_bytes(body.get(at..at + 4)?.try_into().ok()?);
        let start = at + LENGTH_PREFIX_BYTES;
        let end = start.checked_add(usize::try_from(len).ok()?)?;
        proofs.push(body.get(start..end)?.to_vec());
        at = end;
    }
    Some(proofs)
}

/// The `P_bytes` vectors of one `poseidon` section of the shared wallet
/// vectors: `(body, domain, digest)`.
fn p_bytes_vectors(section: &str) -> Vec<(Vec<u8>, u64, Fp)> {
    let vectors = wallet_vectors();
    vectors
        .get("poseidon")
        .and_then(|poseidon| poseidon.get(section))
        .and_then(Json::as_array)
        .unwrap_or_else(|| panic!("poseidon.{section}"))
        .iter()
        .map(|object| {
            let body = hex_bytes(text(object, "body_hex"));
            let domain = domain_word(text(object, "domain"));
            let digest = hex_field::<Fp>(text(object, "digest_hex"));
            let elements = object
                .get("elements")
                .and_then(Json::as_u64)
                .expect("elements");
            let items = p_bytes_items_native::<Fp>(&body);
            assert_eq!(u64::try_from(items.len()).expect("len"), elements);
            assert_eq!(p_bytes_native::<Fp>(domain, &body), digest);
            (body, domain, digest)
        })
        .collect()
}

/// `P_bytes(domain, body)` in circuit: the whole body on the tape, every
/// chunk and the digest public. Returns the smallest accepting `k`; another
/// digest is rejected.
fn assert_p_bytes_in_circuit(body: &[u8], domain: u64, digest: Fp) -> u32 {
    let mut public = p_bytes_items_native::<Fp>(body)[1..].to_vec();
    public.push(digest);
    let inputs = Inputs::new(body.to_vec(), Vec::new(), vec![domain, 0]);
    let whole = build(p_bytes_program::<Fp>, inputs, public.len());
    let k = (10..=13)
        .find(|k| accepts(&whole, *k, &public))
        .unwrap_or_else(|| panic!("{}", report(&whole, 13, &public)));
    let mut wrong = public;
    if let Some(last) = wrong.last_mut() {
        *last += Fp::ONE;
    }
    assert!(!accepts(&whole, k, &wrong));
    k
}

/// The large-input `P_bytes` digests of the shared wallet vectors
/// (`poseidon.large_input_digests`): both `proof_digest` domains, the
/// Payment digest and the lineage, credit-opening, credit-status and
/// credited digests (owner answer A3). Each body packs natively and in
/// circuit to its vectored element count and digest; for the two proof
/// domains the last length-prefixed proof is also exported and appended
/// after the rest, as the leaf hands sigma to the aggregator.
#[test]
fn large_input_digests_match_the_wallet_vectors() {
    let mut domains = Vec::new();
    for (body, domain, digest) in p_bytes_vectors("large_input_digests") {
        if domains.last() != Some(&domain) {
            domains.push(domain);
        }
        let k = assert_p_bytes_in_circuit(&body, domain, digest);
        if domain == STEP_DOMAIN || domain == PROOF_DOMAIN {
            let proofs = split_length_prefixed(&body).expect("length-prefixed proofs");
            let last = proofs.last().expect("one proof");
            let prefix_len = body.len() - LENGTH_PREFIX_BYTES - last.len();
            let mut inputs = body[..prefix_len].to_vec();
            inputs.extend_from_slice(last);
            let inputs = Inputs::new(inputs, Vec::new(), vec![domain, 0, word(prefix_len)]);
            let realigned = build(realign_program::<Fp>, inputs, 1);
            assert!(
                accepts(&realigned, k, &[digest]),
                "{}",
                report(&realigned, k, &[digest])
            );
            assert!(!accepts(&realigned, k, &[digest + Fp::ONE]));
        }
    }
    assert_eq!(
        domains,
        [
            "kgwprf_1", "kgwstep1", "kgwpay_1", "kgwlin_1", "kgwcopn1", "kgwcsts1", "kgwcrdd1",
        ]
        .map(domain_word)
        .to_vec()
    );
}

/// The signing messages of the shared wallet vectors
/// (`poseidon.signing_messages`, owner answer A1): every signed body's
/// 32-byte message `m = P_bytes(d, transcript)` packs natively and in
/// circuit to its vectored value, under each of the 16 signing domains.
#[test]
fn signing_messages_match_the_wallet_vectors() {
    let mut domains = std::collections::BTreeSet::new();
    for (body, domain, message) in p_bytes_vectors("signing_messages") {
        domains.insert(domain);
        assert_p_bytes_in_circuit(&body, domain, message);
    }
    let expected: std::collections::BTreeSet<u64> = [
        "kgwcert1", "kgwcred1", "kgwrnch1", "kgwrnkb1", "kgwartf1", "kgwrcpt1", "kgwspol1",
        "kgwfsch1", "kgwblst1", "kgwqshr1", "kgwtanc1", "kgwchgq1", "kgwoffr1", "kgwsctl1",
        "kgwrqst1", "kgwlctl1",
    ]
    .map(domain_word)
    .into_iter()
    .collect();
    assert_eq!(domains, expected);
}

/// The export at several origins, appended after prefixes at every class of
/// in-chunk offset: each realignment equals the native `P_bytes` of the
/// concatenation.
#[test]
fn length_prefixed_export_realigns_at_every_offset() {
    let proof = pattern(75, 3);
    for origin in [0_u64, 1, 7, 27, 28, 30] {
        for prefix_len in [0_usize, 1, 7, 27, 28, 30, 31, 35, 59] {
            let mut string = pattern(prefix_len, 9);
            let mut inputs = string.clone();
            inputs.extend_from_slice(&proof);
            string.extend_from_slice(&length_prefix(proof.len()).expect("len"));
            string.extend_from_slice(&proof);
            let expected = p_bytes_native::<Fp>(STEP_DOMAIN, &string);
            let inputs = Inputs::new(
                inputs,
                Vec::new(),
                vec![STEP_DOMAIN, origin, word(prefix_len)],
            );
            let circuit = build(realign_program::<Fp>, inputs, 1);
            assert!(
                accepts(&circuit, 9, &[expected]),
                "origin {origin} prefix {prefix_len}: {}",
                report(&circuit, 9, &[expected])
            );
            assert!(!accepts(&circuit, 9, &[expected + Fp::ONE]));
        }
    }
}

/// Exports sigma at origin 0 with message segments; outputs the pieces.
fn sigma_export_program<F: PoseidonField>(
    chips: &mut Chips<F>,
    region: &mut Region<'_, F>,
    inputs: &Inputs<F>,
) -> Result<Vec<Word<F>>, Error> {
    let (run, pieces) = export_length_prefixed(
        &mut chips.bytes,
        &mut chips.glue,
        region,
        &inputs.bytes(),
        &le_message_segments(0, inputs.bytes.len() / MESSAGE_BYTES),
        0,
    )?;
    if pieces.iter().map(BoundedBytes::len).sum::<usize>() != LENGTH_PREFIX_BYTES + run.len() {
        return Err(Error::Synthesis);
    }
    Ok(pieces.iter().map(|piece| piece.word().clone()).collect())
}

#[test]
fn sigma_export_has_107_chunks_matching_native() {
    let sigma = pattern(SIGMA_PROOF_BYTES, 1);
    let mut string = length_prefix(SIGMA_PROOF_BYTES).expect("len").to_vec();
    string.extend_from_slice(&sigma);
    let items = p_bytes_items_native::<Fq>(&string);
    assert_eq!(items.len(), SIGMA_EXPORT_CHUNKS + 1);
    assert_eq!(items[0], Fq::from(3_300_u64));
    let circuit = build(
        sigma_export_program::<Fq>,
        Inputs::new(sigma, Vec::new(), Vec::new()),
        SIGMA_EXPORT_CHUNKS,
    );
    let public = items[1..].to_vec();
    assert!(
        accepts(&circuit, 12, &public),
        "{}",
        report(&circuit, 12, &public)
    );
    let mut wrong = public.clone();
    wrong[0] += Fq::ONE;
    assert!(!accepts(&circuit, 12, &wrong));
    let mut wrong = public;
    wrong[106] += Fq::ONE;
    assert!(!accepts(&circuit, 12, &wrong));
}

// ---------------------------------------------------------------------------
// Tape
// ---------------------------------------------------------------------------

#[test]
fn tape_segments_match_native_integers() {
    for (len, origin) in [(1_usize, 0_u64), (31, 0), (70, 5), (100, 30)] {
        for bytes in [pattern(len, 11), vec![0xff; len], vec![0; len]] {
            let public = tape_public::<Fp>(&bytes, usize::try_from(origin).expect("origin"));
            let inputs = Inputs::new(bytes.clone(), Vec::new(), vec![origin]);
            let circuit = build(tape_program::<Fp>, inputs, public.len());
            assert!(
                accepts(&circuit, 9, &public),
                "{}",
                report(&circuit, 9, &public)
            );
            for position in 0..public.len() {
                let mut wrong = public.clone();
                wrong[position] += Fp::ONE;
                assert!(!accepts(&circuit, 9, &wrong));
            }
            let fq_public = tape_public::<Fq>(&bytes, usize::try_from(origin).expect("origin"));
            let inputs = Inputs::new(bytes, Vec::new(), vec![origin]);
            let fq_circuit = build(tape_program::<Fq>, inputs, fq_public.len());
            assert!(accepts(&fq_circuit, 9, &fq_public));
        }
    }
}

/// A run whose primary lengths do not cover it.
fn short_run_program<F: PoseidonField>(
    chips: &mut Chips<F>,
    region: &mut Region<'_, F>,
    inputs: &Inputs<F>,
) -> Result<Vec<Word<F>>, Error> {
    chips.bytes.run(region, &inputs.bytes(), &[2], &[])?;
    Ok(Vec::new())
}

/// Hashes a string with a nonzero origin.
fn shifted_digest_program<F: PoseidonField>(
    chips: &mut Chips<F>,
    region: &mut Region<'_, F>,
    _inputs: &Inputs<F>,
) -> Result<Vec<Word<F>>, Error> {
    let mut string = PBytes::starting_at(3)?;
    string.push_constant(&[1]);
    Ok(vec![string.digest(
        &mut chips.glue,
        &mut chips.sponge,
        region,
        STEP_DOMAIN,
    )?])
}

#[test]
fn tape_and_packing_misuse_is_a_synthesis_error() {
    let short = build(
        short_run_program::<Fp>,
        Inputs::new(vec![1, 2, 3], Vec::new(), Vec::new()),
        0,
    );
    assert_eq!(
        synthesize(&short, 9, Some(&[Vec::new()][..])).map(|_| ()),
        Err(Error::Synthesis)
    );
    let crossing = build(
        crossing_program::<Fp>,
        Inputs::new(Vec::new(), vec![Fp::from(0x0102_u64)], Vec::new()),
        1,
    );
    assert!(accepts(&crossing, 9, &[Fp::from(0x0102_u64)]));
    // A digest needs a string starting at a chunk boundary.
    let shifted = build(
        shifted_digest_program::<Fp>,
        Inputs::new(Vec::new(), Vec::new(), Vec::new()),
        1,
    );
    assert_eq!(
        synthesize(&shifted, 9, Some(&[vec![Fp::ZERO]][..])).map(|_| ()),
        Err(Error::Synthesis)
    );
}

// ---------------------------------------------------------------------------
// Points
// ---------------------------------------------------------------------------

/// The compressed encoding of `point` (`GroupEncoding::to_bytes` through the
/// `PastaAffine` bound).
fn compressed<A: PastaAffine>(point: &A) -> [u8; 32] {
    point.to_bytes()
}

fn points<A: PastaAffine>(count: u64) -> Vec<A> {
    (1..=count)
        .map(|k| A::from(A::generator() * A::ScalarExt::from(k * 7_919 + 3)))
        .collect()
}

/// `value + modulus` as 32 little-endian bytes when it is below `2^255`.
fn plus_modulus<F: PastaField>(value: &F) -> Option<[u8; 32]> {
    let mut modulus = (-F::ONE).to_canonical_limbs();
    modulus[0] += 1;
    let limbs = value.to_canonical_limbs();
    let mut out = [0_u64; 4];
    let mut carry = 0_u128;
    for i in 0..4 {
        let sum = u128::from(limbs[i]) + u128::from(modulus[i]) + carry;
        out[i] = u64::try_from(sum & u128::from(u64::MAX)).unwrap_or(0);
        carry = sum >> 64;
    }
    if carry != 0 || out[3] >> 63 != 0 {
        return None;
    }
    let mut bytes = [0_u8; 32];
    for (chunk, limb) in bytes.chunks_exact_mut(8).zip(out) {
        chunk.copy_from_slice(&limb.to_le_bytes());
    }
    Some(bytes)
}

fn point_case<F: PoseidonField>(bytes: [u8; 32], x: F, y: F, mode: u64) -> BytesCircuit<F> {
    let public = if mode == 0 || mode == 2 { 3 } else { 4 };
    build(
        point_program::<F>,
        Inputs::new(bytes.to_vec(), vec![x, y], vec![mode]),
        public,
    )
}

/// The soft decode of `bytes` with the forced witness `(q, w)`.
fn soft_decode_case<F: PoseidonField>(bytes: [u8; 32], q: bool, w: F) -> BytesCircuit<F> {
    build(
        point_program::<F>,
        Inputs::new(bytes.to_vec(), vec![F::ZERO, w], vec![4, u64::from(q)]),
        4,
    )
}

/// The PIPA soft decode of `bytes` with the forced witness `(q, w)`.
fn pipa_decode_case<F: PoseidonField>(bytes: [u8; 32], q: bool, w: F) -> BytesCircuit<F> {
    build(
        point_program::<F>,
        Inputs::new(bytes.to_vec(), vec![F::ZERO, w], vec![6, u64::from(q)]),
        4,
    )
}

/// `[bit,] x, y, lo` for a message (`x` is the cell the program outputs).
fn point_public<F: PastaField>(bytes: &[u8; 32], x: F, y: F, valid: Option<bool>) -> Vec<F> {
    let mut public: Vec<F> = valid.map(bit).into_iter().collect();
    public.extend([x, y, le_value::<F>(&bytes[..16]).expect("lo")]);
    public
}

/// The x a message encodes, reduced (`lo + 2^128 hi`).
fn encoded_x<F: PastaField>(bytes: &[u8; 32]) -> F {
    let mut low = *bytes;
    low[31] &= 0x7f;
    let lo = le_value::<F>(&low[..16]).expect("lo");
    let hi = le_value::<F>(&low[16..]).expect("hi");
    lo + F::from_u128(1 << 127).double() * hi
}

fn wrong_parity_on<A: PastaAffine>()
where
    A::Base: PoseidonField,
{
    let k = 9;
    let mut aliased = 0;
    for point in points::<A>(4) {
        let (x, y) = (point.x(), point.y());
        let bytes = compressed(&point);
        assert_eq!(point_bytes_native(&x, &y), bytes, "native encoding");
        // The soft decode is root-agnostic: either root gives the encoded y
        // and bit 1.
        for root in [y, -y] {
            let circuit = soft_decode_case(bytes, true, root);
            let public = point_public(&bytes, x, y, Some(true));
            assert!(
                accepts(&circuit, k, &public),
                "{}",
                report(&circuit, k, &public)
            );
            assert!(!accepts(
                &circuit,
                k,
                &point_public(&bytes, x, y, Some(false))
            ));
            assert!(!accepts(
                &circuit,
                k,
                &point_public(&bytes, x, -y, Some(true))
            ));
        }
        // Honest: every mode accepts and the soft bits are 1.
        for mode in 0..4 {
            let public = point_public(&bytes, x, y, (mode % 2 == 1).then_some(true));
            let circuit = point_case(bytes, x, y, mode);
            assert!(
                accepts(&circuit, k, &public),
                "mode {mode}: {}",
                report(&circuit, k, &public)
            );
            if mode % 2 == 1 {
                let forced = point_public(&bytes, x, y, Some(false));
                assert!(
                    !accepts(&circuit, k, &forced),
                    "honest soft bit forced to 0"
                );
            }
        }
        // The opposite point (x, -y) with the honest bytes, and the honest
        // (x, y) with the sign bit flipped: a wrong parity either way.
        let mut flipped = bytes;
        flipped[31] ^= 0x80;
        for (label, message, y) in [
            ("opposite point", bytes, -y),
            ("flipped sign bit", flipped, y),
        ] {
            for mode in [0, 2] {
                let public = point_public(&message, x, y, None);
                let circuit = point_case(message, x, y, mode);
                let checked =
                    check_circuit(&circuit, k, &[public], CheckMode::Strict).expect("check");
                assert!(!checked.is_satisfied(), "{label} mode {mode}");
                // The parity copy, not a range table, rejects it.
                assert!(
                    checked
                        .failures()
                        .iter()
                        .all(|failure| !matches!(failure, CheckFailure::LookupInputMissing { .. })),
                    "{label} mode {mode}: {checked}"
                );
            }
            let circuit = point_case(message, x, y, 1);
            let zero = point_public(&message, x, y, Some(false));
            assert!(
                accepts(&circuit, k, &zero),
                "{label}: {}",
                report(&circuit, k, &zero)
            );
            let one = point_public(&message, x, y, Some(true));
            assert!(!accepts(&circuit, k, &one), "{label} soft bit forced to 1");
        }
        // The flipped sign bit is the valid encoding of (x, -y): the soft
        // decode returns that point with bit 1.
        let decoded = point_case(flipped, x, y, 3);
        assert!(accepts(
            &decoded,
            k,
            &point_public(&flipped, x, -y, Some(true))
        ));
        assert!(!accepts(
            &decoded,
            k,
            &point_public(&flipped, x, y, Some(true))
        ));
        // A wrong x with the honest bytes: the hard link rejects, the soft
        // link flags it.
        let wrong_x = x + A::Base::ONE;
        let hard = point_case(bytes, wrong_x, y, 0);
        assert!(!accepts(&hard, k, &point_public(&bytes, wrong_x, y, None)));
        let soft = point_case(bytes, wrong_x, y, 1);
        assert!(accepts(
            &soft,
            k,
            &point_public(&bytes, wrong_x, y, Some(false))
        ));
        // The non-canonical encoding of x + p (the same field element): only
        // the canonical comparison (a range lookup) rejects it.
        if let Some(mut alias) = plus_modulus(&x) {
            aliased += 1;
            alias[31] |= bytes[31] & 0x80;
            assert_eq!(encoded_x::<A::Base>(&alias), x);
            for mode in [0, 2] {
                let circuit = point_case(alias, x, y, mode);
                let public = point_public(&alias, x, y, None);
                assert!(
                    only_lookup_failures(&circuit, k, &public),
                    "x + p mode {mode}"
                );
            }
            for mode in [1, 3] {
                let circuit = point_case(alias, x, y, mode);
                assert!(accepts(
                    &circuit,
                    k,
                    &point_public(&alias, x, y, Some(false))
                ));
                assert!(!accepts(
                    &circuit,
                    k,
                    &point_public(&alias, x, y, Some(true))
                ));
            }
        }
    }
    assert!(aliased > 0, "no point with x + p < 2^255 sampled");
    // x = 0 (the identity encoding) has no curve point: 5 is not a square
    // in the base field, which the soft decode's square test relies on.
    assert!(bool::from(A::Base::from(5_u64).sqrt().is_none()));
}

/// The compressed-point link on both curves (Pallas in an `Fp` circuit,
/// Vesta in an `Fq` circuit): a wrong parity (the opposite point `(x, -y)`
/// or a flipped sign bit), a wrong `x` and the non-canonical `x + p` are
/// unsatisfiable in the hard forms and give bit 0 in the soft link, which is
/// satisfiable for every input; honest points give bit 1. The soft decode
/// selects the root of the sign bit's parity from either root, and flags a
/// non-canonical `x`.
#[test]
fn point_bytes_link_rejects_wrong_parity() {
    wrong_parity_on::<EpAffine>();
    wrong_parity_on::<EqAffine>();
}

/// Native reference of the soft decode: the native decoder's point and
/// verdict, and on a rejection the outputs the circuit still computes (the
/// reduced `x` and the root of `x^3 + 5` or `5 (x^3 + 5)` with the sign
/// bit's parity).
fn soft_decode_native<A: PastaAffine>(bytes: &[u8; 32]) -> (bool, A::Base, A::Base) {
    if let Some(point) = Option::<A>::from(A::from_bytes(bytes)) {
        return (true, point.x(), point.y());
    }
    let x = encoded_x::<A::Base>(bytes);
    let (_, root) = super::element::soft_root_witness(&x);
    let y = if root.to_repr()[0] & 1 == bytes[31] >> 7 {
        root
    } else {
        -root
    };
    (false, x, y)
}

/// Messages around the native decoder's edges: points with both sign bits
/// and their non-canonical `x + p`, the identity encoding and the signed
/// zero, an `x` off the curve with both sign bits, and `x = p - 1`.
fn soft_decode_messages<A: PastaAffine>() -> Vec<[u8; 32]> {
    let mut out = Vec::new();
    for point in points::<A>(2) {
        let bytes = compressed(&point);
        let mut flipped = bytes;
        flipped[31] ^= 0x80;
        out.extend([bytes, flipped]);
        if let Some(mut alias) = plus_modulus(&point.x()) {
            alias[31] |= bytes[31] & 0x80;
            out.push(alias);
        }
    }
    let mut signed_zero = [0_u8; 32];
    signed_zero[31] = 0x80;
    out.extend([[0_u8; 32], signed_zero]);
    let b = A::Base::from(5_u64);
    // About half of all x are off the curve; 64 candidates always suffice.
    let off = (2_u64..66)
        .map(A::Base::from)
        .find(|x| bool::from((x.square() * x + b).sqrt().is_none()))
        .expect("an x off the curve");
    let mut off_bytes = off.to_repr();
    out.push(off_bytes);
    off_bytes[31] |= 0x80;
    out.push(off_bytes);
    out.push((-A::Base::ONE).to_repr());
    out
}

fn soft_decode_on<A: PastaAffine>()
where
    A::Base: PoseidonField,
{
    let k = 9;
    let messages = soft_decode_messages::<A>();
    let mut verdicts = [0_usize; 2];
    for bytes in &messages {
        let (valid, x, y) = soft_decode_native::<A>(bytes);
        verdicts[usize::from(valid)] += 1;
        let public = point_public(bytes, x, y, Some(valid));
        let circuit = point_case(*bytes, A::Base::ZERO, A::Base::ZERO, 3);
        assert!(
            accepts(&circuit, k, &public),
            "{bytes:02x?}: {}",
            report(&circuit, k, &public)
        );
        let flipped = point_public(bytes, x, y, Some(!valid));
        assert!(
            !accepts(&circuit, k, &flipped),
            "{bytes:02x?}: verdict flipped"
        );
        // Forced witnesses: either root of the honest square bit gives the
        // same outputs; the other square bit, a wrong root and the root 0
        // have no satisfying assignment.
        let (square, root) = super::element::soft_root_witness(&x);
        for w in [root, -root] {
            let forced = soft_decode_case(*bytes, square, w);
            assert!(
                accepts(&forced, k, &public),
                "{bytes:02x?}: {}",
                report(&forced, k, &public)
            );
        }
        for (q, w) in [
            (!square, root),
            (square, root + A::Base::ONE),
            (square, A::Base::ZERO),
            (!square, A::Base::ZERO),
        ] {
            let forced = soft_decode_case(*bytes, q, w);
            for claim in [valid, !valid] {
                assert!(
                    !accepts(&forced, k, &point_public(bytes, x, y, Some(claim))),
                    "{bytes:02x?}: forged (q, w) = ({q}, {w:?}) accepted"
                );
            }
        }
    }
    assert!(verdicts[0] >= 4 && verdicts[1] >= 4, "{verdicts:?}");
    // The identity encoding decodes to (0, 0) and is accepted; the signed
    // zero, which a free root of 0 used to turn into the identity, is not.
    assert_eq!(
        soft_decode_native::<A>(&[0; 32]),
        (true, A::Base::ZERO, A::Base::ZERO)
    );
    let mut signed_zero = [0_u8; 32];
    signed_zero[31] = 0x80;
    assert!(!soft_decode_native::<A>(&signed_zero).0);
}

/// The soft point decode equals the native decoder
/// (`GroupEncoding::from_bytes`) on every edge message of both curves, and
/// its verdict and point are functions of the bytes: no witness rejects a
/// valid message (a wrong square bit or a non-root) or accepts an invalid
/// one (the signed zero `0x00..0x80`, an `x` off the curve, a non-canonical
/// `x`).
#[test]
fn point_soft_decode_matches_the_native_decoder() {
    soft_decode_on::<EpAffine>();
    soft_decode_on::<EqAffine>();
}

/// Native reference of the PIPA soft decode: the PIPA decoder's point when
/// it accepts (a canonical `x` with a curve point, never the identity),
/// otherwise the dummy `(-1, 2)`.
fn pipa_decode_native<A: PastaAffine>(bytes: &[u8; 32]) -> (bool, A::Base, A::Base) {
    let decoded =
        Option::<A>::from(A::from_bytes(bytes)).filter(|point| !bool::from(point.is_identity()));
    decoded.map_or_else(
        || (false, -A::Base::ONE, A::Base::from(2_u64)),
        |point| (true, point.x(), point.y()),
    )
}

fn pipa_decode_on<A: PastaAffine>(pipa_accepts: impl Fn(&[u8; 32]) -> bool)
where
    A::Base: PoseidonField,
{
    let k = 9;
    let (dummy_x, dummy_y) = PIPA_DUMMY;
    assert_eq!((dummy_x, dummy_y), (-1, 2));
    // The dummy is a curve point (the generator).
    let two = A::Base::from(2_u64);
    assert_eq!(two.square(), -A::Base::ONE + A::Base::from(5_u64));
    let mut verdicts = [0_usize; 2];
    for bytes in &soft_decode_messages::<A>() {
        let (valid, x, y) = pipa_decode_native::<A>(bytes);
        // The verdict is the engine's PIPA-v1 point decoder's.
        assert_eq!(valid, pipa_accepts(bytes), "{bytes:02x?}");
        // ... which is the generic decoder's without the identity.
        let (generic, _, _) = soft_decode_native::<A>(bytes);
        assert_eq!(valid, generic && *bytes != [0; 32], "{bytes:02x?}");
        verdicts[usize::from(valid)] += 1;
        let public = point_public(bytes, x, y, Some(valid));
        let circuit = point_case(*bytes, A::Base::ZERO, A::Base::ZERO, 5);
        assert!(
            accepts(&circuit, k, &public),
            "{bytes:02x?}: {}",
            report(&circuit, k, &public)
        );
        assert!(
            !accepts(&circuit, k, &point_public(bytes, x, y, Some(!valid))),
            "{bytes:02x?}: verdict flipped"
        );
        // Another output point is rejected (the dummy is pinned too).
        assert!(!accepts(
            &circuit,
            k,
            &point_public(bytes, x, y + A::Base::ONE, Some(valid))
        ));
        // Forced witnesses: either root of the honest square bit gives the
        // same outputs; the other square bit, a wrong root and the root 0
        // have no satisfying assignment, whatever the claimed verdict.
        let reduced = encoded_x::<A::Base>(bytes);
        let (square, root) = super::element::soft_root_witness(&reduced);
        for w in [root, -root] {
            let forced = pipa_decode_case(*bytes, square, w);
            assert!(
                accepts(&forced, k, &public),
                "{bytes:02x?}: {}",
                report(&forced, k, &public)
            );
        }
        for (q, w) in [
            (!square, root),
            (square, root + A::Base::ONE),
            (square, A::Base::ZERO),
            (!square, A::Base::ZERO),
        ] {
            let forced = pipa_decode_case(*bytes, q, w);
            for claim in [valid, !valid] {
                for (claimed_x, claimed_y) in [(x, y), (-A::Base::ONE, two)] {
                    assert!(
                        !accepts(
                            &forced,
                            k,
                            &point_public(bytes, claimed_x, claimed_y, Some(claim))
                        ),
                        "{bytes:02x?}: forged (q, w) = ({q}, {w:?}) accepted"
                    );
                }
            }
        }
    }
    assert!(verdicts[0] >= 5 && verdicts[1] >= 4, "{verdicts:?}");
    // The identity encoding: accepted by the generic decoder, rejected here.
    assert!(soft_decode_native::<A>(&[0; 32]).0);
    assert!(!pipa_decode_native::<A>(&[0; 32]).0);
}

/// The PIPA soft point decode equals the engine's PIPA-v1 point decoder
/// (`iroha_plonk::transcript::decode_point`, which rejects the identity
/// encoding that `GroupEncoding::from_bytes` accepts) on every edge message
/// of both curves; a rejected message decodes to the curve point `(-1, 2)`;
/// and no witness flips the verdict or the point.
#[test]
fn point_pipa_soft_decode_matches_the_pipa_decoder() {
    use iroha_pasta::{Ep, Eq};
    use iroha_plonk::transcript::decode_point;
    pipa_decode_on::<EpAffine>(|bytes| decode_point::<Ep>(bytes).is_ok());
    pipa_decode_on::<EqAffine>(|bytes| decode_point::<Eq>(bytes).is_ok());
}

/// The soft decode witness: a root of `x^3 + 5` exactly when it is a
/// square, otherwise a root of `5 (x^3 + 5)`.
#[test]
fn soft_root_witness_squares() {
    for x in [
        Fp::ZERO,
        Fp::ONE,
        -Fp::ONE,
        Fp::from(2_u64),
        Fp::from(3_u64),
    ] {
        let t = x.square() * x + Fp::from(5_u64);
        let (square, root) = super::element::soft_root_witness(&x);
        assert_eq!(square, bool::from(t.sqrt().is_some()));
        let expected = if square { t } else { t * Fp::from(5_u64) };
        assert_eq!(root.square(), expected, "x = {x:?}");
    }
    // The generator's x (-1) is on the curve; x = 0 is not.
    assert!(super::element::soft_root_witness(&-Fp::ONE).0);
    assert!(!super::element::soft_root_witness(&Fp::ZERO).0);
}

/// The foreign point link of the message with `y` given by its limbs
/// `fields = (y_lo, y_hi)` over `G = Fp` (`arg 1 = 0`) or `Fq` (`arg 1 = 1`);
/// `arg 0`: 0 hard, 1 soft. Outputs `[bit,] lo, hi, y_lo, y_hi`.
fn foreign_point_program<F: PoseidonField>(
    chips: &mut Chips<F>,
    region: &mut Region<'_, F>,
    inputs: &Inputs<F>,
) -> Result<Vec<Word<F>>, Error> {
    let element = message(chips, region, inputs)?;
    let mut uint = chips.uint();
    let limb = |index: usize| {
        inputs
            .field(index)
            .map(|value| to_u128(&value).unwrap_or(u128::MAX))
    };
    let y_lo = uint.assign::<128>(region, limb(0))?;
    let y_hi = uint.assign::<128>(region, limb(1))?;
    let valid = match (inputs.arg(0) == 1, inputs.arg(1)) {
        (false, 0) => {
            assert_foreign_point_bytes::<F, Fp>(&mut uint, region, &element, &y_lo, &y_hi)
                .map(|()| None)?
        }
        (false, _) => {
            assert_foreign_point_bytes::<F, Fq>(&mut uint, region, &element, &y_lo, &y_hi)
                .map(|()| None)?
        }
        (true, 0) => Some(foreign_point_bytes_match::<F, Fp>(
            &mut uint, region, &element, &y_lo, &y_hi,
        )?),
        (true, _) => Some(foreign_point_bytes_match::<F, Fq>(
            &mut uint, region, &element, &y_lo, &y_hi,
        )?),
    };
    let mut out: Vec<Word<F>> = valid.into_iter().map(|bit| bit.word().clone()).collect();
    out.extend([
        element.lo().word().clone(),
        element.hi().word().clone(),
        y_lo.word().clone(),
        y_hi.word().clone(),
    ]);
    Ok(out)
}

/// `value + modulus` as two 128-bit limbs (always representable: both are
/// below `2^255`).
fn limbs_plus_modulus<G: PastaField>(value: &G) -> [u128; 2] {
    let [lo, hi] = foreign_limbs(value);
    let [m_lo, m_hi] = modulus_max::<G>();
    let (sum, carry) = lo.overflowing_add(m_lo + 1);
    [sum, hi + m_hi + u128::from(carry)]
}

/// Points of a curve over `G` linked in a circuit over `F` with `y` as
/// limbs: honest points pass (bit 1), the opposite point, a flipped sign
/// bit, the alias `y + |G|` and the non-canonical `x + |G|` fail (bit 0).
fn foreign_points_on<F: PoseidonField, A: PastaAffine>(field: u64)
where
    A::Base: PoseidonField,
{
    let k = 9;
    let case = |bytes: [u8; 32], limbs: [u128; 2], soft: bool| {
        let fields = vec![F::from_u128(limbs[0]), F::from_u128(limbs[1])];
        build(
            foreign_point_program::<F>,
            Inputs::new(bytes.to_vec(), fields, vec![u64::from(soft), field]),
            4 + usize::from(soft),
        )
    };
    let public = |bytes: &[u8; 32], limbs: [u128; 2], valid: Option<bool>| {
        let mut low = *bytes;
        low[31] &= 0x7f;
        let mut out: Vec<F> = valid.map(bit).into_iter().collect();
        out.push(le_value::<F>(&low[..16]).expect("lo"));
        out.push(le_value::<F>(&low[16..]).expect("hi"));
        out.push(F::from_u128(limbs[0]));
        out.push(F::from_u128(limbs[1]));
        out
    };
    let mut aliased = 0;
    for point in points::<A>(3) {
        let bytes = compressed(&point);
        let y = foreign_limbs(&point.y());
        let mut flipped = bytes;
        flipped[31] ^= 0x80;
        let mut cases = vec![
            (bytes, y, true),
            (bytes, foreign_limbs(&-point.y()), false),
            (flipped, y, false),
            (bytes, limbs_plus_modulus(&point.y()), false),
        ];
        if let Some(mut alias) = plus_modulus(&point.x()) {
            aliased += 1;
            alias[31] |= bytes[31] & 0x80;
            cases.push((alias, y, false));
        }
        for (message, limbs, valid) in cases {
            let hard = case(message, limbs, false);
            assert_eq!(
                accepts(&hard, k, &public(&message, limbs, None)),
                valid,
                "{}",
                report(&hard, k, &public(&message, limbs, None))
            );
            let soft = case(message, limbs, true);
            assert!(accepts(&soft, k, &public(&message, limbs, Some(valid))));
            assert!(!accepts(&soft, k, &public(&message, limbs, Some(!valid))));
        }
    }
    assert!(aliased > 0);
}

#[test]
fn foreign_point_bytes_link_canonical_limbs() {
    // Vesta points (Fq coordinates) in an Fp circuit, Pallas in Fq.
    foreign_points_on::<Fp, EqAffine>(1);
    foreign_points_on::<Fq, EpAffine>(0);
}

fn parity_alias_on<F: PoseidonField>() {
    let inverse = F::from(12_345_u64).invert().unwrap_or(F::ONE);
    let mut in_range = 0;
    for y in [
        F::ZERO,
        F::ONE,
        F::from(2_u64),
        -F::ONE,
        -F::from(2_u64),
        inverse,
    ] {
        let [lo, hi] = foreign_limbs(&y);
        let parity_bit = lo & 1 == 1;
        let honest = vec![y, bit(parity_bit), F::from_u128(lo >> 1), F::from_u128(hi)];
        let circuit = build(
            forced_parity_program::<F>,
            Inputs::new(Vec::new(), honest, Vec::new()),
            2,
        );
        let public = [bit(parity_bit), y];
        assert!(
            accepts(&circuit, 9, &public),
            "{}",
            report(&circuit, 9, &public)
        );
        assert!(!accepts(&circuit, 9, &[bit(!parity_bit), y]));
        // The alias y + p: the other parity. Below 2^255 its decomposition
        // passes every range check and only the canonical comparison (a
        // range lookup) rejects it; above, the 127-bit check of `hi` does.
        let [m_lo, m_hi] = modulus_max::<F>();
        let (sum, carry) = lo.overflowing_add(m_lo + 1);
        let alias_hi = hi + m_hi + u128::from(carry);
        in_range += usize::from(alias_hi < 1 << 127);
        let alias_bit = sum & 1 == 1;
        assert_ne!(alias_bit, parity_bit);
        let alias = vec![
            y,
            bit(alias_bit),
            F::from_u128(sum >> 1),
            F::from_u128(alias_hi),
        ];
        let forged = build(
            forced_parity_program::<F>,
            Inputs::new(Vec::new(), alias, Vec::new()),
            2,
        );
        assert!(only_lookup_failures(&forged, 9, &[bit(alias_bit), y]));
    }
    // Small values have an alias below 2^255 that only the comparison rejects.
    assert!(in_range >= 3, "{in_range}");
}

#[test]
fn parity_alias_y_plus_p_is_rejected() {
    parity_alias_on::<Fp>();
    parity_alias_on::<Fq>();
}

// ---------------------------------------------------------------------------
// Scalars and big-endian values
// ---------------------------------------------------------------------------

fn scalar_case<F: PoseidonField>(bytes: [u8; 32], soft: bool, field: u64) -> BytesCircuit<F> {
    build(
        scalar_program::<F>,
        Inputs::new(bytes.to_vec(), Vec::new(), vec![u64::from(soft), field]),
        2 + usize::from(soft),
    )
}

fn scalar_public<F: PastaField>(bytes: &[u8; 32], valid: Option<bool>) -> Vec<F> {
    let mut low = *bytes;
    low[31] &= 0x7f;
    let mut public: Vec<F> = valid.map(bit).into_iter().collect();
    public.push(le_value::<F>(&low[..16]).expect("lo"));
    public.push(le_value::<F>(&low[16..]).expect("hi"));
    public
}

/// Scalars of `G` in a circuit over `F`: zero, small values and `m - 1`
/// pass; `m`, `m + 1`, a value with bit 255 set and all-ones fail (hard) or
/// give bit 0 (soft).
fn scalar_boundaries<F: PoseidonField, G: PastaField>(field: u64) {
    let k = 9;
    let max = (-G::ONE).to_repr();
    // m - 1 is even for both Pasta moduli and its low byte is below 0xfe.
    assert!(max[0] < 0xfe);
    let mut modulus = max;
    modulus[0] += 1;
    let mut above = max;
    above[0] += 2;
    let mut top = G::from(5_u64).to_repr();
    top[31] |= 0x80;
    let cases = [
        (G::ZERO.to_repr(), true),
        (G::from(7_u64).to_repr(), true),
        (max, true),
        (modulus, false),
        (above, false),
        (top, false),
        ([0xff; 32], false),
    ];
    for (bytes, canonical) in cases {
        let hard = scalar_case::<F>(bytes, false, field);
        assert_eq!(
            accepts(&hard, k, &scalar_public::<F>(&bytes, None)),
            canonical,
            "{bytes:02x?}"
        );
        let soft = scalar_case::<F>(bytes, true, field);
        assert!(accepts(
            &soft,
            k,
            &scalar_public::<F>(&bytes, Some(canonical))
        ));
        assert!(!accepts(
            &soft,
            k,
            &scalar_public::<F>(&bytes, Some(!canonical))
        ));
    }
}

#[test]
fn scalar_bytes_canonical_at_m_minus_1_m_and_top_bit() {
    scalar_boundaries::<Fp, Fp>(0);
    scalar_boundaries::<Fp, Fq>(1);
    scalar_boundaries::<Fq, Fp>(0);
    scalar_boundaries::<Fq, Fq>(1);
}

#[test]
fn be_values_decode_and_compare_with_a_256_bit_modulus() {
    // P-256 p - 1 = 2^256 - 2^224 + 2^192 + 2^96 - 2.
    let max_hi: u128 = 0xffff_ffff_0000_0001_0000_0000_0000_0000;
    let max_lo: u128 = 0x0000_0000_ffff_ffff_ffff_ffff_ffff_fffe;
    let words = |value: u128| {
        [
            u64::try_from(value & u128::from(u64::MAX)).expect("low word"),
            u64::try_from(value >> 64).expect("high word"),
        ]
    };
    let [a, b] = words(max_lo);
    let [c, d] = words(max_hi);
    let args = vec![a, b, c, d];
    for (hi, lo, within) in [
        (max_hi, max_lo, true),
        (max_hi, max_lo + 1, false),
        (max_hi - 1, u128::MAX, true),
        (max_hi + 1, 0, false),
        (0, 0, true),
        (u128::MAX, u128::MAX, false),
    ] {
        let mut bytes = vec![0x04];
        bytes.extend_from_slice(&hi.to_be_bytes());
        bytes.extend_from_slice(&lo.to_be_bytes());
        let public = vec![
            Fq::from_u128(hi),
            Fq::from_u128(lo),
            bit(within),
            le_value::<Fq>(&bytes[..31]).expect("chunk"),
            le_value::<Fq>(&bytes[31..]).expect("chunk"),
        ];
        let circuit = build(
            be_program::<Fq>,
            Inputs::new(bytes, Vec::new(), args.clone()),
            5,
        );
        assert!(
            accepts(&circuit, 9, &public),
            "{}",
            report(&circuit, 9, &public)
        );
        let mut wrong = public.clone();
        wrong[2] = Fq::ONE - wrong[2];
        assert!(!accepts(&circuit, 9, &wrong));
        assert_no_undetected(&circuit, 9, &public);
    }
}

// ---------------------------------------------------------------------------
// Opaque chunks
// ---------------------------------------------------------------------------

#[test]
fn opaque_chunks_accept_exactly_their_byte_range() {
    let two = |bits: u64| Fp::from(2_u64).pow_vartime([bits, 0, 0, 0]);
    for len in [1_u64, 16, 31] {
        let ok = vec![Fp::ZERO, two(8 * len) - Fp::ONE];
        let accepted = build(
            opaque_program::<Fp>,
            Inputs::new(Vec::new(), ok.clone(), vec![len]),
            2,
        );
        assert!(accepts(&accepted, 9, &ok));
        for bad in [two(8 * len), -Fp::ONE] {
            let values = vec![Fp::ZERO, bad];
            let rejected = build(
                opaque_program::<Fp>,
                Inputs::new(Vec::new(), values.clone(), vec![len]),
                2,
            );
            assert!(only_lookup_failures(&rejected, 9, &values), "len {len}");
        }
    }
    let long = build(
        opaque_program::<Fp>,
        Inputs::new(Vec::new(), vec![Fp::ZERO], vec![32]),
        1,
    );
    assert_eq!(
        synthesize(&long, 9, Some(&[vec![Fp::ZERO]][..])).map(|_| ()),
        Err(Error::Synthesis)
    );
}

// ---------------------------------------------------------------------------
// Tamper suites
// ---------------------------------------------------------------------------

#[test]
fn tamper_tape_p_bytes_and_realignment() {
    let bytes = pattern(40, 5);
    let public = tape_public::<Fp>(&bytes, 3);
    let inputs = Inputs::new(bytes.clone(), Vec::new(), vec![3]);
    assert_no_undetected(&build(tape_program::<Fp>, inputs, public.len()), 9, &public);
    let mut public = p_bytes_items_native::<Fp>(&bytes)[1..].to_vec();
    public.push(p_bytes_native(STEP_DOMAIN, &bytes));
    let inputs = Inputs::new(bytes, Vec::new(), vec![STEP_DOMAIN, 5]);
    assert_no_undetected(
        &build(p_bytes_program::<Fp>, inputs, public.len()),
        9,
        &public,
    );
    let mut string = pattern(28, 9);
    let mut inputs = string.clone();
    let proof = pattern(35, 4);
    inputs.extend_from_slice(&proof);
    string.extend_from_slice(&length_prefix(proof.len()).expect("len"));
    string.extend_from_slice(&proof);
    let expected = p_bytes_native::<Fp>(STEP_DOMAIN, &string);
    let inputs = Inputs::new(inputs, Vec::new(), vec![STEP_DOMAIN, 0, 28]);
    assert_no_undetected(&build(realign_program::<Fp>, inputs, 1), 9, &[expected]);
}

#[test]
fn tamper_point_links() {
    for point in [points::<EqAffine>(1)[0]] {
        let bytes = compressed(&point);
        for mode in 0..4 {
            let public = point_public(
                &bytes,
                point.x(),
                point.y(),
                (mode % 2 == 1).then_some(true),
            );
            assert_no_undetected(&point_case(bytes, point.x(), point.y(), mode), 9, &public);
        }
        // The PIPA soft decode, accepting and (the identity encoding)
        // rejecting.
        let public = point_public(&bytes, point.x(), point.y(), Some(true));
        assert_no_undetected(&point_case(bytes, Fq::ZERO, Fq::ZERO, 5), 9, &public);
        let public = point_public(&[0; 32], -Fq::ONE, Fq::from(2_u64), Some(false));
        assert_no_undetected(&point_case([0; 32], Fq::ZERO, Fq::ZERO, 5), 9, &public);
    }
    let point = points::<EpAffine>(1)[0];
    let bytes = compressed(&point);
    let public = point_public(&bytes, point.x(), point.y(), None);
    assert_no_undetected(&point_case(bytes, point.x(), point.y(), 0), 9, &public);
    // A Vesta point in an Fp circuit, y as limbs, hard and soft.
    let point = points::<EqAffine>(1)[0];
    let bytes = compressed(&point);
    let [y_lo, y_hi] = foreign_limbs(&point.y());
    let mut low = bytes;
    low[31] &= 0x7f;
    for soft in [false, true] {
        let mut public: Vec<Fp> = soft.then_some(Fp::ONE).into_iter().collect();
        public.extend([
            le_value::<Fp>(&low[..16]).expect("lo"),
            le_value::<Fp>(&low[16..]).expect("hi"),
            Fp::from_u128(y_lo),
            Fp::from_u128(y_hi),
        ]);
        let circuit = build(
            foreign_point_program::<Fp>,
            Inputs::new(
                bytes.to_vec(),
                vec![Fp::from_u128(y_lo), Fp::from_u128(y_hi)],
                vec![u64::from(soft), 1],
            ),
            public.len(),
        );
        assert_no_undetected(&circuit, 9, &public);
    }
}

#[test]
fn tamper_scalar_links_and_parity() {
    let bytes = Fp::from(0x1234_5678_u64)
        .invert()
        .unwrap_or(Fp::ONE)
        .to_repr();
    for soft in [false, true] {
        let public = scalar_public::<Fq>(&bytes, soft.then_some(true));
        assert_no_undetected(&scalar_case::<Fq>(bytes, soft, 0), 9, &public);
    }
    let y = -Fp::from(3_u64);
    let [lo, hi] = foreign_limbs(&y);
    let fields = vec![
        y,
        bit(lo & 1 == 1),
        Fp::from_u128(lo >> 1),
        Fp::from_u128(hi),
    ];
    let parity_circuit = build(
        forced_parity_program::<Fp>,
        Inputs::new(Vec::new(), fields, Vec::new()),
        2,
    );
    assert_no_undetected(&parity_circuit, 9, &[bit(lo & 1 == 1), y]);
}

// ---------------------------------------------------------------------------
// Inventory (8-bit limbs) and the k16 measurement (15-bit limbs)
// ---------------------------------------------------------------------------

/// Assigned advice cells and extent (rows) per column.
fn census<F: PoseidonField>(
    circuit: &BytesCircuit<F>,
    k: u32,
    public: &[F],
) -> (Vec<usize>, Vec<usize>) {
    let synthesized = synthesize(circuit, k, Some(&[public.to_vec()][..])).expect("synthesis");
    let flags = synthesized.tables.advice_assigned();
    let cells = flags
        .iter()
        .map(|column| column.iter().filter(|flag| **flag).count())
        .collect();
    let rows = flags
        .iter()
        .map(|column| {
            column
                .iter()
                .rposition(|flag| *flag)
                .map_or(0, |row| row + 1)
        })
        .collect();
    (cells, rows)
}

fn sum(cells: &[usize], columns: core::ops::Range<usize>) -> usize {
    cells[columns].iter().sum()
}

/// The constraint system summary of a circuit.
fn shape_summary<F: PoseidonField>(circuit: &BytesCircuit<F>) -> String {
    let (cs, _) = configure(circuit).expect("configure");
    format!(
        "advice={} fixed={} selectors={} lookups={} equality={} degree={} blinding={}",
        cs.num_advice_columns(),
        cs.num_fixed_columns(),
        cs.num_selectors(),
        cs.lookups().len(),
        cs.permutation().columns().len(),
        cs.degree(),
        cs.blinding_factors()
    )
}

/// The rows/cells inventory at 8-bit limbs: one tape cell per packed byte,
/// two per linked byte, and the glue/range cells of each link.
#[test]
fn inventory_cells_per_byte_and_per_link() {
    let bytes = pattern(64, 1);
    let public = tape_public::<Fp>(&bytes, 0);
    let inputs = Inputs::new(bytes, Vec::new(), vec![0]);
    let (cells, rows) = census(&build(tape_program::<Fp>, inputs, public.len()), 9, &public);
    let covered: usize = mixed_segments(64).iter().map(|spec| spec.len).sum();
    assert_eq!(cells[TAPE_COLUMNS[0]], 64);
    assert_eq!(cells[TAPE_COLUMNS[1]], covered);
    assert_eq!(rows[TAPE_COLUMNS[0]], 64);
    assert_eq!(sum(&cells, GLUE_COLUMNS) + cells[RANGE_COLUMN], 0);
    // Per link (glue + range cells; the message is 64 tape cells).
    let point = points::<EpAffine>(1)[0];
    let message = compressed(&point);
    let mut links = Vec::new();
    for mode in 0..6 {
        let public = point_public(
            &message,
            point.x(),
            point.y(),
            (mode % 2 == 1 || mode == 4).then_some(true),
        );
        // Mode 4 (forced witness) is the soft decode again: skip it.
        if mode == 4 {
            continue;
        }
        let (cells, _) = census(&point_case(message, point.x(), point.y(), mode), 9, &public);
        assert_eq!(cells[TAPE_COLUMNS[0]] + cells[TAPE_COLUMNS[1]], 64);
        links.push((sum(&cells, GLUE_COLUMNS), cells[RANGE_COLUMN]));
    }
    let scalar = Fq::from(9_u64).to_repr();
    for soft in [false, true] {
        let public = scalar_public::<Fp>(&scalar, soft.then_some(true));
        let (cells, _) = census(&scalar_case::<Fp>(scalar, soft, 1), 9, &public);
        links.push((sum(&cells, GLUE_COLUMNS), cells[RANGE_COLUMN]));
    }
    println!(
        "INVENTORY (8-bit limbs; glue, range cells): point hard {:?}, soft {:?}, decode {:?}, \
         decode soft {:?}, PIPA decode soft {:?}; scalar hard {:?}, soft {:?}",
        links[0], links[1], links[2], links[3], links[4], links[5], links[6]
    );
    // Pinned (8-bit limbs; the glue counts include the program's own `x`
    // and `y` witnesses: two in modes 0 and 1, one in mode 2, none in modes
    // 3 and 5, whose decodes witness their own square bit and root). The
    // PIPA decode drops the identity test and masking (seven rows, 20
    // cells) for one product and two dummy selections (three rows, 9
    // cells). A layout change must update these.
    assert_eq!(
        links,
        vec![
            (39, 100),
            (75, 100),
            (38, 100),
            (105, 100),
            (94, 100),
            (17, 34),
            (40, 34)
        ]
    );
}

/// The leaf side at k16: sigma (3,296 bytes = 43 points + 60 scalars, the
/// PIPA-v1 section 7 split of a k12 descriptor with `d = 6`, 5 advice, 7
/// equality columns and one lookup) exported as 107 pieces with every
/// message linked (points hard; scalars hard against `Fp`). `fields` holds
/// `(x, y)` of the points.
fn sigma_leaf_program(
    chips: &mut Chips<Fq>,
    region: &mut Region<'_, Fq>,
    inputs: &Inputs<Fq>,
) -> Result<Vec<Word<Fq>>, Error> {
    let messages = inputs.bytes.len() / MESSAGE_BYTES;
    let points = inputs.fields.len() / 2;
    let (run, pieces) = export_length_prefixed(
        &mut chips.bytes,
        &mut chips.glue,
        region,
        &inputs.bytes(),
        &le_message_segments(0, messages),
        0,
    )?;
    let coordinates = chips.glue.witnesses(region, &inputs.all_fields())?;
    let mut uint = chips.uint();
    for index in 0..messages {
        let element = decode_le_element(&mut uint, region, &run, MESSAGE_BYTES * index)?;
        if index < points {
            let (x, y) = (&coordinates[2 * index], &coordinates[2 * index + 1]);
            assert_point_bytes(&mut uint, region, &element, x, y)?;
        } else {
            assert_scalar_bytes::<Fq, Fp>(&mut uint, region, &element)?;
        }
    }
    let mut out: Vec<Word<Fq>> = pieces.iter().map(|piece| piece.word().clone()).collect();
    out.extend(coordinates);
    Ok(out)
}

/// The aggregator side at k16: `P_bytes(kgwstep1, LE32 len(sigma) || sigma)`
/// from the 107 trusted pieces (`arg 0 = 0`), or `P_bytes(kgwprf_1, LE32
/// len(Omega) || Omega || LE32 len(sigma) || sigma)` with the Omega bytes
/// (`inputs.bytes`) packed on the tape and the pieces realigned
/// (`arg 0 = 1`). `fields` holds the piece values.
fn sigma_aggregator_program(
    chips: &mut Chips<Fp>,
    region: &mut Region<'_, Fp>,
    inputs: &Inputs<Fp>,
) -> Result<Vec<Word<Fp>>, Error> {
    let lengths = chunk_segments(0, LENGTH_PREFIX_BYTES + SIGMA_PROOF_BYTES);
    let words = chips.glue.witnesses(region, &inputs.all_fields())?;
    let mut string = PBytes::new();
    let domain = if inputs.arg(0) == 0 {
        STEP_DOMAIN
    } else {
        string.push_constant(&length_prefix(inputs.bytes.len())?);
        string.push_run(&mut chips.bytes, region, &inputs.bytes(), &[])?;
        PROOF_DOMAIN
    };
    let mut uint = chips.uint();
    for (word, len) in words.iter().zip(lengths) {
        let piece = BoundedBytes::trusted(word.clone(), len).ok_or(Error::Synthesis)?;
        string.push_bounded_split(&mut uint, region, &piece)?;
    }
    let mut out = words;
    out.push(string.digest(&mut chips.glue, &mut chips.sponge, region, domain)?);
    Ok(out)
}

/// One message (`arg 0 = 1`: a point with `fields = (x, y)`; `0`: an `Fp`
/// scalar) on the tape and linked; outputs the run's primary words and the
/// coordinates.
fn unit_leaf_program(
    chips: &mut Chips<Fq>,
    region: &mut Region<'_, Fq>,
    inputs: &Inputs<Fq>,
) -> Result<Vec<Word<Fq>>, Error> {
    let run = chips.bytes.run(
        region,
        &inputs.bytes(),
        &chunk_segments(0, MESSAGE_BYTES),
        &le_message_segments(0, 1),
    )?;
    let coordinates = chips.glue.witnesses(region, &inputs.all_fields())?;
    let mut uint = chips.uint();
    let element = decode_le_element(&mut uint, region, &run, 0)?;
    if inputs.arg(0) == 1 {
        assert_point_bytes(
            &mut uint,
            region,
            &element,
            &coordinates[0],
            &coordinates[1],
        )?;
    } else {
        assert_scalar_bytes::<Fq, Fp>(&mut uint, region, &element)?;
    }
    let mut out: Vec<Word<Fq>> = run
        .primary()
        .iter()
        .map(|segment| segment.word().clone())
        .collect();
    out.extend(coordinates);
    Ok(out)
}

/// Release measurement at the k16 leaf and aggregator shapes (15-bit
/// running-sum limbs): cells and rows per column, columns, lookups, degree,
/// and one-thread synthesis and strict-check times.
#[test]
#[ignore = "k16 synthesis and strict checks of the sigma export; run in release"]
fn bytes_gate_shape_measurement() {
    const POINTS: usize = 43;
    const SCALARS: usize = 60;
    assert_eq!(MESSAGE_BYTES * (POINTS + SCALARS), SIGMA_PROOF_BYTES);
    let k = 16;
    let shape = |public| Shape {
        public,
        limb_bits: 15,
    };
    let vesta = points::<EqAffine>(u64::try_from(POINTS).expect("count"));
    let mut sigma = Vec::with_capacity(SIGMA_PROOF_BYTES);
    let mut coordinates = Vec::with_capacity(2 * POINTS);
    for point in &vesta {
        sigma.extend_from_slice(&compressed(point));
        coordinates.extend([point.x(), point.y()]);
    }
    for index in 0..SCALARS {
        let scalar = Fp::from(u64::try_from(index).expect("index") + 11)
            .invert()
            .unwrap_or(Fp::ONE);
        sigma.extend_from_slice(&scalar.to_repr());
    }
    let mut string = length_prefix(SIGMA_PROOF_BYTES).expect("len").to_vec();
    string.extend_from_slice(&sigma);

    // Unit costs: an opaque 31-byte chunk and a 31-byte piece split at 24
    // bytes (the realignment at offset 7).
    let units: [(&str, Program<Fp>, Vec<Fp>); 2] = [
        (
            "opaque 31-byte chunk",
            opaque_unit_program,
            vec![Fp::from(5_u64)],
        ),
        (
            "split of a 31-byte piece at 24",
            split_unit_program,
            vec![Fp::from(5_u64)],
        ),
    ];
    for (label, program, values) in units {
        let unit = BytesCircuit {
            shape: shape(values.len()),
            program,
            inputs: Inputs::new(Vec::new(), values.clone(), Vec::new()),
        };
        assert!(accepts(&unit, k, &values), "{}", report(&unit, k, &values));
        let (cells, _) = census(&unit, k, &values);
        println!(
            "MEASURE unit {label} (15-bit limbs): glue {} cells (incl. 1 input), range {} cells",
            sum(&cells, GLUE_COLUMNS),
            cells[RANGE_COLUMN]
        );
    }
    // Unit costs: one point and one scalar.
    for (label, message, fields, mode) in [
        (
            "point (hard)",
            compressed(&vesta[0]).to_vec(),
            vec![vesta[0].x(), vesta[0].y()],
            1,
        ),
        (
            "scalar Fp-in-Fq (hard)",
            sigma[MESSAGE_BYTES * POINTS..][..MESSAGE_BYTES].to_vec(),
            Vec::new(),
            0,
        ),
    ] {
        let mut public: Vec<Fq> = p_bytes_items_native::<Fq>(&message)[1..].to_vec();
        public.extend(&fields);
        let unit = BytesCircuit {
            shape: shape(public.len()),
            program: unit_leaf_program,
            inputs: Inputs::new(message, fields.clone(), vec![mode]),
        };
        assert!(accepts(&unit, k, &public), "{}", report(&unit, k, &public));
        let (cells, _) = census(&unit, k, &public);
        println!(
            "MEASURE unit {label} (15-bit limbs): tape {} cells (2 per byte), glue {} cells, \
             range {} cells, link total {} cells",
            cells[TAPE_COLUMNS[0]] + cells[TAPE_COLUMNS[1]],
            sum(&cells, GLUE_COLUMNS) - fields.len(),
            cells[RANGE_COLUMN],
            sum(&cells, GLUE_COLUMNS) - fields.len() + cells[RANGE_COLUMN]
        );
    }

    // Leaf: the sigma export with every message linked.
    let mut public: Vec<Fq> = p_bytes_items_native::<Fq>(&string)[1..].to_vec();
    public.extend(&coordinates);
    let leaf = BytesCircuit {
        shape: shape(public.len()),
        program: sigma_leaf_program,
        inputs: Inputs::new(sigma.clone(), coordinates.clone(), Vec::new()),
    };
    let started = Instant::now();
    let (cells, rows) = census(&leaf, k, &public);
    let synth = started.elapsed();
    let started = Instant::now();
    let satisfied = accepts(&leaf, k, &public);
    let check = started.elapsed();
    assert!(satisfied, "{}", report(&leaf, k, &public));
    let chip_cells = cells.iter().sum::<usize>() - coordinates.len();
    println!(
        "MEASURE leaf sigma export + 43 point + 60 scalar links, k={k}: {} | cells/column {cells:?} \
         | rows/column {rows:?} | chip cells {chip_cells} (tape {}, glue {}, range {}) \
         | synth_ms={} check_ms={}",
        shape_summary(&leaf),
        cells[TAPE_COLUMNS[0]] + cells[TAPE_COLUMNS[1]],
        sum(&cells, GLUE_COLUMNS) - coordinates.len(),
        cells[RANGE_COLUMN],
        synth.as_millis(),
        check.as_millis()
    );

    // Aggregator: sigma-only and Omega || sigma (Omega = 320-byte public
    // transcript + 4,736-byte transport proof).
    let piece_values: Vec<Fp> = p_bytes_items_native::<Fp>(&string)[1..].to_vec();
    for (label, mode, omega_len) in [
        ("sigma-only kgwstep1", 0_u64, 0_usize),
        ("Omega||sigma kgwprf_1", 1, 320 + 4_736),
    ] {
        let omega = pattern(omega_len, 6);
        let mut full = Vec::new();
        let domain = if mode == 0 {
            STEP_DOMAIN
        } else {
            full.extend_from_slice(&length_prefix(omega_len).expect("len"));
            full.extend_from_slice(&omega);
            PROOF_DOMAIN
        };
        full.extend_from_slice(&string);
        let mut public = piece_values.clone();
        public.push(p_bytes_native::<Fp>(domain, &full));
        let aggregator = BytesCircuit {
            shape: shape(public.len()),
            program: sigma_aggregator_program,
            inputs: Inputs::new(omega, piece_values.clone(), vec![mode]),
        };
        let started = Instant::now();
        let (cells, rows) = census(&aggregator, k, &public);
        let synth = started.elapsed();
        assert!(
            accepts(&aggregator, k, &public),
            "{}",
            report(&aggregator, k, &public)
        );
        let chunks = full.len().div_ceil(CHUNK_BYTES);
        println!(
            "MEASURE aggregator {label}, k={k}: sigma offset {} | cells/column {cells:?} \
             | rows/column {rows:?} | tape {} glue {} (incl. {} piece witnesses) range {} \
             | {} chunks, {} permutations ({} lane cells) | synth_ms={}",
            if mode == 0 {
                0
            } else {
                (LENGTH_PREFIX_BYTES + omega_len) % CHUNK_BYTES
            },
            cells[TAPE_COLUMNS[0]] + cells[TAPE_COLUMNS[1]],
            sum(&cells, GLUE_COLUMNS),
            SIGMA_EXPORT_CHUNKS,
            cells[RANGE_COLUMN],
            chunks,
            domain_permutations(chunks + 1, false),
            sum(&cells, 7..11),
            synth.as_millis()
        );
    }
}

/// One opaque 31-byte chunk of `fields[0]`; outputs it.
fn opaque_unit_program(
    chips: &mut Chips<Fp>,
    region: &mut Region<'_, Fp>,
    inputs: &Inputs<Fp>,
) -> Result<Vec<Word<Fp>>, Error> {
    let piece = opaque_bytes(&mut chips.range, region, inputs.field(0), CHUNK_BYTES)?;
    Ok(vec![piece.word().clone()])
}

/// `fields[0]` as a trusted 31-byte piece split at byte 24; outputs it.
fn split_unit_program(
    chips: &mut Chips<Fp>,
    region: &mut Region<'_, Fp>,
    inputs: &Inputs<Fp>,
) -> Result<Vec<Word<Fp>>, Error> {
    let word = chips.glue.witness(region, inputs.field(0))?;
    let piece = BoundedBytes::trusted(word.clone(), CHUNK_BYTES).ok_or(Error::Synthesis)?;
    split_bounded(&mut chips.uint(), region, &piece, 24)?;
    Ok(vec![word])
}

/// The chip alone stays within the crate's degree policy: the byte lookup
/// has input degree 2 (lookup degree 5) and the link gate degree 3.
#[test]
fn bytes_chip_degree_at_most_six() {
    for (cs_degree, gate_degree) in [chip_degrees::<Fp>(), chip_degrees::<Fq>()] {
        assert_eq!(gate_degree, 3);
        assert_eq!(cs_degree, 5);
        assert!(cs_degree <= crate::MAX_GATE_DEGREE);
    }
}

/// The constraint-system degree and the largest gate degree of a circuit
/// with only the byte tape.
fn chip_degrees<F: PastaField>() -> (usize, usize) {
    let mut meta = ConstraintSystem::<F>::new();
    let z = meta.advice_column();
    let w = meta.advice_column();
    let _config = BytesConfig::configure(&mut meta, z, w);
    assert_eq!(meta.check(), Ok(()));
    assert_eq!(meta.lookups().len(), 1);
    let gate_degree = meta
        .gates()
        .iter()
        .flat_map(|gate| {
            gate.polynomials()
                .iter()
                .map(iroha_plonk::cs::Expression::degree)
        })
        .max()
        .unwrap_or(0);
    (meta.degree(), gate_degree)
}

#[test]
fn byte_powers_values_and_digests() {
    assert_eq!(byte_power::<Fp>(0), Fp::ONE);
    assert_eq!(byte_power::<Fq>(2), Fq::from(65_536_u64));
    assert_eq!(le_value::<Fp>(&[0x34, 0x12]), Some(Fp::from(0x1234_u64)));
    assert_eq!(le_value::<Fp>(&[]), Some(Fp::ZERO));
    assert_eq!(le_value::<Fp>(&[1; 32]), None);
    assert_eq!(field_le_bytes(&Fp::from(258_u64))[..2], [2, 1]);
    assert_eq!(
        known(&collect_bytes(&[Value::known(1), Value::known(2)])),
        Some(vec![1, 2])
    );
    assert_eq!(
        known(&collect_bytes(&[Value::known(1), Value::unknown()])),
        None
    );
    let empty: Vec<Fp> = p_bytes_items_native(&[]);
    assert_eq!(empty, vec![Fp::ZERO]);
    assert_eq!(
        hash_with_domain(STEP_DOMAIN, &empty),
        p_bytes_native::<Fp>(STEP_DOMAIN, &[])
    );
}
