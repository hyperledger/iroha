//! Real PIPA-v1 proofs of chip circuits on both curves (Vesta proofs over
//! `Fp` circuits, Pallas proofs over `Fq` circuits), with both transcripts:
//! the KAGEMUSHA sponge, checked `u128` arithmetic, the glue gates and the
//! G1 step statement digest. Each proof verifies in full, a wrong public
//! input and a corrupted proof are rejected, and repeated proofs use fresh
//! randomness while preserving the same complete verification verdict.

mod common;

use std::time::Instant;

use common::{Chips, GadgetCircuit, Inputs, Shape, accepts, keys, report};
use ff::{Field as _, PrimeField as _};
use iroha_pasta::{
    Ep, Eq, PastaCurve,
    poseidon::{PoseidonField, hash, hash_with_domain},
};
use iroha_plonk::{
    cs::TranscriptV1,
    frontend::{Error, Region},
};
use iroha_plonk_gadgets::{
    AbsorbInput, UintChip, Word,
    cells::low_u128,
    statement::{STATEMENT_DOMAIN, STATEMENT_FIELDS},
};

/// Proves `circuit` at `k` on curve `C` with `transcript` and checks the
/// verdicts.
fn round_trip<C: PastaCurve>(
    circuit: &GadgetCircuit<C::ScalarExt>,
    public: &[C::ScalarExt],
    k: u32,
    transcript: TranscriptV1,
) -> usize
where
    C::ScalarExt: PoseidonField,
{
    assert!(
        accepts(circuit, k, public),
        "{}",
        report(circuit, k, public)
    );
    let started = Instant::now();
    let keys = keys::<C>(circuit, k, transcript);
    let keygen = started.elapsed();
    let started = Instant::now();
    let proof = keys.prove(circuit, public);
    let prove = started.elapsed();
    let started = Instant::now();
    assert_eq!(keys.verify(public, &proof), Ok(()));
    let verify = started.elapsed();
    println!(
        "REAL_PROOF curve={} k={k} transcript={transcript:?} bytes={} keygen_ms={} \
         prove_ms={} verify_ms={}",
        core::any::type_name::<C>(),
        proof.len(),
        keygen.as_millis(),
        prove.as_millis(),
        verify.as_millis()
    );
    let second = keys.prove(circuit, public);
    assert_eq!(keys.verify(public, &second), Ok(()));
    assert_ne!(second, proof, "fresh blinds on the same statement");
    let third = keys.prove(circuit, public);
    assert_eq!(keys.verify(public, &third), Ok(()));
    assert_ne!(third, proof, "fresh blinds on every attempt");
    assert_ne!(third, second, "independent attempts use independent blinds");
    let mut wrong = public.to_vec();
    wrong[0] += C::ScalarExt::ONE;
    assert!(keys.verify(&wrong, &proof).is_err(), "wrong public input");
    let mut corrupted = proof.clone();
    let middle = corrupted.len() / 2;
    corrupted[middle] ^= 1;
    assert!(keys.verify(public, &corrupted).is_err(), "corrupted proof");
    proof.len()
}

/// A folded 3-input hash under `arg 0` and a raw hash of input 3 and that
/// digest.
fn sponge<F: PoseidonField>(
    chips: &mut Chips<F>,
    region: &mut Region<'_, F>,
    inputs: &Inputs<F>,
) -> Result<Vec<Word<F>>, Error> {
    let words = chips.glue.witnesses(region, &inputs.all())?;
    let first = chips.sponges[0].hash_words(region, inputs.arg(0), &words[..3])?;
    let raw = [AbsorbInput::Word(&words[3]), AbsorbInput::Word(&first)];
    let second = chips.sponges[0].hash_raw(region, &raw)?;
    Ok(vec![first, second])
}

fn sponge_case<C: PastaCurve>(transcript: TranscriptV1) -> usize
where
    C::ScalarExt: PoseidonField,
{
    type F<C> = <C as PastaCurve>::ScalarExt;
    let domain = u64::from_le_bytes(*b"kgmleaf1");
    let inputs = vec![
        F::<C>::from(3u64),
        -F::<C>::ONE,
        F::<C>::from(5u64),
        F::<C>::from(8u64),
    ];
    let first = hash_with_domain(domain, &inputs[..3]);
    let public = vec![first, hash(&[inputs[3], first])];
    let shape = Shape::new(1, 4, 2)
        .with_args(&[domain])
        .folding(&[(domain, 3)]);
    let circuit = GadgetCircuit::new(shape, sponge::<F<C>>, inputs);
    round_trip::<C>(&circuit, &public, 8, transcript)
}

#[test]
fn sponge_proofs_on_both_curves() {
    let vesta = sponge_case::<Eq>(TranscriptV1::KagemushaPoseidonRp57);
    let pallas = sponge_case::<Ep>(TranscriptV1::KagemushaPoseidonRp57);
    assert_eq!(vesta, pallas);
    sponge_case::<Eq>(TranscriptV1::Blake2bChallenge255);
    println!("sponge proof bytes (KAGEMUSHA transcript, Direct, suffix): {vesta}");
}

/// `acc + x0 - x1 + x2 - x3` on checked `u128`s.
fn chain<F: PoseidonField>(
    chips: &mut Chips<F>,
    region: &mut Region<'_, F>,
    inputs: &Inputs<F>,
) -> Result<Vec<Word<F>>, Error> {
    let mut uint = UintChip::new(&mut chips.glue, &mut chips.range);
    let mut acc = uint.assign_u128(region, inputs.get(0).map(|v| low_u128(&v)))?;
    for index in 1..inputs.len() {
        let x = uint.assign_u128(region, inputs.get(index).map(|v| low_u128(&v)))?;
        acc = if index % 2 == 1 {
            uint.checked_add(region, &acc, &x)?
        } else {
            uint.checked_sub(region, &acc, &x)?
        };
    }
    let zero = uint.constant::<128>(region, 0)?;
    let positive = uint.lt(region, &zero, &acc)?;
    Ok(vec![acc.word().clone(), positive.word().clone()])
}

fn chain_case<C: PastaCurve>(transcript: TranscriptV1) -> usize
where
    C::ScalarExt: PoseidonField,
{
    type F<C> = <C as PastaCurve>::ScalarExt;
    let values: [u128; 5] = [(1 << 127) + 9, 1 << 99, 3 << 98, 77, 1 << 90];
    let total = values[0] + values[1] - values[2] + values[3] - values[4];
    let inputs = values.iter().map(|v| F::<C>::from_u128(*v)).collect();
    let public = vec![F::<C>::from_u128(total), F::<C>::ONE];
    let circuit = GadgetCircuit::new(Shape::new(0, 7, 2), chain::<F<C>>, inputs);
    round_trip::<C>(&circuit, &public, 9, transcript)
}

#[test]
fn checked_u128_proofs_on_both_curves() {
    let vesta = chain_case::<Eq>(TranscriptV1::KagemushaPoseidonRp57);
    let pallas = chain_case::<Ep>(TranscriptV1::Blake2bChallenge255);
    println!("u128 proof bytes: vesta/poseidon {vesta}, pallas/blake2b {pallas}");
}

/// Glue gates: `select(bit, x * y, x + y)`, `[x - y = 0]` and `NOT bit`.
fn glue<F: PoseidonField>(
    chips: &mut Chips<F>,
    region: &mut Region<'_, F>,
    inputs: &Inputs<F>,
) -> Result<Vec<Word<F>>, Error> {
    let glue = &mut chips.glue;
    let w = glue.witnesses(region, &inputs.all())?;
    let bit = glue.assert_bool(region, &w[2])?;
    let product = glue.mul(region, &w[0], &w[1])?;
    let sum = glue.add(region, &w[0], &w[1])?;
    let selected = glue.select(region, &bit, &product, &sum)?;
    let equal = glue.is_equal(region, &w[0], &w[1])?;
    let negated = glue.not(region, &bit)?;
    Ok(vec![selected, equal.word().clone(), negated.word().clone()])
}

fn glue_case<C: PastaCurve>() -> usize
where
    C::ScalarExt: PoseidonField,
{
    type F<C> = <C as PastaCurve>::ScalarExt;
    let (x, y) = (F::<C>::from(6u64), -F::<C>::from(4u64));
    let public = vec![x * y, F::<C>::ZERO, F::<C>::ZERO];
    let circuit = GadgetCircuit::new(Shape::new(0, 4, 3), glue::<F<C>>, vec![x, y, F::<C>::ONE]);
    round_trip::<C>(&circuit, &public, 6, TranscriptV1::KagemushaPoseidonRp57)
}

#[test]
fn glue_proofs_on_both_curves() {
    let vesta = glue_case::<Eq>();
    let pallas = glue_case::<Ep>();
    assert_eq!(vesta, pallas);
}

/// The step statement digest over its 28 fields as witnesses (folded
/// prefix).
fn statement<F: PoseidonField>(
    chips: &mut Chips<F>,
    region: &mut Region<'_, F>,
    inputs: &Inputs<F>,
) -> Result<Vec<Word<F>>, Error> {
    let words = chips.glue.witnesses(region, &inputs.all())?;
    Ok(vec![chips.sponges[0].hash_words(
        region,
        STATEMENT_DOMAIN,
        &words,
    )?])
}

fn statement_case<C: PastaCurve>() -> usize
where
    C::ScalarExt: PoseidonField,
{
    type F<C> = <C as PastaCurve>::ScalarExt;
    let fields = (0..STATEMENT_FIELDS)
        .map(|i| F::<C>::from(0x9e37_79b9 * (i as u64 + 1)))
        .collect::<Vec<_>>();
    let public = vec![hash_with_domain(STATEMENT_DOMAIN, &fields)];
    let shape = Shape::new(1, 9, 1).folding(&[(STATEMENT_DOMAIN, STATEMENT_FIELDS)]);
    let circuit = GadgetCircuit::new(shape, statement::<F<C>>, fields);
    round_trip::<C>(&circuit, &public, 10, TranscriptV1::KagemushaPoseidonRp57)
}

#[test]
#[ignore = "k = 10 proofs of the 15-block statement digest; run in release"]
fn statement_digest_proofs_on_both_curves() {
    let vesta = statement_case::<Eq>();
    let pallas = statement_case::<Ep>();
    assert_eq!(vesta, pallas);
    println!("statement digest proof bytes (k = 10, 15 Pow5 blocks): {vesta}");
}
