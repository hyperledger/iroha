//! Fixed P-256 signature leaves with exact public input binding.
//!
//! Each slot exports `[digest, x_lo, x_hi, y_lo, y_hi, r_lo, r_hi,
//! s_lo, s_hi, verdict]` in one Bounded instance column. The digest is
//! canonical Fp; every integer limb is 128 bits, including the high limb.
//! A must bind these unsigned integers to its authenticated object bytes and
//! include every soft verdict in the global incoming rule.
//!
//! The existing 17-advice/10-lookup Q layout is retained. Raw 256-bit values
//! are never reduced before verification. Splitting the middle 87-bit FF
//! limb into checked 41/46-bit pieces proves an injective 128/128 export;
//! all bridge equalities are below 2^128 in Fq. This is deliberately distinct
//! from the 128/127 canonical Pasta-scalar codec.

/// Original-key intake and actual proving under one fixed signature-slot plan.
pub mod native;

#[cfg(test)]
#[path = "q_signature_tests.rs"]
mod tests;

use ff::{Field, PrimeField};
use iroha_pasta::{Fp, Fq};
use iroha_plonk::{
    cs::{Column, ConstraintSystem, Instance, InstanceType},
    frontend::{Circuit, Error, Layouter, Region, SimpleFloorPlanner, Value},
};
use iroha_plonk_gadgets::{
    GlueChip, Word,
    ff::{FfValue, ForeignModulus, Nat},
    p256::{P256Key, VerifyMode, native::Affine},
    q_leaf::{QLeafChips, QLeafConfig, sha_rows},
};

/// Public elements per fixed signature slot.
pub const SLOT_WORDS: usize = 10;
/// Circuit-fixed key treatment. A fixed key is included in the verifying key.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SignatureKey {
    /// Exact raw x/y witnesses, including invalid coordinates in soft slots.
    Variable,
    /// Canonical finite P-256 key, pinned at configuration time.
    Fixed(Affine),
}
/// One fixed verification obligation, never selected by witness data.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SignatureSlot {
    /// Hard authorization or total incoming verification.
    pub mode: VerifyMode,
    /// Witness key or circuit-fixed key.
    pub key: SignatureKey,
}
/// Ordered signature schema and fixed keys for one k16 Q leaf.
#[derive(Clone, Debug)]
pub struct QSignaturePlan {
    slots: Vec<SignatureSlot>,
    fixed_keys: Vec<Affine>,
}
impl QSignaturePlan {
    /// Validate a nonempty leaf fitting the fixed table and arithmetic budget.
    ///
    /// # Errors
    /// Invalid fixed keys, more than two distinct fixed keys, or a row estimate
    /// exceeding k16's usable rows. Actual synthesis remains authoritative.
    pub fn new(slots: Vec<SignatureSlot>) -> Result<Self, Error> {
        let mut fixed_keys = Vec::new();
        let mut variable = 0;
        for slot in &slots {
            match slot.key {
                SignatureKey::Variable => variable += 1,
                SignatureKey::Fixed(key) => {
                    if !key.is_valid() {
                        return Err(Error::Synthesis);
                    }
                    if !fixed_keys.contains(&key) {
                        fixed_keys.push(key);
                    }
                }
            }
        }
        if slots.is_empty() || slots.len() > 6 || fixed_keys.len() > 2 {
            return Err(Error::Synthesis);
        }
        let fixed = slots.len() - variable;
        if sha_rows(slots.len()) + 10_003 * variable + 1_659 * fixed > 65_530 {
            return Err(Error::Synthesis);
        }
        Ok(Self { slots, fixed_keys })
    }
    /// Fixed ordered obligations.
    pub fn slots(&self) -> &[SignatureSlot] {
        &self.slots
    }
    /// One homogeneous column; raw limbs and booleans are below Fp.
    pub const fn instance_types() -> [InstanceType; 1] {
        [InstanceType::Bounded]
    }
    /// Exact public-column length.
    pub fn instance_length(&self) -> usize {
        SLOT_WORDS * self.slots.len()
    }
}
/// Raw integer signature witness. Arrays are little-endian 64-bit words;
/// no field reduction or canonicality is implied by this container.
#[derive(Clone, Copy, Debug)]
pub struct SignatureWitness {
    /// Canonical Poseidon digest whose 32-byte LE encoding is SHA-256 hashed.
    pub digest: Fp,
    /// P-256 public-key x and y, as unsigned 256-bit integers.
    pub key: [[u64; 4]; 2],
    /// ECDSA r and s, as unsigned 256-bit integers.
    pub signature: [[u64; 4]; 2],
}
/// Concrete signature relation. It exports raw inputs and the exact verdict;
/// it does not authenticate the object's policy or select an incoming mode.
#[derive(Clone, Debug)]
pub struct QSignatureCircuit {
    plan: QSignaturePlan,
    witnesses: Vec<SignatureWitness>,
    known: bool,
}
impl QSignatureCircuit {
    /// Bind a witness to its fixed slot schema.
    ///
    /// # Errors
    /// Wrong slot count. Invalid signatures remain valid soft witnesses.
    pub fn new(plan: QSignaturePlan, witnesses: Vec<SignatureWitness>) -> Result<Self, Error> {
        if plan.slots.len() != witnesses.len() {
            return Err(Error::Synthesis);
        }
        Ok(Self {
            plan,
            witnesses,
            known: true,
        })
    }
    /// The fixed relation schema.
    pub const fn plan(&self) -> &QSignaturePlan {
        &self.plan
    }
    /// Assemble exact public inputs with caller-supplied expected verdicts.
    /// The circuit proves these bits; this method does not validate signatures.
    ///
    /// # Errors
    /// Wrong verdict count or a failed field embedding.
    pub fn instances(&self, verdicts: &[bool]) -> Result<[Vec<Fq>; 1], Error> {
        if verdicts.len() != self.witnesses.len() {
            return Err(Error::Synthesis);
        }
        let mut out = Vec::with_capacity(self.plan.instance_length());
        for (witness, verdict) in self.witnesses.iter().zip(verdicts) {
            out.push(
                Fq::from_repr(witness.digest.to_repr())
                    .into_option()
                    .ok_or(Error::Synthesis)?,
            );
            for value in witness.key.iter().chain(&witness.signature) {
                let integer = Nat::from_words(*value);
                out.extend([
                    Fq::from_u128(integer.low_u128()),
                    Fq::from_u128(integer.shr(128).low_u128()),
                ]);
            }
            out.push(Fq::from(u64::from(*verdict)));
        }
        Ok([out])
    }
    fn value<T: Copy>(&self, value: T) -> Value<T> {
        if self.known {
            Value::known(value)
        } else {
            Value::unknown()
        }
    }
}
/// Shared Q-leaf configuration and the exact public column.
#[derive(Clone, Debug)]
pub struct QSignatureConfig {
    leaf: QLeafConfig,
    public: Column<Instance>,
}

// Bounded boolean Horner decomposition uses only existing glue columns.
fn fragment(
    glue: &mut GlueChip<Fq>,
    region: &mut Region<'_, Fq>,
    value: Value<u128>,
    bits: usize,
) -> Result<Word<Fq>, Error> {
    let mut out = glue.constant(region, Fq::ZERO)?;
    for index in (0..bits).rev() {
        let bit = glue.boolean(region, value.map(|v| (v >> index) & 1 == 1))?;
        out = glue.linear(
            region,
            &[(Fq::from(2), &out), (Fq::ONE, bit.word())],
            Fq::ZERO,
        )?;
    }
    Ok(out)
}
fn export_raw(
    glue: &mut GlueChip<Fq>,
    region: &mut Region<'_, Fq>,
    value: &FfValue<Fq>,
) -> Result<[Word<Fq>; 2], Error> {
    let integer = value.integer();
    let middle = integer.map(|n| n.shr(87).low_bits_u128(87));
    let low = fragment(glue, region, middle.map(|m| m & ((1 << 41) - 1)), 41)?;
    let high = fragment(glue, region, middle.map(|m| m >> 41), 46)?;
    let joined = glue.linear(
        region,
        &[(Fq::ONE, &low), (Fq::from_u128(1 << 41), &high)],
        Fq::ZERO,
    )?;
    GlueChip::assert_equal(region, &joined, &value.limbs()[1])?;
    Ok([
        glue.linear(
            region,
            &[(Fq::ONE, &value.limbs()[0]), (Fq::from_u128(1 << 87), &low)],
            Fq::ZERO,
        )?,
        glue.linear(
            region,
            &[
                (Fq::ONE, &high),
                (Fq::from_u128(1 << 46), &value.limbs()[2]),
            ],
            Fq::ZERO,
        )?,
    ])
}
fn fixed_raw(
    glue: &mut GlueChip<Fq>,
    region: &mut Region<'_, Fq>,
    value: [u64; 4],
) -> Result<[Word<Fq>; 2], Error> {
    let integer = Nat::from_words(value);
    Ok([
        glue.constant(region, Fq::from_u128(integer.low_u128()))?,
        glue.constant(region, Fq::from_u128(integer.shr(128).low_u128()))?,
    ])
}
impl Circuit<Fq> for QSignatureCircuit {
    type Config = QSignatureConfig;
    type FloorPlanner = SimpleFloorPlanner;
    type Params = (usize, Vec<Affine>);
    fn params(&self) -> Self::Params {
        (self.plan.instance_length(), self.plan.fixed_keys.clone())
    }
    fn without_witnesses(&self) -> Self {
        Self {
            known: false,
            ..self.clone()
        }
    }
    fn configure(meta: &mut ConstraintSystem<Fq>) -> Self::Config {
        Self::configure_with_params(meta, (0, Vec::new()))
    }
    fn configure_with_params(
        meta: &mut ConstraintSystem<Fq>,
        (length, keys): Self::Params,
    ) -> Self::Config {
        let advice = core::array::from_fn(|_| meta.advice_column());
        let constants = meta.fixed_column();
        let leaf = QLeafConfig::configure(meta, advice, constants, &keys);
        let public = meta.instance_column(length);
        meta.enable_equality(public);
        QSignatureConfig { leaf, public }
    }
    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<Fq>,
    ) -> Result<(), Error> {
        config.leaf.load_tables(&mut layouter)?;
        let QLeafChips {
            mut sha,
            mut ff,
            mut glue,
            mut p256,
        } = config.leaf.chips(sha_rows(self.plan.slots.len()))?;
        let output = layouter.assign_region(
            || "bound signature obligations",
            |mut region| {
                let mut output = Vec::with_capacity(self.plan.instance_length());
                for (slot, witness) in self.plan.slots.iter().zip(&self.witnesses) {
                    let digest = Fq::from_repr(witness.digest.to_repr())
                        .into_option()
                        .ok_or(Error::Synthesis)?;
                    let digest = glue.witness(&mut region, self.value(digest))?;
                    let e = p256.message_from_digest::<Fp>(
                        &mut sha,
                        &mut ff,
                        &mut glue,
                        &mut region,
                        &digest,
                    )?;
                    let variable = match slot.key {
                        SignatureKey::Variable => Some([
                            ff.witness(
                                &mut region,
                                ForeignModulus::P256_BASE,
                                self.value(witness.key[0]),
                            )?,
                            ff.witness(
                                &mut region,
                                ForeignModulus::P256_BASE,
                                self.value(witness.key[1]),
                            )?,
                        ]),
                        SignatureKey::Fixed(_) => None,
                    };
                    let mut key_words = Vec::with_capacity(4);
                    let key = match (slot.key, &variable) {
                        (SignatureKey::Variable, Some(xy)) => {
                            for coordinate in xy {
                                key_words.extend(export_raw(&mut glue, &mut region, coordinate)?);
                            }
                            P256Key::Variable {
                                x: &xy[0],
                                y: &xy[1],
                            }
                        }
                        (SignatureKey::Fixed(key), None) => {
                            for (actual, expected) in witness.key.iter().zip([key.x, key.y]) {
                                // Public input equality binds the witness key too; no ignored bytes.
                                for (word, fixed) in actual.chunks_exact(2).zip(fixed_raw(
                                    &mut glue,
                                    &mut region,
                                    expected,
                                )?) {
                                    let integer = u128::from(word[0]) | (u128::from(word[1]) << 64);
                                    let supplied = glue
                                        .witness(&mut region, self.value(Fq::from_u128(integer)))?;
                                    GlueChip::assert_equal(&mut region, &supplied, &fixed)?;
                                    key_words.push(supplied);
                                }
                            }
                            P256Key::Fixed(
                                self.plan
                                    .fixed_keys
                                    .iter()
                                    .position(|v| *v == key)
                                    .ok_or(Error::Synthesis)?,
                            )
                        }
                        _ => return Err(Error::Synthesis),
                    };
                    let r = ff.witness(
                        &mut region,
                        ForeignModulus::P256_ORDER,
                        self.value(witness.signature[0]),
                    )?;
                    let s = ff.witness(
                        &mut region,
                        ForeignModulus::P256_ORDER,
                        self.value(witness.signature[1]),
                    )?;
                    let raw_r = export_raw(&mut glue, &mut region, &r)?;
                    let raw_s = export_raw(&mut glue, &mut region, &s)?;
                    let valid =
                        p256.verify(&mut ff, &mut glue, &mut region, slot.mode, key, &e, &r, &s)?;
                    output.push(digest);
                    output.extend(key_words);
                    output.extend(raw_r);
                    output.extend(raw_s);
                    output.push(valid.word().clone());
                }
                Ok(output)
            },
        )?;
        for (row, word) in output.iter().enumerate() {
            layouter.constrain_instance(word.cell(), config.public, row)?;
        }
        Ok(())
    }
}
