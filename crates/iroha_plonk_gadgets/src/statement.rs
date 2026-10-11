//! The step statement field encoding of the split-lineage step relations
//! (`specs/kagemusha_single_design_proposal.md` sections 3.1 and 3.2), and the
//! canonical limb encodings of spec S6.
//!
//! The element order and the domain are the G1 wallet statement encoding
//! (`KagemushaWalletStatementV1::field_items` in `iroha_data_model`, the
//! `field_encodings` section of `fixtures/kagemusha/wallet_v1_vectors.json`
//! and the wallet wire record `specs/kagemusha_wallet_wire_v1.md` section
//! 3.2): native and in-circuit encodings share those vectors (spec section
//! 3.2).
//!
//! # Encoding (26 elements of the Pasta `Fp` σ field)
//!
//! | index | field |
//! | --- | --- |
//! | 0 | version (1) |
//! | 1-2 | relation id, two little-endian 128-bit limbs |
//! | 3-4 | scheme id limbs |
//! | 5-6 | asset digest limbs |
//! | 7 | credential Poseidon digest |
//! | 8 | successor lifecycle (Active 1, Retiring 2) |
//! | 9 | successor sequence |
//! | 10 | successor `next_load` |
//! | 11 | enabled-controls mask |
//! | 12 | lineage `burned_total` taken from Ω(pred) (Send; 0 for Receive) |
//! | 13 | lineage pending-outgoing root taken from Ω(pred) (Send; 0 for Receive) |
//! | 14 | predecessor state commitment |
//! | 15 | successor state commitment |
//! | 16 | effect tag (the operation tag: Send 3, Receive 4) |
//! | 17-25 | the effect elements, zero filled to 9 |
//!
//! A `P` value (commitment, root, `credit_id`) is one element; a 32-byte
//! SHA-256 digest or identifier is two limbs, low half first.
//!
//! The relation identity is scheme-level (owner answer Q11): one value for
//! every step relation of a scheme, selected per proof by the verifying-key
//! allowlist. It binds the allowlist digest, which binds every verifying key,
//! so it cannot be a constant of the circuit; it enters the digest as two
//! witness cells, bound by the public digest that a verifier recomputes from
//! the canonical statement.
//!
//! The digest is the KAGEMUSHA sponge `hash_with_domain(kgwstmt1, fields)`,
//! 15 permutations, or 14 with the folded prefix. A verifier recomputes it
//! natively from the canonical statement, so every field in it is bound by
//! the public digest.
//!
//! # Canonical limbs (spec S6)
//!
//! A value of a Pasta field enters a circuit as two limbs `lo + 2^128 hi`.
//! [`assign_foreign_scalar`] constrains limbs of the other field to the
//! canonical injective encoding `lo < 2^128`, `hi < 2^127`,
//! `lo + 2^128 hi < modulus`, so `s >= modulus` cannot be passed as
//! `s mod modulus`. [`assign_canonical_limbs`] decomposes a word of the
//! circuit's own field into those canonical limbs, so a digest computed in
//! circuit can be carried as the 32-byte identifier its canonical encoding
//! is.

use iroha_pasta::{PastaField, poseidon::PoseidonField};
use iroha_plonk::frontend::{Error, Region, Value};

use crate::{
    arith::GlueChip,
    cells::{Bit, U128, Uint, Word},
    poseidon::{AbsorbInput, SpongeChip},
    range::u128::UintChip,
};

/// Fields of the statement encoding.
pub const STATEMENT_FIELDS: usize = 26;
/// Fields before the effect.
pub const STATEMENT_HEADER_FIELDS: usize = 17;
/// Fields of the effect union (the Send effect, the largest).
pub const EFFECT_UNION_FIELDS: usize = 9;
/// The statement domain (G1 `KAGEMUSHA_WALLET_STATEMENT_DOMAIN_V1`).
pub const STATEMENT_DOMAIN: u64 = u64::from_le_bytes(*b"kgwstmt1");
/// The statement version (G1 `KAGEMUSHA_WALLET_VERSION_V1`).
pub const STATEMENT_VERSION: u64 = 1;

const _: () = assert!(STATEMENT_HEADER_FIELDS + EFFECT_UNION_FIELDS == STATEMENT_FIELDS);

/// The step relation a statement belongs to.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum StepRelation {
    /// `sigma_send`.
    Send,
    /// `sigma_recv`.
    Receive,
}

impl StepRelation {
    /// The effect tag: the G1 operation tag (`KagemushaWalletOperationKindV1`).
    #[must_use]
    pub const fn effect_tag(self) -> u8 {
        match self {
            Self::Send => 3,
            Self::Receive => 4,
        }
    }
}

/// The two little-endian 128-bit limbs `(lo, hi)` of a 32-byte value.
#[must_use]
pub fn bytes_to_limbs(bytes: &[u8; 32]) -> [u128; 2] {
    let mut lo = [0_u8; 16];
    let mut hi = [0_u8; 16];
    lo.copy_from_slice(&bytes[..16]);
    hi.copy_from_slice(&bytes[16..]);
    [u128::from_le_bytes(lo), u128::from_le_bytes(hi)]
}

/// The limbs as field elements.
#[must_use]
pub fn limb_fields<F: PastaField>(limbs: [u128; 2]) -> [F; 2] {
    limbs.map(F::from_u128)
}

/// The two limb elements of a 32-byte digest or identifier.
#[must_use]
pub fn digest_fields<F: PastaField>(bytes: &[u8; 32]) -> [F; 2] {
    limb_fields(bytes_to_limbs(bytes))
}

/// Decode a canonical little-endian field encoding without reduction.
#[must_use]
pub fn canonical_field<F: PastaField>(bytes: &[u8; 32]) -> Option<F> {
    foreign_value_native::<F>(bytes_to_limbs(bytes))
}

/// The native statement (over the σ field `F`; G1 field names).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StatementV1<F> {
    /// The scheme-level relation identity.
    pub relation_id: [u8; 32],
    /// The step relation (its effect tag).
    pub step: StepRelation,
    /// The scheme identifier.
    pub scheme_id: [u8; 32],
    /// The asset scope digest.
    pub asset_digest: [u8; 32],
    /// The credential digest the transition runs under.
    pub credential_digest: [u8; 32],
    /// The successor lifecycle tag.
    pub lifecycle: u8,
    /// The successor sequence number.
    pub sequence: u128,
    /// The successor `next_load`.
    pub next_load: u128,
    /// The predecessor core's enabled-controls mask.
    pub enabled_controls: u32,
    /// `burned_total` taken from the predecessor's lineage proof (zero for
    /// Receive).
    pub lineage_burned_total: u128,
    /// The pending-outgoing root taken from the predecessor's lineage proof
    /// (zero for Receive).
    pub lineage_pending_outgoing_root: F,
    /// The predecessor state commitment.
    pub predecessor: F,
    /// The successor state commitment.
    pub successor: F,
    /// The effect elements (at most [`EFFECT_UNION_FIELDS`]).
    pub effect: Vec<F>,
}

impl<F: PoseidonField> StatementV1<F> {
    /// The 26-element encoding, or `None` for more than
    /// [`EFFECT_UNION_FIELDS`] effect elements or a noncanonical credential digest.
    #[must_use]
    pub fn encode(&self) -> Option<[F; STATEMENT_FIELDS]> {
        if self.effect.len() > EFFECT_UNION_FIELDS {
            return None;
        }
        let [relation_lo, relation_hi] = digest_fields::<F>(&self.relation_id);
        let [scheme_lo, scheme_hi] = digest_fields::<F>(&self.scheme_id);
        let [asset_lo, asset_hi] = digest_fields::<F>(&self.asset_digest);
        let credential = canonical_field::<F>(&self.credential_digest)?;
        let mut fields = vec![
            F::from(STATEMENT_VERSION),
            relation_lo,
            relation_hi,
            scheme_lo,
            scheme_hi,
            asset_lo,
            asset_hi,
            credential,
            F::from(u64::from(self.lifecycle)),
            F::from_u128(self.sequence),
            F::from_u128(self.next_load),
            F::from(u64::from(self.enabled_controls)),
            F::from_u128(self.lineage_burned_total),
            self.lineage_pending_outgoing_root,
            self.predecessor,
            self.successor,
            F::from(u64::from(self.step.effect_tag())),
        ];
        fields.extend_from_slice(&self.effect);
        fields.resize(STATEMENT_FIELDS, F::ZERO);
        fields.try_into().ok()
    }

    /// The statement digest `P(kgwstmt1, encoding)`, or `None` for more than
    /// [`EFFECT_UNION_FIELDS`] effect elements or a noncanonical credential digest.
    #[must_use]
    pub fn digest(&self) -> Option<F> {
        self.encode()
            .map(|fields| iroha_pasta::poseidon::hash_with_domain(STATEMENT_DOMAIN, &fields))
    }
}

/// The in-circuit statement fields (constants are added by
/// [`statement_digest`]).
#[derive(Clone, Copy, Debug)]
pub struct StatementCells<'a, F: PastaField> {
    /// The scheme-level relation identity limbs (witness cells, bound by the
    /// public digest).
    pub relation_id: [&'a Word<F>; 2],
    /// The scheme identifier limbs.
    pub scheme_id: [&'a Word<F>; 2],
    /// The asset digest limbs.
    pub asset_digest: [&'a Word<F>; 2],
    /// The canonical credential Poseidon digest.
    pub credential_digest: &'a Word<F>,
    /// The successor lifecycle.
    pub lifecycle: &'a Word<F>,
    /// The successor sequence number.
    pub sequence: &'a Word<F>,
    /// The successor `next_load`.
    pub next_load: &'a Word<F>,
    /// The predecessor state commitment.
    pub predecessor: &'a Word<F>,
    /// The successor state commitment.
    pub successor: &'a Word<F>,
    /// The enabled-controls mask.
    pub enabled_controls: &'a Word<F>,
    /// `burned_total` from the predecessor's lineage proof (`None`: the
    /// constant zero, for Receive).
    pub lineage_burned_total: Option<&'a Word<F>>,
    /// The pending-outgoing root from the predecessor's lineage proof
    /// (`None`: the constant zero, for Receive).
    pub lineage_pending_outgoing_root: Option<&'a Word<F>>,
    /// The effect elements (at most [`EFFECT_UNION_FIELDS`]; the rest are
    /// zero).
    pub effect: &'a [Word<F>],
}

/// An optional cell as an absorbed input (the constant zero when absent).
fn optional_input<F: PastaField>(cell: Option<&Word<F>>) -> AbsorbInput<'_, F> {
    cell.map_or(AbsorbInput::Constant(F::ZERO), AbsorbInput::Word)
}

/// Hashes the statement encoding of `cells` for step `step` and returns the
/// digest cell.
///
/// # Errors
///
/// [`Error::Synthesis`] for more than [`EFFECT_UNION_FIELDS`] effect
/// elements, and [`Error`] from the layout.
pub fn statement_digest<F: PoseidonField>(
    sponge: &mut SpongeChip<F>,
    region: &mut Region<'_, F>,
    step: StepRelation,
    cells: &StatementCells<'_, F>,
) -> Result<Word<F>, Error> {
    if cells.effect.len() > EFFECT_UNION_FIELDS {
        return Err(Error::Synthesis);
    }
    let word = AbsorbInput::Word;
    let optional = optional_input::<F>;
    let mut inputs = vec![
        AbsorbInput::Constant(F::from(STATEMENT_VERSION)),
        word(cells.relation_id[0]),
        word(cells.relation_id[1]),
        word(cells.scheme_id[0]),
        word(cells.scheme_id[1]),
        word(cells.asset_digest[0]),
        word(cells.asset_digest[1]),
        word(cells.credential_digest),
        word(cells.lifecycle),
        word(cells.sequence),
        word(cells.next_load),
        word(cells.enabled_controls),
        optional(cells.lineage_burned_total),
        optional(cells.lineage_pending_outgoing_root),
        word(cells.predecessor),
        word(cells.successor),
        AbsorbInput::Constant(F::from(u64::from(step.effect_tag()))),
    ];
    inputs.extend(cells.effect.iter().map(AbsorbInput::Word));
    inputs.resize(STATEMENT_FIELDS, AbsorbInput::Constant(F::ZERO));
    sponge.hash(region, STATEMENT_DOMAIN, &inputs)
}

/// The canonical limbs `(lo, hi)` of a field element `value` (the halves of
/// its canonical little-endian 32-byte encoding).
#[must_use]
pub fn foreign_limbs<G: PastaField>(value: &G) -> [u128; 2] {
    let limbs = value.to_canonical_limbs();
    [
        u128::from(limbs[0]) | (u128::from(limbs[1]) << 64),
        u128::from(limbs[2]) | (u128::from(limbs[3]) << 64),
    ]
}

/// Native reference of [`assign_foreign_scalar`]: the element of `G` whose
/// canonical limbs are `limbs`, or `None` when they encode a value `>=` the
/// modulus.
#[must_use]
pub fn foreign_value_native<G: PastaField>(limbs: [u128; 2]) -> Option<G> {
    let [lo, hi] = limbs;
    let word = |value: u128| u64::try_from(value & u128::from(u64::MAX)).unwrap_or(0);
    let words = [word(lo), word(lo >> 64), word(hi), word(hi >> 64)];
    Option::from(G::from_canonical_limbs(words))
}

/// A value in its canonical injective limb encoding (spec S6): `lo < 2^128`,
/// `hi < 2^127` and `lo + 2^128 hi < |G|` for the field `G` it was checked
/// against.
#[derive(Clone, Debug)]
pub struct ForeignScalar<F: PastaField> {
    lo: U128<F>,
    hi: Uint<F, 127>,
}

impl<F: PastaField> ForeignScalar<F> {
    /// The low limb.
    #[must_use]
    pub const fn lo(&self) -> &U128<F> {
        &self.lo
    }

    /// The high limb.
    #[must_use]
    pub const fn hi(&self) -> &Uint<F, 127> {
        &self.hi
    }

    /// Both limbs, low first.
    #[must_use]
    pub const fn words(&self) -> [&Word<F>; 2] {
        [self.lo.word(), self.hi.word()]
    }
}

/// Assigns the limbs of an element of the foreign field `G` and constrains
/// their encoding to be canonical.
///
/// With `m - 1 = M_lo + 2^128 M_hi` (`M_hi = 2^126` for both Pasta fields):
/// `hi <= M_hi`, and when `hi = M_hi`, `lo <= M_lo`. The second condition is
/// the range check of `[hi = M_hi] (M_lo - lo)`.
///
/// # Errors
///
/// [`Error`] from the layout.
pub fn assign_foreign_scalar<F: PastaField, G: PastaField>(
    uint: &mut UintChip<'_, F>,
    region: &mut Region<'_, F>,
    limbs: Value<[u128; 2]>,
) -> Result<ForeignScalar<F>, Error> {
    let [max_lo, max_hi] = foreign_limbs(&-G::ONE);
    let lo = uint.assign::<128>(region, limbs.map(|[lo, _]| lo))?;
    let hi = uint.assign::<127>(region, limbs.map(|[_, hi]| hi))?;
    let max_hi_cell = uint.constant::<127>(region, max_hi)?;
    uint.assert_le(region, &hi, &max_hi_cell)?;
    let glue = uint.glue();
    let offset = glue.add_constant(region, hi.word(), -F::from_u128(max_hi))?;
    let at_max: Bit<F> = glue.is_zero(region, &offset)?;
    let slack = glue.linear(region, &[(-F::ONE, lo.word())], F::from_u128(max_lo))?;
    let bounded = glue.mul(region, at_max.word(), &slack)?;
    uint.range().range_check(region, &bounded, 128)?;
    Ok(ForeignScalar { lo, hi })
}

/// `2^128` in `F`.
fn two_pow_128<F: PastaField>() -> F {
    F::from_u128(1 << 127).double()
}

/// Decomposes `value`, a word of the circuit's own field, into its canonical
/// limbs: `lo + 2^128 hi = value` with the canonical encoding of
/// [`assign_foreign_scalar`] (checked against `F` itself), so the limbs are
/// the unique halves of the canonical 32-byte encoding of `value`
/// ([`foreign_limbs`]) and the alias `value + modulus` is unsatisfiable.
///
/// # Errors
///
/// [`Error`] from the layout.
pub fn assign_canonical_limbs<F: PastaField>(
    uint: &mut UintChip<'_, F>,
    region: &mut Region<'_, F>,
    value: &Word<F>,
) -> Result<ForeignScalar<F>, Error> {
    let limbs = value.value().map(|value| foreign_limbs(&value));
    canonical_limbs_with_witness(uint, region, value, limbs)
}

/// [`assign_canonical_limbs`] with the limbs supplied by the caller (tests
/// force non-canonical limbs through it).
pub(crate) fn canonical_limbs_with_witness<F: PastaField>(
    uint: &mut UintChip<'_, F>,
    region: &mut Region<'_, F>,
    value: &Word<F>,
    limbs: Value<[u128; 2]>,
) -> Result<ForeignScalar<F>, Error> {
    let scalar = assign_foreign_scalar::<F, F>(uint, region, limbs)?;
    let recomposed = uint.glue().linear(
        region,
        &[
            (F::ONE, scalar.lo.word()),
            (two_pow_128::<F>(), scalar.hi.word()),
        ],
        F::ZERO,
    )?;
    GlueChip::assert_equal(region, &recomposed, value)?;
    Ok(scalar)
}

#[cfg(test)]
mod tests {
    use ff::{Field, PrimeField};
    use iroha_pasta::{Fp, Fq};
    use iroha_plonk::{
        check::{CheckMode, check_circuit},
        cs::ConstraintSystem,
        frontend::{Circuit, Layouter, SimpleFloorPlanner},
    };

    use super::*;
    use crate::{
        arith::GlueConfig,
        range::running_sum::{LimbBits, RunningSumChip, RunningSumConfig},
    };

    #[test]
    fn relation_labels() {
        assert_ne!(
            StepRelation::Send.effect_tag(),
            StepRelation::Receive.effect_tag()
        );
        assert_eq!(StepRelation::Send.effect_tag(), 3);
        assert_eq!(StepRelation::Receive.effect_tag(), 4);
        assert_eq!(STATEMENT_DOMAIN.to_le_bytes(), *b"kgwstmt1");
    }

    #[test]
    fn limbs_split_little_endian_halves() {
        let mut bytes = [0_u8; 32];
        bytes[0] = 1;
        bytes[16] = 2;
        bytes[31] = 0x80;
        assert_eq!(bytes_to_limbs(&bytes), [1, 2 | (0x80 << 120)]);
        assert_eq!(limb_fields::<Fp>([3, 4]), [Fp::from(3u64), Fp::from(4u64)]);
    }

    fn foreign_round_trip<G: PastaField + PrimeField<Repr = [u8; 32]>>() {
        let max = -G::ONE;
        let limbs = foreign_limbs(&max);
        assert_eq!(limbs[1], 1 << 126);
        assert_eq!(foreign_value_native::<G>(limbs), Some(max));
        assert_eq!(canonical_field::<G>(&max.to_repr()), Some(max));
        assert_eq!(canonical_field::<G>(&G::ZERO.to_repr()), Some(G::ZERO));
        let mut modulus = max.to_repr();
        for byte in &mut modulus {
            let (next, carry) = byte.overflowing_add(1);
            *byte = next;
            if !carry {
                break;
            }
        }
        assert_eq!(canonical_field::<G>(&modulus), None);
        assert_eq!(canonical_field::<G>(&[0xff; 32]), None);
        assert_eq!(foreign_value_native::<G>([limbs[0] + 1, limbs[1]]), None);
        assert_eq!(foreign_value_native::<G>([0, 1 << 127]), None);
        let seven = G::from(7u64);
        assert_eq!(
            foreign_value_native::<G>(foreign_limbs(&seven)),
            Some(seven)
        );
        // The canonical limbs are the halves of the canonical encoding.
        assert_eq!(bytes_to_limbs(&max.to_repr()), limbs);
        // lo + 2^128 hi recomposes the value.
        let [lo, hi] = limbs;
        assert_eq!(
            G::from_u128(lo) + two_pow_128::<G>() * G::from_u128(hi),
            max
        );
    }

    #[test]
    fn foreign_limbs_are_canonical() {
        foreign_round_trip::<Fp>();
        foreign_round_trip::<Fq>();
        assert_eq!(two_pow_128::<Fp>(), Fp::from(2u64).pow_vartime([128]));
    }

    #[test]
    fn statement_encoding_layout() {
        let mut relation_id = [0_u8; 32];
        relation_id[0] = 0x34;
        relation_id[1] = 0x12;
        relation_id[16] = 0x56;
        let statement = StatementV1::<Fq> {
            relation_id,
            step: StepRelation::Send,
            scheme_id: [1; 32],
            asset_digest: [3; 32],
            credential_digest: [2; 32],
            lifecycle: 2,
            sequence: 9,
            next_load: 6,
            enabled_controls: 1,
            lineage_burned_total: 40,
            lineage_pending_outgoing_root: Fq::from(11u64),
            predecessor: Fq::from(5u64),
            successor: Fq::from(7u64),
            effect: vec![Fq::from(10u64); EFFECT_UNION_FIELDS],
        };
        let fields = statement.encode().expect("encoding");
        assert_eq!(fields[0], Fq::ONE);
        assert_eq!(fields[1], Fq::from(0x1234u64));
        assert_eq!(fields[2], Fq::from(0x56u64));
        assert_eq!([fields[3], fields[4]], digest_fields(&[1; 32]));
        assert_eq!([fields[5], fields[6]], digest_fields(&[3; 32]));
        assert_eq!(
            fields[7],
            canonical_field::<Fq>(&[2; 32]).expect("canonical")
        );
        assert_eq!(fields[8], Fq::from(2u64));
        assert_eq!(fields[9], Fq::from(9u64));
        assert_eq!(fields[10], Fq::from(6u64));
        assert_eq!(fields[11], Fq::ONE);
        assert_eq!(fields[12], Fq::from(40u64));
        assert_eq!(fields[13], Fq::from(11u64));
        assert_eq!(fields[14], Fq::from(5u64));
        assert_eq!(fields[15], Fq::from(7u64));
        assert_eq!(fields[16], Fq::from(3u64));
        assert_eq!(fields[25], Fq::from(10u64));
        assert_eq!(
            statement.digest(),
            Some(iroha_pasta::poseidon::hash_with_domain(
                STATEMENT_DOMAIN,
                &fields
            ))
        );
        let mut short = statement.clone();
        short.effect.truncate(4);
        assert_eq!(short.encode().expect("encoding")[21], Fq::ZERO);
        let mut malformed = statement.clone();
        malformed.credential_digest = [0xff; 32];
        assert_eq!(malformed.encode(), None);
        assert_eq!(malformed.digest(), None);
        let mut long = statement;
        long.effect = vec![Fq::ONE; EFFECT_UNION_FIELDS + 1];
        assert_eq!(long.encode(), None);
        assert_eq!(long.digest(), None);
    }

    /// `assign_canonical_limbs` of a value with chosen limbs.
    #[derive(Clone, Copy)]
    struct ForcedLimbs {
        value: Fp,
        limbs: [u128; 2],
    }

    impl Circuit<Fp> for ForcedLimbs {
        type Config = (GlueConfig, RunningSumConfig);
        type FloorPlanner = SimpleFloorPlanner;
        type Params = ();

        fn without_witnesses(&self) -> Self {
            *self
        }

        fn configure(meta: &mut ConstraintSystem<Fp>) -> Self::Config {
            let advice = core::array::from_fn(|_| meta.advice_column());
            let constants = meta.fixed_column();
            let glue = GlueConfig::configure(meta, advice, constants);
            let z = meta.advice_column();
            let bits = LimbBits::new(8).unwrap_or_else(|| unreachable!("valid width"));
            (glue, RunningSumConfig::configure(meta, z, bits))
        }

        fn synthesize(
            &self,
            (glue, range): Self::Config,
            mut layouter: impl Layouter<Fp>,
        ) -> Result<(), Error> {
            let mut glue = GlueChip::new(glue);
            let mut range = RunningSumChip::new(range);
            range.load_table(&mut layouter)?;
            layouter.assign_region(
                || "forced limbs",
                |mut region| {
                    let value = glue.witness(&mut region, Value::known(self.value))?;
                    let mut uint = UintChip::new(&mut glue, &mut range);
                    canonical_limbs_with_witness(
                        &mut uint,
                        &mut region,
                        &value,
                        Value::known(self.limbs),
                    )
                    .map(|_| ())
                },
            )
        }
    }

    /// The strict checker report of `ForcedLimbs`.
    fn forced(value: Fp, limbs: [u128; 2]) -> iroha_plonk::check::CheckReport<Fp> {
        check_circuit(&ForcedLimbs { value, limbs }, 9, &[], CheckMode::Strict).expect("check")
    }

    /// `limbs + modulus` as limbs (the alias `value + p` of a value).
    fn plus_modulus([lo, hi]: [u128; 2]) -> [u128; 2] {
        let [max_lo, max_hi] = foreign_limbs(&-Fp::ONE);
        // p = (max_lo + 1) + 2^128 max_hi; max_lo + 1 does not overflow.
        let (sum, carry) = lo.overflowing_add(max_lo + 1);
        [sum, hi + max_hi + u128::from(carry)]
    }

    #[test]
    fn canonical_limbs_are_the_only_decomposition() {
        for value in [
            Fp::ZERO,
            Fp::ONE,
            -Fp::ONE,
            Fp::from(0x1234_5678u64).invert().unwrap(),
        ] {
            let limbs = foreign_limbs(&value);
            assert!(forced(value, limbs).is_satisfied(), "{value:?}");
            // value + p recomposes to the same field element, but its high
            // limb is out of range: only range lookups fail.
            let alias = plus_modulus(limbs);
            assert_ne!(alias, limbs);
            assert_eq!(
                Fp::from_u128(alias[0]) + two_pow_128::<Fp>() * Fp::from_u128(alias[1]),
                value
            );
            let report = forced(value, alias);
            assert!(!report.is_satisfied());
            assert!(report.failures().iter().all(|failure| matches!(
                failure,
                iroha_plonk::check::CheckFailure::LookupInputMissing { .. }
            )));
            // Limbs of another value fail the recomposition copy.
            let wrong = [limbs[0] ^ 1, limbs[1]];
            assert!(!forced(value, wrong).is_satisfied());
        }
    }
}
