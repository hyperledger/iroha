//! Total incoming statement semantics without disabling burn/no-op branches.
//!
//! A owns hard-valid statements for its own operation. Incoming statements may
//! fail those same rules: their exact 26 original words must still enter the
//! statement digest, receipt and Q binding. Bounded integer views select low
//! bits with a mandatory false verdict for oversized words, never a reduced
//! alias accepted as a different statement.

use ff::{Field, PrimeField};
use iroha_pasta::Fp;
use iroha_plonk::frontend::{Error, Region};
use iroha_plonk_gadgets::{
    Bit, GlueChip, Uint, UintChip, Word, WordHasher,
    bytes::element::{LeElement, scalar_bytes_canonical},
    statement::STATEMENT_DOMAIN,
};
use iroha_plonk_recursion::obligation::ledger::Variant;

use super::{
    objects::predicates::{all, is_constant, le64, nonzero, sum_fits128},
    statement::StatementCells,
};

mod sealed {
    pub trait Sealed {}
}

/// Exact statement view for hard own receipts and total incoming receipts.
/// Implementations are sealed to the two constrained constructors.
pub trait StatementView: sealed::Sealed {
    /// Fixed relation class, whose expected effect tag is constrained.
    fn variant(&self) -> Variant;
    /// Original canonical Fp statement words, not sanitized integer dummies.
    fn fields(&self) -> &[Word<Fp>; 26];
    /// Poseidon digest of those original words.
    fn digest(&self) -> &Word<Fp>;
    /// True for a hard own statement; the total predicate for an incoming one.
    ///
    /// # Errors
    /// Layout failure while constructing the hard constant.
    fn validity(
        &self,
        uint: &mut UintChip<'_, Fp>,
        region: &mut Region<'_, Fp>,
    ) -> Result<Bit<Fp>, Error>;
}
impl sealed::Sealed for StatementCells {}
impl StatementView for StatementCells {
    fn variant(&self) -> Variant {
        self.variant()
    }
    fn fields(&self) -> &[Word<Fp>; 26] {
        self.fields()
    }
    fn digest(&self) -> &Word<Fp> {
        self.digest()
    }
    fn validity(
        &self,
        uint: &mut UintChip<'_, Fp>,
        region: &mut Region<'_, Fp>,
    ) -> Result<Bit<Fp>, Error> {
        let one = uint.glue().constant(region, Fp::ONE)?;
        uint.glue().assert_bool(region, &one)
    }
}

/// Same digest and semantic rules as a hard statement, with a total verdict.
/// This object alone does not authenticate a sigma proof or predecessor.
#[derive(Clone, Debug)]
pub struct IncomingStatementCells {
    variant: Variant,
    original: [Word<Fp>; 26],
    bounded: [Word<Fp>; 26],
    widths: [Option<usize>; 26],
    digest: Word<Fp>,
    valid: Bit<Fp>,
}
impl sealed::Sealed for IncomingStatementCells {}
impl StatementView for IncomingStatementCells {
    fn variant(&self) -> Variant {
        self.variant
    }
    fn fields(&self) -> &[Word<Fp>; 26] {
        &self.original
    }
    fn digest(&self) -> &Word<Fp> {
        &self.digest
    }
    fn validity(
        &self,
        _uint: &mut UintChip<'_, Fp>,
        _region: &mut Region<'_, Fp>,
    ) -> Result<Bit<Fp>, Error> {
        Ok(self.valid.clone())
    }
}
impl IncomingStatementCells {
    /// Bind and totally validate the exact 26 words of an incoming statement.
    ///
    /// The caller binds its digest to the Q sigma slot and these words to the
    /// exact retained context. Noncanonical *external bytes* require the outer
    /// decoder's structural predicate as well; Fp cells themselves are canonical.
    /// The supplied words are never replaced in the digest, even on rejection.
    ///
    /// # Errors
    /// Layout failure, not a false semantic predicate or oversized integer.
    pub fn constrain(
        uint: &mut UintChip<'_, Fp>,
        hash: &mut impl WordHasher<Fp>,
        region: &mut Region<'_, Fp>,
        variant: Variant,
        fields: &[Word<Fp>; 26],
    ) -> Result<Self, Error> {
        let (_, _, widths) = layout(variant);
        let mut bounded = fields.clone();
        let mut checks = Vec::new();
        for (i, width) in widths.iter().enumerate() {
            if let Some(width) = width {
                let (word, fits) = bounded_integer(uint, region, &fields[i], *width)?;
                bounded[i] = word;
                checks.push(fits);
            }
        }
        let valid = variant_predicate(uint, region, variant, fields, &bounded, checks)?;
        let digest = hash.hash_words(region, STATEMENT_DOMAIN, fields)?;
        Ok(Self {
            variant,
            original: fields.clone(),
            bounded,
            widths,
            digest,
            valid,
        })
    }
    /// Total statement semantic predicate, mandatory in the incoming verdict.
    pub const fn valid(&self) -> &Bit<Fp> {
        &self.valid
    }
    /// A bounded integer cell for total incoming arithmetic/comparison.
    /// It is the exact original integer when `valid` is true, a low-bit dummy
    /// otherwise. Never use this dummy in place of the original digest words.
    ///
    /// # Errors
    /// The fixed schema index/width is wrong, or a layout failure occurs.
    pub fn integer<const BITS: usize>(
        &self,
        uint: &mut UintChip<'_, Fp>,
        region: &mut Region<'_, Fp>,
        index: usize,
    ) -> Result<Uint<Fp, BITS>, Error> {
        if self.widths.get(index) != Some(&Some(BITS)) {
            return Err(Error::Synthesis);
        }
        uint.range_check::<BITS>(region, &self.bounded[index])
    }
}

/// A `CreditStatus` head statement whose operation tag is part of the witness.
///
/// Every possible statement shape is constrained in one fixed circuit. Integer
/// views are shared by exact field index/width, and the original 26 words are
/// hashed once. Receive/renewed and Archive's two proof sources have identical
/// statement semantics and therefore share their canonical union branch.
#[derive(Clone, Debug)]
pub struct DynamicStatementCells {
    fields: [Word<Fp>; 26],
    digest: Word<Fp>,
    valid: Bit<Fp>,
}
impl DynamicStatementCells {
    /// Constrain the fixed union of every operation statement at a folded head.
    ///
    /// The branch is selected by the constrained effect tag and Refresh subtype,
    /// never a host branch on a witness value. An unknown tag, bad width or other
    /// semantic failure produces false while retaining the original digest.
    ///
    /// # Errors
    /// Layout failure, not malformed incoming fields.
    pub fn constrain(
        uint: &mut UintChip<'_, Fp>,
        hash: &mut impl WordHasher<Fp>,
        region: &mut Region<'_, Fp>,
        fields: &[Word<Fp>; 26],
    ) -> Result<Self, Error> {
        let variants = [
            Variant::Bootstrap,
            Variant::Load,
            Variant::Send,
            Variant::Receive,
            Variant::ArchiveStatus,
            Variant::Unload,
            Variant::Retiring,
            Variant::RefreshCredential,
            Variant::RefreshSchemePolicy,
            Variant::RefreshBlacklist,
            Variant::RefreshQuotaShare,
            Variant::RefreshTimeAnchor,
        ];
        let mut views = std::collections::BTreeMap::new();
        let mut branches = Vec::new();
        for variant in variants {
            let (_, _, widths) = layout(variant);
            let mut bounded = fields.clone();
            let mut checks = Vec::new();
            for (i, width) in widths.into_iter().enumerate() {
                if let Some(width) = width {
                    let (word, fits) = if let Some(view) = views.get(&(i, width)) {
                        view
                    } else {
                        let view = bounded_integer(uint, region, &fields[i], width)?;
                        views.entry((i, width)).or_insert(view)
                    };
                    bounded[i] = word.clone();
                    checks.push(fits.clone());
                }
            }
            branches.push(variant_predicate(
                uint, region, variant, fields, &bounded, checks,
            )?);
        }
        let mut sum = uint.glue().constant(region, Fp::ZERO)?;
        for branch in branches {
            sum = uint.glue().add(region, &sum, branch.word())?;
        }
        let valid = is_constant(uint.glue(), region, &sum, 1)?;
        let digest = hash.hash_words(region, STATEMENT_DOMAIN, fields)?;
        Ok(Self {
            fields: fields.clone(),
            digest,
            valid,
        })
    }
    /// Original full statement fields, including the witness operation tag.
    pub const fn fields(&self) -> &[Word<Fp>; 26] {
        &self.fields
    }
    /// Poseidon digest of the original words.
    pub const fn digest(&self) -> &Word<Fp> {
        &self.digest
    }
    /// Total disjoint-union semantic predicate, mandatory in status validity.
    pub const fn valid(&self) -> &Bit<Fp> {
        &self.valid
    }
}

fn variant_predicate(
    uint: &mut UintChip<'_, Fp>,
    region: &mut Region<'_, Fp>,
    variant: Variant,
    fields: &[Word<Fp>; 26],
    bounded: &[Word<Fp>; 26],
    mut checks: Vec<Bit<Fp>>,
) -> Result<Bit<Fp>, Error> {
    let (tag, count, _) = layout(variant);
    let b = bounded;
    checks.push(is_constant(uint.glue(), region, &b[0], 1)?);
    let active = is_constant(uint.glue(), region, &b[8], 1)?;
    let retiring = is_constant(uint.glue(), region, &b[8], 2)?;
    let lifecycle = uint.glue().add(region, active.word(), retiring.word())?;
    checks.push(is_constant(uint.glue(), region, &lifecycle, 1)?);
    for index in [1, 3, 5] {
        checks.push(nonzero(uint.glue(), region, &b[index..index + 2])?);
    }
    for index in [7, 15] {
        checks.push(nonzero(
            uint.glue(),
            region,
            core::slice::from_ref(&b[index]),
        )?);
    }
    if matches!(variant, Variant::Send | Variant::Unload | Variant::Retiring) {
        checks.push(nonzero(uint.glue(), region, core::slice::from_ref(&b[13]))?);
    } else {
        checks.push(is_constant(uint.glue(), region, &b[12], 0)?);
        checks.push(is_constant(uint.glue(), region, &b[13], 0)?);
    }
    if variant == Variant::Bootstrap {
        for index in [9, 10, 11, 14] {
            checks.push(is_constant(uint.glue(), region, &b[index], 0)?);
        }
        checks.push(active);
    } else {
        for index in [9, 14] {
            checks.push(nonzero(
                uint.glue(),
                region,
                core::slice::from_ref(&b[index]),
            )?);
        }
    }
    checks.push(is_constant(uint.glue(), region, &b[16], tag)?);
    for word in &fields[17 + count..] {
        checks.push(is_constant(uint.glue(), region, word, 0)?);
    }
    let e = &b[17..];
    match variant {
        Variant::Bootstrap => {
            checks.push(nonzero(uint.glue(), region, &e[..2])?);
            checks.push(nonzero(uint.glue(), region, &e[2..4])?);
        }
        Variant::Load => {
            checks.push(nonzero(uint.glue(), region, core::slice::from_ref(&e[0]))?);
            let next = uint.glue().add_constant(region, &e[1], Fp::ONE)?;
            checks.push(uint.glue().is_equal(region, &b[10], &next)?);
        }
        Variant::Send => {
            for i in [0, 4, 6] {
                checks.push(nonzero(uint.glue(), region, core::slice::from_ref(&e[i]))?);
            }
            checks.push(nonzero(uint.glue(), region, &e[1..3])?);
            checks.push(sum_fits128(uint, region, &e[4], &e[5])?);
            checks.push(le64(uint, region, &e[7], &e[8])?);
        }
        Variant::Receive | Variant::ReceiveRenewed => {
            for i in [0, 3] {
                checks.push(nonzero(uint.glue(), region, core::slice::from_ref(&e[i]))?);
            }
            checks.push(nonzero(uint.glue(), region, &e[1..3])?);
        }
        Variant::ArchiveReceive | Variant::ArchiveStatus => {
            for word in &e[..2] {
                checks.push(nonzero(uint.glue(), region, core::slice::from_ref(word))?);
            }
        }
        Variant::Unload => {
            for i in [0, 2] {
                checks.push(nonzero(uint.glue(), region, core::slice::from_ref(&e[i]))?);
            }
            let amount = uint.range_check::<128>(region, &e[2])?;
            let charge = uint.range_check::<128>(region, &e[3])?;
            let over = uint.lt(region, &amount, &charge)?;
            checks.push(uint.glue().not(region, &over)?);
            let no_charge = uint.glue().is_zero(region, charge.word())?;
            let no_quote = uint.glue().is_zero(region, &e[4])?;
            checks.push(
                uint.glue()
                    .is_equal(region, no_charge.word(), no_quote.word())?,
            );
        }
        Variant::Retiring => checks.push(retiring),
        _ => {
            let kind = match variant {
                Variant::RefreshCredential => 1,
                Variant::RefreshSchemePolicy => 2,
                Variant::RefreshBlacklist => 3,
                Variant::RefreshQuotaShare => 4,
                Variant::RefreshTimeAnchor => 5,
                _ => return Err(Error::Synthesis),
            };
            checks.push(is_constant(uint.glue(), region, &e[0], kind)?);
            checks.push(nonzero(uint.glue(), region, core::slice::from_ref(&e[1]))?);
            if variant == Variant::RefreshCredential {
                checks.push(uint.glue().is_equal(region, &e[1], &b[7])?);
            }
        }
    }
    all(uint.glue(), region, &checks)
}

fn layout(variant: Variant) -> (u64, usize, [Option<usize>; 26]) {
    let mut widths = [None; 26];
    for (index, bits) in [
        (0, 16),
        (1, 128),
        (2, 128),
        (3, 128),
        (4, 128),
        (5, 128),
        (6, 128),
        (8, 8),
        (9, 128),
        (10, 128),
        (11, 3),
        (12, 128),
        (16, 8),
    ] {
        widths[index] = Some(bits);
    }
    let (tag, effect): (u64, &[Option<usize>]) = match variant {
        Variant::Bootstrap => (1, &[Some(128); 4]),
        Variant::Load => (2, &[None, Some(128), Some(128), Some(128)]),
        Variant::Send => (
            3,
            &[
                None,
                Some(128),
                Some(128),
                Some(128),
                Some(128),
                Some(128),
                None,
                Some(64),
                Some(64),
            ],
        ),
        Variant::Receive | Variant::ReceiveRenewed => (4, &[None, Some(128), Some(128), Some(128)]),
        Variant::ArchiveReceive | Variant::ArchiveStatus => (5, &[None, None]),
        Variant::Unload => (6, &[None, Some(128), Some(128), Some(128), None]),
        Variant::Retiring => (8, &[]),
        _ => (7, &[Some(8), None, Some(64)]),
    };
    widths[17..17 + effect.len()].copy_from_slice(effect);
    (tag, effect.len(), widths)
}

fn bounded_integer(
    uint: &mut UintChip<'_, Fp>,
    region: &mut Region<'_, Fp>,
    word: &Word<Fp>,
    bits: usize,
) -> Result<(Word<Fp>, Bit<Fp>), Error> {
    let canonical = LeElement::assign(uint, region, word.value().map(|v| v.to_repr()))?;
    let canonical_bit = scalar_bytes_canonical::<Fp, Fp>(uint, region, &canonical)?;
    GlueChip::assert_constant(region, canonical_bit.word(), Fp::ONE)?;
    let joined = uint.glue().linear(
        region,
        &[
            (Fp::ONE, canonical.lo().word()),
            (Fp::from_u128(1 << 127).double(), canonical.hi().word()),
        ],
        Fp::ZERO,
    )?;
    GlueChip::assert_equal(region, word, &joined)?;
    let mut fits = uint.glue().is_zero(region, canonical.hi().word())?;
    if bits == 128 {
        return Ok((canonical.lo().word().clone(), fits));
    }
    let mask = (1_u128 << bits) - 1;
    let low = uint.range().witness_range_checked(
        region,
        canonical.lo().value().map(|v| Fp::from_u128(v & mask)),
        bits,
    )?;
    let high = uint.range().witness_range_checked(
        region,
        canonical.lo().value().map(|v| Fp::from_u128(v >> bits)),
        128 - bits,
    )?;
    let recomposed = uint.glue().linear(
        region,
        &[(Fp::ONE, &low), (Fp::from_u128(1 << bits), &high)],
        Fp::ZERO,
    )?;
    GlueChip::assert_equal(region, &recomposed, canonical.lo().word())?;
    let high_zero = uint.glue().is_zero(region, &high)?;
    fits = uint.glue().and(region, &fits, &high_zero)?;
    Ok((low, fits))
}
