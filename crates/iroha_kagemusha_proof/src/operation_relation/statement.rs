//! Validated 26-element statements shared by every lineage operation.

use ff::Field;
use iroha_pasta::{Ep, Fp};
use iroha_plonk::frontend::{Error, Region};
use iroha_plonk_gadgets::{
    Bit, GlueChip, UintChip, Word, WordHasher,
    statement::{STATEMENT_DOMAIN, STATEMENT_FIELDS},
};
use iroha_plonk_recursion::{obligation::ledger::Variant, verifier::VerifierChip};

use super::state::StateCells;
use crate::{a_relation::LineagePublicCells, witness::core_index as core};

/// Canonical statement with its native self-contained rules constrained.
///
/// Authentication, exact operation effects and key selection are composed
/// by A. This type by itself does not authorize a transition.
#[derive(Clone, Debug)]
pub struct StatementCells {
    variant: Variant,
    fields: [Word<Fp>; STATEMENT_FIELDS],
    digest: Word<Fp>,
}

impl StatementCells {
    /// Validate a fixed operation variant and compute its statement digest.
    ///
    /// Enforces integer widths, exact effect padding, positive transfer
    /// amounts, no overflowing Send gross debit, ordered times, Unload
    /// charges and the Bootstrap/Load/Retiring/renewal header rules.
    ///
    /// # Errors
    /// Layout failure; invalid statements have no satisfying witness.
    pub fn constrain(
        uint: &mut UintChip<'_, Fp>,
        sponge: &mut impl WordHasher<Fp>,
        region: &mut Region<'_, Fp>,
        variant: Variant,
        fields: &[Word<Fp>; STATEMENT_FIELDS],
    ) -> Result<Self, Error> {
        validate_fields(uint, region, variant, fields)?;
        let digest = sponge.hash_words(region, STATEMENT_DOMAIN, fields)?;
        Ok(Self {
            variant,
            fields: fields.clone(),
            digest,
        })
    }

    /// Validate a statement using A's shared recursive transcript lane.
    ///
    /// Applies the same hard field rules as [`Self::constrain`] and keeps
    /// the existing verifier's sponge cursor, avoiding a second hash lane.
    ///
    /// # Errors
    /// Layout failure; invalid statements have no satisfying witness.
    pub fn constrain_with_verifier(
        chip: &mut VerifierChip<Ep>,
        region: &mut Region<'_, Fp>,
        variant: Variant,
        fields: &[Word<Fp>; STATEMENT_FIELDS],
    ) -> Result<Self, Error> {
        let lanes = chip.operation_lanes()?;
        Self::constrain(
            &mut UintChip::new(lanes.glue, lanes.range),
            lanes.hash,
            region,
            variant,
            fields,
        )
    }

    /// The immutable operation variant of this statement.
    #[must_use]
    pub const fn variant(&self) -> Variant {
        self.variant
    }
    /// The canonical 26 statement fields.
    #[must_use]
    pub const fn fields(&self) -> &[Word<Fp>; STATEMENT_FIELDS] {
        &self.fields
    }
    /// The digest verified by the corresponding Q sigma slot.
    #[must_use]
    pub const fn digest(&self) -> &Word<Fp> {
        &self.digest
    }

    /// Bind the header to private state openings and public lineage identity.
    ///
    /// This binds one sequence advance and wallet/scheme/asset continuity.
    /// The operation must still constrain all changed/unchanged core and
    /// rest fields, its maps, signatures and public effect. When the step
    /// consumes lineage, `predecessor` must include the authenticated prefix
    /// so that its burned/pending values cannot be substituted.
    ///
    /// # Errors
    /// Wrong fixed predecessor presence or layout failure; mismatches are unsatisfiable.
    pub fn bind_states(
        &self,
        uint: &mut UintChip<'_, Fp>,
        region: &mut Region<'_, Fp>,
        predecessor: Option<(&StateCells, &LineagePublicCells)>,
        successor: &StateCells,
        lineage: &LineagePublicCells,
    ) -> Result<(), Error> {
        bind_state_fields(
            &self.fields,
            (
                self.variant == Variant::Bootstrap,
                consumes_lineage(self.variant),
            ),
            uint,
            region,
            predecessor,
            successor,
            lineage,
        )
    }
}

fn bind_state_fields(
    fields: &[Word<Fp>; STATEMENT_FIELDS],
    flags: (bool, bool),
    uint: &mut UintChip<'_, Fp>,
    region: &mut Region<'_, Fp>,
    predecessor: Option<(&StateCells, &LineagePublicCells)>,
    successor: &StateCells,
    lineage: &LineagePublicCells,
) -> Result<(), Error> {
    if predecessor.is_none() != flags.0 {
        return Err(Error::Synthesis);
    }
    successor.bind_lineage(uint, region, lineage)?;
    let f = fields;
    for (index, core_index) in [
        (3, core::SCHEME),
        (4, core::SCHEME + 1),
        (5, core::ASSET),
        (6, core::ASSET + 1),
        (7, core::CREDENTIAL),
        (8, core::LIFECYCLE),
        (9, core::SEQUENCE),
        (10, core::NEXT_LOAD),
    ] {
        GlueChip::assert_equal(region, &f[index], &successor.core()[core_index])?;
    }
    GlueChip::assert_equal(region, &f[1], &lineage.fields()[3])?;
    GlueChip::assert_equal(region, &f[2], &lineage.fields()[4])?;
    GlueChip::assert_equal(region, &f[15], successor.commitment())?;
    if let Some((predecessor, previous_lineage)) = predecessor {
        predecessor.bind_lineage(uint, region, previous_lineage)?;
        GlueChip::assert_equal(region, &f[14], predecessor.commitment())?;
        GlueChip::assert_equal(region, &f[11], &predecessor.core()[core::ENABLED_CONTROLS])?;
        for index in core::SCHEME..core::CREDENTIAL {
            GlueChip::assert_equal(region, &predecessor.core()[index], &successor.core()[index])?;
        }
        let sequence = uint.range_check::<128>(region, &predecessor.core()[core::SEQUENCE])?;
        let next = uint.checked_add_constant(region, &sequence, 1)?;
        GlueChip::assert_equal(region, next.word(), &f[9])?;
        for index in [3, 4, 9, 10, 11, 12, 17] {
            GlueChip::assert_equal(
                region,
                &previous_lineage.fields()[index],
                &lineage.fields()[index],
            )?;
        }
        if flags.1 {
            GlueChip::assert_equal(region, &f[12], previous_lineage.burned_total())?;
            GlueChip::assert_equal(region, &f[13], previous_lineage.pending_root())?;
        }
    }
    Ok(())
}

fn validate_fields(
    uint: &mut UintChip<'_, Fp>,
    region: &mut Region<'_, Fp>,
    variant: Variant,
    fields: &[Word<Fp>; STATEMENT_FIELDS],
) -> Result<(), Error> {
    validate_header(
        uint,
        region,
        (variant == Variant::Bootstrap, consumes_lineage(variant)),
        fields,
    )?;
    let (tag, count) = effect(uint, region, variant, &fields[17..])?;
    GlueChip::assert_constant(region, &fields[16], Fp::from(tag))?;
    for word in &fields[17 + count..] {
        GlueChip::assert_constant(region, word, Fp::ZERO)?;
    }
    if variant == Variant::Load {
        let ordinal = uint.range_check::<128>(region, &fields[18])?;
        let next = uint.checked_add_constant(region, &ordinal, 1)?;
        GlueChip::assert_equal(region, next.word(), &fields[10])?;
    }
    if variant == Variant::Retiring {
        GlueChip::assert_constant(region, &fields[8], Fp::from(2))?;
    }
    if variant == Variant::RefreshCredential {
        GlueChip::assert_equal(region, &fields[18], &fields[7])?;
    }
    Ok(())
}

fn validate_header(
    uint: &mut UintChip<'_, Fp>,
    region: &mut Region<'_, Fp>,
    flags: (bool, bool),
    fields: &[Word<Fp>; STATEMENT_FIELDS],
) -> Result<(), Error> {
    GlueChip::assert_constant(region, &fields[0], Fp::ONE)?;
    for start in [1, 3, 5] {
        digest_pair(uint, region, &fields[start..start + 2])?;
    }
    for index in [7, 15] {
        uint.glue().assert_nonzero(region, &fields[index])?;
    }
    let lifecycle = uint.glue().add_constant(region, &fields[8], -Fp::ONE)?;
    uint.glue().assert_bool(region, &lifecycle)?;
    for index in [9, 10, 12] {
        uint.range_check::<128>(region, &fields[index])?;
    }
    uint.range_check::<3>(region, &fields[11])?;
    if flags.1 {
        uint.glue().assert_nonzero(region, &fields[13])?;
    } else {
        for index in [12, 13] {
            GlueChip::assert_constant(region, &fields[index], Fp::ZERO)?;
        }
    }
    if flags.0 {
        for index in [9, 10, 11, 14] {
            GlueChip::assert_constant(region, &fields[index], Fp::ZERO)?;
        }
        GlueChip::assert_constant(region, &fields[8], Fp::ONE)?;
    } else {
        for index in [9, 14] {
            uint.glue().assert_nonzero(region, &fields[index])?;
        }
    }
    Ok(())
}

fn consumes_lineage(variant: Variant) -> bool {
    matches!(variant, Variant::Send | Variant::Unload | Variant::Retiring)
}

fn digest_pair(
    uint: &mut UintChip<'_, Fp>,
    region: &mut Region<'_, Fp>,
    pair: &[Word<Fp>],
) -> Result<(), Error> {
    for word in pair {
        uint.range_check::<128>(region, word)?;
    }
    let sum = uint.glue().add(region, &pair[0], &pair[1])?;
    uint.glue().assert_nonzero(region, &sum)
}

fn effect(
    uint: &mut UintChip<'_, Fp>,
    region: &mut Region<'_, Fp>,
    variant: Variant,
    e: &[Word<Fp>],
) -> Result<(u64, usize), Error> {
    match variant {
        Variant::Bootstrap => {
            digest_pair(uint, region, &e[..2])?;
            digest_pair(uint, region, &e[2..4])?;
            Ok((1, 4))
        }
        Variant::Load => {
            uint.glue().assert_nonzero(region, &e[0])?;
            for word in &e[1..4] {
                uint.range_check::<128>(region, word)?;
            }
            Ok((2, 4))
        }
        Variant::Send => {
            for index in [0, 6] {
                uint.glue().assert_nonzero(region, &e[index])?;
            }
            digest_pair(uint, region, &e[1..3])?;
            uint.range_check::<128>(region, &e[3])?;
            let amount = uint.range_check::<128>(region, &e[4])?;
            let fee = uint.range_check::<128>(region, &e[5])?;
            uint.glue().assert_nonzero(region, amount.word())?;
            uint.checked_add(region, &amount, &fee)?;
            let lower = uint.range_check::<64>(region, &e[7])?;
            let upper = uint.range_check::<64>(region, &e[8])?;
            uint.assert_le(region, &lower, &upper)?;
            Ok((3, 9))
        }
        Variant::Receive | Variant::ReceiveRenewed => {
            uint.glue().assert_nonzero(region, &e[0])?;
            digest_pair(uint, region, &e[1..3])?;
            uint.range_check::<128>(region, &e[3])?;
            uint.glue().assert_nonzero(region, &e[3])?;
            Ok((4, 4))
        }
        Variant::ArchiveReceive | Variant::ArchiveStatus => {
            for word in &e[..2] {
                uint.glue().assert_nonzero(region, word)?;
            }
            Ok((5, 2))
        }
        Variant::Unload => {
            uint.glue().assert_nonzero(region, &e[0])?;
            uint.range_check::<128>(region, &e[1])?;
            let amount = uint.range_check::<128>(region, &e[2])?;
            let charge = uint.range_check::<128>(region, &e[3])?;
            uint.glue().assert_nonzero(region, amount.word())?;
            uint.assert_le(region, &charge, &amount)?;
            let no_charge = uint.glue().is_zero(region, charge.word())?;
            let no_quote = uint.glue().is_zero(region, &e[4])?;
            GlueChip::assert_equal(region, no_charge.word(), no_quote.word())?;
            Ok((6, 5))
        }
        Variant::Retiring => Ok((8, 0)),
        _ => {
            let kind = match variant {
                Variant::RefreshCredential => 1,
                Variant::RefreshSchemePolicy => 2,
                Variant::RefreshBlacklist => 3,
                Variant::RefreshQuotaShare => 4,
                Variant::RefreshTimeAnchor => 5,
                _ => return Err(Error::Synthesis),
            };
            GlueChip::assert_constant(region, &e[0], Fp::from(kind))?;
            uint.glue().assert_nonzero(region, &e[1])?;
            uint.range_check::<64>(region, &e[2])?;
            Ok((7, 3))
        }
    }
}

/// One `RefreshPolicy` statement whose update kind is constrained inside one source.
/// The five selectors are derived from field17; none is a caller's validity flag.
#[derive(Clone, Debug)]
pub struct RefreshStatementCells {
    fields: [Word<Fp>; STATEMENT_FIELDS],
    digest: Word<Fp>,
    kinds: [Bit<Fp>; 5],
}
impl RefreshStatementCells {
    /// Constrain the common header, exactly one kind1..5, effect padding and digest.
    ///
    /// # Errors
    /// Layout failure; invalid kinds, noncanonical statement fields, nonzero lineage
    /// inputs, wrong tag/padding and a credential-update digest mismatch are unsatisfiable.
    pub fn constrain(
        uint: &mut UintChip<'_, Fp>,
        sponge: &mut impl WordHasher<Fp>,
        region: &mut Region<'_, Fp>,
        fields: &[Word<Fp>; STATEMENT_FIELDS],
    ) -> Result<Self, Error> {
        validate_header(uint, region, (false, false), fields)?;
        GlueChip::assert_constant(region, &fields[16], Fp::from(7))?;
        uint.range_check::<3>(region, &fields[17])?;
        let mut kinds = Vec::with_capacity(5);
        for kind in 1_u64..=5 {
            let difference = uint
                .glue()
                .add_constant(region, &fields[17], -Fp::from(kind))?;
            kinds.push(uint.glue().is_zero(region, &difference)?);
        }
        // The shared four-column glue accepts at most three input terms.
        // Sum all five derived bits in two fixed rows without changing the source
        // shape or permitting a host-selected subset of refresh kinds.
        let first = uint.glue().linear(
            region,
            &[
                (Fp::ONE, kinds[0].word()),
                (Fp::ONE, kinds[1].word()),
                (Fp::ONE, kinds[2].word()),
            ],
            Fp::ZERO,
        )?;
        let sum = uint.glue().linear(
            region,
            &[
                (Fp::ONE, &first),
                (Fp::ONE, kinds[3].word()),
                (Fp::ONE, kinds[4].word()),
            ],
            Fp::ZERO,
        )?;
        GlueChip::assert_constant(region, &sum, Fp::ONE)?;
        uint.glue().assert_nonzero(region, &fields[18])?;
        uint.range_check::<64>(region, &fields[19])?;
        for field in &fields[20..] {
            GlueChip::assert_constant(region, field, Fp::ZERO)?;
        }
        let difference = uint.glue().sub(region, &fields[18], &fields[7])?;
        let selected = uint.glue().mul(region, kinds[0].word(), &difference)?;
        GlueChip::assert_constant(region, &selected, Fp::ZERO)?;
        let digest = sponge.hash_words(region, STATEMENT_DOMAIN, fields)?;
        Ok(Self {
            fields: fields.clone(),
            digest,
            kinds: kinds.try_into().map_err(|_| Error::Synthesis)?,
        })
    }

    /// Complete canonical statement words.
    #[must_use]
    pub const fn fields(&self) -> &[Word<Fp>; STATEMENT_FIELDS] {
        &self.fields
    }

    /// The single public sigma instance derived from the statement.
    #[must_use]
    pub const fn digest(&self) -> &Word<Fp> {
        &self.digest
    }

    /// Derived one-hot selectors in Credential, Policy, Blacklist, Share, Anchor order.
    #[must_use]
    pub const fn kinds(&self) -> &[Bit<Fp>; 5] {
        &self.kinds
    }

    /// Bind both complete openings and their identity/sequence continuity.
    /// `RefreshPolicy` never consumes an Omega-adjusted monetary input.
    ///
    /// # Errors
    /// Layout failure or inconsistent state, lineage, sequence and statement fields.
    pub fn bind_states(
        &self,
        uint: &mut UintChip<'_, Fp>,
        region: &mut Region<'_, Fp>,
        predecessor: (&StateCells, &LineagePublicCells),
        successor: &StateCells,
        lineage: &LineagePublicCells,
    ) -> Result<(), Error> {
        bind_state_fields(
            &self.fields,
            (false, false),
            uint,
            region,
            Some(predecessor),
            successor,
            lineage,
        )
    }
}
