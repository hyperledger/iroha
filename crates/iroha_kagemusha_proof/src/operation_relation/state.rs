//! Canonical core/rest openings and their binding to public lineage fields.

use ff::{Field, PrimeField};
use iroha_pasta::{Ep, Fp};
use iroha_plonk::frontend::{Error, Region};
use iroha_plonk_gadgets::{Bit, GlueChip, UintChip, Word, WordHasher};
use iroha_plonk_recursion::verifier::VerifierChip;

use crate::{
    a_relation::LineagePublicCells,
    witness::{CORE_DOMAIN, CORE_FIELDS, REST_DOMAIN, REST_FIELDS, core_index as core},
};

/// Indices in the canonical eight-field state rest.
pub mod rest_index {
    /// Controls the credential permits.
    pub const PERMITTED: usize = 0;
    /// Held scheme-policy object digest.
    pub const SCHEME_POLICY: usize = 1;
    /// Held fee-schedule object digest, or zero.
    pub const FEE_SCHEDULE: usize = 2;
    /// Held blacklist object digest, or zero.
    pub const BLACKLIST: usize = 3;
    /// Held quota-share object digest, or zero.
    pub const QUOTA_SHARE: usize = 4;
    /// Held quota-share identity, or zero.
    pub const QUOTA_SHARE_ID: usize = 5;
    /// Committed time-anchor object digest, or zero.
    pub const TIME_ANCHOR: usize = 6;
    /// Permanent blacklist-version history root.
    pub const BLACKLIST_HISTORY: usize = 7;
}

/// A validated private state opening, with both Poseidon levels constrained.
#[derive(Clone, Debug)]
pub struct StateCells {
    core: [Word<Fp>; CORE_FIELDS],
    rest: [Word<Fp>; REST_FIELDS],
    rest_digest: Word<Fp>,
    commitment: Word<Fp>,
}

impl StateCells {
    /// Validate existing canonical G1 core/rest words and compute the head.
    ///
    /// All integer widths, lifecycle tags, nonzero identities/map roots,
    /// permitted/enabled controls, held-object consistency and regulatory
    /// time/lease rules match the native state's self-contained validation.
    /// Credential authenticity and transition semantics are separate
    /// constraints in the owning operation.
    ///
    /// # Errors
    /// Layout failure; invalid self-contained state has no satisfying witness.
    pub fn constrain(
        uint: &mut UintChip<'_, Fp>,
        sponge: &mut impl WordHasher<Fp>,
        region: &mut Region<'_, Fp>,
        core: &[Word<Fp>; CORE_FIELDS],
        rest: &[Word<Fp>; REST_FIELDS],
    ) -> Result<Self, Error> {
        validate_fields(uint, region, core, rest)?;
        let rest_digest = sponge.hash_words(region, REST_DOMAIN, rest)?;
        let mut preimage = core.to_vec();
        preimage.push(rest_digest.clone());
        let commitment = sponge.hash_words(region, CORE_DOMAIN, &preimage)?;
        Ok(Self {
            core: core.clone(),
            rest: rest.clone(),
            rest_digest,
            commitment,
        })
    }

    /// Validate the state on A's shared recursive hash lane.
    /// Uses the same field/control constraints as [`Self::constrain`].
    ///
    /// # Errors
    /// Layout failure; invalid self-contained state has no satisfying witness.
    pub fn constrain_with_verifier(
        chip: &mut VerifierChip<Ep>,
        region: &mut Region<'_, Fp>,
        core: &[Word<Fp>; CORE_FIELDS],
        rest: &[Word<Fp>; REST_FIELDS],
    ) -> Result<Self, Error> {
        let lanes = chip.operation_lanes()?;
        Self::constrain(
            &mut UintChip::new(lanes.glue, lanes.range),
            lanes.hash,
            region,
            core,
            rest,
        )
    }

    /// The canonical core words, in [`crate::witness::core_index`] order.
    #[must_use]
    pub const fn core(&self) -> &[Word<Fp>; CORE_FIELDS] {
        &self.core
    }
    /// The canonical rest words, in [`rest_index`] order.
    #[must_use]
    pub const fn rest(&self) -> &[Word<Fp>; REST_FIELDS] {
        &self.rest
    }
    /// Digest opened from the eight rest fields.
    #[must_use]
    pub const fn rest_digest(&self) -> &Word<Fp> {
        &self.rest_digest
    }
    /// The constrained state commitment.
    #[must_use]
    pub const fn commitment(&self) -> &Word<Fp> {
        &self.commitment
    }

    /// Bind a lineage prefix to this state opening's head and state facts.
    ///
    /// `burned_total`, pending and credit roots are lineage-adjusted values;
    /// this method does not equate them to the core. The operation separately
    /// constrains those transitions, credential/payment-key binding,
    /// relation identity and Omega key continuity.
    ///
    /// # Errors
    /// Layout failure; a different head, identity or packed state fact is unsatisfiable.
    pub fn bind_lineage(
        &self,
        uint: &mut UintChip<'_, Fp>,
        region: &mut Region<'_, Fp>,
        lineage: &LineagePublicCells,
    ) -> Result<(), Error> {
        let fields = lineage.fields();
        GlueChip::assert_equal(region, self.commitment(), lineage.head())?;
        for (source, target) in [
            (core::SCHEME, 1),
            (core::SCHEME + 1, 2),
            (core::WALLET, 6),
            (core::WALLET + 1, 7),
            (core::CREDENTIAL, 8),
        ] {
            GlueChip::assert_equal(region, &self.core[source], &fields[target])?;
        }
        let packed = uint.glue().linear(
            region,
            &[
                (Fp::ONE, &self.core[core::LIFECYCLE]),
                (Fp::from(1_u64 << 8), &self.core[core::POLICY_EPOCH]),
                (
                    Fp::from_u128(1_u128 << 72),
                    &self.core[core::ENABLED_CONTROLS],
                ),
            ],
            Fp::ZERO,
        )?;
        GlueChip::assert_equal(region, &packed, &fields[13])
    }
}

fn mask(
    uint: &mut UintChip<'_, Fp>,
    region: &mut Region<'_, Fp>,
    word: &Word<Fp>,
) -> Result<[Bit<Fp>; 3], Error> {
    let integer = uint.range_check::<3>(region, word)?;
    let mut bits = Vec::with_capacity(3);
    for index in 0..3 {
        bits.push(
            uint.glue()
                .boolean(region, integer.value().map(|n| n & (1 << index) != 0))?,
        );
    }
    let composed = uint.glue().linear(
        region,
        &[
            (Fp::ONE, bits[0].word()),
            (Fp::from(2), bits[1].word()),
            (Fp::from(4), bits[2].word()),
        ],
        Fp::ZERO,
    )?;
    GlueChip::assert_equal(region, word, &composed)?;
    bits.try_into().map_err(|_| Error::Synthesis)
}

fn gated_zero(
    uint: &mut UintChip<'_, Fp>,
    region: &mut Region<'_, Fp>,
    enabled: &Bit<Fp>,
    word: &Word<Fp>,
) -> Result<(), Error> {
    let product = uint.glue().mul(region, enabled.word(), word)?;
    GlueChip::assert_constant(region, &product, Fp::ZERO)
}

fn validate_fields(
    uint: &mut UintChip<'_, Fp>,
    region: &mut Region<'_, Fp>,
    core: &[Word<Fp>; CORE_FIELDS],
    rest: &[Word<Fp>; REST_FIELDS],
) -> Result<(), Error> {
    let lifecycle = uint
        .glue()
        .add_constant(region, &core[core::LIFECYCLE], -Fp::ONE)?;
    uint.glue().assert_bool(region, &lifecycle)?;
    for word in &core[core::SCHEME..core::CREDENTIAL] {
        uint.range_check::<128>(region, word)?;
    }
    for index in [core::SCHEME, core::ASSET, core::WALLET] {
        let sum = uint.glue().add(region, &core[index], &core[index + 1])?;
        uint.glue().assert_nonzero(region, &sum)?;
    }
    for word in &core[core::BALANCE..=core::NEXT_REDEEM] {
        uint.range_check::<128>(region, word)?;
    }
    for index in [
        core::QUOTA_SHARE_EXPIRY,
        core::BLACKLIST_VERSION,
        core::BLACKLIST_ISSUED_AT,
        core::BLACKLIST_MAX_AGE,
        core::TIME_ANCHOR_MAX_RESPONSE,
        core::LEASE_EXPIRY,
        core::POLICY_EPOCH,
        core::TIME_FLOOR,
    ] {
        uint.range_check::<64>(region, &core[index])?;
    }
    uint.range_check::<64>(region, &rest[rest_index::QUOTA_SHARE_ID])?;
    for index in [
        core::CREDENTIAL,
        core::CONSUMED_CREDIT_ROOT,
        core::PENDING_OUTGOING_ROOT,
        core::LOAD_REDEEM_ROOT,
        core::FEE_CLAIM_ROOT,
        core::QUOTA_USAGE_ROOT,
        core::STATE_NONCE,
    ] {
        uint.glue().assert_nonzero(region, &core[index])?;
    }
    uint.glue()
        .assert_nonzero(region, &rest[rest_index::BLACKLIST_HISTORY])?;
    controls(uint, region, core, rest)?;
    Ok(())
}

fn controls(
    uint: &mut UintChip<'_, Fp>,
    region: &mut Region<'_, Fp>,
    core: &[Word<Fp>; CORE_FIELDS],
    rest: &[Word<Fp>; REST_FIELDS],
) -> Result<(), Error> {
    let permitted = mask(uint, region, &rest[rest_index::PERMITTED])?;
    let enabled = mask(uint, region, &core[core::ENABLED_CONTROLS])?;
    for (enabled, permitted) in enabled.iter().zip(&permitted) {
        let allowed = uint.glue().and(region, enabled, permitted)?;
        GlueChip::assert_equal(region, enabled.word(), allowed.word())?;
    }
    let age_zero = uint
        .glue()
        .is_zero(region, &core[core::BLACKLIST_MAX_AGE])?;
    let has_age = uint.glue().not(region, &age_zero)?;
    let valid_age = uint.glue().and(region, &has_age, &permitted[0])?;
    GlueChip::assert_equal(region, has_age.word(), valid_age.word())?;
    let time_rules = uint.glue().linear(
        region,
        &[
            (Fp::ONE, permitted[1].word()),
            (Fp::ONE, permitted[2].word()),
            (Fp::ONE, has_age.word()),
        ],
        Fp::ZERO,
    )?;
    let no_time_rules = uint.glue().is_zero(region, &time_rules)?;
    let no_response = uint
        .glue()
        .is_zero(region, &core[core::TIME_ANCHOR_MAX_RESPONSE])?;
    GlueChip::assert_equal(region, no_time_rules.word(), no_response.word())?;
    let no_lease = uint.glue().is_zero(region, &core[core::LEASE_EXPIRY])?;
    let lease_forbidden = uint.glue().not(region, &permitted[2])?;
    GlueChip::assert_equal(region, no_lease.word(), lease_forbidden.word())?;

    let no_policy = uint.glue().is_zero(region, &core[core::POLICY_EPOCH])?;
    let no_policy_digest = uint
        .glue()
        .is_zero(region, &rest[rest_index::SCHEME_POLICY])?;
    GlueChip::assert_equal(region, no_policy.word(), no_policy_digest.word())?;
    gated_zero(uint, region, &no_policy, &core[core::ENABLED_CONTROLS])?;
    gated_zero(uint, region, &no_policy, &rest[rest_index::FEE_SCHEDULE])?;

    let no_list = uint
        .glue()
        .is_zero(region, &core[core::BLACKLIST_VERSION])?;
    for value in [&core[core::BLACKLIST_ROOT], &rest[rest_index::BLACKLIST]] {
        let zero = uint.glue().is_zero(region, value)?;
        GlueChip::assert_equal(region, no_list.word(), zero.word())?;
    }
    gated_zero(uint, region, &no_list, &core[core::BLACKLIST_ISSUED_AT])?;
    let no_share = uint
        .glue()
        .is_zero(region, &rest[rest_index::QUOTA_SHARE_ID])?;
    for value in [
        &core[core::QUOTA_WINDOWS_ROOT],
        &core[core::QUOTA_SHARE_EXPIRY],
        &rest[rest_index::QUOTA_SHARE],
    ] {
        let zero = uint.glue().is_zero(region, value)?;
        GlueChip::assert_equal(region, no_share.word(), zero.word())?;
    }
    Ok(())
}
