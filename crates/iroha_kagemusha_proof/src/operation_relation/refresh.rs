//! Policy-refresh state effects, composed with authenticated update objects in A.
//!
//! The update words must come from A's signed-object transcript constraints.
//! These effects alone do not authenticate a credential, issuer or update.
//! Blacklist history insertion and quota-array rebuilding are separate hard
//! relations; their changed roots are not accepted solely by this module.

/// Fixed-layout effects for the single five-kind RefreshPolicy sigma source.
pub mod selected;

use ff::Field;
use iroha_pasta::Fp;
use iroha_plonk::frontend::{Error, Region};
use iroha_plonk_gadgets::{GlueChip, UintChip, Word};
use iroha_plonk_recursion::obligation::ledger::Variant;

use super::{map_effects::MapTransition, state::rest_index as rest};
use crate::witness::core_index as core;

/// Signed object fields used by the fixed policy-refresh variant.
///
/// A must constrain the object digest, signature, certificate purpose and
/// every supplied field to the same canonical transcript before composition.
#[derive(Clone, Copy, Debug)]
pub enum RefreshUpdate<'a> {
    /// A credential whose exact renewal relation A separately authenticates.
    /// All immutable credential fields and the incremented renewal sequence
    /// must be checked against the credential opened by the predecessor.
    Credential {
        /// Replacement credential object digest.
        digest: &'a Word<Fp>,
        /// Replacement issue time.
        issued: &'a Word<Fp>,
        /// Replacement lease expiry.
        lease: &'a Word<Fp>,
    },
    /// Scheme policy, including the optional fee-schedule digest.
    SchemePolicy {
        /// Signed policy digest.
        digest: &'a Word<Fp>,
        /// Scheme identity in two little-endian u128 halves.
        scheme: &'a [Word<Fp>; 2],
        /// Asset identity in two little-endian u128 halves.
        asset: &'a [Word<Fp>; 2],
        /// Strictly increasing policy epoch.
        epoch: &'a Word<Fp>,
        /// Three-bit controls mask before credential permission intersection.
        controls: &'a Word<Fp>,
        /// Fee-schedule digest, or zero.
        fee: &'a Word<Fp>,
    },
    /// New blacklist whose version/root is also inserted into history.
    Blacklist {
        /// Signed list digest.
        digest: &'a Word<Fp>,
        /// Scheme identity.
        scheme: &'a [Word<Fp>; 2],
        /// Strictly increasing list version.
        version: &'a Word<Fp>,
        /// Nonzero canonical gap-tree root.
        root: &'a Word<Fp>,
        /// Signed list issue time.
        issued: &'a Word<Fp>,
    },
    /// New quota share whose windows and usage array A also rebuilds.
    QuotaShare {
        /// Signed share digest.
        digest: &'a Word<Fp>,
        /// Scheme identity.
        scheme: &'a [Word<Fp>; 2],
        /// Asset identity.
        asset: &'a [Word<Fp>; 2],
        /// Wallet identity.
        wallet: &'a [Word<Fp>; 2],
        /// Strictly increasing share identity.
        id: &'a Word<Fp>,
        /// Signed share issue time.
        issued: &'a Word<Fp>,
        /// Signed share expiry.
        expires: &'a Word<Fp>,
        /// Nonzero canonical root of the signed 64-slot windows array.
        windows: &'a Word<Fp>,
    },
    /// A different time-anchor object for this wallet.
    TimeAnchor {
        /// Signed time-anchor digest.
        digest: &'a Word<Fp>,
        /// Scheme identity.
        scheme: &'a [Word<Fp>; 2],
        /// Wallet identity.
        wallet: &'a [Word<Fp>; 2],
        /// Signed issuer time.
        issued: &'a Word<Fp>,
    },
}

impl<'a> RefreshUpdate<'a> {
    fn variant(self) -> Variant {
        match self {
            Self::Credential { .. } => Variant::RefreshCredential,
            Self::SchemePolicy { .. } => Variant::RefreshSchemePolicy,
            Self::Blacklist { .. } => Variant::RefreshBlacklist,
            Self::QuotaShare { .. } => Variant::RefreshQuotaShare,
            Self::TimeAnchor { .. } => Variant::RefreshTimeAnchor,
        }
    }
    fn digest(self) -> &'a Word<Fp> {
        match self {
            Self::Credential { digest, .. }
            | Self::SchemePolicy { digest, .. }
            | Self::Blacklist { digest, .. }
            | Self::QuotaShare { digest, .. }
            | Self::TimeAnchor { digest, .. } => digest,
        }
    }
}

/// Constrain every refresh state effect and every unchanged core/rest word.
///
/// This checks the exact monotone floor, policy permission intersection,
/// object identity, increasing counters, expiry and lineage preservation.
/// Credential identity/renewal authentication, blacklist history insertion
/// and quota rebuilding remain hard obligations of the consuming relation.
///
/// # Errors
/// Mismatched fixed variant or layout failure. Stale counters, a repeated
/// anchor, reduced floor and unrelated field changes are unsatisfiable.
pub fn constrain(
    uint: &mut UintChip<'_, Fp>,
    region: &mut Region<'_, Fp>,
    transition: &MapTransition<'_>,
    update: RefreshUpdate<'_>,
) -> Result<(), Error> {
    let variant = update.variant();
    if variant != transition.statement.variant() {
        return Err(Error::Synthesis);
    }
    transition.statement.bind_states(
        uint,
        region,
        Some((transition.predecessor.state, transition.predecessor.lineage)),
        transition.successor.state,
        transition.successor.lineage,
    )?;
    let before = transition.predecessor.state.core();
    let after = transition.successor.state.core();
    let old_rest = transition.predecessor.state.rest();
    let new_rest = transition.successor.state.rest();
    GlueChip::assert_equal(region, update.digest(), &transition.statement.fields()[18])?;
    uint.glue().assert_nonzero(region, update.digest())?;
    let signed_time = match update {
        RefreshUpdate::Credential {
            digest,
            issued,
            lease,
        } => {
            GlueChip::assert_equal(region, digest, &after[core::CREDENTIAL])?;
            GlueChip::assert_equal(region, lease, &after[core::LEASE_EXPIRY])?;
            issued
        }
        RefreshUpdate::SchemePolicy {
            digest,
            scheme,
            asset,
            epoch,
            controls,
            fee,
        } => {
            bind_pair(region, scheme, &before[core::SCHEME..=core::SCHEME + 1])?;
            bind_pair(region, asset, &before[core::ASSET..=core::ASSET + 1])?;
            increasing(uint, region, &before[core::POLICY_EPOCH], epoch)?;
            GlueChip::assert_equal(region, epoch, &after[core::POLICY_EPOCH])?;
            GlueChip::assert_equal(region, digest, &new_rest[rest::SCHEME_POLICY])?;
            GlueChip::assert_equal(region, fee, &new_rest[rest::FEE_SCHEDULE])?;
            let policy = mask(uint, region, controls)?;
            let permitted = mask(uint, region, &old_rest[rest::PERMITTED])?;
            let mut enabled = Vec::with_capacity(3);
            for i in 0..3 {
                enabled.push(
                    uint.glue()
                        .mul(region, policy[i].word(), permitted[i].word())?,
                );
            }
            let intersection = uint.glue().linear(
                region,
                &[
                    (Fp::ONE, &enabled[0]),
                    (Fp::from(2), &enabled[1]),
                    (Fp::from(4), &enabled[2]),
                ],
                Fp::ZERO,
            )?;
            GlueChip::assert_equal(region, &intersection, &after[core::ENABLED_CONTROLS])?;
            &before[core::TIME_FLOOR]
        }
        RefreshUpdate::Blacklist {
            digest,
            scheme,
            version,
            root,
            issued,
        } => {
            bind_pair(region, scheme, &before[core::SCHEME..=core::SCHEME + 1])?;
            increasing(uint, region, &before[core::BLACKLIST_VERSION], version)?;
            for (word, index) in [
                (version, core::BLACKLIST_VERSION),
                (root, core::BLACKLIST_ROOT),
                (issued, core::BLACKLIST_ISSUED_AT),
            ] {
                GlueChip::assert_equal(region, word, &after[index])?;
            }
            GlueChip::assert_equal(region, digest, &new_rest[rest::BLACKLIST])?;
            issued
        }
        RefreshUpdate::QuotaShare {
            digest,
            scheme,
            asset,
            wallet,
            id,
            issued,
            expires,
            windows,
        } => {
            bind_pair(region, scheme, &before[core::SCHEME..=core::SCHEME + 1])?;
            bind_pair(region, asset, &before[core::ASSET..=core::ASSET + 1])?;
            bind_pair(region, wallet, &before[core::WALLET..=core::WALLET + 1])?;
            increasing(uint, region, &old_rest[rest::QUOTA_SHARE_ID], id)?;
            let start = uint.range_check::<64>(region, issued)?;
            let end = uint.range_check::<64>(region, expires)?;
            uint.assert_lt(region, &start, &end)?;
            GlueChip::assert_equal(region, digest, &new_rest[rest::QUOTA_SHARE])?;
            GlueChip::assert_equal(region, id, &new_rest[rest::QUOTA_SHARE_ID])?;
            GlueChip::assert_equal(region, expires, &after[core::QUOTA_SHARE_EXPIRY])?;
            GlueChip::assert_equal(region, windows, &after[core::QUOTA_WINDOWS_ROOT])?;
            issued
        }
        RefreshUpdate::TimeAnchor {
            digest,
            scheme,
            wallet,
            issued,
        } => {
            bind_pair(region, scheme, &before[core::SCHEME..=core::SCHEME + 1])?;
            bind_pair(region, wallet, &before[core::WALLET..=core::WALLET + 1])?;
            let difference = uint
                .glue()
                .sub(region, digest, &old_rest[rest::TIME_ANCHOR])?;
            uint.glue().assert_nonzero(region, &difference)?;
            GlueChip::assert_equal(region, digest, &new_rest[rest::TIME_ANCHOR])?;
            issued
        }
    };
    let floor = uint.range_check::<64>(region, &before[core::TIME_FLOOR])?;
    let signed_time = uint.range_check::<64>(region, signed_time)?;
    let advance = uint.lt(region, &floor, &signed_time)?;
    let accepted = uint
        .glue()
        .select(region, &advance, signed_time.word(), floor.word())?;
    GlueChip::assert_equal(region, &accepted, &after[core::TIME_FLOOR])?;
    GlueChip::assert_equal(region, &accepted, &transition.statement.fields()[19])?;
    for (i, old) in before.iter().enumerate() {
        let changed = matches!(i, core::SEQUENCE | core::STATE_NONCE | core::TIME_FLOOR)
            || match variant {
                Variant::RefreshCredential => matches!(i, core::CREDENTIAL | core::LEASE_EXPIRY),
                Variant::RefreshSchemePolicy => {
                    matches!(i, core::POLICY_EPOCH | core::ENABLED_CONTROLS)
                }
                Variant::RefreshBlacklist => matches!(
                    i,
                    core::BLACKLIST_VERSION | core::BLACKLIST_ROOT | core::BLACKLIST_ISSUED_AT
                ),
                Variant::RefreshQuotaShare => matches!(
                    i,
                    core::QUOTA_WINDOWS_ROOT | core::QUOTA_SHARE_EXPIRY | core::QUOTA_USAGE_ROOT
                ),
                _ => false,
            };
        if !changed {
            GlueChip::assert_equal(region, old, &after[i])?;
        }
    }
    for (i, old) in old_rest.iter().enumerate() {
        let changed = match variant {
            Variant::RefreshSchemePolicy => matches!(i, rest::SCHEME_POLICY | rest::FEE_SCHEDULE),
            Variant::RefreshBlacklist => matches!(i, rest::BLACKLIST | rest::BLACKLIST_HISTORY),
            Variant::RefreshQuotaShare => matches!(i, rest::QUOTA_SHARE | rest::QUOTA_SHARE_ID),
            Variant::RefreshTimeAnchor => i == rest::TIME_ANCHOR,
            _ => false,
        };
        if !changed {
            GlueChip::assert_equal(region, old, &new_rest[i])?;
        }
    }
    for i in [14, 15, 16] {
        GlueChip::assert_equal(
            region,
            &transition.predecessor.lineage.fields()[i],
            &transition.successor.lineage.fields()[i],
        )?;
    }
    Ok(())
}

fn bind_pair(
    region: &mut Region<'_, Fp>,
    supplied: &[Word<Fp>; 2],
    expected: &[Word<Fp>],
) -> Result<(), Error> {
    for (a, b) in supplied.iter().zip(expected) {
        GlueChip::assert_equal(region, a, b)?;
    }
    Ok(())
}

fn increasing(
    uint: &mut UintChip<'_, Fp>,
    region: &mut Region<'_, Fp>,
    old: &Word<Fp>,
    new: &Word<Fp>,
) -> Result<(), Error> {
    let old = uint.range_check::<64>(region, old)?;
    let new = uint.range_check::<64>(region, new)?;
    uint.assert_lt(region, &old, &new)
}

pub(crate) fn mask(
    uint: &mut UintChip<'_, Fp>,
    region: &mut Region<'_, Fp>,
    word: &Word<Fp>,
) -> Result<[iroha_plonk_gadgets::Bit<Fp>; 3], Error> {
    let integer = uint.range_check::<3>(region, word)?;
    let mut bits = Vec::with_capacity(3);
    for i in 0..3 {
        bits.push(
            uint.glue()
                .boolean(region, integer.value().map(|v| v & (1 << i) != 0))?,
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
    GlueChip::assert_equal(region, &composed, word)?;
    bits.try_into().map_err(|_| Error::Synthesis)
}
