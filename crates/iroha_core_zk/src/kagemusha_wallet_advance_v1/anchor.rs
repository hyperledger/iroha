//! iOS rollback anchor (spec §§1.2, 2.1, 2.3, 4.2; G2 design rev 2 §§0(b), 2, 3).
//!
//! On iPhone, custody files can be restored from an app-data backup while the keychain stays,
//! so a restored older marker would otherwise select an older head that the surviving Secure
//! Enclave key can sign again. The provider therefore keeps a per-slot anchor
//! `{generation, marker_file_digest}` in a `kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly`
//! keychain item, which Apple never backs up, syncs or escrows:
//!
//! - it is created add-only with `NONE` when the slot is created (E2);
//! - it is raised only to a marker that is already durable: generation 0 (E4), every Selected
//!   marker before signing (A6), every Released marker before its Selected predecessor is
//!   retired (A10), and every terminal marker;
//! - selection compares it with the current marker: absent while markers exist is
//!   `AnchorMissing`, ahead of the files is `RolledBack`, the same generation with another
//!   digest is `AnchorMismatch`; a lower generation or `NONE` is accepted and raised before
//!   the next release.
//!
//! Every read is bracketed by protected-data checks before and after the keychain query, so
//! `errSecItemNotFound` counts as absent only while storage was unlocked throughout. Android
//! keeps no anchor ([`KagemushaWalletAnchorPolicyV1::NotRequired`]): its backup set is empty
//! and its keys never leave the device.
//!
//! Whether a slot is anchored is decided once, at enrollment, and recorded in every marker of
//! the slot. The check follows that record: a platform answer that disagrees with it (for
//! example an Apple adapter reporting no anchor for a keychain-anchored slot) refuses the slot
//! as `UnavailableCustodyData("anchor policy")` instead of skipping the check.
//!
//! Successful mutation acknowledgement is required even when a read finds the target value:
//! readback resolves visibility, not persistence. Selected and Released acknowledgements
//! protect against loss of only the final anchor write. They do not establish a bound on
//! writes lost to power failure; the public `SecItem` API documents no durability fence.
// TODO(G2-iOS): establish the platform persistence contract and qualify physical restore and
// power-loss schedules. Loss of both Selected and Released updates followed by restoration
// of pre-Advance files remains undetected if the payment key survives.

use super::{
    KagemushaWalletLostCustodyV1, KagemushaWalletProviderErrorV1, decode_envelope_v1,
    encode_envelope_v1,
    layout::KagemushaWalletSlotIdV1,
    marker::KagemushaWalletMarkerRecordV1,
    platform::{
        KagemushaWalletAnchorPolicyV1, KagemushaWalletNotPublishedV1, KagemushaWalletPlatformV1,
        KagemushaWalletProbeV1, KagemushaWalletPublishOutcomeV1,
    },
};

/// Anchor value version.
pub const KAGEMUSHA_WALLET_ANCHOR_VERSION_V1: u16 = 1;
/// Maximum encoded anchor value.
pub const KAGEMUSHA_WALLET_ANCHOR_MAX_BYTES_V1: usize = 256;

/// Value of one slot's rollback anchor.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, norito::Encode, norito::Decode, norito::NoritoSchema,
)]
#[norito_schema(name = "iroha_core::zk::kagemusha_wallet_advance_v1::AnchorV1")]
pub struct KagemushaWalletAnchorV1 {
    /// Value version; exactly [`KAGEMUSHA_WALLET_ANCHOR_VERSION_V1`].
    pub version: u16,
    /// Whether the anchor names a marker; `false` is `NONE` (no marker durable yet).
    pub named: bool,
    /// Named marker generation; zero for `NONE`.
    pub generation: u128,
    /// Named `marker_file_digest`; zero for `NONE`.
    pub marker_file_digest: [u8; 32],
}

impl KagemushaWalletAnchorV1 {
    /// The `NONE` anchor created with a slot.
    #[must_use]
    pub const fn none() -> Self {
        Self {
            version: KAGEMUSHA_WALLET_ANCHOR_VERSION_V1,
            named: false,
            generation: 0,
            marker_file_digest: [0; 32],
        }
    }

    /// Anchor naming the durable marker `record`.
    #[must_use]
    pub fn naming(record: &KagemushaWalletMarkerRecordV1) -> Self {
        Self {
            version: KAGEMUSHA_WALLET_ANCHOR_VERSION_V1,
            named: true,
            generation: record.generation(),
            marker_file_digest: *record.marker_file_digest(),
        }
    }

    /// Canonical bytes.
    ///
    /// # Errors
    ///
    /// Rejects an invalid anchor.
    pub fn encode(&self) -> Result<Vec<u8>, KagemushaWalletProviderErrorV1> {
        self.validate()?;
        encode_envelope_v1(self, KAGEMUSHA_WALLET_ANCHOR_MAX_BYTES_V1)
    }

    /// Decode and validate canonical bytes.
    ///
    /// # Errors
    ///
    /// Rejects oversized, noncanonical or invalid bytes.
    pub fn decode(bytes: &[u8]) -> Result<Self, KagemushaWalletProviderErrorV1> {
        let anchor: Self = decode_envelope_v1(bytes, KAGEMUSHA_WALLET_ANCHOR_MAX_BYTES_V1)?;
        anchor.validate()?;
        Ok(anchor)
    }

    fn validate(&self) -> Result<(), KagemushaWalletProviderErrorV1> {
        let consistent = if self.named {
            self.marker_file_digest != [0; 32]
        } else {
            self.generation == 0 && self.marker_file_digest == [0; 32]
        };
        if self.version != KAGEMUSHA_WALLET_ANCHOR_VERSION_V1 || !consistent {
            return Err(KagemushaWalletProviderErrorV1::Invalid { field: "anchor" });
        }
        Ok(())
    }
}

/// Result of comparing the anchor with the current marker.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum KagemushaWalletAnchorCheckV1 {
    /// The platform keeps no anchor.
    NotRequired,
    /// The anchor names exactly the current marker.
    Current,
    /// The anchor is `NONE` or names a lower generation; raise it before the next release.
    Lagging,
}

/// Read the anchor of `slot` inside protected-data brackets; `None` only for a definitive
/// absence observed while storage was available before and after the query.
///
/// # Errors
///
/// `Unavailable` when storage or the keychain gives no definitive answer (including a lock
/// event between the brackets) and `UnavailableCustodyData` for an invalid anchor value.
pub(super) fn kagemusha_wallet_read_anchor_v1<P: KagemushaWalletPlatformV1 + ?Sized>(
    platform: &P,
    slot: &KagemushaWalletSlotIdV1,
) -> Result<Option<KagemushaWalletAnchorV1>, KagemushaWalletProviderErrorV1> {
    super::counters::probe_storage(platform)
        .map_err(KagemushaWalletProviderErrorV1::Unavailable)?;
    let answer = platform.anchor_read(slot);
    super::counters::probe_storage(platform)
        .map_err(KagemushaWalletProviderErrorV1::Unavailable)?;
    match answer {
        KagemushaWalletProbeV1::Present(bytes) => KagemushaWalletAnchorV1::decode(&bytes)
            .map(Some)
            .map_err(|_| KagemushaWalletProviderErrorV1::UnavailableCustodyData {
                object: "anchor",
            }),
        KagemushaWalletProbeV1::Absent => Ok(None),
        KagemushaWalletProbeV1::Unavailable(reason) => {
            Err(KagemushaWalletProviderErrorV1::Unavailable(reason))
        }
    }
}

/// Require that the platform's anchor policy is the one `slot_anchor` recorded at enrollment.
///
/// # Errors
///
/// `UnavailableCustodyData("anchor policy")` on a mismatch; nothing is inferred from it.
pub(super) fn kagemusha_wallet_require_anchor_policy_v1<P: KagemushaWalletPlatformV1 + ?Sized>(
    platform: &P,
    slot_anchor: KagemushaWalletAnchorPolicyV1,
) -> Result<(), KagemushaWalletProviderErrorV1> {
    if platform.anchor_policy() != slot_anchor {
        return Err(KagemushaWalletProviderErrorV1::UnavailableCustodyData {
            object: "anchor policy",
        });
    }
    Ok(())
}

/// Compare the anchor of the current marker's slot with that marker (selection rule, §3).
///
/// The marker's recorded anchor kind decides whether the check applies; the platform must
/// agree with it.
///
/// # Errors
///
/// `LostCustody(AnchorMissing | RolledBack | AnchorMismatch)` for the three loss cases,
/// `UnavailableCustodyData("anchor policy")` when the platform disagrees with the slot, and the
/// read errors of [`kagemusha_wallet_read_anchor_v1`]. Nothing is changed in any case.
pub(super) fn kagemusha_wallet_check_anchor_v1<P: KagemushaWalletPlatformV1 + ?Sized>(
    platform: &P,
    current: &KagemushaWalletMarkerRecordV1,
) -> Result<KagemushaWalletAnchorCheckV1, KagemushaWalletProviderErrorV1> {
    kagemusha_wallet_require_anchor_policy_v1(platform, current.anchor())?;
    if current.anchor() == KagemushaWalletAnchorPolicyV1::NotRequired {
        return Ok(KagemushaWalletAnchorCheckV1::NotRequired);
    }
    let Some(anchor) = kagemusha_wallet_read_anchor_v1(platform, current.slot())? else {
        return Err(KagemushaWalletProviderErrorV1::LostCustody(
            KagemushaWalletLostCustodyV1::AnchorMissing,
        ));
    };
    compare(&anchor, current)
}

fn compare(
    anchor: &KagemushaWalletAnchorV1,
    current: &KagemushaWalletMarkerRecordV1,
) -> Result<KagemushaWalletAnchorCheckV1, KagemushaWalletProviderErrorV1> {
    if !anchor.named || anchor.generation < current.generation() {
        return Ok(KagemushaWalletAnchorCheckV1::Lagging);
    }
    if anchor.generation > current.generation() {
        return Err(KagemushaWalletProviderErrorV1::LostCustody(
            KagemushaWalletLostCustodyV1::RolledBack,
        ));
    }
    if anchor.marker_file_digest != *current.marker_file_digest() {
        return Err(KagemushaWalletProviderErrorV1::LostCustody(
            KagemushaWalletLostCustodyV1::AnchorMismatch,
        ));
    }
    Ok(KagemushaWalletAnchorCheckV1::Current)
}

/// Create the `NONE` anchor of a new slot (E2; add-only). An existing `NONE` anchor (a retried
/// E2) requires an acknowledged exact update, since its earlier creation may be uncertain.
///
/// # Errors
///
/// `Invalid("anchor.exists")` when the slot already has a named anchor, `Unavailable` when the
/// keychain refuses (for example without a device passcode: enrollment is then refused) and
/// `Uncertain` when the mutation is not acknowledged; visible bytes never substitute for it.
pub(super) fn kagemusha_wallet_create_anchor_v1<P: KagemushaWalletPlatformV1 + ?Sized>(
    platform: &P,
    slot: &KagemushaWalletSlotIdV1,
) -> Result<(), KagemushaWalletProviderErrorV1> {
    if platform.anchor_policy() == KagemushaWalletAnchorPolicyV1::NotRequired {
        return Ok(());
    }
    let none = KagemushaWalletAnchorV1::none();
    // The anchor only follows custody observed just now (custody transaction fence).
    super::store::kagemusha_wallet_custody_fence_v1()
        .map_err(KagemushaWalletProviderErrorV1::Unavailable)?;
    match platform.anchor_create(slot, &none.encode()?) {
        KagemushaWalletPublishOutcomeV1::Published => Ok(()),
        KagemushaWalletPublishOutcomeV1::NotPublished(
            KagemushaWalletNotPublishedV1::DestinationExists,
        ) => match kagemusha_wallet_read_anchor_v1(platform, slot)? {
            Some(anchor) if anchor == none => acknowledge_update(platform, slot, &none),
            Some(_) => Err(KagemushaWalletProviderErrorV1::Invalid {
                field: "anchor.exists",
            }),
            None => Err(KagemushaWalletProviderErrorV1::Unavailable(
                super::platform::KagemushaWalletUnavailableV1::Busy,
            )),
        },
        KagemushaWalletPublishOutcomeV1::NotPublished(reason) => Err(not_published(reason)),
        KagemushaWalletPublishOutcomeV1::Uncertain(reason) => {
            Err(KagemushaWalletProviderErrorV1::Uncertain(reason))
        }
    }
}

/// Raise the anchor of a durable marker's slot to name that marker (E4, A6, A10, terminal
/// steps). An anchor already naming it requires an acknowledged exact update too: after
/// restart its visible bytes cannot establish whether an earlier mutation was acknowledged.
/// An anchor is never lowered.
///
/// The caller passes only a marker that is durable, so the anchor never names a marker that
/// could still be lost.
///
/// # Errors
///
/// `LostCustody` when the anchor is absent or ahead of `durable`, `Unavailable` when the
/// keychain refuses, `Uncertain` when an update is not acknowledged, and
/// the policy error of [`kagemusha_wallet_check_anchor_v1`].
pub(super) fn kagemusha_wallet_raise_anchor_v1<P: KagemushaWalletPlatformV1 + ?Sized>(
    platform: &P,
    durable: &KagemushaWalletMarkerRecordV1,
) -> Result<(), KagemushaWalletProviderErrorV1> {
    if kagemusha_wallet_check_anchor_v1(platform, durable)?
        == KagemushaWalletAnchorCheckV1::NotRequired
    {
        return Ok(());
    }
    acknowledge_update(
        platform,
        durable.slot(),
        &KagemushaWalletAnchorV1::naming(durable),
    )
}

/// Require one exact mutation acknowledgement. The caller reconciles an uncertain outcome
/// on its next attempt; neither an immediate nor a later read is a persistence barrier.
fn acknowledge_update<P: KagemushaWalletPlatformV1 + ?Sized>(
    platform: &P,
    slot: &KagemushaWalletSlotIdV1,
    target: &KagemushaWalletAnchorV1,
) -> Result<(), KagemushaWalletProviderErrorV1> {
    // The anchor only follows custody observed just now (custody transaction fence).
    super::store::kagemusha_wallet_custody_fence_v1()
        .map_err(KagemushaWalletProviderErrorV1::Unavailable)?;
    match platform.anchor_update(slot, &target.encode()?) {
        KagemushaWalletPublishOutcomeV1::Published => Ok(()),
        KagemushaWalletPublishOutcomeV1::NotPublished(reason) => Err(not_published(reason)),
        KagemushaWalletPublishOutcomeV1::Uncertain(reason) => {
            Err(KagemushaWalletProviderErrorV1::Uncertain(reason))
        }
    }
}

fn not_published(reason: KagemushaWalletNotPublishedV1) -> KagemushaWalletProviderErrorV1 {
    match reason {
        KagemushaWalletNotPublishedV1::Failed(reason) => {
            KagemushaWalletProviderErrorV1::Unavailable(reason)
        }
        KagemushaWalletNotPublishedV1::NoSpace => KagemushaWalletProviderErrorV1::NoSpace,
        _ => KagemushaWalletProviderErrorV1::Unavailable(
            super::platform::KagemushaWalletUnavailableV1::Busy,
        ),
    }
}

#[cfg(test)]
#[path = "anchor_tests.rs"]
mod tests;
