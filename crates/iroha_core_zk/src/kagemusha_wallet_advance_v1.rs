//! Stock-phone durable state provider (`Advance`) of the KAGEMUSHA wallet protocol V1.
//!
//! This module implements the provider contract of
//! `specs/kagemusha_single_design_proposal.md` §4 on a stock phone over the G1 objects of
//! `iroha_data_model::kagemusha::kagemusha_wallet_v1`, following the G2 design (revision 2):
//! custody files under one non-backup root, marker generations that select exactly one head,
//! frozen recovery capsules and completion records kept in redundant copies, retained results
//! by operation identity, and the hardware payment key that alone signs provider receipts. It
//! owns custody bytes and head selection; it never decides monetary validity, which belongs to
//! the state and proof owners (§9).
//!
//! # Layers
//!
//! - `platform`: the platform interface the provider needs — tri-state key, anchor and storage
//!   probes (`Present | Absent | Unavailable`, never inferring absence from an error), explicit
//!   write outcomes (`Published | NotPublished | Uncertain`), the boot identity, a
//!   sleep-inclusive monotonic clock, single-step filesystem operations, and the role-checked
//!   signer that freezes the hardware output with `kagemusha_wallet_freeze_signature_v1`.
//! - `store`: the durable store composing filesystem steps into create-new, paired,
//!   same-content-rewrite and removal primitives, its `std::fs` backend, and (tests and
//!   `test-utils`) a simulator with fault injection at every step and crash, restart and
//!   power-loss simulation.
//! - `layout`: custody root layout, strict names and directory preparation.
//! - `marker`: marker generations (Enrollment, Selected head, Released head bound to its
//!   completion digest, Terminal), generation ordering, selection of the highest generation,
//!   adoption, publication and retirement by name.
//! - `capsule` and `completion`: persistence of the G1 recovery capsule and completion record
//!   in boot-stamped envelopes, two copies each, with digest checks, repair from the surviving
//!   copy and fresh-inode adoption.
//! - `anchor`: the iOS rollback anchor `{generation, marker_file_digest}` kept in a
//!   passcode-bound keychain item, read inside protected-data brackets and raised only to a
//!   durable marker.
//! - `retained`: released results by operation identity, permanent tombstones, pruning and
//!   capsule collection after the state owner's acknowledgement.
//! - `provider`: the exclusive provider handle over one custody root, slot status and the
//!   per-slot cache of verified markers.
//! - `reconcile`: startup and pre-operation reconciliation (design R0-R10).
//! - `advance`: `Advance` (design A0-A12) with capacity reservation and the ballast.
//! - `enrollment`: slot intent, payment-key generation gate, the generation-0 marker and the
//!   retained credential request (design E2-E6).
//! - `terminal`: abandonment of an unused enrollment and deliberate custody deletion.
//!
//! The provider is generic over the frozen objects it persists
//! ([`KagemushaWalletFrozenFrameV1`], [`KagemushaWalletAdvanceCapsuleV1`],
//! [`KagemushaWalletCompletionFrameV1`]) and over the receipt body it signs: the state owner
//! supplies the exact `receipt-body` transcript and assembles the released output
//! ([`KagemushaWalletTransitionOwnerV1`]). A transition design that adds further proofs or
//! retained objects (for example a background lineage proof after `Advance`) therefore
//! changes the frame and transition owners, not this provider; nothing here assumes one proof
//! per transition.
//!
//! # Custody root
//!
//! One non-backup root per app (Android: credential-encrypted `noBackupFilesDir`; iPhone:
//! `Library/Application Support`, mode `0700`) holds `root.norito` (the sentinel, published
//! last and rewritten on every open), `lock`, `canary` (iOS), `probe/`, `ballast.bin` and
//! `slots/<slot>/` with `intent.norito`, `markers/`, `capsules/`, `completion/`, `ops/` and
//! the state owner's `archive/` (see `layout`).
//!
//! # Marker rule
//!
//! Each `Advance` writes a Selected marker (the commit point), signs the receipt only while
//! that Selected marker is current on disk, persists the completion record in two copies and
//! then publishes a Released marker binding the record's digest. Under a Released marker a
//! missing record is `CompletionLost`, never a second signature. The highest durable marker
//! alone selects the head: staging without a marker is discarded, and a payment key or journal
//! without any marker is lost custody. Every marker carries the slot's anchor kind, so the iOS
//! rollback anchor is checked whenever the slot was enrolled with one; on iPhone that
//! passcode-bound keychain anchor refuses restored older custody files as rollbacks.
//!
//! # Public surface
//!
//! Outside this module only the provider ([`KagemushaWalletProviderV1`]), its request,
//! outcome, status and error types (marker records are read-only values), the platform and
//! filesystem traits and the `std::fs` backend are reachable. Marker publication, adoption and
//! retirement, Selected-marker capabilities, the durable store and the receipt signer are
//! private: a capability exists only for a marker published here or adopted after its exact
//! bytes were read back, the receipt signer re-reads that marker immediately before signing,
//! and the payment key's `key_sign` takes a preimage only the role-checked signers construct.
//!
//! # Durability doctrine
//!
//! A read, listing, lock or key-store error means **retry**, never absence, deletion or a zero
//! balance (§1.2). A write whose outcome is unknown is reported as such; the caller poisons
//! its handle and reconciles from disk. Lower marker generations are retired only after the
//! current marker is durable, and a missing completion under a Released marker is
//! `CompletionLost`, never a reason to sign again. Once a Selected marker is durable, the
//! operation is reported as performed (released or pending), never as failed.
//!
//! # Present scope
//!
//! Stages G2-A and G2-B: platform interface, store, layout, markers, capsules, completions,
//! the iOS anchor, retained results, reconciliation, `Advance`, enrollment and terminal
//! flows, exercised by crash matrices over the simulated filesystem (process crashes, power
//! loss with exhaustive survival subsets of unsynced directory operations, lost writebacks,
//! faults during recovery and platform faults); run them with
//! `cargo test -p iroha_core_zk --lib kagemusha_wallet_advance_v1`. Platform adapters (Android
//! Keystore and storage, iPhone Secure Enclave and keychain) and the bridge wiring are not
//! implemented yet, and nothing here has run on a phone.
// TODO(G2-bridge): JNI and C-vtable platform adapters and the exclusive per-process handle
// (one provider per process; revoke the handle after an uncertain dispatch).
// TODO(G2-S): the state owner's G1 transition owner (`assemble_output_v1`, receipt body from
// the credential), its archive under `slots/<slot>/archive/`, the E8 activation request and
// its acknowledgement-driven capsule collection.
// TODO(G2-iOS): Swift adapter (canary, `kern.bootsessionuuid`, keychain anchor) and device
// tests of keychain power-loss durability and the residual anchor window.
// TODO(G2-fs): typed descriptor-relative primitives in `iroha_fs` replace the path-based
// `std::fs` backend in `store`.

mod advance;
mod anchor;
mod capsule;
mod completion;
mod enrollment;
mod layout;
mod marker;
mod platform;
mod provider;
mod reconcile;
mod retained;
mod store;
mod terminal;

#[cfg(any(test, feature = "test-utils"))]
pub use self::store::{
    KagemushaWalletSimFaultV1, KagemushaWalletSimFsV1, KagemushaWalletSimLockV1,
    KagemushaWalletSimPowerLossV1, KagemushaWalletSimStagedFileV1, KagemushaWalletSimStepV1,
};
#[cfg(unix)]
pub use self::store::{KagemushaWalletStdFsLockV1, KagemushaWalletStdFsV1};
pub use self::{
    advance::{
        KAGEMUSHA_WALLET_CAPACITY_HEADROOM_BYTES_V1, KagemushaWalletAdvanceCapsuleV1,
        KagemushaWalletAdvanceOutcomeV1, KagemushaWalletAdvanceRequestV1,
        KagemushaWalletCapacityClassV1, KagemushaWalletExpectedHeadV1,
        KagemushaWalletNotPerformedV1, KagemushaWalletTransitionOwnerV1,
    },
    capsule::{KAGEMUSHA_WALLET_FROZEN_FILE_OVERHEAD_BYTES_V1, KagemushaWalletFrozenFrameV1},
    completion::KagemushaWalletCompletionFrameV1,
    enrollment::{
        KAGEMUSHA_WALLET_ENROLLMENT_REQUEST_MAX_BYTES_V1, KagemushaWalletChallengeLivenessV1,
        KagemushaWalletEnrollmentRecordV1, KagemushaWalletEnrollmentStepV1,
        KagemushaWalletIntentV1,
    },
    layout::{
        KAGEMUSHA_WALLET_BALLAST_BYTES_V1, KAGEMUSHA_WALLET_ROOT_DIR_NAME_V1,
        KagemushaWalletCustodyDirV1, KagemushaWalletEntryNameV1, KagemushaWalletRootSentinelV1,
        KagemushaWalletSlotIdV1,
    },
    marker::{KagemushaWalletMarkerPhaseV1, KagemushaWalletMarkerRecordV1},
    platform::{
        KAGEMUSHA_WALLET_PAYMENT_KEY_SIGNING_DOMAINS_V1, KagemushaWalletAnchorPolicyV1,
        KagemushaWalletEntryKindV1, KagemushaWalletFsV1, KagemushaWalletKeyGenerationRequestV1,
        KagemushaWalletKeyGenerationV1, KagemushaWalletKeyProfileV1, KagemushaWalletListedEntryV1,
        KagemushaWalletNotPublishedV1, KagemushaWalletPlatformSignatureV1,
        KagemushaWalletPlatformV1, KagemushaWalletProbeV1, KagemushaWalletPublishOutcomeV1,
        KagemushaWalletReadV1, KagemushaWalletRemoveOutcomeV1, KagemushaWalletSignErrorV1,
        KagemushaWalletSigningMessageV1, KagemushaWalletUnavailableV1,
        kagemusha_wallet_boot_id_from_text_v1, kagemusha_wallet_native_boot_id_v1,
        kagemusha_wallet_native_monotonic_ms_v1, kagemusha_wallet_sign_role_v1,
    },
    provider::{
        KagemushaWalletProviderOptionsV1, KagemushaWalletProviderV1, KagemushaWalletSlotStatusV1,
    },
    reconcile::KagemushaWalletSlotAbandonReasonV1,
    retained::{
        KagemushaWalletLookupV1, KagemushaWalletRetainedStatusV1, KagemushaWalletRetainedV1,
        KagemushaWalletTombstoneV1,
    },
    terminal::KagemushaWalletDestructiveConfirmationV1,
};
// Tests reach every provider-private item through the module root; modules whose items are
// all re-exported above contribute nothing through these globs.
#[cfg(test)]
#[allow(unused_imports)]
use self::{
    advance::*, anchor::*, capsule::*, completion::*, enrollment::*, layout::*, marker::*,
    platform::*, provider::*, reconcile::*, retained::*, store::*, terminal::*,
};

use sha2::{Digest as _, Sha256};

/// Domain prefix of provider-local digests; these digests never leave the device.
pub const KAGEMUSHA_WALLET_PROVIDER_DIGEST_PREFIX_V1: &[u8] =
    b"iroha:kagemusha:wallet-provider:v1:";

/// Provider-local digest `SHA-256(prefix || label || 0x00 || LE64(len(body)) || body)`.
///
/// It is used for local envelopes only (for example `H("marker-file", envelope)`); every wire
/// digest is a G1 `kagemusha_wallet_digest_v1`.
#[must_use]
pub fn kagemusha_wallet_provider_digest_v1(label: &str, body: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(KAGEMUSHA_WALLET_PROVIDER_DIGEST_PREFIX_V1);
    hasher.update(label.as_bytes());
    hasher.update([0]);
    hasher.update(u64::try_from(body.len()).unwrap_or(u64::MAX).to_le_bytes());
    hasher.update(body);
    hasher.finalize().into()
}

/// Way custody is lost; shown to the user, never acted on destructively.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum KagemushaWalletLostCustodyV1 {
    /// A payment key exists for a slot without any marker.
    KeyWithoutMarker,
    /// Custody files exist without any marker.
    JournalWithoutMarker,
    /// iOS: marker files exist but the rollback anchor is definitively absent.
    AnchorMissing,
    /// iOS: the rollback anchor names a later generation than the files.
    RolledBack,
    /// iOS: the rollback anchor names this generation with another digest.
    AnchorMismatch,
    /// Every copy of a released completion record is missing or invalid.
    CompletionLost,
}

/// Error of the provider.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum KagemushaWalletProviderErrorV1 {
    /// Storage, the key store or the platform gave no definitive answer; retry.
    #[error("wallet custody unavailable: {0:?}")]
    Unavailable(KagemushaWalletUnavailableV1),
    /// A write's outcome is unknown; poison the handle and reconcile.
    #[error("wallet custody write outcome uncertain: {0:?}")]
    Uncertain(KagemushaWalletUnavailableV1),
    /// Not enough storage before any publication.
    #[error("insufficient custody storage")]
    NoSpace,
    /// The filesystem lacks create-new rename; there is no weaker fallback.
    #[error("custody filesystem lacks create-new rename")]
    NoReplaceUnsupported,
    /// The current marker or an object it binds is missing or invalid in every copy.
    #[error("custody data unavailable: {object}")]
    UnavailableCustodyData {
        /// Object kind.
        object: &'static str,
    },
    /// Custody is lost.
    #[error("custody lost: {0:?}")]
    LostCustody(KagemushaWalletLostCustodyV1),
    /// A custody directory holds an entry the provider never writes.
    #[error("unexpected entry in custody directory `{dir}`")]
    UnexpectedEntry {
        /// Directory label.
        dir: &'static str,
    },
    /// A caller-supplied value or transition is invalid.
    #[error("invalid wallet provider input `{field}`")]
    Invalid {
        /// Stable field label.
        field: &'static str,
    },
    /// The payment key is definitively absent or is not the marker's key. Shown to the user,
    /// re-evaluated on every reconcile and never acted on destructively.
    #[error("payment key lost")]
    KeyLost,
    /// The slot's custody is terminal (abandoned or deliberately deleted); operations are
    /// refused.
    #[error("wallet custody is terminal")]
    Terminal,
    /// The operation identity already has a selected head, a released result or a tombstone
    /// with other inputs; the retained operation is unaffected.
    #[error("operation identity already used: {retained:?}")]
    OperationIdConflict {
        /// What is retained for the operation identity.
        retained: KagemushaWalletRetainedStatusV1,
    },
}

/// Encode one canonical provider envelope within `max` bytes.
fn encode_envelope_v1<T: norito::NoritoSerialize>(
    value: &T,
    max: usize,
) -> Result<Vec<u8>, KagemushaWalletProviderErrorV1> {
    let bytes = norito::encode_canonical(value)
        .map_err(|_| KagemushaWalletProviderErrorV1::Invalid { field: "envelope" })?;
    if bytes.len() > max {
        return Err(KagemushaWalletProviderErrorV1::Invalid {
            field: "envelope size",
        });
    }
    Ok(bytes)
}

/// Decode one exact canonical provider envelope of at most `max` bytes.
fn decode_envelope_v1<T>(bytes: &[u8], max: usize) -> Result<T, KagemushaWalletProviderErrorV1>
where
    T: norito::NoritoSerialize,
    for<'de> T: norito::NoritoDeserialize<'de>,
{
    if bytes.len() > max {
        return Err(KagemushaWalletProviderErrorV1::Invalid {
            field: "envelope size",
        });
    }
    norito::decode_canonical_with_limits(bytes, norito::canonical_decode_limits(bytes.len()))
        .map_err(|_| KagemushaWalletProviderErrorV1::Invalid { field: "envelope" })
}

#[cfg(test)]
mod test_support;

#[cfg(test)]
mod crash_matrix_tests;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wallet_advance_v1_provider_digest_is_domain_separated() {
        let digest = kagemusha_wallet_provider_digest_v1("marker-file", b"body");
        let mut hasher = Sha256::new();
        hasher.update(b"iroha:kagemusha:wallet-provider:v1:marker-file\0");
        hasher.update(4_u64.to_le_bytes());
        hasher.update(b"body");
        let expected: [u8; 32] = hasher.finalize().into();
        assert_eq!(digest, expected);
        assert_ne!(
            digest,
            kagemusha_wallet_provider_digest_v1("marker-filf", b"body")
        );
        assert_ne!(
            digest,
            kagemusha_wallet_provider_digest_v1("marker-file", b"bodz")
        );
    }

    #[test]
    fn wallet_advance_v1_envelope_roundtrip_and_bounds() {
        let sentinel = KagemushaWalletRootSentinelV1 {
            version: 1,
            root_nonce: [7; 32],
        };
        let bytes = encode_envelope_v1(&sentinel, 1_024).expect("encode");
        let decoded: KagemushaWalletRootSentinelV1 =
            decode_envelope_v1(&bytes, 1_024).expect("decode");
        assert_eq!(decoded, sentinel);
        assert_eq!(
            encode_envelope_v1(&sentinel, bytes.len() - 1),
            Err(KagemushaWalletProviderErrorV1::Invalid {
                field: "envelope size"
            })
        );
        assert_eq!(
            decode_envelope_v1::<KagemushaWalletRootSentinelV1>(&bytes, bytes.len() - 1),
            Err(KagemushaWalletProviderErrorV1::Invalid {
                field: "envelope size"
            })
        );
        let mut trailing = bytes.clone();
        trailing.push(0);
        assert!(decode_envelope_v1::<KagemushaWalletRootSentinelV1>(&trailing, 1_024).is_err());
        let mut corrupt = bytes;
        let last = corrupt.len() - 1;
        corrupt[last] ^= 1;
        assert!(decode_envelope_v1::<KagemushaWalletRootSentinelV1>(&corrupt, 1_024).is_err());
    }
}
