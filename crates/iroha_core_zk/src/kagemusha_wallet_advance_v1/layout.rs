//! Custody root layout of the stock-phone Advance provider (G2 design rev 2 §2).
//!
//! One custody root per app holds every file the provider trusts:
//!
//! ```text
//! <root>/root.norito                     sentinel {version, root nonce}
//! <root>/lock                            exclusive flock; any lock error is Unavailable
//! <root>/canary                          iOS only: Complete-class protected-data probe
//! <root>/probe/                          scratch directory for the NOREPLACE probe
//! <root>/ballast.bin                     768 KiB random reserve (worst-case Advance)
//! <root>/slots/<slot:64x>/
//!     intent.norito, abandoned.norito    create-new only
//!     key-generation.norito              consumed fresh attempt, never grant authority
//!     enrollment.norito, credential-<n>.norito, abandonment.norito
//!     abandonment_selected.norito         exact retained signed-output selection
//!     markers/m-<gen:032x>.mk            marker generations (marker.rs)
//!     capsules/c-<gen:032x>-<digest:64x>.cap and .cap.r   (capsule.rs)
//!     completion/<op:64x>.cr and .cr.r                      (completion.rs)
//!     ops/<op:64x>.t                     permanent tombstones
//!     archive/                           owned by the state owner
//! ```
//!
//! Names are built and parsed only here. Parsers are strict (lowercase fixed-width hex,
//! exact suffixes), so one object never has two spellings and an unexpected entry is never
//! mistaken for a provider object. Staging files written by the store start with
//! [`KAGEMUSHA_WALLET_STAGING_PREFIX_V1`] and are never interpreted as custody data.
//!
//! The root sentinel is the commit point of the skeleton: `probe/` and `slots/` are created
//! and made durable first, and `root.norito` is published create-new last. A root without a
//! sentinel therefore never holds custody, and its (empty) skeleton directories are recreated
//! before the sentinel is published, because an existing directory entry may come from an
//! earlier attempt whose directory sync failed. Every open rewrites the sentinel to a fresh
//! inode (G2 design R3), and a sentinel without `slots/` is refused.

use super::{
    KagemushaWalletProviderErrorV1, decode_envelope_v1, encode_envelope_v1,
    platform::{
        KagemushaWalletEntryKindV1, KagemushaWalletFsV1, KagemushaWalletListedEntryV1,
        KagemushaWalletNotPublishedV1, KagemushaWalletPublishOutcomeV1, KagemushaWalletReadV1,
        KagemushaWalletUnavailableV1,
    },
    store::KagemushaWalletDurableStoreV1,
};
use rand::rand_core::TryRngCore as _;

/// Directory name of the custody root under the platform's no-backup directory.
pub const KAGEMUSHA_WALLET_ROOT_DIR_NAME_V1: &str = "kagemusha-wallet-v1";
/// Root sentinel file name.
pub const KAGEMUSHA_WALLET_ROOT_SENTINEL_NAME_V1: &str = "root.norito";
/// Exclusive lock file name.
pub const KAGEMUSHA_WALLET_LOCK_NAME_V1: &str = "lock";
/// iOS protected-data canary file name.
// The canary is created with FileProtectionType.complete by the Swift adapter.
pub const KAGEMUSHA_WALLET_CANARY_NAME_V1: &str = "canary";
/// Capacity ballast file name (written at enrollment, drawn and regrown by `advance.rs`).
pub const KAGEMUSHA_WALLET_BALLAST_NAME_V1: &str = "ballast.bin";
/// Ballast size: the worst-case Advance footprint, 768 KiB.
pub const KAGEMUSHA_WALLET_BALLAST_BYTES_V1: u64 = 768 * 1024;
/// NOREPLACE capability probe directory name.
pub const KAGEMUSHA_WALLET_PROBE_DIR_NAME_V1: &str = "probe";
/// Slot directory parent name.
pub const KAGEMUSHA_WALLET_SLOTS_DIR_NAME_V1: &str = "slots";
/// Enrollment intent file name (create-new only).
pub const KAGEMUSHA_WALLET_INTENT_NAME_V1: &str = "intent.norito";
/// Fresh enrollment generation-attempt record (create-new only; never authority).
pub const KAGEMUSHA_WALLET_KEY_GENERATION_ATTEMPT_NAME_V1: &str = "key-generation.norito";
/// Abandoned-slot file name (create-new only).
pub const KAGEMUSHA_WALLET_ABANDONED_NAME_V1: &str = "abandoned.norito";
/// Enrollment record file name.
pub const KAGEMUSHA_WALLET_ENROLLMENT_NAME_V1: &str = "enrollment.norito";
/// Retained signed Abandon control of an abandoned enrollment (create-new only).
pub const KAGEMUSHA_WALLET_ABANDONMENT_NAME_V1: &str = "abandonment.norito";
/// Exact selected Abandon output; retained independently of its original bytes.
pub(super) const KAGEMUSHA_WALLET_ABANDONMENT_SELECTION_NAME_V1: &str =
    "abandonment_selected.norito";
/// Marker generation directory name.
pub const KAGEMUSHA_WALLET_MARKERS_DIR_NAME_V1: &str = "markers";
/// Recovery capsule directory name.
pub const KAGEMUSHA_WALLET_CAPSULES_DIR_NAME_V1: &str = "capsules";
/// Completion record directory name.
pub const KAGEMUSHA_WALLET_COMPLETION_DIR_NAME_V1: &str = "completion";
/// Operation tombstone directory name.
pub const KAGEMUSHA_WALLET_OPS_DIR_NAME_V1: &str = "ops";
/// State-owner archive directory name.
pub const KAGEMUSHA_WALLET_ARCHIVE_DIR_NAME_V1: &str = "archive";
/// Prefix of every staging file the store creates; never custody data.
pub const KAGEMUSHA_WALLET_STAGING_PREFIX_V1: &str = ".tmp-";
/// Maximum length of one entry name.
pub const KAGEMUSHA_WALLET_ENTRY_NAME_MAX_BYTES_V1: usize = 128;
/// Maximum encoded root sentinel.
pub const KAGEMUSHA_WALLET_ROOT_SENTINEL_MAX_BYTES_V1: usize = 256;

const MARKER_PREFIX: &str = "m-";
const MARKER_SUFFIX: &str = ".mk";
const CAPSULE_PREFIX: &str = "c-";
const CAPSULE_SUFFIX: &str = ".cap";
const COMPLETION_SUFFIX: &str = ".cr";
const TOMBSTONE_SUFFIX: &str = ".t";
const REPLICA_SUFFIX: &str = ".r";
const CREDENTIAL_PREFIX: &str = "credential-";
const CREDENTIAL_SUFFIX: &str = ".norito";
const NOREPLACE_PROBE_NAME: &str = "noreplace.probe";

/// Whether `name` is an acceptable entry name: 1 to 128 bytes of `[a-z0-9._-]`, never `.`
/// or `..`.
#[must_use]
pub fn kagemusha_wallet_valid_entry_name_v1(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= KAGEMUSHA_WALLET_ENTRY_NAME_MAX_BYTES_V1
        && name != "."
        && name != ".."
        && name
            .bytes()
            .all(|byte| matches!(byte, b'a'..=b'z' | b'0'..=b'9' | b'.' | b'-' | b'_'))
}

/// Whether `name` is a staging file name produced by the store.
#[must_use]
pub fn kagemusha_wallet_is_staging_name_v1(name: &str) -> bool {
    name.strip_prefix(KAGEMUSHA_WALLET_STAGING_PREFIX_V1)
        .is_some_and(|rest| rest.len() == 32 && is_lower_hex(rest))
}

/// One validated entry name inside a custody directory.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct KagemushaWalletEntryNameV1(String);

impl KagemushaWalletEntryNameV1 {
    /// Validate `name` ([`kagemusha_wallet_valid_entry_name_v1`]).
    #[must_use]
    pub fn new(name: &str) -> Option<Self> {
        kagemusha_wallet_valid_entry_name_v1(name).then(|| Self(name.to_owned()))
    }

    /// The name.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    fn known(name: String) -> Self {
        debug_assert!(kagemusha_wallet_valid_entry_name_v1(&name));
        Self(name)
    }
}

/// One validated directory under the custody root, as path components.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct KagemushaWalletCustodyDirV1 {
    components: Vec<String>,
}

impl KagemushaWalletCustodyDirV1 {
    /// The custody root itself.
    #[must_use]
    pub fn root() -> Self {
        Self::default()
    }

    /// Child directory `name` of `self`.
    #[must_use]
    pub fn child(&self, name: &KagemushaWalletEntryNameV1) -> Self {
        let mut components = self.components.clone();
        components.push(name.0.clone());
        Self { components }
    }

    /// Path components relative to the custody root.
    #[must_use]
    pub fn components(&self) -> &[String] {
        &self.components
    }

    /// Stable label of the directory for diagnostics.
    #[must_use]
    pub fn label(&self) -> String {
        if self.components.is_empty() {
            ".".to_owned()
        } else {
            self.components.join("/")
        }
    }
}

/// Random 32-byte slot identity; one slot per enrollment attempt and payment key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct KagemushaWalletSlotIdV1(pub [u8; 32]);

impl KagemushaWalletSlotIdV1 {
    /// Generate a fresh nonzero slot identity from the operating-system RNG.
    ///
    /// # Errors
    ///
    /// Returns [`KagemushaWalletUnavailableV1::Platform`] when the RNG fails.
    pub fn generate() -> Result<Self, KagemushaWalletUnavailableV1> {
        let mut bytes = [0_u8; 32];
        rand::rngs::OsRng
            .try_fill_bytes(&mut bytes)
            .map_err(|_| KagemushaWalletUnavailableV1::Platform(0))?;
        if bytes == [0; 32] {
            return Err(KagemushaWalletUnavailableV1::Platform(0));
        }
        Ok(Self(bytes))
    }

    /// Lowercase hex directory name.
    #[must_use]
    pub fn dir_name(&self) -> KagemushaWalletEntryNameV1 {
        KagemushaWalletEntryNameV1::known(lower_hex(&self.0))
    }

    /// Parse a slot directory name.
    #[must_use]
    pub fn parse(name: &str) -> Option<Self> {
        let bytes = parse_hex_32(name)?;
        (bytes != [0; 32]).then_some(Self(bytes))
    }
}

/// Primary or replica copy of a redundant object.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum KagemushaWalletCopyV1 {
    /// Primary copy.
    Primary,
    /// Replica copy (`.r` suffix).
    Replica,
}

impl KagemushaWalletCopyV1 {
    /// Both copies, primary first.
    pub const BOTH: [Self; 2] = [Self::Primary, Self::Replica];

    fn suffix(self) -> &'static str {
        match self {
            Self::Primary => "",
            Self::Replica => REPLICA_SUFFIX,
        }
    }

    fn split(name: &str) -> (&str, Self) {
        match name.strip_suffix(REPLICA_SUFFIX) {
            Some(stem) => (stem, Self::Replica),
            None => (name, Self::Primary),
        }
    }
}

/// Parsed capsule file name.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct KagemushaWalletCapsuleNameV1 {
    /// Marker generation of the Selected marker that binds (or would bind) the capsule.
    pub selected_generation: u128,
    /// Full capsule digest.
    pub capsule_digest: [u8; 32],
    /// Copy.
    pub copy: KagemushaWalletCopyV1,
}

/// Parsed completion file name.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct KagemushaWalletCompletionNameV1 {
    /// Operation identity.
    pub operation_id: [u8; 32],
    /// Copy.
    pub copy: KagemushaWalletCopyV1,
}

/// `probe/`.
#[must_use]
pub fn kagemusha_wallet_probe_dir_v1() -> KagemushaWalletCustodyDirV1 {
    KagemushaWalletCustodyDirV1::root().child(&fixed(KAGEMUSHA_WALLET_PROBE_DIR_NAME_V1))
}

/// `slots/`.
#[must_use]
pub fn kagemusha_wallet_slots_dir_v1() -> KagemushaWalletCustodyDirV1 {
    KagemushaWalletCustodyDirV1::root().child(&fixed(KAGEMUSHA_WALLET_SLOTS_DIR_NAME_V1))
}

/// `slots/<slot>/`.
#[must_use]
pub fn kagemusha_wallet_slot_dir_v1(slot: &KagemushaWalletSlotIdV1) -> KagemushaWalletCustodyDirV1 {
    kagemusha_wallet_slots_dir_v1().child(&slot.dir_name())
}

/// `slots/<slot>/markers/`.
#[must_use]
pub fn kagemusha_wallet_markers_dir_v1(
    slot: &KagemushaWalletSlotIdV1,
) -> KagemushaWalletCustodyDirV1 {
    kagemusha_wallet_slot_dir_v1(slot).child(&fixed(KAGEMUSHA_WALLET_MARKERS_DIR_NAME_V1))
}

/// `slots/<slot>/capsules/`.
#[must_use]
pub fn kagemusha_wallet_capsules_dir_v1(
    slot: &KagemushaWalletSlotIdV1,
) -> KagemushaWalletCustodyDirV1 {
    kagemusha_wallet_slot_dir_v1(slot).child(&fixed(KAGEMUSHA_WALLET_CAPSULES_DIR_NAME_V1))
}

/// `slots/<slot>/completion/`.
#[must_use]
pub fn kagemusha_wallet_completion_dir_v1(
    slot: &KagemushaWalletSlotIdV1,
) -> KagemushaWalletCustodyDirV1 {
    kagemusha_wallet_slot_dir_v1(slot).child(&fixed(KAGEMUSHA_WALLET_COMPLETION_DIR_NAME_V1))
}

/// `slots/<slot>/ops/`.
#[must_use]
pub fn kagemusha_wallet_ops_dir_v1(slot: &KagemushaWalletSlotIdV1) -> KagemushaWalletCustodyDirV1 {
    kagemusha_wallet_slot_dir_v1(slot).child(&fixed(KAGEMUSHA_WALLET_OPS_DIR_NAME_V1))
}

/// `slots/<slot>/archive/`.
#[must_use]
pub fn kagemusha_wallet_archive_dir_v1(
    slot: &KagemushaWalletSlotIdV1,
) -> KagemushaWalletCustodyDirV1 {
    kagemusha_wallet_slot_dir_v1(slot).child(&fixed(KAGEMUSHA_WALLET_ARCHIVE_DIR_NAME_V1))
}

/// Fixed file name `name` (one of this module's constants).
#[must_use]
pub fn kagemusha_wallet_fixed_name_v1(name: &'static str) -> KagemushaWalletEntryNameV1 {
    fixed(name)
}

/// `credential-<n>.norito`.
#[must_use]
pub fn kagemusha_wallet_credential_name_v1(index: u32) -> KagemushaWalletEntryNameV1 {
    KagemushaWalletEntryNameV1::known(format!("{CREDENTIAL_PREFIX}{index}{CREDENTIAL_SUFFIX}"))
}

/// Parse `credential-<n>.norito` with a canonical decimal index.
#[must_use]
pub fn kagemusha_wallet_parse_credential_name_v1(name: &str) -> Option<u32> {
    let digits = name
        .strip_prefix(CREDENTIAL_PREFIX)?
        .strip_suffix(CREDENTIAL_SUFFIX)?;
    let canonical = !digits.is_empty()
        && digits.bytes().all(|byte| byte.is_ascii_digit())
        && (digits == "0" || !digits.starts_with('0'));
    if !canonical {
        return None;
    }
    digits.parse().ok()
}

/// `m-<generation:032x>.mk`.
#[must_use]
pub fn kagemusha_wallet_marker_name_v1(generation: u128) -> KagemushaWalletEntryNameV1 {
    KagemushaWalletEntryNameV1::known(format!("{MARKER_PREFIX}{generation:032x}{MARKER_SUFFIX}"))
}

/// Parse a marker file name into its generation.
#[must_use]
pub fn kagemusha_wallet_parse_marker_name_v1(name: &str) -> Option<u128> {
    let digits = name
        .strip_prefix(MARKER_PREFIX)?
        .strip_suffix(MARKER_SUFFIX)?;
    parse_hex_u128(digits)
}

/// `c-<generation:032x>-<digest:64x>.cap` with the copy's suffix.
#[must_use]
pub fn kagemusha_wallet_capsule_name_v1(
    selected_generation: u128,
    capsule_digest: &[u8; 32],
    copy: KagemushaWalletCopyV1,
) -> KagemushaWalletEntryNameV1 {
    KagemushaWalletEntryNameV1::known(format!(
        "{CAPSULE_PREFIX}{selected_generation:032x}-{}{CAPSULE_SUFFIX}{}",
        lower_hex(capsule_digest),
        copy.suffix()
    ))
}

/// Parse a capsule file name.
#[must_use]
pub fn kagemusha_wallet_parse_capsule_name_v1(name: &str) -> Option<KagemushaWalletCapsuleNameV1> {
    let (stem, copy) = KagemushaWalletCopyV1::split(name);
    let body = stem
        .strip_prefix(CAPSULE_PREFIX)?
        .strip_suffix(CAPSULE_SUFFIX)?;
    let (generation, digest) = body.split_once('-')?;
    Some(KagemushaWalletCapsuleNameV1 {
        selected_generation: parse_hex_u128(generation)?,
        capsule_digest: parse_hex_32(digest)?,
        copy,
    })
}

/// `<operation_id:64x>.cr` with the copy's suffix.
#[must_use]
pub fn kagemusha_wallet_completion_name_v1(
    operation_id: &[u8; 32],
    copy: KagemushaWalletCopyV1,
) -> KagemushaWalletEntryNameV1 {
    KagemushaWalletEntryNameV1::known(format!(
        "{}{COMPLETION_SUFFIX}{}",
        lower_hex(operation_id),
        copy.suffix()
    ))
}

/// Parse a completion file name.
#[must_use]
pub fn kagemusha_wallet_parse_completion_name_v1(
    name: &str,
) -> Option<KagemushaWalletCompletionNameV1> {
    let (stem, copy) = KagemushaWalletCopyV1::split(name);
    Some(KagemushaWalletCompletionNameV1 {
        operation_id: parse_hex_32(stem.strip_suffix(COMPLETION_SUFFIX)?)?,
        copy,
    })
}

/// `<operation_id:64x>.t`.
#[must_use]
pub fn kagemusha_wallet_tombstone_name_v1(operation_id: &[u8; 32]) -> KagemushaWalletEntryNameV1 {
    KagemushaWalletEntryNameV1::known(format!("{}{TOMBSTONE_SUFFIX}", lower_hex(operation_id)))
}

/// Parse a tombstone file name.
#[must_use]
pub fn kagemusha_wallet_parse_tombstone_name_v1(name: &str) -> Option<[u8; 32]> {
    parse_hex_32(name.strip_suffix(TOMBSTONE_SUFFIX)?)
}

/// Root sentinel identifying a custody root written by this provider.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, norito::Encode, norito::Decode, norito::NoritoSchema,
)]
#[norito_schema(name = "iroha_core::zk::kagemusha_wallet_advance_v1::RootSentinelV1")]
pub struct KagemushaWalletRootSentinelV1 {
    /// Layout version; exactly 1.
    pub version: u16,
    /// Random nonzero nonce naming this custody root.
    pub root_nonce: [u8; 32],
}

impl KagemushaWalletRootSentinelV1 {
    /// Canonical bytes.
    ///
    /// # Errors
    ///
    /// Rejects an invalid sentinel.
    pub fn encode(&self) -> Result<Vec<u8>, KagemushaWalletProviderErrorV1> {
        self.validate()?;
        encode_envelope_v1(self, KAGEMUSHA_WALLET_ROOT_SENTINEL_MAX_BYTES_V1)
    }

    /// Decode and validate canonical bytes.
    ///
    /// # Errors
    ///
    /// Rejects oversized, noncanonical or invalid bytes.
    pub fn decode(bytes: &[u8]) -> Result<Self, KagemushaWalletProviderErrorV1> {
        let sentinel: Self =
            decode_envelope_v1(bytes, KAGEMUSHA_WALLET_ROOT_SENTINEL_MAX_BYTES_V1)?;
        sentinel.validate()?;
        Ok(sentinel)
    }

    fn validate(&self) -> Result<(), KagemushaWalletProviderErrorV1> {
        if self.version != 1 || self.root_nonce == [0; 32] {
            return Err(KagemushaWalletProviderErrorV1::Invalid {
                field: "root_sentinel",
            });
        }
        Ok(())
    }
}

/// Read the root sentinel: `None` only when the file is definitively absent.
///
/// # Errors
///
/// Returns `Unavailable` on any read error and `UnavailableCustodyData` for an oversized or
/// invalid sentinel; never treats an error as absence.
pub fn kagemusha_wallet_read_root_sentinel_v1<F: KagemushaWalletFsV1>(
    store: &KagemushaWalletDurableStoreV1<F>,
) -> Result<Option<KagemushaWalletRootSentinelV1>, KagemushaWalletProviderErrorV1> {
    match store.read(
        &KagemushaWalletCustodyDirV1::root(),
        &fixed(KAGEMUSHA_WALLET_ROOT_SENTINEL_NAME_V1),
        KAGEMUSHA_WALLET_ROOT_SENTINEL_MAX_BYTES_V1,
    ) {
        KagemushaWalletReadV1::Present(bytes) => KagemushaWalletRootSentinelV1::decode(&bytes)
            .map(Some)
            .map_err(|_| KagemushaWalletProviderErrorV1::UnavailableCustodyData {
                object: "root sentinel",
            }),
        KagemushaWalletReadV1::Absent => Ok(None),
        KagemushaWalletReadV1::Oversized => {
            Err(KagemushaWalletProviderErrorV1::UnavailableCustodyData {
                object: "root sentinel",
            })
        }
        KagemushaWalletReadV1::Unavailable(reason) => {
            Err(KagemushaWalletProviderErrorV1::Unavailable(reason))
        }
    }
}

/// Prepare a custody root (design R0, §2).
///
/// With a sentinel: rewrite it to a fresh inode (drawing the ballast once on a full disk), so
/// a sentinel whose first publication was unacknowledged becomes durable; require `slots/`,
/// which was durable before the sentinel was published; recreate the scratch `probe/` when
/// missing.
///
/// Without a sentinel the root holds no custody (the caller has refused any other entry):
/// empty `probe/` and `slots/` left by an interrupted attempt are removed and recreated so
/// their entries become durable, and the sentinel is published create-new last.
///
/// # Errors
///
/// The read errors of [`kagemusha_wallet_read_root_sentinel_v1`];
/// `UnavailableCustodyData("custody root")` for a sentinel without `slots/`, or for skeleton
/// directories that are not empty without a sentinel; `UnexpectedEntry` for a skeleton name
/// that is not a directory; and the write errors of [`kagemusha_wallet_require_published_v1`].
pub(super) fn kagemusha_wallet_prepare_root_v1<F: KagemushaWalletFsV1>(
    store: &KagemushaWalletDurableStoreV1<F>,
) -> Result<KagemushaWalletRootSentinelV1, KagemushaWalletProviderErrorV1> {
    let root = KagemushaWalletCustodyDirV1::root();
    let sentinel_name = fixed(KAGEMUSHA_WALLET_ROOT_SENTINEL_NAME_V1);
    if let Some(sentinel) = kagemusha_wallet_read_root_sentinel_v1(store)? {
        let bytes = sentinel.encode()?;
        let adopted = match store.rewrite_same(&root, &sentinel_name, &bytes) {
            KagemushaWalletPublishOutcomeV1::NotPublished(
                KagemushaWalletNotPublishedV1::NoSpace,
            ) if kagemusha_wallet_draw_ballast_v1(store)? => {
                store.rewrite_same(&root, &sentinel_name, &bytes)
            }
            outcome => outcome,
        };
        kagemusha_wallet_require_published_v1(adopted)?;
        match root_entry_kind(store, KAGEMUSHA_WALLET_SLOTS_DIR_NAME_V1)? {
            Some(KagemushaWalletEntryKindV1::Directory) => {}
            Some(_) => return Err(KagemushaWalletProviderErrorV1::UnexpectedEntry { dir: "." }),
            None => {
                return Err(KagemushaWalletProviderErrorV1::UnavailableCustodyData {
                    object: "custody root",
                });
            }
        }
        kagemusha_wallet_ensure_dir_v1(store, &root, &fixed(KAGEMUSHA_WALLET_PROBE_DIR_NAME_V1))?;
        return Ok(sentinel);
    }
    for name in [
        KAGEMUSHA_WALLET_PROBE_DIR_NAME_V1,
        KAGEMUSHA_WALLET_SLOTS_DIR_NAME_V1,
    ] {
        let name = fixed(name);
        match root_entry_kind(store, name.as_str())? {
            None => {}
            Some(KagemushaWalletEntryKindV1::Directory) => {
                let child = root.child(&name);
                let entries = kagemusha_wallet_list_dir_v1(store, &child)?.unwrap_or_default();
                if !entries.is_empty() {
                    return Err(KagemushaWalletProviderErrorV1::UnavailableCustodyData {
                        object: "custody root",
                    });
                }
                kagemusha_wallet_require_removed_v1(store.remove_dir(&root, &name))?;
            }
            Some(_) => return Err(KagemushaWalletProviderErrorV1::UnexpectedEntry { dir: "." }),
        }
        match store.create_dir(&root, &name) {
            // Removed above under the lock: a concurrent change.
            KagemushaWalletPublishOutcomeV1::NotPublished(
                KagemushaWalletNotPublishedV1::DestinationExists,
            ) => {
                return Err(KagemushaWalletProviderErrorV1::Unavailable(
                    KagemushaWalletUnavailableV1::Busy,
                ));
            }
            outcome => kagemusha_wallet_require_published_v1(outcome)?,
        }
    }
    let mut root_nonce = [0_u8; 32];
    rand::rngs::OsRng
        .try_fill_bytes(&mut root_nonce)
        .map_err(|_| {
            KagemushaWalletProviderErrorV1::Unavailable(KagemushaWalletUnavailableV1::Platform(0))
        })?;
    let sentinel = KagemushaWalletRootSentinelV1 {
        version: 1,
        root_nonce,
    };
    match store.write_new(&root, &sentinel_name, &sentinel.encode()?) {
        // The lock is held: another sentinel appearing now is a concurrent change.
        KagemushaWalletPublishOutcomeV1::NotPublished(
            KagemushaWalletNotPublishedV1::DestinationExists,
        ) => Err(KagemushaWalletProviderErrorV1::Unavailable(
            KagemushaWalletUnavailableV1::Busy,
        )),
        outcome => kagemusha_wallet_require_published_v1(outcome).map(|()| sentinel),
    }
}

/// Kind of root entry `name`, `None` when absent.
fn root_entry_kind<F: KagemushaWalletFsV1>(
    store: &KagemushaWalletDurableStoreV1<F>,
    name: &str,
) -> Result<Option<KagemushaWalletEntryKindV1>, KagemushaWalletProviderErrorV1> {
    Ok(
        kagemusha_wallet_list_dir_v1(store, &KagemushaWalletCustodyDirV1::root())?
            .unwrap_or_default()
            .into_iter()
            .find(|entry| entry.name == name)
            .map(|entry| entry.kind),
    )
}

/// Remove the capacity ballast so a write that found the disk full can be retried; `false`
/// when no ballast exists.
///
/// # Errors
///
/// `Unavailable` when the root cannot be listed and the removal errors.
pub(super) fn kagemusha_wallet_draw_ballast_v1<F: KagemushaWalletFsV1>(
    store: &KagemushaWalletDurableStoreV1<F>,
) -> Result<bool, KagemushaWalletProviderErrorV1> {
    let present = kagemusha_wallet_list_dir_v1(store, &KagemushaWalletCustodyDirV1::root())?
        .unwrap_or_default()
        .iter()
        .any(|entry| {
            entry.kind == KagemushaWalletEntryKindV1::File
                && entry.name == KAGEMUSHA_WALLET_BALLAST_NAME_V1
        });
    if !present {
        return Ok(false);
    }
    kagemusha_wallet_require_removed_v1(store.remove_file(
        &KagemushaWalletCustodyDirV1::root(),
        &fixed(KAGEMUSHA_WALLET_BALLAST_NAME_V1),
    ))?;
    Ok(true)
}

/// Durably create directory `name` in `parent`, or adopt an existing directory of that name.
///
/// An existing entry is adopted only when the listing shows a directory; any other kind is
/// refused instead of failing every later operation with `ENOTDIR`.
///
/// # Errors
///
/// `UnexpectedEntry` for an existing non-directory, `Unavailable(Busy)` when the entry vanished
/// concurrently, and the write errors of [`kagemusha_wallet_require_dir_v1`].
pub(super) fn kagemusha_wallet_ensure_dir_v1<F: KagemushaWalletFsV1>(
    store: &KagemushaWalletDurableStoreV1<F>,
    parent: &KagemushaWalletCustodyDirV1,
    name: &KagemushaWalletEntryNameV1,
) -> Result<(), KagemushaWalletProviderErrorV1> {
    let outcome = store.create_dir(parent, name);
    if outcome
        != KagemushaWalletPublishOutcomeV1::NotPublished(
            KagemushaWalletNotPublishedV1::DestinationExists,
        )
    {
        return kagemusha_wallet_require_dir_v1(outcome);
    }
    let kind = kagemusha_wallet_list_dir_v1(store, parent)?
        .unwrap_or_default()
        .into_iter()
        .find(|entry| entry.name == name.as_str())
        .map(|entry| entry.kind);
    match kind {
        Some(KagemushaWalletEntryKindV1::Directory) => Ok(()),
        Some(_) => Err(KagemushaWalletProviderErrorV1::UnexpectedEntry {
            dir: dir_label(parent),
        }),
        None => Err(KagemushaWalletProviderErrorV1::Unavailable(
            KagemushaWalletUnavailableV1::Busy,
        )),
    }
}

/// Stable diagnostic label of a provider directory.
fn dir_label(dir: &KagemushaWalletCustodyDirV1) -> &'static str {
    match dir.components() {
        [] => ".",
        [first] if first == KAGEMUSHA_WALLET_SLOTS_DIR_NAME_V1 => "slots",
        [first] if first == KAGEMUSHA_WALLET_PROBE_DIR_NAME_V1 => "probe",
        [_, _] => "slot",
        _ => "custody",
    }
}

/// Durably create the directories of `slot`: the slot itself, then `markers/`, `capsules/`,
/// `completion/`, `ops/` and `archive/`. Directories that hold custody entries are preserved;
/// an existing directory that holds nothing but staging files is removed and created again so
/// its entry is durable; an existing entry of another kind is refused.
///
/// # Errors
///
/// Returns the errors of `kagemusha_wallet_ensure_durable_dir_v1` (listing, staging removal,
/// directory removal and [`kagemusha_wallet_ensure_dir_v1`]).
pub(super) fn kagemusha_wallet_prepare_slot_dirs_v1<F: KagemushaWalletFsV1>(
    store: &KagemushaWalletDurableStoreV1<F>,
    slot: &KagemushaWalletSlotIdV1,
) -> Result<(), KagemushaWalletProviderErrorV1> {
    kagemusha_wallet_ensure_durable_dir_v1(
        store,
        &kagemusha_wallet_slots_dir_v1(),
        &slot.dir_name(),
    )?;
    let slot_dir = kagemusha_wallet_slot_dir_v1(slot);
    for name in [
        KAGEMUSHA_WALLET_MARKERS_DIR_NAME_V1,
        KAGEMUSHA_WALLET_CAPSULES_DIR_NAME_V1,
        KAGEMUSHA_WALLET_COMPLETION_DIR_NAME_V1,
        KAGEMUSHA_WALLET_OPS_DIR_NAME_V1,
        KAGEMUSHA_WALLET_ARCHIVE_DIR_NAME_V1,
    ] {
        kagemusha_wallet_ensure_durable_dir_v1(store, &slot_dir, &fixed(name))?;
    }
    Ok(())
}

/// Ensure the directory `name` under `parent` exists with a durable entry before anything is
/// placed in it. An existing directory that holds nothing but staging files may be the visible
/// residue of a creation whose parent synchronization was lost (a later sync of the parent is
/// then vacuous): its staging files are discarded, and it is removed and created again. A
/// directory that holds custody entries was only ever filled after its creation was durable.
fn kagemusha_wallet_ensure_durable_dir_v1<F: KagemushaWalletFsV1>(
    store: &KagemushaWalletDurableStoreV1<F>,
    parent: &KagemushaWalletCustodyDirV1,
    name: &KagemushaWalletEntryNameV1,
) -> Result<(), KagemushaWalletProviderErrorV1> {
    let dir = parent.child(name);
    if let Some(entries) = kagemusha_wallet_list_dir_v1(store, &dir)? {
        if entries.iter().all(|entry| {
            entry.kind == KagemushaWalletEntryKindV1::File
                && kagemusha_wallet_is_staging_name_v1(&entry.name)
        }) {
            store.remove_staging(&dir)?;
            kagemusha_wallet_require_removed_v1(store.remove_dir(parent, name))?;
        }
    }
    kagemusha_wallet_ensure_dir_v1(store, parent, name)
}

/// List the slot identities under `slots/`; `None` when `slots/` is definitively absent.
///
/// # Errors
///
/// Returns `Unavailable` on a listing error and `UnexpectedEntry` for any entry that is not a
/// slot directory or a staging file.
pub fn kagemusha_wallet_list_slots_v1<F: KagemushaWalletFsV1>(
    store: &KagemushaWalletDurableStoreV1<F>,
) -> Result<Option<Vec<KagemushaWalletSlotIdV1>>, KagemushaWalletProviderErrorV1> {
    let Some(entries) = kagemusha_wallet_list_dir_v1(store, &kagemusha_wallet_slots_dir_v1())?
    else {
        return Ok(None);
    };
    let mut slots = Vec::with_capacity(entries.len());
    for entry in entries {
        match (entry.kind, KagemushaWalletSlotIdV1::parse(&entry.name)) {
            (KagemushaWalletEntryKindV1::Directory, Some(slot)) => slots.push(slot),
            (KagemushaWalletEntryKindV1::File, None)
                if kagemusha_wallet_is_staging_name_v1(&entry.name) => {}
            _ => {
                return Err(KagemushaWalletProviderErrorV1::UnexpectedEntry { dir: "slots" });
            }
        }
    }
    Ok(Some(slots))
}

/// List `dir`: `None` only when the directory is definitively absent.
///
/// # Errors
///
/// Returns `Unavailable` on any listing error.
pub fn kagemusha_wallet_list_dir_v1<F: KagemushaWalletFsV1>(
    store: &KagemushaWalletDurableStoreV1<F>,
    dir: &KagemushaWalletCustodyDirV1,
) -> Result<Option<Vec<KagemushaWalletListedEntryV1>>, KagemushaWalletProviderErrorV1> {
    store.list(dir).into_result()
}

/// Map a directory creation outcome: created and existing directories are both durable.
///
/// # Errors
///
/// Returns `Uncertain`, `NoSpace`, `NoReplaceUnsupported` or `Unavailable` for the
/// corresponding outcomes.
pub fn kagemusha_wallet_require_dir_v1(
    outcome: KagemushaWalletPublishOutcomeV1,
) -> Result<(), KagemushaWalletProviderErrorV1> {
    match outcome {
        KagemushaWalletPublishOutcomeV1::NotPublished(
            KagemushaWalletNotPublishedV1::DestinationExists,
        ) => Ok(()),
        other => kagemusha_wallet_require_published_v1(other),
    }
}

/// Require a durable publication.
///
/// # Errors
///
/// `Uncertain` for an unknown outcome, `NoSpace`, `NoReplaceUnsupported`, `Unavailable(Busy)`
/// for a destination that unexpectedly exists or is absent, `Invalid` for refused content and
/// `Unavailable` for every other failure.
pub fn kagemusha_wallet_require_published_v1(
    outcome: KagemushaWalletPublishOutcomeV1,
) -> Result<(), KagemushaWalletProviderErrorV1> {
    match outcome {
        KagemushaWalletPublishOutcomeV1::Published => Ok(()),
        KagemushaWalletPublishOutcomeV1::Uncertain(reason) => {
            Err(KagemushaWalletProviderErrorV1::Uncertain(reason))
        }
        KagemushaWalletPublishOutcomeV1::NotPublished(reason) => Err(match reason {
            KagemushaWalletNotPublishedV1::NoSpace => KagemushaWalletProviderErrorV1::NoSpace,
            KagemushaWalletNotPublishedV1::NoReplaceUnsupported => {
                KagemushaWalletProviderErrorV1::NoReplaceUnsupported
            }
            KagemushaWalletNotPublishedV1::DestinationExists
            | KagemushaWalletNotPublishedV1::DestinationAbsent => {
                KagemushaWalletProviderErrorV1::Unavailable(KagemushaWalletUnavailableV1::Busy)
            }
            KagemushaWalletNotPublishedV1::ContentMismatch => {
                KagemushaWalletProviderErrorV1::Invalid {
                    field: "rewrite content",
                }
            }
            KagemushaWalletNotPublishedV1::Failed(reason) => {
                KagemushaWalletProviderErrorV1::Unavailable(reason)
            }
        }),
    }
}

/// Run the NOREPLACE capability probe in `probe/` (enrollment step E2).
///
/// # Errors
///
/// `NoReplaceUnsupported` only when the filesystem refuses create-new rename or silently
/// replaces; `NoSpace` when the disk is full (a capacity retry, never the permanent
/// diagnostic); the write errors of [`kagemusha_wallet_require_published_v1`] otherwise.
pub(super) fn kagemusha_wallet_probe_noreplace_v1<F: KagemushaWalletFsV1>(
    store: &KagemushaWalletDurableStoreV1<F>,
) -> Result<(), KagemushaWalletProviderErrorV1> {
    let dir = kagemusha_wallet_probe_dir_v1();
    kagemusha_wallet_ensure_dir_v1(
        store,
        &KagemushaWalletCustodyDirV1::root(),
        &fixed(KAGEMUSHA_WALLET_PROBE_DIR_NAME_V1),
    )?;
    let name = fixed(NOREPLACE_PROBE_NAME);
    kagemusha_wallet_require_removed_v1(store.remove_file(&dir, &name))?;
    kagemusha_wallet_require_published_v1(store.write_new(&dir, &name, b"first"))?;
    match store.write_new(&dir, &name, b"second") {
        KagemushaWalletPublishOutcomeV1::NotPublished(
            KagemushaWalletNotPublishedV1::DestinationExists,
        ) => {}
        // The second name replaced the first: the filesystem ignores the flag.
        KagemushaWalletPublishOutcomeV1::Published => {
            return Err(KagemushaWalletProviderErrorV1::NoReplaceUnsupported);
        }
        KagemushaWalletPublishOutcomeV1::NotPublished(
            KagemushaWalletNotPublishedV1::NoReplaceUnsupported,
        ) => return Err(KagemushaWalletProviderErrorV1::NoReplaceUnsupported),
        KagemushaWalletPublishOutcomeV1::NotPublished(KagemushaWalletNotPublishedV1::NoSpace) => {
            return Err(KagemushaWalletProviderErrorV1::NoSpace);
        }
        KagemushaWalletPublishOutcomeV1::Uncertain(reason) => {
            return Err(KagemushaWalletProviderErrorV1::Uncertain(reason));
        }
        KagemushaWalletPublishOutcomeV1::NotPublished(KagemushaWalletNotPublishedV1::Failed(
            reason,
        )) => return Err(KagemushaWalletProviderErrorV1::Unavailable(reason)),
        // A create-new write never compares content or requires a destination.
        KagemushaWalletPublishOutcomeV1::NotPublished(
            KagemushaWalletNotPublishedV1::DestinationAbsent
            | KagemushaWalletNotPublishedV1::ContentMismatch,
        ) => {
            return Err(KagemushaWalletProviderErrorV1::Unavailable(
                KagemushaWalletUnavailableV1::Busy,
            ));
        }
    }
    kagemusha_wallet_require_removed_v1(store.remove_file(&dir, &name))
}

/// Require a durable removal.
///
/// # Errors
///
/// `Unavailable` when nothing was removed and `Uncertain` for an unknown outcome.
pub fn kagemusha_wallet_require_removed_v1(
    outcome: super::platform::KagemushaWalletRemoveOutcomeV1,
) -> Result<(), KagemushaWalletProviderErrorV1> {
    match outcome {
        super::platform::KagemushaWalletRemoveOutcomeV1::Removed => Ok(()),
        super::platform::KagemushaWalletRemoveOutcomeV1::NotRemoved(reason) => {
            Err(KagemushaWalletProviderErrorV1::Unavailable(reason))
        }
        super::platform::KagemushaWalletRemoveOutcomeV1::Uncertain(reason) => {
            Err(KagemushaWalletProviderErrorV1::Uncertain(reason))
        }
    }
}

fn fixed(name: &'static str) -> KagemushaWalletEntryNameV1 {
    KagemushaWalletEntryNameV1::known(name.to_owned())
}

fn is_lower_hex(text: &str) -> bool {
    text.bytes()
        .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
}

fn parse_hex_u128(text: &str) -> Option<u128> {
    if text.len() != 32 || !is_lower_hex(text) {
        return None;
    }
    u128::from_str_radix(text, 16).ok()
}

fn parse_hex_32(text: &str) -> Option<[u8; 32]> {
    if text.len() != 64 || !is_lower_hex(text) {
        return None;
    }
    let mut bytes = [0_u8; 32];
    for (byte, pair) in bytes.iter_mut().zip(text.as_bytes().chunks_exact(2)) {
        *byte = (hex_value(pair[0])? << 4) | hex_value(pair[1])?;
    }
    Some(bytes)
}

fn hex_value(digit: u8) -> Option<u8> {
    match digit {
        b'0'..=b'9' => Some(digit - b'0'),
        b'a'..=b'f' => Some(digit - b'a' + 10),
        _ => None,
    }
}

/// Lowercase hex of `bytes`.
pub(super) fn lower_hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut text = String::with_capacity(bytes.len().saturating_mul(2));
    for byte in bytes {
        text.push(char::from(DIGITS[usize::from(byte >> 4)]));
        text.push(char::from(DIGITS[usize::from(byte & 0x0f)]));
    }
    text
}

#[cfg(test)]
#[path = "layout_tests.rs"]
mod tests;
