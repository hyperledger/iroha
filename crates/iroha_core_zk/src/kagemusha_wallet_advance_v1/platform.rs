//! Platform interface the Advance provider needs (G2 design rev 2 §§1, 2; spec §§2.3, 4.2).
//!
//! Kotlin and Swift implement only key probe/generate/sign/delete, the iOS anchor item,
//! storage state and the custody root path; everything else is Rust. Three rules hold for
//! every method here:
//!
//! - **Tri-state answers.** A probe answers `Present`, `Absent` or `Unavailable(reason)`.
//!   `Absent` is a definitive answer of a trusted OS (for files, `ENOENT` only; for keys,
//!   Android `KeyStore.getKey() == null` or iOS `errSecItemNotFound` inside a bracketed
//!   protected-data check). Every other error is `Unavailable` and is never read as
//!   absence: no deletion, generation, discard or loss classification follows from it.
//! - **Explicit write outcomes.** A durable write is `Published`, `NotPublished(reason)` (the
//!   name does not hold the new bytes) or `Uncertain(reason)` (it may; reconcile decides).
//!   An error after a rename is never reported as `NotPublished`.
//! - **One role-checked signer.** The hardware payment key signs only through
//!   `kagemusha_wallet_sign_receipt_body_v1` (module-private; it needs a Selected-marker
//!   capability and re-reads that marker on disk immediately before signing) and
//!   [`kagemusha_wallet_sign_role_v1`] (which refuses the receipt roles). The platform's
//!   [`KagemushaWalletPlatformV1::key_sign`] takes a [`KagemushaWalletSigningMessageV1`] that only
//!   these signers can construct, so code holding a platform object cannot reach the key with
//!   arbitrary bytes through this trait. The raw signer output is frozen with
//!   `kagemusha_wallet_freeze_signature_v1`: normalized to low S and verified under the
//!   marker's payment key before any byte is written.

use std::io;

use iroha_data_model::kagemusha::{
    KagemushaDevicePublicKeyV1, KagemushaDeviceSignatureV1, KagemushaWalletSignerOutputV1,
    KagemushaWalletSigningDomainV1, kagemusha_wallet_freeze_signature_v1,
    kagemusha_wallet_signing_message_v1,
};

use super::{
    KagemushaWalletProviderErrorV1,
    layout::{KagemushaWalletCustodyDirV1, KagemushaWalletSlotIdV1},
    marker::KagemushaWalletSelectedCapabilityV1,
    store::KagemushaWalletDurableStoreV1,
};

// ---------------------------------------------------------------------------------------
// Tri-state answers
// ---------------------------------------------------------------------------------------

/// Reason a platform, key-store or storage answer is not definitive. Never absence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum KagemushaWalletUnavailableV1 {
    /// Protected storage or the key store is locked.
    Locked,
    /// The device has not been unlocked since boot.
    BeforeFirstUnlock,
    /// Another opener holds the custody lock, or a concurrent change was observed.
    Busy,
    /// An I/O error; the raw OS error code, or 0 when none is available.
    Io(i32),
    /// A platform API error with its platform code.
    Platform(i32),
    /// The key exists but refused to sign, or its output did not verify.
    KeyUnusable,
    /// The platform reports the key as permanently invalidated.
    PermanentlyInvalidated,
}

impl KagemushaWalletUnavailableV1 {
    /// Reason for an I/O error.
    #[must_use]
    pub fn from_io(error: &io::Error) -> Self {
        match error.kind() {
            io::ErrorKind::WouldBlock => Self::Busy,
            _ => Self::Io(error.raw_os_error().unwrap_or(0)),
        }
    }
}

/// Tri-state platform answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum KagemushaWalletProbeV1<T> {
    /// The object exists.
    Present(T),
    /// The trusted OS definitively reported that the object does not exist.
    Absent,
    /// No definitive answer; retry. Never absence.
    Unavailable(KagemushaWalletUnavailableV1),
}

impl<T> KagemushaWalletProbeV1<T> {
    /// `Ok(Some)` for `Present`, `Ok(None)` for `Absent`, `Err(Unavailable)` otherwise.
    ///
    /// # Errors
    ///
    /// Returns [`KagemushaWalletProviderErrorV1::Unavailable`] for an unavailable answer.
    pub fn into_result(self) -> Result<Option<T>, KagemushaWalletProviderErrorV1> {
        match self {
            Self::Present(value) => Ok(Some(value)),
            Self::Absent => Ok(None),
            Self::Unavailable(reason) => Err(KagemushaWalletProviderErrorV1::Unavailable(reason)),
        }
    }

    /// Map a present value.
    pub fn map<U>(self, map: impl FnOnce(T) -> U) -> KagemushaWalletProbeV1<U> {
        match self {
            Self::Present(value) => KagemushaWalletProbeV1::Present(map(value)),
            Self::Absent => KagemushaWalletProbeV1::Absent,
            Self::Unavailable(reason) => KagemushaWalletProbeV1::Unavailable(reason),
        }
    }
}

/// Bounded read of one custody file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KagemushaWalletReadV1 {
    /// The complete file, within the bound.
    Present(Vec<u8>),
    /// The trusted OS reported that the name does not exist.
    Absent,
    /// The file is larger than the bound: present but never a valid object.
    Oversized,
    /// No definitive answer; retry. Never absence.
    Unavailable(KagemushaWalletUnavailableV1),
}

/// Kind of one listed directory entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum KagemushaWalletEntryKindV1 {
    /// Regular file.
    File,
    /// Directory.
    Directory,
    /// Anything else, including symbolic links.
    Other,
}

/// One entry of a complete directory listing.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct KagemushaWalletListedEntryV1 {
    /// Entry name (UTF-8; a non-UTF-8 name fails the listing).
    pub name: String,
    /// Entry kind.
    pub kind: KagemushaWalletEntryKindV1,
}

// ---------------------------------------------------------------------------------------
// Durable write outcomes
// ---------------------------------------------------------------------------------------

/// Why a durable write did not publish its bytes; the destination name does not hold them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum KagemushaWalletNotPublishedV1 {
    /// A create-new rename found the destination already present (`EEXIST`).
    DestinationExists,
    /// A same-content rewrite found no destination.
    DestinationAbsent,
    /// A same-content rewrite found different bytes at the destination.
    ContentMismatch,
    /// The filesystem is full before any rename.
    NoSpace,
    /// The filesystem lacks create-new rename (`ENOSYS`, `EINVAL`, `ENOTSUP`).
    NoReplaceUnsupported,
    /// Another definitive failure before or at the rename.
    Failed(KagemushaWalletUnavailableV1),
}

/// Outcome of one durable publication.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum KagemushaWalletPublishOutcomeV1 {
    /// The name holds the new bytes; data, rename and parent directory are synced.
    Published,
    /// The name does not hold the new bytes.
    NotPublished(KagemushaWalletNotPublishedV1),
    /// The name may or may not hold the new bytes, or they may not be durable. The caller
    /// poisons its handle and reconciles from disk.
    Uncertain(KagemushaWalletUnavailableV1),
}

/// Outcome of one durable removal.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum KagemushaWalletRemoveOutcomeV1 {
    /// The name is absent and the parent directory is synced.
    Removed,
    /// The name was not removed.
    NotRemoved(KagemushaWalletUnavailableV1),
    /// The removal may or may not be durable.
    Uncertain(KagemushaWalletUnavailableV1),
}

// ---------------------------------------------------------------------------------------
// Raw filesystem steps
// ---------------------------------------------------------------------------------------

/// Single-step filesystem operations under one custody root, without durability policy.
///
/// The durable store (`store.rs`) composes these steps into create-new, rewrite and removal
/// primitives with explicit outcomes. The production implementation is `std::fs`; the
/// simulator keeps visible and durable state separately and injects faults at every step.
/// Directory and entry names are validated by `layout.rs` before they reach this trait.
pub trait KagemushaWalletFsV1 {
    /// Open handle of a staging file.
    type StagedFile;
    /// Held exclusive custody lock; released on drop.
    type Lock;

    /// Create `name` in `dir` exclusively (`O_CREAT | O_EXCL`), mode `0600`.
    ///
    /// # Errors
    ///
    /// Returns the OS error, `AlreadyExists` when `name` exists.
    fn create_new(
        &self,
        dir: &KagemushaWalletCustodyDirV1,
        name: &str,
    ) -> io::Result<Self::StagedFile>;
    /// Append `bytes` to a staging file.
    ///
    /// # Errors
    ///
    /// Returns the OS error; some bytes may have been written.
    fn write_all(&self, file: &mut Self::StagedFile, bytes: &[u8]) -> io::Result<()>;
    /// Sync a staging file's data and metadata (`File::sync_all`: `fsync` on Android,
    /// `F_FULLFSYNC` on Apple).
    ///
    /// # Errors
    ///
    /// Returns the OS error; durability is then unknown.
    fn sync_staged(&self, file: &Self::StagedFile) -> io::Result<()>;
    /// Open and sync an existing file by name.
    ///
    /// # Errors
    ///
    /// Returns the OS error.
    fn sync_named(&self, dir: &KagemushaWalletCustodyDirV1, name: &str) -> io::Result<()>;
    /// Rename `from` to `to` in `dir` only if `to` does not exist (`RENAME_NOREPLACE`).
    ///
    /// # Errors
    ///
    /// `AlreadyExists` when `to` exists; `Unsupported`/`InvalidInput` when the filesystem
    /// lacks create-new rename; otherwise the OS error.
    fn rename_noreplace(
        &self,
        dir: &KagemushaWalletCustodyDirV1,
        from: &str,
        to: &str,
    ) -> io::Result<()>;
    /// Rename `from` to `to` in `dir`, atomically replacing `to`.
    ///
    /// # Errors
    ///
    /// Returns the OS error.
    fn rename_replace(
        &self,
        dir: &KagemushaWalletCustodyDirV1,
        from: &str,
        to: &str,
    ) -> io::Result<()>;
    /// Unlink `name` in `dir`.
    ///
    /// # Errors
    ///
    /// Returns the OS error, `NotFound` when `name` is absent.
    fn unlink(&self, dir: &KagemushaWalletCustodyDirV1, name: &str) -> io::Result<()>;
    /// Sync directory `dir` (`File::sync_all` on the directory).
    ///
    /// # Errors
    ///
    /// Returns the OS error.
    fn sync_dir(&self, dir: &KagemushaWalletCustodyDirV1) -> io::Result<()>;
    /// Create directory `name` in `parent`, mode `0700`.
    ///
    /// # Errors
    ///
    /// Returns the OS error, `AlreadyExists` when `name` exists.
    fn mkdir(&self, parent: &KagemushaWalletCustodyDirV1, name: &str) -> io::Result<()>;
    /// Remove the empty directory `name` in `parent` (`rmdir`; never recursive).
    ///
    /// # Errors
    ///
    /// Returns the OS error: `NotFound` when absent, `DirectoryNotEmpty` when it holds entries,
    /// `NotADirectory` for another kind.
    fn remove_dir(&self, parent: &KagemushaWalletCustodyDirV1, name: &str) -> io::Result<()>;
    /// Read at most `limit` bytes of regular file `name`.
    ///
    /// # Errors
    ///
    /// Returns the OS error, `NotFound` when `name` is absent; a non-regular file is an error.
    fn read(
        &self,
        dir: &KagemushaWalletCustodyDirV1,
        name: &str,
        limit: usize,
    ) -> io::Result<Vec<u8>>;
    /// List every entry of `dir`.
    ///
    /// # Errors
    ///
    /// Returns the OS error, `NotFound` when `dir` is absent; any entry error, non-UTF-8 name
    /// or type error fails the whole listing.
    fn list(
        &self,
        dir: &KagemushaWalletCustodyDirV1,
    ) -> io::Result<Vec<KagemushaWalletListedEntryV1>>;
    /// Bytes available to this app on the custody filesystem (`statvfs`).
    ///
    /// # Errors
    ///
    /// Returns the OS error.
    fn available_bytes(&self) -> io::Result<u64>;
    /// Take the exclusive custody lock without blocking (`flock(LOCK_EX | LOCK_NB)`).
    ///
    /// # Errors
    ///
    /// `WouldBlock` when another opener holds it; otherwise the OS error.
    fn try_lock(&self) -> io::Result<Self::Lock>;
    /// A fresh staging name (`.tmp-` and 32 lowercase hex digits).
    fn staging_name(&self) -> String;
}

// ---------------------------------------------------------------------------------------
// Keys, anchor, storage state, boot and clock
// ---------------------------------------------------------------------------------------

/// Raw P-256 signer output returned by the platform, before it is frozen.
// The fixed 64-byte raw form stays inline; this is a short-lived signer handoff value, as for
// the G1 `KagemushaWalletSignerOutputV1`.
#[allow(variant_size_differences)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KagemushaWalletPlatformSignatureV1 {
    /// Strict DER (Android Keystore `SHA256withECDSA`, `CryptoKit` `derRepresentation`).
    Der(Vec<u8>),
    /// Fixed-width `r || s` (`CryptoKit` `rawRepresentation`).
    Raw([u8; 64]),
}

impl KagemushaWalletPlatformSignatureV1 {
    /// Borrow as the G1 signer output.
    #[must_use]
    pub fn as_signer_output(&self) -> KagemushaWalletSignerOutputV1<'_> {
        match self {
            Self::Der(der) => KagemushaWalletSignerOutputV1::Der(der),
            Self::Raw(raw) => KagemushaWalletSignerOutputV1::Raw(*raw),
        }
    }
}

/// Outcome of a payment-key generation request.
// The 65-byte public key stays inline; this is a short-lived platform handoff value.
#[allow(variant_size_differences)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KagemushaWalletKeyGenerationV1 {
    /// A new key was generated under the slot's alias.
    Generated(KagemushaDevicePublicKeyV1),
    /// An entry already exists; the platform never replaces it.
    AlreadyPresent,
    /// The outcome is unknown; probe again before acting.
    Unavailable(KagemushaWalletUnavailableV1),
}

/// Hardware key policy of one enrollment, taken from the issuer's enrollment policy and kept
/// in the slot's intent, so a resumed enrollment generates under the same policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum KagemushaWalletKeyProfileV1 {
    /// The platform's dedicated secure element only: Android StrongBox (a
    /// `StrongBoxUnavailableException` refuses enrollment); iPhone Secure Enclave.
    SecureElement,
    /// Android StrongBox when available, otherwise the TEE; iPhone Secure Enclave. A TEE key
    /// is generated only while the slot's probe is still definitively absent.
    SecureElementOrTee,
}

impl KagemushaWalletKeyProfileV1 {
    /// Stored tag.
    #[must_use]
    pub const fn tag(self) -> u8 {
        match self {
            Self::SecureElement => 1,
            Self::SecureElementOrTee => 2,
        }
    }

    /// Profile of a stored tag.
    #[must_use]
    pub const fn from_tag(tag: u8) -> Option<Self> {
        match tag {
            1 => Some(Self::SecureElement),
            2 => Some(Self::SecureElementOrTee),
            _ => None,
        }
    }
}

/// What a payment-key generation must bind (design E3; spec §2.2).
///
/// Bridge mapping. Android (JNI): `KeyGenParameterSpec.Builder(alias, PURPOSE_SIGN)` with
/// secp256r1, `DIGEST_SHA256`, `setAttestationChallenge(challenge_digest)`,
/// `setIsStrongBoxBacked(true)` and, for [`KagemushaWalletKeyProfileV1::SecureElementOrTee`]
/// only, a TEE retry after `StrongBoxUnavailableException`; never any user-authentication,
/// unlocked-device, usage-count or confirmation option. iPhone (C vtable): a Secure Enclave
/// P-256 signing key with `.privateKeyUsage`; the challenge digest is the App Attest
/// `clientDataHash` used at E5. The alias or keychain account is derived from the slot
/// (`kgm-w1-<slot hex>`), so the slot identity is the key handle.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct KagemushaWalletKeyGenerationRequestV1 {
    /// Issuer challenge digest the platform attestation must carry.
    pub challenge_digest: [u8; 32],
    /// Hardware key policy.
    pub profile: KagemushaWalletKeyProfileV1,
}

/// Whether the platform keeps a rollback anchor outside the custody files.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum KagemushaWalletAnchorPolicyV1 {
    /// No anchor (Android: the backup set is empty and keys never leave the device).
    NotRequired,
    /// iOS `kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly` keychain anchor.
    Keychain,
}

impl KagemushaWalletAnchorPolicyV1 {
    /// Stored tag: 0 none, 1 keychain.
    #[must_use]
    pub const fn tag(self) -> u8 {
        match self {
            Self::NotRequired => 0,
            Self::Keychain => 1,
        }
    }

    /// Policy of a stored tag.
    #[must_use]
    pub const fn from_tag(tag: u8) -> Option<Self> {
        match tag {
            0 => Some(Self::NotRequired),
            1 => Some(Self::Keychain),
            _ => None,
        }
    }
}

/// Exact 32-byte signing message handed to [`KagemushaWalletPlatformV1::key_sign`].
///
/// Only the provider's role-checked signers construct it. A receipt requires a current
/// Selected marker; other bodies require a permitted payment-key signing domain. The domain
/// is explicit context for the platform adapter, never an additional byte in the message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KagemushaWalletSigningMessageV1<'a> {
    domain: KagemushaWalletSigningDomainV1,
    bytes: &'a [u8; 32],
}

impl KagemushaWalletSigningMessageV1<'_> {
    /// The canonical `P_bytes(domain, transcript)` message. The platform signs
    /// `SHA-256(bytes)` with its ordinary ECDSA-P256-SHA256 API.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; 32] {
        self.bytes
    }

    /// Authenticated signing context, carried separately from the exact message bytes.
    #[must_use]
    pub const fn domain(&self) -> KagemushaWalletSigningDomainV1 {
        self.domain
    }
}

/// Platform services the provider needs. Implementations must never replace an existing
/// key or anchor entry and must never report an error as absence.
// The anchor value codec and the selection checks against it are in `anchor.rs`.
// TODO(G2-bridge): JNI and C-vtable adapters implement this trait for Kotlin and Swift.
pub trait KagemushaWalletPlatformV1: Send + Sync {
    /// Probe the payment key of `slot`.
    fn key_probe(
        &self,
        slot: &KagemushaWalletSlotIdV1,
    ) -> KagemushaWalletProbeV1<KagemushaDevicePublicKeyV1>;

    /// Generate the payment key of `slot` under `request` (attestation challenge and hardware
    /// policy). Called only after a definitive `Absent` probe in the state "intent, no marker,
    /// not abandoned"; never replaces an entry.
    fn key_generate(
        &self,
        slot: &KagemushaWalletSlotIdV1,
        request: &KagemushaWalletKeyGenerationRequestV1,
    ) -> KagemushaWalletKeyGenerationV1;

    /// Sign the exact 32 bytes of `message` with ECDSA-P256-SHA256 and the payment key of
    /// `slot`. Only the role-checked signers construct this handoff; the domain is context
    /// for the adapter and must not be prepended to, or substituted for, these bytes.
    ///
    /// # Errors
    ///
    /// Returns the platform's reason; the provider never falls back to another key.
    fn key_sign(
        &self,
        slot: &KagemushaWalletSlotIdV1,
        message: KagemushaWalletSigningMessageV1<'_>,
    ) -> Result<KagemushaWalletPlatformSignatureV1, KagemushaWalletUnavailableV1>;

    /// Delete the payment key of `slot` (custody deletion step D3 only).
    fn key_delete(&self, slot: &KagemushaWalletSlotIdV1) -> KagemushaWalletRemoveOutcomeV1;

    /// Anchor policy of this platform. Required, with no default: an Apple adapter that
    /// omitted it would silently skip rollback detection. The policy chosen at enrollment is
    /// also recorded in every marker of the slot, and a mismatch refuses the slot.
    fn anchor_policy(&self) -> KagemushaWalletAnchorPolicyV1;

    /// Add the anchor item of `slot` (add-only).
    fn anchor_create(
        &self,
        _slot: &KagemushaWalletSlotIdV1,
        _value: &[u8],
    ) -> KagemushaWalletPublishOutcomeV1 {
        KagemushaWalletPublishOutcomeV1::NotPublished(KagemushaWalletNotPublishedV1::Failed(
            KagemushaWalletUnavailableV1::Platform(0),
        ))
    }

    /// Read the anchor item of `slot`.
    fn anchor_read(&self, _slot: &KagemushaWalletSlotIdV1) -> KagemushaWalletProbeV1<Vec<u8>> {
        KagemushaWalletProbeV1::Unavailable(KagemushaWalletUnavailableV1::Platform(0))
    }

    /// Update the anchor item of `slot`; after an uncertain update the caller re-reads it.
    fn anchor_update(
        &self,
        _slot: &KagemushaWalletSlotIdV1,
        _value: &[u8],
    ) -> KagemushaWalletPublishOutcomeV1 {
        KagemushaWalletPublishOutcomeV1::NotPublished(KagemushaWalletNotPublishedV1::Failed(
            KagemushaWalletUnavailableV1::Platform(0),
        ))
    }

    /// Whether protected storage is available now (Android `UserManager.isUserUnlocked`;
    /// iOS: the Complete-class canary is readable).
    ///
    /// # Errors
    ///
    /// Returns the reason storage is unavailable.
    fn storage_state(&self) -> Result<(), KagemushaWalletUnavailableV1>;

    /// Identity of the current boot session.
    ///
    /// # Errors
    ///
    /// Returns the reason it cannot be read; callers then treat every file as written in the
    /// current boot.
    fn boot_id(&self) -> Result<[u8; 32], KagemushaWalletUnavailableV1> {
        kagemusha_wallet_native_boot_id_v1()
    }

    /// Sleep-inclusive monotonic milliseconds (`CLOCK_BOOTTIME`, Mach continuous time).
    ///
    /// # Errors
    ///
    /// Returns the reason the clock cannot be read.
    fn monotonic_ms(&self) -> Result<u64, KagemushaWalletUnavailableV1> {
        kagemusha_wallet_native_monotonic_ms_v1()
    }
}

/// Boot stamp written into custody envelopes: the current boot identity, or zero when it
/// cannot be read (a zero stamp is always treated as the current boot).
#[must_use]
pub fn kagemusha_wallet_boot_stamp_v1(
    current_boot: &Result<[u8; 32], KagemushaWalletUnavailableV1>,
) -> [u8; 32] {
    current_boot.as_ref().copied().unwrap_or([0; 32])
}

/// Whether a file stamped `written_boot_id` may have been written in the current boot.
///
/// A file read back in a later boot was durable; a file of the current boot, of an unknown
/// boot (zero stamp) or read while the boot identity is unavailable is treated as current
/// (G2 design R3: Linux reports a writeback error only once).
#[must_use]
pub fn kagemusha_wallet_written_this_boot_v1(
    written_boot_id: &[u8; 32],
    current_boot: &Result<[u8; 32], KagemushaWalletUnavailableV1>,
) -> bool {
    match current_boot {
        Ok(current) => *written_boot_id == [0; 32] || written_boot_id == current,
        Err(_) => true,
    }
}

/// Native boot identity: SHA-256 of Linux/Android `/proc/sys/kernel/random/boot_id`.
///
/// # Errors
///
/// Returns `Io` when the file cannot be read or is malformed, and `Platform(0)` on targets
/// whose adapter must supply the boot identity (Apple: `kern.bootsessionuuid`).
pub fn kagemusha_wallet_native_boot_id_v1() -> Result<[u8; 32], KagemushaWalletUnavailableV1> {
    #[cfg(any(target_os = "linux", target_os = "android"))]
    {
        let text = std::fs::read_to_string("/proc/sys/kernel/random/boot_id")
            .map_err(|error| KagemushaWalletUnavailableV1::from_io(&error))?;
        kagemusha_wallet_boot_id_from_text_v1(&text)
    }
    #[cfg(not(any(target_os = "linux", target_os = "android")))]
    {
        // TODO(G2-iOS): the Swift adapter supplies `kern.bootsessionuuid` via `boot_id`.
        Err(KagemushaWalletUnavailableV1::Platform(0))
    }
}

/// Boot identity of one textual boot UUID: `H("boot-id", trimmed UUID)`.
///
/// # Errors
///
/// Returns `Io(0)` unless the trimmed text is a 36-character hyphenated UUID.
pub fn kagemusha_wallet_boot_id_from_text_v1(
    text: &str,
) -> Result<[u8; 32], KagemushaWalletUnavailableV1> {
    let uuid = text.trim();
    let well_formed = uuid.len() == 36
        && uuid.bytes().enumerate().all(|(index, byte)| {
            if matches!(index, 8 | 13 | 18 | 23) {
                byte == b'-'
            } else {
                byte.is_ascii_hexdigit()
            }
        });
    if !well_formed {
        return Err(KagemushaWalletUnavailableV1::Io(0));
    }
    Ok(super::kagemusha_wallet_provider_digest_v1(
        "boot-id",
        uuid.to_ascii_lowercase().as_bytes(),
    ))
}

/// Native sleep-inclusive monotonic milliseconds.
///
/// # Errors
///
/// Returns `Platform(0)` when the native continuous clock is unavailable.
pub fn kagemusha_wallet_native_monotonic_ms_v1() -> Result<u64, KagemushaWalletUnavailableV1> {
    let nanos = iroha_primitives::time::native_continuous_clock_nanos()
        .map_err(|_| KagemushaWalletUnavailableV1::Platform(0))?;
    u64::try_from(nanos / 1_000_000).map_err(|_| KagemushaWalletUnavailableV1::Platform(0))
}

// ---------------------------------------------------------------------------------------
// Role-checked signer
// ---------------------------------------------------------------------------------------

/// Why the role-checked signer produced no signature.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum KagemushaWalletSignErrorV1 {
    /// The platform could not sign; retry. The operation stays Selected and pending.
    #[error("payment key unavailable: {0:?}")]
    Unavailable(KagemushaWalletUnavailableV1),
    /// The signer output is malformed or does not verify under the marker's payment key.
    #[error("payment key output did not verify")]
    KeyUnusable,
    /// The role is not a payment-key role, or is the receipt role outside a capability.
    #[error("role not permitted for the payment key")]
    RoleNotPermitted,
    /// The body does not have the exact transcript length of its signing domain.
    #[error("signing transcript length does not match its domain")]
    InvalidTranscript,
    /// The capability's Selected marker is no longer current on disk, or the marker could not
    /// be read; the key was not reached.
    #[error("receipt capability not current: {0}")]
    Custody(KagemushaWalletProviderErrorV1),
}

impl From<KagemushaWalletSignErrorV1> for KagemushaWalletProviderErrorV1 {
    fn from(error: KagemushaWalletSignErrorV1) -> Self {
        match error {
            KagemushaWalletSignErrorV1::Unavailable(reason) => Self::Unavailable(reason),
            KagemushaWalletSignErrorV1::KeyUnusable => {
                Self::Unavailable(KagemushaWalletUnavailableV1::KeyUnusable)
            }
            KagemushaWalletSignErrorV1::RoleNotPermitted => Self::Invalid {
                field: "signer role",
            },
            KagemushaWalletSignErrorV1::InvalidTranscript => Self::Invalid {
                field: "signer transcript",
            },
            KagemushaWalletSignErrorV1::Custody(error) => error,
        }
    }
}

/// Signing domains the payment key may use outside a provider receipt (spec §2.3).
pub const KAGEMUSHA_WALLET_PAYMENT_KEY_SIGNING_DOMAINS_V1: [KagemushaWalletSigningDomainV1; 6] = [
    KagemushaWalletSigningDomainV1::Offer,
    KagemushaWalletSigningDomainV1::Request,
    KagemushaWalletSigningDomainV1::SessionControl,
    KagemushaWalletSigningDomainV1::LedgerControl,
    KagemushaWalletSigningDomainV1::RenewalChallenge,
    KagemushaWalletSigningDomainV1::RenewalKeyBinding,
];

/// Sign one provider receipt body under a durable Selected-marker capability (A7).
///
/// The capability's marker is re-read from `store` immediately before the key is reached, so a
/// capability kept after its marker was superseded (or derived from a marker that is not on
/// disk) never signs. `receipt_body` is the exact 338-byte canonical receipt transcript;
/// the transition owner derives it from the capsule whose digest the capability binds. The platform signs the exact `P_bytes(kgwrcpt1, receipt_body)` message;
/// `kagemusha_wallet_freeze_signature_v1` verifies its output under the capability's key.
///
/// # Errors
///
/// `Custody` when the marker is no longer current or cannot be read, `Unavailable` when the
/// platform cannot sign, `InvalidTranscript` for a wrong body length, and `KeyUnusable` when
/// its output is malformed or does not verify; nothing is written in any case.
pub(super) fn kagemusha_wallet_sign_receipt_body_v1<F, P>(
    store: &KagemushaWalletDurableStoreV1<F>,
    platform: &P,
    capability: &KagemushaWalletSelectedCapabilityV1,
    receipt_body: &[u8],
) -> Result<KagemushaDeviceSignatureV1, KagemushaWalletSignErrorV1>
where
    F: KagemushaWalletFsV1,
    P: KagemushaWalletPlatformV1 + ?Sized,
{
    capability
        .require_current(store)
        .map_err(KagemushaWalletSignErrorV1::Custody)?;
    sign_with_key(
        platform,
        capability.slot(),
        capability.payment_key(),
        KagemushaWalletSigningDomainV1::Receipt,
        receipt_body,
    )
}

/// Sign one non-receipt payment-key body (`role` in [`KAGEMUSHA_WALLET_PAYMENT_KEY_SIGNING_DOMAINS_V1`]).
///
/// # Errors
///
/// `RoleNotPermitted` for any other role, including the receipt roles; otherwise as
/// [`kagemusha_wallet_sign_receipt_body_v1`].
pub fn kagemusha_wallet_sign_role_v1<P: KagemushaWalletPlatformV1 + ?Sized>(
    platform: &P,
    slot: &KagemushaWalletSlotIdV1,
    payment_key: &KagemushaDevicePublicKeyV1,
    role: KagemushaWalletSigningDomainV1,
    body: &[u8],
) -> Result<KagemushaDeviceSignatureV1, KagemushaWalletSignErrorV1> {
    if !KAGEMUSHA_WALLET_PAYMENT_KEY_SIGNING_DOMAINS_V1.contains(&role) {
        return Err(KagemushaWalletSignErrorV1::RoleNotPermitted);
    }
    sign_with_key(platform, slot, payment_key, role, body)
}

fn sign_with_key<P: KagemushaWalletPlatformV1 + ?Sized>(
    platform: &P,
    slot: &KagemushaWalletSlotIdV1,
    payment_key: &KagemushaDevicePublicKeyV1,
    role: KagemushaWalletSigningDomainV1,
    body: &[u8],
) -> Result<KagemushaDeviceSignatureV1, KagemushaWalletSignErrorV1> {
    if body.len() != role.transcript_bytes() {
        return Err(KagemushaWalletSignErrorV1::InvalidTranscript);
    }
    let message = kagemusha_wallet_signing_message_v1(role, body);
    let output = platform
        .key_sign(
            slot,
            KagemushaWalletSigningMessageV1 {
                domain: role,
                bytes: &message,
            },
        )
        .map_err(KagemushaWalletSignErrorV1::Unavailable)?;
    kagemusha_wallet_freeze_signature_v1(payment_key, role, &message, output.as_signer_output())
        .map_err(|_| KagemushaWalletSignErrorV1::KeyUnusable)
}

#[cfg(test)]
#[path = "platform_tests.rs"]
mod tests;
