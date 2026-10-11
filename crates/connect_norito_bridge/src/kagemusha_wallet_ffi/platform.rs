//! Bounded C callbacks for the Apple platform, with explicit ownership and tri-state results.

use super::{Failure, INVALID, Result, advance};
use advance::{
    KagemushaWalletNotPublishedV1 as NotPublished, KagemushaWalletPlatformV1 as Platform,
    KagemushaWalletProbeV1 as Probe, KagemushaWalletPublishOutcomeV1 as Publish,
    KagemushaWalletSlotIdV1 as Slot, KagemushaWalletUnavailableV1 as Unavailable,
};
use iroha_data_model::kagemusha::KagemushaDevicePublicKeyV1 as PublicKey;
use std::ffi::c_void;

/// Fixed metadata returned by a callback into the caller-owned output buffer.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct PlatformReply {
    /// 0 success/present, 1 absent, 2 unavailable/not performed, 3 already exists,
    /// 4 uncertain write, 5 destination absent. Tags are checked for each operation.
    pub tag: u32,
    /// 0 locked, 1 before first unlock, 2 busy, 3 I/O, 4 platform, 5 unusable key,
    /// 6 permanently invalidated. Unknown reasons become Platform(0), never absence.
    pub reason: u32,
    /// Original OS/platform status.
    pub code: i32,
    /// Bytes initialized in the caller-owned output buffer, at most its capacity.
    pub length: usize,
}
impl Default for PlatformReply {
    fn default() -> Self {
        Self {
            tag: u32::MAX,
            reason: 4,
            code: 0,
            length: 0,
        }
    }
}
/// Lifetime and platform operations; callbacks may execute on native worker threads.
///
/// This vtable is for the Apple adapter and always requires the Keychain anchor policy.
/// All pointers remain valid until `release`; callbacks must be thread-safe and must not
/// throw, panic, re-enter the same wallet, retain borrowed buffers, or write beyond capacity.
/// `retain` and `release` are called once each for every successfully admitted Rust owner.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct PlatformCallbacks {
    /// Exactly 1; there is no fallback layout.
    pub version: u32,
    /// Exactly 1 (Apple Keychain). Android uses its separate typed JNI adapter.
    pub anchor_policy: u32,
    /// Opaque platform object, never a payment key or a proof verifier.
    pub context: *mut c_void,
    /// Retain one strong reference to context.
    pub retain: Option<unsafe extern "C" fn(*mut c_void)>,
    /// Release that reference after all calls have stopped.
    pub release: Option<unsafe extern "C" fn(*mut c_void)>,
    /// Operations: 0 key probe, 1 key generate (input challenge32, auxiliary profile1/2/3 (3 Android TEE-only; Apple refuses)),
    /// 2 key sign (input exact domain-checked32), 3 delete key, 4 anchor read,
    /// 5 anchor create, 6 anchor update, 7 storage state, 8 boot UUID (UTF-8, 36 bytes), 9 prepared no-backup custody root (UTF-8, <=4096),
    /// 10 complete key-slot inventory (ascending unique nonzero32, <=4096 slots),
    /// 13 readback of this owner's actual retained generation return (challenge32/profile1/2).
    /// Operation13 never generates: tag0 is the original SEC1 key, tag3 is no held successful
    /// return (not key absence), tag2 is unavailable; malformed answers remain unavailable.
    /// Slot is exactly32 bytes for operations0..6 and13, null otherwise. Results are key SEC1
    /// (65 bytes), signature DER (8..72), anchor (<=256), or boot UUID, as appropriate.
    pub invoke: Option<
        unsafe extern "C" fn(
            *mut c_void,
            u32,
            *const u8,
            *const u8,
            usize,
            u32,
            *mut u8,
            usize,
            *mut PlatformReply,
        ),
    >,
}
/// A retained Apple platform capability. Its signer is reachable only with G2's typed message.
pub struct CallbackPlatform {
    callbacks: PlatformCallbacks,
}
// SAFETY: the constructor contract requires thread-safe retained callbacks. Rust owns the
// one retained context and does not expose an untyped signing operation.
unsafe impl Send for CallbackPlatform {}
// SAFETY: same contract; callback outputs and all borrowed arguments are call-local.
unsafe impl Sync for CallbackPlatform {}
impl CallbackPlatform {
    /// Retain a complete Apple callback table.
    ///
    /// # Safety
    /// The table and context must satisfy `PlatformCallbacks` for this owner's entire lifetime.
    /// # Errors
    /// Rejects incomplete tables, null context, another version or missing Keychain policy.
    pub unsafe fn new(callbacks: PlatformCallbacks) -> Result<Self> {
        Self::validate(&callbacks)?;
        // SAFETY: admitted callback and lifetime contract from caller.
        unsafe { (callbacks.retain.expect("validated retain"))(callbacks.context) };
        Ok(Self { callbacks })
    }
    pub(super) fn validate(callbacks: &PlatformCallbacks) -> Result<()> {
        if callbacks.version != 1
            || callbacks.anchor_policy != 1
            || callbacks.context.is_null()
            || callbacks.retain.is_none()
            || callbacks.release.is_none()
            || callbacks.invoke.is_none()
        {
            return Err(Failure::code(INVALID));
        }
        Ok(())
    }
    /// Prepare and return the platform's non-backup custody root. This never establishes
    /// monetary authority; the retained native filesystem/provider still must open it.
    /// # Errors
    /// Rejects unavailable, non-UTF-8, relative, empty or NUL-containing paths.
    pub fn custody_root(&self) -> std::result::Result<std::path::PathBuf, Unavailable> {
        let (reply, bytes) = self.call(9, None, &[], 0, 4096);
        if reply.tag == 2 && bytes.is_empty() {
            return Err(reason(reply));
        }
        if reply.tag != 0 || bytes.contains(&0) {
            return Err(Unavailable::Platform(0));
        }
        let path = std::path::PathBuf::from(
            std::str::from_utf8(&bytes).map_err(|_| Unavailable::Platform(0))?,
        );
        if !path.is_absolute() {
            return Err(Unavailable::Platform(0));
        }
        Ok(path)
    }
    fn call(
        &self,
        operation: u32,
        slot: Option<&Slot>,
        input: &[u8],
        auxiliary: u32,
        capacity: usize,
    ) -> (PlatformReply, Vec<u8>) {
        let mut bytes = vec![0; capacity];
        let mut reply = PlatformReply::default();
        // SAFETY: retained callback; all buffers live across the call and carry explicit bounds.
        unsafe {
            (self.callbacks.invoke.expect("validated invoke"))(
                self.callbacks.context,
                operation,
                slot.map_or(std::ptr::null(), |slot| slot.0.as_ptr()),
                input.as_ptr(),
                input.len(),
                auxiliary,
                bytes.as_mut_ptr(),
                bytes.len(),
                &mut reply,
            )
        };
        if reply.length > capacity {
            return (
                PlatformReply {
                    tag: u32::MAX,
                    ..PlatformReply::default()
                },
                Vec::new(),
            );
        }
        bytes.truncate(reply.length);
        (reply, bytes)
    }
    fn anchor_write(&self, operation: u32, slot: &Slot, bytes: &[u8]) -> Publish {
        if bytes.len() > advance::KAGEMUSHA_WALLET_ANCHOR_MAX_BYTES_V1 {
            return Publish::NotPublished(NotPublished::Failed(Unavailable::Platform(0)));
        }
        let (reply, bytes) = self.call(operation, Some(slot), bytes, 0, 0);
        if !bytes.is_empty() {
            return Publish::Uncertain(Unavailable::Platform(0));
        }
        match reply.tag {
            0 => Publish::Published,
            2 => Publish::NotPublished(NotPublished::Failed(reason(reply))),
            3 if operation == 5 => Publish::NotPublished(NotPublished::DestinationExists),
            5 if operation == 6 => Publish::NotPublished(NotPublished::DestinationAbsent),
            4 => Publish::Uncertain(reason(reply)),
            // An invalid response after a write cannot establish that nothing happened.
            _ => Publish::Uncertain(Unavailable::Platform(0)),
        }
    }
}
impl Drop for CallbackPlatform {
    fn drop(&mut self) {
        // SAFETY: the retained context remains valid until this matching release.
        unsafe { (self.callbacks.release.expect("validated release"))(self.callbacks.context) };
    }
}
pub(crate) fn reason(reply: PlatformReply) -> Unavailable {
    match reply.reason {
        0 => Unavailable::Locked,
        1 => Unavailable::BeforeFirstUnlock,
        2 => Unavailable::Busy,
        3 => Unavailable::Io(reply.code),
        4 => Unavailable::Platform(reply.code),
        5 => Unavailable::KeyUnusable,
        6 => Unavailable::PermanentlyInvalidated,
        _ => Unavailable::Platform(0),
    }
}
impl Platform for CallbackPlatform {
    fn key_enumerate(&self) -> std::result::Result<Vec<Slot>, Unavailable> {
        let maximum = advance::KAGEMUSHA_WALLET_KEY_ENUMERATION_MAX_SLOTS_V1;
        let (reply, bytes) = self.call(10, None, &[], 0, maximum * 32);
        if reply.tag == 2 && bytes.is_empty() {
            return Err(reason(reply));
        }
        if reply.tag != 0 || !bytes.len().is_multiple_of(32) {
            return Err(Unavailable::Platform(0));
        }
        let slots: Vec<_> = bytes
            .chunks_exact(32)
            .map(|bytes| Slot(bytes.try_into().expect("exact slot chunk")))
            .collect();
        if slots.iter().any(|slot| slot.0 == [0; 32])
            || !slots.windows(2).all(|pair| pair[0] < pair[1])
        {
            return Err(Unavailable::Platform(0));
        }
        Ok(slots)
    }

    fn key_probe(&self, slot: &Slot) -> Probe<PublicKey> {
        let (reply, bytes) = self.call(0, Some(slot), &[], 0, 65);
        match reply.tag {
            0 => PublicKey::from_sec1_bytes(&bytes)
                .map_or(Probe::Unavailable(Unavailable::KeyUnusable), Probe::Present),
            1 if bytes.is_empty() => Probe::Absent,
            2 if bytes.is_empty() => Probe::Unavailable(reason(reply)),
            _ => Probe::Unavailable(Unavailable::Platform(0)),
        }
    }
    fn key_generate(
        &self,
        slot: &Slot,
        request: &advance::KagemushaWalletKeyGenerationRequestV1,
    ) -> advance::KagemushaWalletKeyGenerationV1 {
        use advance::KagemushaWalletKeyGenerationV1 as G;
        let (reply, bytes) = self.call(
            1,
            Some(slot),
            &request.challenge_digest,
            u32::from(request.profile.tag()),
            65,
        );
        match reply.tag {
            0 => PublicKey::from_sec1_bytes(&bytes)
                .map_or(G::Unavailable(Unavailable::KeyUnusable), G::Generated),
            3 if bytes.is_empty() => G::AlreadyPresent,
            2 if bytes.is_empty() => G::Unavailable(reason(reply)),
            _ => G::Unavailable(Unavailable::Platform(0)),
        }
    }
    fn key_recover_generation_reply(
        &self,
        slot: &Slot,
        request: &advance::KagemushaWalletKeyGenerationRequestV1,
    ) -> std::result::Result<Option<PublicKey>, Unavailable> {
        let (reply, bytes) = self.call(
            13,
            Some(slot),
            &request.challenge_digest,
            u32::from(request.profile.tag()),
            65,
        );
        match reply.tag {
            0 => PublicKey::from_sec1_bytes(&bytes)
                .map(Some)
                .map_err(|_| Unavailable::KeyUnusable),
            // No held successful return is not a Keychain absence verdict.
            3 if bytes.is_empty() => Ok(None),
            2 if bytes.is_empty() => Err(reason(reply)),
            _ => Err(Unavailable::Platform(0)),
        }
    }
    fn key_sign(
        &self,
        slot: &Slot,
        message: advance::KagemushaWalletSignMessageV1<'_>,
    ) -> std::result::Result<advance::KagemushaWalletPlatformSignatureV1, Unavailable> {
        let (reply, bytes) = self.call(2, Some(slot), message.as_bytes(), 0, 72);
        match reply.tag {
            0 if (8..=72).contains(&bytes.len()) => {
                Ok(advance::KagemushaWalletPlatformSignatureV1::Der(bytes))
            }
            2 if bytes.is_empty() => Err(reason(reply)),
            _ => Err(Unavailable::KeyUnusable),
        }
    }
    fn key_delete(&self, slot: &Slot) -> advance::KagemushaWalletRemoveOutcomeV1 {
        use advance::KagemushaWalletRemoveOutcomeV1 as R;
        let (reply, _) = self.call(3, Some(slot), &[], 0, 0);
        match reply.tag {
            0 => R::Removed,
            2 => R::NotRemoved(reason(reply)),
            4 => R::Uncertain(reason(reply)),
            _ => R::Uncertain(Unavailable::Platform(0)),
        }
    }
    fn anchor_policy(&self) -> advance::KagemushaWalletAnchorPolicyV1 {
        advance::KagemushaWalletAnchorPolicyV1::Keychain
    }
    fn anchor_create(&self, slot: &Slot, bytes: &[u8]) -> Publish {
        self.anchor_write(5, slot, bytes)
    }
    fn anchor_update(&self, slot: &Slot, bytes: &[u8]) -> Publish {
        self.anchor_write(6, slot, bytes)
    }
    fn anchor_read(&self, slot: &Slot) -> Probe<Vec<u8>> {
        let (reply, bytes) = self.call(
            4,
            Some(slot),
            &[],
            0,
            advance::KAGEMUSHA_WALLET_ANCHOR_MAX_BYTES_V1,
        );
        match reply.tag {
            0 if !bytes.is_empty() => Probe::Present(bytes),
            1 if bytes.is_empty() => Probe::Absent,
            2 if bytes.is_empty() => Probe::Unavailable(reason(reply)),
            _ => Probe::Unavailable(Unavailable::Platform(0)),
        }
    }
    fn storage_state(&self) -> std::result::Result<(), Unavailable> {
        let (reply, _) = self.call(7, None, &[], 0, 0);
        match reply.tag {
            0 => Ok(()),
            2 => Err(reason(reply)),
            _ => Err(Unavailable::Platform(0)),
        }
    }
    fn boot_id(&self) -> std::result::Result<[u8; 32], Unavailable> {
        let (reply, bytes) = self.call(8, None, &[], 0, 36);
        match reply.tag {
            0 => advance::kagemusha_wallet_boot_id_from_text_v1(
                std::str::from_utf8(&bytes).map_err(|_| Unavailable::Platform(0))?,
            ),
            2 if bytes.is_empty() => Err(reason(reply)),
            _ => Err(Unavailable::Platform(0)),
        }
    }
    /// Design §5.3 memory probe. iOS answers natively, without a platform callback; zero (not
    /// an app, or already over its limit) is no answer, which never refuses.
    fn available_memory(&self) -> Option<u64> {
        #[cfg(any(target_os = "ios", target_os = "tvos", target_os = "watchos"))]
        {
            apple_available_memory()
        }
        #[cfg(not(any(target_os = "ios", target_os = "tvos", target_os = "watchos")))]
        {
            use iroha_core_zk::kagemusha_wallet_capacity_v1 as capacity;
            capacity::kagemusha_wallet_native_available_memory_v1()
        }
    }
}

/// Bytes remaining before this app reaches its current dirty-memory limit
/// (`os_proc_available_memory`, iOS 13+; the deployment floor is iOS 18).
#[cfg(any(target_os = "ios", target_os = "tvos", target_os = "watchos"))]
fn apple_available_memory() -> Option<u64> {
    unsafe extern "C" {
        fn os_proc_available_memory() -> usize;
    }
    // SAFETY: a libSystem query with no arguments and no retained state.
    let bytes = unsafe { os_proc_available_memory() };
    if bytes == 0 {
        return None;
    }
    u64::try_from(bytes).ok()
}
