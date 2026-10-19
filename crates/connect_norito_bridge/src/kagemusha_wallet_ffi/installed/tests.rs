//! Mandatory base and closed financial original bounds; DATA cannot install a runtime.
use super::*;
fn base() -> RuntimeOriginals<'static> {
    RuntimeOriginals {
        app_manifest: b"app",
        envelope: b"envelope",
        wallet_runtime: b"runtime",
        verifier_pack: b"pack",
        producer_inventory: b"catalog",
        signed_genesis: b"genesis",
        originals_root: b"root",
        registration_source: b"",
    }
}
#[test]
fn missing_base_or_partial_financial_original_refuses_before_platform_acquisition() {
    base().validate_bounds().unwrap();
    for field in 0..7 {
        let mut input = base();
        match field {
            0 => input.app_manifest = b"",
            1 => input.envelope = b"",
            2 => input.wallet_runtime = b"",
            3 => input.verifier_pack = b"",
            4 => input.producer_inventory = b"",
            5 => input.signed_genesis = b"",
            _ => input.originals_root = b"",
        }
        assert_eq!(input.validate_bounds(), Err(Failure::code(INVALID)));
        assert!(PreparedInstallation::load(input).is_err());
    }
}
#[test]
fn complete_financial_absence_is_bounded_data_and_partial_offers_refuse() {
    for mask in 0..8 {
        let mut input = base();
        if mask & 1 == 0 {
            input.verifier_pack = b"";
        }
        if mask & 2 == 0 {
            input.producer_inventory = b"";
        }
        if mask & 4 == 0 {
            input.originals_root = b"";
        }
        assert_eq!(
            input.validate_bounds(),
            if mask == 0 || mask == 7 {
                Ok(())
            } else {
                Err(Failure::code(INVALID))
            }
        );
        // Complete presence is still DATA, never authentication or runtime authority.
        assert!(PreparedInstallation::load(input).is_err());
    }
}
#[test]
fn original_extents_are_refused_before_decode_or_platform_acquisition() {
    for (field, bound) in RUNTIME_BOUNDS.into_iter().enumerate() {
        let oversized = vec![1; bound + 1];
        let mut input = base();
        match field {
            0 => input.app_manifest = &oversized,
            1 => input.envelope = &oversized,
            2 => input.wallet_runtime = &oversized,
            3 => input.verifier_pack = &oversized,
            4 => input.producer_inventory = &oversized,
            5 => input.signed_genesis = &oversized,
            6 => input.originals_root = &oversized,
            _ => input.registration_source = &oversized,
        }
        assert_eq!(input.validate_bounds(), Err(Failure::code(INVALID)));
    }
    assert_eq!(read_config().maximum_bytes, PROVING_KEY_MAX_BYTES_V1);
    assert_eq!(read_config().maximum_rows, 1 << 16);
}

#[test]
fn financial_offer_classification_never_grants_an_owner() {
    let mut absent = base();
    absent.verifier_pack = b"";
    absent.producer_inventory = b"";
    absent.originals_root = b"";
    absent.validate_bounds().unwrap();
    assert_eq!(
        financial_offer(&absent),
        Err(Failure::code(ARTIFACTS_UNAVAILABLE))
    );
    absent.verifier_pack = b"pack";
    assert_eq!(absent.validate_bounds(), Err(Failure::code(INVALID)));
    assert_eq!(financial_offer(&absent), Err(Failure::code(INVALID)));
    assert_eq!(financial_offer(&base()), Ok(()));
}

#[test]
fn wallet_artifact_import_retains_its_bounded_process_scratch() {
    assert_eq!(read_config().maximum_bytes, PROVING_KEY_MAX_BYTES_V1);
    assert_eq!(read_config().maximum_rows, 1 << 16);
    assert_eq!(
        iroha_pasta::msm::SharedMemoryBudget::process_default().limit_bytes(),
        64 << 20
    );
}

#[test]
fn registration_original_extends_exact_c_layout_without_role_aliases() {
    use std::mem::{offset_of, size_of};
    let word = size_of::<usize>();
    assert_eq!(size_of::<WalletRuntimeOriginals>(), 16 * word);
    assert_eq!(
        offset_of!(WalletRuntimeOriginals, originals_root),
        12 * word
    );
    assert_eq!(
        offset_of!(WalletRuntimeOriginals, originals_root_length),
        13 * word
    );
    assert_eq!(
        offset_of!(WalletRuntimeOriginals, registration_source),
        14 * word
    );
    assert_eq!(
        offset_of!(WalletRuntimeOriginals, registration_source_length),
        15 * word
    );
}

#[test]
fn install_refuses_invalid_originals_before_any_platform_upcall() {
    // `install` runs the whole admission, including any memo lookup, before the platform
    // factory, custody root and owner; a refused attempt never reaches the platform factory.
    let mut input = base();
    input.app_manifest = b"";
    let refused = install(
        input,
        false,
        || -> Result<(CallbackPlatform, std::path::PathBuf)> {
            panic!("no platform upcall before admission")
        },
    );
    assert_eq!(refused.err(), Some(Failure::code(INVALID)));
}


#[cfg(unix)]
mod failed_provider_open {
    use super::*;
    use std::{
        ffi::c_void,
        fs,
        os::unix::fs::PermissionsExt,
        path::PathBuf,
        sync::{
            Mutex,
            atomic::{AtomicUsize, Ordering},
        },
    };

    struct Callbacks {
        root: PathBuf,
        displaced: Option<PathBuf>,
        retained: AtomicUsize,
        released: AtomicUsize,
        calls: Mutex<Vec<u32>>,
        moved: Mutex<Option<std::result::Result<(), String>>>,
    }
    unsafe extern "C" fn retain(context: *mut c_void) {
        // SAFETY: failed_open retains this stack-owned, thread-safe context through the call.
        let state = unsafe { &*context.cast::<Callbacks>() };
        state.retained.fetch_add(1, Ordering::SeqCst);
    }
    unsafe extern "C" fn release(context: *mut c_void) {
        // SAFETY: the context remains alive until the provider-opening result is consumed.
        let state = unsafe { &*context.cast::<Callbacks>() };
        state.released.fetch_add(1, Ordering::SeqCst);
        if let Some(displaced) = &state.displaced {
            // This is the ordinary retained-platform release after Provider::open fails.
            // Record errors for Rust assertions after the callback; never panic across C.
            let moved = fs::rename(&state.root, displaced).map_err(|error| error.to_string());
            *state
                .moved
                .lock()
                .unwrap_or_else(|error| error.into_inner()) = Some(moved);
        }
    }
    unsafe extern "C" fn invoke(
        context: *mut c_void,
        operation: u32,
        _: *const u8,
        _: *const u8,
        _: usize,
        _: u32,
        _: *mut u8,
        _: usize,
        reply: *mut PlatformReply,
    ) {
        // SAFETY: CallbackPlatform owns the context and reply buffer for this upcall.
        let state = unsafe { &*context.cast::<Callbacks>() };
        state
            .calls
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .push(operation);
        // Only the storage-availability probe succeeds; no key or anchor operation does.
        unsafe {
            reply.write(PlatformReply {
                tag: if operation == 7 { 0 } else { 2 },
                reason: 4,
                code: 0,
                length: 0,
            });
        }
    }
    fn failed_open(displace_on_release: bool) -> Failure {
        let temporary = tempfile::tempdir().unwrap();
        // Resolve the system temporary directory's aliases before private-root admission.
        let parent = temporary.path().canonicalize().unwrap();
        let root = parent.join("custody");
        fs::create_dir(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        let sentinel = b"invalid root sentinel";
        fs::write(root.join("root.norito"), sentinel).unwrap();
        fs::set_permissions(root.join("root.norito"), fs::Permissions::from_mode(0o600)).unwrap();
        let state = Callbacks {
            root: root.clone(),
            displaced: displace_on_release.then(|| parent.join("displaced")),
            retained: AtomicUsize::new(0),
            released: AtomicUsize::new(0),
            calls: Mutex::new(Vec::new()),
            moved: Mutex::new(None),
        };
        // SAFETY: state outlives the call; the callbacks are synchronized and never panic.
        let platform = unsafe {
            CallbackPlatform::new(PlatformCallbacks {
                version: 1,
                anchor_policy: 1,
                context: std::ptr::from_ref(&state).cast_mut().cast(),
                retain: Some(retain),
                release: Some(release),
                invoke: Some(invoke),
            })
        }
        .unwrap();
        let failure = open_custody_provider(platform, root.clone(), [7; 32])
            .err()
            .expect("a failed provider open cannot supply a runtime owner");
        assert_eq!(state.retained.load(Ordering::SeqCst), 1);
        assert_eq!(state.released.load(Ordering::SeqCst), 1);
        assert_eq!(
            *state.calls.lock().unwrap(),
            [7],
            "no key or anchor effects"
        );
        let retained_root = if let Some(displaced) = &state.displaced {
            assert_eq!(*state.moved.lock().unwrap(), Some(Ok(())));
            assert!(
                !root.exists(),
                "the displacement persists through transaction exit"
            );
            displaced
        } else {
            assert!(state.moved.lock().unwrap().is_none());
            &root
        };
        assert_eq!(
            fs::read(retained_root.join("root.norito")).unwrap(),
            sentinel.as_slice()
        );
        let mut entries: Vec<_> = fs::read_dir(retained_root)
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect();
        entries.sort();
        assert_eq!(
            entries,
            [
                std::ffi::OsString::from("lock"),
                std::ffi::OsString::from("root.norito")
            ],
            "failed opening creates no slot, enrollment, journal or monetary state"
        );
        failure
    }

    #[test]
    fn stationary_failed_provider_open_preserves_the_custody_data_error() {
        assert_eq!(failed_open(false), Failure::custody(110));
    }

    #[test]
    fn moved_failed_provider_open_returns_exit_refusal_without_an_owner_or_money() {
        assert_eq!(
            failed_open(true),
            Failure::unavailable(UNAVAILABLE, advance::KagemushaWalletUnavailableV1::Io(0))
        );
    }
}
