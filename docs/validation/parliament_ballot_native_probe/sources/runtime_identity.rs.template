//! Setup-only identities of the installed images in this diagnostic process.
//!
//! LC_UUID/cache UUID identify observed binaries, not correspondence to Apple's
//! published source. This allocates and resolves symbols before the measured
//! worker interval. The caller must not concurrently load or unload images;
//! matching before/after counts alone cannot establish a concurrent snapshot.

use std::ffi::CStr;

use norito::json::JsonSerialize;

type ImageCount = unsafe extern "C" fn() -> u32;
type ImageHeader = unsafe extern "C" fn(u32) -> *const libc::c_void;
type ImageName = unsafe extern "C" fn(u32) -> *const libc::c_char;
type ImageUuid = unsafe extern "C" fn(*const libc::c_void, *mut u8) -> bool;
type CacheUuid = unsafe extern "C" fn(*mut u8) -> bool;
type IsInterposing = unsafe extern "C" fn() -> bool;

/// One currently loaded image's path and UUID; no load address or slide.
#[derive(Debug, JsonSerialize)]
pub struct ImageIdentity {
    pub path: String,
    pub lc_uuid: Option<String>,
}

/// Identity observation in the actual probe, separate from source provenance.
#[derive(Debug, JsonSerialize)]
pub struct RuntimeSnapshot {
    pub schema: &'static str,
    pub scope: &'static str,
    pub api_declaration_source: &'static str,
    pub shared_cache_uuid: Option<String>,
    pub inserted_or_interposing_libraries: bool,
    pub image_count_before: u32,
    pub image_count_after: u32,
    pub loaded_images: Vec<ImageIdentity>,
    pub installed_runtime_source_identity_established: bool,
}

unsafe fn symbol(name: &CStr) -> Result<*mut libc::c_void, &'static str> {
    // SAFETY: the name is NUL terminated. This is setup-only lookup; the loaded
    // process image implements these exact signatures on the admitted target.
    let pointer = unsafe { libc::dlsym(libc::RTLD_DEFAULT, name.as_ptr()) };
    if pointer.is_null() {
        Err("dyld identity API unavailable")
    } else {
        Ok(pointer)
    }
}

fn uuid_string(bytes: [u8; 16]) -> String {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let mut output = String::with_capacity(36);
    for (index, byte) in bytes.into_iter().enumerate() {
        if matches!(index, 4 | 6 | 8 | 10) {
            output.push('-');
        }
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 15)]));
    }
    output
}

/// Read identities before starting any worker or measured marker.
///
/// The public count/header/name APIs are declared by the local SDK's dyld.h.
/// Exact bool/uuid_t signatures for the three SPI calls are in the immutable
/// declaration source below. No private runtime structure is reinterpreted.
/// Unsupported/missing APIs refuse identity capture instead of substituting
/// a source tag or identities from another process.
///
/// # Safety
/// The caller must exclude concurrent image unloading until capture returns,
/// because dyld lends pointers to image names and headers. The diagnostic's
/// main calls this before it creates any worker or performs any image unload.
pub unsafe fn capture() -> Result<RuntimeSnapshot, &'static str> {
    if !cfg!(target_os = "macos") || !cfg!(target_pointer_width = "64") {
        return Err("dyld identity capture requires 64-bit macOS");
    }
    // SAFETY: exact declarations from dyld.h/dyld_priv.h, with UUID buffers of
    // 16 initialized bytes. This diagnostic calls before creating its worker;
    // it has no concurrent loader/unloader and retains all resolved images.
    let (count, header, name, image_uuid, cache_uuid, interposing) = unsafe {
        (
            std::mem::transmute::<*mut libc::c_void, ImageCount>(symbol(c"_dyld_image_count")?),
            std::mem::transmute::<*mut libc::c_void, ImageHeader>(symbol(
                c"_dyld_get_image_header",
            )?),
            std::mem::transmute::<*mut libc::c_void, ImageName>(symbol(c"_dyld_get_image_name")?),
            std::mem::transmute::<*mut libc::c_void, ImageUuid>(symbol(c"_dyld_get_image_uuid")?),
            std::mem::transmute::<*mut libc::c_void, CacheUuid>(symbol(
                c"_dyld_get_shared_cache_uuid",
            )?),
            std::mem::transmute::<*mut libc::c_void, IsInterposing>(symbol(
                c"dyld_has_inserted_or_interposing_libraries",
            )?),
        )
    };
    let mut cache = [0; 16];
    // SAFETY: the exact API writes at most uuid_t's 16 bytes.
    let shared_cache_uuid = unsafe { cache_uuid(cache.as_mut_ptr()) }.then(|| uuid_string(cache));
    // SAFETY: setup-only query; all loaded images stay resident during capture.
    let image_count_before = unsafe { count() };
    if image_count_before > 65_536 {
        return Err("dyld image count exceeds diagnostic cap");
    }
    let mut loaded_images = Vec::with_capacity(image_count_before as usize);
    for index in 0..image_count_before {
        // SAFETY: indices are below the observed count and no loader mutation
        // runs concurrently; dyld owns the returned immutable name/header.
        let (image_header, image_name) = unsafe { (header(index), name(index)) };
        if image_header.is_null() || image_name.is_null() {
            return Err("dyld image disappeared during identity capture");
        }
        // SAFETY: dyld returns a NUL-terminated name under the setup premise.
        let path = unsafe { CStr::from_ptr(image_name) }
            .to_str()
            .map_err(|_| "dyld image path is not UTF-8")?
            .to_owned();
        let mut value = [0; 16];
        // SAFETY: live dyld-supplied Mach-O header and writable uuid_t buffer.
        let lc_uuid =
            unsafe { image_uuid(image_header, value.as_mut_ptr()) }.then(|| uuid_string(value));
        loaded_images.push(ImageIdentity { path, lc_uuid });
    }
    // SAFETY: setup-only calls with no mutable pointer arguments.
    let (image_count_after, inserted_or_interposing_libraries) =
        unsafe { (count(), interposing()) };
    if image_count_before != image_count_after {
        return Err("dyld image count changed during identity capture");
    }
    Ok(RuntimeSnapshot {
        schema: "parliament-native-runtime-identity-v1",
        scope: "Actual diagnostic process before the marked worker interval; no concurrent loader mutation is admitted.",
        api_declaration_source: "https://github.com/apple-oss-distributions/dyld/blob/fd8d0c4d52320ebf64db34f3cb280310d905c5ae/include/mach-o/dyld_priv.h",
        shared_cache_uuid,
        inserted_or_interposing_libraries,
        image_count_before,
        image_count_after,
        loaded_images,
        installed_runtime_source_identity_established: false,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uuid_uses_byte_order_and_fixed_uppercase_groups() {
        assert_eq!(
            uuid_string([0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 255]),
            "00010203-0405-0607-0809-0A0B0C0D0EFF"
        );
    }

    #[test]
    fn missing_symbol_refuses_identity_substitution() {
        // SAFETY: setup-only lookup for a deliberately absent diagnostic name.
        assert!(
            unsafe { symbol(c"parliament_native_probe_deliberately_absent_identity") }.is_err()
        );
    }

    #[test]
    #[cfg(target_os = "macos")]
    fn captures_this_process_and_keeps_source_binding_unestablished() {
        // SAFETY: these diagnostic tests do not unload process images.
        let value = unsafe { capture() }.expect("required macOS diagnostic identity APIs");
        assert_eq!(value.image_count_before, value.image_count_after);
        assert_eq!(value.loaded_images.len(), value.image_count_before as usize);
        assert!(!value.installed_runtime_source_identity_established);
        assert!(value.loaded_images.iter().any(|image| {
            image.path.ends_with("/libsystem_malloc.dylib") && image.lc_uuid.is_some()
        }));
        let encoded = norito::json::to_json(&value).expect("runtime identity JSON");
        assert!(!encoded.contains("load_address"));
    }
}
