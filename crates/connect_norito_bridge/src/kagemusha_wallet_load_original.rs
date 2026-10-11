//! Bounded canonical Load transport decoding, without finality or monetary authority.
//!
//! The HTTP read returns the exact unsigned receipt frame. The independently supplied
//! native finality original remains DATA until the wallet authenticates its BLS
//! certificates, signed-genesis epoch authority and exact receipt event inclusion.

use iroha_data_model::{
    account::address::AccountAddress,
    isi::kagemusha_wallet::load_finality::{
        KAGEMUSHA_WALLET_LOAD_RECEIPT_MAX_BYTES_V1, KagemushaWalletLoadReceiptV1,
    },
    kagemusha::{
        KAGEMUSHA_WALLET_LOAD_FINALITY_MAX_BYTES_V1, KagemushaWalletLoadFinalityV1,
        kagemusha_wallet_account_digest_v1,
    },
};

use crate::kagemusha_wallet_ffi::{self as wallet, Failure, INVALID, Result};

const PAYER_MAX_BYTES: usize = 1024;

#[cfg(any(
    target_os = "android",
    target_os = "linux",
    target_os = "macos",
    windows
))]
#[path = "kagemusha_wallet_load_original/jni.rs"]
mod jni;

fn identity(bytes: &[u8]) -> Result<[u8; 32]> {
    let value = bytes.try_into().map_err(|_| Failure::code(INVALID))?;
    if value == [0; 32] {
        return Err(Failure::code(INVALID));
    }
    Ok(value)
}

/// Decode/bind canonical transport DATA. A successful return is never a proof verdict,
/// installed owner, verified receipt capability, current ordinal or spend permission.
fn validate(
    scheme: &[u8],
    wallet_id: &[u8],
    request: &[u8],
    payer: &[u8],
    receipt_original: &[u8],
    finality_original: &[u8],
) -> Result<u64> {
    let scheme = identity(scheme)?;
    let wallet_id = identity(wallet_id)?;
    let request = identity(request)?;
    if payer.is_empty()
        || payer.len() > PAYER_MAX_BYTES
        || receipt_original.is_empty()
        || receipt_original.len() > KAGEMUSHA_WALLET_LOAD_RECEIPT_MAX_BYTES_V1
        || finality_original.is_empty()
        || finality_original.len() > KAGEMUSHA_WALLET_LOAD_FINALITY_MAX_BYTES_V1
    {
        return Err(Failure::code(INVALID));
    }
    let payer = std::str::from_utf8(payer).map_err(|_| Failure::code(INVALID))?;
    // The exact transport already retains its independently signed network. Decode the
    // literal's own strict canonical I105 prefix here, rather than inventing a global
    // chain prefix. This parser confers no network or wallet admission authority.
    let account = AccountAddress::parse_encoded(payer, None)
        .and_then(|value| value.to_account_id())
        .map_err(|_| Failure::code(INVALID))?;
    let payer_digest =
        kagemusha_wallet_account_digest_v1(&account).map_err(|_| Failure::code(INVALID))?;
    let receipt = KagemushaWalletLoadReceiptV1::decode_canonical(receipt_original)
        .map_err(|_| Failure::code(INVALID))?;
    if receipt.scheme_id != scheme
        || receipt.wallet_id != wallet_id
        || receipt.request_id != request
        || receipt.payer_account_digest != payer_digest
    {
        return Err(Failure::code(INVALID));
    }
    let finality = KagemushaWalletLoadFinalityV1::decode_canonical(finality_original)
        .map_err(|_| Failure::code(INVALID))?;
    if finality.receipt_digest
        != receipt
            .receipt_digest()
            .map_err(|_| Failure::code(INVALID))?
    {
        return Err(Failure::code(INVALID));
    }
    Ok(receipt.block_height)
}

unsafe fn input<'a>(pointer: *const u8, length: usize, bound: usize) -> Result<&'a [u8]> {
    if length == 0 || length > bound || pointer.is_null() {
        return Err(Failure::code(INVALID));
    }
    // SAFETY: caller supplies initialized readable bytes; admitted extent checked first.
    Ok(unsafe { std::slice::from_raw_parts(pointer, length) })
}

/// Validate exact Load originals against independently retained authenticated read selectors.
/// Returns zero only for canonical DATA binding. It does not authenticate ordinary finality,
/// verify any financial proof, prepare a Load, touch storage/key custody or change a balance.
/// The caller retains the exact input bytes; the returned height is an untrusted DATA locator.
///
/// # Safety
/// Each identity points to 32 initialized bytes. Other inputs are readable for their stated
/// lengths and remain alive throughout this call. No callback or borrowed input is retained.
/// `out_height` points to one writable u64 and is zeroed on failure.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn connect_norito_kagemusha_wallet_load_original_validate_v1(
    scheme: *const u8,
    wallet_id: *const u8,
    request: *const u8,
    payer: *const u8,
    payer_length: usize,
    receipt: *const u8,
    receipt_length: usize,
    finality: *const u8,
    finality_length: usize,
    out_height: *mut u64,
) -> i32 {
    wallet::run(|| {
        if out_height.is_null() {
            return Err(Failure::code(INVALID));
        }
        // SAFETY: admitted fixed identity and bounded original extents.
        unsafe {
            *out_height = 0;
            *out_height = validate(
                input(scheme, 32, 32)?,
                input(wallet_id, 32, 32)?,
                input(request, 32, 32)?,
                input(payer, payer_length, PAYER_MAX_BYTES)?,
                input(
                    receipt,
                    receipt_length,
                    KAGEMUSHA_WALLET_LOAD_RECEIPT_MAX_BYTES_V1,
                )?,
                input(
                    finality,
                    finality_length,
                    KAGEMUSHA_WALLET_LOAD_FINALITY_MAX_BYTES_V1,
                )?,
            )?;
            Ok(())
        }
    })
    .err()
    .map_or(0, |error| error.status)
}

#[cfg(test)]
#[path = "kagemusha_wallet_load_original/tests.rs"]
mod tests;
