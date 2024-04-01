//! Data primitives used inside Iroha, but not related directly to the
//! blockchain-specific data model.
//!
//! If you need a thin wrapper around a third-party library, so that
//! it can be used in `IntoSchema`, as well as [`parity_scale_codec`]'s
//! `Encode` and `Decode` trait implementations, you should add the
//! wrapper as a submodule to this crate, rather than into
//! `iroha_data_model` directly.
#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(not(feature = "std"))]
extern crate alloc;

pub mod addr;
pub mod cmpext;
#[cfg(not(feature = "ffi_import"))]
pub mod const_vec;
#[cfg(not(feature = "ffi_import"))]
pub mod conststr;
pub mod must_use;
pub mod numeric;
pub mod riffle_iter;
pub mod small;
#[cfg(feature = "std")]
pub mod time;
pub mod unique_vec;

mod ffi {
    //! Definitions and implementations of FFI related functionalities

    macro_rules! ffi_item {
        ($it: item $($attr: meta)?) => {
            #[cfg(all(not(feature = "ffi_export"), not(feature = "ffi_import")))]
            $it

            #[cfg(all(feature = "ffi_export", not(feature = "ffi_import")))]
            #[derive(iroha_ffi::FfiType)]
            #[iroha_ffi::ffi_export]
            $(#[$attr])?
            $it

            #[cfg(feature = "ffi_import")]
            iroha_ffi::ffi! {
                #[iroha_ffi::ffi_import]
                $(#[$attr])?
                $it
            }
        };
    }

    pub(crate) use ffi_item;
}
