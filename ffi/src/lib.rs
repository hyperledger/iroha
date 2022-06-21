//! Structures, macros related to FFI and generation of FFI bindings.

pub use iroha_ffi_derive::*;

// NOTE: Using `u32` to be compatible with WebAssembly.
// Otherwise `u8` should be sufficient
/// Type of the handle id
pub type HandleId = u32;

/// FFI compatible tuple with 2 elements
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Pair<K, V>(pub K, pub V);

/// Result of execution of an FFI function
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
// NOTE: Enum is `repr(i32)` becasuse WebAssembly supports only
// u32/i32, u64/i64 natively. Otherwise, `repr(i8)` would suffice
#[repr(i32)]
pub enum FfiResult {
    /// Handle id doesn't identify any known handles
    UnknownHandle = -4_i32,
    /// Executing the wrapped method on handle returned error
    ExecutionFail = -3_i32,
    /// Raw pointer input argument to FFI function was null
    ArgIsNull = -2_i32,
    /// Given bytes don't comprise a valid UTF8 string
    Utf8Error = -1_i32,
    /// FFI function executed successfully
    Ok = 0_i32,
}

/// Implement `Handle` for given types with first argument as the initial handle id.
#[macro_export]
macro_rules! handles {
    ( $id:expr, $ty:ty $(, $other:ty)* $(,)? ) => {
        impl Handle for $ty {
            const ID: $crate::HandleId = $id;
        }

        $crate::handles! {$id + 1, $( $other, )*}
    };
    ( $id:expr, $(,)? ) => {
        /// Represents handle in an FFI context
        pub trait Handle {
            /// Unique identifier of the handle. Most commonly, it is
            /// used to facilitate generic monomorphization over FFI
            const ID: $crate::HandleId;
        }
    };
}

/// Generate FFI equivalent implementation of the requested trait method (e.g. Clone, Eq, Ord)
#[macro_export]
macro_rules! gen_ffi_impl {
    (@null_check_stmts $( $ptr:ident ),+ ) => {
    $(  if $ptr.is_null() {
            return $crate::FfiResult::ArgIsNull;
        } )+
    };
    ( Clone: $( $other:ty ),+ $(,)? ) => {
        /// FFI function equivalent of [`Clone::clone`]
        ///
        /// # Safety
        ///
        /// All of the given pointers must be valid and the given handle id must match the expected
        /// pointer type
        #[no_mangle]
        pub unsafe extern "C" fn __clone(
            handle_id: $crate::HandleId,
            handle_ptr: *const core::ffi::c_void,
            output_ptr: *mut *mut core::ffi::c_void
        ) -> $crate::FfiResult {
            gen_ffi_impl!{@null_check_stmts handle_ptr, output_ptr}

            match handle_id {
                $( <$other as Handle>::ID => {
                    let handle = &*handle_ptr.cast::<$other>();

                    let new_handle = Box::new(Clone::clone(handle));
                    let new_handle = Box::into_raw(new_handle);

                    output_ptr.write(new_handle.cast());
                } )+
                _ => return $crate::FfiResult::UnknownHandle,
            }

            $crate::FfiResult::Ok
        }
    };
    ( Eq: $( $other:ty ),+ $(,)? ) => {
        /// FFI function equivalent of [`Eq::eq`]
        ///
        /// # Safety
        ///
        /// All of the given pointers must be valid and the given handle id must match the expected
        /// pointer type
        #[no_mangle]
        pub unsafe extern "C" fn __eq(
            handle_id: $crate::HandleId,
            left_handle_ptr: *const core::ffi::c_void,
            right_handle_ptr: *const core::ffi::c_void,
            output_ptr: *mut bool,
        ) -> $crate::FfiResult {
            gen_ffi_impl!{@null_check_stmts left_handle_ptr, right_handle_ptr, output_ptr}

            match handle_id {
                $( <$other as Handle>::ID => {
                    let left_handle = &*left_handle_ptr.cast::<$other>();
                    let right_handle = &*right_handle_ptr.cast::<$other>();

                    output_ptr.write(left_handle == right_handle);
                } )+
                _ => return $crate::FfiResult::UnknownHandle,
            }

            $crate::FfiResult::Ok
        }
    };
    ( Ord: $( $other:ty ),+ $(,)? ) => {
        /// FFI function equivalent of [`Ord::ord`]
        ///
        /// # Safety
        ///
        /// All of the given pointers must be valid and the given handle id must match the expected
        /// pointer type
        #[no_mangle]
        pub unsafe extern "C" fn __ord(
            handle_id: $crate::HandleId,
            left_handle_ptr: *const core::ffi::c_void,
            right_handle_ptr: *const core::ffi::c_void,
            output_ptr: *mut core::cmp::Ordering,
        ) -> $crate::FfiResult {
            gen_ffi_impl!{@null_check_stmts left_handle_ptr, right_handle_ptr, output_ptr}

            match handle_id {
                $( <$other as Handle>::ID => {
                    let left_handle = &*left_handle_ptr.cast::<$other>();
                    let right_handle = &*right_handle_ptr.cast::<$other>();

                    output_ptr.write(left_handle.cmp(right_handle));
                } )+
                _ => return $crate::FfiResult::UnknownHandle,
            }

            $crate::FfiResult::Ok
        }
    };
    ( Drop: $( $other:ty ),+ $(,)? ) => {
        /// FFI function equivalent of [`Drop::drop`]
        ///
        /// # Safety
        ///
        /// All of the given pointers must be valid and the given handle id must match the expected
        /// pointer type
        #[no_mangle]
        pub unsafe extern "C" fn __drop(
            handle_id: $crate::HandleId,
            handle_ptr: *mut core::ffi::c_void,
        ) -> $crate::FfiResult {
            gen_ffi_impl!{@null_check_stmts handle_ptr}

            match handle_id {
                $( <$other as Handle>::ID => {
                    Box::from_raw(handle_ptr.cast::<$other>());
                } )+
                _ => return $crate::FfiResult::UnknownHandle,
            }

            $crate::FfiResult::Ok
        }
    };
}
