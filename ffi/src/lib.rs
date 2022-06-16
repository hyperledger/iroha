//! Structures, macros related to FFI and generation of FFI bindings.
//! [Non-robust types](https://anssi-fr.github.io/rust-guide/07_ffi.html#non-robust-types-references-function-pointers-enums)
//! are strictly avoided in the FFI API
//!
//! # Conversions:
//! owned type -> opaque pointer
//! reference -> raw pointer
//!
//! # Conversions (WebAssembly):
//! u8, u16 -> u32
//! i8, i16 -> i32
//!
//! # Conversions (input only):
//! enum -> int
//! bool -> u8

pub use iroha_ffi_derive::*;
pub use opaque_pointer;

// NOTE: Using `u32` to be compatible with WebAssembly.
// Otherwise `u8` should be sufficient
/// Type of the handle id
pub type HandleId = u32;

/// Represents handle in an FFI context
pub trait Handle {
    /// Unique identifier of the handle. Most commonly, it is
    /// used to facilitate generic monomorphization over FFI
    const ID: HandleId;
}

/// Indicates that type is converted into an opaque pointer when crossing the FFI boundary
// TODO: Make it unsafe?
pub trait Opaque {}

impl<T: Opaque> IntoFfi for &T {
    type FfiType = *const T;

    fn into_ffi(self) -> Self::FfiType {
        self as Self::FfiType
    }
}

impl<T: Opaque> IntoFfi for &mut T {
    type FfiType = *mut T;

    fn into_ffi(self) -> Self::FfiType {
        self as Self::FfiType
    }
}

impl<'a, T: Opaque> TryFromFfi for &'a T {
    unsafe fn try_from_ffi(source: <Self as IntoFfi>::FfiType) -> Result<Self, FfiResult> {
        source.as_ref().ok_or(FfiResult::ArgIsNull)
    }
}

impl<'a, T: Opaque> TryFromFfi for &'a mut T {
    unsafe fn try_from_ffi(source: <Self as IntoFfi>::FfiType) -> Result<Self, FfiResult> {
        source.as_mut().ok_or(FfiResult::ArgIsNull)
    }
}

/// Conversion into an FFI compatible representation that consumes the input value
pub trait IntoFfi {
    /// FFI compatible representation of `Self`
    type FfiType;

    /// Performs the conversion
    fn into_ffi(self) -> Self::FfiType;
}

/// Conversion from an FFI compatible representation that consumes the input value
pub trait TryFromFfi: IntoFfi + Sized {
    /// Performs the fallible conversion
    ///
    /// # Errors
    ///
    /// * given pointer is null
    /// * given id doesn't identify any known handle
    /// * given id is not a valid enum discriminant
    ///
    /// # Safety
    ///
    /// All conversions from a pointer must ensure pointer validity beforehand
    #[allow(unsafe_code)]
    unsafe fn try_from_ffi(source: <Self as IntoFfi>::FfiType) -> Result<Self, FfiResult>;
}

/// FFI compatible tuple with 2 elements
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Pair<K, V>(pub K, pub V);

/// Result of execution of an FFI function
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
// NOTE: Enum is `repr(i32)` becasuse WebAssembly supports only
// u32/i32, u64/i64 natively. Otherwise, `repr(i8)` would suffice
#[repr(i32)]
pub enum FfiResult {
    /// Indicates that the FFI function execution panicked
    UnrecoverableError = -5_i32,
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

impl From<opaque_pointer::error::PointerError> for FfiResult {
    fn from(source: opaque_pointer::error::PointerError) -> Self {
        use opaque_pointer::error::PointerError::*;

        match source {
            // TODO: Implement error handling (https://github.com/hyperledger/iroha/issues/2252)
            Utf8Error(_) => Self::Utf8Error,
            Null => Self::ArgIsNull,
            Invalid => Self::UnknownHandle,
        }
    }
}

pub trait OptionWrapped: Sized {
    type FfiType;

    fn into_ffi(source: Option<Self>) -> Self::FfiType;
}

impl<'a, T: Opaque> OptionWrapped for &'a T {
    type FfiType = *const T;

    fn into_ffi(source: Option<Self>) -> Self::FfiType {
        source.map_or_else(core::ptr::null, IntoFfi::into_ffi)
    }
}

impl<'a, T: Opaque> OptionWrapped for &'a mut T {
    type FfiType = *mut T;

    fn into_ffi(source: Option<Self>) -> Self::FfiType {
        source.map_or_else(core::ptr::null_mut, IntoFfi::into_ffi)
    }
}

impl<T: OptionWrapped> IntoFfi for Option<T> {
    type FfiType = T::FfiType;

    fn into_ffi(self) -> Self::FfiType {
        OptionWrapped::into_ffi(self)
    }
}

#[repr(C)]
pub struct FfiSlice<T>(*const T, usize);

#[repr(C)]
pub struct FfiSliceMut<T>(*mut T, usize);

impl<T> Drop for FfiSliceMut<T> {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe { core::slice::from_raw_parts_mut(self.0, self.1) };
        }
    }
}

impl<T> Drop for FfiSlice<T> {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe { core::slice::from_raw_parts(self.0, self.1) };
        }
    }
}

// TODO:
//impl<'a, T> From<&'a [T]> for FfiSlice<T> where &'a T: IntoFfi {
//    fn from(source: &'a [T]) -> Self {
//        let source: Vec<_> = source.iter().map(IntoFfi::into_ffi).collect();
//        FfiSlice(source.as_ptr() as *const _, source.len())
//    }
//}

impl<'a, T> IntoFfi for &'a [T]
where
    &'a T: IntoFfi,
{
    type FfiType = FfiSlice<<&'a T as IntoFfi>::FfiType>;

    fn into_ffi(self) -> Self::FfiType {
        let source: Vec<_> = self.iter().map(IntoFfi::into_ffi).collect();

        let source = core::mem::ManuallyDrop::new(source);
        FfiSlice(source.as_ptr() as *const _, source.len())
    }
}

impl<'a, T> IntoFfi for &'a mut [T]
where
    &'a mut T: IntoFfi,
{
    type FfiType = FfiSliceMut<<&'a mut T as IntoFfi>::FfiType>;

    fn into_ffi(self) -> Self::FfiType {
        let source: Vec<_> = self.iter_mut().map(IntoFfi::into_ffi).collect();

        let mut source = core::mem::ManuallyDrop::new(source);
        FfiSliceMut(source.as_mut_ptr() as *mut _, source.len())
    }
}

impl<'a, T> IntoFfi for Option<&'a [T]>
where
    // TODO: These bounds should be redundant
    &'a [T]: IntoFfi<FfiType = FfiSlice<<&'a T as IntoFfi>::FfiType>>,
    &'a T: IntoFfi,
{
    type FfiType = <&'a [T] as IntoFfi>::FfiType;

    fn into_ffi(self) -> Self::FfiType {
        // TODO: size should be uninitialized and not 0 as if it were and empty slice
        self.map_or_else(|| FfiSlice(core::ptr::null(), 0), IntoFfi::into_ffi)
    }
}

impl<'a, T> IntoFfi for Option<&'a mut [T]>
where
    // TODO: These bounds should be redundant
    &'a mut [T]: IntoFfi<FfiType = FfiSlice<<&'a mut T as IntoFfi>::FfiType>>,
    &'a mut T: IntoFfi,
{
    type FfiType = <&'a mut [T] as IntoFfi>::FfiType;

    fn into_ffi(self) -> Self::FfiType {
        // TODO: size should be uninitialized and not 0 as if it were and empty slice
        self.map_or_else(|| FfiSlice(core::ptr::null_mut(), 0), IntoFfi::into_ffi)
    }
}

/// Implement [`Handle`] for given types with first argument as the initial handle id.
#[macro_export]
macro_rules! handles {
    ( $id:expr, $ty:ty $(, $other:ty)* $(,)? ) => {
        impl $crate::Handle for $ty {
            const ID: $crate::HandleId = $id;
        }

        $crate::handles! {$id + 1, $( $other, )*}
    };
    ( $id:expr, $(,)? ) => {};
}

/// Generate FFI equivalent implementation of the requested trait method (e.g. Clone, Eq, Ord)
#[macro_export]
macro_rules! gen_ffi_impl {
    (@catch_unwind $block:block ) => {
        match std::panic::catch_unwind(|| $block) {
            Ok(res) => match res {
                Ok(()) => $crate::FfiResult::Ok,
                Err(err) => err.into(),
            },
            Err(_) => {
                // TODO: Implement error handling (https://github.com/hyperledger/iroha/issues/2252)
                $crate::FfiResult::UnrecoverableError
            },
        }
    };
    ( $vis:vis Clone: $( $other:ty ),+ $(,)? ) => {
        /// FFI function equivalent of [`Clone::clone`]
        ///
        /// # Safety
        ///
        /// All of the given pointers must be valid and the given handle id must match the expected
        /// pointer type
        #[no_mangle]
        $vis unsafe extern "C" fn __clone(
            handle_id: $crate::HandleId,
            handle_ptr: *const core::ffi::c_void,
            output_ptr: *mut *mut core::ffi::c_void
        ) -> $crate::FfiResult {
            use iroha_ffi::opaque_pointer;

            gen_ffi_impl!(@catch_unwind {
                match handle_id {
                    $( <$other as $crate::Handle>::ID => {
                        let handle_ptr = handle_ptr.cast::<$other>();
                        let handle = opaque_pointer::object(handle_ptr).map_err::<$crate::FfiResult, _>(From::from)?;
                        let new_handle = opaque_pointer::raw(Clone::clone(handle));

                        output_ptr.write(new_handle.cast());
                    } )+
                    // TODO: Implement error handling (https://github.com/hyperledger/iroha/issues/2252)
                    _ => return Err($crate::FfiResult::UnknownHandle),
                }

                Ok(())
            })
        }
    };
    ( $vis:vis Eq: $( $other:ty ),+ $(,)? ) => {
        /// FFI function equivalent of [`Eq::eq`]
        ///
        /// # Safety
        ///
        /// All of the given pointers must be valid and the given handle id must match the expected
        /// pointer type
        #[no_mangle]
        $vis unsafe extern "C" fn __eq(
            handle_id: $crate::HandleId,
            left_handle_ptr: *const core::ffi::c_void,
            right_handle_ptr: *const core::ffi::c_void,
            output_ptr: *mut bool,
        ) -> $crate::FfiResult {
            use iroha_ffi::opaque_pointer;

            gen_ffi_impl!(@catch_unwind {
                match handle_id {
                    $( <$other as $crate::Handle>::ID => {
                        let (lhandle_ptr, rhandle_ptr) = (left_handle_ptr.cast::<$other>(), right_handle_ptr.cast::<$other>());
                        let left_handle = opaque_pointer::object(lhandle_ptr).map_err::<$crate::FfiResult, _>(From::from)?;
                        let right_handle = opaque_pointer::object(rhandle_ptr).map_err::<$crate::FfiResult, _>(From::from)?;

                        output_ptr.write(left_handle == right_handle);
                    } )+
                    // TODO: Implement error handling (https://github.com/hyperledger/iroha/issues/2252)
                    _ => return Err($crate::FfiResult::UnknownHandle),
                }

                Ok(())
            })
        }
    };
    ( $vis:vis Ord: $( $other:ty ),+ $(,)? ) => {
        /// FFI function equivalent of [`Ord::ord`]
        ///
        /// # Safety
        ///
        /// All of the given pointers must be valid and the given handle id must match the expected
        /// pointer type
        #[no_mangle]
        $vis unsafe extern "C" fn __ord(
            handle_id: $crate::HandleId,
            left_handle_ptr: *const core::ffi::c_void,
            right_handle_ptr: *const core::ffi::c_void,
            output_ptr: *mut core::cmp::Ordering,
        ) -> $crate::FfiResult {
            gen_ffi_impl!(@catch_unwind {
                use iroha_ffi::opaque_pointer;

                match handle_id {
                    $( <$other as $crate::Handle>::ID => {
                        let (lhandle_ptr, rhandle_ptr) = (left_handle_ptr.cast::<$other>(), right_handle_ptr.cast::<$other>());
                        let left_handle = opaque_pointer::object(lhandle_ptr).map_err::<$crate::FfiResult, _>(From::from)?;
                        let right_handle = opaque_pointer::object(rhandle_ptr).map_err::<$crate::FfiResult, _>(From::from)?;

                        output_ptr.write(left_handle.cmp(right_handle));
                    } )+
                    // TODO: Implement error handling (https://github.com/hyperledger/iroha/issues/2252)
                    _ => return Err($crate::FfiResult::UnknownHandle),
                }

                Ok(())
            })
        }
    };
    ( $vis:vis Drop: $( $other:ty ),+ $(,)? ) => {
        /// FFI function equivalent of [`Drop::drop`]
        ///
        /// # Safety
        ///
        /// All of the given pointers must be valid and the given handle id must match the expected
        /// pointer type
        #[no_mangle]
        $vis unsafe extern "C" fn __drop(
            handle_id: $crate::HandleId,
            handle_ptr: *mut core::ffi::c_void,
        ) -> $crate::FfiResult {
            use iroha_ffi::opaque_pointer;

            gen_ffi_impl!(@catch_unwind {
                match handle_id {
                    $( <$other as $crate::Handle>::ID => {
                        let handle_ptr = handle_ptr.cast::<$other>();
                        opaque_pointer::own_back(handle_ptr).map_err::<$crate::FfiResult, _>(From::from)?;
                    } )+
                    // TODO: Implement error handling (https://github.com/hyperledger/iroha/issues/2252)
                    _ => return Err($crate::FfiResult::UnknownHandle),
                }

                Ok(())
            })
        }
    };
}
