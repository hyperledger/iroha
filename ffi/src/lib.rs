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

const NONE: isize = -1;

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

pub trait OptionWrapped: Sized {
    type FfiType;

    fn into_ffi(source: Option<Self>) -> Self::FfiType;
}

/// Conversion into an FFI compatible representation that consumes the input value
pub trait IntoFfi {
    /// FFI compatible representation of `Self`
    type FfiType;

    /// FFI compatible representation of `Self` when it's an out-pointer
    type OutFfiType;

    /// Performs the conversion
    fn into_ffi(self) -> Self::FfiType;

    /// Performs the conversion and writes the result into out-pointer
    unsafe fn write_out(self, out: Self::OutFfiType);
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
    unsafe fn try_from_ffi(source: Self::FfiType) -> Result<Self, FfiResult>;
}

/// FFI compatible tuple with 2 elements
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct Pair<K, V>(pub K, pub V);

pub struct IteratorWrapper<T: IntoIterator>(T);

#[derive(Clone)]
#[repr(C)]
pub struct BoxedSlice<T: IntoFfi>(*mut <T as IntoFfi>::FfiType, usize);

#[derive(Clone, Copy)]
#[repr(C)]
// NOTE: Returned size is isize to be able to support Option<&[T]>
pub struct OutSlice<T: IntoFfi>(*mut <T as IntoFfi>::FfiType, usize, *mut isize);

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

impl<T: Opaque> IntoFfi for &T {
    type FfiType = *const T;
    type OutFfiType = *mut Self::FfiType;

    fn into_ffi(self) -> Self::FfiType {
        self as Self::FfiType
    }

    unsafe fn write_out(self, out: Self::OutFfiType) {
        out.write(self.into_ffi())
    }
}

impl<T: Opaque> IntoFfi for &mut T {
    type FfiType = *mut T;
    type OutFfiType = *mut Self::FfiType;

    fn into_ffi(self) -> Self::FfiType {
        self as Self::FfiType
    }

    unsafe fn write_out(self, out: Self::OutFfiType) {
        out.write(self.into_ffi())
    }
}

impl<'a, T: Opaque> TryFromFfi for &'a T {
    unsafe fn try_from_ffi(source: Self::FfiType) -> Result<Self, FfiResult> {
        source.as_ref().ok_or(FfiResult::ArgIsNull)
    }
}

impl<'a, T: Opaque> TryFromFfi for &'a mut T {
    unsafe fn try_from_ffi(source: Self::FfiType) -> Result<Self, FfiResult> {
        source.as_mut().ok_or(FfiResult::ArgIsNull)
    }
}

impl<'a, T: IntoIterator<Item = U>, U: IntoFfi> IntoFfi for IteratorWrapper<T> {
    type FfiType = BoxedSlice<U>;
    type OutFfiType = OutSlice<U>;

    fn into_ffi(self) -> Self::FfiType {
        BoxedSlice::from_iter(self.0)
    }

    unsafe fn write_out(self, out: Self::OutFfiType) {
        let slice = self.into_ffi();

        out.2
            .write(slice.len().try_into().expect("allocation too large"));
        for (i, elem) in slice.into_iter().take(out.1).enumerate() {
            let offset = i.try_into().expect("allocation too large");
            out.0.offset(offset).write(elem);
        }
    }
}

impl IntoFfi for &u8 {
    type FfiType = *const u8;
    type OutFfiType = *mut Self::FfiType;

    fn into_ffi(self) -> Self::FfiType {
        self as *const _
    }

    unsafe fn write_out(self, out: Self::OutFfiType) {
        out.write(self.into_ffi())
    }
}

impl IntoFfi for u8 {
    type FfiType = Self;
    type OutFfiType = *mut Self::FfiType;

    fn into_ffi(self) -> Self::FfiType {
        self
    }

    unsafe fn write_out(self, out: Self::OutFfiType) {
        out.write(self.into_ffi())
    }
}

impl TryFromFfi for u8 {
    unsafe fn try_from_ffi(source: Self::FfiType) -> Result<Self, FfiResult> {
        Ok(source)
    }
}

impl IntoFfi for bool {
    type FfiType = u8;
    type OutFfiType = *mut Self::FfiType;

    fn into_ffi(self) -> Self::FfiType {
        IntoFfi::into_ffi(self as u8)
    }

    unsafe fn write_out(self, out: Self::OutFfiType) {
        out.write(self.into_ffi())
    }
}

impl TryFromFfi for bool {
    unsafe fn try_from_ffi(source: Self::FfiType) -> Result<Self, FfiResult> {
        Ok(source != 0)
    }
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
    type OutFfiType = *mut Self::FfiType;

    fn into_ffi(self) -> Self::FfiType {
        OptionWrapped::into_ffi(self)
    }

    unsafe fn write_out(self, out: Self::OutFfiType) {
        out.write(self.into_ffi())
    }
}

impl<U: IntoFfi> FromIterator<U> for BoxedSlice<U> {
    fn from_iter<T: IntoIterator<Item = U>>(iter: T) -> Self {
        let source: Box<[_]> = iter.into_iter().map(IntoFfi::into_ffi).collect();
        let mut source = core::mem::ManuallyDrop::new(source);
        Self(source.as_mut_ptr(), source.len())
    }
}

impl<T: IntoFfi> BoxedSlice<T> {
    fn null() -> Self {
        // TODO: size should be uninitialized and never read from
        Self(core::ptr::null_mut(), 0)
    }

    fn is_null(&self) -> bool {
        self.0.is_null()
    }

    fn len(&self) -> usize {
        self.1
    }
}

impl<T: IntoFfi> IntoIterator for BoxedSlice<T> {
    type Item = T::FfiType;
    type IntoIter = <Vec<Self::Item> as IntoIterator>::IntoIter;

    fn into_iter(self) -> Self::IntoIter {
        let slice = unsafe {
            Box::<[_]>::from_raw(core::slice::from_raw_parts_mut(self.0, self.1)).into_vec()
        };

        slice.into_iter()
    }
}

#[cfg(not(feature = "client"))]
impl<T: IntoFfi> Drop for BoxedSlice<T> {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe {
                Box::<[_]>::from_raw(core::slice::from_raw_parts_mut(self.0, self.1));
            };
        }
    }
}

impl<T: IntoFfi> OutSlice<T> {
    unsafe fn write_null(self) {
        self.2.write(NONE);
    }
}

impl<'a, T> IntoFfi for &'a [T]
where
    &'a T: IntoFfi,
{
    type FfiType = BoxedSlice<&'a T>;
    type OutFfiType = OutSlice<&'a T>;

    fn into_ffi(self) -> Self::FfiType {
        IteratorWrapper(self).into_ffi()
    }

    unsafe fn write_out(self, out: Self::OutFfiType) {
        IteratorWrapper(self).write_out(out)
    }
}

impl<'a, T> IntoFfi for &'a mut [T]
where
    &'a mut T: IntoFfi,
{
    type FfiType = BoxedSlice<&'a mut T>;
    type OutFfiType = OutSlice<&'a mut T>;

    fn into_ffi(self) -> Self::FfiType {
        IteratorWrapper(self).into_ffi()
    }

    unsafe fn write_out(self, out: Self::OutFfiType) {
        IteratorWrapper(self).write_out(out)
    }
}

impl<'a, T> TryFromFfi for &'a [T]
where
    &'a T: IntoFfi,
{
    unsafe fn try_from_ffi(source: Self::FfiType) -> Result<Self, FfiResult> {
        if source.is_null() {
            return Err(FfiResult::ArgIsNull);
        }

        // TODO: Not good
        Ok(core::slice::from_raw_parts(source.0 as *const _, source.1))
    }
}

impl<'a, T> TryFromFfi for &'a mut [T]
where
    &'a mut T: TryFromFfi,
{
    unsafe fn try_from_ffi(source: Self::FfiType) -> Result<Self, FfiResult> {
        if source.is_null() {
            return Err(FfiResult::ArgIsNull);
        }

        unimplemented!()
        //core::slice::from_raw_parts_mut(source.0, source.1).into_iter().map(TryFromFfi::try_from_ffi).collect()
    }
}

impl<'a, T> IntoFfi for Option<&'a [T]>
where
    &'a [T]: IntoFfi<FfiType = BoxedSlice<&'a T>, OutFfiType = OutSlice<&'a T>>,
    &'a T: IntoFfi,
{
    type FfiType = <&'a [T] as IntoFfi>::FfiType;
    type OutFfiType = <&'a [T] as IntoFfi>::OutFfiType;

    fn into_ffi(self) -> Self::FfiType {
        self.map_or_else(BoxedSlice::null, |item| IteratorWrapper(item).into_ffi())
    }

    unsafe fn write_out(self, out: Self::OutFfiType) {
        if let Some(item) = self {
            <&'a [T]>::write_out(item, out);
        } else {
            out.write_null()
        }
    }
}

impl<'a, T> IntoFfi for Option<&'a mut [T]>
where
    &'a mut [T]: IntoFfi<FfiType = BoxedSlice<&'a mut T>, OutFfiType = OutSlice<&'a mut T>>,
    &'a mut T: IntoFfi,
{
    type FfiType = <&'a mut [T] as IntoFfi>::FfiType;
    type OutFfiType = <&'a mut [T] as IntoFfi>::OutFfiType;

    fn into_ffi(self) -> Self::FfiType {
        self.map_or_else(BoxedSlice::null, |item| IteratorWrapper(item).into_ffi())
    }

    unsafe fn write_out(self, out: Self::OutFfiType) {
        if let Some(item) = self {
            <&'a mut [T]>::write_out(item, out);
        } else {
            out.write_null()
        }
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
