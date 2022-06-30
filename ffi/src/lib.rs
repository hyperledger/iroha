//! Structures, macros related to FFI and generation of FFI bindings.
//! [Non-robust types](https://anssi-fr.github.io/rust-guide/07_ffi.html#non-robust-types-references-function-pointers-enums)
//! are strictly avoided in the FFI API
//!
//! # Conversions:
//! owned type -> opaque pointer
//! reference -> raw pointer
//!
//! enum -> int
//! bool -> u8
//!
//! # Conversions (WebAssembly):
//! u8, u16 -> u32
//! i8, i16 -> i32

use core::marker::PhantomData;
use std::borrow::{Borrow, BorrowMut};

pub use iroha_ffi_derive::*;

pub mod handle;
pub mod opaque;
mod primitives;
pub mod slice;

/// Represents handle in an FFI context
///
/// # Safety
///
/// If two structures implement the same id, this may result in void pointer being casted to the wrong type
pub unsafe trait Handle {
    /// Unique identifier of the handle. Most commonly, it is
    /// used to facilitate generic monomorphization over FFI
    const ID: handle::Id;
}

/// Robust type which conforms to C ABI and can be safely shared across FFI boundaries. This does
/// not ensure the ABI of the referent for pointers in which case the pointer should be made opaque
///
/// # Safety
///
/// Type implementing the trait must be a robust type with a guaranteed C ABI
pub unsafe trait ReprC {}

pub trait FfiType: Sized {
    /// Robust C ABI compliant representation of [`Self`]
    type FfiType: ReprC;
}

pub trait FfiRef {
    /// Robust C ABI compliant representation of [`&Self`]
    type FfiRef: ReprC;

    /// Robust C ABI compliant representation of [`&mut Self`]
    type FfiMut: ReprC;
}

/// Conversion into an FFI compatible representation that consumes the input value
///
// TODO: Make it an unsafe trait?
pub trait IntoFfi: FfiType {
    type Item: Into<Self::FfiType>;

    /// Performs the conversion from [`Self`] into [`Self::FfiType`]
    fn into_ffi(self) -> Self::Item;
}

/// Conversion from an FFI compatible representation that consumes the input value
// TODO: Make it an unsafe trait?
pub trait TryFromFfi: FfiType {
    type Item: Into<Self>;

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
    unsafe fn try_from_ffi(source: Self::FfiType) -> Result<Self::Item, FfiResult>;
}

// TODO: Make it an unsafe trait?
pub trait FromOption: OptionWrapped + IntoFfi {
    /// Performs the conversion from [Option<`Self`>] into [`<Self as FromOption>::FfiType`]
    fn into_ffi(source: Option<Self>) -> <Self as OptionWrapped>::FfiType;
}

pub trait FfiWriteOut {
    /// Type used to represent Rust function output as an argument in an FFI function. Must be a repr(C) as well
    type OutPtr: ReprC;

    /// Write [`Self`] into [`Self::OutPtr`]
    unsafe fn write(self, dest: Self::OutPtr);
}

pub trait FfiBorrow {
    type Borrowed: ReprC;
    fn borrow(&self) -> Self::Borrowed;
}

pub trait FfiBorrowMut {
    type Borrowed: ReprC;
    fn borrow_mut(&mut self) -> Self::Borrowed;
}

pub trait AsFfi: FfiRef {
    type ItemRef: FfiBorrow;
    type ItemMut: FfiBorrowMut;

    /// Performs the conversion of shared reference into an FFI equivalent representation
    fn as_ffi_ref(&self) -> Self::ItemRef;

    /// Performs the conversion of mutable reference into an FFI equivalent representation
    fn as_ffi_mut(&mut self) -> Self::ItemMut;
}

pub trait TryAsRust<'itm>: FfiRef {
    type ItemRef: Borrow<Self> + 'itm;
    type ItemMut: BorrowMut<Self> + 'itm;

    /// Performs the fallible conversion from FFI equivalent into shared reference
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
    unsafe fn try_as_rust_ref(source: Self::FfiRef) -> Result<Self::ItemRef, FfiResult>;

    /// Performs the fallible conversion from FFI equivalent into mutable reference
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
    unsafe fn try_as_rust_mut(source: Self::FfiMut) -> Result<Self::ItemMut, FfiResult>;
}

pub trait OptionWrapped: FfiType {
    /// Robust C ABI compliant representation of [Option<`Self`>]
    type FfiType: ReprC;
}

pub struct Boxed<T>(Box<T>);

pub struct IntoWrapper<T: Into<U>, U>(T, PhantomData<U>);

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

impl<T> FfiBorrow for *const T {
    type Borrowed = Self;

    #[inline]
    fn borrow(&self) -> Self::Borrowed {
        *self
    }
}

impl<T> FfiBorrowMut for *mut T {
    type Borrowed = Self;

    #[inline]
    fn borrow_mut(&mut self) -> Self::Borrowed {
        *self
    }
}

impl<T: ReprC> FfiBorrow for Boxed<T> {
    type Borrowed = *const T;

    #[inline]
    fn borrow(&self) -> Self::Borrowed {
        <*const _>::from(self.0.as_ref())
    }
}

impl<T: ReprC> FfiBorrowMut for Boxed<T> {
    type Borrowed = *mut T;

    #[inline]
    fn borrow_mut(&mut self) -> Self::Borrowed {
        <*mut _>::from(self.0.as_mut())
    }
}


unsafe impl<T> ReprC for *const T {}
impl<T> FfiWriteOut for *const T {
    type OutPtr = *mut Self;

    unsafe fn write(self, dest: Self::OutPtr) {
        dest.write(self)
    }
}

unsafe impl<T> ReprC for *mut T {}
impl<T> FfiWriteOut for *mut T {
    type OutPtr = *mut Self;

    unsafe fn write(self, dest: Self::OutPtr) {
        dest.write(self)
    }
}

impl<T: ReprC> FfiWriteOut for Boxed<T> {
    type OutPtr = *mut T;

    unsafe fn write(self, dest: Self::OutPtr) {
        dest.write(*self.0);
    }
}

//impl<'slice, T: ?Sized> IntoFfi for &'slice T
//where
//    &'slice T: FfiType<FfiType = T::FfiRef>,
//{
//    fn into_ffi(self) -> Self::FfiType {
//        self.as_ffi_ref()
//    }
//}
//
//impl<'slice, T: ?Sized> IntoFfi for &'slice mut T
//where
//    &'slice mut T: FfiType<FfiType = T::FfiMut>,
//    T: AsFfi,
//{
//    fn into_ffi(self) -> Self::FfiType {
//        self.as_ffi_mut()
//    }
//}

//impl<'s, T: AsFfi<Store = ()>> IntoFfi for &'s mut [T]
//where
//    &'s mut T: FfiType<FfiType = T::FfiMut>,
//{
//    fn into_ffi(self) -> Self::FfiType {
//        self.as_ffi_mut(&mut ())
//    }
//}
//
//impl<'store, T: Into<U> + 'store, U: IntoFfi<'store>> IntoFfi<'store> for IntoWrapper<T, U> {
//    type FfiType = U::FfiType;
//    type Store = U::Store;
//
//    fn into_ffi(self, store: &'store mut Self::Store) -> Self::FfiType {
//        self.0.into().into_ffi(store)
//    }
//}
//
//impl<'store, T, U> FromOption<'store> for &'store T
//where
//    Self: IntoFfi<FfiType = *const U>,
//{
//    type Store = <Self as IntoFfi<'store>>::Store;
//
//    fn into_ffi(
//        source: Option<Self>,
//        store: &'store mut <Self as FromOption<'store>>::Store,
//    ) -> <Self as OptionWrapped>::FfiType {
//        source.map_or_else(core::ptr::null, |item| IntoFfi::into_ffi(item, store))
//    }
//}
//
//impl<'store, T, U> FromOption<'store> for &'store mut T
//where
//    Self: IntoFfi<'store, FfiType = *mut U>,
//{
//    type Store = <Self as IntoFfi<'store>>::Store;
//
//    fn into_ffi(
//        source: Option<Self>,
//        store: &'store mut <Self as FromOption<'store>>::Store,
//    ) -> <Self as OptionWrapped>::FfiType {
//        source.map_or_else(core::ptr::null_mut, |item| IntoFfi::into_ffi(item, store))
//    }
//}

impl<T> OptionWrapped for &T
where
    Self: FfiType,
{
    type FfiType = <Self as FfiType>::FfiType;
}

impl<T> OptionWrapped for &mut T
where
    Self: FfiType,
{
    type FfiType = <Self as FfiType>::FfiType;
}

impl<T: OptionWrapped> FfiType for Option<T> {
    type FfiType = <T as OptionWrapped>::FfiType;
}

//impl<'store, T: FromOption<'store>> IntoFfi for Option<T>
//where
//    <T as FromOption<'store>>::Store: Default,
//{
//    fn into_ffi(self) -> Self::FfiType {
//        // TODO: Fix this
//        let store = Default::default();
//        FromOption::into_ffi(self, &mut store)
//    }
//}

//impl<'store, T> TryFromFfi<'store> for &'store [T]
//where
//    &'store T: TryFromFfi<'store>,
//    <&'store T as IntoFfi<'store>>::FfiType: Copy,
//{
//    type Store = Vec<<&'store T as TryFromFfi<'store>>::Store>;
//
//    unsafe fn try_from_ffi(
//        source: Self::FfiType,
//        store: &'store mut Self::Store,
//    ) -> Result<Self, FfiResult> {
//        if source.is_null() {
//            return Err(FfiResult::ArgIsNull);
//        }
//
//        let slice: &'store [<&'store T as IntoFfi<'store>>::FfiType] =
//            core::slice::from_raw_parts(source.0, source.1);
//
//        //for item in slice {
//        //    store.push(Default::default());
//        //    let inner_store = store.last_mut().expect("Defined");
//        //    let ffi_ty = <&'store T as TryFromFfi<'store>>::try_from_ffi(*item, inner_store);
//        //}
//
//        unimplemented!("TODO")
//        //if let Some(first) = iter.next() {
//        //    let first: &_ = first?;
//        //    let first: *const _ = first;
//        //    return Ok(core::slice::from_raw_parts(first, source.1));
//        //}
//
//        //return Ok(, 0);
//    }
//}

//impl<'store, T> TryFromFfi<'store> for Option<&'store [T]>
//where
//    &'store [T]: TryFromFfi<'store, FfiType = SliceRef<'store, <&'store T as IntoFfi<'store>>::FfiType>>,
//    &'store T: TryFromFfi<'store>,
//    <&'store T as IntoFfi<'store>>::FfiType: ReprC,
//{
//    type Store = <&'store [T] as TryFromFfi<'store>>::Store;
//
//    unsafe fn try_from_ffi(
//        source: Self::FfiType,
//        store: &'store mut Self::Store,
//    ) -> Result<Self, FfiResult> {
//        Ok(if !source.is_null() {
//            Some(TryFromFfi::try_from_ffi(source, store)?)
//        } else {
//            None
//        })
//    }
//}
//
//impl<'store, T> TryFromFfi<'store> for Option<&'store mut [T]>
//where
//    &'store mut [T]:
//        TryFromFfi<'store, FfiType = SliceMut<'store, <&'store mut T as IntoFfi<'store>>::FfiType>>,
//    &'store mut T: TryFromFfi<'store>,
//    <&'store mut T as IntoFfi<'store>>::FfiType: ReprC,
//{
//    type Store = <&'store mut [T] as TryFromFfi<'store>>::Store;
//
//    unsafe fn try_from_ffi(
//        source: Self::FfiType,
//        store: &'store mut Self::Store,
//    ) -> Result<Self, FfiResult> {
//        Ok(if !source.is_null() {
//            Some(TryFromFfi::try_from_ffi(source, store)?)
//        } else {
//            None
//        })
//    }
//}

macro_rules! impl_tuples {
    ( $( ($( $ty:ident ),+ $(,)?) -> $ffi_ty:ident ),+ $(,)?) => { $(
        /// FFI compatible tuple with n elements
        #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
        #[repr(C)]
        pub struct $ffi_ty<$($ty: FfiType),+>($($ty::FfiType),+);

        unsafe impl<$($ty: FfiType),+> ReprC for $ffi_ty<$($ty),+> {}
        impl<$($ty: FfiType),+> FfiWriteOut for $ffi_ty<$($ty),+> {
            type OutPtr = *mut Self;

            unsafe fn write(self, dest: Self::OutPtr) {
                dest.write(self)
            }
        }

        impl<$($ty: FfiType),+> FfiType for ($( $ty, )+) {
            type FfiType = $ffi_ty<$($ty),+>;
        }

        impl<$($ty: FfiRef),+> FfiRef for ($( $ty, )+) {
            type FfiRef = *const Self;
            type FfiMut = *mut Self;
        }

        #[allow(non_snake_case)]
        impl<$($ty),+> IntoFfi for ($( $ty, )+) where $( $ty: IntoFfi ),+ {
            type Item = Self::FfiType;

            fn into_ffi(self) -> Self::Item {
                let ($($ty,)+) = self;

                $ffi_ty::<$($ty),+>($( <$ty as IntoFfi>::into_ffi($ty).into()),+)
            }
        }
    )+ }

        // TODO: Add implementations for references
        //impl<$($ty),+> AsFfi for ($( $ty, )+) where $( $ty: AsFfi ),+ {
        //    type Store = ($($ty::Store,)+);

        //    #[allow(non_snake_case)]
        //    fn as_ffi_ref<'store>(&'store self, store: &'store mut Self::Store) -> Self::FfiRef {
        //        mod private {
        //            // NOTE: This is a trick to index tuples
        //            pub struct Store<'tup, $($ty: super::AsFfi),+>{
        //                $(pub $ty: &'tup mut $ty::Store),+
        //            }

        //            impl<'store, 'tup, $($ty: super::AsFfi),+> From<&'tup mut ($($ty::Store,)+)> for Store<'tup, $($ty),+> {
        //                fn from(($($ty,)+): &'tup mut ($($ty::Store,)+)) -> Self {
        //                    Self {$($ty,)+}
        //                }
        //            }
        //        }

        //        let ($($ty,)+) = self;
        //        let store: private::Store<$($ty),+> = store.into();

        //        $ffi_ty::<$($ty),+>($( <$ty as AsFfi>::as_ffi($ty, store.$ty)),+)
        //    }
}

impl_tuples! {
    (A) -> FfiTuple1,
    (A, B) -> FfiTuple2,
    (A, B, C) -> FfiTuple3,
    (A, B, C, D) -> FfiTuple4,
    (A, B, C, D, E) -> FfiTuple5,
    (A, B, C, D, E, F) -> FfiTuple6,
    (A, B, C, D, E, F, G) -> FfiTuple7,
    (A, B, C, D, E, F, G, H) -> FfiTuple8,
    (A, B, C, D, E, F, G, H, I) -> FfiTuple9,
    (A, B, C, D, E, F, G, H, I, J) -> FfiTuple10,
}
