#![allow(unsafe_code, clippy::undocumented_unsafe_blocks, clippy::arithmetic)]
#![no_std]

//! Structures, macros related to FFI and generation of FFI bindings.
//! [Non-robust types](https://anssi-fr.github.io/rust-guide/07_ffi.html#non-robust-types-references-function-pointers-enums)
//! are strictly avoided in the FFI API

extern crate alloc;

use alloc::vec::Vec;

pub use iroha_ffi_derive::*;
use owned::Local;

pub mod handle;
pub mod option;
pub mod owned;
mod primitives;
pub mod slice;

/// A specialized `Result` type for FFI operations
pub type Result<T> = core::result::Result<T, FfiReturn>;

/// Represents the handle in an FFI context
///
/// # Safety
///
/// If two structures implement the same id, it may result in a void pointer being casted to the wrong type
pub unsafe trait Handle {
    /// Unique identifier of the handle. Most commonly, it is
    /// used to facilitate generic monomorphization over FFI
    const ID: handle::Id;
}

/// Robust type that conforms to C ABI and can be safely shared across FFI boundaries. This does
/// not guarantee the ABI compatibility of the referent for pointers. These pointers are opaque
///
/// # Safety
///
/// Type implementing the trait must be a robust type with a guaranteed C ABI. Care must be taken
/// not to dereference pointers whose referents don't implement `ReprC`; they are considered opaque
pub unsafe trait ReprC: Sized {}

/// Used to do a cheap reference-to-[`ReprC`]-reference conversion
pub trait AsReprCRef<'itm> {
    /// Robust C ABI compliant representation of &[`Self`]
    type Target: ReprC + 'itm;

    /// Convert from &[`Self`] into [`Self::Target`].
    fn as_ref(&'itm self) -> Self::Target;
}

/// Conversion from a type that implements [`ReprC`].
pub trait TryFromReprC<'itm>: Sized + 'itm {
    /// Robust C ABI compliant representation of [`Self`]
    type Source: ReprC + Copy;

    /// Type into which state can be stored during conversion. Useful for returning
    /// non-owning types but performing some conversion which requires allocation.
    /// Serves similar purpose as does context in a closure
    type Store: Default;

    /// Convert from [`Self::Source`] into [`Self`].
    /// Transferring ownership over FFI is not permitted, except for opaque pointer types
    ///
    /// # Errors
    ///
    /// * [`FfiReturn::ArgIsNull`]          - given pointer is null
    /// * [`FfiReturn::UnknownHandle`]      - given id doesn't identify any known handle
    /// * [`FfiReturn::TrapRepresentation`] - given value contains trap representation
    ///
    /// # Safety
    ///
    /// All conversions from a pointer must ensure pointer validity beforehand
    unsafe fn try_from_repr_c(source: Self::Source, store: &'itm mut Self::Store) -> Result<Self>;
}

/// Conversion into a type that can be converted to an FFI-compatible [`ReprC`] type
/// Except for opaque pointer types, ownership transfer over FFI is not permitted
pub trait IntoFfi: Sized {
    /// The resulting type after conversion
    type Target: ReprC;

    /// Convert from [`Self`] into [`Self::Target`]
    fn into_ffi(self) -> Self::Target;
}

/// Type that can be returned from an FFI function as an out-pointer function argument
pub trait OutPtrOf<T>: ReprC {
    /// Try to write `T` into [`Self`] out-pointer and return whether or not it was successful
    ///
    /// # Errors
    ///
    /// * [`FfiReturn::ArgIsNull`] - if any of the out-pointers in [`Self`] is set to null
    ///
    /// # Safety
    ///
    /// All conversions from a pointer must ensure pointer validity beforehand
    unsafe fn write(self, source: T) -> Result<()>;
}

/// Type that can be returned from an FFI function via out-pointer function argument
pub trait Output: Sized {
    /// Corresponding type of out-pointer
    type OutPtr: OutPtrOf<Self>;
}

/// Result of execution of an FFI function
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i8)]
pub enum FfiReturn {
    /// The input argument provided to FFI function can't be converted into inner rust representation.
    ConversionFailed = -7,
    /// The input argument provided to FFI function has a trap representation.
    TrapRepresentation = -6,
    /// FFI function execution panicked.
    UnrecoverableError = -5,
    /// Provided handle id doesn't match any known handles.
    UnknownHandle = -4,
    /// FFI function failed during the execution of the wrapped method on the provided handle.
    ExecutionFail = -3,
    /// The input argument provided to FFI function is a null pointer.
    ArgIsNull = -2,
    /// The input argument provided to FFI function is not a valid UTF-8 string.
    Utf8Error = -1,
    /// FFI function executed successfully.
    Ok = 0,
}

unsafe impl<T> ReprC for *const T {}
unsafe impl<T> ReprC for *mut T {}

impl<'itm, T: ReprC + Copy + IntoFfi<Target = Self> + 'itm> AsReprCRef<'itm> for T {
    type Target = Self;

    fn as_ref(&self) -> Self::Target {
        *self
    }
}

impl<'itm, T: 'itm> AsReprCRef<'itm> for *const T {
    type Target = Self;

    fn as_ref(&self) -> Self::Target {
        *self
    }
}

impl<'itm, T: ReprC> TryFromReprC<'itm> for &'itm T {
    type Source = *const T;
    type Store = ();

    unsafe fn try_from_repr_c(source: Self::Source, _: &mut ()) -> Result<Self> {
        source.as_ref().ok_or(FfiReturn::ArgIsNull)
    }
}

impl<'itm, T: ReprC> TryFromReprC<'itm> for &'itm mut T {
    type Source = *mut T;
    type Store = ();

    unsafe fn try_from_repr_c(source: Self::Source, _: &mut ()) -> Result<Self> {
        source.as_mut().ok_or(FfiReturn::ArgIsNull)
    }
}

impl<T: ReprC + Copy + IntoFfi<Target = T>> IntoFfi for &T {
    type Target = *const T;

    fn into_ffi(self) -> Self::Target {
        Self::Target::from(self)
    }
}

impl<T: ReprC + Copy + IntoFfi<Target = T>> IntoFfi for &mut T {
    type Target = *mut T;

    fn into_ffi(self) -> Self::Target {
        Self::Target::from(self)
    }
}

impl<T> OutPtrOf<*mut T> for *mut *mut T {
    unsafe fn write(self, source: *mut T) -> Result<()> {
        if self.is_null() {
            return Err(FfiReturn::ArgIsNull);
        }

        self.write(source);
        Ok(())
    }
}

impl<T> OutPtrOf<*const T> for *mut *const T {
    unsafe fn write(self, source: *const T) -> Result<()> {
        if self.is_null() {
            return Err(FfiReturn::ArgIsNull);
        }

        self.write(source);
        Ok(())
    }
}

impl<T: ReprC + IntoFfi<Target = T>> OutPtrOf<T> for *mut T {
    unsafe fn write(self, source: T) -> Result<()> {
        if self.is_null() {
            return Err(FfiReturn::ArgIsNull);
        }

        self.write(source);
        Ok(())
    }
}

impl<T: ReprC + Copy> OutPtrOf<Local<T>> for *mut T {
    unsafe fn write(self, source: Local<T>) -> Result<()> {
        if self.is_null() {
            return Err(FfiReturn::ArgIsNull);
        }

        self.write(source.0);
        Ok(())
    }
}

impl<T> Output for *mut T {
    type OutPtr = *mut *mut T;
}

impl<T> Output for *const T {
    type OutPtr = *mut *const T;
}

impl<T: ReprC + IntoFfi<Target = Self>> Output for T
where
    *mut Self: OutPtrOf<Self>,
{
    type OutPtr = *mut Self;
}

/// Wrapper around struct/enum opaque pointer. When wrapped with the [`ffi`] macro in the
/// crate linking dynamically to some `cdylib`, it replaces struct/enum body definition
#[derive(Debug, Clone, Copy)]
#[repr(transparent)]
pub struct Opaque {
    __data: [u8; 0],

    // Required for !Send & !Sync & !Unpin.
    //
    // - `*mut u8` is !Send & !Sync. It must be in `PhantomData` to not
    //   affect alignment.
    //
    // - `PhantomPinned` is !Unpin. It must be in `PhantomData` because
    //   its memory representation is not considered FFI-safe.
    __marker: core::marker::PhantomData<(*mut u8, core::marker::PhantomPinned)>,
}

/// Trait for `#[repr(transparent)]` structs to convert between [`Self`] and [`Self::Inner`]
///
/// # Safety
/// `Self` and `Self::Inner` must have the same memory layout.
pub unsafe trait Transparent: Sized {
    /// Non-ZST field of transparent struct
    type Inner;

    /// Convert transparent struct into its non-ZST field
    fn into_inner(outer: Self) -> Self::Inner;

    /// Recover transparent struct from its non-ZST field
    fn from_inner(inner: Self::Inner) -> Self;
}

/// Trait for `#[repr(transparent)]` structs to convert between slice of [`Self`] and slice of [`Self::Inner`]
///
/// # Safety
/// `Self` and `Self::Inner` must have the same memory layout.
pub unsafe trait TransparentSlice: Sized {
    /// Non-ZST field of transparent struct
    type Inner;

    /// Convert transparent struct into its non-ZST field
    fn into_inner(outer: &[Self]) -> &[Self::Inner];

    /// Recover transparent struct from its non-ZST field
    fn from_inner(inner: &[Self::Inner]) -> &[Self];
}

/// Trait for `#[repr(transparent)]` structs to convert between vec of [`Self`] and vec of [`Self::Inner`]
///
/// # Safety
/// `Self` and `Self::Inner` must have the same memory layout.
pub unsafe trait TransparentVec: Sized {
    /// Non-ZST field of transparent struct
    type Inner;

    /// Convert transparent struct into its non-ZST field
    fn into_inner(outer: Vec<Self>) -> Vec<Self::Inner>;

    /// Recover transparent struct from its non-ZST field
    fn from_inner(inner: Vec<Self::Inner>) -> Vec<Self>;
}

macro_rules! impl_tuple {
    ( ($( $ty:ident ),+ $(,)?) -> $ffi_ty:ident ) => {
        /// FFI-compatible tuple with n elements
        #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
        #[repr(C)]
        pub struct $ffi_ty<$($ty),+>($(pub $ty),+);

        #[allow(non_snake_case)]
        impl<$($ty),+> From<($( $ty, )*)> for $ffi_ty<$($ty),+> {
            fn from(source: ($( $ty, )*)) -> Self {
                let ($($ty,)+) = source;
                Self($( $ty ),*)
            }
        }

        unsafe impl<$($ty: ReprC),+> ReprC for $ffi_ty<$($ty),+> {}

        impl<'itm, $($ty: ReprC + 'itm),+> AsReprCRef<'itm> for $ffi_ty<$($ty),+> {
            type Target = *const Self;

            fn as_ref(&self) -> Self::Target {
                <*const Self>::from(self)
            }
        }

        impl<'itm, $($ty: TryFromReprC<'itm>),+> TryFromReprC<'itm> for ($($ty,)+) {
            type Source = $ffi_ty<$($ty::Source),+>;
            type Store = ($( $ty::Store, )*);

            #[allow(non_snake_case)]
            unsafe fn try_from_repr_c(source: Self::Source, store: &'itm mut Self::Store) -> Result<Self> {
                impl_tuple! {@decl_priv_mod $($ty),+}

                let $ffi_ty($($ty,)+) = source;
                let store: private::Store<$($ty),+> = store.into();
                Ok(($( <$ty as TryFromReprC>::try_from_repr_c($ty, store.$ty)?, )+))
            }
        }

        impl<$($ty: IntoFfi),+> IntoFfi for ($( $ty, )+) {
            type Target = $ffi_ty<$($ty::Target),+>;

            #[allow(non_snake_case)]
            fn into_ffi(self) -> Self::Target {
                let ($($ty,)+) = self;
                $ffi_ty($( <$ty as IntoFfi>::into_ffi($ty),)+)
            }
        }

        // TODO: With specialization it should be possible to avoid clone
        impl<$($ty: IntoFfi + Clone),+> IntoFfi for &($( $ty, )+) {
            type Target = Local<$ffi_ty<$($ty::Target,)+>>;

            #[allow(non_snake_case)]
            fn into_ffi(self) -> Self::Target {
                let ($($ty,)+) = Clone::clone(self);
                Local::new($ffi_ty($( <$ty as IntoFfi>::into_ffi($ty),)+))
            }
        }

        impl<$($ty: IntoFfi),+> $crate::owned::IntoFfiVec for ($( $ty, )+) {
            type Target = $crate::owned::LocalSlice<<Self as IntoFfi>::Target>;

            fn into_ffi(source: Vec<Self>) -> Self::Target {
                source.into_iter().map(IntoFfi::into_ffi).collect()
            }
        }

        impl<'itm, $($ty: TryFromReprC<'itm>),+> $crate::owned::TryFromReprCVec<'itm> for ($( $ty, )+) {
            type Source = $crate::slice::SliceRef<'itm, <Self as TryFromReprC<'itm>>::Source>;
            type Store = Vec<<Self as TryFromReprC<'itm>>::Store>;

            unsafe fn try_from_repr_c(
                source: Self::Source,
                store: &'itm mut Self::Store,
            ) -> Result<Vec<Self>> {
                let prev_store_len = store.len();
                let slice = source.into_rust().ok_or(FfiReturn::ArgIsNull)?;
                store.extend(core::iter::repeat_with(Default::default).take(slice.len()));

                let mut substore = &mut store[prev_store_len..];
                let mut res = Vec::with_capacity(slice.len());

                let mut i = 0;
                while let Some((first, rest)) = substore.split_first_mut() {
                    res.push(TryFromReprC::try_from_repr_c(slice[i], first)?);
                    substore = rest;
                    i += 1;
                }

                Ok(res)
            }
        }
    };

    // NOTE: This is a trick to index tuples
    ( @decl_priv_mod $( $ty:ident ),+ $(,)? ) => {
        mod private {
            #[allow(non_snake_case)]
            pub struct Store<'itm, $($ty: super::TryFromReprC<'itm>),+>{
                $(pub $ty: &'itm mut $ty::Store),+
            }

            #[allow(non_snake_case)]
            impl<'tup, $($ty: super::TryFromReprC<'tup>),+> From<&'tup mut ($($ty::Store,)+)> for Store<'tup, $($ty),+> {
                fn from(($($ty,)+): &'tup mut ($($ty::Store,)+)) -> Self {
                    Self {$($ty,)+}
                }
            }
        }
    };
}

// TODO: Rewrite via proc macro
impl_tuple! {(A) -> FfiTuple1}
impl_tuple! {(A, B) -> FfiTuple2}
impl_tuple! {(A, B, C) -> FfiTuple3}
impl_tuple! {(A, B, C, D) -> FfiTuple4}
impl_tuple! {(A, B, C, D, E) -> FfiTuple5}
impl_tuple! {(A, B, C, D, E, F) -> FfiTuple6}
impl_tuple! {(A, B, C, D, E, F, G) -> FfiTuple7}
impl_tuple! {(A, B, C, D, E, F, G, H) -> FfiTuple8}
impl_tuple! {(A, B, C, D, E, F, G, H, I) -> FfiTuple9}
impl_tuple! {(A, B, C, D, E, F, G, H, I, J) -> FfiTuple10}
impl_tuple! {(A, B, C, D, E, F, G, H, I, J, K) -> FfiTuple11}
impl_tuple! {(A, B, C, D, E, F, G, H, I, J, K, L) -> FfiTuple12}
