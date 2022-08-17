#![allow(unsafe_code, clippy::undocumented_unsafe_blocks, clippy::arithmetic)]
#![no_std]

//! Structures, macros related to FFI and generation of FFI bindings.
//! [Non-robust types](https://anssi-fr.github.io/rust-guide/07_ffi.html#non-robust-types-references-function-pointers-enums)
//! are strictly avoided in the FFI API

extern crate alloc;

use alloc::vec::Vec;

pub use iroha_ffi_derive::*;

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
pub unsafe trait ReprC: Copy + Sized {}

/// Indicates that the type can be converted into an FFI compatible representation
pub trait FfiType: Sized {
    /// Corresponding FFI-compatible type
    type ReprC: ReprC;
}

/// Marker trait indicating that the type doesn't reference local context
pub unsafe trait NonLocal {}

/// Wrapper indicating that wrapped type references local context. It's main use is to
/// guard against returning output, that references local context, from a function
#[repr(transparent)]
#[derive(Clone, Copy)]
pub struct Local<T>(pub T);

/// Type that can be returned from an FFI function via out-pointer function argument
pub trait Output: ReprC {
    /// Corresponding type of out-pointer
    type OutPtr: OutPtrOf<Self>;
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

/// Conversion from a type that implements [`ReprC`].
pub trait TryFromReprC<'itm>: FfiType + 'itm {
    /// Type into which state can be stored during conversion. Useful for returning
    /// non-owning types but performing some conversion which requires allocation.
    /// Serves similar purpose as does context in a closure
    type Store: Default;

    /// Convert from [`Self::ReprC`] into [`Self`].
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
    unsafe fn try_from_repr_c(source: Self::ReprC, store: &'itm mut Self::Store) -> Result<Self>;
}

/// Conversion into a type that can be converted to an FFI-compatible [`ReprC`] type
/// Except for opaque pointer types, ownership transfer over FFI is not permitted
pub trait IntoFfi: FfiType {
    /// Type into which state can be stored during conversion. Useful for returning
    /// non-owning types but performing some conversion which requires allocation.
    /// Serves similar purpose as does context in a closure
    type Store: Default;

    /// Convert from [`Self`] into [`FfiType::ReprC`]
    fn into_ffi(self, store: &mut Self::Store) -> Self::ReprC;
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
unsafe impl<T: ReprC> ReprC for Local<T> {}

unsafe impl<T: NonLocal> NonLocal for *const T {}
unsafe impl<T: NonLocal> NonLocal for *mut T {}

impl<T: ReprC> FfiType for &T {
    type ReprC = *const T;
}
impl<T: ReprC> FfiType for &mut T {
    type ReprC = *mut T;
}

impl<T: FfiType, E> FfiType for core::result::Result<T, E> {
    type ReprC = T::ReprC;
}

impl<T: NonLocal> Output for *mut T {
    type OutPtr = *mut *mut T;
}
impl<T: NonLocal> Output for *const T {
    type OutPtr = *mut *const T;
}
impl<T: ReprC + FfiType<ReprC = Self>> Output for T {
    type OutPtr = *mut T::ReprC;
}

impl<T: ReprC> OutPtrOf<T> for *mut T {
    unsafe fn write(self, source: T) -> Result<()> {
        if self.is_null() {
            return Err(FfiReturn::ArgIsNull);
        }

        self.write(source);
        Ok(())
    }
}
impl<T: ReprC> OutPtrOf<*mut T> for *mut T {
    unsafe fn write(self, source: *mut T) -> Result<()> {
        if self.is_null() {
            return Err(FfiReturn::ArgIsNull);
        }

        self.write(source.read());
        Ok(())
    }
}
impl<T: ReprC, const N: usize> OutPtrOf<*mut [T; N]> for *mut [T; N] {
    unsafe fn write(self, source: *mut [T; N]) -> Result<()> {
        if self.is_null() {
            return Err(FfiReturn::ArgIsNull);
        }

        for i in 0..N {
            self.add(i).write(source.add(i).read());
        }

        Ok(())
    }
}

impl<'itm, T> TryFromReprC<'itm> for &'itm T
where
    Self: FfiType<ReprC = *const T>,
{
    type Store = ();

    unsafe fn try_from_repr_c(source: Self::ReprC, _: &mut ()) -> Result<Self> {
        source.as_ref().ok_or(FfiReturn::ArgIsNull)
    }
}

impl<'itm, T> TryFromReprC<'itm> for &'itm mut T
where
    Self: FfiType<ReprC = *mut T>,
{
    type Store = ();

    unsafe fn try_from_repr_c(source: Self::ReprC, _: &mut ()) -> Result<Self> {
        source.as_mut().ok_or(FfiReturn::ArgIsNull)
    }
}

impl<T> IntoFfi for &T
where
    Self: FfiType<ReprC = *const T>,
{
    type Store = ();

    fn into_ffi(self, _: &mut Self::Store) -> Self::ReprC {
        Self::ReprC::from(self)
    }
}

impl<T> IntoFfi for &mut T
where
    Self: FfiType<ReprC = *mut T>,
{
    type Store = ();

    fn into_ffi(self, _: &mut Self::Store) -> Self::ReprC {
        Self::ReprC::from(self)
    }
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

macro_rules! impl_tuple {
    ( ($( $ty:ident ),+ $(,)?) -> $ffi_ty:ident ) => {
        /// FFI-compatible tuple with n elements
        #[repr(C)]
        #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
        pub struct $ffi_ty<$($ty),+>($(pub $ty),+);

        #[allow(non_snake_case)]
        impl<$($ty),+> From<($( $ty, )+)> for $ffi_ty<$($ty),+> {
            fn from(source: ($( $ty, )+)) -> Self {
                let ($($ty,)+) = source;
                Self($( $ty ),*)
            }
        }

        unsafe impl<$($ty: ReprC),+> ReprC for $ffi_ty<$($ty),+> {}
        unsafe impl<$($ty: NonLocal),+> NonLocal for $ffi_ty<$($ty,)+> {}

        impl<$($ty: FfiType),+> FfiType for ($($ty,)+) {
            type ReprC = $ffi_ty<$($ty::ReprC),+>;
        }
        impl<$($ty: FfiType),+> FfiType for &($($ty,)+) {
            type ReprC = *const $ffi_ty<$($ty::ReprC),+>;
        }

        impl<$($ty: FfiType),+> owned::FfiVec for ($($ty,)+) {
            type ReprC = $ffi_ty<$($ty::ReprC),+>;
        }

        impl<'itm, $($ty: TryFromReprC<'itm>),+> TryFromReprC<'itm> for ($($ty,)+) {
            type Store = ($( $ty::Store, )+);

            #[allow(non_snake_case)]
            unsafe fn try_from_repr_c(source: Self::ReprC, store: &'itm mut Self::Store) -> Result<Self> {
                impl_tuple! {@decl_priv_mod $($ty),+ for super::TryFromReprC<'itm>}

                let $ffi_ty($($ty,)+) = source;
                let store: private::Store<$($ty),+> = store.into();
                Ok(($( <$ty as TryFromReprC>::try_from_repr_c($ty, store.$ty)?, )+))
            }
        }

        //impl<'itm, $($ty: TryFromReprC<'itm> + Clone),+> owned::TryFromReprCVec<'itm> for ($( $ty, )+) {
        //    type Store = Vec<<Self as TryFromReprC<'itm>>::Store>;

        //    unsafe fn try_from_repr_c(
        //        source: Local<slice::SliceRef<<Self as owned::FfiVec>::ReprC>>,
        //        store: &'itm mut Self::Store,
        //    ) -> Result<Vec<Self>> {
        //        let slice: &[$ffi_ty<$($ty::ReprC,)*>] = source.0.into_rust().ok_or(FfiReturn::ArgIsNull)?;

        //        *store = core::iter::repeat_with(Default::default).take(slice.len()).collect();
        //        let (mut substore, mut res) = (&mut store[..], Vec::with_capacity(slice.len()));

        //        let mut i = 0;
        //        while let Some((first, rest)) = substore.split_first_mut() {
        //            let elem: &$ffi_ty<$($ty::ReprC,)*> = &slice[i];
        //            res.push(Clone::clone(TryFromReprC::try_from_repr_c(elem, first)?));
        //            substore = rest;
        //            i += 1;
        //        }

        //        Ok(res)
        //    }
        //}

        impl<$($ty: IntoFfi),+> IntoFfi for ($( $ty, )+) {
            type Store = ($($ty::Store,)+);

            #[allow(non_snake_case)]
            fn into_ffi(self, store: &mut Self::Store) -> Self::ReprC {
                impl_tuple! {@decl_priv_mod $($ty),+ for super::IntoFfi}

                let ($($ty,)+) = self;
                let store: private::Store<$($ty),+> = store.into();
                $ffi_ty($( <$ty as IntoFfi>::into_ffi($ty, store.$ty),)+)
            }
        }

        //impl<'itm, $($ty),+> IntoFfi for &'itm($( $ty, )+) where $(&'itm $ty: IntoFfi),+, Self: FfiType {
        //    type Store = (
        //        Option<$ffi_ty<$(<&'itm $ty as FfiType>::ReprC,)+>>,
        //        ($(<&'itm $ty as IntoFfi>::Store,)+)
        //    );

        //    #[allow(non_snake_case)]
        //    fn into_ffi(self, store: &mut Self::Store) -> Self::ReprC {
        //        impl_tuple! {@decl_priv_mod_ref $($ty),+ for super::IntoFfi}

        //        let ($($ty,)+) = self;
        //        let store_store: private::Store<$($ty),+> = store.1.into();
        //        store.0.insert($ffi_ty($( <&$ty as IntoFfi>::into_ffi($ty, store_store.$ty),)+))
        //    }
        //}

        //impl<$($ty),+> slice::IntoFfiSliceRef for ($( $ty, )+) where &($($ty,)+): IntoFfi {
        //    type Target = slice::SliceRef<<Self as IntoFfi>::Target>;
        //    type Store = (
        //        Vec<$ffi_ty<$(<&$ty>::ReprC,)+>>,
        //        Vec<<($( $ty, )+) as IntoFfi>::Store>
        //    );

        //    fn into_ffi(source: &[Self], store: &mut Self::Store) -> Self::ReprC {
        //        store.0 = source.iter().enumerate().map(|(i, item)|
        //            IntoFfi::into_ffi(item, &mut store.1[i]).collect()
        //        );

        //        slice::SliceRef::from_slice(&store.0)
        //    }
        //}

        impl<$($ty: IntoFfi),+> owned::IntoFfiVec for ($( $ty, )+) {
            type Store = (
                Vec<<($( $ty, )+) as owned::FfiVec>::ReprC>,
                Vec<<($( $ty, )+) as IntoFfi>::Store>
            );

            fn into_ffi(source: Vec<Self>, store: &mut Self::Store) -> Local<slice::SliceRef<<Self as owned::FfiVec>::ReprC>> {
                store.1 = core::iter::repeat_with(Default::default).take(source.len()).collect();

                store.0 = source.into_iter().enumerate().map(|(i, item)|
                    IntoFfi::into_ffi(item, &mut store.1[i])
                ).collect();

                Local(slice::SliceRef::from_slice(&store.0))
            }
        }
    };

    // NOTE: This is a trick to index tuples
    ( @decl_priv_mod $( $ty:ident ),+ $(,)? for $trait:path ) => {
        mod private {
            #[allow(non_snake_case)]
            pub struct Store<'itm, $($ty),+> where $($ty: $trait),+ {
                $(pub $ty: &'itm mut $ty::Store),+
            }

            #[allow(non_snake_case)]
            impl<'itm, $($ty: $trait),+> From<&'itm mut ($($ty::Store,)+)> for Store<'itm, $($ty),+> {
                fn from(($($ty,)+): &'itm mut ($($ty::Store,)+)) -> Self {
                    Self {$($ty,)+}
                }
            }
        }
    };
}

// TODO: Rewrite via proc macro
impl_tuple! {(A) -> FfiTuple1}
impl_tuple! {(A, B) -> FfiTuple2}
//impl_tuple! {(A, B, C) -> FfiTuple3}
//impl_tuple! {(A, B, C, D) -> FfiTuple4}
//impl_tuple! {(A, B, C, D, E) -> FfiTuple5}
//impl_tuple! {(A, B, C, D, E, F) -> FfiTuple6}
//impl_tuple! {(A, B, C, D, E, F, G) -> FfiTuple7}
//impl_tuple! {(A, B, C, D, E, F, G, H) -> FfiTuple8}
//impl_tuple! {(A, B, C, D, E, F, G, H, I) -> FfiTuple9}
//impl_tuple! {(A, B, C, D, E, F, G, H, I, J) -> FfiTuple10}
//impl_tuple! {(A, B, C, D, E, F, G, H, I, J, K) -> FfiTuple11}
//impl_tuple! {(A, B, C, D, E, F, G, H, I, J, K, L) -> FfiTuple12}
