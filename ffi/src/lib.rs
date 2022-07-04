#![allow(unsafe_code)]

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

pub use iroha_ffi_derive::*;
use owned::Local;

pub mod handle;
pub mod option;
pub mod owned;
mod primitives;
pub mod slice;

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
pub trait AsReprCRef {
    /// Robust C ABI compliant representation of &[`Self`]
    type Target: ReprC;

    /// Convert from &[`Self`] into [`Self::Target`].
    fn as_ref(&self) -> Self::Target;
}

/// Conversion from a type that implements [`ReprC`].
// TODO: bind Self or Self::Store with 'itm?
pub trait TryFromReprC<'itm>: Sized {
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
    /// * [`FfiResult::ArgIsNull`]          - given pointer is null
    /// * [`FfiResult::UnknownHandle`]      - given id doesn't identify any known handle
    /// * [`FfiResult::TrapRepresentation`] - given value contains trap representation
    ///
    /// # Safety
    ///
    /// All conversions from a pointer must ensure pointer validity beforehand
    unsafe fn try_from_repr_c(
        source: Self::Source,
        store: &'itm mut Self::Store,
    ) -> Result<Self, FfiResult>;
}

/// Type that can be used as an out-pointer
pub trait OutPtr: ReprC {
    /// Return `false` if any of the out-pointers in `Self` are null, otherwise `true`
    fn is_valid(&self) -> bool;
}

/// Conversion into a type that can be converted to an FFI-compatible [`ReprC`] type
/// Except for opaque pointer types, ownership transfer over FFI is not permitted
pub trait IntoFfi: Sized {
    /// The resulting type after conversion
    type Target: ReprC;

    /// Convert from [`Self`] into [`Self::Target`]
    fn into_ffi(self) -> Self::Target;
}

/// Type that can be returned from an FFI function as an out pointer function argument
pub trait FfiOutput {
    /// Type used to represent function return value as an out pointer function argument
    type OutPtr: OutPtr;

    /// Try to write [`Self`] into [`Self::OutPtr`] and return whether or not it was successful
    ///
    /// # Errors
    ///
    /// * [`FfiResult::ArgIsNull`] - if any of the out-pointers in [`Self::OutPtr`] is set to null
    ///
    /// # Safety
    ///
    /// All conversions from a pointer must ensure pointer validity beforehand
    unsafe fn write(self, dest: Self::OutPtr) -> Result<(), FfiResult>;
}

/// Result of execution of an FFI function
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i8)]
pub enum FfiResult {
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

impl<T: ReprC + Copy> AsReprCRef for T
where
    T: IntoFfi<Target = Self>,
{
    type Target = Self;

    fn as_ref(&self) -> Self::Target {
        *self
    }
}
impl<T> AsReprCRef for *const T {
    type Target = Self;

    fn as_ref(&self) -> Self::Target {
        *self
    }
}

impl<T: ReprC + Copy> IntoFfi for &T
where
    T: IntoFfi<Target = T>,
{
    type Target = *const T;

    fn into_ffi(self) -> Self::Target {
        Self::Target::from(self)
    }
}
impl<T: ReprC + Copy> IntoFfi for &mut T
where
    T: IntoFfi<Target = T>,
{
    type Target = *mut T;

    fn into_ffi(self) -> Self::Target {
        Self::Target::from(self)
    }
}

impl<T: ReprC> TryFromReprC<'_> for &T {
    type Source = *const T;
    type Store = ();

    unsafe fn try_from_repr_c(source: Self::Source, _: &mut ()) -> Result<Self, FfiResult> {
        source.as_ref().ok_or(FfiResult::ArgIsNull)
    }
}
impl<T: ReprC> TryFromReprC<'_> for &mut T {
    type Source = *mut T;
    type Store = ();

    unsafe fn try_from_repr_c(source: Self::Source, _: &mut ()) -> Result<Self, FfiResult> {
        source.as_mut().ok_or(FfiResult::ArgIsNull)
    }
}

impl<T: ReprC> OutPtr for *mut T {
    fn is_valid(&self) -> bool {
        (*self).is_null()
    }
}

impl<T: ReprC + Copy> FfiOutput for T
where
    T: IntoFfi<Target = Self>,
{
    type OutPtr = *mut Self;

    unsafe fn write(self, dest: Self::OutPtr) -> Result<(), FfiResult> {
        if dest.is_null() {
            return Err(FfiResult::ArgIsNull);
        }

        dest.write(self);
        Ok(())
    }
}
impl<T> FfiOutput for *const T {
    type OutPtr = *mut Self;

    unsafe fn write(self, dest: Self::OutPtr) -> Result<(), FfiResult> {
        if dest.is_null() {
            return Err(FfiResult::ArgIsNull);
        }

        dest.write(self);
        Ok(())
    }
}
impl<T> FfiOutput for *mut T {
    type OutPtr = *mut Self;

    unsafe fn write(self, dest: Self::OutPtr) -> Result<(), FfiResult> {
        if dest.is_null() {
            return Err(FfiResult::ArgIsNull);
        }

        dest.write(self);
        Ok(())
    }
}

macro_rules! impl_tuple {
    ( ($( $ty:ident ),+ $(,)?) -> $ffi_ty:ident ) => {
        /// FFI-compatible tuple with n elements
        #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
        #[repr(C)]
        pub struct $ffi_ty<$($ty),+>($($ty),+);

        #[allow(non_snake_case)]
        impl<$($ty),+> From<($( $ty, )*)> for $ffi_ty<$($ty),+> {
            fn from(source: ($( $ty, )*)) -> Self {
                let ($($ty,)+) = source;
                Self($( $ty ),*)
            }
        }

        unsafe impl<$($ty: ReprC),+> ReprC for $ffi_ty<$($ty),+> {}

        impl<$($ty: ReprC),+> AsReprCRef for $ffi_ty<$($ty),+> {
            type Target = *const Self;

            fn as_ref(&self) -> Self::Target {
                <*const Self>::from(self)
            }
        }

        impl<'itm, $($ty: TryFromReprC<'itm>),+> TryFromReprC<'itm> for ($($ty,)+) {
            type Source = $ffi_ty<$($ty::Source),+>;
            type Store = ($( $ty::Store, )*);

            #[allow(non_snake_case)]
            unsafe fn try_from_repr_c(source: Self::Source, store: &'itm mut Self::Store) -> Result<Self, FfiResult> {
                impl_tuple! {@decl_priv_mod $($ty),+}

                let $ffi_ty($($ty,)+) = source;
                let store: private::Store<$($ty),+> = store.into();
                Ok(($( <$ty as TryFromReprC>::try_from_repr_c($ty, store.$ty)?, )+))
            }
        }

        //impl<'itm, $($ty: TryFromReprC<'itm>),+> TryFromReprC<'itm> for &($($ty,)+) where $($ty::Source: Copy),+ {
        //    type Source = *const $ffi_ty<$($ty::Source),+>;
        //    type Store = ($( $ty::Store, )*);

        //    #[allow(non_snake_case)]
        //    unsafe fn try_from_repr_c(source: Self::Source, store: &'itm mut Self::Store) -> Result<Self, FfiResult> {
        //        impl_tuple! {@decl_priv_mod $($ty),+}

        //        let $ffi_ty($($ty,)+) = &*source;
        //        let store: private::Store<$($ty),+> = store.into();
        //        Ok(($( <$ty as TryFromReprC>::try_from_repr_c($ty, store.$ty)?, )+))
        //    }
        //}

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

        //impl<$($ty),+> slice::IntoFfiSliceRef for ($( $ty, )+) where Self: IntoFfi + Clone {
        //    type Item = slice::LocalSliceRef<<Self as IntoFfi>::Item>;

        //    fn into_ffi_slice(source: &[Self]) -> Self::Item {
        //        source.iter().map(|item| Clone::clone(item).into_ffi()).collect()
        //    }
        //}

        //impl<$($ty: TryAsRust),+> TryAsRust for ($( $ty, )+) {
        //    type Item = ($($ty::Item,)+);

        //    #[allow(non_snake_case)]
        //    unsafe fn try_as_rust(source: &mut Self::Item) -> Result<Self, FfiResult> {
        //        let ($($ty,)+) = source;
        //        Ok(($(<$ty as TryAsRust>::try_as_rust($ty)?,)+))
        //    }
        //}
        //impl<$($ty),+> TryAsRust for &($( $ty, )+) where Local<($($ty,)+)>: TryFromReprC {
        //    type Item = Local<($($ty,)+)>;

        //    #[allow(non_snake_case)]
        //    unsafe fn try_as_rust(source: &mut Self::Item) -> Result<Self, FfiResult> {
        //        Ok(&source.0)
        //    }
        //}

        // TODO: why this clone
        //impl<$($ty: Clone),+> slice::TryFromReprCSliceRef for ($( $ty, )+) {
        //    type Item = slice::LocalSliceRef<Self>;

        //    fn try_from_ffi_slice(source: &Self::Item) -> Result<&[Self], FfiResult> {
        //        Ok(source)
        //    }
        //}

        impl<$($ty: ReprC),+> FfiOutput for $ffi_ty<$($ty),+> {
            type OutPtr = *mut Self;

            unsafe fn write(self, dest: Self::OutPtr) -> Result<(), FfiResult> {
                if dest.is_null() {
                    return Err(FfiResult::ArgIsNull);
                }

                Ok(dest.write(self))
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
            impl<'store, 'tup, $($ty: super::TryFromReprC<'tup>),+> From<&'tup mut ($($ty::Store,)+)> for Store<'tup, $($ty),+> {
                fn from(($($ty,)+): &'tup mut ($($ty::Store,)+)) -> Self {
                    Self {$($ty,)+}
                }
            }
        }
    };
}

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
