#![allow(unsafe_code)]

//! Structures, macros related to FFI and generation of FFI bindings.
//! [Non-robust types](https://anssi-fr.github.io/rust-guide/07_ffi.html#non-robust-types-references-function-pointers-enums)
//! are strictly avoided in the FFI API

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
    /// * [`FfiResult::ArgIsNull`] - if any of the out-pointers in [`Self`] is set to null
    ///
    /// # Safety
    ///
    /// All conversions from a pointer must ensure pointer validity beforehand
    unsafe fn write(self, source: T) -> Result<(), FfiResult>;
}

/// Type that can be returned from an FFI function via out-pointer function argument
pub trait Output: Sized {
    /// Corresponding type of out-pointer
    type OutPtr: OutPtrOf<Self>;
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

impl<'itm, T: ReprC + Copy + 'itm> AsReprCRef<'itm> for T
where
    T: IntoFfi<Target = Self>,
{
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

    unsafe fn try_from_repr_c(source: Self::Source, _: &mut ()) -> Result<Self, FfiResult> {
        source.as_ref().ok_or(FfiResult::ArgIsNull)
    }
}
impl<'itm, T: ReprC> TryFromReprC<'itm> for &'itm mut T {
    type Source = *mut T;
    type Store = ();

    unsafe fn try_from_repr_c(source: Self::Source, _: &mut ()) -> Result<Self, FfiResult> {
        source.as_mut().ok_or(FfiResult::ArgIsNull)
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

impl<T> OutPtrOf<*mut T> for *mut *mut T {
    unsafe fn write(self, source: *mut T) -> Result<(), FfiResult> {
        if self.is_null() {
            return Err(FfiResult::ArgIsNull);
        }

        self.write(source);
        Ok(())
    }
}
impl<T> OutPtrOf<*const T> for *mut *const T {
    unsafe fn write(self, source: *const T) -> Result<(), FfiResult> {
        if self.is_null() {
            return Err(FfiResult::ArgIsNull);
        }

        self.write(source);
        Ok(())
    }
}
impl<T: ReprC> OutPtrOf<T> for *mut T
where
    T: IntoFfi<Target = T>,
{
    unsafe fn write(self, source: T) -> Result<(), FfiResult> {
        if self.is_null() {
            return Err(FfiResult::ArgIsNull);
        }

        self.write(source);
        Ok(())
    }
}
impl<T: ReprC + Copy> OutPtrOf<Local<T>> for *mut T {
    unsafe fn write(self, source: Local<T>) -> Result<(), FfiResult> {
        if self.is_null() {
            return Err(FfiResult::ArgIsNull);
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
impl<T: ReprC> Output for T
where
    T: IntoFfi<Target = Self>,
    *mut Self: OutPtrOf<Self>,
{
    type OutPtr = *mut Self;
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
            unsafe fn try_from_repr_c(source: Self::Source, store: &'itm mut Self::Store) -> Result<Self, FfiResult> {
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
