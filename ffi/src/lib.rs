#![allow(unsafe_code)]
#![no_std]

//! Structures and macros related to FFI and generation of FFI bindings. Any type that implements
//! [`FfiType`] can be used in the FFI bindings generated with [`ffi_export`]/[`ffi_import`]. It
//! is advisable to implement [`Ir`] and benefit from automatic implementation of [`FfiType`]

extern crate alloc;

use ir::{Ir, IrTypeOf};
pub use iroha_ffi_derive::*;
use repr_c::{COutPtr, CType, CTypeConvert, NonLocal, NonTransmute};

pub mod handle;
pub mod ir;
pub mod option;
mod primitives;
pub mod repr_c;
pub mod slice;
mod std_impls;

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
// NOTE: Type is `Copy` to indicate that there can be no ownership transfer
pub unsafe trait ReprC: Copy {}

/// A type that can be converted into some C type
pub trait FfiType: Sized {
    /// C type current type can be converted into
    type ReprC: ReprC;
}

/// Conversion utility for [`FfiType`]s
pub trait FfiConvert<'itm, T: ReprC>: Sized {
    /// Type into which state can be stored during conversion from [`Self`]. Useful for
    /// returning owning heap allocated types or non-owning types that are not transmutable.
    /// Serves similar purpose as does context in a closure
    type RustStore: Default;

    /// Type into which state can be stored during conversion into [`Self`]. Useful for
    /// returning non-owning types that are not transmutable. Serves similar purpose as
    /// does context in a closure
    type FfiStore: Default;

    /// Perform the conversion from [`Self`] into [`Self::ReprC`]
    fn into_ffi(self, store: &'itm mut Self::RustStore) -> T;

    /// Perform the conversion from [`Self::ReprC`] into [`Self`]
    ///
    /// # Errors
    ///
    /// Check [`FfiReturn`]
    ///
    /// # Safety
    ///
    /// All conversions from a pointer must ensure pointer validity beforehand
    unsafe fn try_from_ffi(source: T, store: &'itm mut Self::FfiStore) -> Result<Self>;
}

/// Marker trait designating a type that can be returned from an FFI function as an out-pointer
pub trait FfiOutPtr: FfiType {
    /// Type of the out-pointer
    type OutPtr: OutPtrOf<Self::ReprC>;
}

/// Type that can be returned from an FFI function as an out-pointer function argument
pub trait OutPtrOf<T: ReprC>: ReprC {
    /// Try to write `T` into [`Self`] out-pointer and return whether or not it was successful
    ///
    /// # Errors
    ///
    /// * [`FfiReturn::ArgIsNull`]: if any of the out-pointers in [`Self`] is set to null
    ///
    /// # Safety
    ///
    /// * All conversions from a pointer must ensure pointer validity beforehand
    // TODO: It could return bool for successful vs not?
    // It depends on whether or not `source` should be checked for validity?
    unsafe fn write(self, source: T) -> Result<()>;
}

/// Result of execution of an FFI function
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i8)]
pub enum FfiReturn {
    /// The input argument provided to FFI function can't be converted into inner rust representation.
    ConversionFailed = -6,
    /// The input argument provided to FFI function contains a trap representation.
    TrapRepresentation = -5,
    /// FFI function execution panicked.
    UnrecoverableError = -4,
    /// Provided handle id doesn't match any known handles.
    UnknownHandle = -3,
    /// FFI function failed during the execution of the wrapped method on the provided handle.
    ExecutionFail = -2,
    /// The input argument provided to FFI function is a null pointer.
    ArgIsNull = -1,
    /// FFI function executed successfully.
    Ok = 0,
}

/// Macro for defining FFI types of a known category ([`Opaque`], [`Robust`] or [`Transmute`]).
/// The implementation for an FFI type of one of the categories incurs a lot of bloat that
/// is reduced by the use of this macro
///
/// # Safety
///
/// * If the type is [`Robust`], it derives [`ReprC`]. Check safety invariants for [`ReprC`]
/// * If the type is [`Transparent`], it derives [`Transmute`]. Check safety invariants for [`Transmute`]
///
/// # Example
///
/// ```
/// use iroha_ffi::ffi_type;
///
/// struct OpaqueStruct<T>(T);
///
/// #[derive(Clone, Copy)]
/// #[repr(C)]
/// struct RobustStruct(u64, i32);
///
/// #[repr(transparent)]
/// struct NonNull<T>(*mut T);
///
/// ffi_type! {impl<T> Opaque for OpaqueStruct<T>}
/// ffi_type! {unsafe impl Robust for RobustStruct}
/// ffi_type! {unsafe impl<T> Transparent for NonNull<T>[*mut T] validated with {
///     |target: &*mut T| !target.is_null()
/// }}
///
/// #[repr(C)]
/// struct NonRobustStruct(String, u32);
///
/// // CAUTION: Struct is not robust albeit it's `#[repr(C)]`
/// // ffi_type! {unsafe impl Robust for NonRobustStruct}
/// ```
#[macro_export]
macro_rules! ffi_type {
    (impl $(<$($impl_generics: tt $(: $bounds: path)?),*>)? Opaque for $ty: ty $(where $where_clause: tt )? ) => {
        impl$(<$($impl_generics $(: $bounds)?),*>)? $crate::option::Niche for $ty where $($where_clause)? {
            const NICHE_VALUE: Self::ReprC = core::ptr::null_mut();
        }

        // SAFETY: Opaque types are never dereferenced
        unsafe impl$(<$($impl_generics $(: $bounds)?),*>)? $crate::ir::InfallibleTransmute for $ty where $($where_clause)? {}

        // SAFETY: Transmuting reference to a pointer of the same type
        unsafe impl$(<$($impl_generics $(: $bounds)?),*>)? $crate::ir::Transmute for &$ty where $($where_clause)? {
            type Target = *const $ty;

            #[inline]
            unsafe fn is_valid(target: &Self::Target) -> bool {
                !target.is_null()
            }
        }
        // SAFETY: Transmuting reference to a pointer of the same type
        unsafe impl$(<$($impl_generics $(: $bounds)?),*>)? $crate::ir::Transmute for &mut $ty where $($where_clause)? {
            type Target = *mut $ty;

            #[inline]
            unsafe fn is_valid(target: &Self::Target) -> bool {
                !target.is_null()
            }
        }

        impl$(<$($impl_generics $(: $bounds)?),*>)? $crate::ir::Ir for $ty where $($where_clause)? {
            type Type = $crate::ir::Opaque<Self>;
        }

    };
    (unsafe impl $(<$($impl_generics: tt $(: $bounds: path)?),*>)? Robust for $ty: ty $(where $where_clause: tt )? ) => {
        // SAFETY: Type must be a robust repr(C) type
        unsafe impl$(<$($impl_generics: $crate::ReprC + $($bounds)?),*>)? $crate::ReprC for $ty where $($where_clause)? {}

        impl$(<$($impl_generics $(: $bounds)?),*>)? $crate::ir::Ir for $ty where Self: $crate::ReprC, $($where_clause)? {
            type Type = $crate::ir::Robust<Self>;
        }
    };
    (unsafe impl $(<$($impl_generics: tt $(: $bounds: path)?),*>)? Transparent for $ty: ty[$target: ty] $(where $where_clause: tt )? validated with {$validity_fn: expr}) => {
        // SAFETY: Type must be `#[repr(transparent)]` with respect to the target type
        unsafe impl<$($($impl_generics $(: $bounds)?),*)?> $crate::ir::Transmute for $ty where $($where_clause)? {
            type Target = $target;

            #[inline]
            unsafe fn is_valid(target: &Self::Target) -> bool {
                $validity_fn(target)
            }
        }
        // SAFETY: Type must be `#[repr(transparent)]` with respect to the target type
        unsafe impl<'__iroha_ffi_itm, $($($impl_generics $(: $bounds)?),*)?> $crate::ir::Transmute for &'__iroha_ffi_itm $ty where $($where_clause)? {
            type Target = &'__iroha_ffi_itm $target;

            #[inline]
            unsafe fn is_valid(target: &Self::Target) -> bool {
                $validity_fn(target)
            }
        }
        // SAFETY: Type must be `#[repr(transparent)]` with respect to the target type
        unsafe impl<'__iroha_ffi_itm, $($($impl_generics $(: $bounds)?),*)?> $crate::ir::Transmute for &'__iroha_ffi_itm mut $ty where $($where_clause)? {
            type Target = &'__iroha_ffi_itm mut $target;

            #[inline]
            unsafe fn is_valid(target: &Self::Target) -> bool {
                $validity_fn(target)
            }
        }
        impl<$($($impl_generics $(: $bounds)?),*)?> $crate::ir::Ir for $ty where $($where_clause)? {
            type Type = $crate::ir::Transparent<$ty>;
        }
    };
}

/// Wrapper around struct/enum opaque pointer. When wrapped with the [`ffi`] macro in the
/// crate linking dynamically to some `cdylib` crate, it replaces struct/enum body definition
#[derive(Debug, Clone, Copy)]
#[repr(transparent)]
pub struct Extern {
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

// SAFETY: `*const T` is robust with a defined C ABI regardless of whether `T` is
// When `T` is not `ReprC` the pointer is opaque; dereferencing is immediate UB
unsafe impl<T> ReprC for *const T {}
// SAFETY: `*mut T` is robust with a defined C ABI regardless of whether `T` is
// When `T` is not `ReprC` the pointer is opaque; dereferencing is immediate UB
unsafe impl<T> ReprC for *mut T {}
// SAFETY: `*mut T` is robust with a defined C ABI
unsafe impl<T: ReprC, const N: usize> ReprC for [T; N] {}

impl<'itm, T: Ir + 'itm> FfiType for T
where
    T::Type: CType,
{
    type ReprC = <T::Type as CType>::ReprC;
}
impl<'itm, T: Ir + 'itm, U: ReprC> FfiConvert<'itm, U> for T
where
    T::Type: CTypeConvert<'itm, U>,
{
    type RustStore = <T::Type as CTypeConvert<'itm, U>>::RustStore;
    type FfiStore = <T::Type as CTypeConvert<'itm, U>>::FfiStore;

    #[inline]
    fn into_ffi(self, store: &'itm mut Self::RustStore) -> U {
        T::Type::into_ir(self).into_repr_c(store)
    }

    #[inline]
    unsafe fn try_from_ffi(source: U, store: &'itm mut Self::FfiStore) -> Result<Self> {
        T::Type::try_from_repr_c(source, store).map(IrTypeOf::into_rust)
    }
}

impl<'itm, T: Ir + 'itm> FfiOutPtr for T
where
    T::Type: COutPtr,
{
    type OutPtr = <T::Type as COutPtr>::OutPtr;
}

impl<T: ReprC> OutPtrOf<T> for *mut T {
    #[inline]
    unsafe fn write(self, source: T) -> Result<()> {
        if self.is_null() {
            return Err(FfiReturn::ArgIsNull);
        }

        self.write(source);
        Ok(())
    }
}

impl<T: ReprC> OutPtrOf<*const T> for *mut T {
    #[inline]
    unsafe fn write(self, source: *const T) -> Result<()> {
        if self.is_null() {
            return Err(FfiReturn::ArgIsNull);
        }

        self.write(source.read());
        Ok(())
    }
}

impl<T: ReprC> OutPtrOf<*mut T> for *mut T {
    #[inline]
    unsafe fn write(self, source: *mut T) -> Result<()> {
        if self.is_null() {
            return Err(FfiReturn::ArgIsNull);
        }

        self.write(source.read());
        Ok(())
    }
}

impl<T: ReprC, const N: usize> OutPtrOf<[T; N]> for *mut T {
    #[inline]
    unsafe fn write(self, source: [T; N]) -> Result<()> {
        if self.is_null() {
            return Err(FfiReturn::ArgIsNull);
        }

        for (i, item) in source.into_iter().enumerate() {
            self.add(i).write(item);
        }

        Ok(())
    }
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
                Self($( $ty ),+)
            }
        }

        // SAFETY: Implementing type is robust with a defined C ABI
        unsafe impl<$($ty: ReprC),+> ReprC for $ffi_ty<$($ty),+> {}

        impl<$($ty),+> $crate::ir::Ir for ($($ty,)+) {
            type Type = Self;
        }
        impl<$($ty),+> $crate::ir::Ir for &($($ty,)+) {
            type Type = Self;
        }

        impl<$($ty: FfiType),+> $crate::repr_c::CType for ($($ty,)+) {
            type ReprC = $ffi_ty<$($ty::ReprC),+>;
        }
        impl<'itm, $($ty: FfiType + FfiConvert<'itm, <$ty as FfiType>::ReprC>),+> $crate::repr_c::CTypeConvert<'itm, <Self as FfiType>::ReprC> for ($($ty,)+) {
            type RustStore = ($( $ty::RustStore, )+);
            type FfiStore = ($( $ty::FfiStore, )+);

            #[allow(non_snake_case)]
            fn into_repr_c(self, store: &'itm mut Self::RustStore) -> <Self as $crate::FfiType>::ReprC {
                impl_tuple! {@decl_priv_mod $($ty),+ for RustStore}

                let ($($ty,)+) = self;
                let store: private::Store<$($ty),+> = store.into();
                $ffi_ty($( <$ty as FfiConvert<<$ty as FfiType>::ReprC>>::into_ffi($ty, store.$ty),)+)
            }
            #[allow(non_snake_case, clippy::missing_errors_doc, clippy::missing_safety_doc)]
            unsafe fn try_from_repr_c(source: <Self as FfiType>::ReprC, store: &'itm mut Self::FfiStore) -> Result<Self> {
                impl_tuple! {@decl_priv_mod $($ty),+ for FfiStore}

                let $ffi_ty($($ty,)+) = source;
                let store: private::Store<$($ty),+> = store.into();
                Ok(($( <$ty as FfiConvert<<$ty as FfiType>::ReprC>>::try_from_ffi($ty, store.$ty)?, )+))
            }
        }

        impl<$($ty),+> COutPtr for ($($ty,)+) where Self: CType {
            type OutPtr = *mut Self::ReprC;
        }

        impl<$($ty),+> NonTransmute for ($($ty,)+) where Self: CType {}

        // SAFETY: Tuple doesn't use store if it's inner types don't use it
        unsafe impl<$($ty: Ir),+> NonLocal for ($($ty,)+) where $($ty::Type: NonLocal,)+ {}
    };

    // NOTE: This is a trick to index tuples
    ( @decl_priv_mod $( $ty:ident ),+ $(,)? for $store:ident ) => {
        mod private {
            pub struct Store<'itm, $($ty),+> where $($ty: $crate::FfiType + $crate::FfiConvert<'itm, <$ty as $crate::FfiType>::ReprC>),+ {
                $(pub $ty: &'itm mut $ty::$store),+
            }

            impl<'itm, $($ty: $crate::FfiType + $crate::FfiConvert<'itm, <$ty as $crate::FfiType>::ReprC>),+> From<&'itm mut ($($ty::$store,)+)> for Store<'itm, $($ty),+> {
                fn from(($($ty,)+): &'itm mut ($($ty::$store,)+)) -> Self {
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
