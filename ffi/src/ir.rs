//! Internal representation, a.k.a IR of `Rust` types during conversion into FFI types.
//! While you can implement [`FfiType`] on your `Rust` type directly, it is encouraged
//! that you map your type into IR by providing the implementation of [`Ir`] and benefit
//! from automatic, correct and performant conversions from IR to C type equivalent.
use alloc::{boxed::Box, vec::Vec};
use core::mem::ManuallyDrop;

use crate::ReprC;

/// Marker trait for a type that can be transmuted into some C Type
///
/// # Safety
///
/// * `Self` and `Self::Target` must be mutually transmutable
/// * `Transmute::is_valid` must not return false positives, i.e. return `true` for trap representations
pub unsafe trait Transmute {
    /// Type that [`Self`] can be transmuted into
    type Target;

    /// Function that is called when transmuting types to check for trap representations. This function
    /// will never return false positives, i.e. return `true` for a trap representations.
    ///
    /// # Safety
    ///
    /// Any raw pointer in [`Self::Target`] that will be dereferenced must be valid.
    unsafe fn is_valid(source: &Self::Target) -> bool;
}

/// Marker trait for a type whose [`Transmute::is_valid`] always returns true. The main
/// use of this trait is to guard against the use of `&mut T` in FFI where the caller
/// can set the underlying `T` to a trap representation and cause UB.
///
/// # Safety
///
/// Implementation of [`Transmute::is_valid`] must always return true for this type
pub unsafe trait InfallibleTransmute {}

/// Designates a type that can be converted to/from internal representation.
/// IR types are given automatic implementation of [`FfiType`]
pub trait Ir: Sized {
    /// Internal representation of the type.
    ///
    /// If the [`Ir::Type`] is set to [`Transparent<T>`], `Self` will get an automatic
    /// implementation of [`FfiType`] that delegates to the inner type. If the conversion
    /// of the inner type is zero-copy conversion of [`Transparent<T>`] will also be.
    ///
    /// If the [`Ir::Type`] is set to [`Opaque<T>`], `T` will be serialized as an
    /// opaque pointer (the type is heap allocated during conversion). [`Opaque<T>`]
    /// is currently the only type that transfers ownership over FFI.
    ///
    /// Otherwise, in the common case, [`Ir::Type`] should be set to `Self` to benefit from
    /// the default implementation of [`FfiType`]. Be warned that in this case [`FfiType`]
    /// implementation will most likely clone the given type.
    type Type: IrTypeOf<Self>; // TODO: + CType or CTypeConvert?
}

/// Type that is allowed to be used in IR
pub trait IrTypeOf<T> {
    /// Perform the conversion from [`T`] into [`Self`] where `T: Ir`
    fn into_ir(source: T) -> Self;
    /// Perform the conversion from [`Self`] into [`T`] where `T: Ir`
    fn into_rust(self) -> T;
}

/// Marker struct for a type that is transferred as an opaque pointer over FFI
#[repr(transparent)]
#[derive(Debug, Clone, Copy)]
pub struct Opaque<T>(pub T);

/// Marker struct for a type that is transparent with respect to the wrapped type
#[repr(transparent)]
#[derive(Debug, Clone, Copy)]
pub struct Transparent<T: Transmute>(pub T);

/// Marker struct for a type that is a robust [`ReprC`] type and doesn't require conversion
#[repr(transparent)]
#[derive(Debug, Clone, Copy)]
pub struct Robust<T: ReprC>(pub T);

/// Marker struct for [`Box<T>`]
#[derive(Debug)]
pub struct IrBox<T: Ir<Type = U>, U>(pub Box<T>);
/// Marker struct for `&[T]`
#[derive(Debug)]
pub struct IrSlice<'itm, T: Ir<Type = U>, U>(pub &'itm [T]);
/// Marker struct for `&mut [T]`
#[derive(Debug)]
pub struct IrSliceMut<'itm, T: Ir<Type = U>, U>(pub &'itm mut [T]);
/// Marker struct for [`Vec<T>`]
#[derive(Debug)]
pub struct IrVec<T: Ir<Type = U>, U>(pub Vec<T>);
/// Marker struct for `[T: N]`
#[derive(Debug)]
pub struct IrArray<T: Ir<Type = U>, U, const N: usize>(pub [T; N]);

// SAFETY: `ReprC` are guaranteed to be robust
unsafe impl<T: ReprC + Ir<Type = Robust<T>>> InfallibleTransmute for T {}

impl<T> IrTypeOf<Self> for T {
    #[inline]
    fn into_ir(source: T) -> Self {
        source
    }
    #[inline]
    fn into_rust(self) -> Self {
        self
    }
}

impl<T> IrTypeOf<T> for Opaque<T> {
    #[inline]
    fn into_ir(source: T) -> Self {
        Self(source)
    }
    #[inline]
    fn into_rust(self) -> T {
        self.0
    }
}
impl<T: Transmute> IrTypeOf<T> for Transparent<T> {
    #[inline]
    fn into_ir(source: T) -> Self {
        Self(source)
    }
    #[inline]
    fn into_rust(self) -> T {
        self.0
    }
}
impl<T: ReprC> IrTypeOf<T> for Robust<T> {
    #[inline]
    fn into_ir(source: T) -> Self {
        Self(source)
    }
    #[inline]
    fn into_rust(self) -> T {
        self.0
    }
}

impl<T: Ir> IrTypeOf<Box<T>> for IrBox<T, T::Type> {
    #[inline]
    fn into_ir(source: Box<T>) -> Self {
        Self(source)
    }
    #[inline]
    fn into_rust(self) -> Box<T> {
        self.0
    }
}
impl<'itm, T: Ir> IrTypeOf<&'itm [T]> for IrSlice<'itm, T, T::Type> {
    #[inline]
    fn into_ir(source: &'itm [T]) -> Self {
        Self(source)
    }
    #[inline]
    fn into_rust(self) -> &'itm [T] {
        self.0
    }
}
impl<'itm, T: Ir> IrTypeOf<&'itm mut [T]> for IrSliceMut<'itm, T, T::Type> {
    #[inline]
    fn into_ir(source: &'itm mut [T]) -> Self {
        Self(source)
    }
    #[inline]
    fn into_rust(self) -> &'itm mut [T] {
        self.0
    }
}
impl<T: Ir> IrTypeOf<Vec<T>> for IrVec<T, T::Type> {
    #[inline]
    fn into_ir(source: Vec<T>) -> Self {
        Self(source)
    }
    #[inline]
    fn into_rust(self) -> Vec<T> {
        self.0
    }
}

impl<T: Ir, const N: usize> IrTypeOf<[T; N]> for IrArray<T, T::Type, N> {
    #[inline]
    fn into_ir(source: [T; N]) -> Self {
        Self(source)
    }
    #[inline]
    fn into_rust(self) -> [T; N] {
        self.0
    }
}

impl<T: Ir + Clone> Clone for IrBox<T, T::Type> {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}
impl<T: Ir + Clone> Clone for IrSlice<'_, T, T::Type> {
    fn clone(&self) -> Self {
        Self(self.0)
    }
}
impl<T: Ir + Clone> Clone for IrVec<T, T::Type> {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}
impl<T: Ir + Clone, const N: usize> Clone for IrArray<T, T::Type, N> {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

impl<T: Transmute> Transparent<T> {
    /// Convert from [`Self`] into [`T::Target`].
    /// Type returned is guaranteed to be valid
    pub(crate) fn into_inner(self) -> T::Target {
        #[repr(C)]
        union TransmuteHelper<T: Transmute> {
            source: ManuallyDrop<T>,
            target: ManuallyDrop<T::Target>,
        }

        let transmute_helper = TransmuteHelper {
            source: ManuallyDrop::new(self.0),
        };

        // SAFETY: Transmute is always valid because T::Target is a superset of T
        ManuallyDrop::into_inner(unsafe { transmute_helper.target })
    }

    /// Convert from [`T::Target`] into [`Self`]
    ///
    /// # Safety
    ///
    /// Any raw pointer in [`Self::Target`] that will be dereferenced must be valid.
    pub(crate) unsafe fn try_from_inner(source: T::Target) -> Option<Self> {
        #[repr(C)]
        union TransmuteHelper<T: Transmute> {
            source: ManuallyDrop<T::Target>,
            target: ManuallyDrop<T>,
        }

        if !T::is_valid(&source) {
            return None;
        }

        let transmute_helper = TransmuteHelper {
            source: ManuallyDrop::new(source),
        };
        Some(Transparent(ManuallyDrop::into_inner(
            transmute_helper.target,
        )))
    }
}

// SAFETY: Transmuting reference to a pointer of the same type
unsafe impl<'itm, T: ReprC + Ir<Type = Robust<T>>> Transmute for &'itm T {
    type Target = *const T;

    #[inline]
    unsafe fn is_valid(target: &Self::Target) -> bool {
        !target.is_null()
    }
}

// SAFETY: Transmuting reference to a pointer of the same type
unsafe impl<'itm, T: ReprC + Ir<Type = Robust<T>>> Transmute for &'itm mut T {
    type Target = *mut T;

    #[inline]
    unsafe fn is_valid(target: &Self::Target) -> bool {
        !target.is_null()
    }
}

impl<T> Ir for *const T {
    type Type = Robust<Self>;
}

impl<T> Ir for *mut T {
    type Type = Robust<Self>;
}

impl<'itm, T: Ir> Ir for &'itm T
where
    Self: Transmute,
{
    type Type = Transparent<Self>;
}
#[cfg(feature = "non_robust_ref_mut")]
impl<'itm, T: Ir> Ir for &'itm mut T
where
    Self: Transmute,
{
    type Type = Transparent<Self>;
}
#[cfg(not(feature = "non_robust_ref_mut"))]
impl<'itm, T: Ir + InfallibleTransmute> Ir for &'itm mut T
where
    Self: Transmute,
{
    type Type = Transparent<Self>;
}
impl<T: Ir> Ir for Box<T> {
    type Type = IrBox<T, T::Type>;
}
impl<'itm, T: Ir> Ir for &'itm [T] {
    type Type = IrSlice<'itm, T, T::Type>;
}
#[cfg(feature = "non_robust_ref_mut")]
impl<'itm, T: Ir> Ir for &'itm mut [T]
where
    &'itm mut T: Transmute,
{
    type Type = IrSliceMut<'itm, T, T::Type>;
}
#[cfg(not(feature = "non_robust_ref_mut"))]
impl<'itm, T: Ir + InfallibleTransmute> Ir for &'itm mut [T]
where
    &'itm mut T: Transmute,
{
    type Type = IrSliceMut<'itm, T, T::Type>;
}

impl<T: Ir> Ir for Vec<T> {
    type Type = IrVec<T, T::Type>;
}
impl<T: Ir, const N: usize> Ir for [T; N] {
    type Type = IrArray<T, T::Type, N>;
}
