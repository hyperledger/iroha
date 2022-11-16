//! Internal representation, a.k.a IR of `Rust` types during conversion into FFI types.
//! While you can implement [`FfiType`] on your `Rust` type directly, it is encouraged
//! that you map your type into IR by providing the implementation of [`Ir`] and benefit
//! from automatic, correct and performant conversions from IR to C type equivalent.
use alloc::{boxed::Box, vec::Vec};

use crate::{repr_c::Cloned, ReprC};

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
pub trait Ir {
    /// Internal representation of the type.
    ///
    /// If the `Self` is [`ReprC`], [`Ir::Type`] should be set to [`Robust`] in which
    /// case the type will be used in the FFI function as given without any conversion.
    ///
    /// If the [`Ir::Type`] is set to [`Transparent`], `Self` will get an automatic
    /// implementation of [`FfiType`] that delegates to the inner type. If the conversion
    /// of the inner type is zero-copy conversion of [`Transparent`] will also be.
    ///
    /// If the [`Ir::Type`] is set to [`Opaque`], `T` will be serialized as an
    /// opaque pointer (the type is heap allocated during conversion). [`Opaque`]
    /// is currently the only type that transfers ownership over FFI.
    ///
    /// Otherwise, in the common case, [`Ir::Type`] should be set to `Self` to benefit from
    /// the default implementation of [`FfiType`]. Be warned that in this case [`FfiType`]
    /// implementation will most likely clone the given type.
    type Type; // TODO: + CType or CTypeConvert?
}

/// Marker for a type that is transferred as an opaque pointer over FFI
#[derive(Debug, Clone, Copy)]
pub enum Opaque {}

/// Marker for a type that is transparent with respect to the wrapped type
#[derive(Debug, Clone, Copy)]
pub enum Transparent {}

/// Marker for a type that is a robust [`ReprC`] type and doesn't require conversion
#[derive(Debug, Clone, Copy)]
pub enum Robust {}

// SAFETY: `ReprC` are guaranteed to be robust
unsafe impl<R: ReprC + Ir<Type = Robust>> InfallibleTransmute for R {}

// SAFETY: Transmuting reference to a pointer of the same type
unsafe impl<R: ReprC + Ir<Type = Robust>> Transmute for &R {
    type Target = *const R;

    #[inline]
    unsafe fn is_valid(target: &Self::Target) -> bool {
        !target.is_null()
    }
}

// SAFETY: Transmuting reference to a pointer of the same type
unsafe impl<R: ReprC + Ir<Type = Robust>> Transmute for &mut R {
    type Target = *mut R;

    #[inline]
    unsafe fn is_valid(target: &Self::Target) -> bool {
        !target.is_null()
    }
}

// SAFETY: Arrays have a defined representation
unsafe impl<R: Transmute, const N: usize> Transmute for [R; N] {
    type Target = [R::Target; N];

    unsafe fn is_valid(source: &Self::Target) -> bool {
        source.iter().all(|elem| R::is_valid(elem))
    }
}

impl<R> Ir for *const R {
    type Type = Robust;
}

impl<R> Ir for *mut R {
    type Type = Robust;
}

impl<'itm, R: Ir + Cloned> Ir for &'itm R {
    type Type = &'itm R::Type;
}
#[cfg(feature = "non_robust_ref_mut")]
impl<R: Ir> Ir for &mut R
where
    Self: Transmute,
{
    type Type = Transparent;
}
#[cfg(not(feature = "non_robust_ref_mut"))]
impl<R: Ir + InfallibleTransmute> Ir for &mut R
where
    Self: Transmute,
{
    type Type = Transparent;
}
impl<R: Ir> Ir for Box<R> {
    type Type = Box<R::Type>;
}
impl<'itm, R: Ir> Ir for &'itm [R] {
    type Type = &'itm [R::Type];
}
#[cfg(feature = "non_robust_ref_mut")]
impl<'itm, R: Ir> Ir for &'itm mut [R]
where
    &'itm mut R: Transmute,
{
    type Type = &'itm mut [R::Type];
}
#[cfg(not(feature = "non_robust_ref_mut"))]
impl<'itm, R: Ir + InfallibleTransmute> Ir for &'itm mut [R]
where
    &'itm mut R: Transmute,
{
    type Type = &'itm mut [R::Type];
}

impl<R: Ir> Ir for Vec<R> {
    type Type = Vec<R::Type>;
}
impl<R: Ir, const N: usize> Ir for [R; N] {
    type Type = [R::Type; N];
}
