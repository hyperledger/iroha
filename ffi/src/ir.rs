//! Internal representation, a.k.a IR of `Rust` types during conversion into FFI types.
//! While you can implement [`FfiType`] on your `Rust` type directly, it is encouraged
//! that you map your type into IR by providing the implementation of [`Ir`] and benefit
//! from automatic, correct and performant conversions from IR to C type equivalent.
use alloc::{boxed::Box, vec::Vec};

use crate::{repr_c::Cloned, Extern, LocalRef, LocalSlice};

/// Type which is replaced by an opaque pointer on FFI import
///
/// # Safety
///
/// Type implementing must have the same representation as [`*mut Extern`]
/// `Self::RefType` must have the same representation as [`*const Extern`]
/// `Self::RefMutType` must have the same representation as [`*mut Extern`]
pub unsafe trait External {
    /// Type which replaces `&T` on FFI import
    type RefType<'itm>;
    /// Type which replaces `&mut T` on FFI import
    type RefMutType<'itm>;

    /// Return shared opaque pointer
    fn as_extern_ptr(&self) -> *const Extern;
    /// Return mutable opaque pointer
    fn as_extern_ptr_mut(&mut self) -> *mut Extern;
    /// Construct type from an opaque pointer
    ///
    /// # Safety
    ///
    /// The given opaque pointer must be non-null and valid
    unsafe fn from_extern_ptr(source: *mut Extern) -> Self;
}

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

/// Designates a type that can be converted to/from internal representation. Predefined IR
/// types are given automatic implementation of [`FfiType`] and other conversion traits.
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
    /// opaque pointer (the type is heap allocated during conversion). Except for `Vec<T>`,
    /// [`Opaque`] is currently the only family of types that transfer ownership over FFI.
    ///
    /// Otherwise, in the common case, [`Ir::Type`] should be set to `Self` and implement
    /// [`Cloned`] to benefit from the default implementation of [`FfiType`]. Be warned
    /// that in this case [`FfiType`] implementation will clone the given type.
    type Type;
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

// SAFETY: Transmute relation is transitive
unsafe impl<'itm, R: Transmute> Transmute for &'itm R {
    type Target = &'itm R::Target;

    #[inline]
    unsafe fn is_valid(target: &Self::Target) -> bool {
        R::is_valid(target)
    }
}

// SAFETY: Transmute relation is transitive
unsafe impl<'itm, R: Transmute> Transmute for &'itm mut R {
    type Target = &'itm mut R::Target;

    #[inline]
    unsafe fn is_valid(target: &Self::Target) -> bool {
        R::is_valid(target)
    }
}

// SAFETY: Arrays have a defined representation
unsafe impl<R: Transmute, const N: usize> Transmute for [R; N] {
    type Target = [R::Target; N];

    unsafe fn is_valid(source: &Self::Target) -> bool {
        source.iter().all(|elem| R::is_valid(elem))
    }
}

// SAFETY: Arrays have a defined representation
unsafe impl<R: InfallibleTransmute, const N: usize> InfallibleTransmute for [R; N] {}

impl<R> Ir for *const R {
    type Type = Robust;
}
impl<R> Ir for *mut R {
    type Type = Robust;
}

/// When implemented for a type, defines how dependent types are mapped into [`Ir`]
pub trait IrTypeFamily {
    /// [`Ir`] type that `&T` is mapped into
    type RefType<'itm>
    where
        Self: 'itm;
    /// [`Ir`] type that `&mut T` is mapped into
    type RefMutType<'itm>
    where
        Self: 'itm;
    /// [`Ir`] type that [`Box<T>`] is mapped into
    type BoxType;
    /// [`Ir`] type that `&[T]` is mapped into
    type SliceRefType<'itm>
    where
        Self: 'itm;
    /// [`Ir`] type that `&mut [T]` is mapped into
    type SliceRefMutType<'itm>
    where
        Self: 'itm;
    /// [`Ir`] type that [`Vec<T>`] is mapped into
    type VecType;
    /// [`Ir`] type that `[T; N]` is mapped into
    type ArrType<const N: usize>;
}

impl<R: Cloned> IrTypeFamily for R {
    type RefType<'itm> = &'itm Self where Self: 'itm;
    // NOTE: Unused
    type RefMutType<'itm> = () where Self: 'itm;
    type BoxType = Box<Self>;
    type SliceRefType<'itm> = &'itm [Self] where Self: 'itm;
    // NOTE: Unused
    type SliceRefMutType<'itm> = () where Self: 'itm;
    type VecType = Vec<Self>;
    type ArrType<const N: usize> = [Self; N];
}
impl IrTypeFamily for Robust {
    type RefType<'itm> = Transparent;
    type RefMutType<'itm> = Transparent;
    type BoxType = Box<Self>;
    type SliceRefType<'itm> = &'itm [Self];
    type SliceRefMutType<'itm> = &'itm mut [Self];
    type VecType = Vec<Self>;
    type ArrType<const N: usize> = Self;
}
impl IrTypeFamily for Opaque {
    type RefType<'itm> = Transparent;
    type RefMutType<'itm> = Transparent;
    type BoxType = Box<Self>;
    type SliceRefType<'itm> = &'itm [Self];
    type SliceRefMutType<'itm> = &'itm mut [Self];
    type VecType = Vec<Self>;
    type ArrType<const N: usize> = [Self; N];
}
impl IrTypeFamily for Transparent {
    type RefType<'itm> = Self;
    type RefMutType<'itm> = Self;
    type BoxType = Box<Self>;
    type SliceRefType<'itm> = &'itm [Self];
    type SliceRefMutType<'itm> = &'itm mut [Self];
    type VecType = Vec<Self>;
    type ArrType<const N: usize> = Self;
}
impl IrTypeFamily for &Extern {
    type RefType<'itm> = &'itm Self where Self: 'itm;
    type RefMutType<'itm> = &'itm mut Self where Self: 'itm;
    type BoxType = Box<Self>;
    type SliceRefType<'itm> = &'itm [Self] where Self: 'itm;
    type SliceRefMutType<'itm> = &'itm mut [Self] where Self: 'itm;
    type VecType = Vec<Self>;
    type ArrType<const N: usize> = [Self; N];
}
impl IrTypeFamily for &mut Extern {
    type RefType<'itm> = &'itm Self where Self: 'itm;
    type RefMutType<'itm> = &'itm mut Self where Self: 'itm;
    type BoxType = Box<Self>;
    type SliceRefType<'itm> = &'itm [Self] where Self: 'itm;
    type SliceRefMutType<'itm> = &'itm mut [Self] where Self: 'itm;
    type VecType = Vec<Self>;
    type ArrType<const N: usize> = [Self; N];
}

impl<'itm, R: Ir> Ir for &'itm R
where
    R::Type: IrTypeFamily,
{
    type Type = <R::Type as IrTypeFamily>::RefType<'itm>;
}
#[cfg(feature = "non_robust_ref_mut")]
impl<'itm, R: Ir> Ir for &'itm mut R
where
    R::Type: IrTypeFamily,
{
    type Type = <R::Type as IrTypeFamily>::RefMutType<'itm>;
}
#[cfg(not(feature = "non_robust_ref_mut"))]
impl<'itm, R: Ir + InfallibleTransmute> Ir for &'itm mut R
where
    R::Type: IrTypeFamily,
{
    type Type = <R::Type as IrTypeFamily>::RefMutType<'itm>;
}
impl<R: Ir> Ir for Box<R>
where
    R::Type: IrTypeFamily,
{
    type Type = <R::Type as IrTypeFamily>::BoxType;
}
impl<'itm, R: Ir> Ir for &'itm [R]
where
    R::Type: IrTypeFamily,
{
    type Type = <R::Type as IrTypeFamily>::SliceRefType<'itm>;
}
#[cfg(feature = "non_robust_ref_mut")]
impl<'itm, R: Ir> Ir for &'itm mut [R]
where
    R::Type: IrTypeFamily,
{
    type Type = <R::Type as IrTypeFamily>::SliceRefMutType<'itm>;
}
#[cfg(not(feature = "non_robust_ref_mut"))]
impl<'itm, R: Ir + InfallibleTransmute> Ir for &'itm mut [R]
where
    R::Type: IrTypeFamily,
{
    type Type = <R::Type as IrTypeFamily>::SliceRefMutType<'itm>;
}
impl<R: Ir> Ir for Vec<R>
where
    R::Type: IrTypeFamily,
{
    type Type = <R::Type as IrTypeFamily>::VecType;
}
impl<R: Ir, const N: usize> Ir for [R; N]
where
    R::Type: IrTypeFamily,
{
    type Type = <R::Type as IrTypeFamily>::ArrType<N>;
}

impl<'itm, R: 'itm> Ir for LocalRef<'itm, R>
where
    &'itm R: Ir,
{
    type Type = <&'itm R as Ir>::Type;
}
impl<'itm, R: 'itm> Ir for LocalSlice<'itm, R>
where
    &'itm [R]: Ir,
{
    type Type = <&'itm [R] as Ir>::Type;
}
