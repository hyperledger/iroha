//! Logic related to the conversion of [`Option<T>`] to and from FFI-compatible representation

use crate::{
    ir::{Ir, IrTypeOf},
    repr_c::{COutPtr, CType, CTypeConvert, NonLocal},
    FfiConvert, FfiOutPtr, FfiType, ReprC, Result,
};

/// Type that has at least one trap representation that can be used as a niche value. The
/// niche value is used in the serialization of [`Option<T>`]. For example, [`Option<bool>`]
/// will be serilized into one byte and [`Option<*const T>`] will take the size of the pointer
pub trait Niche: FfiType {
    /// The niche value of the type
    const NICHE_VALUE: Self::ReprC;
}

/// Marker struct for [`Option<T>`]
pub struct IrOption<T: Niche<ReprC = N>, N>(pub Option<T>);

impl<T: Niche> IrTypeOf<Option<T>> for IrOption<T, T::ReprC> {
    #[inline]
    fn into_ir(source: Option<T>) -> Self {
        Self(source)
    }
    #[inline]
    fn into_rust(self) -> Option<T> {
        self.0
    }
}

impl<T: Niche> From<Option<T>> for IrOption<T, T::ReprC> {
    fn from(source: Option<T>) -> Self {
        Self(source)
    }
}

impl<'itm, T, U> Niche for &'itm T
where
    Self: FfiType<ReprC = *const U>,
{
    const NICHE_VALUE: Self::ReprC = core::ptr::null();
}

impl<'itm, T, U> Niche for &'itm mut T
where
    Self: FfiType<ReprC = *mut U>,
{
    const NICHE_VALUE: Self::ReprC = core::ptr::null_mut();
}

impl<T: Niche> Ir for Option<T> {
    type Type = IrOption<T, T::ReprC>;
}

impl<T: Niche> CType for IrOption<T, T::ReprC> {
    type ReprC = T::ReprC;
}
// TODO: Hopefully, compiler will elide checks for Option<&T>, Option<&mut T>, Option<*const T>
// if not U parameter can be used to distinguish set them apart from other type conversions
impl<'itm, T: FfiConvert<'itm, U> + Niche<ReprC = U>, U: ReprC> CTypeConvert<'itm, U>
    for IrOption<T, U>
where
    T::ReprC: PartialEq,
{
    type RustStore = T::RustStore;
    type FfiStore = T::FfiStore;

    fn into_repr_c(self, store: &'itm mut Self::RustStore) -> U {
        if let Some(value) = self.0 {
            return value.into_ffi(store);
        }

        T::NICHE_VALUE
    }

    unsafe fn try_from_repr_c(source: U, store: &'itm mut Self::FfiStore) -> Result<Self> {
        if source == T::NICHE_VALUE {
            return Ok(Self(None));
        }

        Ok(Self(Some(T::try_from_ffi(source, store)?)))
    }
}

impl<T: FfiOutPtr + Niche> COutPtr for IrOption<T, T::ReprC> {
    type OutPtr = T::OutPtr;
}

// SAFETY: Option<T> with a niche doesn't use store if it's inner types don't use it
unsafe impl<T: Niche + Ir> NonLocal for IrOption<T, T::ReprC> where T::Type: NonLocal {}
