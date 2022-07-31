//! Logic related to the conversion of [`Option<T>`] to and from FFI-compatible representation

use crate::{
    owned::LocalSlice,
    slice::{SliceMut, SliceRef},
    FfiReturn, IntoFfi, ReprC, TryFromReprC,
};

/// Type with an FFI-compatible representation that supports [`Option::None`] values
pub trait Nullable: ReprC {
    /// Return null value
    fn null() -> Self;
    /// Return `true` if the value is null, otherwise `false`
    fn is_null(&self) -> bool;
}

/// Trait that facilitates the implementation of [`IntoFfi`] for [`Option<T>`] of foreign types
pub trait IntoFfiOption: Sized {
    /// [`Option<T>`] equivalent of [`IntoFfi::Target`]
    type Target: ReprC;

    /// Convert from [`Option<Self>`] into [`Self::Target`]
    fn into_ffi(source: Option<Self>) -> Self::Target;
}

/// Trait that facilitates the implementation of [`TryFromReprC`] for [`Option<T>`] of foreign types
pub trait TryFromReprCOption<'itm>: Sized + 'itm {
    /// Type that can be converted from a [`ReprC`] type that was sent over FFI
    type Source: ReprC + Copy;

    /// Type into which state can be stored during conversion. Useful for returning
    /// non-owning types but performing some conversion which requires allocation.
    /// Serves similar purpose as does context in a closure
    type Store: Default;

    /// Perform the fallible conversion
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
    unsafe fn try_from_repr_c(
        source: Self::Source,
        store: &'itm mut Self::Store,
    ) -> Result<Option<Self>, FfiReturn>;
}

impl<T> Nullable for *const T {
    fn null() -> Self {
        core::ptr::null()
    }
    fn is_null(&self) -> bool {
        (*self).is_null()
    }
}
impl<T> Nullable for *mut T {
    fn null() -> Self {
        core::ptr::null_mut()
    }
    fn is_null(&self) -> bool {
        (*self).is_null()
    }
}
impl<T> Nullable for SliceRef<'_, T> {
    fn null() -> Self {
        SliceRef::null()
    }
    fn is_null(&self) -> bool {
        self.is_null()
    }
}
impl<T> Nullable for SliceMut<'_, T> {
    fn null() -> Self {
        SliceMut::null()
    }
    fn is_null(&self) -> bool {
        self.is_null()
    }
}
impl<T: ReprC> Nullable for LocalSlice<T> {
    fn null() -> Self {
        LocalSlice::null()
    }
    fn is_null(&self) -> bool {
        self.is_null()
    }
}

impl<'itm, T: TryFromReprCOption<'itm>> TryFromReprC<'itm> for Option<T> {
    type Source = T::Source;
    type Store = T::Store;

    unsafe fn try_from_repr_c(
        source: Self::Source,
        store: &'itm mut Self::Store,
    ) -> Result<Self, FfiReturn> {
        TryFromReprCOption::try_from_repr_c(source, store)
    }
}

impl<'itm, T: TryFromReprC<'itm>> TryFromReprCOption<'itm> for T
where
    T::Source: Nullable,
{
    type Source = T::Source;
    type Store = T::Store;

    unsafe fn try_from_repr_c(
        source: Self::Source,
        store: &'itm mut Self::Store,
    ) -> Result<Option<Self>, FfiReturn> {
        if source.is_null() {
            return Ok(None);
        }

        Ok(Some(TryFromReprC::try_from_repr_c(source, store)?))
    }
}

impl<T: IntoFfiOption> IntoFfi for Option<T> {
    type Target = T::Target;

    fn into_ffi(self) -> Self::Target {
        IntoFfiOption::into_ffi(self)
    }
}

impl<T: IntoFfi> IntoFfiOption for T
where
    T::Target: Nullable,
{
    type Target = T::Target;

    fn into_ffi(source: Option<Self>) -> Self::Target {
        source.map_or_else(T::Target::null, IntoFfi::into_ffi)
    }
}
