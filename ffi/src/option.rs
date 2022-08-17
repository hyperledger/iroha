//! Logic related to the conversion of [`Option<T>`] to and from FFI-compatible representation

use crate::{
    slice::{SliceMut, SliceRef},
    FfiReturn, FfiType, IntoFfi, ReprC, TryFromReprC,
};

/// Indicates that the `Option<T>` can be converted into an FFI compatible representation
pub trait FfiOption: Sized {
    /// Corresponding FFI-compatible type
    type ReprC: ReprC;
}

/// Type with an FFI-compatible representation that supports [`Option::None`] values
pub trait Nullable: ReprC {
    /// Return null value
    fn null() -> Self;
    /// Return `true` if the value is null, otherwise `false`
    fn is_null(&self) -> bool;
}

/// Trait that facilitates the implementation of [`IntoFfi`] for [`Option<T>`] of foreign types
pub trait IntoFfiOption: FfiOption {
    /// [`Option<T>`] equivalent of [`IntoFfi::Store`]
    type Store: Default;

    /// Convert from [`Option<Self>`] into [`Self::Target`]
    fn into_ffi(source: Option<Self>, store: &mut Self::Store) -> Self::ReprC;
}

/// Trait that facilitates the implementation of [`TryFromReprC`] for [`Option<T>`] of foreign types
pub trait TryFromReprCOption<'itm>: FfiOption + 'itm {
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
        source: Self::ReprC,
        store: &'itm mut Self::Store,
    ) -> Result<Option<Self>, FfiReturn>;
}

impl<T> Nullable for *const T
where
    Self: ReprC,
{
    fn null() -> Self {
        core::ptr::null()
    }
    fn is_null(&self) -> bool {
        (*self).is_null()
    }
}
impl<T> Nullable for *mut T
where
    Self: ReprC,
{
    fn null() -> Self {
        core::ptr::null_mut()
    }
    fn is_null(&self) -> bool {
        (*self).is_null()
    }
}
impl<T> Nullable for SliceRef<T>
where
    Self: ReprC,
{
    fn null() -> Self {
        SliceRef::null()
    }
    fn is_null(&self) -> bool {
        self.is_null()
    }
}
impl<T> Nullable for SliceMut<T>
where
    Self: ReprC,
{
    fn null() -> Self {
        SliceMut::null()
    }
    fn is_null(&self) -> bool {
        self.is_null()
    }
}

impl<T: FfiOption> FfiType for Option<T> {
    type ReprC = T::ReprC;
}

impl<T: FfiType> FfiOption for T
where
    T::ReprC: Nullable,
{
    type ReprC = T::ReprC;
}

impl<'itm, T: TryFromReprC<'itm>> TryFromReprCOption<'itm> for T
where
    T::ReprC: Nullable,
{
    type Store = T::Store;

    unsafe fn try_from_repr_c(
        source: Self::ReprC,
        store: &'itm mut Self::Store,
    ) -> Result<Option<Self>, FfiReturn> {
        if source.is_null() {
            return Ok(None);
        }

        Ok(Some(TryFromReprC::try_from_repr_c(source, store)?))
    }
}

impl<'itm, T: TryFromReprCOption<'itm>> TryFromReprC<'itm> for Option<T> {
    type Store = T::Store;

    unsafe fn try_from_repr_c(
        source: Self::ReprC,
        store: &'itm mut Self::Store,
    ) -> Result<Self, FfiReturn> {
        TryFromReprCOption::try_from_repr_c(source, store)
    }
}

impl<T: IntoFfiOption> IntoFfi for Option<T> {
    type Store = T::Store;

    fn into_ffi(self, store: &mut Self::Store) -> Self::ReprC {
        IntoFfiOption::into_ffi(self, store)
    }
}

impl<T: IntoFfi> IntoFfiOption for T
where
    T::ReprC: Nullable,
{
    type Store = T::Store;

    fn into_ffi(source: Option<Self>, store: &mut Self::Store) -> Self::ReprC {
        source.map_or_else(T::ReprC::null, |item| IntoFfi::into_ffi(item, store))
    }
}
