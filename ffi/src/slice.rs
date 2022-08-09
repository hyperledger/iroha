//! Logic related to the conversion of slices to and from FFI-compatible representation
#![allow(clippy::undocumented_unsafe_blocks)]
use core::{marker::PhantomData, mem::MaybeUninit};

use crate::{
    owned::LocalSlice, AsReprCRef, FfiReturn, IntoFfi, OutPtrOf, Output, ReprC, Result,
    TryFromReprC,
};

/// Trait that facilitates the implementation of [`IntoFfi`] for immutable slices of foreign types
pub trait IntoFfiSliceRef<'slice>: Sized {
    /// Immutable slice equivalent of [`IntoFfi::Target`]
    type Target: ReprC;

    /// Convert from `&[Self]` into [`Self::Target`]
    fn into_ffi(source: &'slice [Self]) -> Self::Target;
}

/// Trait that facilitates the implementation of [`IntoFfi`] for mutable slices of foreign types
///
/// # Safety
///
/// `[Self]` and `[Self::Target]` must have the same representation, i.e. must be transmutable.
/// This is because it's not possible to mutably reference local context across FFI boundary
/// Additionally, if implemented on a non-robust type the invariant that trap representations
/// will never be written into values of `Self` by foreign code must be upheld at all times
pub unsafe trait IntoFfiSliceMut<'slice>: Sized {
    /// Mutable slice equivalent of [`IntoFfi::Target`]
    type Target: ReprC + 'slice;

    /// Convert from `&mut [Self]` into [`Self::Target`]
    fn into_ffi(source: &'slice mut [Self]) -> Self::Target;
}

/// Trait that facilitates the implementation of [`TryFromReprC`] for immutable slices of foreign types
pub trait TryFromReprCSliceRef<'slice>: Sized {
    /// Immutable slice equivalent of [`TryFromReprC::Source`]
    type Source: ReprC + Copy;

    /// Type into which state can be stored during conversion. Useful for returning
    /// non-owning types but performing some conversion which requires allocation.
    /// Serves similar purpose as does context in a closure
    type Store: Default;

    /// Convert from [`Self::Source`] into `&[Self]`
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
        store: &'slice mut Self::Store,
    ) -> Result<&'slice [Self]>;
}

/// Trait that facilitates the implementation of [`TryFromReprC`] for mutable slices of foreign types
pub trait TryFromReprCSliceMut<'slice>: Sized {
    /// Mutable slice equivalent of [`TryFromReprC::Source`]
    type Source: ReprC + Copy;

    /// Type into which state can be stored during conversion. Useful for returning
    /// non-owning types but performing some conversion which requires allocation.
    /// Serves similar purpose as does context in a closure
    type Store: Default;

    /// Perform the conversion from [`Self::Source`] into `&mut [Self]`
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
        store: &'slice mut Self::Store,
    ) -> Result<&'slice mut [Self]>;
}

/// Immutable slice with a defined C ABI layout. Consists of data pointer and length
#[repr(C)]
pub struct SliceRef<'data, T>(*const T, usize, PhantomData<&'data T>);

/// Mutable slice with a defined C ABI layout. Consists of data pointer and length
#[repr(C)]
pub struct SliceMut<'data, T>(*mut T, usize, PhantomData<&'data mut T>);

/// Immutable slice with a defined C ABI layout when used as a function return argument. Provides
/// a pointer where data pointer should be stored, and a pointer where length should be stored.
#[repr(C)]
pub struct OutSliceRef<T>(*mut *const T, *mut usize);

/// Mutable slice with a defined C ABI layout when used as a function return argument. Provides
/// a pointer where data pointer should be stored, and a pointer where length should be stored.
#[repr(C)]
pub struct OutSliceMut<T>(*mut *mut T, *mut usize);

/// Owned slice with a defined C ABI layout when used as a function return argument. Provides
/// a pointer to the allocation where the data should be copied into, length of the allocation,
/// and a pointer where total length of the data should be stored in the case that the provided
/// allocation is not large enough to store all the data
///
/// Returned length is [`isize`] to be able to support `None` values when converting types such as [`Option<T>`]
#[repr(C)]
pub struct OutBoxedSlice<T: ReprC>(*mut T, usize, *mut isize);

// NOTE: raw pointers are also `Copy`
impl<T> Copy for SliceRef<'_, T> {}
impl<T> Clone for SliceRef<'_, T> {
    fn clone(&self) -> Self {
        Self(self.0, self.1, PhantomData)
    }
}
impl<T> Copy for SliceMut<'_, T> {}
impl<T> Clone for SliceMut<'_, T> {
    fn clone(&self) -> Self {
        Self(self.0, self.1, PhantomData)
    }
}
impl<T> Copy for OutSliceRef<T> {}
impl<T> Clone for OutSliceRef<T> {
    fn clone(&self) -> Self {
        Self(self.0, self.1)
    }
}
impl<T> Copy for OutSliceMut<T> {}
impl<T> Clone for OutSliceMut<T> {
    fn clone(&self) -> Self {
        Self(self.0, self.1)
    }
}
impl<T: ReprC> Copy for OutBoxedSlice<T> {}
impl<T: ReprC> Clone for OutBoxedSlice<T> {
    fn clone(&self) -> Self {
        Self(self.0, self.1, self.2)
    }
}

impl<'slice, T> SliceRef<'slice, T> {
    /// Forms a slice from a data pointer and a length.
    pub fn from_raw_parts(ptr: *const T, len: usize) -> Self {
        Self(ptr, len, PhantomData)
    }

    /// Create [`Self`] from shared slice
    pub const fn from_slice(slice: &[T]) -> Self {
        Self(slice.as_ptr(), slice.len(), PhantomData)
    }

    /// Convert [`Self`] into a shared slice. Return `None` if data pointer is null
    ///
    /// # Safety
    ///
    /// Data pointer must point to a valid memory
    pub unsafe fn into_rust(self) -> Option<&'slice [T]> {
        if self.is_null() {
            return None;
        }

        Some(core::slice::from_raw_parts(self.0, self.1))
    }

    pub(crate) fn null() -> Self {
        // TODO: len could be uninitialized
        Self(core::ptr::null(), 0, PhantomData)
    }

    pub(crate) fn is_null(&self) -> bool {
        self.0.is_null()
    }
}
impl<'slice, T> SliceMut<'slice, T> {
    /// Create [`Self`] from mutable slice
    pub fn from_slice(slice: &mut [T]) -> Self {
        Self(slice.as_mut_ptr(), slice.len(), PhantomData)
    }

    /// Convert [`Self`] into a mutable slice. Return `None` if data pointer is null
    ///
    /// # Safety
    ///
    /// Data pointer must point to a valid memory
    pub unsafe fn into_rust(self) -> Option<&'slice mut [T]> {
        if self.is_null() {
            return None;
        }

        Some(core::slice::from_raw_parts_mut(self.0, self.1))
    }

    pub(crate) fn null() -> Self {
        // TODO: len could be uninitialized
        Self(core::ptr::null_mut(), 0, PhantomData)
    }

    pub(crate) fn is_null(&self) -> bool {
        self.0.is_null()
    }
}

impl<T> OutSliceRef<T> {
    /// Construct `Self` from a slice of uninitialized elements
    pub fn from_raw(mut data_ptr: Option<&mut *const T>, len_ptr: &mut MaybeUninit<usize>) -> Self {
        Self(
            data_ptr
                .take()
                .map_or_else(core::ptr::null_mut, |item| <*mut _>::from(item)),
            len_ptr.as_mut_ptr(),
        )
    }
    pub(crate) unsafe fn write_none(self) {
        self.0.write(core::ptr::null());
    }
}
impl<T> OutSliceMut<T> {
    /// Construct `Self` from a slice of uninitialized elements
    pub fn from_raw(mut data_ptr: Option<&mut *mut T>, len_ptr: &mut MaybeUninit<usize>) -> Self {
        Self(
            data_ptr
                .take()
                .map_or_else(core::ptr::null_mut, |item| <*mut _>::from(item)),
            len_ptr.as_mut_ptr(),
        )
    }
    pub(crate) unsafe fn write_none(self) {
        self.0.write(core::ptr::null_mut());
    }
}
impl<T: ReprC + Copy> OutBoxedSlice<T> {
    const NONE: isize = -1;

    /// Construct `Self` from a slice of uninitialized elements
    pub fn from_uninit_slice(
        mut data_ptr: Option<&mut [MaybeUninit<T>]>,
        len_ptr: &mut MaybeUninit<isize>,
    ) -> Self {
        let len = data_ptr.as_ref().map_or(0, |slice| slice.len());

        Self(
            data_ptr
                .take()
                .map_or_else(core::ptr::null_mut, |item| <[_]>::as_mut_ptr(item).cast()),
            len,
            len_ptr.as_mut_ptr(),
        )
    }

    pub(crate) unsafe fn write_none(self) {
        self.2.write(Self::NONE);
    }
}

unsafe impl<T> ReprC for SliceRef<'_, T> {}
unsafe impl<T> ReprC for SliceMut<'_, T> {}
unsafe impl<T> ReprC for OutSliceRef<T> {}
unsafe impl<T> ReprC for OutSliceMut<T> {}
unsafe impl<T: ReprC> ReprC for OutBoxedSlice<T> {}

impl<'slice, T: 'slice> AsReprCRef<'slice> for SliceRef<'slice, T> {
    type Target = Self;

    fn as_ref(&self) -> Self::Target {
        *self
    }
}

impl<'slice, T: TryFromReprCSliceRef<'slice>> TryFromReprC<'slice> for &'slice [T] {
    type Source = T::Source;
    type Store = T::Store;

    unsafe fn try_from_repr_c(
        source: Self::Source,
        store: &'slice mut Self::Store,
    ) -> Result<Self> {
        TryFromReprCSliceRef::try_from_repr_c(source, store)
    }
}
impl<'slice, T: TryFromReprCSliceMut<'slice>> TryFromReprC<'slice> for &'slice mut [T] {
    type Source = T::Source;
    type Store = T::Store;

    unsafe fn try_from_repr_c(
        source: Self::Source,
        store: &'slice mut Self::Store,
    ) -> Result<Self> {
        TryFromReprCSliceMut::try_from_repr_c(source, store)
    }
}

impl<'slice, T: IntoFfiSliceRef<'slice>> IntoFfi for &'slice [T] {
    type Target = T::Target;

    fn into_ffi(self) -> Self::Target {
        IntoFfiSliceRef::into_ffi(self)
    }
}
impl<'slice, T: IntoFfiSliceMut<'slice>> IntoFfi for &'slice mut [T] {
    type Target = T::Target;

    fn into_ffi(self) -> Self::Target {
        IntoFfiSliceMut::into_ffi(self)
    }
}
impl<'slice, T: IntoFfiSliceRef<'slice>> IntoFfiSliceRef<'slice> for &'slice [T] {
    type Target = LocalSlice<T::Target>;

    fn into_ffi(source: &[Self]) -> Self::Target {
        source
            .iter()
            .map(|item| IntoFfiSliceRef::into_ffi(item))
            .collect()
    }
}
impl<'slice, T: IntoFfiSliceRef<'slice>> IntoFfiSliceRef<'slice> for &'slice mut [T] {
    type Target = LocalSlice<T::Target>;

    fn into_ffi(source: &'slice [Self]) -> Self::Target {
        source
            .iter()
            .map(|item| IntoFfiSliceRef::into_ffi(item))
            .collect()
    }
}

impl<'data, T> OutPtrOf<SliceRef<'data, T>> for OutSliceRef<T> {
    unsafe fn write(self, source: SliceRef<'data, T>) -> Result<()> {
        if self.1.is_null() {
            return Err(FfiReturn::ArgIsNull);
        }

        if self.0.is_null() {
            self.write_none();
        } else {
            self.0.write(source.0);
            self.1.write(source.1);
        }

        Ok(())
    }
}
impl<'data, T> OutPtrOf<SliceMut<'data, T>> for OutSliceMut<T> {
    unsafe fn write(self, source: SliceMut<'data, T>) -> Result<()> {
        if self.1.is_null() {
            return Err(FfiReturn::ArgIsNull);
        }

        if self.0.is_null() {
            self.write_none();
        } else {
            self.0.write(source.0);
            self.1.write(source.1);
        }

        Ok(())
    }
}
impl<T: ReprC + Copy> OutPtrOf<LocalSlice<T>> for OutBoxedSlice<T> {
    unsafe fn write(self, source: LocalSlice<T>) -> Result<()> {
        if self.2.is_null() {
            return Err(FfiReturn::ArgIsNull);
        }

        // slice len is never larger than `isize::MAX`
        #[allow(clippy::expect_used)]
        source.into_rust().map_or_else(
            || self.write_none(),
            |slice| {
                self.2
                    .write(slice.len().try_into().expect("Allocation too large"));

                if !self.0.is_null() {
                    for (i, elem) in slice.iter().take(self.1).enumerate() {
                        self.0.add(i).write(*elem);
                    }
                }
            },
        );

        Ok(())
    }
}

impl<'data, T> Output for SliceRef<'data, T> {
    type OutPtr = OutSliceRef<T>;
}
impl<'data, T> Output for SliceMut<'data, T> {
    type OutPtr = OutSliceMut<T>;
}
