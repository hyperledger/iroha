//! Logic related to the conversion of slices to and from FFI-compatible representation

use crate::{
    owned::LocalSlice, AsReprCRef, FfiOutput, FfiResult, IntoFfi, OutPtr, ReprC, TryFromReprC,
};

/// Trait that facilitates the implementation of [`IntoFfi`] for immutable slices of foreign types
pub trait IntoFfiSliceRef: Sized {
    /// Immutable slice equivalent of [`IntoFfi::Target`]
    type Target: ReprC;

    /// Convert from `&[Self]` into [`Self::Target`]
    fn into_ffi(source: &[Self]) -> Self::Target;
}

/// Trait that facilitates the implementation of [`IntoFfi`] for mutable slices of foreign types
///
/// # Safety
///
/// `[Self]` and `[Self::Target]` must have the same representation, i.e. must be transmutable.
/// This is because it's not possible to mutably reference local context across FFI boundary
/// Additionally, if implemented on a non-robust type the invariant that trap representations
/// will never be written into values of `Self` by foreign code must be upheld at all times
pub unsafe trait IntoFfiSliceMut: Sized {
    /// Mutable slice equivalent of [`IntoFfi::Target`]
    type Target: ReprC;

    /// Convert from `&mut [Self]` into [`Self::Target`]
    fn into_ffi(source: &mut [Self]) -> Self::Target;
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
    /// * [`FfiResult::ArgIsNull`]          - given pointer is null
    /// * [`FfiResult::UnknownHandle`]      - given id doesn't identify any known handle
    /// * [`FfiResult::TrapRepresentation`] - given value contains trap representation
    ///
    /// # Safety
    ///
    /// All conversions from a pointer must ensure pointer validity beforehand
    unsafe fn try_from_repr_c(
        source: Self::Source,
        store: &'slice mut Self::Store,
    ) -> Result<&'slice [Self], FfiResult>;
}

/// Trait that facilitates the implementation of [`TryFromReprC`] for mutable slices of foreign types
pub trait TryFromReprCSliceMut: Sized {
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
    /// * [`FfiResult::ArgIsNull`]          - given pointer is null
    /// * [`FfiResult::UnknownHandle`]      - given id doesn't identify any known handle
    /// * [`FfiResult::TrapRepresentation`] - given value contains trap representation
    ///
    /// # Safety
    ///
    /// All conversions from a pointer must ensure pointer validity beforehand
    unsafe fn try_from_repr_c(
        source: Self::Source,
        store: &mut Self::Store,
    ) -> Result<&mut [Self], FfiResult>;
}

/// Immutable slice with a defined C ABI layout. Consists of data pointer and length
// TODO: Rethink this comment
// NOTE: There is no point in storing lifetime information in these slices
// because that information cannot be sent across an extern FFI boundary
#[repr(C)]
pub struct SliceRef<T>(*const T, usize);

/// Mutable slice with a defined C ABI layout. Consists of data pointer and length
#[repr(C)]
pub struct SliceMut<T>(*mut T, usize);

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
pub struct OutBoxedSlice<T: ReprC>(pub *mut T, pub usize, pub *mut isize);

// NOTE: raw pointers are also `Copy`
impl<T> Copy for SliceRef<T> {}
impl<T> Clone for SliceRef<T> {
    fn clone(&self) -> Self {
        Self(self.0, self.1)
    }
}
impl<T> Copy for SliceMut<T> {}
impl<T> Clone for SliceMut<T> {
    fn clone(&self) -> Self {
        Self(self.0, self.1)
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

impl<T> SliceRef<T> {
    /// Forms a slice from a data pointer and a length.
    pub fn from_raw_parts(ptr: *const T, len: usize) -> Self {
        Self(ptr, len)
    }

    /// Create [`Self`] from shared slice
    pub const fn from_slice(slice: &[T]) -> Self {
        Self(slice.as_ptr(), slice.len())
    }

    /// Convert [`Self`] into a shared slice. Return `None` if data pointer is null
    ///
    /// # Safety
    ///
    /// Data pointer must point to a valid memory
    pub unsafe fn into_slice<'slice>(self) -> Option<&'slice [T]> {
        if self.is_null() {
            return None;
        }

        Some(core::slice::from_raw_parts(self.0, self.1))
    }

    pub(crate) fn null() -> Self {
        // TODO: len could be uninitialized
        Self(core::ptr::null(), 0)
    }

    pub(crate) fn is_null(&self) -> bool {
        self.0.is_null()
    }
}
impl<T> SliceMut<T> {
    /// Create [`Self`] from mutable slice
    pub fn from_slice(slice: &mut [T]) -> Self {
        Self(slice.as_mut_ptr(), slice.len())
    }

    /// Convert [`Self`] into a mutable slice. Return `None` if data pointer is null
    ///
    /// # Safety
    ///
    /// Data pointer must point to a valid memory
    pub unsafe fn into_slice<'slice>(self) -> Option<&'slice mut [T]> {
        if self.is_null() {
            return None;
        }

        Some(core::slice::from_raw_parts_mut(self.0, self.1))
    }

    pub(crate) fn null() -> Self {
        // TODO: len could be uninitialized
        Self(core::ptr::null_mut(), 0)
    }

    pub(crate) fn is_null(&self) -> bool {
        self.0.is_null()
    }
}

impl<T> OutSliceRef<T> {
    pub(crate) unsafe fn write_none(self) {
        self.0.write(core::ptr::null());
    }
}
impl<T> OutSliceMut<T> {
    pub(crate) unsafe fn write_none(self) {
        self.0.write(core::ptr::null_mut());
    }
}
impl<T: ReprC + Copy> OutBoxedSlice<T> {
    const NONE: isize = -1;

    /// Copies bytes from `slice` to `self`
    ///
    /// # Errors
    ///
    /// * [`FfiResult::ArgIsNull`] - if any of the out-pointers in [`Self`] is null
    ///
    /// # Safety
    ///
    /// All conversions from a pointer must ensure pointer validity beforehand
    // For an internally created slice it is guaranteed that len will be valid
    // https://doc.rust-lang.org/std/primitive.pointer.html#method.offset
    #[allow(clippy::expect_used, clippy::unwrap_in_result)]
    pub unsafe fn copy_from_slice(self, slice: Option<&[T]>) -> Result<(), FfiResult> {
        if !self.is_valid() {
            return Err(FfiResult::ArgIsNull);
        }

        slice.map_or_else(
            || self.write_none(),
            |slice_| {
                self.2
                    .write(slice_.len().try_into().expect("Allocation too large"));

                if !self.0.is_null() {
                    for (i, elem) in slice_.iter().take(self.1).enumerate() {
                        self.0.add(i).write(*elem);
                    }
                }
            },
        );

        Ok(())
    }

    pub(crate) unsafe fn write_none(self) {
        self.2.write(Self::NONE);
    }
}

impl<T> OutPtr for OutSliceRef<T> {
    fn is_valid(&self) -> bool {
        !self.0.is_null()
    }
}
impl<T> OutPtr for OutSliceMut<T> {
    fn is_valid(&self) -> bool {
        !self.0.is_null()
    }
}
impl<T: ReprC> OutPtr for OutBoxedSlice<T> {
    fn is_valid(&self) -> bool {
        !self.2.is_null()
    }
}

unsafe impl<T> ReprC for SliceRef<T> {}
unsafe impl<T> ReprC for SliceMut<T> {}
unsafe impl<T> ReprC for OutSliceRef<T> {}
unsafe impl<T> ReprC for OutSliceMut<T> {}
unsafe impl<T: ReprC> ReprC for OutBoxedSlice<T> {}

impl<T> AsReprCRef for SliceRef<T> {
    type Target = Self;

    fn as_ref(&self) -> Self::Target {
        *self
    }
}

//impl<'slice, T: TryFromReprCSliceRef<'slice> + Clone> TryFromReprCSliceRef<'slice>
//    for &'slice [T]
//{
//    type Source = SliceRef<T::Source>;
//    type Store = (Vec<&'slice [T]>, Vec<Vec<T>>);
//
//    unsafe fn try_from_repr_c(
//        source: Self::Source,
//        store: &'slice mut Self::Store,
//    ) -> Result<&[Self], FfiResult> {
//        let prev_store_len = store.1.len();
//        let slice = source.into_slice().ok_or(FfiResult::ArgIsNull)?;
//        store
//            .1
//            .extend(core::iter::repeat_with(Default::default).take(slice.len()));
//
//        let mut substore = &mut store.1[prev_store_len..];
//        for item in slice {
//            let (first, rest) = substore.split_first_mut().expect("Defined");
//            substore = rest;
//            let mut tmp_store = Default::default();
//            let subslice = TryFromReprCSliceRef::try_from_repr_c(*item, &mut tmp_store)?;
//
//            first.extend(subslice.to_vec());
//            //store.0.push(store.1.last().expect("Defined"));
//        }
//
//        Ok(&store.0[..])
//    }
//}
impl<'slice, T: TryFromReprCSliceRef<'slice>> TryFromReprC<'slice> for &'slice [T] {
    type Source = T::Source;
    type Store = T::Store;

    unsafe fn try_from_repr_c(
        source: Self::Source,
        store: &'slice mut Self::Store,
    ) -> Result<Self, FfiResult> {
        TryFromReprCSliceRef::try_from_repr_c(source, store)
    }
}
impl<'slice, T: TryFromReprCSliceMut> TryFromReprC<'slice> for &'slice mut [T] {
    type Source = T::Source;
    type Store = T::Store;

    unsafe fn try_from_repr_c(
        source: Self::Source,
        store: &'slice mut Self::Store,
    ) -> Result<Self, FfiResult> {
        TryFromReprCSliceMut::try_from_repr_c(source, store)
    }
}

impl<T: IntoFfiSliceRef> IntoFfi for &[T] {
    type Target = T::Target;

    fn into_ffi(self) -> Self::Target {
        IntoFfiSliceRef::into_ffi(self)
    }
}
impl<T: IntoFfiSliceMut> IntoFfi for &mut [T] {
    type Target = T::Target;

    fn into_ffi(self) -> Self::Target {
        IntoFfiSliceMut::into_ffi(self)
    }
}
impl<T: IntoFfiSliceRef> IntoFfiSliceRef for &[T] {
    type Target = LocalSlice<T::Target>;

    fn into_ffi(source: &[Self]) -> Self::Target {
        source
            .iter()
            .map(|item| IntoFfiSliceRef::into_ffi(item))
            .collect()
    }
}
impl<T: IntoFfiSliceRef> IntoFfiSliceRef for &mut [T] {
    type Target = LocalSlice<T::Target>;

    fn into_ffi(source: &[Self]) -> Self::Target {
        source
            .iter()
            .map(|item| IntoFfiSliceRef::into_ffi(item))
            .collect()
    }
}

impl<T> FfiOutput for SliceRef<T> {
    type OutPtr = OutSliceRef<T>;

    unsafe fn write(self, dest: Self::OutPtr) -> Result<(), FfiResult> {
        if !dest.is_valid() {
            return Err(FfiResult::ArgIsNull);
        }

        if self.is_null() {
            dest.write_none();
        } else {
            dest.0.write(self.0);
            dest.1.write(self.1);
        }

        Ok(())
    }
}
impl<T> FfiOutput for SliceMut<T> {
    type OutPtr = OutSliceMut<T>;

    unsafe fn write(self, dest: Self::OutPtr) -> Result<(), FfiResult> {
        if !dest.is_valid() {
            return Err(FfiResult::ArgIsNull);
        }

        if self.is_null() {
            dest.write_none();
        } else {
            dest.0.write(self.0);
            dest.1.write(self.1);
        }

        Ok(())
    }
}
