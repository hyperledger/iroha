//! Logic related to the conversion of slices to and from FFI-compatible representation

use core::mem::MaybeUninit;

use crate::{FfiReturn, OutPtrOf, ReprC, Result};

/// Immutable slice with a defined C ABI layout. Consists of data pointer and length
#[repr(C)]
#[derive(Debug)]
pub struct SliceRef<T>(*const T, usize);

/// Mutable slice with a defined C ABI layout. Consists of data pointer and length
#[repr(C)]
#[derive(Debug)]
pub struct SliceMut<T>(*mut T, usize);

/// Owned slice with a defined C ABI layout when used as a function return argument. Provides
/// a pointer to the allocation where the data should be copied into, length of the allocation,
/// and a pointer where total length of the data should be stored in the case that the provided
/// allocation is not large enough to store all the data
///
/// Returned length is [`isize`] to be able to support `None` values when converting types such as [`Option<T>`]
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct OutBoxedSlice<T>(pub *mut T, pub usize, pub *mut isize);

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

impl<T> SliceRef<T> {
    /// Forms a slice from a data pointer and a length.
    pub fn from_raw_parts(ptr: *const T, len: usize) -> Self {
        Self(ptr, len)
    }

    /// Returns a raw pointer to the slice's buffer.
    pub fn as_ptr(&self) -> *const T {
        self.0
    }

    /// Returns `true` if the slice contains no elements.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Returns the number of elements in the slice.
    pub fn len(&self) -> usize {
        self.1
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
    pub unsafe fn into_rust<'slice>(self) -> Option<&'slice [T]> {
        if self.is_null() {
            return None;
        }

        Some(core::slice::from_raw_parts(self.0, self.1))
    }

    pub(crate) fn is_null(&self) -> bool {
        self.0.is_null()
    }
}
impl<T> SliceMut<T> {
    /// Forms a slice from a data pointer and a length.
    pub fn from_raw_parts_mut(ptr: *mut T, len: usize) -> Self {
        Self(ptr, len)
    }

    /// Returns a raw pointer to the slice's buffer.
    pub fn as_mut_ptr(&self) -> *mut T {
        self.0
    }

    /// Returns `true` if the slice contains no elements.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Returns the number of elements in the slice.
    pub fn len(&self) -> usize {
        self.1
    }

    /// Create [`Self`] from mutable slice
    pub fn from_slice(slice: &mut [T]) -> Self {
        Self(slice.as_mut_ptr(), slice.len())
    }

    /// Convert [`Self`] into a mutable slice. Return `None` if data pointer is null
    ///
    /// # Safety
    ///
    /// Data pointer must point to a valid memory
    pub unsafe fn into_rust<'slice>(self) -> Option<&'slice mut [T]> {
        if self.is_null() {
            return None;
        }

        Some(core::slice::from_raw_parts_mut(self.0, self.1))
    }

    pub(crate) fn is_null(&self) -> bool {
        self.0.is_null()
    }
}

impl<T> OutBoxedSlice<T> {
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

    /// Write the equivalent of `Option<T>::None`
    ///
    /// # Safety
    ///
    /// The pointer to [`OutBoxedSlice`]'s total length must be valid for writes
    pub unsafe fn write_none(self) {
        self.2.write(Self::NONE);
    }
}

// SAFETY: Implementing type is robust with a defined C ABI
unsafe impl<T> ReprC for SliceRef<T> where *const T: ReprC {}
// SAFETY: Implementing type is robust with a defined C ABI
unsafe impl<T> ReprC for SliceMut<T> where *mut T: ReprC {}
// SAFETY: Implementing type is robust with a defined C ABI
unsafe impl<T> ReprC for OutBoxedSlice<T> where T: ReprC {}

impl<T: ReprC> OutPtrOf<SliceRef<T>> for OutBoxedSlice<T> {
    unsafe fn write(self, source: SliceRef<T>) -> Result<()> {
        self.write(SliceMut::from_raw_parts_mut(
            source.as_ptr() as *mut _,
            source.len(),
        ))
    }
}
impl<T: ReprC> OutPtrOf<SliceMut<T>> for OutBoxedSlice<T> {
    unsafe fn write(self, source: SliceMut<T>) -> Result<()> {
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
