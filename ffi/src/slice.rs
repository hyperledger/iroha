//! Logic related to the conversion of slices to and from FFI-compatible representation

use alloc::{boxed::Box, vec::Vec};
use core::slice;

use crate::ReprC;

crate::decl_ffi_fns! { dealloc }

/// Immutable slice `&[C]` with a defined C ABI layout. Consists of a data pointer and a length.
/// If the data pointer is set to `null`, the struct represents `Option<&[C]>`.
#[repr(C)]
#[derive(Debug)]
pub struct SliceRef<C>(*const C, usize);

/// Mutable slice `&mut [C]` with a defined C ABI layout. Consists of a data pointer and a length.
/// If the data pointer is set to `null`, the struct represents `Option<&mut [C]>`.
#[repr(C)]
#[derive(Debug)]
pub struct SliceMut<C>(*mut C, usize);

/// Owned slice `Box<[C]>` with a defined C ABI layout. Consists of a data pointer and a length.
/// Used in place of a function out-pointer to transfer ownership of the slice to the caller.
/// If the data pointer is set to `null`, the struct represents `Option<Box<[C]>>`.
#[repr(C)]
#[derive(Debug)]
pub struct OutBoxedSlice<C>(*mut C, usize);

impl<C> Copy for SliceRef<C> {}
impl<C> Clone for SliceRef<C> {
    fn clone(&self) -> Self {
        *self
    }
}
impl<C> Copy for SliceMut<C> {}
impl<C> Clone for SliceMut<C> {
    fn clone(&self) -> Self {
        *self
    }
}
impl<C> Copy for OutBoxedSlice<C> {}
impl<C> Clone for OutBoxedSlice<C> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<C> SliceRef<C> {
    /// Set the slice's data pointer to null
    pub const fn null() -> Self {
        // TODO: len could be uninitialized
        Self(core::ptr::null(), 0)
    }

    /// Create a slice from a data pointer and a length.
    pub fn from_raw_parts(ptr: *const C, len: usize) -> Self {
        Self(ptr, len)
    }

    /// Returns a raw pointer to the slice's buffer.
    pub fn as_ptr(&self) -> *const C {
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
    pub const fn from_slice(source: Option<&[C]>) -> Self {
        if let Some(slice) = source {
            Self(slice.as_ptr(), slice.len())
        } else {
            Self(core::ptr::null(), 0)
        }
    }

    /// Convert [`Self`] into a shared slice. Return `None` if data pointer is null.
    /// Unlike [`core::slice::from_raw_parts`], data pointer is allowed to be null.
    ///
    /// # Safety
    ///
    /// Check [`core::slice::from_raw_parts`]
    pub unsafe fn into_rust<'slice>(self) -> Option<&'slice [C]> {
        if self.0.is_null() {
            return None;
        }

        Some(slice::from_raw_parts(self.0, self.1))
    }
}
impl<C> SliceMut<C> {
    /// Set the slice's data pointer to null
    pub const fn null_mut() -> Self {
        // TODO: len could be uninitialized
        Self(core::ptr::null_mut(), 0)
    }

    /// Create a slice from a data pointer and a length.
    pub fn from_raw_parts_mut(ptr: *mut C, len: usize) -> Self {
        Self(ptr, len)
    }

    /// Returns a raw pointer to the slice's buffer.
    pub fn as_mut_ptr(&self) -> *mut C {
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
    pub fn from_slice(source: Option<&mut [C]>) -> Self {
        source.map_or_else(
            || Self(core::ptr::null_mut(), 0),
            |slice| Self(slice.as_mut_ptr(), slice.len()),
        )
    }

    /// Convert [`Self`] into a mutable slice. Return `None` if data pointer is null.
    /// Unlike [`core::slice::from_raw_parts_mut`], data pointer is allowed to be null.
    ///
    /// # Safety
    ///
    /// Check [`core::slice::from_raw_parts_mut`]
    pub unsafe fn into_rust<'slice>(self) -> Option<&'slice mut [C]> {
        if self.0.is_null() {
            return None;
        }

        Some(slice::from_raw_parts_mut(self.0, self.1))
    }
}
impl<C: ReprC> OutBoxedSlice<C> {
    /// Create a slice from a data pointer and a length.
    pub fn from_raw_parts(ptr: *mut C, len: usize) -> Self {
        Self(ptr, len)
    }

    /// Return a raw pointer to the slice's buffer.
    pub fn as_mut_ptr(&self) -> *mut C {
        self.0
    }

    /// Return `true` if the slice contains no elements.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Return the number of elements in the slice.
    pub fn len(&self) -> usize {
        self.1
    }

    /// Create [`Self`] from a `Box<[T]>`
    pub fn from_boxed_slice(source: Option<Box<[C]>>) -> Self {
        source.map_or_else(
            || Self(core::ptr::null_mut(), 0),
            |boxed_slice| {
                let mut boxed_slice = core::mem::ManuallyDrop::new(boxed_slice);
                Self(boxed_slice.as_mut_ptr(), boxed_slice.len())
            },
        )
    }

    /// Create [`Self`] from a `Vec<T>`
    pub fn from_vec(source: Option<Vec<C>>) -> Self {
        source.map_or_else(
            || Self(core::ptr::null_mut(), 0),
            |boxed_slice| {
                let mut boxed_slice = core::mem::ManuallyDrop::new(boxed_slice.into_boxed_slice());
                Self(boxed_slice.as_mut_ptr(), boxed_slice.len())
            },
        )
    }

    /// Create a `Vec<T>` directly from the raw components of another vector.
    /// Unlike [`Vec::from_raw_parts`], data pointer is allowed to be null.
    ///
    /// # Safety
    ///
    /// Check [`Vec::from_raw_parts`]
    pub unsafe fn into_rust(self) -> Option<Vec<C>> {
        if self.0.is_null() {
            return None;
        }

        Some(
            Box::<[_]>::from_raw(slice::from_raw_parts_mut(self.as_mut_ptr(), self.len())).to_vec(),
        )
    }

    pub(crate) unsafe fn deallocate(&self) -> bool {
        if self.is_empty() {
            return true;
        }

        if let Ok(layout) = core::alloc::Layout::array::<C>(self.len()) {
            __dealloc(self.as_mut_ptr().cast(), layout.size(), layout.align());
            return true;
        }

        false
    }
}

// SAFETY: Robust type with a defined C ABI
unsafe impl<T: ReprC> ReprC for SliceRef<T> {}
// SAFETY: Robust type with a defined C ABI
unsafe impl<T: ReprC> ReprC for SliceMut<T> {}
// SAFETY: Robust type with a defined C ABI
unsafe impl<T: ReprC> ReprC for OutBoxedSlice<T> {}
