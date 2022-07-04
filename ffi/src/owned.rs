//! Logic related to the conversion of structures with ownership. Ownership is never transferred
//! across FFI. This means that contents of these structures are copied into provided containers

use crate::{
    slice::{OutBoxedSlice, SliceRef},
    AsReprCRef, FfiOutput, FfiResult, IntoFfi, ReprC, TryFromReprC,
};

/// Wrapper around `T` that is local to the conversion site. This structure carries
/// ownership and care must be taken not to let it transfer ownership into an FFI function
// NOTE: It's not possible to mutably reference local context
#[derive(Clone)]
#[repr(transparent)]
pub struct Local<T>(T);

unsafe impl<T: ReprC> ReprC for Local<T> {}

impl<T: ReprC> AsReprCRef for Local<T> {
    type Target = *const T;

    fn as_ref(&self) -> Self::Target {
        &(self.0)
    }
}
impl<T: ReprC + Copy> FfiOutput for Local<T> {
    type OutPtr = *mut T;

    unsafe fn write(self, dest: Self::OutPtr) -> Result<(), FfiResult> {
        if dest.is_null() {
            return Err(FfiResult::ArgIsNull);
        }

        dest.write(self.0);
        Ok(())
    }
}
impl<T> Local<T> {
    /// Create [`Self`] from the given element
    pub fn new(elem: T) -> Self {
        Self(elem)
    }
}

unsafe impl<T: ReprC> ReprC for LocalSlice<T> {}
impl<T> LocalSlice<T> {
    /// Convert [`Self`] into a boxed slice
    ///
    /// # Safety
    ///
    /// Data pointer must point to a valid memory
    pub unsafe fn into_slice(self) -> Option<Box<[T]>> {
        if self.is_null() {
            return None;
        }

        let slice = core::mem::ManuallyDrop::new(self);
        Some(Box::from_raw(core::slice::from_raw_parts_mut(
            slice.0, slice.1,
        )))
    }

    /// Convert [`Self`] into a shared slice
    ///
    /// # Safety
    ///
    /// Data pointer must point to a valid memory
    pub unsafe fn as_slice<'slice>(&self) -> &'slice [T] {
        core::slice::from_raw_parts(self.0, self.1)
    }
}

/// Wrapper around [`Box<[T]>`] that is local to the conversion site. This structure carries
/// ownership and care must be taken not to let it transfer ownership into an FFI function
// NOTE: It's not possible to mutably reference local context
#[derive(Debug)]
#[repr(C)]
pub struct LocalSlice<T>(*mut T, usize);

impl<T> LocalSlice<T> {
    pub(crate) fn null() -> Self {
        // TODO: len could be uninitialized
        Self(core::ptr::null_mut(), 0)
    }

    pub(crate) fn is_null(&self) -> bool {
        self.0.is_null()
    }
}

impl<A> FromIterator<A> for LocalSlice<A> {
    fn from_iter<T: IntoIterator<Item = A>>(iter: T) -> Self {
        let items: Box<[_]> = iter.into_iter().collect();
        let mut items = core::mem::ManuallyDrop::new(items);

        Self(items.as_mut_ptr(), items.len())
    }
}

impl<T> Drop for LocalSlice<T> {
    fn drop(&mut self) {
        if self.is_null() {
            return;
        }

        // SAFETY: Data pointer must either be a null pointer or point to a valid memory
        unsafe { Box::from_raw(core::slice::from_raw_parts_mut(self.0, self.1)) };
    }
}
impl<T> AsReprCRef for LocalSlice<T> {
    type Target = SliceRef<T>;

    fn as_ref(&self) -> Self::Target {
        if self.is_null() {
            return SliceRef::null();
        }

        SliceRef::from_raw_parts(self.0, self.1)
    }
}
impl<T: ReprC + Copy> FfiOutput for LocalSlice<T> {
    type OutPtr = OutBoxedSlice<T>;

    unsafe fn write(self, dest: Self::OutPtr) -> Result<(), FfiResult> {
        let slice = self.into_slice();
        dest.copy_from_slice(slice.as_deref())
    }
}

impl<T: IntoFfi> IntoFfi for Vec<T>
where
    T::Target: ReprC,
{
    type Target = LocalSlice<T::Target>;

    fn into_ffi(self) -> Self::Target {
        self.into_iter().map(IntoFfi::into_ffi).collect()
    }
}

impl<'itm, T: TryFromReprC<'itm>> TryFromReprC<'itm> for Vec<T> {
    type Source = SliceRef<T::Source>;
    type Store = Vec<T::Store>;

    // There will always be at least one element in the subslice
    #[allow(clippy::expect_used, clippy::unwrap_in_result)]
    unsafe fn try_from_repr_c(
        source: Self::Source,
        store: &'itm mut Self::Store,
    ) -> Result<Self, FfiResult> {
        let prev_store_len = store.len();
        let slice = source.into_slice().ok_or(FfiResult::ArgIsNull)?;
        store.extend(core::iter::repeat_with(Default::default).take(slice.len()));

        let mut substore = &mut store[prev_store_len..];
        let mut res = vec![];
        for elem in slice {
            let (first, rest) = substore.split_first_mut().expect("Defined");
            substore = rest;
            res.push(<T as TryFromReprC<'itm>>::try_from_repr_c(*elem, first)?);
        }

        Ok(res)
    }
}

impl<'itm> TryFromReprC<'itm> for String {
    type Source = <Vec<u8> as TryFromReprC<'itm>>::Source;
    type Store = ();

    unsafe fn try_from_repr_c(
        source: Self::Source,
        _: &mut Self::Store,
    ) -> Result<Self, FfiResult> {
        String::from_utf8(source.into_slice().ok_or(FfiResult::ArgIsNull)?.to_owned())
            .map_err(|_e| FfiResult::Utf8Error)
    }
}
impl<'itm> TryFromReprC<'itm> for &'itm str {
    type Source = <&'itm [u8] as TryFromReprC<'itm>>::Source;
    type Store = ();

    unsafe fn try_from_repr_c(
        source: Self::Source,
        _: &mut Self::Store,
    ) -> Result<Self, FfiResult> {
        core::str::from_utf8(source.into_slice().ok_or(FfiResult::ArgIsNull)?)
            .map_err(|_e| FfiResult::Utf8Error)
    }
}

impl IntoFfi for String {
    type Target = <Vec<u8> as IntoFfi>::Target;

    fn into_ffi(self) -> Self::Target {
        self.into_bytes().into_ffi()
    }
}

impl<'slice> IntoFfi for &'slice str {
    type Target = <&'slice [u8] as IntoFfi>::Target;

    fn into_ffi(self) -> Self::Target {
        self.as_bytes().into_ffi()
    }
}

unsafe impl<T: ReprC, const N: usize> ReprC for [T; N] {}
impl<T: IntoFfi, const N: usize> IntoFfi for [T; N]
where
    T::Target: ReprC,
{
    type Target = LocalSlice<T::Target>;

    fn into_ffi(self) -> Self::Target {
        self.into_iter().map(IntoFfi::into_ffi).collect()
    }
}

//impl<T: IntoFfi, const N: usize> TryFromReprC for [T; N]
//where
//    T::Target: ReprC,
//{
//    type Target = LocalSlice<T::Target>;
//
//    fn into_ffi(self) -> Self::Target {
//        self.into_iter().map(IntoFfi::into_ffi).collect()
//    }
//}
