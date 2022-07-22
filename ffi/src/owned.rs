//! Logic related to the conversion of structures with ownership. Ownership is never transferred
//! across FFI. This means that contents of these structures are copied into provided containers

use crate::{
    slice::{OutBoxedSlice, SliceRef},
    AsReprCRef, FfiResult, IntoFfi, Output, ReprC, TryFromReprC,
};

/// Wrapper around `T` that is local to the conversion site. This structure carries
/// ownership and care must be taken not to let it transfer ownership into an FFI function
// NOTE: It's not possible to mutably reference local context
#[derive(Clone)]
#[repr(transparent)]
pub struct Local<T>(pub(crate) T);

/// Wrapper around [`Option<Box<[T]>>`] that is local to the conversion site. This structure
/// carries ownership and care must be taken not to let it transfer ownership into FFI function
// NOTE: It's not possible to mutably reference local context
#[derive(Debug)]
#[repr(C)]
pub struct LocalSlice<T: ReprC>(*const T, usize, core::marker::PhantomData<T>);

unsafe impl<T: ReprC> ReprC for Local<T> {}
unsafe impl<T: ReprC> ReprC for LocalSlice<T> {}

impl<T: ReprC> Drop for LocalSlice<T> {
    fn drop(&mut self) {
        if self.is_null() {
            return;
        }

        // SAFETY: Data pointer must either be a null pointer or point to a valid memory
        unsafe { Box::from_raw(core::slice::from_raw_parts_mut(self.0 as *mut T, self.1)) };
    }
}

impl<A: ReprC> FromIterator<A> for LocalSlice<A> {
    fn from_iter<T: IntoIterator<Item = A>>(iter: T) -> Self {
        let items: Box<[_]> = iter.into_iter().collect();
        let mut items = core::mem::ManuallyDrop::new(items);

        Self(items.as_mut_ptr(), items.len(), core::marker::PhantomData)
    }
}

impl<'itm, T: ReprC + 'itm> AsReprCRef<'itm> for Local<T> {
    type Target = *const T;

    fn as_ref(&self) -> Self::Target {
        &(self.0)
    }
}
impl<'slice, T: ReprC + 'slice> AsReprCRef<'slice> for LocalSlice<T> {
    type Target = SliceRef<'slice, T>;

    fn as_ref(&self) -> Self::Target {
        if self.is_null() {
            return SliceRef::null();
        }

        SliceRef::from_raw_parts(self.0, self.1)
    }
}

impl<T: ReprC + Copy> Output for Local<T> {
    type OutPtr = *mut T;
}
impl<'data, T: ReprC + Copy> Output for LocalSlice<T> {
    type OutPtr = OutBoxedSlice<T>;
}

impl<T> Local<T> {
    /// Create [`Self`] from the given element
    pub fn new(elem: T) -> Self {
        Self(elem)
    }
}

impl<T: ReprC> LocalSlice<T> {
    /// Convert [`Self`] into a boxed slice
    ///
    /// # Safety
    ///
    /// Data pointer must point to a valid memory
    pub unsafe fn into_rust(self) -> Option<Box<[T]>> {
        if self.is_null() {
            return None;
        }

        let slice = core::mem::ManuallyDrop::new(self);
        Some(Box::from_raw(core::slice::from_raw_parts_mut(
            slice.0 as *mut T,
            slice.1,
        )))
    }

    /// Convert [`Self`] into a shared slice
    ///
    /// # Safety
    ///
    /// Data pointer must point to a valid memory
    pub unsafe fn as_rust<'slice>(&self) -> Option<&'slice [T]> {
        if self.is_null() {
            return None;
        }

        Some(core::slice::from_raw_parts(self.0, self.1))
    }

    /// Construct `None` variant
    pub fn null() -> Self {
        // TODO: len could be uninitialized
        Self(core::ptr::null_mut(), 0, core::marker::PhantomData)
    }

    /// Return true if type is null, otherwhise false
    pub fn is_null(&self) -> bool {
        self.0.is_null()
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
    type Source = SliceRef<'itm, T::Source>;
    type Store = Vec<T::Store>;

    unsafe fn try_from_repr_c(
        source: Self::Source,
        store: &'itm mut Self::Store,
    ) -> Result<Self, FfiResult> {
        let prev_store_len = store.len();
        let slice = source.into_rust().ok_or(FfiResult::ArgIsNull)?;
        store.extend(core::iter::repeat_with(Default::default).take(slice.len()));

        let mut substore = &mut store[prev_store_len..];
        let mut res = Vec::with_capacity(slice.len());

        let mut i = 0;
        while let Some((first, rest)) = substore.split_first_mut() {
            res.push(<T as TryFromReprC<'itm>>::try_from_repr_c(slice[i], first)?);
            substore = rest;
            i += 1;
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
        String::from_utf8(source.into_rust().ok_or(FfiResult::ArgIsNull)?.to_owned())
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
        core::str::from_utf8(source.into_rust().ok_or(FfiResult::ArgIsNull)?)
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
impl<T: IntoFfi, const N: usize> IntoFfi for [T; N] {
    type Target = LocalSlice<T::Target>;

    fn into_ffi(self) -> Self::Target {
        self.into_iter().map(IntoFfi::into_ffi).collect()
    }
}
