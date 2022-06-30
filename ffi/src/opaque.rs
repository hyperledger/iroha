use crate::{AsFfi, FfiRef, FfiResult, FfiType, TryAsRust, TryFromFfi};

/// Indicates that type is converted into an opaque pointer when crossing the FFI boundary
// TODO: Make it unsafe?
pub trait Opaque: FfiType {}

impl<T: Opaque> FfiType for &T {
    type FfiType = *const Self;
}

impl<T: Opaque> FfiType for &mut T {
    type FfiType = *mut Self;
}

impl<T: Opaque> FfiRef for T {
    type FfiRef = *const Self;
    type FfiMut = *mut Self;
}

impl<T: Opaque> TryFromFfi for T
where
    T: FfiType<FfiType = *mut Self>,
{
    type Item = Self;

    unsafe fn try_from_ffi(source: Self::FfiType) -> Result<Self, FfiResult> {
        if source.is_null() {
            return Err(FfiResult::ArgIsNull);
        }

        Ok(*Box::from_raw(source))
    }
}

impl<T: Opaque> AsFfi for T {
    type ItemRef = Self::FfiRef;
    type ItemMut = Self::FfiMut;

    fn as_ffi_ref(&self) -> Self::ItemRef {
        <*const T>::from(self)
    }
    fn as_ffi_mut(&mut self) -> Self::ItemMut {
        <*mut T>::from(self)
    }
}

impl<'itm, T: Opaque> TryAsRust<'itm> for T
where
    T: 'itm,
{
    type ItemRef = &'itm Self;
    type ItemMut = &'itm mut Self;

    unsafe fn try_as_rust_ref(source: Self::FfiRef) -> Result<Self::ItemRef, FfiResult> {
        source.as_ref().ok_or(FfiResult::ArgIsNull)
    }

    unsafe fn try_as_rust_mut(source: Self::FfiMut) -> Result<Self::ItemMut, FfiResult> {
        source.as_mut().ok_or(FfiResult::ArgIsNull)
    }
}

//impl<T: Opaque> AsFfiSlice for T {
//    type FfiType = *const T;
//
//    /// Performs the conversion from [`&[Self]`] into [`SliceRef`] with a defined C ABI
//    fn into_ffi_slice<'store>(
//        source: &'store [Self],
//    ) -> SliceRef<Self::FfiType> {
//        let start = store.len();
//        store.extend(source.into_iter().map(|item| item as *const _));
//        SliceRef::from_slice(&store[start + 1..])
//    }
//
//    /// Performs the conversion from [`&mut [Self]`] into [`SliceMut`] with a defined C ABI
//    fn into_ffi_slice_mut(
//        source: &mut [Self],
//    ) -> SliceMut<Self::FfiType> {
//        let start = store.len();
//        store.extend(source.into_iter().map(|item| item as *const _));
//        SliceMut::from_slice(&mut store[start + 1..])
//    }
//}
