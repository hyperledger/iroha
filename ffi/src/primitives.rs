use crate::{
    slice::{AsFfiSlice, SliceMut, SliceRef},
    AsFfi, FfiRef, FfiResult, FfiType, FfiWriteOut, FromOption, IntoFfi, OptionWrapped, ReprC,
    TryAsRust, TryFromFfi,
};

impl FfiType for bool {
    type FfiType = u8;
}

impl FfiRef for bool {
    type FfiRef = *const u8;
    type FfiMut = *mut u8;
}

impl IntoFfi for bool {
    type Item = Self::FfiType;

    fn into_ffi(self) -> Self::Item {
        Self::FfiType::from(self).into_ffi()
    }
}

impl TryFromFfi for bool {
    type Item = Self;

    unsafe fn try_from_ffi(source: Self::FfiType) -> Result<Self::Item, FfiResult> {
        match source {
            0 | 1 => Ok(source != 0),
            // TODO: return invalid value
            _ => Err(FfiResult::UnknownHandle),
        }
    }
}

impl AsFfi for bool {
    type ItemRef = Self::FfiRef;
    type ItemMut = Self::FfiMut;

    fn as_ffi_ref(&self) -> Self::ItemRef {
        // SAFETEY: bool has the same representation as u8
        unsafe { &*(self as *const Self as *const u8) }
    }

    fn as_ffi_mut(&mut self) -> Self::ItemMut {
        // SAFETEY: bool has the same representation as u8
        unsafe { &mut *(self as *mut Self as *mut u8) }
    }
}

impl<'itm> TryAsRust<'itm> for bool {
    type ItemRef = &'itm bool;
    type ItemMut = &'itm mut bool;

    unsafe fn try_as_rust_ref(source: Self::FfiRef) -> Result<Self::ItemRef, FfiResult> {
        match *source {
            0 | 1 => Ok(&*(source as *const bool)),
            // TODO: return invalid value
            _ => Err(FfiResult::UnknownHandle),
        }
    }

    unsafe fn try_as_rust_mut(source: Self::FfiMut) -> Result<Self::ItemMut, FfiResult> {
        match *source {
            0 | 1 => Ok(&mut *(source as *mut bool)),
            // TODO: return invalid value
            _ => Err(FfiResult::UnknownHandle),
        }
    }
}

//impl AsFfiSlice for bool {
//    type FfiType = u8;
//
//    fn into_ffi_slice(source: &[Self]) -> SliceRef<Self::FfiType> {
//        // SAFETEY: bool has the same representation as u8
//        unsafe { SliceRef::from_slice(core::mem::transmute::<&[bool], &[u8]>(source)) }
//    }
//
//    fn into_ffi_slice_mut(source: &mut [Self]) -> SliceMut<Self::FfiType> {
//        // SAFETEY: bool has the same representation as u8
//        unsafe { SliceMut::from_slice(core::mem::transmute::<&mut [bool], &mut [u8]>(source)) }
//    }
//}

impl OptionWrapped for bool {
    type FfiType = <Self as FfiType>::FfiType;
}

impl FromOption for bool {
    // NOTE: Relying on trap representation to represent None values
    fn into_ffi(source: Option<Self>) -> <Self as OptionWrapped>::FfiType {
        source.map_or(u8::MAX, IntoFfi::into_ffi)
    }
}

impl FfiType for core::cmp::Ordering {
    type FfiType = i8;
}

impl IntoFfi for core::cmp::Ordering {
    type Item = Self::FfiType;

    fn into_ffi(self) -> Self::Item {
        self as <Self as FfiType>::FfiType
    }
}

impl TryFromFfi for core::cmp::Ordering {
    type Item = Self;

    unsafe fn try_from_ffi(source: <Self as FfiType>::FfiType) -> Result<Self::Item, FfiResult> {
        match source {
            -1 => Ok(core::cmp::Ordering::Less),
            0 => Ok(core::cmp::Ordering::Equal),
            1 => Ok(core::cmp::Ordering::Greater),
            // TODO: More appropriate error?
            _ => Err(FfiResult::UnknownHandle),
        }
    }
}

macro_rules! primitive_impls {
    ( $( $ty:ty ),+ $(,)? ) => { $(
        unsafe impl ReprC for $ty {}

        impl FfiWriteOut for $ty {
            type OutPtr = *mut Self;

            unsafe fn write(self, dest: Self::OutPtr) {
                dest.write(self)
            }
        }

        impl FfiType for $ty {
            type FfiType = Self;
        }

        impl FfiRef for $ty {
            type FfiRef = *const Self;
            type FfiMut = *mut Self;
        }

        impl IntoFfi for $ty {
            type Item = Self::FfiType;

            fn into_ffi(self) -> Self::Item {
                self
            }
        }

        impl TryFromFfi for $ty {
            type Item = Self;

            unsafe fn try_from_ffi(source: Self::FfiType) -> Result<Self::Item, FfiResult> {
                Ok(source)
            }
        }

        impl AsFfi for $ty {
            type ItemRef = Self::FfiRef;
            type ItemMut = Self::FfiMut;

            fn as_ffi_ref(&self) -> Self::ItemRef {
                <*const $ty>::from(self)
            }

            fn as_ffi_mut(&mut self) -> Self::ItemMut {
                <*mut $ty>::from(self)
            }
        }

        impl<'itm> TryAsRust<'itm> for $ty {
            type ItemRef = &'itm Self;
            type ItemMut = &'itm mut Self;

            unsafe fn try_as_rust_ref(source: Self::FfiRef) -> Result<Self::ItemRef, FfiResult> {
                source.as_ref().ok_or(FfiResult::ArgIsNull)
            }

            unsafe fn try_as_rust_mut(source: Self::FfiMut) -> Result<Self::ItemMut, FfiResult> {
                source.as_mut().ok_or(FfiResult::ArgIsNull)
            }
        }

        impl AsFfiSlice for $ty {
            type ItemRef = SliceRef<$ty>;
            type ItemMut = SliceMut<$ty>;

            fn into_ffi_slice(source: &[Self]) -> Self::ItemRef {
                SliceRef::from_slice(source)
            }

            fn into_ffi_slice_mut(source: &mut [Self]) -> Self::ItemMut {
                SliceMut::from_slice(source)
            }
        }

        impl OptionWrapped for $ty {
            type FfiType = *mut <Self as FfiType>::FfiType;
        }

        //impl<'store> FromOption<'store> for $ty {
        //    type Store = Self;

        //    fn into_ffi(source: Option<Self>, store: &mut <Self as FromOption<'store>>::Store) -> <Self as OptionWrapped>::FfiType {
        //        source.map_or_else(core::ptr::null_mut, |item| {
        //            *store = item;
        //            IntoFfi::into_ffi(store)
        //        })
        //    }
        //}
        )+
    };
}

primitive_impls! {u8, u16, u32, u64, u128, i8, i16, i32, i64, f32, f64}
