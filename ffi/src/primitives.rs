#![allow(trivial_casts, clippy::undocumented_unsafe_blocks)]

use alloc::vec::Vec;

use crate::{
    owned::{IntoFfiVec, TryFromReprCVec},
    slice::{FfiSliceRef, IntoFfiSliceRef, SliceRef, TryFromReprCSliceRef},
    FfiReturn, FfiType, IntoFfi, Local, NonLocal, ReprC, Result, TryFromReprC,
};

#[inline]
const fn is_valid_bool(source: u8) -> bool {
    source == 0 || source == 1
}

// NOTE: &mut bool is not FFI-safe
impl FfiType for bool {
    type ReprC = <u8 as FfiType>::ReprC;
}
impl FfiType for &bool {
    type ReprC = *const u8;
}

impl FfiSliceRef for bool {
    type ReprC = u8;
}

impl<'itm> TryFromReprC<'itm> for bool {
    type Store = ();

    unsafe fn try_from_repr_c(source: Self::ReprC, store: &mut ()) -> Result<Self> {
        let source: u8 = TryFromReprC::try_from_repr_c(source, store)?;

        if !is_valid_bool(source) {
            return Err(FfiReturn::TrapRepresentation);
        }

        Ok(source != 0)
    }
}
impl<'itm> TryFromReprC<'itm> for &'itm bool {
    type Store = ();

    // False positive - doesn't compile otherwise
    #[allow(clippy::let_unit_value)]
    unsafe fn try_from_repr_c(source: Self::ReprC, store: &mut ()) -> Result<Self> {
        let source: &u8 = TryFromReprC::try_from_repr_c(source, store)?;

        if !is_valid_bool(*source) {
            return Err(FfiReturn::TrapRepresentation);
        }

        Ok(&*(source as *const u8).cast::<bool>())
    }
}

impl<'slice> TryFromReprCSliceRef<'slice> for bool {
    type Store = ();

    // False positive - doesn't compile otherwise
    #[allow(clippy::let_unit_value)]
    unsafe fn try_from_repr_c(source: SliceRef<Self::ReprC>, store: &mut ()) -> Result<&[Self]> {
        let source: &[u8] = TryFromReprC::try_from_repr_c(source, store)?;

        if !source.iter().all(|item| is_valid_bool(*item)) {
            return Err(FfiReturn::TrapRepresentation);
        }

        Ok(&*(source as *const _ as *const _))
    }
}

impl IntoFfi for bool {
    type Store = ();

    fn into_ffi(self, store: &mut Self::Store) -> Self::ReprC {
        u8::from(self).into_ffi(store)
    }
}
impl IntoFfi for &bool {
    type Store = ();

    fn into_ffi(self, _: &mut Self::Store) -> Self::ReprC {
        (self as *const bool).cast()
    }
}
impl IntoFfiSliceRef for bool {
    type Store = ();

    fn into_ffi(source: &[Self], _: &mut Self::Store) -> SliceRef<Self::ReprC> {
        // SAFETY: bool has the same representation as u8
        SliceRef::from_slice(unsafe { &*(source as *const [bool] as *const [u8]) })
    }
}

// NOTE: &mut Ordering is not FFI-safe
impl FfiType for core::cmp::Ordering {
    type ReprC = <i8 as FfiType>::ReprC;
}
impl FfiType for &core::cmp::Ordering {
    type ReprC = *const i8;
}
impl FfiSliceRef for core::cmp::Ordering {
    type ReprC = i8;
}

impl<'itm> TryFromReprC<'itm> for core::cmp::Ordering {
    type Store = ();

    unsafe fn try_from_repr_c(source: Self::ReprC, store: &mut ()) -> Result<Self> {
        let source: i8 = TryFromReprC::try_from_repr_c(source, store)?;

        match source {
            -1 => Ok(core::cmp::Ordering::Less),
            0 => Ok(core::cmp::Ordering::Equal),
            1 => Ok(core::cmp::Ordering::Greater),
            _ => Err(FfiReturn::TrapRepresentation),
        }
    }
}
impl<'itm> TryFromReprC<'itm> for &'itm core::cmp::Ordering {
    type Store = ();

    // False positive - doesn't compile otherwise
    #[allow(clippy::let_unit_value)]
    unsafe fn try_from_repr_c(source: Self::ReprC, store: &mut ()) -> Result<Self> {
        let source: &i8 = TryFromReprC::try_from_repr_c(source, store)?;

        if !(*source == -1 || *source == 0 || *source == 1) {
            return Err(FfiReturn::TrapRepresentation);
        }

        Ok(&*(source as *const i8).cast::<core::cmp::Ordering>())
    }
}

impl<'slice> TryFromReprCSliceRef<'slice> for core::cmp::Ordering {
    type Store = ();

    // False positive - doesn't compile otherwise
    #[allow(clippy::let_unit_value)]
    unsafe fn try_from_repr_c(source: SliceRef<Self::ReprC>, store: &mut ()) -> Result<&[Self]> {
        let source: &[i8] = TryFromReprC::try_from_repr_c(source, store)?;

        if !source.iter().all(|e| *e == -1 || *e == 0 || *e == 1) {
            return Err(FfiReturn::TrapRepresentation);
        }

        Ok(&*(source as *const _ as *const _))
    }
}

impl IntoFfi for core::cmp::Ordering {
    type Store = ();

    fn into_ffi(self, store: &mut Self::Store) -> Self::ReprC {
        (self as i8).into_ffi(store)
    }
}
impl IntoFfi for &core::cmp::Ordering {
    type Store = ();

    fn into_ffi(self, _: &mut Self::Store) -> Self::ReprC {
        (self as *const core::cmp::Ordering).cast()
    }
}
impl IntoFfiSliceRef for core::cmp::Ordering {
    type Store = ();

    fn into_ffi(source: &[Self], _: &mut Self::Store) -> SliceRef<Self::ReprC> {
        // SAFETY: `core::cmp::Ordering` has the same representation as i8
        unsafe { SliceRef::from_slice(&*(source as *const [_] as *const [i8])) }
    }
}

#[cfg(feature = "wasm")]
macro_rules! wasm_repr_impls {
    ($src:ty => $dst:ty, $($tail:tt)+) => {
        wasm_repr_impls! { $src => $dst }
        wasm_repr_impls! { $($tail)+ }

        primitive_impls! { @common_impls $src }
    };
    ($src:ty => $dst:ty) => {
        unsafe impl ReprC for SliceRef<$ty> {}
        unsafe impl ReprC for SliceMut<$ty> {}

        impl FfiType for $src {
            type ReprC = $dst;
        }
        impl FfiType for &$src {
            type ReprC = *const $src;
        }
        // NOTE: &mut $ty is FFI-safe
        impl FfiType for &mut $src {
            type ReprC = *mut $src;
        }
        impl crate::owned::FfiVec for $src {
            type ReprC = $src;
        }

        impl FfiSliceRef for $src {
            type ReprC = $src;
        }
        impl crate::slice::FfiSliceMut for $src {
            type ReprC = $src;
        }
    };
}

macro_rules! primitive_impls {
    ( $( $ty:ty ),+ $(,)? ) => {$(
        unsafe impl ReprC for $ty {}
        unsafe impl NonLocal for $ty {}

        impl FfiType for $ty {
            // NOTE: &mut $ty is FFI-safe
            type ReprC = Self;
        })+

        primitive_impls! { @common_impls $( $ty ),+ }
    };
    (@common_impls $( $ty:ty ),+ $(,)? ) => {$(
        impl TryFromReprC<'_> for $ty {
            type Store = ();

            unsafe fn try_from_repr_c(source: Self::ReprC, _: &mut Self::Store) -> Result<Self> {
                source.try_into().map_err(|_| FfiReturn::ConversionFailed)
            }
        }

        impl<'itm> TryFromReprCVec<'itm> for $ty {
            type Store = ();

            unsafe fn try_from_repr_c(
                source: Local<SliceRef<Self::ReprC>>,
                _: &'itm mut Self::Store,
            ) -> Result<Vec<Self>> {
                source.0.into_rust().ok_or(FfiReturn::ArgIsNull).map(alloc::borrow::ToOwned::to_owned)
            }
        }

        impl IntoFfi for $ty {
            type Store = ();

            fn into_ffi(self, _: &mut Self::Store) -> Self::ReprC {
                self.into()
            }
        }

        impl IntoFfiVec for $ty {
            type Store = ();

            fn into_ffi(source: Vec<Self>, _: &mut Self::Store) -> Local<SliceRef<Self::ReprC>> {
                Local(SliceRef::from_slice(&source))
            }
        }
    )+};
}

#[cfg(not(feature = "wasm"))]
primitive_impls! {u8, i8, u16, i16}
primitive_impls! {u32, i32, u64, i64}

#[cfg(feature = "wasm")]
wasm_repr_impls! {u8 => u32, i8 => i32, u16 => u32, i16 => i32}
