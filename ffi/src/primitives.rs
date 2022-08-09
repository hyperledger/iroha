#![allow(trivial_casts, clippy::undocumented_unsafe_blocks)]

use alloc::vec::Vec;

use crate::{
    owned::{IntoFfiVec, LocalSlice, TryFromReprCVec},
    slice::{
        IntoFfiSliceMut, IntoFfiSliceRef, SliceMut, SliceRef, TryFromReprCSliceMut,
        TryFromReprCSliceRef,
    },
    FfiReturn, IntoFfi, ReprC, Result, TryFromReprC,
};

#[inline]
const fn is_valid_bool(source: u8) -> bool {
    source == 0 || source == 1
}

impl<'itm> TryFromReprC<'itm> for bool {
    type Source = <u8 as TryFromReprC<'itm>>::Source;
    type Store = ();

    unsafe fn try_from_repr_c(source: Self::Source, _: &mut ()) -> Result<Self> {
        let source: u8 = TryFromReprC::try_from_repr_c(source, &mut ())?;

        if !is_valid_bool(source) {
            return Err(FfiReturn::TrapRepresentation);
        }

        Ok(source != 0)
    }
}
impl<'itm> TryFromReprC<'itm> for &'itm bool {
    type Source = <&'itm u8 as TryFromReprC<'itm>>::Source;
    type Store = ();

    // False positive - doesn't compile otherwise
    #[allow(clippy::let_unit_value)]
    unsafe fn try_from_repr_c(source: Self::Source, _: &mut ()) -> Result<Self> {
        let mut store = ();
        let source: &u8 = TryFromReprC::try_from_repr_c(source, &mut store)?;

        if !is_valid_bool(*source) {
            return Err(FfiReturn::TrapRepresentation);
        }

        Ok(&*(source as *const u8).cast::<bool>())
    }
}

impl<'slice> TryFromReprCSliceRef<'slice> for bool {
    type Source = <u8 as TryFromReprCSliceRef<'slice>>::Source;
    type Store = ();

    // False positive - doesn't compile otherwise
    #[allow(clippy::let_unit_value)]
    unsafe fn try_from_repr_c(source: Self::Source, _: &mut ()) -> Result<&[Self]> {
        let mut store = ();
        let source: &[u8] = TryFromReprC::try_from_repr_c(source, &mut store)?;

        if !source.iter().all(|item| is_valid_bool(*item)) {
            return Err(FfiReturn::TrapRepresentation);
        }

        Ok(&*(source as *const _ as *const _))
    }
}

impl IntoFfi for bool {
    type Target = <u8 as IntoFfi>::Target;

    fn into_ffi(self) -> Self::Target {
        u8::from(self).into_ffi()
    }
}
impl IntoFfi for &bool {
    type Target = *const u8;

    fn into_ffi(self) -> Self::Target {
        (self as *const bool).cast()
    }
}

impl<'itm> IntoFfiSliceRef<'itm> for bool {
    type Target = SliceRef<'itm, u8>;

    fn into_ffi(source: &[Self]) -> Self::Target {
        // SAFETY: bool has the same representation as u8
        SliceRef::from_slice(unsafe { &*(source as *const [bool] as *const [u8]) })
    }
}

impl<'itm> TryFromReprC<'itm> for core::cmp::Ordering {
    type Source = <i8 as TryFromReprC<'itm>>::Source;
    type Store = ();

    unsafe fn try_from_repr_c(source: Self::Source, _: &mut ()) -> Result<Self> {
        let source: i8 = TryFromReprC::try_from_repr_c(source, &mut ())?;

        match source {
            -1 => Ok(core::cmp::Ordering::Less),
            0 => Ok(core::cmp::Ordering::Equal),
            1 => Ok(core::cmp::Ordering::Greater),
            _ => Err(FfiReturn::TrapRepresentation),
        }
    }
}
impl<'itm> TryFromReprC<'itm> for &'itm core::cmp::Ordering {
    type Source = <&'itm i8 as TryFromReprC<'itm>>::Source;
    type Store = ();

    // False positive - doesn't compile otherwise
    #[allow(clippy::let_unit_value)]
    unsafe fn try_from_repr_c(source: Self::Source, _: &mut ()) -> Result<Self> {
        let mut store = ();
        let source: &i8 = TryFromReprC::try_from_repr_c(source, &mut store)?;

        if !(*source == -1 || *source == 0 || *source == 1) {
            return Err(FfiReturn::TrapRepresentation);
        }

        Ok(&*(source as *const i8).cast::<core::cmp::Ordering>())
    }
}

impl<'slice> TryFromReprCSliceRef<'slice> for core::cmp::Ordering {
    type Source = <i8 as TryFromReprCSliceRef<'slice>>::Source;
    type Store = ();

    // False positive - doesn't compile otherwise
    #[allow(clippy::let_unit_value)]
    unsafe fn try_from_repr_c(source: Self::Source, _: &mut ()) -> Result<&[Self]> {
        let mut store = ();
        let source: &[i8] = TryFromReprC::try_from_repr_c(source, &mut store)?;

        if !source.iter().all(|e| *e == -1 || *e == 0 || *e == 1) {
            return Err(FfiReturn::TrapRepresentation);
        }

        Ok(&*(source as *const _ as *const _))
    }
}

impl IntoFfi for core::cmp::Ordering {
    type Target = <i8 as IntoFfi>::Target;

    fn into_ffi(self) -> Self::Target {
        (self as i8).into_ffi()
    }
}
impl IntoFfi for &core::cmp::Ordering {
    type Target = *const i8;

    fn into_ffi(self) -> Self::Target {
        (self as *const core::cmp::Ordering).cast()
    }
}
impl IntoFfi for &mut core::cmp::Ordering {
    type Target = *mut i8;

    fn into_ffi(self) -> Self::Target {
        (self as *mut core::cmp::Ordering).cast()
    }
}

impl<'itm> IntoFfiSliceRef<'itm> for core::cmp::Ordering {
    type Target = SliceRef<'itm, i8>;

    fn into_ffi(source: &[Self]) -> Self::Target {
        // SAFETY: `core::cmp::Ordering` has the same representation as i8
        unsafe { SliceRef::from_slice(&*(source as *const [_] as *const [i8])) }
    }
}

/// Trait for replacing unsupported types with supported when crossing WASM FFI-boundary
#[cfg(feature = "wasm")]
pub trait WasmRepr {
    /// Type used to represent [`Self`] when crossing FFI-boundry
    type Repr: ReprC;
}

#[cfg(feature = "wasm")]
macro_rules! wasm_repr_impls {
    ($src:ty = $dst:ty, $($tail:tt)+) => {
        wasm_repr_impls! { $src = $dst }
        wasm_repr_impls! { $($tail)+ }
    };
    ($src:ty, $($tail:tt)+) => {
        wasm_repr_impls! { $src }
        wasm_repr_impls! { $($tail)+ }
    };
    ($src:ty = $dst:ty) => {
        impl WasmRepr for $src {
            type Repr = $dst;
        }
    };
    ($src:ty) => {
        impl WasmRepr for $src {
            type Repr = Self;
        }
    };
}

#[cfg(feature = "wasm")]
wasm_repr_impls! {u8 = u32, u16 = u32, i8 = i32, i16 = i32, u32, u64, i32, i64}

macro_rules! primitive_impls {
    ( $( $ty:ty ),+ $(,)? ) => { $(
        unsafe impl ReprC for $ty {}

        impl TryFromReprC<'_> for $ty {
            #[cfg(feature = "wasm")]
            type Source = <$ty as WasmRepr>::Repr;
            #[cfg(not(feature = "wasm"))]
            type Source = Self;
            type Store = ();

            unsafe fn try_from_repr_c(source: Self::Source, _: &mut Self::Store) -> Result<Self> {
                source.try_into().map_err(|_| FfiReturn::ConversionFailed)
            }
        }

        impl<'itm> TryFromReprCSliceRef<'itm> for $ty {
            type Source = SliceRef<'itm, $ty>;
            type Store = ();

            unsafe fn try_from_repr_c(source: Self::Source, _: &'itm mut Self::Store) -> Result<&[Self]> {
                source.into_rust().ok_or(FfiReturn::ArgIsNull)
            }
        }

        impl<'slice> TryFromReprCSliceMut<'slice> for $ty {
            type Source = SliceMut<'slice, $ty>;
            type Store = ();

            unsafe fn try_from_repr_c(source: Self::Source, _: &mut Self::Store) -> Result<&'slice mut [Self]> {
                source.into_rust().ok_or(FfiReturn::ArgIsNull)
            }
        }

        impl IntoFfi for $ty {
            #[cfg(feature = "wasm")]
            type Target = <$ty as WasmRepr>::Repr;
            #[cfg(not(feature = "wasm"))]
            type Target = Self;

            fn into_ffi(self) -> Self::Target {
                self.into()
            }
        }

        impl<'itm> IntoFfiSliceRef<'itm> for $ty {
            type Target = SliceRef<'itm, $ty>;

            fn into_ffi(source: &[Self]) -> Self::Target {
                SliceRef::from_slice(source)
            }
        }
        unsafe impl<'slice> IntoFfiSliceMut<'slice> for $ty {
            type Target = SliceMut<'slice, $ty>;

            fn into_ffi(source: &mut [Self]) -> Self::Target {
                SliceMut::from_slice(source)
            }
        }

        impl IntoFfiVec for $ty
        {
            type Target = LocalSlice<$ty>;

            fn into_ffi(source: Vec<$ty>) -> Self::Target {
                source.into_iter().collect()
            }
        }

        impl<'itm> TryFromReprCVec<'itm> for $ty {
            type Source = SliceRef<'itm, $ty>;
            type Store = ();

            unsafe fn try_from_repr_c(
                source: Self::Source,
                _: &'itm mut Self::Store,
            ) -> Result<Vec<Self>> {
                source.into_rust().ok_or(FfiReturn::ArgIsNull).map(alloc::borrow::ToOwned::to_owned)
            }
        }
    )+};
}

primitive_impls! {u8, u16, u32, u64, i8, i16, i32, i64}
