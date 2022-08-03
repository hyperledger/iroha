//! Logic related to the conversion of primitive types.
#![allow(trivial_casts)]

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

/// Trait for replacing unsupported types with supported ones when crossing FFI-boundary (for example in case of wasm)
pub trait PrimitiveRepr {
    /// Type used to represent [`Self`] when crossing FFI-boundry
    type Repr;
}

macro_rules! primitive_repr_impls {
    ($($source:ty => $target:ty),+ $(,)?) => {$(
        impl PrimitiveRepr for $source {
            type Repr = $target;
        }
    )+};
}
macro_rules! primitive_repr_self_impls {
    ($($source:ty),+ $(,)?) => {
        primitive_repr_impls! {
            $($source => $source),*
        }
    };
}

#[cfg(feature = "wasm")]
primitive_repr_impls! {u8 => u32, u16 => u32, i8 => i32, i16 => i32}
#[cfg(not(feature = "wasm"))]
primitive_repr_self_impls! {u8, u16, i8, i16}
primitive_repr_self_impls! {u32, u64, u128, i32, i64, i128}

macro_rules! primitive_impls {
    ( $( $ty:ty ),+ $(,)? ) => { $(
        unsafe impl ReprC for $ty {}

        impl TryFromReprC<'_> for $ty {
            type Source = <$ty as PrimitiveRepr>::Repr;
            type Store = ();

            unsafe fn try_from_repr_c(source: Self::Source, _: &mut Self::Store) -> Result<Self> {
                source.try_into().map_err(|_| FfiReturn::TrapRepresentation)
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
            type Target = <$ty as PrimitiveRepr>::Repr;

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

primitive_impls! {u8, u16, u32, u64, u128, i8, i16, i32, i64}
