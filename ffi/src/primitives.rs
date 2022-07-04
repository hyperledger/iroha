#![allow(trivial_casts)]

use crate::{
    slice::{
        IntoFfiSliceMut, IntoFfiSliceRef, SliceMut, SliceRef, TryFromReprCSliceMut,
        TryFromReprCSliceRef,
    },
    FfiResult, IntoFfi, ReprC, TryFromReprC,
};

impl<'itm> TryFromReprC<'itm> for bool {
    type Source = <u8 as TryFromReprC<'itm>>::Source;
    type Store = ();

    unsafe fn try_from_repr_c(source: Self::Source, _: &mut ()) -> Result<Self, FfiResult> {
        let source: u8 = TryFromReprC::try_from_repr_c(source, &mut ())?;

        match source {
            0 | 1 => Ok(source != 0),
            _ => Err(FfiResult::TrapRepresentation),
        }
    }
}
impl<'itm> TryFromReprC<'itm> for &bool {
    type Source = <&'itm u8 as TryFromReprC<'itm>>::Source;
    type Store = ();

    unsafe fn try_from_repr_c(source: Self::Source, _: &mut ()) -> Result<Self, FfiResult> {
        let source: &u8 = TryFromReprC::try_from_repr_c(source, &mut ())?;

        if !(*source == 0 || *source == 1) {
            return Err(FfiResult::TrapRepresentation);
        }

        Ok(&*(source as *const u8).cast::<bool>())
    }
}

impl<'slice> TryFromReprCSliceRef<'slice> for bool {
    type Source = <u8 as TryFromReprCSliceRef<'slice>>::Source;
    type Store = ();

    // False positive - doesn't compile otherwise
    #[allow(clippy::let_unit_value)]
    unsafe fn try_from_repr_c(source: Self::Source, _: &mut ()) -> Result<&[Self], FfiResult> {
        let mut store = ();
        let source: &[u8] = TryFromReprC::try_from_repr_c(source, &mut store)?;

        if !source.iter().all(|e| *e == 0 || *e == 1) {
            return Err(FfiResult::TrapRepresentation);
        }

        Ok(&*(source as *const _ as *const _))
    }
}

impl IntoFfi for bool {
    type Target = u8;

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

impl IntoFfiSliceRef for bool {
    type Target = SliceRef<u8>;

    fn into_ffi(source: &[Self]) -> Self::Target {
        // SAFETY: bool has the same representation as u8
        unsafe { SliceRef::from_slice(&*(source as *const [bool] as *const [u8])) }
    }
}

impl<'itm> TryFromReprC<'itm> for core::cmp::Ordering {
    type Source = <i8 as TryFromReprC<'itm>>::Source;
    type Store = ();

    unsafe fn try_from_repr_c(source: Self::Source, _: &mut ()) -> Result<Self, FfiResult> {
        let source: i8 = TryFromReprC::try_from_repr_c(source, &mut ())?;

        match source {
            -1 => Ok(core::cmp::Ordering::Less),
            0 => Ok(core::cmp::Ordering::Equal),
            1 => Ok(core::cmp::Ordering::Greater),
            _ => Err(FfiResult::TrapRepresentation),
        }
    }
}
impl<'itm> TryFromReprC<'itm> for &core::cmp::Ordering {
    type Source = <&'itm i8 as TryFromReprC<'itm>>::Source;
    type Store = ();

    unsafe fn try_from_repr_c(source: Self::Source, _: &mut ()) -> Result<Self, FfiResult> {
        let source: &i8 = TryFromReprC::try_from_repr_c(source, &mut ())?;

        if !(*source == -1 || *source == 0 || *source == 1) {
            return Err(FfiResult::TrapRepresentation);
        }

        Ok(&*(source as *const i8).cast::<core::cmp::Ordering>())
    }
}

impl<'slice> TryFromReprCSliceRef<'slice> for core::cmp::Ordering {
    type Source = <i8 as TryFromReprCSliceRef<'slice>>::Source;
    type Store = ();

    // False positive - doesn't compile otherwise
    #[allow(clippy::let_unit_value)]
    unsafe fn try_from_repr_c(source: Self::Source, _: &mut ()) -> Result<&[Self], FfiResult> {
        let mut store = ();
        let source: &[i8] = TryFromReprC::try_from_repr_c(source, &mut store)?;

        if !source.iter().all(|e| *e == -1 || *e == 0 || *e == 1) {
            return Err(FfiResult::TrapRepresentation);
        }

        Ok(&*(source as *const _ as *const _))
    }
}

impl IntoFfi for core::cmp::Ordering {
    type Target = i8;

    fn into_ffi(self) -> Self::Target {
        self as i8
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

impl IntoFfiSliceRef for core::cmp::Ordering {
    type Target = SliceRef<i8>;

    fn into_ffi(source: &[Self]) -> Self::Target {
        // SAFETY: `core::cmp::Ordering` has the same representation as i8
        unsafe { SliceRef::from_slice(&*(source as *const [_] as *const [i8])) }
    }
}

macro_rules! primitive_impls {
    ( $( $ty:ty ),+ $(,)? ) => { $(
        unsafe impl ReprC for $ty {}

        impl TryFromReprC<'_> for $ty {
            type Source = Self;
            type Store = ();

            unsafe fn try_from_repr_c(source: Self::Source, _: &mut Self::Store) -> Result<Self, FfiResult> {
                Ok(source)
            }
        }

        impl TryFromReprCSliceRef<'_> for $ty {
            type Source = SliceRef<$ty>;
            type Store = ();

            unsafe fn try_from_repr_c(source: Self::Source, _: &mut Self::Store) -> Result<&[Self], FfiResult> {
                source.into_slice().ok_or(FfiResult::ArgIsNull)
            }
        }

        impl TryFromReprCSliceMut for $ty {
            type Source = SliceMut<$ty>;
            type Store = ();

            unsafe fn try_from_repr_c(source: Self::Source, _: &mut Self::Store) -> Result<&mut [Self], FfiResult> {
                source.into_slice().ok_or(FfiResult::ArgIsNull)
            }
        }

        impl IntoFfi for $ty {
            type Target = Self;

            fn into_ffi(self) -> Self::Target {
                self
            }
        }

        impl IntoFfiSliceRef for $ty {
            type Target = SliceRef<$ty>;

            fn into_ffi(source: &[Self]) -> Self::Target {
                SliceRef::from_slice(source)
            }
        }
        unsafe impl IntoFfiSliceMut for $ty {
            type Target = SliceMut<$ty>;

            fn into_ffi(source: &mut [Self]) -> Self::Target {
                SliceMut::from_slice(source)
            }
        } )+
    };
}

primitive_impls! {u8, u16, u32, u64, u128, i8, i16, i32, i64, f32, f64}
