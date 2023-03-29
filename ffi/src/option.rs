//! Logic related to the conversion of [`Option<T>`] to and from FFI-compatible representation

use core::mem::MaybeUninit;

use crate::{
    ir::Ir,
    repr_c::{
        COutPtr, COutPtrRead, COutPtrWrite, CType, CTypeConvert, CWrapperType, Cloned, NonLocal,
    },
    FfiConvert, FfiOutPtr, FfiOutPtrRead, FfiOutPtrWrite, FfiReturn, FfiTuple2, FfiType,
    FfiWrapperType, ReprC, Result,
};

/// Marker for [`Option<T>`] that doesn't have niche representation
#[derive(Debug, Clone, Copy)]
pub enum WithoutNiche {}

/// Used to implement specialized impls of [`Ir`] for [`Option<T>`]
pub trait OptionIr {
    /// Internal representation of [`Option<T>`]
    type Type;
}

impl<'dummy, R: Niche<'dummy>> OptionIr for R {
    type Type = Option<Self>;
}

// TODO: Are they all cloned?
impl<R> Cloned for Option<R> {}

/// Type that has at least one trap representation that can be used as a niche value. The
/// niche value is used in the serialization of [`Option<T>`]. For example, [`Option<bool>`]
/// will be serilized into one byte and [`Option<*const T>`] will take the size of the pointer
// TODO: Lifetime is used as a hack to deal with https://github.com/rust-lang/rust/issues/48214
pub trait Niche<'dummy>: FfiType {
    /// The niche value of the type
    const NICHE_VALUE: Self::ReprC;
}

impl<R, C> Niche<'_> for &R
where
    Self: FfiType<ReprC = *const C>,
{
    const NICHE_VALUE: Self::ReprC = core::ptr::null();
}

impl<R, C> Niche<'_> for &mut R
where
    Self: FfiType<ReprC = *mut C>,
{
    const NICHE_VALUE: Self::ReprC = core::ptr::null_mut();
}

impl<R: OptionIr> Ir for Option<R> {
    type Type = R::Type;
}

impl<'dummy, R: Niche<'dummy>> CType<Self> for Option<R> {
    type ReprC = R::ReprC;
}
impl<'dummy, 'itm, R: Niche<'dummy, ReprC = C> + FfiConvert<'itm, C>, C: ReprC>
    CTypeConvert<'itm, Self, C> for Option<R>
where
    R::ReprC: PartialEq,
{
    type RustStore = R::RustStore;
    type FfiStore = R::FfiStore;

    fn into_repr_c(self, store: &'itm mut Self::RustStore) -> C {
        if let Some(value) = self {
            return value.into_ffi(store);
        }

        R::NICHE_VALUE
    }

    unsafe fn try_from_repr_c(source: C, store: &'itm mut Self::FfiStore) -> Result<Self> {
        if source == R::NICHE_VALUE {
            return Ok(None);
        }

        Ok(Some(R::try_from_ffi(source, store)?))
    }
}

impl<R: FfiWrapperType> CWrapperType<Self> for Option<R> {
    type InputType = Option<R::InputType>;
    type ReturnType = Option<R::ReturnType>;
}
impl<'dummy, R: Niche<'dummy> + FfiOutPtr> COutPtr<Self> for Option<R> {
    type OutPtr = R::OutPtr;
}
impl<'dummy, R: Niche<'dummy> + FfiOutPtrWrite<OutPtr = <R as FfiType>::ReprC>> COutPtrWrite<Self>
    for Option<R>
{
    unsafe fn write_out(self, out_ptr: *mut Self::OutPtr) {
        self.map_or_else(
            || out_ptr.write(R::NICHE_VALUE),
            |value| R::write_out(value, out_ptr),
        );
    }
}
impl<'dummy, R: Niche<'dummy> + FfiOutPtrRead<OutPtr = <R as FfiType>::ReprC>> COutPtrRead<Self>
    for Option<R>
where
    R::ReprC: PartialEq,
{
    unsafe fn try_read_out(out_ptr: Self::OutPtr) -> Result<Self> {
        if out_ptr == R::NICHE_VALUE {
            return Ok(None);
        }

        R::try_read_out(out_ptr).map(Some)
    }
}

impl<R: FfiType> CType<Option<WithoutNiche>> for Option<R> {
    type ReprC = FfiTuple2<<u8 as FfiType>::ReprC, R::ReprC>;
}

impl<'itm, R: FfiConvert<'itm, C>, C: ReprC>
    CTypeConvert<'itm, Option<WithoutNiche>, FfiTuple2<<u8 as FfiType>::ReprC, C>> for Option<R>
{
    type RustStore = R::RustStore;
    type FfiStore = R::FfiStore;

    fn into_repr_c(self, store: &'itm mut Self::RustStore) -> FfiTuple2<<u8 as FfiType>::ReprC, C> {
        // NOTE: Makes the code much more readable
        #[allow(clippy::option_if_let_else)]
        match self {
            // TODO: No need to zero the memory because it must never be read
            None => FfiTuple2(0u8.into_ffi(&mut ()), unsafe { core::mem::zeroed() }),
            Some(value) => FfiTuple2(1u8.into_ffi(&mut ()), value.into_ffi(store)),
        }
    }

    unsafe fn try_from_repr_c(
        source: FfiTuple2<<u8 as FfiType>::ReprC, C>,
        store: &'itm mut Self::FfiStore,
    ) -> Result<Self> {
        match u8::try_from_ffi(source.0, &mut ())? {
            0 => Ok(None),
            1 => Ok(Some(R::try_from_ffi(source.1, store)?)),
            _ => Err(FfiReturn::TrapRepresentation),
        }
    }
}

impl<R: FfiWrapperType> CWrapperType<Option<WithoutNiche>> for Option<R> {
    type InputType = Option<R::InputType>;
    type ReturnType = Option<R::ReturnType>;
}

impl<R: FfiOutPtr> COutPtr<Option<WithoutNiche>> for Option<R> {
    type OutPtr = FfiTuple2<<u8 as FfiOutPtr>::OutPtr, R::OutPtr>;
}

impl<R: FfiOutPtrWrite> COutPtrWrite<Option<WithoutNiche>> for Option<R> {
    unsafe fn write_out(self, out_ptr: *mut Self::OutPtr) {
        // NOTE: Makes the code much more readable
        #[allow(clippy::option_if_let_else)]
        match self {
            None => {
                let mut discriminant_out_ptr = MaybeUninit::uninit();
                FfiOutPtrWrite::write_out(0u8, discriminant_out_ptr.as_mut_ptr());
                let discriminant_out_ptr = unsafe { discriminant_out_ptr.assume_init() };

                // TODO: No need to zero the memory because it must never be read
                out_ptr.write(FfiTuple2(discriminant_out_ptr, unsafe {
                    core::mem::zeroed()
                }))
            }
            Some(value) => {
                let mut discriminant_out_ptr = MaybeUninit::uninit();
                FfiOutPtrWrite::write_out(1u8, discriminant_out_ptr.as_mut_ptr());
                let discriminant_out_ptr = unsafe { discriminant_out_ptr.assume_init() };

                let mut value_out_ptr = MaybeUninit::uninit();
                FfiOutPtrWrite::write_out(value, value_out_ptr.as_mut_ptr());
                let value_out_ptr = unsafe { value_out_ptr.assume_init() };

                out_ptr.write(FfiTuple2(discriminant_out_ptr, value_out_ptr));
            }
        }
    }
}

impl<R: FfiOutPtrRead> COutPtrRead<Option<WithoutNiche>> for Option<R> {
    unsafe fn try_read_out(out_ptr: Self::OutPtr) -> Result<Self> {
        match <u8 as FfiOutPtrRead>::try_read_out(out_ptr.0)? {
            0 => Ok(None),
            1 => Ok(Some(R::try_read_out(out_ptr.1)?)),
            _ => Err(FfiReturn::TrapRepresentation),
        }
    }
}

// SAFETY: Option<Tdoesn't use store if it's inner types don't use it
unsafe impl<'dummy, R: Niche<'dummy> + Ir + NonLocal<R::Type>> NonLocal<Self> for Option<R> {}
// SAFETY: Option<Tdoesn't use store if it's inner types don't use it
unsafe impl<R: Ir + NonLocal<R::Type>> NonLocal<Option<WithoutNiche>> for Option<R> {}
