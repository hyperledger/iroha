//! Logic related to the conversion of structures with ownership. Ownership is never transferred
//! across FFI. This means that contents of these structures are copied into provided containers
#![allow(clippy::undocumented_unsafe_blocks, clippy::arithmetic)]

use alloc::{borrow::ToOwned, string::String, vec::Vec};
use core::mem::MaybeUninit;

use crate::{slice::SliceRef, FfiReturn, FfiType, IntoFfi, Local, ReprC, Result, TryFromReprC};

/// Indicates that the [`Vec<T>`] can be converted into an FFI compatible representation
pub trait FfiVec: Sized
where
    Local<SliceRef<Self::ReprC>>: ReprC,
{
    /// Corresponding FFI-compatible type
    // TODO: any bounds needed?
    type ReprC;
}

/// Trait that facilitates the implementation of [`IntoFfi`] for vectors of foreign types
pub trait IntoFfiVec: FfiVec
where
    Local<SliceRef<Self::ReprC>>: ReprC,
{
    /// Immutable vec equivalent of [`IntoFfi::Store`]
    type Store: Default;

    /// Convert from `&[Self]` into [`Self::ReprC`]
    fn into_ffi(source: Vec<Self>, store: &mut Self::Store) -> Local<SliceRef<Self::ReprC>>;
}

/// Trait that facilitates the implementation of [`TryFromReprC`] for vector of foreign types
pub trait TryFromReprCVec<'slice>: FfiVec
where
    Local<SliceRef<Self::ReprC>>: ReprC,
{
    /// Type into which state can be stored during conversion. Useful for returning
    /// non-owning types but performing some conversion which requires allocation.
    /// Serves similar purpose as does context in a closure
    type Store: Default;

    /// Convert from [`Self::Source`] into `&[Self]`
    ///
    /// # Errors
    ///
    /// * [`FfiReturn::ArgIsNull`]          - given pointer is null
    /// * [`FfiReturn::UnknownHandle`]      - given id doesn't identify any known handle
    /// * [`FfiReturn::TrapRepresentation`] - given value contains trap representation
    ///
    /// # Safety
    ///
    /// All conversions from a pointer must ensure pointer validity beforehand
    unsafe fn try_from_repr_c(
        source: Local<SliceRef<Self::ReprC>>,
        store: &'slice mut Self::Store,
    ) -> Result<Vec<Self>>;
}

impl<T: FfiVec> FfiType for Vec<T>
where
    Local<SliceRef<T::ReprC>>: ReprC,
{
    type ReprC = Local<SliceRef<T::ReprC>>;
}

impl<T: FfiType<ReprC = Self>> FfiVec for T
where
    Local<SliceRef<T>>: ReprC,
{
    type ReprC = T;
}

impl<'slice, T: TryFromReprCVec<'slice> + 'slice> TryFromReprC<'slice> for Vec<T>
where
    Local<SliceRef<<T as FfiVec>::ReprC>>: ReprC,
{
    type Store = T::Store;

    unsafe fn try_from_repr_c(source: Self::ReprC, store: &'slice mut Self::Store) -> Result<Self> {
        <T as TryFromReprCVec>::try_from_repr_c(source, store)
    }
}

impl<T: IntoFfiVec> IntoFfi for Vec<T>
where
    Local<SliceRef<<T as FfiVec>::ReprC>>: ReprC,
{
    type Store = T::Store;

    fn into_ffi(self, store: &mut Self::Store) -> Self::ReprC {
        IntoFfiVec::into_ffi(self, store)
    }
}

// TODO: Be sure to match the bounds correctly
//impl<'itm, T> IntoFfiVec for &'itm T
//where
//    Self: FfiVec<ReprC = <Self as FfiType>::ReprC>,
//{
//    type Store = (Vec<<Self as FfiVec>::ReprC>, Vec<<Self as IntoFfi>::Store>);
//
//    fn into_ffi(source: Vec<Self>, store: &mut Self::Store) -> Local<SliceRef<Self::ReprC>> {
//        store.0 = source
//            .into_iter()
//            .enumerate()
//            .map(|(i, item)| IntoFfi::into_ffi(item, &mut store.1[i]))
//            .collect();
//
//        Local(SliceRef::from_slice(&store.0))
//    }
//}
//
//impl<T: IntoFfiVec> IntoFfiVec for Vec<T>
//where
//    Self: FfiVec<ReprC = SliceRef<T::ReprC>>,
//{
//    type Store = (Vec<<Self as FfiVec>::ReprC>, Vec<<T as IntoFfiVec>::Store>);
//
//    fn into_ffi(source: Vec<Self>, store: &mut Self::Store) -> Local<SliceRef<Self::ReprC>> {
//        store.0 = source
//            .into_iter()
//            .enumerate()
//            .map(|(i, item)| IntoFfiVec::into_ffi(item, &mut store.1[i]).0)
//            .collect();
//
//        Local(SliceRef::from_slice(&store.0))
//    }
//}

impl FfiType for String {
    type ReprC = <Vec<u8> as FfiType>::ReprC;
}

impl<'itm> TryFromReprC<'itm> for String {
    type Store = ();

    unsafe fn try_from_repr_c(source: Self::ReprC, _: &mut Self::Store) -> Result<Self> {
        String::from_utf8(source.0.into_rust().ok_or(FfiReturn::ArgIsNull)?.to_owned())
            .map_err(|_e| FfiReturn::Utf8Error)
    }
}

impl IntoFfi for String {
    type Store = <Vec<u8> as IntoFfi>::Store;

    fn into_ffi(self, store: &mut Self::Store) -> Self::ReprC {
        self.into_bytes().into_ffi(store)
    }
}

impl<'slice> FfiType for &'slice str {
    type ReprC = <&'slice [u8] as FfiType>::ReprC;
}

impl<'itm> TryFromReprC<'itm> for &'itm str {
    type Store = ();

    unsafe fn try_from_repr_c(source: Self::ReprC, _: &mut Self::Store) -> Result<Self> {
        core::str::from_utf8(source.into_rust().ok_or(FfiReturn::ArgIsNull)?)
            .map_err(|_e| FfiReturn::Utf8Error)
    }
}

impl<'slice> IntoFfi for &'slice str {
    type Store = <&'slice [u8] as IntoFfi>::Store;

    fn into_ffi(self, store: &mut Self::Store) -> Self::ReprC {
        self.as_bytes().into_ffi(store)
    }
}

impl<T: FfiType, const N: usize> FfiType for [T; N] {
    type ReprC = Local<*mut [T::ReprC; N]>;
}

impl<'itm, T: TryFromReprC<'itm>, const N: usize> TryFromReprC<'itm> for [T; N]
where
    [T::Store; N]: Default,
{
    type Store = [T::Store; N];

    unsafe fn try_from_repr_c(source: Self::ReprC, store: &'itm mut Self::Store) -> Result<Self> {
        let source = source.0.as_mut().ok_or(FfiReturn::ArgIsNull)?;
        let mut data: [MaybeUninit<T>; N] = MaybeUninit::uninit().assume_init();

        let mut i = 0;
        let mut substore = &mut store[..];
        while let Some((first, rest)) = substore.split_first_mut() {
            data[i].write(TryFromReprC::try_from_repr_c(source[i], first)?);
            substore = rest;
            i += 1;
        }

        Ok(data.as_ptr().cast::<[T; N]>().read())
    }
}
impl<T: IntoFfi, const N: usize> IntoFfi for [T; N]
where
    [T::Store; N]: Default,
{
    type Store = (Option<[T::ReprC; N]>, [T::Store; N]);

    fn into_ffi(self, store: &mut Self::Store) -> Self::ReprC {
        let mut data_store: [MaybeUninit<T::ReprC>; N] =
            unsafe { MaybeUninit::uninit().assume_init() };

        self.into_iter().enumerate().for_each(|(i, item)| {
            data_store[i].write(IntoFfi::into_ffi(item, &mut store.1[i]));
        });

        Local(
            store
                .0
                .insert(unsafe { data_store.as_ptr().cast::<[T::ReprC; N]>().read() }),
        )
    }
}
