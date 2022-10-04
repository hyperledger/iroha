#![allow(trivial_casts, clippy::undocumented_unsafe_blocks)]

//! Logic related to the conversion of IR types to equivalent robust C types. Most of the
//! types that implement [`Ir`], i.e. provide conversion into IR, will get an automatic
//! implementation of [`CType`] and consequently an implementation of [`FfiType`]

use alloc::{boxed::Box, vec::Vec};
use core::{hint::unreachable_unchecked, mem::ManuallyDrop};

use crate::{
    ir::{
        Ir, IrArray, IrBox, IrSlice, IrSliceMut, IrTypeOf, IrVec, Opaque, Robust, Transmute,
        Transparent,
    },
    slice::{OutBoxedSlice, SliceMut, SliceRef},
    FfiConvert, FfiOutPtr, FfiReturn, FfiType, OutPtrOf, ReprC, Result,
};

/// A type that can be converted into some C type. When implemented on [`Ir::Type`] the blanket
/// implementations ensures that [`FfiType`] is also implemented on the type implementing [`Ir`].
/// This trait mainly exists to move types of internal representation into C type equivalents.
pub trait CType: Sized {
    /// C type current type can be converted into
    type ReprC: ReprC;
}

/// Conversion utility [`CType`]s. When implemented on [`Ir::Type`] the blanket implementation
/// ensures that [`FfiType`] is also implemented on the type implementing [`Ir`]. This trait
/// mainly exists to move types of internal representation into C type equivalents. When
/// implementing make sure that the implementation doesn't conflict with [`NonLocal`]
pub trait CTypeConvert<'itm, T>: Sized {
    /// Type into which state can be stored during conversion from [`Self`]. Useful for
    /// returning owning heap allocated types or non-owning types that are not transmutable.
    /// Serves similar purpose as does context in a closure
    type RustStore: Default;

    /// Type into which state can be stored during conversion into [`Self`]. Useful for
    /// returning non-owning types that are not transmutable. Serves similar purpose as
    /// does context in a closure
    type FfiStore: Default;

    /// Perform the conversion from [`Self`] into `[Self::ReprC]`
    fn into_repr_c(self, store: &'itm mut Self::RustStore) -> T;

    /// Perform the conversion from [`Self::ReprC`] into `[Self]`
    ///
    /// # Errors
    ///
    /// Check [`FfiReturn`]
    ///
    /// # Safety
    ///
    /// All conversions from a pointer must ensure pointer validity beforehand
    unsafe fn try_from_repr_c(source: T, store: &'itm mut Self::FfiStore) -> Result<Self>;
}

/// Provides the capability to use the type as an out-pointer.
/// This trait mainly exists to be implemented on IR types.
pub trait COutPtr: CType {
    /// Out-pointer type
    type OutPtr: OutPtrOf<Self::ReprC>;
}

/// Marker trait indicating that a type converted into corresponding [`CType`] doesn't
/// reference conversion context. This is useful to determine which types can be returned
/// from FFI function and how they are returned.
///
/// # Example
///
/// 1. `&mut [u8]`
/// This type will be converted to [`SliceMut<u8>`] and during conversion will not make use
/// of the store (in any direction). This means that the type's corresponding out-pointer
/// will be `*mut SliceMut<u8>`, i.e. a pointer to a location where the slice's
/// data pointer and length will be stored
///
/// 2. `Vec<Opaque<T>>`
/// This type will be converted to [`SliceMut<*mut T>`] and during conversion will use the
/// local store with `Vec<*mut T>`. Therefore, the type's corresponding out-pointer will
/// be `*mut OutBoxedSlice<T>` where each element will be coppied into a data pointer given
/// by the caller (because we cannot return a pointer to a data that is local to a function).
///
/// # Safety
///
/// Type must not use the store during conversion into [`CType`], i.e. it must not reference local context.
pub unsafe trait NonLocal: COutPtr {}

/// Type that cannot be transmuted into a [`ReprC`] type
pub trait NonTransmute: CType {}

impl<T: Ir> NonTransmute for &T where T::Type: NonTransmute {}
impl<T: Ir> NonTransmute for IrBox<T, T::Type> where Self: CType {}
impl<T: Ir> NonTransmute for IrSlice<'_, T, T::Type> where Self: CType {}
impl<T: Ir> NonTransmute for IrSliceMut<'_, T, T::Type> where Self: CType {}
impl<T: Ir> NonTransmute for IrVec<T, T::Type> where Self: CType {}
impl<T: Ir, const N: usize> NonTransmute for IrArray<T, T::Type, N> where T::Type: NonTransmute {}

// NOTE: `CType` cannot be implemented for `&mut T`
impl<T: Ir> CType for &T
where
    T::Type: NonTransmute,
{
    type ReprC = *const <T::Type as CType>::ReprC;
}
impl<'itm, T: Ir + Clone, K: ReprC> CTypeConvert<'itm, *const K> for &'itm T
where
    T::Type: NonTransmute + CTypeConvert<'itm, K> + Clone,
{
    type RustStore = (Option<K>, <T::Type as CTypeConvert<'itm, K>>::RustStore);
    type FfiStore = (Option<T>, <T::Type as CTypeConvert<'itm, K>>::FfiStore);

    fn into_repr_c(self, store: &'itm mut Self::RustStore) -> *const K {
        let item: T::Type = IrTypeOf::into_ir(Clone::clone(self));
        store.0.insert(item.into_repr_c(&mut store.1))
    }

    unsafe fn try_from_repr_c(source: *const K, store: &'itm mut Self::FfiStore) -> Result<Self> {
        if source.as_ref().is_none() {
            return Err(FfiReturn::ArgIsNull);
        }

        Ok(store.0.insert(
            <T::Type as CTypeConvert<_>>::try_from_repr_c(source.read(), &mut store.1)
                .map(ManuallyDrop::new)
                .map(|item| (*item).clone())
                .map(IrTypeOf::into_rust)?,
        ))
    }
}

impl<T: Ir<Type = U>, U: NonTransmute> CType for IrBox<T, U> {
    type ReprC = *mut U::ReprC;
}
impl<
        'itm,
        T: Ir<Type = U> + 'itm,
        U: NonTransmute + IrTypeOf<T> + CTypeConvert<'itm, K> + Clone,
        K: ReprC,
    > CTypeConvert<'itm, *mut K> for IrBox<T, U>
{
    type RustStore = (Option<K>, U::RustStore);
    type FfiStore = U::FfiStore;

    fn into_repr_c(self, store: &'itm mut Self::RustStore) -> *mut K {
        let unboxed: U = IrTypeOf::into_ir(*self.0);
        store.0.insert(unboxed.into_repr_c(&mut store.1))
    }
    unsafe fn try_from_repr_c(source: *mut K, store: &'itm mut Self::FfiStore) -> Result<Self> {
        if source.as_mut().is_none() {
            return Err(FfiReturn::ArgIsNull);
        }

        U::try_from_repr_c(source.read(), store)
            .map(ManuallyDrop::new)
            .map(|item| (*item).clone())
            .map(IrTypeOf::into_rust)
            .map(Box::new)
            .map(IrBox)
    }
}

// NOTE: `CType` cannot be implemented for `&mut [T]`
impl<T: Ir<Type = U>, U: NonTransmute> CType for IrSlice<'_, T, U> {
    type ReprC = SliceRef<U::ReprC>;
}
impl<
        'itm,
        T: Ir<Type = U> + Clone,
        U: NonTransmute + IrTypeOf<T> + CTypeConvert<'itm, K> + Clone,
        K: ReprC,
    > CTypeConvert<'itm, SliceRef<K>> for IrSlice<'itm, T, U>
{
    type RustStore = (Vec<K>, Vec<U::RustStore>);
    type FfiStore = (Vec<T>, Vec<U::FfiStore>);

    fn into_repr_c(self, store: &'itm mut Self::RustStore) -> SliceRef<K> {
        let slice: Vec<U> = self.0.iter().cloned().map(IrTypeOf::into_ir).collect();

        store.1 = core::iter::repeat_with(Default::default)
            .take(slice.len())
            .collect();

        store.0 = slice
            .into_iter()
            .zip(&mut store.1)
            .map(|(item, substore)| item.into_repr_c(substore))
            .collect();

        SliceRef::from_slice(&store.0)
    }

    unsafe fn try_from_repr_c(
        source: SliceRef<K>,
        store: &'itm mut Self::FfiStore,
    ) -> Result<Self> {
        store.1 = core::iter::repeat_with(Default::default)
            .take(source.len())
            .collect();

        let source: Vec<ManuallyDrop<U>> = source
            .into_rust()
            .ok_or(FfiReturn::ArgIsNull)?
            .iter()
            .zip(&mut store.1)
            .map(|(&item, substore)| {
                CTypeConvert::try_from_repr_c(item, substore).map(ManuallyDrop::new)
            })
            .collect::<core::result::Result<_, _>>()?;

        store.0 = source
            .iter()
            .cloned()
            .map(ManuallyDrop::into_inner)
            .map(IrTypeOf::into_rust)
            .collect();

        Ok(IrSlice(&store.0))
    }
}

impl<T: Ir<Type = U>, U: NonTransmute> CType for IrVec<T, U> {
    type ReprC = SliceMut<U::ReprC>;
}
impl<
        'itm,
        T: Ir<Type = U> + 'itm,
        U: NonTransmute + IrTypeOf<T> + CTypeConvert<'itm, K> + Clone,
        K: ReprC,
    > CTypeConvert<'itm, SliceMut<K>> for IrVec<T, U>
{
    type RustStore = (Vec<K>, Vec<U::RustStore>);
    type FfiStore = Vec<U::FfiStore>;

    fn into_repr_c(self, store: &'itm mut Self::RustStore) -> SliceMut<K> {
        let vec: Vec<U> = self.0.into_iter().map(IrTypeOf::into_ir).collect();

        store.1 = core::iter::repeat_with(Default::default)
            .take(vec.len())
            .collect();

        store.0 = vec
            .into_iter()
            .zip(&mut store.1)
            .map(|(item, substore)| item.into_repr_c(substore))
            .collect();

        SliceMut::from_slice(&mut store.0)
    }
    unsafe fn try_from_repr_c(
        source: SliceMut<K>,
        store: &'itm mut Self::FfiStore,
    ) -> Result<Self> {
        let slice = source.into_rust().ok_or(FfiReturn::ArgIsNull)?;

        *store = core::iter::repeat_with(Default::default)
            .take(slice.len())
            .collect();

        let vec: Vec<ManuallyDrop<U>> = slice
            .iter()
            .copied()
            .zip(store)
            .map(|(item, substore)| {
                CTypeConvert::try_from_repr_c(item, substore).map(ManuallyDrop::new)
            })
            .collect::<core::result::Result<_, _>>()?;

        Ok(IrVec(
            vec.iter()
                .cloned()
                .map(ManuallyDrop::into_inner)
                .map(IrTypeOf::into_rust)
                .collect::<Vec<_>>(),
        ))
    }
}

impl<T: Ir<Type = U>, U: NonTransmute, const N: usize> CType for IrArray<T, U, N> {
    type ReprC = [U::ReprC; N];
}
impl<
        'itm,
        T: Ir<Type = U> + 'itm,
        U: NonTransmute + IrTypeOf<T> + CTypeConvert<'itm, K> + Clone,
        K: ReprC,
        const N: usize,
    > CTypeConvert<'itm, [K; N]> for IrArray<T, U, N>
where
    [U::RustStore; N]: Default,
    [U::FfiStore; N]: Default,
{
    type RustStore = [U::RustStore; N];
    type FfiStore = [U::FfiStore; N];

    fn into_repr_c(self, store: &'itm mut Self::RustStore) -> [K; N] {
        let array: [U; N] = if let Ok(arr) = self
            .0
            .into_iter()
            .map(IrTypeOf::into_ir)
            .collect::<Vec<_>>()
            .try_into()
        {
            arr
        } else {
            // SAFETY: Vec<T> length is N
            unsafe { unreachable_unchecked() }
        };
        *store = if let Ok(arr) = TryFrom::try_from(
            core::iter::repeat_with(Default::default)
                .take(array.len())
                .collect::<Vec<U::RustStore>>(),
        ) {
            arr
        } else {
            // SAFETY: Vec<T> length is N
            unsafe { unreachable_unchecked() }
        };

        if let Ok(arr) = array
            .into_iter()
            .zip(store.iter_mut())
            .map(|(item, substore)| item.into_repr_c(substore))
            .collect::<Vec<_>>()
            .try_into()
        {
            arr
        } else {
            // SAFETY: Vec<T> length is N
            unsafe { unreachable_unchecked() }
        }
    }
    unsafe fn try_from_repr_c(source: [K; N], store: &'itm mut Self::FfiStore) -> Result<Self> {
        let array: [ManuallyDrop<U>; N] = if let Ok(arr) = source
            .into_iter()
            .zip(store.iter_mut())
            .map(|(item, substore)| {
                CTypeConvert::try_from_repr_c(item, substore).map(ManuallyDrop::new)
            })
            .collect::<core::result::Result<Vec<_>, FfiReturn>>()?
            .try_into()
        {
            arr
        } else {
            unreachable_unchecked()
        };

        Ok(IrArray(
            if let Ok(arr) = array
                .iter()
                .cloned()
                .map(ManuallyDrop::into_inner)
                .map(IrTypeOf::into_rust)
                .collect::<Vec<_>>()
                .try_into()
            {
                arr
            } else {
                unreachable_unchecked()
            },
        ))
    }
}
impl<
        'itm,
        T: Ir<Type = U> + 'itm,
        U: NonTransmute + CTypeConvert<'itm, K> + IrTypeOf<T> + Clone,
        K: ReprC,
        const N: usize,
    > CTypeConvert<'itm, *mut K> for IrArray<T, U, N>
where
    [U::RustStore; N]: Default,
    [U::FfiStore; N]: Default,
    [K; N]: Default,
{
    type RustStore = ([K; N], [U::RustStore; N]);
    type FfiStore = [U::FfiStore; N];

    fn into_repr_c(self, store: &'itm mut Self::RustStore) -> *mut K {
        store.0 = self.into_repr_c(&mut store.1);
        store.0.as_mut_ptr()
    }
    unsafe fn try_from_repr_c(source: *mut K, store: &'itm mut Self::FfiStore) -> Result<Self> {
        CTypeConvert::try_from_repr_c(source.cast::<[K; N]>().read(), store)
    }
}

impl<T: Ir> COutPtr for &T
where
    T::Type: NonTransmute + NonLocal,
{
    type OutPtr = *mut <T::Type as CType>::ReprC;
}
impl<T: Ir<Type = U>, U: NonTransmute + NonLocal> COutPtr for IrSlice<'_, T, U> {
    type OutPtr = OutBoxedSlice<U::ReprC>;
}
impl<T: Ir<Type = U>, U: NonTransmute + NonLocal> COutPtr for IrBox<T, U> {
    type OutPtr = *mut U::ReprC;
}
impl<T: Ir<Type = U>, U: NonTransmute + NonLocal> COutPtr for IrVec<T, U> {
    type OutPtr = OutBoxedSlice<U::ReprC>;
}
impl<T: Ir<Type = U>, U: NonTransmute + NonLocal, const N: usize> COutPtr for IrArray<T, U, N> {
    type OutPtr = *mut U::ReprC;
}

/* ---------------------------------------Robust-------------------------------------- */

impl<T: ReprC> CType for Robust<T> {
    type ReprC = T;
}
impl<'itm, T: ReprC + 'itm> CTypeConvert<'itm, T> for Robust<T> {
    type RustStore = ();
    type FfiStore = ();

    fn into_repr_c(self, _: &mut ()) -> T {
        self.0
    }

    unsafe fn try_from_repr_c(source: T, _: &mut ()) -> Result<Self> {
        Ok(Self(source))
    }
}

impl<T: ReprC + Ir<Type = Robust<T>>> CType for IrBox<T, Robust<T>> {
    type ReprC = *mut T;
}
impl<'itm, T: ReprC + Ir<Type = Robust<T>> + Default + 'itm> CTypeConvert<'itm, *mut T>
    for IrBox<T, Robust<T>>
{
    type RustStore = Box<T>;
    type FfiStore = ();

    fn into_repr_c(self, store: &mut Self::RustStore) -> *mut T {
        *store = self.0;
        &mut **store
    }

    unsafe fn try_from_repr_c(source: *mut T, _: &mut ()) -> Result<Self> {
        if source.is_null() {
            return Err(FfiReturn::ArgIsNull);
        }

        Ok(Self(Box::new(source.read())))
    }
}

impl<T: ReprC + Ir<Type = Robust<T>>> CType for IrSlice<'_, T, Robust<T>> {
    type ReprC = SliceRef<T>;
}
impl<'itm, T: ReprC + Ir<Type = Robust<T>>> CTypeConvert<'itm, SliceRef<T>>
    for IrSlice<'itm, T, Robust<T>>
{
    type RustStore = ();
    type FfiStore = ();

    fn into_repr_c(self, _: &mut ()) -> SliceRef<T> {
        SliceRef::from_slice(self.0)
    }

    unsafe fn try_from_repr_c(source: SliceRef<T>, _: &mut ()) -> Result<Self> {
        source.into_rust().ok_or(FfiReturn::ArgIsNull).map(Self)
    }
}

impl<T: ReprC + Ir<Type = Robust<T>>> CType for IrSliceMut<'_, T, Robust<T>> {
    type ReprC = SliceMut<T>;
}
impl<'itm, T: ReprC + Ir<Type = Robust<T>>> CTypeConvert<'itm, SliceMut<T>>
    for IrSliceMut<'itm, T, Robust<T>>
{
    type RustStore = ();
    type FfiStore = ();

    fn into_repr_c(self, _: &mut ()) -> SliceMut<T> {
        SliceMut::from_slice(self.0)
    }

    unsafe fn try_from_repr_c(source: SliceMut<T>, _: &mut ()) -> Result<Self> {
        source.into_rust().ok_or(FfiReturn::ArgIsNull).map(Self)
    }
}

impl<T: ReprC + Ir<Type = Robust<T>>> CType for IrVec<T, Robust<T>> {
    type ReprC = SliceMut<T>;
}
impl<'itm, T: ReprC + Ir<Type = Robust<T>> + 'itm> CTypeConvert<'itm, SliceMut<T>>
    for IrVec<T, Robust<T>>
{
    type RustStore = Vec<T>;
    type FfiStore = ();

    fn into_repr_c(self, store: &mut Self::RustStore) -> SliceMut<T> {
        *store = self.0;
        SliceMut::from_slice(store)
    }

    unsafe fn try_from_repr_c(source: SliceMut<T>, _: &mut ()) -> Result<Self> {
        source
            .into_rust()
            .ok_or(FfiReturn::ArgIsNull)
            .map(|slice| slice.to_vec())
            .map(Self)
    }
}

impl<T: ReprC + Ir<Type = Robust<T>>, const N: usize> CType for IrArray<T, Robust<T>, N> {
    type ReprC = [T; N];
}
impl<'itm, T: ReprC + Ir<Type = Robust<T>> + 'itm, const N: usize> CTypeConvert<'itm, [T; N]>
    for IrArray<T, Robust<T>, N>
{
    type RustStore = ();
    type FfiStore = ();

    fn into_repr_c(self, _: &mut ()) -> [T; N] {
        self.0
    }

    unsafe fn try_from_repr_c(source: [T; N], _: &mut ()) -> Result<Self> {
        Ok(Self(source))
    }
}
impl<'itm, T: ReprC + Ir<Type = Robust<T>> + 'itm, const N: usize> CTypeConvert<'itm, *mut T>
    for IrArray<T, Robust<T>, N>
where
    [T; N]: Default,
{
    type RustStore = [T; N];
    type FfiStore = ();

    fn into_repr_c(self, store: &mut Self::RustStore) -> *mut T {
        *store = self.0;
        store.as_mut_ptr()
    }

    unsafe fn try_from_repr_c(source: *mut T, _: &mut ()) -> Result<Self> {
        Ok(Self(source.cast::<[T; N]>().read()))
    }
}

impl<T: ReprC> COutPtr for Robust<T> {
    type OutPtr = *mut T;
}
impl<T: ReprC + Ir<Type = Robust<T>>> COutPtr for IrBox<T, Robust<T>> {
    type OutPtr = *mut T;
}
impl<T: ReprC + Ir<Type = Robust<T>>> COutPtr for IrSlice<'_, T, Robust<T>> {
    type OutPtr = *mut SliceRef<T>;
}
impl<T: ReprC + Ir<Type = Robust<T>>> COutPtr for IrSliceMut<'_, T, Robust<T>> {
    type OutPtr = *mut SliceMut<T>;
}
impl<T: ReprC + Ir<Type = Robust<T>>> COutPtr for IrVec<T, Robust<T>> {
    type OutPtr = OutBoxedSlice<T>;
}
impl<T: ReprC + Ir<Type = Robust<T>>, const N: usize> COutPtr for IrArray<T, Robust<T>, N> {
    type OutPtr = *mut [T; N];
}

// SAFETY: Type doesn't use store during conversion
unsafe impl<T: ReprC> NonLocal for Robust<T> {}
// SAFETY: Type doesn't use store during conversion
unsafe impl<T: ReprC + Ir<Type = Robust<T>>> NonLocal for IrSlice<'_, T, Robust<T>> {}
// SAFETY: Type doesn't use store during conversion
unsafe impl<T: ReprC + Ir<Type = Robust<T>>> NonLocal for IrSliceMut<'_, T, Robust<T>> {}
// SAFETY: Type doesn't use store during conversion
unsafe impl<T: ReprC + Ir<Type = Robust<T>>, const N: usize> NonLocal for IrArray<T, Robust<T>, N> {}

/* ---------------------------------------Opaque-------------------------------------- */

impl<T> CType for Opaque<T> {
    type ReprC = *mut T;
}
impl<'itm, T: 'itm> CTypeConvert<'itm, *mut T> for Opaque<T> {
    type RustStore = ();
    type FfiStore = ();

    fn into_repr_c(self, _: &mut ()) -> *mut T {
        Box::into_raw(Box::new(self.0))
    }
    unsafe fn try_from_repr_c(source: *mut T, _: &mut ()) -> Result<Self> {
        if source.is_null() {
            return Err(FfiReturn::ArgIsNull);
        }

        Ok(Self(*Box::from_raw(source)))
    }
}

impl<T: Ir<Type = Opaque<T>>> CType for IrBox<T, Opaque<T>> {
    type ReprC = *mut T;
}
impl<'itm, T: Ir<Type = Opaque<T>> + 'itm> CTypeConvert<'itm, *mut T> for IrBox<T, Opaque<T>> {
    type RustStore = ();
    type FfiStore = ();

    fn into_repr_c(self, _: &mut ()) -> *mut T {
        Box::into_raw(self.0)
    }

    unsafe fn try_from_repr_c(source: *mut T, _: &mut ()) -> Result<Self> {
        if source.is_null() {
            return Err(FfiReturn::ArgIsNull);
        }

        Ok(Self(Box::from_raw(source)))
    }
}

impl<T: Ir<Type = Opaque<T>> + Clone> CType for IrSlice<'_, T, Opaque<T>> {
    type ReprC = SliceRef<*const T>;
}
impl<'slice, T: Ir<Type = Opaque<T>> + Clone> CTypeConvert<'slice, SliceRef<*const T>>
    for IrSlice<'slice, T, Opaque<T>>
{
    type RustStore = Vec<*const T>;
    type FfiStore = Vec<T>;

    fn into_repr_c(self, store: &mut Self::RustStore) -> SliceRef<*const T> {
        *store = self.0.iter().map(|item| item as *const T).collect();
        SliceRef::from_slice(store)
    }

    unsafe fn try_from_repr_c(
        source: SliceRef<*const T>,
        store: &'slice mut Self::FfiStore,
    ) -> Result<Self> {
        let source = source.into_rust().ok_or(FfiReturn::ArgIsNull)?;

        *store = source
            .iter()
            .map(|item| {
                item
                        .as_ref()
                        // NOTE: This function clones every opaque pointer in the slice. This could
                        // be avoided with the entire slice being opaque, if that even makes sense.
                        .cloned()
                        .ok_or(FfiReturn::ArgIsNull)
            })
            .collect::<core::result::Result<_, _>>()?;

        Ok(Self(store))
    }
}

impl<T: Ir<Type = Opaque<T>>> CType for IrSliceMut<'_, T, Opaque<T>> {
    type ReprC = SliceMut<*mut T>;
}
impl<'slice, T: Ir<Type = Opaque<T>> + Clone> CTypeConvert<'slice, SliceMut<*mut T>>
    for IrSliceMut<'slice, T, Opaque<T>>
{
    type RustStore = Vec<*mut T>;
    type FfiStore = Vec<T>;

    fn into_repr_c(self, store: &mut Self::RustStore) -> SliceMut<*mut T> {
        *store = self.0.iter_mut().map(|item| item as *mut T).collect();

        SliceMut::from_slice(store)
    }

    unsafe fn try_from_repr_c(
        source: SliceMut<*mut T>,
        store: &'slice mut Self::FfiStore,
    ) -> Result<Self> {
        let source = source.into_rust().ok_or(FfiReturn::ArgIsNull)?;

        *store = source
            .iter()
            .map(|item| {
                item
                        .as_mut()
                        // NOTE: This function clones every opaque pointer in the slice. This could
                        // be avoided with the entire slice being opaque, if that even makes sense.
                        .cloned()
                        .ok_or(FfiReturn::ArgIsNull)
            })
            .collect::<core::result::Result<_, _>>()?;

        Ok(Self(store))
    }
}

impl<T: Ir<Type = Opaque<T>>> CType for IrVec<T, Opaque<T>> {
    type ReprC = SliceMut<*mut T>;
}
impl<'itm, T: Ir<Type = Opaque<T>> + 'itm> CTypeConvert<'itm, SliceMut<*mut T>>
    for IrVec<T, Opaque<T>>
{
    type RustStore = Vec<*mut T>;
    type FfiStore = ();

    fn into_repr_c(self, store: &mut Self::RustStore) -> SliceMut<*mut T> {
        *store = self
            .0
            .into_iter()
            .map(Box::new)
            .map(Box::into_raw)
            .collect();

        SliceMut::from_slice(store)
    }

    unsafe fn try_from_repr_c(source: SliceMut<*mut T>, _: &mut ()) -> Result<Self> {
        source
            .into_rust()
            .ok_or(FfiReturn::ArgIsNull)?
            .iter()
            .map(|&item| {
                if let Some(item) = item.as_mut() {
                    return Ok(*Box::from_raw(item));
                }

                Err(FfiReturn::ArgIsNull)
            })
            .collect::<core::result::Result<_, _>>()
            .map(Self)
    }
}

impl<T: Ir<Type = Opaque<T>>, const N: usize> CType for IrArray<T, Opaque<T>, N> {
    type ReprC = [*mut T; N];
}
impl<'itm, T: Ir<Type = Opaque<T>> + 'itm, const N: usize> CTypeConvert<'itm, [*mut T; N]>
    for IrArray<T, Opaque<T>, N>
{
    type RustStore = ();
    type FfiStore = ();

    fn into_repr_c(self, _: &mut Self::RustStore) -> [*mut T; N] {
        if let Ok(arr) = self
            .0
            .into_iter()
            .map(Box::new)
            .map(Box::into_raw)
            .collect::<Vec<_>>()
            .try_into()
        {
            arr
        } else {
            // SAFETY: Vec<T> length is N
            unsafe { unreachable_unchecked() }
        }
    }

    unsafe fn try_from_repr_c(source: [*mut T; N], _: &mut ()) -> Result<Self> {
        Ok(Self(
            if let Ok(arr) = source
                .into_iter()
                .map(|item| {
                    if let Some(item) = item.as_mut() {
                        return Ok(*Box::from_raw(item));
                    }

                    Err(FfiReturn::ArgIsNull)
                })
                .collect::<core::result::Result<Vec<T>, _>>()?
                .try_into()
            {
                arr
            } else {
                unreachable_unchecked()
            },
        ))
    }
}
impl<'itm, T: Ir<Type = Opaque<T>> + 'itm, const N: usize> CTypeConvert<'itm, *mut *mut T>
    for IrArray<T, Opaque<T>, N>
where
    [*mut T; N]: Default,
{
    type RustStore = [*mut T; N];
    type FfiStore = ();

    fn into_repr_c(self, store: &mut Self::RustStore) -> *mut *mut T {
        *store = self.into_repr_c(&mut ());
        store.as_mut_ptr()
    }

    unsafe fn try_from_repr_c(source: *mut *mut T, _: &mut ()) -> Result<Self> {
        CTypeConvert::try_from_repr_c(source.cast::<[*mut T; N]>().read(), &mut ())
    }
}

impl<T> COutPtr for Opaque<T> {
    type OutPtr = *mut *mut T;
}
impl<T: Ir<Type = Opaque<T>>> COutPtr for IrBox<T, Opaque<T>> {
    type OutPtr = *mut *mut T;
}
impl<T: Ir<Type = Opaque<T>>> COutPtr for IrSlice<'_, T, Opaque<T>>
where
    Self: CType<ReprC = SliceRef<*const T>>,
{
    type OutPtr = OutBoxedSlice<*const T>;
}
impl<T: Ir<Type = Opaque<T>>> COutPtr for IrSliceMut<'_, T, Opaque<T>> {
    type OutPtr = OutBoxedSlice<*mut T>;
}
impl<T: Ir<Type = Opaque<T>>> COutPtr for IrVec<T, Opaque<T>> {
    type OutPtr = OutBoxedSlice<*mut T>;
}
impl<T: Ir<Type = Opaque<T>>, const N: usize> COutPtr for IrArray<T, Opaque<T>, N> {
    type OutPtr = *mut [*mut T; N];
}

// SAFETY: Type doesn't use store during conversion
unsafe impl<T> NonLocal for Opaque<T> {}
// SAFETY: Type doesn't use store during conversion
unsafe impl<T: Ir<Type = Opaque<T>>> NonLocal for IrBox<T, Opaque<T>> {}
// SAFETY: Type doesn't use store during conversion
unsafe impl<T: Ir<Type = Opaque<T>>, const N: usize> NonLocal for IrArray<T, Opaque<T>, N> {}

/* ------------------------------------Transparent------------------------------------ */

impl<T: Transmute> CType for Transparent<T>
where
    T::Target: FfiType,
{
    type ReprC = <T::Target as FfiType>::ReprC;
}
impl<'itm, T: Transmute + 'itm, U: ReprC> CTypeConvert<'itm, U> for Transparent<T>
where
    T::Target: FfiConvert<'itm, U>,
{
    type RustStore = <T::Target as FfiConvert<'itm, U>>::RustStore;
    type FfiStore = <T::Target as FfiConvert<'itm, U>>::FfiStore;

    fn into_repr_c(self, store: &'itm mut Self::RustStore) -> U {
        self.into_inner().into_ffi(store)
    }

    unsafe fn try_from_repr_c(source: U, store: &'itm mut Self::FfiStore) -> Result<Self> {
        Self::try_from_inner(FfiConvert::try_from_ffi(source, store)?)
            .ok_or(FfiReturn::TrapRepresentation)
    }
}

impl<T: Transmute + Ir<Type = Transparent<T>>> CType for IrBox<T, Transparent<T>>
where
    Box<T::Target>: FfiType,
{
    type ReprC = <Box<T::Target> as FfiType>::ReprC;
}
impl<'itm, T: Transmute + Ir<Type = Transparent<T>> + 'itm, K: ReprC> CTypeConvert<'itm, K>
    for IrBox<T, Transparent<T>>
where
    Box<T::Target>: FfiConvert<'itm, K>,
{
    type RustStore = <Box<T::Target> as FfiConvert<'itm, K>>::RustStore;
    type FfiStore = <Box<T::Target> as FfiConvert<'itm, K>>::FfiStore;

    fn into_repr_c(self, store: &'itm mut Self::RustStore) -> K {
        // SAFETY: `Transparent` is guaranteed to be transmutable into `T::Target`
        unsafe { Box::from_raw(Box::into_raw(self.0).cast::<T::Target>()).into_ffi(store) }
    }

    unsafe fn try_from_repr_c(source: K, store: &'itm mut Self::FfiStore) -> Result<Self> {
        let item: Box<T::Target> = FfiConvert::try_from_ffi(source, store)?;

        if !T::is_valid(&item) {
            return Err(FfiReturn::TrapRepresentation);
        }

        Ok(Self(Box::from_raw(Box::into_raw(item).cast::<T>())))
    }
}

impl<'slice, T: Transmute + Ir<Type = Transparent<T>>> CType for IrSlice<'slice, T, Transparent<T>>
where
    &'slice [T::Target]: FfiType,
{
    type ReprC = <&'slice [T::Target] as FfiType>::ReprC;
}
impl<'slice, T: Transmute + Ir<Type = Transparent<T>>, U: ReprC> CTypeConvert<'slice, U>
    for IrSlice<'slice, T, Transparent<T>>
where
    &'slice [T::Target]: FfiConvert<'slice, U>,
{
    type RustStore = <&'slice [T::Target] as FfiConvert<'slice, U>>::RustStore;
    type FfiStore = <&'slice [T::Target] as FfiConvert<'slice, U>>::FfiStore;

    fn into_repr_c(self, store: &'slice mut Self::RustStore) -> U {
        let slice = self.0;

        let (ptr, len) = (slice.as_ptr().cast::<T::Target>(), slice.len());
        // SAFETY: `T` is guaranteed to be transmutable into `T::Target`
        unsafe { core::slice::from_raw_parts(ptr, len).into_ffi(store) }
    }

    unsafe fn try_from_repr_c(source: U, store: &'slice mut Self::FfiStore) -> Result<Self> {
        let slice = <&[T::Target]>::try_from_ffi(source, store)?;

        if !slice.iter().all(|item| T::is_valid(item)) {
            return Err(FfiReturn::TrapRepresentation);
        }

        Ok(Self(core::slice::from_raw_parts(
            slice.as_ptr().cast(),
            slice.len(),
        )))
    }
}

impl<'slice, T: Transmute + Ir<Type = Transparent<T>>> CType
    for IrSliceMut<'slice, T, Transparent<T>>
where
    &'slice mut [T::Target]: FfiType,
{
    type ReprC = <&'slice mut [T::Target] as FfiType>::ReprC;
}
impl<'slice, T: Transmute + Ir<Type = Transparent<T>>, U: ReprC> CTypeConvert<'slice, U>
    for IrSliceMut<'slice, T, Transparent<T>>
where
    &'slice mut [T::Target]: FfiConvert<'slice, U>,
{
    type RustStore = <&'slice mut [T::Target] as FfiConvert<'slice, U>>::RustStore;
    type FfiStore = <&'slice mut [T::Target] as FfiConvert<'slice, U>>::FfiStore;

    fn into_repr_c(self, store: &'slice mut Self::RustStore) -> U {
        let slice = self.0;

        let (ptr, len) = (slice.as_mut_ptr().cast::<T::Target>(), slice.len());
        // SAFETY: `T` is guaranteed to be transmutable into `T::Target`
        unsafe { core::slice::from_raw_parts_mut(ptr, len).into_ffi(store) }
    }

    unsafe fn try_from_repr_c(source: U, store: &'slice mut Self::FfiStore) -> Result<Self> {
        let slice = <&mut [T::Target]>::try_from_ffi(source, store)?;

        if !slice.iter().all(|item| T::is_valid(item)) {
            return Err(FfiReturn::TrapRepresentation);
        }

        Ok(Self(core::slice::from_raw_parts_mut(
            slice.as_mut_ptr().cast(),
            slice.len(),
        )))
    }
}

impl<T: Transmute + Ir<Type = Transparent<T>>> CType for IrVec<T, Transparent<T>>
where
    Vec<T::Target>: FfiType,
{
    type ReprC = <Vec<T::Target> as FfiType>::ReprC;
}
impl<'itm, T: Transmute + Ir<Type = Transparent<T>> + 'itm, U: ReprC> CTypeConvert<'itm, U>
    for IrVec<T, Transparent<T>>
where
    Vec<T::Target>: FfiConvert<'itm, U>,
{
    type RustStore = <Vec<T::Target> as FfiConvert<'itm, U>>::RustStore;
    type FfiStore = <Vec<T::Target> as FfiConvert<'itm, U>>::FfiStore;

    fn into_repr_c(self, store: &'itm mut Self::RustStore) -> U {
        let mut vec = ManuallyDrop::new(self.0);

        let vec: Vec<T::Target> =
            // SAFETY: `Transparency` guarantees `T` can be transmuted into `U`
            unsafe { Vec::from_raw_parts(vec.as_mut_ptr().cast(), vec.len(), vec.capacity()) };

        vec.into_ffi(store)
    }

    unsafe fn try_from_repr_c(source: U, store: &'itm mut Self::FfiStore) -> Result<Self> {
        let vec = <Vec<T::Target>>::try_from_ffi(source, store)?;

        if !vec.iter().all(|item| T::is_valid(item)) {
            return Err(FfiReturn::TrapRepresentation);
        }

        let mut vec = ManuallyDrop::new(vec);
        Ok(Self(Vec::from_raw_parts(
            vec.as_mut_ptr().cast(),
            vec.len(),
            vec.capacity(),
        )))
    }
}

impl<T: Transmute + Ir<Type = Transparent<T>>, const N: usize> CType
    for IrArray<T, Transparent<T>, N>
where
    [T::Target; N]: FfiType,
{
    type ReprC = <[T::Target; N] as FfiType>::ReprC;
}
impl<'itm, T: Transmute + Ir<Type = Transparent<T>>, U: ReprC, const N: usize> CTypeConvert<'itm, U>
    for IrArray<T, Transparent<T>, N>
where
    [T::Target; N]: FfiConvert<'itm, U>,
{
    type RustStore = <[T::Target; N] as FfiConvert<'itm, U>>::RustStore;
    type FfiStore = <[T::Target; N] as FfiConvert<'itm, U>>::FfiStore;

    fn into_repr_c(self, store: &'itm mut Self::RustStore) -> U {
        #[repr(C)]
        union TransmuteHelper<T: Transmute, const N: usize> {
            source: ManuallyDrop<[T; N]>,
            target: ManuallyDrop<[T::Target; N]>,
        }

        let transmute_helper = TransmuteHelper {
            source: ManuallyDrop::new(self.0),
        };

        // SAFETY: [T; N] is transmutable into [U; N] if T is transmutable into U
        ManuallyDrop::into_inner(unsafe { transmute_helper.target }).into_ffi(store)
    }

    unsafe fn try_from_repr_c(source: U, store: &'itm mut Self::FfiStore) -> Result<Self> {
        #[repr(C)]
        union TransmuteHelper<T: Transmute, const N: usize> {
            source: ManuallyDrop<[T::Target; N]>,
            target: ManuallyDrop<[T; N]>,
        }

        let array = <[T::Target; N]>::try_from_ffi(source, store)?;
        if !array.iter().all(|item| T::is_valid(item)) {
            return Err(FfiReturn::TrapRepresentation);
        }

        let transmute_helper = TransmuteHelper {
            source: ManuallyDrop::new(array),
        };

        Ok(Self(ManuallyDrop::into_inner(transmute_helper.target)))
    }
}

impl<T: Transmute> COutPtr for Transparent<T>
where
    T::Target: FfiOutPtr,
{
    type OutPtr = <T::Target as FfiOutPtr>::OutPtr;
}
impl<T: Transmute + Ir<Type = Transparent<T>>> COutPtr for IrBox<T, Transparent<T>>
where
    Box<T::Target>: FfiOutPtr,
{
    type OutPtr = <Box<T::Target> as FfiOutPtr>::OutPtr;
}
impl<'itm, T: Transmute + Ir<Type = Transparent<T>>> COutPtr for IrSlice<'itm, T, Transparent<T>>
where
    &'itm [T::Target]: FfiOutPtr,
{
    type OutPtr = <&'itm [T::Target] as FfiOutPtr>::OutPtr;
}
impl<'itm, T: Transmute + Ir<Type = Transparent<T>>> COutPtr for IrSliceMut<'itm, T, Transparent<T>>
where
    &'itm mut [T::Target]: FfiOutPtr,
{
    type OutPtr = <&'itm mut [T::Target] as FfiOutPtr>::OutPtr;
}
impl<T: Transmute + Ir<Type = Transparent<T>>> COutPtr for IrVec<T, Transparent<T>>
where
    Vec<T::Target>: FfiOutPtr,
{
    type OutPtr = <Vec<T::Target> as FfiOutPtr>::OutPtr;
}
impl<T: Transmute + Ir<Type = Transparent<T>>, const N: usize> COutPtr
    for IrArray<T, Transparent<T>, N>
where
    [T::Target; N]: FfiOutPtr,
{
    type OutPtr = <[T::Target; N] as FfiOutPtr>::OutPtr;
}

unsafe impl<T: Transmute + Ir> NonLocal for Transparent<T>
where
    T::Target: Ir,
    <T::Target as Ir>::Type: NonLocal,
{
}
unsafe impl<T: Transmute + Ir<Type = Transparent<T>>> NonLocal for IrBox<T, Transparent<T>>
where
    Box<T::Target>: Ir,
    <Box<T::Target> as Ir>::Type: NonLocal,
{
}
unsafe impl<'itm, T: Transmute + Ir<Type = Transparent<T>>> NonLocal
    for IrSlice<'itm, T, Transparent<T>>
where
    &'itm [T::Target]: Ir,
    <&'itm [T::Target] as Ir>::Type: NonLocal,
{
}
unsafe impl<'itm, T: Transmute + Ir<Type = Transparent<T>>> NonLocal
    for IrSliceMut<'itm, T, Transparent<T>>
where
    &'itm mut [T::Target]: Ir,
    <&'itm mut [T::Target] as Ir>::Type: NonLocal,
{
}
unsafe impl<T: Transmute + Ir<Type = Transparent<T>>> NonLocal for IrVec<T, Transparent<T>>
where
    Vec<T::Target>: Ir,
    <Vec<T::Target> as Ir>::Type: NonLocal,
{
}
unsafe impl<T: Transmute + Ir<Type = Transparent<T>>, const N: usize> NonLocal
    for IrArray<T, Transparent<T>, N>
where
    [T::Target; N]: Ir,
    <[T::Target; N] as Ir>::Type: NonLocal,
{
}
