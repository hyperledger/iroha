#![allow(trivial_casts, clippy::undocumented_unsafe_blocks)]

//! Logic related to the conversion of IR types to equivalent robust C types. Most of the
//! types that implement [`Ir`], i.e. provide conversion into IR, will get an automatic
//! implementation of [`CType`] and consequently an implementation of [`FfiType`]

use alloc::{boxed::Box, vec::Vec};
use core::{hint::unreachable_unchecked, mem::ManuallyDrop};

use crate::{
    ir::{Ir, Opaque, Robust, Transmute, Transparent},
    slice::{OutBoxedSlice, SliceMut, SliceRef},
    FfiConvert, FfiOutPtr, FfiReturn, FfiType, OutPtrOf, ReprC, Result,
};

/// A type that can be converted into some C type. When implemented on [`Ir::Type`] the blanket
/// implementations ensures that [`FfiType`] is also implemented on the type implementing [`Ir`].
/// This trait mainly exists to move types of internal representation into C type equivalents.
pub trait CType<S> {
    /// C type current type can be converted into
    type ReprC: ReprC;
}

/// Conversion utility [`CType`]s. When implemented on [`Ir::Type`] the blanket implementation
/// ensures that [`FfiType`] is also implemented on the type implementing [`Ir`]. This trait
/// mainly exists to move types of internal representation into C type equivalents. When
/// implementing make sure that the implementation doesn't conflict with [`NonLocal`]
pub trait CTypeConvert<'itm, S, C>: Sized {
    /// Type into which state can be stored during conversion from [`Self`]. Useful for
    /// returning owning heap allocated types or non-owning types that are not transmutable.
    /// Serves similar purpose as does context in a closure
    type RustStore: Default;

    /// Type into which state can be stored during conversion into [`Self`]. Useful for
    /// returning non-owning types that are not transmutable. Serves similar purpose as
    /// does context in a closure
    type FfiStore: Default;

    /// Perform the conversion from [`Self`] into `[Self::ReprC]`
    fn into_repr_c(self, store: &'itm mut Self::RustStore) -> C;

    /// Perform the conversion from [`Self::ReprC`] into `[Self]`
    ///
    /// # Errors
    ///
    /// Check [`FfiReturn`]
    ///
    /// # Safety
    ///
    /// All conversions from a pointer must ensure pointer validity beforehand
    unsafe fn try_from_repr_c(source: C, store: &'itm mut Self::FfiStore) -> Result<Self>;
}

/// Provides the capability to use the type as an out-pointer.
/// This trait mainly exists to be implemented on IR types.
pub trait COutPtr<S>: CType<S> {
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
pub unsafe trait NonLocal<S>: COutPtr<S> {}

/// Type that cannot be transmuted into a [`ReprC`] type
pub trait NonTransmute {}

impl<R: Ir> NonTransmute for &R where R::Type: NonTransmute {}
impl<R> NonTransmute for Box<R> {}
impl<R> NonTransmute for &[R] {}
impl<R> NonTransmute for Vec<R> {}
impl<R: Ir, const N: usize> NonTransmute for [R; N] where R::Type: NonTransmute {}

// NOTE: `CType` cannot be implemented for `&mut T`
impl<R: Ir<Type = S> + CType<S>, S: NonTransmute> CType<&S> for &R {
    type ReprC = *const <R as CType<R::Type>>::ReprC;
}
impl<'itm, R: Ir<Type = S> + CTypeConvert<'itm, S, C> + Clone, S: NonTransmute, C: ReprC>
    CTypeConvert<'itm, &S, *const C> for &'itm R
{
    type RustStore = (Option<C>, <R as CTypeConvert<'itm, R::Type, C>>::RustStore);
    type FfiStore = (Option<R>, <R as CTypeConvert<'itm, R::Type, C>>::FfiStore);

    fn into_repr_c(self, store: &'itm mut Self::RustStore) -> *const C {
        store.0.insert(self.clone().into_repr_c(&mut store.1))
    }

    unsafe fn try_from_repr_c(source: *const C, store: &'itm mut Self::FfiStore) -> Result<Self> {
        if source.as_ref().is_none() {
            return Err(FfiReturn::ArgIsNull);
        }

        Ok(store.0.insert(
            <R as CTypeConvert<_, _>>::try_from_repr_c(source.read(), &mut store.1)
                .map(ManuallyDrop::new)
                .map(|item| (*item).clone())?,
        ))
    }
}

impl<R: Ir<Type = S> + CType<S>, S: NonTransmute> CType<Box<S>> for Box<R> {
    type ReprC = *mut R::ReprC;
}
impl<'itm, R: Ir<Type = S> + CTypeConvert<'itm, S, C> + Clone, S: NonTransmute, C: ReprC>
    CTypeConvert<'itm, Box<S>, *mut C> for Box<R>
{
    type RustStore = (Option<C>, R::RustStore);
    type FfiStore = R::FfiStore;

    fn into_repr_c(self, store: &'itm mut Self::RustStore) -> *mut C {
        store.0.insert((*self).into_repr_c(&mut store.1))
    }
    unsafe fn try_from_repr_c(source: *mut C, store: &'itm mut Self::FfiStore) -> Result<Self> {
        if source.as_mut().is_none() {
            return Err(FfiReturn::ArgIsNull);
        }

        R::try_from_repr_c(source.read(), store)
            .map(ManuallyDrop::new)
            .map(|item| (*item).clone())
            .map(Box::new)
    }
}

// NOTE: `CType` cannot be implemented for `&mut [T]`
impl<R: Ir<Type = S> + CType<S>, S: NonTransmute> CType<&[S]> for &[R] {
    type ReprC = SliceRef<R::ReprC>;
}
impl<'slice, R: Ir<Type = S> + CTypeConvert<'slice, S, C> + Clone, S: NonTransmute, C: ReprC>
    CTypeConvert<'slice, &[S], SliceRef<C>> for &'slice [R]
{
    type RustStore = (Vec<C>, Vec<R::RustStore>);
    type FfiStore = (Vec<R>, Vec<R::FfiStore>);

    fn into_repr_c(self, store: &'slice mut Self::RustStore) -> SliceRef<C> {
        let slice = self.to_vec();

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
        source: SliceRef<C>,
        store: &'slice mut Self::FfiStore,
    ) -> Result<Self> {
        store.1 = core::iter::repeat_with(Default::default)
            .take(source.len())
            .collect();

        let source: Vec<ManuallyDrop<R>> = source
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
            .collect();

        Ok(&store.0)
    }
}

impl<R: Ir<Type = S> + CType<S>, S: NonTransmute> CType<Vec<S>> for Vec<R> {
    type ReprC = SliceMut<R::ReprC>;
}
impl<'itm, R: Ir<Type = S> + CTypeConvert<'itm, S, C> + Clone, S: NonTransmute, C: ReprC>
    CTypeConvert<'itm, Vec<S>, SliceMut<C>> for Vec<R>
{
    type RustStore = (Vec<C>, Vec<R::RustStore>);
    type FfiStore = Vec<R::FfiStore>;

    fn into_repr_c(self, store: &'itm mut Self::RustStore) -> SliceMut<C> {
        let vec = self;

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
        source: SliceMut<C>,
        store: &'itm mut Self::FfiStore,
    ) -> Result<Self> {
        let slice = source.into_rust().ok_or(FfiReturn::ArgIsNull)?;

        *store = core::iter::repeat_with(Default::default)
            .take(slice.len())
            .collect();

        let vec: Vec<ManuallyDrop<R>> = slice
            .iter()
            .copied()
            .zip(store)
            .map(|(item, substore)| {
                CTypeConvert::try_from_repr_c(item, substore).map(ManuallyDrop::new)
            })
            .collect::<core::result::Result<_, _>>()?;

        Ok(vec
            .iter()
            .cloned()
            .map(ManuallyDrop::into_inner)
            .collect::<Vec<_>>())
    }
}

impl<R: Ir<Type = S> + CType<S>, S: NonTransmute, const N: usize> CType<[S; N]> for [R; N] {
    type ReprC = [R::ReprC; N];
}
impl<
        'itm,
        R: Ir<Type = S> + CTypeConvert<'itm, S, C> + Clone,
        S: NonTransmute,
        C: ReprC,
        const N: usize,
    > CTypeConvert<'itm, [S; N], [C; N]> for [R; N]
where
    [R::RustStore; N]: Default,
    [R::FfiStore; N]: Default,
{
    type RustStore = [R::RustStore; N];
    type FfiStore = [R::FfiStore; N];

    fn into_repr_c(self, store: &'itm mut Self::RustStore) -> [C; N] {
        let array: [R; N] = if let Ok(arr) = self.into_iter().collect::<Vec<_>>().try_into() {
            arr
        } else {
            // SAFETY: Vec<T> length is N
            unsafe { unreachable_unchecked() }
        };
        *store = if let Ok(arr) = TryFrom::try_from(
            core::iter::repeat_with(Default::default)
                .take(array.len())
                .collect::<Vec<R::RustStore>>(),
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
    unsafe fn try_from_repr_c(source: [C; N], store: &'itm mut Self::FfiStore) -> Result<Self> {
        let array: [ManuallyDrop<R>; N] = if let Ok(arr) = source
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

        Ok(
            if let Ok(arr) = array
                .iter()
                .cloned()
                .map(ManuallyDrop::into_inner)
                .collect::<Vec<_>>()
                .try_into()
            {
                arr
            } else {
                unreachable_unchecked()
            },
        )
    }
}
impl<
        'itm,
        R: Ir<Type = S> + CTypeConvert<'itm, S, C> + Clone,
        S: NonTransmute,
        C: ReprC,
        const N: usize,
    > CTypeConvert<'itm, [S; N], *mut C> for [R; N]
where
    [R::RustStore; N]: Default,
    [R::FfiStore; N]: Default,
    [C; N]: Default,
{
    type RustStore = ([C; N], [R::RustStore; N]);
    type FfiStore = [R::FfiStore; N];

    fn into_repr_c(self, store: &'itm mut Self::RustStore) -> *mut C {
        store.0 = self.into_repr_c(&mut store.1);
        store.0.as_mut_ptr()
    }
    unsafe fn try_from_repr_c(source: *mut C, store: &'itm mut Self::FfiStore) -> Result<Self> {
        CTypeConvert::try_from_repr_c(source.cast::<[C; N]>().read(), store)
    }
}

impl<R: Ir<Type = S> + NonLocal<S>, S: NonTransmute> COutPtr<&S> for &R {
    type OutPtr = *mut Self::ReprC;
}
impl<R: Ir<Type = S> + NonLocal<S>, S: NonTransmute> COutPtr<&[S]> for &[R] {
    type OutPtr = OutBoxedSlice<R::ReprC>;
}
impl<R: Ir<Type = S> + NonLocal<S>, S: NonTransmute> COutPtr<Box<S>> for Box<R> {
    type OutPtr = *mut R::ReprC;
}
impl<R: Ir<Type = S> + NonLocal<S>, S: NonTransmute> COutPtr<Vec<S>> for Vec<R> {
    type OutPtr = OutBoxedSlice<R::ReprC>;
}
impl<R: Ir<Type = S> + NonLocal<S>, S: NonTransmute, const N: usize> COutPtr<[S; N]> for [R; N] {
    type OutPtr = *mut R::ReprC;
}

/* ---------------------------------------Robust-------------------------------------- */

impl<R: ReprC + Ir<Type = Robust>> CType<Robust> for R {
    type ReprC = R;
}
impl<R: ReprC + Ir<Type = Robust>> CTypeConvert<'_, Robust, R> for R {
    type RustStore = ();
    type FfiStore = ();

    fn into_repr_c(self, _: &mut ()) -> R {
        self
    }

    unsafe fn try_from_repr_c(source: R, _: &mut ()) -> Result<Self> {
        Ok(source)
    }
}

impl<R: ReprC + Ir<Type = Robust>> CType<Box<Robust>> for Box<R> {
    type ReprC = *mut R;
}
impl<R: ReprC + Ir<Type = Robust> + Default> CTypeConvert<'_, Box<Robust>, *mut R> for Box<R> {
    type RustStore = Box<R>;
    type FfiStore = ();

    fn into_repr_c(self, store: &mut Self::RustStore) -> *mut R {
        *store = self;
        &mut **store
    }

    unsafe fn try_from_repr_c(source: *mut R, _: &mut ()) -> Result<Self> {
        if source.is_null() {
            return Err(FfiReturn::ArgIsNull);
        }

        Ok(Box::new(source.read()))
    }
}

impl<R: ReprC + Ir<Type = Robust>> CType<&[Robust]> for &[R] {
    type ReprC = SliceRef<R>;
}
impl<R: ReprC + Ir<Type = Robust>> CTypeConvert<'_, &[Robust], SliceRef<R>> for &[R] {
    type RustStore = ();
    type FfiStore = ();

    fn into_repr_c(self, _: &mut ()) -> SliceRef<R> {
        SliceRef::from_slice(self)
    }

    unsafe fn try_from_repr_c(source: SliceRef<R>, _: &mut ()) -> Result<Self> {
        source.into_rust().ok_or(FfiReturn::ArgIsNull)
    }
}

impl<R: ReprC + Ir<Type = Robust>> CType<&mut [Robust]> for &mut [R] {
    type ReprC = SliceMut<R>;
}
impl<R: ReprC + Ir<Type = Robust>> CTypeConvert<'_, &mut [Robust], SliceMut<R>> for &mut [R] {
    type RustStore = ();
    type FfiStore = ();

    fn into_repr_c(self, _: &mut ()) -> SliceMut<R> {
        SliceMut::from_slice(self)
    }

    unsafe fn try_from_repr_c(source: SliceMut<R>, _: &mut ()) -> Result<Self> {
        source.into_rust().ok_or(FfiReturn::ArgIsNull)
    }
}

impl<R: ReprC + Ir<Type = Robust>> CType<Vec<Robust>> for Vec<R> {
    type ReprC = SliceMut<R>;
}
impl<R: ReprC + Ir<Type = Robust>> CTypeConvert<'_, Vec<Robust>, SliceMut<R>> for Vec<R> {
    type RustStore = Vec<R>;
    type FfiStore = ();

    fn into_repr_c(self, store: &mut Self::RustStore) -> SliceMut<R> {
        *store = self;
        SliceMut::from_slice(store)
    }

    unsafe fn try_from_repr_c(source: SliceMut<R>, _: &mut ()) -> Result<Self> {
        source
            .into_rust()
            .ok_or(FfiReturn::ArgIsNull)
            .map(|slice| slice.to_vec())
    }
}

impl<R: ReprC + Ir<Type = Robust>, const N: usize> CType<[Robust; N]> for [R; N] {
    type ReprC = [R; N];
}
impl<R: ReprC + Ir<Type = Robust>, const N: usize> CTypeConvert<'_, [Robust; N], [R; N]>
    for [R; N]
{
    type RustStore = ();
    type FfiStore = ();

    fn into_repr_c(self, _: &mut ()) -> [R; N] {
        self
    }

    unsafe fn try_from_repr_c(source: [R; N], _: &mut ()) -> Result<Self> {
        Ok(source)
    }
}
impl<R: ReprC + Ir<Type = Robust>, const N: usize> CTypeConvert<'_, [Robust; N], *mut R> for [R; N]
where
    [R; N]: Default,
{
    type RustStore = [R; N];
    type FfiStore = ();

    fn into_repr_c(self, store: &mut Self::RustStore) -> *mut R {
        *store = self;
        store.as_mut_ptr()
    }

    unsafe fn try_from_repr_c(source: *mut R, _: &mut ()) -> Result<Self> {
        Ok(source.cast::<[R; N]>().read())
    }
}

impl<R: ReprC + Ir<Type = Robust>> COutPtr<Robust> for R {
    type OutPtr = *mut R;
}
impl<R: ReprC + Ir<Type = Robust>> COutPtr<Box<Robust>> for Box<R> {
    type OutPtr = *mut R;
}
impl<R: ReprC + Ir<Type = Robust>> COutPtr<&[Robust]> for &[R] {
    type OutPtr = *mut SliceRef<R>;
}
impl<R: ReprC + Ir<Type = Robust>> COutPtr<&mut [Robust]> for &mut [R] {
    type OutPtr = *mut SliceMut<R>;
}
impl<R: ReprC + Ir<Type = Robust>> COutPtr<Vec<Robust>> for Vec<R> {
    type OutPtr = OutBoxedSlice<R>;
}
impl<R: ReprC + Ir<Type = Robust>, const N: usize> COutPtr<[Robust; N]> for [R; N] {
    type OutPtr = *mut [R; N];
}

// SAFETY: Type doesn't use store during conversion
unsafe impl<R: ReprC + Ir<Type = Robust>> NonLocal<Robust> for R {}
// SAFETY: Type doesn't use store during conversion
unsafe impl<R: ReprC + Ir<Type = Robust>> NonLocal<&[Robust]> for &[R] {}
// SAFETY: Type doesn't use store during conversion
unsafe impl<R: ReprC + Ir<Type = Robust>> NonLocal<&mut [Robust]> for &mut [R] {}
// SAFETY: Type doesn't use store during conversion
unsafe impl<R: ReprC + Ir<Type = Robust>, const N: usize> NonLocal<[Robust; N]> for [R; N] {}

/* ---------------------------------------Opaque-------------------------------------- */

impl<R: Ir<Type = Opaque>> CType<Opaque> for R {
    type ReprC = *mut R;
}
impl<R: Ir<Type = Opaque>> CTypeConvert<'_, Opaque, *mut R> for R {
    type RustStore = ();
    type FfiStore = ();

    fn into_repr_c(self, _: &mut ()) -> *mut R {
        Box::into_raw(Box::new(self))
    }
    unsafe fn try_from_repr_c(source: *mut R, _: &mut ()) -> Result<Self> {
        if source.is_null() {
            return Err(FfiReturn::ArgIsNull);
        }

        Ok(*Box::from_raw(source))
    }
}

impl<R: Ir<Type = Opaque>> CType<Box<Opaque>> for Box<R> {
    type ReprC = *mut R;
}
impl<R: Ir<Type = Opaque>> CTypeConvert<'_, Box<Opaque>, *mut R> for Box<R> {
    type RustStore = ();
    type FfiStore = ();

    fn into_repr_c(self, _: &mut ()) -> *mut R {
        Box::into_raw(self)
    }

    unsafe fn try_from_repr_c(source: *mut R, _: &mut ()) -> Result<Self> {
        if source.is_null() {
            return Err(FfiReturn::ArgIsNull);
        }

        Ok(Box::from_raw(source))
    }
}

impl<R: Ir<Type = Opaque>> CType<&[Opaque]> for &[R] {
    type ReprC = SliceRef<*const R>;
}
impl<'slice, R: Ir<Type = Opaque> + Clone> CTypeConvert<'slice, &[Opaque], SliceRef<*const R>>
    for &'slice [R]
{
    type RustStore = Vec<*const R>;
    type FfiStore = Vec<R>;

    fn into_repr_c(self, store: &mut Self::RustStore) -> SliceRef<*const R> {
        *store = self.iter().map(|item| item as *const R).collect();
        SliceRef::from_slice(store)
    }

    unsafe fn try_from_repr_c(
        source: SliceRef<*const R>,
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

        Ok(store)
    }
}

impl<R: Ir<Type = Opaque>> CType<&mut [Opaque]> for &mut [R] {
    type ReprC = SliceMut<*mut R>;
}
impl<'slice, R: Ir<Type = Opaque> + Clone> CTypeConvert<'slice, &mut [Opaque], SliceMut<*mut R>>
    for &'slice mut [R]
{
    type RustStore = Vec<*mut R>;
    type FfiStore = Vec<R>;

    fn into_repr_c(self, store: &mut Self::RustStore) -> SliceMut<*mut R> {
        *store = self.iter_mut().map(|item| item as *mut R).collect();

        SliceMut::from_slice(store)
    }

    unsafe fn try_from_repr_c(
        source: SliceMut<*mut R>,
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

        Ok(store)
    }
}

impl<R: Ir<Type = Opaque>> CType<Vec<Opaque>> for Vec<R> {
    type ReprC = SliceMut<*mut R>;
}
impl<R: Ir<Type = Opaque>> CTypeConvert<'_, Vec<Opaque>, SliceMut<*mut R>> for Vec<R> {
    type RustStore = Vec<*mut R>;
    type FfiStore = ();

    fn into_repr_c(self, store: &mut Self::RustStore) -> SliceMut<*mut R> {
        *store = self.into_iter().map(Box::new).map(Box::into_raw).collect();

        SliceMut::from_slice(store)
    }

    unsafe fn try_from_repr_c(source: SliceMut<*mut R>, _: &mut ()) -> Result<Self> {
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
    }
}

impl<R: Ir<Type = Opaque>, const N: usize> CType<[Opaque; N]> for [R; N] {
    type ReprC = [*mut R; N];
}
impl<R: Ir<Type = Opaque>, const N: usize> CTypeConvert<'_, [Opaque; N], [*mut R; N]> for [R; N] {
    type RustStore = ();
    type FfiStore = ();

    fn into_repr_c(self, _: &mut Self::RustStore) -> [*mut R; N] {
        if let Ok(arr) = self
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

    unsafe fn try_from_repr_c(source: [*mut R; N], _: &mut ()) -> Result<Self> {
        Ok(
            if let Ok(arr) = source
                .into_iter()
                .map(|item| {
                    if let Some(item) = item.as_mut() {
                        return Ok(*Box::from_raw(item));
                    }

                    Err(FfiReturn::ArgIsNull)
                })
                .collect::<core::result::Result<Vec<R>, _>>()?
                .try_into()
            {
                arr
            } else {
                unreachable_unchecked()
            },
        )
    }
}
impl<R: Ir<Type = Opaque>, const N: usize> CTypeConvert<'_, [Opaque; N], *mut *mut R> for [R; N]
where
    [*mut R; N]: Default,
{
    type RustStore = [*mut R; N];
    type FfiStore = ();

    fn into_repr_c(self, store: &mut Self::RustStore) -> *mut *mut R {
        *store = self.into_repr_c(&mut ());
        store.as_mut_ptr()
    }

    unsafe fn try_from_repr_c(source: *mut *mut R, _: &mut ()) -> Result<Self> {
        CTypeConvert::try_from_repr_c(source.cast::<[*mut R; N]>().read(), &mut ())
    }
}

impl<R: Ir<Type = Opaque>> COutPtr<Opaque> for R {
    type OutPtr = *mut *mut R;
}
impl<R: Ir<Type = Opaque>> COutPtr<Box<Opaque>> for Box<R> {
    type OutPtr = *mut *mut R;
}
impl<R: Ir<Type = Opaque>> COutPtr<&[Opaque]> for &[R] {
    type OutPtr = OutBoxedSlice<*const R>;
}
impl<R: Ir<Type = Opaque>> COutPtr<&mut [Opaque]> for &mut [R] {
    type OutPtr = OutBoxedSlice<*mut R>;
}
impl<R: Ir<Type = Opaque>> COutPtr<Vec<Opaque>> for Vec<R> {
    type OutPtr = OutBoxedSlice<*mut R>;
}
impl<R: Ir<Type = Opaque>, const N: usize> COutPtr<[Opaque; N]> for [R; N] {
    type OutPtr = *mut [*mut R; N];
}

// SAFETY: Type doesn't use store during conversion
unsafe impl<R: Ir<Type = Opaque>> NonLocal<Opaque> for R {}
// SAFETY: Type doesn't use store during conversion
unsafe impl<R: Ir<Type = Opaque>> NonLocal<Box<Opaque>> for Box<R> {}
// SAFETY: Type doesn't use store during conversion
unsafe impl<R: Ir<Type = Opaque>, const N: usize> NonLocal<[Opaque; N]> for [R; N] {}

/* ------------------------------------Transparent------------------------------------ */

impl<R: Transmute> CType<Transparent> for R
where
    R::Target: FfiType,
{
    type ReprC = <R::Target as FfiType>::ReprC;
}
impl<'itm, R: Transmute + Ir<Type = Transparent>, C: ReprC> CTypeConvert<'itm, Transparent, C> for R
where
    R::Target: FfiConvert<'itm, C>,
{
    type RustStore = <R::Target as FfiConvert<'itm, C>>::RustStore;
    type FfiStore = <R::Target as FfiConvert<'itm, C>>::FfiStore;

    fn into_repr_c(self, store: &'itm mut Self::RustStore) -> C {
        let transmute_helper = TransmuteHelper {
            source: ManuallyDrop::new(self),
        };

        // SAFETY: Transmute is always valid because R::Target is a superset of R
        ManuallyDrop::into_inner(unsafe { transmute_helper.target }).into_ffi(store)
    }

    unsafe fn try_from_repr_c(source: C, store: &'itm mut Self::FfiStore) -> Result<Self> {
        let source = FfiConvert::try_from_ffi(source, store)?;

        if !R::is_valid(&source) {
            return Err(FfiReturn::TrapRepresentation);
        }

        let transmute_helper = TransmuteHelper {
            target: ManuallyDrop::new(source),
        };
        Ok(ManuallyDrop::into_inner(transmute_helper.source))
    }
}

impl<R: Transmute + Ir<Type = Transparent>> CType<Box<Transparent>> for Box<R>
where
    Box<R::Target>: FfiType,
{
    type ReprC = <Box<R::Target> as FfiType>::ReprC;
}
impl<'itm, R: Transmute + Ir<Type = Transparent>, C: ReprC> CTypeConvert<'itm, Box<Transparent>, C>
    for Box<R>
where
    Box<R::Target>: FfiConvert<'itm, C>,
{
    type RustStore = <Box<R::Target> as FfiConvert<'itm, C>>::RustStore;
    type FfiStore = <Box<R::Target> as FfiConvert<'itm, C>>::FfiStore;

    fn into_repr_c(self, store: &'itm mut Self::RustStore) -> C {
        // SAFETY: `R` is guaranteed to be transmutable into `R::Target`
        unsafe { Box::from_raw(Box::into_raw(self).cast::<R::Target>()).into_ffi(store) }
    }

    unsafe fn try_from_repr_c(source: C, store: &'itm mut Self::FfiStore) -> Result<Self> {
        let item: Box<R::Target> = FfiConvert::try_from_ffi(source, store)?;

        if !R::is_valid(&item) {
            return Err(FfiReturn::TrapRepresentation);
        }

        Ok(Box::from_raw(Box::into_raw(item).cast::<R>()))
    }
}

impl<'slice, R: Transmute + Ir<Type = Transparent>> CType<&[Transparent]> for &'slice [R]
where
    &'slice [R::Target]: FfiType,
{
    type ReprC = <&'slice [R::Target] as FfiType>::ReprC;
}
impl<'slice, R: Transmute + Ir<Type = Transparent>, C: ReprC>
    CTypeConvert<'slice, &[Transparent], C> for &'slice [R]
where
    &'slice [R::Target]: FfiConvert<'slice, C>,
{
    type RustStore = <&'slice [R::Target] as FfiConvert<'slice, C>>::RustStore;
    type FfiStore = <&'slice [R::Target] as FfiConvert<'slice, C>>::FfiStore;

    fn into_repr_c(self, store: &'slice mut Self::RustStore) -> C {
        let slice = self;

        let (ptr, len) = (slice.as_ptr().cast::<R::Target>(), slice.len());
        // SAFETY: `R` is guaranteed to be transmutable into `R::Target`
        unsafe { core::slice::from_raw_parts(ptr, len).into_ffi(store) }
    }

    unsafe fn try_from_repr_c(source: C, store: &'slice mut Self::FfiStore) -> Result<Self> {
        let slice = <&[R::Target]>::try_from_ffi(source, store)?;

        if !slice.iter().all(|item| R::is_valid(item)) {
            return Err(FfiReturn::TrapRepresentation);
        }

        Ok(core::slice::from_raw_parts(
            slice.as_ptr().cast(),
            slice.len(),
        ))
    }
}

impl<'slice, R: Transmute + Ir<Type = Transparent>> CType<&mut [Transparent]> for &'slice mut [R]
where
    &'slice mut [R::Target]: FfiType,
{
    type ReprC = <&'slice mut [R::Target] as FfiType>::ReprC;
}
impl<'slice, R: Transmute + Ir<Type = Transparent>, C: ReprC>
    CTypeConvert<'slice, &mut [Transparent], C> for &'slice mut [R]
where
    &'slice mut [R::Target]: FfiConvert<'slice, C>,
{
    type RustStore = <&'slice mut [R::Target] as FfiConvert<'slice, C>>::RustStore;
    type FfiStore = <&'slice mut [R::Target] as FfiConvert<'slice, C>>::FfiStore;

    fn into_repr_c(self, store: &'slice mut Self::RustStore) -> C {
        let slice = self;

        let (ptr, len) = (slice.as_mut_ptr().cast::<R::Target>(), slice.len());
        // SAFETY: `R` is guaranteed to be transmutable into `R::Target`
        unsafe { core::slice::from_raw_parts_mut(ptr, len).into_ffi(store) }
    }

    unsafe fn try_from_repr_c(source: C, store: &'slice mut Self::FfiStore) -> Result<Self> {
        let slice = <&mut [R::Target]>::try_from_ffi(source, store)?;

        if !slice.iter().all(|item| R::is_valid(item)) {
            return Err(FfiReturn::TrapRepresentation);
        }

        Ok(core::slice::from_raw_parts_mut(
            slice.as_mut_ptr().cast(),
            slice.len(),
        ))
    }
}

impl<R: Transmute + Ir<Type = Transparent>> CType<Vec<Transparent>> for Vec<R>
where
    Vec<R::Target>: FfiType,
{
    type ReprC = <Vec<R::Target> as FfiType>::ReprC;
}
impl<'itm, R: Transmute + Ir<Type = Transparent>, C: ReprC> CTypeConvert<'itm, Vec<Transparent>, C>
    for Vec<R>
where
    Vec<R::Target>: FfiConvert<'itm, C>,
{
    type RustStore = <Vec<R::Target> as FfiConvert<'itm, C>>::RustStore;
    type FfiStore = <Vec<R::Target> as FfiConvert<'itm, C>>::FfiStore;

    fn into_repr_c(self, store: &'itm mut Self::RustStore) -> C {
        let mut vec = ManuallyDrop::new(self);

        let vec: Vec<R::Target> =
            // SAFETY: `Transparency` guarantees `T` can be transmuted into `C`
            unsafe { Vec::from_raw_parts(vec.as_mut_ptr().cast(), vec.len(), vec.capacity()) };

        vec.into_ffi(store)
    }

    unsafe fn try_from_repr_c(source: C, store: &'itm mut Self::FfiStore) -> Result<Self> {
        let vec = <Vec<R::Target>>::try_from_ffi(source, store)?;

        if !vec.iter().all(|item| R::is_valid(item)) {
            return Err(FfiReturn::TrapRepresentation);
        }

        let mut vec = ManuallyDrop::new(vec);
        Ok(Vec::from_raw_parts(
            vec.as_mut_ptr().cast(),
            vec.len(),
            vec.capacity(),
        ))
    }
}

impl<R: Transmute + Ir<Type = Transparent>, const N: usize> CType<[Transparent; N]> for [R; N]
where
    [R::Target; N]: FfiType,
{
    type ReprC = <[R::Target; N] as FfiType>::ReprC;
}
impl<'itm, R: Transmute + Ir<Type = Transparent>, C: ReprC, const N: usize>
    CTypeConvert<'itm, [Transparent; N], C> for [R; N]
where
    [R::Target; N]: FfiConvert<'itm, C>,
{
    type RustStore = <[R::Target; N] as FfiConvert<'itm, C>>::RustStore;
    type FfiStore = <[R::Target; N] as FfiConvert<'itm, C>>::FfiStore;

    fn into_repr_c(self, store: &'itm mut Self::RustStore) -> C {
        let transmute_helper = TransmuteHelper {
            source: ManuallyDrop::new(self),
        };

        // SAFETY: Transmute is always valid because R::Target is a superset of R
        ManuallyDrop::into_inner(unsafe { transmute_helper.target }).into_ffi(store)
    }

    unsafe fn try_from_repr_c(source: C, store: &'itm mut Self::FfiStore) -> Result<Self> {
        let source = <[R::Target; N]>::try_from_ffi(source, store)?;

        if !<[R; N]>::is_valid(&source) {
            return Err(FfiReturn::TrapRepresentation);
        }

        let transmute_helper = TransmuteHelper {
            target: ManuallyDrop::new(source),
        };
        Ok(ManuallyDrop::into_inner(transmute_helper.source))
    }
}

impl<R: Transmute + Ir<Type = Transparent>> COutPtr<Transparent> for R
where
    R::Target: FfiOutPtr,
{
    type OutPtr = <R::Target as FfiOutPtr>::OutPtr;
}
impl<R: Transmute + Ir<Type = Transparent>> COutPtr<Box<Transparent>> for Box<R>
where
    Box<R::Target>: FfiOutPtr,
{
    type OutPtr = <Box<R::Target> as FfiOutPtr>::OutPtr;
}
impl<'slice, R: Transmute + Ir<Type = Transparent>> COutPtr<&[Transparent]> for &'slice [R]
where
    &'slice [R::Target]: FfiOutPtr,
{
    type OutPtr = <&'slice [R::Target] as FfiOutPtr>::OutPtr;
}
impl<'slice, R: Transmute + Ir<Type = Transparent>> COutPtr<&mut [Transparent]>
    for &'slice mut [R]
where
    &'slice mut [R::Target]: FfiOutPtr,
{
    type OutPtr = <&'slice mut [R::Target] as FfiOutPtr>::OutPtr;
}
impl<R: Transmute + Ir<Type = Transparent>> COutPtr<Vec<Transparent>> for Vec<R>
where
    Vec<R::Target>: FfiOutPtr,
{
    type OutPtr = <Vec<R::Target> as FfiOutPtr>::OutPtr;
}
impl<R: Transmute + Ir<Type = Transparent>, const N: usize> COutPtr<[Transparent; N]> for [R; N]
where
    [R::Target; N]: FfiOutPtr,
{
    type OutPtr = <[R::Target; N] as FfiOutPtr>::OutPtr;
}

unsafe impl<R: Transmute + Ir<Type = Transparent>> NonLocal<Transparent> for R where
    R::Target: Ir + NonLocal<<R::Target as Ir>::Type>
{
}
unsafe impl<R: Transmute + Ir<Type = Transparent>> NonLocal<Box<Transparent>> for Box<R> where
    Box<R::Target>: Ir + FfiOutPtr + NonLocal<<Box<R::Target> as Ir>::Type>
{
}
unsafe impl<'slice, R: Transmute + Ir<Type = Transparent>> NonLocal<&[Transparent]>
    for &'slice [R]
where
    &'slice [R::Target]: Ir + FfiOutPtr + NonLocal<<&'slice [R::Target] as Ir>::Type>,
{
}
unsafe impl<'slice, R: Transmute + Ir<Type = Transparent>> NonLocal<&mut [Transparent]>
    for &'slice mut [R]
where
    &'slice mut [R::Target]: Ir + FfiOutPtr + NonLocal<<&'slice mut [R::Target] as Ir>::Type>,
{
}
unsafe impl<R: Transmute + Ir<Type = Transparent>> NonLocal<Vec<Transparent>> for Vec<R> where
    Vec<R::Target>: Ir + FfiOutPtr + NonLocal<<Vec<R::Target> as Ir>::Type>
{
}
unsafe impl<R: Transmute + Ir<Type = Transparent>, const N: usize> NonLocal<[Transparent; N]>
    for [R; N]
where
    [R::Target; N]: Ir + FfiOutPtr + NonLocal<<[R::Target; N] as Ir>::Type>,
{
}

#[repr(C)]
// NOTE: Use this struct carefully
union TransmuteHelper<R: Transmute> {
    source: ManuallyDrop<R>,
    target: ManuallyDrop<R::Target>,
}
