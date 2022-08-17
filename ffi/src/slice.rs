//! Logic related to the conversion of slices to and from FFI-compatible representation

use core::mem::MaybeUninit;

use crate::{Local, FfiReturn, FfiType, IntoFfi, NonLocal, OutPtrOf, ReprC, Result, TryFromReprC, Output};

/// Indicates that the shared slice of a given type can be converted into an FFI compatible representation
pub trait FfiSliceRef: Sized
where
    SliceRef<Self::ReprC>: ReprC,
{
    /// Corresponding FFI-compatible type
    type ReprC;
}

/// Indicates that the mutable slice of a given type can be converted into an FFI compatible representation
pub trait FfiSliceMut: Sized
where
    SliceMut<Self::ReprC>: ReprC,
{
    /// Corresponding FFI-compatible type
    type ReprC;
}

/// Trait that facilitates the implementation of [`TryFromReprC`] for immutable slices of foreign types
pub trait TryFromReprCSliceRef<'slice>: FfiSliceRef
where
    SliceRef<Self::ReprC>: ReprC,
{
    /// Type into which state can be stored during conversion. Useful for returning
    /// non-owning types but performing some conversion which requires allocation.
    /// Serves similar purpose as does context in a closure
    type Store: Default;

    /// Convert from [`Self::ReprC`] into `&[Self]`
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
        source: SliceRef<Self::ReprC>,
        store: &'slice mut Self::Store,
    ) -> Result<&'slice [Self]>;
}

/// Trait that facilitates the implementation of [`TryFromReprC`] for mutable slices of foreign types
pub trait TryFromReprCSliceMut<'slice>: FfiSliceMut
where
    SliceMut<Self::ReprC>: ReprC,
{
    /// Type into which state can be stored during conversion. Useful for returning
    /// non-owning types but performing some conversion which requires allocation.
    /// Serves similar purpose as does context in a closure
    type Store: Default;

    /// Perform the conversion from [`Self::ReprC`] into `&mut [Self]`
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
        source: SliceMut<Self::ReprC>,
        store: &'slice mut Self::Store,
    ) -> Result<&'slice mut [Self]>;
}

/// Trait that facilitates the implementation of [`IntoFfi`] for immutable slices of foreign types
pub trait IntoFfiSliceRef: FfiSliceRef
where
    SliceRef<Self::ReprC>: ReprC,
{
    /// Immutable slice equivalent of [`IntoFfi::Store`]
    type Store: Default;

    /// Convert from `&[Self]` into [`Self::Target`]
    fn into_ffi(source: &[Self], store: &mut Self::Store) -> SliceRef<Self::ReprC>;
}

/// Trait that facilitates the implementation of [`IntoFfi`] for mutable slices of foreign types
///
/// # Safety
///
/// `[Self]` and `[Self::Target]` must have the same representation, i.e. must be transmutable.
/// This is because it's not possible to mutably reference local context across FFI boundary
/// Additionally, if implemented on a non-robust type the invariant that trap representations
/// will never be written into values of `Self` by foreign code must be upheld at all times
pub unsafe trait IntoFfiSliceMut: FfiSliceMut
where
    SliceMut<Self::ReprC>: ReprC,
{
    /// Immutable slice equivalent of [`IntoFfi::Store`]
    type Store: Default;

    /// Convert from `&mut [Self]` into [`Self::Target`]
    fn into_ffi(source: &mut [Self], store: &mut Self::Store) -> SliceMut<Self::ReprC>;
}

/// Immutable slice with a defined C ABI layout. Consists of data pointer and length
#[repr(C)]
pub struct SliceRef<T>(*const T, usize);

/// Mutable slice with a defined C ABI layout. Consists of data pointer and length
#[repr(C)]
pub struct SliceMut<T>(*mut T, usize);

/// Immutable slice with a defined C ABI layout when used as a function return argument. Provides
/// a pointer where data pointer should be stored, and a pointer where length should be stored.
#[repr(C)]
pub struct OutSliceRef<T>(*mut *const T, *mut usize);

/// Mutable slice with a defined C ABI layout when used as a function return argument. Provides
/// a pointer where data pointer should be stored, and a pointer where length should be stored.
#[repr(C)]
pub struct OutSliceMut<T>(*mut *mut T, *mut usize);

/// Owned slice with a defined C ABI layout when used as a function return argument. Provides
/// a pointer to the allocation where the data should be copied into, length of the allocation,
/// and a pointer where total length of the data should be stored in the case that the provided
/// allocation is not large enough to store all the data
///
/// Returned length is [`isize`] to be able to support `None` values when converting types such as [`Option<T>`]
#[repr(C)]
#[derive(Clone, Copy)]
pub struct OutBoxedSlice<T>(*mut T, usize, *mut isize);

impl<T> Copy for SliceRef<T> {}
impl<T> Clone for SliceRef<T> {
    fn clone(&self) -> Self {
        Self(self.0, self.1)
    }
}
impl<T> Copy for SliceMut<T> {}
impl<T> Clone for SliceMut<T> {
    fn clone(&self) -> Self {
        Self(self.0, self.1)
    }
}
impl<T> Copy for OutSliceRef<T> {}
impl<T> Clone for OutSliceRef<T> {
    fn clone(&self) -> Self {
        Self(self.0, self.1)
    }
}
impl<T> Copy for OutSliceMut<T> {}
impl<T> Clone for OutSliceMut<T> {
    fn clone(&self) -> Self {
        Self(self.0, self.1)
    }
}

impl<'slice, T> SliceRef<T> {
    /// Forms a slice from a data pointer and a length.
    pub fn from_raw_parts(ptr: *const T, len: usize) -> Self {
        Self(ptr, len)
    }

    /// Create [`Self`] from shared slice
    pub const fn from_slice(slice: &[T]) -> Self {
        Self(slice.as_ptr(), slice.len())
    }

    /// Convert [`Self`] into a shared slice. Return `None` if data pointer is null
    ///
    /// # Safety
    ///
    /// Data pointer must point to a valid memory
    pub unsafe fn into_rust(self) -> Option<&'slice [T]> {
        if self.is_null() {
            return None;
        }

        Some(core::slice::from_raw_parts(self.0, self.1))
    }

    pub(crate) fn null() -> Self {
        // TODO: len could be uninitialized
        Self(core::ptr::null(), 0)
    }

    pub(crate) fn is_null(&self) -> bool {
        self.0.is_null()
    }
}
impl<'slice, T> SliceMut<T> {
    /// Create [`Self`] from mutable slice
    pub fn from_slice(slice: &mut [T]) -> Self {
        Self(slice.as_mut_ptr(), slice.len())
    }

    /// Convert [`Self`] into a mutable slice. Return `None` if data pointer is null
    ///
    /// # Safety
    ///
    /// Data pointer must point to a valid memory
    pub unsafe fn into_rust(self) -> Option<&'slice mut [T]> {
        if self.is_null() {
            return None;
        }

        Some(core::slice::from_raw_parts_mut(self.0, self.1))
    }

    pub(crate) fn null() -> Self {
        // TODO: len could be uninitialized
        Self(core::ptr::null_mut(), 0)
    }

    pub(crate) fn is_null(&self) -> bool {
        self.0.is_null()
    }
}

impl<T> OutSliceRef<T> {
    /// Construct `Self` from a slice of uninitialized elements
    pub fn from_raw(mut data_ptr: Option<&mut *const T>, len_ptr: &mut MaybeUninit<usize>) -> Self {
        Self(
            data_ptr
                .take()
                .map_or_else(core::ptr::null_mut, |item| <*mut _>::from(item)),
            len_ptr.as_mut_ptr(),
        )
    }
    pub(crate) unsafe fn write_none(self) {
        self.0.write(core::ptr::null());
    }
}
impl<T> OutSliceMut<T> {
    /// Construct `Self` from a slice of uninitialized elements
    pub fn from_raw(mut data_ptr: Option<&mut *mut T>, len_ptr: &mut MaybeUninit<usize>) -> Self {
        Self(
            data_ptr
                .take()
                .map_or_else(core::ptr::null_mut, |item| <*mut _>::from(item)),
            len_ptr.as_mut_ptr(),
        )
    }
    pub(crate) unsafe fn write_none(self) {
        self.0.write(core::ptr::null_mut());
    }
}
impl<T> OutBoxedSlice<T> {
    const NONE: isize = -1;

    /// Construct `Self` from a slice of uninitialized elements
    pub fn from_uninit_slice(
        mut data_ptr: Option<&mut [MaybeUninit<T>]>,
        len_ptr: &mut MaybeUninit<isize>,
    ) -> Self {
        let len = data_ptr.as_ref().map_or(0, |slice| slice.len());

        Self(
            data_ptr
                .take()
                .map_or_else(core::ptr::null_mut, |item| <[_]>::as_mut_ptr(item).cast()),
            len,
            len_ptr.as_mut_ptr(),
        )
    }

    pub(crate) unsafe fn write_none(self) {
        self.2.write(Self::NONE);
    }
}

unsafe impl<T> ReprC for SliceRef<T> where *const T: ReprC {}
unsafe impl<T> ReprC for SliceMut<T> where *mut T: ReprC {}
unsafe impl<T> ReprC for OutSliceRef<T> where *const T: ReprC {}
unsafe impl<T> ReprC for OutSliceMut<T> where *mut T: ReprC {}
unsafe impl<T> ReprC for OutBoxedSlice<T> where T: ReprC {}

unsafe impl<T> NonLocal for SliceRef<T> where *const T: NonLocal {}
unsafe impl<T> NonLocal for SliceMut<T> where *mut T: NonLocal {}

impl<T> Output for SliceRef<T> where *const T: NonLocal {
    type OutPtr = OutSliceRef<T>;
}
impl<T> Output for SliceMut<T> where *mut T: NonLocal {
    type OutPtr = OutSliceMut<T>;
}
impl<T: ReprC + NonLocal> Output for Local<SliceRef<T>> {
    type OutPtr = OutBoxedSlice<T>;
}

impl<T: FfiSliceRef> FfiType for &[T]
where
    SliceRef<T::ReprC>: ReprC,
{
    type ReprC = SliceRef<T::ReprC>;
}
impl<T: FfiSliceMut> FfiType for &mut [T]
where
    SliceMut<T::ReprC>: ReprC,
{
    type ReprC = SliceMut<T::ReprC>;
}

// TODO: Why is `ReprC` bound required here?
impl<T: ReprC + FfiType<ReprC = Self>> FfiSliceRef for T
where
    SliceRef<T::ReprC>: ReprC,
{
    type ReprC = Self;
}
impl<T: FfiType<ReprC = Self>> FfiSliceMut for T
where
    SliceMut<T::ReprC>: ReprC,
{
    type ReprC = Self;
}

impl<T: FfiSliceRef> FfiSliceRef for &[T]
where
    SliceRef<T::ReprC>: ReprC,
{
    type ReprC = SliceRef<T::ReprC>;
}
impl<T: FfiSliceRef> FfiSliceRef for &mut [T]
where
    SliceRef<T::ReprC>: ReprC,
{
    type ReprC = SliceRef<T::ReprC>;
}
impl<T: FfiSliceMut> FfiSliceMut for &mut [T]
where
    SliceMut<T::ReprC>: ReprC,
{
    type ReprC = SliceMut<T::ReprC>;
}

impl<T> OutPtrOf<SliceRef<T>> for OutSliceRef<T>
where
    *const T: ReprC + NonLocal,
{
    unsafe fn write(self, source: SliceRef<T>) -> Result<()> {
        if self.1.is_null() {
            return Err(FfiReturn::ArgIsNull);
        }

        if self.0.is_null() {
            self.write_none();
        } else {
            self.0.write(source.0);
            self.1.write(source.1);
        }

        Ok(())
    }
}
impl<T> OutPtrOf<SliceMut<T>> for OutSliceMut<T>
where
    *mut T: ReprC + NonLocal,
{
    unsafe fn write(self, source: SliceMut<T>) -> Result<()> {
        if self.1.is_null() {
            return Err(FfiReturn::ArgIsNull);
        }

        if self.0.is_null() {
            self.write_none();
        } else {
            self.0.write(source.0);
            self.1.write(source.1);
        }

        Ok(())
    }
}
impl<T: ReprC + NonLocal> OutPtrOf<Local<SliceRef<T>>> for OutBoxedSlice<T> {
    unsafe fn write(self, source: Local<SliceRef<T>>) -> Result<()> {
        if self.2.is_null() {
            return Err(FfiReturn::ArgIsNull);
        }

        // slice len is never larger than `isize::MAX`
        #[allow(clippy::expect_used)]
        source.0.into_rust().map_or_else(
            || self.write_none(),
            |slice| {
                self.2
                    .write(slice.len().try_into().expect("Allocation too large"));

                if !self.0.is_null() {
                    for (i, elem) in slice.iter().take(self.1).enumerate() {
                        self.0.add(i).write(*elem);
                    }
                }
            },
        );

        Ok(())
    }
}

impl<'slice, T: TryFromReprCSliceRef<'slice>> TryFromReprC<'slice> for &'slice [T]
where
    SliceRef<<T as FfiSliceRef>::ReprC>: ReprC,
{
    type Store = T::Store;

    unsafe fn try_from_repr_c(source: Self::ReprC, store: &'slice mut Self::Store) -> Result<Self> {
        TryFromReprCSliceRef::try_from_repr_c(source, store)
    }
}
impl<'slice, T: TryFromReprCSliceMut<'slice>> TryFromReprC<'slice> for &'slice mut [T]
where
    SliceMut<<T as FfiSliceMut>::ReprC>: ReprC,
{
    type Store = T::Store;

    unsafe fn try_from_repr_c(source: Self::ReprC, store: &'slice mut Self::Store) -> Result<Self> {
        TryFromReprCSliceMut::try_from_repr_c(source, store)
    }
}

impl<T: FfiSliceRef<ReprC = T>> TryFromReprCSliceRef<'_> for T
where
    SliceRef<<T as FfiSliceRef>::ReprC>: ReprC,
{
    type Store = ();

    unsafe fn try_from_repr_c(
        source: SliceRef<Self::ReprC>,
        _: &mut Self::Store,
    ) -> Result<&[Self]> {
        source.into_rust().ok_or(FfiReturn::ArgIsNull)
    }
}
impl<T: FfiSliceMut<ReprC = Self>> TryFromReprCSliceMut<'_> for T
where
    SliceMut<<Self as FfiSliceMut>::ReprC>: ReprC,
{
    type Store = ();

    unsafe fn try_from_repr_c(
        source: SliceMut<Self::ReprC>,
        _: &mut Self::Store,
    ) -> Result<&mut [Self]> {
        source.into_rust().ok_or(FfiReturn::ArgIsNull)
    }
}

impl<T: IntoFfiSliceRef> IntoFfi for &[T]
where
    SliceRef<<T as FfiSliceRef>::ReprC>: ReprC,
{
    type Store = T::Store;

    fn into_ffi(self, store: &mut Self::Store) -> Self::ReprC {
        IntoFfiSliceRef::into_ffi(self, store)
    }
}
impl<T: IntoFfiSliceMut> IntoFfi for &mut [T]
where
    SliceMut<<T as FfiSliceMut>::ReprC>: ReprC,
{
    type Store = T::Store;

    fn into_ffi(self, store: &mut Self::Store) -> Self::ReprC {
        IntoFfiSliceMut::into_ffi(self, store)
    }
}

impl<T: FfiSliceRef<ReprC = Self>> IntoFfiSliceRef for T
where
    SliceRef<<Self as FfiSliceRef>::ReprC>: ReprC,
{
    type Store = ();

    fn into_ffi(source: &[Self], _: &mut Self::Store) -> SliceRef<Self::ReprC> {
        SliceRef::from_slice(source)
    }
}
unsafe impl<T: FfiSliceMut<ReprC = Self>> IntoFfiSliceMut for T
where
    SliceMut<<Self as FfiSliceMut>::ReprC>: ReprC,
{
    type Store = ();

    fn into_ffi(source: &mut [Self], _: &mut Self::Store) -> SliceMut<Self::ReprC> {
        SliceMut::from_slice(source)
    }
}

// TODO: Be sure to match the bounds correctly
//impl<T: IntoFfiSliceRef> IntoFfiSliceRef for &[T]
//where
//    SliceRef<<T as FfiSliceRef>::ReprC>: ReprC,
//{
//    type Store = (Vec<Self::ReprC>, Vec<T::Store>);
//
//    fn into_ffi(source: &[Self], store: &mut Self::Store) -> SliceRef<Self::ReprC> {
//        store.0 = source
//            .iter()
//            .enumerate()
//            .map(|(i, item)| IntoFfiSliceRef::into_ffi(item, &mut store.1[i]))
//            .collect();
//
//        SliceRef::from_slice(&store.0)
//    }
//}
//impl<T: IntoFfiSliceRef> IntoFfiSliceRef for &mut [T]
//where
//    SliceRef<<T as FfiSliceRef>::ReprC>: ReprC,
//{
//    type Store = (Vec<Self::ReprC>, Vec<<T as IntoFfiSliceRef>::Store>);
//
//    fn into_ffi(source: &[Self], store: &mut Self::Store) -> SliceRef<Self::ReprC> {
//        store.0 = source
//            .iter()
//            .enumerate()
//            .map(|(i, item)| IntoFfiSliceRef::into_ffi(item, &mut store.1[i]))
//            .collect();
//
//        SliceRef::from_slice(&store.0)
//    }
//}
