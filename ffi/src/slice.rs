use crate::{AsFfi, FfiBorrow, FfiBorrowMut, FfiRef, FfiType, FfiWriteOut, IntoFfi, ReprC};

const NONE: isize = -1;

pub trait AsFfiSlice: FfiRef + Sized {
    type ItemRef: FfiBorrow;
    type ItemMut: FfiBorrowMut;

    /// Performs the conversion from [`&[Self]`] into [`SliceRef`] with a defined C ABI
    fn into_ffi_slice(source: &[Self]) -> Self::ItemRef;

    /// Performs the conversion from [`&mut [Self]`] into [`SliceMut`] with a defined C ABI
    fn into_ffi_slice_mut(source: &mut [Self]) -> Self::ItemMut;
}

/// Immutable slice with a defined C ABI
#[repr(C)]
// NOTE: There is no point in storing lifetime information in these slices
// because that information cannot be sent across an extern FFI boundary
// TODO: Rethink this comment
pub struct SliceRef<T>(*const T, usize);

/// Mutable slice with a defined C ABI
#[repr(C)]
pub struct SliceMut<T>(*mut T, usize);

/// Owned slice `Box<[T]>` with a defined C ABI
// NOTE: Intermediary types don't require repr(C)
pub struct BoxedSlice<T>(*mut T, usize);

#[repr(C)]
// NOTE: Returned size is isize to be able to support Option<&[T]>
pub struct OutSliceMut<T>(*mut *mut T, *mut isize);

#[repr(C)]
// NOTE: Returned size is isize to be able to support Option<&[T]>
pub struct OutSliceRef<T>(*mut *const T, *mut isize);

#[repr(C)]
// NOTE: Returned size is isize to be able to support Option<&[T]>
pub struct OutBoxedSlice<T>(*mut T, usize, *mut isize);

impl<T: ReprC> FfiBorrow for SliceRef<T> {
    type Borrowed = Self;

    #[inline]
    fn borrow(&self) -> Self::Borrowed {
        SliceRef(self.0, self.1)
    }
}

impl<T: ReprC> FfiBorrowMut for SliceMut<T> {
    type Borrowed = Self;

    #[inline]
    fn borrow_mut(&mut self) -> Self::Borrowed {
        SliceMut(self.0, self.1)
    }
}

impl<T: ReprC> FfiBorrow for BoxedSlice<T> {
    type Borrowed = SliceRef<T>;

    #[inline]
    fn borrow(&self) -> Self::Borrowed {
        SliceRef(self.0, self.1)
    }
}

impl<T: ReprC> FfiBorrowMut for BoxedSlice<T> {
    type Borrowed = SliceMut<T>;

    #[inline]
    fn borrow_mut(&mut self) -> Self::Borrowed {
        SliceMut(self.0, self.1)
    }
}

unsafe impl<T: ReprC> ReprC for OutSliceRef<T> {}
unsafe impl<T: ReprC> ReprC for OutSliceMut<T> {}
unsafe impl<T: ReprC> ReprC for OutBoxedSlice<T> {}

unsafe impl<T: ReprC> ReprC for SliceRef<T> {}
impl<T: ReprC> FfiWriteOut for SliceRef<T> {
    type OutPtr = OutSliceRef<T>;

    unsafe fn write(self, dest: Self::OutPtr) {
        if self.is_null() {
            dest.write_none();
        } else {
            dest.0.write(self.0);
            dest.1.write(self.len());
        }
    }
}

unsafe impl<T: ReprC> ReprC for SliceMut<T> {}
impl<T: ReprC> FfiWriteOut for SliceMut<T> {
    type OutPtr = OutSliceMut<T>;

    unsafe fn write(self, dest: Self::OutPtr) {
        if self.is_null() {
            dest.write_none();
        } else {
            dest.0.write(self.0);
            dest.1.write(self.len());
        }
    }
}

impl<T: ReprC> FfiWriteOut for BoxedSlice<T> {
    type OutPtr = OutBoxedSlice<T>;

    unsafe fn write(self, dest: Self::OutPtr) {
        let len = self.len();

        if let Some(elems) = self.take(dest.1) {
            dest.2.write(len);

            for (i, elem) in elems.enumerate() {
                dest.0.offset(i as isize).write(elem);
            }
        } else {
            dest.write_none();
        }
    }
}

impl<T> SliceRef<T> {
    pub(crate) const fn from_slice(slice: &[T]) -> Self {
        Self(slice.as_ptr(), slice.len())
    }

    const fn null() -> Self {
        // TODO: size should be uninitialized and never read from
        Self(core::ptr::null_mut(), 0)
    }

    fn is_null(&self) -> bool {
        self.0.is_null()
    }

    fn len(&self) -> isize {
        self.1.try_into().expect("Allocation too large")
    }
}

impl<T> SliceMut<T> {
    pub(crate) fn from_slice(slice: &mut [T]) -> Self {
        Self(slice.as_mut_ptr(), slice.len())
    }

    const fn null() -> Self {
        // TODO: size should be uninitialized and never read from
        Self(core::ptr::null_mut(), 0)
    }

    fn is_null(&self) -> bool {
        self.0.is_null()
    }

    fn len(&self) -> isize {
        self.1.try_into().expect("Allocation too large")
    }
}

impl<T> BoxedSlice<T> {
    unsafe fn as_slice_mut<'slice>(&mut self) -> Option<&'slice mut [T]> {
        if self.0.is_null() {
            return None;
        }

        Some(core::slice::from_raw_parts_mut(self.0, self.1))
    }

    unsafe fn take(self, n: usize) -> Option<impl ExactSizeIterator<Item = T>> {
        if self.is_null() {
            return None;
        }

        let slice = core::slice::from_raw_parts_mut(self.0, self.1);
        Some(Box::<[_]>::from_raw(slice).into_vec().into_iter().take(n))
    }

    const fn null() -> Self {
        // TODO: size should be uninitialized and never read from
        Self(core::ptr::null_mut(), 0)
    }

    fn is_null(&self) -> bool {
        self.0.is_null()
    }

    fn len(&self) -> isize {
        self.1.try_into().expect("Allocation too large")
    }
}

impl<T> OutBoxedSlice<T> {
    unsafe fn write_none(self) {
        self.2.write(NONE);
    }
}

impl<T> OutSliceRef<T> {
    unsafe fn write_none(self) {
        self.1.write(NONE);
    }
}

impl<T> OutSliceMut<T> {
    unsafe fn write_none(self) {
        self.1.write(NONE);
    }
}

impl<T: IntoFfi> FfiType for &[T] {
    type FfiType = SliceRef<T::FfiType>;
}

impl<T: IntoFfi> FfiType for &mut [T] {
    type FfiType = SliceMut<T::FfiType>;
}

impl<T: FfiType> FfiRef for [T] {
    type FfiRef = SliceRef<T::FfiType>;
    type FfiMut = SliceMut<T::FfiType>;
}

impl<T: AsFfiSlice> AsFfi for [T]
where
    [T]: FfiRef,
{
    type ItemRef = <T as AsFfiSlice>::ItemRef;
    type ItemMut = <T as AsFfiSlice>::ItemMut;

    fn as_ffi_ref(&self) -> Self::ItemRef {
        AsFfiSlice::into_ffi_slice(self)
    }
    fn as_ffi_mut(&mut self) -> Self::ItemMut {
        AsFfiSlice::into_ffi_slice_mut(self)
    }
}

//impl<T: AsFfiSlice> FfiType for Option<&[T]> {
//    type FfiType = SliceRef<<T as AsFfiSlice>::FfiType>;
//}
//
//impl<T: AsFfiSlice> FfiType for Option<&mut [T]> {
//    type FfiType = SliceMut<<T as AsFfiSlice>::FfiType>;
//}

//impl<T: AsFfiSlice> IntoFfi for Option<&[T]> {
//    type Item = Self::FfiType;
//
//    fn into_ffi(self) -> Self::Item {
//        self.map_or_else(SliceRef::null, AsFfiSlice::into_ffi_slice)
//    }
//}
//
//impl<T: AsFfiSlice> IntoFfi for Option<&mut [T]> {
//    type Item = Self::FfiType;
//
//    fn into_ffi(self) -> Self::Item {
//        self.map_or_else(SliceMut::null, AsFfiSlice::into_ffi_slice_mut)
//    }
//}

pub struct IteratorWrapper<T: IntoIterator>(T);

//impl FfiType for IteratorWrapper
//type FfiType = SliceMut<'store, U::FfiType>;
//impl<T: IntoIterator<Item = U>, U: IntoFfi> IntoFfi for IteratorWrapper<T>
//where
//    U::FfiType: ReprC
//{
//    type Store = (Vec<U::FfiType>, Vec<U::Store>);
//
//    fn into_ffi(self, store: &'store mut Self::Store) -> Self::FfiType {
//        store.1 = (0..self.len()).map(|_| Default::default()).collect();
//
//        let mut slice = &mut store.1[..];
//        self.0.into_iter().for_each(|item| {
//            let (inner_store, rest) = slice.split_first_mut().expect("Defined");
//            store.0.push(item.as_ffi(inner_store));
//            slice = rest;
//            store.1.push(Default::default());
//            let inner_store = store.1.last_mut().expect("Defined");
//            store.0.push(item.into_ffi(inner_store));
//        });
//
//        SliceMut::from_slice(&mut store.0)
//    }
//}
