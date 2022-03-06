#[cfg(not(feature = "std"))]
use alloc::{
    collections::{btree_map, btree_set},
    string::String,
    vec::Vec,
};
use core::mem::ManuallyDrop;
#[cfg(feature = "std")]
use std::collections::{btree_map, btree_set};

pub trait FfiEncode {
    type FfiType;

    fn ffi_encode(self) -> Self::FfiType;
    unsafe fn ffi_decode(source: Self::FfiType) -> Self;
}

//// TODO: lifetime won't be needed on trait after GAT's are stable
//pub trait FfiEncodeRef<'a> {
//    /// Type which has valid C representation
//    type FfiRefType: 'a;
//    type WrapperRefType: Deref<Self>;
//    fn ffi_encode(&'a self) -> Self::FfiRefType;
//    unsafe fn ffi_decode(source: Self::FfiRefType) -> &'a Self;
//
//    // TODO: Verify representation is valid for type(alignment, ...)
//    // fn verify() -> bool;
//}
//
//#[repr(C)]
//pub struct FfiSlice<'a, T> {
//    // TODO: Verify variance for T
//    // Binds the lifetime to the source
//    _source: core::marker::PhantomData<&'a ()>,
//
//    data: *const T,
//    len: usize,
//}

#[derive(Debug)]
struct FfiVec<T> {
    data: *mut T,
    len: usize,
    capacity: usize,
}

impl Clone for FfiVec {
    fn clone(&self) -> Self {
        unimplemented!()
    }
}

impl<T: FfiEncode<FfiType = T>> FfiEncode for Vec<T> {
}

impl<T> FfiEncode for Vec<T> {
    type FfiType = FfiVec<T>;

    fn ffi_encode(self) -> Self::FfiType {
        let s = ManuallyDrop::new(self);

        let data = s.as_mut_ptr();
        let len = s.len();
        let capacity = s.capacity();

        Self::FfiType {
            data,
            len,
            capacity,
        }
    }

    unsafe fn ffi_decode(source: Self::FfiType) -> Self {
        Vec::from_raw_parts(source.data, source.len, source.capacity)
    }
}

impl FfiEncode for String {
    type FfiType = FfiVec<u8>;

    fn ffi_encode(self) -> Self::FfiType {
        let mut s = ManuallyDrop::new(self);

        let data = s.as_mut_ptr();
        let len = s.len();
        let capacity = s.capacity();

        Self::FfiType {
            data,
            len,
            capacity,
        }
    }

    unsafe fn ffi_decode(source: Self::FfiType) -> Self {
        String::from_raw_parts(source.data, source.len, source.capacity)
    }
}

#[repr(C)]
pub struct FfiMap<K, V>(FfiVec<K>, FfiVec<V>);

impl<K, V> FfiEncode for btree_map::BTreeMap<K, V> {
    type FfiType = FfiMap<K, V>;

    fn ffi_encode(self) -> Self::FfiType {
        let s = ManuallyDrop::new(self);
        let keys: Vec<_> = s.keys().collect();
        let values: Vec<_> = s.values().collect();

        //Self::Target(keys, values)
        unimplemented!()
    }
    unsafe fn ffi_decode(_source: Self::FfiType) -> Self {
        unimplemented!()
    }
}

macro_rules! impl_ffi_encode {
    ( $( $id: ident ),+ ) => {
        $(
        impl FfiEncode for $id {
            type FfiType = Self;

            #[inline]
            fn ffi_encode(self) -> Self::FfiType {
                self
            }

            #[inline]
            unsafe fn ffi_decode(source: Self::FfiType) -> Self {
                source
            }
        }
        )+
    }
}

// TODO: Support usize/isize? bool? MaybeUninit?
impl_ffi_encode!(u8, i8, u16, i16, u32, i32, u64, i64, usize, isize);
