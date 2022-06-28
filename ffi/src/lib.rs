//! Structures, macros related to FFI and generation of FFI bindings.
//! [Non-robust types](https://anssi-fr.github.io/rust-guide/07_ffi.html#non-robust-types-references-function-pointers-enums)
//! are strictly avoided in the FFI API
//!
//! # Conversions:
//! owned type -> opaque pointer
//! reference -> raw pointer
//!
//! enum -> int
//! bool -> u8
//!
//! # Conversions (WebAssembly):
//! u8, u16 -> u32
//! i8, i16 -> i32

use core::marker::PhantomData;

pub use iroha_ffi_derive::*;

const NONE: isize = -1;

// NOTE: Using `u32` to be compatible with WebAssembly.
// Otherwise `u8` should be sufficient
/// Type of the handle id
pub type HandleId = u32;

/// Represents handle in an FFI context
///
/// # Safety
///
/// If two structures implement the same id, this may result in void pointer being casted to the wrong type
pub unsafe trait Handle {
    /// Unique identifier of the handle. Most commonly, it is
    /// used to facilitate generic monomorphization over FFI
    const ID: HandleId;
}

/// Indicates that type is converted into an opaque pointer when crossing the FFI boundary
// TODO: Make it unsafe?
pub trait Opaque: FfiType {}

/// Robust type which conforms to C ABI and can be safely shared across FFI boundaries. This does
/// not ensure the ABI of the referent for pointers in which case the pointer should be made opaque
///
/// # Safety
///
/// Type implementing the trait must be a robust type with a guaranteed C ABI
pub unsafe trait ReprC {
    /// Type used to represent Rust function output as an argument in an FFI function. Must be a repr(C) as well
    type OutPtr;

    /// Write [`Self`] into [`Self::OutPtr`]
    unsafe fn write_out(self, dest: Self::OutPtr);
}

// TODO: Make it an unsafe trait?
pub trait FromOption<'store>: OptionWrapped + IntoFfi {
    /// Type into which state can be stored during conversion. Useful for returning
    /// non-owning types but performing some conversion which requires allocation.
    /// Serves similar purpose as does context in a closure
    type Store;

    /// Performs the conversion from [Option<`Self`>] into [`<Self as FromOption>::FfiType`]
    fn into_ffi(
        source: Option<Self>,
        store: &'store mut <Self as FromOption<'store>>::Store,
    ) -> <Self as OptionWrapped>::FfiType;
}

pub trait AsFfi: FfiRef {
    type Store: Default;

    fn as_ffi_ref<'store>(&'store self, store: &'store mut Self::Store) -> Self::FfiRef;
    fn as_ffi_mut<'store>(&'store mut self, store: &'store mut Self::Store) -> Self::FfiMut;
}

pub trait AsFfiSlice: Sized {
    /// Robust C ABI compliant representation of [Option<`Self`>]
    type FfiType: ReprC;

    /// Type into which state can be stored during conversion. Useful for returning
    /// non-owning types but performing some conversion which requires allocation.
    /// Serves similar purpose as does context in a closure
    type Store: Default;

    /// Performs the conversion from [`&[Self]`] into [`SliceRef`] with a defined C ABI
    fn into_ffi_slice<'store>(
        source: &'store [Self],
        store: &'store mut Self::Store,
    ) -> SliceRef<Self::FfiType>;

    /// Performs the conversion from [`&mut [Self]`] into [`SliceMut`] with a defined C ABI
    fn into_ffi_slice_mut<'store>(
        source: &'store mut [Self],
        store: &'store mut Self::Store,
    ) -> SliceMut<Self::FfiType>;
}

/// Conversion into an FFI compatible representation that consumes the input value
///
// TODO: Make it an unsafe trait?
pub trait IntoFfi: FfiType {
    /// Performs the conversion from [`Self`] into [`Self::FfiType`]
    fn into_ffi(self) -> Self::FfiType;
}

pub trait FfiType: Sized {
    /// Robust C ABI compliant representation of [`Self`]
    type FfiType: ReprC;
}

pub trait FfiRef {
    /// Robust C ABI compliant representation of [`&Self`]
    type FfiRef: ReprC;

    /// Robust C ABI compliant representation of [`&mut Self`]
    type FfiMut: ReprC;
}

/// Conversion from an FFI compatible representation that consumes the input value
// TODO: Make it an unsafe trait?
pub trait TryFromFfi: FfiType {
    /// Performs the fallible conversion
    ///
    /// # Errors
    ///
    /// * given pointer is null
    /// * given id doesn't identify any known handle
    /// * given id is not a valid enum discriminant
    ///
    /// # Safety
    ///
    /// All conversions from a pointer must ensure pointer validity beforehand
    #[allow(unsafe_code)]
    unsafe fn try_from_ffi(source: Self::FfiType) -> Result<Self, FfiResult>;
}

pub trait TryAsRust: FfiRef {
    /// Type into which state can be stored during conversion. Useful for returning
    /// non-owning types but performing some conversion which requires allocation.
    /// Serves similar purpose as does context in a closure
    type Store: Default;

    /// Performs the fallible conversion of a reference
    ///
    /// # Errors
    ///
    /// * given pointer is null
    /// * given id doesn't identify any known handle
    /// * given id is not a valid enum discriminant
    ///
    /// # Safety
    ///
    /// All conversions from a pointer must ensure pointer validity beforehand
    #[allow(unsafe_code)]
    unsafe fn try_as_rust_ref<'store>(
        source: Self::FfiRef,
        store: &'store mut Self::Store,
    ) -> Result<&'store Self, FfiResult>;

    unsafe fn try_as_rust_mut<'store>(
        source: Self::FfiMut,
        store: &'store mut Self::Store,
    ) -> Result<&'store mut Self, FfiResult>;
}

pub struct IteratorWrapper<'iter, T: IntoIterator>(T, PhantomData<&'iter mut T>);

pub struct IntoWrapper<T: Into<U>, U>(T, PhantomData<U>);

/// Mutable slice with a defined C ABI
#[repr(C)]
pub struct SliceMut<T>(*mut T, usize);

/// Immutable slice with a defined C ABI
#[repr(C)]
pub struct SliceRef<T>(*const T, usize);

#[repr(C)]
// NOTE: Returned size is isize to be able to support Option<&[T]>
pub struct OutSliceMut<T>(*mut *mut T, *mut isize);

/// Slice with a C ABI when being used as a function return type
#[repr(C)]
// NOTE: Returned size is isize to be able to support Option<&[T]>
pub struct OutSliceRef<T>(*mut *const T, *mut isize);

/// Result of execution of an FFI function
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
// NOTE: Enum is `repr(i32)` becasuse WebAssembly supports only
// u32/i32, u64/i64 natively. Otherwise, `repr(i8)` would suffice
#[repr(i32)]
pub enum FfiResult {
    /// Indicates that the FFI function execution panicked
    UnrecoverableError = -5_i32,
    /// Handle id doesn't identify any known handles
    UnknownHandle = -4_i32,
    /// Executing the wrapped method on handle returned error
    ExecutionFail = -3_i32,
    /// Raw pointer input argument to FFI function was null
    ArgIsNull = -2_i32,
    /// Given bytes don't comprise a valid UTF8 string
    Utf8Error = -1_i32,
    /// FFI function executed successfully
    Ok = 0_i32,
}

unsafe impl<T> ReprC for *const T {
    type OutPtr = *mut Self;

    unsafe fn write_out(self, dest: Self::OutPtr) {
        dest.write(self)
    }
}

unsafe impl<T> ReprC for *mut T {
    type OutPtr = *mut Self;

    unsafe fn write_out(self, dest: Self::OutPtr) {
        dest.write(self)
    }
}

unsafe impl<'slice, T: ReprC> ReprC for SliceMut<T> {
    type OutPtr = OutSliceMut<T>;

    unsafe fn write_out(self, dest: Self::OutPtr) {
        if self.is_null() {
            dest.write_none();
        } else {
            dest.1
                .write(self.len().try_into().expect("Allocation too large"));
            dest.0.write(self.0);
        }
    }
}

unsafe impl<'slice, T: ReprC> ReprC for SliceRef<T> {
    type OutPtr = OutSliceRef<T>;

    unsafe fn write_out(self, dest: Self::OutPtr) {
        if self.is_null() {
            dest.write_none();
        } else {
            dest.1
                .write(self.len().try_into().expect("Allocation too large"));
            dest.0.write(self.0);
        }
    }
}

impl<T: Opaque> FfiType for T {
    type FfiType = *mut Self;
}

impl<T: Opaque> FfiRef for T {
    type FfiRef = *const Self;
    type FfiMut = *mut Self;
}

impl<T: Opaque + FfiType<FfiType = *mut Self>> IntoFfi for T {
    fn into_ffi(self) -> Self::FfiType {
        Box::into_raw(Box::new(self))
    }
}

impl<T: Opaque> AsFfi for T {
    type Store = ();

    fn as_ffi_ref(&self, _: &mut Self::Store) -> *const T {
        self as *const _
    }
    fn as_ffi_mut(&mut self, _: &mut Self::Store) -> *mut T {
        self as *mut _
    }
}

impl<T: Opaque> TryFromFfi for T
where
    T: FfiType<FfiType = *mut Self>,
{
    unsafe fn try_from_ffi(source: Self::FfiType) -> Result<Self, FfiResult> {
        if source.is_null() {
            return Err(FfiResult::ArgIsNull);
        }

        Ok(*Box::from_raw(source))
    }
}

impl<T: Opaque> TryAsRust for T {
    type Store = ();

    unsafe fn try_as_rust_ref(
        source: Self::FfiRef,
        _: &mut Self::Store,
    ) -> Result<&Self, FfiResult> {
        source.as_ref().ok_or(FfiResult::ArgIsNull)
    }

    unsafe fn try_as_rust_mut(
        source: Self::FfiMut,
        _: &mut Self::Store,
    ) -> Result<&mut Self, FfiResult> {
        source.as_mut().ok_or(FfiResult::ArgIsNull)
    }
}

//impl<'store, 'iter: 'store, T: IntoIterator<Item = U>, U: IntoFfi<'store>> IntoFfi<'store> for IteratorWrapper<'iter, T>
//where
//    U::FfiType: ReprC + 'store,
//{
//    type FfiType = SliceMut<'store, U::FfiType>;
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

//impl<'store, T: Into<U> + 'store, U: IntoFfi<'store>> IntoFfi<'store> for IntoWrapper<T, U> {
//    type FfiType = U::FfiType;
//    type Store = U::Store;
//
//    fn into_ffi(self, store: &'store mut Self::Store) -> Self::FfiType {
//        self.0.into().into_ffi(store)
//    }
//}
//
//impl<'store, T, U> FromOption<'store> for &'store T
//where
//    Self: IntoFfi<FfiType = *const U>,
//{
//    type Store = <Self as IntoFfi<'store>>::Store;
//
//    fn into_ffi(
//        source: Option<Self>,
//        store: &'store mut <Self as FromOption<'store>>::Store,
//    ) -> <Self as OptionWrapped>::FfiType {
//        source.map_or_else(core::ptr::null, |item| IntoFfi::into_ffi(item, store))
//    }
//}
//
//impl<'store, T, U> FromOption<'store> for &'store mut T
//where
//    Self: IntoFfi<'store, FfiType = *mut U>,
//{
//    type Store = <Self as IntoFfi<'store>>::Store;
//
//    fn into_ffi(
//        source: Option<Self>,
//        store: &'store mut <Self as FromOption<'store>>::Store,
//    ) -> <Self as OptionWrapped>::FfiType {
//        source.map_or_else(core::ptr::null_mut, |item| IntoFfi::into_ffi(item, store))
//    }
//}

pub trait OptionWrapped: FfiType {
    /// Robust C ABI compliant representation of [Option<`Self`>]
    type FfiType: ReprC;
}

impl<T> OptionWrapped for &T
where
    Self: FfiType,
{
    type FfiType = <Self as FfiType>::FfiType;
}

impl<T> OptionWrapped for &mut T
where
    Self: FfiType,
{
    type FfiType = <Self as FfiType>::FfiType;
}

impl<T: OptionWrapped> FfiType for Option<T> {
    type FfiType = <T as OptionWrapped>::FfiType;
}

//impl<'store, T: FromOption<'store>> IntoFfi for Option<T>
//where
//    <T as FromOption<'store>>::Store: Default,
//{
//    fn into_ffi(self) -> Self::FfiType {
//        // TODO: Fix this
//        let store = Default::default();
//        FromOption::into_ffi(self, &mut store)
//    }
//}

impl<T> SliceRef<T> {
    pub fn from_slice(slice: &[T]) -> Self {
        Self(slice.as_ptr(), slice.len())
    }

    pub unsafe fn into_slice<'slice>(self) -> Option<&'slice [T]> {
        if self.0.is_null() {
            return None;
        }

        Some(core::slice::from_raw_parts(self.0, self.1))
    }

    pub fn null() -> Self {
        // TODO: size should be uninitialized and never read from
        Self(core::ptr::null_mut(), 0)
    }

    pub fn is_null(&self) -> bool {
        self.0.is_null()
    }

    pub fn len(&self) -> usize {
        self.1
    }
}

impl<T> SliceMut<T> {
    pub fn from_slice(slice: &mut [T]) -> Self {
        Self(slice.as_mut_ptr(), slice.len())
    }

    pub unsafe fn into_slice<'slice>(self) -> Option<&'slice mut [T]> {
        if self.0.is_null() {
            return None;
        }

        Some(core::slice::from_raw_parts_mut(self.0, self.1))
    }

    pub fn null() -> Self {
        // TODO: size should be uninitialized and never read from
        Self(core::ptr::null_mut(), 0)
    }

    pub fn is_null(&self) -> bool {
        self.0.is_null()
    }

    pub fn len(&self) -> usize {
        self.1
    }
}

impl<T> OutSliceMut<T> {
    unsafe fn write_none(self) {
        self.1.write(NONE);
    }
}

impl<T> OutSliceRef<T> {
    unsafe fn write_none(self) {
        self.1.write(NONE);
    }
}

impl<T: Opaque> AsFfiSlice for T {
    type FfiType = *const T;
    type Store = Vec<*const T>;

    /// Performs the conversion from [`&[Self]`] into [`SliceRef`] with a defined C ABI
    fn into_ffi_slice<'store>(
        source: &'store [Self],
        store: &'store mut Self::Store,
    ) -> SliceRef<Self::FfiType> {
        let start = store.len();
        store.extend(source.into_iter().map(|item| item as *const _));
        SliceRef::from_slice(&store[start + 1..])
    }

    /// Performs the conversion from [`&mut [Self]`] into [`SliceMut`] with a defined C ABI
    fn into_ffi_slice_mut<'store>(
        source: &'store mut [Self],
        store: &'store mut Self::Store,
    ) -> SliceMut<Self::FfiType> {
        let start = store.len();
        store.extend(source.into_iter().map(|item| item as *const _));
        SliceMut::from_slice(&mut store[start + 1..])
    }
}

impl<T: AsFfiSlice> AsFfi for [T]
where
    [T]: FfiRef<FfiRef = SliceRef<T>, FfiMut = SliceMut<T>>,
{
    type Store = Vec<T>;

    fn as_ffi_ref(&self, _: &mut Self::Store) -> SliceRef<T> {
        SliceRef::from_slice(self)
    }
    fn as_ffi_mut(&mut self, _: &mut Self::Store) -> SliceMut<T> {
        SliceMut::from_slice(self)
    }
}

//impl<'store, T> TryFromFfi<'store> for &'store [T]
//where
//    &'store T: TryFromFfi<'store>,
//    <&'store T as IntoFfi<'store>>::FfiType: Copy,
//{
//    type Store = Vec<<&'store T as TryFromFfi<'store>>::Store>;
//
//    unsafe fn try_from_ffi(
//        source: Self::FfiType,
//        store: &'store mut Self::Store,
//    ) -> Result<Self, FfiResult> {
//        if source.is_null() {
//            return Err(FfiResult::ArgIsNull);
//        }
//
//        let slice: &'store [<&'store T as IntoFfi<'store>>::FfiType] =
//            core::slice::from_raw_parts(source.0, source.1);
//
//        //for item in slice {
//        //    store.push(Default::default());
//        //    let inner_store = store.last_mut().expect("Defined");
//        //    let ffi_ty = <&'store T as TryFromFfi<'store>>::try_from_ffi(*item, inner_store);
//        //}
//
//        unimplemented!("TODO")
//        //if let Some(first) = iter.next() {
//        //    let first: &_ = first?;
//        //    let first: *const _ = first;
//        //    return Ok(core::slice::from_raw_parts(first, source.1));
//        //}
//
//        //return Ok(, 0);
//    }
//}

impl<'store, T: AsFfiSlice> FfiType for Option<&'store [T]> {
    type FfiType = SliceRef<<T as AsFfiSlice>::FfiType>;
}

impl<'store, T: AsFfiSlice> FfiType for Option<&'store mut [T]> {
    type FfiType = SliceMut<<T as AsFfiSlice>::FfiType>;
}

impl<'store, T: AsFfiSlice> IntoFfi for Option<&'store [T]> {
    fn into_ffi(self) -> Self::FfiType {
        self.map_or_else(SliceRef::null, |item| {
            // TODO: Fix this
            let mut store = Default::default();
            AsFfiSlice::into_ffi_slice(item, &mut store)
        })
    }
}

impl<'store, T: AsFfiSlice> IntoFfi for Option<&'store mut [T]> {
    fn into_ffi(self) -> Self::FfiType {
        self.map_or_else(SliceMut::null, |item| {
            // TODO: Fix this
            let mut store = Default::default();
            AsFfiSlice::into_ffi_slice_mut(item, &mut store)
        })
    }
}

//impl<'store, T> TryFromFfi<'store> for Option<&'store [T]>
//where
//    &'store [T]: TryFromFfi<'store, FfiType = SliceRef<'store, <&'store T as IntoFfi<'store>>::FfiType>>,
//    &'store T: TryFromFfi<'store>,
//    <&'store T as IntoFfi<'store>>::FfiType: ReprC,
//{
//    type Store = <&'store [T] as TryFromFfi<'store>>::Store;
//
//    unsafe fn try_from_ffi(
//        source: Self::FfiType,
//        store: &'store mut Self::Store,
//    ) -> Result<Self, FfiResult> {
//        Ok(if !source.is_null() {
//            Some(TryFromFfi::try_from_ffi(source, store)?)
//        } else {
//            None
//        })
//    }
//}
//
//impl<'store, T> TryFromFfi<'store> for Option<&'store mut [T]>
//where
//    &'store mut [T]:
//        TryFromFfi<'store, FfiType = SliceMut<'store, <&'store mut T as IntoFfi<'store>>::FfiType>>,
//    &'store mut T: TryFromFfi<'store>,
//    <&'store mut T as IntoFfi<'store>>::FfiType: ReprC,
//{
//    type Store = <&'store mut [T] as TryFromFfi<'store>>::Store;
//
//    unsafe fn try_from_ffi(
//        source: Self::FfiType,
//        store: &'store mut Self::Store,
//    ) -> Result<Self, FfiResult> {
//        Ok(if !source.is_null() {
//            Some(TryFromFfi::try_from_ffi(source, store)?)
//        } else {
//            None
//        })
//    }
//}

impl FfiType for bool {
    type FfiType = u8;
}

impl FfiRef for bool {
    type FfiRef = *const u8;
    type FfiMut = *mut u8;
}

impl IntoFfi for bool {
    fn into_ffi(self) -> Self::FfiType {
        Self::FfiType::from(self).into_ffi()
    }
}

//impl AsFfi for bool {
//    type Store = u8;
//
//    fn as_ffi_ref(&self, store: &mut Self::Store) -> Self::FfiRef {
//        *store = (*self).into();
//        IntoFfi::into_ffi(store)
//    }
//
//    fn as_ffi_mut(&mut self, store: &mut Self::Store) -> Self::FfiMut {
//        *store = (*self).into();
//        IntoFfi::into_ffi(store)
//    }
//}

impl OptionWrapped for bool {
    type FfiType = <Self as FfiType>::FfiType;
}

impl<'store> FromOption<'store> for bool {
    type Store = ();

    fn into_ffi(
        source: Option<Self>,
        _: &mut <Self as FromOption<'store>>::Store,
    ) -> <Self as OptionWrapped>::FfiType {
        // NOTE: Relying on trap representation to represent None values
        source.map_or(u8::MAX, |item| IntoFfi::into_ffi(item))
    }
}

impl TryFromFfi for bool {
    unsafe fn try_from_ffi(source: Self::FfiType) -> Result<Self, FfiResult> {
        Ok(source != 0)
    }
}

//impl<'store> TryFromFfi<'store> for &'store bool {
//    type Store = bool;
//
//    unsafe fn try_from_ffi(
//        source: Self::FfiType,
//        store: &'store mut Self::Store,
//    ) -> Result<Self, FfiResult> {
//        let source = source.as_ref().ok_or(FfiResult::ArgIsNull)?;
//        *store = TryFromFfi::try_from_ffi(*source, &mut ())?;
//        Ok(store)
//    }
//}
//
//impl<'store> TryFromFfi<'store> for &'store mut bool {
//    type Store = bool;
//
//    unsafe fn try_from_ffi(
//        source: Self::FfiType,
//        store: &'store mut Self::Store,
//    ) -> Result<Self, FfiResult> {
//        let source = source.as_ref().ok_or(FfiResult::ArgIsNull)?;
//        *store = TryFromFfi::try_from_ffi(*source, &mut ())?;
//        Ok(store)
//    }
//}

impl FfiType for core::cmp::Ordering {
    type FfiType = i8;
}

impl IntoFfi for core::cmp::Ordering {
    fn into_ffi(self) -> <Self as FfiType>::FfiType {
        self as <Self as FfiType>::FfiType
    }
}

impl TryFromFfi for core::cmp::Ordering {
    unsafe fn try_from_ffi(source: <Self as FfiType>::FfiType) -> Result<Self, FfiResult> {
        match source {
            -1 => Ok(core::cmp::Ordering::Less),
            0 => Ok(core::cmp::Ordering::Equal),
            1 => Ok(core::cmp::Ordering::Greater),
            // TODO: More appropriate error?
            _ => Err(FfiResult::UnknownHandle),
        }
    }
}

// TODO: This is vec
//unsafe impl<T: ReprC> ReprC for Vec<'_, T> {
//    type OutPtr = OutSlice<T>;
//
//    unsafe fn write_out(self, dest: Self::OutPtr) {
//        if self.is_null() {
//            dest.write_none();
//        } else {
//            dest.2.write(self.len().try_into().expect("Allocation too large"));
//
//            for (i, elem) in self.into_iter().take(dest.1).enumerate() {
//                dest.0.offset(i as isize).write(elem);
//            }
//        }
//    }
//}

//impl<T: IntoFfi> IntoFfi for Vec<T> {
//    type FfiType = Slice<T>;
//    type Store = T::;
//
//    fn into_ffi(self, store: &'store mut Self::Store) -> Self::FfiType {
//        let vec: Vec<_> = self.into_iter().map(|item| item.into_ffi(store)).collect();
//    }
//}
//
//impl IntoFfi for String {
//    type FfiType = *mut u8;
//    type Store = ();
//    fn into_ffi(self, store: &'store mut Self::Store) -> Self::FfiType {
//        unimplemented!()
//    }
//}
//
//impl TryFromFfi<'_> for String {
//    type Store = ();
//    unsafe fn try_from_ffi(
//        source: Self::FfiType,
//        _: &mut Self::Store,
//    ) -> Result<Self, FfiResult> {
//        unimplemented!()
//    }
//}

macro_rules! impl_tuples {
    ( $( ($( $ty:ident ),+ $(,)?) -> $ffi_ty:ident ),+ $(,)?) => { $(
        /// FFI compatible tuple with n elements
        #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
        #[repr(C)]
        pub struct $ffi_ty<$($ty: FfiType),+>($($ty::FfiType),+);

        unsafe impl<$($ty: FfiType),+> ReprC for $ffi_ty<$($ty),+> {
            type OutPtr = *mut Self;

            unsafe fn write_out(self, dest: Self::OutPtr) {
                dest.write(self)
            }
        }

        impl<$($ty: FfiType),+> FfiType for ($( $ty, )+) {
            type FfiType = $ffi_ty<$($ty),+>;
        }

        impl<$($ty: FfiRef),+> FfiRef for ($( $ty, )+) {
            type FfiRef = *const Self;
            type FfiMut = *mut Self;
        }

        #[allow(non_snake_case)]
        impl<$($ty),+> IntoFfi for ($( $ty, )+) where $( $ty: IntoFfi ),+ {
            fn into_ffi(self) -> Self::FfiType {
                let ($($ty,)+) = self;

                $ffi_ty::<$($ty),+>($( <$ty as IntoFfi>::into_ffi($ty)),+)
            }
        }
    )+ }

        // TODO: Add implementations for references
        //impl<$($ty),+> AsFfi for ($( $ty, )+) where $( $ty: AsFfi ),+ {
        //    type Store = ($($ty::Store,)+);

        //    #[allow(non_snake_case)]
        //    fn as_ffi_ref<'store>(&'store self, store: &'store mut Self::Store) -> Self::FfiRef {
        //        mod private {
        //            // NOTE: This is a trick to index tuples
        //            pub struct Store<'tup, $($ty: super::AsFfi),+>{
        //                $(pub $ty: &'tup mut $ty::Store),+
        //            }

        //            impl<'store, 'tup, $($ty: super::AsFfi),+> From<&'tup mut ($($ty::Store,)+)> for Store<'tup, $($ty),+> {
        //                fn from(($($ty,)+): &'tup mut ($($ty::Store,)+)) -> Self {
        //                    Self {$($ty,)+}
        //                }
        //            }
        //        }

        //        let ($($ty,)+) = self;
        //        let store: private::Store<$($ty),+> = store.into();

        //        $ffi_ty::<$($ty),+>($( <$ty as AsFfi>::as_ffi($ty, store.$ty)),+)
        //    }
}

macro_rules! primitive_impls {
    ( $( $ty:ty ),+ $(,)? ) => { $(
        unsafe impl ReprC for $ty {
            type OutPtr = *mut Self;

            unsafe fn write_out(self, dest: Self::OutPtr) {
                dest.write(self)
            }
        }

        impl FfiRef for $ty {
            type FfiRef = *const $ty;
            type FfiMut = *mut $ty;
        }

        impl FfiRef for [$ty] {
            type FfiRef = *const $ty;
            type FfiMut = *mut $ty;
        }

        impl FfiType for $ty {
            type FfiType = Self;
        }

        impl FfiType for &$ty {
            type FfiType = *const $ty;
        }

        impl FfiType for &mut $ty {
            type FfiType = *mut $ty;
        }

        impl IntoFfi for $ty {
            fn into_ffi(self) -> Self::FfiType {
                self
            }
        }

        impl AsFfi for $ty {
            type Store = ();

            fn as_ffi_ref(&self, _: &mut Self::Store) -> Self::FfiRef {
                Self::FfiRef::from(self)
            }

            fn as_ffi_mut(&mut self, _: &mut Self::Store) -> Self::FfiMut {
                Self::FfiMut::from(self)
            }
        }

        impl AsFfiSlice for $ty {
            type FfiType = <$ty as FfiType>::FfiType;
            type Store = ();

            /// Performs the conversion from [`&[Self]`] into [`SliceRef`] with a defined C ABI
            fn into_ffi_slice<'store>(
                source: &'store [Self],
                store: &'store mut Self::Store,
            ) -> SliceRef<Self::FfiType> {
                unimplemented!();
            }

            /// Performs the conversion from [`&mut [Self]`] into [`SliceMut`] with a defined C ABI
            fn into_ffi_slice_mut<'store>(
                source: &'store mut [Self],
                store: &'store mut Self::Store,
            ) -> SliceMut<Self::FfiType> {
                unimplemented!();
            }
        }

        impl OptionWrapped for $ty {
            type FfiType = *mut <Self as FfiType>::FfiType;
        }

        //impl<'store> FromOption<'store> for $ty {
        //    type Store = Self;

        //    fn into_ffi(source: Option<Self>, store: &mut <Self as FromOption<'store>>::Store) -> <Self as OptionWrapped>::FfiType {
        //        source.map_or_else(core::ptr::null_mut, |item| {
        //            *store = item;
        //            IntoFfi::into_ffi(store)
        //        })
        //    }
        //}

        impl TryFromFfi for $ty {
            unsafe fn try_from_ffi(source: Self::FfiType) -> Result<Self, FfiResult> {
                Ok(source)
            }
        }

        impl TryAsRust for $ty {
            type Store = ();

            unsafe fn try_as_rust_ref(
                source: Self::FfiRef,
                _: &mut Self::Store,
            ) -> Result<&Self, FfiResult> {
                source.as_ref().ok_or(FfiResult::ArgIsNull)
            }

            unsafe fn try_as_rust_mut<'store>(
                source: Self::FfiMut,
                _: &mut Self::Store,
            ) -> Result<&mut Self, FfiResult> {
                source.as_mut().ok_or(FfiResult::ArgIsNull)
            }
        } )+
    };
}

primitive_impls! {u8, u16, u32, u64, u128, i8, i16, i32, i64, i128, f32, f64}

impl_tuples! {
    (A) -> FfiTuple1,
    (A, B) -> FfiTuple2,
    (A, B, C) -> FfiTuple3,
    (A, B, C, D) -> FfiTuple4,
    (A, B, C, D, E) -> FfiTuple5,
    (A, B, C, D, E, F) -> FfiTuple6,
    (A, B, C, D, E, F, G) -> FfiTuple7,
    (A, B, C, D, E, F, G, H) -> FfiTuple8,
    (A, B, C, D, E, F, G, H, I) -> FfiTuple9,
    (A, B, C, D, E, F, G, H, I, J) -> FfiTuple10,
}

/// Implement [`Handle`] for given types with first argument as the initial handle id.
#[macro_export]
macro_rules! handles {
    ( $id:expr, $ty:ty $(, $other:ty)* $(,)? ) => {
        unsafe impl $crate::Handle for $ty {
            const ID: $crate::HandleId = $id;
        }

        $crate::handles! {$id + 1, $( $other, )*}
    };
    ( $id:expr, $(,)? ) => {};
}

/// Generate FFI equivalent implementation of the requested trait method (e.g. Clone, Eq, Ord)
#[macro_export]
macro_rules! gen_ffi_impl {
    (@catch_unwind $block:block ) => {
        match std::panic::catch_unwind(|| $block) {
            Ok(res) => match res {
                Ok(()) => $crate::FfiResult::Ok,
                Err(err) => err.into(),
            },
            Err(_) => {
                // TODO: Implement error handling (https://github.com/hyperledger/iroha/issues/2252)
                $crate::FfiResult::UnrecoverableError
            },
        }
    };
    ( $vis:vis Clone: $( $other:ty ),+ $(,)? ) => {
        /// FFI function equivalent of [`Clone::clone`]
        ///
        /// # Safety
        ///
        /// All of the given pointers must be valid and the given handle id must match the expected
        /// pointer type
        #[no_mangle]
        $vis unsafe extern "C" fn __clone(
            handle_id: $crate::HandleId,
            handle_ptr: *const core::ffi::c_void,
            output_ptr: *mut *mut core::ffi::c_void
        ) -> $crate::FfiResult {
            gen_ffi_impl!(@catch_unwind {
                match handle_id {
                    $( <$other as $crate::Handle>::ID => {
                        let (handle_ptr, mut handle_store) = (handle_ptr.cast::<$other>(), ());
                        let handle = <$other as iroha_ffi::TryAsRust>::try_as_rust_ref(handle_ptr, &mut handle_store)?;

                        let new_handle = Clone::clone(handle);
                        let new_handle_ptr = iroha_ffi::IntoFfi::into_ffi(new_handle);
                        output_ptr.cast::<*mut $other>().write(new_handle_ptr);
                    } )+
                    // TODO: Implement error handling (https://github.com/hyperledger/iroha/issues/2252)
                    _ => return Err($crate::FfiResult::UnknownHandle),
                }

                Ok(())
            })
        }
    };
    ( $vis:vis Eq: $( $other:ty ),+ $(,)? ) => {
        /// FFI function equivalent of [`Eq::eq`]
        ///
        /// # Safety
        ///
        /// All of the given pointers must be valid and the given handle id must match the expected
        /// pointer type
        #[no_mangle]
        $vis unsafe extern "C" fn __eq(
            handle_id: $crate::HandleId,
            left_handle_ptr: *const core::ffi::c_void,
            right_handle_ptr: *const core::ffi::c_void,
            output_ptr: *mut u8,
        ) -> $crate::FfiResult {
            gen_ffi_impl!(@catch_unwind {
                match handle_id {
                    $( <$other as $crate::Handle>::ID => {
                        let (mut lhandle_store, mut rhandle_store) = (Default::default(), ());

                        let (lhandle_ptr, rhandle_ptr) = (left_handle_ptr.cast::<$other>(), right_handle_ptr.cast::<$other>());
                        let left_handle = <$other as iroha_ffi::TryAsRust>::try_as_rust_ref(lhandle_ptr, &mut lhandle_store)?;
                        let right_handle = <$other as iroha_ffi::TryAsRust>::try_as_rust_ref(rhandle_ptr, &mut rhandle_store)?;

                        let res = iroha_ffi::IntoFfi::into_ffi(left_handle == right_handle);
                        output_ptr.write(res);
                    } )+
                    // TODO: Implement error handling (https://github.com/hyperledger/iroha/issues/2252)
                    _ => return Err($crate::FfiResult::UnknownHandle),
                }

                Ok(())
            })
        }
    };
    ( $vis:vis Ord: $( $other:ty ),+ $(,)? ) => {
        /// FFI function equivalent of [`Ord::ord`]
        ///
        /// # Safety
        ///
        /// All of the given pointers must be valid and the given handle id must match the expected
        /// pointer type
        #[no_mangle]
        $vis unsafe extern "C" fn __ord(
            handle_id: $crate::HandleId,
            left_handle_ptr: *const core::ffi::c_void,
            right_handle_ptr: *const core::ffi::c_void,
            output_ptr: *mut i8,
        ) -> $crate::FfiResult {
            gen_ffi_impl!(@catch_unwind {
                match handle_id {
                    $( <$other as $crate::Handle>::ID => {
                        let (mut lhandle_store, mut rhandle_store) = (Default::default(), ());

                        let (lhandle_ptr, rhandle_ptr) = (left_handle_ptr.cast::<$other>(), right_handle_ptr.cast::<$other>());
                        let left_handle = <$other as iroha_ffi::TryAsRust>::try_as_rust_ref(lhandle_ptr, &mut lhandle_store)?;
                        let right_handle = <$other as iroha_ffi::TryAsRust>::try_as_rust_ref(rhandle_ptr, &mut rhandle_store)?;

                        let res = iroha_ffi::IntoFfi::into_ffi(left_handle.cmp(right_handle));
                        output_ptr.write(res);
                    } )+
                    // TODO: Implement error handling (https://github.com/hyperledger/iroha/issues/2252)
                    _ => return Err($crate::FfiResult::UnknownHandle),
                }

                Ok(())
            })
        }
    };
    ( $vis:vis Drop: $( $other:ty ),+ $(,)? ) => {
        /// FFI function equivalent of [`Drop::drop`]
        ///
        /// # Safety
        ///
        /// All of the given pointers must be valid and the given handle id must match the expected
        /// pointer type
        #[no_mangle]
        $vis unsafe extern "C" fn __drop(
            handle_id: $crate::HandleId,
            handle_ptr: *mut core::ffi::c_void,
        ) -> $crate::FfiResult {
            gen_ffi_impl!(@catch_unwind {
                match handle_id {
                    $( <$other as $crate::Handle>::ID => {
                        let handle_ptr = handle_ptr.cast::<$other>();
                        <$other as iroha_ffi::TryFromFfi>::try_from_ffi(handle_ptr)?;
                    } )+
                    // TODO: Implement error handling (https://github.com/hyperledger/iroha/issues/2252)
                    _ => return Err($crate::FfiResult::UnknownHandle),
                }

                Ok(())
            })
        }
    };
}
