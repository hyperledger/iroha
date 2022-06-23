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
pub trait Opaque {}

/// Robust type which conforms to C ABI and can be safely shared across FFI boundaries. This
/// is a shallow representation meaning that it does not ensure the ABI of the referent for pointers.
/// If you need to dereference the pointer it is up to the you to ensure compatible representations
// TODO: Make it an unsafe trait?
pub trait ReprC {
    /// Type used to represent Rust function output as an argument in an FFI function. Must be a repr(C) as well
    type OutPtr;

    /// Write [`Self`] into [`Self::OutPtr`]
    unsafe fn write_out(self, dest: Self::OutPtr);
}

// TODO: Make it an unsafe trait?
pub trait FromOption: IntoFfi + Sized {
    /// Robust C ABI compliant representation of [Option<`Self`>]
    type FfiType: ReprC;

    /// Type into which state can be stored during conversion. Useful for returning
    /// non-owning types but performing some conversion which requires allocation.
    /// Serves similar purpose as does context in a closure
    type Store;

    /// Performs the conversion from [Option<`Self`>] into [`<Self as FromOption>::FfiType`]
    fn into_ffi(
        source: Option<Self>,
        store: &mut <Self as FromOption>::Store,
    ) -> <Self as FromOption>::FfiType;
}

//pub trait IntoOption<'store>: TryFromFfi<'store> + Sized {
//    type Store;
//
//    unsafe fn try_from_ffi(
//        source: <Self as IntoOption>::FfiType,
//        store: &mut <Self as IntoOption>::Store,
//    ) -> Result<Option<Self>, FfiResult>;
//}

/// Conversion into an FFI compatible representation that consumes the input value
///
// TODO: Make it an unsafe trait?
pub trait IntoFfi {
    /// Robust C ABI compliant representation of [`Self`]
    type FfiType;

    /// Type into which state can be stored during conversion. Useful for returning
    /// non-owning types but performing some conversion which requires allocation.
    /// Serves similar purpose as does context in a closure
    type Store: Default;

    /// Performs the conversion from [`Self`] into [`Self::FfiType`]
    fn into_ffi(self, store: &mut Self::Store) -> Self::FfiType;
}

/// Conversion from an FFI compatible representation that consumes the input value
// TODO: Make it an unsafe trait?
pub trait TryFromFfi<'store>: IntoFfi + Sized {
    /// Type into which state can be stored during conversion. Useful for returning
    /// non-owning types but performing some conversion which requires allocation.
    /// Serves similar purpose as does context in a closure
    type Store: Default;

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
    unsafe fn try_from_ffi(
        source: Self::FfiType,
        store: &'store mut <Self as TryFromFfi<'store>>::Store,
    ) -> Result<Self, FfiResult>;
}

pub struct IteratorWrapper<T: IntoIterator>(T);

pub struct IntoWrapper<T: Into<U>, U>(T, core::marker::PhantomData<U>);

/// Slice with a C ABI
#[derive(Clone)]
#[repr(C)]
pub struct Slice<T: ReprC>(*mut T, usize);

/// Slice with a C ABI when being used as a function return type
#[derive(Clone, Copy)]
#[repr(C)]
// NOTE: Returned size is isize to be able to support Option<&[T]>
pub struct OutSlice<T: ReprC>(*mut T, usize, *mut isize);

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

impl<T> ReprC for *const T {
    type OutPtr = *mut Self;

    unsafe fn write_out(self, dest: Self::OutPtr) {
        dest.write(self)
    }
}

impl<T> ReprC for *mut T {
    type OutPtr = *mut Self;

    unsafe fn write_out(self, dest: Self::OutPtr) {
        dest.write(self)
    }
}

impl<T: ReprC> ReprC for Slice<T> {
    type OutPtr = OutSlice<T>;

    unsafe fn write_out(self, dest: Self::OutPtr) {
        if self.is_null() {
            dest.write_null();
        } else {
            dest.2.write(self.len() as isize);

            for (i, elem) in self.into_iter().take(dest.1).enumerate() {
                let offset = i.try_into().expect("allocation too large");
                dest.0.offset(offset).write(elem);
            }
        }
    }
}

impl<T: Opaque> IntoFfi for &T {
    type FfiType = *const T;
    type Store = ();

    fn into_ffi(self, _: &mut Self::Store) -> Self::FfiType {
        Self::FfiType::from(self)
    }
}

impl<T: Opaque> IntoFfi for &mut T {
    type FfiType = *mut T;
    type Store = ();

    fn into_ffi(self, _: &mut Self::Store) -> Self::FfiType {
        Self::FfiType::from(self)
    }
}

impl<T: Opaque> TryFromFfi<'_> for &T {
    type Store = ();

    unsafe fn try_from_ffi(
        source: Self::FfiType,
        _: &mut <Self as TryFromFfi>::Store,
    ) -> Result<Self, FfiResult> {
        source.as_ref().ok_or(FfiResult::ArgIsNull)
    }
}

impl<T: Opaque> TryFromFfi<'_> for &mut T {
    type Store = ();

    unsafe fn try_from_ffi(
        source: Self::FfiType,
        _: &mut <Self as TryFromFfi>::Store,
    ) -> Result<Self, FfiResult> {
        source.as_mut().ok_or(FfiResult::ArgIsNull)
    }
}

impl<T: IntoIterator<Item = U>, U: IntoFfi> IntoFfi for IteratorWrapper<T>
where
    U::FfiType: ReprC,
{
    type FfiType = Slice<U::FfiType>;
    type Store = (Vec<U::FfiType>, Vec<U::Store>);

    fn into_ffi(self, store: &mut Self::Store) -> Self::FfiType {
        self.0.into_iter().for_each(|item| {
            store.1.push(Default::default());
            let inner_store = store.1.last_mut().expect("Defined");
            store.0.push(item.into_ffi(inner_store));
        });

        Slice(store.0.as_mut_ptr(), store.0.len())
    }
}

impl<T: Into<U>, U: IntoFfi> IntoFfi for IntoWrapper<T, U> {
    type FfiType = U::FfiType;
    type Store = U::Store;

    fn into_ffi(self, store: &mut Self::Store) -> Self::FfiType {
        self.0.into().into_ffi(store)
    }
}

impl<T, U> FromOption for &T
where
    Self: IntoFfi<FfiType = *const U>,
{
    type FfiType = <Self as IntoFfi>::FfiType;
    type Store = <Self as IntoFfi>::Store;

    fn into_ffi(
        source: Option<Self>,
        store: &mut <Self as FromOption>::Store,
    ) -> <Self as FromOption>::FfiType {
        source.map_or_else(core::ptr::null, |item| IntoFfi::into_ffi(item, store))
    }
}

impl<T, U> FromOption for &mut T
where
    Self: IntoFfi<FfiType = *mut U>,
{
    type FfiType = <Self as IntoFfi>::FfiType;
    type Store = <Self as IntoFfi>::Store;

    fn into_ffi(
        source: Option<Self>,
        store: &mut <Self as FromOption>::Store,
    ) -> <Self as FromOption>::FfiType {
        source.map_or_else(core::ptr::null_mut, |item| IntoFfi::into_ffi(item, store))
    }
}

impl<T: FromOption> IntoFfi for Option<T>
where
    <T as FromOption>::Store: Default,
{
    type FfiType = <T as FromOption>::FfiType;
    type Store = <T as FromOption>::Store;

    fn into_ffi(self, store: &mut Self::Store) -> Self::FfiType {
        FromOption::into_ffi(self, store)
    }
}

// TODO:
//impl<T: FromOption> TryFromFfi<'_> for Option<T>
//where
//    <T as FromOption>::Store: Default,
//{
//    type Store = <T as FromOption>::Store;
//
//    unsafe fn try_from_ffi(
//        source: Self::FfiType,
//        store: &mut <Self as TryFromFfi>::Store,
//    ) -> Result<Self, FfiResult> {
//        FromOption::try_from_ffi(source, store)
//    }
//}

impl<T: ReprC> Slice<T> {
    fn null() -> Self {
        // TODO: size should be uninitialized and never read from
        Self(core::ptr::null_mut(), 0)
    }

    fn is_null(&self) -> bool {
        self.0.is_null()
    }

    fn len(&self) -> usize {
        self.1
    }
}

impl<T: ReprC> IntoIterator for Slice<T> {
    type Item = T;
    type IntoIter = <Vec<Self::Item> as IntoIterator>::IntoIter;

    fn into_iter(self) -> Self::IntoIter {
        let slice = unsafe {
            Box::<[_]>::from_raw(core::slice::from_raw_parts_mut(self.0, self.1)).into_vec()
        };

        slice.into_iter()
    }
}

impl<T: ReprC> OutSlice<T> {
    unsafe fn write_null(self) {
        self.2.write(NONE);
    }
}

impl<'slice, T> IntoFfi for &'slice [T]
where
    &'slice T: IntoFfi,
    <&'slice T as IntoFfi>::FfiType: ReprC,
{
    type FfiType = Slice<<&'slice T as IntoFfi>::FfiType>;
    type Store = (
        Vec<<&'slice T as IntoFfi>::FfiType>,
        Vec<<&'slice T as IntoFfi>::Store>,
    );

    fn into_ffi(self, store: &mut Self::Store) -> Self::FfiType {
        IteratorWrapper(self).into_ffi(store)
    }
}

impl<'slice, T> IntoFfi for &'slice mut [T]
where
    &'slice mut T: IntoFfi,
    <&'slice mut T as IntoFfi>::FfiType: ReprC,
{
    type FfiType = Slice<<&'slice mut T as IntoFfi>::FfiType>;
    type Store = (
        Vec<<&'slice mut T as IntoFfi>::FfiType>,
        Vec<<&'slice mut T as IntoFfi>::Store>,
    );

    fn into_ffi(self, store: &mut Self::Store) -> Self::FfiType {
        IteratorWrapper(self).into_ffi(store)
    }
}

//impl<'store, T> TryFromFfi<'store> for &'store [T]
//where
//    &'store T: TryFromFfi<'store>,
//    <&'store T as IntoFfi>::FfiType: Copy,
//{
//    type Store = Vec<<&'store T as TryFromFfi<'store>>::Store>;
//
//    unsafe fn try_from_ffi(
//        source: Self::FfiType,
//        store: &'store mut <Self as TryFromFfi<'store>>::Store,
//    ) -> Result<Self, FfiResult> {
//        if source.is_null() {
//            return Err(FfiResult::ArgIsNull);
//        }
//
//        let slice: &'store [<&'store T as IntoFfi>::FfiType] =
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

impl<'slice, T> IntoFfi for Option<&'slice [T]>
where
    &'slice [T]: IntoFfi<FfiType = Slice<<&'slice T as IntoFfi>::FfiType>>,
    &'slice T: IntoFfi,
    <&'slice T as IntoFfi>::FfiType: ReprC,
{
    type FfiType = <&'slice [T] as IntoFfi>::FfiType;
    type Store = <&'slice [T] as IntoFfi>::Store;

    fn into_ffi(self, store: &mut Self::Store) -> Self::FfiType {
        self.map_or_else(Slice::null, |item| item.into_ffi(store))
    }
}

impl<'slice, T> IntoFfi for Option<&'slice mut [T]>
where
    &'slice mut [T]: IntoFfi<FfiType = Slice<<&'slice mut T as IntoFfi>::FfiType>>,
    &'slice mut T: IntoFfi,
    <&'slice mut T as IntoFfi>::FfiType: ReprC,
{
    type FfiType = <&'slice mut [T] as IntoFfi>::FfiType;
    type Store = <&'slice mut [T] as IntoFfi>::Store;

    fn into_ffi(self, store: &mut Self::Store) -> Self::FfiType {
        self.map_or_else(Slice::null, |item| item.into_ffi(store))
    }
}

impl<'store, T> TryFromFfi<'store> for Option<&'store [T]>
where
    &'store [T]: TryFromFfi<'store, FfiType = Slice<<&'store T as IntoFfi>::FfiType>>,
    &'store T: TryFromFfi<'store>,
    <&'store T as IntoFfi>::FfiType: ReprC,
{
    type Store = <&'store [T] as TryFromFfi<'store>>::Store;

    unsafe fn try_from_ffi(
        source: Self::FfiType,
        store: &'store mut <Self as TryFromFfi<'store>>::Store,
    ) -> Result<Self, FfiResult> {
        Ok(if !source.is_null() {
            Some(TryFromFfi::try_from_ffi(source, store)?)
        } else {
            None
        })
    }
}

impl<'store, T> TryFromFfi<'store> for Option<&'store mut [T]>
where
    &'store mut [T]: TryFromFfi<'store, FfiType = Slice<<&'store mut T as IntoFfi>::FfiType>>,
    &'store mut T: TryFromFfi<'store>,
    <&'store mut T as IntoFfi>::FfiType: ReprC,
{
    type Store = <&'store mut [T] as TryFromFfi<'store>>::Store;

    unsafe fn try_from_ffi(
        source: Self::FfiType,
        store: &'store mut <Self as TryFromFfi<'store>>::Store,
    ) -> Result<Self, FfiResult> {
        Ok(if !source.is_null() {
            Some(TryFromFfi::try_from_ffi(source, store)?)
        } else {
            None
        })
    }
}

impl IntoFfi for bool {
    type FfiType = u8;
    type Store = ();

    fn into_ffi(self, store: &mut Self::Store) -> Self::FfiType {
        u8::from(self).into_ffi(store)
    }
}

impl IntoFfi for &bool {
    type FfiType = *const u8;
    type Store = u8;

    fn into_ffi(self, store: &mut Self::Store) -> Self::FfiType {
        *store = (*self).into();
        IntoFfi::into_ffi(store, &mut ())
    }
}

impl IntoFfi for &mut bool {
    type FfiType = *mut u8;
    type Store = u8;

    fn into_ffi(self, store: &mut Self::Store) -> Self::FfiType {
        *store = (*self).into();
        IntoFfi::into_ffi(store, &mut ())
    }
}

impl FromOption for bool {
    type FfiType = *mut <Self as IntoFfi>::FfiType;
    type Store = u8;

    fn into_ffi(
        source: Option<Self>,
        store: &mut <Self as FromOption>::Store,
    ) -> <Self as FromOption>::FfiType {
        source.map_or_else(core::ptr::null_mut, |item| {
            *store = <u8>::from(item);
            IntoFfi::into_ffi(store, &mut ())
        })
    }
}

impl TryFromFfi<'_> for bool {
    type Store = ();

    unsafe fn try_from_ffi(
        source: Self::FfiType,
        _: &mut <Self as TryFromFfi>::Store,
    ) -> Result<Self, FfiResult> {
        Ok(source != 0)
    }
}

impl<'store> TryFromFfi<'store> for &'store bool {
    type Store = bool;

    unsafe fn try_from_ffi(
        source: Self::FfiType,
        store: &'store mut <Self as TryFromFfi<'store>>::Store,
    ) -> Result<Self, FfiResult> {
        let source = source.as_ref().ok_or(FfiResult::ArgIsNull)?;
        *store = TryFromFfi::try_from_ffi(*source, &mut ())?;
        Ok(store)
    }
}

impl<'store> TryFromFfi<'store> for &'store mut bool {
    type Store = bool;

    unsafe fn try_from_ffi(
        source: Self::FfiType,
        store: &'store mut <Self as TryFromFfi<'store>>::Store,
    ) -> Result<Self, FfiResult> {
        let source = source.as_ref().ok_or(FfiResult::ArgIsNull)?;
        *store = TryFromFfi::try_from_ffi(*source, &mut ())?;
        Ok(store)
    }
}

impl IntoFfi for core::cmp::Ordering {
    type FfiType = i8;
    type Store = ();

    fn into_ffi(self, _: &mut Self::Store) -> <Self as IntoFfi>::FfiType {
        self as <Self as IntoFfi>::FfiType
    }
}

impl TryFromFfi<'_> for core::cmp::Ordering {
    type Store = ();

    unsafe fn try_from_ffi(
        source: <Self as IntoFfi>::FfiType,
        _: &mut <Self as TryFromFfi>::Store,
    ) -> Result<Self, FfiResult> {
        match source {
            -1 => Ok(core::cmp::Ordering::Less),
            0 => Ok(core::cmp::Ordering::Equal),
            1 => Ok(core::cmp::Ordering::Greater),
            // TODO: More appropriate error?
            _ => Err(FfiResult::UnknownHandle),
        }
    }
}

//impl<T: IntoFfi> IntoFfi for Vec<T> {
//    type FfiType = Slice<T>;
//    type Store = T::;
//
//    fn into_ffi(self, store: &mut Self::Store) -> Self::FfiType {
//        let vec: Vec<_> = self.into_iter().map(|item| item.into_ffi(store)).collect();
//    }
//}
//
//impl IntoFfi for String {
//    type FfiType = *mut u8;
//    type Store = ();
//    fn into_ffi(self, store: &mut Self::Store) -> Self::FfiType {
//        unimplemented!()
//    }
//}
//
//impl TryFromFfi<'_> for String {
//    type Store = ();
//    unsafe fn try_from_ffi(
//        source: <Self as IntoFfi>::FfiType,
//        _: &mut <Self as TryFromFfi>::Store,
//    ) -> Result<Self, FfiResult> {
//        unimplemented!()
//    }
//}

macro_rules! impl_tuples {
    // TODO: Add implementations for references
    ( $( ($( $ty:ident ),+ $(,)?) -> $ffi_ty:ident ),+ $(,)?) => { $(
        /// FFI compatible tuple with n elements
        #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
        #[repr(C)]
        pub struct $ffi_ty<$($ty: IntoFfi),+>($($ty::FfiType),+);

        impl<$($ty: IntoFfi),+> ReprC for $ffi_ty<$($ty),+> {
            type OutPtr = *mut Self;

            unsafe fn write_out(self, dest: Self::OutPtr) {
                dest.write(self)
            }
        }

        impl<$($ty),+> IntoFfi for ($( $ty, )+) where $( $ty: IntoFfi ),+ {
            type FfiType = $ffi_ty<$($ty),+>;
            type Store = ($($ty::Store,)+);

            #[allow(non_snake_case)]
            fn into_ffi(self, store: &mut Self::Store) -> Self::FfiType {
                mod private {
                    // NOTE: This is a trick to index tuples
                    pub struct Store<'tup, $($ty: super::IntoFfi),+>{
                        $(pub $ty: &'tup mut $ty::Store),+
                    }

                    impl<'tup, $($ty: super::IntoFfi),+> From<&'tup mut ($($ty::Store,)+)> for Store<'tup, $($ty),+> {
                        fn from(($($ty,)+): &'tup mut ($($ty::Store,)+)) -> Self {
                            Self {$($ty,)+}
                        }
                    }
                }

                let ($($ty,)+) = self;
                let store: private::Store<$($ty),+> = store.into();

                $ffi_ty::<$($ty),+>($( <$ty as IntoFfi>::into_ffi($ty, store.$ty)),+)
            }
        } )+
    };
}

macro_rules! primitive_impls {
    ( $( $ty:ty ),+ $(,)? ) => { $(
        impl ReprC for $ty {
            type OutPtr = *mut Self;

            unsafe fn write_out(self, dest: Self::OutPtr) {
                dest.write(self)
            }
        }

        impl IntoFfi for $ty {
            type FfiType = Self;
            type Store = ();

            fn into_ffi(self, _: &mut Self::Store) -> Self::FfiType {
                self
            }
        }

        impl IntoFfi for &$ty {
            type FfiType = *const $ty;
            type Store = ();

            fn into_ffi(self, _: &mut Self::Store) -> Self::FfiType {
                Self::FfiType::from(self)
            }
        }

        impl IntoFfi for &mut $ty {
            type FfiType = *mut $ty;
            type Store = ();

            fn into_ffi(self, _: &mut Self::Store) -> Self::FfiType {
                Self::FfiType::from(self)
            }
        }

        impl FromOption for $ty {
            type FfiType = *mut <Self as IntoFfi>::FfiType;
            type Store = Self;

            fn into_ffi(source: Option<Self>, store: &mut <Self as FromOption>::Store) -> <Self as FromOption>::FfiType {
                source.map_or_else(core::ptr::null_mut, |item| {
                    *store = item;
                    IntoFfi::into_ffi(store, &mut ())
                })
            }
        }

        impl TryFromFfi<'_> for $ty {
            type Store = ();

            unsafe fn try_from_ffi(source: Self::FfiType, _: &mut <Self as TryFromFfi>::Store) -> Result<Self, FfiResult> {
                Ok(source)
            }
        }

        impl TryFromFfi<'_> for &$ty {
            type Store = ();

            unsafe fn try_from_ffi(source: Self::FfiType, _: &mut <Self as TryFromFfi>::Store) -> Result<Self, FfiResult> {
                source.as_ref().ok_or(FfiResult::ArgIsNull)
            }
        }

        impl TryFromFfi<'_> for &mut $ty {
            type Store = ();

            unsafe fn try_from_ffi(source: Self::FfiType, _: &mut <Self as TryFromFfi>::Store) -> Result<Self, FfiResult> {
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
                        let (handle_ptr, mut handle_store) = (handle_ptr.cast::<$other>(), Default::default());
                        let handle = <&$other as iroha_ffi::TryFromFfi>::try_from_ffi(handle_ptr, &mut handle_store)?;

                        let new_handle = Clone::clone(handle);
                        let mut new_handle_store = Default::default();
                        let new_handle_ptr = iroha_ffi::IntoFfi::into_ffi(new_handle, &mut new_handle_store);
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
                        let (mut lhandle_store, mut rhandle_store) = (Default::default(), Default::default());

                        let (lhandle_ptr, rhandle_ptr) = (left_handle_ptr.cast::<$other>(), right_handle_ptr.cast::<$other>());
                        let left_handle = <&$other as iroha_ffi::TryFromFfi>::try_from_ffi(lhandle_ptr, &mut lhandle_store)?;
                        let right_handle = <&$other as iroha_ffi::TryFromFfi>::try_from_ffi(rhandle_ptr, &mut rhandle_store)?;

                        let res = iroha_ffi::IntoFfi::into_ffi(left_handle == right_handle, &mut ());
                        output_ptr.cast::<u8>().write(res);
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
                        let (mut lhandle_store, mut rhandle_store) = (Default::default(), Default::default());

                        let (lhandle_ptr, rhandle_ptr) = (left_handle_ptr.cast::<$other>(), right_handle_ptr.cast::<$other>());
                        let left_handle = <&$other as iroha_ffi::TryFromFfi>::try_from_ffi(lhandle_ptr, &mut lhandle_store)?;
                        let right_handle = <&$other as iroha_ffi::TryFromFfi>::try_from_ffi(rhandle_ptr, &mut rhandle_store)?;

                        let res = iroha_ffi::IntoFfi::into_ffi(left_handle.cmp(right_handle), &mut ());
                        output_ptr.cast::<i8>().write(res);
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
                        <$other as iroha_ffi::TryFromFfi>::try_from_ffi(handle_ptr, &mut ())?;
                    } )+
                    // TODO: Implement error handling (https://github.com/hyperledger/iroha/issues/2252)
                    _ => return Err($crate::FfiResult::UnknownHandle),
                }

                Ok(())
            })
        }
    };
}
