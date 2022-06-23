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
pub use opaque_pointer;

const NONE: isize = -1;

// NOTE: Using `u32` to be compatible with WebAssembly.
// Otherwise `u8` should be sufficient
/// Type of the handle id
pub type HandleId = u32;

/// Represents handle in an FFI context
pub trait Handle {
    /// Unique identifier of the handle. Most commonly, it is
    /// used to facilitate generic monomorphization over FFI
    const ID: HandleId;
}

/// Indicates that type is converted into an opaque pointer when crossing the FFI boundary
// TODO: Make it unsafe?
pub trait Opaque {}

pub trait OptionWrapped: IntoFfi + Sized {
    type FfiType;
    type OutFfiType;
    type Store;

    fn into_ffi(
        source: Option<Self>,
        store: &mut <Self as OptionWrapped>::Store,
    ) -> <Self as OptionWrapped>::FfiType;
    unsafe fn write_out(
        source: Option<Self>,
        store: &mut <Self as OptionWrapped>::Store,
        out: <Self as OptionWrapped>::OutFfiType,
    );
}

/// Conversion into an FFI compatible representation that consumes the input value
pub trait IntoFfi {
    /// FFI compatible representation of `Self`
    type FfiType;

    /// FFI compatible representation of `Self` when it's an out-pointer
    type OutFfiType;

    type Store: Default;

    /// Performs the conversion
    fn into_ffi(self, store: &mut Self::Store) -> Self::FfiType;

    /// Performs the conversion and writes the result into out-pointer
    unsafe fn write_out(self, store: &mut Self::Store, out: Self::OutFfiType);
}

/// Conversion from an FFI compatible representation that consumes the input value
pub trait TryFromFfi: IntoFfi + Sized {
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
        store: &mut <Self as TryFromFfi>::Store,
    ) -> Result<Self, FfiResult>;
}

/// FFI compatible tuple with 2 elements
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct Pair<K, V>(pub K, pub V);

pub struct IteratorWrapper<T: IntoIterator>(T);

#[derive(Clone)]
#[repr(C)]
// TODO: Add SliceMut?
pub struct Slice<T: IntoFfi>(*mut <T as IntoFfi>::FfiType, usize);

#[derive(Clone, Copy)]
#[repr(C)]
// NOTE: Returned size is isize to be able to support Option<&[T]>
pub struct OutSlice<T: IntoFfi>(*mut <T as IntoFfi>::FfiType, usize, *mut isize);

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

impl From<opaque_pointer::error::PointerError> for FfiResult {
    fn from(source: opaque_pointer::error::PointerError) -> Self {
        use opaque_pointer::error::PointerError::*;

        match source {
            // TODO: Implement error handling (https://github.com/hyperledger/iroha/issues/2252)
            Utf8Error(_) => Self::Utf8Error,
            Null => Self::ArgIsNull,
            Invalid => Self::UnknownHandle,
        }
    }
}

impl<T: Opaque> IntoFfi for &T {
    type FfiType = *const T;
    type OutFfiType = *mut Self::FfiType;
    type Store = ();

    fn into_ffi(self, _: &mut Self::Store) -> Self::FfiType {
        Self::FfiType::from(self)
    }

    unsafe fn write_out(self, store: &mut Self::Store, out: Self::OutFfiType) {
        out.write(self.into_ffi(store));
    }
}

impl<T: Opaque> IntoFfi for &mut T {
    type FfiType = *mut T;
    type OutFfiType = *mut Self::FfiType;
    type Store = ();

    fn into_ffi(self, _: &mut Self::Store) -> Self::FfiType {
        Self::FfiType::from(self)
    }

    unsafe fn write_out(self, store: &mut Self::Store, out: Self::OutFfiType) {
        out.write(self.into_ffi(store));
    }
}

impl<T: Opaque> TryFromFfi for &T {
    type Store = ();

    unsafe fn try_from_ffi(
        source: Self::FfiType,
        _: &mut <Self as TryFromFfi>::Store,
    ) -> Result<Self, FfiResult> {
        source.as_ref().ok_or(FfiResult::ArgIsNull)
    }
}

impl<T: Opaque> TryFromFfi for &mut T {
    type Store = ();

    unsafe fn try_from_ffi(
        source: Self::FfiType,
        _: &mut <Self as TryFromFfi>::Store,
    ) -> Result<Self, FfiResult> {
        source.as_mut().ok_or(FfiResult::ArgIsNull)
    }
}

impl<T: IntoIterator<Item = U>, U: IntoFfi> IntoFfi for IteratorWrapper<T> {
    type FfiType = Slice<U>;
    type OutFfiType = OutSlice<U>;
    type Store = (Vec<U::FfiType>, Vec<U::Store>);

    fn into_ffi(self, store: &mut Self::Store) -> Self::FfiType {
        let iter = self.0;

        iter.into_iter().for_each(|item| {
            let mut item_store = Default::default();
            store.0.push(item.into_ffi(&mut item_store));
            store.1.push(item_store);
        });

        Slice(store.0.as_mut_ptr(), store.0.len())
    }

    #[allow(clippy::expect_used)]
    unsafe fn write_out(self, store: &mut Self::Store, out: Self::OutFfiType) {
        let slice = self.into_ffi(store);

        out.2.write(slice.len() as isize);
        for (i, elem) in slice.into_iter().take(out.1).enumerate() {
            let offset = i.try_into().expect("allocation too large");
            out.0.offset(offset).write(elem);
        }
    }
}

impl<T: Opaque> OptionWrapped for &T {
    type FfiType = <Self as IntoFfi>::FfiType;
    type OutFfiType = <Self as IntoFfi>::OutFfiType;
    type Store = <Self as IntoFfi>::Store;

    fn into_ffi(
        source: Option<Self>,
        store: &mut <Self as OptionWrapped>::Store,
    ) -> <Self as OptionWrapped>::FfiType {
        source.map_or_else(core::ptr::null, |item| IntoFfi::into_ffi(item, store))
    }
    unsafe fn write_out(
        source: Option<Self>,
        store: &mut <Self as OptionWrapped>::Store,
        out: <Self as OptionWrapped>::OutFfiType,
    ) {
        if let Some(item) = source {
            IntoFfi::write_out(item, store, out);
        } else {
            out.write(core::ptr::null())
        }
    }
}

impl<T: Opaque> OptionWrapped for &mut T {
    type FfiType = <Self as IntoFfi>::FfiType;
    type OutFfiType = <Self as IntoFfi>::OutFfiType;
    type Store = <Self as IntoFfi>::Store;

    fn into_ffi(
        source: Option<Self>,
        store: &mut <Self as OptionWrapped>::Store,
    ) -> <Self as OptionWrapped>::FfiType {
        source.map_or_else(core::ptr::null_mut, |item| IntoFfi::into_ffi(item, store))
    }
    unsafe fn write_out(
        source: Option<Self>,
        store: &mut <Self as OptionWrapped>::Store,
        out: <Self as OptionWrapped>::OutFfiType,
    ) {
        if let Some(item) = source {
            IntoFfi::write_out(item, store, out);
        } else {
            out.write(core::ptr::null_mut())
        }
    }
}

impl<T: OptionWrapped> IntoFfi for Option<T>
where
    <T as OptionWrapped>::Store: Default,
{
    type FfiType = <T as OptionWrapped>::FfiType;
    type OutFfiType = <T as OptionWrapped>::OutFfiType;
    type Store = <T as OptionWrapped>::Store;

    fn into_ffi(self, store: &mut Self::Store) -> Self::FfiType {
        OptionWrapped::into_ffi(self, store)
    }

    unsafe fn write_out(self, store: &mut Self::Store, out: Self::OutFfiType) {
        OptionWrapped::write_out(self, store, out)
    }
}

impl<T: IntoFfi> Slice<T> {
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

impl<T: IntoFfi> IntoIterator for Slice<T> {
    type Item = T::FfiType;
    type IntoIter = <Vec<Self::Item> as IntoIterator>::IntoIter;

    fn into_iter(self) -> Self::IntoIter {
        let slice = unsafe {
            Box::<[_]>::from_raw(core::slice::from_raw_parts_mut(self.0, self.1)).into_vec()
        };

        slice.into_iter()
    }
}

impl<T: IntoFfi> OutSlice<T> {
    unsafe fn write_null(self) {
        self.2.write(NONE);
    }
}

impl<'slice, T> IntoFfi for &'slice [T]
where
    &'slice T: IntoFfi,
{
    type FfiType = Slice<&'slice T>;
    type OutFfiType = OutSlice<&'slice T>;
    type Store = (
        Vec<<&'slice T as IntoFfi>::FfiType>,
        Vec<<&'slice T as IntoFfi>::Store>,
    );

    fn into_ffi(self, store: &mut Self::Store) -> Self::FfiType {
        IteratorWrapper(self).into_ffi(store)
    }

    unsafe fn write_out(self, store: &mut Self::Store, out: Self::OutFfiType) {
        IteratorWrapper(self).write_out(store, out)
    }
}

impl<'slice, T> IntoFfi for &'slice mut [T]
where
    &'slice mut T: IntoFfi,
{
    type FfiType = Slice<&'slice mut T>;
    type OutFfiType = OutSlice<&'slice mut T>;
    type Store = (
        Vec<<&'slice mut T as IntoFfi>::FfiType>,
        Vec<<&'slice mut T as IntoFfi>::Store>,
    );

    fn into_ffi(self, store: &mut Self::Store) -> Self::FfiType {
        IteratorWrapper(self).into_ffi(store)
    }

    unsafe fn write_out(self, store: &mut Self::Store, out: Self::OutFfiType) {
        IteratorWrapper(self).write_out(store, out)
    }
}

//impl<'slice, T> TryFromFfi for &'slice [T]
//where
//    T: TryFromFfi,
//    <&'slice T as IntoFfi>::FfiType: Copy,
//{
//    unsafe fn try_from_ffi(
//        source: Self::FfiType,
//        store: &mut MaybeUninit<Self::Store>,
//    ) -> Result<Self, FfiResult> {
//        if source.is_null() {
//            return Err(FfiResult::ArgIsNull);
//        }
//
//        let vec: Vec<_> = core::slice::from_raw_parts(source.0, source.1)
//            .iter()
//            .map(|&item| {
//                let mut inner_store = MaybeUninit::uninit();
//
//                Ok((
//                    <&'slice T>::try_from_ffi(item, &mut inner_store)?,
//                    inner_store.assume_init(),
//                ))
//            })
//            .collect::<Result<_, FfiResult>>()?;
//
//        store.as_mut_ptr().write(vec);
//
//        Ok(store)
//    }
//}

//impl<'slice, T> TryFromFfi for &'slice mut [T]
//where
//    &'slice mut T: TryFromFfi,
//    <&'slice mut T as IntoFfi>::FfiType: Copy,
//{
//    unsafe fn try_from_ffi(source: Self::FfiType) -> Result<Self, FfiResult> {
//        if source.is_null() {
//            return Err(FfiResult::ArgIsNull);
//        }
//
//        unimplemented!()
//        //core::slice::from_raw_parts_mut(source.0, source.1).into_iter().map(TryFromFfi::try_from_ffi).collect()
//    }
//}

impl<'slice, T> IntoFfi for Option<&'slice [T]>
where
    &'slice [T]: IntoFfi<FfiType = Slice<&'slice T>, OutFfiType = OutSlice<&'slice T>>,
    &'slice T: IntoFfi,
{
    type FfiType = <&'slice [T] as IntoFfi>::FfiType;
    type OutFfiType = <&'slice [T] as IntoFfi>::OutFfiType;
    type Store = <&'slice [T] as IntoFfi>::Store;

    fn into_ffi(self, store: &mut Self::Store) -> Self::FfiType {
        self.map_or_else(Slice::null, |item| item.into_ffi(store))
    }

    unsafe fn write_out(self, store: &mut Self::Store, out: Self::OutFfiType) {
        self.map_or_else(
            || out.write_null(),
            |item| IntoFfi::write_out(item, store, out),
        );
    }
}

impl<'slice, T> IntoFfi for Option<&'slice mut [T]>
where
    &'slice mut [T]: IntoFfi<FfiType = Slice<&'slice mut T>, OutFfiType = OutSlice<&'slice mut T>>,
    &'slice mut T: IntoFfi,
{
    type FfiType = <&'slice mut [T] as IntoFfi>::FfiType;
    type OutFfiType = <&'slice mut [T] as IntoFfi>::OutFfiType;
    type Store = <&'slice mut [T] as IntoFfi>::Store;

    fn into_ffi(self, store: &mut Self::Store) -> Self::FfiType {
        self.map_or_else(Slice::null, |item| item.into_ffi(store))
    }

    unsafe fn write_out(self, store: &mut Self::Store, out: Self::OutFfiType) {
        if let Some(item) = self {
            IntoFfi::write_out(item, store, out);
        } else {
            out.write_null()
        }
    }
}

impl IntoFfi for bool {
    type FfiType = u8;
    type OutFfiType = *mut Self::FfiType;
    type Store = ();

    fn into_ffi(self, store: &mut Self::Store) -> Self::FfiType {
        u8::from(self).into_ffi(store)
    }

    unsafe fn write_out(self, store: &mut Self::Store, out: Self::OutFfiType) {
        out.write(self.into_ffi(store))
    }
}

impl IntoFfi for &bool {
    type FfiType = *const u8;
    type OutFfiType = *mut Self::FfiType;
    type Store = Vec<u8>;

    fn into_ffi(self, store: &mut Self::Store) -> Self::FfiType {
        store.push((*self).into());
        let elem = store.last().expect("Defined");
        IntoFfi::into_ffi(elem, &mut ())
    }

    unsafe fn write_out(self, store: &mut Self::Store, out: Self::OutFfiType) {
        out.write(self.into_ffi(store))
    }
}

impl IntoFfi for &mut bool {
    type FfiType = *mut u8;
    type OutFfiType = *mut Self::FfiType;
    type Store = Vec<u8>;

    fn into_ffi(self, store: &mut Self::Store) -> Self::FfiType {
        store.push((*self).into());
        let elem = store.last_mut().expect("Defined");
        IntoFfi::into_ffi(elem, &mut ())
    }

    unsafe fn write_out(self, store: &mut Self::Store, out: Self::OutFfiType) {
        out.write(self.into_ffi(store))
    }
}

impl OptionWrapped for bool {
    type FfiType = *mut <Self as IntoFfi>::FfiType;
    type OutFfiType = *mut <Self as OptionWrapped>::FfiType;
    type Store = Vec<u8>;

    fn into_ffi(
        source: Option<Self>,
        store: &mut <Self as OptionWrapped>::Store,
    ) -> <Self as OptionWrapped>::FfiType {
        source.map_or_else(core::ptr::null_mut, |item| {
            store.push(<u8>::from(item));
            let elem = store.last_mut().expect("Defined");
            IntoFfi::into_ffi(elem, &mut ())
        })
    }
    unsafe fn write_out(
        source: Option<Self>,
        store: &mut <Self as OptionWrapped>::Store,
        out: <Self as OptionWrapped>::OutFfiType,
    ) {
        if let Some(item) = source {
            let mut new_out = core::mem::MaybeUninit::<u8>::uninit();
            IntoFfi::write_out(item, &mut (), new_out.as_mut_ptr());
            store.push(new_out.assume_init());
            let elem = store.last_mut().expect("Defined");

            out.write(elem);
        } else {
            out.write(core::ptr::null_mut())
        }
    }
}

impl OptionWrapped for &bool {
    type FfiType = <Self as IntoFfi>::FfiType;
    type OutFfiType = <Self as IntoFfi>::OutFfiType;
    type Store = <Self as IntoFfi>::Store;

    fn into_ffi(
        source: Option<Self>,
        store: &mut <Self as OptionWrapped>::Store,
    ) -> <Self as OptionWrapped>::FfiType {
        source.map_or_else(core::ptr::null, |item| IntoFfi::into_ffi(item, store))
    }
    unsafe fn write_out(
        source: Option<Self>,
        store: &mut <Self as OptionWrapped>::Store,
        out: <Self as OptionWrapped>::OutFfiType,
    ) {
        if let Some(item) = source {
            IntoFfi::write_out(item, store, out);
        } else {
            out.write(core::ptr::null());
        }
    }
}

impl OptionWrapped for &mut bool {
    type FfiType = <Self as IntoFfi>::FfiType;
    type OutFfiType = <Self as IntoFfi>::OutFfiType;
    type Store = <Self as IntoFfi>::Store;

    fn into_ffi(
        source: Option<Self>,
        store: &mut <Self as OptionWrapped>::Store,
    ) -> <Self as OptionWrapped>::FfiType {
        source.map_or_else(core::ptr::null_mut, |item| IntoFfi::into_ffi(item, store))
    }
    unsafe fn write_out(
        source: Option<Self>,
        store: &mut <Self as OptionWrapped>::Store,
        out: <Self as OptionWrapped>::OutFfiType,
    ) {
        if let Some(item) = source {
            IntoFfi::write_out(item, store, out);
        } else {
            out.write(core::ptr::null_mut());
        }
    }
}

impl TryFromFfi for bool {
    type Store = ();

    unsafe fn try_from_ffi(
        source: Self::FfiType,
        _: &mut <Self as TryFromFfi>::Store,
    ) -> Result<Self, FfiResult> {
        Ok(source != 0)
    }
}

impl<'a> TryFromFfi for &'a bool {
    type Store = Vec<bool>;

    unsafe fn try_from_ffi(
        source: Self::FfiType,
        store: &mut <Self as TryFromFfi>::Store,
    ) -> Result<Self, FfiResult> {
        unimplemented!()
        //let source = source.as_ref().ok_or(FfiResult::ArgIsNull)?;
        //store.push(TryFromFfi::try_from_ffi(*source, &mut ())?);
        //Ok(store.last().expect("Defined"))
    }
}

impl TryFromFfi for &mut bool {
    type Store = Vec<bool>;

    unsafe fn try_from_ffi(
        source: Self::FfiType,
        store: &mut <Self as TryFromFfi>::Store,
    ) -> Result<Self, FfiResult> {
        unimplemented!()
        //let source = source.as_ref().ok_or(FfiResult::ArgIsNull)?;
        //store.push(TryFromFfi::try_from_ffi(*source, &mut ())?);
        //Ok(store.last_mut().expect("Defined"))
    }
}

macro_rules! primitive_impls {
    ( $( $ty:ty ),+ $(,)? ) => { $(
        impl IntoFfi for $ty {
            type FfiType = Self;
            type OutFfiType = *mut Self::FfiType;
            type Store = ();

            fn into_ffi(self, _: &mut Self::Store) -> Self::FfiType {
                self
            }

            unsafe fn write_out(self, store: &mut Self::Store, out: Self::OutFfiType) {
                out.write(self.into_ffi(store))
            }
        }

        impl IntoFfi for &$ty {
            type FfiType = *const $ty;
            type OutFfiType = *mut Self::FfiType;
            type Store = ();

            fn into_ffi(self, _: &mut Self::Store) -> Self::FfiType {
                Self::FfiType::from(self)
            }

            unsafe fn write_out(self, store: &mut Self::Store, out: Self::OutFfiType) {
                out.write(self.into_ffi(store))
            }
        }

        impl IntoFfi for &mut $ty {
            type FfiType = *mut $ty;
            type OutFfiType = *mut Self::FfiType;
            type Store = ();

            fn into_ffi(self, _: &mut Self::Store) -> Self::FfiType {
                Self::FfiType::from(self)
            }

            unsafe fn write_out(self, store: &mut Self::Store, out: Self::OutFfiType) {
                out.write(self.into_ffi(store))
            }
        }

        impl OptionWrapped for $ty {
            type FfiType = *mut <Self as IntoFfi>::FfiType;
            type OutFfiType = *mut <Self as OptionWrapped>::FfiType;
            type Store = Vec<Self>;

            fn into_ffi(source: Option<Self>, store: &mut <Self as OptionWrapped>::Store) -> <Self as OptionWrapped>::FfiType {
                source.map_or_else(core::ptr::null_mut, |item| {
                    store.push(item);
                    let elem = store.last_mut().expect("Defined");
                    IntoFfi::into_ffi(elem, &mut ())
                })
            }
            unsafe fn write_out(source: Option<Self>, store: &mut <Self as OptionWrapped>::Store, out: <Self as OptionWrapped>::OutFfiType) {
                if let Some(item) = source {
                    let mut new_out = core::mem::MaybeUninit::<$ty>::uninit();
                    IntoFfi::write_out(item, &mut (), new_out.as_mut_ptr());
                    store.push(new_out.assume_init());
                    let elem = store.last_mut().expect("Defined");

                    out.write(elem);
                } else {
                    out.write(core::ptr::null_mut())
                }
            }
        }

        impl OptionWrapped for &$ty {
            type FfiType = <Self as IntoFfi>::FfiType;
            type OutFfiType = <Self as IntoFfi>::OutFfiType;
            type Store = <Self as IntoFfi>::Store;

            fn into_ffi(source: Option<Self>, store: &mut <Self as OptionWrapped>::Store) -> <Self as OptionWrapped>::FfiType {
                source.map_or_else(core::ptr::null, |item| IntoFfi::into_ffi(item, store))
            }
            unsafe fn write_out(source: Option<Self>, store: &mut <Self as OptionWrapped>::Store, out: <Self as OptionWrapped>::OutFfiType) {
                if let Some(item) = source {
                    IntoFfi::write_out(item, store, out);
                } else {
                    out.write(core::ptr::null());
                }
            }
        }

        impl OptionWrapped for &mut $ty {
            type FfiType = <Self as IntoFfi>::FfiType;
            type OutFfiType = <Self as IntoFfi>::OutFfiType;
            type Store = <Self as IntoFfi>::Store;

            fn into_ffi(source: Option<Self>, store: &mut <Self as OptionWrapped>::Store) -> <Self as OptionWrapped>::FfiType {
                source.map_or_else(core::ptr::null_mut, |item| IntoFfi::into_ffi(item, store))
            }
            unsafe fn write_out(source: Option<Self>, store: &mut <Self as OptionWrapped>::Store, out: <Self as OptionWrapped>::OutFfiType) {
                if let Some(item) = source {
                    IntoFfi::write_out(item, store, out);
                } else {
                    out.write(core::ptr::null_mut());
                }
            }
        }

        impl TryFromFfi for $ty {
            type Store = ();

            unsafe fn try_from_ffi(source: Self::FfiType, _: &mut <Self as TryFromFfi>::Store) -> Result<Self, FfiResult> {
                Ok(source)
            }
        }

        impl TryFromFfi for &$ty {
            type Store = ();

            unsafe fn try_from_ffi(source: Self::FfiType, _: &mut <Self as TryFromFfi>::Store) -> Result<Self, FfiResult> {
                source.as_ref().ok_or(FfiResult::ArgIsNull)
            }
        }

        impl TryFromFfi for &mut $ty {
            type Store = ();

            unsafe fn try_from_ffi(source: Self::FfiType, _: &mut <Self as TryFromFfi>::Store) -> Result<Self, FfiResult> {
                source.as_mut().ok_or(FfiResult::ArgIsNull)
            }
        } )+
    };
}

primitive_impls! {u8, u16, u32, u64, u128, i8, i16, i32, i64, i128, f32, f64}

/// Implement [`Handle`] for given types with first argument as the initial handle id.
#[macro_export]
macro_rules! handles {
    ( $id:expr, $ty:ty $(, $other:ty)* $(,)? ) => {
        impl $crate::Handle for $ty {
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
            use iroha_ffi::opaque_pointer;

            gen_ffi_impl!(@catch_unwind {
                match handle_id {
                    $( <$other as $crate::Handle>::ID => {
                        let handle_ptr = handle_ptr.cast::<$other>();
                        let handle = opaque_pointer::object(handle_ptr).map_err::<$crate::FfiResult, _>(From::from)?;
                        let new_handle = opaque_pointer::raw(Clone::clone(handle));

                        output_ptr.write(new_handle.cast());
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
            output_ptr: *mut bool,
        ) -> $crate::FfiResult {
            use iroha_ffi::opaque_pointer;

            gen_ffi_impl!(@catch_unwind {
                match handle_id {
                    $( <$other as $crate::Handle>::ID => {
                        let (lhandle_ptr, rhandle_ptr) = (left_handle_ptr.cast::<$other>(), right_handle_ptr.cast::<$other>());
                        let left_handle = opaque_pointer::object(lhandle_ptr).map_err::<$crate::FfiResult, _>(From::from)?;
                        let right_handle = opaque_pointer::object(rhandle_ptr).map_err::<$crate::FfiResult, _>(From::from)?;

                        output_ptr.write(left_handle == right_handle);
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
            output_ptr: *mut core::cmp::Ordering,
        ) -> $crate::FfiResult {
            gen_ffi_impl!(@catch_unwind {
                use iroha_ffi::opaque_pointer;

                match handle_id {
                    $( <$other as $crate::Handle>::ID => {
                        let (lhandle_ptr, rhandle_ptr) = (left_handle_ptr.cast::<$other>(), right_handle_ptr.cast::<$other>());
                        let left_handle = opaque_pointer::object(lhandle_ptr).map_err::<$crate::FfiResult, _>(From::from)?;
                        let right_handle = opaque_pointer::object(rhandle_ptr).map_err::<$crate::FfiResult, _>(From::from)?;

                        output_ptr.write(left_handle.cmp(right_handle));
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
            use iroha_ffi::opaque_pointer;

            gen_ffi_impl!(@catch_unwind {
                match handle_id {
                    $( <$other as $crate::Handle>::ID => {
                        let handle_ptr = handle_ptr.cast::<$other>();
                        opaque_pointer::own_back(handle_ptr).map_err::<$crate::FfiResult, _>(From::from)?;
                    } )+
                    // TODO: Implement error handling (https://github.com/hyperledger/iroha/issues/2252)
                    _ => return Err($crate::FfiResult::UnknownHandle),
                }

                Ok(())
            })
        }
    };
}
