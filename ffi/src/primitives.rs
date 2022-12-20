//! Logic related to the conversion of primitives to and from FFI-compatible representation

use crate::ffi_type;

#[cfg(target_family = "wasm")]
mod wasm {
    use alloc::{boxed::Box, vec::Vec};
    use core::{mem::ManuallyDrop, slice};

    use crate::{
        repr_c::{
            read_non_local, write_non_local, COutPtr, COutPtrRead, COutPtrWrite, CType,
            CTypeConvert, CWrapperOutput,
        },
        slice::{OutBoxedSlice, SliceMut, SliceRef},
        FfiReturn, Result,
    };

    crate::decl_ffi_fn! { dealloc }

    /// Marker for an integer primitive type that is not recognized by the `WebAssembly`.
    /// This struct is meant only to be used internally, i.e. there are no constructors.
    // NOTE: There are no blanket impls because it's meant to be used only on a specific set of types
    #[derive(Debug, Clone, Copy)]
    pub enum NonWasmIntPrimitive {}

    macro_rules! wasm_repr_impls {
        ( $($src:ty => $dst:ty),+ ) => {$(
            // SAFETY: Even if it is not used in `wasm` API it is still a `ReprC` type
            unsafe impl $crate::ReprC for $src {}

            impl $crate::option::Niche for $src {
                const NICHE_VALUE: $dst = <$src>::MAX as $dst + 1;
            }

            // SAFETY: References coerce into pointers of the same type
            unsafe impl<'itm> $crate::ir::Transmute for &'itm $src {
                type Target = *const $src;

                #[inline]
                unsafe fn is_valid(target: &Self::Target) -> bool {
                    !target.is_null()
                }
            }
            // SAFETY: References coerce into pointers of the same type
            unsafe impl<'itm> $crate::ir::Transmute for &'itm mut $src {
                type Target = *mut $src;

                #[inline]
                unsafe fn is_valid(target: &Self::Target) -> bool {
                    !target.is_null()
                }
            }

            // SAFETY: Idempotent transmute is always infallible
            unsafe impl $crate::ir::InfallibleTransmute for $src {}

            impl $crate::ir::Ir for $src {
                type Type = NonWasmIntPrimitive;
            }
            impl $crate::ir::Ir for &$src {
                type Type = $crate::ir::Transparent;
            }

            impl CType<NonWasmIntPrimitive> for $src {
                type ReprC = $dst;
            }
            impl CTypeConvert<'_, NonWasmIntPrimitive, $dst> for $src {
                type RustStore = ();
                type FfiStore = ();

                fn into_repr_c(self, _: &mut ()) -> $dst {
                    self as $dst
                }
                unsafe fn try_from_repr_c(source: $dst, _: &mut ()) -> Result<Self> {
                    <$src>::try_from(source).or(Err(FfiReturn::ConversionFailed))
                }
            }

            impl CWrapperOutput<NonWasmIntPrimitive> for $src {
                type ReturnType = Self;
            }
            impl COutPtr<NonWasmIntPrimitive> for $src {
                type OutPtr = $dst;
            }
            impl COutPtrWrite<NonWasmIntPrimitive> for $src {
                unsafe fn write_out(self, out_ptr: *mut Self::OutPtr) {
                    write_non_local::<_, NonWasmIntPrimitive>(self, out_ptr)
                }
            }
            impl COutPtrRead<NonWasmIntPrimitive> for $src {
                unsafe fn try_read_out(out_ptr: Self::OutPtr) -> Result<Self> {
                    read_non_local::<_, NonWasmIntPrimitive>(out_ptr)
                }
            }

            impl CType<Box<NonWasmIntPrimitive>> for Box<$src> {
                type ReprC = *mut $src;
            }
            impl CTypeConvert<'_, Box<NonWasmIntPrimitive>, *mut $src> for Box<$src> {
                type RustStore = Box<$src>;
                type FfiStore = ();

                fn into_repr_c(self, store: &mut Self::RustStore) -> *mut $src {
                    *store = self;
                    store.as_mut()
                }
                unsafe fn try_from_repr_c(source: *mut $src, _: &mut ()) -> Result<Self> {
                    if source.is_null() {
                        return Err(FfiReturn::ArgIsNull);
                    }

                    Ok(ManuallyDrop::into_inner(ManuallyDrop::new(Box::from_raw(source)).clone()))
                }
            }

            impl CWrapperOutput<Box<NonWasmIntPrimitive>> for Box<$src> {
                type ReturnType = Self;
            }
            impl COutPtr<Box<NonWasmIntPrimitive>> for Box<$src> {
                type OutPtr = $src;
            }
            impl COutPtrWrite<Box<NonWasmIntPrimitive>> for Box<$src> {
                unsafe fn write_out(self, out_ptr: *mut Self::OutPtr) {
                    let mut store = Box::default();
                    CTypeConvert::<Box<NonWasmIntPrimitive>, _>::into_repr_c(self, &mut store);
                    out_ptr.write(*store);
                }
            }
            impl COutPtrRead<Box<NonWasmIntPrimitive>> for Box<$src> {
                unsafe fn try_read_out(out_ptr: Self::OutPtr) -> Result<Self> {
                    CTypeConvert::<NonWasmIntPrimitive, _>::try_from_repr_c(out_ptr as $dst, &mut ()).map(Box::new)
                }
            }

            impl CType<&[NonWasmIntPrimitive]> for &[$src] {
                type ReprC = SliceRef<$src>;
            }
            impl CTypeConvert<'_, &[NonWasmIntPrimitive], SliceRef<$src>> for &[$src] {
                type RustStore = ();
                type FfiStore = ();

                fn into_repr_c(self, _: &mut ()) -> SliceRef<$src> {
                    let (ptr, len) = (self.as_ptr(), self.len());
                    SliceRef::from_raw_parts(ptr.cast(), len)
                }
                unsafe fn try_from_repr_c(source: SliceRef<$src>, _: &mut ()) -> Result<Self> {
                    let slice = source.into_rust().ok_or(FfiReturn::ArgIsNull)?;
                    Ok(slice::from_raw_parts(slice.as_ptr().cast(), slice.len()))
                }
            }

            impl CWrapperOutput<&[NonWasmIntPrimitive]> for &[$src] {
                type ReturnType = Self;
            }
            impl COutPtr<&[NonWasmIntPrimitive]> for &[$src] {
                type OutPtr = SliceRef<$src>;
            }
            impl COutPtrWrite<&[NonWasmIntPrimitive]> for &[$src] {
                unsafe fn write_out(self, out_ptr: *mut Self::OutPtr) {
                    write_non_local::<_, &[NonWasmIntPrimitive]>(self, out_ptr)
                }
            }
            impl COutPtrRead<&[NonWasmIntPrimitive]> for &[$src] {
                unsafe fn try_read_out(out_ptr: Self::OutPtr) -> Result<Self> {
                    read_non_local::<_, &[NonWasmIntPrimitive]>(out_ptr)
                }
            }

            impl CType<&mut [NonWasmIntPrimitive]> for &mut [$src] {
                type ReprC = SliceMut<$src>;
            }
            impl<'itm> CTypeConvert<'itm, &mut [NonWasmIntPrimitive], SliceMut<$src>> for &mut [$src] {
                type RustStore = ();
                type FfiStore = ();

                fn into_repr_c(self, _: &mut ()) -> SliceMut<$src> {
                    let (ptr, len) = (self.as_mut_ptr(), self.len());
                    SliceMut::from_raw_parts_mut(ptr.cast(), len)
                }
                unsafe fn try_from_repr_c(source: SliceMut<$src>, _: &mut ()) -> Result<Self> {
                    let slice = source.into_rust().ok_or(FfiReturn::ArgIsNull)?;
                    Ok(slice::from_raw_parts_mut(slice.as_mut_ptr().cast(), slice.len()))
                }
            }

            impl CWrapperOutput<&mut [NonWasmIntPrimitive]> for &mut [$src] {
                type ReturnType = Self;
            }
            impl COutPtr<&mut [NonWasmIntPrimitive]> for &mut [$src] {
                type OutPtr = SliceMut<$src>;
            }
            impl COutPtrWrite<&mut [NonWasmIntPrimitive]> for &mut [$src] {
                unsafe fn write_out(self, out_ptr: *mut Self::OutPtr) {
                    write_non_local::<_, &mut [NonWasmIntPrimitive]>(self, out_ptr)
                }
            }
            impl COutPtrRead<&mut [NonWasmIntPrimitive]> for &mut [$src] {
                unsafe fn try_read_out(out_ptr: Self::OutPtr) -> Result<Self> {
                    read_non_local::<_, &mut [NonWasmIntPrimitive]>(out_ptr)
                }
            }

            impl CType<Vec<NonWasmIntPrimitive>> for Vec<$src> {
                type ReprC = SliceMut<$src>;
            }
            impl CTypeConvert<'_, Vec<NonWasmIntPrimitive>, SliceMut<$src>> for Vec<$src> {
                type RustStore = Vec<$src>;
                type FfiStore = ();

                fn into_repr_c(self, store: &mut Self::RustStore) -> SliceMut<$src> {
                    *store = self;
                    SliceMut::from_slice(Some(store))
                }
                unsafe fn try_from_repr_c(source: SliceMut<$src>, _: &mut ()) -> Result<Self> {
                    source.into_rust().ok_or(FfiReturn::ArgIsNull).map(|slice| slice.to_vec())
                }
            }

            impl CWrapperOutput<Vec<NonWasmIntPrimitive>> for Vec<$src> {
                type ReturnType = Self;
            }
            impl COutPtr<Vec<NonWasmIntPrimitive>> for Vec<$src> {
                type OutPtr = OutBoxedSlice<$src>;
            }
            impl COutPtrWrite<Vec<NonWasmIntPrimitive>> for Vec<$src> {
                unsafe fn write_out(self, out_ptr: *mut Self::OutPtr) {
                    let mut store = Vec::default();
                    CTypeConvert::<Vec<NonWasmIntPrimitive>, _>::into_repr_c(self, &mut store);
                    out_ptr.write(OutBoxedSlice::from_vec(Some(store)));
                }
            }
            impl COutPtrRead<Vec<NonWasmIntPrimitive>> for Vec<$src> {
                unsafe fn try_read_out(out_ptr: Self::OutPtr) -> Result<Self> {
                    let slice = SliceMut::from_raw_parts_mut(out_ptr.as_mut_ptr(), out_ptr.len());
                    let res = CTypeConvert::<Vec<NonWasmIntPrimitive>, _>::try_from_repr_c(slice, &mut ());

                    if !out_ptr.deallocate() {
                        return Err(FfiReturn::TrapRepresentation)
                    }

                    res
                }
            }

            impl<const N: usize> CType<[NonWasmIntPrimitive; N]> for [$src; N] {
                type ReprC = [$src; N];
            }
            impl<const N: usize> CTypeConvert<'_, [NonWasmIntPrimitive; N], [$src; N]> for [$src; N] {
                type RustStore = ();
                type FfiStore = ();

                fn into_repr_c(self, _: &mut ()) -> [$src; N] {
                    self
                }
                unsafe fn try_from_repr_c(source: [$src; N], _: &mut ()) -> Result<Self> {
                    Ok(source)
                }
            }
            impl<const N: usize> CTypeConvert<'_, [NonWasmIntPrimitive; N], *mut $src> for [$src; N]
            where [$src; N]: Default {
                type RustStore = [$src; N];
                type FfiStore = ();

                fn into_repr_c(self, store: &mut Self::RustStore) -> *mut $src {
                    *store = self;
                    store.as_mut_ptr()
                }
                unsafe fn try_from_repr_c(source: *mut $src, _: &mut ()) -> Result<Self> {
                    Ok(source.cast::<[$src; N]>().read())
                }
            }

            impl<const N: usize> CWrapperOutput<[NonWasmIntPrimitive; N]> for [$src; N] {
                type ReturnType = Self;
            }
            impl<const N: usize> COutPtr<[NonWasmIntPrimitive; N]> for [$src; N] {
                type OutPtr = Self;
            }
            impl<const N: usize> COutPtrWrite<[NonWasmIntPrimitive; N]> for [$src; N] {
                unsafe fn write_out(self, out_ptr: *mut Self::OutPtr) {
                    write_non_local::<_, [NonWasmIntPrimitive; N]>(self, out_ptr)
                }
            }
            impl<const N: usize> COutPtrRead<[NonWasmIntPrimitive; N]> for [$src; N] {
                unsafe fn try_read_out(out_ptr: Self::OutPtr) -> Result<Self> {
                    read_non_local::<_, [NonWasmIntPrimitive; N]>(out_ptr)
                }
            }

            // SAFETY: Conversion of non wasm primitive doesn't use store
            unsafe impl $crate::repr_c::NonLocal<NonWasmIntPrimitive> for $src {}
            // SAFETY: Conversion of non wasm primitive slice doesn't use store
            unsafe impl $crate::repr_c::NonLocal<&[NonWasmIntPrimitive]> for &[$src] {}
            // SAFETY: Conversion of non wasm primitive mutable slice doesn't use store
            unsafe impl $crate::repr_c::NonLocal<&mut [NonWasmIntPrimitive]> for &mut [$src] {}
            // SAFETY: Conversion of non wasm primitive array doesn't use store
            unsafe impl<const N: usize> $crate::repr_c::NonLocal<[NonWasmIntPrimitive; N]> for [$src; N] {})+
        };
    }

    wasm_repr_impls! {u8 => u32, i8 => i32, u16 => u32, i16 => i32}
}

/// # Safety
///
/// * the type must be transmutable into an integer
/// * validity function must not return false positives
macro_rules! fieldless_enum_derive {
    ( $src:ty => $dst:ty: {$niche_val:expr}: $validity_fn:expr ) => {
        impl $crate::option::Niche for $src {
            const NICHE_VALUE: <$dst as $crate::FfiType>::ReprC = $niche_val;
        }

        $crate::ffi_type! {unsafe impl Transparent for $src[$dst] validated with {$validity_fn} }
    };
}

fieldless_enum_derive! {
    bool => u8: {2}:
    |i: &u8| *i == 0 || *i == 1
}
fieldless_enum_derive! {
    core::cmp::Ordering => i8: {2}:
    |i: &i8| *i == -1 || *i == 0 || *i == 1
}

ffi_type! {unsafe impl Robust for u32 }
ffi_type! {unsafe impl Robust for i32 }
ffi_type! {unsafe impl Robust for u64 }
ffi_type! {unsafe impl Robust for i64 }

#[cfg(not(target_family = "wasm"))]
ffi_type! {unsafe impl Robust for u8 }
#[cfg(not(target_family = "wasm"))]
ffi_type! {unsafe impl Robust for i8 }
#[cfg(not(target_family = "wasm"))]
ffi_type! {unsafe impl Robust for u16 }
#[cfg(not(target_family = "wasm"))]
ffi_type! {unsafe impl Robust for i16 }

// TODO: u128/i128 is not FFI-safe. Must be properly serialized!
ffi_type! {unsafe impl Robust for u128 }
ffi_type! {unsafe impl Robust for i128 }
