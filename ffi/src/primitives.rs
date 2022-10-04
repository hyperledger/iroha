//! Logic related to the conversion of primitives to and from FFI-compatible representation

use crate::ffi_type;

#[cfg(target_family = "wasm")]
mod wasm {
    use alloc::boxed::Box;
    use core::{mem::ManuallyDrop, slice};

    use crate::{
        ir::{IrArray, IrSlice, IrSliceMut, IrTypeOf},
        repr_c::{COutPtr, CType, CTypeConvert},
        slice::{OutBoxedSlice, SliceMut, SliceRef},
        FfiReturn,
    };

    /// Marker struct for an integer primitive type that is not recognized by the `WebAssembly`.
    /// This struct is meant to only be used internally by the library; there are no constructors.
    // NOTE: There are no blanket impls because it's meant to be used only on a specific set of types
    #[repr(transparent)]
    #[derive(Debug, Clone, Copy, Default)]
    pub struct NonWasmIntPrimitive<T: Default + Copy>(T);

    macro_rules! wasm_repr_impls {
        ( $($src:ty => $dst:ty),+ ) => {$(
            // SAFETY: Even if it is not used in `wasm` API it is still a `ReprC` type
            unsafe impl $crate::ReprC for $src {}

            impl $crate::option::Niche for $src {
                const NICHE_VALUE: $dst = <$src>::MAX as $dst + 1;
            }

            impl IrTypeOf<$src> for NonWasmIntPrimitive<$src> {
                #[inline]
                fn into_ir(source: $src) -> Self {
                    Self(source)
                }
                #[inline]
                fn into_rust(self) -> $src {
                    self.0
                }
            }

            unsafe impl<'itm> $crate::ir::Transmute for &'itm $src {
                type Target = *const $src;

                #[inline]
                unsafe fn is_valid(target: &Self::Target) -> bool {
                    !target.is_null()
                }
            }
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
                type Type = NonWasmIntPrimitive<Self>;
            }

            impl CType for NonWasmIntPrimitive<$src> {
                type ReprC = $dst;
            }
            impl CTypeConvert<'_, $dst> for NonWasmIntPrimitive<$src> {
                type RustStore = ();
                type FfiStore = ();

                fn into_repr_c(self, _: &mut ()) -> $dst {
                    self.0 as $dst
                }
                unsafe fn try_from_repr_c(source: $dst, _: &mut ()) -> $crate::Result<Self> {
                    <$src>::try_from(source).or(Err(FfiReturn::ConversionFailed)).map(Self)
                }
            }

            impl CType for $crate::ir::IrBox<$src, NonWasmIntPrimitive<$src>> {
                type ReprC = *mut $src;
            }
            impl CTypeConvert<'_, *mut $src> for $crate::ir::IrBox<$src, NonWasmIntPrimitive<$src>> {
                type RustStore = $src;
                type FfiStore = ();

                fn into_repr_c(self, store: &mut Self::RustStore) -> *mut $src {
                    *store = *self.0;
                    store
                }
                unsafe fn try_from_repr_c(source: *mut $src, _: &mut ()) -> $crate::Result<Self> {
                    if source.is_null() {
                        return Err(FfiReturn::ArgIsNull);
                    }

                    Ok(Self(Box::new(source.read())))
                }
            }

            impl CType for IrSlice<'_, $src, NonWasmIntPrimitive<$src>> {
                type ReprC = SliceRef<$src>;
            }
            impl<'itm> CTypeConvert<'itm, SliceRef<$src>> for IrSlice<'itm, $src, NonWasmIntPrimitive<$src>> {
                type RustStore = ();
                type FfiStore = ();

                fn into_repr_c(self, _: &mut ()) -> SliceRef<$src> {
                    let slice = self.0;

                    let (ptr, len) = (slice.as_ptr(), slice.len());
                    SliceRef::from_raw_parts(ptr.cast(), len)
                }
                unsafe fn try_from_repr_c(source: SliceRef<$src>, _: &mut ()) -> $crate::Result<Self> {
                    let slice = source.into_rust().ok_or(FfiReturn::ArgIsNull)?;
                    Ok(IrSlice(slice::from_raw_parts(slice.as_ptr().cast(), slice.len())))
                }
            }

            impl CType for IrSliceMut<'_, $src, NonWasmIntPrimitive<$src>> {
                type ReprC = SliceMut<$src>;
            }
            impl<'itm> CTypeConvert<'itm, SliceMut<$src>> for IrSliceMut<'itm, $src, NonWasmIntPrimitive<$src>> {
                type RustStore = ();
                type FfiStore = ();

                fn into_repr_c(self, _: &mut ()) -> SliceMut<$src> {
                    let slice = self.0;

                    let (ptr, len) = (slice.as_mut_ptr(), slice.len());
                    SliceMut::from_raw_parts_mut(ptr.cast(), len)
                }
                unsafe fn try_from_repr_c(source: SliceMut<$src>, _: &mut ()) -> $crate::Result<Self> {
                    let slice = source.into_rust().ok_or(FfiReturn::ArgIsNull)?;
                    Ok(IrSliceMut(slice::from_raw_parts_mut(slice.as_mut_ptr().cast(), slice.len())))
                }
            }

            impl CType for $crate::ir::IrVec<$src, NonWasmIntPrimitive<$src>> {
                type ReprC = SliceMut<$src>;
            }
            impl CTypeConvert<'_, SliceMut<$src>> for $crate::ir::IrVec<$src, NonWasmIntPrimitive<$src>> {
                type RustStore = alloc::vec::Vec<$src>;
                type FfiStore = ();

                fn into_repr_c(self, store: &mut Self::RustStore) -> SliceMut<$src> {
                    let mut vec = ManuallyDrop::new(self.0);

                    *store = unsafe {alloc::vec::Vec::from_raw_parts(
                        vec.as_mut_ptr().cast(), vec.len(), vec.capacity()
                    )};

                    SliceMut::from_slice(store)
                }
                unsafe fn try_from_repr_c(source: SliceMut<$src>, _: &mut ()) -> $crate::Result<Self> {
                    let slice = source.into_rust().ok_or(FfiReturn::ArgIsNull)?;
                    Ok(Self(slice.iter().copied().collect()))
                }
            }

            impl<const N: usize> CType for IrArray<$src, NonWasmIntPrimitive<$src>, N> {
                type ReprC = [$src; N];
            }
            impl<const N: usize> CTypeConvert<'_, [$src; N]> for IrArray<$src, NonWasmIntPrimitive<$src>, N> {
                type RustStore = ();
                type FfiStore = ();

                fn into_repr_c(self, _: &mut ()) -> [$src; N] {
                    self.0
                }
                unsafe fn try_from_repr_c(source: [$src; N], _: &mut ()) -> $crate::Result<Self> {
                    Ok(IrArray(source))
                }
            }
            impl<const N: usize> CTypeConvert<'_, *mut $src> for IrArray<$src, NonWasmIntPrimitive<$src>, N>
            where [$src; N]: Default {
                type RustStore = [$src; N];
                type FfiStore = ();

                fn into_repr_c(self, store: &mut Self::RustStore) -> *mut $src {
                    *store = self.0;
                    store.as_mut_ptr()
                }
                unsafe fn try_from_repr_c(source: *mut $src, _: &mut ()) -> $crate::Result<Self> {
                    Ok(IrArray(source.cast::<[$src; N]>().read()))
                }
            }

            impl COutPtr for NonWasmIntPrimitive<$src> {
                type OutPtr = *mut $dst;
            }
            impl COutPtr for $crate::ir::IrBox<$src, NonWasmIntPrimitive<$src>> {
                type OutPtr = *mut $src;
            }
            impl COutPtr for IrSlice<'_, $src, NonWasmIntPrimitive<$src>> {
                type OutPtr = *mut SliceRef<$src>;
            }
            impl COutPtr for IrSliceMut<'_, $src, NonWasmIntPrimitive<$src>> {
                type OutPtr = *mut SliceMut<$src>;
            }
            impl COutPtr for $crate::ir::IrVec<$src, NonWasmIntPrimitive<$src>> {
                type OutPtr = OutBoxedSlice<$src>;
            }
            impl<const N: usize> COutPtr for IrArray<$src, NonWasmIntPrimitive<$src>, N> {
                type OutPtr = *mut [$src; N];
            }

            // SAFETY: Conversion of non wasm primitive doesn't use store
            unsafe impl $crate::repr_c::NonLocal for NonWasmIntPrimitive<$src> {}

            unsafe impl $crate::repr_c::NonLocal for IrSlice<'_, $src, NonWasmIntPrimitive<$src>> {}
            unsafe impl $crate::repr_c::NonLocal for IrSliceMut<'_, $src, NonWasmIntPrimitive<$src>> {}
            unsafe impl<const N: usize> $crate::repr_c::NonLocal for IrArray<$src, NonWasmIntPrimitive<$src>, N> {})+
        };
    }

    wasm_repr_impls! {u8 => u32, i8 => i32, u16 => u32, i16 => i32}
}

macro_rules! fieldless_enum_derive {
    ( $src:ty => $dst:ty: {$niche_val:expr}: $validity_fn:expr ) => {
        impl $crate::option::Niche for $src {
            const NICHE_VALUE: Self::ReprC = $niche_val;
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
