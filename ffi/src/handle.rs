//! Logic related to opaque pointer handles and functions that are common to multiple handle types

/// Type of the handle id
pub type Id = u8;

/// Implement [`crate::Handle`] for given types with the given initial handle id. Ids are
/// assigned incrementally to every type in the macro invocation. Check the following example:
///
/// ```rust
/// struct Foo1;
/// struct Foo2;
/// struct Bar1;
/// struct Bar2;
///
/// iroha_ffi::handles! {0, Foo1, Foo2, Bar1, Bar2}
///
/// /* will produce:
/// impl Handle for Foo1 {
///     const ID: Id = 0;
/// }
/// impl Handle for Foo2 {
///     const ID: Id = 1;
/// }
/// impl Handle for Bar1 {
///     const ID: Id = 2;
/// }
/// impl Handle for Bar2 {
///     const ID: Id = 3;
/// } */
/// ```
#[macro_export]
macro_rules! handles {
    ( $($other:ty),* $(,)? ) => {
        $crate::handles! {0, $( $other, )*}
    };
    ( $id:expr, $ty:ty $(, $other:ty)* $(,)? ) => {
        unsafe impl $crate::Handle for $ty {
            const ID: $crate::handle::Id = $id;
        }

        $crate::handles! {$id + 1, $( $other, )*}
    };
    ( $id:expr, $ty:ty $(, $other:ty)* $(,)? ) => {
        unsafe impl $crate::Handle for $ty {
            const ID: $crate::handle::Id = $id;
        }

        $crate::handles! {$id + 1, $( $other, )*}
    };
    ( $id:expr, $(,)? ) => {};
}

/// Generate FFI equivalent implementation of the requested trait method (e.g. Clone, Eq, Ord)
#[macro_export]
macro_rules! def_ffi_fn {
    (@catch_unwind $block:block ) => {
        match std::panic::catch_unwind(|| $block) {
            Ok(res) => match res {
                Ok(()) => $crate::FfiReturn::Ok,
                Err(err) => err.into(),
            },
            Err(_) => {
                // TODO: Implement error handling (https://github.com/hyperledger/iroha/issues/2252)
                $crate::FfiReturn::UnrecoverableError
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
            handle_id: $crate::handle::Id,
            handle_ptr: *const core::ffi::c_void,
            output_ptr: *mut *mut core::ffi::c_void
        ) -> $crate::FfiReturn {
            $crate::def_ffi_fn!(@catch_unwind {
                use core::borrow::Borrow;

                // False positive - doesn't compile otherwise
                #[allow(clippy::let_unit_value)]
                match handle_id {
                    $( <$other as $crate::Handle>::ID => {
                        let handle_ptr = handle_ptr.cast::<$other>();
                        let mut store = Default::default();
                        let handle_ref: &$other = $crate::TryFromReprC::try_from_repr_c(handle_ptr, &mut store)?;

                        let new_handle = Clone::clone(handle_ref);
                        let new_handle_ptr = $crate::IntoFfi::into_ffi(new_handle).into();
                        output_ptr.cast::<*mut $other>().write(new_handle_ptr);
                    } )+
                    // TODO: Implement error handling (https://github.com/hyperledger/iroha/issues/2252)
                    _ => return Err($crate::FfiReturn::UnknownHandle),
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
            handle_id: $crate::handle::Id,
            left_handle_ptr: *const core::ffi::c_void,
            right_handle_ptr: *const core::ffi::c_void,
            // Pointer to FFI-safe representation of `bool` (u8 or u32 if `wasm` feature is active)
            output_ptr: *mut <bool as $crate::IntoFfi>::Target,
        ) -> $crate::FfiReturn {
            $crate::def_ffi_fn!(@catch_unwind {
                use core::borrow::Borrow;

                // False positive - doesn't compile otherwise
                #[allow(clippy::let_unit_value)]
                match handle_id {
                    $( <$other as $crate::Handle>::ID => {
                        let (lhandle_ptr, rhandle_ptr) = (left_handle_ptr.cast::<$other>(), right_handle_ptr.cast::<$other>());

                        let mut lhandle_store = Default::default();
                        let mut rhandle_store = Default::default();

                        let lhandle: &$other = $crate::TryFromReprC::try_from_repr_c(lhandle_ptr, &mut lhandle_store)?;
                        let rhandle: &$other = $crate::TryFromReprC::try_from_repr_c(rhandle_ptr, &mut rhandle_store)?;

                        output_ptr.write($crate::IntoFfi::into_ffi(lhandle == rhandle).into());
                    } )+
                    // TODO: Implement error handling (https://github.com/hyperledger/iroha/issues/2252)
                    _ => return Err($crate::FfiReturn::UnknownHandle),
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
            handle_id: $crate::handle::Id,
            left_handle_ptr: *const core::ffi::c_void,
            right_handle_ptr: *const core::ffi::c_void,
            // Pointer to FFI-safe representation of `Ordering` (i8 or i32 if `wasm` feature is active)
            output_ptr: *mut <core::cmp::Ordering as $crate::IntoFfi>::Target,
        ) -> $crate::FfiReturn {
            $crate::def_ffi_fn!(@catch_unwind {
                use core::borrow::Borrow;

                // False positive - doesn't compile otherwise
                #[allow(clippy::let_unit_value)]
                match handle_id {
                    $( <$other as $crate::Handle>::ID => {
                        let (lhandle_ptr, rhandle_ptr) = (left_handle_ptr.cast::<$other>(), right_handle_ptr.cast::<$other>());

                        let mut lhandle_store = Default::default();
                        let mut rhandle_store = Default::default();

                        let lhandle: &$other = $crate::TryFromReprC::try_from_repr_c(lhandle_ptr, &mut lhandle_store)?;
                        let rhandle: &$other = $crate::TryFromReprC::try_from_repr_c(rhandle_ptr, &mut rhandle_store)?;

                        output_ptr.write($crate::IntoFfi::into_ffi(lhandle.cmp(rhandle)).into());
                    } )+
                    // TODO: Implement error handling (https://github.com/hyperledger/iroha/issues/2252)
                    _ => return Err($crate::FfiReturn::UnknownHandle),
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
            handle_id: $crate::handle::Id,
            handle_ptr: *mut core::ffi::c_void,
        ) -> $crate::FfiReturn {
            $crate::def_ffi_fn!(@catch_unwind {
                match handle_id {
                    $( <$other as $crate::Handle>::ID => {
                        let handle_ptr = handle_ptr.cast::<$other>();
                        let handle: $other = $crate::TryFromReprC::try_from_repr_c(handle_ptr, &mut ())?;
                    } )+
                    // TODO: Implement error handling (https://github.com/hyperledger/iroha/issues/2252)
                    _ => return Err($crate::FfiReturn::UnknownHandle),
                }

                Ok(())
            })
        }
    };
}

/// Generate the declaration of FFI functions for the requested trait method (e.g. Clone, Eq, Ord)
#[macro_export]
macro_rules! decl_ffi_fn {
    ( $vis:vis Clone: $( $other:ty ),+ $(,)? ) => {
        extern {
            /// FFI function equivalent of [`Clone::clone`]
            ///
            /// # Safety
            ///
            /// All of the given pointers must be valid and the given handle id must match the expected
            /// pointer type
            #[no_mangle]
            $vis fn __clone(
                handle_id: $crate::handle::Id,
                handle_ptr: *const core::ffi::c_void,
                output_ptr: *mut *mut core::ffi::c_void
            ) -> $crate::FfiReturn;
        }
    };
    ( $vis:vis Eq: $( $other:ty ),+ $(,)? ) => {
        extern {
            /// FFI function equivalent of [`Eq::eq`]
            ///
            /// # Safety
            ///
            /// All of the given pointers must be valid and the given handle id must match the expected
            /// pointer type
            #[no_mangle]
            $vis fn __eq(
                handle_id: $crate::handle::Id,
                left_handle_ptr: *const core::ffi::c_void,
                right_handle_ptr: *const core::ffi::c_void,
                output_ptr: *mut u8,
            ) -> $crate::FfiReturn;
        }
    };
    ( $vis:vis Ord: $( $other:ty ),+ $(,)? ) => {
        extern {
            /// FFI function equivalent of [`Ord::ord`]
            ///
            /// # Safety
            ///
            /// All of the given pointers must be valid and the given handle id must match the expected
            /// pointer type
            #[no_mangle]
            $vis fn __ord(
                handle_id: $crate::handle::Id,
                left_handle_ptr: *const core::ffi::c_void,
                right_handle_ptr: *const core::ffi::c_void,
                output_ptr: *mut i8,
            ) -> $crate::FfiReturn;
        }
    };
    ( $vis:vis Drop: $( $other:ty ),+ $(,)? ) => {
        extern {
            /// FFI function equivalent of [`Drop::drop`]
            ///
            /// # Safety
            ///
            /// All of the given pointers must be valid and the given handle id must match the expected
            /// pointer type
            #[no_mangle]
            $vis fn __drop(
                handle_id: $crate::handle::Id,
                handle_ptr: *mut core::ffi::c_void,
            ) -> $crate::FfiReturn;
        }
    };
}
