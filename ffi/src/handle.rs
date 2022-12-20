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
            handle_id: <$crate::handle::Id as FfiType>::ReprC,
            handle_ptr: *const core::ffi::c_void,
            out_ptr: *mut *mut core::ffi::c_void
        ) -> $crate::FfiReturn {
            $crate::def_ffi_fn!(@catch_unwind {
                match $crate::FfiConvert::try_from_ffi(handle_id, &mut ())? {
                    $( <$other as $crate::Handle>::ID => {
                        let handle_ref: &$other = $crate::FfiConvert::try_from_ffi(handle_ptr as <&$other as FfiType>::ReprC, &mut ())?;
                        <$other as $crate::FfiOutPtrWrite>::write_out(Clone::clone(handle_ref), out_ptr.cast::<<$other as FfiType>::ReprC>());
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
            handle_id: <$crate::handle::Id as FfiType>::ReprC,
            left_handle_ptr: *const core::ffi::c_void,
            right_handle_ptr: *const core::ffi::c_void,
            out_ptr: *mut <bool as $crate::FfiOutPtr>::OutPtr,
        ) -> $crate::FfiReturn {
            $crate::def_ffi_fn!(@catch_unwind {
                match $crate::FfiConvert::try_from_ffi(handle_id, &mut ())? {
                    $( <$other as $crate::Handle>::ID => {
                        let (lhandle_ptr, rhandle_ptr) = (
                            left_handle_ptr as <&$other as FfiType>::ReprC,
                            right_handle_ptr as <&$other as FfiType>::ReprC
                        );

                        let mut lhandle_store = Default::default();
                        let mut rhandle_store = Default::default();

                        let lhandle: &$other = $crate::FfiConvert::try_from_ffi(lhandle_ptr, &mut lhandle_store)?;
                        let rhandle: &$other = $crate::FfiConvert::try_from_ffi(rhandle_ptr, &mut rhandle_store)?;

                        <bool as $crate::FfiOutPtrWrite>::write_out(lhandle == rhandle, out_ptr);
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
            handle_id: <$crate::handle::Id as FfiType>::ReprC,
            left_handle_ptr: *const core::ffi::c_void,
            right_handle_ptr: *const core::ffi::c_void,
            out_ptr: *mut <core::cmp::Ordering as $crate::FfiOutPtr>::OutPtr,
        ) -> $crate::FfiReturn {
            $crate::def_ffi_fn!(@catch_unwind {
                match $crate::FfiConvert::try_from_ffi(handle_id, &mut ())? {
                    $( <$other as $crate::Handle>::ID => {
                        let (lhandle_ptr, rhandle_ptr) = (
                            left_handle_ptr as <&$other as FfiType>::ReprC,
                            right_handle_ptr as <&$other as FfiType>::ReprC
                        );

                        let mut lhandle_store = Default::default();
                        let mut rhandle_store = Default::default();

                        let lhandle: &$other = $crate::FfiConvert::try_from_ffi(lhandle_ptr, &mut lhandle_store)?;
                        let rhandle: &$other = $crate::FfiConvert::try_from_ffi(rhandle_ptr, &mut rhandle_store)?;

                        <core::cmp::Ordering as $crate::FfiOutPtrWrite>::write_out(lhandle.cmp(rhandle), out_ptr);
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
            handle_id: <$crate::handle::Id as FfiType>::ReprC,
            handle_ptr: *mut core::ffi::c_void,
        ) -> $crate::FfiReturn {
            $crate::def_ffi_fn!(@catch_unwind {
                match $crate::FfiConvert::try_from_ffi(handle_id, &mut ())? {
                    $( <$other as $crate::Handle>::ID => {
                        let handle_ptr = handle_ptr as <$other as FfiType>::ReprC;
                        let handle: $other = $crate::FfiConvert::try_from_ffi(handle_ptr, &mut ())?;
                    } )+
                    // TODO: Implement error handling (https://github.com/hyperledger/iroha/issues/2252)
                    _ => return Err($crate::FfiReturn::UnknownHandle),
                }

                Ok(())
            })
        }
    };
    ( dealloc ) => {
        /// FFI function equivalent of [`alloc::alloc::dealloc`]
        ///
        /// # Safety
        ///
        /// See [`GlobalAlloc::dealloc`]
        #[no_mangle]
        pub unsafe extern "C" fn __dealloc(ptr: *mut u8, size: usize, align: usize) -> $crate::FfiReturn {
            if ptr.is_null() {
                return $crate::FfiReturn::ArgIsNull;
            }

            if let Ok(layout) = core::alloc::Layout::from_size_align(size, align) {
                alloc::dealloc(ptr, layout);
                return $crate::FfiReturn::Ok;
            }

            $crate::FfiReturn::TrapRepresentation
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
                handle_id: <$crate::handle::Id as FfiType>::ReprC,
                handle_ptr: *const core::ffi::c_void,
                out_ptr: *mut *mut core::ffi::c_void
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
                handle_id: <$crate::handle::Id as FfiType>::ReprC,
                left_handle_ptr: *const core::ffi::c_void,
                right_handle_ptr: *const core::ffi::c_void,
                out_ptr: *mut u8,
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
                handle_id: <$crate::handle::Id as FfiType>::ReprC,
                left_handle_ptr: *const core::ffi::c_void,
                right_handle_ptr: *const core::ffi::c_void,
                out_ptr: *mut i8,
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
                handle_id: <$crate::handle::Id as FfiType>::ReprC,
                handle_ptr: *mut core::ffi::c_void,
            ) -> $crate::FfiReturn;
        }
    };
    ( dealloc ) => {
        extern "C" {
            /// FFI function equivalent of [`alloc::alloc::dealloc`]
            ///
            /// # Safety
            ///
            /// See [`GlobalAlloc::dealloc`]
            pub fn __dealloc(
                ptr: *mut core::ffi::c_void,
                size: usize,
                align: usize,
            ) -> $crate::FfiReturn;
        }
    };
}
