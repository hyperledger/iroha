#![allow(unsafe_code, clippy::restriction)]

use iroha_ffi::{ffi, ffi_import};

iroha_ffi::handles! {FfiStruct<bool>}
iroha_ffi::decl_ffi_fns! {Drop, Clone, Eq, Ord}

ffi! {
    /// Struct without a repr attribute is opaque by default
    #[derive(Clone, PartialEq, Eq, PartialOrd, Ord)]
    // NOTE: Replaced by the `ffi` macro
    pub struct FfiStruct<T>;
}

#[ffi_import]
impl FfiStruct<bool> {
    /// New
    pub fn new(name: String) -> Self {
        unreachable!("replaced by ffi_import")
    }
}

#[test]
#[allow(clippy::nonminimal_bool)]
#[webassembly_test::webassembly_test]
fn import_shared_fns() {
    let ffi_struct = FfiStruct::new("ipso facto".to_string());
    let ref_ffi_struct: RefFfiStruct<_> = ffi_struct.as_ref();
    let cloned_ffi_struct: FfiStruct<_> = Clone::clone(&ref_ffi_struct);

    assert!(*ref_ffi_struct == *cloned_ffi_struct.as_ref());
    assert!(!(*ref_ffi_struct < *cloned_ffi_struct.as_ref()));
}

mod ffi {
    use std::alloc;

    use iroha_ffi::{def_ffi_fns, slice::SliceMut, FfiReturn, FfiType};

    iroha_ffi::handles! {ExternFfiStruct}

    def_ffi_fns! {
        Drop: {ExternFfiStruct},
        Clone: {ExternFfiStruct},
        Eq: {ExternFfiStruct},
        Ord: {ExternFfiStruct}
    }

    iroha_ffi::def_ffi_fns! { dealloc }

    /// Structure that `Value` points to
    #[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, FfiType)]
    #[ffi_type(opaque)]
    #[repr(C)]
    pub struct ExternFfiStruct(pub String);

    #[no_mangle]
    unsafe extern "C" fn FfiStruct__new(
        input: SliceMut<u8>,
        output: *mut *mut ExternFfiStruct,
    ) -> FfiReturn {
        let string = String::from_utf8(input.into_rust().expect("Defined").to_vec());
        let opaque = Box::new(ExternFfiStruct(string.expect("Valid UTF8 string")));
        output.write(Box::into_raw(opaque));
        FfiReturn::Ok
    }
}
