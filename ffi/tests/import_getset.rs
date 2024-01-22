#![allow(unsafe_code)]

use iroha_ffi::{ffi, ffi_import};

iroha_ffi::handles! {Name, FfiStruct}
iroha_ffi::decl_ffi_fns! {Drop, Clone, Eq}

ffi! {
    /// Struct
    #[derive(Clone, PartialEq, Eq)]
    pub struct Name;

    /// FfiStruct
    #[ffi_import]
    #[derive(Clone, PartialEq, Eq, Setters, Getters, MutGetters)]
    #[getset(get = "pub")]
    #[ffi_type(opaque)]
    #[repr(C)]
    pub struct FfiStruct {
        /// id
        #[getset(set = "pub", get_mut = "pub")]
        id: u8,
        /// Name
        name: Name,
    }
}

#[ffi_import]
impl Name {
    /// New
    pub fn new(name: String) -> Self {
        unreachable!("replaced by ffi_import")
    }
}

#[ffi_import]
impl FfiStruct {
    /// New
    pub fn new(name: String, id: u8) -> Self {
        unreachable!("replaced by ffi_import")
    }
}

#[test]
#[webassembly_test::webassembly_test]
fn import_shared_fns() {
    let mut ffi_struct = FfiStruct::new("ipso facto".to_string(), 42);
    ffi_struct.set_id(84);
    assert!(&mut 84 == ffi_struct.id_mut());

    assert!(*Name::new("ipso facto".to_string()).as_ref() == *ffi_struct.name());
}

mod ffi {
    use std::alloc;

    use iroha_ffi::{
        def_ffi_fns, slice::RefMutSlice, FfiConvert, FfiOutPtr, FfiOutPtrWrite, FfiReturn, FfiType,
    };

    iroha_ffi::handles! {ExternName, ExternFfiStruct}

    def_ffi_fns! { dealloc }
    def_ffi_fns! {
        Drop: {ExternName, ExternFfiStruct},
        Clone: {ExternName, ExternFfiStruct},
        Eq: {ExternName, ExternFfiStruct},
    }

    /// Structure that `Name` points to
    #[derive(Debug, Clone, PartialEq, Eq, FfiType)]
    #[ffi_type(opaque)]
    #[repr(C)]
    pub struct ExternName(String);

    /// Structure that `FfiStruct` points to
    #[derive(Debug, Clone, PartialEq, Eq, FfiType)]
    #[ffi_type(opaque)]
    #[repr(C)]
    pub struct ExternFfiStruct {
        id: u8,
        name: ExternName,
    }

    #[no_mangle]
    unsafe extern "C" fn Name__new(
        input1: RefMutSlice<u8>,
        output: *mut *mut ExternName,
    ) -> FfiReturn {
        let string = String::from_utf8(input1.into_rust().expect("Defined").to_vec());
        let opaque = Box::new(ExternName(string.expect("Valid UTF8 string")));
        output.write(Box::into_raw(opaque));
        FfiReturn::Ok
    }

    #[no_mangle]
    unsafe extern "C" fn FfiStruct__new(
        input1: RefMutSlice<u8>,
        input2: <u8 as FfiType>::ReprC,
        output: *mut *mut ExternFfiStruct,
    ) -> FfiReturn {
        let string = String::from_utf8(input1.into_rust().expect("Defined").to_vec());
        let num = FfiConvert::try_from_ffi(input2, &mut ()).expect("Valid num");
        let name = ExternName(string.expect("Valid UTF8 string"));
        let opaque = Box::new(ExternFfiStruct { id: num, name });
        output.write(Box::into_raw(opaque));
        FfiReturn::Ok
    }

    #[no_mangle]
    unsafe extern "C" fn FfiStruct__id(
        input: *const ExternFfiStruct,
        output: *mut <&u8 as FfiType>::ReprC,
    ) -> FfiReturn {
        let input = &*input;
        output.write(&input.id);
        FfiReturn::Ok
    }

    #[no_mangle]
    unsafe extern "C" fn FfiStruct__id_mut(
        input: *mut ExternFfiStruct,
        output: *mut <&mut u8 as FfiType>::ReprC,
    ) -> FfiReturn {
        let input = &mut *input;
        output.write(&mut input.id);
        FfiReturn::Ok
    }

    #[no_mangle]
    unsafe extern "C" fn FfiStruct__set_id(
        input: *mut ExternFfiStruct,
        id: <u8 as FfiType>::ReprC,
    ) -> FfiReturn {
        let input = &mut *input;
        input.id = FfiConvert::try_from_ffi(id, &mut ()).expect("Valid num");
        FfiReturn::Ok
    }

    #[no_mangle]
    unsafe extern "C" fn FfiStruct__name(
        input: *const ExternFfiStruct,
        output: *mut <&ExternName as FfiOutPtr>::OutPtr,
    ) -> FfiReturn {
        let input = &*input;
        FfiOutPtrWrite::write_out(&input.name, output);
        FfiReturn::Ok
    }
}
